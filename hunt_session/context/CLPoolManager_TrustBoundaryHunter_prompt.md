# TrustBoundaryHunter — CLPoolManager Analysis

## Tu Identidad
Eres el **TrustBoundaryHunter** del equipo de bug hunting de pancakeswap-infinity.
Tu especialidad: **Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions**

## Tu Objetivo
Analizar `CLPoolManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-core/src/pool-cl/CLPoolManager.sol`
**Dominio**: dex


```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 PancakeSwap
pragma solidity 0.8.26;

import {ProtocolFees} from "../ProtocolFees.sol";
import {ICLPoolManager} from "./interfaces/ICLPoolManager.sol";
import {IVault} from "../interfaces/IVault.sol";
import {PoolId} from "../types/PoolId.sol";
import {CLPool} from "./libraries/CLPool.sol";
import {CLPosition} from "./libraries/CLPosition.sol";
import {PoolKey} from "../types/PoolKey.sol";
import {IPoolManager} from "../interfaces/IPoolManager.sol";
import {Hooks} from "../libraries/Hooks.sol";
import {Tick} from "./libraries/Tick.sol";
import {CLPoolParametersHelper} from "./libraries/CLPoolParametersHelper.sol";
import {ParametersHelper} from "../libraries/math/ParametersHelper.sol";
import {LPFeeLibrary} from "../libraries/LPFeeLibrary.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "../types/BalanceDelta.sol";
import {Extsload} from "../Extsload.sol";
import {SafeCast} from "../libraries/SafeCast.sol";
import {CLPoolGetters} from "./libraries/CLPoolGetters.sol";
import {CLHooks} from "./libraries/CLHooks.sol";
import {BeforeSwapDelta} from "../types/BeforeSwapDelta.sol";
import {Currency} from "../types/Currency.sol";
import {TickMath} from "./libraries/TickMath.sol";
import {CLSlot0} from "./types/CLSlot0.sol";
import {VaultAppDeltaSettlement} from "../libraries/VaultAppDeltaSettlement.sol";

contract CLPoolManager is ICLPoolManager, ProtocolFees, Extsload {
    using SafeCast for int256;
    using Hooks for bytes32;
    using LPFeeLibrary for uint24;
    using CLPoolParametersHelper for bytes32;
    using CLPool for *;
    using CLPosition for mapping(bytes32 => CLPosition.Info);
    using CLPoolGetters for CLPool.State;
    using VaultAppDeltaSettlement for IVault;

    mapping(PoolId id => CLPool.State poolState) private pools;

    mapping(PoolId id => PoolKey poolKey) public poolIdToPoolKey;

    constructor(IVault _vault) ProtocolFees(_vault) {}

    /// @notice pool manager specified in the pool key must match current contract
    modifier poolManagerMatch(address poolManager) {
        if (address(this) != poolManager) revert PoolManagerMismatch();
        _;
    }

    /// @inheritdoc ICLPoolManager
    function getSlot0(PoolId id)
        external
        view
        override
        returns (uint160 sqrtPriceX96, int24 tick, uint24 protocolFee, uint24 lpFee)
    {
        CLSlot0 slot0 = pools[id].slot0;
        return (slot0.sqrtPriceX96(), slot0.tick(), slot0.protocolFee(), slot0.lpFee());
    }

    /// @inheritdoc ICLPoolManager
    function getLiquidity(PoolId id) external view override returns (uint128 liquidity) {
        return pools[id].liquidity;
    }

    /// @inheritdoc ICLPoolManager
    function getLiquidity(PoolId id, address _owner, int24 tickLower, int24 tickUpper, bytes32 salt)
        external
        view
        override
        returns (uint128 liquidity)
    {
        return pools[id].positions.get(_owner, tickLower, tickUpper, salt).liquidity;
    }

    /// @inheritdoc ICLPoolManager
    function getPosition(PoolId id, address owner, int24 tickLower, int24 tickUpper, bytes32 salt)
        external
        view
        override
        returns (CLPosition.Info memory position)
    {
        return pools[id].positions.get(owner, tickLower, tickUpper, salt);
    }

    /// @inheritdoc ICLPoolManager
    function initialize(PoolKey memory key, uint160 sqrtPriceX96)
        external
        override
        poolManagerMatch(address(key.poolManager))
        returns (int24 tick)
    {
        int24 tickSpacing = key.parameters.getTickSpacing();
        if (tickSpacing > TickMath.MAX_TICK_SPACING) revert TickSpacingTooLarge(tickSpacing);
        if (tickSpacing < TickMath.MIN_TICK_SPACING) revert TickSpacingTooSmall(tickSpacing);
        if (key.currency0 >= key.currency1) {
            revert CurrenciesInitializedOutOfOrder(Currency.unwrap(key.currency0), Currency.unwrap(key.currency1));
        }

        ParametersHelper.checkUnusedBitsAllZero(
            key.parameters, CLPoolParametersHelper.OFFSET_MOST_SIGNIFICANT_UNUSED_BITS
        );
        Hooks.validateHookConfig(key);
        CLHooks.validatePermissionsConflict(key);

        /// @notice init value for dynamic lp fee is 0, but hook can still set it in afterInitialize
        uint24 lpFee = key.fee.getInitialLPFee();
        lpFee.validate(LPFeeLibrary.ONE_HUNDRED_PERCENT_FEE);

        CLHooks.beforeInitialize(key, sqrtPriceX96);

        PoolId id = key.toId();
        uint24 protocolFee = _fetchProtocolFee(key);
        tick = pools[id].initialize(sqrtPriceX96, protocolFee, lpFee);

        poolIdToPoolKey[id] = key;

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Initialize(id, key.currency0, key.currency1, key.hooks, key.fee, key.parameters, sqrtPriceX96, tick);

        CLHooks.afterInitialize(key, sqrtPriceX96, tick);
    }

    /// @inheritdoc ICLPoolManager
    function modifyLiquidity(
        PoolKey memory key,
        ICLPoolManager.ModifyLiquidityParams memory params,
        bytes calldata hookData
    ) external override returns (BalanceDelta delta, BalanceDelta feeDelta) {
        // Do not allow add liquidity when paused()
        if (params.liquidityDelta > 0 && paused()) revert PoolPaused();

        PoolId id = key.toId();
        CLPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        CLHooks.beforeModifyLiquidity(key, params, hookData);

        (delta, feeDelta) = pool.modifyLiquidity(
            CLPool.ModifyLiquidityParams({
                owner: msg.sender,
                tickLower: params.tickLower,
                tickUpper: params.tickUpper,
                liquidityDelta: params.liquidityDelta.toInt128(),
                tickSpacing: key.parameters.getTickSpacing(),
                salt: params.salt
            })
        );

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit ModifyLiquidity(id, msg.sender, params.tickLower, params.tickUpper, params.liquidityDelta, params.salt);

        BalanceDelta hookDelta;
        // notice that both generated delta and feeDelta (from lpFee) will both be counted on the user
        (delta, hookDelta) = CLHooks.afterModifyLiquidity(key, params, delta + feeDelta, feeDelta, hookData);

        vault.accountAppDeltaWithHookDelta(key, delta, hookDelta);
    }

    /// @inheritdoc ICLPoolManager
    function swap(PoolKey memory key, ICLPoolManager.SwapParams memory params, bytes calldata hookData)
        external
        override
        whenNotPaused
        returns (BalanceDelta delta)
    {
        if (params.amountSpecified == 0) revert SwapAmountCannotBeZero();

        PoolId id = key.toId();
        CLPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        (int256 amountToSwap, BeforeSwapDelta beforeSwapDelta, uint24 lpFeeOverride) =
            CLHooks.beforeSwap(key, params, hookData);
        CLPool.SwapState memory state;
        (delta, state) = pool.swap(
            CLPool.SwapParams({
                tickSpacing: key.parameters.getTickSpacing(),
                zeroForOne: params.zeroForOne,
                amountSpecified: amountToSwap,
                sqrtPriceLimitX96: params.sqrtPriceLimitX96,
                lpFeeOverride: lpFeeOverride
            })
        );

        unchecked {
            if (state.feeAmountToProtocol > 0) {
                protocolFeesAccrued[params.zeroForOne ? key.currency0 : key.currency1] += state.feeAmountToProtocol;
            }
        }

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Swap(
            id,
            msg.sender,
            delta.amount0(),
            delta.amount1(),
            state.sqrtPriceX96,
            state.liquidity,
            state.tick,
            state.swapFee,
            state.protocolFee
        );

        BalanceDelta hookDelta;

        /// @dev delta already includes protocol fee
        (delta, hookDelta) = CLHooks.afterSwap(key, params, delta, hookData, beforeSwapDelta);

        vault.accountAppDeltaWithHookDelta(key, delta, hookDelta);
    }

    /// @inheritdoc ICLPoolManager
    function donate(PoolKey memory key, uint256 amount0, uint256 amount1, bytes calldata hookData)
        external
        override
        whenNotPaused
        returns (BalanceDelta delta)
    {
        PoolId id = key.toId();
        CLPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        CLHooks.beforeDonate(key, amount0, amount1, hookData);

        int24 tick;
        (delta, tick) = pool.donate(amount0, amount1);
        vault.accountAppBalanceDelta(key.currency0, key.currency1, delta, msg.sender);

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Donate(id, msg.sender, amount0, amount1, tick);

        CLHooks.afterDonate(key, amount0, amount1, hookData);
    }

    function getPoolTickInfo(PoolId id, int24 tick) external view returns (Tick.Info memory) {
        return pools[id].getPoolTickInfo(tick);
    }

    function getPoolBitmapInfo(PoolId id, int16 word) external view returns (uint256 tickBitmap) {
        return pools[id].getPoolBitmapInfo(word);
    }

    function getFeeGrowthGlobals(PoolId id)
        external
        view
        returns (uint256 feeGrowthGlobal0x128, uint256 feeGrowthGlobal1x128)
    {
        return pools[id].getFeeGrowthGlobals();
    }

    /// @inheritdoc IPoolManager
    function updateDynamicLPFee(PoolKey memory key, uint24 newDynamicLPFee) external override {
        if (!key.fee.isDynamicLPFee() || msg.sender != address(key.hooks)) revert UnauthorizedDynamicLPFeeUpdate();
        newDynamicLPFee.validate(LPFeeLibrary.ONE_HUNDRED_PERCENT_FEE);

        PoolId id = key.toId();
        pools[id].setLPFee(newDynamicLPFee);
        emit DynamicLPFeeUpdated(id, newDynamicLPFee);
    }

    function _setProtocolFee(PoolId id, uint24 newProtocolFee) internal override {
        pools[id].setProtocolFee(newProtocolFee);
    }

    /// @notice not accept ether
    // receive() external payable {}
    // fallback() external payable {}
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
Sin contexto disponible — busca patrones propios

## Briefing del Dominio (dex)
### Briefing principal: dex
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Constant Product Invariant Violation
### 1.2 LP Token Mint/Burn Ratio Desync
### 1.3 Price Impact Manipulation (Thin Liquidity)
### 1.4 Sandwich Attack Amplification
### 1.5 TWAP Oracle Manipulation
### 1.6 Concentrated Liquidity Tick Boundary Errors
### 1.7 Swap Deadline Missing
### 1.8 Slippage Protection Bypass
### 2.1 Flash Loan + AMM State Manipulation
### 2.2 Fee Accounting Mismatch

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Fees intentionally reduce output — k must increase by fee amount, not stay flat
  ⚠ Virtual reserves in concentrated liquidity mean k is per-range, not global
  ⚠ Rebasing tokens break the invariant naturally — pool must handle rebase
  ⚠ UniV2 MINIMUM_LIQUIDITY (1000 wei) prevents first-depositor attack
  ⚠ Fee-on-transfer tokens cause natural desync — protocol must use actual received amounts
  ⚠ Imbalanced deposits in multi-asset pools intentionally cost more (swap fee applies)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate for spot reads
  ⚠ TWAP with short window (< 10 min) is still manipulable across multiple blocks
  ⚠ Chainlink with proper staleness checks is generally safe
  ⚠ Private mempools (Flashbots) partially mitigate but do not eliminate risk
  ⚠ Protocols computing slippage from oracle price internally may be acceptable
  ⚠ L2s with sequencer ordering have reduced but nonzero sandwich risk

## CHECKLIST DE INVARIANTES
| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| DEX-INV-001 | k_after >= k_before for every swap | 1 | constant product |
| DEX-INV-002 | LP mint-then-burn returns <= deposited | 1 | share math |
| DEX-INV-003 | reserve0 * reserve1 monotonically non-decreasing | 1 | core AMM |
| DEX-INV-004 | sum(LP balances) == LP totalSupply | 1 | token accounting |
| DEX-INV-005 | actual token balances >= internal reserves | 1 | INV-EXPLOIT-012 |
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0) | 1 | INV-EXPLOIT-016 |
| DEX-INV-007 | spot price deviation from TWAP < MAX_PCT | 2 | INV-EXPLOIT-001 |
| DEX-INV-008 | fee deducted <= amount transacted | 1 | INV-EXPLOIT-008 |
| DEX-INV-009 | no profit from sandwich (attacker_out <= attacker_in) | 1 | COMP-MULTI-001 |
| DEX-INV-010 | active liquidity == sum(position liquidity in active range) | 1 | tick math |
**Tier 1** = hard fail = confirmed bug. **Tier 2** = needs review, may have tolerance.
---

## GREP TARGETS
```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp
swap(
getAmountOut
getAmountIn

## INCIDENTES REALES (protocolos afectados)
```yaml
- id: dex-incident-001
  name: "KyberSwap exploit"
  fecha: "2023-11"
  perdida: "$48M"
  causa_raiz: "Precision loss in concentrated liquidity tick boundary math"
  categoria: "Tick boundary error / precision loss"
  vector: "Attacker exploited precision loss at tick boundaries in KyberSwap's concentrated liquidity implementation to drain pools"
  leccion: "CRITICAL: Tick boundary math is the #1 attack surface for concentrated liquidity DEXes. See dex-006. Fuzz with swaps that land exactly on tick boundaries."
  verificado: true

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Trust boundary analysis: token quirks (ERC777) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `CLPM` (ej: CLPM-01, CLPM-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_CLPoolManager_TrustBoundaryHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: CLPM-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "CLPM-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Compiler Version Check (OBLIGATORIO)
1. Verifica la versión de Solidity del contrato
2. Consulta https://docs.soliditylang.org/en/latest/bugs.html — ¿hay bugs conocidos para esa versión?
3. Si usa Vyper: verificar que NO es 0.2.15-0.3.0 (reentrancy lock failure → $69M Curve hack 2023)

## Weird ERC-20 Checklist (d-xo — OBLIGATORIO si el contrato interactúa con tokens)
Para cada token que el contrato maneja, verificar:
- ¿Retorna bool en transfer/approve? (USDT, BNB, OMG NO retornan)
- ¿Requiere approve(0) antes de re-approve? (USDT, KNC)
- ¿Revierte en transfer de valor 0? (LEND)
- ¿Es rebasing? (stETH, AMPL — balance cambia sin transfer)
- ¿Tiene fee-on-transfer? (amount recibido < amount enviado)
- ¿Tiene blocklist? (USDC, USDT — pueden bloquear el contrato)
- ¿Usa SafeERC20 para todas las interacciones?

Si el contrato asume comportamiento estándar ERC-20 y acepta tokens arbitrarios → HIGH risk.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
