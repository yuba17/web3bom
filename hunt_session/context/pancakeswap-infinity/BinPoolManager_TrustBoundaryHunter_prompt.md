# TrustBoundaryHunter — BinPoolManager Analysis

## Tu Identidad
Eres el **TrustBoundaryHunter** del equipo de bug hunting de pancakeswap-infinity.
Tu especialidad: **Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions**

## Tu Objetivo
Analizar `BinPoolManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-core/src/pool-bin/BinPoolManager.sol`
**Dominio**: oracle


## Asset Flow Map
### Minting/Burning
- L199 mint(): (delta, feeAmountToProtocol, mintArray, compositionFeeAmount) = pool.mint(
- L242 burn(): (delta, binIds, amountRemoved) = pool.burn(
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 PancakeSwap
pragma solidity 0.8.26;

import {ProtocolFees} from "../ProtocolFees.sol";
import {Hooks} from "../libraries/Hooks.sol";
import {BinPool} from "./libraries/BinPool.sol";
import {BinPoolParametersHelper} from "./libraries/BinPoolParametersHelper.sol";
import {ParametersHelper} from "../libraries/math/ParametersHelper.sol";
import {Currency, CurrencyLibrary} from "../types/Currency.sol";
import {IPoolManager} from "../interfaces/IPoolManager.sol";
import {IBinPoolManager} from "./interfaces/IBinPoolManager.sol";
import {PoolId} from "../types/PoolId.sol";
import {PoolKey} from "../types/PoolKey.sol";
import {BalanceDelta, BalanceDeltaLibrary} from "../types/BalanceDelta.sol";
import {IVault} from "../interfaces/IVault.sol";
import {BinPosition} from "./libraries/BinPosition.sol";
import {LPFeeLibrary} from "../libraries/LPFeeLibrary.sol";
import {PackedUint128Math} from "./libraries/math/PackedUint128Math.sol";
import {Extsload} from "../Extsload.sol";
import {BinHooks} from "./libraries/BinHooks.sol";
import {PriceHelper} from "./libraries/PriceHelper.sol";
import {BeforeSwapDelta} from "../types/BeforeSwapDelta.sol";
import {BinSlot0} from "./types/BinSlot0.sol";
import {VaultAppDeltaSettlement} from "../libraries/VaultAppDeltaSettlement.sol";

/// @notice Holds the state for all bin pools
contract BinPoolManager is IBinPoolManager, ProtocolFees, Extsload {
    using BinPool for *;
    using BinPosition for mapping(bytes32 => BinPosition.Info);
    using BinPoolParametersHelper for bytes32;
    using LPFeeLibrary for uint24;
    using PackedUint128Math for bytes32;
    using Hooks for bytes32;
    using VaultAppDeltaSettlement for IVault;

    /// @inheritdoc IBinPoolManager
    uint16 public constant override MIN_BIN_STEP = 1;

    /// @inheritdoc IBinPoolManager
    uint16 public override maxBinStep = 100;

    /// @inheritdoc IBinPoolManager
    uint256 public override minBinShareForDonate = 2 ** 128;

    mapping(PoolId id => BinPool.State poolState) public pools;

    mapping(PoolId id => PoolKey poolKey) public poolIdToPoolKey;

    constructor(IVault vault) ProtocolFees(vault) {}

    /// @notice pool manager specified in the pool key must match current contract
    modifier poolManagerMatch(address poolManager) {
        if (address(this) != poolManager) revert PoolManagerMismatch();
        _;
    }

    /// @inheritdoc IBinPoolManager
    function getSlot0(PoolId id) external view override returns (uint24 activeId, uint24 protocolFee, uint24 lpFee) {
        BinSlot0 slot0 = pools[id].slot0;

        return (slot0.activeId(), slot0.protocolFee(), slot0.lpFee());
    }

    /// @inheritdoc IBinPoolManager
    function getBin(PoolId id, uint24 binId)
        external
        view
        override
        returns (uint128 binReserveX, uint128 binReserveY, uint256 binLiquidity, uint256 totalShares)
    {
        PoolKey memory key = poolIdToPoolKey[id];
        (binReserveX, binReserveY, binLiquidity, totalShares) = pools[id].getBin(key.parameters.getBinStep(), binId);
    }

    /// @inheritdoc IBinPoolManager
    function getPosition(PoolId id, address owner, uint24 binId, bytes32 salt)
        external
        view
        override
        returns (BinPosition.Info memory position)
    {
        return pools[id].positions.get(owner, binId, salt);
    }

    /// @inheritdoc IBinPoolManager
    function getNextNonEmptyBin(PoolId id, bool swapForY, uint24 binId)
        external
        view
        override
        returns (uint24 nextId)
    {
        nextId = pools[id].getNextNonEmptyBin(swapForY, binId);
    }

    /// @inheritdoc IBinPoolManager
    function initialize(PoolKey memory key, uint24 activeId)
        external
        override
        poolManagerMatch(address(key.poolManager))
    {
        uint16 binStep = key.parameters.getBinStep();
        if (binStep < MIN_BIN_STEP) revert BinStepTooSmall(binStep);
        if (binStep > maxBinStep) revert BinStepTooLarge(binStep);
        if (key.currency0 >= key.currency1) {
            revert CurrenciesInitializedOutOfOrder(Currency.unwrap(key.currency0), Currency.unwrap(key.currency1));
        }

        // safety check, making sure that the price can be calculated
        PriceHelper.getPriceFromId(activeId, binStep);

        ParametersHelper.checkUnusedBitsAllZero(
            key.parameters, BinPoolParametersHelper.OFFSET_MOST_SIGNIFICANT_UNUSED_BITS
        );
        Hooks.validateHookConfig(key);
        BinHooks.validatePermissionsConflict(key);

        /// @notice init value for dynamic lp fee is 0, but hook can still set it in afterInitialize
        uint24 lpFee = key.fee.getInitialLPFee();
        lpFee.validate(LPFeeLibrary.TEN_PERCENT_FEE);

        BinHooks.beforeInitialize(key, activeId);

        PoolId id = key.toId();

        uint24 protocolFee = _fetchProtocolFee(key);
        pools[id].initialize(activeId, protocolFee, lpFee);

        poolIdToPoolKey[id] = key;

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Initialize(id, key.currency0, key.currency1, key.hooks, key.fee, key.parameters, activeId);

        BinHooks.afterInitialize(key, activeId);
    }

    /// @inheritdoc IBinPoolManager
    function swap(PoolKey memory key, bool swapForY, int128 amountSpecified, bytes calldata hookData)
        external
        override
        whenNotPaused
        returns (BalanceDelta delta)
    {
        if (amountSpecified == 0) revert AmountSpecifiedIsZero();

        PoolId id = key.toId();
        BinPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        (int128 amountToSwap, BeforeSwapDelta beforeSwapDelta, uint24 lpFeeOverride) =
            BinHooks.beforeSwap(key, swapForY, amountSpecified, hookData);

        /// @dev fix stack too deep
        {
            BinPool.SwapState memory state;
            (delta, state) = pool.swap(
                BinPool.SwapParams({
                    swapForY: swapForY,
                    binStep: key.parameters.getBinStep(),
                    lpFeeOverride: lpFeeOverride,
                    amountSpecified: amountToSwap
                })
            );

            unchecked {
                if (state.feeAmountToProtocol > 0) {
                    protocolFeesAccrued[key.currency0] += state.feeAmountToProtocol.decodeX();
                    protocolFeesAccrued[key.currency1] += state.feeAmountToProtocol.decodeY();
                }
            }

            /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
            emit Swap(
                id, msg.sender, delta.amount0(), delta.amount1(), state.activeId, state.swapFee, state.protocolFee
            );
        }

        BalanceDelta hookDelta;
        (delta, hookDelta) = BinHooks.afterSwap(key, swapForY, amountSpecified, delta, hookData, beforeSwapDelta);

        vault.accountAppDeltaWithHookDelta(key, delta, hookDelta);
    }

    /// @inheritdoc IBinPoolManager
    function mint(PoolKey memory key, IBinPoolManager.MintParams calldata params, bytes calldata hookData)
        external
        override
        whenNotPaused
        returns (BalanceDelta delta, BinPool.MintArrays memory mintArray)
    {
        PoolId id = key.toId();
        BinPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        (uint24 lpFeeOverride) = BinHooks.beforeMint(key, params, hookData);

        bytes32 feeAmountToProtocol;
        bytes32 compositionFeeAmount;
        (delta, feeAmountToProtocol, mintArray, compositionFeeAmount) = pool.mint(
            BinPool.MintParams({
                to: msg.sender,
                liquidityConfigs: params.liquidityConfigs,
                amountIn: params.amountIn,
                binStep: key.parameters.getBinStep(),
                lpFeeOverride: lpFeeOverride,
                salt: params.salt
            })
        );

        unchecked {
            if (feeAmountToProtocol > 0) {
                protocolFeesAccrued[key.currency0] += feeAmountToProtocol.decodeX();
                protocolFeesAccrued[key.currency1] += feeAmountToProtocol.decodeY();
            }
        }

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Mint(
            id, msg.sender, mintArray.ids, params.salt, mintArray.amounts, compositionFeeAmount, feeAmountToProtocol
        );

        BalanceDelta hookDelta;
        (delta, hookDelta) = BinHooks.afterMint(key, params, delta, hookData);

        vault.accountAppDeltaWithHookDelta(key, delta, hookDelta);
    }

    /// @inheritdoc IBinPoolManager
    function burn(PoolKey memory key, IBinPoolManager.BurnParams memory params, bytes calldata hookData)
        external
        override
        returns (BalanceDelta delta)
    {
        PoolId id = key.toId();
        BinPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        BinHooks.beforeBurn(key, params, hookData);

        uint256[] memory binIds;
        bytes32[] memory amountRemoved;
        (delta, binIds, amountRemoved) = pool.burn(
            BinPool.BurnParams({
                from: msg.sender,
                ids: params.ids,
                amountsToBurn: params.amountsToBurn,
                salt: params.salt
            })
        );

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Burn(id, msg.sender, binIds, params.salt, amountRemoved);

        BalanceDelta hookDelta;
        (delta, hookDelta) = BinHooks.afterBurn(key, params, delta, hookData);

        vault.accountAppDeltaWithHookDelta(key, delta, hookDelta);
    }

    function donate(PoolKey memory key, uint128 amount0, uint128 amount1, bytes calldata hookData)
        external
        override
        whenNotPaused
        returns (BalanceDelta delta, uint24 binId)
    {
        PoolId id = key.toId();
        BinPool.State storage pool = pools[id];
        pool.checkPoolInitialized();

        BinHooks.beforeDonate(key, amount0, amount1, hookData);

        /// @dev Share is 1:1 liquidity when liquidity is first added to bin
        uint256 currentBinShare = pool.shareOfBin[pool.slot0.activeId()];
        if (currentBinShare < minBinShareForDonate) {
            revert InsufficientBinShareForDonate(currentBinShare);
        }

        (delta, binId) = pool.donate(key.parameters.getBinStep(), amount0, amount1);

        vault.accountAppBalanceDelta(key.currency0, key.currency1, delta, msg.sender);

        /// @notice Make sure the first event is noted, so that later events from afterHook won't get mixed up with this one
        emit Donate(id, msg.sender, delta.amount0(), delta.amount1(), binId);

        BinHooks.afterDonate(key, amount0, amount1, hookData);
    }

    /// @inheritdoc IBinPoolManager
    function setMaxBinStep(uint16 newMaxBinStep) external override onlyOwner {
        if (newMaxBinStep <= MIN_BIN_STEP) revert MaxBinStepTooSmall(newMaxBinStep);

        maxBinStep = newMaxBinStep;
        emit SetMaxBinStep(newMaxBinStep);
    }

    /// @inheritdoc IBinPoolManager
    function setMinBinSharesForDonate(uint256 minBinShare) external override onlyOwner {
        minBinShareForDonate = minBinShare;
        emit SetMinBinSharesForDonate(minBinShare);
    }

    /// @inheritdoc IPoolManager
    function updateDynamicLPFee(PoolKey memory key, uint24 newDynamicLPFee) external override {
        if (!key.fee.isDynamicLPFee() || msg.sender != address(key.hooks)) revert UnauthorizedDynamicLPFeeUpdate();
        newDynamicLPFee.validate(LPFeeLibrary.TEN_PERCENT_FEE);

        PoolId id = key.toId();
        pools[id].setLPFee(newDynamicLPFee);
        emit DynamicLPFeeUpdated(id, newDynamicLPFee);
    }

    function _setProtocolFee(PoolId id, uint24 newProtocolFee) internal override {
        pools[id].setProtocolFee(newProtocolFee);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre BinPoolManager
Buscando 'BinPoolManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (19ms)


### HIGH findings en dominio oracle
Buscando 'BinPoolManager getSlot0 getPosition getNextNonEmptyBin setMaxBinStep' [SQLite FTS5] (dominio: oracle)...

Top 2 findings relevantes: (19ms)

 1. [HIGH] H-17: ````UniswapImplementation.beforeSwap()```` is  vulnerable to price manipul — Flayer
 2. [HIGH] [H-01] `ETHOracle.getLatestPrice` needs to convert to 18 decimals — BakerFi

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: BinPoolManager getSlot0 getPosition getNextNonEmptyBin setMaxBinStep | Dominio: oracle
Los siguientes 2 findings de protocolos similares son relevantes:

1. [HIGH] H-17: ````UniswapImplementation.beforeSwap()```` is  vulnerable to price manipulation attack (Flayer)
   Source: https://github.com/sherlock-audit/2024-08-flayer-judging/issues/559 

## Found by 
AuditorPraise, BugPull, ComposableSecurity, KingNFT, Thanos...

2. [HIGH] [H-01] `ETHOracle.getLatestPrice` needs to convert to 18 decimals (BakerFi)
   
In `ETHOracle.sol`, `getPrecision()` is defined as `10 ** 18`, but the actual oracle used is 8-decimals.

<https://data.chain.link/feeds/arbitrum/mai...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'BinPoolManager getSlot0 getPosition getNextNonEmptyBin setMa' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (2ms)

 1. [HIGH] H-17: ````UniswapImplementation.beforeSwap()```` is  vulnerable to price manipul — Flayer
 2. [HIGH] [H-01] `ETHOracle.getLatestPrice` needs to convert to 18 decimals — BakerFi
 3. [HIGH] [H-04] The `withdrawClosedSize()` Function Misses the Situation Where the Funds  — Pearlabs
 4. [HIGH] H-5: Incorrect price used when updating the global position data — FlatMoney

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: BinPoolManager getSlot0 getPosition getNextNonEmptyBin setMa | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] H-17: ````UniswapImplementation.beforeSwap()```` is  vulnerable to price manipulation attack (Flayer)
   Source: https://github.com/sherlock-audit/2024-08-flayer-judging/issues/559 

## Found by 
AuditorPraise, BugPull, ComposableSecurity, KingNFT, Thanos...

2. [HIGH] [H-01] `ETHOracle.getLatestPrice` needs to convert to 18 decimals (BakerFi)
   
In `ETHOracle.sol`, `getPrecision()` is defined as `10 ** 18`, but the actual oracle used is 8-decimals.

<https://data.chain.link/feeds/arbitrum/mai...

3. [HIGH] [H-04] The `withdrawClosedSize()` Function Misses the Situation Where the Funds Are Transferred as `ETH` From the `GMX` (Pearlabs)
   ## Severity

High Risk

## Description

Users can opt to close their positions with ETH being received, accordingly, they can pass the flag:

File: [s...

4. [HIGH] H-5: Incorrect price used when updating the global position data (FlatMoney)
   Source: https://github.com/sherlock-audit/2023-12-flatmoney-judging/issues/188 

## Found by 
0xLogos, 0xVolodya, juan, nobody2018, santipu\_, xiaomin...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio (oracle)
### Briefing principal: oracle

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Some protocols have fallback oracles that silently handle staleness -- check full path
  ⚠ Heartbeat varies per feed and per chain -- don't assume 1h for all
  ⚠ updatedAt == 0 is a valid failure case (feed never initialized)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate -- cost/benefit matters
  ⚠ Legitimate large trades can trigger deviation on thin pools
  ⚠ Protocol using Chainlink only (no AMM reads) is not vulnerable to this
  ⚠ Very high liquidity pools make even short TWAP expensive to manipulate
  ⚠ Multi-block manipulation requires sustained capital or validator collusion
  ⚠ Post-PoS: proposer can manipulate last block of window more cheaply
  ⚠ Solidity int256 can be negative -- casting to uint256 without check wraps around
  ⚠ Some feeds return minAnswer/maxAnswer bounds, not zero, on extreme events
  ⚠ Check Chainlink aggregator minAnswer -- if real price drops below, feed returns minAnswer (stale)

## CHECKLIST DE INVARIANTES
Oracle audit -- run through for every target:
```
[ ] Grep: latestAnswer, getAnswer, getTimestamp (deprecated functions)
[ ] Grep: latestRoundData -- are ALL return values validated?
[ ] Check: price > 0 after every oracle read
[ ] Check: updatedAt freshness against feed-specific heartbeat
[ ] Check: answeredInRound >= roundId
[ ] Grep: getReserves, slot0, sqrtPriceX96 (spot price reads)
[ ] If spot price used: is TWAP or Chainlink cross-validation present?
[ ] Grep: observe, consult (TWAP reads) -- what window length?
[ ] If TWAP window < 30 min: flag as manipulable
[ ] Check: observationCardinality sufficient for window?
[ ] Check: feed.decimals() called or hardcoded assumption?
[ ] Check: token decimals + oracle decimals combined correctly?
[ ] If L2: sequencer uptime feed checked?
[ ] If L2: grace period after sequencer restart?
[ ] Check: fallback oracle path exists?
[ ] Check: circuit breaker for extreme price events?
[ ] Check: minAnswer/maxAnswer on Chainlink aggregator (hidden staleness)
```


### Grep targets adicionales (dex)
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
ID prefix para este componente: `BPM` (ej: BPM-01, BPM-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_BinPoolManager_TrustBoundaryHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: BPM-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "BPM-01: value decreased");
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
