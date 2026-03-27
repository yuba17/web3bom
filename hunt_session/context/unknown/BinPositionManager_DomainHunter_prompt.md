# DomainHunter — BinPositionManager Analysis

## Tu Identidad
Eres el **DomainHunter** del equipo de bug hunting de pancakeswap-infinity.
Tu especialidad: **Protocol-specific invariants, cross-component interactions, economic attacks**

## Tu Objetivo
Analizar `BinPositionManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-periphery/src/pool-bin/BinPositionManager.sol`
**Dominio**: dex


```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 PancakeSwap
pragma solidity 0.8.26;

import {IVault} from "infinity-core/src/interfaces/IVault.sol";
import {BalanceDelta} from "infinity-core/src/types/BalanceDelta.sol";
import {Currency, CurrencyLibrary} from "infinity-core/src/types/Currency.sol";
import {IBinPoolManager} from "infinity-core/src/pool-bin/interfaces/IBinPoolManager.sol";
import {BinPool} from "infinity-core/src/pool-bin/libraries/BinPool.sol";
import {PoolKey} from "infinity-core/src/types/PoolKey.sol";
import {PoolId} from "infinity-core/src/types/PoolId.sol";
import {LiquidityConfigurations} from "infinity-core/src/pool-bin/libraries/math/LiquidityConfigurations.sol";
import {BinPoolParametersHelper} from "infinity-core/src/pool-bin/libraries/BinPoolParametersHelper.sol";
import {PackedUint128Math} from "infinity-core/src/pool-bin/libraries/math/PackedUint128Math.sol";

import {IAllowanceTransfer} from "permit2/src/interfaces/IAllowanceTransfer.sol";

import {SafeCastTemp} from "../libraries/SafeCast.sol";
import {BaseActionsRouter} from "../base/BaseActionsRouter.sol";
import {ReentrancyLock} from "../base/ReentrancyLock.sol";
import {DeltaResolver} from "../base/DeltaResolver.sol";
import {Permit2Forwarder} from "../base/Permit2Forwarder.sol";
import {IPositionManager} from "../interfaces/IPositionManager.sol";
import {IBinPositionManager} from "./interfaces/IBinPositionManager.sol";
import {CalldataDecoder} from "../libraries/CalldataDecoder.sol";
import {Actions} from "../libraries/Actions.sol";
import {BinCalldataDecoder} from "./libraries/BinCalldataDecoder.sol";
import {BinFungibleToken} from "./BinFungibleToken.sol";
import {BinTokenLibrary} from "./libraries/BinTokenLibrary.sol";
import {Multicall} from "../base/Multicall.sol";
import {SlippageCheck} from "../libraries/SlippageCheck.sol";
import {NativeWrapper} from "../base/NativeWrapper.sol";
import {IWETH9} from "../interfaces/external/IWETH9.sol";

/// @title BinPositionManager
/// @notice Contract for modifying liquidity for PCS infinity Bin pools
contract BinPositionManager is
    IBinPositionManager,
    BinFungibleToken,
    DeltaResolver,
    ReentrancyLock,
    BaseActionsRouter,
    Permit2Forwarder,
    Multicall,
    NativeWrapper
{
    using CalldataDecoder for bytes;
    using PackedUint128Math for uint128;
    using BinCalldataDecoder for bytes;
    using BinTokenLibrary for PoolId;
    using BinPoolParametersHelper for bytes32;
    using SlippageCheck for BalanceDelta;
    using SafeCastTemp for uint256;

    IBinPoolManager public immutable override binPoolManager;

    struct TokenPosition {
        PoolId poolId;
        uint24 binId;
    }

    /// @dev tokenId => TokenPosition
    mapping(uint256 => TokenPosition) private _positions;

    /// @dev poolId => poolKey
    mapping(bytes32 => PoolKey) private _poolIdToPoolKey;

    constructor(IVault _vault, IBinPoolManager _binPoolManager, IAllowanceTransfer _permit2, IWETH9 _weth9)
        BaseActionsRouter(_vault)
        Permit2Forwarder(_permit2)
        NativeWrapper(_weth9)
    {
        binPoolManager = _binPoolManager;
    }

    /// @notice Reverts if the deadline has passed
    /// @param deadline The timestamp at which the call is no longer valid, passed in by the caller
    modifier checkDeadline(uint256 deadline) {
        if (block.timestamp > deadline) revert DeadlinePassed(deadline);
        _;
    }

    /// @notice Enforces that the vault is unlocked.
    modifier onlyIfVaultUnlocked() override {
        if (vault.getLocker() != address(0)) revert VaultMustBeUnlocked();
        _;
    }

    /// @inheritdoc IBinPositionManager
    function positions(uint256 tokenId) external view returns (PoolKey memory, uint24) {
        TokenPosition memory position = _positions[tokenId];

        if (PoolId.unwrap(position.poolId) == 0) revert InvalidTokenID();
        PoolKey memory poolKey = _poolIdToPoolKey[PoolId.unwrap(position.poolId)];

        return (poolKey, position.binId);
    }

    /// @inheritdoc IPositionManager
    function modifyLiquidities(bytes calldata payload, uint256 deadline)
        external
        payable
        override
        isNotLocked
        checkDeadline(deadline)
    {
        _executeActions(payload);
    }

    /// @inheritdoc IPositionManager
    function modifyLiquiditiesWithoutLock(bytes calldata actions, bytes[] calldata params)
        external
        payable
        override
        isNotLocked
    {
        _executeActionsWithoutLock(actions, params);
    }

    /// @inheritdoc IBinPositionManager
    function initializePool(PoolKey memory key, uint24 activeId) external payable {
        /// @dev if the pool revert due to other error (currencyOutOfOrder etc..), then the follow-up action to the pool will still revert accordingly
        try binPoolManager.initialize(key, activeId) {} catch {}
    }

    function msgSender() public view override returns (address) {
        return _getLocker();
    }

    function _handleAction(uint256 action, bytes calldata params) internal virtual override {
        if (action > Actions.BURN_6909) {
            if (action == Actions.BIN_ADD_LIQUIDITY) {
                IBinPositionManager.BinAddLiquidityParams calldata liquidityParams =
                    params.decodeBinAddLiquidityParams();
                _addLiquidity(
                    liquidityParams.poolKey,
                    liquidityParams.amount0,
                    liquidityParams.amount1,
                    liquidityParams.amount0Max,
                    liquidityParams.amount1Max,
                    liquidityParams.activeIdDesired,
                    liquidityParams.idSlippage,
                    liquidityParams.deltaIds,
                    liquidityParams.distributionX,
                    liquidityParams.distributionY,
                    liquidityParams.to,
                    liquidityParams.hookData
                );
                return;
            } else if (action == Actions.BIN_ADD_LIQUIDITY_FROM_DELTAS) {
                IBinPositionManager.BinAddLiquidityFromDeltasParams calldata liquidityParams =
                    params.decodeBinAddLiquidityFromDeltasParams();
                _addLiquidity(
                    liquidityParams.poolKey,
                    _getFullCredit(liquidityParams.poolKey.currency0).toUint128(),
                    _getFullCredit(liquidityParams.poolKey.currency1).toUint128(),
                    liquidityParams.amount0Max,
                    liquidityParams.amount1Max,
                    liquidityParams.activeIdDesired,
                    liquidityParams.idSlippage,
                    liquidityParams.deltaIds,
                    liquidityParams.distributionX,
                    liquidityParams.distributionY,
                    liquidityParams.to,
                    liquidityParams.hookData
                );
                return;
            } else if (action == Actions.BIN_REMOVE_LIQUIDITY) {
                IBinPositionManager.BinRemoveLiquidityParams calldata liquidityParams =
                    params.decodeBinRemoveLiquidityParams();
                _removeLiquidity(liquidityParams);
                return;
            }
        } else {
            if (action == Actions.SETTLE_PAIR) {
                (Currency currency0, Currency currency1) = params.decodeCurrencyPair();
                _settlePair(currency0, currency1);
                return;
            } else if (action == Actions.TAKE_PAIR) {
                (Currency currency0, Currency currency1, address recipient) = params.decodeCurrencyPairAndAddress();
                _takePair(currency0, currency1, _mapRecipient(recipient));
                return;
            } else if (action == Actions.SETTLE) {
                (Currency currency, uint256 amount, bool payerIsUser) = params.decodeCurrencyUint256AndBool();
                _settle(currency, _mapPayer(payerIsUser), _mapSettleAmount(amount, currency));
                return;
            } else if (action == Actions.TAKE) {
                (Currency currency, address recipient, uint256 amount) = params.decodeCurrencyAddressAndUint256();
                _take(currency, _mapRecipient(recipient), _mapTakeAmount(amount, currency));
                return;
            } else if (action == Actions.CLOSE_CURRENCY) {
                Currency currency = params.decodeCurrency();
                _close(currency);
                return;
            } else if (action == Actions.CLEAR_OR_TAKE) {
                (Currency currency, uint256 amountMax) = params.decodeCurrencyAndUint256();
                _clearOrTake(currency, amountMax);
                return;
            } else if (action == Actions.SWEEP) {
                (Currency currency, address to) = params.decodeCurrencyAndAddress();
                _sweep(currency, _mapRecipient(to));
                return;
            } else if (action == Actions.WRAP) {
                uint256 amount = params.decodeUint256();
                _wrap(_mapWrapUnwrapAmount(CurrencyLibrary.NATIVE, amount, Currency.wrap(address(WETH9))));
                return;
            } else if (action == Actions.UNWRAP) {
                uint256 amount = params.decodeUint256();
                _unwrap(_mapWrapUnwrapAmount(Currency.wrap(address(WETH9)), amount, CurrencyLibrary.NATIVE));
                return;
            }
        }
        revert UnsupportedAction(action);
    }

    /// @dev Store poolKey in mapping for lookup
    function cachePoolKey(PoolKey memory poolKey) internal returns (PoolId poolId) {
        poolId = poolKey.toId();

        if (_poolIdToPoolKey[PoolId.unwrap(poolId)].parameters.getBinStep() == 0) {
            _poolIdToPoolKey[PoolId.unwrap(poolId)] = poolKey;
        }
    }

    function _addLiquidity(
        PoolKey calldata poolKey,
        uint128 amount0,
        uint128 amount1,
        uint128 amount0Max,
        uint128 amount1Max,
        uint256 activeIdDesired,
        uint256 idSlippage,
        int256[] calldata deltaIds,
        uint256[] calldata distributionX,
        uint256[] calldata distributionY,
        address to,
        bytes calldata hookData
    ) internal {
        uint256 deltaLen = deltaIds.length;
        uint256 lenX = distributionX.length;
        uint256 lenY = distributionY.length;
        assembly ("memory-safe") {
            /// @dev revert if deltaLen != lenX || deltaLen != lenY
            if iszero(and(eq(deltaLen, lenX), eq(deltaLen, lenY))) {
                mstore(0, 0xaaad13f7) // selector InputLengthMismatch
                revert(0x1c, 0x04)
            }
        }

        if (activeIdDesired > type(uint24).max || idSlippage > type(uint24).max) {
            revert AddLiquidityInputActiveIdMismatch();
        }

        /// @dev Checks if the activeId is within slippage before calling mint. If user mint to activeId and there
        //       was a swap in hook.beforeMint() which changes the activeId, user txn will fail
        (uint24 activeId,,) = binPoolManager.getSlot0(poolKey.toId());
        if (activeIdDesired + idSlippage < activeId) {
            revert IdSlippageCaught(activeIdDesired, idSlippage, activeId);
        }
        if (activeIdDesired - idSlippage > activeId) {
            revert IdSlippageCaught(activeIdDesired, idSlippage, activeId);
        }

        bytes32[] memory liquidityConfigs = new bytes32[](deltaLen);
        for (uint256 i; i < liquidityConfigs.length; i++) {
            int256 _id = int256(uint256(activeId)) + deltaIds[i];
            if (_id < 0 || uint256(_id) > type(uint24).max) revert IdOverflows(_id);

            liquidityConfigs[i] = LiquidityConfigurations.encodeParams(
                uint64(distributionX[i]), uint64(distributionY[i]), uint24(uint256(_id))
            );
        }

        bytes32 amountIn = amount0.encode(amount1);
        (BalanceDelta delta, BinPool.MintArrays memory mintArray) = binPoolManager.mint(
            poolKey,
            IBinPoolManager.MintParams({liquidityConfigs: liquidityConfigs, amountIn: amountIn, salt: bytes32(0)}),
            hookData
        );

        /// Slippage checks, similar to CL type. However, this is different from TJ. In PCS infinity,
        /// as hooks can impact delta (take extra token), user need to be protected with amountMax instead
        delta.validateMaxIn(amount0Max, amount1Max);

        // mint
        PoolId poolId = cachePoolKey(poolKey);
        uint256[] memory tokenIds = new uint256[](mintArray.ids.length);
        for (uint256 i; i < mintArray.ids.length; i++) {
            uint256 tokenId = poolId.toTokenId(mintArray.ids[i]);
            _mint(to, tokenId, mintArray.liquidityMinted[i]);

            if (_positions[tokenId].binId == 0) {
                _positions[tokenId] = TokenPosition({poolId: poolId, binId: uint24(mintArray.ids[i])});
            }

            tokenIds[i] = tokenId;
        }

        emit TransferBatch(msgSender(), address(0), to, tokenIds, mintArray.liquidityMinted);
    }

    function _removeLiquidity(IBinPositionManager.BinRemoveLiquidityParams calldata params)
        internal
        checkApproval(params.from, msgSender())
    {
        if (params.ids.length != params.amounts.length) revert InputLengthMismatch();

        BalanceDelta delta = binPoolManager.burn(
            params.poolKey,
            IBinPoolManager.BurnParams({ids: params.ids, amountsToBurn: params.amounts, salt: bytes32(0)}),
            params.hookData
        );

        // Slippage checks, similar to CL type, if delta is negative, it will revert.
        delta.validateMinOut(params.amount0Min, params.amount1Min);

        PoolId poolId = params.poolKey.toId();
        uint256[] memory tokenIds = new uint256[](params.ids.length);
        for (uint256 i; i < params.ids.length; i++) {
            uint256 tokenId = poolId.toTokenId(params.ids[i]);
            _burn(params.from, tokenId, params.amounts[i]);

            tokenIds[i] = tokenId;
        }

        emit TransferBatch(msgSender(), params.from, address(0), tokenIds, params.amounts);
    }

    function _settlePair(Currency currency0, Currency currency1) internal {
        // the locker is the payer when settling
        address caller = msgSender();
        _settle(currency0, caller, _getFullDebt(currency0));
        _settle(currency1, caller, _getFullDebt(currency1));
    }

    function _takePair(Currency currency0, Currency currency1, address recipient) internal {
        _take(currency0, recipient, _getFullCredit(currency0));
        _take(currency1, recipient, _getFullCredit(currency1));
    }

    function _close(Currency currency) internal {
        // this address has applied all deltas on behalf of the user/owner
        // it is safe to close this entire delta because of slippage checks throughout the batched calls.
        int256 currencyDelta = vault.currencyDelta(address(this), currency);

        // the locker is the payer or receiver
        address caller = msgSender();
        if (currencyDelta < 0) {
            _settle(currency, caller, uint256(-currencyDelta));
        } else {
            _take(currency, caller, uint256(currencyDelta));
        }
    }

    /// @dev integrators may elect to forfeit positive deltas with clear
    /// if the forfeit amount exceeds the user-specified max, the amount is taken instead
    function _clearOrTake(Currency currency, uint256 amountMax) internal {
        uint256 delta = _getFullCredit(currency);

        // forfeit the delta if its less than or equal to the user-specified limit
        if (delta <= amountMax) {
            vault.clear(currency, delta);
        } else {
            _take(currency, msgSender(), delta);
        }
    }

    /// @notice Sweeps the entire contract balance of specified currency to the recipient
    function _sweep(Currency currency, address to) internal {
        uint256 balance = currency.balanceOfSelf();
        if (balance > 0) currency.transfer(to, balance);
    }

    function _pay(Currency currency, address payer, uint256 amount) internal override(DeltaResolver) {
        if (payer == address(this)) {
            currency.transfer(address(vault), amount);
        } else {
            permit2.transferFrom(payer, address(vault), uint160(amount), Currency.unwrap(currency));
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre BinPositionManager
Buscando 'BinPositionManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (4ms)


### HIGH findings en dominio dex
Buscando 'BinPositionManager' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (1ms)

### Cross-domain HIGH relevantes
Buscando 'BinPositionManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

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
2. **Identifica** las funciones donde tu especialidad (Protocol-specific invariants) es relevante
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
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_BinPositionManager_DomainHunter.yaml`

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

## Symmetric Inspection (OBLIGATORIO — después de tu análisis de dominio)
Identifica TODOS los pares simétricos del contrato. Pares comunes:
  deposit/withdraw, mint/burn, lock/unlock, stake/unstake, borrow/repay, open/close

Para CADA par, verifica estas 5 dimensiones:
1. **State variables**: ¿ambas funciones actualizan las mismas variables (en dirección opuesta)?
2. **Validaciones**: ¿mismas validaciones (o su inversa lógica)?
3. **Events**: ¿ambas emiten el evento correspondiente?
4. **Modifiers**: ¿mismos modifiers aplicados (nonReentrant, whenNotPaused)?
5. **Edge cases**: ¿amount=0, amount=max, balance=0 manejados simétricamente?

Cualquier asimetría es un candidato a invariante. Documenta qué variable/check/event falta en qué función.
Bug real: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M.

## Constraint Inference (0xRajeev — OBLIGATORIO)
Para cada validación/require que encuentres:
1. Observa qué se valida en N-1 code paths que hacen algo similar.
2. El path que NO tiene esa validación es el bug candidato.
Ejemplo: si 5 de 6 funciones de withdraw verifican healthFactor, la 6ta que no lo hace es sospechosa.

## Traza Hacia Atrás (samczsun — MENTALIDAD)
No empieces preguntando "¿hay un bug aquí?". Empieza preguntando:
"¿De dónde puede SALIR valor del protocolo?" (withdraw, redeem, liquidate, claim, transfer).
Para cada punto de salida, traza HACIA ATRÁS: ¿qué condiciones se deben cumplir? ¿Se pueden manipular?

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
