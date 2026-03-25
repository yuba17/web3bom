# Contexto de Hunt — BinPoolManager

**Protocolo**: pancakeswap-infinity
**Dominio**: oracle
**LOC**: 230
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-core/src/pool-bin/BinPoolManager.sol
**Generado**: 2026-03-23T06:21:58.201676Z

## Solodit Context
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

## Briefing del Dominio
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
[ ] Check: mi

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

# Deep Flatten — BinPoolManager

Funciones analizadas: 16


## setProtocolFee(PoolKey,uint24) [CRITICAL — mueve fondos]

[FUNC] [ProtocolFees:L34-40] setProtocolFee(PoolKey,uint24)
    READ: protocolFeeController
    [EXTERNAL] ProtocolFeeLibrary.TMP_309(bool) = LIBRARY_CALL, dest:ProtocolFeeLibrary, function:ProtocolFeeLibrary.validate(uint24), arguments:['newProtocolFee'] 
    [EXTERNAL] PoolIdLibrary.TMP_312(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 

## collectProtocolFees(address,Currency,uint256) [CRITICAL — mueve fondos]

[FUNC] [ProtocolFees:L85-95] collectProtocolFees(address,Currency,uint256)
    READ: protocolFeeController
    READ: protocolFeesAccrued
    READ: vault
    WRITE: protocolFeesAccrued
    [EXTERNAL] IVault.HIGH_LEVEL_CALL, dest:vault(IVault), function:collectFee, arguments:['currency', 'amountCollected', 'recipient']  

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [Ownable:L57-62] transferOwnership(address)
  [MODIFIER] onlyOwner()

## mint(PoolKey,IBinPoolManager.MintParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [IBinPoolManager:L177-179] mint(PoolKey,IBinPoolManager.MintParams,bytes)

## burn(PoolKey,IBinPoolManager.BurnParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [IBinPoolManager:L183-185] burn(PoolKey,IBinPoolManager.BurnParams,bytes)

## swap(PoolKey,bool,int128,bytes) [CRITICAL — mueve fondos]

[FUNC] [IBinPoolManager:L191-193] swap(PoolKey,bool,int128,bytes)

## getSlot0(PoolId) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L59-63] getSlot0(PoolId)
    READ: pools
    [EXTERNAL] BinSlot0Library.TMP_369(uint24) = LIBRARY_CALL, dest:BinSlot0Library, function:BinSlot0Library.activeId(BinSlot0), arguments:['slot0'] 
    [EXTERNAL] BinSlot0Library.TMP_370(uint24) = LIBRARY_CALL, dest:BinSlot0Library, function:BinSlot0Library.protocolFee(BinSlot0), arguments:['slot0'] 
    [EXTERNAL] BinSlot0Library.TMP_371(uint24) = LIBRARY_CALL, dest:BinSlot0Library, function:BinSlot0Library.lpFee(BinSlot0), arguments:['slot0'] 

## getBin(PoolId,uint24) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L66-74] getBin(PoolId,uint24)
    READ: poolIdToPoolKey
    READ: pools
    [EXTERNAL] BinPoolParametersHelper.TMP_372(uint16) = LIBRARY_CALL, dest:BinPoolParametersHelper, function:BinPoolParametersHelper.getBinStep(bytes32), arguments:['REF_56'] 
    [EXTERNAL] BinPool.TUPLE_0(uint128,uint128,uint256,uint256) = LIBRARY_CALL, dest:BinPool, function:BinPool.getBin(BinPool.State,uint16,uint24), arguments:['REF_54', 'TMP_372', 'binId'] 

## getPosition(PoolId,address,uint24,bytes32) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L77-84] getPosition(PoolId,address,uint24,bytes32)
    READ: pools
    [EXTERNAL] BinPosition.TMP_373(BinPosition.Info) = LIBRARY_CALL, dest:BinPosition, function:BinPosition.get(mapping(bytes32 => BinPosition.Info),address,uint24,bytes32), arguments:['REF_59', 'owner', 'binId', 'salt'] 

## getNextNonEmptyBin(PoolId,bool,uint24) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L87-94] getNextNonEmptyBin(PoolId,bool,uint24)
    READ: pools
    [EXTERNAL] BinPool.TMP_374(uint24) = LIBRARY_CALL, dest:BinPool, function:BinPool.getNextNonEmptyBin(BinPool.State,bool,uint24), arguments:['REF_61', 'swapForY', 'binId'] 

## initialize(PoolKey,uint24) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L97-135] initialize(PoolKey,uint24)
  [MODIFIER] poolManagerMatch(address)
    READ: MIN_BIN_STEP
    READ: maxBinStep
    READ: pools
    WRITE: poolIdToPoolKey
    [EXTERNAL] Hooks.LIBRARY_CALL, dest:Hooks, function:Hooks.validateHookConfig(PoolKey), arguments:['key'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.afterInitialize(PoolKey,uint24), arguments:['key', 'activeId'] 
    [EXTERNAL] PoolIdLibrary.TMP_391(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] LPFeeLibrary.TMP_388(uint24) = LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.getInitialLPFee(uint24), arguments:['REF_75'] 
    [EXTERNAL] BinPoolParametersHelper.TMP_375(uint16) = LIBRARY_CALL, dest:BinPoolParametersHelper, function:BinPoolParametersHelper.getBinStep(bytes32), arguments:['REF_63'] 
    [EXTERNAL] LPFeeLibrary.LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.validate(uint24,uint24), arguments:['lpFee', 'REF_78'] 
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.initialize(BinPool.State,uint24,uint24,uint24), arguments:['REF_81', 'activeId', 'protocolFee', 'lpFee'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.validatePermissionsConflict(PoolKey), arguments:['key'] 
    [EXTERNAL] PriceHelper.TMP_384(uint256) = LIBRARY_CALL, dest:PriceHelper, function:PriceHelper.getPriceFromId(uint24,uint16), arguments:['activeId', 'binStep'] 
    [EXTERNAL] ParametersHelper.LIBRARY_CALL, dest:ParametersHelper, function:ParametersHelper.checkUnusedBitsAllZero(bytes32,uint256), arguments:['REF_71', 'REF_72'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.beforeInitialize(PoolKey,uint24), arguments:['key', 'activeId'] 

## swap(PoolKey,bool,int128,bytes) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L138-182] swap(PoolKey,bool,int128,bytes)
  [MODIFIER] whenNotPaused()
    READ: pools
    READ: protocolFeesAccrued
    READ: vault
    WRITE: protocolFeesAccrued
    [EXTERNAL] PackedUint128Math.TMP_405(uint128) = LIBRARY_CALL, dest:PackedUint128Math, function:PackedUint128Math.decodeX(bytes32), arguments:['REF_102'] 
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.checkPoolInitialized(BinPool.State), arguments:['pool'] 
    [EXTERNAL] VaultAppDeltaSettlement.LIBRARY_CALL, dest:VaultAppDeltaSettlement, function:VaultAppDeltaSettlement.accountAppDeltaWithHookDelta(IVault,PoolKey,BalanceDelta,BalanceDelta), arguments:['vault', 'key', 'delta', 'hookDelta'] 
    [EXTERNAL] PackedUint128Math.TMP_406(uint128) = LIBRARY_CALL, dest:PackedUint128Math, function:PackedUint128Math.decodeY(bytes32), arguments:['REF_106'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_407(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount0(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] BinPoolParametersHelper.TMP_402(uint16) = LIBRARY_CALL, dest:BinPoolParametersHelper, function:BinPoolParametersHelper.getBinStep(bytes32), arguments:['REF_97'] 
    [EXTERNAL] PoolIdLibrary.TMP_400(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] BinPool.TUPLE_2(BalanceDelta,BinPool.SwapState) = LIBRARY_CALL, dest:BinPool, function:BinPool.swap(BinPool.State,BinPool.SwapParams), arguments:['pool', 'TMP_403'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_408(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount1(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] BinHooks.TUPLE_3(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:BinHooks, function:BinHooks.afterSwap(PoolKey,bool,int128,BalanceDelta,bytes,BeforeSwapDelta), arguments:['key', 'swapForY', 'amountSpecified', 'delta', 'hookData', 'beforeSwapDelta'] 
    [EXTERNAL] BinHooks.TUPLE_1(int128,BeforeSwapDelta,uint24) = LIBRARY_CALL, dest:BinHooks, function:BinHooks.beforeSwap(PoolKey,bool,int128,bytes), arguments:['key', 'swapForY', 'amountSpecified', 'hookData'] 

## mint(PoolKey,IBinPoolManager.MintParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L185-226] mint(PoolKey,IBinPoolManager.MintParams,bytes)
  [MODIFIER] whenNotPaused()
    READ: pools
    READ: protocolFeesAccrued
    READ: vault
    WRITE: protocolFeesAccrued
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.checkPoolInitialized(BinPool.State), arguments:['pool'] 
    [EXTERNAL] BinHooks.TMP_414(uint24) = LIBRARY_CALL, dest:BinHooks, function:BinHooks.beforeMint(PoolKey,IBinPoolManager.MintParams,bytes), arguments:['key', 'params', 'hookData'] 
    [EXTERNAL] PoolIdLibrary.TMP_412(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] BinPool.TUPLE_4(BalanceDelta,bytes32,BinPool.MintArrays,bytes32) = LIBRARY_CALL, dest:BinPool, function:BinPool.mint(BinPool.State,BinPool.MintParams), arguments:['pool', 'TMP_416'] 
    [EXTERNAL] PackedUint128Math.TMP_419(uint128) = LIBRARY_CALL, dest:PackedUint128Math, function:PackedUint128Math.decodeY(bytes32), arguments:['feeAmountToProtocol'] 
    [EXTERNAL] VaultAppDeltaSettlement.LIBRARY_CALL, dest:VaultAppDeltaSettlement, function:VaultAppDeltaSettlement.accountAppDeltaWithHookDelta(IVault,PoolKey,BalanceDelta,BalanceDelta), arguments:['vault', 'key', 'delta', 'hookDelta'] 
    [EXTERNAL] BinHooks.TUPLE_5(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:BinHooks, function:BinHooks.afterMint(PoolKey,IBinPoolManager.MintParams,BalanceDelta,bytes), arguments:['key', 'params', 'delta', 'hookData'] 
    [EXTERNAL] PackedUint128Math.TMP_418(uint128) = LIBRARY_CALL, dest:PackedUint128Math, function:PackedUint128Math.decodeX(bytes32), arguments:['feeAmountToProtocol'] 
    [EXTERNAL] BinPoolParametersHelper.TMP_415(uint16) = LIBRARY_CALL, dest:BinPoolParametersHelper, function:BinPoolParametersHelper.getBinStep(bytes32), arguments:['REF_123'] 

## burn(PoolKey,IBinPoolManager.BurnParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L229-258] burn(PoolKey,IBinPoolManager.BurnParams,bytes)
    READ: pools
    READ: vault
    [EXTERNAL] BinPool.TUPLE_6(BalanceDelta,uint256[],bytes32[]) = LIBRARY_CALL, dest:BinPool, function:BinPool.burn(BinPool.State,BinPool.BurnParams), arguments:['pool', 'TMP_426'] 
    [EXTERNAL] VaultAppDeltaSettlement.LIBRARY_CALL, dest:VaultAppDeltaSettlement, function:VaultAppDeltaSettlement.accountAppDeltaWithHookDelta(IVault,PoolKey,BalanceDelta,BalanceDelta), arguments:['vault', 'key', 'delta', 'hookDelta'] 
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.checkPoolInitialized(BinPool.State), arguments:['pool'] 
    [EXTERNAL] BinHooks.TUPLE_7(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:BinHooks, function:BinHooks.afterBurn(PoolKey,IBinPoolManager.BurnParams,BalanceDelta,bytes), arguments:['key', 'params', 'delta', 'hookData'] 
    [EXTERNAL] PoolIdLibrary.TMP_423(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.beforeBurn(PoolKey,IBinPoolManager.BurnParams,bytes), arguments:['key', 'params', 'hookData'] 

## donate(PoolKey,uint128,uint128,bytes) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L260-286] donate(PoolKey,uint128,uint128,bytes)
  [MODIFIER] whenNotPaused()
    READ: minBinShareForDonate
    READ: pools
    READ: vault
    [EXTERNAL] PoolIdLibrary.TMP_429(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_438(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount1(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] BinPool.TUPLE_8(BalanceDelta,uint24) = LIBRARY_CALL, dest:BinPool, function:BinPool.donate(BinPool.State,uint16,uint128,uint128), arguments:['pool', 'TMP_435', 'amount0', 'amount1'] 
    [EXTERNAL] BinPoolParametersHelper.TMP_435(uint16) = LIBRARY_CALL, dest:BinPoolParametersHelper, function:BinPoolParametersHelper.getBinStep(bytes32), arguments:['REF_158'] 
    [EXTERNAL] IVault.HIGH_LEVEL_CALL, dest:vault(IVault), function:accountAppBalanceDelta, arguments:['REF_161', 'REF_162', 'delta', 'msg.sender']  
    [EXTERNAL] BinSlot0Library.TMP_432(uint24) = LIBRARY_CALL, dest:BinSlot0Library, function:BinSlot0Library.activeId(BinSlot0), arguments:['REF_154'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_437(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount0(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.afterDonate(PoolKey,uint128,uint128,bytes), arguments:['key', 'amount0', 'amount1', 'hookData'] 
    [EXTERNAL] BinHooks.LIBRARY_CALL, dest:BinHooks, function:BinHooks.beforeDonate(PoolKey,uint128,uint128,bytes), arguments:['key', 'amount0', 'amount1', 'hookData'] 
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.checkPoolInitialized(BinPool.State), arguments:['pool'] 

## updateDynamicLPFee(PoolKey,uint24) [CRITICAL — mueve fondos]

[FUNC] [BinPoolManager:L303-310] updateDynamicLPFee(PoolKey,uint24)
    READ: pools
    [EXTERNAL] LPFeeLibrary.TMP_448(bool) = LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.isDynamicLPFee(uint24), arguments:['REF_166'] 
    [EXTERNAL] LPFeeLibrary.LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.validate(uint24,uint24), arguments:['newDynamicLPFee', 'REF_170'] 
    [EXTERNAL] BinPool.LIBRARY_CALL, dest:BinPool, function:BinPool.setLPFee(BinPool.State,uint24), arguments:['REF_172', 'newDynamicLPFee'] 
    [EXTERNAL] PoolIdLibrary.TMP_455(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `getSlot0()` (L59)
```solidity
    function getSlot0(PoolId id) external view override returns (uint24 activeId, uint24 protocolFee, uint24 lpFee) {
        BinSlot0 slot0 = pools[id].slot0;

        return (slot0.activeId(), slot0.protocolFee(), slot0.lpFee());
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `setMaxBinStep()` (L289)
```solidity
    function setMaxBinStep(uint16 newMaxBinStep) external override onlyOwner {
        if (newMaxBinStep <= MIN_BIN_STEP) revert MaxBinStepTooSmall(newMaxBinStep);

        maxBinStep = newMaxBinStep;
        emit SetMaxBinStep(newMaxBinStep);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `setMinBinSharesForDonate()` (L297)
```solidity
    function setMinBinSharesForDonate(uint256 minBinShare) external override onlyOwner {
        minBinShareForDonate = minBinShare;
        emit SetMinBinSharesForDonate(minBinShare);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `updateDynamicLPFee()` (L303)
```solidity
    function updateDynamicLPFee(PoolKey memory key, uint24 newDynamicLPFee) external override {
        if (!key.fee.isDynamicLPFee() || msg.sender != address(key.hooks)) revert UnauthorizedDynamicLPFeeUpdate();
        newDynamicLPFee.validate(LPFeeLibrary.TEN_PERCENT_FEE);

        PoolId id = key.toId();
        pools[id].setLPFee(newDynamicLPFee);
        emit DynamicLPFeeUpdated(id, newDynamicLPFee);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `_setProtocolFee()` (L312)
```solidity
    function _setProtocolFee(PoolId id, uint24 newProtocolFee) internal override {
        pools[id].setProtocolFee(newProtocolFee);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

## Symmetric Analysis
# Symmetric Analysis Report

Pares encontrados: 1


## Par: mint/burn

### State Variables Written
| Variable | mint | burn |
|----------|:---:|:---:|
| **protocolFeesAccrued** | **YES** | **NO** |

### Modifiers
- **whenNotPaused**: solo en mint, falta en burn


---
## Resumen
- Pares analizados: 1
- **Asimetrías encontradas: 2**
- Cada asimetría es un candidato a invariante. Investigar si es by-design o bug.

Bug real de referencia: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M

