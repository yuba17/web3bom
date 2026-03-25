# Contexto de Hunt — CLPoolManager

**Protocolo**: pancakeswap-infinity
**Dominio**: dex
**LOC**: 202
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-core/src/pool-cl/CLPoolManager.sol
**Generado**: 2026-03-23T01:22:28.157292Z

## Solodit Context
No disponible

## Briefing del Dominio
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
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0)

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

# Deep Flatten — CLPoolManager

Funciones analizadas: 15


## setProtocolFee(PoolKey,uint24) [CRITICAL — mueve fondos]

[FUNC] [ProtocolFees:L34-40] setProtocolFee(PoolKey,uint24)
    READ: protocolFeeController
    [EXTERNAL] PoolIdLibrary.TMP_312(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] ProtocolFeeLibrary.TMP_309(bool) = LIBRARY_CALL, dest:ProtocolFeeLibrary, function:ProtocolFeeLibrary.validate(uint24), arguments:['newProtocolFee'] 

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

## swap(PoolKey,ICLPoolManager.SwapParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [ICLPoolManager:L164-166] swap(PoolKey,ICLPoolManager.SwapParams,bytes)

## getSlot0(PoolId) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L52-60] getSlot0(PoolId)
    READ: pools
    [EXTERNAL] CLSlot0Library.TMP_369(uint160) = LIBRARY_CALL, dest:CLSlot0Library, function:CLSlot0Library.sqrtPriceX96(CLSlot0), arguments:['slot0'] 
    [EXTERNAL] CLSlot0Library.TMP_370(int24) = LIBRARY_CALL, dest:CLSlot0Library, function:CLSlot0Library.tick(CLSlot0), arguments:['slot0'] 
    [EXTERNAL] CLSlot0Library.TMP_371(uint24) = LIBRARY_CALL, dest:CLSlot0Library, function:CLSlot0Library.protocolFee(CLSlot0), arguments:['slot0'] 
    [EXTERNAL] CLSlot0Library.TMP_372(uint24) = LIBRARY_CALL, dest:CLSlot0Library, function:CLSlot0Library.lpFee(CLSlot0), arguments:['slot0'] 

## getLiquidity(PoolId,address,int24,int24,bytes32) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L68-75] getLiquidity(PoolId,address,int24,int24,bytes32)
    READ: pools
    [EXTERNAL] CLPosition.TMP_373(CLPosition.Info) = LIBRARY_CALL, dest:CLPosition, function:CLPosition.get(mapping(bytes32 => CLPosition.Info),address,int24,int24,bytes32), arguments:['REF_57', '_owner', 'tickLower', 'tickUpper', 'salt'] 

## getPosition(PoolId,address,int24,int24,bytes32) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L78-85] getPosition(PoolId,address,int24,int24,bytes32)
    READ: pools
    [EXTERNAL] CLPosition.TMP_374(CLPosition.Info) = LIBRARY_CALL, dest:CLPosition, function:CLPosition.get(mapping(bytes32 => CLPosition.Info),address,int24,int24,bytes32), arguments:['REF_61', 'owner', 'tickLower', 'tickUpper', 'salt'] 

## initialize(PoolKey,uint160) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L88-123] initialize(PoolKey,uint160)
  [MODIFIER] poolManagerMatch(address)
    READ: pools
    WRITE: poolIdToPoolKey
    [EXTERNAL] ParametersHelper.LIBRARY_CALL, dest:ParametersHelper, function:ParametersHelper.checkUnusedBitsAllZero(bytes32,uint256), arguments:['REF_72', 'REF_73'] 
    [EXTERNAL] LPFeeLibrary.LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.validate(uint24,uint24), arguments:['lpFee', 'REF_79'] 
    [EXTERNAL] PoolIdLibrary.TMP_390(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] CLPool.TMP_392(int24) = LIBRARY_CALL, dest:CLPool, function:CLPool.initialize(CLPool.State,uint160,uint24,uint24), arguments:['REF_82', 'sqrtPriceX96', 'protocolFee', 'lpFee'] 
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.validatePermissionsConflict(PoolKey), arguments:['key'] 
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.beforeInitialize(PoolKey,uint160), arguments:['key', 'sqrtPriceX96'] 
    [EXTERNAL] CLPoolParametersHelper.TMP_375(int24) = LIBRARY_CALL, dest:CLPoolParametersHelper, function:CLPoolParametersHelper.getTickSpacing(bytes32), arguments:['REF_63'] 
    [EXTERNAL] Hooks.LIBRARY_CALL, dest:Hooks, function:Hooks.validateHookConfig(PoolKey), arguments:['key'] 
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.afterInitialize(PoolKey,uint160,int24), arguments:['key', 'sqrtPriceX96', 'tick'] 
    [EXTERNAL] LPFeeLibrary.TMP_387(uint24) = LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.getInitialLPFee(uint24), arguments:['REF_76'] 

## modifyLiquidity(PoolKey,ICLPoolManager.ModifyLiquidityParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L126-159] modifyLiquidity(PoolKey,ICLPoolManager.ModifyLiquidityParams,bytes)
    READ: pools
    READ: vault
    [EXTERNAL] CLPoolParametersHelper.TMP_405(int24) = LIBRARY_CALL, dest:CLPoolParametersHelper, function:CLPoolParametersHelper.getTickSpacing(bytes32), arguments:['REF_103'] 
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.beforeModifyLiquidity(PoolKey,ICLPoolManager.ModifyLiquidityParams,bytes), arguments:['key', 'params', 'hookData'] 
    [EXTERNAL] SafeCast.TMP_404(int128) = LIBRARY_CALL, dest:SafeCast, function:SafeCast.toInt128(int256), arguments:['REF_101'] 
    [EXTERNAL] VaultAppDeltaSettlement.LIBRARY_CALL, dest:VaultAppDeltaSettlement, function:VaultAppDeltaSettlement.accountAppDeltaWithHookDelta(IVault,PoolKey,BalanceDelta,BalanceDelta), arguments:['vault', 'key', 'delta', 'hookDelta'] 
    [EXTERNAL] PoolIdLibrary.TMP_401(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] CLPool.LIBRARY_CALL, dest:CLPool, function:CLPool.checkPoolInitialized(CLPool.State), arguments:['pool'] 
    [EXTERNAL] CLPool.TUPLE_0(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:CLPool, function:CLPool.modifyLiquidity(CLPool.State,CLPool.ModifyLiquidityParams), arguments:['pool', 'TMP_406'] 
    [EXTERNAL] CLHooks.TUPLE_1(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:CLHooks, function:CLHooks.afterModifyLiquidity(PoolKey,ICLPoolManager.ModifyLiquidityParams,BalanceDelta,BalanceDelta,bytes), arguments:['key', 'params', 'TMP_408', 'feeDelta', 'hookData'] 

## swap(PoolKey,ICLPoolManager.SwapParams,bytes) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L162-212] swap(PoolKey,ICLPoolManager.SwapParams,bytes)
  [MODIFIER] whenNotPaused()
    READ: pools
    READ: protocolFeesAccrued
    READ: vault
    WRITE: protocolFeesAccrued
    [EXTERNAL] CLHooks.TUPLE_2(int256,BeforeSwapDelta,uint24) = LIBRARY_CALL, dest:CLHooks, function:CLHooks.beforeSwap(PoolKey,ICLPoolManager.SwapParams,bytes), arguments:['key', 'params', 'hookData'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_417(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount0(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] CLPoolParametersHelper.TMP_414(int24) = LIBRARY_CALL, dest:CLPoolParametersHelper, function:CLPoolParametersHelper.getTickSpacing(bytes32), arguments:['REF_119'] 
    [EXTERNAL] CLPool.TUPLE_3(BalanceDelta,CLPool.SwapState) = LIBRARY_CALL, dest:CLPool, function:CLPool.swap(CLPool.State,CLPool.SwapParams), arguments:['pool', 'TMP_415'] 
    [EXTERNAL] BalanceDeltaLibrary.TMP_418(int128) = LIBRARY_CALL, dest:BalanceDeltaLibrary, function:BalanceDeltaLibrary.amount1(BalanceDelta), arguments:['delta'] 
    [EXTERNAL] CLHooks.TUPLE_4(BalanceDelta,BalanceDelta) = LIBRARY_CALL, dest:CLHooks, function:CLHooks.afterSwap(PoolKey,ICLPoolManager.SwapParams,BalanceDelta,bytes,BeforeSwapDelta), arguments:['key', 'params', 'delta', 'hookData', 'beforeSwapDelta'] 
    [EXTERNAL] PoolIdLibrary.TMP_412(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] VaultAppDeltaSettlement.LIBRARY_CALL, dest:VaultAppDeltaSettlement, function:VaultAppDeltaSettlement.accountAppDeltaWithHookDelta(IVault,PoolKey,BalanceDelta,BalanceDelta), arguments:['vault', 'key', 'delta', 'hookDelta'] 
    [EXTERNAL] CLPool.LIBRARY_CALL, dest:CLPool, function:CLPool.checkPoolInitialized(CLPool.State), arguments:['pool'] 

## donate(PoolKey,uint256,uint256,bytes) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L215-235] donate(PoolKey,uint256,uint256,bytes)
  [MODIFIER] whenNotPaused()
    READ: pools
    READ: vault
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.afterDonate(PoolKey,uint256,uint256,bytes), arguments:['key', 'amount0', 'amount1', 'hookData'] 
    [EXTERNAL] PoolIdLibrary.TMP_422(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] CLPool.LIBRARY_CALL, dest:CLPool, function:CLPool.checkPoolInitialized(CLPool.State), arguments:['pool'] 
    [EXTERNAL] IVault.HIGH_LEVEL_CALL, dest:vault(IVault), function:accountAppBalanceDelta, arguments:['REF_146', 'REF_147', 'delta', 'msg.sender']  
    [EXTERNAL] CLHooks.LIBRARY_CALL, dest:CLHooks, function:CLHooks.beforeDonate(PoolKey,uint256,uint256,bytes), arguments:['key', 'amount0', 'amount1', 'hookData'] 
    [EXTERNAL] CLPool.TUPLE_5(BalanceDelta,int24) = LIBRARY_CALL, dest:CLPool, function:CLPool.donate(CLPool.State,uint256,uint256), arguments:['pool', 'amount0', 'amount1'] 

## getPoolTickInfo(PoolId,int24) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L237-239] getPoolTickInfo(PoolId,int24)
    READ: pools
    [EXTERNAL] CLPoolGetters.TMP_429(Tick.Info) = LIBRARY_CALL, dest:CLPoolGetters, function:CLPoolGetters.getPoolTickInfo(CLPool.State,int24), arguments:['REF_149', 'tick'] 

## getPoolBitmapInfo(PoolId,int16) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L241-243] getPoolBitmapInfo(PoolId,int16)
    READ: pools
    [EXTERNAL] CLPoolGetters.TMP_430(uint256) = LIBRARY_CALL, dest:CLPoolGetters, function:CLPoolGetters.getPoolBitmapInfo(CLPool.State,int16), arguments:['REF_151', 'word'] 

## getFeeGrowthGlobals(PoolId) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L245-251] getFeeGrowthGlobals(PoolId)
    READ: pools
    [EXTERNAL] CLPoolGetters.TUPLE_6(uint256,uint256) = LIBRARY_CALL, dest:CLPoolGetters, function:CLPoolGetters.getFeeGrowthGlobals(CLPool.State), arguments:['REF_153'] 

## updateDynamicLPFee(PoolKey,uint24) [CRITICAL — mueve fondos]

[FUNC] [CLPoolManager:L254-261] updateDynamicLPFee(PoolKey,uint24)
    READ: pools
    [EXTERNAL] LPFeeLibrary.LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.validate(uint24,uint24), arguments:['newDynamicLPFee', 'REF_159'] 
    [EXTERNAL] CLPool.LIBRARY_CALL, dest:CLPool, function:CLPool.setLPFee(CLPool.State,uint24), arguments:['REF_161', 'newDynamicLPFee'] 
    [EXTERNAL] PoolIdLibrary.TMP_438(PoolId) = LIBRARY_CALL, dest:PoolIdLibrary, function:PoolIdLibrary.toId(PoolKey), arguments:['key'] 
    [EXTERNAL] LPFeeLibrary.TMP_431(bool) = LIBRARY_CALL, dest:LPFeeLibrary, function:LPFeeLibrary.isDynamicLPFee(uint24), arguments:['REF_155'] 


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `getLiquidity()` (L63)
```solidity
    function getLiquidity(PoolId id) external view override returns (uint128 liquidity) {
        return pools[id].liquidity;
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `updateDynamicLPFee()` (L254)
```solidity
    function updateDynamicLPFee(PoolKey memory key, uint24 newDynamicLPFee) external override {
        if (!key.fee.isDynamicLPFee() || msg.sender != address(key.hooks)) revert UnauthorizedDynamicLPFeeUpdate();
        newDynamicLPFee.validate(LPFeeLibrary.ONE_HUNDRED_PERCENT_FEE);

        PoolId id = key.toId();
        pools[id].setLPFee(newDynamicLPFee);
        emit DynamicLPFeeUpdated(id, newDynamicLPFee);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `_setProtocolFee()` (L263)
```solidity
    function _setProtocolFee(PoolId id, uint24 newProtocolFee) internal override {
        pools[id].setProtocolFee(newProtocolFee);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

## Symmetric Analysis
# Symmetric Analysis — CLPoolManager

No se encontraron pares simétricos.
