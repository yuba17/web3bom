# Contexto de Hunt — PreLiquidationFactory

**Protocolo**: morpho-pre-liquidation
**Dominio**: lending
**LOC**: 29
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/morpho/pre-liquidation/src/PreLiquidationFactory.sol
**Generado**: 2026-03-22T23:02:41.564664Z

## Solodit Context
### Findings sobre PreLiquidationFactory
Buscando 'PreLiquidationFactory' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (5ms)


### HIGH findings en dominio lending
Buscando 'PreLiquidationFactory createPreLiquidation' [SQLite FTS5] (dominio: lending)...
Sin resultados para los criterios dados. (4ms)

### Cross-domain HIGH relevantes
Buscando 'PreLiquidationFactory createPreLiquidation' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

## Briefing del Dominio
### Briefing principal: lending

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Rounding dust (1 wei per operation) is normal in integer math -- allow tolerance of max(numPayments, numLoans) + 1
  ⚠ Mock oracles produce unrealistic AUM values -- always confirm on fork
  ⚠ Some protocols batch-accrue via 'touch()' -- verify it covers all paths
  ⚠ Open-term vs fixed-term loans have different accrual mechanics
  ⚠ Interest accrual over long periods can legitimately make positions unhealthy -- not a bug
  ⚠ Oracle price updates between check and execution create edge cases
  ⚠ Rounding can make unrealizedLosses slightly exceed AUM -- allow tolerance of numLoans + 1
  ⚠ Mock liquidation tests often miss the real oracle impact
  ⚠ Partial liquidity scenarios are complex but not bugs -- check the partialLiquidity flag logic
  ⚠ Queue processing in batches may leave dust -- tolerance needed
  ⚠ Rounding tolerance needed: max(numPayments, numLoans) + 1 for interest aggregates
  ⚠ Open-term and fixed-term have different aggregate tracking -- check both

## CHECKLIST DE INVARIANTES
When you open a new lending protocol's code, check these in order:
### Architecture (5 min)
- [ ] Map the contract hierarchy: Vault/Pool -> LoanManager -> Loan
- [ ] Identify: where is `totalAssets` computed? Is it `balanceOf` or internal tracking?
- [ ] Identify: ERC4626 vault? Custom share math?
- [ ] Identify: oracle source and type (Chainlink, TWAP, custom)
- [ ] Identify: interest rate model (linear, kinked, adaptive)
- [ ] Identify: withdrawal mechanism (instant, queued/cyclical, timelock)
### Interest Accrual (10 min)
- [ ] Is `accrueInterest()` called FIRST in every state-changing function?
- [ ] Does the interest accumulator only increase? (INV-INT-005)
- [ ] Is there a MAX interest rate cap? (INV-INT-004)
- [ ] Can `lastAccrualTimestamp` ever be in the future? (INV-INT-002)
- [ ] Fixed-term: is `domainEnd` == earliest payment due date? (INV-LOAN-014)
- [ ] Open-term: is `payment.startDate` ==

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

# Deep Flatten — PreLiquidation

Funciones analizadas: 4


## onMorphoRepay(uint256,bytes) [CRITICAL — mueve fondos]

[FUNC] [IMorphoRepayCallback:L21-21] onMorphoRepay(uint256,bytes)

## preLiquidate(address,uint256,uint256,bytes) [CRITICAL — mueve fondos]

[FUNC] [IPreLiquidation:L29-33] preLiquidate(address,uint256,uint256,bytes)

## preLiquidate(address,uint256,uint256,bytes) [CRITICAL — mueve fondos]

[FUNC] [PreLiquidation:L130-175] preLiquidate(address,uint256,uint256,bytes)
    READ: ID
    READ: LLTV
    READ: MORPHO
    READ: PRE_LCF_1
    READ: PRE_LCF_2
    READ: PRE_LIF_1
    READ: PRE_LIF_2
    READ: PRE_LIQUIDATION_ORACLE
    READ: PRE_LLTV
    [EXTERNAL] MathLib.TMP_205(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivUp(uint256,uint256,uint256), arguments:['seizedAssets', 'collateralPrice', 'ORACLE_PRICE_SCALE'] 
    [EXTERNAL] IOracle.TMP_184(uint256) = HIGH_LEVEL_CALL, dest:TMP_183(IOracle), function:price, arguments:[]  
    [EXTERNAL] IMorpho.TUPLE_0(uint256,uint256) = HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:repay, arguments:['TMP_220', '0', 'repaidShares', 'borrower', 'callbackData']  
    [EXTERNAL] MathLib.TMP_206(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wDivUp(uint256,uint256), arguments:['seizedAssetsQuoted', 'preLIF'] 
    [EXTERNAL] IMorpho.HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:accrueInterest, arguments:['TMP_179']  
    [EXTERNAL] MathLib.TMP_212(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['quotient', 'TMP_211'] 
    [EXTERNAL] MathLib.TMP_186(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['TMP_185', 'collateralPrice', 'ORACLE_PRICE_SCALE'] 
    [EXTERNAL] MathLib.TMP_215(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['TMP_214', 'preLCF'] 
    [EXTERNAL] MathLib.TMP_209(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['TMP_208', 'preLIF'] 
    [EXTERNAL] MathLib.TMP_210(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['TMP_209', 'ORACLE_PRICE_SCALE', 'collateralPrice'] 
    [EXTERNAL] SharesMathLib.TMP_207(uint256) = LIBRARY_CALL, dest:SharesMathLib, function:SharesMathLib.toSharesUp(uint256,uint256,uint256), arguments:['TMP_206', 'REF_69', 'REF_70'] 
    [EXTERNAL] MathLib.TMP_197(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wDivUp(uint256,uint256), arguments:['borrowed', 'collateralQuoted'] 
    [EXTERNAL] IMorpho.TMP_182(Position) = HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:position, arguments:['ID', 'borrower']  
    [EXTERNAL] MathLib.TMP_200(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wDivDown(uint256,uint256), arguments:['TMP_198', 'TMP_199'] 
    [EXTERNAL] MathLib.TMP_189(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['collateralQuoted', 'LLTV'] 
    [EXTERNAL] SharesMathLib.TMP_208(uint256) = LIBRARY_CALL, dest:SharesMathLib, function:SharesMathLib.toAssetsDown(uint256,uint256,uint256), arguments:['repaidShares', 'REF_72', 'REF_73'] 
    [EXTERNAL] UtilsLib.TMP_176(bool) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.exactlyOneZero(uint256,uint256), arguments:['seizedAssets', 'repaidShares'] 
    [EXTERNAL] MathLib.TMP_193(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['collateralQuoted', 'PRE_LLTV'] 
    [EXTERNAL] IMorpho.TMP_181(Market) = HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:market, arguments:['ID']  
    [EXTERNAL] MathLib.TMP_202(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.wMulDown(uint256,uint256), arguments:['quotient', 'TMP_201'] 
    [EXTERNAL] SharesMathLib.TMP_188(uint256) = LIBRARY_CALL, dest:SharesMathLib, function:SharesMathLib.toAssetsUp(uint256,uint256,uint256), arguments:['TMP_187', 'REF_59', 'REF_60'] 

## onMorphoRepay(uint256,bytes) [CRITICAL — mueve fondos]

[FUNC] [PreLiquidation:L182-192] onMorphoRepay(uint256,bytes)
    READ: LOAN_TOKEN
    READ: MORPHO
    [EXTERNAL] SafeTransferLib.LIBRARY_CALL, dest:SafeTransferLib, function:SafeTransferLib.safeTransferFrom(ERC20,address,address,uint256), arguments:['TMP_231', 'liquidator', 'TMP_232', 'repaidAssets'] 
    [EXTERNAL] IMorpho.HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:withdrawCollateral, arguments:['TMP_226', 'seizedAssets', 'borrower', 'liquidator']  
    [EXTERNAL] IPreLiquidationCallback.HIGH_LEVEL_CALL, dest:TMP_229(IPreLiquidationCallback), function:onPreLiquidate, arguments:['repaidAssets', 'data']  



## Symmetric Analysis
# Symmetric Analysis — PreLiquidation

No se encontraron pares simétricos.
