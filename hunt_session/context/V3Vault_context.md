# Contexto de Hunt — V3Vault

**Protocolo**: revert-lend
**Dominio**: lending
**LOC**: 1010
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/V3Vault.sol
**Generado**: 2026-03-20T22:49:22.542427Z

## Solodit Context
Buscando 'lending' (dominio: lending)...
Cargando base de datos Solodit... 50,962 findings cargados

Top 5 findings relevantes:

 1. [MEDIUM] Users Can Lose Funds and Collateral by Repaying Loans After Liquidation Grace Pe — Core Contracts
 2. [HIGH] H-2: _calculateMaxBorrowCollateral calculates repay incorrectly and can lead to  — Index
 3. [HIGH] [H-01] Any borrower with bad debt can be liquidated multiple times to lock funds — Frax Finance
 4. [MEDIUM] M-1: _calculateMaxBorrowCollateral calculates repay incorrectly and can lead to  — Index x Morpho Leverage Integration
 5. [MEDIUM] Inconsistency In Debt Repaid And Collateral Seized — Meso Lending

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: V3Vault | Dominio: lending
Los siguientes 5 findings de protocolos similares son relevantes:

1. [?] Users Can Lose Funds and Collateral by Repaying Loans After Liquidation Grace Period Expiry (Core Contracts)

2. [?] H-2: _calculateMaxBorrowCollateral calculates repay incorrectly and can lead to set token liquidation (Index)

3. [?] [H-01] Any borrower with bad debt can be liquidated multiple times to lock funds in the lending pair (Frax Finance)

4. [?] M-1: _calculateMaxBorrowCollateral calculates repay incorrectly and can lead to set token liquidation (Index x Morpho Leverage Integration)

5. [?] Inconsistency In Debt Repaid And Collateral Seized (Meso Lending)

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


## Briefing del Dominio

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
- [ ] Open-term: is `payment.startDate` == `dateFunded` or `datePaid`? (IN
