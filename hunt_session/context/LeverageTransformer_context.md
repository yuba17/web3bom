# Contexto de Hunt — LeverageTransformer

**Protocolo**: revert-lend
**Dominio**: lending
**LOC**: 148
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/transformers/LeverageTransformer.sol
**Generado**: 2026-03-21T21:06:01.603401Z

## Solodit Context
### Findings sobre LeverageTransformer
Buscando 'LeverageTransformer' [SQLite FTS5] (dominio: general)...

Top 1 findings relevantes: (18ms)

 1. [MEDIUM] [M-21] Dangerous use of deadline parameter — Revert Lend

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:

1. [MEDIUM] [M-21] Dangerous use of deadline parameter (Revert Lend)
   
<https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/transformers/AutoCompound.sol#L159-L172> 

<http...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio lending
Buscando 'LeverageTransformer leverageUp leverageDown' [SQLite FTS5] (dominio: lending)...
Top 1 findings relevantes: (6ms)
 1. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens — Tapioca DAO
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer leverageUp leverageDown | Dominio: lending
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens (Tapioca DAO)
Pathway for [`sendForLeverage`](https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L323) -> [`leverageDown`](https...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'LeverageTransformer leverageUp leverageDown' [SQLite FTS5] (dominio: general)...
Top 3 findings relevantes: (1ms)
 1. [HIGH] [H-28] TOFT and USDO Modules Can Be Selfdestructed — Tapioca DAO
 2. [HIGH] [H-33] `BaseTOFTLeverageModule.sol`: `leverageDownInternal` tries to burn tokens — Tapioca DAO
 3. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens — Tapioca DAO
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer leverageUp leverageDown | Dominio: general
Los siguientes 3 findings de protocolos similares son relevantes:
1. [HIGH] [H-28] TOFT and USDO Modules Can Be Selfdestructed (Tapioca DAO)
<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L184-L...
2. [HIGH] [H-33] `BaseTOFTLeverageModule.sol`: `leverageDownInternal` tries to burn tokens from wrong address (Tapioca DAO)
<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L212> ...
3. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens (Tapioca DAO)
Pathway for [`sendForLeverage`](https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L323) -> [`leverageDown`](https...
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
