# Lending Protocol Combat Briefing

> What you need to know BEFORE reading a lending protocol's code.
> Sources: Maple V2 invariant suite (99 invariants), Euler VK invariant suite, Morpho Blue patterns.

---

## 1. Bugs Conocidos

### Pool-Level Accounting

```yaml
- id: lending-001
  pattern: pool-insolvency
  name: "Pool totalAssets < totalLiabilities"
  causa_raiz: >
    totalAssets is computed as cash + sum(AUM across loan managers). If AUM tracking
    diverges from actual loan state (missed interest updates, double-counted principal,
    stale loan manager state), totalAssets underreports. Meanwhile totalSupply (liabilities
    to depositors) stays correct. The gap means the pool owes more than it has.
  como_funciona: >
    1. Attacker finds a path where a loan repayment or liquidation updates the loan
       but not the loan manager's AUM tracking.
    2. Pool cash increases (repayment received) but AUM does not decrease by the
       corresponding principal amount.
    3. Or vice versa: loan defaults, principal is lost, but AUM still counts it.
    4. Over multiple cycles, totalAssets diverges from reality.
    5. Last withdrawers get less than their share -- first-mover advantage.
  invariante: "totalAssets == cash + sum(loanManager.assetsUnderManagement())"
  que_mirar:
    - "Does every loan state change (fund, repay, default, impair, refinance) update the loan manager's AUM?"
    - "Are interest accrual and principal tracking updated atomically?"
    - "Can a loan be removed from tracking while still holding principal?"
    - "Does the pool's totalAssets match poolManager.totalAssets()? (INV-POOL-009)"
  como_se_arregla: "Ensure every loan lifecycle event (fund, repay, default, liquidate, refinance) atomically updates both loan state and loan manager aggregates."
  trampas:
    - "Rounding dust (1 wei per operation) is normal in integer math -- allow tolerance of max(numPayments, numLoans) + 1"
    - "Mock oracles produce unrealistic AUM values -- always confirm on fork"
  incidentes:
    - "ZeroLend One — _burnCollateralTokens fee omission causes pool insolvency (high)"
    - "Blueberry — totalLend not updated on liquidation, permanently inflated (medium)"
    - "Blueberry — HardVault never deposits assets to Compound, no yield accrual (medium)"
    - "Maple Finance — Unaccounted collateral mishandled in triggerDefault (medium)"
    - "Monolith — Accounting broken if user redeems during bad debt position (medium)"
    - "Notional Update #5 — External lending exceeds threshold, redemption issues (medium)"
    - "Notional Update #5 — Rebalance skipped even if external lending unhealthy (medium)"
    - "DODO V3 — Borrow amount in AssetInfo vs BorrowRecord unmatched due to precision loss (medium)"
    - "RegnumAurum — Protocol misses fees from borrowing positions, never allocated (medium)"
    - "ZeroLend One (Sherlock) — H-9: executeMintToTreasury incorrectly reduces supplyShares, preventing last users from withdrawing (HIGH)"
    - "Folks Finance (Sherlock) — Incorrect Updates to poolDepositData.totalAmount and loanCollateralUsed during repayment (HIGH)"
    - "Part 2 (Pashov) — Incorrect Credit Capacity Validation in VaultRouterBranch.redeem enables locked collateral drainage (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-POOL-001, INV-POOL-012, INV-POOL-013)"
  verificado: true
  tags: [solvency, totalAssets, AUM, pool, accounting]
  relacionado_con: [lending-002, lending-006]

- id: lending-002
  pattern: interest-accrual-desync
  name: "Interest not updated before state-changing operation"
  causa_raiz: >
    Lending protocols track interest via an issuanceRate (interest per second) and a
    domainStart/domainEnd window. accruedInterest = issuanceRate * (now - domainStart).
    If a state-changing operation (deposit, withdraw, borrow, repay, liquidate) does not
    call accrueInterest() first, the operation uses stale totalAssets/totalBorrows values.
    Share minting/burning happens at a wrong exchange rate.
  como_funciona: >
    1. Interest has been accruing for hours but accrueInterest() was not called.
    2. Attacker deposits just before someone else triggers accrual.
    3. Deposit mints shares at pre-accrual (lower) totalAssets.
    4. Accrual happens, totalAssets jumps, attacker's shares are now worth more.
    5. Attacker withdraws at the higher rate. Profit extracted from existing LPs.
  invariante: "domainStart <= block.timestamp AND accrueInterest() called before every mint/burn/borrow/repay"
  que_mirar:
    - "Is accrueInterest() the FIRST thing in deposit/withdraw/borrow/repay/liquidate?"
    - "Can block.timestamp < domainStart? (INV-LOAN-012, INV-LOAN-033)"
    - "Is issuanceRate == sum of per-loan rates? (INV-LOAN-008, INV-LOAN-030)"
    - "Does domainEnd track the earliest payment due date? (INV-LOAN-014)"
  como_se_arregla: "Call accrueInterest() as the first step in every external state-changing function. Use a modifier."
  trampas:
    - "Some protocols batch-accrue via 'touch()' -- verify it covers all paths"
    - "Open-term vs fixed-term loans have different accrual mechanics"
  incidentes:
    - "ZeroLend One — Interest rate updated BEFORE debt updated when repaying (high)"
    - "Roots — Stale totalActiveDebt cached before _accrueActiveInterests in openTrove (high)"
    - "Flayer — calculateCompoundedFactor has 10x error causing interest overpayment (high)"
    - "Hyperstable — AdaptiveIRM integrated incorrectly, stale rate used (medium)"
    - "Isomorph — _updateVirtualPrice calculates interest incorrectly if updated frequently (medium)"
    - "Surge — Interest calculated as 0 in getCurrentState due to division error (medium)"
    - "Morpho — Compound liquidity uses outdated cached borrowIndex (medium)"
    - "Morpho — P2P indexes can be stale in Compound implementation (medium)"
    - "Wild Credit — Reward computation wrong, rewards distributed before index update (high)"
    - "Monolith — Interest accrual stuck when wadExp underflows to 0 causing div-by-zero (medium)"
    - "RegnumAurum — Borrowers avoid paying interest due to wrong _positionScaledDebt (high)"
    - "Inverse Finance — Calling repay sends less DOLA when forceReplenish not called (medium)"
    - "Inverse Finance — User borrows DOLA indefinitely without settling DBR deficit (medium)"
    - "Panoptic — Intra-epoch rateAtTarget updates cause compounding interest error (medium)"
    - "Accountable (Cyfrin) — Frequent accrueInterest calls reduce interest accrual due to integer math truncation (MEDIUM)"
    - "Accountable (Cyfrin) — OpenTerm loan interest cannot be repaid once principal hits zero (HIGH)"
    - "Licredity (Cyfrin) — decreaseDebtShare bypasses interest accrual (HIGH)"
    - "Bima (Sherlock) — Interest accrued is removed from totalActiveDebt when calling openTrove (HIGH)"
    - "Numa (Sherlock) — M-9: Before transferring CToken, accrueInterest() should be called first (MEDIUM)"
    - "Adrena (Spearbit) — Reduced borrow fee due to resetting of accrued interest (HIGH)"
    - "ZeroLend One (Sherlock) — M-5: After user withdraws, interest rate not updated, next user uses inflated index (MEDIUM)"
    - "Ionprotocol (Code4rena) — M-01: New interest module may calculate past interest (MEDIUM)"
    - "Primex Finance (Sherlock) — Interest accumulation prior to bucket launch (MEDIUM)"
    - "Evoq (Spearbit) — Cached borrow index in liquidation logic leads to discrepancy with underlying pool (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-LOAN-004 through INV-LOAN-014), euler_vk (INV-INT-002, INV-INT-003)"
  verificado: true
  tags: [interest, accrual, desync, timing, exchange-rate]
  relacionado_con: [lending-001, lending-006]

- id: lending-003
  pattern: liquidation-threshold-manipulation
  name: "Liquidation of healthy positions or prevention of unhealthy liquidations"
  causa_raiz: >
    Health factor = collateralValue * LTV / debtValue. If oracle price is manipulable
    (e.g. spot price from a DEX pool), an attacker can temporarily move the price to
    make a healthy position appear liquidatable, or make an unhealthy position appear
    healthy. Also: if health check happens at wrong time (before interest accrual),
    position may appear healthy when it is not.
  como_funciona: >
    1. Attacker flash-loans a large amount of the collateral token.
    2. Dumps it on the DEX that the oracle reads, crashing the price.
    3. Calls liquidate() on a victim whose position is now "underwater" at the manipulated price.
    4. Receives collateral at a discount.
    5. Repays flash loan. Net profit from the liquidation bonus.
  invariante: "Liquidation succeeds IFF violator is genuinely unhealthy (INV-LIQ-001)"
  que_mirar:
    - "What oracle does the protocol use? TWAP? Chainlink? Spot price?"
    - "Can health check be bypassed or called with stale data?"
    - "Does the protocol accrue interest before checking health? (INV-LIQ-004)"
    - "Can a healthy account become unhealthy via a non-liquidation operation? (INV-LIQ-002)"
    - "Can an unhealthy account's health score be worsened by non-liquidation? (INV-LIQ-003)"
  como_se_arregla: "Use manipulation-resistant oracles (Chainlink, TWAP with sufficient window). Accrue interest before health checks. Validate health after every state change."
  trampas:
    - "Interest accrual over long periods can legitimately make positions unhealthy -- not a bug"
    - "Oracle price updates between check and execution create edge cases"
  incidentes:
    - nombre: "WiseLending"
      fecha: "Jan 2024"
      monto: "$464K"
      detalle: "Bad HealthFactor check allowed improper liquidation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "UwULend"
      fecha: "Jun 2024"
      monto: "$19.3M"
      detalle: "Price manipulation on lending protocol oracle"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CompoundUni"
      fecha: "Feb 2024"
      monto: "$439.5K"
      detalle: "Oracle returned bad price, enabling exploitation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Moonwell"
      fecha: "Feb 2026"
      monto: "$1.78M"
      detalle: "Faulty oracle allowed collateral/debt mispricing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "LavaLending"
      fecha: "Oct 2024"
      monto: "$130K"
      detalle: "Price manipulation on lending oracle"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Zenterest"
      fecha: "Aug 2024"
      monto: "$21K"
      detalle: "Stale oracle - price out of date used for health checks"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "ExactlyProtocol"
      fecha: "Aug 2023"
      monto: "$7M"
      detalle: "Validation flaw in health/liquidation checks"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - "GammaSwap — Price manipulation risk in GammaVault collateral using spot price (medium)"
    - "Backed Protocol — Users liquidated right after taking maximal debt, no LTV gap (high)"
    - "Sentiment — originationFee makes borrower liquidatable immediately (medium)"
    - "Aave V4 — Users immediately liquidatable after action due to risk premium ordering (medium)"
    - "Inverse Finance — Liquidation should make borrower healthier but doesnt (medium)"
    - "Sentiment — CTokenOracle.getCErc20Price critical math error overvalues cTokens (high)"
    - "Surge — Precision differences in userCollateralRatioMantissa (high)"
    - "Panoptic — Incorrect collateral calculation for delayed swap strategies (medium)"
    - "Notional Finance — Pendle PT Oracle ignores losses, over-valued collateral (medium)"
    - "Vii (Spearbit) — Liquidations can be made to revert by attacker, causing losses and bad debt (HIGH)"
    - "Numa (Sherlock) — M-6: Incorrect liquidation mechanics either causes revert or transition into bad debt (MEDIUM)"
    - "Exactly Protocol (Sherlock) — M-11: Market::liquidate() fails when most liquidity is borrowed due to wrong transferFrom order (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "euler_vk (INV-LIQ-001 through INV-LIQ-004)"
  verificado: true
  tags: [liquidation, oracle, manipulation, health-factor, flash-loan]
  relacionado_con: [lending-008, lending-009]

- id: lending-004
  pattern: bad-debt-socialization-error
  name: "Bad debt distributed incorrectly across depositors"
  causa_raiz: >
    When a borrower's debt exceeds their collateral value and liquidation cannot fully
    recover the debt, the remaining "bad debt" must be socialized (spread across all
    depositors by reducing the exchange rate). If this is done wrong -- double-counted,
    applied to wrong pool, or not applied at all -- some depositors lose too much and
    others lose nothing.
  como_funciona: >
    1. Borrower defaults. Collateral is worth less than debt.
    2. Liquidation recovers partial value. Remaining debt = bad debt.
    3. Bad debt should reduce totalAssets (or increase unrealizedLosses).
    4. If unrealizedLosses > totalAssets (INV-POOL-013 violated), the pool is in
       negative-equity state. Exchange rate conversion breaks.
    5. If bad debt is not socialized, totalAssets is overstated, first withdrawers
       get full value, last withdrawers get nothing (bank run).
  invariante: "unrealizedLosses <= totalAssets (INV-POOL-013, INV-LOAN-009, INV-LOAN-031)"
  que_mirar:
    - "How does the protocol handle the gap between debt and recovered collateral?"
    - "Does unrealizedLosses update atomically with the liquidation?"
    - "Can unrealizedLosses exceed totalAssets? (INV-POOL-013)"
    - "In non-liquidating scenarios, is unrealizedLosses == 0? (INV-LOAN-010, INV-LOAN-032)"
    - "Does exchange rate still work when unrealizedLosses > 0?"
  como_se_arregla: "Bound unrealizedLosses to totalAssets. Socialize bad debt immediately and atomically on liquidation completion. Use convertToExitShares that accounts for losses."
  trampas:
    - "Rounding can make unrealizedLosses slightly exceed AUM -- allow tolerance of numLoans + 1"
    - "Mock liquidation tests often miss the real oracle impact"
  incidentes:
    - "BendDAO — Bad debt never handled, insolvency risk (high)"
    - "Perennial V2 — Bad debt liquidation leaves negative collateral causing bank run (medium)"
    - "Monolith — Single user with bad debt allows minting unbacked tokens (medium)"
    - "Monolith — Accounting broken if user redeems when bad debt exists (medium)"
    - "Panoptic — Withdrawing before bad debt event increases losses for remaining LPs (medium)"
    - "SteadeFi — Depositors face immediate loss when equity = 0 (medium)"
    - "ZeroLend One (Sherlock) — H-7: When bad debt accumulated, loss not shared amongst all suppliers, last to withdraw loses huge (HIGH)"
    - "Exactly Protocol (Sherlock) — M-12: Some bad debt not cleared when it should, decreasing protocol solvency (MEDIUM)"
    - "LoopFi (Sherlock) — H-12: CDPVault.liquidatePositionBadDebt() should not set profit=0 when calling pool.repayCreditAccount() (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-POOL-013, INV-LOAN-009, INV-LOAN-010, INV-LOAN-031, INV-LOAN-032)"
  verificado: true
  tags: [bad-debt, socialization, unrealizedLosses, exchange-rate, bank-run]
  relacionado_con: [lending-001, lending-007]

- id: lending-005
  pattern: withdrawal-queue-fairness
  name: "Withdrawal queue ordering/fairness violation"
  causa_raiz: >
    Lending pools with withdrawal queues (Maple-style cyclical or FIFO queue) must
    ensure shares are locked, tracked per cycle/request, and redeemed in order. If
    the queue accounting desyncs from actual share balances, users can: (a) redeem
    more than they locked, (b) jump the queue, (c) have their request silently dropped.
  como_funciona: >
    1. User requests withdrawal -- shares are locked in the WithdrawalManager.
    2. WM tracks lockedShares[user], totalCycleShares[cycle], and totalShares.
    3. If any of these diverge from the WM's actual pool token balance, redeemable
       amounts are wrong.
    4. Attacker could exploit: request in cycle N, manipulate to get counted in cycle
       N-1 (earlier window), redeem before others.
    5. Or: cancel and re-request to reset position, causing others to lose their spot.
  invariante: "WM.balanceOf(pool) == sum(lockedShares) (INV-WQ-001, INV-WQ-016)"
  que_mirar:
    - "Does WM pool token balance == sum(all locked shares)? (INV-WQ-001)"
    - "Does totalCycleShares[cycle] == sum(lockedShares for that cycle)? (INV-WQ-002)"
    - "Are redeemable shares bounded by lockedShares[user]? (INV-WQ-007)"
    - "Are redeemable assets bounded by pool cash balance? (INV-WQ-009)"
    - "Is requestId unique per lender? (INV-WQ-022)"
    - "Is owner unique per request? (INV-WQ-023)"
    - "Can lockedLiquidity exceed pool.totalAssets? (INV-WQ-013)"
  como_se_arregla: "Maintain strict share conservation: lock shares on request, burn on redeem. Use monotonic request IDs. Enforce uniqueness constraints."
  trampas:
    - "Partial liquidity scenarios are complex but not bugs -- check the partialLiquidity flag logic"
    - "Queue processing in batches may leave dust -- tolerance needed"
  incidentes:
    - "Sublime — SavingsAccount withdrawAll freezes user funds ignoring strategy liquidity (high)"
    - "Notional Update #5 — Rebalance delayed due to revert, excess liquidity lent out (medium)"
  severidad: high
  confianza: alta
  fuente: "maple_v2 (INV-WQ-001 through INV-WQ-023)"
  verificado: true
  tags: [withdrawal, queue, fairness, ordering, shares, lock]
  relacionado_con: [lending-001]

- id: lending-006
  pattern: loan-aum-desync
  name: "Loan accounting AUM desyncs from actual loan state"
  causa_raiz: >
    The loan manager aggregates (principalOut, accountedInterest, issuanceRate) are
    updated separately from individual loan state. If any loan lifecycle event fails
    to update the aggregate, or updates it with wrong values, the loan manager's AUM
    diverges from the sum of actual loan values. This cascades to pool totalAssets.
  como_funciona: >
    1. A loan is funded. principalOut increases by loan.principal().
    2. Loan makes payments. Interest is accounted via issuanceRate accrual.
    3. On refinance, the old payment's issuanceRate must be removed and new one added.
    4. If refinanceInterest is not adjusted for management fees (INV-LOAN-015),
       the accounting drifts.
    5. Over many refinances, AUM diverges. Pool reports wrong totalAssets.
  invariante: "AUM == sum(loan.principal) + sum(outstandingInterest) (INV-LOAN-011, INV-LOAN-027)"
  que_mirar:
    - "Does principalOut == sum(loan.principal)? (INV-LOAN-007, INV-LOAN-029)"
    - "Does issuanceRate == sum(per-payment rates)? (INV-LOAN-008, INV-LOAN-030)"
    - "Does refinanceInterest account for management fee deduction? (INV-LOAN-015)"
    - "Does paymentDueDate cache match loan.nextPaymentDueDate? (INV-LOAN-016)"
    - "Is sortedPayments list actually sorted? (INV-LOAN-005)"
    - "AUM decomposition: AUM - unrealizedLosses - sum(outstandingValue) approx 0? (INV-LOAN-037)"
  como_se_arregla: "Atomic updates: every loan state change must update loan manager aggregates in the same transaction. Cross-validate with sum checks."
  trampas:
    - "Rounding tolerance needed: max(numPayments, numLoans) + 1 for interest aggregates"
    - "Open-term and fixed-term have different aggregate tracking -- check both"
  incidentes:
    - "Blueberry — totalLend not updated on liquidation, permanently inflated value (medium)"
    - "DODO V3 — Borrow amount precision loss for small-decimal tokens like WBTC (medium)"
    - "Carapace — Lending pool state transition broken when pool expired in late state (high)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-LOAN-005 through INV-LOAN-017, INV-LOAN-027 through INV-LOAN-037)"
  verificado: true
  tags: [AUM, loan-manager, principalOut, issuanceRate, desync, aggregate]
  relacionado_con: [lending-001, lending-002]

- id: lending-007
  pattern: collateral-value-miscalculation
  name: "Collateral value under/over-counted"
  causa_raiz: >
    Collateral value depends on: (a) amount of collateral tokens held, (b) oracle
    price, (c) loan-to-value ratio applied. If the protocol tracks collateral
    internally but the actual token balance differs, or if the LTV/collateral factor
    is applied inconsistently between borrow-time and liquidation-time, collateral
    value is miscalculated.
  como_funciona: >
    1. Protocol tracks collateral via internal mapping but actual balanceOf differs
       (direct token transfer, fee-on-transfer token, rebasing token).
    2. User appears to have more collateral than they actually deposited.
    3. User borrows against phantom collateral.
    4. On liquidation, the real collateral is less than expected -- bad debt.
  invariante: "collateralAsset.balanceOf(loan) >= loan.collateral() (INV-LOAN-001)"
  que_mirar:
    - "Does the protocol use balanceOf or internal tracking for collateral?"
    - "Does it handle fee-on-transfer tokens? Rebasing tokens?"
    - "Is collateral proportional to principal drawn? (INV-LOAN-003)"
    - "Can collateral be withdrawn while debt exists? (INV-LEND-008, INV-LEND-012)"
    - "Is supply cap enforced? (INV-LEND-009, INV-LEND-010)"
  como_se_arregla: "Track actual token balance changes (before/after transfer delta, not amount parameter). Validate collateral ratio after every operation."
  trampas:
    - "Standard ERC20 tokens without fees will never trigger this -- focus on weird tokens"
    - "Rebasing token balances change without transfers"
  incidentes:
    - nombre: "MidasCapital"
      fecha: "Jan 2023"
      monto: "$650K"
      detalle: "Read-only reentrancy allowed collateral value manipulation during callback"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Sentiment"
      fecha: "Apr 2023"
      monto: "$1M"
      detalle: "Read-only reentrancy on Balancer pool allowed inflated collateral valuation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "dForce"
      fecha: "Feb 2023"
      monto: "$3.65M"
      detalle: "Read-only reentrancy exploited to misvalue collateral"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "SturdiFinance"
      fecha: "Jun 2023"
      monto: "$800K"
      detalle: "Read-only reentrancy led to incorrect collateral pricing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Paribus"
      fecha: "Apr 2023"
      monto: "$100K"
      detalle: "Reentrancy allowed collateral manipulation during borrow flow"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - "GammaSwap — Collateral calculated using Uniswap V3 spot price, manipulable (medium)"
    - "Blueberry Update — BalancerPairOracle manipulated using read-only reentrancy (high)"
    - "Blueberry Update #2 — ShortLongSpell uses wrong balanceOf for collateral (high)"
    - "Isomorph — Vault_Synths does not consider protocol exchange fee in collateral worth (medium)"
    - "Sentiment — YTokenOracle doesnt account for losses when pricing yToken (medium)"
    - "Peapods — spTKNMinimalOracle doesnt support advanced self-lending pods (medium)"
    - "Notional Finance — Pendle PT Oracle ignores losses during SY redemptions (medium)"
    - "Panoptic — Incorrect collateral calculation for delayed swap strategies (medium)"
    - "The Standard Smart Vault — Collateral in Gamma vaults not counted in liquidation (high)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-LOAN-001, INV-LOAN-003), euler_vk (INV-LEND-008, INV-LEND-012)"
  verificado: true
  tags: [collateral, balance, fee-on-transfer, rebasing, phantom]
  relacionado_con: [lending-003, lending-004]

- id: lending-008
  pattern: self-liquidation-profit
  name: "User self-liquidates for profit via liquidation bonus"
  causa_raiz: >
    If a user can create a position that is barely underwater and then liquidate
    themselves, the liquidation bonus (discount on collateral) can exceed the bad
    debt, resulting in net profit. This is especially dangerous if the user can
    manipulate the oracle to make their position appear slightly unhealthy.
  como_funciona: >
    1. Attacker deposits collateral, borrows maximum amount.
    2. Manipulates oracle price to make position barely liquidatable.
    3. Liquidates own position from a second account.
    4. Receives collateral at a discount (liquidation bonus).
    5. The discount exceeds the cost of the bad debt created.
    6. Net profit extracted from the pool.
  invariante: "Liquidation must not be profitable for the violator (post-liquidation health should improve)"
  que_mirar:
    - "What is the liquidation bonus/discount?"
    - "Can the same user be both liquidator and violator?"
    - "Does health factor improve after liquidation?"
    - "Can oracle be manipulated cheaply enough to profit?"
    - "Does the protocol limit liquidation size to prevent full self-liquidation?"
  como_se_arregla: "Limit liquidation bonus to be less than the collateral factor gap. Prevent same-tx borrow+liquidate. Use close factor to limit liquidation size."
  trampas:
    - "Self-liquidation is sometimes intended behavior (user wants to exit quickly)"
    - "The profitability depends on liquidation bonus vs oracle manipulation cost"
  incidentes:
    - nombre: "EulerFinance"
      fecha: "Mar 2023"
      monto: "$200M"
      detalle: "donateToReserves function allowed self-liquidation for profit via business logic flaw"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "OpenLeverage"
      fecha: "Oct 2023"
      monto: "$8K"
      detalle: "Business logic flaw enabled profitable self-dealing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "OpenLeverage"
      fecha: "Apr 2024"
      monto: "$234K"
      detalle: "Business logic flaw in lending operations"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "LavaLending"
      fecha: "Mar 2024"
      monto: "$340K"
      detalle: "Business logic flaw allowed extraction of value"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "BlueberryProtocol"
      fecha: "Feb 2024"
      monto: "$1.4M"
      detalle: "Logic flaw in lending protocol business logic"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - "Surge — Liquidator gains collateral AND reduces own debt via rounding (medium)"
    - "Curve Finance — Inflation attack on empty ticks via self-liquidation (high)"
    - "Monolith — User abuses rounding to borrow unbacked tokens (high)"
    - "Licredity (Cyfrin) — Proxy-based self-liquidation creates bad debt for lenders (HIGH)"
    - "Euler Labs EVK (Cantina) — Self-liquidations of leveraged positions can be profitable (HIGH)"
    - "LoopFi (Sherlock) — H-02: Liquidation doesn't account for penalty, allowing users to profit by self-liquidation (HIGH)"
    - "Size v1 (Sherlock) — Early self liquidations receive portion of future fees to be paid by other creditors (HIGH)"
    - "Hyperstable (Pashov) — Self-liquidation can help reduce losses when health factor is low (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "euler_vk (INV-LIQ-001, INV-LIQ-002), general DeFi knowledge, DeFiHackLabs"
  verificado: true
  tags: [self-liquidation, bonus, profit, oracle, manipulation]
  relacionado_con: [lending-003, lending-009]

- id: lending-009
  pattern: flash-borrow-repay-same-tx
  name: "Flash loan + borrow/repay in same transaction exploits"
  causa_raiz: >
    If interest accrual is time-based (per-second), a borrow and repay in the same
    block accrues zero interest. Combined with flash loans, an attacker can borrow
    enormous amounts risk-free: deposit flash-loaned collateral, borrow, use borrowed
    funds, repay, withdraw collateral, repay flash loan -- all in one tx. If the
    protocol charges no fee for zero-duration borrows, the attack is free.
  como_funciona: >
    1. Flash loan large amount of collateral asset.
    2. Deposit as collateral.
    3. Borrow maximum amount of the lending token.
    4. Use borrowed funds (e.g., manipulate a DEX, vote in governance, etc.).
    5. Repay borrow (zero interest because same block).
    6. Withdraw collateral.
    7. Repay flash loan.
  invariante: "Users with debt must have nonzero collateral at all times (INV-LEND-008), AND some minimum fee/duration"
  que_mirar:
    - "Can borrow and repay happen in the same transaction?"
    - "Is there a minimum borrow duration or minimum interest charge?"
    - "Can flash-loaned tokens be used as collateral?"
    - "Does the protocol check health at the end of the transaction (deferred check) or immediately?"
    - "EVC-style batch: can operations be batched to defer health checks? (INV-LEND-011)"
  como_se_arregla: "Charge minimum borrow fee regardless of duration. Prevent same-block repay. Or use deferred liquidity checks that still enforce minimum fees."
  trampas:
    - "Deferred liquidity check patterns (EVC) intentionally allow same-tx borrow/repay -- check if fees still apply"
    - "This is a design choice, not always a bug"
  incidentes:
    - nombre: "PolterFinance"
      fecha: "Nov 2024"
      monto: "$7M"
      detalle: "Flash loan attack exploiting lending protocol mechanics"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CompoundFork"
      fecha: "Oct 2024"
      monto: "$1M"
      detalle: "Flash loan attack on Compound fork deployed on Base"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "0vix"
      fecha: "Apr 2023"
      monto: "$2M"
      detalle: "Flash loan manipulation on lending protocol"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - "Arcadia — Reentrancy in flashAction drains liquidity pools via ERC777 (high)"
    - "Olympusdao — SiloAMO forced to fund reduced rates by manipulating utilization (high)"
    - "Based Loans — Reward rates changed through flash borrows (medium)"
    - "Perennial V2 Update #4 — Intent orders bypass fee accounting, bad debt via collateral withdrawal (high)"
  severidad: high
  confianza: alta
  fuente: "euler_vk (INV-LEND-008, INV-LEND-011), general DeFi knowledge, DeFiHackLabs"
  verificado: true
  tags: [flash-loan, same-tx, zero-interest, borrow, repay]
  relacionado_con: [lending-003, lending-008]

- id: lending-010
  pattern: share-inflation-first-depositor
  name: "First depositor share inflation / donation attack"
  causa_raiz: >
    In ERC4626 vaults, the first depositor can manipulate the exchange rate by:
    (1) depositing 1 wei to get 1 share, (2) donating a large amount directly to
    the vault (not via deposit), inflating totalAssets while totalSupply = 1.
    Now convertToShares rounds down for subsequent depositors, causing them to
    receive 0 shares for substantial deposits. The attacker redeems their 1 share
    for the entire vault balance.
  como_funciona: >
    1. Attacker is first depositor, deposits 1 wei, receives 1 share.
    2. Attacker transfers 10000 USDC directly to the vault contract.
    3. Now totalAssets = 10000e6 + 1, totalSupply = 1.
    4. Victim deposits 9999 USDC. convertToShares = 9999e6 * 1 / (10000e6+1) = 0.
    5. Victim gets 0 shares, their 9999 USDC is trapped.
    6. Attacker redeems 1 share for ~19999 USDC.
  invariante: "totalAssets >= totalSupply (exchange rate >= 1) (INV-POOL-003), AND convertToShares never rounds to 0 for nonzero deposits"
  que_mirar:
    - "Is there a minimum initial deposit or dead shares mechanism?"
    - "Does the vault use virtual shares/assets offset (e.g., OpenZeppelin 4626 with _decimalsOffset)?"
    - "Can tokens be directly transferred to inflate totalAssets?"
    - "Does convertToShares round correctly? (INV-POOL-004, INV-POOL-005)"
    - "Is totalAssets derived from balanceOf (donatable) or internal accounting?"
  como_se_arregla: "Use virtual shares offset (add 1e3-1e6 to totalAssets and totalSupply in conversion math). Or require minimum initial deposit that gets burned."
  trampas:
    - "Some protocols intentionally use balanceOf for totalAssets -- check if donation is possible"
    - "Virtual offset solves this but introduces small imprecision"
    - "Revert Lend V3Vault uses exchange-rate-based ERC4626 -- NOT balance-based totalAssets for share pricing. First depositor inflation attack does NOT apply because donations go to reserves (not share price). Share price only changes via _calculateGlobalInterest. Wasted hunting time: rule this out immediately on protocols with explicit exchange-rate-based share math."
  incidentes:
    - nombre: "Sonne Finance"
      fecha: "May 2024"
      monto: "$20M"
      detalle: "Precision loss on CompoundV2 fork - classic share inflation attack on empty markets"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "HundredFinance"
      fecha: "Apr 2023"
      monto: "$7M"
      detalle: "Inflation/rounding attack on CompoundV2 fork - first depositor exploit"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MidasCapitalXYZ"
      fecha: "Jun 2023"
      monto: "$600K"
      detalle: "Precision loss in share/exchange rate calculations"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - "Curve Finance — Inflation attack on empty ticks in AMM (high)"
    - "Taurus — Missing input validation allows keeper to pay back all debt (high)"
    - "StakeDAO — Initial position liquidity so close to liquidation after deployment (medium)"
    - "SOFA.org (Cantina) — Donation attacks on empty AAVE vaults can steal deposits (HIGH)"
    - "Finance Contracts (Quantstamp) — Price inflation in AToken (HIGH)"
    - "Clave (Spearbit) — Using aToken.balanceOf() in ClaggAaveAdapter allows inflation attacks (HIGH)"
    - "Malda (Sherlock) — M-2: First depositor can brick market by forcing very large borrow rate (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "maple_v2 (INV-POOL-002, INV-POOL-003, INV-POOL-004, INV-POOL-005), general ERC4626 knowledge, DeFiHackLabs"
  verificado: true
  tags: [ERC4626, first-depositor, inflation, donation, share-price, rounding]
  relacionado_con: [lending-001, lending-002]

- id: lending-011
  pattern: dust-position-unliquidatable
  name: "Dust/small positions create unliquidatable bad debt"
  causa_raiz: >
    Protocols without minimum borrow/position size allow users to create
    positions so small that the gas cost of liquidation exceeds the liquidation
    reward. These positions accumulate bad debt that nobody has economic
    incentive to clear, eventually making the protocol insolvent.
  como_funciona: >
    1. Attacker creates many positions with dust-sized collateral and borrows.
    2. Each position is individually too small for profitable liquidation.
    3. Price moves make positions unhealthy.
    4. No liquidator bothers (gas > reward).
    5. Bad debt accumulates across hundreds of dust positions.
    6. Protocol becomes insolvent as aggregate bad debt exceeds reserves.
  invariante: "borrowAmount >= minBorrowSize && collateral >= minCollateralSize"
  que_mirar:
    - "minBorrowAmount"
    - "minLoanSize"
    - "MIN_BORROW"
    - "require(amount >"
    - "dust"
  como_se_arregla: "Enforce minimum borrow size that ensures liquidation is always profitable at current gas prices. Include minimum position check in borrow and partial repay functions."
  trampas:
    - "Some protocols intentionally allow small positions for UX -- verify there is SOME floor"
    - "Gas costs vary by chain -- L2s may make this less critical"
  incidentes:
    - "Euler EVK -- Lack of incentives to liquidate small positions (medium)"
    - "DYAD -- No incentive to liquidate small positions, protocol goes underwater (medium)"
    - "DYAD -- No incentive to liquidate when CR<=1 (medium)"
    - "Revert Lend -- No minLoanSize means no liquidation incentive (medium)"
    - "Wise Lending -- Small positions create bad debt (medium)"
    - "The Standard -- No incentive to liquidate small vaults (medium)"
    - "Foundry DeFi Stablecoin -- No incentive to liquidate small positions (high)"
    - "Cooler -- Dust amounts cause payments to fail leading to default (medium)"
    - "DittoETH -- User can create small position after exit with bid (medium)"
    - "Debita Finance V3 -- No minimum size within Loan and Offer (medium)"
    - "Aave V4 -- Deficit reporting DoS via micro-collateral (medium)"
    - "Notional Exponent (Sherlock) — M-20: Lack of minimum debt threshold enables unliquidatable small positions (MEDIUM)"
    - "Peapods (Sherlock) — M-32: Malicious liquidator intentionally leaves dust collateral, won't trigger bad debt handling (MEDIUM)"
    - "Exactly Protocol (Sherlock) — M-10: Liquidations leave dust when repaying expired maturities, impossible to clear bad debt (MEDIUM)"
    - "Sentiment V2 (Sherlock) — M-22: Setting minDebt and minBorrow to low values causes bad debt accrual (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, dust, liquidation, bad-debt, minimum-size, gas]

- id: lending-012
  pattern: liquidation-fee-accounting-mismatch
  name: "Liquidation fee/bonus not properly accounted in collateral math"
  causa_raiz: >
    During liquidation, the protocol must correctly account for liquidation
    fees, bonuses, and protocol cuts when burning collateral tokens and
    transferring assets. If any component (fee, bonus, slippage) is omitted
    from the accounting, the pool's internal balance diverges from reality,
    leading to insolvency.
  como_funciona: >
    1. Liquidation is triggered on an unhealthy position.
    2. Protocol calculates collateral to seize including bonus and fees.
    3. When burning collateral tokens, the fee portion is NOT subtracted.
    4. Pool's internal accounting thinks it has more collateral than it does.
    5. Over many liquidations, the gap compounds.
    6. Pool becomes insolvent -- last withdrawers cannot exit.
  invariante: "collateralBurned == actualCollateralToLiquidate + liquidationProtocolFee"
  que_mirar:
    - "_burnCollateralTokens"
    - "liquidationBonus"
    - "liquidationProtocolFee"
    - "liquidationPenalty"
    - "seizeAmount"
    - "vars.actualCollateralToLiquidate"
  como_se_arregla: "Include ALL components (bonus, protocol fee, penalty) when calculating collateral to burn. Verify post-liquidation that pool balance matches internal accounting."
  trampas:
    - "Liquidation bonus vs liquidation fee are different -- check both"
    - "Protocol fee on liquidation may go to treasury, not liquidator"
  incidentes:
    - "ZeroLend One -- _burnCollateralTokens does not account for liquidation fees (high)"
    - "Backed Protocol -- purchaseLiquidationAuctionNFT takes extra liquidation penalty on last collateral (medium)"
    - "Blueberry -- Liquidator takes all collateral for fraction of correct price (high)"
    - "Isomorph -- Bad debt persists after complete liquidation due to truncation (medium)"
    - "Cap -- Missing slippage protection in liquidation (medium)"
    - "Ostium -- Wrong collateral refund in liquidation when liqPrice == priceAfterImpact (medium)"
    - "Tangent -- Losses due to missing collateral check in _liquidate (medium)"
    - "Filament (Cantina) — Collateral is reduced twice when position liquidated by user different from protocolLiquidator (HIGH)"
    - "Filament (Cantina) — Fees wrongly accrued when reducing collateral (HIGH)"
    - "Size (Sherlock) — H-03: Collateral remainder cap incorrectly calculated during liquidation (HIGH)"
    - "Sentiment V2 (Sherlock) — M-2: Liquidation fee incorrectly calculated leading to unprofitable liquidations (MEDIUM)"
    - "Vii (Spearbit) — More value extracted by liquidations than expected due to incorrect transfer calculations (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, liquidation, fee, accounting, insolvency, bonus]

- id: lending-013
  pattern: liquidation-dos-collateral-drain
  name: "Liquidation DoS via collateral liquidity drain or frontrunning"
  causa_raiz: >
    In multi-asset lending pools, collateral assets can be borrowed by other
    users. If the collateral asset reserve is fully borrowed when liquidation
    is needed, the liquidator cannot seize collateral because the tokens are
    not physically available. Alternatively, borrowers can frontrun liquidation
    by slightly increasing collateral to temporarily restore health.
  como_funciona: >
    1. Borrower has position close to liquidation threshold.
    2. Attacker (or the borrower themselves) borrows all available collateral tokens from the reserve.
    3. Liquidator calls liquidate() but it reverts -- insufficient collateral tokens to transfer.
    4. Position accrues more bad debt while unliquidatable.
    5. OR: borrower frontruns liquidation tx, adds tiny collateral to become healthy, then removes it next block.
  invariante: "liquidation must always be executable when position is unhealthy"
  que_mirar:
    - "transfer(liquidator"
    - "balanceOf(address(this))"
    - "availableLiquidity"
    - "require(collateral >="
    - "canBorrow"
  como_se_arregla: "Reserve a portion of collateral asset pool exclusively for liquidation. Implement a cooldown after collateral changes before health can be rechecked. Use flash-liquidation that sources tokens externally."
  trampas:
    - "Some protocols use aTokens/cTokens as collateral which are always redeemable -- not affected"
    - "Frontrunning mitigation depends on chain -- L2s with sequencers are different"
  incidentes:
    - "ZeroLend One -- Liquidation DoS due to lack of liquidity on collateral reserve (high)"
    - "Taurus -- User prevents liquidation by frontrunning and slightly increasing collateral (medium)"
    - "Morpho -- Cannot liquidate users if no liquidity on pool (medium)"
    - "Morpho -- User withdrawals fail if position close to liquidation (medium)"
    - "Isomorph -- Outstanding loans cannot be closed if collateral is paused (high)"
    - "Backed Protocol -- Grieving attack by failing user transactions (medium)"
    - "Panoptic -- Wide-range short legs revert solvency checks blocking liquidations (medium)"
    - "Panoptic -- Division-by-zero blocks solvency checks and liquidation (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, liquidation, dos, frontrunning, collateral, liquidity]

- id: lending-014
  pattern: interest-rate-math-error
  name: "Interest rate calculation/compounding math error"
  causa_raiz: >
    Interest rate models involve precision-sensitive math: basis points to
    per-second rates, compounding factors, decimal normalization across tokens
    with different decimals. Off-by-one in scaling, wrong order of operations,
    or incorrect precision constants cause interest to be dramatically over/under-charged.
  como_funciona: >
    1. Interest rate model calculates annual rate (e.g., 800 = 8% in basis points).
    2. Conversion to per-second rate uses wrong denominator or scaling factor.
    3. Compounding function multiplies by wrong precision (e.g., /1000 instead of /10000).
    4. Effective rate is 10x higher or lower than intended.
    5. Borrowers overpay massively OR lenders receive near-zero interest.
  invariante: "effectiveAnnualRate == configuredAnnualRate (within 0.1% tolerance)"
  que_mirar:
    - "calculateCompoundedFactor"
    - "perSecondRate"
    - "1e18"
    - "365 * 24 * 60 * 60"
    - "RATE_PRECISION"
    - "interestRate * 1e"
    - "wTaylorCompounded"
    - "wadExp"
  como_se_arregla: "Add invariant tests that verify effective annual rate matches configured rate. Use well-audited math libraries. Test with multiple decimal configurations."
  trampas:
    - "Taylor approximation for compounding is intentionally imprecise -- verify against full exp"
    - "Different protocols use different precision bases (1e4, 1e18, 1e27)"
  incidentes:
    - "Flayer -- calculateCompoundedFactor has calculation error, users overpay 10x interest (high)"
    - "Surge -- Precision differences in userCollateralRatioMantissa (high, found twice)"
    - "Surge -- Interest calculated as 0 due to division error in getCurrentState (medium)"
    - "Taurus -- Protocol assumes 18 decimals collateral (high)"
    - "Hyperstable -- AdaptiveIRM integrated incorrectly with stale rate (medium)"
    - "Isomorph -- _updateVirtualPrice calculates interest incorrectly if updated frequently (medium)"
    - "Monolith -- Interest accrual stuck when wadExp underflows to 0 causing div-by-zero (medium)"
    - "Sentiment -- CTokenOracle.getCErc20Price critical math error (high)"
    - "DODO V3 -- Borrow amount precision loss for small-decimal tokens (medium)"
    - "Panoptic -- Intra-epoch rateAtTarget updates allow compounding error exploitation (medium)"
    - "Ammplify (Sherlock) — H-5: Borrow fee uses APY as per-second rate, causing extreme overcharging (31M x inflation) (HIGH)"
    - "Astera/Cod3x Lend (Spearbit) — getCurrentInterestRates() does not calculate interests correctly (MEDIUM)"
    - "Astera/Cod3x Lend (Spearbit) — minLiquidityRate formula is incorrect (HIGH)"
    - "Cryptex (Cantina) — Calculating interest without considering collateral decimals (HIGH)"
    - "Folks Finance (Sherlock) — Wrong borrow balance calculation in getLoanLiquidity (HIGH)"
    - "Folks Finance (Sherlock) — Incorrect calculation of effective borrow value leads to protocol insolvency (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, interest-rate, math, precision, decimals, compounding]

- id: lending-015
  pattern: state-update-ordering
  name: "State update ordering: interest/debt updated before or after dependent operation"
  causa_raiz: >
    When a state-changing operation (repay, borrow, liquidate) needs to update
    multiple pieces of state (interest rate, debt balance, collateral), the
    ORDER matters. If interest rate is recalculated before debt is updated,
    it uses stale debt. If debt is cached before accrual, the accrued amount
    is lost. Classic TOCTOU in DeFi accounting.
  como_funciona: >
    1. User calls repay() to pay back debt.
    2. Function updates interest rate BEFORE reducing totalBorrows.
    3. Interest rate calculation uses pre-repayment (higher) debt.
    4. New rate is set too high because it thinks more is borrowed.
    5. All borrowers pay inflated rate until next state update.
    6. OR: totalActiveDebt cached before accrueInterest, then overwritten with stale value.
  invariante: "interestRateUpdate MUST happen AFTER debt/supply state changes"
  que_mirar:
    - "updateInterestRates"
    - "cache = reserve.cache"
    - "uint256 supply = totalActiveDebt"
    - "updateState"
    - "reserve.updateInterestRates"
  como_se_arregla: "Ensure interest rate recalculation always uses post-operation state. Avoid caching state variables before calling functions that modify them."
  trampas:
    - "Some protocols intentionally calculate rate before update for gas optimization -- verify impact"
    - "The bug may only manifest after many operations accumulate drift"
  incidentes:
    - "ZeroLend One -- Interest rate updated before debt updated when repaying (high)"
    - "Roots -- Stale totalActiveDebt used in openTrove after accrueInterest (high)"
    - "Morpho -- Compound liquidity computation uses outdated cached borrowIndex (medium)"
    - "Morpho -- P2P indexes can be stale in Compound implementation (medium)"
    - "RegnumAurum -- Borrowers avoid paying interest due to wrong _positionScaledDebt (high)"
    - "Wild Credit -- Reward computation wrong due to order of updates (high)"
    - "ZeroLend One (Sherlock) — M-8: Liquidation fails to update interest rate when funds sent to treasury, next user uses inflated index (MEDIUM)"
    - "Astera/Cod3x Lend (Spearbit) — Updating reserve factor should update interest rates (MEDIUM)"
    - "BendDAO (Sherlock) — M-19: Protocol should update interest rate after changing rate model in configurator (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, state-ordering, interest, stale, cache, TOCTOU]

- id: lending-016
  pattern: collateral-not-counted-in-liquidation
  name: "Collateral in sub-vaults/yield positions excluded from liquidation"
  causa_raiz: >
    When protocols allow collateral to be moved into yield-generating positions
    (LP vaults, staking, gamma vaults), the liquidation logic may not be able
    to access or account for that collateral. The collateral is economically
    backing the debt but technically unreachable by the liquidation function.
  como_funciona: >
    1. User deposits collateral into lending vault.
    2. User moves collateral into yield position (Gamma vault, LP position, etc).
    3. User borrows maximum against the yield-position-backed collateral.
    4. Price drops, position becomes liquidatable.
    5. Liquidation function iterates over accepted tokens but yield tokens are NOT in the list.
    6. Liquidation seizes zero collateral. Debt persists as bad debt.
    7. User can then reclaim yield position after debt is written off.
  invariante: "sum(all collateral sources) >= debtValue for any liquidatable position"
  que_mirar:
    - "getAcceptedTokens"
    - "liquidateERC20"
    - "hypervisors"
    - "yieldPosition"
    - "getCollateral"
    - "for (uint256 i = 0; i < tokens.length"
  como_se_arregla: "Include ALL collateral forms (direct tokens, yield positions, LP tokens, staked tokens) in the liquidation sweep. Or prevent moving collateral to unreachable positions while debt exists."
  trampas:
    - "Yield position tokens may have different addresses than underlying -- check both"
    - "Some yield positions are non-transferable by design"
  incidentes:
    - "The Standard Smart Vault -- Collateral in Gamma vaults not considered during liquidation (high)"
    - "Zaros -- User withdraws all collateral when position has profit, nothing to deduct on liquidation (medium)"
    - "Perennial V2 -- Bad debt liquidation leaves negative collateral balance causing bank run (medium)"
    - "Blueberry -- LP tokens not sent back to withdrawing user during closePosition (high)"
    - "Blueberry -- ShortLongSpell uses wrong balanceOf for collateral (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, collateral, yield, liquidation, unreachable, vault]

- id: lending-017
  pattern: pause-repay-liquidation-conflict
  name: "Pause/freeze blocks repayments but allows liquidation or accrual"
  causa_raiz: >
    When an admin pauses/freezes a market, repayment functions may be disabled
    while interest continues accruing or liquidation remains enabled. Users
    cannot repay their debt (paused), but get liquidated as interest pushes
    them underwater. This is a governance attack vector against borrowers.
  como_funciona: >
    1. Admin pauses/freezes the market or collateral asset.
    2. Interest continues accruing on all borrowers' positions.
    3. Borrowers cannot call repay() -- it reverts due to pause.
    4. Positions become unhealthy purely from accrued interest during pause.
    5. When unpaused, or if liquidation is not paused, positions are immediately liquidatable.
    6. Borrowers lose collateral through no fault of their own.
  invariante: "if repay is paused, then either interest accrual OR liquidation must also be paused"
  que_mirar:
    - "whenNotPaused"
    - "setReserveFreeze"
    - "isRepayPaused"
    - "isBorrowPaused"
    - "isLiquidateBorrowPaused"
    - "collateralValid"
    - "_setPauseStatus"
  como_se_arregla: "If repayments are paused, also pause interest accrual and liquidation. Or always allow repayment even during pause. Use separate pause flags for each operation."
  trampas:
    - "Some protocols pause by asset, not globally -- check per-market granularity"
    - "Emergency pause may legitimately need to freeze everything including repay"
  incidentes:
    - "Blueberry -- Liquidations enabled when repayments disabled, borrowers lose funds (medium)"
    - "Isomorph -- Outstanding loans cannot be closed or liquidated if collateral paused (high)"
    - "Morpho -- Deprecated market still prevents liquidation if isLiquidateBorrowPaused is true (medium)"
    - "Morpho -- setIsPausedForAllMarkets bypasses setIsBorrowPaused check on deprecated market (medium)"
    - "Morpho -- Turning off collateral on Aave still allows seizing on Morpho (medium)"
    - "Inverse Finance -- Collateral withdrawals locked if governance sets collateralFactorBps to 0 (medium)"
    - "AAVE -- _pendingLtv set to 0 if two consecutive freeze calls (medium)"
    - "EVAA (Cantina) — Possible unfair race conditions between borrowers and liquidators when system reactivated (MEDIUM)"
    - "Filament (Cantina) — Improper use of whenNotPaused modifier for liquidations may result in bad debt (MEDIUM)"
    - "BendDAO (Sherlock) — M-02: Risk of mass liquidation after pool/asset pause and unpause, due to interest compounding (MEDIUM)"
    - "Filament (Cantina) — Back-running attacks can liquidate without option to repay after changing collateralization ratio (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, pause, freeze, repay, liquidation, governance, accrual]

- id: lending-018
  pattern: no-ltv-liquidation-gap
  name: "Missing gap between max borrow LTV and liquidation threshold"
  causa_raiz: >
    If the maximum borrow LTV equals or is very close to the liquidation
    threshold, any price movement or fee application immediately makes the
    position liquidatable. Originiation fees, risk premiums, or rounding can
    push a position past the threshold in the same transaction as borrowing.
  como_funciona: >
    1. User borrows at maximum allowed LTV (e.g., 80%).
    2. Liquidation threshold is also 80% (or very close).
    3. Origination fee is applied, increasing effective debt above collateral threshold.
    4. User is immediately liquidatable in the same block they borrowed.
    5. OR: any oracle update in the next block triggers liquidation.
    6. User loses liquidation penalty on a position they just opened.
  invariante: "maxBorrowLTV + originationFee + maxSingleBlockPriceMove < liquidationThreshold"
  que_mirar:
    - "liquidationThreshold"
    - "maxLTV"
    - "borrowFactor"
    - "originationFee"
    - "collateralFactorBps"
    - "HEALTH_FACTOR_LIQUIDATION_THRESHOLD"
  como_se_arregla: "Enforce a minimum gap between max borrow LTV and liquidation threshold that accounts for fees, oracle granularity, and one block of interest. Apply origination fees BEFORE health check."
  trampas:
    - "Risk premiums that update post-borrow can also close the gap -- check deferred updates"
    - "Different assets may have different gaps needed"
  incidentes:
    - "Backed Protocol -- Users liquidated right after taking maximal debt (high)"
    - "Sentiment -- originationFee makes borrower liquidatable immediately (medium)"
    - "Aave V4 -- Users immediately liquidatable after action due to risk premium ordering (medium)"
    - "Isomorph -- User not allowed to increase collateral freely, forced toward liquidation (medium)"
    - "Isomorph -- Unable to partially payback if cant meet minOpeningMargin (high)"
    - "StakeDAO -- Initial position liquidity so close to liquidation (medium)"
    - "Duality Focus -- Undercollateralized loans possible, no upper bound on collateral factor (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, LTV, liquidation-threshold, gap, origination-fee, immediate-liquidation]

- id: lending-019
  pattern: bad-debt-handling-missing
  name: "Bad debt never written off or socialized, causing insolvency"
  causa_raiz: >
    When a position's debt exceeds collateral value and liquidation cannot
    fully recover the debt, the remaining bad debt must be handled (socialized
    across depositors, covered by reserves, or written off). If the protocol
    has no bad debt handling mechanism, the phantom debt remains, making
    accounting permanently wrong and potentially blocking all withdrawals.
  como_funciona: >
    1. Borrower's collateral value drops below debt value.
    2. Liquidation recovers collateral but debt remains.
    3. Protocol has no mechanism to write off or socialize this bad debt.
    4. totalBorrows includes phantom debt that can never be repaid.
    5. Interest continues accruing on phantom debt, inflating totalBorrows further.
    6. Eventually totalBorrows > totalSupply, pool appears to have negative equity.
    7. Last depositors cannot withdraw -- funds are locked.
  invariante: "if collateral[user] == 0 && debt[user] > 0, bad debt must be socialized or written off"
  que_mirar:
    - "handleBadDebt"
    - "socializeLoss"
    - "writeOff"
    - "settleDebt"
    - "unrealizedLosses"
    - "defaultedDebt"
  como_se_arregla: "Implement automatic bad debt socialization on liquidation completion. Reduce totalSupplyAssets or increase a loss reserve when bad debt is confirmed."
  trampas:
    - "Bad debt can be legitimate in extreme market conditions -- focus on whether it is HANDLED, not prevented"
    - "Some protocols use insurance funds instead of socialization"
  incidentes:
    - "BendDAO -- Bad debt never handled, insolvency risk (high)"
    - "Perennial V2 -- Bad debt liquidation leaves negative collateral causing bank run (medium)"
    - "Monolith -- Accounting broken if user redeems when bad debt position exists (medium)"
    - "Monolith -- Single user with bad debt allows minting unbacked tokens (medium)"
    - "Panoptic -- Withdrawing before bad debt event increases losses for remaining LPs (medium)"
    - "Inverse Finance -- Liquidation should make borrower healthier but doesnt (medium)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, bad-debt, insolvency, socialization, write-off, phantom-debt]

- id: lending-020
  pattern: utilization-rate-manipulation
  name: "Utilization rate manipulation via flash borrow or large temporary borrows"
  causa_raiz: >
    Interest rates are typically a function of utilization (totalBorrows / totalSupply).
    An attacker can temporarily spike utilization by borrowing a large amount,
    which pushes interest rates up for all borrowers. Or manipulate AMO/strategy
    deposits by draining liquidity first.
  como_funciona: >
    1. Attacker flash-loans or deposits large collateral.
    2. Borrows maximum from the pool, spiking utilization to near 100%.
    3. Interest rate model jumps to high rate (past the kink).
    4. All existing borrowers now accrue expensive interest.
    5. Attacker repays in same or next tx with minimal interest paid.
    6. OR: attacker manipulates an AMO to deposit when utilization is artificially low.
  invariante: "interestRate should not change by more than X% in a single block"
  que_mirar:
    - "utilizationRate"
    - "getBorrowRate"
    - "getSupplyRate"
    - "UTILIZATION_KINK"
    - "update()"
    - "AMO"
    - "totalBorrows * 1e18 / totalSupply"
  como_se_arregla: "Use time-weighted utilization for rate calculation. Implement rate change caps per block. Charge minimum borrow fees regardless of duration."
  trampas:
    - "Flash loans that borrow and repay atomically may not affect rates if rates are calculated pre-tx"
    - "Some IRM models are intentionally responsive -- high sensitivity is a feature"
  incidentes:
    - "Olympusdao -- SiloAMO forced to fund reduced rates by manipulating utilization (high)"
    - "Surge -- Attackers skip collateral ratio recovery to inflate ratios and steal funds (medium)"
    - "Surge -- Users can borrow all loan tokens in one tx (medium)"
    - "Ajna -- Interest rates raised above market as griefing, disabling pool (medium)"
    - "Based Loans -- Reward rates changed through flash borrows (medium)"
    - "Sentiment -- Reserves should not be in available liquidity for interest rate calc (medium)"
    - "Notional Update #5 -- External lending can exceed threshold (medium)"
    - "Astera/Cod3x Lend (Spearbit) — Pi interest rate model manipulatable due to current balances used (MEDIUM)"
    - "Peapods (Sherlock) — M-16: Malicious lenders increase borrower interest due to wrong UtilizationRate calculation (MEDIUM)"
    - "Teller Finance (Sherlock) — H-8: Interest rate in LenderCommitmentGroup may be easily manipulated by depositing, borrowing, withdrawing (HIGH)"
    - "Sharwafinance (Cantina) — M-05: Liquidity pool interest accrual can be manipulated (MEDIUM)"
    - "Exactly Protocol (Sherlock) — M-2: Fixed interest rates can be manipulated by whale borrower (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, utilization, interest-rate, manipulation, flash-loan, AMO]

- id: lending-021
  pattern: nft-collateral-lifecycle-bugs
  name: "NFT collateral lifecycle: auction, lien, and sale state conflicts"
  causa_raiz: >
    NFT-backed lending has complex state machines: collateral can be deposited,
    have liens, be at auction, be listed for sale, or be liquidated. If state
    transitions are not properly guarded (e.g., creating liens while at auction,
    listing for sale while borrowed against), collateral can be double-spent or
    stolen.
  como_funciona: >
    1. User deposits NFT as collateral and borrows against it.
    2. User lists same NFT for sale on Seaport via the protocol.
    3. Sale executes, buyer pays, NFT transfers.
    4. But the lien still exists -- the sale proceeds go to borrower, not to repay debt.
    5. OR: User creates new lien on collateral that is already at auction by spoofing collateralId.
    6. Protocol loses both the NFT and the debt is unpaid.
  invariante: "collateral at auction => no new liens allowed; collateral with liens => sale proceeds go to lien holders first"
  que_mirar:
    - "onERC721Received"
    - "validateCommitment"
    - "auctionData"
    - "collateralId"
    - "listForSaleOnSeaport"
    - "_createLien"
    - "maxLiens"
    - "stateHash"
  como_se_arregla: "Enforce strict state machine for NFT collateral. Lock collateral during auction. Route all sale proceeds through lien repayment. Validate collateralId consistently across all params."
  trampas:
    - "ERC721 and ERC1155 have different transfer semantics -- check both"
    - "Seaport/marketplace integration adds external state machine complexity"
  incidentes:
    - "Astaria -- Anyone can take loan on behalf of any collateral holder (high)"
    - "Astaria -- Borrower lists collateral on Seaport, receives price without repaying liens (high)"
    - "Astaria -- Collateral owner steals funds by taking liens while listed for sale (high)"
    - "Astaria -- Create lien for collateral at auction by passing spoofed data (high)"
    - "Astaria -- Auction ends without bid, liquidatorNFTClaim doesnt clear data (high)"
    - "Astaria -- validateStack allows any stack with no-lien collateral (high)"
    - "Astaria -- Liquidation fails if liquidationInitialAsk > 2**88-1 (high)"
    - "Astaria -- Second-time NFT collateral auction fails due to clearingHouse reuse (high)"
    - "Astaria -- Liens cant be bought out at max active liens (medium)"
    - "Backed Protocol -- Collateral NFT deposited to wrong address on direct transfer (high)"
    - "Backed Protocol -- Disabled NFT collateral used to mint debt (medium)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, NFT, collateral, auction, lien, seaport, state-machine]

- id: lending-022
  pattern: token-approval-and-transfer-bugs
  name: "Token approval/transfer edge cases: safeApprove, fee-on-transfer, blacklists"
  causa_raiz: >
    Lending protocols interact with diverse ERC20 tokens that have non-standard
    behaviors: fee-on-transfer reduces actual received amount, safeApprove
    reverts if current allowance is non-zero (USDT), blacklisted addresses
    cannot send/receive, and rebasing tokens change balances autonomously.
    If the protocol does not handle these, core operations break.
  como_funciona: >
    1. Protocol uses safeApprove() to set allowance for pool interaction.
    2. If previous approval was not fully consumed, safeApprove reverts (USDT behavior).
    3. All subsequent deposits/borrows/liquidations for that token permanently fail.
    4. OR: fee-on-transfer token deposits X but only X-fee arrives, internal accounting overestimates.
    5. OR: borrower gets blacklisted, repay() transfers fail, loan defaults unfairly.
  invariante: "actual token balance change == expected token balance change for every transfer"
  que_mirar:
    - "safeApprove"
    - "approve(address, uint256)"
    - "transferFrom"
    - "balanceOf(address(this))"
    - "fee-on-transfer"
    - "blacklist"
    - "rebasing"
  como_se_arregla: "Use forceApprove() or approve(0) then approve(amount). Measure balance before/after transfers. Support pull-based repayment for blacklisted users. Document unsupported token types."
  trampas:
    - "Most standard ERC20s work fine -- this only matters for non-standard tokens"
    - "Fee-on-transfer is rare but USDT-on-some-chains has been known to enable it"
  incidentes:
    - "Hyperlend -- Deprecated safeApprove blocks collateral approval to pool (high)"
    - "Morpho -- ERC20 with transfer fee not handled by PositionManager (medium)"
    - "Morpho -- USDT mainnet market broken state due to approval (high)"
    - "Cooler -- Lender force Loan default via blacklisted debt token transfer (high)"
    - "Ajna -- Borrower/kicker blacklisted, collateral permanently frozen (medium)"
    - "Sublime -- Aave share tokens are rebasing breaking strategy code (high)"
    - "Taurus -- Collateral token with multiple addresses bypasses swap check (medium)"
    - "Blend (Sherlock) — M-11: safeApprove on USDT can break collateral approval (MEDIUM)"
    - "predict.fun (Sherlock) — M-1: Borrower cannot repay to a USDC blacklisted lender (MEDIUM)"
    - "Level Money (Spearbit) — USDT cannot be withdrawn from AaveV3YieldManager (HIGH)"
    - "BendDAO (Sherlock) — M-03: If isolated borrower/bidder blacklisted by debt token, risk of DOS liquidation/auction (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, ERC20, approval, fee-on-transfer, blacklist, rebasing, USDT]

- id: lending-023
  pattern: p2p-matching-desync
  name: "Peer-to-peer matching engine state desynchronization"
  causa_raiz: >
    P2P lending optimizers (Morpho-style) maintain internal state tracking
    which users are matched P2P vs on-pool. When the underlying pool (Aave/Compound)
    state changes externally (liquidation, rate update), or when matching
    deltas accumulate, the P2P state desyncs from the pool state.
  como_funciona: >
    1. Morpho matches suppliers and borrowers P2P at better rates.
    2. External event (Aave liquidation of Morpho's position) changes actual pool state.
    3. Morpho's internal tracking still shows old positions.
    4. Users cannot withdraw because Morpho thinks funds are in pool but they are not.
    5. OR: P2P rate is lazy-updated, attacker manipulates pool rate before update to get favorable P2P rate.
    6. OR: matching creates P2P credit lines even when P2P is disabled.
  invariante: "Morpho internal state == actual position on underlying pool (Aave/Compound)"
  que_mirar:
    - "p2pSupplyIndex"
    - "p2pBorrowIndex"
    - "p2pSupplyDelta"
    - "p2pBorrowDelta"
    - "matchBorrowers"
    - "matchSuppliers"
    - "isP2PDisabled"
    - "updateP2PIndexes"
  como_se_arregla: "Sync Morpho state with underlying pool before every operation. Add circuit breakers for large state divergence. Verify P2P disabled flag in matching engine."
  trampas:
    - "Small deltas are normal due to rounding -- only large divergence is a bug"
    - "Morpho-specific pattern but applies to any P2P optimization layer"
  incidentes:
    - "Morpho -- Liquidating Morpho's Aave position leads to state desync (high, found twice)"
    - "Morpho -- P2P rate manipulated as lazy-updated snapshot (high)"
    - "Morpho -- Wrong reserve factor computation on P2P rates (high)"
    - "Morpho -- P2P borrowers rate can be reduced (medium, found twice)"
    - "Morpho -- Supplying/borrowing recreates P2P credit lines when disabled (medium)"
    - "Morpho -- MatchingEngineForAave uses wrong totalSupply in updateBorrowers (high)"
    - "Morpho -- RewardsManagerAave does not verify token addresses (high)"
    - "Morpho -- Differences between Morpho and Compound borrow validation logic (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, P2P, matching, Morpho, desync, Aave, Compound]

- id: lending-024
  pattern: auction-timing-manipulation
  name: "Liquidation auction timing manipulation or price floor breach"
  causa_raiz: >
    Protocols using Dutch auctions for liquidation have time-decaying prices.
    If the auction duration is misconfigured, or if an attacker can manipulate
    the timing (reset auction timer, delay settlement), the auction price can
    fall below the floor price, causing the protocol to sell collateral at a
    loss or accumulate bad debt.
  como_funciona: >
    1. Borrower position is liquidated via Dutch auction.
    2. Auction price starts high and decays over time.
    3. Attacker performs minimal liquidation (few wei) that resets health to >=1.
    4. Liquidation timer resets to 0, auction restarts from high price.
    5. Nobody can purchase at high price, timer decays again.
    6. Attacker repeats to delay liquidation indefinitely while collateral depreciates.
    7. OR: auction runs past floor price, collateral sold at loss.
  invariante: "auction price >= floor price && liquidation timer cannot be reset by partial liquidation"
  que_mirar:
    - "liquidationStart"
    - "auctionTimer"
    - "_closeLiquidation"
    - "health >= 1e27"
    - "floorPrice"
    - "dutchAuction"
    - "kickAuction"
  como_se_arregla: "Never reset liquidation timer on partial liquidation. Use monotonic auction timer. Set a hard floor price below which the protocol absorbs the loss rather than selling at discount."
  trampas:
    - "Partial liquidation restoring health may be legitimate -- only the TIMER RESET is the bug"
    - "Dutch auction parameters are highly protocol-specific"
  incidentes:
    - "Ajna -- Auction timers fall through floor price causing pool insolvency (medium)"
    - "Ajna -- scaledQuoteTokenAmount not updated in take calculation (high)"
    - "Ajna -- ERC721Pool take proceeds with truncated collateral but full debt (high)"
    - "Ajna -- ERC721Pool mergeOrRemoveCollateral while auction clearable (high)"
    - "Ajna -- Remaining collateral missed in take/bucketTake return structures (high)"
    - "Ajna -- Settled collateral unavailable for lenders until debt fully cleared (medium)"
    - "Curve Finance -- Inflation attack on empty ticks via self-liquidation (high)"
    - "Yield -- Non-liquidatable auction if collateral fails transfer to address(0) (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, auction, liquidation, timing, dutch-auction, floor-price]

- id: lending-025
  pattern: cross-contract-reentrancy-lending
  name: "Cross-contract reentrancy via callbacks drains lending pools"
  causa_raiz: >
    Lending protocols that interact with tokens supporting callbacks (ERC777,
    ERC1155, ERC721 onReceived) or with external protocols (Balancer, Uniswap)
    are vulnerable to reentrancy during mid-operation state. The attacker
    re-enters during a callback when accounting is partially updated, exploiting
    the inconsistent state.
  como_funciona: >
    1. Attacker initiates a flash action or deposit/withdraw with a callback-enabled token.
    2. During the token transfer, a callback is triggered (ERC777 tokensReceived, ERC1155 onReceived).
    3. Inside the callback, attacker re-enters the lending protocol.
    4. Protocol state is partially updated (e.g., shares minted but balance not yet adjusted).
    5. Attacker exploits the inconsistent state to mint extra shares or drain funds.
    6. Callback returns, original operation completes with wrong state.
  invariante: "no reentrant calls allowed during state-changing operations; balances consistent at all external call points"
  que_mirar:
    - "nonReentrant"
    - "ReentrancyGuard"
    - "onERC721Received"
    - "tokensReceived"
    - "flashAction"
    - "onFlashLoan"
    - "getPoolTokens"
    - "read-only reentrancy"
    - "callback"
  como_se_arregla: "Apply reentrancy guards on all state-changing functions. Use checks-effects-interactions pattern. For read-only reentrancy, verify Balancer vault reentrancy lock before reading pool state."
  trampas:
    - "Read-only reentrancy does not modify state but reads stale state -- separate pattern from write reentrancy"
    - "Cross-contract reentrancy bypasses single-contract reentrancy guards"
  incidentes:
    - "Arcadia -- Reentrancy in flashAction drains liquidity pools via ERC777 (high)"
    - "Blueberry Update -- BalancerPairOracle manipulated via read-only reentrancy (high)"
    - "Panoptic -- Cross-contract reentrancy in liquidation converts phantom to real shares (high)"
    - "Ajna -- Anyone who approved quote tokens forced to take via unguarded take() (high)"
    - "Debt DAO -- Borrower crafts unliquidatable borrow via ids array corruption (high)"
    - "Debt DAO -- Borrower closes credit without repaying debt (high)"
    - "Ammplify (Sherlock) — H-2: All taker collateral stolen by re-entering via RFTLib.settle to manipulate uniswap spot price (HIGH)"
    - "Eggs (Cantina) — Contract can be drained of sonic via reentrancy (HIGH)"
    - "Numa (Sherlock) — H-1: leverageStrategy() can be re-entered, crashing NUMA price (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [lending, reentrancy, callback, ERC777, flash-action, cross-contract, read-only-reentrancy]

- id: lending-026
  pattern: cross-chain-lending-state-desync
  name: "Cross-chain lending: collateral/debt state desync between chains"
  causa_raiz: >
    Cross-chain lending protocols maintain collateral on one chain and debt on
    another, synchronizing via messaging (LayerZero, etc.). The source chain
    sends collateral value to the destination chain for borrow validation, but
    does NOT include existing borrows from that collateral. This lets users
    borrow against the same collateral on multiple chains simultaneously. Also:
    cross-chain liquidation passes the wrong amount type (seize amount instead
    of repay amount), decimal mismatches between chains are not normalized, and
    debt tracking after cross-chain repayment uses incorrect array indices.
  como_funciona: >
    1. User deposits collateral on Chain A worth $10,000.
    2. User calls borrowCrossChain() to borrow $8,000 on Chain B. Source chain sends raw collateral value, not net of existing borrows.
    3. User calls borrowCrossChain() again to borrow $8,000 on Chain C. Same collateral supports both borrows.
    4. Total debt: $16,000 against $10,000 collateral. Protocol is undercollateralized.
    5. OR: cross-chain liquidation encodes seizeTokens (collateral amount) as repayment amount, causing debt to be under-repaid or over-repaid.
    6. OR: token decimals differ between chains (USDC 6 on Ethereum, 18 on another), amounts are not normalized, user receives 1e12x more than intended.
  invariante: "sum(borrows across ALL chains) <= collateralValue * maxLTV; cross-chain messages must normalize decimals"
  que_mirar:
    - "borrowCrossChain"
    - "CrossChainRouter"
    - "_handleBorrowCrossChainRequest"
    - "seizeTokens vs repayAmount"
    - "LayerZero"
    - "lzSend"
    - "crossChainCollaterals"
    - "decimals normalization"
  como_se_arregla: "Include existing cross-chain borrows when validating new borrow requests. Normalize token decimals at message boundaries. Use repayAmount (not seizeAmount) for debt reduction in cross-chain liquidation. Implement atomic cross-chain state locks."
  trampas:
    - "Message ordering is not guaranteed across chains -- race conditions are inherent"
    - "Failed cross-chain messages can leave state permanently desynchronized"
    - "Different token addresses on different chains may represent the same asset"
  incidentes:
    - "LEND -- Cross-chain borrow ignores existing debt in collateral validation (high, 20+ finders)"
    - "LEND -- Cross-chain liquidation uses seize amount instead of repay amount (high, 15 finders)"
    - "LEND -- Users lose funds due to token decimal mismatches across chains (high)"
    - "LEND -- Malicious liquidator liquidates without providing collateral cross-chain (high, 18 finders)"
    - "LEND -- Incorrect debt tracking in _updateRepaymentState (high, 14 finders)"
    - "LEND -- Multiple cross-chain borrows using same collateral (high)"
    - "Autonomint -- H-20: borrowing::liquidate() sends wrong liquidation index to destination chain (high)"
    - "Autonomint -- H-37: treasury.updateYieldsFromLiquidatedLrts() updates yield on wrong chain (high)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, cross-chain, LayerZero, state-desync, double-borrow, decimals, liquidation]

- id: lending-027
  pattern: stablecoin-depeg-health-assumption
  name: "Hardcoded stablecoin peg assumption in health factor / LTV checks"
  causa_raiz: >
    Lending protocols that issue or accept stablecoins often hardcode the
    assumption that 1 stablecoin == $1 in their health factor, LTV, and
    liquidation calculations. The debt side uses raw token amounts instead of
    converting to USD via an oracle. When the stablecoin depegs (even slightly),
    the unit mismatch between USD-valued collateral and token-denominated debt
    causes incorrect health assessments: positions may appear healthy when
    actually insolvent (depeg down) or be unfairly liquidated (depeg up).
  como_funciona: >
    1. Protocol values collateral in USD via oracle: collateralValueUSD = amount * oraclePrice.
    2. Protocol values debt in raw token units assuming 1:1 peg: debtValueUSD = debtTokenAmount.
    3. Health factor = collateralValueUSD * LTV / debtValueUSD (but debt is in token units, not USD).
    4. Stablecoin depegs to $0.95. Real debt value is $0.95 per token.
    5. Protocol still treats debt as $1 per token. Health factor is understated.
    6. Positions that should be healthy get liquidated unfairly.
    7. OR depeg to $1.05: debt is undervalued, positions appear healthier than reality, silent insolvency.
  invariante: "health factor calculation must use USD-denominated values for BOTH collateral AND debt"
  que_mirar:
    - "healthFactor"
    - "getLTV"
    - "userDebt"
    - "collateralValue"
    - "1e18 (assumed price)"
    - "no oracle for debt token"
    - "isStable"
    - "== 1"
  como_se_arregla: "Use an oracle for the debt token as well, even for stablecoins. Apply the debt token price when calculating health factor. Add a circuit breaker that pauses the protocol if the stablecoin depegs beyond a threshold."
  trampas:
    - "Many protocols intentionally assume peg as a design choice -- check if there is explicit depeg handling"
    - "The bug only manifests during depeg events which may be rare but catastrophic"
    - "Some stablecoins have secondary oracles (Chainlink USDC/USD) that can be used"
  incidentes:
    - "USG-Tangent -- USG peg assumption in on-chain safety checks causes incorrect liquidation (medium, 8 finders)"
    - "The Standard Smart Vault -- USD stablecoins incorrectly assumed to always be at peg (high)"
    - "Colbfinance -- Incorrect collateral calculation due to inverted oracle math for near-peg assets (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, stablecoin, depeg, health-factor, oracle, peg-assumption, unit-mismatch]

- id: lending-028
  pattern: debt-share-rounding-rebase
  name: "Debt share value manipulation via rounding truncation and rate changes"
  causa_raiz: >
    Protocols that use shares to track debt (batch debt shares, borrow shares)
    are vulnerable when truncation-based integer math is combined with the
    ability to change the rate that determines share value. An attacker can
    repeatedly increase the debt share value (e.g., via rate changes), causing
    accumulated truncation errors that effectively forgive debt. Similarly,
    borrowers can be left with residual debt shares after full repayment (shares
    round up), or borrow without generating shares at all (shares round down to
    zero for dust amounts).
  como_funciona: >
    1. Debt is tracked as: userDebt = batchDebt * userShares / totalShares.
    2. Attacker calls setBatchManagerAnnualInterestRate() repeatedly, each time updating shares.
    3. Each share update truncates: newShares = oldDebt * newTotalShares / newTotalDebt.
    4. Accumulated truncation over many calls reduces effective debt significantly.
    5. Attacker borrows a full Trove worth of debt but owes nearly nothing after rebase.
    6. OR: user repays full debt amount, but shares round up, leaving 1 share of "phantom debt".
    7. OR: user borrows dust amount, shares round down to 0, free borrowing.
  invariante: "sum(userDebt via shares) == totalDebt (within 1 wei per user tolerance)"
  que_mirar:
    - "_updateBatchShares"
    - "totalDebtShares"
    - "borrowShares"
    - "debtSharesOf"
    - "mulDiv"
    - "roundUp vs roundDown"
    - "setBatchManagerAnnualInterestRate"
    - "convertToShares"
  como_se_arregla: "Use virtual shares offset for debt tracking. Round debt shares AGAINST the borrower (round up on borrow, round down on repay). Enforce minimum borrow amount that always produces at least 1 share. Limit frequency of rate changes that trigger share recalculation."
  trampas:
    - "1 wei of dust per operation is normal -- only large accumulated truncation is a bug"
    - "Rate change functions may be admin-only, reducing exploitability"
    - "Some protocols use ray math (1e27) which has much less truncation"
  incidentes:
    - "Bold -- Batch shares math can be rebased to forgive entire Trove debt via rounding + rate changes (high)"
    - "Sharwafinance -- Borrowers left with debt shares after full repayment (medium)"
    - "Sharwafinance -- Users can borrow tokens without generating debt shares (critical)"
    - "Meso Lending -- Removal of incorrect debt shares (medium)"
    - "ZeroLend One -- Wrong calculation of supply/debt balance of a position (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, debt-shares, rounding, truncation, rebase, rate-change, batch]

- id: lending-029
  pattern: index-overflow-dos-dust-supply
  name: "Interest/reward index overflow when totalSupply is dust, causing permanent DoS"
  causa_raiz: >
    Lending protocols use scaled balance mechanisms where an index tracks
    cumulative interest or reward accrual per unit of token. The index is stored
    in a fixed-size integer (e.g., uint104, uint128). When the total supply of
    the underlying asset is extremely small (dust), the per-unit accrual becomes
    enormous, causing the index to overflow its storage type. Once overflowed,
    all transfers and state updates that touch the index revert permanently,
    bricking the market or reward distribution.
  como_funciona: >
    1. Market is created with very small totalSupply (e.g., 1 wei of aToken).
    2. Rewards or interest accrue normally, but per-unit index grows as rewards/totalSupply.
    3. With dust totalSupply, index grows rapidly: index += rewardsPerSecond * elapsed / totalSupply.
    4. Index exceeds type(uint104).max or type(uint128).max.
    5. All subsequent operations that read/update the index revert with overflow.
    6. Token transfers, deposits, withdrawals all permanently bricked for that market.
    7. First depositor attack variant: attacker creates dust market, triggers DoS.
  invariante: "index < type(uint_storage_type).max at all times; totalSupply must be above minimum for index accrual"
  que_mirar:
    - "uint104"
    - "uint128"
    - "scaledBalance"
    - "liquidityIndex"
    - "rewardIndex"
    - "totalScaledSupply"
    - "handleAction"
    - "type(uint104).max"
  como_se_arregla: "Cap the index to a maximum value. Use larger storage types (uint256). Enforce minimum totalSupply before enabling reward accrual. Skip accrual when totalSupply is below a threshold."
  trampas:
    - "This can take time to manifest -- index grows slowly with normal supply but explodes with dust"
    - "May be triggered by first-depositor attack (lending-010) as a secondary effect"
    - "Reward distributors and interest accumulators have separate indices -- check both"
  incidentes:
    - "Astera/Cod3x Lend -- Index reaches type(uint104).max when totalSupply is dust, DoS aToken transfers (high)"
    - "Astera/Cod3x Lend -- RewardsController inconsistent scaling in handleAction causes transfer DoS (high)"
    - "Dahlia -- Inflation of zero totalBorrowShares to disable borrowing (medium)"
    - "Folks Finance -- Infinite interest rate bug when supply is dust (high)"
    - "Sentiment V2 -- Super Pool shares inflated by bad debt leading to overflows (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, index, overflow, DoS, dust, totalSupply, scaled-balance, rewards]

- id: lending-030
  pattern: leverage-unwind-amount-mismatch
  name: "Leveraged vault unwind/deleverage uses wrong amounts, token, or path"
  causa_raiz: >
    Leveraged lending vaults (looping strategies) automate borrow-deposit cycles
    to amplify yield. The unwind/deleverage process reverses this: withdraw
    collateral, swap to repay token, repay debt. Multiple bugs cluster here:
    wrong token sent to user, incorrect swap amounts, flash loan fees not
    accounted, shares-to-assets conversion errors, and fee bypass during
    deleverage. The complexity of multi-step atomic operations across lending
    pool + DEX + vault creates many opportunities for amount mismatches.
  como_funciona: >
    1. User calls removeLeverage() to exit their leveraged position.
    2. Protocol takes flash loan to repay debt, freeing collateral.
    3. Collateral is withdrawn and swapped to underlying asset.
    4. BUG: swap amount uses pre-fee balance, or wrong token address, or wrong share conversion.
    5. User receives less than expected, or protocol retains excess, or the tx reverts.
    6. OR: flash loan fee is not subtracted from available amount, causing shortfall.
    7. OR: closeFee is only applied to one token path, easily bypassed by using alternate path.
  invariante: "user receives full collateral value minus fees; no tokens stuck in intermediate contracts"
  que_mirar:
    - "removeLeverage"
    - "unwind"
    - "deleverage"
    - "flashLoanFee"
    - "harvest"
    - "_removeLeverage"
    - "redeemShares"
    - "closeFee"
    - "swapAmount"
  como_se_arregla: "Calculate swap/repay amounts from actual balances after each step (not predicted amounts). Account for flash loan fees. Apply close fees at the vault level before any token routing. Verify no tokens are stuck after operation."
  trampas:
    - "Leveraged vaults are complex multi-step operations -- trace the full flow carefully"
    - "Slippage during deleverage swaps is expected -- only accounting bugs are real findings"
    - "Some leftover tokens may be by design (dust tolerance)"
  incidentes:
    - "Peapods -- _removeLeverage() provides incorrect amounts when swapping (high)"
    - "Peapods -- removeLeverage sends wrong token to user (high)"
    - "Peapods -- _removeLeverage uses incorrect amount when redeeming lending pair shares (high)"
    - "Peapods -- closeFee only collected for pTKN, easily bypassed (medium)"
    - "BakerFi -- Harvesting strategy doesn't account flashloan fee (medium)"
    - "BakerFi -- Leftover collateral from debt adjustment lost during harvest (high)"
    - "Beets Looped Sonic -- UNWIND_ROLE can extract profit via repeated slippage arbitrage (medium)"
    - "Numa -- leverageStrategy reentrancy crashes token price (high)"
    - "Elfi -- Deleveraging results in zero borrowed amount while maintaining leveraged position (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, leverage, unwind, deleverage, flash-loan, swap, amount-mismatch, vault]

- id: lending-031
  pattern: emode-isolation-config-residual
  name: "E-Mode/isolation mode config changes leave stale elevated parameters"
  causa_raiz: >
    Aave-fork E-Mode allows elevated collateral factors and LTV for correlated
    asset groups. When an asset is removed from an E-Mode category, or when
    isolation mode configuration is changed, existing positions may retain the
    old elevated parameters. Users in E-Mode with the removed asset continue
    getting higher collateral factor than the default, leading to
    undercollateralized positions. Similarly, once a position enters isolation
    mode, there may be no mechanism to exit it.
  como_funciona: >
    1. Admin adds Asset X to E-Mode category with 95% LTV (default is 75%).
    2. Users deposit Asset X and borrow at 95% LTV.
    3. Admin removes Asset X from E-Mode category.
    4. Existing users STILL get 95% LTV because their E-Mode flag is not cleared.
    5. Their positions are now undercollateralized relative to the true risk.
    6. If price drops, bad debt accrues because the effective LTV was too high.
    7. OR: user enters isolation mode, but no function exists to exit it, permanently limiting their account.
  invariante: "if asset not in E-Mode category, collateral factor must equal default; isolation mode must be exitable"
  que_mirar:
    - "supportEMode"
    - "setEModeCategory"
    - "removeAsset"
    - "_getCollateralFactor"
    - "_getLiquidationThreshold"
    - "isInIsolationMode"
    - "exitIsolationMode"
    - "configureEModeCategory"
  como_se_arregla: "When removing an asset from E-Mode, force all users using that asset in E-Mode to revert to default parameters. Provide an explicit exitIsolationMode function. Validate positions against current (not cached) E-Mode parameters."
  trampas:
    - "E-Mode removal is a rare admin action, but the impact on existing positions is immediate"
    - "Some protocols cache E-Mode parameters at borrow time, making changes even harder to propagate"
  incidentes:
    - "NUTS Finance/Cod3x Lend -- E-Mode misconfiguration causing inaccurate collateral accounting (medium)"
    - "Resolv -- No mechanism to exit isolation mode once entered (medium)"
    - "BendDAO -- Updating asset collateral params can lead to arbitrary liquidation (medium)"
    - "Sentiment V2 -- LTV of 98% would be extremely dangerous (medium)"
    - "Duality Focus -- Undercollateralized loans possible, no upper bound on collateral factor (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, E-Mode, isolation-mode, config, collateral-factor, LTV, stale-parameters]

- id: lending-032
  pattern: minipool-subpool-borrow-bypass
  name: "Sub-pool/minipool borrows from restricted main pool reserves"
  causa_raiz: >
    Hierarchical lending architectures (main pool + minipools/sub-pools) allow
    sub-pools to borrow from the main pool. If access controls on the main pool
    do not properly filter sub-pool borrow requests, minipools can borrow from
    reserves that are flagged as non-borrowable, frozen, or restricted. The
    minipool owner can also create positions that are unliquidatable from the
    main pool's perspective, imposing bad debt on main pool depositors.
  como_funciona: >
    1. Main lending pool has Reserve X marked as non-borrowable (governance decision).
    2. Minipool is a separate contract that interacts with main pool as a borrower.
    3. Minipool's borrow function does not check main pool's reserve restrictions.
    4. Minipool borrows from Reserve X, bypassing the non-borrowable flag.
    5. OR: Minipool owner creates a position where the minipool itself is the borrower, but liquidation logic cannot access the minipool's internal positions.
    6. If minipool defaults, bad debt is imposed on the main pool with no recourse.
  invariante: "sub-pool borrows must respect ALL main pool reserve restrictions; sub-pool positions must be liquidatable by main pool"
  que_mirar:
    - "minipool"
    - "subPool"
    - "isBorrowableReserve"
    - "validateBorrow"
    - "liquidateMiniPool"
    - "flowLimiter"
    - "reserveIsActive"
    - "reserveIsFrozen"
  como_se_arregla: "Enforce main pool reserve restrictions in minipool borrow paths. Ensure minipool positions are visible and liquidatable by the main pool. Set flow limits and borrow caps per minipool."
  trampas:
    - "Minipools may have different risk parameters by design -- only RESTRICTION BYPASS is a bug"
    - "Liquidation of minipool positions requires understanding the hierarchical ownership model"
  incidentes:
    - "Astera/Cod3x Lend -- Minipools can borrow from lending pool reserves that are not borrowable (high)"
    - "Astera/Cod3x Lend -- Minipool owner can create unliquidatable loan, imposing bad debt on main pool (medium)"
    - "Astera/Cod3x Lend -- Mini pool reserves for unique tokens can be reinitialised (medium)"
    - "Astera/Cod3x Lend -- variableBorrowIndex only updated if currentLiquidityRate nonzero in minipool (medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, minipool, sub-pool, borrow-bypass, access-control, bad-debt, hierarchical]

- id: lending-033
  pattern: front-run-bad-debt-socialization
  name: "Front-running bad debt socialization by closing/reopening positions"
  causa_raiz: >
    When bad debt from a liquidation is socialized (redistributed) across all
    open positions in a pool, users who can predict the socialization event can
    close their positions before it happens and reopen afterward, avoiding their
    share of the loss. This shifts a disproportionate amount of bad debt onto
    remaining depositors/borrowers who could not exit in time.
  como_funciona: >
    1. Alice sees a large position is about to be liquidated with bad debt.
    2. Alice closes her Trove/position before the liquidation executes.
    3. Liquidation happens, bad debt is redistributed among remaining open Troves.
    4. Alice reopens her Trove immediately after the redistribution.
    5. Alice avoided her share of the bad debt entirely.
    6. Remaining users absorb Alice's portion, suffering greater losses.
    7. With multiple positions, this can be automated to systematically dodge all bad debt events.
  invariante: "no user should be able to avoid bad debt socialization by timing position open/close around liquidation"
  que_mirar:
    - "redistributeDebt"
    - "socializeLoss"
    - "closeTrove"
    - "openTrove"
    - "redistributionSnapshot"
    - "pending redistribution"
    - "applyPendingRewards"
    - "StabilityPool"
  como_se_arregla: "Implement a cooldown period after opening a position before it can be closed. Record pending redistributions for all addresses (not just open positions). Use snapshot-based socialization that includes recently-closed positions."
  trampas:
    - "In practice, closing and reopening has gas costs that may make this uneconomical for small amounts"
    - "Some protocols use StabilityPool instead of redistribution, partially mitigating this"
    - "Block-level atomicity makes this easy on L2s with cheap gas"
  incidentes:
    - "Bima -- Users can prevent getting bad debt by withdrawing just before liquidation (medium)"
    - "Bima -- Bad debt redistribution not happening between liquidations in batch mode (high)"
    - "Panoptic -- Withdrawing before bad debt event increases losses for remaining LPs (medium)"
    - "Exactly Protocol -- Bad debt not cleared when earningsAccumulator is below fixed-pool bad debt (medium)"
    - "ZeroLend One -- When bad debt accumulated, loss not shared amongst all suppliers (high)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [lending, bad-debt, front-running, socialization, redistribution, timing, dodge]

- id: lending-034
  pattern: transform-arbitrary-data-injection
  name: "transform() passes unvalidated calldata to arbitrary transformer"
  causa_raiz: >
    Lending vaults that support a `transform(tokenId, transformer, data)` pattern
    allow any depositor to call a whitelisted transformer with arbitrary `data`. If the
    contract only checks that the transformer is approved but not that the caller
    owns the position or that `data` encodes expected parameters, any depositor can
    hijack another user's position that has approved the transformer contract.
  como_funciona: |
    1. Alice has position tokenId=1 and has approved TransformerX on the vault.
    2. Bob calls vault.transform(1, TransformerX, maliciousData).
    3. Vault checks: transformer == TransformerX ✓ (whitelisted).
    4. Vault does NOT check: does Bob own tokenId=1? Does maliciousData encode valid params?
    5. TransformerX executes with Alice's position + Bob's data → drains Alice.
  invariante: "msg.sender must own or be approved for tokenId before transform() can execute"
  que_mirar:
    - "Does transform() check msg.sender == ownerOf(tokenId) before delegating?"
    - "Is there a per-position approval whitelist, or only a global transformer whitelist?"
    - "Can data encoding be crafted to trigger unintended state in the transformer?"
    - "Does the transformer re-enter the vault to manipulate collateral token config?"
  como_se_arregla: "Add require(ownerOf(tokenId) == msg.sender || approved[tokenId][msg.sender]) before calling transformer. Validate data length/selector at minimum."
  trampas:
    - "A transformer being whitelisted does NOT mean any caller can use it on any position"
    - "The reentrancy risk here is transform → vault.onERC721Received → manipulate config shares — check call ordering"
    - "If transform() is protected by a modifier that checks ownership, the bug doesn't exist — confirm the modifier applies"
  severidad: high
  confianza: alta
  fuente: "Solodit: Revert Lend H-03 (transform data validation), Revert Lend H-02 (onERC721Received reentrancy)"
  verificado: false
  tags: [transform, callback, access-control, calldata-injection, ERC721, reentrancy]
  relacionado_con: [lending-007, lending-008]

- id: lending-035
  pattern: pause-skips-interest-accrual
  name: "Pause window silently skips interest — interest-free window on unpause"
  causa_raiz: >
    Protocols that update `lastRateUpdate = block.timestamp` on unpause (or in the
    first accrue call after unpause) effectively forgive all interest that accrued
    during the pause window. This is usually unintentional — the intent is to prevent
    a large spike on unpause, but the result is that borrowers get free credit for
    potentially days or weeks during which the protocol was paused.
  como_funciona: |
    1. Protocol has $10M in loans at 10% APY.
    2. Admin pauses for 14 days (security incident or upgrade).
    3. On unpause, _accrueFee / _updateInterest runs: lastRateUpdate = block.timestamp.
    4. The 14-day interest (~$38K) is never collected.
    5. Borrowers pocket $38K. Lenders receive nothing for that period.
    6. If pause is triggered by attacker, they borrow max, wait for admin to pause, unpause = interest-free loan.
  invariante: "Accumulated interest for any time window must be collected regardless of pause/unpause events"
  que_mirar:
    - "What happens to lastRateUpdate / lastAccruedTimestamp when protocol is paused?"
    - "Does the unpause function or the first post-unpause accrue reset the timestamp?"
    - "Can an attacker trigger a pause via governance attack or emergency mechanism to get free interest?"
    - "Is there a cap on pause duration? What happens if paused for 365 days?"
  como_se_arregla: "Separate interest-accrual tracking from operational state. Never reset lastRateUpdate to block.timestamp on unpause — instead, process accrued interest up to the pause timestamp first, then resume from there."
  trampas:
    - "Some protocols INTENTIONALLY skip interest during pause as compensation for users — verify design intent in docs"
    - "A pause that resets to block.timestamp is not always exploitable if there is no way to trigger pause as an attacker"
    - "The IonProtocol H-01 variant is subtler: _accrueFee is called WHILE paused, which resets the timestamp, then resumes from unpause time — look for accrue calls inside pausable functions"
  severidad: high
  confianza: media
  fuente: "Solodit: IonProtocol H-01 (pause timestamp skip), general pattern"
  verificado: false
  tags: [interest-accrual, pause, timestamp, lastRateUpdate, fee, economic-attack]
  relacionado_con: [lending-005, lending-006]

- id: lending-036
  pattern: liquidation-frontrun-griefing
  name: "1 wei repay prevents full liquidation — griefing via frontrun"
  causa_raiz: >
    If a liquidation function reverts when the debt after partial repay would be
    non-zero but below a minimum dust threshold, an attacker (or the borrower themselves)
    can frontrun a liquidator by repaying exactly 1 wei of debt. The position's debt
    is now slightly smaller, and the liquidation's internal math may revert because
    the resulting seizable collateral drops below a floor check, or the repay amount
    calculation is now stale. The position stays unhealthy but unliquidatable.
  como_funciona: |
    1. Bob has a position at 99% LTV — fully liquidatable.
    2. Alice submits liquidateFull(Bob) expecting to repay 1000 USDC, seize 1100 USDC.
    3. Bob frontruns with repay(1 wei).
    4. Alice's tx executes: debt is now 1000 USDC - 1 wei.
    5. Liquidation function calculates seizable collateral = floor((999.999... USDC) * factor).
    6. Either: seizable amount rounds to 0 or triggers a minimum check → revert.
    7. Bob's position stays at ~99% LTV, perpetually undercollateralized.
  invariante: "A position below health threshold must always be liquidatable by at least some non-zero amount"
  que_mirar:
    - "Are there minimum amounts on seized collateral or repaid debt in liquidation?"
    - "Does any arithmetic in liquidation path round to 0 for sub-1-wei differences?"
    - "Can the borrower call repay() to make their position borderline — below threshold but above minimum?"
    - "Is there a partial liquidation path that could get griefed by a tiny repay changing expected shares?"
  como_se_arregla: "Use current on-chain debt in liquidation math rather than calldata amount. Add a minimum liquidatable amount check and a revert-if-not-liquidatable guard that uses the real-time position state."
  trampas:
    - "This is primarily griefing, not direct fund theft — severity depends on how long a position can remain unhealthy"
    - "If liquidation uses msg.sender's specified repay amount (not max possible), it's less vulnerable because partial liquidation is already supported"
    - "Protocols with grace periods or keepers that auto-liquidate reduce exploitability"
  severidad: medium
  confianza: alta
  fuente: "Solodit: INIT Capital H-01 (1 wei frontrun liquidation griefing)"
  verificado: false
  tags: [liquidation, frontrun, griefing, dust, minimum-amount, MEV]
  relacionado_con: [lending-004, lending-009]

- id: lending-037
  pattern: missing-ltv-liquidation-threshold-gap
  name: "No gap between borrow LTV and liquidation threshold — instant liquidation on max borrow"
  causa_raiz: >
    If `maxBorrowLTV == liquidationThreshold` (or `collateralFactor == liquidationThreshold`),
    a user who borrows the maximum allowed amount is IMMEDIATELY liquidatable in the same block
    (or next block due to any interest accrual). There is no buffer zone where the position
    is "safe" after a max borrow. Any interest tick or tiny price movement instantly makes it
    liquidatable.
  como_funciona: |
    1. Protocol sets borrowLTV = 80%, liquidationThreshold = 80% (no gap).
    2. User deposits 1 ETH ($3000), borrows $2400 USDC (exactly 80% LTV).
    3. Block N+1: interest accrues, effective LTV = 80.001%.
    4. Position is immediately liquidatable — user had no "safe zone".
    5. If flash-loan: borrow max in same tx → liquidate in same tx → profit the liquidation penalty.
  invariante: "borrowLTV + minimum_safe_buffer < liquidationThreshold (at least 2-5% gap)"
  que_mirar:
    - "What are the configured LTV and liquidation threshold values per collateral type?"
    - "Is there a dedicated 'collateralFactor' separate from 'liquidationFactor'?"
    - "How quickly does interest accrue? (high-rate assets hit threshold faster)"
    - "Can a governance tx set them equal? Is there a validation on the setter?"
  como_se_arregla: "Enforce borrowLTV + buffer <= liquidationThreshold in the setter. Typical gap: 5-10%. Add an on-chain require in setLTV-like functions to prevent equal values."
  trampas:
    - "Some protocols use separate per-token LTV and global liquidation threshold — verify all code paths use the right value"
    - "If interest is low enough, equal LTV/threshold may be functionally safe — check actual rate configs"
    - "The instant-liquidation scenario may require the oracle to be called in the same tx — check oracle freshness requirements"
  severidad: medium
  confianza: alta
  fuente: "Solodit: Euler EVK (missing LTV/liquidation gap), general Compound/Aave pattern"
  verificado: false
  tags: [LTV, liquidation-threshold, collateral-factor, gap, interest, economic-attack]
  relacionado_con: [lending-003, lending-004]

- id: lending-038
  pattern: supply-borrow-cap-check-before-not-after
  name: "Supply/borrow cap checked before operation, not after — bypass by exact-amount overshoot"
  causa_raiz: >
    The cap enforcement uses a pre-state check (`require(current < cap)`) rather than
    a post-state check (`require(current + amount <= cap)`). An attacker can pass the
    pre-check with any current value below cap, then execute an operation that brings
    the total ABOVE the cap. The require passes because it only verifies the state
    before the loan/deposit is opened.
  como_funciona: |
    1. Protocol sets maxSupply = 1,000,000 USDC. Current supply = 999,999 USDC.
    2. Attacker calls openLoan(amount=500,000).
    3. Pre-check: require(999,999 < 1,000,000) → passes.
    4. Loan executes: new supply = 1,499,999 USDC.
    5. Cap bypassed by 499,999 USDC.
    6. Protocol is over-leveraged. Systemic risk if collateral drops.
  invariante: |
    // Post-state check (correct)
    assert(totalBorrows + amount <= borrowCap);
    assert(totalSupply + amount <= supplyCap);
  que_mirar:
    - "Does the cap check happen before or after updating the state variable?"
    - "Is the check `require(current < cap)` or `require(current + delta <= cap)`?"
    - "Are supply cap and borrow cap enforced in all entry paths (borrow, mint, openLoan, flashLoan)?"
    - "Can a flash loan temporarily exceed the cap without triggering a revert?"
    - "rg 'supplyCap|borrowCap|maxLoan|maxIssuance' --type sol"
  como_se_arregla: "Move cap check to AFTER state update: require(totalBorrows <= borrowCap). Or use: uint256 newTotal = totalBorrows + amount; require(newTotal <= borrowCap); totalBorrows = newTotal."
  trampas:
    - "Off-by-one: `<` vs `<=` in the pre-check — `< cap` allows exactly cap+delta"
    - "Some protocols enforce caps per-asset and globally — check both"
    - "If totalBorrows tracks shares not assets, cap in assets can be bypassed via rounding"
    - "Flash loans that borrow and repay in one tx may bypass a supply cap check that reads pre-tx state"
  incidentes:
    - "Synthetix (Sigma Prime) — openLoan() checks supply cap before issuance, not after; cap can be exceeded by exact overshot (HIGH)"
    - "Aave Protocol (OpenZeppelin) — Fixed-rate loan max size bypass via pre-check on available liquidity (HIGH)"
    - "Compound-fork forks — Multiple forks copied borrow cap check but placed it pre-accrual, bypassing via interest (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Synthetix Sigma Prime audit, Aave OpenZeppelin audit"
  tags: [lending, supply-cap, borrow-cap, pre-check, bypass, cap-enforcement]
  relacionado_con: [lending-005, lending-031]

- id: lending-039
  pattern: isolated-asset-allowed-as-cross-collateral
  name: "Isolation mode asset incorrectly accepted as standard cross-collateral"
  causa_raiz: >
    Aave V3 and forks introduce isolation mode: certain high-risk assets can ONLY be used
    as collateral when the user is in isolation mode, and ONLY to borrow specific approved
    stablecoins. When the integration layer (e.g., a lending optimizer like Morpho on top
    of Aave) does not replicate this isolation-mode check, users can supply an isolated
    asset and borrow arbitrary assets using it as cross-collateral — bypassing the risk
    segregation the underlying protocol enforces.
  como_funciona: |
    1. Aave V3 marks Token X as "isolated" — only borrowable stablecoins, capped at $1M.
    2. Integration protocol (Morpho/Compound-fork) reads Aave's aToken address for X.
    3. Integration does NOT call getUserConfiguration() or check isolationModeActive.
    4. User supplies X as collateral to integration.
    5. Integration treats X as normal cross-collateral, allows borrowing ETH/WBTC.
    6. If X depegs, massive undercollateralized exposure in assets that should be impossible.
    7. OR: isolation debt ceiling is a global cap — integration's borrow bypasses ceiling.
  invariante: |
    // For each user, if any supplied asset has ISOLATION_MODE flag:
    // 1. Only isolation-approved debt tokens allowed as borrow assets
    // 2. totalDebt <= isolationDebtCeiling
    assert(!isIsolatedAsset(collateral) || isApprovedIsolationBorrow(borrowAsset));
  que_mirar:
    - "Does the protocol check Aave's getUserConfiguration().isUsingAsCollateral with isolation flags?"
    - "Is there a check for DataTypes.ReserveConfigurationMap isolation bit (bit 56)?"
    - "Does the protocol enforce the isolation debt ceiling independently?"
    - "Can a user supply an isolated asset + a non-isolated asset together (violates isolation)?"
    - "rg 'isolat|ISOLATION|debtCeiling|getUserConfiguration' --type sol"
  como_se_arregla: "Before accepting collateral, call Aave's ValidationLogic to verify isolation constraints. Track isInIsolationMode per user. Block cross-collateral use of isolated assets. Mirror Aave's isolation ceiling tracking."
  trampas:
    - "Isolation mode is per-USER not per-asset: entering with any isolated asset locks out other collateral types"
    - "Aave's LTV=0 assets are related but different: LTV=0 means no NEW borrows, but existing borrows are valid"
    - "The isolation debt ceiling is global across ALL users borrowing against that asset — a single large position can block all others"
    - "Some isolation assets have LTV>0 for the isolated asset itself but 0 for cross-collateral use"
  incidentes:
    - "Morpho on Aave V3 (Spearbit) — Isolated assets treated as valid cross-collateral, bypassing isolation mode restrictions (CRITICAL)"
    - "Multiple Aave V3 forks — Integration layers that read aToken balances but ignore isolation-mode bit in reserveConfig (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Morpho Spearbit audit (isolated-assets-are-treated-as-collateral-in-morpho)"
  tags: [lending, isolation-mode, aave, cross-collateral, debt-ceiling, aave-v3, integration]
  relacionado_con: [lending-032, lending-027]

- id: lending-040
  pattern: health-factor-decimal-precision-error
  name: "Health factor precision mismatch allows liquidating all healthy positions"
  causa_raiz: >
    Health factor calculations involve multiple unit systems (basis points, WAD 1e18,
    percentages, token decimals). If the calculated healthFactor is in a different unit
    than the threshold it is compared against, ALL positions can appear unhealthy or ALL
    appear healthy — regardless of actual collateral ratios. A single missing scale factor
    (e.g., multiplying by 1e18 but comparing against 1e4) can make every user liquidatable.
  como_funciona: |
    1. Protocol stores collateralFactor as 8500 (basis points = 85%).
    2. Health factor calculated as: HF = collateral * collateralFactor / debt.
    3. Result is ~8500 * 1e18 / 1e18 = 8500.
    4. Liquidation guard: require(HF > DECIMAL) where DECIMAL = 1e18.
    5. 8500 < 1e18 → ALL positions appear unhealthy, ALL can be liquidated.
    6. Attacker liquidates every user at the liquidation discount.
    OR inverse:
    1. HF = collateral * 1e18 / debt → ~1.1e18.
    2. Liquidation threshold = 1100 (in basis points).
    3. 1.1e18 > 1100 always → NO positions can ever be liquidated. Bad debt accumulates.
  invariante: |
    // HF units must match threshold units
    // If HF is WAD (1e18 = 100%), threshold must be WAD
    // If HF is basis points (10000 = 100%), threshold must be in BPS
    assert(healthFactor(safeUser) > LIQUIDATION_THRESHOLD);
    assert(!healthFactor(unsafeUser) > LIQUIDATION_THRESHOLD); // unsafe user IS liquidatable
  que_mirar:
    - "What unit is the health factor returned in? (WAD, BPS, percentage, raw ratio)"
    - "What unit is DECIMAL, HEALTH_FACTOR_THRESHOLD, or collateralFactor in?"
    - "Are there multiple collateralFactor representations used interchangeably?"
    - "Does the math mix 1e18 (WAD) with 1e4 (BPS) in the same expression?"
    - "Is DECIMAL == 1e18 or 10000? What does HF actually represent?"
    - "rg 'healthFactor|DECIMAL|liquidat.*threshold|collateralFactor' --type sol"
  como_se_arregla: "Normalize all inputs to WAD (1e18) before health factor math. Enforce a single unit system. Add an explicit comment documenting the unit of each storage variable. Write a unit test: user at 150% collateral should have HF > 1e18."
  trampas:
    - "If collateralFactor is 0.85e18 (WAD) and you multiply by another 1e18, you overflow — precision errors can go both ways"
    - "Different collateral types may have different decimals — normalize BEFORE applying collateralFactor"
    - "A precision error that only allows liquidating 0.01% of positions may still be high severity if repeated"
    - "Inherited protocols (Compound fork, Aave fork) may change decimal convention in one place but not all callers"
  incidentes:
    - "Stader Labs (Sigma Prime) — healthFactor precision issue causes all healthy positions to be liquidatable (HIGH)"
    - "Navi Protocol (OtterSec) — Erroneous max_liquidable_collateral calculation leads to unfair liquidation (HIGH)"
    - "Venus Protocol (Code4rena) — blocksPerYear constant 5x too large in WhitePaperIRM; users overpay 5x interest (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Stader Labs Sigma Prime audit, Navi OtterSec audit"
  tags: [lending, health-factor, precision, decimal, WAD, basis-points, liquidation, unit-mismatch]
  relacionado_con: [lending-003, lending-015, lending-037]

- id: lending-041
  pattern: stake-position-fee-collateral-discontinuity
  name: "Stakear posicion NFT excluye fees del colateral — health factor colapsa instantaneamente"
  causa_raiz: >
    En protocolos que integran staking de posiciones V3 (e.g., Revert Lend + GaugeManager),
    la valoracion oracle del colateral cambia segun si la posicion esta stakeada:
    - No stakeada: oracle.getValue(tokenId, asset, ignoreFees=false) — incluye feeValue
    - Stakeada: oracle.getValue(tokenId, asset, ignoreFees=true) — excluye feeValue
    Si un usuario pide prestado usando la posicion como colateral (estado no stakeado),
    y el calculo de health incluye fees, el usuario puede luego stakear la posicion.
    Al stakear, el health check post-stake usa ignoreFees=true — el colateral se reduce.
    Si los fees representaban una fraccion significativa del colateral, la posicion
    puede quedar undercollateralizada inmediatamente despues del stake.
  como_funciona: |
    1. Alice tiene posicion con: liquidez=$1000, fees acumulados=$200, total=$1200.
    2. CollateralFactor=80%. collateralValue = $1200 * 80% = $960.
    3. Alice pide prestado $950 (sano: $960 >= $950).
    4. Alice llama stakePosition(tokenId). V3Vault._stake() ejecuta.
    5. Post-stake: oracle.getValue(ignoreFees=true) -> fullValue=$1000, collateralValue=$800.
    6. $800 < $950 debt -> posicion inmediatamente liquidatable.
    7. Alice no tenia intencion de liquidarse pero el acto de stakear la liquido.
    Variante maliciosa:
    1. Atacante tiene posicion marginalmente sana gracias a fees.
    2. Stakea -> health colapsa -> otro usuario la liquida inmediatamente.
    3. Atacante pierde colateral pero potencialmente evita pagar el debt (si protocol tiene bad debt handling).
  invariante: |
    // stakePosition() debe verificar health con ignoreFees=true ANTES de permitir el stake
    // (no solo despues — el order de operaciones importa)
    assert(healthCheckWithIgnoreFees(tokenId) BEFORE stake executes);
    // si posicion tiene debt, post-stake health debe mantenerse
    assert(collateralValue_staked >= debt_after_stake);
  que_mirar:
    - "stakePosition() hace _requireLoanIsHealthy DESPUES del stake o ANTES?"
    - "El health check post-stake usa ignoreFees=true? (correcto) o ignoreFees=false? (incorrecto)"
    - "Cual es la diferencia maxima entre feeValue y fullValue en posiciones tipicas?"
    - "Puede el owner stakear una posicion con deuda maxima para triggear liquidacion de otro?"
    - "rg 'stakePosition|_isStaked|ignoreFees' --type sol"
  como_se_arregla: >
    Antes de ejecutar el stake, verificar health con la metrica post-stake (ignoreFees=true).
    Si el health check fallaria post-stake, revertir stakePosition() con CollateralFail.
    V3Vault.stakePosition() ya hace este check (linea 1390-1393) — pero verificar
    que el check ocurre en el estado post-stake (despues de _stake()), no pre-stake.
  trampas:
    - "V3Vault.sol ya implementa esta verificacion post-stake (linea 1388-1394) — confirmar que el check es post-stake, no pre"
    - "El riesgo real es si el check pre-stake usa la metrica incorrecta (con fees) y luego el post-stake la cambia"
    - "decreaseLiquidityAndCollect() puede reducir liquidez sin check staked/unstaked — verificar flujo"
    - "transformWithRewardCompound() re-stakea si wasStaked=true — mismo riesgo al re-entrar"
  incidentes:
    - "Patron especifico de Revert Lend GaugeManager — no hay incidentes previos documentados (NEW)"
  severidad: high
  confianza: media
  verificado: false
  fuente: "Analisis V3Vault.stakePosition() lineas 1381-1394 + _checkLoanIsHealthy() lineas 1423-1434 revert-lend 2026-03-21"
  tags: [lending, staking, collateral, health-factor, fees, ignoreFees, GaugeManager, discontinuity]
  relacionado_con: [lending-037, oracle-036, oracle-035]

- id: lending-042
  pattern: zero-liquidity-v3-nft-collateral
  name: "V3 NFT con liquidity=0 aceptado como colateral por tokensOwed residuales"
  causa_raiz: >
    V3Oracle.getValue() calcula el valor de una posicion sumando:
    (a) amounts de liquidez activa via _getAmounts() [cero si liquidity=0]
    (b) fees no cobrados via _getFees() = _getUncollectedFees() + tokensOwed
    Si la posicion tiene liquidity=0 pero tokensOwed > 0 (fees previos no cobrados),
    el oracle retorna value > 0. V3Vault acepta cualquier NFT de Uniswap v3 —
    no valida que liquidity > 0 en el momento del deposito. Un atacante puede
    depositar un NFT "vacio" (liquidity=0) con tokensOwed residuales como colateral,
    pedir prestado contra ese valor, luego cobrar los tokensOwed via transformer,
    dejando la posicion sin valor pero con deuda activa.
  como_funciona: |
    1. Atacante mint posicion V3 (rango, fee tier arbitrario).
    2. Agrega liquidez, genera fees via swaps, llama decreaseLiquidity para retirar
       toda la liquidez — tokensOwed quedan en el NonfungiblePositionManager.
    3. NO llama collect() — tokensOwed persisten (estado: liquidity=0, tokensOwed>0).
    4. Deposita NFT en V3Vault via create(). Vault acepta — no hay check de liquidity.
    5. oracle.getValue() calcula: amounts=0 (liquidity=0), fees=tokensOwed > 0.
    6. collateralValue = tokensOwed * collateralFactor.
    7. Atacante llama borrow() contra ese valor.
    8. Llama transform() con V3Utils/AutoCompound como transformer, collect calldata.
    9. tokensOwed van al atacante. Posicion queda con value=0, deuda activa.
    NOTA: _requireLoanIsHealthy se llama post-transform, pero si collect ocurre
    dentro del transformer antes del health check, la deuda ya se tomó.
  invariante: |
    // posicion depositada como colateral debe tener liquidity > 0
    assert(liquidity > 0 at time of create/onERC721Received);
    // o bien: collateralValue debe excluir tokensOwed de posiciones con liquidity=0
    assert(liquidity == 0 => collateralValue == 0);
  que_mirar:
    - "onERC721Received() valida liquidity > 0 antes de aceptar el NFT?"
    - "Puede borrow() ejecutarse cuando toda la value proviene de tokensOwed?"
    - "transformer.call(data) puede incluir collect() que drena tokensOwed pre-health-check?"
    - "Hay un minLoanSize que previene depositar NFTs de valor minimo?"
    - "rg 'tokensOwed|liquidity.*0|zero.*liquidity' en V3Oracle.sol y V3Vault.sol"
  como_se_arregla: >
    Opcion 1: En onERC721Received(), verificar que la posicion tiene liquidity > 0.
    Opcion 2: En _checkLoanIsHealthy(), excluir tokensOwed del collateralValue si liquidity=0.
    Opcion 3: Despues de cualquier transformer que pueda collect(), re-verificar health
    con la metrica actualizada (ya implementado en V3Vault transform flow).
    La mitigacion mas simple: require liquidity > 0 en create() / onERC721Received().
  trampas:
    - "minLoanSize mitiga parcialmente — un NFT vacio con fees minimos no llega al umbral"
    - "El transformer debe ser whitelisted — si solo V3Utils/AutoCompound son whitelisted, el collect path esta limitado"
    - "_requireLoanIsHealthy post-transform ES llamado (linea 579) — pero la deuda ya fue enviada en borrow()"
    - "Si borrow() ocurre DENTRO del transform (via transformer -> vault.borrow()), el health check es al final del transform"
    - "La ventana real: create() con tokensOwed -> borrow() directamente (no via transform) -> position value cero despues"
  incidentes:
    - "Patron derivado de analisis de V3Oracle.sol/V3Vault.sol Revert Lend — no hay incidente previo exacto (NEW)"
    - "ParaSpace (Code4rena) — V3 position collateral manipulation via pool price (HIGH, relacionado)"
  severidad: high
  confianza: media
  verificado: false
  fuente: "Analisis V3Oracle._getFees() + V3Vault.onERC721Received() + transform() revert-lend 2026-03-21"
  tags: [lending, v3-position, collateral, zero-liquidity, tokensOwed, fees, transformer, NFT]
  relacionado_con: [oracle-036, lending-034, lending-041]

- id: lending-043
  pattern: leverage-transformer-sandwich-undercollateralized-no-twap
  name: "LeverageTransformer.leverageUp — sin TWAP protection, sandwich crea posición apalancada undercollateralized"
  causa_raiz: >
    `LeverageTransformer.leverageUp()` no tiene protección TWAP (a diferencia de AutoRangeAndCompound).
    El flujo: borrow() → swap() vía router externo → increaseLiquidity(). Los parámetros
    `amountOut0Min`, `amountOut1Min`, `amountAddMin0`, `amountAddMin1` son controlados
    por el llamador. Si se pasan como 0 (o insuficientes), un attacker MEV puede:
    1. Poner el precio desfavorable antes del leverageUp.
    2. Permitir que la tx ejecute con slippage máximo.
    3. El valor añadido a la posición es menor que borrowAmount.
    4. El vault valida HF post-transform, pero si HF > minHealthFactor (e.g., 1.001), la tx pasa.
    5. La posición queda casi-liquidable y el attacker puede ejecutar liquidación obteniendo premium.
  como_funciona: |
    1. Owner: position ETH/USDC, collateral=2000 USDC, debt=0 USDC. HF = ∞.
    2. leverageUp params: borrowAmount=1000 USDC, amountIn0=1000 USDC→ETH,
       amountOut0Min=0, amountAddMin0=0, amountAddMin1=0.
    3. MEV sandwich: compra ETH antes, mueve precio +5% fuera del TWAP tolerance.
       (Sin TWAP check en leverageUp — la tx NO reverts por precio!)
    4. swap(1000 USDC → ETH) ejecuta a precio inflado: gets 0.28 ETH vs fair 0.33 ETH.
    5. increaseLiquidity(0.28 ETH, 0): añade ~560 USDC de valor.
    6. Net: debt +1000 USDC, collateral +560 USDC.
    7. Total: collateral=2560 USDC, debt=1000 USDC. HF = 2560*0.85/1000 = 2.18.
    8. Esto es sano — pero el leverage ratio es peor de lo esperado.
    ESCENARIO CRITICO (posición ya apalancada):
    Si collateral=1500, debt=800 USDC (HF=1.594), y leverageUp añade 600 USDC deuda pero
    solo 400 USDC valor → HF final = (1500+400)*0.85 / (800+600) = 1615/1400 = 1.15.
    Si HF_liquidation = 1.1, la posición queda a 5% del liquidation threshold.
  invariante: |
    // Valor neto añadido debe ser >= borrowAmount * collateralFactor
    // (para que el HF no empeore)
    uint256 addedValue = computePositionValue(added0, added1);
    uint256 minAcceptableAdded = borrowAmount * collateralFactor / 1e18;
    assert(addedValue >= minAcceptableAdded);
    // HF post-leverage debe ser >= HF pre-leverage (no se acepta empeoramiento)
    assert(healthFactorAfter >= healthFactorBefore);
  que_mirar:
    - "¿leverageUp tiene TWAP check? → NO (a diferencia de AutoRangeAndCompound.execute)"
    - "¿El vault chequea HF después de transform()? → Sí en V3Vault._requireLoanIsHealthy"
    - "¿Cuál es el minHealthFactor del vault? (si es 1.001, hay riesgo real de liquidación)"
    - "¿amountOut0Min y amountAddMin pueden ser 0? → Sí, calldata libre"
    - "¿params.recipient puede ser address(0) o una dirección maliciosa?"
    - "rg 'leverageUp|transform.*leverage|LeverageTransformer' --type sol"
    - "Comparar: AutoRangeAndCompound._validateSwap() vs leverageUp (ninguna validación)"
  como_se_arregla: "Añadir TWAP check en leverageUp similar al de AutoRangeAndCompound. El vault debería imponer un minHealthFactor más conservador post-leverage-transform. Documentar que amountOut0Min=0 expone al usuario a sandwich."
  trampas:
    - "El vault SÍ valida HF post-transform — el ataque requiere que el HF resultante sea aún > minHealthFactor"
    - "El usuario controla los parámetros de slippage — si pasa valores correctos, no hay riesgo"
    - "Para que sea explotable el HF inicial debe ser bajo (posición ya apalancada)"
    - "Revert Lend C4 H-03 parchado: transform() ya no permite llamadas arbitrarias — el exploit path está limitado"
    - "El llamador de transform() debe ser el owner del tokenId en V3Vault — no cualquier actor"
  incidentes:
    - "Revert Lend C4 (2024-03) H-03: transform() no valida data input — permite explotar posiciones ajenas (HIGH)"
    - "LoopFi C4 M-05: PositionAction4626.increaseLever siempre reverts por manejo incorrecto de leverage (MEDIUM, relacionado)"
    - "Paraspace TrailOfBits: V3 NFT flash claims pueden causar undercollateralization (HIGH, relacionado)"
  severidad: medium
  confianza: media
  verificado: false
  fuente: "Análisis directo LeverageTransformer.sol líneas 45-106, comparado vs AutoRangeAndCompound líneas 207-243"
  tags: [lending, leverage, transformer, slippage, sandwich, mev, no-twap, undercollateralized, uniswap-v3, vault-transform]
  relacionado_con: [lending-036, lending-042, dex-039]

- id: lending-044
  pattern: irm-utilization-same-block-manipulation
  name: "Interest rate manipulation via same-block utilization cycling (borrow at low rate, restore utilization)"
  causa_raiz: >
    Jump-rate interest rate models (Compound-style, kink-based) compute the borrow rate
    instantaneously from spot utilization = debt/(cash+debt) at transaction time. If a large
    actor can temporarily reduce utilization in the same block as a borrow (by depositing
    liquidity, borrowing at the low resulting rate, then withdrawing the deposit), they lock
    in a low borrow rate for the entire subsequent lazy-accrual period.
    In Revert Lend's InterestRateModel.sol: the formula is `debt * Q64 / (cash + debt)`.
    Interest accrues lazily via `_updateGlobalInterest()` called only on the next protocol
    interaction. A borrower who manipulates utilization at borrow-time pays the manipulated
    rate until the next vault interaction.
  como_funciona: |
    Setup: vault has cash=100K USDC, debt=90K → utilization=90% → above kink → jump rate ~100%/yr.
    Attack in single block (flash loan available) or across two blocks (whale LP):
    1. Deposit 1M USDC → utilization drops to ~8% → below kink → base rate = ~2%/yr.
    2. Borrow $500K at the low rate. Interest clock starts at 2%/yr.
    3. Withdraw the 1M USDC deposit (can be same or next block — no lock period in Revert Lend).
    4. Vault returns to high utilization, but attacker's debt accrues at 2%/yr until next update.
    Over 30 days on $500K borrow: saves ~$500K * (100%-2%) * 30/365 ≈ $40K in interest.
    Constraint in Revert Lend: `dailyDebtIncreaseLimitLeft` caps new borrows at ~10% of lent/day.
    At $1M TVL: max ~$100K/day new borrows. Limits max attack scale but does not eliminate pattern.
  invariante: |
    // Borrow rate locked at borrow time must reflect prevailing (not spot-manipulated) utilization
    // Property: successive large deposits+borrows in one block should not dramatically lower rate
    uint256 utilBefore = irm.getUtilizationRateX64(cashBefore, debtBefore);
    uint256 utilAfter = irm.getUtilizationRateX64(cashAfter, debtAfter);
    // If utilization dropped >50% in one block due to a deposit, rate manipulation is likely
    assert(utilAfter >= utilBefore / 2 || no_borrow_followed_large_deposit_in_same_block);
  que_mirar:
    - "Is the borrow rate computed from spot utilization or a time-weighted average?"
    - "What is the multiplier gap between below-kink and above-kink rates in the IRM config?"
    - "Is there a deposit lock period or withdrawal fee that prevents same-block round-trips?"
    - "How often is `_updateGlobalInterest()` called — triggered by any action or lazily?"
    - "Does `dailyDebtIncreaseLimitLeft` effectively bound the dollar value of the attack?"
    - "Can flash loans be used to deposit into the vault in the same tx as a borrow?"
    - "rg 'getUtilizationRateX64|kinkX64|_updateGlobalInterest' --type sol"
  como_se_arregla: >
    Use time-weighted average utilization (TWAP of utilization over N blocks/seconds) for
    interest rate computation instead of spot values. Alternatively, enforce a minimum
    deposit lock duration (e.g., 1 block or 1 hour) or add a symmetric deposit/withdrawal
    fee that makes round-trip manipulation economically unviable (cost > interest savings).
    Compound v3 / Aave v3 mitigate this by accruing interest continuously per-second on
    every state-changing call, making the benefit window zero.
  trampas:
    - "Revert Lend's `dailyDebtIncreaseLimitLeft` (~10%/day of TVL) limits attack scale significantly"
    - "Interest accrues lazily — the attacker benefits only until next vault interaction, which may be soon in a high-activity vault"
    - "Large depositors have legitimate reasons to enter/exit — distinguish griefing from innocent large LPs"
    - "If the protocol charges a deposit/withdrawal fee, the round-trip cost may exceed the interest savings"
    - "The reserve factor reduces attacker incentive (some interest goes to protocol reserves regardless)"
    - "The V3Vault has a per-day borrow limit — a single day's manipulation is bounded, but repeated daily attacks compound"
  incidentes:
    - "Teller Finance (Sherlock, H-8) — Interest rate in LenderCommitmentGroup manipulatable by depositing, borrowing, withdrawing (HIGH)"
    - "Exactly Protocol (Sherlock, M-2) — Fixed interest rates manipulated by whale borrower cycling borrows (MEDIUM)"
    - "Sharwafinance (Cantina, M-05) — Liquidity pool interest accrual manipulation via frequent borrows (MEDIUM)"
    - "Astera/Cod3x Lend (Spearbit) — Pi interest rate model manipulatable due to current balances used (MEDIUM)"
  severidad: medium
  confianza: media
  fuente: "Análisis InterestRateModel.sol revert-lend 2026 + Solodit lending domain search 2026-03-21"
  verificado: false
  tags: [lending, interest-rate, utilization, manipulation, kink, flash-loan, IRM, rate-manipulation, lazy-accrual, jump-rate]
  relacionado_con: [lending-009, lending-038, lending-043]

- id: lending-045
  pattern: v3-zero-liquidity-liquidation-dos
  name: "V3 NFT colateral con liquidity=0 hace revert la liquidacion en NonfungiblePositionManager"
  causa_raiz: >
    Cuando un protocolo de lending intenta liquidar una posicion V3 llamando a
    `decreaseLiquidity(tokenId, 0, ...)` en NonfungiblePositionManager, la llamada reverte
    porque el contrato de Uniswap valida que `liquidity > 0`. Si el atacante habia vaciado
    previamente la liquidez de la posicion (removiendo toda la liquidez sin cobrar los fees),
    la posicion tiene liquidity=0 en el momento de la liquidacion. El liquidador no puede
    ejecutar `decreaseLiquidity` ni `_unwrapUniPosition`, haciendo la posicion iliquidable.
    El atacante retiene el colateral sin repagar la deuda, generando bad debt.
  como_funciona: |
    1. Atacante deposita posicion V3 con liquidez real como colateral y pide prestado.
    2. Usando un transformer permitido (AutoRangeAndCompound, DecreaseLiquidityAndCollect),
       el atacante llama `decreaseLiquidity` para remover TODA la liquidez.
       Los fees quedan como tokensOwed pero liquidity=0.
    3. (Opcional: retira el prestamo y la posicion cae en undercollateralizacion naturalmente.)
    4. Precio cae, posicion se vuelve liquidatable.
    5. Liquidador llama liquidateAccount() → internamente llama _unwrapUniPosition() →
       llama positionManager.decreaseLiquidity(params) donde params.liquidity = 0.
    6. NonfungiblePositionManager.decreaseLiquidity() reverte con "IL" (invalid liquidity=0).
    7. Transaccion del liquidador falla. La posicion permanece iliquidable.
    8. Bad debt acumulado. Liquidador pierde gas. Protocolo absorbe la perdida.
    Variante combinada: atacante primero vacia liquidez via transformer ANTES de caer en
    undercollateralizacion. Si el protocolo no verifica `liquidity > 0` en el transformer,
    la operacion pasa el health check (tokensOwed mantienen algo de valor) y el atacante
    puede vaciar silenciosamente antes de que el precio caiga.
  invariante: |
    // Si una posicion es liquidatable, debe ser posible ejecutar la liquidacion
    // Propiedad: toda posicion con health factor < threshold debe ser liquidable
    bool liquidatable = collateralValue < debtValue * LIQUIDATION_THRESHOLD;
    if (liquidatable) {
        // liquidation must NOT revert
        uint128 posLiquidity = nftManager.positions(tokenId).liquidity;
        assert(posLiquidity > 0 || tokensOwed0 > 0 || tokensOwed1 > 0);
        // Y el protocolo debe manejar el caso liquidity=0 sin revert
    }
  que_mirar:
    - "¿La funcion de liquidacion llama decreaseLiquidity() sin verificar primero que liquidity > 0?"
    - "¿Puede el borrower vaciar la liquidez via transformer ANTES de que caiga el precio?"
    - "¿El health check en el transformer verifica el colateral DESPUES de reducir liquidez a 0?"
    - "¿Existe un guard `require(liquidity > 0)` en el unwind path de liquidacion?"
    - "rg 'decreaseLiquidity|_unwrapUniPosition|removeLiquidity' --type sol"
    - "rg 'liquidity.*0\\|positions.*liquidity' --type sol"
  como_se_arregla: >
    En la funcion de liquidacion, verificar `positions(tokenId).liquidity` antes de llamar
    `decreaseLiquidity`. Si liquidity=0, saltar directamente a `collect()` para recoger
    tokensOwed y continuar la liquidacion. Alternativamente, prohibir reducir liquidez a 0
    via transformer mientras existe deuda activa (health check post-transform incluye
    verificacion de `liquidity > 0 || deuda == 0`).
  trampas:
    - "Si liquidity=0 pero tokensOwed > 0, el colateral no es cero — collect() aun puede recuperar valor"
    - "Wild Credit tenia esta vulnerabilidad pero otros protocolos pueden haberla parcheado en el unwind path"
    - "El atacante necesita que el transformer permita bajar a liquidity=0 SIN que el health check falle"
    - "Si el protocolo requiere liquidity > MIN para aceptar la posicion como colateral, el ataque es mas dificil"
  incidentes:
    - "Wild Credit (Code4rena) — H-02: Liquidation escaped by depositing Uni V3 position with 0 liquidity; decreaseLiquidity(0) reverts in NonfungiblePositionManager (HIGH, Code4rena)"
    - "Revert Lend (Code4rena) — zero-liquidity-v3-nft-collateral: tokensOwed residuales aceptados como colateral con liquidity=0 (HIGH, relacionado)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Wild Credit Code4rena H-02 https://solodit.xyz/issues/h-02-liquidation-can-be-escaped-by-depositing-a-uni-v3-position-with-0-liquidity-code4rena-wild-credit-wild-credit-contest-git"
  tags: [lending, v3-position, liquidation, dos, zero-liquidity, nft-collateral, unwind, decreaseLiquidity, wild-credit]
  relacionado_con: [lending-040, lending-016, oracle-035]

- id: lending-046
  pattern: v3-nft-flash-claim-undercollateralization
  name: "Flash claim sobre NFT V3 colateralizado permite operar el activo y dejarlo undercollateralizado"
  causa_raiz: >
    Algunos protocolos de lending (ParaSpace) permiten "flash claims" sobre NFTs colateralizados:
    el usuario puede tomar ownership temporal del NFT por una sola transaccion, con la condicion
    de devolverlo al final. Esta funcionalidad, disenada para NFTs de arte/juego para permitir
    uso en airdrops o utilidades, se vuelve peligrosa con posiciones V3: durante la ventana del
    flash claim, el propietario temporal puede modificar la posicion (remover liquidez, cobrar
    fees, cambiar rango) sin que el protocolo re-verifique la salud del prestamo. Al devolver el
    NFT, la posicion vale menos de lo que valorizaba como colateral.
  como_funciona: |
    1. Usuario deposita posicion V3 con liquidez $100K como colateral y pide prestado $70K.
    2. Usuario inicia flash claim — toma ownership del NFT por una transaccion.
    3. Durante el flash claim, en la misma transaccion:
       a. Llama decreaseLiquidity() y collect() — extrae $100K de liquidez de la posicion.
       b. La posicion ahora tiene liquidity=0, tokensOwed=0, value=0.
    4. Devuelve el NFT al protocolo al final de la transaccion (requirido por el flash claim).
    5. Proteccion: el NFT esta de vuelta. Pero el VALOR del NFT colapso de $100K a $0.
    6. Deuda: $70K. Colateral: $0. Protocolo tiene bad debt instantaneo.
    Nota: NO requiere precio de mercado caer — el atacante activamente extrae el valor.
    El protocolo no valida la salud del prestamo AL DEVOLVER el NFT.
  invariante: |
    // El valor del colateral no puede disminuir durante un flash claim
    uint256 valueBefore = oracle.getValue(tokenId, ...);
    // [flash claim window]
    uint256 valueAfter = oracle.getValue(tokenId, ...);
    assert(valueAfter >= valueBefore * (1e18 - MAX_FLASH_VALUE_DROP) / 1e18);
    // O bien: health check obligatorio al finalizar el flash claim
  que_mirar:
    - "¿Existe una funcion flashClaim, flashLoan o borrow-NFT que devuelva temporalmente ownership?"
    - "¿El health check se ejecuta AL DEVOLVER el NFT, no solo al iniciarlo?"
    - "¿Puede el flash claimant modificar la composicion/liquidez del NFT durante la ventana?"
    - "¿El protocolo revalua el colateral despues del flash claim?"
    - "rg 'flashClaim|flashLoan.*NFT|safeTransferFrom.*collateral' --type sol"
    - "rg 'onERC721Received|_returnNFT|endFlashClaim' --type sol"
  como_se_arregla: >
    Revalidar el valor del colateral al finalizar el flash claim (no solo al inicio).
    Si el valor post-flash-claim cae por debajo del umbral de salud del prestamo, revertir
    la transaccion entera. Alternativamente, prohibir flash claims sobre posiciones que
    tengan deuda activa. Para posiciones V3 especificamente: durante el flash claim,
    solo permitir operaciones que no reduzcan el valor del colateral (e.g., colectar fees
    SIN remover liquidez, con cap en el valor extraible).
  trampas:
    - "Si el protocolo revalua el colateral post-flash y reverte si unhealthy, el ataque falla"
    - "Flash claims son una feature legitima para NFTs de utilidad (airdrops, juegos) — el fix no debe eliminarlos, sino acotarlos"
    - "La ventana de undercollateralizacion es intra-transaccion — no hay liquidacion durante ella, pero el estado persiste si no hay validacion final"
    - "Trail of Bits clasifico esto como HIGH porque la undercollateralizacion persiste post-transaccion (NFT devuelto pero vaciado)"
  incidentes:
    - "ParaSpace (Trail of Bits) — Uniswap V3 NFT flash claims may lead to undercollateralization: durante flash claim, borrower extrae todo el valor de la posicion V3 y la devuelve vacia (HIGH, Trail of Bits)"
    - "Astaria (Code4rena) — Security hook not set for non-V3 NFT blocks flash auction flow (LOW, relacionado — flash flow vulnerabilities en NFT lending)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: ParaSpace TrailOfBits https://solodit.xyz/issues/uniswap-v3-nft-flash-claims-may-lead-to-undercollateralization-trailofbits-paraspace-pdf"
  tags: [lending, v3-position, flash-claim, nft-collateral, undercollateralization, paraspace, liquidity-extraction, intra-tx]
  relacionado_con: [lending-040, lending-045, lending-016, oracle-036]

- id: lending-047
  pattern: v3-transform-unvalidated-data-input
  name: "V3Vault::transform no valida el data input — deposito/retirada arbitraria via transformer"
  causa_raiz: >
    V3Vault delega la ejecucion de transformaciones sobre posiciones V3 a contratos transformer
    externos (LeverageTransformer, AutoRange, AutoCompound, etc.). La funcion transform() recibe
    un tokenId, la direccion del transformer, y un bytes calldata data arbitrario que se pasa
    sin validacion al transformer via delegatecall o call. Un transformer malicioso — o uno
    legitimo con un data payload manipulado — puede usar este dato para ejecutar operaciones
    no autorizadas: depositar tokens del vault en el position de un atacante, retirar fondos,
    o modificar el estado de prestamos ajenos. El vault asume que cualquier direccion en la
    whitelist es segura, pero no valida el CONTENIDO de data ni QUIEN es msg.sender dentro
    del contexto de la llamada.
  como_funciona: |
    1. Atacante tiene acceso a un transformer en la whitelist (o puede ser el propio propietario
       de la posicion invocando un transformer legitimo con data malicioso).
    2. Llama V3Vault.transform(victimTokenId, transformerAddress, maliciousData).
    3. El transformer ejecuta con el contexto del vault usando maliciousData sin sanitizar.
    4. Dentro del transformer, maliciousData instruye a depositar fondos del vault en una
       posicion controlada por el atacante, o retirar colateral ajeno.
    5. Al volver al vault, el health check puede ser insuficiente o el estado ya es irreversible.
    6. Resultado: fondos del vault transferidos a atacante, o deuda de una posicion transferida
       a otra, o colateral extraido de posicion ajena.
  invariante: |
    // Solo el owner del tokenId puede iniciar transform sobre ese tokenId
    address owner = ownerOf(tokenId);
    require(msg.sender == owner || approvedOperators[owner][msg.sender],
            "transform: unauthorized");
    // Post-transform: health check obligatorio
    (uint256 debt, uint256 collateral) = _getPositionHealth(tokenId);
    assert(collateral * MIN_COLLATERAL_RATIO / 1e18 >= debt);
  que_mirar:
    - "¿V3Vault.transform() verifica que msg.sender es el owner del tokenId ANTES de llamar al transformer?"
    - "¿El data payload se valida o sanitiza en algun punto antes de ejecutar el transformer?"
    - "¿El transformer puede acceder a posiciones distintas del tokenId pasado?"
    - "¿Se ejecuta health check post-transform para el tokenId afectado?"
    - "rg 'function transform' src/V3Vault.sol"
    - "rg 'transformerAllowed|allowedTransformer' src/V3Vault.sol"
  como_se_arregla: >
    Verificar que msg.sender == ownerOf(tokenId) o es operator aprobado ANTES de invocar
    el transformer. Ademas, el data payload debe ser validado o codificado de forma que
    no pueda ser manipulado para referenciar recursos externos al tokenId. Ejecutar health
    check estricto despues de cada transformacion. Considerar pasar msg.sender al transformer
    para que este pueda validar el caller independientemente.
  trampas:
    - "Si transform() ya valida msg.sender == owner antes de la call, el vector es mitigado"
    - "El verdadero riesgo es si el transformer puede operar sobre tokenIds distintos al recibido"
    - "Algunos transformers usan delegatecall (ejecutan EN el contexto del vault) — esto amplifica el riesgo enormemente"
    - "Un data payload que apunta a otro tokenId (no el que se esta transformando) es el ataque clasico"
  incidentes:
    - "Revert Lend (Code4rena) — H-03: V3Vault::transform does not validate the data input, allows depositing tokens of one position into another position and draining vault funds (HIGH, Code4rena)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Revert Lend Code4rena https://solodit.xyz/issues/h-03-v3vaulttransform-does-not-validate-the-data-input-and-allows-a-depositor-to-drain-vault-funds-code4rena-revert-lend-git"
  tags: [lending, v3-position, transformer, data-validation, access-control, revert-lend, arbitrary-call]
  relacionado_con: [lending-044, lending-046, lending-009]

- id: lending-048
  pattern: onerc721received-reentrancy-collateral-manipulation
  name: "Reentrancy via onERC721Received permite manipular colateral antes de que el prestamo se registre"
  causa_raiz: >
    Cuando un protocolo de lending acepta NFTs (ej. posiciones Uniswap V3) como colateral via
    safeTransferFrom, el receptor ERC721 recibe el callback onERC721Received DURANTE la
    transferencia, antes de que el protocolo complete el registro del prestamo o la evaluacion
    del colateral. Si el callback no esta protegido con un reentrancy guard, el atacante puede
    reentrar el protocolo para: (1) modificar el estado del NFT que se esta depositando,
    (2) iniciar un prestamo sobre un colateral que aun no esta completamente registrado,
    o (3) manipular la contabilidad del vault antes de que se complete la operacion inicial.
    El estado del protocolo es inconsistente durante la ventana del callback.
  como_funciona: |
    1. Atacante llama deposit(nftId) en el vault de lending.
    2. Vault llama safeTransferFrom(atacante, vault, nftId).
    3. Durante la transferencia, ERC721 llama atacante.onERC721Received().
    4. Dentro del callback, atacante re-entra el vault:
       a. Llama borrow() usando el nftId que AUN NO esta completamente registrado.
       b. O llama a la funcion de liquidacion con estado inconsistente.
       c. O deposita otro NFT usando el estado manipulado.
    5. El vault registra el colateral POST-callback, pero el prestamo ya fue aprobado
       usando el estado pre-registro.
    6. Resultado: prestamo sin colateral valido, o colateral doble-contado, o liquidacion
       evitada porque el estado era inconsistente durante la verificacion.
  invariante: |
    // No se puede tener deuda en una posicion cuyo deposito no esta completo
    // (chequear via reentrancy guard o estado de "depositing" flag)
    bool depositInProgress = _depositInProgress[tokenId];
    if (depositInProgress) {
        // Ningun prestamo ni liquidacion puede ejecutarse sobre este tokenId
        assert(!_hasBorrow(tokenId));
    }
    // O simplemente: nonReentrant en todas las funciones criticas
  que_mirar:
    - "¿La funcion de deposito de NFT usa safeTransferFrom sin nonReentrant?"
    - "¿onERC721Received del vault puede ser llamado externamente o en reentrada?"
    - "¿El registro del colateral ocurre ANTES o DESPUES de la transferencia del NFT?"
    - "¿Puede un borrower iniciar prestamo dentro del callback onERC721Received?"
    - "rg 'onERC721Received' src/V3Vault.sol"
    - "rg 'safeTransferFrom.*nonReentrant|nonReentrant.*safeTransferFrom' src/"
  como_se_arregla: >
    Aplicar nonReentrant modifier a todas las funciones que inician con safeTransferFrom
    o que pueden ser llamadas durante el callback. Alternativa: usar transferFrom en lugar
    de safeTransferFrom (no llama callback) para deposito, y hacer la validacion del
    receptor manualmente. Si se mantiene safeTransferFrom, registrar el colateral ANTES
    de ejecutar la transferencia (checks-effects-interactions).
  trampas:
    - "Si el vault registra el colateral ANTES de llamar safeTransferFrom (CEI pattern), el ataque falla"
    - "La reentrancy via onERC721Received es menos obvia que la reentrancy via call() — los auditores la pasan por alto"
    - "El atacante DEBE ser un contrato (para implementar onERC721Received) — wallets normales no pueden hacer esto"
    - "Algunos protocolos mitigan esto con un mapping _depositLock[tokenId] pero olvidan validarlo en borrow()"
  incidentes:
    - "Revert Lend (Code4rena) — H-02: Risk of reentrancy in onERC721Received function to manipulate collateral tracking before loan is registered (HIGH, Code4rena)"
    - "Timeswap (Code4rena) — H-04: State updates made after callback in mint() allow reentrancy to mint liquidity without paying (HIGH, Code4rena)"
    - "Timeswap (Code4rena) — H-06: borrow() has state updates after callback to msg.sender, allowing debt manipulation (HIGH, Code4rena)"
    - "Key Finance — LPS-2: onERC721Received reentrancy in lending position system (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Revert Lend Code4rena https://solodit.xyz/issues/h-02-risk-of-reentrancy-onERC721Received-function-manipulate-collateral-code4rena-revert-lend-git"
  tags: [lending, reentrancy, onerc721received, nft-collateral, callback, v3-position, revert-lend, timeswap]
  relacionado_con: [lending-040, lending-009, lending-044, lending-046, lending-047]

- id: lending-049
  pattern: flash-loan-missing-initiator-check-margin-trading
  name: "Flash loan callback sin verificacion del iniciador — ejecucion arbitraria de acciones en nombre de otro usuario"
  causa_raiz: >
    Los contratos de margin trading o leverage que implementan callbacks de flash loan
    (onFlashLoan, executeOperation, uniswapV3FlashCallback) no siempre verifican que el
    llamador es EXACTAMENTE el pool de flash loan esperado Y que la transaccion fue iniciada
    por el usuario legitimo. Si solo se verifica el caller (el pool) pero no el initiator
    (quien origino el flash loan), un atacante puede llamar flashLoan() directamente pasando
    el contrato victima como receiver, forzandolo a ejecutar acciones — abrir/cerrar posiciones,
    depositar colateral, modificar deuda — sobre la cuenta de otro usuario sin su consentimiento.
  como_funciona: |
    1. Protocolo tiene MarginTrading.sol con executeOperation(assets, amounts, data) callback.
    2. executeOperation valida: require(msg.sender == aaveLendingPool) — solo verifica el pool.
    3. Atacante llama aaveLendingPool.flashLoan(receiver=victimMarginContract, ..., initiatorData).
    4. aaveLendingPool llama victimMarginContract.executeOperation() con data controlado por atacante.
    5. victimMarginContract ve msg.sender == aaveLendingPool (check pasa) pero NO verifica
       que el initiator sea el owner del contrato.
    6. Atacante puede: abrir posicion en nombre de la victima, depositar colateral ajeno,
       retirar fondos del contrato victima hacia su propia cuenta.
  invariante: |
    // En el callback del flash loan, verificar AMBOS: caller Y initiator
    function executeOperation(..., address initiator, bytes calldata params) external {
        require(msg.sender == address(lendingPool), "caller not pool");
        require(initiator == address(this) || initiator == owner, "unauthorized initiator");
        // Solo continuar si el flash loan fue iniciado por ESTE contrato o su owner
    }
  que_mirar:
    - "¿El callback de flash loan (executeOperation/onFlashLoan/uniswapV3FlashCallback) verifica el initiator ademas del caller?"
    - "¿Puede un atacante llamar el flash loan pool con este contrato como receiver?"
    - "¿El callback ejecuta acciones con fondos o posiciones del contrato sin validar quien inicio la llamada?"
    - "rg 'executeOperation|onFlashLoan|flashCallback' src/LeverageTransformer.sol"
    - "rg 'msg.sender.*lendingPool|require.*flashLoan' src/"
  como_se_arregla: >
    Verificar SIEMPRE que: (1) msg.sender es exactamente el pool de flash loan esperado,
    Y (2) el initiator es este mismo contrato o un caller autorizado. En Aave V2/V3:
    el parametro initiator en executeOperation debe ser address(this). En callbacks
    custom: usar un storage flag (flashLoanInProgress = true) activado antes de llamar
    al pool y verificado en el callback.
  trampas:
    - "Verificar solo msg.sender == pool NO es suficiente — cualquiera puede forzar un flash loan hacia el contrato"
    - "En Aave V3 el parametro se llama 'initiator' pero en otros pools puede llamarse 'sender' o no existir"
    - "Si el callback no ejecuta acciones privilegiadas (solo valida deuda), el riesgo es menor"
    - "LeverageTransformer en Revert Lend: si el flash loan callback no valida initiator, un atacante puede forzar leverage sobre cualquier posicion"
  incidentes:
    - "DODO Margin Trading (PeckShield) — H-1: MarginTrading.sol missing flash loan initiator check allows attacker to open/close positions on behalf of any user (HIGH, PeckShield)"
    - "Stakewise (Sigma Prime) — STAKE-6: Unprotected flash loan callback abused to manipulate and claim other users' positions (HIGH, Sigma Prime)"
    - "Fuji Protocol — FlasherFTM unsolicited invocation of flash loan callback bypasses CREAM auth (HIGH)"
    - "Paribus — Missing flash loan initiator check in leveraged position contract (LOW)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: DODO Margin Trading PeckShield https://solodit.xyz/issues/h-1-margintradinsolmissing-flash-loan-initiator-check-allows-attacker-to-open-positions-peckshield-dodo-margin-trading-pdf"
  tags: [lending, flash-loan, initiator-check, margin-trading, leverage, callback, access-control, dodo, stakewise]
  relacionado_con: [lending-040, lending-043, lending-044, lending-009, lending-047]

- id: lending-050
  pattern: uniswapv3-swap-callback-missing-caller-validation
  name: "uniswapV3SwapCallback / uniswapV3MintCallback sin validacion del caller — fondos extraibles por cualquier contrato"
  causa_raiz: >
    Los contratos que implementan uniswapV3SwapCallback o uniswapV3MintCallback para interactuar
    con pools Uniswap V3 (swaps, mints de liquidez) deben verificar que el llamador es un pool
    V3 legitimo. Sin esta validacion, cualquier contrato puede llamar el callback directamente
    sin que haya ocurrido un swap o mint real, forzando al contrato victima a transferir tokens
    (para "pagar" el swap/mint que nunca ocurrio). El contrato victima tiene tokens aprobados
    al pool o los transfiere en el callback asumiendo que viene de un pool legitimo.
  como_funciona: |
    1. Contrato victima (V3Utils, AutoRange, LeverageTransformer) implementa:
       function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) {
           // Transfiere tokens para "pagar" el swap
           IERC20(token).transfer(msg.sender, amount);
       }
    2. No hay require(msg.sender == computePoolAddress(...)).
    3. Atacante despliega FakePool que llama victima.uniswapV3SwapCallback(amount0, 0, fakeData).
    4. Victima transfiere tokens al FakePool pensando que es un pool legitimo.
    5. Todos los tokens aprobados o en custodia del contrato son extraibles.
  invariante: |
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external override {
        // CRITICO: verificar que el caller es un pool V3 real con los parametros correctos
        (address token0, address token1, uint24 fee) = abi.decode(data, (address, address, uint24));
        address expectedPool = IUniswapV3Factory(factory).getPool(token0, token1, fee);
        require(msg.sender == expectedPool, "callback: invalid pool");
        require(expectedPool != address(0), "callback: pool not found");
    }
  que_mirar:
    - "¿uniswapV3SwapCallback verifica que msg.sender es un pool V3 real via factory.getPool()?"
    - "¿uniswapV3MintCallback hace la misma validacion?"
    - "¿El contrato transfiere tokens en el callback sin validar el caller?"
    - "¿Se pasan los parametros del pool (token0, token1, fee) en el data del callback para recalcular la direccion?"
    - "rg 'uniswapV3SwapCallback|uniswapV3MintCallback' src/V3Utils.sol src/LeverageTransformer.sol"
    - "rg 'msg.sender.*pool|getPool.*factory' src/"
  como_se_arregla: >
    En cada callback, decodificar los parametros del pool (token0, token1, fee) y recalcular
    la direccion del pool usando IUniswapV3Factory(factory).getPool(). Verificar que
    msg.sender == pool calculado. Alternativamente, verificar que msg.sender tiene el
    codehash de un pool V3 legitimo (menos robusto). El patron estandar de Uniswap V3
    es pasar los parametros en el bytes data y verificar en el callback.
  trampas:
    - "Verificar solo que msg.sender != address(0) o que tiene cierto balance NO es suficiente"
    - "Un atacante puede deployar un contrato en la direccion esperada si usa CREATE2 con los parametros correctos — verificar via factory siempre"
    - "Si el contrato no tiene tokens aprobados ni en custodia, el impacto es bajo aunque el callback sea llamable"
    - "V3Utils.sol y LeverageTransformer.sol de Revert Lend tienen callbacks — CRITICO verificar esta validacion"
  incidentes:
    - "Barter DAO (Sherlock) — Missing caller verification in uniswapV3SwapCallback() allows any contract to force token transfers (LOW, Sherlock)"
    - "Gamma (Trail of Bits) — Uniswap V3 callbacks access control should be hardened to prevent unauthorized invocation (LOW, Trail of Bits, Fixed)"
    - "Sushi (Trail of Bits) — Use shared callback handler for uniswapV3SwapCallback and algebraSwapCallback with proper caller validation (LOW, Trail of Bits)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Barter DAO Sherlock https://solodit.xyz/issues/missing-caller-verification-in-uniswapv3swapcallback-sherlock-barter-dao-git"
  tags: [lending, uniswap-v3, swap-callback, mint-callback, access-control, callback-validation, v3utils, leverage-transformer]
  relacionado_con: [lending-047, lending-048, lending-044, lending-009]

- id: lending-051
  pattern: leverage-deleverage-missing-slippage-protection
  name: "LeverageTransformer sin slippage check en remove leverage — tokens bloqueados o perdida por swap desfavorable"
  causa_raiz: >
    Las funciones de leverage y deleverage que ejecutan swaps en pools Uniswap V3 (o similares)
    para rebalancear colateral/deuda necesitan parametros de slippage: amountOutMinimum en swaps
    exactInput, o sqrtPriceLimitX96 en swaps directos al pool. Sin estos limites, un bloque
    con precio desfavorable (MEV, manipulacion de pool, condiciones de mercado) puede resultar
    en: (1) swap que produce menos tokens de los esperados, dejando el loan undercollateralizado
    despues de la operacion, o (2) la transaccion queda bloqueada esperando condiciones que
    nunca llegan. En leverage operations criticas (flash loan + swap + repay en un bloque),
    la falta de slippage puede causar que el repago del flash loan falle o que queden tokens
    atascados en el transformer.
  como_funciona: |
    1. Usuario llama removeLeverage(tokenId, params) en LeverageTransformer.
    2. Transformer usa flash loan para obtener tokens y cerrar la posicion.
    3. Swap interno: swapExactInputSingle(tokenIn, tokenOut, amountIn, amountOutMin=0).
       — amountOutMinimum = 0 significa: acepta cualquier precio, incluso 0.
    4. MEV bot ve la transaccion en mempool, ejecuta sandwich attack:
       — Compra tokenOut antes → sube precio → usuario recibe menos tokenOut.
       — Vende despues → baja precio de nuevo.
    5. Usuario recibe tokenOut insuficiente → no puede repagar el flash loan → TX revert.
    6. O peor: si el amountOut es mayor que el monto del flash loan pero menor que lo esperado,
       la TX no revierte pero el usuario pierde el exceso al mercado.
    Variante con tokens bloqueados: si el swap falla por slippage, el transformer retiene
    los tokens pero no los devuelve al usuario (no hay path de rescate).
  invariante: |
    // En cualquier swap dentro de leverage/deleverage, el slippage debe ser acotado
    // amountOutMinimum debe ser >= precio_oraculo * amountIn * (1 - MAX_SLIPPAGE)
    uint256 minOut = oracle.getExpectedOut(tokenIn, tokenOut, amountIn)
                         * (1e18 - MAX_ALLOWED_SLIPPAGE) / 1e18;
    require(params.amountOutMinimum >= minOut, "slippage too high");
    // Tambien verificar deadline
    require(params.deadline >= block.timestamp, "swap expired");
  que_mirar:
    - "¿Las funciones leverageUp/leverageDown/removeLeverage pasan amountOutMinimum != 0 al swap?"
    - "¿Hay un deadline en los params del swap para evitar ejecucion en bloque viejo?"
    - "¿Si el swap falla o produce menos tokens de lo esperado, hay path de recuperacion?"
    - "¿Quien controla el amountOutMinimum — el usuario o el contrato? Si es el contrato, ¿usa oracle?"
    - "rg 'amountOutMinimum|sqrtPriceLimitX96|exactInputSingle' src/LeverageTransformer.sol"
    - "rg 'leverageUp|leverageDown|removeLeverage|deleverage' src/"
  como_se_arregla: >
    Pasar siempre amountOutMinimum calculado via oracle (TWAP) con tolerancia razonable
    (0.5-2% slippage max). Incluir deadline en todos los swaps. Si el usuario provee
    params, validar que amountOutMinimum >= piso minimo derivado del oracle. Para
    operaciones atomicas (flash loan + swap + repay), calcular el minOut requerido
    para que el repago del flash loan tenga exito con margen de seguridad.
  trampas:
    - "Si el usuario puede setear amountOutMinimum=0 intencionalmente (sabe que el slippage es alto), puede ser 'by design' — verificar si el protocolo obliga un minimo"
    - "Peapods: tokens bloqueados son HIGH; solo slippage es MEDIUM — la severidad depende si hay recovery path"
    - "El sandwich attack requiere mempool visible — en L2s con sequencer centralizado el riesgo es menor"
    - "TWAP oracles no funcionan bien para tokens con liquidez baja — el fix del oracle puede crear otro problema"
  incidentes:
    - "Peapods Finance (Code4rena, Nov 2024) — H-06: No slippage checks when removing leverage leads to stuck tokens if slippage exceeds _podAmountOutMin (HIGH, Code4rena)"
    - "Peapods Finance — H-6: LeverageManager remove leverage will lead to stuck tokens if slippage _podAmountOutMin is too strict (HIGH)"
    - "Numa Protocol (Sherlock) — M-11: No slippage check for leverageStrategy function allows sandwich attacks on leverage operations (MEDIUM, Sherlock)"
    - "Fuji Protocol — Missing slippage protection for rewards swap in compound strategy (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Peapods Finance Code4rena https://solodit.xyz/issues/h-06-no-slippage-checks-when-removing-leverage-code4rena-peapods-2024-11-16-git"
  tags: [lending, leverage, deleverage, slippage, uniswap-v3, swap, flash-loan, mev, sandwich, leverage-transformer]
  relacionado_con: [lending-047, lending-009, lending-046, oracle-036]
```

---

## 2. Invariantes Clave

### Solvency (if any of these break, funds are at risk)

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `totalAssets >= fundsAsset.balanceOf(pool)` | Pool can't owe more than it holds + loans | INV-POOL-001 |
| `totalAssets == cash + sum(AUM)` | Fundamental asset decomposition | INV-POOL-012 |
| `unrealizedLosses <= totalAssets` | Bad debt can't exceed total value | INV-POOL-013 |
| `token.balanceOf(vault) + totalBorrows >= totalSupply` | Core solvency equation | INV-LEND-007 |
| `totalSupplyAssets >= totalBorrowAssets` | Utilization never > 100% | INV-LEND-006 |

### Share Accounting (if these break, exchange rate is wrong)

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `sum(balanceOf) == totalSupply` | Supply conservation | INV-POOL-007 |
| `sum(balanceOfAssets) == totalAssets` | Asset conservation per user | INV-POOL-002 |
| `totalAssets >= totalSupply` | Exchange rate >= 1 | INV-POOL-003 |
| `convertToAssets(totalSupply) == totalAssets` | ERC4626 consistency | INV-POOL-004 |
| `sum(supplyShares) == totalSupplyShares` | Supply share conservation | INV-LEND-004 |
| `sum(borrowShares) == totalBorrowShares` | Borrow share conservation | INV-LEND-005 |

### Loan Manager Aggregates (if these break, AUM is wrong)

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `principalOut == sum(loan.principal)` | Principal tracking | INV-LOAN-007, INV-LOAN-029 |
| `issuanceRate == sum(payment rates)` | Interest accrual rate | INV-LOAN-008, INV-LOAN-030 |
| `AUM == sum(principal) + sum(interest)` | Full AUM decomposition | INV-LOAN-011, INV-LOAN-027 |
| `accountedInterest + accruedInterest == sum(outstanding interest)` | Interest tracking | INV-LOAN-006 |
| `domainStart <= block.timestamp` | Accrual anchor in the past | INV-LOAN-012, INV-LOAN-033 |

### Liquidation Safety (if these break, healthy users get liquidated or unhealthy escape)

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `Liquidation only if unhealthy` | No wrongful liquidation | INV-LIQ-001 |
| `Only liquidation can make healthy -> unhealthy` | No operation worsens health | INV-LIQ-002 |
| `Exchange rate monotonic (no debt socialization)` | Share price never decreases | INV-LIQ-005 |
| `Unhealthy users cannot borrow` | No deepening insolvency | INV-LIQ-007 |
| `Users can always repay in full` | No trapped debt | INV-LIQ-009 |

### Interest Rate Safety

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `Interest accumulator monotonically increases` | Debt only grows via interest | INV-INT-005 |
| `Interest rate <= MAX_ALLOWED` | No unbounded rates | INV-INT-004 |
| `lastAccrualTimestamp <= block.timestamp` | No future timestamps | INV-INT-002 |

### Withdrawal Queue Integrity (Maple-specific, applicable to any queued withdrawal)

| Invariant | What it protects | Source ID |
|-----------|-----------------|-----------|
| `WM.balance == sum(lockedShares)` | Share conservation in WM | INV-WQ-001 |
| `totalCycleShares == sum(lockedShares for cycle)` | Per-cycle consistency | INV-WQ-002 |
| `Redeemable shares <= lockedShares[user]` | No over-redemption | INV-WQ-007 |
| `Redeemable assets <= pool cash` | Can't withdraw more than pool has | INV-WQ-009 |
| `requestId unique per lender` | No request duplication | INV-WQ-022 |

---

## 3. Checklist Rapido

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
- [ ] Open-term: is `payment.startDate` == `dateFunded` or `datePaid`? (INV-LOAN-034)

### Share/Exchange Rate (10 min)
- [ ] `sum(balanceOf) == totalSupply`? (INV-POOL-007)
- [ ] `totalAssets >= totalSupply` (exchange rate >= 1)? (INV-POOL-003)
- [ ] First depositor inflation protection? (dead shares, virtual offset)
- [ ] `convertToShares` and `convertToAssets` are inverse? (INV-POOL-004, INV-POOL-005)
- [ ] Rounding direction: deposits round DOWN (fewer shares), withdrawals round UP (more shares burned)

### Collateral & Borrowing (10 min)
- [ ] `borrower has debt => collateral > 0`? (INV-LEND-008, INV-LEND-012)
- [ ] `totalBorrows == sum(all user debts)`? (INV-LEND-002)
- [ ] Supply/borrow caps enforced? (INV-LEND-009, INV-LEND-010)
- [ ] Can controller be disabled with outstanding debt? (INV-LEND-011)
- [ ] Fee-on-transfer / rebasing token handling?

### Liquidation (10 min)
- [ ] Liquidation ONLY if unhealthy? (INV-LIQ-001)
- [ ] No operation (except liquidation) makes healthy -> unhealthy? (INV-LIQ-002)
- [ ] Unhealthy users cannot borrow more? (INV-LIQ-007)
- [ ] Users can always repay in full? (INV-LIQ-009)
- [ ] Self-liquidation profitability?
- [ ] Bad debt socialization path -- what happens when collateral < debt?

### Loan Manager (if applicable) (10 min)
- [ ] `principalOut == sum(loan.principal)`? (INV-LOAN-007)
- [ ] `issuanceRate == sum(payment issuance rates)`? (INV-LOAN-008)
- [ ] Sorted payment list is actually sorted? (INV-LOAN-005)
- [ ] Refinance interest accounts for fee deduction? (INV-LOAN-015)
- [ ] Payment due date cache matches loan state? (INV-LOAN-016)

### Withdrawal Queue (if applicable) (5 min)
- [ ] WM token balance == sum locked shares? (INV-WQ-001)
- [ ] Redeemable bounded by locked shares AND pool cash? (INV-WQ-007, INV-WQ-009)
- [ ] Request IDs unique and ordered? (INV-WQ-018, INV-WQ-022)
- [ ] lockedLiquidity == 0 outside withdrawal window? (INV-WQ-013)

### Cross-Contract Consistency (5 min)
- [ ] `pool.totalAssets() == poolManager.totalAssets()`? (INV-POOL-009)
- [ ] `pool.unrealizedLosses() == poolManager.unrealizedLosses()`? (INV-POOL-010)
- [ ] `convertToExitShares` consistent across contracts? (INV-POOL-011)

---

## Solodit Verified Findings

### Maps to lending-002 (interest accrual desync)

- **[HIGH] Fail to accrue interests on multiple token positions (Solodit #140)** -- borrow/repay/lend/withdrawLend call poke(token) for the concerned token but fail to accrue interest on OTHER token debts of the same position; multi-collateral positions accumulate stale interest on non-touched tokens.
- **[HIGH] LendingPair.liquidateAccount does not update cumulativeInterestRate (Solodit lending-1)** -- liquidateAccount calls _accrueAccountInterest but not the global rate update; liquidation executes at stale exchange rate, under-counting debt owed.
- **[HIGH] Malicious borrower cycle exploits to inflate interest rates (Solodit lending-2)** -- Attacker repeatedly borrows and repays to artificially spike the utilization-based interest rate, forcing all borrowers to pay inflated rates. New twist: interest rate manipulation via utilization cycling.
- **[HIGH] Interest accrual failure due to incorrect scaling in RToken (Solodit lending-6)** -- Scaled balance mechanism for interest-bearing tokens implemented incorrectly; liquidity index tracks accrual correctly but token scaling logic inverts it, zeroing all interest distribution.
- **[HIGH] AccountableOpenTerm loan interest cannot be repaid once principal hits zero (Solodit lending-7)** -- Interest accrues via _scaleFactor but repay() first services withdrawals then reduces principal; when principal=0, no repayment path exists for accrued interest, creating permanent bad debt.
- **[HIGH] decreaseDebtShare bypasses interest accrual (Solodit lending-8)** -- Treated as "safe" because it only reduces debt, so accrueInterest() is skipped; attacker repays at pre-accrual debt amount, avoiding accumulated interest.
- **[MEDIUM] Interest accrual while VaultController is paused (Solodit lending-11)** -- Users cannot repay during pause but interest continues accruing; forced into liquidation through no fault of their own. New pattern: pause/unpause + accrual interaction.
- **[MEDIUM] Borrower can reduce lender accruals via small repeated borrows (Solodit lending-12)** -- Borrowing small amounts multiple times resets accrual checkpoints; each micro-borrow truncates accumulated interest due to integer division, reducing total interest paid to lenders.
- **[MEDIUM] NFTPositionManager repay unavailable without preceding accrual operation (Solodit lending-15)** -- _repay() check cannot be satisfied unless pool state was already updated in the same block; standalone repay calls always revert, requiring users to batch with a state-updating operation.
- **[MEDIUM] Users can avoid borrowing interest after fyToken matures (Solodit lending-10)** -- User gives vault to Witch (liquidation contract) and buys back collateral with underlying tokens, bypassing the interest-bearing repayment path entirely.

### Maps to lending-003 (liquidation threshold manipulation)

- **[HIGH] Liquidation prevented due to strict liquidation bonus implementation (Solodit lending-28)** -- When collateral value is between debt and debt+bonus, liquidation reverts because it tries to seize more collateral than exists; unhealthy positions become unliquidatable, accumulating bad debt.
- **[HIGH] Missing gap between borrow LTV and liquidation threshold (Solodit lending-49)** -- Borrowing allowed at the exact liquidation edge; any price movement triggers liquidation, enabling attacker to profit by monitoring oracle updates and self-liquidating with the bonus.
- **[HIGH] Discrepancy between health calculation and slashable collateral (Solodit lending-32)** -- Health factor uses one formula, slashable collateral uses another; positions can be "healthy" by health check but have insufficient slashable collateral to cover liquidation, creating silent bad debt.
- **[MEDIUM] Liquidation does not prioritize lowest LTV tokens (Solodit lending-29)** -- Partial liquidations repay arbitrary debt tokens instead of lowest-LTV ones; inefficient liquidations leave positions with worse health than optimal liquidation would achieve.
- **[MEDIUM] TARGET_HEALTH calculation ignores per-market adjust factors (Solodit lending-30)** -- Debt-to-pay calculation uses average adjustFactor across all markets; for multi-market positions, this produces wrong liquidation amounts that don't restore health.
- **[MEDIUM] Liquidation seizeassets rounding issue (Solodit lending-34)** -- Borrower ends up with less healthy position after liquidation due to repaidAssets rounding down in shares conversion; violates the core invariant that liquidation must improve health.
- **[MEDIUM] Liquidation should make borrower healthier (Solodit lending-21/33)** -- Liquidation bonus calculation can result in health factor decreasing post-liquidation when collateral value is close to debt; repeated partial liquidations progressively worsen position.

### Maps to lending-004 (bad debt socialization)

- **[HIGH] Reserves stolen by settling artificially created bad debt (Solodit lending-50)** -- Attacker inflates LUP (Lowest Utilized Price), pulls collateral from loan, then settles the artificial bad debt against protocol reserves; repeated to drain all reserves.
- **[MEDIUM] Profitable liquidations via earnings accumulator not triggered (Solodit lending-27)** -- Earnings accumulator not converted to floatingAssets before liquidation; liquidatee's shares reflect pre-accumulator value, enabling liquidator to capture the unrealized earnings as profit.

### Maps to lending-008 (self-liquidation profit)

- **[HIGH] Operator continues utilizing after being liquidated (Solodit lending-39)** -- utilize() and utilizeWhileAddingKeys() lack status checks; liquidated operators can keep borrowing, deepening insolvency.
- **[MEDIUM] Self-liquidation reduces losses when health factor is low (Solodit lending-38)** -- When collateral insufficient for liquidation reward, tokens withdrawn from LiquidationBuffer then Vault; self-liquidating transfers losses from the user to the protocol's buffer/vault.
- **[MEDIUM] Attacker extends liquidation by resetting liquidationStart to 0 (Solodit lending-31)** -- Partial liquidation of a few wei manipulates health to >=1e27, resetting liquidation timer; attacker can keep resetting to delay liquidation indefinitely while collateral depreciates.

### Maps to lending-009 (flash loan exploits)

- **[HIGH] Reentrancy in flashAction drains liquidity pools (Solodit lending-40)** -- ERC777 token callback during flash action allows reentrancy; attacker re-enters to manipulate accounting before the flash action's state updates complete.
- **[HIGH] flashActionByCreditor drains assets without withdrawing (Solodit lending-41)** -- Making an account own itself allows arbitrary calls through flash action; ERC721 assets transferred directly out, bypassing all withdrawal checks.
- **[HIGH] Flash loan protection bypassed via self-liquidation (Solodit lending-42)** -- Protocol's flash-loan manipulation protection (block-based cooldown) bypassed by using self-liquidation instead of direct flash loan; the liquidation path lacks the same cooldown check.
- **[HIGH] Unsolicited flash loan callback invocation (Solodit lending-43)** -- Attacker calls crToken.flashLoan directly with FlasherFTM as receiver; onFlashLoan validation checks pass because attacker controls the params, forcing the contract to execute attacker-defined actions.
- **[HIGH] Unprotected flash loan callback manipulates other users' positions (Solodit lending-44)** -- receiveFlashLoan has no caller validation; attacker invokes callback directly with crafted userData to claim/deposit/rescue positions belonging to other users.
- **[HIGH] DebtManager.requestLiquidity exploited to reduce vault returns (Solodit lending-46)** -- No limit on liquidity requested from other silos; attacker drains liquidity from target silos via excessive cross-silo borrowing, reducing returns for those silo depositors.

### Maps to lending-010 (first depositor share inflation)

- **[MEDIUM] reinvestReward generates dust totalPoolClaim causing vault abnormal (Solodit oracle-88 cross-ref)** -- Minimum borrow size/leverage ratio protects deposits but reinvestReward() bypasses these limits; a dust-sized reward reinvestment creates the same first-depositor vulnerability through a different entry path.

### New patterns not in existing bugs

- **[HIGH] Malicious borrowers never repay loans with high interest (Solodit lending-4)** -- LTV liquidation check ignores accrued interest; borrower has no incentive to repay once interest exceeds collateral value because they can't be liquidated (interest not counted). New pattern: interest exclusion from health factor creates rational default incentive.
- **[HIGH] Liquidity token value manipulation via LP claims (Solodit lending-47)** -- LP token valuation sums claims on cash (cTokens) and fCash; attacker manipulates the relative composition by trading between these, inflating LP value used as collateral. New pattern: composite collateral token component manipulation.
- **[HIGH] Attacker manipulates low TVL Uniswap V3 pool to borrow at inflated collateral value (Solodit lending-52)** -- UniV3 position used as collateral valued via oracle wrapper; attacker manipulates thin pool to inflate position value, borrows against it, then lets position revert to real value. New pattern: NFT position collateral manipulation.
- **[HIGH] Reentrancy via ERC1155 rent hijack (Solodit lending-53)** -- Gnosis Safe fallback handler used with rented ERC1155; reentrancy during rental flow allows hijacking the token. New pattern: callback-based asset hijack in lending/rental protocols.
- **[MEDIUM] Users become immediately liquidatable after legitimate action (Solodit lending-20)** -- Health factor validated BEFORE risk premium updates are applied; user passes health check, then risk premium makes them instantly liquidatable. New pattern: pre-update validation with post-update state change.
- **[MEDIUM] Liquidation cannot be closed even with healthy position (Solodit lending-36)** -- closeLiquidation requires debt below dust threshold instead of checking health factor; user with healthy position but remaining dust debt stays in permanent liquidation state. New pattern: liquidation exit criteria mismatch.
- **[MEDIUM] Unclaimable reserve assets accrue in pool (Solodit lending-24)** -- Borrow interest compounds but supply interest is linear (fixed); the difference accumulates as unclaimable reserves, slowly reducing capital efficiency. New pattern: compound vs simple interest mismatch.
- **[MEDIUM] Liquidity pool interest accrual manipulation via frequent borrows (Solodit lending-9)** -- Each borrow call resets totalBorrowsSnapshotTimestamp; frequent small borrows reduce effective accrual window, lowering total interest collected. New pattern: timestamp reset via high-frequency operations.
