# Invariant Testing — Real-World Audit Reports & Bugs Found

> Compiled from public audit reports, fuzzing campaigns, and case studies.
> Last updated: 2026-03-18

---

## Table of Contents
1. [Cap Protocol (100 properties)](#1-cap-protocol)
2. [Liquity Bold V2 (20+ properties)](#2-liquity-bold-v2)
3. [Centrifuge Protocol V3 (10+ properties)](#3-centrifuge-protocol-v3)
4. [Apollon (7+ properties)](#4-apollon)
5. [eBTC / Badger DAO (40+ properties)](#5-ebtc--badger-dao)
6. [eBTC BSM (6 properties)](#6-ebtc-bsm)
7. [Spine Finance (3+ properties)](#7-spine-finance)
8. [Quill Finance (6 properties)](#8-quill-finance)
9. [Orki (4+ properties)](#9-orki)
10. [Devdacian Fuzzing Comparison (8+ challenges)](#10-devdacian-fuzzing-comparison)
11. [Trail of Bits crytic/properties (168 properties)](#11-trail-of-bits-cryticproperties)
12. [Invariant Categories & Methodology](#12-invariant-categories--methodology)
13. [Tools Comparison](#13-tools-comparison)
14. [Key Patterns from Real Campaigns](#14-key-patterns-from-real-campaigns)

---

## 1. Cap Protocol

**Source**: https://github.com/Recon-Fuzz/cap-invariants/blob/main/report.MD
**Type**: Lending / Stablecoin (cUSD backed 1:1 by stable assets)
**Auditor**: Recon (Nican0r, 0xKnot)
**Duration**: 4 weeks
**Tools**: Echidna (primary), Foundry, Halmos, Medusa
**Properties**: 100

### Invariant Properties (ALL 100)

**Solvency & Accounting (20)**
| # | Property | Description |
|---|----------|-------------|
| 1 | property_sum_of_deposits | Sum of deposits <= total supply |
| 2 | property_sum_of_withdrawals | Sum of deposits + withdrawals <= total supply |
| 3 | property_vault_solvency_assets | Total supplies <= vault balance + borrows + fractional reserve |
| 4 | property_vault_solvency_borrows | Total supplies >= total borrows |
| 12 | property_total_system_collateralization | System overcollateralized post-liquidations |
| 15 | property_cap_token_backed_1_to_1 | cUSD backed 1:1 by stable assets |
| 16 | doomsday_debt_token_solvency | DebtToken balance >= total vault debt at all times |
| 17 | property_total_borrowed_less_than_total_supply | Total borrowed < supply (utilization < 1e27) |
| 19 | property_utilization_ratio_never_greater_than_1e27 | Utilization ratio <= 1e27 |
| 20 | property_maxWithdraw_less_than_loaned_and_reserve | Sum of maxWithdraw <= loaned + reserve |
| 72 | property_fractional_reserve_vault_has_reserve_amount | Reserve sufficiency |
| 84 | property_previewRedeem_greater_than_loaned | previewRedeem(totalSupply) >= loaned |
| 88 | property_no_agent_borrowing_total_debt_should_be_zero | Zero borrowers = zero debt |
| 89 | property_no_agent_borrowing_utilization_rate_should_be_zero | Zero borrowers = zero utilization |
| 93 | property_debt_token_total_supply_greater_than_vault_debt | debtToken.totalSupply >= reserve.debt |

**Monotonicity (3)**
| # | Property | Description |
|---|----------|-------------|
| 5 | property_utilization_index_only_increases | Utilization index only increases over time |
| 18 | property_staked_cap_value_non_decreasing | Staked CAP value non-decreasing |
| 92 | doomsday_compound_vs_linear_accumulation | Interest consistency regardless of realization frequency |

**Health & Liquidation (12)**
| # | Property | Description |
|---|----------|-------------|
| 10 | property_borrowed_asset_value | Loaned assets value < delegations value or liquidatable |
| 11 | property_health_not_changed_with_realizeInterest | Health unchanged when interest realized |
| 13 | property_delegated_value_greater_than_borrowed_value | Delegated > borrowed or liquidatable |
| 14 | property_ltv | LTV always <= 1e27 |
| 73 | property_liquidation_does_not_increase_bonus | Bonus stability during liquidation |
| 74 | property_borrower_cannot_borrow_more_than_ltv | LTV enforcement |
| 75 | property_health_should_not_change_when_realizeRestakerInterest | Restaker interest health neutrality |
| 76 | property_no_operation_makes_user_liquidatable | Operations preserve solvency |
| 94 | property_healthy_account_stays_healthy_after_liquidation | Health preservation for healthy accounts |
| 95 | property_no_bad_debt_creation_on_liquidation | No bad debt during liquidation |

**Borrow (6)**
| # | Property | Description |
|---|----------|-------------|
| 8 | property_agent_cannot_have_less_than_minBorrow | Agent balance >= minimum borrow threshold |
| 45-50 | lender_borrow (6 properties) | Borrow pause checks, health, balances |

**Repay & Dust (5)**
| # | Property | Description |
|---|----------|-------------|
| 9 | property_repaid_debt_equals_zero_debt | All repaid = reserve debt = 0 |
| 77 | property_dust_on_repay | Full repay results in zero balance |
| 78 | property_zero_debt_is_borrowing | Zero balance = not borrowing |
| 80 | property_lender_does_not_accumulate_dust | No dust accumulation |
| 81 | property_debt_zero_after_repay | Reserve debt = 0 when all repaid |

**CapToken Operations (26)**
| # | Property | Description |
|---|----------|-------------|
| 21-28 | capToken_burn (8 props) | Burn amount validation, fees, supply tracking |
| 29 | capToken_divestAll | ERC4626 must always be divestable |
| 30-36 | capToken_mint (7 props) | Mint validation, fees, oracle dependency |
| 37-41 | capToken_redeem (5 props) | Redeem validation and fee tracking |
| 85 | capToken_divestAll | No assets left in vault after divest |

**Liquidation Operations (14)**
| # | Property | Description |
|---|----------|-------------|
| 42-43 | doomsday_liquidate (2 props) | Liquidation success and debt generation |
| 44 | doomsday_repay | Repay succeeds for indebted agents |
| 51-52 | lender_initiateLiquidation (2 props) | Health factor validation |
| 53-60 | lender_liquidate (8 props) | Liquidation profitability, health, collateral |
| 96-97 | lender_cancelLiquidation (2 props) | Cancellation health-based validation |

**Interest Realization (10)**
| # | Property | Description |
|---|----------|-------------|
| 6 | property_utilization_ratio | Utilization ratio increases after borrow/interest |
| 61-66 | lender_realizeInterest (6 props) | Interest realization and health invariants |
| 67-70 | lender_realizeRestakerInterest (4 props) | Restaker interest accumulation |

**Never-Revert (5)**
| # | Property | Description |
|---|----------|-------------|
| 86 | property_available_balance_never_reverts | Available balance call reliability |
| 87 | property_maxBorrow_never_reverts | maxBorrowable call reliability |
| 98 | property_maxLiquidatable_never_reverts | Arithmetic reliability for liquidation queries |
| 99 | property_bonus_never_reverts | Bonus calculation reliability |
| 100 | property_staked_cap_total_assets_never_reverts | Staked CAP assets reliability |

**Miscellaneous (9)**
| # | Property | Description |
|---|----------|-------------|
| 7 | property_vault_balance_does_not_change_redeemAmountsOut | Vault invest/divest shouldn't change redeem amounts |
| 71 | lender_repay | Repay arithmetic reliability |
| 79 | property_agent_always_has_more_than_min_borrow | Minimum borrow enforcement |
| 82 | doomsday_repay_all | Interest transfer consistency |
| 83 | doomsday_manipulate_utilization_rate | Same-block borrow/repay rate stability |
| 90-91 | doomsday_maxBorrow (2 props) | Max borrow limits and index behavior |

### Bugs Found

**Medium (2)**
- **M-01**: Agent health changes after `realizeRestakerInterest` when rate reduced pre-realization
- **M-02**: Vault redeem always reverts due to array initialization bug

**Low (4)**
- **L-01**: Liquidation can worsen health factor due to price changes
- **L-02**: Full repay doesn't set isBorrowing flag and emit event
- **L-03**: Permanent DOS of CapToken when using tokens with 18 decimals
- **L-04**: debtToken totalSupply can be less than vault debt

**QA (4)**: Incorrect debtToken usage, missing custom reverts, missing access patterns, missing grantAccess

---

## 2. Liquity Bold V2

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/bold-report.md
**Type**: CDP / Stablecoin (BOLD)
**Auditor**: Recon (Alex The Entreprenerd)
**Tools**: Foundry (PoC development), property-based invariant testing
**Properties**: 20+ explicitly named

### Invariant Properties

**Sorting**
- Trove always added to end of batch in sorted troves
- Troves sorted by interest rate

**Trove**
- getLatestTroveData is exactly post-accrual value
- Min Debt and Min Coll enforced at all times
- Delta debt = debtIncrease - debtDecrease (excluding fees)

**Collateral Surplus**
- Surplus balance can increase only after liquidation
- Owner with surplus can always claim (never reverts)
- Total Coll > getCollBalance
- SUM(getCollateral) == getCollBalance (ignoring donations)

**Batch**
- Batch share PPFS always increases (unless total debt reset to 0)
- When batch has no Troves, debt is 0
- Adding/removing Trove from Batch never decreases Trove debt
- Batch Coll == Sum(Trove_Coll - Redist Coll)
- Post accrual, Batch Coll == Sum(Trove_Coll)
- Closed Trove has zero batch shares

**Redemption**
- Redemption cannot turn trove with >= MIN_DEBT into unredeemable trove
- Redemptions ALWAYS raise CR (unless CR < premium or underwater)

**Accounting**
- NewAggWeightedDebtSum == aggRecordedDebt if all Troves synchronized this block
- For all operations: weightedRecordedDebt == sum of (new debt * rate)

**Pool Safety**
- sendCollToActivePool never underflows
- decreaseBoldDebt never underflows

**Stability Pool**
- Once getCompoundedBoldDeposit == 0, no more yield gain increases

### Bugs Found

**HIGH (2)**
- **H-01**: Batch Shares Math Rebase — infinite free borrowing through ~2,355 rate-setting calls exploiting truncation. Cost: zero. Result: system insolvency.
- **H-02**: Insufficient Flashloan Protection in Zappers — can operate on Troves you don't own via flashloans.

**MEDIUM (6)**
- **M-01**: Oracle fallback logic flaws (redemption fee vs oracle drift, stale pricing during shutdown, stETH deviation up to 1%, RETH minimum price arbitrage)
- **M-02**: Zapper leverage exchange leftovers (missing sweep, arbitrary recipient input)
- **M-03**: Batch management rounding error (debt forgiveness charged to batch not trove)
- **M-04**: Branch borrowing disable attack (whale can disable borrowing via deposit/withdrawal manipulation)
- **M-05**: Oracle deviation threshold arbitrage
- **M-06**: Zapper and swap dust accumulation (permanently lost)

**QA (24)**: Oracle decimal assertions, rounding inflation, base rate decay, stability pool compounding exploitation, unredeemable flag rounding, weightedRecordedDebt ratio errors, liquidator redistribution preference, etc.

---

## 3. Centrifuge Protocol V3

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/Centrifuge_Protocol_V3.MD
**Type**: Real-World Asset (RWA) tokenization / cross-chain vaults
**Auditor**: Recon (Alex The Entreprenerd)
**Duration**: 3 weeks
**Tools**: Manual review, PoC construction, accounting flow analysis
**Properties**: 10+ categories

### Invariant Properties

**Accounting**
- Total debits == total credits across all accounts
- Account balances consistent with transaction history
- No spontaneous value creation/destruction

**Holdings**
- Holdings values synchronized with underlying assets
- Share valuations maintain internal consistency
- NAV calculations accurate across state changes

**Hub Soundness**
- Hub -> Accounting soundness (double-entry integrity)
- Hub -> Accounting type properties (account categorizations remain correct)

**Vault Solvency**
- SOLVENCY: liabilities always <= actual assets
- SOLVENCY: property can only increase (losses attributed to users, not system)
- DOOMSDAY: Price Per Share stability across operations
- DOOMSDAY: After USER OP - PPFS NEVER CHANGES
- Won't revert due to roundUp

**ShareClassManager**
- State transitions remain valid
- Epoch processing maintains consistency

### Bugs Found

**HIGH (1)**
- **H-01**: int128 to uint128 casting overflow — negative values wrap to max uint128 (e.g., -123 becomes 340282366920938463463374607431768211333), breaking accounting in `updateHolding`

**MEDIUM (3)**
- **M-01**: `_withdraw` triggers `sendUpdateHoldingAmount` at wrong time (should be during `revokeShares`)
- **M-02**: Redeem request token transfer evasion (transfer shares to alt accounts)
- **M-03**: Account value overflow in extreme conditions

**QA (29)**: Including 27 rounding-related issues, oracle drift arbitrage, ERC4626 rounding non-compliance, low gas attacks on try/catch, race conditions in claimDepositUntilEpoch

---

## 4. Apollon

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/Apollon_Report.md
**Type**: CDP / Multi-collateral stablecoin (Liquity fork)
**Auditor**: Alex The Entreprenerd
**Duration**: 3 weeks
**Tools**: Crytica Tester framework, invariant assertions

### Invariant Properties

1. Troves should never break `_debtTokenUsedAsCollRatio > MAX_DEBTS_AS_COLLATERAL`
2. No Trove with 0 net debt in Sorted Trove list
3. No operation can trigger recovery mode when combined with oracle update
4. No Trove opened and liquidated in same block
5. Bad debt redistributions cannot be skipped
6. Post-accrual getTroveColl == pre-accrual getTroveWithdrawableColls
7. Liquidations should raise system TCR (unless liquidating bad-debt Troves)

### Bugs Found

**HIGH (7)**
- **H-01**: `updateSystemSnapshots_excludeCollRemainder` lacks access control — unauthorized stake manipulation
- **H-02**: `claimUnassignedAssets` increases debt without finalization checks — self-liquidation bypass
- **H-03**: Inconsistent IMCR logic in Recovery Mode — risky collaterals get higher CR allowance
- **H-04**: Missing minimum borrow + fee allows spam Trove creation — attacker triggers Recovery Mode at will
- **H-05**: StakingOperations token transfer updates supply before accruing rewards — users lose rewards
- **H-06**: `StakingOperations.claim` doesn't update reward debt — enables repeated reward claims
- **H-07**: Pull-based oracle enables risk-free Recovery Mode arbitrage — liquidate victims for profit

**MEDIUM (13)**: Redemption during Recovery Mode, exchange rate validation, stale prices, bad debt redistribution, decay coefficient rounding, borrowing rate calculation, interest rate MEV, debt alteration with stale prices, Pyth oracle bypass, non-deterministic swap fees, swaps without price updates, profitable self-liquidations, parameter change risks

**QA (31)**: Loop breaks, OOG gas, reward dripping timing, hardcoded domain separators, compound interest exploitation, fee accumulation exceeding 100%, etc.

---

## 5. eBTC / Badger DAO

**Source**: https://allthingsfuzzy.substack.com/p/learnings-from-6-weeks-of-fuzzing + https://getrecon.substack.com/p/ebtc-retrospective
**Type**: CDP (Bitcoin-pegged stablecoin backed by stETH)
**Auditor**: Recon (Antonio Viggiano / nican0r)
**Duration**: 6 weeks
**Tools**: Echidna (primary, recommended), Foundry, Medusa
**Properties**: 40+

### Known Invariant Properties

- **invariant_PYS_04**: Protocol's claimable fees should increase by PYS % on expected increase of system collateral shares value following stETH rebasing
- **TCR must increase after liquidations** — mathematically proven INVALID during redistribution scenarios where bad debt remains

### Key Techniques

**Oracle Manipulation via Storage Slots**
- Directly manipulated oracle storage using HEVM cheatcodes
- Constrained price changes within realistic bounds relative to previous values
- Simulated stETH rebasing events realistically

**Inductive Proof Approach**
- Instead of testing yield over arbitrary time, proved correctness for individual rebasing events
- Used mathematical induction to establish system correctness across multiple events

**EchidnaToFoundry Converter**
- Created `EchidnaToFoundry.t.sol` to convert Echidna breaking sequences into reproducible Foundry unit tests
- Essential for debugging broken invariants

**Coverage-Driven Approach**
- Required 100% line coverage before invariants could be effectively broken
- Used coverage analysis to identify untested code paths

**Mock Differential Fuzzing**
- Compared mock contracts vs actual implementations
- Found function signature mismatches (stETH `submit()` method difference between mock and mainnet)

### Findings
- "Previously undisclosed bugs" were found and fixed by the team
- Specific bugs not publicly disclosed
- Team subsequently implemented continuous fuzzing integration to monitor invariants

---

## 6. eBTC BSM

**Source**: https://github.com/ebtc-protocol/ebtc-bsm/tree/main/test/recon-core
**Type**: eBTC Buy/Sell Module
**Tools**: Echidna, Foundry (Chimera framework)

### Invariant Properties (from Properties.sol)

```solidity
// 1. Total balance >= total assets deposited
property_accounting_is_sound()
  assert: escrow.totalBalance() >= escrow.totalAssetsDeposited()

// 2. Total balance >= fee profit
property_accounting_of_profit_is_sound()
  assert: escrow.totalBalance() >= escrow.feeProfit()

// 3. Minted tokens match deposited assets (precision-adjusted)
property_total_minted_eq_total_asset_deposits()
  assert: bsmTester.totalMinted() == escrow.totalAssetsDeposited() * 1e18 / (10 ** decimals)

// 4. Fee profit only increases (monotonic)
property_fees_profit_increases()
  assert: _after.feesProfit >= _before.feesProfit
  // Excludes: CLAIM, MIGRATE operations

// 5. Assets are not lost (gross)
property_assets_are_not_lost()
  assert: _after.totalBalance >= _before.totalBalance
  // Excludes: MIGRATE, CLAIM, BUY_ASSET_WITH_EBTC

// 6. Assets are not lost (net)
property_assets_are_not_lost_net()
  assert: _after.netTotalBalance >= _before.netTotalBalance
  // Excludes: CLAIM, BUY_ASSET_WITH_EBTC
```

### Architecture Files
- `BeforeAfter.sol` — State snapshots pre/post operations
- `CryticTester.sol` — Echidna test harness
- `CryticToFoundry.sol` — Sequence converter for debugging
- `Properties.sol` — All invariant assertions
- `Setup.sol` — Test environment configuration
- `TargetFunctions.sol` — Handler functions
- `managers/` — Actor management
- `targets/` — Target contract definitions
- `trophies/` — Broken invariant reproductions

---

## 7. Spine Finance

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/Spine_Finance_Review.MD
**Type**: RestakingBondMM (DeFi bond market maker)
**Auditor**: Recon
**Tools**: Foundry-based invariant testing

### Invariant Properties

1. **X/Y Relationship**: X/Y ratio maintenance between bond and quote token reserves
2. **Never 1**: Prevents critical edge cases where values approach zero
3. **Overflow Scenarios/Solvency Math**: Mathematical operations maintain system solvency across extremes

### Bugs Found

**HIGH (3)**
- **H-01**: `onCloseBorrowingPositionEarly` queries collateral from wrong address (msg.sender vs _account)
- **H-02**: 100% - 1 wei swap combined with lossy ERC4626 withdrawal causes permanent DOS (division by zero when y reaches zero)
- **H-03**: Pendle strategy callbacks trigger nonReentrant guard reversion

**MEDIUM (12)**: Insufficient slippage, USDT incompatibility, Pendle strategy slippage, pool creator DOS, incorrect lltv/ltv reset, PRICE_FEED_BUFFER_DELAY wrong units, wrong equity risk calculation, inconsistent fee math, fee impact on invariant causing bond repricing, handleCashOut loss socialization, non-standard approval incompatibility, Venus integration yield leakage

---

## 8. Quill Finance

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/Quill_Finance_Report.md
**Type**: CDP / Stablecoin on Scroll (Liquity V2 fork)
**Auditor**: Recon (Alex The Entreprenerd)
**Tools**: Recon Pro cloud fuzzing, Chainlink oracle data scraping, statistical volatility analysis

### Invariant Properties

1. **Debt Assignment Precision**: "Whenever I open a trove, I get the debt assigned to me, with at most 1e9 in error"
2. **Non-Zero Debt Requirement**: "I can never open a trove and be liable for zero debt"
3. **Batch Rebase Finality**: "Once a Batch is rebased, no new troves can be opened in it"
4. **Shutdown Stability**: System only reverts due to specific error conditions during liquidation
5. **Stake Math Protection**: Prevents overflow conditions in staking calculations
6. **Active Pool Balance**: `_activePool.getCollBalance() - _collRemainder` maintains consistency

### Bugs Found

**MEDIUM (6)**
- **M-01**: Liquidations blocked during sequencer grace period — bad debt accumulation
- **M-02**: Missing accrual before `stabilityPoolYieldSplit` changes
- **M-03**: `CCR == SCR` triggers unintended shutdown
- **M-04**: `QuillSimplePriceFeed` lacks `fetchRedemptionPrice` — oracle drift arbitrage
- **M-05**: Price x Rate Feed overborrowing risk
- **M-06**: Bold footguns inherited without mitigation

**Economic (3)**: stETH MCR recommendation (120 -> 110), borrow caps mandatory ("Mango'd" scenario), CL price feed volatility analysis (ETH/USD: 23% daily extremes)

---

## 9. Orki

**Source**: https://github.com/Recon-Fuzz/audits/blob/main/Orki_audit.MD
**Type**: CDP / Stablecoin (Liquity V2 fork, differential review)
**Auditor**: Recon
**Tools**: Foundry, Echidna, Medusa, Halmos, Kontrol (via Recon Pro)

### Invariant Properties

1. **Price Conversion Integrity**: `priceToSqrtPriceX96` must correctly convert prices below uint64.max
2. **Gas Safety**: External oracle calls must not trigger shutdowns due to insufficient gas
3. **Collateral Safety**: LST collaterals must maintain proper liquidation ratios
4. **Oracle Consistency**: Price feeds should not depeg beyond acceptable thresholds

### Bugs Found

**MEDIUM (4)**
- **M-01**: `priceToSqrtPriceX96` math overflow for prices exceeding uint64
- **M-02**: Extra gas check change enables system shutdown via low-gas manipulation
- **M-03**: `swapFromBold` uses ExactOutput — vulnerable to sandwich attacks
- **M-04**: Fundamental price feeds carry LST depeg risks

---

## 10. Devdacian Fuzzing Comparison

**Source**: https://github.com/devdacian/solidity-fuzzing-comparison
**Type**: Simplified real audit findings for tool comparison
**Author**: Dacian (Cyfrin auditor)
**Tools Compared**: Foundry, Echidna, Medusa, Halmos, Certora

### Challenge Matrix

| # | Name | Invariant Property | Foundry | Echidna | Medusa | Halmos | Certora |
|---|------|-------------------|---------|---------|--------|--------|---------|
| 1 | Naive Receiver | Prevent unauthorized fund transfers | PASS | PASS | PASS | - | - |
| 2 | Unstoppable | Block protocol disruption | PASS | PASS | PASS | - | - |
| 3 | Proposal | Valid proposal state transitions | PASS | PASS | PASS | - | - |
| 4 | Voting NFT | Voting power constraints (totalPower != 0, totalPower == initMaxPower) | PASS | PASS | PASS | - | - |
| 5 | Token Sale | Token distribution flaws | FAIL | FAIL | PASS | - | - |
| 6 | Rarely False | Stateless assertion validation | FAIL | FAIL | FAIL | PASS | PASS |
| 7 | Byte Battle | Byte operation correctness | PASS | PASS | PASS | - | - |
| 8 | Omni Protocol | 16 invariants on complex protocol | FAIL | Partial | PASS | - | - |

**Key Insight**: Medusa consistently outperforms — "able to break 2 invariants within 5 minutes" on challenge #8 where Foundry fails entirely. Challenges 9-14 are additional from real audit findings.

### Voting NFT Example Properties (Challenge 4)

```solidity
// High-value: total voting power must never reach zero
function property_total_power_gt_zero_power_calc_start() public view returns(bool) {
    return votingNft.getTotalPower() != 0;
}

// Lower-value: total power should equal initial max
function property_total_power_eq_init_max_power_calc_start() public view returns(bool) {
    return votingNft.getTotalPower() == initMaxNftPower;
}
```

### Dacian's 9 Real Audit Examples (from blog post)

From "Find Highs Before External Auditors Using Invariant Fuzz Testing":
- 9 simplified examples from private Cyfrin audits
- 8 of 9 were BLACK BOX invariants (deducible from spec alone)
- Only 1 was WHITE BOX (required internal implementation knowledge)
- Categories: liquidation logic, collateral prioritization, precision loss, state transitions

---

## 11. Trail of Bits crytic/properties

**Source**: https://github.com/crytic/properties
**Total Properties**: 168
**Tools**: Echidna, Medusa

### ERC20 Properties (25)
- 17 base (supply constancy, balance <= supply, zero address, self-transfer, transfer accounting, allowance)
- 3 burnable (burn balance/supply, burnFrom allowance)
- 1 mintable (mint balance/supply)
- 2 pausable (transfer fails when paused)
- 2 allowance (increase/decrease)

### ERC721 Properties (19)
- 11 base (balanceOf(0) reverts, ownerOf invalid reverts, approval reset on transfer, etc.)
- 6 burnable (supply reduction, transfer/approve revert for burned tokens)
- 2 mintable (supply increase, fresh token creation)

### ERC4626 Properties (37)
- 8 must-not-revert (asset, totalAssets, convertToAssets/Shares, maxDeposit/Mint/Redeem/Withdraw)
- 10 rounding direction (previewDeposit/Mint/Redeem/Withdraw rounds in favor of vault)
- 6 sender-independent (maxDeposit/Mint assume infinite assets, previews don't depend on msg.sender)
- 4 functional accounting (deposit/mint/redeem/withdraw update balances correctly)
- 5 approval-based redemption
- 2 security (share price inflation attack, decimals >= asset decimals)

### ABDKMath64x64 Properties (106)
- Addition (9), Subtraction (10), Multiplication (8), Division (8)
- Negation (5), Absolute Value (7), Inverse (10)
- Averages (11), and more across 19 arithmetic operations
- Mathematical properties: commutativity, associativity, distributivity, identity, boundaries, overflow/underflow

### Bug Found
- ABDKMath64x64: `divuu` function assertion triggered for specific input range

---

## 12. Invariant Categories & Methodology

### Six Types of Invariants (AllThingsFuzzy)

1. **Functional-level (Stateless)**: Test functions in isolation. E.g., calling same function twice produces identical results
2. **System-level (Stateful)**: High-level system properties. E.g., `sum(all_user_balances) == total_funds`
3. **Valid States**: System remains in permissible states only
4. **State Transitions**: Changes occur in correct order. E.g., ToDo -> InProgress -> Completed
5. **Variable Transitions**: Monotonic behavior. E.g., totalTransactions only increases
6. **Unit Tests**: Isolated function verification under various scenarios

### Invariant-Driven Development (Trail of Bits)

**Design Phase**: Document 10 essential invariants before coding
**Implementation Phase**: Use fuzzers + formal verification
**Validation Phase**: Test through automated techniques during reviews
**Monitoring Phase**: On-chain fuzzers and monitoring tools (Hexagate, Tenderly)

**Real Bug**: Uniswap V3 (TOB-UNI-005) — broken invariant that "could have allowed a malicious user to drain any Uniswap pool"

### Handler Structure (Recommended Pattern)

```
test/
  recon-core/
    Setup.sol              — Environment configuration
    TargetFunctions.sol    — Handler functions (bounded inputs, pranks)
    Properties.sol         — All invariant assertions
    BeforeAfter.sol        — State snapshots for comparison
    CryticTester.sol       — Echidna/Medusa harness
    CryticToFoundry.sol    — Sequence converter for debugging
    managers/              — Actor/role management
    targets/               — Target contract wrappers
    trophies/              — Broken invariant reproductions
```

### Property Documentation Pattern

Write properties in plain English first (PROPERTIES.md), then translate to Solidity:

```
PROPERTY: The sum of all user deposits minus withdrawals must equal the contract's token balance
CATEGORY: Accounting / Conservation
SEVERITY IF BROKEN: Critical (fund loss)
```

---

## 13. Tools Comparison

| Tool | Type | Strengths | Weaknesses |
|------|------|-----------|------------|
| **Echidna** | Haskell fuzzer | Best coverage reports, most mature, recommended by Trail of Bits | Slower than Medusa on some challenges |
| **Medusa** | Go fuzzer | Fastest at finding bugs, best "out of the box", parallel execution | Insufficient sequence shrinking (as of 2024) |
| **Foundry** | Rust fuzzer | Most popular, great DX, integrated with dev workflow | Lacks coverage reports for invariant tests, weaker on complex sequences |
| **Halmos** | Symbolic execution | Proves absence of bugs (not just finds them), catches "rarely false" props | Slower, limited to bounded verification |
| **Certora** | Formal verification | Mathematical proofs, catches what fuzzers miss | Steep learning curve, expensive, requires CVL spec language |
| **Kontrol** | K framework | Full formal verification | Complex setup |
| **Recon Pro** | Cloud platform | Runs Echidna+Medusa+Foundry+Halmos in parallel, auto-generates boilerplate | Commercial service |

### When to Use What

- **Start with**: Foundry (easiest setup, most developers know it)
- **Escalate to**: Echidna or Medusa (better at finding complex multi-step bugs)
- **For proofs**: Halmos or Certora (proves properties hold for ALL inputs)
- **For production**: Recon Pro (parallel execution, cloud-based)

---

## 14. Key Patterns from Real Campaigns

### Pattern: "Doomsday" Properties
Used by Recon to test extreme/catastrophic scenarios:
- `doomsday_debt_token_solvency` — System-wide solvency under stress
- `doomsday_compound_vs_linear_accumulation` — Interest consistency
- `doomsday_manipulate_utilization_rate` — Same-block gaming
- `DOOMSDAY - Price Per Share Property Test` — PPFS manipulation

### Pattern: Before/After State Comparison
Used in eBTC BSM and Cap:
```solidity
struct SystemState {
    uint256 totalBalance;
    uint256 feesProfit;
    uint256 netTotalBalance;
}
// Capture before, execute action, capture after, compare
```

### Pattern: Exclusion-Aware Properties
Properties that hold EXCEPT during specific operations:
```solidity
// Fees only increase (except during CLAIM and MIGRATE)
if (lastOperation != Operation.CLAIM && lastOperation != Operation.MIGRATE) {
    assert(_after.feesProfit >= _before.feesProfit);
}
```

### Pattern: Oracle Manipulation for Realistic Testing
From eBTC campaign:
- Directly manipulate oracle storage slots via HEVM cheatcodes
- Constrain price changes within realistic bounds
- Simulate rebasing events (stETH) with proper constraints

### Pattern: Mathematical Induction for Yield
From eBTC:
- Prove correctness for ONE rebasing event
- Induction proves correctness for N events
- Reduces fuzzing state space dramatically

### Pattern: Chimera Framework (Cross-Tool Compatibility)
Write invariants once, run on Echidna + Medusa + Foundry:
- `CryticTester.sol` for Echidna/Medusa
- `CryticToFoundry.sol` for Foundry
- Same `Properties.sol` and `TargetFunctions.sol` shared

### Bug Categories Most Often Found by Invariant Testing

Based on all reports surveyed:

1. **Accounting/Rounding Errors** — Most common (Cap M-02, Centrifuge H-01, Bold M-03, Spine H-02)
2. **Solvency Violations** — System becomes insolvent under specific sequences (Bold H-01, Cap L-04)
3. **Access Control Gaps** — Functions callable by unauthorized actors (Apollon H-01)
4. **State Corruption** — Bad state transitions or stale state (Apollon H-05/H-06, eBTC mock signature mismatch)
5. **Oracle Manipulation** — Price feed exploitation combined with protocol operations (Apollon H-07, Quill M-04)
6. **Dust/Precision Loss** — Small amounts accumulate or disappear (Bold M-06, Cap L-01)
7. **DOS via Edge Cases** — Division by zero, overflow, gas exhaustion (Spine H-02, Centrifuge M-03)
8. **Reentrancy/Callback Issues** — Callback patterns breaking guards (Spine H-03)

---

## Summary Statistics

| Protocol | Type | Properties | H | M | L/QA | Tool |
|----------|------|-----------|---|---|------|------|
| Cap | Lending/Stablecoin | 100 | 0 | 2 | 8 | Echidna |
| Liquity Bold | CDP/Stablecoin | 20+ | 2 | 6 | 24 | Foundry |
| Centrifuge V3 | RWA Vaults | 10+ | 1 | 3 | 29 | Manual+PoC |
| Apollon | CDP/Stablecoin | 7 | 7 | 13 | 31 | Crytica |
| eBTC | CDP (BTC-pegged) | 40+ | ? | ? | ? | Echidna |
| eBTC BSM | Buy/Sell Module | 6 | ? | ? | ? | Echidna+Foundry |
| Spine Finance | Bond MM | 3+ | 3 | 12 | 26 | Foundry |
| Quill Finance | CDP/Stablecoin | 6 | 0 | 6 | 10+ | Recon Pro |
| Orki | CDP/Stablecoin | 4+ | 0 | 4 | 11+ | Recon Pro |
| crytic/properties | Standard libs | 168 | 0 | 0 | 1 | Echidna |

**Total properties documented**: ~364+
**Total bugs found across reports**: 12 High, 49 Medium, 140+ Low/QA
