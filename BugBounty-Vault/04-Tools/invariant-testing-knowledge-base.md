# Invariant Testing Knowledge Base — Comprehensive Reference

> Extracted from 8 leading repositories. Every invariant property, handler pattern, ghost variable, and configuration documented.

---

## Table of Contents

1. [Trail of Bits — 145 Properties (crytic/properties)](#1-trail-of-bits--145-properties)
2. [WETH9 Invariant Testing (horsefacts)](#2-weth9-invariant-testing)
3. [Maple Finance — 90+ Invariants (maple-core-v2)](#3-maple-finance--90-invariants)
4. [a16z ERC4626 Property Tests](#4-a16z-erc4626-property-tests)
5. [Cap Protocol — 100 Invariants (Recon-Fuzz)](#5-cap-protocol--100-invariants)
6. [Morpho Blue — Invariant Suite](#6-morpho-blue--invariant-suite)
7. [Liquity Bold — Invariant Suite](#7-liquity-bold--invariant-suite)
8. [Solidity Fuzzing Comparison (devdacian)](#8-solidity-fuzzing-comparison)
9. [Cross-Repo Patterns & Lessons](#9-cross-repo-patterns--lessons)

---

## 1. Trail of Bits — 145 Properties

**Repo:** `crytic/properties` — PROPERTIES.md
**Purpose:** Reusable property tests for standard token implementations.

### ERC20 (22 Properties)

#### Basic (17)
| ID | Function | Property |
|----|----------|----------|
| BASE-001 | `test_ERC20_constantSupply` | Supply constant for non-mintable/burnable |
| BASE-002 | `test_ERC20_userBalanceNotHigherThanSupply` | Individual balance <= totalSupply |
| BASE-003 | `test_ERC20_usersBalancesNotHigherThanSupply` | Sum of balances <= totalSupply |
| BASE-004 | `test_ERC20_zeroAddressBalance` | address(0) has zero balance |
| BASE-005 | `test_ERC20_transferToZeroAddress` | Transfer to address(0) reverts |
| BASE-006 | `test_ERC20_transferFromToZeroAddress` | transferFrom to address(0) reverts |
| BASE-007 | `test_ERC20_selfTransfer` | Self-transfer preserves accounting |
| BASE-008 | `test_ERC20_selfTransferFrom` | Self-transferFrom preserves accounting |
| BASE-009 | `test_ERC20_transferMoreThanBalance` | Transfer > balance reverts |
| BASE-010 | `test_ERC20_transferFromMoreThanBalance` | transferFrom > balance reverts |
| BASE-011 | `test_ERC20_transferZeroAmount` | Zero transfer preserves accounting |
| BASE-012 | `test_ERC20_transferFromZeroAmount` | Zero transferFrom preserves accounting |
| BASE-013 | `test_ERC20_transfer` | Valid transfer updates correctly |
| BASE-014 | `test_ERC20_transferFrom` | Valid transferFrom updates correctly |
| BASE-015 | `test_ERC20_setAllowance` | Approve sets allowance correctly |
| BASE-016 | `test_ERC20_setAllowanceTwice` | Sequential approvals update correctly |
| BASE-017 | `test_ERC20_spendAllowanceAfterTransfer` | Allowance updates after transferFrom |

#### Burnable (3)
| ID | Function | Property |
|----|----------|----------|
| BURNABLE-001 | `test_ERC20_burn` | Balance and supply decrease |
| BURNABLE-002 | `test_ERC20_burnFrom` | Balance and supply decrease |
| BURNABLE-003 | `test_ERC20_burnFromUpdateAllowance` | Allowance decreases after burnFrom |

#### Mintable (1)
| MINTABLE-001 | `test_ERC20_mintTokens` | Balance and supply increase |

#### Pausable (2)
| PAUSABLE-001 | `test_ERC20_pausedTransfer` | Transfers blocked when paused |
| PAUSABLE-002 | `test_ERC20_pausedTransferFrom` | transferFrom blocked when paused |

#### Allowance (2)
| ALLOWANCE-001 | `test_ERC20_setAndIncreaseAllowance` | increaseAllowance works |
| ALLOWANCE-002 | `test_ERC20_setAndDecreaseAllowance` | decreaseAllowance works |

### ERC721 (19 Properties)

#### Basic (11)
| ID | Function | Property |
|----|----------|----------|
| BASE-001 | `test_ERC721_balanceOfZeroAddressMustRevert` | balanceOf(0) reverts |
| BASE-002 | `test_ERC721_ownerOfInvalidTokenMustRevert` | ownerOf nonexistent reverts |
| BASE-003 | `test_ERC721_approvingInvalidTokenMustRevert` | approve invalid reverts |
| BASE-004 | `test_ERC721_transferFromNotApproved` | unauthorized transfer reverts |
| BASE-005 | `test_ERC721_transferFromResetApproval` | transferFrom clears approvals |
| BASE-006 | `test_ERC721_transferFromUpdatesOwner` | ownership changes correctly |
| BASE-007 | `test_ERC721_transferFromZeroAddress` | from zero reverts |
| BASE-008 | `test_ERC721_transferToZeroAddress` | to zero reverts |
| BASE-009 | `test_ERC721_transferFromSelf` | self-transfer works |
| BASE-010 | `test_ERC721_transferFromSelfResetsApproval` | self-transfer clears approvals |
| BASE-011 | `test_ERC721_safeTransferFromRevertsOnNoncontractReceiver` | requires onERC721Received |

#### Burnable (6)
| BURNABLE-001 | `test_ERC721_burnReducesTotalSupply` | Supply decreases |
| BURNABLE-002-006 | Various burn revert checks | Burned tokens cannot be operated on |

#### Mintable (2)
| MINTABLE-001 | `test_ERC721_mintIncreasesSupply` | Supply increases |
| MINTABLE-002 | `test_ERC721_mintCreatesFreshToken` | New token is valid |

### ERC4626 (37 Properties)

#### Must Not Revert (8)
| ERC4626-001 to 008 | `verify_*MustNotRevert` | asset(), totalAssets(), convertToAssets/Shares(), maxDeposit/Mint/Redeem/Withdraw() never revert |

#### Rounding Direction (10)
| ERC4626-013 to 022 | `verify_*RoundingDirection` | All preview and convert functions round in correct direction |

#### Sender Independence (6)
| ERC4626-023 to 028 | `verify_*IgnoresSender` | maxDeposit/Mint and all preview functions are caller-independent |

#### Functional Accounting (4)
| ERC4626-029 to 032 | `verify_*Properties` | deposit/mint/redeem/withdraw update balances correctly |

#### Security (2)
| ERC4626-033 | `verify_sharePriceInflationAttack` | Protection against inflation attack |
| ERC4626-034 | `verify_assetDecimalsLessThanVault` | Decimal comparison |

### ABDKMath64x64 (67 Properties)

Mathematical properties across 9 categories:
- **Addition (9):** Commutativity, associativity, identity, range, overflow
- **Subtraction (10):** Equivalence to addition, anti-commutativity, neutrality, range
- **Multiplication (8):** Commutativity, associativity, distributivity, identity, range
- **Division (8):** Identity, sign, zero numerator, zero denominator reverts, range
- **Negation (5):** Double negation, identity, zero, max/min
- **Absolute Value (7):** Positivity, symmetry, multiplicativeness, subadditivity
- **Inverse (10):** Double inverse, division equivalence, sign preservation
- **Arithmetic Mean (5):** Value in range, self-average, order independence
- **Geometric Mean (5):** Value in range, self-average, order independence

---

## 2. WETH9 Invariant Testing

**Repo:** `horsefacts/weth-invariant-testing`
**Purpose:** Canonical tutorial for Foundry invariant testing patterns.

### Directory Structure
```
test/
├── handlers/
│   └── Handler.sol
└── WETH9.invariants.t.sol
```

### Foundry Configuration
```toml
[invariant]
runs = 2000
depth = 25
fail_on_revert = false
call_override = false
dictionary_weight = 80
include_storage = true
include_push_bytes = true
```

### Invariant Properties (5)

| # | Function | Assertion | Purpose |
|---|----------|-----------|---------|
| 1 | `invariant_conservationOfETH` | `ETH_SUPPLY == handler.balance + weth.totalSupply()` | Total ETH is conserved |
| 2 | `invariant_solvencyDeposits` | `weth.balance == ghost_depositSum + ghost_forcePushSum - ghost_withdrawSum` | Deposit/withdrawal accounting |
| 3 | `invariant_solvencyBalances` | `weth.balance - ghost_forcePushSum == sumOfBalances` | ETH covers all balances |
| 4 | `invariant_depositorBalances` | `weth.balanceOf(account) <= weth.totalSupply()` for all actors | No balance > totalSupply |
| 5 | `invariant_callSummary` | (logging only) | Fuzz campaign statistics |

### Ghost Variables (6)
```solidity
ghost_depositSum      // cumulative deposits
ghost_withdrawSum     // cumulative withdrawals
ghost_forcePushSum    // cumulative force-pushed amounts
ghost_zeroWithdrawals // count of zero-amount withdrawals
ghost_zeroTransfers   // count of zero-amount transfers
ghost_zeroTransferFroms // count of zero-amount transferFroms
```

### Handler Functions (7)
| Function | Bounds | Tracks |
|----------|--------|--------|
| `deposit(uint256 amount)` | 0 to handler.balance | ghost_depositSum |
| `withdraw(uint256 actorSeed, uint256 amount)` | 0 to actor WETH balance | ghost_zeroWithdrawals |
| `approve(uint256 actorSeed, uint256 spenderSeed, uint256 amount)` | unbounded | - |
| `transfer(uint256 actorSeed, uint256 toSeed, uint256 amount)` | 0 to sender balance | ghost_zeroTransfers |
| `transferFrom(uint256 actorSeed, uint256 fromSeed, uint256 toSeed, bool _approve, uint256 amount)` | balance + allowance | ghost_zeroTransferFroms |
| `sendFallback(uint256 amount)` | 0 to handler.balance | ghost_depositSum |
| `forcePush(uint256 amount)` | 0 to handler.balance | ghost_forcePushSum |

### Key Patterns
- **Actor Management:** `AddressSet` library tracks all actors; `createActor` modifier records new actors
- **Reducer Pattern:** `reduceActors(acc, fn)` for accumulating values across all actors
- **ForEach Pattern:** `forEachActor(fn)` for per-actor assertions
- **Call Summary:** Logs function call counts to verify fuzzer coverage
- **Constant:** `ETH_SUPPLY = 120_500_000 ether` — total ETH in system

### Methodology (from README)
1. **Unconstrained first** — let fuzzer hit raw contract to find assumption violations
2. **Add handlers** — constrain to realistic inputs via bounded wrappers
3. **Ghost variables** — track cumulative state not exposed by contract
4. **Actor management** — multiple users with different balances
5. **Call summaries** — verify fuzzer exercises all paths
6. **Mutation testing** — create `.patch` files with artificial bugs to validate tests catch them

---

## 3. Maple Finance — 90+ Invariants

**Repo:** `maple-labs/maple-core-v2`
**Purpose:** Production DeFi lending protocol with the most comprehensive invariant suite in the industry.

### Directory Structure
```
tests/invariants/
├── handlers/
│   ├── CyclicalWithdrawalHandler.sol
│   ├── DepositHandler.sol
│   ├── DistributionHandler.sol
│   ├── FixedTermLoanHandler.sol
│   ├── GlobalsHandler.sol
│   ├── Governor.sol
│   ├── HandlerBase.sol
│   ├── Keeper.sol
│   ├── OpenTermLoanHandler.sol
│   ├── PermissionHandler.sol
│   ├── QueueWithdrawalHandler.sol
│   ├── Skimmer.sol
│   ├── StrategyHandler.sol
│   ├── TransferHandler.sol
│   └── Transferer.sol
├── BaseInvariants.t.sol
├── BasicInvariants.t.sol
├── DefaultsInvariants.t.sol
├── ImpairInvariants.t.sol
├── OpenTermInvariants.t.sol
├── PermissionInvariants.t.sol
├── Regression.t.sol
├── StrategyInvariants.t.sol
└── WithdrawalManagerQueueInvariants.t.sol
```

### Test Scenarios (7 suites)
Each suite tests the SAME invariants but under DIFFERENT action sets:
1. **BasicInvariants** — deposits, withdrawals, fixed-term loans, payments
2. **DefaultsInvariants** — same + loan defaults and liquidations
3. **ImpairInvariants** — same + loan impairments
4. **OpenTermInvariants** — open-term loans (call, fund, impair, refinance)
5. **PermissionInvariants** — permission manager properties
6. **StrategyInvariants** — strategy vault properties
7. **WithdrawalManagerQueueInvariants** — queue-based withdrawal manager

### ALL Invariant Properties (90+)

#### Fixed Term Loan (3)
| ID | Property |
|----|----------|
| FTL-A | Collateral balance >= stored collateral amount |
| FTL-B | Funds asset balance >= drawable funds |
| FTL-C | `collateral >= collateralRequired * (principal - drawableFunds) / principalRequested` |

#### Fixed Term Loan Manager (14)
| ID | Property |
|----|----------|
| FTLM-A | domainStart <= domainEnd |
| FTLM-B | Sorted payments list maintains chronological order |
| FTLM-C | accountedInterest + accruedInterest ~= sum of outstanding interest |
| FTLM-D | principalOut = sum of all loan principals |
| FTLM-E | issuanceRate = sum of payment issuance rates |
| FTLM-F | unrealizedLosses <= AUM |
| FTLM-G | unrealizedLosses == 0 (non-liquidating) |
| FTLM-H | AUM ~= sum(principals) + sum(interest) |
| FTLM-I | domainStart <= block.timestamp |
| FTLM-J | If earliest payment exists, issuanceRate > 0 |
| FTLM-K | If earliest payment exists, domainEnd == payment due date |
| FTLM-L | Refinance interest matches loan's net refinance interest |
| FTLM-M | Payment due date matches loan's next payment due date |
| FTLM-N | startDate <= paymentDueDate - paymentInterval |

#### Pool (11)
| ID | Property |
|----|----------|
| Pool-A | totalAssets > fundsAssetBalance |
| Pool-B | totalAssets ~= sum of user balanceOfAssets (with rounding) |
| Pool-C | totalAssets >= totalSupply |
| Pool-D | convertToAssets(totalSupply) ~= totalAssets |
| Pool-E | convertToShares(totalAssets) ~= totalSupply |
| Pool-F | balanceOfAssets >= balanceOf per user |
| Pool-G | sum(balanceOf) == totalSupply |
| Pool-H | convertToExitShares == convertToShares (when assets > 0) |
| Pool-I | pool.totalAssets == poolManager.totalAssets |
| Pool-J | pool.unrealizedLosses == poolManager.unrealizedLosses |
| Pool-K | pool.convertToExitShares == poolManager.convertToExitShares |

#### Pool Manager (2)
| ID | Property |
|----|----------|
| PM-A | totalAssets ~= cash + sum(loanManager.AUM) |
| PM-B | unrealizedLosses <= totalAssets |

#### Withdrawal Manager — Cyclical (14)
| ID | Property |
|----|----------|
| WM-A | WM LP balance == sum of user locked shares |
| WM-B | totalCycleShares == sum of locked shares per cycle |
| WM-C | windowStart <= block.timestamp |
| WM-D | initialCycleTime <= block.timestamp |
| WM-E | initialCycleId <= currentCycleId |
| WM-F | redeemableShares <= WM LP balance |
| WM-G | redeemableShares <= user locked shares |
| WM-H | redeemableShares <= cycle total shares |
| WM-I | redeemableAssets <= pool funds balance |
| WM-J | redeemableAssets <= requested liquidity |
| WM-K | redeemableAssets <= user liquid asset entitlement |
| WM-L | partialLiquidity flag correctness |
| WM-M | lockedLiquidity <= totalAssets |
| WM-N | lockedLiquidity <= cycle available liquidity |

#### Withdrawal Manager — Queue (9)
| ID | Property |
|----|----------|
| WMQ-A | sum(queued + manual shares) == total shares |
| WMQ-B | WM LP balance >= total shares |
| WMQ-C | Valid request IDs have nonzero shares and correct owner |
| WMQ-D | nextRequestId <= lastRequestId + 1 |
| WMQ-E | nextRequestId != 0 |
| WMQ-F | requestId 0 has zero values |
| WMQ-G | All request IDs <= lastRequestId |
| WMQ-H | All request IDs are unique |
| WMQ-I | All request owners are unique |

#### Open Term Loan (9)
| ID | Property |
|----|----------|
| OTL-A | dateFunded <= datePaid |
| OTL-B | dateFunded <= dateImpaired |
| OTL-C | dateFunded <= dateCalled |
| OTL-D | datePaid <= dateImpaired |
| OTL-E | datePaid <= dateCalled |
| OTL-F | calledPrincipal <= principal |
| OTL-G | calledPrincipal != 0 iff dateCalled != 0 |
| OTL-H | paymentDueDate <= defaultDate |
| OTL-I | Payment breakdown matches theoretical calculation |

#### Open Term Loan Manager (11)
| ID | Property |
|----|----------|
| OTLM-A | AUM ~= sum(principal + netInterest) |
| OTLM-B | AUM ~= 0 when no payments |
| OTLM-C | principalOut = sum of loan principals |
| OTLM-D | issuanceRate = sum of payment issuance rates |
| OTLM-E | unrealizedLosses <= AUM |
| OTLM-F | unrealizedLosses == 0 when no impairments |
| OTLM-G | domainStart <= block.timestamp |
| OTLM-H | paymentStartDate == dateFunded or datePaid |
| OTLM-I | issuanceRate matches theoretical calculation |
| OTLM-J | impairmentDate >= paymentStartDate |
| OTLM-K | (AUM - unrealizedLosses - sumOutstandingValues) ~= 0 |

#### Pool Permission Manager (4)
| ID | Property |
|----|----------|
| PPM-A | permissionLevel in [0, 3] |
| PPM-B | poolBitmap in [0, 2^16 - 1] |
| PPM-C | lenderBitmap in [0, 2^16 - 1] |
| PPM-D | Public permission pools remain permanently public |

#### Strategy (7)
| ID | Property |
|----|----------|
| Strategy-A | AUM == currentTotalAssets - accruedFees |
| Strategy-B | accruedFees <= currentTotalAssets |
| Strategy-C | Active state -> unrealizedLosses == 0 |
| Strategy-D | Impaired state -> AUM == unrealizedLosses |
| Strategy-E | Inactive state -> AUM == unrealizedLosses == 0 |
| Strategy-F | strategyState in [0, 2] |
| Strategy-G | strategyFeeRate <= 1e6 |

### Handler Patterns

#### FixedTermLoanHandler — 9 Actions
| Action | Input Bounds |
|--------|-------------|
| `createLoanAndFund(seed)` | principal bounded by liquidity (max 1e29), rates 0-30%, intervals 5min-730d |
| `makePayment(seed)` | selects random active loan |
| `impairmentMakePayment(seed)` | payment on impaired loan |
| `defaultMakePayment(seed)` | routes by loan status |
| `impairLoan(seed)` | random active loan |
| `triggerDefault(seed)` | after grace period |
| `finishCollateralLiquidation(seed)` | completes liquidation |
| `refinance(seed)` | modified terms |
| `warp(seed)` | 0-10 days forward |

#### DepositHandler — 2 Actions
| Action | Input Bounds |
|--------|-------------|
| `deposit(seed)` | 100 to 1_000_000e6 |
| `mint(seed)` | proportional to pool state |

#### OpenTermLoanHandler — 9 Actions
| Action | Input Bounds |
|--------|-------------|
| `callLoan(seed)` | bounded principal |
| `fundLoan(seed)` | creates new loan |
| `impairLoan(seed)` | active loan |
| `makePayment(seed)` | active loan |
| `refinance(seed)` | modified terms |
| `removeLoanCall(seed)` | removes call status |
| `removeLoanImpairment(seed)` | removes impairment |
| `triggerDefault(seed)` | overdue loan |
| `warp(seed)` | 1-15 days forward |

### Ghost Variables (FixedTermLoanHandler)
```solidity
numBorrowers, numDefaults, numLatePayments, numLoans, numMatures, numPayments
unrealizedLosses
loanDefaulted[address], loanImpaired[address]
fundingTime[address], lateIntervalInterest[address]
paymentTimestamp[address], platformOriginationFee[address]
sum_loan_principal, sum_loanManager_paymentIssuanceRate
earliestPaymentDueDate
activeLoans[]
```

---

## 4. a16z ERC4626 Property Tests

**Repo:** `a16z/erc4626-tests`
**Purpose:** Reusable ERC4626 vault compliance testing.

### Directory Structure
```
ERC4626.prop.sol   — All property functions
ERC4626.test.sol   — Test runner with setup
```

### Configuration Variables
```solidity
_vault_            // ERC4626 vault address
_underlying_       // underlying asset address
_delta_            // absolute tolerance for rounding
_vaultMayBeEmpty   // allow empty vault states
_unlimitedAmount   // test with large amounts
```

### ALL Property Functions (24)

#### Non-Revert Properties (6)
| Function | Property |
|----------|----------|
| `prop_asset(caller)` | asset() never reverts |
| `prop_totalAssets(caller)` | totalAssets() never reverts |
| `prop_maxDeposit(caller, receiver)` | maxDeposit() never reverts |
| `prop_maxMint(caller, receiver)` | maxMint() never reverts |
| `prop_maxWithdraw(caller, owner)` | maxWithdraw() never reverts |
| `prop_maxRedeem(caller, owner)` | maxRedeem() never reverts |

#### Caller Independence (2)
| Function | Property |
|----------|----------|
| `prop_convertToShares(c1, c2, assets)` | Same result regardless of caller |
| `prop_convertToAssets(c1, c2, shares)` | Same result regardless of caller |

#### Preview Accuracy (4)
| Function | Assertion |
|----------|-----------|
| `prop_previewDeposit` | actual shares >= preview shares |
| `prop_previewMint` | actual assets <= preview assets |
| `prop_previewWithdraw` | actual shares <= preview shares |
| `prop_previewRedeem` | actual assets >= preview assets |

#### State Change Correctness (4)
| Function | Checks |
|----------|--------|
| `prop_deposit` | caller loses assets, receiver gains shares |
| `prop_mint` | caller loses assets, receiver gains shares |
| `prop_withdraw` | owner loses shares, receiver gains assets, access control |
| `prop_redeem` | owner loses shares, receiver gains assets, access control |

#### Round-Trip Properties (8)
| Function | Property |
|----------|----------|
| `prop_RT_deposit_redeem` | redeem(deposit(a)) <= a |
| `prop_RT_deposit_withdraw` | withdraw shares >= deposit shares |
| `prop_RT_redeem_deposit` | deposit(redeem(s)) <= s |
| `prop_RT_redeem_mint` | mint assets >= redeem assets |
| `prop_RT_mint_withdraw` | withdraw(mint(s)) shares >= s |
| `prop_RT_mint_redeem` | redeem(mint(s)) assets <= mint assets |
| `prop_RT_withdraw_mint` | mint(withdraw(a)) assets >= a |
| `prop_RT_withdraw_deposit` | deposit shares <= withdraw shares |

**Key Insight:** Round-trip properties ensure users cannot profit from deposit-withdraw cycles. The direction of inequality always prevents extraction.

---

## 5. Cap Protocol — 100 Invariants

**Repo:** `Recon-Fuzz/cap-invariants`
**Engagement:** 4-week invariant testing review by Nican0r and 0xKnot.
**Tools:** Echidna + Foundry + Halmos + Medusa compatible.

### Findings from Invariant Testing
- **2 Medium:** Agent health changes on restaker interest; vault redeem always reverts
- **4 Low:** Liquidations worsen health; full repay fails; DOS with 18 decimals; debtToken supply drift
- **4 QA:** Various observations

### ALL 100 Properties by Category

#### General System (3)
| # | Property | Description |
|---|----------|-------------|
| 1 | `property_sum_of_deposits` | Sum of deposits <= total supply |
| 2 | `property_sum_of_withdrawals` | deposits + withdrawals <= total supply |
| 80 | `property_lender_does_not_accumulate_dust` | No dust accumulation |

#### Vault Solvency (3)
| # | Property | Description |
|---|----------|-------------|
| 3 | `property_vault_solvency_assets` | Total supply never exceeds vault balance + borrows + reserve |
| 4 | `property_vault_solvency_borrows` | Total supply > total borrows |
| 72 | `property_fractional_reserve_vault_has_reserve` | Fractional reserve maintained |

#### Utilization (5)
| # | Property | Description |
|---|----------|-------------|
| 5 | `property_utilization_index_only_increases` | Index monotonically increases |
| 6 | `property_utilization_ratio` | Ratio increases only on borrow/realization |
| 19 | `property_utilization_ratio_never_greater_than_1e27` | Never exceeds max |
| 83 | `doomsday_manipulate_utilization_rate` | Same-block borrow/repay doesn't change rate |
| 89 | `property_no_agent_borrowing_utilization_rate_zero` | Zero agents = zero rate |

#### Debt (6)
| # | Property | Description |
|---|----------|-------------|
| 8 | `property_agent_min_borrow_balance` | Debt never below minimum |
| 9 | `property_repaid_debt_equals_zero` | Full repay = zero debt |
| 16 | `doomsday_debt_token_solvency` | debtToken balance >= total vault debt |
| 77 | `property_dust_on_repay` | Full repay reaches zero |
| 81 | `property_debt_zero_after_repay` | Reserve debt zero after all repay |
| 93 | `property_debt_token_total_supply_gte_vault_debt` | totalSupply >= reserve.debt |

#### Borrowing (8)
| # | Property | Description |
|---|----------|-------------|
| 10 | `property_borrowed_asset_value` | Loan value < delegations or liquidatable |
| 17 | `property_total_borrowed_lt_total_supply` | Utilization < 100% |
| 45 | `lender_borrow` | Cannot borrow paused asset |
| 46 | `lender_borrow` | Borrower healthy after borrow |
| 47 | `lender_borrow` | Balance increases after borrow |
| 48 | `lender_borrow` | Debt increases after borrow |
| 49 | `lender_borrow` | Total borrows increase |
| 50 | `lender_borrow` | No arithmetic error |

#### Interest (10)
| # | Property | Description |
|---|----------|-------------|
| 11 | `property_health_not_changed_with_realizeInterest` | Health constant on realization |
| 61-66 | `lender_realizeInterest` | 6 properties: debt unchanged, vault/borrow increase, health unchanged, sufficient assets, revert conditions |
| 67-70 | `lender_realizeRestakerInterest` | 4 properties: same as above for restaker path |

#### CapToken (16)
| # | Property | Description |
|---|----------|-------------|
| 15 | `property_cap_token_backed_1_to_1` | cUSD backed 1:1 by stables |
| 21-28 | `capToken_burn` | 8 properties: min/max amounts, supply decrease, fees, rounding, value cap |
| 29 | `capToken_divestAll` | ERC4626 always divestable |
| 30-36 | `capToken_mint` | 7 properties: min/max amounts, fees, vault assets, pause check |
| 37-41 | `capToken_redeem` | 5 properties: min/max amounts, supply decrease, fees, balance check |

#### Liquidation (14)
| # | Property | Description |
|---|----------|-------------|
| 12 | `property_total_system_collateralization` | Overcollateralized after all liquidations |
| 42-43 | `doomsday_liquidate` | Always succeeds for liquidatable; healthy = no bad debt |
| 51-52 | `lender_initiateLiquidation` | No liquidation if health > 1e27; always if unhealthy |
| 53-60 | `lender_liquidate` | 8 properties: no arithmetic error, profitable, health threshold, health improves, emergency available, partial cap, delegation/collateral reduction |
| 73 | `property_liquidation_no_bonus_increase` | Bonus never increases |
| 76 | `property_no_operation_makes_user_liquidatable` | No op creates liquidation |
| 94-95 | `property_healthy_stays_healthy` / `property_no_bad_debt_on_liquidation` | Post-liquidation safety |
| 96-97 | `lender_cancelLiquidation` | Cancel succeeds/reverts based on health |

#### LTV & Delegation (3)
| # | Property | Description |
|---|----------|-------------|
| 13 | `property_delegated_value_gt_borrowed` | Delegation exceeds borrows |
| 14 | `property_ltv` | LTV <= 1e27 |
| 74 | `property_borrower_cannot_exceed_ltv` | LTV limit enforced |

#### Repayment (4)
| # | Property | Description |
|---|----------|-------------|
| 44 | `doomsday_repay` | Repay always succeeds for indebted agent |
| 71 | `lender_repay` | No arithmetic error |
| 78 | `property_zero_debt_is_borrowing` | Zero debt = not borrowing |
| 82 | `doomsday_repay_all` | Full repay matches realizeInterest |

#### Staking & Other (5)
| # | Property | Description |
|---|----------|-------------|
| 18 | `property_staked_cap_value_non_decreasing` | Staked value monotonically increases |
| 20 | `property_maxWithdraw_bounded` | maxWithdraw <= loaned + reserve |
| 84 | `property_previewRedeem_gte_loaned` | previewRedeem(totalSupply) >= loaned |
| 85 | `capToken_divestAll` | No assets remain after divest |
| 86-100 | Various never-revert properties | availableBalance, maxBorrow, maxLiquidatable, bonus, stakedCapTotalAssets |

---

## 6. Morpho Blue — Invariant Suite

**Repo:** `morpho-org/morpho-blue`
**Purpose:** Minimal lending protocol with focused invariant testing.

### Directory Structure
```
test/
├── invariant/
│   ├── BaseInvariantTest.sol    — Handler + setup
│   ├── DynamicInvariantTest.sol — 5 market invariants
│   └── StaticInvariantTest.sol  — Health invariant
├── BaseTest.sol
└── InvariantTest.sol
```

### Invariant Properties (6)

| # | Function | Property |
|---|----------|----------|
| 1 | `invariantHealthy` | All users healthy across all markets |
| 2 | `invariantSupplyShares` | sum(userSupplyShares) + feeRecipient == totalSupplyShares |
| 3 | `invariantBorrowShares` | sum(userBorrowShares) == totalBorrowShares |
| 4 | `invariantTotalSupplyGeTotalBorrow` | totalSupplyAssets >= totalBorrowAssets per market |
| 5 | `invariantMorphoBalance` | loanToken.balanceOf(morpho) + totalBorrowed >= totalSupplied |
| 6 | `invariantBadDebt` | if collateral == 0 then borrowShares == 0 |

### Handler Functions (11)
| Function | Bounds |
|----------|--------|
| `setFeeNoRevert` | 0 to MAX_FEE |
| `supplyAssetsOnBehalfNoRevert` | `_boundSupplyAssets()` |
| `supplySharesOnBehalfNoRevert` | `_boundSupplyShares()` |
| `withdrawAssetsOnBehalfNoRevert` | `_boundWithdrawAssets()` |
| `borrowAssetsOnBehalfNoRevert` | `_boundBorrowAssets()` |
| `repayAssetsOnBehalfNoRevert` | `_boundRepayAssets()` |
| `repaySharesOnBehalfNoRevert` | `_boundRepayShares()` |
| `supplyCollateralOnBehalfNoRevert` | `_boundSupplyCollateralAssets()` |
| `withdrawCollateralOnBehalfNoRevert` | `_boundWithdrawCollateralAssets()` |
| `liquidateSeizedAssetsNoRevert` | `_boundLiquidateSeizedAssets()` |
| `liquidateRepaidSharesNoRevert` | `_boundLiquidateRepaidShares()` |

### Configuration
- 5 markets with same loan/collateral but varying LLTVs (`MAX_TEST_LLTV / i` for i in 1..6)
- 8 target senders
- `NoRevert` suffix = `fail_on_revert = false` pattern (handlers catch reverts)
- Utility functions: `_randomSupplier()`, `_randomBorrower()`, `_randomHealthyCollateralSupplier()`, `_randomUnhealthyBorrower()`

### Key Pattern: Bounded Inputs via Helper Functions
Each action has a dedicated `_bound*()` function that constrains fuzzer inputs to valid ranges for that specific action, preventing wasted runs.

---

## 7. Liquity Bold — Invariant Suite

**Repo:** `liquity/bold`
**Purpose:** Liquity v2 (BOLD stablecoin) with comprehensive system invariants.

### Directory Structure
```
contracts/test/
├── Invariants.t.sol               — 9 main invariants
├── SPInvariants.t.sol             — Stability pool solvency
├── AnchoredInvariantsTest.t.sol   — Regression tests from invariant failures
└── AnchoredSPInvariantsTest.t.sol — SP regression tests
```

### Invariant Properties (12)

| # | Function | Property |
|---|----------|----------|
| 1 | `invariant_FundsAreSwept` | All actors have zero BOLD/WETH balances and allowances |
| 2 | `invariant_SystemStateMatchesGhostState` | Trove count, sorted list size, interest accrual, gas pool, collateral surplus, SP balances, per-trove properties, batch fees all match ghost state |
| 3 | `invariant_OnlyActiveTrovesInSortedTroves` | Only active troves in sorted list; zombie troves excluded |
| 4 | `invariant_AllBoldBackedByTroveDebt` | BOLD totalSupply + pending interest == total debt |
| 5 | `invariant_AllCollClaimable` | System collateral == sum of all trove collateral |
| 6 | `invariant_StabilityPool_AllBoldClaimable` | Compounded deposits sum ~= total deposits; yield gains match |
| 7 | `invariant_StabilityPool_AllCollClaimable` | SP collateral == sum of depositor claims + stashed |
| 8 | `invariant_SortedTroves_OrderedByInterestRate` | Troves ordered descending by interest rate |
| 9 | `invariant_SortedTroves_BatchesAreContiguous` | Batches appear as contiguous blocks in sorted list |
| 10 | `invariant_AllFundsClaimable` (SP) | SP collateral balance >= claimable collateral |
| 11 | (SP) | BOLD deposits >= compounded claimable |
| 12 | (SP) | Yield gains >= sum of depositor yield gains |

### Ghost Variables (Liquity Bold Handler)
```solidity
numTroves(i)                      // active trove count per branch
numZombies(i)                     // zombie count per branch
designatedVictimId(i)             // last zombie trove ID
getPendingInterest(i)             // accumulated interest
getInterestAccrual(i)             // weighted debt sum
getBatchManagementFeeAccrual(i)   // fee tracking
getGasPool(i)                     // gas pool balance per branch
collSurplus(i)                    // collateral surplus per branch
spBoldDeposits(i)                 // SP BOLD deposits
spBoldYield(i)                    // SP BOLD yield
spColl(i)                         // SP collateral
getTrove(i, j)                    // per-trove: coll, debt, status, batchManager
getPendingBatchManagementFee(i, account)
getRedemptionRate()
```

---

## 8. Solidity Fuzzing Comparison

**Repo:** `devdacian/solidity-fuzzing-comparison`
**Purpose:** Head-to-head comparison of Foundry, Echidna, Medusa, Halmos, Certora.

### Challenges (14)
```
test/
├── 01-naive-receiver/     — Flash loan invariant
├── 02-unstoppable/        — Multiple invariant breaking
├── 03-proposal/           — Basic invariant violation
├── 04-voting-nft/         — Easier vs harder invariants
├── 05-token-sale/         — Unguided bug discovery (Medusa wins)
├── 06-rarely-false/       — Stateless challenge (Halmos/Certora win)
├── 07-byte-battle/        — Byte manipulation
├── 08-omni-protocol/      — Complex multi-invariant (Medusa wins)
├── 09-vesting/            — Real audit finding
├── 10-vesting-ext/        — Extended vesting
├── 11-op-reg/             — Operator registry
├── 12-liquidate-dos/      — Liquidation DOS
├── 13-stability-pool/     — Stability pool
└── 14-priority/           — Priority queue
```

### Omni Protocol Example (Challenge 08) — 16 Invariants

| # | Invariant | Check |
|---|-----------|-------|
| 1 | `invariant_tranche_borrow_deposit_shares_integrity` | (shares>0, amount=0) impossible |
| 2 | `invariant_subaccount_one_isolated_market` | Max 1 isolated market |
| 3 | `invariant_subaccount_one_mode` | Max 1 mode |
| 4 | `invariant_cant_enter_isolated_market_with_active_borrows` | Entry blocked if borrowing |
| 5 | `invariant_cant_exit_market_or_mode_with_active_borrows` | Exit blocked with borrows |
| 6 | `invariant_cant_enter_mode_with_entered_markets` | Mode entry blocked |
| 7 | `invariant_cant_enter_expired_market_or_mode` | Expired unreachable |
| 8 | `invariant_cant_borrow_without_entering_market_or_mode` | Must enter first |
| 9 | `invariant_deposit_receives_shares` | Non-zero shares on deposit |
| 10 | `invariant_deposit_receives_correct_amount` | Correct tracking |
| 11 | `invariant_withdraw_decreases_shares` | Share decrease |
| 12 | `invariant_withdraw_receives_correct_amount` | Correct return |
| 13 | `invariant_repay_decreases_borrow_shares` | Share decrease |
| 14 | `invariant_repay_correctly_decreases_borrow_amount` | Principal decrease |
| 15 | `invariant_borrow_increases_borrow_shares` | Share increase |
| 16 | `invariant_borrow_correctly_increases_borrow_amount` | Principal increase |

### Ghost Variable Pattern (SubAccountGhost)
```solidity
struct SubAccountGhost {
    uint8 numEnteredIsolatedMarkets;
    uint8 numEnteredMarkets;
    uint8 numEnteredModes;
    bool enteredIsolatedMarketWithActiveBorrows;
    bool exitedMarketOrModeWithActiveBorrows;
    bool enteredModeWithEnteredMarkets;
    bool enteredExpiredMarketOrMode;
    bool depositReceivedZeroShares;
    bool depositReceivedIncorrectAmount;
    bool withdrawReceivedIncorrectAmount;
    bool withdrawDecreasedZeroShares;
    bool repayDidntDecreaseBorrowShares;
    bool repayIncorrectBorrowAmountDecrease;
    bool borrowIncorrectBorrowAmountIncrease;
    bool borrowDidntIncreaseBorrowShares;
}
```

### Key Finding
**Medusa** consistently outperforms Foundry on complex multi-invariant scenarios with precision-loss bugs (rounding-down-to-zero). Echidna also catches some that Foundry misses. Formal verification (Halmos/Certora) wins on stateless properties.

---

## 9. Cross-Repo Patterns & Lessons

### Universal Invariant Categories for DeFi

1. **Conservation of Value** — Total assets in = total assets out (WETH, Maple, Morpho)
2. **Share Accounting** — sum(userShares) == totalShares (Morpho, Maple, WETH)
3. **Solvency** — contract balance >= total liabilities (ALL repos)
4. **Health Factor** — users maintain required collateralization (Morpho, Cap, Omni)
5. **Ordering** — sorted data structures maintain order (Liquity, Maple)
6. **State Machine** — valid state transitions only (Cap liquidation, Maple loan lifecycle)
7. **Monotonicity** — certain values only increase/decrease (Cap utilization index, staking value)
8. **Round-Trip** — deposit then withdraw returns <= original (a16z ERC4626)
9. **Rounding Direction** — always rounds in protocol's favor (a16z ERC4626, Trail of Bits)
10. **Access Control** — operations require proper authorization (a16z, Maple permissions)

### Handler Pattern Best Practices

| Pattern | Used By | Description |
|---------|---------|-------------|
| **Bounded inputs** | ALL | `_bound(seed, min, max)` to constrain fuzzer |
| **Actor management** | WETH, Maple, Liquity | AddressSet of users, random selection |
| **Ghost variables** | ALL | Track cumulative state not in contract |
| **NoRevert suffix** | Morpho | Handlers catch reverts, log them |
| **Call summary** | WETH | Log function call counts for coverage |
| **Seed-based selection** | Maple | Single seed selects loan/borrower/amount |
| **Time warping** | Maple, Liquity | `warp(seed)` advances time randomly |
| **Oracle manipulation** | Omni, Cap | Random price swings trigger liquidations |
| **Struct ghosts** | Omni | Per-entity ghost tracking via structs |
| **Multiple suites** | Maple | Same invariants tested under different scenarios |

### Foundry Configuration Recommendations

```toml
[invariant]
runs = 2000          # Maple/WETH standard
depth = 25           # calls per run (25-100 typical)
fail_on_revert = false  # handlers manage reverts
dictionary_weight = 80  # high = more value reuse
include_storage = true  # capture state for dictionary
include_push_bytes = true
```

### Tool Comparison Summary

| Tool | Strengths | Weaknesses |
|------|-----------|-----------|
| **Foundry** | Fast, native Solidity, easy setup | Misses precision bugs, basic corpus |
| **Echidna** | Haskell-powered corpus, good coverage | Slower, separate config |
| **Medusa** | Best at complex multi-invariant | Newer, smaller community |
| **Halmos** | Proves absence of bugs | Only stateless properties |
| **Certora** | Most powerful prover | Complex setup, expensive |

### Property Count by Repository

| Repo | Properties | Handlers | Ghost Vars |
|------|-----------|----------|------------|
| Trail of Bits (crytic) | 145 | N/A (unit-style) | N/A |
| Maple Finance | 84+ | 15 handlers | 20+ |
| Cap Protocol | 100 | Multi-handler | 15+ |
| a16z ERC4626 | 24 | N/A (property-style) | N/A |
| Liquity Bold | 12 | Full system handler | 15+ |
| WETH9 | 5 | 1 handler | 6 |
| Morpho Blue | 6 | 1 handler, 11 actions | 0 |
| Omni (fuzzing-comparison) | 16 | 1 handler, 13 actions | 15 (struct) |

**Total unique invariant properties cataloged: ~390+**
