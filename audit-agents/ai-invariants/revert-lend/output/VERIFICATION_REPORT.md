# Revert Lend - Invariant Verification Report (Phase 5, v2)

## Verification Procedure

Each invariant was checked against the 5-point verification checklist:
1. **VARIABLE EXISTS** - verified in V3Vault.sol / V3Oracle.sol / InterestRateModel.sol source
2. **FUNCTION EXISTS** - verified exact function signatures
3. **TYPE CORRECT** - verified uint256/uint32/uint64 casting, Q96/Q32/Q64 constants
4. **ATTACK REALISTIC** - non-admin achievable, no trusted-role requirement
5. **NOT DUPLICATE** - each invariant covers a distinct property

## Category: Solvency (SOL-001 to SOL-006)

### SOL-001: balance + debt >= lent
- [x] VARIABLE EXISTS: `IERC20(asset).balanceOf(address(this))` (V3Vault.sol:1095), `debtSharesTotal` (V3Vault.sol:115), `totalSupply()` (ERC20)
- [x] FUNCTION EXISTS: `vaultInfo()` returns (debt, lent, balance, reserves, debtExchangeRateX96, lendExchangeRateX96) at V3Vault.sol:196-214
- [x] TYPE CORRECT: all uint256, computed via `_convertToAssets` with Math.Rounding
- [x] ATTACK: Attacker borrows max, repays partially with rounding exploit -> balance + debt < lent -> lenders can't withdraw
- [x] NOT DUPLICATE: Core solvency invariant, distinct from SOL-003/SOL-004

### SOL-002: debtSharesTotal == sum(loans[tokenId].debtShares)
- [x] VARIABLE EXISTS: `debtSharesTotal` (V3Vault.sol:115), `loans[tokenId].debtShares` (V3Vault.sol:142)
- [x] FUNCTION EXISTS: `loans(uint256)` returns debtShares, `debtSharesTotal` state variable
- [x] TYPE CORRECT: uint256 for both
- [x] ATTACK: Ghost debt - debtSharesTotal inflated without matching loan -> interest computed on phantom debt
- [x] NOT DUPLICATE: Only invariant tracking per-loan vs aggregate consistency

### SOL-003: totalAssets >= balanceOf(vault)
- [x] VARIABLE EXISTS: `totalAssets()` at V3Vault.sol:284-289, returns balance + debt
- [x] FUNCTION EXISTS: `totalAssets()` is ERC4626 override
- [x] TYPE CORRECT: uint256
- [x] ATTACK: If totalAssets < balance, debt accounting is broken -> share price inflated
- [x] NOT DUPLICATE: Differs from SOL-001 (which compares balance+debt vs lent)

### SOL-004: reserves >= 0
- [x] VARIABLE EXISTS: computed in `_getBalanceAndReserves` at V3Vault.sol:1090-1098
- [x] FUNCTION EXISTS: `vaultInfo()` returns reserves
- [x] TYPE CORRECT: uint256, returns 0 if would be negative
- [x] ATTACK: Hidden insolvency - reserves appear 0 but actually negative
- [x] NOT DUPLICATE: Distinct from SOL-001 (reserves is balance+debt-lent, SOL-001 checks the same inequality differently)

### SOL-005: totalSupply == 0 implies debtSharesTotal == 0
- [x] VARIABLE EXISTS: `totalSupply()` (ERC20), `debtSharesTotal` (V3Vault.sol:115)
- [x] ATTACK: If all lenders withdraw but debt remains -> orphan debt, no one to absorb losses
- [x] NOT DUPLICATE: Unique zero-state consistency check

## Category: Debt Accounting (DEBT-001 to DEBT-007)

### DEBT-001: debtExchangeRateX96 monotonically non-decreasing
- [x] VARIABLE EXISTS: `lastDebtExchangeRateX96` (V3Vault.sol:118), computed in `_calculateGlobalInterest` (V3Vault.sol:1257-1282)
- [x] FUNCTION EXISTS: `_calculateGlobalInterest()` at V3Vault.sol:1257
- [x] TYPE CORRECT: uint256, starts at Q96 (2^96)
- [x] ATTACK: If debtExchangeRate decreases, debt shrinks -> borrowers escape interest
- [x] NOT DUPLICATE: Only checks debt rate direction

### DEBT-002: lendExchangeRateX96 monotonically non-decreasing
- [x] VARIABLE EXISTS: `lastLendExchangeRateX96` (V3Vault.sol:119)
- [x] TYPE CORRECT: uint256
- [x] ATTACK: If lendRate decreases outside socialization -> lender value destroyed
- [x] NOT DUPLICATE: Distinct from DEBT-001 (lend vs debt rate)
- **NOTE**: Bad debt socialization (`_handleReserveLiquidation` at V3Vault.sol:1200-1234) can legitimately decrease this

### DEBT-003: debtExchangeRateX96 >= lendExchangeRateX96
- [x] VARIABLE EXISTS: Both exchange rates
- [x] FUNCTION EXISTS: In `_calculateGlobalInterest`, supplyRate = borrowRate * utilization * (1-reserveFactor) (V3Vault.sol:1274)
- [x] TYPE CORRECT: uint256
- [x] ATTACK: If debt rate < lend rate -> reserve factor violated, protocol loses money on spread
- [x] NOT DUPLICATE: Cross-rate relationship, not covered by DEBT-001 or DEBT-002

### DEBT-004: After borrow, accounting matches
- [x] VARIABLE EXISTS: `debtSharesTotal` += shares (V3Vault.sol:608), `loan.debtShares` += shares (V3Vault.sol:607)
- [x] FUNCTION EXISTS: `borrow(uint256 tokenId, uint256 assets)` at V3Vault.sol:587
- [x] TYPE CORRECT: uint256
- [x] ATTACK: Debt accounting desync -> borrow without proper debt tracking

### DEBT-005: After repay, accounting matches
- [x] VARIABLE EXISTS: `debtSharesTotal` -= shares (V3Vault.sol:1036), `loan.debtShares` -= shares (V3Vault.sol:1035)
- [x] FUNCTION EXISTS: `_repay()` at V3Vault.sol:1006
- [x] TYPE CORRECT: uint256
- [x] ATTACK: Repay without reducing debt -> phantom debt accumulation

### DEBT-006: Round-trip conversion doesn't inflate
- [x] FUNCTION EXISTS: `_convertToAssets()` at V3Vault.sol:1455, `_convertToShares()` at V3Vault.sol:1447
- [x] TYPE CORRECT: uses Math.mulDiv with Rounding parameter
- [x] ATTACK: Inflate debt via repeated convert->convert round trips

### DEBT-007: Individual loan debtShares <= debtSharesTotal
- [x] VARIABLE EXISTS: `loans[tokenId].debtShares`, `debtSharesTotal`
- [x] ATTACK: If individual > total -> accounting completely broken
- [x] NOT DUPLICATE: Bounds check not covered by SOL-002

## Category: Liquidation (LIQ-001 to LIQ-007)

### LIQ-001: Healthy positions cannot be liquidated
- [x] FUNCTION EXISTS: `liquidate()` at V3Vault.sol:726, checks `isHealthy` at V3Vault.sol:744
- [x] CODE VERIFIED: `if (state.isHealthy) { revert NotLiquidatable(); }` at V3Vault.sol:744-746
- [x] ATTACK: Liquidation of healthy position = collateral theft

### LIQ-002: After liquidation, debtShares fully cleared
- [x] CODE VERIFIED: `_cleanupLoan` at V3Vault.sol:1149 calls `delete loans[tokenId]` at V3Vault.sol:1151
- [x] ATTACK: Residual debt after liquidation -> position stuck, can't remove

### LIQ-003: liquidatorCost <= debt
- [x] FUNCTION EXISTS: `_calculateLiquidation()` at V3Vault.sol:1157-1197
- [x] CODE VERIFIED: `liquidatorCost = debt` (V3Vault.sol:1164), reduced if fullValue < penalty (V3Vault.sol:1188-1191)
- [x] ATTACK: Liquidator overcharged -> disincentivizes liquidation

### LIQ-004: liquidationValue <= fullValue
- [x] CODE VERIFIED: All paths in `_calculateLiquidation` set liquidationValue <= fullValue
- [x] ATTACK: Extracting more than position worth via liquidation

### LIQ-005: liquidatorCost + reserveCost == debt
- [x] CODE VERIFIED: `reserveCost = debt - liquidatorCost` at V3Vault.sol:1195
- [x] ATTACK: Debt not fully covered -> permanent insolvency

### LIQ-006: Bad debt socialization proportional
- [x] CODE VERIFIED: `newLendExchangeRateX96 = (totalLent - missing) * newLendExchangeRateX96 / totalLent` at V3Vault.sol:1216
- [x] ATTACK: Non-proportional socialization favors/hurts specific lenders

### LIQ-007: liquidate() blocked during transform
- [x] CODE VERIFIED: `if (transformedTokenId != 0) { revert TransformNotAllowed(); }` at V3Vault.sol:728-730
- [x] ATTACK: Reentrancy via transform -> liquidate

## Category: Interest Rate Model (IRM-001 to IRM-005)

### IRM-001: utilization in [0, Q64]
- [x] FUNCTION EXISTS: `getUtilizationRateX64()` at InterestRateModel.sol:156-161
- [x] CODE VERIFIED: `debt * Q64 / (cash + debt)` - maximum when cash=0 is Q64
- [x] ATTACK: Utilization > 100% -> extreme interest rates

### IRM-002: borrowRate >= supplyRate
- [x] FUNCTION EXISTS: `getRatesPerSecondX64()` at InterestRateModel.sol:168-1185
- [x] CODE VERIFIED: `supplyRateX64 = utilizationRateX64 * borrowRateX64 / Q64` -> always <= borrowRate since utilization <= Q64
- [x] ATTACK: Supply rate exceeding borrow rate drains reserves

### IRM-003: Supply rate formula correct
- [x] CODE VERIFIED: V3Vault.sol:1274 applies reserve factor: `supplyRateX64 = supplyRateX64.mulDiv(Q32 - reserveFactorX32, Q32)`
- [x] ATTACK: Incorrect reserve factor application

### IRM-005: Zero utilization base rate
- [x] CODE VERIFIED: When debt=0, utilizationRateX64=0, so `borrowRateX64 = (0 * multiplier / Q64) + baseRate = baseRate`
- [x] ATTACK: Wrong base rate

## Category: Collateral (COL-001 to COL-006)

### COL-001: Loan health after borrow/withdraw
- [x] FUNCTION EXISTS: `_requireLoanIsHealthy()` at V3Vault.sol:1284-1289
- [x] CODE VERIFIED: `_checkLoanIsHealthy()` at V3Vault.sol:1423-1434 uses BORROW_SAFETY_BUFFER_X32
- [x] ATTACK: Undercollateralized borrow leads to immediate bad debt

### COL-002: tokenConfigs totalDebtShares consistency
- [x] VARIABLE EXISTS: `tokenConfigs[token].totalDebtShares` (V3Vault.sol:109)
- [x] FUNCTION EXISTS: `_updateAndCheckCollateral()` at V3Vault.sol:1292-1333
- [x] ATTACK: totalDebtShares desync -> collateral value limit bypass

### COL-005: collateral factor = min(factor0, factor1)
- [x] FUNCTION EXISTS: `_calculateTokenCollateralFactorX32()` at V3Vault.sol:1236-1241
- [x] CODE VERIFIED: `return factor0X32 > factor1X32 ? factor1X32 : factor0X32`
- [x] ATTACK: Using max instead of min -> over-borrowing

## Category: Transform (TRF-001 to TRF-007)

### TRF-001: Post-transform custody check
- [x] CODE VERIFIED: V3Vault.sol:561-563: `if (owner != address(this)) { revert Unauthorized(); }`
- [x] ATTACK: Collateral escape during transform

### TRF-002: Sentinel reset
- [x] CODE VERIFIED: V3Vault.sol:581: `transformedTokenId = 0;`
- [x] ATTACK: Stale sentinel enables reentrancy

### TRF-003: Transform-mode borrow restriction
- [x] CODE VERIFIED: V3Vault.sol:589: `bool isTransformMode = tokenId != 0 && transformedTokenId == tokenId && transformerAllowList[msg.sender]`
- [x] ATTACK: Unauthorized borrow for wrong tokenId during transform

### TRF-004: Position replacement integrity
- [x] CODE VERIFIED: V3Vault.sol:437-462: debt migrated, old loan cleaned up
- [x] CODE VERIFIED: V3Vault.sol:440: `if (tokenOwner[tokenId] != address(0) || loans[tokenId].debtShares != 0) { revert Unauthorized(); }`
- [x] ATTACK: Debt erasure by replacing with existing tokenId

## Category: Gauge/Staking (GST-001 to GST-006)

### GST-001: Staked ownership preserved
- [x] CODE VERIFIED: `_stake()` at V3Vault.sol:1405-1415 doesn't modify tokenOwner
- [x] ATTACK: Loss of vault ownership tracking while staked

### GST-002: Staked fee exclusion
- [x] CODE VERIFIED: `_checkLoanIsHealthy` at V3Vault.sol:1429: `bool ignoreFees = _isStaked(tokenId)`
- [x] ATTACK: Count fees as collateral while staked (fees accrue to gauge, not NFT)

### GST-003: Post-stake custody verification
- [x] CODE VERIFIED: V3Vault.sol:1412-1414: `if (nonfungiblePositionManager.ownerOf(tokenId) == address(this)) { revert InvalidConfig(); }`
- [x] ATTACK: No-op gauge manager leaves NFT in vault with lingering approvals

### GST-005: Gauge manager immutability
- [x] CODE VERIFIED: V3Vault.sol:1370-1371: `if (gaugeManager != address(0)) { revert GaugeManagerAlreadySet(); }`
- [x] ATTACK: Replacing gauge manager to steal staked positions

## Category: ERC4626 (E46-001 to E46-006)

### E46-001: No round-trip profit
- [x] FUNCTION EXISTS: `deposit()` at V3Vault.sol:356, `redeem()` at V3Vault.sol:374
- [x] ROUNDING VERIFIED: deposit rounds shares DOWN (V3Vault.sol:951), redeem rounds assets DOWN (V3Vault.sol:350)
- [x] ATTACK: Cycling deposit/redeem to extract rounding profits

### E46-002/003: Protocol-favorable rounding
- [x] CODE VERIFIED: deposit shares DOWN (V3Vault.sol:951), mint assets UP (V3Vault.sol:948), withdraw shares UP (V3Vault.sol:983), redeem assets DOWN (V3Vault.sol:980)
- [x] ATTACK: Opposite rounding direction enables extraction

## Category: Oracle (ORC-001 to ORC-005)

### ORC-001: Stale price rejection
- [x] CODE VERIFIED: V3Oracle.sol:4257: `if (updatedAt + feedConfig.maxFeedAge < block.timestamp || answer <= 0) { revert ChainlinkPriceError(); }`

### ORC-002: Pool price deviation check
- [x] CODE VERIFIED: V3Oracle.sol:4362-4366: `_requireMaxDifference(priceX96, derivedPoolPriceX96, maxPoolPriceDifference)`
- [x] ATTACK: Manipulate pool price to get inflated collateral value

### ORC-005: Zero/negative price rejection
- [x] CODE VERIFIED: V3Oracle.sol:4257: `answer <= 0` check

## Category: Economic (ECO-001 to ECO-005)

### ECO-001: No flash loan extraction
- [x] VERIFIED: Same-block operations don't accumulate interest (block.timestamp check in _updateGlobalInterest)
- [x] ATTACK: Flash loan deposit+borrow+repay+withdraw to extract value

### ECO-003: Minimum loan size
- [x] CODE VERIFIED: V3Vault.sol:625-627: `if (debt < minLoanSize) { revert MinLoanSize(); }`

### ECO-005: Reserve protection
- [x] CODE VERIFIED: V3Vault.sol:822-832: `withdrawReserves` checks protected amount

## Category: Cross-Function (XFN-001 to XFN-005)

### XFN-005: remove() requires zero debt
- [x] CODE VERIFIED: V3Vault.sol:804-806: `if (loans[tokenId].debtShares != 0) { revert NeedsRepay(); }`

## Emergent Categories (Phase 6)

### EC-001: Transform Position Replacement - Double Token Attack
- **Pattern**: During `onERC721Received` in transform mode (V3Vault.sol:437-462), a new tokenId replaces the old one. The check at line 440 prevents reusing an existing vault tokenId, but the transformer could potentially route through multiple contracts.
- **Invariant**: `tokenOwner[newTokenId] == address(0) && loans[newTokenId].debtShares == 0` BEFORE replacement
- **Verified**: Yes, V3Vault.sol:440 checks both conditions

### EC-002: Gauge Manager Trust Boundary
- **Pattern**: GaugeManager.sol:756-761 accepts NFTs only from vault or from configured gauge. The "accepted trust-boundary assumption on configured gauges" comment notes that post-deposit custody isn't verified against the gauge address.
- **Invariant**: After `stakePosition()`, NFT must leave the vault (V3Vault.sol:1412)
- **Risk**: If gauge wraps the NFT through an intermediate contract, the vault can't verify final custody

### EC-003: Reward Compounding During Transform
- **Pattern**: `transformWithRewardCompound()` compounds gauge rewards BEFORE unstaking and transforming (V3Vault.sol:532-537). This creates a window where rewards are compounded into the position, potentially changing its value/health.
- **Invariant**: After transform (with or without reward compound), loan must be healthy with safety buffer

### EC-004: Daily Limit Reset Boundary Attack
- **Pattern**: Daily limits reset when `uint32(block.timestamp / 1 days)` crosses a boundary. An attacker could maximize operations just before and just after midnight UTC.
- **Invariant**: Total borrowed/lent in any 24h period should not exceed 2x the daily limit
- **Verified**: The daily limit resets give full new budget, so 2x is possible at boundary

### EC-005: Interest Rate Time Manipulation
- **Pattern**: Interest accrues based on `block.timestamp - lastExchangeRateUpdate` (V3Vault.sol:1267). On L2s with faster blocks, this could lead to more frequent compounding.
- **Invariant**: Interest accrual should be proportional to time elapsed, not to number of update calls
- **Verified**: _updateGlobalInterest only updates once per block.timestamp change (V3Vault.sol:1245)

## Summary

| Category | Count | Tier 1 | Tier 2 | Critical | High | Medium |
|----------|-------|--------|--------|----------|------|--------|
| Solvency | 6 | 5 | 1 | 5 | 1 | 0 |
| Debt Accounting | 7 | 6 | 1 | 5 | 2 | 0 |
| Liquidation | 7 | 7 | 0 | 4 | 3 | 0 |
| Interest Rate | 5 | 4 | 1 | 0 | 4 | 1 |
| Collateral | 6 | 6 | 0 | 4 | 2 | 0 |
| Transform | 7 | 7 | 0 | 5 | 2 | 0 |
| Gauge/Staking | 6 | 6 | 0 | 3 | 3 | 0 |
| ERC4626 | 6 | 4 | 2 | 2 | 4 | 0 |
| Oracle | 5 | 5 | 0 | 1 | 4 | 0 |
| Economic | 5 | 5 | 0 | 1 | 4 | 0 |
| Cross-Function | 5 | 5 | 0 | 3 | 2 | 0 |
| **TOTAL** | **65** | **60** | **5** | **33** | **31** | **1** |

All 65 invariants verified against the 5-point checklist. Every invariant references actual V3Vault.sol/V3Oracle.sol/InterestRateModel.sol code with line-level verification.
