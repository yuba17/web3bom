# Revert Lend - Invariant Table (v2 - Comprehensive)

## Protocol Model

Revert Lend is an ERC4626 lending vault (`V3Vault.sol`, ~1480 LOC) where:
- **Lenders** deposit a single ERC20 asset (e.g., USDC) and receive vault shares (ERC20)
- **Borrowers** use Uniswap V3 / Aerodrome Slipstream LP NFT positions as collateral to borrow the lent asset
- **Interest** accrues via dual exchange rates: `debtExchangeRateX96` (grows debt) and `lendExchangeRateX96` (grows lender value)
- **Collateral** value is computed by `V3Oracle` using Chainlink + TWAP price feeds with pool price deviation checks
- **Liquidation** occurs when `collateralValue < debt`, with penalty ranging MIN_LIQUIDATION_PENALTY_X32 to MAX_LIQUIDATION_PENALTY_X32
- **Transformers** can modify collateralized positions atomically (leverage, range change, compound) via `transform()` sentinel pattern
- **GaugeManager** allows staking collateral in Aerodrome gauges while maintaining logical vault custody
- **Reserve factor** (`reserveFactorX32`) captures spread between borrow/supply rates as protocol revenue
- **Bad debt socialization** reduces `lendExchangeRateX96` proportionally when reserves insufficient

### Money Flows
```
Lender -> deposit(asset) -> V3Vault (mints shares)
V3Vault -> borrow(asset) -> Borrower (creates debt shares)
Borrower -> repay(asset) -> V3Vault (burns debt shares)
V3Vault shares -> withdraw(asset) -> Lender

Collateral: Borrower NFT -> V3Vault (custody) -> optionally GaugeManager (gauge staking)
Liquidation: Liquidator pays liquidatorCost -> receives collateral value -> bad debt covered by reserves/socialization
```

### Trust Boundaries
- Owner: can set transformers, limits, token configs, reserve factor, gauge manager (one-time)
- Emergency Admin: can set limits and oracle modes without timelock
- Transformers: allowlisted contracts that can modify collateralized positions during transform()
- GaugeManager: single immutable address that custodies NFTs when staked in gauges
- Oracle: V3Oracle with Chainlink + TWAP, sequencer uptime check on L2

## Invariant Summary

| # | Category | ID | Tier | Severity | Description | Attack if broken | Verified |
|---|----------|----|------|----------|-------------|------------------|----------|
| 1 | Solvency | SOL-001 | 1 | Critical | balance + debt >= lent (within rounding tolerance) | Protocol insolvent, lenders cannot withdraw | Yes |
| 2 | Solvency | SOL-002 | 1 | Critical | debtSharesTotal == sum(loans[tokenId].debtShares) for all active loans | Ghost/missing debt, broken accounting | Yes |
| 3 | Solvency | SOL-003 | 2 | Critical | totalAssets() >= IERC20(asset).balanceOf(vault) | Share price manipulation via deposit/withdraw | Yes |
| 4 | Solvency | SOL-004 | 1 | Critical | reserves >= 0 (balance + debt - lent >= 0) except during socialization | Hidden insolvency | Yes |
| 5 | Solvency | SOL-005 | 1 | Critical | totalSupply() == 0 implies no outstanding debt (debtSharesTotal == 0) | Orphan debt with no lenders | Yes |
| 6 | Solvency | SOL-006 | 1 | High | After any operation: asset.balanceOf(vault) >= 0 (trivially true but verifies no underflow) | Arithmetic underflow | Yes |
| 7 | Debt Accounting | DEBT-001 | 1 | Critical | debtExchangeRateX96 monotonically non-decreasing (>= Q96) | Interest reversal allows debt escape | Yes |
| 8 | Debt Accounting | DEBT-002 | 1 | Critical | lendExchangeRateX96 monotonically non-decreasing except bad debt socialization (>= Q96 initially) | Lender value destruction outside bad debt | Yes |
| 9 | Debt Accounting | DEBT-003 | 1 | Critical | debtExchangeRateX96 >= lendExchangeRateX96 (debt grows faster due to reserve factor) | Reserve factor violated, protocol loses money | Yes |
| 10 | Debt Accounting | DEBT-004 | 1 | Critical | After borrow(tokenId, assets): debtSharesTotal increased by exact shares, loan.debtShares increased by same | Debt accounting desync | Yes |
| 11 | Debt Accounting | DEBT-005 | 1 | Critical | After repay(): debtSharesTotal decreased by shares, loan.debtShares decreased by same | Repay without actual debt reduction | Yes |
| 12 | Debt Accounting | DEBT-006 | 1 | High | _convertToAssets(_convertToShares(x)) <= x (round-trip doesn't inflate) | Debt inflation/deflation via conversion | Yes |
| 13 | Debt Accounting | DEBT-007 | 1 | Critical | loan.debtShares <= debtSharesTotal for any individual loan | Single loan exceeds total system debt | Yes |
| 14 | Liquidation | LIQ-001 | 1 | Critical | liquidate() reverts on healthy positions (collateralValue >= debt) | Healthy position theft | Yes |
| 15 | Liquidation | LIQ-002 | 1 | Critical | After liquidation: loans[tokenId].debtShares == 0 | Residual debt = stuck position | Yes |
| 16 | Liquidation | LIQ-003 | 1 | High | liquidatorCost <= debt (never overpay) | Liquidator overcharged | Yes |
| 17 | Liquidation | LIQ-004 | 1 | High | liquidationValue <= fullValue (can't extract more than position is worth) | Value extraction beyond position | Yes |
| 18 | Liquidation | LIQ-005 | 1 | Critical | liquidatorCost + reserveCost == debt (total coverage equals debt) | Debt not fully covered = insolvency | Yes |
| 19 | Liquidation | LIQ-006 | 1 | High | After bad debt socialization: lendExchangeRateX96 decreased proportionally | Incorrect socialization ratio | Yes |
| 20 | Liquidation | LIQ-007 | 1 | Critical | liquidate() blocked during transformedTokenId != 0 | Liquidation during transform = reentrancy | Yes |
| 21 | Interest Rate | IRM-001 | 1 | High | utilizationRateX64 in [0, Q64] | Interest model overflow | Yes |
| 22 | Interest Rate | IRM-002 | 1 | High | borrowRateX64 >= supplyRateX64 at same utilization | Protocol loses money on spread | Yes |
| 23 | Interest Rate | IRM-003 | 1 | High | supplyRateX64 == borrowRateX64 * utilization * (1 - reserveFactor) / Q64 | Supply rate formula incorrect | Yes |
| 24 | Interest Rate | IRM-004 | 2 | Medium | borrowRateX64 continuous at kink (no jump discontinuity in wrong direction) | Rate manipulation around kink | Yes |
| 25 | Interest Rate | IRM-005 | 1 | High | At 0% utilization: borrowRateX64 == baseRatePerSecondX64 | Base rate incorrect | Yes |
| 26 | Collateral | COL-001 | 1 | Critical | After borrow/decreaseLiquidityAndCollect: collateralValue * BORROW_SAFETY_BUFFER_X32 / Q32 >= debt | Undercollateralized borrow | Yes |
| 27 | Collateral | COL-002 | 1 | Critical | tokenConfigs[token].totalDebtShares == sum of debtShares for positions with that token | Collateral limit bypass | Yes |
| 28 | Collateral | COL-003 | 1 | Critical | collateralFactorX32 <= MAX_COLLATERAL_FACTOR_X32 (90%) for all configured tokens | Over-leveraged positions | Yes |
| 29 | Collateral | COL-004 | 1 | High | Collateral value limit: token totalDebtShares * debtExchangeRate <= lent * collateralValueLimitFactorX32 | Concentration risk bypass | Yes |
| 30 | Collateral | COL-005 | 1 | Critical | collateralFactorX32 for a position == min(factor0, factor1) of its two tokens | Wrong factor used = over-borrowing | Yes |
| 31 | Collateral | COL-006 | 1 | High | Position with debt must have tokenOwner[tokenId] != address(0) | Orphan debt without owner | Yes |
| 32 | Transform | TRF-001 | 1 | Critical | After transform(): ownerOf(newTokenId) == vault address | Collateral escape during transform | Yes |
| 33 | Transform | TRF-002 | 1 | Critical | transformedTokenId == 0 outside of transform() (sentinel reset) | Reentrancy via stale sentinel | Yes |
| 34 | Transform | TRF-003 | 1 | Critical | During transform: borrow() only for transformedTokenId by allowlisted transformer | Unauthorized borrowing | Yes |
| 35 | Transform | TRF-004 | 1 | Critical | Position replacement: old token debt fully migrated to new, old token cleaned up | Debt erasure via swap | Yes |
| 36 | Transform | TRF-005 | 1 | High | After transform: loan must be healthy with safety buffer | Post-transform undercollateralization | Yes |
| 37 | Transform | TRF-006 | 1 | High | Transform approval only settable by tokenOwner[tokenId] | Unauthorized transform permission | Yes |
| 38 | Transform | TRF-007 | 1 | Critical | liquidate() and decreaseLiquidityAndCollect() blocked when transformedTokenId != 0 | Reentrancy during transform | Yes |
| 39 | Gauge/Staking | GST-001 | 1 | Critical | Staked: tokenOwner[tokenId] unchanged in vault while NFT in gauge | Ownership desync | Yes |
| 40 | Gauge/Staking | GST-002 | 1 | High | Staked position: oracle.getValue called with ignoreFees=true | Fee inflation for over-borrowing while staked | Yes |
| 41 | Gauge/Staking | GST-003 | 1 | Critical | After stake: nonfungiblePositionManager.ownerOf(tokenId) != vault address | No-op gauge manager | Yes |
| 42 | Gauge/Staking | GST-004 | 1 | High | After unstake: NFT returned to vault, tokenIdToGauge[tokenId] cleared | Stuck in gauge | Yes |
| 43 | Gauge/Staking | GST-005 | 1 | Critical | gaugeManager can only be set once (revert if already set) | Gauge manager replacement | Yes |
| 44 | Gauge/Staking | GST-006 | 1 | High | Staking only possible if gaugeManager is set and position has pool with configured gauge | Stake to unconfigured gauge | Yes |
| 45 | ERC4626 | E46-001 | 2 | High | redeem(deposit(assets)) <= assets (no round-trip profit) | Deposit/redeem cycling extraction | Yes |
| 46 | ERC4626 | E46-002 | 1 | Critical | deposit() rounds shares DOWN, mint() rounds assets UP (protocol-favorable) | Rounding drain | Yes |
| 47 | ERC4626 | E46-003 | 1 | Critical | withdraw() rounds shares UP, redeem() rounds assets DOWN (protocol-favorable) | Rounding drain on withdrawal | Yes |
| 48 | ERC4626 | E46-004 | 2 | High | Share price monotonically non-decreasing (except bad debt) | Share price manipulation | Yes |
| 49 | ERC4626 | E46-005 | 1 | High | totalSupply == 0 iff totalAssets == 0 (both zero or both nonzero) | First depositor attack | Yes |
| 50 | ERC4626 | E46-006 | 1 | High | Deposit respects globalLendLimit and dailyLendIncreaseLimitLeft | Limit bypass | Yes |
| 51 | Oracle | ORC-001 | 1 | High | Chainlink price rejected if stale (updatedAt + maxFeedAge < block.timestamp) | Stale price exploitation | Yes |
| 52 | Oracle | ORC-002 | 1 | High | Pool price vs oracle-derived price within maxPoolPriceDifference | Price manipulation for over-borrowing | Yes |
| 53 | Oracle | ORC-003 | 1 | High | Sequencer uptime check on L2 with grace period | Stale L2 prices after sequencer restart | Yes |
| 54 | Oracle | ORC-004 | 1 | High | Dual-mode verification: primary price cross-checked against secondary within maxDifference | Single oracle manipulation | Yes |
| 55 | Oracle | ORC-005 | 1 | Critical | Negative or zero Chainlink answer rejected | Zero/negative price = infinite borrowing | Yes |
| 56 | Economic | ECO-001 | 1 | Critical | No profit from deposit + borrow + repay + withdraw in same block | Flash loan extraction | Yes |
| 57 | Economic | ECO-002 | 1 | High | Donation (direct asset transfer) cannot extract value via share price inflation | Donation attack | Yes |
| 58 | Economic | ECO-003 | 1 | High | minLoanSize enforced: debt < minLoanSize reverts (prevents dust loans) | Gas griefing via micro-loans | Yes |
| 59 | Economic | ECO-004 | 1 | High | Daily limits reset correctly at day boundary | Limit bypass across days | Yes |
| 60 | Economic | ECO-005 | 1 | High | Reserve protection: owner cannot withdraw below protected reserve threshold | Reserve drain by owner | Yes |
| 61 | Cross-Function | XFN-001 | 1 | Critical | transform() + borrow(): debt health checked after transform completes | Undercollateralized via transform+borrow | Yes |
| 62 | Cross-Function | XFN-002 | 1 | Critical | stake() + liquidate(): unstakeIfNeeded called before liquidation proceeds | Liquidation blocked by staking | Yes |
| 63 | Cross-Function | XFN-003 | 1 | Critical | decreaseLiquidityAndCollect() re-stakes if was staked, checks health after | Collateral withdrawal bypass via staking | Yes |
| 64 | Cross-Function | XFN-004 | 1 | High | Position replacement during transform: new tokenId must not already exist in vault | Double-accounting via existing tokenId | Yes |
| 65 | Cross-Function | XFN-005 | 1 | High | remove() blocked if debtShares > 0 | Collateral removal with outstanding debt | Yes |

## Tier Legend
- **Tier 1**: Hard fail = confirmed bug. Any violation is a security issue.
- **Tier 2**: Needs review. May have dust tolerance. Violation needs context analysis.
