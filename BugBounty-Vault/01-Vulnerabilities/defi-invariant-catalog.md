# DeFi Invariant Properties Catalog

Comprehensive catalog of protocol-specific invariant properties for security auditing, fuzzing, and formal verification. Sourced from Certora, a16z, OpenZeppelin, horsefacts, Aave V3/V4 specs, Uniswap V4 proofs, and real-world exploit post-mortems.

---

## 1. Token Systems (ERC20)

### 1.1 Supply Conservation
```solidity
// The sum of all balances must equal totalSupply at all times
// Certora CVL:
ghost mathint g_sumOfBalances;
hook Sstore balances[KEY address a] uint256 newVal (uint256 oldVal) {
    g_sumOfBalances = g_sumOfBalances + newVal - oldVal;
}
invariant totalSupplyIsSumOfBalances()
    to_mathint(totalSupply()) == g_sumOfBalances;
```

### 1.2 Transfer Integrity
```solidity
// Foundry invariant test
function invariant_transferConservation() public {
    // For any transfer(from, to, amount):
    // balanceOf[from]_after == balanceOf[from]_before - amount
    // balanceOf[to]_after == balanceOf[to]_before + amount
    // totalSupply unchanged
    assertEq(token.totalSupply(), INITIAL_SUPPLY);
}
```

### 1.3 Allowance Consistency
```solidity
// After approve(spender, amount): allowance(owner, spender) == amount
// After transferFrom: allowance decreases by exactly the transferred amount
// Infinite allowance (type(uint256).max) should NOT decrease on transferFrom
```

### 1.4 Zero Address
```solidity
// balanceOf(address(0)) == 0 always
// transfer to address(0) must revert
// approve address(0) behavior must be consistent
```

### 1.5 Mint/Burn Invertibility (from Aave V3 specs)
```solidity
// mint(user, amount) followed by burn(user, amount) restores original balance
// burn additivity: burn(a) + burn(b) == burn(a+b) in same timestamp
// mint isolation: mint to user A does not change user B's balance
```

---

## 2. Vaults / ERC4626

### 2.1 Share Price Monotonicity
```solidity
// Share price (totalAssets/totalSupply) should never decrease
// Exception: slashing events, loss realization
function invariant_sharePriceMonotonicity() public {
    uint256 currentPrice = vault.totalAssets() * 1e18 / vault.totalSupply();
    assertGe(currentPrice, lastRecordedSharePrice);
    lastRecordedSharePrice = currentPrice;
}
```

### 2.2 Round-Trip Properties (a16z erc4626-tests)
```solidity
// No free profit from deposit-then-withdraw:
// redeem(deposit(assets)) <= assets  (user cannot extract more than deposited)
// withdraw(mint(shares)) <= shares   (symmetric for share-denominated ops)

// No free profit from withdraw-then-deposit:
// deposit(withdraw(assets)) >= assets (re-depositing costs at least as much)
// mint(redeem(shares)) >= shares
```

### 2.3 Preview Function Bounds
```solidity
// previewDeposit(assets) <= deposit(assets)  -- must NOT over-estimate shares received
// previewMint(shares) >= mint(shares)        -- must NOT under-estimate assets required
// previewWithdraw(assets) >= withdraw(assets) -- must NOT under-estimate shares burned
// previewRedeem(shares) <= redeem(shares)     -- must NOT over-estimate assets received
```

### 2.4 Conversion Consistency
```solidity
// convertToShares and convertToAssets must be caller-independent
// convertToAssets(convertToShares(x)) ~= x (within rounding tolerance)
// convertToShares(convertToAssets(x)) ~= x
```

### 2.5 Total Assets Tracking
```solidity
function invariant_totalAssetsConsistency() public {
    // totalAssets() >= sum of all deposited assets - withdrawn assets
    // totalAssets() == underlying.balanceOf(vault) + externalStrategyAssets
    assertEq(
        vault.totalAssets(),
        underlying.balanceOf(address(vault)) + vault.totalDebt()
    );
}
```

### 2.6 Supply Cap / Inflation Guard
```solidity
// Certora rule: totalMinted <= totalDeposited * MAX_RATIO
// This catches double-mint bugs (e.g., Solv Protocol vulnerability)

// First-depositor inflation attack prevention:
// With virtual shares: totalSupply() + virtualShares > 0 always
// Attack cost: must exceed (virtualAssets * attackerDeposit) to profit
```

### 2.7 Non-Reverting View Functions
```solidity
// These must NEVER revert:
// asset(), totalAssets(), maxDeposit(), maxMint(), maxWithdraw(), maxRedeem()
```

---

## 3. Lending Protocols (Aave/Compound Style)

### 3.1 Solvency
```solidity
// For every reserve:
// aToken.totalSupply() denominated in underlying >= total borrowed
// Contract holds enough underlying to service all withdrawals
// (accounting for utilization ratio)
```

### 3.2 Supply Cap Enforcement (Aave V3)
```solidity
// Certora verified:
// aToken supply shall NEVER exceed the configured cap
invariant supplyCapEnforced(address asset)
    aToken[asset].totalSupply() <= reserveConfig[asset].supplyCap;
```

### 3.3 Interest Accrual Monotonicity
```solidity
// Liquidity index only increases over time
// Variable borrow index only increases over time
// Reserve index monotonicity: index_after >= index_before for any operation

function invariant_indexMonotonicity() public {
    assertGe(pool.getReserveData(asset).liquidityIndex, lastLiquidityIndex);
    assertGe(pool.getReserveData(asset).variableBorrowIndex, lastBorrowIndex);
}
```

### 3.4 Debt Token Properties (from Aave V3 Certora specs)
```solidity
// Single user modification: any operation changes at most ONE user's balance
// Total supply consistency: delta(totalSupply) == delta(userBalance) for any op
// Pool authority: only the pool contract can mint/burn debt tokens
// Timestamp integrity: user lastUpdateTimestamp <= block.timestamp always
// Balance isolation: burn(userA) does not affect balanceOf(userB)
```

### 3.5 Health Factor / Liquidation
```solidity
// Account health after any non-liquidation operation:
// healthFactor >= 1.0 (or operation reverts)
// Euler V2 "Holy Grail": accounts stay healthy as long as prices don't change

// After liquidation:
// borrower health factor improves (or stays same)
// liquidator receives correct bonus
// protocol fee is correctly extracted
```

### 3.6 Reserve Configuration Isolation (Aave V3)
```solidity
// Setting one config member does NOT affect others
// Each setter changes ONLY one member
// Reserve count never decreases (monotonicity)
// Bijective mapping: reserve index <-> token address
```

### 3.7 User Configuration Consistency (Aave V3)
```solidity
// isEmpty == true implies no borrowing AND no collateral usage
// isBorrowing(reserveId) == true implies isBorrowingAny() == true
// Isolation mode: exactly one collateral asset active
// setBorrowing(reserveA) does NOT affect reserveB state
```

---

## 4. DEX / AMM

### 4.1 Constant Product Invariant
```solidity
// For Uniswap V2 style:
// reserveA * reserveB >= k (k can only increase from fees, never decrease)

function invariant_constantProduct() public {
    uint256 newK = pool.reserve0() * pool.reserve1();
    assertGe(newK, lastK); // k increases from fees, never decreases
    lastK = newK;
}
```

### 4.2 AMM Solvency (Certora-verified for Uniswap V4)
```solidity
// Contract Balance = Pool Liquidity + LP Fees + Protocol Fees
//                    + ERC6909 Reserves + Currency Deltas
// The contract ALWAYS has enough funds to pay out ALL LPs

// Formal property: enough_funds@before && function -> enough_funds@after
// Verified via SMT solver for ALL possible states and parameters
```

### 4.3 Liquidity Tracking (Uniswap V4)
```solidity
// pool.liquidity == sum of all active position liquidities
// For any tick: ticks[tick].netLiquidity ==
//   sum(liquidity starting at tick) - sum(liquidity ending at tick)

// Concentrated liquidity: position token requirements must match
// liquidity values across specified price ranges
```

### 4.4 Fee Accounting
```solidity
// Fees collected monotonically increase (feeGrowthGlobal only goes up)
// Sum of all claimed fees + unclaimed fees == total fees generated
// No user can claim more fees than their proportional share

function invariant_feeAccounting() public {
    // feeGrowthGlobal can only increase
    assertGe(pool.feeGrowthGlobal0X128(), lastFeeGrowth0);
    assertGe(pool.feeGrowthGlobal1X128(), lastFeeGrowth1);
}
```

### 4.5 Price Bounds
```solidity
// sqrtPriceX96 must stay within [MIN_SQRT_RATIO, MAX_SQRT_RATIO]
// After swap: price moves in correct direction
//   (buy token0 -> price increases, sell token0 -> price decreases)
// Price cannot be manipulated beyond slippage bounds in single tx
```

### 4.6 Swap Conservation
```solidity
// For every swap:
// amountIn (after fees) corresponds exactly to amountOut per the invariant curve
// No tokens created or destroyed during swap
// pool_balance_change_tokenA + user_balance_change_tokenA == 0
// pool_balance_change_tokenB + user_balance_change_tokenB == 0
```

---

## 5. Staking / Rewards

### 5.1 Stake/Unstake Balance
```solidity
// totalStaked == sum of all individual stakes
// unstake(amount) requires stake[user] >= amount
// After stake: totalStaked increases by exactly amount
// After unstake: totalStaked decreases by exactly amount

function invariant_stakingBalance() public {
    assertEq(staking.totalStaked(), ghost_sumOfAllStakes);
}
```

### 5.2 Reward Distribution Fairness (Synthetix Pattern)
```solidity
// rewardPerToken only increases over time (monotonic)
// User earned = stake[user] * (rewardPerToken - userRewardPerTokenPaid[user])
// Sum of all distributed rewards <= rewardRate * duration
// No user can claim more than their proportional share

function invariant_rewardPerTokenMonotonic() public {
    assertGe(staking.rewardPerToken(), lastRewardPerToken);
}
```

### 5.3 No Double-Claim
```solidity
// After claim(): user.rewards == 0
// claim() twice in same block yields 0 on second call
// userRewardPerTokenPaid updates to current rewardPerToken after claim
```

### 5.4 Flash-Loan Staking Prevention
```solidity
// Rewards should not accrue for zero-duration stakes
// If stake and unstake in same block: earned rewards == 0
// Minimum staking duration or snapshot-based rewards
```

### 5.5 Epoch/Period Consistency
```solidity
// rewardRate * rewardsDuration <= rewardsToken.balanceOf(contract)
// periodFinish == lastUpdateTime + rewardsDuration
// After periodFinish: no new rewards accrue (rewardPerToken stays flat)
```

---

## 6. Bridges / Cross-Chain

### 6.1 Balance Conservation
```solidity
// locked_source == minted_destination (across all pending messages)
// Formal: locked = SCDepositBalance + canceled + withdrawn + released
// Total token supply constant across ALL chains:
// sum(chain_supply[i] for all chains i) == TOTAL_SUPPLY

function invariant_crossChainSupply() public {
    // Pre-Crime pattern: fork all chains, deliver messages, verify:
    uint256 totalAcrossChains = 0;
    for (uint i = 0; i < chains.length; i++) {
        totalAcrossChains += token.totalSupply(chains[i]);
    }
    assertEq(totalAcrossChains, IMMUTABLE_TOTAL_SUPPLY);
}
```

### 6.2 Message Nonce Uniqueness
```solidity
// Every message has a unique nonce
// No nonce can be processed twice (replay prevention)
// mapping(bytes32 => bool) processedMessages; must be checked

function invariant_nonceUniqueness() public {
    // For every processed message: nonce is marked as used
    // For every nonce: at most one message exists
    // Nonces are monotonically increasing (no gaps in some designs)
}
```

### 6.3 Message Ordering
```solidity
// If protocol requires ordered delivery:
// message[nonce N] must be processed before message[nonce N+1]
// Out-of-order processing must revert

// If protocol allows unordered:
// Each message is independently executable
// No message depends on another's execution state
```

### 6.4 Rate Limiting
```solidity
// bridged_amount_in_window <= rate_limit
// Window resets correctly after cooldown
// Rate limit cannot be bypassed by splitting into smaller messages
```

### 6.5 Rescue/Emergency Properties
```solidity
// Formal (fail-safe bridge verification):
// locked = mintedBeforeDeath + nonMintedBeforeDeath
// Sufficient funds always exist for rescue operations
// Emergency pause halts ALL bridge operations (no partial state)
```

---

## 7. Dutch Auctions

### 7.1 Price Decay Monotonicity
```solidity
// Price is strictly non-increasing over time
// getPrice(t1) >= getPrice(t2) when t1 < t2

function invariant_priceDecay() public {
    uint256 currentPrice = auction.getCurrentPrice();
    assertLe(currentPrice, lastRecordedPrice);
    lastRecordedPrice = currentPrice;
}

// For exponential decay: price(t) = startPrice * e^(-k*t)
// For linear decay: price(t) = startPrice - (startPrice - endPrice) * t / duration
```

### 7.2 Time Bounds
```solidity
// Auction cannot start before startTime
// Auction cannot accept bids after endTime
// Price at startTime == startPrice
// Price at endTime >= reservePrice (floor)

function invariant_timeBounds() public {
    if (block.timestamp < auction.startTime()) {
        // Bidding must revert
    }
    if (block.timestamp > auction.endTime()) {
        // Auction is settled or expired
    }
    assertGe(auction.getCurrentPrice(), auction.reservePrice());
}
```

### 7.3 Settlement Guarantees
```solidity
// Once settled, no more bids accepted
// Settlement price == price at time of winning bid
// Winner receives the auctioned asset
// Seller receives the payment
// Excess ETH/tokens refunded to bidder

// For batch Dutch auctions (uniform clearing):
// All winners pay the same final clearing price
// clearing_price <= each winner's bid price
```

### 7.4 Supply/Demand Consistency
```solidity
// totalBidAmount <= totalAvailableSupply (before clearing)
// After clearing: allocated <= totalSupply
// Unsold tokens returned to seller or handled per spec
```

---

## 8. WETH-Specific (Formally Verified by Zellic)

### 8.1 Conservation of ETH
```solidity
// ETH can only be wrapped into WETH, WETH unwrapped back to ETH
// handler.ETH_SUPPLY == address(handler).balance + weth.totalSupply()

function invariant_conservationOfETH() public {
    assertEq(
        handler.ETH_SUPPLY(),
        address(handler).balance + weth.totalSupply()
    );
}
```

### 8.2 Solvency (Inductive Proof)
```solidity
// Any depositor can ALWAYS withdraw regardless of other users' actions
// Proved inductively:
//   Base: user deposits X, can immediately withdraw X
//   Inductive step: after ANY transaction T by ANY other user,
//                   original user can still withdraw X

// Key: sum(balanceOf[all users]) <= address(weth).balance
// Note: SELFDESTRUCT/coinbase can send ETH to WETH, making
//       balance > totalSupply (safe direction)
```

---

## 9. Cross-Cutting Invariant Patterns

### 9.1 Ghost Variable Tracking (horsefacts pattern)
```solidity
// In handler contract, maintain cumulative counters:
uint256 public ghost_totalDeposits;
uint256 public ghost_totalWithdrawals;
uint256 public ghost_sumOfBalances;

// Update in every handler function:
function deposit(uint256 amount) external {
    amount = bound(amount, 0, address(this).balance);
    target.deposit{value: amount}();
    ghost_totalDeposits += amount;
}

// Assert in invariant:
function invariant_conservation() public {
    assertEq(ghost_totalDeposits - ghost_totalWithdrawals, target.totalSupply());
}
```

### 9.2 Handler-Based Bounded Fuzzing
```solidity
// Constrain fuzzer inputs to valid ranges to reduce reverts:
amount = bound(amount, 1, token.balanceOf(address(this)));
// Use deal() to establish initial state
// Closed system: fixed initial supply, verify conservation
```

### 9.3 Rounding Direction Consistency
```solidity
// Protocol-favoring rounding:
// Deposits: round DOWN shares received (user gets fewer shares)
// Withdrawals: round UP shares burned (user pays more shares)
// Minting: round UP assets required (user pays more)
// Redeeming: round DOWN assets received (user gets less)

// This ensures the protocol never loses value to rounding
```

### 9.4 Access Control Invariants
```solidity
// Only authorized roles can call privileged functions
// Role assignments are consistent (admin can't remove self if last admin)
// Paused state blocks all user-facing operations
```

---

## 10. Real-World Bugs Caught by Invariant Testing

| Bug | Protocol | Invariant Broken | Impact |
|-----|----------|-----------------|--------|
| Share accounting desync | dTRINITY (2025) | totalAssets != actual assets | $257K lost |
| Double mint | Solv Protocol | totalMinted > totalDeposited * MAX_RATIO | Critical |
| TCR decrease after liquidation | eBTC (Badger) | TCR must increase after liquidation | Math proven invalid during redistribution |
| First depositor inflation | Multiple ERC4626 | Share price manipulation via donation | Critical |
| Euler V1 hack | Euler | Accounts stay healthy if prices unchanged | $197M lost |

---

## 11. Tool Recommendations by Invariant Type

| Invariant Type | Best Tool | Why |
|---|---|---|
| Arithmetic (overflow, rounding) | **Halmos** | Symbolic execution covers ALL inputs |
| Cross-function state | **Certora CVL** | Ghost variables + inductive reasoning |
| Stateful sequences | **Medusa** | Parallel + coverage-guided, fastest to break |
| Basic properties | **Foundry fuzz** | Table stakes, easy setup |
| Equivalence (upgrades) | **HEVM** | Bytecode-level comparison |
| On-chain monitoring | **Tenderly + custom** | Maple Finance pattern: webhook on invariant break |

### Recommended Pipeline
1. Slither static analysis (5 min baseline)
2. Foundry fuzz tests (existing suite)
3. Medusa/Echidna stateful invariant testing (break complex properties)
4. Halmos symbolic verification (prove arithmetic properties)
5. Certora CVL (critical cross-function invariants, 2-4 days)

---

## Sources

- Certora: Proving Solvency in Uniswap V4
- Certora: Formal Verification of Aave V3
- Certora: Formal Verification of Compound
- Certora: Euler V2 "Holy Grail" invariant
- a16z: erc4626-tests (reusable ERC4626 properties)
- a16z: Modern Invariant Testing with Halmos
- horsefacts: WETH Invariant Testing (ghost variables, reusable patterns)
- Zellic: Formal Verification of WETH (solvency proof)
- OpenZeppelin: ERC20 Certora specs (sum of balances)
- Badger DAO eBTC: 6 weeks of fuzzing learnings
- dTRINITY exploit post-mortem (share accounting bug)
- Maple Finance: on-chain invariant checking
- Aave V4 Security Blueprint (345 days of review)
- FMBC 2025: Formal Verification of Fail-Safe Cross-Chain Bridge
