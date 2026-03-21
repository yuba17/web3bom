# Invariant Testing Properties — Complete Reference

> Sources: Trail of Bits crytic/properties (148 properties), Echidna docs, Foundry Book, RareSkills guide, secure-contracts.com

---

## Table of Contents
1. [Foundry Invariant Testing Setup](#foundry-invariant-testing-setup)
2. [Echidna Property Testing Setup](#echidna-property-testing-setup)
3. [ERC20 Properties (25)](#erc20-properties)
4. [ERC721 Properties (19)](#erc721-properties)
5. [ERC4626 Vault Properties (37)](#erc4626-vault-properties)
6. [ABDKMath64x64 Properties (67)](#abdkmath64x64-properties)
7. [DeFi Protocol Properties](#defi-protocol-properties)
8. [Access Control Properties](#access-control-properties)
9. [Accounting / Balance Properties](#accounting--balance-properties)
10. [State Machine Properties](#state-machine-properties)
11. [Property Writing Patterns](#property-writing-patterns)

---

## Foundry Invariant Testing Setup

### Configuration (foundry.toml)
```toml
[invariant]
runs = 1000           # Number of test executions (default: 256)
depth = 1000          # Function calls per run (default: 15)
fail_on_revert = false # Discard reverts vs fail on them
```

Override via env: `FOUNDRY_INVARIANT_RUNS=10000`

### Function Naming
```solidity
// Must start with invariant_ prefix
function invariant_totalSupplyMatchesBalances() external { ... }
```

### Open Testing (default)
All deployed contracts in the test become fuzz targets. Fuzzer randomly calls functions with random inputs.

### Handler-Based Testing (recommended)
Wrapper contracts that interact with target — gives control over:
- Call sequences and preconditions
- State management
- Selective function targeting

```solidity
contract Handler is Test {
    TargetContract target;

    constructor(TargetContract _target) {
        target = _target;
    }

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, 1e24); // bound inputs
        deal(address(token), address(this), amount);
        token.approve(address(target), amount);
        target.deposit(amount);
    }
}
```

### Target Control Functions
```solidity
function setUp() public {
    // Only fuzz the handler, not the target directly
    targetContract(address(handler));

    // Target specific selectors
    bytes4[] memory selectors = new bytes4[](2);
    selectors[0] = Handler.deposit.selector;
    selectors[1] = Handler.withdraw.selector;
    targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));

    // Exclude contracts from fuzzing
    excludeContract(address(token));
}
```

### Ghost Variables Pattern
Track cumulative state that the contract itself doesn't store:
```solidity
contract Handler is Test {
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;

    function deposit(uint256 amount) external {
        amount = bound(amount, 1, 1e24);
        target.deposit(amount);
        ghost_depositSum += amount;
    }

    function withdraw(uint256 amount) external {
        amount = bound(amount, 1, target.balanceOf(address(this)));
        target.withdraw(amount);
        ghost_withdrawSum += amount;
    }
}

// In invariant test:
function invariant_depositsSolvent() external {
    assertGe(
        handler.ghost_depositSum(),
        handler.ghost_withdrawSum(),
        "More withdrawn than deposited"
    );
}
```

### Bounding Fuzzed Inputs
```solidity
function testFunction(int256 x) external {
    x = bound(x, 10_000, 100_000);
}
```

---

## Echidna Property Testing Setup

### Property Requirements
- No arguments (for boolean properties)
- Return true if successful
- Name starts with `echidna_`

```solidity
function echidna_balance_under_1000() public view returns (bool) {
    return balances[msg.sender] <= 1000;
}
```

### Configuration (echidna.yaml)
```yaml
testMode: property          # or assertion, optimization
testLimit: 1000000
corpusDir: corpus
rpcUrl: https://eth-mainnet.g.alchemy.com/v2/KEY
rpcBlock: 18000000
```

### Optimization Mode
```solidity
// Echidna maximizes the return value
function echidna_optimize_extracted_profit() public returns (int256) {
    return int256(token.balanceOf(address(this))) - int256(initialAmount);
}
```

### Assertion Mode
```solidity
function test_deposit(uint256 amount) public {
    uint256 balBefore = token.balanceOf(address(this));
    vault.deposit(amount);
    assert(token.balanceOf(address(this)) == balBefore - amount);
}
```

### Inheritance Pattern (recommended)
```solidity
contract TestToken is Token {
    function echidna_supply_constant() public view returns (bool) {
        return totalSupply() == INITIAL_SUPPLY;
    }
}
```

### Never-Revert Pattern
```solidity
function getShares_never_reverts() public {
    (bool b,) = target.call(abi.encodeWithSignature("getShares(address)", address(this)));
    assert(b);
}
```

### Try/Catch Pattern (Solidity 0.6+)
```solidity
function depositShares_never_reverts(uint256 val) public {
    if (token.balanceOf(address(this)) >= val) {
        try target.depositShares(val) { /* ok */ }
        catch { assert(false); }
        assert(target.getShares(address(this)) > 0);
    }
}
```

### Round-Trip Property Pattern
```solidity
function deposit_withdraw_roundtrip(uint256 val) public {
    uint256 original = token.balanceOf(address(this));
    if (original >= val) {
        try target.depositShares(val) {} catch { assert(false); }
        uint256 shares = target.getShares(address(this));
        assert(shares > 0);
        try target.withdrawShares(shares) {} catch { assert(false); }
        assert(token.balanceOf(address(this)) == original);
    }
}
```

---

## ERC20 Properties

Source: `crytic/properties` — 25 properties

### Base Properties (17)

| ID | Function | Property |
|---|---|---|
| ERC20-BASE-001 | `test_ERC20_constantSupply` | Total supply constant for non-mintable/burnable tokens |
| ERC20-BASE-002 | `test_ERC20_userBalanceNotHigherThanSupply` | No user balance > totalSupply |
| ERC20-BASE-003 | `test_ERC20_usersBalancesNotHigherThanSupply` | Sum of user balances <= totalSupply |
| ERC20-BASE-004 | `test_ERC20_zeroAddressBalance` | balance(address(0)) == 0 |
| ERC20-BASE-005 | `test_ERC20_transferToZeroAddress` | transfer(address(0), x) must fail |
| ERC20-BASE-006 | `test_ERC20_transferFromToZeroAddress` | transferFrom to address(0) must fail |
| ERC20-BASE-007 | `test_ERC20_selfTransfer` | Self-transfer doesn't break accounting |
| ERC20-BASE-008 | `test_ERC20_selfTransferFrom` | Self-transferFrom doesn't break accounting |
| ERC20-BASE-009 | `test_ERC20_transferMoreThanBalance` | transfer(amount > balance) must fail |
| ERC20-BASE-010 | `test_ERC20_transferFromMoreThanBalance` | transferFrom(amount > balance) must fail |
| ERC20-BASE-011 | `test_ERC20_transferZeroAmount` | Zero-amount transfer doesn't break accounting |
| ERC20-BASE-012 | `test_ERC20_transferFromZeroAmount` | Zero-amount transferFrom doesn't break accounting |
| ERC20-BASE-013 | `test_ERC20_transfer` | transfer updates sender/receiver balances correctly |
| ERC20-BASE-014 | `test_ERC20_transferFrom` | transferFrom updates sender/receiver balances correctly |
| ERC20-BASE-015 | `test_ERC20_setAllowance` | approve sets allowance correctly |
| ERC20-BASE-016 | `test_ERC20_setAllowanceTwice` | Double approve updates correctly |
| ERC20-BASE-017 | `test_ERC20_spendAllowanceAfterTransfer` | allowance decreases after transferFrom (unless max) |

### Code Patterns

```solidity
// Supply constancy
function test_ERC20_constantSupply() public virtual {
    require(!isMintableOrBurnable);
    assertEq(initialSupply, totalSupply(), "Token supply was modified");
}

// No balance exceeds supply
function test_ERC20_userBalanceNotHigherThanSupply() public {
    assertLte(balanceOf(msg.sender), totalSupply(), "User balance higher than total supply");
}

// Sum of balances <= supply
function test_ERC20_usersBalancesNotHigherThanSupply() public {
    uint256 balance = balanceOf(USER1) + balanceOf(USER2) + balanceOf(USER3);
    assertLte(balance, totalSupply(), "Sum of user balances higher than total supply");
}

// Self-transfer preserves balance
function test_ERC20_selfTransfer(uint256 value) public {
    uint256 balance_sender = balanceOf(address(this));
    require(balance_sender > 0);
    bool r = this.transfer(address(this), value % (balance_sender + 1));
    assertWithMsg(r == true, "Failed self transfer");
    assertEq(balance_sender, balanceOf(address(this)), "Self transfer breaks accounting");
}

// Transfer updates both balances
function test_ERC20_transfer(address target, uint256 amount) public {
    require(target != address(this));
    uint256 balance_sender = balanceOf(address(this));
    uint256 balance_receiver = balanceOf(target);
    require(balance_sender > 2);
    uint256 transfer_value = (amount % balance_sender) + 1;
    bool r = this.transfer(target, transfer_value);
    assertWithMsg(r == true, "transfer failed");
    assertEq(balanceOf(address(this)), balance_sender - transfer_value);
    assertEq(balanceOf(target), balance_receiver + transfer_value);
}

// Allowance decreases after transferFrom (unless type(uint256).max)
function test_ERC20_spendAllowanceAfterTransfer(address target, uint256 amount) public {
    // ... setup ...
    bool r = this.transferFrom(msg.sender, target, transfer_value);
    if (current_allowance != type(uint256).max) {
        assertEq(allowance(msg.sender, address(this)), current_allowance - transfer_value);
    }
}
```

### Burnable Properties (3)

| ID | Function | Property |
|---|---|---|
| ERC20-BURNABLE-001 | `test_ERC20_burn` | burn updates balance and supply correctly |
| ERC20-BURNABLE-002 | `test_ERC20_burnFrom` | burnFrom updates balance and supply correctly |
| ERC20-BURNABLE-003 | `test_ERC20_burnFromUpdateAllowance` | burnFrom updates allowance correctly |

### Mintable Properties (1)

| ID | Function | Property |
|---|---|---|
| ERC20-MINTABLE-001 | `test_ERC20_mintTokens` | mint updates balance and supply correctly |

### Pausable Properties (2)

| ID | Function | Property |
|---|---|---|
| ERC20-PAUSABLE-001 | `test_ERC20_pausedTransfer` | transfer fails when paused |
| ERC20-PAUSABLE-002 | `test_ERC20_pausedTransferFrom` | transferFrom fails when paused |

### Allowance Properties (2)

| ID | Function | Property |
|---|---|---|
| ERC20-ALLOWANCE-001 | `test_ERC20_setAndIncreaseAllowance` | increaseAllowance works correctly |
| ERC20-ALLOWANCE-002 | `test_ERC20_setAndDecreaseAllowance` | decreaseAllowance works correctly |

---

## ERC721 Properties

Source: `crytic/properties` — 19 properties

### Base Properties (11)

| ID | Function | Property |
|---|---|---|
| ERC721-BASE-001 | `test_ERC721_balanceOfZeroAddressMustRevert` | balanceOf(address(0)) must revert |
| ERC721-BASE-002 | `test_ERC721_ownerOfInvalidTokenMustRevert` | ownerOf(invalidId) must revert |
| ERC721-BASE-003 | `test_ERC721_approvingInvalidTokenMustRevert` | approve(invalidId) must revert |
| ERC721-BASE-004 | `test_ERC721_transferFromNotApproved` | transferFrom reverts without approval |
| ERC721-BASE-005 | `test_ERC721_transferFromResetApproval` | transferFrom resets token approval |
| ERC721-BASE-006 | `test_ERC721_transferFromUpdatesOwner` | transferFrom updates token owner |
| ERC721-BASE-007 | `test_ERC721_transferFromZeroAddress` | transferFrom(from=address(0)) reverts |
| ERC721-BASE-008 | `test_ERC721_transferToZeroAddress` | transferFrom(to=address(0)) reverts |
| ERC721-BASE-009 | `test_ERC721_transferFromSelf` | Self-transfer doesn't break accounting |
| ERC721-BASE-010 | `test_ERC721_transferFromSelfResetsApproval` | Self-transfer resets approval |
| ERC721-BASE-011 | `test_ERC721_safeTransferFromRevertsOnNoncontractReceiver` | safeTransferFrom reverts for non-ERC721Receiver |

### Burnable Properties (6)

| ID | Function | Property |
|---|---|---|
| ERC721-BURNABLE-001 | `test_ERC721_burnReducesTotalSupply` | burn updates balance and supply |
| ERC721-BURNABLE-002 | `test_ERC721_burnRevertOnTransferFromPreviousOwner` | Burned tokens can't be transferred |
| ERC721-BURNABLE-003 | `test_ERC721_burnRevertOnTransferFromZeroAddress` | Burned tokens can't be transferred from 0 |
| ERC721-BURNABLE-004 | `test_ERC721_burnRevertOnApprove` | Burned tokens have approvals reset |
| ERC721-BURNABLE-005 | `test_ERC721_burnRevertOnGetApproved` | getApproved reverts for burned tokens |
| ERC721-BURNABLE-006 | `test_ERC721_burnRevertOnOwnerOf` | ownerOf reverts for burned tokens |

### Mintable Properties (2)

| ID | Function | Property |
|---|---|---|
| ERC721-MINTABLE-001 | `test_ERC721_mintIncreasesSupply` | mint updates balance and supply |
| ERC721-MINTABLE-002 | `test_ERC721_mintCreatesFreshToken` | mint creates token with correct owner |

---

## ERC4626 Vault Properties

Source: `crytic/properties` — 37 properties

### Must-Not-Revert Properties (8)

| ID | Property |
|---|---|
| ERC4626-001 | `asset()` must not revert |
| ERC4626-002 | `totalAssets()` must not revert |
| ERC4626-003 | `convertToAssets()` must not revert for reasonable values |
| ERC4626-004 | `convertToShares()` must not revert for reasonable values |
| ERC4626-005 | `maxDeposit()` must not revert |
| ERC4626-006 | `maxMint()` must not revert |
| ERC4626-007 | `maxRedeem()` must not revert |
| ERC4626-008 | `maxWithdraw()` must not revert |

### Rounding Direction Properties (10)

| ID | Property |
|---|---|
| ERC4626-013 | `previewDeposit()` rounds in favor of vault (fewer shares) |
| ERC4626-014 | `previewMint()` rounds in favor of vault (more assets) |
| ERC4626-015 | `convertToShares()` rounds down |
| ERC4626-016 | `previewRedeem()` rounds in favor of vault (fewer assets) |
| ERC4626-017 | `previewWithdraw()` rounds in favor of vault (more shares) |
| ERC4626-018 | `convertToAssets()` rounds down |
| ERC4626-019 | `deposit()` mints shares >= previewDeposit |
| ERC4626-020 | `mint()` consumes assets <= previewMint |
| ERC4626-021 | `withdraw()` burns shares <= previewWithdraw |
| ERC4626-022 | `redeem()` returns assets >= previewRedeem |

### Sender-Independent Properties (6)

| ID | Property |
|---|---|
| ERC4626-023 | `maxDeposit()` assumes infinite caller assets |
| ERC4626-024 | `maxMint()` assumes infinite caller assets |
| ERC4626-025 | `previewMint()` must not depend on msg.sender |
| ERC4626-026 | `previewDeposit()` must not depend on msg.sender |
| ERC4626-027 | `previewWithdraw()` must not depend on msg.sender |
| ERC4626-028 | `previewRedeem()` must not depend on msg.sender |

### Functional Accounting Properties (4)

| ID | Property |
|---|---|
| ERC4626-029 | `deposit()` removes assets from owner, adds shares to receiver |
| ERC4626-030 | `mint()` removes assets from owner, adds shares to receiver |
| ERC4626-031 | `redeem()` removes shares from owner, adds assets to receiver |
| ERC4626-032 | `withdraw()` removes shares from owner, adds assets to receiver |

### Approval-Based Redemption Properties (5)

| ID | Property |
|---|---|
| ERC4626-009 | Redemption via approval proxy works |
| ERC4626-010 | Withdrawal via approval proxy works |
| ERC4626-011 | withdraw requires share token approval for third parties |
| ERC4626-012 | redeem requires share token approval for third parties |
| ERC4626-035 | Third-party calls decrease spender's remaining allowance |

### Security Properties (2)

| ID | Property |
|---|---|
| ERC4626-033 | **Share price inflation attack detection** |
| ERC4626-034 | Vault decimals >= asset decimals |

### Key ERC4626 Patterns

```solidity
// Rounding: deposit should favor the vault
function verify_depositRoundingDirection(uint256 assets) public {
    uint256 sharesBefore = vault.balanceOf(address(this));
    uint256 previewShares = vault.previewDeposit(assets);
    vault.deposit(assets, address(this));
    uint256 actualShares = vault.balanceOf(address(this)) - sharesBefore;
    assertGe(actualShares, previewShares, "Deposit minted fewer shares than preview");
}

// Share inflation attack check
function verify_sharePriceInflationAttack(uint256 donationAmount, uint256 depositAmount) public {
    // Attacker donates assets directly to vault to inflate share price
    // Then a victim deposits and gets 0 shares due to rounding
    // Property: no deposit of > 0 assets should result in 0 shares
    uint256 shares = vault.previewDeposit(depositAmount);
    if (depositAmount > 0) {
        assertGt(shares, 0, "Deposit of nonzero assets returns 0 shares");
    }
}

// Round-trip: deposit then withdraw should not create value
function verify_noFreeValue(uint256 assets) public {
    uint256 shares = vault.deposit(assets, address(this));
    uint256 assetsBack = vault.redeem(shares, address(this), address(this));
    assertLe(assetsBack, assets, "User extracted more than deposited");
}
```

---

## ABDKMath64x64 Properties

Source: `crytic/properties` — 67 properties covering 19 arithmetic operations

### Addition (9 properties)
- Commutative: `add(x, y) == add(y, x)`
- Associative: `add(add(x, y), z) == add(x, add(y, z))`
- Identity: `add(x, 0) == x`
- Sign correctness: result sign matches operand signs
- Range: result within valid 64x64 range
- Max boundary: `add(MAX, 0) == MAX`
- Overflow: `add(MAX, 1)` reverts
- Min boundary: `add(MIN, 0) == MIN`
- Underflow: `add(MIN, -1)` reverts

### Subtraction (10 properties)
- Equivalence to addition: `sub(x, y) == add(x, neg(y))`
- Anti-commutative: `sub(x, y) == neg(sub(y, x))`
- Identity: `sub(x, 0) == x`
- Neutrality: `sub(add(x, y), y) == x`
- Sign correctness, range, max/min boundaries, overflow/underflow

### Multiplication (8 properties)
- Commutative: `mul(x, y) == mul(y, x)`
- Associative: `mul(mul(x, y), z) == mul(x, mul(y, z))`
- Distributive: `mul(x, add(y, z)) == add(mul(x, y), mul(x, z))`
- Identity: `mul(x, 1) == x`
- Sign correctness, range, max/min boundaries

### Division (8 properties)
- Identity: `div(x, 1) == x`
- Sign with negative divisor
- Zero numerator: `div(0, x) == 0`
- Magnitude effects, div-by-zero reverts, max/min boundaries, range

### Negation (5 properties)
- Double negation: `neg(neg(x)) == x`
- Identity, zero, max/min boundaries

### Absolute Value (7 properties)
- Always positive: `abs(x) >= 0`
- Symmetry: `abs(x) == abs(neg(x))`
- Multiplicativeness: `abs(mul(x, y)) == mul(abs(x), abs(y))`
- Subadditivity: `abs(add(x, y)) <= abs(x) + abs(y)`
- Zero, max/min boundaries

### Inverse (10 properties)
- Double inverse: `inv(inv(x)) ≈ x`
- Division equivalence: `inv(x) == div(1, x)`
- Identity: `mul(x, inv(x)) ≈ 1`
- Sign preservation, zero reverts, max/min approach zero

### Averages (11 properties)
- Arithmetic mean: result between operands, same value returns itself, order independent
- Geometric mean: same properties

---

## DeFi Protocol Properties

### Lending Protocol (Compound/Aave forks)

```solidity
// 1. Solvency: protocol always has enough to cover withdrawals
function invariant_protocolSolvent() external {
    assertGe(
        underlying.balanceOf(address(pool)),
        pool.totalDeposits() - pool.totalBorrows(),
        "Protocol insolvent"
    );
}

// 2. Borrow cannot exceed collateral value
function invariant_borrowBelowCollateral() external {
    for (uint i = 0; i < users.length; i++) {
        uint256 borrowed = pool.getBorrowBalance(users[i]);
        uint256 collateral = pool.getCollateralValue(users[i]);
        assertLe(borrowed, collateral * pool.collateralFactor() / 1e18);
    }
}

// 3. Interest accrual is monotonic (totalBorrows only increases between repays)
function invariant_interestMonotonic() external {
    assertGe(pool.totalBorrows(), ghost_lastTotalBorrows);
}

// 4. Exchange rate only increases (no share deflation)
function invariant_exchangeRateNonDecreasing() external {
    uint256 currentRate = pool.exchangeRate();
    assertGe(currentRate, ghost_lastExchangeRate);
}

// 5. Sum of deposits == total supply of receipt tokens
function invariant_depositSupplyMatch() external {
    assertEq(pool.totalDeposits(), cToken.totalSupply() * pool.exchangeRate() / 1e18);
}

// 6. Liquidation health check
function invariant_noUnderwaterPositions() external {
    // After liquidation, position must be healthy
    for (uint i = 0; i < users.length; i++) {
        if (pool.wasLiquidated(users[i])) {
            assertGe(pool.healthFactor(users[i]), 1e18);
        }
    }
}

// 7. Oracle staleness
function invariant_oracleNotStale() external {
    (, , , uint256 updatedAt, ) = oracle.latestRoundData();
    assertGt(block.timestamp - updatedAt, MAX_STALENESS, "Oracle stale");
}

// 8. First depositor attack prevention
function invariant_noFirstDepositorAttack() external {
    if (pool.totalSupply() > 0) {
        assertGt(pool.totalAssets(), 0, "Shares exist but no assets");
    }
}
```

### DEX / AMM Properties

```solidity
// 1. Constant product invariant (x * y = k, only increases from fees)
function invariant_constantProduct() external {
    uint256 reserve0 = pair.reserve0();
    uint256 reserve1 = pair.reserve1();
    assertGe(reserve0 * reserve1, ghost_lastK, "K decreased");
}

// 2. LP token supply matches liquidity
function invariant_lpSupplyMatchesReserves() external {
    if (pair.totalSupply() == 0) {
        assertEq(pair.reserve0(), 0);
        assertEq(pair.reserve1(), 0);
    } else {
        assertGt(pair.reserve0(), 0);
        assertGt(pair.reserve1(), 0);
    }
}

// 3. No tokens stuck in the router
function invariant_routerHoldsNoTokens() external {
    assertEq(token0.balanceOf(address(router)), 0);
    assertEq(token1.balanceOf(address(router)), 0);
}

// 4. Swap output < input (considering fees)
function invariant_swapNoFreeTokens() external {
    // After every swap, the product must not decrease
    assertGe(pair.reserve0() * pair.reserve1(), ghost_kBeforeSwap);
}

// 5. Price within bounds relative to oracle
function invariant_priceNotManipulated() external {
    uint256 spotPrice = pair.reserve0() * 1e18 / pair.reserve1();
    uint256 oraclePrice = oracle.getPrice();
    uint256 deviation = spotPrice > oraclePrice
        ? spotPrice - oraclePrice
        : oraclePrice - spotPrice;
    assertLe(deviation * 100 / oraclePrice, MAX_DEVIATION_PERCENT);
}

// 6. Fee accounting
function invariant_feesCollected() external {
    assertGe(pair.cumulativeFees0(), ghost_lastFees0);
    assertGe(pair.cumulativeFees1(), ghost_lastFees1);
}
```

### Staking / Rewards Properties

```solidity
// 1. Cannot withdraw more than deposited
function invariant_noExcessWithdrawal() external {
    for (uint i = 0; i < users.length; i++) {
        assertLe(
            ghost_totalWithdrawn[users[i]],
            ghost_totalDeposited[users[i]] + staking.earned(users[i])
        );
    }
}

// 2. Reward rate * duration <= reward balance
function invariant_rewardsSolvent() external {
    uint256 remaining = staking.periodFinish() - block.timestamp;
    uint256 owed = staking.rewardRate() * remaining;
    assertLe(owed, rewardToken.balanceOf(address(staking)));
}

// 3. Sum of all user stakes == totalStaked
function invariant_stakeSumMatchesTotal() external {
    uint256 sum;
    for (uint i = 0; i < users.length; i++) {
        sum += staking.balanceOf(users[i]);
    }
    assertEq(sum, staking.totalSupply());
}

// 4. No double claims in same epoch
function invariant_noDoubleClaim() external {
    // Track claims per user per epoch via ghost variables
    for (uint i = 0; i < users.length; i++) {
        assertLe(ghost_claimsPerEpoch[users[i]][currentEpoch], 1);
    }
}

// 5. Share price monotonically increasing
function invariant_sharePriceIncreasing() external {
    if (staking.totalSupply() > 0) {
        uint256 pricePerShare = staking.totalAssets() * 1e18 / staking.totalSupply();
        assertGe(pricePerShare, ghost_lastPricePerShare);
    }
}
```

### Cross-Chain / Bridge Properties

```solidity
// 1. Message nonce uniqueness (no replay)
function invariant_nonceUnique() external {
    assertFalse(bridge.usedNonces(ghost_lastNonce), "Nonce replayed");
}

// 2. Locked assets >= minted wrapped tokens
function invariant_bridgeSolvent() external {
    assertGe(
        token.balanceOf(address(bridge)),
        wrappedToken.totalSupply()
    );
}

// 3. Rate limit not exceeded
function invariant_rateLimitRespected() external {
    assertLe(
        ghost_bridgedThisPeriod,
        bridge.rateLimit()
    );
}
```

---

## Access Control Properties

```solidity
// 1. Only admin can call restricted functions
function invariant_onlyAdminCanPause() external {
    if (ghost_lastPauseCaller != address(0)) {
        assertTrue(
            accessControl.hasRole(ADMIN_ROLE, ghost_lastPauseCaller),
            "Non-admin paused"
        );
    }
}

// 2. Role count never exceeds maximum
function invariant_roleCountBounded() external {
    assertLe(
        accessControl.getRoleMemberCount(ADMIN_ROLE),
        MAX_ADMINS
    );
}

// 3. Owner cannot be address(0) while contract is active
function invariant_ownerNotZero() external {
    if (!contract_.paused()) {
        assertNotEq(contract_.owner(), address(0));
    }
}

// 4. Timelock delay respected
function invariant_timelockDelayRespected() external {
    for (uint i = 0; i < ghost_executedTxs.length; i++) {
        assertGe(
            ghost_executedTxs[i].executedAt - ghost_executedTxs[i].queuedAt,
            timelock.delay()
        );
    }
}

// 5. Initializer can only be called once (proxy pattern)
function invariant_initializerOnlyOnce() external {
    assertLe(ghost_initializeCallCount, 1);
}
```

---

## Accounting / Balance Properties

```solidity
// 1. Conservation of value: total assets in == total assets out + held
function invariant_conservationOfValue() external {
    assertEq(
        ghost_totalDeposited,
        ghost_totalWithdrawn + token.balanceOf(address(vault))
    );
}

// 2. No value creation from thin air
function invariant_noValueCreation() external {
    uint256 totalValue = 0;
    for (uint i = 0; i < allContracts.length; i++) {
        totalValue += token.balanceOf(allContracts[i]);
    }
    for (uint i = 0; i < allUsers.length; i++) {
        totalValue += token.balanceOf(allUsers[i]);
    }
    assertEq(totalValue, INITIAL_TOTAL_SUPPLY);
}

// 3. Fees never exceed principal
function invariant_feesReasonable() external {
    assertLe(ghost_totalFees, ghost_totalVolume * MAX_FEE_BPS / 10000);
}

// 4. No rounding exploits: repeated small operations shouldn't drain
function invariant_noRoundingDrain() external {
    // After N deposit/withdraw cycles, loss < N * 1 wei per operation
    int256 netLoss = int256(ghost_totalDeposited) - int256(ghost_totalWithdrawn)
                   - int256(token.balanceOf(address(vault)));
    assertLe(uint256(netLoss > 0 ? netLoss : -netLoss), ghost_operationCount);
}

// 5. Balances sum to total
function invariant_balancesSumToTotal() external {
    uint256 sum;
    for (uint i = 0; i < users.length; i++) {
        sum += vault.balanceOf(users[i]);
    }
    assertEq(sum, vault.totalSupply());
}

// 6. Share price bounded
function invariant_sharePriceBounded() external {
    if (vault.totalSupply() > 0) {
        uint256 price = vault.totalAssets() * 1e18 / vault.totalSupply();
        assertGe(price, MIN_SHARE_PRICE);
        assertLe(price, MAX_SHARE_PRICE);
    }
}
```

---

## State Machine Properties

```solidity
// 1. Valid state transitions only
function invariant_validStateTransition() external {
    State current = contract_.state();
    if (ghost_previousState == State.Pending) {
        assertTrue(
            current == State.Pending || current == State.Active,
            "Invalid transition from Pending"
        );
    } else if (ghost_previousState == State.Active) {
        assertTrue(
            current == State.Active || current == State.Finalized,
            "Invalid transition from Active"
        );
    } else if (ghost_previousState == State.Finalized) {
        assertEq(uint(current), uint(State.Finalized), "Finalized is terminal");
    }
}

// 2. No action in terminal state
function invariant_terminalStateImmutable() external {
    if (ghost_previousState == State.Finalized) {
        assertEq(ghost_actionCount, ghost_previousActionCount, "Action in terminal state");
    }
}

// 3. Auction: price monotonically decreasing (Dutch) or increasing (English)
function invariant_auctionPriceMonotonic() external {
    if (auction.isActive()) {
        uint256 currentPrice = auction.getCurrentPrice();
        if (auction.isDutch()) {
            assertLe(currentPrice, ghost_lastPrice);
        } else {
            assertGe(currentPrice, ghost_lastPrice);
        }
    }
}

// 4. Epoch transitions are sequential
function invariant_epochSequential() external {
    assertEq(contract_.currentEpoch(), ghost_lastEpoch + 1);
    // OR
    assertEq(contract_.currentEpoch(), ghost_lastEpoch);
}

// 5. Reentrancy guard: no nested calls
function invariant_noReentrancy() external {
    assertLe(ghost_callDepth, 1, "Reentrancy detected");
}

// 6. Paused state blocks all mutative operations
function invariant_pauseBlocksMutations() external {
    if (contract_.paused()) {
        assertEq(ghost_mutationsDuringPause, 0, "Mutation during pause");
    }
}
```

---

## Property Writing Patterns — Quick Reference

### Pattern 1: Before/After Comparison
```solidity
function handler_action(uint256 amount) external {
    uint256 before = target.value();
    target.action(amount);
    uint256 after_ = target.value();
    // Assert relationship between before and after
    assertGe(after_, before); // monotonically increasing
}
```

### Pattern 2: Ghost Variable Accumulation
```solidity
uint256 public ghost_sum;
function handler_deposit(uint256 amount) external {
    target.deposit(amount);
    ghost_sum += amount;
}
function invariant_sumCorrect() external {
    assertEq(target.totalDeposits(), ghost_sum);
}
```

### Pattern 3: Conditional Invariant
```solidity
function invariant_conditional() external {
    if (target.totalSupply() > 0) {
        assertGt(target.totalAssets(), 0, "Shares without backing");
    }
}
```

### Pattern 4: Bounded Input Fuzzing
```solidity
function handler_action(uint256 amount) external {
    amount = bound(amount, 1, target.maxDeposit(address(this)));
    target.deposit(amount);
}
```

### Pattern 5: Multi-Actor Testing
```solidity
function handler_depositAs(uint256 actorSeed, uint256 amount) external {
    address actor = actors[actorSeed % actors.length];
    vm.prank(actor);
    target.deposit(amount);
}
```

### Pattern 6: Optimization (Echidna)
```solidity
function echidna_optimize_profit() public returns (int256) {
    return int256(token.balanceOf(address(this))) - int256(initialBalance);
}
```

---

## Bug Hunting Checklist — Invariant Properties to Test

For any new protocol, write invariants for:

- [ ] **Solvency**: contract balance >= sum of user claims
- [ ] **Conservation**: total in == total out + held
- [ ] **Supply consistency**: sum(balances) == totalSupply
- [ ] **No free tokens**: no operation sequence creates value from nothing
- [ ] **No stuck tokens**: deposited tokens are always withdrawable
- [ ] **Monotonicity**: share price / exchange rate never decreases (excluding fees)
- [ ] **Rounding**: always favors the protocol, not the user
- [ ] **Access control**: privileged functions only callable by authorized roles
- [ ] **State transitions**: only valid transitions, terminal states are final
- [ ] **Reentrancy**: no nested calls modify state
- [ ] **Oracle freshness**: prices not stale
- [ ] **Rate limits**: not bypassable through multiple small transactions
- [ ] **First depositor**: no inflation attack on empty vaults
- [ ] **Zero amounts**: handle 0 deposits/withdrawals/transfers gracefully
- [ ] **Self-interactions**: self-transfer, self-approve, self-liquidate edge cases
