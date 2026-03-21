# Invariant Testing Playbook for Bug Bounty Hunting

## Table of Contents
1. [Core Concepts](#core-concepts)
2. [Foundry Configuration & Setup](#foundry-configuration--setup)
3. [Handler-Based Testing Pattern](#handler-based-testing-pattern)
4. [Ghost Variables](#ghost-variables)
5. [Chimera Framework (Multi-Fuzzer)](#chimera-framework)
6. [Domain-Specific Invariants](#domain-specific-invariants)
7. [Trail of Bits Reusable Properties (168 Total)](#trail-of-bits-reusable-properties)
8. [Real Bugs Found via Invariant Testing](#real-bugs-found)
9. [Methodology: How to Define Invariants](#methodology-how-to-define-invariants)
10. [Bug Bounty Application](#bug-bounty-application)

---

## Core Concepts

**Invariant**: A condition that must ALWAYS hold true, regardless of state or execution path.
**Property**: A condition that holds only in a specific context (with preconditions).

Invariant testing = **stateful fuzz testing**. The fuzzer:
1. Deploys contracts
2. Randomly calls functions with random inputs
3. Checks invariants after EVERY call
4. Maintains state between calls (unlike stateless fuzzing)
5. If an invariant breaks, outputs the exact call sequence

### Why This Matters for Bug Bounties
- Finds bugs that unit tests miss (unexpected state combinations)
- Discovers multi-step attack paths automatically
- The Balancer $100M+ hack (Nov 2025) was a rounding bug that standard tests missed because they tested single swaps, not sequences of hundreds

---

## Foundry Configuration & Setup

### foundry.toml
```toml
[invariant]
runs = 1000        # Number of random sequences (default 256)
depth = 1000       # Calls per sequence (default 15)
fail_on_revert = false  # Don't fail on reverts (default false)
```

For bug hunting, increase both `runs` and `depth` significantly. Default 256/15 is too low.

### Basic Test Structure
```solidity
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";

contract InvariantTest is StdInvariant, Test {
    TargetContract target;

    function setUp() public {
        target = new TargetContract();
        targetContract(address(target));  // Tell fuzzer what to call
    }

    // Prefix with invariant_ — checked after EVERY fuzzed call
    function invariant_totalSupplyConsistent() public view {
        assertEq(target.totalSupply(), target.computedTotalSupply());
    }
}
```

### Key Helper Functions
| Function | Purpose |
|----------|---------|
| `targetContract(address)` | Restrict fuzzing to specific contracts |
| `targetSelector(FuzzSelector)` | Restrict which functions are called |
| `excludeContract(address)` | Remove contracts from fuzzing scope |
| `excludeSender(address)` | Prevent specific addresses from being callers |
| `afterInvariant()` | Lifecycle hook, runs after each sequence |

### Important Gotchas
- Each `invariant_` function creates a **separate EVM fork** — group related checks in one function
- `fail_on_revert = false` means reverts are silent — set to `true` when debugging
- Default mode targets ALL deployed contracts unless you use `targetContract()`

---

## Handler-Based Testing Pattern

Handlers are wrapper contracts that provide realistic interactions. This is the **most important pattern** for bug bounty invariant testing.

### Why Handlers?
- Raw fuzzing calls functions with nonsensical inputs → tons of reverts → wasted coverage
- Handlers bound inputs, set up preconditions, and track ghost state
- Result: meaningful sequences that exercise real protocol logic

### Template Handler
```solidity
contract Handler is Test {
    Protocol public protocol;
    IERC20 public token;

    // Ghost variables for tracking
    uint256 public ghost_depositSum;
    uint256 public ghost_withdrawSum;
    address[] public actors;

    constructor(Protocol _protocol, IERC20 _token) {
        protocol = _protocol;
        token = _token;
    }

    // Bounded deposit handler
    function deposit(uint256 amount, uint256 actorSeed) external {
        // Bound inputs to realistic range
        amount = bound(amount, 1e18, 100_000e18);

        // Select or create actor
        address actor = _getActor(actorSeed);

        // Setup preconditions
        deal(address(token), actor, amount);
        vm.startPrank(actor);
        token.approve(address(protocol), amount);

        // Execute
        protocol.deposit(amount);
        vm.stopPrank();

        // Track ghost state
        ghost_depositSum += amount;
    }

    function withdraw(uint256 amount, uint256 actorSeed) external {
        address actor = _getActor(actorSeed);
        uint256 maxWithdraw = protocol.balanceOf(actor);
        if (maxWithdraw == 0) return;  // Skip if nothing to withdraw

        amount = bound(amount, 1, maxWithdraw);

        vm.prank(actor);
        protocol.withdraw(amount);

        ghost_withdrawSum += amount;
    }

    function _getActor(uint256 seed) internal returns (address) {
        if (actors.length == 0) {
            actors.push(address(0x1));
            return address(0x1);
        }
        return actors[seed % actors.length];
    }
}
```

### Test Using Handler
```solidity
contract ProtocolInvariantTest is StdInvariant, Test {
    Protocol protocol;
    Handler handler;

    function setUp() public {
        protocol = new Protocol();
        handler = new Handler(protocol, token);

        // ONLY target the handler, not the protocol directly
        targetContract(address(handler));
    }

    function invariant_solvency() public view {
        assertGe(
            token.balanceOf(address(protocol)),
            protocol.totalDeposits()
        );
    }

    function invariant_depositWithdrawAccounting() public view {
        assertEq(
            handler.ghost_depositSum() - handler.ghost_withdrawSum(),
            protocol.totalDeposits()
        );
    }
}
```

---

## Ghost Variables

Ghost variables track derived state that the protocol doesn't expose directly. They are the key to powerful invariants.

### Common Ghost Variable Patterns

```solidity
// 1. Sum tracking — verify sum of parts equals whole
uint256 public ghost_totalShares;  // Sum of all user shares
// Invariant: ghost_totalShares == vault.totalSupply()

// 2. Cumulative operation tracking
uint256 public ghost_depositSum;
uint256 public ghost_withdrawSum;
// Invariant: ghost_depositSum - ghost_withdrawSum == totalDeposits

// 3. Per-user balance tracking
mapping(address => uint256) public ghost_userBalances;
// Invariant: sum(ghost_userBalances) == totalSupply

// 4. Before/after state tracking
uint256 public ghost_lastTotalAssets;
// Used in inline assertions within handler functions

// 5. Operation counting
uint256 public ghost_depositCount;
uint256 public ghost_withdrawCount;
// Used to verify events or state transitions
```

### WETH Example (Classic Reference)
Three invariants for WETH9 using ghost variables:
1. **Conservation of ETH**: `handler.ETH_balance + weth.totalSupply() == TOTAL_ETH_SUPPLY`
2. **Solvency**: `address(weth).balance >= weth.totalSupply()`
3. **Balance consistency**: `sum(balances[i]) == weth.totalSupply()`

---

## Chimera Framework

Write once, run on Foundry + Echidna + Medusa + Halmos.

### Setup
```bash
# Install template
forge init --template Recon-Fuzz/create-chimera-app my-invariant-tests
```

### Run Commands
```bash
# Foundry
FOUNDRY_PROFILE=invariants forge test --match-contract CryticToFoundry -vv

# Echidna
echidna . --contract CryticTester --config echidna.yaml

# Medusa
medusa fuzz
```

### Key Benefit
Echidna and Medusa use different fuzzing strategies than Foundry. Running all three maximizes coverage. Echidna is particularly good at finding counterexamples for mathematical properties.

### Limitation
Only HEVM-compatible cheatcodes work across all tools. Foundry-specific cheatcodes will fail in Echidna/Medusa.

---

## Domain-Specific Invariants

### ERC20 Token
| Invariant | Description |
|-----------|-------------|
| Constant supply | `totalSupply` unchanged without mint/burn |
| Balance cap | No user balance > totalSupply |
| Sum of balances | sum(balances) <= totalSupply |
| Zero address | balanceOf(address(0)) == 0 |
| Transfer accounting | sender decreases, receiver increases by exact amount |
| Allowance consistency | transferFrom reduces allowance correctly |

### ERC4626 Vault (37 properties from Crytic)
| Category | Key Invariants |
|----------|---------------|
| Non-revert | asset(), totalAssets(), convertToAssets/Shares(), maxDeposit/Mint/Redeem/Withdraw() must not revert |
| Rounding direction | deposit/mint round IN FAVOR of vault (more assets taken, fewer shares given) |
| | withdraw/redeem round IN FAVOR of vault (more shares taken, fewer assets given) |
| | previewDeposit <= actual shares, previewWithdraw >= actual shares |
| Sender independence | maxDeposit, maxMint, preview functions must not depend on msg.sender |
| Share inflation | First depositor cannot inflate share price to steal from subsequent depositors |
| Solvency | totalSupply >= sum(userShares) |
| Price stability | Price per share changes only on deposit/withdraw/mint/redeem |

### AMM / DEX
| Invariant | Description |
|-----------|-------------|
| Constant product | x * y = k (or x * y >= k with fees) |
| Reserve non-negativity | Reserves never go to zero or negative |
| No token creation | Total tokens in + out = constant |
| Solvency | Contract balance >= tracked reserves |
| Swap fairness | Output amount consistent with formula |
| LP share proportionality | LP tokens proportional to liquidity contribution |
| Fee monotonicity | Accumulated fees only increase |

### Lending Protocol
| Invariant | Description |
|-----------|-------------|
| Total collateral | sum(user collateral) == protocol total collateral |
| Total debt | sum(user debt) == protocol total debt |
| Solvency | total collateral value >= total debt value |
| Liquidation threshold | No undercollateralized position can borrow more |
| Interest monotonicity | Accrued interest only increases over time |
| No free borrowing | Can't borrow without sufficient collateral |
| Repayment accounting | Repaying reduces debt proportionally |
| Oracle freshness | Interest calculations use non-stale prices |

### Staking / Rewards
| Invariant | Description |
|-----------|-------------|
| Reward cap | Rewards distributed <= total reward pool |
| No double claim | User can't claim same epoch rewards twice |
| Stake accounting | sum(user stakes) == totalStaked |
| Reward proportionality | Rewards proportional to stake duration and amount |
| Withdrawal completeness | Unstaking returns full stake + earned rewards |

### Cross-Chain / Bridge
| Invariant | Description |
|-----------|-------------|
| Message uniqueness | No nonce reuse |
| Balance conservation | tokens_locked_source == tokens_minted_destination |
| Rate limiting | Transfer volume within limits per time window |

---

## Trail of Bits Reusable Properties

**Repository**: https://github.com/crytic/properties

### Complete Property Count
| Standard | Count | Categories |
|----------|-------|------------|
| ERC20 | 25 | Basic (17), Burnable (3), Mintable (1), Pausable (2), Allowance (2) |
| ERC721 | 19 | Basic (11), Burnable (6), Mintable (2) |
| ERC4626 | 37 | Non-revert (8), Approval proxy (5), Rounding (10), Sender independence (6), Functional (4), Security (2), Approval (2) |
| ABDKMath64x64 | 67 | Add (9), Sub (10), Mul (8), Div (8), Neg (5), Abs (7), Inv (10), Avg (6), Gavg (6) |
| **TOTAL** | **148** | |

### Critical ERC4626 Properties for Bug Hunting
- **ERC4626-033**: Share price inflation attack detection
- **ERC4626-013 to 022**: Rounding direction (THE category that led to Balancer's $100M loss)
- **ERC4626-029 to 032**: Functional deposit/mint/redeem/withdraw accounting

### How to Use
```solidity
import {CryticERC4626PropertyTests} from "@crytic/properties/ERC4626/ERC4626PropertyTests.sol";

contract MyVaultTest is CryticERC4626PropertyTests {
    constructor() {
        // Initialize with your vault and underlying token
        _vault_ = IHevm(address(myVault));
        _asset_ = IERC20(address(underlyingToken));
    }
}
```

---

## Real Bugs Found

### 1. Balancer V2 — $100M+ Hack (November 2025)
- **Bug**: Rounding direction error in Stable Math library
- **Root cause**: 1 wei precision loss in wrong direction per swap
- **Exploit**: Hundreds of batch swaps accumulated rounding errors
- **Missing invariant**: "Rounding must favor the protocol across N repeated operations"
- **Lesson**: Test invariants over SEQUENCES, not just single operations
- **Trail of Bits had flagged this class in 2021** (TOB-BALANCER-004) but severity was "undetermined"

### 2. Badger DAO eBTC — Fuzzing Campaign (2024)
- **40+ properties** tested over 6 weeks
- Found previously undisclosed bugs in liquidation mechanics
- Discovered that "TCR must increase after liquidations" is actually FALSE during bad debt redistribution
- Used Echidna + Foundry with test converter (EchidnaToFoundry.t.sol)
- Achieved 100% line coverage before finding the most impactful bugs

### 3. Uniswap V3 — TOB-UNI-005
- Inadequate invariant checking could have allowed draining any Uniswap pool
- Found during Trail of Bits' audit using invariant-driven analysis
- **Missing invariant**: Position accounting must always sum to pool totals

### 4. Flash Loan Vulnerability (SideEntranceLenderPool)
- Invariant tested: `address(pool).balance >= pool.initialPoolBalance()`
- Fuzzer automatically discovered: flashLoan → deposit in callback → withdraw
- No human had to specify the attack path

### 5. Hundred Finance & Sonne Finance (2023-2024)
- Share inflation / first depositor attacks
- Would have been caught by ERC4626-033 (share price inflation property)
- Now a standard check in all vault audits

---

## Methodology: How to Define Invariants

### Four Categories of Properties (Recon Framework)

1. **Valid States** — What states can the system be in?
   - Example: `x * y = k` for AMMs
   - Example: `totalCollateral >= totalDebt` for lending

2. **State Transitions** — What transitions are allowed?
   - Example: "Can't borrow without collateral"
   - Example: "Liquidation only when undercollateralized"

3. **Variable Transitions** — How should individual variables change?
   - Example: "Total fees only increase"
   - Example: "Total supply decreases on burn"

4. **High-Level Properties** — System-wide behaviors
   - Example: "Price per share changes only on deposit/withdraw"
   - Example: "No user ends up with more than they deposited + rewards"

### Step-by-Step Process

1. **Read the docs/spec FIRST** — Define how the system SHOULD behave before reading code
2. **List 10+ invariants** covering all four categories
3. **Prioritize by impact** — Solvency and accounting invariants first
4. **Write handlers** with bounded inputs and actor management
5. **Add ghost variables** for derived state tracking
6. **Start with `fail_on_revert = false`** — get tests running
7. **Gradually increase runs/depth** — 256/15 → 1000/100 → 10000/1000
8. **Switch to `fail_on_revert = true`** once handlers are stable
9. **Run multiple fuzzers** (Foundry + Echidna + Medusa via Chimera)
10. **Document broken invariants** — these are your findings

### Invariant Documentation Format (Trail of Bits)
```
ID: INV-001
Description: The total collateral value must always exceed total debt value
Components: LendingPool, CollateralManager
Testing Strategy: Stateful fuzz testing with handler
Proof/Justification: Protocol solvency requires this; violation = bad debt
```

---

## Bug Bounty Application

### Pre-Audit Setup (30 min)
1. Clone target repo, set up Foundry
2. Install Chimera: `forge install Recon-Fuzz/chimera`
3. Install crytic/properties: `forge install crytic/properties`
4. Create handler contract for main entry points
5. Write 5-10 core invariants based on protocol type

### What to Test First (by protocol type)
| Protocol Type | Priority Invariants |
|---------------|-------------------|
| Any ERC20 | Supply consistency, balance bounds |
| Vault/ERC4626 | Share inflation, rounding direction, solvency |
| AMM/DEX | Constant product, reserve solvency, no token creation |
| Lending | Collateral >= debt, liquidation correctness, interest monotonicity |
| Staking | Reward cap, no double claim, stake accounting |
| Bridge | Message uniqueness, balance conservation |

### Reporting Findings from Invariant Tests
When an invariant breaks:
1. **Save the call sequence** from Foundry output
2. **Minimize it** — remove unnecessary calls
3. **Convert to PoC** — deterministic unit test
4. **Calculate impact** — what's the financial damage?
5. **Frame as concrete exploit** — not "theoretical invariant violation"

### High-Signal Invariant Categories for Bug Bounties
1. **Rounding direction** — Balancer proved this is Critical severity
2. **Share inflation / first depositor** — Standard vault attack
3. **Accounting mismatches** — ghost_sum != contract_total
4. **Solvency violations** — contract balance < tracked deposits
5. **Cross-function interactions** — deposit → flashLoan → withdraw sequences
6. **Fee avoidance** — operations that skip fee collection
7. **Oracle manipulation** — stale or manipulated price leads to wrong liquidation

### Tips
- Run with high depth (500+) for multi-step attacks
- Use multiple actors in handlers to test cross-user interactions
- Track cumulative rounding errors across many operations
- Test with extreme values: 1 wei, type(uint256).max, 0
- Test with tiny and huge liquidity pools
- After finding a broken invariant, check if it's exploitable ON MAINNET FORK

---

## 2026 Fuzzer Benchmark Results

Tested against 8 vulnerability patterns from real 2025-2026 DeFi exploits:

| Bug Pattern | Foundry | Echidna | Medusa |
|---|---|---|---|
| First Depositor Inflation | 3 runs | 45 runs | 12 runs |
| Reentrancy via Callback | 847 runs | 1,203 runs | 456 runs |
| Oracle Manipulation | MISS | 23,456 runs | 8,901 runs |
| Unchecked Overflow | 12 runs | 89 runs | 23 runs |
| Flash Loan + Governance | MISS | 67,891 runs | 12,345 runs |
| Cross-Function Reentrancy | 2,341 runs | 5,678 runs | 1,234 runs |
| Precision Loss Accumulation | MISS | MISS | 234,567 runs |
| tx.origin Phishing | 1 run | 234 runs | 67 runs |

**Scores**: Foundry 5/8, Echidna 7/8, Medusa 8/8

**Key insight**: Foundry misses multi-step exploits (oracle manipulation, flash loan governance, precision loss). Medusa's coverage-guided approach caught precision loss that required hundreds of small transactions.

**Recommended pipeline**: Foundry for fast CI -> Medusa for deep stateful fuzzing -> Echidna for critical invariants with coverage reports.

### First Depositor Inflation Test (from Benchmark)
```solidity
function testFuzz_firstDepositorInflation(
    uint256 donation,
    uint256 deposit
) public {
    donation = bound(donation, 1, 1e24);
    deposit = bound(deposit, 1, 1e24);

    vault.deposit(1, attacker);
    token.transfer(address(vault), donation); // Inflate share price
    uint256 shares = vault.deposit(deposit, victim);
    uint256 redeemable = vault.previewRedeem(shares);

    // Victim should get back ~what they deposited
    assertGe(redeemable, deposit * 99 / 100);
}
```

---

## Case Study: Cap Protocol (Recon-Fuzz Audit) — 100 Invariants, 6 Bugs Found

**Protocol**: Cap -- lending protocol with cUSD stablecoin backed 1:1 by stable assets.

### Invariant Properties (100 total, key examples)

**Core Vault Solvency:**
- "Sum of deposits is less than or equal to total supply"
- "totalSupplies for a given asset is always <= vault balance + totalBorrows"
- "Utilization ratio never exceeds 1e27"

**Agent Health & Liquidation:**
- "Health should not change when interest is realized"
- "Liquidations should always improve the health factor"
- "Agent should always be liquidatable if it is unhealthy"

**CapToken Operations:**
- "User always receives at least the minimum amount out"
- "Fees are always <= the amount out"
- "User can always redeem cap token if they have sufficient balance"

**Debt Management:**
- "DebtToken balance >= total vault debt at all times"
- "If debt token balance is 0, agent should not be isBorrowing"
- "Agent can never have less than minBorrow balance of debt token"

### Handler Functions Used
- `capToken_mint_clamped()` / `capToken_redeem_clamped()`
- `lender_borrow_clamped()` / `lender_repay()`
- `lender_liquidate()` / `lender_initiateLiquidation()`
- `lender_realizeInterest()` / `lender_realizeRestakerInterest()`
- `oracle_setRestakerRate()` -- oracle manipulation for edge cases
- `switchActor()` -- multi-agent scenarios

### Bugs Found

**Medium (2):**
1. **M-01**: Agent health changes after `realizeRestakerInterest()` -- Reducing restaker rate before interest realization increases total debt, worsening health despite the operation's expected invariant
2. **M-02**: Vault redeem always reverts -- Array initialization uses wrong length variable, causing out-of-bounds access

**Low (4):**
1. Liquidations under certain price conditions worsen health factors
2. Full repayment doesn't reset `isBorrowing` flag to false
3. Permanent DOS of CapToken with 18-decimal tokens -- price rounds to zero, blocking all operations
4. DebtToken totalSupply falls below actual vault debt

**Takeaway**: 100 invariants across a lending protocol caught 2 Mediums and 4 Lows. The "health unchanged by interest realization" invariant was the highest-value property.

---

## Case Study: Badger DAO eBTC — 6 Weeks of Fuzzing

**Protocol**: eBTC -- collateralized crypto asset pegged to BTC, backed by stETH

### Key Details
- **40+ invariant properties** implemented
- **Tooling**: Echidna primary (coverage-guided), with EchidnaToFoundry converter for debugging
- **Coverage**: Achieved 100% line coverage, THEN started finding real bugs
- **Validated**: Spearbit's manual review findings through fuzzing

### Critical Finding
"TCR must increase after liquidations" was proven mathematically invalid during debt redistributions -- portions of a liquidated CDP's debt remaining in the system can lower the Total Collateral Ratio.

### Debugging Pattern: EchidnaToFoundry Converter
When Echidna finds a violation, convert to Foundry unit test for step-by-step debugging:
```
EchidnaToFoundry.t.sol -- converts Echidna call sequences to reproducible Foundry tests
```
This avoids embedding debug events in production test code.

---

## Echidna Property Syntax & Configuration

### Property Definitions
```solidity
// Boolean properties: start with echidna_, no args, return bool
function echidna_totalSupplyConstant() public returns (bool) {
    return token.totalSupply() == initialSupply;
}

function echidna_balanceNeverNegative() public returns (bool) {
    return token.balanceOf(msg.sender) >= 0;
}

// Assertion mode (alternative)
function test_depositWithdraw(uint256 amount) public {
    amount = bound(amount, 1, 1e18);
    protocol.deposit{value: amount}();
    protocol.withdraw(amount);
    assert(address(this).balance >= previousBalance);
}
```

### Echidna Config (echidna.yaml)
```yaml
corpusDir: "tests/echidna-corpus"
testMode: assertion          # options: property, assertion, foundry, overflow, optimization, exploration
testLimit: 100000
deployer: "0x10000"
sender: ["0x10000", "0x20000", "0x30000"]
```

### Echidna Real-World Bug Discoveries

| Project | Vulnerability | Year |
|---------|---------------|------|
| 0x Protocol | Order cancellation failures | 2019 |
| Balancer Core | Pool asset theft vectors | 2020 |
| Origin Dollar | Balance invariant violations | 2020 |
| Liquity | Improper trove removal mechanics | 2020 |
| Set Protocol (AddressArrayUtils) | `hasDuplicate()` underflow on empty array -- DoS | 2020 |
| ABDKMath64x64 | Assertion failure in `divuu` for specific input range | 2023 |
| MakerDAO | System invariant violation | 2024 |

### AddressArrayUtils Bug Detail (Trail of Bits)
```solidity
// Bug: if A.length is 0, then A.length - 1 underflows to type(uint256).max
// causing the outer loop to iterate over all uint256 values, exhausting gas
// Property that caught it:
for (uint i = 0; i < addrs1.length; i++) {
    (i1, b) = AddressArrayUtils.indexOf(addrs1, addrs1[i]);
    (i2, b) = AddressArrayUtils.indexOfFromEnd(addrs1, addrs1[i]);
    if (i1 != (i2-1)) {
        hasDup = true;
    }
}
return hasDup == AddressArrayUtils.hasDuplicate(addrs1);
```

---

## Trail of Bits: Property Writing Methodology

### Step-by-Step (from secure-contracts.com)

**1. Basic Revert Properties** -- foundational checks:
```solidity
function depositShares_never_reverts(uint256 val) public {
    if (token.balanceOf(address(this)) >= val) {
        try defi.depositShares(val) { /* success */ }
        catch { assert(false); }
    }
}
```

**2. Postcondition Verification** -- check state after execution:
```solidity
function depositShares_never_reverts(uint256 val) public {
    if (token.balanceOf(address(this)) >= val) {
        try defi.depositShares(val) { /* not reverted */ }
        catch { assert(false); }
        assert(defi.getShares(address(this)) > 0);
    }
}
```

**3. Combined Operation Properties** -- multi-step:
```solidity
function deposit_withdraw_shares_never_reverts(uint256 val) public {
    uint256 original_balance = token.balanceOf(address(this));
    if (original_balance >= val) {
        try defi.depositShares(val) { /* success */ }
        catch { assert(false); }
        uint256 shares = defi.getShares(address(this));
        assert(shares > 0);
        try defi.withdrawShares(shares) { /* success */ }
        catch { assert(false); }
        assert(token.balanceOf(address(this)) == original_balance);
    }
}
```

### Best Practices (Trail of Bits)
- **Start simple**: Basic revert assertions before postconditions
- **Minimize dead code**: Use `val = val % (token.balanceOf(address(this)) + 1)` instead of if/else
- **Keep simpler properties alongside complex ones** -- they catch different bugs
- **Use try/catch** over low-level calls for cleaner error handling
- **Run frequently**: Execute fuzzing after each new property

---

## Resources

- **Foundry Invariant Docs**: https://getfoundry.sh/forge/invariant-testing
- **Trail of Bits Reusable Properties (168)**: https://github.com/crytic/properties
- **Trail of Bits Testing Handbook**: https://github.com/trailofbits/testing-handbook
- **Building Secure Contracts**: https://secure-contracts.com/program-analysis/echidna/basic/property-creation.html
- **WETH9 Reference Implementation**: https://github.com/horsefacts/weth-invariant-testing
- **Cap Protocol Invariants (100 properties)**: https://github.com/Recon-Fuzz/cap-invariants
- **Echidna**: https://github.com/crytic/echidna
- **RareSkills Invariant Guide**: https://rareskills.io/post/invariant-testing-solidity
- **ThreeSigma Foundry Cheatcodes**: https://threesigma.xyz/blog/foundry/foundry-cheatcodes-invariant-testing
- **eBTC Fuzzing Learnings**: https://allthingsfuzzy.substack.com/p/learnings-from-6-weeks-of-fuzzing
- **2026 Fuzzer Benchmark**: https://dev.to/ohmygod/the-smart-contract-fuzzer-showdown-foundry-vs-echidna-vs-medusa-vs-trident-2026-benchmark-4ofm
- **Echidna Blog (AddressArrayUtils)**: https://blog.trailofbits.com/2020/08/17/using-echidna-to-test-a-smart-contract-library/
- **Reusable Properties Blog**: https://blog.trailofbits.com/2023/02/27/reusable-properties-ethereum-contracts-echidna/
