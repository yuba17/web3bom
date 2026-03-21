# Invariant Testing Master Strategy — Comprehensive Research Report

> Deep research compiled 2026-03-19. Sources: Recon/zigtur, Trail of Bits, Certora, Euler, Maple Finance, Cap Protocol, devdacian benchmarks, Foundry docs, a16z, Morpho, Liquity, eBTC, and 30+ audit reports.

---

## TABLE OF CONTENTS

1. [Complete Landscape of Tools & Frameworks](#1-complete-landscape)
2. [The Chimera/Recon Ecosystem (Best-in-Class)](#2-chimera-recon-ecosystem)
3. [Fuzzer Comparison: Which Tool for What](#3-fuzzer-comparison)
4. [Invariant Categories That Actually Find Bugs](#4-invariant-categories)
5. [Real Bugs Found by Invariant Testing](#5-real-bugs-found)
6. [The Optimal Workflow (What Top Teams Do)](#6-optimal-workflow)
7. [Advanced Techniques We Should Adopt](#7-advanced-techniques)
8. [Formal Verification Layer (Certora/Halmos/Kontrol)](#8-formal-verification)
9. [Property Libraries & Checklists We Need](#9-property-libraries)
10. [Gap Analysis: What We Have vs What We Need](#10-gap-analysis)
11. [Implementation Plan](#11-implementation-plan)

---

## 1. COMPLETE LANDSCAPE OF TOOLS & FRAMEWORKS

### Tier 1: Production Fuzzers (Must Use)

| Tool | Language | Engine | Best For | Parallel | Corpus |
|------|----------|--------|----------|----------|--------|
| **Echidna** | Haskell | hevm | Deep invariant testing, optimization mode | Via Parade | Yes |
| **Medusa** | Go | go-ethereum | Complex multi-invariant protocols, parallel fuzzing | Native multi-worker | Yes |
| **Foundry** | Rust | revm | Developer-friendly invariant tests, rapid iteration | No | Limited |

### Tier 2: Formal Verification (Complement Fuzzing)

| Tool | Approach | Best For |
|------|----------|----------|
| **Certora** | SMT-based formal verification via CVL | Proving mathematical invariants hold for ALL inputs |
| **Halmos** | Symbolic execution for Foundry tests | Stateless property verification, edge cases fuzzers miss |
| **Kontrol** | KEVM symbolic execution | Formal verification without new language |

### Tier 3: Frameworks & Glue

| Tool | Purpose |
|------|---------|
| **Chimera** (Recon) | Write-once-run-everywhere: single test suite works on Echidna + Medusa + Foundry + Halmos |
| **create-chimera-app** | Template project bootstrapping multi-fuzzer setup |
| **Recon VS Code Extension** | One-click setup, fuzzer integration, reproducer generation, coverage visualization |
| **Recon Pro** | Cloud fuzzing platform for unlimited runs |
| **fuzzlib** (Perimeter) | Utility library: assertions, clamping, ghost helpers, actor management |
| **crytic/properties** | 168 pre-built properties for ERC20/ERC721/ERC4626/ABDKMath64x64 |

### Tier 4: Complementary Tools

| Tool | Purpose |
|------|---------|
| **Slither** | Static analysis, feeds info to Echidna for better fuzzing |
| **Wake** | Python-based fuzzer with MGF (manually-guided fuzzing), 23+ vulns found |
| **Scribble** (Consensys) | Runtime verification annotations, used with Harvey fuzzer |
| **Vertigo** | Mutation testing — validates your test suite catches real bugs |

---

## 2. THE CHIMERA/RECON ECOSYSTEM (BEST-IN-CLASS)

### What Chimera Is

Chimera solves the critical problem: invariant tests written for one fuzzer don't work on others. Each tool has different assertion mechanisms, setup patterns, and cheatcode support. Chimera provides a unified abstraction layer.

### Architecture

```
Your Test Code
    |
    v
BaseSetup.sol        -- Deployment & initialization
BaseProperties.sol   -- Invariant definitions
BaseTargetFunctions.sol -- Handler functions (what fuzzers call)
Asserts.sol          -- Unified assertion interface
    |
    +---> CryticAsserts.sol    --> Echidna/Medusa
    +---> FoundryAsserts.sol   --> Foundry invariant testing
    +---> HalmosAsserts.sol    --> Halmos symbolic execution
    +---> Hevm.sol             --> Cheatcode abstraction
```

### Project Structure (create-chimera-app)

```
project/
├── src/                 # Target contracts
├── test/recon/          # All invariant testing code
│   ├── Setup.sol        # Deploy contracts, initialize state
│   ├── Properties.sol   # Invariant definitions (checked after every call)
│   ├── TargetFunctions.sol  # Handler functions fuzzers can call
│   ├── CryticTester.sol     # Echidna/Medusa entry point
│   └── CryticToFoundry.t.sol  # Foundry bridge
├── echidna.yaml         # Echidna config
├── medusa.json          # Medusa config
├── halmos.toml          # Halmos config
└── foundry.toml         # Foundry config (with [invariant] section)
```

### Running Tests Across All Fuzzers

```bash
# Echidna
echidna . --contract CryticTester --config echidna.yaml

# Medusa
medusa fuzz

# Foundry (unit test mode — reproduces fuzzer-found sequences)
forge test --match-contract CryticToFoundry -vv

# Foundry (invariant mode)
FOUNDRY_PROFILE=invariants forge test --match-contract CryticToFoundry -vv

# Halmos (symbolic)
halmos
```

### Key Limitation

Chimera only supports cheatcodes implemented by HEVM. Foundry-specific cheatcodes will break Echidna/Medusa compatibility. Medusa supports `etch` but Echidna does not.

### Recon VS Code Extension Workflow

1. One-click project setup (installs Chimera, creates template files)
2. Contract & function selection UI (pick which functions fuzzers should call)
3. Configure actor roles (user/admin) per function
4. Run Echidna/Medusa/Halmos from status bar
5. View coverage reports
6. Generate mocks via right-click
7. Convert fuzzer logs to reproducible Foundry tests (Log to Foundry tool)

---

## 3. FUZZER COMPARISON: WHICH TOOL FOR WHAT

### Head-to-Head Benchmarks (devdacian, 14 challenges)

| Scenario | Winner | Notes |
|----------|--------|-------|
| Simple invariants (1-4, 7) | Tie | All three equivalent |
| Token sale (multi-invariant) | **Medusa** | Broke both invariants immediately; Foundry/Echidna only broke one |
| Rarely false (extreme edge) | **Halmos/Certora** | All fuzzers failed; formal verification won |
| Complex DeFi (Omni Protocol) | **Medusa** | 2 invariants in 5min; Echidna sometimes 1; Foundry none |
| Simple speed | **Foundry** | Slightly faster on trivial cases |

### Practical Recommendations

- **Medusa**: Best overall for serious protocol security. Superior on complex multi-invariant scenarios. Go-based, parallel workers.
- **Echidna**: Best for optimization mode (maximize/minimize values), on-chain fork testing, established corpus management.
- **Foundry**: Best for developer-in-the-loop rapid iteration. Use for debugging and reproducing. Weakest on deep stateful exploration.
- **Halmos/Certora**: Use for properties where fuzzing fails — mathematical edge cases, stateless properties, proves things hold for ALL inputs (not just random samples).

### THE CORRECT STRATEGY: Use ALL of them via Chimera

Write once, run on Medusa (primary explorer), Echidna (secondary + optimization), Foundry (debugging + reproduction), Halmos (formal verification of critical properties).

---

## 4. INVARIANT CATEGORIES THAT ACTUALLY FIND BUGS

### Category Ranking by Bug-Finding Effectiveness

Based on analysis of 50+ real audit reports and bug bounties:

#### S-Tier: Almost Always Finds Something

1. **Solvency/Accounting Invariants** — "Does the protocol have enough assets to cover all claims?"
   - `totalAssets >= totalLiabilities`
   - `token.balanceOf(vault) >= cash`
   - `sum(userDeposits) == totalDeposits`
   - Found: Euler $196M, Cap Protocol M-01, Recon Finding #1

2. **Rounding Direction Invariants** — "Does rounding always favor the protocol?"
   - `previewDeposit(x) <= deposit(x)` (shares received)
   - `previewWithdraw(x) >= withdraw(x)` (shares burned)
   - `redeem(deposit(a)) <= a` (round-trip)
   - Found: Raft $3.6M, Recon Finding #2, 30+ audit findings

3. **Supply Conservation** — "Do all balances sum to totalSupply?"
   - `sum(balances[i]) == totalSupply()`
   - `totalBorrowed == sum(userDebts[i])`
   - Found: Optimism $2M infinite mint, 20+ protocols

#### A-Tier: Frequently Finds Bugs

4. **Health Factor / Liquidation Integrity**
   - "Healthy accounts stay healthy after non-liquidation operations"
   - "Unhealthy accounts can always be liquidated"
   - "Liquidation improves (never worsens) health factor"
   - Found: Cap Protocol L-01, 25+ lending protocols

5. **Monotonicity Invariants** — "What only goes one direction?"
   - Interest rate accumulator only increases
   - Fee growth globals only increase
   - `k` in AMM only increases (from fees)
   - Share price never decreases (absent loss events)
   - Found: Recon Finding #3, Euler I_INVARIANT_E

6. **Cap/Bound Enforcement**
   - "Total supply cannot exceed supply cap"
   - "Borrow amount cannot exceed borrow cap"
   - "Utilization ratio <= 100%"
   - Found: Recon Finding #2 (deposit cap bypass), Aave V3 Certora

#### B-Tier: Catches Specific Bug Classes

7. **State Machine Consistency**
   - "Reentrancy lock is always unlocked between transactions"
   - "Snapshot is reset after every action"
   - "Controller enabled iff liabilities exist"
   - Found: Euler BASE_INVARIANT_A/B

8. **Access Control Invariants**
   - "Only pool can mint/burn debt tokens"
   - "Operations require correct roles"
   - Found: $953.2M in losses (OWASP SC01:2025)

9. **ERC4626 Specification Compliance**
   - All 37 crytic/properties for ERC4626
   - Non-reverting view functions
   - Sender-independent preview functions
   - Round-trip properties (8 from Euler)

10. **Cross-Function Consistency**
    - "`debtOf` and `debtOfExact` maintain correct relationship"
    - "`maxWithdraw <= loaned + reserve`"
    - Preview functions approximate actual operations

#### C-Tier: Useful for Completeness

11. **Timestamp Invariants** — `lastUpdate <= block.timestamp`
12. **Fee Bounds** — `interestFee` within configured range
13. **Interest Rate Bounds** — rate within expected range
14. **Zero-State Invariants** — "No borrowers implies zero total debt"

---

## 5. REAL BUGS FOUND BY INVARIANT TESTING

### High-Value Finds

| Protocol | Bug | Severity | $ Impact | How Caught |
|----------|-----|----------|----------|------------|
| **Lending Protocol** (Recon) | Wrong rounding direction on deposits — new depositors got extra shares | Critical | Protocol insolvency | Solvency invariant: totalAssets >= totalShares * pricePerShare |
| **Staking Protocol** (Recon) | uint128 overflow on cumulative reward tracker after specific stake/unstake sequences | High | Permanent DoS | Overflow invariant on reward accumulator |
| **Staking Protocol** (Recon) | Deposits in same block as reward distribution received unearned rewards | High | Unfair distribution | Reward-per-token monotonicity invariant |
| **Cap Protocol** (Recon) | Agent health degrades after realizeRestakerInterest when rates decrease | Medium | Health manipulation | Property: health unchanged by interest realization |
| **Cap Protocol** (Recon) | Vault redeem always reverts (array init before population) | Medium | Complete DoS of redemptions | Functional testing of redeem path |
| **Cap Protocol** (Recon) | Permanent DoS with 18-decimal tokens at low supply | Low | Freeze mint/redeem | Extreme value testing: low supply + high decimals |
| **DeFi Protocol** (Recon) | Deposit cap bypass via cumulative rounding (1 wei per deposit, thousands of deposits) | Medium | Cap circumvention | Cap enforcement invariant across many operations |
| **Euler Vault Kit** | Comprehensive invariant suite with 50+ properties covering borrowing, liquidation, interest, tokens, vault | Preventive | $4M bounty program | Enigma Dark invariant suite |
| **Stax Finance** | Exploit reproduced with Echidna optimization mode | Critical | 321K xLP stolen | Profit maximization + historical state fork |
| **0x Protocol** | Vulnerability found via Echidna | — | — | Echidna campaign |
| **Balancer** | Vulnerability found via Echidna | — | — | Echidna campaign |

### Key Insight from Recon

> "The individual operations all used reasonable values. It was the specific SEQUENCE and TIMING that triggered the overflow." — This is why stateful fuzzing beats unit tests. No developer writes a test with 1000 stake/unstake operations in specific order.

### Why Unit Tests Miss These

Recon identified 5 categories unit tests never catch:
1. **State accumulation bugs** — rounding errors compound over thousands of operations
2. **Sequence-dependent bugs** — specific ordering of operations creates exploitable state
3. **Timing-dependent bugs** — same-block interactions, epoch boundaries
4. **Multi-actor interaction bugs** — combinations of different users' actions
5. **Edge case combinations** — low supply + high decimals + specific operation order

---

## 6. THE OPTIMAL WORKFLOW (WHAT TOP TEAMS DO)

### Recon's "Scientific Audit" Methodology

#### Phase 1: Standardize Scope
- Deploy the ENTIRE system under test
- Map all contracts, relationships, storage variables
- For external dependencies, deploy mocks returning SYMBOLIC values (any price, any balance, any return code)
- This tests protocol resilience across the full range of external scenarios

#### Phase 2: Enumerate Coverage Classes
Three types:
- **Non-reverting classes**: Successful execution paths (reachable states)
- **Assertion-breaking classes**: Invariant failures (bugs)
- **Revert-at-line-X classes**: Defensive check triggers

On a typical 3,000-line DeFi protocol: 500-2,000 coverage classes and 100-400 semantic classes. Manual review typically covers 60-70%. The remaining 30-40% (reached through unusual condition combinations) is where critical bugs hide.

#### Phase 3: Semantic Analysis
Identify:
- **Truncation classes**: Division and downcast boundaries
- **Overflow classes**: Multiplication, addition, shift boundaries
- **Reentrancy classes**: External call points with potential state inconsistency

#### Phase 4: Stateful Fuzzing Campaign
Using Chimera framework:
1. Write properties in Properties.sol
2. Write handlers in TargetFunctions.sol
3. Run Medusa (primary), Echidna (secondary)
4. Analyze coverage reports
5. Iterate: add handlers for uncovered paths, tighten invariants

### The Handler Pattern (Critical for Effectiveness)

Raw fuzzing = tons of reverts, wasted coverage. Handlers transform this:

```solidity
contract TargetFunctions is BaseTargetFunctions, Properties {

    function handler_deposit(uint256 amount, uint8 actorSeed) external {
        // 1. Bound inputs to meaningful ranges
        amount = fl.clamp(amount, 1, 1e24);

        // 2. Select actor
        address actor = _selectActor(actorSeed);

        // 3. Setup preconditions
        deal(address(token), actor, amount);
        vm.startPrank(actor);
        token.approve(address(vault), amount);

        // 4. Execute
        vault.deposit(amount, actor);
        vm.stopPrank();

        // 5. Track ghost state
        ghost_totalDeposited += amount;
        ghost_userDeposits[actor] += amount;
    }
}
```

### Ghost Variables (Essential for Deep Invariants)

Track state that the protocol itself doesn't store:

```solidity
// In handler
uint256 public ghost_depositSum;
uint256 public ghost_withdrawSum;
mapping(address => uint256) public ghost_userDeposits;
uint256 public ghost_lastSharePrice;
bool public ghost_hasWithdrawn;

// In properties
function property_solvency() public returns (bool) {
    return token.balanceOf(address(vault)) >= ghost_depositSum - ghost_withdrawSum;
}

function property_sharePriceNonDecreasing() public returns (bool) {
    uint256 current = vault.totalAssets() * 1e18 / vault.totalSupply();
    bool ok = current >= ghost_lastSharePrice;
    ghost_lastSharePrice = current;
    return ok;
}
```

### Foundry Configuration for Serious Hunting

```toml
[invariant]
runs = 5000        # Default 256 is far too low
depth = 500        # Default 15 is far too low
fail_on_revert = false
```

For Echidna:
```yaml
testLimit: 100000      # Or higher
seqLen: 100            # Sequence length
corpusDir: "corpus"    # Save corpus for resumable campaigns
testMode: assertion    # or "property"
```

---

## 7. ADVANCED TECHNIQUES WE SHOULD ADOPT

### 7.1 Guided Corpus Fuzzing

Both Echidna and Medusa save "coverage-increasing" call sequences to a corpus directory. This corpus persists between runs:

```yaml
# Echidna
corpusDir: "corpus/echidna"
```

**How it works**: The fuzzer saves any transaction sequence that covers new code. On next run, it loads these as seeds and mutates them. Over multiple campaigns, the corpus grows to explore deeper state spaces.

**Best practice**: Run overnight campaigns with large test limits. Save corpus. Next session, the fuzzer starts from where it left off.

### 7.2 Optimization Mode (Echidna)

Instead of checking boolean properties, ask Echidna to MAXIMIZE a value:

```solidity
function echidna_optimize_profit() public returns (int256) {
    return int256(attacker.balance) - int256(INITIAL_BALANCE);
}
```

Echidna will find the transaction sequence that maximizes attacker profit. This is how the Stax Finance exploit was reproduced automatically.

### 7.3 Multi-Actor Testing

Deploy multiple actors (users) with different roles:

```solidity
address[] actors = [USER1, USER2, USER3, ADMIN, ATTACKER];

function handler_deposit(uint256 amount, uint8 actorIndex) external {
    address actor = actors[actorIndex % actors.length];
    vm.prank(actor);
    vault.deposit(bound(amount, 1, 1e24), actor);
}
```

This discovers bugs from interactions between different users that single-actor testing misses.

### 7.4 Differential Testing

Compare two implementations of the same logic:

```solidity
function property_differential() public returns (bool) {
    uint256 resultA = vault.convertToShares(1e18);
    uint256 resultB = referenceImpl.convertToShares(1e18);
    return resultA == resultB; // or within tolerance
}
```

Useful for: upgraded contracts, alternative math libraries, spec vs implementation.

### 7.5 Mutation Testing

Tools like Vertigo systematically modify source code (flip operators, change constants) and verify your test suite catches each mutation. If a mutation survives (tests still pass), your invariants are incomplete.

**Purpose**: Validates the quality of your invariant suite itself.

### 7.6 Conditional / Stateful Invariants

Some properties only hold in certain states:

```solidity
function property_zeroDebtImpliesZeroBorrowers() public returns (bool) {
    if (ghost_activeBorrowers == 0) {
        return vault.totalBorrowed() == 0;
    }
    return true; // vacuously true when borrowers exist
}
```

### 7.7 "Doomsday" Invariants

Properties that should NEVER break under any circumstances:

```solidity
// From Cap Protocol
function doomsday_debt_token_solvency() public returns (bool) {
    return debtToken.balanceOf(address(vault)) >= reserve.totalDebt();
}
```

These are your highest-priority invariants. Name them distinctly.

### 7.8 Semantic Coverage Classes (Recon "Magic")

Automatically identify critical boundaries via static analysis:
- **Truncation points**: Every division and downcast
- **Overflow points**: Every multiplication and addition
- **Reentrancy points**: Every external call with pre/post state inconsistency

Then write targeted invariants for each class.

---

## 8. FORMAL VERIFICATION LAYER

### Certora (CVL)

**What it does**: Proves properties hold for ALL possible inputs and states, not just random samples.

**Invariant syntax**:
```cvl
invariant totalSupplyIsSumOfBalances()
    to_mathint(totalSupply()) == g_sumOfBalances;

invariant healthyAccountStaysHealthy(address user)
    healthFactor(user) >= 1e18
    { preserved { requireInvariant totalSupplyIsSumOfBalances(); } }
```

**Key features**:
- Preserved blocks: add preconditions for proving invariants
- Ghost variables in CVL
- Inductive verification
- 17-lesson tutorial course available

**When to use**: Mathematical properties (sum of balances = totalSupply), access control (only pool can mint), bounds proofs.

**Real bugs found**: Uniswap v4 malicious hooks, rounding errors in multiple protocols, infiniFi redemption logic.

### Halmos

**What it does**: Symbolic execution on Foundry tests. Write regular Foundry tests, Halmos explores ALL paths.

**When to use**: Stateless properties where fuzzing failed (devdacian Challenge 6 — "Rarely False").

### Kontrol

**What it does**: KEVM-based formal verification, works with existing Foundry tests.

**When to use**: When you want formal guarantees without learning CVL.

### Practical Integration

```
Invariant Suite
    |
    +---> Medusa/Echidna: Stateful exploration (finds sequence-dependent bugs)
    +---> Halmos: Symbolic verification of stateless properties
    +---> Certora: Mathematical proof of critical invariants
```

---

## 9. PROPERTY LIBRARIES & CHECKLISTS WE NEED

### Available Property Libraries

| Library | Properties | Coverage |
|---------|-----------|----------|
| **crytic/properties** | 168 | ERC20 (25), ERC721 (19), ERC4626 (37), ABDKMath (106) |
| **Euler InvariantsSpec** | 50+ | Base, Token, Vault, ERC4626, Borrowing, Interest, Liquidation |
| **Cap Protocol suite** | 100 | Solvency, Monotonicity, Health, Borrow, Delegation, Staking, Rewards |
| **Our defi-invariant-catalog.md** | ~288 | Token, Vault, Lending, DEX, Staking, Bridge, Governance, ZK |
| **Our top-30 research** | 30 | Ranked by real-world frequency across 50+ protocols |

### Libraries We DON'T Have Yet (Should Build/Adopt)

1. **Protocol-specific property templates** for common DeFi patterns:
   - CDP/Stablecoin (MakerDAO pattern): collateral ratio, liquidation, debt ceiling
   - Perpetuals/Derivatives: funding rate, mark vs index price, position accounting
   - Restaking protocols: delegation accounting, slash handling, reward distribution
   - Orderbook DEX: order matching integrity, fee extraction, position limits

2. **Recon's lending protocol design patterns** (from their blog):
   - Solvency patterns (20 properties)
   - Health/Liquidation patterns (12 properties)
   - Interest accrual patterns
   - Borrow cap patterns

3. **Semantic class templates**:
   - Truncation boundary invariants (for every division in protocol)
   - Overflow boundary invariants (for every multiplication)
   - Reentrancy surface invariants (for every external call)

---

## 10. GAP ANALYSIS: WHAT WE HAVE vs WHAT WE NEED

### What We Have (Strong Foundation)

- 288 invariants in defi-invariant-catalog.md (comprehensive)
- Top 30 invariant failures research (frequency-ranked)
- Knowledge base from 8 leading repositories
- Real-world reports database
- 3-phase framework (Extract → Attack → Verify)
- Foundry configuration and handler patterns documented
- Understanding of ghost variables and handler-based testing

### What We're Missing (Critical Gaps)

| Gap | Impact | Fix |
|-----|--------|-----|
| **No Chimera integration** | Can only run Foundry, missing Medusa's superior exploration | Install Chimera, adopt create-chimera-app template |
| **No Medusa** | Missing the best fuzzer for complex invariants | `go install github.com/crytic/medusa@latest` |
| **No Echidna optimization mode** | Missing profit-maximization attack discovery | Add optimization properties |
| **No corpus persistence** | Each fuzzing session starts from scratch | Configure corpusDir, run overnight campaigns |
| **No multi-actor handlers** | Missing cross-user interaction bugs | Add actor selection to handlers |
| **No semantic class analysis** | Missing truncation/overflow boundary testing | Implement Recon's semantic class methodology |
| **No formal verification** | Properties only tested on random inputs | Add Halmos for critical stateless properties |
| **No mutation testing** | Can't validate our invariant suite quality | Evaluate Vertigo or equivalent |
| **No Recon VS Code extension** | Missing productivity tooling | Install extension |
| **No cloud fuzzing** | Limited by local compute | Evaluate Recon Pro for overnight campaigns |
| **No fuzzlib integration** | Missing utility helpers (clamping, assertions, actor mgmt) | Install perimetersec/fuzzlib |
| **Invariants are documentation, not code** | 288 invariants exist on paper but not as runnable tests | Systematically convert to Chimera test suites |

---

## 11. IMPLEMENTATION PLAN

### Phase 1: Tooling Setup (Day 1)

```bash
# Install Medusa
go install github.com/crytic/medusa@latest

# Install Echidna (if not present)
# brew install echidna  (or download from GitHub releases)

# Create new invariant testing workspace
forge init --template https://github.com/Recon-Fuzz/create-chimera-app invariant-workspace

# Install fuzzlib
cd invariant-workspace
forge install perimetersec/fuzzlib

# Install crytic/properties
forge install crytic/properties

# Install Recon VS Code extension
# (from VS Code marketplace)

# Install Halmos
pip install halmos
```

### Phase 2: Convert Top-30 Invariants to Code (Week 1)

Priority order (by bug-finding frequency):
1. Vault share inflation / first depositor (SOLODIT-001)
2. Rounding direction consistency (SOLODIT-005)
3. Supply conservation (SOLODIT-009)
4. Solvency invariants (from Euler spec + Cap Protocol)
5. Health factor / liquidation integrity (SOLODIT-006, 014)
6. Monotonicity (interest, fee growth, share price)
7. ERC4626 round-trip properties (all 8 from Euler)
8. Cap/bound enforcement
9. Reward distribution accuracy
10. Flash loan manipulation resistance

### Phase 3: Build Reusable Handler Templates (Week 2)

For each DeFi category, create a handler template:

```
handlers/
├── LendingHandler.sol     # deposit, borrow, repay, liquidate, withdraw
├── VaultHandler.sol       # deposit, mint, redeem, withdraw (ERC4626)
├── DEXHandler.sol         # swap, addLiquidity, removeLiquidity
├── StakingHandler.sol     # stake, unstake, claim, distribute
├── BridgeHandler.sol      # send, receive, relay, challenge
└── GovernanceHandler.sol  # propose, vote, execute, cancel
```

Each handler includes:
- Input bounding
- Multi-actor support
- Ghost variable tracking
- Pre/post condition checks

### Phase 4: Establish Campaign Workflow (Ongoing)

For each new bounty target:

```
1. Clone target → forge install Recon-Fuzz/chimera
2. Setup.sol: Deploy all contracts with realistic state
3. TargetFunctions.sol: Write handlers using templates
4. Properties.sol: Select relevant invariants from our catalog
5. Run Medusa (1 hour initial) → analyze coverage
6. Add handlers for uncovered paths
7. Run Medusa + Echidna (overnight with corpus persistence)
8. Run Halmos on critical stateless properties
9. Review breaking sequences → convert to PoC
10. Devil's advocate validation → submit if >50% confidence
```

### Phase 5: Continuous Improvement

- After each bounty: add any new invariant patterns discovered
- Build protocol-specific property libraries (perpetuals, restaking, orderbook)
- Evaluate Recon Pro for cloud campaigns
- Track metrics: invariants run, bugs found, false positive rate, coverage %

---

## KEY TAKEAWAYS

### The 5 Things That Matter Most

1. **Use Medusa as primary fuzzer, not just Foundry** — Medusa finds 2x more bugs on complex protocols (devdacian benchmarks). Foundry is weakest on deep stateful exploration.

2. **Adopt Chimera for write-once-run-everywhere** — Write one invariant suite, run it on Medusa + Echidna + Foundry + Halmos. Different tools find different bugs.

3. **Handlers are everything** — Raw fuzzing wastes 90%+ of calls on reverts. Well-designed handlers with input bounding, actor management, and ghost variables are what make fuzzing actually work.

4. **Persist your corpus** — Each overnight campaign builds on previous discoveries. Never start from scratch. This is the single biggest multiplier for fuzzing effectiveness.

5. **The bugs that pay are sequence-dependent** — Unit tests check single operations. The real bugs are "deposit + wait + borrow + liquidate + withdraw" with specific values and timing. Only stateful fuzzing finds these. Focus on multi-step invariants.

### The Invariant Hierarchy

```
CRITICAL (always check):
├── Solvency: protocol assets >= protocol liabilities
├── Conservation: sum(balances) == totalSupply
├── Round-trip: redeem(deposit(x)) <= x (no free money)
└── Rounding: always favors protocol, never user

HIGH (usually finds something):
├── Monotonicity: indices/accumulators only increase
├── Health: healthy accounts stay healthy
├── Caps: limits cannot be exceeded
└── Liquidation: always possible when required

MEDIUM (catches specific classes):
├── State machine: locks, flags, modes consistent
├── Access control: only authorized callers
├── Specification: ERC4626/ERC20 compliance
└── Cross-function: related getters are consistent

USEFUL (completeness):
├── Timestamps: lastUpdate <= block.timestamp
├── Bounds: rates/fees within configured ranges
├── Zero-state: no borrowers = no debt
└── Conditional: state-dependent properties
```

---

## APPENDIX A: Euler Vault Kit Complete Invariant Spec

(For reference — this is what a $4M-bounty-grade invariant suite looks like)

- BASE_INVARIANT_A: reentrancyLock == UNLOCKED
- BASE_INVARIANT_B: snapshot reset after every action
- TM_INVARIANT_A: totalSupply == sum(minted shares) + accumulated fees
- TM_INVARIANT_B: balanceOf(actor) == all shares owned
- TM_INVARIANT_C: totalSupply == sum(all balances) + fees
- VM_INVARIANT_A: underlying.balanceOf(vault) >= cash
- VM_INVARIANT_B: totalSupply increase <= supply cap
- VM_INVARIANT_C: totalAssets == 0 iff totalSupply == 0
- ERC4626: 16 invariants (non-revert, rounding, sender-independence, functional)
- ERC4626 ROUNDTRIP: 8 invariants (A-H covering all deposit/withdraw/mint/redeem combos)
- BM_INVARIANT_A-P: 16 borrowing invariants (total >= individual, sum correctness, health checks, cap enforcement, repayability)
- I_INVARIANT_A-E: 5 interest invariants (fee bounds, timestamp, monotonicity)
- LM_INVARIANT_A-D: 4 liquidation invariants (only unhealthy, exchange rate, health degradation)

Total: ~50 core invariants organized across 6 modules.

## APPENDIX B: Cap Protocol Complete Property List (100 Properties)

Categories:
- Solvency & Accounting: 20 properties
- Monotonicity: 3 properties
- Health & Liquidation: 12 properties
- Borrow: 6 properties
- Delegation: 10 properties
- Deposit/Withdraw: 8 properties
- Vault Operations: 10 properties
- Rewards & Staking: 8 properties
- Edge Cases: 12 properties
- System-Level: 11 properties

## APPENDIX C: Quick Reference — Running Multi-Fuzzer Campaign

```bash
# 1. Setup (once)
forge init --template https://github.com/Recon-Fuzz/create-chimera-app
forge install perimetersec/fuzzlib
forge install crytic/properties
forge build

# 2. Write tests in test/recon/
# Properties.sol + TargetFunctions.sol + Setup.sol

# 3. Quick validation (5 min)
medusa fuzz --test-limit 10000

# 4. Deep campaign (overnight)
medusa fuzz --test-limit 1000000 &
echidna . --contract CryticTester --config echidna.yaml &

# 5. Symbolic verification of critical properties
halmos --function check_solvency --loop 10

# 6. Debug any failures
forge test --match-contract CryticToFoundry -vvvv

# 7. Generate reproducible PoC
# Use Recon VS Code extension "Log to Foundry" converter
```
