#!/usr/bin/env python3
"""
Hybrid LLM + Formal Verification Pipeline
============================================
Combines Claude Code (LLM) with Foundry/Slither/Echidna/Certora for
systematic smart contract bug hunting.

Architecture (inspired by SymGPT + PropertyGPT + LLAMA):
  Step 1: LLM reads code -> extracts invariants
  Step 2: LLM generates Foundry invariant tests
  Step 3: forge test --fuzz to try breaking invariants
  Step 4: LLM analyzes failures -> generates exploit PoC
  Step 5: LLM writes bounty report

Also includes differential analysis pipeline:
  Step 1: git diff between last audit and HEAD
  Step 2: LLM identifies what changed and WHY
  Step 3: LLM generates hypotheses about new bugs
  Step 4: Targeted verification per hypothesis

Usage:
  # Full pipeline on a contract directory
  python hybrid_pipeline.py --target ./contracts/euler-vault-kit/src --domain defi-lending

  # Differential analysis
  python hybrid_pipeline.py --diff --repo ./contracts/euler-vault-kit --from-tag audit-v1 --to-tag HEAD

  # Just generate invariant tests
  python hybrid_pipeline.py --target ./contracts/euler-vault-kit/src --step invariant-tests

  # Just run and analyze fuzz results
  python hybrid_pipeline.py --target ./contracts/euler-vault-kit/src --step analyze-fuzz
"""

import argparse
import json
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# PROMPT TEMPLATES — copy-pasteable for Claude Code / any LLM
# ---------------------------------------------------------------------------

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: INVARIANT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

STEP1_INVARIANT_EXTRACTION = """
You are a formal verification specialist analyzing a smart contract protocol.
Your goal is to extract EVERY invariant this protocol depends on, formatted so
they can be directly translated into Foundry invariant tests and Certora rules.

You will receive all source code for the protocol.

TASK: Extract invariants in THREE tiers.

## TIER 1: GLOBAL INVARIANTS (must hold after EVERY state-changing tx)

These are the properties a fuzzer should check after every random call sequence.
Express each as a Solidity boolean expression that can go inside a function:

Format:
```
GLOBAL-[N]: [human description]
Solidity: assert([expression]);
Contracts: [which contracts this spans]
Financial impact if violated: [what an attacker gains]
```

Examples of what to look for:
- Total shares * price per share <= total assets (no value creation)
- sum(user balances) == total supply (conservation)
- contract token balance >= total tracked deposits (solvency)
- No user can have negative effective balance
- Protocol fee accumulator only increases
- Collateral ratio >= minimum for every position
- Total debt <= total supplied (lending)

## TIER 2: TRANSITION INVARIANTS (must hold across specific operations)

These check that a specific function does what it claims.
Express as before/after assertions:

Format:
```
TRANS-[N]: [human description]
Function: [contract.function]
Before: [state snapshot expression]
After: assert([relationship between before and after]);
```

Examples:
- After deposit(X): user_shares_after >= user_shares_before (monotonic)
- After withdraw(X): contract_balance_before - contract_balance_after == X (exact)
- After liquidate: violator health factor improves
- After swap: constant_product_after >= constant_product_before (no leakage)

## TIER 3: RELATIONAL INVARIANTS (relationships between contracts/modules)

Format:
```
REL-[N]: [human description]
Contracts: [A, B]
Relationship: assert([expression involving state from both]);
```

Examples:
- Vault total assets == sum of all strategy allocations
- Bridge source locked == bridge destination minted
- Oracle reported price within X% of TWAP

## IMPLICIT INVARIANTS (HIGHEST VALUE)

For each explicit invariant above, ask: "What related property is ASSUMED but
NEVER asserted in the code?" These implicit invariants are where 80% of bounty-
worthy bugs hide. Flag them with [IMPLICIT] tag.

## OUTPUT CONSTRAINTS

- Express every invariant as a runnable Solidity `assert()` or `require()`
- Include the exact storage slot / variable names from the actual code
- For math invariants, specify rounding direction tolerance
- Number sequentially: GLOBAL-1, GLOBAL-2, TRANS-1, etc.
- Target: 10-30 global, 5-15 per major function, 5-10 relational
- Mark priority: P0 (breaks solvency), P1 (loses user funds), P2 (incorrect accounting), P3 (griefing)

SOURCE CODE:
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: FOUNDRY INVARIANT TEST GENERATION
# ═══════════════════════════════════════════════════════════════════════════

STEP2_INVARIANT_TEST_GEN = """
You are a Foundry test engineer. You write production-quality invariant tests
that catch real bugs, not toy examples.

You will receive:
1. The invariant list from the previous step
2. The original source code

YOUR TASK: Generate a complete, COMPILABLE Foundry invariant test suite.

## ARCHITECTURE

Generate THREE test files:

### File 1: `InvariantGlobal.t.sol` — Global invariants
Uses Foundry's built-in invariant testing. The fuzzer calls random sequences
of target functions, and after each sequence, ALL invariant_* functions run.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
// [import target contracts]

contract InvariantGlobal is StdInvariant, Test {{
    // --- DEPLOY & SETUP ---
    function setUp() public {{
        // Deploy all contracts
        // Set initial state (deposit some funds, create positions, etc.)
        // CRITICAL: Set up targetContract() for the fuzzer
        targetContract(address(targetProtocol));
        // Optionally restrict which functions the fuzzer calls:
        // bytes4[] memory selectors = new bytes4[](3);
        // selectors[0] = targetProtocol.deposit.selector;
        // selectors[1] = targetProtocol.withdraw.selector;
        // selectors[2] = targetProtocol.transfer.selector;
        // targetSelector(FuzzSelector({{
        //     addr: address(targetProtocol),
        //     selectors: selectors
        // }}));
    }}

    // --- GLOBAL INVARIANTS ---
    // Each function prefixed with `invariant_` runs after every fuzz sequence

    function invariant_solvency() public view {{
        // GLOBAL-1: Contract holds enough tokens to cover all claims
        // assert(token.balanceOf(address(vault)) >= vault.totalAssets());
    }}

    function invariant_share_conservation() public view {{
        // GLOBAL-2: Total shares are consistent
        // assert(vault.totalSupply() == sum_of_all_user_shares);
    }}

    // [Add one function per GLOBAL invariant from Step 1]
}}
```

### File 2: `InvariantTransition.t.sol` — Per-function transition checks
Uses Foundry fuzz tests (not invariant mode) to verify before/after properties.

```solidity
contract InvariantTransition is Test {{
    function setUp() public {{ /* deploy */ }}

    function test_deposit_increases_shares(uint256 amount) public {{
        amount = bound(amount, 1, type(uint128).max);
        // Snapshot before
        uint256 sharesBefore = vault.balanceOf(user);
        uint256 totalBefore = vault.totalAssets();

        // Action
        vm.prank(user);
        vault.deposit(amount, user);

        // Verify TRANS-1: shares increase
        assertGe(vault.balanceOf(user), sharesBefore, "TRANS-1: shares must increase on deposit");

        // Verify TRANS-2: total assets increase by exactly deposit amount
        assertEq(vault.totalAssets(), totalBefore + amount, "TRANS-2: totalAssets must increase by deposit");
    }}

    // [Add one test per TRANS invariant from Step 1]
}}
```

### File 3: `InvariantEconomic.t.sol` — Economic attack simulations
Guided fuzz tests that simulate specific attack patterns.

```solidity
contract InvariantEconomic is Test {{
    function setUp() public {{ /* deploy */ }}

    function test_no_inflation_attack(uint256 donationAmount, uint256 depositAmount) public {{
        donationAmount = bound(donationAmount, 1, 1000 ether);
        depositAmount = bound(depositAmount, 1, 1000 ether);

        // Attacker donates to inflate share price
        vm.prank(attacker);
        token.transfer(address(vault), donationAmount);

        // Victim deposits
        uint256 victimShares = vault.previewDeposit(depositAmount);

        // INVARIANT: victim must receive > 0 shares for any nonzero deposit
        assertGt(victimShares, 0, "ECON-1: inflation attack - victim gets 0 shares");

        // INVARIANT: victim can withdraw at least depositAmount - 1 (rounding)
        uint256 victimCanRedeem = vault.previewRedeem(victimShares);
        assertGe(victimCanRedeem, depositAmount - 1, "ECON-2: victim loses funds to inflation");
    }}

    function test_no_sandwich_profit(uint256 frontrunAmount) public {{
        frontrunAmount = bound(frontrunAmount, 1 ether, 10000 ether);

        // Snapshot attacker balance
        uint256 attackerBefore = token.balanceOf(attacker);

        // Front-run: attacker deposits
        vm.prank(attacker);
        uint256 shares = vault.deposit(frontrunAmount, attacker);

        // Victim transaction
        vm.prank(victim);
        vault.deposit(100 ether, victim);

        // Back-run: attacker withdraws
        vm.prank(attacker);
        uint256 received = vault.redeem(shares, attacker, attacker);

        // INVARIANT: attacker should not profit from sandwich
        assertLe(received, frontrunAmount, "ECON-3: sandwich attack profitable");
    }}
}}
```

## CRITICAL REQUIREMENTS

1. **MUST COMPILE**: Use exact contract names, function signatures, and types from the source code. Do NOT guess interfaces.
2. **MUST USE `bound()`**: Never use raw fuzz inputs. Always bound to valid ranges.
3. **MUST SET UP REALISTIC STATE**: Deploy with realistic parameters, fund accounts, create initial positions.
4. **MUST TARGET RIGHT CONTRACTS**: Use `targetContract()` to tell the fuzzer which contracts to call.
5. **USE `deal()` for funding**: `deal(address(token), user, amount)` to set ERC20 balances.
6. **HANDLER PATTERN for complex protocols**: If the protocol has complex call sequences, create a Handler contract that wraps valid call sequences:

```solidity
contract Handler is Test {{
    Protocol protocol;

    constructor(Protocol _protocol) {{ protocol = _protocol; }}

    function deposit(uint256 amount) external {{
        amount = bound(amount, 1, 1e24);
        deal(address(token), msg.sender, amount);
        vm.prank(msg.sender);
        protocol.deposit(amount);
    }}
    // ... other wrapped functions
}}
```

## foundry.toml additions needed:
```toml
[invariant]
runs = 256
depth = 50
fail_on_revert = false
shrink_run_limit = 5000
```

INVARIANT LIST FROM STEP 1:
{invariants}

SOURCE CODE:
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: FUZZ RESULT ANALYSIS (run after `forge test --fuzz`)
# ═══════════════════════════════════════════════════════════════════════════

STEP3_FUZZ_ANALYSIS = """
You are a smart contract security researcher analyzing fuzzer output. The fuzzer
has been running invariant tests and some have FAILED. Your job is to determine
if each failure represents a REAL exploitable vulnerability or a test setup issue.

## FOR EACH FAILURE, DO THIS:

### 1. EXTRACT THE COUNTEREXAMPLE
The fuzzer provides a call sequence that breaks the invariant. Extract:
- The exact sequence of function calls
- The exact parameters for each call
- The final state that violated the invariant
- The shrunk (minimal) counterexample if available

### 2. REPLAY MENTALLY
Walk through the counterexample step by step against the actual source code:
- What is the state after each call?
- Where exactly does the invariant break?
- Is this a real code path or a test setup artifact?

### 3. CLASSIFY
- **REAL BUG**: The code has a logic error. The invariant violation translates to
  a concrete financial impact (theft, lock, grief).
- **TEST ARTIFACT**: The test setup is wrong (missing approvals, wrong deployment
  order, unrealistic parameters). Fix the test, not the code.
- **KNOWN LIMITATION**: The protocol knows about this and documents it as a known
  issue or accepted trade-off.
- **ROUNDING**: The invariant is violated by 1-2 wei due to rounding. Check if
  this compounds over many operations to become material.

### 4. FOR REAL BUGS: ESCALATE
Output a structured finding:
```
FINDING: [title]
Invariant: [which one was violated]
Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Counterexample: [the minimal call sequence]
Root cause: [exact line of code and why it's wrong]
Impact: [quantified financial impact]
Confidence: [HIGH/MEDIUM/LOW]
```

### 5. FOR ROUNDING ISSUES: COMPOUND TEST
If a rounding error of N wei occurs per operation, calculate:
- After 1000 operations: N * 1000 wei lost
- With high-value tokens (WBTC, 8 decimals): is N significant?
- Can an attacker amplify this via loops or flash loans?
- If cumulative loss > $100, it's likely a valid MEDIUM.

FUZZER OUTPUT:
{fuzz_output}

INVARIANT DEFINITIONS:
{invariants}

SOURCE CODE:
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: EXPLOIT POC GENERATION
# ═══════════════════════════════════════════════════════════════════════════

STEP4_EXPLOIT_POC = """
You are a Foundry exploit developer. You take validated bug findings and
produce COMPILABLE, RUNNABLE Foundry test PoCs that prove the vulnerability.

For each finding, generate a COMPLETE test file.

## REQUIREMENTS

1. The test MUST compile. Use exact function signatures from the source.
2. The test MUST fork mainnet if the contracts are deployed. Use:
   `vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);`
3. The test MUST have clear BEFORE/AFTER assertions showing the invariant violation.
4. The test MUST calculate attacker profit vs cost.
5. The test MUST be runnable with: `forge test --match-test test_exploit -vvvv`

## TEMPLATE

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{Test, console2}} from "forge-std/Test.sol";

// Minimal interfaces — only include functions actually called
interface IVault {{
    // [exact signatures from source code]
}}

contract Exploit_[BugName] is Test {{
    // Deployed addresses (if forking)
    address constant VAULT = 0x...;
    address constant TOKEN = 0x...;
    uint256 constant FORK_BLOCK = 12345678;

    // Actors
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {{
        // Fork at specific block for reproducibility
        vm.createSelectFork(vm.envString("ETH_RPC_URL"), FORK_BLOCK);

        // Or deploy locally:
        // Token token = new Token();
        // Vault vault = new Vault(address(token));
    }}

    function test_exploit() public {{
        // ═══ SNAPSHOT BEFORE ═══
        uint256 attackerBefore = IERC20(TOKEN).balanceOf(attacker);
        uint256 vaultBefore = IERC20(TOKEN).balanceOf(VAULT);
        console2.log("Vault TVL before:", vaultBefore);
        console2.log("Attacker balance before:", attackerBefore);

        // ═══ EXPLOIT EXECUTION ═══
        vm.startPrank(attacker);

        // Step 1: [describe]
        // Step 2: [describe]
        // Step 3: [describe]

        vm.stopPrank();

        // ═══ SNAPSHOT AFTER ═══
        uint256 attackerAfter = IERC20(TOKEN).balanceOf(attacker);
        uint256 vaultAfter = IERC20(TOKEN).balanceOf(VAULT);
        console2.log("Vault TVL after:", vaultAfter);
        console2.log("Attacker balance after:", attackerAfter);

        // ═══ PROOF ═══
        uint256 profit = attackerAfter - attackerBefore;
        uint256 vaultLoss = vaultBefore - vaultAfter;
        console2.log("Attacker profit:", profit);
        console2.log("Vault loss:", vaultLoss);

        assertGt(profit, 0, "Attacker must profit");
        assertGt(vaultLoss, 0, "Vault must lose funds");
    }}
}}
```

## ADDITIONAL PATTERNS

For flash loan exploits, include a helper contract with the flash loan callback.
For reentrancy, include the attack contract with receive()/fallback().
For governance attacks, use vm.roll() and vm.warp() to advance time.
For oracle manipulation, manipulate the oracle and show the downstream impact.

FINDINGS TO GENERATE POC FOR:
{findings}

SOURCE CODE:
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: BOUNTY REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════

STEP5_REPORT = """
You are a bug bounty report writer. You write reports that WIN payouts. You've
studied hundreds of winning reports from Immunefi, Code4rena, and Cantina.

For each validated finding with a working PoC, generate a platform-ready report.

## IMMUNEFI FORMAT (for direct bounty programs)

```markdown
# [Concise Title — Bug Type in Protocol Component]

## Bug Description

[2-3 paragraphs explaining the vulnerability:
- What is the intended behavior?
- What actually happens?
- What is the root cause in the code?]

## Impact

[Quantified impact — dollar amounts, percentages, affected users.
Frame as "direct loss of funds" whenever possible — Immunefi's highest tier.]

Severity: [Critical/High/Medium/Low] per Immunefi's impact scale:
- Critical: Direct theft or permanent freezing of funds
- High: Theft of unclaimed yield, permanent DoS, or governance manipulation
- Medium: Theft that requires specific conditions, or griefing with material loss
- Low: Informational or minor impact

## Risk Breakdown
- Difficulty: [Low/Medium/High — how hard is it to execute?]
- Likelihood: [Low/Medium/High — how likely is the precondition?]

## Proof of Concept

[Complete, runnable Foundry test from Step 4]

### How to reproduce:
1. Clone the repository: `git clone [repo]`
2. Install dependencies: `forge install`
3. Create test file: `test/poc/Exploit.t.sol`
4. Run: `forge test --match-test test_exploit --fork-url $RPC_URL -vvvv`
5. Expected output: [describe what the successful exploit shows]

## Recommendation

[Specific code fix — show the exact diff:
```diff
- uint256 shares = amount * totalSupply / totalAssets;
+ uint256 shares = amount.mulDiv(totalSupply, totalAssets, Math.Rounding.Down);
+ require(shares > 0, "zero shares");
```
]

## References

[Similar past exploits, audit findings, or academic papers]
```

## CODE4RENA FORMAT

```markdown
# [H-01] [Title]

## Summary
[1-2 sentences]

## Vulnerability Detail
[Full technical explanation with code references]

## Impact
[Frame as HIGH: direct theft/loss, or MEDIUM: conditional loss]

## Code Snippet
[Link to specific lines in the repo]

## Tool used
Manual Review + Foundry Invariant Testing

## Recommendation
[Specific fix with code diff]

## Proof of Concept
[Foundry test]
```

## REPORT QUALITY CHECKLIST

Before finalizing each report, verify:
- [ ] Title is specific (not "Reentrancy vulnerability" but "Reentrancy in withdraw() allows draining vault via ERC777 callback")
- [ ] Impact is quantified with numbers
- [ ] Root cause points to exact code line
- [ ] PoC compiles and runs
- [ ] Fix is specific code change, not "add a check"
- [ ] No admin/governance actions required for exploit
- [ ] Not a known issue or previous audit finding

FINDINGS WITH POCS:
{findings}

TARGET PLATFORM: {platform}
"""

# ═══════════════════════════════════════════════════════════════════════════
# DIFFERENTIAL ANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

DIFF_STEP1_IDENTIFY_CHANGES = """
You are a smart contract security researcher performing differential analysis.
You are comparing the code BEFORE (last audited version) with AFTER (current HEAD).

Your goal: identify every change that could introduce a new vulnerability.

## ANALYSIS FRAMEWORK

### 1. CATEGORIZE EACH CHANGE

For every modified file/function, classify:

- **NEW CODE**: Entirely new contract or function. HIGHEST PRIORITY — never been
  audited. Focus 50% of effort here.
- **MODIFIED LOGIC**: Existing function with changed logic (not just refactoring).
  HIGH PRIORITY — the change might break an invariant the old code maintained.
- **MODIFIED PARAMETERS**: Changed constants, thresholds, addresses, fee rates.
  MEDIUM PRIORITY — can break economic invariants.
- **REFACTORED**: Same logic, different structure (renamed variables, extracted
  functions, code reorganization). LOW PRIORITY but verify equivalence.
- **DEPENDENCY UPDATE**: Updated external library or interface. MEDIUM PRIORITY —
  new version might behave differently.
- **REMOVED CODE**: Deleted checks, functions, or contracts. HIGH PRIORITY —
  was the removed code a safety check?

### 2. FOR EACH NON-TRIVIAL CHANGE

Answer:
a) What WAS the old behavior?
b) What IS the new behavior?
c) WHY was this changed? (commit message, PR description, comments)
d) What invariants from the old code MIGHT this change violate?
e) Does this change interact with other changes in this diff?

### 3. GENERATE HYPOTHESES

For each change, generate 1-3 hypotheses about how it could be buggy:

Format:
```
HYPOTHESIS-[N]:
Change: [file:function, brief description]
Theory: [how this change could introduce a bug]
Attack: [concrete attack scenario if theory is correct]
Verify: [exact test or check to confirm/deny]
Priority: [P0/P1/P2 based on financial impact]
```

### 4. CROSS-CHANGE INTERACTIONS

The most dangerous bugs come from interactions between changes that are
individually correct. For every pair of related changes, ask:
- Did change A assume something that change B invalidates?
- Do these changes modify the same state in different ways?
- Is there a call path that goes through both changed functions?

GIT DIFF:
{diff}

PREVIOUS AUDIT REPORT (if available):
{previous_audit}
"""

DIFF_STEP2_HYPOTHESIS_VERIFICATION = """
You are verifying a specific hypothesis about a potential bug introduced by
a code change. You must either CONFIRM the hypothesis with a concrete exploit
path, or REJECT it with evidence.

## VERIFICATION PROTOCOL

### STEP A: Understand the hypothesis
Restate: "The hypothesis claims that [X change] could enable [Y attack] because [Z reason]."

### STEP B: Trace the code path
Starting from the changed code, trace the EXACT execution path an attacker would take:
1. Entry point (which function, which contract)
2. Parameters the attacker provides
3. Every line that executes (quote the actual code)
4. State before and after each critical operation
5. The exact point where the invariant would be violated

### STEP C: Check for guards
Exhaustively check if the attack is blocked:
- require/revert/assert statements in the path
- Modifiers (reentrancy guards, access control, pause)
- Upstream validation that constrains the parameters
- Other contracts that would revert
- Economic constraints (would the attack cost more than it gains?)

### STEP D: Verdict

If CONFIRMED:
```
STATUS: CONFIRMED
Attack path: [step by step]
Root cause: [exact line]
Impact: [quantified]
PoC needed: [describe what the PoC should demonstrate]
```

If REJECTED:
```
STATUS: REJECTED
Blocked by: [exact code reference]
Reason: [why the attack fails]
```

If UNCERTAIN:
```
STATUS: NEEDS TESTING
Reason: [what you can't determine from static analysis]
Test needed: [describe the Foundry test to write]
```

HYPOTHESIS:
{hypothesis}

FULL SOURCE CODE (current version):
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# SLITHER INTEGRATION PROMPT
# ═══════════════════════════════════════════════════════════════════════════

SLITHER_ANALYSIS = """
You are analyzing Slither static analysis output alongside the invariant list
to identify which Slither findings are REAL vulnerabilities vs false positives.

Slither finds hundreds of issues. Most are informational or false positives.
Your job is to correlate Slither findings with our invariant list to identify
the 1-3 findings that are actually exploitable.

## CORRELATION RULES

1. If Slither reports "reentrancy" in a function that modifies an accounting
   invariant BEFORE making an external call -> REAL (check if guard exists)

2. If Slither reports "uninitialized state variable" for a variable used in
   an invariant -> REAL (the invariant might evaluate incorrectly)

3. If Slither reports "dangerous strict equality" in a function with a
   transition invariant -> CHECK (the invariant might have off-by-one)

4. If Slither reports "unused return value" for an external call in a function
   that assumes success -> REAL (failed call = broken state assumption)

5. If Slither reports "arbitrary send" in a function with an access control
   invariant -> REAL (invariant might be violated by unauthorized caller)

For each Slither finding that correlates with an invariant:
```
SLITHER-INVARIANT CORRELATION:
Slither finding: [detector name + description]
Related invariant: [ID from invariant list]
Correlation: [how the Slither finding could violate the invariant]
Exploitable: [YES/NO/NEEDS TESTING]
If YES: [attack scenario]
```

SLITHER OUTPUT:
{slither_output}

INVARIANT LIST:
{invariants}
"""

# ═══════════════════════════════════════════════════════════════════════════
# CERTORA SPEC GENERATION
# ═══════════════════════════════════════════════════════════════════════════

CERTORA_SPEC_GEN = """
You are a Certora Prover specialist. You translate invariants into Certora
CVL (Certora Verification Language) specifications for formal verification.

Certora can MATHEMATICALLY PROVE that invariants hold for ALL possible inputs,
not just fuzzed samples. This eliminates false negatives from fuzzing.

## TASK

Convert the high-priority invariants (P0 and P1) into Certora CVL specs.

## CVL SYNTAX GUIDE

### Invariants (checked after every state change):
```cvl
invariant solvency()
    asset.balanceOf(currentContract) >= totalAssets()
    {{
        preserved with (env e) {{
            require e.msg.sender != currentContract;
        }}
    }}
```

### Rules (checked for specific functions):
```cvl
rule deposit_increases_shares(uint256 amount) {{
    env e;
    require amount > 0;

    uint256 sharesBefore = balanceOf(e.msg.sender);

    deposit(e, amount);

    uint256 sharesAfter = balanceOf(e.msg.sender);
    assert sharesAfter >= sharesBefore, "deposit must increase shares";
}}
```

### Ghost variables (for tracking cumulative state):
```cvl
ghost mathint sumOfBalances {{
    init_state axiom sumOfBalances == 0;
}}

hook Sstore balances[KEY address user] uint256 newValue (uint256 oldValue) {{
    sumOfBalances = sumOfBalances + newValue - oldValue;
}}

invariant totalSupplyIsSumOfBalances()
    to_mathint(totalSupply()) == sumOfBalances;
```

### Parametric rules (verify property for ALL functions):
```cvl
rule no_unauthorized_balance_change(method f) {{
    env e;
    calldataarg args;
    address user;
    require user != e.msg.sender;

    uint256 balanceBefore = balanceOf(user);

    f(e, args);

    uint256 balanceAfter = balanceOf(user);
    assert balanceAfter >= balanceBefore, "no function should decrease other user's balance without approval";
}}
```

## OUTPUT

Generate:
1. A `.spec` file with CVL rules for each P0/P1 invariant
2. A `.conf` file for running the verification
3. A `run.sh` script to execute

### .conf file template:
```json
{{
    "files": ["src/Vault.sol"],
    "verify": "Vault:certora/specs/Vault.spec",
    "solc": "solc",
    "msg": "Vault invariant verification",
    "rule_sanity": "basic",
    "optimistic_loop": true,
    "loop_iter": 3
}}
```

### run.sh template:
```bash
#!/bin/bash
certoraRun certora/conf/Vault.conf
```

INVARIANT LIST (P0 and P1 only):
{invariants}

SOURCE CODE:
{code}
"""

# ═══════════════════════════════════════════════════════════════════════════
# ECHIDNA CONFIG GENERATION
# ═══════════════════════════════════════════════════════════════════════════

ECHIDNA_CONFIG_GEN = """
You are an Echidna/Medusa fuzzing specialist. Generate a fuzzing harness that
tests the extracted invariants using Echidna's property-based testing.

## ECHIDNA CONVENTIONS

- Properties are functions starting with `echidna_` that return bool
- Echidna calls random functions and checks properties after each call
- Use `config.yaml` for fuzzing parameters

## TASK

Generate:

### 1. Fuzzing harness contract
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./TargetProtocol.sol";

contract EchidnaHarness {{
    TargetProtocol target;

    constructor() {{
        // Deploy and initialize
        target = new TargetProtocol();
        // Set up initial state
    }}

    // === ACTIONS (Echidna calls these randomly) ===

    function deposit(uint256 amount) public {{
        amount = amount % 1e24; // bound
        if (amount == 0) return;
        // ... execute deposit
    }}

    function withdraw(uint256 amount) public {{
        amount = amount % (target.balanceOf(msg.sender) + 1);
        if (amount == 0) return;
        // ... execute withdraw
    }}

    // === PROPERTIES (must always return true) ===

    function echidna_solvency() public view returns (bool) {{
        return token.balanceOf(address(target)) >= target.totalAssets();
    }}

    function echidna_no_free_shares() public view returns (bool) {{
        return target.totalSupply() == 0 || target.totalAssets() > 0;
    }}

    // [One property per GLOBAL invariant]
}}
```

### 2. Echidna config
```yaml
testMode: "property"
testLimit: 100000
seqLen: 50
shrinkLimit: 5000
deployer: "0x10000"
sender: ["0x20000", "0x30000", "0x40000"]
coverage: true
corpusDir: "echidna-corpus"
```

### 3. Medusa config (alternative fuzzer — often finds different bugs)
```json
{{
    "fuzzing": {{
        "workers": 4,
        "workerResetLimit": 50,
        "timeout": 300,
        "testLimit": 500000,
        "callSequenceLength": 50,
        "targetContracts": ["EchidnaHarness"],
        "testing": {{
            "propertyTesting": {{
                "enabled": true,
                "testPrefixes": ["echidna_"]
            }}
        }}
    }}
}}
```

INVARIANT LIST:
{invariants}

SOURCE CODE:
{code}
"""


# ---------------------------------------------------------------------------
# ORCHESTRATOR — Ties all steps together
# ---------------------------------------------------------------------------

@dataclass
class HybridPipelineResult:
    """Complete result of the hybrid pipeline run."""
    target: str
    domain: str
    timestamp: str
    invariants_file: str = ""
    foundry_tests_dir: str = ""
    fuzz_output: str = ""
    findings: list = field(default_factory=list)
    reports_dir: str = ""
    certora_dir: str = ""
    echidna_dir: str = ""


def collect_solidity_sources(target_dir: str) -> dict[str, str]:
    """Collect all .sol files from target directory into a dict."""
    sources = {}
    target_path = Path(target_dir)
    for sol_file in sorted(target_path.rglob("*.sol")):
        # Skip test files and build artifacts
        rel_path = sol_file.relative_to(target_path)
        if any(part in str(rel_path) for part in ["test/", "script/", "node_modules/", "lib/"]):
            continue
        try:
            sources[str(rel_path)] = sol_file.read_text(encoding="utf-8")
        except Exception:
            pass
    return sources


def format_code_for_prompt(sources: dict[str, str]) -> str:
    """Format source code dict into a single string for prompts."""
    parts = []
    for fname, content in sources.items():
        parts.append(f"// === {fname} ===\n{content}")
    return "\n\n".join(parts)


def run_slither(target_dir: str) -> str:
    """Run Slither and return output."""
    try:
        result = subprocess.run(
            ["slither", target_dir, "--json", "-"],
            capture_output=True, text=True, timeout=300
        )
        return result.stdout or result.stderr
    except FileNotFoundError:
        return "[Slither not installed — skip]"
    except subprocess.TimeoutExpired:
        return "[Slither timed out after 300s]"


def run_forge_invariant(test_dir: str) -> str:
    """Run Foundry invariant tests and return output."""
    try:
        result = subprocess.run(
            ["forge", "test", "--match-path", f"{test_dir}/*",
             "-vvvv", "--fuzz-runs", "256"],
            capture_output=True, text=True, timeout=600,
            cwd=str(Path(test_dir).parent.parent)  # foundry project root
        )
        return result.stdout + "\n" + result.stderr
    except FileNotFoundError:
        return "[Forge not installed — skip]"
    except subprocess.TimeoutExpired:
        return "[Forge timed out after 600s]"


def get_git_diff(repo_dir: str, from_ref: str, to_ref: str) -> str:
    """Get git diff between two refs."""
    try:
        result = subprocess.run(
            ["git", "diff", from_ref, to_ref, "--", "*.sol"],
            capture_output=True, text=True, cwd=repo_dir
        )
        return result.stdout
    except Exception as e:
        return f"[Git diff failed: {e}]"


def print_step(step_num: int, title: str):
    """Print a visible step header."""
    print(f"\n{'='*70}")
    print(f"  STEP {step_num}: {title}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Hybrid LLM + Formal Verification Pipeline"
    )
    parser.add_argument("--target", "-t", help="Target contract directory")
    parser.add_argument("--domain", "-d", default="defi-lending",
                        choices=["defi-lending", "defi-dex", "defi-staking",
                                 "bridge", "zk", "governance"])
    parser.add_argument("--step", "-s", default="all",
                        choices=["all", "invariants", "invariant-tests",
                                 "fuzz", "analyze-fuzz", "report",
                                 "slither", "certora", "echidna"])
    parser.add_argument("--diff", action="store_true",
                        help="Run differential analysis pipeline")
    parser.add_argument("--repo", help="Repository path for diff analysis")
    parser.add_argument("--from-tag", help="Starting ref for diff")
    parser.add_argument("--to-tag", default="HEAD", help="Ending ref for diff")
    parser.add_argument("--platform", default="immunefi",
                        choices=["immunefi", "code4rena", "cantina"],
                        help="Target bounty platform for report format")
    parser.add_argument("--output", "-o", default="hybrid-output",
                        help="Output directory")

    args = parser.parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(args.output) / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.diff:
        # ─── DIFFERENTIAL ANALYSIS PIPELINE ───
        if not args.repo:
            print("[ERROR] --repo is required for diff analysis")
            sys.exit(1)

        print_step(1, "GET GIT DIFF")
        diff = get_git_diff(args.repo, args.from_tag, args.to_tag)
        diff_file = output_dir / "git_diff.txt"
        diff_file.write_text(diff, encoding="utf-8")
        print(f"  Diff saved to: {diff_file}")
        print(f"  Diff size: {len(diff)} chars, ~{diff.count(chr(10))} lines")

        # Collect current source for hypothesis verification
        sources = collect_solidity_sources(args.repo)
        code = format_code_for_prompt(sources)

        print_step(2, "GENERATE CHANGE ANALYSIS PROMPT")
        prompt = DIFF_STEP1_IDENTIFY_CHANGES.format(
            diff=diff,
            previous_audit="[No previous audit report provided — analyze changes on their own merit]"
        )
        prompt_file = output_dir / "prompt_diff_analysis.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Prompt saved to: {prompt_file}")
        print(f"  Copy this prompt into Claude Code with the diff content.")

        print_step(3, "GENERATE HYPOTHESIS VERIFICATION TEMPLATE")
        prompt = DIFF_STEP2_HYPOTHESIS_VERIFICATION.format(
            hypothesis="[PASTE HYPOTHESIS FROM STEP 2 HERE]",
            code=code[:50000]  # Truncate for very large codebases
        )
        prompt_file = output_dir / "prompt_hypothesis_verify.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Template saved to: {prompt_file}")

        print("\n" + "="*70)
        print("  DIFFERENTIAL PIPELINE READY")
        print("="*70)
        print(f"\n  Output dir: {output_dir}")
        print(f"\n  Next steps:")
        print(f"  1. Open prompt_diff_analysis.md")
        print(f"  2. Feed it to Claude Code along with the git diff")
        print(f"  3. For each hypothesis, use prompt_hypothesis_verify.md")
        print(f"  4. For confirmed bugs, use Step 4 (exploit PoC) from main pipeline")
        return

    # ─── MAIN HYBRID PIPELINE ───
    if not args.target:
        print("[ERROR] --target is required")
        sys.exit(1)

    # Collect source code
    sources = collect_solidity_sources(args.target)
    if not sources:
        print(f"[ERROR] No .sol files found in {args.target}")
        sys.exit(1)

    code = format_code_for_prompt(sources)
    print(f"[*] Collected {len(sources)} Solidity files ({len(code)} chars)")

    # ─── STEP 1: INVARIANT EXTRACTION ───
    if args.step in ("all", "invariants"):
        print_step(1, "INVARIANT EXTRACTION")
        prompt = STEP1_INVARIANT_EXTRACTION.format(code=code)
        prompt_file = output_dir / "step1_invariant_extraction.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Prompt saved to: {prompt_file}")
        print(f"  Prompt size: {len(prompt)} chars")

        # Also save placeholder for output
        invariant_output = output_dir / "step1_invariants_output.md"
        invariant_output.write_text(
            "# Invariant Extraction Results\n\n"
            "[Paste Claude Code output here after running the prompt]\n",
            encoding="utf-8"
        )
        print(f"  Output placeholder: {invariant_output}")

    # ─── STEP 2: INVARIANT TEST GENERATION ───
    if args.step in ("all", "invariant-tests"):
        print_step(2, "FOUNDRY INVARIANT TEST GENERATION")
        invariant_output = output_dir / "step1_invariants_output.md"
        invariants = ""
        if invariant_output.exists():
            invariants = invariant_output.read_text(encoding="utf-8")

        prompt = STEP2_INVARIANT_TEST_GEN.format(
            invariants=invariants or "[RUN STEP 1 FIRST — paste invariant list here]",
            code=code
        )
        prompt_file = output_dir / "step2_invariant_tests.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Prompt saved to: {prompt_file}")

        # Save foundry.toml additions
        foundry_additions = output_dir / "foundry_toml_additions.toml"
        foundry_additions.write_text(
            "[invariant]\n"
            "runs = 256\n"
            "depth = 50\n"
            "fail_on_revert = false\n"
            "shrink_run_limit = 5000\n"
            "\n"
            "[fuzz]\n"
            "runs = 1000\n"
            "max_test_rejects = 100000\n",
            encoding="utf-8"
        )
        print(f"  Foundry config additions: {foundry_additions}")

    # ─── RUN SLITHER (if requested) ───
    if args.step in ("all", "slither"):
        print_step("S", "SLITHER STATIC ANALYSIS")
        slither_output = run_slither(args.target)
        slither_file = output_dir / "slither_output.json"
        slither_file.write_text(slither_output, encoding="utf-8")
        print(f"  Slither output saved to: {slither_file}")

        # Generate correlation prompt
        invariant_output = output_dir / "step1_invariants_output.md"
        invariants = ""
        if invariant_output.exists():
            invariants = invariant_output.read_text(encoding="utf-8")

        prompt = SLITHER_ANALYSIS.format(
            slither_output=slither_output[:20000],  # Truncate if huge
            invariants=invariants or "[RUN STEP 1 FIRST]"
        )
        prompt_file = output_dir / "prompt_slither_correlation.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Correlation prompt: {prompt_file}")

    # ─── RUN FUZZ & ANALYZE (if requested) ───
    if args.step in ("all", "fuzz", "analyze-fuzz"):
        print_step(3, "FUZZ EXECUTION & ANALYSIS")
        if args.step == "fuzz":
            fuzz_output = run_forge_invariant(str(output_dir / "tests"))
            fuzz_file = output_dir / "fuzz_output.txt"
            fuzz_file.write_text(fuzz_output, encoding="utf-8")
            print(f"  Fuzz output saved to: {fuzz_file}")

        fuzz_file = output_dir / "fuzz_output.txt"
        fuzz_output = ""
        if fuzz_file.exists():
            fuzz_output = fuzz_file.read_text(encoding="utf-8")

        invariant_output = output_dir / "step1_invariants_output.md"
        invariants = ""
        if invariant_output.exists():
            invariants = invariant_output.read_text(encoding="utf-8")

        prompt = STEP3_FUZZ_ANALYSIS.format(
            fuzz_output=fuzz_output or "[RUN FUZZ FIRST — paste forge test output here]",
            invariants=invariants or "[PASTE INVARIANTS HERE]",
            code=code
        )
        prompt_file = output_dir / "step3_fuzz_analysis.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Analysis prompt: {prompt_file}")

    # ─── STEP 4: EXPLOIT POC ───
    if args.step in ("all", "report"):
        print_step(4, "EXPLOIT POC GENERATION")
        prompt = STEP4_EXPLOIT_POC.format(
            findings="[PASTE CONFIRMED FINDINGS FROM STEP 3 HERE]",
            code=code
        )
        prompt_file = output_dir / "step4_exploit_poc.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  PoC prompt: {prompt_file}")

    # ─── STEP 5: REPORT ───
    if args.step in ("all", "report"):
        print_step(5, "BOUNTY REPORT GENERATION")
        prompt = STEP5_REPORT.format(
            findings="[PASTE FINDINGS + POCS FROM STEP 4 HERE]",
            platform=args.platform
        )
        prompt_file = output_dir / "step5_report.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Report prompt: {prompt_file}")

    # ─── CERTORA SPEC GENERATION ───
    if args.step in ("all", "certora"):
        print_step("C", "CERTORA SPEC GENERATION")
        invariant_output = output_dir / "step1_invariants_output.md"
        invariants = ""
        if invariant_output.exists():
            invariants = invariant_output.read_text(encoding="utf-8")

        prompt = CERTORA_SPEC_GEN.format(
            invariants=invariants or "[RUN STEP 1 FIRST — paste P0/P1 invariants here]",
            code=code
        )
        prompt_file = output_dir / "prompt_certora_spec.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Certora prompt: {prompt_file}")

    # ─── ECHIDNA HARNESS GENERATION ───
    if args.step in ("all", "echidna"):
        print_step("E", "ECHIDNA/MEDUSA HARNESS GENERATION")
        invariant_output = output_dir / "step1_invariants_output.md"
        invariants = ""
        if invariant_output.exists():
            invariants = invariant_output.read_text(encoding="utf-8")

        prompt = ECHIDNA_CONFIG_GEN.format(
            invariants=invariants or "[RUN STEP 1 FIRST — paste invariants here]",
            code=code
        )
        prompt_file = output_dir / "prompt_echidna_harness.md"
        prompt_file.write_text(prompt, encoding="utf-8")
        print(f"  Echidna prompt: {prompt_file}")

    # ─── SUMMARY ───
    print("\n" + "="*70)
    print("  HYBRID PIPELINE READY")
    print("="*70)
    print(f"\n  Target: {args.target}")
    print(f"  Domain: {args.domain}")
    print(f"  Output: {output_dir}")
    print(f"\n  Files generated:")
    for f in sorted(output_dir.iterdir()):
        size = f.stat().st_size
        print(f"    {f.name} ({size:,} bytes)")
    print(f"\n  WORKFLOW:")
    print(f"  1. Feed step1_invariant_extraction.md to Claude Code")
    print(f"  2. Save output to step1_invariants_output.md")
    print(f"  3. Feed step2_invariant_tests.md to Claude Code")
    print(f"  4. Save generated .t.sol files to foundry-workspace/test/invariant/")
    print(f"  5. Run: forge test --match-path test/invariant/ -vvvv")
    print(f"  6. Save output to fuzz_output.txt")
    print(f"  7. Feed step3_fuzz_analysis.md to Claude Code")
    print(f"  8. For confirmed bugs: feed step4_exploit_poc.md")
    print(f"  9. For final reports: feed step5_report.md")
    print(f"\n  PARALLEL (run alongside steps 1-5):")
    print(f"  - Slither: slither {args.target} --json slither.json")
    print(f"  - Feed prompt_slither_correlation.md with Slither output")
    print(f"  - Certora: feed prompt_certora_spec.md for formal proofs")
    print(f"  - Echidna: feed prompt_echidna_harness.md for alternative fuzzing")


if __name__ == "__main__":
    main()
