# Hybrid LLM + Formal Verification Pipeline — Copy-Paste Prompts

All prompts below are designed to be pasted directly into Claude Code.
Replace `{PLACEHOLDER}` values with actual content.

---

## HOW TO USE THIS FILE

### Full Pipeline (30-60 min per protocol)
```
Step 1 → extract invariants → save output
Step 2 → generate Foundry tests → save .t.sol files
Step 3 → run `forge test` → paste output back
Step 4 → analyze failures → get exploit PoCs
Step 5 → write report → submit
```

### Quick Hunt (10-15 min per protocol)
```
Step 1 → extract invariants → immediately go to Step 4 (skip test generation)
Step 4 → LLM tries to break invariants directly → gets findings
Step 5 → write report
```

### Differential Hunt (15-20 min)
```
Diff-1 → analyze changes → get hypotheses
Diff-2 → verify each hypothesis → confirmed findings → Step 5
```

---

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: INVARIANT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: First step. Always.
# INPUT: All .sol source files
# OUTPUT: Numbered list of invariants with Solidity expressions
# TIME: 3-5 min
#
# USAGE IN CLAUDE CODE:
#   1. Open the project directory
#   2. Paste this prompt
#   3. Claude will read the files and extract invariants
# ═══════════════════════════════════════════════════════════════════════════

```
Read all Solidity source files in {TARGET_DIR} (excluding test/, script/, lib/, node_modules/). Then extract every invariant this protocol relies on.

For each invariant, output in this exact format:

GLOBAL-[N]: [description]
Solidity: assert([boolean expression using actual variable names from the code]);
Contracts: [which contracts]
Priority: P0/P1/P2/P3
Impact if violated: [what attacker gains]

TRANS-[N]: [description]
Function: [Contract.function]
Before: [snapshot expression]
After: assert([relationship]);

REL-[N]: [description]
Contracts: [A, B]
Relationship: assert([cross-contract expression]);

CATEGORIES TO CHECK:
1. ACCOUNTING: total_shares * price == total_assets, sum(balances) == totalSupply, solvency (contract balance >= obligations)
2. ACCESS CONTROL: only authorized callers for privileged functions
3. STATE MACHINE: valid state transitions, no skipping steps
4. ECONOMIC: no value extraction beyond legitimate yield, no sandwich profit, no oracle manipulation profit
5. CROSS-CONTRACT: assumptions about external call returns, token behavior
6. TEMPORAL: time-dependent operations, deadline enforcement

FOCUS 70% ON IMPLICIT INVARIANTS — properties assumed but never asserted with require/assert. Tag these [IMPLICIT].

Target: 10-30 global, 5-15 per major function, 5-10 relational invariants.
```

---

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: FOUNDRY INVARIANT TEST GENERATION
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: After Step 1 produces invariant list
# INPUT: Invariant list from Step 1 + source code
# OUTPUT: Compilable .t.sol files
# TIME: 5-10 min
# ═══════════════════════════════════════════════════════════════════════════

```
Based on the invariant list below, generate Foundry invariant tests. Create THREE files:

FILE 1: test/invariant/InvariantGlobal.t.sol
- Uses StdInvariant for stateful fuzzing
- targetContract() set to main protocol contract
- One `invariant_*` function per GLOBAL invariant
- Handler contract that wraps protocol functions with bound() on all inputs
- setUp() deploys all contracts with realistic parameters and funds actors

FILE 2: test/invariant/InvariantTransition.t.sol
- Standard fuzz tests (function test_*(uint256 amount))
- Before/after assertions per TRANS invariant
- Uses bound() on all fuzz inputs
- Tests edge cases: amount=0, amount=1, amount=type(uint256).max

FILE 3: test/invariant/InvariantEconomic.t.sol
- Guided fuzz tests simulating attack patterns:
  - First depositor / inflation attack
  - Donation attack (direct transfer to inflate share price)
  - Sandwich attack (deposit before victim, withdraw after)
  - Flash loan attack simulation
  - Rounding exploitation across many small operations

REQUIREMENTS:
- MUST compile against the actual source code (use exact contract names, function signatures, types)
- MUST use bound() on every fuzz input
- MUST use deal() for token funding
- MUST have realistic setUp() (not empty contracts)
- Include foundry.toml additions:
  [invariant]
  runs = 256
  depth = 50
  fail_on_revert = false

INVARIANT LIST:
{PASTE STEP 1 OUTPUT HERE}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: FUZZ RESULT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: After running `forge test --match-path test/invariant/ -vvvv`
# INPUT: forge test output (including failures and counterexamples)
# OUTPUT: Classified findings (REAL BUG / FALSE POSITIVE / ROUNDING)
# TIME: 5 min per failure
# ═══════════════════════════════════════════════════════════════════════════

```
Analyze these Foundry invariant test results. For each FAILURE:

1. Extract the counterexample (call sequence + parameters)
2. Replay the counterexample against the source code mentally — trace every line
3. Classify as:
   - REAL BUG: logic error with financial impact → output structured finding
   - TEST ARTIFACT: test setup issue → suggest fix
   - KNOWN LIMITATION: documented/accepted trade-off
   - ROUNDING: 1-2 wei error → check if compounds over 1000 ops

For REAL BUGS, output:
```
FINDING: [title]
Invariant violated: [ID]
Severity: CRITICAL/HIGH/MEDIUM/LOW
Counterexample: [minimal call sequence]
Root cause: [exact line of code]
Impact: [quantified — dollar amount or percentage]
Confidence: HIGH/MEDIUM/LOW
```

For ROUNDING issues, calculate:
- Error per operation: N wei
- After 1000 ops: N * 1000
- With WBTC (8 decimals): is it material?
- Attacker amplification via flash loan loops?

FORGE TEST OUTPUT:
{PASTE FORGE OUTPUT HERE}

INVARIANT DEFINITIONS:
{PASTE FROM STEP 1}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: EXPLOIT POC
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: After Step 3 confirms real bugs
# INPUT: Confirmed findings
# OUTPUT: Compilable, runnable Foundry exploit tests
# TIME: 10-15 min per finding
# ═══════════════════════════════════════════════════════════════════════════

```
Generate a COMPLETE, COMPILABLE Foundry test PoC for each confirmed finding below.

Requirements:
1. Must compile with `forge build`
2. Must pass with `forge test --match-test test_exploit -vvvv`
3. Must fork mainnet if contracts are deployed:
   vm.createSelectFork(vm.envString("ETH_RPC_URL"), BLOCK_NUMBER);
4. Must show BEFORE/AFTER state with console2.log
5. Must assert attacker profit > 0 AND vault/protocol loss > 0
6. Must calculate: profit = attacker_after - attacker_before
7. Must use exact function signatures from source code
8. Must include all necessary interface definitions

Structure:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test, console2} from "forge-std/Test.sol";

contract Exploit_[Name] is Test {
    function setUp() public { /* deploy or fork */ }

    function test_exploit() public {
        // BEFORE snapshot
        // EXPLOIT steps (commented with explanation)
        // AFTER snapshot
        // ASSERTIONS proving the bug
    }
}
```

For flash loan exploits: include callback contract
For reentrancy: include attack contract with receive()
For economic attacks: use vm.roll/vm.warp for time manipulation

CONFIRMED FINDINGS:
{PASTE FROM STEP 3}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: BOUNTY REPORT
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: After Step 4 produces working PoC
# INPUT: Finding + PoC
# OUTPUT: Platform-ready bounty report
# TIME: 5-10 min per report
# ═══════════════════════════════════════════════════════════════════════════

### For Immunefi:

```
Write an Immunefi bug bounty report for this finding. Format:

# [Specific Title — Bug Type in Component Name]

## Bug Description
[3 paragraphs: intended behavior, actual behavior, root cause with line references]

## Impact
[Quantified: "Attacker can extract X% of TVL" or "Users lose up to $Y"]
Severity: Critical/High/Medium/Low

## Risk Breakdown
Difficulty: Low/Medium/High
Likelihood: Low/Medium/High

## Proof of Concept
[Complete Foundry test — runnable]

### Reproduction steps:
1. git clone [repo] && forge install
2. Save PoC to test/poc/Exploit.t.sol
3. forge test --match-test test_exploit --fork-url $RPC_URL -vvvv
4. Expected: [describe successful exploit output]

## Recommendation
```diff
- [buggy code]
+ [fixed code]
```

## References
[Similar past exploits]

FINDING + POC:
{PASTE FROM STEP 4}
```

### For Code4rena:

```
Write a Code4rena submission for this finding. Format:

# [H-01] [Title]

## Summary
[2 sentences max]

## Vulnerability Detail
[Full technical walk-through with code references: Contract.sol#L123]

## Impact
HIGH/MEDIUM with justification

## Code Snippet
[Exact lines from repo with links]

## Tool used
Manual Review + Foundry Invariant Testing

## Recommendation
```diff
- [buggy line]
+ [fixed line]
```

## Proof of Concept
[Foundry test]

FINDING + POC:
{PASTE FROM STEP 4}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# DIFFERENTIAL ANALYSIS — STEP D1: Change Analysis
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: Protocol has been audited before, new code deployed
# INPUT: git diff between audited version and current HEAD
# OUTPUT: Categorized changes + attack hypotheses
# TIME: 5-10 min
# ═══════════════════════════════════════════════════════════════════════════

```
Analyze this git diff between the last audited version and the current code.

For each change, classify as:
- NEW CODE: Never audited. HIGHEST PRIORITY.
- MODIFIED LOGIC: Changed behavior. HIGH PRIORITY.
- MODIFIED PARAMETERS: Changed constants/thresholds. MEDIUM.
- REFACTORED: Same logic, different structure. LOW.
- DEPENDENCY UPDATE: Updated library. MEDIUM.
- REMOVED CODE: Was this a safety check? HIGH if yes.

For each non-trivial change, generate hypotheses:

HYPOTHESIS-[N]:
Change: [file:function]
Theory: [how this could introduce a bug]
Attack: [concrete scenario]
Verify: [what test would confirm/deny]
Priority: P0/P1/P2

ALSO CHECK cross-change interactions:
- Does change A assume something that change B invalidates?
- Do changes modify the same state differently?
- Is there a call path through multiple changed functions?

GIT DIFF (run: git diff {FROM_TAG}..{TO_TAG} -- "*.sol"):
{PASTE DIFF HERE}

PREVIOUS AUDIT FINDINGS (if available):
{PASTE OR "none available"}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# DIFFERENTIAL ANALYSIS — STEP D2: Hypothesis Verification
# ═══════════════════════════════════════════════════════════════════════════
#
# WHEN: After D1 generates hypotheses
# INPUT: Single hypothesis + full current source code
# OUTPUT: CONFIRMED / REJECTED / NEEDS TESTING
# TIME: 3-5 min per hypothesis
#
# Run this ONCE PER HYPOTHESIS from D1. Parallelize across Claude Code sessions.
# ═══════════════════════════════════════════════════════════════════════════

```
Verify this hypothesis about a potential bug in the current code.

HYPOTHESIS:
{PASTE ONE HYPOTHESIS FROM D1}

VERIFICATION STEPS:
A) Restate: "The claim is that [X] enables [Y] because [Z]"
B) Trace the exact code path an attacker would take — quote every line that executes
C) Check ALL guards: require(), assert(), modifiers, upstream validation, economic constraints
D) Verdict:

If CONFIRMED:
  STATUS: CONFIRMED
  Attack: [step by step with exact function calls and parameters]
  Root cause: [file:line]
  Impact: [quantified]
  → Proceed to Step 4 (exploit PoC)

If REJECTED:
  STATUS: REJECTED
  Blocked by: [file:line — the specific guard that prevents this]

If UNCERTAIN:
  STATUS: NEEDS TESTING
  Test: [describe the Foundry test to write]

Read all source files in {TARGET_DIR} before analyzing.
```

---

# ═══════════════════════════════════════════════════════════════════════════
# BONUS: SLITHER CORRELATION
# ═══════════════════════════════════════════════════════════════════════════
#
# Run after Step 1 (invariants) + Slither scan
# Correlates static analysis findings with invariants to filter false positives
# ═══════════════════════════════════════════════════════════════════════════

```
Correlate these Slither findings with the invariant list. Most Slither findings are false positives. Identify the 1-3 that could actually violate an invariant.

CORRELATION RULES:
- Slither "reentrancy" + function modifies accounting invariant BEFORE external call → REAL
- Slither "uninitialized variable" + variable in invariant expression → REAL
- Slither "dangerous strict equality" + transition invariant → CHECK for off-by-one
- Slither "unused return value" + function assumes call success → REAL
- Slither "arbitrary send" + access control invariant → REAL

For each real correlation:
SLITHER-INVARIANT:
  Slither: [finding]
  Invariant: [ID]
  Attack: [how violation works]
  → Proceed to Step 4 if exploitable

SLITHER OUTPUT (run: slither . --print human-summary):
{PASTE SLITHER OUTPUT}

INVARIANT LIST:
{PASTE FROM STEP 1}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# BONUS: CERTORA SPEC GENERATION
# ═══════════════════════════════════════════════════════════════════════════
#
# For P0/P1 invariants — mathematical proof they hold for ALL inputs
# Use Certora free tier: https://www.certora.com/
# ═══════════════════════════════════════════════════════════════════════════

```
Generate Certora CVL specs for these P0/P1 invariants. I need:

1. A .spec file with:
   - `invariant` blocks for global invariants
   - `rule` blocks for transition invariants
   - `ghost` variables + `hook` for tracking cumulative state (sum of balances)
   - Parametric rules using `method f` for "no function should violate X"

2. A .conf JSON file pointing to the right source files

3. A run.sh script

CVL syntax reminders:
- invariant name() expression { preserved with (env e) { require ... } }
- rule name() { env e; calldataarg args; ... f(e, args); ... assert ...; }
- ghost mathint name { init_state axiom name == 0; }
- hook Sstore slot[KEY type k] type newVal (type oldVal) { ghost update }

P0/P1 INVARIANTS:
{PASTE P0 AND P1 INVARIANTS FROM STEP 1}
```

---

# ═══════════════════════════════════════════════════════════════════════════
# TIMING GUIDE
# ═══════════════════════════════════════════════════════════════════════════
#
# Full pipeline:      45-90 min (thorough, for high-value targets $1M+)
# Quick hunt:         15-25 min (invariants → direct breaking → report)
# Differential only:  15-20 min (best ROI for previously-audited protocols)
# Slither+invariant:  10-15 min (fast correlation, good for medium targets)
#
# PARALLELIZATION:
# - Run Step 1 in session A
# - Run Slither in terminal
# - When Step 1 done: run Step 2 in session A, correlation in session B
# - When tests generated: run forge in terminal
# - When forge done: run Step 3 in session A
# - For diff analysis: run D2 for each hypothesis in parallel sessions
#
# ═══════════════════════════════════════════════════════════════════════════
