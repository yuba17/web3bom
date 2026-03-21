#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# HYBRID PIPELINE — Concrete Quickstart
# ═══════════════════════════════════════════════════════════════════════════
#
# This shows the EXACT commands to run for a complete hybrid audit.
# Replace TARGET_DIR with your actual contract directory.
#
# Prerequisites:
#   - forge (Foundry) installed
#   - slither installed (pip install slither-analyzer)
#   - echidna installed (optional, for alternative fuzzing)
#   - Claude Code available
#
# ═══════════════════════════════════════════════════════════════════════════

# ─── CONFIGURATION ───
TARGET_DIR="./contracts/euler-vault-kit/src"   # Change this
DOMAIN="defi-lending"                           # Change this
PLATFORM="immunefi"                             # Change this
OUTPUT_DIR="./hybrid-output/$(date +%Y%m%d_%H%M%S)"
FOUNDRY_DIR="./foundry-workspace"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$FOUNDRY_DIR/test/invariant"
mkdir -p "$FOUNDRY_DIR/test/poc"

echo "═══════════════════════════════════════"
echo "  TARGET: $TARGET_DIR"
echo "  OUTPUT: $OUTPUT_DIR"
echo "═══════════════════════════════════════"

# ═══════════════════════════════════════════════════════════════════════════
# STEP 0: PARALLEL TOOLING (run in background while LLM works)
# ═══════════════════════════════════════════════════════════════════════════

echo "[STEP 0] Running Slither in background..."
slither "$TARGET_DIR" --json "$OUTPUT_DIR/slither.json" 2>"$OUTPUT_DIR/slither_stderr.txt" &
SLITHER_PID=$!

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: INVARIANT EXTRACTION (in Claude Code)
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 1: INVARIANT EXTRACTION ═══"
echo ""
echo "Open Claude Code in the project directory and paste:"
echo ""
echo "─────────────────────────────────────────────────────"
cat << 'PROMPT_END'
Read all Solidity source files in src/ (excluding test/, script/, lib/,
node_modules/). Extract every invariant this protocol relies on.

Format each as:

GLOBAL-[N]: [description]
Solidity: assert([expression with actual variable names]);
Priority: P0 (solvency) / P1 (user funds) / P2 (accounting) / P3 (grief)

TRANS-[N]: [description]
Function: [Contract.function]
Solidity: assert([before_after_relationship]);

Focus 70% on IMPLICIT invariants — assumed but never asserted.
Tag implicit ones with [IMPLICIT].
Target: 15-30 invariants total.
PROMPT_END
echo "─────────────────────────────────────────────────────"
echo ""
echo "Save the output to: $OUTPUT_DIR/invariants.md"
echo ""
read -p "Press Enter when invariants are saved..."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: GENERATE FOUNDRY TESTS (in Claude Code)
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 2: FOUNDRY TEST GENERATION ═══"
echo ""
echo "Paste in Claude Code:"
echo ""
echo "─────────────────────────────────────────────────────"
cat << 'PROMPT_END'
Based on the invariants I just extracted, generate Foundry invariant tests.

Create these files in test/invariant/:

1. InvariantGlobal.t.sol — Uses StdInvariant, Handler pattern
   - setUp() deploys all contracts with realistic state
   - Handler wraps each protocol function with bound() inputs
   - One invariant_* function per GLOBAL invariant

2. InvariantTransition.t.sol — Fuzz tests per function
   - test_deposit_*(uint256 amount) with bound(amount, 1, 1e24)
   - Before/after assertions per TRANS invariant

3. InvariantEconomic.t.sol — Attack simulations
   - test_no_inflation_attack(uint256, uint256)
   - test_no_sandwich_profit(uint256)
   - test_no_donation_attack(uint256)

All tests MUST compile. Use exact types and names from source.
PROMPT_END
echo "─────────────────────────────────────────────────────"
echo ""
echo "Save .t.sol files to: $FOUNDRY_DIR/test/invariant/"
echo ""
read -p "Press Enter when test files are saved..."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 2.5: ADD FOUNDRY CONFIG
# ═══════════════════════════════════════════════════════════════════════════

echo "[STEP 2.5] Adding invariant config to foundry.toml..."
if ! grep -q "\[invariant\]" "$FOUNDRY_DIR/foundry.toml" 2>/dev/null; then
    cat >> "$FOUNDRY_DIR/foundry.toml" << 'EOF'

[invariant]
runs = 256
depth = 50
fail_on_revert = false
shrink_run_limit = 5000

[fuzz]
runs = 1000
max_test_rejects = 100000
EOF
    echo "  Added invariant/fuzz config to foundry.toml"
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: RUN FUZZ TESTS
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 3: RUNNING FUZZ TESTS ═══"
echo ""
cd "$FOUNDRY_DIR"

echo "[*] Running invariant tests..."
forge test --match-path "test/invariant/*" -vvvv 2>&1 | tee "$OUTPUT_DIR/fuzz_output.txt"
FUZZ_EXIT=$?

cd - > /dev/null

if [ $FUZZ_EXIT -ne 0 ]; then
    echo ""
    echo "[!] SOME INVARIANT TESTS FAILED — potential bugs found!"
    echo "[*] Output saved to: $OUTPUT_DIR/fuzz_output.txt"
else
    echo ""
    echo "[*] All invariant tests passed with fuzz inputs"
    echo "[*] Consider: increase runs, depth, or add more invariants"
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 3.5: SLITHER CORRELATION (background job should be done)
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 3.5: SLITHER CORRELATION ═══"
wait $SLITHER_PID 2>/dev/null
if [ -f "$OUTPUT_DIR/slither.json" ]; then
    echo "[*] Slither completed. Results in: $OUTPUT_DIR/slither.json"
    echo ""
    echo "Paste in Claude Code to correlate with invariants:"
    echo "─────────────────────────────────────────────────────"
    echo "Correlate Slither findings with invariant list."
    echo "Slither output is in $OUTPUT_DIR/slither.json"
    echo "Identify the 1-3 findings that could violate an invariant."
    echo "─────────────────────────────────────────────────────"
fi

# ═══════════════════════════════════════════════════════════════════════════
# STEP 4: ANALYZE FAILURES (in Claude Code)
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 4: FAILURE ANALYSIS ═══"
echo ""
echo "Paste in Claude Code along with fuzz_output.txt content:"
echo ""
echo "─────────────────────────────────────────────────────"
cat << 'PROMPT_END'
Analyze the Foundry invariant test failures below.

For each failure:
1. Extract the counterexample call sequence
2. Replay against source code — trace every line
3. Classify: REAL BUG / TEST ARTIFACT / ROUNDING / KNOWN

For REAL BUGS: output a structured finding with severity, root cause,
and impact. Then generate a COMPILABLE Foundry exploit PoC.

FORGE OUTPUT:
[paste fuzz_output.txt content]
PROMPT_END
echo "─────────────────────────────────────────────────────"
echo ""
read -p "Press Enter when analysis is complete..."

# ═══════════════════════════════════════════════════════════════════════════
# STEP 5: GENERATE REPORT (in Claude Code)
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══ STEP 5: REPORT GENERATION ═══"
echo ""
echo "For each confirmed finding, paste in Claude Code:"
echo ""
echo "─────────────────────────────────────────────────────"
cat << PROMPT_END
Write a $PLATFORM bug bounty report for this finding.
Include the complete PoC with reproduction steps.
Frame impact as "direct loss of funds" if applicable.
Include a specific code diff for the fix.

FINDING:
[paste confirmed finding + PoC]
PROMPT_END
echo "─────────────────────────────────────────────────────"

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════"
echo "  PIPELINE COMPLETE"
echo "═══════════════════════════════════════"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Files:"
ls -la "$OUTPUT_DIR/" 2>/dev/null
echo ""
echo "Next: Submit confirmed findings to $PLATFORM"
