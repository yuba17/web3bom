# Pipeline v4 — Fuzzing Obligatorio + DeepDiveHunter

**Date**: 2026-03-23
**Status**: Approved
**Scope**: Nivel 1 (Fuzzing mínimo obligatorio) + Nivel 2 (DeepDiveHunter)

---

## Problem Statement

The current pipeline allows skipping ALL fuzzing phases when "ROI is insufficient." This happened on PancakeSwap Infinity (17,764 LOC, 504 hypotheses, 0 fuzzing runs). Top hunters like MiloTruck/samczsun never skip fuzzing entirely — they adjust depth. Additionally, the 7-hunter system generates breadth (50-70 hypotheses per component) but lacks depth (the "eureka moment" that finds bugs no hypothesis predicted).

Two gaps to close:
1. **No escape hatch for Phases 1-2**: 17 minutes of mandatory fuzzing per component
2. **Depth over breadth**: A DeepDiveHunter that traces backward from value exits

---

## Design

### 1. Mandatory Fuzzing (Nivel 1)

#### Rules (to be added to CLAUDE.md)

- **Phase 1 (Foundry 5K runs)**: ALWAYS mandatory. ~2 minutes. No exceptions.
- **Phase 2 (Medusa 15 min)**: ALWAYS mandatory. Finds multi-step sequences Foundry misses.
- **Phase 3 (Fork 10 min)**: Mandatory if bounty >= $50K OR if Phase 1/2 breaks an invariant.
- **Phase 4 (Echidna optimize)**: Only after confirmed finding (maximize attacker profit).
- **Phase 5 (Halmos)**: Only for pure math functions identified by MathHunter.

The previous escape hatch ("ROI insuficiente para crear Chimera setup desde cero") is eliminated by auto-generating the setup.

#### Gate System

```
Phase 1 (Foundry 5K)  →  ALWAYS (2 min)
Phase 2 (Medusa)       →  ALWAYS (15 min)
        │
        ├─ Invariant broken? → Phase 3 (Fork) to confirm
        │                          │
        │                          └─ Confirmed? → Finding Pipeline
        │
        └─ All clean? → Gate:
             ├─ Bounty ≥ $50K? → Phase 3 (Fork 10 min) mandatory
             └─ Bounty < $50K? → Phase 3 optional, log skip

Bounty value source: read from `current_hunt.json` field `payout` (already exists, e.g., "Critical up to $1M, High $20K").
Parse logic: extract the max numeric value from the payout string. If unparseable or missing, default to mandatory (assume high value — safer).

Phase 4 (Echidna)     →  Post-confirmed-finding only
Phase 5 (Halmos)      →  Pure math only
```

### 2. Auto-Setup: ChimeraBuilder Sub-Agent

When a repo lacks `test/chimera/`, the pipeline auto-generates the fuzzing setup using a dedicated sub-agent with clean context.

#### Architecture

```
7 hunters (parallel) → DeepDiveHunter (sequential)
    │
    └── merge_invariants.py
            │
            └── Sub-agent "ChimeraBuilder" (CLEAN context):
                  Input ONLY:
                    1. Contract source code (raw file)
                    2. Merged invariants list (from YAML)
                    3. 7 universal invariant definitions
                    4. Chimera template (static structure)
                  Output:
                    4 .sol files ready to compile
                  Post:
                    Compile-fix loop (max 3 attempts)
```

The sub-agent does NOT receive the hunt history, discarded hypotheses, or conversation context. Clean context = fewer hallucinations.

#### Files Generated

| File | Method | Description |
|------|--------|-------------|
| `CryticTester.sol` | Static template | Always identical: inherits Properties + TargetFunctions |
| `Setup.sol` | Semi-template | Fixed structure, sub-agent fills constructor args and deploys |
| `TargetFunctions.sol` | Sub-agent generated | Handlers for all external/public functions |
| `Properties.sol` | Sub-agent generated | 6 universal invariants + specific invariants from hunters |

#### Compile-Fix Loop

After generating the 4 files:
1. Run `forge build`
2. If fails: sub-agent reads error, fixes the file, retries
3. Maximum 3 attempts with full invariant set
4. If still fails after 3: **fallback to universal-only mode** — strip all hunter-specific invariants, keep only the 7 universal invariants, regenerate Properties.sol, retry compile (1 more attempt)
5. If universal-only ALSO fails: **BLOCK the hunt** — notify user with full error log, require manual intervention. The hunt CANNOT proceed without fuzzing. This is not an exception — it is a hard stop.

**Rationale**: "Zero exceptions" means zero exceptions. If the ChimeraBuilder cannot produce compiling code even with only 6 simple universal invariants, the contract likely has unusual compilation requirements that need human attention.

### 3. Seven Universal Invariants

These are protocol-agnostic and always generated in Properties.sol:

1. **Basic solvency**: Contract token balances remain non-negative / consistent with internal accounting
2. **No-revert on exit**: Withdrawal functions (withdraw, redeem, claim) don't revert when user has balance
3. **Supply conservation**: `totalSupply == sum(balanceOf(all_tracked_holders))`
4. **Share price monotonicity** (if ERC4626/vault): Share price doesn't decrease more than 1 wei per operation
5. **No self-destruct**: Contract continues to exist after any call
6. **Reentrancy canary**: Ghost variable detects if any function executes twice in the same tx
7. **Setup canary**: `t(true, "CANARY: setup is working")` — a known-true assertion that, if it breaks, indicates a ChimeraBuilder setup error rather than a real bug. If the canary fails, all other invariant failures in that run are suspect.

The sub-agent determines which invariants apply (e.g., #4 only if vault pattern detected) and adapts them to the specific contract's interface.

### 4. DeepDiveHunter (Nivel 2)

#### Position in Pipeline

Sequential pass AFTER the 7 parallel hunters. Not a replacement — an additional depth layer.

```
7 hunters (parallel, ~5 min each)
    │
    └── DeepDiveHunter (sequential, reads hunter results)
            Input:
              1. Top 5 converging hypotheses from all 7 hunters
              2. Full source code of 3-5 critical functions (value flow)
              3. List of already-debunked false positives
            Output:
              hyp_{Component}_DeepDiveHunter.yaml (SAME YAML schema as other hunters)
              - Maximum 5 hypotheses (deep, not broad)
              - Each with standard `solidity` field (Chimera assertions) for merge_invariants.py
              - Each with additional `poc_sketch` field (Foundry test outline, NOT consumed by merge)
              - Each with `call_stack` field (execution trace, NOT consumed by merge)
```

#### How It Differs From Other Hunters

| Aspect | 7 Existing Hunters | DeepDiveHunter |
|--------|-------------------|----------------|
| Hypothesis count | 5-10 each (broad) | Maximum 5 (deep) |
| Input | Contract code + briefing | Code + ALL hunter results |
| Focus | One domain (math/access/flow) | Cross-domain convergence |
| Output | Invariant description + Solidity body | Standard invariant Solidity body + PoC sketch + call stack |
| Methodology | Pattern matching + checklist | samczsun trace-backward |

#### Mandatory Sections in DeepDiveHunter Prompt

1. **Design Assumption Analysis**: What does the developer assume will never happen? List each assumption. For each: construct a scenario that violates it.

2. **Cross-Function State Analysis**: For each pair of critical functions: what happens if called in unexpected order? What state can A leave that makes B behave differently?

3. **Value Exit Trace** (samczsun methodology): From each point where value leaves the protocol (withdraw, redeem, liquidate, claim, transfer), trace BACKWARD: what conditions must hold? Can they be manipulated? What's the cheapest way to manipulate them?

4. **Convergence Analysis**: Where did 2+ hunters flag the same area? Why? Is there a deeper bug hiding behind the surface-level observations?

#### Integration in `run_hunt.py`

New function: `generate_deepdive_prompt(component, hunter_results)`:
- Reads all `hyp_{Component}_*.yaml` files
- Extracts hypotheses with confidence >= 50%
- **Convergence algorithm**: group hypotheses by the function name they reference in their `solidity` or `description` field. Two hypotheses "converge" if they reference the same function OR the same state variable. Rank functions by number of distinct hunters that flagged them. Top 3-5 by density = critical functions.
- Generates prompt with convergence map (which hunters flagged what, at what confidence) + full source of those functions
- **Novelty check**: the prompt explicitly lists all existing hypothesis IDs and descriptions, instructing DeepDiveHunter to NOT repeat them. Post-generation, `merge_invariants.py` deduplicates by comparing `description` fields (fuzzy match, >80% similarity = duplicate → drop).

### 5. Updated Pipeline Flow (v4)

```
run_hunt.py --component X
    │
    ├── 1. Generate context + prompts (unchanged)
    │
    ├── 2. Launch 7 hunters in parallel (unchanged)
    │      → hyp_*.yaml × 7
    │
    ├── 3. [NEW] DeepDiveHunter (sequential)
    │      ← Input: convergences from 7 hunters + critical functions
    │      → hyp_{Component}_DeepDiveHunter.yaml
    │
    ├── 4. merge_invariants.py (unchanged, includes DeepDive output)
    │
    ├── 5. [NEW] Check test/chimera/ exists?
    │      ├── YES → use existing setup
    │      └── NO → launch ChimeraBuilder sub-agent:
    │              ├── Generate 4 .sol files
    │              └── Compile-fix loop (max 3 attempts)
    │
    ├── 6. Phase 1 — Foundry 5K runs (MANDATORY, ~2 min)
    │
    ├── 7. Phase 2 — Medusa 15 min (MANDATORY)
    │
    ├── 8. Gate evaluation:
    │      ├── Invariant broken? → Phase 3 (Fork) to confirm
    │      ├── Bounty ≥ $50K? → Phase 3 (Fork) mandatory
    │      └── Otherwise → log skip, continue
    │
    └── 9. If confirmed finding → Phase 4/5 + Finding Pipeline
```

### 6. Changes Required

| Action | File | Description |
|--------|------|-------------|
| MODIFY | `CLAUDE.md` | Add mandatory fuzzing rules, auto-setup rules, DeepDiveHunter step. **Fix "6 hunters" → "7 hunters" on line 82** (pre-existing inconsistency). Add DeepDiveHunter as step 2.5 in component checklist. |
| MODIFY | `run_hunt.py` | Add `generate_deepdive_prompt()`, `check_chimera_exists()`, `parse_bounty_value()`. Do NOT add DeepDiveHunter to `HUNTER_DOMAINS` — it runs differently (sequential, not parallel). |
| MODIFY | `current_hunt.json` schema | Add `fuzzing_executed: bool` field per component (track whether Phases 1-2 actually ran, for enforcing zero-exceptions criterion). `payout` field already exists. |
| MODIFY | `hyp_template.yaml` | Add optional fields: `poc_sketch` (string), `call_stack` (string) — used only by DeepDiveHunter, ignored by other hunters and merge_invariants.py. |
| CREATE | `audit-agents/templates/chimera/CryticTester.sol.template` | Static template |
| CREATE | `audit-agents/templates/chimera/chimera_builder_prompt.md` | Prompt for ChimeraBuilder sub-agent (includes 7 universal invariant definitions + Chimera API reference) |
| CREATE | `audit-agents/templates/chimera/medusa.json.template` | Medusa config template (target contract, corpus dir, timeout) — required for auto-setup |
| CREATE | Skill: DeepDiveHunter | `audit-agents/.claude/skills/web3-deepdive-hunter/SKILL.md` |

### 7. Success Criteria

1. **No hunt completes without Phase 1 + Phase 2 fuzzing** — zero exceptions
2. **Auto-setup compiles on first or second attempt** for >80% of repos
3. **DeepDiveHunter produces at least 1 hypothesis not found by the 7 hunters** in >50% of components
4. **Time overhead per component**: +25 minutes max breakdown:
   - DeepDiveHunter LLM call: ~3 min
   - ChimeraBuilder (generate + up to 3 compile-fix iterations): ~5 min
   - Phase 1 Foundry 5K runs: ~2 min
   - Phase 2 Medusa: 15 min
   - Total: ~25 min (if auto-setup needed; ~17 min if chimera setup already exists)

### 8. Scope Limitations

- **Solidity only**: The auto-setup (ChimeraBuilder, Chimera templates, Medusa/Echidna) applies exclusively to Solidity smart contracts. For Rust/Solana, CosmWasm, and ZK circuits, the mandatory fuzzing rule still applies but must use chain-specific tools (e.g., Trident for Solana, cargo-fuzz for Rust). The auto-setup does NOT generate harnesses for non-Solidity targets — manual setup is required, and the hunt BLOCKS until fuzzing is configured.

### 9. What This Does NOT Change

- The 7 existing hunters remain unchanged (same prompts, same domains)
- The Finding Pipeline (RedTeam, ReportWriter, report_finding.py) remains unchanged
- The component checklist (12 items) remains unchanged — fuzzing is already items 9-12
- `merge_invariants.py` remains unchanged (DeepDiveHunter uses same YAML schema)
- Cross-component hunts (RULE #0.5) remain unchanged
