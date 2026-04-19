# Phase 10: Deprecate hybrid_pipeline.py

**Date**: 2026-04-19
**Type**: Deprecation (deletion)
**Scope**: 2 files deleted, 3 docs updated, 1 parity entry added

## Goal

Eliminate `audit-agents/hybrid_pipeline.py` (1,332 LOC) and its single caller
`audit-agents/run_hybrid.sh` (51 LOC). Clear one of the three remaining god-file
WARNs from the Phase 8 audit.

## Why deprecation, not splitting

- **Zero Python importers**: nothing in the codebase imports from it.
- **Single shell caller**: only `run_hybrid.sh` invokes it as a CLI.
- **No skill integration**: no `.claude/skills/` references it.
- **Never modified**: only 2 commits in history, both initial.
- **Superseded**: `run_benchmark.py` + Agent Teams covers every step it
  performed (invariant extraction, Foundry test gen, fuzz analysis, exploit
  PoC, bounty report) via specialized hunters and the finding pipeline.

Splitting would produce maintenance debt for code that nobody uses. Git
history preserves the file if anyone needs to recover it.

## Deliverables

### Files deleted

- `audit-agents/hybrid_pipeline.py`
- `audit-agents/run_hybrid.sh`

### Docs updated

- `audit-agents/FUTURE_ARCHITECTURE.md` — lines 23 and 444 mark the prompt-
  template approach as historical context, not current state.
- `AUDIT-REPORT-CONSOLIDATED.md:23` — add "(removed Phase 10)" tag to the
  existing descriptive mention.
- `WIKI.md:680` — remove the table row referencing the file.

### Parity matrix entry

Add F055 to `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:

```yaml
- id: F055
  name: "hybrid_pipeline.py (deprecated)"
  legacy_location: "audit-agents/hybrid_pipeline.py + audit-agents/run_hybrid.sh"
  modern_location: null
  migration_decision: deprecated
  notes: "Removed Phase 10 (2026-04-19). Prompt-based experiment never integrated: 0 Python importers, only run_hybrid.sh as caller, untouched since initial commit. Superseded by run_benchmark.py + Agent Teams. Git history preserves it."
```

Summary updates:
- `total_features: 54` → `55`
- `by_decision.deprecated: 14` → `15`

### Phase 8 audit refresh

Re-run `python3 audit-agents/phase_8_audit.py`. Expected: `check_size_inventory`
WARN still fires (hybrid_pipeline gone, but merge_invariants + target_monitor
remain). Debt counts decrease by 1 on the god-file line.

## Testing

- Full suite stays at **227 passed** — no test file references `hybrid_pipeline`.
- Manual: `ls audit-agents/hybrid_pipeline.py audit-agents/run_hybrid.sh` fails.
- `grep hybrid_pipeline audit-agents/ -r` returns nothing (save the historical
  doc mentions).

## Risk

Low. Zero live callers, content recoverable from git history via
`git show 5efe6b4:audit-agents/hybrid_pipeline.py`.
