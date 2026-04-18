# Phase 2D — Component Closer (`--complete`)

**Roadmap**: Phase 2D of the 8-phase optimization roadmap (`docs/superpowers/specs/2026-04-17-optimization-roadmap.md`).
**Feature migrated**: F006 (Cierre de componente — `--complete`).
**Parity matrix**: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`.

## Goal

Close the last Phase 2 gap: the legacy `run_hunt.py --complete <COMPONENT>` flag does four things atomically that the modern pipeline does not expose as a single operation:

1. **Gate check** — run `pipeline_gate.py -c <COMPONENT> --gate all`. If any gate fails and `--force` is absent, abort.
2. **State transition** — move the component from `components_remaining` to `components_done` in `~/.claude/MEMORY/STATE/current_hunt.json`, set `current_component` to the next pending, update `last_session`, update the matching `component_map[].status = "done"`.
3. **Feedback loop** — subprocess `apply_feedback.py --hypotheses` so briefings + wiki pick up what this component taught the system.
4. **Cross-component trigger** — run the pair/chain detection (now served by `run_benchmark.run_cross_component` + `component_discovery` from Phase 2C). Skip if everything is already analyzed.

The modern flow has all four pieces individually but no orchestrator. Phase 2D adds it.

## Architecture

### New module: `audit-agents/component_closer.py`

Pure orchestrator — no prompt building, no LLM calls. Keyword-only args for consistency with `component_discovery.py`.

```python
from __future__ import annotations
from pathlib import Path
from typing import Any

def close_component(
    *,
    component: str,
    state_file: Path | None = None,
    apply_feedback: bool = True,
    cross_component: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Atomic per-component closing transition.

    Returns a dict report:
        {
            "component": str,
            "gated": bool,           # pipeline_gate all passed
            "forced": bool,          # True if gated=False but force=True allowed transition
            "state_updated": bool,   # state file mutated
            "feedback_rc": int | None,     # apply_feedback exit code, None if skipped
            "cross_triggered": bool,       # cross-component invoked
            "next_component": str | None,  # components_remaining[0] after transition, or None
            "errors": list[str],           # empty on success
        }

    Does not raise on subprocess non-zero; records in errors and returns.
    Raises ValueError if component is not in components_remaining AND not in
    components_done (caller typo). If already in components_done and not in
    components_remaining, the closer is idempotent and returns immediately.
    """
```

**Why pure**: legacy coupled to module-global `state` dict + stdout prints. The new version accepts an explicit `state_file` path (default: `~/.claude/MEMORY/STATE/current_hunt.json`), so tests can redirect to `tmp_path / "hunt.json"` without monkeypatching. Subprocess calls go through `subprocess.run` with `capture_output=True, text=True, timeout=60`; result codes are returned, not printed.

**Gate check**: calls `pipeline_gate.py` via `sys.executable` + absolute path to `audit-agents/pipeline_gate.py`. Timeout 30s (matches legacy).

**State update**: atomic write via tempfile + `shutil.move` (matches `save_hunt_state` pattern from run_hunt.py:705).

**Cross-component trigger**: for Phase 2D we do NOT embed the full `run_cross_component` (LLM-heavy). Instead, the closer records `cross_triggered = True` and returns a pending marker; the caller (`run_benchmark.py` main) decides whether to actually launch the cross-component hunt based on CLI context. In the `--complete` single-shot CLI path, we launch it inline. See CLI wiring below.

### Changes to `audit-agents/run_benchmark.py`

**New flag** (around the existing `--components` / `--auto-components` block):
- `--complete COMPONENT` — single-shot mode: run the closer and exit. Mutually exclusive with `--components` AND `--auto-components`.

**Post-parse routing** (top of `main()` before the normal benchmark path):
- If `args.complete`:
  1. Call `component_closer.close_component(component=args.complete, force=args.force)`.
  2. Print a human-readable summary of the report dict.
  3. If `cross_triggered` and cross-component should run: invoke the existing `run_cross_component(...)` helper with the now-updated state (components_done includes the just-closed component).
  4. Return 0 on success (gated or forced), 1 if gate failed and no force.

**Mutex validation**: extend the existing `_resolve_components` post-parse check so that `--complete` cannot coexist with `--components` or `--auto-components`.

**`--force` flag**: reuse if it already exists; add if not (only for gate bypass, not for arbitrary semantic).

### No changes to `plan_generator.py`

`phase_checkpoint` keeps its single job (write `findings_all.json`). Embedding the closer there would couple prompt generation to filesystem state mutation — not the right boundary. The closer is a separate concern invoked by the CLI wrapper.

### No changes to `apply_feedback.py`

The Phase 2B migration already gave it `--hypotheses` flag coverage. The closer just subprocesses it.

## Compatibility

- **`run_hunt.py`**: untouched. Its internal `--complete` path + `run_cross_component_check` remain as legacy. Phase 4 will delete them.
- **Existing benchmark invocations**: unchanged. `--complete` is a new opt-in flag; absence = old behavior.
- **State file schema**: no changes. The closer reads/writes the same fields legacy does (`components_remaining`, `components_done`, `current_component`, `last_session`, `component_map[].status`).

## Tests

All new tests under `audit-agents/tests/phase_2d/`. ~15 tests total:

- `test_scaffold.py` (2): package importable, tmp fixtures load.
- `test_close_component_gated.py` (4):
  - Gate pass → state mutated, feedback invoked, returns `gated=True`.
  - Gate fail + no force → state NOT mutated, returns `gated=False, forced=False`, exit indicator.
  - Gate fail + force=True → state mutated anyway, `forced=True`.
  - Subprocess timeout recorded in `errors`.
- `test_close_component_state.py` (4):
  - Component moves from `components_remaining` to `components_done`.
  - `component_map[].status` updated to `"done"` for matching entry.
  - `current_component` advances to `components_remaining[0]` after transition (or None).
  - Idempotent: calling twice on same component leaves state identical.
- `test_close_component_apply_feedback.py` (2):
  - `apply_feedback=False` skips the subprocess.
  - `apply_feedback=True` with stub script records exit code.
- `test_complete_flag_cli.py` (3):
  - `--complete X` + `--components Y` → argparse error (mutex).
  - `--complete X` + `--auto-components` → argparse error (mutex).
  - `--complete X` alone → invokes closer, returns 0 on gate pass (mocked).

Tests use `pytest` fixtures with a synthetic `current_hunt.json` and monkeypatched `subprocess.run` (or a tiny stub `pipeline_gate.py` / `apply_feedback.py` on PATH). Follows Phase 2A/2B/2C precedent: `rtk proxy python -m pytest`.

## Deliverables

- New file: `audit-agents/component_closer.py`.
- Modified: `audit-agents/run_benchmark.py` (flag + mutex + main routing).
- Modified: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` (F006 → `migrated`).
- New tests: `audit-agents/tests/phase_2d/` (5 test files, ~15 tests).
- Memory update: `~/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md` (2D → COMPLETA, Phase 3 → NEXT).

## Risk / Effort

- Risk: medium. State mutation is easy to get wrong — atomic write + backup is mandatory. Subprocess calls need timeouts + graceful failure (don't leave state half-updated).
- Effort: M (estimated 9 tasks, ~1 day via subagent-driven-development).

## Non-goals

- Embedding the closer automatically inside `run_benchmark.py`'s parallel-components loop (out of scope — current contract: closer is manual via `--complete`).
- Restructuring `apply_feedback.py` beyond what Phase 2B delivered.
- Per-component cross-component with the transitive chain logic fully encapsulated (reuses existing `run_cross_component` as-is; no refactor).
- Deleting legacy `--complete` from `run_hunt.py` (Phase 4).
