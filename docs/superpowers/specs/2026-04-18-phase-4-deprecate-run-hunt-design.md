# Phase 4 — Deprecate `run_hunt.py`

**Roadmap**: Phase 4 of the 8-phase optimization roadmap (`docs/superpowers/specs/2026-04-17-optimization-roadmap.md`).
**Precedent**: Phases 2A (F002/F003/F009/F019/F022/F024/F015/F016), 2B (F013/F014), 2C (F007/F008/F026), 2D (F006) completed 2026-04-18. Phase 3 reconciled `CLAUDE.md` on 2026-04-18. Modern pipeline (`run_benchmark.py` + Agent Teams + `component_*` / `context_enrichment` / `solodit_to_wiki` modules) is now the canonical entry point.

## Goal

Delete `audit-agents/run_hunt.py` (3962 LOC legacy coordinator) without regressing the modern pipeline. After Phase 4, `run_benchmark.py` + Agent Teams + pure helper modules are the **only** pipeline surface.

## Scope

**In scope:**
- Extraction of 3 still-used symbols from `run_hunt.py` to a new module.
- Rewire of 3 imports in `run_benchmark.py`.
- Removal of 1 subprocess call in `scope_intake.py`.
- Update of 5 error messages in `pipeline_gate.py`.
- Batch update of 4 documentation/config files (`setup.sh`, `hunt-dashboard/index.html`, `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md`, `knowledge/state-machine-modeling.md`).
- Deletion of `audit-agents/run_hunt.py`.
- Parity matrix reclassification (F012/F020/F021/F023).

**Out of scope:**
- Any product/behavioural change to the modern pipeline (identical behaviour pre/post migration).
- Refactor of the extracted functions beyond verbatim move.
- Migration of features marked `deprecate` that are NOT imported by the modern code (F001, F004, F005, F010, F011).
- Migration of F012 `--print-prompts` — deleted per brainstorm (debug utility superseded by plain-file access to `audit-agents/prompts/hunters/*.md`).
- Cleanup of orphan state files (`hunt_session/fichas/`, legacy `current_hunt.json` entries) — Phase 7's job.
- Deletion of the historical comment `Migrated from legacy run_hunt.py during Phase 2A` in `context_enrichment.py:3` — stays (it is accurate and describes historical provenance, not a live dependency).

## Execution model

**Direct edits on `main`** — precedent from Fases 2A-2D and Fase 3 (branch strategy is `main` direct). No subagent-driven-development for this phase: the changes are mechanical (module extract + import rewire + delete), the modern test suite (122 tests across `phase_modern` + `phase_2a/2b/2c/2d`) is the red-green safety net, and the parity matrix freezes the contract.

Option (1) from the brainstorm. Options (2) subagent-driven and (3) hybrid were considered and rejected: the 2-stage review overhead does not pay for ~15 localised edits with no new logic surface.

## Current dependency map

Grep of `run_hunt` across the repo (excluding `docs/` and `run_hunt.py` itself):

| File | Line(s) | Dependency kind | Fate in Phase 4 |
|---|---|---|---|
| `audit-agents/run_benchmark.py` | 1680 | `from run_hunt import load_rejection_context as _load_rej` | Rewire to `hunter_context`. |
| `audit-agents/run_benchmark.py` | 1709 | `from run_hunt import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples` | Rewire to `hunter_context`. |
| `audit-agents/run_benchmark.py` | 3696 | `from run_hunt import HUNTER_DOMAINS` | Rewire to `hunter_context`. |
| `audit-agents/run_benchmark.py` | 1438, 1849-1850 | Comments referencing `run_hunt.HUNT_SESSION_DIR` / `generate_deepdive_prompt` | Keep comments; replace `run_hunt` textual reference with `run_hunt.py (deleted Phase 4)` style note where useful. |
| `audit-agents/scope_intake.py` | 405-412 | `subprocess.run([..., "run_hunt.py", "--component", first])` | Delete block entirely (auto-dispatch eliminated). |
| `audit-agents/scope_intake.py` | 60 | Docstring mentioning `run_hunt.py and hunters can pick it up` | Rewrite: `run_benchmark.py and hunters can pick it up`. |
| `audit-agents/pipeline_gate.py` | 201, 203, 210, 221, 223 | Error messages `Run: python3 audit-agents/run_hunt.py --...` | Rewrite to `Run: python3 audit-agents/run_benchmark.py --components <C> --protocol <P> --repo <R>` (or `--auto-components` where the original was `--map-components`). |
| `audit-agents/context_enrichment.py` | 3 | Historical comment | **Keep.** |
| `audit-agents/detection_engine.py` | 168 | Comment `YAML consumable by run_hunt.py hunter prompts` | Rewrite: `YAML consumable by hunter prompts (run_benchmark.py flow)`. |
| `setup.sh` | 168 | syntax-check loop lists `run_hunt.py` | Remove `run_hunt.py` from the loop list. |
| `setup.sh` | 191 | example command `python3 audit-agents/run_hunt.py --component <Name>` | Rewrite to modern invocation. |
| `hunt-dashboard/index.html` | 372 | UI string `ejecuta run_hunt.py` | Rewrite: `ejecuta run_benchmark.py`. |
| `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md` | 20 | `run_hunt.py --init-ficha` example | Rewrite to `run_benchmark.py --components <C> --protocol <P> --repo <R>` (or drop `--init-ficha` — that feature was deprecated per F005). |
| `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md` | 91 | `run_hunt.py --complete` example | Rewrite to `run_benchmark.py --complete <C>` (Fase 2D syntax). |
| `knowledge/state-machine-modeling.md` | 557 | Textual reference `nuestro run_hunt.py` | Rewrite: `nuestro run_benchmark.py`. |
| `audit-agents/run_hunt.py` | — | 3962 LOC legacy coordinator | **DELETE**. |

`context_enrichment.py:3` is the only remaining textual reference post-Phase 4, kept intentionally as historical provenance.

## New module — `audit-agents/hunter_context.py`

Pure module containing exactly what `run_benchmark.py` still imports. Verbatim extraction from `run_hunt.py`; no refactor. Semantics unchanged.

### Exported symbols

| Symbol | Type | Responsibility | Source in legacy |
|---|---|---|---|
| `HUNTER_DOMAINS` | `dict[str, tuple[str, str]]` | Maps hunter class name → (domain_key, domain_description). Used to resolve per-hunter few-shot directory and briefing tier. | `run_hunt.py` top-level constant. |
| `load_rejection_context()` | `() -> str` | Reads `hunt_session/feedback/rejection_rules.yaml` (and any tier-specific rejection feedback files) and returns a text block injectable into hunter briefs. | `run_hunt.py.load_rejection_context`. |
| `load_few_shot_examples(domain_key: str)` | `(str) -> str` | Reads `knowledge/few_shot/<domain>/*.md` and returns concatenated examples for the given domain. | `run_hunt.py.load_few_shot_examples`. |

**Private helpers**: any module-internal helpers used by the two loaders (e.g. path resolution constants) move with them, as private `_` -prefixed symbols.

**No new dependencies.** The module imports only stdlib + `yaml` (already project-wide).

### Interface contract

- Functions are pure: output depends only on filesystem state at call time. No global mutation.
- Missing files are tolerated: loaders return `""` rather than raising. Matches current `run_hunt.py` behaviour — `run_benchmark.py:1680` already wraps `load_rejection_context()` in a `try/except Exception: _rejection_ctx = ""`.
- `HUNTER_DOMAINS` is a frozen constant; consumers treat it as read-only.

## Testing

**No new tests.** Red-green safety comes from the existing 122-test combined suite:

```
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d
```

Baseline: 122 passed. Invariant: every commit in Phase 4 leaves the suite at 122 passed.

**Per-commit protocol** (applied before marking the commit done):
1. Run the combined suite.
2. `rtk grep -rn "run_hunt" audit-agents/ --include='*.py'` — expected set of remaining matches shrinks monotonically until the final delete commit (only `context_enrichment.py:3` comment remains).
3. `rtk grep -rn "from run_hunt" audit-agents/` — after the rewire commit, expected to be empty.

**Smoke check post-delete** (final commit):
- `python3 -c "import audit_agents.run_benchmark"` — imports cleanly (or, if project layout doesn't expose the package, `python3 -c "import run_benchmark" && python3 -c "from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples"` from `audit-agents/`).
- `python3 audit-agents/run_benchmark.py --help` — exits 0, shows all Fases 2A-2D flags.
- `python3 audit-agents/scope_intake.py --help` — exits 0, no `run_hunt` symbol referenced.

## Commits (plan)

Five commits, each green under the 122-test suite:

1. **`feat(phase_4): extract hunter_context module from run_hunt.py`**
   - Create `audit-agents/hunter_context.py` (new file).
   - Rewire 3 imports in `audit-agents/run_benchmark.py` (lines 1680, 1709, 3696).
   - Leave `run_hunt.py` untouched (imports still resolve the same symbols; the module's public shape is now duplicated across both files — this is fine, next commit deletes the legacy copy).

2. **`refactor(phase_4): remove run_hunt subprocess from scope_intake`**
   - Delete block `audit-agents/scope_intake.py:405-412` (auto-dispatch to `run_hunt.py --component <first>`).
   - Rewrite docstring at line 60 to reference `run_benchmark.py`.

3. **`docs(phase_4): point pipeline_gate error messages to run_benchmark`**
   - Rewrite 5 error message strings in `audit-agents/pipeline_gate.py` (lines 201, 203, 210, 221, 223).
   - Each `Run: python3 audit-agents/run_hunt.py --component X` → `Run: python3 audit-agents/run_benchmark.py --components X --protocol <name> --repo <path>`.
   - The `--map-components` message (line 201) becomes `--auto-components`.

4. **`docs(phase_4): update setup.sh + dashboard + runbook + knowledge docs`**
   - `setup.sh`: remove `run_hunt.py` from syntax loop (line 168), rewrite example command (line 191).
   - `hunt-dashboard/index.html:372`: UI string update.
   - `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md`: 2 command examples updated to modern invocations.
   - `knowledge/state-machine-modeling.md:557`: textual reference.
   - `audit-agents/detection_engine.py:168`: comment update.
   - `audit-agents/run_benchmark.py:1438,1849-1850`: in-file comments referencing `run_hunt` updated (historical notes preserved where accurate).

5. **`feat(phase_4): delete run_hunt.py + update parity matrix`**
   - `rm audit-agents/run_hunt.py`.
   - Update `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
     - F012 `--print-prompts`: `keep_standalone` → `deprecated` (reason: "superseded by direct file access to prompts/hunters/*.md; removed in Phase 4").
     - F020 rejection rules: `deprecate` → `migrated` (reason: "extracted to hunter_context.py in Phase 4").
     - F021 few-shot examples: `deprecate` → `migrated` (reason: "extracted to hunter_context.py in Phase 4").
     - F023 hunter selection by code features: `deprecate` → `migrated` (only the `HUNTER_DOMAINS` constant was actually used by the modern flow; extracted to `hunter_context.py`).
     - Summary `by_decision` block regenerated to reflect new counts.

Each commit's `Co-Authored-By:` line follows the Fase 2D template.

## Risk / Effort

- **Risk: medium-low.** The rewire in `run_benchmark.py` is the only path with regression risk; it's covered by the `phase_modern` suite (which exercises the benchmark end-to-end with `_llm` monkeypatched). `scope_intake.py` is uncovered by tests, but the change is a pure deletion of side-effect IO — the previous behaviour (auto-scaffold first component) is no longer needed because `run_benchmark.py` scaffolds on demand inside `build_hunter_brief`.
- **Effort: M.** ~15-20 localised edits + 5 commits + parity matrix update + memory roadmap update. No design work.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Silent regression in `run_benchmark.py` after import rewire. | `phase_modern` suite (monkeypatched LLM) covers the brief-building path that uses `load_rejection_context` + `load_few_shot_examples`. 122/122 required before each commit. |
| `hunter_context.py` extraction misses a transitive helper. | First commit includes only the extraction; `import` smoke check (`python3 -c "from hunter_context import ..."`) runs before committing. If a helper is missed, `ImportError` or `NameError` surfaces immediately in the suite. |
| External caller of `run_hunt.py` outside the repo (user shell history, CI config). | User-confirmed during Phase 0 audit: no external CI; shell history is not a supported caller. Docs (`setup.sh`, `BENCHMARK_V2_RUNBOOK.md`, `hunt-dashboard`) are the only externally-visible refs and get updated in commit 4. |
| Historical comment `context_enrichment.py:3` confuses future readers. | Kept on purpose (describes provenance, not dependency). The comment does not reference a live symbol. |
| Parity matrix inconsistency post-reclassification (F020/F021/F023 now `migrated` but only their public surface moved, not the deprecated flag-level features). | Reclassification is limited to the 3 specific feature IDs in the matrix; other deprecated features (F001/F004/F005/etc.) remain `deprecated` because their CLI surface disappears with `run_hunt.py` itself. |

## Deliverables

- Created: `audit-agents/hunter_context.py`.
- Modified: `audit-agents/run_benchmark.py`, `audit-agents/scope_intake.py`, `audit-agents/pipeline_gate.py`, `audit-agents/detection_engine.py`, `setup.sh`, `hunt-dashboard/index.html`, `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md`, `knowledge/state-machine-modeling.md`.
- Deleted: `audit-agents/run_hunt.py`.
- Updated: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` (F012/F020/F021/F023 + summary).
- Memory update: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md` — Phase 4 → ✅ COMPLETA, Phase 5 → 🔜 NEXT, append "Fase 4 — resumen al cerrar" section.

## Non-goals

- Any logic refactor inside the 3 extracted functions.
- Tests for `hunter_context.py` itself — the existing `phase_modern` + `phase_2*` suites already exercise these functions end-to-end through `run_benchmark.py`; a unit test layer would duplicate coverage without adding signal.
- Deletion of `hunt_session/fichas/` contents or legacy `current_hunt.json` fields produced by old `run_hunt.py` runs (Phase 7 orphan cleanup).
- Re-routing of the `hunt-dashboard/index.html` functionality — only the stale message string is updated.
- Touching `~/.claude/CLAUDE.md` (user-global instructions).
