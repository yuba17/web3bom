# Phase 2A — Quick Wins Design Spec

**Date:** 2026-04-18
**Roadmap phase:** 2A (first of four sub-plans splitting Phase 2 of the 8-phase optimization roadmap)
**Parent roadmap:** `docs/superpowers/specs/2026-04-17-optimization-roadmap.md`
**Parity matrix (source of truth):** `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`
**Fase 1 regression floor:** `audit-agents/tests/phase_modern/` — 19 tests must stay green.

## Goal

Migrate 8 low-risk, high-value features from the legacy `run_hunt.py` into the modern flow (`run_benchmark.py` + `plan_generator.py`). All features are already written and battle-tested in legacy; the job is to connect them to the modern entry points without regressing the Phase 1 snapshot tests.

## Scope

**In scope — 8 features:**

| ID | Feature | Group |
|----|---------|-------|
| F002 | `--hunters <subset>` CLI flag | A. CLI |
| F003 | `--domain <name>` override | A. CLI |
| F009 | `--force-regen-map`, `--force-gate=<name>` (granular, NOT global `--force`) | A. CLI |
| F019 | `query_wiki_context` — Obsidian vault search, ~2500ch injected | B. Context |
| F022 | `load_briefings` tiered (primary=1500ch, secondary=grep-targets 300ch, tertiary=omit) | B. Context |
| F024 | `generate_asset_flow_map` regex scanner (transfers/approvals/mints/balance reads) | B. Context |
| F015 | `symmetric_analyzer` — asymmetry detection (deposit/withdraw, mint/burn) | B. Context |
| F016 | `deep_flatten --critical-only` — flattened READ/WRITE/EXTERNAL trace | B. Context |

**Out of scope (belongs to 2B/2C/2D):**
- F013 Solodit (→ 2B with F014)
- F014 `apply_feedback` L8 loop (→ 2B)
- F007, F008, F026 cross-component family (→ 2C)
- F006 `--complete` integration (→ 2D)

**Out of scope entirely:**
- Deleting code from `run_hunt.py` — that's Phase 4.
- Rewriting the 8 functions — we reuse them via import.

## Architecture

### Integration map

```
run_benchmark.py (CLI)
├── --hunters SUBSET        (F002) → validates against HUNTER_DOMAINS, filters before plan
├── --domain NAME           (F003) → sets BenchmarkConfig.domain_override
├── --force-regen-map       (F009) → deletes cached component_map artifact
└── --force-gate=GATE       (F009) → passes gate name to pipeline_gate CLI

plan_generator.py
├── phase_hunter_prompt(...)
│   └── calls → context_enrichment.build_hunter_context(...)
│       ├── query_wiki_context(domain, component)              (F019)
│       ├── load_briefings_tiered(primary, secondary)          (F022)
│       ├── generate_asset_flow_map(contract_path)             (F024)
│       ├── run_symmetric_analysis(contract_path)              (F015)
│       └── run_deep_flatten(contract_path, critical_only)     (F016)
│
└── honors --domain / --hunters overrides

audit-agents/context_enrichment.py (NEW)
└── thin re-exports + orchestration over the 5 legacy functions

audit-agents/run_hunt.py (legacy)
└── untouched — we import from it
```

### Why a new `context_enrichment.py` instead of importing from `run_hunt.py`

Three reasons:

1. **Decouple the legacy entry point from its utilities.** When Phase 4 deletes `run_hunt.py`, these 5 functions must survive. Putting them behind a stable import path (`audit_agents.context_enrichment`) lets Phase 4 be a simple deletion instead of a migration.

2. **One place to test.** Phase 2A adds targeted tests; having them co-located with the import boundary avoids test coverage drifting when `run_hunt.py` goes away.

3. **Single orchestration point.** `build_hunter_context()` composes all 5 signals into a single string block appended to the hunter brief. Callers don't have to know the order or the tier logic.

### Function-by-function migration approach

| Feature | Mechanism | Effort |
|---------|-----------|--------|
| F002 | Add `--hunters` argparse flag to `run_benchmark.py`; validate against `HUNTER_DOMAINS`; filter `HUNTER_DOMAINS` to the subset before passing to `plan_generator`. | XS |
| F003 | Add `--domain` argparse flag; thread through `BenchmarkConfig.domain_override`; `phase_hunter_prompt` prefers override over auto-detect. | XS |
| F009 | Add two granular flags. `--force-regen-map` deletes the cached `component_map_*.json` before plan generation. `--force-gate=<name>` passes the gate to `pipeline_gate.py --force <name>` (requires small `pipeline_gate.py` change to accept the flag). | S |
| F019 | Move `query_wiki_context` body to `context_enrichment.py`; re-export from `run_hunt.py` to preserve legacy behavior; call from `phase_hunter_prompt` brief. Max 2500ch truncation preserved. | S |
| F022 | Move `load_briefings`, `load_briefing_single`, `load_grep_targets_only` to `context_enrichment.py`; expose `load_briefings_tiered(primary: list[str], secondary: list[str]) -> str`. Re-export from `run_hunt.py`. | S |
| F024 | Move `generate_asset_flow_map` to `context_enrichment.py`; re-export. Emit `asset_flow_map.md` artifact under `<session_dir>/context/<component>/` so both hunters and humans can read it. | S |
| F015 | Wrap the existing `symmetric_analyzer.py` CLI via `subprocess.run` in `context_enrichment.run_symmetric_analysis()`. Cache by contract hash to avoid re-running. | S |
| F016 | Wrap existing `deep_flatten.py` CLI via `subprocess.run`; only called when `contract_lines >= 200` (see "Selective application" below). Cache by contract hash. | S |

### Selective application for `deep_flatten` (F016)

`deep_flatten` is expensive on large files. Rule: only apply when `contract_lines >= 200`. Below threshold, skip and log "deep_flatten: skipped (<200 lines)". Threshold is a module constant (`DEEP_FLATTEN_MIN_LINES = 200`) so it's easy to tune later. No CLI flag yet — that's Phase 2 polish, not quick-win.

### Caching for symmetric + deep_flatten

Both are pure functions of the source file. Cache key = sha256 of file bytes. Cache dir = `<session_dir>/cache/context_enrichment/`. Cache miss → run subprocess → write result. Cache hit → read result. Simple, filesystem-based, no invalidation logic needed (a new session gets a new cache dir).

### Data flow for a single hunter prompt

1. `phase_hunter_prompt(component, ..., hunter_name)` called.
2. Resolve `contract_path` for the component (existing logic).
3. Call `build_hunter_context(contract_path, domain, component)` → returns a single markdown string.
4. Append to the existing hunter brief template.
5. Write prompt file.

`build_hunter_context` internally:
```python
def build_hunter_context(
    contract_path: Path,
    domain: str,
    component: str,
    *,
    hunters_subset: set[str] | None = None,    # F002 filter reaches here for log parity only
) -> str:
    sections = []
    sections.append(query_wiki_context(domain, component))            # F019
    sections.append(load_briefings_tiered([domain], [...]))           # F022
    sections.append(generate_asset_flow_map(contract_path))           # F024
    sections.append(run_symmetric_analysis(contract_path))            # F015
    if contract_lines(contract_path) >= DEEP_FLATTEN_MIN_LINES:
        sections.append(run_deep_flatten(contract_path))              # F016
    return "\n\n---\n\n".join(s for s in sections if s.strip())
```

If any single signal fails (`subprocess` error, file missing, etc.), that section is skipped with a one-line log note — the hunter still gets the other 4 signals. No hunter prompt should fail because a context-enrichment helper is unhappy.

## Error handling and failure modes

- **Invalid `--hunters` value:** fail fast at argparse level with the list of valid names. Don't run anything.
- **Invalid `--domain` value:** log a warning, proceed with override (domains are free-form strings in legacy — we preserve that permissiveness).
- **`--force-gate` name not in registry:** fail with the list of known gates.
- **Wiki vault unreachable:** `query_wiki_context` returns empty string; log `wiki: unavailable`.
- **Briefings dir missing:** same pattern; empty string.
- **`symmetric_analyzer` subprocess non-zero exit:** log stderr tail, return empty string.
- **`deep_flatten` subprocess timeout (>60s):** kill, log, return empty string. (Threshold chosen to be generous; tune later if needed.)

## Testing strategy

### Phase 1 regression floor (non-negotiable)

Before any commit touches `plan_generator.py` or `run_benchmark.py`:
```
python -m pytest audit-agents/tests/phase_modern/ -v
```
Must stay at 19/19 green. Any regression = blocker, fix before proceeding.

### New tests (`audit-agents/tests/phase_2a/`)

1. `test_hunters_subset.py` — F002: `--hunters math,access` filters `HUNTER_DOMAINS` correctly; invalid subset exits non-zero with list.
2. `test_domain_override.py` — F003: `--domain lending` is surfaced to `phase_hunter_prompt`; absent flag falls back to auto-detect (no behavior change vs. today).
3. `test_force_flags.py` — F009: `--force-regen-map` removes cache file; `--force-gate=prepass` calls `pipeline_gate.py` with the right args.
4. `test_context_enrichment.py` — Unit tests per function: wiki query, briefings tiered, asset flow map, symmetric wrapper, deep_flatten wrapper. Each tests happy path + one failure path (→ empty string).
5. `test_context_enrichment_orchestration.py` — `build_hunter_context` integration: stubs the 5 sub-functions, asserts order + section separator + skip-on-empty.
6. `test_plan_generator_with_context.py` — Golden-extension: re-run `plan_generator` with wiki/briefings stubbed → new hunter prompts include the context block. If the Phase 1 plan goldens change shape, update them with `UPDATE_SNAPSHOTS=1` and commit.

### Success criteria

- 19 Phase 1 tests still pass.
- ~15–25 new Phase 2A tests pass.
- `--hunters`, `--domain`, `--force-regen-map`, `--force-gate` all visible in `run_benchmark.py --help`.
- A hunter prompt generated by the modern flow for `yieldoor/Vault` contains, at minimum:
  - wiki excerpt (if vault exists)
  - domain briefing excerpt
  - asset flow map section
  - symmetry signal section
  - deep-flatten section (Vault is >200 lines, so yes)
- Running `run_benchmark.py --hunters math` only emits prompts for the math hunter.

## Non-goals / deferred

- Deleting legacy copies in `run_hunt.py` (Phase 4).
- Full wiki ingestion loop (F014 → Phase 2B).
- Solodit integration (F013 → Phase 2B).
- `--force-gate` applied across multiple gates in one invocation (single gate only in 2A).
- Rust-language context enrichment — `build_hunter_context` short-circuits to empty for `lang=="rust"` until a Rust symmetric/flatten story exists.

## Open questions (none blocking)

None. Every call site and wrapper is mechanically driven by the parity matrix.

## File inventory

**Modified:**
- `audit-agents/run_benchmark.py` — 4 new flags + wiring
- `audit-agents/plan_generator.py` — `phase_hunter_prompt` calls `build_hunter_context`, honors `--domain` / `--hunters`
- `audit-agents/pipeline_gate.py` — accept `--force <gate>` (small)
- `audit-agents/run_hunt.py` — re-exports from `context_enrichment` to preserve legacy call sites

**Created:**
- `audit-agents/context_enrichment.py` — new orchestration module (5 function re-exports + `build_hunter_context`)
- `audit-agents/tests/phase_2a/` — directory for the 6 new test modules
- `audit-agents/tests/phase_2a/conftest.py` — shared fixtures (tmp vault, tmp briefings dir, fake contract paths)

**Unchanged:**
- `audit-agents/symmetric_analyzer.py`, `audit-agents/deep_flatten.py` — we wrap, don't edit.
- `audit-agents/tests/phase_modern/` — used as the regression floor.

## Branch / commit strategy

Fase 0 + 1 precedent: work directly on `main`. Worktree attempted and abandoned (27 untracked deltas in main make the worktree baseline inconsistent — out of scope to clean up here).

Commits: one per task from the implementation plan, TDD style (test first, implementation, refactor). Commit messages follow the Fase 1 pattern (`feat:`, `test:`, `refactor:`).
