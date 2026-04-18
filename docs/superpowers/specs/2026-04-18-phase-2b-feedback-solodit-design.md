# Phase 2B — Solodit → Wiki + Apply Feedback Loop Design Spec

**Date:** 2026-04-18
**Roadmap phase:** 2B (second of four sub-plans splitting Phase 2 of the 8-phase optimization roadmap)
**Parent roadmap:** `docs/superpowers/specs/2026-04-17-optimization-roadmap.md`
**Parity matrix (source of truth):** `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`
**Predecessor:** `docs/superpowers/specs/2026-04-18-phase-2a-quickwins-design.md` (completed 2026-04-18)
**Regression floors:**
- `audit-agents/tests/phase_modern/` — 19 tests (Phase 1 snapshot).
- `audit-agents/tests/phase_2a/` — 50 tests (Phase 2A migration).

## Goal

Consolidate external knowledge sources into a single Obsidian vault that `query_wiki_context` (wired in Phase 2A) already reads, and migrate the legacy L8 feedback loop (`apply_feedback.py`) into the modern benchmark flow as an opt-in end-of-run step. After Phase 2B, hunter briefs see Solodit corpus through the same vault path they already use for curated concepts, and real hunts can opt into feedback ingestion without benchmarks ever polluting the corpus.

## Scope

**In scope — 3 migrations + 1 deprecation:**

| ID | Feature | Mechanism |
|----|---------|-----------|
| F013 | Solodit reports search | **Deprecate.** Wiki + rejection_rules already cover the value. Parity matrix updated with rationale. |
| (new) | Solodit → Wiki one-shot ingestion | New script `solodit_to_wiki.py` converts `knowledge/solodit_cards/*.yaml` → `~/obsidian-vault/web3-audit/solodit/*.md` (one page per category). `query_wiki_context` picks them up organically — zero orchestrator changes. |
| F014 | `apply_feedback` L8 loop | `--knowledge-dir` + `--vault-dir` overrides for testability; `run_benchmark.py --apply-feedback` opt-in flag invokes it once at end-of-run via subprocess. |

**Out of scope (belongs to 2C / 2D / 4):**
- F007, F008, F026 cross-component family (→ 2C).
- F006 `--complete` orchestration (→ 2D).
- Deleting legacy Solodit code (`solodit_search.py`, `solodit.db`, `build_solodit_index.py`) — Phase 4.
- Deleting `apply_feedback` call sites in `run_hunt.py` — Phase 4.

**Out of scope entirely:**
- Rebuilding or re-ingesting Solodit DB (`solodit.db`). Manual cadence.
- Browser UI for reviewing ingested findings.
- Auto-scheduling `solodit_to_wiki.py` (manual or future CI).

## Architecture

### Integration map

```
┌─────────────────────────────────────────────────────────────┐
│ One-shot (manual / CI, independent of benchmark runs):     │
│                                                             │
│  knowledge/solodit_cards/*.yaml (48 YAMLs, 12 categories)  │
│          │                                                  │
│          ▼                                                  │
│  audit-agents/solodit_to_wiki.py   (NEW)                    │
│          │  group by category, merge 4 source files        │
│          │  into one Obsidian page per category             │
│          ▼                                                  │
│  ~/obsidian-vault/web3-audit/solodit/{category}.md (~12)    │
│          │                                                  │
│          ▼                                                  │
│  query_wiki_context()  ← already wired in Phase 2A.         │
│  Zero orchestrator changes.                                 │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ End-of-run (opt-in, only when --apply-feedback passed):    │
│                                                             │
│  hunt_session/hypotheses/<protocol>/*.yaml                  │
│  (pending_briefing_updates accumulated during hunt)         │
│          │                                                  │
│          ▼                                                  │
│  audit-agents/apply_feedback.py   (MODIFIED)                │
│          │  new: --knowledge-dir, --vault-dir overrides    │
│          │  defaults: real paths (knowledge/, vault/_raw)   │
│          ▼                                                  │
│  knowledge/<domain>.md + ~/obsidian-vault/.../_raw/         │
│                                                             │
│  run_benchmark.py (MODIFIED)                                │
│  - new flag: --apply-feedback (store_true, default False)   │
│  - hook: after all components complete, subprocess.run      │
│  - check=False (consistent with --force-gate pattern)       │
│  - Default benchmark behavior: flag off → no ingestion       │
└─────────────────────────────────────────────────────────────┘
```

### Why deprecate F013 instead of migrating

The parity matrix carries an explicit escape hatch for F013: *"Alternativa: si wiki + rejection_rules cubren, downgrade a deprecate. Decidir tras Fase 1 tests."* Two facts make the decision:

1. **Solodit content is static.** It ships as 48 YAML cards already curated by domain and severity. Converting them into Obsidian pages pays the token cost once (at ingest) rather than every hunter prompt (runtime FTS5 query against SQLite).
2. **Phase 2A already wired `query_wiki_context`.** Putting Solodit into the vault means the same retrieval path that picks up `concepts/lending.md` now picks up `solodit/lending.md`. No new orchestrator code, no new enrichment section in `build_hunter_context`, no new test surface.

The `solodit_search.py` + `solodit.db` stack stays on disk until Phase 4's run_hunt.py cleanup, but no modern code path calls it after 2B.

### Why end-of-run instead of per-component for F014

Per-component feedback creates coupling between components in the same run: component 2's briefings benefit from component 1's findings. In a benchmark, that's detection contamination — you want each component to be evaluated against the same briefings the benchmark started with. In a long real hunt, the marginal value is small because briefings evolve slowly. End-of-run is one subprocess call, the hunt is over, and the corpus updates atomically.

If a future real-hunt use case demands per-component feedback, Phase 3+ can promote the trigger to a `--feedback-when=per-component|end-of-run` CLI flag. YAGNI for 2B.

### Solodit page format

Each category generates one markdown file with frontmatter consumable by `query_wiki_context` (which reads `summary:` from YAML frontmatter if present, else first 300 chars):

```markdown
---
name: Solodit — {Category Display}
summary: Curated Solodit findings for {category} — N incidents across M patterns
type: solodit-reference
generated: 2026-04-18
---

# Solodit references: {Category Display}

## Existing patterns — incidents
{content from <cat>_existing_incidents.yaml, rendered as bullets}

## New patterns
{content from <cat>_new_patterns.yaml, rendered as bullets}

## Round 2 — incidents
{content from <cat>_r2_incidents.yaml, rendered as bullets}

## Round 2 — new patterns
{content from <cat>_r2_new_patterns.yaml, rendered as bullets}
```

**Filename convention** matches vault's `concepts/`: underscores → dashes (`access_control` → `access-control.md`, `dex_amm` → `dex-amm.md`, `flash_loan` → `flash-loan.md`). This keeps grep discovery + `Obsidian wikilinks` consistent.

**Category list** (12): access_control, bridge, dex_amm, flash_loan, lending, oracle, proxy, signature, staking, token, vault, zk.

**Missing-file tolerance**: if a category has only 2 of the 4 source files, the page still generates with the two present sections (no empty section headers). Protects against partial corpus updates.

### `apply_feedback.py` path overrides

Current hardcoded paths (lines ~16-19 of the file):
```python
WEB3_DIR      = Path.home() / "Documents/Web3"
KNOWLEDGE_DIR = WEB3_DIR / "knowledge"
VAULT_RAW     = Path.home() / "obsidian-vault" / "web3-audit" / "_raw"
```

Changes: promote `KNOWLEDGE_DIR` and `VAULT_RAW` to overridable module-level globals, analogous to `pipeline_gate.HUNT_SESSION_DIR` established in Phase 2A. New flags:

```
--knowledge-dir PATH   Override KNOWLEDGE_DIR (default: WEB3_DIR/knowledge).
                       Used by tests and benchmark sandboxing to redirect writes.
--vault-dir PATH       Override vault root (default: ~/obsidian-vault/web3-audit).
                       VAULT_RAW becomes <vault-dir>/_raw.
```

Default behavior (no flags) is preserved. Dry-run mode is unaffected.

### `run_benchmark.py` opt-in hook

New flag, right after `--force-gate` from Phase 2A Task 10:
```
--apply-feedback   action="store_true", default=False
                   help="After all components finish, invoke apply_feedback.py once to
                         ingest pending_briefing_updates into knowledge/ and the wiki.
                         Off by default — benchmarks must not pollute the corpus."
```

Hook location: inside `main()`, after the main per-component loop ends but before the final summary / exit. Simple subprocess call:
```python
if args.apply_feedback:
    fb_cmd = [sys.executable,
              str(Path(__file__).resolve().parent / "apply_feedback.py")]
    result = subprocess.run(fb_cmd, check=False)
    if result.returncode != 0:
        logger.warning(f"apply_feedback exited {result.returncode} — corpus unchanged")
```

No path args threaded. Opt-in means "you want production corpus updated"; if you don't, you don't pass the flag. Tests mock subprocess to verify the flag behavior without touching production dirs.

## Data flow

### Solodit ingestion (one-shot)

1. Developer (or future CI job) runs `python audit-agents/solodit_to_wiki.py`.
2. Script loads `knowledge/solodit_cards/*.yaml`, 48 files.
3. For each of 12 categories: collect up to 4 source files, render a single `<category>.md` under `~/obsidian-vault/web3-audit/solodit/`.
4. Script prints a one-line summary per category: `✓ access-control.md (4 sources, 52 entries)`.
5. Exit 0 on success, non-zero on YAML parse failure.
6. Next hunter prompt generated via `plan_generator.phase_hunter_prompt` sees Solodit content through `query_wiki_context` — no code path changes.

### End-of-run feedback (opt-in)

1. Benchmark / real hunt runs N components normally via `run_benchmark.py`.
2. Each component writes its hyp YAMLs with optional `pending_briefing_updates:` blocks.
3. After the last component completes, if `--apply-feedback` was passed:
   - Subprocess `apply_feedback.py` (no args → production paths).
   - It reads all hyp YAMLs under `hunt_session/hypotheses/<protocol>/`, applies updates to `knowledge/<domain>.md`, and ingests findings into vault `_raw/`.
   - Subprocess failure is logged as warning; benchmark summary still completes.

### Benchmark default (no flag)

Steps 1-2 happen. Step 3 never runs. `knowledge/` and the vault are untouched. This matches the isolation guarantee already established for `hunt_session/` in Phase 2A.

## Error handling and failure modes

| Source | Failure | Behavior |
|---|---|---|
| `solodit_to_wiki.py` | YAML parse error on any card file | Exit non-zero, print file path + error message. No partial writes persisted (buffer, then flush at end). |
| `solodit_to_wiki.py` | Output directory not writable | Exit non-zero with mkdir error. |
| `solodit_to_wiki.py` | `--cards-dir` points to empty/missing dir | Exit non-zero with "no cards found". |
| `apply_feedback.py` `--knowledge-dir` | Path doesn't exist | Exit non-zero (existing behavior; new flag doesn't change this). |
| `apply_feedback.py` `--vault-dir` | Path doesn't exist | Same. |
| `run_benchmark.py --apply-feedback` | `apply_feedback.py` exits non-zero | Log warning at `logger.warning`, return from `main()` normally. Benchmark summary prints as usual. |
| `run_benchmark.py --apply-feedback` | `apply_feedback.py` times out (should not — no timeout enforced) | Subprocess inherits stdin/stdout; user sees progress live. No artificial timeout. |

## Testing strategy

### Regression floor (non-negotiable)

Before any commit in Phase 2B:
```
python -m pytest audit-agents/tests/phase_modern/ audit-agents/tests/phase_2a/ -q
```
Must stay at 69/69 passed.

### New tests (`audit-agents/tests/phase_2b/`)

New directory + `__init__.py` + shared `conftest.py` (fixtures for tmp card dir, tmp vault).

**`test_solodit_to_wiki.py`** — 4 tests:
1. `test_help_ok` — `--help` exits 0, mentions `--cards-dir`, `--output-dir`, `--dry-run`.
2. `test_generates_expected_categories` — feed 8 fixture YAMLs (4 cards × 2 categories), verify 2 output files with correct filenames (`access-control.md`, `lending.md`), each with all expected section headers.
3. `test_frontmatter_has_summary` — output frontmatter contains a `summary:` line with non-empty value. (Directly verifies `query_wiki_context` compatibility.)
4. `test_idempotent` — running the script twice produces byte-identical output on the second run.

**`test_apply_feedback_paths.py`** — 2 tests:
1. `test_knowledge_dir_override_redirects_writes` — given a fixture hyp file with a `pending_briefing_updates` block, invoke `apply_feedback.py --knowledge-dir <tmp> --dry-run`; verify no writes to real `knowledge/`, all updates targeted at tmp.
2. `test_vault_dir_override_redirects_writes` — same pattern for `--vault-dir`.

**`test_benchmark_feedback_flag.py`** — 2 tests:
1. `test_flag_appears_in_help` — `python run_benchmark.py --help` stdout contains `--apply-feedback`.
2. `test_flag_invokes_subprocess` — mock `subprocess.run`; run `run_benchmark.py --apply-feedback` through a minimal path (or unit-test the hook function directly) and assert one subprocess call whose argv contains `apply_feedback.py`.

### Success criteria

- Phase 2B suite: 8/8 new tests passing.
- Combined `phase_modern + phase_2a + phase_2b`: 77/77 passing.
- `python audit-agents/solodit_to_wiki.py` produces 12 pages under `~/obsidian-vault/web3-audit/solodit/`.
- A hunter prompt generated **after** Solodit ingestion, for a lending component, contains a bullet entry whose stem starts with `solodit-` in the "Prior Knowledge (Obsidian Vault)" section.
- `python audit-agents/run_benchmark.py --help | grep apply-feedback` emits one line.
- A benchmark run without `--apply-feedback` leaves `knowledge/` and `~/obsidian-vault/web3-audit/` mtimes unchanged.

## Non-goals / deferred

- Splitting `solodit/` pages by severity (critical/high/medium). G1 would have been per-card; G2's per-category is the chosen density.
- Mixing Solodit into existing `concepts/<domain>.md` pages. G3 was rejected because it touches curated content and idempotency becomes fragile.
- Per-component feedback trigger (T1). See "Why end-of-run" section above.
- Rust feedback ingestion — `apply_feedback` already handles any hyp YAML regardless of language, no Rust-specific work needed.
- `--apply-feedback-dry-run` flag on `run_benchmark.py` — the user can simply invoke `apply_feedback.py --dry-run` manually.

## Open questions (none blocking)

None. Scope is bounded by the parity matrix rows for F013 and F014 plus the user-added Solodit-into-wiki directive.

## File inventory

**Created:**
- `audit-agents/solodit_to_wiki.py` — the one-shot converter (~150 LOC).
- `audit-agents/tests/phase_2b/` — new test directory.
- `audit-agents/tests/phase_2b/__init__.py`.
- `audit-agents/tests/phase_2b/conftest.py` — shared fixtures.
- `audit-agents/tests/phase_2b/test_solodit_to_wiki.py`.
- `audit-agents/tests/phase_2b/test_apply_feedback_paths.py`.
- `audit-agents/tests/phase_2b/test_benchmark_feedback_flag.py`.

**Modified:**
- `audit-agents/apply_feedback.py` — two new flags + two module-level overrides.
- `audit-agents/run_benchmark.py` — one new flag + end-of-run hook.
- `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` — F013 row flipped to `deprecate` with rationale.

**Unchanged:**
- `audit-agents/run_hunt.py` (Phase 4 concern).
- `audit-agents/solodit_search.py`, `audit-agents/build_solodit_index.py`, `audit-agents/solodit.db` — legacy, untouched.
- `audit-agents/context_enrichment.py` — zero changes. `query_wiki_context` picks up the new `solodit/*.md` pages automatically.
- `audit-agents/plan_generator.py` — zero changes. Orchestrator is agnostic to vault contents.
- `audit-agents/tests/phase_modern/`, `audit-agents/tests/phase_2a/` — regression floors.

## Branch / commit strategy

Consistent with Phases 0, 1, and 2A: work directly on `main`. Worktree ruled out by 27+ pre-existing untracked deltas that make a clean worktree baseline impractical (out of scope to clean up here).

Commits: one per task from the implementation plan, TDD style (test first, implementation, refactor). Commit messages follow the Phase 2A pattern (`feat:`, `test:`, `refactor:`, `chore:`).

## Post-plan notes for Phase 2C / 2D

- Once Phase 2B commits, the vault becomes the single authoritative external-knowledge surface for the modern flow. Phase 4's run_hunt.py cleanup can delete `solodit_search.py`, `build_solodit_index.py`, and `solodit.db` with no runtime regression.
- `apply_feedback.py`'s `--knowledge-dir` / `--vault-dir` flags position Phase 5 (shared infra consolidation) to collapse the two hardcoded path constants into a single `config.py` module.
- If Phase 2C's cross-component hunts generate inter-component briefing updates, they flow through the same `pending_briefing_updates:` mechanism and are picked up by the end-of-run feedback hook with no further wiring.
