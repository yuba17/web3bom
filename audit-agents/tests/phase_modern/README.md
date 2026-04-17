# phase_modern snapshot tests

Snapshots the modern benchmark flow's deterministic outputs so Phase 2 migrations do not regress silently. See `docs/superpowers/specs/2026-04-17-phase-1-snapshot-tests-design.md`.

## Run

```bash
python -m pytest audit-agents/tests/phase_modern/ -v
```

## Regenerate goldens after an intentional change

```bash
UPDATE_SNAPSHOTS=1 python -m pytest audit-agents/tests/phase_modern/ -v
```

Goldens are plain JSON/YAML — review the diff in git before committing. Update mode writes cleaned output (with `ignore_keys` dropped), so committed goldens are human-reviewable.

## Add a new language (e.g., Rust)

1. Create `fixtures/rust/<benchmark>/repo_ref.txt` pointing at the Rust benchmark repo (relative to repo root).
2. Append `("rust", "<benchmark>")` to `LANGUAGE_BENCHMARK_MATRIX` at the top of each relevant test module (a single edit per file covers every parametrized test).
3. Run `UPDATE_SNAPSHOTS=1 python -m pytest ...` to generate goldens for the new combination.
4. Commit fixtures + goldens.

## Layout

```
phase_modern/
├── conftest.py              # shared fixtures: tmp_session_dir, benchmark_fixture, frozen_session_fixture, fixtures_dir
├── helpers.py               # assert_matches_golden (UPDATE_SNAPSHOTS-aware)
├── test_helpers.py          # self-tests for helpers
├── test_pipeline_gate_status.py
├── test_plan_generator_golden.py
├── test_prepass_golden.py
├── test_schemas.py
└── fixtures/
    └── <language>/<benchmark>/
        ├── repo_ref.txt     # relative path from repo root to the benchmark's source repo
        └── goldens/         # JSON/YAML reference outputs
```
