# Fase 5 — Shared Infra Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract 4 duplicated path constants to `audit-agents/paths.py` and 2 duplicated state-I/O functions to `audit-agents/state_manager.py`, rewiring 19 callers and 6 callers respectively, while keeping the combined test suite green.

**Architecture:** Two new self-contained modules in `audit-agents/`. `paths.py` exports constants only (no functions). `state_manager.py` exports `load_state()` + `save_state(state, *, backup=False)` and depends only on `paths.STATE_FILE`. All migration is semantics-preserving — callers that used to back up keep backing up via `backup=True`; callers that didn't, don't.

**Tech Stack:** Python 3.11+, pathlib, json, pytest, existing repo conventions (`audit-agents/tests/phase_N/` layout from Fases 2A-2D).

---

## File Structure

**New files:**
- `audit-agents/paths.py` — 4 Path constants (`WEB3_DIR`, `AUDIT_AGENTS_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE`)
- `audit-agents/state_manager.py` — `load_state()`, `save_state(state, *, backup=False)`
- `audit-agents/tests/phase_5/__init__.py` — empty package marker
- `audit-agents/tests/phase_5/test_paths.py` — 4 tests
- `audit-agents/tests/phase_5/test_state_manager.py` — 6 tests
- `audit-agents/tests/phase_5/test_caller_integration.py` — 3 tests

**Modified files** (19 for paths, 6 of which also route through state_manager):
- Read-only callers (Task 2, 10 files): `hunter_context.py`, `context_enrichment.py`, `invariant_rag.py`, `claude_classify.py`, `solodit_to_wiki.py`, `migrate_hunt_session.py`, `solodit_search.py`, `build_solodit_index.py`, `add_finding.py`, `merge_invariants.py`
- State-writer callers (Task 3, 9 files): `run_benchmark.py`, `pipeline_gate.py`, `apply_feedback.py`, `scope_intake.py`, `benchmark.py`, `report_finding.py`, `submit_finding.py`, `sync_state.py`, `component_closer.py`
- state_manager routing (Tasks 5-7, 6 files): `pipeline_gate.py`, `merge_invariants.py`, `sync_state.py`, `submit_finding.py`, `report_finding.py`, `component_closer.py`
- Parity matrix (Task 8): `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

**Untouched (explicit):**
- `constants.py` — scope BR, no paths mixed in.
- `target_monitor.py` — `STATE_FILE` apunta a otro archivo (`data/state.json`).
- `bounty_scanner.py` — `CACHE_DIR` local one-off.
- Files with `< 3` references: `REPORTS_DIR`, `KNOWLEDGE_DIR`, `VAULT_RAW`, `BENCHMARKS_DIR` keep their local definitions.

---

## Task 0: Baseline verification

**Files:** none.

- [ ] **Step 1: Verify current suite is green**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q`

Expected: `122 passed`.

If not 122, stop and report the delta to the user. Do not proceed until baseline is verified green.

- [ ] **Step 2: Confirm working tree has no unrelated staged changes that would dilute Phase 5 commits**

Run: `git status --porcelain | head -40`

Expected: note any pre-existing uncommitted files. Per the precedent from Fases 2A-2D / 3 / 4, these may be absorbed into Task 8's final commit. Just record the delta for the commit message.

---

## Task 1: Scaffold `paths.py` + test suite

**Files:**
- Create: `audit-agents/paths.py`
- Create: `audit-agents/tests/phase_5/__init__.py`
- Create: `audit-agents/tests/phase_5/test_paths.py`

- [ ] **Step 1: Write the failing tests**

Create `audit-agents/tests/phase_5/test_paths.py`:

```python
"""Phase 5 — canonical path constants."""
from pathlib import Path

from paths import (
    WEB3_DIR,
    AUDIT_AGENTS_DIR,
    HUNT_SESSION_DIR,
    STATE_FILE,
)


def test_paths_are_absolute():
    assert WEB3_DIR.is_absolute()
    assert AUDIT_AGENTS_DIR.is_absolute()
    assert HUNT_SESSION_DIR.is_absolute()
    assert STATE_FILE.is_absolute()


def test_web3_dir_is_home_documents_web3():
    assert WEB3_DIR == Path.home() / "Documents" / "Web3"


def test_hunt_session_dir_under_web3():
    assert HUNT_SESSION_DIR == WEB3_DIR / "hunt_session"
    assert AUDIT_AGENTS_DIR == WEB3_DIR / "audit-agents"


def test_state_file_under_claude_memory():
    assert STATE_FILE == Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
```

Create empty `audit-agents/tests/phase_5/__init__.py`:

```python
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest audit-agents/tests/phase_5/test_paths.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'paths'`.

- [ ] **Step 3: Create `audit-agents/paths.py`**

```python
"""paths.py — Canonical path constants for the audit-agents toolchain.

Single source of truth for the 4 paths that were duplicated across 3+ files
before Phase 5. Anchored at ``Path.home() / "Documents" / "Web3"`` because
the modern flow always runs from that directory (CLAUDE.md enforces the cwd).

Consumers with < 3 definitions (REPORTS_DIR, KNOWLEDGE_DIR, VAULT_RAW,
BENCHMARKS_DIR) intentionally keep their local definitions — they are
definition-at-point-of-use, not duplication.
"""
from __future__ import annotations

from pathlib import Path

WEB3_DIR = Path.home() / "Documents" / "Web3"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest audit-agents/tests/phase_5/test_paths.py -v`

Expected: `4 passed`.

- [ ] **Step 5: Run the combined baseline to verify no regression**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `126 passed` (122 baseline + 4 new).

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/paths.py audit-agents/tests/phase_5/__init__.py audit-agents/tests/phase_5/test_paths.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_5): add paths module with 4 canonical constants

New audit-agents/paths.py exports WEB3_DIR, AUDIT_AGENTS_DIR,
HUNT_SESSION_DIR, STATE_FILE — the 4 path constants that were duplicated
across 3+ files before Phase 5. Anchored at Path.home() / "Documents/Web3"
(most common strategy: 13/16 callers).

4 tests in audit-agents/tests/phase_5/test_paths.py verify absolute,
canonical derivation, and exact STATE_FILE path.

Callers wired in Tasks 2-3 of the Phase 5 plan.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands with subject `feat(phase_5): add paths module with 4 canonical constants`.

---

## Task 2: Rewire read-only callers to `paths` (group A)

**Files modified:** `audit-agents/hunter_context.py`, `audit-agents/context_enrichment.py`, `audit-agents/invariant_rag.py`, `audit-agents/claude_classify.py`, `audit-agents/solodit_to_wiki.py`, `audit-agents/migrate_hunt_session.py`, `audit-agents/solodit_search.py`, `audit-agents/build_solodit_index.py`, `audit-agents/add_finding.py`, `audit-agents/merge_invariants.py`.

- [ ] **Step 1: Edit `audit-agents/hunter_context.py`**

Replace lines 13-19:

```python
from pathlib import Path

import yaml

WEB3_DIR = Path.home() / "Documents/Web3"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
```

With:

```python
import yaml

from paths import WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR
```

Keep the `from __future__ import annotations` and module docstring intact.

- [ ] **Step 2: Edit `audit-agents/context_enrichment.py`**

Replace line 25 (`AUDIT_AGENTS_DIR = Path(__file__).resolve().parent  # /home/kali/Documents/Web3/audit-agents`) and line 136 (`WEB3_DIR = Path(__file__).resolve().parents[1]  # /home/kali/Documents/Web3`) with a single import at the top of the module (after existing imports around line 19):

Add after the last `import` line at the top of the file:

```python
from paths import WEB3_DIR, AUDIT_AGENTS_DIR
```

Delete line 25 (`AUDIT_AGENTS_DIR = Path(__file__).resolve().parent  # ...`) and line 136 (`WEB3_DIR = Path(__file__).resolve().parents[1]  # ...`).

- [ ] **Step 3: Edit `audit-agents/invariant_rag.py`**

Replace lines 26-28:

```python
SCRIPT_DIR = Path(__file__).resolve().parent
WEB3_DIR = SCRIPT_DIR.parent
INDEX_PATH = SCRIPT_DIR / "invariant_rag.json"
```

With:

```python
from paths import WEB3_DIR, AUDIT_AGENTS_DIR

SCRIPT_DIR = AUDIT_AGENTS_DIR
INDEX_PATH = SCRIPT_DIR / "invariant_rag.json"
```

Rationale: keeps `SCRIPT_DIR` available as the existing name so callers in the file don't need renaming.

- [ ] **Step 4: Edit `audit-agents/claude_classify.py`**

Replace line 32 (`WEB3_DIR = Path.home() / "Documents/Web3"`) with:

```python
from paths import WEB3_DIR
```

Place the import near the top of the module with the other imports.

- [ ] **Step 5: Edit `audit-agents/solodit_to_wiki.py`**

Replace line 18 (`WEB3_DIR = Path(__file__).resolve().parents[1]`) with:

```python
from paths import WEB3_DIR
```

Place with the other imports.

- [ ] **Step 6: Edit `audit-agents/migrate_hunt_session.py`**

Replace line 13 (`WEB3_DIR = Path.home() / "Documents" / "Web3"`) with:

```python
from paths import WEB3_DIR
```

- [ ] **Step 7: Edit `audit-agents/solodit_search.py`**

Replace line 23 (`WEB3_DIR = Path.home() / "Documents/Web3"`) with:

```python
from paths import WEB3_DIR
```

- [ ] **Step 8: Edit `audit-agents/build_solodit_index.py`**

Replace line 18 (`WEB3_DIR = Path.home() / "Documents/Web3"`) with:

```python
from paths import WEB3_DIR
```

- [ ] **Step 9: Edit `audit-agents/add_finding.py`**

Replace line 20 (`WEB3_DIR = Path.home() / "Documents/Web3"`) with:

```python
from paths import WEB3_DIR
```

- [ ] **Step 10: Edit `audit-agents/merge_invariants.py`**

Replace lines 51-52:

```python
WEB3_DIR = Path.home() / "Documents/Web3"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
```

With:

```python
from paths import WEB3_DIR, HUNT_SESSION_DIR
```

Leave line 58 (`STATE_FILE = ...`) for now — it is rewired in Task 3 along with the other state-writer callers.

- [ ] **Step 11: Run combined suite to verify no regression**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `126 passed`.

- [ ] **Step 12: Smoke-check the top-level CLIs still import**

Run: `python3 audit-agents/run_benchmark.py --help > /dev/null && echo OK`

Expected: `OK` (the read-only callers are imported transitively via `run_benchmark.py`).

Run: `python3 audit-agents/merge_invariants.py --help 2>&1 | head -3`

Expected: no `ImportError` in output.

- [ ] **Step 13: Commit**

```bash
rtk git add audit-agents/hunter_context.py audit-agents/context_enrichment.py audit-agents/invariant_rag.py audit-agents/claude_classify.py audit-agents/solodit_to_wiki.py audit-agents/migrate_hunt_session.py audit-agents/solodit_search.py audit-agents/build_solodit_index.py audit-agents/add_finding.py audit-agents/merge_invariants.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_5): rewire read-only callers to paths module

10 files that previously defined WEB3_DIR / HUNT_SESSION_DIR /
AUDIT_AGENTS_DIR locally now import from audit-agents/paths.py. No
behaviour change — path resolution is identical. merge_invariants.py
STATE_FILE and the 9 state-writer callers wire in Task 3.

Affected: hunter_context, context_enrichment, invariant_rag,
claude_classify, solodit_to_wiki, migrate_hunt_session, solodit_search,
build_solodit_index, add_finding, merge_invariants.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 3: Rewire state-writer callers to `paths` (group B)

**Files modified:** `audit-agents/run_benchmark.py`, `audit-agents/pipeline_gate.py`, `audit-agents/apply_feedback.py`, `audit-agents/scope_intake.py`, `audit-agents/benchmark.py`, `audit-agents/report_finding.py`, `audit-agents/submit_finding.py`, `audit-agents/sync_state.py`, `audit-agents/component_closer.py`, `audit-agents/merge_invariants.py`.

- [ ] **Step 1: Edit `audit-agents/run_benchmark.py`**

Replace lines 66-69:

```python
SCRIPT_DIR = Path(__file__).resolve().parent
WEB3_DIR = SCRIPT_DIR.parent
PROMPTS_DIR = SCRIPT_DIR / "prompts"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
```

With:

```python
from paths import WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR

SCRIPT_DIR = AUDIT_AGENTS_DIR
PROMPTS_DIR = SCRIPT_DIR / "prompts"
```

Rationale: `SCRIPT_DIR` remains available for local uses (`PROMPTS_DIR`).

- [ ] **Step 2: Edit `audit-agents/pipeline_gate.py`**

Replace lines 63-65:

```python
WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
```

With:

```python
from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
```

Leave line 1207 (`REPORTS_DIR = WEB3_DIR / "reports"`) unchanged — `REPORTS_DIR` has < 3 consumers and is intentionally kept local.

- [ ] **Step 3: Edit `audit-agents/apply_feedback.py`**

Replace lines 29-33:

```python
WEB3_DIR = Path.home() / "Documents/Web3"
KNOWLEDGE_DIR = WEB3_DIR / "knowledge"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
VAULT_RAW = Path.home() / "obsidian-vault" / "web3-audit" / "_raw"
```

With:

```python
from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE

KNOWLEDGE_DIR = WEB3_DIR / "knowledge"
VAULT_RAW = Path.home() / "obsidian-vault" / "web3-audit" / "_raw"
```

`KNOWLEDGE_DIR` and `VAULT_RAW` have < 3 consumers — keep local. The `_apply_path_overrides` function (lines 36-46) that mutates `KNOWLEDGE_DIR` / `VAULT_RAW` via `global` keeps working — both remain module-level names.

- [ ] **Step 4: Edit `audit-agents/scope_intake.py`**

Replace lines 23-25:

```python
WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
```

With:

```python
from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
```

- [ ] **Step 5: Edit `audit-agents/benchmark.py`**

Replace lines 27-32:

```python
WEB3_DIR = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = WEB3_DIR / "benchmarks"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
REPORTS_DIR = WEB3_DIR / "reports"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
```

With:

```python
from paths import WEB3_DIR, AUDIT_AGENTS_DIR, HUNT_SESSION_DIR, STATE_FILE

BENCHMARKS_DIR = WEB3_DIR / "benchmarks"
REPORTS_DIR = WEB3_DIR / "reports"
```

`BENCHMARKS_DIR` and `REPORTS_DIR` have < 3 consumers — keep local.

- [ ] **Step 6: Edit `audit-agents/report_finding.py`**

Replace line 24 (`STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`) with:

```python
from paths import STATE_FILE
```

Place the import near the top of the module with other imports (after `import shutil` etc.).

- [ ] **Step 7: Edit `audit-agents/submit_finding.py`**

Replace line 34 (`STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`) with:

```python
from paths import STATE_FILE
```

- [ ] **Step 8: Edit `audit-agents/sync_state.py`**

Replace line 25 (`STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`) with:

```python
from paths import STATE_FILE
```

- [ ] **Step 9: Edit `audit-agents/component_closer.py`**

Replace line 12 (`_DEFAULT_STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`) with:

```python
from paths import STATE_FILE as _DEFAULT_STATE_FILE
```

Keep the alias name `_DEFAULT_STATE_FILE` so the existing `close_component` body (`state_file = state_file or _DEFAULT_STATE_FILE`) keeps working without edits.

- [ ] **Step 10: Edit `audit-agents/merge_invariants.py`**

Replace line 58 (`STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`) with:

```python
from paths import STATE_FILE
```

Place adjacent to the `from paths import WEB3_DIR, HUNT_SESSION_DIR` line added in Task 2 — merge the two into a single `from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE`.

- [ ] **Step 11: Run combined suite to verify no regression**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `126 passed`.

- [ ] **Step 12: Smoke-check CLIs**

Run: `python3 audit-agents/run_benchmark.py --help > /dev/null && echo OK`

Expected: `OK`.

Run: `python3 audit-agents/pipeline_gate.py --help > /dev/null && echo OK`

Expected: `OK`.

Run: `python3 audit-agents/scope_intake.py --help > /dev/null && echo OK`

Expected: `OK`.

- [ ] **Step 13: Verify no WEB3_DIR / STATE_FILE duplicates remain**

Run (should both print `1`):

```bash
grep -lE "^WEB3_DIR\s*=" audit-agents/*.py | wc -l
grep -lE "^STATE_FILE\s*=.*current_hunt" audit-agents/*.py | wc -l
```

Expected: `1` (only `paths.py`) for both. If greater than 1, stop and investigate — a caller was missed.

Exception — if `bounty_scanner.py` or `target_monitor.py` show up, they are out-of-scope (different state files / cache dirs). Re-run the exact grep above with `audit-agents/*.py` glob to isolate just the scripts.

- [ ] **Step 14: Commit**

```bash
rtk git add audit-agents/run_benchmark.py audit-agents/pipeline_gate.py audit-agents/apply_feedback.py audit-agents/scope_intake.py audit-agents/benchmark.py audit-agents/report_finding.py audit-agents/submit_finding.py audit-agents/sync_state.py audit-agents/component_closer.py audit-agents/merge_invariants.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_5): rewire state-writer callers to paths module

9 state-writer scripts plus merge_invariants.py now import WEB3_DIR /
HUNT_SESSION_DIR / STATE_FILE / AUDIT_AGENTS_DIR from audit-agents/paths.py
instead of defining them locally. Only the 4 duplicated-3x+ constants are
consolidated; REPORTS_DIR, KNOWLEDGE_DIR, VAULT_RAW, BENCHMARKS_DIR (all
< 3 consumers) stay local.

component_closer.py uses `STATE_FILE as _DEFAULT_STATE_FILE` to keep the
existing local alias so close_component() body is unchanged. The
state_file override parameter for tests keeps working.

Post-task check: WEB3_DIR and STATE_FILE are each defined in exactly 1
file (paths.py).

Task 3 finishes Eje 1 (paths consolidation). Eje 2 (state_manager)
starts in Task 4.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 4: Scaffold `state_manager.py` + test suite

**Files:**
- Create: `audit-agents/state_manager.py`
- Create: `audit-agents/tests/phase_5/test_state_manager.py`

- [ ] **Step 1: Write the failing tests**

Create `audit-agents/tests/phase_5/test_state_manager.py`:

```python
"""Phase 5 — shared state manager for current_hunt.json I/O."""
import json
from pathlib import Path

import pytest

import state_manager


@pytest.fixture
def patched_state_file(tmp_path, monkeypatch):
    target = tmp_path / "current_hunt.json"
    monkeypatch.setattr(state_manager, "STATE_FILE", target)
    return target


def test_load_state_returns_empty_if_missing(patched_state_file):
    assert state_manager.load_state() == {}


def test_load_state_returns_parsed_json(patched_state_file):
    patched_state_file.write_text(json.dumps({"x": 1, "y": [1, 2, 3]}))
    assert state_manager.load_state() == {"x": 1, "y": [1, 2, 3]}


def test_save_state_writes_atomically(patched_state_file):
    state_manager.save_state({"a": 1})
    assert patched_state_file.exists()
    assert json.loads(patched_state_file.read_text()) == {"a": 1}
    # No tmp residue
    assert not patched_state_file.with_suffix(".tmp.json").exists()


def test_save_state_creates_parent_dir(tmp_path, monkeypatch):
    deeper = tmp_path / "deep" / "nested" / "dir" / "current_hunt.json"
    monkeypatch.setattr(state_manager, "STATE_FILE", deeper)
    state_manager.save_state({"a": 1})
    assert deeper.exists()
    assert json.loads(deeper.read_text()) == {"a": 1}


def test_save_state_backup_opt_in(patched_state_file):
    patched_state_file.write_text(json.dumps({"old": True}))
    backup_path = patched_state_file.with_suffix(".backup.json")

    # Default: no backup
    state_manager.save_state({"new": 1})
    assert not backup_path.exists()

    # Explicit: backup=True creates .backup.json copy of previous state
    state_manager.save_state({"newer": 2}, backup=True)
    assert backup_path.exists()
    assert json.loads(backup_path.read_text()) == {"new": 1}


def test_save_state_cleans_tmp_on_failure(patched_state_file, monkeypatch):
    tmp_path_obj = patched_state_file.with_suffix(".tmp.json")

    def boom(self, target):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(Path, "replace", boom)

    with pytest.raises(OSError, match="simulated rename failure"):
        state_manager.save_state({"a": 1})

    assert not tmp_path_obj.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest audit-agents/tests/phase_5/test_state_manager.py -v`

Expected: FAIL with `ModuleNotFoundError: No module named 'state_manager'`.

- [ ] **Step 3: Create `audit-agents/state_manager.py`**

```python
"""state_manager.py — Single source of truth for current_hunt.json I/O.

Consolidates the 6 near-identical load_state() / save_state() variants that
lived in pipeline_gate, sync_state, submit_finding, report_finding,
merge_invariants, and component_closer before Phase 5.

Atomic write via tempfile → rename. Optional backup via `backup=True`
kwarg (opt-in) preserves the behaviour of callers that used to call
shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json")) first.

No file locks — the atomic rename already prevents corruption under
concurrent writes; no incidents observed to justify the extra complexity.
"""
from __future__ import annotations

import json
import shutil
from typing import Any

from paths import STATE_FILE


def load_state() -> dict[str, Any]:
    """Return parsed current_hunt.json, or {} if the file is absent.

    Propagates json.JSONDecodeError if the file exists but is malformed.
    """
    if not STATE_FILE.exists():
        return {}
    return json.loads(STATE_FILE.read_text())


def save_state(state: dict[str, Any], *, backup: bool = False) -> None:
    """Atomically write state to current_hunt.json.

    If backup=True and STATE_FILE exists, copy the current file to
    STATE_FILE.with_suffix(".backup.json") before the atomic rename.
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if backup and STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest audit-agents/tests/phase_5/test_state_manager.py -v`

Expected: `6 passed`.

- [ ] **Step 5: Run combined suite**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `132 passed` (122 baseline + 4 paths + 6 state_manager).

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/state_manager.py audit-agents/tests/phase_5/test_state_manager.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_5): add state_manager module for current_hunt.json I/O

New audit-agents/state_manager.py exports:
- load_state() -> dict — returns {} if file missing
- save_state(state, *, backup=False) -> None — atomic tmp→rename + optional backup

Consolidates the 6 near-identical load_state/save_state variants from
pipeline_gate, sync_state, submit_finding, report_finding,
merge_invariants, and component_closer.

No file locks — atomic rename prevents corruption; no incidents reported
to justify extra complexity. Backup is opt-in kwarg (preserves callers
that used to backup; callers that did not, do not).

6 tests in tests/phase_5/test_state_manager.py cover empty-file, parsed
JSON, atomic write, parent-dir creation, backup opt-in, tmp cleanup on
failure.

Callers wired in Tasks 5-7.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 5: Route `pipeline_gate` + `merge_invariants` through `state_manager`

**Files modified:** `audit-agents/pipeline_gate.py`, `audit-agents/merge_invariants.py`.

- [ ] **Step 1: Edit `audit-agents/pipeline_gate.py` — delegate `load_state`**

Replace lines 106-109:

```python
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}
```

With:

```python
from state_manager import load_state, save_state as _sm_save_state


```

Move the import to the top of the file with other imports. Delete the old `def load_state` definition. The re-export of `load_state` via `from state_manager import load_state` keeps `pipeline_gate.load_state` callable from other modules that used to import it from `pipeline_gate`.

- [ ] **Step 2: Edit `audit-agents/pipeline_gate.py` — delegate `_save_state`**

Replace lines 1670-1679:

```python
def _save_state(state: dict):
    """Write current_hunt.json atomically."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
        tmp.rename(STATE_FILE)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
```

With:

```python
def _save_state(state: dict):
    """Write current_hunt.json atomically (delegates to state_manager)."""
    _sm_save_state(state)
```

Note: the old code used `.tmp` suffix; the new shared module uses `.tmp.json`. This is a minor semantic change — we accept it because atomic rename is what matters, and the new suffix is more conventional. No existing test asserts on the tmp suffix.

- [ ] **Step 3: Edit `audit-agents/merge_invariants.py` — delegate `load_current_hunt`**

Replace lines 164-171:

```python
def load_current_hunt() -> dict:
    """Carga el estado del hunt activo."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {}
```

With:

```python
def load_current_hunt() -> dict:
    """Carga el estado del hunt activo. Corrupted JSON swallowed to {}."""
    import json as _json
    try:
        return load_state()
    except _json.JSONDecodeError:
        return {}
```

Add `from state_manager import load_state` to the top imports of the file. The defensive `try/except json.JSONDecodeError` preserves the swallow semantic for corrupted files — without it, `state_manager.load_state()` would raise and change behaviour. `FileNotFoundError` is not possible here because `state_manager.load_state()` returns `{}` when the file is missing.

- [ ] **Step 4: Run combined suite**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `132 passed`.

- [ ] **Step 5: Smoke-check pipeline_gate CLI**

Run: `python3 audit-agents/pipeline_gate.py --help > /dev/null && echo OK`

Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/pipeline_gate.py audit-agents/merge_invariants.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_5): route pipeline_gate + merge_invariants through state_manager

pipeline_gate.load_state is now re-exported from state_manager (no local
definition). pipeline_gate._save_state delegates to
state_manager.save_state (no backup).

merge_invariants.load_current_hunt delegates via a defensive
try/except JSONDecodeError wrapper to preserve the corrupted-JSON swallow
semantic.

No behaviour change: atomic write, {} on missing file, raise on JSON
error (swallowed in merge_invariants only, to match legacy).

Minor: pipeline_gate's tmp suffix changes from .tmp to .tmp.json (what
state_manager uses). Nothing asserts on the suffix.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 6: Route `sync_state` + `submit_finding` + `report_finding` through `state_manager` (backup=True)

**Files modified:** `audit-agents/sync_state.py`, `audit-agents/submit_finding.py`, `audit-agents/report_finding.py`.

- [ ] **Step 1: Edit `audit-agents/sync_state.py`**

Add near the top imports (after `from constants import ...`):

```python
from state_manager import load_state as _sm_load_state, save_state as _sm_save_state
```

Replace lines 40-44:

```python
def load_state() -> dict:
    if not STATE_FILE.exists():
        print("✗ current_hunt.json no encontrado")
        sys.exit(1)
    return json.loads(STATE_FILE.read_text())
```

With:

```python
def load_state() -> dict:
    """Wrapper around state_manager.load_state that exits if file missing."""
    if not STATE_FILE.exists():
        print("✗ current_hunt.json no encontrado")
        sys.exit(1)
    return _sm_load_state()
```

Rationale: sync_state is the only caller that `sys.exit(1)` on missing file. Preserve that UX wrapper around the shared manager.

Replace lines 47-57:

```python
def save_state(state: dict):
    state["last_sync"] = datetime.utcnow().isoformat() + "Z"
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

With:

```python
def save_state(state: dict):
    """Inject last_sync sidecar, then delegate to state_manager with backup."""
    state["last_sync"] = datetime.utcnow().isoformat() + "Z"
    _sm_save_state(state, backup=True)
```

Keep `datetime.utcnow()` — while it is deprecated in 3.12+, this script has not been updated and changing it is outside Phase 5 scope. If it triggers a DeprecationWarning in tests, silence via `-W ignore::DeprecationWarning` temporarily; no test currently asserts on this.

- [ ] **Step 2: Edit `audit-agents/submit_finding.py`**

Add near the top imports:

```python
from state_manager import load_state as _sm_load_state, save_state as _sm_save_state
```

Replace lines 64-79:

```python
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict):
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

With:

```python
def load_state() -> dict:
    return _sm_load_state()


def save_state(state: dict):
    _sm_save_state(state, backup=True)
```

- [ ] **Step 3: Edit `audit-agents/report_finding.py`**

Add near the top imports:

```python
from state_manager import load_state as _sm_load_state, save_state as _sm_save_state
```

Replace lines 187-200:

```python
def load_state() -> dict:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(state: dict):
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

With:

```python
def load_state() -> dict:
    return _sm_load_state()


def save_state(state: dict):
    _sm_save_state(state, backup=True)
```

- [ ] **Step 4: Run combined suite**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `132 passed`.

- [ ] **Step 5: Smoke-check the 3 CLIs**

Run: `python3 audit-agents/sync_state.py --help > /dev/null && echo OK`

Expected: `OK`.

Run: `python3 audit-agents/submit_finding.py --help > /dev/null && echo OK`

Expected: `OK`.

Run: `python3 audit-agents/report_finding.py --help > /dev/null && echo OK`

Expected: `OK`.

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/sync_state.py audit-agents/submit_finding.py audit-agents/report_finding.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_5): route finding scripts through state_manager with backup=True

sync_state, submit_finding, report_finding all delegate load_state and
save_state to state_manager. All three preserve the backup=True semantic
of writing .backup.json before the rename.

sync_state keeps its last_sync sidecar injection in the wrapper — it runs
before the delegation. sync_state also keeps its sys.exit(1) on
missing-file UX (only script that exits instead of returning {}).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 7: Route `component_closer` through `state_manager` preserving `state_file` override

**Files modified:** `audit-agents/component_closer.py`.

- [ ] **Step 1: Write the integration test first (caller integration test)**

Create `audit-agents/tests/phase_5/test_caller_integration.py`:

```python
"""Phase 5 — caller integration tests that pin the rewire behaviour."""
import json
from pathlib import Path

import pytest

import state_manager


def test_pipeline_gate_load_state_is_shared_manager(monkeypatch, tmp_path):
    """After Phase 5 rewire, pipeline_gate.load_state delegates to state_manager."""
    import pipeline_gate

    target = tmp_path / "current_hunt.json"
    monkeypatch.setattr(state_manager, "STATE_FILE", target)
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", target)

    target.write_text(json.dumps({"sentinel": "shared"}))
    assert pipeline_gate.load_state() == {"sentinel": "shared"}


def test_sync_state_last_sync_sidecar_preserved(monkeypatch, tmp_path):
    """sync_state.save_state injects last_sync before delegating."""
    import sync_state

    target = tmp_path / "current_hunt.json"
    monkeypatch.setattr(state_manager, "STATE_FILE", target)
    monkeypatch.setattr(sync_state, "STATE_FILE", target)

    sync_state.save_state({"a": 1})

    written = json.loads(target.read_text())
    assert written["a"] == 1
    assert "last_sync" in written
    assert written["last_sync"].endswith("Z")


def test_component_closer_state_file_override_still_works(monkeypatch, tmp_path):
    """close_component(state_file=custom_path) writes to custom_path, not STATE_FILE."""
    import component_closer

    default_target = tmp_path / "default_current_hunt.json"
    custom_target = tmp_path / "custom" / "other_hunt.json"

    monkeypatch.setattr(state_manager, "STATE_FILE", default_target)
    monkeypatch.setattr(component_closer, "_DEFAULT_STATE_FILE", default_target)
    # Stub the gate + feedback subprocesses so the test is hermetic
    monkeypatch.setattr(component_closer, "_run_gate", lambda c: (True, ""))
    monkeypatch.setattr(component_closer, "_run_feedback", lambda: (0, ""))

    custom_target.parent.mkdir(parents=True)
    custom_target.write_text(json.dumps({
        "components_remaining": ["Foo"],
        "components_done": [],
        "component_map": [{"name": "Foo", "status": "pending"}],
    }))

    result = component_closer.close_component(
        component="Foo",
        state_file=custom_target,
        apply_feedback=False,
        cross_component=False,
    )

    assert result["state_updated"] is True
    # The custom file must have been updated
    updated = json.loads(custom_target.read_text())
    assert "Foo" in updated["components_done"]
    # The default file must NOT have been touched
    assert not default_target.exists()
```

- [ ] **Step 2: Run the new integration tests — they must fail**

Run: `python3 -m pytest audit-agents/tests/phase_5/test_caller_integration.py -v`

Expected: the first 2 tests pass already (Tasks 5 and 6 did the work). The third (`test_component_closer_state_file_override_still_works`) passes too because component_closer already supports the override. If all 3 pass on first run, that's fine — the test still locks in the behaviour for Task 7's edit. Proceed.

If the third test FAILS because `component_closer._DEFAULT_STATE_FILE` is not present as a module attribute, that indicates Task 3 Step 9 was not applied correctly — go back and fix Task 3 Step 9.

- [ ] **Step 3: Edit `audit-agents/component_closer.py` — route through state_manager when state_file == default**

Replace lines 18-31:

```python
def _load_state(state_file: Path) -> dict:
    if not state_file.exists():
        return {}
    return json.loads(state_file.read_text())


def _save_state_atomic(state_file: Path, data: dict) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=state_file.parent, suffix=".tmp", encoding="utf-8"
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = Path(tmp.name)
    shutil.move(str(tmp_path), str(state_file))
```

With:

```python
from state_manager import load_state as _sm_load_state, save_state as _sm_save_state


def _load_state(state_file: Path) -> dict:
    """Route through state_manager when state_file == default; else read directly."""
    if state_file == _DEFAULT_STATE_FILE:
        return _sm_load_state()
    if not state_file.exists():
        return {}
    return json.loads(state_file.read_text())


def _save_state_atomic(state_file: Path, data: dict) -> None:
    """Route through state_manager when state_file == default; else write directly."""
    if state_file == _DEFAULT_STATE_FILE:
        _sm_save_state(data)
        return
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=state_file.parent, suffix=".tmp", encoding="utf-8"
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = Path(tmp.name)
    shutil.move(str(tmp_path), str(state_file))
```

The import line `from state_manager import load_state as _sm_load_state, save_state as _sm_save_state` goes at the top of the file with the other imports (after `from paths import STATE_FILE as _DEFAULT_STATE_FILE`). Remove the duplicate if left inside the function.

- [ ] **Step 4: Run the phase_5 + phase_2d suites to verify no regression**

Run: `python3 -m pytest audit-agents/tests/phase_5 audit-agents/tests/phase_2d -v`

Expected: all phase_5 tests plus the 15 phase_2d tests pass. If any phase_2d test fails, it's because the `state_file` override regressed — go back to Step 3 and make sure both branches in `_load_state` and `_save_state_atomic` are correct.

- [ ] **Step 5: Run the full combined suite**

Run: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`

Expected: `135 passed` (122 baseline + 4 paths + 6 state_manager + 3 caller integration).

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/component_closer.py audit-agents/tests/phase_5/test_caller_integration.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_5): route component_closer through state_manager with state_file override

component_closer._load_state and _save_state_atomic now delegate to
state_manager when state_file == _DEFAULT_STATE_FILE (production path),
and fall through to direct-file I/O when state_file is a custom path
(test path — 15 phase_2d tests depend on this override).

3 new caller-integration tests in tests/phase_5/test_caller_integration.py:
- pipeline_gate.load_state delegates to state_manager
- sync_state.save_state preserves last_sync sidecar before delegation
- component_closer(state_file=custom) writes to custom, not STATE_FILE

Combined suite: 135/135.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

---

## Task 8: Parity matrix + roadmap memory + final smoke checks

**Files modified:** `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`, `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`.

- [ ] **Step 1: Edit the parity matrix — add F031 (paths) and F032 (state_manager)**

Open `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`. Find the `by_decision:` summary block at the bottom. Before that block, add two new feature entries (format match the existing F001-F030 structure). The exact keys depend on the schema of existing entries; check one of F020-F024 first and copy its shape.

Template (adapt to match existing schema):

```yaml
F031:
  name: "Canonical path constants"
  legacy_location: "Defined locally in 16 files with 3 different derivation strategies"
  modern_location: "audit-agents/paths.py (single source of truth)"
  status: added_phase_5
  phase_5_note: "Extracted WEB3_DIR / AUDIT_AGENTS_DIR / HUNT_SESSION_DIR / STATE_FILE from 19 callers to audit-agents/paths.py. Consumers with < 3 references kept local (REPORTS_DIR, KNOWLEDGE_DIR, VAULT_RAW, BENCHMARKS_DIR)."

F032:
  name: "Shared current_hunt.json I/O"
  legacy_location: "Duplicated load_state/save_state in 7 files (pipeline_gate, sync_state, submit_finding, report_finding, merge_invariants, component_closer, apply_feedback-read-only)"
  modern_location: "audit-agents/state_manager.py"
  status: added_phase_5
  phase_5_note: "Consolidated 6 callers through state_manager.load_state + save_state(state, *, backup=False). component_closer retains state_file override for tests via pass-through. No file locks (YAGNI). sync_state wraps with sys.exit UX and last_sync sidecar injection."
```

Update the `by_decision:` summary comment at the bottom to include `added_phase_5: 2`.

- [ ] **Step 2: Update roadmap memory — mark Fase 5 complete + Fase 6 NEXT**

Edit `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`:

1. Frontmatter `description:` line — replace the existing
   `"Fase 4 COMPLETA (2026-04-18). Siguiente Fase 5."`
   with
   `"Fase 5 COMPLETA (2026-04-18). Siguiente Fase 6."`

2. Phases table — find the row `| 5 | Shared infra consolidation | 🔜 NEXT | Refactor duplicaciones |` and replace it with:
   `| 5 | Shared infra consolidation | ✅ COMPLETA (2026-04-18) | paths.py + state_manager.py; 19+6 callers rewired; 13 tests nuevos; 8 commits |`

   Find the row `| 6 | Refactor polish | PENDING | Cleanup post-migración |` and replace `PENDING` with `🔜 NEXT`.

3. After the `## Fase 4 — resumen al cerrar` section (before `## Metodología validada`), append:

```markdown
## Fase 5 — resumen al cerrar

- **Módulos nuevos**: `audit-agents/paths.py` (4 constantes: WEB3_DIR, AUDIT_AGENTS_DIR, HUNT_SESSION_DIR, STATE_FILE) + `audit-agents/state_manager.py` (load_state, save_state con `backup: bool = False` opt-in).
- **Eje 1 (paths)**: 19 archivos rewireados a `paths.py`. Antes: WEB3_DIR definido en 16 archivos con 3 estrategias (`Path.home()`, `__file__.parent.parent`, `SCRIPT_DIR.parent`). Post: 1 definición canónica anclada en `Path.home() / "Documents/Web3"`. Consumers < 3 usos (REPORTS_DIR, KNOWLEDGE_DIR, VAULT_RAW, BENCHMARKS_DIR) conservados locales.
- **Eje 2 (state_manager)**: 6 archivos delegan su I/O de `current_hunt.json` al módulo compartido. `component_closer` mantiene override `state_file` para tests (delega cuando es default, I/O directo cuando es custom). `sync_state` conserva wrapper con `sys.exit(1)` en missing-file + inyección de `last_sync` sidecar antes de `save_state(state, backup=True)`. `merge_invariants.load_current_hunt` conserva swallow de JSON corrupto via `try/except JSONDecodeError`.
- **Eje 3 (matching)**: fuera de scope — `benchmark_score.match_finding` (integer scoring) y `benchmark.match_findings` (float similarity) tienen semánticas distintas. Se dejó para Fase 6 refactor polish.
- **No-scope explícito**: file locks (YAGNI — atomic rename ya previene corrupción), backup unificado forzado (se dejó opt-in), `target_monitor.py` (STATE_FILE apunta a otro archivo), `constants.py` (scope BR).
- **Tests nuevos**: 13 en `audit-agents/tests/phase_5/` — 4 paths + 6 state_manager + 3 caller integration (pipeline_gate load delegation, sync_state last_sync sidecar, component_closer state_file override).
- **Suite combinada**: 135/135 (phase_modern + 2a + 2b + 2c + 2d + 5).
- **Commits**: 8 — scaffold paths + test (Task 1), rewire read-only callers (Task 2), rewire state-writer callers (Task 3), scaffold state_manager + test (Task 4), route pipeline_gate + merge_invariants (Task 5), route finding scripts backup=True (Task 6), route component_closer override-preserving (Task 7), parity matrix + memory (Task 8).
- **Gotchas**: pipeline_gate `_save_state` cambió sufijo `.tmp` → `.tmp.json` (cosmético, nada asserts sobre él). `sync_state` mantiene `datetime.utcnow()` deprecado — cambio fuera de scope de Fase 5. component_closer test override verification es el pin crítico — 15 tests de Fase 2D dependen de él.
- **Spec**: `docs/superpowers/specs/2026-04-18-phase-5-shared-infra-design.md`. Plan: `docs/superpowers/plans/2026-04-18-phase-5-shared-infra.md`.
```

- [ ] **Step 3: Final smoke checks**

Run all 5 in sequence, each must exit 0:

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q
```

Expected: `135 passed`.

```bash
python3 audit-agents/run_benchmark.py --help > /dev/null && echo OK
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo OK
python3 audit-agents/scope_intake.py --help > /dev/null && echo OK
python3 audit-agents/sync_state.py --help > /dev/null && echo OK
```

Expected: 4× `OK`.

Verify uniqueness:

```bash
grep -lE "^WEB3_DIR\s*=" audit-agents/*.py | wc -l
grep -lE "^STATE_FILE\s*=.*current_hunt" audit-agents/*.py | wc -l
```

Expected: `1` and `1` (both only in `paths.py`).

- [ ] **Step 4: Commit**

```bash
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml /home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md
rtk git commit -m "$(cat <<'EOF'
docs(phase_5): update parity matrix + roadmap memory

Parity matrix: add F031 (paths consolidation) and F032 (state_manager
consolidation) with status added_phase_5.

Roadmap memory: mark Fase 5 COMPLETA, Fase 6 🔜 NEXT, append
"Fase 5 — resumen al cerrar" section documenting the 2 new modules,
19+6 caller rewires, explicit no-scope (file locks, matching, forced
backup, target_monitor, constants.py), 13 new tests, 135/135 suite,
8-commit sequence.

Per Fases 2A-2D / 3 / 4 precedent: if this commit absorbs pre-existing
uncommitted deltas from the audit-agents tree, that is accepted as
long as the main changes are the parity matrix and memory roadmap.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit lands.

- [ ] **Step 5: Verify final commit sequence**

Run: `rtk git log --oneline -10`

Expected: 8 phase_5 commits on top of the existing Fase 4 commits, latest is `docs(phase_5): update parity matrix + roadmap memory`.

---

## Post-plan: verification and end-of-phase report

- [ ] **Step 6.1: Report closing summary to user**

Match the Fase 2D / Fase 3 / Fase 4 pattern:

> **Fase 5 COMPLETA (2026-04-18)**
>
> **Consolidación de infraestructura compartida — scope ejecutado:**
>
> - **2 módulos nuevos**: `paths.py` (4 constantes) + `state_manager.py` (2 funciones).
> - **Eje 1**: 19 archivos rewireados a `paths.py`. WEB3_DIR: 16 defs → 1.
> - **Eje 2**: 6 archivos delegan I/O de `current_hunt.json` a `state_manager`. load_state/save_state: 7 defs → 1.
> - **Eje 3 (matching)**: fuera de scope, Fase 6.
> - **Tests**: 13 nuevos. Suite combinada 135/135.
> - **Commits**: 8 (Tasks 1-8, direct a `main`).
> - **No-scope explícito**: file locks (YAGNI), backup forzado, constants.py, target_monitor.
>
> **🔜 Siguiente: Fase 6 — Refactor polish.**

---

## Self-review checklist (plan author)

- [x] **Spec coverage**: every section of `2026-04-18-phase-5-shared-infra-design.md` has a task:
  - Architecture (2 modules) → Task 1 + Task 4
  - API contracts → Task 1 (paths) + Task 4 (state_manager)
  - paths migration (19 files) → Tasks 2-3
  - state_manager migration (6 callers) → Tasks 5-7
  - Testing strategy → Tasks 1, 4, 7 include the 13 tests
  - Commit sequence → matches 8 commits
  - Parity matrix + memory → Task 8
- [x] **Placeholder scan**: no TBD / TODO / "implement appropriately". Every Edit step shows the before + after code.
- [x] **Type consistency**: `load_state() -> dict[str, Any]` in state_manager, wrappers in callers return `dict`. `save_state(state, *, backup=False)` signature consistent across Tasks 4-7. `_DEFAULT_STATE_FILE` name preserved in component_closer across Tasks 3 and 7. `STATE_FILE` name preserved everywhere. `_sm_load_state` / `_sm_save_state` aliases used consistently in Tasks 5-7.
- [x] **Step granularity**: each step is one action (write test, run test, edit one file, commit). No step spans multiple files except the commit steps (which bundle related edits).
