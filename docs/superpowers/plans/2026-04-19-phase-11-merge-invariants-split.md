# Phase 11: merge_invariants.py Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 1,280-LOC `audit-agents/merge_invariants.py` god-file with a thin CLI shim + cohesive `merge/` package (7 submodules), maintaining CLI equivalence for existing subprocess callers.

**Architecture:** `merge_invariants.py` collapses to ~5 LOC that delegates to `merge.cli:main`. All logic migrates into `merge/` sub-modules split by responsibility (constants, loading, solidity, hypothesis, files, modes, cli). Zero Python importers simplifies migration — no public API to preserve.

**Tech Stack:** Python 3, stdlib argparse + pathlib, PyYAML, pytest for contract tests. Migration order: bottom-up (pure helpers first, orchestrators last).

---

## File Structure

```
audit-agents/
├─ merge_invariants.py        # Shim ~5 LOC after migration
└─ merge/                     # NEW package
   ├─ __init__.py             # Empty (internal use only)
   ├─ constants.py            # HUNTER_FILE_MAP, CROSS_COMPONENT_HUNTERS, _PRAGMA, REQUIRED_HYP_FIELDS, HUNTER_REQUIRED_TABLES
   ├─ loading.py              # Path/YAML I/O + hypothesis validation
   ├─ solidity.py             # Pure Solidity code generation helpers
   ├─ hypothesis.py           # process_hypothesis + dedup + ID extraction
   ├─ files.py                # Full .sol file generation
   ├─ modes.py                # run_split_mode, run_monolithic_mode, list_invariants, insert_into_properties_sol
   └─ cli.py                  # main() + argparse

tests/phase_11/
├─ __init__.py
└─ test_merge_shim.py          # 3 contract tests
```

**Dependency order (bottom-up):** constants → (solidity, loading) → hypothesis → files → modes → cli.

---

### Task 1: Scaffold merge/ package + constants

**Files:**
- Create: `audit-agents/merge/__init__.py`
- Create: `audit-agents/merge/constants.py`
- Modify: `audit-agents/merge_invariants.py:61-86` (remove migrated block)

- [ ] **Step 1: Create empty package init**

```bash
: > audit-agents/merge/__init__.py
```

- [ ] **Step 2: Create constants module**

Copy from `merge_invariants.py:61-86`:

```python
# audit-agents/merge/constants.py
"""Module-level constants for merge_invariants package."""

HUNTER_FILE_MAP = {
    # ... exact content from legacy lines 61-79
}

CROSS_COMPONENT_HUNTERS = {"EdgeHunter"}

_PRAGMA = "pragma solidity ^0.8.0;"

REQUIRED_HYP_FIELDS = {"id", "description", "solidity"}

HUNTER_REQUIRED_TABLES = {
    # ... exact content from legacy lines 217-233
}
```

- [ ] **Step 3: Update legacy file to re-import**

In `merge_invariants.py`, replace the constant definitions (lines 61-86 and 217-233) with:

```python
from merge.constants import (
    HUNTER_FILE_MAP,
    CROSS_COMPONENT_HUNTERS,
    _PRAGMA,
    REQUIRED_HYP_FIELDS,
    HUNTER_REQUIRED_TABLES,
)
```

- [ ] **Step 4: Verify CLI still works**

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help text prints, exit 0.

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/merge/ audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): scaffold merge/ package with constants module

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Migrate solidity.py

**Files:**
- Create: `audit-agents/merge/solidity.py`
- Modify: `audit-agents/merge_invariants.py:285-411` (remove migrated functions)

- [ ] **Step 1: Create solidity module**

Move exactly these functions from `merge_invariants.py` to `merge/solidity.py`:
- `id_to_function_name` (line 285)
- `_wrap_comment` (line 293)
- `_clean_solidity_body` (line 310)
- `_sanitize_solidity` (line 336)
- `generate_property_function` (line 344)
- `generate_optimize_function` (line 376)
- `generate_ghost_var` (line 400)

Required imports in `merge/solidity.py`:
```python
import re
from merge.constants import _PRAGMA  # only if referenced; else omit
```

- [ ] **Step 2: Replace legacy definitions with re-import**

In `merge_invariants.py`, replace the removed function bodies with:
```python
from merge.solidity import (
    id_to_function_name,
    _wrap_comment,
    _clean_solidity_body,
    _sanitize_solidity,
    generate_property_function,
    generate_optimize_function,
    generate_ghost_var,
)
```

- [ ] **Step 3: Verify CLI + imports**

Run: `python3 -c "from merge.solidity import generate_property_function; print(generate_property_function({'id':'X-01','description':'d','solidity':'t(true, \"ok\");'}, 'test'))"`
Expected: prints a property_x_01 function definition.

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help still prints.

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/solidity.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): migrate solidity helpers to merge.solidity

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Migrate loading.py

**Files:**
- Create: `audit-agents/merge/loading.py`
- Modify: `audit-agents/merge_invariants.py` (remove migrated functions)

- [ ] **Step 1: Create loading module**

Move to `merge/loading.py`:
- `get_hyp_dir` (line 54)
- `validate_hypothesis` (line 88)
- `dedup_hypotheses` (line 100)
- `detect_pragma` (line 139)
- `load_current_hunt` (line 164)
- `find_chimera_dir` (line 172)
- `find_properties_sol` (line 192)
- `load_hypothesis_file` (line 200)
- `validate_evidence_tables` (line 227)

Required imports:
```python
import sys
import yaml
from pathlib import Path

from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
from state_manager import load_state
from merge.constants import REQUIRED_HYP_FIELDS, HUNTER_REQUIRED_TABLES, _PRAGMA
```

- [ ] **Step 2: Replace legacy definitions with re-import**

```python
from merge.loading import (
    get_hyp_dir,
    validate_hypothesis,
    dedup_hypotheses,
    detect_pragma,
    load_current_hunt,
    find_chimera_dir,
    find_properties_sol,
    load_hypothesis_file,
    validate_evidence_tables,
)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from merge.loading import load_current_hunt; print(type(load_current_hunt()))"`
Expected: prints `<class 'dict'>`.

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help.

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/loading.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): migrate I/O + validation to merge.loading

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Migrate hypothesis.py

**Files:**
- Create: `audit-agents/merge/hypothesis.py`
- Modify: `audit-agents/merge_invariants.py` (remove migrated functions)

- [ ] **Step 1: Create hypothesis module**

Move to `merge/hypothesis.py`:
- `extract_existing_ids_from_dir` (line 260)
- `extract_existing_ids` (line 268)
- `process_hypothesis` (line 414)
- `_dedup_ghosts` (line 487)

Required imports:
```python
import re
from pathlib import Path

from merge.solidity import (
    generate_ghost_var,
    generate_property_function,
    generate_optimize_function,
)
from merge.loading import validate_hypothesis
```

- [ ] **Step 2: Replace legacy definitions**

```python
from merge.hypothesis import (
    extract_existing_ids,
    extract_existing_ids_from_dir,
    process_hypothesis,
    _dedup_ghosts,
)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from merge.hypothesis import extract_existing_ids; print(extract_existing_ids('/// @notice X-01: foo'))"`
Expected: prints `{'X-01'}`.

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help.

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/hypothesis.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): migrate hypothesis processing to merge.hypothesis

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5: Migrate files.py

**Files:**
- Create: `audit-agents/merge/files.py`
- Modify: `audit-agents/merge_invariants.py` (remove migrated functions)

- [ ] **Step 1: Create files module**

Move to `merge/files.py`:
- `generate_hunter_sol_file` (line 503)
- `generate_cross_component_sol_file` (line 554)
- `update_target_functions_import` (line 617)
- `clean_properties_base` (line 686)

Required imports:
```python
import re
from datetime import datetime, timezone
from pathlib import Path

from merge.constants import _PRAGMA, HUNTER_FILE_MAP
```

- [ ] **Step 2: Replace legacy definitions**

```python
from merge.files import (
    generate_hunter_sol_file,
    generate_cross_component_sol_file,
    update_target_functions_import,
    clean_properties_base,
)
```

- [ ] **Step 3: Verify**

Run: `python3 -c "from merge.files import generate_hunter_sol_file; print(generate_hunter_sol_file('Test', 'PropertiesBase', [], [], [], 'Foo')[:80])"`
Expected: prints first 80 chars of generated .sol.

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help.

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/files.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): migrate file generation to merge.files

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6: Migrate modes.py

**Files:**
- Create: `audit-agents/merge/modes.py`
- Modify: `audit-agents/merge_invariants.py` (remove migrated functions)

- [ ] **Step 1: Create modes module**

Move to `merge/modes.py`:
- `run_split_mode` (line 751)
- `insert_into_properties_sol` (line 976)
- `run_monolithic_mode` (line 1048)
- `list_invariants` (line 1130)

Required imports:
```python
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from merge.constants import HUNTER_FILE_MAP, CROSS_COMPONENT_HUNTERS, _PRAGMA
from merge.loading import load_hypothesis_file, detect_pragma, dedup_hypotheses
from merge.hypothesis import process_hypothesis, _dedup_ghosts, extract_existing_ids
from merge.files import (
    generate_hunter_sol_file,
    generate_cross_component_sol_file,
    update_target_functions_import,
    clean_properties_base,
)
```

- [ ] **Step 2: Replace legacy definitions**

```python
from merge.modes import (
    run_split_mode,
    insert_into_properties_sol,
    run_monolithic_mode,
    list_invariants,
)
```

- [ ] **Step 3: Verify CLI still works**

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: argparse help prints.

Run: `python3 audit-agents/merge_invariants.py --list 2>&1 | head -5`
Expected: runs without ImportError (may print "No se encontró Properties.sol").

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/modes.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): migrate orchestrators to merge.modes

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7: Migrate cli.py + collapse shim

**Files:**
- Create: `audit-agents/merge/cli.py`
- Rewrite: `audit-agents/merge_invariants.py` (collapse to shim)

- [ ] **Step 1: Create cli module**

Move `main()` (line 1157 to end, including `if __name__ == "__main__"` block) to `merge/cli.py`.

Required imports:
```python
import argparse
import subprocess
import sys
from pathlib import Path

from merge.loading import load_current_hunt, find_chimera_dir, find_properties_sol, get_hyp_dir
from merge.hypothesis import extract_existing_ids_from_dir
from merge.modes import run_split_mode, run_monolithic_mode, list_invariants
```

Preserve all argparse flags and flow exactly as legacy `main()`.

- [ ] **Step 2: Rewrite merge_invariants.py as shim**

Replace ENTIRE contents of `audit-agents/merge_invariants.py` with:

```python
#!/usr/bin/env python3
"""merge_invariants.py — CLI entry point. Logic in merge/ package."""
from merge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 3: Verify CLI equivalence**

Run: `python3 audit-agents/merge_invariants.py --help`
Expected: same argparse help as before migration.

Run: `wc -l audit-agents/merge_invariants.py`
Expected: ≤ 6 lines.

Run: `python3 audit-agents/merge_invariants.py --list 2>&1 | head -3`
Expected: runs without error.

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/merge/cli.py audit-agents/merge_invariants.py
rtk git commit -m "refactor(phase_11): collapse merge_invariants.py to CLI shim

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 8: Add contract tests phase_11

**Files:**
- Create: `audit-agents/tests/phase_11/__init__.py`
- Create: `audit-agents/tests/phase_11/test_merge_shim.py`

- [ ] **Step 1: Create empty package init**

```bash
: > audit-agents/tests/phase_11/__init__.py
```

- [ ] **Step 2: Write contract tests**

```python
# audit-agents/tests/phase_11/test_merge_shim.py
"""Phase 11 contract tests: merge_invariants.py shim + merge/ package."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

MERGE_SUBMODULES = [
    "merge",
    "merge.constants",
    "merge.loading",
    "merge.solidity",
    "merge.hypothesis",
    "merge.files",
    "merge.modes",
    "merge.cli",
]


def test_shim_loc_budget():
    """merge_invariants.py must remain a thin shim (<30 LOC)."""
    shim_path = Path(__file__).resolve().parent.parent.parent / "merge_invariants.py"
    loc = sum(1 for _ in shim_path.open())
    assert loc < 30, f"Shim grew to {loc} LOC — should stay below 30"


def test_merge_package_modules_importable():
    """All merge/ submodules must be importable."""
    for name in MERGE_SUBMODULES:
        importlib.import_module(name)


def test_cli_main_callable():
    """merge.cli.main must be resolvable and callable."""
    from merge.cli import main
    assert callable(main)
```

- [ ] **Step 3: Run tests**

Run: `cd audit-agents && python3 -m pytest tests/phase_11/ -v`
Expected: 3 passed.

Run full suite: `cd audit-agents && python3 -m pytest tests/ -q 2>&1 | tail -5`
Expected: 230 passed (227 previous + 3 new).

- [ ] **Step 4: Commit**

```bash
rtk git add audit-agents/tests/phase_11/
rtk git commit -m "test(phase_11): contract tests for merge_invariants shim

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 9: Update parity matrix + audit + memory

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`
- Modify: `audit-agents/phase_8_audit.py` (expected_count 227→230)
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/MEMORY.md`

- [ ] **Step 1: Add F056 to parity matrix**

Append to `features:` list:

```yaml
- id: F056
  name: "merge_invariants.py"
  legacy_location: "audit-agents/merge_invariants.py (1,280 LOC)"
  modern_location: "audit-agents/merge/ (package, 7 submodules)"
  migration_decision: migrate
  notes: "Split in Phase 11 (2026-04-19). Shim ≤6 LOC + merge/{constants,loading,solidity,hypothesis,files,modes,cli}.py. Zero Python importers preserved — only CLI subprocess callers (runner.py, plan/generator.py, plan/prompts_rust.py)."
```

Update `summary`:
- `total_features`: 55 → 56
- `by_decision.migrate`: (prev + 1)
- `added_phase_11`: 1 (new key)

Verify: `sum(by_decision.values()) == total_features`.

- [ ] **Step 2: Update phase_8_audit.py expected_count**

Edit `audit-agents/phase_8_audit.py` line containing `expected_count: int = 227`:

```python
def check_test_suite(*, root: Path, expected_count: int = 230) -> CheckResult:
```

- [ ] **Step 3: Run audit and verify god-file gone**

Run: `cd audit-agents && python3 phase_8_audit.py`
Expected: exit 0, verdict PARTIAL or better, `merge_invariants.py` no longer in god-files list (HIGH debt 12 → 11).

- [ ] **Step 4: Update roadmap memory**

Append new section to `project_optimization_roadmap.md`:

```markdown
## Fase 11 — merge_invariants.py split (2026-04-19) COMPLETA

**Goal**: Reducir merge_invariants.py (1,280 LOC) a shim CLI + paquete merge/.

**Resultado**:
- Shim: 6 LOC (merge_invariants.py)
- merge/ package: 7 submódulos (constants, loading, solidity, hypothesis, files, modes, cli)
- Tests: 230 passing (227 + 3 contract tests Phase 11)
- Audit: merge_invariants.py eliminado de god-files; HIGH debt 12 → 11
- Parity: F056 añadida, total 56 features
- Zero importer breakage: CLI equivalencia mantenida

**Backlog remanente para Phase 12+**:
- Split target_monitor.py (1,261 LOC)
- Split benchmark/component_pipeline/runner.py (1,608 LOC)
- Eje 3 matching consolidation
- Dead-code cleanup (197 LOW items)
```

Update frontmatter `description:` to mention Phase 11.

- [ ] **Step 5: Update MEMORY.md index**

Edit the roadmap line:

```markdown
- [project_optimization_roadmap.md](project_optimization_roadmap.md) — Roadmap 8 + Fases 9-11 (pipeline_gate split + hybrid deprecated + merge_invariants split) COMPLETAS (2026-04-19). PARTIAL, backlog: target_monitor + runner.py + Eje 3 + dead-code.
```

- [ ] **Step 6: Commit parity + audit + memory in one commit**

```bash
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml audit-agents/phase_8_audit.py
rtk git commit -m "chore(phase_11): bump parity + test count to 230

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

(Memory files in `~/.claude/` are outside repo — no commit needed.)

- [ ] **Step 7: Refresh audit artifacts**

Run: `cd audit-agents && python3 phase_8_audit.py > /dev/null`
Expected: generates refreshed `audit_report.json` + `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md`.

- [ ] **Step 8: Commit audit artifacts**

```bash
rtk git add audit-agents/audit_report.json docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
rtk git commit -m "chore(phase_11): refresh Phase 8 audit artifacts post-split

merge_invariants.py no longer god-file. Tests 230 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Success Criteria (end of Phase 11)

- `merge_invariants.py` ≤ 6 LOC
- `merge/` package: 7 submodules, none > 450 LOC
- Tests: 230 passing (3 new contract tests)
- Audit: `merge_invariants.py` no longer in god-file list
- Parity matrix: F056 added, arithmetic consistent
- CLI equivalence: `--help`, `--list`, `--dry-run` etc. behave identically
- Zero importer breakage: all subprocess callers (`runner.py`, `plan/generator.py`, `plan/prompts_rust.py`) work unchanged
