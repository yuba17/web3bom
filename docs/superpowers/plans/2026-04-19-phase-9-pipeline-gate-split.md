# Phase 9 — pipeline_gate.py Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `audit-agents/pipeline_gate.py` (1,982 LOC) into an 8-module `audit-agents/gate/` package + a <80 LOC shim, preserving the 224-test baseline and all public imports.

**Architecture:** Phase 6 pattern — keep `pipeline_gate.py` as a shim of `# noqa: F401` re-exports so external consumers (`run_benchmark`, `scope_intake`, tests, etc.) import unchanged. The new package lives at a different path (`audit-agents/gate/`) to avoid the Python package/file namespace collision. Each extraction is a verbatim copy — no logic changes, no renames, no signature tweaks. Topological order (leaves first) prevents import cycles.

**Tech Stack:** Python 3.11+, pytest, existing `paths.py` + `state_manager.py` from Phase 5.

---

## File Structure

**Files created:**
- `audit-agents/gate/__init__.py` — package marker, empty (all consumers use explicit submodule paths).
- `audit-agents/gate/constants.py` — `HUNTER_NAMES`, `GATE_ORDER`, `DISPLAY_GATES`, path helpers.
- `audit-agents/gate/ficha.py` — `load_ficha`, `update_ficha`.
- `audit-agents/gate/scope_master.py` — SCOPE_MASTER auto-update helpers.
- `audit-agents/gate/gates_component.py` — 13 component gate checks + `GATE_CHECKS`.
- `audit-agents/gate/gate_status.py` — JSON export + `run_gate` + `show_status` + `mark_gate`.
- `audit-agents/gate/gates_finding.py` — 7 finding gate checks + `FINDING_GATE_CHECKS`.
- `audit-agents/gate/finding_queue.py` — queue/promote/update/id-gen.
- `audit-agents/gate/cli.py` — `main()` + argparse.
- `audit-agents/tests/phase_9/__init__.py` — empty.
- `audit-agents/tests/phase_9/test_shim_reexports.py` — public-contract snapshot.

**Files modified:**
- `audit-agents/pipeline_gate.py` — progressively reduced from 1,982 LOC to <80 LOC shim.
- `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` — add F047-F054, update summary.

---

## Task 0: Baseline verification

**Files:** none (read-only).

- [ ] **Step 1: Confirm green baseline**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -m pytest audit-agents/tests/ -q
```

Expected: `224 passed, 1 warning in ~18s`. If anything else, STOP and investigate before proceeding.

- [ ] **Step 2: Confirm CLI entry point works**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help 2>&1 | head -5
echo "exit=$?"
```

Expected: argparse help text starting with `usage: pipeline_gate.py`, `exit=0`.

- [ ] **Step 3: Snapshot current LOC and structure**

Run:
```bash
cd /home/kali/Documents/Web3
wc -l audit-agents/pipeline_gate.py
ls -d audit-agents/gate 2>&1 || echo "gate/ does not exist (good)"
```

Expected: `1982 audit-agents/pipeline_gate.py` + `gate/ does not exist (good)`.

No commit for this task — it's verification only.

---

## Task 1: Extract `gate/constants.py`

**Files:**
- Create: `audit-agents/gate/__init__.py` (empty)
- Create: `audit-agents/gate/constants.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 61-101 with re-export)

- [ ] **Step 1: Create empty package marker**

```bash
cd /home/kali/Documents/Web3
mkdir -p audit-agents/gate
: > audit-agents/gate/__init__.py
```

Expected: `audit-agents/gate/__init__.py` exists and is empty.

- [ ] **Step 2: Read the source section to extract**

Use the Read tool on `audit-agents/pipeline_gate.py` lines 61-101. The section starts with the comment banner `# ─── Paths ───` and ends just before `# ─── State helpers ───` (line 103). It contains:
- `get_hyp_dir(protocol)`
- `_get_protocol()`
- `get_context_dir(protocol)`
- `get_gate_status_file(protocol)`
- `HUNTER_NAMES` (list)
- `GATE_ORDER` (list)

Note: `DISPLAY_GATES` is currently defined at line 1012 (inside the gate-status section). For this task, **leave it at line 1012** — it will move to `constants.py` in Task 5 when we extract `gate_status.py`, OR we can proactively include it here. Include it here to avoid cross-task churn.

- [ ] **Step 3: Write `gate/constants.py`**

```python
"""Constants, path helpers, and gate ordering for the pipeline_gate package.

Leaf module: depends only on stdlib + paths.HUNT_SESSION_DIR.
"""
from pathlib import Path

from paths import HUNT_SESSION_DIR, STATE_FILE


def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_protocol() -> str:
    """Read protocol from current_hunt.json; return '' if missing/unset."""
    import json
    if not STATE_FILE.exists():
        return ""
    try:
        return json.loads(STATE_FILE.read_text()).get("protocol", "")
    except json.JSONDecodeError:
        return ""


def get_context_dir(protocol: str) -> Path:
    """Return protocol-namespaced context directory."""
    d = HUNT_SESSION_DIR / "context" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_gate_status_file(protocol: str) -> Path:
    """Return protocol-specific gate_status file."""
    d = HUNT_SESSION_DIR / "gate_status"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{protocol}.json"


HUNTER_NAMES = [
    "AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
    "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
    "SignatureHunter", "DoSHunter",
]

GATE_ORDER = [
    "scope", "prepass", "hunters", "crosschain", "deepdive",
    "merge", "compile", "phase1", "phase2", "phase3", "phase4", "phase5",
    "complete",
]

DISPLAY_GATES = [g for g in GATE_ORDER if g != "complete"]
```

**Critical:** The exact text of functions must match `pipeline_gate.py:69-92` verbatim. Before pasting, run:

```bash
cd /home/kali/Documents/Web3
sed -n '69,92p' audit-agents/pipeline_gate.py
```

…and verify the function bodies in the block above match byte-for-byte. If `_get_protocol()` uses `from state_manager import load_state` instead of inline JSON, copy that style verbatim.

- [ ] **Step 4: Verify direct import works**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.constants import HUNTER_NAMES, GATE_ORDER, DISPLAY_GATES, get_hyp_dir, _get_protocol, get_context_dir, get_gate_status_file; print('OK', len(HUNTER_NAMES), len(GATE_ORDER), len(DISPLAY_GATES))"
```

Expected: `OK 9 13 12` (9 hunters, 13 gates including 'complete', 12 display gates).

- [ ] **Step 5: Replace section in `pipeline_gate.py` with re-exports**

Open `audit-agents/pipeline_gate.py` and replace lines 61-101 (the whole `# ─── Paths ───` block + HUNTER_NAMES/GATE_ORDER) with:

```python
# ─── Paths ───────────────────────────────────────────────────────────────────
from gate.constants import (  # noqa: F401  re-export
    get_hyp_dir, _get_protocol, get_context_dir, get_gate_status_file,
    HUNTER_NAMES, GATE_ORDER, DISPLAY_GATES,
)
```

Also: find the original `DISPLAY_GATES = [g for g in GATE_ORDER if g != "complete"]` at line 1012 and **delete** that line (now re-exported via the block above).

- [ ] **Step 6: Run full suite**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -m pytest audit-agents/tests/ -q
```

Expected: `224 passed`. If any fail, inspect which symbol is missing from the re-export and fix.

- [ ] **Step 7: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help 2>&1 | head -3
echo "exit=$?"
```

Expected: argparse help, `exit=0`.

- [ ] **Step 8: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/__init__.py audit-agents/gate/constants.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/constants.py

Move HUNTER_NAMES, GATE_ORDER, DISPLAY_GATES, and 4 path helpers
(get_hyp_dir, _get_protocol, get_context_dir, get_gate_status_file)
from pipeline_gate.py to gate/constants.py. Shim re-exports via
# noqa: F401. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 2: Extract `gate/ficha.py`

**Files:**
- Create: `audit-agents/gate/ficha.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 103-149 with re-export)

- [ ] **Step 1: Read the source section**

Use Read tool on `audit-agents/pipeline_gate.py` lines 103-149. Contains:
- `load_ficha(component, protocol="")` — returns dict or None
- `update_ficha(component, updates, protocol="")` — writes ficha yaml

- [ ] **Step 2: Write `gate/ficha.py`**

Copy lines 105-148 verbatim, prepended by:

```python
"""Ficha (component metadata YAML) read/write helpers.

Depends on: paths.HUNT_SESSION_DIR.
"""
import yaml
from pathlib import Path

from paths import HUNT_SESSION_DIR
```

Then append the two functions **verbatim** from the source. Double-check by:

```bash
cd /home/kali/Documents/Web3
sed -n '105,148p' audit-agents/pipeline_gate.py > /tmp/ficha_src.txt
# Then ensure your new file's function bodies match /tmp/ficha_src.txt
```

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.ficha import load_ficha, update_ficha; print('OK')"
```

Expected: `OK`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Replace lines 103-149 (the `# ─── State helpers ───` block) with:

```python
# ─── State helpers ───────────────────────────────────────────────────────────
from gate.ficha import load_ficha, update_ficha  # noqa: F401  re-export
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

- [ ] **Step 6: CLI smoke**

Run: `python3 audit-agents/pipeline_gate.py --help > /dev/null && echo ok`. Expected: `ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/ficha.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/ficha.py

Move load_ficha + update_ficha from pipeline_gate.py to gate/ficha.py.
Shim re-exports. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 3: Extract `gate/scope_master.py`

**Files:**
- Create: `audit-agents/gate/scope_master.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 731-1008 with re-exports)

**Rationale for ordering:** `scope_master` has no dependencies on `gates_component` or `gate_status`. `finding_queue` (Task 7) calls `scope_master_on_finding`, so scope_master must exist before then. Extracting early keeps the monolith shrinking predictably.

- [ ] **Step 1: Read the source section**

Use Read tool on `audit-agents/pipeline_gate.py` lines 731-1008. Contains:
- `_find_scope_master(protocol) -> Path | None`
- `_scope_master_update_component(protocol, component, add_finding=None, ...)`
- `_scope_master_update_coverage(protocol)`
- `scope_master_on_complete(protocol, component)`
- `scope_master_on_review(protocol, component)`
- `scope_master_on_finding(protocol, component, finding_id)`
- `show_scope_status()` — reads `SCOPE_MASTER_DIR` constant and `_re_module`

Also identify module-level imports that these functions rely on (look above line 731 for `import re as _re_module`, `SCOPE_MASTER_DIR = ...`, etc.).

- [ ] **Step 2: Write `gate/scope_master.py`**

The function bodies and top-level constants must be copied **verbatim**. Preserve names like `_re_module`, `SCOPE_MASTER_DIR` exactly. Header:

```python
"""SCOPE_MASTER.md auto-update helpers.

Keeps the human-readable component ledger in sync with finding/review state.
Depends on: paths.HUNT_SESSION_DIR, state_manager.load_state.
"""
import re as _re_module
import sys
from datetime import datetime
from pathlib import Path

from paths import HUNT_SESSION_DIR, WEB3_DIR
from state_manager import load_state
```

Then `SCOPE_MASTER_DIR = ...` (exact literal from source — `grep "SCOPE_MASTER_DIR\s*=" audit-agents/pipeline_gate.py` to find the assignment line) followed by the 7 functions verbatim.

**If `SCOPE_MASTER_DIR` is defined above line 731 in the original file**, keep it defined in scope_master.py only; remove the original definition from pipeline_gate.py in Step 3 (and add `SCOPE_MASTER_DIR` to the re-export list if any external consumer references it — grep first with `rtk grep "SCOPE_MASTER_DIR" audit-agents/ --include=*.py`).

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.scope_master import scope_master_on_complete, scope_master_on_finding, scope_master_on_review, show_scope_status, _find_scope_master, _scope_master_update_component, _scope_master_update_coverage; print('OK')"
```

Expected: `OK`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Replace lines 731-1008 (the `# ─── SCOPE_MASTER Auto-Update ───` block) with:

```python
# ─── SCOPE_MASTER Auto-Update ─────────────────────────────────────────────────
from gate.scope_master import (  # noqa: F401  re-export
    _find_scope_master, _scope_master_update_component,
    _scope_master_update_coverage, scope_master_on_complete,
    scope_master_on_review, scope_master_on_finding, show_scope_status,
)
```

If `SCOPE_MASTER_DIR` was defined in pipeline_gate.py before line 731, delete that line now and add `SCOPE_MASTER_DIR` to the re-export list above (between parens).

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

- [ ] **Step 6: CLI smoke + scope_status smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo help_ok
python3 -c "from pipeline_gate import scope_master_on_complete; print('reexport_ok')"
```

Expected: `help_ok` + `reexport_ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/scope_master.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/scope_master.py

Move 7 SCOPE_MASTER.md helpers (_find_scope_master,
_scope_master_update_component/coverage, scope_master_on_complete/
review/finding, show_scope_status) from pipeline_gate.py. Shim
re-exports. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 4: Extract `gate/gates_component.py`

**Files:**
- Create: `audit-agents/gate/gates_component.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 150-729 with re-exports)

- [ ] **Step 1: Read the source section**

Use Read tool on `audit-agents/pipeline_gate.py` lines 150-729. Contains 13 `check_*` functions + the `GATE_CHECKS` dict. Each function signature is `(component: str, repo: str = "") -> tuple[bool, list[str], list[str]]` (or close). Identify any module-level imports these rely on (e.g., `from pipeline_gate.constants import ...` after Task 1, or `from state_manager import load_state`).

- [ ] **Step 2: Write `gate/gates_component.py`**

Header:

```python
"""13 component-level gate checks + GATE_CHECKS dispatch.

Each check returns (ok, passed_reasons, failed_reasons).
Depends on: gate.constants, gate.ficha, state_manager, paths.HUNT_SESSION_DIR.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

from paths import HUNT_SESSION_DIR, WEB3_DIR
from state_manager import load_state

from gate.constants import HUNTER_NAMES, GATE_ORDER, get_gate_status_file, get_hyp_dir, get_context_dir
from gate.ficha import load_ficha
```

**Reconcile imports:** before writing, grep the source for every non-stdlib reference the functions make (`yaml`, `hashlib`, etc.) and include them. Run:

```bash
cd /home/kali/Documents/Web3
sed -n '150,729p' audit-agents/pipeline_gate.py | grep -E "^(import |from )" | sort -u
```

Include every import that appears.

Then paste the 13 `check_*` functions **verbatim** followed by `GATE_CHECKS = { ... }` verbatim (around line 716).

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.gates_component import check_scope, check_hunters, check_deepdive, check_crosschain, check_merge, check_compile, check_phase1, check_phase2, check_phase3, check_phase4, check_phase5, check_prepass, GATE_CHECKS; print('OK', len(GATE_CHECKS))"
```

Expected: `OK 12` (or whatever GATE_CHECKS actually contains — confirm by inspecting source).

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Replace lines 150-729 (the `# ─── Gate checks ───` block + `GATE_CHECKS` dict) with:

```python
# ─── Gate checks ─────────────────────────────────────────────────────────────
from gate.gates_component import (  # noqa: F401  re-export
    check_scope, check_hunters, check_deepdive, check_crosschain,
    check_merge, check_compile, check_phase1, check_phase2, check_phase3,
    check_phase4, check_phase5, check_prepass, GATE_CHECKS,
)
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

- [ ] **Step 6: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo help_ok
python3 -c "from pipeline_gate import check_scope, GATE_CHECKS; print('reexport_ok', len(GATE_CHECKS))"
```

Expected: `help_ok` + `reexport_ok 12`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/gates_component.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/gates_component.py

Move 13 component gate checks (check_scope/hunters/deepdive/crosschain/
merge/compile/phase1-5/prepass) + GATE_CHECKS dispatch from
pipeline_gate.py. Largest extraction (~580 LOC). Shim re-exports.
Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 5: Extract `gate/gate_status.py`

**Files:**
- Create: `audit-agents/gate/gate_status.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 1010-1192 with re-exports)

- [ ] **Step 1: Read the source section**

Use Read tool on `audit-agents/pipeline_gate.py` lines 1010-1192 (after Task 4, the line numbers have shifted — use `grep -n "def _map_gate_state\|def _load_gate_status\|def _save_gate_status\|def export_gate_status\|def run_gate\|def show_status\|def mark_gate" audit-agents/pipeline_gate.py` to re-locate).

Contains:
- `_map_gate_state(ok, detail) -> str`
- `_load_gate_status(protocol) -> dict`
- `_save_gate_status(data, protocol)`
- `export_gate_status(component, repo="")`
- `run_gate(component, gate, repo="") -> bool`
- `show_status(component, repo="")`
- `mark_gate(component, gate, protocol="")`

- [ ] **Step 2: Write `gate/gate_status.py`**

Header:

```python
"""Gate status JSON export + run_gate dispatcher + show_status + mark_gate.

Depends on: gate.constants, gate.gates_component (GATE_CHECKS),
gate.scope_master (scope_master_on_complete), state_manager.
"""
import json
import sys
from datetime import datetime
from pathlib import Path

from state_manager import load_state

from gate.constants import (
    GATE_ORDER, DISPLAY_GATES, get_gate_status_file,
)
from gate.gates_component import GATE_CHECKS
from gate.scope_master import scope_master_on_complete
```

Then paste the 7 functions **verbatim**.

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.gate_status import _map_gate_state, _load_gate_status, _save_gate_status, export_gate_status, run_gate, show_status, mark_gate; print('OK')"
```

Expected: `OK`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Find the `# ─── Gate Status JSON Export ───` block and replace it with:

```python
# ─── Gate Status JSON Export ──────────────────────────────────────────────────
from gate.gate_status import (  # noqa: F401  re-export
    _map_gate_state, _load_gate_status, _save_gate_status,
    export_gate_status, run_gate, show_status, mark_gate,
)
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

This is a critical checkpoint — `test_export_gate_status_creates_json`, `test_export_is_incremental`, and `test_gate_states_are_4_state` all exercise `export_gate_status`. If they fail, check:
1. Is `scope_master_on_complete` still callable from `gate.gate_status`?
2. Does `get_gate_status_file` get the right path?
3. Are test monkeypatches on `pipeline_gate.HUNT_SESSION_DIR` still effective? (They should be — the shim re-exports `HUNT_SESSION_DIR` from `paths`, and `get_gate_status_file` reads `HUNT_SESSION_DIR` from `gate.constants` which also imports from `paths`. Monkeypatching `pipeline_gate.HUNT_SESSION_DIR` only changes the shim's binding; `gate.constants.HUNT_SESSION_DIR` keeps pointing to the real one.)

**If tests fail due to monkeypatch mismatch**, update `test_pipeline_gate.py::_isolate` to also `monkeypatch.setattr(gate.constants, "HUNT_SESSION_DIR", fake_hunt)` and commit that fix in the same commit.

- [ ] **Step 6: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo help_ok
python3 -c "from pipeline_gate import export_gate_status, run_gate, show_status, mark_gate; print('reexport_ok')"
```

Expected: `help_ok` + `reexport_ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/gate_status.py audit-agents/pipeline_gate.py
# If you needed to update test_pipeline_gate.py monkeypatches:
# rtk git add audit-agents/tests/test_pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/gate_status.py

Move export_gate_status, run_gate, show_status, mark_gate +
_map_gate_state, _load/_save_gate_status from pipeline_gate.py. Shim
re-exports. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 6: Extract `gate/gates_finding.py`

**Files:**
- Create: `audit-agents/gate/gates_finding.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 1194-1659 with re-exports)

- [ ] **Step 1: Read the source section**

After Tasks 1-5, the `# ─── Finding Pipeline Gates ───` block is much earlier in `pipeline_gate.py`. Re-locate with:

```bash
cd /home/kali/Documents/Web3
grep -n "# ─── Finding Pipeline Gates" audit-agents/pipeline_gate.py
grep -n "# ─── Finding Queue" audit-agents/pipeline_gate.py
```

Contents (7 check functions + 4 helpers + 1 dispatch dict):
- `_find_hyp_with_finding(finding_id) -> dict | None`
- `_check_poc_uses_fork(solidity_text: str) -> bool`
- `check_finding_poc/escalation/variant/redteam/verify/report/submit(finding_id)`
- `FINDING_GATE_CHECKS` dict
- `export_finding_gate_status(finding_id)`
- `run_finding_gate(finding_id, gate) -> bool`
- `show_finding_status(finding_id)`
- `mark_finding_gate(finding_id, gate)`

- [ ] **Step 2: Write `gate/gates_finding.py`**

Header:

```python
"""7 finding-level gate checks + FINDING_GATE_CHECKS dispatch + run/show/mark.

Depends on: gate.constants, gate.gate_status (for _load/_save_gate_status
helpers if shared), state_manager, paths.HUNT_SESSION_DIR.
"""
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from paths import HUNT_SESSION_DIR, WEB3_DIR
from state_manager import load_state

from gate.constants import GATE_ORDER, get_gate_status_file, get_hyp_dir
from gate.gate_status import _map_gate_state, _load_gate_status, _save_gate_status
```

Reconcile imports via the same `sed | grep "^(import |from )"` trick used in Task 4.

Then paste the 7 check functions + 4 helpers + `FINDING_GATE_CHECKS` dict + 4 runner functions **verbatim**.

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.gates_finding import _check_poc_uses_fork, _find_hyp_with_finding, check_finding_poc, check_finding_escalation, check_finding_variant, check_finding_redteam, check_finding_verify, check_finding_report, check_finding_submit, FINDING_GATE_CHECKS, export_finding_gate_status, run_finding_gate, show_finding_status, mark_finding_gate; print('OK', len(FINDING_GATE_CHECKS))"
```

Expected: `OK 7`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Replace the `# ─── Finding Pipeline Gates ───` block with:

```python
# ─── Finding Pipeline Gates ──────────────────────────────────────────────────
from gate.gates_finding import (  # noqa: F401  re-export
    _check_poc_uses_fork, _find_hyp_with_finding,
    check_finding_poc, check_finding_escalation, check_finding_variant,
    check_finding_redteam, check_finding_verify, check_finding_report,
    check_finding_submit, FINDING_GATE_CHECKS,
    export_finding_gate_status, run_finding_gate, show_finding_status,
    mark_finding_gate,
)
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

`test_poc_gate_requires_fork` exercises `_check_poc_uses_fork` — it must still work via the shim re-export.

- [ ] **Step 6: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo help_ok
python3 -c "from pipeline_gate import check_finding_poc, FINDING_GATE_CHECKS, run_finding_gate; print('reexport_ok', len(FINDING_GATE_CHECKS))"
```

Expected: `help_ok` + `reexport_ok 7`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/gates_finding.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/gates_finding.py

Move 7 finding gate checks (check_finding_poc/escalation/variant/
redteam/verify/report/submit) + FINDING_GATE_CHECKS + 4 runner helpers
(export/run/show/mark_finding_gate) + 2 utilities
(_check_poc_uses_fork, _find_hyp_with_finding) from pipeline_gate.py.
Shim re-exports. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 7: Extract `gate/finding_queue.py`

**Files:**
- Create: `audit-agents/gate/finding_queue.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 1661-1812 with re-exports)

- [ ] **Step 1: Read the source section**

Re-locate with:
```bash
cd /home/kali/Documents/Web3
grep -n "# ─── Finding Queue" audit-agents/pipeline_gate.py
grep -n "# ─── Main" audit-agents/pipeline_gate.py
```

Contents:
- `_save_state(state)` — delegates to state_manager.save_state
- `generate_queue_id(source, parent_id=None, components=None, component="", hunter="")`
- `queue_finding(source, parent_id=None, title="", component="", severity="", notes="", components=None, hunter="")`
- `list_queue()`
- `queue_update(finding_id, new_status, notes="")`
- `queue_promote(finding_id)`

- [ ] **Step 2: Write `gate/finding_queue.py`**

Header:

```python
"""Finding queue: add/update/promote entries in current_hunt.json.

Depends on: state_manager, gate.scope_master (for scope_master_on_finding).
"""
from datetime import datetime

from state_manager import load_state, save_state as _sm_save_state

from gate.scope_master import scope_master_on_finding


def _save_state(state: dict):
    """Write current_hunt.json atomically (delegates to state_manager)."""
    _sm_save_state(state)
```

Then paste `generate_queue_id`, `queue_finding`, `list_queue`, `queue_update`, `queue_promote` **verbatim** from the source.

- [ ] **Step 3: Verify direct import**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.finding_queue import _save_state, generate_queue_id, queue_finding, list_queue, queue_update, queue_promote; print('OK')"
```

Expected: `OK`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Replace the `# ─── Finding Queue ───` block with:

```python
# ─── Finding Queue ───────────────────────────────────────────────────────────
from gate.finding_queue import (  # noqa: F401  re-export
    _save_state, generate_queue_id, queue_finding,
    list_queue, queue_update, queue_promote,
)
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

`test_queue_finding_generates_id`, `test_queue_finding_adds_to_state`, and `test_queue_promote_moves_to_findings` all exercise these symbols — they must pass.

- [ ] **Step 6: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo help_ok
python3 -c "from pipeline_gate import queue_finding, generate_queue_id, queue_promote; print('reexport_ok')"
```

Expected: `help_ok` + `reexport_ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/finding_queue.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/finding_queue.py

Move generate_queue_id, queue_finding, list_queue, queue_update,
queue_promote + _save_state helper from pipeline_gate.py. Shim
re-exports. Suite 224/224 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 8: Extract `gate/cli.py`

**Files:**
- Create: `audit-agents/gate/cli.py`
- Modify: `audit-agents/pipeline_gate.py` (replace lines 1814+ with re-export + `if __name__ == "__main__"`)

- [ ] **Step 1: Read the source section**

Re-locate with:
```bash
cd /home/kali/Documents/Web3
grep -n "# ─── Main\|^def main\|^if __name__" audit-agents/pipeline_gate.py
```

Everything from the `# ─── Main ───` banner to end-of-file, including `def main()`, argparse setup, and the `if __name__ == "__main__": main()` block.

- [ ] **Step 2: Write `gate/cli.py`**

Header:

```python
"""CLI entry point for pipeline gate commands.

Invoked via `python3 audit-agents/pipeline_gate.py ...` (shim delegates
to gate.cli.main) or `python3 -m gate.cli` directly.
"""
import argparse
import sys

from gate.gates_component import GATE_CHECKS
from gate.gate_status import (
    export_gate_status, run_gate, show_status, mark_gate,
)
from gate.gates_finding import (
    FINDING_GATE_CHECKS, export_finding_gate_status,
    run_finding_gate, show_finding_status, mark_finding_gate,
)
from gate.finding_queue import (
    queue_finding, list_queue, queue_update, queue_promote,
)
from gate.scope_master import show_scope_status
```

Reconcile by grepping the source main() body for every module-level name it references (`print`, `sys.exit`, etc. are stdlib; focus on `from pipeline_gate` style dependencies).

Then paste `main()` **verbatim** followed by:

```python
if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Verify direct import and CLI invocation via module**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "from gate.cli import main; print('OK')"
python3 -m gate.cli --help > /dev/null && echo module_cli_ok
```

Expected: `OK` + `module_cli_ok`.

- [ ] **Step 4: Replace section in `pipeline_gate.py`**

Find the `# ─── Main ───` banner (and everything below it) and replace with:

```python
# ─── Main ────────────────────────────────────────────────────────────────────
from gate.cli import main  # noqa: F401  re-export

if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

- [ ] **Step 6: CLI smoke — full entry points**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo shim_cli_ok
python3 -m gate.cli --help > /dev/null && echo module_cli_ok
```

Expected: both print `*_cli_ok`.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/gate/cli.py audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): extract gate/cli.py

Move main() + argparse wiring from pipeline_gate.py to gate/cli.py.
Shim delegates via re-export + if __name__ == '__main__': main().
Suite 224/224 passed. CLI exit 0 via both shim and python3 -m gate.cli.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 9: Verify shim budget and slim remaining cruft

**Files:**
- Modify: `audit-agents/pipeline_gate.py` (trim any surviving top-of-file imports + module docstring)

- [ ] **Step 1: Measure current shim size**

Run:
```bash
cd /home/kali/Documents/Web3
wc -l audit-agents/pipeline_gate.py
```

If >80 lines, proceed to trim. If ≤80, skip to Step 4.

- [ ] **Step 2: Identify non-re-export lines**

Open `audit-agents/pipeline_gate.py`. After Tasks 1-8, the file should contain only:
- Top-of-file module docstring (if any)
- Section banner comments (`# ─── Paths ───`, etc.)
- `from gate.X import ...  # noqa: F401  re-export` blocks
- `from paths import ...` for `HUNT_SESSION_DIR`, `STATE_FILE`, `WEB3_DIR`
- `from state_manager import load_state, save_state as _sm_save_state`
- The `if __name__ == "__main__": main()` block

Any leftover function definitions, constants, or legacy imports are removal candidates. Delete them if they aren't in the re-export contract.

- [ ] **Step 3: Replace pipeline_gate.py with the canonical shim**

If trimming is needed, the target final shape of `audit-agents/pipeline_gate.py` is:

```python
"""Shim module — backward-compat facade for the `gate/` package (Phase 9 split).

The pipeline_gate module was split into an 8-module package at
`audit-agents/gate/`. This shim re-exports the same public contract so
external consumers (`from pipeline_gate import X`) keep working without
edits. All lines use `# noqa: F401` because consumers reach in by name.

See docs/superpowers/specs/2026-04-19-phase-9-pipeline-gate-split-design.md.
"""
# State + paths (tests monkeypatch these names)
from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE  # noqa: F401
from state_manager import load_state, save_state as _sm_save_state  # noqa: F401

# ─── Paths + constants ──────────────────────────────────────────────────────
from gate.constants import (  # noqa: F401
    get_hyp_dir, _get_protocol, get_context_dir, get_gate_status_file,
    HUNTER_NAMES, GATE_ORDER, DISPLAY_GATES,
)

# ─── Ficha I/O ──────────────────────────────────────────────────────────────
from gate.ficha import load_ficha, update_ficha  # noqa: F401

# ─── Component gate checks ──────────────────────────────────────────────────
from gate.gates_component import (  # noqa: F401
    check_scope, check_hunters, check_deepdive, check_crosschain,
    check_merge, check_compile, check_phase1, check_phase2, check_phase3,
    check_phase4, check_phase5, check_prepass, GATE_CHECKS,
)

# ─── SCOPE_MASTER auto-update ───────────────────────────────────────────────
from gate.scope_master import (  # noqa: F401
    _find_scope_master, _scope_master_update_component,
    _scope_master_update_coverage, scope_master_on_complete,
    scope_master_on_review, scope_master_on_finding, show_scope_status,
)

# ─── Gate status export + runner ────────────────────────────────────────────
from gate.gate_status import (  # noqa: F401
    _map_gate_state, _load_gate_status, _save_gate_status,
    export_gate_status, run_gate, show_status, mark_gate,
)

# ─── Finding gate checks ────────────────────────────────────────────────────
from gate.gates_finding import (  # noqa: F401
    _check_poc_uses_fork, _find_hyp_with_finding,
    check_finding_poc, check_finding_escalation, check_finding_variant,
    check_finding_redteam, check_finding_verify, check_finding_report,
    check_finding_submit, FINDING_GATE_CHECKS,
    export_finding_gate_status, run_finding_gate, show_finding_status,
    mark_finding_gate,
)

# ─── Finding queue ──────────────────────────────────────────────────────────
from gate.finding_queue import (  # noqa: F401
    _save_state, generate_queue_id, queue_finding,
    list_queue, queue_update, queue_promote,
)

# ─── CLI entry point ────────────────────────────────────────────────────────
from gate.cli import main  # noqa: F401

if __name__ == "__main__":
    main()
```

Paste this as the full file contents. Count: ~75 non-blank lines.

- [ ] **Step 4: Verify shim size and full contract**

Run:
```bash
cd /home/kali/Documents/Web3
wc -l audit-agents/pipeline_gate.py
python3 -c "
import pipeline_gate
required = ['export_gate_status','run_gate','queue_finding','check_scope','check_finding_poc','HUNTER_NAMES','GATE_CHECKS','FINDING_GATE_CHECKS','main','HUNT_SESSION_DIR','STATE_FILE','load_state','load_ficha','scope_master_on_complete','_check_poc_uses_fork','DISPLAY_GATES']
missing = [n for n in required if not hasattr(pipeline_gate, n)]
print('missing:', missing)
"
```

Expected: LOC ≤80, `missing: []`.

- [ ] **Step 5: Run full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `224 passed`.

- [ ] **Step 6: CLI smoke**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo shim_ok
python3 audit-agents/pipeline_gate.py --status 2>&1 | head -3  # smoke: real CLI path
```

Expected: `shim_ok` + the usual `--status` output (may error if no component, but should not crash on import).

- [ ] **Step 7: Commit (only if Step 3 changed the file)**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/pipeline_gate.py
rtk git commit -m "refactor(phase_9): slim pipeline_gate.py to canonical <80-LOC shim

Removed leftover imports and banner cruft. Final shape: module
docstring + 8 re-export blocks + if __name__ == '__main__': main().
Suite 224/224 passed. Shim LOC: $(wc -l < audit-agents/pipeline_gate.py).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

(If the LOC after Task 8 was already ≤80, skip the commit — nothing to change. Note in the session log that Task 9 was a no-op verification.)

---

## Task 10: Add phase_9 contract tests

**Files:**
- Create: `audit-agents/tests/phase_9/__init__.py`
- Create: `audit-agents/tests/phase_9/test_shim_reexports.py`

- [ ] **Step 1: Create empty test package marker**

```bash
cd /home/kali/Documents/Web3
mkdir -p audit-agents/tests/phase_9
: > audit-agents/tests/phase_9/__init__.py
```

- [ ] **Step 2: Write the contract snapshot test**

Create `audit-agents/tests/phase_9/test_shim_reexports.py` with:

```python
"""Phase 9 shim contract: pipeline_gate re-exports the full public API.

If a consumer of `from pipeline_gate import X` breaks, it's because a
symbol fell off this list. Keep this test in sync with the spec's
contract section.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pipeline_gate


EXPECTED_PUBLIC = {
    # constants
    "HUNTER_NAMES", "GATE_ORDER", "DISPLAY_GATES",
    "get_hyp_dir", "_get_protocol", "get_context_dir", "get_gate_status_file",
    # paths/state re-exports
    "HUNT_SESSION_DIR", "STATE_FILE", "WEB3_DIR", "load_state",
    # ficha
    "load_ficha", "update_ficha",
    # gates_component
    "check_scope", "check_hunters", "check_deepdive", "check_crosschain",
    "check_merge", "check_compile", "check_phase1", "check_phase2",
    "check_phase3", "check_phase4", "check_phase5", "check_prepass",
    "GATE_CHECKS",
    # scope_master
    "_find_scope_master", "_scope_master_update_component",
    "_scope_master_update_coverage", "scope_master_on_complete",
    "scope_master_on_review", "scope_master_on_finding", "show_scope_status",
    # gate_status
    "_map_gate_state", "_load_gate_status", "_save_gate_status",
    "export_gate_status", "run_gate", "show_status", "mark_gate",
    # gates_finding
    "_check_poc_uses_fork", "_find_hyp_with_finding",
    "check_finding_poc", "check_finding_escalation", "check_finding_variant",
    "check_finding_redteam", "check_finding_verify", "check_finding_report",
    "check_finding_submit", "FINDING_GATE_CHECKS",
    "export_finding_gate_status", "run_finding_gate",
    "show_finding_status", "mark_finding_gate",
    # finding_queue
    "_save_state", "generate_queue_id", "queue_finding",
    "list_queue", "queue_update", "queue_promote",
    # cli
    "main",
}


def test_shim_reexports_full_contract():
    missing = sorted(name for name in EXPECTED_PUBLIC if not hasattr(pipeline_gate, name))
    assert not missing, f"Shim missing re-exports: {missing}"


def test_shim_line_budget():
    """pipeline_gate.py stays under 80 non-blank, non-comment lines."""
    p = Path(pipeline_gate.__file__)
    lines = p.read_text().splitlines()
    code_lines = [
        ln for ln in lines
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert len(code_lines) <= 80, (
        f"Shim grew to {len(code_lines)} code lines "
        f"(limit 80). Contents:\n{chr(10).join(code_lines)}"
    )


def test_gate_package_modules_exist():
    """All 8 gate/* modules declared in the spec are importable."""
    import gate.constants
    import gate.ficha
    import gate.scope_master
    import gate.gates_component
    import gate.gate_status
    import gate.gates_finding
    import gate.finding_queue
    import gate.cli
    assert all([
        gate.constants.HUNTER_NAMES,
        callable(gate.ficha.load_ficha),
        callable(gate.scope_master.scope_master_on_complete),
        callable(gate.gates_component.check_scope),
        callable(gate.gate_status.export_gate_status),
        callable(gate.gates_finding.check_finding_poc),
        callable(gate.finding_queue.queue_finding),
        callable(gate.cli.main),
    ])
```

- [ ] **Step 3: Run the new tests in isolation**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -m pytest audit-agents/tests/phase_9/ -v
```

Expected: `3 passed`.

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `227 passed` (224 + 3 new).

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_9/
rtk git commit -m "test(phase_9): shim re-export contract + package module snapshot

3 tests:
- test_shim_reexports_full_contract: EXPECTED_PUBLIC set matches
  actual pipeline_gate attributes.
- test_shim_line_budget: pipeline_gate.py ≤80 code lines.
- test_gate_package_modules_exist: all 8 gate/* modules importable.

Suite 224 → 227 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 11: Update parity matrix (F047-F054)

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

- [ ] **Step 1: Read the current tail of the features list**

Use Read tool on `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`. Locate:
- The last feature entry (should be `F046` from Phase 6)
- The `summary:` block at the end — in particular `total_features:` and `by_decision.added_phase_6:`

- [ ] **Step 2: Append 8 new feature entries after F046**

Insert the following block after the last `F046` entry and before `summary:`:

```yaml
  - id: F047
    name: "gate/constants package module"
    legacy_location: "pipeline_gate.py (Paths + constants section)"
    modern_location: "audit-agents/gate/constants.py"
    migration_decision: added_phase_9
    notes: "Leaf module — path helpers + HUNTER_NAMES + GATE_ORDER + DISPLAY_GATES."

  - id: F048
    name: "gate/ficha package module"
    legacy_location: "pipeline_gate.py (State helpers section)"
    modern_location: "audit-agents/gate/ficha.py"
    migration_decision: added_phase_9
    notes: "load_ficha + update_ficha."

  - id: F049
    name: "gate/gates_component package module"
    legacy_location: "pipeline_gate.py (Gate checks section)"
    modern_location: "audit-agents/gate/gates_component.py"
    migration_decision: added_phase_9
    notes: "13 component-level gate checks + GATE_CHECKS dispatch (largest module, ~580 LOC)."

  - id: F050
    name: "gate/scope_master package module"
    legacy_location: "pipeline_gate.py (SCOPE_MASTER Auto-Update section)"
    modern_location: "audit-agents/gate/scope_master.py"
    migration_decision: added_phase_9
    notes: "SCOPE_MASTER.md auto-update helpers."

  - id: F051
    name: "gate/gate_status package module"
    legacy_location: "pipeline_gate.py (Gate Status JSON Export section)"
    modern_location: "audit-agents/gate/gate_status.py"
    migration_decision: added_phase_9
    notes: "JSON export + run_gate + show_status + mark_gate."

  - id: F052
    name: "gate/gates_finding package module"
    legacy_location: "pipeline_gate.py (Finding Pipeline Gates section)"
    modern_location: "audit-agents/gate/gates_finding.py"
    migration_decision: added_phase_9
    notes: "7 finding-level gate checks + FINDING_GATE_CHECKS + runner helpers."

  - id: F053
    name: "gate/finding_queue package module"
    legacy_location: "pipeline_gate.py (Finding Queue section)"
    modern_location: "audit-agents/gate/finding_queue.py"
    migration_decision: added_phase_9
    notes: "queue_finding, queue_update, queue_promote, generate_queue_id, list_queue."

  - id: F054
    name: "gate/cli package module"
    legacy_location: "pipeline_gate.py (Main section)"
    modern_location: "audit-agents/gate/cli.py"
    migration_decision: added_phase_9
    notes: "main() + argparse wiring. Shim delegates via if __name__ == '__main__'."
```

- [ ] **Step 3: Update the summary block**

Locate the `summary:` block. Update:

```yaml
summary:
  total_features: 54       # was 46
  by_decision:
    migrated: 16
    deprecated: 14
    keep_standalone: 0
    added_phase_5: 2
    added_phase_6: 14
    added_phase_9: 8       # new
```

Checksum: 16 + 14 + 0 + 2 + 14 + 8 = 54 ✓.

- [ ] **Step 4: Verify via audit script**

Run the Phase 8 audit in check-only mode:

```bash
cd /home/kali/Documents/Web3
python3 audit-agents/phase_8_audit.py --check check_parity_matrix --json-out /tmp/parity_check.json
python3 -c "import json; d = json.load(open('/tmp/parity_check.json')); print('status:', d['checks'][0]['status'])"
```

Expected: `status: PASS`. If any entry's modern_location points to a missing file, the check will flag it as stale_claim.

- [ ] **Step 5: Run full suite (sanity)**

Run: `python3 -m pytest audit-agents/tests/ -q`. Expected: `227 passed`.

- [ ] **Step 6: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "docs(phase_9): parity matrix F047-F054 + summary totals

8 new entries for the gate/ package modules. total_features 46 → 54;
by_decision.added_phase_9: 8. Checksum 16+14+0+2+14+8 = 54.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Task 12: Re-run Phase 8 audit + commit refreshed artifacts

**Files:**
- Modify (auto-generated): `audit-agents/audit_report.json`
- Modify (auto-generated): `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md`

- [ ] **Step 1: Run the audit end-to-end**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/phase_8_audit.py
echo "exit=$?"
```

Expected: `exit=0` (runtime, not pass/fail verdict).

- [ ] **Step 2: Inspect new verdict**

Run:
```bash
cd /home/kali/Documents/Web3
python3 -c "
import json
d = json.load(open('audit-agents/audit_report.json'))
print('verdict:', d['verdict'])
print('gates:', d['summary']['gates'])
print('debt:', d['summary']['debt_items'])
for c in d['checks']:
    print(f'  {c[\"name\"]}: {c[\"status\"]}')
"
```

Expected: `check_parity_matrix: PASS` (from Task 11) + `check_size_inventory: ???`.

`check_size_inventory` should report `pipeline_gate.py` as <80 LOC (no longer a god-file) but will still WARN for the other 3 god-files (`hybrid_pipeline.py`, `merge_invariants.py`, `target_monitor.py`). That's expected — Phase 9 only fixes one of the four.

Verdict should remain `PARTIAL` (3 WARNs down to 2 or 1, but still not full PASS). If verdict somehow regresses to FAILED, investigate before committing.

- [ ] **Step 3: Inspect the Markdown report for the pipeline_gate entry**

Run:
```bash
cd /home/kali/Documents/Web3
grep -A 3 "pipeline_gate" docs/superpowers/specs/2026-04-19-phase-8-audit-report.md | head -10
```

Expected: `pipeline_gate.py` LOC is now ~75-80 (or whatever the shim measures), not 1,982.

- [ ] **Step 4: Update `check_test_suite` expected count**

If the suite count changed (now 227 from Task 10), update the default in `phase_8_audit.py`:

```bash
cd /home/kali/Documents/Web3
grep -n "expected_count" audit-agents/phase_8_audit.py
```

If the default is still `224`, edit to `227`:

```python
def check_test_suite(*, root: Path, expected_count: int = 227) -> CheckResult:
```

Then re-run `python3 audit-agents/phase_8_audit.py` to regenerate artifacts with the updated count.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/phase_8_audit.py audit-agents/audit_report.json docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
rtk git commit -m "chore(phase_9): re-run Phase 8 audit + refresh artifacts

After pipeline_gate.py split (1,982 → ~75 LOC shim + 8 gate/* modules):
- check_parity_matrix: PASS (F047-F054 + summary in sync)
- check_size_inventory: still WARN (3 god-files remain) but
  pipeline_gate.py no longer flagged
- check_test_suite default recalibrated to 227 (224 + 3 phase_9 tests)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

- [ ] **Step 6: Update roadmap memory**

Edit `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`:

1. Update frontmatter description to mention Phase 9 (pipeline_gate split done; 3 god-files remain).
2. Add a `## Fase 9 — resumen al cerrar` section after the Phase 8 quick-wins section, summarizing:
   - 8 modules extracted into `audit-agents/gate/` package (constants, ficha, gates_component, scope_master, gate_status, gates_finding, finding_queue, cli).
   - `pipeline_gate.py` reduced from 1,982 → ~75 LOC shim.
   - 3 new tests in `audit-agents/tests/phase_9/` (contract snapshot + LOC budget + package import).
   - Suite 224 → 227.
   - Parity matrix F047-F054 added.
   - Verdict remains PARTIAL; 3 god-files still pending (`hybrid_pipeline.py`, `merge_invariants.py`, `target_monitor.py`) for Phase 9.2-9.4.

3. Update `MEMORY.md` index line to reflect new state.

No commit — memory is outside the repo.

---

## Self-Review Checklist (run after plan is written)

**1. Spec coverage:**
- [x] Shim pattern (spec §Estrategia) → covered by Task 9.
- [x] 8 new modules (spec §Arquitectura table) → Tasks 1-8.
- [x] Contract preservation (spec §Contrato público) → Tasks 1-8 each verify + Task 10 snapshot.
- [x] Topological extraction order (spec §Dependencias internas) → Tasks 1-8 in order.
- [x] Testing strategy (spec §Testing) → Task 10 adds phase_9 tests.
- [x] Parity matrix update (spec §Parity matrix) → Task 11.
- [x] Re-run audit (spec §Criterios de éxito #7) → Task 12.
- [x] Success criteria #1 (226+ passed) → Task 10 verifies 227.
- [x] Success criteria #2 (shim ≤80 LOC) → Task 9 + Task 10 test.
- [x] Success criteria #3 (no module >800 LOC) — largest is gates_component at ~580 LOC per spec, well under budget. Implicit.
- [x] Success criteria #4 (CLI functional) → every task verifies `--help`.
- [x] Success criteria #5 (consumers intact) — no task edits external consumers; shim preserves the contract.

**2. Placeholder scan:** no "TBD", no "similar to Task N", every code step has code.

**3. Type consistency:** function signatures (`check_scope(component, repo="")`, `run_gate(component, gate, repo="")`, `queue_finding(source, parent_id=None, ...)`) match the spec and source.

**4. Ordering invariants:**
- `constants` (Task 1) before everything (leaf).
- `ficha` (Task 2) before `gates_component` (Task 4 imports `load_ficha`).
- `scope_master` (Task 3) before `gate_status` (Task 5 imports `scope_master_on_complete`) and before `finding_queue` (Task 7 imports `scope_master_on_finding`).
- `gates_component` (Task 4) before `gate_status` (Task 5 imports `GATE_CHECKS`).
- `gate_status` (Task 5) before `gates_finding` (Task 6 imports `_map_gate_state`, `_load/_save_gate_status`).
- `cli` (Task 8) last — imports from every other module.

No cycles. Each task's Step 1 re-locates line numbers via grep because earlier extractions shift them.
