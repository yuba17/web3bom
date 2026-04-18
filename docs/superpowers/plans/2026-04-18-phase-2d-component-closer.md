# Phase 2D — Component Closer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate F006 (`--complete <COMPONENT>`) from legacy `run_hunt.py` into the modern flow via a pure `component_closer.py` orchestrator + a `--complete` flag on `run_benchmark.py`.

**Architecture:** New module `audit-agents/component_closer.py` with a single public function `close_component(*, component, state_file=None, apply_feedback=True, cross_component=True, force=False) -> dict`. The closer runs four phases: pipeline_gate check → state transition → apply_feedback subprocess → cross-component trigger (marker only; caller decides). The CLI wrapper in `run_benchmark.py` adds `--complete` + `--force`, enforces mutex with `--components` / `--auto-components`, and invokes the real cross-component helper when the closer signals.

**Tech Stack:** Python 3.13, pytest, stdlib only (`subprocess`, `json`, `tempfile`, `pathlib`). No new external deps.

---

## File Structure

| File | Role |
|---|---|
| `audit-agents/component_closer.py` | **NEW** — pure orchestrator. Reads `state_file`, calls `pipeline_gate.py` + `apply_feedback.py` via subprocess, mutates state atomically, returns a report dict. |
| `audit-agents/run_benchmark.py` | **MODIFY** — add `--complete`, `--force`; mutex check with `--components` / `--auto-components`; route to closer at top of `main()`. |
| `audit-agents/tests/phase_2d/conftest.py` | **NEW** — fixtures for synthetic `current_hunt.json`, stub `pipeline_gate.py` / `apply_feedback.py` via monkeypatch. |
| `audit-agents/tests/phase_2d/test_*.py` | **NEW** — 5 test modules, ~15 tests. |
| `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` | **MODIFY** — F006 → `migrated`. |

---

## Common Helpers (used across tests)

Every test module imports a minimal synthetic state:

```python
SAMPLE_STATE = {
    "protocol": "demo",
    "repo_path": "/tmp/demo",
    "components_remaining": ["Vault", "Strategy", "Oracle"],
    "components_done": [],
    "current_component": "Vault",
    "component_map": [
        {"name": "Vault",    "files": ["src/Vault.sol"],    "loc": 100, "status": "pending", "priority": 1, "depends_on": []},
        {"name": "Strategy", "files": ["src/Strategy.sol"], "loc":  80, "status": "pending", "priority": 2, "depends_on": []},
        {"name": "Oracle",   "files": ["src/Oracle.sol"],   "loc":  60, "status": "pending", "priority": 3, "depends_on": []},
    ],
    "last_session": "2026-04-17T00:00:00Z",
}
```

---

## Task 1: Scaffold `tests/phase_2d/` with package + fixtures

**Files:**
- Create: `audit-agents/tests/phase_2d/__init__.py`
- Create: `audit-agents/tests/phase_2d/conftest.py`
- Create: `audit-agents/tests/phase_2d/test_scaffold.py`

- [ ] **Step 1: Create package init**

```bash
mkdir -p audit-agents/tests/phase_2d
touch audit-agents/tests/phase_2d/__init__.py
```

- [ ] **Step 2: Write `conftest.py`**

Create `audit-agents/tests/phase_2d/conftest.py`:

```python
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_THIS_DIR = Path(__file__).resolve().parent
_AUDIT_AGENTS = _THIS_DIR.parent.parent  # audit-agents/
if str(_AUDIT_AGENTS) not in sys.path:
    sys.path.insert(0, str(_AUDIT_AGENTS))


SAMPLE_STATE = {
    "protocol": "demo",
    "repo_path": "/tmp/demo",
    "components_remaining": ["Vault", "Strategy", "Oracle"],
    "components_done": [],
    "current_component": "Vault",
    "component_map": [
        {"name": "Vault",    "files": ["src/Vault.sol"],    "loc": 100, "status": "pending", "priority": 1, "depends_on": []},
        {"name": "Strategy", "files": ["src/Strategy.sol"], "loc":  80, "status": "pending", "priority": 2, "depends_on": []},
        {"name": "Oracle",   "files": ["src/Oracle.sol"],   "loc":  60, "status": "pending", "priority": 3, "depends_on": []},
    ],
    "last_session": "2026-04-17T00:00:00Z",
}


@pytest.fixture
def tmp_state_file(tmp_path: Path) -> Path:
    """Synthetic current_hunt.json written to tmp_path."""
    f = tmp_path / "current_hunt.json"
    f.write_text(json.dumps(SAMPLE_STATE, indent=2))
    return f


@pytest.fixture
def patched_subprocess(monkeypatch):
    """
    Replaces subprocess.run globally for the duration of a test.
    Returns a list that captures every invocation. Default: all calls
    return rc=0 with empty stdout/stderr. Tests can mutate the default
    by reassigning `patched_subprocess.rc` / `patched_subprocess.stdout`.
    """
    calls: list[dict] = []

    class _Result:
        def __init__(self, rc: int, stdout: str, stderr: str):
            self.returncode = rc
            self.stdout = stdout
            self.stderr = stderr

    def _fake_run(cmd, *args, **kwargs):
        calls.append({"cmd": list(cmd), "kwargs": dict(kwargs)})
        return _Result(_fake_run.rc, _fake_run.stdout, _fake_run.stderr)

    _fake_run.rc = 0
    _fake_run.stdout = ""
    _fake_run.stderr = ""

    import subprocess
    monkeypatch.setattr(subprocess, "run", _fake_run)
    _fake_run.calls = calls
    return _fake_run
```

- [ ] **Step 3: Write smoke test**

Create `audit-agents/tests/phase_2d/test_scaffold.py`:

```python
from __future__ import annotations

import json
from pathlib import Path


def test_tmp_state_file_contains_sample(tmp_state_file: Path):
    data = json.loads(tmp_state_file.read_text())
    assert data["protocol"] == "demo"
    assert "Vault" in data["components_remaining"]
    assert data["current_component"] == "Vault"


def test_patched_subprocess_captures_calls(patched_subprocess):
    import subprocess
    subprocess.run(["echo", "hello"])
    assert len(patched_subprocess.calls) == 1
    assert patched_subprocess.calls[0]["cmd"] == ["echo", "hello"]
```

- [ ] **Step 4: Run smoke tests**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_scaffold.py -v
```

Expected: PASS 2/2.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_2d/
rtk git commit -m "$(cat <<'EOF'
test(phase_2d): scaffold tests/phase_2d/ — state fixtures + subprocess stub

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Create `component_closer.py` skeleton + gated-transition happy path

**Files:**
- Create: `audit-agents/component_closer.py`
- Create: `audit-agents/tests/phase_2d/test_close_component_gated.py`

- [ ] **Step 1: Write the failing test**

Create `audit-agents/tests/phase_2d/test_close_component_gated.py`:

```python
from __future__ import annotations

import json
from pathlib import Path


def test_close_component_gate_pass_mutates_state(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    # All subprocess calls succeed (pipeline_gate + apply_feedback)
    patched_subprocess.rc = 0

    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
    )

    assert report["component"] == "Vault"
    assert report["gated"] is True
    assert report["forced"] is False
    assert report["state_updated"] is True
    assert report["next_component"] == "Strategy"

    data = json.loads(tmp_state_file.read_text())
    assert "Vault" in data["components_done"]
    assert "Vault" not in data["components_remaining"]
    assert data["current_component"] == "Strategy"
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_close_component_gated.py::test_close_component_gate_pass_mutates_state -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'component_closer'`.

- [ ] **Step 3: Implement minimal closer**

Create `audit-agents/component_closer.py`:

```python
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

_DEFAULT_STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
_AUDIT_AGENTS_DIR = Path(__file__).resolve().parent
_PIPELINE_GATE = _AUDIT_AGENTS_DIR / "pipeline_gate.py"
_APPLY_FEEDBACK = _AUDIT_AGENTS_DIR / "apply_feedback.py"


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


def _run_gate(component: str) -> tuple[bool, str]:
    if not _PIPELINE_GATE.exists():
        return True, ""
    try:
        result = subprocess.run(
            [sys.executable, str(_PIPELINE_GATE), "--component", component, "--gate", "all"],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0, result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return False, "pipeline_gate timeout"


def _run_feedback() -> tuple[int | None, str]:
    if not _APPLY_FEEDBACK.exists():
        return None, ""
    try:
        result = subprocess.run(
            [sys.executable, str(_APPLY_FEEDBACK), "--hypotheses"],
            capture_output=True, text=True, timeout=60,
        )
        return result.returncode, result.stdout or result.stderr
    except subprocess.TimeoutExpired:
        return None, "apply_feedback timeout"


def close_component(
    *,
    component: str,
    state_file: Path | None = None,
    apply_feedback: bool = True,
    cross_component: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    state_file = state_file or _DEFAULT_STATE_FILE
    errors: list[str] = []

    state = _load_state(state_file)
    remaining = state.get("components_remaining", [])
    done = state.get("components_done", [])

    if component in done and component not in remaining:
        return {
            "component": component,
            "gated": True,
            "forced": False,
            "state_updated": False,
            "feedback_rc": None,
            "cross_triggered": False,
            "next_component": remaining[0] if remaining else None,
            "errors": [],
        }

    if component not in remaining and component not in done:
        raise ValueError(
            f"component '{component}' not found in components_remaining or components_done"
        )

    gated, gate_output = _run_gate(component)
    forced = False
    if not gated:
        if not force:
            return {
                "component": component,
                "gated": False,
                "forced": False,
                "state_updated": False,
                "feedback_rc": None,
                "cross_triggered": False,
                "next_component": remaining[0] if remaining else None,
                "errors": [gate_output.strip()] if gate_output else ["gate failed"],
            }
        forced = True
        errors.append(f"gate bypassed via force: {gate_output.strip()}")

    if component in remaining:
        remaining.remove(component)
    if component not in done:
        done.append(component)
    state["components_remaining"] = remaining
    state["components_done"] = done
    state["current_component"] = remaining[0] if remaining else None
    state["last_session"] = datetime.utcnow().isoformat() + "Z"
    for c in state.get("component_map", []):
        if c.get("name") == component:
            c["status"] = "done"
            break
    _save_state_atomic(state_file, state)

    feedback_rc: int | None = None
    if apply_feedback:
        feedback_rc, fb_output = _run_feedback()
        if feedback_rc not in (0, None):
            errors.append(f"apply_feedback rc={feedback_rc}: {fb_output.strip()}")

    return {
        "component": component,
        "gated": gated,
        "forced": forced,
        "state_updated": True,
        "feedback_rc": feedback_rc,
        "cross_triggered": bool(cross_component and len(done) >= 2),
        "next_component": remaining[0] if remaining else None,
        "errors": errors,
    }
```

- [ ] **Step 4: Run the test**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_close_component_gated.py::test_close_component_gate_pass_mutates_state -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/component_closer.py audit-agents/tests/phase_2d/test_close_component_gated.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_2d): add component_closer.close_component — gated transition

Pure orchestrator for per-component closing:
1. pipeline_gate --gate all (timeout 30s)
2. atomic state file mutation (components_remaining → components_done)
3. apply_feedback subprocess (timeout 60s)
4. cross-component marker (caller-driven)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Gate failure with and without `--force`

**Files:**
- Modify: `audit-agents/tests/phase_2d/test_close_component_gated.py`

- [ ] **Step 1: Add failing tests**

Append to `audit-agents/tests/phase_2d/test_close_component_gated.py`:

```python
def test_close_component_gate_fail_no_force_leaves_state(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component
    import json

    patched_subprocess.rc = 1
    patched_subprocess.stderr = "gate: forge build missing"

    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
    )

    assert report["gated"] is False
    assert report["forced"] is False
    assert report["state_updated"] is False
    assert report["errors"] and "forge build missing" in report["errors"][0]

    data = json.loads(tmp_state_file.read_text())
    assert "Vault" in data["components_remaining"]
    assert "Vault" not in data["components_done"]


def test_close_component_gate_fail_with_force_proceeds(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component
    import json

    patched_subprocess.rc = 1
    patched_subprocess.stderr = "gate: forge build missing"

    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
        force=True,
    )

    assert report["gated"] is False
    assert report["forced"] is True
    assert report["state_updated"] is True
    assert any("gate bypassed via force" in e for e in report["errors"])

    data = json.loads(tmp_state_file.read_text())
    assert "Vault" in data["components_done"]
```

- [ ] **Step 2: Run tests to confirm pass**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_close_component_gated.py -v
```

Expected: PASS 3/3. (The implementation from Task 2 already handles both cases; these tests verify the behaviour locks in.)

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_2d/test_close_component_gated.py
rtk git commit -m "$(cat <<'EOF'
test(phase_2d): cover gate-failure paths (no force vs force=True)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: State-file semantics — component_map + current_component + idempotency

**Files:**
- Create: `audit-agents/tests/phase_2d/test_close_component_state.py`

- [ ] **Step 1: Write the failing tests**

Create `audit-agents/tests/phase_2d/test_close_component_state.py`:

```python
from __future__ import annotations

import json
from pathlib import Path


def test_component_map_status_updated(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    close_component(component="Vault", state_file=tmp_state_file)

    data = json.loads(tmp_state_file.read_text())
    vault_entry = next(c for c in data["component_map"] if c["name"] == "Vault")
    assert vault_entry["status"] == "done"
    strategy_entry = next(c for c in data["component_map"] if c["name"] == "Strategy")
    assert strategy_entry["status"] == "pending"


def test_current_component_advances(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    close_component(component="Vault", state_file=tmp_state_file)
    data = json.loads(tmp_state_file.read_text())
    assert data["current_component"] == "Strategy"

    close_component(component="Strategy", state_file=tmp_state_file)
    data = json.loads(tmp_state_file.read_text())
    assert data["current_component"] == "Oracle"

    close_component(component="Oracle", state_file=tmp_state_file)
    data = json.loads(tmp_state_file.read_text())
    assert data["current_component"] is None


def test_idempotent_on_already_done(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    close_component(component="Vault", state_file=tmp_state_file)
    snapshot = tmp_state_file.read_text()

    report = close_component(component="Vault", state_file=tmp_state_file)
    assert report["state_updated"] is False
    assert tmp_state_file.read_text() == snapshot


def test_unknown_component_raises(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component
    import pytest

    with pytest.raises(ValueError, match="not found"):
        close_component(component="DoesNotExist", state_file=tmp_state_file)
```

- [ ] **Step 2: Run tests**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_close_component_state.py -v
```

Expected: PASS 4/4.

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_2d/test_close_component_state.py
rtk git commit -m "$(cat <<'EOF'
test(phase_2d): lock in state-file semantics + idempotency + ValueError

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `apply_feedback` subprocess control

**Files:**
- Create: `audit-agents/tests/phase_2d/test_close_component_apply_feedback.py`

- [ ] **Step 1: Write failing tests**

Create `audit-agents/tests/phase_2d/test_close_component_apply_feedback.py`:

```python
from __future__ import annotations

from pathlib import Path


def test_apply_feedback_false_skips_subprocess(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
        apply_feedback=False,
    )

    assert report["feedback_rc"] is None
    # Only pipeline_gate.py call, not apply_feedback.py
    scripts_called = [c["cmd"][1] for c in patched_subprocess.calls if len(c["cmd"]) > 1]
    assert not any("apply_feedback" in s for s in scripts_called)


def test_apply_feedback_true_records_rc(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    patched_subprocess.rc = 0
    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
        apply_feedback=True,
    )

    scripts_called = [c["cmd"][1] for c in patched_subprocess.calls if len(c["cmd"]) > 1]
    assert any("apply_feedback" in s for s in scripts_called)
    assert report["feedback_rc"] == 0
```

- [ ] **Step 2: Run tests**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_close_component_apply_feedback.py -v
```

Expected: PASS 2/2.

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_2d/test_close_component_apply_feedback.py
rtk git commit -m "$(cat <<'EOF'
test(phase_2d): apply_feedback toggle + rc recording

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Add `--complete` + `--force` flags to `run_benchmark.py` with mutex

**Files:**
- Modify: `audit-agents/run_benchmark.py` (argparse block around line 3670, post-parse mutex check around 3750)
- Create: `audit-agents/tests/phase_2d/test_complete_flag_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Create `audit-agents/tests/phase_2d/test_complete_flag_cli.py`:

```python
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCH = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RUN_BENCH), *args],
        capture_output=True, text=True, timeout=20,
    )


def test_help_mentions_complete():
    proc = _run_cli("--help")
    assert proc.returncode == 0
    assert "--complete" in proc.stdout


def test_complete_and_components_mutex_error():
    proc = _run_cli(
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--components", "Vault,Strategy",
    )
    assert proc.returncode != 0
    assert "mutually exclusive" in (proc.stderr + proc.stdout).lower()


def test_complete_and_auto_components_mutex_error():
    proc = _run_cli(
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--auto-components",
    )
    assert proc.returncode != 0
    assert "mutually exclusive" in (proc.stderr + proc.stdout).lower()
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_complete_flag_cli.py::test_help_mentions_complete -v
```

Expected: FAIL — `--complete` not in help.

- [ ] **Step 3: Locate argparse block in `run_benchmark.py`**

```bash
cd /home/kali/Documents/Web3 && rtk grep -n "auto-components" audit-agents/run_benchmark.py
```

Expected: lines ~3743 (definition) and ~3750 (mutex check with `--components`). Read 30 lines of context:

```bash
rtk read audit-agents/run_benchmark.py 3735 3780
```

- [ ] **Step 4: Add `--complete` and `--force` flags**

Right after the `--auto-components` `add_argument` call (around line 3747), insert:

```python
    parser.add_argument(
        "--complete",
        type=str,
        metavar="COMPONENT",
        default="",
        help="Single-shot: close the given component (gate check + state transition + apply_feedback + cross-component). Mutually exclusive with --components / --auto-components.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass pipeline_gate failures when --complete is set. Ignored otherwise.",
    )
```

- [ ] **Step 5: Extend the mutex check**

Find the existing post-parse block (around line 3750):

```python
    if bool(args.components) == bool(args.auto_components):
        parser.error(
            "exactly one of --components / --auto-components is required "
            "(they are mutually exclusive)"
        )
```

Replace with:

```python
    if args.complete:
        if args.components or args.auto_components:
            parser.error(
                "--complete is mutually exclusive with --components / --auto-components"
            )
    else:
        if bool(args.components) == bool(args.auto_components):
            parser.error(
                "exactly one of --components / --auto-components is required "
                "(they are mutually exclusive)"
            )
```

- [ ] **Step 6: Run the CLI tests**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_complete_flag_cli.py -v
```

Expected: PASS 3/3.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/run_benchmark.py audit-agents/tests/phase_2d/test_complete_flag_cli.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_2d): add --complete + --force to run_benchmark.py with mutex

--complete <COMPONENT> routes to component_closer. Mutually exclusive
with --components and --auto-components. --force only applies when
--complete is set; bypasses pipeline_gate failures.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Route `--complete` through `close_component()` in `main()`

**Files:**
- Modify: `audit-agents/run_benchmark.py` (inside `main()`, after the mutex block, before `components = _resolve_components(args)`)
- Create: `audit-agents/tests/phase_2d/test_complete_routing.py`

- [ ] **Step 1: Write the failing integration test**

Create `audit-agents/tests/phase_2d/test_complete_routing.py`:

```python
from __future__ import annotations

import json
import sys
from pathlib import Path


def test_complete_routes_through_closer(tmp_path: Path, monkeypatch, capsys):
    """run_benchmark.py main() with --complete invokes component_closer.close_component."""
    state_file = tmp_path / "hunt.json"
    state_file.write_text(json.dumps({
        "protocol": "demo",
        "components_remaining": ["Vault", "Strategy"],
        "components_done": [],
        "current_component": "Vault",
        "component_map": [
            {"name": "Vault", "files": ["src/Vault.sol"], "loc": 100, "status": "pending", "priority": 1, "depends_on": []},
            {"name": "Strategy", "files": ["src/Strategy.sol"], "loc": 80, "status": "pending", "priority": 2, "depends_on": []},
        ],
    }))

    import importlib
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    run_benchmark = importlib.import_module("run_benchmark")
    component_closer = importlib.import_module("component_closer")

    captured: list[dict] = []

    def _fake_close(**kwargs):
        captured.append(kwargs)
        return {
            "component": kwargs["component"],
            "gated": True,
            "forced": False,
            "state_updated": True,
            "feedback_rc": 0,
            "cross_triggered": False,
            "next_component": "Strategy",
            "errors": [],
        }

    monkeypatch.setattr(component_closer, "close_component", _fake_close)
    monkeypatch.setattr(run_benchmark, "close_component", _fake_close, raising=False)
    monkeypatch.setattr(sys, "argv", [
        "run_benchmark.py",
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--state-file", str(state_file),
    ])

    rc = run_benchmark.main()
    assert rc == 0
    assert captured and captured[0]["component"] == "Vault"
    assert captured[0]["force"] is False
```

- [ ] **Step 2: Run the test to confirm failure**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_complete_routing.py -v
```

Expected: FAIL — `--state-file` not recognized or main() does not route.

- [ ] **Step 3: Add `--state-file` flag next to `--complete`**

In the argparse block added in Task 6, append another `add_argument`:

```python
    parser.add_argument(
        "--state-file",
        type=str,
        default="",
        help="Override state file path for --complete (default: ~/.claude/MEMORY/STATE/current_hunt.json).",
    )
```

- [ ] **Step 4: Add import + routing at the top of `main()`**

Find `def main():` in `run_benchmark.py`. After the argparse block (after the mutex check added in Task 6, before `components = _resolve_components(args)`), insert:

```python
    if args.complete:
        from pathlib import Path as _Path
        from component_closer import close_component
        state_file = _Path(args.state_file) if args.state_file else None
        report = close_component(
            component=args.complete,
            state_file=state_file,
            force=args.force,
        )
        print(f"[complete] {report['component']}: gated={report['gated']} forced={report['forced']} "
              f"state_updated={report['state_updated']} feedback_rc={report['feedback_rc']} "
              f"next={report['next_component']}")
        for err in report["errors"]:
            print(f"  ! {err}")
        if not report["state_updated"]:
            return 1
        return 0
```

- [ ] **Step 5: Run the routing test**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/test_complete_routing.py -v
```

Expected: PASS 1/1.

- [ ] **Step 6: Run the full phase_2d suite**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_2d/ -v
```

Expected: PASS 14/14 (2 scaffold + 3 gated + 4 state + 2 feedback + 3 CLI).

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/run_benchmark.py audit-agents/tests/phase_2d/test_complete_routing.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_2d): route --complete through component_closer.close_component

Top-of-main() routing before _resolve_components. Prints a single
human-readable summary line plus any error details. Returns 0 on
successful state update (gated or forced), 1 otherwise.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Update parity matrix — F006 → `migrated`

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

- [ ] **Step 1: Locate F006 block**

```bash
cd /home/kali/Documents/Web3 && rtk grep -B 2 -A 15 "id: F006" docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
```

Read the block; you will edit `modern_equivalent`, `migration_decision`, and `migration_target` / `notes`.

- [ ] **Step 2: Apply the edits**

Replace the F006 `modern_equivalent`, `migration_decision`, `migration_target`, and `notes` blocks with:

```yaml
    modern_equivalent:
      status: complete
      location: "component_closer.close_component + run_benchmark.py --complete --force --state-file"
      evidence: "Phase 2D (2026-04-18): pure closer orchestrates gate check, state transition (atomic write), apply_feedback subprocess, and cross-component marker. run_benchmark.py gains --complete / --force / --state-file flags with mutex vs --components / --auto-components."
    migration_decision: migrated
    migration_target: "component_closer.close_component invoked by run_benchmark.py main() when --complete is set."
```

And the `notes:` line:

```yaml
    notes: "apply_feedback es el gap más crítico: cierra L8 feedback loop (briefings + wiki auto-ingest). Phase 2D 2026-04-18: closer orchestrates it per-component."
```

- [ ] **Step 3: Verify the diff**

```bash
cd /home/kali/Documents/Web3 && rtk git diff docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
```

Expected: only the F006 block changed, status `partial → complete`, decision `migrate → migrated`.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "$(cat <<'EOF'
docs(phase_2d): mark F006 as migrated in parity matrix

Component closer now lives in component_closer.py and is invoked by
run_benchmark.py --complete. The feedback loop + gate check + state
transition are orchestrated per-component.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Final verification + memory update

**Files:**
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`

- [ ] **Step 1: Run full test suite**

```bash
cd /home/kali/Documents/Web3 && rtk proxy python -m pytest audit-agents/tests/phase_modern/ audit-agents/tests/phase_2a/ audit-agents/tests/phase_2b/ audit-agents/tests/phase_2c/ audit-agents/tests/phase_2d/ -v 2>&1 | tail -20
```

Expected: PASS all (should be ~121 total: 107 prior + 14 new).

- [ ] **Step 2: Verify CLI flags visible**

```bash
cd /home/kali/Documents/Web3 && python3 audit-agents/run_benchmark.py --help 2>&1 | grep -E "(complete|force|state-file|components)"
```

Expected: lines for `--components`, `--auto-components`, `--complete`, `--force`, `--state-file`.

- [ ] **Step 3: Update roadmap memory**

Edit `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`:

In the frontmatter, update `description` to:

```
description: Estado del roadmap de 8 fases para optimizar el sistema de bug bounty (Web3/). Fase 2D COMPLETA (2026-04-18). Siguiente Fase 3.
```

In the phases table, change the 2D row to:

```
| 2D | Closing — `--complete` integration (F006) | ✅ COMPLETA (2026-04-18) | 9 tareas TDD, 14/14 nuevos tests |
| 3  | Reconcile CLAUDE.md | 🔜 NEXT | Alinear docs tras Fase 2 |
```

And after the "Fase 2C — resumen al cerrar" section, append:

```markdown
## Fase 2D — resumen al cerrar

- **Módulo nuevo**: `audit-agents/component_closer.py` — pure orchestrator (`close_component(*, component, state_file=None, apply_feedback=True, cross_component=True, force=False) -> dict`). Atomic state write via tempfile + shutil.move. Subprocess calls to pipeline_gate.py (30s timeout) and apply_feedback.py (60s timeout). Idempotent on already-done components.
- **F006 migrated**: 3 flags nuevos en `run_benchmark.py`: `--complete COMPONENT` (single-shot closer), `--force` (bypass gate failures, only with --complete), `--state-file` (override default path for tests). Mutex con `--components` / `--auto-components` via post-parse check.
- **Cross-component trigger**: closer reporta `cross_triggered=True` cuando `len(components_done) >= 2` pero NO ejecuta el hunt LLM-heavy. La CLI decide si invocar `run_cross_component` (intencional: closer sigue puro y rápido).
- **Parity matrix actualizada**: F006 → `migrated`.
- **Tests nuevos**: 14 en `audit-agents/tests/phase_2d/` — 2 scaffold + 3 gated + 4 state + 2 feedback + 3 CLI.
- **Commits**: 8 (cada task hizo 1 commit).
```

- [ ] **Step 4: Commit the memory update**

Memory files live outside the repo — no git commit needed. Verify the file updated:

```bash
rtk grep "2D COMPLETA\|Fase 2D — resumen" /home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md
```

Expected: the new lines visible.

- [ ] **Step 5: Final git log check**

```bash
cd /home/kali/Documents/Web3 && rtk git log --oneline -12
```

Expected: 8 Phase 2D commits on top of the Phase 2C history, latest one being the parity-matrix update.

---

## Self-Review Checklist (post-write)

- **Spec coverage**: Every section of the spec maps to a task.
  - Goal / four phases → Tasks 2 (happy path) + 3 (gate fail) + 5 (feedback) + 7 (CLI routing/cross marker).
  - `close_component` signature → Task 2 body.
  - State semantics → Task 4.
  - `run_benchmark.py` flags + mutex → Tasks 6 + 7.
  - Tests → Tasks 1 + 3 + 4 + 5 + 6 + 7.
  - Parity matrix → Task 8.
  - Memory update → Task 9.
- **Placeholder scan**: No TBD/TODO. Each step has concrete code or command.
- **Type consistency**: `close_component` signature matches across all tests (kwargs: `component`, `state_file`, `apply_feedback`, `cross_component`, `force`). Report dict keys consistent: `component`, `gated`, `forced`, `state_updated`, `feedback_rc`, `cross_triggered`, `next_component`, `errors`.
