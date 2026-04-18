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
    # Patches subprocess.run in the module namespace — safe only if callers
    # use `import subprocess; subprocess.run(...)`, NOT `from subprocess import run`.
    monkeypatch.setattr(subprocess, "run", _fake_run)
    _fake_run.calls = calls
    return _fake_run
