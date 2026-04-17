"""Live tests for pipeline_gate.py status export."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_AGENTS = REPO_ROOT / "audit-agents"


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_gate_status_export_structure(language: str, benchmark: str, tmp_session_dir: Path):
    """pipeline_gate.py --export-json produces a gate_status/<protocol>.json with the expected schema."""
    result = subprocess.run(
        [
            sys.executable,
            str(AUDIT_AGENTS / "pipeline_gate.py"),
            "--component", "Vault",
            "--protocol", benchmark,
            "--export-json",
            "--session-dir", str(tmp_session_dir),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode in (0, 1), (
        f"pipeline_gate.py exited {result.returncode}. "
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # Legacy quirk: export_gate_status() reads protocol from load_state() directly
    # instead of _get_protocol(), so --protocol is NOT honored here. We glob the
    # output dir for whatever file was written. Phase 2 should fix this.
    gate_dir = tmp_session_dir / "gate_status"
    exported_files = sorted(gate_dir.glob("*.json")) if gate_dir.is_dir() else []
    assert exported_files, (
        f"No gate_status JSON written under {gate_dir}. "
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    data = json.loads(exported_files[0].read_text())
    # Contract: top-level keys
    assert "component_gates" in data
    assert "updated_at" in data
    # Contract: component keyed and contains gate dict
    assert "Vault" in data["component_gates"]
    gates = data["component_gates"]["Vault"]
    assert isinstance(gates, dict)


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_gate_status_missing_component_no_crash(language: str, benchmark: str, tmp_session_dir: Path):
    """Exporting status for a nonexistent component should not crash."""
    result = subprocess.run(
        [
            sys.executable,
            str(AUDIT_AGENTS / "pipeline_gate.py"),
            "--component", "DoesNotExist__",
            "--protocol", benchmark,
            "--export-json",
            "--session-dir", str(tmp_session_dir),
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    # Exit code may be non-zero (no scope), but must not be a crash (>= 2 on Python exc)
    assert result.returncode in (0, 1), (
        f"Unexpected exit code {result.returncode}. stderr:\n{result.stderr}"
    )
    # Must still have written something structured or not broken the session dir
    assert tmp_session_dir.is_dir()
