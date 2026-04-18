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
