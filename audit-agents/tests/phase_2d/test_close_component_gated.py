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
