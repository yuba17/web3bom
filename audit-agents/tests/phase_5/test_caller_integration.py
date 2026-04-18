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
