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
