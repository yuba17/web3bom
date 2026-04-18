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
