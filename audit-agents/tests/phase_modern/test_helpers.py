"""Self-tests for the snapshot helper."""
import json
import os
import sys
from pathlib import Path

import pytest

# Add this test's directory to sys.path so `from helpers import ...` works
sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import assert_matches_golden


def test_assert_matches_golden_pass(tmp_path: Path):
    golden = tmp_path / "golden.json"
    golden.write_text(json.dumps({"foo": 1, "bar": [1, 2]}))
    assert_matches_golden({"foo": 1, "bar": [1, 2]}, golden, mode="json")


def test_assert_matches_golden_diff(tmp_path: Path):
    golden = tmp_path / "golden.json"
    golden.write_text(json.dumps({"foo": 1}))
    with pytest.raises(AssertionError, match="Snapshot mismatch"):
        assert_matches_golden({"foo": 2}, golden, mode="json")


def test_update_mode_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    golden = tmp_path / "new_golden.json"
    monkeypatch.setenv("UPDATE_SNAPSHOTS", "1")
    with pytest.raises(pytest.skip.Exception):
        assert_matches_golden({"foo": 42}, golden, mode="json")
    assert golden.exists()
    assert json.loads(golden.read_text()) == {"foo": 42}


def test_ignore_keys_excluded_from_diff(tmp_path: Path):
    golden = tmp_path / "g.json"
    golden.write_text(json.dumps({"foo": 1, "created_at": "2026-01-01"}))
    # Different created_at but same foo — should pass because ignored
    assert_matches_golden(
        {"foo": 1, "created_at": "2026-04-17"},
        golden,
        mode="json",
        ignore_keys=["created_at"],
    )
