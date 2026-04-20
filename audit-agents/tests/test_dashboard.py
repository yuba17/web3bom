"""Tests for dashboard data helpers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dashboard import (
    load_current_hunt,
    load_gate_status,
    load_findings,
    build_snapshot,
    parse_recent_events,
    aggregate_findings_by_severity,
    HuntSnapshot,
)


def test_load_current_hunt_present(tmp_path, monkeypatch):
    state_dir = tmp_path / "hunt_session" / "MEMORY" / "STATE"
    state_dir.mkdir(parents=True)
    (state_dir / "current_hunt.json").write_text(
        json.dumps({"protocol": "yieldoor-bench", "components": ["Leverager", "LendingPool"]})
    )
    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", state_dir / "current_hunt.json")
    data = d.load_current_hunt()
    assert data["protocol"] == "yieldoor-bench"
    assert data["components"] == ["Leverager", "LendingPool"]


def test_load_current_hunt_missing(tmp_path, monkeypatch):
    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", tmp_path / "does_not_exist.json")
    assert d.load_current_hunt() == {}
