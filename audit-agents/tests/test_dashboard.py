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


def test_build_snapshot_merges_sources(tmp_path, monkeypatch):
    """Snapshot must merge current_hunt + gate_status + findings into one object."""
    state_dir = tmp_path / "hunt_session" / "MEMORY" / "STATE"
    state_dir.mkdir(parents=True)
    (state_dir / "current_hunt.json").write_text(
        json.dumps({"protocol": "testproto", "components": ["Alpha", "Beta"]})
    )
    gate_dir = tmp_path / "hunt_session" / "gate_status"
    gate_dir.mkdir(parents=True)
    (gate_dir / "testproto.json").write_text(json.dumps({
        "component_gates": {
            "Alpha": {
                "scope":   {"state": "pass", "detail": "ok"},
                "prepass": {"state": "pass", "detail": "ok"},
                "hunters": {"state": "pending", "detail": "active"},
            },
            "Beta": {
                "scope":   {"state": "pass", "detail": "ok"},
                "prepass": {"state": "pending", "detail": "active"},
            },
        }
    }))
    findings_path = tmp_path / "hunt_session" / "findings.json"
    findings_path.write_text(json.dumps({"findings": [
        {"severity": "high"},
        {"severity": "medium"},
    ]}))

    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", state_dir / "current_hunt.json")
    monkeypatch.setattr(d, "HUNT_SESSION", tmp_path / "hunt_session")

    snap = d.build_snapshot(protocol_override=None)

    assert snap.protocol == "testproto"
    assert snap.components == ["Alpha", "Beta"]
    assert snap.gates["Alpha"]["scope"] == "pass"
    assert snap.gates["Alpha"]["hunters"] == "pending"
    assert snap.findings_total == 2
    assert snap.findings_by_severity["high"] == 1
    assert snap.findings_by_severity["medium"] == 1
