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
    parse_phase1_progress,
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
    assert snap.active_component == "Alpha"
    assert snap.active_gate == "hunters"


def test_parse_recent_events_extracts_step_markers(tmp_path):
    log = tmp_path / "orchestrator.log"
    log.write_text(
        "2026-04-20 16:58:40 INFO | some noise line\n"
        "2026-04-20 16:58:41 INFO |   Step 4: DeepDive Hunter\n"
        "2026-04-20 16:58:42 INFO |   Running claude -p sub (3175 chars)...\n"
        "2026-04-20 16:58:43 INFO |   12 Hunters completed (5.2min)\n"
    )
    import dashboard as d
    events, new_offset = d.parse_recent_events(log, offset=0, max_events=3)
    assert new_offset == log.stat().st_size
    assert len(events) == 3
    assert any("Step 4: DeepDive Hunter" in msg for _, _, msg in events)
    assert any("12 Hunters completed" in msg for _, _, msg in events)


def test_parse_phase1_progress_reads_latest_runs(tmp_path):
    from dashboard import parse_phase1_progress
    log = tmp_path / "orch.log"
    log.write_text("\n".join([
        "foo",
        "runs: 500 / 5000",
        "bar",
        "runs: 2300 / 5000",
        "runs: 4100 / 5000",
    ]) + "\n")
    assert parse_phase1_progress(log) == 4100


def test_parse_phase1_progress_missing(tmp_path):
    from dashboard import parse_phase1_progress
    assert parse_phase1_progress(tmp_path / "does_not_exist.log") is None


def test_findings_severity_aggregation():
    import dashboard as d
    findings = [
        {"severity": "High"}, {"severity": "high"}, {"severity": "MEDIUM"},
        {"severity": "low"}, {"severity": "low"}, {"severity": "low"},
        {},  # no severity → "unknown"
    ]
    counts = d.aggregate_findings_by_severity(findings)
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 3
    assert counts["unknown"] == 1
