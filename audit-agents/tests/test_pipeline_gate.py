"""Tests for pipeline_gate.py — gate status export + finding queue.

Post-Phase-5 reality: gate_status is per-protocol at
`hunt_session/gate_status/<protocol>.json` (directory, not single file).
`current_hunt.json` I/O is delegated to `state_manager`, whose STATE_FILE is
bound from `paths` at import time — tests must monkeypatch
`state_manager.STATE_FILE` (not just `pipeline_gate.STATE_FILE`).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _isolate(tmp_path, monkeypatch, protocol="testproto"):
    """Redirect hunt_session + STATE_FILE into tmp_path for a single test."""
    import pipeline_gate
    import state_manager

    fake_hunt = tmp_path / "hunt_session"
    fake_hunt.mkdir(parents=True, exist_ok=True)
    fake_state = fake_hunt / "current_hunt.json"
    fake_state.write_text(json.dumps({
        "protocol": protocol,
        "findings": [],
        "finding_queue": [],
    }))

    monkeypatch.setattr(pipeline_gate, "HUNT_SESSION_DIR", fake_hunt)
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", fake_state)
    monkeypatch.setattr(state_manager, "STATE_FILE", fake_state)
    return fake_hunt, fake_state, protocol


def test_export_gate_status_creates_json(tmp_path, monkeypatch):
    """export_gate_status() writes per-protocol JSON with correct structure."""
    fake_hunt, _, protocol = _isolate(tmp_path, monkeypatch)
    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")

    gate_file = fake_hunt / "gate_status" / f"{protocol}.json"
    assert gate_file.exists()
    data = json.loads(gate_file.read_text())
    assert "component_gates" in data
    assert "PreLiquidation" in data["component_gates"]
    assert "updated_at" in data


def test_export_is_incremental(tmp_path, monkeypatch):
    """Exporting a second component merges into the same per-protocol file."""
    fake_hunt, _, protocol = _isolate(tmp_path, monkeypatch)
    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")
    export_gate_status("Bundler3", "")

    gate_file = fake_hunt / "gate_status" / f"{protocol}.json"
    data = json.loads(gate_file.read_text())
    assert "PreLiquidation" in data["component_gates"]
    assert "Bundler3" in data["component_gates"]


def test_gate_states_are_4_state(tmp_path, monkeypatch):
    """Gates use pass/fail/pending/skip — not boolean ok."""
    fake_hunt, _, protocol = _isolate(tmp_path, monkeypatch)
    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")

    gate_file = fake_hunt / "gate_status" / f"{protocol}.json"
    data = json.loads(gate_file.read_text())
    comp = data["component_gates"]["PreLiquidation"]
    states_used = {
        comp[g]["state"]
        for g in comp
        if isinstance(comp.get(g), dict) and "state" in comp[g]
    }
    assert len(states_used) >= 2, f"Only states found: {states_used}"


def test_poc_gate_requires_fork():
    """PoC gate must verify vm.createFork or vm.selectFork usage."""
    from pipeline_gate import _check_poc_uses_fork

    poc_with_fork = """
    function test_exploit() public {
        uint256 forkId = vm.createFork(vm.envString("BASE_RPC_URL"), 12345);
        vm.selectFork(forkId);
        // ... exploit ...
    }
    """
    assert _check_poc_uses_fork(poc_with_fork) is True

    poc_no_fork = """
    function test_exploit() public {
        token.transfer(attacker, 1000);
        assertEq(token.balanceOf(attacker), 1000);
    }
    """
    assert _check_poc_uses_fork(poc_no_fork) is False

    poc_comment_fork = """
    function test_exploit() public {
        // vm.createFork would be nice but we use mocks
        token.transfer(attacker, 1000);
    }
    """
    assert _check_poc_uses_fork(poc_comment_fork) is False


def test_queue_finding_generates_id():
    """--queue-finding auto-generates variant ID from parent."""
    from pipeline_gate import generate_queue_id

    assert generate_queue_id("variant", "PL-M-01") == "PL-M-01-V1"

    xc_id = generate_queue_id("cross-component", None, ["Vault", "Gauge"])
    assert xc_id == "XC-Gauge-Vault-01"

    sp_id = generate_queue_id("hunter_spillover", None, component="Factory", hunter="MathHunter")
    assert sp_id == "MATH-Factory-01"


def test_queue_finding_adds_to_state(tmp_path, monkeypatch):
    """queue_finding() adds entry to current_hunt.json finding_queue."""
    _, _, _ = _isolate(tmp_path, monkeypatch)
    import pipeline_gate

    entry = pipeline_gate.queue_finding(
        source="variant",
        parent_id="TEST-01",
        title="Test variant finding",
        component="TestContract",
        severity="medium",
        notes="test note",
    )
    assert entry["id"] == "TEST-01-V1"
    assert entry["status"] == "pending_pipeline"

    state = pipeline_gate.load_state()
    queue = state.get("finding_queue", [])
    match = [f for f in queue if f["id"] == "TEST-01-V1"]
    assert len(match) == 1


def test_queue_promote_moves_to_findings(tmp_path, monkeypatch):
    """queue_promote() moves item from finding_queue to findings."""
    _, _, _ = _isolate(tmp_path, monkeypatch)
    import pipeline_gate

    pipeline_gate.queue_finding(source="variant", parent_id="PROMO-01",
                                title="Promotable", component="X", severity="high")

    pipeline_gate.queue_update("PROMO-01-V1", "completed")
    pipeline_gate.queue_promote("PROMO-01-V1")

    state = pipeline_gate.load_state()
    queue_ids = [f["id"] for f in state.get("finding_queue", [])]
    finding_ids = [f["id"] for f in state.get("findings", [])]
    assert "PROMO-01-V1" not in queue_ids
    assert "PROMO-01-V1" in finding_ids
