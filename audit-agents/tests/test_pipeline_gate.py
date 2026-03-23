"""Tests for pipeline_gate.py — gate status export."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GATE_STATUS_FILE = Path(__file__).resolve().parent.parent.parent / "hunt_session" / "gate_status.json"


def test_export_gate_status_creates_json():
    """export_gate_status() writes gate_status.json with correct structure."""
    if GATE_STATUS_FILE.exists():
        GATE_STATUS_FILE.unlink()

    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")

    assert GATE_STATUS_FILE.exists()
    data = json.loads(GATE_STATUS_FILE.read_text())
    assert "component_gates" in data
    assert "PreLiquidation" in data["component_gates"]
    assert "updated_at" in data


def test_export_is_incremental():
    """Exporting a second component merges into existing file."""
    if GATE_STATUS_FILE.exists():
        GATE_STATUS_FILE.unlink()

    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")
    export_gate_status("Bundler3", "")

    data = json.loads(GATE_STATUS_FILE.read_text())
    assert "PreLiquidation" in data["component_gates"]
    assert "Bundler3" in data["component_gates"]


def test_gate_states_are_4_state():
    """Gates use pass/fail/pending/skip — not boolean ok."""
    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")
    data = json.loads(GATE_STATUS_FILE.read_text())
    comp = data["component_gates"]["PreLiquidation"]
    states_used = {comp[g]["state"] for g in comp if isinstance(comp.get(g), dict) and "state" in comp[g]}
    # At minimum should have some pass and some fail/pending
    assert len(states_used) >= 2, f"Only states found: {states_used}"


def test_poc_gate_requires_fork():
    """PoC gate must verify vm.createFork or vm.selectFork usage."""
    from pipeline_gate import _check_poc_uses_fork

    # Mock PoC with fork
    poc_with_fork = """
    function test_exploit() public {
        uint256 forkId = vm.createFork(vm.envString("BASE_RPC_URL"), 12345);
        vm.selectFork(forkId);
        // ... exploit ...
    }
    """
    assert _check_poc_uses_fork(poc_with_fork) is True

    # Mock PoC without fork
    poc_no_fork = """
    function test_exploit() public {
        token.transfer(attacker, 1000);
        assertEq(token.balanceOf(attacker), 1000);
    }
    """
    assert _check_poc_uses_fork(poc_no_fork) is False

    # Edge case: fork in comment doesn't count
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

    # Variant: PL-M-01 → PL-M-01-V1
    assert generate_queue_id("variant", "PL-M-01") == "PL-M-01-V1"

    # Cross-component: alphabetical order
    xc_id = generate_queue_id("cross-component", None, ["Vault", "Gauge"])
    assert xc_id == "XC-Gauge-Vault-01"

    # Spillover
    sp_id = generate_queue_id("hunter_spillover", None, component="Factory", hunter="MathHunter")
    assert sp_id == "MATH-Factory-01"


def test_queue_finding_adds_to_state(tmp_path, monkeypatch):
    """queue_finding() adds entry to current_hunt.json finding_queue."""
    import pipeline_gate
    fake_state = tmp_path / "current_hunt.json"
    fake_state.write_text('{"protocol":"test","findings":[]}')
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", fake_state)

    entry = pipeline_gate.queue_finding(
        source="variant",
        parent_id="TEST-01",
        title="Test variant finding",
        component="TestContract",
        severity="medium",
        notes="test note"
    )
    assert entry["id"] == "TEST-01-V1"
    assert entry["status"] == "pending_pipeline"

    state = pipeline_gate.load_state()
    queue = state.get("finding_queue", [])
    match = [f for f in queue if f["id"] == "TEST-01-V1"]
    assert len(match) == 1


def test_queue_promote_moves_to_findings(tmp_path, monkeypatch):
    """queue_promote() moves item from finding_queue to findings."""
    import pipeline_gate
    fake_state = tmp_path / "current_hunt.json"
    fake_state.write_text('{"protocol":"test","findings":[]}')
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", fake_state)

    pipeline_gate.queue_finding(source="variant", parent_id="PROMO-01",
                  title="Promotable", component="X", severity="high")

    # Must be "completed" before promoting
    pipeline_gate.queue_update("PROMO-01-V1", "completed")
    pipeline_gate.queue_promote("PROMO-01-V1")

    state = pipeline_gate.load_state()
    queue_ids = [f["id"] for f in state.get("finding_queue", [])]
    finding_ids = [f["id"] for f in state.get("findings", [])]
    assert "PROMO-01-V1" not in queue_ids
    assert "PROMO-01-V1" in finding_ids
