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
