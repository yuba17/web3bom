"""Contract tests for the Phase 9 pipeline_gate.py shim.

After the split, pipeline_gate.py is a thin shim that re-exports the
public API of the gate/ package. These tests lock in:
  1. The intentional public API remains importable from pipeline_gate.
  2. The shim stays under its LOC budget (canonical form).
  3. All gate/ submodules are importable as a package.
"""

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pipeline_gate

# Intentional public API. Does not include transient imports that
# leaked through wildcard re-exports (Path, datetime, sys, yaml,
# load_state) — those are not part of the contract.
EXPECTED_PUBLIC = {
    # Constants
    "DISPLAY_FINDING_GATES",
    "DISPLAY_GATES",
    "FINDING_GATE_CHECKS",
    "FINDING_GATE_ORDER",
    "GATE_CHECKS",
    "GATE_ORDER",
    "HUNTER_NAMES",
    "HUNT_SESSION_DIR",
    "REPORTS_DIR",
    "RESULTS_DIR",
    "SCOPE_MASTER_DIR",
    "STATE_FILE",
    "WEB3_DIR",
    # Component gate checks
    "check_compile",
    "check_crosschain",
    "check_deepdive",
    "check_hunters",
    "check_merge",
    "check_phase1",
    "check_phase2",
    "check_phase3",
    "check_phase4",
    "check_phase5",
    "check_prepass",
    "check_scope",
    # Finding gate checks
    "check_finding_escalation",
    "check_finding_poc",
    "check_finding_redteam",
    "check_finding_report",
    "check_finding_submit",
    "check_finding_variant",
    "check_finding_verify",
    # Scope master
    "scope_master_on_complete",
    "scope_master_on_finding",
    "scope_master_on_review",
    "show_scope_status",
    # Finding queue
    "generate_queue_id",
    "list_queue",
    "queue_finding",
    "queue_promote",
    "queue_update",
    # Gate status I/O
    "export_finding_gate_status",
    "export_gate_status",
    # Ficha
    "load_ficha",
    "update_ficha",
    # Path helpers
    "get_context_dir",
    "get_gate_status_file",
    "get_hyp_dir",
    # CLI
    "main",
    "mark_finding_gate",
    "mark_gate",
    "run_finding_gate",
    "run_gate",
    "show_finding_status",
    "show_status",
}

GATE_SUBMODULES = [
    "gate",
    "gate.cli",
    "gate.constants",
    "gate.ficha",
    "gate.finding_queue",
    "gate.gate_status",
    "gate.gates_component",
    "gate.gates_finding",
    "gate.scope_master",
]


def test_shim_reexports_public_api():
    """All intentional public symbols must remain importable from pipeline_gate."""
    actual = set(dir(pipeline_gate))
    missing = EXPECTED_PUBLIC - actual
    assert not missing, f"Shim dropped public symbols: {sorted(missing)}"


def test_shim_loc_budget():
    """pipeline_gate.py must stay under 80 LOC (canonical shim form)."""
    shim_path = Path(pipeline_gate.__file__)
    loc = sum(1 for _ in shim_path.open())
    assert loc < 80, f"pipeline_gate.py grew to {loc} LOC (budget: <80)"


def test_gate_package_modules_importable():
    """All gate/ submodules must be importable."""
    for name in GATE_SUBMODULES:
        importlib.import_module(name)
