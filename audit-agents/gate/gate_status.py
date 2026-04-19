"""Per-protocol gate_status JSON I/O and status mutations.

Hosts pure I/O helpers `_load_gate_status` / `_save_gate_status` plus the
component-level `export_gate_status` that writes per-protocol gate_status
summaries. Finding-level export stays in pipeline_gate.py until Task 6
(extract finding gate checks), because it depends on _find_hyp_with_finding
and FINDING_GATE_CHECKS which remain in the shim.

Late-bound HUNT_SESSION_DIR lookup is inherited from gate.gates_component
via get_gate_status_file, so test_pipeline_gate.py monkeypatches on
`pipeline_gate.HUNT_SESSION_DIR` continue to apply here without extra work.
"""

import json
from datetime import datetime

from state_manager import load_state
from gate.gates_component import (
    get_gate_status_file,
    GATE_CHECKS,
    DISPLAY_GATES,
)

__all__ = [
    "_map_gate_state",
    "_load_gate_status",
    "_save_gate_status",
    "export_gate_status",
]


def _map_gate_state(ok: bool, detail: str) -> str:
    """Map gate result to 4-state: pass, fail, pending, skip."""
    if ok and detail.startswith("SKIP"):
        return "skip"
    if ok:
        return "pass"
    return "fail"


def _load_gate_status(protocol: str) -> dict:
    """Load existing per-protocol gate_status JSON or return empty structure."""
    gate_file = get_gate_status_file(protocol)
    if gate_file.exists():
        try:
            return json.loads(gate_file.read_text())
        except json.JSONDecodeError:
            pass
    return {"component_gates": {}, "finding_gates": {}, "updated_at": ""}


def _save_gate_status(data: dict, protocol: str):
    """Write per-protocol gate_status JSON atomically."""
    gate_file = get_gate_status_file(protocol)
    data["updated_at"] = datetime.now().isoformat()
    gate_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = gate_file.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        tmp.rename(gate_file)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def export_gate_status(component: str, repo: str = ""):
    """Run all gates for a component and write results to per-protocol gate_status.json."""
    state_data = load_state()
    protocol = state_data.get("protocol", "")
    status = _load_gate_status(protocol)
    comp_data = {}
    first_fail = None
    passed_count = 0

    for g in DISPLAY_GATES:
        if first_fail is not None:
            # Gates after first failure are not yet reached
            comp_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        if g not in GATE_CHECKS:
            comp_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        ok, passed, failed = GATE_CHECKS[g](component, repo)
        detail = passed[0] if passed else (failed[0] if failed else "")
        state = _map_gate_state(ok, detail)
        comp_data[g] = {"state": state, "detail": detail}
        if state in ("pass", "skip"):
            passed_count += 1
        elif first_fail is None:
            first_fail = g

    comp_data["progress"] = f"{passed_count}/{len(DISPLAY_GATES)}"
    comp_data["blocked_at"] = first_fail
    comp_data["updated_at"] = datetime.now().isoformat()

    status["component_gates"][component] = comp_data

    # Also export finding_queue_summary from current_hunt.json
    queue = state_data.get("finding_queue", [])
    status["finding_queue_summary"] = {
        "total": len(queue),
        "pending": sum(1 for f in queue if f.get("status") == "pending_pipeline"),
        "in_pipeline": sum(1 for f in queue if f.get("status") == "in_pipeline"),
    }

    _save_gate_status(status, protocol)
