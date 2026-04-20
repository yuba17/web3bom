"""gate_status_writer — reflect ctx.summary['gates'] to hunt_session/gate_status/<protocol>.json.

Benchmark mode does not invoke pipeline_gate.py, so the on-disk gate_status JSON
(which dashboard.py reads) would otherwise never update during a run. This helper
serialises the current gates dict into the schema dashboard.py + pipeline_gate.py
both understand, preserving other components' state via read-modify-write.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext
from paths import HUNT_SESSION_DIR

GATE_ORDER = (
    "scope", "prepass", "hunters", "crosschain", "deepdive",
    "merge", "compile", "phase1", "phase2", "phase3", "phase4", "phase5",
)


def flush_gate_status(ctx: PipelineContext) -> None:
    """Serialise ctx.summary['gates'] for this component. Atomic write."""
    path = HUNT_SESSION_DIR / "gate_status" / f"{ctx.protocol}.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data.setdefault("component_gates", {})
    data.setdefault("finding_gates", {})

    gates_dict = ctx.summary.get("gates", {})
    comp_entry: dict = {}
    passed = 0
    blocked_at = None
    for gate_name in GATE_ORDER:
        if gate_name in gates_dict:
            value = gates_dict[gate_name]
            state = "pass" if value else "fail"
            if value:
                passed += 1
            elif blocked_at is None:
                blocked_at = gate_name
            comp_entry[gate_name] = {"state": state, "detail": f"benchmark: {state}"}
        else:
            comp_entry[gate_name] = {"state": "pending", "detail": "Not yet reached"}

    comp_entry["progress"] = f"{passed}/{len(GATE_ORDER)}"
    if blocked_at:
        comp_entry["blocked_at"] = blocked_at
    now = datetime.utcnow().isoformat()
    comp_entry["updated_at"] = now

    data["component_gates"][ctx.component] = comp_entry
    data["updated_at"] = now

    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)
