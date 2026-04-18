from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DEFAULT_STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
_AUDIT_AGENTS_DIR = Path(__file__).resolve().parent
_PIPELINE_GATE = _AUDIT_AGENTS_DIR / "pipeline_gate.py"
_APPLY_FEEDBACK = _AUDIT_AGENTS_DIR / "apply_feedback.py"


def _load_state(state_file: Path) -> dict:
    if not state_file.exists():
        return {}
    return json.loads(state_file.read_text())


def _save_state_atomic(state_file: Path, data: dict) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", delete=False, dir=state_file.parent, suffix=".tmp", encoding="utf-8"
    ) as tmp:
        json.dump(data, tmp, indent=2)
        tmp_path = Path(tmp.name)
    shutil.move(str(tmp_path), str(state_file))


def _run_gate(component: str) -> tuple[bool, str]:
    if not _PIPELINE_GATE.exists():
        return True, ""
    try:
        result = subprocess.run(
            [sys.executable, str(_PIPELINE_GATE), "--component", component, "--gate", "all"],
            capture_output=True, text=True, timeout=30,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "pipeline_gate timeout"


def _run_feedback() -> tuple[int | None, str]:
    if not _APPLY_FEEDBACK.exists():
        return None, ""
    try:
        result = subprocess.run(
            [sys.executable, str(_APPLY_FEEDBACK), "--hypotheses"],
            capture_output=True, text=True, timeout=60,
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode, output.strip()
    except subprocess.TimeoutExpired:
        return None, "apply_feedback timeout"


def close_component(
    *,
    component: str,
    state_file: Path | None = None,
    apply_feedback: bool = True,
    cross_component: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    state_file = state_file or _DEFAULT_STATE_FILE
    errors: list[str] = []

    state = _load_state(state_file)
    remaining = state.get("components_remaining", [])
    done = state.get("components_done", [])

    if component in done and component not in remaining:
        return {
            "component": component,
            "gated": True,
            "forced": False,
            "state_updated": False,
            "feedback_rc": None,
            "cross_triggered": False,
            "next_component": remaining[0] if remaining else None,
            "errors": [],
        }

    if component not in remaining and component not in done:
        raise ValueError(
            f"component '{component}' not found in components_remaining or components_done"
        )

    gated, gate_output = _run_gate(component)
    gate_detail = gate_output.strip()
    forced = False
    if not gated:
        if not force:
            return {
                "component": component,
                "gated": False,
                "forced": False,
                "state_updated": False,
                "feedback_rc": None,
                "cross_triggered": False,
                "next_component": remaining[0] if remaining else None,
                "errors": [gate_detail] if gate_detail else ["gate failed"],
            }
        forced = True
        errors.append(
            f"gate bypassed via force: {gate_detail}" if gate_detail else "gate bypassed via force"
        )

    if component in remaining:
        remaining.remove(component)
    if component not in done:
        done.append(component)
    state["components_remaining"] = remaining
    state["components_done"] = done
    state["current_component"] = remaining[0] if remaining else None
    state["last_session"] = datetime.now(timezone.utc).isoformat()
    for c in state.get("component_map", []):
        if c.get("name") == component:
            c["status"] = "done"
            break
    _save_state_atomic(state_file, state)

    feedback_rc: int | None = None
    if apply_feedback:
        feedback_rc, fb_output = _run_feedback()
        if feedback_rc not in (0, None):
            errors.append(f"apply_feedback rc={feedback_rc}: {fb_output.strip()}")

    return {
        "component": component,
        "gated": gated,
        "forced": forced,
        "state_updated": True,
        "feedback_rc": feedback_rc,
        "cross_triggered": bool(cross_component and len(done) >= 2),
        "next_component": remaining[0] if remaining else None,
        "errors": errors,
    }
