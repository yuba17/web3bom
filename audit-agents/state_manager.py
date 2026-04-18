"""state_manager.py — Single source of truth for current_hunt.json I/O.

Consolidates the 6 near-identical load_state() / save_state() variants that
lived in pipeline_gate, sync_state, submit_finding, report_finding,
merge_invariants, and component_closer before Phase 5.

Atomic write via tempfile → rename. Optional backup via `backup=True`
kwarg (opt-in) preserves the behaviour of callers that used to call
shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json")) first.

No file locks — the atomic rename already prevents corruption under
concurrent writes; no incidents observed to justify the extra complexity.
"""
from __future__ import annotations

import json
import shutil
from typing import Any

from paths import STATE_FILE


def load_state() -> dict[str, Any]:
    """Return parsed current_hunt.json, or {} if the file is absent.

    Propagates json.JSONDecodeError if the file exists but is malformed.
    """
    if not STATE_FILE.exists():
        return {}
    return json.loads(STATE_FILE.read_text())


def save_state(state: dict[str, Any], *, backup: bool = False) -> None:
    """Atomically write state to current_hunt.json.

    If backup=True and STATE_FILE exists, copy the current file to
    STATE_FILE.with_suffix(".backup.json") before the atomic rename.
    """
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if backup and STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
