"""narrator — append human-friendly narration lines for dashboard display.

Each call writes one JSONL row to hunt_session/narration/<protocol>.jsonl so
dashboard.py can tail it and render a live "Claude is doing X" panel in
natural language, independent of the cryptic orchestrator.log.
"""
from __future__ import annotations

import fcntl
import json
from datetime import datetime
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext
from paths import HUNT_SESSION_DIR


def narrate(ctx: PipelineContext, emoji: str, message: str) -> None:
    """Append one narration entry. Thread/process safe via fcntl lock."""
    path = HUNT_SESSION_DIR / "narration" / f"{ctx.protocol}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "component": ctx.component,
        "emoji": emoji,
        "message": message,
    }
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            fh.write(line)
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)
