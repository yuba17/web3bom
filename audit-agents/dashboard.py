"""Real-time TUI dashboard for the audit pipeline.

Reads hunt_session JSONs + orchestrator.log and renders a live rich view.
Run: python3 audit-agents/dashboard.py [--protocol NAME]
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION = WEB3_DIR / "hunt_session"
CURRENT_HUNT = HUNT_SESSION / "MEMORY" / "STATE" / "current_hunt.json"


def load_current_hunt() -> dict[str, Any]:
    """Read current_hunt.json. Return {} if missing or malformed."""
    try:
        return json.loads(CURRENT_HUNT.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TUI dashboard for audit pipeline")
    p.add_argument("--protocol", help="Protocol name (overrides current_hunt.json)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print(f"dashboard started (protocol={args.protocol or 'auto'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
