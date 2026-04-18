from __future__ import annotations

import sys
from pathlib import Path

_AUDIT_AGENTS = Path(__file__).resolve().parents[2]


def ensure_audit_agents_on_path() -> None:
    if str(_AUDIT_AGENTS) not in sys.path:
        sys.path.insert(0, str(_AUDIT_AGENTS))
