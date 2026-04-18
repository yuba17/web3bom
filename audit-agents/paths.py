"""paths.py — Canonical path constants for the audit-agents toolchain.

Single source of truth for the 4 paths that were duplicated across 3+ files
before Phase 5. Anchored at ``Path.home() / "Documents" / "Web3"`` because
the modern flow always runs from that directory (CLAUDE.md enforces the cwd).

Consumers with < 3 definitions (REPORTS_DIR, KNOWLEDGE_DIR, VAULT_RAW,
BENCHMARKS_DIR) intentionally keep their local definitions — they are
definition-at-point-of-use, not duplication.
"""
from __future__ import annotations

from pathlib import Path

WEB3_DIR = Path.home() / "Documents" / "Web3"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
