"""Phase 5 — canonical path constants."""
from pathlib import Path

from paths import (
    WEB3_DIR,
    AUDIT_AGENTS_DIR,
    HUNT_SESSION_DIR,
    STATE_FILE,
)


def test_paths_are_absolute():
    assert WEB3_DIR.is_absolute()
    assert AUDIT_AGENTS_DIR.is_absolute()
    assert HUNT_SESSION_DIR.is_absolute()
    assert STATE_FILE.is_absolute()


def test_web3_dir_is_home_documents_web3():
    assert WEB3_DIR == Path.home() / "Documents" / "Web3"


def test_hunt_session_dir_under_web3():
    assert HUNT_SESSION_DIR == WEB3_DIR / "hunt_session"
    assert AUDIT_AGENTS_DIR == WEB3_DIR / "audit-agents"


def test_state_file_under_claude_memory():
    assert STATE_FILE == Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
