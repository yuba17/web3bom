"""Phase 2B — solodit_to_wiki.py tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "audit-agents" / "solodit_to_wiki.py"


def test_help_mentions_all_flags():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert "--cards-dir" in r.stdout
    assert "--output-dir" in r.stdout
    assert "--dry-run" in r.stdout
