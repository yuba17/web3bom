"""Phase 2B — run_benchmark.py --apply-feedback flag tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def test_help_mentions_apply_feedback():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert "--apply-feedback" in r.stdout
