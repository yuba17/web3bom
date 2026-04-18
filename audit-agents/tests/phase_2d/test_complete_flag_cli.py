from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCH = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RUN_BENCH), *args],
        capture_output=True, text=True, timeout=20,
    )


def test_help_mentions_complete():
    proc = _run_cli("--help")
    assert proc.returncode == 0
    assert "--complete" in proc.stdout


def test_complete_and_components_mutex_error():
    proc = _run_cli(
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--components", "Vault,Strategy",
    )
    assert proc.returncode != 0
    assert "mutually exclusive" in (proc.stderr + proc.stdout).lower()


def test_complete_and_auto_components_mutex_error():
    proc = _run_cli(
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--auto-components",
    )
    assert proc.returncode != 0
    assert "mutually exclusive" in (proc.stderr + proc.stdout).lower()
