from __future__ import annotations

import subprocess
import sys
from pathlib import Path


AUDIT = Path(__file__).resolve().parents[2]


def test_help_mentions_auto_components() -> None:
    res = subprocess.run(
        [sys.executable, str(AUDIT / "run_benchmark.py"), "--help"],
        capture_output=True, text=True, check=True,
    )
    assert "--auto-components" in res.stdout
    assert "--components" in res.stdout


def test_neither_components_nor_auto_errors() -> None:
    res = subprocess.run(
        [sys.executable, str(AUDIT / "run_benchmark.py"),
         "--repo", "/tmp", "--protocol", "x"],
        capture_output=True, text=True,
    )
    assert res.returncode != 0
    combined = (res.stdout + res.stderr).lower()
    assert "components" in combined


def test_both_components_and_auto_errors() -> None:
    res = subprocess.run(
        [sys.executable, str(AUDIT / "run_benchmark.py"),
         "--repo", "/tmp", "--protocol", "x",
         "--components", "A", "--auto-components"],
        capture_output=True, text=True,
    )
    assert res.returncode != 0
    combined = (res.stdout + res.stderr).lower()
    assert "auto-components" in combined or "mutually" in combined or "exactly one" in combined
