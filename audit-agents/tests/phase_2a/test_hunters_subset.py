"""F002 — --hunters subset CLI flag."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def _run(*args: str):
    return subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )


def test_help_mentions_hunters_flag():
    r = _run("--help")
    assert r.returncode == 0
    assert "--hunters" in r.stdout
    assert "subset" in r.stdout.lower()


def test_invalid_subset_exits_nonzero_with_valid_list():
    r = _run(
        "--repo", "/tmp", "--components", "X", "--protocol", "y",
        "--hunters", "BogusHunter",
    )
    assert r.returncode != 0
    assert "BogusHunter" in (r.stderr + r.stdout)
    assert "MathHunter" in (r.stderr + r.stdout)  # valid list surfaced


def test_valid_subset_accepted_by_argparse(tmp_path):
    # Use --help to avoid running the whole pipeline — we only verify argparse accepts.
    # Re-parse args by invoking a dry-run path: provide --ground-truth that triggers
    # scope-detection failure early, but AFTER argparse validation.
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _validate_hunters_subset  # unit-level function
    ok = _validate_hunters_subset("MathHunter,AccessHunter")
    assert ok == {"MathHunter", "AccessHunter"}


def test_validate_rejects_unknown():
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _validate_hunters_subset
    with pytest.raises(SystemExit):
        _validate_hunters_subset("MathHunter,NotARealHunter")
