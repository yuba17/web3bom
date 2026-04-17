"""F016 — deep_flatten subprocess wrapper with LOC threshold."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from context_enrichment import DEEP_FLATTEN_MIN_LINES, run_deep_flatten


@pytest.fixture(autouse=True)
def _clear_flatten_cache():
    import context_enrichment
    context_enrichment._flatten_mem_cache.clear()
    yield
    context_enrichment._flatten_mem_cache.clear()


def test_empty_for_missing_file(tmp_path):
    assert run_deep_flatten(tmp_path / "nope.sol") == ""


def test_skipped_below_threshold(tmp_path):
    f = tmp_path / "small.sol"
    f.write_text("\n".join(["// line"] * 50))  # 50 lines < 200
    with patch("context_enrichment.subprocess.run") as m:
        out = run_deep_flatten(f)
    assert out == ""
    m.assert_not_called()


def _make_large_contract(path: Path, lines: int = DEEP_FLATTEN_MIN_LINES + 10) -> Path:
    path.write_text("\n".join(["// filler"] * lines))
    return path


def test_runs_above_threshold(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## Deep Flatten\nok\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        out = run_deep_flatten(f)
    assert "Deep Flatten" in out
    m.assert_called_once()


def test_error_returncode_returns_empty(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        assert run_deep_flatten(f) == ""


def test_caches_across_calls(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## cache test\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        run_deep_flatten(f)
        run_deep_flatten(f)
    assert m.call_count == 1
