"""F015 — symmetric_analyzer subprocess wrapper."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

import context_enrichment
from context_enrichment import run_symmetric_analysis


@pytest.fixture(autouse=True)
def _clear_sym_cache():
    """Clear module-level cache before each test to avoid cross-test pollution.

    All tmp_solidity_contract fixtures produce the same file content → same
    sha256 → same cache key. Without clearing, a cache hit in test N causes
    a false result in test N+1.
    """
    context_enrichment._symmetric_mem_cache.clear()
    yield
    context_enrichment._symmetric_mem_cache.clear()


def test_empty_for_missing_file(tmp_path):
    assert run_symmetric_analysis(tmp_path / "nope.sol") == ""


def test_empty_when_script_missing(tmp_solidity_contract, monkeypatch, tmp_path):
    import context_enrichment
    monkeypatch.setattr(context_enrichment, "AUDIT_AGENTS_DIR", tmp_path)
    assert run_symmetric_analysis(tmp_solidity_contract) == ""


def test_success_path_returns_stdout(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## Symmetry Analysis\nok\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        out = run_symmetric_analysis(tmp_solidity_contract)
    assert "Symmetry Analysis" in out


def test_error_returncode_returns_empty(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="ERROR: parse failed", stderr="boom"
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        assert run_symmetric_analysis(tmp_solidity_contract) == ""


def test_caching_avoids_second_subprocess(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## cache hit test\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        run_symmetric_analysis(tmp_solidity_contract, cache_dir=None)
        run_symmetric_analysis(tmp_solidity_contract, cache_dir=None)
    # Without cache_dir, caching uses module-level dict — second call hits cache
    assert m.call_count == 1


def test_filesystem_cache_roundtrip(tmp_solidity_contract, tmp_path):
    cache = tmp_path / "cache"
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## disk cache\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        out1 = run_symmetric_analysis(tmp_solidity_contract, cache_dir=cache)
    # Second call in a fresh mock should read from disk, NOT call subprocess
    with patch("context_enrichment.subprocess.run", side_effect=AssertionError("should be cached")) as m2:
        out2 = run_symmetric_analysis(tmp_solidity_contract, cache_dir=cache)
    assert out1 == out2 == "## disk cache"
