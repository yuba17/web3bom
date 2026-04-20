"""Regression tests for extract_findings_from_yaml orphan-fuzz handling.

Context: the fuzzer broke `invariant_borrowIndicesNeverDecrease` in a real
yieldoor run, but extract_findings_from_yaml only correlated fuzz failures
against function names found inside hyp_*.yaml files. Invariants from the
generic registry (matcher.py) or merge-time injection have no owning YAML,
so a real bug was silently discarded — "Found 0 findings" despite a
counterexample captured by deep trace analysis.

These tests pin the orphan-fuzz branch so that regression never recurs.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from finding_pipeline import extract_findings_from_yaml


def _write_hyp(path: Path, component: str, hunter: str, hyps: list[dict]) -> Path:
    fp = path / f"hyp_{component}_{hunter}.yaml"
    fp.write_text(yaml.safe_dump({"hypotheses": hyps}), encoding="utf-8")
    return fp


def test_orphan_fuzz_failure_produces_synthetic_finding(tmp_path: Path) -> None:
    # Hunter YAML exists but references a DIFFERENT invariant function.
    _write_hyp(tmp_path, "LendingPool", "MathHunter", [
        {
            "id": "LENDING-MATH-01",
            "title": "Rounding in interest calc",
            "confidence": 70,
            "tier": 2,
            "validated": True,
            "solidity_property": "function invariant_interestRoundsDown() public {}",
        },
    ])

    fuzz_failures = {
        "invariant_borrowIndicesNeverDecrease": "sender=0xBEEF\ncall=borrow(1)\nrevert=assertion failed",
    }
    findings = extract_findings_from_yaml(tmp_path, "LendingPool", fuzz_failures)

    orphan = [f for f in findings if f["hunter"] == "FuzzOrphan"]
    assert len(orphan) == 1
    f = orphan[0]
    assert f["fuzz_confirmed"] is True
    assert f["property_name"] == "invariant_borrowIndicesNeverDecrease"
    assert "sender=0xBEEF" in f["counterexample_trace"]
    assert f["id"].startswith("FUZZ-LendingPool-")
    assert f["severity"] == "Medium"
    assert f["confidence"] >= 80


def test_owned_fuzz_failure_not_duplicated_as_orphan(tmp_path: Path) -> None:
    # Hunter YAML OWNS the broken invariant — no synthetic finding expected.
    _write_hyp(tmp_path, "LendingPool", "MathHunter", [
        {
            "id": "LENDING-MATH-01",
            "title": "Borrow index monotonicity",
            "confidence": 80,
            "tier": 1,
            "validated": True,
            "solidity_property": "function invariant_borrowIndicesNeverDecrease() public {}",
        },
    ])

    fuzz_failures = {
        "invariant_borrowIndicesNeverDecrease": "sender=0xBEEF\ntrace",
    }
    findings = extract_findings_from_yaml(tmp_path, "LendingPool", fuzz_failures)

    orphans = [f for f in findings if f["hunter"] == "FuzzOrphan"]
    owned = [f for f in findings if f["property_name"] == "invariant_borrowIndicesNeverDecrease"
             and f["hunter"] != "FuzzOrphan"]
    assert orphans == []
    assert len(owned) == 1
    assert owned[0]["fuzz_confirmed"] is True


def test_mixed_owned_and_orphan(tmp_path: Path) -> None:
    _write_hyp(tmp_path, "LendingPool", "MathHunter", [
        {
            "id": "LENDING-MATH-01",
            "title": "Owned inv",
            "confidence": 70,
            "tier": 1,
            "validated": True,
            "solidity_property": "function invariant_totalDebtEqSumPositions() public {}",
        },
    ])
    fuzz_failures = {
        "invariant_totalDebtEqSumPositions": "trace-A",
        "invariant_borrowIndicesNeverDecrease": "trace-B",
        "invariant_sharePriceMonotonic": "trace-C",
    }
    findings = extract_findings_from_yaml(tmp_path, "LendingPool", fuzz_failures)

    confirmed = [f for f in findings if f["fuzz_confirmed"]]
    prop_names = {f["property_name"] for f in confirmed}
    assert prop_names == {
        "invariant_totalDebtEqSumPositions",
        "invariant_borrowIndicesNeverDecrease",
        "invariant_sharePriceMonotonic",
    }
    orphans = [f for f in confirmed if f["hunter"] == "FuzzOrphan"]
    assert {f["property_name"] for f in orphans} == {
        "invariant_borrowIndicesNeverDecrease",
        "invariant_sharePriceMonotonic",
    }


def test_no_fuzz_failures_no_orphans(tmp_path: Path) -> None:
    _write_hyp(tmp_path, "LendingPool", "MathHunter", [
        {
            "id": "X",
            "title": "t",
            "confidence": 70,
            "tier": 2,
            "validated": True,
            "solidity_property": "function invariant_x() public {}",
        },
    ])
    findings = extract_findings_from_yaml(tmp_path, "LendingPool", {})
    assert all(f["hunter"] != "FuzzOrphan" for f in findings)


def test_orphan_fuzz_with_no_hyp_files(tmp_path: Path) -> None:
    # Edge case: no hypotheses at all, but fuzzer broke an invariant.
    fuzz_failures = {"invariant_borrowIndicesNeverDecrease": "trace"}
    findings = extract_findings_from_yaml(tmp_path, "LendingPool", fuzz_failures)
    assert len(findings) == 1
    assert findings[0]["hunter"] == "FuzzOrphan"
    assert findings[0]["fuzz_confirmed"] is True


def test_benchmark_extract_honors_explicit_hyp_dir(tmp_path: Path, monkeypatch) -> None:
    """benchmark.finding_pipeline.extract_findings must read from the hyp_dir
    argument, not from the module-level HUNT_SESSION_DIR snapshot.

    Regression: cli.main() reassigns run_benchmark.HUNT_SESSION_DIR to
    `benchmarks/<p>/bench_session/` when a benchmark starts. A legacy
    `from paths import HUNT_SESSION_DIR` in benchmark/finding_pipeline.py
    captured the original value at import time and kept reading the empty
    standalone hunt_session dir — resulting in "Found 0 findings" despite
    30 hypothesis YAMLs sitting in the reassigned bench_session path.
    """
    from benchmark.finding_pipeline import extract_findings as bench_extract

    # Arrange: hypotheses in an arbitrary directory that is NOT HUNT_SESSION_DIR
    bench_hyp_dir = tmp_path / "fake-bench-session" / "hypotheses" / "myproto"
    bench_hyp_dir.mkdir(parents=True)
    _write_hyp(bench_hyp_dir, "Leverager", "LogicHunter", [
        {
            "id": "LEV-LOG-01",
            "title": "withdraw copy-paste",
            "confidence": 93,
            "tier": 1,
            "validated": True,
            "solidity_property": "function invariant_withdrawSymmetric() public {}",
        },
    ])

    # Point run_benchmark.HUNT_SESSION_DIR somewhere completely different (empty).
    # If extract_findings used that, it would find 0 findings.
    import run_benchmark as _rb
    original = _rb.HUNT_SESSION_DIR
    try:
        _rb.HUNT_SESSION_DIR = tmp_path / "empty-hunt-session"
        (_rb.HUNT_SESSION_DIR / "hypotheses" / "myproto").mkdir(parents=True)

        findings = bench_extract("Leverager", "myproto", {}, hyp_dir=bench_hyp_dir)
    finally:
        _rb.HUNT_SESSION_DIR = original

    assert len(findings) == 1, "must read from explicit hyp_dir, not HUNT_SESSION_DIR"
    assert findings[0]["id"] == "LEV-LOG-01"


def test_benchmark_extract_fallback_uses_runtime_HUNT_SESSION_DIR(tmp_path: Path) -> None:
    """When hyp_dir is not passed, extract_findings must read the CURRENT
    value of run_benchmark.HUNT_SESSION_DIR (late binding), not a snapshot.
    """
    from benchmark.finding_pipeline import extract_findings as bench_extract

    fake_session = tmp_path / "bench_session"
    hyp_dir = fake_session / "hypotheses" / "myproto"
    hyp_dir.mkdir(parents=True)
    _write_hyp(hyp_dir, "Leverager", "MathHunter", [
        {
            "id": "LEV-MATH-01",
            "title": "x",
            "confidence": 80,
            "tier": 1,
            "validated": True,
            "solidity_property": "function invariant_x() public {}",
        },
    ])

    import run_benchmark as _rb
    original = _rb.HUNT_SESSION_DIR
    try:
        _rb.HUNT_SESSION_DIR = fake_session
        findings = bench_extract("Leverager", "myproto", {})
    finally:
        _rb.HUNT_SESSION_DIR = original

    assert len(findings) == 1
    assert findings[0]["id"] == "LEV-MATH-01"
