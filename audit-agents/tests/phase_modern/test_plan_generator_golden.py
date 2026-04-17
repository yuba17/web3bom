"""Live golden tests for plan_generator.py --generate."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import assert_matches_golden


REPO_ROOT = Path(__file__).resolve().parents[3]
AUDIT_AGENTS = REPO_ROOT / "audit-agents"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Volatile or env-specific keys to exclude from golden comparison.
# - created_at: ISO timestamp changes every run
# - session_dir: tmp path changes every run
# - hypotheses_dir: derived from session_dir, also volatile
# - repo: absolute path, env-specific
# - command: embeds session_dir and sys.executable paths, volatile
PLAN_IGNORE_KEYS = ["created_at", "session_dir", "hypotheses_dir", "repo", "command"]


def _run_plan_generator(
    repo: Path,
    components: str,
    protocol: str,
    session_dir: Path,
    ground_truth: Path,
    *,
    fast: bool = True,
) -> dict:
    cmd = [
        sys.executable,
        str(AUDIT_AGENTS / "plan_generator.py"),
        "--generate",
        "--repo", str(repo),
        "--components", components,
        "--protocol", protocol,
        "--session-dir", str(session_dir),
        "--ground-truth", str(ground_truth),
    ]
    if fast:
        cmd.append("--fast")
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    assert result.returncode == 0, (
        f"plan_generator exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    plan_path = session_dir / "execution_plan.json"
    assert plan_path.exists(), f"Plan not written: {plan_path}"
    return json.loads(plan_path.read_text())


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_plan_full_yieldoor(
    language: str,
    benchmark: str,
    benchmark_fixture,
    tmp_session_dir: Path,
):
    repo = benchmark_fixture(language, benchmark)
    ground_truth = REPO_ROOT / "benchmarks" / benchmark / "benchmark.yaml"
    plan = _run_plan_generator(
        repo=repo,
        components="Vault,Strategy,Leverager,ReserveLogic",
        protocol=benchmark,
        session_dir=tmp_session_dir,
        ground_truth=ground_truth,
        fast=True,
    )
    golden = FIXTURES / language / benchmark / "goldens" / "plan_generator" / "execution_plan_full.json"
    assert_matches_golden(plan, golden, mode="json", ignore_keys=PLAN_IGNORE_KEYS)


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_plan_single_component(
    language: str,
    benchmark: str,
    benchmark_fixture,
    tmp_session_dir: Path,
):
    repo = benchmark_fixture(language, benchmark)
    ground_truth = REPO_ROOT / "benchmarks" / benchmark / "benchmark.yaml"
    plan = _run_plan_generator(
        repo=repo,
        components="Vault",
        protocol=benchmark,
        session_dir=tmp_session_dir,
        ground_truth=ground_truth,
        fast=True,
    )
    golden = FIXTURES / language / benchmark / "goldens" / "plan_generator" / "execution_plan_single.json"
    assert_matches_golden(plan, golden, mode="json", ignore_keys=PLAN_IGNORE_KEYS)


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_plan_ignores_created_at(
    language: str,
    benchmark: str,
    benchmark_fixture,
    tmp_session_dir: Path,
    tmp_path: Path,
):
    """Two runs of plan_generator produce plans with different created_at — golden still matches."""
    repo = benchmark_fixture(language, benchmark)
    ground_truth = REPO_ROOT / "benchmarks" / benchmark / "benchmark.yaml"
    plan_a = _run_plan_generator(
        repo=repo, components="Vault", protocol=benchmark,
        session_dir=tmp_session_dir, ground_truth=ground_truth, fast=True,
    )
    session_b = tmp_path / "session_b"
    session_b.mkdir()
    plan_b = _run_plan_generator(
        repo=repo, components="Vault", protocol=benchmark,
        session_dir=session_b, ground_truth=ground_truth, fast=True,
    )
    # created_at should differ (ISO timestamps)
    assert plan_a.get("created_at") != plan_b.get("created_at") or \
           plan_a.get("created_at") is None  # tolerate absent field
    # Both should match the same golden when created_at ignored
    golden = FIXTURES / language / benchmark / "goldens" / "plan_generator" / "execution_plan_single.json"
    assert_matches_golden(plan_a, golden, mode="json", ignore_keys=PLAN_IGNORE_KEYS)
    assert_matches_golden(plan_b, golden, mode="json", ignore_keys=PLAN_IGNORE_KEYS)


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_plan_includes_cross_when_multi_component(
    language: str,
    benchmark: str,
    benchmark_fixture,
    tmp_session_dir: Path,
):
    """Contract: with 2+ components the plan must include a cross-component step."""
    repo = benchmark_fixture(language, benchmark)
    ground_truth = REPO_ROOT / "benchmarks" / benchmark / "benchmark.yaml"
    plan = _run_plan_generator(
        repo=repo,
        components="Vault,Strategy",
        protocol=benchmark,
        session_dir=tmp_session_dir,
        ground_truth=ground_truth,
        fast=True,
    )
    step_ids = [s.get("id", "") for s in plan.get("steps", [])]
    assert any("cross" in sid for sid in step_ids), (
        f"No cross-component step found in plan. step ids: {step_ids}"
    )
