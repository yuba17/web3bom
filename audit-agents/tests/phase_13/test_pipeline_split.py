"""Phase 13 contract tests — pipeline split structural invariants."""

import importlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PIPELINE_DIR = REPO / "benchmark" / "component_pipeline"

PHASE_MODULES = [
    "pipeline_context",
    "context", "hunters", "deepdive", "merge", "enhance",
    "fuzz", "extract", "verify", "poc", "finding",
]

LOC_BUDGET = {
    "runner.py": 120,
    "pipeline_context.py": 100,
    "context.py": 400,
    "hunters.py": 280,
    "deepdive.py": 120,
    "merge.py": 320,
    "enhance.py": 100,
    "fuzz.py": 360,
    "extract.py": 110,
    "verify.py": 120,
    "poc.py": 230,
    "finding.py": 120,
}


def test_pipeline_context_importable():
    mod = importlib.import_module("benchmark.component_pipeline.pipeline_context")
    assert hasattr(mod, "PipelineContext")


def test_runner_loc_budget():
    runner = PIPELINE_DIR / "runner.py"
    loc = sum(1 for _ in runner.read_text().splitlines())
    assert loc <= LOC_BUDGET["runner.py"], f"runner.py is {loc} LOC, budget {LOC_BUDGET['runner.py']}"


def test_all_phase_modules_importable():
    for name in PHASE_MODULES:
        importlib.import_module(f"benchmark.component_pipeline.{name}")


def test_phase_loc_budgets():
    for fname, budget in LOC_BUDGET.items():
        path = PIPELINE_DIR / fname
        if not path.exists():
            continue
        loc = sum(1 for _ in path.read_text().splitlines())
        assert loc <= budget, f"{fname} is {loc} LOC, budget {budget}"


def test_run_component_pipeline_entry_point():
    mod = importlib.import_module("benchmark.component_pipeline.runner")
    assert callable(getattr(mod, "run_component_pipeline", None))
