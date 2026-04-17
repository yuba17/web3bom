"""Frozen comparison tests for detection_engine --prepass outputs.

The prepass YAMLs are expensive to regenerate (Slither + Aderyn), so we
keep a copy of a known-good output and compare. Regenerate only on intent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from helpers import assert_matches_golden


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Extension point: adding a new language = adding rows here + dropping goldens
# and fixtures under `fixtures/<language>/<benchmark>/`. No test rewrites needed.
#   ("rust", "<benchmark>", "<component>"),   # TODO(phase-2+): Rust path migration
#   ("move", "<benchmark>", "<component>"),   # TODO(phase-2+): Aptos/Sui targets
#   ("cairo", "<benchmark>", "<component>"),  # TODO(phase-2+): Starknet targets
LANGUAGE_BENCHMARK_COMPONENT_MATRIX = [
    ("solidity", "yieldoor", "Vault"),
    ("solidity", "yieldoor", "Strategy"),
]
LANGUAGE_BENCHMARK_MATRIX = [("solidity", "yieldoor")]


@pytest.mark.parametrize(
    "language,benchmark,component",
    LANGUAGE_BENCHMARK_COMPONENT_MATRIX,
)
def test_prepass_matches_frozen(language: str, benchmark: str, component: str):
    session_out = REPO_ROOT / "benchmarks" / benchmark / "bench_session" / "results" / f"{component}_prepass.yaml"
    golden = FIXTURES / language / benchmark / "goldens" / "prepass" / f"{component}_prepass.yaml"
    assert session_out.exists(), f"Source prepass missing: {session_out}"
    actual = yaml.safe_load(session_out.read_text())
    assert_matches_golden(actual, golden, mode="yaml")


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_prepass_schema_stable(language: str, benchmark: str):
    """Every prepass YAML in the current session has the required top-level keys."""
    required = {"generated_at", "prepass_signals", "total"}
    results_dir = REPO_ROOT / "benchmarks" / benchmark / "bench_session" / "results"
    yamls = sorted(results_dir.glob("*_prepass.yaml"))
    assert yamls, f"No prepass YAMLs found in {results_dir}"
    for yml in yamls:
        data = yaml.safe_load(yml.read_text())
        missing = required - set(data.keys())
        assert not missing, f"{yml.name} missing keys: {missing}"
