"""Shared fixtures for phase_modern snapshot tests."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

import pytest

# Make audit-agents importable for test modules
# conftest.py lives at audit-agents/tests/phase_modern/, so parents[2] = audit-agents/
AUDIT_AGENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(AUDIT_AGENTS))

REPO_ROOT = AUDIT_AGENTS.parent  # /home/kali/Documents/Web3
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def tmp_session_dir(tmp_path: Path) -> Path:
    """A scratch session dir with the standard subdirs the modern flow expects."""
    session = tmp_path / "session"
    for sub in ("context", "results", "hypotheses", "gate_status", "logs"):
        (session / sub).mkdir(parents=True, exist_ok=True)
    return session


@pytest.fixture
def benchmark_fixture() -> Callable[[str, str], Path]:
    """Resolve `fixtures/{language}/{benchmark}/repo_ref.txt` to an absolute repo path."""
    def _resolve(language: str, benchmark: str) -> Path:
        ref = FIXTURES / language / benchmark / "repo_ref.txt"
        if not ref.exists():
            pytest.skip(f"No repo_ref.txt for {language}/{benchmark}")
        rel = ref.read_text().strip()
        abs_path = (REPO_ROOT / rel).resolve()
        if not abs_path.exists():
            pytest.fail(
                f"Benchmark repo missing: {abs_path} "
                f"(referenced from {ref}). Update repo_ref.txt if the repo moved."
            )
        return abs_path
    return _resolve


@pytest.fixture
def frozen_session_fixture() -> Callable[[str], Path]:
    """Resolve a frozen benchmark session (for schema contract tests)."""
    def _resolve(version: str = "v12") -> Path:
        candidate = REPO_ROOT / "benchmarks" / "yieldoor" / f"bench_session_{version}"
        if not candidate.exists():
            pytest.fail(
                f"Frozen session missing: {candidate}. "
                f"Either regenerate or point the fixture at a different version."
            )
        return candidate
    return _resolve


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to `fixtures/` for tests that reach for goldens."""
    return FIXTURES
