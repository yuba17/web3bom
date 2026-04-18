"""F003 — --domain override CLI flag."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def test_help_mentions_domain_flag():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0
    assert "--domain" in r.stdout


def test_plan_generator_respects_domain_arg(tmp_path, monkeypatch):
    """If plan_generator is called with domain='lending', the brief shows the lending briefing."""
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    import plan_generator

    session = tmp_path / "session"
    session.mkdir()
    (session / "context").mkdir()
    benchmark = "yieldoor"
    repo = REPO_ROOT / "benchmarks" / benchmark / "repo"
    if not repo.exists():
        import pytest
        pytest.skip(f"benchmark repo missing: {repo}")

    # Monkey-patch _detect_primary_domain to force auto-detect to return ""
    # so that the override from the call path is exercised.
    monkeypatch.setattr(plan_generator, "_detect_primary_domain", lambda src: "")

    # With no override, domain falls back to protocol name (not a real briefing).
    plan_generator.phase_hunter_prompt(
        component="Vault", protocol=benchmark,
        repo=str(repo), session_dir=str(session),
        lang="solidity",
    )
    # With override passed via new kwarg, the briefing should appear.
    plan_generator.phase_hunter_prompt(
        component="Vault", protocol=benchmark,
        repo=str(repo), session_dir=str(session),
        lang="solidity",
        domain_override="lending",
    )
    brief = (session / "hunter_brief_Vault.md").read_text()
    assert "lending" in brief.lower()
