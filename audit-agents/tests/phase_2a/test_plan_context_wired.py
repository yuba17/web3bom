"""Contract: plan_generator.phase_hunter_prompt calls build_hunter_context."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_phase_hunter_prompt_invokes_context_builder(language, benchmark, tmp_path):
    import sys
    REPO_ROOT = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    import plan_generator

    session = tmp_path / "session"
    session.mkdir()
    (session / "context").mkdir()

    repo = REPO_ROOT / "benchmarks" / benchmark / "repo"
    if not repo.exists():
        pytest.skip(f"benchmark repo missing: {repo}")

    with patch("plan_generator.build_hunter_context", return_value="STUBBED CTX") as m:
        steps = plan_generator.phase_hunter_prompt(
            component="Vault",
            protocol=benchmark,
            repo=str(repo),
            session_dir=str(session),
            lang=language,
        )
    assert m.called, "build_hunter_context not invoked"
    brief_path = session / "hunter_brief_Vault.md"
    assert brief_path.exists()
    assert "STUBBED CTX" in brief_path.read_text()
