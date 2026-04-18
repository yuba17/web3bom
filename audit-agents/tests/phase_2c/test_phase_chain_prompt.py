from __future__ import annotations

from pathlib import Path

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
import plan_generator  # noqa: E402


def test_chain_prompt_parses_three_components(tmp_repo: Path, tmp_path: Path) -> None:
    steps = plan_generator.phase_transitive_chain_prompt(
        "Vault,Strategy,Oracle",
        protocol="test",
        repo=str(tmp_repo),
        session_dir=str(tmp_path),
    )
    assert len(steps) == 1
    step = steps[0]
    assert step["step_id"] == "chain:Vault_Strategy_Oracle:analyze"
    assert "Vault" in step["prompt"]
    assert "Strategy" in step["prompt"]
    assert "Oracle" in step["prompt"]


def test_chain_prompt_rejects_wrong_arity(tmp_repo: Path, tmp_path: Path) -> None:
    steps = plan_generator.phase_transitive_chain_prompt(
        "A,B",
        protocol="test",
        repo=str(tmp_repo),
        session_dir=str(tmp_path),
    )
    assert len(steps) == 1 and "error" in steps[0]
