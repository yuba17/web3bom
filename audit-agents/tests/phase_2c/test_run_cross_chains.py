from __future__ import annotations

from pathlib import Path

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
import run_benchmark  # noqa: E402


def test_run_cross_component_emits_chain_prompt(tmp_path: Path, monkeypatch) -> None:
    """Given 3 completed components with A↔B↔C adjacency (no A↔C),
    run_cross_component should invoke the chain prompt via _llm."""
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    # Use distinctive names to avoid substring false positives in _find_cross_calls.
    (src / "Alpha.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Alpha {\n"
        + "\n".join(f'    uint256 var{i};' for i in range(20))
        + "\n}\n"
    )
    # Beta imports both Alpha and Gamma so pair-finder links Alpha-Beta and Beta-Gamma,
    # but Alpha-Gamma not direct.
    (src / "Beta.sol").write_text(
        'pragma solidity ^0.8.0;\nimport "./Alpha.sol";\nimport "./Gamma.sol";\n'
        "contract Beta {\n"
        "    function callAlpha(Alpha a) external {}\n"
        "    function callGamma(Gamma g) external {}\n"
        + "\n".join(f'    uint256 var{i};' for i in range(20))
        + "\n}\n"
    )
    (src / "Gamma.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Gamma {\n"
        + "\n".join(f'    uint256 var{i};' for i in range(20))
        + "\n}\n"
    )

    monkeypatch.setattr(run_benchmark, "HUNT_SESSION_DIR", tmp_path / "session")
    monkeypatch.setattr(run_benchmark, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(run_benchmark, "component_log_dir",
                        lambda name: tmp_path / "logs" / name)
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "cross_component").mkdir(parents=True, exist_ok=True)

    calls: list[str] = []
    def _fake_llm(prompt: str, **kw):
        calls.append(prompt[:500])
        return "ok"

    monkeypatch.setattr(run_benchmark, "_llm", _fake_llm)

    run_benchmark.run_cross_component(
        components_done=["Alpha", "Beta", "Gamma"],
        protocol="testproto",
        repo=str(repo),
    )

    chain_prompts = [c for c in calls if "Transitive Chain" in c or "transitive chain" in c.lower()]
    assert len(chain_prompts) >= 1, f"No chain prompt invoked. All calls: {calls!r}"
