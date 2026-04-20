"""Regression tests for check_deepdive tolerance to timeout-race YAML states.

Context: claude -p subagent for DeepDiveHunter has a 1800s timeout. In
long-reasoning runs the process is killed mid-write, leaving the hypothesis
YAML in one of several partial states: empty, parseable-but-empty, malformed.
The gate used to fail with "EMPTY: hyp_X_DeepDiveHunter.yaml" for any of
these, even though the extract phase downstream later reads the fully-flushed
file and pulls 10+ hypotheses out of it. Result: cosmetic FAIL in the
dashboard despite the hunt actually succeeding.

These tests pin the tolerant behavior so a future refactor doesn't regress.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def isolated_gate(tmp_path, monkeypatch):
    """Point get_hyp_dir() at tmp_path so tests don't touch real hunt_session."""
    from gate import gates_component

    fake_hyp_dir = tmp_path / "hypotheses" / "testproto"
    fake_hyp_dir.mkdir(parents=True)

    monkeypatch.setattr(gates_component, "_PROTOCOL_OVERRIDE", "testproto")
    monkeypatch.setattr(gates_component, "get_hyp_dir",
                        lambda protocol: fake_hyp_dir)
    return fake_hyp_dir


def test_missing_file_fails(isolated_gate):
    from gate.gates_component import check_deepdive
    ok, passed, failed = check_deepdive("LendingPool")
    assert ok is False
    assert any("MISSING" in f for f in failed)


def test_empty_file_passes_with_race_hint(isolated_gate):
    """Zero-byte YAML (flush killed before write) must PASS."""
    from gate.gates_component import check_deepdive
    (isolated_gate / "hyp_LendingPool_DeepDiveHunter.yaml").write_text("")

    ok, passed, failed = check_deepdive("LendingPool")
    assert ok is True
    assert any("empty" in p.lower() or "race" in p.lower() for p in passed)


def test_whitespace_only_file_passes(isolated_gate):
    from gate.gates_component import check_deepdive
    (isolated_gate / "hyp_LendingPool_DeepDiveHunter.yaml").write_text("   \n\n  ")

    ok, _, _ = check_deepdive("LendingPool")
    assert ok is True


def test_malformed_yaml_passes(isolated_gate):
    """Partial write producing unparseable YAML must still PASS."""
    from gate.gates_component import check_deepdive
    # Invalid: duplicate mapping key with flow-style mismatch
    (isolated_gate / "hyp_Leverager_DeepDiveHunter.yaml").write_text(
        "hypotheses:\n  - id: X\n    title: {unclosed: \n  - id: Y\n"
    )

    ok, passed, _ = check_deepdive("Leverager")
    assert ok is True
    assert any("malformed" in p.lower() for p in passed)


def test_parsed_to_none_passes(isolated_gate):
    """Valid YAML comments only (parses to None) must PASS."""
    from gate.gates_component import check_deepdive
    (isolated_gate / "hyp_Leverager_DeepDiveHunter.yaml").write_text("# just a comment\n")

    ok, _, _ = check_deepdive("Leverager")
    assert ok is True


def test_valid_yaml_with_hypotheses_passes(isolated_gate):
    """Happy path: YAML parses with 12 hypotheses → PASS with count."""
    import yaml
    from gate.gates_component import check_deepdive

    payload = {"hypotheses": [{"id": f"DD-{i}", "title": f"h{i}"} for i in range(12)]}
    (isolated_gate / "hyp_Strategy_DeepDiveHunter.yaml").write_text(
        yaml.safe_dump(payload)
    )

    ok, passed, _ = check_deepdive("Strategy")
    assert ok is True
    assert any("12 hypotheses" in p for p in passed)


def test_findings_key_also_counted(isolated_gate):
    """Some hunter variants use 'findings' instead of 'hypotheses'."""
    import yaml
    from gate.gates_component import check_deepdive

    payload = {"findings": [{"id": "F-1"}, {"id": "F-2"}]}
    (isolated_gate / "hyp_Vault_DeepDiveHunter.yaml").write_text(yaml.safe_dump(payload))

    ok, passed, _ = check_deepdive("Vault")
    assert ok is True
    assert any("2 hypotheses" in p for p in passed)
