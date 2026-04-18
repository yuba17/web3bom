"""Phase 2B — apply_feedback.py --knowledge-dir + --vault-dir override tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "audit-agents" / "apply_feedback.py"


def test_help_mentions_both_overrides():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert "--knowledge-dir" in r.stdout
    assert "--vault-dir" in r.stdout


def test_knowledge_dir_override_mutates_module_global(tmp_path, monkeypatch):
    """Apply overrides directly and verify module-level globals change."""
    sys_path_mutation = str(REPO_ROOT / "audit-agents")
    monkeypatch.syspath_prepend(sys_path_mutation)
    import apply_feedback
    original_k = apply_feedback.KNOWLEDGE_DIR
    original_v = apply_feedback.VAULT_RAW
    try:
        knowledge = tmp_path / "kn"
        vault = tmp_path / "va"
        knowledge.mkdir()
        vault.mkdir()
        apply_feedback._apply_path_overrides(
            knowledge_dir=str(knowledge),
            vault_dir=str(vault),
        )
        assert apply_feedback.KNOWLEDGE_DIR == knowledge.resolve()
        assert apply_feedback.VAULT_RAW == (vault / "_raw").resolve()
    finally:
        apply_feedback.KNOWLEDGE_DIR = original_k
        apply_feedback.VAULT_RAW = original_v


def test_overrides_noop_when_flags_absent(tmp_path, monkeypatch):
    """Passing None leaves globals untouched."""
    monkeypatch.syspath_prepend(str(REPO_ROOT / "audit-agents"))
    import apply_feedback
    before_k = apply_feedback.KNOWLEDGE_DIR
    before_v = apply_feedback.VAULT_RAW
    apply_feedback._apply_path_overrides(knowledge_dir=None, vault_dir=None)
    assert apply_feedback.KNOWLEDGE_DIR == before_k
    assert apply_feedback.VAULT_RAW == before_v
