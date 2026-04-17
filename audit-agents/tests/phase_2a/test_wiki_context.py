"""F019 — Obsidian vault wiki-context query."""
from __future__ import annotations

from pathlib import Path

from context_enrichment import query_wiki_context


def test_returns_empty_when_vault_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # No vault created. Expect empty string, not exception.
    assert query_wiki_context("lending", "Vault") == ""


def test_returns_empty_when_no_match(tmp_vault):
    (tmp_vault / "unrelated.md").write_text("# Nothing relevant\nBody about staking.")
    assert query_wiki_context("lending", "Vault") == ""


def test_finds_match_by_domain(tmp_vault):
    (tmp_vault / "lending-notes.md").write_text(
        "---\nsummary: Key lending patterns\n---\n# Lending\nContent."
    )
    out = query_wiki_context("lending", "Vault")
    assert "lending-notes" in out
    assert "Key lending patterns" in out
    assert out.startswith("\n---\n## Prior Knowledge (Obsidian Vault)\n")


def test_finds_match_by_component(tmp_vault):
    (tmp_vault / "vault-audit.md").write_text("# Vault audit\nVault specifics here.")
    out = query_wiki_context("staking", "Vault")
    assert "vault-audit" in out


def test_skips_internal_dirs(tmp_vault):
    (tmp_vault / "_raw").mkdir()
    (tmp_vault / "_raw" / "lending-draft.md").write_text("# Lending draft")
    (tmp_vault / ".obsidian").mkdir()
    (tmp_vault / ".obsidian" / "workspace.md").write_text("# Lending workspace")
    (tmp_vault / "projects").mkdir()
    (tmp_vault / "projects" / "lending.md").write_text("# Lending project")
    assert query_wiki_context("lending", "Vault") == ""


def test_output_capped_at_8_results(tmp_vault):
    for i in range(20):
        (tmp_vault / f"lending-{i}.md").write_text(f"# Note {i} about lending")
    out = query_wiki_context("lending", "Vault")
    # Count markdown list entries
    assert out.count("\n- **") == 8


def test_prefers_frontmatter_summary_over_body(tmp_vault):
    (tmp_vault / "hit.md").write_text(
        "---\nsummary: SHORT SUMMARY\n---\n# Lending\n" + ("LONG BODY " * 200)
    )
    out = query_wiki_context("lending", "Vault")
    assert "SHORT SUMMARY" in out
    assert "LONG BODY" not in out
