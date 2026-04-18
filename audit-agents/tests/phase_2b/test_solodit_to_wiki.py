"""Phase 2B — solodit_to_wiki.py tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "audit-agents" / "solodit_to_wiki.py"


def test_help_mentions_all_flags():
    r = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert "--cards-dir" in r.stdout
    assert "--output-dir" in r.stdout
    assert "--dry-run" in r.stdout


def test_generates_expected_categories(tmp_cards_dir, tmp_vault):
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--cards-dir", str(tmp_cards_dir),
         "--output-dir", str(tmp_vault / "solodit")],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    out_dir = tmp_vault / "solodit"
    generated = sorted(p.name for p in out_dir.glob("*.md"))
    assert generated == ["access-control.md", "lending.md"], (
        f"expected 2 category pages, got {generated}"
    )
    page = (out_dir / "access-control.md").read_text()
    # All four source suffixes must produce a section header in the page.
    assert "## Existing patterns — incidents" in page
    assert "## New patterns" in page
    assert "## Round 2 — incidents" in page
    assert "## Round 2 — new patterns" in page
    # Bullet content from the fixture must land in the page.
    assert "unrestricted setAdmin" in page


def test_frontmatter_has_nonempty_summary(tmp_cards_dir, tmp_vault):
    subprocess.run(
        [sys.executable, str(SCRIPT),
         "--cards-dir", str(tmp_cards_dir),
         "--output-dir", str(tmp_vault / "solodit")],
        check=True, cwd=REPO_ROOT,
    )
    page = (tmp_vault / "solodit" / "lending.md").read_text()
    assert page.startswith("---\n"), "page must start with YAML frontmatter"
    head, _, _ = page[4:].partition("---\n")
    summary_lines = [line for line in head.splitlines() if line.startswith("summary:")]
    assert len(summary_lines) == 1, summary_lines
    value = summary_lines[0].split("summary:", 1)[1].strip()
    assert value, "summary value must be non-empty for query_wiki_context"
    # Heuristic: the summary should reference the category or the word 'Solodit'.
    assert "lending" in value.lower() or "solodit" in value.lower()


def test_idempotent(tmp_cards_dir, tmp_vault):
    out_dir = tmp_vault / "solodit"
    for _ in range(2):
        subprocess.run(
            [sys.executable, str(SCRIPT),
             "--cards-dir", str(tmp_cards_dir),
             "--output-dir", str(out_dir)],
            check=True, cwd=REPO_ROOT,
        )
    # Two identical runs → byte-identical contents.
    first = (out_dir / "access-control.md").read_bytes()
    subprocess.run(
        [sys.executable, str(SCRIPT),
         "--cards-dir", str(tmp_cards_dir),
         "--output-dir", str(out_dir)],
        check=True, cwd=REPO_ROOT,
    )
    second = (out_dir / "access-control.md").read_bytes()
    assert first == second, "two runs with the same inputs must produce identical output"


def test_dry_run_writes_nothing(tmp_cards_dir, tmp_vault):
    out_dir = tmp_vault / "solodit"
    before = sorted(p.name for p in out_dir.iterdir())
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--cards-dir", str(tmp_cards_dir),
         "--output-dir", str(out_dir),
         "--dry-run"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    after = sorted(p.name for p in out_dir.iterdir())
    assert before == after, "dry-run must not create or modify files"
    assert "would write" in r.stdout
