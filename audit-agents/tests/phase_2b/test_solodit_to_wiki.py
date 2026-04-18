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
