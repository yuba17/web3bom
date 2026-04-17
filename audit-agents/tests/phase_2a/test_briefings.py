"""F022 — Domain briefings loader (tiered: primary full, secondary grep-only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from context_enrichment import (
    load_briefing_single,
    load_briefings_tiered,
    load_grep_targets_only,
)


@pytest.fixture
def tmp_briefings(tmp_path, monkeypatch):
    """Install a fake WEB3_DIR with knowledge/ briefings."""
    web3 = tmp_path / "Web3"
    knowledge = web3 / "knowledge"
    knowledge.mkdir(parents=True)
    (knowledge / "lending.md").write_text(
        "# Lending\n"
        "### 1. First bug\n"
        "### 2. Second bug\n"
        "## 3. Invariant Checklist\n"
        "- must do X\n"
        "- must do Y\n"
        "## 4. Grep Targets\n"
        "- grep foo\n"
        "- grep bar\n"
        "## 2.3 Real-World Incidents\n"
        "- Protocol A 2023\n"
    )
    (knowledge / "vault-erc4626.md").write_text(
        "# Vault\n## 4. Grep Targets\n- grep vault\n- grep shares\n"
    )
    import context_enrichment
    monkeypatch.setattr(context_enrichment, "WEB3_DIR", web3)
    return web3


def test_single_returns_empty_when_domain_unknown(tmp_briefings):
    assert load_briefing_single("not-a-domain") == ""


def test_single_extracts_structured_sections(tmp_briefings):
    out = load_briefing_single("lending")
    assert "PATRONES CONOCIDOS" in out
    assert "First bug" in out
    assert "CHECKLIST DE INVARIANTES" in out
    assert "GREP TARGETS" in out
    assert "INCIDENTES REALES" in out


def test_grep_only_compact(tmp_briefings):
    out = load_grep_targets_only("vault")
    assert "grep vault" in out
    assert "grep shares" in out
    # Must NOT contain checklist markers
    assert "CHECKLIST" not in out


def test_tiered_primary_full(tmp_briefings):
    out = load_briefings_tiered(["lending"])
    assert "Briefing principal: lending" in out
    assert "CHECKLIST DE INVARIANTES" in out


def test_tiered_primary_plus_secondary_grep(tmp_briefings):
    out = load_briefings_tiered(["lending", "vault"])
    assert "Briefing principal: lending" in out
    assert "Grep targets adicionales (vault)" in out
    assert "grep vault" in out


def test_tiered_drops_tertiary(tmp_briefings):
    out = load_briefings_tiered(["lending", "vault", "staking"])
    assert "staking" not in out.lower() or "Grep targets adicionales (staking)" not in out


def test_tiered_empty_list_returns_empty(tmp_briefings):
    assert load_briefings_tiered([]) == ""
