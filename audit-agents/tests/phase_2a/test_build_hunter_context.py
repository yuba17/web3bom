"""Orchestrator: build_hunter_context composes 5 sub-functions."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from context_enrichment import build_hunter_context


def test_all_empty_returns_empty_string(tmp_path):
    # Contract doesn't exist → file-dependent sub-functions return "";
    # use a domain/component guaranteed to have no wiki matches.
    with patch("context_enrichment.query_wiki_context", return_value=""), \
         patch("context_enrichment.load_briefings_tiered", return_value=""):
        assert build_hunter_context(tmp_path / "nope.sol", "xyznonexistent999", "NopeSol") == ""


def test_combines_sections_with_separator(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value="W"), \
         patch("context_enrichment.load_briefings_tiered", return_value="B"), \
         patch("context_enrichment.generate_asset_flow_map", return_value="A"), \
         patch("context_enrichment.run_symmetric_analysis", return_value="S"), \
         patch("context_enrichment.run_deep_flatten", return_value="D"):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    # 5 sections joined with "\n\n---\n\n"
    assert out.count("\n\n---\n\n") == 4
    assert "W" in out and "B" in out and "A" in out and "S" in out and "D" in out


def test_skips_empty_sections(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value=""), \
         patch("context_enrichment.load_briefings_tiered", return_value="B"), \
         patch("context_enrichment.generate_asset_flow_map", return_value=""), \
         patch("context_enrichment.run_symmetric_analysis", return_value="S"), \
         patch("context_enrichment.run_deep_flatten", return_value=""):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    # Only "B" and "S" survive — one separator
    assert out == "B\n\n---\n\nS"


def test_section_order_is_wiki_brief_flow_sym_deep(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value="WIKI"), \
         patch("context_enrichment.load_briefings_tiered", return_value="BRIEF"), \
         patch("context_enrichment.generate_asset_flow_map", return_value="FLOW"), \
         patch("context_enrichment.run_symmetric_analysis", return_value="SYM"), \
         patch("context_enrichment.run_deep_flatten", return_value="DEEP"):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    assert out.index("WIKI") < out.index("BRIEF") < out.index("FLOW") < out.index("SYM") < out.index("DEEP")
