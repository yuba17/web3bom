"""Shared fixtures for Phase 2A tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_AGENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(AUDIT_AGENTS))

REPO_ROOT = AUDIT_AGENTS.parent


@pytest.fixture
def tmp_vault(tmp_path: Path, monkeypatch) -> Path:
    """Temporary Obsidian vault rooted at <tmp>/obsidian-vault/web3-audit/.

    Override `Path.home()` via monkeypatch so `query_wiki_context` reads
    from the tmp vault instead of the user's real home directory.
    """
    vault = tmp_path / "obsidian-vault" / "web3-audit"
    vault.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return vault


@pytest.fixture
def tmp_solidity_contract(tmp_path: Path) -> Path:
    """A minimal Solidity contract file with a handful of asset-flow patterns."""
    contract = tmp_path / "TestVault.sol"
    contract.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "contract TestVault {\n"
        "    function deposit(uint256 amt) external {\n"
        "        token.transferFrom(msg.sender, address(this), amt);\n"
        "    }\n"
        "    function withdraw(uint256 amt) external {\n"
        "        token.transfer(msg.sender, amt);\n"
        "    }\n"
        "    function approveSpender(address s) external {\n"
        "        token.approve(s, type(uint256).max);\n"
        "    }\n"
        "    function balance() external view returns (uint256) {\n"
        "        return token.balanceOf(address(this));\n"
        "    }\n"
        "}\n"
    )
    return contract
