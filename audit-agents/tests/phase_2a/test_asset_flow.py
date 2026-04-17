"""F024 — Asset flow map regex scanner."""
from __future__ import annotations

from pathlib import Path

from context_enrichment import generate_asset_flow_map


def test_empty_for_missing_file(tmp_path):
    assert generate_asset_flow_map(tmp_path / "nope.sol") == ""


def test_empty_for_contract_without_asset_ops(tmp_path):
    f = tmp_path / "nothing.sol"
    f.write_text("contract X { function f() external {} }")
    assert generate_asset_flow_map(f) == ""


def test_detects_transferFrom_as_money_in(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Money IN" in out
    assert "transferFrom" in out


def test_detects_transfer_as_money_out(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Money OUT" in out
    assert "transfer" in out


def test_does_not_double_count_transferFrom_as_money_out(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    # money_out section should not contain transferFrom entries
    lines = out.splitlines()
    in_money_out = False
    for line in lines:
        if line.startswith("### Money OUT"):
            in_money_out = True
            continue
        if in_money_out and line.startswith("### "):
            break
        if in_money_out:
            assert "transferFrom" not in line


def test_detects_approvals_and_balance_reads(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Approvals" in out
    assert "approve" in out
    assert "Balance Reads" in out
    assert "balanceOf" in out


def test_includes_function_context(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "deposit()" in out or "deposit" in out
