from __future__ import annotations

from pathlib import Path


def test_tmp_repo_has_src_contracts(tmp_repo: Path) -> None:
    assert (tmp_repo / "src" / "Vault.sol").exists()
    assert (tmp_repo / "src" / "Strategy.sol").exists()
    assert (tmp_repo / "src" / "Oracle.sol").exists()


def test_tmp_repo_excludes_tests_and_mocks(tmp_repo: Path) -> None:
    assert (tmp_repo / "test" / "TestVault.sol").exists()
    assert (tmp_repo / "lib" / "openzeppelin" / "Ownable.sol").exists()


def test_tmp_component_map_has_expected_adjacency(tmp_component_map: list[dict]) -> None:
    names = {c["name"] for c in tmp_component_map}
    assert names == {"Vault", "Strategy", "Oracle", "Router"}
    vault = next(c for c in tmp_component_map if c["name"] == "Vault")
    assert "Strategy" in vault["depends_on"]
