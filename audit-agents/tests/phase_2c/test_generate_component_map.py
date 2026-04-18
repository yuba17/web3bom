from __future__ import annotations

from pathlib import Path

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
from component_discovery import generate_component_map  # noqa: E402


def test_generate_component_map_finds_core_contracts(tmp_repo: Path) -> None:
    cmap = generate_component_map(repo_path=str(tmp_repo))
    names = {c["name"] for c in cmap}
    assert "Vault" in names
    assert "Strategy" in names
    assert "Oracle" in names


def test_generate_component_map_excludes_interfaces_and_tests(tmp_repo: Path) -> None:
    cmap = generate_component_map(repo_path=str(tmp_repo))
    names = {c["name"] for c in cmap}
    assert "IStrategy" not in names
    assert "IVault" not in names
    assert "MockERC20" not in names
    assert "TestVault" not in names
    assert "Ownable" not in names


def test_generate_component_map_detects_imports_as_deps(tmp_repo: Path) -> None:
    cmap = generate_component_map(repo_path=str(tmp_repo))
    vault = next(c for c in cmap if c["name"] == "Vault")
    assert isinstance(vault["depends_on"], list)


def test_generate_component_map_orders_by_loc_descending(tmp_repo: Path) -> None:
    cmap = generate_component_map(repo_path=str(tmp_repo))
    locs = [c["loc"] for c in cmap]
    assert locs == sorted(locs, reverse=True)
    for i, c in enumerate(cmap):
        assert c["priority"] == i + 1


def test_generate_component_map_assigns_status(tmp_repo: Path) -> None:
    cmap = generate_component_map(
        repo_path=str(tmp_repo),
        components_done=["Vault"],
        components_remaining=["Strategy"],
    )
    by_name = {c["name"]: c for c in cmap}
    assert by_name["Vault"]["status"] == "done"
    assert by_name["Strategy"]["status"] == "pending"
    assert by_name["Oracle"]["status"] == "unmapped"
