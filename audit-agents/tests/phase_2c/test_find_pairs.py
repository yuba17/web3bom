from __future__ import annotations

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
from component_discovery import find_cross_component_pairs  # noqa: E402


def test_find_pairs_detects_direct_imports(tmp_component_map: list[dict]) -> None:
    pairs = find_cross_component_pairs(
        components_done=["Vault", "Strategy", "Oracle", "Router"],
        component_map=tmp_component_map,
    )
    keys = {tuple(sorted([a, b])) for a, b, _ in pairs}
    assert ("Strategy", "Vault") in keys
    assert ("Oracle", "Strategy") in keys


def test_find_pairs_excludes_isolated_components(tmp_component_map: list[dict]) -> None:
    pairs = find_cross_component_pairs(
        components_done=["Vault", "Strategy", "Oracle", "Router"],
        component_map=tmp_component_map,
    )
    all_names = {a for a, _, _ in pairs} | {b for _, b, _ in pairs}
    assert "Router" not in all_names


def test_find_pairs_needs_at_least_two_done() -> None:
    pairs = find_cross_component_pairs(
        components_done=["Vault"],
        component_map=[{"name": "Vault", "depends_on": []}],
    )
    assert pairs == []
