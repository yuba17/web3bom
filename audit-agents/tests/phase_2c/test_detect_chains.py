from __future__ import annotations

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
from component_discovery import detect_transitive_chains  # noqa: E402


def test_detect_chains_finds_simple_ABC() -> None:
    pairs = [
        ("A", "B", ["A imports B"]),
        ("B", "C", ["B imports C"]),
    ]
    chains = detect_transitive_chains(all_pairs=pairs)
    assert chains == [("A", "B", "C")]


def test_detect_chains_excludes_if_direct_AC_edge() -> None:
    pairs = [
        ("A", "B", ["x"]),
        ("B", "C", ["x"]),
        ("A", "C", ["x"]),
    ]
    chains = detect_transitive_chains(all_pairs=pairs)
    assert chains == []


def test_detect_chains_isolated_node_no_chain() -> None:
    pairs = [("A", "B", ["x"])]
    chains = detect_transitive_chains(all_pairs=pairs)
    assert chains == []


def test_detect_chains_unique_ordering() -> None:
    pairs = [
        ("A", "B", ["x"]),
        ("B", "C", ["x"]),
        ("A", "D", ["x"]),
        ("D", "C", ["x"]),
    ]
    chains = detect_transitive_chains(all_pairs=pairs)
    assert ("A", "B", "C") in chains
    assert ("A", "D", "C") in chains
    assert ("C", "B", "A") not in chains
