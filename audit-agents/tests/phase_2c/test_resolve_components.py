from __future__ import annotations

import argparse
from pathlib import Path

from audit_agents_path import ensure_audit_agents_on_path

ensure_audit_agents_on_path()
import run_benchmark  # noqa: E402


def _mk_ns(**kw) -> argparse.Namespace:
    defaults = dict(components=None, auto_components=False, repo="")
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def test_resolve_components_passthrough_explicit() -> None:
    ns = _mk_ns(components="A,B, C ")
    result = run_benchmark._resolve_components(ns)
    assert result == ["A", "B", "C"]


def test_resolve_components_auto_from_repo(tmp_repo: Path) -> None:
    ns = _mk_ns(auto_components=True, repo=str(tmp_repo))
    result = run_benchmark._resolve_components(ns)
    assert set(result) >= {"Vault", "Strategy", "Oracle"}
