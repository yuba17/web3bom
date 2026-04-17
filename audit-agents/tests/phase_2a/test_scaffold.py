"""Smoke tests confirming context_enrichment module is importable."""
from __future__ import annotations


def test_module_imports():
    import context_enrichment  # noqa: F401


def test_module_constants_present():
    import context_enrichment
    assert isinstance(context_enrichment.DEEP_FLATTEN_MIN_LINES, int)
    assert context_enrichment.DEEP_FLATTEN_MIN_LINES >= 100
