"""Snapshot helper for phase_modern tests.

Compares actual output against a golden file. Respects UPDATE_SNAPSHOTS=1
to regenerate goldens. Parser-aware for json/yaml so diffs are structural
rather than byte-level.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import pytest
import yaml

Mode = Literal["json", "yaml", "text"]


def _load(text: str, mode: Mode) -> Any:
    if mode == "json":
        return json.loads(text)
    if mode == "yaml":
        return yaml.safe_load(text)
    return text


def _dump(value: Any, mode: Mode) -> str:
    if mode == "json":
        return json.dumps(value, indent=2, sort_keys=True) + "\n"
    if mode == "yaml":
        return yaml.safe_dump(value, sort_keys=True, default_flow_style=False)
    return str(value)


def _drop_keys(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        return {k: _drop_keys(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [_drop_keys(item, keys) for item in obj]
    return obj


def _serialize_actual(actual: Any, mode: Mode) -> str:
    if isinstance(actual, (dict, list)):
        return _dump(actual, mode)
    if isinstance(actual, bytes):
        return actual.decode("utf-8")
    return str(actual)


def assert_matches_golden(
    actual: Any,
    golden_path: Path,
    *,
    mode: Mode = "json",
    ignore_keys: list[str] | None = None,
) -> None:
    """Assert that `actual` matches the content of `golden_path`.

    - If UPDATE_SNAPSHOTS=1: write actual to golden_path and skip.
    - If golden missing: fail with hint to regenerate.
    - Otherwise: parse both per mode, drop ignore_keys recursively, compare.
    """
    ignore = set(ignore_keys or [])
    update = os.environ.get("UPDATE_SNAPSHOTS") == "1"

    if update:
        golden_path.parent.mkdir(parents=True, exist_ok=True)
        # Strip ignore_keys before writing so the committed golden is clean and
        # human-reviewable — not polluted with /tmp paths or other volatile data.
        if isinstance(actual, (dict, list)):
            cleaned = _drop_keys(actual, ignore)
            golden_path.write_text(_dump(cleaned, mode))
        else:
            golden_path.write_text(_serialize_actual(actual, mode))
        pytest.skip(f"golden updated: {golden_path}")

    if not golden_path.exists():
        pytest.fail(
            f"Golden not found: {golden_path}. "
            "Run with UPDATE_SNAPSHOTS=1 to create."
        )

    golden_text = golden_path.read_text()
    golden_value = _load(golden_text, mode)

    if isinstance(actual, (dict, list)):
        actual_value = actual
    else:
        actual_value = _load(_serialize_actual(actual, mode), mode)

    actual_clean = _drop_keys(actual_value, ignore)
    golden_clean = _drop_keys(golden_value, ignore)

    assert actual_clean == golden_clean, (
        f"Snapshot mismatch at {golden_path}\n"
        f"--- golden ---\n{_dump(golden_clean, mode)}\n"
        f"--- actual ---\n{_dump(actual_clean, mode)}\n"
    )
