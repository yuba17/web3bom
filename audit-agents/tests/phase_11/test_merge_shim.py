"""Phase 11 contract tests: merge_invariants.py shim + merge/ package."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

MERGE_SUBMODULES = [
    "merge",
    "merge.constants",
    "merge.loading",
    "merge.solidity",
    "merge.hypothesis",
    "merge.files",
    "merge.modes",
    "merge.cli",
]


def test_shim_loc_budget():
    """merge_invariants.py must remain a thin shim (<30 LOC)."""
    shim_path = Path(__file__).resolve().parent.parent.parent / "merge_invariants.py"
    loc = sum(1 for _ in shim_path.open())
    assert loc < 30, f"Shim grew to {loc} LOC — should stay below 30"


def test_merge_package_modules_importable():
    """All merge/ submodules must be importable."""
    for name in MERGE_SUBMODULES:
        importlib.import_module(name)


def test_cli_main_callable():
    """merge.cli.main must be resolvable and callable."""
    from merge.cli import main
    assert callable(main)
