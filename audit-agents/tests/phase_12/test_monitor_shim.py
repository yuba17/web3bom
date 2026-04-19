"""Phase 12 contract tests: target_monitor.py shim + monitor/ package."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

MONITOR_SUBMODULES = [
    "monitor",
    "monitor.config",
    "monitor.state",
    "monitor.notifier",
    "monitor.github",
    "monitor.proxy",
    "monitor.deployment",
    "monitor.orchestrator",
    "monitor.cli",
]


def test_shim_loc_budget():
    """target_monitor.py must remain a thin shim (<30 LOC)."""
    shim_path = Path(__file__).resolve().parent.parent.parent / "target_monitor.py"
    loc = sum(1 for _ in shim_path.open())
    assert loc < 30, f"Shim grew to {loc} LOC"


def test_monitor_package_modules_importable():
    """All monitor/ submodules must be importable."""
    for name in MONITOR_SUBMODULES:
        importlib.import_module(name)


def test_cli_main_callable():
    """monitor.cli.main must be callable."""
    from monitor.cli import main
    assert callable(main)
