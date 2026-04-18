from __future__ import annotations

import json
import sys
from pathlib import Path


def test_complete_routes_through_closer(tmp_path: Path, monkeypatch, capsys):
    """run_benchmark.py main() with --complete invokes component_closer.close_component."""
    state_file = tmp_path / "hunt.json"
    state_file.write_text(json.dumps({
        "protocol": "demo",
        "components_remaining": ["Vault", "Strategy"],
        "components_done": [],
        "current_component": "Vault",
        "component_map": [
            {"name": "Vault", "files": ["src/Vault.sol"], "loc": 100, "status": "pending", "priority": 1, "depends_on": []},
            {"name": "Strategy", "files": ["src/Strategy.sol"], "loc": 80, "status": "pending", "priority": 2, "depends_on": []},
        ],
    }))

    import importlib
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    run_benchmark = importlib.import_module("run_benchmark")
    component_closer = importlib.import_module("component_closer")

    captured: list[dict] = []

    def _fake_close(**kwargs):
        captured.append(kwargs)
        return {
            "component": kwargs["component"],
            "gated": True,
            "forced": False,
            "state_updated": True,
            "feedback_rc": 0,
            "cross_triggered": False,
            "next_component": "Strategy",
            "errors": [],
        }

    monkeypatch.setattr(component_closer, "close_component", _fake_close)
    monkeypatch.setattr(run_benchmark, "close_component", _fake_close, raising=False)
    monkeypatch.setattr(sys, "argv", [
        "run_benchmark.py",
        "--repo", "/tmp/x",
        "--complete", "Vault",
        "--state-file", str(state_file),
    ])

    rc = run_benchmark.main()
    assert rc == 0
    assert captured and captured[0]["component"] == "Vault"
    assert captured[0]["force"] is False
