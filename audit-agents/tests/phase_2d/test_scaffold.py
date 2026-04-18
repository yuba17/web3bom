from __future__ import annotations

import json
from pathlib import Path


def test_tmp_state_file_contains_sample(tmp_state_file: Path):
    data = json.loads(tmp_state_file.read_text())
    assert data["protocol"] == "demo"
    assert "Vault" in data["components_remaining"]
    assert data["current_component"] == "Vault"


def test_patched_subprocess_captures_calls(patched_subprocess):
    import subprocess
    subprocess.run(["echo", "hello"])
    assert len(patched_subprocess.calls) == 1
    assert patched_subprocess.calls[0]["cmd"] == ["echo", "hello"]
