"""F009 — granular --force-regen-map + --force-gate flags."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"
PIPELINE_GATE = REPO_ROOT / "audit-agents" / "pipeline_gate.py"


def test_help_mentions_both_flags():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert "--force-regen-map" in r.stdout
    assert "--force-gate" in r.stdout


def test_force_regen_map_removes_cached_map(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    cache = session / "component_map_yieldoor.json"
    cache.write_text(json.dumps({"components": ["Vault"]}))
    assert cache.exists()

    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _apply_force_regen_map
    _apply_force_regen_map(session_dir=session, protocol="yieldoor")
    assert not cache.exists(), "--force-regen-map must delete the cached map"


def test_force_regen_map_noop_when_file_missing(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _apply_force_regen_map
    # Must not raise even when nothing to remove
    _apply_force_regen_map(session_dir=session, protocol="yieldoor")


def test_pipeline_gate_accepts_force_flag():
    r = subprocess.run(
        [sys.executable, str(PIPELINE_GATE), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert "--force" in r.stdout


def test_pipeline_gate_force_resets_component_gate(tmp_path):
    session = tmp_path / "session"
    for sub in ("results", "hypotheses", "gate_status", "context", "logs"):
        (session / sub).mkdir(parents=True)
    # Mark a gate, then force-reset it
    r1 = subprocess.run(
        [sys.executable, str(PIPELINE_GATE),
         "-c", "Vault", "--mark", "scope", "--session-dir", str(session)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r1.returncode == 0, r1.stderr
    r2 = subprocess.run(
        [sys.executable, str(PIPELINE_GATE),
         "-c", "Vault", "--force", "scope", "--session-dir", str(session)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r2.returncode == 0, r2.stderr
