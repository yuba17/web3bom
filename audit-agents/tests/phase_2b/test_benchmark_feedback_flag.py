"""Phase 2B — run_benchmark.py --apply-feedback flag tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def test_help_mentions_apply_feedback():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0, r.stderr
    assert "--apply-feedback" in r.stdout


def test_hook_noop_when_flag_absent(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO_ROOT / "audit-agents"))
    import run_benchmark
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(run_benchmark.subprocess, "run", fake_run)
    run_benchmark._maybe_run_apply_feedback(apply_feedback=False)
    assert calls == []


def test_hook_invokes_subprocess_when_flag_set(monkeypatch):
    monkeypatch.syspath_prepend(str(REPO_ROOT / "audit-agents"))
    import run_benchmark
    calls: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        class R:
            returncode = 0
        return R()

    monkeypatch.setattr(run_benchmark.subprocess, "run", fake_run)
    run_benchmark._maybe_run_apply_feedback(apply_feedback=True)
    assert len(calls) == 1
    assert any("apply_feedback.py" in part for part in calls[0])


def test_hook_logs_warning_on_nonzero_exit(monkeypatch, caplog):
    monkeypatch.syspath_prepend(str(REPO_ROOT / "audit-agents"))
    import run_benchmark
    import logging

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 2
        return R()

    monkeypatch.setattr(run_benchmark.subprocess, "run", fake_run)
    with caplog.at_level(logging.WARNING, logger=run_benchmark.logger.name):
        run_benchmark._maybe_run_apply_feedback(apply_feedback=True)
    assert any("apply_feedback" in rec.message for rec in caplog.records)
