from __future__ import annotations

from pathlib import Path


def test_apply_feedback_false_skips_subprocess(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
        apply_feedback=False,
    )

    assert report["feedback_rc"] is None
    # Only pipeline_gate.py call, not apply_feedback.py
    scripts_called = [c["cmd"][1] for c in patched_subprocess.calls if len(c["cmd"]) > 1]
    assert not any("apply_feedback" in s for s in scripts_called)


def test_apply_feedback_true_records_rc(tmp_state_file: Path, patched_subprocess):
    from component_closer import close_component

    patched_subprocess.rc = 0
    report = close_component(
        component="Vault",
        state_file=tmp_state_file,
        apply_feedback=True,
    )

    scripts_called = [c["cmd"][1] for c in patched_subprocess.calls if len(c["cmd"]) > 1]
    assert any("apply_feedback" in s for s in scripts_called)
    assert report["feedback_rc"] == 0
