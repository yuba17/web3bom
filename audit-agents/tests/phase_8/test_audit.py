"""Phase 8 audit tests — scaffold."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from phase_8_audit import CheckResult, DebtItem


def test_check_result_dataclass_has_required_fields():
    r = CheckResult(name="x", status="PASS", evidence={}, debt_items=[])
    assert r.name == "x"
    assert r.status == "PASS"
    assert r.evidence == {}
    assert r.debt_items == []


def test_debt_item_dataclass_has_required_fields():
    d = DebtItem(severity="HIGH", category="size", description="foo", evidence={"loc": 1500})
    assert d.severity == "HIGH"
    assert d.category == "size"
    assert d.description == "foo"
    assert d.evidence == {"loc": 1500}


def test_check_result_status_values_allowed():
    for s in ["PASS", "FAIL", "WARN", "ERROR"]:
        r = CheckResult(name="x", status=s, evidence={}, debt_items=[])
        assert r.status == s


def test_debt_item_severity_values_allowed():
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        d = DebtItem(severity=s, category="x", description="x", evidence={})
        assert d.severity == s


from unittest.mock import patch, MagicMock

from phase_8_audit import check_test_suite


def test_check_test_suite_pass():
    mock_result = MagicMock(returncode=0, stdout="138 passed in 23.52s\n", stderr="")
    with patch("phase_8_audit.subprocess.run", return_value=mock_result):
        r = check_test_suite(root=Path("/tmp"), expected_count=138)
    assert r.name == "check_test_suite"
    assert r.status == "PASS"
    assert r.evidence["passed"] == 138
    assert r.debt_items == []


def test_check_test_suite_fail_count_mismatch():
    mock_result = MagicMock(returncode=0, stdout="120 passed in 20s\n", stderr="")
    with patch("phase_8_audit.subprocess.run", return_value=mock_result):
        r = check_test_suite(root=Path("/tmp"), expected_count=138)
    assert r.status == "FAIL"
    assert r.evidence["passed"] == 120
    assert len(r.debt_items) == 1
    assert r.debt_items[0].severity == "HIGH"


def test_check_test_suite_fail_pytest_nonzero_exit():
    mock_result = MagicMock(returncode=1, stdout="5 failed, 133 passed\n", stderr="")
    with patch("phase_8_audit.subprocess.run", return_value=mock_result):
        r = check_test_suite(root=Path("/tmp"), expected_count=138)
    assert r.status == "FAIL"
    assert len(r.debt_items) == 1


from phase_8_audit import check_clis


def test_check_clis_all_pass():
    def fake_run(*args, **kwargs):
        return MagicMock(returncode=0, stdout="usage: ...\n", stderr="")
    with patch("phase_8_audit.subprocess.run", side_effect=fake_run):
        r = check_clis(root=Path("/tmp"))
    assert r.name == "check_clis"
    assert r.status == "PASS"
    assert len(r.evidence["clis"]) == 5
    assert all(c["exit_code"] == 0 for c in r.evidence["clis"])


def test_check_clis_one_fails():
    def fake_run(cmd, *args, **kwargs):
        if "pipeline_gate" in " ".join(str(x) for x in cmd):
            return MagicMock(returncode=2, stdout="", stderr="Traceback...\n")
        return MagicMock(returncode=0, stdout="usage: ...\n", stderr="")
    with patch("phase_8_audit.subprocess.run", side_effect=fake_run):
        r = check_clis(root=Path("/tmp"))
    assert r.status == "FAIL"
    assert any(c["exit_code"] == 2 for c in r.evidence["clis"])
    assert len(r.debt_items) == 1
    assert "pipeline_gate" in r.debt_items[0].description
