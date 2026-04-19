"""Phase 8 audit tests — scaffold."""
import sys
import textwrap
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


from phase_8_audit import check_parity_matrix, load_parity_matrix


def _write_matrix(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "parity.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_load_parity_matrix_parses_entries(tmp_path):
    p = _write_matrix(tmp_path, """
    features:
      - id: F001
        modern_location: "audit-agents/foo.py"
        migration_decision: migrated
    summary:
      total_features: 1
      by_decision:
        migrated: 1
    """)
    d = load_parity_matrix(p)
    assert d["features"][0]["id"] == "F001"


def test_check_parity_matrix_all_valid(tmp_path):
    (tmp_path / "audit-agents").mkdir()
    (tmp_path / "audit-agents" / "foo.py").write_text("# ok")
    p = _write_matrix(tmp_path, """
    features:
      - id: F001
        modern_location: "audit-agents/foo.py"
        migration_decision: migrated
    summary:
      total_features: 1
      by_decision:
        migrated: 1
        deprecated: 0
        keep_standalone: 0
        added_phase_5: 0
        added_phase_6: 0
    """)
    r = check_parity_matrix(root=tmp_path, matrix_path=p)
    assert r.status == "PASS"
    assert r.evidence["total"] == 1
    assert r.debt_items == []


def test_check_parity_matrix_migrated_file_missing(tmp_path):
    p = _write_matrix(tmp_path, """
    features:
      - id: F001
        modern_location: "audit-agents/missing.py"
        migration_decision: migrated
    summary:
      total_features: 1
      by_decision:
        migrated: 1
        deprecated: 0
        keep_standalone: 0
        added_phase_5: 0
        added_phase_6: 0
    """)
    r = check_parity_matrix(root=tmp_path, matrix_path=p)
    assert r.status == "FAIL"
    assert any("F001" in d.description for d in r.debt_items)


def test_check_parity_matrix_summary_arithmetic_mismatch(tmp_path):
    (tmp_path / "audit-agents").mkdir()
    (tmp_path / "audit-agents" / "foo.py").write_text("# ok")
    p = _write_matrix(tmp_path, """
    features:
      - id: F001
        modern_location: "audit-agents/foo.py"
        migration_decision: migrated
    summary:
      total_features: 2
      by_decision:
        migrated: 1
        deprecated: 0
        keep_standalone: 0
        added_phase_5: 0
        added_phase_6: 0
    """)
    r = check_parity_matrix(root=tmp_path, matrix_path=p)
    assert r.status == "FAIL"
    assert any(d.category == "arithmetic" for d in r.debt_items)


from phase_8_audit import check_docs_sync


def test_check_docs_sync_clean(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("Nothing to flag here.\n")
    (tmp_path / "WIKI.md").write_text("Modern pipeline description.\n")
    r = check_docs_sync(root=tmp_path, removed_modules=["run_hunt", "target_score"], docs=["CLAUDE.md", "WIKI.md"])
    assert r.status == "PASS"
    assert r.evidence["hits"] == []


def test_check_docs_sync_flags_stale_ref(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("Use run_hunt.py --component X\n")
    (tmp_path / "WIKI.md").write_text("clean\n")
    r = check_docs_sync(root=tmp_path, removed_modules=["run_hunt"], docs=["CLAUDE.md", "WIKI.md"])
    assert r.status == "FAIL"
    assert len(r.evidence["hits"]) == 1
    assert r.evidence["hits"][0]["doc"] == "CLAUDE.md"
    assert r.evidence["hits"][0]["line"] == 1


def test_check_docs_sync_skips_archived_block(tmp_path):
    content = "Active section.\n<!-- Archived/Phase 7 cleanup -->\nold: run_hunt.py mention\n<!-- /Archived -->\nActive again.\n"
    (tmp_path / "CLAUDE.md").write_text(content)
    r = check_docs_sync(root=tmp_path, removed_modules=["run_hunt"], docs=["CLAUDE.md"])
    assert r.status == "PASS"
    assert r.evidence["hits"] == []


def test_check_docs_sync_missing_doc_is_warn(tmp_path):
    r = check_docs_sync(root=tmp_path, removed_modules=["run_hunt"], docs=["DOES_NOT_EXIST.md"])
    assert r.status == "WARN"
    assert "DOES_NOT_EXIST.md" in str(r.evidence)


from phase_8_audit import check_size_inventory


def test_check_size_inventory_under_thresholds(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "small.py").write_text("def a():\n    return 1\n")
    r = check_size_inventory(root=tmp_path)
    assert r.status == "PASS"
    assert r.evidence["file_count"] == 1
    assert r.debt_items == []


def test_check_size_inventory_flags_critical_file(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    lines = "\n".join([f"x{i} = {i}" for i in range(2100)])
    (pkg / "huge.py").write_text(lines + "\n")
    r = check_size_inventory(root=tmp_path)
    assert r.status == "WARN"
    assert any(d.severity == "CRITICAL" and "huge.py" in d.description for d in r.debt_items)


def test_check_size_inventory_flags_large_function(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    body = "\n".join([f"    y{i} = {i}" for i in range(150)])
    (pkg / "fn.py").write_text(f"def huge_fn():\n{body}\n    return 1\n")
    r = check_size_inventory(root=tmp_path)
    assert any(d.category == "function_size" and "huge_fn" in d.description for d in r.debt_items)


def test_check_size_inventory_excludes_tests(tmp_path):
    pkg = tmp_path / "audit-agents"
    (pkg / "tests").mkdir(parents=True)
    lines = "\n".join([f"x{i} = {i}" for i in range(2100)])
    (pkg / "tests" / "test_huge.py").write_text(lines + "\n")
    r = check_size_inventory(root=tmp_path)
    assert r.debt_items == []


from phase_8_audit import check_dead_code_residual


def test_check_dead_code_residual_clean(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "ok.py").write_text("import os\nprint(os.getcwd())\n")
    r = check_dead_code_residual(root=tmp_path)
    assert r.status == "PASS"
    assert r.evidence["todo_count"] == 0
    assert r.evidence["unused_import_count"] == 0


def test_check_dead_code_residual_flags_todo(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "x.py").write_text("# TODO: fix this\nimport os\nprint(os.getcwd())\n")
    r = check_dead_code_residual(root=tmp_path)
    assert r.evidence["todo_count"] == 1
    assert any(d.category == "todo" for d in r.debt_items)


def test_check_dead_code_residual_flags_unused_import(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "x.py").write_text("import unused_pkg\ndef f():\n    return 1\n")
    r = check_dead_code_residual(root=tmp_path)
    assert r.evidence["unused_import_count"] == 1


def test_check_dead_code_residual_respects_noqa(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "x.py").write_text("import shim  # noqa: F401\n")
    r = check_dead_code_residual(root=tmp_path)
    assert r.evidence["unused_import_count"] == 0


from phase_8_audit import check_shim_status


def test_check_shim_status_thin_and_consumed(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "run_benchmark.py").write_text("from mod import build_x  # noqa: F401\n")
    (pkg / "plan_generator.py").write_text("from mod import phase_x  # noqa: F401\n")
    (pkg / "consumer.py").write_text("from run_benchmark import build_x\nfrom plan_generator import phase_x\n")
    r = check_shim_status(root=tmp_path)
    assert r.status == "PASS"


def test_check_shim_status_fat_shim(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    body = "\n".join([f"x{i} = {i}" for i in range(80)])
    (pkg / "run_benchmark.py").write_text(body + "\n")
    (pkg / "plan_generator.py").write_text("# thin\n")
    r = check_shim_status(root=tmp_path)
    assert any(d.category == "shim_size" and "run_benchmark" in d.description for d in r.debt_items)


def test_check_shim_status_orphan_reexport(tmp_path):
    pkg = tmp_path / "audit-agents"
    pkg.mkdir()
    (pkg / "run_benchmark.py").write_text("from mod import orphan_fn  # noqa: F401\n")
    (pkg / "plan_generator.py").write_text("# empty\n")
    r = check_shim_status(root=tmp_path)
    assert any(d.category == "orphan_reexport" and "orphan_fn" in d.description for d in r.debt_items)
