# Phase 8 — Audit-First Roadmap Closure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reproducible script (`audit-agents/phase_8_audit.py`) that validates the Phase 0-7 roadmap claims, emits a debt backlog, and closes the roadmap.

**Architecture:** Single-module script with 7 independent check functions (pure, kwargs-injected paths), two renderers (JSON + Markdown), a CLI, and ~15 new tests under `audit-agents/tests/phase_8/`. Each check returns a `CheckResult` dataclass; renderers consume the list. The script produces `audit-agents/audit_report.json` and `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md`.

**Tech Stack:** Python 3 stdlib (`ast`, `subprocess`, `pathlib`, `dataclasses`, `argparse`) + PyYAML. No new dependencies.

---

## File Structure

| File | Responsibility |
|---|---|
| `audit-agents/phase_8_audit.py` | Script with all 7 checks + renderers + CLI main. Target LOC <800. |
| `audit-agents/tests/phase_8/__init__.py` | Empty package marker. |
| `audit-agents/tests/phase_8/test_audit.py` | ~15 tests, one per check happy/failure + renderer/CLI tests. |
| `audit-agents/audit_report.json` | Generated artifact (Task 11). |
| `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md` | Generated artifact (Task 11). |

If `phase_8_audit.py` exceeds 800 LOC, split checks into `audit-agents/audit/checks/check_*.py` and `audit-agents/audit/renderers.py` as part of Task 10. Decision deferred to Task 10 review.

---

## Task 0: Baseline verification

**Files:** None modified.

- [ ] **Step 1: Verify current suite green**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/ -q 2>&1 | tail -3`
Expected: `138 passed`

- [ ] **Step 2: Verify 5 CLIs respond**

Run: `for cli in run_benchmark plan_generator pipeline_gate scope_intake sync_state; do python3 audit-agents/${cli}.py --help >/dev/null 2>&1 && echo "$cli OK" || echo "$cli FAIL"; done`
Expected: 5 lines, all "OK"

- [ ] **Step 3: Confirm spec committed**

Run: `git log --oneline -1 docs/superpowers/specs/2026-04-19-phase-8-audit-design.md`
Expected: one line showing the spec commit

No commit for Task 0.

---

## Task 1: Scaffold script + dataclasses + pytest scaffolding

**Files:**
- Create: `audit-agents/phase_8_audit.py`
- Create: `audit-agents/tests/phase_8/__init__.py`
- Create: `audit-agents/tests/phase_8/test_audit.py`

- [ ] **Step 1: Write the failing test**

Create `audit-agents/tests/phase_8/__init__.py` (empty file).

Create `audit-agents/tests/phase_8/test_audit.py`:

```python
"""Phase 8 audit tests — scaffold."""
from pathlib import Path

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -10`
Expected: `ModuleNotFoundError: No module named 'phase_8_audit'` or equivalent import failure

- [ ] **Step 3: Write minimal implementation**

Create `audit-agents/phase_8_audit.py`:

```python
"""Phase 8 audit — roadmap closure script.

Runs 7 independent checks over the audit-agents codebase and emits a
debt backlog for Phases 9+. See docs/superpowers/specs/2026-04-19-phase-8-audit-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Status = Literal["PASS", "FAIL", "WARN", "ERROR"]


@dataclass
class DebtItem:
    severity: Severity
    category: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    name: str
    status: Status
    evidence: dict[str, Any] = field(default_factory=dict)
    debt_items: list[DebtItem] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -10`
Expected: `4 passed`

- [ ] **Step 5: Verify combined suite**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/ -q 2>&1 | tail -3`
Expected: `142 passed` (138 baseline + 4 new)

- [ ] **Step 6: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/
git commit -m "feat(phase_8): scaffold — CheckResult/DebtItem dataclasses + test harness"
```

---

## Task 2: check_test_suite

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_test_suite`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -10`
Expected: `ImportError` or `AttributeError` — `check_test_suite` not defined

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
import re
import subprocess
from pathlib import Path


def check_test_suite(*, root: Path, expected_count: int = 138) -> CheckResult:
    """Run pytest over audit-agents/tests and verify expected_count passed."""
    proc = subprocess.run(
        ["python3", "-m", "pytest", "audit-agents/tests/", "-q"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=300,
    )
    stdout = proc.stdout or ""
    match = re.search(r"(\d+)\s+passed", stdout)
    passed = int(match.group(1)) if match else 0
    evidence = {"passed": passed, "expected": expected_count, "returncode": proc.returncode}
    if proc.returncode == 0 and passed == expected_count:
        return CheckResult(name="check_test_suite", status="PASS", evidence=evidence)
    debt = DebtItem(
        severity="HIGH",
        category="test_regression",
        description=f"pytest: expected {expected_count} passed, got {passed} (returncode={proc.returncode})",
        evidence=evidence,
    )
    return CheckResult(name="check_test_suite", status="FAIL", evidence=evidence, debt_items=[debt])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -10`
Expected: `7 passed` (4 previous + 3 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_test_suite — validate pytest count"
```

---

## Task 3: check_clis

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_clis`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_clis`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
CLI_SCRIPTS = ["run_benchmark.py", "plan_generator.py", "pipeline_gate.py", "scope_intake.py", "sync_state.py"]


def check_clis(*, root: Path, scripts: list[str] | None = None) -> CheckResult:
    """Run `python3 <cli> --help` for each CLI and check exit 0."""
    scripts = scripts or CLI_SCRIPTS
    cli_results = []
    debts = []
    for cli in scripts:
        proc = subprocess.run(
            ["python3", f"audit-agents/{cli}", "--help"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        first_line = (proc.stdout or "").splitlines()[0] if proc.stdout else ""
        cli_results.append({"cli": cli, "exit_code": proc.returncode, "first_line": first_line})
        if proc.returncode != 0:
            debts.append(DebtItem(
                severity="HIGH",
                category="cli_broken",
                description=f"{cli} --help exited {proc.returncode}",
                evidence={"stderr": (proc.stderr or "")[:200]},
            ))
    status = "PASS" if not debts else "FAIL"
    return CheckResult(name="check_clis", status=status, evidence={"clis": cli_results}, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: `9 passed` (7 previous + 2 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_clis — validate 5 CLIs respond to --help"
```

---

## Task 4: check_parity_matrix

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_parity_matrix`, `load_parity_matrix`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
import textwrap

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_parity_matrix` / `load_parity_matrix`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
import yaml


def load_parity_matrix(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _strip_location_qualifier(loc: str) -> str:
    """'run_benchmark.py (section X)' -> 'run_benchmark.py'; keep 'foo.py' as-is."""
    return loc.split(" ")[0].split(":")[0] if loc else ""


def check_parity_matrix(*, root: Path, matrix_path: Path) -> CheckResult:
    """Validate every entry in the parity matrix and arithmetic of summary."""
    try:
        data = load_parity_matrix(matrix_path)
    except Exception as e:
        return CheckResult(
            name="check_parity_matrix",
            status="ERROR",
            evidence={"error": str(e)},
            debt_items=[DebtItem(severity="CRITICAL", category="parse", description=f"YAML parse failed: {e}", evidence={})],
        )
    debts: list[DebtItem] = []
    features = data.get("features", [])
    for feat in features:
        fid = feat.get("id", "?")
        decision = feat.get("migration_decision", "")
        if decision in ("migrated", "added_phase_5", "added_phase_6"):
            modern = _strip_location_qualifier(feat.get("modern_location", ""))
            if modern and not (root / modern).exists():
                debts.append(DebtItem(
                    severity="HIGH",
                    category="stale_claim",
                    description=f"{fid} ({decision}): modern_location '{modern}' missing",
                    evidence={"entry": fid, "path": modern},
                ))
        elif decision == "deprecated":
            legacy = _strip_location_qualifier(feat.get("legacy_location", ""))
            if legacy and (root / legacy).exists():
                debts.append(DebtItem(
                    severity="HIGH",
                    category="stale_claim",
                    description=f"{fid} (deprecated): legacy_location '{legacy}' still exists",
                    evidence={"entry": fid, "path": legacy},
                ))
    summary = data.get("summary", {})
    total = summary.get("total_features", 0)
    by_decision = summary.get("by_decision", {}) or {}
    declared_sum = sum(by_decision.values()) if by_decision else 0
    actual_count = len(features)
    if total != declared_sum or total != actual_count:
        debts.append(DebtItem(
            severity="MEDIUM",
            category="arithmetic",
            description=f"summary arithmetic: total={total}, by_decision_sum={declared_sum}, features_count={actual_count}",
            evidence={"total": total, "by_decision_sum": declared_sum, "features_count": actual_count},
        ))
    evidence = {"total": actual_count, "by_decision": by_decision, "summary_total": total}
    status = "PASS" if not debts else "FAIL"
    return CheckResult(name="check_parity_matrix", status=status, evidence=evidence, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: `13 passed` (9 previous + 4 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_parity_matrix — validate claims + summary arithmetic"
```

---

## Task 5: check_docs_sync

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_docs_sync`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_docs_sync`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
REMOVED_MODULES_DEFAULT = [
    "run_hunt",
    "bounty_monitor_config", "results_tracker", "test_stream_claude2",
    "invariant_test_runner", "quickstart", "bounty_scanner", "claude_classify",
    "invariant-hunt", "parameter_boundary_scanner", "target_score", "test_stream_claude",
    "ai_invariant_generator", "migrate_hunt_session", "protocol_analyzer",
    "compile_fixer", "invariant_rag",
]

DOCS_DEFAULT = ["CLAUDE.md", "WIKI.md", "HUNT_TRACKER.md", "README.md"]

_ARCHIVED_OPEN = "<!-- Archived"
_ARCHIVED_CLOSE = "<!-- /Archived"


def _strip_archived_blocks(text: str) -> list[tuple[int, str]]:
    """Return list of (1-based_line_number, line) excluding lines inside archived blocks."""
    result = []
    in_archived = False
    for i, line in enumerate(text.splitlines(), start=1):
        if _ARCHIVED_OPEN in line:
            in_archived = True
            continue
        if _ARCHIVED_CLOSE in line:
            in_archived = False
            continue
        if not in_archived:
            result.append((i, line))
    return result


def check_docs_sync(*, root: Path, removed_modules: list[str] | None = None, docs: list[str] | None = None) -> CheckResult:
    """Grep docs for stale refs to removed modules, skipping archived blocks."""
    removed_modules = removed_modules or REMOVED_MODULES_DEFAULT
    docs = docs or DOCS_DEFAULT
    hits = []
    missing = []
    for doc in docs:
        path = root / doc
        if not path.exists():
            missing.append(doc)
            continue
        text = path.read_text()
        for lineno, line in _strip_archived_blocks(text):
            for mod in removed_modules:
                if mod in line:
                    hits.append({"doc": doc, "line": lineno, "module": mod, "content": line.strip()[:120]})
    evidence: dict[str, Any] = {"hits": hits, "docs_checked": [d for d in docs if d not in missing]}
    debts = []
    if hits:
        debts.append(DebtItem(
            severity="MEDIUM",
            category="stale_ref",
            description=f"{len(hits)} stale module reference(s) in docs",
            evidence={"sample": hits[:5]},
        ))
    if missing:
        evidence["missing_docs"] = missing
        status = "WARN"
    else:
        status = "PASS" if not hits else "FAIL"
    return CheckResult(name="check_docs_sync", status=status, evidence=evidence, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: `17 passed` (13 previous + 4 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_docs_sync — grep removed modules in live docs"
```

---

## Task 6: check_size_inventory

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_size_inventory`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_size_inventory`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
import ast


def _iter_py_files(pkg_root: Path) -> list[Path]:
    """Walk pkg_root for .py files, excluding any tests/ subdirectory."""
    return sorted(p for p in pkg_root.rglob("*.py") if "tests" not in p.relative_to(pkg_root).parts)


def _file_loc(path: Path) -> int:
    return sum(1 for _ in path.read_text(errors="replace").splitlines())


def _function_lengths(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except SyntaxError:
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.end_lineno is not None:
                out.append((node.name, node.end_lineno - node.lineno + 1))
    return out


def check_size_inventory(*, root: Path) -> CheckResult:
    """Report files >800 LOC and functions >100 LOC."""
    pkg = root / "audit-agents"
    if not pkg.exists():
        return CheckResult(name="check_size_inventory", status="ERROR", evidence={"reason": "audit-agents/ missing"})
    files = _iter_py_files(pkg)
    file_entries = []
    debts: list[DebtItem] = []
    for p in files:
        loc = _file_loc(p)
        rel = str(p.relative_to(root))
        file_entries.append({"path": rel, "loc": loc})
        if loc >= 2000:
            sev = "CRITICAL"
        elif loc >= 1500:
            sev = "HIGH"
        elif loc >= 800:
            sev = "MEDIUM"
        else:
            sev = None
        if sev:
            debts.append(DebtItem(
                severity=sev,
                category="file_size",
                description=f"{rel} is {loc} LOC ({sev.lower()} threshold)",
                evidence={"path": rel, "loc": loc},
            ))
        for name, flen in _function_lengths(p):
            if flen >= 200:
                debts.append(DebtItem(severity="HIGH", category="function_size",
                    description=f"{rel}::{name} is {flen} LOC", evidence={"path": rel, "function": name, "loc": flen}))
            elif flen >= 100:
                debts.append(DebtItem(severity="MEDIUM", category="function_size",
                    description=f"{rel}::{name} is {flen} LOC", evidence={"path": rel, "function": name, "loc": flen}))
    evidence = {"file_count": len(files), "files": sorted(file_entries, key=lambda e: -e["loc"])[:20]}
    has_high = any(d.severity in ("CRITICAL", "HIGH") for d in debts)
    status = "WARN" if has_high else "PASS"
    return CheckResult(name="check_size_inventory", status=status, evidence=evidence, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: `21 passed` (17 previous + 4 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_size_inventory — AST-based LOC thresholds"
```

---

## Task 7: check_dead_code_residual

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_dead_code_residual`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_dead_code_residual`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")


def _line_has_noqa(text: str, lineno: int) -> bool:
    lines = text.splitlines()
    if 0 < lineno <= len(lines):
        return "# noqa" in lines[lineno - 1]
    return False


def _unused_imports(path: Path) -> list[dict]:
    text = path.read_text(errors="replace")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    imported: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                name = a.asname or a.name.split(".")[0]
                imported[name] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                name = a.asname or a.name
                if name == "*":
                    continue
                imported[name] = node.lineno
    if not imported:
        return []
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            n = node
            while isinstance(n, ast.Attribute):
                n = n.value
            if isinstance(n, ast.Name):
                used.add(n.id)
    out = []
    for name, lineno in imported.items():
        if name in used:
            continue
        if _line_has_noqa(text, lineno):
            continue
        out.append({"name": name, "line": lineno})
    return out


def check_dead_code_residual(*, root: Path) -> CheckResult:
    """Find TODO markers and unused imports in audit-agents/."""
    pkg = root / "audit-agents"
    if not pkg.exists():
        return CheckResult(name="check_dead_code_residual", status="ERROR", evidence={"reason": "audit-agents/ missing"})
    files = _iter_py_files(pkg)
    todos = []
    unused = []
    debts: list[DebtItem] = []
    for p in files:
        rel = str(p.relative_to(root))
        text = p.read_text(errors="replace")
        for i, line in enumerate(text.splitlines(), start=1):
            if _TODO_RE.search(line):
                todos.append({"path": rel, "line": i, "content": line.strip()[:120]})
        for u in _unused_imports(p):
            unused.append({"path": rel, **u})
    for t in todos:
        debts.append(DebtItem(severity="LOW", category="todo",
            description=f"{t['path']}:{t['line']} — {t['content']}", evidence=t))
    for u in unused:
        debts.append(DebtItem(severity="LOW", category="unused_import",
            description=f"{u['path']}:{u['line']} imports '{u['name']}' but never uses it", evidence=u))
    evidence = {"todo_count": len(todos), "unused_import_count": len(unused)}
    status = "PASS" if not debts else "WARN"
    return CheckResult(name="check_dead_code_residual", status=status, evidence=evidence, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: `25 passed` (21 previous + 4 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_dead_code_residual — TODOs + unused imports"
```

---

## Task 8: check_shim_status

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `check_shim_status`)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `check_shim_status`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
SHIMS = ["run_benchmark.py", "plan_generator.py"]


def _reexports_in_shim(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, FileNotFoundError):
        return []
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for a in node.names:
                name = a.asname or a.name
                if name != "*":
                    names.append(name)
    return names


def _consumer_count(pkg: Path, shim_mod: str, reexport: str) -> int:
    """Count `from <shim_mod> import <reexport>` across pkg (excluding the shim itself)."""
    pattern = re.compile(rf"from\s+{re.escape(shim_mod)}\s+import[^\n]*\b{re.escape(reexport)}\b")
    count = 0
    for p in pkg.rglob("*.py"):
        if p.name == f"{shim_mod}.py":
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            count += 1
    return count


def check_shim_status(*, root: Path, shims: list[str] | None = None) -> CheckResult:
    """Analyze shim size + re-export consumer counts."""
    shims = shims or SHIMS
    pkg = root / "audit-agents"
    if not pkg.exists():
        return CheckResult(name="check_shim_status", status="ERROR", evidence={"reason": "audit-agents/ missing"})
    debts: list[DebtItem] = []
    shim_info = []
    for shim in shims:
        path = pkg / shim
        if not path.exists():
            debts.append(DebtItem(severity="MEDIUM", category="missing_shim",
                description=f"shim {shim} missing", evidence={"shim": shim}))
            continue
        loc = _file_loc(path)
        reexports = _reexports_in_shim(path)
        shim_mod = shim[:-3]
        consumer_counts = {rx: _consumer_count(pkg, shim_mod, rx) for rx in reexports}
        orphan = [rx for rx, n in consumer_counts.items() if n == 0]
        shim_info.append({"shim": shim, "loc": loc, "reexports": len(reexports), "orphans": orphan})
        if loc > 50:
            debts.append(DebtItem(severity="LOW", category="shim_size",
                description=f"{shim} is {loc} LOC (expected <50)", evidence={"shim": shim, "loc": loc}))
        for o in orphan:
            debts.append(DebtItem(severity="LOW", category="orphan_reexport",
                description=f"{shim} re-exports '{o}' with 0 consumers — sunset candidate",
                evidence={"shim": shim, "reexport": o}))
    evidence = {"shims": shim_info}
    has_issue = bool(debts)
    status = "WARN" if has_issue else "PASS"
    return CheckResult(name="check_shim_status", status=status, evidence=evidence, debt_items=debts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: `28 passed` (25 previous + 3 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): check_shim_status — LOC + orphan re-export detection"
```

---

## Task 9: render_json + render_markdown

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add renderers)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
import json as _json

from phase_8_audit import render_json, render_markdown


def test_render_json_schema(tmp_path):
    results = [
        CheckResult(name="check_test_suite", status="PASS", evidence={"passed": 138}),
        CheckResult(name="check_size_inventory", status="WARN", evidence={"file_count": 60},
                    debt_items=[DebtItem(severity="HIGH", category="file_size", description="x.py 1500 LOC", evidence={"loc": 1500})]),
    ]
    out = tmp_path / "report.json"
    render_json(results, out)
    data = _json.loads(out.read_text())
    assert "generated_at" in data
    assert "summary" in data
    assert data["summary"]["gates"]["PASS"] == 1
    assert data["summary"]["gates"]["WARN"] == 1
    assert data["summary"]["debt_items"]["HIGH"] == 1
    assert len(data["checks"]) == 2


def test_render_markdown_has_required_sections(tmp_path):
    results = [
        CheckResult(name="check_test_suite", status="PASS", evidence={"passed": 138}),
        CheckResult(name="check_size_inventory", status="WARN", evidence={"file_count": 60},
                    debt_items=[DebtItem(severity="HIGH", category="file_size", description="x.py 1500 LOC", evidence={"loc": 1500})]),
    ]
    out = tmp_path / "report.md"
    render_markdown(results, out)
    text = out.read_text()
    assert "# Phase 8 Audit Report" in text
    assert "## Executive Summary" in text
    assert "## Per-check results" in text
    assert "## Debt Backlog" in text
    assert "## Roadmap closure" in text
    assert "check_test_suite" in text
    assert "x.py 1500 LOC" in text


def test_render_markdown_verdict_successful_when_no_fail():
    r = [CheckResult(name="a", status="PASS", evidence={})]
    from phase_8_audit import _roadmap_verdict
    assert _roadmap_verdict(r) == "SUCCESSFUL"


def test_render_markdown_verdict_partial_on_warn():
    r = [CheckResult(name="a", status="PASS", evidence={}),
         CheckResult(name="b", status="WARN", evidence={})]
    from phase_8_audit import _roadmap_verdict
    assert _roadmap_verdict(r) == "PARTIAL"


def test_render_markdown_verdict_failed_on_fail():
    r = [CheckResult(name="a", status="FAIL", evidence={})]
    from phase_8_audit import _roadmap_verdict
    assert _roadmap_verdict(r) == "FAILED"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -6`
Expected: ImportError on `render_json` / `render_markdown` / `_roadmap_verdict`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
import json
from collections import Counter
from datetime import datetime, timezone


def _summarize(results: list[CheckResult]) -> dict:
    gates = Counter(r.status for r in results)
    debts = Counter(d.severity for r in results for d in r.debt_items)
    return {
        "gates": {"PASS": gates.get("PASS", 0), "FAIL": gates.get("FAIL", 0),
                  "WARN": gates.get("WARN", 0), "ERROR": gates.get("ERROR", 0)},
        "debt_items": {"CRITICAL": debts.get("CRITICAL", 0), "HIGH": debts.get("HIGH", 0),
                       "MEDIUM": debts.get("MEDIUM", 0), "LOW": debts.get("LOW", 0)},
    }


def _roadmap_verdict(results: list[CheckResult]) -> str:
    statuses = {r.status for r in results}
    if "FAIL" in statuses or "ERROR" in statuses:
        return "FAILED"
    if "WARN" in statuses:
        return "PARTIAL"
    return "SUCCESSFUL"


def render_json(results: list[CheckResult], output_path: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _summarize(results),
        "verdict": _roadmap_verdict(results),
        "checks": [
            {
                "name": r.name,
                "status": r.status,
                "evidence": r.evidence,
                "debt_items": [
                    {"severity": d.severity, "category": d.category,
                     "description": d.description, "evidence": d.evidence}
                    for d in r.debt_items
                ],
            }
            for r in results
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str))


_STATUS_GLYPH = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "ERROR": "💥"}


def render_markdown(results: list[CheckResult], output_path: Path) -> None:
    summary = _summarize(results)
    verdict = _roadmap_verdict(results)
    lines = [
        "# Phase 8 Audit Report — " + datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "",
        "## Executive Summary",
        "",
        f"- Gates: {summary['gates']['PASS']} PASS / {summary['gates']['FAIL']} FAIL / {summary['gates']['WARN']} WARN / {summary['gates']['ERROR']} ERROR",
        f"- Debt: {summary['debt_items']['CRITICAL']} CRITICAL / {summary['debt_items']['HIGH']} HIGH / {summary['debt_items']['MEDIUM']} MEDIUM / {summary['debt_items']['LOW']} LOW",
        f"- Roadmap verdict: **{verdict}**",
        "",
        "## Per-check results",
        "",
    ]
    for r in results:
        glyph = _STATUS_GLYPH.get(r.status, "")
        lines.append(f"### {glyph} {r.name} — {r.status}")
        lines.append("")
        lines.append("Evidence:")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(r.evidence, indent=2, default=str))
        lines.append("```")
        lines.append("")
    lines += ["## Debt Backlog", ""]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = [d for r in results for d in r.debt_items if d.severity == sev]
        if not items:
            continue
        lines.append(f"### {sev}")
        lines.append("")
        for i, d in enumerate(items, start=1):
            lines.append(f"- **{sev}-{i:02d}** [{d.category}] {d.description}")
        lines.append("")
    lines += [
        "## Roadmap closure",
        "",
        f"Phase 8 status: **COMPLETE**. Verdict: **{verdict}**.",
        "",
        "Next: Phase 9+ addresses the backlog above, prioritized by severity.",
        "",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -7`
Expected: `33 passed` (28 previous + 5 new)

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): render_json + render_markdown with roadmap verdict"
```

---

## Task 10: CLI wiring

**Files:**
- Modify: `audit-agents/phase_8_audit.py` (add `main` + argparse)
- Modify: `audit-agents/tests/phase_8/test_audit.py` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `audit-agents/tests/phase_8/test_audit.py`:

```python
from phase_8_audit import main


def _stub_all_checks(monkeypatch, results):
    for r in results:
        monkeypatch.setattr(f"phase_8_audit.{r.name}", lambda *, root, _r=r, **kw: _r)


def test_cli_all_checks_pass_exit_0(tmp_path, monkeypatch):
    results = [CheckResult(name=n, status="PASS", evidence={}) for n in [
        "check_test_suite", "check_clis", "check_parity_matrix", "check_docs_sync",
        "check_size_inventory", "check_dead_code_residual", "check_shim_status"
    ]]
    _stub_all_checks(monkeypatch, results)
    exit_code = main(["--root", str(tmp_path), "--json-only", "--json-path", str(tmp_path / "r.json")])
    assert exit_code == 0
    assert (tmp_path / "r.json").exists()


def test_cli_fail_on_warn_exits_2(tmp_path, monkeypatch):
    results = [CheckResult(name="check_test_suite", status="PASS", evidence={}),
               CheckResult(name="check_size_inventory", status="WARN", evidence={})]
    # stub only the 2 we want; others return PASS
    def stub(name, res):
        return lambda *, root, **kw: res
    monkeypatch.setattr("phase_8_audit.check_test_suite", stub("check_test_suite", results[0]))
    monkeypatch.setattr("phase_8_audit.check_size_inventory", stub("check_size_inventory", results[1]))
    for n in ["check_clis", "check_parity_matrix", "check_docs_sync", "check_dead_code_residual", "check_shim_status"]:
        monkeypatch.setattr(f"phase_8_audit.{n}", lambda *, root, _n=n, **kw: CheckResult(name=_n, status="PASS", evidence={}))
    exit_code = main(["--root", str(tmp_path), "--json-only",
                      "--json-path", str(tmp_path / "r.json"), "--fail-on", "WARN"])
    assert exit_code == 2


def test_cli_single_check_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("phase_8_audit.check_test_suite",
                        lambda *, root, **kw: CheckResult(name="check_test_suite", status="PASS", evidence={"passed": 138}))
    exit_code = main(["--root", str(tmp_path), "--check", "check_test_suite"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "check_test_suite" in captured.out
    assert "PASS" in captured.out


def test_cli_unknown_check_errors(tmp_path):
    exit_code = main(["--root", str(tmp_path), "--check", "bogus"])
    assert exit_code != 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -5`
Expected: ImportError on `main`

- [ ] **Step 3: Write minimal implementation**

Append to `audit-agents/phase_8_audit.py`:

```python
import argparse
import sys

_ALL_CHECKS = {
    "check_test_suite": lambda root: check_test_suite(root=root),
    "check_clis": lambda root: check_clis(root=root),
    "check_parity_matrix": lambda root: check_parity_matrix(
        root=root, matrix_path=root / "docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml"),
    "check_docs_sync": lambda root: check_docs_sync(root=root),
    "check_size_inventory": lambda root: check_size_inventory(root=root),
    "check_dead_code_residual": lambda root: check_dead_code_residual(root=root),
    "check_shim_status": lambda root: check_shim_status(root=root),
}

_DEFAULT_JSON = "audit-agents/audit_report.json"
_DEFAULT_MD = "docs/superpowers/specs/2026-04-19-phase-8-audit-report.md"


def _exit_code(results: list[CheckResult], fail_on: str | None) -> int:
    statuses = {r.status for r in results}
    if "ERROR" in statuses:
        return 3
    if "FAIL" in statuses:
        return 1
    if fail_on == "WARN" and "WARN" in statuses:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 8 audit — roadmap closure")
    parser.add_argument("--root", default=".", help="Repo root (default: cwd)")
    parser.add_argument("--check", help="Run a single check and print to stdout")
    parser.add_argument("--json-only", action="store_true")
    parser.add_argument("--md-only", action="store_true")
    parser.add_argument("--json-path", default=None)
    parser.add_argument("--md-path", default=None)
    parser.add_argument("--fail-on", choices=["WARN"], default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()

    if args.check:
        if args.check not in _ALL_CHECKS:
            print(f"unknown check: {args.check}", file=sys.stderr)
            print(f"available: {', '.join(_ALL_CHECKS)}", file=sys.stderr)
            return 4
        r = _ALL_CHECKS[args.check](root)
        print(f"{r.name}: {r.status}")
        print(json.dumps({"evidence": r.evidence, "debts": [d.__dict__ for d in r.debt_items]}, indent=2, default=str))
        return _exit_code([r], args.fail_on)

    results = [fn(root) for fn in _ALL_CHECKS.values()]
    if not args.md_only:
        render_json(results, Path(args.json_path) if args.json_path else root / _DEFAULT_JSON)
    if not args.json_only:
        render_markdown(results, Path(args.md_path) if args.md_path else root / _DEFAULT_MD)
    return _exit_code(results, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/phase_8/ -v 2>&1 | tail -8`
Expected: `37 passed` (33 previous + 4 new)

- [ ] **Step 5: Verify combined suite**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/ -q 2>&1 | tail -3`
Expected: `175 passed` (138 baseline + 37 phase_8)

- [ ] **Step 6: Verify script LOC still under 800**

Run: `cd /home/kali/Documents/Web3 && wc -l audit-agents/phase_8_audit.py`
Expected: <800 LOC

If >800 LOC, file for refactor in follow-up commit (split into `audit-agents/audit/checks/*.py` modules). Don't block Task 10 merge.

- [ ] **Step 7: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/phase_8_audit.py audit-agents/tests/phase_8/test_audit.py
git commit -m "feat(phase_8): CLI main — argparse + exit codes + single-check mode"
```

---

## Task 11: Execute audit + produce artifact reports

**Files:**
- Create: `audit-agents/audit_report.json` (generated)
- Create: `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md` (generated)
- Possibly modify: up to 2 trivial stale refs inline

- [ ] **Step 1: Run the audit**

Run: `cd /home/kali/Documents/Web3 && python3 audit-agents/phase_8_audit.py 2>&1 | tail -20`
Expected: exit 0, 1, or 2; JSON + MD written to expected paths

- [ ] **Step 2: Inspect summary**

Run: `cd /home/kali/Documents/Web3 && python3 -c "import json; d=json.load(open('audit-agents/audit_report.json')); print(json.dumps(d['summary'], indent=2)); print('verdict:', d['verdict'])"`
Expected: summary dict printed with counts + verdict

- [ ] **Step 3: Identify trivial stale refs (≤2)**

Inspect the debt backlog for `category: stale_ref` items (from `check_docs_sync`). Count them.
- If 0 → skip to Step 5.
- If 1-2 → Step 4.
- If >2 → leave all in backlog; skip to Step 5.

- [ ] **Step 4: Fix ≤2 trivial stale refs inline (only if count is 1-2)**

For each stale ref, apply the minimal Edit to remove or correct the reference in the doc. Examples:
- Row removal in a markdown table
- Sentence rewrite to drop the reference

After fixing, re-run Step 1 to confirm `check_docs_sync` now PASSES.

- [ ] **Step 5: Re-run audit to regenerate artifacts (post-fix)**

Run: `cd /home/kali/Documents/Web3 && python3 audit-agents/phase_8_audit.py`
Expected: exit code stable; artifacts regenerated

- [ ] **Step 6: Commit the generated artifacts + any inline fixes**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/audit_report.json docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
# If Step 4 applied fixes, include the doc edits:
git add -u CLAUDE.md WIKI.md HUNT_TRACKER.md README.md 2>/dev/null || true
git commit -m "chore(phase_8): execute audit — emit JSON + MD report (+ inline fixes if any)"
```

---

## Task 12: Roadmap closure

**Files:**
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/MEMORY.md`

- [ ] **Step 1: Update roadmap memory — Fase 8 row + summary section**

Edit `memory/project_optimization_roadmap.md`:

1. Frontmatter description: change `Fase 7 COMPLETA (2026-04-19). Siguiente Fase 8.` → `Roadmap 8 fases COMPLETO (2026-04-19). Backlog en report Phase 8.`
2. Fases table row 8: change `🔜 NEXT` to `✅ COMPLETA (2026-04-19)` and summarize the audit outcome.
3. Add new section `## Fase 8 — resumen al cerrar` with:
   - Verdict (SUCCESSFUL/PARTIAL/FAILED)
   - Summary counts (gates + debts)
   - Link to `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md`
   - Commits produced
   - Link to design spec
   - Explicit "backlog para Fase 9+" with top HIGH/CRITICAL items

Exact content to add/modify depends on audit results from Task 11.

- [ ] **Step 2: Update MEMORY.md index**

Edit `memory/MEMORY.md`:

Change the roadmap row from:
```
- [project_optimization_roadmap.md](project_optimization_roadmap.md) — Roadmap 8 fases: Fase 7 COMPLETA (2026-04-19, orphan cleanup + parity polish), Fase 8 NEXT.
```

To:
```
- [project_optimization_roadmap.md](project_optimization_roadmap.md) — Roadmap 8 fases: COMPLETO (2026-04-19). Verdict <VERDICT>. Backlog en audit report.
```

Where `<VERDICT>` is from Task 11 output.

- [ ] **Step 3: Verify memory still parses as markdown**

Run: `cd /home/kali && head -20 /home/kali/.claude/projects/-home-kali-Documents-Web3/memory/MEMORY.md`
Expected: index with the updated roadmap entry visible

- [ ] **Step 4: No commit (memory is outside repo)**

Memory updates are outside the git repo. No commit step.

- [ ] **Step 5: Final suite verification**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/ -q 2>&1 | tail -3`
Expected: `175 passed` (or higher if Task 11 added tests)

---

## Success criteria

- [ ] `audit-agents/phase_8_audit.py` exists, <800 LOC, runs exit 0/1/2
- [ ] `audit-agents/audit_report.json` generated with 7 checks
- [ ] `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md` generated with Executive Summary + Per-check + Debt Backlog + Roadmap closure
- [ ] Combined test suite 175+ passed, 0 regressions
- [ ] `project_optimization_roadmap.md` marks Fase 8 COMPLETA
- [ ] `MEMORY.md` index updated

## Out of scope (reminder from spec §10)

- ❌ Splits of pipeline_gate.py / hybrid_pipeline.py / merge_invariants.py / target_monitor.py
- ❌ Eje 3 matching consolidation
- ❌ Regression sweep via benchmark
- ❌ Auto-fix of debt items (exception: ≤2 trivial stale refs in Task 11)
- ❌ Modifying the parity matrix (only validates)
