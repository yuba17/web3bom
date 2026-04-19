"""Phase 8 audit — roadmap closure script.

Runs 7 independent checks over the audit-agents codebase and emits a
debt backlog for Phases 9+. See docs/superpowers/specs/2026-04-19-phase-8-audit-design.md.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
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
