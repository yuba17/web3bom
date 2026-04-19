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
