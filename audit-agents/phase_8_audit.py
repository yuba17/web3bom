"""Phase 8 audit — roadmap closure script.

Runs 7 independent checks over the audit-agents codebase and emits a
debt backlog for Phases 9+. See docs/superpowers/specs/2026-04-19-phase-8-audit-design.md.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import yaml
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
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


def check_test_suite(*, root: Path, expected_count: int = 227) -> CheckResult:
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


# ---------------------------------------------------------------------------
# Task 8: check_shim_status — LOC + orphan re-export detection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Task 9: render_json + render_markdown — artifact emitters
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Task 10: CLI entrypoint — argparse + exit codes + single-check mode
# ---------------------------------------------------------------------------

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
