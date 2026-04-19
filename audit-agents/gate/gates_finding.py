"""Finding-stage gate checks: poc, escalation, variant, redteam, verify, report, submit.

Hosts the finding-pipeline gate check functions, FINDING_GATE_ORDER dispatch
metadata, and finding-level gate_status export. The check helpers search all
hypothesis YAMLs in `HUNT_SESSION_DIR/hypotheses/` via `_find_hyp_with_finding`
and then verify per-gate preconditions.

Late-bound HUNT_SESSION_DIR lookup mirrors gate.gates_component so CLI
session-dir overrides and test monkeypatches (on `pipeline_gate.HUNT_SESSION_DIR`)
take effect without requiring callers to re-import.
"""

from pathlib import Path

import yaml

from paths import WEB3_DIR, HUNT_SESSION_DIR
from state_manager import load_state
from gate.gate_status import _map_gate_state, _load_gate_status, _save_gate_status

__all__ = [
    "FINDING_GATE_ORDER",
    "DISPLAY_FINDING_GATES",
    "REPORTS_DIR",
    "RESULTS_DIR",
    "_find_hyp_with_finding",
    "_check_poc_uses_fork",
    "check_finding_poc",
    "check_finding_escalation",
    "check_finding_variant",
    "check_finding_redteam",
    "check_finding_verify",
    "check_finding_report",
    "check_finding_submit",
    "FINDING_GATE_CHECKS",
    "export_finding_gate_status",
]


FINDING_GATE_ORDER = ["poc", "escalation", "variant", "redteam", "verify", "report", "submit", "reportable"]

DISPLAY_FINDING_GATES = [g for g in FINDING_GATE_ORDER if g != "reportable"]

REPORTS_DIR = WEB3_DIR / "reports"
RESULTS_DIR = HUNT_SESSION_DIR / "results"


def _hunt_session_dir() -> Path:
    """Late-bound HUNT_SESSION_DIR so CLI session-dir overrides and test
    monkeypatches (on `pipeline_gate.HUNT_SESSION_DIR`) take effect without
    requiring callers to re-import.

    Handles two execution modes:
      - imported as `pipeline_gate` (tests, other modules)
      - run as script (`__name__ == "__main__"`), where the shim lives in
        sys.modules under the key "__main__" instead of "pipeline_gate".
    """
    import sys
    for key in ("pipeline_gate", "__main__"):
        mod = sys.modules.get(key)
        if mod is not None and hasattr(mod, "HUNT_SESSION_DIR") and hasattr(mod, "_gates_component"):
            return mod.HUNT_SESSION_DIR
    return HUNT_SESSION_DIR


def _find_hyp_with_finding(finding_id: str) -> dict | None:
    """Search all hypothesis YAMLs for a specific finding ID.

    Searches ALL protocol subdirectories, not just the current protocol,
    so findings from previous components can still be resolved.
    """
    hyp_root = _hunt_session_dir() / "hypotheses"
    if not hyp_root.exists():
        return None
    for hyp_file in hyp_root.rglob("hyp_*.yaml"):
        try:
            content = yaml.safe_load(hyp_file.read_text())
        except yaml.YAMLError:
            # Fallback: grep for the ID
            text = hyp_file.read_text()
            if finding_id in text:
                return {"_file": str(hyp_file), "_raw": True, "_text": text}
            continue
        if not content:
            continue
        for key in ["findings", "invariants", "hypotheses"]:
            for item in content.get(key, []):
                if isinstance(item, dict) and item.get("id") == finding_id:
                    item["_file"] = str(hyp_file)
                    return item
    return None


def _check_poc_uses_fork(solidity_text: str) -> bool:
    """Check if Solidity test code uses mainnet fork (not just mocks)."""
    import re
    # Remove single-line comments
    no_comments = re.sub(r'//.*$', '', solidity_text, flags=re.MULTILINE)
    # Remove multi-line comments
    no_comments = re.sub(r'/\*.*?\*/', '', no_comments, flags=re.DOTALL)
    # Check for fork-related calls (strict — only vm.* fork functions)
    fork_patterns = [
        r'vm\.createFork',
        r'vm\.selectFork',
        r'vm\.createSelectFork',
        r'vm\.activeFork',
    ]
    for pattern in fork_patterns:
        if re.search(pattern, no_comments):
            return True
    return False


def check_finding_poc(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that a PoC exists for this finding."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id} not in any hyp_*.yaml"]

    passed = []
    failed = []

    # Check if hyp has poc field
    poc = hyp.get("poc", "")
    poc_sketch = hyp.get("poc_sketch", "")
    if poc and "PASS" in str(poc).upper():
        passed.append(f"OK: PoC referenced — {poc}")
    elif poc:
        passed.append(f"INFO: PoC field exists — {poc}")
    else:
        failed.append(f"NO_POC: {finding_id} has no 'poc' field in hypothesis YAML")

    # Check for PoC test files
    poc_files = list(WEB3_DIR.rglob(f"*{finding_id}*"))
    poc_files += list(WEB3_DIR.rglob("*PoCFindings*"))
    poc_files += list(WEB3_DIR.rglob("*PoC*Finding*"))
    # Filter to .sol/.t.sol only, exclude build artifacts
    skip_dirs = {"out", "forge-cache", "dependencies", "artifacts", "node_modules"}
    poc_files = [f for f in poc_files if f.is_file() and f.suffix == ".sol" and "lib/" not in str(f) and not any(part in skip_dirs for part in f.parts)]
    if poc_files:
        passed.append(f"OK: PoC files found — {[f.name for f in poc_files[:3]]}")
    elif not poc:
        failed.append(f"NO_POC_FILE: No Solidity PoC file found matching {finding_id}")

    # Also check the PoC file referenced directly in the YAML poc field
    if poc:
        # Extract file paths from poc field — supports "path::func" and embedded paths
        import re as _re
        # Match paths ending in .sol or .t.sol
        _sol_paths = _re.findall(r'([\w/._-]+\.(?:t\.)?sol)', str(poc))
        if "::" in poc:
            _sol_paths.insert(0, poc.split("::")[0])
        for poc_path_str in _sol_paths:
            for base in [WEB3_DIR, WEB3_DIR / "basenames", WEB3_DIR / "wrapped-tokens-os",
                         WEB3_DIR / "commerce-payments", WEB3_DIR / "flywheel"]:
                candidate = base / poc_path_str
                if candidate.is_file() and candidate not in poc_files:
                    poc_files.append(candidate)

    # Check that PoC uses fork (not just mocks)
    state = load_state()
    is_pre_launch = state.get("pre_launch", False)

    if not is_pre_launch:
        fork_found = False
        for f in poc_files:
            text = f.read_text()
            if _check_poc_uses_fork(text):
                fork_found = True
                passed.append(f"OK: PoC uses mainnet fork — {f.name}")
                break
        if not fork_found and poc_files:
            failed.append(
                "NO_FORK_IN_POC: PoC exists but does not use vm.createFork/vm.selectFork\n"
                "  PoCs must run against mainnet fork, not mocks (CLAUDE.md rule)\n"
                '  Add: uint256 forkId = vm.createFork(vm.envString("RPC_URL"), blockNumber);'
            )

    # Check report file for PoC section
    for report in REPORTS_DIR.glob(f"*{finding_id}*"):
        text = report.read_text()
        if "```solidity" in text and ("function test" in text or "function check" in text):
            passed.append(f"OK: PoC code in report — {report.name}")

    ok = len(failed) == 0 and len(passed) > 0
    return ok, passed, failed


def check_finding_escalation(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that EscalationHunter was executed (mandatory for Medium+)."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id}"]

    # Check severity — only mandatory for Medium+
    severity = str(hyp.get("severity", "")).lower()
    if severity in ("info", "informational", "gas", "qa"):
        return True, [f"SKIP: Severity={severity} — EscalationHunter not required for Info/QA"], []

    # Check for escalation fields
    escalation = hyp.get("escalation_verdict") or hyp.get("escalation_analysis") or hyp.get("escalation_done")
    if escalation:
        return True, [f"OK: EscalationHunter executed — verdict: {escalation}"], []

    # Check report for escalation section
    for report in REPORTS_DIR.glob(f"*{finding_id}*"):
        text = report.read_text()
        if "escalat" in text.lower():
            return True, [f"OK: Report mentions escalation analysis — {report.name}"], []

    return False, [], [
        f"NO_ESCALATION: {finding_id} (severity={severity}) — EscalationHunter not executed",
        "  Run: /escalation-hunter with finding details",
        f"  Then update hyp YAML with escalation_verdict field"
    ]


def check_finding_variant(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that variant hunt was executed after this finding."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id}"]

    # Check for variant_hunt field in hyp
    if hyp.get("variant_hunt_done"):
        return True, [f"OK: variant_hunt_done = true in YAML"], []

    # Check HUNT_TRACKER for variant mention
    tracker = WEB3_DIR / "HUNT_TRACKER.md"
    if tracker.exists():
        text = tracker.read_text()
        if "variant" in text.lower() and finding_id in text:
            return True, [f"OK: HUNT_TRACKER mentions variant hunt for {finding_id}"], []

    return False, [], [
        f"NO_VARIANT_HUNT: {finding_id} — variant hunt not executed",
        "  Run: /variant-hunt after confirming this finding",
        f"  Then: pipeline_gate.py --finding {finding_id} --mark variant"
    ]


def check_finding_redteam(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that RedTeam review was executed."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id}"]

    verdict = hyp.get("redteam_verdict", "")
    severity_final = hyp.get("redteam_severity_final", "")
    user_override = hyp.get("user_override", "")

    if verdict:
        details = [f"OK: RedTeam verdict = {verdict}"]
        if severity_final:
            details.append(f"  Severity final: {severity_final}")
        if user_override:
            details.append(f"  User override: {user_override}")
        # Check if verdict allows reporting
        if verdict in ("REPORT", "REPORT_DOWNGRADED") or user_override == "REPORT":
            details.append("  → REPORTABLE")
            return True, details, []
        elif verdict == "DO_NOT_REPORT" and user_override != "REPORT":
            return True, details, [f"WARNING: RedTeam says DO_NOT_REPORT and no user override"]
        return True, details, []

    return False, [], [
        f"NO_REDTEAM: {finding_id} — RedTeam not executed",
        "  Run: /redteam with finding details",
        f"  Then update hyp YAML with redteam_verdict field"
    ]


def check_finding_verify(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that code verification was done (on-chain check)."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id}"]

    # Check for verify fields
    if hyp.get("code_verified") or hyp.get("onchain_verified"):
        return True, [f"OK: code_verified = true"], []

    # Check report for verification section
    for report in REPORTS_DIR.glob(f"*{finding_id}*"):
        text = report.read_text()
        if "verified" in text.lower() or "etherscan" in text.lower() or "basescan" in text.lower():
            return True, [f"OK: Report mentions verification — {report.name}"], []

    # For pre-launch protocols, this is skippable
    state = load_state()
    if state.get("pre_launch"):
        return True, ["SKIP: Pre-launch protocol — on-chain verification N/A"], []

    return False, [], [
        f"NO_VERIFY: {finding_id} — on-chain code verification not done",
        "  Check: contract verified on Etherscan/Basescan",
        "  Check: functions affected exist in deployed version",
        "  Check: no recent fix in repo that mitigates the bug",
        f"  Then: pipeline_gate.py --finding {finding_id} --mark verify"
    ]


def check_finding_report(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that ReportWriter generated a DRAFT markdown."""
    # Search for report files
    for report in REPORTS_DIR.glob(f"*{finding_id}*"):
        text = report.read_text()
        loc = text.count("\n")
        has_severity = "severity" in text.lower() or "## Severity" in text
        has_impact = "impact" in text.lower() or "## Impact" in text
        has_poc = "```solidity" in text
        has_rec = "recommendation" in text.lower() or "## Rec" in text
        sections = sum([has_severity, has_impact, has_poc, has_rec])
        if sections >= 3:
            return True, [f"OK: Report found — {report.name} ({loc} LOC, {sections}/4 sections)"], []
        else:
            return False, [f"INFO: Report exists but incomplete — {report.name}"], [
                f"INCOMPLETE_REPORT: Only {sections}/4 required sections (Severity, Impact, PoC, Recommendation)"
            ]

    return False, [], [
        f"NO_REPORT: No report file matching {finding_id} in reports/",
        "  Run: /report-writer to generate DRAFT markdown",
        f"  Output to: reports/DRAFT-{finding_id}-<slug>.md"
    ]


def check_finding_submit(finding_id: str) -> tuple[bool, list[str], list[str]]:
    """Check that report_finding.py registered in Bounty Radar."""
    hyp = _find_hyp_with_finding(finding_id)
    if not hyp:
        return False, [], [f"FINDING_NOT_FOUND: {finding_id}"]

    if hyp.get("radar_id"):
        return True, [f"OK: Registered in Bounty Radar — radar_id: {hyp['radar_id']}"], []
    if hyp.get("report_file"):
        return False, [f"INFO: report_file = {hyp['report_file']}"], [
            f"NOT_SUBMITTED: {finding_id} has report but not registered in Bounty Radar",
            f"  Run: python3 audit-agents/report_finding.py --finding {finding_id}"
        ]

    return False, [], [
        f"NOT_SUBMITTED: {finding_id} not registered in Bounty Radar",
        f"  Run: python3 audit-agents/report_finding.py --finding {finding_id}"
    ]


FINDING_GATE_CHECKS = {
    "poc": check_finding_poc,
    "escalation": check_finding_escalation,
    "variant": check_finding_variant,
    "redteam": check_finding_redteam,
    "verify": check_finding_verify,
    "report": check_finding_report,
    "submit": check_finding_submit,
}


def export_finding_gate_status(finding_id: str):
    """Run all finding gates and write results to per-protocol gate_status.json."""
    state_data = load_state()
    protocol = state_data.get("protocol", "")
    status = _load_gate_status(protocol)
    hyp = _find_hyp_with_finding(finding_id)

    f_data = {}
    if hyp:
        f_data["title"] = str(hyp.get("title", hyp.get("description", "")))[:60]
        f_data["severity"] = hyp.get("severity", "unknown")
    else:
        f_data["title"] = finding_id
        f_data["severity"] = "unknown"

    first_fail = None
    passed_count = 0

    for g in DISPLAY_FINDING_GATES:
        if g not in FINDING_GATE_CHECKS:
            f_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        ok, passed, failed = FINDING_GATE_CHECKS[g](finding_id)
        detail = passed[0] if passed else (failed[0] if failed else "")
        state = _map_gate_state(ok, detail)
        f_data[g] = {"state": state, "detail": detail}
        if state in ("pass", "skip"):
            passed_count += 1
        elif first_fail is None:
            first_fail = g

    f_data["progress"] = f"{passed_count}/{len(DISPLAY_FINDING_GATES)}"
    f_data["blocked_at"] = first_fail

    status["finding_gates"][finding_id] = f_data
    _save_gate_status(status, protocol)
