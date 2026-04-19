#!/usr/bin/env python3
"""
pipeline_gate.py — Deterministic pipeline enforcer for the hunt system.

Checks that ALL required steps are completed before allowing progression.
Returns exit code 0 if gate passes, 1 if blocked.

Usage:
    python3 pipeline_gate.py --component <name> --gate <gate_name> [--repo <path>] [--fix]
    python3 pipeline_gate.py --component <name> --status          # Show full pipeline status
    python3 pipeline_gate.py --component <name> --gate all        # Check ALL gates

Component gates (in order):
    hunters     — All 9 hunters generated hypothesis YAMLs with solidity fields
    crosschain  — CrossChainHunter analyzed multi-chain deployments (or skip if single-chain)
    deepdive    — DeepDiveHunter ran after the 9 hunters
    merge       — merge_invariants.py ran, Properties.sol exists
    compile     — forge build passes
    phase1      — Foundry fuzz min 5K runs (evidence file exists)
    phase2      — Medusa fuzz min 15 min (corpus directory exists)
    phase3      — Fork test executed (for bounties >= $2K or broken invariant)
    phase4      — Echidna optimization (if optimize_* functions exist)
    phase5      — Halmos symbolic proof (if pure math functions exist)
    complete    — Component fully done, ready for next

Finding gates (after a bug is found):
    python3 pipeline_gate.py --finding <ID> --status
    python3 pipeline_gate.py --finding <ID> --fgate <gate_name>
    python3 pipeline_gate.py --finding <ID> --mark <gate_name>

    poc         — PoC exists and PASSES (Foundry fork test)
    escalation  — EscalationHunter executed (mandatory for Medium+)
    variant     — Variant hunt executed across full scope
    redteam     — RedTeam 4-attacker review with Round 0 calibration
    verify      — Code verified on-chain (deployed, not fixed, feature active)
    report      — ReportWriter generated DRAFT markdown
    submit      — report_finding.py registered in Bounty Radar
    reportable  — ALL finding gates passed, ready for platform submission

Each gate checks ALL previous gates too (cumulative).

Scope master operations:
    python3 pipeline_gate.py --scope-status                    # Show SCOPE_MASTER summary
    python3 pipeline_gate.py --scope-review -c <component>     # Mark component as re-reviewed

Auto-updates SCOPE_MASTER.md when:
    - Component passes 'complete' gate → state=DONE + review date added
    - Finding is queued → finding count updated in component entry
    - --scope-review is called → adds today's date without changing state
"""

import argparse
import json
import sys
import os
from pathlib import Path
from datetime import datetime

import yaml

# ─── Paths ───────────────────────────────────────────────────────────────────

from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
from state_manager import load_state, save_state as _sm_save_state
from gate.constants import *  # noqa: F401,F403
from gate.ficha import *  # noqa: F401,F403
from gate.scope_master import *  # noqa: F401,F403
from gate.gates_component import *  # noqa: F401,F403
from gate.gate_status import *  # noqa: F401,F403
from gate.gates_finding import *  # noqa: F401,F403
from gate.finding_queue import *  # noqa: F401,F403
import gate.gates_component as _gates_component  # module handle for CLI overrides

# ─── State helpers ───────────────────────────────────────────────────────────
# load_ficha / update_ficha: extracted to gate/ficha.py (re-exported above).
# Component gate checks + GATE_CHECKS + DISPLAY_GATES + path helpers +
# _PROTOCOL_OVERRIDE / _get_protocol: extracted to gate/gates_component.py.


# ─── Gate Status JSON Export ──────────────────────────────────────────────────
# _map_gate_state / _load_gate_status / _save_gate_status / export_gate_status:
# extracted to gate/gate_status.py (re-exported via wildcard import above).
# Finding-stage gate checks (check_finding_*, FINDING_GATE_CHECKS,
# FINDING_GATE_ORDER, DISPLAY_FINDING_GATES, REPORTS_DIR, RESULTS_DIR,
# _find_hyp_with_finding, _check_poc_uses_fork, export_finding_gate_status):
# extracted to gate/gates_finding.py (re-exported via wildcard import above).


def run_gate(component: str, gate: str, repo: str = "") -> bool:
    """Run a specific gate check (cumulative — also checks all previous gates)."""
    if gate == "complete":
        # Must pass ALL gates
        gates_to_check = GATE_ORDER[:-1]
    elif gate == "all":
        gates_to_check = GATE_ORDER[:-1]
    else:
        idx = GATE_ORDER.index(gate)
        gates_to_check = GATE_ORDER[:idx + 1]

    all_passed = True
    for g in gates_to_check:
        if g not in GATE_CHECKS:
            continue
        ok, passed, failed = GATE_CHECKS[g](component, repo)
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"\n{'='*60}")
        print(f"  GATE: {g.upper()} — {status}")
        print(f"{'='*60}")
        for p in passed:
            print(f"  {p}")
        for f in failed:
            print(f"  ⛔ {f}")
        if not ok:
            all_passed = False

    # Auto-export to gate_status.json
    export_gate_status(component, repo)

    # Auto-update SCOPE_MASTER when component completes
    if all_passed and gate in ("complete", "all"):
        state_data = load_state()
        protocol = state_data.get("protocol", "")
        if protocol:
            scope_master_on_complete(protocol, component)

    return all_passed


def show_status(component: str, repo: str = ""):
    """Show full pipeline status for a component."""
    print(f"\n{'#'*60}")
    print(f"  PIPELINE STATUS: {component}")
    print(f"{'#'*60}")

    results = {}
    for g in GATE_ORDER[:-1]:
        if g not in GATE_CHECKS:
            results[g] = (True, ["N/A"], [])
            continue
        results[g] = GATE_CHECKS[g](component, repo)

    # Summary table
    print(f"\n  {'Gate':<12} {'Status':<8} {'Details'}")
    print(f"  {'-'*12} {'-'*8} {'-'*40}")
    for g in GATE_ORDER[:-1]:
        ok, passed, failed = results[g]
        status = "✅ PASS" if ok else "❌ FAIL"
        detail = passed[0] if passed else (failed[0] if failed else "")
        # Truncate detail
        if len(detail) > 50:
            detail = detail[:47] + "..."
        print(f"  {g:<12} {status:<8} {detail}")

    # Count
    total = len(GATE_ORDER) - 1
    passed_count = sum(1 for g in GATE_ORDER[:-1] if results.get(g, (False,))[0])
    print(f"\n  Progress: {passed_count}/{total} gates passed")

    if passed_count == total:
        print(f"\n  🎯 COMPONENT {component} IS COMPLETE — ready for next component")
    else:
        first_fail = next((g for g in GATE_ORDER[:-1] if not results.get(g, (True,))[0]), None)
        print(f"\n  ⛔ BLOCKED at gate: {first_fail}")
        print(f"  Next action: fix {first_fail} gate before proceeding")

    # Auto-export to gate_status.json
    export_gate_status(component, repo)
    return passed_count == total


def mark_gate(component: str, gate: str, protocol: str = ""):
    """Manually mark a gate as passed in the ficha (for evidence that can't be auto-detected)."""
    gate_to_field = {
        "phase1": "fuzzing_phase1_executed",
        "phase2": "fuzzing_phase2_executed",
        "phase3": "fork_test_executed",
        "phase4": "echidna_executed",
        "phase5": "halmos_executed",
        "compile": "compile_check",
        "merge": "invariants_added_to_properties",
        "deepdive": "deepdive_hunter",
    }
    field = gate_to_field.get(gate)
    if not field:
        print(f"Cannot mark gate '{gate}' — not a markable gate")
        return
    update_ficha(component, {"checklist": {field: True}}, protocol)
    print(f"✅ Marked {gate} as passed for {component}")


# ─── Finding Pipeline Gates ──────────────────────────────────────────────────
# check_finding_* / FINDING_GATE_CHECKS / FINDING_GATE_ORDER /
# DISPLAY_FINDING_GATES / REPORTS_DIR / RESULTS_DIR / _find_hyp_with_finding /
# _check_poc_uses_fork / export_finding_gate_status: extracted to
# gate/gates_finding.py (re-exported via wildcard import above).


def run_finding_gate(finding_id: str, gate: str) -> bool:
    """Run finding pipeline gate (cumulative)."""
    if gate == "reportable" or gate == "all":
        gates_to_check = FINDING_GATE_ORDER[:-1]
    else:
        idx = FINDING_GATE_ORDER.index(gate)
        gates_to_check = FINDING_GATE_ORDER[:idx + 1]

    all_passed = True
    for g in gates_to_check:
        if g not in FINDING_GATE_CHECKS:
            continue
        ok, passed, failed = FINDING_GATE_CHECKS[g](finding_id)
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"\n{'='*60}")
        print(f"  FINDING GATE: {g.upper()} — {status}")
        print(f"{'='*60}")
        for p in passed:
            print(f"  {p}")
        for f in failed:
            print(f"  ⛔ {f}")
        if not ok:
            all_passed = False

    # Auto-export to gate_status.json
    export_finding_gate_status(finding_id)
    return all_passed


def show_finding_status(finding_id: str):
    """Show full finding pipeline status."""
    print(f"\n{'#'*60}")
    print(f"  FINDING PIPELINE: {finding_id}")
    print(f"{'#'*60}")

    # Show finding info
    hyp = _find_hyp_with_finding(finding_id)
    if hyp:
        print(f"\n  Source: {hyp.get('_file', 'unknown')}")
        print(f"  Title: {hyp.get('title', hyp.get('description', 'N/A'))[:60]}")
        print(f"  Severity: {hyp.get('severity', 'N/A')}")
        print(f"  Confidence: {hyp.get('confidence', 'N/A')}%")
        print(f"  RedTeam: {hyp.get('redteam_verdict', 'NOT_RUN')}")
        if hyp.get("user_override"):
            print(f"  User Override: {hyp['user_override']}")

    results = {}
    for g in FINDING_GATE_ORDER[:-1]:
        if g not in FINDING_GATE_CHECKS:
            results[g] = (True, ["N/A"], [])
            continue
        results[g] = FINDING_GATE_CHECKS[g](finding_id)

    print(f"\n  {'Gate':<12} {'Status':<8} {'Details'}")
    print(f"  {'-'*12} {'-'*8} {'-'*40}")
    for g in FINDING_GATE_ORDER[:-1]:
        ok, passed, failed = results[g]
        status = "✅ PASS" if ok else "❌ FAIL"
        detail = passed[0] if passed else (failed[0] if failed else "")
        if len(detail) > 50:
            detail = detail[:47] + "..."
        print(f"  {g:<12} {status:<8} {detail}")

    total = len(FINDING_GATE_ORDER) - 1
    passed_count = sum(1 for g in FINDING_GATE_ORDER[:-1] if results.get(g, (False,))[0])
    print(f"\n  Progress: {passed_count}/{total} gates passed")

    if passed_count == total:
        print(f"\n  🎯 FINDING {finding_id} IS REPORTABLE — all gates passed")
    else:
        first_fail = next((g for g in FINDING_GATE_ORDER[:-1] if not results.get(g, (True,))[0]), None)
        print(f"\n  ⛔ BLOCKED at gate: {first_fail}")
        print(f"  DO NOT submit this finding until all gates pass.")

    # Auto-export to gate_status.json
    export_finding_gate_status(finding_id)
    return passed_count == total


def mark_finding_gate(finding_id: str, gate: str):
    """Mark a finding gate as passed by updating the hypothesis YAML."""
    gate_to_field = {
        "poc": "poc",
        "escalation": "escalation_verdict",
        "variant": "variant_hunt_done",
        "redteam": "redteam_verdict",
        "verify": "code_verified",
        "report": "report_file",
        "submit": "radar_id",
    }
    field = gate_to_field.get(gate)
    if not field:
        print(f"Cannot mark finding gate '{gate}'")
        return

    # Find the hyp file
    state = load_state()
    protocol = state.get("protocol", "")
    hyp_dir = get_hyp_dir(protocol)
    for hyp_file in hyp_dir.glob("hyp_*.yaml"):
        try:
            content = yaml.safe_load(hyp_file.read_text())
        except yaml.YAMLError:
            continue
        if not content:
            continue
        for key in ["findings", "invariants", "hypotheses"]:
            items = content.get(key, [])
            for i, item in enumerate(items):
                if isinstance(item, dict) and item.get("id") == finding_id:
                    if gate == "escalation":
                        items[i]["escalation_verdict"] = "ANALYZED"
                    elif gate == "variant":
                        items[i]["variant_hunt_done"] = True
                    elif gate == "verify":
                        items[i]["code_verified"] = True
                    else:
                        print(f"Gate '{gate}' requires specific value — update YAML manually")
                        return
                    with open(hyp_file, "w") as f:
                        yaml.dump(content, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
                    print(f"✅ Marked finding gate '{gate}' as passed for {finding_id} in {hyp_file.name}")
                    return
    print(f"⛔ Finding {finding_id} not found in any hyp_*.yaml")


# ─── Finding Queue ───────────────────────────────────────────────────────────
# _save_state / generate_queue_id / queue_finding / list_queue / queue_update /
# queue_promote: extracted to gate/finding_queue.py (re-exported via wildcard).


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Pipeline gate enforcer — component & finding pipelines")
    parser.add_argument("--component", "-c", help="Component name (for component pipeline)")
    parser.add_argument("--finding", "-f", help="Finding ID (for finding pipeline, e.g. PL-M-01)")
    parser.add_argument("--gate", "-g", help="Component gate (hunters|deepdive|merge|compile|phase1|phase2|phase3|complete|all)")
    parser.add_argument("--fgate", help="Finding gate (poc|variant|redteam|verify|report|submit|reportable|all)")
    parser.add_argument("--status", "-s", action="store_true", help="Show full pipeline status")
    parser.add_argument("--repo", "-r", default="", help="Repository path")
    parser.add_argument("--mark", "-m", help="Mark a gate as manually passed")
    parser.add_argument("--protocol", "-p", default="", help="Protocol name for ficha lookup")
    parser.add_argument("--export-json", action="store_true", help="Run all gates and export to gate_status.json")
    # Queue operations
    parser.add_argument("--queue-finding", action="store_true", help="Add finding to queue")
    parser.add_argument("--list-queue", action="store_true", help="List finding queue")
    parser.add_argument("--queue-update", help="Update queue item (provide finding ID)")
    parser.add_argument("--queue-promote", help="Promote queue item to findings")
    parser.add_argument("--source", help="Finding source (variant|cross-component|hunter_spillover)")
    parser.add_argument("--parent", help="Parent finding ID for variants")
    parser.add_argument("--title", help="Finding title")
    parser.add_argument("--severity", help="Severity estimate")
    parser.add_argument("--notes", help="Additional notes")
    parser.add_argument("--qstatus", help="New status for queue-update")
    parser.add_argument("--components", help="Components for cross-component (comma-separated)")
    parser.add_argument("--hunter", help="Hunter name for spillover")
    # Scope master operations
    parser.add_argument("--scope-status", action="store_true", help="Show SCOPE_MASTER summary for current program")
    parser.add_argument("--scope-review", action="store_true", help="Mark component as re-reviewed (adds today's date)")
    parser.add_argument("--program", help="Program name for SCOPE_MASTER lookup (e.g. coinbase, hyperlane)")
    parser.add_argument("--session-dir", help=(
        "Override HUNT_SESSION_DIR (used by run_benchmark.py to isolate benchmark outputs)"
    ))
    parser.add_argument("--force", default="",
                        help="Reset the named gate's status so it re-runs. "
                             "Accepts gate names like 'scope', 'prepass', 'hunters', 'merge'. "
                             "Can be used once per invocation.")
    args = parser.parse_args()

    # ── Session dir override (benchmark isolation) ──
    if args.session_dir:
        global HUNT_SESSION_DIR, SCOPE_MASTER_DIR
        HUNT_SESSION_DIR = Path(args.session_dir).resolve()
        SCOPE_MASTER_DIR = HUNT_SESSION_DIR / "context"
        # gate.gates_component looks up HUNT_SESSION_DIR late-bound via
        # sys.modules["pipeline_gate"], so reassigning the shim binding is
        # enough — helpers there see the fresh value without explicit sync.

    # ── Protocol override (benchmark mode — current_hunt.json may have wrong protocol) ──
    if args.protocol:
        _gates_component._PROTOCOL_OVERRIDE = args.protocol

    if args.force:
        gate = args.force
        protocol = args.protocol or _gates_component._PROTOCOL_OVERRIDE
        status_path = get_gate_status_file(protocol) if protocol else None
        if status_path and status_path.exists():
            data = json.loads(status_path.read_text())
            comp_gates = data.get("component_gates", {})
            for comp in list(comp_gates.keys()):
                comp_gates[comp].pop(gate, None)
            status_path.write_text(json.dumps(data, indent=2))
            print(f"[force] reset gate '{gate}' for all components", file=sys.stderr)
        else:
            print(f"[force] no gate_status file to reset (session fresh)", file=sys.stderr)
        sys.exit(0)

    # ── Scope master operations ──
    if args.scope_status:
        if args.program:
            # Override protocol with program name for SCOPE_MASTER lookup
            _orig_load = load_state
            def _patched_load():
                s = _orig_load()
                s["protocol"] = args.program
                return s
            import types
            globals()["load_state"] = _patched_load
        show_scope_status()
        sys.exit(0)

    if args.scope_review:
        if not args.component:
            parser.error("--scope-review requires --component")
        program = args.program or ""
        if not program:
            state_data = load_state()
            program = state_data.get("protocol", "")
        if program:
            scope_master_on_review(program, args.component)
        else:
            print("⛔ No program specified. Use --program <name>")
        sys.exit(0)

    # ── Queue operations ──
    if args.list_queue:
        list_queue()
        sys.exit(0)

    if args.queue_finding:
        comps = args.components.split(",") if args.components else None
        queue_finding(
            source=args.source or "variant",
            parent_id=args.parent,
            title=args.title or "",
            component=args.component or "",
            severity=args.severity or "",
            notes=args.notes or "",
            components=comps,
            hunter=args.hunter or "",
        )
        sys.exit(0)

    if args.queue_update:
        queue_update(args.queue_update, args.qstatus or "in_pipeline", args.notes or "")
        sys.exit(0)

    if args.queue_promote:
        queue_promote(args.queue_promote)
        sys.exit(0)

    # ── Finding pipeline ──
    if args.finding:
        if args.mark:
            mark_finding_gate(args.finding, args.mark)
            sys.exit(0)
        if args.fgate:
            ok = run_finding_gate(args.finding, args.fgate)
            if ok:
                print(f"\n✅ Finding gate '{args.fgate}' PASSED for {args.finding}")
            else:
                print(f"\n⛔ Finding gate '{args.fgate}' FAILED for {args.finding}")
            sys.exit(0 if ok else 1)
        # Default: show finding status
        ok = show_finding_status(args.finding)
        sys.exit(0 if ok else 1)

    # ── Component pipeline ──
    if not args.component:
        parser.error("Either --component or --finding is required")

    if args.mark:
        mark_gate(args.component, args.mark, args.protocol)
        sys.exit(0)

    if args.export_json:
        export_gate_status(args.component, args.repo)
        state = load_state()
        protocol = state.get("protocol", "")
        print(f"Exported gate status for {args.component} to {get_gate_status_file(protocol)}")
        sys.exit(0)

    if args.status:
        ok = show_status(args.component, args.repo)
        sys.exit(0 if ok else 1)

    if args.gate:
        ok = run_gate(args.component, args.gate, args.repo)
        if ok:
            print(f"\n✅ Gate '{args.gate}' PASSED for {args.component}")
        else:
            print(f"\n⛔ Gate '{args.gate}' FAILED for {args.component} — fix issues above before proceeding")
        sys.exit(0 if ok else 1)

    # Default: show status
    ok = show_status(args.component, args.repo)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
