#!/usr/bin/env python3
"""
results_tracker.py — Track fuzzing campaign results and update invariant hit rates.

Closes the feedback loop: campaign results → update invariant historical_hit_rate
and false_positive_rate in the registry.

Usage:
    python results_tracker.py log --campaign "chainlink-pav2-01" --target "chainlink-pa-v2" \
        --invariant INV-V4626-001 --result violation --confirmed true
    python results_tracker.py log --campaign "chainlink-pav2-01" --target "chainlink-pa-v2" \
        --invariant INV-V4626-003 --result pass
    python results_tracker.py log --campaign "chainlink-pav2-01" --target "chainlink-pa-v2" \
        --invariant INV-LEND-004 --result violation --confirmed false --fp-reason "harness setup issue"
    python results_tracker.py update-rates
    python results_tracker.py report
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

REGISTRY_DIR = Path(__file__).parent.parent / "invariant-registry"
RESULTS_FILE = REGISTRY_DIR / "results" / "campaigns.json"


def load_results() -> list[dict]:
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_results(results: list[dict]):
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def cmd_log(args):
    """Log a single invariant test result."""
    results = load_results()

    entry = {
        "timestamp": datetime.now().isoformat(),
        "campaign": args.campaign,
        "target": args.target,
        "invariant_id": args.invariant,
        "result": args.result,  # "pass", "violation", "compile_fail", "timeout"
        "confirmed_real": args.confirmed if args.result == "violation" else None,
        "false_positive_reason": args.fp_reason if hasattr(args, "fp_reason") else None,
        "payout": args.payout if hasattr(args, "payout") else None,
        "notes": args.notes if hasattr(args, "notes") else None,
    }

    results.append(entry)
    save_results(results)
    print(f"Logged: {args.invariant} -> {args.result} (campaign: {args.campaign})")


def cmd_update_rates(args):
    """Update historical_hit_rate and false_positive_rate in registry JSON files."""
    results = load_results()

    if not results:
        print("No results to process.")
        return

    # Aggregate by invariant
    stats: dict[str, dict] = {}
    for r in results:
        inv_id = r["invariant_id"]
        if inv_id not in stats:
            stats[inv_id] = {"tested": 0, "violations": 0, "confirmed": 0, "false_positives": 0}

        stats[inv_id]["tested"] += 1
        if r["result"] == "violation":
            stats[inv_id]["violations"] += 1
            if r.get("confirmed_real"):
                stats[inv_id]["confirmed"] += 1
            else:
                stats[inv_id]["false_positives"] += 1

    # Update registry files
    updated = 0
    for json_file in REGISTRY_DIR.rglob("*.json"):
        if json_file.name == "schema.json" or "results" in str(json_file):
            continue

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                continue

            changed = False
            for entry in data:
                inv_id = entry.get("id", "")
                if inv_id in stats:
                    s = stats[inv_id]
                    if s["tested"] > 0:
                        entry["historical_hit_rate"] = s["confirmed"] / s["tested"]
                        if s["violations"] > 0:
                            entry["false_positive_rate"] = s["false_positives"] / s["violations"]
                        changed = True
                        updated += 1

            if changed:
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)

        except (json.JSONDecodeError, KeyError):
            continue

    print(f"Updated rates for {updated} invariants across registry files.")


def cmd_report(args):
    """Print a summary report of all campaign results."""
    results = load_results()

    if not results:
        print("No results recorded yet.")
        return

    # Group by campaign
    campaigns: dict[str, list] = {}
    for r in results:
        campaigns.setdefault(r["campaign"], []).append(r)

    print(f"\n{'='*70}")
    print(f"CAMPAIGN RESULTS SUMMARY")
    print(f"{'='*70}")

    total_tested = 0
    total_violations = 0
    total_confirmed = 0
    total_payouts = 0

    for campaign, entries in sorted(campaigns.items()):
        tested = len(entries)
        violations = sum(1 for e in entries if e["result"] == "violation")
        confirmed = sum(1 for e in entries if e.get("confirmed_real"))
        fp = sum(1 for e in entries if e["result"] == "violation" and not e.get("confirmed_real"))
        payouts = sum(e.get("payout", 0) or 0 for e in entries)

        total_tested += tested
        total_violations += violations
        total_confirmed += confirmed
        total_payouts += payouts

        print(f"\n--- {campaign} ({entries[0].get('target', '?')}) ---")
        print(f"  Tested: {tested} | Violations: {violations} | Confirmed: {confirmed} | FP: {fp}")
        if payouts > 0:
            print(f"  Payouts: ${payouts:,}")

        for e in entries:
            if e["result"] == "violation":
                status = "CONFIRMED" if e.get("confirmed_real") else "FALSE POSITIVE"
                print(f"    {e['invariant_id']}: {status}")
                if e.get("false_positive_reason"):
                    print(f"      Reason: {e['false_positive_reason']}")

    print(f"\n{'='*70}")
    print(f"TOTALS: {total_tested} tested | {total_violations} violations | {total_confirmed} confirmed | ${total_payouts:,} payouts")
    if total_tested > 0:
        print(f"Hit rate: {total_confirmed/total_tested:.1%}")
    if total_violations > 0:
        fp_rate = (total_violations - total_confirmed) / total_violations
        print(f"False positive rate: {fp_rate:.1%}")


def main():
    parser = argparse.ArgumentParser(description="Track invariant testing results")
    subparsers = parser.add_subparsers(dest="command")

    # Log command
    log_parser = subparsers.add_parser("log", help="Log a test result")
    log_parser.add_argument("--campaign", required=True)
    log_parser.add_argument("--target", required=True)
    log_parser.add_argument("--invariant", required=True)
    log_parser.add_argument("--result", required=True, choices=["pass", "violation", "compile_fail", "timeout"])
    log_parser.add_argument("--confirmed", type=lambda x: x.lower() == "true", default=None)
    log_parser.add_argument("--fp-reason", default=None)
    log_parser.add_argument("--payout", type=int, default=None)
    log_parser.add_argument("--notes", default=None)
    log_parser.set_defaults(func=cmd_log)

    # Update rates command
    update_parser = subparsers.add_parser("update-rates", help="Update hit rates from results")
    update_parser.set_defaults(func=cmd_update_rates)

    # Report command
    report_parser = subparsers.add_parser("report", help="Show results summary")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
