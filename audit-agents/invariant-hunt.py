#!/usr/bin/env python3
"""
invariant-hunt — Automated invariant-based bug hunting for Web3 bounties.

Usage:
    python invariant-hunt.py --source ./target/ --budget 2h
    python invariant-hunt.py --source ./target/ --match-only
    python invariant-hunt.py --source ./target/ --focus vault,lending --budget 1h
    python invariant-hunt.py --source ./target/ --novel-protocol --budget 2h
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# Add audit-agents to path
sys.path.insert(0, str(Path(__file__).parent))

from registry import get_registry
from matcher import MatcherPipeline


def parse_budget(budget_str: str) -> int:
    """Parse time budget string like '2h', '90m', '120' into minutes."""
    budget_str = budget_str.strip().lower()
    if budget_str.endswith("h"):
        return int(float(budget_str[:-1]) * 60)
    elif budget_str.endswith("m"):
        return int(budget_str[:-1])
    else:
        return int(budget_str)


def cmd_match(args):
    """Run matching pipeline and print results."""
    pipeline = MatcherPipeline()

    focus = args.focus.split(",") if args.focus else None
    budget = parse_budget(args.budget) if args.budget else 120

    print(f"Target: {args.source}")
    print(f"Budget: {budget} minutes")
    if focus:
        print(f"Focus: {', '.join(focus)}")
    print()

    results = pipeline.match(
        source_dir=args.source,
        focus_categories=focus,
        max_payout=args.payout,
        time_budget_minutes=budget,
        novel_protocol=args.novel_protocol,
    )

    pipeline.print_report(results, args.payout)

    if args.match_only:
        return

    # Generate invariant test suggestions
    if results:
        print("\n\n=== SUGGESTED TEST ORDER ===\n")
        print("Round 1 (Tier S — first 30 min):")
        for i, r in enumerate(results[:5]):
            print(f"  {i+1}. {r.invariant.id} — {r.invariant.title}")
            print(f"     Solidity: {r.invariant.invariant_solidity[:100]}...")

        if len(results) > 5:
            print(f"\nRound 2 (Tier A — next 30 min):")
            for i, r in enumerate(results[5:15], 6):
                print(f"  {i}. {r.invariant.id} — {r.invariant.title}")

        if len(results) > 15:
            print(f"\nRound 3 (Tier B — remaining):")
            for i, r in enumerate(results[15:], 16):
                print(f"  {i}. {r.invariant.id} — {r.invariant.title}")

        # Export to JSON for harness generation
        export_path = Path(args.source) / "matched_invariants.json"
        export_data = []
        for r in results:
            export_data.append({
                "id": r.invariant.id,
                "title": r.invariant.title,
                "category": r.invariant.category,
                "severity": r.invariant.severity,
                "confidence": r.confidence,
                "priority": r.invariant.priority_score(r.confidence, args.payout),
                "invariant_solidity": r.invariant.invariant_solidity,
                "invariant_natural": r.invariant.invariant_natural,
                "setup_requirements": r.invariant.setup_requirements,
                "estimated_minutes": r.invariant.estimated_test_minutes,
                "composition_with": r.invariant.composition_with,
            })

        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"\nExported {len(export_data)} invariants to {export_path}")


def cmd_stats(args):
    """Print registry statistics."""
    reg = get_registry()
    stats = reg.stats()
    print(f"=== Invariant Registry Stats ===")
    print(f"Total: {stats['total']} invariants")
    print(f"\nBy severity:")
    for sev in ["critical", "high", "medium", "low"]:
        count = stats["by_severity"].get(sev, 0)
        if count:
            print(f"  {sev}: {count}")
    print(f"\nBy top-level category:")
    top_cats = {}
    for cat, count in stats["by_category"].items():
        top = cat.split("/")[0]
        if top == cat:  # Only top-level
            top_cats[top] = count
    for cat, count in sorted(top_cats.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    print(f"\nReferences:")
    print(f"  With positive reference: {stats['with_positive_ref']}")
    print(f"  With negative reference: {stats['with_negative_ref']}")
    print(f"  Found real bugs: {stats['with_real_bugs']}")


def cmd_search(args):
    """Search invariants by query string."""
    reg = get_registry()
    results = reg.search(args.query)
    print(f"Found {len(results)} invariants matching '{args.query}':\n")
    for inv in results[:30]:
        print(f"  [{inv.severity:8s}] {inv.id:16s} | {inv.title}")
        print(f"             {inv.category} | {', '.join(inv.tags[:5])}")


def main():
    parser = argparse.ArgumentParser(
        description="Invariant-based bug hunting for Web3 bounties"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Match command
    match_parser = subparsers.add_parser("match", help="Match invariants against target")
    match_parser.add_argument("--source", required=True, help="Path to target source")
    match_parser.add_argument("--focus", help="Comma-separated category focus")
    match_parser.add_argument("--budget", default="2h", help="Time budget (e.g. 2h, 90m)")
    match_parser.add_argument("--payout", type=int, default=100000, help="Max bounty payout")
    match_parser.add_argument("--match-only", action="store_true", help="Only match, no test suggestions")
    match_parser.add_argument("--novel-protocol", action="store_true", help="Use universal invariants only")
    match_parser.set_defaults(func=cmd_match)

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show registry statistics")
    stats_parser.set_defaults(func=cmd_stats)

    # Search command
    search_parser = subparsers.add_parser("search", help="Search invariants")
    search_parser.add_argument("query", help="Search query")
    search_parser.set_defaults(func=cmd_search)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
