#!/usr/bin/env python3
"""
verify_team_outputs.py — Post-team gate: verify all groups produced expected outputs.

Usage:
    python3 audit-agents/verify_team_outputs.py \
        --session-dir /path/to/bench_session \
        --protocol yieldoor \
        --groups '[ {"group_id": 0, "components": ["Strategy", "Vault"]} ]'

Exit code 0 = all checks pass. Non-zero = failures found.
"""

import argparse
import json
import sys
from pathlib import Path


def verify_group(session_dir: Path, protocol: str, group: dict) -> list[str]:
    """Verify a single group's outputs. Returns list of failure messages."""
    failures = []
    group_id = group["group_id"]
    components = group["components"]

    for comp in components:
        # 1. Check hypothesis files exist
        hyp_dir = session_dir / "hypotheses" / protocol
        hyp_files = list(hyp_dir.glob(f"hyp_{comp}_*.yaml"))
        if not hyp_files:
            failures.append(
                f"Group {group_id}/{comp}: No hypothesis YAML files "
                f"in {hyp_dir}/hyp_{comp}_*.yaml"
            )

        # 2. Check prepass ran
        prepass = session_dir / "results" / f"{comp}_prepass.yaml"
        if not prepass.exists():
            failures.append(
                f"Group {group_id}/{comp}: Missing prepass at {prepass}"
            )

        # 3. Check checkpoint exists for the sub-plan
        plan_file = group.get("plan_file", "")
        if plan_file:
            # Try group-specific checkpoint first, then generic
            ckpt_group = Path(plan_file).parent / f"checkpoint_group_{group_id}.json"
            ckpt_generic = Path(plan_file).parent / "checkpoint.json"
            ckpt = ckpt_group if ckpt_group.exists() else ckpt_generic
            if ckpt.exists():
                with open(ckpt) as f:
                    ckpt_data = json.load(f)
                completed = len(ckpt_data.get("completed_steps", []))
                failed = ckpt_data.get("failed_steps", {})
                if failed:
                    for step_id, info in failed.items():
                        failures.append(
                            f"Group {group_id}: Step {step_id} failed: "
                            f"{info.get('error', 'unknown')}"
                        )
            else:
                failures.append(
                    f"Group {group_id}: No checkpoint.json at {ckpt}"
                )

    return failures


def main():
    parser = argparse.ArgumentParser(
        description="Verify team agent outputs before cross-component phase"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--groups", required=True,
                        help="JSON array of group objects")
    args = parser.parse_args()

    session_dir = Path(args.session_dir)
    groups = json.loads(args.groups)

    all_failures = []
    for group in groups:
        all_failures.extend(
            verify_group(session_dir, args.protocol, group)
        )

    if all_failures:
        print("VERIFICATION FAILED", file=sys.stderr)
        for f in all_failures:
            print(f"  ❌ {f}", file=sys.stderr)
        print(f"\n{len(all_failures)} issue(s) found. "
              "Fix before proceeding to cross-component.", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"✅ All groups verified. "
              f"{len(groups)} groups, "
              f"{sum(len(g['components']) for g in groups)} components OK.")
        sys.exit(0)


if __name__ == "__main__":
    main()
