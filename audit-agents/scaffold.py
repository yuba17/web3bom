#!/usr/bin/env python3
"""
scaffold.py — Contest Quickstart: generates a complete invariant testing project.

Takes a target protocol and generates:
1. Foundry project structure
2. Matched invariants from registry
3. Skeleton harness adapted to target
4. Fuzzer configs (Foundry, Echidna, Medusa)
5. Run scripts

Usage:
    python scaffold.py --source ./target-protocol/ --name "protocol-name" --type vault
    python scaffold.py --source ./target-protocol/ --name "protocol-name" --type lending
    python scaffold.py --source ./target-protocol/ --name "protocol-name" --auto
"""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from registry import get_registry
from matcher import MatcherPipeline

SKELETONS_DIR = Path(__file__).parent / "harness" / "skeletons"
CONFIGS_DIR = Path(__file__).parent.parent / "BugBounty-Vault" / "04-Tools" / "pipeline" / "configs"

PROTOCOL_TYPES = {
    "vault": "erc4626_vault.sol",
    "lending": "lending_pool.sol",
    "dex": "amm_dex.sol",
    "staking": "staking_rewards.sol",
}


def detect_protocol_type(source_dir: str) -> str:
    """Auto-detect protocol type from source code patterns."""
    source_path = Path(source_dir)
    combined = ""
    for sol_file in source_path.rglob("*.sol"):
        if any(skip in str(sol_file).lower() for skip in ["test", "lib", "node_modules", "mock"]):
            continue
        try:
            combined += sol_file.read_text(encoding="utf-8") + "\n"
        except UnicodeDecodeError:
            continue

    combined_lower = combined.lower()

    # Score each type
    scores = {
        "vault": 0,
        "lending": 0,
        "dex": 0,
        "staking": 0,
    }

    # Vault indicators
    vault_keywords = ["erc4626", "totalassets", "converttoshares", "converttoassets", "redeem", "vault", "shares"]
    for kw in vault_keywords:
        if kw in combined_lower:
            scores["vault"] += 1

    # Lending indicators
    lending_keywords = ["borrow", "repay", "liquidat", "collateral", "healthfactor", "interestrate", "debtof", "loanmanager"]
    for kw in lending_keywords:
        if kw in combined_lower:
            scores["lending"] += 1

    # DEX indicators
    dex_keywords = ["swap", "addliquidity", "removeliquidity", "reserve0", "reserve1", "getamountout", "pair", "amm", "router"]
    for kw in dex_keywords:
        if kw in combined_lower:
            scores["dex"] += 1

    # Staking indicators
    staking_keywords = ["stake", "unstake", "rewardpertoken", "earned", "getreward", "notifyrewardamount", "rewardduration", "staking"]
    for kw in staking_keywords:
        if kw in combined_lower:
            scores["staking"] += 1

    best = max(scores, key=scores.get)
    if scores[best] >= 3:
        return best
    return "vault"  # Default fallback


def scaffold_project(source_dir: str, name: str, protocol_type: str, output_dir: str = None, budget: int = 120, max_payout: int = 100000):
    """Generate a complete invariant testing project."""

    source_path = Path(source_dir).resolve()
    if output_dir:
        out_path = Path(output_dir).resolve()
    else:
        out_path = source_path / "test" / "invariant-hunt"

    out_path.mkdir(parents=True, exist_ok=True)

    print(f"=== Scaffold: {name} ===")
    print(f"Source: {source_path}")
    print(f"Type: {protocol_type}")
    print(f"Output: {out_path}")
    print()

    # Step 1: Run matcher
    print("Step 1: Matching invariants...")
    pipeline = MatcherPipeline()
    results = pipeline.match(
        source_dir=str(source_path),
        max_payout=max_payout,
        time_budget_minutes=budget,
    )
    pipeline.print_report(results, max_payout)

    # Step 2: Export matched invariants
    matched_path = out_path / "matched_invariants.json"
    export_data = []
    for r in results:
        export_data.append({
            "id": r.invariant.id,
            "title": r.invariant.title,
            "category": r.invariant.category,
            "severity": r.invariant.severity,
            "confidence": r.confidence,
            "invariant_solidity": r.invariant.invariant_solidity,
            "invariant_natural": r.invariant.invariant_natural,
            "composition_with": r.invariant.composition_with,
        })
    with open(matched_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2)
    print(f"\nExported {len(export_data)} invariants to {matched_path}")

    # Step 3: Copy skeleton harness
    skeleton_file = SKELETONS_DIR / PROTOCOL_TYPES.get(protocol_type, "erc4626_vault.sol")
    if skeleton_file.exists():
        dest = out_path / f"{name}_invariants.t.sol"
        shutil.copy2(skeleton_file, dest)
        print(f"Skeleton copied: {dest}")
    else:
        print(f"Warning: No skeleton for type '{protocol_type}'")

    # Step 4: Generate invariant checklist
    checklist_path = out_path / "INVARIANT_CHECKLIST.md"
    with open(checklist_path, "w", encoding="utf-8") as f:
        f.write(f"# Invariant Checklist: {name}\n\n")
        f.write(f"Protocol type: {protocol_type}\n")
        f.write(f"Generated: {__import__('datetime').datetime.now().isoformat()}\n")
        f.write(f"Budget: {budget} minutes\n")
        f.write(f"Max payout: ${max_payout:,}\n\n")

        f.write("## Round 1: Tier S (first 30 min)\n\n")
        for i, r in enumerate(results[:5]):
            f.write(f"- [ ] **{r.invariant.id}** — {r.invariant.title}\n")
            f.write(f"  - Severity: {r.invariant.severity} | Confidence: {r.confidence:.2f}\n")
            f.write(f"  - {r.invariant.invariant_natural}\n\n")

        if len(results) > 5:
            f.write("## Round 2: Tier A (next 30 min)\n\n")
            for r in results[5:15]:
                f.write(f"- [ ] **{r.invariant.id}** — {r.invariant.title}\n")
                f.write(f"  - {r.invariant.invariant_natural}\n\n")

        if len(results) > 15:
            f.write("## Round 3: Tier B (remaining)\n\n")
            for r in results[15:]:
                f.write(f"- [ ] **{r.invariant.id}** — {r.invariant.title}\n\n")

    print(f"Checklist: {checklist_path}")

    # Step 5: Copy fuzzer configs
    for config_name in ["echidna.yaml", "medusa.json", "foundry_invariant.toml"]:
        config_src = CONFIGS_DIR / config_name
        if config_src.exists():
            shutil.copy2(config_src, out_path / config_name)

    # Step 6: Generate run script
    run_script = out_path / "run.sh"
    with open(run_script, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"# Invariant hunt: {name}\n")
        f.write(f"# Generated for {protocol_type} protocol\n\n")
        f.write("# Round 1: Foundry invariant tests\n")
        f.write(f'echo "Running Foundry invariant tests..."\n')
        f.write(f"forge test --match-contract {name.replace('-', '')}Invariant -vvv --fuzz-runs 10000\n\n")
        f.write("# Round 2: Medusa (if installed)\n")
        f.write("# medusa fuzz --config medusa.json\n\n")
        f.write("# Round 3: Echidna (if installed)\n")
        f.write("# echidna . --config echidna.yaml\n")

    print(f"Run script: {run_script}")

    print(f"\n{'='*60}")
    print(f"SCAFFOLD COMPLETE: {name}")
    print(f"  {len(results)} invariants matched")
    print(f"  Skeleton: {protocol_type}")
    print(f"  Next: Edit {out_path / f'{name}_invariants.t.sol'}")
    print(f"  Then: bash {run_script}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(description="Generate invariant testing project for a target")
    parser.add_argument("--source", required=True, help="Path to target source code")
    parser.add_argument("--name", required=True, help="Protocol name (used for file naming)")
    parser.add_argument("--type", dest="protocol_type", choices=list(PROTOCOL_TYPES.keys()),
                        help="Protocol type (auto-detected if not specified)")
    parser.add_argument("--auto", action="store_true", help="Auto-detect protocol type")
    parser.add_argument("--output", help="Output directory (default: source/test/invariant-hunt)")
    parser.add_argument("--budget", type=int, default=120, help="Time budget in minutes")
    parser.add_argument("--payout", type=int, default=100000, help="Max bounty payout")

    args = parser.parse_args()

    protocol_type = args.protocol_type
    if not protocol_type or args.auto:
        protocol_type = detect_protocol_type(args.source)
        print(f"Auto-detected protocol type: {protocol_type}")

    scaffold_project(
        source_dir=args.source,
        name=args.name,
        protocol_type=protocol_type,
        output_dir=args.output,
        budget=args.budget,
        max_payout=args.payout,
    )


if __name__ == "__main__":
    main()
