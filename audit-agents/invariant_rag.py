#!/usr/bin/env python3
"""
invariant_rag.py — RAG index of confirmed invariants from past audits.

Builds a searchable index from validated hypotheses (confidence >= 70%)
across all benchmark sessions and hunt sessions.

Usage:
    python3 invariant_rag.py --build                          # Build/rebuild index
    python3 invariant_rag.py --query "oracle price stale"     # Search by keywords
    python3 invariant_rag.py --query "flash loan" --top-k 3   # Top 3 results
    python3 invariant_rag.py --stats                          # Show index statistics
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

SCRIPT_DIR = Path(__file__).resolve().parent
WEB3_DIR = SCRIPT_DIR.parent
INDEX_PATH = SCRIPT_DIR / "invariant_rag.json"


def _to_str(val) -> str:
    """Coerce a value to string (handles dicts, lists, None)."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    return json.dumps(val)


def build_index() -> int:
    """Scan all benchmark and hunt session hypotheses for validated invariants."""
    confirmed = []

    # Scan benchmark sessions
    for yaml_file in WEB3_DIR.glob("benchmarks/*/bench_session*/hypotheses/**/hyp_*.yaml"):
        confirmed.extend(_extract_from_yaml(yaml_file))

    # Scan hunt session hypotheses
    for yaml_file in WEB3_DIR.glob("hunt_session/hypotheses/**/hyp_*.yaml"):
        confirmed.extend(_extract_from_yaml(yaml_file))

    # Deduplicate by solidity content hash
    seen = set()
    unique = []
    for inv in confirmed:
        raw_sol = inv.get("solidity") or ""
        key = (raw_sol if isinstance(raw_sol, str) else json.dumps(raw_sol)).strip()[:200]
        if key and key not in seen:
            seen.add(key)
            unique.append(inv)

    with open(INDEX_PATH, "w") as f:
        json.dump(unique, f, indent=2)

    print(f"Indexed {len(unique)} confirmed invariants (from {len(confirmed)} total)")
    return len(unique)


def _extract_from_yaml(yaml_file: Path) -> list[dict]:
    """Extract validated invariants from a hypothesis YAML file."""
    if yaml is None:
        return []
    try:
        data = yaml.safe_load(yaml_file.read_text())
        if not data or not isinstance(data, dict):
            return []
    except Exception:
        return []

    results = []
    for inv in data.get("invariants", data.get("hypotheses", [])):
        if not isinstance(inv, dict):
            continue
        try:
            confidence = int(inv.get("confidence", 0))
        except (ValueError, TypeError):
            confidence = 0
        validated = inv.get("validated", False)
        if confidence >= 70 or validated:
            results.append({
                "id": inv.get("id") or "?",
                "description": inv.get("description") or inv.get("title") or "",
                "solidity": _to_str(inv.get("solidity") or inv.get("solidity_property") or ""),
                "category": data.get("domain") or inv.get("type") or "",
                "protocol": data.get("protocol") or "",
                "component": data.get("component") or "",
                "hunter": data.get("hunter") or yaml_file.stem,
                "confidence": confidence,
                "tier": inv.get("tier", 2),
                "source": str(yaml_file.relative_to(WEB3_DIR)),
            })
    return results


def query(search_text: str, top_k: int = 5) -> list[dict]:
    """Find similar confirmed invariants by keyword matching."""
    if not INDEX_PATH.exists():
        print("Index not built. Run: python3 invariant_rag.py --build")
        return []

    with open(INDEX_PATH) as f:
        index = json.load(f)

    search_lower = search_text.lower()
    search_tokens = set(re.findall(r'\w+', search_lower))

    scored = []
    for inv in index:
        text = f"{inv.get('description', '')} {inv.get('solidity', '')} {inv.get('category', '')}".lower()
        inv_tokens = set(re.findall(r'\w+', text))

        # Score: number of matching tokens + bonus for exact substring match
        overlap = len(search_tokens & inv_tokens)
        if search_lower in text:
            overlap += 3  # bonus for exact match

        if overlap > 0:
            scored.append((overlap, inv))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [inv for _, inv in scored[:top_k]]


def format_for_prompt(results: list[dict], max_chars: int = 2000) -> str:
    """Format RAG results for injection into merge_invariants or hunter prompts."""
    if not results:
        return ""
    lines = ["\n## Confirmed Invariants from Prior Audits (RAG)"]
    total = 0
    for inv in results:
        entry = (
            f"- **{inv['id']}** ({inv.get('protocol', '?')}/{inv.get('component', '?')}): "
            f"{inv.get('description', '')[:150]}"
        )
        sol = inv.get("solidity", "").strip()
        if sol:
            entry += f"\n  ```solidity\n  {sol[:200]}\n  ```"
        if total + len(entry) > max_chars:
            break
        lines.append(entry)
        total += len(entry)
    return "\n".join(lines)


def show_stats():
    """Show index statistics."""
    if not INDEX_PATH.exists():
        print("Index not built. Run: python3 invariant_rag.py --build")
        return

    with open(INDEX_PATH) as f:
        index = json.load(f)

    print(f"Total invariants: {len(index)}")

    # By protocol
    protocols = {}
    for inv in index:
        p = inv.get("protocol", "unknown")
        protocols[p] = protocols.get(p, 0) + 1
    print(f"\nBy protocol:")
    for p, count in sorted(protocols.items(), key=lambda x: -x[1]):
        print(f"  {p}: {count}")

    # By category
    categories = {}
    for inv in index:
        c = inv.get("category", "unknown")
        categories[c] = categories.get(c, 0) + 1
    print(f"\nBy category:")
    for c, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {c}: {count}")

    # By tier
    tiers = {}
    for inv in index:
        t = inv.get("tier", "?")
        tiers[t] = tiers.get(t, 0) + 1
    print(f"\nBy tier:")
    for t, count in sorted(tiers.items(), key=lambda x: str(x[0])):
        print(f"  Tier {t}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Invariant RAG index")
    parser.add_argument("--build", action="store_true", help="Build/rebuild index")
    parser.add_argument("--query", type=str, help="Search query")
    parser.add_argument("--top-k", type=int, default=5, help="Number of results")
    parser.add_argument("--stats", action="store_true", help="Show index statistics")
    args = parser.parse_args()

    if args.build:
        build_index()
    elif args.query:
        results = query(args.query, args.top_k)
        if results:
            print(format_for_prompt(results))
        else:
            print("No matching invariants found.")
    elif args.stats:
        show_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
