#!/usr/bin/env python3
"""
scope_intake.py — Generate hunt state from repo + bounty text.

Usage:
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-text "..."
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-file rules.txt
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-file rules.txt --dry-run
"""
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE


# ─── Graphify Structural Recon ────────────────────────────────────────────

def run_graphify_recon(repo_path: Path, protocol: str) -> Path:
    """Run graphify on target repo to generate structural graph."""
    graph_dir = HUNT_SESSION_DIR / "graph" / protocol
    graph_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["graphify", str(repo_path), "--no-viz"],
            capture_output=True, text=True, timeout=300,
            cwd=str(graph_dir)
        )
        if result.returncode == 0:
            print(f"[graphify] Graph generated at {graph_dir}")
            report = graph_dir / "GRAPH_REPORT.md"
            if report.exists():
                print(f"[graphify] God nodes and connections in {report}")
        else:
            print(f"[graphify] Warning: {result.stderr[:200]}")
    except FileNotFoundError:
        print("[graphify] Not installed, skipping recon (pip install graphifyy)")
    except subprocess.TimeoutExpired:
        print("[graphify] Timeout after 5min, skipping")
    return graph_dir


# ─── Obsidian Wiki Prior-Knowledge Query ──────────────────────────────────

def run_wiki_query(protocol: str, components: list[str]) -> Path | None:
    """Invoke /wiki-query to fetch prior knowledge for this protocol + components.

    Writes result to hunt_session/context/{protocol}/wiki_prior_knowledge.md so
    run_benchmark.py and hunters can pick it up. Failure-tolerant: missing skill,
    timeout, or empty vault do not abort scope_intake.
    """
    ctx_dir = HUNT_SESSION_DIR / "context" / protocol
    ctx_dir.mkdir(parents=True, exist_ok=True)
    out_path = ctx_dir / "wiki_prior_knowledge.md"

    query = (
        f"/wiki-query Previous findings, attack patterns, and known-vulnerable "
        f"primitives related to the {protocol} protocol. Components: "
        f"{', '.join(components)}. Focus on DeFi attack vectors that have been "
        f"paid bounties on similar code. Return a concise markdown brief."
    )
    try:
        result = subprocess.run(
            ["claude", "-p", query, "--output-format", "text"],
            capture_output=True, text=True, timeout=600
        )
        if result.returncode == 0 and result.stdout.strip():
            out_path.write_text(result.stdout, encoding="utf-8")
            print(f"[wiki-query] Prior knowledge → {out_path}")
            return out_path
        else:
            print(f"[wiki-query] No content returned (rc={result.returncode})")
    except FileNotFoundError:
        print("[wiki-query] claude CLI not found, skipping")
    except subprocess.TimeoutExpired:
        print("[wiki-query] Timeout after 10min, skipping")
    return None


# ─── Bounty Text Parser ───────────────────────────────────────────────────

def parse_bounty_text(text: str) -> dict:
    """Parse bounty rules text and extract structured fields."""
    result = {
        "payout": "",
        "exclusions": [],
        "commits": [],
        "contracts_mentioned": [],
        "prior_audits": "",
        "attack_surfaces": [],
        "raw_scope_text": text,
    }

    if not text.strip():
        return result

    # ── Payouts ──
    payout_lines = []
    for line in text.split("\n"):
        if re.search(r'\$\s*[\d,.]+\s*[KkMm]?', line):
            payout_lines.append(line.strip())
    if payout_lines:
        result["payout"] = " | ".join(payout_lines[:6])

    # ── Exclusions ──
    exclusion_zone = False
    for line in text.split("\n"):
        lower = line.lower().strip()
        if any(kw in lower for kw in ["out of scope", "not eligible", "exclusion",
                                       "not in scope", "will not be", "are excluded"]):
            exclusion_zone = True
            continue
        if exclusion_zone:
            stripped = line.strip().lstrip("-•*").strip()
            if stripped and len(stripped) > 10:
                result["exclusions"].append(stripped)
            if not stripped and result["exclusions"]:
                exclusion_zone = False

    # ── Commits ──
    commits = re.findall(r'\b([0-9a-f]{7,40})\b', text)
    result["commits"] = [c for c in commits if len(c) <= 40 and not c.startswith("0x")][:10]

    # ── Contract names ──
    sol_files = re.findall(r'(\w+\.sol)\b', text)
    result["contracts_mentioned"] = list(set(sol_files))

    # ── Prior audits ──
    audit_patterns = [
        r'(?:audited|reviewed|contest|audit)\s+(?:by|from|with)\s+(\w[\w\s,]+)',
        r'(trail of bits|openzeppelin|cyfrin|spearbit|cantina|code4rena|sherlock)',
    ]
    audits = []
    for pat in audit_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            audits.append(m.group(0).strip())
    if audits:
        result["prior_audits"] = "; ".join(set(audits))

    # ── Attack surfaces ──
    surface_keywords = ["flash loan", "oracle", "reentrancy", "cross-chain",
                        "liquidation", "migration", "permit", "multicall",
                        "delegation", "proxy", "upgrade", "bridge"]
    for kw in surface_keywords:
        if kw.lower() in text.lower():
            result["attack_surfaces"].append(kw)

    return result


# ─── Component Mapper ─────────────────────────────────────────────────────

def map_components(repo_path: Path) -> list:
    """Map Solidity contracts in repo to component entries sorted by LOC desc."""
    components = []
    src_dirs = [repo_path / "src", repo_path / "contracts", repo_path]

    seen_names = set()
    for src_dir in src_dirs:
        if not src_dir.is_dir():
            continue
        for sol_file in sorted(src_dir.rglob("*.sol")):
            # Skip test/script/lib files
            rel = str(sol_file.relative_to(repo_path))
            if any(skip in rel for skip in ["test/", "tests/", "script/", "lib/", "node_modules/",
                                              "forge-std/", "openzeppelin", "mock", "Mock",
                                              "out/", "cache/", "artifacts/"]):
                continue

            # Skip directories that happen to match *.sol (rare but possible)
            if not sol_file.is_file():
                continue

            name = sol_file.stem
            if name in seen_names:
                continue
            seen_names.add(name)

            loc = sum(1 for line in sol_file.read_text(errors="ignore").split("\n")
                      if line.strip() and not line.strip().startswith("//") and not line.strip().startswith("*"))

            if loc < 20:  # Skip tiny files (interfaces, imports-only)
                continue

            components.append({
                "name": name,
                "file": rel,
                "loc": loc,
                "priority": 0,
                "status": "pending",
                "scope": "direct",
            })

    # Sort by LOC descending, assign priority
    components.sort(key=lambda c: c["loc"], reverse=True)
    for i, comp in enumerate(components):
        comp["priority"] = i + 1

    return components


# ─── State Generator ──────────────────────────────────────────────────────

def generate_hunt_state(repo_path: str, platform: str, parsed: dict) -> dict:
    """Generate current_hunt.json from parsed bounty text + repo."""
    protocol = Path(repo_path).name

    component_map = map_components(Path(repo_path))

    # Mark mentioned contracts as direct scope
    mentioned = {c.replace(".sol", "") for c in parsed.get("contracts_mentioned", [])}
    if mentioned:
        for comp in component_map:
            if comp["name"] in mentioned:
                comp["scope"] = "direct"
            else:
                comp["scope"] = "indirect"

    all_names = [c["name"] for c in component_map]

    state = {
        "protocol": protocol,
        "repo_path": str(Path(repo_path).resolve()),
        "platform": platform,
        "payout": parsed.get("payout", ""),
        "status": "active",
        "current_component": all_names[0] if all_names else None,
        "components_done": [],
        "components_remaining": all_names,
        "component_map": component_map,
        "findings": [],
        "finding_queue": [],
        "scope_notes": {
            "prior_audits": parsed.get("prior_audits", ""),
            "exclusions": parsed.get("exclusions", []),
            "key_attack_surfaces": parsed.get("attack_surfaces", []),
            "commits": parsed.get("commits", []),
            "raw_scope_text": parsed.get("raw_scope_text", ""),
        },
        "last_session": datetime.now().isoformat(),
    }
    return state


def generate_fichas(state: dict):
    """Generate empty ficha YAMLs for each component."""
    if not yaml:
        print("  WARNING: PyYAML not installed — skipping ficha generation")
        return

    protocol = state["protocol"]
    fichas_dir = HUNT_SESSION_DIR / "fichas" / protocol
    fichas_dir.mkdir(parents=True, exist_ok=True)
    (HUNT_SESSION_DIR / "hypotheses" / protocol).mkdir(parents=True, exist_ok=True)
    (HUNT_SESSION_DIR / "context" / protocol).mkdir(parents=True, exist_ok=True)
    (HUNT_SESSION_DIR / "gate_status").mkdir(parents=True, exist_ok=True)

    template = {
        "protocol": protocol,
        "status": "pending",
        "hunters_completed": {
            "AccessHunter": False, "DomainHunter": False, "FlowHunter": False,
            "MathHunter": False, "OracleHunter": False, "TrustBoundaryHunter": False,
            "WildcardHunter": False, "SignatureHunter": False, "DoSHunter": False,
        },
        "checklist": {
            "full_code_read": False, "protocol_model": False,
            "ai_invariants_generated": False, "invariants_added_to_properties": False,
            "handlers_added": False, "boundary_values": False,
            "optimization_functions": False, "compile_check": False,
            "foundry_fuzz": False, "findings_logged": False,
            "tier1_separated": False, "tolerance_tuned": False,
        },
        "confirmed_findings": [],
        "dismissed_findings": [],
        "false_positives": [],
        "notes": "",
        "feedback_applied": None,
    }

    created = 0
    for comp in state.get("component_map", []):
        ficha_path = fichas_dir / f"{comp['name']}.yaml"
        if ficha_path.exists():
            continue
        ficha = {**template}
        ficha["component"] = comp["name"]
        ficha["file"] = comp.get("file", "")
        ficha["domain"] = "unknown"
        with open(ficha_path, "w") as f:
            yaml.dump(ficha, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        created += 1

    print(f"  Generated {created} fichas in {fichas_dir}")


# ─── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scope intake — generate hunt state from repo + bounty text")
    parser.add_argument("--repo", "-r", required=True, help="Path to cloned repo")
    parser.add_argument("--platform", "-p", required=True, help="Bounty platform (cantina|immunefi|c4|sherlock)")
    parser.add_argument("--scope-text", "-t", help="Bounty rules as text string")
    parser.add_argument("--scope-file", "-f", help="Path to file with bounty rules")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    parser.add_argument("--force", action="store_true", help="Overwrite existing current_hunt.json")
    args = parser.parse_args()

    # Validate repo
    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        print(f"ERROR: Repository not found: {repo_path}")
        sys.exit(1)

    # Load scope text
    scope_text = ""
    if args.scope_text:
        scope_text = args.scope_text
    elif args.scope_file:
        scope_file = Path(args.scope_file)
        if not scope_file.exists():
            print(f"ERROR: Scope file not found: {scope_file}")
            sys.exit(1)
        scope_text = scope_file.read_text()
    else:
        print("WARNING: No scope text provided. Component mapping only.")

    # Check existing state
    if STATE_FILE.exists() and not args.force and not args.dry_run:
        print(f"ERROR: {STATE_FILE} already exists. Use --force to overwrite.")
        sys.exit(1)

    # Parse
    parsed = parse_bounty_text(scope_text)

    # Warnings for missing fields
    if not parsed["payout"]:
        print("WARNING: Could not extract payout amounts from scope text")
    if not parsed["exclusions"]:
        print("WARNING: Could not extract exclusion rules from scope text")

    # Generate state
    state = generate_hunt_state(str(repo_path), args.platform, parsed)

    # Summary
    n_comps = len(state["component_map"])
    first = state["current_component"] or "N/A"
    first_loc = next((c["loc"] for c in state["component_map"] if c["name"] == first), 0)
    n_excl = len(parsed["exclusions"])

    print(f"\n{'='*60}")
    print(f"  SCOPE INTAKE SUMMARY")
    print(f"{'='*60}")
    print(f"  Protocol:    {state['protocol']}")
    print(f"  Platform:    {state['platform']}")
    print(f"  Repo:        {state['repo_path']}")
    print(f"  Components:  {n_comps} mapped")
    print(f"  Starting:    {first} ({first_loc} LOC)")
    print(f"  Payouts:     {parsed['payout'] or 'NOT DETECTED'}")
    print(f"  Exclusions:  {n_excl}")
    print(f"  Commits:     {parsed['commits'] or 'none detected'}")
    if parsed["attack_surfaces"]:
        print(f"  Surfaces:    {', '.join(parsed['attack_surfaces'])}")
    print()

    # Component table
    print(f"  {'#':<4} {'Component':<30} {'LOC':<8} {'Scope'}")
    print(f"  {'-'*4} {'-'*30} {'-'*8} {'-'*10}")
    for comp in state["component_map"][:15]:
        print(f"  {comp['priority']:<4} {comp['name']:<30} {comp.get('loc',0):<8} {comp.get('scope','')}")
    if n_comps > 15:
        print(f"  ... and {n_comps - 15} more")

    if args.dry_run:
        print(f"\n  DRY RUN — no files written")
        return

    # Write state
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    print(f"\n  Written: {STATE_FILE}")

    # Run graphify structural recon
    if not args.dry_run:
        run_graphify_recon(Path(args.repo), state["protocol"])
        # Pull prior knowledge from the Obsidian vault into hunt_session/context/
        comp_names = [c.get("name") if isinstance(c, dict) else str(c)
                      for c in state.get("component_map", [])] or [first]
        run_wiki_query(state["protocol"], comp_names)

    # Generate fichas
    generate_fichas(state)

    # Scope gate check (run_hunt.py auto-dispatch removed in Phase 4 —
    # users now invoke run_benchmark.py manually when they are ready to hunt)
    print(f"\n  Running pipeline_gate.py --gate scope ...")
    ret2 = subprocess.run(
        ["python3", str(WEB3_DIR / "audit-agents" / "pipeline_gate.py"),
         "-c", first, "--gate", "scope"],
        cwd=str(WEB3_DIR),
    )
    if ret2.returncode != 0:
        print(f"  WARNING: scope gate failed — fix before launching hunters")

    print(f"\n  Dashboard: python3 hunt-dashboard/serve.py")


if __name__ == "__main__":
    main()
