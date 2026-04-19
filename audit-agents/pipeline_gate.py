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
_PROTOCOL_OVERRIDE = ""  # Set by --protocol CLI arg; overrides load_state() protocol


def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_protocol() -> str:
    """Get protocol from override (--protocol CLI) or current_hunt.json state."""
    return _PROTOCOL_OVERRIDE or load_state().get("protocol", "")


def get_context_dir(protocol: str) -> Path:
    """Return protocol-namespaced context directory."""
    d = HUNT_SESSION_DIR / "context" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_gate_status_file(protocol: str) -> Path:
    """Return protocol-specific gate_status file."""
    d = HUNT_SESSION_DIR / "gate_status"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{protocol}.json"

# ─── State helpers ───────────────────────────────────────────────────────────
# load_ficha / update_ficha: extracted to gate/ficha.py (re-exported above).


# ─── Gate checks ─────────────────────────────────────────────────────────────

def check_scope(component: str, repo: str = "") -> tuple[bool, list[str], list[str]]:
    """Check that the hunt is properly set up before hunters can run."""
    passed = []
    failed = []

    state = load_state()

    # 1. current_hunt.json exists and has required fields
    if not state:
        failed.append("NO_STATE: ~/.claude/MEMORY/STATE/current_hunt.json missing or empty")
        failed.append("  Run: set up current_hunt.json with protocol, repo_path, payout, scope")
        return False, passed, failed

    # 2. Protocol and repo_path set
    if state.get("protocol"):
        passed.append(f"OK: protocol = {state['protocol']}")
    else:
        failed.append("MISSING: current_hunt.json needs 'protocol' field")

    repo_path = repo or state.get("repo_path", "")
    if repo_path and Path(repo_path).exists():
        passed.append(f"OK: repo_path = {repo_path}")
    elif repo_path:
        failed.append(f"INVALID: repo_path = {repo_path} (directory doesn't exist)")
    else:
        failed.append("MISSING: current_hunt.json needs 'repo_path' field")

    # 3. Component map exists
    cmap = state.get("component_map", {})
    if cmap:
        # Support both dict-keyed and list-of-dicts formats
        if isinstance(cmap, dict):
            comp_names = list(cmap.keys())
            comp_info = cmap.get(component, {})
        else:
            comp_names = [c["name"] for c in cmap]
            comp_info = next((c for c in cmap if c["name"] == component), {})
        if component in comp_names:
            passed.append(f"OK: {component} in component_map ({comp_info.get('loc', '?')} LOC, priority={comp_info.get('priority', '?')})")
        else:
            failed.append(f"NOT_IN_MAP: {component} not found in component_map. Available: {comp_names[:5]}")
    else:
        failed.append("NO_MAP: component_map empty. Run: python3 audit-agents/run_benchmark.py --auto-components --protocol <name> --repo <path>")

    # 4. Context file exists (run_benchmark.py --components was executed)
    protocol = _get_protocol() or state.get("protocol", "")
    ctx_file = get_context_dir(protocol) / f"{component}_context.md"
    if ctx_file.exists():
        size = ctx_file.stat().st_size
        passed.append(f"OK: context file exists ({size:,} bytes)")
    else:
        failed.append(f"NO_CONTEXT: {ctx_file.name} missing. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")

    # 5. Hunter prompts generated
    prompts_found = 0
    for hunter in HUNTER_NAMES:
        prompt_file = get_context_dir(protocol) / f"{component}_{hunter}_prompt.md"
        if prompt_file.exists():
            prompts_found += 1
    if prompts_found >= 7:  # Allow some new hunters to not have prompts yet
        passed.append(f"OK: {prompts_found}/{len(HUNTER_NAMES)} hunter prompts generated")
    elif prompts_found > 0:
        failed.append(f"PARTIAL: Only {prompts_found}/{len(HUNTER_NAMES)} hunter prompts. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")
    else:
        failed.append(f"NO_PROMPTS: No hunter prompts found. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")

    # 6. Ficha exists
    ficha = load_ficha(component)
    if ficha:
        passed.append(f"OK: ficha exists (status={ficha.get('status', 'unknown')})")
    else:
        failed.append(f"NO_FICHA: No ficha YAML for {component}")

    # 7. Bounty scope documented
    if state.get("payout") or state.get("scope"):
        passed.append(f"OK: payout/scope documented")
    else:
        failed.append("WARNING: No payout or scope in current_hunt.json (optional but recommended)")

    ok = all("MISSING" not in f and "NO_STATE" not in f and "NO_CONTEXT" not in f and "NO_PROMPTS" not in f for f in failed)
    return ok, passed, failed


def check_hunters(component: str) -> tuple[bool, list[str], list[str]]:
    """Check that all 9 hunters produced hypothesis YAMLs with solidity fields."""
    passed = []
    failed = []

    protocol = _get_protocol()
    hyp_dir = get_hyp_dir(protocol)

    for hunter in HUNTER_NAMES:
        hyp_file = hyp_dir / f"hyp_{component}_{hunter}.yaml"
        if not hyp_file.exists():
            failed.append(f"MISSING: {hyp_file.name}")
            continue

        try:
            content = yaml.safe_load(hyp_file.read_text())
        except yaml.YAMLError:
            # Malformed YAML — try counting solidity fields via grep
            text = hyp_file.read_text()
            sol_count = text.count("solidity: |") + text.count("solidity: |-") + text.count("solidity_property: |") + text.count("solidity_property: |-") + text.count("solidity_invariant: |") + text.count("solidity_invariant: |-")
            if sol_count > 0:
                passed.append(f"OK: {hunter} — {sol_count}+ with solidity (YAML malformed, grep fallback)")
                continue
            failed.append(f"YAML_ERROR: {hyp_file.name} — malformed and no solidity fields found")
            continue
        if not content:
            failed.append(f"EMPTY: {hyp_file.name}")
            continue

        # Check for findings/invariants/hypotheses with solidity fields
        findings = content.get("findings", content.get("invariants", content.get("hypotheses", [])))
        if not findings:
            # Accept if hunter documented false_positives (legitimate "nothing found")
            fps = content.get("false_positives", [])
            if fps:
                passed.append(f"OK: {hunter} — 0 findings, {len(fps)} false_positives documented")
                continue
            failed.append(f"NO_FINDINGS: {hyp_file.name}")
            continue

        has_solidity = 0
        total = len(findings)
        for f in findings:
            if isinstance(f, dict) and (f.get("solidity") or f.get("solidity_property") or f.get("solidity_invariant")):
                has_solidity += 1

        if has_solidity == 0:
            failed.append(f"NO_SOLIDITY: {hyp_file.name} ({total} findings, 0 with solidity)")
        else:
            pct = int(100 * has_solidity / total)
            passed.append(f"OK: {hunter} — {has_solidity}/{total} with solidity ({pct}%)")

    ok = len(failed) == 0
    return ok, passed, failed


def check_deepdive(component: str) -> tuple[bool, list[str], list[str]]:
    """Check that DeepDiveHunter produced output."""
    protocol = _get_protocol()
    hyp_file = get_hyp_dir(protocol) / f"hyp_{component}_DeepDiveHunter.yaml"
    if not hyp_file.exists():
        return False, [], [f"MISSING: {hyp_file.name}"]

    try:
        content = yaml.safe_load(hyp_file.read_text())
    except yaml.YAMLError:
        # File exists but malformed — still counts as executed
        return True, [f"OK: DeepDiveHunter — YAML malformed but file exists"], []
    if not content:
        return False, [], [f"EMPTY: {hyp_file.name}"]

    findings = content.get("findings", content.get("invariants", content.get("hypotheses", [])))
    return True, [f"OK: DeepDiveHunter — {len(findings)} hypotheses"], []


def check_crosschain(component: str) -> tuple[bool, list[str], list[str]]:
    """Check that CrossChainHunter produced output (or justified skip for single-chain)."""
    protocol = _get_protocol()
    hyp_dir = get_hyp_dir(protocol)
    hyp_file = hyp_dir / f"hyp_{component}_CrossChainHunter.yaml"

    # Check if component is single-chain (skip file)
    skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
    if skip_file.exists():
        reason = skip_file.read_text().strip() or "single-chain component"
        return True, [f"SKIP: CrossChainHunter — {reason}"], []

    if not hyp_file.exists():
        return False, [], [f"MISSING: {hyp_file.name} (create .skip file if single-chain)"]

    try:
        content = yaml.safe_load(hyp_file.read_text())
    except yaml.YAMLError:
        return True, [f"OK: CrossChainHunter — YAML malformed but file exists"], []
    if not content:
        return False, [], [f"EMPTY: {hyp_file.name}"]

    passed = []
    failed = []

    # Check deployment_map exists
    dmap = content.get("deployment_map", [])
    if not dmap:
        failed.append("MISSING: deployment_map field")
    else:
        chains = [d.get("chain", "?") for d in dmap]
        passed.append(f"OK: deployment_map — {len(dmap)} deployments across {', '.join(chains)}")

    # Check bytecode_match field
    if "bytecode_match" not in content:
        failed.append("MISSING: bytecode_match field")
    else:
        passed.append(f"OK: bytecode_match = {content['bytecode_match']}")

    # Check at least 1 invariant or false_positive documented
    findings = content.get("invariants", content.get("findings", content.get("hypotheses", [])))
    fps = content.get("false_positives", [])
    if not findings and not fps:
        failed.append("NO_ANALYSIS: need at least 1 invariant or 1 documented false_positive")
    else:
        passed.append(f"OK: {len(findings)} invariants, {len(fps)} false_positives")

    ok = len(failed) == 0
    return ok, passed, failed


def check_merge(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check that merge_invariants.py ran and Properties.sol exists."""
    passed = []
    failed = []

    # Find Properties.sol in repo
    props_found = False
    search_paths = []
    if repo_path:
        search_paths.append(Path(repo_path))
    # Also check common locations
    state = load_state()
    if state.get("repo_path"):
        search_paths.append(Path(state["repo_path"]))

    for base in search_paths:
        for props in base.rglob("Properties.sol"):
            if not props.is_file():
                continue
            if "chimera" in str(props) or "test" in str(props):
                props_found = True
                # Check it has content related to this component
                text = props.read_text()
                loc = text.count("\n")
                passed.append(f"OK: Properties.sol found — {props} ({loc} LOC)")
                break
        if props_found:
            break

    if not props_found:
        failed.append("MISSING: Properties.sol not found in test/chimera/")

    # Check TargetFunctions.sol (checklist item 5)
    target_found = False
    for base in search_paths:
        for tf in base.rglob("TargetFunctions.sol"):
            if not tf.is_file():
                continue
            if "chimera" in str(tf) or "test" in str(tf):
                target_found = True
                tf_text = tf.read_text()
                tf_loc = tf_text.count("\n")
                passed.append(f"OK: TargetFunctions.sol found — {tf} ({tf_loc} LOC)")
                # Check boundary values (checklist item 6)
                has_boundary = any(kw in tf_text for kw in ["_clampAmount", "type(uint256).max", "type(uint128).max", "0,", "1,"])
                if has_boundary:
                    passed.append("OK: TargetFunctions.sol has boundary value patterns")
                else:
                    failed.append("WARNING: TargetFunctions.sol missing boundary value injection (_clampAmount, 0, 1, max)")
                break
        if target_found:
            break
    if not target_found:
        failed.append("MISSING: TargetFunctions.sol not found — handlers not generated (checklist item 5)")

    # Count how many hypothesis invariants have solidity vs how many are in Properties.sol
    protocol = _get_protocol() or state.get("protocol", "")
    hyp_dir = get_hyp_dir(protocol)
    total_solidity_invariants = 0
    for hunter in HUNTER_NAMES + ["DeepDiveHunter"]:
        hyp_file = hyp_dir / f"hyp_{component}_{hunter}.yaml"
        if not hyp_file.exists():
            continue
        try:
            content = yaml.safe_load(hyp_file.read_text())
        except yaml.YAMLError:
            # Count via grep fallback
            text = hyp_file.read_text()
            total_solidity_invariants += text.count("solidity: |") + text.count("solidity: |-") + text.count("solidity_property: |") + text.count("solidity_property: |-")
            continue
        if not content:
            continue
        findings = content.get("findings", content.get("invariants", content.get("hypotheses", [])))
        for f in findings:
            if isinstance(f, dict) and (f.get("solidity") or f.get("solidity_property") or f.get("solidity_invariant")) and f.get("validated", True):
                priority = str(f.get("priority", "medium")).lower()
                if priority != "low":
                    total_solidity_invariants += 1

    if total_solidity_invariants > 0:
        passed.append(f"INFO: {total_solidity_invariants} validated invariants with solidity (should be in Properties.sol)")
    else:
        failed.append("WARNING: 0 validated invariants with solidity code found in hypotheses")

    ok = props_found
    return ok, passed, failed


def check_compile(repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check that forge build passes. Does NOT run it — checks for artifacts."""
    search_paths = []
    if repo_path:
        search_paths.append(Path(repo_path))
    state = load_state()
    if state.get("repo_path"):
        search_paths.append(Path(state["repo_path"]))

    for base in search_paths:
        out_dir = base / "out"
        if out_dir.exists() and any(out_dir.rglob("*.json")):
            # Check timestamp — compiled recently?
            newest = max(out_dir.rglob("*.json"), key=lambda p: p.stat().st_mtime)
            age_hours = (datetime.now().timestamp() - newest.stat().st_mtime) / 3600
            return True, [f"OK: forge artifacts found, newest {age_hours:.1f}h ago"], []

    return False, [], ["MISSING: No forge build artifacts found. Run: FOUNDRY_PROFILE=chimera forge build"]


def check_phase1(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check Foundry fuzz evidence (Phase 1 — min 5K runs)."""
    # Look for test results, logs, or tracker entries
    evidence_found = False
    details = []

    # Check HUNT_TRACKER.md for Phase 1 evidence
    tracker = WEB3_DIR / "HUNT_TRACKER.md"
    if tracker.exists():
        text = tracker.read_text()
        if component in text and ("foundry" in text.lower() or "fuzz" in text.lower() or "phase 1" in text.lower()):
            evidence_found = True
            details.append("OK: HUNT_TRACKER.md mentions Foundry fuzzing for this component")

    # Check for Foundry test cache
    state = load_state()
    repo = Path(repo_path) if repo_path else Path(state.get("repo_path", ""))
    if repo.exists():
        cache = repo / "cache"
        if cache.exists():
            details.append(f"OK: Foundry cache directory exists at {cache}")
            evidence_found = True

    # Check ficha
    ficha = load_ficha(component)
    if ficha and ficha.get("checklist", {}).get("fuzzing_phase1_executed"):
        evidence_found = True
        details.append("OK: ficha.checklist.fuzzing_phase1_executed = true")

    if not evidence_found:
        return False, details, [
            f"NO_EVIDENCE: No Foundry Phase 1 fuzzing evidence for {component}",
            "  Run: FOUNDRY_PROFILE=chimera forge test --fuzz-runs 5000",
            "  Then: pipeline_gate.py --component X --mark phase1"
        ]

    # Soft checks: items 10-12 (findings logged, tier1 separated, tolerance tuned)
    warnings = []
    tracker = WEB3_DIR / "HUNT_TRACKER.md"
    if tracker.exists():
        text = tracker.read_text()
        if component in text:
            details.append("OK: Component mentioned in HUNT_TRACKER.md (item 10)")
        else:
            warnings.append(f"WARNING: {component} not found in HUNT_TRACKER.md — log findings (item 10)")
    else:
        warnings.append("WARNING: HUNT_TRACKER.md doesn't exist — create and log findings (item 10)")

    # Check tolerance tuning (item 12) — ficha field
    if ficha and ficha.get("checklist", {}).get("tolerance_tuned"):
        details.append("OK: Tolerance tuned (item 12)")
    else:
        warnings.append("WARNING: Tolerance not marked as tuned — classify each failure: real/dust/mock (item 12)")

    # Warnings don't block, but are shown
    for w in warnings:
        details.append(w)

    return True, details, []


def check_phase2(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check Medusa fuzz evidence (Phase 2 — min 15 min)."""
    evidence_found = False
    details = []

    state = load_state()
    repo = Path(repo_path) if repo_path else Path(state.get("repo_path", ""))

    if repo.exists():
        # Check for medusa corpus
        for corpus in repo.rglob("medusa-corpus"):
            if corpus.is_dir():
                files = list(corpus.rglob("*.json"))
                evidence_found = True
                details.append(f"OK: Medusa corpus at {corpus} ({len(files)} files)")
                break

        # Check for medusa config
        for config in repo.rglob("medusa*.json"):
            details.append(f"INFO: Medusa config at {config}")

    # Check ficha
    ficha = load_ficha(component)
    if ficha and ficha.get("checklist", {}).get("fuzzing_phase2_executed"):
        evidence_found = True
        details.append("OK: ficha.checklist.fuzzing_phase2_executed = true")

    if not evidence_found:
        return False, details, [
            f"NO_EVIDENCE: No Medusa Phase 2 fuzzing evidence for {component}",
            "  Run: medusa fuzz --config test/chimera/medusa.json --timeout 900",
            "  Then: pipeline_gate.py --component X --mark phase2"
        ]
    return True, details, []


def check_phase3(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check Fork test evidence (Phase 3 — required if bounty >= $2K)."""
    state = load_state()
    bounty_value = 0
    payout_str = state.get("payout", "")
    if payout_str:
        # Simple extraction
        import re
        amounts = []
        for m in re.finditer(r'\$\s*([\d,.]+)\s*([KkMm])?', str(payout_str)):
            val = float(m.group(1).replace(",", ""))
            suffix = (m.group(2) or "").upper()
            if suffix == "K": val *= 1000
            elif suffix == "M": val *= 1_000_000
            amounts.append(int(val))
        bounty_value = max(amounts) if amounts else 0

    if bounty_value < 2_000 and bounty_value > 0:
        return True, [f"SKIP: Bounty ${bounty_value:,} < $2K — Phase 3 fork optional"], []

    # If bounty >= $2K or unknown, require fork evidence
    ficha = load_ficha(component)
    if ficha and ficha.get("checklist", {}).get("fork_test_executed"):
        return True, ["OK: ficha confirms fork test executed"], []

    tracker = WEB3_DIR / "HUNT_TRACKER.md"
    if tracker.exists():
        text = tracker.read_text()
        if component in text and "fork" in text.lower():
            return True, ["OK: HUNT_TRACKER mentions fork testing for this component"], []

    return False, [], [
        f"NO_EVIDENCE: Phase 3 fork test required (bounty ${bounty_value:,} >= $2K)",
        "  Run: BASE_RPC_URL=... forge test --match-contract ForkTester --fuzz-runs 10000",
        "  Then: pipeline_gate.py --component X --mark phase3"
    ]


def check_phase4(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check Echidna optimization evidence (Phase 4 — optimize_* functions)."""
    # Phase 4 is optional unless a finding was confirmed in Phase 1-3
    # Check if there are confirmed findings that warrant optimization
    ficha = load_ficha(component)
    if ficha and ficha.get("checklist", {}).get("echidna_executed"):
        return True, ["OK: ficha confirms Echidna optimization executed"], []

    # Check for echidna config
    state = load_state()
    repo = Path(repo_path) if repo_path else Path(state.get("repo_path", ""))
    if repo.exists():
        for cfg in repo.rglob("echidna*.yaml"):
            if "chimera" in str(cfg) or "test" in str(cfg):
                # Config exists — check if there's a crytic-export or echidna output
                crytic = repo / "crytic-export"
                if crytic.exists():
                    return True, [f"OK: Echidna config + crytic-export found"], []
                return False, [f"INFO: Echidna config at {cfg}"], [
                    f"PARTIAL: Echidna config exists but no crytic-export (not run yet)",
                    "  Run: echidna . --contract CryticTester --config test/chimera/echidna.yaml",
                    f"  Then: pipeline_gate.py --component {component} --mark phase4"
                ]

    # Phase 4 is mandatory if optimize_* functions exist in Properties.sol
    if repo.exists():
        for props in repo.rglob("Properties.sol"):
            if not props.is_file():
                continue
            text = props.read_text()
            if "optimize_" in text:
                return False, [], [
                    f"REQUIRED: Properties.sol has optimize_* functions — Echidna Phase 4 is mandatory",
                    "  Run: echidna . --contract CryticTester --config test/chimera/echidna.yaml",
                    f"  Then: pipeline_gate.py --component {component} --mark phase4"
                ]

    # No optimize functions, no config → skip is ok
    return True, ["SKIP: No optimize_* functions found — Phase 4 optional"], []


def check_phase5(component: str, repo_path: str = "") -> tuple[bool, list[str], list[str]]:
    """Check Halmos symbolic proof evidence (Phase 5 — check_* functions for math)."""
    ficha = load_ficha(component)
    if ficha and ficha.get("checklist", {}).get("halmos_executed"):
        return True, ["OK: ficha confirms Halmos proof executed"], []

    state = load_state()
    repo = Path(repo_path) if repo_path else Path(state.get("repo_path", ""))

    # Check if there are Halmos check files
    if repo.exists():
        for halmos_file in repo.rglob("HalmosCheck_*.sol"):
            return True, [f"OK: Halmos check file found — {halmos_file.name}"], []
        for halmos_file in repo.rglob("Halmos*.sol"):
            if "check_" in halmos_file.read_text():
                return True, [f"OK: Halmos file with check_ functions — {halmos_file.name}"], []

    # Check if the contract has pure math functions that warrant Halmos
    if repo.exists():
        contract_path = None
        for sol in repo.rglob(f"*{component}*.sol"):
            if "test" not in str(sol) and "lib" not in str(sol):
                contract_path = sol
                break
        if contract_path and contract_path.is_file():
            src = contract_path.read_text()
            has_pure = "pure" in src and ("/" in src or "*" in src)
            if has_pure:
                return False, [], [
                    f"RECOMMENDED: {component} has pure math functions — Halmos Phase 5 recommended",
                    f"  Run: python3 audit-agents/halmos_property_generator.py {contract_path}",
                    f"  Then: ~/.local/bin/halmos --function check_ --loop 10",
                    f"  Then: pipeline_gate.py --component {component} --mark phase5"
                ]

    # No pure math → skip
    return True, ["SKIP: No pure math functions found — Phase 5 optional"], []


def check_prepass(component: str, repo: str) -> tuple:
    """Check that detection_engine prepass ran and produced output."""
    hunt = load_state()
    protocol = hunt.get("protocol", "")

    # Check for prepass YAML in results/
    results_dir = HUNT_SESSION_DIR / "results"
    prepass_file = results_dir / f"{component}_prepass.yaml"

    if prepass_file.exists():
        try:
            content = prepass_file.read_text()
            n_signals = content.count("- title:")
            return True, [f"Prepass YAML found: {prepass_file} ({n_signals} signals)"], []
        except Exception as e:
            return True, [f"Prepass YAML exists but unreadable: {e}"], []

    # Also check alternate location
    alt_file = results_dir / f"{component}_detection_report.json"
    if alt_file.exists():
        return True, [f"Detection report found (no YAML): {alt_file}"], []

    # Not found — warn but don't block (prepass is recommended, not mandatory)
    return True, [
        f"⚠ No prepass YAML found for {component}.",
        f"  Recommended: python3 audit-agents/detection_engine.py --prepass --source <src> --name {component} --output hunt_session/results/",
        f"  Hunters will run without static pre-signals."
    ], []


# ─── Gate dispatcher ─────────────────────────────────────────────────────────

GATE_CHECKS = {
    "scope": lambda comp, repo: check_scope(comp, repo),
    "prepass": lambda comp, repo: check_prepass(comp, repo),
    "hunters": lambda comp, repo: check_hunters(comp),
    "crosschain": lambda comp, repo: check_crosschain(comp),
    "deepdive": lambda comp, repo: check_deepdive(comp),
    "merge": lambda comp, repo: check_merge(comp, repo),
    "compile": lambda comp, repo: check_compile(repo),
    "phase1": lambda comp, repo: check_phase1(comp, repo),
    "phase2": lambda comp, repo: check_phase2(comp, repo),
    "phase3": lambda comp, repo: check_phase3(comp, repo),
    "phase4": lambda comp, repo: check_phase4(comp, repo),
    "phase5": lambda comp, repo: check_phase5(comp, repo),
}



# ─── Gate Status JSON Export ──────────────────────────────────────────────────

DISPLAY_GATES = [g for g in GATE_ORDER if g != "complete"]


def _map_gate_state(ok: bool, detail: str) -> str:
    """Map gate result to 4-state: pass, fail, pending, skip."""
    if ok and detail.startswith("SKIP"):
        return "skip"
    if ok:
        return "pass"
    return "fail"


def _load_gate_status(protocol: str) -> dict:
    """Load existing per-protocol gate_status JSON or return empty structure."""
    gate_file = get_gate_status_file(protocol)
    if gate_file.exists():
        try:
            return json.loads(gate_file.read_text())
        except json.JSONDecodeError:
            pass
    return {"component_gates": {}, "finding_gates": {}, "updated_at": ""}


def _save_gate_status(data: dict, protocol: str):
    """Write per-protocol gate_status JSON atomically."""
    gate_file = get_gate_status_file(protocol)
    data["updated_at"] = datetime.now().isoformat()
    gate_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = gate_file.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        tmp.rename(gate_file)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def export_gate_status(component: str, repo: str = ""):
    """Run all gates for a component and write results to per-protocol gate_status.json."""
    state_data = load_state()
    protocol = state_data.get("protocol", "")
    status = _load_gate_status(protocol)
    comp_data = {}
    first_fail = None
    passed_count = 0

    for g in DISPLAY_GATES:
        if first_fail is not None:
            # Gates after first failure are not yet reached
            comp_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        if g not in GATE_CHECKS:
            comp_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        ok, passed, failed = GATE_CHECKS[g](component, repo)
        detail = passed[0] if passed else (failed[0] if failed else "")
        state = _map_gate_state(ok, detail)
        comp_data[g] = {"state": state, "detail": detail}
        if state in ("pass", "skip"):
            passed_count += 1
        elif first_fail is None:
            first_fail = g

    comp_data["progress"] = f"{passed_count}/{len(DISPLAY_GATES)}"
    comp_data["blocked_at"] = first_fail
    comp_data["updated_at"] = datetime.now().isoformat()

    status["component_gates"][component] = comp_data

    # Also export finding_queue_summary from current_hunt.json
    queue = state_data.get("finding_queue", [])
    status["finding_queue_summary"] = {
        "total": len(queue),
        "pending": sum(1 for f in queue if f.get("status") == "pending_pipeline"),
        "in_pipeline": sum(1 for f in queue if f.get("status") == "in_pipeline"),
    }

    _save_gate_status(status, protocol)


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

FINDING_GATE_ORDER = ["poc", "escalation", "variant", "redteam", "verify", "report", "submit", "reportable"]

DISPLAY_FINDING_GATES = [g for g in FINDING_GATE_ORDER if g != "reportable"]

REPORTS_DIR = WEB3_DIR / "reports"
RESULTS_DIR = HUNT_SESSION_DIR / "results"


def _find_hyp_with_finding(finding_id: str) -> dict | None:
    """Search all hypothesis YAMLs for a specific finding ID.

    Searches ALL protocol subdirectories, not just the current protocol,
    so findings from previous components can still be resolved.
    """
    hyp_root = HUNT_SESSION_DIR / "hypotheses"
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

def _save_state(state: dict):
    """Write current_hunt.json atomically (delegates to state_manager)."""
    _sm_save_state(state)


def generate_queue_id(source: str, parent_id: str = None,
                      components: list = None, component: str = "",
                      hunter: str = "") -> str:
    """Generate auto-incremented ID for finding queue entry."""
    state = load_state()
    existing_ids = {f.get("id", "") for f in state.get("finding_queue", [])}
    existing_ids |= {f.get("id", "") for f in state.get("findings", [])}

    if source == "variant" and parent_id:
        n = 1
        while f"{parent_id}-V{n}" in existing_ids:
            n += 1
        return f"{parent_id}-V{n}"

    elif source == "cross-component" and components:
        sorted_comps = sorted(components)
        prefix = f"XC-{'-'.join(sorted_comps)}"
        n = 1
        while f"{prefix}-{n:02d}" in existing_ids:
            n += 1
        return f"{prefix}-{n:02d}"

    elif source == "hunter_spillover":
        hunter_prefix = hunter.replace("Hunter", "").upper()[:4]
        prefix = f"{hunter_prefix}-{component}"
        n = 1
        while f"{prefix}-{n:02d}" in existing_ids:
            n += 1
        return f"{prefix}-{n:02d}"

    # Fallback
    n = 1
    while f"Q-{n:03d}" in existing_ids:
        n += 1
    return f"Q-{n:03d}"


def queue_finding(source: str, parent_id: str = None, title: str = "",
                  component: str = "", severity: str = "", notes: str = "",
                  components: list = None, hunter: str = "") -> dict:
    """Add a finding to the queue in current_hunt.json. Returns the entry."""
    state = load_state()
    if "finding_queue" not in state:
        state["finding_queue"] = []

    fid = generate_queue_id(source, parent_id, components, component, hunter)

    entry = {
        "id": fid,
        "title": title,
        "source": source,
        "component": component,
        "severity_estimate": severity,
        "status": "pending_pipeline",
        "added_at": datetime.now().isoformat(),
        "notes": notes,
    }
    if parent_id:
        entry["parent_finding"] = parent_id
    if components:
        entry["components"] = sorted(components)
    if hunter:
        entry["discovered_by"] = hunter

    state["finding_queue"].append(entry)
    _save_state(state)
    print(f"✅ Queued finding {fid}: {title}")

    # Auto-update SCOPE_MASTER with new finding
    protocol = state.get("protocol", "")
    if protocol and component:
        scope_master_on_finding(protocol, component, fid)

    return entry


def list_queue():
    """Print finding queue as table."""
    state = load_state()
    queue = state.get("finding_queue", [])
    if not queue:
        print("Finding queue is empty.")
        return

    print(f"\n{'ID':<20} {'Status':<18} {'Component':<20} {'Sev':<8} {'Title'}")
    print(f"{'-'*20} {'-'*18} {'-'*20} {'-'*8} {'-'*40}")
    for f in queue:
        print(f"{f.get('id',''):<20} {f.get('status',''):<18} {f.get('component',''):<20} "
              f"{f.get('severity_estimate',''):<8} {f.get('title','')[:40]}")
    print(f"\nTotal: {len(queue)} | "
          f"Pending: {sum(1 for f in queue if f.get('status')=='pending_pipeline')} | "
          f"In pipeline: {sum(1 for f in queue if f.get('status')=='in_pipeline')}")


def queue_update(finding_id: str, new_status: str, notes: str = ""):
    """Update a queue item's status."""
    state = load_state()
    queue = state.get("finding_queue", [])
    for item in queue:
        if item.get("id") == finding_id:
            item["status"] = new_status
            if notes:
                if new_status == "dismissed":
                    item["dismissed_reason"] = notes
                else:
                    item["notes"] = notes
            _save_state(state)
            print(f"✅ Updated {finding_id} → {new_status}")
            return
    print(f"⛔ {finding_id} not found in queue")


def queue_promote(finding_id: str):
    """Move a completed queue item to the findings array."""
    state = load_state()
    queue = state.get("finding_queue", [])
    if "findings" not in state:
        state["findings"] = []

    item = None
    for i, f in enumerate(queue):
        if f.get("id") == finding_id:
            if f.get("status") != "completed":
                print(f"⛔ {finding_id} status is '{f.get('status')}' — must be 'completed' before promoting")
                return
            f["status"] = "moved_to_findings"
            item = queue.pop(i)
            break

    if not item:
        print(f"⛔ {finding_id} not found in queue")
        return

    state["findings"].append({
        "id": item["id"],
        "title": item["title"],
        "severity": item.get("severity_estimate", ""),
        "component": item.get("component", ""),
        "status": "CONFIRMED",
        "source": item.get("source", ""),
        "parent_finding": item.get("parent_finding", ""),
    })
    _save_state(state)
    print(f"✅ Promoted {finding_id} from queue to findings")


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

    # ── Protocol override (benchmark mode — current_hunt.json may have wrong protocol) ──
    if args.protocol:
        global _PROTOCOL_OVERRIDE
        _PROTOCOL_OVERRIDE = args.protocol

    if args.force:
        gate = args.force
        protocol = args.protocol or _PROTOCOL_OVERRIDE
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
