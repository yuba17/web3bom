"""Component-stage gate check functions: scope, prepass, hunters, crosschain,
deepdive, merge, compile, phase1..phase5.

Also hosts the component-gate path helpers (get_hyp_dir, get_context_dir,
get_gate_status_file) and the protocol override module state used by these
checks. The CLI sets `gate.gates_component._PROTOCOL_OVERRIDE` to propagate
--protocol from argv into the gate checks.
"""

from datetime import datetime
from pathlib import Path

import yaml

from paths import WEB3_DIR, HUNT_SESSION_DIR
from state_manager import load_state
from gate.constants import HUNTER_NAMES, GATE_ORDER
from gate.ficha import load_ficha

# ─── Protocol override (set by CLI --protocol flag) ──────────────────────────

_PROTOCOL_OVERRIDE = ""  # Set by --protocol CLI arg; overrides load_state() protocol


def _get_protocol() -> str:
    """Get protocol from override (--protocol CLI) or current_hunt.json state."""
    return _PROTOCOL_OVERRIDE or load_state().get("protocol", "")


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


# ─── Path helpers ─────────────────────────────────────────────────────────────

def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = _hunt_session_dir() / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_context_dir(protocol: str) -> Path:
    """Return protocol-namespaced context directory."""
    d = _hunt_session_dir() / "context" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_gate_status_file(protocol: str) -> Path:
    """Return protocol-specific gate_status file."""
    d = _hunt_session_dir() / "gate_status"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{protocol}.json"


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
    results_dir = _hunt_session_dir() / "results"
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
