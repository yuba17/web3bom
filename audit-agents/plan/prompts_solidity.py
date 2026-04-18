"""Solidity phase prompt builders — extracted from plan_generator.py in Phase 6.

Rompe el ciclo lazy plan_generator → run_benchmark: estos 9 phase_*_prompt
importaban los prompt builders de run_benchmark via lazy imports dentro
de las funciones. Ahora importan top-level desde benchmark.prompt_builders.

Consumers: plan_generator (re-export shim).
"""
from __future__ import annotations

import sys
from pathlib import Path

from plan.detectors import (
    _detect_primary_domain, _read_file_safe, _detect_lang, _src_dir,
    _hyp_dir, _results_dir, _step_id, _fork_sol_snippet,
)
from benchmark.prompt_builders import (
    build_hunter_brief, build_hunter_dispatch_prompt, build_deepdive_prompt,
    build_cross_pair_prompt,
)
from context_enrichment import build_hunter_context

# SCRIPT_DIR is used by phase_findings to locate finding_pipeline.py.
# We resolve it relative to THIS file's parent (audit-agents/).
SCRIPT_DIR = Path(__file__).resolve().parent.parent


# ─── 1. phase_hunter_prompt ───────────────────────────────────────────────────

def phase_hunter_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "solidity",
    *,
    domain_override: str = "",
) -> list[dict]:
    """Build hunter brief + dispatch prompt; return one step dict with real prompt."""

    is_rust = (lang == "rust")
    results_dir = _results_dir(session_dir)
    hyp_dir = _hyp_dir(session_dir, protocol)

    if is_rust:
        # lazy — breaks in Task 9 when _phase_hunter_prompt_rust moves to plan.prompts_rust
        from plan_generator import _phase_hunter_prompt_rust
        return _phase_hunter_prompt_rust(component, protocol, repo, session_dir, hyp_dir, results_dir)

    # ── Solidity path — top-level imports above replace the lazy import ──

    src_dir = _src_dir(repo)
    src_file = src_dir / f"{component}.sol"

    # Read source code
    source_code = _read_file_safe(src_file, max_chars=50000)

    # Read prepass signals
    prepass_path = results_dir / f"{component}_prepass.yaml"
    prepass_signals_text = _read_file_safe(prepass_path, max_chars=4000)

    # Read Setup.sol
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    setup_sol_text = _read_file_safe(setup_path, max_chars=5000)

    # Extract variable names from Setup.sol
    setup_var_names = ""
    if setup_sol_text:
        import re
        var_matches = re.findall(
            r'(?:internal|public|private)\s+(\w+)', setup_sol_text
        )
        setup_var_names = ", ".join(set(var_matches)) if var_matches else ""

    # Read interfaces
    interfaces_code = ""
    iface_dir = src_dir / "interfaces"
    if iface_dir.exists():
        for ifile in sorted(iface_dir.glob("*.sol")):
            interfaces_code += _read_file_safe(ifile, max_chars=3000)
            if len(interfaces_code) > 10000:
                break

    # Protocol model (if exists)
    protocol_model = ""
    model_path = Path(session_dir) / "context" / f"{protocol}_model.md"
    if model_path.exists():
        protocol_model = _read_file_safe(model_path, max_chars=3000)

    # F019 + F022 + F024 + F015 + F016 — context enrichment pipeline.
    # Each sub-signal degrades to empty string on failure; the brief
    # still assembles. Domain auto-detection: cheap keyword scan on src.
    detected_domain = domain_override or _detect_primary_domain(source_code) or protocol
    context_block = build_hunter_context(
        contract_path=src_file,
        domain=detected_domain,
        component=component,
        cache_dir=Path(session_dir) / "cache" / "context_enrichment",
    )

    # Build hunter brief
    brief_content = build_hunter_brief(
        component=component,
        protocol=protocol,
        src_file=src_file,
        src_dir=src_dir,
        protocol_model=protocol_model,
        prepass_signals_text=prepass_signals_text,
        setup_sol_text=setup_sol_text,
        setup_var_names=setup_var_names,
        existing_tests_summary="",
        knowledge_context="",
        interfaces_code=interfaces_code,
        accumulated_context="",
        hyp_dir=hyp_dir,
        context_enrichment_block=context_block,
    )

    # Write brief to disk
    brief_path = Path(session_dir) / f"hunter_brief_{component}.md"
    brief_path.parent.mkdir(parents=True, exist_ok=True)
    brief_path.write_text(brief_content, encoding="utf-8")

    # Build dispatch prompt
    dispatch_prompt = build_hunter_dispatch_prompt(
        component=component,
        protocol=protocol,
        src_file=src_file,
        src_dir=src_dir,
        hunter_brief_path=brief_path,
        hyp_dir=hyp_dir,
    )

    return [{
        "step_id": _step_id(component, "hunters"),
        "prompt": dispatch_prompt,
    }]


# ─── 2. phase_deepdive_prompt ─────────────────────────────────────────────────

def phase_deepdive_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "solidity",
) -> list[dict]:
    """Build DeepDive prompt from hunter convergences; return one step dict."""

    is_rust = (lang == "rust")
    hyp_dir = _hyp_dir(session_dir, protocol)

    if is_rust:
        # lazy — breaks in Task 9
        from plan_generator import _rust_crate_sources, _find_rust_crate_src
        source_code = _rust_crate_sources(repo, component)
        library_code = ""  # Rust deps are read from other crates
        setup_sol_text = ""
        src_file = _find_rust_crate_src(repo, component)
    else:
        # ── Solidity path — top-level import above replaces the lazy import ──
        src_dir = _src_dir(repo)
        src_file = src_dir / f"{component}.sol"
        source_code = _read_file_safe(src_file, max_chars=50000)
        library_code = ""
        lib_dir = src_dir / "libraries"
        if lib_dir.exists():
            for lfile in sorted(lib_dir.glob("*.sol")):
                library_code += _read_file_safe(lfile, max_chars=5000)
                if len(library_code) > 20000:
                    break
        setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
        setup_sol_text = _read_file_safe(setup_path, max_chars=5000)

    # Protocol model
    protocol_model = ""
    model_path = Path(session_dir) / "context" / f"{protocol}_model.md"
    if model_path.exists():
        protocol_model = _read_file_safe(model_path, max_chars=3000)

    # Digest hunter convergences (same logic as run_benchmark.py lines 1609-1634)
    hunter_digest = ""
    convergence_map: dict[str, list[str]] = {}

    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    if _yaml:
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
            if "DeepDive" in hyp_file.name or "CrossChain" in hyp_file.name:
                continue
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
                hyps = data.get("hypotheses", data.get("invariants", []))
                for h in hyps:
                    if h.get("confidence", 0) >= 50 and h.get("tier", 3) <= 2:
                        desc = h.get("description", h.get("title", ""))
                        area = h.get("type", "unknown")
                        hunter_digest += (
                            f"- [{hunter_name}] (tier={h.get('tier')}, "
                            f"conf={h.get('confidence')}%) {desc}\n"
                        )
                        convergence_map.setdefault(area, []).append(hunter_name)
            except Exception:
                pass

    convergence_text = ""
    for area, hunters in convergence_map.items():
        if len(hunters) >= 2:
            convergence_text += (
                f"- **{area}**: flagged by {', '.join(set(hunters))} "
                f"— INVESTIGATE DEEPER\n"
            )

    # Cross-hints: scan hypotheses from OTHER components (written by sibling group agents
    # to the shared hyp_dir). If Strategy's hunters found something affecting Leverager,
    # DeepDive for Leverager gets that signal. No messaging needed — filesystem is shared.
    cross_hints = ""
    if _yaml:
        comp_lower = component.lower()
        for hyp_file in sorted(hyp_dir.glob("hyp_*.yaml")):
            # Skip own component's files
            if f"hyp_{component}_" in hyp_file.name:
                continue
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                sibling_comp = hyp_file.stem.split("_")[1]  # hyp_Strategy_MathHunter → Strategy
                hyps = data.get("hypotheses", data.get("invariants", []))
                for h in hyps:
                    desc = (h.get("description", "") + " " + h.get("title", "")).lower()
                    # Include if it mentions our component by name
                    if comp_lower in desc and h.get("confidence", 0) >= 60:
                        cross_hints += (
                            f"- [{sibling_comp}→{component}] (conf={h.get('confidence')}%) "
                            f"{h.get('title', h.get('description', ''))}\n"
                        )
            except Exception:
                pass

    # Build the prompt
    cross_hints_section = ""
    if cross_hints:
        cross_hints_section = (
            f"## Cross-Component Signals (from sibling component hunters)\n"
            f"These hypotheses from OTHER components mention {component}. "
            f"Investigate the interaction surface — the bug may live HERE.\n"
            f"{cross_hints}\n\n"
        )

    if is_rust:
        deepdive_prompt = (
            f"You are DeepDiveHunter analyzing {component} of {protocol} [RUST/SOROBAN].\n\n"
            f"## Source Code (Rust)\n```rust\n{source_code}\n```\n\n"
            f"## Protocol Model\n{protocol_model[:3000]}\n\n"
            f"## Pre-Digested Hunter Convergences\n{convergence_text or 'No convergences detected.'}\n\n"
            f"## Hunter Hypothesis Summary (tier 1-2 only)\n{hunter_digest[:8000]}\n\n"
            f"{cross_hints_section}"
            f"## SOROBAN-SPECIFIC DEEP DIVE\n"
            f"- Trace ALL cross-contract calls: what assumptions does this component make about called contracts?\n"
            f"- Check EVERY storage write: is TTL extended? Can entries expire at a critical moment?\n"
            f"- Check EVERY auth call: is require_auth() called for ALL privileged paths?\n"
            f"- Check bytes32 ↔ Address conversions: truncation, padding, zero-extension correctness\n"
            f"- Check nonce handling: can messages be replayed? Is ordering enforced correctly?\n"
            f"- Check multisig: threshold changes, signer rotation edge cases\n\n"
            f"Write hypotheses to: {hyp_dir}/hyp_{component}_DeepDiveHunter.yaml\n"
            f"No artificial limit. Confidence >= 60% for validated: true.\n"
            f"Each hypothesis MUST have rust_test field and vulnerable_location."
        )
    else:
        # ── Solidity path — top-level import above replaces the lazy import ──
        # Inject cross-hints into convergence text so DeepDive sees them
        enriched_convergence = convergence_text
        if cross_hints:
            enriched_convergence += (
                f"\n### Cross-Component Signals (from sibling hunters)\n"
                f"These hypotheses from OTHER components mention {component}. "
                f"The bug may live in {component}'s handling of the interaction.\n"
                f"{cross_hints}"
            )
        deepdive_prompt = build_deepdive_prompt(
            component=component,
            protocol=protocol,
            source_code=source_code,
            library_code=library_code,
            setup_sol_text=setup_sol_text,
            protocol_model=protocol_model,
            hyp_dir=hyp_dir,
            convergence_text=enriched_convergence,
            hunter_digest=hunter_digest,
        )

    return [{
        "step_id": _step_id(component, "deepdive"),
        "prompt": deepdive_prompt,
    }]


# ─── 3. phase_findings ───────────────────────────────────────────────────────

def phase_findings(
    component: str, protocol: str, repo: str, session_dir: str,
    benchmark_mode: str = "redteam",
    chain: str = "mainnet",
    fork_block: int = 0,
    lang: str = "solidity",
    parallel_components: int = 1,
) -> list[dict]:
    """Emit triage pipeline steps via finding_pipeline.py CLI phases.

    benchmark_mode controls which stages are emitted:
    - "hypothesis": skip entire finding pipeline (scoring against raw YAMLs)
    - "poc"/"redteam": emit triage chain (dedup → verify → PoC → Capa 2+3 → RedTeam)

    Solidity: delegates to finding_pipeline.py phase chain.
    Rust: uses existing inline logic (_phase_findings_rust).
    """

    # In hypothesis mode, scoring happens against YAML files directly — no finding pipeline
    if benchmark_mode == "hypothesis":
        return [{"status": "hypothesis_mode_skip", "component": component}]

    is_rust = (lang == "rust")
    if is_rust:
        # Rust path: collect findings inline, delegate to _phase_findings_rust
        # lazy — breaks in Task 9
        from plan_generator import _phase_findings_rust
        hyp_dir = _hyp_dir(session_dir, protocol)
        findings: list[dict] = []
        try:
            import yaml as _yaml
        except ImportError:
            return []
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
                hyps = data.get("hypotheses", data.get("findings", data.get("invariants", [])))
                for h in (hyps or []):
                    if not isinstance(h, dict):
                        continue
                    if h.get("confidence", 0) >= 70 and h.get("validated", False):
                        h["hunter"] = hunter_name
                        h["component"] = component
                        findings.append(h)
            except Exception:
                pass
        if not findings:
            return [{"status": "no_findings", "component": component}]
        src_dir = _src_dir(repo, lang, component)
        return _phase_findings_rust(findings, component, protocol, repo, session_dir, benchmark_mode, src_dir)

    # ── Solidity path: delegate to finding_pipeline.py triage chain ──
    # Phase 1: dedup emits verify agents + post-verify chain dynamically
    pipeline_cmd = f"{sys.executable} {SCRIPT_DIR / 'finding_pipeline.py'}"
    steps_out: list[dict] = [{
        "id": _step_id(component, "triage_dedup"),
        "type": "generate",
        "description": f"Triage Phase 1: dedup {component} hypotheses",
        "command": (
            f"{pipeline_cmd} --phase dedup "
            f"--component {component} --protocol {protocol} "
            f"--session-dir {session_dir} --repo {repo} "
            f"--threshold 65 --lang {lang}"
        ),
        "timeout": 120,
    }]

    # If benchmark_mode includes PoC/RedTeam, add a dedicated agent step
    # that drives the full finding pipeline chain (verify → PoC → RedTeam).
    # This is more reliable than depending on the executor to follow the
    # deep generate→agent→generate chain produced by dedup.
    if benchmark_mode in ("poc", "redteam"):
        poc_prompt = (
            f"You are a finding pipeline executor for {component} in the {protocol} protocol.\n\n"
            f"## Mission\n"
            f"Execute the FULL finding pipeline for {component}. The dedup phase has already run.\n"
            f"Triage groups are at: {session_dir}/triage/{component}_groups.json\n\n"
            f"## Steps to execute IN ORDER:\n\n"
            f"### 1. Verify each finding candidate\n"
            f"For each dedup group with confidence >= 65%, read the source code and determine:\n"
            f"- Is this a REAL bug or a FALSE_POSITIVE?\n"
            f"- Write verdict to: {session_dir}/triage/{component}_verify_{{id}}.json\n"
            f"  Format: {{\"finding_id\": \"...\", \"verdict\": \"REAL\"|\"FALSE_POSITIVE\", \"reason\": \"...\"}}\n\n"
            f"Source code is at: {repo}/src/ (or {repo}/yieldoor/src/ if present)\n\n"
            f"### 2. Generate PoC for each REAL finding\n"
            f"For each finding with verdict=REAL:\n"
            f"- Write a Foundry PoC test that demonstrates the bug\n"
            f"- Save to: {session_dir}/triage/{component}_poc_{{id}}.sol\n"
            f"- Run: cd {repo} && forge test --match-test test_poc_{{id}} -vv 2>&1\n"
            f"- Write result to: {session_dir}/triage/{component}_poc_{{id}}.json\n"
            f"  Format: {{\"finding_id\": \"...\", \"poc_passed\": true/false, \"output\": \"...\"}}\n\n"
        )
        if benchmark_mode == "redteam":
            poc_prompt += (
                f"### 3. RedTeam each finding with PoC\n"
                f"For each finding with poc_passed=true, evaluate:\n"
                f"- Is the PoC convincing? Does it demonstrate real loss?\n"
                f"- Severity assessment: Critical/High/Medium/Low\n"
                f"- Write verdict to: {session_dir}/triage/{component}_redteam_{{id}}.json\n"
                f"  Format: {{\"finding_id\": \"...\", \"verdict\": \"REPORT\"|\"REJECT\", "
                f"\"severity\": \"...\", \"reason\": \"...\"}}\n\n"
            )
        poc_prompt += (
            f"### Final: Write summary\n"
            f"Write final summary to: {session_dir}/triage/{component}_pipeline_complete.json\n"
            f"Format: {{\"component\": \"{component}\", \"verified\": N, \"poc_passed\": N, "
            f"\"redteam_report\": N, \"redteam_reject\": N}}\n"
        )
        steps_out.append({
            "id": _step_id(component, "finding_pipeline"),
            "type": "agent",
            "description": f"Full finding pipeline (verify+PoC+RedTeam) for {component}",
            "prompt": poc_prompt,
            "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            "depends_on": [_step_id(component, "triage_dedup")],
            "timeout": 3600,
            "retry": 1,
        })

    return steps_out


# ─── 4. phase_fork_poc_prompt ─────────────────────────────────────────────────

def phase_fork_poc_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    finding_id: str,
    chain: str = "mainnet",
    fork_block: int = 0,
    parallel_components: int = 1,
) -> list[dict]:
    """Build Fork PoC prompt for a specific finding. Called dynamically mid-execution.

    Reads the finding from hypothesis YAMLs, builds a detailed fork PoC prompt
    that uses real fork (ETH_RPC_URL) for individual test confirmation.
    """

    hyp_dir = _hyp_dir(session_dir, protocol)
    src_dir = _src_dir(repo)

    try:
        import yaml as _yaml
    except ImportError:
        return [{"error": "PyYAML not installed"}]

    # Find the specific finding across all hypothesis files
    finding = None
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        try:
            data = _yaml.safe_load(hyp_file.read_text())
            if not data:
                continue
            hyps = data.get("hypotheses", data.get("findings", data.get("invariants", [])))
            for h in (hyps or []):
                if isinstance(h, dict) and h.get("id") == finding_id:
                    finding = h
                    break
            if finding:
                break
        except Exception:
            pass

    if not finding:
        return [{
            "step_id": f"{component}:fork_poc:{finding_id}",
            "prompt": (
                f"Finding {finding_id} not found in hypothesis files for {component}. "
                f"Skip this PoC — no action needed."
            ),
        }]

    # Read source code for context
    source_code = _read_file_safe(src_dir / f"{component}.sol", max_chars=30000)

    # Read existing test patterns from the project
    existing_test_code = ""
    test_dir = Path(repo) / "test"
    if test_dir.exists():
        for tf in sorted(test_dir.glob("*.sol"))[:2]:
            content = _read_file_safe(tf, max_chars=3000)
            existing_test_code += f"\n// === {tf.name} ===\n{content}\n"

    # Read foundry.toml for RPC config
    foundry_toml = _read_file_safe(Path(repo) / "foundry.toml", max_chars=2000)

    title = finding.get("title", finding.get("description", "N/A"))
    severity = finding.get("severity", "Unknown")
    description = finding.get("description", "N/A")
    attack = finding.get("attack_scenario", "N/A")
    solidity = finding.get("solidity", "")
    confidence = finding.get("confidence", 0)

    # Ensure shared ForkSetup.sol exists (one fork for all PoCs)
    poc_dir = Path(repo) / "test" / "poc"
    fork_setup_path = poc_dir / "ForkSetup.sol"
    env_path = Path(repo).parent.parent / ".env"

    block_label = f"block {fork_block}" if fork_block > 0 else "latest block"
    fork_snippet = _fork_sol_snippet(chain, fork_block)

    fork_setup_note = ""
    if not fork_setup_path.exists():
        fork_setup_note = (
            f"## FIRST: Create the shared ForkSetup base\n"
            f"Create `{fork_setup_path}` with this EXACT content:\n"
            f"```solidity\n"
            f"// SPDX-License-Identifier: UNLICENSED\n"
            f"pragma solidity ^0.8.13;\n\n"
            f"import \"forge-std/Test.sol\";\n\n"
            f"abstract contract ForkSetup is Test {{\n"
            f"    uint256 internal forkId;\n\n"
            f"    function setUp() public virtual {{\n"
            f"        {fork_snippet}\n"
            f"    }}\n"
            f"}}\n"
            f"```\n\n"
            f"This creates ONE fork at {block_label}. Foundry caches all RPC responses\n"
            f"in ~/.foundry/cache/rpc/ — so the first test fills the cache, and ALL subsequent\n"
            f"tests reuse it with ~0 extra RPC calls.\n\n"
        )
    else:
        fork_setup_note = (
            f"## ForkSetup base already exists\n"
            f"Inherit from `ForkSetup` at `{fork_setup_path}`.\n"
            f"Call `super.setUp()` in your setUp to get the fork.\n\n"
        )

    poc_prompt = (
        f"Write a Foundry Fork PoC test for this finding in {component} ({protocol}).\n\n"
        f"## Finding\n"
        f"- ID: {finding_id}\n"
        f"- Title: {title}\n"
        f"- Severity: {severity}\n"
        f"- Confidence: {confidence}%\n"
        f"- Description: {description}\n"
        f"- Attack scenario: {attack}\n\n"
        f"## Invariant (from Phase 1 mock fuzzing)\n"
        f"```solidity\n{solidity}\n```\n\n"
        f"## Source Code ({component}.sol)\n"
        f"```solidity\n{source_code}\n```\n\n"
        f"## Project Test Patterns (how THEY set up tests)\n"
        f"```solidity\n{existing_test_code[:6000]}\n```\n\n"
        f"## foundry.toml\n```toml\n{foundry_toml}\n```\n\n"
        f"{fork_setup_note}"
        f"## Instructions\n"
        f"1. Create `{poc_dir}/PoC_{finding_id}.t.sol`\n"
        f"2. Inherit from ForkSetup: `contract PoC_{finding_id} is ForkSetup`\n"
        f"3. Override setUp(): call `super.setUp()` FIRST, then deploy/configure contracts\n"
        f"4. Copy deployment patterns from the project's own tests above\n"
        f"5. The test MUST:\n"
        f"   - Use the fork state from ForkSetup ({block_label})\n"
        f"   - Execute the exact attack described in the finding\n"
        f"   - Assert that funds are lost / invariant is broken\n"
        f"   - Use `assertGt/assertLt/assertEq` with descriptive messages\n"
        f"   - Name the test function `test_poc_{finding_id}()`\n"
        f"6. Run: `source {env_path} && "
        f"cd {repo} && forge test --match-test test_poc_{finding_id} -vvv{' --jobs 3' if parallel_components > 1 else ''}`\n"
        f"   This runs ONLY this one test. Chimera tests in test/chimera/ are NOT matched.\n"
        f"7. If the test passes → write to {session_dir}/poc_{finding_id}.json:\n"
        f"   {{\"finding_id\": \"{finding_id}\", \"poc_passed\": true, "
        f"\"poc_path\": \"test/poc/PoC_{finding_id}.t.sol\", \"output\": \"...\"}}\n"
        f"8. If the test fails → same format with poc_passed=false\n\n"
        f"IMPORTANT:\n"
        f"- Do NOT use --fork-url CLI flag — fork is managed by ForkSetup.sol.\n"
        f"- Do NOT create your own fork with createSelectFork — use the inherited one.\n"
        f"- Do NOT inherit from test/chimera/ — PoCs are self-contained.\n"
        f"- All PoCs share the SAME fork + cache. First PoC fills cache, rest are instant."
    )

    return [{
        "step_id": f"{component}:fork_poc:{finding_id}",
        "prompt": poc_prompt,
    }]


# ─── 5. phase_cross_prompt ────────────────────────────────────────────────────

def phase_cross_prompt(
    components_str: str, protocol: str, repo: str, session_dir: str,
    lang: str = "solidity",
) -> list[dict]:
    """Build cross-component pair prompt; return one step dict."""

    parts = components_str.split(",")
    if len(parts) != 2:
        return [{"error": f"Expected 2 components, got {len(parts)}"}]

    comp_a, comp_b = parts[0].strip(), parts[1].strip()
    lang = lang or _detect_lang(repo)
    hyp_dir = _hyp_dir(session_dir, protocol)
    pair_tag = f"{comp_a}_{comp_b}"
    pair_file = hyp_dir / f"cross_{comp_a}_{comp_b}.yaml"

    if lang == "rust":
        # lazy — breaks in Task 9
        from plan_generator import _phase_cross_prompt_rust
        return _phase_cross_prompt_rust(
            comp_a, comp_b, protocol, repo, session_dir, hyp_dir, pair_file,
        )

    # ── Solidity path — top-level import above replaces the lazy import ──
    src_dir = _src_dir(repo)

    # Read interfaces for each component
    iface_a = _read_file_safe(src_dir / f"{comp_a}.sol", max_chars=5000)
    iface_b = _read_file_safe(src_dir / f"{comp_b}.sol", max_chars=5000)

    # Find cross-calls (simple grep for component references)
    cross_calls = ""
    for comp, other in [(comp_a, comp_b), (comp_b, comp_a)]:
        src_file = src_dir / f"{comp}.sol"
        code = _read_file_safe(src_file)
        if code:
            for line in code.splitlines():
                if other.lower() in line.lower() and ("." in line or "(" in line):
                    cross_calls += f"  {comp} → {other}: {line.strip()}\n"

    prompt = build_cross_pair_prompt(
        comp_a=comp_a,
        comp_b=comp_b,
        iface_a=iface_a,
        iface_b=iface_b,
        cross_calls=cross_calls or "No direct cross-calls found — check for shared state.",
        src_dir=src_dir,
        pair_file=pair_file,
    )

    return [{
        "step_id": f"cross:{pair_tag}:analyze",
        "prompt": prompt,
    }]


# ─── 6. phase_transitive_chain_prompt ─────────────────────────────────────────

def phase_transitive_chain_prompt(
    components_str: str,
    protocol: str,
    repo: str,
    session_dir: str,
    lang: str = "solidity",
) -> list[dict]:
    """Build transitive chain prompt for (a, mid, c) triples.

    Components come in as 'A,B,C' where B is the middle component. The
    caller has already confirmed A↔C is NOT a direct edge (chain detector
    dedups those). The prompt asks the EdgeHunter to find bugs that
    require the full A→B→C chain.
    """
    parts = [p.strip() for p in components_str.split(",")]
    if len(parts) != 3:
        return [{"error": f"Expected 3 components, got {len(parts)}"}]

    comp_a, comp_mid, comp_c = parts
    abbreviation = f"{comp_a[:2]}{comp_mid[:2]}{comp_c[:2]}".upper()

    hyp_dir = _hyp_dir(session_dir, protocol)
    chain_file = hyp_dir / f"hyp_{comp_a}_{comp_mid}_{comp_c}_EdgeHunter.yaml"

    src_dir = _src_dir(repo)
    iface_a = _read_file_safe(src_dir / f"{comp_a}.sol", max_chars=4000)
    iface_mid = _read_file_safe(src_dir / f"{comp_mid}.sol", max_chars=4000)
    iface_c = _read_file_safe(src_dir / f"{comp_c}.sol", max_chars=4000)

    prompt = (
        f"# EdgeHunter — Transitive Chain: {comp_a}→{comp_mid}→{comp_c}\n\n"
        f"## Identity\n"
        f"You are the EdgeHunter for {protocol}. Find bugs that ONLY exist when\n"
        f"{comp_a}, {comp_mid}, and {comp_c} interact in a chain. {comp_a}↔{comp_mid}\n"
        f"and {comp_mid}↔{comp_c} are direct edges; {comp_a}↔{comp_c} is NOT —\n"
        f"they communicate only through {comp_mid}.\n\n"
        f"## Interaction Map: {comp_a} ↔ {comp_mid}\n"
        f"```solidity\n"
        f"// {comp_a}.sol\n"
        f"{iface_a}\n\n"
        f"// {comp_mid}.sol (as seen from {comp_a})\n"
        f"{iface_mid}\n"
        f"```\n\n"
        f"## Interaction Map: {comp_mid} ↔ {comp_c}\n"
        f"```solidity\n"
        f"// {comp_mid}.sol (as seen from {comp_c})\n"
        f"{iface_mid}\n\n"
        f"// {comp_c}.sol\n"
        f"{iface_c}\n"
        f"```\n\n"
        f"## Checklist\n\n"
        f"### 1. Transitive state manipulation\n"
        f"- Can an attacker use {comp_a} to change state in {comp_mid} that {comp_c}\n"
        f"  then consumes as trusted?\n"
        f"- Is the reverse path ({comp_c} → {comp_mid} → {comp_a}) also exploitable?\n\n"
        f"### 2. Trust chain breaks\n"
        f"- {comp_c} trusts {comp_mid}. {comp_mid} trusts {comp_a}. Can {comp_a}\n"
        f"  abuse this transitive trust?\n\n"
        f"### 3. Multi-tx attack sequences\n"
        f"- Is there a 3+ tx sequence that crosses all three components and extracts\n"
        f"  value? Does flash loan amplify any path?\n\n"
        f"## Output\n"
        f"Write to: `{chain_file}`\n\n"
        f"```yaml\n"
        f"hunter: EdgeHunter\n"
        f"component: \"{comp_a}_{comp_mid}_{comp_c}\"\n"
        f"invariants:\n"
        f"  - id: {abbreviation}-CH-01\n"
        f"    description: \"...\"\n"
        f"    solidity: |\n"
        f"      // Uses crossContractA, crossContractB, crossContractC\n"
        f"    call_stack: \"...\"\n"
        f"    confidence: 70\n"
        f"    tier: 1\n"
        f"    type: property\n"
        f"```\n\n"
        f"ID prefix: `{abbreviation}-CH`. No artificial limit. Only emit\n"
        f"invariants that REQUIRE all three components to exploit.\n"
    )
    return [{
        "step_id": f"chain:{comp_a}_{comp_mid}_{comp_c}:analyze",
        "prompt": prompt,
    }]


# ─── 7. phase_chimera_early_prompt ────────────────────────────────────────────

def phase_chimera_early_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    parallel_components: int = 1,
) -> list[dict]:
    """Check if Setup.sol exists; if not, return a step with the full chimera setup prompt.

    Mirrors API mode Step 1.9 (lines 1418-1497 of run_benchmark.py).
    """
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if setup_path.exists():
        # Check if existing Setup.sol uses fork (incompatible with Phase 1 mocks)
        setup_content = _read_file_safe(setup_path)
        # Setup already exists — reuse it (fork with real addresses is OK)
        return [{
            "step_id": _step_id(component, "chimera_early_setup"),
            "prompt": (
                f"Setup.sol already exists at {setup_path}. "
                f"No action needed — proceed to hunter phase."
            ),
        }]

    src_dir = _src_dir(repo)
    src_file = src_dir / f"{component}.sol"
    source_code = _read_file_safe(src_file, max_chars=50000)

    # Read library code
    library_code = ""
    lib_dir = src_dir / "libraries"
    if lib_dir.exists():
        for lfile in sorted(lib_dir.glob("*.sol")):
            library_code += _read_file_safe(lfile, max_chars=5000)
            if len(library_code) > 20000:
                break

    # Read interfaces
    interfaces_code = ""
    iface_dir = src_dir / "interfaces"
    if iface_dir.exists():
        for ifile in sorted(iface_dir.glob("*.sol")):
            interfaces_code += _read_file_safe(ifile, max_chars=3000)
            if len(interfaces_code) > 10000:
                break

    # Read project's own tests
    existing_test_code = ""
    test_dir = Path(repo) / "test"
    if test_dir.exists():
        for tf in sorted(test_dir.glob("*.sol"))[:3]:
            content = _read_file_safe(tf, max_chars=5000)
            existing_test_code += f"\n// === {tf.name} ===\n{content}\n"

    # Read foundry.toml
    foundry_toml = _read_file_safe(Path(repo) / "foundry.toml", max_chars=3000)

    chimera_dir = Path(repo) / "test" / "chimera"

    setup_prompt = (
        f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
        f"## Source Code\n```solidity\n{source_code}\n```\n\n"
        f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
        f"## Interfaces\n```solidity\n{interfaces_code[:10000]}\n```\n\n"
        f"## Project's Own Tests (CRITICAL — shows how THEY deploy the contracts)\n"
        f"```solidity\n{existing_test_code[:8000]}\n```\n\n"
        f"## foundry.toml (remappings, compiler version)\n```toml\n{foundry_toml}\n```\n\n"
        f"Create these files in {chimera_dir}/:\n"
        f"- Setup.sol: abstract contract that deploys {component} with ALL its dependencies.\n"
        f"  COPY the deployment pattern from the project's own tests above — they know their constructor args.\n"
        f"  FORK-FIRST STRATEGY (preferred): Use REAL mainnet addresses for external contracts (Uniswap pools, tokens, oracles).\n"
        f"  The fuzz command runs with `--fork-url` via CLI (Foundry RPC cache makes reruns instant).\n"
        f"  Do NOT use vm.createSelectFork in setUp() — the fork URL is passed via CLI flag, not in code.\n"
        f"  Use `deal(address(token), user, amount)` for token balances on the fork.\n"
        f"  For Uniswap V3 pools: use the REAL deployed pool address — real pool state gives higher fidelity than mocks.\n"
        f"  Do NOT hardcode a specific block number — let Foundry use latest (portable across runs via cache).\n"
        f"  MOCK FALLBACK: If the protocol is pre-launch (no mainnet deployment) or uses non-EVM chains,\n"
        f"  deploy MockERC20 tokens and MockUniswapV3Pool that return controlled values.\n"
        f"  The forge command auto-detects: if ETH_RPC_URL is set → fork mode, otherwise → mock mode.\n"
        f"  MUST define internal variables accessible by Properties: the main contract + tokens + actors.\n"
        f"  Example: `Strategy internal strategy; Vault internal vault; IERC20 internal token0;`\n"
        f"  Define actors: owner, user, depositor, attacker with distinct addresses.\n"
        f"  Do an initial deposit + rebalance so the system is in a realistic state.\n"
        f"  HELPER FUNCTIONS (CRITICAL): Add internal helper functions that wrap complex calls.\n"
        f"  For EVERY public/external function that returns a struct, create a getter helper.\n"
        f"  For EVERY function that requires setup (prank, approve, deal), create an action helper.\n"
        f"  Examples:\n"
        f"    `function _getTotalAssets() internal view returns (uint256) {{ return vault.totalAssets(); }}`\n"
        f"    `function _depositAs(address who, uint256 amt0, uint256 amt1) internal {{ vm.prank(who); vault.deposit(amt0, amt1, 0, 0); }}`\n"
        f"    `function _dealAndDeposit(address who, uint256 amt) internal {{ deal(address(token0), who, amt); vm.prank(who); vault.deposit(amt, 0, 0, 0); }}`\n"
        f"  This lets hunters write simple invariants without worrying about types or setup boilerplate.\n"
        f"  IMPORTS (CRITICAL): Import ALL contracts, interfaces, and libraries the component uses.\n"
        f"  Properties*.sol inherits from Setup, so everything you import here is available to hunters.\n"
        f"  If the component uses Strategy.sol + IStrategy.sol + TickMath.sol, import ALL of them.\n"
        f"  CONSTANTS: Define constants hunters will need:\n"
        f"    `uint256 internal constant DECIMALS0 = 8;  // WBTC`\n"
        f"    `uint256 internal constant DECIMALS1 = 6;  // USDC`\n"
        f"    `uint256 internal constant ONE_TOKEN0 = 10 ** DECIMALS0;`\n"
        f"    `uint256 internal constant ONE_TOKEN1 = 10 ** DECIMALS1;`\n"
        f"  If the protocol defines precision constants (WAD, RAY, PRECISION, BPS), re-expose them.\n"
        f"  ENUMS/STRUCTS: If the component uses enums or structs, add a comment listing them with their values:\n"
        f"    `// Status enum: 0=Inactive, 1=Active, 2=Paused`\n"
        f"    `// VestingPosition struct: (uint256 amount, uint256 start, uint256 end)`\n"
        f"  INTERNAL STATE GETTERS: If the component has internal state that's only accessible via public getters\n"
        f"  that return structs, create simple getters that return individual fields:\n"
        f"    `function _getPositionAmount(uint256 id) internal view returns (uint256) {{ return strategy.positions(id).amount; }}`\n"
        f"- BeforeAfter.sol: ghost variables for state tracking (inherits Setup)\n"
        f"- Properties.sol: empty base (inherits BeforeAfter) — hunters will fill this later\n"
        f"- TargetFunctions.sol: handlers for EACH public/external function with clamped inputs.\n"
        f"  Use `_clampBetween(amount, 1, type(uint128).max)` for amounts.\n"
        f"  Use `vm.prank(actor)` before external calls. Use `_pickActor(seed)` for random actor.\n"
        f"- FoundryTester.sol: inherits Properties, placeholder for invariant_* wrappers\n"
        f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa/Echidna\n\n"
        f"AFTER creating all files, run `forge build{' --jobs 3' if parallel_components > 1 else ''}` to verify compilation.\n"
        f"If it fails, fix the errors and re-run until it compiles.\n"
        f"Use the EXACT same import paths and remappings from foundry.toml."
    )

    return [{
        "step_id": _step_id(component, "chimera_early_setup"),
        "prompt": setup_prompt,
    }]


# ─── 8. phase_chimera_builder_prompt ─────────────────────────────────────────

def phase_chimera_builder_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    parallel_components: int = 1,
) -> list[dict]:
    """Check if full Chimera Setup exists; if not, return setup generation prompt.

    Mirrors API mode Step 5a (lines 1700-1724 of run_benchmark.py).
    """
    chimera_dir = Path(repo) / "test" / "chimera"
    setup_sol = chimera_dir / "Setup.sol"

    if chimera_dir.exists() and setup_sol.exists():
        # Setup exists — verify it compiles (fork with real addresses is OK)
        return [{
            "step_id": _step_id(component, "chimera_builder"),
            "prompt": (
                f"Chimera Setup already exists at {setup_sol}. "
                f"Verify it compiles with `cd {repo} && forge build{' --jobs 3' if parallel_components > 1 else ''}`. "
                f"If compilation fails, fix the errors. Do not rewrite from scratch."
            ),
        }]

    src_dir = _src_dir(repo)
    src_file = src_dir / f"{component}.sol"
    source_code = _read_file_safe(src_file, max_chars=50000)

    # Read library code
    library_code = ""
    lib_dir = src_dir / "libraries"
    if lib_dir.exists():
        for lfile in sorted(lib_dir.glob("*.sol")):
            library_code += _read_file_safe(lfile, max_chars=5000)
            if len(library_code) > 20000:
                break

    chimera_prompt = (
        f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
        f"## Source Code\n```solidity\n{source_code}\n```\n\n"
        f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
        f"Create these files in {chimera_dir}/:\n"
        f"- Setup.sol: deploy {component} with ALL its dependencies using REAL mainnet addresses.\n"
        f"  Forge runs with --fork-url (ETH mainnet, RPC cache). Use real Uniswap pools, real tokens.\n"
        f"  Do NOT use vm.createSelectFork — fork URL is passed via CLI. Do NOT hardcode block numbers.\n"
        f"  Use deal() for token balances on the fork.\n"
        f"  MUST define: contract instance variables accessible by Properties (e.g., `Strategy internal strategy;`)\n"
        f"- BeforeAfter.sol: ghost variables and state snapshots\n"
        f"- Properties.sol: base with ghost vars, inherits BeforeAfter\n"
        f"- TargetFunctions.sol: handlers for each public function with clamped inputs\n"
        f"- FoundryTester.sol: inherits Properties, has invariant_* wrapper functions\n"
        f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa\n\n"
        f"The setup MUST compile with `forge build{' --jobs 3' if parallel_components > 1 else ''}`. Test it after creating."
    )

    return [{
        "step_id": _step_id(component, "chimera_builder"),
        "prompt": chimera_prompt,
    }]


# ─── 9. phase_enhance_targets_prompt ─────────────────────────────────────────

def phase_enhance_targets_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    parallel_components: int = 1,
) -> list[dict]:
    """Build prompt to enhance TargetFunctions with multi-step attack sequences.

    Mirrors API mode Step 7.5 (lines 1930-1989 of run_benchmark.py).
    """
    chimera_dir = Path(repo) / "test" / "chimera"
    target_funcs_path = chimera_dir / "TargetFunctions.sol"
    setup_path = chimera_dir / "Setup.sol"
    hyp_dir = _hyp_dir(session_dir, protocol)

    if not target_funcs_path.exists():
        return [{
            "step_id": _step_id(component, "enhance_targets"),
            "prompt": (
                f"TargetFunctions.sol does not exist at {target_funcs_path}. "
                f"No enhancement needed — proceed."
            ),
        }]

    # Collect high-priority hypotheses
    top_hyps = ""
    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    if _yaml:
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml"))[:5]:
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if data:
                    hyps = data.get("hypotheses", data.get("invariants", []))
                    for h in hyps[:3]:
                        if h.get("tier", 3) <= 2 and h.get("confidence", 0) >= 60:
                            top_hyps += (
                                f"\n- {h.get('id', '?')}: {h.get('description', '')}\n"
                                f"  Attack: {h.get('attack_scenario', '')}\n"
                            )
            except Exception:
                pass

    if not top_hyps:
        return [{
            "step_id": _step_id(component, "enhance_targets"),
            "prompt": (
                f"No high-priority hypotheses found for {component}. "
                f"Skipping TargetFunctions enhancement — proceed."
            ),
        }]

    target_funcs_code = _read_file_safe(target_funcs_path, max_chars=15000)
    setup_sol_text = _read_file_safe(setup_path, max_chars=5000)

    enhance_prompt = (
        f"Enhance the TargetFunctions.sol for {component} with multi-step attack sequences.\n\n"
        f"## Current TargetFunctions\n```solidity\n{target_funcs_code}\n```\n\n"
        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
        f"## High-Priority Attack Scenarios from Hunters\n{top_hyps}\n\n"
        f"## Task\n"
        f"Add 3-5 NEW handler functions that encode MULTI-STEP attack sequences:\n"
        f"1. Flash loan -> deposit -> manipulate -> withdraw sequences\n"
        f"2. Sandwich patterns: frontrun -> victim action -> backrun\n"
        f"3. State manipulation: set up bad state -> trigger vulnerable path\n"
        f"4. Cross-function: call A to set state, call B to exploit it\n\n"
        f"Each handler should:\n"
        f"- Use clamped inputs (bound by `_clampBetween`)\n"
        f"- Prank as attacker where needed\n"
        f"- Be a realistic attack, not random calls\n\n"
        f"ONLY ADD new functions. Do NOT modify or remove existing handlers.\n"
        f"Write changes to: {target_funcs_path}\n"
        f"After editing, run `cd {repo} && forge build{' --jobs 3' if parallel_components > 1 else ''}` to verify compilation.\n"
        f"If it breaks, revert your changes."
    )

    return [{
        "step_id": _step_id(component, "enhance_targets"),
        "prompt": enhance_prompt,
    }]
