"""Cross-component hunt orchestration — extracted from run_benchmark.py in Phase 6.

Provides run_cross_component: after 2+ components complete, generates
EdgeHunter prompts for pairs + transitive chains, runs them in parallel,
merges hypotheses, PoC+RedTeams high-confidence findings, then builds
multi-contract chimera fuzzing setup and runs Phase 1/2 fuzzing.

Consumers: benchmark.cli (invoked via --components or --auto-components end-hook).
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from finding_pipeline import POC_CONFIDENCE_THRESHOLD

logger = logging.getLogger("orchestrator")


# ─── Cross-Component Hunt ────────────────────────────────────────────────────

def run_cross_component(components_done: list[str], protocol: str, repo: str,
                        parallel_poc: int = 2) -> list[dict]:
    """Run cross-component analysis + multi-contract fuzzing after 2+ components.
    Returns list of cross-component findings that passed PoC + RedTeam."""
    # Lazy import — avoids circular at load time (run_benchmark re-exports from
    # benchmark.cross_component). Also reads mutable globals (HUNT_SESSION_DIR,
    # LOG_DIR, _llm, component_log_dir, run_cmd, build_cross_pair_prompt,
    # fix_and_retry, generate_and_test_poc, run_finding_pipeline, extract_findings,
    # parse_fuzz_failures) that main() mutates after argparse or tests monkeypatch;
    # top-level import would freeze defaults and break monkeypatching.
    import run_benchmark as _rb  # lazy — avoids circular; reads globals mutated by main()/tests
    if len(components_done) < 2:
        return []
    poc_candidates: list[dict] = []  # populated in Phase A.5; returned at end

    logger.info(f"\n{'='*60}")
    logger.info(f"  CROSS-COMPONENT HUNT: {', '.join(components_done)}")
    logger.info(f"{'='*60}")

    import shutil
    import itertools
    clog = _rb.component_log_dir("cross_component")
    src_dir = Path(repo) / "src"
    chimera_dir = Path(repo) / "test" / "chimera"

    # ─── Phase A: Per-pair hypothesis generation (parallel) ───────────
    # Old approach: dump all N contracts at once → 70k+ chars → Claude times out.
    # New approach: one focused call per pair, using interfaces (not full source).
    logger.info("  Cross-A: Generating interaction hypotheses (per pair)")

    def _read_interface(comp: str) -> str:
        """Read the interface file for a component, fallback to extracting
        function signatures from source if no interface file exists."""
        # Try interface file first (I<Comp>.sol or <Comp>.sol under interfaces/)
        iface_dir = src_dir / "interfaces"
        for name in (f"I{comp}.sol", f"{comp}.sol"):
            p = iface_dir / name
            if p.exists():
                return p.read_text(encoding="utf-8")[:6000]
        # Fallback: extract function signatures from source via regex
        src_files = list(src_dir.glob(f"**/{comp}.sol"))
        if not src_files:
            return ""
        import re as _re
        text = src_files[0].read_text(encoding="utf-8")
        # Extract: state variables (public), function signatures, events, errors
        lines = text.splitlines()
        sigs = []
        in_func = False
        brace_depth = 0
        for line in lines:
            stripped = line.strip()
            # State vars and events/errors — always include
            if _re.match(r'(address|uint|int|bool|bytes|mapping|struct|enum|event|error|I\w+)\s', stripped):
                sigs.append(line)
            # Function signature lines
            elif stripped.startswith("function "):
                sigs.append(line)
                if "{" in line:
                    in_func = True
                    brace_depth = line.count("{") - line.count("}")
            elif in_func:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    in_func = False
        return "\n".join(sigs[:200])  # cap at 200 lines

    def _find_cross_calls(comp_a: str, comp_b: str) -> str:
        """Grep for places where comp_a calls comp_b and vice versa."""
        results = []
        for caller, callee in ((comp_a, comp_b), (comp_b, comp_a)):
            src_files = list(src_dir.glob(f"**/{caller}.sol"))
            if not src_files:
                continue
            text = src_files[0].read_text(encoding="utf-8")
            lines = text.splitlines()
            hits = []
            for i, line in enumerate(lines):
                if callee.lower() in line.lower() or f"I{callee}" in line:
                    ctx_start = max(0, i - 1)
                    ctx_end = min(len(lines), i + 3)
                    hits.append(f"  L{i+1}: " + " | ".join(lines[ctx_start:ctx_end]))
            if hits:
                results.append(f"{caller} → {callee} ({len(hits)} call sites):\n" + "\n".join(hits[:10]))
        return "\n\n".join(results) if results else "No direct cross-calls detected."

    # Each pair writes to its own temp file; at the end we merge into the
    # canonical hyp_CrossComponent_DeepDiveHunter.yaml so extract_findings() finds it.
    hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    canonical_file = hyp_dir / "hyp_CrossComponent_DeepDiveHunter.yaml"

    # Clean up pair files from any previous run to avoid stale data contaminating the merge
    for stale in hyp_dir.glob("hyp_Cross_*.yaml"):
        stale.unlink()
    if canonical_file.exists():
        canonical_file.unlink()

    def _run_pair_hunt(pair: tuple) -> None:
        comp_a, comp_b = pair
        iface_a = _read_interface(comp_a)
        iface_b = _read_interface(comp_b)
        cross_calls = _find_cross_calls(comp_a, comp_b)
        # Temp file per pair — merged into canonical after all pairs complete
        pair_file = hyp_dir / f"hyp_Cross_{comp_a}_{comp_b}.yaml"
        pair_prompt = _rb.build_cross_pair_prompt(
            comp_a=comp_a, comp_b=comp_b, iface_a=iface_a, iface_b=iface_b,
            cross_calls=cross_calls, src_dir=src_dir, pair_file=pair_file
        )
        _rb._llm(
            pair_prompt,
            allowed_tools=["Read", "Write", "Grep", "Glob"],
            timeout=900,
            stall_timeout=600,
            log_file=clog / f"cross_{comp_a}_{comp_b}.log",
            cwd=repo
        )
        logger.info(f"    Cross pair {comp_a}×{comp_b}: done")

    pairs = list(itertools.combinations(components_done, 2))
    logger.info(f"  Cross-A: {len(pairs)} pairs — {', '.join(f'{a}×{b}' for a,b in pairs)}")
    with ThreadPoolExecutor(max_workers=min(3, len(pairs))) as executor:
        list(executor.map(_run_pair_hunt, pairs))

    # Merge all per-pair YAML files into the canonical file that extract_findings() expects.
    # Also builds the combined source needed for the PoC phase below.
    import yaml as _yaml
    merged_findings = []
    for pair_file in sorted(hyp_dir.glob("hyp_Cross_*.yaml")):
        try:
            data = _yaml.safe_load(pair_file.read_text())
            if not data:
                continue
            # Collect from all possible keys — a YAML may have findings + hypotheses
            for key in ("findings", "hypotheses", "invariants"):
                for entry in (data.get(key) or []):
                    if isinstance(entry, dict):
                        merged_findings.append(entry)
        except Exception:
            pass
    if merged_findings:
        canonical_file.write_text(
            _yaml.dump({"hunter": "CrossComponentHunter",
                        "component": "CrossComponent",
                        "findings": merged_findings},
                       allow_unicode=True, sort_keys=False)
        )
        logger.info(f"  Cross-A merged: {len(merged_findings)} findings → {canonical_file.name}")

    # ─── Phase A.2: Transitive chain detection & hunt ────────────────
    from component_discovery import detect_transitive_chains as _detect_chains
    # Filter to pairs with real cross-calls: detect_transitive_chains requires
    # true adjacency (A↔C absent). itertools.combinations yields a complete
    # graph, which would suppress every chain. Only keep pairs where at least
    # one component actually references the other in source.
    _adj_pairs: list[tuple[str, str, list[str]]] = []
    for _a, _b in pairs:
        _calls = _find_cross_calls(_a, _b)
        if _calls and "No direct cross-calls detected" not in _calls:
            _adj_pairs.append((_a, _b, []))
    pair_tuples = _adj_pairs
    chain_triples = _detect_chains(all_pairs=pair_tuples)
    if chain_triples:
        logger.info(f"  Cross-A.2: {len(chain_triples)} transitive chain(s) detected")

        def _run_chain_hunt(triple: tuple) -> None:
            comp_a, comp_mid, comp_c = triple
            iface_a = _read_interface(comp_a)
            iface_mid = _read_interface(comp_mid)
            iface_c = _read_interface(comp_c)
            chain_file = hyp_dir / f"hyp_Chain_{comp_a}_{comp_mid}_{comp_c}.yaml"
            chain_prompt = (
                f"# EdgeHunter — Transitive Chain {comp_a}→{comp_mid}→{comp_c}\n\n"
                f"You are investigating a TRANSITIVE CHAIN attack surface in "
                f"{protocol}. {comp_a}↔{comp_mid} and {comp_mid}↔{comp_c} are "
                f"direct edges; {comp_a}↔{comp_c} is NOT. Find bugs that require "
                f"all three components.\n\n"
                f"## {comp_a} interface\n```solidity\n{iface_a}\n```\n\n"
                f"## {comp_mid} interface\n```solidity\n{iface_mid}\n```\n\n"
                f"## {comp_c} interface\n```solidity\n{iface_c}\n```\n\n"
                f"## Checklist\n"
                f"1. Transitive state manipulation: can {comp_a} influence state "
                f"in {comp_mid} that {comp_c} trusts?\n"
                f"2. Trust chain breaks: {comp_c} trusts {comp_mid}, which trusts "
                f"{comp_a} — does this transitive trust collapse?\n"
                f"3. Multi-tx sequences: is there a 3+ tx attack spanning all "
                f"three? Flash-loan amplification?\n\n"
                f"## Output\nWrite invariants (YAML) to `{chain_file}` with "
                f"hunter='EdgeHunter', component='{comp_a}_{comp_mid}_{comp_c}'.\n"
            )
            _rb._llm(
                chain_prompt,
                allowed_tools=["Read", "Write", "Grep", "Glob"],
                timeout=900,
                stall_timeout=600,
                log_file=clog / f"chain_{comp_a}_{comp_mid}_{comp_c}.log",
                cwd=repo,
            )
            logger.info(f"    Chain {comp_a}→{comp_mid}→{comp_c}: done")

        with ThreadPoolExecutor(max_workers=min(3, len(chain_triples))) as executor:
            list(executor.map(_run_chain_hunt, chain_triples))

        chain_merged: list[dict] = []
        for cf in sorted(hyp_dir.glob("hyp_Chain_*.yaml")):
            try:
                data = _yaml.safe_load(cf.read_text())
                if not data:
                    continue
                for key in ("findings", "hypotheses", "invariants"):
                    for entry in (data.get(key) or []):
                        if isinstance(entry, dict):
                            chain_merged.append(entry)
            except Exception:
                pass
        if chain_merged:
            merged_findings.extend(chain_merged)
            canonical_file.write_text(
                _yaml.dump({"hunter": "CrossComponentHunter",
                            "component": "CrossComponent",
                            "findings": merged_findings},
                           allow_unicode=True, sort_keys=False)
            )
            logger.info(f"  Cross-A.2 merged: {len(chain_merged)} chain findings into canonical")

    # ─── Phase A.5: PoC + RedTeam for cross-component findings ────────
    # Cross-component findings are never PoC'd in the component pipelines.
    # We: (1) generate+test PoC, (2) only send PoC-confirmed to RedTeam.
    if merged_findings:
        # Build combined source from all component .sol files.
        # IMPORTANT: combined_source is NOT injected wholesale into any prompt.
        # It only feeds _extract_relevant_code(), which always outputs max 8K focused.
        # RedTeam/Escalation use focused_code (8K) + file access tools, never raw combined.
        # The cap exists only to bound memory and _extract_relevant_code search time.
        # Strategy: sort ascending by file size — small contracts always included fully;
        # only the largest get truncated if combined total exceeds the cap (rare).
        _CROSS_COMBINED_CAP = 100_000
        _comp_files = []
        for comp in components_done:
            src_files = list(src_dir.glob(f"**/{comp}.sol"))
            if src_files:
                size = src_files[0].stat().st_size
                _comp_files.append((size, comp, src_files[0]))
        _comp_files.sort()  # ascending by size — small contracts enter first, always complete

        combined_source = ""
        for size, comp, src_path in _comp_files:
            budget_left = _CROSS_COMBINED_CAP - len(combined_source)
            if budget_left <= 0:
                logger.warning(f"  Cross: combined_source hit {_CROSS_COMBINED_CAP//1000}K cap — "
                               f"skipping {comp} ({size//1000}K)")
                break
            raw = src_path.read_text(encoding="utf-8", errors="replace")
            if len(raw) > budget_left:
                raw = raw[:budget_left] + f"\n// ... {comp}.sol truncated (budget exhausted)\n"
                logger.info(f"  Cross: {comp}.sol truncated to {budget_left//1000}K "
                            f"(full size {size//1000}K)")
            combined_source += f"\n// === {comp}.sol ===\n{raw}\n"
        logger.info(f"  Cross: combined_source = {len(combined_source)//1000}K chars "
                    f"({len(_comp_files)} contracts)")

        # Build interfaces code (all interface files)
        cross_interfaces = ""
        iface_dir = src_dir / "interfaces"
        if iface_dir.exists():
            for ifile in sorted(iface_dir.glob("*.sol")):
                cross_interfaces += f"\n// === {ifile.name} ===\n{ifile.read_text()[:3000]}\n"

        # forge env for PoC runs
        cross_poc_env = os.environ.copy()
        cross_poc_env["FOUNDRY_PROFILE"] = "chimera"
        for _v in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
            _val = os.environ.get(_v, "")
            if _val:
                cross_poc_env[_v] = _val

        # Filter to high-confidence findings worth PoC'ing
        poc_candidates = [
            f for f in merged_findings
            if isinstance(f, dict)
            and f.get("confidence", 0) >= POC_CONFIDENCE_THRESHOLD
            and f.get("severity", "Low").capitalize() in ("High", "Medium", "Critical")
        ]
        if poc_candidates:
            logger.info(f"  Cross-A.5: PoC → RedTeam on {len(poc_candidates)} cross-component findings")

            def _run_cross_finding(finding: dict) -> None:
                fid = finding.get("id", "?")
                # Step 1: generate and test PoC
                _rb.generate_and_test_poc(
                    finding, combined_source, cross_interfaces,
                    "CrossComponent", protocol, repo, clog, cross_poc_env,
                    poc_confidence_threshold=POC_CONFIDENCE_THRESHOLD
                )
                # Step 2: RedTeam only if PoC passed (or always — RedTeam will judge)
                _rb.run_finding_pipeline(
                    finding, "CrossComponent", protocol, combined_source, repo, clog,
                    benchmark_mode=True
                )
                logger.info(f"    Cross {fid}: PoC={'✓' if finding.get('has_poc') else '✗'} "
                            f"RedTeam={finding.get('redteam_verdict', '?')}")

            with ThreadPoolExecutor(max_workers=parallel_poc) as executor:
                futures = {executor.submit(_run_cross_finding, f): f for f in poc_candidates}
                for future in as_completed(futures):
                    finding = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"    Cross {finding.get('id','?')}: error: {e}")

            confirmed = [f for f in poc_candidates if f.get("has_poc")]
            reportable = [f for f in poc_candidates
                          if f.get("redteam_verdict") in ("REPORT", "REPORT_DOWNGRADED")]
            logger.info(f"  Cross-A.5 complete: {len(confirmed)} PoC confirmed, "
                        f"{len(reportable)} reportable")
        else:
            logger.info("  Cross-A.5: No high-confidence cross-component findings to PoC")

    # ─── Phase B: Multi-Contract Chimera Setup ───────────────────────
    logger.info("  Cross-B: Building multi-contract chimera setup")

    # Collect chimera backups from each component's log dir
    all_properties = {}
    for comp in components_done:
        backup_dir = _rb.LOG_DIR / comp / "chimera_backup"
        if backup_dir.exists():
            for f in backup_dir.glob("Properties*.sol"):
                # Namespace to avoid collisions: Properties_Strategy.sol etc
                target_name = f"Properties_{comp}.sol"
                all_properties[target_name] = f.read_text(encoding="utf-8")
                logger.info(f"    Restored {f.name} as {target_name} from {comp} backup")

    if not all_properties:
        logger.warning("  No chimera backups found — skipping cross-component fuzzing")
        return poc_candidates

    # Reset chimera to git state first
    if chimera_dir.exists():
        code_git, tracked, _ = _rb.run_cmd(
            ["git", "ls-files", str(chimera_dir.relative_to(Path(repo)))],
            cwd=repo
        )
        if code_git == 0 and tracked.strip():
            _rb.run_cmd(["git", "checkout", "--", str(chimera_dir.relative_to(Path(repo)))], cwd=repo)

    # Ask Claude to build multi-contract Setup.sol that deploys ALL components
    component_list = ", ".join(components_done)
    properties_summary = "\n".join(
        f"- {name}: {len(content.splitlines())} lines, "
        f"{content.count('function ')}) properties"
        for name, content in all_properties.items()
    )

    setup_prompt = (
        f"Build a CROSS-COMPONENT Chimera fuzzing setup for {protocol}.\n\n"
        f"## Components to deploy together: {component_list}\n\n"
        f"## Available per-component Properties (from individual hunts):\n{properties_summary}\n\n"
        f"## Task\n"
        f"1. Read the existing Setup.sol in {chimera_dir}/ to understand the current single-component setup\n"
        f"2. Read ALL source contracts: {', '.join(f'{c}.sol' for c in components_done)} in {src_dir}/\n"
        f"3. Create a NEW Setup.sol that deploys ALL {len(components_done)} components with their real interactions\n"
        f"   - Use the REAL contracts (not mocks) for cross-component calls\n"
        f"   - Wire dependencies correctly (e.g., Vault→Strategy, LendingPool→Vault)\n"
        f"   - Expose all contract instances as internal variables\n"
        f"4. Create Properties_CrossComponent.sol with interaction invariants:\n"
        f"   - Total value conservation across components\n"
        f"   - Custody: assets in component A XOR component B\n"
        f"   - Debt consistency: borrow in LP matches strategy accounting\n"
        f"   - Sequence invariants: A→B vs B→A should not diverge\n"
        f"5. Create TargetFunctions.sol with cross-component sequences as handlers\n"
        f"6. Update FoundryTester.sol and CryticTester.sol to inherit all Properties\n"
        f"7. Run `forge build` to verify it compiles\n\n"
        f"CRITICAL: the setup must deploy the REAL contracts interacting with each other, "
        f"not isolated instances. That's the whole point of cross-component testing."
    )
    _rb._llm(
        setup_prompt,
        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
        timeout=1800,
        log_file=clog / "cross_chimera_setup.log",
        cwd=repo
    )

    # ─── Phase C: Compile cross-component setup ──────────────────────
    logger.info("  Cross-C: Compile cross-component setup")
    compile_ok = _rb.fix_and_retry(
        "cross_compile",
        ["forge", "build"],
        [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else [],
        max_retries=5,
        cwd=repo
    )

    if not compile_ok:
        logger.error("  Cross-component chimera failed to compile — skipping fuzzing")
        return poc_candidates

    # ─── Phase D: Fuzz cross-component ───────────────────────────────
    logger.info("  Cross-D: Phase 1 — Foundry 5K runs (cross-component)")
    # Build forge env with RPC vars
    cross_forge_env = os.environ.copy()
    cross_forge_env["FOUNDRY_PROFILE"] = "chimera"
    for var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        val = os.environ.get(var, "")
        if val:
            cross_forge_env[var] = val

    code, stdout, stderr = _rb.run_cmd(
        ["forge", "test", "--match-contract", "FoundryTester", "--fuzz-runs", "5000", "-vv"],
        timeout=600,
        cwd=repo,
        log_file=clog / "cross_phase1.log",
        env=cross_forge_env
    )
    if code != 0:
        logger.info("  Cross-component Phase 1: Failures detected — potential cross-component bugs!")

    logger.info("  Cross-D: Phase 2 — Medusa 15 min (cross-component)")
    medusa_config = chimera_dir / f"medusa-{protocol}.json"
    if not medusa_config.exists():
        medusa_config = chimera_dir / "medusa.json"
    if medusa_config.exists():
        _rb.run_cmd(
            ["medusa", "fuzz", "--config", str(medusa_config), "--timeout", "900"],
            timeout=1000,
            cwd=repo,
            log_file=clog / "cross_phase2.log"
        )

    # ─── Phase E: Extract cross-component findings ───────────────────
    logger.info("  Cross-E: Extracting cross-component findings")
    cross_fuzz_failures = _rb.parse_fuzz_failures(
        clog / "cross_phase1.log",
        clog / "cross_phase2.log"
    )
    if cross_fuzz_failures:
        logger.info(f"  Cross-component fuzz failures: {cross_fuzz_failures}")
    findings = _rb.extract_findings("CrossComponent", protocol, cross_fuzz_failures)
    logger.info(f"  Cross-component hunt complete: {len(findings)} findings")
    return poc_candidates
