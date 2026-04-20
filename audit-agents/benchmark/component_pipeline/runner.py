"""run_component_pipeline — full per-component hunt orchestration.

Verbatim cut-and-paste from run_benchmark.py with mutable / monkeypatched
symbols rewired through `import run_benchmark as _rb` (lazy, avoids
circular imports and freeze-at-load semantics).

See package __init__.py for the rationale.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from finding_pipeline import (
    POC_CONFIDENCE_THRESHOLD,
    dedup_findings as _dedup_findings_pure,
    collect_verify_candidates as _collect_verify_candidates_pure,
    dedup_for_poc as _dedup_for_poc_pure,
)
from paths import WEB3_DIR
from benchmark.prompt_builders import (
    read_source,
    build_hunter_brief,
    build_hunter_dispatch_prompt,
    build_deepdive_prompt,
)
from benchmark.component_pipeline.reporting import parse_fuzz_failures

logger = logging.getLogger("orchestrator")


# ─── Component Pipeline ─────────────────────────────────────────────────────

def run_component_pipeline(component: str, repo: str, protocol: str,
                           args: argparse.Namespace,
                           accumulated_context: str = "",
                           hunters_subset: set | None = None) -> dict:
    """Run the full pipeline for one component. Returns summary dict."""
    # lazy module-ref — reads mutable globals (HUNT_SESSION_DIR, SCRIPT_DIR,
    # USE_SUB_MODE, PARALLEL_HUNTERS, DISABLE_FEW_SHOT) that main() mutates
    # after argparse, plus names that tests monkeypatch on the run_benchmark
    # namespace (_llm, run_cmd, component_log_dir, HUNT_SESSION_DIR, LOG_DIR,
    # close_component, subprocess). Top-level import would freeze bindings
    # AND create a circular import (since run_benchmark re-exports this module).
    import run_benchmark as _rb
    import os
    import re
    import subprocess
    import sys
    import time
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    comp_start = time.time()
    logger.info(f"\n{'='*60}")
    logger.info(f"  🔍 COMPONENT: {component}")
    logger.info(f"{'='*60}")

    clog = _rb.component_log_dir(component)
    src_dir = Path(repo) / "src"
    chimera_dir = Path(repo) / "test" / "chimera"

    # Find source file
    src_files = list(src_dir.glob(f"{component}.sol"))
    if not src_files:
        src_files = list(src_dir.glob(f"**/{component}.sol"))
    if not src_files:
        logger.error(f"  Source file not found for {component}")
        return {"component": component, "status": "ERROR", "reason": "source not found"}

    src_file = src_files[0]
    source_code = read_source(str(src_file))

    # Also read library files in src/libraries/
    lib_dir = src_dir / "libraries"
    library_code = ""
    if lib_dir.exists():
        for lib_file in sorted(lib_dir.glob("*.sol")):
            lib_content = lib_file.read_text(encoding="utf-8")
            library_code += f"\n// === {lib_file.name} ===\n{lib_content}"

    summary = {"component": component, "gates": {}, "findings": [], "status": "OK"}

    # ─── Skip-hunters: jump to merge if hypothesis files already exist ────
    _skip_to_merge = False
    if getattr(args, 'skip_hunters', False):
        hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
        existing_hyps = list(hyp_dir.glob(f"hyp_{component}_*.yaml"))
        if len(existing_hyps) >= 7:  # At least 7 hunter files = valid previous run
            logger.info(f"  --skip-hunters: {len(existing_hyps)} hypothesis files found, skipping to merge")
            summary["gates"]["prepass"] = True
            summary["gates"]["hunters"] = True
            summary["gates"]["deepdive"] = (hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml").exists()
            protocol_model = ""
            _skip_to_merge = True
        else:
            logger.warning(f"  --skip-hunters: only {len(existing_hyps)} hypothesis files, running full pipeline")

    # ─── Step -1: Clean slate ─────────────────────────────────────────────
    logger.info("  Step -1: Clean slate (reset chimera to git state)")

    # Save current chimera state for cross-component later
    import shutil
    comp_chimera_backup = clog / "chimera_backup"
    if chimera_dir.exists():
        # Backup compiled invariants from previous component (for cross-component)
        prev_props = list(chimera_dir.glob("Properties*.sol"))
        if prev_props and comp_chimera_backup.parent.exists():
            comp_chimera_backup.mkdir(exist_ok=True)
            for f in prev_props:
                shutil.copy2(f, comp_chimera_backup / f.name)

    # Reset chimera dir to git state — removes changes from previous components
    if chimera_dir.exists():
        code_git, tracked, _ = _rb.run_cmd(
            ["git", "ls-files", str(chimera_dir.relative_to(Path(repo)))],
            cwd=repo
        )
        if code_git == 0 and tracked.strip():
            _rb.run_cmd(["git", "checkout", "--", str(chimera_dir.relative_to(Path(repo)))], cwd=repo)
            logger.info("    Chimera dir reset to git state")

        # Remove generated Properties files from previous merge (untracked)
        for gen_file in chimera_dir.glob("Properties*.sol"):
            if gen_file.name != "Properties.sol":
                code_check, _, _ = _rb.run_cmd(
                    ["git", "ls-files", "--error-unmatch", str(gen_file.relative_to(Path(repo)))],
                    cwd=repo
                )
                if code_check != 0:  # untracked = generated
                    gen_file.unlink()
                    logger.info(f"    Removed generated {gen_file.name}")

    # Clean forge cache — only chimera artifacts (forge detects src staleness via hash)
    chimera_out = Path(repo) / "out" / "test" / "chimera"
    if chimera_out.exists():
        shutil.rmtree(chimera_out, ignore_errors=True)
        logger.info("    Cleaned out/test/chimera/ artifacts (forge cache retained)")

    # Clean PoC directory from previous runs
    poc_clean_dir = Path(repo) / "test" / "poc"
    if poc_clean_dir.exists():
        for old_poc in poc_clean_dir.glob("PoC_*.t.sol"):
            old_poc.unlink()
        logger.info("    Cleaned test/poc/ from previous runs")

    # ─── Skip Steps 0-4 if --skip-hunters and hypothesis files exist ────
    hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    if _skip_to_merge:
        logger.info("  Steps 0-4 SKIPPED (--skip-hunters, reusing existing hypotheses)")

    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    # Benchmark pipelines never read the ficha back (scope gate is not checked here),
    # so skipping is safe and avoids contaminating the real hunt_session/fichas/.
    if not _skip_to_merge:
        logger.info("  Step 0: Ficha init skipped (benchmark mode — not needed)")

    # ─── Step 1: Prepass ─────────────────────────────────────────────────
    prepass_yaml = _rb.HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
    if _skip_to_merge and prepass_yaml.exists():
        logger.info("  Step 1: Prepass SKIPPED (existing results)")
        summary["gates"]["prepass"] = True
    else:
        logger.info("  Step 1: Prepass (Slither + Aderyn + patterns)")
        code, _, _ = _rb.run_cmd([
            sys.executable, str(_rb.SCRIPT_DIR / "detection_engine.py"),
            "--prepass", "--source", str(src_dir), "--name", component,
            "--output", str(_rb.HUNT_SESSION_DIR / "results")
        ], log_file=clog / "prepass.log", cwd=repo)
        summary["gates"]["prepass"] = code == 0

    # ─── Early-exit: skip downstream work if prepass is empty (opt-in) ──────
    if getattr(args, 'skip_empty_prepass', False) and prepass_yaml.exists():
        try:
            import yaml as _yaml
            prepass_data = _yaml.safe_load(prepass_yaml.read_text(encoding='utf-8')) or {}
            total_findings = prepass_data.get('total_findings', len(prepass_data.get('findings', [])))
            if total_findings == 0:
                logger.info(f"  Early-exit: prepass found 0 signals — skipping hunters+merge+fuzz+PoC")
                summary["status"] = "EMPTY_PREPASS_SKIP"
                summary["findings"] = []
                comp_elapsed = (time.time() - comp_start) / 60
                logger.info(f"  🏁 Component {component} EARLY-EXIT (empty prepass, {comp_elapsed:.1f}min)")
                return summary
        except Exception as e:
            logger.warning(f"  Early-exit check failed: {e} — continuing pipeline")

    # protocol_model — not generated by Claude anymore (was Step 1.5, cut for speed)
    # Hunters read the code directly, which is what I did manually
    protocol_model = ""

    # ─── Step 1.6: Read project's existing tests (inline, no Claude call) ──
    # Include raw test content in hunter brief — hunters interpret it themselves.
    # QW6: Load once into _test_files_cache, derive slices at consumption points.
    existing_tests_summary = ""
    _test_files_cache: List[Tuple[str, str]] = []  # (filename, full_content) — used by Setup.sol prompt later
    test_dir = Path(repo) / "test"
    if test_dir.exists():
        test_files = [f for f in test_dir.glob("*.sol") if "chimera" not in str(f)]
        for tf in sorted(test_files)[:3]:  # max 3 test files, raw content
            content = tf.read_text(encoding="utf-8")
            _test_files_cache.append((tf.name, content))
            existing_tests_summary += f"\n// === {tf.name} ===\n{content[:3000]}\n"
        if existing_tests_summary:
            logger.info(f"  Loaded {len(test_files)} existing test files (raw, {len(existing_tests_summary)} chars)")

    # ─── Step 1.7: Load relevant knowledge base briefings ────────────────
    # Gap C: inject domain expertise from our 64 briefings
    knowledge_context = ""
    knowledge_dir = WEB3_DIR / "knowledge"
    if knowledge_dir.exists():
        # Auto-detect relevant briefings based on source code keywords
        code_lower = source_code.lower()
        relevant_briefings = []
        briefing_map = {
            "concentrated-liquidity.md": ["uniswapv3", "tickmath", "sqrtprice", "liquidity", "tick"],
            "yield-aggregator.md": ["vault", "strategy", "yield", "harvest", "compound"],
            "dex-amm.md": ["swap", "pool", "amm", "router", "slippage"],
            "lending-market-forks.md": ["lendingpool", "borrow", "collateral", "liquidat", "interest"],
            "liquidation-mechanics.md": ["liquidat", "health", "collateral", "undercollateral"],
            "flash-loan.md": ["flashloan", "flash", "callback"],
            "oracle.md": ["oracle", "pricefeed", "chainlink", "twap", "latestround"],
            "erc4626.md": ["erc4626", "shares", "converttoassets", "converttoshares"],
            "fee-distribution.md": ["fee", "collect", "distribute", "reward"],
        }
        for briefing_file, keywords in briefing_map.items():
            if any(kw in code_lower for kw in keywords):
                bp = knowledge_dir / briefing_file
                if bp.exists():
                    relevant_briefings.append(bp)

        for bp in relevant_briefings[:3]:  # max 3 briefings
            content = bp.read_text(encoding="utf-8")
            # Extract just the bug patterns (YAML sections with known vulns)
            knowledge_context += f"\n## Known bugs from {bp.name}:\n{content[:3000]}\n"
        if relevant_briefings:
            logger.info(f"  Loaded {len(relevant_briefings)} knowledge briefings: {[b.name for b in relevant_briefings[:3]]}")

    # ─── Step 1.8: Read interfaces ───────────────────────────────────────
    # Gap D: interfaces show what the contract expects from external deps
    interfaces_code = ""
    iface_dir = src_dir / "interfaces"
    if iface_dir.exists():
        for iface_file in sorted(iface_dir.glob("*.sol")):
            content = iface_file.read_text(encoding="utf-8")
            interfaces_code += f"\n// === {iface_file.name} ===\n{content}\n"
        if interfaces_code:
            logger.info(f"  Loaded {len(list(iface_dir.glob('*.sol')))} interface files")

    # ─── Step 1.9: Ensure Chimera Setup exists BEFORE hunters ──────────
    # Hunters need Setup.sol to know which variables exist (strategy, vault, etc.)
    # Without it, they write invariants that reference non-existent variables
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if _skip_to_merge:
        logger.info("  Step 1.9: SKIPPED (--skip-hunters)")
    elif not setup_path.exists():
        logger.info("  Step 1.9: Generate Chimera Setup (needed for hunter context)")
        chimera_dir_early = Path(repo) / "test" / "chimera"
        chimera_dir_early.mkdir(parents=True, exist_ok=True)

        # QW6: Reuse _test_files_cache loaded in Step 1.6 (no re-read from disk)
        existing_test_code = ""
        for _tf_name, _tf_content in _test_files_cache:
            existing_test_code += f"\n// === {_tf_name} ===\n{_tf_content[:5000]}\n"

        # Read foundry.toml for remappings and compiler settings
        foundry_toml = ""
        foundry_path = Path(repo) / "foundry.toml"
        if foundry_path.exists():
            foundry_toml = foundry_path.read_text(encoding="utf-8")[:3000]

        setup_prompt = (
            f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
            f"## Source Code\n```solidity\n{source_code}\n```\n\n"
            f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
            f"## Interfaces\n```solidity\n{interfaces_code[:10000]}\n```\n\n"
            f"## Project's Own Tests (CRITICAL — shows how THEY deploy the contracts)\n"
            f"```solidity\n{existing_test_code[:8000]}\n```\n\n"
            f"## foundry.toml (remappings, compiler version)\n```toml\n{foundry_toml}\n```\n\n"
            f"Create these files in {chimera_dir_early}/:\n"
            f"- Setup.sol: abstract contract that deploys {component} with ALL its dependencies.\n"
            f"  COPY the deployment pattern from the project's own tests above — they know their constructor args.\n"
            f"  NEVER use vm.createSelectFork or fork in Phase 1 Setup.sol — Phase 1 uses MOCKS for fast feedback (0 RPC calls).\n"
            f"  For external contracts (Uniswap pools, oracles, tokens): deploy mock contracts that simulate their interface.\n"
            f"  Use forge's `deal()` for token balances. Use MockERC20 or `deal(address(token), user, amount)` for tokens.\n"
            f"  For Uniswap V3: create a minimal MockUniswapV3Pool that returns controlled slot0/observe/mint/burn values.\n"
            f"  Fork testing is ONLY for Phase 3 PoCs (individual tests, not invariant fuzzing).\n"
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
            f"AFTER creating all files, run `forge build` to verify compilation.\n"
            f"If it fails, fix the errors and re-run until it compiles.\n"
            f"Use the EXACT same import paths and remappings from foundry.toml."
        )
        _rb._llm(
            setup_prompt,
            allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            timeout=1500,  # Increased: complex components (Leverager, LendingPool) need >600s
            log_file=clog / "chimera_setup_early.log",
            cwd=repo
        )
        if setup_path.exists():
            logger.info(f"  Setup.sol generated ({setup_path.stat().st_size} bytes)")
        else:
            logger.warning("  Setup.sol generation failed — hunters will work without it")

    # ─── Step 2: 12 Hunters (coordinator + context file on disk) ─────────
    hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    if _skip_to_merge:
        hyp_count = len(list(hyp_dir.glob(f"hyp_{component}_*.yaml")))
        logger.info(f"  Steps 2-4: SKIPPED — {hyp_count} existing hypothesis files")
        summary["gates"]["hunters"] = True
        summary["gates"]["deepdive"] = (hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml").exists()
        # Create crosschain skip if needed
        skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
        if not skip_file.exists():
            skip_file.write_text("single-chain protocol")
        # Initialize variables used by Steps 5+ that are normally set in Steps 1-4
        setup_sol_text = ""
        setup_var_names = ""
        setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
        if setup_path.exists():
            setup_sol_text = setup_path.read_text()
            import re as _re_skip
            setup_var_names = ", ".join(_re_skip.findall(r'\b(?:address|uint\d*|int\d*|bool)\s+(?:public\s+)?(\w+)', setup_sol_text))
        prepass_signals_text = ""
        interfaces_code = ""
        existing_tests_summary = ""
        knowledge_context = ""
    else:

        # Load prepass signals
        import yaml as _yaml
        prepass_signals_text = ""
        prepass_path = _rb.HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
        if prepass_path.exists():
            try:
                prepass_data = _yaml.safe_load(prepass_path.read_text())
                signals = prepass_data.get("prepass_signals", [])
                top_signals = [s for s in signals if s.get("severity") in ("high", "medium", "critical")][:30]
                if top_signals:
                    prepass_signals_text = _yaml.dump(top_signals, default_flow_style=False)
                    logger.info(f"  Loaded {len(top_signals)} prepass signals for hunters")
            except Exception as e:
                logger.warning(f"  Failed to load prepass signals: {e}")

        # Load Setup.sol for hunter context (helps write compilable invariants)
        setup_sol_text = ""
        setup_var_names = ""
        setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
        if setup_path.exists():
            setup_sol_text = setup_path.read_text()
            logger.info(f"  Loaded Setup.sol ({len(setup_sol_text.splitlines())} lines) for hunter context")
            # Extract variable names dynamically so hunters use the REAL names
            import re as _re
            # Match: Type internal varName  or  Type public varName
            var_matches = _re.findall(
                r'(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
                setup_sol_text
            )
            # Also match: address internal varName
            addr_matches = _re.findall(
                r'address\s+(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
                setup_sol_text
            )
            all_vars = list(dict.fromkeys(var_matches + addr_matches))  # dedupe, preserve order
            setup_var_names = ", ".join(all_vars) if all_vars else "strategy, vault, token0, token1, pool"
            logger.info(f"  Setup.sol variables: {setup_var_names}")

        # Write shared context to a file on disk — each hunter agent reads it
        # This guarantees every hunter gets full context regardless of coordinator behavior
        context_dir = _rb.HUNT_SESSION_DIR / "context" / f"{protocol}-bench"
        context_dir.mkdir(parents=True, exist_ok=True)
        hunter_brief_path = context_dir / f"{component}_hunter_brief.md"
        # Load v10 context for hunter brief (benefits both api and sub modes)
        try:
            from hunter_context import load_rejection_context as _load_rej
            _rejection_ctx = _load_rej()
        except Exception:
            _rejection_ctx = ""

        hunter_brief_content = build_hunter_brief(
            component=component, protocol=protocol, src_file=src_file,
            src_dir=src_dir, protocol_model=protocol_model,
            prepass_signals_text=prepass_signals_text,
            setup_sol_text=setup_sol_text, setup_var_names=setup_var_names,
            existing_tests_summary=existing_tests_summary,
            knowledge_context=knowledge_context, interfaces_code=interfaces_code,
            accumulated_context=accumulated_context, hyp_dir=hyp_dir,
            rejection_context=_rejection_ctx,
        )
        hunter_brief_path.write_text(hunter_brief_content, encoding="utf-8")
        logger.info(f"  Wrote hunter brief ({len(hunter_brief_content)} chars) to {hunter_brief_path}")

        # Coordinator prompt — lightweight, tells agents to read brief + methodology from disk
        hunter_dispatch_prompt = build_hunter_dispatch_prompt(
            component=component, protocol=protocol, src_file=src_file,
            src_dir=src_dir, hunter_brief_path=hunter_brief_path, hyp_dir=hyp_dir
        )

        t0 = time.time()

        if _rb.USE_SUB_MODE:
            # Sub mode: dispatch individual hunters in parallel from Python
            # Each hunter gets agentic tools to explore code autonomously
            from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
            methodology_dir = _rb.SCRIPT_DIR / "prompts" / "hunters"

            def _run_single_hunter(hunter_name: str) -> str:
                domain_key = HUNTER_DOMAINS.get(hunter_name, ("general", ""))[0]
                rejection_ctx = load_rejection_context()
                few_shot_ctx = "" if _rb.DISABLE_FEW_SHOT else load_few_shot_examples(domain_key)

                prompt = (
                    f"You are {hunter_name} analyzing {component} in {protocol}.\n\n"
                    f"Read these files FIRST before any analysis:\n"
                    f"1. {hunter_brief_path} -- protocol context, Setup.sol, prepass signals, output rules\n"
                    f"2. {methodology_dir}/{hunter_name}.md -- your hunting methodology\n\n"
                    f"Then read the source code: {src_file} and all .sol files in {src_dir / 'libraries'}/.\n\n"
                    f"Follow your methodology file. Write YAML to {hyp_dir}/hyp_{component}_{hunter_name}.yaml\n\n"
                    f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
                    f"1. Que HACE esta funcion? (inputs, outputs, estado)\n"
                    f"2. Que ASUME? (precondiciones implicitas)\n"
                    f"3. Que pasa si la asuncion es FALSA?\n"
                    f"4. COMO puede un atacante forzar esa condicion?\n"
                    f"5. CUAL es el impacto concreto en fondos/acceso?\n\n"
                    f"{rejection_ctx}\n{few_shot_ctx}"
                )
                _rb._llm(prompt, allowed_tools=["Read", "Write", "Grep", "Glob", "Bash"],
                     timeout=1800,
                     log_file=clog / f"hunter_{hunter_name}.log",
                     cwd=repo)
                return hunter_name

            hunters = ["MathHunter", "AccessHunter", "FlowHunter", "OracleHunter",
                        "DomainHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter", "LogicHunter",
                        "AdversarialHunter", "LibraryHunter"]
            # Filter to subset if --hunters was provided (non-empty = user-specified subset).
            # hunters_subset is pre-validated by main() at startup (fail-fast); reuse it here.
            # When args.hunters is "" (default), hunters_subset is None — run all hunters.
            if hunters_subset is not None:
                hunters = [h for h in hunters if h in hunters_subset]
            logger.info(f"  Sub mode: {len(hunters)} hunters, {_rb.PARALLEL_HUNTERS} parallel")
            failed_hunters = []
            with ThreadPoolExecutor(max_workers=_rb.PARALLEL_HUNTERS) as executor:
                future_to_hunter = {
                    executor.submit(_run_single_hunter, h): h for h in hunters
                }
                for future in as_completed(future_to_hunter):
                    hunter_name = future_to_hunter[future]
                    try:
                        future.result()
                    except Exception as e:
                        failed_hunters.append(hunter_name)
                        logger.warning(f"  Hunter {hunter_name} FAILED: {e} — continuing with remaining hunters")
            if failed_hunters:
                logger.warning(f"  {len(failed_hunters)} hunters failed: {failed_hunters}")
        else:
            # API mode: single coordinator dispatches 12 agents
            rc, out = _rb._llm(
                hunter_dispatch_prompt,
                allowed_tools=["Agent", "Read", "Write", "Edit", "Grep", "Glob"],
                timeout=1800,
                log_file=clog / "hunters_dispatch.log",
                cwd=repo
            )

        elapsed = time.time() - t0
        logger.info(f"  12 Hunters completed ({elapsed/60:.1f}min)")

        # Create crosschain skip file
        skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
        if not skip_file.exists():
            skip_file.write_text("single-chain protocol")

        # Check hunters gate — in benchmark mode, verify YAML count directly
        # (pipeline_gate.py checks for solidity_property fields which benchmark hunters don't require)
        REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                            "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                            "SignatureHunter", "DoSHunter"]
        hyp_count = len(list(hyp_dir.glob(f"hyp_{component}_*.yaml")))
        MIN_REQUIRED_HUNTERS = 7  # allow up to 2 failures
        missing_hunters = [h for h in REQUIRED_HUNTERS
                           if not (hyp_dir / f"hyp_{component}_{h}.yaml").exists()]
        present_count = len(REQUIRED_HUNTERS) - len(missing_hunters)
        if present_count < MIN_REQUIRED_HUNTERS:
            logger.error(f"  BLOCKED: Only {present_count}/{len(REQUIRED_HUNTERS)} required hunters present "
                         f"(minimum {MIN_REQUIRED_HUNTERS}). Missing: {missing_hunters}")
            summary["status"] = "BLOCKED_HUNTERS"
            summary["gates"]["hunters"] = False
            return summary
        else:
            hunters_ok = True
            summary["gates"]["hunters"] = True
            if missing_hunters:
                logger.warning(f"  Gate hunters: PASS with degradation — {present_count}/{len(REQUIRED_HUNTERS)} "
                              f"required hunters present ({hyp_count} total YAML files). "
                              f"Missing: {missing_hunters}")
            else:
                logger.info(f"  Gate hunters: PASS ({hyp_count} YAML files, all {len(REQUIRED_HUNTERS)} required hunters present)")

        # Mandatory team output verification
        verify_result = subprocess.run([
            "python3", str(_rb.SCRIPT_DIR / "verify_team_outputs.py"),
            "--session-dir", str(Path(hyp_dir).parent.parent),
            "--protocol", protocol,
            "--groups", json.dumps([{"group_id": 0, "components": [component]}])
        ], capture_output=True, text=True)
        if verify_result.returncode != 0:
            logger.warning(f"  Team verification warnings:\n{verify_result.stdout[:500]}")

        # Step 3 (Library Analyzer) — now runs as LibraryHunter (#11) in parallel with other hunters above

        # ─── Step 4: DeepDive Hunter ────────────────────────────────────────
        logger.info("  Step 4: DeepDive Hunter")

        # Pre-digest hunter hypotheses: summarize convergences for DeepDive (Gap #5)
        import yaml as _yaml_dd
        hunter_digest = ""
        convergence_map = {}  # track which areas multiple hunters flagged
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
            if "DeepDive" in hyp_file.name or "CrossChain" in hyp_file.name:
                continue
            try:
                data = _yaml_dd.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
                hyps = data.get("hypotheses", data.get("invariants", []))
                for h in hyps:
                    if h.get("confidence", 0) >= 50 and h.get("tier", 3) <= 2:
                        desc = h.get("description", h.get("title", ""))
                        area = h.get("type", "unknown")
                        hunter_digest += f"- [{hunter_name}] (tier={h.get('tier')}, conf={h.get('confidence')}%) {desc}\n"
                        convergence_map.setdefault(area, []).append(hunter_name)
            except Exception:
                pass

        convergence_text = ""
        for area, hunters in convergence_map.items():
            if len(hunters) >= 2:
                convergence_text += f"- **{area}**: flagged by {', '.join(set(hunters))} — INVESTIGATE DEEPER\n"

        # Build deepdive prompt inline from bench_session hyp_dir.
        # Keep this local — a helper reading from a module-global hunt dir would
        # race across parallel components (two threads would patch the same global).
        deepdive_prompt = build_deepdive_prompt(
            component=component, protocol=protocol, source_code=source_code,
            library_code=library_code, setup_sol_text=setup_sol_text,
            protocol_model=protocol_model, hyp_dir=hyp_dir,
            convergence_text=convergence_text, hunter_digest=hunter_digest
        )

        _rb._llm(
            deepdive_prompt,
            allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
            timeout=1800,
            log_file=clog / "deepdive.log",
            cwd=repo
        )

        # Rescue DeepDive YAML: Claude may write to cwd (worktree root) instead of hyp_dir.
        def _rescue_deepdive_yaml(context_label: str) -> bool:
            target = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
            if target.exists():
                return True
            _find_out = subprocess.run(
                ["find", str(repo), "-name", f"hyp_{component}_DeepDiveHunter.yaml", "-type", "f"],
                capture_output=True, text=True
            )
            for _found in _find_out.stdout.strip().splitlines():
                if _found and Path(_found) != target:
                    import shutil as _sh_rescue
                    _sh_rescue.copy2(_found, target)
                    logger.info(f"  {context_label}: rescued {Path(_found).name} → {hyp_dir.name}/")
                    return True
            return False

        _rescue_deepdive_yaml("DeepDive rescue")

        deepdive_ok = _rb.check_gate(component, "deepdive", protocol, repo)
        summary["gates"]["deepdive"] = deepdive_ok
        if not deepdive_ok:
            dd_file = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
            if not dd_file.exists():
                logger.warning("  DeepDive gate failed and no YAML — continuing without DeepDive")
            # Not blocking — DeepDive is additive, hunters provide the base

    # ─── Forge env (shared by fuzz + PoC steps) ─────────────────────────
    forge_env = os.environ.copy()
    forge_env["FOUNDRY_PROFILE"] = "chimera"
    for _rpc_var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        _rpc_val = os.environ.get(_rpc_var, "")
        if _rpc_val:
            forge_env[_rpc_var] = _rpc_val

    # ─── Steps 5-9: Compile + Fuzz ──────────────────────────────────────
    # Fast mode: runs Steps 5-8 (setup+merge+compile+Phase1 5K) but skips 9-9.5 (Medusa+tuning)
    # Full mode: runs everything
    all_fuzz_failures = {}
    phase1_fuzz_failures = {}
    phase2_log = clog / "phase2_medusa.log"  # may not exist in fast mode
    _SKIP_HEAVY_FUZZ = args.fast  # skip Medusa + tolerance tuning
    if args.fast:
        logger.info("  ⚡ FAST MODE: Steps 5-8 (compile+Phase1 5K), skip 9-9.5 (Medusa+tuning)")
        summary["gates"]["phase2"] = True  # skip Medusa gate

    if True:  # Steps 5-8 always run; Steps 9-9.5 gated by _SKIP_HEAVY_FUZZ
        # ─── Step 5: Ensure Chimera Setup exists & compiles BEFORE merge ────
        setup_sol = chimera_dir / "Setup.sol"
        # ── Chimera Setup cache: reuse Setup.sol from a sibling component ──
        # If another component already compiled a Setup.sol, use it as starting template.
        # Siblings share 80%+ of the setup (same protocol deps/mocks), only handlers differ.
        # Lookup order (most durable first):
        #   1. Persistent cache at /tmp/chimera-cache-{protocol}/<sibling>/   ← survives worktree destruction
        #   2. Live sibling worktree /tmp/bench-{protocol}-*/*/test/chimera/
        #   3. Main repo's chimera dir (prior batch)
        _persistent_cache_root = Path("/tmp") / f"chimera-cache-{protocol}"
        if not setup_sol.exists():
            _cache_search = []
            if _persistent_cache_root.exists():
                # Any sibling dir under the persistent cache with a compiled Setup.sol
                _cache_search = list(_persistent_cache_root.glob("*/Setup.sol"))
            if not _cache_search:
                _cache_search = list(Path("/tmp").glob(f"bench-{protocol}-*/*/test/chimera/Setup.sol"))
            if not _cache_search:
                # Also check the main repo's chimera dir from a prior batch
                _main_chimera = Path(repo).parent / "test" / "chimera" / "Setup.sol"
                if _main_chimera.exists():
                    _cache_search = [_main_chimera]
            if _cache_search:
                _cached_setup = _cache_search[0]
                logger.info(f"  Step 5a: Reusing Setup.sol from {_cached_setup.parent}")
                chimera_dir.mkdir(parents=True, exist_ok=True)
                import shutil as _shutil_cache
                # Copy ALL chimera files from sibling, not just Setup.sol
                _sibling_chimera = _cached_setup.parent
                for _cf in _sibling_chimera.glob("*.sol"):
                    _shutil_cache.copy2(_cf, chimera_dir / _cf.name)
        if not chimera_dir.exists() or not setup_sol.exists():
            logger.info("  Step 5a: Generate Chimera Setup (no existing setup found)")
            chimera_prompt = (
                f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
                f"## Source Code\n```solidity\n{source_code}\n```\n\n"
                f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
                f"Create these files in {chimera_dir}/:\n"
                f"- Setup.sol: deploy {component} with ALL its dependencies. Use MOCKS for external contracts (no fork, no RPC).\n"
                f"  NEVER use vm.createSelectFork — Phase 1 is mock-only for fast feedback.\n"
                f"  For Uniswap V3: create MockUniswapV3Pool. For oracles: MockOracle. For tokens: deal().\n"
                f"  MUST define: contract instance variables accessible by Properties (e.g., `Strategy internal strategy;`)\n"
                f"- BeforeAfter.sol: ghost variables and state snapshots\n"
                f"- Properties.sol: base with ghost vars, inherits BeforeAfter\n"
                f"- TargetFunctions.sol: handlers for each public function with clamped inputs\n"
                f"- FoundryTester.sol: inherits Properties, has invariant_* wrapper functions\n"
                f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa\n\n"
                f"The setup MUST compile with `forge build`. Test it after creating."
            )
            _rb._llm(
                chimera_prompt,
                allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
                timeout=1500,  # Increased: complex components need >600s for full setup
                log_file=clog / "chimera_builder.log",
                cwd=repo
            )

        # Verify base chimera compiles before merge
        logger.info("  Step 5b: Verify base chimera compiles")
        base_compile_ok = _rb.fix_and_retry(
            "base_compile",
            ["forge", "build"],
            [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else [],
            max_retries=5,
            cwd=repo
        )
        if not base_compile_ok:
            logger.error("  Base chimera doesn't compile — skipping merge+fuzz")
            summary["status"] = "BLOCKED_CHIMERA"
            summary["gates"]["compile"] = False
            return summary

        # ── Persist compiled chimera to /tmp/chimera-cache-{protocol}/{component}/ ──
        # Survives worktree destruction so sibling components can reuse it even if
        # their worktrees start simultaneously or the source worktree is cleaned up.
        try:
            import shutil as _shutil_persist
            _persist_dir = Path("/tmp") / f"chimera-cache-{protocol}" / component
            _persist_dir.mkdir(parents=True, exist_ok=True)
            for _sf in chimera_dir.glob("*.sol"):
                _shutil_persist.copy2(_sf, _persist_dir / _sf.name)
            logger.info(f"  Step 5b: Cached chimera setup → {_persist_dir}")
        except Exception as _e_cache:
            logger.warning(f"  Step 5b: Could not persist chimera cache: {_e_cache}")

        # ─── Step 6: Merge Invariants (setup-aware) ──────────────────────────
        logger.info("  Step 6: Merge Invariants")

        # Extract available variables from Setup.sol so merge knows what exists
        setup_context = ""
        if setup_sol.exists():
            setup_content = setup_sol.read_text(encoding="utf-8")
            setup_context = setup_content[:20000]  # Full Setup.sol — critical for compile fixes

        code, _, _ = _rb.run_cmd([
            sys.executable, str(_rb.SCRIPT_DIR / "merge_invariants.py"),
            "--component", component,
            "--hypotheses-dir", str(hyp_dir),
            "--session-dir", str(_rb.HUNT_SESSION_DIR),
            "--protocol", protocol,
        ], log_file=clog / "merge.log")
        merge_ok = code == 0
        summary["gates"]["merge"] = merge_ok
        if not merge_ok:
            logger.error(f"  BLOCKED: merge_invariants.py failed. Cannot compile without Properties.")
            summary["status"] = "BLOCKED_MERGE"
            return summary

        # ─── Step 6.5: Generate FoundryTester invariant_ wrappers ────────────
        logger.info("  Step 6.5: Generate FoundryTester invariant_ wrappers")
        _rb._generate_foundry_tester_wrappers(chimera_dir)

        # ─── Step 6.7: Inject missing imports into Properties*.sol ────────────
        # merge_invariants.py generates Properties files that often lack imports
        # present in Setup.sol (e.g., IStrategy). This pre-injects them to avoid
        # burning 9 compile-fix attempts on the same import error across files.
        setup_path = chimera_dir / "Setup.sol"
        if setup_path.exists():
            setup_text = setup_path.read_text(encoding="utf-8")
            # Extract import lines from Setup.sol
            setup_imports = [line.strip() for line in setup_text.splitlines()
                           if line.strip().startswith("import ")]
            for prop_file in sorted(chimera_dir.glob("Properties*.sol")):
                if prop_file.name in ("PropertiesAll.sol",):
                    continue
                prop_text = prop_file.read_text(encoding="utf-8")
                added = []
                for imp in setup_imports:
                    # Check if the imported symbol is used but not imported
                    # Extract symbol name from: import {Foo} from "..." or import "..."
                    m_sym = re.search(r'import\s+\{([^}]+)\}', imp)
                    if m_sym:
                        symbols = [s.strip() for s in m_sym.group(1).split(",")]
                        for sym in symbols:
                            if sym in prop_text and imp not in prop_text:
                                added.append(imp)
                                break
                if added:
                    # Insert after pragma line
                    lines = prop_text.splitlines(keepends=True)
                    insert_idx = 0
                    for i, line in enumerate(lines):
                        if line.strip().startswith("pragma "):
                            insert_idx = i + 1
                            break
                    for imp_line in reversed(added):
                        lines.insert(insert_idx, imp_line + "\n")
                    prop_file.write_text("".join(lines), encoding="utf-8")
                    logger.info(f"    Injected {len(added)} imports into {prop_file.name}")

        # ─── Step 7: Compile merged invariants (setup-aware fix) ─────────────
        logger.info("  Step 7: Compile (setup-aware fix-and-retry)")

        # Custom fix prompt that understands chimera architecture
        compile_files = [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else []

        for attempt in range(9):
            code, stdout, stderr = _rb.run_cmd(["forge", "build"], cwd=repo)
            if code == 0:
                logger.info(f"  ✅ Compile passed (attempt {attempt + 1})")
                break

            error_text = _rb._extract_first_errors(stderr, max_errors=25, max_chars=5000)
            logger.warning(f"  ❌ Compile failed (attempt {attempt + 1}/9)")

            if attempt < 8:
                # All attempts try to FIX first. Only last resort (attempt 8) deletes.
                # Each level adds more context to help the fixer understand the error.
                if attempt <= 2:
                    strategy_hint = (
                        f"## STRATEGY: Fix errors (attempt {attempt + 1}/9)\n"
                        f"1. Read Setup.sol FIRST to understand what contracts/variables are deployed and their EXACT types\n"
                        f"2. Properties*.sol can ONLY reference variables defined in Setup.sol\n"
                        f"3. If an import is missing, add it. If a type is wrong, fix the type\n"
                        f"4. **TYPE MISMATCH FIX**: If error is about IFoo.Struct vs Foo.Struct (interface vs concrete):\n"
                        f"   - Check Setup.sol — if it declares `Foo internal foo` (concrete), use `Foo.StructName` not `IFoo.StructName`\n"
                        f"   - Or remove the type annotation entirely: `(uint a, uint b) = foo.getX()` instead of `IFoo.X memory x = foo.getX()`\n"
                        f"5. **STRUCT GETTER FIX** (MOST COMMON ERROR): Solidity public struct state variables return TUPLES from auto-generated getters.\n"
                        f"   - WRONG: `strategy.mainPosition().tickLower` — `.tickLower` fails on a tuple\n"
                        f"   - RIGHT: `(int24 tickLower, int24 tickUpper, uint128 liquidity) = strategy.mainPosition();`\n"
                        f"   - OR: if the contract has explicit `getMainPosition()` returning a struct, use that instead\n"
                        f"   - Check the source contract for explicit getter functions that return structs by memory\n"
                        f"6. If an invariant references a contract/function not in Setup.sol, check if Setup.sol has a helper for it\n"
                        f"7. Do NOT delete functions — FIX them. Every invariant matters.\n"
                        f"8. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                elif attempt <= 5:
                    strategy_hint = (
                        f"## STRATEGY: Fix with more context (attempt {attempt + 1}/9)\n"
                        f"Previous attempts didn't resolve all errors. Read MORE carefully:\n"
                        f"1. Read Setup.sol line by line — list EVERY variable, its type, and what helpers exist\n"
                        f"2. Read the ACTUAL source contract to verify function signatures, return types, and struct definitions\n"
                        f"3. For each error: read the exact line, understand WHY it fails, fix the ROOT CAUSE\n"
                        f"4. Common fixes:\n"
                        f"   - Wrong type: `IFoo.X` → `Foo.X` (match Setup.sol concrete type)\n"
                        f"   - Missing function: check if Setup.sol has a `_helper()` that wraps it\n"
                        f"   - Wrong args: read the actual function signature in the source contract\n"
                        f"   - Missing import: add the import from Setup.sol's import list\n"
                        f"   - Struct field access: use a getter helper or destructure the return value\n"
                        f"5. Do NOT delete functions — FIX them. Every invariant matters.\n"
                        f"6. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                elif attempt <= 7:
                    strategy_hint = (
                        f"## STRATEGY: Simplify broken functions (attempt {attempt + 1}/9)\n"
                        f"Multiple fix attempts failed. For functions that STILL don't compile:\n"
                        f"1. Read the error and the function. Understand the INTENT of the invariant.\n"
                        f"2. REWRITE the function body to test the SAME property but with simpler code:\n"
                        f"   - Replace struct access with direct getter calls\n"
                        f"   - Replace complex expressions with multiple simple lines\n"
                        f"   - Use only variables and types from Setup.sol\n"
                        f"3. If a function calls something that doesn't exist, replace with the closest equivalent\n"
                        f"4. PRESERVE the function — rewrite it simpler, do NOT delete it\n"
                        f"5. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                else:
                    strategy_hint = (
                        f"## STRATEGY: Last resort — delete ONLY what cannot be fixed (attempt {attempt + 1}/9)\n"
                        f"This is the final attempt. For each remaining error:\n"
                        f"1. Try one more time to fix or simplify the function\n"
                        f"2. ONLY if it's truly unfixable (references something that doesn't exist at all), delete JUST that one function\n"
                        f"3. Keep as many invariants as possible — each one is valuable\n"
                        f"4. Do NOT delete Setup.sol, BeforeAfter.sol, TargetFunctions.sol, FoundryTester.sol, CryticTester.sol\n"
                    )

                fix_prompt = (
                    f"Fix compile errors in the Chimera fuzzing setup for {component}.\n\n"
                    f"## Error\n```\n{error_text}\n```\n\n"
                    f"{strategy_hint}\n"
                    f"## Available Setup Context\n```solidity\n{setup_context}\n```\n\n"
                    f"Read ALL .sol files in {chimera_dir}/ to understand the full picture before making fixes.\n"
                    f"After fixing, run `forge build` to verify ALL errors are resolved — fix any new ones too."
                )
                # Shorter timeout for simple fixes, longer for later attempts
                fix_timeout = 300 if attempt <= 2 else 360 if attempt <= 5 else 480
                tier = "fix" if attempt <= 2 else "context" if attempt <= 5 else "simplify" if attempt <= 7 else "delete"
                _rb._llm(
                    fix_prompt,
                    allowed_tools=["Read", "Edit", "Write", "Grep", "Glob", "Bash"],
                    timeout=fix_timeout,
                    log_file=clog / f"compile_fix_{attempt:02d}_{tier}.log",
                    cwd=repo
                )

        compile_ok = code == 0
        summary["gates"]["compile"] = compile_ok

        _skip_to_extract = False
        if not compile_ok:
            if _SKIP_HEAVY_FUZZ:
                logger.warning(f"  Compile failed — fast mode skips to findings extraction")
                summary["gates"]["compile"] = False
                summary["gates"]["phase1"] = False
                _skip_to_extract = True
            else:
                logger.error(f"  Component {component} BLOCKED at compile")
                summary["status"] = "BLOCKED_COMPILE"
                return summary

        # ─── Step 7.5: Enhance TargetFunctions with attack sequences (opt-in) ────
        if _skip_to_extract:
            logger.info("  Skipping Step 7.5 (compile failed, fast mode)")
        elif not getattr(args, 'enhance_targets', False):
            logger.info("  Step 7.5 skipped (activate with --enhance-targets)")
        else:
            logger.info("  Step 7.5: Enhance TargetFunctions with attack sequences")
            target_funcs_path = chimera_dir / "TargetFunctions.sol"
            if target_funcs_path.exists():
                top_hyps = ""
                for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml"))[:5]:
                    try:
                        import yaml as _y
                        data = _y.safe_load(hyp_file.read_text())
                        if data:
                            hyps = data.get("hypotheses", data.get("invariants", []))
                            for h in hyps[:3]:
                                if h.get("tier", 3) <= 2 and h.get("confidence", 0) >= 60:
                                    top_hyps += f"\n- {h.get('id','?')}: {h.get('description','')}\n  Attack: {h.get('attack_scenario','')}\n"
                    except Exception:
                        pass

                if top_hyps:
                    target_funcs_code = target_funcs_path.read_text(encoding="utf-8")
                    enhance_prompt = (
                        f"Enhance the TargetFunctions.sol for {component} with multi-step attack sequences.\n\n"
                        f"## Current TargetFunctions\n```solidity\n{target_funcs_code[:15000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## High-Priority Attack Scenarios from Hunters\n{top_hyps}\n\n"
                        f"## Task\n"
                        f"Add 3-5 NEW handler functions that encode MULTI-STEP attack sequences:\n"
                        f"1. Flash loan → deposit → manipulate → withdraw sequences\n"
                        f"2. Sandwich patterns: frontrun → victim action → backrun\n"
                        f"3. State manipulation: set up bad state → trigger vulnerable path\n"
                        f"4. Cross-function: call A to set state, call B to exploit it\n\n"
                        f"Each handler should:\n"
                        f"- Use clamped inputs (bound by `_clampBetween`)\n"
                        f"- Prank as attacker where needed\n"
                        f"- Be a realistic attack, not random calls\n\n"
                        f"ONLY ADD new functions. Do NOT modify or remove existing handlers.\n"
                        f"Write changes to: {target_funcs_path}"
                    )
                    _rb._llm(
                        enhance_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / "target_functions_enhance.log",
                        cwd=repo
                    )
                    # Quick recompile to make sure enhancement didn't break anything
                    recomp_ok = _rb.fix_and_retry(
                        "targetfunc_compile", ["forge", "build"],
                        [str(target_funcs_path)], max_retries=2, cwd=repo
                    )
                    if recomp_ok:
                        logger.info("  TargetFunctions enhanced and compiles")
                    else:
                        logger.warning("  TargetFunctions enhancement broke compile — reverting")
                        _rb.run_cmd(["git", "checkout", "--", str(target_funcs_path.relative_to(Path(repo)))], cwd=repo)
                        _rb.run_cmd(["forge", "build"], cwd=repo)  # restore working state
                else:
                    logger.info("  No high-priority hypotheses — skipping TargetFunctions enhancement")

        # forge_env already defined above (shared by fuzz + PoC steps)

        # ─── Step 8: Phase 1 — Foundry fuzz runs (parallel batches) ────────
        if _skip_to_extract:
            logger.info("  Skipping Steps 8-9.5 (compile failed, fast mode)")
        if not _skip_to_extract:
            FUZZ_RUNS = 3000 if args.fast else 5000
            FUZZ_PARALLEL = args.parallel_fuzz
            FUZZ_BATCH_TIMEOUT = 1800  # per batch

            # Discover all invariant_ functions from FoundryTester
            foundry_tester = chimera_dir / "FoundryTester.sol"
            inv_fns = []
            if foundry_tester.exists():
                for line in foundry_tester.read_text(encoding="utf-8").splitlines():
                    m = re.match(r'\s*function\s+(invariant_\w+)', line)
                    if m:
                        inv_fns.append(m.group(1))

            if not inv_fns:
                # Fallback: single run with all invariants
                inv_fns = ["invariant_"]  # match all

            logger.info(f"  Step 8: Phase 1 — {len(inv_fns)} invariants × {FUZZ_RUNS} runs "
                        f"({FUZZ_PARALLEL} parallel batches)")

            # Split invariants into batches for parallel execution
            batch_size = max(1, len(inv_fns) // FUZZ_PARALLEL + (1 if len(inv_fns) % FUZZ_PARALLEL else 0))
            batches = [inv_fns[i:i + batch_size] for i in range(0, len(inv_fns), batch_size)]

            all_stdout = []
            all_stderr = []
            any_infra_fail = False
            any_invariant_fail = False

            def _run_fuzz_batch(batch_idx_and_fns):
                batch_idx, fns = batch_idx_and_fns
                # Build regex pattern to match multiple invariant functions
                pattern = "|".join(fns) if len(fns) > 1 else fns[0]
                batch_log = clog / f"phase1_batch{batch_idx}.log"
                logger.info(f"    Batch {batch_idx}: {len(fns)} invariants ({fns[0]}...)")
                code, stdout, stderr = _rb.run_cmd(
                    ["forge", "test", "--match-contract", "FoundryTester",
                     "--match-test", pattern, "--fuzz-runs", str(FUZZ_RUNS), "-vv"],
                    timeout=FUZZ_BATCH_TIMEOUT, cwd=repo,
                    log_file=batch_log, env=forge_env
                )
                return batch_idx, code, stdout, stderr

            with ThreadPoolExecutor(max_workers=FUZZ_PARALLEL) as executor:
                futures = {
                    executor.submit(_run_fuzz_batch, (i, batch)): i
                    for i, batch in enumerate(batches)
                }
                for future in as_completed(futures):
                    batch_idx = futures[future]
                    try:
                        _, code, stdout, stderr = future.result()
                        all_stdout.append(stdout)
                        all_stderr.append(stderr)
                        if code != 0:
                            combined = stdout + stderr
                            if "FAIL" in stdout and ("invariant" in stdout.lower() or "assertion" in stdout.lower()):
                                any_invariant_fail = True
                            elif "createFork" in combined or "Connection refused" in combined:
                                any_infra_fail = True
                            elif "setUp()" in stdout and "FAIL" in stdout:
                                any_infra_fail = True
                            else:
                                any_invariant_fail = True  # assume real failure
                    except Exception as e:
                        logger.error(f"    Batch {batch_idx}: error: {e}")

            # Merge batch outputs into single log for downstream parsing
            merged_stdout = "\n".join(all_stdout)
            merged_stderr = "\n".join(all_stderr)
            (clog / "phase1_foundry.log").write_text(
                f"=== CMD: forge test (merged {len(batches)} batches × {FUZZ_RUNS} runs) ===\n"
                f"=== STDOUT ===\n{merged_stdout}\n=== STDERR ===\n{merged_stderr}\n",
                encoding="utf-8"
            )

            if any_infra_fail and not any_invariant_fail:
                logger.error(f"  Phase 1: Infrastructure failure — check RPC/setUp")
                summary["gates"]["phase1"] = False
            elif any_invariant_fail:
                logger.warning(f"  Phase 1: INVARIANT FAILURES detected — potential bugs!")
            else:
                logger.info("  Phase 1: ALL PASS")

            if "phase1" not in summary["gates"]:
                summary["gates"]["phase1"] = True

            if not summary["gates"].get("phase1", False):
                logger.error("  BLOCKED: Phase 1 infra failure — no fuzz data. Cannot extract findings.")
                summary["status"] = "BLOCKED_PHASE1_INFRA"
                return summary

            # ─── Parse Phase 1 failures + optional deep trace ──────────────────
            # Round 2 refinement (LLM-driven re-write + re-fuzz) is gated behind
            # --fuzz-refine flag. Medusa (Phase 2) already explores multi-step
            # sequences, so the refinement round duplicates effort at 20-25 min cost.
            all_fuzz_failures = {}
            current_log = clog / "phase1_foundry.log"
            round_failures = parse_fuzz_failures(current_log)
            all_fuzz_failures.update(round_failures)

            if round_failures and not _SKIP_HEAVY_FUZZ:
                logger.info(f"  Round 0: Deep trace analysis for {len(round_failures)} failures")
                for fail_name in list(round_failures.keys())[:5]:
                    logger.info(f"    Re-running {fail_name} with -vvv...")
                    _, deep_stdout, _ = _rb.run_cmd(
                        ["forge", "test", "--match-test", fail_name, "--fuzz-runs", "100", "-vvv"],
                        timeout=300, cwd=repo,
                        log_file=clog / f"deep_trace_{fail_name}.log",
                        env=forge_env
                    )
                    if deep_stdout and "FAIL" in deep_stdout:
                        all_fuzz_failures[fail_name] = deep_stdout[-5000:]
                        logger.info(f"    {fail_name}: deep trace captured")
            elif round_failures and _SKIP_HEAVY_FUZZ:
                logger.info(f"  Round 0: Skipping deep trace in fast mode ({len(round_failures)} failures — using -vv traces)")

            # ─── Optional: Round 2 refinement (gated by --fuzz-refine) ─────────
            if getattr(args, 'fuzz_refine', False):
                round_label = "Round 1"
                if round_failures:
                    logger.info(f"  {round_label}: {len(round_failures)} failures → writing targeted invariants for same area")
                    failure_traces = "\n".join(
                        f"### {name}\n```\n{trace[:1500]}\n```"
                        for name, trace in list(round_failures.items())[:3]
                    )
                    existing_props = ""
                    for pf in chimera_dir.glob("Properties*.sol"):
                        existing_props += f"\n// {pf.name}\n{pf.read_text(encoding='utf-8')[:5000]}\n"

                    deepen_prompt = (
                        f"The fuzzer BROKE these invariants in {component}:\n\n"
                        f"{failure_traces}\n\n"
                        f"This means there's a real vulnerability in this area. Now DEEPEN the analysis:\n"
                        f"1. Read the counterexample traces above — understand the EXACT attack path\n"
                        f"2. Write 3-5 NEW invariants that probe DEEPER into the same area:\n"
                        f"   - Tighter bounds on the same values\n"
                        f"   - Related state variables that might also be affected\n"
                        f"   - What else can an attacker exploit AFTER this initial break?\n"
                        f"   - Can the attacker chain this with another function for bigger impact?\n"
                        f"3. Also write 2-3 invariants for ADJACENT areas that might have the same root cause\n\n"
                        f"## Current Properties\n```solidity\n{existing_props[:10000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## Source Code (first 15K — full source at {src_file})\n```solidity\n{source_code[:15000]}\n```\n\n"
                        f"APPEND new functions to existing Properties files. Use Setup.sol variables.\n"
                        f"Use Chimera helpers: t(), eq(), gte(), lte()."
                    )
                    _rb._llm(
                        deepen_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / "deepen_round1.log",
                        cwd=repo
                    )
                else:
                    logger.info(f"  {round_label}: All invariants held — writing more aggressive properties")
                    existing_props = ""
                    for pf in chimera_dir.glob("Properties*.sol"):
                        existing_props += f"\n// {pf.name}\n{pf.read_text(encoding='utf-8')[:5000]}\n"

                    refocus_prompt = (
                        f"ALL {component} invariants passed 5000 Foundry fuzz runs without breaking.\n\n"
                        f"This means either: (a) the code is safe, or (b) our invariants are too weak.\n\n"
                        f"## Current Properties (all passing)\n```solidity\n{existing_props[:15000]}\n```\n\n"
                        f"## Source Code (first 20K — full source at {src_file})\n```solidity\n{source_code[:20000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## Task: Write MORE AGGRESSIVE invariants\n"
                        f"Add 5-10 new property functions to the existing Properties files. Focus on:\n"
                        f"1. **Exact equalities** (not just >= or <=) — tighter bounds catch more bugs\n"
                        f"2. **Cross-function state**: after deposit+withdraw, state should be EXACTLY original\n"
                        f"3. **Economic invariants**: no profit from round-trip, no value creation from thin air\n"
                        f"4. **Edge cases**: what happens with amount=0, amount=1, amount=type(uint256).max\n"
                        f"5. **Ordering**: does calling A→B give different result than B→A?\n\n"
                        f"Use variable names from Setup.sol. Use Chimera helpers: t(), eq(), gte(), lte().\n"
                        f"APPEND to existing Properties files — do NOT overwrite them."
                    )
                    _rb._llm(
                        refocus_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / "refocus_round1.log",
                        cwd=repo
                    )

                recompile_ok = _rb.fix_and_retry(
                    "round1_compile", ["forge", "build"],
                    [str(f) for f in chimera_dir.glob("*.sol")],
                    max_retries=3, cwd=repo
                )
                if recompile_ok:
                    logger.info("  Round 1: Re-fuzzing with refined invariants (3K runs)")
                    _rb.run_cmd(
                        ["forge", "test", "--match-contract", "FoundryTester", "--fuzz-runs", "3000", "-vv"],
                        timeout=600, cwd=repo,
                        log_file=clog / "phase1_round1.log",
                        env=forge_env
                    )
                    round1_failures = parse_fuzz_failures(clog / "phase1_round1.log")
                    all_fuzz_failures.update(round1_failures)
                else:
                    logger.warning("  Round 1: New invariants don't compile — skipping re-fuzz")
            else:
                logger.info("  Fuzz-refine round 1 skipped (activate with --fuzz-refine)")

            phase1_fuzz_failures = all_fuzz_failures
            if phase1_fuzz_failures:
                logger.info(f"  Total fuzz failures: {list(phase1_fuzz_failures.keys())}")
            else:
                logger.info("  No fuzz failures in Phase 1")

            # ─── Step 9: Phase 2 — Medusa 15 min (skipped in fast mode) ─────────
            if not _SKIP_HEAVY_FUZZ:
                # ─── Step 9: Phase 2 — Medusa 15 min ─────────────────────────────
                logger.info("  Step 9: Phase 2 — Medusa 15 min")
                medusa_config = chimera_dir / f"medusa-{protocol}.json"
                if not medusa_config.exists():
                    base_name = protocol.split("-")[0] if "-" in protocol else protocol
                    medusa_config = chimera_dir / f"medusa-{base_name}.json"
                if not medusa_config.exists():
                    medusa_config = chimera_dir / "medusa.json"
                if not medusa_config.exists():
                    medusa_candidates = list(chimera_dir.glob("medusa*.json"))
                    if medusa_candidates:
                        medusa_config = medusa_candidates[0]

                if medusa_config.exists():
                    code, stdout, stderr = _rb.run_cmd(
                        ["medusa", "fuzz", "--config", str(medusa_config), "--timeout", "900"],
                        timeout=1000,
                        cwd=repo,
                        log_file=clog / "phase2_medusa.log"
                    )
                    summary["gates"]["phase2"] = True
                else:
                    logger.warning("  Medusa config not found — skipping Phase 2")
                    summary["gates"]["phase2"] = False

                # ─── Step 9.5: Tolerance Tuning ───────────────────────────────────
                logger.info("  Step 9.5: Tolerance Tuning (Claude analyzes fuzz output)")
                phase1_log = clog / "phase1_foundry.log"
                phase2_log_path = clog / "phase2_medusa.log"
                fuzz_output = ""
                for log_path in [phase1_log, phase2_log_path]:
                    if log_path.exists():
                        content = log_path.read_text(encoding="utf-8", errors="replace")
                        if "=== STDOUT ===" in content:
                            fuzz_output += content.split("=== STDOUT ===")[1].split("=== STDERR ===")[0][:8000]

                triage_results = ""
                if fuzz_output.strip() and "FAIL" in fuzz_output:
                    triage_prompt = (
                        f"You are analyzing Foundry/Medusa fuzzing results for {component} in {protocol}.\n\n"
                        f"## Fuzz Output\n```\n{fuzz_output}\n```\n\n"
                        f"## Task\n"
                        f"For EACH failing test/invariant:\n"
                        f"1. Function name that failed\n"
                        f"2. Classify: REAL_BUG / ROUNDING_DUST / MOCK_ARTIFACT / INFRA_ERROR / TEST_ARTIFACT\n"
                        f"3. Reasoning (1 sentence)\n"
                        f"4. If REAL_BUG: what's the attack? If ROUNDING_DUST: what tolerance would fix it?\n\n"
                        f"Output as structured text, one finding per block.\n"
                        f"REAL_BUG = actual exploitable vulnerability\n"
                        f"ROUNDING_DUST = off by 1-2 wei, no economic impact\n"
                        f"MOCK_ARTIFACT = failure caused by mock not matching real behavior\n"
                        f"INFRA_ERROR = fork/RPC/compilation issue, not a bug\n"
                        f"TEST_ARTIFACT = test setup issue, not a protocol bug"
                    )
                    rc, triage_results = _rb._llm(
                        triage_prompt, timeout=180,
                        log_file=clog / "tolerance_tuning.log", cwd=repo
                    )
                    logger.info(f"  Tolerance tuning complete")
                elif fuzz_output.strip():
                    logger.info("  No fuzz failures — all invariants held")
                else:
                    logger.info("  No fuzz output to analyze (infra issue?)")
            else:
                logger.info("  ⚡ Skipping Steps 9-9.5 (Medusa + tolerance tuning)")

    # ─── Step 10: Extract Findings + dedup ──────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.extract import extract_findings
    _ctx_extract = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
        comp_start=comp_start,
        phase1_fuzz_failures=phase1_fuzz_failures,
        phase2_log=phase2_log,
    )
    _ctx_extract.summary = summary  # share by reference
    _extract_result = extract_findings(_ctx_extract)
    if _extract_result == "EARLY_EXIT_hypothesis":
        return summary
    findings = summary["findings"]
    finding_groups = _ctx_extract.finding_groups
    poc_findings = _ctx_extract.poc_findings
    escaped_siblings = _ctx_extract.escaped_siblings
    fallback_findings = _ctx_extract.fallback_findings

    # ─── Step 10.2: Verify findings (lightweight) ──────────────────────────
    from benchmark.component_pipeline.verify import verify_findings_lightweight
    _ctx_verify = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
    )
    _ctx_verify.summary = summary  # share by reference
    _ctx_verify.source_code = source_code
    _ctx_verify.library_code = library_code
    _ctx_verify.finding_groups = finding_groups
    verify_findings_lightweight(_ctx_verify)
    # Rebind locals that downstream Steps consume:
    verified_findings = _ctx_verify.verified_findings

    # ─── Step 10.5: Fork PoC per confirmed finding (Phase 3) ─────────
    if finding_groups:
        logger.info("  Step 10.5: Generating Fork PoCs for confirmed findings")
        poc_dir = Path(repo) / "test" / "poc"
        poc_dir.mkdir(parents=True, exist_ok=True)

        def _run_poc(finding):
            """Delegate to top-level generate_and_test_poc with component context."""
            _rb.generate_and_test_poc(
                finding, source_code, interfaces_code,
                component, protocol, repo, clog, forge_env,
                poc_confidence_threshold=POC_CONFIDENCE_THRESHOLD
            )

        # Run PoC for every verified finding (Step 10.2 output).
        # Fallback to group leaders if verification produced nothing.
        POC_PHASE_TIMEOUT = 12 * 3600 if not args.fast else 3 * 3600
        POC_PARALLEL = args.parallel_poc

        # ── Dedup verified findings before PoC phase ──────────────────────
        # Multiple hunters often find the same bug — verification confirms all of
        # them because they describe the same issue. Without dedup, we'd generate
        # N PoCs for the same bug (N = convergence count, typically 3-5×).
        # Strategy: keep only the best representative per dedup group (lowest rank
        # = highest confidence). If the leader's PoC fails, the group's fallbacks
        # are still attempted in _process_finding's retry logic.
        if verified_findings:
            pre_dedup = len(verified_findings)
            poc_findings = _dedup_for_poc_pure(verified_findings)
            post_dedup = len(poc_findings)
            if pre_dedup != post_dedup:
                logger.info(f"  Step 10.3: Dedup before PoC — {pre_dedup} verified → "
                            f"{post_dedup} unique ({pre_dedup - post_dedup} duplicates removed)")
        else:
            poc_findings = [
                g[0] for g in finding_groups
                if g and (g[0].get("fuzz_confirmed") or g[0].get("confidence", 0) >= POC_CONFIDENCE_THRESHOLD)
            ]

        logger.info(f"  Step 10.5: PoC phase — {len(poc_findings)} verified findings "
                    f"({POC_PHASE_TIMEOUT/3600:.0f}h timer, {POC_PARALLEL} parallel)")
        poc_phase_start = time.time()
        pocs_confirmed = 0

        def _process_finding(idx_and_finding):
            """Generate and test PoC for one verified finding."""
            idx, finding, total = idx_and_finding
            elapsed = time.time() - poc_phase_start
            if elapsed > POC_PHASE_TIMEOUT:
                return idx, False, None
            remaining = POC_PHASE_TIMEOUT - elapsed
            logger.info(f"    [Finding {idx+1}/{total}] {finding['id']} "
                        f"— {remaining/60:.0f}min remaining")
            _run_poc(finding)
            return idx, finding.get("has_poc", False), finding["id"]

        n_poc = len(poc_findings)
        with ThreadPoolExecutor(max_workers=POC_PARALLEL) as executor:
            futures = {
                executor.submit(_process_finding, (i, f, n_poc)): i
                for i, f in enumerate(poc_findings)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    _, confirmed, fid = future.result()
                    if confirmed:
                        pocs_confirmed += 1
                except Exception as e:
                    logger.error(f"    Finding {idx+1}: PoC error: {e}")

        logger.info(f"  PoC phase complete: {pocs_confirmed}/{len(poc_findings)} findings confirmed")

        # ── Step 10.5b+10.6+10.7: Unified Capa 2 (fallback) + Capa 3 (escaped) ──
        # Phase A: Identify fallback candidates (groups where leader failed PoC)
        fallback_findings: list[dict] = []
        for g in finding_groups:
            if len(g) > 1 and not g[0].get("has_poc"):
                for sib in g[1:]:
                    if sib.get("_verified") or sib.get("fuzz_confirmed"):
                        sib["_capa2_fallback"] = True
                        fallback_findings.append(sib)
                        break

        # ── Step 10.6: is_same_bug safety check (Capa 3) ─────────────────
        # For every group whose leader passed PoC, check each sibling:
        # "Is B really the same bug as A, or a different vulnerability?"
        # If DIFFERENT → the sibling escaped dedup by mistake and needs its own PoC.
        # This prevents silent loss of real bugs due to over-aggressive deduplication.
        def _check_is_same_bug(leader: dict, sibling: dict) -> bool:
            """180s Claude call: does sibling describe the same bug as leader?
            Conservative: returns True (SAME) on timeout/error — avoid duplicate PoC work."""
            prompt = _rb.build_is_same_bug_prompt(leader=leader, sibling=sibling)
            fid_s = sibling["id"]
            _, out = _rb._llm(
                prompt, allowed_tools=[], timeout=180, stall_timeout=120,
                log_file=clog / f"{fid_s}_same_bug_check.log", cwd=repo
            )
            # Conservative fallback: empty/timeout → treat as SAME (avoid duplicate PoC work)
            result = (out or "").strip().upper()
            if not result:
                # Timeout/empty → treat as SAME (conservative: avoid duplicate PoC work)
                is_same = True
                verdict = "SAME (timeout fallback)"
                logger.info(f"    is_same_bug({leader['id']}, {fid_s}): {verdict}")
                return is_same
            is_same = result.startswith("SAME") and not result.startswith("DIFFERENT")
            verdict = "SAME" if is_same else "DIFFERENT"
            logger.info(f"    is_same_bug({leader['id']}, {fid_s}): {verdict}")
            return is_same

        # Phase B: is_same_bug check for groups where leader PASSED
        groups_with_passed_leader = [
            g for g in finding_groups
            if len(g) > 1 and g[0].get("has_poc")
        ]
        if groups_with_passed_leader:
            sibling_checks = [
                (g[0], sib)
                for g in groups_with_passed_leader
                for sib in g[1:]
                if sib.get("_verified") or sib.get("fuzz_confirmed")
            ]
            if sibling_checks:
                logger.info(f"  Step 10.6: is_same_bug check — {len(sibling_checks)} siblings "
                            f"across {len(groups_with_passed_leader)} confirmed groups")
                with ThreadPoolExecutor(max_workers=min(8, len(sibling_checks))) as ex:
                    future_map = {
                        ex.submit(_check_is_same_bug, leader, sib): (leader, sib)
                        for leader, sib in sibling_checks
                    }
                    for fut in as_completed(future_map):
                        leader, sib = future_map[fut]
                        try:
                            same = fut.result()
                        except Exception:
                            same = True
                        if not same:
                            sib["_escaped_dedup"] = True
                            escaped_siblings.append(sib)

        # Phase C: Single unified PoC batch for all fallbacks + escaped siblings
        unified_extra = fallback_findings + escaped_siblings
        if unified_extra:
            logger.info(f"  Step 10.7: Unified PoC batch — {len(fallback_findings)} fallbacks + "
                        f"{len(escaped_siblings)} escaped siblings = {len(unified_extra)} total")
            n_extra = len(unified_extra)
            with ThreadPoolExecutor(max_workers=POC_PARALLEL) as executor:
                futures = {
                    executor.submit(_process_finding, (i, f, n_extra)): (i, f)
                    for i, f in enumerate(unified_extra)
                }
                for future in as_completed(futures):
                    i, f = futures[future]
                    try:
                        _, confirmed, fid = future.result()
                        if confirmed:
                            pocs_confirmed += 1
                            source = "Capa 2 fallback" if f.get("_capa2_fallback") else "Escaped sibling"
                            logger.info(f"    {source} {fid}: PoC PASSED — real distinct bug!")
                    except Exception as e:
                        logger.error(f"    Unified batch PoC error: {e}")
            fb_confirmed = sum(1 for f in fallback_findings if f.get("has_poc"))
            esc_confirmed = sum(1 for f in escaped_siblings if f.get("has_poc"))
            logger.info(f"  Unified batch complete: {fb_confirmed} fallbacks + {esc_confirmed} escaped = "
                        f"{fb_confirmed + esc_confirmed} new confirmed")

        # Mark all findings without PoC (default)
        for group in finding_groups:
            for f in group:
                f.setdefault("has_poc", False)
        for f in escaped_siblings:
            f.setdefault("has_poc", False)

    # ─── Step 12: Finding pipeline dispatch ────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.finding import dispatch_finding_pipeline
    _ctx_finding = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
    )
    _ctx_finding.summary = summary  # share by reference
    _ctx_finding.source_code = source_code
    _ctx_finding.comp_start = comp_start
    _ctx_finding.finding_groups = finding_groups
    if 'verified_findings' in dir():
        _ctx_finding.verified_findings = verified_findings
    _ctx_finding.poc_findings = poc_findings
    _ctx_finding.escaped_siblings = escaped_siblings
    _ctx_finding.fallback_findings = fallback_findings
    _finding_result = dispatch_finding_pipeline(_ctx_finding)
    if _finding_result == "EARLY_EXIT_poc_mode":
        return summary
    return summary
