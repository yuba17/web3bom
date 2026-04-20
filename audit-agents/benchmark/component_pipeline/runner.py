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
)
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

    # ─── Step 2: 12 Hunters ──────────────────────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.hunters import run_hunters, BLOCKED_HUNTERS
    _ctx_hunters = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir,
        hyp_dir=_rb.HUNT_SESSION_DIR / "hypotheses" / protocol,
        clog=clog,
        src_file=src_file if 'src_file' in dir() else Path("."),
    )
    _ctx_hunters.summary = summary
    _ctx_hunters._skip_to_merge = _skip_to_merge
    if 'source_code' in dir(): _ctx_hunters.source_code = source_code
    if 'library_code' in dir(): _ctx_hunters.library_code = library_code
    if 'accumulated_context' in dir(): _ctx_hunters.accumulated_context = accumulated_context
    if 'protocol_model' in dir(): _ctx_hunters.protocol_model = protocol_model
    if 'interfaces_code' in dir(): _ctx_hunters.interfaces_code = interfaces_code
    if 'existing_tests_summary' in dir(): _ctx_hunters.existing_tests_summary = existing_tests_summary
    if 'knowledge_context' in dir(): _ctx_hunters.knowledge_context = knowledge_context
    _hunters_result = run_hunters(_ctx_hunters, hunters_subset=hunters_subset)
    if _hunters_result == BLOCKED_HUNTERS:
        return summary
    # Propagate ctx fields mutated by run_hunters back to local variables
    hyp_dir = _ctx_hunters.hyp_dir
    setup_sol_text = _ctx_hunters.setup_sol_text
    setup_var_names = _ctx_hunters.setup_var_names
    prepass_signals_text = _ctx_hunters.prepass_signals_text
    interfaces_code = _ctx_hunters.interfaces_code
    existing_tests_summary = _ctx_hunters.existing_tests_summary
    knowledge_context = _ctx_hunters.knowledge_context

    # ─── Step 4: DeepDive hunter ─────────────────────────────────────────
    if not _skip_to_merge:
        from benchmark.component_pipeline.deepdive import run_deepdive
        _ctx_dd = PipelineContext(
            component=component, repo=repo, protocol=protocol,
            args=args, logger=logger,
            src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
            src_file=src_file if 'src_file' in dir() else Path("."),
        )
        _ctx_dd.summary = summary
        if 'source_code' in dir(): _ctx_dd.source_code = source_code
        if 'library_code' in dir(): _ctx_dd.library_code = library_code
        if 'accumulated_context' in dir(): _ctx_dd.accumulated_context = accumulated_context
        if 'prepass_signals_text' in dir(): _ctx_dd.prepass_signals_text = prepass_signals_text
        if 'setup_sol_text' in dir(): _ctx_dd.setup_sol_text = setup_sol_text
        if 'protocol_model' in dir(): _ctx_dd.protocol_model = protocol_model
        run_deepdive(_ctx_dd)

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
        # ─── Steps 5-7: Ensure Setup + Merge invariants + compile ──────
        from benchmark.component_pipeline.pipeline_context import PipelineContext
        from benchmark.component_pipeline.merge import run_merge, SKIP_TO_EXTRACT
        _ctx_merge = PipelineContext(
            component=component, repo=repo, protocol=protocol,
            args=args, logger=logger,
            src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
            src_file=src_file if 'src_file' in dir() else Path("."),
        )
        _ctx_merge.summary = summary
        if 'source_code' in dir(): _ctx_merge.source_code = source_code
        if 'library_code' in dir(): _ctx_merge.library_code = library_code
        if 'interfaces_code' in dir(): _ctx_merge.interfaces_code = interfaces_code
        if 'existing_tests_summary' in dir(): _ctx_merge.existing_tests_summary = existing_tests_summary
        if 'knowledge_context' in dir(): _ctx_merge.knowledge_context = knowledge_context
        if 'setup_sol_text' in dir(): _ctx_merge.setup_sol_text = setup_sol_text
        _merge_result = run_merge(_ctx_merge)
        # Rebind updated locals:
        setup_sol_text = _ctx_merge.setup_sol_text
        # Propagate blocking states back to caller
        if _ctx_merge.summary.get("status") in ("BLOCKED_CHIMERA", "BLOCKED_MERGE", "BLOCKED_COMPILE"):
            return summary
        _skip_to_extract = False
        if _merge_result == SKIP_TO_EXTRACT:
            _skip_to_extract = True

        # ─── Step 7.5: Enhance TargetFunctions (opt-in) ────────────────
        if _skip_to_extract:
            logger.info("  Skipping Step 7.5 (compile failed, fast mode)")
        else:
            from benchmark.component_pipeline.pipeline_context import PipelineContext
            from benchmark.component_pipeline.enhance import enhance_target_functions
            _ctx_enhance = PipelineContext(
                component=component, repo=repo, protocol=protocol,
                args=args, logger=logger,
                src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
                src_file=src_file if 'src_file' in dir() else Path("."),
            )
            _ctx_enhance.summary = summary
            _ctx_enhance.setup_sol_text = setup_sol_text
            enhance_target_functions(_ctx_enhance)

        # ─── Step 8: Phase 1 + Step 9: Phase 2 + Step 9.5: Tolerance Tuning ──
        if _skip_to_extract:
            logger.info("  Skipping Steps 8-9.5 (compile failed, fast mode)")
        if not _skip_to_extract:
            from benchmark.component_pipeline.fuzz import (
                run_phase1_foundry, run_phase2_medusa, BLOCKED_PHASE1_INFRA,
            )
            _ctx_fuzz = PipelineContext(
                component=component, repo=repo, protocol=protocol,
                args=args, logger=logger,
                src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
                src_file=src_file if 'src_file' in dir() else Path("."),
            )
            _ctx_fuzz.summary = summary
            if 'setup_sol_text' in dir(): _ctx_fuzz.setup_sol_text = setup_sol_text
            if 'source_code' in dir(): _ctx_fuzz.source_code = source_code
            _fuzz1_result = run_phase1_foundry(_ctx_fuzz)
            if _fuzz1_result == BLOCKED_PHASE1_INFRA:
                return summary
            run_phase2_medusa(_ctx_fuzz)
            # Rebind outputs for downstream steps:
            phase1_fuzz_failures = _ctx_fuzz.phase1_fuzz_failures
            phase2_log = _ctx_fuzz.phase2_log

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

    # ─── Step 11: Fork PoC per finding (Phase 3) ───────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.poc import generate_fork_pocs
    _ctx_poc = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
        src_file=src_file if 'src_file' in dir() else Path("."),
    )
    _ctx_poc.summary = summary
    if 'source_code' in dir(): _ctx_poc.source_code = source_code
    if 'library_code' in dir(): _ctx_poc.library_code = library_code
    if 'interfaces_code' in dir(): _ctx_poc.interfaces_code = interfaces_code
    if 'verified_findings' in dir(): _ctx_poc.verified_findings = verified_findings
    _ctx_poc.finding_groups = finding_groups
    _ctx_poc.poc_findings = poc_findings
    _ctx_poc.escaped_siblings = escaped_siblings
    _ctx_poc.fallback_findings = fallback_findings
    generate_fork_pocs(_ctx_poc)
    # Rebind locals downstream steps consume:
    finding_groups = _ctx_poc.finding_groups
    poc_findings = _ctx_poc.poc_findings
    fallback_findings = _ctx_poc.fallback_findings
    escaped_siblings = _ctx_poc.escaped_siblings

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
