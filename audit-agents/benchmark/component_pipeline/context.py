"""context — Steps -1 through 1.9 of the component pipeline.

Handles clean-slate preparation, prepass execution, skip-hunters detection,
early-exit check, test/knowledge/interfaces loading, and Chimera Setup
pre-generation before the 12 parallel hunters run.

See package __init__.py for the module-split rationale.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from benchmark.component_pipeline.pipeline_context import PipelineContext


# ─── Step -1 ─────────────────────────────────────────────────────────────────

def clean_slate(ctx: PipelineContext) -> None:
    """Step -1: Backup chimera artifacts and reset chimera dir to git state."""
    import shutil
    import run_benchmark as _rb

    chimera_dir = Path(ctx.repo) / "test" / "chimera"
    clog = ctx.clog
    comp_chimera_backup = clog / "chimera_backup"

    ctx.logger.info("  Step -1: Clean slate (reset chimera to git state)")

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
            ["git", "ls-files", str(chimera_dir.relative_to(Path(ctx.repo)))],
            cwd=ctx.repo
        )
        if code_git == 0 and tracked.strip():
            _rb.run_cmd(
                ["git", "checkout", "--", str(chimera_dir.relative_to(Path(ctx.repo)))],
                cwd=ctx.repo
            )
            ctx.logger.info("    Chimera dir reset to git state")

        # Remove generated Properties files from previous merge (untracked)
        for gen_file in chimera_dir.glob("Properties*.sol"):
            if gen_file.name != "Properties.sol":
                code_check, _, _ = _rb.run_cmd(
                    ["git", "ls-files", "--error-unmatch",
                     str(gen_file.relative_to(Path(ctx.repo)))],
                    cwd=ctx.repo
                )
                if code_check != 0:  # untracked = generated
                    gen_file.unlink()
                    ctx.logger.info(f"    Removed generated {gen_file.name}")

    # Clean forge cache — only chimera artifacts (forge detects src staleness via hash)
    chimera_out = Path(ctx.repo) / "out" / "test" / "chimera"
    if chimera_out.exists():
        shutil.rmtree(chimera_out, ignore_errors=True)
        ctx.logger.info("    Cleaned out/test/chimera/ artifacts (forge cache retained)")

    # Clean PoC directory from previous runs
    poc_clean_dir = Path(ctx.repo) / "test" / "poc"
    if poc_clean_dir.exists():
        for old_poc in poc_clean_dir.glob("PoC_*.t.sol"):
            old_poc.unlink()
        ctx.logger.info("    Cleaned test/poc/ from previous runs")


# ─── Step 1 ───────────────────────────────────────────────────────────────────

def run_prepass(ctx: PipelineContext) -> None:
    """Step 1: Detect skip-hunters, run detection_engine prepass.

    Sets ctx._skip_to_merge if --skip-hunters and sufficient hypothesis files
    already exist. Initialises ctx.hyp_dir. Runs prepass detection engine when
    not skipping. Sets ctx.protocol_model = "".
    """
    import sys
    import run_benchmark as _rb

    # ─── Skip-hunters: jump to merge if hypothesis files already exist ────
    if getattr(ctx.args, 'skip_hunters', False):
        hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / ctx.protocol
        existing_hyps = list(hyp_dir.glob(f"hyp_{ctx.component}_*.yaml"))
        if len(existing_hyps) >= 7:  # At least 7 hunter files = valid previous run
            ctx.logger.info(
                f"  --skip-hunters: {len(existing_hyps)} hypothesis files found, "
                f"skipping to merge"
            )
            ctx.summary["gates"]["prepass"] = True
            ctx.summary["gates"]["hunters"] = True
            ctx.summary["gates"]["deepdive"] = (
                hyp_dir / f"hyp_{ctx.component}_DeepDiveHunter.yaml"
            ).exists()
            ctx._skip_to_merge = True
        else:
            ctx.logger.warning(
                f"  --skip-hunters: only {len(existing_hyps)} hypothesis files, "
                f"running full pipeline"
            )

    # ─── Initialise hyp_dir ───────────────────────────────────────────────
    ctx.hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / ctx.protocol
    ctx.hyp_dir.mkdir(parents=True, exist_ok=True)

    if ctx._skip_to_merge:
        ctx.logger.info("  Steps 0-4 SKIPPED (--skip-hunters, reusing existing hypotheses)")

    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    if not ctx._skip_to_merge:
        ctx.logger.info("  Step 0: Ficha init skipped (benchmark mode — not needed)")

    # ─── Step 1: Prepass ─────────────────────────────────────────────────
    prepass_yaml = _rb.HUNT_SESSION_DIR / "results" / f"{ctx.component}_prepass.yaml"
    if ctx._skip_to_merge and prepass_yaml.exists():
        ctx.logger.info("  Step 1: Prepass SKIPPED (existing results)")
        ctx.summary["gates"]["prepass"] = True
    else:
        ctx.logger.info("  Step 1: Prepass (Slither + Aderyn + patterns)")
        code, _, _ = _rb.run_cmd([
            sys.executable, str(_rb.SCRIPT_DIR / "detection_engine.py"),
            "--prepass", "--source", str(ctx.src_dir), "--name", ctx.component,
            "--output", str(_rb.HUNT_SESSION_DIR / "results")
        ], log_file=ctx.clog / "prepass.log", cwd=ctx.repo)
        ctx.summary["gates"]["prepass"] = code == 0

    # protocol_model — not generated by Claude anymore (was Step 1.5, cut for speed)
    # Hunters read the code directly, which is what I did manually
    ctx.protocol_model = ""


# ─── Step 1 early-exit ───────────────────────────────────────────────────────

def check_early_exit(ctx: PipelineContext) -> Optional[str]:
    """Step 1 early-exit: skip all downstream work if prepass is empty (opt-in).

    Returns ``"EMPTY_PREPASS_SKIP"`` sentinel when the orchestrator should
    return immediately; returns ``None`` to continue the pipeline.
    """
    import time
    import run_benchmark as _rb

    prepass_yaml = _rb.HUNT_SESSION_DIR / "results" / f"{ctx.component}_prepass.yaml"

    if getattr(ctx.args, 'skip_empty_prepass', False) and prepass_yaml.exists():
        try:
            import yaml as _yaml
            prepass_data = (
                _yaml.safe_load(prepass_yaml.read_text(encoding='utf-8')) or {}
            )
            total_findings = prepass_data.get(
                'total_findings', len(prepass_data.get('findings', []))
            )
            if total_findings == 0:
                ctx.logger.info(
                    f"  Early-exit: prepass found 0 signals — "
                    f"skipping hunters+merge+fuzz+PoC"
                )
                ctx.summary["status"] = "EMPTY_PREPASS_SKIP"
                ctx.summary["findings"] = []
                comp_elapsed = (time.time() - ctx.comp_start) / 60
                ctx.logger.info(
                    f"  🏁 Component {ctx.component} EARLY-EXIT "
                    f"(empty prepass, {comp_elapsed:.1f}min)"
                )
                return "EMPTY_PREPASS_SKIP"
        except Exception as e:
            ctx.logger.warning(f"  Early-exit check failed: {e} — continuing pipeline")

    return None


# ─── Step 1.6 ────────────────────────────────────────────────────────────────

def load_tests(ctx: PipelineContext) -> None:
    """Step 1.6: Read project's existing tests (inline, no Claude call).

    Populates ``ctx.existing_tests_summary`` and ``ctx._test_files_cache``.
    """
    # Include raw test content in hunter brief — hunters interpret it themselves.
    # QW6: Load once into _test_files_cache, derive slices at consumption points.
    ctx.existing_tests_summary = ""
    ctx._test_files_cache = []
    test_dir = Path(ctx.repo) / "test"
    if test_dir.exists():
        test_files = [f for f in test_dir.glob("*.sol") if "chimera" not in str(f)]
        for tf in sorted(test_files)[:3]:  # max 3 test files, raw content
            content = tf.read_text(encoding="utf-8")
            ctx._test_files_cache.append((tf.name, content))
            ctx.existing_tests_summary += f"\n// === {tf.name} ===\n{content[:3000]}\n"
        if ctx.existing_tests_summary:
            ctx.logger.info(
                f"  Loaded {len(test_files)} existing test files "
                f"(raw, {len(ctx.existing_tests_summary)} chars)"
            )


# ─── Step 1.7 ────────────────────────────────────────────────────────────────

def load_knowledge(ctx: PipelineContext) -> None:
    """Step 1.7: Load relevant knowledge base briefings.

    Populates ``ctx.knowledge_context``.
    """
    from paths import WEB3_DIR

    ctx.knowledge_context = ""
    knowledge_dir = WEB3_DIR / "knowledge"
    if knowledge_dir.exists():
        # Auto-detect relevant briefings based on source code keywords
        code_lower = ctx.source_code.lower()
        relevant_briefings = []
        briefing_map = {
            "concentrated-liquidity.md": [
                "uniswapv3", "tickmath", "sqrtprice", "liquidity", "tick"
            ],
            "yield-aggregator.md": [
                "vault", "strategy", "yield", "harvest", "compound"
            ],
            "dex-amm.md": ["swap", "pool", "amm", "router", "slippage"],
            "lending-market-forks.md": [
                "lendingpool", "borrow", "collateral", "liquidat", "interest"
            ],
            "liquidation-mechanics.md": [
                "liquidat", "health", "collateral", "undercollateral"
            ],
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
            ctx.knowledge_context += (
                f"\n## Known bugs from {bp.name}:\n{content[:3000]}\n"
            )
        if relevant_briefings:
            ctx.logger.info(
                f"  Loaded {len(relevant_briefings)} knowledge briefings: "
                f"{[b.name for b in relevant_briefings[:3]]}"
            )


# ─── Step 1.8 ────────────────────────────────────────────────────────────────

def load_interfaces(ctx: PipelineContext) -> None:
    """Step 1.8: Read interfaces directory.

    Populates ``ctx.interfaces_code``.
    """
    ctx.interfaces_code = ""
    iface_dir = ctx.src_dir / "interfaces"
    if iface_dir.exists():
        for iface_file in sorted(iface_dir.glob("*.sol")):
            content = iface_file.read_text(encoding="utf-8")
            ctx.interfaces_code += f"\n// === {iface_file.name} ===\n{content}\n"
        if ctx.interfaces_code:
            ctx.logger.info(
                f"  Loaded {len(list(iface_dir.glob('*.sol')))} interface files"
            )


# ─── Step 1.9 ────────────────────────────────────────────────────────────────

def ensure_chimera_setup(ctx: PipelineContext) -> None:
    """Step 1.9: Pre-generate Chimera Setup.sol before hunters run.

    Hunters need Setup.sol to know which variables exist (strategy, vault, etc.).
    Without it, they write invariants that reference non-existent variables.
    Sets ``ctx.setup_sol_text`` if generation succeeds.
    """
    import run_benchmark as _rb

    setup_path = Path(ctx.repo) / "test" / "chimera" / "Setup.sol"

    if ctx._skip_to_merge:
        ctx.logger.info("  Step 1.9: SKIPPED (--skip-hunters)")
        return

    if setup_path.exists():
        return

    ctx.logger.info("  Step 1.9: Generate Chimera Setup (needed for hunter context)")
    chimera_dir_early = Path(ctx.repo) / "test" / "chimera"
    chimera_dir_early.mkdir(parents=True, exist_ok=True)

    # QW6: Reuse _test_files_cache loaded in Step 1.6 (no re-read from disk)
    existing_test_code = ""
    for _tf_name, _tf_content in ctx._test_files_cache:
        existing_test_code += f"\n// === {_tf_name} ===\n{_tf_content[:5000]}\n"

    # Read foundry.toml for remappings and compiler settings
    foundry_toml = ""
    foundry_path = Path(ctx.repo) / "foundry.toml"
    if foundry_path.exists():
        foundry_toml = foundry_path.read_text(encoding="utf-8")[:3000]

    setup_prompt = (
        f"Generate a complete Chimera fuzzing setup for {ctx.component} in {ctx.protocol}.\n\n"
        f"## Source Code\n```solidity\n{ctx.source_code}\n```\n\n"
        f"## Libraries\n```solidity\n{ctx.library_code[:20000]}\n```\n\n"
        f"## Interfaces\n```solidity\n{ctx.interfaces_code[:10000]}\n```\n\n"
        f"## Project's Own Tests (CRITICAL — shows how THEY deploy the contracts)\n"
        f"```solidity\n{existing_test_code[:8000]}\n```\n\n"
        f"## foundry.toml (remappings, compiler version)\n```toml\n{foundry_toml}\n```\n\n"
        f"Create these files in {chimera_dir_early}/:\n"
        f"- Setup.sol: abstract contract that deploys {ctx.component} with ALL its dependencies.\n"
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
        log_file=ctx.clog / "chimera_setup_early.log",
        cwd=ctx.repo
    )
    if setup_path.exists():
        ctx.logger.info(f"  Setup.sol generated ({setup_path.stat().st_size} bytes)")
    else:
        ctx.logger.warning("  Setup.sol generation failed — hunters will work without it")
