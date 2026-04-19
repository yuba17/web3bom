#!/usr/bin/env python3
"""
run_benchmark.py — Pipeline orchestrator that enforces ALL steps for each component.

Runs the full hunt pipeline sequentially. No steps can be skipped.
Uses claude CLI (-p) for LLM analysis, subprocess for tools.

Usage:
    python3 run_benchmark.py \\
      --repo /path/to/repo \\
      --components Strategy,Leverager,Vault,LendingPool \\
      --protocol yieldoor \\
      --ground-truth benchmarks/yieldoor/benchmark.yaml

    python3 run_benchmark.py \\
      --repo /path/to/repo \\
      --components Strategy \\
      --protocol myprotocol \\
      --skip-phase3          # explicit flag required to skip fork PoC
"""

import argparse
import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from finding_pipeline import (
    extract_fingerprint,
    dedup_findings as _dedup_findings_pure,
    collect_verify_candidates as _collect_verify_candidates_pure,
    dedup_for_poc as _dedup_for_poc_pure,
    extract_findings_from_yaml,
    extract_relevant_code as _extract_relevant_code_shared,
    build_verify_prompt as _build_verify_prompt_shared,
    build_is_same_bug_prompt as _build_is_same_bug_prompt_shared,
    format_funnel,
    POC_CONFIDENCE_THRESHOLD,
)

# ─── Global Claude concurrency limiter ───────────────────────────────────────
# Safety net against runaway concurrency bugs — NOT a rate-limit guard.
# Tier 4 API: 4K RPM / 2M input tok/min. Our peak: 2 components × 9 hunters =
# 18 calls × 8k tokens ≈ 144k tok/min = 7% of limit. API is NOT the bottleneck.
# Default 24: enough for 2×9 hunters (18) + 2×10 verification (20) fully parallel,
# while capping any accidental explosion. PoC concurrency is separately controlled
# by --parallel-poc (forge/RAM bound, not API bound).
_CLAUDE_SEMAPHORE = threading.Semaphore(
    int(os.environ.get("MAX_CLAUDE_CONCURRENT", "24"))
)

# Add audit-agents to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

# ─── Paths ───────────────────────────────────────────────────────────────────

from paths import WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR

SCRIPT_DIR = AUDIT_AGENTS_DIR
PROMPTS_DIR = SCRIPT_DIR / "prompts"
# POC_CONFIDENCE_THRESHOLD imported from finding_pipeline
IS_PRE_PRODUCTION = False      # set in main() — changes PoC strategy to deploy-on-fork

# ─── Load .env if present ────────────────────────────────────────────────────
_env_file = WEB3_DIR / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and val and key not in os.environ:
                os.environ[key] = val

# ─── Logging ─────────────────────────────────────────────────────────────────

LOG_DIR = None  # set in main()
logger = logging.getLogger("orchestrator")


def setup_logging(protocol: str):
    global LOG_DIR
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    # Keep logs inside the session dir so benchmark logs don't pollute WEB3_DIR/logs/
    LOG_DIR = HUNT_SESSION_DIR / "logs" / f"{protocol}_{timestamp}"
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(LOG_DIR / "orchestrator.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    # Flush stdout immediately so tee shows progress in real-time
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)
    logger.info(f"Logging to {LOG_DIR}")
    sys.stdout.reconfigure(line_buffering=True)  # force line-buffered stdout


def component_log_dir(component: str) -> Path:
    d = LOG_DIR / component
    d.mkdir(parents=True, exist_ok=True)
    return d


def detect_pragma(repo: str) -> str:
    """Detect pragma from project source files."""
    repo_path = Path(repo)
    for d in [repo_path / "src", repo_path / "contracts", repo_path]:
        if not d.is_dir():
            continue
        for sol in sorted(d.glob("**/*.sol"))[:10]:
            try:
                for line in sol.read_text(encoding="utf-8").splitlines():
                    m = re.match(r'\s*(pragma\s+solidity\s+[^;]+;)', line)
                    if m:
                        return m.group(1)
            except Exception:
                continue
    return "pragma solidity ^0.8.0;"


# ─── LLM runners (extracted to benchmark/llm_runners in Phase 6) ────────────
from benchmark.llm_runners import (  # noqa: F401
    run_claude, _run_claude_inner, run_claude_sub, _llm, run_cmd,
    _extract_first_errors,
    # module-level globals also re-exported so existing code in this file
    # and tests that do monkeypatch.setattr(run_benchmark, "_llm", ...) work
    _CLAUDE_SEMAPHORE, _AGENTIC_TOOLS,
)
import benchmark.llm_runners as _llm_runners_mod  # for main() to mutate globals

# ─── LLM dispatcher globals (owned by llm_runners; local copies for this module) ──
# These are READ by functions in this file (run_hunters, etc.).
# main() updates BOTH llm_runners and these local names via inline assignment.
USE_SUB_MODE = False  # Set in main() based on --mode sub
SUB_MODEL = "sonnet"  # Set in main()
PARALLEL_HUNTERS = 6  # Set in main() from --parallel-hunters
POC_GEN_TIMEOUT = 900  # Set in main() based on --mode and --poc-timeout
DISABLE_FEW_SHOT = False  # Set in main() from --no-few-shot


# ─── PoC pipeline (extracted to benchmark/poc_pipeline in Phase 6) ───────────
from benchmark.poc_pipeline import (  # noqa: F401
    fix_and_retry, _generate_foundry_tester_wrappers, _log_funnel,
    _sanitize_sol_unicode, _filter_errors_for_file, generate_and_test_poc,
)


# ─── Pipeline Gate ───────────────────────────────────────────────────────────

def check_gate(component: str, gate: str, protocol: str, repo: str = "") -> bool:
    """Run pipeline_gate.py and return True if gate passes."""
    cmd = [
        sys.executable, str(SCRIPT_DIR / "pipeline_gate.py"),
        "-c", component, "--gate", gate, "--protocol", protocol,
        "--session-dir", str(HUNT_SESSION_DIR),
    ]
    if repo:
        cmd += ["--repo", repo]

    code, stdout, stderr = run_cmd(cmd)
    logger.info(f"  Gate {gate}: {'PASS' if code == 0 else 'FAIL'}")
    return code == 0


# ─── Prompt builders (extracted to benchmark/prompt_builders in Phase 6) ───
from benchmark.prompt_builders import (  # noqa: F401
    load_prompt, read_source,
    build_hunter_brief, build_hunter_dispatch_prompt, build_deepdive_prompt,
    build_poc_prompt, build_escalation_prompt, build_redteam_prompt,
    build_variant_prompt, build_report_prompt, build_cross_pair_prompt,
)

build_verify_prompt = _build_verify_prompt_shared

build_is_same_bug_prompt = _build_is_same_bug_prompt_shared




# ─── Component Pipeline ─────────────────────────────────────────────────────

def run_component_pipeline(component: str, repo: str, protocol: str,
                           args: argparse.Namespace,
                           accumulated_context: str = "",
                           hunters_subset: set | None = None) -> dict:
    """Run the full pipeline for one component. Returns summary dict."""
    comp_start = time.time()
    logger.info(f"\n{'='*60}")
    logger.info(f"  🔍 COMPONENT: {component}")
    logger.info(f"{'='*60}")

    clog = component_log_dir(component)
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
        hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
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
        code_git, tracked, _ = run_cmd(
            ["git", "ls-files", str(chimera_dir.relative_to(Path(repo)))],
            cwd=repo
        )
        if code_git == 0 and tracked.strip():
            run_cmd(["git", "checkout", "--", str(chimera_dir.relative_to(Path(repo)))], cwd=repo)
            logger.info("    Chimera dir reset to git state")

        # Remove generated Properties files from previous merge (untracked)
        for gen_file in chimera_dir.glob("Properties*.sol"):
            if gen_file.name != "Properties.sol":
                code_check, _, _ = run_cmd(
                    ["git", "ls-files", "--error-unmatch", str(gen_file.relative_to(Path(repo)))],
                    cwd=repo
                )
                if code_check != 0:  # untracked = generated
                    gen_file.unlink()
                    logger.info(f"    Removed generated {gen_file.name}")

    # Clean forge cache
    out_dir = Path(repo) / "out"
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
        logger.info("    Cleaned forge out/ cache")

    # Clean PoC directory from previous runs
    poc_clean_dir = Path(repo) / "test" / "poc"
    if poc_clean_dir.exists():
        for old_poc in poc_clean_dir.glob("PoC_*.t.sol"):
            old_poc.unlink()
        logger.info("    Cleaned test/poc/ from previous runs")

    # ─── Skip Steps 0-4 if --skip-hunters and hypothesis files exist ────
    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    if _skip_to_merge:
        logger.info("  Steps 0-4 SKIPPED (--skip-hunters, reusing existing hypotheses)")

    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    # Benchmark pipelines never read the ficha back (scope gate is not checked here),
    # so skipping is safe and avoids contaminating the real hunt_session/fichas/.
    if not _skip_to_merge:
        logger.info("  Step 0: Ficha init skipped (benchmark mode — not needed)")

    # ─── Step 1: Prepass ─────────────────────────────────────────────────
    prepass_yaml = HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
    if _skip_to_merge and prepass_yaml.exists():
        logger.info("  Step 1: Prepass SKIPPED (existing results)")
        summary["gates"]["prepass"] = True
    else:
        logger.info("  Step 1: Prepass (Slither + Aderyn + patterns)")
        code, _, _ = run_cmd([
            sys.executable, str(SCRIPT_DIR / "detection_engine.py"),
            "--prepass", "--source", str(src_dir), "--name", component,
            "--output", str(HUNT_SESSION_DIR / "results")
        ], log_file=clog / "prepass.log", cwd=repo)
        summary["gates"]["prepass"] = code == 0

    # protocol_model — not generated by Claude anymore (was Step 1.5, cut for speed)
    # Hunters read the code directly, which is what I did manually
    protocol_model = ""

    # ─── Step 1.6: Read project's existing tests (inline, no Claude call) ──
    # Include raw test content in hunter brief — hunters interpret it themselves
    existing_tests_summary = ""
    test_dir = Path(repo) / "test"
    if test_dir.exists():
        test_files = [f for f in test_dir.glob("*.sol") if "chimera" not in str(f)]
        for tf in sorted(test_files)[:3]:  # max 3 test files, raw content
            content = tf.read_text(encoding="utf-8")
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

        # Read project's own tests to understand deployment pattern
        existing_test_code = ""
        test_dir = Path(repo) / "test"
        if test_dir.exists():
            for tf in sorted(test_dir.glob("*.sol"))[:3]:
                content = tf.read_text(encoding="utf-8")
                existing_test_code += f"\n// === {tf.name} ===\n{content[:5000]}\n"

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
        _llm(
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
    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
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
        prepass_path = HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
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
        context_dir = HUNT_SESSION_DIR / "context" / f"{protocol}-bench"
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

        if USE_SUB_MODE:
            # Sub mode: dispatch individual hunters in parallel from Python
            # Each hunter gets agentic tools to explore code autonomously
            from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
            methodology_dir = SCRIPT_DIR / "prompts" / "hunters"

            def _run_single_hunter(hunter_name: str) -> str:
                domain_key = HUNTER_DOMAINS.get(hunter_name, ("general", ""))[0]
                rejection_ctx = load_rejection_context()
                few_shot_ctx = "" if DISABLE_FEW_SHOT else load_few_shot_examples(domain_key)

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
                _llm(prompt, allowed_tools=["Read", "Write", "Grep", "Glob", "Bash"],
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
            logger.info(f"  Sub mode: {len(hunters)} hunters, {PARALLEL_HUNTERS} parallel")
            failed_hunters = []
            with ThreadPoolExecutor(max_workers=PARALLEL_HUNTERS) as executor:
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
            rc, out = _llm(
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
            "python3", str(SCRIPT_DIR / "verify_team_outputs.py"),
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

        _llm(
            deepdive_prompt,
            allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
            timeout=1800,
            log_file=clog / "deepdive.log",
            cwd=repo
        )

        # Rescue DeepDive YAML: Claude may write to cwd (worktree root) instead of hyp_dir.
        # Use find to locate the file wherever it landed in the worktree, then copy to hyp_dir.
        dd_yaml_target = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
        if not dd_yaml_target.exists():
            import shutil as _shutil_dd
            import subprocess as _sp_dd
            _find = _sp_dd.run(
                ["find", str(repo), "-name", f"hyp_{component}_DeepDiveHunter.yaml", "-type", "f"],
                capture_output=True, text=True
            )
            for _found in _find.stdout.strip().splitlines():
                if _found and Path(_found) != dd_yaml_target:
                    _shutil_dd.copy2(_found, dd_yaml_target)
                    logger.info(f"  Rescued DeepDive YAML from worktree: {Path(_found).name} → {hyp_dir.name}/")
                    break

        deepdive_ok = check_gate(component, "deepdive", protocol, repo)
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
            _llm(
                chimera_prompt,
                allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
                timeout=1500,  # Increased: complex components need >600s for full setup
                log_file=clog / "chimera_builder.log",
                cwd=repo
            )

        # Verify base chimera compiles before merge
        logger.info("  Step 5b: Verify base chimera compiles")
        base_compile_ok = fix_and_retry(
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

        # ─── Step 5c: Second-chance rescue of DeepDive YAML before merge ──────
        # (Primary rescue is right after run_claude; this catches any edge cases)
        dd_yaml_pre = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
        if not dd_yaml_pre.exists():
            import shutil as _shutil_pre, subprocess as _sp_pre
            _find2 = _sp_pre.run(
                ["find", str(repo), "-name", f"hyp_{component}_DeepDiveHunter.yaml", "-type", "f"],
                capture_output=True, text=True
            )
            for _f2 in _find2.stdout.strip().splitlines():
                if _f2 and Path(_f2) != dd_yaml_pre:
                    _shutil_pre.copy2(_f2, dd_yaml_pre)
                    logger.info(f"  Pre-merge rescue: {Path(_f2).name} → {hyp_dir.name}/")
                    break

        # ─── Step 6: Merge Invariants (setup-aware) ──────────────────────────
        logger.info("  Step 6: Merge Invariants")

        # Extract available variables from Setup.sol so merge knows what exists
        setup_context = ""
        if setup_sol.exists():
            setup_content = setup_sol.read_text(encoding="utf-8")
            setup_context = setup_content[:20000]  # Full Setup.sol — critical for compile fixes

        code, _, _ = run_cmd([
            sys.executable, str(SCRIPT_DIR / "merge_invariants.py"),
            "--component", component,
            "--hypotheses-dir", str(hyp_dir),
            "--session-dir", str(HUNT_SESSION_DIR),
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
        _generate_foundry_tester_wrappers(chimera_dir)

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
            code, stdout, stderr = run_cmd(["forge", "build"], cwd=repo)
            if code == 0:
                logger.info(f"  ✅ Compile passed (attempt {attempt + 1})")
                break

            error_text = _extract_first_errors(stderr, max_errors=25, max_chars=5000)
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
                _llm(
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

        # ─── Step 7.5: Enhance TargetFunctions with attack sequences ────────
        if _skip_to_extract:
            logger.info("  Skipping Step 7.5 (compile failed, fast mode)")
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
                    _llm(
                        enhance_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / "target_functions_enhance.log",
                        cwd=repo
                    )
                    # Quick recompile to make sure enhancement didn't break anything
                    recomp_ok = fix_and_retry(
                        "targetfunc_compile", ["forge", "build"],
                        [str(target_funcs_path)], max_retries=2, cwd=repo
                    )
                    if recomp_ok:
                        logger.info("  TargetFunctions enhanced and compiles")
                    else:
                        logger.warning("  TargetFunctions enhancement broke compile — reverting")
                        run_cmd(["git", "checkout", "--", str(target_funcs_path.relative_to(Path(repo)))], cwd=repo)
                        run_cmd(["forge", "build"], cwd=repo)  # restore working state
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
                code, stdout, stderr = run_cmd(
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

            # ─── ITERATIVE FUZZ-REFINE LOOP (max 3 rounds) ─────────────────────
            # This replicates what I did manually: fuzz → analyze → refine → re-fuzz
            # Round 0 = Phase 1 already ran above
            # Round 1+ = targeted refinement based on what we learned
            all_fuzz_failures = {}  # accumulate across rounds

            for fuzz_round in range(2):  # max 2 rounds: initial + 1 refinement
                round_label = f"Round {fuzz_round}"

                # ─── Analyze current fuzz results ─────────────────────────────
                if fuzz_round == 0:
                    current_log = clog / "phase1_foundry.log"
                else:
                    current_log = clog / f"phase1_round{fuzz_round}.log"

                round_failures = parse_fuzz_failures(current_log)
                all_fuzz_failures.update(round_failures)

                # ─── Deep trace analysis for failures (-vvvv) ─────────────────
                # Skip in fast mode: normal -vv already has call sequences for PoC gen.
                # Deep trace adds opcodes/SLOAD/SSTORE detail but costs 10-15 min with
                # frequent timeouts, and content gets truncated before use anyway.
                if round_failures and not _SKIP_HEAVY_FUZZ:
                    logger.info(f"  {round_label}: Deep trace analysis for {len(round_failures)} failures")
                    for fail_name in list(round_failures.keys())[:5]:
                        logger.info(f"    Re-running {fail_name} with -vvvv...")
                        _, deep_stdout, _ = run_cmd(
                            ["forge", "test", "--match-test", fail_name, "--fuzz-runs", "100", "-vvvv"],
                            timeout=300, cwd=repo,
                            log_file=clog / f"deep_trace_{fail_name}.log",
                            env=forge_env
                        )
                        if deep_stdout and "FAIL" in deep_stdout:
                            all_fuzz_failures[fail_name] = deep_stdout[-5000:]
                            logger.info(f"    {fail_name}: deep trace captured")
                elif round_failures and _SKIP_HEAVY_FUZZ:
                    logger.info(f"  {round_label}: Skipping deep trace in fast mode ({len(round_failures)} failures — using -vv traces)")

                # ─── Decide: refine or stop? ──────────────────────────────────
                if fuzz_round >= 1:
                    logger.info(f"  {round_label}: Max refinement reached — proceeding to Medusa")
                    break

                if round_failures and fuzz_round < 1:
                    # FOUND BUGS → write MORE invariants targeting the SAME area
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
                    _llm(
                        deepen_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / f"deepen_round{fuzz_round + 1}.log",
                        cwd=repo
                    )

                elif not round_failures:
                    # ALL PASS → invariants too weak, write more aggressive ones
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
                    _llm(
                        refocus_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / f"refocus_round{fuzz_round + 1}.log",
                        cwd=repo
                    )

                # ─── Re-compile and re-fuzz ───────────────────────────────────
                recompile_ok = fix_and_retry(
                    f"round{fuzz_round + 1}_compile", ["forge", "build"],
                    [str(f) for f in chimera_dir.glob("*.sol")],
                    max_retries=3, cwd=repo
                )
                if not recompile_ok:
                    logger.warning(f"  {round_label}: New invariants don't compile — stopping refinement loop")
                    break

                # Re-fuzz with new invariants
                logger.info(f"  Round {fuzz_round + 1}: Re-fuzzing with refined invariants (3K runs)")
                run_cmd(
                    ["forge", "test", "--match-contract", "FoundryTester", "--fuzz-runs", "3000", "-vv"],
                    timeout=600, cwd=repo,
                    log_file=clog / f"phase1_round{fuzz_round + 1}.log",
                    env=forge_env
                )

            # Update fuzz_failures for downstream use (includes all rounds)
            phase1_fuzz_failures = all_fuzz_failures
            if phase1_fuzz_failures:
                logger.info(f"  Total fuzz failures across all rounds: {list(phase1_fuzz_failures.keys())}")
            else:
                logger.info(f"  No fuzz failures after {fuzz_round + 1} rounds of refinement")

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
                    code, stdout, stderr = run_cmd(
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
                    rc, triage_results = _llm(
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

    # ─── Step 10: Extract Findings ──────────────────────────────────────
    logger.info("  Step 10: Extract findings from hypotheses + fuzz results")

    # Rescue misplaced YAML files — hunters may write inside repo instead of global dir
    import shutil as _shutil
    for rescue_dir in [
        Path(repo) / "hunt_session" / "hypotheses",
        Path(repo) / "hunt_session" / "hypotheses" / protocol,
        Path(repo) / "results",
    ]:
        if rescue_dir.exists():
            for misplaced in rescue_dir.glob(f"hyp_{component}_*.yaml"):
                target = hyp_dir / misplaced.name
                if not target.exists():
                    _shutil.copy2(misplaced, target)
                    logger.info(f"    Rescued {misplaced.name} → {hyp_dir.name}/")

    # Parse fuzz results — combine iterative loop results + Medusa
    # phase1_fuzz_failures already accumulated from all fuzz rounds above
    fuzz_failures = dict(phase1_fuzz_failures)  # copy accumulated Phase 1 results
    medusa_failures = parse_fuzz_failures(phase2_log) if phase2_log.exists() else {}
    fuzz_failures.update(medusa_failures)
    if fuzz_failures:
        logger.info(f"  Fuzz failures detected: {list(fuzz_failures.keys())}")

    findings = extract_findings(component, protocol, fuzz_failures)
    summary["findings"] = findings
    logger.info(f"  Found {len(findings)} findings ({sum(1 for f in findings if f.get('fuzz_confirmed'))} fuzz-confirmed)")

    # ─── Early exit for hypothesis mode ──────────────────────────────────
    # In hypothesis mode, scoring happens at the main() level against the YAML files.
    # No PoC generation, no verification, no RedTeam. Fastest possible iteration.
    benchmark_mode_flag = getattr(args, "benchmark_mode", "redteam")
    if benchmark_mode_flag == "hypothesis":
        comp_elapsed = (time.time() - comp_start) / 60
        logger.info(f"  🏁 Component {component} COMPLETE (hypothesis mode) — "
                    f"{len(findings)} findings ({comp_elapsed:.1f}min)")
        return summary

    # ─── Step 10.1: Deduplicate findings by root cause ─────────────────
    finding_groups = _dedup_findings_pure(findings)
    logger.info(f"  Step 10.1: Dedup — {len(findings)} findings → {len(finding_groups)} unique groups")
    for i, g in enumerate(finding_groups):
        leader = g[0]
        logger.info(f"    Group {i}: {leader['id']} (conv={len(g)}, conf={leader.get('confidence',0)}%) "
                    f"+ {len(g)-1} dupes — {leader['title'][:60]}")
    poc_findings: list = []        # populated in Step 10.3/10.5 — initialized here for funnel
    escaped_siblings: list = []    # Capa 3: siblings that are different bugs (Step 10.6)
    fallback_findings: list = []   # Capa 2: fallbacks when group leader fails PoC (Step 10.5b)

    # ─── Step 10.2: Verification — lightweight code-read before Foundry PoC ─────
    # For every distinct (function, line) location, run a quick Claude call:
    # "Read this specific code + hypothesis — is the bug real?"
    # This replicates the manual auditor step: suspect bug → re-read focused code
    # → confirm before investing 15 min in a Foundry PoC.
    # POC_CONFIDENCE_THRESHOLD is a module-level constant (65) shared with cross-component.

    def _verify_finding(finding: dict) -> tuple[bool, str, str]:
        """Quick code-read verification: re-read the specific function and confirm
        the bug is real before investing 15 minutes in a Foundry PoC.
        Returns (is_real, reason, poc_hint)."""
        fid = finding["id"]
        relevant_code = _extract_relevant_code(source_code, library_code, finding)

        verify_prompt = build_verify_prompt(finding=finding, relevant_code=relevant_code)

        rc, output = _llm(
            verify_prompt,
            allowed_tools=[],  # pure reasoning — no tool calls, stays fast (~30-90s)
            timeout=300,
            log_file=clog / f"{fid}_verify.log",
            cwd=repo
        )

        output_lower = output.lower()
        # On timeout or empty output: conservative fallback → treat as REAL
        # (better to attempt a PoC on a false positive than to drop a real bug)
        if not output_lower.strip() or rc != 0:
            logger.info(f"    [TIMEOUT/ERROR → REAL fallback] {fid}")
            return True, "timeout — included conservatively", ""
        is_real = "verdict: real" in output_lower and "verdict: false_positive" not in output_lower

        reason, poc_hint = "", ""
        for line in output.splitlines():
            if line.upper().startswith("REASON:"):
                reason = line[7:].strip()
            elif line.upper().startswith("POC_HINT:"):
                poc_hint = line[9:].strip()

        status = "REAL ✓" if is_real else "FALSE_POSITIVE ✗"
        logger.info(f"    [{status}] {fid}: {reason[:80]}")
        return is_real, reason, poc_hint

    verify_candidates = _collect_verify_candidates_pure(finding_groups, POC_CONFIDENCE_THRESHOLD)
    logger.info(f"  Step 10.2: Verifying {len(verify_candidates)} distinct hypotheses "
                f"({min(10, len(verify_candidates))} parallel)")

    verified_findings: list[dict] = []
    if verify_candidates:
        with ThreadPoolExecutor(max_workers=min(10, len(verify_candidates))) as executor:
            futures = {executor.submit(_verify_finding, f): f for f in verify_candidates}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    is_real, reason, poc_hint = future.result()
                    f["_verified"] = is_real
                    f["_verify_reason"] = reason
                    if poc_hint and poc_hint.lower() != "n/a":
                        f["_poc_hint"] = poc_hint
                    if is_real or f.get("fuzz_confirmed"):
                        verified_findings.append(f)
                except Exception as e:
                    logger.error(f"    Verification error for {f['id']}: {e}")
                    f["_verified"] = True  # conservative: include on error
                    verified_findings.append(f)
        verified_findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        logger.info(f"  Verification complete: {len(verified_findings)}/{len(verify_candidates)} confirmed real bugs")

    # ─── Step 10.5: Fork PoC per confirmed finding (Phase 3) ─────────
    if finding_groups:
        logger.info("  Step 10.5: Generating Fork PoCs for confirmed findings")
        poc_dir = Path(repo) / "test" / "poc"
        poc_dir.mkdir(parents=True, exist_ok=True)

        def _run_poc(finding):
            """Delegate to top-level generate_and_test_poc with component context."""
            generate_and_test_poc(
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
            prompt = build_is_same_bug_prompt(leader=leader, sibling=sibling)
            fid_s = sibling["id"]
            _, out = _llm(
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

    # Flatten groups back to findings list for downstream
    findings = [f for group in finding_groups for f in group]
    summary["findings"] = findings

    # ─── Step 11: Finding Pipeline (parallel — 4 findings at a time) ────
    # Only findings with PoC OR fuzz-confirmed go through the full pipeline
    pipeline_findings = [f for f in findings if f.get("has_poc") or f.get("fuzz_confirmed")]
    skipped = len(findings) - len(pipeline_findings)
    if skipped:
        logger.info(f"  Skipping {skipped} unverified findings (no PoC, no fuzz confirmation)")

    # In 'poc' mode: stop here — we have PoC-confirmed findings but don't need RedTeam.
    # In 'redteam' mode (default): run the full finding pipeline.
    if benchmark_mode_flag == "poc":
        _log_funnel(component, findings, verified_findings,
                    poc_findings + escaped_siblings + fallback_findings,
                    pipeline_findings, [])
        comp_elapsed = (time.time() - comp_start) / 60
        logger.info(f"  🏁 Component {component} COMPLETE (poc mode) — "
                    f"{len(pipeline_findings)} PoC-confirmed ({comp_elapsed:.1f}min)")
        return summary

    report_findings = []
    if pipeline_findings:
        logger.info(f"  Processing {len(pipeline_findings)} verified findings (3 parallel)")
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    run_finding_pipeline, f, component, protocol, source_code, repo, clog,
                    benchmark_mode=True  # always True in benchmark: skip Variant+Report, stop at RedTeam
                ): f["id"]
                for f in pipeline_findings
            }
            for future in as_completed(futures):
                fid = futures[future]
                try:
                    future.result()
                    logger.info(f"    {fid}: pipeline complete")
                except Exception as e:
                    logger.error(f"    {fid}: pipeline error: {e}")

        report_findings = [f for f in pipeline_findings
                           if f.get("redteam_verdict") in ("REPORT", "REPORT_DOWNGRADED")]

    # ─── Funnel Dashboard ────────────────────────────────────────────────
    # Total PoC attempts = initial dedup batch + escaped siblings (Capa 3) + fallback (Capa 2)
    _log_funnel(component, findings, verified_findings,
                poc_findings + escaped_siblings + fallback_findings,
                pipeline_findings, report_findings)

    # ─── Done ────────────────────────────────────────────────────────────
    comp_elapsed = (time.time() - comp_start) / 60
    logger.info(f"  🏁 Component {component} COMPLETE — {len(findings)} findings ({comp_elapsed:.1f}min)")
    return summary


# ─── Finding Extraction ──────────────────────────────────────────────────────

def parse_fuzz_failures(phase1_log: Path, phase2_log: Path = None) -> dict[str, str]:
    """Parse Foundry/Medusa output to find which invariant functions failed.

    Returns dict mapping failed function names to their counterexample traces.
    e.g. {'invariant_xxx': 'Call sequence: sender=0xBEEF, vault.deposit(1000)...'}
    """
    failed = {}
    import re

    for log_path in [phase1_log, phase2_log]:
        if not log_path or not log_path.exists():
            continue
        content = log_path.read_text(encoding="utf-8", errors="replace")

        # Only parse the STDOUT section — avoid matching text from the prompt
        if "=== STDOUT ===" in content:
            content = content.split("=== STDOUT ===")[1]
            if "=== STDERR ===" in content:
                content = content.split("=== STDERR ===")[0]

        # Foundry format: [FAIL. Reason: ...] invariant_xxx() or property_xxx() (runs: ...)
        for m in re.finditer(r'\[FAIL[^\]]*\]\s+(invariant_\w+|check_\w+|property_\w+)\(\)', content):
            name = m.group(1)
            # Extract counterexample trace — everything from this FAIL line to next test or end
            fail_pos = m.start()
            # Look for the trace section after this failure
            trace_end = content.find("[PASS]", fail_pos + 1)
            trace_end2 = content.find("[FAIL", fail_pos + 1)
            if trace_end == -1:
                trace_end = len(content)
            if trace_end2 != -1 and trace_end2 < trace_end:
                trace_end = trace_end2
            trace = content[fail_pos:trace_end].strip()[:3000]
            failed[name] = trace

        # Medusa format: "assertion failed" or "property violated" with function name
        for m in re.finditer(r'(?:assertion failed|property violated).*?(invariant_\w+|check_\w+|property_\w+)', content):
            name = m.group(1)
            fail_pos = m.start()
            # Capture surrounding context as trace
            trace_start = max(0, fail_pos - 500)
            trace_end = min(len(content), fail_pos + 2000)
            trace = content[trace_start:trace_end].strip()[:3000]
            if name not in failed:
                failed[name] = trace

        # Also catch: "Failing tests:" section
        for m in re.finditer(r'FAIL.*?\]\s+(\w+)\(\)', content):
            name = m.group(1)
            if name.startswith(("invariant_", "check_", "echidna_", "property_")) and name not in failed:
                fail_pos = m.start()
                trace_end = content.find("\n\n", fail_pos + 1)
                if trace_end == -1:
                    trace_end = min(len(content), fail_pos + 2000)
                failed[name] = content[fail_pos:trace_end].strip()[:3000]

    return failed


_extract_relevant_code = _extract_relevant_code_shared


# ─── Finding pipeline (extracted to benchmark/finding_pipeline in Phase 6) ───
from benchmark.finding_pipeline import (  # noqa: F401
    extract_findings, run_finding_pipeline,
)


# ─── Cross-component (extracted to benchmark/cross_component in Phase 6) ───
from benchmark.cross_component import run_cross_component  # noqa: F401



# ─── Worktree helpers (extracted to benchmark/worktree_helpers in Phase 6) ───
from benchmark.worktree_helpers import (  # noqa: F401
    _create_worktree, _remove_worktree, _validate_hunters_subset,
    _apply_force_regen_map, _maybe_run_apply_feedback, _resolve_components,
)

# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Pipeline orchestrator for hunt benchmarks")
    parser.add_argument("--repo", required=True, help="Path to the repo root")
    parser.add_argument("--components", help="Comma-separated component names (mutually exclusive with --auto-components)")
    parser.add_argument("--protocol", default="", help="Protocol name for namespacing (required unless --complete is set)")
    parser.add_argument("--ground-truth", help="Path to benchmark YAML (for scoring at end)")
    parser.add_argument("--max-retries", type=int, default=5, help="Max fix-and-retry attempts")
    parser.add_argument("--skip-phase3", action="store_true", help="Skip fork PoC (explicit)")
    parser.add_argument("--fast", action="store_true",
                        help="Fast mode: reduced fuzz runs (3K vs 5K), skip Medusa, compile retry=1. "
                             "Does NOT skip finding pipeline (verify/PoC/RedTeam) — that's controlled by --benchmark-mode.")
    parser.add_argument("--benchmark-mode",
                        choices=["hypothesis", "poc", "redteam"],
                        default="redteam",
                        help=(
                            "Benchmark depth. "
                            "'hypothesis': hunters+deepdive+scoring only (~45min/component). "
                            "'poc': +verification+PoC phase (~3h/component). "
                            "'redteam': +EscalationHunter+RedTeam (default, full pipeline)."
                        ))
    parser.add_argument("--workers", type=int, default=9, help="Max parallel hunters (default 9 = all hunters truly parallel, pure API calls)")
    parser.add_argument("--parallel-components", type=int, default=2,
                        help="Number of components to run in parallel (requires git worktrees, default 2 proven stable on 16GB)")
    parser.add_argument("--parallel-fuzz", type=int, default=3,
                        help="Number of parallel fuzz batches per component (forge-bound, default 3 for 16GB RAM)")
    parser.add_argument("--parallel-poc", type=int, default=3,
                        help="Number of parallel PoC generators per component (forge-bound, default 3 for 16GB RAM)")
    parser.add_argument("--pre-production", action="store_true",
                        help=(
                            "Protocol is pre-production (not deployed on-chain). "
                            "PoC generation deploys contracts in setUp() instead of using fork state. "
                            "Auto-detected if ground-truth YAML has no on-chain addresses."
                        ))
    parser.add_argument("--session-dir", help=(
        "Override hunt_session output directory. "
        "Default in benchmark mode: benchmarks/<protocol>/bench_session/ "
        "(isolated from the real hunt_session to avoid contamination)."
    ))
    parser.add_argument("--mode", choices=["api", "sub"], default="api",
                        help="Execution mode: 'api' (API key, stream-json, stall detection) or 'sub' (subscription, agentic tools, sonnet)")
    parser.add_argument("--parallel-hunters", type=int, default=6,
                        help="Max parallel hunter calls in sub mode (default 6, subscription rate limits)")
    parser.add_argument("--lang", default="",
                        help="Contract language: solidity, rust (auto-detected from repo if empty)")
    parser.add_argument("--chain", default="mainnet",
                        help="Target chain for fork PoCs (mainnet, base, optimism, arbitrum, polygon)")
    parser.add_argument("--fork-block", type=int, default=0,
                        help="Fork block for PoCs. 0 = latest (portable), N = pinned (deterministic)")
    parser.add_argument("--poc-timeout", type=int, default=0,
                        help="PoC generation timeout in seconds. Default: 900 (api) / 1500 (sub)")
    parser.add_argument("--poc-confidence", type=int, default=65,
                        help="Minimum confidence %% to attempt PoC generation (default 65)")
    parser.add_argument("--no-few-shot", action="store_true",
                        help="Disable few-shot example injection into hunter prompts (prevents benchmark contamination)")
    parser.add_argument("--skip-hunters", action="store_true",
                        help="Skip prepass+hunters+deepdive if hypothesis files already exist. Resume from merge step.")
    parser.add_argument("--hunters", default="",
                        help="Comma-separated subset of hunter names to run "
                             "(e.g., 'MathHunter,AccessHunter'). Default: all. "
                             "Unknown names exit non-zero with the valid list.")
    parser.add_argument("--domain", default="",
                        help="Override auto-detected domain for hunter briefings. "
                             "Valid values: any key of context_enrichment.DOMAIN_BRIEFING "
                             "(e.g., lending, vault, oracle, staking). Empty = auto-detect.")
    parser.add_argument("--force-regen-map", action="store_true",
                        help="Delete cached component_map_<protocol>.json before planning. "
                             "Forces re-detection of components from the repo.")
    parser.add_argument("--force-gate", default="",
                        help="Force a specific pipeline gate to re-run (e.g., 'scope', 'prepass', "
                             "'hunters'). Bypasses the gate's cached status. See pipeline_gate.py "
                             "for valid gate names.")
    parser.add_argument("--apply-feedback", action="store_true",
                        help="After all components finish, invoke apply_feedback.py once "
                             "to ingest pending_briefing_updates into knowledge/ and the "
                             "Obsidian vault. Off by default — benchmarks must not "
                             "pollute the corpus.")
    parser.add_argument("--auto-components", action="store_true",
                        help="Auto-discover components via component_discovery.generate_component_map "
                             "(scans repo, filters interfaces/mocks/tests, orders by LOC). "
                             "Mutually exclusive with --components — exactly one must be set.")
    parser.add_argument(
        "--complete",
        type=str,
        metavar="COMPONENT",
        default="",
        help="Single-shot: close the given component (gate check + state transition + apply_feedback + cross-component). Mutually exclusive with --components / --auto-components.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass pipeline_gate failures when --complete is set. Ignored otherwise.",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="",
        help="Override state file path for --complete (default: ~/.claude/MEMORY/STATE/current_hunt.json).",
    )

    args = parser.parse_args()
    if args.complete:
        if args.components or args.auto_components:
            parser.error(
                "--complete is mutually exclusive with --components / --auto-components"
            )
    else:
        if not args.protocol:
            parser.error("--protocol is required (unless --complete is set)")
        if bool(args.components) == bool(args.auto_components):
            parser.error(
                "Exactly one of --components or --auto-components must be set "
                "(got both or neither)."
            )
    hunters_subset = _validate_hunters_subset(args.hunters)

    # ── --complete routing ─────────────────────────────────────────────────
    if args.complete:
        from component_closer import close_component
        stripped = args.state_file.strip()
        state_file = Path(stripped) if stripped else None
        report = close_component(
            component=args.complete,
            state_file=state_file,
            force=args.force,
        )
        print(f"[complete] {report['component']}: gated={report['gated']} forced={report['forced']} "
              f"state_updated={report['state_updated']} feedback_rc={report['feedback_rc']} "
              f"next={report['next_component']}")
        for err in report["errors"]:
            print(f"  ! {err}")
        if not report["state_updated"]:
            return 1
        return 0

    # ── Isolate benchmark outputs ──────────────────────────────────────────
    # When running a benchmark, NEVER write to the real hunt_session/.
    # Auto-derive an isolated session dir alongside the ground-truth YAML,
    # or use the explicit --session-dir override.
    global HUNT_SESSION_DIR, IS_PRE_PRODUCTION
    if args.session_dir:
        HUNT_SESSION_DIR = Path(args.session_dir).resolve()
    elif args.ground_truth:
        HUNT_SESSION_DIR = Path(args.ground_truth).resolve().parent / "bench_session"
    # else: keep default WEB3_DIR / "hunt_session" (non-benchmark invocation)
    HUNT_SESSION_DIR.mkdir(parents=True, exist_ok=True)

    if args.force_regen_map:
        _apply_force_regen_map(session_dir=HUNT_SESSION_DIR, protocol=args.protocol)
    if args.force_gate:
        force_cmd = [
            sys.executable, str(Path(__file__).resolve().parent / "pipeline_gate.py"),
            "-c", "__all__",
            "--force", args.force_gate,
            "--session-dir", str(HUNT_SESSION_DIR),
        ]
        subprocess.run(force_cmd, check=False)

    # Auto-detect pre-production: flag set OR ground-truth has no on-chain addresses
    IS_PRE_PRODUCTION = getattr(args, "pre_production", False)
    if not IS_PRE_PRODUCTION and args.ground_truth:
        try:
            import yaml as _yaml
            gt = _yaml.safe_load(Path(args.ground_truth).read_text())
            scope = gt.get("scope", [])
            # Pre-production if scope has only .sol paths (no 0x addresses)
            has_address = any(
                str(s).strip().startswith("0x") or str(s).strip().startswith("0X")
                for s in scope if isinstance(s, str)
            )
            if not has_address:
                IS_PRE_PRODUCTION = True
        except Exception:
            pass
    if IS_PRE_PRODUCTION:
        logger.info("  ⚠️  PRE-PRODUCTION mode: PoC will deploy contracts, not use fork state")

    setup_logging(args.protocol)

    # ── Sub mode globals ──────────────────────────────────────────────────
    global USE_SUB_MODE, SUB_MODEL, PARALLEL_HUNTERS
    if args.mode == "sub":
        USE_SUB_MODE = True
        SUB_MODEL = "sonnet"
        PARALLEL_HUNTERS = args.parallel_hunters
        # Mirror into llm_runners so _llm() / run_claude() read the updated values
        _llm_runners_mod.USE_SUB_MODE = True
        _llm_runners_mod.SUB_MODEL = "sonnet"
        logger.info(f"  SUB MODE: subscription, model={SUB_MODEL}, "
                    f"parallel-hunters={PARALLEL_HUNTERS}")

    global POC_GEN_TIMEOUT
    if args.poc_timeout > 0:
        POC_GEN_TIMEOUT = args.poc_timeout
    elif args.mode == "sub":
        POC_GEN_TIMEOUT = 1500  # agents need more time for tool calls
    else:
        POC_GEN_TIMEOUT = 900
    logger.info(f"  PoC generation timeout: {POC_GEN_TIMEOUT}s")

    global POC_CONFIDENCE_THRESHOLD
    POC_CONFIDENCE_THRESHOLD = args.poc_confidence
    logger.info(f"  PoC confidence threshold: {POC_CONFIDENCE_THRESHOLD}%")

    global DISABLE_FEW_SHOT
    DISABLE_FEW_SHOT = args.no_few_shot
    if DISABLE_FEW_SHOT:
        logger.info("  Few-shot examples DISABLED (--no-few-shot)")

    components = _resolve_components(args)
    if not components:
        parser.error("No components resolved from --components / --auto-components.")
    repo = str(Path(args.repo).resolve())

    logger.info(f"Pipeline Orchestrator starting")
    logger.info(f"  Protocol: {args.protocol}")
    logger.info(f"  Components: {components}")
    logger.info(f"  Repo: {repo}")
    logger.info(f"  Session dir: {HUNT_SESSION_DIR}")
    logger.info(f"  Ground truth: {args.ground_truth or 'none'}")
    logger.info(f"  Parallel components: {args.parallel_components}")

    start_time = time.time()
    # Unique run ID (short timestamp) so concurrent benchmark runs never share worktree names
    run_id = datetime.now().strftime("%H%M%S")
    results = []
    components_done = []
    accumulated_context = ""

    def _write_incremental_findings(extra_findings: list = None) -> None:
        """Write findings_all.json checkpoint after each component completes (P0.3)."""
        flat = []
        for r in results:
            for f in r.get("findings", []):
                flat.append({
                    "component": r["component"],
                    "id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", 0),
                    "fuzz_confirmed": f.get("fuzz_confirmed", False),
                    "poc_passed": f.get("has_poc", False),
                    "poc_path": f.get("poc_path", ""),
                    "hunter": f.get("hunter", ""),
                    "redteam_verdict": f.get("redteam_verdict", ""),
                    "redteam_kill_reason": f.get("redteam_kill_reason", ""),
                    "fix_scope": f.get("fix_scope", "n_a"),
                })
        for f in (extra_findings or []):
            flat.append({
                "component": "CrossComponent",
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", 0),
                "fuzz_confirmed": f.get("fuzz_confirmed", False),
                "poc_passed": f.get("has_poc", False),
                "poc_path": f.get("poc_path", ""),
                "hunter": "CrossComponentHunter",
                "redteam_verdict": f.get("redteam_verdict", ""),
                "redteam_kill_reason": f.get("redteam_kill_reason", ""),
                "fix_scope": f.get("fix_scope", "n_a"),
            })
        findings_json = HUNT_SESSION_DIR / "findings_all.json"
        findings_json.write_text(json.dumps({
            "protocol": args.protocol,
            "components_done": components_done[:],
            "total_findings": len(flat),
            "generated_at": datetime.now().isoformat(),
            "complete": False,
            "findings": flat,
        }, indent=2, ensure_ascii=False))
        logger.info(f"  [checkpoint] findings_all.json updated: {len(flat)} findings")

    if args.parallel_components > 1:
        # ─── Parallel mode: worktrees ────────────────────────────────────
        logger.info(f"  🔀 PARALLEL MODE: {args.parallel_components} components at a time via worktrees")
        logger.info(f"  Run ID: {run_id} (worktree suffix to avoid cross-run conflicts)")

        # Process in batches of parallel_components
        for batch_start in range(0, len(components), args.parallel_components):
            batch = components[batch_start:batch_start + args.parallel_components]
            logger.info(f"\n  ── Batch {batch_start // args.parallel_components + 1}: "
                        f"{', '.join(batch)} ──")

            # Create worktrees
            worktrees = {}
            for comp in batch:
                wt = _create_worktree(repo, comp, args.protocol, run_id=run_id)
                if wt:
                    worktrees[comp] = wt
                else:
                    logger.error(f"  Skipping {comp} — worktree creation failed")

            # Run components in parallel
            batch_results = {}
            with ThreadPoolExecutor(max_workers=args.parallel_components) as executor:
                futures = {
                    executor.submit(
                        run_component_pipeline, comp, worktrees[comp],
                        args.protocol, args, accumulated_context=accumulated_context,
                        hunters_subset=hunters_subset
                    ): comp
                    for comp in worktrees
                }
                for future in as_completed(futures):
                    comp = futures[future]
                    try:
                        result = future.result()
                        batch_results[comp] = result
                        results.append(result)
                    except Exception as e:
                        logger.error(f"  {comp}: pipeline error: {e}")
                        results.append({"component": comp, "status": "ERROR",
                                       "gates": {}, "findings": []})

            # Cleanup worktrees
            for comp, wt in worktrees.items():
                _remove_worktree(repo, wt)

            # Build accumulated context from this batch (for next batch)
            for comp in batch:
                result = batch_results.get(comp)
                if result and result.get("status") == "OK":
                    components_done.append(comp)
                    n_findings = len(result.get("findings", []))
                    confirmed = sum(1 for f in result.get("findings", [])
                                   if f.get("fuzz_confirmed"))
                    finding_summary = ""
                    for f in result.get("findings", [])[:10]:
                        finding_summary += (
                            f"\n  - {f.get('id','?')}: {f.get('title','')}"
                            f" (conf={f.get('confidence',0)}%,"
                            f" fuzz={f.get('fuzz_confirmed',False)})"
                        )
                    accumulated_context += (
                        f"\n## {comp} (completed)\n"
                        f"- {n_findings} findings ({confirmed} fuzz-confirmed)\n"
                        f"- Key findings:{finding_summary}\n"
                        f"- Key patterns found: check trust boundaries with this component\n"
                    )

            # Write incremental checkpoint after each batch
            _write_incremental_findings()

            # Cross-component runs once after ALL batches — see below

    else:
        # ─── Sequential mode (original) ─────────────────────────────────
        for i, component in enumerate(components):
            result = run_component_pipeline(component, repo, args.protocol, args,
                                            accumulated_context=accumulated_context,
                                            hunters_subset=hunters_subset)
            results.append(result)
            if result.get("status") == "OK":
                components_done.append(component)
                n_findings = len(result.get("findings", []))
                confirmed = sum(1 for f in result.get("findings", []) if f.get("fuzz_confirmed"))
                finding_summary = ""
                for f in result.get("findings", [])[:10]:
                    finding_summary += f"\n  - {f.get('id','?')}: {f.get('title','')} (conf={f.get('confidence',0)}%, fuzz={f.get('fuzz_confirmed',False)})"
                accumulated_context += (
                    f"\n## {component} (completed)\n"
                    f"- {n_findings} findings ({confirmed} fuzz-confirmed)\n"
                    f"- Key findings:{finding_summary}\n"
                    f"- Key patterns found: check trust boundaries with this component\n"
                )
            else:
                logger.warning(f"  {component} not added to cross-component (status: {result.get('status')})")
            # Write checkpoint after every component regardless of status
            # (so findings from a failed component are not lost if run is interrupted)
            _write_incremental_findings()

    # ─── Cross-component: single run after ALL components complete ────────
    # Runs once with the full components_done list to avoid redundant pair analysis.
    cross_findings: list[dict] = []
    if len(components_done) >= 2:
        cross_findings = run_cross_component(components_done, args.protocol, repo,
                                             parallel_poc=args.parallel_poc) or []

    # ─── Scoring ─────────────────────────────────────────────────────────
    if args.ground_truth:
        logger.info(f"\n{'='*60}")
        logger.info(f"  FINAL SCORING")
        logger.info(f"{'='*60}")

        # Filter scoring to only the components we actually ran
        score_cmd = [
            sys.executable, str(SCRIPT_DIR / "benchmark_score.py"),
            "--ground-truth", args.ground_truth,
            "--hypotheses-dir", str(HUNT_SESSION_DIR / "hypotheses" / args.protocol)
        ]
        if components:
            score_cmd += ["--components", ",".join(components)]
        code, stdout, _ = run_cmd(score_cmd, log_file=LOG_DIR / "scoring.log")

        logger.info(stdout)

    # ─── Summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    total_findings = sum(len(r.get("findings", [])) for r in results)

    logger.info(f"\n{'═'*60}")
    logger.info(f"  BENCHMARK COMPLETE: {args.protocol}")
    logger.info(f"{'═'*60}")
    logger.info(f"  Duration:       {elapsed/60:.1f} min")
    logger.info(f"  Components:     {len(components_done)}/{len(components)}")
    logger.info(f"  Total findings: {total_findings}")
    for r in results:
        gates_ok = sum(1 for v in r.get("gates", {}).values() if v)
        gates_total = len(r.get("gates", {}))
        n_findings = len(r.get("findings", []))
        status = r.get("status", "?")
        logger.info(f"    {r['component']:15s}  {gates_ok}/{gates_total} gates  {n_findings} findings  [{status}]")
    logger.info(f"{'═'*60}")
    logger.info(f"  Logs: {LOG_DIR}")

    # ─── Persist consolidated findings to JSON ────────────────────────────
    # Allows querying all findings from all components after the run completes.
    findings_json = HUNT_SESSION_DIR / "findings_all.json"
    all_findings_flat = []
    for r in results:
        for f in r.get("findings", []):
            all_findings_flat.append({
                "component": r["component"],
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", 0),
                "fuzz_confirmed": f.get("fuzz_confirmed", False),
                "poc_passed": f.get("has_poc", False),
                "poc_path": f.get("poc_path", ""),
                "hunter": f.get("hunter", ""),
                "redteam_verdict": f.get("redteam_verdict", ""),
                "redteam_kill_reason": f.get("redteam_kill_reason", ""),
                "fix_scope": f.get("fix_scope", "n_a"),
            })
    # Include cross-component findings that were PoC'd and RedTeam'd
    for f in cross_findings:
        all_findings_flat.append({
            "component": "CrossComponent",
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", 0),
            "fuzz_confirmed": f.get("fuzz_confirmed", False),
            "poc_passed": f.get("has_poc", False),
            "poc_path": f.get("poc_path", ""),
            "hunter": "CrossComponentHunter",
            "redteam_verdict": f.get("redteam_verdict", ""),
            "redteam_kill_reason": f.get("redteam_kill_reason", ""),
            "fix_scope": f.get("fix_scope", "n_a"),
        })
    findings_json_data = {
        "protocol": args.protocol,
        "components": components_done,
        "total_findings": len(all_findings_flat),
        "generated_at": datetime.now().isoformat(),
        "complete": True,
        "findings": all_findings_flat,
    }
    findings_json.write_text(json.dumps(findings_json_data, indent=2, ensure_ascii=False))
    logger.info(f"  Findings JSON: {findings_json}")

    # ─── P1.3: Hunter performance tracking ───────────────────────────────
    # Scan all hyp_*.yaml files and compute per-hunter stats:
    # total hypotheses, validated count, avg confidence, finding conversion rate
    import yaml as _perf_yaml  # ensure yaml is available in main() scope
    hunter_stats: dict = {}
    hyp_dir_final = HUNT_SESSION_DIR / "hypotheses" / args.protocol
    if hyp_dir_final.exists():
        for hyp_file in sorted(hyp_dir_final.glob("hyp_*.yaml")):
            # Extract hunter name from filename: hyp_<Component>_<HunterName>.yaml
            parts = hyp_file.stem.split("_", 2)  # ['hyp', 'Component', 'HunterName']
            hunter_name = parts[2] if len(parts) >= 3 else hyp_file.stem
            try:
                data = _perf_yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hyps = []
                for key in ("hypotheses", "findings", "invariants"):
                    hyps.extend(h for h in (data.get(key) or []) if isinstance(h, dict))
                if not hyps:
                    continue
                confidences = [h.get("confidence", 0) for h in hyps]
                validated = sum(1 for h in hyps if h.get("validated"))
                hs = hunter_stats.setdefault(hunter_name, {
                    "total_hypotheses": 0, "validated": 0, "confidence_sum": 0,
                    "files": 0, "high_confidence": 0,
                })
                hs["total_hypotheses"] += len(hyps)
                hs["validated"] += validated
                hs["confidence_sum"] += sum(confidences)
                hs["files"] += 1
                hs["high_confidence"] += sum(1 for c in confidences if c >= 70)
            except Exception:
                pass

    # Compute derived metrics and write JSON
    hunter_perf = []
    for hunter_name, hs in sorted(hunter_stats.items()):
        total = hs["total_hypotheses"]
        # Count how many findings in all_findings_flat came from this hunter
        # Exact match: "MathHunter" == f["hunter"] — avoid substring false positives
        # e.g. "Hunter" substring would match every hunter name
        findings_generated = sum(
            1 for f in all_findings_flat if f.get("hunter", "") == hunter_name
        )
        hunter_perf.append({
            "hunter": hunter_name,
            "total_hypotheses": total,
            "validated_hypotheses": hs["validated"],
            "high_confidence_hypotheses": hs["high_confidence"],
            "avg_confidence": round(hs["confidence_sum"] / total, 1) if total else 0,
            "findings_generated": findings_generated,
            "components_covered": hs["files"],
        })
    # Sort by findings_generated desc, then avg_confidence desc
    hunter_perf.sort(key=lambda x: (-x["findings_generated"], -x["avg_confidence"]))

    perf_json = HUNT_SESSION_DIR / "hunter_performance.json"
    perf_json.write_text(json.dumps({
        "protocol": args.protocol,
        "generated_at": datetime.now().isoformat(),
        "hunters": hunter_perf,
    }, indent=2, ensure_ascii=False))
    logger.info(f"  Hunter perf:   {perf_json}")
    if hunter_perf:
        logger.info(f"  Top hunters by findings:")
        for hp in hunter_perf[:5]:
            logger.info(f"    {hp['hunter']:25s} {hp['findings_generated']} findings, "
                        f"{hp['total_hypotheses']} hyps, avg_conf={hp['avg_confidence']}")

    logger.info(f"  Reports:       {HUNT_SESSION_DIR / 'reports'}/")
    logger.info(f"  Hypotheses:    {HUNT_SESSION_DIR / 'hypotheses' / args.protocol}/")
    logger.info(f"")
    logger.info(f"  To re-score hypotheses vs ground truth:")
    if args.ground_truth:
        logger.info(f"    python3 audit-agents/benchmark_score.py \\")
        logger.info(f"      --ground-truth {args.ground_truth} \\")
        logger.info(f"      --hypotheses-dir {HUNT_SESSION_DIR / 'hypotheses' / args.protocol}")

    _maybe_run_apply_feedback(apply_feedback=args.apply_feedback)


if __name__ == "__main__":
    main()
