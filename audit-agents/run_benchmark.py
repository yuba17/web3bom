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




# ─── Component pipeline (extracted to benchmark/component_pipeline in Phase 6) ───
from benchmark.component_pipeline import (  # noqa: F401
    run_component_pipeline,
    parse_fuzz_failures,
)


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
