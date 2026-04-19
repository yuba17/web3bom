"""CLI entry point for benchmark pipeline — extracted from run_benchmark.py.

Final step of Phase 6 refactor. Imports all previously extracted modules
and wires them via argparse + main() orchestrator.

Consumers: run_benchmark.py shim (exposes `main` for backward compat).

Mutable-global pattern (Option A): module-level globals such as
USE_SUB_MODE, POC_GEN_TIMEOUT, HUNT_SESSION_DIR, LOG_DIR continue to live
on the run_benchmark shim so that downstream modules (component_pipeline,
cross_component, poc_pipeline) can keep reading them via
`import run_benchmark as _rb; _rb.<NAME>`. main() mutates them through
the shim using `import run_benchmark as _rb; _rb.<NAME> = ...`.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
import re

from paths import WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR
from finding_pipeline import POC_CONFIDENCE_THRESHOLD  # noqa: F401  (re-exposed via shim)

# ─── Load .env if present (preserved from run_benchmark.py pre-Phase-6) ──────
_env_file = WEB3_DIR / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and val and key not in os.environ:
                os.environ[key] = val

from benchmark.component_pipeline import run_component_pipeline
from benchmark.cross_component import run_cross_component
from benchmark.worktree_helpers import (
    _create_worktree,
    _remove_worktree,
    _validate_hunters_subset,
    _apply_force_regen_map,
    _maybe_run_apply_feedback,
    _resolve_components,
)
import benchmark.llm_runners as _llm_runners_mod

SCRIPT_DIR = AUDIT_AGENTS_DIR

logger = logging.getLogger("orchestrator")


def setup_logging(protocol: str):
    import run_benchmark as _rb  # write-back to shim — downstream modules read via _rb.LOG_DIR
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    # Keep logs inside the session dir so benchmark logs don't pollute WEB3_DIR/logs/
    _rb.LOG_DIR = _rb.HUNT_SESSION_DIR / "logs" / f"{protocol}_{timestamp}"
    _rb.LOG_DIR.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(_rb.LOG_DIR / "orchestrator.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    _rb.logger.addHandler(handler)
    # Flush stdout immediately so tee shows progress in real-time
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    _rb.logger.addHandler(stream_handler)
    _rb.logger.setLevel(logging.INFO)
    _rb.logger.info(f"Logging to {_rb.LOG_DIR}")
    sys.stdout.reconfigure(line_buffering=True)  # force line-buffered stdout


def component_log_dir(component: str) -> Path:
    import run_benchmark as _rb  # read mutable LOG_DIR from shim
    d = _rb.LOG_DIR / component
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


def check_gate(component: str, gate: str, protocol: str, repo: str = "") -> bool:
    """Run pipeline_gate.py and return True if gate passes."""
    import run_benchmark as _rb  # read mutable HUNT_SESSION_DIR from shim
    cmd = [
        sys.executable, str(_rb.SCRIPT_DIR / "pipeline_gate.py"),
        "-c", component, "--gate", gate, "--protocol", protocol,
        "--session-dir", str(_rb.HUNT_SESSION_DIR),
    ]
    if repo:
        cmd += ["--repo", repo]

    code, stdout, stderr = _rb.run_cmd(cmd)
    _rb.logger.info(f"  Gate {gate}: {'PASS' if code == 0 else 'FAIL'}")
    return code == 0


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
    parser.add_argument("--fuzz-refine", action="store_true",
                        help="Enable round 2 of fuzz-refine loop (LLM refines invariants and re-fuzzes). "
                             "Disabled by default — empirically adds 20-25min with low marginal value "
                             "since Medusa (Phase 2) already explores multi-step sequences.")
    parser.add_argument("--skip-empty-prepass", action="store_true",
                        help="If prepass produces 0 findings, skip hunters+merge+fuzz+PoC for this "
                             "component and return early. Use for protocols already audited exhaustively "
                             "(ToB/OZ/Cyfrin) — saves ~40min on components with no detectable signals.")
    parser.add_argument("--enhance-targets", action="store_true",
                        help="Run Step 7.5 (LLM enhances TargetFunctions.sol with multi-step attack "
                             "sequences). Disabled by default — empirically adds 10-15min, often breaks "
                             "compile and reverts. Hunters already produce TargetFunctions handlers via merge.")
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
    import run_benchmark as _rb  # write-back to shim — downstream modules read these via _rb.<NAME>
    if args.session_dir:
        _rb.HUNT_SESSION_DIR = Path(args.session_dir).resolve()
    elif args.ground_truth:
        _rb.HUNT_SESSION_DIR = Path(args.ground_truth).resolve().parent / "bench_session"
    # else: keep default WEB3_DIR / "hunt_session" (non-benchmark invocation)
    _rb.HUNT_SESSION_DIR.mkdir(parents=True, exist_ok=True)

    if args.force_regen_map:
        _apply_force_regen_map(session_dir=_rb.HUNT_SESSION_DIR, protocol=args.protocol)
    if args.force_gate:
        force_cmd = [
            sys.executable, str(_rb.SCRIPT_DIR / "pipeline_gate.py"),
            "-c", "__all__",
            "--force", args.force_gate,
            "--session-dir", str(_rb.HUNT_SESSION_DIR),
        ]
        subprocess.run(force_cmd, check=False)

    # Auto-detect pre-production: flag set OR ground-truth has no on-chain addresses
    _rb.IS_PRE_PRODUCTION = getattr(args, "pre_production", False)
    if not _rb.IS_PRE_PRODUCTION and args.ground_truth:
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
                _rb.IS_PRE_PRODUCTION = True
        except Exception:
            pass
    if _rb.IS_PRE_PRODUCTION:
        _rb.logger.info("  ⚠️  PRE-PRODUCTION mode: PoC will deploy contracts, not use fork state")

    setup_logging(args.protocol)

    # ── Sub mode globals ──────────────────────────────────────────────────
    if args.mode == "sub":
        _rb.USE_SUB_MODE = True
        _rb.SUB_MODEL = "sonnet"
        _rb.PARALLEL_HUNTERS = args.parallel_hunters
        # Mirror into llm_runners so _llm() / run_claude() read the updated values
        _llm_runners_mod.USE_SUB_MODE = True
        _llm_runners_mod.SUB_MODEL = "sonnet"
        _rb.logger.info(f"  SUB MODE: subscription, model={_rb.SUB_MODEL}, "
                        f"parallel-hunters={_rb.PARALLEL_HUNTERS}")

    if args.poc_timeout > 0:
        _rb.POC_GEN_TIMEOUT = args.poc_timeout
    elif args.mode == "sub":
        _rb.POC_GEN_TIMEOUT = 1500  # agents need more time for tool calls
    else:
        _rb.POC_GEN_TIMEOUT = 900
    _rb.logger.info(f"  PoC generation timeout: {_rb.POC_GEN_TIMEOUT}s")

    _rb.POC_CONFIDENCE_THRESHOLD = args.poc_confidence
    _rb.logger.info(f"  PoC confidence threshold: {_rb.POC_CONFIDENCE_THRESHOLD}%")

    _rb.DISABLE_FEW_SHOT = args.no_few_shot
    if _rb.DISABLE_FEW_SHOT:
        _rb.logger.info("  Few-shot examples DISABLED (--no-few-shot)")

    components = _resolve_components(args)
    if not components:
        parser.error("No components resolved from --components / --auto-components.")
    repo = str(Path(args.repo).resolve())

    _rb.logger.info(f"Pipeline Orchestrator starting")
    _rb.logger.info(f"  Protocol: {args.protocol}")
    _rb.logger.info(f"  Components: {components}")
    _rb.logger.info(f"  Repo: {repo}")
    _rb.logger.info(f"  Session dir: {_rb.HUNT_SESSION_DIR}")
    _rb.logger.info(f"  Ground truth: {args.ground_truth or 'none'}")
    _rb.logger.info(f"  Parallel components: {args.parallel_components}")

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
        findings_json = _rb.HUNT_SESSION_DIR / "findings_all.json"
        findings_json.write_text(json.dumps({
            "protocol": args.protocol,
            "components_done": components_done[:],
            "total_findings": len(flat),
            "generated_at": datetime.now().isoformat(),
            "complete": False,
            "findings": flat,
        }, indent=2, ensure_ascii=False))
        _rb.logger.info(f"  [checkpoint] findings_all.json updated: {len(flat)} findings")

    if args.parallel_components > 1:
        # ─── Parallel mode: worktrees ────────────────────────────────────
        _rb.logger.info(f"  🔀 PARALLEL MODE: {args.parallel_components} components at a time via worktrees")
        _rb.logger.info(f"  Run ID: {run_id} (worktree suffix to avoid cross-run conflicts)")

        # Process in batches of parallel_components
        for batch_start in range(0, len(components), args.parallel_components):
            batch = components[batch_start:batch_start + args.parallel_components]
            _rb.logger.info(f"\n  ── Batch {batch_start // args.parallel_components + 1}: "
                            f"{', '.join(batch)} ──")

            # Create worktrees
            worktrees = {}
            for comp in batch:
                wt = _create_worktree(repo, comp, args.protocol, run_id=run_id)
                if wt:
                    worktrees[comp] = wt
                else:
                    _rb.logger.error(f"  Skipping {comp} — worktree creation failed")

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
                        _rb.logger.error(f"  {comp}: pipeline error: {e}")
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
                _rb.logger.warning(f"  {component} not added to cross-component (status: {result.get('status')})")
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
        _rb.logger.info(f"\n{'='*60}")
        _rb.logger.info(f"  FINAL SCORING")
        _rb.logger.info(f"{'='*60}")

        # Filter scoring to only the components we actually ran
        score_cmd = [
            sys.executable, str(_rb.SCRIPT_DIR / "benchmark_score.py"),
            "--ground-truth", args.ground_truth,
            "--hypotheses-dir", str(_rb.HUNT_SESSION_DIR / "hypotheses" / args.protocol)
        ]
        if components:
            score_cmd += ["--components", ",".join(components)]
        code, stdout, _ = _rb.run_cmd(score_cmd, log_file=_rb.LOG_DIR / "scoring.log")

        _rb.logger.info(stdout)

    # ─── Summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    total_findings = sum(len(r.get("findings", [])) for r in results)

    _rb.logger.info(f"\n{'═'*60}")
    _rb.logger.info(f"  BENCHMARK COMPLETE: {args.protocol}")
    _rb.logger.info(f"{'═'*60}")
    _rb.logger.info(f"  Duration:       {elapsed/60:.1f} min")
    _rb.logger.info(f"  Components:     {len(components_done)}/{len(components)}")
    _rb.logger.info(f"  Total findings: {total_findings}")
    for r in results:
        gates_ok = sum(1 for v in r.get("gates", {}).values() if v)
        gates_total = len(r.get("gates", {}))
        n_findings = len(r.get("findings", []))
        status = r.get("status", "?")
        _rb.logger.info(f"    {r['component']:15s}  {gates_ok}/{gates_total} gates  {n_findings} findings  [{status}]")
    _rb.logger.info(f"{'═'*60}")
    _rb.logger.info(f"  Logs: {_rb.LOG_DIR}")

    # ─── Persist consolidated findings to JSON ────────────────────────────
    # Allows querying all findings from all components after the run completes.
    findings_json = _rb.HUNT_SESSION_DIR / "findings_all.json"
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
    _rb.logger.info(f"  Findings JSON: {findings_json}")

    # ─── P1.3: Hunter performance tracking ───────────────────────────────
    # Scan all hyp_*.yaml files and compute per-hunter stats:
    # total hypotheses, validated count, avg confidence, finding conversion rate
    import yaml as _perf_yaml  # ensure yaml is available in main() scope
    hunter_stats: dict = {}
    hyp_dir_final = _rb.HUNT_SESSION_DIR / "hypotheses" / args.protocol
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

    perf_json = _rb.HUNT_SESSION_DIR / "hunter_performance.json"
    perf_json.write_text(json.dumps({
        "protocol": args.protocol,
        "generated_at": datetime.now().isoformat(),
        "hunters": hunter_perf,
    }, indent=2, ensure_ascii=False))
    _rb.logger.info(f"  Hunter perf:   {perf_json}")
    if hunter_perf:
        _rb.logger.info(f"  Top hunters by findings:")
        for hp in hunter_perf[:5]:
            _rb.logger.info(f"    {hp['hunter']:25s} {hp['findings_generated']} findings, "
                            f"{hp['total_hypotheses']} hyps, avg_conf={hp['avg_confidence']}")

    _rb.logger.info(f"  Reports:       {_rb.HUNT_SESSION_DIR / 'reports'}/")
    _rb.logger.info(f"  Hypotheses:    {_rb.HUNT_SESSION_DIR / 'hypotheses' / args.protocol}/")
    _rb.logger.info(f"")
    _rb.logger.info(f"  To re-score hypotheses vs ground truth:")
    if args.ground_truth:
        _rb.logger.info(f"    python3 audit-agents/benchmark_score.py \\")
        _rb.logger.info(f"      --ground-truth {args.ground_truth} \\")
        _rb.logger.info(f"      --hypotheses-dir {_rb.HUNT_SESSION_DIR / 'hypotheses' / args.protocol}")

    _maybe_run_apply_feedback(apply_feedback=args.apply_feedback)


if __name__ == "__main__":
    main()
