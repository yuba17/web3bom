"""fuzz.py — Phase 1 (Foundry) + Phase 2 (Medusa) + Tolerance Tuning."""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.component_pipeline.reporting import parse_fuzz_failures

# Sentinel returned when Phase 1 infra fails and we must abort the pipeline
BLOCKED_PHASE1_INFRA = "BLOCKED_PHASE1_INFRA"


def run_phase1_foundry(ctx: PipelineContext) -> str | None:
    """Phase 1 Foundry fuzz with --fuzz-runs 5000 (parallel batches).

    Returns BLOCKED_PHASE1_INFRA if Phase 1 fails with an infrastructure error
    (caller must propagate the early return).  Otherwise returns None and writes:
      ctx.phase1_fuzz_failures  — dict of {invariant_name: trace}
    """
    import run_benchmark as _rb

    # Unpack context locals for readability
    summary = ctx.summary
    component = ctx.component
    protocol = ctx.protocol
    clog = ctx.clog
    logger = ctx.logger
    repo = ctx.repo
    args = ctx.args
    src_file = ctx.src_file
    setup_sol_text = ctx.setup_sol_text

    chimera_dir = Path(repo) / "test" / "chimera"

    # forge_env: local dict derived from os.environ — stays inline, not in ctx
    forge_env = os.environ.copy()
    forge_env["FOUNDRY_PROFILE"] = "chimera"
    for _rpc_var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        _rpc_val = os.environ.get(_rpc_var, "")
        if _rpc_val:
            forge_env[_rpc_var] = _rpc_val

    _SKIP_HEAVY_FUZZ = args.fast

    # ─── Step 8: Phase 1 — Foundry fuzz runs (parallel batches) ────────
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
        return BLOCKED_PHASE1_INFRA

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
                f"## Source Code (first 15K — full source at {src_file})\n```solidity\n{ctx.source_code[:15000]}\n```\n\n"
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
                f"## Source Code (first 20K — full source at {src_file})\n```solidity\n{ctx.source_code[:20000]}\n```\n\n"
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

    ctx.phase1_fuzz_failures = all_fuzz_failures
    if ctx.phase1_fuzz_failures:
        logger.info(f"  Total fuzz failures: {list(ctx.phase1_fuzz_failures.keys())}")
    else:
        logger.info("  No fuzz failures in Phase 1")

    return None


def run_phase2_medusa(ctx: PipelineContext) -> None:
    """Phase 2 Medusa fuzz (15 min) + Tolerance Tuning. Skipped in --fast mode."""
    import run_benchmark as _rb

    # Unpack context locals for readability
    summary = ctx.summary
    component = ctx.component
    protocol = ctx.protocol
    clog = ctx.clog
    logger = ctx.logger
    repo = ctx.repo
    args = ctx.args

    chimera_dir = Path(repo) / "test" / "chimera"

    _SKIP_HEAVY_FUZZ = args.fast

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

    # Update ctx.phase2_log to point at actual log (may or may not exist)
    ctx.phase2_log = clog / "phase2_medusa.log"
