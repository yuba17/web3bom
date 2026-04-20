"""enhance.py — Step 7.5 opt-in TargetFunctions enhancer (--enhance-targets).

Verbatim cut-and-paste of the Step 7.5 block from runner.py.
Receives PipelineContext; no output mutations (side-effect: writes TargetFunctions.sol).

Gated by --enhance-targets flag (opt-in).
"""

from __future__ import annotations

from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext


def enhance_target_functions(ctx: PipelineContext) -> None:
    """LLM-enhances test/chimera/TargetFunctions.sol with multi-step attack sequences.

    Gated by --enhance-targets flag. No-op if flag absent or if compile failed
    (_skip_to_merge would have short-circuited before this call in the orchestrator).
    """
    import run_benchmark as _rb

    logger = ctx.logger
    component = ctx.component
    repo = ctx.repo
    hyp_dir = ctx.hyp_dir
    clog = ctx.clog
    setup_sol_text = ctx.setup_sol_text

    # ─── Step 7.5: Enhance TargetFunctions with attack sequences (opt-in) ────
    if not getattr(ctx.args, 'enhance_targets', False):
        logger.info("  Step 7.5 skipped (activate with --enhance-targets)")
        return

    logger.info("  Step 7.5: Enhance TargetFunctions with attack sequences")
    chimera_dir = Path(repo) / "test" / "chimera"
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
