"""deepdive.py — DeepDive hunter (sequential, post-12-hunters)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext


def _rescue_deepdive_yaml(ctx: PipelineContext, context_label: str) -> bool:
    """Locate DeepDive YAML written to wrong dir and copy to hyp_dir."""
    import shutil as _sh_rescue
    target = ctx.hyp_dir / f"hyp_{ctx.component}_DeepDiveHunter.yaml"
    if target.exists():
        return True
    _find_out = subprocess.run(
        ["find", str(ctx.repo), "-name", f"hyp_{ctx.component}_DeepDiveHunter.yaml", "-type", "f"],
        capture_output=True, text=True
    )
    for _found in _find_out.stdout.strip().splitlines():
        if _found and Path(_found) != target:
            _sh_rescue.copy2(_found, target)
            ctx.logger.info(f"  {context_label}: rescued {Path(_found).name} → {ctx.hyp_dir.name}/")
            return True
    return False


def run_deepdive(ctx: PipelineContext) -> None:
    """Runs DeepDiveHunter sequentially after 12 parallel hunters."""
    import run_benchmark as _rb
    from benchmark.prompt_builders import build_deepdive_prompt

    component = ctx.component
    protocol = ctx.protocol
    source_code = ctx.source_code
    library_code = ctx.library_code
    setup_sol_text = ctx.setup_sol_text
    protocol_model = ctx.protocol_model
    hyp_dir = ctx.hyp_dir
    clog = ctx.clog
    repo = ctx.repo
    summary = ctx.summary
    logger = ctx.logger

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
    _rescue_deepdive_yaml(ctx, "DeepDive rescue")

    deepdive_ok = _rb.check_gate(component, "deepdive", protocol, repo)
    summary["gates"]["deepdive"] = deepdive_ok
    if not deepdive_ok:
        dd_file = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
        if not dd_file.exists():
            logger.warning("  DeepDive gate failed and no YAML — continuing without DeepDive")
        # Not blocking — DeepDive is additive, hunters provide the base
