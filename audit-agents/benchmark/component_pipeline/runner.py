"""run_component_pipeline — thin orchestrator for the per-component hunt pipeline.

Delegates each phase to a dedicated module in benchmark.component_pipeline.
A single PipelineContext is shared across all phases.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.component_pipeline.context import (clean_slate, run_prepass, check_early_exit,
    load_tests, load_knowledge, load_interfaces, ensure_chimera_setup)
from benchmark.component_pipeline.hunters import run_hunters, BLOCKED_HUNTERS
from benchmark.component_pipeline.deepdive import run_deepdive
from benchmark.component_pipeline.merge import run_merge, SKIP_TO_EXTRACT
from benchmark.component_pipeline.enhance import enhance_target_functions
from benchmark.component_pipeline.fuzz import run_phase1_foundry, run_phase2_medusa, BLOCKED_PHASE1_INFRA
from benchmark.component_pipeline.extract import extract_findings
from benchmark.component_pipeline.verify import verify_findings_lightweight
from benchmark.component_pipeline.poc import generate_fork_pocs
from benchmark.component_pipeline.finding import dispatch_finding_pipeline
from benchmark.component_pipeline.gate_status_writer import flush_gate_status
from benchmark.component_pipeline.narrator import narrate
from benchmark.prompt_builders import read_source

logger = logging.getLogger("orchestrator")


def run_component_pipeline(component: str, repo: str, protocol: str,
                           args: argparse.Namespace,
                           accumulated_context: str = "",
                           hunters_subset: set | None = None) -> dict:
    """Run the full pipeline for one component. Returns summary dict."""
    import run_benchmark as _rb
    import time

    comp_start = time.time()
    logger.info(f"\n{'='*60}")
    logger.info(f"  COMPONENT: {component}")
    logger.info(f"{'='*60}")

    clog = _rb.component_log_dir(component)
    src_dir = Path(repo) / "src"

    src_files = list(src_dir.glob(f"{component}.sol")) or list(src_dir.glob(f"**/{component}.sol"))
    if not src_files:
        logger.error(f"  Source file not found for {component}")
        return {"component": component, "status": "ERROR", "reason": "source not found"}
    src_file = src_files[0]

    library_code = ""
    lib_dir = src_dir / "libraries"
    if lib_dir.exists():
        for lib_file in sorted(lib_dir.glob("*.sol")):
            library_code += f"\n// === {lib_file.name} ===\n{lib_file.read_text(encoding='utf-8')}"

    summary = {"component": component, "gates": {}, "findings": [], "status": "OK"}

    ctx = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir,
        hyp_dir=_rb.HUNT_SESSION_DIR / "hypotheses" / protocol,
        clog=clog, src_file=src_file,
        comp_start=comp_start,
    )
    ctx.summary = summary
    ctx.source_code = read_source(str(src_file))
    ctx.library_code = library_code
    ctx.accumulated_context = accumulated_context

    # Benchmark mode bypasses pipeline_gate.py — flush after each phase for dashboard live view.
    summary["gates"]["scope"] = True; flush_gate_status(ctx)
    narrate(ctx, "🎯", f"Empezando análisis de {component}")
    clean_slate(ctx)
    narrate(ctx, "🔍", "Ejecutando prepass (Slither + Aderyn + exploit patterns)")
    run_prepass(ctx); flush_gate_status(ctx)
    if check_early_exit(ctx) == "EMPTY_PREPASS_SKIP": return summary
    load_tests(ctx); load_knowledge(ctx); load_interfaces(ctx); ensure_chimera_setup(ctx)

    narrate(ctx, "🎯", "Lanzando 12 hunters en paralelo")
    if run_hunters(ctx, hunters_subset=hunters_subset) == BLOCKED_HUNTERS:
        narrate(ctx, "⛔", "Hunters bloqueados"); flush_gate_status(ctx); return summary
    n_hyps = len(list(ctx.hyp_dir.glob(f"hyp_{component}_*.yaml"))) if ctx.hyp_dir.exists() else 0
    narrate(ctx, "✅", f"Hunters completados — {n_hyps} hipótesis generadas")
    if not ctx._skip_to_merge:
        narrate(ctx, "🔬", "DeepDiveHunter analizando convergencias"); run_deepdive(ctx)
    flush_gate_status(ctx)

    if args.fast:
        logger.info("  FAST MODE: Steps 5-8 (compile+Phase1 5K), skip 9-9.5 (Medusa+tuning)")
        summary["gates"]["phase2"] = True

    narrate(ctx, "🧬", "Fusionando invariantes en Properties.sol")
    merge_result = run_merge(ctx); flush_gate_status(ctx)
    if summary.get("status") in ("BLOCKED_CHIMERA", "BLOCKED_MERGE", "BLOCKED_COMPILE"):
        narrate(ctx, "⛔", f"Bloqueado en {summary.get('status')}"); return summary
    if merge_result != SKIP_TO_EXTRACT:
        enhance_target_functions(ctx)
        narrate(ctx, "🔥", "Phase 1: Foundry fuzzing 5K runs")
        if run_phase1_foundry(ctx) == BLOCKED_PHASE1_INFRA:
            narrate(ctx, "⛔", "Phase 1 bloqueada"); flush_gate_status(ctx); return summary
        flush_gate_status(ctx)
        narrate(ctx, "🌊", "Phase 2: Medusa 15 min")
        run_phase2_medusa(ctx); flush_gate_status(ctx)

    if extract_findings(ctx) == "EARLY_EXIT_hypothesis": return summary
    n_found = len(summary.get("findings", []))
    narrate(ctx, "💎" if n_found else "🕳️", f"Findings extraídos: {n_found}")
    verify_findings_lightweight(ctx); generate_fork_pocs(ctx)
    if dispatch_finding_pipeline(ctx) == "EARLY_EXIT_poc_mode": return summary
    return summary
