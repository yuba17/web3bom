"""extract.py — Step 10: Extract Findings + dedup phase.

Verbatim cut-and-paste of the Step 10 block from runner.py.
Receives PipelineContext; mutates ctx.summary["findings"] and related fields.

Returns:
    None              — normal flow (continues to Step 10.2)
    "EARLY_EXIT_hypothesis" — hypothesis mode early exit (orchestrator must return summary)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.component_pipeline.reporting import parse_fuzz_failures
from finding_pipeline import (
    dedup_findings as _dedup_findings_pure,
)


def extract_findings(ctx: PipelineContext):
    """Extract findings from hypotheses + fuzz results, deduplicate them.

    Mutates ctx.summary["findings"], ctx.finding_groups, ctx.poc_findings,
    ctx.escaped_siblings, ctx.fallback_findings.

    Returns None on normal flow, or "EARLY_EXIT_hypothesis" if hypothesis mode
    triggered an early return.
    """
    import run_benchmark as _rb
    import time

    logger = ctx.logger
    component = ctx.component
    protocol = ctx.protocol
    repo = ctx.repo
    hyp_dir = ctx.hyp_dir
    args = ctx.args
    summary = ctx.summary
    phase1_fuzz_failures = ctx.phase1_fuzz_failures
    phase2_log = ctx.phase2_log
    comp_start = ctx.comp_start

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

    findings = _rb.extract_findings(component, protocol, fuzz_failures, hyp_dir=hyp_dir)
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
        return "EARLY_EXIT_hypothesis"

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

    # Write back to ctx so downstream phases can consume
    ctx.finding_groups = finding_groups
    ctx.poc_findings = poc_findings
    ctx.escaped_siblings = escaped_siblings
    ctx.fallback_findings = fallback_findings

    return None
