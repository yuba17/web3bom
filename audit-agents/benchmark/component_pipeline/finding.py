"""finding.py — Step 11: Finding Pipeline (parallel — 4 findings at a time).

Verbatim cut-and-paste of the Step 11 + Funnel Dashboard + Done blocks from runner.py.
Receives PipelineContext; returns None on normal flow or "EARLY_EXIT_poc_mode" sentinel.

Orchestrator interprets the sentinel as: populate funnel dashboard + return summary early.
"""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def dispatch_finding_pipeline(ctx: PipelineContext) -> str | None:
    """Dispatches finding pipeline for each verified finding (parallel — 3 concurrent).

    Returns "EARLY_EXIT_poc_mode" if benchmark_mode is 'poc' (orchestrator must return summary).
    Returns None on normal flow (redteam mode).
    """
    import time
    import run_benchmark as _rb
    from concurrent.futures import ThreadPoolExecutor, as_completed

    component = ctx.component
    repo = ctx.repo
    protocol = ctx.protocol
    logger = ctx.logger
    clog = ctx.clog
    source_code = ctx.source_code
    summary = ctx.summary
    verified_findings = ctx.verified_findings
    poc_findings = ctx.poc_findings
    escaped_siblings = ctx.escaped_siblings
    fallback_findings = ctx.fallback_findings
    finding_groups = ctx.finding_groups
    comp_start = ctx.comp_start
    args = ctx.args

    benchmark_mode_flag = getattr(args, "benchmark_mode", "redteam")

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
        _rb._log_funnel(component, findings, verified_findings,
                    poc_findings + escaped_siblings + fallback_findings,
                    pipeline_findings, [])
        comp_elapsed = (time.time() - comp_start) / 60
        logger.info(f"  🏁 Component {component} COMPLETE (poc mode) — "
                    f"{len(pipeline_findings)} PoC-confirmed ({comp_elapsed:.1f}min)")
        return "EARLY_EXIT_poc_mode"

    report_findings = []
    if pipeline_findings:
        logger.info(f"  Processing {len(pipeline_findings)} verified findings (3 parallel)")
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    _rb.run_finding_pipeline, f, component, protocol, source_code, repo, clog,
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
    _rb._log_funnel(component, findings, verified_findings,
                poc_findings + escaped_siblings + fallback_findings,
                pipeline_findings, report_findings)

    # ─── Done ────────────────────────────────────────────────────────────
    comp_elapsed = (time.time() - comp_start) / 60
    logger.info(f"  🏁 Component {component} COMPLETE — {len(findings)} findings ({comp_elapsed:.1f}min)")
    return None
