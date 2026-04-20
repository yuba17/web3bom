"""run_component_pipeline — full per-component hunt orchestration.

Verbatim cut-and-paste from run_benchmark.py with mutable / monkeypatched
symbols rewired through `import run_benchmark as _rb` (lazy, avoids
circular imports and freeze-at-load semantics).

See package __init__.py for the rationale.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from finding_pipeline import (
    POC_CONFIDENCE_THRESHOLD,
    dedup_findings as _dedup_findings_pure,
    collect_verify_candidates as _collect_verify_candidates_pure,
    dedup_for_poc as _dedup_for_poc_pure,
)
from paths import WEB3_DIR
from benchmark.prompt_builders import (
    read_source,
    build_hunter_brief,
    build_hunter_dispatch_prompt,
)
logger = logging.getLogger("orchestrator")


# ─── Component Pipeline ─────────────────────────────────────────────────────

def run_component_pipeline(component: str, repo: str, protocol: str,
                           args: argparse.Namespace,
                           accumulated_context: str = "",
                           hunters_subset: set | None = None) -> dict:
    """Run the full pipeline for one component. Returns summary dict."""
    # lazy module-ref — reads mutable globals (HUNT_SESSION_DIR, SCRIPT_DIR,
    # USE_SUB_MODE, PARALLEL_HUNTERS, DISABLE_FEW_SHOT) that main() mutates
    # after argparse, plus names that tests monkeypatch on the run_benchmark
    # namespace (_llm, run_cmd, component_log_dir, HUNT_SESSION_DIR, LOG_DIR,
    # close_component, subprocess). Top-level import would freeze bindings
    # AND create a circular import (since run_benchmark re-exports this module).
    import run_benchmark as _rb
    import os
    import re
    import subprocess
    import sys
    import time
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    comp_start = time.time()
    logger.info(f"\n{'='*60}")
    logger.info(f"  🔍 COMPONENT: {component}")
    logger.info(f"{'='*60}")

    clog = _rb.component_log_dir(component)
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

    # ─── Context Phase (Steps -1 through 1.9) ─────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.context import (
        clean_slate, run_prepass, check_early_exit,
        load_tests, load_knowledge, load_interfaces, ensure_chimera_setup,
    )
    _ctx = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir,
        hyp_dir=_rb.HUNT_SESSION_DIR / "hypotheses" / protocol,
        clog=clog, src_file=src_file,
        comp_start=comp_start,
    )
    _ctx.summary = summary  # share by reference
    _ctx.source_code = source_code
    _ctx.library_code = library_code
    _ctx.accumulated_context = accumulated_context

    clean_slate(_ctx)
    run_prepass(_ctx)
    _early = check_early_exit(_ctx)
    if _early == "EMPTY_PREPASS_SKIP":
        return summary  # summary already populated by check_early_exit
    load_tests(_ctx)
    load_knowledge(_ctx)
    load_interfaces(_ctx)
    ensure_chimera_setup(_ctx)

    # propagate ctx mutations back to locals (hunters and downstream phases still use locals)
    _skip_to_merge = _ctx._skip_to_merge
    protocol_model = _ctx.protocol_model
    existing_tests_summary = _ctx.existing_tests_summary
    _test_files_cache = _ctx._test_files_cache
    knowledge_context = _ctx.knowledge_context
    interfaces_code = _ctx.interfaces_code
    hyp_dir = _ctx.hyp_dir

    # ─── Step 2: 12 Hunters ──────────────────────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.hunters import run_hunters, BLOCKED_HUNTERS
    _ctx_hunters = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir,
        hyp_dir=_rb.HUNT_SESSION_DIR / "hypotheses" / protocol,
        clog=clog,
        src_file=src_file if 'src_file' in dir() else Path("."),
    )
    _ctx_hunters.summary = summary
    _ctx_hunters._skip_to_merge = _skip_to_merge
    if 'source_code' in dir(): _ctx_hunters.source_code = source_code
    if 'library_code' in dir(): _ctx_hunters.library_code = library_code
    if 'accumulated_context' in dir(): _ctx_hunters.accumulated_context = accumulated_context
    if 'protocol_model' in dir(): _ctx_hunters.protocol_model = protocol_model
    if 'interfaces_code' in dir(): _ctx_hunters.interfaces_code = interfaces_code
    if 'existing_tests_summary' in dir(): _ctx_hunters.existing_tests_summary = existing_tests_summary
    if 'knowledge_context' in dir(): _ctx_hunters.knowledge_context = knowledge_context
    _hunters_result = run_hunters(_ctx_hunters, hunters_subset=hunters_subset)
    if _hunters_result == BLOCKED_HUNTERS:
        return summary
    # Propagate ctx fields mutated by run_hunters back to local variables
    hyp_dir = _ctx_hunters.hyp_dir
    setup_sol_text = _ctx_hunters.setup_sol_text
    setup_var_names = _ctx_hunters.setup_var_names
    prepass_signals_text = _ctx_hunters.prepass_signals_text
    interfaces_code = _ctx_hunters.interfaces_code
    existing_tests_summary = _ctx_hunters.existing_tests_summary
    knowledge_context = _ctx_hunters.knowledge_context

    # ─── Step 4: DeepDive hunter ─────────────────────────────────────────
    if not _skip_to_merge:
        from benchmark.component_pipeline.deepdive import run_deepdive
        _ctx_dd = PipelineContext(
            component=component, repo=repo, protocol=protocol,
            args=args, logger=logger,
            src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
            src_file=src_file if 'src_file' in dir() else Path("."),
        )
        _ctx_dd.summary = summary
        if 'source_code' in dir(): _ctx_dd.source_code = source_code
        if 'library_code' in dir(): _ctx_dd.library_code = library_code
        if 'accumulated_context' in dir(): _ctx_dd.accumulated_context = accumulated_context
        if 'prepass_signals_text' in dir(): _ctx_dd.prepass_signals_text = prepass_signals_text
        if 'setup_sol_text' in dir(): _ctx_dd.setup_sol_text = setup_sol_text
        if 'protocol_model' in dir(): _ctx_dd.protocol_model = protocol_model
        run_deepdive(_ctx_dd)

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
        # ─── Steps 5-7: Ensure Setup + Merge invariants + compile ──────
        from benchmark.component_pipeline.pipeline_context import PipelineContext
        from benchmark.component_pipeline.merge import run_merge, SKIP_TO_EXTRACT
        _ctx_merge = PipelineContext(
            component=component, repo=repo, protocol=protocol,
            args=args, logger=logger,
            src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
            src_file=src_file if 'src_file' in dir() else Path("."),
        )
        _ctx_merge.summary = summary
        if 'source_code' in dir(): _ctx_merge.source_code = source_code
        if 'library_code' in dir(): _ctx_merge.library_code = library_code
        if 'interfaces_code' in dir(): _ctx_merge.interfaces_code = interfaces_code
        if 'existing_tests_summary' in dir(): _ctx_merge.existing_tests_summary = existing_tests_summary
        if 'knowledge_context' in dir(): _ctx_merge.knowledge_context = knowledge_context
        if 'setup_sol_text' in dir(): _ctx_merge.setup_sol_text = setup_sol_text
        _merge_result = run_merge(_ctx_merge)
        # Rebind updated locals:
        setup_sol_text = _ctx_merge.setup_sol_text
        # Propagate blocking states back to caller
        if _ctx_merge.summary.get("status") in ("BLOCKED_CHIMERA", "BLOCKED_MERGE", "BLOCKED_COMPILE"):
            return summary
        _skip_to_extract = False
        if _merge_result == SKIP_TO_EXTRACT:
            _skip_to_extract = True

        # ─── Step 7.5: Enhance TargetFunctions (opt-in) ────────────────
        if _skip_to_extract:
            logger.info("  Skipping Step 7.5 (compile failed, fast mode)")
        else:
            from benchmark.component_pipeline.pipeline_context import PipelineContext
            from benchmark.component_pipeline.enhance import enhance_target_functions
            _ctx_enhance = PipelineContext(
                component=component, repo=repo, protocol=protocol,
                args=args, logger=logger,
                src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
                src_file=src_file if 'src_file' in dir() else Path("."),
            )
            _ctx_enhance.summary = summary
            _ctx_enhance.setup_sol_text = setup_sol_text
            enhance_target_functions(_ctx_enhance)

        # ─── Step 8: Phase 1 + Step 9: Phase 2 + Step 9.5: Tolerance Tuning ──
        if _skip_to_extract:
            logger.info("  Skipping Steps 8-9.5 (compile failed, fast mode)")
        if not _skip_to_extract:
            from benchmark.component_pipeline.fuzz import (
                run_phase1_foundry, run_phase2_medusa, BLOCKED_PHASE1_INFRA,
            )
            _ctx_fuzz = PipelineContext(
                component=component, repo=repo, protocol=protocol,
                args=args, logger=logger,
                src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
                src_file=src_file if 'src_file' in dir() else Path("."),
            )
            _ctx_fuzz.summary = summary
            if 'setup_sol_text' in dir(): _ctx_fuzz.setup_sol_text = setup_sol_text
            if 'source_code' in dir(): _ctx_fuzz.source_code = source_code
            _fuzz1_result = run_phase1_foundry(_ctx_fuzz)
            if _fuzz1_result == BLOCKED_PHASE1_INFRA:
                return summary
            run_phase2_medusa(_ctx_fuzz)
            # Rebind outputs for downstream steps:
            phase1_fuzz_failures = _ctx_fuzz.phase1_fuzz_failures
            phase2_log = _ctx_fuzz.phase2_log

    # ─── Step 10: Extract Findings + dedup ──────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.extract import extract_findings
    _ctx_extract = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
        comp_start=comp_start,
        phase1_fuzz_failures=phase1_fuzz_failures,
        phase2_log=phase2_log,
    )
    _ctx_extract.summary = summary  # share by reference
    _extract_result = extract_findings(_ctx_extract)
    if _extract_result == "EARLY_EXIT_hypothesis":
        return summary
    findings = summary["findings"]
    finding_groups = _ctx_extract.finding_groups
    poc_findings = _ctx_extract.poc_findings
    escaped_siblings = _ctx_extract.escaped_siblings
    fallback_findings = _ctx_extract.fallback_findings

    # ─── Step 10.2: Verify findings (lightweight) ──────────────────────────
    from benchmark.component_pipeline.verify import verify_findings_lightweight
    _ctx_verify = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
    )
    _ctx_verify.summary = summary  # share by reference
    _ctx_verify.source_code = source_code
    _ctx_verify.library_code = library_code
    _ctx_verify.finding_groups = finding_groups
    verify_findings_lightweight(_ctx_verify)
    # Rebind locals that downstream Steps consume:
    verified_findings = _ctx_verify.verified_findings

    # ─── Step 11: Fork PoC per finding (Phase 3) ───────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.poc import generate_fork_pocs
    _ctx_poc = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog,
        src_file=src_file if 'src_file' in dir() else Path("."),
    )
    _ctx_poc.summary = summary
    if 'source_code' in dir(): _ctx_poc.source_code = source_code
    if 'library_code' in dir(): _ctx_poc.library_code = library_code
    if 'interfaces_code' in dir(): _ctx_poc.interfaces_code = interfaces_code
    if 'verified_findings' in dir(): _ctx_poc.verified_findings = verified_findings
    _ctx_poc.finding_groups = finding_groups
    _ctx_poc.poc_findings = poc_findings
    _ctx_poc.escaped_siblings = escaped_siblings
    _ctx_poc.fallback_findings = fallback_findings
    generate_fork_pocs(_ctx_poc)
    # Rebind locals downstream steps consume:
    finding_groups = _ctx_poc.finding_groups
    poc_findings = _ctx_poc.poc_findings
    fallback_findings = _ctx_poc.fallback_findings
    escaped_siblings = _ctx_poc.escaped_siblings

    # ─── Step 12: Finding pipeline dispatch ────────────────────────────
    from benchmark.component_pipeline.pipeline_context import PipelineContext
    from benchmark.component_pipeline.finding import dispatch_finding_pipeline
    _ctx_finding = PipelineContext(
        component=component, repo=repo, protocol=protocol,
        args=args, logger=logger,
        src_dir=src_dir, hyp_dir=hyp_dir, clog=clog, src_file=src_file,
    )
    _ctx_finding.summary = summary  # share by reference
    _ctx_finding.source_code = source_code
    _ctx_finding.comp_start = comp_start
    _ctx_finding.finding_groups = finding_groups
    if 'verified_findings' in dir():
        _ctx_finding.verified_findings = verified_findings
    _ctx_finding.poc_findings = poc_findings
    _ctx_finding.escaped_siblings = escaped_siblings
    _ctx_finding.fallback_findings = fallback_findings
    _finding_result = dispatch_finding_pipeline(_ctx_finding)
    if _finding_result == "EARLY_EXIT_poc_mode":
        return summary
    return summary
