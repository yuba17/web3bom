"""poc.py — Phase 3 Fork PoC generator per confirmed finding."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from benchmark.component_pipeline.pipeline_context import PipelineContext


def generate_fork_pocs(ctx: PipelineContext) -> None:
    """Generates Foundry fork PoC per finding via parallel dispatches.

    Mutates ctx.summary['findings'], ctx.poc_findings, ctx.finding_groups,
    ctx.fallback_findings, and ctx.escaped_siblings.
    """
    import run_benchmark as _rb
    from finding_pipeline import (
        POC_CONFIDENCE_THRESHOLD,
        dedup_for_poc as _dedup_for_poc_pure,
    )

    # Unpack context locals for readability (mirrors the original runner locals)
    summary = ctx.summary
    component = ctx.component
    protocol = ctx.protocol
    hyp_dir = ctx.hyp_dir
    clog = ctx.clog
    logger = ctx.logger
    repo = ctx.repo
    src_dir = ctx.src_dir
    args = ctx.args
    source_code = ctx.source_code
    library_code = ctx.library_code
    interfaces_code = ctx.interfaces_code
    verified_findings = ctx.verified_findings
    finding_groups = ctx.finding_groups
    escaped_siblings = ctx.escaped_siblings
    fallback_findings = ctx.fallback_findings

    if not finding_groups:
        return

    logger.info("  Step 10.5: Generating Fork PoCs for confirmed findings")
    from pathlib import Path
    poc_dir = Path(repo) / "test" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)

    # forge_env: local dict derived from os.environ — stays inline, not in ctx
    forge_env = os.environ.copy()
    forge_env["FOUNDRY_PROFILE"] = "chimera"
    for _rpc_var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        _rpc_val = os.environ.get(_rpc_var, "")
        if _rpc_val:
            forge_env[_rpc_var] = _rpc_val

    def _run_poc(finding):
        """Delegate to top-level generate_and_test_poc with component context."""
        _rb.generate_and_test_poc(
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
    import time
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
    fallback_findings_local: list[dict] = []
    for g in finding_groups:
        if len(g) > 1 and not g[0].get("has_poc"):
            for sib in g[1:]:
                if sib.get("_verified") or sib.get("fuzz_confirmed"):
                    sib["_capa2_fallback"] = True
                    fallback_findings_local.append(sib)
                    break

    # ── Step 10.6: is_same_bug safety check (Capa 3) ─────────────────
    # For every group whose leader passed PoC, check each sibling:
    # "Is B really the same bug as A, or a different vulnerability?"
    # If DIFFERENT → the sibling escaped dedup by mistake and needs its own PoC.
    # This prevents silent loss of real bugs due to over-aggressive deduplication.
    def _check_is_same_bug(leader: dict, sibling: dict) -> bool:
        """180s Claude call: does sibling describe the same bug as leader?
        Conservative: returns True (SAME) on timeout/error — avoid duplicate PoC work."""
        prompt = _rb.build_is_same_bug_prompt(leader=leader, sibling=sibling)
        fid_s = sibling["id"]
        _, out = _rb._llm(
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
    escaped_siblings_local: list[dict] = []
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
                        escaped_siblings_local.append(sib)

    # Phase C: Single unified PoC batch for all fallbacks + escaped siblings
    unified_extra = fallback_findings_local + escaped_siblings_local
    if unified_extra:
        logger.info(f"  Step 10.7: Unified PoC batch — {len(fallback_findings_local)} fallbacks + "
                    f"{len(escaped_siblings_local)} escaped siblings = {len(unified_extra)} total")
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
        fb_confirmed = sum(1 for f in fallback_findings_local if f.get("has_poc"))
        esc_confirmed = sum(1 for f in escaped_siblings_local if f.get("has_poc"))
        logger.info(f"  Unified batch complete: {fb_confirmed} fallbacks + {esc_confirmed} escaped = "
                    f"{fb_confirmed + esc_confirmed} new confirmed")

    # Mark all findings without PoC (default)
    for group in finding_groups:
        for f in group:
            f.setdefault("has_poc", False)
    for f in escaped_siblings_local:
        f.setdefault("has_poc", False)

    # Write back mutated lists to ctx
    ctx.poc_findings = poc_findings
    ctx.fallback_findings = fallback_findings_local
    ctx.escaped_siblings = escaped_siblings_local
