"""verify.py — Step 10.2: Verification — lightweight code-read before Foundry PoC.

Verbatim cut-and-paste of the Step 10.2 block from runner.py.
Receives PipelineContext; mutates ctx.verified_findings.

Returns None on normal flow.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from finding_pipeline import (
    POC_CONFIDENCE_THRESHOLD,
    collect_verify_candidates as _collect_verify_candidates_pure,
)

from benchmark.component_pipeline.pipeline_context import PipelineContext


def verify_findings_lightweight(ctx: PipelineContext) -> None:
    """Quick code-read verification: re-read the specific function and confirm
    the bug is real before investing 15 minutes in a Foundry PoC.

    Mutates ctx.verified_findings.
    """
    import run_benchmark as _rb

    logger = ctx.logger
    clog = ctx.clog
    repo = ctx.repo
    source_code = ctx.source_code
    library_code = ctx.library_code
    finding_groups = ctx.finding_groups

    # ─── Step 10.2: Verification — lightweight code-read before Foundry PoC ─────
    # For every distinct (function, line) location, run a quick Claude call:
    # "Read this specific code + hypothesis — is the bug real?"
    # This replicates the manual auditor step: suspect bug → re-read focused code
    # → confirm before investing 15 min in a Foundry PoC.
    # POC_CONFIDENCE_THRESHOLD is a module-level constant (65) shared with cross-component.

    def _verify_finding(finding: dict) -> tuple[bool, str, str]:
        """Quick code-read verification: re-read the specific function and confirm
        the bug is real before investing 15 minutes in a Foundry PoC.
        Returns (is_real, reason, poc_hint)."""
        fid = finding["id"]
        relevant_code = _rb._extract_relevant_code(source_code, library_code, finding)

        verify_prompt = _rb.build_verify_prompt(finding=finding, relevant_code=relevant_code)

        rc, output = _rb._llm(
            verify_prompt,
            allowed_tools=[],  # pure reasoning — no tool calls, stays fast (~30-90s)
            timeout=300,
            log_file=clog / f"{fid}_verify.log",
            cwd=repo
        )

        output_lower = output.lower()
        # On timeout or empty output: conservative fallback → treat as REAL
        # (better to attempt a PoC on a false positive than to drop a real bug)
        if not output_lower.strip() or rc != 0:
            logger.info(f"    [TIMEOUT/ERROR → REAL fallback] {fid}")
            return True, "timeout — included conservatively", ""
        is_real = "verdict: real" in output_lower and "verdict: false_positive" not in output_lower

        reason, poc_hint = "", ""
        for line in output.splitlines():
            if line.upper().startswith("REASON:"):
                reason = line[7:].strip()
            elif line.upper().startswith("POC_HINT:"):
                poc_hint = line[9:].strip()

        status = "REAL ✓" if is_real else "FALSE_POSITIVE ✗"
        logger.info(f"    [{status}] {fid}: {reason[:80]}")
        return is_real, reason, poc_hint

    verify_candidates = _collect_verify_candidates_pure(finding_groups, POC_CONFIDENCE_THRESHOLD)
    logger.info(f"  Step 10.2: Verifying {len(verify_candidates)} distinct hypotheses "
                f"({min(10, len(verify_candidates))} parallel)")

    verified_findings: list[dict] = []
    if verify_candidates:
        with ThreadPoolExecutor(max_workers=min(10, len(verify_candidates))) as executor:
            futures = {executor.submit(_verify_finding, f): f for f in verify_candidates}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    is_real, reason, poc_hint = future.result()
                    f["_verified"] = is_real
                    f["_verify_reason"] = reason
                    if poc_hint and poc_hint.lower() != "n/a":
                        f["_poc_hint"] = poc_hint
                    if is_real or f.get("fuzz_confirmed"):
                        verified_findings.append(f)
                except Exception as e:
                    logger.error(f"    Verification error for {f['id']}: {e}")
                    f["_verified"] = True  # conservative: include on error
                    verified_findings.append(f)
        verified_findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        logger.info(f"  Verification complete: {len(verified_findings)}/{len(verify_candidates)} confirmed real bugs")

    ctx.verified_findings = verified_findings
