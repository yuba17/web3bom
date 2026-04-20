"""Finding pipeline — extracted from run_benchmark.py in Phase 6.

Provides:
    - extract_findings (pull hunter YAML outputs into structured list)
    - run_finding_pipeline (per-finding orchestrator: escalation + variant +
      redteam + report gates)

Consumers: benchmark.component_pipeline (called at the end of a component run).
"""

import logging
import re
from pathlib import Path

from benchmark.llm_runners import _llm
from benchmark.prompt_builders import (
    build_escalation_prompt, build_redteam_prompt,
    build_variant_prompt, build_report_prompt,
)
# Standalone module (NOT this package) — provides shared helpers.
from finding_pipeline import (
    extract_findings_from_yaml,
    extract_relevant_code as _extract_relevant_code,
)
logger = logging.getLogger("orchestrator")


def extract_findings(component: str, protocol: str,
                     fuzz_failures: dict[str, str] = None,
                     hyp_dir: Path = None) -> list[dict]:
    """Extract findings from hypothesis files, prioritizing fuzz-confirmed ones.

    Thin wrapper around finding_pipeline.extract_findings_from_yaml that adds
    logging and constructs hyp_dir.

    hyp_dir: explicit directory to read hypothesis YAMLs from. When None, falls
        back to run_benchmark.HUNT_SESSION_DIR (which is reassigned by
        benchmark.cli.main() in benchmark mode). Module-level `from paths import
        HUNT_SESSION_DIR` would bind to the original value and miss the
        reassignment — that's the historical bug this defaulting dodges.
    """
    if hyp_dir is None:
        import run_benchmark as _rb
        hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
    findings = extract_findings_from_yaml(hyp_dir, component, fuzz_failures)

    # Log fuzz-confirmed findings
    confirmed = [f for f in findings if f.get("fuzz_confirmed")]
    unconfirmed = [f for f in findings if not f.get("fuzz_confirmed")]
    for f in confirmed:
        logger.info(f"    CONFIRMED by fuzzer: {f['id']} ({f.get('property_name', '')})")
    if confirmed:
        logger.info(f"  {len(confirmed)} fuzz-confirmed findings, {len(unconfirmed)} unconfirmed")
    else:
        logger.info(f"  0 fuzz-confirmed — {len(unconfirmed)} unconfirmed findings sorted by confidence")
    return findings


# ─── Finding Pipeline ────────────────────────────────────────────────────────

def run_finding_pipeline(finding: dict, component: str, protocol: str,
                         source_code: str, repo: str, clog: Path,
                         benchmark_mode: bool = False):
    """Run escalation → redteam → variant → report for a single finding.

    Each stage mirrors the full skill implementation from ~/.claude/skills/.
    If benchmark_mode=True, stops after RedTeam (skips Variant + Report).
    """
    fid = finding.get("id", finding.get("title", "UNKNOWN")[:20])
    logger.info(f"    Finding {fid}: {finding.get('title','?')} ({finding.get('severity','?')})")

    # Load PoC code if it exists
    poc_code = ""
    poc_path = finding.get("poc_path", "")
    if poc_path and Path(poc_path).exists():
        poc_code = Path(poc_path).read_text(encoding="utf-8")[:10000]

    # Use focused code extraction for the finding — keeps prompts under 12k chars
    # instead of sending full 30k contract for every escalation/redteam call.
    focused_code = _extract_relevant_code(source_code, "", finding)

    # For cross-component findings: source_code = combined_source (all contracts).
    # Injecting source_code[:12000] would show the WRONG contracts (sorted-first small ones)
    # instead of the contracts where the bug actually lives. Since RedTeam/EscalationHunter
    # have unrestricted file access, show the repo path and let them read what they need.
    if component == "CrossComponent":
        _src_hint = (
            f"## Source Files (use Read tool to access)\n"
            f"Repo: {repo}\n"
            f"Protocol contracts: {repo}/src/\n"
            f"(focused extract above already targets the vulnerable area)"
        )
    else:
        _src_hint = f"## Full Source (for context)\n```solidity\n{source_code[:12000]}\n```"

    finding_context = (
        f"Finding ID: {fid}\n"
        f"Title: {finding.get('title', finding.get('id', '?'))}\n"
        f"Severity: {finding.get('severity', 'Medium')}\n"
        f"Confidence: {finding.get('confidence', 70)}%\n"
        f"Root Cause: {finding.get('root_cause', finding.get('description', ''))}\n"
        f"Component: {component}\n"
        f"Protocol: {protocol}\n"
        f"Fuzz Confirmed: {finding.get('fuzz_confirmed', False)}\n"
        f"Has PoC: {finding.get('has_poc', False)}\n\n"
        f"## Source Code (focused on vulnerable area)\n```solidity\n{focused_code}\n```\n\n"
        f"{_src_hint}"
    )
    if poc_code:
        finding_context += f"\n\n## Proof of Concept\n```solidity\n{poc_code}\n```"

    # ── F1: Escalation Hunter (Medium+ only) — skip in benchmark mode ────
    # EscalationHunter only adjusts severity ceiling, doesn't affect REPORT/NO verdict.
    # Skip in benchmark mode to save ~150s per finding.
    if not benchmark_mode and finding.get("severity", "Low").capitalize() in ("High", "Medium", "Critical"):
        logger.info(f"    {fid}: EscalationHunter (5 checks)")
        esc_prompt = build_escalation_prompt(finding=finding, finding_context=finding_context)
        _llm(esc_prompt, timeout=180, stall_timeout=120,
                   log_file=clog / f"{fid}_escalation.log", cwd=repo)

    # ── F2: RedTeam (4 attackers, Ronda 0 + 3 rounds) ────────────────────
    # Full skill: severity calibration table, 4 adversarial roles, structured verdict
    logger.info(f"    {fid}: RedTeam (Ronda 0 + 3 rounds)")
    redteam_prompt = build_redteam_prompt(
        finding_context=finding_context, fid=fid, finding=finding,
        component=component
    )
    _, redteam_output = _llm(redteam_prompt, timeout=300, stall_timeout=180,
                                   log_file=clog / f"{fid}_redteam.log", cwd=repo)

    # Parse RedTeam verdict and store on finding for scoring
    def _parse_redteam_verdict(text: str) -> str:
        """Try strict then lenient parse of RESULTADO line."""
        m = re.search(r'RESULTADO:\s*(REPORT_DOWNGRADED|DO_NOT_REPORT|REPORT)', text or "")
        if m:
            return m.group(1)
        # Lenient: case-insensitive, allow surrounding text
        m2 = re.search(r'(?:resultado|verdict)[:\s]+(REPORT_DOWNGRADED|DO_NOT_REPORT|REPORT)',
                       text or "", re.IGNORECASE)
        if m2:
            return m2.group(1).upper()
        return "UNKNOWN"

    def _parse_fix_scope(text: str) -> str:
        """Parse FIX_SCOPE line. Returns same_fix / different_fix / n_a."""
        m = re.search(r'FIX_SCOPE:\s*(same_fix|different_fix|n_a)', text or "", re.IGNORECASE)
        if m:
            return m.group(1).lower()
        return "n_a"

    verdict = _parse_redteam_verdict(redteam_output)
    fix_scope = _parse_fix_scope(redteam_output)

    # If still UNKNOWN, retry once — output may have cut off or missed the RESULTADO line
    if verdict == "UNKNOWN":
        logger.warning(f"    {fid}: RedTeam returned UNKNOWN — retrying (1/1)")
        _, redteam_output2 = _llm(redteam_prompt, timeout=300, stall_timeout=180,
                                        log_file=clog / f"{fid}_redteam_retry.log", cwd=repo)
        verdict = _parse_redteam_verdict(redteam_output2)
        if fix_scope == "n_a":
            fix_scope = _parse_fix_scope(redteam_output2)
        if verdict != "UNKNOWN":
            logger.info(f"    {fid}: RedTeam retry → {verdict}")
        else:
            logger.warning(f"    {fid}: RedTeam still UNKNOWN after retry — keeping UNKNOWN")

    finding["redteam_verdict"] = verdict
    finding["fix_scope"] = fix_scope
    # Save raw output for post-hoc analysis (capped at 2K chars)
    finding["_redteam_output"] = (redteam_output or "")[:2000]

    # Categorize kill reason using R1-R5 rejection rules (for analytics)
    if verdict == "DO_NOT_REPORT":
        _rt = (redteam_output or "").lower()
        if any(w in _rt for w in ["trusted role", "admin", "owner", "manager", "privileged", "only owner", "onlyowner"]):
            finding["redteam_kill_reason"] = "R1_TRUSTED_ROLE"
        elif any(w in _rt for w in ["view only", "no-op", "read-only", "read only", "pure function"]):
            finding["redteam_kill_reason"] = "R2_VIEW_ONLY"
        elif any(w in _rt for w in ["by design", "intended behavior", "disabled by design", "works as intended"]):
            finding["redteam_kill_reason"] = "R3_BY_DESIGN"
        elif any(w in _rt for w in ["out of scope", "not in scope", "not in the scope", "oos", "outside scope"]):
            finding["redteam_kill_reason"] = "R4_OUT_OF_SCOPE"
        elif any(w in _rt for w in ["no funds", "cosmetic", "no security impact", "ux issue", "no impact"]):
            finding["redteam_kill_reason"] = "R5_NO_IMPACT"
        else:
            finding["redteam_kill_reason"] = "R0_OTHER"
    else:
        finding["redteam_kill_reason"] = ""

    logger.info(f"    {fid}: RedTeam verdict → {verdict}"
                + (f" [{finding['redteam_kill_reason']}]" if finding.get("redteam_kill_reason") else ""))

    if benchmark_mode:
        logger.info(f"    {fid}: benchmark mode — stopping after RedTeam")
        return

    # ── F3: Variant Hunt (4-step: root cause → L0-L3 → triage) ───────────
    # Full skill: root cause statement template, 4 search levels, triage classification
    logger.info(f"    {fid}: VariantHunt (L0-L3)")
    variant_prompt = build_variant_prompt(fid=fid, finding_context=finding_context, repo=repo)
    _llm(
        variant_prompt,
        allowed_tools=["Read", "Grep", "Glob"],
        timeout=240, stall_timeout=120,
        log_file=clog / f"{fid}_variant.log",
        cwd=repo
    )

    # ── F4: Report Writer (platform-aware, anti-AI writing) ───────────────
    # Full skill: platform detection, RedTeam mapping, anti-AI pass, Sherlock template
    logger.info(f"    {fid}: ReportWriter (Sherlock template)")
    # Keep benchmark reports isolated — never write to WEB3_DIR/reports/
    reports_dir = HUNT_SESSION_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)

    slug = finding.get("title", fid)[:40].lower().replace(" ", "-").replace("/", "-")
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    report_path = reports_dir / f"DRAFT-{fid}-{slug}.md"
    report_prompt = build_report_prompt(finding_context=finding_context, report_path=report_path)
    _llm(
        report_prompt,
        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
        timeout=240, stall_timeout=120,
        log_file=clog / f"{fid}_report.log",
        cwd=repo
    )
