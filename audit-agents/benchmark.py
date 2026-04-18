#!/usr/bin/env python3
"""
Benchmark Scorer — Mide findings reportados contra ground truth de contests públicos.

Uso:
  python3 benchmark.py --score benchmarks/yieldoor/ [--threshold 0.35]
  python3 benchmark.py --setup benchmarks/yieldoor/benchmark.yaml   # clona repo al commit del scope
  python3 benchmark.py --list                                        # listar benchmarks

Flujo completo:
  1. benchmark.py --setup  → clona repo
  2. Correr pipeline COMPLETO como hunt real (scope_intake → hunters → fuzz → findings → reports)
  3. benchmark.py --score  → compara nuestros findings reportados vs ground truth
"""

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from paths import WEB3_DIR, AUDIT_AGENTS_DIR, HUNT_SESSION_DIR, STATE_FILE

BENCHMARKS_DIR = WEB3_DIR / "benchmarks"
REPORTS_DIR = WEB3_DIR / "reports"

# Hunter → typical bug categories they should catch (for diagnosis)
HUNTER_CATEGORY_MAP = {
    "MathHunter": {"accounting", "rounding", "flash_loan"},
    "AccessHunter": {"access_control", "upgrade"},
    "FlowHunter": {"reentrancy", "logic", "cross_component"},
    "OracleHunter": {"oracle"},
    "DomainHunter": {"logic", "other"},
    "TrustBoundaryHunter": {"input_validation", "cross_component", "signature"},
    "SignatureHunter": {"signature", "replay"},
    "DoSHunter": {"dos"},
    "WildcardHunter": {"other", "logic", "race_condition"},
    "DeepDiveHunter": {"accounting", "logic", "cross_component", "reentrancy", "oracle"},
    "EdgeHunter": {"cross_component"},
}


# ═══════════════════════════════════════════════════════════════════════
# LOADING
# ═══════════════════════════════════════════════════════════════════════

def load_benchmark(path: Path) -> dict:
    """Load and validate a benchmark YAML file."""
    data = yaml.safe_load(path.read_text())
    contest = data.get("contest", {})
    for field in ["name", "repo", "commit"]:
        if not contest.get(field):
            print(f"ERROR: benchmark.yaml missing contest.{field}")
            sys.exit(1)
    if not data.get("findings"):
        print("ERROR: benchmark.yaml has no findings (ground truth)")
        sys.exit(1)
    return data


def load_our_findings(protocol: str) -> list[dict]:
    """
    Load OUR reported findings from two sources:
    1. current_hunt.json — structured finding records
    2. reports/DRAFT-*.md — full report markdown files

    These are the findings that survived the full pipeline:
    hunters → deepdive → fuzz → PoC → RedTeam → ReportWriter
    """
    our_findings = []

    # Source 1: current_hunt.json
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        if state.get("protocol", "").lower() == protocol.lower():
            for f in state.get("findings", []):
                our_findings.append({
                    "id": f.get("id", ""),
                    "severity": f.get("severity", "").upper(),
                    "title": f.get("title", ""),
                    "component": f.get("component", ""),
                    "status": f.get("status", ""),
                    "notes": f.get("notes", ""),
                    "source": "current_hunt.json",
                    "_full_text": f"{f.get('title', '')} {f.get('notes', '')}",
                })

    # Source 2: DRAFT reports (richer content)
    for report_file in sorted(REPORTS_DIR.glob("DRAFT-*.md")):
        content = report_file.read_text()

        # Extract severity
        severity = "UNKNOWN"
        sev_match = re.search(r"##\s*Severity\s*\n+\s*(Critical|High|Medium|Low|Info)", content, re.IGNORECASE)
        if sev_match:
            severity = sev_match.group(1).upper()

        # Extract title (first H1)
        title = ""
        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        if title_match:
            title = title_match.group(1).strip()

        # Extract finding ID from filename (e.g., DRAFT-FW-DD-01-... → FW-DD-01)
        fname = report_file.stem
        # Remove DRAFT- prefix
        finding_id = fname.replace("DRAFT-", "")
        # Try to extract the structured ID (letters-letters-digits)
        id_match = re.match(r"([A-Z]+-[A-Z]+-\d+)", finding_id, re.IGNORECASE)
        if id_match:
            finding_id = id_match.group(1).upper()

        # Check if this report belongs to our protocol
        # We include all reports and let matching handle it
        our_findings.append({
            "id": finding_id,
            "severity": severity,
            "title": title,
            "component": "",
            "status": "reported",
            "notes": "",
            "source": report_file.name,
            "_full_text": f"{title}\n{content[:3000]}",  # first 3K chars for matching
        })

    # Dedup by ID (prefer report source over current_hunt.json)
    seen_ids = set()
    deduped = []
    # Reports first (richer)
    for f in sorted(our_findings, key=lambda x: x["source"] != "current_hunt.json"):
        fid = f["id"].upper()
        if fid not in seen_ids:
            seen_ids.add(fid)
            deduped.append(f)

    return deduped


def load_hypotheses(protocol: str) -> list[dict]:
    """Load all hypotheses generated by hunters (for diagnosis, not scoring)."""
    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
    if not hyp_dir.exists():
        return []

    all_hyps = []
    for hyp_file in sorted(hyp_dir.glob("hyp_*.yaml")):
        if "template" in hyp_file.name:
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            if not data:
                continue
            hunter = data.get("hunter", hyp_file.stem)
            component = data.get("component", "unknown")
            for inv in data.get("invariants", data.get("findings", data.get("hypotheses", []))):
                if not isinstance(inv, dict):
                    continue
                inv["_hunter"] = hunter
                inv["_component"] = component
                inv["_file"] = hyp_file.name
                all_hyps.append(inv)
        except Exception:
            continue
    return all_hyps


# ═══════════════════════════════════════════════════════════════════════
# MATCHING
# ═══════════════════════════════════════════════════════════════════════

def normalize(text: str) -> str:
    """Lowercase, remove punctuation, collapse whitespace."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def extract_keywords(text: str) -> set[str]:
    """Extract meaningful keywords from text, filtering stopwords."""
    stopwords = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "can", "shall", "to", "of", "in", "for",
        "on", "with", "at", "by", "from", "as", "into", "through", "during",
        "before", "after", "above", "below", "between", "out", "off", "over",
        "under", "again", "further", "then", "once", "that", "this", "these",
        "those", "not", "no", "nor", "and", "but", "or", "if", "when", "than",
        "so", "it", "its", "all", "each", "every", "both", "few", "more",
        "most", "other", "some", "such", "only", "same", "function", "contract",
        "address", "uint256", "uint", "bool", "mapping", "returns", "public",
        "external", "internal", "private", "view", "pure", "memory", "storage",
        "calldata", "return", "require", "assert", "revert", "emit", "event",
    }
    words = set(normalize(text).split())
    return words - stopwords


def match_our_finding_to_ground_truth(our: dict, gt: dict) -> float:
    """
    Compute similarity [0, 1] between one of our reported findings and a ground truth finding.
    """
    score = 0.0

    our_text = our.get("_full_text", f"{our.get('title', '')} {our.get('notes', '')}")
    gt_text = f"{gt.get('title', '')} {gt.get('description', '')}"

    # Signal 1: Contract overlap (0.25)
    our_component = normalize(our.get("component", "") + " " + our.get("title", ""))
    gt_contracts = [normalize(c.replace(".sol", "")) for c in gt.get("contracts", [])]
    contract_hit = any(gc in our_component or our_component in gc for gc in gt_contracts if gc)
    score += 0.25 * (1.0 if contract_hit else 0.0)

    # Signal 2: Keyword overlap (0.40)
    our_kws = extract_keywords(our_text)
    gt_kws = extract_keywords(gt_text) | {normalize(k) for k in gt.get("keywords", [])}
    if our_kws and gt_kws:
        overlap = len(our_kws & gt_kws)
        union = len(our_kws | gt_kws)
        jaccard = overlap / union if union > 0 else 0
        # Explicit keyword boost
        explicit_hits = sum(1 for k in gt.get("keywords", []) if normalize(k) in normalize(our_text))
        boost = min(0.3, explicit_hits * 0.1)
        score += 0.40 * min(1.0, jaccard * 3 + boost)

    # Signal 3: Function name overlap (0.20)
    gt_funcs = {normalize(f) for f in gt.get("functions", [])}
    our_text_norm = normalize(our_text)
    func_hit = any(f in our_text_norm for f in gt_funcs) if gt_funcs else False
    score += 0.20 * (1.0 if func_hit else 0.0)

    # Signal 4: Severity match (0.15)
    sev_match = our.get("severity", "").upper() == gt.get("severity", "").upper()
    score += 0.15 * (1.0 if sev_match else 0.5)  # partial credit for any severity

    return score


def match_findings(our_findings: list[dict], gt_findings: list[dict], threshold: float = 0.35) -> dict:
    """Match our reported findings against ground truth."""
    results = []

    for gt in gt_findings:
        best_score = 0.0
        best_ours = []

        for our in our_findings:
            sim = match_our_finding_to_ground_truth(our, gt)
            if sim >= threshold:
                best_ours.append((our, sim))
            if sim > best_score:
                best_score = sim

        best_ours.sort(key=lambda x: -x[1])
        results.append({
            "ground_truth": gt,
            "best_score": best_score,
            "matched": best_score >= threshold,
            "our_matches": best_ours[:3],
        })

    # Track which of our findings didn't match anything (potential novel finds or false positives)
    matched_our_ids = set()
    for r in results:
        for our, _ in r["our_matches"]:
            matched_our_ids.add(our["id"])
    extra_findings = [f for f in our_findings if f["id"] not in matched_our_ids]

    return {
        "results": results,
        "extra_findings": extra_findings,
        "threshold": threshold,
    }


# ═══════════════════════════════════════════════════════════════════════
# SCORECARD
# ═══════════════════════════════════════════════════════════════════════

def generate_scorecard(benchmark: dict, our_findings: list[dict], match_results: dict,
                       hypotheses: list[dict]) -> str:
    """Generate detailed markdown scorecard."""
    contest = benchmark["contest"]
    gt_findings = benchmark["findings"]
    results = match_results["results"]
    threshold = match_results["threshold"]

    lines = []
    lines.append(f"# Benchmark Scorecard: {contest['name']}")
    lines.append(f"")
    lines.append(f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Platform**: {contest.get('platform', '?')}")
    lines.append(f"**Scope commit**: `{contest['commit'][:12]}`")
    lines.append(f"**Pool**: ${contest.get('pool_size', '?'):,}")
    lines.append(f"**Match threshold**: {threshold}")
    lines.append(f"")

    # ── Summary ──
    total_gt = len(gt_findings)
    found = sum(1 for r in results if r["matched"])
    missed = total_gt - found
    recall = found / total_gt if total_gt > 0 else 0

    lines.append(f"## Results")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Contest findings (ground truth) | {total_gt} |")
    lines.append(f"| **Our findings reported** | **{len(our_findings)}** |")
    lines.append(f"| **Matched to ground truth** | **{found}/{total_gt} ({recall:.0%})** |")
    lines.append(f"| Missed | {missed} |")
    lines.append(f"| Extra (not in ground truth) | {len(match_results['extra_findings'])} |")
    lines.append(f"| Hypotheses generated (all hunters) | {len(hypotheses)} |")
    lines.append(f"")

    # ── By severity ──
    lines.append(f"## By Severity")
    lines.append(f"")
    lines.append(f"| Severity | In Contest | We Found | We Missed | Recall |")
    lines.append(f"|----------|-----------|----------|-----------|--------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_results = [r for r in results if r["ground_truth"].get("severity", "").upper() == sev]
        if not sev_results:
            continue
        sev_found = sum(1 for r in sev_results if r["matched"])
        sev_total = len(sev_results)
        sev_recall = sev_found / sev_total if sev_total > 0 else 0
        lines.append(f"| {sev} | {sev_total} | {sev_found} | {sev_total - sev_found} | {sev_recall:.0%} |")
    lines.append(f"")

    # ── By category ──
    lines.append(f"## By Category")
    lines.append(f"")
    lines.append(f"| Category | In Contest | We Found | We Missed | Recall |")
    lines.append(f"|----------|-----------|----------|-----------|--------|")
    cats = defaultdict(lambda: {"total": 0, "found": 0})
    for r in results:
        cat = r["ground_truth"].get("category", "other")
        cats[cat]["total"] += 1
        if r["matched"]:
            cats[cat]["found"] += 1
    for cat, data in sorted(cats.items(), key=lambda x: -x[1]["total"]):
        cat_recall = data["found"] / data["total"] if data["total"] > 0 else 0
        lines.append(f"| {cat} | {data['total']} | {data['found']} | {data['total'] - data['found']} | {cat_recall:.0%} |")
    lines.append(f"")

    # ── Findings we GOT ──
    lines.append(f"## Findings We Detected")
    lines.append(f"")
    for r in results:
        if not r["matched"]:
            continue
        gt = r["ground_truth"]
        lines.append(f"### ✓ {gt['id']} [{gt.get('severity', '?')}] — {gt.get('title', '?')}")
        lines.append(f"**Category**: {gt.get('category', '?')} | **Match score**: {r['best_score']:.2f}")
        for our, score in r["our_matches"][:2]:
            lines.append(f"- Our [{our['id']}] ({score:.2f}): {our.get('title', '')[:100]}")
        lines.append(f"")

    # ── Findings we MISSED (most important section) ──
    lines.append(f"## Findings We MISSED — Root Cause Analysis")
    lines.append(f"")
    for r in results:
        if r["matched"]:
            continue
        gt = r["ground_truth"]
        lines.append(f"### ✗ {gt['id']} [{gt.get('severity', '?')}] — {gt.get('title', '?')}")
        lines.append(f"**Category**: {gt.get('category', '?')} | **Best (sub-threshold) score**: {r['best_score']:.2f}")
        lines.append(f"**Contracts**: {', '.join(gt.get('contracts', []))}")
        lines.append(f"**Functions**: {', '.join(gt.get('functions', []))}")
        lines.append(f"")
        lines.append(f"> {gt.get('description', '').strip()[:400]}")
        lines.append(f"")

        # Root cause diagnosis using hypothesis data
        diagnosis = _diagnose_miss(gt, hypotheses)
        lines.append(f"**Diagnosis**: {diagnosis}")
        lines.append(f"")

    # ── Pipeline diagnosis: hypothesis → finding conversion rate ──
    if hypotheses:
        lines.append(f"## Pipeline Funnel Analysis")
        lines.append(f"")
        lines.append(f"How many hypotheses survived each pipeline stage:")
        lines.append(f"")
        lines.append(f"| Stage | Count |")
        lines.append(f"|-------|-------|")
        lines.append(f"| Hypotheses generated (all hunters) | {len(hypotheses)} |")

        # Count hypotheses that match any ground truth finding
        hyp_matches = 0
        for gt in gt_findings:
            for hyp in hypotheses:
                hyp_text = f"{hyp.get('description', '')} {hyp.get('attack_scenario', '')}"
                gt_text = f"{gt.get('title', '')} {gt.get('description', '')}"
                hyp_kws = extract_keywords(hyp_text)
                gt_kws = extract_keywords(gt_text) | {normalize(k) for k in gt.get("keywords", [])}
                if hyp_kws and gt_kws:
                    overlap = len(hyp_kws & gt_kws)
                    if overlap >= 3:
                        hyp_matches += 1
                        break

        lines.append(f"| Hypotheses touching real bugs (≥3 keyword overlap) | ~{hyp_matches} |")
        lines.append(f"| Findings reported (survived full pipeline) | {len(our_findings)} |")
        lines.append(f"| Findings matching ground truth | {found} |")
        lines.append(f"")

        if hyp_matches > found:
            lines.append(f"**⚠ {hyp_matches - found} potential findings were detected by hunters but lost in the pipeline.**")
            lines.append(f"Check: Did fuzzing fail to confirm? Did RedTeam reject? Did we not prioritize?")
            lines.append(f"")

    # ── Extra findings (not in ground truth) ──
    extra = match_results["extra_findings"]
    if extra:
        lines.append(f"## Our Extra Findings ({len(extra)} — not in contest results)")
        lines.append(f"")
        lines.append(f"These could be: false positives, valid but different severity, or genuine finds the contest missed.")
        lines.append(f"")
        for f in extra:
            lines.append(f"- [{f['id']}] {f.get('severity', '?')}: {f.get('title', '')[:100]}")
        lines.append(f"")

    # ── Action items ──
    lines.append(f"## Action Items")
    lines.append(f"")
    if missed > 0:
        missed_cats = [r["ground_truth"].get("category", "other") for r in results if not r["matched"]]
        cat_counts = defaultdict(int)
        for c in missed_cats:
            cat_counts[c] += 1
        if cat_counts:
            worst_cat = max(cat_counts, key=cat_counts.get)
            lines.append(f"1. **Worst category**: `{worst_cat}` ({cat_counts[worst_cat]} missed)")

            responsible = set()
            for hunter, cats in HUNTER_CATEGORY_MAP.items():
                if worst_cat in cats:
                    responsible.add(hunter)
            if responsible:
                lines.append(f"   Responsible hunters: {', '.join(sorted(responsible))}")

        # Missed Highs are most critical
        missed_highs = [r for r in results if not r["matched"] and r["ground_truth"].get("severity", "").upper() == "HIGH"]
        if missed_highs:
            lines.append(f"2. **Missed {len(missed_highs)} HIGH severity** — each one is a failed pipeline. Deep-dive into why.")

    lines.append(f"")
    return "\n".join(lines)


def _diagnose_miss(gt_finding: dict, hypotheses: list[dict]) -> str:
    """Diagnose WHY we missed a ground truth finding, using hypothesis data."""
    category = gt_finding.get("category", "other")
    contracts = [c.replace(".sol", "").lower() for c in gt_finding.get("contracts", [])]
    gt_kws = extract_keywords(f"{gt_finding.get('title', '')} {gt_finding.get('description', '')}")

    # Did any hunter generate hypotheses for the right contract?
    right_contract = [
        h for h in hypotheses
        if any(c in normalize(h.get("_component", "")) for c in contracts)
    ]
    if not right_contract:
        return (
            f"**No hunter looked at {gt_finding.get('contracts', [])}**. "
            f"Contract not in scope or component was skipped entirely."
        )

    # Did the right type of hunter generate hypotheses?
    responsible = [name for name, cats in HUNTER_CATEGORY_MAP.items() if category in cats]
    right_hunter = [h for h in right_contract if h.get("_hunter") in responsible]
    if not right_hunter:
        return (
            f"Hunters generated {len(right_contract)} hypotheses for this contract, "
            f"but none from category-relevant hunters ({', '.join(responsible)}). "
            f"The `{category}` bug class was not covered here."
        )

    # Right hunter, right contract — check keyword proximity
    best_overlap = 0
    best_hyp = None
    for h in right_hunter:
        h_kws = extract_keywords(f"{h.get('description', '')} {h.get('attack_scenario', '')}")
        overlap = len(h_kws & gt_kws)
        if overlap > best_overlap:
            best_overlap = overlap
            best_hyp = h

    if best_overlap >= 2 and best_hyp:
        return (
            f"**Near miss** — {best_hyp.get('_hunter')} generated [{best_hyp.get('id', '?')}] "
            f"with {best_overlap} keyword overlap, but it didn't survive the pipeline. "
            f"Check if fuzzing/PoC/RedTeam killed it. Hyp: \"{best_hyp.get('description', '')[:80]}...\""
        )

    return (
        f"{len(right_hunter)} hypotheses from responsible hunters on the right contract, "
        f"but none were close to this bug pattern. "
        f"Keywords to detect: {', '.join(gt_finding.get('keywords', [])[:5])}"
    )


# ═══════════════════════════════════════════════════════════════════════
# SETUP — clone repo at scope commit
# ═══════════════════════════════════════════════════════════════════════

def cmd_setup(benchmark_path: Path):
    """Clone contest repo at the exact scope commit."""
    benchmark = load_benchmark(benchmark_path)
    contest = benchmark["contest"]
    benchmark_dir = benchmark_path.parent
    repo_dir = benchmark_dir / "repo"

    print(f"\n{'='*60}")
    print(f"  BENCHMARK SETUP: {contest['name']}")
    print(f"  Commit: {contest['commit']}")
    print(f"  Scope: {len(benchmark.get('scope', []))} files")
    print(f"{'='*60}\n")

    if repo_dir.exists():
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_dir, capture_output=True, text=True
        )
        current = result.stdout.strip() if result.returncode == 0 else ""
        if current.startswith(contest["commit"][:8]):
            print(f"  ✓ Repo already at correct commit ({contest['commit'][:12]})")
            _print_next_steps(benchmark_dir, contest)
            return
        print(f"  Repo exists at {current[:12]}, checking out {contest['commit'][:12]}...")
        subprocess.run(["git", "checkout", contest["commit"]], cwd=repo_dir, capture_output=True)
        _print_next_steps(benchmark_dir, contest)
        return

    print(f"  Cloning {contest['repo']}...")
    result = subprocess.run(
        ["git", "clone", contest["repo"], str(repo_dir)],
        capture_output=True, text=True, timeout=180,
    )
    if result.returncode != 0:
        print(f"  ERROR: clone failed: {result.stderr[:300]}")
        sys.exit(1)

    print(f"  Checking out scope commit {contest['commit'][:12]}...")
    result = subprocess.run(
        ["git", "checkout", contest["commit"]],
        cwd=repo_dir, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  ERROR: checkout failed: {result.stderr[:200]}")
        sys.exit(1)

    # Install forge deps if applicable
    if (repo_dir / "foundry.toml").exists():
        print(f"  Installing forge dependencies...")
        subprocess.run(["forge", "install"], cwd=repo_dir, capture_output=True, timeout=120)

    print(f"  ✓ Repo ready at {repo_dir}")
    _print_next_steps(benchmark_dir, contest)


def _print_next_steps(benchmark_dir: Path, contest: dict):
    """Print instructions for running the hunt."""
    repo_dir = benchmark_dir / "repo"
    protocol = benchmark_dir.name
    scope = " ".join(f.split("/")[-1] for f in contest.get("scope", []) if f.endswith(".sol"))

    print(f"\n  Next steps — run as a NORMAL hunt:")
    print(f"  ─────────────────────────────────")
    print(f"  1. scope_intake:")
    print(f"     python3 audit-agents/scope_intake.py --repo {repo_dir} \\")
    print(f"       --platform {contest.get('platform', 'SHERLOCK')} --scope-text \"{scope}\"")
    print(f"  2. Run full pipeline (hunters, deepdive, fuzz, findings)")
    print(f"  3. When done, score:")
    print(f"     python3 audit-agents/benchmark.py --score {benchmark_dir}")


# ═══════════════════════════════════════════════════════════════════════
# SCORE
# ═══════════════════════════════════════════════════════════════════════

def cmd_score(benchmark_dir: Path, threshold: float):
    """Score our reported findings against ground truth."""
    bf = benchmark_dir / "benchmark.yaml"
    if not bf.exists():
        print(f"ERROR: {bf} not found")
        sys.exit(1)

    benchmark = load_benchmark(bf)
    contest = benchmark["contest"]
    protocol = benchmark_dir.name

    print(f"\n{'='*60}")
    print(f"  SCORING: {contest['name']}")
    print(f"{'='*60}")

    # Load our findings
    our_findings = load_our_findings(protocol)
    print(f"  Our reported findings: {len(our_findings)}")
    for f in our_findings:
        print(f"    [{f['severity']}] {f['id']}: {f.get('title', '')[:60]}")

    # Load hypotheses for diagnosis
    hypotheses = load_hypotheses(protocol)
    print(f"  Hypotheses (all hunters): {len(hypotheses)}")
    print(f"  Ground truth: {len(benchmark['findings'])} findings")

    if not our_findings:
        print(f"\n  ⚠ No findings found. Complete the full pipeline first.")
        print(f"  Check: current_hunt.json protocol matches '{protocol}'")
        print(f"  Check: reports/DRAFT-*.md exist")
        # Still generate scorecard showing 0% recall
        results = match_findings([], benchmark["findings"], threshold)
        scorecard = generate_scorecard(benchmark, [], results, hypotheses)
        output = benchmark_dir / "scorecard.md"
        output.write_text(scorecard)
        print(f"\n  Scorecard (0% recall): {output}")
        return

    # Match
    results = match_findings(our_findings, benchmark["findings"], threshold)
    scorecard = generate_scorecard(benchmark, our_findings, results, hypotheses)

    # Save
    output = benchmark_dir / "scorecard.md"
    output.write_text(scorecard)

    # Save JSON for programmatic analysis
    match_json = benchmark_dir / "match_results.json"
    found = sum(1 for r in results["results"] if r["matched"])
    total = len(benchmark["findings"])
    serializable = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": protocol,
        "threshold": threshold,
        "our_findings": len(our_findings),
        "ground_truth": total,
        "matched": found,
        "missed": total - found,
        "recall": round(found / total, 3) if total > 0 else 0,
        "extra": len(results["extra_findings"]),
        "hypotheses_total": len(hypotheses),
        "per_finding": [
            {
                "id": r["ground_truth"]["id"],
                "severity": r["ground_truth"].get("severity"),
                "category": r["ground_truth"].get("category"),
                "matched": r["matched"],
                "best_score": round(r["best_score"], 3),
                "our_match": r["our_matches"][0][0]["id"] if r["our_matches"] else None,
            }
            for r in results["results"]
        ],
    }
    match_json.write_text(json.dumps(serializable, indent=2))

    # Print summary
    recall = found / total if total > 0 else 0
    print(f"\n{'='*50}")
    print(f"  RECALL: {found}/{total} ({recall:.0%})")
    print(f"  Our findings: {len(our_findings)} reported")
    print(f"  Extra (not in contest): {len(results['extra_findings'])}")
    print(f"{'='*50}")

    missed = [r for r in results["results"] if not r["matched"]]
    if missed:
        print(f"\n  MISSED ({len(missed)}):")
        for r in missed:
            gt = r["ground_truth"]
            print(f"    [{gt.get('severity', '?')}] {gt['id']}: {gt.get('title', '')[:60]}")

    print(f"\n  Full scorecard: {output}")


# ═══════════════════════════════════════════════════════════════════════
# LIST
# ═══════════════════════════════════════════════════════════════════════

def cmd_list():
    """List available benchmarks."""
    print("\nAvailable benchmarks:\n")
    if not BENCHMARKS_DIR.exists():
        print("  No benchmarks directory found.")
        return

    for d in sorted(BENCHMARKS_DIR.iterdir()):
        if not d.is_dir():
            continue
        bf = d / "benchmark.yaml"
        if not bf.exists():
            continue
        data = yaml.safe_load(bf.read_text())
        contest = data.get("contest", {})
        findings = data.get("findings", [])
        n_h = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
        n_m = sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM")

        # Check if scorecard exists
        has_score = (d / "scorecard.md").exists()
        score_label = " [SCORED]" if has_score else ""

        print(f"  {d.name}{score_label}")
        print(f"    {contest.get('name', '?')} ({contest.get('platform', '?')})")
        print(f"    {len(findings)} findings ({n_h}H, {n_m}M)")
        print(f"    Commit: {contest.get('commit', '?')[:12]}")
        if has_score:
            try:
                mj = json.loads((d / "match_results.json").read_text())
                print(f"    Last score: {mj['matched']}/{mj['ground_truth']} ({mj['recall']:.0%} recall)")
            except Exception:
                pass
        print()


def match_hypothesis_to_ground_truth(hyp: dict, gt: dict) -> float:
    """
    Compute similarity [0, 1] between a hypothesis and a ground truth finding.
    Used for --score-hypotheses mode (detection capability, not full pipeline).
    """
    score = 0.0

    hyp_text = f"{hyp.get('title', '')} {hyp.get('description', '')} {hyp.get('attack_scenario', '')}"
    gt_text = f"{gt.get('title', '')} {gt.get('description', '')}"

    # Signal 1: Component/contract overlap (0.25)
    hyp_component = normalize(hyp.get("_component", "") + " " + hyp.get("title", ""))
    gt_contracts = [normalize(c.replace(".sol", "")) for c in gt.get("contracts", [])]
    contract_hit = any(gc in hyp_component or hyp_component in gc for gc in gt_contracts if gc)
    score += 0.25 * (1.0 if contract_hit else 0.0)

    # Signal 2: Keyword overlap (0.40)
    hyp_kws = extract_keywords(hyp_text) | {normalize(k) for k in hyp.get("keywords", [])}
    gt_kws = extract_keywords(gt_text) | {normalize(k) for k in gt.get("keywords", [])}
    if hyp_kws and gt_kws:
        overlap = len(hyp_kws & gt_kws)
        union = len(hyp_kws | gt_kws)
        jaccard = overlap / union if union > 0 else 0
        explicit_hits = sum(1 for k in gt.get("keywords", []) if normalize(k) in normalize(hyp_text))
        boost = min(0.3, explicit_hits * 0.1)
        score += 0.40 * min(1.0, jaccard * 3 + boost)

    # Signal 3: Function name overlap (0.20)
    gt_funcs = {normalize(f) for f in gt.get("functions", [])}
    hyp_funcs = {normalize(f) for f in hyp.get("affected_functions", [])}
    hyp_text_norm = normalize(hyp_text)
    func_hit = bool(hyp_funcs & gt_funcs) or any(f in hyp_text_norm for f in gt_funcs)
    score += 0.20 * (1.0 if func_hit else 0.0)

    # Signal 4: Severity match (0.15)
    hyp_sev = hyp.get("severity", "").upper()
    gt_sev = gt.get("severity", "").upper()
    sev_match = hyp_sev == gt_sev
    sev_adjacent = (
        (hyp_sev in ("HIGH", "CRITICAL") and gt_sev in ("HIGH", "CRITICAL")) or
        (hyp_sev == "MEDIUM" and gt_sev == "MEDIUM")
    )
    score += 0.15 * (1.0 if sev_match else 0.7 if sev_adjacent else 0.3)

    return score


def cmd_score_hypotheses(benchmark_dir: Path, threshold: float):
    """
    Score hunter hypotheses against ground truth (detection capability mode).
    Does NOT require full pipeline — measures if hunters can detect the bugs.
    """
    bf = benchmark_dir / "benchmark.yaml"
    if not bf.exists():
        print(f"ERROR: {bf} not found")
        sys.exit(1)

    benchmark = load_benchmark(bf)
    contest = benchmark["contest"]
    protocol = benchmark_dir.name
    gt_findings = benchmark["findings"]

    print(f"\n{'='*60}")
    print(f"  HYPOTHESIS SCORING: {contest['name']}")
    print(f"  Mode: Detection capability (hunters only, no full pipeline)")
    print(f"{'='*60}")

    hypotheses = load_hypotheses(protocol)
    print(f"  Hypotheses loaded: {len(hypotheses)}")
    print(f"  Ground truth: {len(gt_findings)} findings")

    if not hypotheses:
        print(f"\n  ⚠ No hypotheses found for protocol '{protocol}'")
        sys.exit(1)

    # Match each GT finding to best hypothesis
    lines = []
    lines.append(f"# Benchmark Scorecard (Hypothesis Mode): {contest['name']}")
    lines.append(f"")
    lines.append(f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Mode**: Detection capability — hunter hypotheses vs ground truth")
    lines.append(f"**Platform**: {contest.get('platform', '?')}")
    lines.append(f"**Pool**: ${contest.get('pool_size', '?'):,}")
    lines.append(f"**Threshold**: {threshold}")
    lines.append(f"**Hypotheses**: {len(hypotheses)} total across all hunters")
    lines.append(f"")

    detected = 0
    missed = 0
    results_table = []

    for gt in gt_findings:
        best_score = 0.0
        best_hyps = []

        for hyp in hypotheses:
            sim = match_hypothesis_to_ground_truth(hyp, gt)
            if sim >= threshold:
                best_hyps.append((hyp, sim))
            if sim > best_score:
                best_score = sim

        best_hyps.sort(key=lambda x: -x[1])
        is_detected = best_score >= threshold

        if is_detected:
            detected += 1
        else:
            missed += 1

        results_table.append({
            "gt": gt,
            "best_score": best_score,
            "detected": is_detected,
            "best_hyps": best_hyps[:5],
            "n_matching_hyps": len(best_hyps),
        })

    total = len(gt_findings)
    recall = detected / total if total > 0 else 0

    lines.append(f"## Results Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Ground truth findings | {total} |")
    lines.append(f"| **Detected by hunters** | **{detected}/{total} ({recall:.0%})** |")
    lines.append(f"| Missed entirely | {missed} |")
    lines.append(f"| Total hypotheses | {len(hypotheses)} |")
    lines.append(f"")

    # By severity
    lines.append(f"## By Severity")
    lines.append(f"")
    lines.append(f"| Severity | Total | Detected | Missed | Recall |")
    lines.append(f"|----------|-------|----------|--------|--------|")
    for sev in ["HIGH", "MEDIUM"]:
        sev_results = [r for r in results_table if r["gt"].get("severity", "").upper() == sev]
        if not sev_results:
            continue
        sev_found = sum(1 for r in sev_results if r["detected"])
        sev_total = len(sev_results)
        sev_recall = sev_found / sev_total if sev_total > 0 else 0
        lines.append(f"| {sev} | {sev_total} | {sev_found} | {sev_total - sev_found} | {sev_recall:.0%} |")
    lines.append(f"")

    # By category
    lines.append(f"## By Category")
    lines.append(f"")
    lines.append(f"| Category | Total | Detected | Recall |")
    lines.append(f"|----------|-------|----------|--------|")
    cats = defaultdict(lambda: {"total": 0, "found": 0})
    for r in results_table:
        cat = r["gt"].get("category", "other")
        cats[cat]["total"] += 1
        if r["detected"]:
            cats[cat]["found"] += 1
    for cat, data in sorted(cats.items(), key=lambda x: -x[1]["total"]):
        cat_recall = data["found"] / data["total"] if data["total"] > 0 else 0
        lines.append(f"| {cat} | {data['total']} | {data['found']} | {cat_recall:.0%} |")
    lines.append(f"")

    # Detected findings detail
    lines.append(f"## Findings DETECTED")
    lines.append(f"")
    for r in results_table:
        if not r["detected"]:
            continue
        gt = r["gt"]
        lines.append(f"### ✓ {gt['id']} [{gt.get('severity')}] — {gt.get('title', '?')}")
        lines.append(f"**Best score**: {r['best_score']:.2f} | **Matching hyps**: {r['n_matching_hyps']}")
        for hyp, sim in r["best_hyps"][:3]:
            conf = hyp.get("confidence", "?")
            lines.append(f"- [{hyp.get('_hunter')}] {hyp.get('id', '?')} ({sim:.2f}, conf={conf}%): {hyp.get('title', '')[:80]}")
        lines.append(f"")

    # Missed findings detail (most important)
    lines.append(f"## Findings MISSED — Root Cause Analysis")
    lines.append(f"")
    for r in results_table:
        if r["detected"]:
            continue
        gt = r["gt"]
        lines.append(f"### ✗ {gt['id']} [{gt.get('severity')}] — {gt.get('title', '?')}")
        lines.append(f"**Category**: {gt.get('category', '?')} | **Best score**: {r['best_score']:.2f}")
        lines.append(f"**Contracts**: {', '.join(gt.get('contracts', []))} | **Functions**: {', '.join(gt.get('functions', []))}")
        lines.append(f"")
        lines.append(f"> {gt.get('description', '').strip()[:400]}")
        lines.append(f"")
        diagnosis = _diagnose_miss(gt, hypotheses)
        lines.append(f"**Diagnosis**: {diagnosis}")
        if r["best_hyps"]:
            lines.append(f"**Closest hypothesis** ({r['best_score']:.2f}):")
            hyp = r["best_hyps"][0][0]
            lines.append(f"  [{hyp.get('_hunter')}] {hyp.get('id', '?')}: {hyp.get('title', '')[:100]}")
        lines.append(f"")

    # Per-hunter contribution
    lines.append(f"## Hunter Contribution Analysis")
    lines.append(f"")
    hunter_stats = defaultdict(lambda: {"total": 0, "unique_detections": set()})
    for hyp in hypotheses:
        hunter = hyp.get("_hunter", "unknown")
        hunter_stats[hunter]["total"] += 1

    for r in results_table:
        if not r["detected"]:
            continue
        gt_id = r["gt"]["id"]
        # Which hunters contributed to detecting this?
        hunters_for_this = set()
        for hyp, sim in r["best_hyps"]:
            hunters_for_this.add(hyp.get("_hunter", "unknown"))
        for h in hunters_for_this:
            hunter_stats[h]["unique_detections"].add(gt_id)

    lines.append(f"| Hunter | Hypotheses | Findings Contributed To | Detection Rate |")
    lines.append(f"|--------|-----------|------------------------|----------------|")
    for hunter, stats in sorted(hunter_stats.items(), key=lambda x: -len(x[1]["unique_detections"])):
        n_det = len(stats["unique_detections"])
        rate = n_det / total if total > 0 else 0
        det_ids = ", ".join(sorted(stats["unique_detections"])) if stats["unique_detections"] else "—"
        lines.append(f"| {hunter} | {stats['total']} | {n_det} ({det_ids}) | {rate:.0%} |")
    lines.append(f"")

    scorecard_text = "\n".join(lines)

    # Save
    output = benchmark_dir / "scorecard_hypotheses.md"
    output.write_text(scorecard_text)

    # Save JSON
    match_json = benchmark_dir / "match_results_hypotheses.json"
    serializable = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": protocol,
        "mode": "hypotheses",
        "threshold": threshold,
        "ground_truth": total,
        "detected": detected,
        "missed": missed,
        "recall": round(recall, 3),
        "hypotheses_total": len(hypotheses),
        "per_finding": [
            {
                "id": r["gt"]["id"],
                "severity": r["gt"].get("severity"),
                "category": r["gt"].get("category"),
                "detected": r["detected"],
                "best_score": round(r["best_score"], 3),
                "n_matching_hyps": r["n_matching_hyps"],
                "best_hunter": r["best_hyps"][0][0].get("_hunter") if r["best_hyps"] else None,
            }
            for r in results_table
        ],
    }
    match_json.write_text(json.dumps(serializable, indent=2))

    # Print summary
    print(f"\n{'='*50}")
    print(f"  DETECTION RECALL: {detected}/{total} ({recall:.0%})")
    print(f"  Hypotheses: {len(hypotheses)}")
    print(f"{'='*50}")

    if missed > 0:
        print(f"\n  MISSED ({missed}):")
        for r in results_table:
            if not r["detected"]:
                gt = r["gt"]
                print(f"    [{gt.get('severity', '?')}] {gt['id']}: {gt.get('title', '')[:60]} (best={r['best_score']:.2f})")

    print(f"\n  Scorecard: {output}")


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark scorer — compara findings reportados contra contests públicos"
    )
    parser.add_argument("--setup", type=Path, help="Clone repo at scope commit (path to benchmark.yaml)")
    parser.add_argument("--score", type=Path, help="Score findings (path to benchmark directory)")
    parser.add_argument("--score-hypotheses", type=Path,
                       help="Score hunter hypotheses against ground truth (detection mode)")
    parser.add_argument("--list", action="store_true", help="List available benchmarks")
    parser.add_argument("--threshold", type=float, default=0.35,
                       help="Similarity threshold for matching (default: 0.35)")
    args = parser.parse_args()

    if args.list:
        cmd_list()
    elif args.setup:
        cmd_setup(args.setup)
    elif args.score:
        cmd_score(args.score, args.threshold)
    elif args.score_hypotheses:
        cmd_score_hypotheses(args.score_hypotheses, args.threshold)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
