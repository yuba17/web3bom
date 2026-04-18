#!/usr/bin/env python3
"""
Benchmark scoring: compares hunter hypotheses against ground truth findings.

Modes:
  Hypothesis mode (default): semantic matching of all hunter YAML hypotheses vs ground truth.
  Confirmed mode (--findings-json): only PoC-confirmed findings vs ground truth — the REAL score.

Usage:
    # All hypotheses (inflated — includes unverified)
    python3 audit-agents/benchmark_score.py \
        --ground-truth benchmarks/yieldoor/benchmark.yaml \
        --hypotheses-dir hunt_session/hypotheses/yieldoor

    # PoC-confirmed only (realistic score)
    python3 audit-agents/benchmark_score.py \
        --ground-truth benchmarks/yieldoor/benchmark.yaml \
        --findings-json benchmarks/yieldoor/bench_session/findings_all.json
"""

import argparse
import json
import yaml
import re
from pathlib import Path
from collections import defaultdict


def load_ground_truth(path: str) -> list[dict]:
    """Load ground truth findings from benchmark YAML."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("findings", [])


def load_confirmed_findings(findings_json_path: str) -> list[dict]:
    """Load only PoC-confirmed (or fuzz-confirmed) findings from findings_all.json.
    Returns them in hypothesis format so match_finding() can reuse them."""
    with open(findings_json_path) as f:
        data = json.load(f)
    confirmed = []
    for finding in data.get("findings", []):
        if not (finding.get("poc_passed") or finding.get("fuzz_confirmed")):
            continue
        # If RedTeam verdict is available, filter out DO_NOT_REPORT findings
        redteam_verdict = finding.get("redteam_verdict", "")
        if redteam_verdict == "DO_NOT_REPORT":
            continue
        confirmed.append({
                "id": finding.get("id", ""),
                "title": finding.get("title", ""),
                "description": finding.get("title", ""),  # title IS the description
                "confidence": finding.get("confidence", 80),
                "severity": finding.get("severity", ""),
                "_component": finding.get("component", ""),
                "_hunter": f"[PoC-confirmed] {finding.get('component','')}",
                "_source_file": f"findings_all.json",
            })
    return confirmed


def load_hypotheses(hyp_dir: str) -> list[dict]:
    """Load all hunter hypotheses from YAML files."""
    hyp_path = Path(hyp_dir)
    all_hypotheses = []

    for yaml_file in sorted(hyp_path.glob("hyp_*.yaml")):
        try:
            with open(yaml_file) as f:
                content = yaml.safe_load(f)
            if not content:
                continue

            hunter = content.get("hunter", yaml_file.stem)
            component = content.get("component", "")
            invariants = content.get("invariants", content.get("findings", content.get("hypotheses", [])))

            if not invariants:
                continue

            for inv in invariants:
                if not isinstance(inv, dict):
                    continue
                inv["_source_file"] = yaml_file.name
                inv["_hunter"] = hunter
                inv["_component"] = component
                all_hypotheses.append(inv)
        except yaml.YAMLError:
            # Try grep-based extraction for malformed YAML
            text = yaml_file.read_text()
            # Count findings roughly
            ids = re.findall(r'id:\s*(\S+)', text)
            for fid in ids:
                all_hypotheses.append({
                    "id": fid,
                    "_source_file": yaml_file.name,
                    "_hunter": yaml_file.stem,
                    "_component": "",
                    "title": "(extracted from malformed YAML)",
                    "confidence": 50,
                })

    return all_hypotheses


def match_finding(finding: dict, hypotheses: list[dict]) -> tuple[str, list[dict]]:
    """
    Match a ground truth finding against hypotheses.

    Returns: (status, matching_hypotheses)
    - status: "DETECTED", "PARTIAL", "MISSED"
    """
    f_contracts = [c.lower().replace(".sol", "") for c in finding.get("contracts", [])]
    f_functions = [fn.lower() for fn in finding.get("functions", [])]
    f_keywords = [kw.lower() for kw in finding.get("keywords", [])]
    f_title = finding.get("title", "").lower()
    f_description = finding.get("description", "").lower()
    f_category = finding.get("category", "").lower()

    matches = []
    partial_matches = []

    for hyp in hypotheses:
        confidence = hyp.get("confidence", 0)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence.replace("%", ""))
            except:
                confidence = 50
        if confidence < 40:
            continue

        h_title = str(hyp.get("title", "")).lower()
        h_desc = str(hyp.get("description", "")).lower()
        h_attack = str(hyp.get("attack_scenario", "")).lower()
        h_component = str(hyp.get("_component", "")).lower()
        h_all_text = f"{h_title} {h_desc} {h_attack}"

        # Contract match
        contract_match = False
        for c in f_contracts:
            if c in h_component or c in h_all_text:
                contract_match = True
                break

        if not contract_match:
            continue

        # Function match
        function_match = False
        for fn in f_functions:
            if fn in h_all_text:
                function_match = True
                break

        # Keyword match (at least 2 keywords)
        keyword_hits = sum(1 for kw in f_keywords if kw in h_all_text)

        # Scoring
        score = 0
        if function_match:
            score += 3
        if keyword_hits >= 3:
            score += 3
        elif keyword_hits >= 2:
            score += 2
        elif keyword_hits >= 1:
            score += 1

        # Title similarity (check key phrases)
        title_words = set(f_title.split())
        h_title_words = set(h_title.split())
        title_overlap = len(title_words & h_title_words)
        if title_overlap >= 3:
            score += 2

        if score >= 4 and confidence >= 60:
            matches.append(hyp)
        elif score >= 2:
            partial_matches.append(hyp)

    if matches:
        return "DETECTED", matches
    elif partial_matches:
        return "PARTIAL", partial_matches
    else:
        return "MISSED", []


def score_benchmark(ground_truth_path: str, hypotheses_dir: str = None,
                    components: list[str] = None, preloaded_hypotheses: list[dict] = None,
                    mode_label: str = "hypotheses"):
    """Run full benchmark scoring. If components given, filter both findings and hypotheses."""
    findings = load_ground_truth(ground_truth_path)
    if preloaded_hypotheses is not None:
        hypotheses = preloaded_hypotheses
    else:
        hypotheses = load_hypotheses(hypotheses_dir)

    if components:
        # Filter hypotheses to only those from specified components
        comp_set = {c.lower() for c in components}
        hypotheses = [h for h in hypotheses
                      if any(c in h.get("_source_file", "").lower() for c in comp_set)]
        # Filter findings to only those whose contracts match specified components
        findings = [f for f in findings
                    if any(c.lower().replace(".sol", "") in (comp.lower().replace(".sol", ""))
                           for c in components
                           for comp in f.get("contracts", []))]
        print(f"  Filtered to components: {', '.join(components)}")
        print(f"  Findings in scope: {len(findings)}, Hypotheses in scope: {len(hypotheses)}")

    print(f"\n{'='*70}")
    print(f"  BENCHMARK SCORING ({mode_label})")
    print(f"  Ground truth: {len(findings)} findings")
    print(f"  {'Confirmed findings' if preloaded_hypotheses is not None else 'Hypotheses'} loaded: {len(hypotheses)}")
    print(f"{'='*70}\n")

    results = []
    detected = 0
    partial = 0
    missed = 0
    detected_high = 0
    detected_medium = 0
    total_high = 0
    total_medium = 0

    for f in findings:
        severity = f.get("severity", "MEDIUM")
        if severity == "HIGH":
            total_high += 1
        else:
            total_medium += 1

        status, matches = match_finding(f, hypotheses)

        if status == "DETECTED":
            detected += 1
            if severity == "HIGH":
                detected_high += 1
            else:
                detected_medium += 1
        elif status == "PARTIAL":
            partial += 1
        else:
            missed += 1

        # Print result
        icon = {"DETECTED": "✅", "PARTIAL": "⚠️", "MISSED": "❌"}[status]
        print(f"  {icon} {f['id']} ({severity}) — {status}")
        print(f"     {f['title'][:80]}")
        if matches:
            hunters = set(m.get("_hunter", "?") for m in matches[:5])
            confs = [m.get("confidence", "?") for m in matches[:5]]
            print(f"     Matched by: {', '.join(hunters)} (confidence: {confs})")
        print()

        results.append({
            "id": f["id"],
            "severity": severity,
            "status": status,
            "match_count": len(matches),
        })

    # Summary
    total = len(findings)
    recall_strict = detected / total if total else 0
    recall_weighted = (detected + partial * 0.5) / total if total else 0
    recall_high = detected_high / total_high if total_high else 0
    recall_medium = detected_medium / total_medium if total_medium else 0

    print(f"\n{'='*70}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"  Total findings:     {total}")
    print(f"  Detected:           {detected} ({detected/total*100:.0f}%)")
    print(f"  Partial:            {partial} ({partial/total*100:.0f}%)")
    print(f"  Missed:             {missed} ({missed/total*100:.0f}%)")
    print(f"")
    print(f"  Recall (strict):    {recall_strict:.1%}")
    print(f"  Recall (weighted):  {recall_weighted:.1%}")
    print(f"  Recall HIGH:        {recall_high:.1%} ({detected_high}/{total_high})")
    print(f"  Recall MEDIUM:      {recall_medium:.1%} ({detected_medium}/{total_medium})")
    print(f"")
    label = "Confirmed findings" if preloaded_hypotheses is not None else "Total hypotheses"
    print(f"  {label}:   {len(hypotheses)}")
    print(f"{'='*70}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark scoring for hunting system")
    parser.add_argument("--ground-truth", "-g", required=True, help="Path to benchmark.yaml")
    parser.add_argument("--hypotheses-dir", "-d", help="Directory with hyp_*.yaml files (hypothesis mode)")
    parser.add_argument("--findings-json", "-f", help="Path to findings_all.json (confirmed-only mode — realistic score)")
    parser.add_argument("--components", "-c", help="Comma-separated components to filter (e.g. Strategy,Vault)")
    args = parser.parse_args()

    if not args.hypotheses_dir and not args.findings_json:
        parser.error("One of --hypotheses-dir or --findings-json is required")

    comps = [c.strip() for c in args.components.split(",")] if args.components else None

    if args.findings_json:
        # Confirmed-only mode: realistic score
        confirmed = load_confirmed_findings(args.findings_json)
        print(f"\n{'='*70}")
        print(f"  BENCHMARK SCORING — PoC-CONFIRMED FINDINGS ONLY (realistic)")
        print(f"  Source: {args.findings_json}")
        print(f"  Confirmed findings: {len(confirmed)}")
        print(f"{'='*70}\n")
        if not confirmed:
            print("  ⚠ No PoC-confirmed findings found. Run the benchmark first.")
            print("  Fields needed: poc_passed=true OR fuzz_confirmed=true in findings_all.json")
        else:
            score_benchmark(args.ground_truth, hypotheses_dir=None,
                            components=comps, preloaded_hypotheses=confirmed,
                            mode_label="PoC-confirmed")
    else:
        score_benchmark(args.ground_truth, args.hypotheses_dir, components=comps)
