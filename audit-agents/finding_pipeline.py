"""finding_pipeline.py — Pure functions for the finding dedup/verify/funnel pipeline.

Extracted from run_benchmark.py for reuse by both run_benchmark.py and plan_generator.py.
All functions are side-effect-free (no logging, no globals, no file I/O beyond YAML parsing).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

POC_CONFIDENCE_THRESHOLD = 65  # min confidence to attempt PoC


# ─── Fingerprinting & Deduplication ───────────────────────────────────────────

def extract_fingerprint(finding: dict) -> set[str]:
    """Extract mentioned fn names, line numbers, and camelCase vars as tokens."""
    text = f"{finding.get('root_cause', '')} {finding.get('title', '')}".lower()
    tokens: set[str] = set()
    # Extract function names: word followed by ()
    for m in re.finditer(r'(\w+)\s*\(', text):
        fn = m.group(1)
        if fn not in ('line', 'function', 'returns', 'require', 'assert',
                      'if', 'for', 'while', 'emit', 'revert', 'error'):
            tokens.add(f"fn:{fn}")
    # Extract line numbers
    for m in re.finditer(r'(?:line|l\.?|:)\s*(\d{2,4})', text):
        tokens.add(f"line:{m.group(1)}")
    # Extract key variable names (camelCase identifiers)
    for m in re.finditer(r'\b([a-z]+[A-Z]\w+)\b',
                         f"{finding.get('root_cause', '')} {finding.get('title', '')}"):
        tokens.add(f"var:{m.group(1).lower()}")
    return tokens


def dedup_findings(findings_list: list[dict]) -> list[list[dict]]:
    """Group findings by root cause fingerprint (Jaccard > 0.4 or fn_match).

    Returns list of groups, each sorted by confidence desc.
    Tags each finding with _dedup_group, _dedup_rank, _dedup_group_size.
    Groups sorted by (convergence, confidence) desc.
    """
    groups: list[list[dict]] = []
    group_fps: list[set[str]] = []

    for f in findings_list:
        fp = extract_fingerprint(f)
        if not fp:
            groups.append([f])
            group_fps.append(fp)
            continue

        merged = False
        for i, group in enumerate(groups):
            gfp = group_fps[i]
            if not gfp:
                continue
            # Jaccard similarity on extracted tokens
            intersection = fp & gfp
            union = fp | gfp
            jaccard = len(intersection) / len(union) if union else 0
            # Function + variable overlap: 1 shared function AND >= 2 non-function tokens
            fn_overlap = {t for t in intersection if t.startswith("fn:")}
            non_fn_overlap = {t for t in intersection if not t.startswith("fn:")}
            fn_match = len(fn_overlap) >= 1 and len(non_fn_overlap) >= 2
            if jaccard > 0.4 or fn_match:
                group.append(f)
                group_fps[i] = gfp | fp  # expand group fingerprint
                merged = True
                break
        if not merged:
            groups.append([f])
            group_fps.append(fp)

    # Sort each group by confidence desc
    for g in groups:
        g.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    # Tag findings with their group info
    deduped: list[list[dict]] = []
    for i, group in enumerate(groups):
        for rank, f in enumerate(group):
            f["_dedup_group"] = i
            f["_dedup_rank"] = rank
            f["_dedup_group_size"] = len(group)
        deduped.append(group)

    # Sort groups by convergence-weighted score
    def _group_score(g):
        convergence = len(g)
        confidence = g[0].get("confidence", 0)
        return (convergence, confidence)
    deduped.sort(key=_group_score, reverse=True)

    return deduped


def collect_verify_candidates(groups: list[list[dict]],
                              threshold: int = 65) -> list[dict]:
    """All findings above threshold, deduped by ID."""
    seen_ids: set[str] = set()
    candidates = []
    for group in groups:
        for f in group:
            if not (f.get("fuzz_confirmed") or f.get("confidence", 0) >= threshold):
                continue
            fid = f.get("id", "")
            if fid in seen_ids:
                continue
            seen_ids.add(fid)
            candidates.append(f)
    return sorted(candidates, key=lambda x: x.get("confidence", 0), reverse=True)


def dedup_for_poc(verified: list[dict]) -> list[dict]:
    """One representative per dedup group (highest confidence)."""
    best_per_group: dict = {}  # group_id -> finding
    ungrouped = []
    for f in verified:
        gid = f.get("_dedup_group")
        if gid is None:
            ungrouped.append(f)
            continue
        rank = f.get("_dedup_rank", 0)
        existing = best_per_group.get(gid)
        if existing is None or rank < existing.get("_dedup_rank", 999):
            best_per_group[gid] = f
    result = list(best_per_group.values()) + ungrouped
    result.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    return result


def identify_fallbacks(groups: list[list[dict]]) -> list[dict]:
    """Capa 2: when leader fails PoC, promote best verified sibling.

    Returns list of fallback findings (one per group whose leader failed).
    """
    fallbacks: list[dict] = []
    for g in groups:
        if len(g) > 1 and not g[0].get("has_poc"):
            for sib in g[1:]:
                if sib.get("_verified") or sib.get("fuzz_confirmed"):
                    sib["_capa2_fallback"] = True
                    fallbacks.append(sib)
                    break  # only the best sibling per group
    return fallbacks


def identify_escaped_siblings(groups: list[list[dict]]) -> list[tuple[dict, dict]]:
    """Capa 3: (leader, sibling) pairs for is_same_bug check.

    For groups whose leader passed PoC, collect verified siblings
    that need a dedup confirmation check.
    """
    pairs: list[tuple[dict, dict]] = []
    for g in groups:
        if len(g) > 1 and g[0].get("has_poc"):
            for sib in g[1:]:
                if sib.get("_verified") or sib.get("fuzz_confirmed"):
                    pairs.append((g[0], sib))
    return pairs


# ─── YAML Extraction ─────────────────────────────────────────────────────────

def extract_findings_from_yaml(hyp_dir: Path, component: str,
                               fuzz_failures: dict = None) -> list[dict]:
    """Parse hypothesis YAMLs, correlate with fuzz failures.

    Two tiers:
    - CONFIRMED: hypothesis whose solidity_property function name matches a fuzz failure
    - UNCONFIRMED: high-confidence hypothesis without fuzz proof (lower priority)

    fuzz_failures: dict mapping function name -> counterexample trace
    """
    import yaml

    confirmed = []
    unconfirmed = []
    seen_ids: set[str] = set()

    fuzz_failures = fuzz_failures or {}

    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        if "CrossChain" in hyp_file.name:
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            if not data:
                continue
            hypotheses = data.get("hypotheses", data.get("invariants", data.get("findings", [])))
            for hyp in hypotheses:
                fid = hyp.get("id", "UNKNOWN")
                if fid in seen_ids:
                    continue

                tier = hyp.get("tier", 3)
                confidence = hyp.get("confidence", 0)

                # Map tier -> severity (hunters use tier, not severity)
                severity = hyp.get("severity", "")
                if not severity:
                    severity = {1: "High", 2: "Medium"}.get(tier, "Low")
                if severity not in ("High", "Medium", "Critical"):
                    continue
                validated = hyp.get("validated", False)

                # Check if this hypothesis has a matching fuzz failure
                sol_prop = hyp.get("solidity_property", hyp.get("solidity", ""))
                prop_name = ""
                if sol_prop:
                    match = re.search(
                        r'function\s+(invariant_\w+|check_\w+|echidna_\w+|property_\w+)',
                        sol_prop
                    )
                    if match:
                        prop_name = match.group(1)

                fuzz_confirmed = prop_name in fuzz_failures if prop_name else False
                counterexample_trace = fuzz_failures.get(prop_name, "") if prop_name else ""

                # Derive hunter name from filename: hyp_Strategy_MathHunter.yaml -> "MathHunter"
                _stem_parts = hyp_file.stem.split("_", 2)
                _hunter_name = _stem_parts[2] if len(_stem_parts) >= 3 else hyp_file.stem

                finding = {
                    "id": fid,
                    "title": hyp.get("title", hyp.get("description", "")),
                    "severity": severity,
                    "confidence": confidence,
                    "root_cause": hyp.get("root_cause", hyp.get("attack_scenario", "")),
                    "source_file": hyp_file.name,
                    "hunter": _hunter_name,
                    "fuzz_confirmed": fuzz_confirmed,
                    "property_name": prop_name,
                    "counterexample_trace": counterexample_trace,
                    "vulnerable_location": hyp.get("vulnerable_location"),
                }

                if fuzz_confirmed:
                    confirmed.append(finding)
                elif (validated and confidence >= 60) or tier == 1:
                    unconfirmed.append(finding)

                seen_ids.add(fid)
        except Exception:
            continue

    # Orphan fuzz failures: a broken invariant with no owning hypothesis.
    # Happens when the invariant comes from the generic registry (matcher.py)
    # or from merge/DeepDive injection — not from a per-hunter hyp_*.yaml.
    # Without this block, a real fuzzer-proven bug would be silently dropped.
    matched_props = {f["property_name"] for f in confirmed if f.get("property_name")}
    for prop_name, trace in fuzz_failures.items():
        if prop_name in matched_props:
            continue
        synth_id = f"FUZZ-{component}-{prop_name}"
        if synth_id in seen_ids:
            continue
        confirmed.append({
            "id": synth_id,
            "title": f"Fuzzer broke invariant {prop_name}",
            "severity": "Medium",
            "confidence": 90,
            "root_cause": (
                f"Invariant `{prop_name}` violated by fuzz sequence. "
                f"No hunter hypothesis owned this property — likely from the "
                f"generic invariant registry or merge-time injection."
            ),
            "source_file": "",
            "hunter": "FuzzOrphan",
            "fuzz_confirmed": True,
            "property_name": prop_name,
            "counterexample_trace": trace,
            "vulnerable_location": None,
        })
        seen_ids.add(synth_id)

    unconfirmed.sort(key=lambda f: f.get("confidence", 0), reverse=True)

    # No artificial cap — dedup + verify filter by quality, not count
    return confirmed + unconfirmed


# ─── Code Extraction ─────────────────────────────────────────────────────────

def extract_relevant_code(source_code: str, library_code: str,
                          finding: dict) -> str:
    """Extract focused code sections relevant to a finding.

    Provides the exact functions + line ranges mentioned, rather than
    the full contract.
    """
    all_source = source_code + "\n\n" + (library_code or "")

    # Step 1: Extract function names + line numbers from finding fields
    finding_text = " ".join([
        finding.get("title", ""),
        finding.get("root_cause", ""),
        finding.get("description", ""),
        finding.get("attack_scenario", ""),
    ])
    vuln_loc = finding.get("vulnerable_location") or {}
    if vuln_loc.get("function"):
        finding_text += " " + vuln_loc["function"] + "("
    if vuln_loc.get("vulnerable_code"):
        finding_text += " " + vuln_loc["vulnerable_code"]

    SKIP_WORDS = {
        "if", "for", "while", "require", "assert", "emit", "revert", "return",
        "new", "delete", "type", "uint256", "uint128", "uint64", "int256",
        "address", "bytes", "bytes32", "string", "bool", "mapping", "memory",
        "storage", "calldata", "public", "private", "external", "internal",
        "view", "pure", "override", "virtual", "immutable", "constant",
        "function", "event", "modifier", "struct", "error", "interface",
        "contract", "library", "abstract", "constructor", "fallback", "receive",
    }

    fn_names = []
    seen_fns: set[str] = set()
    for m in re.finditer(r'\b(\w+)\s*\(', finding_text):
        fn = m.group(1)
        if fn not in SKIP_WORDS and len(fn) > 2 and fn not in seen_fns:
            fn_names.append(fn)
            seen_fns.add(fn)

    # Explicit line numbers
    explicit_lines = []
    for m in re.finditer(r'(?:line|l\.?)\s*(\d{2,4})\b', finding_text, re.IGNORECASE):
        ln = int(m.group(1))
        if 1 <= ln <= 5000:
            explicit_lines.append(ln)
    if vuln_loc.get("lines"):
        raw = vuln_loc["lines"]
        if isinstance(raw, list):
            explicit_lines.extend([int(x) for x in raw if str(x).isdigit()])
        elif isinstance(raw, (int, str)):
            try:
                explicit_lines.append(int(str(raw).split("-")[0]))
            except ValueError:
                pass

    sections = []
    used_ranges: list[tuple[int, int]] = []

    source_lines = all_source.splitlines()

    def _add_range(start_ln: int, end_ln: int, label: str = ""):
        """Add a line range to sections, avoiding duplicates."""
        for used_s, used_e in used_ranges:
            if start_ln <= used_e and end_ln >= used_s:
                return  # overlaps existing range
        used_ranges.append((start_ln, end_ln))
        snippet = "\n".join(
            f"{i+1:4d}: {l}"
            for i, l in enumerate(source_lines[start_ln:end_ln], start_ln)
        )
        if label:
            sections.append(f"// === {label} ===\n{snippet}")
        else:
            sections.append(snippet)

    # Step 2: Extract function bodies for each mentioned function
    for fn_name in fn_names[:6]:
        pattern = re.compile(
            r'^\s*(?:function\s+' + re.escape(fn_name) + r'\b)',
            re.MULTILINE
        )
        for match in pattern.finditer(all_source):
            fn_start_char = match.start()
            brace_pos = all_source.find('{', fn_start_char)
            if brace_pos == -1 or brace_pos - fn_start_char > 500:
                continue
            depth = 0
            end_char = brace_pos
            for i, ch in enumerate(all_source[brace_pos:], brace_pos):
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end_char = i + 1
                        break
            start_ln = all_source[:fn_start_char].count('\n')
            end_ln = all_source[:end_char].count('\n') + 1
            if end_ln - start_ln > 150:
                end_ln = start_ln + 150
            _add_range(start_ln, end_ln, f"function {fn_name}")
            break  # only first definition

    # Step 3: Add +/-30 lines around specific line numbers
    for ln in explicit_lines[:5]:
        start_ln = max(0, ln - 30)
        end_ln = min(len(source_lines), ln + 30)
        _add_range(start_ln, end_ln, f"context around line {ln}")

    if not sections:
        return source_code[:8000]

    result = "\n\n".join(sections)
    if len(result) > 8000:
        result = result[:8000] + "\n// ... (truncated)"
    return result


# ─── Prompt Builders ─────────────────────────────────────────────────────────

def build_verify_prompt(finding: dict, relevant_code: str) -> str:
    """Build the quick verification prompt for a finding."""
    vuln_loc = finding.get("vulnerable_location") or {}
    vuln_section = ""
    if vuln_loc:
        vuln_section = (
            f"Hunter's claimed location:\n"
            f"  Function: {vuln_loc.get('function', 'N/A')}\n"
            f"  Lines: {vuln_loc.get('lines', 'N/A')}\n"
            f"  Wrong code: `{vuln_loc.get('vulnerable_code', 'N/A')}`\n"
            f"  Fix: {vuln_loc.get('fix', 'N/A')}\n"
        )
    return (
        f"You are a senior smart contract auditor doing a QUICK VERIFICATION of a bug report.\n"
        f"Read the code and determine — with adversarial skepticism — if this is a REAL bug.\n\n"
        f"## Hypothesis\n"
        f"Title: {finding.get('title', finding.get('id', '?'))}\n"
        f"Root Cause: {finding.get('root_cause', '')}\n"
        f"Confidence reported by hunter: {finding.get('confidence', 0)}%\n"
        f"{vuln_section}\n"
        f"## Source Code (focused on the vulnerable area)\n"
        f"```solidity\n{relevant_code}\n```\n\n"
        f"## Verification Checklist (check ALL before deciding)\n"
        f"1. Can you find the EXACT code expression that's wrong in the source above?\n"
        f"2. Is there a require/modifier/check that already prevents exploitation?\n"
        f"3. Does exploitation require a privileged caller (owner/admin/governance)? → FALSE_POSITIVE\n"
        f"4. Is the 'wrong' behavior actually documented / intentional by design?\n"
        f"5. Is there real economic impact (fund loss / DoS / access bypass)?\n\n"
        f"## Output (EXACTLY this format, nothing else)\n"
        f"VERDICT: REAL\n"
        f"REASON: <one sentence — the exact wrong expression and why it causes harm>\n"
        f"POC_HINT: <one sentence — simplest way to trigger it in a fork test>\n\n"
        f"OR:\n\n"
        f"VERDICT: FALSE_POSITIVE\n"
        f"REASON: <one sentence — what check/design prevents exploitation>\n"
        f"POC_HINT: N/A"
    )


def build_is_same_bug_prompt(leader: dict, sibling: dict) -> str:
    """Build the dedup check prompt for two findings."""
    return (
        f"You are deduplicating smart contract audit findings.\n"
        f"Determine if Finding B is the SAME bug as Finding A, or a genuinely DIFFERENT bug.\n\n"
        f"## Finding A (PoC-confirmed)\n"
        f"Title: {leader['title']}\n"
        f"Root Cause: {leader.get('root_cause', 'N/A')}\n\n"
        f"## Finding B (needs evaluation)\n"
        f"Title: {sibling['title']}\n"
        f"Root Cause: {sibling.get('root_cause', 'N/A')}\n\n"
        f"## The ONE test that matters\n"
        f"Would a single code patch that fixes Finding A ALSO fix Finding B?\n"
        f"If yes → SAME. If no (requires a separate code change) → DIFFERENT.\n\n"
        f"## SAME examples (different wording, same fix)\n"
        f"- A: 'pullFunds does not decrement underlyingBalance'\n"
        f"  B: 'pushFunds does not increment underlyingBalance'\n"
        f"  → SAME if both fix the same missing balance update in the same function family\n"
        f"- A: 'collectFees uses wrong tickUpper for vesting position (line 167)'\n"
        f"  B: 'collectPositionFees called with mainPosition.tickUpper instead of vestPosition.tickUpper'\n"
        f"  → SAME — identical line, identical fix\n"
        f"- A: 'DoS via uninitialized observation in checkPoolActivity'\n"
        f"  B: 'checkPoolActivity reverts when observation[0] is uninitialized'\n"
        f"  → SAME — same function, same trigger, same fix\n\n"
        f"## DIFFERENT examples (genuinely separate bugs)\n"
        f"- A: 'pullFunds does not check frozen reserve'\n"
        f"  B: 'borrow() allows borrowing above utilization cap'\n"
        f"  → DIFFERENT — different checks, different fixes\n"
        f"- A: 'collectFees tick mismatch (line 167)'\n"
        f"  B: 'balances() excludes vesting position liquidity'\n"
        f"  → DIFFERENT — different functions, different fixes\n\n"
        f"## Output — EXACTLY one of these two lines, nothing else:\n"
        f"SAME\n"
        f"DIFFERENT: <one sentence — what separate code change Finding B requires>"
    )


# ─── Pipeline Funnel Dashboard ───────────────────────────────────────────────

def format_funnel(component: str, n_hypotheses: int, n_verified: int,
                  n_poc_in: int, n_poc_out: int, n_redteam: int) -> str:
    """Return a formatted pipeline funnel dashboard string."""
    def _pct(a, b):
        return f"{a/b*100:.0f}%" if b else "—"

    lines = [
        f"  {'─'*52}",
        f"  PIPELINE FUNNEL — {component}",
        f"  {'─'*52}",
        f"  Hypotheses generated:  {n_hypotheses:>4}",
    ]
    if n_verified:
        lines.append(f"  Post-verification:     {n_verified:>4}  ({_pct(n_verified, n_hypotheses)} pass)")
    if n_poc_in:
        lines.append(f"  Post-dedup (PoC in):   {n_poc_in:>4}  ({_pct(n_poc_in, n_verified or n_hypotheses)} of verified)")
    if n_poc_out:
        lines.append(f"  PoC confirmed:         {n_poc_out:>4}  ({_pct(n_poc_out, n_poc_in)} pass)")
    if n_redteam:
        lines.append(f"  RedTeam REPORT:        {n_redteam:>4}  ({_pct(n_redteam, n_poc_out)} of PoC)")
    lines.append(f"  {'─'*52}")

    return "\n".join(lines)


# ─── CLI Phase Interface ────────────────────────────────────────────────────

POC_PARALLEL = 2  # max parallel PoC agents per batch


def _ensure_triage_dir(session_dir: str) -> Path:
    """Create and return the triage subdirectory."""
    d = Path(session_dir) / "triage"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _read_source_for_component(repo: str, component: str, lang: str) -> tuple[str, str]:
    """Read source + library code for a component.

    Tries multiple path patterns:
    1. repo/src/Component.sol
    2. repo/src/**/Component.sol (glob)
    3. repo/*/src/Component.sol (nested repos like monorepos)

    Returns (source, library) where library is all other .sol files in the same dir.
    """
    ext = ".sol" if lang == "solidity" else ".rs"
    repo_path = Path(repo)
    source_file = None

    # Pattern 1: direct
    candidate = repo_path / "src" / f"{component}{ext}"
    if candidate.exists():
        source_file = candidate
    else:
        # Pattern 2: glob in repo
        matches = list(repo_path.glob(f"**/{component}{ext}"))
        # Exclude test/node_modules/out, files only
        matches = [m for m in matches if m.is_file()
                   and "test" not in m.parts
                   and "node_modules" not in m.parts
                   and "out" not in m.parts]
        if matches:
            source_file = matches[0]
        else:
            # Pattern 3: nested repo
            for sub in repo_path.iterdir():
                if sub.is_dir():
                    candidate = sub / "src" / f"{component}{ext}"
                    if candidate.exists():
                        source_file = candidate
                        break

    if not source_file or not source_file.exists():
        return ("", "")

    source = source_file.read_text(errors="replace")

    # Collect library code from same directory (other .sol files)
    lib_parts = []
    for sibling in source_file.parent.glob(f"*{ext}"):
        if sibling != source_file and sibling.stat().st_size < 50000:
            lib_parts.append(f"// === {sibling.name} ===\n" + sibling.read_text(errors="replace"))
    library = "\n\n".join(lib_parts[:5])  # limit to 5 library files

    return (source, library)


def _serialize_finding(f: dict) -> dict:
    """Strip None values from finding dict for clean JSON."""
    return {k: v for k, v in f.items() if v is not None}


def _parse_fuzz_failures(log_path: Path) -> dict:
    """Parse fuzz failures from Phase 1 log file. Returns {prop_name: trace}."""
    failures: dict[str, str] = {}
    if not log_path.exists():
        return failures
    try:
        text = log_path.read_text(errors="replace")
        # Match patterns like: [FAIL. Reason: ...] invariant_xxx()
        for m in re.finditer(
            r'\[FAIL[^\]]*\]\s*(invariant_\w+|check_\w+|echidna_\w+|property_\w+)',
            text
        ):
            prop_name = m.group(1)
            # Grab surrounding context as trace
            start = max(0, m.start() - 200)
            end = min(len(text), m.end() + 500)
            failures[prop_name] = text[start:end].strip()
    except Exception:
        pass
    return failures


def phase_dedup(component: str, protocol: str, session_dir: str,
                repo: str, threshold: int, lang: str) -> list[dict]:
    """Phase 1: Extract findings from YAMLs, dedup, emit verify agent steps."""
    steps: list[dict] = []
    hyp_dir = Path(session_dir) / "hypotheses" / protocol
    triage_dir = _ensure_triage_dir(session_dir)
    gen_cmd = f"{sys.executable} {Path(__file__).resolve()}"

    # Try to parse fuzz failures (optional)
    log_path = Path(session_dir) / "logs" / f"{component}_phase1.log"
    fuzz_failures = _parse_fuzz_failures(log_path)

    # Extract and dedup
    findings = extract_findings_from_yaml(hyp_dir, component, fuzz_failures)
    if not findings:
        # No findings — emit empty result
        (triage_dir / f"{component}_groups.json").write_text("[]")
        return steps

    groups = dedup_findings(findings)
    candidates = collect_verify_candidates(groups, threshold)

    # Save groups for later phases
    serializable_groups = [[_serialize_finding(f) for f in g] for g in groups]
    (triage_dir / f"{component}_groups.json").write_text(
        json.dumps(serializable_groups, indent=2)
    )

    # Read source code for verify prompts
    source, library = _read_source_for_component(repo, component, lang)

    # Emit verify agent steps
    for f in candidates:
        fid = f.get("id", "UNKNOWN")
        relevant_code = extract_relevant_code(source, library, f)
        prompt = build_verify_prompt(f, relevant_code)
        result_path = triage_dir / f"{component}_verify_{fid}.json"

        steps.append({
            "id": f"{component}:verify:{fid}",
            "type": "agent",
            "description": f"Verify {fid}: {f.get('title', '')[:60]}",
            "prompt": (
                f"{prompt}\n\n"
                f"After your analysis, write your result using the Write tool to:\n"
                f"{result_path}\n\n"
                f"JSON format: {{\"finding_id\": \"{fid}\", \"verdict\": \"REAL\" or \"FALSE_POSITIVE\", "
                f"\"reason\": \"...\", \"poc_hint\": \"...\"}}"
            ),
            "tools": ["Read", "Write", "Grep", "Glob"],
            "timeout": 120,
            "parallel_group": f"{component}:verify_batch",
        })

    # Final step: post-verify phase
    steps.append({
        "id": f"{component}:triage_post_verify",
        "type": "generate",
        "description": f"Post-verify triage for {component}",
        "command": (
            f"{gen_cmd} --phase post-verify "
            f"--component {component} --protocol {protocol} "
            f"--session-dir {session_dir} --repo {repo} --lang {lang}"
        ),
        "depends_on": [f"parallel_group:{component}:verify_batch"],
        "timeout": 60,
    })

    return steps


def phase_post_verify(component: str, protocol: str, session_dir: str,
                      repo: str, lang: str) -> list[dict]:
    """Phase 2: Read verify results, dedup for PoC, emit PoC agent steps."""
    steps: list[dict] = []
    triage_dir = Path(session_dir) / "triage"
    gen_cmd = f"{sys.executable} {Path(__file__).resolve()}"
    plan_gen_cmd = f"{sys.executable} {Path(__file__).resolve().parent / 'plan_generator.py'}"

    # Load groups
    groups_path = triage_dir / f"{component}_groups.json"
    if not groups_path.exists():
        return steps
    groups = json.loads(groups_path.read_text())

    # Read verify results — missing files = conservative REAL
    for group in groups:
        for f in group:
            fid = f.get("id", "UNKNOWN")
            verify_path = triage_dir / f"{component}_verify_{fid}.json"
            if verify_path.exists():
                try:
                    result = json.loads(verify_path.read_text())
                    verdict = result.get("verdict", "REAL").upper()
                    f["_verified"] = verdict == "REAL"
                    f["_verify_reason"] = result.get("reason", "")
                except Exception:
                    f["_verified"] = True  # conservative
            else:
                f["_verified"] = True  # conservative: missing = REAL

    # Filter verified findings
    verified = []
    for group in groups:
        for f in group:
            if f.get("_verified") or f.get("fuzz_confirmed"):
                verified.append(f)

    # Dedup for PoC
    poc_candidates = dedup_for_poc(verified)

    # Save state
    (triage_dir / f"{component}_poc_candidates.json").write_text(
        json.dumps([_serialize_finding(f) for f in poc_candidates], indent=2)
    )
    # Re-save groups with verified tags
    (triage_dir / f"{component}_groups.json").write_text(
        json.dumps([[_serialize_finding(f) for f in g] for g in groups], indent=2)
    )

    if not poc_candidates:
        return steps

    # Step 0: Create ForkSetup.sol (bash step)
    poc_dir = Path(repo) / "test" / "poc"
    steps.append({
        "id": f"{component}:create_fork_setup",
        "type": "bash",
        "description": f"Create test/poc directory for {component}",
        "command": f"mkdir -p {poc_dir}",
        "timeout": 10,
    })

    # Batch PoC steps
    batches = [poc_candidates[i:i + POC_PARALLEL]
               for i in range(0, len(poc_candidates), POC_PARALLEL)]
    prev_deps: list[str] = [f"{component}:create_fork_setup"]

    for batch_idx, batch in enumerate(batches):
        batch_ids: list[str] = []
        for f in batch:
            fid = f.get("id", "UNKNOWN")
            title = f.get("title", "N/A")[:80]

            # Generate step: build fork PoC prompt
            prompt_id = f"{component}:fork_poc_prompt:{fid}"
            steps.append({
                "id": prompt_id,
                "type": "generate",
                "description": f"Build Fork PoC prompt for {fid}",
                "command": (
                    f"{plan_gen_cmd} --phase fork-poc-prompt "
                    f"--component {component} --protocol {protocol} "
                    f"--repo {repo} --session-dir {session_dir} "
                    f"--finding-id {fid}"
                ),
                "depends_on": prev_deps[:],
                "parallel_group": f"{component}:poc_prompt_batch_{batch_idx}",
                "timeout": 60,
            })

            # Agent step: execute PoC
            poc_id = f"{component}:fork_poc:{fid}"
            batch_ids.append(poc_id)
            steps.append({
                "id": poc_id,
                "type": "agent",
                "description": f"Fork PoC for {fid}: {title}",
                "prompt": "__DYNAMIC__",
                "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
                "depends_on": [prompt_id],
                "parallel_group": f"{component}:poc_batch_{batch_idx}",
                "timeout": 600,
                "retry": 1,
            })

        prev_deps = batch_ids[:]

    # Final: post-poc phase
    steps.append({
        "id": f"{component}:triage_post_poc",
        "type": "generate",
        "description": f"Post-PoC triage for {component}",
        "command": (
            f"{gen_cmd} --phase post-poc "
            f"--component {component} --protocol {protocol} "
            f"--session-dir {session_dir} --repo {repo} --lang {lang}"
        ),
        "depends_on": prev_deps[:],
        "timeout": 60,
    })

    return steps


def phase_post_poc(component: str, protocol: str, session_dir: str,
                   repo: str, lang: str) -> list[dict]:
    """Phase 3: Read PoC results, emit Capa 2 fallbacks + Capa 3 is_same_bug."""
    steps: list[dict] = []
    triage_dir = Path(session_dir) / "triage"
    gen_cmd = f"{sys.executable} {Path(__file__).resolve()}"
    plan_gen_cmd = f"{sys.executable} {Path(__file__).resolve().parent / 'plan_generator.py'}"
    session_path = Path(session_dir)

    # Load groups
    groups_path = triage_dir / f"{component}_groups.json"
    if not groups_path.exists():
        return steps
    groups = json.loads(groups_path.read_text())

    # Read PoC results — mark has_poc on findings
    for group in groups:
        for f in group:
            fid = f.get("id", "UNKNOWN")
            poc_path = session_path / f"poc_{fid}.json"
            if poc_path.exists():
                try:
                    result = json.loads(poc_path.read_text())
                    f["has_poc"] = result.get("passed", result.get("success", False))
                except Exception:
                    f["has_poc"] = False
            else:
                f["has_poc"] = False

    # Capa 2: fallbacks
    fallbacks = identify_fallbacks(groups)

    # Capa 3: escaped siblings
    sibling_pairs = identify_escaped_siblings(groups)

    # Save state
    (triage_dir / f"{component}_capa23.json").write_text(json.dumps({
        "fallbacks": [_serialize_finding(f) for f in fallbacks],
        "sibling_pairs": [
            [_serialize_finding(l), _serialize_finding(s)]
            for l, s in sibling_pairs
        ],
    }, indent=2))

    # Re-save groups
    (triage_dir / f"{component}_groups.json").write_text(
        json.dumps([[_serialize_finding(f) for f in g] for g in groups], indent=2)
    )

    if not fallbacks and not sibling_pairs:
        # Skip directly to finalize
        steps.append({
            "id": f"{component}:triage_finalize",
            "type": "generate",
            "description": f"Finalize triage for {component}",
            "command": (
                f"{gen_cmd} --phase finalize "
                f"--component {component} --protocol {protocol} "
                f"--session-dir {session_dir} --repo {repo} --lang {lang}"
            ),
            "timeout": 60,
        })
        return steps

    # Capa 2: fallback PoC steps
    for f in fallbacks:
        fid = f.get("id", "UNKNOWN")
        title = f.get("title", "N/A")[:80]

        prompt_id = f"{component}:fallback_poc_prompt:{fid}"
        steps.append({
            "id": prompt_id,
            "type": "generate",
            "description": f"Build Capa 2 fallback PoC prompt for {fid}",
            "command": (
                f"{plan_gen_cmd} --phase fork-poc-prompt "
                f"--component {component} --protocol {protocol} "
                f"--repo {repo} --session-dir {session_dir} "
                f"--finding-id {fid}"
            ),
            "parallel_group": f"{component}:fallback_prompts",
            "timeout": 60,
        })

        steps.append({
            "id": f"{component}:fallback_poc:{fid}",
            "type": "agent",
            "description": f"Capa 2 fallback PoC for {fid}: {title}",
            "prompt": "__DYNAMIC__",
            "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            "depends_on": [prompt_id],
            "parallel_group": f"{component}:fallback_batch",
            "timeout": 600,
            "retry": 1,
        })

    # Capa 3: is_same_bug agent steps
    for leader, sibling in sibling_pairs:
        sid = sibling.get("id", "UNKNOWN")
        prompt = build_is_same_bug_prompt(leader, sibling)
        result_path = triage_dir / f"{component}_same_bug_{sid}.json"

        steps.append({
            "id": f"{component}:same_bug:{sid}",
            "type": "agent",
            "description": f"Capa 3 dedup check: {leader.get('id', '?')} vs {sid}",
            "prompt": (
                f"{prompt}\n\n"
                f"After your analysis, write your result using the Write tool to:\n"
                f"{result_path}\n\n"
                f"JSON format: {{\"leader_id\": \"{leader.get('id', '')}\", "
                f"\"sibling_id\": \"{sid}\", "
                f"\"verdict\": \"SAME\" or \"DIFFERENT\", \"reason\": \"...\"}}"
            ),
            "tools": ["Read", "Write", "Grep", "Glob"],
            "timeout": 120,
            "parallel_group": f"{component}:capa3_batch",
        })

    # Post capa23 step
    capa_deps: list[str] = []
    if fallbacks:
        capa_deps.append(f"parallel_group:{component}:fallback_batch")
    if sibling_pairs:
        capa_deps.append(f"parallel_group:{component}:capa3_batch")

    steps.append({
        "id": f"{component}:triage_post_capa23",
        "type": "generate",
        "description": f"Post Capa 2/3 triage for {component}",
        "command": (
            f"{gen_cmd} --phase post-capa23 "
            f"--component {component} --protocol {protocol} "
            f"--session-dir {session_dir} --repo {repo} --lang {lang}"
        ),
        "depends_on": capa_deps,
        "timeout": 60,
    })

    return steps


def phase_post_capa23(component: str, protocol: str, session_dir: str,
                      repo: str, lang: str) -> list[dict]:
    """Phase 4: Read Capa 3 results, emit escaped sibling PoC steps if needed."""
    steps: list[dict] = []
    triage_dir = Path(session_dir) / "triage"
    gen_cmd = f"{sys.executable} {Path(__file__).resolve()}"
    plan_gen_cmd = f"{sys.executable} {Path(__file__).resolve().parent / 'plan_generator.py'}"

    # Load capa23 state
    capa_path = triage_dir / f"{component}_capa23.json"
    if not capa_path.exists():
        # Nothing to do, go to finalize
        steps.append({
            "id": f"{component}:triage_finalize",
            "type": "generate",
            "description": f"Finalize triage for {component}",
            "command": (
                f"{gen_cmd} --phase finalize "
                f"--component {component} --protocol {protocol} "
                f"--session-dir {session_dir} --repo {repo} --lang {lang}"
            ),
            "timeout": 60,
        })
        return steps

    capa_data = json.loads(capa_path.read_text())
    sibling_pairs = capa_data.get("sibling_pairs", [])

    # Check Capa 3 results — missing = conservative DIFFERENT (sibling escapes)
    escaped: list[dict] = []
    for pair in sibling_pairs:
        if len(pair) < 2:
            continue
        sibling = pair[1]
        sid = sibling.get("id", "UNKNOWN")
        result_path = triage_dir / f"{component}_same_bug_{sid}.json"
        if result_path.exists():
            try:
                result = json.loads(result_path.read_text())
                if result.get("verdict", "").upper() == "DIFFERENT":
                    escaped.append(sibling)
            except Exception:
                escaped.append(sibling)  # conservative
        else:
            escaped.append(sibling)  # conservative: missing = DIFFERENT

    # Emit PoC steps for escaped siblings
    for f in escaped:
        fid = f.get("id", "UNKNOWN")
        title = f.get("title", "N/A")[:80]

        prompt_id = f"{component}:escaped_poc_prompt:{fid}"
        steps.append({
            "id": prompt_id,
            "type": "generate",
            "description": f"Build escaped sibling PoC prompt for {fid}",
            "command": (
                f"{plan_gen_cmd} --phase fork-poc-prompt "
                f"--component {component} --protocol {protocol} "
                f"--repo {repo} --session-dir {session_dir} "
                f"--finding-id {fid}"
            ),
            "parallel_group": f"{component}:escaped_prompts",
            "timeout": 60,
        })

        steps.append({
            "id": f"{component}:escaped_poc:{fid}",
            "type": "agent",
            "description": f"Escaped sibling PoC for {fid}: {title}",
            "prompt": "__DYNAMIC__",
            "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            "depends_on": [prompt_id],
            "parallel_group": f"{component}:escaped_batch",
            "timeout": 600,
            "retry": 1,
        })

    # Always end with finalize
    finalize_deps: list[str] = []
    if escaped:
        finalize_deps.append(f"parallel_group:{component}:escaped_batch")

    steps.append({
        "id": f"{component}:triage_finalize",
        "type": "generate",
        "description": f"Finalize triage for {component}",
        "command": (
            f"{gen_cmd} --phase finalize "
            f"--component {component} --protocol {protocol} "
            f"--session-dir {session_dir} --repo {repo} --lang {lang}"
        ),
        "depends_on": finalize_deps if finalize_deps else None,
        "timeout": 60,
    })

    return steps


def phase_finalize(component: str, protocol: str, session_dir: str,
                   repo: str, lang: str) -> list[dict]:
    """Phase 5: Collect all PoC results, log funnel, emit RedTeam steps."""
    steps: list[dict] = []
    triage_dir = Path(session_dir) / "triage"
    session_path = Path(session_dir)

    # Load groups
    groups_path = triage_dir / f"{component}_groups.json"
    if not groups_path.exists():
        return steps
    groups = json.loads(groups_path.read_text())

    # Count hypotheses
    n_hypotheses = sum(len(g) for g in groups)

    # Count verified
    n_verified = sum(
        1 for g in groups for f in g
        if f.get("_verified") or f.get("fuzz_confirmed")
    )

    # Load PoC candidates
    poc_candidates_path = triage_dir / f"{component}_poc_candidates.json"
    n_poc_in = 0
    if poc_candidates_path.exists():
        try:
            poc_candidates = json.loads(poc_candidates_path.read_text())
            n_poc_in = len(poc_candidates)
        except Exception:
            pass

    # Collect ALL PoC results from session dir
    poc_confirmed: list[dict] = []
    for poc_file in session_path.glob("poc_*.json"):
        try:
            result = json.loads(poc_file.read_text())
            if result.get("passed", result.get("success", False)):
                poc_confirmed.append(result)
        except Exception:
            continue

    n_poc_out = len(poc_confirmed)

    # Read source for RedTeam prompts
    source, library = _read_source_for_component(repo, component, lang)

    # Build final findings list (PoC confirmed)
    final_findings: list[dict] = []
    confirmed_ids = {r.get("finding_id", "") for r in poc_confirmed}

    for g in groups:
        for f in g:
            if f.get("id") in confirmed_ids:
                f["has_poc"] = True
                final_findings.append(f)

    # Save final state
    (triage_dir / f"{component}_final.json").write_text(
        json.dumps([_serialize_finding(f) for f in final_findings], indent=2)
    )

    # Save funnel
    funnel_data = {
        "component": component,
        "n_hypotheses": n_hypotheses,
        "n_verified": n_verified,
        "n_poc_in": n_poc_in,
        "n_poc_confirmed": n_poc_out,
        "n_redteam": len(final_findings),
        "confirmed_ids": list(confirmed_ids),
    }
    (triage_dir / f"{component}_funnel.json").write_text(
        json.dumps(funnel_data, indent=2)
    )

    # Print funnel to stderr
    funnel_str = format_funnel(
        component, n_hypotheses, n_verified, n_poc_in, n_poc_out, len(final_findings)
    )
    print(funnel_str, file=sys.stderr)

    # Emit RedTeam agent steps for each PoC-confirmed finding
    for f in final_findings:
        fid = f.get("id", "UNKNOWN")
        title = f.get("title", "N/A")[:80]
        severity = f.get("severity", "Unknown")

        # Find the PoC file path
        poc_file = session_path / f"poc_{fid}.json"
        poc_code = ""
        if poc_file.exists():
            try:
                poc_data = json.loads(poc_file.read_text())
                poc_code = poc_data.get("poc_code", poc_data.get("test_code", ""))
            except Exception:
                pass

        relevant_code = extract_relevant_code(source, library, f)

        steps.append({
            "id": f"{component}:redteam:{fid}",
            "type": "agent",
            "description": f"RedTeam {fid}: {title}",
            "prompt": (
                f"RedTeam this finding for {component} in {protocol}.\n"
                f"Act as 4 adversarial reviewers trying to KILL this finding.\n\n"
                f"## Finding Details\n"
                f"- ID: {fid}\n"
                f"- Title: {title}\n"
                f"- Severity: {severity}\n"
                f"- Confidence: {f.get('confidence', 0)}%\n"
                f"- Hunter: {f.get('hunter', 'N/A')}\n"
                f"- Root Cause: {f.get('root_cause', 'N/A')}\n\n"
                f"## Source Code\n```solidity\n{relevant_code}\n```\n\n"
                f"## PoC Code\n```solidity\n{poc_code}\n```\n\n"
                f"## 5 Kill Questions\n"
                f"1. Is exploitation actually possible on-chain, or only in test mocks?\n"
                f"2. Does the PoC demonstrate REAL fund loss (not just rounding dust)?\n"
                f"3. Does a require/modifier/access check already prevent this?\n"
                f"4. Is this behavior intentional/documented by the protocol?\n"
                f"5. Does the attack require privileged access (admin/owner)? → R1 reject\n\n"
                f"## Output\n"
                f"Write your verdict to: {session_dir}/redteam_{fid}.json\n"
                f"Format: {{\"finding_id\": \"{fid}\", \"verdict\": \"REPORT\" or "
                f"\"REPORT_DOWNGRADED\" or \"DO_NOT_REPORT\", "
                f"\"kill_reason\": \"...\", \"severity_adjustment\": \"...\"}}"
            ),
            "tools": ["Read", "Write", "Grep", "Glob", "Bash"],
            "depends_on": None,
            "parallel_group": f"{component}:redteam_batch",
            "timeout": 300,
        })

    return steps


# ─── CLI Entry Point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Finding pipeline — CLI phase interface for plan_generator.py"
    )
    parser.add_argument("--phase", required=True,
                        choices=["dedup", "post-verify", "post-poc",
                                 "post-capa23", "finalize"],
                        help="Pipeline phase to execute")
    parser.add_argument("--component", required=True, help="Component name")
    parser.add_argument("--protocol", required=True, help="Protocol name")
    parser.add_argument("--session-dir", required=True, help="Session directory path")
    parser.add_argument("--repo", required=True, help="Repository root path")
    parser.add_argument("--threshold", type=int, default=65,
                        help="Min confidence threshold (default: 65)")
    parser.add_argument("--lang", default="solidity",
                        help="Source language (default: solidity)")

    args = parser.parse_args()

    dispatch = {
        "dedup": lambda: phase_dedup(
            args.component, args.protocol, args.session_dir,
            args.repo, args.threshold, args.lang),
        "post-verify": lambda: phase_post_verify(
            args.component, args.protocol, args.session_dir,
            args.repo, args.lang),
        "post-poc": lambda: phase_post_poc(
            args.component, args.protocol, args.session_dir,
            args.repo, args.lang),
        "post-capa23": lambda: phase_post_capa23(
            args.component, args.protocol, args.session_dir,
            args.repo, args.lang),
        "finalize": lambda: phase_finalize(
            args.component, args.protocol, args.session_dir,
            args.repo, args.lang),
    }

    steps = dispatch[args.phase]()
    # Clean None values from step dicts
    clean_steps = []
    for s in steps:
        clean_steps.append({k: v for k, v in s.items() if v is not None})
    print(json.dumps(clean_steps, indent=2))


if __name__ == "__main__":
    main()
