"""finding_pipeline.py — Pure functions for the finding dedup/verify/funnel pipeline.

Extracted from run_benchmark.py for reuse by both run_benchmark.py and plan_generator.py.
All functions are side-effect-free (no logging, no globals, no file I/O beyond YAML parsing).
"""

from __future__ import annotations

import re
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

    unconfirmed.sort(key=lambda f: f.get("confidence", 0), reverse=True)

    if confirmed:
        return confirmed + unconfirmed[:10]
    else:
        return unconfirmed


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
