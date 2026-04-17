"""Context-enrichment helpers for the modern hunter pipeline.

Migrated from legacy `run_hunt.py` during Phase 2A of the optimization
roadmap. These functions enrich the hunter brief with wiki excerpts,
domain briefings, asset-flow maps, symmetry signals, and deep-flatten
traces. `build_hunter_context` composes all five into a single markdown
block appended to the brief.

Each helper degrades gracefully: on failure (missing file, subprocess
error, vault unreachable) it returns an empty string. A hunter prompt
must never fail because of a context-enrichment helper.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

# Skip deep_flatten when the contract is small — the signal isn't worth
# the subprocess cost. Threshold chosen empirically; tune if needed.
DEEP_FLATTEN_MIN_LINES = 200

AUDIT_AGENTS_DIR = Path(__file__).resolve().parent  # /home/kali/Documents/Web3/audit-agents

_symmetric_mem_cache: dict[str, str] = {}
_flatten_mem_cache: dict[str, str] = {}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _cached_subprocess(
    key: str,
    cache_dir: Path | None,
    mem_cache: dict[str, str],
    runner,
) -> str:
    """Shared cache plumbing for symmetric + deep_flatten wrappers.

    Lookup order: in-memory dict → filesystem (if cache_dir) → runner().
    `runner` must be a zero-arg callable returning the raw string output
    (empty string on any failure is acceptable; caller still caches it).
    """
    if key in mem_cache:
        return mem_cache[key]
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        disk = cache_dir / f"{key}.txt"
        if disk.exists():
            value = disk.read_text()
            mem_cache[key] = value
            return value
    value = runner()
    mem_cache[key] = value
    if cache_dir is not None:
        (cache_dir / f"{key}.txt").write_text(value)
    return value


def run_symmetric_analysis(
    contract_path: Path,
    *,
    cache_dir: Path | None = None,
) -> str:
    """Wrap `symmetric_analyzer.py` CLI. Returns trimmed stdout or "".

    Caches by sha256 of file bytes. Pass `cache_dir` to persist across
    runs; otherwise caches in-process only.
    """
    if not contract_path or not contract_path.exists():
        return ""
    script = AUDIT_AGENTS_DIR / "symmetric_analyzer.py"
    if not script.exists():
        return ""
    key = f"sym-{contract_path.stem}-{_file_sha256(contract_path)}"

    def _run() -> str:
        try:
            result = subprocess.run(
                [sys.executable, str(script), str(contract_path), "--contract", contract_path.stem],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip() and "ERROR" not in result.stdout[:20]:
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    return _cached_subprocess(key, cache_dir, _symmetric_mem_cache, _run)


def query_wiki_context(domain: str, component: str) -> str:
    """Query Obsidian vault for relevant prior knowledge.

    Searches recursively through the vault (skipping _raw, _archives,
    .obsidian, projects). Returns up to 8 summaries, capped implicitly
    by 8 x ~300ch = ~2400ch max. Empty string if vault missing or no
    matches.
    """
    vault_dir = Path.home() / "obsidian-vault" / "web3-audit"
    if not vault_dir.exists():
        return ""
    skip_dirs = {"_raw", "_archives", ".obsidian", "projects"}
    skip_files = {"index.md", "log.md"}
    results: list[str] = []
    domain_l, comp_l = domain.lower(), component.lower()
    for md_file in vault_dir.glob("**/*.md"):
        if md_file.name.startswith("_") or md_file.name in skip_files:
            continue
        if any(part in skip_dirs for part in md_file.relative_to(vault_dir).parts):
            continue
        try:
            content = md_file.read_text(errors="ignore")
        except Exception:
            continue
        lower = content.lower()
        if domain_l in lower or comp_l in lower:
            summary = ""
            if content.startswith("---"):
                end = content.find("---", 3)
                if end != -1:
                    for line in content[3:end].splitlines():
                        if line.strip().startswith("summary:"):
                            summary = line.split("summary:", 1)[1].strip()
                            break
            snippet = summary if summary else content[:300]
            results.append(f"- **{md_file.stem}**: {snippet}")
    if not results:
        return ""
    return "\n---\n## Prior Knowledge (Obsidian Vault)\n" + "\n".join(results[:8])


WEB3_DIR = Path(__file__).resolve().parents[1]  # /home/kali/Documents/Web3

DOMAIN_BRIEFING: dict[str, str] = {
    "staking":    "knowledge/staking.md",
    "lending":    "knowledge/lending.md",
    "vault":      "knowledge/vault-erc4626.md",
    "oracle":     "knowledge/oracle.md",
    "dex":        "knowledge/dex-amm.md",
    "flash":      "knowledge/flash-loan.md",
    "token":      "knowledge/token-erc20.md",
    "access":     "knowledge/access-control.md",
    "signature":  "knowledge/signature-replay.md",
    "proxy":      "knowledge/proxy-upgrade.md",
    "trust":      "knowledge/trust-boundaries.md",
    "bridge":     "knowledge/bridge.md",
    "opstack":    "knowledge/bridge-opstack.md",
    "erc4337":    "knowledge/erc4337-account-abstraction.md",
    "zk":         "knowledge/zk-circuits.md",
    "governance": "knowledge/governance.md",
    "nft":        "knowledge/nft-erc721.md",
    "yield":      "knowledge/yield-aggregator.md",
    "liquid":     "knowledge/liquid-staking.md",
    "perps":      "knowledge/perps-derivatives.md",
    "crosschain": "knowledge/cross-chain-intents.md",
    "vesting":    "knowledge/vesting-tokenomics.md",
    "options":    "knowledge/options-structured-products.md",
    "mev":        "knowledge/mev-sandwich.md",
    "reentrancy": "knowledge/reentrancy-patterns.md",
    "inputval":   "knowledge/input-validation.md",
}


def load_briefing_single(domain: str) -> str:
    """Extract structured sections from a domain briefing markdown file.

    Returns a compressed summary (patrones conocidos, trampas, checklist,
    grep, incidents). Empty string if the briefing does not exist.
    Falls back to the first 4000 chars if structured extraction finds
    nothing useful (<200 chars of structured output).
    """
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except Exception:
        return ""

    lines = text.split("\n")
    sections: dict[str, list[str]] = {
        "bugs_index": [], "trampas": [], "checklist": [], "grep": [], "incidents": [],
    }
    current = None
    in_trampa_block = False

    for line in lines:
        if line.startswith("### 1.") or line.startswith("### 2."):
            sections["bugs_index"].append(line.strip())
            current = None
        elif "Invariant Checklist" in line or "## 3." in line:
            current = "checklist"
        elif "Grep Targets" in line or "## 4." in line:
            current = "grep"
        elif "Real-World Incidents" in line or "## 2.3" in line:
            current = "incidents"
        elif line.strip() == "trampas:":
            in_trampa_block = True
        elif in_trampa_block:
            if line.strip().startswith("- ") or line.strip().startswith("  - "):
                sections["trampas"].append(line.strip())
            elif line.strip() and not line.strip().startswith(" "):
                in_trampa_block = False
        elif current in sections:
            if line.strip():
                sections[current].append(line)
            if line.startswith("## ") and current != "checklist":
                current = None

    parts: list[str] = []
    if sections["bugs_index"]:
        parts.append("## PATRONES CONOCIDOS (busca primero estos)")
        parts.extend(sections["bugs_index"])
    if sections["trampas"]:
        parts.append("\n## TRAMPAS — NO pierdas tiempo en esto")
        seen: set[str] = set()
        for t in sections["trampas"]:
            clean = t.strip().lstrip("- ").strip('"')
            if clean and clean not in seen:
                seen.add(clean)
                parts.append(f"  ⚠ {clean}")
                if len(seen) >= 12:
                    break
    if sections["checklist"]:
        parts.append("\n## CHECKLIST DE INVARIANTES")
        parts.extend(sections["checklist"][:20])
    if sections["grep"]:
        parts.append("\n## GREP TARGETS")
        parts.extend(sections["grep"][:15])
    if sections["incidents"]:
        parts.append("\n## INCIDENTES REALES (protocolos afectados)")
        parts.extend(sections["incidents"][:10])

    result = "\n".join(parts)
    if len(result) < 200:
        return text[:4000]
    return result


def load_grep_targets_only(domain: str) -> str:
    """Compact secondary-domain briefing: just the Grep Targets section."""
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except Exception:
        return ""
    lines = text.split("\n")
    in_grep = False
    grep_lines: list[str] = []
    for line in lines:
        if "Grep Targets" in line or "Quick Grep" in line or "## 4." in line:
            in_grep = True
            continue
        if in_grep:
            if line.startswith("## ") and grep_lines:
                break
            if line.strip():
                grep_lines.append(line)
            if len(grep_lines) >= 12:
                break
    return "\n".join(grep_lines)


def load_briefings_tiered(domains: list[str]) -> str:
    """Tiered briefings: primary full, secondary grep-only, tertiary dropped.

    Rationale: more than one full briefing saturates the hunter prompt with
    irrelevant patterns and lowers invariant quality. Grep-targets-only is
    the signal/noise sweet spot for secondary domains.
    """
    if not domains:
        return ""
    parts: list[str] = []
    primary = domains[0]
    primary_text = load_briefing_single(primary)
    if primary_text:
        parts.append(f"### Briefing principal: {primary}\n{primary_text}")
    if len(domains) > 1:
        secondary = domains[1]
        grep_text = load_grep_targets_only(secondary)
        if grep_text:
            parts.append(f"\n### Grep targets adicionales ({secondary})\n{grep_text}")
    return "\n\n".join(parts)


def generate_asset_flow_map(contract_path: Path) -> str:
    """Regex-based asset-flow scanner for a Solidity contract.

    Detects transfers, approvals, mints/burns, and balance reads with
    line-number + function-name context. Output is a markdown section
    ready to be injected into a hunter brief.
    """
    if not contract_path or not contract_path.exists():
        return ""
    try:
        src = contract_path.read_text()
    except Exception:
        return ""

    lines = src.split("\n")
    patterns = {
        "money_in": [
            (r'\.transferFrom\(', "transferFrom"),
            (r'\.safeTransferFrom\(', "safeTransferFrom"),
            (r'msg\.value', "msg.value"),
        ],
        "money_out": [
            (r'\.transfer\(', "transfer"),
            (r'\.safeTransfer\(', "safeTransfer"),
            (r'\.call\{value:', "call{value:}"),
        ],
        "approvals": [
            (r'\.approve\(', "approve"),
            (r'\.safeApprove\(', "safeApprove"),
            (r'\.forceApprove\(', "forceApprove"),
        ],
        "balance_reads": [
            (r'balanceOf\(', "balanceOf"),
            (r'address\(this\)\.balance', "address(this).balance"),
        ],
        "mint_burn": [
            (r'\.mint\(', "mint"),
            (r'\.burn\(', "burn"),
            (r'_mint\(', "_mint"),
            (r'_burn\(', "_burn"),
        ],
    }

    current_function = "<top-level>"
    results: dict[str, list[str]] = {k: [] for k in patterns}

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        fn_match = re.match(r'\s*function\s+(\w+)\s*\(', line)
        if fn_match:
            current_function = fn_match.group(1) + "()"
        if re.match(r'\s*(receive|fallback)\s*\(', line):
            current_function = stripped.split("(")[0].strip() + "()"
            if "receive" in stripped:
                results["money_in"].append(
                    f"- L{line_num} {current_function}: accepts ETH via payable receive"
                )
        for category, pattern_list in patterns.items():
            for regex, _label in pattern_list:
                if re.search(regex, line):
                    display_line = stripped
                    if len(display_line) > 120:
                        display_line = display_line[:117] + "..."
                    results[category].append(
                        f"- L{line_num} {current_function}: {display_line}"
                    )

    # Filter transferFrom out of money_out to avoid double-counting
    results["money_out"] = [
        e for e in results["money_out"]
        if "transferFrom" not in e and "safeTransferFrom" not in e
    ]

    sections: list[str] = []
    section_map = [
        ("money_in",      "Money IN (deposits/receives)"),
        ("money_out",     "Money OUT (withdrawals/sends)"),
        ("approvals",     "Approvals (attack surface)"),
        ("mint_burn",     "Minting/Burning"),
        ("balance_reads", "Balance Reads (manipulation vectors)"),
    ]
    for key, title in section_map:
        if results[key]:
            sections.append(f"### {title}\n" + "\n".join(results[key]))
    if not sections:
        return ""
    return "## Asset Flow Map\n" + "\n\n".join(sections) + "\n"
