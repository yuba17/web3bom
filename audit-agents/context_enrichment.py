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

from pathlib import Path

# Skip deep_flatten when the contract is small — the signal isn't worth
# the subprocess cost. Threshold chosen empirically; tune if needed.
DEEP_FLATTEN_MIN_LINES = 200


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
