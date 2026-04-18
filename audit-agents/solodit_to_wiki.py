#!/usr/bin/env python3
"""Convert knowledge/solodit_cards/*.yaml into Obsidian wiki pages.

One page per category under <output-dir>. Designed to feed
query_wiki_context() without any orchestrator changes.
"""
from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

import yaml


WEB3_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CARDS_DIR = WEB3_DIR / "knowledge" / "solodit_cards"
DEFAULT_OUTPUT_DIR = Path.home() / "obsidian-vault" / "web3-audit" / "solodit"

SUFFIX_ORDER = [
    ("r2_new_patterns",    "Round 2 — new patterns"),
    ("r2_incidents",       "Round 2 — incidents"),
    ("new_patterns",       "New patterns"),
    ("existing_incidents", "Existing patterns — incidents"),
]
SUFFIX_MATCH_ORDER = [s for s, _ in SUFFIX_ORDER]  # longest-first via sort below
SUFFIX_MATCH_ORDER.sort(key=len, reverse=True)

RENDER_ORDER = ["existing_incidents", "new_patterns", "r2_incidents", "r2_new_patterns"]
SUFFIX_TITLE = dict(SUFFIX_ORDER)


def _split_category(stem: str) -> tuple[str, str] | None:
    """Return (category, suffix) or None if no suffix matches."""
    for suffix in SUFFIX_MATCH_ORDER:
        tail = "_" + suffix
        if stem.endswith(tail):
            return stem[: -len(tail)], suffix
    return None


def _category_display(category: str) -> str:
    return category.replace("_", " ").title().replace(" ", " ")


def _filename(category: str) -> str:
    return category.replace("_", "-") + ".md"


def _render_bullets(payload) -> str:
    """Render a YAML payload (dict of pattern-id → list[str]) as markdown bullets."""
    if not isinstance(payload, dict):
        return ""
    lines: list[str] = []
    for pattern_id, bullets in payload.items():
        if not isinstance(bullets, list):
            continue
        lines.append(f"### {pattern_id}")
        for b in bullets:
            lines.append(f"- {b}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_page(category: str, sources: dict[str, Path]) -> str:
    """Compose the full markdown page for a category."""
    display = _category_display(category)
    total_entries = 0
    body_sections: list[str] = []
    for suffix in RENDER_ORDER:
        path = sources.get(suffix)
        if path is None:
            continue
        payload = yaml.safe_load(path.read_text()) or {}
        rendered = _render_bullets(payload)
        if not rendered.strip():
            continue
        body_sections.append(f"## {SUFFIX_TITLE[suffix]}\n\n{rendered}")
        if isinstance(payload, dict):
            for bullets in payload.values():
                if isinstance(bullets, list):
                    total_entries += len(bullets)
    pattern_count = len(sources)
    summary = (f"Curated Solodit findings for {category} — "
               f"{total_entries} incidents across {pattern_count} source files")
    frontmatter = (
        "---\n"
        f"name: Solodit — {display}\n"
        f"summary: {summary}\n"
        "type: solodit-reference\n"
        f"generated: {date.today().isoformat()}\n"
        "---\n\n"
        f"# Solodit references: {display}\n\n"
    )
    return frontmatter + "\n".join(body_sections).rstrip() + "\n"


def _group_sources(cards_dir: Path) -> dict[str, dict[str, Path]]:
    grouped: dict[str, dict[str, Path]] = defaultdict(dict)
    for yaml_path in sorted(cards_dir.glob("*.yaml")):
        split = _split_category(yaml_path.stem)
        if split is None:
            continue
        category, suffix = split
        grouped[category][suffix] = yaml_path
    return grouped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Solodit YAML cards into Obsidian wiki pages.",
    )
    parser.add_argument("--cards-dir", default=str(DEFAULT_CARDS_DIR),
                        help=f"Directory with Solodit YAML cards (default: {DEFAULT_CARDS_DIR}).")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR),
                        help=f"Output directory for wiki pages (default: {DEFAULT_OUTPUT_DIR}).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print intended writes without touching the filesystem.")
    args = parser.parse_args(argv)

    cards_dir = Path(args.cards_dir)
    output_dir = Path(args.output_dir)

    if not cards_dir.is_dir():
        print(f"error: cards-dir not found: {cards_dir}", file=sys.stderr)
        return 1

    grouped = _group_sources(cards_dir)
    if not grouped:
        print(f"error: no Solodit cards found in {cards_dir}", file=sys.stderr)
        return 1

    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    for category in sorted(grouped):
        page = _render_page(category, grouped[category])
        target = output_dir / _filename(category)
        if args.dry_run:
            print(f"would write: {target} ({len(page)} chars)")
            continue
        target.write_text(page)
        print(f"wrote {target.name} ({len(grouped[category])} sources)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
