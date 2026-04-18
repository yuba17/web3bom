#!/usr/bin/env python3
"""Convert knowledge/solodit_cards/*.yaml into Obsidian wiki pages.

One page per category under <output-dir>. Designed to feed
query_wiki_context() without any orchestrator changes.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


WEB3_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CARDS_DIR = WEB3_DIR / "knowledge" / "solodit_cards"
DEFAULT_OUTPUT_DIR = Path.home() / "obsidian-vault" / "web3-audit" / "solodit"


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
    # Body filled in Task 2.
    print(f"cards-dir: {args.cards_dir}")
    print(f"output-dir: {args.output_dir}")
    print(f"dry-run: {args.dry_run}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
