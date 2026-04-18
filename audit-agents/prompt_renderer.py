#!/usr/bin/env python3
"""
prompt_renderer.py — Reads prompt templates and interpolates context placeholders.

Templates use {{PLACEHOLDER}} syntax. Context is a dict of placeholder → value.

Usage:
    from prompt_renderer import render_prompt
    prompt = render_prompt("hunters/math_hunter.md", {"COMPONENT": "Strategy", "CODE": code})
"""

import re
from pathlib import Path

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def render_prompt(template_name: str, context: dict) -> str:
    """Read a template file and interpolate {{PLACEHOLDER}} with context values."""
    template_path = PROMPTS_DIR / template_name
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")

    template = template_path.read_text(encoding="utf-8")

    def replacer(match):
        key = match.group(1)
        if key in context:
            return str(context[key])
        return match.group(0)  # leave unresolved placeholders as-is

    return re.sub(r"\{\{(\w+)\}\}", replacer, template)


def list_templates() -> list[str]:
    """List all available template files."""
    templates = []
    for f in PROMPTS_DIR.rglob("*.md"):
        templates.append(str(f.relative_to(PROMPTS_DIR)))
    return sorted(templates)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        for t in list_templates():
            print(t)
    else:
        print(f"Templates dir: {PROMPTS_DIR}")
        print(f"Templates: {len(list_templates())}")
