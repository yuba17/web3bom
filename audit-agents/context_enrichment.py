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
