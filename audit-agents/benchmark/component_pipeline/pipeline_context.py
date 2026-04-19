"""PipelineContext — shared mutable state for component_pipeline phases.

Captures all locals previously held inside run_component_pipeline.
Each phase function reads/writes its fields directly.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple


@dataclass
class PipelineContext:
    # Inputs
    component: str
    repo: str
    protocol: str
    args: argparse.Namespace
    logger: logging.Logger

    # Derived paths (set early in orchestrator)
    src_dir: Path
    hyp_dir: Path
    clog: Path  # component log dir
    src_file: Path

    # Timing
    comp_start: float = field(default_factory=time.time)

    # Accumulators (mutated by phases)
    summary: Dict[str, Any] = field(default_factory=lambda: {"gates": {}, "findings": []})

    # Source / library / interfaces (loaded by context phase)
    source_code: str = ""
    library_code: str = ""
    interfaces_code: str = ""

    # Test artifacts
    existing_tests_summary: str = ""
    _test_files_cache: List[Tuple[str, str]] = field(default_factory=list)

    # Knowledge briefings
    knowledge_context: str = ""

    # Setup artifacts
    setup_sol_text: str = ""
    setup_var_names: str = ""

    # Prepass
    prepass_signals_text: str = ""

    # Protocol model (kept for compat)
    protocol_model: str = ""

    # Cross-component context
    accumulated_context: str = ""

    # Skip flags
    _skip_to_merge: bool = False

    # Fuzz accumulators (set by fuzz phase, consumed by extract phase)
    phase1_fuzz_failures: Dict[str, Any] = field(default_factory=dict)
    phase2_log: Path = field(default_factory=lambda: Path(".") / "phase2_medusa.log")

    # Extract-phase outputs (set by extract, consumed by verify/poc phases)
    finding_groups: List[Any] = field(default_factory=list)
    poc_findings: List[Any] = field(default_factory=list)
    escaped_siblings: List[Any] = field(default_factory=list)
    fallback_findings: List[Any] = field(default_factory=list)
