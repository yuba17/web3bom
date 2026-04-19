"""Per-component hunt pipeline — extracted from run_benchmark.py in Phase 6.

Public API (re-exported here for callers):
    - run_component_pipeline (runner.py): full pipeline for one component.
    - parse_fuzz_failures (reporting.py): extract invariant failures from logs.

Layout rationale:
    - runner.py holds the orchestration (one coherent flow with many local
      closures/state — splitting helpers further would require threading
      massive context dicts).
    - reporting.py holds the pure log-parsing utility used by both runner
      and downstream callers (re-exported via run_benchmark shim).

Mutable globals (HUNT_SESSION_DIR, SCRIPT_DIR, USE_SUB_MODE, PARALLEL_HUNTERS,
DISABLE_FEW_SHOT) and test-monkeypatched names (_llm, run_cmd,
component_log_dir, fix_and_retry, etc.) are accessed lazily via
`import run_benchmark as _rb` inside the function body. Top-level import
would freeze bindings AND create a circular import (since run_benchmark
re-exports this module).
"""
from benchmark.component_pipeline.runner import run_component_pipeline  # noqa: F401
from benchmark.component_pipeline.reporting import parse_fuzz_failures  # noqa: F401
