#!/usr/bin/env python3
"""Compatibility shim — symbols re-exported from benchmark/* in Phase 6.

Direct imports (tests, plan_generator shim, external tooling) keep working.
Mutable globals (USE_SUB_MODE, POC_GEN_TIMEOUT, HUNT_SESSION_DIR, LOG_DIR …)
are declared HERE so downstream modules can keep reading them via
`import run_benchmark as _rb; _rb.<NAME>`. main() (in benchmark.cli)
mutates them through the shim. See cli.py docstring.
"""
import subprocess  # noqa: F401  (tests patch run_benchmark.subprocess.run)
from paths import HUNT_SESSION_DIR, AUDIT_AGENTS_DIR  # noqa: F401
from benchmark.llm_runners import (  # noqa: F401
    run_claude, _run_claude_inner, run_claude_sub, _llm, run_cmd,
    _extract_first_errors, _CLAUDE_SEMAPHORE, _AGENTIC_TOOLS,
)
from benchmark.prompt_builders import (  # noqa: F401
    load_prompt, read_source, build_hunter_brief, build_hunter_dispatch_prompt,
    build_deepdive_prompt, build_poc_prompt, build_escalation_prompt,
    build_redteam_prompt, build_variant_prompt, build_report_prompt,
    build_cross_pair_prompt,
)
from benchmark.poc_pipeline import (  # noqa: F401
    fix_and_retry, _generate_foundry_tester_wrappers, _log_funnel,
    _sanitize_sol_unicode, _filter_errors_for_file, generate_and_test_poc,
)
from benchmark.component_pipeline import run_component_pipeline, parse_fuzz_failures  # noqa: F401
from benchmark.finding_pipeline import extract_findings, run_finding_pipeline  # noqa: F401
from benchmark.cross_component import run_cross_component  # noqa: F401
from benchmark.worktree_helpers import (  # noqa: F401
    _create_worktree, _remove_worktree, _validate_hunters_subset,
    _apply_force_regen_map, _maybe_run_apply_feedback, _resolve_components,
)
from finding_pipeline import (  # noqa: F401  (legacy aliases)
    extract_relevant_code as _extract_relevant_code,
    build_verify_prompt, build_is_same_bug_prompt, POC_CONFIDENCE_THRESHOLD,
)
from benchmark.cli import (  # noqa: F401
    setup_logging, component_log_dir, detect_pragma, check_gate, main,
    logger, SCRIPT_DIR,
)
# Mutable globals — set by benchmark.cli.main() after argparse, read by other
# benchmark/* modules via `import run_benchmark as _rb; _rb.<NAME>`.
IS_PRE_PRODUCTION: bool = False
USE_SUB_MODE: bool = False
SUB_MODEL: str = "sonnet"
PARALLEL_HUNTERS: int = 6
POC_GEN_TIMEOUT: int = 900
DISABLE_FEW_SHOT: bool = False
LOG_DIR = None  # set by setup_logging()

if __name__ == "__main__":
    main()
