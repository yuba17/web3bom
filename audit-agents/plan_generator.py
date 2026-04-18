"""Compatibility shim — symbols re-exported from plan/* in Phase 6.

Kept transitionally so that direct imports (tests, scope_intake subprocess
invocations) keep working. Will be re-evaluated in Phase 7 cleanup.
"""
from plan.detectors import (  # noqa: F401
    _detect_primary_domain, _read_file_safe, _detect_lang, _src_dir,
    _find_cargo_workspace, _find_rust_crate_src, _rust_crate_sources,
    _results_dir, _hyp_dir, _step_id, _rpc_var, _fork_sol_snippet,
    _worktree_path, _last_step_id,
)
from plan.generator import (  # noqa: F401
    generate_plan, _add_component_steps, _add_cross_component_steps,
)
from plan.prompts_solidity import (  # noqa: F401
    phase_hunter_prompt, phase_deepdive_prompt, phase_findings,
    phase_fork_poc_prompt, phase_cross_prompt, phase_transitive_chain_prompt,
    phase_chimera_early_prompt, phase_chimera_builder_prompt,
    phase_enhance_targets_prompt,
)
from plan.prompts_rust import (  # noqa: F401
    phase_rust_fuzz_scaffold_prompt, phase_rust_fuzz_harness_prompt,
    phase_rust_merge_harness, _rust_enhance_fuzz_prompt,
    _phase_hunter_prompt_rust, _phase_findings_rust, _phase_cross_prompt_rust,
)
from plan.post_compile import (  # noqa: F401
    phase_write_fork_setup, phase_post_compile, phase_checkpoint,
)
from plan.cli import main

if __name__ == "__main__":
    main()
