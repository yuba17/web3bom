"""Phase 6 shim smoke tests — anchor the re-export contract + no-cycle."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

BENCHMARK_PUBLIC = {
    # LLM runners
    "run_claude", "_run_claude_inner", "run_claude_sub", "_llm", "run_cmd",
    "_extract_first_errors",
    # Prompt builders
    "load_prompt", "read_source",
    "build_hunter_brief", "build_hunter_dispatch_prompt", "build_deepdive_prompt",
    "build_poc_prompt", "build_escalation_prompt", "build_redteam_prompt",
    "build_variant_prompt", "build_report_prompt", "build_cross_pair_prompt",
    # PoC pipeline
    "fix_and_retry", "generate_and_test_poc",
    # Component + finding + cross
    "run_component_pipeline", "parse_fuzz_failures",
    "extract_findings", "run_finding_pipeline",
    "run_cross_component",
    # Worktree + resolvers
    "_create_worktree", "_remove_worktree", "_validate_hunters_subset",
    "_apply_force_regen_map", "_maybe_run_apply_feedback", "_resolve_components",
    # CLI
    "setup_logging", "component_log_dir", "detect_pragma", "check_gate", "main",
}

PLAN_PUBLIC = {
    # Detectors (public)
    "_detect_primary_domain", "_detect_lang", "_src_dir",
    # Generator
    "generate_plan",
    # Solidity prompts
    "phase_hunter_prompt", "phase_deepdive_prompt", "phase_findings",
    "phase_fork_poc_prompt", "phase_cross_prompt", "phase_transitive_chain_prompt",
    "phase_chimera_early_prompt", "phase_chimera_builder_prompt",
    "phase_enhance_targets_prompt",
    # Rust prompts
    "phase_rust_fuzz_scaffold_prompt", "phase_rust_fuzz_harness_prompt",
    "phase_rust_merge_harness",
    # Post-compile
    "phase_write_fork_setup", "phase_post_compile", "phase_checkpoint",
    # CLI
    "main",
}


def test_run_benchmark_shim_reexports_contract():
    """Shim run_benchmark.py exporta exactamente el contrato público esperado."""
    rb = importlib.import_module("run_benchmark")
    exported = set(vars(rb))
    missing = BENCHMARK_PUBLIC - exported
    assert not missing, f"run_benchmark shim missing symbols: {sorted(missing)}"


def test_plan_generator_shim_reexports_contract():
    """Shim plan_generator.py exporta exactamente el contrato público esperado."""
    pg = importlib.import_module("plan_generator")
    exported = set(vars(pg))
    missing = PLAN_PUBLIC - exported
    assert not missing, f"plan_generator shim missing symbols: {sorted(missing)}"


def test_no_import_cycle():
    """Paquetes benchmark/ y plan/ se cargan top-level sin ciclo ni side-effect fatal."""
    # Reset cache para forzar re-import limpio
    for mod_name in list(sys.modules.keys()):
        if mod_name.startswith(("benchmark", "plan")) and mod_name not in {"plan_schema"}:
            del sys.modules[mod_name]

    import benchmark  # noqa: F401
    import benchmark.prompt_builders  # noqa: F401
    import plan  # noqa: F401
    import plan.prompts_solidity  # noqa: F401 — was lazy-imported before Phase 6
    import plan.generator  # noqa: F401
