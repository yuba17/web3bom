# Phase 8 Audit Report — 2026-04-19

## Executive Summary

- Gates: 4 PASS / 0 FAIL / 3 WARN / 0 ERROR
- Debt: 1 CRITICAL / 13 HIGH / 46 MEDIUM / 199 LOW
- Roadmap verdict: **PARTIAL**

## Per-check results

### ✅ check_test_suite — PASS

Evidence:

```json
{
  "passed": 227,
  "expected": 227,
  "returncode": 0
}
```

### ✅ check_clis — PASS

Evidence:

```json
{
  "clis": [
    {
      "cli": "run_benchmark.py",
      "exit_code": 0,
      "first_line": "usage: run_benchmark.py [-h] --repo REPO [--components COMPONENTS]"
    },
    {
      "cli": "plan_generator.py",
      "exit_code": 0,
      "first_line": "usage: plan_generator.py [-h] [--generate]"
    },
    {
      "cli": "pipeline_gate.py",
      "exit_code": 0,
      "first_line": "usage: pipeline_gate.py [-h] [--component COMPONENT] [--finding FINDING]"
    },
    {
      "cli": "scope_intake.py",
      "exit_code": 0,
      "first_line": "usage: scope_intake.py [-h] --repo REPO --platform PLATFORM"
    },
    {
      "cli": "sync_state.py",
      "exit_code": 0,
      "first_line": "usage: sync_state.py [-h] [--dry-run] [--verbose] [--password PASSWORD]"
    }
  ]
}
```

### ✅ check_parity_matrix — PASS

Evidence:

```json
{
  "total": 54,
  "by_decision": {
    "migrated": 16,
    "deprecated": 14,
    "keep_standalone": 0,
    "added_phase_5": 2,
    "added_phase_6": 14,
    "added_phase_9": 8
  },
  "summary_total": 54
}
```

### ✅ check_docs_sync — PASS

Evidence:

```json
{
  "hits": [],
  "docs_checked": [
    "CLAUDE.md",
    "WIKI.md",
    "HUNT_TRACKER.md",
    "README.md"
  ]
}
```

### ⚠️ check_size_inventory — WARN

Evidence:

```json
{
  "file_count": 98,
  "files": [
    {
      "path": "audit-agents/scanners/vulnerability_patterns.py",
      "loc": 2073
    },
    {
      "path": "audit-agents/benchmark/component_pipeline/runner.py",
      "loc": 1608
    },
    {
      "path": "audit-agents/agents/v2/zk_circuit_agent.py",
      "loc": 1520
    },
    {
      "path": "audit-agents/hybrid_pipeline.py",
      "loc": 1332
    },
    {
      "path": "audit-agents/merge_invariants.py",
      "loc": 1280
    },
    {
      "path": "audit-agents/target_monitor.py",
      "loc": 1261
    },
    {
      "path": "audit-agents/finding_pipeline.py",
      "loc": 1199
    },
    {
      "path": "audit-agents/bounty_monitor_v2.py",
      "loc": 1133
    },
    {
      "path": "audit-agents/detection_engine.py",
      "loc": 1123
    },
    {
      "path": "audit-agents/benchmark.py",
      "loc": 1019
    },
    {
      "path": "audit-agents/plan/prompts_solidity.py",
      "loc": 988
    },
    {
      "path": "audit-agents/agents/bridge_agent.py",
      "loc": 857
    },
    {
      "path": "audit-agents/plan/prompts_rust.py",
      "loc": 807
    },
    {
      "path": "audit-agents/report_finding.py",
      "loc": 679
    },
    {
      "path": "audit-agents/plan/generator.py",
      "loc": 674
    },
    {
      "path": "audit-agents/benchmark/cli.py",
      "loc": 660
    },
    {
      "path": "audit-agents/gate/gates_component.py",
      "loc": 655
    },
    {
      "path": "audit-agents/report_generator.py",
      "loc": 593
    },
    {
      "path": "audit-agents/phase_8_audit.py",
      "loc": 588
    },
    {
      "path": "audit-agents/build_solodit_index.py",
      "loc": 585
    }
  ]
}
```

### ⚠️ check_dead_code_residual — WARN

Evidence:

```json
{
  "todo_count": 21,
  "unused_import_count": 95
}
```

### ⚠️ check_shim_status — WARN

Evidence:

```json
{
  "shims": [
    {
      "shim": "run_benchmark.py",
      "loc": 52,
      "reexports": 49,
      "orphans": [
        "HUNT_SESSION_DIR",
        "AUDIT_AGENTS_DIR",
        "run_claude",
        "_run_claude_inner",
        "run_claude_sub",
        "_llm",
        "run_cmd",
        "_extract_first_errors",
        "_CLAUDE_SEMAPHORE",
        "_AGENTIC_TOOLS",
        "load_prompt",
        "read_source",
        "build_hunter_brief",
        "build_hunter_dispatch_prompt",
        "build_deepdive_prompt",
        "build_poc_prompt",
        "build_escalation_prompt",
        "build_redteam_prompt",
        "build_variant_prompt",
        "build_report_prompt",
        "build_cross_pair_prompt",
        "fix_and_retry",
        "_generate_foundry_tester_wrappers",
        "_log_funnel",
        "_sanitize_sol_unicode",
        "_filter_errors_for_file",
        "generate_and_test_poc",
        "run_component_pipeline",
        "parse_fuzz_failures",
        "extract_findings",
        "run_finding_pipeline",
        "run_cross_component",
        "_create_worktree",
        "_remove_worktree",
        "_maybe_run_apply_feedback",
        "_resolve_components",
        "_extract_relevant_code",
        "build_verify_prompt",
        "build_is_same_bug_prompt",
        "POC_CONFIDENCE_THRESHOLD",
        "setup_logging",
        "check_gate",
        "main",
        "logger",
        "SCRIPT_DIR"
      ]
    },
    {
      "shim": "plan_generator.py",
      "loc": 32,
      "reexports": 37,
      "orphans": [
        "_detect_primary_domain",
        "_read_file_safe",
        "_detect_lang",
        "_src_dir",
        "_find_cargo_workspace",
        "_find_rust_crate_src",
        "_rust_crate_sources",
        "_results_dir",
        "_hyp_dir",
        "_step_id",
        "_rpc_var",
        "_fork_sol_snippet",
        "_worktree_path",
        "_last_step_id",
        "generate_plan",
        "_add_component_steps",
        "_add_cross_component_steps",
        "phase_hunter_prompt",
        "phase_deepdive_prompt",
        "phase_findings",
        "phase_fork_poc_prompt",
        "phase_cross_prompt",
        "phase_transitive_chain_prompt",
        "phase_chimera_early_prompt",
        "phase_chimera_builder_prompt",
        "phase_enhance_targets_prompt",
        "phase_rust_fuzz_scaffold_prompt",
        "phase_rust_fuzz_harness_prompt",
        "phase_rust_merge_harness",
        "_rust_enhance_fuzz_prompt",
        "_phase_hunter_prompt_rust",
        "_phase_findings_rust",
        "_phase_cross_prompt_rust",
        "phase_write_fork_setup",
        "phase_post_compile",
        "phase_checkpoint",
        "main"
      ]
    }
  ]
}
```

## Debt Backlog

### CRITICAL

- **CRITICAL-01** [file_size] audit-agents/scanners/vulnerability_patterns.py is 2073 LOC (critical threshold)

### HIGH

- **HIGH-01** [file_size] audit-agents/agents/v2/zk_circuit_agent.py is 1520 LOC (high threshold)
- **HIGH-02** [function_size] audit-agents/benchmark/cli.py::main is 538 LOC
- **HIGH-03** [file_size] audit-agents/benchmark/component_pipeline/runner.py is 1608 LOC (high threshold)
- **HIGH-04** [function_size] audit-agents/benchmark/component_pipeline/runner.py::run_component_pipeline is 1573 LOC
- **HIGH-05** [function_size] audit-agents/benchmark/cross_component.py::run_cross_component is 441 LOC
- **HIGH-06** [function_size] audit-agents/benchmark.py::cmd_score_hypotheses is 225 LOC
- **HIGH-07** [function_size] audit-agents/hybrid_pipeline.py::main is 269 LOC
- **HIGH-08** [function_size] audit-agents/merge_invariants.py::run_split_mode is 219 LOC
- **HIGH-09** [function_size] audit-agents/plan/cli.py::main is 222 LOC
- **HIGH-10** [function_size] audit-agents/plan/generator.py::_add_component_steps is 382 LOC
- **HIGH-11** [function_size] audit-agents/plan/post_compile.py::phase_post_compile is 235 LOC
- **HIGH-12** [function_size] audit-agents/plan/prompts_rust.py::_phase_findings_rust is 225 LOC
- **HIGH-13** [function_size] audit-agents/report_finding.py::main is 286 LOC

### MEDIUM

- **MEDIUM-01** [file_size] audit-agents/agents/bridge_agent.py is 857 LOC (medium threshold)
- **MEDIUM-02** [function_size] audit-agents/apply_feedback.py::main is 100 LOC
- **MEDIUM-03** [function_size] audit-agents/benchmark/finding_pipeline.py::run_finding_pipeline is 166 LOC
- **MEDIUM-04** [function_size] audit-agents/benchmark/llm_runners.py::_run_claude_inner is 138 LOC
- **MEDIUM-05** [function_size] audit-agents/benchmark/poc_pipeline.py::generate_and_test_poc is 128 LOC
- **MEDIUM-06** [file_size] audit-agents/benchmark.py is 1019 LOC (medium threshold)
- **MEDIUM-07** [function_size] audit-agents/benchmark.py::generate_scorecard is 171 LOC
- **MEDIUM-08** [function_size] audit-agents/benchmark_score.py::score_benchmark is 100 LOC
- **MEDIUM-09** [file_size] audit-agents/bounty_monitor_v2.py is 1133 LOC (medium threshold)
- **MEDIUM-10** [function_size] audit-agents/bounty_monitor_v2.py::score is 142 LOC
- **MEDIUM-11** [function_size] audit-agents/build_solodit_index.py::build_index is 126 LOC
- **MEDIUM-12** [function_size] audit-agents/clippy_to_prepass.py::scan_soroban_patterns is 129 LOC
- **MEDIUM-13** [function_size] audit-agents/contract_fetcher.py::fetch_contract is 119 LOC
- **MEDIUM-14** [function_size] audit-agents/crosschain_verify.py::verify_component is 126 LOC
- **MEDIUM-15** [file_size] audit-agents/detection_engine.py is 1123 LOC (medium threshold)
- **MEDIUM-16** [function_size] audit-agents/detection_engine.py::generate_hypothesis_prompts is 186 LOC
- **MEDIUM-17** [function_size] audit-agents/detection_engine.py::_check_uninitialized_state_vars is 137 LOC
- **MEDIUM-18** [function_size] audit-agents/detection_engine.py::run_exploit_pattern_matching is 184 LOC
- **MEDIUM-19** [file_size] audit-agents/finding_pipeline.py is 1199 LOC (medium threshold)
- **MEDIUM-20** [function_size] audit-agents/finding_pipeline.py::extract_relevant_code is 117 LOC
- **MEDIUM-21** [function_size] audit-agents/finding_pipeline.py::phase_post_verify is 122 LOC
- **MEDIUM-22** [function_size] audit-agents/finding_pipeline.py::phase_post_poc is 140 LOC
- **MEDIUM-23** [function_size] audit-agents/finding_pipeline.py::phase_finalize is 135 LOC
- **MEDIUM-24** [function_size] audit-agents/gate/cli.py::main is 171 LOC
- **MEDIUM-25** [function_size] audit-agents/halmos_property_generator.py::parse_functions is 133 LOC
- **MEDIUM-26** [function_size] audit-agents/halmos_property_generator.py::generate_check_functions is 167 LOC
- **MEDIUM-27** [file_size] audit-agents/hybrid_pipeline.py is 1332 LOC (medium threshold)
- **MEDIUM-28** [file_size] audit-agents/merge_invariants.py is 1280 LOC (medium threshold)
- **MEDIUM-29** [function_size] audit-agents/merge_invariants.py::main is 120 LOC
- **MEDIUM-30** [function_size] audit-agents/plan/generator.py::generate_plan is 174 LOC
- **MEDIUM-31** [file_size] audit-agents/plan/prompts_rust.py is 807 LOC (medium threshold)
- **MEDIUM-32** [function_size] audit-agents/plan/prompts_rust.py::phase_rust_fuzz_harness_prompt is 121 LOC
- **MEDIUM-33** [function_size] audit-agents/plan/prompts_rust.py::_phase_hunter_prompt_rust is 126 LOC
- **MEDIUM-34** [file_size] audit-agents/plan/prompts_solidity.py is 988 LOC (medium threshold)
- **MEDIUM-35** [function_size] audit-agents/plan/prompts_solidity.py::phase_hunter_prompt is 103 LOC
- **MEDIUM-36** [function_size] audit-agents/plan/prompts_solidity.py::phase_deepdive_prompt is 157 LOC
- **MEDIUM-37** [function_size] audit-agents/plan/prompts_solidity.py::phase_findings is 121 LOC
- **MEDIUM-38** [function_size] audit-agents/plan/prompts_solidity.py::phase_fork_poc_prompt is 149 LOC
- **MEDIUM-39** [function_size] audit-agents/plan/prompts_solidity.py::phase_chimera_early_prompt is 119 LOC
- **MEDIUM-40** [function_size] audit-agents/scaffold.py::scaffold_project is 111 LOC
- **MEDIUM-41** [function_size] audit-agents/scope_intake.py::main is 107 LOC
- **MEDIUM-42** [function_size] audit-agents/solodit_search.py::search_sqlite is 124 LOC
- **MEDIUM-43** [function_size] audit-agents/sync_state.py::main is 102 LOC
- **MEDIUM-44** [file_size] audit-agents/target_monitor.py is 1261 LOC (medium threshold)
- **MEDIUM-45** [function_size] audit-agents/target_monitor.py::main is 107 LOC
- **MEDIUM-46** [function_size] audit-agents/target_monitor.py::_check_deployer is 125 LOC

### LOW

- **LOW-01** [todo] audit-agents/halmos_property_generator.py:380 — // TODO: Import the target contract
- **LOW-02** [todo] audit-agents/halmos_property_generator.py:384 — // TODO: Initialize target contract
- **LOW-03** [todo] audit-agents/merge_invariants.py:349 — body = inv.get("solidity_property", inv.get("solidity", "    // TODO: implement")).rstrip()
- **LOW-04** [todo] audit-agents/phase_8_audit.py:281 — _TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
- **LOW-05** [todo] audit-agents/phase_8_audit.py:332 — """Find TODO markers and unused imports in audit-agents/."""
- **LOW-06** [todo] audit-agents/poc_generator.py:40 — // TODO: Add target contract interface functions
- **LOW-07** [todo] audit-agents/poc_generator.py:75 — // TODO: Implement exploit based on finding:
- **LOW-08** [todo] audit-agents/poc_generator.py:162 — // TODO: Deploy or fork the vulnerable contract
- **LOW-09** [todo] audit-agents/poc_generator.py:199 — // TODO: Add the unprotected function signatures
- **LOW-10** [todo] audit-agents/poc_generator.py:211 — // TODO: Deploy or fork
- **LOW-11** [todo] audit-agents/poc_generator.py:257 — // TODO: Add target interface
- **LOW-12** [todo] audit-agents/poc_generator.py:283 — // TODO: Add manipulation logic
- **LOW-13** [todo] audit-agents/poc_generator.py:286 — // TODO: Add exploit logic
- **LOW-14** [todo] audit-agents/poc_generator.py:289 — // TODO: Undo the price manipulation
- **LOW-15** [todo] audit-agents/poc_generator.py:306 — // TODO: Deploy attacker, execute attack, verify profit
- **LOW-16** [todo] audit-agents/report_generator.py:178 — lines.append("<!-- TODO: Add runnable Foundry PoC -->")
- **LOW-17** [todo] audit-agents/report_generator.py:300 — lines.append("<!-- TODO: Add mainnet-fork Foundry PoC -->")
- **LOW-18** [todo] audit-agents/report_generator.py:389 — lines.append("<!-- TODO: Add runnable Foundry PoC -->")
- **LOW-19** [todo] audit-agents/scanners/vulnerability_patterns.py:1735 — "// TODO",
- **LOW-20** [todo] audit-agents/scanners/vulnerability_patterns.py:1736 — "// FIXME",
- **LOW-21** [todo] audit-agents/scanners/vulnerability_patterns.py:1737 — "// HACK",
- **LOW-22** [unused_import] audit-agents/add_finding.py:12 imports 'json' but never uses it
- **LOW-23** [unused_import] audit-agents/agents/__init__.py:1 imports 'BaseAgent' but never uses it
- **LOW-24** [unused_import] audit-agents/agents/__init__.py:2 imports 'PatternAgent' but never uses it
- **LOW-25** [unused_import] audit-agents/agents/__init__.py:3 imports 'SlitherAgent' but never uses it
- **LOW-26** [unused_import] audit-agents/agents/__init__.py:4 imports 'ReentrancyAgent' but never uses it
- **LOW-27** [unused_import] audit-agents/agents/__init__.py:5 imports 'AccessControlAgent' but never uses it
- **LOW-28** [unused_import] audit-agents/agents/__init__.py:6 imports 'OracleAgent' but never uses it
- **LOW-29** [unused_import] audit-agents/agents/__init__.py:7 imports 'LogicAgent' but never uses it
- **LOW-30** [unused_import] audit-agents/agents/__init__.py:8 imports 'GasOptimizationAgent' but never uses it
- **LOW-31** [unused_import] audit-agents/agents/__init__.py:9 imports 'ProxyAgent' but never uses it
- **LOW-32** [unused_import] audit-agents/agents/__init__.py:10 imports 'TokenAgent' but never uses it
- **LOW-33** [unused_import] audit-agents/agents/__init__.py:11 imports 'BridgeAgent' but never uses it
- **LOW-34** [unused_import] audit-agents/agents/base_agent.py:3 imports 'field' but never uses it
- **LOW-35** [unused_import] audit-agents/agents/v2/__init__.py:21 imports 'PROTOCOL_MODEL_PROMPT' but never uses it
- **LOW-36** [unused_import] audit-agents/agents/v2/__init__.py:22 imports 'INVARIANT_EXTRACTION_PROMPT' but never uses it
- **LOW-37** [unused_import] audit-agents/agents/v2/__init__.py:23 imports 'NOVELTY_IDENTIFICATION_PROMPT' but never uses it
- **LOW-38** [unused_import] audit-agents/agents/v2/__init__.py:24 imports 'INVARIANT_BREAKER_PROMPT' but never uses it
- **LOW-39** [unused_import] audit-agents/agents/v2/__init__.py:25 imports 'EXPLOIT_SYNTHESIS_PROMPT' but never uses it
- **LOW-40** [unused_import] audit-agents/agents/v2/pipeline.py:20 imports 'Optional' but never uses it
- **LOW-41** [unused_import] audit-agents/agents/v2/zk_circuit_agent.py:14 imports 'os' but never uses it
- **LOW-42** [unused_import] audit-agents/agents/v2/zk_circuit_agent.py:15 imports 're' but never uses it
- **LOW-43** [unused_import] audit-agents/agents/v2/zk_circuit_agent.py:16 imports 'json' but never uses it
- **LOW-44** [unused_import] audit-agents/agents/v2/zk_circuit_agent.py:19 imports 'Optional' but never uses it
- **LOW-45** [unused_import] audit-agents/apply_feedback.py:17 imports 'os' but never uses it
- **LOW-46** [unused_import] audit-agents/apply_feedback.py:21 imports 'glob' but never uses it
- **LOW-47** [unused_import] audit-agents/benchmark/cli.py:15 imports 'annotations' but never uses it
- **LOW-48** [unused_import] audit-agents/benchmark/cli.py:29 imports 'HUNT_SESSION_DIR' but never uses it
- **LOW-49** [unused_import] audit-agents/benchmark/component_pipeline/reporting.py:7 imports 'annotations' but never uses it
- **LOW-50** [unused_import] audit-agents/benchmark/component_pipeline/runner.py:10 imports 'annotations' but never uses it
- **LOW-51** [unused_import] audit-agents/benchmark/cross_component.py:11 imports 'annotations' but never uses it
- **LOW-52** [unused_import] audit-agents/benchmark/cross_component.py:44 imports 'shutil' but never uses it
- **LOW-53** [unused_import] audit-agents/benchmark/llm_runners.py:15 imports 'annotations' but never uses it
- **LOW-54** [unused_import] audit-agents/benchmark/llm_runners.py:17 imports '_json_mod' but never uses it
- **LOW-55** [unused_import] audit-agents/benchmark.py:27 imports 'AUDIT_AGENTS_DIR' but never uses it
- **LOW-56** [unused_import] audit-agents/benchmark_score.py:26 imports 'defaultdict' but never uses it
- **LOW-57** [unused_import] audit-agents/bounty_monitor_v2.py:25 imports 'hashlib' but never uses it
- **LOW-58** [unused_import] audit-agents/bounty_monitor_v2.py:30 imports 'sys' but never uses it
- **LOW-59** [unused_import] audit-agents/clippy_to_prepass.py:16 imports 'annotations' but never uses it
- **LOW-60** [unused_import] audit-agents/component_closer.py:1 imports 'annotations' but never uses it
- **LOW-61** [unused_import] audit-agents/component_discovery.py:1 imports 'annotations' but never uses it
- **LOW-62** [unused_import] audit-agents/context_enrichment.py:13 imports 'annotations' but never uses it
- **LOW-63** [unused_import] audit-agents/deep_flatten.py:15 imports 'sys' but never uses it
- **LOW-64** [unused_import] audit-agents/detection_engine.py:23 imports 'os' but never uses it
- **LOW-65** [unused_import] audit-agents/detection_engine.py:34 imports 'get_registry' but never uses it
- **LOW-66** [unused_import] audit-agents/detection_engine.py:34 imports 'InvariantRegistry' but never uses it
- **LOW-67** [unused_import] audit-agents/finding_pipeline.py:7 imports 'annotations' but never uses it
- **LOW-68** [unused_import] audit-agents/full_pipeline.py:24 imports 'scan_directory' but never uses it
- **LOW-69** [unused_import] audit-agents/gate/cli.py:11 imports 'HUNT_SESSION_DIR' but never uses it
- **LOW-70** [unused_import] audit-agents/gate/cli.py:361 imports 'types' but never uses it
- **LOW-71** [unused_import] audit-agents/halmos_property_generator.py:25 imports 'field' but never uses it
- **LOW-72** [unused_import] audit-agents/hunter_context.py:11 imports 'annotations' but never uses it
- **LOW-73** [unused_import] audit-agents/hunter_context.py:15 imports 'WEB3_DIR' but never uses it
- **LOW-74** [unused_import] audit-agents/hybrid_pipeline.py:36 imports 'json' but never uses it
- **LOW-75** [unused_import] audit-agents/hybrid_pipeline.py:39 imports 'os' but never uses it
- **LOW-76** [unused_import] audit-agents/ingest_rejections.py:18 imports 'json' but never uses it
- **LOW-77** [unused_import] audit-agents/matcher.py:10 imports 'os' but never uses it
- **LOW-78** [unused_import] audit-agents/matcher.py:11 imports 're' but never uses it
- **LOW-79** [unused_import] audit-agents/matcher.py:12 imports 'subprocess' but never uses it
- **LOW-80** [unused_import] audit-agents/matcher.py:13 imports 'tempfile' but never uses it
- **LOW-81** [unused_import] audit-agents/merge_invariants.py:51 imports 'STATE_FILE' but never uses it
- **LOW-82** [unused_import] audit-agents/paths.py:11 imports 'annotations' but never uses it
- **LOW-83** [unused_import] audit-agents/phase_8_audit.py:6 imports 'annotations' but never uses it
- **LOW-84** [unused_import] audit-agents/pipeline_gate.py:54 imports 'WEB3_DIR' but never uses it
- **LOW-85** [unused_import] audit-agents/pipeline_gate.py:54 imports 'HUNT_SESSION_DIR' but never uses it
- **LOW-86** [unused_import] audit-agents/pipeline_gate.py:54 imports 'STATE_FILE' but never uses it
- **LOW-87** [unused_import] audit-agents/pipeline_gate.py:55 imports 'load_state' but never uses it
- **LOW-88** [unused_import] audit-agents/pipeline_gate.py:55 imports '_sm_save_state' but never uses it
- **LOW-89** [unused_import] audit-agents/plan/cli.py:2 imports 'annotations' but never uses it
- **LOW-90** [unused_import] audit-agents/plan/detectors.py:7 imports 'annotations' but never uses it
- **LOW-91** [unused_import] audit-agents/plan/generator.py:10 imports 'annotations' but never uses it
- **LOW-92** [unused_import] audit-agents/plan/post_compile.py:6 imports 'annotations' but never uses it
- **LOW-93** [unused_import] audit-agents/plan/prompts_rust.py:14 imports 'annotations' but never uses it
- **LOW-94** [unused_import] audit-agents/plan/prompts_solidity.py:9 imports 'annotations' but never uses it
- **LOW-95** [unused_import] audit-agents/plan_schema.py:8 imports 'annotations' but never uses it
- **LOW-96** [unused_import] audit-agents/plan_schema.py:11 imports 'asdict' but never uses it
- **LOW-97** [unused_import] audit-agents/registry.py:10 imports 'os' but never uses it
- **LOW-98** [unused_import] audit-agents/scaffold.py:20 imports 'os' but never uses it
- **LOW-99** [unused_import] audit-agents/scaffold.py:27 imports 'get_registry' but never uses it
- **LOW-100** [unused_import] audit-agents/solodit_to_wiki.py:7 imports 'annotations' but never uses it
- **LOW-101** [unused_import] audit-agents/state_manager.py:14 imports 'annotations' but never uses it
- **LOW-102** [unused_import] audit-agents/symmetric_analyzer.py:17 imports 'sys' but never uses it
- **LOW-103** [unused_import] audit-agents/target_monitor.py:34 imports 're' but never uses it
- **LOW-104** [unused_import] audit-agents/target_monitor.py:35 imports 'sys' but never uses it
- **LOW-105** [unused_import] audit-agents/target_monitor.py:38 imports 'timedelta' but never uses it
- **LOW-106** [unused_import] audit-agents/utils/__init__.py:1 imports 'console' but never uses it
- **LOW-107** [unused_import] audit-agents/utils/__init__.py:1 imports 'banner' but never uses it
- **LOW-108** [unused_import] audit-agents/utils/__init__.py:1 imports 'agent_start' but never uses it
- **LOW-109** [unused_import] audit-agents/utils/__init__.py:1 imports 'agent_done' but never uses it
- **LOW-110** [unused_import] audit-agents/utils/__init__.py:1 imports 'finding' but never uses it
- **LOW-111** [unused_import] audit-agents/utils/__init__.py:1 imports 'info' but never uses it
- **LOW-112** [unused_import] audit-agents/utils/__init__.py:1 imports 'error' but never uses it
- **LOW-113** [unused_import] audit-agents/utils/__init__.py:1 imports 'results_table' but never uses it
- **LOW-114** [unused_import] audit-agents/utils/__init__.py:2 imports 'parse_solidity' but never uses it
- **LOW-115** [unused_import] audit-agents/utils/__init__.py:2 imports 'SolidityContract' but never uses it
- **LOW-116** [unused_import] audit-agents/utils/__init__.py:2 imports 'SolidityFunction' but never uses it
- **LOW-117** [shim_size] run_benchmark.py is 52 LOC (expected <50)
- **LOW-118** [orphan_reexport] run_benchmark.py re-exports 'HUNT_SESSION_DIR' with 0 consumers — sunset candidate
- **LOW-119** [orphan_reexport] run_benchmark.py re-exports 'AUDIT_AGENTS_DIR' with 0 consumers — sunset candidate
- **LOW-120** [orphan_reexport] run_benchmark.py re-exports 'run_claude' with 0 consumers — sunset candidate
- **LOW-121** [orphan_reexport] run_benchmark.py re-exports '_run_claude_inner' with 0 consumers — sunset candidate
- **LOW-122** [orphan_reexport] run_benchmark.py re-exports 'run_claude_sub' with 0 consumers — sunset candidate
- **LOW-123** [orphan_reexport] run_benchmark.py re-exports '_llm' with 0 consumers — sunset candidate
- **LOW-124** [orphan_reexport] run_benchmark.py re-exports 'run_cmd' with 0 consumers — sunset candidate
- **LOW-125** [orphan_reexport] run_benchmark.py re-exports '_extract_first_errors' with 0 consumers — sunset candidate
- **LOW-126** [orphan_reexport] run_benchmark.py re-exports '_CLAUDE_SEMAPHORE' with 0 consumers — sunset candidate
- **LOW-127** [orphan_reexport] run_benchmark.py re-exports '_AGENTIC_TOOLS' with 0 consumers — sunset candidate
- **LOW-128** [orphan_reexport] run_benchmark.py re-exports 'load_prompt' with 0 consumers — sunset candidate
- **LOW-129** [orphan_reexport] run_benchmark.py re-exports 'read_source' with 0 consumers — sunset candidate
- **LOW-130** [orphan_reexport] run_benchmark.py re-exports 'build_hunter_brief' with 0 consumers — sunset candidate
- **LOW-131** [orphan_reexport] run_benchmark.py re-exports 'build_hunter_dispatch_prompt' with 0 consumers — sunset candidate
- **LOW-132** [orphan_reexport] run_benchmark.py re-exports 'build_deepdive_prompt' with 0 consumers — sunset candidate
- **LOW-133** [orphan_reexport] run_benchmark.py re-exports 'build_poc_prompt' with 0 consumers — sunset candidate
- **LOW-134** [orphan_reexport] run_benchmark.py re-exports 'build_escalation_prompt' with 0 consumers — sunset candidate
- **LOW-135** [orphan_reexport] run_benchmark.py re-exports 'build_redteam_prompt' with 0 consumers — sunset candidate
- **LOW-136** [orphan_reexport] run_benchmark.py re-exports 'build_variant_prompt' with 0 consumers — sunset candidate
- **LOW-137** [orphan_reexport] run_benchmark.py re-exports 'build_report_prompt' with 0 consumers — sunset candidate
- **LOW-138** [orphan_reexport] run_benchmark.py re-exports 'build_cross_pair_prompt' with 0 consumers — sunset candidate
- **LOW-139** [orphan_reexport] run_benchmark.py re-exports 'fix_and_retry' with 0 consumers — sunset candidate
- **LOW-140** [orphan_reexport] run_benchmark.py re-exports '_generate_foundry_tester_wrappers' with 0 consumers — sunset candidate
- **LOW-141** [orphan_reexport] run_benchmark.py re-exports '_log_funnel' with 0 consumers — sunset candidate
- **LOW-142** [orphan_reexport] run_benchmark.py re-exports '_sanitize_sol_unicode' with 0 consumers — sunset candidate
- **LOW-143** [orphan_reexport] run_benchmark.py re-exports '_filter_errors_for_file' with 0 consumers — sunset candidate
- **LOW-144** [orphan_reexport] run_benchmark.py re-exports 'generate_and_test_poc' with 0 consumers — sunset candidate
- **LOW-145** [orphan_reexport] run_benchmark.py re-exports 'run_component_pipeline' with 0 consumers — sunset candidate
- **LOW-146** [orphan_reexport] run_benchmark.py re-exports 'parse_fuzz_failures' with 0 consumers — sunset candidate
- **LOW-147** [orphan_reexport] run_benchmark.py re-exports 'extract_findings' with 0 consumers — sunset candidate
- **LOW-148** [orphan_reexport] run_benchmark.py re-exports 'run_finding_pipeline' with 0 consumers — sunset candidate
- **LOW-149** [orphan_reexport] run_benchmark.py re-exports 'run_cross_component' with 0 consumers — sunset candidate
- **LOW-150** [orphan_reexport] run_benchmark.py re-exports '_create_worktree' with 0 consumers — sunset candidate
- **LOW-151** [orphan_reexport] run_benchmark.py re-exports '_remove_worktree' with 0 consumers — sunset candidate
- **LOW-152** [orphan_reexport] run_benchmark.py re-exports '_maybe_run_apply_feedback' with 0 consumers — sunset candidate
- **LOW-153** [orphan_reexport] run_benchmark.py re-exports '_resolve_components' with 0 consumers — sunset candidate
- **LOW-154** [orphan_reexport] run_benchmark.py re-exports '_extract_relevant_code' with 0 consumers — sunset candidate
- **LOW-155** [orphan_reexport] run_benchmark.py re-exports 'build_verify_prompt' with 0 consumers — sunset candidate
- **LOW-156** [orphan_reexport] run_benchmark.py re-exports 'build_is_same_bug_prompt' with 0 consumers — sunset candidate
- **LOW-157** [orphan_reexport] run_benchmark.py re-exports 'POC_CONFIDENCE_THRESHOLD' with 0 consumers — sunset candidate
- **LOW-158** [orphan_reexport] run_benchmark.py re-exports 'setup_logging' with 0 consumers — sunset candidate
- **LOW-159** [orphan_reexport] run_benchmark.py re-exports 'check_gate' with 0 consumers — sunset candidate
- **LOW-160** [orphan_reexport] run_benchmark.py re-exports 'main' with 0 consumers — sunset candidate
- **LOW-161** [orphan_reexport] run_benchmark.py re-exports 'logger' with 0 consumers — sunset candidate
- **LOW-162** [orphan_reexport] run_benchmark.py re-exports 'SCRIPT_DIR' with 0 consumers — sunset candidate
- **LOW-163** [orphan_reexport] plan_generator.py re-exports '_detect_primary_domain' with 0 consumers — sunset candidate
- **LOW-164** [orphan_reexport] plan_generator.py re-exports '_read_file_safe' with 0 consumers — sunset candidate
- **LOW-165** [orphan_reexport] plan_generator.py re-exports '_detect_lang' with 0 consumers — sunset candidate
- **LOW-166** [orphan_reexport] plan_generator.py re-exports '_src_dir' with 0 consumers — sunset candidate
- **LOW-167** [orphan_reexport] plan_generator.py re-exports '_find_cargo_workspace' with 0 consumers — sunset candidate
- **LOW-168** [orphan_reexport] plan_generator.py re-exports '_find_rust_crate_src' with 0 consumers — sunset candidate
- **LOW-169** [orphan_reexport] plan_generator.py re-exports '_rust_crate_sources' with 0 consumers — sunset candidate
- **LOW-170** [orphan_reexport] plan_generator.py re-exports '_results_dir' with 0 consumers — sunset candidate
- **LOW-171** [orphan_reexport] plan_generator.py re-exports '_hyp_dir' with 0 consumers — sunset candidate
- **LOW-172** [orphan_reexport] plan_generator.py re-exports '_step_id' with 0 consumers — sunset candidate
- **LOW-173** [orphan_reexport] plan_generator.py re-exports '_rpc_var' with 0 consumers — sunset candidate
- **LOW-174** [orphan_reexport] plan_generator.py re-exports '_fork_sol_snippet' with 0 consumers — sunset candidate
- **LOW-175** [orphan_reexport] plan_generator.py re-exports '_worktree_path' with 0 consumers — sunset candidate
- **LOW-176** [orphan_reexport] plan_generator.py re-exports '_last_step_id' with 0 consumers — sunset candidate
- **LOW-177** [orphan_reexport] plan_generator.py re-exports 'generate_plan' with 0 consumers — sunset candidate
- **LOW-178** [orphan_reexport] plan_generator.py re-exports '_add_component_steps' with 0 consumers — sunset candidate
- **LOW-179** [orphan_reexport] plan_generator.py re-exports '_add_cross_component_steps' with 0 consumers — sunset candidate
- **LOW-180** [orphan_reexport] plan_generator.py re-exports 'phase_hunter_prompt' with 0 consumers — sunset candidate
- **LOW-181** [orphan_reexport] plan_generator.py re-exports 'phase_deepdive_prompt' with 0 consumers — sunset candidate
- **LOW-182** [orphan_reexport] plan_generator.py re-exports 'phase_findings' with 0 consumers — sunset candidate
- **LOW-183** [orphan_reexport] plan_generator.py re-exports 'phase_fork_poc_prompt' with 0 consumers — sunset candidate
- **LOW-184** [orphan_reexport] plan_generator.py re-exports 'phase_cross_prompt' with 0 consumers — sunset candidate
- **LOW-185** [orphan_reexport] plan_generator.py re-exports 'phase_transitive_chain_prompt' with 0 consumers — sunset candidate
- **LOW-186** [orphan_reexport] plan_generator.py re-exports 'phase_chimera_early_prompt' with 0 consumers — sunset candidate
- **LOW-187** [orphan_reexport] plan_generator.py re-exports 'phase_chimera_builder_prompt' with 0 consumers — sunset candidate
- **LOW-188** [orphan_reexport] plan_generator.py re-exports 'phase_enhance_targets_prompt' with 0 consumers — sunset candidate
- **LOW-189** [orphan_reexport] plan_generator.py re-exports 'phase_rust_fuzz_scaffold_prompt' with 0 consumers — sunset candidate
- **LOW-190** [orphan_reexport] plan_generator.py re-exports 'phase_rust_fuzz_harness_prompt' with 0 consumers — sunset candidate
- **LOW-191** [orphan_reexport] plan_generator.py re-exports 'phase_rust_merge_harness' with 0 consumers — sunset candidate
- **LOW-192** [orphan_reexport] plan_generator.py re-exports '_rust_enhance_fuzz_prompt' with 0 consumers — sunset candidate
- **LOW-193** [orphan_reexport] plan_generator.py re-exports '_phase_hunter_prompt_rust' with 0 consumers — sunset candidate
- **LOW-194** [orphan_reexport] plan_generator.py re-exports '_phase_findings_rust' with 0 consumers — sunset candidate
- **LOW-195** [orphan_reexport] plan_generator.py re-exports '_phase_cross_prompt_rust' with 0 consumers — sunset candidate
- **LOW-196** [orphan_reexport] plan_generator.py re-exports 'phase_write_fork_setup' with 0 consumers — sunset candidate
- **LOW-197** [orphan_reexport] plan_generator.py re-exports 'phase_post_compile' with 0 consumers — sunset candidate
- **LOW-198** [orphan_reexport] plan_generator.py re-exports 'phase_checkpoint' with 0 consumers — sunset candidate
- **LOW-199** [orphan_reexport] plan_generator.py re-exports 'main' with 0 consumers — sunset candidate

## Roadmap closure

Phase 8 status: **COMPLETE**. Verdict: **PARTIAL**.

Next: Phase 9+ addresses the backlog above, prioritized by severity.
