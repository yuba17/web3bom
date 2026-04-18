#!/usr/bin/env python3
"""
plan_generator.py — Generates an execution_plan.json for agent-mode benchmarks.

Two entry points:
  1. --generate: produces a full ExecutionPlan JSON for the skill to execute.
  2. --phase <name>: called MID-EXECUTION to dynamically generate steps
     (hunter prompts, deepdive prompts, findings collection, cross-component, checkpoints).

Usage:
    # Generate full plan
    python3 audit-agents/plan_generator.py --generate \
        --repo /path/to/repo --components Strategy,Leverager \
        --protocol yieldoor --session-dir /path/to/bench_session \
        --ground-truth benchmarks/yieldoor/benchmark.yaml

    # Dynamic phase (called by skill mid-execution)
    python3 audit-agents/plan_generator.py --phase hunter-prompt \
        --component Strategy --protocol yieldoor \
        --repo /path/to/repo --session-dir /path/to/bench_session
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Ensure audit-agents is on the path for sibling imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

from plan_schema import Step, ExecutionPlan
from context_enrichment import build_hunter_context

# ─── Constants ────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
VERSION = "1.0.0"


# ─── Detectors (extracted to plan/detectors in Phase 6) ───
from plan.detectors import (  # noqa: F401
    _detect_primary_domain, _read_file_safe, _detect_lang, _src_dir,
    _find_cargo_workspace, _find_rust_crate_src, _rust_crate_sources,
    _results_dir, _hyp_dir, _step_id, _rpc_var, _fork_sol_snippet,
    _worktree_path, _last_step_id,
)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Main plan generator
# ═══════════════════════════════════════════════════════════════════════════════

def generate_plan(
    repo: str,
    components: list[str],
    protocol: str,
    session_dir: str,
    ground_truth: str = "",
    is_pre_production: bool = True,
    fast: bool = False,
    benchmark_mode: str = "redteam",
    parallel_components: int = 1,
    chain: str = "mainnet",
    fork_block: int = 0,
    lang: str = "",
) -> ExecutionPlan:
    """Build a complete ExecutionPlan for the given components.

    When *parallel_components* > 1 and there are more components than that
    limit, the plan is split into **team sub-plans** for real parallel
    execution via Agent Teams.  The master plan contains only the
    cross-component + scoring steps and a ``teams`` metadata block that
    the executor skill uses to orchestrate.
    """

    # Resolve language and chain config
    lang = _detect_lang(repo, lang)
    rpc_env_var = _rpc_var(chain)

    hyp_dir = str(_hyp_dir(session_dir, protocol))

    plan = ExecutionPlan(
        version=VERSION,
        protocol=protocol,
        repo=repo,
        session_dir=session_dir,
        hypotheses_dir=hyp_dir,
        components=components,
        is_pre_production=is_pre_production,
        lang=lang,
    )

    # ── Decide parallelism strategy ─────────────────────────────────────
    use_teams = parallel_components > 1 and len(components) > 1
    use_wt = len(components) > 1  # worktrees for merge/compile/fuzz isolation

    if use_teams:
        # Split components into groups of `parallel_components`
        groups: list[list[str]] = []
        for i in range(0, len(components), parallel_components):
            groups.append(components[i:i + parallel_components])

        # Generate a sub-plan for each group
        team_groups_meta: list[dict] = []
        for gidx, group in enumerate(groups):
            sub_plan = ExecutionPlan(
                version=VERSION,
                protocol=protocol,
                repo=repo,
                session_dir=session_dir,
                hypotheses_dir=hyp_dir,
                components=group,
                is_pre_production=is_pre_production,
                lang=lang,
            )
            sub_wt = len(group) > 1
            prev_comp: str | None = None
            for comp in group:
                # Pipeline overlap: Comp2's API phases (prepass→hunters→deepdive)
                # start when Comp1 enters its CPU phase (after deepdive).
                # Comp2's forge phases (create_worktree+) wait for Comp1's forge to finish.
                # This overlaps API-only work with CPU-bound forge — no hardware contention.
                chain_after = _step_id(prev_comp, "hunters") if prev_comp else None
                forge_after = _step_id(prev_comp, "cleanup_worktree") if prev_comp else None
                _add_component_steps(sub_plan, comp, repo, protocol,
                                     session_dir, fast,
                                     use_worktrees=sub_wt,
                                     benchmark_mode=benchmark_mode,
                                     chain=chain,
                                     fork_block=fork_block,
                                     lang=lang,
                                     parallel_components=parallel_components,
                                     chain_after=chain_after,
                                     forge_after=forge_after,
                                     is_pre_production=is_pre_production)
                prev_comp = comp

            sub_path = str(Path(session_dir) / f"execution_plan_group_{gidx}.json")
            sub_plan.to_json(sub_path)

            team_groups_meta.append({
                "group_id": gidx,
                "components": group,
                "plan_file": sub_path,
                "agent_name": f"group-{gidx}",
            })

        # Master plan: teams metadata + cross-component + scoring only
        plan.teams = {
            "parallel_components": parallel_components,
            "groups": team_groups_meta,
        }

        # Sentinel step: the skill marks this done after all team agents
        # report completion.  Cross-component steps depend on it.
        plan.add_step(Step(
            id="all_groups_done",
            type="bash",
            description="Sync point — all team agents have completed",
            command="echo 'All component groups finished'",
            timeout=10,
        ))

        # Verification gate: validate all team outputs before cross-component
        groups_json = json.dumps(team_groups_meta)
        plan.add_step(Step(
            id="verify_teams",
            type="gate",
            description="Verify all team agents produced expected outputs",
            command=(
                f"{sys.executable} {SCRIPT_DIR / 'verify_team_outputs.py'} "
                f"--session-dir {session_dir} "
                f"--protocol {protocol} "
                f"--groups '{groups_json}'"
            ),
            depends_on=["all_groups_done"],
            timeout=60,
        ))

        # Cross-component steps (only if >1 component)
        if len(components) > 1:
            _add_cross_component_steps(plan, components, repo, protocol,
                                       session_dir,
                                       benchmark_mode=benchmark_mode,
                                       override_deps=["verify_teams"],
                                       lang=lang)

    else:
        # Single-group mode: all component steps in the master plan (sequential)
        prev_checkpoint = None
        for comp in components:
            _add_component_steps(plan, comp, repo, protocol, session_dir,
                                 fast, use_worktrees=use_wt,
                                 benchmark_mode=benchmark_mode,
                                 chain=chain,
                                 fork_block=fork_block,
                                 lang=lang,
                                 chain_after=prev_checkpoint,
                                 is_pre_production=is_pre_production)
            prev_checkpoint = _step_id(comp, "checkpoint")

        # Cross-component steps (only if >1 component)
        if len(components) > 1:
            _add_cross_component_steps(plan, components, repo, protocol,
                                       session_dir,
                                       benchmark_mode=benchmark_mode,
                                       lang=lang)

    # Scoring step (if ground truth provided)
    if ground_truth:
        last_dep = _last_step_id(plan, components)
        plan.add_step(Step(
            id="scoring",
            type="bash",
            description="Score findings against ground truth",
            command=(
                f"{sys.executable} {SCRIPT_DIR / 'benchmark_score.py'} "
                f"--ground-truth {ground_truth} "
                f"--hypotheses-dir {hyp_dir} "
                f"--components {','.join(components)}"
            ),
            depends_on=[last_dep],
            timeout=120,
        ))

    return plan


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Component steps
# ═══════════════════════════════════════════════════════════════════════════════

def _add_component_steps(
    plan: ExecutionPlan,
    comp: str,
    repo: str,
    protocol: str,
    session_dir: str,
    fast: bool,
    use_worktrees: bool = True,
    chain: str = "mainnet",
    fork_block: int = 0,
    benchmark_mode: str = "redteam",
    lang: str = "solidity",
    parallel_components: int = 1,
    chain_after: str | None = None,
    forge_after: str | None = None,
    is_pre_production: bool = False,
) -> None:
    """Add the sequential steps for a single component.

    When use_worktrees=True (default for multi-component), merge/compile/fuzz
    run in an isolated git worktree so components can execute in parallel safely.

    Pipeline overlap: *chain_after* gates the API-only phases (prepass→hunters→deepdive).
    *forge_after* gates the CPU-heavy phases (create_worktree→compile→fuzz).
    This allows Comp2's hunters to overlap with Comp1's fuzz (API vs CPU, no contention).

    When lang="rust", Solidity-specific steps (chimera, merge, foundry fuzz)
    are replaced with Rust equivalents (cargo clippy, cargo build, cargo test).
    """

    is_rust = (lang == "rust")
    src_dir = _src_dir(repo, lang, comp)
    results_dir = _results_dir(session_dir)
    hyp_dir = _hyp_dir(session_dir, protocol)
    gen_cmd = f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'}"
    lang_flag = f" --lang {lang}"

    # Worktree: isolated repo copy for merge/compile/fuzz
    wt_path = _worktree_path(protocol, comp)
    # Steps that modify repo (merge, compile, fuzz) use worktree cwd
    repo_for_build = wt_path if use_worktrees else repo

    # ── 1. Prepass ──
    if is_rust:
        # Rust: cargo clippy as static analysis + Soroban pattern scanning
        cargo_ws = _find_cargo_workspace(repo)
        # Limit clippy jobs to avoid CPU/RAM spikes when multiple crates
        # are analysed in parallel across groups (same rationale as compile).
        prepass_cmd = (
            f"cd {cargo_ws} && CARGO_BUILD_JOBS=3 cargo clippy -p {comp} --all-targets "
            f"--message-format=json 2>/dev/null | "
            f"{sys.executable} {SCRIPT_DIR / 'clippy_to_prepass.py'} "
            f"--name {comp} --output {results_dir}/ "
            f"--src-dir {src_dir}"
        )
    else:
        prepass_cmd = (
            f"{sys.executable} {SCRIPT_DIR / 'detection_engine.py'} "
            f"--prepass --source {src_dir}/{comp}.sol "
            f"--name {comp} --output {results_dir}/"
        )
    prepass_deps = [chain_after] if chain_after else []
    plan.add_step(Step(
        id=_step_id(comp, "prepass"),
        type="bash",
        description=f"Run {'clippy' if is_rust else 'detection engine'} prepass for {comp}",
        command=prepass_cmd,
        depends_on=prepass_deps,
        timeout=120,
        retry=1,
    ))

    # ── 1.9. Chimera early setup (Solidity only) ──
    # Rust skips this: Soroban projects already have test infrastructure (TestSetup,
    # mock_auth, client patterns). No scaffold needed before hunters.
    if not is_rust:
        plan.add_step(Step(
            id=_step_id(comp, "chimera_early_check"),
            type="generate",
            description=f"Check if Chimera Setup exists and build early setup prompt for {comp}",
            command=(
                f"{gen_cmd} --phase chimera-early-prompt "
                f"--component {comp} --protocol {protocol} "
                f"--repo {repo} --session-dir {session_dir}{lang_flag}"
                + (f" --parallel-components {parallel_components}" if parallel_components > 1 else "")
            ),
            depends_on=[_step_id(comp, "prepass")],
            timeout=60,
        ))
        plan.add_step(Step(
            id=_step_id(comp, "chimera_early_setup"),
            type="agent",
            description=f"Generate early Chimera Setup for {comp} (hunter context)",
            prompt="__DYNAMIC__",
            tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            depends_on=[_step_id(comp, "chimera_early_check")],
            timeout=1200,
            retry=1,
        ))
        hunter_dep = _step_id(comp, "chimera_early_setup")
    else:
        # Rust: hunters depend directly on prepass (no scaffold step)
        hunter_dep = _step_id(comp, "prepass")

    # ── 2. Build hunter prompt ──
    plan.add_step(Step(
        id=_step_id(comp, "build_hunter_prompt"),
        type="generate",
        description=f"Build hunter brief and dispatch prompt for {comp}",
        command=(
            f"{gen_cmd} --phase hunter-prompt "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}{lang_flag}"
        ),
        depends_on=[hunter_dep],
        timeout=60,
    ))

    # ── 3. Hunters ──
    plan.add_step(Step(
        id=_step_id(comp, "hunters"),
        type="agent",
        description=f"Run 12 parallel hunters for {comp}",
        prompt="__DYNAMIC__",
        tools=["Agent", "Read", "Write", "Edit", "Grep", "Glob"],
        depends_on=[_step_id(comp, "build_hunter_prompt")],
        timeout=1800,
        retry=1,
    ))

    # ── 4. Build DeepDive prompt ──
    plan.add_step(Step(
        id=_step_id(comp, "build_deepdive_prompt"),
        type="generate",
        description=f"Build DeepDive prompt for {comp}",
        command=(
            f"{gen_cmd} --phase deepdive-prompt "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}{lang_flag}"
        ),
        depends_on=[_step_id(comp, "hunters")],
        timeout=60,
    ))

    # ── 5. DeepDive ──
    plan.add_step(Step(
        id=_step_id(comp, "deepdive"),
        type="agent",
        description=f"DeepDive analysis for {comp}",
        prompt="__DYNAMIC__",
        tools=["Read", "Write", "Edit", "Grep", "Glob"],
        depends_on=[_step_id(comp, "build_deepdive_prompt")],
        timeout=1800,
        retry=1,
    ))

    # ── Worktree boundary: from here, steps MODIFY the repo ──

    if use_worktrees:
        if is_rust:
            # Rust: create worktree and verify cargo workspace resolves
            cargo_ws_rel = str(Path(_find_cargo_workspace(repo)).relative_to(Path(repo)))
            wt_cargo_ws = f"{wt_path}/{cargo_ws_rel}" if cargo_ws_rel != "." else wt_path
            wt_create_cmd = (
                f"git -C {repo} worktree prune && "
                f"rm -rf {wt_path} && "
                f"git -C {repo} worktree add -f --detach {wt_path} HEAD && "
                f"cd {wt_cargo_ws} && cargo metadata --no-deps --format-version 1 > /dev/null 2>&1 && "
                f"echo 'Worktree created (Rust workspace OK): {wt_path}'"
            )
        else:
            # Solidity: create worktree, copy .env, and patch foundry.toml
            # Find .env by walking up from the ORIGINAL repo (not the worktree)
            env_copy_cmd = ""
            for parent in [Path(repo), Path(repo).parent, Path(repo).parent.parent, Path(repo).parent.parent.parent]:
                if (parent / ".env").exists():
                    env_copy_cmd = f"cp {parent / '.env'} {wt_path}/.env && "
                    break
            wt_create_cmd = (
                f"git -C {repo} worktree prune && "
                f"rm -rf {wt_path} && "
                f"git -C {repo} worktree add -f --detach {wt_path} HEAD && "
                f"{env_copy_cmd}"
                f"if [ -f {wt_path}/foundry.toml ] && ! grep -q rpc_endpoints {wt_path}/foundry.toml; then "
                f"  echo -e '\\n[rpc_endpoints]\\nmainnet = \"${{ETH_RPC_URL}}\"\\nbase = \"${{BASE_RPC_URL}}\"' >> {wt_path}/foundry.toml; "
                f"fi && "
                f"echo 'Worktree created: {wt_path}'"
            )
        # Worktree depends on deepdive (own API work done) AND forge_after
        # (previous component's forge finished — no CPU contention).
        wt_deps = [_step_id(comp, "deepdive")]
        if forge_after:
            wt_deps.append(forge_after)
        plan.add_step(Step(
            id=_step_id(comp, "create_worktree"),
            type="bash",
            description=f"Create git worktree for {comp}",
            command=wt_create_cmd,
            depends_on=wt_deps,
            timeout=60,
        ))
        build_dep = _step_id(comp, "create_worktree")
    else:
        build_dep = _step_id(comp, "deepdive")

    # ── Solidity: chimera_builder + merge | Rust: fuzz_harness + merge_harness ──
    if not is_rust:
        plan.add_step(Step(
            id=_step_id(comp, "chimera_builder_check"),
            type="generate",
            description=f"Check if full Chimera Setup needed and build prompt for {comp}",
            command=(
                f"{gen_cmd} --phase chimera-builder-prompt "
                f"--component {comp} --protocol {protocol} "
                f"--repo {repo_for_build} --session-dir {session_dir}{lang_flag}"
                + (f" --parallel-components {parallel_components}" if parallel_components > 1 else "")
            ),
            depends_on=[build_dep],
            timeout=60,
        ))
        plan.add_step(Step(
            id=_step_id(comp, "chimera_builder"),
            type="agent",
            description=f"Generate/verify Chimera Setup for {comp} (pre-merge)",
            prompt="__DYNAMIC__",
            tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            depends_on=[_step_id(comp, "chimera_builder_check")],
            timeout=1200,
            retry=1,
        ))
        plan.add_step(Step(
            id=_step_id(comp, "merge"),
            type="bash",
            description=f"Merge invariants for {comp}",
            command=(
                f"{sys.executable} {SCRIPT_DIR / 'merge_invariants.py'} "
                f"--component {comp} --hyp-dir {hyp_dir} --repo {repo_for_build}"
            ),
            depends_on=[_step_id(comp, "chimera_builder")],
            timeout=120,
        ))
        compile_dep = _step_id(comp, "merge")
    else:
        # Rust: single fuzz_harness agent (combines chimera_builder + enhance_targets)
        # Reads ALL hunter hypotheses, generates invariant tests + attack sequences
        # in ONE step. Then merge_harness validates compilation.
        plan.add_step(Step(
            id=_step_id(comp, "fuzz_harness_check"),
            type="generate",
            description=f"Build fuzz harness prompt for {comp} (invariants + attacks from hunters)",
            command=(
                f"{gen_cmd} --phase rust-fuzz-harness-prompt "
                f"--component {comp} --protocol {protocol} "
                f"--repo {repo_for_build} --session-dir {session_dir}{lang_flag}"
            ),
            depends_on=[build_dep],
            timeout=60,
        ))
        plan.add_step(Step(
            id=_step_id(comp, "fuzz_harness"),
            type="agent",
            description=f"Generate fuzz harness: invariants + attack sequences for {comp}",
            prompt="__DYNAMIC__",
            tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            depends_on=[_step_id(comp, "fuzz_harness_check")],
            timeout=1200,
            retry=1,
        ))
        plan.add_step(Step(
            id=_step_id(comp, "merge_harness"),
            type="bash",
            description=f"Validate and merge fuzz harness for {comp}",
            command=(
                f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'} "
                f"--phase rust-merge-harness "
                f"--component {comp} --protocol {protocol} "
                f"--repo {repo_for_build} --session-dir {session_dir}{lang_flag}"
            ),
            depends_on=[_step_id(comp, "fuzz_harness")],
            timeout=120,
        ))
        compile_dep = _step_id(comp, "merge_harness")

    # ── Compile ──
    compile_retry = 3
    if is_rust:
        cargo_ws_build = _find_cargo_workspace(repo_for_build)
        # Limit cargo parallelism to avoid OOM when multiple crates compile
        # simultaneously across worktrees (8 cores / 10 GB RAM baseline).
        # 3 jobs per crate × 3 worktrees = 9 threads — fits in 8 cores with
        # minor contention, and keeps peak RSS well under available RAM.
        compile_cmd = (
            f"cd {cargo_ws_build} && "
            f"CARGO_BUILD_JOBS=3 cargo build -p {comp} 2>&1 && "
            f"CARGO_BUILD_JOBS=3 cargo test -p {comp} --no-run 2>&1"
        )
    else:
        # Limit forge parallelism when multiple components compile simultaneously
        # to avoid OOM (8 cores / 10 GB RAM baseline). 3 threads per component
        # × 2 parallel components = 6 threads peak.
        forge_jobs = " --jobs 3" if parallel_components > 1 else ""
        compile_cmd = f"cd {repo_for_build} && forge build{forge_jobs}"
    plan.add_step(Step(
        id=_step_id(comp, "compile"),
        type="bash",
        description=f"{'cargo build' if is_rust else 'forge build'} for {comp}",
        command=compile_cmd,
        cwd=repo_for_build,
        depends_on=[compile_dep],
        timeout=300,
        retry=compile_retry,
    ))

    # ── Post-compile (emit fuzz/test steps) ──
    plan.add_step(Step(
        id=_step_id(comp, "post_compile"),
        type="generate",
        description=f"Check compile result and emit {'test' if is_rust else 'fuzz'} steps for {comp}",
        command=(
            f"{gen_cmd} --phase post-compile "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo_for_build} --session-dir {session_dir}"
            + (" --fast" if fast else "")
            + (f" --parallel-components {parallel_components}" if parallel_components > 1 else "")
            + (" --pre-production" if is_pre_production else "")
            + lang_flag
        ),
        depends_on=[_step_id(comp, "compile")],
        timeout=60,
    ))

    # ── End worktree boundary ──

    if use_worktrees:
        # Depend on post_fuzz sentinel (emitted by phase_post_compile) so that
        # dynamically-injected fuzz steps finish BEFORE the worktree is removed.
        plan.add_step(Step(
            id=_step_id(comp, "cleanup_worktree"),
            type="bash",
            description=f"Remove git worktree for {comp}",
            command=(
                f"git -C {repo} worktree remove --force {wt_path} 2>/dev/null; "
                f"rm -rf {wt_path}; echo 'Worktree cleaned: {wt_path}'"
            ),
            depends_on=[_step_id(comp, "post_fuzz")],
            timeout=30,
        ))
        findings_dep = _step_id(comp, "cleanup_worktree")
    else:
        findings_dep = _step_id(comp, "post_compile")

    # ── Collect findings ──
    plan.add_step(Step(
        id=_step_id(comp, "collect_findings"),
        type="generate",
        description=f"Collect and process findings for {comp}",
        command=(
            f"{gen_cmd} --phase findings "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}"
            f" --benchmark-mode {benchmark_mode}"
            f" --chain {chain} --fork-block {fork_block}"
            f"{lang_flag}"
            + (f" --parallel-components {parallel_components}" if parallel_components > 1 else "")
        ),
        depends_on=[findings_dep],
        timeout=60,
    ))

    # ── Checkpoint ──
    plan.add_step(Step(
        id=_step_id(comp, "checkpoint"),
        type="bash",
        description=f"Write checkpoint for {comp}",
        command=(
            f"{gen_cmd} --phase checkpoint "
            f"--component {comp} --protocol {protocol} "
            f"--session-dir {session_dir}"
        ),
        depends_on=[_step_id(comp, "collect_findings")],
        timeout=30,
    ))


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Cross-component steps
# ═══════════════════════════════════════════════════════════════════════════════

def _add_cross_component_steps(
    plan: ExecutionPlan,
    components: list[str],
    repo: str,
    protocol: str,
    session_dir: str,
    benchmark_mode: str = "redteam",
    override_deps: list[str] | None = None,
    lang: str = "solidity",
) -> None:
    """Add cross-component analysis steps for all pairs.

    *override_deps* replaces the default checkpoint dependencies.  Used in
    team mode where cross-component runs after all team agents complete
    (represented by the synthetic ``all_groups_done`` sentinel).
    """

    gen_cmd = f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'}"

    # All component checkpoints must complete first (unless overridden)
    checkpoint_deps = override_deps or [_step_id(c, "checkpoint") for c in components]

    pair_prompt_ids = []
    pair_agent_ids = []

    for comp_a, comp_b in itertools.combinations(components, 2):
        pair_tag = f"{comp_a}_{comp_b}"

        # Build cross prompt
        prompt_id = f"cross:{pair_tag}:build_prompt"
        plan.add_step(Step(
            id=prompt_id,
            type="generate",
            description=f"Build cross-component prompt for {comp_a} x {comp_b}",
            command=(
                f"{gen_cmd} --phase cross-prompt "
                f"--component {comp_a},{comp_b} --protocol {protocol} "
                f"--repo {repo} --session-dir {session_dir} --lang {lang}"
            ),
            depends_on=checkpoint_deps,
            parallel_group="cross_prompts",
            timeout=60,
        ))
        pair_prompt_ids.append(prompt_id)

        # Cross pair agent
        agent_id = f"cross:{pair_tag}:analyze"
        plan.add_step(Step(
            id=agent_id,
            type="agent",
            description=f"Cross-component analysis: {comp_a} x {comp_b}",
            prompt="__DYNAMIC__",
            tools=["Read", "Write", "Grep", "Glob"],
            depends_on=[prompt_id],
            parallel_group="cross_pairs",
            timeout=900,
        ))
        pair_agent_ids.append(agent_id)

    # Final cross-component checkpoint
    plan.add_step(Step(
        id="cross:checkpoint",
        type="bash",
        description="Cross-component checkpoint",
        command=(
            f"{gen_cmd} --phase checkpoint "
            f"--component cross --protocol {protocol} "
            f"--session-dir {session_dir}"
        ),
        depends_on=["parallel_group:cross_pairs"],
        timeout=30,
    ))



# ═══════════════════════════════════════════════════════════════════════════════
# 4. Dynamic phase generators (--phase handlers)
# ═══════════════════════════════════════════════════════════════════════════════

# ─── Solidity prompts (extracted to plan/prompts_solidity in Phase 6) ───────
from plan.prompts_solidity import (  # noqa: F401
    phase_hunter_prompt, phase_deepdive_prompt, phase_findings,
    phase_fork_poc_prompt, phase_cross_prompt, phase_transitive_chain_prompt,
    phase_chimera_early_prompt, phase_chimera_builder_prompt,
    phase_enhance_targets_prompt,
)


## ─── Rust Fuzz Pipeline Phases ────────────────────────────────────────────────
#
# These mirror the Solidity chimera/fuzz pipeline:
#   Solidity: chimera_early → hunters → chimera_builder → merge → compile → enhance → fuzz → medusa
#   Rust:     fuzz_scaffold → hunters → fuzz_harness → merge_harness → compile → enhance_fuzz → cargo_test → cargo_fuzz


def phase_rust_fuzz_scaffold_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "rust",
) -> list[dict]:
    """Generate the fuzz scaffold prompt (Rust equivalent of chimera_early_prompt).

    Creates a basic test harness with setup, teardown, and placeholders for
    invariant properties — gives hunters context about the testing pattern.
    """
    src_dir = _src_dir(repo, lang, component)
    crate_dir = src_dir.parent

    # Read existing test patterns
    test_patterns = ""
    for test_dir in [crate_dir / "src" / "tests", crate_dir / "tests"]:
        if test_dir.exists():
            for tf in sorted(test_dir.glob("*.rs"))[:3]:
                content = _read_file_safe(tf, max_chars=4000)
                test_patterns += f"\n// === {tf.name} ===\n{content}\n"
            break

    # Read contract source (first 15K)
    source_code = _rust_crate_sources(repo, component)[:15000]

    # Read prepass findings
    results_dir = _results_dir(session_dir)
    prepass = _read_file_safe(results_dir / f"{component}_prepass.yaml", max_chars=3000)

    prompt = (
        f"Generate a fuzz test SCAFFOLD for the Rust/Soroban crate `{component}` in `{protocol}`.\n\n"
        f"This is the EARLY scaffold (before hunters run) — similar to Chimera Setup in Solidity.\n"
        f"The scaffold provides a testing framework that hunters will reference.\n\n"
        f"## Source Code (key files)\n"
        f"```rust\n{source_code[:12000]}\n```\n\n"
        f"## Existing Test Patterns (COPY this style)\n"
        f"```rust\n{test_patterns[:6000]}\n```\n\n"
        f"## Prepass Findings (clippy)\n"
        f"```yaml\n{prepass}\n```\n\n"
        f"## What to Generate\n"
        f"Create file: `{crate_dir}/src/tests/fuzz_scaffold.rs`\n\n"
        f"The scaffold MUST include:\n"
        f"1. **FuzzSetup struct** — wraps `Env`, contract client, test accounts (owner, attacker, user)\n"
        f"   - Use the SAME pattern as existing tests (TestSetup::new() style)\n"
        f"   - Deploy the contract with default params\n"
        f"2. **Helper methods** on FuzzSetup:\n"
        f"   - `random_action(&self, seed: u64)` — picks a random contract function and calls it\n"
        f"   - `check_invariants(&self)` — placeholder, will be filled by fuzz_harness step\n"
        f"3. **Basic invariant stubs** (at least 5):\n"
        f"   - `invariant_no_panic` — any sequence of calls doesn't panic\n"
        f"   - `invariant_auth_required` — unprivileged calls are rejected\n"
        f"   - `invariant_state_consistent` — storage state is internally consistent\n"
        f"   - `invariant_balance_conservation` — if tokens involved, sum is conserved\n"
        f"   - `invariant_ttl_extended` — storage entries have TTL set\n"
        f"4. **10-iteration loop test** that calls `random_action` then `check_invariants`\n\n"
        f"## Rules\n"
        f"- Use `soroban_sdk::Env::default()` for environment\n"
        f"- Use `Address::generate(&env)` for test addresses\n"
        f"- Import from the crate's own modules (check Cargo.toml for crate name)\n"
        f"- MUST compile: `cargo test -p {component} --no-run 2>&1` — run this to verify\n"
        f"- If existing tests use a TestSetup, REUSE it — don't reinvent\n"
        f"- Add `mod fuzz_scaffold;` to `tests/mod.rs` if a mod.rs exists\n"
    )

    return [{
        "step_id": _step_id(component, "fuzz_scaffold"),
        "prompt": prompt,
    }]


def phase_rust_fuzz_harness_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "rust",
) -> list[dict]:
    """Generate the COMPLETE fuzz harness prompt — single agent, all-in-one.

    Rust equivalent of chimera_builder + enhance_targets combined.
    Reads ALL hunter hypotheses and generates:
    - Invariant tests (Properties.sol equivalent)
    - Target function handlers (TargetFunctions.sol equivalent)
    - Attack sequences (enhance_targets equivalent)
    - Property-based loop tests (Medusa sequence equivalent)
    """
    src_dir = _src_dir(repo, lang, component)
    crate_dir = src_dir.parent
    hyp_dir = _hyp_dir(session_dir, protocol)
    cargo_ws = _find_cargo_workspace(repo)

    # Read ALL hunter hypotheses
    hyp_texts: list[str] = []
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        content = _read_file_safe(hyp_file, max_chars=3000)
        hyp_texts.append(f"### {hyp_file.stem}\n{content}")
    hunter_findings = "\n\n".join(hyp_texts[:15])

    # Read existing test patterns from the project
    test_patterns = ""
    for test_dir in [crate_dir / "src" / "tests", crate_dir / "tests"]:
        if test_dir.exists():
            for tf in sorted(test_dir.glob("*.rs"))[:3]:
                content = _read_file_safe(tf, max_chars=4000)
                test_patterns += f"\n// === {tf.name} ===\n{content}\n"
            break

    # Read contract source
    source_code = _rust_crate_sources(repo, component)[:20000]

    # Read prepass
    results_dir = _results_dir(session_dir)
    prepass = _read_file_safe(results_dir / f"{component}_prepass.yaml", max_chars=2000)

    prompt = (
        f"Generate a COMPLETE fuzz test harness for `{component}` in `{protocol}` [Rust/Soroban].\n\n"
        f"This is the Rust equivalent of Properties.sol + TargetFunctions.sol + enhance_targets combined.\n"
        f"You are generating ALL invariant tests, attack sequences, and property tests in ONE step.\n\n"

        f"## Hunter Hypotheses (the bugs to test)\n"
        f"{hunter_findings[:15000]}\n\n"

        f"## Clippy Prepass\n```yaml\n{prepass}\n```\n\n"

        f"## Source Code\n```rust\n{source_code[:15000]}\n```\n\n"

        f"## Existing Test Patterns (COPY this style exactly)\n"
        f"```rust\n{test_patterns[:8000]}\n```\n\n"

        f"## Output File\n"
        f"Create: `{crate_dir}/src/tests/fuzz_harness.rs`\n"
        f"Add `mod fuzz_harness;` to `{crate_dir}/src/tests/mod.rs` if mod.rs exists.\n\n"

        f"## Required Test Categories\n\n"

        f"### A. Invariant Tests (1 per hypothesis, minimum 10)\n"
        f"Name: `test_invariant_<hypothesis_id>`\n"
        f"- Set up the EXACT precondition from the hypothesis\n"
        f"- Execute the EXACT attack sequence described\n"
        f"- Assert the specific invariant (balance, auth, state)\n"
        f"- Use concrete boundary values, not random\n"
        f"- If test FAILS → bug found. If PASSES → invariant holds.\n\n"

        f"### B. Property-Based Loop Tests (minimum 5)\n"
        f"Name: `test_proptest_<name>`\n"
        f"- Loop 50-100 iterations with varied inputs per iteration\n"
        f"- Use seed-based input generation: `let amount = (seed * 7919) % u128::MAX;`\n"
        f"- Boundary values: 0, 1, u128::MAX, i128::MIN+1, i128::MAX\n"
        f"- Empty vectors, max-length vectors, zero-address, self-address\n"
        f"- Check invariants AFTER each iteration\n\n"

        f"### C. Multi-Step Sequence Tests (minimum 3)\n"
        f"Name: `test_sequence_<name>`\n"
        f"- Chain 5-10 contract calls in specific order\n"
        f"- State transitions: register→deregister, set_admin→remove_admin\n"
        f"- Interleave privileged and unprivileged calls\n"
        f"- Interleave different accounts (owner, admin, attacker, user)\n"
        f"- Assert state consistency after the full sequence\n\n"

        f"### D. Optimization Tests (minimum 2)\n"
        f"Name: `test_optimize_<name>`\n"
        f"- Find maximum extractable value via varied amounts\n"
        f"- Find sequence that maximizes attacker profit\n"
        f"- Track a `max_profit` variable across iterations\n\n"

        f"### E. Frontrun/Sandwich Tests (if applicable)\n"
        f"Name: `test_frontrun_<name>`\n"
        f"- Two accounts: victim + attacker\n"
        f"- Attacker acts before victim, then after\n"
        f"- Measure attacker profit vs victim loss\n\n"

        f"## Ghost Variable Tracking\n"
        f"Use test-local variables to track cumulative state:\n"
        f"```rust\n"
        f"let mut total_deposited: i128 = 0;\n"
        f"let mut total_withdrawn: i128 = 0;\n"
        f"// ... after each action, update and assert:\n"
        f"assert!(total_deposited >= total_withdrawn, \"conservation violated\");\n"
        f"```\n\n"

        f"## Rules\n"
        f"- Use the project's existing TestSetup/mock_auth patterns — do NOT reinvent\n"
        f"- MUST compile: `cd {cargo_ws} && cargo test -p {component} --no-run 2>&1` — run to verify\n"
        f"- If compilation fails, fix and re-run (up to 3 attempts)\n"
        f"- If a hypothesis is untestable (requires external oracle, cross-chain state), skip with comment\n"
        f"- Soroban-specific: use `env.as_contract()` for internal state access\n"
        f"- Soroban-specific: `require_auth` tests need `mock_auths` or `mock_all_auths`\n"
        f"- Soroban-specific: check TTL extension with `env.storage().instance().get_ttl()`\n"
    )

    return [{
        "step_id": _step_id(component, "fuzz_harness"),
        "prompt": prompt,
    }]


def phase_rust_merge_harness(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "rust",
) -> None:
    """Merge and validate fuzz harness (Rust equivalent of merge_invariants.py).

    1. Reads ALL hunter hypotheses → counts how many have test coverage in harness
    2. Reads fuzz_harness.rs → counts test functions by category
    3. Verifies compilation with cargo test --no-run
    4. Writes detailed summary to results/
    """
    import subprocess
    import re

    src_dir = _src_dir(repo, lang, component)
    crate_dir = src_dir.parent
    hyp_dir = _hyp_dir(session_dir, protocol)
    cargo_ws = _find_cargo_workspace(repo)

    # Find harness file
    harness_path = None
    harness_content = ""
    for test_dir in [crate_dir / "src" / "tests", crate_dir / "tests"]:
        candidate = test_dir / "fuzz_harness.rs"
        if candidate.exists():
            harness_path = str(candidate)
            harness_content = candidate.read_text(encoding="utf-8")
            break

    # Count tests by category
    test_counts = {
        "invariant": len(re.findall(r"fn\s+test_invariant_", harness_content)),
        "proptest": len(re.findall(r"fn\s+test_proptest_", harness_content)),
        "sequence": len(re.findall(r"fn\s+test_sequence_", harness_content)),
        "optimize": len(re.findall(r"fn\s+test_optimize_", harness_content)),
        "frontrun": len(re.findall(r"fn\s+test_frontrun_", harness_content)),
        "total": harness_content.count("#[test]"),
    }

    # Count hunter hypotheses and check coverage
    hyp_count = 0
    covered = 0
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        hyp_content = _read_file_safe(hyp_file, max_chars=5000)
        # Count hypotheses (each - id: line is a hypothesis)
        ids = re.findall(r"^\s*id:\s*(\S+)", hyp_content, re.MULTILINE)
        for hid in ids:
            hyp_count += 1
            # Check if this hypothesis has a test in the harness
            if hid.lower().replace("-", "_") in harness_content.lower():
                covered += 1

    # Verify compilation
    compile_ok = False
    compile_error = ""
    try:
        result = subprocess.run(
            ["cargo", "test", "-p", component, "--no-run"],
            cwd=cargo_ws, capture_output=True, text=True, timeout=120,
        )
        compile_ok = result.returncode == 0
        if not compile_ok:
            compile_error = result.stderr[-2000:] if result.stderr else ""
    except Exception as e:
        compile_error = str(e)

    summary = {
        "component": component,
        "harness_file": harness_path or "NOT FOUND",
        "test_counts": test_counts,
        "hypotheses_total": hyp_count,
        "hypotheses_covered": covered,
        "coverage_pct": round(covered / hyp_count * 100) if hyp_count > 0 else 0,
        "compile_ok": compile_ok,
    }
    if compile_error:
        summary["compile_error"] = compile_error

    # Write summary
    out_path = Path(session_dir) / "results" / f"{component}_harness_summary.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))


def _rust_enhance_fuzz_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
) -> str:
    """Build prompt for enhancing Rust fuzz targets with attack sequences.

    Equivalent to Solidity's enhance_targets_prompt — adds targeted attack
    sequences based on Phase 1 test results.
    """
    src_dir = _find_rust_crate_src(repo, component)
    crate_dir = src_dir.parent

    # Read harness summary if available
    summary_path = Path(session_dir) / "results" / f"{component}_harness_summary.json"
    summary = _read_file_safe(summary_path, max_chars=2000)

    # Read existing harness
    harness = ""
    for test_dir in [crate_dir / "src" / "tests", crate_dir / "tests"]:
        hf = test_dir / "fuzz_harness.rs"
        if hf.exists():
            harness = _read_file_safe(hf, max_chars=10000)
            break

    return (
        f"Enhance the fuzz test harness for `{component}` in `{protocol}` with targeted attack sequences.\n\n"
        f"This is the equivalent of Solidity's enhance-targets step — add concrete exploit sequences.\n\n"
        f"## Current Harness\n"
        f"```rust\n{harness[:8000]}\n```\n\n"
        f"## Harness Summary\n{summary}\n\n"
        f"## What to Add\n"
        f"Add to the existing fuzz_harness.rs file:\n\n"
        f"1. **Optimization tests** (equivalent to Echidna optimize_*):\n"
        f"   - `test_optimize_profit` — find the maximum extractable value\n"
        f"   - `test_optimize_drain` — find sequence that drains the most funds\n"
        f"   - These use loops with varied amounts to maximize some metric\n\n"
        f"2. **Sandwich/frontrun sequences**:\n"
        f"   - `test_frontrun_<function>` — attacker front-runs user TX\n"
        f"   - Use two accounts: victim and attacker\n"
        f"   - Measure attacker profit\n\n"
        f"3. **Flash-loan-equivalent sequences** (for Soroban: same-TX multi-call):\n"
        f"   - Deposit → exploit → withdraw in same test\n"
        f"   - Check if contract state is manipulable within one sequence\n\n"
        f"4. **Boundary value tests**:\n"
        f"   - All numeric params: 0, 1, u128::MAX, i128::MIN+1, i128::MAX\n"
        f"   - Empty vectors, max-length vectors\n"
        f"   - Zero-address, self-address\n\n"
        f"## Rules\n"
        f"- Edit the EXISTING fuzz_harness.rs — don't create new files\n"
        f"- MUST compile: `cargo test -p {component} --no-run 2>&1`\n"
        f"- Run: `cargo test -p {component} test_optimize_ -- --nocapture 2>&1` to verify\n"
        f"- Use the project's test infrastructure (TestSetup, mock_auth, etc.)\n"
    )


def _phase_hunter_prompt_rust(
    component: str, protocol: str, repo: str, session_dir: str,
    hyp_dir: Path, results_dir: Path,
) -> list[dict]:
    """Build hunter brief + dispatch for Rust/Soroban components."""

    src_dir = _find_rust_crate_src(repo, component)
    source_code = _rust_crate_sources(repo, component)

    # Prepass signals
    prepass_path = results_dir / f"{component}_prepass.yaml"
    prepass_signals_text = _read_file_safe(prepass_path, max_chars=4000)

    # Cargo.toml for dependency context
    crate_dir = src_dir.parent
    cargo_toml = _read_file_safe(crate_dir / "Cargo.toml", max_chars=3000)

    # Protocol model
    protocol_model = ""
    model_path = Path(session_dir) / "context" / f"{protocol}_model.md"
    if model_path.exists():
        protocol_model = _read_file_safe(model_path, max_chars=3000)

    # Read docs if present
    docs_text = ""
    docs_dir = Path(repo) / "docs"
    if docs_dir.exists():
        for doc in sorted(docs_dir.rglob("*.md"))[:5]:
            docs_text += _read_file_safe(doc, max_chars=3000)
            if len(docs_text) > 10000:
                break

    brief_content = (
        f"# Hunter Brief — {component} ({protocol}) [RUST/SOROBAN]\n\n"
        f"## Source Files to Read\n"
        f"- Crate src directory: {src_dir}\n"
        f"- Read ALL .rs files in this directory (excluding tests/)\n\n"
        f"## Protocol Model\n{protocol_model[:3000] if protocol_model else 'Read the source to understand the protocol.'}\n\n"
        f"## Documentation\n{docs_text[:5000] if docs_text else 'No docs found. Read source code carefully.'}\n\n"
        f"## Prepass Signals (clippy/static analysis)\n```yaml\n{prepass_signals_text[:4000] if prepass_signals_text else 'None'}\n```\n\n"
        f"## Cargo.toml (dependencies)\n```toml\n{cargo_toml}\n```\n\n"
        f"## SOROBAN-SPECIFIC ATTACK SURFACES\n"
        f"- **TTL Expiry**: Storage entries expire. Can an attacker grief by NOT extending TTL?\n"
        f"- **Storage Read Limits**: Soroban limits 200 reads/tx. Can state grow unbounded?\n"
        f"- **No Reentrancy**: Soroban prevents reentrancy, but cross-contract call ordering matters.\n"
        f"- **bytes32 ↔ Address**: LayerZero uses bytes32, Stellar uses variable-length. Conversion bugs?\n"
        f"- **Abstract Account Pattern**: DVN/Executor use __check_auth. Auth bypass?\n"
        f"- **i128 Arithmetic**: Soroban uses i128 natively. Overflow/underflow in checked vs wrapping?\n"
        f"- **require_auth**: Missing auth checks on privileged functions?\n"
        f"- **Ed25519 Signatures**: Replay, malleability, missing nonce validation?\n"
        f"- **Multisig**: Threshold manipulation, signer management edge cases?\n\n"
        f"## OUTPUT RULES\n"
        f"1. Write YAML to ABSOLUTE PATH: {hyp_dir}/hyp_{component}_<YourHunterName>.yaml\n"
        f"2. Each hypothesis MUST have `rust_test`: a complete #[test] function body (or pseudocode if test framework not available)\n"
        f"3. Also include `vulnerable_location` with file path, function, line numbers, vulnerable code, and fix\n"
        f"4. Confidence >= 60% for validated: true\n"
        f"5. Minimum 5 hypotheses, no maximum\n"
        f"6. YAML schema: id, tier, type, description, attack_scenario, rust_test, validated, priority, confidence, vulnerable_location, severity\n"
        f"7. `vulnerable_location` format:\n"
        f"   ```yaml\n"
        f"   vulnerable_location:\n"
        f"     file: \"endpoint_v2.rs\"\n"
        f"     function: \"send\"\n"
        f"     lines: [142, 143]\n"
        f"     vulnerable_code: \"let nonce = self.nonce + 1;\"  # wrapping addition, not checked\n"
        f"     fix: \"use checked_add and handle overflow\"\n"
        f"   ```\n"
    )

    # Write brief
    brief_path = Path(session_dir) / f"hunter_brief_{component}.md"
    brief_path.parent.mkdir(parents=True, exist_ok=True)
    brief_path.write_text(brief_content, encoding="utf-8")

    # Dispatch prompt — use Rust-native hunter methodologies
    methodology_dir = Path(__file__).resolve().parent / "prompts" / "hunters" / "rust"
    dispatch_prompt = f"""You are the Hunt Coordinator for {component} in {protocol} [RUST/SOROBAN].

Your ONLY job: launch 12 hunter subagents in parallel using the Agent tool, then wait for all to complete.

## CRITICAL: THIS IS RUST/SOROBAN, NOT SOLIDITY
- Source files are .rs, not .sol
- No EVM, no Foundry, no Chimera
- Soroban-specific: TTL expiry, storage limits (200 reads/tx), no reentrancy, i128 arithmetic
- LayerZero-specific: DVN verification, message replay, nonce handling, bytes32 address conversion
- Auth pattern: require_auth(), __check_auth, Abstract Account
- Hunters use RUST-NATIVE methodologies at {methodology_dir}/

## INSTRUCTION FOR EACH AGENT
Every agent prompt MUST follow this template:

"You are [HunterName] analyzing {component} in {protocol}.
THIS IS RUST/SOROBAN CODE, NOT SOLIDITY.

Read these files FIRST:
1. {brief_path} — protocol context, Soroban attack surfaces, output rules
2. {methodology_dir}/[HunterName].md — your RUST-NATIVE hunting methodology

Then read ALL .rs source files in: {src_dir}/

Follow your methodology EXACTLY — it is written specifically for Rust/Soroban.
Complete ALL mandatory analysis tables from your methodology file.
Write rust_test field (not solidity_property) in your YAML output.

Write YAML to {hyp_dir}/hyp_{component}_[HunterName].yaml"

## The 12 Hunters (ALL in parallel)
1. **MathHunter** — i128 arithmetic, checked/wrapping/as truncation, precision, signed overflow
2. **AccessHunter** — require_auth, __check_auth bypass, RBAC, initialization, storage key collision
3. **FlowHunter** — cross-contract call ordering, state transitions, ABA pattern, derived state
4. **OracleHunter** — cross-chain message verification, DVN validation, staleness, price feeds
5. **DomainHunter** — protocol invariants, nonce sequencing, conservation laws, message ordering
6. **TrustBoundaryHunter** — external contract trust, Abstract Account auth, upgrade authority, token trust
7. **WildcardHunter** — TTL expiry griefing, storage limit DoS, WASM fuel, composition attacks
8. **SignatureHunter** — Ed25519, multisig threshold, nonce replay, __check_auth, cross-chain replay
9. **DoSHunter** — unbounded storage growth, panic points, TTL expiry, 200 read limit, fuel exhaustion
10. **LogicHunter** — variable shadowing, copy-paste, wrong fields, match arms, boolean inversions
11. **AdversarialHunter** — backward from exits, value extraction, timing, multi-message ordering
12. **LibraryHunter** — workspace crate bugs, macro expansion, shared trait edge cases, serialization

Launch ALL 12 NOW in a single response."""

    return [{
        "step_id": _step_id(component, "hunters"),
        "prompt": dispatch_prompt,
    }]


def _phase_findings_rust(
    findings: list[dict], component: str, protocol: str, repo: str,
    session_dir: str, benchmark_mode: str, src_dir: Path,
) -> list[dict]:
    """Rust findings pipeline: Rust PoC test + RedTeam.

    PoC = a #[test] function using soroban_sdk::Env that reproduces the bug.
    No mainnet fork (Soroban has no fork testing), but local integration tests
    using the SDK's test environment are the equivalent.
    """
    steps: list[dict] = []
    POC_PARALLEL = 2
    batches = [findings[i:i + POC_PARALLEL] for i in range(0, len(findings), POC_PARALLEL)]

    # Read existing test patterns from the project
    test_patterns = ""
    crate_dir = src_dir.parent
    test_dir = crate_dir / "src" / "tests"
    if not test_dir.exists():
        test_dir = crate_dir / "tests"
    if test_dir.exists():
        for tf in sorted(test_dir.glob("*.rs"))[:3]:
            content = _read_file_safe(tf, max_chars=4000)
            test_patterns += f"\n// === {tf.name} ===\n{content}\n"

    prev_batch_ids: list[str] = []

    for batch_idx, batch in enumerate(batches):
        batch_poc_ids: list[str] = []

        for i_in_batch, f in enumerate(batch):
            global_idx = batch_idx * POC_PARALLEL + i_in_batch
            fid = f.get("id", f"F-{component}-{global_idx:03d}")
            severity = f.get("severity", "Unknown")
            title = f.get("title", f.get("description", "N/A"))[:80]
            description = f.get("description", "N/A")
            attack = f.get("attack_scenario", "N/A")
            rust_test = f.get("rust_test", "")
            confidence = f.get("confidence", 0)

            # ── Rust PoC step ──
            poc_step_id = f"{component}:rust_poc:{fid}"
            batch_poc_ids.append(poc_step_id)

            cargo_ws = _find_cargo_workspace(repo)
            poc_prompt = (
                f"Write a HIGH-QUALITY Rust/Soroban integration test (PoC) for this finding in {component} ({protocol}).\n\n"
                f"## Finding\n"
                f"- ID: {fid}\n"
                f"- Title: {title}\n"
                f"- Severity: {severity}\n"
                f"- Confidence: {confidence}%\n"
                f"- Description: {description}\n"
                f"- Attack scenario: {attack}\n\n"
                f"## Suggested Test Code (from hunter)\n"
                f"```rust\n{rust_test}\n```\n\n"
                f"## Source Code Location\n"
                f"- Crate src: {src_dir}/\n"
                f"- Crate Cargo.toml: {crate_dir}/Cargo.toml\n"
                f"- Workspace root: {cargo_ws}\n\n"
                f"## Existing Test Patterns (how THEY write tests — COPY THIS STYLE)\n"
                f"```rust\n{test_patterns[:8000]}\n```\n\n"
                f"## SOROBAN PoC PATTERNS (mandatory)\n\n"
                f"### Setup Pattern\n"
                f"```rust\n"
                f"// ALWAYS start with the project's own TestSetup if available\n"
                f"use crate::tests::setup::{{setup, TestSetup}}; // or endpoint_setup, etc.\n\n"
                f"// If no TestSetup exists, create a minimal one:\n"
                f"let env = Env::default();\n"
                f"env.mock_all_auths(); // or use specific mock_auths for auth testing\n"
                f"let owner = Address::generate(&env);\n"
                f"let attacker = Address::generate(&env);\n"
                f"let contract_id = env.register(MyContract, (&owner, &init_args));\n"
                f"let client = MyContractClient::new(&env, &contract_id);\n"
                f"```\n\n"
                f"### Auth Testing Pattern\n"
                f"```rust\n"
                f"// For testing missing require_auth:\n"
                f"env.mock_auths(&[]); // NO auths mocked — call should fail\n"
                f"let result = client.try_privileged_fn(&attacker); // should panic or return Err\n"
                f"assert!(result.is_err(), \"privileged function callable without auth\");\n\n"
                f"// For testing auth bypass:\n"
                f"env.mock_auths(&[MockAuth {{\n"
                f"    address: &attacker,\n"
                f"    invoke: &MockAuthInvoke {{\n"
                f"        contract: &contract_id,\n"
                f"        fn_name: \"admin_fn\",\n"
                f"        args: (&attacker,).into_val(&env),\n"
                f"        sub_invokes: &[],\n"
                f"    }},\n"
                f"}}]);\n"
                f"```\n\n"
                f"### Balance/State Verification Pattern\n"
                f"```rust\n"
                f"// Token balances:\n"
                f"let balance_before = token_client.balance(&victim);\n"
                f"// ... execute attack ...\n"
                f"let balance_after = token_client.balance(&victim);\n"
                f"assert!(balance_after < balance_before, \"funds not stolen — PoC fails\");\n"
                f"let profit = token_client.balance(&attacker);\n"
                f"assert!(profit > 0, \"attacker gained nothing — PoC fails\");\n\n"
                f"// Internal state via env.as_contract:\n"
                f"let stored_val: i128 = env.as_contract(&contract_id, || {{\n"
                f"    env.storage().instance().get(&DataKey::Balance).unwrap()\n"
                f"}});\n"
                f"```\n\n"
                f"### Ledger Time Manipulation\n"
                f"```rust\n"
                f"// For TTL/time-dependent bugs:\n"
                f"env.ledger().set(LedgerInfo {{\n"
                f"    timestamp: 1000,\n"
                f"    protocol_version: 22,\n"
                f"    sequence_number: 100,\n"
                f"    ..env.ledger().get()\n"
                f"}});\n"
                f"// ... set up state ...\n"
                f"env.ledger().set(LedgerInfo {{\n"
                f"    timestamp: 1000 + 86400 * 30, // 30 days later\n"
                f"    sequence_number: 200,\n"
                f"    ..env.ledger().get()\n"
                f"}});\n"
                f"// ... TTL expired, state should be lost or corrupted\n"
                f"```\n\n"
                f"### Nonce/Replay Testing\n"
                f"```rust\n"
                f"// For message replay bugs:\n"
                f"let msg = create_test_message(&env, nonce_1, dst_eid);\n"
                f"client.receive(&msg); // first delivery — should succeed\n"
                f"let result = client.try_receive(&msg); // replay — should fail\n"
                f"assert!(result.is_err(), \"message replay succeeded — nonce not enforced\");\n"
                f"```\n\n"
                f"### Bytes32 Conversion Testing\n"
                f"```rust\n"
                f"// For truncation/padding bugs:\n"
                f"let short_addr = BytesN::<32>::from_array(&env, &[0u8; 32]); // zero-padded\n"
                f"let result = client.try_send_to(&short_addr); // may be misinterpreted\n"
                f"// Verify the address was NOT treated as valid\n"
                f"```\n\n"
                f"## Instructions\n"
                f"1. **Read** the crate's existing tests FIRST — find TestSetup/setup() and REUSE it\n"
                f"2. **Create** PoC in `{crate_dir}/src/tests/poc_{fid}.rs` as a new test module\n"
                f"3. **Add** `mod poc_{fid};` to `{crate_dir}/src/tests/mod.rs`\n"
                f"4. The test MUST:\n"
                f"   - Name: `test_poc_{fid}` with `#[test]` attribute\n"
                f"   - Use the project's TestSetup (not custom setup unless needed)\n"
                f"   - Set up BOTH legitimate state AND attack preconditions\n"
                f"   - Execute the EXACT attack sequence from the finding\n"
                f"   - Assert the CONCRETE impact: fund loss, auth bypass, state corruption\n"
                f"   - Print key values with `std::println!` for debugging output\n"
                f"   - If test PASSES → the bug is real. If it PANICS at the assert → no bug.\n"
                f"5. **Compile check**: `cd {cargo_ws} && cargo test -p {component} --no-run 2>&1`\n"
                f"6. **Run PoC**: `cd {cargo_ws} && cargo test -p {component} test_poc_{fid} -- --nocapture 2>&1`\n"
                f"7. **Write result** to {session_dir}/poc_{fid}.json:\n"
                f"   {{\"finding_id\": \"{fid}\", \"poc_passed\": true/false, "
                f"\"poc_path\": \"<path to test file>\", \"output\": \"<test output>\"}}\n\n"
                f"## QUALITY RULES\n"
                f"- PoC MUST use project's own test infrastructure (TestSetup, mock patterns)\n"
                f"- PoC MUST compile AND run — if compilation fails, fix it (up to 3 attempts)\n"
                f"- PoC MUST demonstrate CONCRETE impact (not just \"this function is callable\")\n"
                f"- Add `extern crate std;` at top of test module if using println!\n"
                f"- If the crate needs [dev-dependencies], add them to Cargo.toml\n"
                f"- A passing test that asserts the attack SUCCEEDED = bug confirmed\n"
                f"- A failing test (panic at assert) = bug NOT confirmed, report poc_passed=false"
            )

            steps.append({
                "id": poc_step_id,
                "type": "agent",
                "description": f"Rust PoC for {fid}: {title}",
                "prompt": poc_prompt,
                "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
                "depends_on": prev_batch_ids[:] if prev_batch_ids else [],
                "parallel_group": f"{component}:poc_batch_{batch_idx}",
                "timeout": 600,
                "retry": 1,
            })

            # ── RedTeam step (redteam mode only, sequential after PoC) ──
            if benchmark_mode == "redteam":
                steps.append({
                    "id": f"{component}:redteam:{fid}",
                    "type": "agent",
                    "description": f"RedTeam {fid}: {title}",
                    "prompt": (
                        f"RedTeam this finding for {component} in {protocol} [RUST/SOROBAN].\n"
                        f"Act as 4 adversarial reviewers trying to KILL this finding.\n\n"
                        f"## Finding Details\n"
                        f"- ID: {fid}\n"
                        f"- Title: {title}\n"
                        f"- Severity: {severity}\n"
                        f"- Confidence: {f.get('confidence', 0)}%\n"
                        f"- Hunter: {f.get('hunter', 'N/A')}\n"
                        f"- Description: {f.get('description', 'N/A')}\n"
                        f"- Attack: {f.get('attack_scenario', 'N/A')}\n\n"
                        f"## Your Task\n"
                        f"1. Read the Rust source code at {src_dir}/\n"
                        f"2. Check if a PoC test exists and passed (check {session_dir}/poc_{fid}.json)\n"
                        f"3. Apply rejection rules:\n"
                        f"   - R1: Attack requires admin/owner role → REJECT\n"
                        f"   - R2: No-op function by design → REJECT\n"
                        f"   - R3: Off-chain config signal → REJECT\n"
                        f"   - R4: File/crate not in scope → REJECT\n"
                        f"   - R5: No funds at risk, no access control bypass → REJECT\n"
                        f"4. SOROBAN-SPECIFIC CHECKS:\n"
                        f"   - Is this actually exploitable given Soroban's no-reentrancy model?\n"
                        f"   - Does TTL expiry make this a temporary DoS or permanent state loss?\n"
                        f"   - Storage read limit (200 reads/tx) — does the attack fit within one tx?\n"
                        f"   - Cross-contract calls are NOT reentrant in Soroban — does the attack assume reentrancy?\n"
                        f"   - Auth model: require_auth is checked at tx level — can attacker mock auth?\n"
                        f"5. Check PoC quality: does `{session_dir}/poc_{fid}.json` show poc_passed=true?\n"
                        f"   If PoC exists and passed → strong evidence. If no PoC → weaker.\n"
                        f"6. Conclude with ONE of:\n"
                        f"   RESULTADO: REPORT | REPORT_DOWNGRADED | DO_NOT_REPORT\n\n"
                        f"Write verdict to: {session_dir}/redteam_{fid}.json\n"
                        f"Format: {{\"finding_id\": \"{fid}\", \"verdict\": \"...\", "
                        f"\"kill_reason\": \"...\", \"severity_adjustment\": \"...\"}}"
                    ),
                    "tools": ["Read", "Write", "Grep", "Glob", "Bash"],
                    "depends_on": [poc_step_id],
                    "timeout": 300,
                })

        prev_batch_ids = batch_poc_ids[:]

    return steps if steps else [{"status": "rust_findings_processed", "component": component}]


# ─── Post-compile steps (extracted to plan/post_compile in Phase 6) ───
from plan.post_compile import (  # noqa: F401
    phase_write_fork_setup, phase_post_compile, phase_checkpoint,
)


def _phase_cross_prompt_rust(
    comp_a: str, comp_b: str, protocol: str, repo: str,
    session_dir: str, hyp_dir: Path, pair_file: Path,
) -> list[dict]:
    """Build cross-crate analysis prompt for Rust/Soroban components.

    Analyzes:
    - Shared traits and interfaces between crates
    - Cross-contract calls via Client pattern (Soroban)
    - Shared storage keys / types
    - Message passing patterns (LayerZero: endpoint → msglib → dvn)
    - Cargo.toml dependency relationships
    """
    src_a = _find_rust_crate_src(repo, comp_a)
    src_b = _find_rust_crate_src(repo, comp_b)
    crate_a = src_a.parent
    crate_b = src_b.parent

    # Read source code summaries
    code_a = _rust_crate_sources(repo, comp_a)[:15000]
    code_b = _rust_crate_sources(repo, comp_b)[:15000]

    # Read Cargo.toml for dependency analysis
    cargo_a = _read_file_safe(crate_a / "Cargo.toml", max_chars=3000)
    cargo_b = _read_file_safe(crate_b / "Cargo.toml", max_chars=3000)

    # Detect cross-crate references
    cross_refs = ""

    # Check if A depends on B or vice versa (Cargo.toml)
    b_variants = {comp_b, comp_b.replace("-", "_"), comp_b.replace("_", "-")}
    a_variants = {comp_a, comp_a.replace("-", "_"), comp_a.replace("_", "-")}

    if any(v in cargo_a for v in b_variants):
        cross_refs += f"  {comp_a} depends on {comp_b} (Cargo.toml)\n"
    if any(v in cargo_b for v in a_variants):
        cross_refs += f"  {comp_b} depends on {comp_a} (Cargo.toml)\n"

    # Grep for cross-contract Client calls
    for comp, other, code in [(comp_a, comp_b, code_a), (comp_b, comp_a, code_b)]:
        other_variants = {other, other.replace("-", "_"), other.replace("_", "-")}
        for line in code.splitlines():
            line_stripped = line.strip()
            if any(v.lower() in line_stripped.lower() for v in other_variants):
                if any(kw in line_stripped for kw in ["Client", "invoke", "call", "use ", "mod "]):
                    cross_refs += f"  {comp} → {other}: {line_stripped[:120]}\n"

    # Read hypothesis convergences for both components
    hyp_summary = ""
    for comp in [comp_a, comp_b]:
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{comp}_*.yaml"))[:5]:
            content = _read_file_safe(hyp_file, max_chars=2000)
            if content:
                hyp_summary += f"\n### {hyp_file.stem}\n{content[:1500]}\n"

    pair_tag = f"{comp_a}_{comp_b}"

    prompt = (
        f"Cross-component analysis for {comp_a} × {comp_b} in {protocol} [RUST/SOROBAN].\n\n"
        f"## Crate A: {comp_a}\n```rust\n{code_a[:10000]}\n```\n\n"
        f"## Crate B: {comp_b}\n```rust\n{code_b[:10000]}\n```\n\n"
        f"## Cargo Dependencies\n"
        f"### {comp_a}/Cargo.toml\n```toml\n{cargo_a}\n```\n"
        f"### {comp_b}/Cargo.toml\n```toml\n{cargo_b}\n```\n\n"
        f"## Cross-Crate References Detected\n"
        f"{cross_refs or 'No direct references found — check for shared traits and interfaces.'}\n\n"
        f"## Hunter Hypotheses (both components)\n{hyp_summary[:8000]}\n\n"
        f"## SOROBAN CROSS-CONTRACT ATTACK SURFACES\n"
        f"Analyze these interaction patterns:\n\n"
        f"1. **Client call trust**: When {comp_a} calls {comp_b} (or vice versa), what happens if the\n"
        f"   called contract returns unexpected values? Is there validation on return?\n\n"
        f"2. **Shared storage keys**: Do both crates use the same DataKey enum values?\n"
        f"   Could one crate's storage writes corrupt the other's assumptions?\n\n"
        f"3. **Auth delegation**: If {comp_a} calls require_auth on behalf of {comp_b},\n"
        f"   can an attacker exploit the delegation chain?\n\n"
        f"4. **Message ordering**: For LayerZero message passing (endpoint → msglib → dvn),\n"
        f"   can out-of-order delivery between {comp_a} and {comp_b} break invariants?\n\n"
        f"5. **Nonce/sequence across crates**: If {comp_a} manages nonces and {comp_b}\n"
        f"   consumes them, are there TOCTOU races or replay windows?\n\n"
        f"6. **TTL desync**: If {comp_a} extends TTL but {comp_b} doesn't (or vice versa),\n"
        f"   can storage expiry create inconsistent state between crates?\n\n"
        f"7. **Type conversion at boundary**: bytes32 ↔ Address, u128 ↔ i128 at the\n"
        f"   interface between crates — truncation, sign extension, padding bugs?\n\n"
        f"8. **Upgrade desync**: If {comp_a} is upgraded but {comp_b} isn't, do the\n"
        f"   interfaces still match? Can storage layout changes break cross-calls?\n\n"
        f"## Output\n"
        f"Write findings to: {pair_file}\n"
        f"YAML format with: id, tier, severity, description, attack_scenario, rust_test, "
        f"confidence, vulnerable_location (both crates).\n"
        f"No artificial limit on hypotheses. Confidence >= 60% for validated: true."
    )

    return [{
        "step_id": f"cross:{pair_tag}:analyze",
        "prompt": prompt,
    }]


# phase_post_compile and phase_checkpoint extracted to plan/post_compile (Phase 6)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. CLI interface
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Plan generator for agent-mode benchmarks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # Generate full execution plan\n"
            "  python3 plan_generator.py --generate --repo /path --components A,B "
            "--protocol proto --session-dir /tmp/sess\n\n"
            "  # Dynamic phase (called mid-execution by skill)\n"
            "  python3 plan_generator.py --phase hunter-prompt --component A "
            "--protocol proto --repo /path --session-dir /tmp/sess\n"
        ),
    )
    parser.add_argument(
        "--generate", action="store_true",
        help="Generate a full execution plan JSON",
    )
    parser.add_argument(
        "--phase",
        choices=[
            "hunter-prompt", "deepdive-prompt", "findings", "cross-prompt",
            "checkpoint", "chimera-early-prompt", "chimera-builder-prompt",
            "enhance-targets-prompt", "post-compile", "write-fork-setup",
            "fork-poc-prompt",
            # Rust pipeline phases
            "rust-fuzz-scaffold-prompt", "rust-fuzz-harness-prompt",
            "rust-merge-harness",
        ],
        help="Dynamic phase to execute mid-run",
    )
    parser.add_argument("--repo", help="Path to repo root")
    parser.add_argument(
        "--components", help="Comma-separated components (for --generate)",
    )
    parser.add_argument(
        "--component", help="Single component or comma pair (for --phase)",
    )
    parser.add_argument("--protocol", help="Protocol name")
    parser.add_argument("--session-dir", help="Path to session directory")
    parser.add_argument("--ground-truth", help="Path to benchmark YAML")
    parser.add_argument("--fast", action="store_true", help="Fast mode (fewer fuzz runs)")
    parser.add_argument(
        "--pre-production", action="store_true",
        help="Pre-production mode (deploy-on-fork PoC strategy)",
    )
    parser.add_argument(
        "--benchmark-mode",
        choices=["hypothesis", "poc", "redteam"],
        default="redteam",
        help="Benchmark depth: hypothesis (hunters only), poc (+PoC), redteam (full pipeline)",
    )
    parser.add_argument(
        "--finding-id",
        help="Finding ID (for --phase fork-poc-prompt)",
    )
    parser.add_argument(
        "--parallel-components", type=int, default=1,
        help="Max components to run in parallel via Agent Teams (default: 1 = sequential)",
    )
    parser.add_argument(
        "--chain", default="mainnet",
        help="Target chain for fork PoCs (mainnet, base, optimism, arbitrum, polygon)",
    )
    parser.add_argument(
        "--fork-block", type=int, default=0,
        help="Fork block for PoCs. 0 = latest (portable, no hardcoded block)",
    )
    parser.add_argument(
        "--lang", default="",
        help="Contract language: solidity, rust (auto-detected if empty)",
    )

    args = parser.parse_args()

    if args.generate:
        if not args.repo or not args.components or not args.protocol or not args.session_dir:
            parser.error("--generate requires --repo, --components, --protocol, --session-dir")

        components = [c.strip() for c in args.components.split(",") if c.strip()]
        plan = generate_plan(
            repo=args.repo,
            components=components,
            protocol=args.protocol,
            session_dir=args.session_dir,
            ground_truth=args.ground_truth or "",
            is_pre_production=args.pre_production,
            fast=args.fast,
            benchmark_mode=args.benchmark_mode,
            parallel_components=args.parallel_components,
            chain=args.chain,
            fork_block=args.fork_block,
            lang=args.lang,
        )

        # Write plan to session_dir/execution_plan.json
        out_path = Path(args.session_dir) / "execution_plan.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        plan.to_json(str(out_path))
        print(json.dumps({"plan_path": str(out_path), "steps": len(plan.steps)}, indent=2))

    elif args.phase:
        if not args.protocol or not args.session_dir:
            parser.error("--phase requires --protocol and --session-dir")

        if args.phase == "hunter-prompt":
            if not args.component or not args.repo:
                parser.error("--phase hunter-prompt requires --component and --repo")
            result = phase_hunter_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                         lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "deepdive-prompt":
            if not args.component or not args.repo:
                parser.error("--phase deepdive-prompt requires --component and --repo")
            result = phase_deepdive_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                            lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "findings":
            if not args.component or not args.repo:
                parser.error("--phase findings requires --component and --repo")
            result = phase_findings(
                args.component, args.protocol, args.repo, args.session_dir,
                benchmark_mode=args.benchmark_mode,
                chain=args.chain,
                fork_block=args.fork_block,
                lang=args.lang or _detect_lang(args.repo),
                parallel_components=args.parallel_components,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "cross-prompt":
            if not args.component or not args.repo:
                parser.error("--phase cross-prompt requires --component and --repo")
            result = phase_cross_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                         lang=args.lang or _detect_lang(args.repo))
            print(json.dumps(result, indent=2))

        elif args.phase == "chimera-early-prompt":
            if not args.component or not args.repo:
                parser.error("--phase chimera-early-prompt requires --component and --repo")
            result = phase_chimera_early_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "chimera-builder-prompt":
            if not args.component or not args.repo:
                parser.error("--phase chimera-builder-prompt requires --component and --repo")
            result = phase_chimera_builder_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                 parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "enhance-targets-prompt":
            if not args.component or not args.repo:
                parser.error("--phase enhance-targets-prompt requires --component and --repo")
            result = phase_enhance_targets_prompt(args.component, args.protocol, args.repo, args.session_dir,
                                                  parallel_components=args.parallel_components)
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-fuzz-scaffold-prompt":
            if not args.component or not args.repo:
                parser.error("--phase rust-fuzz-scaffold-prompt requires --component and --repo")
            result = phase_rust_fuzz_scaffold_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-fuzz-harness-prompt":
            if not args.component or not args.repo:
                parser.error("--phase rust-fuzz-harness-prompt requires --component and --repo")
            result = phase_rust_fuzz_harness_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "rust-merge-harness":
            if not args.component or not args.repo:
                parser.error("--phase rust-merge-harness requires --component and --repo")
            phase_rust_merge_harness(
                args.component, args.protocol, args.repo, args.session_dir,
                lang=args.lang or _detect_lang(args.repo),
            )

        elif args.phase == "post-compile":
            if not args.component or not args.repo:
                parser.error("--phase post-compile requires --component and --repo")
            result = phase_post_compile(
                args.component, args.protocol, args.repo, args.session_dir,
                fast=args.fast,
                lang=args.lang or _detect_lang(args.repo),
                parallel_components=args.parallel_components,
                is_pre_production=args.pre_production,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "write-fork-setup":
            if not args.repo:
                parser.error("--phase write-fork-setup requires --repo")
            phase_write_fork_setup(args.repo, chain=args.chain, fork_block=args.fork_block)

        elif args.phase == "fork-poc-prompt":
            if not args.component or not args.repo or not args.finding_id:
                parser.error("--phase fork-poc-prompt requires --component, --repo, --finding-id")
            result = phase_fork_poc_prompt(
                args.component, args.protocol, args.repo, args.session_dir,
                finding_id=args.finding_id,
                chain=args.chain,
                fork_block=args.fork_block,
                parallel_components=args.parallel_components,
            )
            print(json.dumps(result, indent=2))

        elif args.phase == "checkpoint":
            if not args.component:
                parser.error("--phase checkpoint requires --component")
            phase_checkpoint(args.component, args.protocol, args.session_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
