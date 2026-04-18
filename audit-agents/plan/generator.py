"""Plan generation entry point — extracted from plan_generator.py in Phase 6.

Provides:
    - generate_plan (top-level entry: build ExecutionPlan from components + protocol)
    - _add_component_steps (per-component step emission with lang branch)
    - _add_cross_component_steps (cross-component pair + chain steps)

Consumers: run_benchmark (shim), audit-agents/scope_intake via subprocess.
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

from plan.detectors import (
    _detect_lang, _src_dir, _step_id, _worktree_path, _last_step_id,
    _rpc_var, _hyp_dir, _results_dir, _find_cargo_workspace,
)
from plan_schema import Step, ExecutionPlan

# SCRIPT_DIR points to audit-agents/ (parent of audit-agents/plan/) so that
# subprocess command strings continue to reference sibling scripts like
# plan_generator.py (the shim), benchmark_score.py, verify_team_outputs.py,
# detection_engine.py, merge_invariants.py, clippy_to_prepass.py.
SCRIPT_DIR = Path(__file__).resolve().parent.parent
VERSION = "1.0.0"


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
