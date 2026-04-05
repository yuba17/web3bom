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

# ─── Constants ────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
VERSION = "1.0.0"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _read_file_safe(path: Path, max_chars: int = 0) -> str:
    """Read a file, returning empty string on any error."""
    try:
        text = path.read_text(encoding="utf-8")
        if max_chars > 0:
            text = text[:max_chars]
        return text
    except Exception:
        return ""


def _src_dir(repo: str) -> Path:
    """Return the src/ directory of the repo."""
    return Path(repo) / "src"


def _results_dir(session_dir: str) -> Path:
    d = Path(session_dir) / "results"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _hyp_dir(session_dir: str, protocol: str) -> Path:
    d = Path(session_dir) / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def _step_id(component: str, name: str) -> str:
    """Generate a deterministic step ID like 'Strategy:prepass'."""
    return f"{component}:{name}"


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
) -> ExecutionPlan:
    """Build a complete ExecutionPlan for the given components."""

    hyp_dir = str(_hyp_dir(session_dir, protocol))

    plan = ExecutionPlan(
        version=VERSION,
        protocol=protocol,
        repo=repo,
        session_dir=session_dir,
        hypotheses_dir=hyp_dir,
        components=components,
        is_pre_production=is_pre_production,
    )

    # Per-component steps
    for comp in components:
        _add_component_steps(plan, comp, repo, protocol, session_dir, fast)

    # Cross-component steps (only if >1 component)
    if len(components) > 1:
        _add_cross_component_steps(plan, components, repo, protocol, session_dir)

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
) -> None:
    """Add the 10 sequential steps for a single component."""

    src_dir = _src_dir(repo)
    results_dir = _results_dir(session_dir)
    hyp_dir = _hyp_dir(session_dir, protocol)
    gen_cmd = f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'}"

    # 1. prepass
    plan.add_step(Step(
        id=_step_id(comp, "prepass"),
        type="bash",
        description=f"Run detection engine prepass for {comp}",
        command=(
            f"{sys.executable} {SCRIPT_DIR / 'detection_engine.py'} "
            f"--prepass --source {src_dir}/{comp}.sol "
            f"--name {comp} --output {results_dir}/"
        ),
        timeout=120,
        retry=1,
    ))

    # 2. build_hunter_prompt
    plan.add_step(Step(
        id=_step_id(comp, "build_hunter_prompt"),
        type="generate",
        description=f"Build hunter brief and dispatch prompt for {comp}",
        command=(
            f"{gen_cmd} --phase hunter-prompt "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}"
        ),
        depends_on=[_step_id(comp, "prepass")],
        timeout=60,
    ))

    # 3. hunters (agent)
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

    # 4. build_deepdive_prompt
    plan.add_step(Step(
        id=_step_id(comp, "build_deepdive_prompt"),
        type="generate",
        description=f"Build DeepDive prompt for {comp}",
        command=(
            f"{gen_cmd} --phase deepdive-prompt "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}"
        ),
        depends_on=[_step_id(comp, "hunters")],
        timeout=60,
    ))

    # 5. deepdive (agent)
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

    # 6. merge
    plan.add_step(Step(
        id=_step_id(comp, "merge"),
        type="bash",
        description=f"Merge invariants for {comp}",
        command=(
            f"{sys.executable} {SCRIPT_DIR / 'merge_invariants.py'} "
            f"--component {comp} --hyp-dir {hyp_dir} --repo {repo}"
        ),
        depends_on=[_step_id(comp, "deepdive")],
        timeout=120,
    ))

    # 7. compile
    plan.add_step(Step(
        id=_step_id(comp, "compile"),
        type="bash",
        description=f"Compile contracts for {comp}",
        command=f"cd {repo} && forge build",
        cwd=repo,
        depends_on=[_step_id(comp, "merge")],
        timeout=300,
        retry=3,
    ))

    # 8. fuzz
    fuzz_runs = 3000 if fast else 5000
    fuzz_timeout = 900 if fast else 1800
    plan.add_step(Step(
        id=_step_id(comp, "fuzz"),
        type="bash",
        description=f"Foundry fuzz {fuzz_runs} runs for {comp}",
        command=(
            f"cd {repo} && FOUNDRY_PROFILE=chimera forge test "
            f"--match-contract FoundryTester --fuzz-runs {fuzz_runs} -vv"
        ),
        cwd=repo,
        depends_on=[_step_id(comp, "compile")],
        timeout=fuzz_timeout,
    ))

    # 9. collect_findings
    plan.add_step(Step(
        id=_step_id(comp, "collect_findings"),
        type="generate",
        description=f"Collect and process findings for {comp}",
        command=(
            f"{gen_cmd} --phase findings "
            f"--component {comp} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}"
        ),
        depends_on=[_step_id(comp, "fuzz")],
        timeout=60,
    ))

    # 10. checkpoint
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
) -> None:
    """Add cross-component analysis steps for all pairs."""

    gen_cmd = f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'}"

    # All component checkpoints must complete first
    checkpoint_deps = [_step_id(c, "checkpoint") for c in components]

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
                f"--repo {repo} --session-dir {session_dir}"
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


def _last_step_id(plan: ExecutionPlan, components: list[str]) -> str:
    """Return the ID of the last step in the plan (for scoring dependency)."""
    if len(components) > 1:
        return "cross:checkpoint"
    return _step_id(components[0], "checkpoint")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Dynamic phase generators (--phase handlers)
# ═══════════════════════════════════════════════════════════════════════════════

def phase_hunter_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
) -> list[dict]:
    """Build hunter brief + dispatch prompt; return one step dict with real prompt."""

    from run_benchmark import build_hunter_brief, build_hunter_dispatch_prompt

    src_dir = _src_dir(repo)
    src_file = src_dir / f"{component}.sol"
    results_dir = _results_dir(session_dir)
    hyp_dir = _hyp_dir(session_dir, protocol)

    # Read source code
    source_code = _read_file_safe(src_file, max_chars=50000)

    # Read prepass signals
    prepass_path = results_dir / f"{component}_prepass.yaml"
    prepass_signals_text = _read_file_safe(prepass_path, max_chars=4000)

    # Read Setup.sol
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    setup_sol_text = _read_file_safe(setup_path, max_chars=5000)

    # Extract variable names from Setup.sol
    setup_var_names = ""
    if setup_sol_text:
        import re
        var_matches = re.findall(
            r'(?:internal|public|private)\s+(\w+)', setup_sol_text
        )
        setup_var_names = ", ".join(set(var_matches)) if var_matches else ""

    # Read interfaces
    interfaces_code = ""
    iface_dir = src_dir / "interfaces"
    if iface_dir.exists():
        for ifile in sorted(iface_dir.glob("*.sol")):
            interfaces_code += _read_file_safe(ifile, max_chars=3000)
            if len(interfaces_code) > 10000:
                break

    # Protocol model (if exists)
    protocol_model = ""
    model_path = Path(session_dir) / "context" / f"{protocol}_model.md"
    if model_path.exists():
        protocol_model = _read_file_safe(model_path, max_chars=3000)

    # Build hunter brief
    brief_content = build_hunter_brief(
        component=component,
        protocol=protocol,
        src_file=src_file,
        src_dir=src_dir,
        protocol_model=protocol_model,
        prepass_signals_text=prepass_signals_text,
        setup_sol_text=setup_sol_text,
        setup_var_names=setup_var_names,
        existing_tests_summary="",
        knowledge_context="",
        interfaces_code=interfaces_code,
        accumulated_context="",
        hyp_dir=hyp_dir,
    )

    # Write brief to disk
    brief_path = Path(session_dir) / f"hunter_brief_{component}.md"
    brief_path.parent.mkdir(parents=True, exist_ok=True)
    brief_path.write_text(brief_content, encoding="utf-8")

    # Build dispatch prompt
    dispatch_prompt = build_hunter_dispatch_prompt(
        component=component,
        protocol=protocol,
        src_file=src_file,
        src_dir=src_dir,
        hunter_brief_path=brief_path,
        hyp_dir=hyp_dir,
    )

    return [{
        "step_id": _step_id(component, "hunters"),
        "prompt": dispatch_prompt,
    }]


def phase_deepdive_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
) -> list[dict]:
    """Build DeepDive prompt from hunter convergences; return one step dict."""

    from run_benchmark import build_deepdive_prompt

    src_dir = _src_dir(repo)
    src_file = src_dir / f"{component}.sol"
    hyp_dir = _hyp_dir(session_dir, protocol)

    # Read source code
    source_code = _read_file_safe(src_file, max_chars=50000)

    # Read library code
    library_code = ""
    lib_dir = src_dir / "libraries"
    if lib_dir.exists():
        for lfile in sorted(lib_dir.glob("*.sol")):
            library_code += _read_file_safe(lfile, max_chars=5000)
            if len(library_code) > 20000:
                break

    # Read Setup.sol
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    setup_sol_text = _read_file_safe(setup_path, max_chars=5000)

    # Protocol model
    protocol_model = ""
    model_path = Path(session_dir) / "context" / f"{protocol}_model.md"
    if model_path.exists():
        protocol_model = _read_file_safe(model_path, max_chars=3000)

    # Digest hunter convergences (same logic as run_benchmark.py lines 1609-1634)
    hunter_digest = ""
    convergence_map: dict[str, list[str]] = {}

    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    if _yaml:
        for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
            if "DeepDive" in hyp_file.name or "CrossChain" in hyp_file.name:
                continue
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
                hyps = data.get("hypotheses", data.get("invariants", []))
                for h in hyps:
                    if h.get("confidence", 0) >= 50 and h.get("tier", 3) <= 2:
                        desc = h.get("description", h.get("title", ""))
                        area = h.get("type", "unknown")
                        hunter_digest += (
                            f"- [{hunter_name}] (tier={h.get('tier')}, "
                            f"conf={h.get('confidence')}%) {desc}\n"
                        )
                        convergence_map.setdefault(area, []).append(hunter_name)
            except Exception:
                pass

    convergence_text = ""
    for area, hunters in convergence_map.items():
        if len(hunters) >= 2:
            convergence_text += (
                f"- **{area}**: flagged by {', '.join(set(hunters))} "
                f"— INVESTIGATE DEEPER\n"
            )

    # Build the prompt
    deepdive_prompt = build_deepdive_prompt(
        component=component,
        protocol=protocol,
        source_code=source_code,
        library_code=library_code,
        setup_sol_text=setup_sol_text,
        protocol_model=protocol_model,
        hyp_dir=hyp_dir,
        convergence_text=convergence_text,
        hunter_digest=hunter_digest,
    )

    return [{
        "step_id": _step_id(component, "deepdive"),
        "prompt": deepdive_prompt,
    }]


def phase_findings(
    component: str, protocol: str, repo: str, session_dir: str,
) -> list[dict]:
    """Read hypothesis YAMLs and return finding verification/PoC/RedTeam steps."""

    hyp_dir = _hyp_dir(session_dir, protocol)
    findings: list[dict] = []

    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None
        return []

    # Collect all findings from hypothesis files
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        try:
            data = _yaml.safe_load(hyp_file.read_text())
            if not data:
                continue
            hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
            hyps = data.get("hypotheses", data.get("findings", data.get("invariants", [])))
            for h in (hyps or []):
                if not isinstance(h, dict):
                    continue
                if h.get("confidence", 0) >= 55 and h.get("validated", False):
                    h["hunter"] = hunter_name
                    h["component"] = component
                    findings.append(h)
        except Exception:
            pass

    if not findings:
        return [{"status": "no_findings", "component": component}]

    # Generate parallel verification steps for each finding
    steps: list[dict] = []
    for i, f in enumerate(findings):
        fid = f.get("id", f"F-{component}-{i:03d}")
        steps.append({
            "id": f"{component}:verify:{fid}",
            "type": "agent",
            "description": f"Verify finding {fid}: {f.get('title', f.get('description', '')[:60])}",
            "prompt": (
                f"Verify this finding for {component} in {protocol}:\n"
                f"ID: {fid}\n"
                f"Title: {f.get('title', f.get('description', 'N/A'))}\n"
                f"Severity: {f.get('severity', 'Unknown')}\n"
                f"Confidence: {f.get('confidence', 0)}%\n"
                f"Description: {f.get('description', 'N/A')}\n"
                f"Attack: {f.get('attack_scenario', 'N/A')}\n\n"
                f"Read the source code in {_src_dir(repo)}/{component}.sol and verify "
                f"this finding is real. Report your conclusion."
            ),
            "tools": ["Read", "Grep", "Glob"],
            "parallel_group": f"{component}:verification",
            "timeout": 300,
        })

    return steps


def phase_cross_prompt(
    components_str: str, protocol: str, repo: str, session_dir: str,
) -> list[dict]:
    """Build cross-component pair prompt; return one step dict."""

    from run_benchmark import build_cross_pair_prompt

    parts = components_str.split(",")
    if len(parts) != 2:
        return [{"error": f"Expected 2 components, got {len(parts)}"}]

    comp_a, comp_b = parts[0].strip(), parts[1].strip()
    src_dir = _src_dir(repo)
    hyp_dir = _hyp_dir(session_dir, protocol)

    # Read interfaces for each component
    iface_a = _read_file_safe(src_dir / f"{comp_a}.sol", max_chars=5000)
    iface_b = _read_file_safe(src_dir / f"{comp_b}.sol", max_chars=5000)

    # Find cross-calls (simple grep for component references)
    cross_calls = ""
    for comp, other in [(comp_a, comp_b), (comp_b, comp_a)]:
        src_file = src_dir / f"{comp}.sol"
        code = _read_file_safe(src_file)
        if code:
            for line in code.splitlines():
                if other.lower() in line.lower() and ("." in line or "(" in line):
                    cross_calls += f"  {comp} → {other}: {line.strip()}\n"

    pair_file = hyp_dir / f"cross_{comp_a}_{comp_b}.yaml"

    prompt = build_cross_pair_prompt(
        comp_a=comp_a,
        comp_b=comp_b,
        iface_a=iface_a,
        iface_b=iface_b,
        cross_calls=cross_calls or "No direct cross-calls found — check for shared state.",
        src_dir=src_dir,
        pair_file=pair_file,
    )

    pair_tag = f"{comp_a}_{comp_b}"
    return [{
        "step_id": f"cross:{pair_tag}:analyze",
        "prompt": prompt,
    }]


def phase_checkpoint(
    component: str, protocol: str, session_dir: str,
) -> None:
    """Write/update findings_all.json from collected hypotheses. Print status to stdout."""

    hyp_dir = _hyp_dir(session_dir, protocol)
    findings_all: list[dict] = []

    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None

    if _yaml:
        for hyp_file in sorted(hyp_dir.glob("hyp_*.yaml")):
            try:
                data = _yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                # Extract component and hunter from filename
                stem = hyp_file.stem  # e.g. hyp_Strategy_MathHunter
                parts = stem.split("_", 2)
                comp = parts[1] if len(parts) >= 2 else "unknown"
                hunter = parts[2] if len(parts) >= 3 else "unknown"

                hyps = data.get("hypotheses", data.get("findings", data.get("invariants", [])))
                for h in (hyps or []):
                    if not isinstance(h, dict):
                        continue
                    findings_all.append({
                        "component": comp,
                        "id": h.get("id", ""),
                        "title": h.get("title", h.get("description", "")[:80]),
                        "severity": h.get("severity", ""),
                        "confidence": h.get("confidence", 0),
                        "fuzz_confirmed": h.get("fuzz_confirmed", False),
                        "poc_passed": h.get("has_poc", False),
                        "poc_path": h.get("poc_path", ""),
                        "hunter": hunter,
                        "redteam_verdict": h.get("redteam_verdict", ""),
                        "redteam_kill_reason": h.get("redteam_kill_reason", ""),
                    })
            except Exception:
                pass

    # Also load cross-component findings
    for cross_file in sorted(hyp_dir.glob("cross_*.yaml")):
        try:
            data = _yaml.safe_load(cross_file.read_text()) if _yaml else None
            if not data:
                continue
            for f in data.get("findings", []):
                if not isinstance(f, dict):
                    continue
                findings_all.append({
                    "component": "CrossComponent",
                    "id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", 0),
                    "fuzz_confirmed": False,
                    "poc_passed": False,
                    "poc_path": "",
                    "hunter": "CrossComponentHunter",
                    "redteam_verdict": "",
                    "redteam_kill_reason": "",
                })
        except Exception:
            pass

    # Write findings_all.json
    findings_json_path = Path(session_dir) / "findings_all.json"
    payload = {
        "protocol": protocol,
        "checkpoint_component": component,
        "total_findings": len(findings_all),
        "generated_at": datetime.now().isoformat(),
        "complete": component == "cross",
        "findings": findings_all,
    }
    findings_json_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Print status to stdout for the skill to capture
    status = {
        "component": component,
        "total_findings": len(findings_all),
        "findings_json": str(findings_json_path),
    }
    print(json.dumps(status, indent=2))


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
        choices=["hunter-prompt", "deepdive-prompt", "findings", "cross-prompt", "checkpoint"],
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
            result = phase_hunter_prompt(args.component, args.protocol, args.repo, args.session_dir)
            print(json.dumps(result, indent=2))

        elif args.phase == "deepdive-prompt":
            if not args.component or not args.repo:
                parser.error("--phase deepdive-prompt requires --component and --repo")
            result = phase_deepdive_prompt(args.component, args.protocol, args.repo, args.session_dir)
            print(json.dumps(result, indent=2))

        elif args.phase == "findings":
            if not args.component or not args.repo:
                parser.error("--phase findings requires --component and --repo")
            result = phase_findings(args.component, args.protocol, args.repo, args.session_dir)
            print(json.dumps(result, indent=2))

        elif args.phase == "cross-prompt":
            if not args.component or not args.repo:
                parser.error("--phase cross-prompt requires --component and --repo")
            result = phase_cross_prompt(args.component, args.protocol, args.repo, args.session_dir)
            print(json.dumps(result, indent=2))

        elif args.phase == "checkpoint":
            if not args.component:
                parser.error("--phase checkpoint requires --component")
            phase_checkpoint(args.component, args.protocol, args.session_dir)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
