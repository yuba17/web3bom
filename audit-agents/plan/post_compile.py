"""Post-compile + fork setup + checkpoint steps — extracted from plan_generator.py.

Consumers: plan.generator.generate_plan (emits these as plan steps).
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

# SCRIPT_DIR points to audit-agents/ (parent of plan/)
SCRIPT_DIR = Path(__file__).resolve().parent.parent

# Ensure audit-agents is on the path for sibling imports
sys.path.insert(0, str(SCRIPT_DIR))

from plan.detectors import (  # noqa: F401
    _fork_sol_snippet, _rpc_var, _worktree_path, _step_id,
    _find_cargo_workspace, _hyp_dir,
)


def phase_write_fork_setup(repo: str, chain: str = "mainnet", fork_block: int = 0) -> None:
    """Write test/poc/ForkSetup.sol to disk. Called as --phase write-fork-setup."""
    poc_dir = Path(repo) / "test" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    fork_setup_path = poc_dir / "ForkSetup.sol"
    snippet = _fork_sol_snippet(chain, fork_block)
    block_comment = f"block {fork_block}" if fork_block > 0 else "latest block"
    content = (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.13;\n\n"
        'import "forge-std/Test.sol";\n\n'
        f"/// @notice Shared fork setup for ALL PoC tests ({block_comment}).\n"
        "abstract contract ForkSetup is Test {\n"
        "    uint256 internal forkId;\n\n"
        "    function setUp() public virtual {\n"
        f"        {snippet}\n"
        "    }\n"
        "}\n"
    )
    fork_setup_path.write_text(content)
    print(f"ForkSetup.sol created at {fork_setup_path}")


def phase_post_compile(
    component: str, protocol: str, repo: str, session_dir: str,
    fast: bool = False,
    lang: str = "solidity",
    parallel_components: int = 1,
    is_pre_production: bool = False,
) -> list[dict]:
    """Check compile result and conditionally emit test/fuzz steps.

    In fast mode, compile failure is non-fatal — returns empty steps.
    In non-fast mode, compile failure returns a gate-fail step.
    """
    is_rust = (lang == "rust")
    gen_cmd = f"{sys.executable} {SCRIPT_DIR / 'plan_generator.py'}"

    # Check if compilation produced artifacts
    if is_rust:
        # target/ lives at the Cargo workspace root, which may differ from repo root
        cargo_ws = _find_cargo_workspace(repo)
        target_dir = Path(cargo_ws) / "target"
        compile_ok = target_dir.exists()
    else:
        # Check multiple locations for Foundry artifacts
        out_dir = Path(repo) / "out"
        if not (out_dir.exists() and any(out_dir.iterdir())):
            # Try nested subdirectories (e.g., repo/yieldoor/out/)
            for subdir in Path(repo).iterdir():
                if subdir.is_dir() and (subdir / "out").exists():
                    candidate = subdir / "out"
                    try:
                        if any(candidate.iterdir()):
                            out_dir = candidate
                            break
                    except (StopIteration, PermissionError):
                        pass
        compile_ok = out_dir.exists() and any(out_dir.iterdir()) if out_dir.exists() else False

    # Sentinel step: cleanup_worktree depends on this, not on post_compile.
    # This ensures dynamically-injected fuzz steps run BEFORE worktree cleanup.
    sentinel = {
        "id": _step_id(component, "post_fuzz"),
        "type": "bash",
        "description": f"Sentinel: fuzz phase complete for {component}",
        "command": "echo 'post_fuzz sentinel reached'",
        "timeout": 10,
    }

    if not compile_ok:
        if fast:
            # Fast mode: compile failed but we continue to collect_findings
            # Still emit sentinel so cleanup_worktree dependency resolves
            sentinel["depends_on"] = []
            return [sentinel]
        else:
            # Non-fast mode: emit a gate step that will fail the pipeline
            return [{
                "id": _step_id(component, "compile_gate_fail"),
                "type": "gate",
                "description": f"BLOCKED: Compilation failed for {component} — pipeline halted",
                "command": "exit 1",
            }]

    # Compile succeeded — emit test/fuzz steps
    steps: list[dict] = []

    # ── Rust path: Phase 1 cargo test + Phase 2 proptest loop ──
    # The fuzz_harness agent already generated invariants + attack sequences
    # in a single step (before compile), so no enhance_targets step needed here.
    if is_rust:
        # Find the workspace root (Cargo workspace may be nested)
        cargo_dir = _find_cargo_workspace(repo)

        test_timeout = 300 if fast else 600

        # Phase 1: Run all tests — existing + generated invariant harness
        # (equivalent to Foundry fuzz 5K)
        steps.append({
            "id": _step_id(component, "cargo_test"),
            "type": "bash",
            "description": f"Phase 1: cargo test for {component} (existing + invariant harness)",
            "command": f"cd {cargo_dir} && cargo test -p {component} -- --nocapture 2>&1",
            "cwd": cargo_dir,
            "timeout": test_timeout,
        })

        # Phase 2: Property-based multi-iteration tests (equivalent to Medusa).
        # Runs the test_proptest_* and test_sequence_* functions generated by
        # fuzz_harness — these use loops with varied inputs. Skip in fast mode.
        if not fast:
            steps.append({
                "id": _step_id(component, "proptest_run"),
                "type": "bash",
                "description": f"Phase 2: Run proptest/sequence tests for {component}",
                "command": (
                    f"cd {cargo_dir} && "
                    f"cargo test -p {component} test_proptest_ -- --nocapture 2>&1; "
                    f"cargo test -p {component} test_sequence_ -- --nocapture 2>&1; "
                    f"cargo test -p {component} test_optimize_ -- --nocapture 2>&1"
                ),
                "cwd": cargo_dir,
                "depends_on": [_step_id(component, "cargo_test")],
                "timeout": 600,
            })

        # Sentinel: last step in the dynamic chain (Rust path)
        last_rust_step = steps[-1]["id"]
        sentinel["depends_on"] = [last_rust_step]
        steps.append(sentinel)
        return steps

    # ── Solidity path: enhance_targets + fuzz ──

    # 7.5a. enhance_targets_check
    steps.append({
        "id": _step_id(component, "enhance_targets_check"),
        "type": "generate",
        "description": f"Build enhance-targets prompt for {component}",
        "command": (
            f"{gen_cmd} --phase enhance-targets-prompt "
            f"--component {component} --protocol {protocol} "
            f"--repo {repo} --session-dir {session_dir}"
            + (f" --parallel-components {parallel_components}" if parallel_components > 1 else "")
        ),
        "timeout": 60,
    })

    # 7.5b. enhance_targets (agent)
    steps.append({
        "id": _step_id(component, "enhance_targets"),
        "type": "agent",
        "description": f"Enhance TargetFunctions with attack sequences for {component}",
        "prompt": "__DYNAMIC__",
        "tools": ["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
        "depends_on": [_step_id(component, "enhance_targets_check")],
        "timeout": 600,
    })

    # 8. Phase 1 — Foundry fuzz (fork-first with RPC cache, fallback to no-fork)
    fuzz_runs = 3000 if fast else 5000
    fuzz_timeout = 1800
    forge_jobs = " --jobs 3" if parallel_components > 1 else ""
    # Source .env to ensure RPC URLs are available (subagents don't inherit shell exports).
    # Try fork first (real state, high fidelity). If no RPC URL → run without fork (mocks).
    env_file = Path(repo).resolve()
    # Walk up to find .env (could be in repo root, parent, or grandparent).
    # Also check the session_dir ancestors (worktrees live in /tmp/ far from the project .env).
    env_source = ""
    _search_roots = [env_file, env_file.parent, env_file.parent.parent, env_file.parent.parent.parent]
    # session_dir is always inside the real project tree — use it to find .env
    _sess = Path(session_dir).resolve()
    for _anc in [_sess, _sess.parent, _sess.parent.parent, _sess.parent.parent.parent]:
        if _anc not in _search_roots:
            _search_roots.append(_anc)
    for parent in _search_roots:
        if (parent / ".env").exists():
            env_source = f"set -a && source {parent / '.env'} && set +a && "
            break
    # Pin fork block for deterministic cache: fetch once, reuse across all components.
    # cast block latest returns current block; all fuzz runs in this session share it.
    mock_cmd = (
        f"echo '[MOCK MODE] Running without fork' && "
        f"forge test --match-contract FoundryTester --fuzz-runs {fuzz_runs} -vv{forge_jobs}"
    )
    if is_pre_production:
        # Pre-production: try fork if RPC available (tests may use vm.createFork for
        # external deps like Uniswap), fall back to mock if no RPC.
        fuzz_cmd = (
            f"cd {repo} && {env_source}"
            f"if [ -n \"${{ETH_RPC_URL:-}}\" ]; then "
            f"  echo '[PRE-PROD FORK] RPC available, running with fork for external deps' && "
            f"  forge test --match-contract FoundryTester --fuzz-runs {fuzz_runs} -vv{forge_jobs} "
            f"--fork-url \"$ETH_RPC_URL\" || "
            f"  (echo '[FORK FAILED] Falling back to mock mode' && {mock_cmd}); "
            f"else "
            f"  {mock_cmd}; "
            f"fi"
        )
    else:
        # Deployed protocol: try fork first, fallback to mock if RPC fails
        fuzz_cmd = (
            f"cd {repo} && {env_source}"
            f"if [ -n \"${{ETH_RPC_URL:-}}\" ]; then "
            f"  FORK_BLOCK=${{FORK_BLOCK:-$(cast block latest --field number --rpc-url \"$ETH_RPC_URL\" 2>/dev/null || echo 0)}} && "
            f"  if [ \"$FORK_BLOCK\" != \"0\" ]; then "
            f"    echo \"[FORK MODE] block=$FORK_BLOCK (pinned, RPC cache reused across components)\" && "
            f"    forge test --match-contract FoundryTester --fuzz-runs {fuzz_runs} -vv{forge_jobs} "
            f"--fork-url \"$ETH_RPC_URL\" --fork-block-number $FORK_BLOCK || "
            f"    (echo '[FORK FAILED] Falling back to mock mode' && {mock_cmd}); "
            f"  else "
            f"    echo '[FORK FALLBACK] Could not fetch block — running mock mode' && "
            f"    {mock_cmd}; "
            f"  fi; "
            f"else "
            f"  {mock_cmd}; "
            f"fi"
        )
    steps.append({
        "id": _step_id(component, "fuzz"),
        "type": "bash",
        "description": f"Phase 1: Foundry fuzz {fuzz_runs} runs for {component} (fork-first, mock fallback)",
        "command": fuzz_cmd,
        "cwd": repo,
        "depends_on": [_step_id(component, "enhance_targets")],
        "timeout": fuzz_timeout,
    })

    # 8.5. Phase 2 — Medusa (multi-step sequences, 15 min). Skipped in fast mode.
    if not fast:
        medusa_config = Path(repo) / "test" / "chimera" / f"medusa-{component}.json"
        # If no component-specific config exists, use default medusa.json
        medusa_fallback = Path(repo) / "test" / "chimera" / "medusa.json"
        steps.append({
            "id": _step_id(component, "medusa"),
            "type": "bash",
            "description": f"Phase 2: Medusa 15min fuzz for {component}",
            "command": (
                f"cd {repo} && "
                f"if [ -f {medusa_config} ]; then "
                f"  medusa fuzz --config {medusa_config} --timeout 900; "
                f"elif [ -f {medusa_fallback} ]; then "
                f"  medusa fuzz --config {medusa_fallback} --timeout 900; "
                f"else "
                f"  echo 'No medusa config found — skipping Phase 2'; "
                f"fi"
            ),
            "cwd": repo,
            "depends_on": [_step_id(component, "fuzz")],
            "timeout": 1200,
        })

    # Sentinel: last step in the dynamic chain (Solidity path)
    last_sol_step = steps[-1]["id"]
    sentinel["depends_on"] = [last_sol_step]
    steps.append(sentinel)
    return steps


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
