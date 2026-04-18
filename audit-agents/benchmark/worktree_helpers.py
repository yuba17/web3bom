"""Worktree + resolver helpers — extracted from run_benchmark.py in Phase 6.

Provides:
    - _create_worktree, _remove_worktree (git worktree lifecycle)
    - _validate_hunters_subset (CLI --hunters flag validator)
    - _apply_force_regen_map (CLI --force-regen-map flag handler)
    - _maybe_run_apply_feedback (end-of-run hook for --apply-feedback)
    - _resolve_components (router: explicit --components vs --auto-components)

Consumers: benchmark.cli (argparse handlers), tests.phase_2a, tests.phase_2c.
"""

import logging
import subprocess
import sys
from pathlib import Path

from benchmark.llm_runners import run_cmd  # noqa: F401

logger = logging.getLogger("orchestrator")


def _create_worktree(repo: str, component: str, protocol: str, run_id: str = "") -> str:
    """Create a git worktree for a component. Returns the effective repo path inside worktree.

    If --repo points to a subdirectory of the git root (e.g., .../repo/yieldoor),
    we create the worktree from the git root and return worktree_path + subdirectory offset.

    run_id: unique suffix per benchmark run (timestamp) to avoid collisions between concurrent runs.
    """
    import tempfile, shutil

    repo_path = Path(repo).resolve()

    # Find the actual git root
    code, git_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=str(repo_path))
    if code != 0:
        logger.error(f"  {repo} is not inside a git repo")
        return ""
    git_root = Path(git_root.strip()).resolve()

    # Prune any stale worktree registrations (missing dirs still registered in git)
    run_cmd(["git", "worktree", "prune"], cwd=str(git_root))

    # Compute subdirectory offset (e.g., "yieldoor" if repo=.../repo/yieldoor and git root=.../repo)
    try:
        subdir = repo_path.relative_to(git_root)
    except ValueError:
        subdir = Path(".")

    # Include run_id in name to avoid collisions between concurrent benchmark runs
    suffix = f"-{run_id}" if run_id else ""
    wt_path = str(Path(tempfile.gettempdir()) / f"bench-{protocol}-{component}{suffix}")

    # Clean up stale worktree if the directory still exists
    if Path(wt_path).exists():
        run_cmd(["git", "worktree", "remove", "--force", wt_path], cwd=str(git_root))
        if Path(wt_path).exists():
            shutil.rmtree(wt_path, ignore_errors=True)

    # Use -f (force) to override any stale git registration that survived prune
    code, _, stderr = run_cmd(
        ["git", "worktree", "add", "-f", "--detach", wt_path, "HEAD"], cwd=str(git_root)
    )
    if code != 0:
        logger.error(f"  Failed to create worktree for {component}: {stderr}")
        return ""

    effective_path = str(Path(wt_path) / subdir) if str(subdir) != "." else wt_path

    # Copy .env to worktree root so forge/foundry can read env vars (especially in agent mode
    # where subprocesses don't inherit shell exports)
    for _env_search in [repo_path, repo_path.parent, repo_path.parent.parent, git_root, git_root.parent]:
        _env_candidate = _env_search / ".env"
        if _env_candidate.exists():
            shutil.copy2(str(_env_candidate), str(Path(wt_path) / ".env"))
            logger.info(f"  Copied .env to worktree: {_env_candidate} → {wt_path}/.env")
            break

    # Patch foundry.toml to add [rpc_endpoints] if missing — prevents vm.createSelectFork("mainnet") failures
    ft = Path(effective_path) / "foundry.toml"
    if ft.exists():
        ft_text = ft.read_text(encoding="utf-8")
        if "[rpc_endpoints]" not in ft_text:
            ft.write_text(
                ft_text.rstrip() + "\n\n[rpc_endpoints]\n"
                'mainnet = "${ETH_RPC_URL}"\n'
                'base = "${BASE_RPC_URL}"\n'
                'arbitrum = "${ARB_RPC_URL}"\n',
                encoding="utf-8"
            )
            logger.info(f"  Patched foundry.toml: added [rpc_endpoints] in {effective_path}")

    logger.info(f"  Worktree created: {wt_path} (effective repo: {effective_path})")
    return effective_path


def _remove_worktree(repo: str, wt_path: str):
    """Remove a git worktree. Finds the actual worktree root (may differ from wt_path if subdir offset)."""
    if not wt_path or not Path(wt_path).exists():
        return
    # Find git root of the worktree to get the actual worktree path
    code, wt_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=wt_path)
    if code == 0:
        wt_root = wt_root.strip()
    else:
        wt_root = wt_path
    # Find git root of the main repo for the worktree remove command
    code, git_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=repo)
    git_root = git_root.strip() if code == 0 else repo
    run_cmd(["git", "worktree", "remove", "--force", wt_root], cwd=git_root)
    logger.info(f"  Worktree removed: {wt_root}")


def _validate_hunters_subset(raw: str) -> set[str] | None:
    """Parse --hunters value. Exits with list of valid names if any unknown.

    Returns None when raw is empty (meaning: run all hunters, no filtering).
    Returns a set of requested hunter names when a subset is specified.

    Examples:
        ""            → None  (run all)
        "MathHunter"  → {"MathHunter"}
        "Math,Access" → exits with error (use full names like "MathHunter")
    """
    from hunter_context import HUNTER_DOMAINS
    valid = set(HUNTER_DOMAINS.keys())
    raw = (raw or "").strip()
    if not raw:
        return None
    requested = {tok.strip() for tok in raw.split(",") if tok.strip()}
    unknown = requested - valid
    if unknown:
        sys.stderr.write(
            f"--hunters: unknown hunter(s): {sorted(unknown)}\n"
            f"Valid hunters: {sorted(valid)}\n"
        )
        sys.exit(2)
    return requested


def _apply_force_regen_map(*, session_dir: Path, protocol: str) -> None:
    """Delete cached component_map_<protocol>.json under session_dir. No-op if missing."""
    for candidate in [
        session_dir / f"component_map_{protocol}.json",
        session_dir / "context" / f"component_map_{protocol}.json",
    ]:
        if candidate.exists():
            candidate.unlink()
            print(f"[force] removed cached component map: {candidate}", file=sys.stderr)


def _maybe_run_apply_feedback(*, apply_feedback: bool) -> None:
    """If flag is set, invoke apply_feedback.py once via subprocess.

    Default (flag off) is the safe path for benchmarks — the corpus is
    untouched. With the flag on, apply_feedback runs with its own defaults
    (production knowledge/ and vault paths).
    """
    if not apply_feedback:
        return
    fb_cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent.parent / "apply_feedback.py"),
    ]
    result = subprocess.run(fb_cmd, check=False)
    if result.returncode != 0:
        logger.warning(
            f"apply_feedback exited {result.returncode} — corpus may be unchanged"
        )


def _resolve_components(args) -> list[str]:
    if args.components:
        return [c.strip() for c in args.components.split(",") if c.strip()]
    if args.auto_components:
        from component_discovery import generate_component_map
        cmap = generate_component_map(repo_path=args.repo)
        return [c["name"] for c in cmap if c["status"] in ("pending", "unmapped")]
    return []
