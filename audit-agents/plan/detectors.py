"""Path/lang detectors and pure helpers — extracted from plan_generator.py.

Zero internal dependencies. Consumers: plan.generator, plan.prompts_solidity,
plan.prompts_rust, plan.post_compile.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from plan_schema import ExecutionPlan


# ─── Helpers ──────────────────────────────────────────────────────────────────

# Minimal domain detector for hunter context enrichment.
# Keeps this file self-sufficient; a richer detector lives in
# context_enrichment.DOMAIN_BRIEFING keys — we reuse that list.
def _detect_primary_domain(source_code: str) -> str:
    """Return the first DOMAIN_BRIEFING key that appears in source, or ''."""
    from context_enrichment import DOMAIN_BRIEFING
    src_lower = (source_code or "").lower()
    for domain in DOMAIN_BRIEFING.keys():
        if domain in src_lower:
            return domain
    return ""


def _read_file_safe(path: Path, max_chars: int = 0) -> str:
    """Read a file, returning empty string on any error."""
    try:
        text = path.read_text(encoding="utf-8")
        if max_chars > 0:
            text = text[:max_chars]
        return text
    except Exception:
        return ""


def _detect_lang(repo: str, explicit: str = "") -> str:
    """Auto-detect language: 'rust' if Cargo.toml found, else 'solidity'."""
    if explicit:
        return explicit
    repo_path = Path(repo)
    if (repo_path / "foundry.toml").exists():
        return "solidity"
    if (repo_path / "Cargo.toml").exists():
        return "rust"
    # Check nested workspace (layerzero-stellar style: contracts/protocol/stellar/)
    for cargo in repo_path.rglob("Cargo.toml"):
        content = _read_file_safe(cargo, max_chars=2000).lower()
        if "soroban" in content or "[workspace]" in content:
            return "rust"
        break
    return "solidity"


def _src_dir(repo: str, lang: str = "solidity", component: str = "") -> Path:
    """Return the source directory for a component.

    Solidity: repo/src/
    Rust: finds the crate's src/ by searching Cargo.toml workspace members.
    """
    if lang == "rust":
        return _find_rust_crate_src(repo, component)
    return Path(repo) / "src"


def _find_cargo_workspace(repo: str) -> str:
    """Find the Cargo workspace root directory.

    The workspace Cargo.toml may be nested (e.g., contracts/protocol/stellar/).
    Returns the directory containing the workspace Cargo.toml, or repo root as fallback.
    """
    repo_path = Path(repo)

    # Check repo root first
    root_cargo = repo_path / "Cargo.toml"
    if root_cargo.exists():
        content = _read_file_safe(root_cargo, max_chars=2000)
        if "[workspace]" in content:
            return str(repo_path)

    # Search for nested workspace
    for cargo in sorted(repo_path.rglob("Cargo.toml")):
        content = _read_file_safe(cargo, max_chars=2000)
        if "[workspace]" in content:
            return str(cargo.parent)

    return str(repo_path)


def _find_rust_crate_src(repo: str, component: str) -> Path:
    """Find the src/ directory of a Rust crate by component name.

    Searches for a directory matching the component name that contains
    a Cargo.toml. Handles nested workspaces like LayerZero Stellar:
      contracts/protocol/stellar/contracts/<component>/src/

    Also handles hyphenated crate names (endpoint-v2 → endpoint_v2 dir or vice versa).
    """
    repo_path = Path(repo)
    # Normalize: both hyphen and underscore variants
    variants = {component, component.replace("-", "_"), component.replace("_", "-")}

    # 1. Direct match at common locations
    for name in variants:
        for candidate in [
            repo_path / "contracts" / name / "src",
            repo_path / name / "src",
            repo_path / "src",  # single-crate repos
        ]:
            if candidate.exists() and any(candidate.glob("*.rs")):
                return candidate

    # 2. Search recursively — finds nested workspaces like
    #    contracts/protocol/stellar/contracts/<component>/src/
    for cargo in sorted(repo_path.rglob("Cargo.toml")):
        crate_dir = cargo.parent
        if crate_dir.name in variants and (crate_dir / "src").exists():
            return crate_dir / "src"

    # 3. Check Cargo.toml [package] name field for crates whose directory
    #    name differs from the package name
    for cargo in sorted(repo_path.rglob("Cargo.toml")):
        try:
            content = cargo.read_text(encoding="utf-8")
            # Quick parse: find `name = "xxx"` under [package]
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("name") and "=" in line:
                    pkg_name = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if pkg_name in variants and (cargo.parent / "src").exists():
                        return cargo.parent / "src"
        except Exception:
            continue

    # Fallback: repo/src
    return repo_path / "src"


def _rust_crate_sources(repo: str, component: str) -> str:
    """Read ALL .rs source files of a Rust crate, concatenated. Max 60K chars."""
    src_dir = _find_rust_crate_src(repo, component)
    parts: list[str] = []
    total = 0
    for rs_file in sorted(src_dir.rglob("*.rs")):
        if "test" in rs_file.parts:
            continue
        content = _read_file_safe(rs_file, max_chars=15000)
        header = f"\n// === {rs_file.relative_to(src_dir)} ===\n"
        parts.append(header + content)
        total += len(content)
        if total > 60000:
            break
    return "".join(parts)


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


# Chain → RPC env var mapping
_CHAIN_RPC_VAR = {
    "mainnet": "ETH_RPC_URL",
    "ethereum": "ETH_RPC_URL",
    "base": "BASE_RPC_URL",
    "optimism": "OPTIMISM_RPC_URL",
    "arbitrum": "ARBITRUM_RPC_URL",
    "polygon": "POLYGON_RPC_URL",
}


def _rpc_var(chain: str) -> str:
    """Return the env var name for the RPC URL of a chain."""
    return _CHAIN_RPC_VAR.get(chain.lower(), "ETH_RPC_URL")


def _fork_sol_snippet(chain: str, fork_block: int) -> str:
    """Return the Solidity snippet for createSelectFork.

    If *fork_block* > 0 → pin to that block (deterministic + cacheable).
    If *fork_block* == 0 → use latest block (portable, no hardcoded value).
    """
    rpc = _rpc_var(chain)
    if fork_block > 0:
        return (
            f'forkId = vm.createSelectFork(\n'
            f'            vm.envString("{rpc}"),\n'
            f'            {fork_block}\n'
            f'        );'
        )
    return (
        f'forkId = vm.createSelectFork(\n'
        f'            vm.envString("{rpc}")\n'
        f'        );'
    )


def _worktree_path(protocol: str, comp: str) -> str:
    """Deterministic worktree path for a component (matches API mode convention)."""
    return str(Path(tempfile.gettempdir()) / f"bench-{protocol}-{comp}")


def _last_step_id(plan: ExecutionPlan, components: list[str]) -> str:
    """Return the ID of the last step in the plan (for scoring dependency)."""
    if len(components) > 1:
        return "cross:checkpoint"
    return _step_id(components[0], "checkpoint")
