"""merge.py — merge invariants + compile Setup + import injection + compile merged.

Steps 5-7 of the component pipeline:
  5a. Ensure Chimera Setup exists (cache lookup → generate)
  5b. Verify base chimera compiles
  6.  Merge invariants (merge_invariants.py)
  6.5 Generate FoundryTester invariant_ wrappers
  6.7 Inject missing imports into Properties*.sol
  7.  Compile merged invariants (setup-aware fix-and-retry, 9 attempts)
"""
from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext

# Sentinel returned when compile fails in --fast mode (skip straight to extract)
SKIP_TO_EXTRACT = "SKIP_TO_EXTRACT"


def run_merge(ctx: PipelineContext) -> str | None:
    """Steps 5-7: ensure Setup + merge invariants + generate wrappers + compile.

    Mutates ctx.setup_sol_text after successful setup gen.
    Returns SKIP_TO_EXTRACT if compile fails in --fast mode.
    """
    import sys
    import re
    from pathlib import Path

    import run_benchmark as _rb

    # Unpack context locals for readability
    component = ctx.component
    repo = ctx.repo
    protocol = ctx.protocol
    args = ctx.args
    logger = ctx.logger
    src_dir = ctx.src_dir
    hyp_dir = ctx.hyp_dir
    clog = ctx.clog
    summary = ctx.summary
    source_code = ctx.source_code
    library_code = ctx.library_code

    chimera_dir = Path(repo) / "test" / "chimera"

    # ─── Step 5: Ensure Chimera Setup exists & compiles BEFORE merge ────
    setup_sol = chimera_dir / "Setup.sol"
    # ── Chimera Setup cache: reuse Setup.sol from a sibling component ──
    # If another component already compiled a Setup.sol, use it as starting template.
    # Siblings share 80%+ of the setup (same protocol deps/mocks), only handlers differ.
    # Lookup order (most durable first):
    #   1. Persistent cache at /tmp/chimera-cache-{protocol}/<sibling>/   ← survives worktree destruction
    #   2. Live sibling worktree /tmp/bench-{protocol}-*/*/test/chimera/
    #   3. Main repo's chimera dir (prior batch)
    _persistent_cache_root = Path("/tmp") / f"chimera-cache-{protocol}"
    if not setup_sol.exists():
        _cache_search = []
        if _persistent_cache_root.exists():
            # Any sibling dir under the persistent cache with a compiled Setup.sol
            _cache_search = list(_persistent_cache_root.glob("*/Setup.sol"))
        if not _cache_search:
            _cache_search = list(Path("/tmp").glob(f"bench-{protocol}-*/*/test/chimera/Setup.sol"))
        if not _cache_search:
            # Also check the main repo's chimera dir from a prior batch
            _main_chimera = Path(repo).parent / "test" / "chimera" / "Setup.sol"
            if _main_chimera.exists():
                _cache_search = [_main_chimera]
        if _cache_search:
            _cached_setup = _cache_search[0]
            logger.info(f"  Step 5a: Reusing Setup.sol from {_cached_setup.parent}")
            chimera_dir.mkdir(parents=True, exist_ok=True)
            import shutil as _shutil_cache
            # Copy ALL chimera files from sibling, not just Setup.sol
            _sibling_chimera = _cached_setup.parent
            for _cf in _sibling_chimera.glob("*.sol"):
                _shutil_cache.copy2(_cf, chimera_dir / _cf.name)
    if not chimera_dir.exists() or not setup_sol.exists():
        logger.info("  Step 5a: Generate Chimera Setup (no existing setup found)")
        chimera_prompt = (
            f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
            f"## Source Code\n```solidity\n{source_code}\n```\n\n"
            f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
            f"Create these files in {chimera_dir}/:\n"
            f"- Setup.sol: deploy {component} with ALL its dependencies. Use MOCKS for external contracts (no fork, no RPC).\n"
            f"  NEVER use vm.createSelectFork — Phase 1 is mock-only for fast feedback.\n"
            f"  For Uniswap V3: create MockUniswapV3Pool. For oracles: MockOracle. For tokens: deal().\n"
            f"  MUST define: contract instance variables accessible by Properties (e.g., `Strategy internal strategy;`)\n"
            f"- BeforeAfter.sol: ghost variables and state snapshots\n"
            f"- Properties.sol: base with ghost vars, inherits BeforeAfter\n"
            f"- TargetFunctions.sol: handlers for each public function with clamped inputs\n"
            f"- FoundryTester.sol: inherits Properties, has invariant_* wrapper functions\n"
            f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa\n\n"
            f"The setup MUST compile with `forge build`. Test it after creating."
        )
        _rb._llm(
            chimera_prompt,
            allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            timeout=1500,  # Increased: complex components need >600s for full setup
            log_file=clog / "chimera_builder.log",
            cwd=repo
        )

    # Verify base chimera compiles before merge
    logger.info("  Step 5b: Verify base chimera compiles")
    base_compile_ok = _rb.fix_and_retry(
        "base_compile",
        ["forge", "build"],
        [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else [],
        max_retries=5,
        cwd=repo
    )
    if not base_compile_ok:
        logger.error("  Base chimera doesn't compile — skipping merge+fuzz")
        summary["status"] = "BLOCKED_CHIMERA"
        summary["gates"]["compile"] = False
        return None  # caller checks summary["status"]

    # ── Persist compiled chimera to /tmp/chimera-cache-{protocol}/{component}/ ──
    # Survives worktree destruction so sibling components can reuse it even if
    # their worktrees start simultaneously or the source worktree is cleaned up.
    try:
        import shutil as _shutil_persist
        _persist_dir = Path("/tmp") / f"chimera-cache-{protocol}" / component
        _persist_dir.mkdir(parents=True, exist_ok=True)
        for _sf in chimera_dir.glob("*.sol"):
            _shutil_persist.copy2(_sf, _persist_dir / _sf.name)
        logger.info(f"  Step 5b: Cached chimera setup → {_persist_dir}")
    except Exception as _e_cache:
        logger.warning(f"  Step 5b: Could not persist chimera cache: {_e_cache}")

    # ─── Step 6: Merge Invariants (setup-aware) ──────────────────────────
    logger.info("  Step 6: Merge Invariants")

    # Extract available variables from Setup.sol so merge knows what exists
    setup_context = ""
    if setup_sol.exists():
        setup_content = setup_sol.read_text(encoding="utf-8")
        setup_context = setup_content[:20000]  # Full Setup.sol — critical for compile fixes

    code, _, _ = _rb.run_cmd([
        sys.executable, str(_rb.SCRIPT_DIR / "merge_invariants.py"),
        "--component", component,
        "--hypotheses-dir", str(hyp_dir),
        "--session-dir", str(_rb.HUNT_SESSION_DIR),
        "--protocol", protocol,
    ], log_file=clog / "merge.log")
    merge_ok = code == 0
    summary["gates"]["merge"] = merge_ok
    if not merge_ok:
        logger.error(f"  BLOCKED: merge_invariants.py failed. Cannot compile without Properties.")
        summary["status"] = "BLOCKED_MERGE"
        return None  # caller checks summary["status"]

    # ─── Step 6.5: Generate FoundryTester invariant_ wrappers ────────────
    logger.info("  Step 6.5: Generate FoundryTester invariant_ wrappers")
    _rb._generate_foundry_tester_wrappers(chimera_dir)

    # ─── Step 6.7: Inject missing imports into Properties*.sol ────────────
    # merge_invariants.py generates Properties files that often lack imports
    # present in Setup.sol (e.g., IStrategy). This pre-injects them to avoid
    # burning 9 compile-fix attempts on the same import error across files.
    setup_path = chimera_dir / "Setup.sol"
    if setup_path.exists():
        setup_text = setup_path.read_text(encoding="utf-8")
        # Extract import lines from Setup.sol
        setup_imports = [line.strip() for line in setup_text.splitlines()
                       if line.strip().startswith("import ")]
        for prop_file in sorted(chimera_dir.glob("Properties*.sol")):
            if prop_file.name in ("PropertiesAll.sol",):
                continue
            prop_text = prop_file.read_text(encoding="utf-8")
            added = []
            for imp in setup_imports:
                # Check if the imported symbol is used but not imported
                # Extract symbol name from: import {Foo} from "..." or import "..."
                m_sym = re.search(r'import\s+\{([^}]+)\}', imp)
                if m_sym:
                    symbols = [s.strip() for s in m_sym.group(1).split(",")]
                    for sym in symbols:
                        if sym in prop_text and imp not in prop_text:
                            added.append(imp)
                            break
            if added:
                # Insert after pragma line
                lines = prop_text.splitlines(keepends=True)
                insert_idx = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith("pragma "):
                        insert_idx = i + 1
                        break
                for imp_line in reversed(added):
                    lines.insert(insert_idx, imp_line + "\n")
                prop_file.write_text("".join(lines), encoding="utf-8")
                logger.info(f"    Injected {len(added)} imports into {prop_file.name}")

    # ─── Step 7: Compile merged invariants (setup-aware fix) ─────────────
    logger.info("  Step 7: Compile (setup-aware fix-and-retry)")

    # Custom fix prompt that understands chimera architecture
    compile_files = [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else []

    for attempt in range(9):
        code, stdout, stderr = _rb.run_cmd(["forge", "build"], cwd=repo)
        if code == 0:
            logger.info(f"  ✅ Compile passed (attempt {attempt + 1})")
            break

        error_text = _rb._extract_first_errors(stderr, max_errors=25, max_chars=5000)
        logger.warning(f"  ❌ Compile failed (attempt {attempt + 1}/9)")

        if attempt < 8:
            # All attempts try to FIX first. Only last resort (attempt 8) deletes.
            # Each level adds more context to help the fixer understand the error.
            if attempt <= 2:
                strategy_hint = (
                    f"## STRATEGY: Fix errors (attempt {attempt + 1}/9)\n"
                    f"1. Read Setup.sol FIRST to understand what contracts/variables are deployed and their EXACT types\n"
                    f"2. Properties*.sol can ONLY reference variables defined in Setup.sol\n"
                    f"3. If an import is missing, add it. If a type is wrong, fix the type\n"
                    f"4. **TYPE MISMATCH FIX**: If error is about IFoo.Struct vs Foo.Struct (interface vs concrete):\n"
                    f"   - Check Setup.sol — if it declares `Foo internal foo` (concrete), use `Foo.StructName` not `IFoo.StructName`\n"
                    f"   - Or remove the type annotation entirely: `(uint a, uint b) = foo.getX()` instead of `IFoo.X memory x = foo.getX()`\n"
                    f"5. **STRUCT GETTER FIX** (MOST COMMON ERROR): Solidity public struct state variables return TUPLES from auto-generated getters.\n"
                    f"   - WRONG: `strategy.mainPosition().tickLower` — `.tickLower` fails on a tuple\n"
                    f"   - RIGHT: `(int24 tickLower, int24 tickUpper, uint128 liquidity) = strategy.mainPosition();`\n"
                    f"   - OR: if the contract has explicit `getMainPosition()` returning a struct, use that instead\n"
                    f"   - Check the source contract for explicit getter functions that return structs by memory\n"
                    f"6. If an invariant references a contract/function not in Setup.sol, check if Setup.sol has a helper for it\n"
                    f"7. Do NOT delete functions — FIX them. Every invariant matters.\n"
                    f"8. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                )
            elif attempt <= 5:
                strategy_hint = (
                    f"## STRATEGY: Fix with more context (attempt {attempt + 1}/9)\n"
                    f"Previous attempts didn't resolve all errors. Read MORE carefully:\n"
                    f"1. Read Setup.sol line by line — list EVERY variable, its type, and what helpers exist\n"
                    f"2. Read the ACTUAL source contract to verify function signatures, return types, and struct definitions\n"
                    f"3. For each error: read the exact line, understand WHY it fails, fix the ROOT CAUSE\n"
                    f"4. Common fixes:\n"
                    f"   - Wrong type: `IFoo.X` → `Foo.X` (match Setup.sol concrete type)\n"
                    f"   - Missing function: check if Setup.sol has a `_helper()` that wraps it\n"
                    f"   - Wrong args: read the actual function signature in the source contract\n"
                    f"   - Missing import: add the import from Setup.sol's import list\n"
                    f"   - Struct field access: use a getter helper or destructure the return value\n"
                    f"5. Do NOT delete functions — FIX them. Every invariant matters.\n"
                    f"6. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                )
            elif attempt <= 7:
                strategy_hint = (
                    f"## STRATEGY: Simplify broken functions (attempt {attempt + 1}/9)\n"
                    f"Multiple fix attempts failed. For functions that STILL don't compile:\n"
                    f"1. Read the error and the function. Understand the INTENT of the invariant.\n"
                    f"2. REWRITE the function body to test the SAME property but with simpler code:\n"
                    f"   - Replace struct access with direct getter calls\n"
                    f"   - Replace complex expressions with multiple simple lines\n"
                    f"   - Use only variables and types from Setup.sol\n"
                    f"3. If a function calls something that doesn't exist, replace with the closest equivalent\n"
                    f"4. PRESERVE the function — rewrite it simpler, do NOT delete it\n"
                    f"5. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                )
            else:
                strategy_hint = (
                    f"## STRATEGY: Last resort — delete ONLY what cannot be fixed (attempt {attempt + 1}/9)\n"
                    f"This is the final attempt. For each remaining error:\n"
                    f"1. Try one more time to fix or simplify the function\n"
                    f"2. ONLY if it's truly unfixable (references something that doesn't exist at all), delete JUST that one function\n"
                    f"3. Keep as many invariants as possible — each one is valuable\n"
                    f"4. Do NOT delete Setup.sol, BeforeAfter.sol, TargetFunctions.sol, FoundryTester.sol, CryticTester.sol\n"
                )

            fix_prompt = (
                f"Fix compile errors in the Chimera fuzzing setup for {component}.\n\n"
                f"## Error\n```\n{error_text}\n```\n\n"
                f"{strategy_hint}\n"
                f"## Available Setup Context\n```solidity\n{setup_context}\n```\n\n"
                f"Read ALL .sol files in {chimera_dir}/ to understand the full picture before making fixes.\n"
                f"After fixing, run `forge build` to verify ALL errors are resolved — fix any new ones too."
            )
            # Shorter timeout for simple fixes, longer for later attempts
            fix_timeout = 300 if attempt <= 2 else 360 if attempt <= 5 else 480
            tier = "fix" if attempt <= 2 else "context" if attempt <= 5 else "simplify" if attempt <= 7 else "delete"
            _rb._llm(
                fix_prompt,
                allowed_tools=["Read", "Edit", "Write", "Grep", "Glob", "Bash"],
                timeout=fix_timeout,
                log_file=clog / f"compile_fix_{attempt:02d}_{tier}.log",
                cwd=repo
            )

    compile_ok = code == 0
    summary["gates"]["compile"] = compile_ok

    if not compile_ok:
        if args.fast:
            logger.warning(f"  Compile failed — fast mode skips to findings extraction")
            summary["gates"]["compile"] = False
            summary["gates"]["phase1"] = False
            return SKIP_TO_EXTRACT
        else:
            logger.error(f"  Component {component} BLOCKED at compile")
            summary["status"] = "BLOCKED_COMPILE"
            return None  # caller checks summary["status"]

    return None
