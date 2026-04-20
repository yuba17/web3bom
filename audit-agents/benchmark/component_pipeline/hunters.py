"""hunters.py — Step 2: 12 Hunters (coordinator + context file on disk).

Handles both branches of the hunters phase:
  - _skip_to_merge=True  → fast-path: sets gates, initialises ctx fields, returns None
  - _skip_to_merge=False → full path: prepass load, brief writer, SUB/API dispatch,
                            crosschain skip creation, gate validation, team verification

Returns the sentinel string "BLOCKED_HUNTERS" when the gate check fails so the
caller can propagate the early-return.  Returns None on success (or skip).
"""
from __future__ import annotations

import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.prompt_builders import build_hunter_brief, build_hunter_dispatch_prompt

# Sentinel returned when the hunters gate fails (< MIN_REQUIRED_HUNTERS present)
BLOCKED_HUNTERS = "BLOCKED_HUNTERS"


def run_hunters(ctx: PipelineContext,
                hunters_subset: Optional[set] = None) -> Optional[str]:
    """Run the 12-hunters phase (Step 2) for one component.

    Reads/writes fields on *ctx* in-place.  Returns BLOCKED_HUNTERS if the gate
    check fails (caller must abort the pipeline), otherwise None.
    """
    import run_benchmark as _rb
    import re as _re

    # Unpack frequently used ctx fields for readability (mirrors prior modules)
    component = ctx.component
    repo = ctx.repo
    protocol = ctx.protocol
    args = ctx.args
    logger = ctx.logger
    hyp_dir = ctx.hyp_dir
    clog = ctx.clog
    src_file = ctx.src_file
    src_dir = ctx.src_dir
    summary = ctx.summary

    # ─── Step 2: 12 Hunters (coordinator + context file on disk) ─────────
    hyp_dir = _rb.HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    # Keep ctx in sync (hyp_dir may have been constructed before HUNT_SESSION_DIR
    # was set by main(); rebuild it here to be safe — same pattern as runner.py)
    ctx.hyp_dir = hyp_dir

    if ctx._skip_to_merge:
        hyp_count = len(list(hyp_dir.glob(f"hyp_{component}_*.yaml")))
        logger.info(f"  Steps 2-4: SKIPPED — {hyp_count} existing hypothesis files")
        summary["gates"]["hunters"] = True
        summary["gates"]["deepdive"] = (hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml").exists()
        # Create crosschain skip if needed
        skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
        if not skip_file.exists():
            skip_file.write_text("single-chain protocol")
        # Initialize variables used by Steps 5+ that are normally set in Steps 1-4
        ctx.setup_sol_text = ""
        ctx.setup_var_names = ""
        setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
        if setup_path.exists():
            ctx.setup_sol_text = setup_path.read_text()
            import re as _re_skip
            ctx.setup_var_names = ", ".join(
                _re_skip.findall(r'\b(?:address|uint\d*|int\d*|bool)\s+(?:public\s+)?(\w+)',
                                 ctx.setup_sol_text)
            )
        ctx.prepass_signals_text = ""
        ctx.interfaces_code = ""
        ctx.existing_tests_summary = ""
        ctx.knowledge_context = ""
        return None

    # ── Full path (not _skip_to_merge) ────────────────────────────────────

    # Load prepass signals
    import yaml as _yaml
    prepass_signals_text = ""
    prepass_path = _rb.HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
    if prepass_path.exists():
        try:
            prepass_data = _yaml.safe_load(prepass_path.read_text())
            signals = prepass_data.get("prepass_signals", [])
            top_signals = [s for s in signals if s.get("severity") in ("high", "medium", "critical")][:30]
            if top_signals:
                prepass_signals_text = _yaml.dump(top_signals, default_flow_style=False)
                logger.info(f"  Loaded {len(top_signals)} prepass signals for hunters")
        except Exception as e:
            logger.warning(f"  Failed to load prepass signals: {e}")
    ctx.prepass_signals_text = prepass_signals_text

    # Load Setup.sol for hunter context (helps write compilable invariants)
    setup_sol_text = ""
    setup_var_names = ""
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if setup_path.exists():
        setup_sol_text = setup_path.read_text()
        logger.info(f"  Loaded Setup.sol ({len(setup_sol_text.splitlines())} lines) for hunter context")
        # Extract variable names dynamically so hunters use the REAL names
        # Match: Type internal varName  or  Type public varName
        var_matches = _re.findall(
            r'(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
            setup_sol_text
        )
        # Also match: address internal varName
        addr_matches = _re.findall(
            r'address\s+(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
            setup_sol_text
        )
        all_vars = list(dict.fromkeys(var_matches + addr_matches))  # dedupe, preserve order
        setup_var_names = ", ".join(all_vars) if all_vars else "strategy, vault, token0, token1, pool"
        logger.info(f"  Setup.sol variables: {setup_var_names}")
    ctx.setup_sol_text = setup_sol_text
    ctx.setup_var_names = setup_var_names

    # Write shared context to a file on disk — each hunter agent reads it
    # This guarantees every hunter gets full context regardless of coordinator behavior
    context_dir = _rb.HUNT_SESSION_DIR / "context" / f"{protocol}-bench"
    context_dir.mkdir(parents=True, exist_ok=True)
    hunter_brief_path = context_dir / f"{component}_hunter_brief.md"
    # Load v10 context for hunter brief (benefits both api and sub modes)
    try:
        from hunter_context import load_rejection_context as _load_rej
        _rejection_ctx = _load_rej()
    except Exception:
        _rejection_ctx = ""

    hunter_brief_content = build_hunter_brief(
        component=component, protocol=protocol, src_file=src_file,
        src_dir=src_dir, protocol_model=ctx.protocol_model,
        prepass_signals_text=prepass_signals_text,
        setup_sol_text=setup_sol_text, setup_var_names=setup_var_names,
        existing_tests_summary=ctx.existing_tests_summary,
        knowledge_context=ctx.knowledge_context, interfaces_code=ctx.interfaces_code,
        accumulated_context=ctx.accumulated_context, hyp_dir=hyp_dir,
        rejection_context=_rejection_ctx,
    )
    hunter_brief_path.write_text(hunter_brief_content, encoding="utf-8")
    logger.info(f"  Wrote hunter brief ({len(hunter_brief_content)} chars) to {hunter_brief_path}")

    # Coordinator prompt — lightweight, tells agents to read brief + methodology from disk
    hunter_dispatch_prompt = build_hunter_dispatch_prompt(
        component=component, protocol=protocol, src_file=src_file,
        src_dir=src_dir, hunter_brief_path=hunter_brief_path, hyp_dir=hyp_dir
    )

    t0 = time.time()

    if _rb.USE_SUB_MODE:
        # Sub mode: dispatch individual hunters in parallel from Python
        # Each hunter gets agentic tools to explore code autonomously
        from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
        methodology_dir = _rb.SCRIPT_DIR / "prompts" / "hunters"

        def _run_single_hunter(hunter_name: str) -> str:
            domain_key = HUNTER_DOMAINS.get(hunter_name, ("general", ""))[0]
            rejection_ctx = load_rejection_context()
            few_shot_ctx = "" if _rb.DISABLE_FEW_SHOT else load_few_shot_examples(domain_key)

            prompt = (
                f"You are {hunter_name} analyzing {component} in {protocol}.\n\n"
                f"Read these files FIRST before any analysis:\n"
                f"1. {hunter_brief_path} -- protocol context, Setup.sol, prepass signals, output rules\n"
                f"2. {methodology_dir}/{hunter_name}.md -- your hunting methodology\n\n"
                f"Then read the source code: {src_file} and all .sol files in {src_dir / 'libraries'}/.\n\n"
                f"Follow your methodology file. Write YAML to {hyp_dir}/hyp_{component}_{hunter_name}.yaml\n\n"
                f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
                f"1. Que HACE esta funcion? (inputs, outputs, estado)\n"
                f"2. Que ASUME? (precondiciones implicitas)\n"
                f"3. Que pasa si la asuncion es FALSA?\n"
                f"4. COMO puede un atacante forzar esa condicion?\n"
                f"5. CUAL es el impacto concreto en fondos/acceso?\n\n"
                f"{rejection_ctx}\n{few_shot_ctx}"
            )
            _rb._llm(prompt, allowed_tools=["Read", "Write", "Grep", "Glob", "Bash"],
                 timeout=1800,
                 log_file=clog / f"hunter_{hunter_name}.log",
                 cwd=repo)
            return hunter_name

        hunters = ["MathHunter", "AccessHunter", "FlowHunter", "OracleHunter",
                    "DomainHunter", "TrustBoundaryHunter", "WildcardHunter",
                    "SignatureHunter", "DoSHunter", "LogicHunter",
                    "AdversarialHunter", "LibraryHunter"]
        # Filter to subset if --hunters was provided (non-empty = user-specified subset).
        # hunters_subset is pre-validated by main() at startup (fail-fast); reuse it here.
        # When args.hunters is "" (default), hunters_subset is None — run all hunters.
        if hunters_subset is not None:
            hunters = [h for h in hunters if h in hunters_subset]
        logger.info(f"  Sub mode: {len(hunters)} hunters, {_rb.PARALLEL_HUNTERS} parallel")
        failed_hunters = []
        with ThreadPoolExecutor(max_workers=_rb.PARALLEL_HUNTERS) as executor:
            future_to_hunter = {
                executor.submit(_run_single_hunter, h): h for h in hunters
            }
            for future in as_completed(future_to_hunter):
                hunter_name = future_to_hunter[future]
                try:
                    future.result()
                except Exception as e:
                    failed_hunters.append(hunter_name)
                    logger.warning(f"  Hunter {hunter_name} FAILED: {e} — continuing with remaining hunters")
        if failed_hunters:
            logger.warning(f"  {len(failed_hunters)} hunters failed: {failed_hunters}")
    else:
        # API mode: single coordinator dispatches 12 agents
        rc, out = _rb._llm(
            hunter_dispatch_prompt,
            allowed_tools=["Agent", "Read", "Write", "Edit", "Grep", "Glob"],
            timeout=1800,
            log_file=clog / "hunters_dispatch.log",
            cwd=repo
        )

    elapsed = time.time() - t0
    logger.info(f"  12 Hunters completed ({elapsed/60:.1f}min)")

    # Create crosschain skip file
    skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
    if not skip_file.exists():
        skip_file.write_text("single-chain protocol")

    # Check hunters gate — in benchmark mode, verify YAML count directly
    # (pipeline_gate.py checks for solidity_property fields which benchmark hunters don't require)
    REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                        "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter"]
    hyp_count = len(list(hyp_dir.glob(f"hyp_{component}_*.yaml")))
    MIN_REQUIRED_HUNTERS = 7  # allow up to 2 failures
    missing_hunters = [h for h in REQUIRED_HUNTERS
                       if not (hyp_dir / f"hyp_{component}_{h}.yaml").exists()]
    present_count = len(REQUIRED_HUNTERS) - len(missing_hunters)
    if present_count < MIN_REQUIRED_HUNTERS:
        logger.error(f"  BLOCKED: Only {present_count}/{len(REQUIRED_HUNTERS)} required hunters present "
                     f"(minimum {MIN_REQUIRED_HUNTERS}). Missing: {missing_hunters}")
        summary["status"] = BLOCKED_HUNTERS
        summary["gates"]["hunters"] = False
        return BLOCKED_HUNTERS
    else:
        summary["gates"]["hunters"] = True
        if missing_hunters:
            logger.warning(f"  Gate hunters: PASS with degradation — {present_count}/{len(REQUIRED_HUNTERS)} "
                          f"required hunters present ({hyp_count} total YAML files). "
                          f"Missing: {missing_hunters}")
        else:
            logger.info(f"  Gate hunters: PASS ({hyp_count} YAML files, all {len(REQUIRED_HUNTERS)} required hunters present)")

    # Mandatory team output verification
    verify_result = subprocess.run([
        "python3", str(_rb.SCRIPT_DIR / "verify_team_outputs.py"),
        "--session-dir", str(Path(hyp_dir).parent.parent),
        "--protocol", protocol,
        "--groups", json.dumps([{"group_id": 0, "components": [component]}])
    ], capture_output=True, text=True)
    if verify_result.returncode != 0:
        logger.warning(f"  Team verification warnings:\n{verify_result.stdout[:500]}")

    # Step 3 (Library Analyzer) — now runs as LibraryHunter (#11) in parallel with other hunters above
    return None
