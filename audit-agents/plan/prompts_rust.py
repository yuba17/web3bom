"""Rust-specific phase prompts — extracted from plan_generator.py in Phase 6.

Variants of the Solidity prompts adapted for Rust codebases (Cargo workspaces,
fuzz harness patterns). Three public entry points:
    - phase_rust_fuzz_scaffold_prompt
    - phase_rust_fuzz_harness_prompt
    - phase_rust_merge_harness

Plus four internal helpers (_rust_enhance_fuzz_prompt,
_phase_hunter_prompt_rust, _phase_findings_rust, _phase_cross_prompt_rust).

Consumers: plan.generator._add_component_steps (Rust branch).
"""
from __future__ import annotations

import json
from pathlib import Path

from plan.detectors import (
    _find_cargo_workspace, _find_rust_crate_src, _hyp_dir, _read_file_safe,
    _results_dir, _rust_crate_sources, _src_dir, _step_id,
)


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
    methodology_dir = Path(__file__).resolve().parent.parent / "prompts" / "hunters" / "rust"
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
