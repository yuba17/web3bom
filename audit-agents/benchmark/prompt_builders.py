"""Prompt builders — extracted from run_benchmark.py in Phase 6.

Provides 9 build_*_prompt functions for the various phases of the hunt
pipeline (hunter, dispatch, deepdive, poc, escalation, redteam, variant,
report, cross-pair), plus the load_prompt + read_source template helpers.

Breaks the Phase-0..5 lazy import cycle: plan/prompts_solidity imports
these top-level (was 4 lazy imports in plan_generator.py).

Consumers: benchmark.poc_pipeline, benchmark.component_pipeline,
benchmark.finding_pipeline, benchmark.cross_component, plan.prompts_solidity.
"""

from pathlib import Path


def load_prompt(template_name: str, context: dict) -> str:
    """Load and render a prompt template."""
    from prompt_renderer import render_prompt
    return render_prompt(template_name, context)


def read_source(src_path: str) -> str:
    """Read source file, truncate at 60K chars."""
    content = Path(src_path).read_text(encoding="utf-8")
    if len(content) > 60000:
        content = content[:60000] + "\n// ... truncated at 60K chars"
    return content


def build_hunter_brief(component: str, protocol: str, src_file, src_dir,
                       protocol_model: str, prepass_signals_text: str,
                       setup_sol_text: str, setup_var_names: str,
                       existing_tests_summary: str, knowledge_context: str,
                       interfaces_code: str, accumulated_context: str,
                       hyp_dir,
                       rejection_context: str = "",
                       few_shot_context: str = "",
                       context_enrichment_block: str = "") -> str:
    """Build the hunter brief content written to hunter_brief_{component}.md."""
    return (
        f"# Hunter Brief — {component} ({protocol})\n\n"
        f"## Source Files to Read\n"
        f"- Main contract: {src_file}\n"
        f"- Libraries: {src_dir / 'libraries'}/ (read ALL .sol files)\n\n"
        f"## Protocol Model\n{protocol_model[:3000] if protocol_model else 'Read the source to understand the protocol.'}\n\n"
        f"## Prepass Signals (static analysis findings)\n```yaml\n{prepass_signals_text[:4000] if prepass_signals_text else 'None'}\n```\n\n"
        f"## Chimera Setup (use these EXACT variable names in solidity_property)\n```solidity\n{setup_sol_text}\n```\n\n"
        f"## Dev Test Gaps (what the project's own tests MISSED)\n{existing_tests_summary[:2000] if existing_tests_summary else 'No analysis available.'}\n\n"
        f"## Known Vulnerability Patterns (from knowledge base)\n{knowledge_context[:2000] if knowledge_context else 'None loaded.'}\n\n"
        f"## Interfaces (function signatures the contract calls externally)\n```solidity\n{interfaces_code[:5000] if interfaces_code else 'None loaded.'}\n```\n\n"
        f"## Context from Previous Components\n{accumulated_context[:1500] if accumulated_context else 'This is the first component.'}\n\n"
        + (f"{rejection_context}\n\n" if rejection_context else "")
        + (f"{few_shot_context}\n\n" if few_shot_context else "")
        + (f"{context_enrichment_block}\n\n" if context_enrichment_block else "")
        + f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
        f"Para cada hipotesis, razona estos 5 pasos ANTES de escribir el YAML:\n"
        f"1. Que HACE esta funcion? (inputs, outputs, estado modificado)\n"
        f"2. Que ASUME? (precondiciones implicitas, trust en callers)\n"
        f"3. Que pasa si la asuncion es FALSA? (estado corrupto, leak de fondos)\n"
        f"4. COMO puede un atacante forzar esa condicion? (flash loan, reentrancy, params extremos)\n"
        f"5. CUAL es el impacto concreto? (perdida en $, DoS permanente, escalacion de privilegios)\n\n"
        f"## OUTPUT RULES\n"
        f"1. Write YAML to ABSOLUTE PATH: {hyp_dir}/hyp_{component}_<YourHunterName>.yaml\n"
        f"   DO NOT use relative paths. DO NOT create hunt_session/ inside the repo.\n"
        f"2. Each hypothesis MUST have `solidity_property`: a COMPLETE Solidity function body\n"
        f"3. Use EXACT variable names from Setup.sol above: {setup_var_names}\n"
        f"4. Use Chimera assertion helpers: t(condition, \"msg\"), eq(a, b, \"msg\"), gte(a, b, \"msg\"), lte(a, b, \"msg\")\n"
        f"5. Confidence >= 60% for validated: true\n"
        f"6. Minimum 5 hypotheses, no maximum\n"
        f"7. YAML schema: id, tier, type, description, attack_scenario, solidity_property, validated, priority, confidence, vulnerable_location\n"
        f"   `vulnerable_location` is REQUIRED for every finding. Format:\n"
        f"   ```yaml\n"
        f"   vulnerable_location:\n"
        f"     contract: \"Strategy.sol\"\n"
        f"     function: \"_setSecondaryPositionsTicks\"  # the primary function where bug lives\n"
        f"     lines: [142, 143]                          # exact line numbers from the source\n"
        f"     vulnerable_code: \"tick = price() >> 1\"   # the exact wrong expression/statement\n"
        f"     fix: \"should use sqrtPriceX96 not spot price\"\n"
        f"   ```\n"
        f"   This is how manual auditors think — they know the EXACT LINE and EXACT CODE that's wrong.\n"
        f"   Do NOT write a vulnerable_location that just says 'the whole function' — be specific.\n"
        f"8. **TYPE RULE (CRITICAL)**: Setup.sol declares CONCRETE types, not interfaces.\n"
        f"   Look at Setup.sol variable declarations to know the exact type of each variable.\n"
        f"   In solidity_property, use the SAME type as declared in Setup.sol for struct access.\n"
        f"   WRONG: `IFoo.SomeStruct memory x = foo.getX()` (if Setup.sol says `Foo internal foo`)\n"
        f"   RIGHT: `Foo.SomeStruct memory x = foo.getX()` (matches the concrete type in Setup.sol)\n"
        f"   SAFEST: avoid struct type annotations — use tuple destructuring: `(uint a, uint b) = foo.getX()`\n"
        f"9. **STRUCT GETTER RULE (CRITICAL)**: Solidity auto-generates getters for public struct state variables that return TUPLES, not structs.\n"
        f"   WRONG: `contract.myStruct().field` — tuple has no named fields, this WILL NOT compile\n"
        f"   WRONG: `(a,b) = (contract.myStruct().x, contract.myStruct().y)` — same error\n"
        f"   RIGHT: `(uint a, uint b) = contract.myStruct();` — destructure the tuple\n"
        f"   RIGHT: `MyStruct memory s = contract.getMyStruct();` — if an explicit getter exists that returns the struct type\n"
        f"   Before using `.field` access, verify the contract has an explicit getter returning the struct type.\n"
        f"10. Example solidity_property:\n"
        f"   ```\n"
        f"   function property_vault_no_drain() public {{\n"
        f"       uint256 bal0 = token0.balanceOf(address(vault));\n"
        f"       t(bal0 > 0, \"Vault drained\");\n"
        f"   }}\n"
        f"   ```\n"
        f"11. Example vulnerable_location:\n"
        f"   ```yaml\n"
        f"   vulnerable_location:\n"
        f"     contract: \"Leverager.sol\"\n"
        f"     function: \"withdraw\"\n"
        f"     lines: [232]\n"
        f"     vulnerable_code: \"token1Amount = amountOut;\"  # amountOut is for token0, wrong for token1\n"
        f"     fix: \"compute token1Amount independently from token0 amountOut\"\n"
        f"   ```\n"
    )


def build_hunter_dispatch_prompt(component: str, protocol: str, src_file,
                                 src_dir, hunter_brief_path, hyp_dir) -> str:
    """Build the coordinator prompt that launches 12 hunters."""
    methodology_dir = Path(__file__).resolve().parent.parent / "prompts" / "hunters"
    return f"""You are the Hunt Coordinator for {component} in {protocol}.

Your ONLY job: launch 12 hunter subagents in parallel using the Agent tool, then wait for all to complete.

## CRITICAL INSTRUCTION FOR EACH AGENT
Every agent prompt MUST follow this EXACT template (fill in [HunterName]):

"You are [HunterName] analyzing {component} in {protocol}.

Read these files FIRST before any analysis:
1. {hunter_brief_path} — protocol context, Setup.sol, prepass signals, output rules
2. {methodology_dir}/[HunterName].md — your hunting methodology, examples of real bugs to find, and key questions

Then read the source code: {src_file} and all .sol files in {src_dir / 'libraries'}/.

Follow your methodology file. Write YAML to {hyp_dir}/hyp_{component}_[HunterName].yaml"

Do NOT summarize or paraphrase the methodology — the agent MUST read the file itself.

## HYPOTHESIS QUALITY REQUIREMENTS
- Find ≥2 distinct bugs per public/external function analyzed, or explicitly state "no additional vulnerabilities found at confidence ≥60%".
- Do NOT include hypotheses with confidence < 55%. Quality over quantity.
- Do NOT generate low-confidence padding hypotheses.
- Each hypothesis MUST have a concrete poc_sketch with specific function calls and values.
- If a function has BOTH a prepass signal AND a hunter hypothesis → investigate deeply for HIDDEN secondary bugs in the same function.
- When 2+ hunters flag the same area (convergence), the DeepDive will investigate — but YOU should still try to find the deeper bug.

## The 12 Hunters (ALL in parallel, single message)
Launch using Agent tool with run_in_background=true for all except the last:

1. **MathHunter** — arithmetic, precision, share/exchange rate manipulation
2. **AccessHunter** — roles, modifiers, privilege escalation, initialization
3. **FlowHunter** — reentrancy, CEI, callbacks, state transitions, flash loans
4. **OracleHunter** — price feeds, TWAP manipulation, oracle staleness
5. **DomainHunter** — protocol invariants, symmetric inspection, value tracing
6. **TrustBoundaryHunter** — external call trust, weird ERC-20, proxy/upgrade
7. **WildcardHunter** — low-level EVM, composability, gas griefing
8. **SignatureHunter** — ecrecover, EIP-712, nonces, permit, replay
9. **DoSHunter** — unbounded loops, gas exhaustion, blocked withdrawals
10. **LogicHunter** — copy-paste bugs, wrong variables, sibling function diffs, symmetry
11. **AdversarialHunter** — attacker mindset, backward reasoning from value exits, assumption breaking
12. **LibraryHunter** — library function analysis: stale state, ignored returns, broken loops

Launch ALL 12 NOW in a single response."""


def build_deepdive_prompt(component: str, protocol: str, source_code: str,
                          library_code: str, setup_sol_text: str,
                          protocol_model: str, hyp_dir,
                          convergence_text: str, hunter_digest: str) -> str:
    """Build the DeepDiveHunter prompt."""
    return (
        f"You are DeepDiveHunter analyzing {component} of {protocol}.\n\n"
        f"## Source Code\n```solidity\n{source_code}\n```\n\n"
        f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
        f"## Chimera Setup (use these variable names in solidity_property)\n```solidity\n{setup_sol_text}\n```\n\n"
        f"## Protocol Model\n{protocol_model[:3000]}\n\n"
        f"## Pre-Digested Hunter Convergences\n{convergence_text or 'No convergences detected.'}\n\n"
        f"## Hunter Hypothesis Summary (tier 1-2 only)\n{hunter_digest[:8000]}\n\n"
        f"Write hypotheses to: {hyp_dir}/hyp_{component}_DeepDiveHunter.yaml\n"
        f"No artificial limit. Confidence >= 60% for validated: true.\n"
        f"Each solidity_property MUST be a complete function using variable names from Setup.sol.\n"
        f"Use Chimera helpers: t(condition, \"msg\"), eq(a, b, \"msg\"), gte(a, b, \"msg\")."
    )


def build_poc_prompt(finding: dict, fid: str, component: str,
                     relevant_code: str, interfaces_code: str,
                     setup_content: str, poc_path, test_name: str,
                     is_pre_production: bool) -> str:
    """Build the PoC generation prompt."""
    vuln_loc = finding.get("vulnerable_location") or {}
    vuln_loc_section = ""
    if vuln_loc:
        vuln_loc_section = (
            f"## EXACT VULNERABLE LOCATION (from hunter analysis)\n"
            f"Contract: {vuln_loc.get('contract', 'N/A')}\n"
            f"Function: `{vuln_loc.get('function', 'N/A')}`\n"
            f"Lines: {vuln_loc.get('lines', 'N/A')}\n"
            f"Vulnerable code: `{vuln_loc.get('vulnerable_code', 'N/A')}`\n"
            f"Fix: {vuln_loc.get('fix', 'N/A')}\n\n"
        )

    poc_hint_section = ""
    if finding.get("_poc_hint"):
        poc_hint_section = f"## Verification Hint (from code-read step)\n{finding['_poc_hint']}\n\n"

    return (
        f"Write a Foundry fork test that proves this vulnerability.\n\n"
        f"## Finding\n"
        f"ID: {fid}\n"
        f"Title: {finding.get('title', fid)}\n"
        f"Root Cause: {finding.get('root_cause', finding.get('description', ''))}\n"
        f"Component: {component}\n"
        f"Fuzz confirmed: {finding.get('fuzz_confirmed', False)}\n"
        f"Property that broke: {finding.get('property_name', 'N/A')}\n\n"
        f"{poc_hint_section}"
        f"## Counterexample Trace from Fuzzer\n"
        f"```\n{finding.get('counterexample_trace', 'No trace available')}\n```\n\n"
        f"{vuln_loc_section}"
        f"## Source Code (focused on vulnerable area)\n```solidity\n{relevant_code}\n```\n\n"
        f"## Interfaces (CRITICAL — use ONLY these function signatures)\n"
        f"```solidity\n{interfaces_code[:5000]}\n```\n\n"
        f"## Deployment Template (from test/chimera/Setup.sol)\n"
        f"```solidity\n{setup_content}\n```\n"
        f"COPY the deployment pattern above for your setUp(). It shows correct constructor args,\n"
        f"fork setup, and dependency initialization.\n\n"
        f"## STEP 0: Constraint Analysis (DO THIS BEFORE WRITING CODE)\n"
        f"Before writing any Solidity, read the source code and:\n"
        f"1. List EVERY require/revert/assert that could block your exploit path\n"
        f"2. For each constraint, determine the exact values that satisfy it\n"
        f"3. If a swap is needed: calculate the MAXIMUM amount that stays within protocol limits\n"
        f"4. If a call needs specific msg.sender: check if it's immutable/hardcoded (if yes, the bug may be unexploitable)\n"
        f"5. Design your PoC to satisfy ALL constraints while exploiting the bug\n\n"
        f"## Requirements\n"
        f"1. Write to: {poc_path}\n"
        f"2. Test function MUST be named `{test_name}`\n"
        f"3. Use ONLY ASCII characters in strings — NO em-dashes or curly quotes\n"
        f"4. Keep <16 local variables per function (avoid stack-too-deep)\n"
        + (
        f"5. DEPLOYMENT STRATEGY — PRE-PRODUCTION PROTOCOL (contracts NOT deployed on-chain):\n"
        f"   a) Use vm.createFork(vm.envString(\"BASE_RPC_URL\")) to get real token state (USDC, WETH, etc.)\n"
        f"   b) Deploy ALL protocol contracts yourself in setUp() using `new Contract(args)`\n"
        f"   c) Read constructor args from src/ — look for immutables and initializers\n"
        f"   d) Use vm.deal() to fund attacker with tokens, then interact with YOUR deployed contracts\n"
        f"   e) Do NOT try to call contracts at hardcoded addresses — they don't exist on-chain\n"
        if is_pre_production else
        f"5. Use vm.createFork with the deployed contract address — REAL fork state, not local deployment\n"
        ) +
        f"6. The test MUST prove CONCRETE DAMAGE — one of:\n"
        f"   a) Token balance loss: `assertGt(balanceBefore - balanceAfter, threshold)`\n"
        f"   b) State corruption: a storage value is wrong after the attack\n"
        f"   c) DoS: a critical function reverts when it shouldn't\n"
        f"   d) Privilege escalation: unauthorized caller can execute privileged action AND it persists\n"
        f"7. If the attack requires msg.sender == immutable_address, the bug is likely unexploitable — SKIP it.\n\n"
        f"## Workflow\n"
        f"1. Complete Step 0 constraint analysis (write it as a comment in the test)\n"
        f"2. Write the .sol file\n"
        f"3. Run: forge test --match-test {test_name} --match-path test/poc/{poc_path.name} -vvv --fuzz-runs 1\n"
        f"4. If it fails, read the error and fix the .sol file\n"
        f"5. Repeat until it passes or you've tried 3 times\n\n"
        f"Keep it minimal — just enough to prove the bug exists."
    )


def build_escalation_prompt(finding: dict, finding_context: str) -> str:
    """Build the EscalationHunter prompt."""
    return (
        f"You are EscalationHunter. Establish the severity CEILING for this finding.\n\n"
        f"{finding_context}\n\n"
        f"Execute ALL 5 checks in order. Even if the first is ESCALABLE, continue all 5.\n\n"
        f"### CHECK 1 — ESCAPE MECHANISMS (highest ROI)\n"
        f"Can the admin/protocol undo the damage once it occurs?\n"
        f"Look for: pause(), emergencyShutdown(), upgradeable proxies, rescue functions.\n"
        f"If NO escape mechanism AND impact is permanent → severity goes up one level.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + 2-line justification.\n\n"
        f"### CHECK 2 — SCOPE MULTIPLIER\n"
        f"Does a single attack execution affect 1 victim or N victims?\n"
        f"Does it affect all positions in a pool simultaneously? All lenders? Repeatable at ~0 marginal cost?\n"
        f"If 1 attack → N victims (all users of pool/vault) → severity goes up one level.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + victim count and why.\n\n"
        f"### CHECK 3 — PERMANENCE OF DAMAGE\n"
        f"Is damage temporary (reversible) or permanent?\n"
        f"Can a user recover funds? Can admin restore correct state? Does damage accumulate over time?\n"
        f"Permanent + no escape = +1 level. Temporary with mitigation window = no escalation.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + permanence description.\n\n"
        f"### CHECK 4 — COMBINATION WITH PRIOR FINDINGS\n"
        f"Combined with another confirmed finding in same protocol, does it produce greater impact?\n"
        f"Only escalate if combination produces qualitatively different impact (e.g., liquidation bypass + oracle manipulation = fund theft).\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] / [CONDICIONAL] + which finding and how.\n\n"
        f"### CHECK 5 — ATTACKER DIRECT (no permissions)\n"
        f"Can an unprivileged actor trigger the impact directly without admin or external event?\n"
        f"If any user can trigger with only capital → +1 level. If requires trusted role → no escalation.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + who can trigger and how.\n\n"
        f"## REQUIRED OUTPUT FORMAT:\n"
        f"```\n"
        f"ESCALATION HUNTER REPORT\n"
        f"═════════════════════════\n"
        f"Finding: {finding.get('title', finding.get('id', '?'))}\n"
        f"Severidad propuesta: {finding['severity']}\n\n"
        f"CHECK 1 — Escape Mechanisms:    [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 2 — Scope Multiplier:     [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 3 — Permanencia del daño: [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 4 — Combinación:          [ESCALABLE/NO_ESCALABLE/CONDICIONAL]\n"
        f"  → [justification]\n"
        f"CHECK 5 — Attacker directo:     [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n\n"
        f"TECHO DE SEVERIDAD: [Critical/High/Medium]\n"
        f"ARGUMENTO PARA REDTEAM (3-5 lines): [concrete, technical, falsifiable]\n"
        f"CHECKS QUE ESCALARON: [...]\n"
        f"CHECKS QUE NO ESCALARON: [...]\n"
        f"```\n\n"
        f"Rules:\n"
        f"- Max 1 level escalation per check. Multiple checks REINFORCE the level, not raise further.\n"
        f"- If no check escalates → ceiling = original severity.\n"
        f"- The RedTeam argument MUST be falsifiable — if you can't describe how JUDGE could attack it, it's too vague.\n"
        f"- Don't access code not provided in the snippets. Mark as [CONDICIONAL: requires verifying X]."
    )


def build_redteam_prompt(finding_context: str, fid: str, finding: dict,
                         component: str) -> str:
    """Build the RedTeam prompt with 4 attackers."""
    return (
        f"You are the RedTeam moderator. Attack this finding aggressively to destroy it before reporting.\n\n"
        f"{finding_context}\n\n"
        f"## 4 ADVERSARIAL ATTACKERS\n\n"
        f"**[JUDGE]** — Platform judge (Sherlock/C4/Cantina/Immunefi)\n"
        f"Seeks formal rejection: out of scope, known issue, requires admin, by design.\n"
        f"In Ronda 0: would a platform judge assign this severity? Too high (inflated) or too low?\n\n"
        f"**[DEVIL]** — Technical devil's advocate\n"
        f"Attacks exploit logic: PoC doesn't prove real loss, oracle can't be manipulated this way, slippage protection blocks it.\n"
        f"In Ronda 0: technically verify the 5 severity checks. Can severity go UP or DOWN?\n\n"
        f"**[GUARD]** — Protocol defender\n"
        f"Finds existing mitigations: checks in callers, governance limits, rate limits, circuit breakers.\n"
        f"In Ronda 0: is there a rescue mechanism (multisig, timelock, proxy upgrade) that reduces permanent impact?\n\n"
        f"**[ECONOMIST]** — Economic analyst\n"
        f"Calculates attack profitability: gas, capital needed, MEV competition, timing windows.\n"
        f"In Ronda 0: how much real money at risk? $1K or $1M? Magnitude matters.\n\n"
        f"## SEVERITY CALIBRATION TABLE\n"
        f"| Scope (% affected ops) | Permanence | Path type | Severity |\n"
        f"|---|---|---|---|\n"
        f"| 100% (all users) | permanent (no admin fix) | normal operation | Critical or High |\n"
        f"| 100% | temporal (admin can fix) | normal operation | High |\n"
        f"| 50% (one token/path) | permanent | normal operation | High |\n"
        f"| 50% | temporal | requires specific config | Medium |\n"
        f"| 10% (edge case) | permanent | requires attack | Medium |\n"
        f"| 10% | temporal | requires attack | Low |\n\n"
        f"PRIOR CALIBRATION ERRORS:\n"
        f"- Fee loss in ALL liquidations → we said Medium, GT said High. Rule: 100% scope + permanent + normal path = High minimum.\n"
        f"- DoS only in denomination==token1 path → we said High, GT said Medium. Rule: 50% scope + permanent + normal = Medium/High boundary → Medium.\n\n"
        f"## PROTOCOL: RONDA 0 + 3 ROUNDS\n\n"
        f"### RONDA 0: Severity Calibration\n"
        f"All 4 attackers answer these 5 questions BRIEFLY. Severity can go UP or DOWN:\n"
        f"1. Escape mechanisms: can admin/protocol undo damage? No rescue + permanent → consider raising.\n"
        f"2. Scope: 1 victim or all pool/vault users? Systemic → raise. Single user → lower.\n"
        f"3. Permanence: reversible or permanent? Permanent → raise. Temporal with reaction window → lower.\n"
        f"4. Trigger: unprivileged attacker can execute directly? Yes → raise. Requires trusted role → lower.\n"
        f"5. Combination: adds to another confirmed finding for qualitatively greater impact?\n"
        f"Each attacker gives severity verdict in ONE line at end of Ronda 0.\n"
        f"If consensus that proposed severity is wrong → ADJUST BEFORE rounds 1-3.\n\n"
        f"### ROUND 1: First Attack (each attacker, max 150 words)\n"
        f"Each attacker identifies the STRONGEST argument against the finding. Only the best argument.\n\n"
        f"### ROUND 2: Cross-response\n"
        f"Are the other attackers correct? Or wrong? Can ally with or contradict each other.\n"
        f"If two attackers contradict → ambiguity signal, must resolve.\n\n"
        f"### ROUND 3: Individual Verdict (1 paragraph each)\n"
        f"Each attacker: KILL (finding doesn't survive) / WEAKEN (valid but lower severity) / SURVIVE (solid)\n\n"
        f"## REQUIRED FINAL OUTPUT:\n"
        f"```\n"
        f"VEREDITO REDTEAM\n"
        f"════════════════\n"
        f"Finding: {finding.get('title', finding.get('id', '?'))}\n"
        f"Componente: {component}\n\n"
        f"RESULTADO: [REPORT / REPORT_DOWNGRADED / DO_NOT_REPORT]\n"
        f"FIX_SCOPE: [same_fix / different_fix / n_a]\n\n"
        f"Argumentos que sobrevivieron:\n  [list]\n"
        f"Argumentos que lo debilitan:\n  [list]\n"
        f"Argumentos que fallaron (attackers equivocados):\n  [list]\n\n"
        f"Severidad propuesta:   {finding['severity']}\n"
        f"Severidad final:       [Critical/High/Medium/Low]\n"
        f"Razón del cambio:      [why up/down/same]\n"
        f"Confianza: [0-100%]\n\n"
        f"Qué añadir al reporte para sobrevivir review:\n  [specific points]\n"
        f"Qué NO incluir (weakens argument):\n  [list]\n"
        f"```\n\n"
        f"## FIX_SCOPE — how to choose:\n"
        f"Use FIX_SCOPE to flag whether this finding shares a root-cause fix with another finding already REPORTED in this session.\n"
        f"- `same_fix`: the fix is a single code change that also resolves another reported finding (e.g., identical bug in shared library). Treat as dedup candidate downstream.\n"
        f"- `different_fix`: the finding mirrors another one (same bug class / copy-paste) BUT requires its own code change in a different file/function. Each fix is independent → keep both as separate REPORTs.\n"
        f"- `n_a`: finding has no obvious sibling, or this is a DO_NOT_REPORT. Default.\n"
        f"Rule: copy-paste bugs in different locations = different_fix (each site must be patched individually).\n\n"
        f"Rules:\n"
        f"- Attackers do NOT help the hunter — they try to KILL the finding.\n"
        f"- Specific arguments ONLY — 'could be by design' without citing code is INVALID.\n"
        f"- No authority arguments — 'OpenZeppelin audited this' is invalid unless you cite what they found.\n"
        f"- Hunter CANNOT respond during rounds.\n"
        f"- If all 4 say KILL → DO_NOT_REPORT, no exceptions.\n"
        f"- If 3 SURVIVE + 1 KILL → investigate the KILL argument deeply before reporting.\n\n"
        f"## REPORT vs REPORT_DOWNGRADED — use these exact criteria:\n"
        f"REPORT: the finding is valid at the proposed severity. Attackers found no fatal flaw and no severe overestimate.\n"
        f"REPORT_DOWNGRADED: the finding is valid but the severity is WRONG (too high) AND you can state the correct severity.\n"
        f"  → Only use DOWNGRADED if the severity deserves 1+ levels down (e.g., proposed High → correct Medium).\n"
        f"  → Do NOT use DOWNGRADED just because the finding is 'borderline' or 'context-dependent'.\n"
        f"  → If attackers couldn't kill it AND severity seems right → REPORT, not DOWNGRADED.\n"
        f"DO_NOT_REPORT: at least one attacker found a FATAL flaw (out of scope, requires trusted role, mitigated, impossible to trigger)."
    )


def build_variant_prompt(fid: str, finding_context: str, repo: str) -> str:
    """Build the VariantHunter prompt."""
    return (
        f"You are VariantHunter. A confirmed bug rarely appears only once. Search for variants systematically.\n\n"
        f"{finding_context}\n\n"
        f"## STEP 1: ROOT CAUSE STATEMENT\n"
        f"Write the root cause in this EXACT format:\n"
        f'> "This vulnerability exists because **[UNTRUSTED DATA]** reaches **[DANGEROUS OPERATION]** without **[REQUIRED PROTECTION]**."\n\n'
        f"Examples:\n"
        f'- "...because **slot0.sqrtPriceX96** reaches **amountOut calculation** without **using TWAP instead of spot price**"\n'
        f'- "...because **balanceOf(address(this))** reaches **share calculation** without **pre-operation snapshot**"\n\n'
        f"If you can't write it in this format, you don't understand the bug well enough.\n\n"
        f"## STEP 2: EXACT MATCH (Level 0)\n"
        f"Use Grep to search the EXACT code pattern of the bug.\n"
        f"MUST match ONLY the known instance (1 result). If 0: pattern is wrong. If >1: already have variant candidates.\n"
        f"Document: Level 0: <pattern>, Matches: N, Locations: [list]\n\n"
        f"## STEP 3: PROGRESSIVE ABSTRACTION (Levels 1-3)\n"
        f"Abstract ONE element at a time. After each, search and document.\n\n"
        f"**Level 1** — Variable names → wildcards:\n"
        f"Replace specific names with generic patterns.\n\n"
        f"**Level 2** — Function names → family:\n"
        f"Replace specific function with the family (e.g., withdraw → any function that sends tokens).\n\n"
        f"**Level 3** — Full structural pattern:\n"
        f"Combine multiple grep searches to find the structural pattern.\n\n"
        f"For EACH level document: Level N: <pattern>, Matches: N, New locations: [list]\n\n"
        f"## STEP 4: TRIAGE\n"
        f"For EACH location found in Levels 1-3 that is NOT the original:\n"
        f"- **TRUE VARIANT**: same root cause, same impact, different fix → NEW FINDING\n"
        f"- **SIMILAR PATTERN**: same structure but different context → INVESTIGATE\n"
        f"- **FALSE POSITIVE**: pattern matches but protection/context prevents it → DISCARD\n\n"
        f"## REQUIRED OUTPUT FORMAT:\n"
        f"```\n"
        f"# Variant Hunt — {fid}\n\n"
        f"## Root Cause Statement\n"
        f'"This vulnerability exists because..."\n\n'
        f"## Search Results\n"
        f"### Level 0 (exact match)\n"
        f"### Level 1 (variable abstraction)\n"
        f"### Level 2 (function family)\n"
        f"### Level 3 (structural)\n\n"
        f"## Triage\n"
        f"| Location | Level | Classification | Notes |\n\n"
        f"## Variants Found: X\n"
        f"```\n\n"
        f"Search ALL .sol files in {repo}/src/. Max 15 minutes."
    )


def build_report_prompt(finding_context: str, report_path) -> str:
    """Build the ReportWriter prompt."""
    return (
        f"You are ReportWriter. Convert a RedTeam-validated finding into a platform-ready report.\n\n"
        f"{finding_context}\n\n"
        f"## STEP 1 — PLATFORM: SHERLOCK\n"
        f"This is a Sherlock contest benchmark. Use the Sherlock template.\n\n"
        f"## STEP 2 — REDTEAM MAPPING\n"
        f"Extract from the finding context:\n"
        f"- Severidad final → Severity field\n"
        f"- Surviving arguments → Impact section (strongest ones)\n"
        f"- Weakening arguments → mention + counter in Impact\n"
        f"- What NOT to include → exclusion list (don't put in report)\n"
        f"- What to ADD → reinforce in Description or Impact\n"
        f"Only arguments that survived RedTeam go in the report.\n\n"
        f"## STEP 3 — ANTI-AI WRITING RULES (CRITICAL)\n"
        f"DO NOT use:\n"
        f"- Filler phrases: 'It is important to note', 'This could potentially lead to', 'It is worth mentioning'\n"
        f"- Hedging: 'may', 'could', 'might', 'potentially', 'in some cases' — the PoC proved it, no 'might'\n"
        f"- Passive voice: write 'the function lacks', 'an attacker calls', not 'it was found that'\n"
        f"- Symmetric structure: not all sections same length, not all paragraphs with 3 sentences\n"
        f"- Explaining the obvious: don't explain what liquidation is, what a gauge is — the judge knows\n"
        f"- Generic openings: start with the punch, not context\n\n"
        f"DO write like a senior auditor:\n"
        f"- First sentence already says what's broken and what happens\n"
        f"- Active voice, specific: 'withdraw() at line 224 has no try/catch'\n"
        f"- Asymmetric: section lengths follow complexity, not aesthetics\n"
        f"- Confident: no hedging, the PoC demonstrated it\n"
        f"- Technically specific: cite contract, line, exact variable\n\n"
        f"## SHERLOCK TEMPLATE:\n"
        f"```markdown\n"
        f"## Summary\n"
        f"[One sentence: who can do what, with what result]\n\n"
        f"## Vulnerability Detail\n"
        f"[Deep technical explanation. Sherlock values depth.\n"
        f"Include code with comments. Cite Sherlock severity criteria.]\n\n"
        f"## Impact\n"
        f"[Cite which Sherlock severity rule applies:\n"
        f"- High: direct loss without time limit or user interaction\n"
        f"- Medium: with specific conditions / temporary DoS]\n\n"
        f"## Code Snippet\n"
        f"```solidity\n"
        f"// [file]:[line]\n"
        f"[vulnerable snippet]\n"
        f"```\n\n"
        f"## Tool used\n"
        f"Manual Review\n\n"
        f"## Recommendation\n"
        f"[Fix with code]\n"
        f"```\n\n"
        f"## AFTER WRITING — MANDATORY REVIEW PASS:\n"
        f"Re-read line by line and eliminate:\n"
        f"- Any sentence starting with 'It is', 'This could', 'It is worth', 'As a result'\n"
        f"- Any 'may', 'could', 'might', 'potentially', 'in some cases'\n"
        f"- Any section where all sentences are approximately equal length\n"
        f"- Any paragraph with 3 bullets when one sentence would suffice\n"
        f"- Any sentence explaining something the judge already knows\n"
        f"- Any passive voice usable as active\n"
        f"If a section sounds like corporate documentation → rewrite it.\n\n"
        f"Write the report to: {report_path}\n"
        f"Use English for all content (Sherlock platform). Be specific with line numbers."
    )


def build_cross_pair_prompt(comp_a: str, comp_b: str, iface_a: str,
                            iface_b: str, cross_calls: str, src_dir,
                            pair_file) -> str:
    """Build the cross-component pair analysis prompt."""
    return (
        f"You are CrossComponentHunter. Analyze the interaction between {comp_a} and {comp_b}.\n\n"
        f"## {comp_a} Interface\n```solidity\n{iface_a}\n```\n\n"
        f"## {comp_b} Interface\n```solidity\n{iface_b}\n```\n\n"
        f"## Known cross-component call sites\n{cross_calls}\n\n"
        f"## Your task\n"
        f"For the {comp_a} × {comp_b} interaction surface:\n"
        f"1. What breaks if {comp_b} behaves unexpectedly at each call site in {comp_a}?\n"
        f"2. What breaks if {comp_a} behaves unexpectedly at each call site in {comp_b}?\n"
        f"3. Custody invariants: assets in {comp_a} XOR {comp_b} — can both hold the same asset?\n"
        f"4. Accounting desync: does {comp_a} track a value that {comp_b} can change without notifying {comp_a}?\n"
        f"5. Sequence-dependent state: does calling {comp_a} then {comp_b} differ from {comp_b} then {comp_a}?\n"
        f"6. If you need to read full source, use the Read tool on the .sol files in {src_dir}/\n\n"
        f"Write findings (YAML list) to: {pair_file}\n\n"
        f"YAML format — top-level key must be 'findings', each entry:\n"
        f"  - id: CROSS-{comp_a[:3].upper()}-{comp_b[:3].upper()}-001\n"
        f"    title: <one line>\n"
        f"    severity: High/Medium/Low\n"
        f"    confidence: 70\n"
        f"    description: <root cause>\n"
        f"    attack_scenario: <step by step>\n"
        f"    components: [{comp_a}, {comp_b}]\n"
    )
