# Phase 4 — Deprecate `run_hunt.py` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete `audit-agents/run_hunt.py` (3962 LOC legacy coordinator) without regressing the modern pipeline. After this plan, `run_benchmark.py` + Agent Teams + pure helper modules are the only pipeline surface.

**Architecture:** Extract the 3 symbols `run_benchmark.py` still imports (`HUNTER_DOMAINS`, `load_rejection_context`, `load_few_shot_examples`) into a new pure-function module `audit-agents/hunter_context.py`. Rewire the 3 imports. Remove the 1 subprocess caller in `scope_intake.py`. Update 5 error messages in `pipeline_gate.py` and 6 docs/comments elsewhere. Delete `run_hunt.py`. Update the parity matrix.

**Tech Stack:** Python 3.11 stdlib + PyYAML. Tests: pytest against the existing combined suite (`audit-agents/tests/phase_modern/`, `phase_2a/`, `phase_2b/`, `phase_2c/`, `phase_2d/` — 122 tests total). No new tests; existing suite exercises these symbols end-to-end through `run_benchmark.py` with `_llm` monkeypatched.

---

## Files

| File | Role in this plan | Change |
|---|---|---|
| `audit-agents/hunter_context.py` | Pure module exporting `HUNTER_DOMAINS`, `load_rejection_context`, `load_few_shot_examples` | **Create** (Task 1) |
| `audit-agents/run_benchmark.py` | Benchmark entry point that consumes the 3 symbols | Rewire 3 imports (Task 1), rewrite 2 stale comments (Task 4) |
| `audit-agents/scope_intake.py` | Scope intake CLI | Delete 1 subprocess block + update docstring (Task 2) |
| `audit-agents/pipeline_gate.py` | Gate enforcement CLI | Rewrite 5 error messages (Task 3) |
| `audit-agents/detection_engine.py` | Prepass generator | Rewrite 1 comment (Task 4) |
| `setup.sh` | Setup health check | Remove `run_hunt.py` from syntax loop + update example (Task 4) |
| `hunt-dashboard/index.html` | Dashboard UI | Update 1 user-facing string (Task 4) |
| `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md` | Benchmark runbook | Update 2 command examples (Task 4) |
| `knowledge/state-machine-modeling.md` | Knowledge doc | Update 1 textual reference (Task 4) |
| `audit-agents/run_hunt.py` | 3962 LOC legacy coordinator | **Delete** (Task 5) |
| `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` | Fase 0 source-of-truth | Reclassify F012/F020/F021/F023 (Task 5) |

---

## Baseline: Run test suite before starting

- [ ] **Step 0.1: Capture baseline**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`. Every task below must leave this count at `122 passed`.

---

## Task 1: Extract `hunter_context` module + rewire `run_benchmark.py` imports

**Files:**
- Create: `audit-agents/hunter_context.py`
- Modify: `audit-agents/run_benchmark.py:1680`, `audit-agents/run_benchmark.py:1709`, `audit-agents/run_benchmark.py:3696`

- [ ] **Step 1.1: Create `audit-agents/hunter_context.py` with the full extracted body**

Write the following to `audit-agents/hunter_context.py`:

```python
"""hunter_context.py — Hunter-level context extracted from legacy run_hunt.py.

Contains the symbols that run_benchmark.py still imports:
- HUNTER_DOMAINS: hunter name -> (domain_key, description) dict.
- load_rejection_context: reads hunt_session/feedback/rejection_rules.yaml.
- load_few_shot_examples: reads audit-agents/few_shot_examples/<cat>.yaml.

Migrated from run_hunt.py during Phase 4 of the optimization roadmap
(2026-04-18). Behaviour is identical to the legacy versions.
"""
from __future__ import annotations

from pathlib import Path

import yaml

WEB3_DIR = Path.home() / "Documents/Web3"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"


HUNTER_DOMAINS = {
    "MathHunter":    ("math",    "Overflow, rounding, precision, exchange rate math, share price manipulation"),
    "AccessHunter":  ("access",  "Access control, missing modifiers, privilege escalation, role misconfig"),
    "FlowHunter":    ("flow",    "Reentrancy, CEI violations, token flow, callback abuse, fund routing"),
    "OracleHunter":  ("oracle",  "Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies"),
    "DomainHunter":  ("domain",  "Protocol-specific invariants, cross-component interactions, economic attacks"),
    "WildcardHunter":("wildcard","Novel bugs, unconventional vectors, assumption violations, composability risks"),
    "TrustBoundaryHunter":("trust","Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions"),
    "SignatureHunter":("signature","Signature replay, permit abuse, EIP-712 issues, nonce handling, ecrecover validation, approval/allowance patterns, Permit2, meta-transactions"),
    "DoSHunter":     ("dos",      "Denial of service, gas griefing, unbounded loops, blocked withdrawals, revert-based DoS, resource exhaustion, emergency function blocking"),
}


def load_rejection_context() -> str:
    """Load rejection rules as anti-patterns for hunters."""
    rules_path = HUNT_SESSION_DIR / "feedback" / "rejection_rules.yaml"
    if not rules_path.exists():
        return ""
    try:
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        if not rules:
            return ""
        lines = ["\n## Anti-Patterns (Rechazados en plataformas reales -- NO reportar estos)"]
        categories = rules.get("rejection_categories", {})
        for cat_name, cat_data in categories.items():
            if cat_name == "duplicate":
                continue
            rule_text = cat_data.get("rule", "")
            count = cat_data.get("count", 0)
            if rule_text:
                lines.append(f"- **{cat_name}** ({count}x rechazado): {rule_text}")
        for lesson in rules.get("lessons", []):
            lines.append(f"- {lesson}")
        return "\n".join(lines) if len(lines) > 1 else ""
    except Exception:
        return ""


def load_few_shot_examples(hunter_domain: str) -> str:
    """Load 2-3 relevant few-shot examples for this hunter's domain."""
    domain_categories = {
        "math": ["rounding", "accounting"], "access": ["access"],
        "flow": ["accounting", "logic"], "oracle": ["oracle"],
        "domain": ["logic", "accounting"], "dos": ["dos"],
        "logic": ["logic"], "adversarial": ["accounting", "oracle", "logic"],
        "trust": ["access", "logic"], "signature": ["access"],
        "wildcard": ["logic", "dos"],
    }
    cats = domain_categories.get(hunter_domain, ["logic"])
    examples_dir = AUDIT_AGENTS_DIR / "few_shot_examples"
    if not examples_dir.exists():
        return ""
    results = []
    for cat in cats:
        cat_file = examples_dir / f"{cat}.yaml"
        if not cat_file.exists():
            continue
        try:
            data = yaml.safe_load(cat_file.read_text())
            for ex in data.get("examples", [])[:2]:
                results.append(
                    f"### {ex.get('title', '?')} ({ex.get('source', '')})\n"
                    f"```solidity\n{ex.get('vulnerable_code', '').strip()}\n```\n"
                    f"{ex.get('explanation', '').strip()}\n"
                )
        except Exception:
            continue
    if not results:
        return ""
    return (
        "\n---\n## Ejemplos Reales de Bugs (Few-Shot — bugs confirmados en auditorías reales)\n"
        + "\n".join(results[:3])
    )
```

- [ ] **Step 1.2: Smoke-check the new module imports cleanly**

Run:
```bash
cd /home/kali/Documents/Web3/audit-agents
python3 -c "from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples; print(len(HUNTER_DOMAINS), type(load_rejection_context()), type(load_few_shot_examples('math')))"
```
Expected output: `9 <class 'str'> <class 'str'>`.

- [ ] **Step 1.3: Rewire import at `audit-agents/run_benchmark.py:1680`**

Replace:
```python
            from run_hunt import load_rejection_context as _load_rej
```
with:
```python
            from hunter_context import load_rejection_context as _load_rej
```

- [ ] **Step 1.4: Rewire import at `audit-agents/run_benchmark.py:1709`**

Replace:
```python
            from run_hunt import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
```
with:
```python
            from hunter_context import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
```

- [ ] **Step 1.5: Rewire import at `audit-agents/run_benchmark.py:3696`**

Replace:
```python
    from run_hunt import HUNTER_DOMAINS
```
with:
```python
    from hunter_context import HUNTER_DOMAINS
```

- [ ] **Step 1.6: Verify no `from run_hunt` imports remain in modern code**

Run:
```bash
cd /home/kali/Documents/Web3
rtk grep -rn "from run_hunt" audit-agents/
```
Expected output: no matches (empty).

- [ ] **Step 1.7: Run full test suite**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`.

- [ ] **Step 1.8: Commit**

Run:
```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/hunter_context.py audit-agents/run_benchmark.py
rtk git commit -m "$(cat <<'EOF'
feat(phase_4): extract hunter_context module from run_hunt.py

- New hunter_context.py with HUNTER_DOMAINS, load_rejection_context,
  load_few_shot_examples (verbatim extraction from run_hunt.py).
- Rewire 3 imports in run_benchmark.py (lines 1680, 1709, 3696).
- run_hunt.py still exists; subsequent commits remove callers and
  delete the legacy file.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Remove `run_hunt.py` subprocess from `scope_intake.py`

**Files:**
- Modify: `audit-agents/scope_intake.py:60` (docstring) and `audit-agents/scope_intake.py:405-412` (subprocess block)

- [ ] **Step 2.1: Remove the auto-dispatch block at `audit-agents/scope_intake.py:405-412`**

Replace the block:
```python
    # Auto-run run_hunt.py and pipeline_gate scope check for first component
    print(f"\n  Running run_hunt.py --component {first} ...")
    ret = subprocess.run(
        ["python3", str(WEB3_DIR / "audit-agents" / "run_hunt.py"), "--component", first],
        cwd=str(WEB3_DIR),
    )
    if ret.returncode != 0:
        print(f"  WARNING: run_hunt.py exited with code {ret.returncode}")

    print(f"\n  Running pipeline_gate.py --gate scope ...")
```
with (the pipeline_gate scope check header stays; only the `run_hunt.py` subprocess block is removed):
```python
    # Scope gate check (run_hunt.py auto-dispatch removed in Phase 4 —
    # users now invoke run_benchmark.py manually when they are ready to hunt)
    print(f"\n  Running pipeline_gate.py --gate scope ...")
```

- [ ] **Step 2.2: Update the stale docstring at `audit-agents/scope_intake.py:60`**

Replace:
```python
    Writes result to hunt_session/context/{protocol}/wiki_prior_knowledge.md so
    run_hunt.py and hunters can pick it up. Failure-tolerant: missing skill,
```
with:
```python
    Writes result to hunt_session/context/{protocol}/wiki_prior_knowledge.md so
    run_benchmark.py and hunters can pick it up. Failure-tolerant: missing skill,
```

- [ ] **Step 2.3: Smoke-check `scope_intake.py --help`**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/scope_intake.py --help
```
Expected: exits 0, prints argparse usage, no reference to `run_hunt` in the help text.

- [ ] **Step 2.4: Run full test suite**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`.

- [ ] **Step 2.5: Commit**

Run:
```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/scope_intake.py
rtk git commit -m "$(cat <<'EOF'
refactor(phase_4): remove run_hunt subprocess from scope_intake

- Delete auto-dispatch of run_hunt.py --component <first> at end of
  scope_intake.main (lines 405-412 pre-edit).
- Keep the pipeline_gate --gate scope check; the scope gate remains
  a valid post-intake signal even without the auto-dispatch.
- Fix stale docstring at line 60 mentioning run_hunt.py.

Users now invoke run_benchmark.py manually when they are ready to
start hunting (no need to couple intake to a full LLM-heavy pipeline).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Update 5 error messages in `pipeline_gate.py`

**Files:**
- Modify: `audit-agents/pipeline_gate.py:201`, `:203`, `:210`, `:221`, `:223`

- [ ] **Step 3.1: Update line 201 — map-components message**

Replace:
```python
        failed.append("NO_MAP: component_map empty. Run: python3 audit-agents/run_hunt.py --map-components")
```
with:
```python
        failed.append("NO_MAP: component_map empty. Run: python3 audit-agents/run_benchmark.py --auto-components --protocol <name> --repo <path>")
```

- [ ] **Step 3.2: Update line 203 — context comment**

Replace:
```python
    # 4. Context file exists (run_hunt.py --component was executed)
```
with:
```python
    # 4. Context file exists (run_benchmark.py --components was executed)
```

- [ ] **Step 3.3: Update line 210 — missing context message**

Replace:
```python
        failed.append(f"NO_CONTEXT: {ctx_file.name} missing. Run: python3 audit-agents/run_hunt.py --component {component}")
```
with:
```python
        failed.append(f"NO_CONTEXT: {ctx_file.name} missing. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")
```

- [ ] **Step 3.4: Update line 221 — partial prompts message**

Replace:
```python
        failed.append(f"PARTIAL: Only {prompts_found}/{len(HUNTER_NAMES)} hunter prompts. Run: python3 audit-agents/run_hunt.py --component {component}")
```
with:
```python
        failed.append(f"PARTIAL: Only {prompts_found}/{len(HUNTER_NAMES)} hunter prompts. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")
```

- [ ] **Step 3.5: Update line 223 — no prompts message**

Replace:
```python
        failed.append(f"NO_PROMPTS: No hunter prompts found. Run: python3 audit-agents/run_hunt.py --component {component}")
```
with:
```python
        failed.append(f"NO_PROMPTS: No hunter prompts found. Run: python3 audit-agents/run_benchmark.py --components {component} --protocol <name> --repo <path>")
```

- [ ] **Step 3.6: Run full test suite**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`.

- [ ] **Step 3.7: Commit**

Run:
```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/pipeline_gate.py
rtk git commit -m "$(cat <<'EOF'
docs(phase_4): point pipeline_gate error messages to run_benchmark

Rewrite 5 error messages (lines 201, 203, 210, 221, 223) so failed
gates suggest the modern run_benchmark.py invocation instead of
the legacy run_hunt.py CLI.

--map-components becomes --auto-components (Fase 2C). --component
becomes --components (Fase 2A).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Update docs + stale comments across 6 files

**Files:**
- Modify: `setup.sh:168`, `setup.sh:191`, `hunt-dashboard/index.html:372`, `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md:20`, `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md:91`, `knowledge/state-machine-modeling.md:557`, `audit-agents/detection_engine.py:168`, `audit-agents/run_benchmark.py:1438-1441`, `audit-agents/run_benchmark.py:1849-1853`

- [ ] **Step 4.1: `setup.sh:168` — remove `run_hunt.py` from syntax loop**

Replace:
```bash
for script in run_benchmark.py run_hunt.py detection_engine.py pipeline_gate.py benchmark_score.py; do
```
with:
```bash
for script in run_benchmark.py detection_engine.py pipeline_gate.py benchmark_score.py; do
```

- [ ] **Step 4.2: `setup.sh:191` — rewrite example command**

Replace:
```bash
    echo "    # Run a hunt on a new protocol:"
    echo "    python3 audit-agents/run_hunt.py --component <Name>"
```
with:
```bash
    echo "    # Run a hunt on a new protocol:"
    echo "    python3 audit-agents/run_benchmark.py --components <Name> --protocol <name> --repo <path>"
```

- [ ] **Step 4.3: `hunt-dashboard/index.html:372` — update UI string**

Replace:
```html
                <div class="no-ficha">Sin ficha — ejecuta run_hunt.py</div>
```
with:
```html
                <div class="no-ficha">Sin ficha — ejecuta run_benchmark.py</div>
```

- [ ] **Step 4.4: `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md:20` — rewrite scope command**

Replace:
```markdown
### 0. Scope
```bash
cd /home/kali/Documents/Web3/benchmarks/yieldoor/repo/yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_hunt.py -c <Component> --init-ficha <Component>
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate scope --protocol yieldoor
```
```
with:
```markdown
### 0. Scope
```bash
cd /home/kali/Documents/Web3/benchmarks/yieldoor/repo/yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_benchmark.py --components <Component> --protocol yieldoor --repo .
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --gate scope --protocol yieldoor
```
```

- [ ] **Step 4.5: `benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md:91` — rewrite complete command**

Replace:
```markdown
### 11. Completar componente
```bash
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --status --protocol yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_hunt.py --complete <Component>
```
```
with:
```markdown
### 11. Completar componente
```bash
python3 /home/kali/Documents/Web3/audit-agents/pipeline_gate.py -c <Component> --status --protocol yieldoor
python3 /home/kali/Documents/Web3/audit-agents/run_benchmark.py --complete <Component>
```
```

- [ ] **Step 4.6: `knowledge/state-machine-modeling.md:557` — update textual reference**

Replace:
```markdown
- Contexto del protocolo específico (nuestro run_hunt.py)
```
with:
```markdown
- Contexto del protocolo específico (nuestro run_benchmark.py)
```

- [ ] **Step 4.7: `audit-agents/detection_engine.py:168` — update comment**

Replace:
```python
def generate_prepass_yaml(findings: list, output_path: Path):
    """Generate YAML consumable by run_hunt.py hunter prompts."""
```
with:
```python
def generate_prepass_yaml(findings: list, output_path: Path):
    """Generate YAML consumable by hunter prompts (run_benchmark.py flow)."""
```

- [ ] **Step 4.8: `audit-agents/run_benchmark.py:1438-1441` — trim stale multi-line comment**

Replace the block (lines 1438-1441 pre-edit):
```python
    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    # run_hunt.py --init-ficha uses run_hunt.HUNT_SESSION_DIR (hardcoded to real hunt_session)
    # and cannot easily accept --session-dir without a larger refactor.
    # Benchmark pipelines never read the ficha back (scope gate is not checked here),
    # so skipping init-ficha is safe and avoids contaminating the real hunt_session/fichas/.
```
with:
```python
    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    # Benchmark pipelines never read the ficha back (scope gate is not checked here),
    # so skipping is safe and avoids contaminating the real hunt_session/fichas/.
```

- [ ] **Step 4.9: `audit-agents/run_benchmark.py:1848-1853` — rewrite stale deepdive comment**

Replace the block (lines 1848-1853 pre-edit):
```python
        # Build deepdive prompt directly from bench_session hyp_dir.
        # Do NOT import generate_deepdive_prompt from run_hunt — that function uses
        # run_hunt.HUNT_SESSION_DIR (real hunt_session, not bench_session) to read
        # hypotheses, which is wrong in benchmark mode and would be a thread-safety
        # issue in parallel component execution (two threads patching the same module global).
        deepdive_prompt = build_deepdive_prompt(
```
with:
```python
        # Build deepdive prompt inline from bench_session hyp_dir.
        # Keep this local — a helper reading from a module-global hunt dir would
        # race across parallel components (two threads would patch the same global).
        deepdive_prompt = build_deepdive_prompt(
```

- [ ] **Step 4.10: Run full test suite**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`.

- [ ] **Step 4.11: Commit**

Run:
```bash
cd /home/kali/Documents/Web3
rtk git add setup.sh hunt-dashboard/index.html benchmarks/yieldoor/BENCHMARK_V2_RUNBOOK.md knowledge/state-machine-modeling.md audit-agents/detection_engine.py audit-agents/run_benchmark.py
rtk git commit -m "$(cat <<'EOF'
docs(phase_4): update setup.sh + dashboard + runbook + knowledge docs

- setup.sh: drop run_hunt.py from syntax check loop + rewrite example
  to the modern run_benchmark.py invocation.
- hunt-dashboard/index.html:372: user-facing UI string.
- BENCHMARK_V2_RUNBOOK.md: 2 command examples updated (scope +
  complete) to Fase 2A + 2D syntax.
- knowledge/state-machine-modeling.md:557: textual reference.
- detection_engine.py:168: docstring of generate_prepass_yaml.
- run_benchmark.py: trim 2 stale multi-line comments that referred
  to run_hunt.HUNT_SESSION_DIR and the deprecated --init-ficha flow.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Delete `run_hunt.py` + update parity matrix

**Files:**
- Delete: `audit-agents/run_hunt.py`
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

- [ ] **Step 5.1: Verify no remaining `run_hunt` references in Python code (except the historical comment)**

Run:
```bash
cd /home/kali/Documents/Web3
rtk grep -rn "run_hunt" audit-agents/ --include='*.py'
```
Expected output: exactly one line — `audit-agents/context_enrichment.py:3:Migrated from legacy \`run_hunt.py\` during Phase 2A of the optimization` (historical comment, intentionally preserved). If any additional match appears, re-check Tasks 1-4 before deleting.

- [ ] **Step 5.2: Delete `audit-agents/run_hunt.py`**

Run:
```bash
cd /home/kali/Documents/Web3
rm audit-agents/run_hunt.py
```

- [ ] **Step 5.3: Update F020 in parity matrix — `deprecate` → `migrated`**

In `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`, find the F020 entry (search for `feature_id: F020`) and change its `migration_decision:` line from:
```yaml
    migration_decision: deprecate
```
to:
```yaml
    migration_decision: migrated
```
Also append a `phase_4_note:` line right under it:
```yaml
    phase_4_note: "Extracted verbatim to audit-agents/hunter_context.py during Phase 4 (2026-04-18)."
```

- [ ] **Step 5.4: Update F021 in parity matrix — `deprecate` → `migrated`**

In the same file, find the F021 entry and apply the same two-line change (change `migration_decision:` to `migrated` and append the same `phase_4_note:`).

- [ ] **Step 5.5: Update F023 in parity matrix — `deprecate` → `migrated`**

In the same file, find the F023 entry. Change `migration_decision:` to `migrated` and append:
```yaml
    phase_4_note: "HUNTER_DOMAINS constant extracted to audit-agents/hunter_context.py during Phase 4 (2026-04-18); the broader code-feature-based selection logic was not in use by run_benchmark.py and is gone with run_hunt.py."
```

- [ ] **Step 5.6: Update F012 in parity matrix — `keep_standalone` → `deprecated`**

In the same file, find the F012 entry. Change its `migration_decision:` from:
```yaml
    migration_decision: keep_standalone
```
to:
```yaml
    migration_decision: deprecated
```
Append:
```yaml
    phase_4_note: "Debug utility removed in Phase 4 (2026-04-18); hunter prompts now live as plain files in audit-agents/prompts/hunters/*.md and are readable directly without a --print-prompts flag."
```

- [ ] **Step 5.7: Update the `by_decision:` summary block in the parity matrix**

In `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`, locate the summary section (starts around line 657 with `by_decision:`). Update the counts: F012 moves from `keep_standalone` to `deprecated`; F020, F021, F023 move from `deprecate` (pending) to `migrated`. If the summary tracks counts per decision, recompute them: `migrated` gains 3, `deprecate` loses 3, `keep_standalone` loses 1, `deprecated` gains 1. Keep the structural shape of the block unchanged — only numeric fields and the feature_id lists under each decision move.

- [ ] **Step 5.8: Run full test suite**

Run:
```bash
cd /home/kali/Documents/Web3
pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d -q
```
Expected: `122 passed`.

- [ ] **Step 5.9: Smoke-check `run_benchmark.py --help` and `scope_intake.py --help`**

Run:
```bash
cd /home/kali/Documents/Web3
python3 audit-agents/run_benchmark.py --help 2>&1 | head -40
python3 audit-agents/scope_intake.py --help 2>&1 | head -20
```
Expected: both exit 0 and print argparse usage. No `ImportError`, no `ModuleNotFoundError`, no `run_hunt` in the output.

- [ ] **Step 5.10: Final grep sanity check — only the historical comment mentions `run_hunt`**

Run:
```bash
cd /home/kali/Documents/Web3
rtk grep -rn "run_hunt" audit-agents/ --include='*.py'
```
Expected: exactly 1 line, `audit-agents/context_enrichment.py:3:...Migrated from legacy \`run_hunt.py\`...`.

- [ ] **Step 5.11: Commit**

Run:
```bash
cd /home/kali/Documents/Web3
rtk git add -A audit-agents/ docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "$(cat <<'EOF'
feat(phase_4): delete run_hunt.py + update parity matrix

- rm audit-agents/run_hunt.py (3962 LOC legacy coordinator).
- Parity matrix reclassification:
  * F012 --print-prompts: keep_standalone -> deprecated (superseded
    by direct file access to prompts/hunters/*.md).
  * F020 rejection rules: deprecate -> migrated (hunter_context.py).
  * F021 few-shot examples: deprecate -> migrated (hunter_context.py).
  * F023 hunter selection by code features: deprecate -> migrated
    (HUNTER_DOMAINS dict extracted; broader code-feature selection
    was never imported by run_benchmark.py).
- by_decision summary recomputed.

Modern pipeline (run_benchmark.py + Agent Teams + component_*
modules + hunter_context + context_enrichment + solodit_to_wiki)
is now the only entry point. One historical comment in
context_enrichment.py:3 remains as provenance.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Post-plan: Update memory roadmap

Not a code task, but required for session hygiene — matches the pattern used at the close of Fases 2A-2D and 3.

- [ ] **Step 6.1: Update `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`**

Three edits:
1. Frontmatter `description:` line: `"Fase 3 COMPLETA (2026-04-18). Siguiente Fase 4."` → `"Fase 4 COMPLETA (2026-04-18). Siguiente Fase 5."`
2. Phases table: row `| 4 | Deprecate \`run_hunt.py\` | 🔜 NEXT | ... |` → `| 4 | Deprecate \`run_hunt.py\` | ✅ COMPLETA (2026-04-18) | hunter_context module; run_hunt.py deleted (3962 LOC); 5 commits |`. Row `| 5 | Shared infra consolidation | PENDING | ... |` → `| 5 | Shared infra consolidation | 🔜 NEXT | ... |`.
3. Append a `## Fase 4 — resumen al cerrar` section following the shape of the existing Fase 2A/2B/2C/2D/3 summaries. Include: module extracted (`hunter_context.py`), files modified (count + short list), `run_hunt.py` deletion (3962 LOC), parity matrix reclassifications (F012/F020/F021/F023), test baseline held (122/122 through all 5 commits), spec path, commit count (5).

---

## Self-review notes (for implementer)

- The 5-commit sequence is deliberate: `run_hunt.py` is still importable between commits 1-4 (nothing imports it after Task 1, but the file lives until Task 5). This keeps every commit green under the 122-test suite and makes bisect useful.
- Every task ends with the same `pytest` command against the combined suite. If a task fails tests, stop and investigate before committing — do not advance.
- No new test files are created. The 122-test suite (Fases 1-2D) already exercises the paths that `hunter_context.py` sits on; a unit test layer would duplicate coverage without adding signal.
- The historical comment at `context_enrichment.py:3` is preserved intentionally. It describes provenance, not a live dependency, and helps future readers understand why the module exists.
- `--print-prompts` (F012) is deleted rather than extracted because `audit-agents/prompts/hunters/*.md` are now plain files — `cat` or any editor is a better debug tool than a bespoke flag.
