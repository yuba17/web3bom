# Phase 13 — Split runner.py Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reducir `audit-agents/benchmark/component_pipeline/runner.py` (1,596 LOC) a un orchestrator de ~80 LOC + 10 phase modules + `PipelineContext` dataclass, sin cambios de comportamiento.

**Architecture:** `PipelineContext` dataclass agrupa state mutable. 10 submódulos (uno por fase del pipeline) reciben `ctx`, mutan campos compartidos, retornan resultados locales. `runner.py` queda como orchestrator que llama fases en orden. Patrón cut-and-paste verbatim de Fase 11/12 — **no reescribir lógica**.

**Tech Stack:** Python 3.11+ (dataclasses, typing), pytest. Imports lazy `import run_benchmark as _rb` preservados dentro de cada fase.

**Worktree:** `.worktrees/phase-13-runner-split` (branch `feature/phase-13-runner-split`).

**Spec:** `docs/superpowers/specs/2026-04-19-phase-13-runner-split-design.md`.

---

## File Structure

```
audit-agents/benchmark/component_pipeline/
├─ __init__.py             (sin cambios)
├─ reporting.py            (sin cambios)
├─ pipeline_context.py     [NUEVO ~60 LOC]
├─ context.py              [NUEVO ~240 LOC]
├─ hunters.py              [NUEVO ~210 LOC]
├─ deepdive.py             [NUEVO ~80 LOC]
├─ merge.py                [NUEVO ~270 LOC]
├─ enhance.py              [NUEVO ~65 LOC]
├─ fuzz.py                 [NUEVO ~230 LOC]
├─ extract.py              [NUEVO ~50 LOC]
├─ verify.py               [NUEVO ~70 LOC]
├─ poc.py                  [NUEVO ~180 LOC]
├─ finding.py              [NUEVO ~80 LOC]
└─ runner.py               (reducido a ~80 LOC)

audit-agents/tests/phase_13/
└─ test_pipeline_split.py  [NUEVO 4 contract tests]
```

---

## Migration Pattern (común a todas las fases T2-T11)

Cada fase migrada sigue 5 pasos repetibles:

1. **Identify block** en `runner.py` por marcador `# ─── Step N: <Name> ───`
2. **Create module** `component_pipeline/<phase>.py` con imports lazy preservados
3. **Define function** `def <phase_name>(ctx: PipelineContext) -> <ReturnType>:` que recibe contexto, hace cut-and-paste del bloque, sustituye locals por accesos a `ctx`
4. **Replace block** en `runner.py` con `<result> = <phase_name>(ctx)` o `<phase_name>(ctx)`
5. **Smoke import** `python3 -c "from benchmark.component_pipeline.runner import run_component_pipeline"` debe pasar

**Reglas de cut-and-paste:**
- Imports lazy (`import run_benchmark as _rb`, `import subprocess`, etc.) van dentro de la función de fase, igual que estaban en runner.py
- Helpers internos (ej. `_rescue_deepdive_yaml`) se mueven a la fase que los usa
- Logging strings (`logger.info("  Step N: ...")`) se preservan **idénticos** para no romper grep en logs
- Variables que la fase escribe en ctx → mutate `ctx.field = value`
- Variables que la fase lee de ctx → `local = ctx.field` al inicio si se usan ≥3 veces
- `summary["gates"][...] = ...` se vuelve `ctx.summary["gates"][...] = ...`
- `return summary` (early-exits): se vuelve `return "EARLY_EXIT_<reason>"` (sentinel string), orchestrator interpreta y hace return real

---

## Task 1: PipelineContext dataclass + test scaffold

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/pipeline_context.py`
- Create: `audit-agents/tests/phase_13/__init__.py` (empty)
- Create: `audit-agents/tests/phase_13/test_pipeline_split.py`

- [ ] **Step 1: Write the dataclass file**

Create `pipeline_context.py`:

```python
"""PipelineContext — shared mutable state for component_pipeline phases.

Captures all locals previously held inside run_component_pipeline.
Each phase function reads/writes its fields directly.
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple


@dataclass
class PipelineContext:
    # Inputs
    component: str
    repo: str
    protocol: str
    args: argparse.Namespace
    logger: logging.Logger

    # Derived paths (set early in orchestrator)
    src_dir: Path
    hyp_dir: Path
    clog: Path  # component log dir
    src_file: Path

    # Timing
    comp_start: float = field(default_factory=time.time)

    # Accumulators (mutated by phases)
    summary: Dict[str, Any] = field(default_factory=lambda: {"gates": {}, "findings": []})

    # Source / library / interfaces (loaded by context phase)
    source_code: str = ""
    library_code: str = ""
    interfaces_code: str = ""

    # Test artifacts
    existing_tests_summary: str = ""
    _test_files_cache: List[Tuple[str, str]] = field(default_factory=list)

    # Knowledge briefings
    knowledge_context: str = ""

    # Setup artifacts
    setup_sol_text: str = ""
    setup_var_names: str = ""

    # Prepass
    prepass_signals_text: str = ""

    # Protocol model (kept for compat)
    protocol_model: str = ""

    # Cross-component context
    accumulated_context: str = ""

    # Skip flags
    _skip_to_merge: bool = False
```

- [ ] **Step 2: Write the test file**

Create `audit-agents/tests/phase_13/__init__.py` (empty file).

Create `audit-agents/tests/phase_13/test_pipeline_split.py`:

```python
"""Phase 13 contract tests — pipeline split structural invariants."""

import importlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PIPELINE_DIR = REPO / "audit-agents" / "benchmark" / "component_pipeline"

PHASE_MODULES = [
    "pipeline_context",
    # Filled in by later tasks:
    # "context", "hunters", "deepdive", "merge", "enhance",
    # "fuzz", "extract", "verify", "poc", "finding",
]

LOC_BUDGET = {
    "runner.py": 120,
    "pipeline_context.py": 100,
    "context.py": 280,
    "hunters.py": 280,
    "deepdive.py": 120,
    "merge.py": 280,
    "enhance.py": 100,
    "fuzz.py": 280,
    "extract.py": 100,
    "verify.py": 120,
    "poc.py": 230,
    "finding.py": 120,
}


def test_pipeline_context_importable():
    mod = importlib.import_module("benchmark.component_pipeline.pipeline_context")
    assert hasattr(mod, "PipelineContext")


@pytest.mark.skip(reason="Activated in Task 12 once runner.py is reduced")
def test_runner_loc_budget():
    runner = PIPELINE_DIR / "runner.py"
    loc = sum(1 for _ in runner.read_text().splitlines())
    assert loc <= LOC_BUDGET["runner.py"], f"runner.py is {loc} LOC, budget {LOC_BUDGET['runner.py']}"


@pytest.mark.skip(reason="Activated in Task 12 once all phase modules exist")
def test_all_phase_modules_importable():
    for name in PHASE_MODULES:
        importlib.import_module(f"benchmark.component_pipeline.{name}")


@pytest.mark.skip(reason="Activated in Task 12 once all phase modules exist")
def test_phase_loc_budgets():
    for fname, budget in LOC_BUDGET.items():
        path = PIPELINE_DIR / fname
        if not path.exists():
            continue
        loc = sum(1 for _ in path.read_text().splitlines())
        assert loc <= budget, f"{fname} is {loc} LOC, budget {budget}"


@pytest.mark.skip(reason="Activated in Task 12")
def test_run_component_pipeline_entry_point():
    mod = importlib.import_module("benchmark.component_pipeline.runner")
    assert callable(getattr(mod, "run_component_pipeline", None))
```

- [ ] **Step 3: Verify import works**

Run: `cd audit-agents && python3 -c "from benchmark.component_pipeline.pipeline_context import PipelineContext; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Run the active test**

Run: `cd audit-agents && python3 -m pytest tests/phase_13/test_pipeline_split.py -v`
Expected: 1 passed (`test_pipeline_context_importable`), 4 skipped.

- [ ] **Step 5: Commit**

```bash
git add audit-agents/benchmark/component_pipeline/pipeline_context.py audit-agents/tests/phase_13/
git commit -m "feat(p13): PipelineContext dataclass + test scaffold"
```

---

## Task 2: Migrate `extract.py` (L1251-1300)

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/extract.py`
- Modify: `audit-agents/benchmark/component_pipeline/runner.py` (remove L1251-1300 block, replace with call)

**Block to migrate:** Sections `# ─── Extract Findings ───` and `# ─── Deduplicate findings by root cause ───`.

- [ ] **Step 1: Read the current block**

Use `Read` tool on `runner.py:1251-1300` to capture the exact code.

- [ ] **Step 2: Create extract.py**

Skeleton (real cut-and-paste fills body):

```python
"""extract.py — parse fuzz failures + dedup findings by root cause."""

from __future__ import annotations

from typing import List

from benchmark.component_pipeline.pipeline_context import PipelineContext


def extract_findings(ctx: PipelineContext) -> List[dict]:
    """Parse fuzz output → findings list. Mutates ctx.summary['findings'].

    Returns the findings list for downstream consumption.
    """
    import run_benchmark as _rb  # noqa: F401  — preserved for parity
    from finding_pipeline import dedup_findings as _dedup_findings_pure

    # ─── Extract Findings ──────────────────────────────────────────
    # <CUT-AND-PASTE EXACT BODY FROM runner.py:1251-1289 HERE>
    # — substitute `summary` → `ctx.summary`
    # — substitute `component` → `ctx.component`
    # — substitute `protocol` → `ctx.protocol`
    # — substitute `clog` → `ctx.clog`
    # — substitute `logger` → `ctx.logger`

    # ─── Deduplicate findings by root cause ───────────────────────
    # <CUT-AND-PASTE EXACT BODY FROM runner.py:1290-1300 HERE>

    return ctx.summary["findings"]
```

- [ ] **Step 3: Update runner.py**

Replace original block (L1251-1300) with:

```python
    # ─── Step 9: Extract Findings + dedup ──────────────────────────
    from benchmark.component_pipeline.extract import extract_findings
    extract_findings(ctx)
```

- [ ] **Step 4: Verify imports**

```bash
cd audit-agents && python3 -c "from benchmark.component_pipeline.runner import run_component_pipeline; print('OK')"
```
Expected: `OK`

- [ ] **Step 5: Run tests**

```bash
cd audit-agents && python3 -m pytest tests/phase_13/ -v
```
Expected: 1 passed, 4 skipped (no new failures).

- [ ] **Step 6: Commit**

```bash
git add audit-agents/benchmark/component_pipeline/extract.py audit-agents/benchmark/component_pipeline/runner.py
git commit -m "refactor(p13): extract findings phase → extract.py"
```

---

## Task 3: Migrate `verify.py` (L1301-1368)

Same pattern as Task 2. Block: `# ─── Verification — lightweight code-read before Foundry PoC ───`.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/verify.py`
- Modify: `audit-agents/benchmark/component_pipeline/runner.py`

- [ ] **Step 1: Read current block** (`runner.py:1301-1368`)

- [ ] **Step 2: Create verify.py**

```python
"""verify.py — lightweight code-read verification before Phase 3 PoC."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def verify_findings_lightweight(ctx: PipelineContext) -> None:
    """Filters ctx.summary['findings'] in place using code-read confidence."""
    import run_benchmark as _rb
    from finding_pipeline import collect_verify_candidates as _collect_verify_candidates_pure

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:1301-1368 HERE>
    # — substitute summary→ctx.summary, component→ctx.component, etc.
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 10: Verify findings (lightweight) ────────────────────
    from benchmark.component_pipeline.verify import verify_findings_lightweight
    verify_findings_lightweight(ctx)
```

- [ ] **Step 4: Smoke + tests** (same as Task 2 Steps 4-5)

- [ ] **Step 5: Commit**

```bash
git add audit-agents/benchmark/component_pipeline/verify.py audit-agents/benchmark/component_pipeline/runner.py
git commit -m "refactor(p13): verify phase → verify.py"
```

---

## Task 4: Migrate `finding.py` (L1547-1586)

Block: `# ─── Finding Pipeline (parallel — 4 findings at a time) ───`.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/finding.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:1547-1586`)

- [ ] **Step 2: Create finding.py**

```python
"""finding.py — parallel finding pipeline dispatch (4 concurrent)."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def dispatch_finding_pipeline(ctx: PipelineContext) -> None:
    """Dispatches finding pipeline for each verified finding (parallel)."""
    import run_benchmark as _rb
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:1547-1586 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 12: Finding pipeline dispatch ────────────────────────
    from benchmark.component_pipeline.finding import dispatch_finding_pipeline
    dispatch_finding_pipeline(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): finding pipeline phase → finding.py"
```

---

## Task 5: Migrate `enhance.py` (L904-968)

Block: `# ─── Step 7.5: Enhance TargetFunctions with attack sequences (opt-in) ───`.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/enhance.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:904-968`)

- [ ] **Step 2: Create enhance.py**

```python
"""enhance.py — Step 7.5 opt-in TargetFunctions enhancer (--enhance-targets)."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def enhance_target_functions(ctx: PipelineContext) -> None:
    """LLM-enhances test/chimera/TargetFunctions.sol with attack sequences.

    Gated by --enhance-targets flag. Skipped silently otherwise.
    """
    import run_benchmark as _rb

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:904-968 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 7.5: Enhance TargetFunctions (opt-in) ────────────────
    from benchmark.component_pipeline.enhance import enhance_target_functions
    enhance_target_functions(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): enhance phase → enhance.py"
```

---

## Task 6: Migrate `deepdive.py` (L550-624)

Block: `# ─── DeepDive Hunter ───` + `_rescue_deepdive_yaml` helper currently shared.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/deepdive.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:550-624`) AND helper (`_rescue_deepdive_yaml` from L598-612 added in QW7)

- [ ] **Step 2: Create deepdive.py**

```python
"""deepdive.py — DeepDive hunter (sequential, post-12-hunters)."""

from __future__ import annotations

from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext


def _rescue_deepdive_yaml(ctx: PipelineContext, hyp_dir: Path, context_label: str) -> bool:
    """Locate DeepDive YAML written to wrong dir and copy to hyp_dir."""
    import subprocess
    import shutil as _sh_rescue

    target = hyp_dir / f"hyp_{ctx.component}_DeepDiveHunter.yaml"
    if target.exists():
        return True
    _find_out = subprocess.run(
        ["find", str(ctx.repo), "-name", f"hyp_{ctx.component}_DeepDiveHunter.yaml", "-type", "f"],
        capture_output=True, text=True
    )
    for _found in _find_out.stdout.strip().splitlines():
        if _found and Path(_found) != target:
            _sh_rescue.copy2(_found, target)
            ctx.logger.info(f"  {context_label}: rescued {Path(_found).name} → {hyp_dir.name}/")
            return True
    return False


def run_deepdive(ctx: PipelineContext) -> None:
    """Runs DeepDiveHunter sequentially after 12 parallel hunters."""
    import run_benchmark as _rb

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:550-624 HERE>
    # — _rescue_deepdive_yaml(...) calls swap to use ctx variant
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 3: DeepDive hunter ───────────────────────────────────
    from benchmark.component_pipeline.deepdive import run_deepdive
    run_deepdive(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): deepdive phase → deepdive.py"
```

---

## Task 7: Migrate `poc.py` (L1369-1546)

Block: `# ─── Fork PoC per confirmed finding (Phase 3) ───`. Largest single block (~180 LOC).

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/poc.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:1369-1546`)

- [ ] **Step 2: Create poc.py**

```python
"""poc.py — Phase 3 Fork PoC generator per confirmed finding."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def generate_fork_pocs(ctx: PipelineContext) -> None:
    """Generates Foundry fork PoC per finding via parallel Claude dispatches.

    Mutates ctx.summary['findings'] entries with poc_path, poc_status.
    """
    import run_benchmark as _rb
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from finding_pipeline import dedup_for_poc as _dedup_for_poc_pure

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:1369-1546 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 11: Fork PoC per finding (Phase 3) ───────────────────
    from benchmark.component_pipeline.poc import generate_fork_pocs
    generate_fork_pocs(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): PoC phase → poc.py"
```

---

## Task 8: Migrate `fuzz.py` (L969-1249)

Two contiguous blocks: `# ─── Phase 1 — Foundry fuzz runs ───` (L969-1182) + `# ─── Phase 2 — Medusa ───` and tolerance tuning (L1183-1249). ~280 LOC total — at LOC budget.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/fuzz.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:969-1249`)

- [ ] **Step 2: Create fuzz.py with TWO functions**

```python
"""fuzz.py — Phase 1 (Foundry) + Phase 2 (Medusa) + tolerance tuning."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.component_pipeline.reporting import parse_fuzz_failures


def run_phase1_foundry(ctx: PipelineContext) -> None:
    """Phase 1 Foundry fuzz with --fuzz-runs 5000 (parallel batches)."""
    import run_benchmark as _rb
    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # <CUT-AND-PASTE BODY FROM runner.py:969-1182 HERE>


def run_phase2_medusa(ctx: PipelineContext) -> None:
    """Phase 2 Medusa fuzz (15 min, secuencias multi-step). Skipped in --fast mode."""
    import run_benchmark as _rb

    # <CUT-AND-PASTE BODY FROM runner.py:1183-1249 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 8: Fuzz (Phase 1 + Phase 2) ──────────────────────────
    from benchmark.component_pipeline.fuzz import run_phase1_foundry, run_phase2_medusa
    run_phase1_foundry(ctx)
    run_phase2_medusa(ctx)
```

- [ ] **Step 4: Smoke**

- [ ] **Step 5: Verify LOC budget for fuzz.py**

```bash
wc -l audit-agents/benchmark/component_pipeline/fuzz.py
```
Expected: ≤ 280. If over, leave note in PR — Task 12 may need budget adjustment.

- [ ] **Step 6: Commit**

```bash
git commit -m "refactor(p13): fuzz phase (Phase 1+2) → fuzz.py"
```

---

## Task 9: Migrate `merge.py` (L633-903)

Block: `# ─── Compile + Fuzz ───` ... `# ─── Compile merged invariants (setup-aware fix) ───`. ~270 LOC. Contains: ensure setup, merge_invariants call, FoundryTester wrappers, import injection, compile loop.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/merge.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:633-903`)

- [ ] **Step 2: Create merge.py**

```python
"""merge.py — merge invariants + compile Setup + import injection + compile merged."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def run_merge(ctx: PipelineContext) -> None:
    """Steps 5-7: ensure setup + merge invariants + compile.

    Sets ctx.setup_sol_text after setup gen if not already populated.
    """
    import run_benchmark as _rb
    import subprocess
    import os
    import re as _re
    from pathlib import Path

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:633-903 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Steps 5-7: Merge invariants + compile ─────────────────────
    from benchmark.component_pipeline.merge import run_merge
    run_merge(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): merge phase → merge.py"
```

---

## Task 10: Migrate `hunters.py` (L341-549)

Block: `# ─── Step 2: 12 Hunters (coordinator + context file on disk) ───`. ~210 LOC.

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/hunters.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:341-549`)

- [ ] **Step 2: Create hunters.py**

```python
"""hunters.py — 12 parallel hunters dispatch + brief writer."""

from __future__ import annotations

from benchmark.component_pipeline.pipeline_context import PipelineContext


def run_hunters(ctx: PipelineContext) -> None:
    """Dispatches 12 hunters in parallel via Claude coordinator.

    Reads ctx.{setup_sol_text, prepass_signals_text, knowledge_context, ...}.
    Writes hunter brief file under hunt_session/context/<protocol>-bench/.
    """
    import run_benchmark as _rb
    from benchmark.prompt_builders import build_hunter_brief, build_hunter_dispatch_prompt
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # <CUT-AND-PASTE EXACT BODY FROM runner.py:341-549 HERE>
```

- [ ] **Step 3: Replace block in runner.py**

```python
    # ─── Step 2: 12 hunters ────────────────────────────────────────
    from benchmark.component_pipeline.hunters import run_hunters
    run_hunters(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): hunters phase → hunters.py"
```

---

## Task 11: Migrate `context.py` (L86-340)

Largest and most coupled phase. Block covers: skip-hunters branch (L86-148), clean slate (L101-160), prepass + early-exit (L161-194), tests (L195-209), knowledge (L210-241), interfaces (L242-252), Chimera Setup pre-gen (L253-340), and skip-to-merge fallback context (L353-365 — also lives in this phase).

**Files:**
- Create: `audit-agents/benchmark/component_pipeline/context.py`
- Modify: `runner.py`

- [ ] **Step 1: Read block** (`runner.py:86-340` + L353-365)

- [ ] **Step 2: Create context.py with multiple functions**

```python
"""context.py — Steps 0-1.9: clean slate, prepass, context loading, Setup.sol pre-gen."""

from __future__ import annotations

from typing import Optional

from benchmark.component_pipeline.pipeline_context import PipelineContext

# Sentinel return values for early exits
EARLY_EXIT_EMPTY_PREPASS = "EARLY_EXIT_EMPTY_PREPASS"


def clean_slate(ctx: PipelineContext) -> bool:
    """Removes out/test/chimera/. Returns True if --skip-hunters and hyps exist."""
    # <CUT BODY FROM runner.py:86-160 HERE>
    # Returns True if orchestrator should skip directly to merge step.


def run_prepass(ctx: PipelineContext) -> Optional[str]:
    """Step 1: detection_engine.py --prepass. Returns sentinel if early-exit hit."""
    # <CUT BODY FROM runner.py:161-194 HERE>
    # Returns EARLY_EXIT_EMPTY_PREPASS if --skip-empty-prepass and 0 findings.


def load_context_artifacts(ctx: PipelineContext) -> None:
    """Steps 1.6-1.9: load tests, knowledge briefings, interfaces."""
    # <CUT BODY FROM runner.py:195-252 HERE>


def ensure_chimera_setup(ctx: PipelineContext) -> None:
    """Step 1.9: pre-generate Setup.sol if missing (needed by hunters)."""
    # <CUT BODY FROM runner.py:253-340 HERE>


def populate_skip_to_merge_fallback(ctx: PipelineContext) -> None:
    """Hydrate context fields when --skip-hunters skipped Steps 1-4."""
    # <CUT BODY FROM runner.py:353-365 HERE>
```

- [ ] **Step 3: Replace blocks in runner.py**

```python
    # ─── Steps 0-1: clean slate + skip-hunters branch ──────────────
    from benchmark.component_pipeline.context import (
        clean_slate, run_prepass, load_context_artifacts,
        ensure_chimera_setup, populate_skip_to_merge_fallback,
        EARLY_EXIT_EMPTY_PREPASS,
    )

    if clean_slate(ctx):
        ctx._skip_to_merge = True

    # Run pre-merge phases only if not skip-to-merge
    if not ctx._skip_to_merge:
        sentinel = run_prepass(ctx)
        if sentinel == EARLY_EXIT_EMPTY_PREPASS:
            return ctx.summary
        load_context_artifacts(ctx)
        ensure_chimera_setup(ctx)
    else:
        populate_skip_to_merge_fallback(ctx)
```

- [ ] **Step 4-5: Smoke + commit**

```bash
git commit -m "refactor(p13): context phase → context.py"
```

---

## Task 12: Reduce runner.py + activate contract tests

**Files:**
- Modify: `audit-agents/benchmark/component_pipeline/runner.py` (final cleanup, should already be small)
- Modify: `audit-agents/tests/phase_13/test_pipeline_split.py` (un-skip tests, fill PHASE_MODULES)

- [ ] **Step 1: Verify runner.py LOC**

```bash
wc -l audit-agents/benchmark/component_pipeline/runner.py
```
Expected: ≤ 120. If over, identify what didn't migrate and address before continuing.

- [ ] **Step 2: Final shape of runner.py**

Should look approximately like:

```python
"""run_component_pipeline — orchestrator over component_pipeline phases."""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

from benchmark.component_pipeline.pipeline_context import PipelineContext
from benchmark.component_pipeline.context import (
    clean_slate, run_prepass, load_context_artifacts,
    ensure_chimera_setup, populate_skip_to_merge_fallback,
    EARLY_EXIT_EMPTY_PREPASS,
)
from benchmark.component_pipeline.hunters import run_hunters
from benchmark.component_pipeline.deepdive import run_deepdive
from benchmark.component_pipeline.merge import run_merge
from benchmark.component_pipeline.enhance import enhance_target_functions
from benchmark.component_pipeline.fuzz import run_phase1_foundry, run_phase2_medusa
from benchmark.component_pipeline.extract import extract_findings
from benchmark.component_pipeline.verify import verify_findings_lightweight
from benchmark.component_pipeline.poc import generate_fork_pocs
from benchmark.component_pipeline.finding import dispatch_finding_pipeline


def run_component_pipeline(component, repo, protocol, args, logger, accumulated_context=""):
    # Build context
    ctx = PipelineContext(
        component=component, repo=repo, protocol=protocol, args=args, logger=logger,
        src_dir=Path(repo) / "src",
        hyp_dir=...,
        clog=...,
        src_file=...,
        accumulated_context=accumulated_context,
    )
    ctx.comp_start = time.time()
    ctx.logger.info(f"\n=== Component: {component} ===")

    try:
        # Phase 0-1: Context
        if clean_slate(ctx):
            ctx._skip_to_merge = True
        if not ctx._skip_to_merge:
            if run_prepass(ctx) == EARLY_EXIT_EMPTY_PREPASS:
                return ctx.summary
            load_context_artifacts(ctx)
            ensure_chimera_setup(ctx)
        else:
            populate_skip_to_merge_fallback(ctx)

        # Phase 2-3: Hunters + DeepDive
        run_hunters(ctx)
        run_deepdive(ctx)

        # Phase 5-7: Merge + enhance
        run_merge(ctx)
        enhance_target_functions(ctx)

        # Phase 8: Fuzz
        run_phase1_foundry(ctx)
        run_phase2_medusa(ctx)

        # Phase 9-10: Extract + verify
        extract_findings(ctx)
        verify_findings_lightweight(ctx)

        # Phase 11-12: PoC + finding pipeline
        generate_fork_pocs(ctx)
        dispatch_finding_pipeline(ctx)

    except Exception as e:
        ctx.logger.error(f"Component {component} pipeline error: {e}", exc_info=True)
        ctx.summary["status"] = "ERROR"
        ctx.summary["error"] = str(e)

    elapsed = (time.time() - ctx.comp_start) / 60
    ctx.logger.info(f"  🏁 Component {component} done ({elapsed:.1f}min)")
    return ctx.summary
```

(Exact ctx field initialization and edge cases match what runner.py currently does — refer to original if uncertain.)

- [ ] **Step 3: Activate contract tests**

Edit `audit-agents/tests/phase_13/test_pipeline_split.py`:

- Remove `@pytest.mark.skip` from `test_runner_loc_budget`, `test_all_phase_modules_importable`, `test_phase_loc_budgets`, `test_run_component_pipeline_entry_point`.
- Update `PHASE_MODULES`:

```python
PHASE_MODULES = [
    "pipeline_context",
    "context",
    "hunters",
    "deepdive",
    "merge",
    "enhance",
    "fuzz",
    "extract",
    "verify",
    "poc",
    "finding",
]
```

- [ ] **Step 4: Run tests**

```bash
cd audit-agents && python3 -m pytest tests/phase_13/ -v
```
Expected: 5 passed.

- [ ] **Step 5: Run full suite**

```bash
cd audit-agents && python3 -m pytest tests/ -v --timeout=120 2>&1 | tail -30
```
Expected: pre-existing pass count + 4 new (5 total in phase_13). 0 new failures.

- [ ] **Step 6: Commit**

```bash
git add audit-agents/benchmark/component_pipeline/runner.py audit-agents/tests/phase_13/test_pipeline_split.py
git commit -m "refactor(p13): reduce runner.py to orchestrator + activate contract tests"
```

---

## Self-Review Checklist (controller, before final review)

After Task 12, before invoking the final code reviewer:

1. **Spec coverage:** every section of `2026-04-19-phase-13-runner-split-design.md` mapped to a task ✓
2. **LOC budgets met:** `wc -l audit-agents/benchmark/component_pipeline/*.py` matches design table
3. **Smoke test:** `python3 -c "from benchmark.component_pipeline.runner import run_component_pipeline; print(run_component_pipeline)"` works
4. **No behavioral changes:** diff vs `main` shows only file moves + ctx accessor swaps (no new logic, no removed branches)
5. **Parity matrix:** add F058 entry to `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` (component_pipeline/runner.py → phase package)
