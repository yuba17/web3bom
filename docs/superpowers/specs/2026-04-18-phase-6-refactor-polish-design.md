# Phase 6 — Refactor Polish / Split God-Files — Design

**Fecha**: 2026-04-18
**Fase**: 6 de 8 del roadmap `docs/superpowers/specs/2026-04-17-optimization-roadmap.md`
**Objetivo**: partir los dos god-files del flujo moderno en módulos cohesivos de boundaries claros, con 135/135 tests verdes en cada commit.

---

## 1. Contexto

Tras Fase 5 (shared infra consolidation), el sistema tiene 2 god-files combinados en 7,514 LOC:

| Archivo | LOC | Funcs top-level | Rol |
|---|---|---|---|
| `audit-agents/run_benchmark.py` | 4,291 | 40 | Entrypoint CLI + pipeline runner + prompt builders + worktree mgmt |
| `audit-agents/plan_generator.py` | 3,223 | 36 | Plan generation + phase prompt builders (Solidity/Rust) |

**Problema**: reasoning con god-files consume contexto, edits riesgosos, boundaries difusos. `run_component_pipeline` tiene 1,600 LOC dentro del god-file (god-function nested).

**Detectado además**: ciclo lazy `plan_generator.py → run_benchmark.py` (4 imports dentro de funciones: `build_hunter_brief`, `build_hunter_dispatch_prompt`, `build_deepdive_prompt`, `build_cross_pair_prompt`). Este ciclo existe porque los prompt builders viven en `run_benchmark.py` pero son consumidos desde `plan_generator.phase_*_prompt`. La Fase 6 aprovecha el split para romperlo.

**Fuera de scope**: Eje 3 (matching consolidation `benchmark.py` + `benchmark_score.py` + `ingest_rejections.py`) — reservado para Fase 7 o posterior.

---

## 2. Decisiones tomadas en brainstorming

| # | Decisión | Opción elegida |
|---|---|---|
| Q1 | Scope | **A**: solo god-files. Eje 3 fuera de scope |
| Q2 | Strategy | **B**: incremental + transitional re-export shims |
| Q3 | Granularidad | **A**: fine-grained (~14 módulos, boundaries naturales) |
| Q4 | Tests | **A+1**: suite existente + 1 smoke test global de shim re-exports |

---

## 3. Arquitectura objetivo

```
audit-agents/
├── benchmark/                          # nuevo paquete
│   ├── __init__.py
│   ├── llm_runners.py       (~400 LOC)  # run_claude, _run_claude_inner, run_claude_sub,
│   │                                    # _llm, run_cmd, _extract_first_errors
│   ├── prompt_builders.py   (~600 LOC)  # build_hunter_brief, build_hunter_dispatch_prompt,
│   │                                    # build_deepdive_prompt, build_poc_prompt,
│   │                                    # build_escalation_prompt, build_redteam_prompt,
│   │                                    # build_variant_prompt, build_report_prompt,
│   │                                    # build_cross_pair_prompt
│   ├── poc_pipeline.py      (~200 LOC)  # generate_and_test_poc, fix_and_retry,
│   │                                    # _generate_foundry_tester_wrappers,
│   │                                    # _sanitize_sol_unicode, _filter_errors_for_file,
│   │                                    # _log_funnel
│   ├── component_pipeline.py(~1600→split posible) # run_component_pipeline +
│   │                                    # parse_fuzz_failures
│   ├── finding_pipeline.py  (~200 LOC)  # extract_findings, run_finding_pipeline
│   ├── cross_component.py   (~500 LOC)  # run_cross_component
│   ├── worktree_helpers.py  (~170 LOC)  # _create_worktree, _remove_worktree,
│   │                                    # _apply_force_regen_map, _maybe_run_apply_feedback,
│   │                                    # _resolve_components, _validate_hunters_subset
│   └── cli.py               (~550 LOC)  # main() + argparse + orchestration
├── plan/                               # nuevo paquete
│   ├── __init__.py
│   ├── detectors.py         (~225 LOC)  # _detect_primary_domain, _read_file_safe,
│   │                                    # _detect_lang, _src_dir, _find_cargo_workspace,
│   │                                    # _find_rust_crate_src, _rust_crate_sources,
│   │                                    # _results_dir, _hyp_dir, _step_id,
│   │                                    # _rpc_var, _fork_sol_snippet, _worktree_path,
│   │                                    # _last_step_id
│   ├── generator.py         (~670 LOC)  # generate_plan, _add_component_steps,
│   │                                    # _add_cross_component_steps
│   ├── prompts_solidity.py  (~900 LOC)  # phase_hunter_prompt, phase_deepdive_prompt,
│   │                                    # phase_findings, phase_write_fork_setup,
│   │                                    # phase_fork_poc_prompt, phase_cross_prompt,
│   │                                    # phase_transitive_chain_prompt,
│   │                                    # phase_chimera_early_prompt,
│   │                                    # phase_chimera_builder_prompt,
│   │                                    # phase_enhance_targets_prompt
│   ├── prompts_rust.py      (~800 LOC)  # phase_rust_fuzz_scaffold_prompt,
│   │                                    # phase_rust_fuzz_harness_prompt,
│   │                                    # phase_rust_merge_harness,
│   │                                    # _rust_enhance_fuzz_prompt,
│   │                                    # _phase_hunter_prompt_rust,
│   │                                    # _phase_findings_rust,
│   │                                    # _phase_cross_prompt_rust
│   ├── post_compile.py      (~340 LOC)  # phase_post_compile, phase_checkpoint
│   └── cli.py               (~140 LOC)  # main()
├── run_benchmark.py (shim <50 LOC)    # re-exports desde benchmark/*
└── plan_generator.py (shim <50 LOC)   # re-exports desde plan/*
```

**Nota sobre `phase_write_fork_setup`**: a pesar de tener "write" en el nombre y escribir archivos, es parte de `prompts_solidity` porque su output es el prompt builder de setup. Si durante la extracción se ve que no encaja semánticamente, se reubica (decisión en plan).

---

## 4. Grafo de dependencias (post-split, sin ciclos)

```
paths, state_manager  ← (Fase 5, ya existen)
      ↑
      ├── benchmark/llm_runners       (LLM/subprocess, zero deps internos)
      ├── benchmark/prompt_builders   (string templates, zero deps internos)
      ├── plan/detectors              (path/lang helpers, zero deps internos)
      │
      ├── benchmark/poc_pipeline      ← llm_runners, prompt_builders
      ├── benchmark/worktree_helpers  ← (stdlib only)
      │
      ├── plan/prompts_solidity       ← detectors, benchmark/prompt_builders  [ROMPE CICLO]
      ├── plan/prompts_rust           ← detectors
      ├── plan/post_compile           ← detectors
      │
      ├── plan/generator              ← detectors, prompts_solidity, prompts_rust, post_compile
      │
      ├── benchmark/component_pipeline ← llm_runners, prompt_builders, poc_pipeline,
      │                                  worktree_helpers, hunter_context, context_enrichment
      ├── benchmark/finding_pipeline   ← llm_runners, prompt_builders
      ├── benchmark/cross_component    ← llm_runners, prompt_builders, worktree_helpers
      │
      └── benchmark/cli                ← todos los módulos anteriores (entrypoint)
```

**Cambio clave — ciclo roto**: los 4 lazy imports en `plan_generator.py` (líneas 922, 1494, 1610, 2184) pasan a ser `from benchmark.prompt_builders import ...` top-level en `plan/prompts_solidity.py`. Sin lazy, sin ciclo.

**Dependencias externas a respetar (no mover):**
- `context_enrichment.build_hunter_context` — consumido por `plan/prompts_solidity.phase_hunter_prompt`
- `hunter_context.{HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples}` — consumidos por `benchmark/component_pipeline`
- `paths.{WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR, STATE_FILE}` — consumidos por casi todos
- `state_manager.{load_state, save_state}` — consumidos por `benchmark/cli` + `component_pipeline`
- `plan_schema.ExecutionPlan` — consumido por `plan/generator`
- `pipeline_gate` — invocado via subprocess en `benchmark/cli` (no import Python)

---

## 5. Orden de extracción

16 tareas secuenciales, cada una commit atómico que mantiene 135/135:

| # | Tarea | Dep |
|---|---|---|
| 0 | Baseline verification (135/135) | — |
| 1 | Crear `benchmark/__init__.py` + `plan/__init__.py` (empty) | 0 |
| 2 | Extract `benchmark/llm_runners.py` (zero deps → safe first) | 1 |
| 3 | Extract `benchmark/prompt_builders.py` (rompe ciclo lazy) | 2 |
| 4 | Extract `plan/detectors.py` | 1 |
| 5 | Extract `benchmark/poc_pipeline.py` | 2, 3 |
| 6 | Extract `benchmark/worktree_helpers.py` | 1 |
| 7 | Extract `plan/post_compile.py` | 4 |
| 8 | Extract `plan/prompts_solidity.py` (migra lazy → top-level) | 3, 4 |
| 9 | Extract `plan/prompts_rust.py` | 4 |
| 10 | Extract `plan/generator.py` (último de plan/; plan_generator.py queda shim) | 4, 7, 8, 9 |
| 11 | Extract `benchmark/finding_pipeline.py` | 2, 3 |
| 12 | Extract `benchmark/cross_component.py` | 2, 3, 6 |
| 13 | Extract `benchmark/component_pipeline.py` (split interno si >800 LOC post-extract) | 2, 3, 5, 6 |
| 14 | Extract `benchmark/cli.py` (último de benchmark/; run_benchmark.py queda shim) | 2-13 |
| 15 | Añadir `tests/phase_6/test_shim_reexports.py` (3 tests smoke) | 14 |
| 16 | Update parity matrix + memory roadmap (Fase 6 COMPLETA → Fase 7 NEXT) | 15 |

**Patrón por tarea de extracción (2-14):**
1. Crear nuevo módulo con las funciones copiadas (incluyendo imports internos necesarios).
2. En el god-file origen, reemplazar las definiciones con `from <new_module> import <symbols>  # noqa: F401` — convierte el bloque en re-export.
3. Si otro módulo ya extraído importa lazy desde el god-file, actualizar a import directo del nuevo módulo.
4. Correr: `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q`.
5. Expected: `135 passed`.
6. Commit: `refactor(phase_6): extract <module> from <god-file>`.

---

## 6. Shim pattern

Ejemplo `run_benchmark.py` post-Tarea 14:

```python
"""Compatibility shim — symbols re-exported from benchmark/*.

Kept transitionally so direct imports (tests, external tooling) keep
working during Phase 6 split. Will be re-evaluated in Phase 7 cleanup.
"""
from benchmark.llm_runners import (  # noqa: F401
    run_claude, _run_claude_inner, run_claude_sub, _llm, run_cmd,
    _extract_first_errors,
)
from benchmark.prompt_builders import (  # noqa: F401
    build_hunter_brief, build_hunter_dispatch_prompt, build_deepdive_prompt,
    build_poc_prompt, build_escalation_prompt, build_redteam_prompt,
    build_variant_prompt, build_report_prompt, build_cross_pair_prompt,
)
from benchmark.poc_pipeline import generate_and_test_poc, fix_and_retry  # noqa: F401
from benchmark.component_pipeline import run_component_pipeline  # noqa: F401
from benchmark.finding_pipeline import extract_findings, run_finding_pipeline  # noqa: F401
from benchmark.cross_component import run_cross_component  # noqa: F401
from benchmark.worktree_helpers import (  # noqa: F401
    _create_worktree, _remove_worktree, _apply_force_regen_map,
    _maybe_run_apply_feedback, _resolve_components, _validate_hunters_subset,
)
from benchmark.cli import main

if __name__ == "__main__":
    main()
```

Ejemplo `plan_generator.py` post-Tarea 10:

```python
"""Compatibility shim — symbols re-exported from plan/*."""
from plan.generator import generate_plan  # noqa: F401
from plan.prompts_solidity import (  # noqa: F401
    phase_hunter_prompt, phase_deepdive_prompt, phase_findings,
    phase_write_fork_setup, phase_fork_poc_prompt, phase_cross_prompt,
    phase_transitive_chain_prompt, phase_chimera_early_prompt,
    phase_chimera_builder_prompt, phase_enhance_targets_prompt,
)
from plan.prompts_rust import (  # noqa: F401
    phase_rust_fuzz_scaffold_prompt, phase_rust_fuzz_harness_prompt,
    phase_rust_merge_harness,
)
from plan.post_compile import phase_post_compile, phase_checkpoint  # noqa: F401
from plan.cli import main

if __name__ == "__main__":
    main()
```

**Shim lifetime**: transitional. Fase 7 decide si se eliminan (updating callers) o quedan como permanent compat layer.

---

## 7. Edge cases y riesgos

| # | Riesgo | Mitigación |
|---|---|---|
| 1 | Tests importan helpers privados (`_validate_hunters_subset`, etc.) | Shim re-exporta con `# noqa: F401` incluyendo los `_` helpers. Tests no cambian |
| 2 | Lazy imports intencionales por performance/side-effects | Auditar en cada extracción. Si existe por razón ≠ ciclo, preservar lazy en módulo destino |
| 3 | `run_component_pipeline` 1,600 LOC | Tarea 13 hace extracción plana. Si post-extract el módulo excede 800 LOC, sub-tarea 13b para split interno (`component_pipeline/{runner, fuzzing_helpers, reporting}.py`). Si no excede (p.ej. porque helpers como `parse_fuzz_failures` ya cuentan), YAGNI |
| 4 | `main()` en `run_benchmark.py` | Queda `if __name__ == "__main__": main()` via re-export desde `benchmark/cli.py`. Callers CLI (`python3 audit-agents/run_benchmark.py ...`) siguen funcionando |
| 5 | Tests que hacen `import run_benchmark` como módulo | Shim mantiene el módulo importable con símbolos públicos re-exportados. `plan_generator.phase_X(...)` sigue funcionando |
| 6 | Rollback si una tarea rompe tests | Cada tarea es commit atómico. `rtk git revert <sha>` recupera estado previo sin afectar tareas posteriores |
| 7 | Side-effects de monkey-patching en tests | El smoke test de Tarea 15 carga ambos shims + paquetes; falla ruidosamente si hay ciclo o import side-effect roto |

---

## 8. Tests

**Baseline (Tarea 0):** 135/135 en la suite combinada.

**Durante extracción (Tareas 2-14):** 135/135 passed en cada commit. Regla hard — no se avanza si baja. Si falla, revertir y sub-dividir.

**Tarea 15 — smoke test de shim:** `audit-agents/tests/phase_6/test_shim_reexports.py` con 3 tests:

1. `test_run_benchmark_shim_reexports_contract` — BENCHMARK_PUBLIC (set de ~27 símbolos) ⊆ `vars(run_benchmark)`
2. `test_plan_generator_shim_reexports_contract` — PLAN_PUBLIC (set de ~16 símbolos) ⊆ `vars(plan_generator)`
3. `test_no_import_cycle` — `import benchmark; import plan; import plan.prompts_solidity; import benchmark.prompt_builders` no lanza

Contract sets exactos: ver Sección 5 del brainstorming (definidos en el plan).

**Suite combinada post-Fase 6:** 138 passed.

---

## 9. Criterios de éxito

Al completar Tarea 16:

1. `rtk wc -l audit-agents/run_benchmark.py audit-agents/plan_generator.py` → ambos < 50 LOC
2. `rtk grep -n "from run_benchmark import" audit-agents/plan_generator.py` → 0 matches
3. `rtk grep -n "from run_benchmark import\|import run_benchmark" audit-agents/plan/` → 0 matches
4. Suite combinada: `138 passed` (135 existing + 3 shim smoke)
5. 4 CLIs `--help` exit 0: `run_benchmark.py`, `pipeline_gate.py`, `scope_intake.py`, `sync_state.py`
6. Parity matrix: 14 entradas nuevas F033..F046 con `migration_decision: added_phase_6` (una por módulo extraído + __init__ entries)
7. Memory roadmap: Fase 6 COMPLETA (2026-04-18), Fase 7 → 🔜 NEXT

---

## 10. Fuera de scope (Fase 7+)

- Eje 3 matching consolidation (`benchmark.py` + `benchmark_score.py` + `ingest_rejections.py`)
- Split de `pipeline_gate.py` (1,982 LOC) — no está en el meta-spec Fase 6
- Eliminación definitiva de shims — depende de si Fase 7 detecta callers externos
- `run_component_pipeline` split interno — se hace solo si post-Tarea 13 el módulo queda >800 LOC

---

## 11. Métricas esperadas

| Métrica | Pre-Fase 6 | Post-Fase 6 |
|---|---|---|
| LOC `run_benchmark.py` | 4,291 | < 50 (shim) |
| LOC `plan_generator.py` | 3,223 | < 50 (shim) |
| Módulos en `benchmark/` | 0 | 8 |
| Módulos en `plan/` | 0 | 6 |
| Ciclos lazy plan_generator → run_benchmark | 4 | 0 |
| Tests combinados | 135 | 138 |
| Commits Fase 6 | — | ~17 (Tareas 0-16, uno por tarea más baseline + docs) |

---

## 12. Próximo paso

Invocar `superpowers:writing-plans` para crear el plan TDD detallado en `docs/superpowers/plans/2026-04-18-phase-6-refactor-polish.md` con las 17 tareas (16 + baseline).
