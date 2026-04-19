# Phase 13 — Split de `component_pipeline/runner.py` Design Spec

**Fecha:** 2026-04-19
**Goal:** Reducir `audit-agents/benchmark/component_pipeline/runner.py` (1,596 LOC tras QW1–QW7, god-file HIGH debt) a un orchestrator thin de ~80 LOC + 10 submódulos por fase del pipeline.

---

## Contexto

Fase 9 partió `pipeline_gate.py`, Fase 10 deprecó `hybrid_pipeline.py`, Fase 11 partió `merge_invariants.py`, Fase 12 partió `target_monitor.py`. Siguiente god-file en backlog: `runner.py` (1,596 LOC).

El archivo expone **una sola función** `run_component_pipeline` que actúa como monolito del pipeline por componente. Internamente ejecuta ~14 pasos secuenciales:

1. Clean slate (`out/test/chimera/`)
2. Prepass + early-exit opt-in
3. Context loading (tests, knowledge, interfaces)
4. Chimera Setup pre-generation
5. 12 hunters paralelos
6. DeepDive hunter + rescue
7. Merge invariants + import injection + compile
8. Enhance TargetFunctions (opt-in)
9. Phase 1 Foundry fuzz
10. Phase 2 Medusa (skippable)
11. Extract + dedup findings
12. Verify (lightweight code-read)
13. Phase 3 Fork PoC per finding
14. Finding pipeline dispatch (paralelo)

**Inventario del archivo actual:**
- 1 función pública: `run_component_pipeline`
- Imports lazy dentro del function body (patrón `_rb = import run_benchmark`)
- State compartido vía locals: `summary`, `hyp_dir`, `src_dir`, `setup_sol_text`, `prepass_signals_text`, `_test_files_cache`, etc.
- **Importers Python**: sólo `run_benchmark.py` vía `from benchmark.component_pipeline.runner import run_component_pipeline`
- Tests existentes: ninguno específico (solo integration benchmark tests indirectos)
- Siblings ya en paquete: `__init__.py`, `reporting.py`

La propiedad "1 solo importer" (igual que Fase 12) hace el split simple: solo preservamos el entry point `run_component_pipeline` exportado desde `runner.py`.

---

## Arquitectura

### Orchestrator thin

`component_pipeline/runner.py` queda reducido a la función `run_component_pipeline` que:
1. Construye un `PipelineContext` con los inputs
2. Ejecuta cada fase llamando a los submódulos, en orden, respetando skips/early-exits
3. Retorna el `summary` dict (contrato idéntico al actual)

Presupuesto: ~80 LOC (signature + ctx init + 14 llamadas secuenciales + logging de apertura/cierre).

### Paquete `component_pipeline/` (flat, sin subdir `phases/`)

```
audit-agents/benchmark/component_pipeline/
├─ __init__.py          (existente, vacío)
├─ runner.py            (~80 LOC)   — orchestrator thin
├─ reporting.py         (existente) — parse_fuzz_failures
├─ pipeline_context.py  (~60 LOC)   — PipelineContext dataclass
├─ context.py           (~240 LOC)  — clean slate, prepass, early-exit, tests, knowledge, interfaces, Chimera Setup pre-gen
├─ hunters.py           (~210 LOC)  — 12 hunters paralelos + brief writer
├─ deepdive.py          (~80 LOC)   — DeepDive + rescue helper
├─ merge.py             (~270 LOC)  — merge invariants + compile Setup + import injection + compile merged
├─ enhance.py           (~65 LOC)   — Step 7.5 opt-in enhance TargetFunctions
├─ fuzz.py              (~230 LOC)  — Phase 1 Foundry + Phase 2 Medusa + tolerance tuning
├─ extract.py           (~50 LOC)   — parse fuzz failures + dedup
├─ verify.py            (~70 LOC)   — lightweight code-read verification
├─ poc.py               (~180 LOC)  — Phase 3 Fork PoC per finding
└─ finding.py           (~80 LOC)   — parallel finding pipeline dispatch
```

**Total:** 13 módulos, ningún archivo > 280 LOC.

### Responsabilidades por módulo

| Módulo | Contenido | Propósito |
|---|---|---|
| `pipeline_context.py` | `PipelineContext` dataclass | State compartido entre fases |
| `context.py` | `clean_slate`, `run_prepass`, `check_early_exit`, `load_tests`, `load_knowledge`, `load_interfaces`, `ensure_chimera_setup` | Step 0–1.9 |
| `hunters.py` | `run_hunters`, `build_and_write_hunter_brief` | Step 2 |
| `deepdive.py` | `run_deepdive`, `_rescue_deepdive_yaml` | Step 3 |
| `merge.py` | `run_merge`, `inject_properties_imports`, `compile_merged` | Steps 5–7 |
| `enhance.py` | `enhance_target_functions` (opt-in) | Step 7.5 |
| `fuzz.py` | `run_phase1_foundry`, `run_phase2_medusa`, `tolerance_tuning` | Step 8 (Phase 1 + Phase 2) |
| `extract.py` | `extract_findings`, `dedup_by_root_cause` | Step 9 |
| `verify.py` | `verify_findings_lightweight` | Step 10 |
| `poc.py` | `generate_fork_pocs` | Step 11 (Phase 3) |
| `finding.py` | `dispatch_finding_pipeline` | Step 12 |

### `PipelineContext` dataclass

Encapsula state mutable compartido. Matchea locals actuales de `run_component_pipeline` 1:1 para minimizar fricción:

```python
@dataclass
class PipelineContext:
    # Inputs
    component: str
    repo: str
    protocol: str
    args: argparse.Namespace
    logger: logging.Logger

    # Derived paths
    src_dir: Path
    hyp_dir: Path
    clog: Path  # component log dir
    comp_start: float

    # Accumulators (mutated by phases)
    summary: Dict[str, Any]  # status, gates, findings, timings
    setup_sol_text: str = ""
    setup_var_names: str = ""
    prepass_signals_text: str = ""
    existing_tests_summary: str = ""
    knowledge_context: str = ""
    interfaces_code: str = ""
    source_code: str = ""
    library_code: str = ""
    _test_files_cache: List[Tuple[str, str]] = field(default_factory=list)
    protocol_model: str = ""
    accumulated_context: str = ""
    _skip_to_merge: bool = False
```

Cada fase recibe `ctx: PipelineContext` como primer arg, muta campos compartidos (ej. `ctx.summary["gates"]["hunters"] = True`), retorna `None` o un resultado local específico de la fase (ej. `extract_findings` retorna `List[Finding]`).

### Flujo de dependencias

```
runner.py → pipeline_context.py
runner.py → context.py   → pipeline_context
runner.py → hunters.py   → pipeline_context, context (hunter brief reuses context artifacts)
runner.py → deepdive.py  → pipeline_context
runner.py → merge.py     → pipeline_context
runner.py → enhance.py   → pipeline_context
runner.py → fuzz.py      → pipeline_context, reporting (parse_fuzz_failures)
runner.py → extract.py   → pipeline_context, reporting
runner.py → verify.py    → pipeline_context
runner.py → poc.py       → pipeline_context
runner.py → finding.py   → pipeline_context
```

Sin ciclos. `pipeline_context.py` es hoja (sólo imports de stdlib + typing). `reporting.py` permanece hoja (ya existente).

### Exports públicos

Sólo `run_component_pipeline` permanece público. Exportado desde `runner.py`. `run_benchmark.py` no cambia su import.

`__init__.py` queda vacío (sin re-exports) — matchea el estado actual del paquete.

---

## Patrón de migración (verbatim cut-and-paste)

Seguimos exactamente el patrón de Fase 11/12 documentado en `runner.py:1-7`:

> Verbatim cut-and-paste from run_benchmark.py with mutable / monkeypatched symbols rewired through `import run_benchmark as _rb` (lazy, avoids circular imports and freeze-at-load semantics).

Cada fase migrada:
- Preserva imports lazy (`import run_benchmark as _rb` dentro de la función)
- Preserva llamadas a `_rb._llm`, `_rb._run`, `_rb.HUNT_SESSION_DIR`, etc.
- Recibe `ctx: PipelineContext` y lee/muta sus campos en vez de locals

No reescribir lógica. No añadir abstracciones. El split es estructural, no semántico.

---

## Tests (nuevos)

`audit-agents/tests/phase_13/test_pipeline_split.py` con 4 contract tests:

1. **`test_runner_loc_budget`**: `runner.py` < 120 LOC (target real ~80, margen +50%)
2. **`test_all_phase_modules_importable`**: cada submódulo importable vía `import benchmark.component_pipeline.<name>`
3. **`test_run_component_pipeline_entry_point`**: `from benchmark.component_pipeline.runner import run_component_pipeline` resuelve y es callable
4. **`test_phase_loc_budgets`**: ningún submódulo > 280 LOC

No añadimos tests unitarios de fases individuales — el criterio de éxito es **equivalencia funcional** con el `runner.py` actual, verificable vía benchmark smoke test existente.

---

## Criterios de éxito

- `from benchmark.component_pipeline.runner import run_component_pipeline` importa sin errores
- `python3 audit-agents/run_benchmark.py --components VaultV2 --protocol morpho-vault-v2 --repo ... --fast` completa sin ImportError ni cambios de comportamiento
- `runner.py` ≤ 120 LOC (target real ~80)
- Ningún submódulo de `component_pipeline/` > 280 LOC
- Suite de tests crece +4 (de 233 a 237)
- `phase_8_audit.py`: `runner.py` ya no aparece como god-file
- CLI flags preservados: `--fuzz-refine`, `--skip-empty-prepass`, `--enhance-targets`, `--fast`, `--skip-hunters`, etc.

---

## Riesgos mitigados

| Riesgo | Mitigación |
|---|---|
| `_rb` lazy import pattern rompe al sacar código de la función | Cada fase mantiene su `import run_benchmark as _rb` local dentro de la función exportada |
| `_skip_to_merge` cambia control flow en múltiples fases | Bandera viaja en `ctx._skip_to_merge`; cada fase verifica y hace early-return |
| State sharing implícito (ej. `setup_sol_text` escrito por `context.py`, leído por `hunters.py`) | Dataclass explícito en `pipeline_context.py` documenta qué campos escribe cada fase |
| Test existentes de integración podrían romper por paths | Tests actuales sólo importan `run_component_pipeline`; contract path preservado |
| `try/except` global del pipeline | Se mantiene en `runner.py` wrapping la secuencia completa, no por fase |
| Logging formato `"  Step N:"` | Cada fase preserva su prefijo exacto (search-preservation) |

---

## Parity matrix

Al final de Fase 13, añadir entry `F058` en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
- `legacy_location: audit-agents/benchmark/component_pipeline/runner.py (monolithic)`
- `modern_location: audit-agents/benchmark/component_pipeline/ (phase package)`
- `migration_decision: migrate`
- Total features: 57 → 58

---

## Out of scope

- Cambios de comportamiento del pipeline
- Reescritura de lógica interna de fases (cut-and-paste estricto)
- Tests unitarios por fase (solo contract tests estructurales)
- Token-reduction optimizations (Option B del review — tratada como phase posterior)
- Migración a Anthropic SDK (`claude -p` CLI permanece obligatorio — ver memoria `feedback_claude_subscription_only`)
- Split de `run_benchmark.py` (Fase 14+)
- Eliminar el patrón `_rb` lazy import (requiere refactor mayor separado)
- Añadir async/concurrency (las 14 fases ya son secuenciales por diseño)

---

## Orden de ejecución sugerido

Para minimizar breakage entre commits:

1. Crear `pipeline_context.py` y el dataclass
2. Crear cada fase *uno a uno*, empezando por fases con menos dependencias (`extract.py`, `verify.py`, `finding.py` primero; `context.py` al final por tamaño)
3. En cada commit, `runner.py` delega progresivamente más a submódulos hasta quedar reducido al orchestrator
4. Contract tests añadidos en último commit, cuando la estructura final está estable
