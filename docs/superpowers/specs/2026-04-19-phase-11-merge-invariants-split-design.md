# Phase 11 — Split de `merge_invariants.py` Design Spec

**Fecha:** 2026-04-19
**Goal:** Reducir `merge_invariants.py` (1,280 LOC, god-file HIGH debt) a un shim CLI de ~25 LOC + paquete `merge/` con submódulos cohesivos.

---

## Contexto

Phase 9 partió `pipeline_gate.py` (1,982 LOC) en un shim + paquete `gate/` con 8 submódulos. Phase 10 deprecó `hybrid_pipeline.py`. Siguiente god-file en el backlog: `merge_invariants.py`.

**Inventario del archivo actual:**
- 28 funciones top-level, sin classes
- Imports limitados: `paths`, `state_manager`, stdlib
- **Cero importers Python**: solo se invoca como subprocess desde `runner.py`, `plan/generator.py`, `plan/prompts_rust.py`
- Tests existentes: ninguno

Esta propiedad (cero importers Python) hace el split **más simple que Fase 9**: no hay API pública que preservar vía `__all__`. El shim solo mantiene el entry-point CLI.

---

## Arquitectura

### Shim canónico
`audit-agents/merge_invariants.py` queda como CLI thin shim:

```python
#!/usr/bin/env python3
"""merge_invariants.py — CLI entry point. Logic in merge/ package."""
from merge.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

Mantiene compatibilidad con todos los callers actuales (que invocan `python3 merge_invariants.py ...`).

### Paquete `merge/`

```
audit-agents/merge/
├─ __init__.py          (vacío — paquete es de uso interno)
├─ loading.py           (~170 LOC)
├─ solidity.py          (~100 LOC)
├─ hypothesis.py        (~110 LOC)
├─ files.py             (~200 LOC)
├─ modes.py             (~440 LOC)
└─ cli.py               (~150 LOC)
```

### Responsabilidades por módulo

| Módulo | Funciones migradas | Propósito |
|---|---|---|
| `loading.py` | `get_hyp_dir`, `load_current_hunt`, `find_chimera_dir`, `find_properties_sol`, `load_hypothesis_file`, `validate_hypothesis`, `dedup_hypotheses`, `validate_evidence_tables`, `detect_pragma` | I/O + validación de hipótesis YAML y chimera dir discovery |
| `solidity.py` | `id_to_function_name`, `_wrap_comment`, `_clean_solidity_body`, `_sanitize_solidity`, `generate_property_function`, `generate_optimize_function`, `generate_ghost_var` | Generación/limpieza de código Solidity individual |
| `hypothesis.py` | `process_hypothesis`, `_dedup_ghosts`, `extract_existing_ids`, `extract_existing_ids_from_dir` | Transformación de hipótesis → código + deduplicación |
| `files.py` | `generate_hunter_sol_file`, `generate_cross_component_sol_file`, `update_target_functions_import`, `clean_properties_base` | Generación de archivos `.sol` completos |
| `modes.py` | `run_split_mode`, `run_monolithic_mode`, `insert_into_properties_sol`, `list_invariants` | Orquestadores de alto nivel (flujos end-to-end) |
| `cli.py` | `main` + argparse | CLI entry point |

### Flujo de dependencias

```
cli.py → modes.py → files.py → hypothesis.py → solidity.py, loading.py
                              → loading.py
         loading.py (independiente)
         solidity.py (independiente)
```

Cada módulo depende solo de los de abajo. Sin ciclos.

---

## Tests (nuevos)

`audit-agents/tests/phase_11/test_merge_shim.py` con 3 contract tests:

1. **`test_shim_loc_budget`**: `merge_invariants.py` < 30 LOC
2. **`test_merge_package_modules_importable`**: cada submódulo importable vía `import merge.<name>`
3. **`test_cli_main_callable`**: `from merge.cli import main` resuelve y es callable

No añadimos tests unitarios de comportamiento — el archivo original no tiene tests, y el criterio de éxito es **equivalencia funcional** (mismo CLI, mismos outputs).

---

## Criterios de éxito

- `python3 audit-agents/merge_invariants.py --help` imprime el mismo help que antes
- Invocaciones subprocess existentes (desde `runner.py`, `plan/generator.py`, `plan/prompts_rust.py`) funcionan sin cambios
- `merge_invariants.py` < 30 LOC
- Ningún submódulo de `merge/` > 450 LOC
- Suite de tests pasa (incluyendo 3 nuevos contract tests de Phase 11 → 230 total)
- `phase_8_audit.py`: `merge_invariants.py` ya no aparece como god-file (< 1000 LOC)

---

## Riesgos mitigados

| Riesgo | Mitigación |
|---|---|
| Dependencias circulares entre submódulos | Orden de migración bottom-up: solidity + loading primero (independientes), luego hypothesis, luego files, modes, cli |
| Acoplamiento oculto vía globals | Auditar antes de mover: `sys.path.insert`, módulo `paths`, `state_manager`. Todos son imports, no globals mutables |
| Callers rotos por path mismatch | Shim mantiene CLI idéntico. Submódulos no se importan externamente |

---

## Parity matrix

Al final de Phase 11, añadir entry `F056` en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
- `legacy_location: audit-agents/merge_invariants.py`
- `modern_location: audit-agents/merge/ (package)`
- `migration_decision: migrate`
- Total features: 55 → 56

---

## Out of scope

- Cambios de comportamiento del CLI
- Reescritura de lógica interna
- Tests unitarios de funciones migradas
- Split de `target_monitor.py` o `runner.py` (Phase 12+)
