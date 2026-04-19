# Fase 9 — Split de pipeline_gate.py

**Fecha:** 2026-04-19
**Scope:** backlog Phase 9+ identificado en Fase 8 audit (check_size_inventory WARN)
**Objetivo:** descomponer `audit-agents/pipeline_gate.py` (1,982 LOC) en un paquete de módulos focalizados ≤800 LOC cada uno, preservando el contrato público y los 224 tests passing.

## Motivación

Fase 8 audit flag como HIGH-severity debt:

```
audit-agents/pipeline_gate.py: 1,982 LOC (budget 800)
```

`pipeline_gate.py` acumula seis responsabilidades distintas:

1. Paths + constants (HUNTER_NAMES, GATE_ORDER).
2. State/ficha I/O (load_ficha, update_ficha).
3. Gate checks de componente — 13 gates: scope, prepass, hunters, crosschain, deepdive, merge, compile, phase1-5, plus dispatcher.
4. SCOPE_MASTER.md auto-update.
5. Gate status JSON export + `run_gate` dispatcher + `show_status` + `mark_gate`.
6. Finding gates — 7 gates: poc, escalation, variant, redteam, verify, report, submit + dispatcher.
7. Finding queue (generate_queue_id, queue_finding/update/promote, list_queue).
8. CLI (main + argparse).

Editar cualquiera requiere cargar las otras siete en contexto. El archivo cabe apenas en un read — cualquier iteración LLM sobre él es cara y riesgosa.

## Estrategia

Patrón validado en Fase 6: **paquete + shim de compat**.

- `audit-agents/pipeline_gate.py` → shim `<50 LOC` con re-exports marcados `# noqa: F401`. Preserva `from pipeline_gate import X`, `pipeline_gate.STATE_FILE`, el entry-point CLI (`python3 audit-agents/pipeline_gate.py --help`), y los tests existentes sin tocar sus imports.
- `audit-agents/pipeline_gate/` paquete nuevo con 8 módulos + `__init__.py`.

Todo el código se preserva verbatim en la primera fase del split — misma lógica, mismo comportamiento observable. Ninguna feature nueva, ningún bugfix encubierto.

## Arquitectura — módulos del paquete

| Módulo | LOC estimado | Responsabilidad | Dependencias internas |
|---|---|---|---|
| `constants.py` | ~40 | `get_hyp_dir`, `_get_protocol`, `get_context_dir`, `get_gate_status_file`, `HUNTER_NAMES`, `GATE_ORDER`, `DISPLAY_GATES` | — (hoja del grafo) |
| `ficha.py` | ~50 | `load_ficha`, `update_ficha` | `constants` |
| `gates_component.py` | ~580 | 13 gate checks (scope, prepass, hunters, crosschain, deepdive, merge, compile, phase1-5) + `GATE_CHECKS` dict | `constants`, `ficha`, `state_manager` |
| `scope_master.py` | ~275 | `_find_scope_master`, `_scope_master_update_component/coverage`, `scope_master_on_complete/review/finding`, `show_scope_status` | `state_manager`, `paths` |
| `gate_status.py` | ~220 | `_map_gate_state`, `_load_gate_status`, `_save_gate_status`, `export_gate_status`, `run_gate`, `show_status`, `mark_gate` | `constants`, `gates_component`, `scope_master`, `state_manager` |
| `gates_finding.py` | ~480 | 7 finding gate checks + `FINDING_GATE_CHECKS` dict + `_check_poc_uses_fork`, `_find_hyp_with_finding`, `export_finding_gate_status`, `run_finding_gate`, `show_finding_status`, `mark_finding_gate` | `constants`, `state_manager`, `gate_status` (for export helpers) |
| `finding_queue.py` | ~150 | `_save_state`, `generate_queue_id`, `queue_finding`, `list_queue`, `queue_update`, `queue_promote` | `state_manager`, `scope_master` |
| `cli.py` | ~180 | `main()` + argparse wiring; single CLI entry point | todos los módulos anteriores |

**Total:** ~1,975 LOC distribuidos en 8 archivos — mismo total que el monolito, con el archivo más grande en ~580 LOC (dentro del budget 800).

## Contrato público — invariantes de backward-compat

El shim `pipeline_gate.py` debe re-exportar (en este orden mínimo, vía `# noqa: F401`):

```python
# constants
from pipeline_gate.constants import (
    HUNTER_NAMES, GATE_ORDER, DISPLAY_GATES,
    get_hyp_dir, get_context_dir, get_gate_status_file, _get_protocol,
)
# state
from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
from state_manager import load_state, save_state as _sm_save_state
# ficha
from pipeline_gate.ficha import load_ficha, update_ficha
# gates_component
from pipeline_gate.gates_component import (
    check_scope, check_hunters, check_deepdive, check_crosschain,
    check_merge, check_compile, check_phase1, check_phase2, check_phase3,
    check_phase4, check_phase5, check_prepass, GATE_CHECKS,
)
# scope_master
from pipeline_gate.scope_master import (
    _find_scope_master, _scope_master_update_component,
    _scope_master_update_coverage, scope_master_on_complete,
    scope_master_on_review, scope_master_on_finding, show_scope_status,
)
# gate_status
from pipeline_gate.gate_status import (
    _map_gate_state, _load_gate_status, _save_gate_status,
    export_gate_status, run_gate, show_status, mark_gate,
)
# gates_finding
from pipeline_gate.gates_finding import (
    _check_poc_uses_fork, _find_hyp_with_finding,
    check_finding_poc, check_finding_escalation, check_finding_variant,
    check_finding_redteam, check_finding_verify, check_finding_report,
    check_finding_submit, FINDING_GATE_CHECKS,
    export_finding_gate_status, run_finding_gate, show_finding_status,
    mark_finding_gate,
)
# finding_queue
from pipeline_gate.finding_queue import (
    _save_state, generate_queue_id, queue_finding,
    list_queue, queue_update, queue_promote,
)
# cli
from pipeline_gate.cli import main

if __name__ == "__main__":
    main()
```

Tests existentes (`audit-agents/tests/test_pipeline_gate.py`) hacen:
- `from pipeline_gate import export_gate_status` → sigue funcionando (shim re-export).
- `monkeypatch.setattr(pipeline_gate, "HUNT_SESSION_DIR", ...)` → depende de que `HUNT_SESSION_DIR` siga bound en el módulo `pipeline_gate`. Se re-exporta desde `paths` y queda en el namespace del shim.
- `monkeypatch.setattr(pipeline_gate, "STATE_FILE", ...)` → ídem (re-export desde `paths`).
- `monkeypatch.setattr(state_manager, "STATE_FILE", ...)` → sin cambios.
- `pipeline_gate.load_state()` → re-export desde `state_manager`.
- `pipeline_gate.queue_finding(...)`, `pipeline_gate.queue_update(...)`, `pipeline_gate.queue_promote(...)` → re-exports.

**Consumidores externos** que imports `from pipeline_gate import X` (detectar con grep antes del split):
- `audit-agents/run_benchmark.py` / `benchmark/*.py`
- `audit-agents/scope_intake.py`
- `audit-agents/apply_feedback.py`
- `audit-agents/sync_state.py`
- `audit-agents/report_finding.py`
- `audit-agents/submit_finding.py`
- `audit-agents/component_closer.py`

El shim debe cubrirlos sin cambios en sus imports.

## Dependencias internas — orden de split

Para romper ciclos y permitir TDD incremental:

```
constants (hoja)
   ↑
  ficha
   ↑
  scope_master ←── state_manager (externo)
   ↑
  gates_component
   ↑
  gate_status
   ↑
  gates_finding
   ↑
  finding_queue ←── scope_master (para scope_master_on_finding)
   ↑
   cli
```

Orden de extracción (una tarea por módulo, en orden topológico):

1. `constants.py`
2. `ficha.py`
3. `scope_master.py`
4. `gates_component.py`
5. `gate_status.py`
6. `gates_finding.py`
7. `finding_queue.py`
8. `cli.py`
9. Reducir `pipeline_gate.py` a shim + verificar contrato

## Flujo de datos — no cambia

El split es puramente estructural. El flujo actual:

1. CLI parsea args → invoca `run_gate(component, gate)` o `run_finding_gate(finding_id, gate)`.
2. Runner loopea gates ordenados llamando cada `check_*` o `check_finding_*`.
3. Cada check lee `hunt_session/` y devuelve `(ok, passed, failed)`.
4. Runner invoca `export_gate_status` / `export_finding_gate_status` al final.
5. Export escribe `hunt_session/gate_status/<protocol>.json` (vía `_save_gate_status`).
6. Componente completado dispara `scope_master_on_complete` + SCOPE_MASTER.md update.
7. Queue ops leen/escriben `current_hunt.json` vía `state_manager`.

Post-split: mismo flujo, mismos side-effects, mismas signatures. Solo cambia la ubicación de los símbolos.

## Testing strategy

### Red de seguridad existente (224 tests)

- 7 tests en `audit-agents/tests/test_pipeline_gate.py` — cubren `_check_poc_uses_fork`, `generate_queue_id`, `export_gate_status` (3 variantes), `queue_finding`, `queue_promote`.
- Tests de fases 2A-8 que importan `pipeline_gate` via consumidores (`run_benchmark`, `scope_intake`, etc.).

Baseline a mantener en cada tarea: **224/224 passed** tras cada commit.

### Tests nuevos mínimos

Añadir `audit-agents/tests/phase_9/test_shim_reexports.py` (~30 LOC):

```python
"""Shim contract: all documented symbols are re-exported from pipeline_gate."""
import pipeline_gate

EXPECTED_PUBLIC = {
    # constants
    "HUNTER_NAMES", "GATE_ORDER", "DISPLAY_GATES",
    "get_hyp_dir", "get_context_dir", "get_gate_status_file",
    # state
    "HUNT_SESSION_DIR", "STATE_FILE", "load_state",
    # ficha
    "load_ficha", "update_ficha",
    # gates_component
    "check_scope", "check_hunters", "check_deepdive", "check_crosschain",
    "check_merge", "check_compile", "check_phase1", "check_phase2",
    "check_phase3", "check_phase4", "check_phase5", "check_prepass",
    "GATE_CHECKS",
    # scope_master
    "scope_master_on_complete", "scope_master_on_finding",
    "scope_master_on_review", "show_scope_status",
    # gate_status
    "export_gate_status", "run_gate", "show_status", "mark_gate",
    # gates_finding
    "check_finding_poc", "check_finding_escalation", "check_finding_variant",
    "check_finding_redteam", "check_finding_verify", "check_finding_report",
    "check_finding_submit", "FINDING_GATE_CHECKS",
    "export_finding_gate_status", "run_finding_gate",
    "show_finding_status", "mark_finding_gate",
    # finding_queue
    "generate_queue_id", "queue_finding", "list_queue",
    "queue_update", "queue_promote",
    # cli
    "main",
}


def test_shim_reexports_public_contract():
    missing = [name for name in EXPECTED_PUBLIC if not hasattr(pipeline_gate, name)]
    assert not missing, f"Missing re-exports: {missing}"


def test_shim_line_budget():
    """Shim stays under 80 LOC (re-exports only)."""
    from pathlib import Path
    p = Path(pipeline_gate.__file__)
    lines = p.read_text().splitlines()
    non_blank = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    assert len(non_blank) <= 80, f"shim grew to {len(non_blank)} non-blank non-comment lines"
```

Este test protege el contrato y atrapa regresiones si alguien accidentalmente borra un re-export durante refactors futuros.

### Smoke checks por módulo

Tras extraer cada módulo, ejecutar:

```bash
python3 -c "from pipeline_gate.<module> import <sym1>, <sym2>"
python3 -m pytest audit-agents/tests/ -q  # 224 passed
python3 audit-agents/pipeline_gate.py --help > /dev/null  # CLI exit 0
```

## Parity matrix update

Añadir una entrada por cada módulo nuevo (8 entries F047-F054) con `migration_decision: added_phase_9`:

| ID | Módulo | legacy_location | modern_location |
|---|---|---|---|
| F047 | constants | `pipeline_gate.py (Paths + constants section)` | `audit-agents/pipeline_gate/constants.py` |
| F048 | ficha | `pipeline_gate.py (State helpers section)` | `audit-agents/pipeline_gate/ficha.py` |
| F049 | gates_component | `pipeline_gate.py (Gate checks section)` | `audit-agents/pipeline_gate/gates_component.py` |
| F050 | scope_master | `pipeline_gate.py (SCOPE_MASTER section)` | `audit-agents/pipeline_gate/scope_master.py` |
| F051 | gate_status | `pipeline_gate.py (Gate Status JSON Export section)` | `audit-agents/pipeline_gate/gate_status.py` |
| F052 | gates_finding | `pipeline_gate.py (Finding Pipeline Gates section)` | `audit-agents/pipeline_gate/gates_finding.py` |
| F053 | finding_queue | `pipeline_gate.py (Finding Queue section)` | `audit-agents/pipeline_gate/finding_queue.py` |
| F054 | cli | `pipeline_gate.py (Main section)` | `audit-agents/pipeline_gate/cli.py` |

Summary block:
- `total_features: 46 → 54`
- `by_decision.added_phase_9: 8`
- `total` checksum: 16 + 14 + 0 + 2 + 14 + 8 = 54 ✓

## Criterios de éxito

1. **Suite passing**: `python3 -m pytest audit-agents/tests/ -q` → 224 + 2 (nuevos shim tests) = **226 passed, 0 failed** tras la última tarea.
2. **Shim ≤80 LOC** (re-exports + 2 líneas de CLI bootstrap, sin lógica).
3. **Ningún módulo nuevo >800 LOC**.
4. **CLI funcional**: `python3 audit-agents/pipeline_gate.py --help` exit 0, mismo output que antes del split.
5. **Consumers intactos**: no se modifica ningún `from pipeline_gate import ...` en el resto del repo. `rtk grep "from pipeline_gate import"` antes y después devuelve el mismo set (o subset si el shim cubre).
6. **Parity matrix actualizada**: 8 entradas F047-F054 + summary aritmética correcta.
7. **Re-run Fase 8 audit**: check_size_inventory WARN pasa a reconocer el split — `pipeline_gate.py` del shim queda bajo el umbral; los nuevos módulos bajo 800 LOC.

## No-goles (fuera de scope)

- Cambios de lógica, bugfixes, mejoras de performance.
- Tocar los otros 3 god-files (`hybrid_pipeline.py`, `merge_invariants.py`, `target_monitor.py`) — quedan para fases 9.2, 9.3, 9.4.
- Eliminar dead code (`check_dead_code_residual` WARN) — fase distinta.
- Crear tests nuevos más allá del contrato shim.
- Renombrar símbolos, cambiar APIs, reordenar parámetros.

## Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Test monkeypatches de `pipeline_gate.STATE_FILE` / `HUNT_SESSION_DIR` se rompen tras el split | Shim re-exporta explícitamente desde `paths`, preservando el binding en el namespace `pipeline_gate`. Verificado con test_pipeline_gate tras cada tarea. |
| Ciclos de import entre módulos nuevos (ej: `finding_queue` necesita `scope_master`, pero `scope_master` podría necesitar algo de gates) | Orden topológico respetado; si aparece ciclo inesperado, resolverlo con lazy import dentro de función (patrón Fase 6). |
| Un consumer (ej: `benchmark/cli.py`) importa un símbolo privado (`_foo`) que no re-exporté | Grep exhaustivo pre-split: `rtk grep "from pipeline_gate import" audit-agents/ --include=*.py`; añadir al re-export list. |
| Shim crece >80 LOC por volumen de re-exports | Budget holgado (40-50 símbolos × 1 línea = ~50 LOC); si se excede, usar `__all__ = [...]` + `*` import (anti-pattern; evitar) o aceptar budget de 100. |
| Regresión de comportamiento durante extracción | Verbatim copy — no refactor. Tests tras cada commit. Git bisect si algo rompe. |
| `gate_status.run_gate` llama `export_gate_status` que llama `scope_master_on_complete`: orden de extracción los coloca en módulos distintos | Resuelto: `scope_master` se extrae antes que `gate_status`, que se extrae antes que `gates_finding`. |

## Branch strategy

Commits directos a `main` siguiendo el patrón de Fases 2A-8 (no worktree, no PR). Un commit por tarea para `git bisect` eficaz.

## Referencias

- Precedente: `docs/superpowers/specs/2026-04-18-phase-6-refactor-polish-design.md` (split de `run_benchmark.py` 4,291→<50 LOC y `plan_generator.py` 3,223→<50 LOC).
- Audit que lo flagea: `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md` §check_size_inventory.
- Parity matrix: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`.
