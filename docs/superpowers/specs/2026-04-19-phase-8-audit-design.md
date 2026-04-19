# Phase 8 — Audit-First Roadmap Closure — Design

**Fecha**: 2026-04-19
**Fase**: 8 de 8 del roadmap (cierre)
**Objetivo**: Validar que las Fases 0-7 entregaron lo que prometen y generar un backlog priorizado de deuda residual para Fases 9+. Script-driven, reproducible, sin refactors adicionales.

---

## 1. Contexto

Tras Fase 7, el flujo moderno está consolidado: `run_hunt.py` eliminado, 16 orphans removidos, parity matrix pulida, 138 tests verdes, 5 CLIs operativos. El roadmap original tenía Fase 8 = "Final review + splits diferidos + Eje 3 matching".

**Decisión del usuario (2026-04-19)**: scope B — audit-first, SIN splits. Los splits de los 4 archivos residuales (pipeline_gate 1,982 / hybrid_pipeline 1,332 / merge_invariants 1,280 / target_monitor 1,261) y el Eje 3 matching (benchmark.py + benchmark_score.py + ingest_rejections.py) se difieren al backlog de Fase 9+ sólo si el audit demuestra pain concreto.

**Depth del audit (B2)**: smoke audit + inventario de deuda residual. NO regression sweep (B3 rechazado por dependencia de bounty activo).

**Enfoque (1)**: script-driven reutilizable. Deja infraestructura permanente: `audit-agents/phase_8_audit.py` puede re-ejecutarse en Fases 9+ para confirmar que nuevo trabajo no introduce regresión.

---

## 2. Decisiones tomadas en brainstorming

| # | Decisión | Opción elegida |
|---|---|---|
| Q1 | Scope Phase 8 | **B**: audit-first. Sin splits, sin Eje 3. |
| Q2 | Depth del audit | **B2**: smoke + debt inventory. Sin regression sweep (B3). |
| Q3 | Enfoque | **1**: script-driven reutilizable (`phase_8_audit.py`). |
| Q4 | Deliverables | JSON + Markdown report; 1 commit por check implementado. |
| Q5 | Out-of-scope fixes | Trivial stale refs (≤2): fix inline; resto → backlog. |

---

## 3. Arquitectura

```
audit-agents/phase_8_audit.py
   │
   ├── load_parity_matrix(path) → dict
   ├── checks/                          # 7 funciones puras → CheckResult
   │   ├── check_test_suite(*, root)
   │   ├── check_clis(*, root)
   │   ├── check_parity_matrix(*, root, matrix)
   │   ├── check_docs_sync(*, root, removed_modules)
   │   ├── check_size_inventory(*, root)
   │   ├── check_dead_code_residual(*, root)
   │   └── check_shim_status(*, root)
   │
   ├── render_json(results) → writes audit-agents/audit_report.json
   ├── render_markdown(results) → writes docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
   └── main(argv)                       # CLI: --json-only / --md-only / --check NAME / --fail-on LEVEL
```

### Modelo de datos

```python
@dataclass
class DebtItem:
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    category: str                   # "size", "stale_ref", "shim", etc.
    description: str
    evidence: dict                  # file:line, counts, etc.

@dataclass
class CheckResult:
    name: str
    status: Literal["PASS", "FAIL", "WARN", "ERROR"]
    evidence: dict
    debt_items: list[DebtItem]
```

### Inyección de dependencias

Todo check recibe `root: Path` y parámetros específicos como kwargs. No hardcodea paths. Esto permite tests con `root=tmp_path` y fixtures controlados sin tocar el repo real.

---

## 4. Los 7 checks

### 4.1 `check_test_suite` — PASS/FAIL gate

- **Qué hace**: subprocess `python3 -m pytest audit-agents/tests/ -q` en el root.
- **Criterio PASS**: stdout contiene "138 passed" (valor configurable via parámetro `expected_count=138`).
- **Evidence**: output por suite parseado de stdout.
- **Debt**: si FAIL, lista tests que fallan.

### 4.2 `check_clis` — PASS/FAIL gate

- **Qué hace**: subprocess `python3 <cli> --help` para los 5 CLIs (`run_benchmark.py`, `plan_generator.py`, `pipeline_gate.py`, `scope_intake.py`, `sync_state.py`).
- **Criterio PASS**: los 5 exit 0.
- **Evidence**: exit codes + primera línea de help por CLI.
- **Debt**: CLIs que fallan con traceback completo.

### 4.3 `check_parity_matrix` — PASS/FAIL gate

- **Qué hace**: parsea `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` y verifica por cada entry:
  - `migration_decision: migrated` → `modern_location` apunta a archivo existente
  - `migration_decision: deprecated` → `legacy_location` NO corresponde a archivo existente (o `legacy_location` es una sección de un archivo también deprecado)
  - `migration_decision: added_phase_5/6` → `modern_location` existe
  - Aritmética: `summary.total_features == sum(by_decision.values())`
- **Criterio PASS**: todas las 46 entries verificadas + aritmética cuadra.
- **Evidence**: counts por status + lista de entries verificadas.
- **Debt**: entries que fallan (file:line en el YAML).

### 4.4 `check_docs_sync` — PASS/FAIL gate

- **Qué hace**: grep en `CLAUDE.md`, `WIKI.md`, `HUNT_TRACKER.md`, `README.md` (si existe) de los 16 módulos eliminados en Fases 4/7.
  - Lista: `run_hunt`, `bounty_monitor_config`, `results_tracker`, `test_stream_claude2`, `invariant_test_runner`, `quickstart`, `bounty_scanner`, `claude_classify`, `invariant-hunt`, `parameter_boundary_scanner`, `target_score`, `test_stream_claude`, `ai_invariant_generator`, `migrate_hunt_session`, `protocol_analyzer`, `compile_fixer`, `invariant_rag`.
- **Criterio PASS**: 0 hits en todos los docs.
- **Filtro**: refs dentro de bloques marcados "Archived/Phase 7 cleanup" se ignoran (opt-out explícito).
- **Debt**: refs con file:line.

### 4.5 `check_size_inventory` — WARN + inventory

- **Qué hace**: AST walk sobre `audit-agents/**/*.py`:
  - Archivos por LOC (excluyendo tests)
  - Funciones por LOC (non-empty, sin docstring-only)
- **Criterio**:
  - Archivo >2000 LOC → CRITICAL debt
  - Archivo >1500 LOC → HIGH debt
  - Archivo >800 LOC → MEDIUM debt
  - Función >100 LOC → MEDIUM debt
  - Función >200 LOC → HIGH debt
- **Status**: WARN si hay algún HIGH+, PASS en caso contrario. Nunca FAIL (es inventario).
- **Evidence**: tabla por archivo con LOC + top-5 funciones.

### 4.6 `check_dead_code_residual` — WARN + inventory

- **Qué hace**: sobre `audit-agents/**/*.py`:
  - AST walk de imports — detecta imports declarados nunca usados (heurístico: excluye `# noqa` y re-exports explícitos tipo `__all__`).
  - Grep de comentarios `TODO`, `FIXME`, `XXX`, `HACK` — lista file:line.
  - Import-cycle detector: graph de imports top-level, reporta ciclos.
- **Status**: WARN si import cycles o HIGH TODO density, PASS en caso contrario.
- **Debt**: LOW para imports/TODOs individuales; HIGH para cycles.

### 4.7 `check_shim_status` — informativo

- **Qué hace**: analiza `run_benchmark.py` y `plan_generator.py`:
  - LOC actual (esperado <50)
  - Re-exports listados (via AST)
  - Grep en `audit-agents/**/*.py` + `audit-agents/tests/**/*.py` de consumers por cada re-export
- **Status**: PASS si shims son <50 LOC y cada re-export tiene ≥1 consumer. WARN si algún re-export no tiene consumer (candidato a sunset).
- **Debt**: recomendación de sunset por re-export huérfano (severidad LOW).

---

## 5. Output y deliverables

### 5.1 JSON — `audit-agents/audit_report.json`

```json
{
  "generated_at": "2026-04-19T10:00:00Z",
  "summary": {
    "gates": {"PASS": 4, "FAIL": 0, "WARN": 0, "ERROR": 0},
    "inventory": {"PASS": 1, "WARN": 2},
    "debt_items": {"CRITICAL": 0, "HIGH": 4, "MEDIUM": 8, "LOW": 15}
  },
  "checks": [
    {
      "name": "check_test_suite",
      "status": "PASS",
      "evidence": {"phase_modern": 19, "phase_2a": 50, "phase_2b": 15, "phase_2c": 23, "phase_2d": 15, "phase_5": 13, "phase_6": 3, "total": 138},
      "debt_items": []
    }
  ]
}
```

### 5.2 Markdown — `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md`

Secciones obligatorias:
- Executive Summary (gates PASS/FAIL/WARN counts + debt totals)
- Per-check results (una subsección por check con evidence)
- Debt Backlog priorizado (CRITICAL → LOW)
- Roadmap closure (verdict: SUCCESSFUL/PARTIAL/FAILED + next steps)

### 5.3 CLI

```
python3 audit-agents/phase_8_audit.py                 # all checks + JSON + MD
python3 audit-agents/phase_8_audit.py --json-only     # JSON only (stdout)
python3 audit-agents/phase_8_audit.py --md-only       # MD only
python3 audit-agents/phase_8_audit.py --check NAME    # single check, stdout
python3 audit-agents/phase_8_audit.py --fail-on WARN  # non-zero exit if WARN
python3 audit-agents/phase_8_audit.py --root PATH     # override repo root (tests)
```

### 5.4 Exit codes

| Code | Condición |
|---|---|
| 0 | All PASS |
| 1 | Any FAIL |
| 2 | Any WARN (solo con `--fail-on WARN`) |
| 3 | Any ERROR (check reventó) |

---

## 6. Testing

`audit-agents/tests/phase_8/test_audit.py` — ~12-15 tests:

- **Per-check tests** (2 por check = 14 total):
  - Happy-path (PASS con fixture mínimo válido)
  - Failure-path (FAIL/WARN con fixture que trigger debt item)
- **Renderer tests** (2):
  - `test_render_json_schema`: valida keys requeridas
  - `test_render_markdown_structure`: valida secciones obligatorias
- **CLI tests** (2-3):
  - `test_cli_all_checks_pass_exit_0`
  - `test_cli_fail_on_warn_exit_2`
  - `test_cli_single_check_output`

Patrón: inyección via kwargs (`root=tmp_path`), `subprocess.run` mockeado, fixtures YAML/MD generados con `tmp_path.write_text()`. No toca repo real durante test.

**Target**: suite combinada 138 → ~150 passed.

---

## 7. Error handling

- Check individual que revienta → `CheckResult(status=ERROR, evidence={traceback: ...})`; los demás siguen ejecutándose.
- `check_parity_matrix` con YAML corrupto → ERROR limpio, no stack trace al usuario.
- `check_docs_sync` con docs faltantes → tratamiento como "0 matches" + WARN en evidence.
- `subprocess.run` timeout (60s por default) → ERROR.

---

## 8. Orden de ejecución

```
Task 0 — Baseline (138 passed, spec commit)
Task 1 — Scaffold script: CLI skeleton + CheckResult/DebtItem dataclasses + pytest scaffolding
Task 2 — check_test_suite + test
Task 3 — check_clis + test
Task 4 — check_parity_matrix + test
Task 5 — check_docs_sync + test
Task 6 — check_size_inventory + test
Task 7 — check_dead_code_residual + test
Task 8 — check_shim_status + test
Task 9 — render_json + render_markdown + tests
Task 10 — CLI wiring (--json-only/--md-only/--check/--fail-on) + tests
Task 11 — Ejecutar script; incluir outputs (JSON + MD) en commit; fix trivial stale refs (≤2) inline; resto al backlog
Task 12 — Roadmap closure: update memory + MEMORY.md; sección "Fase 8 — resumen al cerrar"
```

Cada Task 2-10: implementer → spec reviewer → code quality reviewer (subagent-driven).

Task 11 genera el **artefacto central** de Fase 8: el report ejecutado. Task 12 cierra el roadmap.

---

## 9. Criterios de éxito

- [ ] `phase_8_audit.py` existe y corre sin errores: `python3 audit-agents/phase_8_audit.py` exit 0
- [ ] Reporte generado: JSON + MD con los 7 checks ejecutados
- [ ] Test suite: 138 → ~150 passed, 0 regresiones
- [ ] Debt backlog concreto con severidades y evidence (no items genéricos como "refactor things")
- [ ] Roadmap verdict documentado: SUCCESSFUL / PARTIAL / FAILED con justificación
- [ ] Memory roadmap cerrado: Fase 8 COMPLETA, Fase 9+ = backlog dependiente

---

## 10. Out of scope (explícito)

- ❌ Splits de los 4 god-files residuales (`pipeline_gate.py`, `hybrid_pipeline.py`, `merge_invariants.py`, `target_monitor.py`) — diferidos al backlog. Si el audit los flaggea como HIGH/CRITICAL, se addressean en Fase 9+.
- ❌ Eje 3 matching consolidation (`benchmark.py` + `benchmark_score.py` + `ingest_rejections.py`) — mismo tratamiento.
- ❌ Regression sweep con benchmark real (opción B3) — dependía de bounty activo, rechazado.
- ❌ Auto-fix del debt encontrado — sólo report + backlog. Excepción: refs stale triviales (≤2) se fixan inline en Task 11.
- ❌ Tocar el parity matrix — el audit lo valida, no lo modifica.

---

## 11. Riesgos y mitigaciones

| # | Riesgo | Mitigación |
|---|---|---|
| 1 | `check_size_inventory` genera ruido (muchos archivos >800 LOC) → report noisy | Severidad CRITICAL/HIGH/MEDIUM modula prioridad; el debt backlog muestra sólo HIGH+ en Executive Summary |
| 2 | `check_dead_code_residual` false positives en imports (re-exports via `__all__`) | Heurístico excluye `__all__` + `# noqa`; test explícito |
| 3 | `check_docs_sync` flaggea refs en docs archivados | Opt-out por bloque marcado "Archived" |
| 4 | Subprocess en tests lentos | `subprocess.run` mockeado en tests unitarios; check real sólo en Task 11 integration |
| 5 | Script crece a >800 LOC (ironic) | Cada check es función <100 LOC en su propio módulo `checks/check_*.py` si conviene |

---

## 12. Herramientas

- `ast` (stdlib) — LOC counting, function detection, import analysis
- `yaml` (PyYAML) — parity matrix parsing
- `subprocess` — pytest + CLI invocations
- `pathlib` — path ops
- `dataclasses` — result types
- `argparse` — CLI

No dependencias externas nuevas.
