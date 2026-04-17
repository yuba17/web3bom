# System Optimization Roadmap — Meta-Spec

**Fecha**: 2026-04-17
**Objetivo**: optimizar y mejorar el sistema `/home/kali/Documents/Web3/` al máximo posible.
**Premisa confirmada (con evidencia)**: el flujo `run_benchmark.py --mode agent` + skill `run-benchmark-agent` + Agent Teams es **el flujo canónico y moderno**. `run_hunt.py` es legacy y debe migrarse/deprecarse, no refactorizarse.
**Libertad**: total. No hay hunts activos, breaking changes permitidos.
**Aprobado**: sí, usuario confirmó 2026-04-17.

---

## Evidencia del veredicto benchmark > run_hunt

**Actividad git (último día de commits)**:
- `run_benchmark.py` → 2026-04-15 con 5+ commits de features propias: PoC retry loop, parallel batching, `--poc-timeout`, graceful hunter failure, session isolation.
- `run_hunt.py` → último commit propio mucho más antiguo; sólo recibió v10 upgrade transversal.
- `plan_generator.py` → creado post-benchmark; 4 commits enfocados en worktree isolation + artifact detection.

**Features únicas del flujo moderno** (inexistentes en legacy):
1. Plan-based execution (`execution_plan.json`) — auditable, resumible, checkpointable.
2. `--mode agent` (Claude Code Agent tool) y `--mode sub` (subscripción).
3. Agent Teams con worktree isolation por grupo de componentes.
4. PoC retry loop (3 intentos, timeout escalating).
5. Parallel PoC batching (Capa 2+3 simultáneas).
6. Graceful hunter failure (7/9 mínimo).
7. Session dir isolation por protocolo.
8. Verificación post-team (`verify_team_outputs.py`) contra trust-agents-reports.

**Features únicas de `run_hunt.py`** (NO son capacidades técnicas, son integraciones sueltas migrables):
- Solodit search (`solodit_search.py`)
- Apply feedback (`apply_feedback.py` invocación)
- Ficha management (`--init-ficha`)
- Component_map auto-generation (`--map-components`)
- Pipeline gate wrappers (`--complete`, `--force`)

**Benchmark outputs validados**: yieldoor 94.1% recall (16/17), 100% HIGH (7/7), 90% MEDIUM (9/10).

---

## Roadmap — 8 fases secuenciales

Cada fase es un **sub-proyecto independiente** con su propio ciclo brainstorming → spec → plan → execute → verify. Entre fases, el usuario revisa y aprueba.

### Fase 0 — Auditoría de paridad exhaustiva

**Objetivo**: producir una matriz completa de features `run_hunt.py` vs flujo moderno, con dependencias transitivas y plan ordenado de qué migrar, deprecar sin migrar, o mantener.

**Por qué primero**: la auditoría superficial del health check identificó ~5 features únicas, pero el sub-agente recorrió el código en 30 min. Migrar sin un mapa exhaustivo arriesga dejar funcionalidad en el aire.

**Entregable**:
- Matriz TSV/YAML con cada feature de `run_hunt.py` × su estado en el flujo moderno (tiene | no tiene | parcial).
- Grafo de callers transitivos (qué scripts, hooks, shell scripts, skills invocan cada flag).
- Lista ordenada: features a migrar, features a deprecar-sin-migrar, features a mantener como scripts independientes.
- Riesgos identificados.

**Fuera de scope**: migración propiamente dicha (eso es Fase 2).

### Fase 1 — Snapshot tests del flujo moderno

**Objetivo**: capturar comportamiento actual del flujo benchmark con tests automatizados ANTES de tocar nada, para detectar regresiones en fases 2-8.

**Por qué segunda**: cualquier refactor/migración sin snapshot arriesga regresiones silenciosas en LLM outputs, scoring, generación de planes.

**Entregable**:
- Tests smoke de CLI (`run_benchmark.py --help`, cada `--phase X` genera output válido).
- Schema validation de `execution_plan.json`, `checkpoint.json`, YAMLs de hunters, `benchmark_score.json`.
- Golden outputs de `plan_generator.py` sobre un protocolo de referencia (yieldoor/LayerZero) — comparación determinista aislando LLM-generated content.
- Smoke test de la skill `run-benchmark-agent` (estructura del plan, no ejecución completa).

**Fuera de scope**: tests unitarios internos (eso viene con el refactor de cada sub-sistema).

### Fase 2 — Migrar features únicas de `run_hunt.py` al flujo moderno

**Objetivo**: portar las N features identificadas en Fase 0 como steps del plan, hooks pre/post, o scripts invocados desde el plan.

**Posibles candidatas** (confirmar en Fase 0):
- Solodit search → step `phase_solodit_search_prompt()` en `plan_generator.py` o hook pre-hunter.
- Apply feedback → step post-componente (hook en checkpoint del plan).
- Component_map auto → ya existe en `plan_generator`, verificar paridad.
- Ficha management → YAMLs canónicos en `hunt_session/hypotheses/` ya cubren; decidir si se mantiene.
- Pipeline gates `--complete/--force` → wrapper fino en la skill o CLI del benchmark.

**Entregable**: cada feature migrada tiene su prueba en Fase 1 actualizada.

**Fuera de scope**: eliminar `run_hunt.py` (eso es Fase 4).

### Fase 3 — Reconciliar CLAUDE.md con flujo moderno

**Objetivo**: eliminar toda referencia legacy a `run_hunt.py` en CLAUDE.md, documentar el flujo agent teams como el único válido, corregir spec drift del finding pipeline (8 gates vs 11 prometidos).

**Entregable**:
- CLAUDE.md sección 3 (Modo Autónomo) actualizada: comandos legacy → comandos modernos.
- Sección 5 (Pipeline de Componente — Gates) alineada con steps del plan.
- Sección 6 (Finding Pipeline) alineada con gates reales (8), no los 11 del spec viejo.
- Sección 16 (Benchmark default) actualizada si cambió la interfaz.
- Diff revisado y commiteado con justificaciones por bloque.

**Fuera de scope**: skill directory changes (eso es Fase 7 junto con huérfanos de harness).

### Fase 4 — Deprecar `run_hunt.py`

**Objetivo**: convertir `run_hunt.py` en stub que redirige a `run_benchmark.py` con mensaje deprecation; tras grace period (p.ej. una sesión de uso), eliminar.

**Entregable**:
- Stub con mensaje claro (`run_hunt.py ha sido reemplazado por run_benchmark.py --mode agent`).
- Referencias externas (setup.sh, scope_intake.py, hooks, skills) actualizadas.
- Después de validación → eliminación física del archivo + commit con justificación.

**Fuera de scope**: limpieza de directorios de estado generados por run_hunt (eso es Fase 6).

### Fase 5 — Infra compartida (CONDICIONAL)

**Objetivo**: extraer duplicación REAL del flujo moderno, no asumida. Solo si Fase 1 detecta duplicación:
- `config.py` para paths/constants duplicados.
- `state_manager.py` con atomic writes + file locks (si current_hunt.json o gate_status.json viven en paralelos).
- Clase única de matching findings↔ground-truth (si `benchmark.py`, `benchmark_score.py`, `ingest_rejections.py` siguen duplicando post-migración).

**Por qué condicional**: el health check asumió duplicación a partir de patrones superficiales. Algunas pueden ser falsos positivos post-migración de `run_hunt.py`.

**Entregable**: solo si hay duplicación real confirmada.

### Fase 6 — Refactor polish del flujo moderno

**Objetivo**: dividir los dos god-files del flujo moderno en módulos cohesivos, con el respaldo de los tests de Fase 1.

- `run_benchmark.py` 4.051 LOC → `benchmark/{cli, phases, plan_builder, scoring, runner}.py`.
- `plan_generator.py` 3.110 LOC → `plan/{generator, phases, dynamic_steps, validation}.py`.

**Por qué al final**: no urgente, el flujo funciona. Refactor sin rompimiento es posible gracias a Fase 1.

**Entregable**: mismo comportamiento externo, código más navegable.

### Fase 7 — Conectar o eliminar huérfanos + resto 🟡

- `rejection_rules.yaml` → consumido como pre-gate en RedTeam.
- `invariant_rag.json` (5.8 MB) → cache en `ai_invariant_generator.py` o eliminado.
- Layers 2-4 de `detection_engine.py` → inyectar findings en prepass YAML consumido por hunters.
- Knowledge/ stale → TTL / marcado deprecated de 17 MDs obsoletos.
- Skills H → estandarizar formato (directorio vs .md), documentar web3-* en CLAUDE.md.
- Finding pipeline D → fusionar `report_finding.py` + `submit_finding.py` si sigue duplicado post-Fase 2.

**Entregable**: cada huérfano conectado O eliminado con justificación.

### Fase 8 — Revisión final y documentación

**Objetivo**: verificar que todo el sistema está mejor y documentarlo.

- Re-ejecutar health check de 8 sub-agentes y comparar con el de 2026-04-17.
- Si hay mejoras medibles, escribir un resumen ejecutivo.
- Actualizar CLAUDE.md y memoria con el estado final.

---

## Orden, dependencias y checkpoints

```
Fase 0 (auditoría) → Fase 1 (tests) → Fase 2 (migración)
                                          ↓
Fase 3 (CLAUDE.md) ← ← ← ← ← ← ← ← ← ← ←  ↓
   ↓
Fase 4 (deprecar run_hunt.py)
   ↓
Fase 5 (infra compartida, condicional)
   ↓
Fase 6 (refactor polish)
   ↓
Fase 7 (huérfanos + 🟡)
   ↓
Fase 8 (revisión final)
```

Entre cada fase: revisión del usuario, commit(s), push opcional. No se arranca la siguiente sin aprobación.

---

## Criterios de éxito globales

Al terminar las 8 fases:

1. **Un solo flujo canónico** — `run_hunt.py` eliminado.
2. **CLAUDE.md coherente** — cero referencias al flujo legacy, cero spec drift.
3. **Tests de regresión** — snapshot de plan generation + scoring + gates.
4. **Cero huérfanos** — cada script/YAML/JSON es consumido o eliminado.
5. **God-files divididos** — `run_benchmark.py` y `plan_generator.py` repartidos en módulos <500 LOC.
6. **Health check re-run** — todos los sub-sistemas 🟢 healthy, o justificación documentada de los 🟡 restantes.

---

## Fuera de scope del roadmap (para eventual v2)

- Performance / latencia de pipelines (no medido en health check).
- Seguridad del harness (permisos de hooks, credenciales en `.env`).
- Calidad intrínseca de los findings generados (es otro tipo de revisión).
- Nuevos features (hunters adicionales, integraciones).

---

## Próximo paso

Entrar en **brainstorming de Fase 0** en esta misma conversación. Producto: `docs/superpowers/specs/2026-04-17-phase-0-parity-audit-design.md`.
