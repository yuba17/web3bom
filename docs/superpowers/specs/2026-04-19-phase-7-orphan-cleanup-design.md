# Phase 7 — Orphan Cleanup + Parity Matrix Polish — Design

**Fecha**: 2026-04-19
**Fase**: 7 de 8 del roadmap
**Objetivo**: Eliminar código muerto detectado tras Fases 1-6 (Track A) y cerrar la deuda documental del parity matrix (Track B). Sin regresiones: 138 tests verdes en cada commit.

---

## 1. Contexto

Tras Fase 6 (split god-files), el flujo moderno quedó distribuido en 14 módulos nuevos bajo `benchmark/` + `plan/`. El pipeline legacy (`run_hunt.py`) fue deprecado formalmente en Fase 4. Este estado deja dos tipos de deuda:

**Track A — código muerto**: scan de los 61 módulos en `audit-agents/` muestra 11 con ≤2 hits en TODO el repo (contando `.py`, `.md`, `.sh`, `.yaml`/`.yml`) y 8 sospechosos con 3-5 hits. Candidatos iniciales:

| Tier | Módulos | Hits | Acción propuesta |
|---|---|---|---|
| 0 hits | `bounty_monitor_config`, `results_tracker`, `test_stream_claude2` | 0 | Eliminar directo |
| 1 hit | `invariant_test_runner`, `quickstart` | 1 | Verificar self-reference, eliminar |
| 2 hits | `bounty_scanner`, `claude_classify`, `invariant-hunt`, `parameter_boundary_scanner`, `target_score`, `test_stream_claude` | 2 | Verificar self-reference, eliminar |
| 3-5 hits | `ai_invariant_generator`, `migrate_hunt_session`, `crosschain_verify`, `protocol_analyzer`, `target_monitor`, `compile_fixer`, `hybrid_pipeline`, `invariant_rag` | 3-5 | Uno-a-uno: keep / delete |

**Track B — parity matrix**: el review de Task 16 (Fase 6) identificó 4 inconsistencias pre-existentes en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
1. Taxonomy drift: mezcla present/past tense (`migrate` vs `migrated`, `deprecate` vs `deprecated`).
2. `summary.by_decision` aritméticamente incorrecto (suma funcional → 46 solo porque dos off-by-ones se cancelan).
3. `legacy_location` ranges F033-F046 se solapan/contienen de forma implausible.
4. `by_risk` subtotals stale (no reflejan F033-F046).
5. F037, F038, F039, F042, F044 sin `notes` (inconsistente con siblings).

**Fuera de scope**:
- Split de archivos >800 LOC restantes (`pipeline_gate.py` 1,982 / `hybrid_pipeline.py` 1,332 / `merge_invariants.py` 1,280 / `target_monitor.py` 1,261) — reservado para Fase 7.5 o 8.
- Eje 3 (matching consolidation) — reservado para Fase 8.

---

## 2. Decisiones tomadas en brainstorming

| # | Decisión | Opción elegida |
|---|---|---|
| Q1 | Scope Phase 7 | **A+B**: orphans + parity matrix. C (splits) diferido |
| Q2 | Orphan strategy | Batch-delete los 11 fuertes (1 commit), then one-by-one los 8 sospechosos |
| Q3 | Parity fix para `legacy_location` | Drop line numbers, dejar `"run_benchmark.py (label)"`. Re-derivar desde git sería más caro |
| Q4 | Parity fix para `by_risk` | Eliminar el bloque (nadie lo consume). YAGNI |
| Q5 | Tests | Suite existente + smoke re-run tras cada commit. No tests nuevos (orphan cleanup no introduce features) |

---

## 3. Track A — Orphan cleanup design

### 3.1 Verificación por módulo

Para cada candidato, antes de eliminar verificar:
1. **Inbound imports** — `grep -rn "from <mod> import\|import <mod>\b" --include="*.py"` devuelve 0 en todo `/home/kali/Documents/Web3/`.
2. **Subprocess invocation** — `grep -rn "<mod>\.py" --include="*.py" --include="*.sh" --include="*.md"` devuelve 0 o solo self-references.
3. **CLI entry point** — chequeo manual: ¿es un CLI standalone que se invoca via `python3 <mod>.py` desde shell o skill? Si es así, **mantener** incluso con 0 hits.
4. **Referencias en docs** — `CLAUDE.md`, `HUNT_TRACKER.md`, skills (`.claude/skills/`) podrían mencionarlo.

**Regla de seguridad**: si verificación muestra cualquier hit fuera del propio archivo y de tests, NO eliminar y marcar como "alive".

### 3.2 Batch plan

- **Batch 1** (11 fuertes, 1 commit): eliminar los que pasen verificación. Esperado: 8-11 archivos removidos.
- **Batch 2** (8 sospechosos, commits separados o agrupados según verificación). Esperado: 0-5 archivos removidos.

Cada batch → `python3 -m pytest` combinado debe seguir en 138 passed.

### 3.3 Edge case: archivos con hyphen en nombre

`invariant-hunt.py` usa hyphen (no `_`), lo que impide `import invariant-hunt`. Solo puede invocarse como CLI (`python3 invariant-hunt.py`). Verificar via `rg "invariant-hunt"` directo.

### 3.4 Edge case: tests que mencionan módulos pero los mockean

Si un test tiene `patch("<mod>.foo")` eso cuenta como inbound uso REAL. Chequeo explícito en grep.

---

## 4. Track B — Parity matrix cleanup design

### 4.1 Fix #1: taxonomy drift (tense flip)

```yaml
# Replace-all en docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml:
migration_decision: migrate     →  migration_decision: migrated
migration_decision: deprecate   →  migration_decision: deprecated
```

Efecto: 9 entries flipped `migrate→migrated`, 13 entries flipped `deprecate→deprecated`.

### 4.2 Fix #2: summary re-tally

Tras flip, las cuentas reales son:
- `migrated`: 16 (7 pre-existentes + 9 flipped)
- `deprecated`: 14 (1 pre-existente + 13 flipped)
- `keep_standalone`: 0
- `added_phase_5`: 2
- `added_phase_6`: 14
- **total**: 46 ✓

Actualizar el bloque `summary.by_decision` con los nuevos valores.

### 4.3 Fix #3: `legacy_location` ranges overlapping

**Decisión**: drop line numbers. Cambiar:
```yaml
legacy_location: "run_benchmark.py:541-1087"
```
a:
```yaml
legacy_location: "run_benchmark.py (prompt builders section)"
```

Aplica solo a F033-F046 (los 14 añadidos en Fase 6). Las entries F001-F032 no se tocan (tienen sus propios ranges pre-Phase-6, fuera de scope).

### 4.4 Fix #4: eliminar `by_risk`

Si existe `summary.by_risk: { low: X, medium: Y, ... }` y nadie lo consume, eliminar el sub-block entero. Grep preventivo: `rg "by_risk" --include="*.py" --include="*.yaml" --include="*.md"` para confirmar 0 consumidores.

### 4.5 Fix #5: añadir `notes` a entries huérfanas

F037, F038, F039, F042, F044 — añadir one-liner descriptive `notes: "..."`. Contenido sugerido:
- F037 (finding_pipeline): "Extracts findings from DeepDive YAML; runs full finding pipeline"
- F038 (cross_component): "Cross-component pair analysis (RULE #0.5)"
- F039 (worktree_helpers): "Git worktree lifecycle + resolver helpers"
- F042 (generator): "Execution plan DAG generator (generate_plan + _add_*_steps)"
- F044 (prompts_rust): "Rust fuzz scaffold / harness prompts"

---

## 5. Orden de ejecución

```
Task 0 — Baseline (138 passed, spec commit)
Task 1 — Track A Batch 1: 11 orphans fuertes, verify + delete in 1 commit
Task 2 — Track A Batch 2: 8 sospechosos, one-by-one verification + delete where appropriate
Task 3 — Track B Fix #1-#5 en un commit (docs-only)
Task 4 — Update memory roadmap: Fase 7 COMPLETA → Fase 8 NEXT
```

Cada task: subagent-driven (implementer → spec reviewer → code quality reviewer).

---

## 6. Criterios de éxito

- [ ] ≥8 orphan files removidos (Batch 1)
- [ ] 0 regresiones: suite combinada sigue en 138 passed
- [ ] Parity matrix: taxonomy consistente (todos past-tense), summary correcto, `legacy_location` sin ranges solapados, `by_risk` eliminado, notes completos
- [ ] Memory roadmap actualizado
- [ ] 5 CLIs (`run_benchmark`, `plan_generator`, `pipeline_gate`, `scope_intake`, `sync_state`) siguen respondiendo a `--help`

---

## 7. Edge cases y riesgos

| # | Riesgo | Mitigación |
|---|---|---|
| 1 | Módulo aparenta orphan pero es invocado via `subprocess.run(["python3", "<mod>.py", ...])` | Verification step #2 grepea `<mod>.py` literal en todo el repo |
| 2 | Módulo invocado desde skill YAML/MD (`.claude/skills/**`) | Verification step #4 incluye skills dir |
| 3 | Tests mockean pero módulo ya no existe → test rompe | Suite se corre tras cada batch. Si falla, revert commit |
| 4 | Otro módulo tiene docstring/comment que menciona orphan sin usarlo | Grep textual puede producir false positives — verificación manual del match |
| 5 | `invariant-hunt.py` (hyphen) invocado desde shell script | Grep en `.sh` + self-check manual |
| 6 | Parity matrix consumido por script de reporte | Grep `parity-matrix` en todo el repo pre-cambio |

---

## 8. Herramientas

- `rtk grep` / `Grep tool` para verificación
- `git mv` / `git rm` para deletions (preserve history)
- Edit / Write para parity matrix
- Subagent-driven-development skill para el loop de implementación
