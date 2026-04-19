# Performance Review — Pipeline `run_component_pipeline`

**Fecha:** 2026-04-19
**Alcance:** Pasada 1 (static audit de `runner.py` y callers) + Pasada 2 (log mining de runs históricos).
**Goal:** Contestar dos preguntas: (a) ¿por qué va lento el sistema? (b) ¿qué se está haciendo que sobra?

---

## Executive summary

1. **El cuello de botella NO está en los hunters** (≈5% del tiempo en API-mode, ≈25% en sub-mode Sonnet). **PoC + verify + compile-fix + fuzz-refine dominan el 75-95%** del tiempo de componente.

2. **El principal sumidero medible son los `Claude killed: hard timeout`.** En `v6 Strategy` (287 min, ~2.9× mediana) se observaron >12 timeouts de 900s ≈ **63% del tiempo de componente perdido a timeouts**. Los dos generadores de timeouts son el compile-fix de 9 intentos (`runner.py:797-883`) y el PoC fix loop de 3 attempts (`poc_pipeline.py:282-326`).

3. **Dos wins de bajo esfuerzo, alto impacto:**
   - Eliminar la ronda 2 del fuzz-refine loop (`runner.py:1059-1193`): ahorra ~25 min/componente.
   - Early-exit cuando `prepass` no detecta nada (`runner.py:161-177`): ahorra ~40 min/componente "limpio" (protocolos ya auditados por ToB/OZ).

4. **Constraint: el sistema usa suscripción `claude -p` CLI, no API Anthropic SDK.** Eso descarta `cache_control: ephemeral` (sólo disponible en SDK). Las optimizaciones de tokens deben hacerse dentro del CLI: **reducir input enviado** (trim prompts, dedup de contexto en filesystem) y **consolidar calls** (batching). Savings realistas vía CLI: 20-40% input tokens vs 60-80% que daría el SDK, pero sin cambio de billing model.

5. **Mediana por componente: 100 min** (rango 69.6–316.3 min, N=12 runs con instrumentación completa). **Mediana PoC-confirm: ~75%** (findings que superan Phase 3 fork PoC).

---

## Datos empíricos (Pasada 2)

### Tiempos medidos en runs históricos

| Métrica | Valor | N | Nota |
|---|---|---|---|
| Mediana componente completo | **100.0 min** | 12 | rango 69.6–316.3 |
| Promedio componente | 146.4 min | 12 | sesgado por outliers |
| Mediana hunters (API-mode) | **4.8 min** | 13 | 12 paralelos |
| Mediana hunters (sub-mode Sonnet, parallel=6) | **46.9 min** | 4 | **~10× más lento** que API |
| % tiempo en hunters (API-mode) | **~5%** | — | baratos |
| % tiempo en PoC+verify+compile | **75-95%** | — | dominante |
| Mediana PoC-confirm rate | **~75%** | 14 | N confirmed / N candidates |

### Outliers confirmados por logs

| Componente | Duración | Causa principal |
|---|---|---|
| v6 Strategy | 287.7 min (2.9× mediana) | >12 timeouts de 900s en fase PoC individual |
| bench 23:50 Vault | 316.3 min (3.2× mediana) | sub-mode Sonnet + 17/17 PoCs confirmados (éxito pero lento) |
| v9 LendingPool vs v5 vs v6 | 69.6 / 86.7 / 126.4 min | Variación ~1.8× según #findings (80/64/88) y #timeouts |

### Gaps en los datos

Los 6 `time.time()` en `runner.py` solo producen 3 líneas útiles de log (`Hunters completed`, `PoC phase complete`, `Component COMPLETE`). No hay instrumentación granular en: prepass, chimera_builder, merge, compile, phase1 fuzz, verify step, ni gates del finding pipeline (escalation/redteam/variant). Pasada 3 (opcional) podría añadir ~15 timers con context manager `@timed_phase` si se necesita data más fina.

---

## Top 10 issues (priorizados por `severity × 1/effort`)

| # | Issue | Sev | Effort | Ahorro estimado | File:line |
|---|---|---|---|---|---|
| 1 | Ronda 2 de fuzz-refine casi siempre desperdicia | HIGH | S | ~25 min/componente | `runner.py:1059-1193` |
| 2 | Sin early-exit gate tras prepass vacío | MED | S | ~40 min/componente "limpio" | `runner.py:161-177` |
| 3 | Deep trace `-vvvv` truncado al final (95% descartado) | MED | S | 10-15 min | `runner.py:1077-1093` |
| 4 | Clean slate borra `out/` entero | MED | S | 1-3 min × varias veces | `runner.py:137-140` |
| 5 | Verify timeout 300s por finding | MED | S | 1-3 min/batch | `runner.py:1320-1354` |
| 6 | TargetFunctions enhance (Step 7.5) rompe y revierte | MED | S | 10-15 min | `runner.py:900-959` |
| 7 | Compile-fix de 9 intentos sin feedback diferencial | HIGH | M | 20-40 min worst-case | `runner.py:797-883` |
| 8 | PoC fix loop — worst case 67 min/finding | MED | M | 5+ h de long tail | `poc_pipeline.py:282-326` |
| 9 | 12 hunters reciben 90% del mismo prompt (brief ~15K chars × 12) | HIGH | M | 20-40% input tokens vía trim/batching CLI | `runner.py:428-452` |
| 10 | Input tokens no optimizados (source+libs enviados completos repetidos) | MED | M | 15-25% input tokens | `prompt_builders.py:31-111`, `llm_runners.py` |

---

## "Qué sobra" — trabajo superfluo identificado

Respuesta directa a la pregunta del usuario. Lista accionable, ordenada por valor.

### Obvio (Effort S, eliminar / restringir)

1. **Ronda 2 del fuzz-refine loop** (`runner.py:1059-1193`)
   - El comentario dice "replicates what I did manually" pero el manual convergía en 1 iteración.
   - Medusa (Phase 2, 15 min) ya explora secuencias multi-step.
   - Acción: borrar ronda 2 por defecto, dejar detrás de flag `--fuzz-refine`.

2. **Deep trace `-vvvv` con `-fuzz-runs 100`** (`runner.py:1077-1093`)
   - Genera 10-50 MB de traces; el código sólo conserva `[-5000:]`.
   - Acción: usar `-vvv` (sin opcodes) o paralelizar los 5 traces con ThreadPool.

3. **TargetFunctions enhance step** (`runner.py:900-959`)
   - LLM pide "ADD new" pero frecuentemente edita existentes → rompe compile → revierte con `git checkout` → perdidos 10-15 min.
   - Los hunters ya escriben handlers via merge.
   - Acción: eliminar, o escribir a `TargetFunctionsExtra.sol` separado.

4. **Clean `out/` entero** (`runner.py:137-140`)
   - `shutil.rmtree(out/)` fuerza rebuild fresco (30-120s) cada vez.
   - Acción: limpiar sólo `out/test/chimera/` o dejar a forge detectar cambios por hash.

5. **Dos bloques de "rescue DeepDive YAML"** (`runner.py:586-596` y `713-724`)
   - Mismo `subprocess.run(["find", ...])` duplicado por defensividad.
   - Acción: unificar en `_rescue_deepdive_yaml()`, o pasar absolute path en el prompt.

6. **Source code leído múltiples veces** (`runner.py:74, 181-189, 228-230, 244-251`)
   - `source_code`, `library_code`, `existing_tests`, `interfaces_code`, `foundry.toml` se re-leen para setup early-gen.
   - Acción: `_load_component_context()` helper una vez, dict a callers.

### Mediano (Effort M, refactor moderado)

7. **Compile-fix de 9 intentos sin feedback diferencial** (`runner.py:797-883`)
   - Cada intento reenvía `setup_context[:20000]` entero + lista de errores, pero no adjunta qué cambió el intento previo.
   - Los "tiers" (1-2, 3-5, 6-7, 8) son instrucciones verbales, no escalación real.
   - Acción: `max_retries=4`, detectar errores idénticos consecutivos (early-exit), enviar diff de cambios.

8. **PoC fix loop con timeout 900s × 3** (`poc_pipeline.py:282-326`)
   - Worst case por finding: 3 × (900s LLM + 450s forge) = 67 min.
   - 10 findings × 67 min / `parallel_poc=2` = **5.5 horas** de long tail.
   - Acción: cap total por finding a 20 min (envoltorio); attempts=2; usar `finding.counterexample_trace` directo como esqueleto en vez de regenerar desde cero.

9. **Tres mecanismos de dedup consecutivos** (`runner.py:1303, 1409, 1475`)
   - Step 10.1 estructural → Step 10.3 estructural (otra vez) → Step 10.6 LLM `is_same_bug` (180s × N siblings, acepta "SAME" por timeout → sesgo a descartar).
   - Acción: consolidar en una pasada estructural; LLM sólo para pares con delta de confidence grande.

10. **Medusa secuencial tras fuzz-refine** (`runner.py:1198-1220`)
    - Medusa 900s corre después del refine loop de Phase 1. Podrían correr en paralelo.
    - Acción: lanzar Medusa en background al inicio del refine loop; join antes de extract findings.

### Token reduction dentro de `claude -p` (Effort M, sin migrar a SDK)

**Constraint:** el sistema usa suscripción Claude (CLI subprocess), no API SDK. `cache_control: ephemeral` no está disponible. Alternativas realistas:

11. **Brief común de hunters sobredimensionado** (`prompt_builders.py:31-111`)
    - `build_hunter_brief` genera ~15K chars que se envían 12 veces idénticos. Cada hunter solo lee las secciones relevantes a su especialización.
    - Acción: generar briefs específicos por hunter (`build_hunter_brief(hunter_name)`) que incluyan sólo la methodology + hypothesis types relevantes. Savings: 40-60% chars en el brief.

12. **Source code enviado completo a cada call** (`runner.py:74, 181-189`)
    - El source se envía a setup early-gen, a los 12 hunters, a DeepDive, a merge, a compile-fix, a verify, a PoC gen. Con `source_code` de 10-20K chars, son ~150-300K tokens redundantes por componente.
    - Acción: enviar sólo las funciones relevantes al scope del call (slice por AST). Para verify/PoC, enviar sólo la función atacada + dependencias directas. Savings: 30-50% input tokens en calls downstream.

13. **Batching de verify** (`runner.py:1320-1354`)
    - Hoy: 1 LLM call por finding × N findings (10 paralelos).
    - Acción: 1 LLM call analiza 3-5 findings a la vez (prompt estructurado con separadores). Savings: 60-70% calls = 60-70% overhead de proceso + input repetido.

14. **Session reuse con `claude --session-id`** (exploración)
    - Investigar si `claude -p --session-id <uuid>` permite reusar contexto entre calls consecutivos (setup → hunters → merge). Si aplica, el source_code se envía una sola vez por sesión y los hunters referencian el contexto.
    - Acción: prototipar en `llm_runners.run_claude` con flag opcional `session_id`. Validar empíricamente si reduce tiempo de warmup.
    - **No confirmado que funcione** — requiere experimentación antes de invertir.

### No sobra (validado)

- `llm_runners.py`: watchdog + stream-json están correctamente implementados.
- `finding_pipeline.py`: parsing de verdicts y categorización R1-R5 limpia.
- Timeouts en finding pipeline (escalation/redteam/variant/report) son razonables (180-300s).
- `_CLAUDE_SEMAPHORE=24` es apropiado para tier 4.

---

## Recomendaciones priorizadas por ROI

### Quick wins (Effort S, este sprint)

Implementar en orden. Total esfuerzo estimado: ~1 día. Savings agregadas esperadas: **40-80 min/componente**.

1. Añadir gate `if len(top_signals)==0: return early_summary` tras prepass (Issue #2 / #10 del static audit)
2. Comentar/eliminar ronda 2 del fuzz-refine loop; flag `--fuzz-refine` para reactivar
3. Bajar deep trace a `-vvv` y paralelizar con ThreadPool(5)
4. Cambiar `shutil.rmtree(out/)` a `shutil.rmtree(out/test/chimera/)` selectivo
5. Eliminar/aislar Step 7.5 (TargetFunctions enhance)
6. Consolidar lecturas de source en `_load_component_context()`
7. Unificar los 2 `_rescue_deepdive_yaml` en helper

### Medium-effort (próximo sprint)

Total esfuerzo estimado: ~3-5 días. Savings: long-tail eliminado (5h → 1.5h peor caso).

8. Rewrite del compile-fix: max_retries=4, early-exit por errores idénticos, diff entre attempts
9. PoC fix loop: cap total 20 min/finding, attempts=2, usar counterexample directo como esqueleto
10. Dedup consolidado: una pasada estructural; LLM sólo para high-delta pairs
11. Medusa en paralelo con fuzz-refine round 1

### Token reduction (Effort M, cuando quick wins estén estables)

12. Briefs específicos por hunter (savings ~40-60% en el brief × 12)
13. Source code sliced por AST en calls downstream (savings ~30-50% en verify/PoC)
14. Batching de verify en grupos de 3-5 (savings ~60-70% calls)
15. Investigar `claude --session-id` para reuso de contexto entre calls relacionados (unvalidated)

**Nota:** migrar a SDK Anthropic con `cache_control` daría savings mayores (60-80%) pero queda fuera de alcance — constraint del usuario: seguir usando suscripción `claude -p`.

---

## Input para el split de `runner.py` (Phase 13 futuro)

Los issues encontrados sugieren fronteras naturales para el split:

```
runner.py (shim + run_component_pipeline)
  ↓
component_pipeline/
  phases/
    ├─ clean_slate.py      (Step -1, ~50 LOC)
    ├─ prepass_gate.py     (Step 1 + early-exit añadido, ~80 LOC)
    ├─ knowledge_base.py   (Step 1.6-1.8 load KB, ~90 LOC)
    ├─ chimera_setup.py    (Step 1.9, 5, 5a-5c setup generation, ~180 LOC)
    ├─ hunters.py          (Step 2, 12 paralelos + DeepDive, ~220 LOC)
    ├─ merge_compile.py    (Step 6, 6.5, 6.7, 7 + compile-fix, ~260 LOC)
    ├─ fuzz.py             (Step 8, 9, 9.5 sin ronda 2, ~180 LOC)
    ├─ findings.py         (Step 10, 10.1, 10.2 extract+dedup+verify, ~200 LOC)
    ├─ poc.py              (Step 10.5-10.7, ~220 LOC)
    └─ finding_pipeline.py (Step 11 wrapper, ~50 LOC)
  runner.py                (thin orchestrator, ~150 LOC con context dict compartido)
```

**Prerequisito antes del split:** aplicar quick wins #1-7 primero. Eliminar ronda 2 + TargetFunctions enhance + rescue duplicado **reduce el LOC actual de 1,608 a ~1,300** sin tocar arquitectura. El split resultante es más limpio (menos código accidental que preservar).

---

## Out of scope

- Benchmarks sintéticos nuevos (Pasada 3 opcional con instrumentación).
- Optimización de `pipeline_gate.py` (ya está split en Phase 9).
- Optimización de `merge_invariants.py` / `target_monitor.py` (ya split en Phases 11/12).
- **Migración a SDK Anthropic** — descartada por constraint del usuario (suscripción `claude -p` CLI, no API billing).

---

## Pasada 3 opcional (no incluida aquí)

Si hace falta data granular para confirmar estas hipótesis antes de implementar:

- Instrumentar con context manager `@timed_phase` cada step (~15 timers nuevos).
- Log al cierre: `Component X breakdown: prepass=Xs, chimera=Xs, merge=Xs, phase1=Xs, verify=Xs, poc=Xs`.
- Log agregado: `timeouts_total_sec = sum(timeout_s per killed call)` — mide el sumidero de timeouts directamente.
- Re-correr 1 componente representativo con y sin `--fast` para comparar.
- Esfuerzo: 30-60 min setup + duración del run.

No recomendado hoy porque los quick wins tienen valor claro sin medir con más precisión. Activar Pasada 3 sólo si al aplicar #1-7 no se observa el ahorro esperado.
