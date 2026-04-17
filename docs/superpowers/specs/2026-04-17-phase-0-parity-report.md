# Fase 0 — Parity Report: `run_hunt.py` ↔ Flujo Benchmark

**Fecha**: 2026-04-17 · **Input de Fase 2** (migración).

## TL;DR

- **30 features** identificadas (12 flags CLI + 6 satélites + 12 funciones de enriquecimiento/estado/outputs).
- **Distribución**: 14 migrate · 15 deprecate · 1 keep_standalone.
- **Effort agregado estimado**: 18 × XS + 7 × S + 5 × M. Nada L/XL. Fase 2 es mecánica, no de diseño.
- **Riesgo alto** sólo en 2 features (F006 `--complete` y F014 `apply_feedback`); ambas del mismo loop L8.
- **Sorpresa principal**: 3 satélites que enriquecen contexto (Solodit, symmetric_analyzer, deep_flatten) **no están en el moderno**; los hunters del benchmark corren con menos señal pre-prompt de la que teníamos.

## Hallazgos clave

**1. Gap silencioso de context enrichment.** El moderno importa `load_rejection_context`, `load_few_shot_examples` y `HUNTER_DOMAINS` desde `run_hunt.py` (F020/F021/F023), pero **no** `query_wiki_context` (F019), `load_briefings` tiered (F022), `generate_asset_flow_map` (F024), ni las salidas de `symmetric_analyzer.py` (F015) o `deep_flatten.py` (F016). Los hunters modernos probablemente rinden peor de lo que podrían por context deficit, aunque ningún test lo demuestra todavía.

**2. Feedback loop L8 roto en el moderno.** `apply_feedback.py` (F014) no aparece en `run_benchmark.py` ni `plan_generator.py`. Cada benchmark corre con briefings y wiki congelados desde el último hunt legacy. Este es el gap más crítico del reporte.

**3. Cross-component (Rule 0.5) parcialmente migrado.** `phase_cross_prompt` existe pero la detección de cadenas transitivas (A→B→C, F026) — una señal de 2º orden valiosa — no está verificada. `--complete` en legacy dispara este chequeo automáticamente; el moderno no.

**4. Outputs convergentes.** `hyp_*.yaml`, `*_prepass.yaml` y `<c>_harness_summary.json` son idénticos en schema. El moderno añade `execution_plan.json`, `checkpoint.json` y `step_outputs/` (sin equivalente legacy, y superiores). Legacy mantiene `hunt_session/fichas/` y `_context.md` pre-generados que el moderno no usa (decisión aceptable: briefs on-the-fly es limpio).

**5. Callers ligeros.** `run_hunt.py` tiene 8 callers totales (1 subprocess real en `scope_intake.py`, el resto son docs + 2 imports transitivos). `run_benchmark.py` tiene 13, dominados por imports desde `plan_generator.py` y la skill `run-benchmark-agent`. La deprecación de `run_hunt.py` afectará sólo a `scope_intake.py`, `setup.sh` y tres docs.

## Decisiones no obvias

- **F013 Solodit → migrate (revisable)**. Valor claro pero cubierto parcialmente por el Obsidian vault + rejection_rules. Si tras Fase 1 los smoke tests muestran recall sin Solodit, bajar a deprecate. Incluido como migrate por default para no perder señal.
- **F012 `--print-prompts` → keep_standalone**. Debug utility sin integración; no justifica migración ni deprecación.
- **F005 `--init-ficha` → deprecate**. La ficha persistente fue útil como artefacto humano, pero el moderno tiene `findings_all.json` + `hunter_performance.json` que cubren el tracking sin acumulación de estado stale.
- **F009 `--force` → migrate** pero con **flags específicos** (p.ej. `--force-regen-map`) en lugar de un escape global. Bypass de gates sin granularidad es peligroso.
- **F028 state management atómica → deprecate** pero con caveat: `sync_state.py` y `current_hunt.json` podrían seguir usándose fuera del pipeline. Verificar en Fase 4 antes de borrar el archivo.

## Top 10 del orden recomendado

1. F002 `--hunters subset` (XS) — CLI trivial.
2. F003 `--domain` override (XS) — escape para auto-detect.
3. F009 `--force` específico (S).
4. F019 wiki context query (S) — enriquece brief.
5. F022 briefings tiered (S) — context sizing.
6. F024 asset flow map (S) — señal regex compacta.
7. F015 symmetric_analyzer (S) — pre-phase.
8. F016 deep_flatten (S) — pre-phase selectivo.
9. F013 Solodit context (S) — revisar tras Fase 1.
10. F008 `--map-components` auto (M) — productividad.

F026 (transitive chain, M) → F007 (cross-component completo, M) → F014 (apply_feedback, M) → F006 (`--complete` integrado, M) cierran la lista.

## Riesgos para Fase 2

- **F014 apply_feedback** toca briefings + wiki compartidos. Sin snapshot tests (Fase 1), una migración buggy puede corromper conocimiento. Mitigación: correr en `--dry-run` antes de commitear outputs.
- **F006 `--complete`** depende de F014 y F026. Si se migra sin las dos, el comportamiento moderno diverge silenciosamente del legacy.
- **F008 auto-map** puede descubrir componentes que el usuario no quería auditar. Mitigación: flag `--auto-components` opt-in, no default.
- **Callers externos** (`scope_intake.py:408`, docs) deben actualizarse en Fase 4 antes de borrar `run_hunt.py`; de lo contrario se rompen comandos documentados.

## Input para Fase 1 (tests snapshot)

Priorizar capturar antes de tocar código:
1. Determinismo de `plan_generator.py` sobre yieldoor (execution_plan.json estructura).
2. Schema de `hyp_*.yaml` producidos por hunters (fichero por hunter).
3. `findings_all.json` tras benchmark completo.
4. Verificación de gates por `pipeline_gate.py --status`.
5. Golden para `detection_engine.py --prepass` (hash del YAML emitido).

Con estos snapshots, Fase 2 puede migrar las 14 features sin regresiones silenciosas.

---

**Artefactos**:
- `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` (machine-readable).
- `docs/superpowers/specs/phase-0-agent-outputs/P1-P6-*.yaml` (audit trail).
