# System Health Check — Report

**Fecha**: 2026-04-17
**Metodología**: 8 sub-agentes `Explore` concurrentes, uno por sub-sistema. Ver [design spec](2026-04-17-system-health-check-design.md).
**Objetivo**: priorizar deep dives con evidencia, no intuición.

---

## TL;DR

- **1 sub-sistema 🔴 critical**: E (Benchmark & Feedback) — `run_benchmark.py` es un god-file de 4.051 LOC, 49 funciones, con 3 algoritmos de matching duplicados.
- **7 sub-sistemas 🟡 concerning**: todos tienen god-files, scripts huérfanos, tests ausentes o drift entre documentación y código.
- **0 sub-sistemas 🟢 healthy**.

### Patrones transversales (visibles en 4+ sub-sistemas)

1. **God-files**: 5 archivos >1.000 LOC cargan responsabilidades de varias capas.
   - `run_hunt.py` 4.270 LOC · `run_benchmark.py` 4.051 · `plan_generator.py` 3.110 · `pipeline_gate.py` 1.977 · `merge_invariants.py` 1.282
2. **Scripts y datos huérfanos** (generados pero no consumidos):
   - `crosschain_verify.py`, `verify_team_outputs.py` (B)
   - `invariant_rag.json` 5.8 MB con 3.661 invariantes (C)
   - `rejection_rules.yaml` con 4 rechazos (D)
   - Layers 2-4 de `detection_engine.py` (F)
3. **Spec drift** entre CLAUDE.md y código:
   - CLAUDE.md §6 promete 11 pasos de finding pipeline → código tiene 8 (D)
   - HUNT_TRACKER muestra 6 componentes completados → `current_hunt.json` tiene 1 (G)
   - Skills fantasmas en formato inconsistente (H)
4. **Tests ausentes o rotos** en 7 de 8 sub-sistemas.
5. **Estado mutable sin locks** — `gate_status.json`, `current_hunt.json` escritos sin atomic writes ni file locks (riesgo en benchmarks paralelos).

---

## Ranking priorizado (para deep dives)

| # | Sub-sistema | Estado | Impacto | Urgencia | Score |
|---|---|---|---|---|---|
| 1 | **E. Benchmark & Feedback** | 🔴 | alto (toca todo el pipeline) | alta (god-file 4K LOC) | **9/10** |
| 2 | **D. Finding Pipeline** | 🟡 | alto (resultado monetizable) | alta (spec drift + datos huérfanos) | **8/10** |
| 3 | **A. Hunt Orchestration** | 🟡 | alto (punto de entrada) | alta (race conditions, failures silenciosos) | **8/10** |
| 4 | **G. Knowledge & State** | 🟡 | medio (puede perder historial) | alta (divergencia activa) | **7/10** |
| 5 | **C. Fuzzing & Invariants** | 🟡 | alto (motor de verdad) | media (RAG huérfano, sin cache) | **6/10** |
| 6 | **F. Detection Prepass** | 🟡 | medio (pre-feed a hunters) | media (layers huérfanas) | **5/10** |
| 7 | **B. Hunters** | 🟡 | alto (output principal) | media (monolítico pero funciona) | **5/10** |
| 8 | **H. Skills & Harness** | 🟡 | bajo (no bloquea pipeline) | baja (inconsistencia cosmética) | **3/10** |

**Score** = impacto × urgencia, normalizado. Justificación del top 3 en sección siguiente.

---

## Top 10 riesgos globales

Ordenados por (impacto × probabilidad):

| # | Riesgo | Sub-sistema | Evidencia |
|---|---|---|---|
| 1 | **3 algoritmos de matching findings↔ground-truth desincronizados** | E | `benchmark.py`, `benchmark_score.py`, `ingest_rejections.py` reimplementan regex+keywords. Cambio de schema rompe los 3 |
| 2 | **`run_benchmark.py` god-file (4.051 LOC, 49 funciones)** | E | Cualquier cambio de phase afecta a todo el pipeline; sin separación de responsabilidades |
| 3 | **Finding pipeline tiene 8 gates, CLAUDE.md §6 promete 11** | D | Usuarios creen que Phase 1-5 fuzzing están en finding gate; viven en component pipeline. Confusión sobre "reportable" |
| 4 | **HUNT_TRACKER vs `current_hunt.json` divergen 11 días** | G | 5+ componentes históricos (Hyperlane, Morpho, Commerce, Smart Wallet, Wrapped Tokens) no están en source of truth |
| 5 | **`run_hunt.py` 64 subprocess calls con `check=False`** | A | Slither timeout, aderyn crash, graphify missing → agentes reciben contexto incompleto sin alerta |
| 6 | **`rejection_rules.yaml` es código muerto** | D | 4 rechazos históricos ingestados pero no consultados en RedTeam → puede recomendar REPORT de findings que violan R1 (trusted role) |
| 7 | **Gate state sin locks / atomic writes** | A, G | `pipeline_gate.py` y `current_hunt.json` escriben JSON sin locks; race condition en hunts paralelos del mismo protocol |
| 8 | **`invariant_rag.json` (5.8 MB, 3.661 invariantes) huérfano** | C | Generado por `invariant_rag.py --build`, nunca consumido por `ai_invariant_generator.py`. Desperdicio de conocimiento validado |
| 9 | **Detection prepass layers 2-4 generan findings pero no llegan a hunters** | F | `generate_prepass_yaml()` sólo procesa layer 1 (static) + layer 5 (exploit). Invariant/symbolic/hypothesis se pierden |
| 10 | **Paths duplicados en 4 archivos** | A | `STATE_FILE`, `HUNT_SESSION_DIR` redefinidos en `run_hunt.py`, `pipeline_gate.py`, `scope_intake.py`, `sync_state.py`. No hay `config.py` único |

---

## Mapa de dependencias observado

```
                    scope_intake.py
                           │
                           ▼
   ┌──────────── run_hunt.py ──────────────┐
   │                    │                  │
   │           ┌────────┼────────┐         │
   │           ▼        ▼        ▼         │
   │     detection_  plan_gen  hunters/    │
   │     engine.py   erator    *.md        │
   │         │          │         │        │
   │         └──────────┴────►YAMLs        │
   │                          │            │
   │                          ▼            │
   └───► pipeline_gate.py ◄── merge_       │
              │               invariants   │
              │               .py          │
              ▼                  │         │
         gate_status/            ▼         │
                             Properties.   │
                             sol + fuzz    │
                                 │         │
                                 ▼         │
                         finding_pipeline  │
                                 │         │
                                 ▼         │
                         report_finding.py │
                                 │         │
                                 ▼         │
                          Bounty Radar ◄───┘
                                 │
                                 └── sync_state.py ──► current_hunt.json
```

### Huérfanos (generados pero no conectados)

```
crosschain_verify.py        (caller invisible)
verify_team_outputs.py      (usado sólo por pipeline_gate, no por run_benchmark)
invariant_rag.json          (generado, nunca leído por ai_invariant_generator)
rejection_rules.yaml        (ingestado, nunca consultado por RedTeam gate)
detection_engine layers 2-4 (findings generados, no inyectados en prepass YAML)
```

---

## Detalle por sub-sistema

### A. Hunt Orchestration — 🟡 concerning

**Top archivos**: `run_hunt.py` 4.270 · `pipeline_gate.py` 1.977 · `hybrid_pipeline.py` 1.332 · `scope_intake.py` 427 · `sync_state.py` 184.

**Invariantes**:
- Pipeline secuencial, gates en orden estricto.
- 9+2 hunters completados antes de `merge`.
- `current_hunt.json` como única fuente de verdad.
- Contexto generado antes de hunters.

**Top riesgos**:
1. `run_hunt.py` como SPOF cognitivo (4.270 LOC, 139 funciones).
2. Gate state sin locks → race condition en paralelos.
3. 64 subprocess con `check=False` → fallos silenciosos.

**Deep dive**: **ALTA**. Extraer `config.py`, dividir `run_hunt.py` en prompt-generator + context-builder, atomic writes en gates.

### B. Hunters — 🟡 concerning

**Top archivos**: `run_hunt.py` 4.270 · `run_benchmark.py` 4.051 · `plan_generator.py` 3.110 · `scanners/vulnerability_patterns.py` 2.073 · `pipeline_gate.py` 1.977.

**Invariantes**:
- Prompts comparten estructura `Key Questions | Mandatory Analysis | Examples`.
- YAML schema estricto validado en 44+9 outputs reales.
- Quórum mínimo 7/9 hunters enforced.

**Top riesgos**:
1. `plan_generator.py` (3.110 LOC) es "máquina de estados oculta" — desincronización con `run_benchmark.py` sin test e2e.
2. DeepDive/CrossChain "bolted-on": 419 LOC de IFs anidados en `run_hunt.py` líneas 2607-2826.
3. `crosschain_verify.py` desacoplado — requiere Web3/RPC pero no hay invocación automática.

**Deep dive**: **MEDIA**. Refactor hunters/{Hunter}/{prompt,gate}.py para desacoplar del monolito.

### C. Fuzzing & Invariants — 🟡 concerning

**Top archivos**: `merge_invariants.py` 1.282 · `ai_invariant_generator.py` 1.035 · `halmos_property_generator.py` 541 · `invariant_test_runner.py` 460 · `parameter_boundary_scanner.py` 405.

**Invariantes**:
- Merge → Compile → Fix (forge build + comentar errores).
- Registry-driven matching (hunters → sufijos de archivo).
- Split mode default (PropertiesMath.sol, PropertiesAccess.sol).
- Universal 7 en toda Properties (canary, selfdestruct, reentrancy, supply, solvency, share_price, no-revert).

**Top riesgos**:
1. `compile_fixer` comenta properties rotas en lugar de rechazar la hipótesis — cero feedback al hunter.
2. `invariant_rag.json` (5.8 MB, 3.661 invariantes) huérfano.
3. No hay test e2e de fuzzing (Properties pueden romperse half-way sin alerta).

**Deep dive**: **MEDIA-ALTA**. Dividir `merge_invariants.py` en yaml_validator + sol_codegen + compile_loop. Integrar RAG como cache en `ai_invariant_generator.py`.

### D. Finding Pipeline — 🔴 **spec drift** · 🟡 código

**Top archivos**: `pipeline_gate.py` 1.977 · `report_finding.py` 686 · `submit_finding.py` 568 · `add_finding.py` 477 · `finding_pipeline.py` ~200.

**Invariantes** (actuales, no las del spec):
- 8 gates secuenciales: poc → escalation → variant → redteam → verify → report → submit → reportable.
- RedTeam/Escalation/Variant son **skills**, no scripts Python.
- `report_finding` ≠ `submit_finding` (el primero registra en Bounty Radar, el segundo actualiza status post-reporte).

**Top riesgos**:
1. **Spec drift crítico** CLAUDE.md §6 (11 pasos) vs código (8 gates). Phase 1-5 fuzzing están en component pipeline, NO en finding gate.
2. `rejection_rules.yaml` muerto → RedTeam puede recomendar REPORT violando R1.
3. `report_finding.py` + `submit_finding.py` duplican HTTP + payout estimate + category mapping.

**Deep dive**: **ALTA**. Reconciliar CLAUDE.md §6 con código. Integrar `rejection_rules` como pre-gate en RedTeam. Fusionar `report_finding` + `submit_finding`.

### E. Benchmark & Feedback — 🔴 critical

**Top archivos**: `run_benchmark.py` **4.051 LOC / 49 funciones** · `benchmark.py` 1.021 · `ingest_rejections.py` 553 · `apply_feedback.py` 530 · `benchmark_score.py` 321.

**Invariantes**:
- Ground truth completo (2 benchmarks validados: Yieldoor, LayerZero-Stellar).
- Feedback loop cerrado (rejection_rules.yaml actualizado 2026-03-31).
- Plan-driven execution vía `run-benchmark-agent` skill.

**Top riesgos**:
1. **God-file** `run_benchmark.py` — 13 builders de prompts + LLM/CLI + subprocess + threading + 5 phases en un archivo.
2. **Matching triplicado** — `benchmark.py`, `benchmark_score.py`, `ingest_rejections.py` con regex+keywords desincronizados.
3. Sin replay/rollback → si scoring regresiona, no se puede reproducir score histórico.

**Deep dive**: **ALTA · PRIORIDAD #1**. Extraer 5 builders a módulo. Consolidar matching findings↔ground-truth en clase única. Añadir tests de regresión.

### F. Detection Prepass — 🟡 concerning

**Top archivos**: `detection_engine.py` 1.123 · `protocol_analyzer.py` 927 · `parameter_boundary_scanner.py` 405 · `symmetric_analyzer.py` 358 · `clippy_to_prepass.py` 315.

**Invariantes**:
- Prepass YAML consumido por `run_hunt.py` L~725.
- Slither es fuente de verdad estructural.
- 5 capas declaradas (static, invariant, symbolic, hypothesis, exploit).

**Top riesgos**:
1. **Gap prepass↔hunter context** — layers 2-4 no entran a YAML final. False negatives.
2. Slither/Aderyn como subprocess sin captura robusta; fallback regex silencioso.
3. `parameter_boundary_scanner` + `symmetric_analyzer` desconectados del prepass — merge manual.

**Deep dive**: **ALTA**. Validar que layers 2-4 llegan a hunters. Mapear cobertura del invariant registry vs CVEs reales.

### G. Knowledge & State — 🟡 concerning

**Fuentes de verdad actuales**:
- `~/.claude/MEMORY/STATE/current_hunt.json` (hunt activo, 2 findings LayerZero).
- `HUNT_TRACKER.md` (narrativo, modificado 2026-04-06).
- `hunt_session/gate_status/*.json` (227 archivos, fragmentado).
- `hunt_session/findings_all.json` (174 KB, 453 hipótesis pre-RedTeam).
- `hunt_session/results/*.json` (15 archivos).

**Top riesgos**:
1. **Divergencia activa** HUNT_TRACKER (6 componentes) vs `current_hunt.json` (1).
2. 61 reports en `reports/` sin mapping claro a `current_hunt.findings`.
3. 17 MD en `knowledge/` deprecados pero aún consultables por `/wiki-query` → riesgo de contexto obsoleto a hunters nuevos.

**Deep dive**: **ALTA**. Consolidar histórico HUNT_TRACKER → current_hunt. Auto-sync Radar submissions. TTL en knowledge/.

### H. Skills & Harness — 🟡 concerning

**Inventario**:
- 15 skills globales en `~/.claude/skills/`.
- 14 web3-* skills en `audit-agents/.claude/skills/`.
- 0 overlap entre ambos.

**Hooks activos**: SessionStart (load-context.sh) · SessionEnd (work-completion + integrity-check) · PreToolUse Bash (rtk-rewrite.sh).

**Top riesgos**:
1. Pipeline Python sin skill wrappers (`/detection-engine`, `/merge-invariants` no existen).
2. Formato inconsistente: `escalation-hunter`, `variant-hunt`, `report-writer` son `.md` standalone; otros skills son directorios.
3. 19 skills web3-* + wiki-* no trazables en CLAUDE.md → riesgo de dead code gradual.

**Deep dive**: **MEDIA**. Estandarizar formato SKILL.md. Sección en CLAUDE.md para skills web3-*.

---

## Recomendación para el próximo ciclo

**Empezar por E (Benchmark & Feedback)**. Razones:
1. Único 🔴 critical.
2. Impacta todos los demás sub-sistemas (orquesta hunt + finding pipeline completo).
3. El god-file (4.051 LOC) + matching triplicado son la deuda técnica más cara del proyecto.
4. Sin tests de regresión, cualquier cambio futuro en schema YAML rompe matching.

### Propuesta de ciclo para E

1. Brainstorming → spec del deep dive de E.
2. Plan de implementación (writing-plans skill).
3. Ejecución con checkpoints (executing-plans skill, una fase a la vez).
4. Al terminar E → re-evaluar ranking (algunos riesgos pueden haberse resuelto lateralmente).

### Alternativas (si prefieres otro orden)

- **D** si la urgencia es monetizar findings pendientes sin confusión de gates.
- **A** si estás a punto de arrancar un hunt nuevo (prevenir race conditions).
- **G** si vas a reinicializar sesión y riesgas perder historial pre-2026-04-06.

---

## Fuera de scope (no revisado)

- Performance / tiempos reales de ejecución (sólo LOC y estructura).
- Correctness funcional de los outputs (el agente de E dice "2 benchmarks validados" pero no verificamos que el scoring sea acertado).
- Seguridad del harness (credenciales en `.env`, permisos de hooks, etc.).
- Calidad de los findings generados (ese es otro tipo de revisión).

Todos estos pueden ser specs futuros.
