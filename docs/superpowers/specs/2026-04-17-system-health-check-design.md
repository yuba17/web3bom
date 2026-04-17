# System Health Check — Design Spec

**Fecha**: 2026-04-17
**Scope**: `/home/kali/Documents/Web3/` completo
**Objetivo**: diagnóstico superficial de los 8 sub-sistemas del proyecto para priorizar deep dives posteriores.

## Por qué un health check primero

El sistema tiene ~70 módulos Python en `audit-agents/`, múltiples pipelines (hunt, benchmark, finding), 14 hunters, skills custom, tracking en `hunt_session/`, conocimiento en Obsidian, y ~20 repos de protocolos forked. Los archivos más grandes superan los 150KB. Sin un mapa general, cualquier deep dive arriesga gastar contexto en un sub-sistema que no es el cuello de botella real.

## Sub-sistemas (8)

| # | Sub-sistema | Archivos clave |
|---|---|---|
| A | Orquestación del Hunt | `run_hunt.py`, `pipeline_gate.py`, `scope_intake.py` |
| B | Hunters | `prompts/hunters/*.md`, `plan_generator.py`, CrossChain, DeepDive |
| C | Fuzzing & Invariants | `ai_invariant_generator.py`, `merge_invariants.py`, `halmos_*`, `chimera-template/` |
| D | Finding Pipeline | `finding_pipeline.py`, `report_finding.py`, RedTeam/Escalation/Variant |
| E | Benchmark & Feedback | `run_benchmark.py`, `benchmark_score.py`, `apply_feedback.py`, `ingest_rejections.py` |
| F | Detection Prepass | `detection_engine.py`, `parameter_boundary_scanner.py`, `protocol_analyzer.py` |
| G | Knowledge & State | Obsidian wiki, `sync_state.py`, `hunt_session/`, `HUNT_TRACKER.md` |
| H | Skills & Harness | `.claude/skills/`, `audit-agents/.claude/skills/` |

## Metodología

Ocho agentes `Explore` concurrentes. Cada uno explora en profundidad su sub-sistema y devuelve un informe estructurado <400 palabras. Los informes se sintetizan en un reporte final con ranking.

### Razón de usar sub-agentes en paralelo

1. **Control de contexto del agente principal** — cada sub-agente parte con contexto limpio; sólo devuelve el resumen, no el código leído.
2. **Paralelismo** — 8 exploraciones concurrentes vs. secuencial.
3. **Independencia** — ningún sub-sistema requiere estado de otro para su health check superficial.

### Formato fijo del informe por agente

```
## Sub-sistema: [letra y nombre]

### Estado general: 🟢 healthy / 🟡 concerning / 🔴 critical

### Inventario
- Archivos clave (top 5 por LOC)
- Puntos de entrada (CLI / imports externos)
- Dependencias con otros sub-sistemas

### Invariantes del sistema (3-5)
- Qué DEBE ser verdad para que funcione

### Señales de deuda observables
- Archivos >1500 LOC
- Duplicación evidente
- Dead code / imports rotos
- Tests ausentes o rotos

### Top 3 riesgos
1. [riesgo] — [por qué importa]
2. ...
3. ...

### Recomendación de deep dive
Prioridad: alta/media/baja + justificación 1 línea
```

## Entregables

1. **Este spec** — `docs/superpowers/specs/2026-04-17-system-health-check-design.md`
2. **Reporte de salud** — `docs/superpowers/specs/2026-04-17-system-health-check-report.md` con:
   - 8 informes consolidados
   - Mapa de dependencias entre sub-sistemas
   - Top 10 riesgos globales (impacto × probabilidad)
   - Orden recomendado para deep dives

## Fuera de scope (para futuros specs)

- Deep dives individuales por sub-sistema
- Refactors / cambios de código
- Nuevos features
- Benchmarks de performance

El health check **no modifica código**. Sólo observa.

## Criterio de éxito

Al terminar:
- Puedo nombrar los 3 sub-sistemas de mayor riesgo con evidencia (no intuición).
- Tengo un ranking ordenado para el próximo spec (deep dive del #1).
- El usuario tiene visión global del sistema en una página.

## Siguientes pasos post-health-check

Sobre el top 1 del ranking: nuevo ciclo brainstorming → spec → plan → revisión. No se ejecuta nada antes de completar ese ciclo.
