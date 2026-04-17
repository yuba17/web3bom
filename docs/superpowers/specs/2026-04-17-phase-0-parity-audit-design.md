# Fase 0 — Auditoría de Paridad run_hunt.py ↔ Flujo Benchmark · Design Spec

**Fecha**: 2026-04-17
**Sub-proyecto**: Fase 0 del [optimization roadmap](2026-04-17-optimization-roadmap.md).
**Objetivo**: producir matriz machine-readable de paridad entre `run_hunt.py` (legacy) y el flujo moderno (`run_benchmark.py --mode agent` + `plan_generator.py` + skill `run-benchmark-agent`) que Fase 2 consume sin interpretación humana.

## Por qué existe esta fase

El health check (2026-04-17) identificó ~5 features únicas de `run_hunt.py` mediante un sub-agente de 30 min. Migrar sobre esa base arriesga dejar lógica en el aire. Fase 0 produce una auditoría exhaustiva que cubre:

1. Cada flag CLI de `run_hunt.py` con su comportamiento observable.
2. Cada script satélite invocado directamente por `run_hunt.py`.
3. Grafo completo de callers transitivos (`.py`, `.sh`, `.md`, hooks, skills, `settings.json`).
4. Diff de outputs generados (directorios, YAMLs, JSONs) entre ambos flujos.
5. Decisión de migración (migrate / deprecate / keep_standalone) por cada feature, con risk + effort.

## Granularidad

**Feature-level** (confirmado). Cada "cosa que run_hunt.py hace visible desde fuera" — flags CLI + artefactos generados + llamadas a satélites. Se espera 20-30 features. El grafo de callers captura rutas de uso real; lógica interna no visible desde fuera no necesita migrarse al flujo moderno.

## Scope

### Archivos principales bajo auditoría (legacy)

- `audit-agents/run_hunt.py`

### Scripts satélite (a confirmar via grep de subprocess.run, imports)

- `audit-agents/solodit_search.py`
- `audit-agents/apply_feedback.py`
- `audit-agents/scope_intake.py`
- `audit-agents/sync_state.py`
- Cualquier otro script ejecutado por run_hunt.py

### Archivos de referencia (flujo moderno)

- `audit-agents/run_benchmark.py`
- `audit-agents/plan_generator.py`
- `audit-agents/plan_schema.py`
- `audit-agents/.claude/skills/run-benchmark-agent/SKILL.md`
- `audit-agents/verify_team_outputs.py`

## Entregables

### 1. Matriz de paridad — `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

Schema:

```yaml
version: 1
generated: 2026-04-17
source: run_hunt.py + satélites
target: run_benchmark.py --mode agent + plan_generator.py + skill

features:
  - id: F001
    name: "<nombre humano corto>"
    source_file: "audit-agents/<file>.py"
    source_refs: ["--flag", "function_name()"]
    description: "Qué hace, visible desde fuera"
    satellite_deps: ["audit-agents/<satélite>.py"]
    outputs_generated:
      - "hunt_session/<path>"
    modern_equivalent:
      status: present | partial | missing
      location: "<file>:<function or phase>"
      evidence: "grep output o reference"
    migration_decision: migrate | deprecate | keep_standalone
    migration_target: "<dónde aterriza en el flujo moderno>"
    risk: low | medium | high
    effort: XS | S | M | L | XL
    notes: "..."

callers:
  run_hunt.py:
    direct_python: [{path, line, invocation}]
    shell_scripts: [{path, line}]
    skills: [{path, invocation}]
    docs: [{path, section}]
    hooks: [{path, event}]
  run_benchmark.py:
    ...  # mismo schema

satellites:
  <satélite.py>:
    invoked_by: [run_hunt.py | standalone | both]
    callers: [...]  # mismo schema
    modern_status: present | partial | missing
    migration_decision: ...

outputs_diff:
  run_hunt_only: ["hunt_session/fichas/", ...]
  benchmark_only: ["benchmarks/<proto>/bench_session/", ...]
  shared: ["hunt_session/hypotheses/"]

summary:
  total_features: N
  by_decision:
    migrate: N
    deprecate: N
    keep_standalone: N
  by_risk: {low: N, medium: N, high: N}
  by_effort: {XS: N, S: N, M: N, L: N, XL: N}
  ordered_migration_plan:
    - feature_id: F001
      reason: "low risk, high value"
      order: 1
    - feature_id: F007
      reason: "dependency of F012"
      order: 2
```

### 2. Resumen narrativo — `docs/superpowers/specs/2026-04-17-phase-0-parity-report.md`

Resumen humano <800 palabras con hallazgos clave, sorpresas, decisiones no obvias, y orden recomendado para Fase 2.

## Metodología

6 sub-agentes `Explore` concurrentes, cada uno con scope estrecho, devuelven YAML parcial. Yo consolido en la matriz final y añado campos de decisión.

### División de agentes

| ID | Agente | Entregable |
|---|---|---|
| **P1** | Auditor CLI de `run_hunt.py` | YAML: cada flag argparse con descripción, handler, side effects, outputs generados |
| **P2** | Auditor funciones públicas de `run_hunt.py` | YAML: funciones agrupadas por área (scope / hunters / gates / PoC / knowledge / state) con qué hacen |
| **P3** | Auditor flujo moderno | YAML: flags + fases + steps de `run_benchmark.py` + `plan_generator.py` + skill. Incluye `verify_team_outputs.py` |
| **P4** | Auditor scripts satélite | YAML: cada script invocado por run_hunt.py, su CLI, su salida, si hay equivalente moderno |
| **P5** | Auditor grafo de callers | YAML: callers transitivos de run_hunt.py y run_benchmark.py en `.py`, `.sh`, `.md`, skills, hooks, `settings.json` |
| **P6** | Auditor de outputs generados | YAML: directorios creados por cada flujo, formato de archivos, solapamiento vs exclusivos |

Cada agente recibe un prompt self-contained que define:
- Scope de archivos exactos.
- Schema exacto del YAML a devolver.
- Lista de preguntas específicas que debe responder.
- Restricción de ≤400 palabras de prosa; el cuerpo es el YAML.
- Instrucción: no modificar archivos, sólo observar.

### Síntesis (yo)

1. Consolidar los 6 YAMLs parciales en `parity-matrix.yaml`.
2. Para cada feature, añadir:
   - `migration_decision` según criterios (sección siguiente).
   - `risk` según impacto si migración falla.
   - `effort` según LOC a migrar + complejidad.
3. Calcular `ordered_migration_plan` por risk ascendente, effort ascendente, dependencias.
4. Escribir `parity-report.md` con narrativa.
5. Commit.

### Criterios de decisión por feature

| Evidencia | Decisión |
|---|---|
| `modern_equivalent.status == present` (igual o mejor) | **deprecate** (no migrar) |
| `modern_equivalent.status == partial` | **migrate** (completar) |
| `modern_equivalent.status == missing`, valor claro (usado en callers reales) | **migrate** |
| `modern_equivalent.status == missing`, sin callers reales | **deprecate** (eliminar sin reemplazar) |
| `modern_equivalent.status == missing`, valor dudoso (util independiente) | **keep_standalone** (script suelto, no integrar al flujo) |

## Criterio de éxito

- Matriz YAML con ≥20 features, cero `status: unknown`.
- Grafo de callers cubre `.py`, `.sh`, `.md`, hooks, skills, `settings.json`.
- Risk + effort asignados a cada feature.
- `ordered_migration_plan` producido, revisable por el usuario.
- Resumen narrativo <800 palabras en `parity-report.md`.
- Ambos archivos commiteados.

## Fuera de scope

- Migración (Fase 2).
- Escribir tests (Fase 1).
- Modificar código.
- Opinión sobre calidad interna del flujo moderno (ya validado en verificación previa).

## Riesgos de Fase 0 y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Sub-agente P5 pierde callers por limitaciones de grep | Grep explícito en el prompt por cada patrón (`subprocess.run.*run_hunt`, `import run_hunt`, etc.) |
| Matriz queda incompleta porque un agente no entiende su scope | Schema YAML estricto en cada prompt; validar que el output cumpla antes de consolidar |
| Decisiones `migrate vs deprecate` sesgadas a conservar todo | Regla explícita: sin callers reales + sin valor claro → deprecate, no keep_standalone |
| Features ocultas en runtime (p.ej. dispatch por string) | P2 busca explícitamente `getattr`, `globals()`, dispatch dinámico |

## Duración estimada

- Lanzar 6 agentes en paralelo: ~15 min.
- Consolidación + decisión + narrativa: ~20 min.
- Revisión del usuario: variable.

Total ejecución del diseño: ~35 min + review.

## Siguiente paso

Cuando este spec se apruebe, invoco `writing-plans` skill para generar el plan de ejecución (lanzar agentes → consolidar → validar → escribir entregables → commit). Después se ejecuta el plan.
