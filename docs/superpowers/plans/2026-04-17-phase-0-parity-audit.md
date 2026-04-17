# Fase 0 — Auditoría Paridad run_hunt ↔ Benchmark · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** producir matriz YAML de paridad entre `run_hunt.py` (legacy) y flujo benchmark (moderno), con decisiones de migración por feature, como input de Fase 2.

**Architecture:** lanzar 6 sub-agentes `Explore` concurrentes con scopes estrechos, recibir YAML parciales, consolidar localmente, enriquecer con decisiones, validar, escribir dos entregables y commitear. Cero modificación de código fuente.

**Tech Stack:** Python 3 (para validación YAML), `pyyaml`, Claude Code Agent tool, git. Sin dependencias nuevas.

---

## File Structure

### Creados

- `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` — entregable machine-readable (consumido por Fase 2).
- `docs/superpowers/specs/2026-04-17-phase-0-parity-report.md` — narrativa humana <800 palabras.
- `docs/superpowers/specs/phase-0-agent-outputs/` — directorio intermedio con los 6 YAML parciales de los agentes (archivo por agente, commiteados como audit trail).

### Modificados

Ninguno. La auditoría no toca código fuente.

---

## Task 1: Preparar directorio y baseline de validación

**Files:**
- Create: `docs/superpowers/specs/phase-0-agent-outputs/.gitkeep`

- [ ] **Step 1.1: Crear directorio intermedio**

```bash
mkdir -p /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs
touch /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/.gitkeep
```

Expected: directorio creado, `.gitkeep` dentro.

- [ ] **Step 1.2: Verificar herramientas disponibles**

```bash
python3 -c "import yaml; print(yaml.__version__)"
```

Expected: versión impresa (cualquier >=5.0). Si falla: `pip install pyyaml` (en venv del proyecto).

- [ ] **Step 1.3: Commit del scaffold**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/phase-0-agent-outputs/.gitkeep
rtk git commit -m "chore: scaffold Fase 0 agent outputs directory"
```

Expected: commit creado.

---

## Task 2: Lanzar los 6 agentes Explore en paralelo

**Files:**
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P1-cli-legacy.yaml`
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P2-functions-legacy.yaml`
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P3-modern-flow.yaml`
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P4-satellites.yaml`
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P5-callers-graph.yaml`
- Create: `docs/superpowers/specs/phase-0-agent-outputs/P6-outputs-diff.yaml`

**Importante:** los 6 agentes se lanzan en **un solo mensaje** con 6 tool calls `Agent` concurrentes.

- [ ] **Step 2.1: Lanzar agente P1 — CLI de `run_hunt.py`**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt (self-contained):

```
Eres el auditor P1 de la Fase 0 de paridad legacy↔moderno del proyecto /home/kali/Documents/Web3/.

Scope: SÓLO audit-agents/run_hunt.py. Extraer la definición argparse (todos los flags CLI) y mapear cada flag a:
- Qué hace (1 línea)
- Qué función interna invoca (función handler)
- Qué side effects produce (archivos creados, subprocess lanzados)
- Qué outputs genera (directorios/YAMLs/JSONs)

No leas todo el archivo. Busca la sección argparse (grep por "add_argument") y lee sólo el contexto necesario.

Devuelve EXCLUSIVAMENTE un YAML válido con esta estructura (cero prosa fuera del YAML):

---
agent: P1
scope: "audit-agents/run_hunt.py CLI"
flags:
  - name: "--component"
    short: "-c"
    description: "..."
    handler_function: "cmd_hunt_component"
    side_effects:
      - "escribe hunt_session/context/<protocol>/<component>_*.md"
      - "subprocess: claude -p (9 hunters)"
    outputs:
      - "hunt_session/hypotheses/<protocol>/hyp_*.yaml"
  - name: "--init-ficha"
    ...
notes:
  - "Cualquier observación relevante"

Escribe el YAML a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P1-cli-legacy.yaml

No modifiques ningún otro archivo.
```

Expected: archivo `P1-cli-legacy.yaml` creado con YAML válido, ≥5 flags listados.

- [ ] **Step 2.2: Lanzar agente P2 — funciones públicas de `run_hunt.py`**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt:

```
Eres el auditor P2 de Fase 0 en /home/kali/Documents/Web3/.

Scope: funciones públicas de audit-agents/run_hunt.py agrupadas por área. No leas todo (4.270 LOC). Usa Grep para:
- Funciones top-level (grep "^def ")
- Funciones cmd_* (handlers de CLI)
- Funciones generate_* (constructores de prompts)
- Funciones de dispatch (run_hunters, run_deepdive, etc.)

Agrupa por área: scope_setup, hunters_dispatch, gates_management, poc_generation, knowledge_integration, state_management, other.

Devuelve EXCLUSIVAMENTE YAML válido:

---
agent: P2
scope: "audit-agents/run_hunt.py funciones públicas"
areas:
  scope_setup:
    - name: "ensure_protocol_dirs"
      line: 123
      purpose: "..."
      side_effects: ["..."]
  hunters_dispatch:
    - name: "run_hunters_parallel"
      line: 456
      purpose: "..."
      ...
  gates_management:
    ...
dynamic_dispatch_found:
  - pattern: "getattr"
    location: "line N"
    description: "..."
notes: []

Escribe el YAML a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P2-functions-legacy.yaml
```

Expected: YAML válido con ≥4 áreas, ≥15 funciones totales, sección `dynamic_dispatch_found` (vacía si no hay).

- [ ] **Step 2.3: Lanzar agente P3 — flujo moderno completo**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt:

```
Eres el auditor P3 de Fase 0 en /home/kali/Documents/Web3/.

Scope:
- audit-agents/run_benchmark.py (CLI argparse + fases top-level)
- audit-agents/plan_generator.py (funciones phase_*)
- audit-agents/plan_schema.py (dataclasses Step, ExecutionPlan)
- audit-agents/.claude/skills/run-benchmark-agent/SKILL.md (secciones de ejecución)
- audit-agents/verify_team_outputs.py (qué verifica)

Devuelve EXCLUSIVAMENTE YAML:

---
agent: P3
scope: "flujo moderno: benchmark + plan_generator + skill"
run_benchmark_cli:
  flags:
    - name: "--mode"
      values: ["agent", "sub", "api"]
      description: "..."
    ...
  phases:
    - name: "prepass"
      function: "phase_prepass"
      outputs: ["..."]
    ...
plan_generator_phases:
  - name: "phase_hunter_prompt"
    generates_step_type: "agent"
    outputs_to_plan: "..."
  ...
skill_sections:
  - section: "Sequential Mode"
    what_it_does: "..."
  - section: "Team-Parallel Mode"
    what_it_does: "..."
verify_team_outputs:
  what_it_verifies: ["..."]
  invoked_by: "skill run-benchmark-agent section 8.6"
notes: []

Escribe a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P3-modern-flow.yaml
```

Expected: YAML válido con flags CLI, ≥5 fases, secciones de skill identificadas.

- [ ] **Step 2.4: Lanzar agente P4 — scripts satélite**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt:

```
Eres el auditor P4 de Fase 0 en /home/kali/Documents/Web3/.

Scope: scripts invocados por run_hunt.py vía subprocess o import. Para encontrarlos:
- Grep en audit-agents/run_hunt.py por: "subprocess.run", "import ", "from ."
- Candidatos conocidos: solodit_search.py, apply_feedback.py, scope_intake.py, sync_state.py, pipeline_gate.py, matcher.py, merge_invariants.py, compile_fixer.py
- Descartar: librerías stdlib, terceros

Para cada satélite real:
- Qué CLI expone (si tiene argparse)
- Qué hace (1-2 líneas)
- Si el flujo moderno también lo invoca (buscar en run_benchmark.py, plan_generator.py, skill)

Devuelve EXCLUSIVAMENTE YAML:

---
agent: P4
scope: "scripts satélite invocados por run_hunt.py"
satellites:
  - path: "audit-agents/solodit_search.py"
    invoked_by_legacy: ["run_hunt.py:L123 subprocess"]
    invoked_by_modern: []  # vacío = no lo invoca
    cli:
      flags: ["--query", "--limit"]
    purpose: "Buscar reports similares en Solodit"
    modern_status: "missing"  # present | partial | missing
  - path: "audit-agents/apply_feedback.py"
    ...
notes: []

Escribe a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P4-satellites.yaml
```

Expected: YAML con ≥4 satélites identificados, cada uno con `modern_status`.

- [ ] **Step 2.5: Lanzar agente P5 — grafo de callers transitivos**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt:

```
Eres el auditor P5 de Fase 0 en /home/kali/Documents/Web3/.

Scope: grafo completo de callers de run_hunt.py y run_benchmark.py. Usar Grep en TODO el repo (no solo audit-agents/).

Patrones a buscar:
- run_hunt.py: `run_hunt`, `run_hunt.py`, `python3 run_hunt`, `./run_hunt`
- run_benchmark.py: `run_benchmark`, `run_benchmark.py`, `python3 run_benchmark`

Categorizar cada caller:
- direct_python: otros .py que hacen subprocess/import
- shell_scripts: .sh / setup.sh / run_hybrid.sh
- skills: .md en .claude/skills/ o audit-agents/.claude/skills/
- docs: CLAUDE.md, READMEs, otros .md
- hooks: settings.json, .claude/hooks/
- ci: .github/, workflows

Devuelve EXCLUSIVAMENTE YAML:

---
agent: P5
scope: "grafo de callers transitivos"
run_hunt_callers:
  direct_python:
    - path: "audit-agents/scope_intake.py"
      line: 312
      invocation: "subprocess.run(['python3', 'run_hunt.py', '--init-ficha'])"
      transitive_callers: ["<quién llama a scope_intake.py>"]
  shell_scripts:
    - path: "setup.sh"
      line: 45
      invocation: "python3 run_hunt.py ..."
  skills: []
  docs:
    - path: "CLAUDE.md"
      section: "3. Modo Autónomo"
      mentions: ["run_hunt.py --component X"]
  hooks: []
  ci: []
run_benchmark_callers:
  ...
notes: []

Escribe a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P5-callers-graph.yaml
```

Expected: YAML con ambos grafos, al menos un caller por cada categoría donde aplique.

- [ ] **Step 2.6: Lanzar agente P6 — diff de outputs generados**

Tool: `Agent`, subagent_type: `Explore`, thoroughness: medium.

Prompt:

```
Eres el auditor P6 de Fase 0 en /home/kali/Documents/Web3/.

Scope: comparar qué directorios/archivos generan run_hunt.py vs flujo moderno.

Método:
1. Leer docs de inicio de cada flujo (CLAUDE.md secciones 3, 5, 16; skill run-benchmark-agent SKILL.md).
2. Grep en código por paths escritos (funciones open(), Path(), write_text(), mkdir()).
3. Listar outputs por flujo.
4. Categorizar: solo_run_hunt, solo_benchmark, shared, schema_divergente (misma ruta pero formato distinto).

Devuelve EXCLUSIVAMENTE YAML:

---
agent: P6
scope: "outputs diff"
run_hunt_outputs:
  - path: "hunt_session/fichas/<protocol>/<component>.yaml"
    format: "YAML"
    purpose: "..."
  - path: "hunt_session/context/<protocol>/<component>_*.md"
    format: "Markdown"
    purpose: "..."
benchmark_outputs:
  - path: "benchmarks/<protocol>/bench_session/execution_plan.json"
    format: "JSON"
    purpose: "..."
  - path: "benchmarks/<protocol>/bench_session/checkpoint.json"
    ...
shared_outputs:
  - path: "hunt_session/hypotheses/<protocol>/hyp_*.yaml"
    used_by_legacy: true
    used_by_modern: true
    schema_identical: true  # o false con explicación
schema_divergences: []
notes: []

Escribe a: /home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs/P6-outputs-diff.yaml
```

Expected: YAML con listas no vacías de outputs por categoría.

- [ ] **Step 2.7: Ejecutar los 6 lanzamientos en un solo mensaje**

Los 6 prompts anteriores se envían en un único mensaje con 6 tool calls `Agent` concurrentes. Tiempo esperado: 10-15 min.

Expected al final: 6 archivos YAML en `docs/superpowers/specs/phase-0-agent-outputs/`.

---

## Task 3: Validar outputs de los agentes

**Files:**
- Read: `docs/superpowers/specs/phase-0-agent-outputs/P1..P6-*.yaml`

- [ ] **Step 3.1: Validar que los 6 YAML existen y son parseables**

```bash
cd /home/kali/Documents/Web3
for f in docs/superpowers/specs/phase-0-agent-outputs/P*.yaml; do
  echo "=== $f ==="
  python3 -c "import yaml, sys; yaml.safe_load(open('$f'))" && echo "OK" || echo "FAIL"
done
```

Expected: `OK` para los 6 archivos. Si alguno falla: re-lanzar ese agente con prompt más estricto.

- [ ] **Step 3.2: Validar contenido mínimo**

```bash
python3 << 'EOF'
import yaml
from pathlib import Path

base = Path("/home/kali/Documents/Web3/docs/superpowers/specs/phase-0-agent-outputs")
checks = {
    "P1-cli-legacy.yaml":     lambda d: len(d.get("flags", [])) >= 5,
    "P2-functions-legacy.yaml": lambda d: len(d.get("areas", {})) >= 4,
    "P3-modern-flow.yaml":    lambda d: "run_benchmark_cli" in d and "plan_generator_phases" in d,
    "P4-satellites.yaml":     lambda d: len(d.get("satellites", [])) >= 4,
    "P5-callers-graph.yaml":  lambda d: "run_hunt_callers" in d and "run_benchmark_callers" in d,
    "P6-outputs-diff.yaml":   lambda d: all(k in d for k in ["run_hunt_outputs", "benchmark_outputs", "shared_outputs"]),
}
failed = []
for name, check in checks.items():
    with open(base / name) as f:
        data = yaml.safe_load(f)
    status = "OK" if check(data) else "FAIL"
    print(f"{status} {name}")
    if status == "FAIL":
        failed.append(name)

if failed:
    print(f"\n{len(failed)} archivo(s) no cumplen contenido mínimo: {failed}")
    exit(1)
print("\nTodos los outputs válidos.")
EOF
```

Expected: salida "Todos los outputs válidos." Si algún archivo falla: re-lanzar ese agente con instrucciones más específicas hasta cumplir.

- [ ] **Step 3.3: Commit de los outputs intermedios (audit trail)**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/phase-0-agent-outputs/P*.yaml
rtk git commit -m "chore: Fase 0 agent outputs (P1-P6, audit trail)"
```

Expected: commit creado con los 6 YAMLs.

---

## Task 4: Consolidar en `parity-matrix.yaml`

**Files:**
- Create: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

- [ ] **Step 4.1: Identificar features consolidadas**

Cruzar P1 (flags CLI) + P2 (funciones por área) + P4 (satélites) para producir una lista de features únicas. Cada flag + cada satélite + cada área funcional son candidatos.

Criterio de feature: "cosa que run_hunt.py expone o produce, observable desde fuera".

Esperadas ≥20 features. Ejemplos mínimos:
- F001: Solodit search (flag `--no-solodit` + satélite `solodit_search.py`)
- F002: Apply feedback (llamada interna a `apply_feedback.py`)
- F003: Init ficha (`--init-ficha`)
- F004: Component map (`--map-components`)
- F005: Cross-component (`--cross-component`)
- F006: Complete gate (`--complete`)
- ... (el resto sale del cruce de P1+P2+P4)

- [ ] **Step 4.2: Para cada feature, buscar equivalente en P3 (flujo moderno)**

Por cada feature, determinar `modern_equivalent.status`:
- `present` — misma funcionalidad en mode agent/plan_generator.
- `partial` — existe pero incompleto (p.ej. falta integrarlo en un phase).
- `missing` — no existe en P3.

Evidencia debe citar texto de P3 o confirmar ausencia con grep 0 hits.

- [ ] **Step 4.3: Asignar decision + risk + effort**

Usar los criterios del spec:

| `modern_equivalent.status` | Contexto | Decisión |
|---|---|---|
| `present` | | **deprecate** |
| `partial` | valor claro | **migrate** |
| `missing` | con callers reales | **migrate** |
| `missing` | sin callers, sin valor | **deprecate** |
| `missing` | valor como utility suelta | **keep_standalone** |

Risk:
- **high**: feature toca estado persistente compartido o pipeline crítico.
- **medium**: feature tiene callers múltiples o integración en varias fases.
- **low**: feature aislada, fácil de mover.

Effort (LOC aproximadas a migrar):
- XS: <50
- S: 50-200
- M: 200-500
- L: 500-1000
- XL: >1000

- [ ] **Step 4.4: Escribir `parity-matrix.yaml` consolidado**

Usar el schema del spec (sección "Matriz de paridad"). El archivo debe incluir secciones: `features`, `callers` (de P5), `satellites` (de P4), `outputs_diff` (de P6), `summary`.

Estructura exacta:

```yaml
version: 1
generated: 2026-04-17
source: run_hunt.py + satélites
target: run_benchmark.py --mode agent + plan_generator.py + skill

features: [ ... ]   # con decision, risk, effort
callers: { ... }    # desde P5
satellites: { ... } # desde P4
outputs_diff: { ... } # desde P6
summary:
  total_features: N
  by_decision: { migrate: N, deprecate: N, keep_standalone: N }
  by_risk: { low: N, medium: N, high: N }
  by_effort: { XS: N, S: N, M: N, L: N, XL: N }
  ordered_migration_plan: [ ... ]
```

Escribir con `Write` tool al path exacto: `/home/kali/Documents/Web3/docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`.

- [ ] **Step 4.5: Validar matriz consolidada**

```bash
python3 << 'EOF'
import yaml
from pathlib import Path

path = Path("/home/kali/Documents/Web3/docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml")
with open(path) as f:
    m = yaml.safe_load(f)

errors = []

# Feature count
features = m.get("features", [])
if len(features) < 20:
    errors.append(f"Solo {len(features)} features, mínimo 20")

# Cada feature tiene decision, risk, effort
for feat in features:
    fid = feat.get("id", "?")
    if "migration_decision" not in feat:
        errors.append(f"{fid}: falta migration_decision")
    if "risk" not in feat:
        errors.append(f"{fid}: falta risk")
    if "effort" not in feat:
        errors.append(f"{fid}: falta effort")
    if feat.get("modern_equivalent", {}).get("status") == "unknown":
        errors.append(f"{fid}: modern_equivalent.status es unknown")

# Summary presente
if "summary" not in m:
    errors.append("Falta sección summary")

# Ordered migration plan presente
if not m.get("summary", {}).get("ordered_migration_plan"):
    errors.append("Falta ordered_migration_plan")

if errors:
    print("FAIL")
    for e in errors:
        print(f"  - {e}")
    exit(1)
print("OK: matriz válida")
print(f"  {len(features)} features")
print(f"  decisions: {m['summary']['by_decision']}")
EOF
```

Expected: "OK: matriz válida" con conteo de features y distribución de decisiones. Si FAIL: completar campos faltantes y re-validar.

---

## Task 5: Calcular orden de migración

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml` (sección `summary.ordered_migration_plan`)

- [ ] **Step 5.1: Algoritmo de ordenamiento**

Para features con `decision == migrate`, ordenar por:

1. Prerequisite first — si F007 depende de F001 (F001 debe existir para que F007 aterrice), F001 va antes.
2. Risk ascendente — low antes de high.
3. Effort ascendente — XS antes de XL.

Dependencies sólo se declaran si evidentes (ej: "Solodit context" debe existir antes de "Hunter prompts con solodit en contexto").

- [ ] **Step 5.2: Escribir `ordered_migration_plan`**

Editar la matriz para añadir el plan:

```yaml
summary:
  ordered_migration_plan:
    - feature_id: F001
      order: 1
      reason: "low risk, no deps, small effort"
      depends_on: []
    - feature_id: F003
      order: 2
      reason: "prerequisite for F007"
      depends_on: []
    ...
```

- [ ] **Step 5.3: Validar**

```bash
python3 << 'EOF'
import yaml
with open("/home/kali/Documents/Web3/docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml") as f:
    m = yaml.safe_load(f)

plan = m["summary"]["ordered_migration_plan"]
migrate_features = [f["id"] for f in m["features"] if f["migration_decision"] == "migrate"]

# Cada feature migrate aparece en el plan
planned_ids = [p["feature_id"] for p in plan]
missing = set(migrate_features) - set(planned_ids)
if missing:
    print(f"FAIL: {missing} no aparecen en ordered_migration_plan")
    exit(1)

# Order es único y consecutivo 1..N
orders = sorted([p["order"] for p in plan])
if orders != list(range(1, len(plan) + 1)):
    print(f"FAIL: orders no son 1..{len(plan)} consecutivos: {orders}")
    exit(1)

# Dependencies están en planned_ids
for p in plan:
    for dep in p.get("depends_on", []):
        if dep not in planned_ids:
            print(f"FAIL: {p['feature_id']} depende de {dep} pero {dep} no está en plan")
            exit(1)

print(f"OK: {len(plan)} features en plan, ordenamiento consistente")
EOF
```

Expected: "OK: N features en plan, ordenamiento consistente".

---

## Task 6: Escribir `parity-report.md`

**Files:**
- Create: `docs/superpowers/specs/2026-04-17-phase-0-parity-report.md`

- [ ] **Step 6.1: Redactar narrativa <800 palabras**

Secciones:

1. **TL;DR** (3-5 bullets): cuántas features, cuántas a migrar, cuánto effort total estimado, sorpresas principales.
2. **Hallazgos clave**: features inesperadas, callers sorprendentes, outputs huérfanos.
3. **Decisiones no obvias**: features donde `migrate vs deprecate vs keep_standalone` requirió juicio (justificar).
4. **Orden recomendado de migración**: top 10 del `ordered_migration_plan` con justificación corta.
5. **Riesgos para Fase 2**: qué puede salir mal en la migración (p.ej. satélites con estado compartido, callers externos no controlados).
6. **Input para Fase 1**: qué smoke tests deberían capturar antes de tocar código.

Límite estricto: 800 palabras.

- [ ] **Step 6.2: Escribir el archivo**

Usar `Write` tool al path: `/home/kali/Documents/Web3/docs/superpowers/specs/2026-04-17-phase-0-parity-report.md`.

- [ ] **Step 6.3: Validar longitud**

```bash
wc -w /home/kali/Documents/Web3/docs/superpowers/specs/2026-04-17-phase-0-parity-report.md
```

Expected: ≤800 palabras. Si excede: abreviar la sección más verbosa.

---

## Task 7: Commit de entregables finales

**Files:**
- Add: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`
- Add: `docs/superpowers/specs/2026-04-17-phase-0-parity-report.md`

- [ ] **Step 7.1: Verificar estado git**

```bash
cd /home/kali/Documents/Web3
rtk git status
```

Expected: `parity-matrix.yaml` y `parity-report.md` en unstaged.

- [ ] **Step 7.2: Add + commit**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml docs/superpowers/specs/2026-04-17-phase-0-parity-report.md
rtk git commit -m "$(cat <<'EOF'
docs: Fase 0 parity audit deliverables

Matriz YAML machine-readable + reporte narrativo de paridad
run_hunt.py (legacy) vs flujo benchmark (moderno). Input directo
de Fase 2 (migración) sin interpretación humana.

Agent trail en docs/superpowers/specs/phase-0-agent-outputs/.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

Expected: commit creado.

---

## Task 8: Resumen al usuario

- [ ] **Step 8.1: Reportar hallazgos clave al usuario**

Sin tool calls. Mensaje breve <120 palabras con:
- Número total de features identificadas.
- Distribución migrate/deprecate/keep_standalone.
- Top 3 sorpresas del report.
- Recomendación: "¿seguimos a Fase 1 (tests snapshot) o quieres ajustar algo del plan de migración ordenado?"

---

## Done Criteria

- Los 6 YAMLs de agentes commiteados en `phase-0-agent-outputs/`.
- `parity-matrix.yaml` con ≥20 features, cero `unknown`, cada feature con decision+risk+effort, `ordered_migration_plan` válido.
- `parity-report.md` ≤800 palabras commiteado.
- Usuario informado del resultado y próximo paso.
