# Phase 7 — Orphan Cleanup + Parity Matrix Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminar los módulos de `audit-agents/` que realmente son orphans (código muerto detectado tras Fases 1-6) y cerrar la deuda documental del parity matrix, manteniendo 138/138 tests verdes en cada commit.

**Architecture:** Dos tracks independientes. **Track A** — verificación + deletion en 2 batches (11 fuertes en 1 commit, 8 sospechosos uno-a-uno). **Track B** — 5 fixes al parity matrix YAML en un commit (docs-only). Memory roadmap update al final.

**Tech Stack:** Python 3 stdlib (pytest), `rtk git` para commits, `git rm` para deletions (preserva history), `Grep` tool para verificación.

---

## File Structure

```
audit-agents/
├── [~11 archivos orphan a eliminar]       # Track A Batch 1
├── [0-5 archivos sospechosos a eliminar]  # Track A Batch 2
└── ... (resto intacto)

docs/superpowers/specs/
└── 2026-04-17-phase-0-parity-matrix.yaml  # Track B: 5 fixes

~/.claude/projects/-home-kali-Documents-Web3/memory/
└── project_optimization_roadmap.md        # Task 4: frontmatter + tabla + sección
```

No se crean archivos nuevos. Solo deletions + edits docs.

---

## Baseline Harness Command

Comando canónico en cada task:

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected todas las tareas: `138 passed`.

---

## Verification Protocol (Track A)

Para cada módulo candidato `<mod>` (sin `.py`), ejecutar estos 4 greps y aplicar reglas:

### Grep 1 — Inbound Python imports

```bash
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/
```

Filtrar hits del propio archivo (`audit-agents/$mod.py`). **Si queda ≥1 hit → NO eliminar.**

### Grep 2 — Subprocess / shell invocation

```bash
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" --include="*.yml" /home/kali/Documents/Web3/
```

Filtrar self-references. **Si queda ≥1 hit → inspeccionar manualmente**:
- Hit es historial del plan/spec/memory → safe, ignorar
- Hit es invocación real (`python3 $mod.py ...` dentro de código) → NO eliminar

### Grep 3 — Skills / hooks directories

```bash
rtk grep -rn "$mod" /home/kali/Documents/Web3/.claude/ /home/kali/.claude/skills/
```

**Cualquier hit en `.claude/` → inspeccionar**: si un skill dispatcher lo llama, NO eliminar.

### Grep 4 — Test mocks

```bash
rtk grep -rn "patch.*$mod\|mock.*$mod\|Mock.*$mod" --include="*.py" /home/kali/Documents/Web3/
```

**Cualquier hit → NO eliminar** (tests romperían).

### Regla de seguridad

Si el módulo tiene `if __name__ == "__main__"` + argparse → es un CLI standalone. Verificar si está documentado en `CLAUDE.md`, `HUNT_TRACKER.md` o README. Si se menciona → NO eliminar.

---

## Task 0: Baseline verification

**Files:**
- Read-only: toda la suite existente

- [ ] **Step 1: Ejecutar suite combinada baseline**

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected: `138 passed`.

- [ ] **Step 2: Verificar 5 CLIs --help**

```bash
python3 audit-agents/run_benchmark.py --help > /dev/null && echo "run_benchmark OK"
python3 audit-agents/plan_generator.py --help > /dev/null && echo "plan_generator OK"
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo "pipeline_gate OK"
python3 audit-agents/scope_intake.py --help > /dev/null && echo "scope_intake OK"
python3 audit-agents/sync_state.py --help > /dev/null && echo "sync_state OK"
```

Expected: 5 líneas con `OK`.

- [ ] **Step 3: Verificar spec commiteado**

```bash
rtk git log --oneline -1 -- docs/superpowers/specs/2026-04-19-phase-7-orphan-cleanup-design.md
```

Expected: 1 línea mostrando el commit `docs(phase_7): design — orphan cleanup + parity matrix polish`.

- [ ] **Step 4: No commit en esta task**

Task 0 es read-only. No hay changes que commitear.

---

## Task 1: Track A Batch 1 — 11 orphans fuertes

**Files:**
- Delete (candidatos): `audit-agents/{bounty_monitor_config, results_tracker, test_stream_claude2, invariant_test_runner, quickstart, bounty_scanner, claude_classify, parameter_boundary_scanner, target_score, test_stream_claude}.py`
- Delete (candidato con hyphen): `audit-agents/invariant-hunt.py`

Los 11 candidatos tienen 0-2 hits totales en el repo. La task aplica el verification protocol a cada uno y elimina los que pasen.

- [ ] **Step 1: Verificar los 3 con 0 hits**

Para cada `<mod>` in `[bounty_monitor_config, results_tracker, test_stream_claude2]`, ejecutar Grep 1-4 del verification protocol.

```bash
for mod in bounty_monitor_config results_tracker test_stream_claude2; do
  echo "=== $mod ==="
  rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
  rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
  rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -3
done
```

Expected: solo hits en specs/plans de Phase 7 (este mismo plan y el spec). Esos NO cuentan — son docs del cleanup actual.

- [ ] **Step 2: Verificar los 2 con 1 hit**

```bash
for mod in invariant_test_runner quickstart; do
  echo "=== $mod ==="
  rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
  rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
done
```

Inspeccionar manualmente cada hit. Si todos los hits están en docs de fases antiguas (memory, specs previos) sin ser invocaciones reales → safe eliminar. Si hay invocación real (skill, shell script) → NO eliminar.

- [ ] **Step 3: Verificar los 6 con 2 hits**

```bash
for mod in bounty_scanner claude_classify parameter_boundary_scanner target_score test_stream_claude; do
  echo "=== $mod ==="
  rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
  rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
done
```

Mismo criterio que Step 2.

- [ ] **Step 4: Verificar `invariant-hunt.py` (hyphen, solo CLI posible)**

```bash
rtk grep -rn "invariant-hunt" /home/kali/Documents/Web3/ /home/kali/.claude/skills/ 2>/dev/null | grep -v "audit-agents/invariant-hunt.py"
```

Inspeccionar: si cualquier `.sh` o `.md` documenta `python3 invariant-hunt.py ...` como workflow activo → NO eliminar. Si solo hay referencias históricas (HUNT_TRACKER menciones) → safe.

- [ ] **Step 5: Generar lista definitiva de eliminables**

Basado en los 4 steps previos, construir `ELIMINABLE_BATCH1` como subset de la lista original. Esperado: 8-11 archivos.

Declarar explícitamente la lista antes de borrar:

```bash
# Ejemplo (ajustar tras verificación):
ELIMINABLE_BATCH1="bounty_monitor_config results_tracker test_stream_claude2 invariant_test_runner quickstart bounty_scanner claude_classify parameter_boundary_scanner target_score test_stream_claude"
# (invariant-hunt se añade solo si step 4 lo confirma)
echo "$ELIMINABLE_BATCH1"
```

- [ ] **Step 6: Eliminar archivos via `git rm`**

```bash
cd /home/kali/Documents/Web3
for mod in $ELIMINABLE_BATCH1; do
  rtk git rm audit-agents/$mod.py
done
# Si invariant-hunt está en la lista:
# rtk git rm audit-agents/invariant-hunt.py
```

- [ ] **Step 7: Verificar suite combinada**

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected: `138 passed`.

**Si falla**: identificar qué test rompió, leer el error, revertir con `rtk git checkout HEAD -- audit-agents/<mod>.py`, y quitar ese módulo de la lista. No intentar arreglar el test — el módulo no era orphan.

- [ ] **Step 8: Verificar 5 CLIs --help siguen funcionando**

```bash
python3 audit-agents/run_benchmark.py --help > /dev/null && echo "run_benchmark OK"
python3 audit-agents/plan_generator.py --help > /dev/null && echo "plan_generator OK"
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo "pipeline_gate OK"
python3 audit-agents/scope_intake.py --help > /dev/null && echo "scope_intake OK"
python3 audit-agents/sync_state.py --help > /dev/null && echo "sync_state OK"
```

Expected: 5 líneas con `OK`.

- [ ] **Step 9: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git commit -m "chore(phase_7): remove orphan modules (Batch 1) — $(echo $ELIMINABLE_BATCH1 | wc -w) files"
```

Expected: commit creado mostrando N archivos deleted.

---

## Task 2: Track A Batch 2 — 8 sospechosos uno-a-uno

**Files:** (candidatos, decisión por módulo)
- `audit-agents/ai_invariant_generator.py`
- `audit-agents/migrate_hunt_session.py`
- `audit-agents/crosschain_verify.py`
- `audit-agents/protocol_analyzer.py`
- `audit-agents/target_monitor.py`
- `audit-agents/compile_fixer.py`
- `audit-agents/hybrid_pipeline.py`
- `audit-agents/invariant_rag.py`

Cada uno tiene 3-5 hits. Inspección manual; commit separado por módulo eliminado, o 1 commit combinado si varios pasan verificación.

- [ ] **Step 1: Verificar `ai_invariant_generator`**

```bash
mod="ai_invariant_generator"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
rtk grep -rn "patch.*$mod\|mock.*$mod" --include="*.py" /home/kali/Documents/Web3/
```

Decidir: **eliminar** o **mantener** (anotar razón).

- [ ] **Step 2: Verificar `migrate_hunt_session`**

```bash
mod="migrate_hunt_session"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener** (anotar razón).

- [ ] **Step 3: Verificar `crosschain_verify`**

```bash
mod="crosschain_verify"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener** (anotar razón). Nota: este módulo podría ser llamado por el CrossChainHunter del pipeline — verificar con cuidado.

- [ ] **Step 4: Verificar `protocol_analyzer`**

```bash
mod="protocol_analyzer"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener** (anotar razón).

- [ ] **Step 5: Verificar `target_monitor`**

```bash
mod="target_monitor"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener** (anotar razón). Nota: 1,261 LOC — si es alive, contribuye a "splits" futuros (Fase 8).

- [ ] **Step 6: Verificar `compile_fixer`**

```bash
mod="compile_fixer"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener**. Nota: `prompts/compile_fixer.md` existe — verificar si es un prompt LLM consumido o un módulo Python. Si es solo prompt → el `.py` puede ser orphan.

- [ ] **Step 7: Verificar `hybrid_pipeline`**

```bash
mod="hybrid_pipeline"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener**. Nota: 1,332 LOC — alternativa al pipeline moderno. Si es experimental sin consumidores → eliminar. Si es referenced en specs activas → mantener.

- [ ] **Step 8: Verificar `invariant_rag`**

```bash
mod="invariant_rag"
rtk grep -rn "from $mod import\|import $mod\b\|import $mod " --include="*.py" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod\.py" --include="*.py" --include="*.sh" --include="*.md" --include="*.yaml" /home/kali/Documents/Web3/ | grep -v "audit-agents/$mod.py"
rtk grep -rn "$mod" /home/kali/.claude/skills/ 2>/dev/null | head -5
```

Decidir: **eliminar** o **mantener** (anotar razón).

- [ ] **Step 9: Aplicar deletions**

Construir lista `ELIMINABLE_BATCH2` con los módulos que pasaron verificación en steps 1-8.

```bash
cd /home/kali/Documents/Web3
# Ejemplo (ajustar según resultados):
ELIMINABLE_BATCH2=""  # llenar según decisiones
for mod in $ELIMINABLE_BATCH2; do
  rtk git rm audit-agents/$mod.py
done
```

Si la lista está vacía (todos resultaron alive) → saltar steps 10-11 y marcar task como "no-op: todos alive" en el commit.

- [ ] **Step 10: Verificar suite + CLIs**

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected: `138 passed`.

```bash
python3 audit-agents/run_benchmark.py --help > /dev/null && echo "run_benchmark OK"
python3 audit-agents/plan_generator.py --help > /dev/null && echo "plan_generator OK"
python3 audit-agents/pipeline_gate.py --help > /dev/null && echo "pipeline_gate OK"
python3 audit-agents/scope_intake.py --help > /dev/null && echo "scope_intake OK"
python3 audit-agents/sync_state.py --help > /dev/null && echo "sync_state OK"
```

Expected: 5 `OK`.

- [ ] **Step 11: Commit**

Si hay deletions:

```bash
cd /home/kali/Documents/Web3
N=$(echo $ELIMINABLE_BATCH2 | wc -w)
rtk git commit -m "chore(phase_7): remove orphan modules (Batch 2) — $N files"
```

Si no hay deletions (task no-op):

```bash
cd /home/kali/Documents/Web3
rtk git commit --allow-empty -m "chore(phase_7): Batch 2 verification — all 8 suspects alive, no removals"
```

---

## Task 3: Track B — Parity matrix polish (5 fixes)

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

5 fixes aplicados en un commit. Cada fix es una edición discreta.

- [ ] **Step 1: Verificar que nadie consume `by_risk`**

```bash
rtk grep -rn "by_risk" --include="*.py" --include="*.yaml" --include="*.md" /home/kali/Documents/Web3/
```

Expected: solo hit en el propio YAML (línea ~795). Si hay consumidores reales → Fix #4 no se aplica (mantener `by_risk`).

- [ ] **Step 2: Fix #1 — Flip `migrate` → `migrated`**

Edit sobre `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:

```
old_string: migration_decision: migrate
new_string: migration_decision: migrated
replace_all: true
```

Expected: 9 reemplazos (F002, F003, F009, F014, F015, F016, F019, F022, F024).

- [ ] **Step 3: Fix #1 — Flip `deprecate` → `deprecated`**

Edit sobre el mismo archivo:

```
old_string: migration_decision: deprecate
new_string: migration_decision: deprecated
replace_all: true
```

Expected: 13 reemplazos (F001, F004, F005, F010, F011, F013, F017, F018, F025, F027, F028, F029, F030).

- [ ] **Step 4: Fix #2 — Re-tally summary (cuentas post-flip)**

Edit sobre el mismo archivo. Localizar el bloque summary (~líneas 787-804) y reemplazar:

```yaml
# old_string:
summary:
  total_features: 46
  by_decision:
    migrated: 17       # Fases 2A-2D (14) + Fase 4 extractions (F020/F021/F023 to hunter_context.py)
    deprecated: 13     # Original 15 deprecate - 3 migrated to hunter_context.py + 1 from F012 (--print-prompts removed)
    keep_standalone: 0 # F012 moved to deprecated in Fase 4 (superseded by direct file access to prompts/hunters/*.md)
    added_phase_5: 2   # F031 paths.py + F032 state_manager.py (shared infra consolidation 2026-04-18)
    added_phase_6: 14  # F033-F046 benchmark/ + plan/ packages (refactor polish 2026-04-18)
```

```yaml
# new_string:
summary:
  total_features: 46
  by_decision:
    migrated: 16       # 7 Fases 2A-2D + 9 flipped from migrate→migrated en Fase 7 (cleanup)
    deprecated: 14     # 1 F012 + 13 flipped from deprecate→deprecated en Fase 7 (cleanup)
    keep_standalone: 0 # F012 moved to deprecated in Fase 4
    added_phase_5: 2   # F031 paths.py + F032 state_manager.py (shared infra 2026-04-18)
    added_phase_6: 14  # F033-F046 benchmark/ + plan/ packages (refactor polish 2026-04-18)
```

**Verificación aritmética**: 16 + 14 + 0 + 2 + 14 = 46 ✓

- [ ] **Step 5: Fix #4 — Eliminar bloque `by_risk`**

Edit sobre el mismo archivo. Si Step 1 confirmó 0 consumidores, eliminar el sub-block:

```yaml
# old_string:
  by_risk:
    low: 23
    medium: 5
    high: 2
  by_effort:
```

```yaml
# new_string:
  by_effort:
```

Nota: `by_effort` queda intacto (no es parte de Fix #4).

Si Step 1 mostró consumidores → saltar este step y dejar `by_risk` como está.

- [ ] **Step 6: Fix #3 — Simplificar `legacy_location` en F033-F046**

Reemplazar 14 rangos por labels descriptivos. 14 edits individuales sobre el mismo archivo (todas `replace_all: false` porque cada string es único).

**F033** (llm_runners):
```
old_string: legacy_location: "run_benchmark.py:134-463"
new_string: legacy_location: "run_benchmark.py (LLM runner helpers section)"
```

**F034** (prompt_builders):
```
old_string: legacy_location: "run_benchmark.py:541-1087"
new_string: legacy_location: "run_benchmark.py (prompt builders section)"
```

**F035** (poc_pipeline):
```
old_string: legacy_location: "run_benchmark.py:464-1332"
new_string: legacy_location: "run_benchmark.py (PoC pipeline section)"
```

**F036** (component_pipeline):
```
old_string: legacy_location: "run_benchmark.py:1333-2956"
new_string: legacy_location: "run_benchmark.py (component pipeline section)"
```

**F037** (finding_pipeline):
```
old_string: legacy_location: "run_benchmark.py:2957-3150"
new_string: legacy_location: "run_benchmark.py (finding pipeline section)"
```

**F038** (cross_component):
```
old_string: legacy_location: "run_benchmark.py:3151-3588"
new_string: legacy_location: "run_benchmark.py (cross-component section)"
```

**F039** (worktree_helpers):
```
old_string: legacy_location: "run_benchmark.py:3589-3748"
new_string: legacy_location: "run_benchmark.py (worktree helpers section)"
```

**F040** (cli):
```
old_string: legacy_location: "run_benchmark.py:90-3749"
new_string: legacy_location: "run_benchmark.py (CLI + main() entrypoint)"
```

**F041** (detectors):
```
old_string: legacy_location: "plan_generator.py:50-895"
new_string: legacy_location: "plan_generator.py (detectors + path helpers section)"
```

**F042** (generator):
```
old_string: legacy_location: "plan_generator.py:248-895"
new_string: legacy_location: "plan_generator.py (plan generation section)"
```

**F043** (prompts_solidity):
```
old_string: legacy_location: "plan_generator.py:907-2663"
new_string: legacy_location: "plan_generator.py (Solidity prompt builders section)"
```

**F044** (prompts_rust):
```
old_string: legacy_location: "plan_generator.py:1019-2315"
new_string: legacy_location: "plan_generator.py (Rust prompt builders section)"
```

**F045** (post_compile):
```
old_string: legacy_location: "plan_generator.py:1988-2997"
new_string: legacy_location: "plan_generator.py (post-compile phases section)"
```

**F046** (cli):
```
old_string: legacy_location: "plan_generator.py:2998"
new_string: legacy_location: "plan_generator.py (CLI + main() entrypoint)"
```

- [ ] **Step 7: Fix #5 — Añadir `notes` a F037, F038, F039, F042, F044**

Localizar cada entry y añadir línea `notes` justo después de `migration_decision: added_phase_6`. 5 edits individuales.

**F037**:
```
old_string:
  - id: F037
    name: "benchmark/finding_pipeline package"
    legacy_location: "run_benchmark.py (finding pipeline section)"
    modern_location: "audit-agents/benchmark/finding_pipeline.py"
    migration_decision: added_phase_6

  - id: F038

new_string:
  - id: F037
    name: "benchmark/finding_pipeline package"
    legacy_location: "run_benchmark.py (finding pipeline section)"
    modern_location: "audit-agents/benchmark/finding_pipeline.py"
    migration_decision: added_phase_6
    notes: "Extracts findings from DeepDive YAML; runs full finding pipeline"

  - id: F038
```

**F038**:
```
old_string:
  - id: F038
    name: "benchmark/cross_component package"
    legacy_location: "run_benchmark.py (cross-component section)"
    modern_location: "audit-agents/benchmark/cross_component.py"
    migration_decision: added_phase_6

  - id: F039

new_string:
  - id: F038
    name: "benchmark/cross_component package"
    legacy_location: "run_benchmark.py (cross-component section)"
    modern_location: "audit-agents/benchmark/cross_component.py"
    migration_decision: added_phase_6
    notes: "Cross-component pair analysis (RULE #0.5)"

  - id: F039
```

**F039**:
```
old_string:
  - id: F039
    name: "benchmark/worktree_helpers package"
    legacy_location: "run_benchmark.py (worktree helpers section)"
    modern_location: "audit-agents/benchmark/worktree_helpers.py"
    migration_decision: added_phase_6

  - id: F040

new_string:
  - id: F039
    name: "benchmark/worktree_helpers package"
    legacy_location: "run_benchmark.py (worktree helpers section)"
    modern_location: "audit-agents/benchmark/worktree_helpers.py"
    migration_decision: added_phase_6
    notes: "Git worktree lifecycle + resolver helpers"

  - id: F040
```

**F042**:
```
old_string:
  - id: F042
    name: "plan/generator package"
    legacy_location: "plan_generator.py (plan generation section)"
    modern_location: "audit-agents/plan/generator.py"
    migration_decision: added_phase_6

  - id: F043

new_string:
  - id: F042
    name: "plan/generator package"
    legacy_location: "plan_generator.py (plan generation section)"
    modern_location: "audit-agents/plan/generator.py"
    migration_decision: added_phase_6
    notes: "Execution plan DAG generator (generate_plan + _add_*_steps)"

  - id: F043
```

**F044**:
```
old_string:
  - id: F044
    name: "plan/prompts_rust package"
    legacy_location: "plan_generator.py (Rust prompt builders section)"
    modern_location: "audit-agents/plan/prompts_rust.py"
    migration_decision: added_phase_6

  - id: F045

new_string:
  - id: F044
    name: "plan/prompts_rust package"
    legacy_location: "plan_generator.py (Rust prompt builders section)"
    modern_location: "audit-agents/plan/prompts_rust.py"
    migration_decision: added_phase_6
    notes: "Rust fuzz scaffold / harness prompts"

  - id: F045
```

- [ ] **Step 8: Validar YAML sigue siendo parseable**

```bash
python3 -c "
import yaml
data = yaml.safe_load(open('docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml'))
print(f'features: {len(data[\"features\"])}')
print(f'total: {data[\"summary\"][\"total_features\"]}')
print(f'by_decision: {data[\"summary\"][\"by_decision\"]}')
"
```

Expected:
```
features: 46
total: 46
by_decision: {'migrated': 16, 'deprecated': 14, 'keep_standalone': 0, 'added_phase_5': 2, 'added_phase_6': 14}
```

Suma: 16 + 14 + 0 + 2 + 14 = 46 ✓

- [ ] **Step 9: Verificar aritmética y consistencia**

```bash
python3 <<'EOF'
import yaml, collections
data = yaml.safe_load(open('docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml'))
counts = collections.Counter(f['migration_decision'] for f in data['features'])
print('actual counts:', dict(counts))
print('summary says :', data['summary']['by_decision'])
assert dict(counts) == dict(data['summary']['by_decision']), "MISMATCH!"
assert sum(counts.values()) == data['summary']['total_features']
print('OK: counts match summary; total consistent')
EOF
```

Expected: `OK: counts match summary; total consistent`.

- [ ] **Step 10: Verificar suite**

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected: `138 passed`.

- [ ] **Step 11: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "docs(phase_7): polish parity matrix — tense flip, summary re-tally, drop line ranges, notes"
```

---

## Task 4: Update memory roadmap

**Files:**
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`

Este archivo vive FUERA del repo. NO se commitea — solo Edit tool.

- [ ] **Step 1: Leer roadmap actual**

Usar el Read tool sobre `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`.

- [ ] **Step 2: Actualizar frontmatter**

Edit:

```markdown
# old_string:
---
name: Optimization Roadmap 2026-04
description: Estado del roadmap de 8 fases para optimizar el sistema de bug bounty (Web3/). Fase 6 COMPLETA (2026-04-18). Siguiente Fase 7.
type: project
originSessionId: 602f7e5c-940d-4905-b39f-780267d1993f
---
```

```markdown
# new_string:
---
name: Optimization Roadmap 2026-04
description: Estado del roadmap de 8 fases para optimizar el sistema de bug bounty (Web3/). Fase 7 COMPLETA (2026-04-19). Siguiente Fase 8 (final audit).
type: project
originSessionId: 602f7e5c-940d-4905-b39f-780267d1993f
---
```

- [ ] **Step 3: Actualizar rows 7 y 8 en la tabla de fases**

Edit. Localizar las filas:

```markdown
# old_string:
| 7 | Orphan cleanup | 🔜 NEXT | Eliminar código muerto |
| 8 | Final review | PENDING | Audit completo |
```

```markdown
# new_string:
| 7 | Orphan cleanup | ✅ COMPLETA (2026-04-19) | Removed N orphan modules; parity matrix polish (5 fixes); 138/138 tests |
| 8 | Final review | 🔜 NEXT | Audit completo del sistema |
```

Nota: el implementer debe sustituir `N` por el número real de archivos eliminados (suma de Batch 1 + Batch 2).

- [ ] **Step 4: Añadir sección "## Fase 7 — resumen al cerrar"**

Edit. Insertar justo ANTES de `## Metodología validada` (línea 133 aprox):

```markdown
## Fase 7 — resumen al cerrar

- **Track A — Orphans removed**: N archivos eliminados de `audit-agents/` tras verificación (inbound imports + subprocess + skills + mocks). Batch 1: X archivos (confidence alta, ≤2 hits). Batch 2: Y archivos (verificación manual de sospechosos con 3-5 hits).
- **Track A — Survivors**: módulos que aparentaban orphan pero resultaron alive: [lista]. Razón: [subprocess/skill/CLI].
- **Track B — Parity matrix polish**: 5 fixes en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
  1. Taxonomy drift — flipped 9 `migrate→migrated` + 13 `deprecate→deprecated`.
  2. Summary re-tally: `migrated: 17→16`, `deprecated: 13→14`. Total consistente: 46.
  3. `legacy_location` F033-F046: dropped line ranges, replaced con section labels.
  4. Eliminado bloque `by_risk` (sin consumidores).
  5. Añadido `notes` a F037, F038, F039, F042, F044.
- **Tests**: 138/138 passed en cada commit. Sin regresiones.
- **Commits**: 3-4 (Batch 1 + Batch 2 opcional + parity matrix).
- **Fuera de scope**: split de `pipeline_gate.py` (1,982 LOC), `hybrid_pipeline.py` (1,332), `merge_invariants.py` (1,280), `target_monitor.py` (1,261) — reservado para Fase 8. Eje 3 (matching consolidation) — también Fase 8.

```

El implementer debe rellenar `N`, `X`, `Y`, lista de survivors con los datos reales de la ejecución.

- [ ] **Step 5: NO commit**

El roadmap vive fuera del repo (`~/.claude/projects/`), se persiste solo en disco. No `rtk git add`.

- [ ] **Step 6: Verificar suite final**

```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 audit-agents/tests/phase_6 -q
```

Expected: `138 passed`.

- [ ] **Step 7: Verificar log de commits**

```bash
rtk git log --oneline -5
```

Expected: ver commits de Tasks 1, 2 (opcional), 3 en top.

---

## Self-Review Checklist

**1. Spec coverage:**
- [x] Sec 1 (Contexto) → Task 0 baseline
- [x] Sec 3 (Track A design) → Tasks 1 + 2 implementan verification protocol + batch delete
- [x] Sec 4 (Track B design) → Task 3 cubre los 5 fixes
- [x] Sec 5 (Orden de ejecución) → Tasks 0-4 mapean 1:1
- [x] Sec 6 (Criterios éxito) → Task 3 Step 10 + Task 4 Step 6 verifican `138 passed`; Task 3 Step 9 verifica consistencia parity matrix; Task 4 Steps 2-4 cubren memory roadmap
- [x] Sec 7 (Edge cases) → Verification Protocol aborda riesgos 1-4; Task 1 Step 4 aborda riesgo 5 (hyphen); Task 3 Step 1 aborda riesgo 6

**2. Placeholder scan:** sin TBD/TODO/FIXME en el plan. Los placeholders `N`/`X`/`Y` en Task 4 son datos runtime que el implementer rellena tras ejecutar — no son placeholders de planificación.

**3. Type consistency:** `ELIMINABLE_BATCH1` / `ELIMINABLE_BATCH2` usados consistentemente entre tasks. Grep commands idénticos en estructura entre Task 1 y Task 2. El verification protocol se aplica uniformemente.

**4. Gaps detected:** ninguno.
