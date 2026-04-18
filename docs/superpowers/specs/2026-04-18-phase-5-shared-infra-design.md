# Fase 5 — Shared Infra Consolidation (Design Spec)

**Fecha**: 2026-04-18
**Fase**: 5 de 8 del roadmap de optimización
**Scope**: consolidar duplicación real post-Fase 4 en dos módulos compartidos
**Branch**: `main` directo (patrón validado en Fases 2A-2D / 3 / 4)
**Methodology**: subagent-driven-development con two-stage review

---

## Motivación

El spec maestro del roadmap (`2026-04-17-optimization-roadmap.md` §5) marcó Fase 5 como **condicional**: sólo procede si la auditoría post-migración detecta duplicación REAL (no asumida). Tras Fases 2A-2D y Fase 4 (Fase 4 recién eliminó `run_hunt.py` y extrajo `hunter_context.py`), se auditaron los tres ejes candidatos del spec maestro:

1. **Paths/constants duplicados** — CONFIRMADO.
2. **State manager con atomic writes** — CONFIRMADO.
3. **Matching findings↔ground-truth** — DISPUTABLE (semánticas distintas, no mecánico).

Decisión: **atacar ejes 1 y 2; dejar eje 3 fuera** (encaja mejor en Fase 6 refactor polish, no es dedupe mecánico).

## Evidencia de duplicación (ejes 1 y 2)

### Eje 1 — Path constants

Repetidos con 3 estrategias distintas de derivación:

| Constante | Files que la definen | Estrategias |
|---|---|---|
| `WEB3_DIR` | 16 | `Path.home() / "Documents/Web3"` (13) + `Path(__file__).resolve().parent.parent` (3) + `SCRIPT_DIR.parent` (2) |
| `STATE_FILE = ~/.claude/MEMORY/STATE/current_hunt.json` | 9 | literal repetido |
| `HUNT_SESSION_DIR` | 8 | derivado de cada `WEB3_DIR` local |
| `AUDIT_AGENTS_DIR` | 3 | derivado local |

Consumers con `< 3` definiciones (`REPORTS_DIR` 2×, `KNOWLEDGE_DIR` 2×, `VAULT_RAW` 1×, `BENCHMARKS_DIR` 1×) NO se consolidan — son definiciones-donde-se-usa, no duplicación.

### Eje 2 — State manager

7 archivos con implementaciones casi idénticas de `load_state()` + `save_state()` sobre `current_hunt.json`:

| Archivo | load | save | backup? | notas |
|---|---|---|---|---|
| `sync_state.py` | ✅ | ✅ | ✅ | inyecta `last_sync` sidecar antes de save |
| `submit_finding.py` | ✅ | ✅ | ✅ | |
| `report_finding.py` | ✅ | ✅ | ✅ | |
| `pipeline_gate.py` | ✅ | `_save_state` | ❌ | |
| `component_closer.py` | `_load_state(path)` | `_save_state_atomic(path, data)` | ❌ | toma `state_file` custom para tests |
| `merge_invariants.py` | `load_current_hunt` | — | n/a | solo lee |

Patrón compartido: `tmp.write_text` → `tmp.replace(STATE_FILE)`, cleanup en except. Opcional: `shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))` antes del write.

## No-scope (explícito)

- **File locks** — spec maestro los mencionaba como condicional ("si `current_hunt.json` viven en paralelos"). Descartados por YAGNI: el atomic `rename()` ya previene corrupción en escrituras concurrentes; el race teórico es cola de espera, no data loss. No hay incidentes reportados en el repo.
- **Backup unificado forzado** — se deja como `backup: bool = False` kwarg opt-in para preservar el comportamiento exacto de cada caller (4 de 6 callers que escriben hoy hacen backup, 2 no; se mantiene así).
- **Eje 3 matching findings↔ground-truth** — `benchmark_score.match_finding` usa integer scoring (DETECTED/PARTIAL/MISSED con score≥4); `benchmark.match_findings` usa float similarity (threshold 0.35). Semánticas distintas, consolidación es decisión de diseño no refactor. Va a Fase 6.
- **`target_monitor.py::STATE_FILE`** — apunta a `data/state.json` (no a `current_hunt.json`), scope distinto; se mantiene local.
- **`constants.py`** — mantiene su scope actual (Bounty Radar ↔ local status mappings). No se mezcla con paths.

## Arquitectura

Dos módulos nuevos en `audit-agents/`, cada uno con una responsabilidad única y dependencias mínimas:

```
audit-agents/paths.py          ← single source of truth para directorios + state file path
  ├─ WEB3_DIR:          Path    (= Path.home() / "Documents/Web3")
  ├─ AUDIT_AGENTS_DIR:  Path    (= WEB3_DIR / "audit-agents")
  ├─ HUNT_SESSION_DIR:  Path    (= WEB3_DIR / "hunt_session")
  └─ STATE_FILE:        Path    (= Path.home() / ".claude/MEMORY/STATE/current_hunt.json")

audit-agents/state_manager.py  ← single source of truth para current_hunt.json I/O
  ├─ load_state() -> dict
  └─ save_state(state, *, backup=False) -> None
```

**Dependency graph**:
- `state_manager.py` importa `STATE_FILE` de `paths.py`
- Ningún otro cross-import entre ambos

**Anchoring de `WEB3_DIR`**: se ancla en `Path.home() / "Documents" / "Web3"` (no en `__file__`). Justificación: el flujo moderno exige `cd /home/kali/Documents/Web3` (CLAUDE.md) y 13/16 callers ya usan esta estrategia. Los 3 callers que derivaban desde `__file__` dan el mismo resultado cuando el repo vive en `~/Documents/Web3`, pero la estrategia `Path.home()` es robusta a ejecución vía symlink o worktree (un worktree en `.worktrees/foo/` NO quiere apuntar a `.worktrees/` como `WEB3_DIR`).

## API contracts

### `paths.py`

No funciones, solo constantes `Path` (no strings):

```python
from pathlib import Path

WEB3_DIR = Path.home() / "Documents" / "Web3"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
```

### `state_manager.py`

```python
from __future__ import annotations
import json
import shutil
from typing import Any
from paths import STATE_FILE

def load_state() -> dict[str, Any]:
    """Return parsed current_hunt.json, or {} if absent. Raises on malformed JSON."""
    if not STATE_FILE.exists():
        return {}
    return json.loads(STATE_FILE.read_text())

def save_state(state: dict[str, Any], *, backup: bool = False) -> None:
    """Atomic write. If backup=True and file exists, copy to .backup.json first."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if backup and STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
```

**Semánticas preservadas**:
- `load_state` retorna `{}` si el archivo no existe (igual que `pipeline_gate.load_state`, `submit_finding.load_state`, `report_finding.load_state`).
- `load_state` propaga `json.JSONDecodeError` si el archivo está corrupto (igual que los callers actuales).
- `save_state` crea `STATE_FILE.parent` si no existe (igual que `component_closer._save_state_atomic`).
- `save_state` usa `tmp.replace(STATE_FILE)` para rename atómico (igual que todos los callers).
- `save_state` limpia `tmp` si el rename falla.
- `backup=True` reproduce exactamente `shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))`.

## Plan de migración

### Rewire de `paths.py` — 19 archivos

| Archivo | Constantes que importa |
|---|---|
| `run_benchmark.py` | `WEB3_DIR`, `HUNT_SESSION_DIR` |
| `pipeline_gate.py` | `WEB3_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE` |
| `apply_feedback.py` | `WEB3_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE` |
| `scope_intake.py` | `WEB3_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE` |
| `benchmark.py` | `WEB3_DIR`, `AUDIT_AGENTS_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE` |
| `hunter_context.py` | `WEB3_DIR`, `HUNT_SESSION_DIR`, `AUDIT_AGENTS_DIR` |
| `context_enrichment.py` | `WEB3_DIR`, `AUDIT_AGENTS_DIR` |
| `merge_invariants.py` | `WEB3_DIR`, `HUNT_SESSION_DIR`, `STATE_FILE` |
| `invariant_rag.py` | `WEB3_DIR` |
| `claude_classify.py` | `WEB3_DIR` |
| `solodit_to_wiki.py` | `WEB3_DIR` |
| `migrate_hunt_session.py` | `WEB3_DIR` |
| `solodit_search.py` | `WEB3_DIR` |
| `build_solodit_index.py` | `WEB3_DIR` |
| `add_finding.py` | `WEB3_DIR` |
| `report_finding.py` | `STATE_FILE` |
| `submit_finding.py` | `STATE_FILE` |
| `sync_state.py` | `STATE_FILE` |
| `component_closer.py` | `STATE_FILE` (reemplaza `_DEFAULT_STATE_FILE`) |

**No tocados** (retienen constantes locales):
- `target_monitor.py` — su `STATE_FILE` apunta a otro archivo.
- `constants.py` — scope BR.
- `bounty_scanner.py` — `CACHE_DIR` local, usa una sola vez.
- Consumers con `< 3` references (`REPORTS_DIR`, `KNOWLEDGE_DIR`, `VAULT_RAW`, `BENCHMARKS_DIR`).

### Rewire de `state_manager.py` — 6 archivos

| Archivo | Qué reemplaza | `backup=` | Notas |
|---|---|---|---|
| `sync_state.py` | `load_state` + `save_state` | `True` | mantener inyección de `last_sync` sidecar en caller antes de llamar `state_manager.save_state(state, backup=True)` |
| `submit_finding.py` | `load_state` + `save_state` | `True` | rewire directo |
| `report_finding.py` | `load_state` + `save_state` | `True` | rewire directo |
| `pipeline_gate.py` | `load_state` + `_save_state` | `False` | `_save_state` interno reemplazado; callers internos siguen llamando a los nombres locales que delegan |
| `component_closer.py` | `_load_state` + `_save_state_atomic` | `False` | conservar `state_file` param para tests — wrapper que delega a `state_manager` cuando `state_file == STATE_FILE`, hace I/O directo al custom path cuando es distinto |
| `merge_invariants.py::load_current_hunt` | solo lee | n/a | `load_current_hunt` pasa a ser wrapper defensivo: `try: return load_state(); except json.JSONDecodeError: return {}`. Preserva exactamente la semántica del swallow actual (que atrapa `Exception`) para corruptos, pero propaga `FileNotFoundError` y otros (igual que hace `state_manager.load_state` — retorna `{}` si el archivo no existe). |

## Testing strategy

**Baseline**: suite combinada 122/122 (`phase_modern + 2a + 2b + 2c + 2d`) verde en cada commit. Cero regresiones toleradas.

**Tests nuevos** en `audit-agents/tests/phase_5/`:

### `test_paths.py` (4 tests)

- `test_paths_are_absolute` — las 4 constantes son `Path` absolutas.
- `test_web3_dir_is_home_documents_web3` — `WEB3_DIR == Path.home() / "Documents" / "Web3"`.
- `test_hunt_session_dir_under_web3` — `HUNT_SESSION_DIR.parent == WEB3_DIR`.
- `test_state_file_under_claude_memory` — `STATE_FILE == Path.home() / ".claude/MEMORY/STATE/current_hunt.json"`.

### `test_state_manager.py` (6 tests)

Todos monkeypatching `state_manager.STATE_FILE` a `tmp_path / "current_hunt.json"`:

- `test_load_state_returns_empty_if_missing` — archivo inexistente → `{}`.
- `test_load_state_returns_parsed_json` — archivo con `{"x": 1}` → `{"x": 1}`.
- `test_save_state_writes_atomically` — tras `save_state({"a": 1})`, el archivo existe con JSON indentado válido; no deja `.tmp.json` residual.
- `test_save_state_creates_parent_dir` — si `STATE_FILE.parent` no existe, `save_state` lo crea.
- `test_save_state_backup_opt_in` — con archivo pre-existente: `backup=True` crea `.backup.json`, `backup=False` (default) no lo crea.
- `test_save_state_cleans_tmp_on_failure` — monkeypatch `Path.replace` para raise → `.tmp.json` se borra, raise propaga.

### `test_caller_integration.py` (3 tests)

- `test_pipeline_gate_load_state_is_shared_manager` — `pipeline_gate.load_state` returnea desde `state_manager.load_state` (identidad verificable via `is` o proxy call check).
- `test_sync_state_last_sync_sidecar_preserved` — `sync_state.save_state(state)` inyecta `last_sync` en el dict antes de llamar `state_manager.save_state(..., backup=True)`. Verificable vía spy/mock.
- `test_component_closer_state_file_override_still_works` — `component_closer.close_component(..., state_file=custom_path)` sigue escribiendo al path custom (no a `STATE_FILE`), preservando los 15 tests existentes de Fase 2D.

**Total**: 13 tests nuevos. Suite post-Fase 5: **135/135**.

**Smoke checks CLI** (Task 8):
- `python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a audit-agents/tests/phase_2b audit-agents/tests/phase_2c audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q` → 135 passed.
- `python3 audit-agents/run_benchmark.py --help` → exit 0, sin `ImportError`.
- `python3 audit-agents/pipeline_gate.py --help` → exit 0, sin `ImportError`.
- `python3 audit-agents/scope_intake.py --help` → exit 0, sin `ImportError`.
- `grep -rE "^WEB3_DIR\s*=" audit-agents/*.py` — solo debe aparecer en `paths.py` (excluir `target_monitor.py` si usa mismo nombre — no, no lo usa).
- `grep -rE "STATE_FILE\s*=.*current_hunt" audit-agents/*.py` — solo debe aparecer en `paths.py`.

## Secuencia de commits

8 commits en `main`. Cada uno deja el repo en estado verde (tests + smoke CLI).

| # | Task | Commit |
|---|---|---|
| 1 | Scaffold `paths.py` + `test_paths.py` | `feat(phase_5): add paths module with 4 canonical constants` |
| 2 | Rewire read-only callers (group A) — `hunter_context`, `context_enrichment`, `invariant_rag`, `claude_classify`, `solodit_to_wiki`, `migrate_hunt_session`, `solodit_search`, `build_solodit_index`, `add_finding`, `merge_invariants` | `refactor(phase_5): rewire read-only callers to paths module` |
| 3 | Rewire state-writer callers (group B) — `run_benchmark`, `pipeline_gate`, `apply_feedback`, `scope_intake`, `benchmark`, `report_finding`, `submit_finding`, `sync_state`, `component_closer` | `refactor(phase_5): rewire state-writer callers to paths module` |
| 4 | Scaffold `state_manager.py` + `test_state_manager.py` | `feat(phase_5): add state_manager module for current_hunt.json I/O` |
| 5 | Route `pipeline_gate.py` + `merge_invariants.py` through `state_manager` (no backup, read-only) | `refactor(phase_5): route pipeline_gate + merge_invariants through state_manager` |
| 6 | Route `sync_state.py` + `submit_finding.py` + `report_finding.py` (backup=True) | `refactor(phase_5): route finding scripts through state_manager with backup=True` |
| 7 | Route `component_closer.py` preservando `state_file` override para tests | `refactor(phase_5): route component_closer through state_manager with state_file override` |
| 8 | Parity matrix + memoria roadmap | `docs(phase_5): update parity matrix + roadmap memory` |

**Verification gate entre cada commit**:
```bash
python3 -m pytest audit-agents/tests/phase_modern audit-agents/tests/phase_2a \
                   audit-agents/tests/phase_2b audit-agents/tests/phase_2c \
                   audit-agents/tests/phase_2d audit-agents/tests/phase_5 -q
```

## Riesgos y mitigaciones

| Riesgo | Probabilidad | Mitigación |
|---|---|---|
| Regresión por cambio de estrategia de `WEB3_DIR` en los 3 callers que usaban `__file__` | Baja | Todos los callers están en `audit-agents/`, que vive en `~/Documents/Web3/audit-agents/` — `Path.home() / "Documents/Web3"` da el mismo valor. Smoke check `--help` cubre imports en cada caller. |
| Divergencia de semántica en `merge_invariants::load_current_hunt` que swallow `Exception` | Baja | Tests actuales del módulo no dependen de ese swallow; el nuevo `load_state` propaga `JSONDecodeError` cual es el comportamiento de 5 de 6 callers. Si un test falla, añadimos `try/except JSONDecodeError` en el caller. |
| `component_closer` test failures por pérdida del `state_file` override | Baja | Tarea 7 preserva el param explícitamente; test 3 del caller integration suite verifica el override. |
| Commit absorbe deltas preexistentes (patrón Fases 2A-2D / 3 / 4) | Casi seguro | Aceptado: mismo patrón validado. Commit message deja constancia en Task 8 si ocurre. |

## Entregables

1. 8 commits en `main` con la secuencia arriba.
2. Suite combinada 135/135 verde en el commit final.
3. Spec `docs/superpowers/specs/2026-04-18-phase-5-shared-infra-design.md` (este archivo).
4. Plan `docs/superpowers/plans/2026-04-18-phase-5-shared-infra.md` (siguiente paso post-aprobación).
5. Parity matrix actualizada en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`: añadir features nuevas F031 (paths consolidation) y F032 (state_manager consolidation) con `status: added_phase_5`.
6. Memoria roadmap actualizada al cierre: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`.

## Criterios de éxito

Fase 5 se considera completa cuando:

- [ ] `paths.py` existe con las 4 constantes y 4 tests pasan.
- [ ] `state_manager.py` existe con `load_state` + `save_state(state, *, backup=False)` y 6 tests pasan.
- [ ] 3 tests de caller integration pasan.
- [ ] 19 archivos importan sus paths desde `paths.py`; ninguno mantiene definición local.
- [ ] 6 archivos delegan su I/O de `current_hunt.json` a `state_manager.py` (preservando backup policy y `state_file` override donde aplique).
- [ ] Suite combinada 135/135.
- [ ] Smoke checks CLI pasan para `run_benchmark.py`, `pipeline_gate.py`, `scope_intake.py`.
- [ ] Parity matrix + memoria roadmap actualizadas.
- [ ] 8 commits en `main`, cada uno deja el repo verde.
