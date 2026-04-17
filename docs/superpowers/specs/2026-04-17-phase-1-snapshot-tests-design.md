# Fase 1 — Snapshot Tests del Flujo Moderno: Design Spec

**Fecha**: 2026-04-17 · **Roadmap**: Fase 1 de 8 · **Previo**: `2026-04-17-phase-0-parity-report.md`.

## Propósito

Capturar el comportamiento actual del flujo moderno (`run_benchmark.py` + `plan_generator.py` + `run-benchmark-agent` skill + satélites migrados) como **red de seguridad previa a la migración de Fase 2**.

Sin esta suite, las 14 features del parity matrix se migran a ciegas: cualquier regresión de `execution_plan.json`, `hyp_*.yaml` o `findings_all.json` pasaría silenciosa y solo aparecería al correr un benchmark real (horas después, con fricción alta).

La suite es **híbrida**: goldens bit-exact para componentes deterministas + contract tests para outputs semi-deterministas. Solidity es la base canónica hoy; la estructura se deja extensible para Rust/Move/Cairo sin reescritura.

## Objetivos

1. **Detectar regresiones en Fase 2** antes de que lleguen a un benchmark e2e.
2. **Formalizar el contrato** de los outputs del flujo moderno (schemas obligatorios).
3. **Permitir extensión por lenguaje** añadiendo fixtures sin tocar tests.
4. **Mantener velocidad**: suite completa <10s, runnable en cada commit.

## No-objetivos

- No e2e con LLM (costoso, no determinista, no aporta señal de regresión).
- No performance benchmarking (distinto del parity).
- No cobertura de los 5 tests unitarios existentes (quedan donde están).

## Decisiones clave

| Decisión | Elegido | Alternativas descartadas |
|---|---|---|
| Scope | Híbrido (goldens durables + schemas) | Minimal throwaway / Full e2e con LLM |
| Cobertura de lenguajes | Solidity canónica + estructura extensible | Solo Solidity sin framework / Ambos con paridad inmediata |
| Strategy | Bit-exact donde determinista + contract tests donde semántico | 100% bit-exact / 100% contract |
| Ejecución | Live donde barato + frozen donde caro | 100% live / 100% frozen |
| Herramienta | Pytest puro + helpers propios | syrupy / golden framework propio |

Rationale de cada decisión resumida en las secciones siguientes.

## Arquitectura

### Ubicación y estructura

```
audit-agents/tests/phase_modern/
├── conftest.py                     # fixtures compartidas
├── helpers.py                      # assert_matches_golden
├── fixtures/
│   ├── solidity/
│   │   └── yieldoor/
│   │       ├── repo_ref.txt        # pointer a /home/kali/Documents/Web3/benchmarks/yieldoor/repo
│   │       └── goldens/
│   │           ├── plan_generator/
│   │           │   ├── execution_plan_full.json       # 4 componentes, --fast
│   │           │   └── execution_plan_single.json     # 1 componente minimal
│   │           ├── prepass/
│   │           │   ├── Vault_prepass.yaml
│   │           │   └── Strategy_prepass.yaml
│   │           └── gate_status/
│   │               └── status_initial.json
│   └── rust/                       # placeholder — se llena cuando migremos Rust
├── test_plan_generator_golden.py
├── test_prepass_golden.py
├── test_schemas.py
├── test_pipeline_gate_status.py
└── test_helpers.py                 # self-tests del framework
```

Los 5 tests unitarios existentes (`test_pipeline_gate.py`, `test_scope_intake.py`, etc.) quedan en `audit-agents/tests/` sin tocar.

### Parametrización por lenguaje

Todos los tests usan:
```python
@pytest.mark.parametrize(
    "language,benchmark",
    [
        ("solidity", "yieldoor"),
        # Añadir Rust mañana:
        # ("rust", "layerzero-stellar"),
    ],
)
```

Añadir un lenguaje nuevo = crear `fixtures/<lang>/<benchmark>/` + registrar en la lista. Ningún test se reescribe.

## Componentes

### `helpers.py` — API de comparación

```python
from pathlib import Path
from typing import Literal

def assert_matches_golden(
    actual: dict | str | bytes,
    golden_path: Path,
    *,
    mode: Literal["json", "yaml", "text"] = "json",
    ignore_keys: list[str] | None = None,
) -> None:
    """
    Compares `actual` against the file at `golden_path`.

    - If UPDATE_SNAPSHOTS=1: overwrites golden_path with actual, then
      pytest.skip("golden updated: <path>") for visibility.
    - If golden file missing: fails with hint to run UPDATE_SNAPSHOTS=1.
    - If present: parses both per `mode`, drops `ignore_keys` recursively,
      computes structural diff, asserts equality.
    - On mismatch: AssertionError with readable diff.
    """
```

Implementación ~60 LOC. `ignore_keys` se aplica recursivamente (p.ej. `["created_at"]` dropea el campo en el plan root y en cada step anidado).

### `conftest.py` — Fixtures compartidas

- `tmp_session_dir` — `TemporaryDirectory` con subdirs `context/`, `results/`, `hypotheses/`, `gate_status/`.
- `benchmark_fixture(language, benchmark)` — lee `fixtures/{language}/{benchmark}/repo_ref.txt` y devuelve Path al repo real.
- `frozen_session_fixture(version="v12")` — devuelve Path a `benchmarks/yieldoor/bench_session_v12/` para tests de schemas sobre output real de un benchmark pasado.

### Tests — archivos y responsabilidades

**`test_plan_generator_golden.py`** (live, ~4-5 tests)
- `test_plan_full_yieldoor`: ejecuta `plan_generator.py --generate` sobre yieldoor completo (4 componentes + `--fast` + ground-truth), compara con `execution_plan_full.json`.
- `test_plan_single_component`: 1 componente minimal, compara con `execution_plan_single.json`.
- `test_plan_ignores_created_at`: regenera un plan, muta `created_at`, valida que `ignore_keys=["created_at"]` absorbe el cambio.
- `test_plan_includes_cross_when_multi_component`: contract assert — al haber ≥2 componentes el plan debe contener al menos un step cuyo `id` empieza con `phase_cross_`.

**`test_prepass_golden.py`** (frozen, ~3-4 tests)
- `test_prepass_vault_matches_frozen`: compara `benchmarks/yieldoor/bench_session/results/Vault_prepass.yaml` con golden.
- `test_prepass_strategy_matches_frozen`: idem para Strategy.
- `test_prepass_schema_stable`: claves obligatorias presentes (`findings`, `tools_used`, `layers`, `source`, `name`).

**`test_schemas.py`** (contract, ~5-6 tests, sobre sesión v12 congelada)
- `test_hyp_yaml_has_required_fields`: cada `hyp_*.yaml` en `hypotheses/yieldoor/` contiene `title`, `component`, `confidence`, `severity`, `invariant`.
- `test_hyp_yaml_solidity_section_present`: campo `solidity.invariant_solidity` existe en hunters Solidity.
- `test_findings_all_json_schema`: `findings_all.json` tiene `findings[]` con `id`, `component`, `severity`, `confidence` en cada entrada.
- `test_checkpoint_json_schema`: `completed_steps`, `failed_steps`, `current_batch` presentes y del tipo correcto.
- `test_hunter_performance_schema`: `hunter_performance.json` es dict `{hunter_name: {count, duration_sec, ...}}`.

**`test_pipeline_gate_status.py`** (live, ~2-3 tests)
- `test_gate_status_export_structure`: ejecuta `pipeline_gate.py --scope-status --export-json`, valida schema.
- `test_gate_status_empty_component`: componente inexistente no crashea (exit code != 2, stderr informativo).

**`test_helpers.py`** (self-test del framework, 4 tests)
- `test_assert_matches_golden_pass`: actual idéntico → no raise.
- `test_assert_matches_golden_diff`: actual != golden → AssertionError con diff en el mensaje.
- `test_update_mode_writes_file`: `UPDATE_SNAPSHOTS=1` crea/sobrescribe el golden.
- `test_ignore_keys_excluded_from_diff`: `ignore_keys=["created_at"]` dropea el campo recursivamente.

### Totales

- 5 archivos de test, ~18-22 tests.
- Goldens en disco: ~5-6 JSON/YAML, <500KB total.
- Runtime esperado: <10s (plan_generator es ~1s, prepass no se ejecuta live, schemas leen de disco).

## Data flow

### Test live (ejemplo — plan_generator)
```
pytest test_plan_generator_golden.py::test_plan_full_yieldoor
  ├── conftest resolves fixtures/solidity/yieldoor/repo_ref.txt → benchmarks/yieldoor/repo
  ├── tmp_session_dir → /tmp/pytest-xxx/session/
  ├── subprocess.run(["python3", "plan_generator.py", "--generate",
  │                    "--repo", <repo>, "--components", "Vault,Strategy,Leverager,ReserveLogic",
  │                    "--protocol", "yieldoor", "--session-dir", <tmp>,
  │                    "--ground-truth", "benchmarks/yieldoor/benchmark.yaml"])
  ├── capture /tmp/.../execution_plan.json
  ├── assert_matches_golden(actual, goldens/plan_generator/execution_plan_full.json,
  │                         mode="json", ignore_keys=["created_at"])
  └── pass/fail con parser-aware diff
```

### Test frozen (ejemplo — prepass)
```
pytest test_prepass_golden.py::test_prepass_vault_matches_frozen
  ├── source = benchmarks/yieldoor/bench_session/results/Vault_prepass.yaml
  ├── golden = fixtures/solidity/yieldoor/goldens/prepass/Vault_prepass.yaml
  ├── assert_matches_golden(source.read_text(), golden, mode="yaml")
  └── pass/fail
```

### Regeneración
```
UPDATE_SNAPSHOTS=1 pytest tests/phase_modern/ -v
  ├── cada assert_matches_golden sobrescribe si actual != golden
  ├── pytest.skip("golden updated: plan_generator/execution_plan_full.json")
  └── el humano revisa el diff en git, hace commit explícito
```

Los goldens regenerados nunca se commitean sin revisión. El flujo esperado es:
1. Developer cambia código.
2. Corre pytest — tests fallan con diff.
3. Si el cambio es intencional: `UPDATE_SNAPSHOTS=1 pytest tests/phase_modern/`.
4. `git diff` sobre los goldens regenerados — valida que los cambios sean los esperados.
5. Commit incluye tanto el código como los goldens actualizados.

## Error handling

| Situación | Comportamiento |
|---|---|
| Golden no existe | Fail explícito: `Golden not found: <path>. Run with UPDATE_SNAPSHOTS=1 to create.` |
| Subprocess de `plan_generator.py` falla | Fail con `returncode` + `stderr` capturados en el mensaje. |
| YAML/JSON de golden malformado | Fail en parsing (no en diff), mensaje identifica el archivo. |
| Slither/Aderyn ausentes | Tests frozen pasan (no invocan binarios). Tests live que dependan de ellos marcados con `@pytest.mark.requires_slither` → skip si no está en PATH. |
| `repo_ref.txt` apunta a path inexistente | Fail en fixture con hint: "Benchmark repo moved? Update fixtures/solidity/yieldoor/repo_ref.txt". |
| `bench_session_v12/` desaparece | Fail en `frozen_session_fixture` con hint a regenerar o apuntar a versión distinta. |
| `UPDATE_SNAPSHOTS=1` con escritura fallida (p.ej. permisos) | Fail explícito, no silencia. |

## Testing del framework

`test_helpers.py` (4 tests) cubre el helper. Razón: un snapshot framework buggy produce false negatives en todos los demás tests de la suite — es la dependencia crítica.

No se añade infraestructura CI en esta fase. Los tests son runnable localmente (`pytest tests/phase_modern/`) y eso basta para el propósito de red-de-seguridad pre-Fase-2. CI integration puede evaluarse en Fase 3+ si surge necesidad.

## Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Goldens se vuelven stale y nadie los regenera | Regeneración es trivial (`UPDATE_SNAPSHOTS=1`) y parser-aware diff hace obvio qué cambió. |
| `plan_generator.py` introduce campos no deterministas no previstos | `ignore_keys` en helpers es extensible; añadimos el campo a la lista. |
| Sesiones frozen (`bench_session_v12/`) se borran | Documentamos dependencia explícita; añadir snapshot mínimo en fixtures si hace falta. |
| Rust llega con estructura distinta | El parametrize por `(language, benchmark)` soporta tests específicos por lenguaje vía `pytest.mark.skipif` si hace falta; goldens en directorios separados. |

## Input de Fase 0 cubierto

Los 5 snapshots propuestos por el parity report están cubiertos:

| # | Propuesta del parity report | Cobertura en esta fase |
|---|---|---|
| 1 | Determinismo plan_generator.py sobre yieldoor | `test_plan_generator_golden.py` (4 tests) |
| 2 | Schema `hyp_*.yaml` por hunter | `test_schemas.py::test_hyp_yaml_*` (2 tests) |
| 3 | `findings_all.json` tras benchmark | `test_schemas.py::test_findings_all_json_schema` |
| 4 | Verificación de gates por `pipeline_gate.py --status` | `test_pipeline_gate_status.py` (2-3 tests) |
| 5 | Golden para `detection_engine.py --prepass` | `test_prepass_golden.py` (3-4 tests, frozen) |

## Criterios de éxito

Fase 1 se considera completa cuando:
1. Suite ejecuta en <10s sobre yieldoor sin red.
2. 100% de tests verdes en estado actual del repo.
3. Regeneración funciona: cambiar `plan_generator.py` rompe el golden → `UPDATE_SNAPSHOTS=1` lo corrige.
4. Framework soporta Rust sin cambios de test (validable con un parametrize comentado que sirve como documentación).
5. `test_helpers.py` verde — el framework es fiable.

Con estos 5 criterios, Fase 2 puede arrancar con red de seguridad.

---

**Próximo paso**: `writing-plans` skill genera `docs/superpowers/plans/2026-04-17-phase-1-snapshot-tests.md` con tareas granulares.
