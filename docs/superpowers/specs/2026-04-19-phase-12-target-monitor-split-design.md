# Phase 12 — Split de `target_monitor.py` Design Spec

**Fecha:** 2026-04-19
**Goal:** Reducir `audit-agents/target_monitor.py` (1,261 LOC, god-file HIGH debt) a un shim CLI de ~6 LOC + paquete `monitor/` con 8 submódulos organizados por dominio.

---

## Contexto

Phase 9 partió `pipeline_gate.py`, Phase 10 deprecó `hybrid_pipeline.py`, Phase 11 partió `merge_invariants.py`. Siguiente god-file en backlog: `target_monitor.py` (1,261 LOC).

**Inventario del archivo actual:**
- 3 dataclasses: `Alert`, `State`
- 1 delivery class: `Notifier` (telegram/discord/console)
- 3 domain monitor classes: `GitHubMonitor` (~200 LOC), `ProxyUpgradeMonitor` (~200 LOC), `DeploymentMonitor` (~170 LOC)
- 4 funciones top-level: `_get_key`, `score_target`, `run_monitors`, `daemon_mode`, `main`
- Config module-level: `DATA_DIR`, `STATE_FILE`, `ALERTS_FILE`, `LOG_FILE`, API keys, `POLL_INTERVAL`
- **Cero importers Python**: no hay `from target_monitor import ...` en ningún archivo del repo
- Tests existentes: ninguno

La propiedad "cero importers Python" hace el split simple: no hay API pública que preservar. El shim solo mantiene el entry-point CLI.

---

## Arquitectura

### Shim canónico

`audit-agents/target_monitor.py` queda como CLI thin shim:

```python
#!/usr/bin/env python3
"""target_monitor.py — CLI entry point. Logic in monitor/ package."""
from monitor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

### Paquete `monitor/`

```
audit-agents/monitor/
├─ __init__.py          (vacío)
├─ config.py            (~80 LOC) — env vars + paths + constants
├─ state.py             (~100 LOC) — Alert + State dataclasses
├─ notifier.py          (~100 LOC) — Notifier class
├─ github.py            (~200 LOC) — GitHubMonitor
├─ proxy.py             (~200 LOC) — ProxyUpgradeMonitor
├─ deployment.py        (~170 LOC) — DeploymentMonitor
├─ orchestrator.py      (~180 LOC) — score_target, run_monitors, daemon_mode
└─ cli.py               (~110 LOC) — main + argparse
```

### Responsabilidades por módulo

| Módulo | Contenido | Propósito |
|---|---|---|
| `config.py` | `_get_key`, API keys, paths, POLL_INTERVAL, console, logger | Configuración compartida |
| `state.py` | `Alert`, `State` dataclasses + serialización | Persistencia de estado y alertas |
| `notifier.py` | `Notifier` class | Delivery de alertas (telegram/discord/console) |
| `github.py` | `GitHubMonitor` | Monitoreo de commits GitHub post-audit |
| `proxy.py` | `ProxyUpgradeMonitor` | Monitoreo de upgrades on-chain |
| `deployment.py` | `DeploymentMonitor` | Monitoreo de deployments de deployers conocidos |
| `orchestrator.py` | `score_target`, `run_monitors`, `daemon_mode` | Orquestación y scoring |
| `cli.py` | `main`, argparse setup | CLI entry point |

### Flujo de dependencias

```
cli.py → orchestrator.py → {github, proxy, deployment}.py → {state, notifier, config}.py
         orchestrator.py → state.py (scoring)
         github.py → state.py, notifier.py, config.py
         proxy.py   → state.py, notifier.py, config.py
         deployment.py → state.py, notifier.py, config.py
         notifier.py → config.py (logger, telegram/discord env)
         state.py   → config.py (paths)
         config.py  (sin dependencies internas)
```

Sin ciclos.

---

## Tests (nuevos)

`audit-agents/tests/phase_12/test_monitor_shim.py` con 3 contract tests:

1. **`test_shim_loc_budget`**: `target_monitor.py` < 30 LOC
2. **`test_monitor_package_modules_importable`**: cada submódulo importable vía `import monitor.<name>`
3. **`test_cli_main_callable`**: `from monitor.cli import main` resuelve y es callable

No añadimos tests unitarios — el archivo original no tiene tests, y el criterio de éxito es **equivalencia funcional** (mismo CLI, mismos outputs).

---

## Criterios de éxito

- `python3 audit-agents/target_monitor.py --help` imprime el mismo help que antes
- Modo daemon (`--daemon`) arranca sin ImportError
- `target_monitor.py` ≤ 6 LOC
- Ningún submódulo de `monitor/` > 220 LOC
- Suite de tests pasa (230 → 233 con 3 contract tests nuevos de Phase 12)
- `phase_8_audit.py`: `target_monitor.py` ya no aparece como god-file
- CLI flags preservados: `--monitor`, `--daemon`, `--notify`, etc.

---

## Riesgos mitigados

| Riesgo | Mitigación |
|---|---|
| Config module-level (API keys, paths) necesita ser accesible desde múltiples monitors | Centralizado en `config.py` e importado por cada monitor |
| Notifier comparte estado con cada monitor | Pasado como dependencia inyectada al constructor (patrón ya existente) |
| `load_dotenv()` debe ejecutarse antes de `_get_key()` | `config.py` hace `load_dotenv()` en top-level, inmediato antes de leer env |
| `daemon_mode` loop + logging handler setup | Movido a `orchestrator.py`, logger compartido via `config.py` |

---

## Parity matrix

Al final de Phase 12, añadir entry `F057` en `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`:
- `legacy_location: audit-agents/target_monitor.py`
- `modern_location: audit-agents/monitor/ (package)`
- `migration_decision: migrate`
- Total features: 56 → 57

---

## Out of scope

- Cambios de comportamiento del CLI
- Reescritura de la lógica interna de los monitors
- Tests unitarios de funciones migradas
- Split de `runner.py` (Phase 13+)
- Renombrar el paquete para evitar colisión con stdlib (`monitor` no colisiona con stdlib — verificado)
