# TUI Dashboard Design Spec

**Fecha:** 2026-04-20
**Goal:** Dashboard de consola en tiempo real con `rich` que muestra gates del pipeline, findings y actividad del hunt activo — standalone, stdin-only, lectura de artefactos existentes.

---

## Contexto

Todo el pipeline expone telemetría via JSON:
- `hunt_session/MEMORY/STATE/current_hunt.json` — protocolo activo, componentes
- `hunt_session/gate_status/<protocol>.json` — estado de cada gate por componente (`component_gates.<Component>.<gate>.state` ∈ `pass|fail|pending`)
- `hunt_session/findings.json` — findings de hunts reales
- `benchmarks/<protocol>/bench_session/findings_all.json` — findings de benchmarks
- `bench_session/logs/<run>/orchestrator.log` — log unificado del pipeline (contiene `Step N:` markers)

Hoy el usuario ve el pipeline por `tail -f` del stdout. Queremos un TUI que consolide estado + acciones en curso en una sola pantalla con feedback visual.

---

## Arquitectura

**Archivo único:** `audit-agents/dashboard.py` (~240 LOC), ejecutable directamente.

**Stack:** `rich` (ya instalado) + stdlib. Sin Flask, sin WS, sin dependencias nuevas.

**Invocación:**
```bash
python3 audit-agents/dashboard.py              # auto-detecta hunt activo
python3 audit-agents/dashboard.py --protocol yieldoor-bench   # override
```

**Ciclo:**
- `rich.Live` con refresh 4 Hz (250ms)
- Lecturas de JSON cacheadas con TTL 1s (evita saturar I/O)
- Parser de log usa `tail` incremental por offset de fichero (no re-lee)

---

## Layout

Usa `rich.layout.Layout`:

```
┌─[ yieldoor-bench  •  16:58:42 ]──────────────────────────────┐
│ Comp       scope prep hunt  dd  mrg cmp  p1  p2  p3  vfy    │
│ Leverager   ✅    ✅   ⠋    ⋯   ⋯   ⋯   ⋯   ⋯   ⋯   ⋯    ←  │   (fila pulsa)
│ LendingPool ✅    ⠋    ⋯    ⋯   ⋯   ⋯   ⋯   ⋯   ⋯   ⋯        │
├──────────────────────────────────────────────────────────────┤
│ 🐛  0 findings   H:0  M:0  L:0                               │
├──────────────────────────────────────────────────────────────┤
│ ▸▸▸ Activity                                                 │
│   16:58:40  Leverager  Running claude -p sub (3175 chars)    │
│   16:58:41  Leverager  12 Hunters completed (5.2min)         │
│   16:58:42  Leverager  Step 4: DeepDive Hunter               │
└──────────────────────────────────────────────────────────────┘
```

- **Header**: protocolo activo + reloj en vivo (HH:MM:SS refrescado cada 1s)
- **Grid**: filas = componentes, columnas = gates. ✅ verde / ❌ rojo / ⠋ spinner amarillo (activo) / ⋯ gris (pending)
- **Componente activo** (el que tiene un gate en `⏳`): su fila alterna bold/dim cada 1s + marcador `←` al final
- **Findings strip**: contador total + desglose por severidad. Flash verde 1s cuando el total sube.
- **Activity**: últimos 3 eventos parseados del orchestrator.log (timestamp + componente + mensaje). Scroll natural — nuevo evento por abajo empuja el más viejo hacia arriba.
- **Phase 1 progress bar**: si se detecta Step 8 activo + patrón `runs: N`, se añade `rich.progress.Progress` encima del grid (transitorio — solo durante phase 1).

---

## Estructura interna

```python
# audit-agents/dashboard.py

@dataclass
class HuntSnapshot:
    protocol: str
    components: list[str]
    gates: dict[str, dict[str, str]]   # {comp: {gate: state}}
    active_component: str | None
    active_gate: str | None
    active_step: str | None            # "Step 4: DeepDive Hunter"
    findings_total: int
    findings_by_severity: dict[str, int]
    recent_events: list[tuple[str, str, str]]  # (ts, comp, msg)

def load_current_hunt() -> dict: ...
def load_gate_status(protocol: str) -> dict: ...
def load_findings(protocol: str) -> dict: ...
def parse_recent_events(log_path: Path, offset: int) -> tuple[list[Event], int]: ...
def build_snapshot(protocol: str, log_state: LogState) -> HuntSnapshot: ...

def render_header(snap) -> Panel: ...
def render_gates(snap) -> Table: ...     # uses Spinner for active cells
def render_findings(snap, prev_total: int, flash_until: float) -> Panel: ...
def render_activity(snap) -> Panel: ...
def render_layout(snap, ...) -> Layout: ...

def main():
    args = parse_args()
    with Live(..., refresh_per_second=4) as live:
        while True:
            snap = build_snapshot(...)
            live.update(render_layout(snap, ...))
            time.sleep(0.25)
```

---

## Animaciones (detalle)

| Elemento | Técnica |
|---|---|
| Spinner en gate activo | `rich.spinner.Spinner("dots", style="yellow")` — `Spinner.render(Console().get_time())` |
| Fila componente activo pulsa | `Style(bold=True)` vs `Style(dim=True)` alternado por `int(time.time()) % 2` |
| Flash verde en findings | Detectar delta; guardar `flash_until = now + 1.0`; mientras `now < flash_until`, render con `bgcolor="green"` |
| Marquee activity | Append al buffer `deque(maxlen=3)`. Cuando llega evento nuevo, se pinta entero. Scroll visual por reemplazo natural. |
| Reloj live | `datetime.now().strftime("%H:%M:%S")` en cada render |
| Phase 1 progress | Regex `runs:\s*(\d+)\s*/\s*5000` sobre últimas 50 líneas del log |

---

## Tests

`audit-agents/tests/test_dashboard.py` — 5 tests sobre helpers puros (sin render):

1. `test_load_current_hunt_present`: lee JSON mock, retorna dict con `protocol` y `components`
2. `test_load_current_hunt_missing`: archivo no existe → `{}` (no crash)
3. `test_build_snapshot_merges_sources`: dado JSON mocks de current_hunt + gate_status + findings, el snapshot agrega todo correcto
4. `test_parse_recent_events_extracts_step_markers`: dado un log de ejemplo con "Step 4: DeepDive", extrae 1 evento con el mensaje limpio
5. `test_findings_severity_aggregation`: dado findings con severidades mixtas, agrupa por severity con counts correctos

No se testean los helpers de render (dependen de Console y son difíciles de assert).

---

## Criterios de éxito

- `python3 audit-agents/dashboard.py` arranca sin error si hay `current_hunt.json` activo
- `python3 audit-agents/dashboard.py` con no hay hunt → imprime "No active hunt" y espera polling (no crash)
- Refresh visual sin flicker a 4 Hz
- Spinner visible en gates activos
- Fila del componente activo pulsa (bold↔dim)
- Activity panel muestra últimos 3 eventos con timestamp
- `Ctrl-C` cierra limpio (restora terminal)
- 5/5 tests nuevos pasan
- 238 tests existentes siguen pasando

---

## Out of scope

- Histórico (sesiones pasadas) — sólo hunt activo
- Control interactivo (teclas para saltar/pausar/etc.) — sólo lectura
- Múltiples hunts simultáneos — un protocolo a la vez
- Gráficas de throughput / latencia
- Persistir screenshots o snapshots
- WebSocket / HTML — solo TUI en consola
- Integración con `run_benchmark.py --dashboard` — standalone puro

---

## Riesgos mitigados

| Riesgo | Mitigación |
|---|---|
| Log file grande → relectura costosa | Lectura incremental con offset por fichero. Parser sólo mira últimas 50 líneas nuevas. |
| JSON parcial durante escritura atómica | `try/except json.JSONDecodeError` → ignorar ciclo, mantener snapshot anterior |
| Terminal pequeño corta columnas | `rich` auto-ajusta; columnas con `min_width`. Grid scroll horizontal si > 15 componentes. |
| Arranque sin hunt activo | Mostrar mensaje + seguir polling cada 2s hasta detectar `current_hunt.json` |
| Ctrl-C deja terminal sucia | `Live` ya gestiona cleanup; envolver en `try/KeyboardInterrupt` |
