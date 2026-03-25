# Hunt Dashboard — Design Spec

**Date**: 2026-03-23
**Status**: Approved
**Scope**: Local dashboard para monitoreo en tiempo real del pipeline de hunting

---

## Problem Statement

Durante un hunt largo (8+ componentes, 56+ instancias de hunters, múltiples fases de fuzzing), el único feedback es la terminal de Claude Code. No hay forma visual de ver:
- En qué componente estamos y cuáles faltan
- Qué etapas del checklist se han completado
- Qué hunters están corriendo y qué encontraron
- El estado del fuzzing (qué phase, cuánto tiempo, qué se rompió)
- El pipeline de cada finding

El dashboard resuelve esto con una vista de monitoreo en tiempo real, local, read-only.

---

## Design

### Architecture

```
hunt-dashboard/
  serve.py        ← Python server (~100 líneas)
  index.html      ← SPA con Alpine.js (CDN)
```

**`serve.py`**:
- Servidor HTTP Python (stdlib `http.server`, sin dependencias externas)
- Puerto por defecto: 8080 (configurable con `--port`)
- Sirve `index.html` en `/`
- Endpoint `/api/dashboard` → JSON consolidado (GET, read-only)
- Endpoint `/api/refresh` → fuerza re-lectura inmediata (POST, no modifica datos)
- No modifica ningún archivo del pipeline — solo lectura

**`index.html`**:
- SPA con Alpine.js bundled localmente (`hunt-dashboard/alpine.min.js`, descargado una vez desde CDN)
- Fallback: si el fichero local no existe, carga desde CDN como backup
- CSS inline (sin build, sin dependencias)
- Auto-fetch `/api/dashboard` cada 5 segundos
- Tema claro/oscuro persistido en localStorage
- Toda la UI en español

### Data Sources (Read-Only)

El endpoint `/api/dashboard` lee y consolida:

| Source | Data | Path |
|--------|------|------|
| Hunt state | Protocolo, payout, component_map, findings, status | `~/.claude/MEMORY/STATE/current_hunt.json` |
| Fichas | Checklist items, hunter completions por componente | `hunt_session/fichas/{protocol}/*.yaml` — protocolo leído de `current_hunt.json.protocol`. Excluir `ficha_template.yaml`. |
| Hipótesis | Hipótesis por hunter, confidence, tier, invariantes | `hunt_session/hypotheses/hyp_*.yaml` — nombre parseado: `hyp_{Component}_{Hunter}.yaml`. Si el nombre no sigue este patrón (e.g., `hyp_Bundler3_Analysis.yaml`), se agrupa como "Other" bajo el componente extraído del primer segmento. Excluir `hyp_template.yaml`. |
| Prompts | Existencia indica hunter fue lanzado | `hunt_session/context/*_prompt.md` |

**Importante**: `serve.py` NO modifica ninguno de estos archivos. Solo los lee y sirve como JSON.

### Response Schema (`/api/dashboard`)

```json
{
  "protocol": "pancakeswap-infinity",
  "platform": "Cantina",
  "payout": "Critical up to $1M, High $20K",
  "status": "in_progress",
  "current_component": "BinPositionManager",
  "components_done": ["Vault", "CLPoolManager"],
  "components_remaining": ["Dispatcher"],
  "component_map": [
    {
      "name": "Vault",
      "files": ["src/Vault.sol"],
      "loc": 150,
      "priority": 1,
      "status": "done",
      "depends_on": ["VaultToken"]
    }
  ],
  "findings": [
    {
      "id": "VAULT-AC-03",
      "title": "No unregisterApp()",
      "severity": "low",
      "status": "PARKED",
      "component": "Vault.sol",
      "confidence": 30
    }
  ],
  "fichas": {
    "BinPositionManager": {
      "status": "in_progress",
      "hunters_completed": {
        "MathHunter": true,
        "AccessHunter": true,
        "FlowHunter": true,
        "OracleHunter": false,
        "DomainHunter": false,
        "WildcardHunter": false,
        "TrustBoundaryHunter": false
      },
      "checklist": {
        "full_code_read": true,
        "protocol_model": true,
        "ai_invariants_generated": true,
        "invariants_added_to_properties": false,
        "handlers_added": false,
        "boundary_values": false,
        "optimization_functions": false,
        "compile_check": false,
        "foundry_fuzz": false,
        "findings_logged": false,
        "tier1_separated": false,
        "tolerance_tuned": false
      }
    }
  },
  "hypotheses": {
    "BinPositionManager": {
      "MathHunter": {
        "count": 8,
        "tier1": 3,
        "items": [
          {
            "id": "MATH-BPM-01",
            "description": "Rounding in addLiquidity favors user",
            "confidence": 75,
            "tier": 1
          }
        ]
      }
    }
  },
  "convergence": {
    "BinPositionManager": [
      {
        "function": "addLiquidity",
        "hunters": ["MathHunter", "FlowHunter", "DomainHunter"],
        "count": 3
      }
    ]
  },
  "activity_log": []
}
```

### Activity Log

`serve.py` genera el activity log a partir de las marcas de tiempo de los archivos:
- Ficheros `hyp_*.yaml` → timestamp de creación = cuándo completó el hunter
- Ficheros `*_prompt.md` → timestamp de creación = cuándo se lanzó el hunter
- Cambios en fichas YAML → cuándo se actualizó el checklist

El log se ordena cronológicamente y se sirve como array de events con:
```json
{
  "time": "14:32",
  "event": "MathHunter completado — 8 hipótesis, 3 Tier 1",
  "narrative": "Encontró 8 hipótesis sobre riesgos matemáticos...",
  "type": "success"
}
```

Las narrativas son plantillas en español dentro de `serve.py`. Tipos de evento y sus plantillas:

| Tipo | Evento | Narrativa |
|------|--------|-----------|
| `hunter_launched` | "{hunter} lanzado" | "Analizando {component} en busca de {domain_desc}. El hunter lee el código fuente completo y genera hipótesis de vulnerabilidad." |
| `hunter_completed` | "{hunter} completado — {n} hipótesis, {t1} Tier 1" | "Encontró {n} hipótesis. {t1} de Tier 1 (posible pérdida de fondos). {top_hyp_desc}" |
| `compile` | "Compilación {exitosa/fallida}" | "forge build {pasó sin errores / falló con N errores}. Los invariantes {están listos / necesitan corrección}." |
| `fuzz_phase` | "Phase {N} {iniciada/completada}" | Plantilla por phase (ver tabla abajo) |
| `finding` | "Finding detectado: {title}" | "Se detectó un posible bug: {title}. Severidad: {severity}. Confianza: {confidence}%." |
| `component_started` | "Iniciando componente #{n}: {name}" | "Componente {n} de {total} en el scope. {brief_desc} Prioridad {priority_reason}." |
| `component_completed` | "{name} completado" | "Checklist de 12 items completado. {n_findings} findings, {n_hyp} hipótesis analizadas." |
| `convergence` | "Convergencia detectada: {function}()" | "{count} hunters señalaron {function}() independientemente. Alta probabilidad de bug real." |

Narrativas de fuzzing por phase:
- Phase 1: "Foundry ejecutó {runs} runs aleatorios. Validación rápida de invariantes."
- Phase 2: "Medusa busca secuencias multi-paso que el fuzzing aleatorio no alcanza."
- Phase 3: "Fork de mainnet: confirmando findings contra contratos reales deployados."
- Phase 4: "Echidna maximiza el beneficio del atacante automáticamente."
- Phase 5: "Halmos prueba propiedades matemáticas para TODOS los inputs posibles."

### UI Sections

#### 1. Header
- Nombre del protocolo, plataforma, payout (del JSON)
- Toggle tema claro/oscuro (botones pill, localStorage)
- Indicador de auto-refresh (punto verde pulsante + "Auto-refresh 5s")
- Botón "Refrescar ahora" (POST `/api/refresh`)

#### 2. Barra de Progreso
- Barra horizontal con gradiente accent
- Label: "{done} / {total} componentes completados"
- Label derecho: "{n} findings · {confirmed} confirmados"

#### 3. Mapa de Componentes
- Grid responsive (auto-fill, minmax 260px)
- Cada card: icono estado (✓/▶/○) + nombre + LOC + prioridad
- Colores del borde izquierdo: verde (done), accent (active), gris (pending)
- **Click** → toggle `x-show` del panel de detalle de ese componente
- Solo un componente expandido a la vez

#### 4. Detalle del Componente (expandible, Alpine.js)

**4a. Checklist del Pipeline (12 items)**

Los 12 items corresponden exactamente a las keys del checklist en `ficha_template.yaml`. El dashboard mapea cada key a un label y descripción en español:

| Key YAML | Label | Descripción |
|----------|-------|-------------|
| `full_code_read` | Lectura completa del código | Se leyó cada línea del contrato para entender la lógica completa. |
| `protocol_model` | Modelo del protocolo | Documentado: qué hace, flujo de fondos, tokens, roles y dependencias externas. |
| `ai_invariants_generated` | Invariantes generados | N propiedades que NUNCA deberían romperse. Cada una con código Solidity y escenario de ataque. |
| `invariants_added_to_properties` | Invariantes en Properties.sol | Las N propiedades añadidas al contrato de testing Chimera, listas para fuzzear. |
| `handlers_added` | Handlers en TargetFunctions.sol | Funciones wrapper para cada función pública — el fuzzer las llama aleatoriamente. |
| `boundary_values` | Valores límite en handlers | 5% ceros, 5% unos, 5% máximos, 20% diminutos — los bugs de redondeo necesitan extremos. |
| `optimization_functions` | Funciones de optimización | Funciones optimize_* para Echidna: maximiza el beneficio del atacante automáticamente. |
| `compile_check` | Compilación — forge build | Verificando que todo compila sin errores antes de lanzar los fuzzers. |
| `foundry_fuzz` | Fuzzing Foundry (5,000 runs) | Primera pasada rápida (~2 min). Valida invariantes y detecta bugs obvios. |
| `findings_logged` | Findings documentados | Cada invariante roto se documenta en HUNT_TRACKER.md con severidad y análisis. |
| `tier1_separated` | Invariantes Tier 1 confirmados | Separar findings confirmados (pérdida de fondos) de dust/artefactos de mock. |
| `tolerance_tuned` | Tolerancias ajustadas | Clasificar cada fallo: bug real / redondeo / artefacto. Ajustar para explorar más profundo. |

Cada item muestra: icono (✓ done / ◉ active / ○ pending) + label + descripción en español.

**4b. Hunters (dinámico — 6 o 7 cards)**
- Grid responsive (auto-fill, minmax 190px)
- Cada card: nombre + dominio (español) + hipótesis count + tier 1 count + estado
- Dominios en español: "Overflow, redondeo, precios" / "Control de acceso, roles" / etc.
- **Click** → despliega lista de hipótesis con id, description, confidence, tier
- Colores: verde (completado), amarillo (en curso), gris (en espera)
- **Número de hunters dinámico**: `serve.py` lee las keys de `hunters_completed` de la ficha. Algunas fichas tienen 6 hunters, otras 7 (con TrustBoundaryHunter). El dashboard renderiza lo que exista sin hardcodear el número. El mapa de dominios en español está en `index.html` como diccionario estático para los 7 nombres conocidos.

**4c. Mapa de Convergencia**
- Lista de funciones señaladas por 2+ hunters
- Cada fila: nombre de función + bolitas por hunter (coloreada si flagged) + count + descripción breve
- Ordenado por count descendente (más convergencia = más interesante)

**Cómo se computa la convergencia en `serve.py`**:
Para cada componente, `serve.py` lee los archivos `hyp_{Component}_{Hunter}.yaml` y extrae nombres de funciones de dos fuentes en cada invariante:
1. El campo `solidity` — busca regex `function\s+(\w+)\(` en el código Solidity del invariante
2. El campo `description` — busca regex `\b(\w+)\(\)` (nombres de función con paréntesis)
Luego agrupa por función y cuenta cuántos hunters distintos la mencionan. Funciones con count >= 2 van al mapa de convergencia. Esto es heurístico pero funciona porque los invariantes casi siempre referencian la función que testean.

**4d. Pipeline de Fuzzing (5 phases)**
- Flex row horizontal con flechas →
- Cada phase: nombre + herramienta + descripción en español + estado
- **Estado derivado del checklist de la ficha**: si `foundry_fuzz: true` → Phase 1 done. Si `foundry_fuzz: false` pero `compile_check: true` → Phase 1 pending (listo para empezar). Las phases 2-5 no tienen tracking en la ficha actual, así que se muestran como "pending" a menos que el checklist esté completo.
- **No hay timers en tiempo real** (no hay data source). El dashboard muestra estados estáticos basados en el checklist. Si en el futuro se añade `fuzzing_phase1_executed`/`fuzzing_phase2_executed` a las fichas (ya existen en `run_hunt.py init_ficha`), se enriquecerá automáticamente.
- Colores: verde (done), gris (pending). Sin running/timer por ahora.

#### 5. Feed de Actividad (panel lateral)
- Panel derecho (340px) al lado del detalle del componente
- Scroll vertical, max-height con overflow
- Cada entrada: timestamp + evento + narrativa explicativa en español
- Tipos con iconos y colores: success (verde), info (azul), warning (amarillo), error (rojo)
- Generado por `serve.py` a partir de timestamps de archivos

#### 6. Findings (tabla global)
- Tabla con columnas: ID, Título, Severidad, Componente, Estado, Pipeline, Confianza
- Severidad con badges de color (critical/high/medium/low)
- Pipeline simplificado: NO dots por etapa (no hay data source que trackee las 9 etapas individuales). En su lugar, mostrar el `status` del finding como badge textual (PARKED / CONFIRMED / REPORTED / ACCEPTED / REJECTED). Si en el futuro se añade tracking de etapas al YAML, se puede enriquecer.
- **Click en fila** → expande con descripción completa del finding (campos del JSON: title, severity, component, status, confidence)

### Interactivity (Level 1 — Frontend Only)

Toda la interactividad es Alpine.js, sin llamadas POST:

| Acción | Implementación |
|--------|---------------|
| Click componente | `@click="expanded = expanded === name ? null : name"` + `x-show="expanded === name"` |
| Click finding | `@click="expandedFinding = expandedFinding === id ? null : id"` |
| Click hunter | `@click="expandedHunter = expandedHunter === name ? null : name"` |
| Hover pipeline dot | `title` attribute nativo del browser |
| Filtro estado | `x-model="filter"` + `x-show="filter === 'all' || comp.status === filter"` |
| Toggle tema | `@click="setTheme('dark')"` + `localStorage` |
| Auto-refresh | `x-init="setInterval(() => fetch('/api/dashboard').then(...), 5000)"` |

### Theme System

Dos temas con CSS custom properties, idénticos al mockup v3:
- **Dark**: fondo #0a0a0f, cards #0f0f18, texto #e0e0e0
- **Light**: fondo #f5f5f7, cards #ffffff, texto #1a1a2e
- Toggle persistido en `localStorage.hunt-theme`
- Transición suave (0.3s) al cambiar

### Responsive Layout

- **>= 1100px**: Two-column layout (detail + feed side-by-side)
- **< 1100px**: Single column, feed below detail
- Component grid: `auto-fill, minmax(260px, 1fr)` adapts automatically
- Hunter grid: `auto-fill, minmax(190px, 1fr)` adapts automatically

Solo 3 archivos. Sin build, sin node_modules, sin framework pesado.

```
hunt-dashboard/
  serve.py          ← HTTP server + /api/dashboard endpoint
  index.html        ← SPA completa (HTML + CSS + Alpine.js)
  alpine.min.js     ← Alpine.js bundled localmente (~15KB)
```

### Data Derivation Rules

- `confirmed_findings` count: computed from `findings` array filtering `status !== "PARKED"`, NOT from the `confirmed_findings` integer in `current_hunt.json` (which may be stale)
- `components_done` / `components_remaining`: read directly from `current_hunt.json` (authoritative source), NOT derived from `component_map` status (which may be out of sync)
- Hunter status (completed/waiting): read from ficha `hunters_completed` dict. "Running" state is NOT derivable — if a hunter's prompt file exists but `hunters_completed[hunter]` is false, show as "en curso" (heuristic, not guaranteed)

### Error Handling

| Scenario | Dashboard behavior |
|----------|-------------------|
| `current_hunt.json` missing | Show "No hay hunt activo" message, empty dashboard |
| `current_hunt.json` malformed | Show error banner with parse error, rest of dashboard empty |
| No fichas for current protocol | Component detail section shows "Sin ficha — ejecuta run_hunt.py" |
| YAML file malformed | Skip that file, log warning in server console |
| No hypotheses files | Hunters section shows 0 hipótesis per hunter |
| `hunt_session/` directory missing | All detail sections empty, component map still shows from `current_hunt.json` |

### Running

```bash
cd ~/Documents/Web3
python3 hunt-dashboard/serve.py
# → Serving on http://localhost:8080
# → Reading state from ~/.claude/MEMORY/STATE/current_hunt.json
# → Reading hunt_session/ for fichas, hypotheses, prompts
```

Flags opcionales:
- `--port 9090` — puerto alternativo
- `--hunt-dir /path/to/hunt_session` — directorio de hunt session (default: `./hunt_session`)
- `--state /path/to/current_hunt.json` — archivo de estado (default: `~/.claude/MEMORY/STATE/current_hunt.json`)

---

## What This Does NOT Include

- No ejecuta comandos del pipeline (Level 2 — futuro)
- No modifica ningún archivo
- No requiere base de datos
- No requiere node/npm/build
- No se integra con Bounty Radar (son herramientas independientes)
- No requiere deploy — es local only

---

## Success Criteria

1. `python3 hunt-dashboard/serve.py` arranca sin dependencias externas (Alpine.js bundled localmente)
2. El dashboard muestra datos reales de `current_hunt.json` + fichas + hipótesis
3. Auto-refresh funciona sin parpadeo visible
4. Tema claro/oscuro funciona y se persiste
5. Click en componente expande/colapsa su detalle
6. Feed de actividad muestra timeline con narrativas en español
7. Funciona en Firefox y Chrome
