# WIKI — Sistema de Bug Bounty Web3
> Referencia completa del sistema. Última actualización: 2026-03-20

---

## ÍNDICE

1. [Visión y Objetivo](#1-visión-y-objetivo)
2. [Arquitectura General](#2-arquitectura-general)
3. [Sistema Multi-Hunter — Diseño Final](#3-sistema-multi-hunter--diseño-final)
4. [Agent Teams — Claude Code](#4-agent-teams--claude-code)
5. [Knowledge Base — Base de Conocimiento](#5-knowledge-base--base-de-conocimiento)
6. [Pipeline de Fuzzing](#6-pipeline-de-fuzzing)
7. [Los 6 Hunters — Metodología](#7-los-6-hunters--metodología)
8. [Estructura de Ficheros](#8-estructura-de-ficheros)
9. [Herramientas Disponibles](#9-herramientas-disponibles)
10. [Hunt Workflow Completo](#10-hunt-workflow-completo)
11. [Estado Actual — Revert Lend](#11-estado-actual--revert-lend)
12. [Gaps Pendientes y Soluciones](#12-gaps-pendientes-y-soluciones)
13. [Reglas Inamovibles](#13-reglas-inamovibles)
14. [Quick Reference — Comandos](#14-quick-reference--comandos)

---

## 1. VISIÓN Y OBJETIVO

### El objetivo
Construir la maquinaria de bug hunting más efectiva posible, que mejore con cada uso. No un cazador genérico, sino el mejor hunter del mundo en cada categoría trabajando en equipo, de forma autónoma, sobre cualquier protocolo DeFi.

### La premisa central
- El 80% del conocimiento tácito de los mejores hunters está codificado en nuestras YAMLs, briefings, fichas y el feedback loop
- El 20% explícito se captura de sus blog posts, audit reports, y conference talks
- Con IA podemos replicar N especialistas trabajando en paralelo — algo imposible para cualquier equipo humano

### La métrica real
**Bugs aceptados / tiempo invertido**. Todo lo demás es infraestructura. La infraestructura no vale nada hasta que produce payouts.

### Principios inquebrantables
1. **No te engañes** — 0 findings honestos > 5 false positives
2. **El PoC es la verdad** — sin Foundry test que demuestre pérdida, no hay finding
3. **Sé específico o cállate** — "puede haber reentrancy" no es un finding
4. **Fork primero** — los mocks producen false positives, siempre confirmar en mainnet
5. **Prioriza implacablemente** — 80% de bugs críticos están en accounting, access control, oracle manipulation
6. **Mide y mejora** — sin datos no hay mejora

---

## 2. ARQUITECTURA GENERAL

```
┌─────────────────────────────────────────────────────────────┐
│                    BOUNTY RADAR                             │
│  Monitorea 6 plataformas + cambios de código en repos       │
│  Scoring: payout × expertise × competencia × freshness      │
│  Output: target con score 0-100 → PRIORITY / SKIP           │
└──────────────────────────┬──────────────────────────────────┘
                           │ target seleccionado
┌──────────────────────────▼──────────────────────────────────┐
│                 SISTEMA MULTI-HUNTER                        │
│         (Team Lead + 6-8 Teammates via Agent Teams)         │
│  L0→L4.5: Análisis paralelo por dominio                     │
│  L5: Fuzzing pipeline (serial, RAM constraint)              │
│  L6→L8: PoC, validación, feedback a knowledge base         │
└──────────────────────────┬──────────────────────────────────┘
                           │ findings confirmados
┌──────────────────────────▼──────────────────────────────────┐
│                  KNOWLEDGE BASE                             │
│  12 briefings por dominio (YAMLs con bug patterns)          │
│  Fichas por protocolo (experiencia específica)              │
│  Feedback loop: fichas → briefings → mejora continua        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. SISTEMA MULTI-HUNTER — DISEÑO FINAL

### Las 8 capas (L0-L8)

#### L0 — INTAKE + TRIAGE
**Qué hace:** Mapea el repo y decide si vale la pena el hunt completo.

**Inputs:** URL del repo, reglas del bounty
**Outputs:** Lista de componentes con priority score, target score global

**Priority score por componente:**
```
score = LOC × is_new_code × has_external_calls × money_flow_count
```

**Target score del bounty:**
```
score = payout_potential × (1/competition_density) × domain_strength × time_remaining
```

**Decisión:**
- Score > 70 → Agent Team completo
- Score 40-70 → Hunt estándar (un agente)
- Score < 40 → grep arsenal 30 min + pasar

---

#### L0.5 — COMPONENT CLASSIFIER
**Qué hace:** Para cada componente, detecta qué dominios son relevantes y asigna tier.

**Señales de activación por hunter (grep-based):**
| Hunter | Palabras clave que lo activan |
|--------|-------------------------------|
| MathHunter | balance, shares, interest, rewards, division, rounding, totalAssets |
| AccessHunter | role, owner, onlyOwner, require(msg.sender, governance, timelockk |
| FlowHunter | external call, callback, transfer, receive, call{, delegatecall |
| OracleHunter | price, twap, feed, getPrice, oracle, latestAnswer |
| DomainHunter | stake, unstake, gauge, reward, epoch, swap, pool, bridge |
| WildcardHunter | siempre en tier full |

**Tiers:**
- **Full** (score alto): 6 hunters + WILDCARD
- **Medium** (score medio): 3 hunters relevantes
- **Light** (score bajo): solo MathHunter

**Output:** mapa de componentes → hunters asignados + code sections pre-extraídas

---

#### L1 — ANALYST (2 pasadas)
**Qué hace:** Construye el Protocol Model verificado. Es el artefacto más crítico del sistema.

**Pasada 1 — Draft:**
Lee el código completo del componente. Genera:
```markdown
## State Variables
  [qué gestiona el contrato y sus invariantes asumidos]
## Money Flows
  [flujos con nombres exactos de funciones: deposit() → pool → borrow()]
## Trust Boundaries
  [quién puede llamar qué, roles, permisos]
## External Dependencies
  [contratos externos y cómo se interactúa]
## Pressure Points
  [donde se cruzan múltiples dominios — aquí viven los bugs]
  [incluye code snippets exactos]
## New Code [NEW]
  [funciones nuevas desde el último audit, marcadas explícitamente]
## Protocol Assumptions
  [qué cree el protocolo que siempre es verdad — los hunters atacarán esto]
```

**Pasada 2 — Verification:**
Un segundo agente lee código contra el modelo buscando omisiones:
- Funciones públicas no mencionadas en el modelo
- State variables sin explicar
- External calls no mapeados
- Añade lo que falta sin reescribir

**Output:** `hunt_session/models/{Component}_model.md` (verificado)

**Validación estructural automática:** contar funciones públicas en código vs menciones en modelo. Gap > 10% → el Verifier debe cubrirlas.

---

#### L2 — HUNTERS (6 tipos)
**Qué hace:** Genera hipótesis de ataque específicas por dominio.

**Cada hunter recibe:**
1. Protocol Model verificado (siempre)
2. Code snippets de pressure points de su dominio (extraídos en L0.5)
3. Briefing comprimido de su especialidad
4. Lista explícita de dominios que otros hunters cubren (para no duplicar)
5. WildcardHunter además recibe: lista de hipótesis ya generadas ("ya cubierto, no repetir")

**Cada hunter produce:**
- Hipótesis estructuradas (YAML) para patrones conocidos
- Hipótesis libres (texto) para observaciones creativas
- Auto-DA antes de emitir: cada hipótesis pasa el filtro "¿por qué estaría equivocado?"

**Escribe a su propio fichero** (append-only, sin file conflicts):
`hunt_session/hypotheses/hyp_{component}_{domain}.yaml`

**Formato hipótesis YAML:**
```yaml
- id: hyp-gauge-003
  hunter: StakingHunter
  domain: staking
  briefing_ref: staking.md/stk-007
  novel: false
  attack_scenario: >
    Atacante stakes posición, en el mismo bloque llama unstake,
    receives rewards de ese bloque sin haber esperado el periodo mínimo
  precondition: "stake() y unstake() ejecutables en el mismo bloque"
  if_true_severity: medium
  confidence: medium
  confidence_reason: "staking.md/stk-007 documenta este patrón en 3 protocolos"
  validation_target: "GaugeManager.sol::stake(), unstake(), _rewardPerToken"
  estimated_effort: low
```

**Nota sobre confidence:**
- `high` → requiere citar evidencia concreta en código o briefing
- `medium` → patrón documentado, condiciones plausibles
- `low` → especulativo, posible pero sin evidencia directa
- Hipótesis `novel: true` con `confidence: low` NO se descartan — tratamiento especial

---

#### L3 — PRIORITIZER
**Qué hace:** Ordena todas las hipótesis para el Validator.

**Score:** `severity_if_true × confidence × (1/effort)`

**Flags especiales:**
- `cross_component: true` → hipótesis referencia state de otro componente → prioridad alta
- `novel: true` → no filtrar por probabilidad baja → tratamiento especial en L4

**Output:** `hunt_session/prioritized/{component}_ordered.yaml`

---

#### L4 — VALIDATOR
**Qué hace:** Confirma o refuta cada hipótesis leyendo código específico.

**Lee:** code snippets del `validation_target` (NO el archivo completo)
**Produce:** binary plausible/implausible + razón obligatoria

**Si PLAUSIBLE:**
→ Escribe invariante en `Properties.sol` (formato Chimera)

**Si IMPLAUSIBLE:**
→ Propone `pending_briefing_update` con trampa → se aplica inmediatamente a briefing

**Para `novel: true`:** threshold de plausibilidad más bajo. Si hay cualquier duda razonable, pasa.

---

#### L4.5 — CROSS-HUNTER
**Cuándo corre:** Solo después de que TODOS los componentes tienen su Protocol Model.

**Qué hace:** Lee todos los Protocol Models simultáneamente buscando:
"Componente A asume que B garantiza X. Protocol Model de B dice que X puede fallar bajo condición Y."

**Estas intersecciones → candidatos a Critical findings**

Opera solo sobre modelos (no lee código). Sus hipótesis vuelven a L4 con prioridad alta.

**Output:** `hunt_session/cross_component/cross_hypotheses.yaml`

---

#### L5 — FUZZING PIPELINE
**Inamovible. Siempre secuencial. Nunca paralelo.**

```
1. Compile:     FOUNDRY_PROFILE=chimera forge build --build-info
2. Foundry Mock (5 min):   forge test --fuzz-runs 5000
                           → feedback rápido, valida que invariantes compilan
3. Tolerance Tuning (10 min): clasificar CADA fallo:
                           Real bug / Rounding dust / Mock artifact / Setup error
4. Foundry Fork (10 min):  BASE_RPC_URL=... forge test --match-contract ForkTester
                           → confirma en mainnet, elimina mock artifacts
5. Medusa (10 min):        medusa fuzz --config test/chimera/medusa.json --timeout 600
                           → bugs de secuencia multi-step
6. Echidna (10 min):       echidna . --contract CryticTester --config test/chimera/echidna.yaml
                           → maximizar profit del atacante
7. Halmos (5 min):         halmos (opcional, solo math pura)
```

**Feedback loop de fuzzing:**
- Medusa rompe invariante → extraer secuencia → reproducir en Foundry fork → PoC
- Foundry fork confirma → documentar en HUNT_TRACKER → escribir report
- Foundry fork rechaza → mock artifact → actualizar tolerancia → continuar
- Echidna maximiza profit → si positivo → trazar secuencia → PoC

---

#### L6 — POC WRITER
**Input:** invariante confirmado + counterexample trace de Medusa/Echidna
**Output:** Foundry test ejecutable con profit calculado

**Formato obligatorio:**
```solidity
function test_exploit_{component}_{finding_id}() public {
    // Setup: estado inicial necesario
    // Attack: secuencia exacta del exploit
    // Assert: profit > 0, pérdida demostrada
}
```

El PoC calcula profit exacto. Sin número concreto, no es un finding.

---

#### L7 — DEVIL'S ADVOCATE
**Cuándo:** Solo para findings confirmados por fuzzing. No para hipótesis especulativas.

**Recibe:** PoC + código fuente del componente + Protocol Model + reglas del bounty + known issues

**Output estructurado en 3 secciones:**
1. **Argumentos para rechazar:** "Un juez lo rechazaría porque..."
2. **Por qué no puede rechazarlo:** "Sin embargo, el código muestra..."
3. **Veredicto:** pass (reportar) / fail (descartar, documentar por qué)

---

#### L8 — FEEDBACK (inmediato tras cada componente)
**Es una tarea BLOQUEANTE en el Shared Task List.** El componente no se marca `completed` hasta que L8 esté `completed`.

**Qué hace:**
1. Lee `pending_briefing_updates` de la ficha del componente
2. Aplica updates a briefings inmediatamente
3. Actualiza métricas de hunter effectiveness
4. Promueve patrones vistos en 3+ fichas a nuevas bug entries en briefing
5. Registra false positives con razón explícita en campo `trampas`

---

## 4. AGENT TEAMS — CLAUDE CODE

### Estado
- **Activado:** `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` en `~/.claude/settings.json` ✅
- **Versión requerida:** v2.1.32+. Tenemos v2.1.72 ✅
- **Experimental:** funcionalidad real, no demo

### Cómo funciona
```
TEAM LEAD (Coordinator)
  └── analiza task, crea el equipo, orquesta
  └── Shared Task List en ~/.claude/tasks/{team-name}/
  └── Delegate Mode: solo coordina, no implementa

TEAMMATES (Hunters en nuestro caso)
  └── Proceso Claude Code independiente
  └── Context window propio de 1M tokens
  └── Acceso completo a tools (read, write, bash, etc.)
  └── Se comunican via SendMessage (peer-to-peer)
  └── Se asignan tasks del Shared Task List automáticamente
```

### Tools que desbloquea el flag
- `TeamCreate` — crea el equipo y lanza teammates
- `TaskCreate` — añade task al Shared Task List
- `TaskUpdate` — actualiza estado (pending/in_progress/completed)
- `TaskList` — lista tasks del equipo
- `SendMessage` — mensaje directo a teammate o broadcast

### Delegate Mode
Activar con `Shift+Tab`. El Lead solo puede:
- Gestionar tasks
- Enviar mensajes a teammates
- Revisar outputs

No puede escribir código ni ejecutar herramientas de análisis. **Crítico para que no intente hacerlo todo él mismo.**

### Limitaciones importantes
1. **No session resumption:** si el equipo se interrumpe, los teammates desaparecen. Solución: cada teammate escribe output a ficheros inmediatamente (nuestro diseño append-only resuelve esto)
2. **File conflicts:** dos teammates editando el mismo fichero = overwrites. Solución: hunters escriben a ficheros individuales (`hyp_{component}_{domain}.yaml`)
3. **No nested teams:** un Teammate no puede crear sub-teams. Puede usar Subagents normales
4. **Broadcasts costosos:** un broadcast llega a todos los teammates (coste × N teammates)

### Cómo mapea a nuestro sistema
```
Team Lead         = Coordinator (L0, L3, L7, L8)
Analyst Teammate  = L1 (Protocol Model)
Hunter Teammates  = L2 (uno por dominio)
CrossHunter       = L4.5 (corre al final)
Shared Task List  = L3 Prioritizer output
SendMessage       = comunicación hunter→hunter para cross-synthesis
```

---

## 5. KNOWLEDGE BASE — BASE DE CONOCIMIENTO

### Estructura de dos capas

```
CAPA 1: BRIEFINGS (conocimiento general)
  knowledge/vault-erc4626.md
  knowledge/lending.md
  knowledge/oracle.md
  knowledge/access-control.md
  knowledge/dex-amm.md
  knowledge/staking.md
  knowledge/flash-loan.md
  knowledge/bridge.md
  knowledge/token-erc20.md
  knowledge/proxy-upgrade.md
  knowledge/zk-circuits.md
  knowledge/signature-replay.md

CAPA 2: FICHAS (experiencia específica por protocolo)
  hunt_session/fichas/ficha_{Component}.yaml
  → se promueven a briefings cuando el patrón aparece en 3+ fichas
```

### Qué contiene cada briefing
Cada briefing tiene 3 secciones:

**1. Bugs Conocidos** (YAML entries):
```yaml
- id: vault-001
  pattern: share-inflation
  name: "First depositor share inflation"
  causa_raiz: "División entera trunca a 0 cuando totalSupply pequeño"
  como_funciona: "Atacante deposita 1 wei, dona tokens, siguiente depositor pierde todo"
  incidentes: [Euler 2023 $197M, Midas 2023]
  invariante: "shares_received > 0 para cualquier deposit > 0"
  que_mirar:
    - "¿Hay virtual shares/offset?"
    - "¿deposit() tiene mínimo?"
  como_se_arregla: "Virtual shares (OZ) o minimum deposit"
  trampas:
    - "Si usa virtual shares, NO es vulnerable"
    - "Mock vaults sin seed deposit dan falso positivo"
  severidad: critical
  confianza: alta
  tags: [erc4626, rounding, first-depositor]
  relacionado_con: [vault-002]
```

**2. Invariantes Clave** — qué debe ser siempre verdad

**3. Checklist Rápido** — qué mirar inmediatamente

### Fuentes integradas
- **DeFiHackLabs:** 175+ incidentes reales verificados
- **Cyfrin checklist:** 117 items mapeados a briefings
- **Solodit bulk:** 483 findings con contenido completo
- **Solodit full DB:** ~51K findings en `knowledge/solodit_all_findings.jsonl`
- **180+ YAML fichas** en `knowledge/solodit_cards/`

### Ciclo de aprendizaje (3 ciclos)
- **Cycle 0 (DONE):** Seed desde fuentes verificadas (Crytic, Trail of Bits, Maple V2)
- **Cycle 1 (DONE):** Enriquecimiento con DeFiHackLabs + Cyfrin + Solodit
- **Cycle 2 (ONGOING):** Aprender de cada audit → ficha → briefing

### Reglas del feedback loop
- Finding aceptado → nueva bug entry en briefing relevante
- Finding rechazado → nueva trampa en briefing (¿por qué fue rechazado?)
- False positive descartado → nueva trampa con razón exacta
- Patrón en 3+ fichas → promover a bug entry en briefing

---

## 6. PIPELINE DE FUZZING

### Herramientas y estado
| Herramienta | Versión | Estado |
|-------------|---------|--------|
| Foundry | v1.5.1 | ✅ Operativo |
| Medusa (Crytic) | v1.5.1 | ✅ Operativo |
| Echidna | v2.2.5 | ✅ Operativo (fix aplicado) |
| Halmos | v0.3.3 | ✅ Operativo |
| Slither | latest | ✅ Operativo |

### Fix de Echidna (OOM resuelto — 2026-03-20)
El problema era que `out-chimera/build-info/` no tenía la key `output` (construido sin `--build-info`).

**Fix aplicado:**
```bash
FOUNDRY_PROFILE=chimera forge build --build-info  # genera build-info completo
```

**echidna.yaml actualizado:**
```yaml
cryticArgs:
  - "--foundry-out-directory"
  - "out-chimera"
  - "--foundry-ignore-compile"  # usa artifacts pre-compilados, evita OOM
```

### Perfiles de Foundry (revert-lend)
```toml
[profile.chimera]   # para invariants: via_ir=true, out=out-chimera
[profile.crytic]    # NO viaIR (pero V3Vault.sol necesita viaIR → no funciona)
[profile.fork]      # para fork tests contra mainnet
```

### RPC Keys configuradas
- Base mainnet: `BASE_RPC_URL` en `revert-lend/.env`
- ETH mainnet: `ETH_RPC_URL` en `revert-lend/.env`
- Proveedor: Alchemy

### Formato Chimera (Properties.sol)
```solidity
// property_ prefix para assertion mode
function property_solvency() public view {
    t(vault.totalAssets() >= vault.totalLent(), "solvency broken");
}

// optimize_ prefix para optimization mode (maximizar profit atacante)
function optimize_attacker_profit() public view returns (int256) {
    return int256(attacker.balance) - int256(INITIAL_ATTACKER_BALANCE);
}
```

### Tolerancias (lecciones de Revert Lend)
- Solvency (balance + debt >= lent): hasta 1 USDC por 1000 operaciones
- Share price monotonicity: hasta 1 wei de bajada (rounding)
- Reserves vs cash: pueden divergir cuando todo está borrowed
- Health factor: necesita fork (mock oracle da falsos positivos)
- **Time advance:** máximo 7 días por step, 90 días total acumulado

---

## 7. LOS 6 HUNTERS — METODOLOGÍA

### MathHunter
**Referente:** Trust_90
**Metodología:**
1. Identifica el invariante económico central del componente
2. Enumera TODAS las formas de modificar assets sin modificar shares (o equivalente)
3. Para cada forma, calcula: ¿cuánto pierde el siguiente usuario?
4. Solo valida si hay pérdida concreta > gas cost del ataque
5. Descarta inmediatamente si hay virtual offset ≥ 1000 (share inflation)

**Patrones prioritarios:** rounding truncation acumulativa, donation attacks, interest calculation drift, share inflation, fee accounting mismatch

**Briefing:** `lending.md`, `vault-erc4626.md`

---

### AccessHunter
**Referente:** Mudit Gupta
**Metodología:**
1. Construye el grafo completo de privilegios del contrato
2. Identifica todos los paths que llevan a roles privilegiados
3. Busca paths indirectos (A llama B llama C que tiene el rol)
4. Verifica que cada función privilegiada tiene exactamente los checks necesarios
5. Busca inicialización de roles en constructores sin timelock

**Patrones prioritarios:** missing access control, privilege escalation paths, unprotected initializers, trust assumption violations, role misconfiguration on deploy

**Briefing:** `access-control.md`

---

### FlowHunter
**Referente:** samczsun (reentrancy methodology)
**Metodología:**
1. Mapea cada external call como un punto de reentrada potencial
2. En cada punto de reentrada: ¿qué estado está desincronizado?
3. ¿Puede un contrato malicioso explotar esa desincronización?
4. Verifica el orden: checks → effects → interactions
5. Casos especiales: ERC777 tokensReceived, ERC721 onReceived, flashloan callbacks

**Patrones prioritarios:** reentrancy via callback, cross-function reentrancy, read-only reentrancy, CEI violations, token callback abuse

**Briefing:** `flash-loan.md`, `token-erc20.md`

---

### OracleHunter
**Referente:** samczsun (oracle manipulation)
**Metodología:**
1. Identifica todos los puntos donde el precio es consumido
2. Para cada punto, traza hacia atrás hasta la fuente de precio
3. Pregunta: ¿puede la fuente ser manipulada en un solo bloque?
4. Calcula: con $X de flash loan, ¿cuánto puedo mover el precio? ¿Qué profit obtengo?
5. Verifica: ¿hay TWAP? ¿Cuántos segundos de observación? ¿Es suficiente?

**Patrones prioritarios:** spot price manipulation, TWAP with insufficient window, oracle staleness, cross-dex arbitrage attacks, multi-oracle inconsistency

**Briefing:** `oracle.md`, `dex-amm.md`

---

### DomainHunter
**Variable según el protocolo.**

Para protocolos de staking/gauges (como Revert Lend):
**Referente:** StErRo
**Metodología:**
1. Verifica invariante de proporcionalidad: dos actores con mismo stake reciben mismos rewards
2. Busca epoch boundary bugs: ¿qué pasa en el primer/último bloque de un epoch?
3. Flash loan staking: ¿puede alguien stakear y unstakear en el mismo bloque obteniendo rewards?
4. Verifica que los rewards no pueden ser "drenados" antes de que los usuarios los reclamen

**Briefing:** `staking.md`

---

### WildcardHunter
**Sin referente. Sin briefing.**

**Instrucción:**
"Todos los patrones conocidos están cubiertos por otros hunters. Tu misión es encontrar lo que nadie documentó antes. Lee el Protocol Model y las hipótesis ya generadas (para no repetir). Piensa como un atacante con $10M y motivación real. ¿Qué haría que rompiera este protocolo de una forma que ningún auditor buscaría?"

**Sus hipótesis tienen tag `novel: true` y NUNCA se filtran por baja probabilidad.**

---

## 8. ESTRUCTURA DE FICHEROS

### Proyecto principal
```
/home/kali/Documents/Web3/
├── knowledge/              # 12 briefings + solodit data
├── invariant-registry/     # 293 invariants JSON (13 categorías)
├── audit-agents/           # Python pipeline tools
├── chimera-template/       # Template de fuzzing reutilizable
├── BugBounty-Vault/        # Obsidian notes (legacy)
├── revert-lend/            # Hunt actual
└── WIKI.md                 # Este fichero
```

### Durante un hunt
```
hunt_session/
├── models/
│   └── {Component}_model.md      # Protocol Models (L1 output)
├── hypotheses/
│   ├── hyp_{comp}_math.yaml      # Hunter outputs (append-only)
│   ├── hyp_{comp}_access.yaml
│   ├── hyp_{comp}_flow.yaml
│   ├── hyp_{comp}_oracle.yaml
│   ├── hyp_{comp}_domain.yaml
│   └── hyp_{comp}_wildcard.yaml
├── prioritized/
│   └── {comp}_ordered.yaml       # Prioritizer output (L3)
├── fichas/
│   └── ficha_{Component}.yaml    # Experiencia acumulada (L8)
├── cross_component/
│   └── cross_hypotheses.yaml     # Cross-hunter output (L4.5)
└── metrics/
    └── hunt_metrics.json          # Métricas acumuladas
```

### Chimera (fuzzing harness)
```
revert-lend/test/chimera/
├── Properties.sol      # Invariantes (property_ + optimize_)
├── TargetFunctions.sol # Handlers de funciones públicas
├── Setup.sol           # Deploy del sistema completo
├── CryticTester.sol    # Entry point Medusa/Echidna
├── FoundryTester.t.sol # Entry point Foundry
├── ForkTester.t.sol    # Fork tests contra mainnet
├── medusa.json         # Config Medusa
└── echidna.yaml        # Config Echidna (fix OOM aplicado)
```

### Ficha por protocolo (formato)
```yaml
protocol: revert-lend
component: GaugeManager
file: src/automators/GaugeManager.sol
tier: full
audited: 2026-03-20

findings:
  - id: gauge-f01
    hunter: MathHunter
    briefing_ref: staking.md/stk-004
    confidence_at_hypothesis: high
    confirmed_by_fuzzing: true
    severity: medium
    poc_file: test/exploits/test_exploit_gauge_f01.sol

false_positives:
  - hunter: FlowHunter
    hypothesis: "reentrancy via onERC721Received"
    reason: "nonReentrant en todas las entry points"
    pending_briefing_update:
      action: add_to_trampas
      briefing: staking.md
      content: "Si nonReentrant en todas las entries, no pierdas tiempo en ERC721 callbacks"
```

---

## 9. HERRAMIENTAS DISPONIBLES

### Python Pipeline (audit-agents/)
| Herramienta | Función | Estado |
|-------------|---------|--------|
| `bounty_monitor_v2.py` | Escanea 6 plataformas bounty | ✅ 90% |
| `target_monitor.py` | Detecta cambios de código | ✅ 80% |
| `matcher.py` | Cruza código con registry | ✅ funcional, poco usado |
| `registry.py` | 293 invariants, 13 categorías | ✅ cargado |
| `scaffold.py` | Genera proyecto Foundry | ✅ funcional |
| `detection_engine.py` | Multi-layer detection | ✅ funcional |
| `poc_generator.py` | Template de PoC | ⚠️ parcial |
| `report_generator.py` | Formato C4/Immunefi/Cantina | ⚠️ parcial |

### Claude Code Skills (web3-bug-bounty-hunting-ai-skills/)
- `web3-grep-arsenal` — 10 bloques de grep para patrones comunes
- `web3-bug-classes` — 10 tipos de vulnerabilidad DeFi
- `web3-poc-foundry` — guía PoC con cheatcodes
- `web3-triage-report` — validación + 20 ejemplos pagados
- `web3-hunt-foundation` — recon, scoring, mindset
- `web3-ai-tools` — frameworks de automatización
- `web3-solidity-audit-mcp` — MCP server (Slither + Aderyn)

### Invariant Registry (293 invariants)
- `vault/` — 62 ERC4626 (Crytic + Euler)
- `lending/` — 124 lending (Maple + Euler)
- `token/` — 25 ERC20 (Crytic)
- `universal/` — 46 universales
- DEX: **VACÍO** (gap crítico)
- ZK: **escaso**

---

## 10. HUNT WORKFLOW COMPLETO

### Fase 0: Triage del target (5 min)
```
1. Leer reglas del bounty COMPLETAS
2. Identificar exclusiones y known issues
3. Calcular target score (payout × competencia × dominio × tiempo)
4. Si score < 40: grep arsenal 30 min y pasar
5. Verificar que el repo es el LIVE (no mirror de audit)
6. Identificar commit/tag especificado por el bounty
```

### Fase 1: Scope y setup (10 min)
```
1. Clone del repo especificado
2. Count LOC, identificar lenguajes
3. Map de arquitectura (qué contratos, qué hacen)
4. Research: audits anteriores, known issues, public reports
5. Buscar audit tag en git: git log --oneline --tags
6. git diff {audit_tag} HEAD → marcar código nuevo
```

### Fase 2: Por cada componente (checklist 12 pasos)
```
[ ] 1.  FULL CODE READ — cada línea, sin skim
[ ] 2.  PROTOCOL MODEL — L1 Analyst (2 pasadas)
[ ] 3.  AI INVARIANTS — L2 Hunters generan hipótesis
[ ] 4.  PROPERTIES.SOL — merge de invariants validados
[ ] 5.  HANDLERS — TargetFunctions.sol con todas las funciones públicas
[ ] 6.  BOUNDARY VALUES — clampAmount con 0, 1, max, edge cases
[ ] 7.  OPTIMIZE FUNCS — echidna optimize_* para economic attacks
[ ] 8.  COMPILE CHECK — forge build pasa
[ ] 9.  FOUNDRY FUZZ — mínimo 5000 runs, resultados documentados
[ ] 10. FINDINGS LOG — cada invariante roto en HUNT_TRACKER.md
[ ] 11. TIER 1 — findings confirmados separados de dust/known
[ ] 12. TOLERANCE — dust-level findings con tolerancia explícita
```

**REGLA #0: No empezar el siguiente componente hasta que los 12 estén marcados.**

### Fase 3: Validación y reporte
```
1. Para cada finding confirmado: Devil's Advocate
2. Para cada DA pass: escribir report
3. Formato según plataforma (C4, Immunefi, Cantina)
4. Solo reportar con > 50% de confianza
5. Incluir PoC ejecutable obligatoriamente
```

---

## 11. ESTADO ACTUAL — REVERT LEND

### Datos del bounty
- **Plataforma:** Cantina
- **Payout:** $50K total
- **Deadline:** 2026-03-25 (5 días restantes)
- **Repo:** branch `aerodrome-slipstream`, commit `2bb022e`
- **Scope:** 14 contratos, 5184 LOC

### Completado
- **V3Vault** (~1400 LOC): todos los 12 pasos ✅
  - Mock fuzzing: 50K runs pass
  - Fork fuzzing (Base mainnet): 10K runs pass
  - Medusa: bloqueado (constructor revert en setup)
  - Echidna: bloqueado (mismo motivo), pero OOM fix aplicado

### Finding confirmado
**F-01 — Medium: Insolvencia acumulativa por rounding**
- **Función:** `_calculateGlobalInterest()` en V3Vault.sol
- **Root cause:** 5 puntos de truncación en la misma función
- **Impacto:** `lent > balance + debt` crece superlinealmente con el tiempo
- **Confirmado:** gap > 10 USDC en 289 runs fork
- **Estado:** TO REPORT (no enviado aún — urgente antes del deadline)

### Lecciones aprendidas (mock artifacts)
- F-03 a F-06 eran todos mock artifacts
- Mock oracle subvalúa posiciones → falsos health failures
- Mock IRM produce 740%/día vs 5%/año en real
- **SIEMPRE fork mainnet para testing final**

### Componentes restantes (orden de prioridad)
1. **GaugeManager** (~400 LOC) — código NUEVO, máxima prioridad
2. **V3Oracle** (~350 LOC)
3. **AutoRangeAndCompound** (~300 LOC) — código NUEVO
4. **LeverageTransformer** (~200 LOC)
5-14. V3Utils, FlashloanLiquidator, AutoExit, etc.

### Vectores de ataque prioritarios para GaugeManager
- A: onERC721Received callback abuse (histórico Critical en protocolos similares)
- B: Staking/unstaking lifecycle (NUEVO código)
- C: Reward compounding flow (NUEVO código)
- D: Oracle pricing de posiciones Aerodrome
- E: Transform durante estado colateralizado
- F: Liquidación con posiciones staked

### Briefings relevantes para GaugeManager
- `knowledge/staking.md` (principal)
- `knowledge/dex-amm.md` (posiciones Aerodrome/Slipstream)
- `knowledge/access-control.md`

---

## 12. GAPS PENDIENTES Y SOLUCIONES

### Por gravedad

**Alta gravedad:**

| Gap | Solución |
|-----|---------|
| No session resumption en Agent Teams | Ficheros de output inmediatos por teammate (ya en diseño) |
| Protocol Model puede tener omisiones | Validación estructural: funciones públicas en código vs modelo |
| Feedback a briefings se salta | L8 es tarea BLOQUEANTE en Shared Task List |
| Sin diff automático (código nuevo) | L0 busca audit tags en git, marca `[NEW]` en Protocol Model |

**Media gravedad:**

| Gap | Solución |
|-----|---------|
| File conflicts en Properties.sol | `merge_invariants.py` script (no merge manual) |
| Devil's Advocate superficial | DA recibe TODO el contexto + output en 3 secciones |
| WildcardHunter genera ruido | Recibe lista "ya cubierto" de los otros hunters |
| Coste tokens sin control | `hunter_effectiveness` metrics post-hunt |

### Estado de construcción de capas

| Capa | Estado |
|------|--------|
| L0 INTAKE + TRIAGE | Parcial — bounty_monitor existe, falta priority score |
| L0.5 CLASSIFIER | ❌ No existe — construir |
| L1 ANALYST | No existe — eliminado en Phase 7 cleanup |
| L2 HUNTERS | ❌ No existe — V2 agents son la base |
| L3 PRIORITIZER | ❌ No existe — construir |
| L4 VALIDATOR | ❌ No existe — construir |
| L4.5 CROSS-HUNTER | ❌ No existe — construir |
| L5 FUZZING | ✅ Completo |
| L6 POC WRITER | Parcial — poc_generator.py existe |
| L7 DA | Parcial — template existe, no automatizado |
| L8 FEEDBACK | ❌ No existe como proceso automático |

---

## 13. REGLAS INAMOVIBLES

### Del sistema de fuzzing
1. **Fuzzing siempre secuencial** — Foundry → Fork → Medusa → Echidna. Nunca paralelo (RAM/solc compartido)
2. **Fork antes de Medusa** — los mock artifacts son la mayor pérdida de tiempo
3. **Tolerance tuning obligatorio** — clasificar CADA fallo antes de continuar
4. **forge build --build-info** — necesario para que Echidna cargue artifacts correctamente
5. **Time advance máximo:** 7 días/step, 90 días total

### Del proceso de hunting
6. **Un componente a la vez** — 12 pasos completos antes de moverse al siguiente
7. **PoC ejecutable = finding** — sin Foundry test, no hay bug
8. **Sé específico** — citar función, línea, y escenario concreto de ataque
9. **Solo reportar con > 50% de confianza**
10. **No clonar mirror de audits** — siempre el repo live especificado

### Del knowledge base
11. **L8 es bloqueante** — el componente no está completo hasta que el feedback se aplica
12. **trampas son tan valiosas como los bugs** — documentar los false positives es conocimiento real
13. **confianza: alta requiere evidencia** — citar la evidencia en el campo `confidence_reason`

### Del Agent Teams
14. **Delegate mode para el Coordinator** — si el Lead empieza a analizar código, algo está mal
15. **Ficheros individuales por hunter** — nunca dos hunters escribiendo al mismo fichero
16. **No nested teams** — Teammates usan Subagents, no TeamCreate

---

## 14. QUICK REFERENCE — COMANDOS

### Setup de un hunt
```bash
# Clonar y configurar
cd /home/kali/Documents/Web3
git clone {repo} {protocol-name}
cd {protocol-name}
git checkout {tag/commit}

# Configurar RPC (nunca commitear)
cp ../revert-lend/.env .env  # tiene BASE_RPC_URL + ETH_RPC_URL

# Verificar que compila con chimera profile
FOUNDRY_PROFILE=chimera forge build --build-info
```

### Fuzzing
```bash
# Foundry mock (rápido)
FOUNDRY_PROFILE=chimera forge test --fuzz-runs 5000 -vvv

# Foundry fork
FOUNDRY_PROFILE=chimera forge test --match-contract ForkTester --fuzz-runs 10000

# Medusa (usa artifacts pre-compilados de out-chimera)
medusa fuzz --config test/chimera/medusa.json --timeout 600

# Echidna (OOM fix aplicado)
echidna . --contract CryticTester --config test/chimera/echidna.yaml

# Halmos (math pura)
halmos --contract {ContractName} --function {mathFunction}
```

### Knowledge base
```bash
# Buscar bug en briefings
grep -r "donation attack" /home/kali/Documents/Web3/knowledge/

# Buscar en Solodit local
grep -i "gauge\|staking\|reward" knowledge/solodit_all_findings.jsonl | head -20

# Ver fichas de solodit para staking
ls knowledge/solodit_cards/ | grep -i staking
```

### Agent Teams (cuando esté implementado)
```bash
# El flag ya está activado en settings.json
# Verificar
echo $CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS  # → 1

# Display modes
claude --teammate-mode in-process   # todo en terminal
claude --teammate-mode split-panes  # requiere tmux
```

### Slither rápido
```bash
slither src/{Contract}.sol \
  --solc-remaps "@openzeppelin=lib/openzeppelin-contracts" \
  --filter-paths "lib/" \
  --checklist
```

---

*Wiki generada: 2026-03-20 | Sistema: v1.0 Multi-Hunter | Estado: Agent Teams activado, Echidna OOM resuelto, F-01 pendiente de report*
