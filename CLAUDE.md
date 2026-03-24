# Web3 Bug Bounty Hunting — Project Guidelines

## IDIOMA: Español

**OBLIGATORIO**: Responde SIEMPRE en español. Explica los conceptos técnicos en español, con ejemplos claros y directos. Si el usuario usa inglés, responde en español igualmente. La excepción son los fragmentos de código, nombres de funciones/variables, y términos técnicos específicos del dominio (e.g., "invariant", "reentrancy", "flash loan") que pueden dejarse en inglés.

---

## REGLA OBLIGATORIA: Presentación Formal de Findings

**CADA VEZ que se identifica un finding (cualquier severidad, cualquier componente):**

1. **Preséntalo al usuario INMEDIATAMENTE** — no lo dejes en el tracker y sigas adelante
2. **Explícalo con esta estructura exacta:**
   - **Qué es**: descripción en una frase
   - **Dónde**: contrato + función + línea exacta
   - **Cómo funciona el ataque**: paso a paso, concreto
   - **Impacto**: quién pierde qué y cuánto
   - **Confianza**: % y por qué
   - **¿Reportable?**: sí/no y a qué plataforma
3. **Espera confirmación** del usuario antes de continuar al siguiente componente
4. **Pipeline obligatorio para TODOS los findings (cualquier severidad)**:
   - Ejecuta `/redteam` con la severidad propuesta como input (no como decisión fija)
   - El RedTeam incluye Ronda 0 de calibración de severidad: puede subir, bajar, o confirmar — **siempre, sin excepción, también para Low/Info**
   - `/escalation-hunter` es opcional — úsalo cuando el finding tenga interacciones complejas entre componentes y quieras un análisis de severidad más profundo antes de RedTeam

**Esta regla NO tiene excepciones.** No vale mencionar el finding de pasada en un tracker y seguir. El usuario DEBE saber qué encontraste, cómo, y qué hacer con ello.

---

## MINDSET: Realismo Brutal — Sin Filtros

**Sé honesto, duro, y obsesivo con la mejora del sistema. El objetivo es encontrar vulnerabilidades REALES con el máximo nivel de fiabilidad. Nada más importa.**

### Principios inquebrantables:

1. **No te engañes.** Si un finding es débil, dilo. Si un invariante es genérico, descártalo. Si el fuzzing no encontró nada, no inventes. Mejor 0 findings honestos que 5 false positives que destruyen credibilidad.

2. **Autocrítica permanente.** Después de cada hunt, pregúntate:
   - ¿Qué bugs se me escaparon? ¿Por qué?
   - ¿Los invariantes eran realmente específicos o eran copypaste genéricos?
   - ¿Estuve fuzzeando código muerto o caminos que nadie usa?
   - ¿Perdí tiempo en rabbit holes por no entender el protocolo primero?

3. **La knowledge base no es un trofeo — es una herramienta.** 200 fichas YAML no sirven de nada si no se consultan en el momento correcto. 50K findings de Solodit no sirven si no sabemos buscar en ellos. Mide el sistema por bugs encontrados, no por cantidad de datos acumulados.

4. **Prioriza implacablemente.**
   - El 80% de los bugs críticos están en: accounting, access control, y oracle manipulation.
   - El 80% del tiempo se pierde en: setup, tooling, y findings que resultan ser "by design".
   - Ataca el 20% que produce el 80% del valor. Si llevas 2 horas sin progreso concreto en la SELECCIÓN de target, cambia de target. NOTA: esta regla aplica a la decisión de qué protocolo huntar, NO al pipeline intra-componente. Una vez dentro de un componente, RULE #0 prevalece: termina el checklist de 13 items antes de moverte.

5. **Sé específico o cállate.** "Puede haber un problema de reentrancy" no es un finding. "La función `withdraw()` en línea 142 permite reentrada vía el callback ERC777 `tokensReceived()` porque actualiza el balance después del transfer externo" SÍ lo es. Si no puedes ser así de preciso, no has entendido el código.

6. **El PoC es la verdad.** Si no puedes escribir un test Foundry que demuestre pérdida de fondos, no tienes un finding. Punto. Las descripciones teóricas no pagan bounties.

7. **Asume que eres el último auditor.** Trail of Bits, OpenZeppelin, y Cyfrin ya revisaron esto. Los bugs obvios ya se encontraron. Busca lo que ellos NO buscan: interacciones entre componentes, edge cases en valores extremos, assumptions incorrectas sobre el estado externo.

8. **Mide y mejora.** Track ratio de: findings enviados vs aceptados, tiempo por protocolo, categorías donde somos más/menos efectivos. Sin datos, no hay mejora.

9. **No confundas actividad con progreso.** Descargar 50K findings, crear 200 fichas, tener 12 briefings — todo eso es infraestructura. La métrica real es: ¿cuántos bugs válidos hemos encontrado? ¿cuánto dinero hemos ganado? Si la respuesta es "poco", la infraestructura necesita cambiar, no crecer.

10. **Cuando algo no funciona, CAMBIA.** Si el pipeline Medusa→Echidna→Foundry no encuentra nada en 3 targets seguidos, el problema no es mala suerte — es el approach. Revisa invariantes, revisa setup, revisa si estamos buscando donde hay bugs o donde es cómodo buscar.

### Anti-patrones a eliminar:

- **Optimismo falso**: "Este invariante probablemente encontrará algo" → Demuéstralo o descártalo.
- **Complejidad innecesaria**: Si un grep + lectura manual encuentra el bug más rápido que 30 min de setup de fuzzing, haz el grep.
- **Parálisis por análisis**: Leer el protocolo entero 3 veces sin escribir un solo invariante. Lee una vez, genera hipótesis, testea.
- **Cargo cult fuzzing**: Copiar invariantes de otro protocolo sin adaptarlos. Cada protocolo tiene SU lógica, SUS edge cases.
- **Aversión a abandonar**: Si después de 4 horas el target no da señales, muévete al siguiente. No todos los protocolos tienen bugs accesibles.

## MODO AUTÓNOMO — Regla de Operación Principal

**El usuario solo aporta el repositorio. Tú haces todo lo demás.**

### Cómo operar en cada sesión:

1. **Al iniciar sesión**: lee `~/.claude/MEMORY/STATE/current_hunt.json` (ruta canónica del estado activo). Si hay findings con `radar_id`, ejecuta `python3 audit-agents/sync_state.py` para traer cambios de Bounty Radar antes de continuar. Si hay un `current_component`, **empieza a huntar ese componente inmediatamente** sin esperar instrucción del usuario. Si el archivo no existe, lee `~/.claude/projects/-home-kali-Documents-Web3/memory/project_revert_lend_hunt.md` como fallback. **Para hunts NUEVOS** (sin `current_hunt.json`): el punto de entrada es `python3 audit-agents/scope_intake.py --repo <path> --platform <platform> --scope-text "..."` — esto crea el estado inicial y arranca el pipeline automáticamente.

2. **Ejecuta el pipeline completo de forma autónoma**:
   - Corre `python3 ~/Documents/Web3/audit-agents/run_hunt.py --component <X>` para preparar contexto
   - Usa el **Agent tool** para lanzar los 9 hunters en paralelo — SOLO para análisis de código (Fase 1). El fuzzing es SIEMPRE secuencial (Foundry → Medusa → Echidna comparten solc y RAM).
     - Hunters paralelos (9): AccessHunter, DomainHunter, FlowHunter, MathHunter, OracleHunter, TrustBoundaryHunter, WildcardHunter, SignatureHunter, **DoSHunter**
   - Cada sub-agente lee su prompt de `hunt_session/context/`, analiza el contrato, escribe `hyp_*.yaml`
   - Tras los 9 hunters, lanza el **DeepDiveHunter** (secuencial) — lee convergencias de los 9 hunters, genera máximo 5 hipótesis profundas en `hyp_{Component}_DeepDiveHunter.yaml`
   - Recoge los resultados, corre `merge_invariants.py`, compila, fuzzea secuencialmente
   - Documenta findings en HUNT_TRACKER.md y fichas YAML
   - Para findings Medium+: RedTeam (`~/.claude/skills/redteam.md`) con Ronda 0 de calibración de severidad. Si REPORT → dos acciones INDEPENDIENTES (orden no importa, son workflows paralelos):
     1. **ReportWriter** (`~/.claude/skills/report-writer.md`) → genera el markdown que se pega en Cantina/Immunefi/etc.
     2. **`report_finding.py --finding <ID>`** → registra en Bounty Radar desde el YAML (contenido distinto al markdown)
   - EscalationHunter (`~/.claude/skills/escalation-hunter.md`) → OBLIGATORIO para todo finding Medium+ — analiza escalación de severidad vía composability
   - Para findings Low/Info: RedTeam igualmente, Ronda 0 incluida (está integrada en el skill — no se puede omitir)
   - Si cualquier script del pipeline falla (exit code != 0), detente y notifica al usuario con el error completo antes de continuar.

3. **El usuario puede interrumpir en cualquier momento** para preguntar, redirigir, o pedir que mires un fichero específico. Responde y luego **vuelve al pipeline donde lo dejaste**.

4. **Toma decisiones sin pedir permiso** para: leer contratos, escribir invariantes, correr tests, actualizar trackers. Pide confirmación solo para: reportar un finding a la plataforma, hacer git push, o gastar tokens en contexto masivo (>50 contratos).

5. **Cuando termines un componente**: márcalo como completo en `current_hunt.json`, actualiza HUNT_TRACKER.md, llama a `apply_feedback.py`. **OBLIGATORIO: informa al usuario del resumen del componente (invariantes probados, findings, resultado) y espera confirmación explícita antes de pasar al siguiente componente.** El paso de componente NUNCA es automático.

6. **Si encuentras un finding confirmado en fork**: actualiza `current_hunt.json`, crea el PoC en Foundry, ejecuta RedTeam (incluye Ronda 0 de calibración de severidad). Si veredicto es REPORT, en este orden:
   1. **ReportWriter** → genera y guarda el markdown del reporte (reports/DRAFT-<ID>-<slug>.md)
   2. **`report_finding.py --finding <ID>`** → registra en Bounty Radar desde el YAML + manda Telegram
   3. Avisa al usuario con el path del reporte para que lo revise y submitee manualmente en la plataforma.

### Qué invocar internamente (no esperar que el usuario lo pida):
- `run_hunt.py` → al inicio de cada componente
- Agent tool (9 hunters paralelos: Access, Domain, Flow, Math, Oracle, TrustBoundary, Wildcard, Signature, DoS) → en el paso de análisis
- `halmos_property_generator.py <contract.sol>` → antes de Phase 5 Halmos, auto-genera `check_*` functions
- State Machine Model → OBLIGATORIO tras leer el código, antes de DeepDiveHunter. Modelar estados, transiciones, stuck states.
- `merge_invariants.py` → cuando los hunters terminen
- **`pipeline_gate.py --component X --gate <gate>`** → OBLIGATORIO entre cada fase. Si el gate falla, NO avanzar.
  - `--gate scope` → antes de lanzar hunters (verifica current_hunt.json, context, prompts, ficha)
  - `--gate hunters` → después de los 9 hunters (verifica que todos generaron YAML con solidity)
  - `--gate deepdive` → después de DeepDiveHunter (verifica hyp_*_DeepDiveHunter.yaml)
  - `--gate merge` → después de merge_invariants.py (verifica Properties.sol existe)
  - `--gate compile` → después de forge build (verifica artifacts en out/)
  - `--gate phase1` → después de Foundry 5K (verifica evidencia de fuzzing)
  - `--gate phase2` → después de Medusa 15 min (verifica corpus existe)
  - `--gate phase3` → después de Fork test (obligatorio si bounty >= $2K)
  - `--gate phase4` → después de Echidna optimization (obligatorio si optimize_* functions existen)
  - `--gate phase5` → después de Halmos proof (recomendado si funciones math puras existen)
  - `--status` → muestra dashboard completo del componente
  - `--mark <gate>` → marca gate manualmente cuando evidencia no es auto-detectable
- `apply_feedback.py` → al finalizar cada componente
- `/variant-hunt` → OBLIGATORIO después de cada finding confirmado. Buscar mismo root cause en todo el scope. NUNCA omitir.
- RedTeam (`~/.claude/skills/redteam.md`) → finding Medium+, incluye Ronda 0 de calibración de severidad (puede subir/bajar/confirmar)
- ReportWriter (`~/.claude/skills/report-writer.md`) → después de RedTeam REPORT. Genera el markdown del reporte (paso 1 — obligatorio antes de report_finding.py).
- `report_finding.py --finding <ID>` → después de ReportWriter. Registra en Bounty Radar, genera draft en la UI, manda Telegram (paso 2).
- `sync_state.py` (`/sincronizar_radar`) → al inicio de sesión si hay findings con radar_id. Trae cambios de bugbounty.0mnia.dev a current_hunt.json (ACCEPTED, REJECTED, PAID, payout).
- EscalationHunter (`~/.claude/skills/escalation-hunter.md`) → OBLIGATORIO para todo finding Medium+ — analiza escalación de severidad vía composability
- `run_hunt.py --status` → para actualizar contexto en cualquier momento
- DeepDiveHunter (secuencial, post-9 hunters) → genera hipótesis profundas basadas en convergencias
- ChimeraBuilder (sub-agente contexto limpio) → auto-genera setup de fuzzing si no existe `test/chimera/`
- `scope_intake.py --repo <path> --platform <platform> --scope-text "..." [--dry-run]` → al INICIAR un hunt nuevo. Genera `current_hunt.json` + fichas desde el repo + texto del bounty. Ordena componentes por LOC descendente. Auto-ejecuta `run_hunt.py` + `pipeline_gate --gate scope` para el primer componente.

## REGLA: Persistir Contexto Entre Sesiones

**OBLIGATORIO:** Guardar progreso, decisiones, y aprendizajes en la memoria persistente (`~/.claude/projects/-home-kali-Documents-Web3/memory/`) conforme se avanza. No esperar al final de la sesión. Cada decisión importante, cada gap identificado, cada componente construido debe guardarse inmediatamente para no perder contexto entre sesiones.

## System Architecture

### Knowledge Base: `BugBounty-Vault/` (Obsidian)
- `01-Vulnerabilities/` — Patterns by type, with real examples
- `02-Protocols-Studied/` — One note per protocol analyzed
- `03-Exploits-Studied/` — Real-world exploit reproductions
- `04-Tools/` — Cheatsheets for Foundry, Slither, etc.
- `05-CTF-Writeups/` — Practice challenge solutions
- `06-Submissions/` — All reports sent to bounties
- `07-Daily-Findings/` — Daily learnings from Solodit/audits
- `08-Report-Templates/` — Winning report examples by platform
- `09-Reference-Reports/` — Downloaded public bounty reports that won payouts

### Automated Tools: `audit-agents/`
- Python agents for Solidity scanning
- Foundry workspace for PoC testing
- Contract fetcher for Etherscan downloads

## Mindset: Think Outside the Box

- **Don't just run pattern matchers.** The obvious bugs have been found by automated tools and previous auditors.
- **Think like an attacker with $10M.** Flash loans, cross-contract interactions, timing attacks, economic exploits.
- **Combine bugs.** A Low + a Low can equal a Critical.
- **Question assumptions.** "This is by design" might actually be a bug.
- **Explore unconventional vectors** per chain:
  - Solidity: reentrancy, access control, integer overflow, proxy storage collision
  - Rust/Solana: account validation, PDA spoofing, remaining_accounts, CPI
  - CosmWasm: sudo abuse, submessage reentrancy, bank module, reply handlers
  - ZK circuits: missing constraints, range check gaps, Fiat-Shamir transcript issues
  - Cross-chain: message replay, timing desync, bridge trust assumptions

## THE LAW: Invariant Proving Engine (3-Layer Procedure)

**This procedure is MANDATORY for every target. No exceptions. Follow it exactly.**

### LAYER 1: AI UNDERSTANDS THE CODE (Claude reads deeply)

For EACH component in scope (ordered by LOC, largest first):

1. **Read the FULL source code** — no skimming, no summaries. Every line.
2. **Generate Protocol Model**:
   - What is this component? What does it do?
   - Where does money flow? (deposit → pool → borrow → repay)
   - What tokens does it handle?
   - What external calls does it make?
   - What roles/trust boundaries exist?
3. **Generate SPECIFIC invariants** (MINIMUM 10 per component, no upper limit — more is better):
   - Each invariant must have: natural language description + Solidity assertion code
   - Each invariant must answer: "If this breaks, what's the attack scenario?"
   - Use Chimera assertion helpers: `t()`, `eq()`, `gte()`, `lte()`
   - Priority: CRITICAL (fund loss) > HIGH (logic break) > MEDIUM (consistency)
4. **Generate handler functions** for each public/external function
5. **Generate ghost variables** for cumulative tracking (deposits, withdrawals, fees per user)
6. **Generate optimization functions** for Echidna (`optimize_*` → maximize attacker profit)

### LAYER 2: COMBINE INVARIANTS

1. **Registry match**: `python audit-agents/matcher.py <source_dir>` → top 20 generic invariants
2. **AI-generated**: 10+ specific invariants from Layer 1 (minimum 10, sin techo)
3. **Merge into Properties.sol** (Chimera format, deduplicated, max 25 total)
4. **Tag tiers**: Tier 1 (hard fail = confirmed bug) vs Tier 2 (needs review, dust tolerance)

### LAYER 3: FUZZ TO DEATH (Sequential pipeline — memory-safe)

**CRITICAL: Run tools SEQUENTIALLY, never in parallel. They share solc and RAM.**
**Foundry is MANDATORY for PoCs — contest platforms require it.**

**REGLA v4 — FUZZING MÍNIMO OBLIGATORIO:**
- **Phase 1 (Foundry 5K) + Phase 2 (Medusa 15 min) = SIEMPRE, sin excepciones.**
- Si el repo no tiene `test/chimera/`, lanzar sub-agente **ChimeraBuilder** (contexto limpio) para auto-generar el setup.
- ChimeraBuilder recibe: código fuente + invariantes merged + 7 invariantes universales + template Chimera.
- Compile-fix loop: max 9 intentos (PropertyGPT: 87% con 9 vs 63% con 3). Si falla → fallback a solo invariantes universales (3 intentos más). Si aún falla → BLOQUEAR hunt, notificar usuario.
- Phase 3 (Fork): obligatorio si bounty >= $2K (se lee de `current_hunt.json` campo `payout`) O si Phase 1/2 rompe invariante.
- Phase 4-5: solo post-finding confirmado.

#### Pipeline order (v3 — Medusa promovida a Phase 2):

**Principio: feedback rápido → secuencias → contratos reales → maximización.**

1. **Compile**: `FOUNDRY_PROFILE=chimera forge build --build-info` (chimera profile for invariants)
2. **Phase 1 — Foundry Mock Quick (5 min)**: `FOUNDRY_PROFILE=chimera forge test --fuzz-runs 5000`
   - Foundry FIRST: mejores mensajes de error, feedback inmediato
   - Valida que invariantes compilan y tienen sentido — si falla aquí, arregla antes de continuar
   - **Tune tolerancias aquí**: Real bug / Rounding dust / Setup error → clasificar y ajustar
3. **Phase 2 — Medusa Stateful (15 min)**: `medusa fuzz --config test/chimera/medusa-<component>.json --timeout 900`
   - Medusa SEGUNDA: corre sobre invariantes ya validados por Foundry (sin noise de dust)
   - Su fuerza: bugs de SECUENCIA multi-step que Foundry random-walk no alcanza
   - Corpus persistente: guarda secuencias interesantes entre runs
   - Si rompe invariante → extraer call sequence → reproducir en Foundry fork
   - **Por qué aquí y no al final**: secuencias complejas necesitan confirmación en fork; si Medusa encuentra algo, el fork lo confirma inmediatamente en el paso siguiente
4. **Phase 3 — Foundry FORK Deep (10 min)**: `BASE_RPC_URL=... forge test --match-contract ForkTester --fuzz-runs 10000`
   - CONTRATOS REALES: IRM, oracle, pools, gauges desde mainnet fork
   - Confirma findings de Phase 1+2 (elimina mock artifacts de una vez)
   - Pin a bloque específico para reproducibilidad
5. **Phase 4 — Echidna Optimization (10 min)**: `echidna . --contract CryticTester --config test/chimera/echidna.yaml`
   - Modo optimización: maximizar profit del atacante (`optimize_*` functions)
   - Solo después de invariantes tuneados y confirmados en fork
6. **Phase 5 — Halmos Proof (5 min)**: `~/.local/bin/halmos --function check_ --loop 10 --solver-timeout-assertion 10000`
   - Symbolic execution: prueba propiedades para TODOS los inputs posibles (bounded)
   - Ideal para funciones math puras: share price calculation, fee computation, exchange rates
   - **Auto-generar con**: `python3 audit-agents/halmos_property_generator.py <contract.sol> --output test/halmos/HalmosCheck_<Component>.sol`
     - Detecta funciones pure/view con aritmética y genera: no-revert, monotonicity, zero-safety, round-trip, precision-bound
     - Detecta pares bidireccionales (convertToShares↔convertToAssets, wMulDown↔wDivDown) → round-trip automático
   - Escribir funciones `check_*` que llaman la función math + assert el invariante
   - Si Halmos encuentra counterexample → PoC inmediato (input exacto que rompe la propiedad)
   - NO usar para funciones con dependencias externas (oracles, callbacks) — solo math pura

**Rationale del orden**:
- Foundry primero: 10x mejor error reporting, detecta invariantes rotos en segundos
- Medusa segundo: secuencias valiosas pero necesitan invariantes sanos primero (sin dust = sin noise)
- Fork tercero: una sola pasada confirma/descarta tanto findings de Foundry como de Medusa
- Echidna al final: optimización tiene más valor cuando el espacio ya está explorado

#### Feedback loop:
- **Medusa breaks invariant** → extract call sequence → reproduce in Foundry fork → write PoC
- **Foundry fork confirms** → document in HUNT_TRACKER → write report
- **Foundry fork rejects** → mock artifact, update tolerance, continue
- **Echidna maximizes profit** → if positive, trace the sequence → PoC

**If something BREAKS an invariant → it IS the bug. The counterexample IS the PoC.**

### TRACKING (mandatory)

- Create `HUNT_TRACKER.md` in repo root for every target
- Track: component status, invariants tested, findings, fuzzing results
- Update after every component and every fuzzing session
- Log ALL findings (even Low/QA) with severity assessment

### RULE #0.5: CROSS-COMPONENT HUNT — MANDATORY AFTER EVERY 2-3 RELATED COMPONENTS

**After completing 2-3 related components, ALWAYS run a dedicated cross-component hunt BEFORE moving to unrelated components.**

The component-by-component approach catches individual bugs but misses interaction-surface bugs — often the most valuable ones (VV-O-02 was a V3Vault×GaugeManager interaction). Individual component mocks hide real call paths.

#### Protocol: Cross-Component Hunt Session

**Trigger**: After completing component N, if component N calls or is called by a previously completed component.

**Step 1 — Map the interaction surface** (15 min):
```
For each pair (A, B) of completed components:
  - List every function A calls on B
  - List every function B calls on A
  - List shared state / shared tokens / shared NFT custody
  - List assumptions A makes about B's behavior (and vice versa)
```

**Step 2 — Launch EdgeHunters** (parallel agents, one per high-value edge):
Each EdgeHunter gets: full source of BOTH components + specific interaction edge to analyze.
Ask: "What breaks if component B behaves unexpectedly at this call site?"

**Step 3 — Multi-component fuzzing setup** (warranted cuando: al menos un EdgeHunter encuentra una hipótesis Tier 1, o cuando la superficie de interacción implica transferencia de fondos o cambio de estado crítico entre contratos):
Build a `MultiComponentSetup.sol` that deploys BOTH real contracts (not mocks) together.
Add interaction handlers: sequences that span both components.
Run 5000+ fuzz runs on cross-component invariants.

**Step 5 — Si se encuentra un finding**: entra en el FINDING PIPELINE COMPLETO desde el paso 1.
El cross-component hunt es un mecanismo de descubrimiento — el finding resultante es un finding nuevo y requiere el pipeline completo (Mock→Medusa→Fork→PoC→Echidna→EscalationHunter→RedTeam→VerifyCode→Report).
EscalationHunter es especialmente relevante aquí porque el finding ES cross-component por definición.

**Step 4 — Interaction invariants** (add to Properties.sol):
```
- tokenId custody: NFT is EITHER in vault OR in gauge, never neither, never both
- debt conservation: debtSharesTotal unchanged by stake/unstake/compound
- health consistency: position healthy pre-stake → must remain healthy post-stake
- reward conservation: AERO claimed ≤ AERO earned by gauge
```

#### Known high-value interaction surfaces for Revert Lend:

| Edge | Risk | When to hunt |
|------|------|-------------|
| V3Vault × GaugeManager | High — staking/liquidation/compound | After GaugeManager done ← NOW |
| V3Vault × LeverageTransformer | Critical — flash loans on collateral | After LeverageTransformer done |
| V3Vault × AutoRangeAndCompound | High — rerange changes position value mid-debt | After AutoRangeAndCompound done |
| V3Vault × V3Oracle | High — pricing assumptions | After V3Oracle done |
| GaugeManager × V3Oracle | Medium — TWAP shared | After V3Oracle done |
| All Transformers → V3Vault | High — debt accounting during transform | After all transformers done |

---

### Finding Queue — Gestión Automática de Findings Descubiertos

**Variant Hunt, Cross-Component, y Hunter Spillover generan findings nuevos que entran en una cola para no interrumpir el componente actual:**

```bash
# Añadir variant finding
python3 audit-agents/pipeline_gate.py --queue-finding --source variant --parent PL-M-01 --title "Same pattern in X" -c ComponentName --severity medium

# Añadir cross-component finding
python3 audit-agents/pipeline_gate.py --queue-finding --source cross-component --components "Vault,Gauge" --title "Interaction bug" --severity high

# Ver la cola
python3 audit-agents/pipeline_gate.py --list-queue

# Actualizar estado de un item
python3 audit-agents/pipeline_gate.py --queue-update PL-M-01-V1 --qstatus in_pipeline

# Promover a findings activos (solo si status=completed)
python3 audit-agents/pipeline_gate.py --queue-promote PL-M-01-V1
```

**Reglas de la cola:**
- La cola se procesa ENTRE componentes, no interrumpiendo el componente actual
- Cada item en la cola pasa por el FINDING PIPELINE COMPLETO antes de reportarse
- Status lifecycle: `pending_pipeline` → `in_pipeline` → `completed` → `moved_to_findings` (o `dismissed`)
- IDs auto-generados según origen: variants → `PL-M-01-V1`, cross-component → `XC-Gauge-Vault-01`, spillover → `MATH-Factory-01`
- **PoC Fork Gate**: todas las PoCs deben usar `vm.createFork`/`vm.selectFork`. PoCs solo con mocks son rechazadas por el gate `poc`. Excepción: campo `pre_launch: true` en `current_hunt.json` (protocolo no deployado).

---

### RULE #0: ONE COMPONENT AT A TIME — FINISH COMPLETELY BEFORE MOVING ON

**This is the most important rule. NEVER skip to another component until the current one is 100% done.**

A component is DONE only when ALL of these are checked off:

```
COMPONENT COMPLETION CHECKLIST (mandatory for each file):
[ ] 1. FULL CODE READ — every line read and understood
[ ] 2. PROTOCOL MODEL — what it does, money flows, trust boundaries documented
[ ] 2.3. STATE MACHINE MODEL — generado por FlowHunter automáticamente:
       └─ FlowHunter produce FSM en su hyp_*.yaml (estados, transiciones, anomalías)
       └─ DeepDiveHunter lo consume en Sección 4 para buscar attack paths
       └─ VERIFICAR que el FSM está en el output de FlowHunter antes de lanzar DeepDive
       └─ Si FlowHunter no lo incluyó → DeepDiveHunter lo construye como fallback
[ ] 2.5. DEEPDIVE HUNTER — ejecutado secuencialmente tras los 9 hunters, máximo 5 hipótesis profundas
[ ] 3. AI INVARIANTS GENERATED — MINIMUM 10 specific invariants in Chimera format (no upper limit)
[ ] 4. INVARIANTS ADDED TO Properties.sol — Solidity code, compiles
[ ] 5. HANDLERS ADDED TO TargetFunctions.sol — all public functions covered
[ ] 6. HANDLERS USE BOUNDARY VALUES — _clampAmount with 0, 1, max, edge cases
[ ] 7. OPTIMIZATION FUNCTIONS — Echidna optimize_* for economic attacks
[ ] 8. COMPILE CHECK — `forge build` passes
[ ] 9. FOUNDRY FUZZ — minimum 5,000 runs, all results recorded
[ ] 10. FINDINGS LOGGED — every broken invariant documented in HUNT_TRACKER.md
[ ] 11. TIER 1 INVARIANTS — confirmed findings separated from dust/known issues
[ ] 12. TOLERANCE TUNED — dust-level findings have explicit tolerance, not blocking deeper exploration
```

**DO NOT start reading the next component until all 13 boxes are checked.**
**DO NOT skip any step. DO NOT say "we'll come back to it".**
**If a step fails, FIX IT before moving on.**

### ENFORCEMENT DETERMINISTA — pipeline_gate.py (OBLIGATORIO)

**Ejecutar `pipeline_gate.py` en estos puntos exactos del pipeline:**

```
COMPONENT PIPELINE (10 gates):
Antes de lanzar hunters:  python3 audit-agents/pipeline_gate.py -c <Component> --gate scope
Después de 9 hunters:     python3 audit-agents/pipeline_gate.py -c <Component> --gate hunters
Después de DeepDive:      python3 audit-agents/pipeline_gate.py -c <Component> --gate deepdive
Después de merge:         python3 audit-agents/pipeline_gate.py -c <Component> --gate merge
Después de forge build:   python3 audit-agents/pipeline_gate.py -c <Component> --gate compile
Después de Foundry 5K:    python3 audit-agents/pipeline_gate.py -c <Component> --gate phase1
Después de Medusa 15min:  python3 audit-agents/pipeline_gate.py -c <Component> --gate phase2
Después de Fork test:     python3 audit-agents/pipeline_gate.py -c <Component> --gate phase3
Después de Echidna:       python3 audit-agents/pipeline_gate.py -c <Component> --gate phase4
Después de Halmos:        python3 audit-agents/pipeline_gate.py -c <Component> --gate phase5
Antes de next component:  python3 audit-agents/pipeline_gate.py -c <Component> --status

FINDING PIPELINE (6 gates):
Después de PoC:           python3 audit-agents/pipeline_gate.py --finding <ID> --fgate poc
Después de Escalation:    python3 audit-agents/pipeline_gate.py --finding <ID> --fgate escalation
Después de Variant Hunt:  python3 audit-agents/pipeline_gate.py --finding <ID> --fgate variant
Después de RedTeam:       python3 audit-agents/pipeline_gate.py --finding <ID> --fgate redteam
Después de Verify Code:   python3 audit-agents/pipeline_gate.py --finding <ID> --fgate verify
Después de ReportWriter:  python3 audit-agents/pipeline_gate.py --finding <ID> --fgate report
Antes de enviar:          python3 audit-agents/pipeline_gate.py --finding <ID> --fgate reportable
```

**Si un gate falla → NO avanzar. Arreglar primero.** El gate es acumulativo: cada gate verifica todos los anteriores.
**Si un gate no puede detectar evidencia automáticamente** (ej: Foundry se ejecutó pero no queda cache):
```
python3 audit-agents/pipeline_gate.py -c <Component> --mark phase1
```

Update HUNT_TRACKER.md with the component status after completing the checklist.

### FORK vs MOCK RULES

**RULE: ALWAYS fork mainnet/testnet for DeFi protocols. NEVER use mocks for final testing.**

Mocks are PROVEN to cause false positives and waste time:
- Mock oracles undervalue positions → false health failures (Revert Lend F-06: wasted hours)
- Mock interest rate models produce extreme rates → inflated rounding drift (Revert Lend: 740%/day vs 5%/year real)
- Mock positions don't change value → can't test realistic collateral changes
- Mock gauges don't accrue real rewards → can't test compound/claim flows
- **Lesson learned**: Revert Lend session — 4 out of 6 "findings" (F-03 to F-06) were mock artifacts. Only F-01 survived.

**Fork setup (MANDATORY):**
```bash
# .env (NEVER commit to git)
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# In Foundry test
uint256 forkId = vm.createFork(vm.envString("BASE_RPC_URL"), FORK_BLOCK);
vm.selectFork(forkId);

# Pin to specific block for reproducibility
# Find a good block with active positions and liquidity
```

**We have Alchemy keys configured for: ETH mainnet, Base mainnet, Optimism mainnet.**

**Mocks are ONLY acceptable for:**
- Protocol not yet deployed on any chain (pre-launch audit)
- Testing pure math logic that doesn't depend on external state
- **Phase 1 del pipeline (Foundry Mock Quick, 5 min)** — es el paso inicial de validación de invariantes antes de Medusa. Es la excepción explícita y permitida.
- **ALWAYS migrate to fork before running final fuzzing passes (Phase 3)**

### TOLERANCE TUNING (mandatory 2-pass approach)

1. **Pass 1 (strict)**: Run with zero tolerance. Document EVERY failure.
2. **Classify each failure**: Real bug / Rounding dust / Mock artifact / Test artifact
3. **Pass 2 (tuned)**: Set tolerances for known dust. Explore DEEPER for real bugs.

**Without tuning, the first rounding failure blocks discovery of all deeper bugs.**

Tolerance guidelines:
- Solvency (balance + debt >= lent): allow up to 1 USDC per 1000 operations
- totalAssets vs balance: allow up to 1 USDC per 1000 operations
- Share price monotonicity: allow 1 wei decrease (rounding)
- Reserves: can exceed cash when all liquidity is borrowed (virtual reserves)
- Health factor: needs fork (mock oracle artifacts)

### TIME ADVANCE LIMITS

- **Per step**: max 7 days
- **Total accumulated**: max 90 days
- Without cap, interest explosion makes ALL accounting invariants fail — not a bug, unrealistic conditions

### KEY RULES

- **Boundary value injection**: 5% zeros, 5% ones, 5% max, 20% tiny — rounding bugs need small values
- **15 precise invariants > 200 vague ones** — fewer = more fuzzing cycles where it matters
- **Medusa primary** (2x more effective than Foundry), Echidna optimization mode for economic attacks
- **Corpus persistent** — save between sessions, seed with known attack patterns
- **3 actors**: honest user, attacker (high balance), keeper/liquidator
- **Every invariant must have an attack scenario** — if you can't describe how violating it causes fund loss, it's noise
- **Compile-fix loop**: generate → compile → fix errors → recompile (max 9 retries — PropertyGPT demostró +24% compilabilidad con 9 vs 3)

---

## FINDING PIPELINE OBLIGATORIO — Checklist Anti-Reporte-Prematuro

**REGLA DE ORO**: Un finding NO puede reportarse hasta completar las 9 etapas.
Ninguna es opcional para findings Medium+. Si una etapa no se puede completar (e.g., protocolo no deployado), documentar explícitamente por qué y obtener confirmación del usuario.

**CADA VEZ QUE SE PROPONGA REDACTAR UN REPORTE**, Claude debe mostrar este checklist con el estado actual del finding ANTES de escribir una sola línea del reporte:

### ⚠️ REGLA CRÍTICA DE SEGURIDAD JURÍDICA

**NUNCA ejecutar transacciones contra contratos REALES en mainnet/testnet con fondos reales.**
Hacerlo es ILEGAL — equivale a robar fondos de usuarios reales aunque sea "para probar".

**Las únicas formas legales de probar un bug son:**
1. **PoC con mocks** (Foundry + contratos simulados) → siempre legal, SUFICIENTE para bounties
2. **Fork local con Foundry** (`vm.createFork(rpcUrl)`) → lee estado de la chain pero ejecuta TODO localmente, nunca mueve fondos reales → también legal

**Lo que JAMÁS se hace:**
- Llamar directamente a un contrato deployed con una wallet real para explotar el bug
- Enviar transacciones que muevan fondos de otros usuarios, aunque sea "para verificar"
- Usar `cast send` o scripts de deploy contra mainnet para probar un exploit

**Un PoC Foundry con mocks que demuestra la lógica del bug con assertions duras ES SUFICIENTE para cualquier bug bounty.** Los jueces de Cantina/Immunefi/Code4rena aceptan PoCs de Foundry con mocks o fork locales — nunca piden "ejecuta el exploit en mainnet".

---

```
FINDING PIPELINE — [NOMBRE DEL FINDING]
════════════════════════════════════════
[ ] 1.  CÓDIGO LEÍDO — Cada línea relevante, entendida en contexto
[ ] 2.  INVARIANTE GENERADO — Solidity assertion en Properties.sol, compila

        ── FUZZING (orden obligatorio: Phase 1 → 2 → 3 → 4) ──────────────
[ ] 3.  FOUNDRY MOCK QUICK (Phase 1) — min 5,000 runs con mocks
        └─ Valida que el invariante compila y tiene sentido. Feedback inmediato.
[ ] 4.  TOLERANCE TUNING — clasifica cada fallo: real bug / rounding dust / mock artifact
[ ] 5.  MEDUSA STATEFUL (Phase 2) — min 10 min, corpus guardado
        └─ Fuerza: secuencias multi-step que Foundry random-walk no alcanza
[ ] 6.  FOUNDRY FORK + POC (Phase 3) — fork local vm.createFork(), contratos reales
        └─ Confirma findings de Phase 1+2. PoC con assertions duras (PASS obligatorio)
        └─ NUNCA: transacciones reales en mainnet — ILEGAL
[ ] 7.  ECHIDNA OPTIMIZATION (Phase 4) — optimize_* functions, min 10 min
        └─ Maximiza profit del atacante. Solo útil con invariantes ya tuneados.
[ ] 7.1 HALMOS PROOF (Phase 5) — check_* functions en math pura, 5 min
        └─ Symbolic execution: prueba TODOS los inputs. Solo para funciones math puras.
        └─ Comando: ~/.local/bin/halmos --function check_ --loop 10
        └─ Si encuentra counterexample → PoC con input exacto
        ────────────────────────────────────────────────────────────────────

[ ] 7.5 ESCALATION HUNTER (OBLIGATORIO) — ejecutar SIEMPRE para todo finding Medium+
        └─ Analiza si el finding escala a mayor severidad por interacciones cross-component
        └─ Incluso findings single-component pueden tener impacto amplificado vía composability
        └─ Output: escalation_analysis en el hyp YAML (campo escalation_verdict)
[ ] 7.6 VARIANT HUNT (OBLIGATORIO) — `/variant-hunt` después de cada finding confirmado
        └─ Busca el MISMO root cause en todo el scope (todos los contratos, no solo el actual)
        └─ Trail of Bits: 1 finding → 3-5 variantes en promedio
        └─ Buscar: mismo patrón de missing validation, misma asimetría, mismo math error
        └─ Cada variante encontrada entra como finding NUEVO en el pipeline desde paso 1
        └─ NUNCA omitir — es la forma más eficiente de multiplicar findings
[ ] 8.  REDTEAM — 4 atacantes (JUDGE/DEVIL/GUARD/ECONOMIST), Ronda 0 siempre incluida
        └─ Ronda 0 es obligatoria para TODA severidad (también Low/Info) — calibra antes de atacar
        └─ Resultado debe ser REPORT o REPORT_DOWNGRADED (no DO_NOT_REPORT)
[ ] 9.  VERIFY CODE — verificación estática del código deployed (SIN ejecutar nada):
        └─ Buscar contrato en Etherscan/Basescan y confirmar que está verified
        └─ Comparar que las funciones afectadas existen en la versión deployed
        └─ Verificar que no hay un fix reciente en el repo que mitigue el bug
        └─ Comprobar que el feature (e.g., gaugeManager) está activado on-chain
[ ] 10. REPORT WRITER — solo si RedTeam dice REPORT o REPORT_DOWNGRADED
        └─ Genera reports/DRAFT-<ID>-<slug>.md — obligatorio ANTES de report_finding.py
[ ] 11. report_finding.py --finding <ID> — registra en Bounty Radar + manda Telegram
        └─ Solo después de ReportWriter. Nunca antes.

RESULTADO: [ ] APTO PARA REPORTE  /  [ ] BLOQUEADO — faltan etapas: [lista]
```

**Si cualquier etapa tiene ❌, Claude debe decir:**
> "⛔ [Finding X] NO puede reportarse. Falta(n): [etapa(s)]. Ejecutar antes de continuar."

### ENFORCEMENT DETERMINISTA — pipeline_gate.py para findings (OBLIGATORIO)

**ANTES de escribir un reporte, ejecutar:**
```
python3 audit-agents/pipeline_gate.py --finding <ID> --status
```

**Después de cada etapa del finding pipeline:**
```
Después de PoC:           pipeline_gate.py --finding <ID> --fgate poc
Después de Escalation:    pipeline_gate.py --finding <ID> --fgate escalation
Después de Variant Hunt:  pipeline_gate.py --finding <ID> --fgate variant
Después de RedTeam:       pipeline_gate.py --finding <ID> --fgate redteam
Después de Verify Code:   pipeline_gate.py --finding <ID> --fgate verify
Después de ReportWriter:  pipeline_gate.py --finding <ID> --fgate report
Después de report_finding: pipeline_gate.py --finding <ID> --fgate submit
Antes de enviar a plataforma: pipeline_gate.py --finding <ID> --fgate reportable
```

**Si `--fgate reportable` falla → NO enviar a la plataforma.** Sin excepciones.

**Secuencialidad del pipeline — IMPORTANTE:**
- El orden de fuzzing es ESTRICTO: Phase 1 (mock) → Phase 2 (Medusa) → Phase 3 (fork+PoC) → Phase 4 (Echidna). No invertir fases.
- Las etapas 3, 4, 5, 6, 7 (fuzzing completo) pueden considerarse un bloque — pero dentro del bloque el orden es fijo.
- Secuencia obligatoria de gates: PoC (paso 6) → EscalationHunter (7.5) → Variant Hunt (7.6) → RedTeam (8) → Verify Code (9) → ReportWriter (10) → report_finding.py (11).

**Etapas que pueden omitirse SOLO con justificación explícita declarada al usuario:**
- Etapas 3/4/5/6/7 (fuzzing): si el finding es de lógica pura ya demostrada por PoC estático — declarar explícitamente y esperar confirmación del usuario
- Etapa 7 (Echidna): si Medusa ya encontró el bug (no añade valor incremental)
- Etapa 9 (verify code): si el protocolo NO está deployado (pre-launch) — documentar

**Etapas NUNCA omisibles para findings Medium+:**
- Etapa 6 (PoC fork runnable) — sin PoC no hay finding
- Etapa 7.5 (EscalationHunter) — SIEMPRE. Incluso single-component puede escalar vía composability
- Etapa 7.6 (Variant Hunt) — NUNCA omitir. 1 finding → 3-5 variantes. Es el mayor multiplicador de ROI
- Etapa 8 (RedTeam) — sin esto el reporte puede tener errores graves
- Etapa 9 (verify code) — para no reportar bugs ya fixeados en el deployed

---

## Bug Bounty Workflow (v2 — improved from Day 1)

### Phase 0: Triage (5 min)
- Read bounty rules COMPLETELY
- List exclusions, known issues, trusted roles
- Check max payout vs deposit cost ratio
- Verify repos are LIVE code (not old audit mirrors)
- Check deployed commit if specified

### Phase 1: Scope & Clone (10 min)
- Clone from bounty-specified source ONLY
- Pull latest / checkout specified tag
- Count LOC, identify languages
- Map architecture (1 agent)
- Research known issues + past audits (1 agent)

### Phase 2: Hunt (20 agents, parallel)
- Deploy specialized agents per attack surface
- Each agent gets: contract files + attack vectors + exclusion list
- Instruction to every agent: "NO admin required, NO known issues, CONCRETE attack steps only"
- Focus on NEW code, cross-contract interactions, custom math

### Phase 3: Validate (devil's advocate per finding)
- For EACH promising finding, launch a devil's advocate agent
- Ask: "Would a Code4rena judge REJECT this? Why?"
- Verify bug exists in CURRENT deployed code (not old versions)
- Check all known issue sources exhaustively
- Calculate realistic payout probability

### Phase 4: Verify On-Chain (if applicable)
- Fork mainnet, run PoC against live contracts
- Check deployed contract state for misconfigurations
- Verify function signatures and parameters match

### Phase 5: Report & Submit

> ⛔ **BLOQUEO ABSOLUTO**: NO generar ni preparar ningún reporte hasta que el finding haya
> completado el FINDING PIPELINE COMPLETO (ver sección abajo). Si falta cualquier etapa,
> la respuesta debe ser: "Finding [X] está en etapa Y — falta completar Z antes del reporte."

- Use platform-specific format (Code4rena, Immunefi, Cantina)
- Frame impact as "direct fund loss" when possible
- Include CONCRETE PoC (runnable, not conceptual)
- Reference similar real-world incidents
- Propose simple fix
- Only submit at >50% confidence

## REGLA: Reportar Siempre que el Bug Sea Válido (Duplicados = Puntos)

**En plataformas con leaderboard (Immunefi, Code4rena, Cantina):**

1. **Un duplicado válido NO es un desperdicio** — da puntos de leaderboard, builds reputación, y abre puertas a programas invite-only y Whitehat Hall of Fame.
2. **El cálculo de ROI incluye reputación, no solo dinero.** Peor caso de un report válido duplicado = $0 + puntos + señal de competencia.
3. **Reporta TODO finding verificado con PoC sólido**, incluso si sospechas alta probabilidad de duplicado. La única razón para NO reportar es si el bug no es real o el PoC no funciona.
4. **No autocensures por miedo a duplicados.** Especialmente en:
   - Programas recién lanzados (<30 días) — el backlog de reports es pequeño
   - Findings Critical/High — los puntos de leaderboard valen más
   - Programas con KYC — menos hunters compiten, menos duplicados
5. **El único costo real es el tiempo de preparar el PoC + report.** Si el bug es real y el PoC ya existe del pipeline de fuzzing, el costo marginal de reportar es bajo.
6. **Prioriza por severidad, no por probabilidad de originalidad.** Un Critical duplicado da más puntos que un Medium original.

## What NOT to Do (Lessons from Day 1)

- Don't submit findings requiring admin/governance (usually excluded)
- Don't submit "defense-in-depth" findings without concrete exploit
- Don't submit known issues or previous audit findings
- Don't spend deposit money on <50% confidence findings
- Don't clone old audit repos — use the LIVE source
- Don't assume code is same across repos (Rujira GitLab vs GitHub)
- Don't assume a "missing check" is exploitable — verify the IMPACT
- Don't skip the validation step to save time

## Protocol-Specific Checklists

### DeFi Lending (Compound forks, Aave, etc.)
- [ ] First depositor / share inflation attack
- [ ] Interest rate manipulation
- [ ] Liquidation logic edge cases
- [ ] Oracle staleness / manipulation
- [ ] Fee avoidance paths
- [ ] Cross-market interactions

### DEX / Orderbook
- [ ] Price manipulation via thin liquidity
- [ ] Fee accounting mismatches
- [ ] Order matching edge cases
- [ ] Sandwich / MEV extraction
- [ ] Rounding direction consistency

### Staking / Rewards
- [ ] Double-claim prevention
- [ ] Flash loan staking
- [ ] Reward calculation precision
- [ ] Donation attacks on share price
- [ ] Epoch boundary edge cases

### Cross-Chain / Bridges
- [ ] Message replay
- [ ] Nonce handling
- [ ] Rate limit bypass
- [ ] Timing desync between chains

### ZK Systems (NEW)
- [ ] Missing constraints (CRITICAL for soundness)
- [ ] Range check completeness
- [ ] Fiat-Shamir transcript correctness
- [ ] Memory argument soundness
- [ ] Shard/recursion boundary consistency
- [ ] Public IO commitment integrity
- [ ] Precompile constraint completeness

## Technical Standards

- Always verify on the latest commit/tag specified by the bounty
- Fork mainnet for PoCs when possible
- Test against deployed contract addresses, not just code review
- Check on-chain state for misconfigurations
