# Web3 Bug Bounty Hunting — Project Guidelines

## IDIOMA: Español

**OBLIGATORIO**: Responde SIEMPRE en español. Explica los conceptos técnicos en español, con ejemplos claros y directos. Si el usuario usa inglés, responde en español igualmente. La excepción son los fragmentos de código, nombres de funciones/variables, y términos técnicos específicos del dominio (e.g., "invariant", "reentrancy", "flash loan") que pueden dejarse en inglés.

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
   - Ataca el 20% que produce el 80% del valor. Si llevas 2 horas sin progreso concreto en la SELECCIÓN de target, cambia de target. NOTA: esta regla aplica a la decisión de qué protocolo huntar, NO al pipeline intra-componente. Una vez dentro de un componente, RULE #0 prevalece: termina el checklist de 12 items antes de moverte.

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

1. **Al iniciar sesión**: lee `~/.claude/MEMORY/STATE/current_hunt.json` (ruta canónica del estado activo). Si hay un `current_component`, **empieza a huntar ese componente inmediatamente** sin esperar instrucción del usuario. Si el archivo no existe, lee `~/.claude/projects/-home-kali-Documents-Web3/memory/project_revert_lend_hunt.md` como fallback.

2. **Ejecuta el pipeline completo de forma autónoma**:
   - Corre `python3 ~/Documents/Web3/audit-agents/run_hunt.py --component <X>` para preparar contexto
   - Usa el **Agent tool** para lanzar los 6 hunters en paralelo — SOLO para análisis de código (Fase 1). El fuzzing es SIEMPRE secuencial (Foundry → Medusa → Echidna comparten solc y RAM).
   - Cada sub-agente lee su prompt de `hunt_session/context/`, analiza el contrato, escribe `hyp_*.yaml`
   - Recoge los resultados, corre `merge_invariants.py`, compila, fuzzea secuencialmente
   - Documenta findings en HUNT_TRACKER.md y fichas YAML
   - Ejecuta RedTeam (aplica el protocolo de 4 atacantes de `~/.claude/skills/redteam.md`) antes de reportar cualquier finding Medium+
   - Si cualquier script del pipeline falla (exit code != 0), detente y notifica al usuario con el error completo antes de continuar.

3. **El usuario puede interrumpir en cualquier momento** para preguntar, redirigir, o pedir que mires un fichero específico. Responde y luego **vuelve al pipeline donde lo dejaste**.

4. **Toma decisiones sin pedir permiso** para: leer contratos, escribir invariantes, correr tests, actualizar trackers. Pide confirmación solo para: reportar un finding a la plataforma, hacer git push, o gastar tokens en contexto masivo (>50 contratos).

5. **Cuando termines un componente**: márcalo como completo en `current_hunt.json`, actualiza HUNT_TRACKER.md, llama a `apply_feedback.py`. **OBLIGATORIO: informa al usuario del resumen del componente (invariantes probados, findings, resultado) y espera confirmación explícita antes de pasar al siguiente componente.** El paso de componente NUNCA es automático.

6. **Si encuentras un finding confirmado en fork**: actualiza `current_hunt.json`, crea el PoC en Foundry, ejecuta RedTeam internamente, y prepara el reporte. Avisa al usuario con un resumen conciso.

### Qué invocar internamente (no esperar que el usuario lo pida):
- `run_hunt.py` → al inicio de cada componente
- Agent tool (6 hunters paralelos) → en el paso de análisis
- `merge_invariants.py` → cuando los hunters terminen
- `apply_feedback.py` → al finalizar cada componente
- RedTeam (internamente, sin skill) → antes de reportar cualquier finding Medium+
- `run_hunt.py --status` → para actualizar contexto en cualquier momento

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
3. **Generate SPECIFIC invariants** (10-20 per component):
   - Each invariant must have: natural language description + Solidity assertion code
   - Each invariant must answer: "If this breaks, what's the attack scenario?"
   - Use Chimera assertion helpers: `t()`, `eq()`, `gte()`, `lte()`
   - Priority: CRITICAL (fund loss) > HIGH (logic break) > MEDIUM (consistency)
4. **Generate handler functions** for each public/external function
5. **Generate ghost variables** for cumulative tracking (deposits, withdrawals, fees per user)
6. **Generate optimization functions** for Echidna (`optimize_*` → maximize attacker profit)

### LAYER 2: COMBINE INVARIANTS

1. **Registry match**: `python audit-agents/matcher.py <source_dir>` → top 20 generic invariants
2. **AI-generated**: 10-20 specific invariants from Layer 1
3. **Merge into Properties.sol** (Chimera format, deduplicated, max 25 total)
4. **Tag tiers**: Tier 1 (hard fail = confirmed bug) vs Tier 2 (needs review, dust tolerance)

### LAYER 3: FUZZ TO DEATH (Sequential pipeline — memory-safe)

**CRITICAL: Run tools SEQUENTIALLY, never in parallel. They share solc and RAM.**
**Foundry is MANDATORY for PoCs — contest platforms require it.**

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
6. **Phase 5 — Halmos Proof (5 min)**: Symbolic execution en funciones math puras (opcional)

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

**Step 3 — Multi-component fuzzing setup** (when warranted):
Build a `MultiComponentSetup.sol` that deploys BOTH real contracts (not mocks) together.
Add interaction handlers: sequences that span both components.
Run 5000+ fuzz runs on cross-component invariants.

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

### RULE #0: ONE COMPONENT AT A TIME — FINISH COMPLETELY BEFORE MOVING ON

**This is the most important rule. NEVER skip to another component until the current one is 100% done.**

A component is DONE only when ALL of these are checked off:

```
COMPONENT COMPLETION CHECKLIST (mandatory for each file):
[ ] 1. FULL CODE READ — every line read and understood
[ ] 2. PROTOCOL MODEL — what it does, money flows, trust boundaries documented
[ ] 3. AI INVARIANTS GENERATED — 10-20 specific invariants in Chimera format
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

**DO NOT start reading the next component until all 12 boxes are checked.**
**DO NOT skip any step. DO NOT say "we'll come back to it".**
**If a step fails, FIX IT before moving on.**

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
- Initial 5-minute iteration on invariant structure before switching to fork
- **ALWAYS migrate to fork before running final fuzzing passes**

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
- **Compile-fix loop**: generate → compile → fix errors → recompile (max 3 retries)

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
[ ] 1. CÓDIGO LEÍDO — Cada línea relevante, entendida en contexto
[ ] 2. INVARIANTE GENERADO — Solidity assertion en Properties.sol, compila
[ ] 3. FOUNDRY FUZZ — min 5,000 runs, invariante roto o bounds verificados
[ ] 4. TOLERANCE TUNING — artefactos de mock vs bug real clasificados
[ ] 5. POC FOUNDRY RUNNABLE — test que demuestra el bug con assertions duras (PASS)
        └─ Opción A: mocks controlables (siempre válido para bugs de lógica)
        └─ Opción B: fork local vm.createFork() (añade confianza, nunca toca fondos reales)
        └─ NUNCA: transacciones reales en mainnet — ILEGAL
[ ] 6. MEDUSA STATEFUL — min 10 min, corpus guardado
[ ] 7. ECHIDNA OPTIMIZATION — optimize_ functions, min 10 min
[ ] 8. REDTEAM — 4 atacantes (JUDGE/DEVIL/GUARD/ECONOMIST), 3 rondas, veredito emitido
        └─ Resultado debe ser REPORT o REPORT_DOWNGRADED (no DO_NOT_REPORT)
[ ] 9. VERIFY CODE — verificación estática del código deployed (SIN ejecutar nada):
        └─ Buscar contrato en Etherscan/Basescan y confirmar que está verified
        └─ Comparar que las funciones afectadas existen en la versión deployed
        └─ Verificar que no hay un fix reciente en el repo que mitigue el bug
        └─ Comprobar que el feature (e.g., gaugeManager) está activado on-chain

RESULTADO: [ ] APTO PARA REPORTE  /  [ ] BLOQUEADO — faltan etapas: [lista]
```

**Si cualquier etapa tiene ❌, Claude debe decir:**
> "⛔ [Finding X] NO puede reportarse. Falta(n): [etapa(s)]. Ejecutar antes de continuar."

**Secuencialidad del pipeline — IMPORTANTE:**
- Las etapas 3, 4, 6, 7 (fuzzing) pueden ejecutarse EN PARALELO entre sí — no dependen unas de otras.
- Lo que SÍ es estrictamente secuencial: el gate de REPORTE. No se reporta hasta que TODAS las etapas estén ✅.
- La regla "no pasar de etapa hasta finalizar la anterior" aplica a: (a) transiciones de componente (RULE #0 — 12 checkboxes), y (b) el gate de reporte (9 etapas del pipeline). NO aplica a ejecutar etapas de fuzzing en paralelo.
- Secuencia obligatoria: Etapa 5 (PoC) debe existir ANTES de ejecutar RedTeam (8). Etapa 8 debe estar ANTES de Verify Code (9). Verify Code (9) debe estar ANTES de reportar.

**Etapas que pueden omitirse SOLO con justificación explícita:**
- Etapa 3/4/6/7 (fuzzing): si el finding es de lógica pura ya demostrada por PoC estático
- Etapa 7 (Echidna): si Medusa ya encontró el bug (no añade valor incremental)
- Etapa 9 (verify code): si el protocolo NO está deployado (pre-launch) — documentar

**Etapas NUNCA omisibles para findings Medium+:**
- Etapa 5 (PoC runnable) — sin PoC no hay finding
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
