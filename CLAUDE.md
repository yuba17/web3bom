# Web3 Bug Bounty Hunting — Project Guidelines

## IDIOMA: Español

Responde SIEMPRE en español. Términos técnicos del dominio (invariant, reentrancy, flash loan) pueden dejarse en inglés. Código siempre en inglés.

---

## 1. Presentación de Findings

Cada vez que se identifica un finding (cualquier severidad):

1. **Preséntalo al usuario INMEDIATAMENTE** con esta estructura:
   - **Qué es**: descripción en una frase
   - **Dónde**: contrato + función + línea exacta
   - **Cómo funciona el ataque**: paso a paso
   - **Impacto**: quién pierde qué y cuánto
   - **Confianza**: % y por qué
   - **Riesgo de rechazo**: % y razón (ej: "centralización", "by design", "impacto insuficiente")
   - **Riesgo de duplicado**: % y razón (ej: "patrón conocido", "competición previa con N submissions")
   - **Reportable**: sí/no y a qué plataforma
2. **Espera confirmación** del usuario antes de continuar
3. **Ejecuta el finding pipeline completo** (sección 6) — `pipeline_gate.py` lo enforce

---

## 2. Mindset: Realismo Brutal

1. **No te engañes.** Si un finding es débil, dilo. Mejor 0 findings honestos que 5 false positives.
2. **Sé específico o cállate.** "Puede haber reentrancy" no es un finding. Línea exacta, call path exacto, pérdida concreta.
3. **El PoC es la verdad.** Sin test Foundry que demuestre pérdida de fondos, no hay finding.
4. **Prioriza implacablemente.** 80% de bugs críticos: accounting, access control, oracle manipulation. Si llevas 2h sin progreso en selección de target, cambia. Dentro de un componente, RULE #0 prevalece.
5. **Asume que eres el último auditor.** ToB, OZ, Cyfrin ya pasaron. Busca interacciones entre componentes, edge cases extremos, assumptions incorrectas sobre estado externo.

**Anti-patrones**: optimismo falso, complejidad innecesaria, parálisis por análisis, cargo cult fuzzing, aversión a abandonar.

---

## 3. Modo Autónomo

### Arranque de sesión
1. Lee `~/.claude/MEMORY/STATE/current_hunt.json`. Si hay findings con `radar_id`, ejecuta `sync_state.py`.
2. Si hay `current_component`, empieza a huntar inmediatamente sin esperar instrucción.
3. Si no existe, lee `memory/project_revert_lend_hunt.md` como fallback.
4. **Hunts nuevos**: `python3 audit-agents/scope_intake.py --repo <path> --platform <platform> --scope-text "..."` (auto-ejecuta graphify recon)
5. **Vault de conocimiento**: `~/obsidian-vault/web3-audit/` — consultar con `/wiki-query` al inicio, findings se auto-ingestan via `apply_feedback.py`

### Decisiones autónomas (sin pedir permiso)
- Leer contratos, escribir invariantes, correr tests, actualizar trackers, lanzar hunters/skills

### Decisiones que requieren confirmación
- Reportar finding a plataforma
- Git push
- Contexto masivo (>50 contratos)

### Monitoreo de procesos largos (benchmarks, fuzzing, builds)
- **NUNCA** usar `sleep` > 180s. Monitorear SIEMPRE cada 3 minutos máximo.
- Patrón: `sleep 180 && tail -20 <logfile>` — repetir hasta completar.
- Si el proceso lleva >30 min sin progreso nuevo en el log, avisar al usuario.
- Entre checks, reportar al usuario el último milestone visible (ej: "Hunters completados, DeepDive en progreso").

### Transición de componente
Marcar como completo en `current_hunt.json`, actualizar HUNT_TRACKER.md, ejecutar `apply_feedback.py`. Informar resumen al usuario y **esperar confirmación explícita** antes del siguiente componente.

### Resumen de componente (obligatorio al completar)
Al informar al usuario que un componente está completo, el resumen DEBE incluir:
- **Contratos verificados**: lista de CADA contrato leído con nombre de archivo y LOC
- **Hipótesis analizadas**: total, desglosado por hunter
- **Findings**: nuevos + referencia a existentes si aplica
- **Falsos positivos descartados**: cuántos y razón principal
- **Cross-component**: si se hizo, resultado. Si no, por qué
- **Gates**: estado final (X/Y passed)

### Scripts del pipeline (invocar internamente)

| Script | Cuándo |
|---|---|
| `run_benchmark.py --components X --protocol <name> --repo <path>` | Inicio de cada componente (flujo canónico) |
| `run_benchmark.py --auto-components --protocol <name> --repo <path>` | Alternativa: auto-descubrir componentes (Fase 2C) |
| `run_benchmark.py --complete <COMPONENT> [--force]` | Cierre atómico: gate+state+feedback+cross-marker (Fase 2D) |
| `detection_engine.py --prepass --source <src> --name X --output hunt_session/results/` | Después de scope, antes de hunters |
| Agent tool (12 hunters paralelos + 2 secuenciales) | Fase de análisis (reciben prepass signals) |
| `halmos_property_generator.py` | Antes de Phase 5 Halmos |
| `merge_invariants.py` | Después de hunters + DeepDive |
| `pipeline_gate.py -c X --gate <gate>` | Entre cada fase (ver sección 5) |
| `apply_feedback.py` | Al finalizar componente |
| `report_finding.py --finding <ID>` | Después de ReportWriter, nunca antes |
| `sync_state.py` | Inicio de sesión si hay radar_ids |

### Flags de `run_benchmark.py` (referencia rápida)

| Flag | Qué hace | Fase |
|---|---|---|
| `--components X,Y` | Componentes explícitos (mutex con --auto-components, --complete) | 2A |
| `--auto-components` | Auto-descubre vía component_discovery.generate_component_map | 2C |
| `--complete X [--force]` | Single-shot closer (mutex con --components, --auto-components) | 2D |
| `--state-file PATH` | Override path para current_hunt.json (testing) | 2D |
| `--hunters H1,H2` | Subset de hunters a lanzar | 2A |
| `--domain DOM` | Fuerza dominio (lending/dex/staking/bridges/zk) | 2A |
| `--force-regen-map` | Regenera component_map.json | 2A |
| `--force-gate G` | Re-ejecuta un gate cached | 2A |
| `--apply-feedback` | Invoca apply_feedback.py al final | 2B |

### Módulos del pipeline moderno (audit-agents/)

| Módulo | Rol |
|---|---|
| `context_enrichment.py` | Orchestrator de briefings + wiki + asset flow map + symmetric/flatten analysis (Fase 2A). |
| `component_discovery.py` | 3 helpers puros: generate_component_map, find_cross_component_pairs, detect_transitive_chains (Fase 2C). |
| `component_closer.py` | close_component: atomic gate+state+feedback+cross trigger (Fase 2D). |
| `solodit_to_wiki.py` | Converter solodit_cards → ~/obsidian-vault/web3-audit/solodit/*.md (Fase 2B). |

### Skills (invocar internamente)

| Skill | Cuándo |
|---|---|
| `/redteam` | Todo finding, cualquier severidad. Incluye Ronda 0 de calibración |
| `/escalation-hunter` | Todo finding Medium+ (obligatorio). Info/QA: skip |
| `/variant-hunt` | Después de cada finding confirmado. NUNCA omitir |
| `/report-writer` | Después de RedTeam si veredicto = REPORT. Genera markdown |
| `/council FINDING` | Antes de RedTeam si hay duda. Cross-review anónimo (Karpathy pattern) |
| `/wiki-query` | Al inicio de hunt para consultar conocimiento previo del vault |
| `/wiki-ingest` | Al completar componente o confirmar finding (auto via apply_feedback) |
| `/graphify <repo>` | Recon estructural. Auto via scope_intake o manual para ad-hoc |

Si cualquier script falla (exit code != 0), detenerse y notificar al usuario.

---

## 4. RULE #0: Un Componente a la Vez

**NUNCA** pasar al siguiente componente hasta completar todos los items:

```
COMPONENT COMPLETION CHECKLIST:
[ ] 1.  FULL CODE READ — cada línea leída y entendida
[ ] 2.  PROTOCOL MODEL — qué hace, flujos de dinero, trust boundaries
[ ] 2.3 STATE MACHINE MODEL — FlowHunter genera FSM, DeepDive lo consume
[ ] 2.4 CROSSCHAIN HUNTER — secuencial tras los 12 hunters, solo si multi-chain
[ ] 2.5 DEEPDIVE HUNTER — secuencial tras los 12 hunters, sin límite artificial
[ ] 3.  AI INVARIANTS — mínimo 10 específicos en formato Chimera
[ ] 4.  Properties.sol — compilable, invariantes en Solidity
[ ] 5.  TargetFunctions.sol — handlers para cada función pública
[ ] 6.  BOUNDARY VALUES — _clampAmount con 0, 1, max, edge cases
[ ] 7.  OPTIMIZATION FUNCTIONS — optimize_* para ataques económicos (Echidna)
[ ] 8.  COMPILE CHECK — forge build pasa
[ ] 9.  FOUNDRY FUZZ — mínimo 5,000 runs, resultados registrados
[ ] 10. FINDINGS LOGGED — cada invariante roto documentado en HUNT_TRACKER.md
[ ] 11. TIER 1 SEPARATED — findings confirmados separados de dust/known
[ ] 12. TOLERANCE TUNED — dust con tolerancia explícita, no bloqueando exploración
```

---

## 5. Pipeline de Componente — Gates

`pipeline_gate.py` es la fuente de verdad. Ejecutar en cada transición. Si falla, NO avanzar.

```
python3 audit-agents/pipeline_gate.py -c <Component> --gate <gate>
python3 audit-agents/pipeline_gate.py -c <Component> --status
python3 audit-agents/pipeline_gate.py -c <Component> --mark <gate>   # evidencia manual
```

| Gate | Qué verifica | Cuándo |
|---|---|---|
| `scope` | current_hunt.json, context, prompts, ficha | Antes de lanzar hunters |
| `prepass` | detection_engine.py --prepass generó YAML (Slither + Aderyn + exploit patterns) | Después de scope, antes de hunters |
| `hunters` | 12 hyp_*.yaml con campos solidity | Después de 12 hunters |
| `crosschain` | CrossChainHunter YAML o .skip existe | Después de 12 hunters (solo multi-chain) |
| `deepdive` | hyp_*_DeepDiveHunter.yaml existe | Después de DeepDiveHunter |
| `merge` | Properties.sol + TargetFunctions.sol + boundary values | Después de merge_invariants.py |
| `compile` | Artifacts en out/ | Después de forge build |
| `phase1` | Evidencia de Foundry 5K runs | Después de Phase 1 |
| `phase2` | Corpus Medusa existe | Después de Phase 2 |
| `phase3` | Fork test (obligatorio si bounty >= $2K) | Después de Phase 3 |
| `phase4` | Echidna (obligatorio si optimize_* existen) | Después de Phase 4 |
| `phase5` | Halmos (recomendado si math pura existe) | Después de Phase 5 |

**12 hunters paralelos**: AccessHunter, DomainHunter, FlowHunter, MathHunter, OracleHunter, TrustBoundaryHunter, WildcardHunter, SignatureHunter, DoSHunter, LogicHunter, AdversarialHunter, LibraryHunter.

Después (secuenciales):
1. **CrossChainHunter** — solo si componente tiene deployments en 2+ chains. Analiza signature replay, config divergence, bytecode mismatch, proxy upgrade desync, cross-chain state dependencies. Skip automático si single-chain.
2. **DeepDiveHunter** — lee convergencias, genera hipótesis profundas (**sin límite mínimo ni máximo**). Puede lanzarse múltiples rondas con ángulos distintos. Calidad > cantidad pero nunca cortar artificialmente. Confidence >= 60% para validated: true.

Total: **14 hunters** (12 paralelos + 2 secuenciales).

Si el repo no tiene `test/chimera/`, lanzar sub-agente **ChimeraBuilder** para auto-generar el setup. Compile-fix loop: max 9 intentos.

### REGLA: FIX & RETURN — Cuando un paso del pipeline falla

1. **ANOTAR** el paso exacto donde estás (ej: "V3Vault: merge → compile")
2. Arreglar **SOLO** lo mínimo para que ese paso pase — nada más
3. **RE-EJECUTAR** el paso que falló (no el siguiente)
4. Si pasa → **continuar pipeline desde donde anotaste**, ejecutando el gate correspondiente
5. Si no pasa tras 3 intentos → **PARAR** y avisar al usuario con el error completo

**PROHIBIDO durante un fix:**
- Refactorizar código que no bloquea el paso actual
- Arreglar "de paso" cosas que no rompieron nada
- Saltar al siguiente paso sin confirmar que el actual pasó
- Perder el hilo del pipeline por estar debugging

**Después de cada fix**, ejecutar `pipeline_gate.py --status` para re-orientarse.

---

## 6. Finding Pipeline — Gates

Secuencial y acumulativo. `pipeline_gate.py` enforce cada paso.

```
python3 audit-agents/pipeline_gate.py --finding <ID> --fgate <gate>
python3 audit-agents/pipeline_gate.py --finding <ID> --status
python3 audit-agents/pipeline_gate.py --finding <ID> --fgate reportable  # ALL gates
```

| # | Paso | Gate | Notas |
|---|---|---|---|
| 1 | Código leído en contexto | — | Pre-requisito |
| 2 | Invariante en Properties.sol | — | Debe compilar |
| 3 | Phase 1: Foundry Mock 5K runs | — | Feedback inmediato |
| 4 | Tolerance tuning | — | Clasificar: real / dust / mock artifact |
| 5 | Phase 2: Medusa 15 min | — | Secuencias multi-step |
| 6 | Phase 3: Fork PoC | `poc` | `vm.createFork` obligatorio (excepto pre_launch) |
| 7 | Phase 4: Echidna optimization | — | Solo si optimize_* existen |
| 7.1 | Phase 5: Halmos proof | — | Solo para math pura |
| 7.5 | EscalationHunter | `escalation` | **Medium+: obligatorio. Info/QA: skip** |
| 7.6 | Variant Hunt | `variant` | Obligatorio siempre. 1 finding → 3-5 variantes |
| 8 | RedTeam (4 atacantes + Ronda 0) | `redteam` | **Obligatorio para TODA severidad** |
| 9 | Verify Code on-chain | `verify` | Skip si pre_launch. Verificar Etherscan, no hay fix reciente |
| 10 | ReportWriter | `report` | Solo si RedTeam = REPORT. Genera reports/DRAFT-<ID>-<slug>.md |
| 11 | report_finding.py | `submit` | **Después** de ReportWriter (secuencial, no paralelo) |

**Si `--fgate reportable` falla → NO enviar a la plataforma.**

Checklist pre-reporte:
```
pipeline_gate.py --finding <ID> --status
→ Si algún gate tiene ❌: "Finding X NO puede reportarse. Faltan: [gates]."
```

### Flujo post-RedTeam REPORT
1. `/report-writer` → genera markdown en reports/
2. `report_finding.py --finding <ID>` → registra en Bounty Radar + Telegram
3. Avisar al usuario con path del reporte para revisión manual

---

## 7. Fuzzing Pipeline (Secuencial — comparten solc y RAM)

**Phase 1 y 2 son SIEMPRE obligatorios. Phase 3+ según condiciones.**

| Phase | Tool | Duración | Propósito |
|---|---|---|---|
| 1 | `FOUNDRY_PROFILE=chimera forge test --fuzz-runs 5000` | 5 min | Validar invariantes, feedback inmediato. **Mocks OK aquí** |
| 2 | `medusa fuzz --config test/chimera/medusa-<comp>.json --timeout 900` | 15 min | Secuencias multi-step. Corpus persistente |
| 3 | `BASE_RPC_URL=... forge test --match-contract ForkTester --fuzz-runs 10000` | 10 min | Fork real. Confirma Phase 1+2. **Obligatorio si bounty >= $2K** |
| 4 | `echidna . --contract CryticTester --config test/chimera/echidna.yaml` | 10 min | Optimización: maximizar profit atacante. **Obligatorio si optimize_* existen** |
| 5 | `~/.local/bin/halmos --function check_ --loop 10 --solver-timeout-assertion 10000` | 5 min | Prueba simbólica para math pura. Auto-generar con `halmos_property_generator.py` |

**Rationale del orden**: Foundry primero (10x mejor error reporting) → Medusa segundo (secuencias, pero necesita invariantes sanos) → Fork tercero (confirma/descarta todo) → Echidna/Halmos al final (valor incremental).

### Tolerance Tuning (obligatorio entre Phase 1 y 2)
1. Pass 1 (strict): zero tolerance, documentar CADA fallo
2. Clasificar: Real bug / Rounding dust / Mock artifact / Test artifact
3. Pass 2 (tuned): tolerancias para dust conocido, explorar más profundo

### Time Advance Limits
- Por step: max 7 días. Total acumulado: max 90 días.

### Fork vs Mock
- **Fork obligatorio** para DeFi. Mocks causan false positives (oracles, IRM, gauges).
- **Mocks aceptables solo**: protocolo pre-launch, math pura sin estado externo, **Phase 1 del pipeline**.
- RPC disponibles: ETH mainnet, Base mainnet, Optimism mainnet (Alchemy).

---

## 8. Invariant Proving Engine

### Layer 1: Entender el código
Para cada componente: leer TODO el código, generar protocol model (flujos de dinero, tokens, external calls, trust boundaries), generar **mínimo 10** invariantes específicos en formato Chimera con assertion helpers (`t()`, `eq()`, `gte()`, `lte()`). Cada invariante debe responder: "si se rompe, cuál es el ataque?"

Generar: handlers para funciones públicas, ghost variables para tracking acumulativo, optimization functions para Echidna.

### Layer 2: Merge
1. Registry match: `python audit-agents/matcher.py <source_dir>` → top 20 genéricos
2. AI-generated: 10+ específicos de Layer 1
3. Merge en Properties.sol (Chimera, deduplicado, **sin límite artificial**)
4. Tag tiers: Tier 1 (hard fail = bug confirmado) vs Tier 2 (necesita review, tolerancia dust)

### Layer 3: Fuzz
Ver sección 7 (Fuzzing Pipeline).

**Si algo ROMPE un invariante → ES el bug. El counterexample ES el PoC.**

---

## 9. RULE #0.5: Cross-Component Hunt

**Después de completar 2-3 componentes relacionados**, ejecutar hunt cross-component ANTES de pasar a componentes no relacionados. **Sin límite artificial de hipótesis ni edges** — analizar TODOS los pares, TODAS las interacciones. Igual que DeepDiveHunter: calidad > cantidad pero nunca cortar artificialmente.

1. **Map interaction surface**: para cada par (A, B) completado — listar funciones cruzadas, estado compartido, assumptions mutuas. Sin límite de tiempo — completar el mapa entero.
2. **EdgeHunters** (paralelos): un agente por edge de alto valor. Pregunta: "Qué rompe si B se comporta inesperadamente en este call site?" **Analizar CADA edge, no solo los "de alto valor".**
3. **Multi-component fuzzing**: si EdgeHunter encuentra hipótesis Tier 1, o si la interacción implica transferencia de fondos. Deploy AMBOS contratos reales (no mocks).
4. **Interaction invariants**: custody (NFT en vault XOR gauge), debt conservation, health consistency, reward conservation.
5. **Si se encuentra finding**: entra en el finding pipeline completo (sección 6).
6. **Ejecutar AUTOMÁTICAMENTE** — no esperar a que el usuario lo pida. Está en el pipeline, se hace siempre.

---

## 10. Finding Queue

Variant Hunt, Cross-Component, y Hunter Spillover generan findings que entran en cola sin interrumpir el componente actual:

```bash
pipeline_gate.py --queue-finding --source variant --parent PL-M-01 --title "Same pattern in X" -c Component --severity medium
pipeline_gate.py --list-queue
pipeline_gate.py --queue-update <ID> --qstatus in_pipeline
pipeline_gate.py --queue-promote <ID>   # solo si status=completed
```

Cola se procesa ENTRE componentes. Cada item pasa por el finding pipeline completo. Status: `pending_pipeline` → `in_pipeline` → `completed` → `moved_to_findings`.

---

## 11. Seguridad Jurídica

- **Fork local** (`vm.createFork`): lee estado de la chain, ejecuta TODO localmente → legal.
- **Transacciones reales en mainnet/testnet**: ILEGAL, equivale a robar fondos.
- Un PoC Foundry con fork local es SUFICIENTE para cualquier bug bounty.

---

## 12. Protocol Checklists (Referencia Rápida)

### DeFi Lending
First depositor/share inflation, interest rate manipulation, liquidation edge cases, oracle staleness, fee avoidance, cross-market interactions.

### DEX / Orderbook
Price manipulation via thin liquidity, fee accounting mismatches, order matching edge cases, sandwich/MEV, rounding direction consistency.

### Staking / Rewards
Double-claim, flash loan staking, reward precision, donation attacks on share price, epoch boundary.

### Cross-Chain / Bridges
Message replay, nonce handling, rate limit bypass, timing desync.

### ZK Systems
Missing constraints, range check completeness, Fiat-Shamir transcript, memory argument soundness, shard/recursion boundaries, public IO commitment, precompile constraints.

---

## 13. Reportar Siempre (Duplicados = Puntos)

En plataformas con leaderboard: un duplicado válido da puntos, builds reputación, abre programas invite-only. Reportar TODO finding verificado con PoC sólido. El único costo real es tiempo de preparar el report — si el PoC ya existe del fuzzing, el costo marginal es bajo. Priorizar por severidad, no por probabilidad de originalidad.

---

## 14. Tracking

- `HUNT_TRACKER.md` en repo root: estado de componentes, invariantes testeados, findings, resultados de fuzzing.
- Actualizar después de cada componente y cada sesión de fuzzing.
- Log TODOS los findings (incluso Low/QA) con severidad.
- `current_hunt.json`: estado activo del hunt, component_map, findings, finding_queue.
- `gate_status.json`: estado de gates exportado por pipeline_gate.py.

---

## 15. Rejection Rules — Aprendidas de Rechazos Reales

Estas reglas se extraen de findings rechazados en plataformas reales. El RedTeam DEBE verificar cada finding contra estas reglas antes de recomendar REPORT.

### Reglas de Rechazo Automático

| # | Patrón | Acción | Fuente |
|---|--------|--------|--------|
| R1 | Attack path requiere trusted/admin/manager/owner role | REJECT — centralización, no es vuln | Coinbase rechazó 3/3 findings de este tipo (Flywheel, AdConversion ×2) |
| R2 | Función view-only vacía (no-op) por diseño | REJECT — design issue, no security impact | Coinbase AdConversion `_onUpdateMetadata` |
| R3 | Config disabled/paused es señal off-chain, no security gate on-chain | REJECT — el contrato no lo enforce intencionalmente | Coinbase AdConversion disabled config |
| R4 | Address del contrato NO está en la lista explícita de scope | REJECT — verificar scope ANTES de pipeline completo | DD-WT-01 gastó pipeline completo en address OOS |
| R5 | Impacto es cosmético/UX sin fondos ni access control afectados | REJECT — las plataformas solo pagan por security impact | Coinbase "no funds at risk, no access control bypassed" |

### Checklist Pre-Report (obligatorio)

Antes de ejecutar `/report-writer`, verificar:
1. [ ] ¿El attack path requiere SOLO acciones de actores no privilegiados? (Si requiere admin → R1)
2. [ ] ¿El contrato afectado está EXPLÍCITAMENTE en scope? (Verificar address list → R4)
3. [ ] ¿Hay pérdida de fondos O bypass de access control? (Si solo UX → R5)
4. [ ] ¿La "vulnerabilidad" es realmente un comportamiento documentado/intencional? (→ R3)
5. [ ] ¿Cuántos duplicados probables? (Si patrón muy conocido en contest con 200+ submissions → considerar ROI)

### Actualización

Estas reglas se actualizan con cada rechazo. Script: `audit-agents/ingest_rejections.py`.
Archivo de reglas: `hunt_session/feedback/rejection_rules.yaml`.

---

## 16. Configuración por Defecto — Benchmark

```bash
python3 audit-agents/run_benchmark.py \
  --repo <repo_path> \
  --components <components> \
  --protocol <protocol> \
  --ground-truth benchmarks/<protocol>/benchmark.yaml \
  --parallel-components 2 \
  --parallel-fuzz 3 \
  --parallel-poc 2 \
  --fast
```

**Parámetros fijos (validados en PC con 8 cores / 10 GB RAM):**
- `--parallel-components 2` — 2 componentes en paralelo vía git worktrees
- `--parallel-fuzz 3` — 3 batches de fuzzing en paralelo (Phase 1 Foundry)
- `--parallel-poc 2` — 2 PoC generators en paralelo por componente
- `--fast` — skip Phase 2 (Medusa) y Phase 3 (Fork PoC); usar sólo para benchmarks rápidos

**Consumo peak estimado:** ~5 GB RAM, ~6-7 cores. Seguro con recursos actuales.

**Para benchmark completo (sin `--fast`):** quitar el flag. Añade ~30 min por batch (Medusa 15 min + PoC).
