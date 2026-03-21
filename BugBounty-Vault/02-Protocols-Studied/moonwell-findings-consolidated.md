---
tags: [protocol, moonwell, findings, bounty-active]
platform: code4rena
bounty_max: $250,000
date: 2026-03-16
status: analyzing
---

# Moonwell — Consolidated Findings Analysis

## FILTRO DE CALIDAD PARA >90% CONFIRMACIÓN

Criterios para reportar:
- Solo bugs que NO sean "known issues" o "by design" de Compound v2
- Solo bugs con impacto real (pérdida de fondos o DoS permanente)
- Requiere PoC funcional antes de enviar
- Excluir: admin-only issues (governance es trusted role)
- Excluir: bugs que requieren Wormhole malicioso (out of scope)

---

## TIER 1 — HIGHEST CONFIDENCE (>80% real, worth PoC)

### 1. [HIGH] MG-02: Quorum retroactivo en MultichainGovernor
- **Contrato**: MultichainGovernor.sol, state() line 546
- **Bug**: `proposal.totalVotes < quorum` usa el quorum ACTUAL, no el snapshot.
  Si governance cambia el quorum, propuestas ya aprobadas pueden pasar a Defeated
  y viceversa.
- **Impacto**: Manipulación de governance. Propuestas derrotadas resucitan si bajan quorum.
- **Confianza**: HIGH — bug claro de lógica, fácil de demostrar con PoC
- **Payout estimado**: $15K-$20K (High)
- **Estado**: 🔍 Verificar que no es known issue

### 2. [HIGH] Comptroller: _setCloseFactor sin validación de bounds
- **Contrato**: Comptroller.sol, _setCloseFactor() line ~887
- **Bug**: No valida contra closeFactorMinMantissa/closeFactorMaxMantissa.
  Las constantes están definidas (0.05e18 y 0.9e18) pero nunca se usan.
  Desviación de Compound v2 que sí validaba.
- **Impacto**: Close factor = 0 bloquea liquidaciones → insolvencia del protocolo.
  Close factor = 1e18 permite liquidar 100% de una posición de golpe.
- **Confianza**: HIGH — desviación clara de Compound, constantes definidas pero no usadas
- **Payout estimado**: $15K-$20K (High) pero REQUIERE ADMIN — puede ser Medium
- **Nota**: Admin/governance es "trusted role" → probablemente Medium ($1K-$5K)
- **Estado**: ⚠️ Validar si admin-only lo reduce a Medium

### 3. [HIGH] Comptroller: _setLiquidationIncentive sin validación
- **Contrato**: Comptroller.sol, _setLiquidationIncentive() line ~976
- **Bug**: Sin upper/lower bound check. Se puede setear a 0 (liquidaciones no rentables)
  o a valores extremos. Compound v2 tenía min check >= 1e18.
- **Impacto**: Similar a #2. Desactivar liquidaciones = insolvencia.
- **Confianza**: HIGH — misma desviación de Compound v2
- **Nota**: Mismo issue que #2 — admin-only
- **Estado**: ⚠️ Combinar con #2 en un solo report

### 4. [HIGH] MToken: _setProtocolSeizeShareFresh sin upper bound
- **Contrato**: MToken.sol, _setProtocolSeizeShareFresh() line ~2147
- **Bug**: A diferencia de _setReserveFactorFresh (que SÍ chequea max),
  protocolSeizeShare puede setearse a >= 100%. Esto causa underflow en
  seizeInternal: `liquidatorSeizeTokens = sub_(seizeTokens, protocolSeizeTokens)`
  → reverts → TODAS las liquidaciones bloqueadas.
- **Impacto**: DoS de liquidaciones → insolvencia del protocolo completo.
- **Confianza**: HIGH — la inconsistencia con reserveFactor es clara evidencia de oversight
- **Nota**: Admin-only, pero el impacto (freezing ALL liquidations) es severo
- **Estado**: 🎯 MEJOR CANDIDATO — inconsistencia demostrable

### 5. [MEDIUM] ChainlinkOracle: sin staleness check
- **Contrato**: ChainlinkOracle.sol, getChainlinkPrice() line 101
- **Bug**: Solo chequea `answer > 0` y `updatedAt != 0`, pero no chequea
  cuánto tiempo ha pasado desde updatedAt. El CompositeOracle SÍ tiene
  `answeredInRound == roundId` check, pero el Oracle básico no.
- **Impacto**: Precios stale pueden usarse para liquidaciones injustas o
  para evitar liquidaciones legítimas.
- **Confianza**: MEDIUM — es un patrón conocido pero el impacto depende del heartbeat
- **Payout estimado**: $1K-$5K (Medium)
- **Estado**: 🔍 Verificar heartbeat de cada feed en cada chain

### 6. [MEDIUM] Comptroller: nonReentrant definido pero NUNCA usado
- **Contrato**: Comptroller.sol, lines 1405-1417
- **Bug**: El modifier nonReentrant está definido con _locked pero NO se aplica
  a ninguna función. Funciones como mintAllowed, borrowAllowed, seizeAllowed
  hacen external calls sin protección de reentrancy.
- **Impacto**: Si un mToken tiene un underlying con callbacks (ERC-777),
  cross-contract reentrancy es posible a través del Comptroller.
- **Confianza**: MEDIUM — el modifier existe pero no se usa, sugiere oversight.
  Pero el impacto real depende de si algún token con hooks es listado.
- **Estado**: 🔍 Verificar tokens listados en Base/Optimism

---

## TIER 2 — MEDIUM CONFIDENCE (50-80%, necesita más investigación)

### 7. [MEDIUM] TG-02: intendedRecipient no validado en fast-track execution
- **Contrato**: TemporalGovernor.sol, _executeProposal() + fastTrackProposalExecution()
- **Bug**: El guardian puede fast-track execute un VAA destinado a OTRO
  TemporalGovernor deployment. El check de intendedRecipient solo existe
  en _queueProposal, no en _executeProposal con overrideDelay=true.
- **Confianza**: MEDIUM — requiere guardian, que es semi-trusted
- **Estado**: 🔍 Verificar flujo exacto de fast-track

### 8. [MEDIUM] MG-03: proposalThreshold usa valor actual para cancel
- **Contrato**: MultichainGovernor.sol, cancel() lines 778-784
- **Bug**: Si governance aumenta proposalThreshold, proposers existentes
  pueden ser cancelados permissionlessly. Attack: proponer aumento de threshold →
  una vez aprobado, cancelar propuestas rivales.
- **Confianza**: MEDIUM — documentado en comments pero el código no mitiga
- **Estado**: 🔍 Check si es known issue

### 9. [MEDIUM] MRD: Unbounded loop over emission configs puede DoS markets
- **Contrato**: MultiRewardDistributor.sol, múltiples funciones
- **Bug**: Cada operación en un market (supply, borrow, transfer, liquidate)
  itera TODOS los emission configs de ese market. Los configs no se pueden eliminar.
  Si se acumulan muchos configs, el gas excede el block limit.
- **Confianza**: MEDIUM — requiere admin negligence acumulativa
- **Estado**: 🔍 Verificar cuántos configs hay actualmente en prod

### 10. [MEDIUM] Comptroller: Reward distributor revert bloquea protocolo
- **Contrato**: Comptroller.sol, lines 1271-1300
- **Bug**: Si rewardDistributor reverts por cualquier razón, bloquea
  TODOS los mints, redeems, borrows, repays, liquidaciones y transfers.
- **Confianza**: MEDIUM — el admin puede setear distributor a address(0) como escape
- **Estado**: 🔍 Buscar condiciones de revert en MRD

---

## TIER 3 — LOWER CONFIDENCE (<50% o impacto limitado)

### 11-15. Issues menores
- MToken CEI violations (Compound v2 herencia, probablemente known)
- MG-01 zero-vote replay (impacto mínimo, solo gas waste)
- Fee-on-transfer en MRD (depende de tokens usados)
- TG-01 no proposal expiration (design choice)
- Exchange rate stale en liquidación calcs (mitigado por accrueInterest)

---

## PLAN DE ACCIÓN (PRÓXIMAS 48 HORAS)

### Fase 1: Validación rápida (2-4h)
1. ✅ Verificar si findings #1-4 ya están en past audits o known issues
2. Verificar configs actuales en producción (closeFactor, liquidationIncentive, etc.)
3. Revisar los repos de past audits de Code4rena 2023-07

### Fase 2: PoC Development (8-16h)
4. PoC #4 (protocolSeizeShare > 100% → DoS liquidations) — MEJOR CANDIDATO
5. PoC #1 (quorum retroactivo → propuestas resucitan)
6. PoC #2+3 (closeFactor/liquidationIncentive sin bounds)

### Fase 3: Esperar resultados agentes OEV/Mamo (running)
7. Consolidar findings del OEV wrapper
8. Consolidar findings de Mamo Strategy
9. Priorizar por confianza y escribir PoCs adicionales

### Fase 4: Submit (2-4h per report)
10. Escribir reports con PoC para cada finding validado
11. Submit a Code4rena
