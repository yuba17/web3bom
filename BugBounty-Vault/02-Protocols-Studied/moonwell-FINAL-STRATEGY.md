---
tags: [protocol, moonwell, strategy, bounty-active]
platform: code4rena
date: 2026-03-16
status: ready-for-poc
---

# Moonwell Bounty — FINAL STRATEGY & PRIORITIZED FINDINGS

## Análisis: 6 agentes completados, 2 pendientes
## Total findings analizados: ~60
## Findings con >60% confianza de pago: 10

---

## TOP FINDINGS — PRIORIDAD DE PoC

### ═══════════════════════════════════════
### #1 🎯 ChainlinkOEVMorphoWrapper.initializeV2 front-runnable
### ═══════════════════════════════════════

**Severity**: CRITICAL/HIGH
**Confianza**: 65% (depende del deployment timing)
**Contrato**: ChainlinkOEVMorphoWrapper.sol, initializeV2()
**Payout**: $100K+ si Critical, $15-20K si High

**Bug**: `initializeV2` usa `reinitializer(2)`. Si el proxy fue inicializado
en v1 pero v2 no ha sido llamado aún, CUALQUIERA puede front-run y:
- Hacerse owner del wrapper
- Setear feeRecipient a su dirección
- Controlar liquidatorFeeBps
- Redirigir TODOS los profits de OEV

**Verificación necesaria**:
- [ ] ¿Existe un proxy deployado donde initializeV2 no ha sido llamado?
- [ ] ¿El deploy fue atómico (upgrade + initializeV2 en misma tx)?
- [ ] Checkear en Base/Optimism si hay wrappers pendientes de v2 init

**PoC approach**: Fork Base, call initializeV2 antes que el team

---

### ═══════════════════════════════════════
### #2 🎯 MultichainGovernor: Quorum retroactivo
### ═══════════════════════════════════════

**Severity**: HIGH
**Confianza**: 80%
**Contrato**: MultichainGovernor.sol, state() line 546
**Payout**: $15K-$20K

**Bug**: `state()` compara `proposal.totalVotes < quorum` contra el
quorum ACTUAL, no el quorum del momento de creación de la propuesta.

**Impacto demostrable**:
1. Propuesta A se crea con quorum = 1M
2. Propuesta A recibe 800K votos → Defeated
3. Governance baja quorum a 500K (por otra propuesta)
4. Propuesta A ahora tiene 800K > 500K → Succeeded
5. Propuesta A resucita y puede ejecutarse

**PoC approach**: Deploy local MultichainGovernor, demostrar el flip de estado

---

### ═══════════════════════════════════════
### #3 🎯 MToken: protocolSeizeShare sin upper bound → DoS liquidaciones
### ═══════════════════════════════════════

**Severity**: HIGH (posible MEDIUM por admin-only)
**Confianza**: 85%
**Contrato**: MToken.sol, _setProtocolSeizeShareFresh() line ~2147
**Payout**: $15K-$20K o $1K-$5K

**Bug**: Sin max check. Si se setea >= 1e18 (100%), en seizeInternal:
```
protocolSeizeTokens = mul_(seizeTokens, Exp({mantissa: protocolSeizeShareMantissa}))
liquidatorSeizeTokens = sub_(seizeTokens, protocolSeizeTokens) // UNDERFLOW REVERT
```
→ TODAS las liquidaciones del protocolo se bloquean.

**Evidencia de oversight**: _setReserveFactorFresh SÍ tiene `reserveFactorMaxMantissa` check.
La inconsistencia es la prueba de que fue un olvido, no diseño.

**Riesgo**: Admin-only. Pero Compound v2 NO tenía este parámetro — es un
NUEVO parámetro añadido por Moonwell, por tanto menos auditado.

**PoC approach**: Fork, set protocolSeizeShare a 1.1e18, intentar liquidar → revert

---

### ═══════════════════════════════════════
### #4 Comptroller: closeFactor sin bounds validation
### ═══════════════════════════════════════

**Severity**: MEDIUM (admin-only)
**Confianza**: 80%
**Contrato**: Comptroller.sol, _setCloseFactor() line ~887
**Payout**: $1K-$5K

**Bug**: Constantes `closeFactorMinMantissa` (0.05e18) y `closeFactorMaxMantissa`
(0.9e18) definidas pero nunca usadas en el setter. Desviación de Compound v2.
- Close factor = 0 → liquidaciones bloqueadas
- Close factor > 1e18 → liquidar más del 100% de una posición

**Combinable con**: _setLiquidationIncentive (mismo patrón)

---

### ═══════════════════════════════════════
### #5 OEV Wrappers: unsafe approve sin SafeERC20
### ═══════════════════════════════════════

**Severity**: MEDIUM
**Confianza**: 55%
**Contratos**: ChainlinkOEVWrapper.sol:580, ChainlinkOEVMorphoWrapper.sol:431, ChainlinkCompositeOEVWrapper.sol:549
**Payout**: $1K-$5K

**Bug**: `underlyingLoan.approve(_mTokenLoan, repayAmount)` usa EIP20Interface
sin SafeERC20 y sin checkear return value. Para tokens no estándar (USDT):
- En Solidity 0.8.x, ABI decoding espera bool → revert
- Resultado: liquidaciones imposibles para esos tokens via OEV wrapper

**Ironía**: El mismo contrato USA SafeERC20 para `safeTransferFrom` en la línea
anterior, pero NO para `approve`. Inconsistencia clara.

---

### ═══════════════════════════════════════
### #6 Comptroller: nonReentrant definido pero nunca aplicado
### ═══════════════════════════════════════

**Severity**: MEDIUM
**Confianza**: 70%
**Contrato**: Comptroller.sol, lines 1405-1417
**Payout**: $1K-$5K

**Bug**: El modifier `nonReentrant` existe con `_locked` state variable pero
NO se aplica a ninguna función. El Comptroller hace external calls en:
- mintAllowed → rewardDistributor
- borrowAllowed → rewardDistributor
- seizeAllowed → rewardDistributor
- transferAllowed → rewardDistributor

Sin reentrancy guard, un token con callbacks podría explotar cross-contract reentrancy.

---

### ═══════════════════════════════════════
### #7 ChainlinkOracle: sin staleness check
### ═══════════════════════════════════════

**Severity**: MEDIUM
**Confianza**: 70%
**Contrato**: ChainlinkOracle.sol:101-104
**Payout**: $1K-$5K

**Bug**: Solo `answer > 0` y `updatedAt != 0`. Sin check de cuánto tiempo
ha pasado. El CompositeOracle SÍ tiene `answeredInRound == roundId` check.
Inconsistencia entre oráculos del mismo protocolo.

---

### ═══════════════════════════════════════
### #8-10 Findings adicionales
### ═══════════════════════════════════════

8. **TG-02**: intendedRecipient no validado en fast-track (MEDIUM, 60%)
9. **MG-03**: proposalThreshold usa current value para cancel (MEDIUM, 60%)
10. **Factory4626**: initial mint amount demasiado pequeño para tokens low-decimal (MEDIUM, 60%)

---

## PLAN DE EJECUCIÓN OPTIMIZADO

### Día 1 (HOY): Validación
```
□ Verificar si initializeV2 fue llamado en proxies deployados (on-chain check)
□ Verificar past audits para descartar known issues
□ Verificar valores actuales de closeFactor/liquidationIncentive/protocolSeizeShare
□ Determinar si USDT está listado en algún mercado Moonwell
```

### Día 2: PoCs
```
□ PoC #1: initializeV2 front-run (si no fue llamado)
□ PoC #2: quorum retroactivo en MultichainGovernor
□ PoC #3: protocolSeizeShare > 100% → DoS liquidations
□ PoC #4: closeFactor = 0 → DoS liquidations
```

### Día 3: Reports
```
□ Escribir reports para findings validados con PoC
□ Submit a Code4rena
□ Track responses
```

---

## REGISTRO PARA CODE4RENA

**Pasos para registrarte tú**:
1. Ve a https://code4rena.com
2. "Connect Wallet" con MetaMask (necesitas wallet en cualquier chain)
3. Crea tu perfil de warden
4. Completa KYC (requerido por Moonwell antes de pago)
5. Ve a https://code4rena.com/bounties/moonwell
6. "Submit Finding" para cada hallazgo
