---
tags: [protocol, moonwell, final-findings]
platform: code4rena
date: 2026-03-16
status: ready-to-submit
---

# Moonwell Bounty — ALL FINDINGS CONSOLIDATED (8 Agents Complete)

## TIER 1: SUBMIT THESE (Confianza >75%)

### F-01 [HIGH] protocolSeizeShare sin upper bound → DoS ALL liquidations
- **Contrato**: MToken.sol:2147
- **Confianza**: 85%
- **Payout**: $15K-$20K (o Medium $1-5K si admin-only lo reduce)
- **Draft**: moonwell-001-protocolSeizeShare.md ✅

### F-02 [HIGH] Quorum retroactivo en MultichainGovernor
- **Contrato**: MultichainGovernor.sol:546
- **Confianza**: 80%
- **Payout**: $15K-$20K
- **Draft**: moonwell-002-quorum-retroactive.md ✅

### F-03 [HIGH] closeFactor + liquidationIncentive sin bounds validation
- **Contrato**: Comptroller.sol:887, :976
- **Confianza**: 80%
- **Payout**: $1K-$5K (admin-only)
- **Draft**: PENDIENTE

### F-04 [MEDIUM] OEV latestRoundData() NO valida datos dentro del loop
- **Contrato**: ChainlinkOEVWrapper.sol:234-255
- **Confianza**: 75%
- **Nuevo finding del OEV deep agent**
- **Bug**: El loop busca round N-1, pero valida los datos DESPUÉS del loop (línea 255).
  Si round N-1 devuelve datos inválidos (answeredInRound < roundId), todo latestRoundData() reverts.
  → DoS del oráculo para operaciones normales hasta que maxRoundDelay expire.
- **Draft**: PENDIENTE

### F-05 [MEDIUM] OEV bypass en Chainlink phase changes
- **Contrato**: ChainlinkOEVWrapper.sol:221-256
- **Confianza**: 75%
- **Nuevo finding del OEV deep agent**
- **Bug**: Cuando Chainlink cambia de fase, roundId salta ~2^64. El loop decrementa
  desde roundId-1 pero esos rounds no existen en la nueva fase. Todos los getRoundData
  reverts, el loop termina sin cambiar datos, y se devuelve el precio FRESCO sin delay.
  → OEV protection bypassed, protocol pierde fees de liquidación.
- **Draft**: PENDIENTE

### F-06 [MEDIUM] ChainlinkOEVMorphoWrapper missing nonReentrant
- **Contrato**: ChainlinkOEVMorphoWrapper.sol:368
- **Confianza**: 80%
- **Nuevo finding del OEV deep agent**
- **Bug**: Los otros dos wrappers (OEVWrapper y CompositeOEVWrapper) usan nonReentrant.
  El MorphoWrapper NO hereda ReentrancyGuard ni usa el modifier.
  Inconsistencia clara entre contratos hermanos.
- **Draft**: PENDIENTE

---

## TIER 2: SUBMIT SI HAY TIEMPO (Confianza 55-75%)

### F-07 [MEDIUM] Break glass guardian calldata no bound a target address
- **Contrato**: MultichainGovernor.sol:1000-1031
- **Confianza**: 70%
- whitelistedCalldatas valida bytes pero no (target, calldata)
- Admin calls ejecutables contra CUALQUIER target

### F-08 [MEDIUM] Comptroller nonReentrant definido pero nunca aplicado
- **Contrato**: Comptroller.sol:1405-1417
- **Confianza**: 70%
- Modifier existe con _locked pero no se aplica a ninguna función

### F-09 [MEDIUM] ChainlinkOracle sin staleness check
- **Contrato**: ChainlinkOracle.sol:101
- **Confianza**: 70%
- Solo answer > 0 y updatedAt != 0, sin check temporal

### F-10 [MEDIUM] First-caller advantage en emitVotes() bloquea snapshots parciales
- **Contrato**: MultichainVoteCollection.sol:246-286
- **Confianza**: 65%
- Quien llama primero emitVotes() congela el voto cross-chain

### F-11 [MEDIUM] OEV unsafe approve sin SafeERC20
- **Contratos**: ChainlinkOEVWrapper.sol:580, OEVMorphoWrapper.sol:431
- **Confianza**: 55%
- approve() sin SafeERC20 falla con USDT-like tokens

### F-12 [MEDIUM] initializeV2 front-runnable en OEVMorphoWrapper
- **Contrato**: ChainlinkOEVMorphoWrapper.sol:103
- **Confianza**: 65%
- reinitializer(2) callable por cualquiera si v2 no fue llamado

### F-13 [MEDIUM] Stale proposals ejecutan inmediatamente tras permissionlessUnpause
- **Contrato**: TemporalGovernor.sol:254-269
- **Confianza**: 60%
- Propuestas queued sobreviven al pause, ejecutan sin review

### F-14 [MEDIUM] protocolFee underflow potencial en OEV fee split
- **Contrato**: ChainlinkOEVWrapper.sol:691
- **Confianza**: 55%
- Round-trip math puede hacer liquidatorFee > collateralSeized → revert

---

## DESCARTADOS (confianza <50% o known issues)

- MToken CEI violations — herencia Compound v2, probablemente known
- MRD first-depositor — by design en Compound-style models
- MRD emission owner drain — acknowledged en comments del contrato
- Fee-on-transfer en MRD — depende de tokens usados como rewards
- proposalThreshold retroactivo — documentado en comments
- Zero-vote replay — impacto nulo (solo waste gas)
- MToken initialize sin proxy protection — herencia Compound
- Exchange rate simple interest — by design
- ERC20 approve race condition — known ERC20 issue

---

## RESUMEN EJECUTIVO

| Tier | Count | Payout potencial total |
|------|-------|----------------------|
| TIER 1 (>75% confianza) | 6 findings | $40K-$90K |
| TIER 2 (55-75%) | 8 findings | $8K-$40K |
| **TOTAL** | **14 findings** | **$48K-$130K** |

## PRIORIDAD DE PoC

1. F-01: protocolSeizeShare (más fácil de demostrar)
2. F-02: quorum retroactivo (segunda prioridad)
3. F-04: OEV oracle DoS (requiere simular Chainlink state)
4. F-05: OEV phase change bypass (requiere simular phase change)
5. F-06: OEVMorpho missing nonReentrant (no necesita PoC complejo)
6. F-03: closeFactor bounds (fácil pero puede ser Medium)
