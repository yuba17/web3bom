# Cross-Component Interaction Surface — Revert Lend
# Generado: 2026-03-21 | Usar en: cross-component hunt pass

## SUPERFICIE DE INTERACCIÓN MAPEADA

### V3Vault × GaugeManager (PRIORIDAD MÁXIMA — ya completados ambos)

**Vault llama a GaugeManager:**
| Función Vault | Llama a GM | Parámetros | Assumption que hace Vault |
|---|---|---|---|
| `_stake(tokenId)` | `gm.stakePosition(tokenId)` | — | NFT sale del vault (ownerOf != vault post-call) |
| `_unstakeIfNeeded(tokenId)` | `gm.unstakeIfStaked(tokenId)` | — | NFT vuelve al vault si estaba stakeado |
| `stakePosition(tokenId)` | via `_stake` | — | Health check post-stake válido |
| `unstakePosition(tokenId)` | `gm.unstakePosition(tokenId)` | — | NFT vuelve al vault |
| `_transform(...)` | via `_unstakeIfNeeded` + `_stake` | — | NFT round-trip correcto |
| `compoundRewards` (via transform) | `gm.compoundRewards(...)` | tokenId, params | Aumenta valor colateral, no rompe health |

**GaugeManager llama a Vault:**
| Función GM | Llama a Vault | Para qué |
|---|---|---|
| `stakePosition` | `vault.ownerOf(tokenId)` | Verificar ownership |
| `unstakePosition` | `vault.ownerOf(tokenId)` | Recipient de rewards |
| `compoundRewards` | `vault.ownerOf(tokenId)` | Recipient de leftovers |
| `_requireVaultOrOwner` | `vault.ownerOf(tokenId)` | Auth check |

**Estado compartido:**
- `tokenIdToGauge[tokenId]` en GM ↔ `_isStaked(tokenId)` en Vault
- NFT custody: vault → GM → gauge (stake) / gauge → GM → vault (unstake)
- Borrower address: vault's `tokenOwner[tokenId]`

**Invariantes cross-component críticos:**
```
INV-CC-01: Para todo tokenId con deuda:
  vault.ownerOf(tokenId) != address(0)  // no orphaned debt post stake/unstake

INV-CC-02: NFT custody es exclusivo:
  if gm.tokenIdToGauge(tokenId) != address(0):
    npm.ownerOf(tokenId) != address(vault)  // si stakeado, no está en vault
  else:
    npm.ownerOf(tokenId) == address(vault)  // si no stakeado, está en vault

INV-CC-03: debtSharesTotal invariante a través de stake/unstake:
  debtBefore = vault.debtSharesTotal()
  vault.stakePosition(tokenId)
  debtAfter = vault.debtSharesTotal()
  eq(debtBefore, debtAfter)  // staking no cambia deuda

INV-CC-04: Health consistency post-compound:
  Si posición era healthy antes de compound, debe serlo después
  (compound añade liquidez → valor colateral solo puede aumentar)

INV-CC-05: Reward conservation:
  Si gm.claimRewards(tokenId) devuelve X, el balance de aeroToken del recipient aumenta en X
```

**Bugs ya encontrados en esta superficie:**
- VV-O-02+VV-O-05: liquidación de staked position con feeValue=0 → liquidador roba fees
- GM-D-03: setGauge no migra tokenIdToGauge → posiciones permanentemente bloqueadas
- GM-A-08: gauge.withdraw() sin try/catch → liquidación DoS si gauge es malicioso

**Bugs pendientes de confirmar:**
- GM-A-03: compoundRewards directo bypasea vault health check (confidence 65%)
- GM-O-02: zero-output silencioso en two-hop swap (confidence 60%)

---

### V3Vault × LeverageTransformer (PENDIENTE — LeverageTransformer no leído)

**Superficie esperada:**
- LeverageTransformer llama a `vault.borrow(tokenId, amount)` durante transform
- Vault en transform-mode: `transformedTokenId != 0` → borrow permitido sin health check inmediato
- Flash loan + lever up + health check al final del transform
- Riesgo: posición stakeada + leverage = compound de bugs

**Invariantes a construir cuando se haga:**
- debtShares no cambia más de lo esperado durante leverage transform
- Colateral post-leverage >= deuda post-leverage (health check final debe pasar)
- Si posición estaba stakeada pre-transform, debe re-stakearse post-transform

---

### V3Vault × AutoRangeAndCompound (PENDIENTE)

**Superficie esperada:**
- AutoRangeAndCompound mueve el rango del tick → cambia el valor de la posición
- Si hay deuda, el nuevo rango puede tener menos liquidez → position se vuelve unhealthy
- Transformer llama borrow() dentro de transform-mode

---

### V3Vault × V3Oracle (PENDIENTE)

**Superficie esperada:**
- Vault llama `oracle.getValue(tokenId, asset, ignoreFees)` para health check
- Oracle llama `npm.positions(tokenId)` para obtener tick range y liquidez
- Oracle usa TWAPs para precio — posible manipulation

---

## PROTOCOLO PARA CROSS-COMPONENT HUNT SESSION

### Cuándo ejecutar
- AHORA: V3Vault × GaugeManager (ambos completados)
- Después de LeverageTransformer: + V3Vault × LeverageTransformer
- Después de V3Oracle: + V3Vault × V3Oracle + GaugeManager × V3Oracle

### Cómo ejecutar
1. Leer este documento
2. Lanzar EdgeHunters paralelos — uno por par de componentes
3. Prompt: "Aquí están los contratos A y B completos. Analiza ESPECÍFICAMENTE la superficie de interacción entre ellos. No re-analices el interior de cada componente — solo las llamadas que van de A a B y de B a A. Busca: assumptions incorrectas, estado inconsistente, race conditions cross-contract, tokens perdidos en el boundary."
4. Construir MultiComponentSetup.sol con ambos contratos reales
5. Añadir interaction handlers y cross-component invariants
6. Fuzz 5000+ runs

### Setup para V3Vault × GaugeManager (siguiente paso)
Necesita:
- V3Vault real (ya tenemos setup)
- GaugeManager real (nuevo — necesita deploy)
- Aerodrome NPM mock con gauge funcional
- AERO token mock
- Handlers: stakePosition, unstakePosition, compoundRewards, liquidate-staked
