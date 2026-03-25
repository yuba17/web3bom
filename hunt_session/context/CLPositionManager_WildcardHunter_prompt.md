# WildcardHunter — CLPositionManager Analysis

## Tu Identidad
Eres el **WildcardHunter** del equipo de bug hunting de pancakeswap-infinity.
Tu especialidad: **Novel bugs, unconventional vectors, assumption violations, composability risks**

## Tu Objetivo
Analizar `CLPositionManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `None`
**Dominio**: dex


```solidity

```

## Contexto de Solodit (bugs similares en protocolos similares)
Sin contexto disponible — busca patrones propios

## Briefing del Dominio (dex)
### Briefing principal: dex
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Constant Product Invariant Violation
### 1.2 LP Token Mint/Burn Ratio Desync
### 1.3 Price Impact Manipulation (Thin Liquidity)
### 1.4 Sandwich Attack Amplification
### 1.5 TWAP Oracle Manipulation
### 1.6 Concentrated Liquidity Tick Boundary Errors
### 1.7 Swap Deadline Missing
### 1.8 Slippage Protection Bypass
### 2.1 Flash Loan + AMM State Manipulation
### 2.2 Fee Accounting Mismatch

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Fees intentionally reduce output — k must increase by fee amount, not stay flat
  ⚠ Virtual reserves in concentrated liquidity mean k is per-range, not global
  ⚠ Rebasing tokens break the invariant naturally — pool must handle rebase
  ⚠ UniV2 MINIMUM_LIQUIDITY (1000 wei) prevents first-depositor attack
  ⚠ Fee-on-transfer tokens cause natural desync — protocol must use actual received amounts
  ⚠ Imbalanced deposits in multi-asset pools intentionally cost more (swap fee applies)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate for spot reads
  ⚠ TWAP with short window (< 10 min) is still manipulable across multiple blocks
  ⚠ Chainlink with proper staleness checks is generally safe
  ⚠ Private mempools (Flashbots) partially mitigate but do not eliminate risk
  ⚠ Protocols computing slippage from oracle price internally may be acceptable
  ⚠ L2s with sequencer ordering have reduced but nonzero sandwich risk

## CHECKLIST DE INVARIANTES
| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| DEX-INV-001 | k_after >= k_before for every swap | 1 | constant product |
| DEX-INV-002 | LP mint-then-burn returns <= deposited | 1 | share math |
| DEX-INV-003 | reserve0 * reserve1 monotonically non-decreasing | 1 | core AMM |
| DEX-INV-004 | sum(LP balances) == LP totalSupply | 1 | token accounting |
| DEX-INV-005 | actual token balances >= internal reserves | 1 | INV-EXPLOIT-012 |
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0) | 1 | INV-EXPLOIT-016 |
| DEX-INV-007 | spot price deviation from TWAP < MAX_PCT | 2 | INV-EXPLOIT-001 |
| DEX-INV-008 | fee deducted <= amount transacted | 1 | INV-EXPLOIT-008 |
| DEX-INV-009 | no profit from sandwich (attacker_out <= attacker_in) | 1 | COMP-MULTI-001 |
| DEX-INV-010 | active liquidity == sum(position liquidity in active range) | 1 | tick math |
**Tier 1** = hard fail = confirmed bug. **Tier 2** = needs review, may have tolerance.
---

## GREP TARGETS
```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp
swap(
getAmountOut
getAmountIn

## INCIDENTES REALES (protocolos afectados)
```yaml
- id: dex-incident-001
  name: "KyberSwap exploit"
  fecha: "2023-11"
  perdida: "$48M"
  causa_raiz: "Precision loss in concentrated liquidity tick boundary math"
  categoria: "Tick boundary error / precision loss"
  vector: "Attacker exploited precision loss at tick boundaries in KyberSwap's concentrated liquidity implementation to drain pools"
  leccion: "CRITICAL: Tick boundary math is the #1 attack surface for concentrated liquidity DEXes. See dex-006. Fuzz with swaps that land exactly on tick boundaries."
  verificado: true

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Novel bugs) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `CLPM` (ej: CLPM-01, CLPM-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_CLPositionManager_WildcardHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: CLPM-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "CLPM-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Deadlock Analysis (OBLIGATORIO — después de tu búsqueda creativa)
Para cada safety check, margin, cap, o límite en el contrato:
1. ¿Puede BLOQUEAR una operación de emergencia? (repay, withdraw, liquidate, unstake)
2. ¿Hay un escenario donde el usuario NO PUEDE deshacer su posición?
3. ¿El safety mechanism puede dejar fondos permanentemente bloqueados?
4. ¿Un cap que protege al protocolo puede impedir que un usuario se salve de liquidación?

Bug real: Safety margin aplicado al cálculo de repago impedía que usuarios repagaran → liquidados sin poder hacer nada.
Busca: require/assert/if que revierten en funciones de salida (withdraw, repay, unstake, emergencyWithdraw).

## Composability Attack (samczsun — "Two Rights Make A Wrong")
Para cada interacción con un contrato externo:
1. ¿Qué ASUME este contrato sobre el comportamiento del otro?
2. ¿Bajo qué condiciones esa asunción se viola?
3. ¿Se puede crear un estado donde ambos contratos son internamente consistentes pero juntos son inseguros?
Bug real: SushiSwap MISO — msg.value reutilizado en loop de batch. Auction y batch handler eran seguros individualmente.

## "Reimplementa de Memoria" (cmichel — MENTALIDAD)
Después de leer el contrato, pregúntate: ¿podría reimplementar esto desde cero sin mirar el código?
Si tu versión mental DIFIERE del código real en algún punto → ese punto es un candidato a bug.
La gap entre "qué debería hacer" y "qué realmente hace" es donde viven los bugs novedosos.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
