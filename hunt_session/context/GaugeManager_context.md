# Contexto de Hunt — GaugeManager

**Protocolo**: chainlink-pa-v2
**Dominio**: dex
**LOC**: 0
**Archivo**: None
**Generado**: 2026-03-22T05:05:51.078124Z

## Solodit Context
### Findings sobre GaugeManager
Buscando 'GaugeManager' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (4ms)

 1. [MEDIUM] [M-09] CL gauge accepts unverified pools, allowing malicious pool to brick distr — Hybra Finance
 2. [LOW] [11] Governance/centralization Risks (21 contracts covered) — Audit 507
 3. [LOW] [07] `distributeAll()` function at risk of repeated failure due to unbounded loo — Audit 507
 4. [GAS] [G-17] A modifier used only once and not being inherited should be inlined to sa — Maia DAO Ecosystem
 5. [MEDIUM] [M-18] Status does not update inside the `BlackGovernor` leading to complete dis — Audit 507

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GaugeManager | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [MEDIUM] [M-09] CL gauge accepts unverified pools, allowing malicious pool to brick distribution (Hybra Finance)
   

*This issue was also [found](https://code4rena.com/audits/2025-10-hybra-finance/submissions/S-631) by [V12](https://v12.zellic.io).*

* `GaugeManage...

2. [LOW] [11] Governance/centralization Risks (21 contracts covered) (Audit 507)
   
### Roles/Actors in the system

|  | Contract | Roles/Actors |
| --- | --- | --- |
| 1. | Black.sol | Minter |
| 2. | BlackClaims.sol | Owner/Second ...

3. [LOW] [07] `distributeAll()` function at risk of repeated failure due to unbounded loop over gauges (Audit 507)
   
<https://github.com/code-423n4/2025-05-blackhole/blob/92fff849d3b266e609e6d63478c4164d9f608e91/contracts/GaugeManager.sol# L341>

### Finding descrip...

4. [GAS] [G-17] A modifier used only once and not being inherited should be inlined to save gas (Maia DAO Ecosystem)
   
When a modifier is used only once and is not inherited by any other contracts, inlining it can reduce gas costs. Inlining means that the modifier's c...

5. [MEDIUM] [M-18] Status does not update inside the `BlackGovernor` leading to complete distribution of nudge functionality (Audit 507)
   

<https://github.com/code-423n4/2025-05-blackhole/blob/main/contracts/governance/Governor.sol# L308-L330>

### Finding description and impact

`Minte...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio dex
Buscando 'GaugeManager' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (1ms)

### Cross-domain HIGH relevantes
Buscando 'GaugeManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

## Briefing del Dominio
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
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0)
