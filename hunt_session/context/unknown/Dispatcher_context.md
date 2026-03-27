# Contexto de Hunt — Dispatcher

**Protocolo**: pancakeswap-infinity
**Dominio**: dex
**LOC**: 0
**Archivo**: None
**Generado**: 2026-03-23T06:25:35.166230Z

## Solodit Context
### Findings sobre Dispatcher
Buscando 'Dispatcher' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (33ms)

 1. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` — Nucleus_2024-12-14
 2. [LOW] Race condition in dispatch.Subscribe can crash the node during startup / restart — Berachain Beaconkit
 3. [LOW] ThresholdsVeriﬁer is initialized using the compiler contract instead of the comp — Arkis DeFi Prime Brokerage Protocol
 4. [LOW] Race condition in broker.Broker results in panic — Berachain Beaconkit
 5. [GAS] Re-order high usage function to top of dispatch order  — Omni X

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Dispatcher | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` (Nucleus_2024-12-14)
   ## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_bridge()` and `_quote()` in the `MultiChainHyperlaneTellerWithMultiAssetSupp...

2. [LOW] Race condition in dispatch.Subscribe can crash the node during startup / restart (Berachain Beaconkit)
   ## Severity: Low Risk

## Context
File: `mod/async/pkg/dispatcher/dispatcher.go#L71`

Subscribe on broker will access map subscriptions.  
```go
b.sub...

3. [LOW] ThresholdsVeriﬁer is initialized using the compiler contract instead of the compliance contract (Arkis DeFi Prime Brokerage Protocol)
   ## Diﬃculty: Low

## Type: Data Validation

## Description
The `ThresholdsVerifier` contract constructor accepts an address for the compliance contrac...

4. [LOW] Race condition in broker.Broker results in panic (Berachain Beaconkit)
   ## Severity: Low Risk

## Context
`mod/async/pkg/broker/broker.go#L127-L133`

## Description
The `broker.Broker` struct includes the following map: `s...

5. [GAS] Re-order high usage function to top of dispatch order  (Omni X)
   ## OmniXMultisender.sol#L92-L100

## Description
Functions expected to be the most called within a contract should ideally be put at the top of the fu...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio dex
Buscando 'Dispatcher' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (68ms)

### Cross-domain HIGH relevantes
Buscando 'Dispatcher' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (2ms)
 1. [HIGH] Proxy has public methods that shadow implementation — NuCypher
 2. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, resul — RealWagmi
 3. [HIGH] Issue with Fee Payment During Interchain Callback — DIA
 4. [HIGH] Permission in method description doesn't match implementation — Basilisk
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Dispatcher | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:
1. [HIGH] Proxy has public methods that shadow implementation (NuCypher)
   ## Auditing and Logging Report
## Type: 
Auditing and Logging
## Target: 
- Issuer.sol
- MinersEscrow.sol
- MiningAdjucator.sol
## Difficulty: 
Low...
2. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, result in users losing significant incentives or being unable to withdraw from the Dispatcher contract (RealWagmi)
   Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/142 
## Found by 
crimson-rat-reach, duc, qpzm
## Summary
The `_estimateW...
3. [HIGH] Issue with Fee Payment During Interchain Callback (DIA)
   ##### Description
In the `OracleRequestRecipient.handle()` function the `msg.value` parameter is missing [in the call](https://github.com/diadata-org/...
4. [HIGH] Permission in method description doesn't match implementation (Basilisk)
   **Occurs**:
B

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


