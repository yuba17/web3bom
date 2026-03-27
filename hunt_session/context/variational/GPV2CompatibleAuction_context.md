# Contexto de Hunt — GPV2CompatibleAuction

**Protocolo**: chainlink-pa-v2
**Dominio**: dex
**LOC**: 121
**Archivo**: /home/kali/Documents/Web3/chainlink-pa-v2/src/GPV2CompatibleAuction.sol
**Generado**: 2026-03-22T13:34:42.810398Z

## Solodit Context
### Findings sobre GPV2CompatibleAuction
Buscando 'GPV2CompatibleAuction' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (2ms)


### HIGH findings en dominio dex
Buscando 'GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidSignature invalidateO' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (102ms)

### Cross-domain HIGH relevantes
Buscando 'GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidS' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (20ms)

 1. [HIGH] [H-06] Funds are permanently stuck in OptimisticListingSeaport.sol contract if a — Tessera
 2. [HIGH] Expired token groups not synchronized with ERC1155 balance tracking — Radius Technology EVMAuth
 3. [HIGH] [H-02] Partial signature replay/frontrunning attack on session calls — Sequence
 4. [HIGH] H-8: It is possible to DoS batch auctions by submitting invalid AltBn128 points  — Axis Finance

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidS | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] [H-06] Funds are permanently stuck in OptimisticListingSeaport.sol contract if active proposal is executed after new proposal is pending. (Tessera)
   
`\_constructOrder` is called in `propose()`, OptimisticListingSeaport.sol. It fills the order params stored in proposedListings\[\_vault].

    {
   ...

2. [HIGH] Expired token groups not synchronized with ERC1155 balance tracking (Radius Technology EVMAuth)
   ## Diﬃculty: Low

## Type: Data Validation

## Description
The *pruneGroups* function removes expired token groups from the custom group tracking syst...

3. [HIGH] [H-02] Partial signature replay/frontrunning attack on session calls (Sequence)
   

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/Calls.sol# L36-L48>

<https://github.com/c...

4. [HIGH] H-8: It is possible to DoS batch auctions by submitting invalid AltBn128 points when bidding (Axis Finance)
   Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/147 

## Found by 
hash, underdog
## Summary

Bidders can submit invalid...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

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
