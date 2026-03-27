# Contexto de Hunt — AuctionBidder

**Protocolo**: chainlink-pa-v2
**Dominio**: dex
**LOC**: 124
**Archivo**: /home/kali/Documents/Web3/chainlink-pa-v2/src/AuctionBidder.sol
**Generado**: 2026-03-22T15:10:01.868253Z

## Solodit Context
### Findings sobre AuctionBidder
Buscando 'AuctionBidder' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (4ms)


### HIGH findings en dominio dex
Buscando 'AuctionBidder auctionCallback withdraw setAuction _setAuction' [SQLite FTS5] (dominio: dex)...

Top 6 findings relevantes: (372ms)

 1. [HIGH] sweep function should prevent Treasury from withdrawing pool’s BPTs — Gauntlet
 2. [HIGH] Withdrawal shares of msg.sender are burnt incorrectly in _removeLiquidity flow — Hyperdrive February 2024
 3. [HIGH] LPs can split their liquidity withdrawal to get more tokens  — TermMax
 4. [HIGH] H-19: No slippage for withdrawal without swapping path — GMX
 5. [HIGH] [H-02] Missing `fromToken != toToken` check — Marginswap
 6. [HIGH] [H-02] Underflow of `lpPosition.points` during withdrawLP causes huge reward min — Neo Tokyo

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: AuctionBidder auctionCallback withdraw setAuction _setAuction | Dominio: dex
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] sweep function should prevent Treasury from withdrawing pool’s BPTs (Gauntlet)
   ## Severity: Critical Risk

## Context
AeraVaultV1.sol#L559-L561

## Description
The current `sweep()` implementation allows the vault owner (the Trea...

2. [HIGH] Withdrawal shares of msg.sender are burnt incorrectly in _removeLiquidity flow (Hyperdrive February 2024)
   ## Severity: High Risk

## Context
- HyperdriveLP .sol#L279-L296
- HyperdriveLP .sol#L397-L402

## Description
When `_removeLiquidity` is called, the ...

3. [HIGH] LPs can split their liquidity withdrawal to get more tokens  (TermMax)
   ## Context
(No context files were provided by the reviewer)

## Summary
When LPs split their liquidity withdrawal into several pieces, they may get mo...

4. [HIGH] H-19: No slippage for withdrawal without swapping path (GMX)
   Source: https://github.com/sherlock-audit/2023-02-gmx-judging/issues/70 

## Found by 
bin2chen, rvierdiiev

## Summary
No slippage for withdrawal wit...

5. [HIGH] [H-02] Missing `fromToken != toToken` check (Marginswap)
   
Attacker calls `MarginRouter.crossSwapExactTokensForTokens` with a fake pair and the same token[0] == token[1].
`crossSwapExactTokensForTokens(1000 W...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'AuctionBidder auctionCallback withdraw setAuction _setAuctio' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (11ms)

 1. [HIGH] [H-01] `finalizeVaultEndedWithdrawals()` will fail when last withdrawal request  — Saffron
 2. [HIGH] Function `claimEffectiveBalance()` may consistently revert, making it impossible — Casimir
 3. [HIGH] mod/state-transition/pkg/core/state/ExpectedWithdrawals returns error if non-0x0 — Berachain Beaconkit
 4. [HIGH] Disabling Withdrawals by Withdrawing Zero-Value FA — Aptos Securitize

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: AuctionBidder auctionCallback withdraw setAuction _setAuctio | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] [H-01] `finalizeVaultEndedWithdrawals()` will fail when last withdrawal request is less than 100 wei (Saffron)
   **Severity**

**Impact:** High, the issue will prevent withdrawal of stETH

**Likelihood:** Medium, when last withdrawal request is < 100 wei

**Descr...

2. [HIGH] Function `claimEffectiveBalance()` may consistently revert, making it impossible to complete queue withdrawals (Casimir)
   **Description:** The function attempts to remove the withdrawal at index `0`, while it uses the withdrawal at index `i` to call `completeQueuedWithdra...

3. [HIGH] mod/state-transition/pkg/core/state/ExpectedWithdrawals returns error if non-0x01 wi

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
