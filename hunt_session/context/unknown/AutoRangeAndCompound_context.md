# Contexto de Hunt — AutoRangeAndCompound

**Protocolo**: revert-lend
**Dominio**: dex
**LOC**: 457
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/transformers/AutoRangeAndCompound.sol
**Generado**: 2026-03-21T22:46:58.920410Z

## Solodit Context
### Findings sobre AutoRangeAndCompound
Buscando 'AutoRangeAndCompound' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (18ms)


### HIGH findings en dominio dex
Buscando 'AutoRangeAndCompound executeWithVault executeWithVaultAndRewardCompound execute ' [SQLite FTS5] (dominio: dex)...

Top 6 findings relevantes: (821ms)

 1. [HIGH] Lack of locking mechanism leads to loss of funds in `swap-router` PBC — Partisia Smart Contracts (Rust)
 2. [HIGH] Insufficient slippage protection can lead to displaced transactions — Copra
 3. [HIGH] Risk of unlimited slippage in NestedDca swaps — Mass
 4. [HIGH] SwapCallLib.call() incorrectly uses return() instead of revert() on failed calls — Sorella Angstrom
 5. [HIGH] Lack of the pair_id and token_id validation in the PixelswapStreamPool contract — PixelSwap DEX
 6. [HIGH] H-14: Deadline check is not effective, allowing outdated slippage and allow pend — Blueberry Update

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: AutoRangeAndCompound executeWithVault executeWithVaultAndRewardCompound execute  | Dominio: dex
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] Lack of locking mechanism leads to loss of funds in `swap-router` PBC (Partisia Smart Contracts (Rust))
   ##### Description

The `swap-router` PBC does not acquire locks on swap contracts before executing swaps. Locks should be obtained using the `SwapLock...

2. [HIGH] Insufficient slippage protection can lead to displaced transactions (Copra)
   **Severity**: High	

**Status**: Acknowledged

**Description**

The `_withdrawFromTarget` function in the `CurveLiquidityWarehouse.sol` contract does ...

3. [HIGH] Risk of unlimited slippage in NestedDca swaps (Mass)
   ## Diﬃculty: Low

## Type: Data Validation

## Description

The swaps executed by the `NestedDca` contract from Uniswap V3 allow unlimited slippage be...

4. [HIGH] SwapCallLib.call() incorrectly uses return() instead of revert() on failed calls (Sorella Angstrom)
   Severity: High Risk
Context: SwapCall.sol#L61-L67
Description: When a swap call to UniswapV4 fails in SwapCallLib.call() , the return opcode is used...

5. [HIGH] Lack of the pair_id and token_id validation in the PixelswapStreamPool contract (PixelSwap DEX)
   ## Diﬃculty: High

## Type: Data Validation

## Target: contracts/pixelswap_streampool.tact

### Description
The `PlaceOrder` message receiver functio...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'AutoRangeAndCompound executeWithVault executeWithVaultAndRew' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (3ms)

## Briefing del Dominio
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
| D
