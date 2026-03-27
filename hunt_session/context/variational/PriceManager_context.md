# Contexto de Hunt — PriceManager

**Protocolo**: chainlink-pa-v2
**Dominio**: oracle
**LOC**: 249
**Archivo**: /home/kali/Documents/Web3/chainlink-pa-v2/src/PriceManager.sol
**Generado**: 2026-03-22T15:00:29.262978Z

## Solodit Context
### Findings sobre PriceManager
Buscando 'PriceManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (4ms)


### HIGH findings en dominio oracle
Buscando 'PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpdates _onFeedInfoUpda' [SQLite FTS5] (dominio: oracle)...
Sin resultados para los criterios dados. (35ms)

### Cross-domain HIGH relevantes
Buscando 'PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpd' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (3ms)

 1. [HIGH] Non-context-aware JSON Parsing — Proximity Labs
 2. [HIGH] Risk of Passing Incorrect Context to Firewall Policies — Ironblocks Onchain Firewall Audit
 3. [HIGH] ​Lack of ​chainID — Yield Protocol
 4. [HIGH] [H01] Attackers can prevent honest users from performing an instant withdraw fro — Futureswap V2 Audit

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpd | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] Non-context-aware JSON Parsing (Proximity Labs)
   ## Custom JSON Parsing in Near-Eth Contract

Custom JSON parsing is used within the Near-Eth Contract. This parsing method is non-context-aware, which...

2. [HIGH] Risk of Passing Incorrect Context to Firewall Policies (Ironblocks Onchain Firewall Audit)
   The on\-chain firewall system is designed to support meta\-transactions. The [FirewallConsumerBase](https://github.com/ironblocks/onchain-firewall/blo...

3. [HIGH] ​Lack of ​chainID (Yield Protocol)
   ## Type: Timing  
**Target:** ERC20Permit.sol  

## Difficulty: Low  
Implements the draft ERC 2612 via the ERC20Permit contract it inherits from. Thi...

4. [HIGH] [H01] Attackers can prevent honest users from performing an instant withdraw from the Wallet contract (Futureswap V2 Audit)
   An attacker who sees an honest user’s call to [`MessageProcessor.instantWithdraw`](https://github.com/futureswap/fs_core/blob/96255fc4a550a5f34681c117...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio
### Briefing principal: oracle

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Some protocols have fallback oracles that silently handle staleness -- check full path
  ⚠ Heartbeat varies per feed and per chain -- don't assume 1h for all
  ⚠ updatedAt == 0 is a valid failure case (feed never initialized)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate -- cost/benefit matters
  ⚠ Legitimate large trades can trigger deviation on thin pools
  ⚠ Protocol using Chainlink only (no AMM reads) is not vulnerable to this
  ⚠ Very high liquidity pools make even short TWAP expensive to manipulate
  ⚠ Multi-block manipulation requires sustained capital or validator collusion
  ⚠ Post-PoS: proposer can manipulate last block of window more cheaply
  ⚠ Solidity int256 can be negative -- casting to uint256 without check wraps around
  ⚠ Some feeds return minAnswer/maxAnswer bounds, not zero, on extreme events
  ⚠ Check Chainlink aggregator minAnswer -- if real price drops below, feed returns minAnswer (stale)

## CHECKLIST DE INVARIANTES
Oracle audit -- run through for every target:
```
[ ] Grep: latestAnswer, getAnswer, getTimestamp (deprecated functions)
[ ] Grep: latestRoundData -- are ALL return values validated?
[ ] Check: price > 0 after every oracle read
[ ] Check: updatedAt freshness against feed-specific heartbeat
[ ] Check: answeredInRound >= roundId
[ ] Grep: getReserves, slot0, sqrtPriceX96 (spot price reads)
[ ] If spot price used: is TWAP or Chainlink cross-validation present?
[ ] Grep: observe, consult (TWAP reads) -- what window length?
[ ] If TWAP window < 30 min: flag as manipulable
[ ] Check: observationCardinality sufficient for window?
[ ] Check: feed.decimals() called or hardcoded assumption?
[ ] Check: token decimals + oracle decimals combined correctly?
[ ] If L2: sequencer uptime feed checked?
[ ] If L2: grace period after sequencer restart?
[ ] Check: fallback oracle path exists?
[ ] Check: circuit breaker for extreme price events?
[ ] Check: mi
