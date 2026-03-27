# Contexto de Hunt — V3Oracle

**Protocolo**: revert-lend
**Dominio**: oracle
**LOC**: 516
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/V3Oracle.sol
**Generado**: 2026-03-21T10:05:29.685031Z

## Solodit Context
No disponible

## Briefing del Dominio

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
[ ] Check: minAnswer/maxAnswer on Chainlink 
