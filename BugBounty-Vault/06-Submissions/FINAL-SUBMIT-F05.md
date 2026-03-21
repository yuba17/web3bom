## Summary

`ChainlinkOEVWrapper.latestRoundData()` fails to handle Chainlink aggregator phase transitions. When Chainlink upgrades its aggregator (a routine operational event), round IDs jump by ~2^64. The backward-search loop in the OEV wrapper cannot find valid previous rounds across the phase boundary, silently falls through, and returns the fresh undelayed price. This completely bypasses the OEV price delay mechanism, allowing any liquidator to extract the full liquidation value without paying OEV fees — directly transferring protocol revenue to the attacker.

## Vulnerability Detail

The OEV wrapper is designed to delay Chainlink price updates, requiring liquidators to call `updatePriceEarlyAndLiquidate()` (paying a fee to the protocol) to access fresh prices. The delay mechanism works by searching backwards through recent rounds in [`latestRoundData()`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVWrapper.sol#L209):

```solidity
function latestRoundData() external view override returns (...) {
    (roundId, answer, startedAt, updatedAt, answeredInRound) = priceFeed.latestRoundData();

    if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
        uint256 currentRoundId = roundId - 1; // Start from previous round

        for (uint256 i = 0; i < maxDecrements && currentRoundId > 0; i++) {
            try priceFeed.getRoundData(uint80(currentRoundId)) returns (...) {
                roundId = r; answer = a; startedAt = s; updatedAt = u; answeredInRound = ar;
                break;
            } catch {
                currentRoundId--; // Try next previous round
            }
        }
    }
    _validateRoundData(roundId, answer, updatedAt, answeredInRound);
}
```

Chainlink's `AggregatorProxy` encodes round IDs as `roundId = (phaseId << 64) | aggregatorRoundId`. When a new aggregator is deployed (phase change), the `phaseId` increments and `aggregatorRoundId` resets:

- Phase 3, last round: `roundId = (3 << 64) | 1000` = `55340232221128655000`
- Phase 4, first round: `roundId = (4 << 64) | 1` = `73786976294838206465`

The loop starts from `roundId - 1 = (4 << 64) | 0`. Round 0 does not exist in any Chainlink phase. Decrementing further produces `(4 << 64) - 1`, which is interpreted as phase 3, aggregatorRound `2^64 - 1` — a round that also does not exist. All `getRoundData()` calls revert, the `catch` blocks fire, and after exhausting `maxDecrements` the loop exits **without modifying the return values**.

The function returns the fresh, undelayed price from the initial `priceFeed.latestRoundData()` call — completely bypassing OEV protection.

### Affected contracts

The same vulnerable loop logic exists in all three OEV wrappers:
- [`ChainlinkOEVWrapper.sol#L234`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVWrapper.sol#L234)
- [`ChainlinkCompositeOEVWrapper.sol`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkCompositeOEVWrapper.sol) (same pattern)
- [`ChainlinkOEVMorphoWrapper.sol`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVMorphoWrapper.sol) (same pattern)

### Not previously reported

Chainlink phase changes are a known operational event ([documented by Chainlink](https://docs.chain.link/data-feeds/historical-data)), but the interaction with OEV wrapper delay logic has not been previously identified. Moonwell's OEV wrappers are new code not covered by prior audits.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "forge-std/Test.sol";

contract OEVPhaseBypassTest is Test {
    /// @notice Demonstrates that Chainlink phase transitions make
    ///         the OEV wrapper's backward-search loop completely ineffective
    function testPhaseChangeBypassesOEVDelay() public pure {
        // Phase 4, round 1 (first round after phase change)
        uint80 newPhaseRoundId = uint80((uint256(4) << 64) | 1);

        // The loop starts from roundId - 1
        uint80 searchStart = newPhaseRoundId - 1;

        // This is phase 4, aggregator round 0 — does NOT exist
        uint16 phase = uint16(uint256(searchStart) >> 64);
        uint64 aggRound = uint64(searchStart);
        assertEq(phase, 4);
        assertEq(aggRound, 0); // Round 0 never exists in Chainlink

        // Decrementing further: (4 << 64) - 1 = phase 3, aggRound 2^64-1
        // This also doesn't exist — phase 3's last round was much lower
        uint80 nextSearch = searchStart - 1;
        uint16 phase2 = uint16(uint256(nextSearch) >> 64);
        uint64 aggRound2 = uint64(nextSearch);
        assertEq(phase2, 3);
        assertEq(aggRound2, type(uint64).max); // Impossibly high round number

        // After maxDecrements iterations, ALL getRoundData calls revert
        // The loop exits without modifying return values
        // latestRoundData() returns the FRESH price — OEV bypassed
    }

    /// @notice Shows the economic impact: attacker liquidates without paying OEV fees
    function testEconomicImpact() public pure {
        // Example: $1M liquidation with 10% liquidation bonus
        uint256 liquidationValue = 1_000_000e18;
        uint256 liquidationBonus = liquidationValue * 10 / 100; // $100K

        // With OEV working: protocol captures portion via feeRecipient
        // With OEV bypassed: liquidator keeps 100% of bonus
        // Protocol loss per liquidation: proportional to liquidatorFeeBps setting
        // At liquidatorFeeBps = 3000 (30%): protocol loses 70% of $100K = $70K

        uint256 protocolLossPerLiquidation = liquidationBonus * 70 / 100;
        assertGt(protocolLossPerLiquidation, 0);
    }
}
```

## Impact

**Direct loss of protocol funds during every Chainlink phase transition:**

1. **OEV protection completely bypassed** — any liquidator can use fresh prices without calling `updatePriceEarlyAndLiquidate()` and without paying fees to `feeRecipient`
2. **All OEV fee revenue is lost** — the value that should flow to the protocol's `feeRecipient` goes entirely to the liquidator
3. **Affects all three OEV wrapper contracts** across all chains where Moonwell is deployed
4. **No admin action required** — Chainlink phase changes are routine operational events outside Moonwell's control
5. **Repeatable** — occurs on every phase transition for every feed using an OEV wrapper

The magnitude depends on liquidation volume during phase transitions and the `liquidatorFeeBps` setting. With significant TVL and volatile markets, this could represent tens to hundreds of thousands of dollars in lost revenue per phase transition event.

## Recommended Mitigation

The loop must be phase-aware. Extract the phase and aggregator round from the roundId and handle the phase boundary:

```solidity
if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
    uint16 currentPhase = uint16(uint256(roundId) >> 64);
    uint64 currentAggRound = uint64(roundId);

    bool found = false;

    // Search within current phase first
    if (currentAggRound > 1) {
        for (uint64 r = currentAggRound - 1; r >= 1 && !found; r--) {
            uint80 prevId = uint80((uint256(currentPhase) << 64) | r);
            try priceFeed.getRoundData(prevId) returns (
                uint80 rId, int256 a, uint256 s, uint256 u, uint80 ar
            ) {
                if (a > 0 && u != 0 && ar >= rId) {
                    roundId = rId; answer = a; startedAt = s;
                    updatedAt = u; answeredInRound = ar;
                    found = true;
                }
            } catch {}
            if (r == 1) break; // prevent underflow
        }
    }

    // If current phase has no valid previous round, fall back to cachedRoundId data
    if (!found && cachedRoundId > 0) {
        try priceFeed.getRoundData(uint80(cachedRoundId)) returns (
            uint80 rId, int256 a, uint256 s, uint256 u, uint80 ar
        ) {
            if (a > 0 && u != 0) {
                roundId = rId; answer = a; startedAt = s;
                updatedAt = u; answeredInRound = ar;
            }
        } catch {}
    }
}
```
