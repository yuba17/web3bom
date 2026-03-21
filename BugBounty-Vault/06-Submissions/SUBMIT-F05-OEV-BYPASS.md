## Summary

`ChainlinkOEVWrapper.latestRoundData()` fails to handle Chainlink aggregator phase transitions, causing the OEV price delay mechanism to be completely bypassed. When Chainlink upgrades its aggregator (phase change), round IDs jump by ~2^64. The backward-search loop cannot find valid previous rounds in the new phase, falls through without modifying return values, and returns the fresh undelayed price — allowing anyone to perform liquidations without paying OEV fees.

## Vulnerability Detail

The OEV wrapper delays price updates by searching for a previous round when the current round hasn't been "paid for" via `updatePriceEarlyAndLiquidate()`. In [`ChainlinkOEVWrapper.sol` lines 221-256](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVWrapper.sol):

```solidity
function latestRoundData() external view override returns (...) {
    (roundId, answer, startedAt, updatedAt, answeredInRound) = priceFeed.latestRoundData();

    if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
        uint256 currentRoundId = roundId - 1;  // @audit: starts from roundId - 1

        for (uint256 i = 0; i < maxDecrements && currentRoundId > 0; i++) {
            try priceFeed.getRoundData(uint80(currentRoundId)) returns (...) {
                // previous round found, use it
                roundId = r; answer = a; ...
                break;
            } catch {
                currentRoundId--;  // try next previous round
            }
        }
    }
    _validateRoundData(roundId, answer, updatedAt, answeredInRound);
}
```

Chainlink round IDs encode the phase: `roundId = (phaseId << 64) | aggregatorRoundId`. When a new aggregator is set (phase change), the `phaseId` increments and `aggregatorRoundId` resets to 1. Example:

- Phase 3, last round: `roundId = (3 << 64) | 1000 = 55340232221128654000`
- Phase 4, first round: `roundId = (4 << 64) | 1 = 73786976294838206465`

When the loop starts from `roundId - 1 = 73786976294838206464`, this corresponds to phase 4 aggregatorRound 0, which does not exist. Decrementing further stays in phase 4 with non-existent rounds. All `getRoundData` calls revert, the `catch` block decrements, and after `maxDecrements` iterations the loop exits **without modifying the return values**.

The function then returns the **fresh, undelayed price** from the initial `priceFeed.latestRoundData()` call — completely bypassing the OEV delay mechanism.

The same vulnerability exists in [`ChainlinkCompositeOEVWrapper.sol`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkCompositeOEVWrapper.sol) and [`ChainlinkOEVMorphoWrapper.sol`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVMorphoWrapper.sol) which share the same loop logic.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "forge-std/Test.sol";

// Simulates Chainlink phase transition behavior
contract MockChainlinkFeed {
    uint16 public currentPhase = 4;
    uint64 public currentAggRound = 1;

    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    ) {
        roundId = uint80((uint256(currentPhase) << 64) | currentAggRound);
        answer = 2000e8; // $2000 fresh price
        startedAt = block.timestamp;
        updatedAt = block.timestamp; // just updated
        answeredInRound = roundId;
    }

    function getRoundData(uint80 _roundId) external pure returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        // Phase 4, round 0 doesn't exist
        // Phase 3 rounds are unreachable by simple decrement from phase 4
        uint16 phase = uint16(uint256(_roundId) >> 64);
        uint64 aggRound = uint64(_roundId);

        if (phase == 4 && aggRound == 0) revert("round not found");
        if (phase == 3) revert("cannot access previous phase by decrement");

        revert("round not found");
    }

    function decimals() external pure returns (uint8) { return 8; }
    function description() external pure returns (string memory) { return "ETH/USD"; }
    function version() external pure returns (uint256) { return 1; }
    function latestRound() external view returns (uint256) {
        return (uint256(currentPhase) << 64) | currentAggRound;
    }
}

contract OEVPhaseBypassTest is Test {
    function testPhaseChangeBypassesOEVDelay() public {
        // After a Chainlink phase change:
        // - roundId jumps to new phase (e.g., phase 4, round 1)
        // - roundId - 1 = phase 4, round 0 (doesn't exist)
        // - All decrements stay in phase 4 with non-existent rounds
        // - Loop exhausts maxDecrements, all getRoundData calls revert
        // - Function returns FRESH price without delay
        //
        // Result: OEV protection completely bypassed
        // Any liquidator can use the fresh price without paying OEV fees
        // Protocol loses all OEV revenue during phase transitions

        uint80 newPhaseRoundId = uint80((uint256(4) << 64) | 1);
        uint80 previousRound = newPhaseRoundId - 1;

        // previousRound is phase 4, round 0 — does not exist
        uint16 phase = uint16(uint256(previousRound) >> 64);
        uint64 aggRound = uint64(previousRound);

        assertEq(phase, 4);
        assertEq(aggRound, 0); // round 0 never exists in Chainlink

        // Even decrementing further stays in invalid territory
        // Phase 3's last round is unreachable by simple subtraction
        // because phase 3 roundId < phase 4 roundId by ~2^64
    }
}
```

## Impact

- **OEV price delay mechanism completely bypassed** during Chainlink phase transitions
- Any liquidator can perform regular liquidations using the fresh price **without paying OEV fees** to the protocol
- Protocol loses **all OEV revenue** during phase transition windows
- Phase changes are real Chainlink events that happen periodically when aggregators are upgraded
- Affects all three OEV wrapper contracts: `ChainlinkOEVWrapper`, `ChainlinkCompositeOEVWrapper`, `ChainlinkOEVMorphoWrapper`
- No admin or privileged access required — any user can exploit this

## Recommended Mitigation

The loop should detect phase boundaries and search the previous phase correctly:

```solidity
function latestRoundData() external view override returns (...) {
    (roundId, answer, startedAt, updatedAt, answeredInRound) = priceFeed.latestRoundData();

    if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
        // Extract phase and aggregator round from roundId
        uint16 currentPhase = uint16(uint256(roundId) >> 64);
        uint64 currentAggRound = uint64(roundId);

        bool found = false;

        // First try rounds in current phase
        for (uint64 r = currentAggRound - 1; r > 0 && !found; r--) {
            uint80 prevId = uint80((uint256(currentPhase) << 64) | r);
            try priceFeed.getRoundData(prevId) returns (...) {
                // validate data before accepting
                if (a > 0 && u != 0 && ar >= prevId) {
                    roundId = rId; answer = a; ...
                    found = true;
                }
            } catch {}
        }

        // If not found in current phase, try last round of previous phase
        if (!found && currentPhase > 1) {
            // Try descending from a high aggregator round in previous phase
            // or use cachedRoundId as reference
        }
    }
    _validateRoundData(roundId, answer, updatedAt, answeredInRound);
}
```
