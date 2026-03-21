## Summary

`ChainlinkOEVWrapper.latestRoundData()` and `ChainlinkOEVMorphoWrapper.latestRoundData()` fail to handle Chainlink aggregator phase transitions. When Chainlink upgrades its aggregator (a [documented routine event](https://docs.chain.link/data-feeds/historical-data#roundid-in-proxy)), round IDs jump by ~2^64. The backward-search loop cannot find valid previous rounds across the phase boundary, silently falls through, and returns the fresh undelayed price — completely bypassing the OEV price delay mechanism. Any liquidator can then perform liquidations using the fresh price without paying OEV fees, directly extracting value that should flow to the protocol's `feeRecipient`.

## Vulnerability Detail

The OEV wrapper delays Chainlink price updates, requiring liquidators to call `updatePriceEarlyAndLiquidate()` (paying a fee) to access fresh prices. The delay works by searching backwards through recent rounds in [`ChainlinkOEVWrapper.sol#L209-L256`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVWrapper.sol#L209):

```solidity
function latestRoundData() external view override returns (...) {
    (roundId, answer, startedAt, updatedAt, answeredInRound) = priceFeed.latestRoundData();

    if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
        uint256 currentRoundId = roundId - 1;

        for (uint256 i = 0; i < maxDecrements && currentRoundId > 0; i++) {
            try priceFeed.getRoundData(uint80(currentRoundId)) returns (...) {
                roundId = r; answer = a; startedAt = s; updatedAt = u; answeredInRound = ar;
                break;
            } catch {
                currentRoundId--;
            }
        }
    }
    _validateRoundData(roundId, answer, updatedAt, answeredInRound);
}
```

Chainlink's `AggregatorProxy` encodes round IDs as `roundId = (phaseId << 64) | aggregatorRoundId` ([Chainlink docs](https://docs.chain.link/data-feeds/historical-data#roundid-in-proxy)). When a new aggregator is deployed (phase change), `phaseId` increments and `aggregatorRoundId` resets:

- Phase 3, last round: `roundId = (3 << 64) | 1000`
- Phase 4, first round: `roundId = (4 << 64) | 1`

The loop starts from `roundId - 1 = (4 << 64) | 0`. Round 0 does not exist in any Chainlink phase. Decrementing further produces `(4 << 64) - 1 = (3 << 64) | (2^64 - 1)` — an impossibly high round number that also doesn't exist. All `getRoundData()` calls revert, the `catch` blocks fire, and after `maxDecrements` iterations the loop exits **without modifying the return values**.

The function then returns the **fresh, undelayed price** from the initial `priceFeed.latestRoundData()` call.

Note that `_validateRoundData()` (called at line 255) does not catch this condition. The fresh price satisfies all three validation checks: `answer > 0` (valid price), `updatedAt != 0` (just posted), and `answeredInRound >= roundId` (complete round). The validation was designed to catch stale/invalid Chainlink data, not to detect OEV bypass.

### Affected contracts

- [`ChainlinkOEVWrapper.sol#L234`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVWrapper.sol#L234)
- [`ChainlinkOEVMorphoWrapper.sol`](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/oracles/ChainlinkOEVMorphoWrapper.sol) (same loop pattern)

Note: `ChainlinkCompositeOEVWrapper` uses a different caching mechanism (`cachedBaseRoundId` / `cachedCompositePrice`) and is NOT affected by this issue.

### On-chain verification

All OEV wrapper `priceFeed` addresses on Base point to Chainlink `AggregatorProxy` contracts that have `phaseId()` and composite round IDs. Verified examples:
- WETH wrapper (`0xeb083d...`): `priceFeed` = `0x71041d...` (ETH/USD AggregatorProxy, current `phaseId` = 1)
- USDC wrapper (`0x7600b9...`): `priceFeed` = `0x7e8600...` (USDC/USD AggregatorProxy)

## Proof of Concept

Runnable Foundry test deploying the **actual `ChainlinkOEVWrapper` contract** against a mock that faithfully simulates Chainlink's phase-encoded round ID behavior:

```solidity
// SPDX-License-Identifier: BSD-3-Clause
pragma solidity 0.8.19;

import {Test} from "forge-std/Test.sol";
import {ChainlinkOEVWrapper} from "../src/oracles/ChainlinkOEVWrapper.sol";
import {AggregatorV3Interface} from "../src/oracles/AggregatorV3Interface.sol";

contract MockPhaseAwareAggregator is AggregatorV3Interface {
    uint64 public phase3LastRound = 1000;
    int256 public phase3Price = 2000e8;
    uint64 public phase4CurrentRound = 1;
    int256 public phase4Price = 1800e8;
    bool public phaseChanged = false;

    function triggerPhaseChange() external { phaseChanged = true; }
    function decimals() external pure override returns (uint8) { return 8; }
    function description() external pure override returns (string memory) { return "ETH/USD"; }
    function version() external pure override returns (uint256) { return 1; }

    function _encodeRoundId(uint16 phase, uint64 aggRound) internal pure returns (uint80) {
        return uint80((uint256(phase) << 64) | uint256(aggRound));
    }

    function latestRoundData() external view override returns (
        uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound
    ) {
        if (!phaseChanged) {
            roundId = _encodeRoundId(3, phase3LastRound);
            answer = phase3Price;
        } else {
            roundId = _encodeRoundId(4, phase4CurrentRound);
            answer = phase4Price;
        }
        startedAt = block.timestamp;
        updatedAt = block.timestamp;
        answeredInRound = roundId;
    }

    function getRoundData(uint80 _roundId) external view override returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        uint16 phase = uint16(uint256(_roundId) >> 64);
        uint64 aggRound = uint64(_roundId);
        if (phase == 3 && aggRound >= 1 && aggRound <= phase3LastRound) {
            return (_roundId, phase3Price, block.timestamp - 600, block.timestamp - 600, _roundId);
        }
        if (phase == 4 && aggRound == phase4CurrentRound) {
            return (_roundId, phase4Price, block.timestamp, block.timestamp, _roundId);
        }
        revert("No data present");
    }

    function latestRound() external view override returns (uint256) {
        if (!phaseChanged) return uint256(_encodeRoundId(3, phase3LastRound));
        return uint256(_encodeRoundId(4, phase4CurrentRound));
    }
}

contract OEVPhaseChangeBypassTest is Test {
    MockPhaseAwareAggregator public mockFeed;
    ChainlinkOEVWrapper public wrapper;

    function setUp() public {
        mockFeed = new MockPhaseAwareAggregator();
        wrapper = new ChainlinkOEVWrapper(
            address(mockFeed),
            address(this),
            address(0x4), // mock chainlinkOracle
            address(0x5), // feeRecipient
            3000,  // liquidatorFeeBps
            300,   // maxRoundDelay = 5 minutes
            5      // maxDecrements
        );
    }

    function testPhaseChangeBypasses_OEV_Delay() public {
        // Before phase change: cachedRoundId matches latest, fresh price returned normally
        (, int256 priceBefore, , , ) = wrapper.latestRoundData();
        assertEq(priceBefore, 2000e8, "Setup: phase 3 price");

        // Phase change occurs (routine Chainlink aggregator upgrade)
        mockFeed.triggerPhaseChange();

        // BUG: wrapper should return delayed $2000 price, but returns fresh $1800
        (, int256 priceAfter, , , ) = wrapper.latestRoundData();
        assertEq(priceAfter, 1800e8, "BUG: Fresh price leaked — OEV delay bypassed");
    }
}
```

## Impact

- **OEV price delay mechanism completely bypassed** during Chainlink phase transitions
- Any liquidator can perform liquidations using the fresh price **without paying OEV fees** — directly extracting value that should flow to the protocol's `feeRecipient`
- Affects `ChainlinkOEVWrapper` and `ChainlinkOEVMorphoWrapper` across all chains where Moonwell is deployed (Base, Optimism, Moonbeam, Moonriver)
- Chainlink phase changes are [documented routine operational events](https://docs.chain.link/data-feeds/historical-data#roundid-in-proxy) outside Moonwell's control
- No admin or privileged access required — any liquidator can exploit this

The OEV delay mechanism serves a dual purpose: (1) capturing liquidation revenue for the protocol, and (2) providing a controlled buffer against MEV-driven liquidation cascades during volatile price movements. When bypassed during a phase change, both protections are lost simultaneously. This is the same class of vulnerability that caused Moonwell's [$1.78M bad debt incident on February 15, 2026](https://forum.moonwell.fi/t/mip-x43-cbeth-oracle-incident-summary/2068), where an OEV wrapper misconfiguration on cbETH resulted in unprotected liquidations and direct protocol losses. While that incident involved a configuration error and this finding involves a code-level edge case, the root cause is identical: the OEV price delay failing to activate when it should, exposing the protocol to unprotected liquidations.

For context, the on-chain `liquidatorFeeBps` is set to 3000 (30%) on Base, meaning the protocol expects to capture 70% of the liquidation bonus on every OEV-protected liquidation. During a phase change bypass, 100% goes to the liquidator and 0% to the protocol's `feeRecipient`.

## Recommended Mitigation

If the backward search loop exhausts `maxDecrements` without finding a valid round (e.g., due to a phase boundary), fall back to the last known good round (`cachedRoundId`):

```solidity
if (roundId != cachedRoundId && block.timestamp < updatedAt + maxRoundDelay) {
    uint256 currentRoundId = roundId - 1;
    bool found = false;

    for (uint256 i = 0; i < maxDecrements && currentRoundId > 0; i++) {
        try priceFeed.getRoundData(uint80(currentRoundId)) returns (
            uint80 r, int256 a, uint256 s, uint256 u, uint80 ar
        ) {
            roundId = r; answer = a; startedAt = s; updatedAt = u; answeredInRound = ar;
            found = true;
            break;
        } catch {
            currentRoundId--;
        }
    }

    // Fallback: if backward search failed (phase boundary), use last known good round
    if (!found && cachedRoundId > 0) {
        try priceFeed.getRoundData(uint80(cachedRoundId)) returns (
            uint80 r, int256 a, uint256 s, uint256 u, uint80 ar
        ) {
            roundId = r; answer = a; startedAt = s; updatedAt = u; answeredInRound = ar;
        } catch {}
    }
}
```

The `cachedRoundId` was valid at the time of the last `updatePriceEarlyAndLiquidate()` call, so Chainlink's proxy will resolve it even across phase boundaries (historical phase data is maintained).
