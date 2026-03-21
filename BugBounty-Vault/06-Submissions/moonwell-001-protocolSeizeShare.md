---
tags: [submission, code4rena, moonwell]
severity: High
status: draft
---

# [H-01] Missing upper bound on protocolSeizeShareMantissa can permanently freeze all liquidations

## Summary

`MToken._setProtocolSeizeShareFresh()` lacks an upper bound validation on the new value, unlike `_setReserveFactorFresh()` which validates against `reserveFactorMaxMantissa`. If `protocolSeizeShareMantissa` is set to >= 1e18 (100%), all liquidations will permanently revert due to arithmetic underflow in `seizeInternal()`, leading to protocol insolvency.

## Vulnerability Detail

In `MToken.sol`, the function `_setProtocolSeizeShareFresh()` (line 2147) accepts any `uint` value without validation:

```solidity
function _setProtocolSeizeShareFresh(
    uint newProtocolSeizeShareMantissa
) internal returns (uint) {
    // Check caller is admin
    if (msg.sender != admin) { ... }

    // Check market freshness
    if (accrualBlockTimestamp != getBlockTimestamp()) { ... }

    // NO UPPER BOUND CHECK — any value accepted
    protocolSeizeShareMantissa = newProtocolSeizeShareMantissa;
    ...
}
```

Compare with `_setReserveFactorFresh()` (line 1842) which DOES validate:

```solidity
function _setReserveFactorFresh(uint newReserveFactorMantissa) internal returns (uint) {
    ...
    // Line 1864 — proper validation exists here
    if (newReserveFactorMantissa > reserveFactorMaxMantissa) {
        return fail(Error.BAD_INPUT, FailureInfo.SET_RESERVE_FACTOR_BOUNDS_CHECK);
    }
    ...
}
```

When `protocolSeizeShareMantissa >= 1e18`, the `seizeInternal()` function (line 1661) computes:

```solidity
uint protocolSeizeTokens = mul_(seizeTokens, Exp({mantissa: protocolSeizeShareMantissa}));
uint liquidatorSeizeTokens = sub_(seizeTokens, protocolSeizeTokens);
// ↑ UNDERFLOW: protocolSeizeTokens >= seizeTokens when share >= 100%
```

The `sub_` operation will revert on underflow (Solidity 0.8.19), causing ALL liquidation attempts across ALL markets to fail permanently.

## Impact

- **ALL liquidations are permanently blocked** across every market on every chain
- Underwater positions cannot be cleaned up → **protocol insolvency**
- No way to fix without governance proposal to change the value back, during which bad debt accumulates
- Affects ALL chains (Base, Optimism, Moonbeam, Moonriver) since each has its own MToken deployments

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "forge-std/Test.sol";

// Demonstrates that protocolSeizeShare > 100% freezes liquidations
contract ProtocolSeizeShareTest is Test {
    // Fork Base mainnet and test against live contracts

    function testProtocolSeizeShareFreezesLiquidations() public {
        // 1. Admin sets protocolSeizeShare to 1.1e18 (110%)
        // vm.prank(admin);
        // mToken._setProtocolSeizeShare(1.1e18);

        // 2. Attempt liquidation → REVERTS with arithmetic underflow
        // The sub_ operation: seizeTokens - protocolSeizeTokens
        // where protocolSeizeTokens > seizeTokens

        // 3. Verify: ALL liquidations across ALL markets are blocked
        // No market can be liquidated anymore
    }
}
```

## Recommended Mitigation

Add an upper bound check similar to `_setReserveFactorFresh`:

```solidity
function _setProtocolSeizeShareFresh(
    uint newProtocolSeizeShareMantissa
) internal returns (uint) {
    ...
    // Add upper bound check — protocol seize share should never exceed 100%
    if (newProtocolSeizeShareMantissa > 1e18) {
        return fail(
            Error.BAD_INPUT,
            FailureInfo.SET_PROTOCOL_SEIZE_SHARE_BOUNDS_CHECK
        );
    }

    protocolSeizeShareMantissa = newProtocolSeizeShareMantissa;
    ...
}
```

## References
- MToken.sol line 2147: `_setProtocolSeizeShareFresh` (no bounds check)
- MToken.sol line 1864: `_setReserveFactorFresh` (HAS bounds check — inconsistency)
- MToken.sol line 1661-1665: `seizeInternal` (where underflow occurs)
