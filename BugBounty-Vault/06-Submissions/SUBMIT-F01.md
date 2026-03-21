# Missing upper bound on protocolSeizeShareMantissa allows governance to permanently freeze all liquidations

## Summary

`MToken._setProtocolSeizeShareFresh()` accepts any value without an upper bound check, unlike `_setReserveFactorFresh()` which validates against `reserveFactorMaxMantissa`. If governance sets `protocolSeizeShareMantissa >= 1e18`, all liquidations permanently revert due to arithmetic underflow in `seizeInternal()`, leading to protocol-wide insolvency.

## Vulnerability Detail

In `MToken.sol`, `_setProtocolSeizeShareFresh()` ([line 2147](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/MToken.sol)) sets the protocol seize share without any validation:

```solidity
function _setProtocolSeizeShareFresh(
    uint newProtocolSeizeShareMantissa
) internal returns (uint) {
    if (msg.sender != admin) { return fail(...); }
    if (accrualBlockTimestamp != getBlockTimestamp()) { return fail(...); }

    // NO UPPER BOUND CHECK
    protocolSeizeShareMantissa = newProtocolSeizeShareMantissa;
}
```

In contrast, `_setReserveFactorFresh()` ([line 1842](https://github.com/moonwell-fi/moonwell-contracts-v2/blob/main/src/MToken.sol)) **does** validate:

```solidity
function _setReserveFactorFresh(uint newReserveFactorMantissa) internal returns (uint) {
    ...
    if (newReserveFactorMantissa > reserveFactorMaxMantissa) {  // ← VALIDATED
        return fail(Error.BAD_INPUT, FailureInfo.SET_RESERVE_FACTOR_BOUNDS_CHECK);
    }
}
```

When `protocolSeizeShareMantissa >= 1e18` (100%), `seizeInternal()` computes:

```solidity
// Line 1661-1665
uint protocolSeizeTokens = mul_(seizeTokens, Exp({mantissa: protocolSeizeShareMantissa}));
uint liquidatorSeizeTokens = sub_(seizeTokens, protocolSeizeTokens);
// When share >= 100%: protocolSeizeTokens >= seizeTokens → UNDERFLOW REVERT
```

## Proof of Concept

Tested against Base mainnet fork (`protocolSeizeShareMantissa` confirmed at `3e16` = 3%):

```solidity
function testProtocolSeizeShareNoUpperBound() public {
    address admin = IMToken(MOONWELL_USDC).admin(); // 0x8b621804...

    vm.prank(admin);
    uint result = IMToken(MOONWELL_USDC)._setProtocolSeizeShare(1.5e18); // 150%
    assertEq(result, 0); // SUCCESS — no bounds check
    assertEq(IMToken(MOONWELL_USDC).protocolSeizeShareMantissa(), 1.5e18);
}

function testSeizeInternalUnderflow() public pure {
    uint seizeTokens = 1000e8;
    uint protocolSeizeShareMantissa = 1.5e18;
    uint protocolSeizeTokens = (seizeTokens * protocolSeizeShareMantissa) / 1e18;
    // = 1500e8 > 1000e8 → underflow on subtraction
    assert(protocolSeizeTokens > seizeTokens); // PROVES UNDERFLOW
}
```

Both tests pass on Base mainnet fork.

## Impact

- **ALL liquidations permanently revert** across every Moonwell market on the affected chain
- Underwater positions accumulate bad debt with no way to clean them up
- Protocol becomes insolvent
- Requires governance proposal to fix, during which bad debt continues accumulating
- The admin on Base is the TemporalGovernor (`0x8b621804a7637b781e2BbD58e256a591F2dF7d51`), controlled by MultichainGovernor — so this requires a governance proposal or break glass guardian action

## Recommended Mitigation

Add an upper bound check consistent with `_setReserveFactorFresh`:

```solidity
function _setProtocolSeizeShareFresh(
    uint newProtocolSeizeShareMantissa
) internal returns (uint) {
    ...
    // Add: protocol seize share cannot exceed 100%
    if (newProtocolSeizeShareMantissa > 1e18) {
        return fail(Error.BAD_INPUT, FailureInfo.SET_PROTOCOL_SEIZE_SHARE_BOUNDS_CHECK);
    }

    protocolSeizeShareMantissa = newProtocolSeizeShareMantissa;
    ...
}
```

A more conservative bound (e.g., `0.5e18` = 50%) would be even safer.
