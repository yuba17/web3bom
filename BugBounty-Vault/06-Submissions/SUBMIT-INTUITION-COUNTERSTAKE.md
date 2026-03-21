## Summary

The `_hasCounterStake` function in MultiVault only checks for opposing positions within the **same bonding curve ID**, allowing users to bypass the for/against mutual exclusion by depositing on opposing sides of a triple using different bonding curves. This breaks the protocol's core semantic integrity — a user can simultaneously hold a "for" position on one curve and an "against" position on another curve for the same claim.

## Vulnerability Detail

In [`MultiVault.sol` line 1378-1387](https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/MultiVault.sol#L1378-L1387):

```solidity
function _hasCounterStake(bytes32 tripleId, uint256 curveId, address receiver) internal view returns (bool) {
    if (!_isTriple[tripleId]) {
        revert MultiVault_TermNotTriple();
    }

    // Find the "other side" of this triple
    bytes32 oppositeId = _getInverseTripleId(tripleId);

    return _vaults[oppositeId][curveId].balanceOf[receiver] > 0;
    //                         ^^^^^^^^ BUG: only checks the SAME curveId
}
```

The function checks `_vaults[oppositeId][curveId]` — the balance on the opposing triple vault **for the same curve only**. It does not iterate over all available curves to check for opposing positions.

This guard is called during `_processDeposit` at [line 753](https://github.com/0xIntuition/intuition-contracts-v2/blob/20181c162502da226ca25c31aef47872369212c9/src/protocol/MultiVault.sol#L753):

```solidity
if (_vaultType != VaultType.ATOM) {
    if (_hasCounterStake(termId, curveId, receiver)) revert MultiVault_HasCounterStake();
}
```

Since `curveId` is a user-controlled parameter (passed via `deposit()`), the user chooses which curve to deposit on. The guard only looks at that specific curve on the opposing side.

## Proof of Concept

Attack steps:

1. A triple exists with ID `tripleId` and counter-triple `counterTripleId`. Both have vaults initialized on curves 1 (default, Linear) and 2 (Progressive).

2. Alice calls `deposit(alice, tripleId, curveId=1, msg.value=1 ETH, minShares=0)` — deposits FOR on curve 1.

3. Alice calls `deposit(alice, counterTripleId, curveId=2, msg.value=1 ETH, minShares=0)` — deposits AGAINST on curve 2.

4. At step 3, `_hasCounterStake(counterTripleId, curveId=2, alice)` checks:
   - `oppositeId = tripleId`
   - `_vaults[tripleId][curveId=2].balanceOf[alice]` → **0** (Alice's FOR position is on curve 1, not curve 2)
   - Returns `false` → no revert → **deposit succeeds**

5. Alice now holds a FOR position (curve 1) AND an AGAINST position (curve 2) on the same claim. The counter-stake guard is completely bypassed.

## Impact

- **Breaks the core semantic invariant** of the for/against system — users should NOT be able to stake on both sides of the same claim
- **Enables risk-free hedging**: A user can deposit on both sides, profiting from whichever direction gains more subsequent deposits while limiting losses on the losing side
- **Undermines attestation credibility**: The entire purpose of the for/against mechanism is to ensure users have "skin in the game" for their position. Hedging both sides defeats this purpose
- **Applies to ALL triples** across ALL non-default curves

This qualifies as **High severity** under the bounty's criteria: "Economic loss not involving direct on-chain asset theft" and constitutes a way to circumvent expected protocol behavior that has direct economic consequences for other users who are faithfully participating in the for/against mechanism.

## Recommended Mitigation

Check all curves when validating counter-stakes, not just the depositing curve:

```solidity
function _hasCounterStake(bytes32 tripleId, uint256 curveId, address receiver) internal view returns (bool) {
    if (!_isTriple[tripleId]) {
        revert MultiVault_TermNotTriple();
    }

    bytes32 oppositeId = _getInverseTripleId(tripleId);

    // Check ALL curves for opposing positions, not just the same curveId
    uint256 curveCount = bondingCurveRegistry.count();
    for (uint256 i = 1; i <= curveCount; i++) {
        if (_vaults[oppositeId][i].balanceOf[receiver] > 0) {
            return true;
        }
    }
    return false;
}
```

Alternatively, maintain a per-user mapping of which "side" they are on for each triple, independent of curve ID.
