# IAR-DD-02: `callRemoteCommitReveal` Drains Pre-existing Router ETH via `address(this).balance`

## Bug Description

`InterchainAccountRouter.callRemoteCommitReveal()` performs two sequential dispatches — a commit and a reveal. The reveal dispatch at line 630 uses `address(this).balance` instead of tracking the remaining `msg.value`, causing pre-existing ETH in the router to be consumed.

```solidity
// InterchainAccountRouter.sol:606-631
function callRemoteCommitReveal(...) external payable returns (bytes32, bytes32) {
    // First dispatch: commit (uses msg.value, refundAddress=address(this))
    bytes32 commitId = _dispatchMessageWithValue(
        ...
        StandardHookMetadata.overrideRefundAddress(address(this)), // L613
        msg.value  // L617
    );

    // Second dispatch: reveal (BUG: uses ALL of router's ETH balance)
    bytes32 revealId = _dispatchMessageWithValue(
        ...
        StandardHookMetadata.overrideRefundAddress(msg.sender), // L625
        address(this).balance  // L630 — includes pre-existing ETH!
    );
}
```

The `receive() external payable {}` function (line 107) allows anyone to send ETH to the router. Additionally, the first dispatch's refund goes to `address(this)`, accumulating in the router.

## Impact

**Inter-user ETH value leak.** When a user calls `callRemoteCommitReveal`:

1. The commit dispatch sends `msg.value` to the hook, which refunds excess back to the router
2. The reveal dispatch sends `address(this).balance` — which includes pre-existing ETH from other users' refunds, direct deposits, or force-sent ETH
3. The reveal's refund goes to `msg.sender` (the caller), meaning the caller receives refunds that include OTHER users' ETH

Cumulative effect: ETH from earlier callers' refunds subsidizes later callers' reveal dispatches. The last caller effectively drains accumulated ETH.

## Risk Breakdown

- **Difficulty**: Low — requires sending ETH to router (via `receive()`) before another user's `callRemoteCommitReveal`
- **On-chain**: `callRemoteCommitReveal` selector `0x802d0616` confirmed in deployed Polygon router
- **Severity**: Medium — value leak bounded by router's ETH balance at time of call

## Recommendation

Track the remaining `msg.value` after the first dispatch instead of using `address(this).balance`:

```solidity
uint256 balanceBefore = address(this).balance - msg.value;
// ... first dispatch ...
uint256 remaining = address(this).balance - balanceBefore;
// ... second dispatch with 'remaining' instead of address(this).balance ...
```

## Proof of Concept

Tests run on ETH mainnet fork. 3/3 PASS demonstrating:
1. Pre-existing ETH consumed by reveal dispatch
2. Multiple victims' ETH drained by subsequent caller
3. Precise accounting showing the exact value leak

### Running

```bash
cd hyperlane-monorepo/solidity
source ../../.env && export ETH_RPC_URL
forge test --match-contract IAR_DD_02 -vvv
```

### Output (3/3 PASS)

```
[PASS] test_DD02_fullDrainMultipleVictims() (gas: 573687)
[PASS] test_DD02_preciseAccounting() (gas: 553040)
[PASS] test_DD02_revealConsumesPreExistingEth() (gas: 566720)
Suite result: ok. 3 passed; 0 failed; 0 skipped
```
