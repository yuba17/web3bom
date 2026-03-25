# IAR-DD-05: Atomic Multicall in `handle()` — Permanent Message DoS

## Bug Description

`InterchainAccountRouter.handle()` at line 163 calls `ica.multicall{value: msg.value}(calls)` atomically. Inside `CallLib.multicall()`, calls execute sequentially — if **any single call reverts**, the entire multicall reverts, `handle()` reverts, and `Mailbox.process()` reverts.

```solidity
// InterchainAccountRouter.sol:161-163
ica.multicall{value: msg.value}(calls);
// No try/catch, no partial execution, no fallback
```

There is **no mechanism** to:
- Skip a failing call and execute the rest
- Cancel a pending message from the origin chain
- Modify the calls after dispatch
- Force-deliver with error handling

## Impact

**Permanent cross-chain message DoS.** If the target contract's state changes between dispatch (origin) and delivery (destination) such that any call always reverts, the message is permanently stuck.

Attack scenario:
1. User dispatches `callRemote` with a batch of calls targeting a pausable contract
2. Adversary front-runs delivery by pausing the target contract (or changing state)
3. `handle()` reverts on every retry attempt
4. A single reverting call in a batch blocks ALL calls — including ones that would succeed

**Collateral damage**: In a batch of N calls, if call #3 reverts, calls #1, #2, #4...#N are all blocked despite being valid.

## Risk Breakdown

- **Severity**: Medium — permanent DoS, no recovery mechanism
- **On-chain**: `handle()` and `multicall()` confirmed in deployed Polygon contracts
- **Novelty**: Known cross-chain pattern, but no mitigation implemented

## Recommendation

Add a `tryMulticall` option or per-call error handling:

```solidity
function multicall(Call[] memory calls) internal {
    for (uint i = 0; i < calls.length; i++) {
        (bool success, ) = target.call{value: calls[i].value}(calls[i].data);
        if (!success) emit CallFailed(i, calls[i]);
        // Continue with remaining calls
    }
}
```

## Proof of Concept

4/4 tests PASS demonstrating: normal operation, revert on pause, permanent stuck message, and batch collateral damage.

### Running

```bash
cd hyperlane-monorepo/solidity
source ../../.env && export ETH_RPC_URL
forge test --match-contract IAR_DD_05 -vvv
```
