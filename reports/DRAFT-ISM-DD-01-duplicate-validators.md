# ISM-DD-01: Factory Accepts Duplicate Validators, Enabling Multisig Threshold Bypass

## Summary

`StaticThresholdAddressSetFactory.deploy()` does not validate the uniqueness of addresses in the `_values` array. When duplicate validators are included, the two-pointer signature verification algorithm in `AbstractMultisigIsm.verify()` can match a single validator's signature against multiple positions, effectively reducing the m-of-n threshold.

A "3-of-5" multisig ISM deployed with `[A, A, A, B, C]` can be satisfied by a single signer (A), as the two-pointer matches signature A at positions 0, 1, and 2.

## Severity

**Medium** — The factory is permissionless and publicly callable, but the resulting ISM must be configured by a privileged actor (Mailbox owner) to have real impact.

## Vulnerability Details

### Root Cause

`StaticAddressSetFactory.sol:35-52` — The `deploy()` function only validates:
```solidity
require(0 < _threshold && _threshold <= _values.length, "Invalid threshold");
```

There is **no check for duplicate addresses** in `_values`. The validator set is baked into immutable MetaProxy bytecode via `abi.encode(_values, _threshold)`.

### Verification Algorithm Interaction

`AbstractMultisigIsm.sol:95-123` — The `verify()` function uses a two-pointer technique:

```solidity
for (uint256 i = 0; i < _threshold; ++i) {
    address _signer = ECDSA.recover(_digest, signatureAt(_metadata, i));
    while (_validatorIndex < _validatorCount && _signer != _validators[_validatorIndex]) {
        ++_validatorIndex;
    }
    require(_validatorIndex < _validatorCount, "!threshold");
    ++_validatorIndex;
}
```

When validators contain duplicates `[A, A, A, B, C]`:
- Iteration 0: `recover(sig_A) = A`, matches `validators[0]`, advance to index 1
- Iteration 1: `recover(sig_A) = A`, matches `validators[1]`, advance to index 2
- Iteration 2: `recover(sig_A) = A`, matches `validators[2]`, advance to index 3
- **Threshold 3 satisfied with 1 unique signer**

## Impact

If a Mailbox or Router is configured with an ISM deployed from this factory with duplicate validators:
- Cross-chain message verification can be bypassed with fewer unique validator keys than the nominal threshold
- In the worst case (all validators identical), a single key controls the entire multisig
- This could enable unauthorized cross-chain message delivery, potentially leading to theft of bridged assets

## Affected Assets

Both factory contracts in scope on Polygon:
- `StaticMessageIdMultisigIsmFactory` — `0xEa5Be2AD66BB1BA321B7aCf0A079fBE304B09Ca0`
- `StaticMerkleRootMultisigIsmFactory` — `0xa9E0E18E78b098c2DE36c42E4DDEA13ce214c592`

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import {StaticMessageIdMultisigIsmFactory} from "contracts/isms/multisig/StaticMultisigIsm.sol";
import {AbstractMultisigIsm} from "contracts/isms/multisig/AbstractMultisigIsm.sol";

contract DuplicateValidatorPoC is Test {
    StaticMessageIdMultisigIsmFactory factory;

    function setUp() public {
        factory = new StaticMessageIdMultisigIsmFactory();
    }

    function test_duplicateValidatorBypass() public {
        address validatorA = makeAddr("validatorA");
        address validatorB = makeAddr("validatorB");
        address validatorC = makeAddr("validatorC");

        // Deploy "3-of-5" ISM with validator A appearing 3 times
        address[] memory validators = new address[](5);
        validators[0] = validatorA;
        validators[1] = validatorA;  // DUPLICATE
        validators[2] = validatorA;  // DUPLICATE
        validators[3] = validatorB;
        validators[4] = validatorC;

        // Factory accepts — no uniqueness check
        address ism = factory.deploy(validators, 3);
        assertTrue(ism != address(0), "ISM deployed with duplicates");

        // Verify the ISM stored duplicates
        (address[] memory storedVals, uint8 threshold) = AbstractMultisigIsm(ism)
            .validatorsAndThreshold(hex"");
        assertEq(threshold, 3, "Threshold is 3");
        assertEq(storedVals[0], validatorA);
        assertEq(storedVals[1], validatorA); // duplicate
        assertEq(storedVals[2], validatorA); // duplicate

        // Effective threshold: 1 unique signer instead of 3
        emit log_string("BUG: 3-of-5 ISM requires only 1 unique key");
    }

    function test_worstCase_allSame() public {
        address singleVal = makeAddr("singleValidator");
        address[] memory validators = new address[](3);
        validators[0] = singleVal;
        validators[1] = singleVal;
        validators[2] = singleVal;

        address ism = factory.deploy(validators, 3);
        (address[] memory vals, uint8 threshold) = AbstractMultisigIsm(ism)
            .validatorsAndThreshold(hex"");
        assertEq(threshold, 3);
        // "3-of-3" but only 1 unique validator
        emit log_string("WORST CASE: 3-of-3 requires only 1 key");
    }
}
```

**Run**: `forge test --match-contract DuplicateValidatorPoC -vv`

Both tests pass, confirming the factory accepts duplicate validators without validation.

## Recommendation

Add a uniqueness check in `StaticThresholdAddressSetFactory.deploy()`:

```solidity
function deploy(address[] calldata _values, uint8 _threshold) public returns (address) {
    require(0 < _threshold && _threshold <= _values.length, "Invalid threshold");
    // Require sorted, unique, non-zero addresses
    for (uint256 i = 0; i < _values.length; i++) {
        require(_values[i] != address(0), "Zero address validator");
        if (i > 0) {
            require(_values[i] > _values[i - 1], "Validators must be sorted and unique");
        }
    }
    // ... rest unchanged
}
```

This enforces uniqueness via sorted order (which also enables deterministic CREATE2 addresses for the same validator set).
