# [H/M-XX] Title — One sentence describing the vulnerability

## Summary
2-3 sentences. What's broken, where, and what's the impact.

## Finding Description
Detailed technical description with code references.

```solidity
// Vulnerable code with line numbers
```

Explain the root cause. Reference specific lines.

## Impact
- **Severity:** High/Medium
- **Likelihood:** How likely is this to happen naturally or be exploited?
- **Impact:** What's the worst case? Quantify in USD if possible.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
// ... imports

contract PoC is Test {
    function setUp() public {
        // Deploy contracts
    }

    function test_exploit() public {
        // Step-by-step exploit
        // Assert the impact
    }
}
```

**Run:** `forge test --match-test test_exploit -vvv`

## Recommendation

```solidity
// Fix code
```

One paragraph explaining why the fix works.
