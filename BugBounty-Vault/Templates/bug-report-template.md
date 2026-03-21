---
tags: [submission, {{platform}}]
protocol: {{protocol}}
severity: {{Critical/High/Medium/Low}}
status: {{draft/submitted/accepted/rejected/duplicate}}
bounty: ${{amount}}
date_submitted: {{date}}
---

# {{Bug Title}}

## Summary
<!-- One paragraph describing the vulnerability -->

## Vulnerability Detail
<!-- Technical description with code references -->

### Root Cause
```solidity
// The vulnerable code
```

### Attack Path
1. Attacker calls...
2. This causes...
3. Resulting in...

## Impact
<!-- What can an attacker achieve? Quantify funds at risk -->

- **Funds at Risk**: $
- **Affected Users**:
- **Attack Cost**:

## Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function testExploit() public {
        // Setup

        // Attack

        // Verify
    }
}
```

## Recommended Mitigation
```solidity
// Fixed code
```

## References
- Similar bugs:
- Related audits:

## Post-Submission Notes
- Response date:
- Outcome:
- Lessons learned:
