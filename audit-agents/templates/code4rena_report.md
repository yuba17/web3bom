# Code4rena Bug Bounty Report Template

<!--
=============================================================================
CODE4RENA SUBMISSION FORMAT
=============================================================================

PLATFORM RULES (as of 2026):
- High/Medium: Submit INDIVIDUALLY (one finding per submission)
- Low/QA/Governance: Submit as ONE consolidated QA report per warden
- PoC REQUIRED for all High/Medium unless repo README says otherwise
- PoC must use the audit repo's test suite
- Quality bar: "professional auditor draft report"
- Duplicates share awards; full credit requires root cause + max impact

SEVERITY DEFINITIONS (Code4rena):
  HIGH (3): Assets can be stolen/lost/compromised directly or via valid
            attack path. Direct or demonstrable indirect loss of funds,
            NFTs, data, or authorization.
  MEDIUM (2): Assets not at direct risk, but protocol function or
              availability could be impacted. Requires stated assumptions.
              Unmatured yield loss caps at Medium.
  QA/LOW: Assets not at risk. State handling or spec-incorrect functions.
           Dust amounts, rounding errors, unused view functions, governance
           issues all cap at QA.

NOT VALID at High/Medium:
  - Rounding errors / dust amounts
  - Unused view functions
  - Event/data display issues (Low max)
  - User input mistakes
  - Admin/governance privilege issues (QA only)

TITLE FORMAT: [Verb] + [Impact] + [Location]
  GOOD:  "Reentrancy in `withdraw()` allows draining all vault ETH"
  GOOD:  "Missing slippage check in `swap()` enables sandwich attacks for ~5% loss per tx"
  BAD:   "Bug in withdraw function"
  BAD:   "Possible issue with swap"
-->

## Lines of code

<!-- REQUIRED: Direct GitHub permalink(s) to the vulnerable line(s).
     Use the audit repo's GitHub URL, not local file paths.
     Multiple links allowed, one per line. -->

https://github.com/code-423n4/2026-XX-PROTOCOL/blob/main/src/Contract.sol#L123-L145

## Vulnerability details

### Impact

<!-- SEVERITY FRAMING - use these EXACT patterns:

FOR HIGH:
"This vulnerability allows an attacker to [steal/drain/permanently freeze]
[specific assets] from [the protocol/all depositors/the treasury].
At current TVL of $X, the maximum extractable value is approximately $Y."

FOR MEDIUM:
"This vulnerability causes [protocol dysfunction/temporary freeze/value leakage]
under [specific conditions]. While assets are not directly at risk, [specific
consequence] impacts protocol availability/correctness."

QUANTIFY IN USD:
1. Check current TVL on DefiLlama
2. Calculate maximum extractable amount
3. State assumptions clearly
4. If yield/fee related, annualize the loss

Example:
"The vault currently holds ~$12M in TVL. An attacker can extract the full
balance in a single transaction by re-entering `withdraw()` before the
balance update. Estimated loss: $12M (full TVL)."
-->

[Describe impact here. Be specific. Quantify in USD.]

### Proof of Concept

<!-- POC REQUIREMENTS:
1. MUST use the audit repo's existing test suite
2. MUST be a runnable Foundry/Hardhat test
3. MUST show the exact revert error (not just "reverts")
4. Show it as a diff against existing test files
5. Include setup, attack, and assertion phases clearly labeled

Structure:
  1. SETUP: Fork state or use existing test fixtures
  2. STATE BEFORE: Log/assert the pre-attack state
  3. ATTACK: Execute the exploit step by step
  4. STATE AFTER: Log/assert the post-attack state proving impact
  5. PROFIT: Show exactly what the attacker gained
-->

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
// Import from the audit repo's existing contracts
import {VulnerableContract} from "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Use the audit repo's deployment scripts or replicate setup
        target = new VulnerableContract();

        // Fund accounts to match realistic conditions
        vm.deal(victim, 10 ether);
        vm.deal(attacker, 1 ether);

        // Setup: victim deposits funds
        vm.prank(victim);
        target.deposit{value: 10 ether}();
    }

    function test_exploit_description() public {
        // === STATE BEFORE ===
        uint256 attackerBalanceBefore = attacker.balance;
        uint256 vaultBalanceBefore = address(target).balance;
        console2.log("Vault balance before:", vaultBalanceBefore);
        console2.log("Attacker balance before:", attackerBalanceBefore);

        // === ATTACK ===
        vm.startPrank(attacker);
        // Step 1: [describe first action]
        // Step 2: [describe second action]
        // Step 3: [describe third action]
        vm.stopPrank();

        // === STATE AFTER ===
        uint256 attackerBalanceAfter = attacker.balance;
        uint256 vaultBalanceAfter = address(target).balance;
        console2.log("Vault balance after:", vaultBalanceAfter);
        console2.log("Attacker balance after:", attackerBalanceAfter);

        // === PROFIT ===
        uint256 profit = attackerBalanceAfter - attackerBalanceBefore;
        console2.log("Attacker profit:", profit);

        // Assertions proving the vulnerability
        assertGt(profit, 0, "Attacker should have profited");
        assertLt(vaultBalanceAfter, vaultBalanceBefore, "Vault should have lost funds");
    }
}
```

**Steps to reproduce:**
1. `cd` into the audit repo
2. Run `forge test --match-test test_exploit_description -vvv`
3. Observe that [specific outcome proving the bug]

### Tools Used

Manual review, Foundry

### Recommended Mitigation Steps

<!-- MITIGATION FORMAT: Show you understand the fix deeply.
     1. Explain the ROOT CAUSE (not just the symptom)
     2. Provide a concrete code diff
     3. If multiple fixes exist, recommend the most robust one
     4. Mention any tradeoffs
-->

**Root Cause:** [One sentence identifying exactly why this bug exists]

**Recommended Fix:**

```diff
// src/Contract.sol

  function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount, "Insufficient");
+     balances[msg.sender] -= amount;
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success, "Transfer failed");
-     balances[msg.sender] -= amount;
  }
```

**Alternative approaches:**
- Add OpenZeppelin's `ReentrancyGuard` with `nonReentrant` modifier
- Both fixes should be applied for defense-in-depth

---

<!--
=============================================================================
QA REPORT FORMAT (for Low/Governance findings - ONE report per warden)
=============================================================================
-->

# QA Report

<!-- Use this format ONLY for Low and Centralization/Governance findings.
     ALL such findings go in a single report. Use L-XX and C-XX labels. -->

## [L-01] Missing zero-address check in `setOracle()`

**Location:** [GitHub permalink]

**Description:** The `setOracle()` function accepts any address without
validating against `address(0)`. If accidentally set to zero address,
all oracle-dependent functions will revert permanently.

**Recommendation:**
```diff
  function setOracle(address _oracle) external onlyOwner {
+     require(_oracle != address(0), "zero address");
      oracle = _oracle;
  }
```

## [L-02] [Next finding title]

...

## [C-01] Owner can rug-pull via `emergencyWithdraw()`

**Location:** [GitHub permalink]

**Description:** The owner can call `emergencyWithdraw()` at any time to
drain all deposited funds. No timelock, multisig, or governance vote
is required.

**Recommendation:** Add a timelock mechanism and emit an event before
execution so users can exit.

---

<!--
=============================================================================
COMMON MISTAKES TO AVOID (Code4rena specific)
=============================================================================

1. WRONG SEVERITY: Inflating Low -> Medium or Medium -> High is the #1
   reason for rejection. When in doubt, go lower.

2. NO RUNNABLE POC: For High/Medium, "theoretically possible" is not enough.
   The PoC must compile and run.

3. DUPLICATE OF KNOWN ISSUE: Always check the audit repo's README "known issues"
   section, previous audits, and the contest's Discord channel.

4. ADMIN/GOVERNANCE FINDINGS AS HIGH: These cap at QA. The protocol trusts
   its admin. Don't submit "admin can rug" as High.

5. GENERIC DESCRIPTIONS: "This could lead to loss of funds" without specifics.
   Always quantify: how much, under what conditions, with what probability.

6. SUBMITTING BOT FINDINGS: Automated tool output (Slither, Aderyn) findings
   are excluded. The issue must require human insight.

7. MULTIPLE FINDINGS SAME ROOT CAUSE: If two issues share a root cause,
   they're ONE finding. Submit the highest-impact version.

8. MISSING GITHUB PERMALINKS: The "Lines of code" section is mandatory.
   Use exact line numbers from the audit repo.

9. STALE FINDINGS: Verify the bug exists in the CURRENT commit, not an
   older version of the code.

10. LLM-GENERATED FLUFF: Judges can tell. Be concise, technical, specific.
    No filler paragraphs.
-->
