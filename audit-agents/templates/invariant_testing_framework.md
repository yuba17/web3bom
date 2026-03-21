# Economic Invariant Testing Framework

## Overview

This framework flips the audit approach: instead of searching for code bugs,
we define what MUST be true (invariants), then systematically try to break them.
Every DeFi exploit in history is an invariant violation. This makes the hunt systematic.

## Architecture

```
Phase 1: EXTRACT         Phase 2: ATTACK          Phase 3: VERIFY
[Protocol Code] -->      [Invariant List] -->      [Attack Sequences] -->
  InvariantExtractor       AttackGenerator           FoundryForkTest
  Agent                    Agent                     (automated)
```

Three Claude Code agents run sequentially. Each agent's output feeds the next.
The final output is runnable Foundry test code that forks mainnet and attempts
to break each invariant.

---

## HOW TO USE THIS FRAMEWORK

### Quick Start (5 minutes)

1. Set your target:
```bash
export TARGET_PROTOCOL="EulerVault"
export TARGET_DIR="/path/to/protocol/contracts"
export CHAIN_RPC="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
export DEPLOYED_ADDRESS="0x..."
```

2. Run Agent 1 (Invariant Extraction):
   - Open Claude Code
   - Paste the Agent 1 prompt below
   - Append the contract source code
   - Save output as `invariants.md`

3. Run Agent 2 (Attack Generation):
   - New Claude Code session
   - Paste the Agent 2 prompt below
   - Append `invariants.md` content + contract source
   - Save output as `attacks.md`

4. Run Agent 3 (Foundry Test Generation):
   - New Claude Code session
   - Paste the Agent 3 prompt below
   - Append `attacks.md` content + contract source
   - Agent outputs `.t.sol` files directly

5. Execute:
```bash
cd foundry-workspace
forge test --match-contract InvariantBreaker --fork-url $CHAIN_RPC -vvvv
```

---

## AGENT 1: INVARIANT EXTRACTOR

### Prompt Template

```
You are analyzing a DeFi protocol to extract every economic invariant it
depends on. An invariant is a property that MUST hold after every state-
changing transaction, or the protocol is broken.

YOUR OUTPUT will be consumed by an attack-generation agent. Be precise.
Every invariant you miss is a bug we will never find. Every false invariant
wastes attack budget. Quality matters.

## PROTOCOL CODE

{{PASTE_CONTRACT_SOURCE_HERE}}

## EXTRACTION METHODOLOGY

Read the code and extract invariants in this exact order:

### 1. BALANCE INVARIANTS (what adds up to what)

For every token the protocol holds, answer:
- What is the relationship between the contract's actual token balance
  and its internal accounting variables?
- Formula: `token.balanceOf(contract) [>=|==|<=] internalVariable`
- When does equality hold vs inequality? What causes the gap?

For every share/receipt token the protocol mints:
- `totalShares * pricePerShare [relationship] totalAssets`
- What happens to this after: deposit, withdraw, fee accrual, donation,
  liquidation, rebalance?

For every mapping of user balances:
- `sum(userBalances[i] for all i) [relationship] totalTracked`
- Can any operation break this? What about the first user? Last user?

### 2. MONOTONICITY INVARIANTS (what only goes one direction)

- Which variables should NEVER decrease? (totalSupply of non-burnable token,
  accumulated fees, share price in fee-only vaults)
- Which variables should NEVER increase? (remaining allowance after transfer
  without approval, debt after full repayment)
- Which counters should be strictly increasing? (nonces, epoch IDs)

### 3. RATIO/BOUND INVARIANTS (what stays within limits)

- Collateralization ratios: `collateral * price / debt >= minRatio`
- Utilization bounds: `0 <= borrowed / deposited <= maxUtilization`
- Fee bounds: `fee <= maxFee` and `fee >= 0`
- Slippage bounds: `actualOutput >= minOutput`
- Supply caps: `totalMinted <= supplyCap`

### 4. STATE MACHINE INVARIANTS (valid transitions)

- What states can the protocol be in? (Active, Paused, Shutdown, Migrating)
- Which transitions are valid? Draw the state graph.
- For multi-step operations (e.g., request withdrawal -> wait -> claim):
  what is the required sequence? Can steps be skipped or reordered?
- Are there states that should be unreachable?

### 5. CROSS-CONTRACT INVARIANTS (consistency across contracts)

- If the protocol has multiple interacting contracts, what must be
  consistent between them?
- For bridges: `locked_on_source >= minted_on_destination`
- For multi-pool systems: `sum(pool_assets) == global_total_assets`
- For proxy patterns: `implementation.slot == expected_implementation`

### 6. TIMING INVARIANTS (temporal constraints)

- Cooldown periods: `lastAction + cooldown <= block.timestamp` for
  time-restricted operations
- Deadline enforcement: operations expire after deadline
- Oracle freshness: `block.timestamp - oracle.updatedAt <= maxStaleness`
- Epoch boundaries: what must be true at epoch transitions?

## OUTPUT FORMAT

For each invariant, output EXACTLY this structure:

```
INVARIANT [category_letter][number]:
  PROPERTY: [mathematical statement using actual variable names from code]
  HOLDS_AFTER: [list of functions where this must hold after execution]
  TYPE: [equality | inequality | monotonic_increase | monotonic_decrease | bound | state_transition]
  IMPLICIT: [yes/no -- is this asserted in code with require/assert, or just assumed?]
  PRIORITY: [P0/P1/P2 -- P0 means violation = direct fund loss]
  ATTACK_SURFACE: [brief note on what could break this]
```

IMPORTANT RULES:
- Use ACTUAL variable names from the source code, not generic names.
- Every invariant must reference specific contract functions.
- Mark implicit invariants (no on-chain assertion). These are the
  highest-value targets because the code does not enforce them.
- P0 = direct fund theft possible. P1 = fund loss under conditions.
  P2 = protocol malfunction without direct theft.
- Aim for 15-40 invariants. Fewer means you missed some. More than
  50 means you are including trivial ones.
```

---

## AGENT 2: ATTACK SEQUENCE GENERATOR

### Prompt Template

```
You are constructing concrete attack sequences to break DeFi protocol
invariants. You have received an invariant list from the previous agent.
Your job: for each P0 and P1 invariant, design 2-3 specific transaction
sequences that attempt to violate it.

You think like a $10M attacker with flash loan access and perfect timing.

## INVARIANT LIST

{{PASTE_INVARIANT_LIST_HERE}}

## PROTOCOL CODE

{{PASTE_CONTRACT_SOURCE_HERE}}

## ATTACK GENERATION RULES

For each invariant, try EACH of these attack patterns (in order of
historical success rate):

### PATTERN A: Donation Attack (most common vault bug)
1. Send tokens directly to contract via `token.transfer(contract, amount)`
   (NOT through deposit function)
2. Check: does this break the balance invariant?
3. Check: does this inflate share price?
4. Check: can the next depositor be front-run for profit?

Concrete test: deposit 1 wei -> donate 1e18 tokens -> next user deposits
1e18 tokens and gets 0 shares due to rounding.

### PATTERN B: Flash Loan Amplification
1. Flash borrow maximum available liquidity
2. Use borrowed funds to manipulate protocol state
3. Extract value at manipulated state
4. Return flash loan
5. Check: net profit after flash loan fee?

Concrete test: flash borrow -> deposit into vault -> manipulate price ->
withdraw more than deposited -> repay flash loan -> check profit.

### PATTERN C: First/Last User Edge Cases
1. Be the first depositor with 1 wei
2. Donate large amount to inflate share price
3. Other users deposit and lose to rounding
4. Withdraw everything

Also test: what happens when you are the LAST user withdrawing?
Does `totalShares == 0` but `totalAssets > 0` (stuck dust)?

### PATTERN D: Rounding Exploitation
1. Find all division operations in deposit/withdraw/fee paths
2. For each: which direction does rounding go?
3. Can you do many small operations to accumulate rounding errors?
4. Specific: deposit amount that rounds shares DOWN, withdraw same
   shares at amount that rounds UP. Repeat 1000x.

### PATTERN E: Reentrancy During State Transition
1. Identify all external calls (token transfers, callbacks)
2. For each: what is the contract state DURING the call?
3. If state is partially updated, can a callback exploit the
   inconsistency?
4. Specific: withdraw triggers token transfer -> callback re-enters
   deposit -> state is inconsistent.

### PATTERN F: Oracle Manipulation
1. If protocol reads from an AMM for pricing: flash swap to
   move price, execute protocol action, swap back.
2. If protocol uses Chainlink: wait for price at deviation threshold
   boundary.
3. If protocol uses TWAP: can sustained trading over the window
   manipulate the TWAP enough to profit?

### PATTERN G: Fee Avoidance
1. Can you deposit and withdraw in the same block, paying zero fees?
2. Can you pass amount=0 to trigger state changes without fees?
3. Can you split a large operation into many small ones where the
   fee rounds to 0 each time?

### PATTERN H: Sandwich Protocol Operations
1. Identify any operation that reads and then writes a price/rate.
2. Front-run: move the price in your favor before the operation.
3. Back-run: reverse your trade after the operation executes.
4. Specific targets: rebalance(), harvest(), liquidate(), updatePrice()

### PATTERN I: Cross-Function Composition
1. Can calling function A put the system in a state where function B
   misbehaves?
2. Are there two operations that are individually safe but dangerous
   in sequence?
3. Can you interleave your calls with another user's calls for profit?

### PATTERN J: Extreme Values
1. amount = 0 (should this be allowed?)
2. amount = 1 (minimum meaningful amount)
3. amount = type(uint256).max (overflow? underflow?)
4. address = address(0) (zero address edge cases)
5. Empty array parameters
6. Duplicate entries in arrays

## OUTPUT FORMAT

For each attack, output EXACTLY:

```
ATTACK [invariant_id]-[pattern_letter][attempt_number]:
  TARGET_INVARIANT: [invariant ID from the list]
  PATTERN: [A/B/C/D/E/F/G/H/I/J]
  DESCRIPTION: [one-line summary]

  SEQUENCE:
    1. [actor] calls [contract.function(params)] -- [state change]
    2. [actor] calls [contract.function(params)] -- [state change]
    ...

  EXPECTED_RESULT:
    BEFORE: [invariant expression] == [value]
    AFTER:  [invariant expression] == [different value]
    VIOLATION: [yes/no, and why]

  PROFIT_ESTIMATE: [rough $ estimate if violation is exploitable]
  CONFIDENCE: [HIGH/MEDIUM/LOW that this actually works]
  NEEDS_FLASH_LOAN: [yes/no, amount]
  FOUNDRY_HINT: [specific Foundry cheatcodes needed: vm.deal, vm.prank, deal()]
```

CRITICAL: Only output attacks with MEDIUM or HIGH confidence. Do not
waste the verification agent's time on theoretical attacks you are not
confident about. Trace through the code for each attack.

Mark the top 5 most promising attacks with **PRIORITY**.
```

---

## AGENT 3: FOUNDRY TEST GENERATOR

### Prompt Template

```
You are generating Foundry test code that forks mainnet and attempts to
break protocol invariants. You have received:
1. The invariant list
2. Specific attack sequences to test

Generate RUNNABLE Foundry tests. Not pseudocode. Not conceptual. Code
that compiles and runs with `forge test`.

## ATTACK SEQUENCES

{{PASTE_ATTACK_SEQUENCES_HERE}}

## PROTOCOL CODE

{{PASTE_CONTRACT_SOURCE_HERE}}

## DEPLOYED CONTRACT INFO

{{CHAIN}}: {{DEPLOYED_ADDRESS}}
RPC: Use vm.envString("RPC_URL")
Fork block: latest (or specify if needed)

## CODE GENERATION RULES

1. One test file per invariant category. Name: `InvariantBreaker_[Category].t.sol`

2. Each test function follows this pattern:
   - Record invariant value BEFORE
   - Execute attack sequence
   - Record invariant value AFTER
   - Assert the invariant still holds (test PASSES if invariant holds,
     FAILS if we broke it -- a failing test means we found a bug)

3. Use these Foundry features:
   - `vm.createSelectFork(rpcUrl)` for mainnet fork
   - `deal(token, user, amount)` for token setup
   - `vm.prank(user)` / `vm.startPrank(user)` for caller impersonation
   - `vm.roll(block)` / `vm.warp(timestamp)` for time manipulation
   - `vm.expectRevert()` if the attack should be blocked
   - `console2.log()` for debugging output

4. Helper functions to include:
   - `_checkInvariant_[name]()` -- reads and returns the invariant value
   - `_setupAttacker()` -- creates attacker with ETH and token approvals
   - `_logState()` -- logs all relevant balances and state

5. For flash loan tests, inline a minimal FlashLoanReceiver contract.

6. For donation attacks, use `deal()` to give tokens, then `transfer()`
   directly to the contract.

## TEMPLATE STRUCTURE

Generate code following this structure:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

interface IProtocol {
    // Extract from actual contract ABI
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function totalSupply() external view returns (uint256);
    function decimals() external view returns (uint8);
}

contract InvariantBreaker_Accounting is Test {
    IProtocol protocol;
    address attacker;

    // Tokens used by protocol
    IERC20 asset;   // underlying asset
    IERC20 shares;  // share/receipt token

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"));
        protocol = IProtocol(DEPLOYED_ADDRESS);
        asset = IERC20(ASSET_ADDRESS);
        shares = IERC20(SHARES_ADDRESS);

        attacker = makeAddr("attacker");
        vm.deal(attacker, 100 ether);
    }

    // ============================================================
    // INVARIANT CHECKERS
    // ============================================================

    function _invariant_totalAssets_gte_totalShares_times_price()
        internal view returns (bool holds, uint256 totalAssets, uint256 implied)
    {
        totalAssets = asset.balanceOf(address(protocol));
        uint256 supply = shares.totalSupply();
        if (supply == 0) return (true, totalAssets, 0);
        // implied = supply * pricePerShare
        // Compare with totalAssets
        // Return whether invariant holds
    }

    // ============================================================
    // ATTACK: Donation to break share price
    // ============================================================

    function test_break_invariant_A1_donation() public {
        // --- BEFORE ---
        (bool holdsBefore,,) = _invariant_totalAssets_gte_totalShares_times_price();
        assertTrue(holdsBefore, "Invariant broken before attack");

        // --- ATTACK ---
        vm.startPrank(attacker);

        // Step 1: Deposit minimum amount
        deal(address(asset), attacker, 1);
        asset.approve(address(protocol), 1);
        protocol.deposit(1, attacker);

        // Step 2: Donate large amount directly
        deal(address(asset), attacker, 1_000_000e18);
        asset.transfer(address(protocol), 1_000_000e18);

        // Step 3: Check if next depositor loses funds
        address victim = makeAddr("victim");
        deal(address(asset), victim, 1_000_000e18);
        vm.stopPrank();

        vm.startPrank(victim);
        asset.approve(address(protocol), 1_000_000e18);
        protocol.deposit(1_000_000e18, victim);
        vm.stopPrank();

        // --- AFTER ---
        uint256 victimShares = shares.balanceOf(victim);
        uint256 attackerShares = shares.balanceOf(attacker);

        console2.log("Victim shares:", victimShares);
        console2.log("Attacker shares:", attackerShares);

        // If victim got 0 shares, the invariant is broken
        // (attacker stole victim's deposit via share inflation)
        assertGt(victimShares, 0, "INVARIANT BROKEN: Victim got 0 shares (donation attack)");
    }

    // ============================================================
    // ATTACK: Rounding exploitation via repeated small operations
    // ============================================================

    function test_break_invariant_A1_rounding() public {
        vm.startPrank(attacker);

        uint256 startBalance = asset.balanceOf(attacker);
        deal(address(asset), attacker, 100e18);
        asset.approve(address(protocol), type(uint256).max);

        // Do 100 small deposit+withdraw cycles
        for (uint256 i = 0; i < 100; i++) {
            uint256 depositAmt = 1e18;
            protocol.deposit(depositAmt, attacker);

            uint256 myShares = shares.balanceOf(attacker);
            protocol.redeem(myShares, attacker, attacker);
        }

        uint256 endBalance = asset.balanceOf(attacker);

        vm.stopPrank();

        console2.log("Start:", startBalance);
        console2.log("End:", endBalance);

        // Attacker should not have MORE than they started with
        assertLe(
            endBalance,
            startBalance + 100e18, // original deal amount
            "INVARIANT BROKEN: Attacker extracted value via rounding"
        );
    }

    // ============================================================
    // ATTACK: Flash loan share price manipulation
    // ============================================================

    // function test_break_invariant_A1_flashloan() public {
    //     // Implement per protocol -- see FlashLoanAttacker pattern
    //     // in universal_poc.sol
    // }
}
```

## IMPORTANT

- Every test function name starts with `test_break_invariant_`
- A PASSING test means the invariant held (attack failed)
- A FAILING test means we FOUND A BUG (invariant broken)
- Log values with console2 so we can see the state even when tests pass
- Use `deal()` for token setup, never rely on mainnet token holdings
- Generate the ACTUAL interface from the protocol's ABI, not generic stubs
- If unsure about a function signature, add a comment with the uncertainty
```

---

## CHAINING THE AGENTS

### Option A: Manual (recommended for first use)

Run each agent in a separate Claude Code session. Copy output between sessions.

```
Session 1: "Here is a protocol. Extract all invariants. [paste code]"
           -> Save output as invariants.txt

Session 2: "Here are invariants for a protocol. Generate attack sequences.
            [paste invariants.txt + code]"
           -> Save output as attacks.txt

Session 3: "Here are attack sequences. Generate Foundry tests.
            [paste attacks.txt + code + deployed addresses]"
           -> Agent writes .t.sol files directly
```

### Option B: Single-session pipeline

Use Claude Code's ability to chain tasks in one session:

```
I need you to perform an economic invariant analysis of this protocol.

PROTOCOL: [name]
CODE: [paste or point to directory]
DEPLOYED: [chain + address]

Follow these 3 steps IN ORDER:

STEP 1 - EXTRACT INVARIANTS:
[paste Agent 1 prompt]

STEP 2 - GENERATE ATTACKS:
Using the invariants from Step 1:
[paste Agent 2 prompt]

STEP 3 - WRITE FOUNDRY TESTS:
Using the attacks from Step 2, write Foundry test files to:
/path/to/foundry-workspace/test/invariant/
[paste Agent 3 prompt]

After writing the tests, tell me the exact command to run them.
```

### Option C: Programmatic (for batch analysis)

Use the existing V2 pipeline with domain="invariant-testing":

```python
from agents.v2.pipeline import build_pipeline_prompts

# Load contract sources
sources = {
    "Vault.sol": open("contracts/Vault.sol").read(),
    "Pool.sol": open("contracts/Pool.sol").read(),
}

# Build pipeline with invariant focus
prompts = build_pipeline_prompts(
    contract_sources=sources,
    documentation="Protocol docs here",
    domain="defi-lending",  # or defi-dex, defi-staking, bridge, etc.
)

# Execute each prompt through your LLM client
# Feed previous outputs as context to each subsequent prompt
```

---

## PROTOCOL-SPECIFIC INVARIANT CHECKLISTS

### ERC4626 Vault

```
B1: asset.balanceOf(vault) >= convertToAssets(totalSupply())
B2: convertToShares(convertToAssets(shares)) <= shares  (round-trip loss)
B3: convertToAssets(convertToShares(assets)) <= assets  (round-trip loss)
M1: totalAssets() monotonically increases (in fee-only vaults)
M2: pricePerShare = totalAssets / totalSupply never decreases (unless loss event)
E1: deposit(x) then redeem(shares_received) returns <= x (no free money)
E2: No user can withdraw more than their proportional share of totalAssets
S1: totalSupply == 0 implies totalAssets == 0 (no stuck tokens)
S2: First depositor cannot manipulate share price for subsequent depositors
```

### AMM / DEX

```
B1: x * y >= k after every swap (constant product)
B2: sum(LP_tokens) == totalSupply of LP token
B3: reserve0 * reserve1 >= k_previous after every operation
M1: k only increases (from fees) or stays constant
M2: LP token value in terms of underlying never decreases from swaps alone
E1: No arbitrage exists within the pool (output price = input price after fees)
E2: Swap output satisfies: amountOut <= reserve_out * amountIn / (reserve_in + amountIn)
S1: Pool cannot be drained to (0, 0) reserves
```

### Lending Protocol

```
B1: totalBorrows <= totalDeposits (protocol level)
B2: sum(userBorrows[i]) == totalBorrows
B3: sum(userDeposits[i]) == totalDeposits
B4: collateral[user] * price / debt[user] >= liquidationThreshold (or user is liquidatable)
M1: totalBorrows increases with time (interest accrual, never decreases except repayment)
M2: exchangeRate (deposit token to underlying) only increases
E1: No user can borrow without sufficient collateral
E2: Liquidation is always profitable for liquidator (incentive alignment)
E3: Bad debt cannot accumulate silently -- must be detected and socialized
S1: Cannot borrow and repay in same tx for profit (flash loan guard)
S2: Cannot self-liquidate for profit
T1: Interest accrual is continuous -- no jump at epoch boundary exploitable
```

### Staking / Rewards

```
B1: sum(userStake[i]) == totalStaked
B2: sum(claimedRewards[i]) <= totalRewardsAllocated
B3: rewardPerToken * totalStaked <= totalRewardsAvailable
M1: rewardPerTokenStored only increases
M2: Each user's earned rewards only increase (until claimed)
E1: Cannot stake for 0 seconds and claim rewards (flash-stake prevention)
E2: Late staker does not claim rewards from before their stake
S1: When totalStaked == 0, rewards are not lost (or are handled explicitly)
S2: Cannot claim rewards twice for the same period
T1: Reward rate transition does not create claimable spike
```

### Bridge

```
B1: L1_locked >= L2_minted (fundamental solvency)
B2: sum(pending_messages) + sum(completed_messages) == sum(initiated_messages)
M1: message nonce strictly increases (no replay)
M2: L1_locked only decreases via valid withdrawal proof
E1: Cannot mint on L2 without corresponding lock on L1
E2: Cannot withdraw on L1 without burning on L2
S1: Failed message can be retried OR refunded, not both
S2: No message can be in both "pending" and "completed" state
T1: Finality period is enforced -- cannot claim before timeout
```

---

## RUNNING THE TESTS

```bash
# Run all invariant-breaking tests
forge test --match-contract InvariantBreaker --fork-url $RPC_URL -vvvv

# Run specific invariant category
forge test --match-test "test_break_invariant_A" --fork-url $RPC_URL -vvvv

# Run with gas reporting
forge test --match-contract InvariantBreaker --fork-url $RPC_URL -vvvv --gas-report

# Run against specific block (for reproducibility)
forge test --match-contract InvariantBreaker --fork-url $RPC_URL --fork-block-number 19000000 -vvvv
```

## INTERPRETING RESULTS

- **All tests PASS**: Invariants held. Protocol survived your attacks. Move to
  more creative attack patterns or check if you missed invariants.
- **Test FAILS with assertion error**: YOU FOUND A BUG. The invariant was
  violated. Document it, calculate the profit, write the report.
- **Test FAILS with revert**: The protocol blocked the attack. This is expected.
  Check if the revert is the RIGHT revert (correct require/modifier) or if it
  reverts for the wrong reason (which might indicate a different bug).
- **Test FAILS with out of gas**: The attack might work but needs optimization.
  Reduce loop counts or simplify the sequence.

## COMMON PITFALLS

1. **Testing against wrong version**: Always verify the deployed bytecode matches
   the source code you are testing. Use `cast code [address]` to check.

2. **Missing token approvals**: Most attacks fail on the first run because of
   missing `approve()` calls. Always approve before interacting.

3. **Decimal mismatches**: USDC has 6 decimals, ETH has 18. A "1e18" amount of
   USDC is a trillion dollars. Always check `decimals()`.

4. **Fork state vs fresh state**: Mainnet fork includes existing positions.
   Your "first depositor" attack will not work if the vault already has deposits.
   Use `deal()` to set balances, or choose a block before the vault launched.

5. **Read-only reentrancy**: Some invariants can be violated during execution
   (view functions return wrong values mid-transaction) even if state is correct
   after execution. Test both mid-tx and post-tx invariant values.
