"""
Economic Invariant Testing Runner
==================================
Orchestrates the 3-agent pipeline for invariant-based protocol testing.

Usage:
    # Quick mode: Single Claude Code session with all 3 phases
    python invariant_test_runner.py --protocol "EulerVault" \
        --contracts ./contracts/euler/ \
        --address 0x... \
        --chain ethereum \
        --rpc $ETH_RPC_URL

    # Generate prompts only (for manual copy-paste into Claude Code)
    python invariant_test_runner.py --prompts-only \
        --protocol "EulerVault" \
        --contracts ./contracts/euler/

    # Just the invariant checklist for a protocol type
    python invariant_test_runner.py --checklist vault
    python invariant_test_runner.py --checklist lending
    python invariant_test_runner.py --checklist amm
    python invariant_test_runner.py --checklist staking
    python invariant_test_runner.py --checklist bridge
"""

import argparse
import os
import sys
from pathlib import Path


# ========================================================================
# PROTOCOL-SPECIFIC INVARIANT CHECKLISTS
# ========================================================================

INVARIANT_CHECKLISTS = {
    "vault": """
## ERC4626 Vault Invariant Checklist

### Balance Invariants
- B1: asset.balanceOf(vault) >= totalAssets()
- B2: convertToAssets(totalSupply()) <= asset.balanceOf(vault)
- B3: sum(convertToAssets(shares[user])) <= totalAssets()

### Monotonicity Invariants
- M1: totalAssets() only increases (fee-accrual vaults)
- M2: convertToAssets(1e18) never decreases (share price)

### Round-Trip Invariants
- E1: deposit(x) then redeem(shares) returns <= x
- E2: mint(s) then withdraw(assets) costs >= original mint cost
- E3: convertToShares(convertToAssets(s)) <= s (round-trip loses, never gains)
- E4: convertToAssets(convertToShares(a)) <= a

### Edge Case Invariants
- S1: totalSupply == 0 implies totalAssets == 0
- S2: First depositor cannot inflate share price to steal from second depositor
- S3: Last withdrawer gets their fair share (no stuck dust they cannot claim)
- S4: deposit(0) returns 0 shares (or reverts)
- S5: withdraw(0) burns 0 shares (or reverts)

### Fee Invariants (if applicable)
- F1: fee_collected + user_receives == total_amount
- F2: No path bypasses fee collection
""",

    "lending": """
## Lending Protocol Invariant Checklist

### Balance Invariants
- B1: totalBorrows <= totalDeposits (protocol level)
- B2: sum(userBorrows[i]) == totalBorrows
- B3: sum(userDeposits[i]) == totalDeposits
- B4: cash + totalBorrows == totalDeposits + reserves

### Collateralization Invariants
- C1: collateral[user] * price / debt[user] >= liqThreshold (or user is liquidatable)
- C2: New borrows require collateral * price / (debt + newBorrow) >= collateralFactor
- C3: After liquidation: remaining debt == 0 OR remaining position is healthy

### Rate Invariants
- R1: borrowRate >= supplyRate (protocol takes spread)
- R2: utilizationRate = totalBorrows / totalDeposits is in [0, 1]
- R3: Interest accrual is monotonic (accrued interest never decreases)

### Liquidation Invariants
- L1: Liquidation is profitable for liquidator at threshold
- L2: Self-liquidation is not profitable
- L3: Liquidation cannot create bad debt (or bad debt is socialized)

### Safety Invariants
- S1: Cannot borrow without sufficient collateral
- S2: Cannot withdraw collateral below liquidation threshold
- S3: Flash loan attack cannot create lasting bad debt
""",

    "amm": """
## AMM / DEX Invariant Checklist

### Core Invariant
- K1: x * y >= k after every swap (constant product)
- K2: k only increases from fees, never decreases from swaps
- K3: reserve0 * reserve1 >= k_previous after any operation

### LP Token Invariants
- L1: sum(LP_balances[i]) == LP_totalSupply
- L2: LP value in underlying terms never decreases from swap fees alone
- L3: First LP cannot manipulate initial price for profit

### Swap Invariants
- S1: amountOut <= reserve_out * amountIn / (reserve_in + amountIn) (with fees)
- S2: No swap produces more output than the output reserve
- S3: Swap fee is always collected (no zero-fee path)

### Price Invariants
- P1: TWAP oracle cannot be permanently manipulated by single-block attacks
- P2: Spot price = reserve0 / reserve1 matches swap execution price (within fee)

### Liquidity Invariants
- LQ1: Adding liquidity does not change the price
- LQ2: Removing liquidity returns proportional share of both tokens
- LQ3: Pool cannot be drained to (0, 0) reserves
""",

    "staking": """
## Staking / Rewards Invariant Checklist

### Balance Invariants
- B1: sum(userStake[i]) == totalStaked
- B2: stakingToken.balanceOf(contract) >= totalStaked
- B3: sum(claimedRewards[i]) <= totalRewardsAllocated

### Reward Invariants
- R1: rewardPerTokenStored only increases
- R2: earned[user] >= 0 (never negative)
- R3: earned[user] only increases between claims (no rewards lost)
- R4: Late staker does not earn rewards from before their stake

### Timing Invariants
- T1: Flash-staking (stake and unstake in same block) earns 0 rewards
- T2: Reward rate change does not create claimable spike
- T3: When totalStaked == 0, rewards are handled (not lost, not claimable by ghost)

### Edge Cases
- S1: Cannot claim rewards twice for same period
- S2: Cannot stake 0 to trigger reward update without real stake
- S3: Last unstaker gets exactly their remaining earned rewards
""",

    "bridge": """
## Cross-Chain Bridge Invariant Checklist

### Fundamental Solvency
- B1: L1_locked >= L2_minted (at all times)
- B2: No message can mint on L2 without corresponding lock on L1

### Message Integrity
- M1: message_nonce strictly increases (replay prevention)
- M2: Each message processed exactly once
- M3: Message content cannot be modified between send and receive

### State Consistency
- S1: pending + completed + expired == total_initiated
- S2: No message in both "pending" and "completed" state
- S3: Expired messages can be refunded OR retried, not both

### Timing
- T1: Finality period enforced (cannot claim before timeout)
- T2: Challenge window cannot be bypassed
""",
}


# ========================================================================
# PROMPT BUILDER
# ========================================================================

def load_contract_sources(contracts_dir: str) -> dict[str, str]:
    """Load all Solidity files from a directory."""
    sources = {}
    contracts_path = Path(contracts_dir)

    if not contracts_path.exists():
        print(f"ERROR: Directory not found: {contracts_dir}")
        sys.exit(1)

    for sol_file in sorted(contracts_path.rglob("*.sol")):
        # Skip test files and dependencies
        rel = sol_file.relative_to(contracts_path)
        rel_str = str(rel)
        if any(skip in rel_str for skip in ["test/", "lib/", "node_modules/", "mock", "Mock"]):
            continue
        sources[rel_str] = sol_file.read_text(encoding="utf-8", errors="replace")

    if not sources:
        print(f"WARNING: No .sol files found in {contracts_dir}")

    return sources


def build_agent1_prompt(protocol_name: str, sources: dict[str, str]) -> str:
    """Build the invariant extraction prompt."""
    code_block = "\n\n".join(
        f"// === {fname} ===\n{src}" for fname, src in sources.items()
    )

    return f"""You are analyzing the {protocol_name} protocol to extract every economic
invariant it depends on. An invariant is a property that MUST hold after every
state-changing transaction, or the protocol is broken.

YOUR OUTPUT will be consumed by an attack-generation agent. Be precise.

## PROTOCOL CODE

{code_block}

## EXTRACTION INSTRUCTIONS

Extract invariants in these categories:
1. BALANCE INVARIANTS -- what adds up to what
2. MONOTONICITY INVARIANTS -- what only goes one direction
3. RATIO/BOUND INVARIANTS -- what stays within limits
4. STATE MACHINE INVARIANTS -- valid transitions only
5. CROSS-CONTRACT INVARIANTS -- consistency across contracts
6. TIMING INVARIANTS -- temporal constraints

For each invariant output:

```
INVARIANT [letter][number]:
  PROPERTY: [mathematical statement using actual variable names from code]
  HOLDS_AFTER: [functions where this must hold after execution]
  TYPE: [equality | inequality | monotonic_increase | monotonic_decrease | bound | state_transition]
  IMPLICIT: [yes/no -- is this asserted in code, or just assumed?]
  PRIORITY: [P0 = direct fund loss / P1 = conditional fund loss / P2 = malfunction]
  ATTACK_SURFACE: [brief note on what could break this]
```

FOCUS 70% of effort on IMPLICIT invariants (no require/assert in code).
These are the highest-value targets. Aim for 15-40 invariants total.
"""


def build_agent2_prompt(protocol_name: str, sources: dict[str, str]) -> str:
    """Build the attack sequence generation prompt."""
    code_block = "\n\n".join(
        f"// === {fname} ===\n{src}" for fname, src in sources.items()
    )

    return f"""You are constructing concrete attack sequences to break {protocol_name}'s
economic invariants. You think like a $10M attacker with flash loan access.

## INVARIANT LIST

{{{{PASTE AGENT 1 OUTPUT HERE}}}}

## PROTOCOL CODE

{code_block}

## ATTACK PATTERNS TO APPLY (for each P0 and P1 invariant):

A. Donation: transfer tokens directly to contract (bypass deposit)
B. Flash Loan: borrow -> manipulate -> extract -> repay
C. First/Last User: 1 wei deposit, empty vault, sole withdrawer
D. Rounding: many small ops accumulating dust extraction
E. Reentrancy: callback during state transition
F. Oracle: flash swap to move price, exploit, swap back
G. Fee Avoidance: zero amount, dust, same-block round-trip
H. Sandwich: front-run harvest/rebalance/liquidate
I. Cross-Function: function A state makes function B misbehave
J. Extreme Values: 0, 1, type(uint256).max, address(0)

## OUTPUT FORMAT (for each attack):

```
ATTACK [invariant_id]-[pattern][attempt]:
  TARGET_INVARIANT: [ID]
  PATTERN: [A-J]
  DESCRIPTION: [one-line]
  SEQUENCE:
    1. [actor] calls [contract.function(params)] -- [effect]
    2. ...
  EXPECTED_RESULT:
    BEFORE: [expression] == [value]
    AFTER: [expression] == [different value]
    VIOLATION: [yes/no + reason]
  PROFIT_ESTIMATE: [$amount]
  CONFIDENCE: [HIGH/MEDIUM/LOW]
  NEEDS_FLASH_LOAN: [yes/no]
  FOUNDRY_HINT: [cheatcodes needed]
```

Only output MEDIUM+ confidence attacks. Mark top 5 as **PRIORITY**.
Trace through actual code for each attack.
"""


def build_agent3_prompt(
    protocol_name: str,
    sources: dict[str, str],
    deployed_address: str = "0x0",
    chain: str = "ethereum",
) -> str:
    """Build the Foundry test generation prompt."""
    code_block = "\n\n".join(
        f"// === {fname} ===\n{src}" for fname, src in sources.items()
    )

    return f"""Generate RUNNABLE Foundry test code that forks mainnet and attempts to break
{protocol_name}'s invariants using the attack sequences provided.

## ATTACK SEQUENCES

{{{{PASTE AGENT 2 OUTPUT HERE}}}}

## PROTOCOL CODE

{code_block}

## DEPLOYMENT INFO

Chain: {chain}
Address: {deployed_address}
RPC: Use vm.envString("RPC_URL")

## RULES

1. One test file per invariant category: InvariantBreaker_[Category].t.sol
2. Each test:
   - Records invariant BEFORE
   - Executes attack
   - Records invariant AFTER
   - Asserts invariant holds (FAIL = we found a bug)
3. Use Foundry features: vm.createSelectFork, deal(), vm.prank, vm.warp, console2.log
4. Include helper functions: _invariant_[name](), _setupAttacker(), _logState()
5. For flash loans, inline a FlashLoanReceiver contract
6. Extract the ACTUAL interface from the protocol ABI (not generic stubs)
7. Every test function starts with test_break_invariant_
8. Log state with console2 even on pass (for debugging)
9. Write to: foundry-workspace/test/invariant/

Generate COMPILABLE code. Not pseudocode.
"""


# ========================================================================
# MAIN
# ========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Economic Invariant Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Print the vault invariant checklist
  python invariant_test_runner.py --checklist vault

  # Generate all 3 agent prompts for manual use
  python invariant_test_runner.py --prompts-only --protocol EulerVault --contracts ./contracts/euler/

  # Generate prompts with deployment info
  python invariant_test_runner.py --prompts-only --protocol EulerVault \\
      --contracts ./contracts/euler/ --address 0xabc... --chain ethereum
        """
    )

    parser.add_argument("--checklist", choices=list(INVARIANT_CHECKLISTS.keys()),
                        help="Print invariant checklist for protocol type")
    parser.add_argument("--protocol", help="Protocol name")
    parser.add_argument("--contracts", help="Path to contracts directory")
    parser.add_argument("--address", default="0x0", help="Deployed contract address")
    parser.add_argument("--chain", default="ethereum", help="Chain name")
    parser.add_argument("--prompts-only", action="store_true",
                        help="Print prompts for manual copy-paste")
    parser.add_argument("--output-dir", default="./prompts",
                        help="Directory to write prompt files")

    args = parser.parse_args()

    # Checklist mode
    if args.checklist:
        print(INVARIANT_CHECKLISTS[args.checklist])
        return

    # Prompt generation mode
    if not args.protocol or not args.contracts:
        parser.error("--protocol and --contracts are required (unless using --checklist)")

    sources = load_contract_sources(args.contracts)
    print(f"Loaded {len(sources)} contract files from {args.contracts}")
    for fname in sources:
        print(f"  - {fname}")

    prompt1 = build_agent1_prompt(args.protocol, sources)
    prompt2 = build_agent2_prompt(args.protocol, sources)
    prompt3 = build_agent3_prompt(args.protocol, sources, args.address, args.chain)

    if args.prompts_only:
        # Write prompts to files for manual use
        out_dir = Path(args.output_dir)
        out_dir.mkdir(exist_ok=True)

        (out_dir / "01_extract_invariants.md").write_text(prompt1, encoding="utf-8")
        (out_dir / "02_generate_attacks.md").write_text(prompt2, encoding="utf-8")
        (out_dir / "03_generate_foundry_tests.md").write_text(prompt3, encoding="utf-8")

        print(f"\nPrompts written to {out_dir}/")
        print(f"  01_extract_invariants.md  ({len(prompt1):,} chars)")
        print(f"  02_generate_attacks.md    ({len(prompt2):,} chars)")
        print(f"  03_generate_foundry_tests.md ({len(prompt3):,} chars)")
        print()
        print("NEXT STEPS:")
        print("  1. Open Claude Code, paste 01_extract_invariants.md")
        print("     Save output as invariants.txt")
        print("  2. New session, paste 02_generate_attacks.md")
        print("     Replace {{PASTE AGENT 1 OUTPUT HERE}} with invariants.txt content")
        print("     Save output as attacks.txt")
        print("  3. New session, paste 03_generate_foundry_tests.md")
        print("     Replace {{PASTE AGENT 2 OUTPUT HERE}} with attacks.txt content")
        print("     Agent writes .t.sol files to foundry-workspace/test/invariant/")
        print("  4. Run: forge test --match-contract InvariantBreaker --fork-url $RPC_URL -vvvv")
    else:
        # Print the combined single-session prompt
        combined = f"""I need you to perform an economic invariant analysis of the {args.protocol} protocol.

STEP 1 -- EXTRACT INVARIANTS:
{prompt1}

---

STEP 2 -- GENERATE ATTACK SEQUENCES:
Using the invariants from Step 1, generate concrete attack sequences.
For each P0 and P1 invariant, try patterns A through J (donation, flash loan,
first/last user, rounding, reentrancy, oracle, fee avoidance, sandwich,
cross-function, extreme values).

Output each attack with: target invariant, exact sequence of calls,
expected before/after state, violation assessment, profit estimate.
Only MEDIUM+ confidence. Mark top 5 as PRIORITY.

---

STEP 3 -- WRITE FOUNDRY TESTS:
Using the attacks from Step 2, write Foundry test files.
Deployed at: {args.address} on {args.chain}
Write to: foundry-workspace/test/invariant/

Each test: record invariant before, execute attack, assert invariant after.
A FAILING test = we found a bug. Generate COMPILABLE code.

After writing, tell me the exact forge command to run the tests.
"""
        print(combined)


if __name__ == "__main__":
    main()
