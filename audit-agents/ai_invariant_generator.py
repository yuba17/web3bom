#!/usr/bin/env python3
"""
AI Invariant Generator v2 — Context-Aware, Category-by-Category

Instead of dumping everything into one giant prompt, this generator:
1. Auto-classifies the protocol type from source code
2. For each invariant category, Claude QUERIES the relevant knowledge base
3. Generates invariants per category with a target of 5 each
4. Uses deep-thinking retries: if <5, think harder (2 retries max), then accept

The output is a single MASTER_PROMPT.md that Claude Code executes directly.
Claude reads the code, consults knowledge per category, and generates Chimera code.

Usage:
    python ai_invariant_generator.py --source ./target/src --name "protocol"
    Then in Claude Code: read and execute MASTER_PROMPT.md
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))
from registry import get_registry
from matcher import MatcherPipeline


# ============================================================================
# PROTOCOL TYPE DETECTION
# ============================================================================

PROTOCOL_SIGNATURES = {
    "erc4626_vault": {
        "keywords": ["totalAssets", "convertToShares", "convertToAssets", "maxDeposit",
                      "maxMint", "maxWithdraw", "maxRedeem", "previewDeposit", "ERC4626"],
        "threshold": 3,
        "label": "ERC4626 Vault",
        "categories": [
            "solvency", "share_price", "round_trip", "rounding_direction",
            "access_control", "economic_attack", "cross_function", "first_depositor"
        ],
        "knowledge_files": [
            "invariant-registry/vault/erc4626_share_price.json",
            "invariant-registry/vault/erc4626_deposit_withdraw.json",
            "invariant-registry/vault/erc4626_crytic.json",
            "BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md",
        ],
    },
    "lending_pool": {
        "keywords": ["borrow", "repay", "liquidat", "collateral", "healthFactor",
                      "totalBorrows", "totalSupply", "interestRate", "utilizationRate",
                      "isHealthy", "debtOf", "supplyOf"],
        "threshold": 3,
        "label": "Lending Pool",
        "categories": [
            "solvency", "debt_accounting", "liquidation_logic", "interest_rate",
            "access_control", "economic_attack", "cross_function", "oracle_dependency"
        ],
        "knowledge_files": [
            "invariant-registry/lending/pool_accounting.json",
            "invariant-registry/lending/collateral_accounting.json",
            "invariant-registry/lending/liquidation_logic.json",
            "invariant-registry/lending/interest_rate.json",
            "invariant-registry/lending/loan_accounting.json",
            "BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md",
        ],
    },
    "amm_dex": {
        "keywords": ["swap", "addLiquidity", "removeLiquidity", "getReserves",
                      "token0", "token1", "getAmountOut", "sqrtPrice", "tick",
                      "liquidity", "slot0", "pool"],
        "threshold": 3,
        "label": "AMM / DEX",
        "categories": [
            "solvency", "constant_product", "rounding_direction", "fee_accounting",
            "access_control", "economic_attack", "cross_function", "slippage"
        ],
        "knowledge_files": [
            "invariant-registry/universal/conservation_of_value.json",
            "invariant-registry/universal/exploit_derived.json",
            "BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md",
        ],
    },
    "staking_rewards": {
        "keywords": ["stake", "unstake", "getReward", "rewardRate", "rewardPerToken",
                      "earned", "notifyRewardAmount", "periodFinish", "totalStaked"],
        "threshold": 3,
        "label": "Staking / Rewards",
        "categories": [
            "solvency", "reward_accounting", "proportionality", "epoch_boundary",
            "access_control", "economic_attack", "cross_function", "flash_stake"
        ],
        "knowledge_files": [
            "invariant-registry/staking/reward_distribution.json",
            "invariant-registry/universal/conservation_of_value.json",
            "BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md",
        ],
    },
    "bridge": {
        "keywords": ["relayMessage", "proveMessage", "finalizeMessage", "disputeGame",
                      "portal", "crossDomain", "l2ToL1", "l1ToL2", "nonce",
                      "messageHash", "bridge"],
        "threshold": 3,
        "label": "Bridge / Cross-chain",
        "categories": [
            "message_integrity", "replay_protection", "nonce_ordering",
            "access_control", "economic_attack", "cross_function", "timing"
        ],
        "knowledge_files": [
            "invariant-registry/bridge/message_integrity.json",
            "invariant-registry/bridge/dispute_games.json",
            "BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md",
        ],
    },
    "token_erc20": {
        "keywords": ["transfer", "transferFrom", "approve", "allowance",
                      "totalSupply", "balanceOf", "mint", "burn"],
        "threshold": 4,  # Higher threshold — these are too common
        "label": "ERC20 Token",
        "categories": [
            "supply_conservation", "transfer_integrity", "approval_safety",
            "access_control", "economic_attack", "cross_function", "rounding_direction"
        ],
        "knowledge_files": [
            "invariant-registry/token/erc20_core.json",
            "invariant-registry/universal/conservation_of_value.json",
        ],
    },
}

# Universal categories always checked regardless of protocol type
UNIVERSAL_CATEGORIES = [
    "solvency",
    "access_control",
    "economic_attack",
    "rounding_direction",
    "cross_function",
]

# Universal knowledge files always consulted
UNIVERSAL_KNOWLEDGE = [
    "invariant-registry/universal/exploit_derived.json",
    "invariant-registry/universal/conservation_of_value.json",
    "invariant-registry/universal/reentrancy_safety.json",
    "BugBounty-Vault/01-Vulnerabilities/DeFiHackLabs-Invariant-Extraction.md",
]


def detect_protocol_type(source_code: str) -> list[dict]:
    """Detect protocol type(s) from source code keywords. Returns sorted by match score.

    For hybrid protocols (e.g., lending that uses AMM positions as collateral),
    we merge categories from all detected types so nothing is missed.
    """
    source_lower = source_code.lower()
    results = []

    for ptype, config in PROTOCOL_SIGNATURES.items():
        matched_kw = sum(1 for kw in config["keywords"] if kw.lower() in source_lower)
        if matched_kw >= config["threshold"]:
            results.append({
                "type": ptype,
                "label": config["label"],
                "matched_keywords": matched_kw,
                "total_keywords": len(config["keywords"]),
                "score": matched_kw / len(config["keywords"]),
                "categories": config["categories"],
                "knowledge_files": config["knowledge_files"],
            })

    results.sort(key=lambda x: x["score"], reverse=True)

    # For hybrid protocols: merge categories and knowledge from ALL detected types
    if len(results) > 1:
        merged_categories = list(dict.fromkeys(
            cat for r in results for cat in r["categories"]
        ))
        merged_knowledge = list(dict.fromkeys(
            f for r in results for f in r["knowledge_files"]
        ))
        # Primary type gets the merged data
        results[0]["categories"] = merged_categories
        results[0]["knowledge_files"] = merged_knowledge
        results[0]["label"] += " (hybrid: " + ", ".join(r["label"] for r in results[1:]) + ")"

    return results


def collect_source(source_dir: str, max_chars: int = 200000) -> tuple[str, list[str]]:
    """Collect all Solidity source files, excluding tests/libs."""
    source_path = Path(source_dir)
    sol_files = sorted(source_path.rglob("*.sol"))
    sol_files = [
        f for f in sol_files
        if not any(skip in str(f).lower()
                   for skip in ["test", "lib/", "node_modules", "mock", "script/"])
    ]

    combined = ""
    file_list = []
    for f in sol_files:
        try:
            content = f.read_text(encoding="utf-8")
            header = f"\n// ========== {f.relative_to(source_path)} ==========\n"
            if len(combined) + len(header) + len(content) > max_chars:
                break
            combined += header + content + "\n"
            file_list.append(str(f.relative_to(source_path)))
        except UnicodeDecodeError:
            continue

    return combined, file_list


def extract_public_functions(source_code: str) -> list[dict]:
    """Extract all public/external function signatures from source."""
    pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(public|external)[^{]*'
    matches = re.findall(pattern, source_code)
    functions = []
    seen = set()
    for name, params, visibility in matches:
        if name.startswith("_") or name in seen:
            continue
        seen.add(name)
        functions.append({
            "name": name,
            "params": params.strip(),
            "visibility": visibility,
        })
    return functions


def extract_state_variables(source_code: str) -> list[str]:
    """Extract state variable declarations for ghost variable hints."""
    pattern = r'(?:uint256|int256|address|bool|mapping\([^)]+\))\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]'
    matches = re.findall(pattern, source_code)
    return list(dict.fromkeys(matches))[:30]  # Dedupe, max 30


def get_matched_invariants(source_dir: str, max_payout: int = 100000) -> list[dict]:
    """Get invariants from registry that match this target."""
    pipeline = MatcherPipeline()
    results = pipeline.match(source_dir=source_dir, max_payout=max_payout)

    matched = []
    for r in results[:20]:
        matched.append({
            "id": r.invariant.id,
            "title": r.invariant.title,
            "severity": r.invariant.severity,
            "solidity": r.invariant.invariant_solidity,
            "natural": r.invariant.invariant_natural,
            "confidence": r.confidence,
        })
    return matched


# ============================================================================
# CATEGORY DEFINITIONS — What each category means and what to look for
# ============================================================================

CATEGORY_DESCRIPTIONS = {
    "solvency": {
        "name": "Solvency / Balance Integrity",
        "description": "The protocol must always hold enough tokens to cover its obligations. "
                       "Real token balance >= internal accounting. No money created from nothing.",
        "attack_examples": [
            "Euler Finance $197M: self-liquidation created bad debt, protocol became insolvent",
            "Sonne Finance $20M: first depositor inflated share price, subsequent depositors got 0 shares",
        ],
        "what_to_check": [
            "token.balanceOf(protocol) >= internal accounting total",
            "sum of all user claims <= total protocol holdings",
            "no path to withdraw more than deposited (accounting level)",
            "totalAssets consistency with real balances",
        ],
    },
    "share_price": {
        "name": "Share Price Monotonicity",
        "description": "Share price (assets per share) must never decrease from user actions. "
                       "Only protocol-level losses should decrease share price.",
        "attack_examples": [
            "ResupplyFi $9.6M: flash loan inflated share price then redeemed",
            "PolterFinance $7M: first depositor share inflation on Compound fork",
        ],
        "what_to_check": [
            "convertToAssets(1e18) never decreases after any non-loss operation",
            "no single-block share price spikes > reasonable yield",
            "first deposit cannot set extreme exchange rate",
        ],
    },
    "round_trip": {
        "name": "Round-Trip Conservation",
        "description": "withdraw(deposit(x)) <= x and redeem(mint(x)) should return close to x. "
                       "Users must not profit from deposit+immediate-withdraw cycles.",
        "attack_examples": [
            "BalancerV2 $120M: repeated small swaps accumulated rounding in attacker's favor",
            "MIMSpell $6.5M: flash loan borrow/repay sequence extracted value from rounding",
        ],
        "what_to_check": [
            "deposit then withdraw returns <= original amount",
            "mint then redeem returns <= original amount",
            "no profit from rapid deposit/withdraw cycles",
        ],
    },
    "rounding_direction": {
        "name": "Rounding Direction Consistency",
        "description": "All rounding must favor the protocol, never the user. "
                       "Deposits/mints round UP (user pays more), withdrawals/redeems round DOWN (user gets less).",
        "attack_examples": [
            "BalancerV2: precision loss in StableMath accumulated across thousands of swaps",
            "KyberSwap $46M: precision loss in concentrated liquidity tick math",
        ],
        "what_to_check": [
            "shares received from deposit <= previewDeposit result",
            "assets needed for mint >= previewMint result",
            "assets received from withdraw <= previewWithdraw result",
            "mulDiv direction: UP for debt, DOWN for credit",
        ],
    },
    "debt_accounting": {
        "name": "Debt Accounting Integrity",
        "description": "Total borrows must equal sum of individual debts. Interest only increases debt. "
                       "No path to reduce debt without actual repayment.",
        "attack_examples": [
            "Venus THE: borrowBehalf increased victim's debt without authorization",
            "AlkemiEarn: self-liquidation zeroed attacker debt but kept collateral",
        ],
        "what_to_check": [
            "totalBorrows >= sum of all individual debts (within rounding)",
            "interest accrual only increases debt, never decreases",
            "debt can only decrease through repay() or liquidate()",
            "no path to create unbacked debt",
        ],
    },
    "liquidation_logic": {
        "name": "Liquidation Safety",
        "description": "Liquidation must improve protocol health. Self-liquidation must not yield profit. "
                       "Liquidation bonus must not exceed collateral value.",
        "attack_examples": [
            "Euler $197M: donateToReserves + self-liquidation for profit",
            "Compound: liquidation of healthy positions",
        ],
        "what_to_check": [
            "only unhealthy positions can be liquidated",
            "liquidation reduces debt and increases protocol health",
            "self-liquidation yields no profit to the liquidator-borrower",
            "liquidation bonus <= seized collateral value",
        ],
    },
    "interest_rate": {
        "name": "Interest Rate Bounds",
        "description": "Interest rates must stay within reasonable bounds. "
                       "Utilization rate must be [0, 1]. Interest must accrue monotonically.",
        "attack_examples": [
            "Revert Lend mock artifact: 740%/day vs 5%/year real rate caused false invariant breaks",
        ],
        "what_to_check": [
            "interest rate >= 0 and <= MAX_RATE",
            "utilization = borrows / supply, always in [0, 1e18]",
            "interest accrual monotonically increases borrow index",
            "no interest charged on zero borrows",
        ],
    },
    "access_control": {
        "name": "Access Control Integrity",
        "description": "Only authorized addresses can call privileged functions. "
                       "No path to escalate privileges without going through governance.",
        "attack_examples": [
            "TempleDAO $2.3M: migrateStake() had zero access control",
            "CorkProtocol $12M: missing access control on critical function",
            "DeltaPrime $4.75M: arbitrary calldata forwarding bypassed access control",
        ],
        "what_to_check": [
            "admin-only functions revert when called by non-admin",
            "no function increases another user's debt without authorization",
            "ownership transfer requires 2-step or timelock",
            "no arbitrary calldata forwarding to token contracts",
        ],
    },
    "economic_attack": {
        "name": "Economic / Flash Loan Attack Vectors",
        "description": "No profit possible from atomic (single-tx) operations. "
                       "Flash loan + protocol interaction should not yield net profit.",
        "attack_examples": [
            "Curve LlamaLend $240K: flash loan inflated collateral value",
            "Makina $5.1M: flash loan TWAP manipulation",
            "PRXVT: staking + flash loan extracted disproportionate rewards",
        ],
        "what_to_check": [
            "no profit from deposit + action + withdraw in same tx",
            "no profit from manipulating oracle price in same block",
            "no flash-loan-stake-claim-unstake attack path",
            "donation to protocol does not create extractable value for attacker",
        ],
    },
    "cross_function": {
        "name": "Cross-Function / Interaction Invariants",
        "description": "State consistency across function calls. Calling function A then B "
                       "must not create invalid states that neither function alone would allow.",
        "attack_examples": [
            "Euler: donateToReserves → liquidateSelf sequence enabled extraction",
            "DoughFinance $1.81M: callback forwarded calldata to Aave on behalf of other users",
        ],
        "what_to_check": [
            "reentrancy: external calls don't allow re-entry to manipulate state",
            "function ordering: no sequence of valid calls produces invalid state",
            "callback safety: callbacks don't allow state manipulation",
            "read-only reentrancy: view functions return consistent values during external calls",
        ],
    },
    "first_depositor": {
        "name": "First Depositor / Share Inflation Protection",
        "description": "First deposit to empty pool/vault must not allow price manipulation.",
        "attack_examples": [
            "Sonne Finance $20M: empty Compound market, deposit 1 wei, donate large amount",
            "PolterFinance $7M: same pattern on Fantom",
        ],
        "what_to_check": [
            "minimum deposit enforced on first deposit",
            "virtual shares/assets (dead shares) prevent inflation",
            "totalSupply > 0 implies totalAssets > 0 (and vice versa)",
            "convertToShares on empty vault doesn't return 0 for large deposits",
        ],
    },
    "oracle_dependency": {
        "name": "Oracle Safety / Price Feed Dependency",
        "description": "Oracle prices must be validated (freshness, bounds, circuit breakers). "
                       "Spot price must not be used for critical calculations.",
        "attack_examples": [
            "Moonwell $1.78M: oracle failure led to wrong liquidation prices",
            "Makina $5.1M: TWAP manipulation via flash loan",
        ],
        "what_to_check": [
            "oracle price freshness check (revert if stale)",
            "price within reasonable bounds (not 0, not astronomical)",
            "TWAP used instead of spot for critical decisions",
            "fallback oracle if primary fails",
        ],
    },
    "constant_product": {
        "name": "Constant Product / AMM Invariant",
        "description": "k = reserve0 * reserve1 must never decrease from swaps. "
                       "Only increases from fees.",
        "attack_examples": [
            "Various DEX hacks: price manipulation via reserve manipulation",
        ],
        "what_to_check": [
            "k_after >= k_before for every swap",
            "reserves match actual token balances",
            "fee accounting: fees increase k, not decrease",
        ],
    },
    "fee_accounting": {
        "name": "Fee Accounting Integrity",
        "description": "Fees collected must equal fees distributed. No fee evasion paths.",
        "attack_examples": [
            "FutureSwap $394K: fee unit mismatch (basis points vs percentage)",
            "MTToken: unbounded fee percentage sum",
        ],
        "what_to_check": [
            "fees collected >= fees distributed",
            "fee percentage within valid bounds (0-100%)",
            "no path to avoid paying fees",
            "fee-on-transfer tokens handled correctly",
        ],
    },
    "reward_accounting": {
        "name": "Reward Distribution Integrity",
        "description": "Total rewards distributed must not exceed total rewards notified. "
                       "Proportional to stake amount and duration.",
        "attack_examples": [
            "PRXVT: staking + flash loan extracted disproportionate rewards",
        ],
        "what_to_check": [
            "sum of all earned() <= total rewards notified",
            "rewards proportional to stake amount and time",
            "no double-claim possible",
            "claiming does not affect other users' pending rewards",
        ],
    },
    "supply_conservation": {
        "name": "Supply Conservation",
        "description": "totalSupply must equal sum of all balanceOf. "
                       "Mints increase supply, burns decrease supply, transfers conserve.",
        "attack_examples": [
            "Various: supply inflation bugs allowing unbacked minting",
        ],
        "what_to_check": [
            "totalSupply == sum of all balanceOf (exact)",
            "mint increases totalSupply by exact amount",
            "burn decreases totalSupply by exact amount",
            "transfer: sender decrease == receiver increase",
        ],
    },
    "message_integrity": {
        "name": "Message Integrity / Replay Protection",
        "description": "Cross-chain messages must not be replayable. Nonces must be sequential.",
        "attack_examples": [
            "Various bridge hacks: message replay across chains",
        ],
        "what_to_check": [
            "each message can only be executed once",
            "nonce is strictly increasing",
            "message hash includes chain ID",
            "finalization requires valid proof",
        ],
    },
    "replay_protection": {
        "name": "Replay Protection",
        "description": "Signatures and messages must not be replayable across chains or contexts.",
        "attack_examples": [
            "Bridge replays: same message executed on multiple chains",
        ],
        "what_to_check": [
            "nonce consumed after execution",
            "domain separator includes chain ID",
            "signature includes timestamp or deadline",
        ],
    },
}


# ============================================================================
# MASTER PROMPT GENERATION
# ============================================================================

def generate_master_prompt(
    source_code: str,
    file_list: list[str],
    functions: list[dict],
    state_vars: list[str],
    detected_types: list[dict],
    matched_invariants: list[dict],
    protocol_name: str,
    web3_root: str,
) -> str:
    """Generate the MASTER prompt that Claude Code executes directly."""

    func_summary = "\n".join(
        f"  - `{f['name']}({f['params']})` {f['visibility']}"
        for f in functions[:60]
    )

    state_var_summary = ", ".join(state_vars[:20])

    # Build detected type info
    if detected_types:
        primary = detected_types[0]
        type_info = f"**Primary type detected: {primary['label']}** (score: {primary['score']:.0%}, matched: {primary['matched_keywords']}/{primary['total_keywords']} keywords)"
        if len(detected_types) > 1:
            type_info += f"\nSecondary: {', '.join(d['label'] for d in detected_types[1:])}"
        categories = primary["categories"]
        knowledge_files = primary["knowledge_files"]
    else:
        type_info = "**Type: UNKNOWN** — novel protocol, using universal categories only"
        categories = list(UNIVERSAL_CATEGORIES)
        knowledge_files = []

    # Dedupe and add universal knowledge
    all_knowledge = list(dict.fromkeys(knowledge_files + UNIVERSAL_KNOWLEDGE))
    knowledge_paths = "\n".join(f"  - `{web3_root}/{f}`" for f in all_knowledge)

    # Build category sections
    category_sections = ""
    for cat in categories:
        desc = CATEGORY_DESCRIPTIONS.get(cat)
        if not desc:
            continue
        examples = "\n".join(f"    - {ex}" for ex in desc.get("attack_examples", []))
        checks = "\n".join(f"    - {c}" for c in desc.get("what_to_check", []))
        category_sections += f"""
#### Category: {desc['name']}

{desc['description']}

**Real exploits that this would have caught:**
{examples}

**What to check in THIS protocol:**
{checks}

"""

    # Matched invariants from registry
    inv_summary = ""
    if matched_invariants:
        inv_summary = "## Registry invariants that matched this target\n\n"
        inv_summary += "These are GENERIC invariants from our knowledge base that pattern-matched.\n"
        inv_summary += "Use them as STARTING POINTS, but generate SPECIFIC ones for this protocol.\n\n"
        for i in matched_invariants[:15]:
            inv_summary += f"- **[{i['severity'].upper()}] {i['id']}**: {i['title']} (confidence: {i['confidence']:.0%})\n"
            if i.get("natural"):
                inv_summary += f"  Natural: {i['natural']}\n"

    return f"""# INVARIANT GENERATION — {protocol_name}

## ROLE

You are an elite Web3 security auditor specialized in invariant-based testing.
Your job is to deeply understand this protocol and generate SPECIFIC invariants
that would catch real bugs — the kind that pay $50K-$1M+ bounties.

## PROTOCOL CLASSIFICATION

{type_info}

## SOURCE FILES

{', '.join(file_list)}

## PUBLIC FUNCTIONS

{func_summary}

## KEY STATE VARIABLES

{state_var_summary}

{inv_summary}

## SOURCE CODE

{source_code}

---

# INSTRUCTIONS — Follow this EXACT procedure

## PHASE 1: DEEP READ (mandatory)

Read ALL the source code above. For each contract file, understand:
- What does this contract do?
- Where does money flow in and out?
- What external calls does it make?
- What trust assumptions does it have?
- What math operations could have precision issues?

Write a Protocol Model (5-10 lines) documenting your understanding.

## PHASE 2: CONSULT KNOWLEDGE BASE

Before generating invariants, READ these files from our knowledge base to understand
what patterns have caught real bugs in protocols of this type:

{knowledge_paths}

For each file, extract the patterns most relevant to THIS specific protocol.
Don't copy generic invariants — understand the PATTERN and apply it specifically.

## PHASE 3: GENERATE INVARIANTS — Category by Category

For each category below, follow this procedure:

```
1. Generate AT LEAST 5 SPECIFIC invariants for this category.
   5 is the MINIMUM, not the ceiling. If you see more valid invariants, KEEP GOING.
   A complex component like a vault or lending pool can easily have 10-15 per category.
2. Each invariant must be:
   - SPECIFIC to this protocol's code (reference actual function/variable names)
   - Expressible as a Chimera assertion (t(), eq(), gte(), lte(), gt(), lt())
   - Tied to a concrete attack scenario (what happens if it breaks?)
3. If you have fewer than 5:
   - THINK DEEPER: consider edge cases, multi-step attacks, flash loan scenarios,
     cross-function interactions, rounding in specific math operations
   - Try one more time to find additional invariants
4. If after 2 rounds of deep thinking you still have fewer than 5:
   - That's OK. Some categories won't have 5 valid invariants for every protocol.
   - Quality > quantity. 2 precise invariants > 5 vague ones.
   - Move to the next category.
5. If you have MORE than 5 — GREAT. Include them all.
   The more specific invariants we have, the more attack surface we cover.
   There is NO upper limit. Only stop when you've exhausted real possibilities.
```

### Categories to analyze:

{category_sections}

## PHASE 4: OUTPUT FORMAT

Generate the complete Chimera harness code. ALL output must be in this exact format:

### OUTPUT 1: INVARIANT TABLE

A summary table of all generated invariants (AFTER Phase 5 verification):

```
| # | Category | ID | Tier | Severity | Description | Attack if broken | Verified |
|---|----------|----|------|----------|-------------|------------------|----------|
| 1 | solvency | INV-001 | 1 | Critical | ... | ... | Yes |
| 2 | rounding | INV-002 | 2 | High | ... (tolerance: 1 wei) | ... | Fixed |
```

Tier 1 = hard fail, any violation is a confirmed bug (fund loss, access bypass)
Tier 2 = needs tolerance for dust/rounding, violation needs manual review

### OUTPUT 2: BeforeAfter.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {{Setup}} from "./Setup.sol";

abstract contract BeforeAfter is Setup {{
    struct Vars {{
        // Ghost variables — track state before/after each operation
        // MUST include all values referenced in Properties.sol
    }}

    Vars internal _before;
    Vars internal _after;

    // Cumulative ghost variables (for conservation invariants)
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    // ... add protocol-specific cumulative trackers

    modifier updateGhosts {{
        __before();
        _;
        __after();
    }}

    function __before() internal {{
        // Snapshot all tracked values
    }}

    function __after() internal {{
        // Snapshot all tracked values after operation
    }}
}}
```

### OUTPUT 3: Properties.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {{Asserts}} from "@chimera/Asserts.sol";
import {{BeforeAfter}} from "./BeforeAfter.sol";

abstract contract Properties is BeforeAfter, Asserts {{

    // ==================== SOLVENCY (Tier 1 — hard fail) ====================

    function invariant_INV001_description() public {{
        // Use: t(), eq(), gt(), gte(), lt(), lte()
        // NO assert() or require() — not compatible with all fuzzers
        // Properties must NOT modify state
    }}

    // ==================== NEXT CATEGORY ====================
    // ... group invariants by category with clear headers
}}
```

### OUTPUT 4: TargetFunctions.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {{vm}} from "@chimera/Hevm.sol";
import {{Properties}} from "./Properties.sol";

abstract contract TargetFunctions is Properties {{

    // Handler for each public function
    // MUST use: updateGhosts modifier OR manual __before()/__after()
    // MUST use: between() for input clamping
    // MUST include boundary values: 0, 1, type(uint256).max, balance-1

    function handler_functionName(uint256 param) public updateGhosts asActor {{
        // Clamp input
        param = between(param, 0, maxReasonableValue);

        // Execute
        target.functionName(param);

        // Inline assertion (optional — for function-specific properties)
    }}
}}
```

### OUTPUT 5: optimize_* functions (for Echidna optimization mode)

```solidity
// Add these to TargetFunctions.sol or a separate OptimizationTargets.sol

// Echidna will try to MAXIMIZE the return value
// If it finds a positive value = potential exploit

function optimize_attacker_profit() public view returns (int256) {{
    // Return: attacker's balance change from initial state
    // Positive = attacker extracted value = BUG
    return int256(currentAttackerBalance) - int256(initialAttackerBalance);
}}
```

### OUTPUT 6: Setup.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {{BaseSetup}} from "@chimera/BaseSetup.sol";
import {{vm}} from "@chimera/Hevm.sol";
import {{ActorManager}} from "@recon/ActorManager.sol";
import {{AssetManager}} from "@recon/AssetManager.sol";
import {{Utils}} from "@recon/Utils.sol";

abstract contract Setup is BaseSetup, ActorManager, AssetManager, Utils {{
    // Protocol contract instances

    function setup() internal virtual override {{
        // Deploy all protocol contracts
        // Add 3 actors: user1, attacker (high balance), keeper/liquidator
        // Configure realistic initial state (not empty)
        // Approve tokens, deal balances
    }}
}}
```

## PHASE 5: VERIFICATION (mandatory — do NOT skip)

After generating all invariants and code, verify EVERY single one against this checklist.
This phase exists because invariants that reference non-existent variables/functions are
WORSE than no invariants — they waste fuzzing time on compilation errors.

### For EACH invariant, check ALL 5 points:

```
VERIFICATION CHECKLIST (per invariant):

[ ] 1. VARIABLE EXISTS — Every variable referenced in the assertion actually exists
       in the source code. Search for the exact name. If it's a ghost variable,
       verify it's declared in BeforeAfter.sol.

[ ] 2. FUNCTION EXISTS — Every function called in the assertion/handler actually exists
       in the protocol contracts. Search for the exact signature.
       DO NOT invent functions like "target.getHealth()" if the protocol uses "isHealthy()".

[ ] 3. TYPE CORRECT — uint256 vs int256, address vs contract type, etc.
       Casting must be explicit. No implicit bool→uint conversions.

[ ] 4. ATTACK REALISTIC — The BREAKS_IF scenario is actually possible:
       - Does the attacker have access to the required functions?
       - Is the attack NOT admin-only? (admin bugs are usually excluded from bounties)
       - Can this actually be executed atomically or does it require unrealistic setup?

[ ] 5. NOT DUPLICATE — This invariant is genuinely different from every other invariant
       in the set. Two invariants testing the same property with different names = waste.
```

### Verification procedure:

1. Go through each invariant in your table
2. For any that FAIL a checklist item:
   - Fix it if the fix is obvious (wrong variable name → correct name)
   - REMOVE it if it's fundamentally broken (references non-existent logic)
   - REPLACE it with a better invariant for that category if possible
3. After verification, update the INVARIANT TABLE with a new column: VERIFIED (Yes/No/Fixed)
4. The final Properties.sol and TargetFunctions.sol must ONLY contain verified invariants

### Common mistakes to catch:

- Using `totalAssets()` when the protocol calls it `getTotalAssets()`
- Using `balanceOf(address)` on a contract that doesn't inherit ERC20
- Referencing `msg.sender` inside an invariant (invariants are called by the fuzzer, not users)
- Using `assert()` instead of `t()` / `gte()` / etc.
- Ghost variables declared but never populated in `__before()` / `__after()`
- Handler calling a function with wrong number of arguments
- Assuming a function returns a value when it returns void
- Checking oracle price in an invariant without the protocol actually using an oracle

## PHASE 6: EMERGENT CATEGORIES (optional)

If during your deep read (Phase 1) you noticed something unusual in the code that
doesn't fit any predefined category — a custom mechanism, a novel DeFi primitive,
a cross-protocol interaction — you SHOULD create additional invariants for it.

This is where the highest-value bugs live: in the code that's unique to THIS protocol,
that no generic invariant template would cover.

Examples of emergent patterns:
- Custom bonding curve math → verify curve properties
- Epoch-based state machine → verify valid state transitions
- Permit/meta-transaction → verify signature validation
- Custom oracle aggregation → verify aggregation logic
- Novel liquidation mechanism → verify it can't be gamed

## ANTI-PATTERNS — DO NOT generate these:

1. **Generic ERC20 compliance** tests (transfer, approve, etc.) unless the protocol
   implements a custom ERC20 — these are already covered by crytic/properties
2. **Admin-only attack scenarios** — most bounty programs exclude these
3. **"totalSupply == sum of balances"** as a standalone invariant — too generic,
   already in our registry
4. **View function revert checks** (maxDeposit must not revert) — low value,
   rarely pays bounties
5. **Invariants that require unrealistic gas** (iterating over all users on-chain)
6. **Copy-pasted invariants** from the registry with names changed — must be SPECIFIC

## CRITICAL RULES

1. **Chimera assertion helpers ONLY**: t(), eq(), gt(), gte(), lt(), lte() — NEVER assert()/require()
2. **Properties MUST NOT modify state** — they are called as view checks
3. **Handlers MUST use updateGhosts** or manual __before()/__after()
4. **Boundary value injection**: 5% chance of 0, 5% chance of 1, 5% chance of max
5. **3 actors minimum**: honest user, attacker (large balance), keeper/liquidator
6. **Every invariant needs BREAKS_IF**: if you can't describe the attack, it's noise
7. **Reference ACTUAL names** from the code — no placeholder "target.someFunction()"
8. **Tier 1 invariants** (hard fail = confirmed bug) vs **Tier 2** (needs tolerance for dust)
9. **Time limits on warp**: max 7 days per step, max 90 days total
10. **optimize_* functions**: at least 2 for Echidna — one for attacker profit, one for protocol loss
11. **Verified only**: ONLY include invariants that passed Phase 5 verification
"""


# ============================================================================
# MAIN
# ============================================================================

def run_generator(source_dir: str, name: str, output_dir: str,
                  max_payout: int = 100000):
    """Generate the master prompt for Claude to execute."""

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Detect Web3 root (parent of audit-agents/)
    web3_root = str(Path(__file__).parent.parent)

    print(f"\n{'='*60}")
    print(f"AI INVARIANT GENERATOR v2: {name}")
    print(f"{'='*60}")

    # Step 1: Collect source
    print("\n[1/5] Collecting source code...")
    source_code, file_list = collect_source(source_dir)
    print(f"  {len(file_list)} files, {len(source_code):,} chars")

    # Step 2: Extract functions & state vars
    print("[2/5] Extracting functions and state variables...")
    functions = extract_public_functions(source_code)
    state_vars = extract_state_variables(source_code)
    print(f"  {len(functions)} public/external functions")
    print(f"  {len(state_vars)} state variables")

    # Step 3: Detect protocol type
    print("[3/5] Detecting protocol type...")
    detected_types = detect_protocol_type(source_code)
    if detected_types:
        for dt in detected_types:
            print(f"  -> {dt['label']} (score: {dt['score']:.0%}, {dt['matched_keywords']}/{dt['total_keywords']} keywords)")
    else:
        print("  -> Unknown type (will use universal categories)")

    # Step 4: Match registry invariants
    print("[4/5] Matching registry invariants...")
    matched = get_matched_invariants(source_dir, max_payout)
    print(f"  {len(matched)} invariants matched from registry")

    # Step 5: Generate master prompt
    print("[5/5] Generating master prompt...")
    master_prompt = generate_master_prompt(
        source_code, file_list, functions, state_vars,
        detected_types, matched, name, web3_root,
    )

    prompt_file = out_path / "MASTER_PROMPT.md"
    with open(prompt_file, "w", encoding="utf-8") as f:
        f.write(master_prompt)

    # Save metadata
    meta = {
        "target": name,
        "source_dir": source_dir,
        "files": file_list,
        "functions_count": len(functions),
        "functions": functions[:60],
        "state_variables": state_vars,
        "detected_types": detected_types,
        "matched_invariants": matched,
        "categories": detected_types[0]["categories"] if detected_types else list(UNIVERSAL_CATEGORIES),
    }
    meta_file = out_path / "metadata.json"
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    # Summary
    categories = detected_types[0]["categories"] if detected_types else list(UNIVERSAL_CATEGORIES)
    target_count = len(categories) * 5
    knowledge_count = len(detected_types[0]["knowledge_files"] if detected_types else []) + len(UNIVERSAL_KNOWLEDGE)

    print(f"\n{'='*60}")
    print(f"GENERATED: {prompt_file}")
    print(f"  Protocol type: {detected_types[0]['label'] if detected_types else 'Unknown'}")
    print(f"  Categories: {len(categories)}")
    print(f"  Target invariants: minimum {target_count} (5+ per category, no upper limit)")
    print(f"  Knowledge files to consult: {knowledge_count}")
    print(f"  Registry matches: {len(matched)}")
    print(f"\nNEXT STEP:")
    print(f"  In Claude Code, read {prompt_file} and follow the instructions.")
    print(f"  Claude will execute 6 phases:")
    print(f"    Phase 1: Deep read — understand protocol model")
    print(f"    Phase 2: Consult {knowledge_count} knowledge base files")
    print(f"    Phase 3: Generate 5+ invariants per category (no ceiling, deep-think retries if <5)")
    print(f"    Phase 4: Output complete Chimera harness code")
    print(f"    Phase 5: VERIFY every invariant (vars exist, funcs exist, types correct)")
    print(f"    Phase 6: Emergent categories (protocol-specific patterns)")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="AI-powered invariant generator v2 — context-aware, category-by-category"
    )
    parser.add_argument("--source", required=True, help="Path to target source directory")
    parser.add_argument("--name", required=True, help="Protocol name")
    parser.add_argument("--output", default="./ai-invariants", help="Output directory")
    parser.add_argument("--payout", type=int, default=100000, help="Max bounty payout (for priority scoring)")

    args = parser.parse_args()
    run_generator(args.source, args.name, args.output, args.payout)


if __name__ == "__main__":
    main()
