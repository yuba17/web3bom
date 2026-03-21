# BRIDGE-SPECIFIC SCORING SYSTEM

## Purpose

This scoring system is a specialized variant of our protocol triage scoring, optimized for cross-chain bridge targets. Bridges are our primary niche ($500K-$15M payouts), and this system helps us prioritize which bridge bounties to attack first.

---

## Scoring Dimensions (1-10 each, 10 = best for us)

### 1. BOUNTY ECONOMICS (weight: 2x)

Bridges have the highest payouts in Web3 bug bounties. Score accordingly.

| Score | Criteria |
|-------|----------|
| 10 | Max payout >= $10M (LayerZero, Stargate) |
| 9 | Max payout $5M-$10M |
| 8 | Max payout $2M-$5M (Wormhole, Hyperlane, Celer) |
| 7 | Max payout $1M-$2M |
| 6 | Max payout $500K-$1M (Axelar) |
| 5 | Max payout $200K-$500K (deBridge) |
| 4 | Max payout $100K-$200K |
| 3 | Max payout $50K-$100K |
| 2 | Max payout $10K-$50K |
| 1 | Max payout < $10K or no bounty |

**Bonus**: +1 if the program has a history of paying out (not just advertising a max).

### 2. TVL EXPOSURE (weight: 2x)

Higher TVL = higher impact = higher payout for critical findings.

| Score | Criteria |
|-------|----------|
| 10 | TVL > $1B |
| 8 | TVL $500M-$1B |
| 6 | TVL $100M-$500M |
| 4 | TVL $10M-$100M |
| 2 | TVL < $10M |

### 3. BRIDGE ARCHITECTURE COMPLEXITY (weight: 1.5x)

More complex = more bugs. Novel mechanisms are where undiscovered vulnerabilities live.

| Score | Criteria |
|-------|----------|
| 10 | Custom messaging layer + custom verification + multi-chain |
| 9 | Novel mechanisms (new proof systems, ZK bridges, intent-based) |
| 8 | Multi-chain support (5+ chains) with chain-specific logic |
| 7 | Lock-and-mint with custom guardian set |
| 6 | Liquidity pool model with complex rebalancing |
| 5 | Standard OFT/OApp with modifications |
| 4 | Standard lock-and-mint using established messaging layer |
| 3 | Simple wrapper around established bridge SDK |
| 2 | Single-chain-pair bridge with minimal logic |
| 1 | Fork of audited bridge with no changes |

### 4. CODE FRESHNESS (weight: 1.5x)

Recently deployed or updated code has the most undiscovered bugs.

| Score | Criteria |
|-------|----------|
| 10 | Deployed < 1 month ago, never audited |
| 9 | Major upgrade in the last month |
| 8 | New chain added in the last month |
| 7 | Deployed 1-3 months ago |
| 6 | Significant code changes in the last 3 months |
| 5 | Deployed 3-6 months ago, 1 audit |
| 4 | Deployed 6-12 months ago, 1 audit |
| 3 | Deployed > 1 year, 2 audits |
| 2 | Deployed > 1 year, 3+ audits + formal verification |
| 1 | Battle-tested > 2 years, no incidents |

### 5. VALIDATOR/GUARDIAN MODEL (weight: 1.5x)

Governance model is the #1 attack surface for bridges.

| Score | Criteria |
|-------|----------|
| 10 | Single-key or 1-of-N multisig controls funds |
| 9 | Low quorum (2/5 or 3/7) with centralized validators |
| 8 | Multisig with no timelock on upgrades |
| 7 | Multisig with short timelock (< 24 hours) |
| 6 | Moderate quorum (4/7) with some decentralization |
| 5 | High quorum (5/9+) with known validators |
| 4 | Decentralized validator set with staking |
| 3 | ZK proof verification (no validator trust) |
| 2 | Fully decentralized with formal verification |
| 1 | Canonical bridge (rollup native bridge) with L1 security |

### 6. SCOPE BREADTH (weight: 1x)

More code in scope = more attack surface.

| Score | Criteria |
|-------|----------|
| 10 | Full stack in scope (smart contracts + off-chain relayer + client) |
| 8 | Smart contracts + node/validator code in scope |
| 6 | Multiple contract types (bridge + token + governance) in scope |
| 4 | Core bridge contracts only |
| 2 | Very limited scope (single contract) |

### 7. CHAIN DIVERSITY (weight: 1x)

Multi-language bridges (Solidity + Rust + CosmWasm) have more places for bugs.

| Score | Criteria |
|-------|----------|
| 10 | 3+ languages (e.g., Solidity + Rust + CosmWasm + Move) |
| 8 | 2 languages (e.g., Solidity + Rust/Solana) |
| 6 | Single language but many chains (EVM-only, 10+ chains) |
| 4 | Single language, 3-5 chains |
| 2 | Single language, 1-2 chains |

### 8. COMPETITION LEVEL (weight: 1x)

| Score | Criteria |
|-------|----------|
| 10 | New bounty program, few researchers aware |
| 8 | Small or niche protocol, limited attention |
| 6 | Moderate attention, some researchers |
| 4 | Well-known protocol, many researchers |
| 2 | Heavily scrutinized (post-hack, many audits, big community) |

---

## Composite Score Calculation

```
WEIGHTED_SCORE = (
    (bounty_economics * 2) +
    (tvl_exposure * 2) +
    (architecture_complexity * 1.5) +
    (code_freshness * 1.5) +
    (validator_model * 1.5) +
    (scope_breadth * 1) +
    (chain_diversity * 1) +
    (competition * 1)
) / 11.5

COMPOSITE = round(WEIGHTED_SCORE, 1)
```

---

## Decision Thresholds (Bridge-Specific)

| Score | Decision | Action |
|-------|----------|--------|
| >= 7.5 | **PRIORITY TARGET** | Deploy all 5 bridge agents immediately. Allocate 40+ hours. |
| 6.0-7.4 | **GO** | Deploy bridge agents 1-3. Allocate 20-30 hours. |
| 5.0-5.9 | **MAYBE** | Run Agent 1 (message verification) only. Reassess after 4 hours. |
| < 5.0 | **SKIP** | Not worth our time for bridge analysis. Consider generic audit only. |

---

## Scorecard Template

```
# BRIDGE TARGET SCORECARD: [Protocol Name]
Date: YYYY-MM-DD

| Dimension | Score | Weight | Weighted | Notes |
|-----------|-------|--------|----------|-------|
| Bounty Economics | /10 | 2.0x | /20 | Max payout: $X |
| TVL Exposure | /10 | 2.0x | /20 | TVL: $X |
| Architecture Complexity | /10 | 1.5x | /15 | [model type] |
| Code Freshness | /10 | 1.5x | /15 | Last update: date |
| Validator Model | /10 | 1.5x | /15 | [M-of-N or model] |
| Scope Breadth | /10 | 1.0x | /10 | [# contracts] |
| Chain Diversity | /10 | 1.0x | /10 | [# chains, # languages] |
| Competition Level | /10 | 1.0x | /10 | [assessment] |
| **COMPOSITE** | | | **X.X/10** | |

Decision: [PRIORITY TARGET / GO / MAYBE / SKIP]
Recommended Agents: [1-5]
Estimated Hours: [X]
Expected ROI: $[max_payout * P(finding)] / [hours]
```
