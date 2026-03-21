---
tags: [strategy, master, v2]
date: 2026-03-16
---

# MASTER STRATEGY v2 — Bug Bounty Hunting System

## THE KEY INSIGHT (from top hunter research)

"You don't need 100 bugs. You need ONE critical in ONE high-value protocol."
- $10M Wormhole = uninitialized proxy (one report)
- $6M Aurora = unlimited ETH minting (one report)
- $2M Optimism = bridge bug (one report)

Our findings confirm: logic bugs in novel code > pattern matching in old code.

## TWO ARCHETYPES

### Sniper ($500K-$10M/year potential)
- Pick 1 domain (bridges, ZK, L2)
- Study 3-5 protocols deeply (weeks each)
- Target ONLY Critical on $1M+ bounties

### Grinder ($100K-$500K/year potential)
- Hit every Code4rena/Sherlock contest
- Read ENTIRE codebase (200 LOC/hour benchmark)
- Target unique Highs for solo payout

### Our Approach: HYBRID
- Use agents for broad scanning (Grinder speed)
- Focus on novel code (Sniper targeting)
- Primary niche: Cross-chain bridges + ZK circuits
- Secondary: Novel DeFi mechanisms

## PROTOCOL SCORING (validated Day 1)
See: protocol-scoring-system.md
- Score 20+ = PRIORITY (6-10h)
- Score 15-19 = GOOD (3-6h)
- Score 12-14 = MARGINAL (2h max)
- Below 12 = SKIP

## TOOLS STACK
### Tier 1 (Non-negotiable):
- Foundry (testing, fuzzing, PoC, fork)
- Slither + Slitherin (static analysis + DeFi detectors)
- Solodit (50K+ vulnerability patterns)
- VSCode + Solidity Visual Developer

### Tier 2 (Power multipliers):
- Aderyn (Rust-based, sub-second analysis)
- Echidna/Medusa (property-based fuzzing)
- Halmos (symbolic testing)
- DeFiHackLabs (reproduce real exploits)

### Tier 3 (Automation):
- scrapyFi (download Immunefi contracts)
- VigilSeek (monitor all platforms)
- Solodit MCP Server (AI-integrated pattern matching)
- Custom agent prompt library

### Chain-specific:
- Solana: X-Ray (sec3), Trident fuzzer
- ZK: Circomspect, Picus (Veridise)
- CosmWasm: cosmwasm-check

## BUG TYPES THAT PAY MOST
1. Accounting desync (37% of payouts)
2. Access control — missing on sibling functions (19% of Criticals)
3. Oracle/price manipulation ($52M in 2024)
4. Uninitialized proxy (highest single payout ever: $10M)
5. Cross-function reentrancy ($47M in 2024)

## PRIMARY NICHES (best edge)
1. Cross-chain bridges — $500K-$15M, multi-chain analysis edge
2. ZK circuits — $250K-$1.6M, only 50-150 hunters globally
3. New L2/L3 launches — time-sensitive first-mover advantage

## DAILY ROUTINE
1. Morning: Check new bounties, Twitter exploits
2. Core (4-6h): Deep code review, one protocol at a time
3. Break: Study one past exploit from DeFiHackLabs
4. Evening: Write/refine PoCs, submit reports
5. Weekly: Review published C4/Sherlock reports

## WORKFLOW v2
### Phase 0: Score (10 min per protocol)
### Phase 1: Triage (30-45 min) — 2-3 agents
### Phase 2: Targeted analysis (2-3h) — 8-12 agents
### Phase 3: Deep dive (2-3h) — 5-10 agents, only on candidates
### Phase 4: Validate (devil's advocate) — mandatory gate
### Phase 5: Verify on latest code — check deployed version
### Phase 6: Write report — platform-specific format
### Phase 7: Submit — only at >50% confidence

## PRE-SUBMISSION MANDATORY CHECKLIST
- [ ] Bug in CURRENT deployed code (not old version)
- [ ] Not in ANY known issues (all sources)
- [ ] Not excluded by bounty rules
- [ ] Does NOT require admin/privileged access
- [ ] Concrete, demonstrable impact
- [ ] Validation agent >50% payout probability
- [ ] Runnable PoC included
- [ ] Severity correctly framed
- [ ] USD impact quantified
- [ ] Title is descriptive and impactful
