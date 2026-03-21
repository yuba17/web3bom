---
tags: [analysis, day1, performance]
date: 2026-03-16
---

# Day 1 Performance Analysis

## Stats
- Protocols: 5 (Moonwell, GMX-Solana, Rujira, Intuition, SP1)
- Total LOC: 226K
- Agents deployed: 107+
- Findings submitted: 2 (Moonwell, Intuition)
- Pending: 1 (SP1 REMUW)
- Money spent: $75 ($25 lost on GMX)
- Expected value: $6K-$30K (4x-20x ROI on cash, 4x-20x on time at $100/hr)

## Key Insight: ALL finds were in NOVEL LOGIC
- Intuition: logic bug in game-theoretic mechanism
- SP1: missing algebraic term in ZK constraint
- Moonwell: phase transition edge case in new OEV code
- Rujira: fee accounting in new orderbook code
- ZERO finds in generic vulnerability classes (reentrancy, overflow, etc.)

## Protocol Selection Ranking (best to worst)
1. SP1 — 85% confidence, ZK constraints are under-audited
2. Intuition — 65% confidence, small codebase, novel logic
3. Moonwell — 55% confidence, only viable in OEV (new code)
4. Rujira — bug was real but already fixed
5. GMX-Solana — 0 findings, battle-tested fork, $25 lost

## Optimal Protocol Profile
- Novel protocol, NOT a fork (or fork with substantial new code)
- Under 30K LOC (agents more effective on focused codebases)
- New bounty program (less competition)
- Complex state machines or game-theoretic mechanisms
- ZK circuits or custom math

## Time Allocation (optimal)
- Phase 1 Triage: 30-45 min, 2-3 agents → STOP if fork/battle-tested
- Phase 2 Targeted: 2-3 hours, 8-12 agents → STOP if no leads
- Phase 3 Deep dive: 2-3 hours, 5-10 agents → only on candidate bugs
- Phase 4 Writeup: 30-60 min → only after validation passes

## Process Failures to Fix
1. Paid $25 deposit before having validated finding (GMX)
2. Didn't check live repo before deep analysis (Rujira)
3. Spent deep-dive time on battle-tested forks (GMX, Moonwell)
4. Searched for generic vulns instead of protocol-specific invariants
