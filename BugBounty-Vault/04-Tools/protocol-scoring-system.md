---
tags: [tools, scoring, protocol-selection]
date: 2026-03-16
---

# Protocol Scoring System v1.0

Rate each bounty program on 5 dimensions (1-5, max 25):

## A. NOVEL CODE DENSITY [/5]
- 1 = Thin fork (<10% modified)
- 2 = Fork with moderate changes (10-30%)
- 3 = Fork with major changes (>30%) OR >50K novel LOC
- 4 = Custom, 3K-8K novel LOC
- 5 = Custom, 8K-25K novel LOC

## B. AUDIT GAP [/5]
- 1 = 5+ top-firm audits + public contest, recent
- 2 = 3-4 thorough audits, full scope
- 3 = 2-3 audits with scope gaps or stale coverage
- 4 = 1 audit only, or only lesser-known firms
- 5 = 1-2 audits with recent unaudited code changes

## C. MECHANISM COMPLEXITY [/5]
- 1 = Simple token/NFT
- 2 = Standard DeFi primitive
- 3 = Modified standard + 2+ integrations
- 4 = Novel mechanism OR cross-domain
- 5 = Novel mechanism AND cross-domain AND state complexity

## D. BOUNTY ECONOMICS [/5]
- 1 = Max <$5K or inactive
- 2 = Max $5K-$15K
- 3 = Max $15K-$50K
- 4 = Max $50K-$200K, active
- 5 = Max >$200K, responsive team

## E. COMPETITION LEVEL [/5]
- 1 = Active contest, 100+ hunters
- 2 = Recent contest, many hunters
- 3 = Established, moderate activity
- 4 = Newer, low activity
- 5 = New/unknown, very few hunters

## DECISION THRESHOLDS
- 20-25 → PRIORITY TARGET (6-10h deep dive)
- 15-19 → GOOD TARGET (3-6h selective)
- 12-14 → MARGINAL (2h max, only if nothing better)
- Below 12 → SKIP

## VALIDATED: Day 1 retroactive scoring perfectly predicted outcomes
- Intuition 20/25 → Found High ✅
- Rujira 19/25 → Found real bug ✅
- SP1 17/25 → Found Medium ✅
- Moonwell 10/25 → Almost nothing ✅
- GMX-Solana 10/25 → Nothing, $25 lost ✅
