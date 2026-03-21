---
tags: [strategy, methodology, v6, master]
date: 2026-03-17
status: ACTIVE
---

# V6 METHODOLOGY — Bug Bounty Hunting System

**Objective:** $25-40K/month --> $100-200K/month within 90 days.
**Baseline data:** 7 findings in 2 weeks, 24% hit rate on hypothesis agents, 0% on generic agents.

---

## 1. DAILY ROUTINE (6-8 hours active hunting)

### Morning Block: 30 min (07:00-07:30)
| Min | Action |
|-----|--------|
| 0-5 | Check upgrade monitor alerts (Forta/custom). If proxy upgrade detected on a scored-20+ target, DROP EVERYTHING and audit the diff. This is the single highest-ROI activity (30min/High). |
| 5-15 | Scan new bounties: Immunefi, Code4rena, Sherlock, Cantina, HackerOne. Score each using Section 2 formula. Takes 2 min per program. |
| 15-25 | Check Twitter/Telegram for exploits in last 24h. If a protocol was exploited, check adjacent protocols with similar code for the same bug class. |
| 25-30 | Update target queue. Pick top target for today's deep session. |

### Core Block: 4-5 hours (08:00-13:00)
| Min | Action |
|-----|--------|
| 0-10 | Clone target repo at exact bounty-specified commit. Run `cloc` on in-scope files. Run Slither + Aderyn in background. |
| 10-25 | Architecture mapping: 1 agent reads all contracts, produces call graph + state variable inventory + trust boundary map. |
| 25-40 | Known issues research: 1 agent checks past audits, Code4rena/Sherlock reports, GitHub issues, Solodit patterns. Output = exclusion list. |
| 40-90 | **PRIMARY HUNT** (see Section 3 for agent deployment). Deploy 8-12 hypothesis agents in parallel. Each gets specific attack vector + contract subset + exclusion list. |
| 90 | **HARD STOP.** Review all agent outputs. If nothing promising: PIVOT to next target. If promising leads exist: continue to validation. |
| 90-150 | **VALIDATION** (only if leads exist). Deploy devil's advocate agent per finding. Run Foundry fork PoC. Check deployed state. |
| 150-180 | **SECOND TARGET** (if first target exhausted). Run same pipeline on target #2 from queue. 90-min hard stop applies again. |

### Afternoon Block: 1-2 hours (15:00-17:00)
| Min | Action |
|-----|--------|
| 0-30 | Write and polish reports for any validated findings. Use platform-specific templates (Section 7). |
| 30-60 | Study one real exploit from DeFiHackLabs or Solodit. Add pattern to vulnerability-patterns-db.md. |
| 60-90 | Skill building: ZK circuit review, Rust/Solana, or Foundry invariant test writing. Rotate weekly. |
| 90-120 | Review one published audit report (C4, Sherlock, Spearbit). Extract new hypothesis templates. |

### Weekly (Sunday, 2h)
- Review week's metrics (Section 8)
- Score all new bounty programs added during the week
- Prune/update target queue
- Review and improve agent prompts based on hit/miss data

---

## 2. TARGET SELECTION ALGORITHM

### Scoring Formula (max 30 points, updated from V2)

```
SCORE = Novel_Code(1-5) + Audit_Gap(1-5) + Complexity(1-5) + Economics(1-5) + Competition(1-5) + Timing(1-5)
```

**Dimensions A-E:** Same as protocol-scoring-system.md (unchanged, validated on Day 1).

**NEW Dimension F: TIMING BONUS [/5]**
- 1 = Stable program, no recent changes, 6+ months old
- 2 = Minor update in last 3 months
- 3 = Significant update in last month
- 4 = Major code change or emergency patch in last 2 weeks
- 5 = Emergency patch in last 72 hours OR new program launched < 1 week ago

### Decision Thresholds (updated)
| Score | Action | Time Budget |
|-------|--------|-------------|
| 24-30 | DROP EVERYTHING. Immediate deep dive. | 8-10h |
| 20-23 | PRIORITY. Schedule for next available slot. | 4-6h |
| 16-19 | GOOD. Slot in if no priority targets. | 2-3h |
| 12-15 | MARGINAL. 90-min scan only. | 90min max |
| <12 | SKIP. | 0 |

### Meta-Gaming Multiplier
Track historical data per program. Multiply score by:
- 1.3x if program has paid >$100K total in last 6 months
- 1.2x if median response time < 3 days
- 0.7x if program has history of downgrading/rejecting valid findings
- 0.5x if program has >50 active hunters (check leaderboard)

### Current Target Queue (as of 2026-03-17)
| Target | Raw Score | Multiplier | Final | Rationale |
|--------|-----------|------------|-------|-----------|
| Scroll zkvm-prover | 24 | 1.3x (emergency patch) | 31 | Emergency patch Feb 23, ZK niche, $1M max |
| zkSync Airbender | 22 | 1.0x | 22 | New STARK/FRI prover, ZK niche, $2.3M max |
| NEAR Intents Bridges | 21 | 1.2x (new program) | 25 | MPC + bridge, 2 weeks old, low competition |
| Coinbase/Base | 19 | 1.3x (proven payer) | 25 | 4 findings already, more scope, $5M max |
| LayerZero | 20 | 1.0x | 20 | Group 2 chains less hunted, $15M max |

---

## 3. AGENT DEPLOYMENT PROTOCOL

### Critical Rule: HYPOTHESIS AGENTS ONLY
Generic "find all bugs" agents have a 0% hit rate. Every agent MUST receive a specific hypothesis to test.

### Phase 1: Recon (2 agents, 15 min)

**Agent R1 — Architecture Mapper**
```
You are auditing [PROTOCOL]. Read ALL Solidity files in [SCOPE].
Output a structured report:
1. Contract inheritance hierarchy
2. All external/public functions with access control
3. State variables that hold user funds or control critical logic
4. Trust boundaries: what roles exist, what can each do
5. Integration points: external calls, oracles, other protocols
6. Upgrade mechanisms: proxies, admin functions, timelocks
Do NOT look for bugs. Only map the system.
```

**Agent R2 — Known Issues Researcher**
```
Research all known issues for [PROTOCOL]:
1. Search for past audit reports (list firms, dates, findings count)
2. Check Code4rena/Sherlock contest results if any
3. Check GitHub issues and recent commits for bug fixes
4. Check Solodit for similar protocol type vulnerabilities
5. List ALL known issues that are OUT OF SCOPE for bounty
Output: exclusion list with brief description of each known issue.
```

### Phase 2: Hunt (8-12 hypothesis agents, 50 min)

Deploy from the following agent types based on protocol category.
Each agent gets: relevant contract files + hypothesis + exclusion list.

**UNIVERSAL AGENTS (deploy on every target):**

**Agent H1 — Post-Audit Diff Hunter (HIGHEST PRIORITY)**
```
Compare the current codebase against the last audited version.
For EACH changed function:
1. What was the change?
2. Could this change introduce: incorrect state update, missing validation, broken invariant?
3. Does this change interact with previously-audited code in a new way?
Focus on: new parameters, changed conditionals, reordered operations, removed checks.
Flag anything where the diff introduces an inconsistency with unchanged code.
Exclusion list: [PASTE]
```

**Agent H2 — Flag-Set-But-Never-Read**
```
Search for state variables or flags that are SET in one function but never READ
in any conditional or return value. These indicate incomplete implementations.
For each found: trace what the flag was supposed to control and what happens
without it being checked. If the flag controls a security property, this is a bug.
Contracts: [SCOPE]. Exclusion list: [PASTE]
```

**Agent H3 — Cross-Function Consistency**
```
For each pair of related functions (deposit/withdraw, stake/unstake, borrow/repay,
lock/unlock, mint/burn), verify:
1. Every state variable modified in function A is correctly reversed/updated in function B
2. Fee calculations are symmetric (or intentionally asymmetric with documented reason)
3. Access control is consistent (if A requires X, B should require X or stronger)
4. Edge cases: zero amounts, max amounts, self-referential calls
Flag any asymmetry that could lead to stuck funds, incorrect balances, or fee bypass.
Contracts: [SCOPE]. Exclusion list: [PASTE]
```

**Agent H4 — Check-Outside-Branch**
```
Find validation checks (require, assert, if-revert) that exist in SOME code paths
but are MISSING in other code paths that reach the same state modification.
Example: a require(amount > 0) in deposit() but not in depositFor().
For each: determine if the missing check allows an attacker to bypass intended constraints.
Contracts: [SCOPE]. Exclusion list: [PASTE]
```

**Agent H5 — Spec-vs-Code Divergence**
```
Read the protocol documentation, NatSpec comments, and README.
For each documented behavior or invariant, verify the code actually implements it.
Focus on:
1. Documented fee percentages vs. actual math
2. Documented access restrictions vs. actual modifiers
3. Documented limits/caps vs. actual enforcement
4. Documented token support vs. actual token handling
Any divergence is a potential bug. Contracts: [SCOPE]. Docs: [DOCS_PATH].
Exclusion list: [PASTE]
```

**CATEGORY-SPECIFIC AGENTS (deploy 3-5 based on protocol type):**

**DeFi Lending:**
- H-Lend-1: First depositor / share inflation on every vault
- H-Lend-2: Oracle staleness + fallback behavior under extreme prices
- H-Lend-3: Liquidation edge cases (dust positions, incentive > collateral, bad debt path)
- H-Lend-4: Interest accrual ordering (is accrueInterest called before every state change?)
- H-Lend-5: Cross-market position manipulation (borrow in A, manipulate collateral in B)

**ZK Circuits:**
- H-ZK-1: Under-constrained witness values (can a malicious prover satisfy constraints with invalid witness?)
- H-ZK-2: Range check completeness (every field element properly range-checked?)
- H-ZK-3: Fiat-Shamir transcript (all public values included? ordering correct?)
- H-ZK-4: Boundary conditions in recursive/shard proofs
- H-ZK-5: Public IO commitment integrity (can prover lie about public inputs?)

**Bridges / Cross-Chain:**
- H-Bridge-1: Message replay (chain ID in hash? nonce tracking?)
- H-Bridge-2: Validator/guardian set update race conditions
- H-Bridge-3: Rate limit bypass via multiple small transfers
- H-Bridge-4: Token decimal mismatch across chains
- H-Bridge-5: Timeout/expiry handling (what happens to stuck messages?)

**Staking / Rewards:**
- H-Stake-1: Flash loan staking for reward capture
- H-Stake-2: Reward precision loss under extreme total supply
- H-Stake-3: Epoch boundary double-claim
- H-Stake-4: Emergency withdraw bypasses slashing/penalty

### Phase 3: Validate (1 agent per finding)

**Agent V1 — Devil's Advocate**
```
A researcher claims: [FINDING DESCRIPTION]

Your job is to DISPROVE this finding. Try to show it is:
1. Not exploitable (what prevents the attack in practice?)
2. Already known (is this in any audit report or known issue?)
3. Requires admin/privileged access (excluded by most bounties)
4. Theoretical only (no concrete path to fund loss)
5. Already mitigated by other code not considered by the researcher
6. Out of scope for this bounty program

Be aggressive. If you cannot disprove it after thorough analysis, output:
"VALIDATED — could not disprove" with remaining concerns.
If you can disprove it, output: "REJECTED — [reason]"
```

### Phase 4: PoC (Foundry, fork mainnet)

**Agent P1 — PoC Builder**
```
Write a Foundry test that demonstrates [FINDING].
Requirements:
1. Fork mainnet at latest block
2. Use actual deployed contract addresses
3. Show exact profit/loss amounts
4. Include comments explaining each step
5. Must compile and pass with `forge test --fork-url [RPC] -vvv`
Template: see foundry-workspace/test/templates/
```

---

## 4. PIPELINE STAGES

```
STAGE 0: MONITOR (continuous, automated)
  |-- Upgrade alerts (Forta/OpenZeppelin Defender)
  |-- New bounty alerts (Immunefi RSS, Code4rena, Sherlock)
  |-- Exploit alerts (Twitter bot, DeFi Llama hacks)
  v
STAGE 1: SCORE (2 min per program)
  |-- Apply scoring formula (Section 2)
  |-- Reject < 12 immediately
  |-- Queue 12+ sorted by final score
  v
STAGE 2: RECON (15 min)
  |-- Clone at bounty-specified commit
  |-- Deploy R1 + R2 agents
  |-- Run static analysis in background
  |-- Output: architecture map, exclusion list, LOC count
  v
STAGE 3: HUNT (50 min, HARD STOP at 90 min total)
  |-- Deploy 8-12 hypothesis agents (Section 3)
  |-- Each agent returns: findings ranked by confidence
  |-- Filter: discard anything in exclusion list
  |-- Filter: discard anything requiring admin access
  |-- Output: candidate findings list
  v
STAGE 4: VALIDATE (30 min per finding)
  |-- Devil's advocate agent per finding
  |-- Check finding exists in CURRENT deployed code
  |-- Check all known issue databases
  |-- Estimate realistic payout probability
  |-- KILL if < 50% confidence after validation
  v
STAGE 5: POC (30-60 min per finding)
  |-- Fork mainnet Foundry test
  |-- Quantify exact USD impact
  |-- Verify on deployed contract state
  |-- If PoC fails: re-examine finding, likely false positive
  v
STAGE 6: REPORT (30 min per finding)
  |-- Platform-specific format (Section 7)
  |-- Include PoC code
  |-- Quantify impact in USD
  |-- Propose fix (1-3 lines)
  |-- Run pre-submission checklist (Section 7)
  v
STAGE 7: SUBMIT
  |-- Only at > 50% confidence
  |-- Track in 06-Submissions/ with metadata
  |-- Set calendar reminder for follow-up at 7 days
```

---

## 5. TOOLING STACK

### Tier 0: Infrastructure (install first)

| Tool | Purpose | Install |
|------|---------|---------|
| Foundry | Testing, fuzzing, fork PoC | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| Slither | Static analysis | `pip install slither-analyzer` |
| Aderyn | Fast Rust-based analysis | `cargo install aderyn` |
| Trail of Bits Claude Skills | `github.com/trailofbits/skills` — install as Claude Code custom skills for Solidity review | Clone + follow setup |
| forefy/.context | Prompt framework for audit context | Clone into each audit workspace |

### Tier 1: Discovery & Monitoring

| Tool | Purpose | Priority |
|------|---------|----------|
| Forta Bot (custom) | Real-time proxy upgrade alerts | BUILD WEEK 1 |
| OpenZeppelin Defender Sentinel | Backup monitoring | Configure WEEK 1 |
| Immunefi RSS + parser | New bounty alerts | BUILD WEEK 1 |
| DeFi Llama Hacks API | Exploit alerts | BUILD WEEK 2 |

### Tier 2: Analysis

| Tool | Purpose | Priority |
|------|---------|----------|
| PropertyGPT | LLM generates invariants, formal verifier checks | INTEGRATE WEEK 2 |
| Echidna/Medusa | Property-based fuzzing for invariant tests | USE PER-TARGET |
| Halmos | Symbolic execution for edge cases | USE PER-TARGET |
| Circomspect + Picus | ZK circuit analysis | USE FOR ZK TARGETS |
| Solodit MCP Server | AI-integrated pattern matching | INTEGRATE WEEK 1 |

### Tier 3: Experimental

| Tool | Purpose | Priority |
|------|---------|----------|
| Octane Security approach | RL-guided offensive AI. Study their methodology. Build simplified version: agent generates attack, tests it, learns from failure. | RESEARCH MONTH 2 |
| SCONE-bench patterns | Study how Claude found zero-days in deployed contracts. Replicate methodology. | RESEARCH MONTH 1 |
| Economic Invariant Templates | Reusable Foundry invariant test suites per protocol type (lending, DEX, staking) | BUILD MONTH 1-2 |

### Workspace Structure
```
audit-agents/
  contracts/
    [protocol-name]/        # cloned repos
  foundry-workspace/
    test/
      templates/            # reusable PoC templates
      invariants/           # per-protocol-type invariant suites
        lending/
        dex/
        staking/
        bridge/
  agents/
    prompts/
      universal/            # H1-H5 templates
      lending/              # H-Lend-1 through H-Lend-5
      zk/                   # H-ZK-1 through H-ZK-5
      bridge/               # H-Bridge-1 through H-Bridge-5
      staking/              # H-Stake-1 through H-Stake-4
    results/
      [protocol-name]/
        [date]/             # agent outputs per session
  monitoring/
    upgrade-monitor/        # Forta bot code
    bounty-scanner/         # new program alerter
    exploit-tracker/        # live exploit monitor
```

---

## 6. KILL RULES

These are non-negotiable. They exist because 50% of time was wasted on exhausted programs.

| Rule | Condition | Action |
|------|-----------|--------|
| 90-MIN HARD STOP | 90 minutes on a target with zero promising leads | STOP. Move to next target. No exceptions. |
| EXHAUSTED PROGRAM | Program has been live >1 year with >3 audits and no recent code changes | SKIP unless score > 22. |
| ADMIN-ONLY | Finding requires admin/governance action to exploit | KILL immediately. Do not even validate. |
| KNOWN ISSUE | Finding appears in any past audit, GitHub issue, or forum post | KILL immediately. |
| THEORETICAL ONLY | Cannot construct concrete attack path with specific function calls | KILL. "Could be dangerous" is not a finding. |
| LOW CONFIDENCE | After validation, confidence < 50% | Do NOT submit. Archive in 07-Daily-Findings/ for learning. |
| DIMINISHING RETURNS | 3+ hours on a target with only Medium-severity leads | STOP unless the Medium is very high confidence. |
| DEPLOYMENT MISMATCH | Code differs between repo and deployed contract | STOP. Verify correct source. If unresolvable, SKIP target. |

### Pivot Protocol
When a kill rule triggers:
1. Log time spent and reason for stopping in session notes
2. Move target to "REVISIT" queue (only revisit if new code deployed)
3. Pick next target from queue immediately
4. Do NOT spend time second-guessing the kill decision

---

## 7. QUALITY CHECKLIST (Pre-Submission)

### Gate 1: Is it real?
- [ ] Bug exists in the CURRENT deployed code at the bounty-specified commit
- [ ] Verified on-chain state matches assumptions (not just code review)
- [ ] PoC compiles and passes on mainnet fork at latest block
- [ ] Impact is quantifiable in USD terms

### Gate 2: Is it in scope?
- [ ] Not in any known issues list (audits, GitHub, forums, contest results)
- [ ] Not excluded by bounty rules (read rules AGAIN before submitting)
- [ ] Does NOT require admin, governance, or privileged access
- [ ] Affected contract is listed in bounty scope
- [ ] Uses the correct bounty-specified source (not old repo)

### Gate 3: Is it worth submitting?
- [ ] Devil's advocate agent could NOT disprove it
- [ ] Confidence level > 50%
- [ ] Expected payout > $500 (factor in probability of acceptance)
- [ ] If Code4rena/Sherlock: is it a unique High, not a duplicate Medium?

### Gate 4: Is the report strong?
- [ ] Title is specific and describes the impact (not the mechanism)
- [ ] Severity is correctly framed per platform guidelines
- [ ] Impact section leads with "direct fund loss" or "permanent DoS" when applicable
- [ ] PoC is included, runnable, and commented
- [ ] Fix is proposed (1-5 lines of code)
- [ ] Similar real-world incidents referenced if available
- [ ] Report uses platform-specific format (Immunefi/C4/Sherlock/Cantina)

### Platform-Specific Formatting

**Immunefi:** Title, Severity, Description, Impact, PoC, Fix. Lead with impact. Reference their severity guidelines explicitly.

**Code4rena:** Follow exact template. H/M/QA classification. Include "Lines of Code" section with GitHub permalink. Wardens judge, so write for technical readers.

**Sherlock:** Follow judging guidelines precisely. "Definite loss of funds" = High. "Conditional loss" = Medium. Include constraints analysis.

**Cantina:** Professional tone. Spearbit-style detailed writeup. Include threat model.

---

## 8. REVENUE TRACKING

### Per-Finding Metrics
| Field | Example |
|-------|---------|
| Finding ID | F-2026-03-17-001 |
| Protocol | Scroll zkvm-prover |
| Platform | Immunefi |
| Severity claimed | Critical |
| Severity accepted | (pending) |
| Payout | (pending) |
| Time to find | 2.5h |
| Time to report | 1h |
| Total time | 3.5h |
| Hourly rate | (calculated on payout) |
| Agent type that found it | H-ZK-1 (under-constrained witness) |
| Was it from: diff / state / hypothesis / monitoring | hypothesis |
| Confidence at submission | 70% |

### Weekly Dashboard
| Metric | Target | This Week |
|--------|--------|-----------|
| Targets scored | 15+ | |
| Targets hunted | 5-7 | |
| Findings submitted | 2-3 | |
| Findings accepted | (lagging) | |
| Total time hunting | 30-40h | |
| Hours wasted (killed targets) | < 10h | |
| Agent hit rate (by type) | > 20% | |
| $/hour (rolling 4-week) | > $200 | |

### Monthly Review
- Calculate actual $/hour by agent type, target type, and severity
- Drop agent types with < 10% hit rate over 4 weeks
- Add new hypothesis templates based on accepted findings
- Review kill rule effectiveness (did we stop too early? too late?)
- Update target scoring weights based on actual payout data

---

## 9. INFRASTRUCTURE TO BUILD (prioritized by ROI)

### WEEK 1 (highest ROI, build immediately)

**1. Upgrade Monitor (ROI: extreme)**
- Forta bot that watches proxy upgrade events on top 50 protocols
- On upgrade: auto-fetch new implementation, diff against previous
- Alert via Telegram/Discord within 60 seconds
- This is the single most valuable infrastructure. Post-audit diffs = 30min/High.
- Contracts to watch: every protocol in our target queue + all protocols with >$500K bounty

**2. Hypothesis Agent Prompt Library**
- Formalize all agent templates from Section 3 into reusable files
- Directory: `audit-agents/agents/prompts/`
- Include exclusion list injection, scope injection, output format
- A/B test prompt variations and track hit rates

**3. Bounty Program Scanner**
- Extend existing bounty_monitor_v2.py
- Auto-score new programs using Section 2 formula
- Alert only for score > 16
- Include: max payout, age, last audit date, LOC estimate

### WEEK 2-3

**4. Economic Invariant Template Library**
- Foundry invariant test suites per protocol type
- Lending: total deposits >= total borrows, no negative health factors, interest monotonically increases
- DEX: K-value invariant, fee accounting sums correctly, no tokens stuck
- Staking: total staked == sum of individual stakes, rewards distributed <= rewards funded
- Deploy these as first pass on any new target

**5. PropertyGPT Integration**
- LLM generates invariants from NatSpec + code
- Formal verifier (Halmos/Certora-lite) checks them
- This catches "what SHOULD be true but isn't" bugs
- Integrate into Phase 2 as an additional agent type

**6. Deployed State Scanner**
- Script that checks common misconfigurations on deployed contracts:
  - Uninitialized proxies (implementation.initialize() not called)
  - Admin keys = EOA (not multisig)
  - Paused contracts with funds
  - Allowance approvals to deprecated contracts
- Run weekly against top 100 DeFi protocols

### MONTH 2

**7. RL-Guided Attack Agent (Octane-inspired)**
- Agent generates attack hypothesis
- Runs Foundry fork test
- If test fails: analyzes WHY and generates refined hypothesis
- Iterates 5-10 times per target
- Track improvement in hit rate vs. single-shot agents

**8. Cross-Protocol Vulnerability Propagation**
- When a bug is found in Protocol A, auto-scan all forks/similar protocols
- Maintain fork genealogy database
- "Compound V2 fork" -> check all 47 known forks for same bug
- This is how the IoTeX $4.4M was found (same bug class, different protocol)

### MONTH 3

**9. Contest Result Analyzer**
- Scrape all Code4rena/Sherlock contest results
- For each accepted High/Critical: extract bug pattern, add to hypothesis library
- Track which bug patterns are most common per protocol type
- Auto-generate new hypothesis agents from trending patterns

**10. Payout Prediction Model**
- Train on our submission history + public contest results
- Input: finding description, severity, protocol type, platform
- Output: probability of acceptance, expected payout range
- Use as additional gate before submission

---

## 10. MONTHLY GOALS

### Month 1 (Days 1-30): Foundation + Quick Wins
**Revenue target: $40-60K**
- Build Week 1 infrastructure (upgrade monitor, prompt library, scanner)
- Hunt 5 targets per week using V6 pipeline
- Submit 8-12 findings total
- Focus on: Scroll emergency patch (adjacent bugs), Coinbase/Base (existing context), NEAR Intents (new program)
- Build economic invariant templates for lending + staking
- Study 4 real exploits from DeFiHackLabs (1/week)
- Integrate Trail of Bits Claude skills + forefy/.context

### Month 2 (Days 31-60): Scale + Specialize
**Revenue target: $60-100K**
- ZK deep specialization: complete Scroll + zkSync Airbender + any new ZK bounty
- PropertyGPT integration live
- RL-guided attack agent prototype
- Deploy cross-protocol propagation for any finding in Month 1
- Hunt 6-8 targets per week (efficiency gains from tooling)
- Submit 12-16 findings total
- Review Month 1 metrics: drop low-ROI activities, double down on high-ROI

### Month 3 (Days 61-90): Compound + Optimize
**Revenue target: $100-200K**
- Full automation pipeline: monitor -> alert -> auto-clone -> auto-score -> agent deploy
- Contest result analyzer feeding new hypothesis templates
- Payout prediction model operational
- Target the big fish: LayerZero ($15M), Wormhole ($10M), zkSync ($2.3M)
- Hunt 8-10 targets per week
- Submit 15-20 findings total
- Hit rate target: 30%+ on hypothesis agents (up from 24%)

### 90-Day Success Metrics
| Metric | Target |
|--------|--------|
| Total findings submitted | 35-48 |
| Findings accepted | 15-25 (40-50% acceptance) |
| Total revenue | $200-400K cumulative |
| Monthly run rate by Day 90 | $100-200K/month |
| $/hour (average) | > $300 |
| Highest single payout | > $50K |
| Agent hit rate | > 30% |
| Time wasted ratio | < 20% of total hours |

### Scaling Levers (ordered by impact)
1. **Upgrade monitoring** — near-zero competition on fresh diffs, 30min/High
2. **ZK specialization** — 50-150 global competitors vs 5000+ in EVM, 10x payout/competition ratio
3. **Agent prompt refinement** — every 5% hit rate improvement = ~$15K/month at scale
4. **Cross-protocol propagation** — one bug pattern tested across 10+ forks = multiplicative returns
5. **Economic invariant templates** — reusable across all protocols of same type, catches accounting bugs that are 37% of all payouts

---

## APPENDIX A: Quick Reference — What To Do When

| Situation | Action |
|-----------|--------|
| Upgrade alert fires | Drop everything. Diff within 5 min. Hunt for 90 min. |
| New $1M+ bounty appears | Score immediately. If > 20, schedule for tomorrow. |
| Protocol gets exploited | Check adjacent protocols for same bug class within 2h. |
| Agent returns 5+ findings | Suspicious. Most are probably false positives. Validate top 2 only. |
| Agent returns 0 findings | Expected. Move on. Do NOT re-run with looser prompts. |
| Finding rejected by platform | Analyze why. Update exclusion heuristics. Do NOT argue unless clear error. |
| Finding downgraded | Analyze severity framing. Update report templates. |
| 3 days without a finding | Normal variance. Do NOT change methodology. Check you are following kill rules. |
| 7 days without a finding | Review: are targets scored correctly? Are agents getting right context? Spend 2h on prompt refinement. |

## APPENDIX B: Bug Pattern Quick Deploy

When starting a new target, copy-paste the relevant patterns from vulnerability-patterns-db.md into agent prompts. Minimum patterns to check per protocol type:

- **Lending:** L-01, L-02, L-03, L-08, L-09, L-10 (the 6 that caused >$100M in real losses)
- **DEX:** D-01, D-03, D-04, D-05, D-15 (callback validation is most missed)
- **Staking:** S-01, S-04, S-06, S-10 (flash stake + double claim + precision + merkle)
- **Bridge:** B-01, B-02 (replay + validator race = 90% of bridge exploits)
- **ZK:** All H-ZK agents (small enough field that exhaustive checking is feasible)

## APPENDIX C: The 4x Revenue Formula

Current: 7 findings / 2 weeks = $25-40K/month

To reach $100-200K/month, we need ONE of:
- 4x more findings at same average payout (28 findings/2wk) — achievable via tooling + more targets
- Same findings at 4x average payout — achievable via ZK/bridge niche (avg $25K vs $6K)
- 2x findings at 2x payout — most realistic path

**The plan:** 2x findings (better tooling, faster pipeline, monitoring alerts) + 2x payout (ZK + bridge specialization, targeting $1M+ programs) = 4x revenue.
