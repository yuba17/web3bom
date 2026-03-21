# Autonomous Bug Hunting System — Future Architecture v1.0
# Design Date: 2026-03-19
# Author: Future Architecture Planner (10-person team)

---

## ROUND 1: VISION — The Perfect Autonomous Bug Hunter

### What Does $100K/Month Look Like?

At current bounty rates:
- 1 Critical/month at $50-100K programs = $50-100K
- 2-3 Highs/month at $10-50K programs = $20-100K
- 5-10 Mediums/month at various programs = $10-50K

The system needs to process 30-50 programs/month, find actionable bugs in ~10%,
and convert those into accepted reports at >60% acceptance rate.

### Current System Gaps (Honest Assessment)

What we HAVE (v2):
- 129 invariants in registry, 13 categories
- hybrid_pipeline.py (prompt-based, semi-manual)
- matcher.py (pattern matching against invariant registry)
- scaffold.py (contest quickstart)
- bounty_monitor_v2.py (target discovery)
- 20 specialized agents (prompt templates)
- Foundry/Echidna/Medusa/Slither installed

What we LACK:
1. **No closed loop** — pipeline steps require manual copy-paste between LLM and tools
2. **No continuous monitoring** — monitor detects targets but doesn't auto-analyze
3. **No learning from outcomes** — no feedback from accepted/rejected reports
4. **No multi-chain** — EVM only, no Solana/Cosmos/ZK circuit analysis
5. **No economic modeling** — no prediction of payout probability
6. **No auto-PoC** — PoC generation is LLM-prompted, not autonomous
7. **No parallel execution** — one target at a time

### The Vision: HYDRA (Hybrid Detection & Response Architecture)

An always-on system that:
1. Watches every new deployment, upgrade, and bounty listing across 5+ chains
2. Automatically triages, scans, and hunts within minutes of detection
3. Generates and validates PoCs without human intervention
4. Predicts payout probability and auto-submits above threshold
5. Learns from every outcome to improve future performance

---

## ROUND 2: ARCHITECTURE — Data Flow, Components, Feedback Loops

### System Architecture (ASCII Diagram)

```
 EXTERNAL WORLD                           HYDRA CORE
 ================                         ==========

 +------------------+    +-----------------------------------------+
 | Chain Watchers   |    |          NERVE CENTER (Orchestrator)     |
 | - EVM (5 chains) |--->|                                         |
 | - Solana         |    |  Job Queue --> Scheduler --> Executor    |
 | - Cosmos/IBC     |    |       ^            |            |       |
 +------------------+    |       |            v            v       |
                         |  +----------+ +----------+ +----------+ |
 +------------------+    |  | Feedback | | Triage   | | Analysis | |
 | Bounty Monitors  |    |  | Loop     | | Engine   | | Workers  | |
 | - Immunefi API   |--->|  |          | |          | | (pool)   | |
 | - Code4rena RSS  |    |  +----^-----+ +----+-----+ +----+-----+ |
 | - Cantina API    |    |       |            |            |       |
 | - Sherlock       |    |       |            v            v       |
 +------------------+    |  +----------+ +----------+ +----------+ |
                         |  | Outcome  | | Scope    | | Hunt     | |
 +------------------+    |  | Tracker  | | Analyzer | | Agents   | |
 | Code Watchers    |    |  |          | |          | | (LLM x N)| |
 | - GitHub webhooks|--->|  +----------+ +----------+ +----------+ |
 | - GitLab         |    |       |            |            |       |
 | - Etherscan      |    |       |            v            v       |
 +------------------+    |  +----------+ +----------+ +----------+ |
                         |  | Report   | | Invariant| | Verify   | |
                         |  | Database | | Registry | | Engine   | |
                         |  | (SQLite) | | (JSON+)  | | (Fuzz+)  | |
                         |  +----------+ +----------+ +----------+ |
                         |       |            |            |       |
                         |       v            v            v       |
                         |  +-----------------------------------------+
                         |  |           SUBMISSION ENGINE              |
                         |  | - Platform adapters (Immunefi, C4, etc) |
                         |  | - Confidence gating (>50% threshold)    |
                         |  | - Human-in-loop for Criticals           |
                         |  +-----------------------------------------+
                         +-----------------------------------------+
```

### Component Breakdown

#### Layer 0: Watchers (Always On)

```
+------------------------------------------------------------------+
|                     WATCHER LAYER                                 |
|                                                                   |
|  EVM Watcher          Solana Watcher      Bounty Watcher          |
|  -----------          --------------      --------------          |
|  - New proxy deploys  - Program deploys   - New listings          |
|  - Upgrade txns       - Upgrade authority - Scope changes         |
|  - Factory creates    - IDL changes       - Payout updates        |
|  - Large fund inflows - Account changes   - Deadline alerts       |
|                                                                   |
|  Code Watcher          ZK Watcher                                 |
|  ------------          ----------                                 |
|  - GitHub push events  - Prover upgrades                          |
|  - New tags/releases   - Circuit changes                          |
|  - Audit repo diffs    - Ceremony updates                         |
|                                                                   |
|  OUTPUT: Event stream --> Job Queue                               |
+------------------------------------------------------------------+
```

**Implementation:**
- EVM: Alchemy/Infura websockets + ethers.js event filters
- Solana: Helius webhooks for program deploys
- Bounty platforms: REST API polling every 5 minutes
- Code: GitHub webhooks + GitLab webhooks
- ZK: Custom watchers per prover system

#### Layer 1: Triage Engine (< 2 minutes per target)

```
Event arrives --> Is this in scope of any active bounty?
                      |
                      YES --> Priority Score
                      |        |
                      |        score = (max_payout * freshness * complexity_inverse)
                      |        |
                      |        score > threshold? --> Queue for Analysis
                      |        score < threshold? --> Log and skip
                      |
                      NO --> Is this a high-TVL unaudited contract?
                               |
                               YES --> Check if any bounty program covers it
                               NO  --> Skip
```

**Triage Signals (weighted):**
- Bounty payout (0-40 points): $1M+ = 40, $100K+ = 30, $10K+ = 15
- Code freshness (0-25 points): <24h = 25, <1 week = 15, <1 month = 5
- Audit gap (0-20 points): no audit = 20, audit >6mo ago = 10
- Protocol type match (0-15 points): matches our strongest categories = 15

#### Layer 2: Scope Analyzer (< 5 minutes)

Runs automatically when a job is dequeued:

```
1. Clone/fetch code at specified commit
2. Language detection (Solidity, Rust, Cairo, Noir, Circom)
3. LOC count + complexity metrics
4. Architecture mapping:
   - Entry points (external/public functions)
   - Value flows (where does money move?)
   - Trust boundaries (admin vs user vs external)
   - State dependencies (which storage slots matter?)
5. Known issue collection:
   - Previous audit reports (automated download)
   - GitHub issues
   - Forum discussions
6. Exclusion list compilation
7. OUTPUT: ScopeReport JSON
```

#### Layer 3: Hunt Engine (The Core — 30-90 minutes per target)

This is where the LLM does its primary work, orchestrating multiple
analysis strategies in parallel:

```
                    ScopeReport
                        |
                        v
            +------- STRATEGY SELECTOR -------+
            |       (LLM Decision)            |
            |                                 |
            v           v           v         v
      +----------+ +----------+ +--------+ +--------+
      | Invariant| |  Diff    | | Static | | Manual |
      | Hunting  | | Analysis | | Enrich | | Hypo.  |
      | Pipeline | | Pipeline | | Pipeline | Pipeline |
      +----+-----+ +----+-----+ +----+---+ +----+---+
           |             |            |          |
           v             v            v          v
      +-------------------------------------------------+
      |          FINDING AGGREGATOR                      |
      |  - Deduplicate across strategies                 |
      |  - Merge partial findings                        |
      |  - Assign preliminary severity                   |
      +-------------------------------------------------+
                        |
                        v
              VALIDATION PIPELINE
```

**Strategy A: Invariant Hunting Pipeline (Primary)**
```
1. matcher.py --> top 20 invariants for this protocol type
2. For each invariant:
   a. LLM adapts invariant to target's specific interface
   b. Compile check (forge build)
   c. If compiles: fuzz (forge test --fuzz-runs 10000)
   d. If fails: LLM analyzes counterexample
   e. If real bug: escalate to Validation
3. LLM generates 5-10 NOVEL invariants specific to this protocol
4. Repeat steps 2a-2e for novel invariants
```

**Strategy B: Differential Analysis Pipeline**
```
1. Get git diff since last audit tag
2. LLM categorizes each change (new/modified/removed/refactored)
3. For each non-trivial change: generate 1-3 hypotheses
4. For each hypothesis: LLM traces code path, checks guards
5. Confirmed hypotheses --> Validation
```

**Strategy C: Static Analysis Enrichment**
```
1. Run Slither --> JSON output
2. LLM correlates Slither findings with invariant list
3. Filter: only findings that intersect with value flows
4. High-correlation findings --> Validation
```

**Strategy D: LLM Hypothesis Generation (Creative Hunting)**
```
1. LLM reads full source with attack mindset
2. Applies 5 proven agent templates:
   - Diff Hunter
   - Flag-Set-But-Never-Read
   - Cross-Function Consistency
   - Check-Outside-Branch
   - Spec-vs-Code
3. Generates novel hypotheses based on:
   - Cross-contract interaction patterns
   - Economic attack vectors (flash loans, sandwiches)
   - State machine violations
   - Timing/ordering dependencies
4. Each hypothesis --> Validation
```

#### Layer 4: Validation Engine (10-30 minutes per finding)

```
Finding arrives
      |
      v
+-- DEVIL'S ADVOCATE (LLM) --+
|                              |
| "Would a C4 judge REJECT    |
|  this? List all reasons."   |
|                              |
+--+---------------------------+
   |
   | Passes DA check?
   |
   YES --> PoC Generator
   |         |
   |         v
   |    +-- LLM WRITES FOUNDRY POC --+
   |    |                             |
   |    | - Fork mainnet at block N   |
   |    | - Execute attack steps      |
   |    | - Assert profit > 0         |
   |    | - Assert victim loss > 0    |
   |    +--+--+-----------------------+
   |       |  |
   |       |  | Compiles?
   |       |  YES --> forge test --fork-url $RPC -vvvv
   |       |  |         |
   |       |  |         | Passes?
   |       |  |         YES --> CONFIRMED FINDING
   |       |  |         NO  --> LLM debugs, retry (max 3)
   |       |  |
   |       |  NO --> LLM fixes, retry (max 3)
   |       |
   NO --> Discard (log reason for learning)
```

#### Layer 5: Economic Model & Submission Engine

```
Confirmed Finding
      |
      v
+-- PAYOUT PREDICTOR --+
|                       |
| Inputs:               |
| - Severity            |
| - Protocol max payout |
| - Similar past payouts|
| - PoC quality score   |
| - Known issue overlap |
| - Report clarity      |
|                       |
| Output:               |
| - P(accept) [0-1]    |
| - E(payout) [$]      |
| - Risk score          |
+--+--------------------+
   |
   | P(accept) > 0.50 AND E(payout) > $500?
   |
   YES --> Report Generator
   |         |
   |         v
   |    +-- LLM WRITES REPORT --+
   |    |  Platform-specific     |
   |    |  format (Immunefi/C4)  |
   |    +--+---------------------+
   |       |
   |       v
   |    +-- HUMAN REVIEW GATE --+
   |    |  Critical: ALWAYS     |
   |    |  High: ALWAYS         |
   |    |  Medium: if P > 0.7   |
   |    |   auto-submit         |
   |    +--+---------------------+
   |       |
   |       v
   |    Platform API Submit
   |
   NO --> Archive (may revisit if conditions change)
```

#### Layer 6: Feedback Loop (Continuous Learning)

```
+-- OUTCOME TRACKER --+
|                      |
| For every submission:|
| - Track status       |
| - Record judgment    |
| - Capture comments   |
| - Log payout amount  |
+--+-------------------+
   |
   v
+-- LEARNING ENGINE --+
|                      |
| ACCEPTED reports:    |
| - Boost invariant    |
|   hit_rate           |
| - Boost strategy     |
|   weight             |
| - Extract new        |
|   invariant patterns |
| - Add to training    |
|   examples           |
|                      |
| REJECTED reports:    |
| - Reduce hit_rate    |
| - Analyze rejection  |
|   reason             |
| - Add to exclusion   |
|   patterns           |
| - Update known issue |
|   database           |
|                      |
| METRICS DASHBOARD:   |
| - $/hour by strategy |
| - $/hour by protocol |
| - Acceptance rate    |
| - False positive rate|
+----------------------+
```

### Data Model

```
┌─────────────────────┐     ┌──────────────────────┐
│ Target              │     │ Invariant             │
│─────────────────────│     │──────────────────────│
│ id                  │     │ id                    │
│ protocol_name       │     │ category              │
│ chain               │     │ severity              │
│ bounty_platform     │     │ max_payout             │
│ scope_hash          │     │ solidity_code          │
│ loc                 │     │ natural_language       │
│ language            │     │ hit_rate (updated)     │
│ last_audit_date     │     │ times_tested           │
│ tvl                 │     │ times_found_bug        │
│ created_at          │     │ avg_payout_when_found  │
│ status              │     │ false_positive_rate    │
└────────┬────────────┘     └──────────┬───────────┘
         │ 1:N                         │ M:N
         v                             v
┌─────────────────────┐     ┌──────────────────────┐
│ Finding             │     │ Submission            │
│─────────────────────│     │──────────────────────│
│ id                  │     │ id                    │
│ target_id (FK)      │     │ finding_id (FK)       │
│ invariant_id (FK)   │     │ platform              │
│ strategy_used       │     │ submitted_at          │
│ severity            │     │ status (pending/       │
│ confidence          │     │   accepted/rejected)  │
│ poc_path            │     │ payout_amount         │
│ poc_compiles        │     │ judge_comments        │
│ poc_passes          │     │ rejection_reason      │
│ da_passed           │     │ time_to_resolution    │
│ predicted_payout    │     └──────────────────────┘
│ created_at          │
└─────────────────────┘

┌─────────────────────┐
│ Strategy_Stats      │
│─────────────────────│
│ strategy_name       │
│ targets_scanned     │
│ findings_generated  │
│ findings_confirmed  │
│ submissions_made    │
│ submissions_accepted│
│ total_payout        │
│ avg_time_per_target │
│ roi_per_hour        │
└─────────────────────┘
```

---

## ROUND 3: FEASIBILITY — What's Buildable Now vs 6 Months vs Never

### Tier 1: Buildable NOW (Weeks 1-4)

| Component | Effort | Dependencies | Status |
|-----------|--------|-------------|--------|
| Closed-loop pipeline (no copy-paste) | 1 week | Claude API key | **Not started** |
| SQLite outcome tracker | 2 days | None | **Not started** |
| Auto-PoC compile+test loop | 3 days | Foundry (installed) | **Not started** |
| Devil's advocate auto-validation | 2 days | Claude API | **Not started** |
| Payout predictor (rule-based v1) | 2 days | Historical data | **Not started** |
| Enhanced bounty monitor (5 platforms) | 3 days | API keys | **Partial (v2 exists)** |
| Invariant registry feedback updater | 1 day | SQLite tracker | **Not started** |
| Dashboard (CLI-based) | 2 days | SQLite | **Not started** |

**Key enabler:** Replace the current prompt-template approach in hybrid_pipeline.py
with actual Claude API calls. The current system generates .md files for manual
copy-paste. The v3 system calls the API directly and pipes outputs between steps.

### Tier 2: Buildable in 1-3 Months

| Component | Effort | Dependencies | Blockers |
|-----------|--------|-------------|----------|
| EVM chain watcher (new deploys) | 2 weeks | Alchemy API | API costs |
| GitHub webhook integration | 1 week | Server/VPS | Hosting |
| Solana program analyzer | 3 weeks | Anchor/native parser | Language support |
| Multi-target parallel execution | 2 weeks | Job queue system | Compute budget |
| ML payout predictor | 2 weeks | 50+ labeled outcomes | Data collection |
| Auto-submission (Immunefi API) | 1 week | API access | Platform approval |
| Report template learner | 2 weeks | 20+ winning reports | Data collection |

**Key enabler:** A VPS or cloud instance running 24/7 with the watcher layer.
Current system runs on local Windows machine only during active sessions.

### Tier 3: Buildable in 3-6 Months

| Component | Effort | Dependencies | Blockers |
|-----------|--------|-------------|----------|
| CosmWasm analyzer | 4 weeks | Rust parser | CosmWasm expertise |
| ZK circuit analyzer | 6 weeks | Circom/Noir parsers | Deep ZK knowledge |
| Cross-chain interaction analyzer | 4 weeks | Multi-chain state | Bridge complexity |
| Self-improving invariant generator | 4 weeks | Large outcome dataset | Need 100+ outcomes |
| Economic attack simulator | 3 weeks | DeFi state modeling | Flash loan modeling |
| Full auto-submission pipeline | 2 weeks | All platform APIs | Trust/reputation |

### Tier 4: Aspirational / Research

| Component | Why Hard | Possible Path |
|-----------|----------|---------------|
| Fully autonomous Critical finding | LLMs hallucinate novel attacks | Constrain to known patterns + fuzzing confirmation |
| Zero-day discovery in novel math | Requires deep mathematical reasoning | Hybrid: LLM hypothesizes, symbolic prover validates |
| Cross-protocol composability bugs | State space explosion | Focus on top-10 DeFi composability pairs |
| Real-time MEV-style exploitation | Latency requirements | Not a bounty use case, different system |

### Honest Assessment of LLM Limitations

**LLMs are GOOD at:**
- Pattern recognition (matching known vuln patterns to new code)
- Report writing (formatting, clarity, persuasion)
- Hypothesis generation (creative "what if" scenarios)
- Code translation (invariant -> Foundry test)
- Triage (quickly assessing relevance/severity)

**LLMs are BAD at:**
- Novel mathematical proofs (can't discover new math bugs)
- Precise state tracking across 10+ contract calls
- Distinguishing 1-wei rounding from exploitable precision loss
- Understanding complex economic equilibria
- Reliable compilation (often generates code that doesn't compile)

**Implication for architecture:**
- LLM = hypothesis generator + report writer
- Formal tools (Foundry/Echidna/Certora) = ground truth verifiers
- NEVER trust an LLM finding without tool confirmation
- The auto-compile-and-retry loop is the single most important component

---

## ROUND 4: ROADMAP — Specific Build Plan for Next 4 Weeks

### Week 1: Close the Loop (The Most Important Week)

**Goal:** Eliminate all manual copy-paste. One command triggers full pipeline.

**Day 1-2: API-Driven Pipeline Core**
```
File: audit-agents/pipeline_v3.py

class PipelineV3:
    def __init__(self, api_key, target_dir, domain):
        self.llm = ClaudeClient(api_key)
        self.foundry = FoundryRunner(target_dir)
        self.slither = SlitherRunner(target_dir)
        self.registry = InvariantRegistry()
        self.db = OutcomeDB("hydra.db")

    async def run(self):
        scope = await self.analyze_scope()
        invariants = await self.extract_invariants(scope)
        matched = self.registry.match(scope)
        all_invariants = merge(invariants, matched)
        tests = await self.generate_tests(all_invariants)
        compiled = await self.compile_loop(tests, max_retries=3)
        fuzz_results = await self.fuzz(compiled)
        findings = await self.analyze_results(fuzz_results)
        validated = await self.validate(findings)  # devil's advocate
        pocs = await self.generate_pocs(validated, max_retries=3)
        reports = await self.generate_reports(pocs)
        return reports
```

**Day 3: Auto-Compile Retry Loop**
```
File: audit-agents/compile_loop.py

async def compile_with_retry(llm, test_code, source_code, max_retries=3):
    for attempt in range(max_retries):
        result = foundry.compile(test_code)
        if result.success:
            return test_code
        # Feed error back to LLM
        test_code = await llm.fix_compilation(
            test_code, result.errors, source_code
        )
    return None  # Give up after max retries
```

**Day 4: Outcome Database**
```
File: audit-agents/outcome_db.py

Schema:
- targets (id, name, chain, platform, max_payout, scope_hash)
- findings (id, target_id, invariant_id, strategy, severity, confidence)
- submissions (id, finding_id, platform, status, payout, judge_comments)
- invariant_stats (invariant_id, times_tested, times_found, hit_rate)
- strategy_stats (strategy, targets_scanned, findings, accepted, payout)
```

**Day 5: Integration Test**
- Run full pipeline against a known-vulnerable contract (from DeFiHackLabs)
- Verify it finds the bug, generates PoC, writes report
- Measure: time to finding, compilation success rate, PoC pass rate

### Week 2: Validation & Monitoring

**Day 1-2: Devil's Advocate Automation**
```
File: audit-agents/validator.py

class DevilsAdvocate:
    REJECTION_CHECKS = [
        "Does this require admin/governance action?",
        "Is this a known issue in any previous audit?",
        "Is this a design choice documented in the code?",
        "Does the PoC use unrealistic parameters?",
        "Is the impact < $100 in practice?",
        "Is this a duplicate of another finding?",
        "Does this only affect the attacker themselves?",
    ]

    async def validate(self, finding, known_issues, exclusions):
        for check in self.REJECTION_CHECKS:
            result = await self.llm.evaluate(finding, check)
            if result.fails:
                return Rejected(reason=check)
        return Validated()
```

**Day 3-4: Enhanced Monitor**
```
File: audit-agents/monitor_v3.py

- Poll Immunefi, Code4rena, Cantina, Sherlock, Hats every 5 min
- On new listing: auto-triage (score + queue)
- On scope change: re-triage existing target
- On deadline <48h: boost priority
- Output: JSON event stream to job queue
```

**Day 5: Payout Predictor v1 (Rule-Based)**
```
File: audit-agents/predictor.py

def predict_payout(finding, target):
    base = {
        "critical": 0.4, "high": 0.25,
        "medium": 0.15, "low": 0.05
    }[finding.severity]

    # Adjustments
    if finding.poc_passes: base += 0.15
    if finding.da_passed: base += 0.10
    if finding.is_known_pattern: base -= 0.10
    if target.has_previous_audit: base -= 0.05
    if target.max_payout > 100000: base += 0.05

    expected = base * target.max_payout * severity_fraction(finding.severity)
    return PredictionResult(p_accept=base, expected_payout=expected)
```

### Week 3: Scale & Parallel Execution

**Day 1-2: Job Queue + Worker Pool**
```
File: audit-agents/scheduler.py

class HydraScheduler:
    def __init__(self, max_workers=4):
        self.queue = PriorityQueue()
        self.workers = [PipelineV3Worker() for _ in range(max_workers)]

    async def run(self):
        while True:
            job = await self.queue.get()
            worker = await self.get_free_worker()
            asyncio.create_task(worker.process(job))
```

**Day 3-4: Invariant Registry Feedback Loop**
```
File: audit-agents/feedback.py

class FeedbackLoop:
    def on_submission_resolved(self, submission):
        inv = self.registry.get(submission.finding.invariant_id)
        if submission.status == "accepted":
            inv.times_found_bug += 1
            inv.hit_rate = inv.times_found_bug / inv.times_tested
            inv.avg_payout = rolling_avg(inv.avg_payout, submission.payout)
            # Extract new pattern if novel
            if submission.finding.strategy == "hypothesis":
                self.registry.add_new_invariant_from_finding(submission)
        elif submission.status == "rejected":
            inv.false_positive_count += 1
            self.exclusion_db.add(submission.rejection_reason)
```

**Day 5: Multi-Strategy Orchestration**
```
File: audit-agents/strategy_selector.py

Run all 4 strategies in parallel per target:
- Invariant hunting (invariant registry + LLM-generated)
- Diff analysis (if audit tag available)
- Static enrichment (Slither correlation)
- LLM hypothesis (5 proven templates)

Deduplicate findings across strategies.
Allocate time budget: 60% invariant, 15% diff, 10% static, 15% hypothesis.
```

### Week 4: Dashboard, Reporting, Polish

**Day 1-2: CLI Dashboard**
```
File: audit-agents/dashboard.py

$ python dashboard.py

HYDRA STATUS (2026-04-15)
========================
Active targets:     12
Queue depth:         7
Running analyses:    3

LAST 30 DAYS:
Targets scanned:    47
Findings generated: 23
PoCs confirmed:     11
Reports submitted:   8
Accepted:            3
Total payout:    $42,500

TOP STRATEGIES:
Invariant hunting:  $28,000  (6.2 findings/target)
Diff analysis:      $10,000  (2.1 findings/target)
LLM hypothesis:      $4,500  (0.8 findings/target)

TOP INVARIANT CATEGORIES:
vault/erc4626:     hit_rate=0.23  avg_payout=$8,500
lending/liquidation: hit_rate=0.18  avg_payout=$12,000
universal/conservation: hit_rate=0.15  avg_payout=$5,000
```

**Day 3: Report Template Optimization**
- Analyze all accepted reports: what made them win?
- Analyze all rejected reports: what got them rejected?
- Encode patterns into report generation prompts

**Day 4: End-to-End Stress Test**
- Run against 5 active bounty targets simultaneously
- Measure: throughput, finding quality, false positive rate
- Identify bottlenecks (likely: LLM API rate limits, compilation time)

**Day 5: Documentation + Deployment**
- Document all components
- Set up cron/systemd for monitor
- Configure alert system (Telegram/Discord for findings)

---

## Key Metrics to Track

| Metric | Target Month 1 | Target Month 3 |
|--------|----------------|----------------|
| Targets scanned/month | 30 | 80 |
| Findings per target | 0.3 | 0.5 |
| PoC compilation rate | 40% | 70% |
| PoC pass rate (of compiled) | 50% | 65% |
| DA pass rate | 60% | 75% |
| Submission acceptance rate | 30% | 55% |
| Avg time per target | 90 min | 45 min |
| Revenue/month | $20-40K | $80-120K |
| $/hour of compute | $50 | $200 |

## Cost Model (Monthly)

| Resource | Cost |
|----------|------|
| Claude API (Opus, ~2M tokens/target x 50 targets) | $3,000-5,000 |
| RPC providers (Alchemy/Infura, multiple chains) | $500-1,000 |
| VPS (8-core, 32GB RAM, always-on) | $200-400 |
| Bounty platform deposits (where required) | $500-1,000 |
| **Total** | **$4,200-7,400** |

At $40K/month revenue, ROI = 5-10x. At $100K/month, ROI = 13-24x.

## Critical Success Factors

1. **Compile loop reliability** — If PoCs don't compile, the system produces nothing.
   This is the #1 technical risk. Mitigate with few-shot examples per protocol type.

2. **False positive rate** — If >50% of submissions are rejected, platforms may
   throttle or ban. Mitigate with devil's advocate + historical pattern matching.

3. **Freshness advantage** — The system's edge is SPEED. Being first to analyze
   new code is worth 10x more than being thorough on old code. Optimize for
   time-to-first-finding, not exhaustive coverage.

4. **Invariant quality** — The registry is the moat. Every confirmed finding
   should generate 2-3 new invariants. Target 500 invariants by month 3.

5. **Human-in-loop for Criticals** — Never auto-submit Criticals. The reputational
   cost of a bad Critical submission is enormous. Always human-review.

## What This System Does NOT Do

- Real-time MEV extraction (different domain, different latency requirements)
- Smart contract development or auditing-as-a-service
- Compete with manual auditors on depth (we compete on breadth + speed)
- Find bugs requiring deep protocol-specific domain knowledge on first pass
  (but the learning loop should develop this over time)
- Replace human judgment for novel attack vectors (LLM generates, human validates)

---

## Summary: From Current State to $100K/Month

```
CURRENT (March 2026)              TARGET (July 2026)
====================              ==================

Manual copy-paste       -->       Closed-loop API pipeline
1 target at a time      -->       4 parallel workers
No outcome tracking     -->       SQLite + feedback loop
129 invariants          -->       500+ invariants
EVM only               -->        EVM + Solana (basic)
Semi-manual PoC        -->        Auto-compile-retry loop
No payout prediction   -->        ML predictor (50+ data points)
Session-based          -->        Always-on monitoring
0 auto-submissions     -->        Mediums auto-submitted
$0/month               -->        $80-120K/month
```

The single most impactful change: **close the loop**. Replace prompt templates
with API calls. Everything else builds on that foundation.
