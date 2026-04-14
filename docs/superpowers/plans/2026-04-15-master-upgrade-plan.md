# Audit-Agents Master Upgrade Plan — v9 → v10

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolucionar el sistema de audit agents desde v9 (94% detección, 41% PoC) a v10 (95%+ detección, 70% PoC, 40% menos noise) mediante mejoras incrementales validadas contra benchmark.

**Architecture:** 7 fases. Fases 1-3 ya completadas (knowledge base + recon + council). Fases 4-7 son nuevas mejoras priorizadas por impacto medible contra el benchmark Yieldoor (17 findings ground truth).

**Tech Stack:** Python 3, Claude Code Agent tool, Foundry, sentence-transformers, Obsidian vault, YAML/JSON

**Benchmark v9 baseline:**
- Detection recall: 94.1% (16/17, 100% HIGH)
- PoC-confirmed recall: 41.2% (7/17)
- Hypotheses: 383 across 13 hunters
- FP rate: ~40% (TrustBoundary 55%, MathHunter 63%)
- Time per component: ~90 min (12 hunters parallel)

---

## Phase 1: Obsidian-Wiki — Persistent Knowledge Base [COMPLETADA]

### Task 1: Install + initialize Obsidian vault [DONE]

- [x] Vault at `~/obsidian-vault/web3-audit/` — 101 pages, 801 wikilinks
- [x] 4 categories: concepts (71), references (9), synthesis (3), projects (16)
- [x] `.manifest.json` for delta tracking
- [x] Raw sources fully ingested (0 pending)

### Task 2: Hook apply_feedback.py for auto-ingest [DONE]

- [x] `wiki_ingest_finding()` copies validated findings (confidence >= 60%) to vault `_raw/`
- [x] Auto-staging on component completion

### Task 3: Hook run_hunt.py to query vault [DONE]

- [x] `query_wiki_context()` searches vault recursively (`**/*.md`)
- [x] Uses `summary:` frontmatter for token efficiency (not raw text)
- [x] Max 8 results × ~100 tokens = ~800-1200 tokens injected per hunter (~3-4% of prompt)
- [x] Excludes `_raw/`, `_archives/`, `.obsidian/`, `projects/`

---

## Phase 2: Graphify — Structural Recon [COMPLETADA]

### Task 4: Install + configure Graphify [DONE]

- [x] `pip install graphifyy --break-system-packages`
- [x] `.graphifyignore` at repo root
- [x] Skill at `~/.claude/skills/graphify/SKILL.md`

### Task 5: Hook scope_intake.py for auto-recon [DONE]

- [x] `run_graphify_recon()` runs on `scope_intake.py --repo`
- [x] Output: `hunt_session/graph/{protocol}/GRAPH_REPORT.md`
- [x] Timeout: 5 min, graceful degradation if not installed

### Task 6: Feed graph report to hunter context [DONE]

- [x] `load_graph_report()` injects truncated GRAPH_REPORT (max 3000 chars)
- [x] Injected into `generate_hunter_prompt()` alongside wiki context

---

## Phase 3: Enhanced Council — Karpathy Pattern [COMPLETADA]

### Task 7: Council v2 skill [DONE]

- [x] 3-stage pattern: independent → anonymous cross-review → chairman synthesis
- [x] 3 modes: DEBATE, QUICK, FINDING
- [x] Agent-A..E anonymous labels in Stage 2
- [x] Prepared for multi-model future

### Task 8: RedTeam pre-screening with Council [DONE]

- [x] Added PRE-SCREENING section to redteam.md
- [x] Council FINDING mode as optional pre-filter

### Task 9: CLAUDE.md + memory updates [DONE]

- [x] Skills table updated with `/council`, `/wiki-query`, `/wiki-ingest`, `/graphify`
- [x] Memory file `project_knowledge_tools.md` created

---

## Phase 4: Quick Wins — Integration Glue [COMPLETADA]

### Task 10: Auto-mark gates from pipeline steps

**Files:**
- Modify: `audit-agents/run_hunt.py` (post-hunter gate marking)
- Modify: `audit-agents/merge_invariants.py` (post-merge gate marking)

**Problem:** Skills producen output pero no llaman `pipeline_gate.py --mark`, dejando gates en "pending" permanentemente.

- [ ] **Step 1: Add gate auto-marking after hunter completion**

In `run_hunt.py`, after the parallel hunter batch completes (Agent tool returns), add:

```python
import subprocess

def mark_gate(component: str, gate: str):
    """Mark a pipeline gate as completed."""
    subprocess.run([
        "python3", str(Path(__file__).parent / "pipeline_gate.py"),
        "-c", component, "--mark", gate
    ], check=False)
```

Call after each phase:
- `mark_gate(component, "hunters")` — after 12 parallel hunters
- `mark_gate(component, "crosschain")` — after CrossChainHunter or .skip
- `mark_gate(component, "deepdive")` — after DeepDiveHunter

- [ ] **Step 2: Add gate marking to merge_invariants.py**

At the end of successful merge:

```python
import subprocess
subprocess.run([
    "python3", str(Path(__file__).parent / "pipeline_gate.py"),
    "-c", component, "--mark", "merge"
], check=False)
```

- [ ] **Step 3: Test gate auto-marking**

Run: `python3 audit-agents/pipeline_gate.py -c Strategy --status`
Expected: gates show timestamps after each phase completes

- [ ] **Step 4: Commit**

```bash
git add audit-agents/run_hunt.py audit-agents/merge_invariants.py
git commit -m "feat: auto-mark pipeline gates after each phase"
```

---

### Task 11: Inject rejection rules into hunter prompts

**Files:**
- Modify: `audit-agents/run_hunt.py` (función `generate_hunter_prompt`)

**Problem:** `rejection_rules.yaml` existe con 15 rejections analizadas pero hunters nunca lo ven, repitiendo patrones rechazados.

- [ ] **Step 1: Add rejection context loader**

```python
def load_rejection_context() -> str:
    """Load rejection rules as anti-patterns for hunters."""
    rules_path = HUNT_SESSION_DIR / "feedback" / "rejection_rules.yaml"
    if not rules_path.exists():
        return ""
    try:
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        if not rules:
            return ""
        lines = ["\n## Anti-Patterns (Rechazados en plataformas reales -- NO reportar estos)"]
        for rule in rules.get("rules", []):
            lines.append(f"- **{rule.get('id', '?')}**: {rule.get('description', '')}")
            if rule.get('example'):
                lines.append(f"  Ejemplo: {rule['example']}")
        return "\n".join(lines)
    except Exception:
        return ""
```

- [ ] **Step 2: Inject into generate_hunter_prompt()**

Add `{rejection_ctx}` in the prompt template, just before `## Tu Proceso`:

```python
rejection_ctx = load_rejection_context()
```

- [ ] **Step 3: Commit**

```bash
git add audit-agents/run_hunt.py
git commit -m "feat: inject rejection rules into hunter prompts as anti-patterns"
```

---

### Task 12: YAML validation post-hunter

**Files:**
- Modify: `audit-agents/merge_invariants.py` (add schema validation before merge)

**Problem:** Hunters producen `solidity:` malformado que rompe merge silenciosamente.

- [ ] **Step 1: Add YAML schema validator**

```python
REQUIRED_FIELDS = {"id", "description", "solidity"}

def validate_hypothesis(hyp: dict, source_file: str) -> list[str]:
    """Validate a single hypothesis. Returns list of warnings."""
    warnings = []
    for field in REQUIRED_FIELDS:
        if field not in hyp or not hyp[field]:
            warnings.append(f"  {source_file}: {hyp.get('id', '?')} missing '{field}'")
    sol = hyp.get("solidity", "")
    if sol and not any(kw in sol for kw in ["t(", "eq(", "gte(", "lte(", "assert", "require"]):
        warnings.append(f"  {source_file}: {hyp.get('id', '?')} solidity has no assertion")
    return warnings
```

- [ ] **Step 2: Skip invalid hypotheses with warning instead of crashing**

Before merging each hypothesis, call `validate_hypothesis()`. If missing `solidity`, skip with warning log.

- [ ] **Step 3: Commit**

```bash
git add audit-agents/merge_invariants.py
git commit -m "feat: validate hypothesis YAML schema before merge"
```

---

### Task 13: Dev session auto-capture

**Files:**
- Create: `.claude/hooks/session-end.sh`

**Problem:** Sesiones de desarrollo no dejan rastro automático. Mañana no sabemos qué archivos se editaron ni qué decisiones se tomaron.

- [ ] **Step 1: Create session-end hook**

```bash
#!/bin/bash
MEMORY_DIR="$HOME/.claude/projects/-home-kali-Documents-Web3/memory"
SESSION_LOG="$MEMORY_DIR/dev_sessions.md"
DATE=$(date +"%Y-%m-%d %H:%M")

RECENT_COMMITS=$(cd /home/kali/Documents/Web3 && git log --oneline -5 --since="8 hours ago" 2>/dev/null)
CHANGED_FILES=$(cd /home/kali/Documents/Web3 && git diff --name-only HEAD~3 2>/dev/null | head -15)

if [ -n "$RECENT_COMMITS" ] || [ -n "$CHANGED_FILES" ]; then
    {
        echo ""
        echo "## $DATE"
        [ -n "$RECENT_COMMITS" ] && echo "### Commits" && echo "$RECENT_COMMITS"
        [ -n "$CHANGED_FILES" ] && echo "### Files changed" && echo "$CHANGED_FILES"
        echo "---"
    } >> "$SESSION_LOG"
fi
```

- [ ] **Step 2: Make executable and register**

```bash
chmod +x .claude/hooks/session-end.sh
```

- [ ] **Step 3: Commit**

```bash
git add .claude/hooks/session-end.sh
git commit -m "feat: auto-capture dev session summaries on session end"
```

---

### Task 14: verify_team_outputs obligatorio

**Files:**
- Modify: `audit-agents/run_benchmark.py`

**Problem:** Agentes pueden falsamente reportar completado. `verify_team_outputs.py` existe pero no se ejecuta por defecto.

- [ ] **Step 1: Add mandatory verification after hunter phase**

After all hunters complete and gate `hunters` is marked:

```python
verify_result = subprocess.run([
    "python3", "audit-agents/verify_team_outputs.py",
    "--session-dir", str(session_dir),
    "--protocol", protocol,
    "--groups", group_id
], capture_output=True, text=True)

if verify_result.returncode != 0:
    print(f"[HALT] Team verification failed:\n{verify_result.stdout}")
    print("Fix missing outputs before continuing.")
    sys.exit(1)
```

- [ ] **Step 2: Commit**

```bash
git add audit-agents/run_benchmark.py
git commit -m "feat: mandatory team output verification after hunter phase"
```

---

## Phase 5: PoC Conversion + Conditional Hunters [COMPLETADA]

### Task 15: Iterative PoC Repair Loop

**Files:**
- Modify: `audit-agents/poc_generator.py` (add iterative repair)
- Create: `audit-agents/poc_templates/` (per-category templates)

**Problem:** PoC conversion rate is 41% (7/17). Research shows iterative repair doubles it:
- A1 (arxiv 2507.05558): 32% → 63% with repair loop
- SPEAR (arxiv 2602.04418): 94% with Programmatic-First Iterative Repair
- PoCo (arxiv 2511.02780): PoC from natural language descriptions

**Root cause of the 8 missed PoCs:**
- 4/8 require complex deployment setup (pools, tokens, oracles)
- 2/8 require temporal advancement (vm.warp)
- 2/8 require specific prior state (multi-hop paths, specific decimals)

- [ ] **Step 1: Create PoC template library**

```
audit-agents/poc_templates/
  base_defi_setup.sol      -- Deploy pool + tokens + oracle + initial liquidity
  liquidation_setup.sol    -- Open position + advance price + attempt liquidation
  oracle_manipulation.sol  -- Slot0 manipulation + TWAP bypass
  token_decimals.sol       -- Deploy tokens with specific decimals (6, 8, 18)
  time_advance.sol         -- vm.warp + vm.roll patterns
  multi_hop.sol            -- Multi-token swap path setup
```

Each template: parametrizable Foundry `setUp()` fragment with `{PLACEHOLDER}` variables.

- [ ] **Step 2: Implement iterative repair loop**

```python
MAX_REPAIR_ATTEMPTS = 5

def generate_poc_with_repair(hypothesis: dict, contract_source: str,
                              templates: list[str]) -> tuple[bool, str]:
    """Generate PoC with iterative repair loop.
    1. Generate initial PoC (with relevant template)
    2. Compile -- if fails, feed error to LLM for repair
    3. Execute -- if fails, feed revert reason to LLM for repair
    4. Repeat up to MAX_REPAIR_ATTEMPTS
    """
    template = select_template(hypothesis.get("category", ""), templates)
    poc_code = initial_generation(hypothesis, contract_source, template)

    for attempt in range(MAX_REPAIR_ATTEMPTS):
        compile_result = run_forge_build(poc_code)
        if not compile_result.success:
            poc_code = repair_compilation(poc_code, compile_result.errors, hypothesis)
            continue

        exec_result = run_forge_test(poc_code)
        if exec_result.success:
            return True, poc_code

        poc_code = repair_execution(poc_code, exec_result.revert_reason,
                                     exec_result.trace, hypothesis)

    return False, poc_code
```

- [ ] **Step 3: Implement repair_compilation helper**

Feed compilation errors to LLM with instruction: "Fix ONLY the compilation errors. Do not change test logic."

- [ ] **Step 4: Implement repair_execution helper**

Feed revert reason + trace to LLM with common fix hints:
- Missing `vm.deal()` for balances
- Missing token `approve()`
- Wrong function call order
- Need `vm.warp()` for time-dependent logic
- Need `vm.prank()` for caller identity

- [ ] **Step 5: Implement template selection**

```python
CATEGORY_TEMPLATES = {
    "accounting": ["base_defi_setup.sol", "token_decimals.sol"],
    "oracle": ["base_defi_setup.sol", "oracle_manipulation.sol"],
    "dos": ["base_defi_setup.sol"],
    "logic": ["base_defi_setup.sol"],
    "rounding": ["base_defi_setup.sol", "token_decimals.sol"],
    "liquidation": ["base_defi_setup.sol", "liquidation_setup.sol"],
}
```

- [ ] **Step 6: Test on a known-failing PoC from v9**

Take H-01 (liquidation decimal handling) — was detected but PoC failed.
Run: `python3 audit-agents/poc_generator.py --hypothesis <path> --repair`
Expected: PoC compiles and demonstrates the bug within 5 attempts

- [ ] **Step 7: Commit**

```bash
git add audit-agents/poc_generator.py audit-agents/poc_templates/
git commit -m "feat: iterative PoC repair loop with template library (A1/SPEAR pattern)"
```

---

### Task 16: Conditional Hunter Selection (3-Tier System)

**Files:**
- Create: `audit-agents/hunter_profiles.yaml` (hunter -> protocol-type mapping)
- Modify: `audit-agents/run_hunt.py` (hunter selection logic)

**Problem:** 12 hunters corren en todos los componentes. TrustBoundaryHunter tiene 55% validation en Yieldoor (noise). Solución: 3-tier system basado en triggers de código + tipo de protocolo.

**Strategy validated by v9 data:**
- Tier 0 (ALWAYS, 5 hunters): Access(96%), Domain(77%), Math(63%), Flow(93%), Adversarial(84%)
- Tier 1 (CONDITIONAL): Oracle, DoS, Signature, TrustBoundary, Logic, Library, Wildcard — selected by code pattern triggers
- Tier 2 (SPECIALIZED, future): Governance, Liquidation, MEV, Yield, TTL
- Sequential (ALWAYS): CrossChain (if multi-chain) + DeepDive

Expected: 7-8 hunters instead of 12 → ~40% less noise, ~35% faster

- [ ] **Step 1: Create hunter_profiles.yaml**

```yaml
tier0:
  - AccessHunter
  - DomainHunter
  - MathHunter
  - FlowHunter
  - AdversarialHunter

tier1:
  OracleHunter:
    triggers: ["latestRoundData", "slot0", "sqrtPriceX96", "getReserves",
               "observe", "consult", "getPrice", "oracle", "twap", "priceFeed"]
    protocol_types: ["dex", "lending", "vault", "derivatives"]
  DoSHunter:
    triggers: ["for (", "while (", ".length", "push(", "observationCardinality"]
    protocol_types: ["*"]
  SignatureHunter:
    triggers: ["ecrecover", "ECDSA", "permit", "EIP712", "nonce",
               "deadline", "signature", "v, r, s"]
    protocol_types: ["*"]
  TrustBoundaryHunter:
    triggers: ["safeTransfer", "IERC20", "transferFrom", "delegatecall", "proxy"]
    protocol_types: ["vault", "bridge", "lending"]
  LogicHunter:
    triggers: []
    min_loc: 500
    protocol_types: ["*"]
  LibraryHunter:
    triggers: ["import", "using", "library"]
    protocol_types: ["*"]
  WildcardHunter:
    triggers: ["assembly", "delegatecall", "create2", "selfdestruct", "abi.encodePacked"]
    protocol_types: ["*"]

sequential:
  - CrossChainHunter
  - DeepDiveHunter

protocol_type_signals:
  lending: ["borrow", "repay", "liquidat", "collateral", "healthFactor"]
  dex: ["swap", "addLiquidity", "removeLiquidity", "getAmountOut", "router"]
  vault: ["deposit", "withdraw", "totalAssets", "convertToShares", "ERC4626"]
  staking: ["stake", "unstake", "reward", "epoch", "rewardRate"]
  bridge: ["bridge", "relay", "message", "crossChain", "lzReceive"]
  governance: ["vote", "proposal", "delegate", "quorum", "governor"]
  derivatives: ["perpetual", "margin", "funding", "settlement", "option"]
```

- [ ] **Step 2: Implement select_hunters() function**

```python
def select_hunters(contract_source: str, protocol_type: str = None,
                   profiles_path: str = "audit-agents/hunter_profiles.yaml") -> list[str]:
    """Select hunters based on code features and protocol type.
    Tier 0 always. Tier 1 if triggers match. Returns ordered list."""
    with open(profiles_path) as f:
        profiles = yaml.safe_load(f)

    source_lower = contract_source.lower()
    selected = list(profiles.get("tier0", []))

    if not protocol_type:
        protocol_type = detect_protocol_type(source_lower, profiles)

    for hunter, config in profiles.get("tier1", {}).items():
        triggers = config.get("triggers", [])
        ptypes = config.get("protocol_types", ["*"])
        min_loc = config.get("min_loc", 0)

        if "*" not in ptypes and protocol_type not in ptypes:
            continue
        if triggers and any(t.lower() in source_lower for t in triggers):
            selected.append(hunter)
            continue
        if min_loc and source_lower.count("\n") >= min_loc:
            selected.append(hunter)

    return list(dict.fromkeys(selected))  # deduplicate preserving order


def detect_protocol_type(source_lower: str, profiles: dict) -> str:
    """Auto-detect protocol type from source code."""
    scores = {}
    for ptype, keywords in profiles.get("protocol_type_signals", {}).items():
        score = sum(1 for kw in keywords if kw.lower() in source_lower)
        if score > 0:
            scores[ptype] = score
    return max(scores, key=scores.get) if scores else "unknown"
```

- [ ] **Step 3: Replace hardcoded hunter list in run_hunt.py**

```python
contract_source = Path(contract_path).read_text()
hunters = select_hunters(contract_source, protocol_type)
print(f"[hunt] Protocol type: {detect_protocol_type(contract_source.lower(), profiles)}")
print(f"[hunt] Selected {len(hunters)}/{len(ALL_HUNTERS)} hunters: {hunters}")
```

- [ ] **Step 4: Add --all-hunters override flag**

```python
parser.add_argument("--all-hunters", action="store_true",
                    help="Launch all 12 hunters regardless of protocol type")
```

- [ ] **Step 5: Test on Yieldoor Strategy.sol**

Expected: ~7-8 hunters selected (Tier 0 + Oracle + DoS + maybe Wildcard)

- [ ] **Step 6: Commit**

```bash
git add audit-agents/run_hunt.py audit-agents/hunter_profiles.yaml
git commit -m "feat: 3-tier conditional hunter selection by protocol type"
```

---

## Phase 6: RAG + Few-Shot + DeFi Templates [COMPLETADA]

### Task 17: Few-shot examples from confirmed findings

**Files:**
- Create: `audit-agents/few_shot_examples/` (per-category YAML bank)
- Modify: `audit-agents/run_hunt.py` (inject examples into prompts)

**Problem:** Hunters go zero-shot. SmartGuard: F1 94.95% with few-shot+CoT vs ~60% zero-shot. Research shows few-shot with real bugs consistently outperforms zero-shot.

- [ ] **Step 1: Create example bank**

```
audit-agents/few_shot_examples/
  accounting.yaml   -- 3 examples (H-01 decimal, M-02 stale rate, M-07 excess withdrawal)
  oracle.yaml       -- 3 examples (H-02 slot0 tick, M-04 uninitialized obs, M-05 short window)
  logic.yaml        -- 3 examples (H-06 wrong tick, M-09 copy-paste, H-05 contradiction)
  dos.yaml          -- 3 examples (H-03 overflow, M-10 infinite loop, observation DoS)
  rounding.yaml     -- 3 examples (M-01 overflow, M-08 WBTC precision, M-06 negative modulo)
  access.yaml       -- 3 examples (H-07 uninitialized, changePositionWidth no modifier)
```

Each example:
```yaml
examples:
  - id: "ex-logic-01"
    title: "Wrong tick parameter in collectFees"
    source: "Yieldoor H-06 (Sherlock 2025)"
    vulnerable_code: |
      pool.collect(address(this), mainPosition.tickLower,
                   mainPosition.tickUpper, ...)  // Should be vestPosition.tickUpper
    explanation: |
      After rebalance, main ticks diverge from vesting ticks.
      When vestPosition.tickLower > mainPosition.tickUpper, collect() reverts.
    invariant: "vestPosition ticks must be used when collecting vesting fees"
```

- [ ] **Step 2: Build 18+ examples from confirmed findings + public CVEs**

Sources: our 17 Yieldoor findings, LayerZero TTL findings, 5+ public CVEs from Solodit.

- [ ] **Step 3: Implement few-shot loader**

```python
def load_few_shot_examples(hunter_domain: str) -> str:
    """Load 2-3 relevant examples for this hunter's domain."""
    domain_categories = {
        "math": ["rounding", "accounting"], "access": ["access"],
        "flow": ["accounting", "logic"], "oracle": ["oracle"],
        "domain": ["logic", "accounting"], "dos": ["dos"],
        "logic": ["logic"], "adversarial": ["accounting", "oracle", "logic"],
        # ...
    }
    cats = domain_categories.get(hunter_domain, ["logic"])
    # Load up to 3 examples total from relevant categories
    # Return formatted markdown section
```

- [ ] **Step 4: Inject into hunter prompt template**

Add `{few_shot_ctx}` before `## Tu Proceso` section.

- [ ] **Step 5: Commit**

```bash
git add audit-agents/few_shot_examples/ audit-agents/run_hunt.py
git commit -m "feat: few-shot examples from confirmed findings in hunter prompts"
```

---

### Task 18: PromFuzz DeFi checker templates

**Files:**
- Modify: `audit-agents/merge_invariants.py`

**Problem:** Our invariants are generic. PromFuzz achieved 0 FP with 6 DeFi-specific checker templates.

- [ ] **Step 1: Implement 6 checker templates**

Templates: PriceChange, ExchangeRate, TokenChange (conservation), StatementOrder (CEI), ShareSafety (inflation), StateChange (unauthorized mutation).

Each template is a parametrizable Chimera assertion function.

- [ ] **Step 2: Auto-detect applicable templates per component**

Scan source for keywords: `getPrice` → PriceChange, `convertToShares` → ExchangeRate+ShareSafety, `transfer` → TokenChange, `.call(` → StatementOrder, `onlyOwner` → StateChange.

- [ ] **Step 3: Append applicable templates to Properties.sol output**

After merge generates Properties.sol from hunter hypotheses, append DeFi checker templates as additional invariants.

- [ ] **Step 4: Test on Yieldoor Strategy.sol**

Expected: PriceChange, TokenChange, StatementOrder detected as applicable.

- [ ] **Step 5: Commit**

```bash
git add audit-agents/merge_invariants.py
git commit -m "feat: 6 PromFuzz DeFi checker templates (0 FP pattern)"
```

---

## Phase 7: Strategic Differentiators [COMPLETADA]

### Task 19: Semantic search over Obsidian vault

**Files:**
- Create: `audit-agents/wiki_embeddings.py`
- Modify: `audit-agents/run_hunt.py` (replace keyword with semantic search)

**Problem:** `query_wiki_context()` is keyword-match only. "oracle price stale" won't find a page titled "Chainlink heartbeat validation". Knowdit achieved 88% coverage with a knowledge graph approach.

- [ ] **Step 1: Create embeddings generator**

Use `sentence-transformers` (all-MiniLM-L6-v2, 80MB, local, no API cost):

```python
def build_embeddings():
    model = SentenceTransformer("all-MiniLM-L6-v2")
    # Read all vault pages, extract summary from frontmatter
    # Encode summaries, save to .embeddings.json
```

- [ ] **Step 2: Create semantic search function**

```python
def search(query: str, top_k: int = 8) -> list[tuple[str, float, str]]:
    # Encode query, cosine similarity against all page embeddings
    # Return [(path, score, summary)] sorted by relevance
```

- [ ] **Step 3: Replace keyword search with semantic in run_hunt.py**

Fallback to keyword search if sentence-transformers not installed.

- [ ] **Step 4: Build initial embeddings and test**

```bash
python3 audit-agents/wiki_embeddings.py --build
python3 -c "from wiki_embeddings import search; print(search('oracle price stale'))"
```

- [ ] **Step 5: Commit**

```bash
git add audit-agents/wiki_embeddings.py audit-agents/run_hunt.py
git commit -m "feat: semantic search over Obsidian vault (sentence-transformers)"
```

---

### Task 20: Multi-model RedTeam (temperature variation)

**Files:**
- Modify: `~/.claude/skills/redteam.md`

**Problem:** Same model as auditor and critic is ineffective (CORRECT paper: heterogeneous models improve oversight). Until multi-model is available, use temperature variation as proxy.

- [ ] **Step 1: Add model diversity guidance to redteam.md**

```markdown
## Model Diversity
- Judge: temperature 0.3 (precise analysis)
- Devil's Advocate: temperature 0.8 (creative/contrarian)
- Guard: temperature 0.1 (strict verification)
- Economist: temperature 0.5 (balanced quantification)

When multi-model available (future):
- Attackers 1-2: Claude
- Attackers 3-4: GPT/Gemini
```

- [ ] **Step 2: Commit**

```bash
git add ~/.claude/skills/redteam.md
git commit -m "feat: temperature diversity in RedTeam (multi-model ready)"
```

---

### Task 21: New specialized hunters (Tier 2)

**Files:**
- Create: `audit-agents/prompts/hunters/GovernanceHunter.md`
- Create: `audit-agents/prompts/hunters/LiquidationHunter.md`
- Create: `audit-agents/prompts/hunters/MEVHunter.md`
- Modify: `audit-agents/hunter_profiles.yaml` (add Tier 2)

**Problem:** 11+ vulnerability classes without systematic coverage. Priority based on market impact.

- [ ] **Step 1: Create GovernanceHunter prompt**

Focus: voting power manipulation (flash loan governance), delegation loops, proposal timing, quorum gaming, vote escrow quirks.

- [ ] **Step 2: Create LiquidationHunter prompt**

Focus: health factor manipulation, bad debt socialization, liquidation cascade triggers, partial liquidation accounting, self-liquidation profitability.

- [ ] **Step 3: Create MEVHunter prompt**

Focus: sandwich attack vectors, missing/insufficient slippage checks, block proposer ordering dependency, token approval front-running.

- [ ] **Step 4: Add Tier 2 to hunter_profiles.yaml**

```yaml
tier2:
  GovernanceHunter:
    triggers: ["vote", "proposal", "delegate", "quorum", "governor", "veToken"]
    protocol_types: ["governance"]
  LiquidationHunter:
    triggers: ["liquidat", "healthFactor", "collateral", "badDebt", "closeFactor"]
    protocol_types: ["lending"]
  MEVHunter:
    triggers: ["swap", "slippage", "minAmountOut", "deadline", "router"]
    protocol_types: ["dex", "vault", "derivatives"]
```

- [ ] **Step 5: Update select_hunters() to include Tier 2**

- [ ] **Step 6: Commit**

```bash
git add audit-agents/prompts/hunters/ audit-agents/hunter_profiles.yaml audit-agents/run_hunt.py
git commit -m "feat: add GovernanceHunter, LiquidationHunter, MEVHunter (Tier 2)"
```

---

## Phase 8: Gaps Residuales — Calidad y Cobertura [COMPLETADA]

### Task 22: Dedup pre-merge (eliminar variantes redundantes)

**Files:**
- Modify: `audit-agents/merge_invariants.py`

**Problem:** En v9, ~31 hipótesis son variantes del mismo bug H-06 (wrong tick in collectFees). Esto infla el count de hipótesis y consume tokens de fuzzing en invariantes redundantes. 383 hipótesis → debería ser ~200 después de dedup.

- [ ] **Step 1: Implement hypothesis deduplication before merge**

```python
def dedup_hypotheses(hypotheses: list[dict]) -> list[dict]:
    """Remove near-duplicate hypotheses across hunters.

    Two hypotheses are duplicates if:
    - Same contract + same function(s) referenced
    - >70% keyword overlap in description
    - Same tier
    Keep the one with highest confidence.
    """
    from collections import defaultdict

    groups = defaultdict(list)
    for hyp in hypotheses:
        # Fingerprint: contract + primary function + tier
        functions = set()
        desc = hyp.get("description", "").lower()
        sol = hyp.get("solidity", "").lower()
        # Extract function names from solidity/description
        for token in re.findall(r'\b\w+\(', desc + " " + sol):
            functions.add(token.rstrip("("))
        key = (hyp.get("_component", ""), frozenset(functions), hyp.get("tier", 1))
        groups[key].append(hyp)

    deduped = []
    for key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            # Keep highest confidence, note how many were merged
            best = max(group, key=lambda h: h.get("confidence", 0))
            best["_merged_count"] = len(group)
            best["_merged_from"] = [h.get("_hunter", "?") for h in group]
            deduped.append(best)

    return deduped
```

- [ ] **Step 2: Call dedup before generating Properties.sol**

- [ ] **Step 3: Log dedup stats**

```
[merge] Deduped 383 → 247 hypotheses (136 duplicates removed)
[merge] Top duplicate: "collectFees wrong tick" appeared in 12 hunters
```

- [ ] **Step 4: Commit**

```bash
git add audit-agents/merge_invariants.py
git commit -m "feat: deduplicate hypotheses across hunters before merge"
```

---

### Task 23: poc_sketch obligatorio en hunters paralelos

**Files:**
- Modify: `audit-agents/prompts/hunters/*.md` (all 12 parallel hunter prompts)
- Modify: `audit-agents/run_hunt.py` (add to prompt template)

**Problem:** Solo DeepDiveHunter exige `poc_sketch` (Foundry test outline). Los 12 hunters paralelos no producen sketch de PoC, haciendo más difícil la conversión hipótesis → PoC en Phase 5.

- [ ] **Step 1: Add poc_sketch requirement to prompt template**

In `generate_hunter_prompt()`, add to the output format section:

```markdown
## Output YAML obligatorio por hipótesis

Para CADA invariante con confidence >= 60%, incluir `poc_sketch`:

```yaml
poc_sketch: |
  function test_<ID>() public {
      // 1. Setup: [qué deploy/configurar]
      // 2. Estado previo: [qué condiciones crear]
      // 3. Acción del atacante: [qué función llamar con qué params]
      // 4. Verificación: [qué assert demuestra el bug]
  }
```

Sin poc_sketch = hipótesis incompleta. El PoC generator depende de este sketch.
```

- [ ] **Step 2: Update YAML validation (Task 12) to warn on missing poc_sketch for high-confidence**

- [ ] **Step 3: Commit**

```bash
git add audit-agents/run_hunt.py
git commit -m "feat: require poc_sketch in parallel hunter output for confidence >= 60%"
```

---

### Task 24: CoT explícito en hunter prompts

**Files:**
- Modify: `audit-agents/run_hunt.py` (prompt template)

**Problem:** SmartGuard logró F1 94.95% con Chain-of-Thought explícito vs ~60% zero-shot. Nuestros hunters no tienen CoT estructurado — van directo a generar hipótesis.

- [ ] **Step 1: Add CoT section to hunter prompt template**

Before `## Tu Proceso`, add:

```markdown
## Razonamiento Paso a Paso (OBLIGATORIO antes de cada hipótesis)

Para CADA posible vulnerabilidad, razona explícitamente:
1. **Qué hace esta función**: describe en 1 frase
2. **Qué asume sobre el estado**: precondiciones implícitas
3. **Qué pasa si esa asunción es falsa**: escenario concreto
4. **Cómo se explota**: paso a paso del atacante
5. **Cuánto pierde la víctima**: en USD o % del pool

Si no puedes completar los 5 pasos con datos concretos, la hipótesis tiene confidence < 60%.
```

- [ ] **Step 2: Commit**

```bash
git add audit-agents/run_hunt.py
git commit -m "feat: explicit chain-of-thought in hunter prompts (SmartGuard pattern)"
```

---

### Task 25: Finding queue wired to variant-hunt and cross-component

**Files:**
- Modify: `audit-agents/run_hunt.py` (wire variant output to queue)

**Problem:** La infraestructura de finding queue existe en `pipeline_gate.py` pero variant-hunt y cross-component nunca la usan. Findings se pierden entre componentes.

- [ ] **Step 1: After variant-hunt skill completes, queue new findings**

```python
# After /variant-hunt produces variants
for variant in variants:
    subprocess.run([
        "python3", "audit-agents/pipeline_gate.py",
        "--queue-finding",
        "--source", "variant",
        "--parent", parent_finding_id,
        "--title", variant["title"],
        "-c", component,
        "--severity", variant.get("severity", "medium")
    ], check=False)
```

- [ ] **Step 2: After cross-component hunt, queue edge findings**

```python
# After EdgeHunter produces cross-component findings
for finding in edge_findings:
    subprocess.run([
        "python3", "audit-agents/pipeline_gate.py",
        "--queue-finding",
        "--source", "cross-component",
        "--title", finding["title"],
        "-c", f"{comp_a}+{comp_b}",
        "--severity", finding.get("severity", "medium")
    ], check=False)
```

- [ ] **Step 3: Process queue between components**

Add to component transition logic:

```python
# Before starting next component, process queued findings
queue_result = subprocess.run([
    "python3", "audit-agents/pipeline_gate.py", "--list-queue"
], capture_output=True, text=True)
# Process any pending items through finding pipeline
```

- [ ] **Step 4: Commit**

```bash
git add audit-agents/run_hunt.py
git commit -m "feat: wire finding queue to variant-hunt and cross-component outputs"
```

---

### Task 26: DeepDive improvement — inception prompting + convergence

**Files:**
- Modify: `audit-agents/.claude/skills/web3-deepdive-hunter/SKILL.md`

**Problem:** DeepDiveHunter produced only 6 findings (2.6%) in v9 despite being the highest-quality hunter (95% validated). It needs more context and structured reasoning. LLM-SmartAudit's inception prompting (internal auditor + internal critic) improved recall to 48.36%.

- [ ] **Step 1: Add inception prompting to DeepDive skill**

Add to SKILL.md after the methodology sections:

```markdown
## Razonamiento Interno Dual (Inception Prompting)

Para cada área de convergencia, ejecutar DOS pasadas internas:

**Pasada 1 — Auditor Interno:**
"Dado que los hunters [X, Y, Z] flaggearon esta función, ¿cuál es el bug MÁS PROFUNDO
que ninguno de ellos vio? No repitas lo que ya encontraron. Busca la interacción entre
sus hallazgos."

**Pasada 2 — Crítico Interno:**
"El Auditor propone [hipótesis]. ¿Es realmente explotable? ¿Cuál es el contraargumento
más fuerte? ¿Qué condición EXACTA debe cumplirse para que el ataque funcione?"

Solo las hipótesis que sobreviven ambas pasadas van al output.
```

- [ ] **Step 2: Inject full convergence data (not just top-N)**

Currently DeepDive receives top-N flagged functions. Change to receive ALL convergence data:
- Every function flagged by 2+ hunters with their specific observations
- False positives list from parallel hunters
- Ghost variables already defined

- [ ] **Step 3: Commit**

```bash
git add audit-agents/.claude/skills/web3-deepdive-hunter/SKILL.md
git commit -m "feat: inception prompting + full convergence data in DeepDiveHunter"
```

---

### Task 27: RAG de invariantes confirmadas (PropertyGPT pattern)

**Files:**
- Create: `audit-agents/invariant_rag.py`
- Modify: `audit-agents/merge_invariants.py` (query RAG during merge)

**Problem:** PropertyGPT achieved 80% recall using RAG over 623 human-written Certora properties. We have 0 RAG — our invariants are generated from scratch each time. We should reuse confirmed invariants from past audits as seeds.

- [ ] **Step 1: Create invariant RAG index**

```python
"""Build and search a RAG index of confirmed invariants from past audits."""

def build_index():
    """Scan all bench_session_*/hypotheses/ for validated invariants.
    Extract: id, solidity, description, confidence, component, protocol.
    Store in invariant_rag.json with embeddings."""

    confirmed = []
    for session_dir in Path("benchmarks").glob("*/bench_session_*/hypotheses"):
        for yaml_file in session_dir.glob("**/hyp_*.yaml"):
            content = yaml.safe_load(yaml_file.read_text())
            for inv in content.get("invariants", []):
                if inv.get("validated") and inv.get("confidence", 0) >= 70:
                    confirmed.append({
                        "id": inv["id"],
                        "solidity": inv.get("solidity", ""),
                        "description": inv.get("description", ""),
                        "category": content.get("domain", ""),
                        "protocol": content.get("protocol", ""),
                    })
    # Save index
    with open("audit-agents/invariant_rag.json", "w") as f:
        json.dump(confirmed, f, indent=2)
    print(f"Indexed {len(confirmed)} confirmed invariants")

def query(domain: str, contract_source: str, top_k: int = 5) -> list[dict]:
    """Find similar confirmed invariants for this domain/source."""
    # Keyword matching (upgrade to embeddings in Phase 7)
    ...
```

- [ ] **Step 2: Inject RAG results into merge_invariants.py**

During merge, query RAG for similar confirmed invariants. Append as "seed invariants" with source attribution.

- [ ] **Step 3: Build initial index from v9 data**

```bash
python3 audit-agents/invariant_rag.py --build
```

- [ ] **Step 4: Commit**

```bash
git add audit-agents/invariant_rag.py audit-agents/invariant_rag.json audit-agents/merge_invariants.py
git commit -m "feat: RAG index of confirmed invariants (PropertyGPT pattern)"
```

---

### Task 28: Slither-MCP as post-hunter filter

**Files:**
- Modify: `audit-agents/detection_engine.py` (add post-hunter Slither verification)

**Problem:** GPTScan reduced 2/3 of false positives by using static analysis to confirm LLM-detected vulnerabilities. IRIS achieved -80% FP with LLM+CodeQL loop. We use Slither in prepass but NOT as a post-hunter filter.

- [ ] **Step 1: Add Slither confirmation step after hunters**

```python
def slither_confirm_hypothesis(hypothesis: dict, contract_path: str) -> dict:
    """Use Slither to check if the hypothesis is statically confirmable.

    Checks:
    - Does the function mentioned exist?
    - Are the variables mentioned real state variables?
    - Is the code path reachable (no dead code)?
    - Are there existing Slither detectors that flag the same area?

    Returns hypothesis with added 'static_confirmation' field.
    """
    # Run targeted Slither analysis
    result = subprocess.run([
        "slither", contract_path,
        "--print", "human-summary",
        "--filter-paths", "test|lib|node_modules"
    ], capture_output=True, text=True, timeout=60)

    # Cross-reference hypothesis with Slither output
    # If Slither also flags the same function → boost confidence
    # If function doesn't exist → flag as likely FP
    ...
```

- [ ] **Step 2: Run post-hunter Slither filter on all hypotheses**

After hunters complete, before merge:
```python
for hyp_file in hypotheses:
    hypotheses_data = load_yaml(hyp_file)
    for inv in hypotheses_data.get("invariants", []):
        result = slither_confirm_hypothesis(inv, contract_path)
        if result.get("function_not_found"):
            inv["confidence"] = max(0, inv.get("confidence", 0) - 30)
            inv["static_note"] = "Function not found by Slither"
```

- [ ] **Step 3: Commit**

```bash
git add audit-agents/detection_engine.py
git commit -m "feat: Slither post-hunter filter to reduce FPs (GPTScan/-80% FP pattern)"
```

---

### Task 29: Second ground truth benchmark (LayerZero-Stellar)

**Files:**
- Create: `benchmarks/layerzero-stellar/benchmark.yaml`

**Problem:** Solo tenemos 1 ground truth (Yieldoor, 17 findings). Para validar mejoras necesitamos al menos 2 benchmarks con protocolos diferentes (EVM vs Soroban).

- [ ] **Step 1: Create benchmark.yaml from our own confirmed findings**

Use our TTL desync findings and the systemic analysis as ground truth:

```yaml
contest:
  name: "LayerZero-Stellar"
  platform: "C4"
  date: "2026-04"

findings:
  - id: "H-01"
    severity: HIGH
    title: "Allowlist size counter corruption via TTL desync"
    contracts: ["Worker"]
    functions: ["set_allowlist"]
    category: "ttl-storage"
    # ... from our C4-SUBMIT-H-01
```

- [ ] **Step 2: Score existing hypotheses against new ground truth**

```bash
python3 audit-agents/benchmark_score.py \
  --ground-truth benchmarks/layerzero-stellar/benchmark.yaml \
  --hypotheses-dir hunt_session/hypotheses/layerzero-stellar
```

- [ ] **Step 3: Commit**

```bash
git add benchmarks/layerzero-stellar/benchmark.yaml
git commit -m "feat: add LayerZero-Stellar ground truth benchmark (TTL desync patterns)"
```

---

### Task 30: Halmos feedback loop (contraejemplo → LLM repair)

**Files:**
- Modify: `audit-agents/halmos_property_generator.py`

**Problem:** When Halmos finds a counterexample, we currently just log it. Research shows feeding counterexamples back to the LLM doubles repair success (LLM+SMT hybrid: 78% generation, 16% repair).

- [ ] **Step 1: Capture Halmos counterexamples**

```python
def parse_halmos_counterexample(output: str) -> dict | None:
    """Extract counterexample from Halmos output."""
    # Halmos outputs: "Counterexample: p_x = 0x..."
    ...
```

- [ ] **Step 2: Feed counterexample to LLM for invariant repair**

```python
def repair_invariant_with_counterexample(invariant: dict, counterexample: dict) -> dict:
    """Use LLM to refine invariant based on Halmos counterexample."""
    prompt = f"""This invariant was disproven by Halmos:

Invariant: {invariant['description']}
Solidity: {invariant['solidity']}

Counterexample: {counterexample}

Either:
1. The invariant is wrong (needs tighter bounds or different condition)
2. The invariant found a real bug (the counterexample IS the exploit)

Determine which case this is. If case 1, provide the corrected invariant.
If case 2, provide a poc_sketch exploiting the counterexample."""
    ...
```

- [ ] **Step 3: Commit**

```bash
git add audit-agents/halmos_property_generator.py
git commit -m "feat: Halmos counterexample feedback loop for invariant repair"
```

---

## Benchmark Re-run (v10 validation)

After completing Phases 4-6, re-run benchmark against same ground truth:

```bash
python3 audit-agents/run_benchmark.py \
  --repo benchmarks/yieldoor/repo \
  --components Strategy,Vault,Leverager,LendingPool \
  --protocol yieldoor \
  --ground-truth benchmarks/yieldoor/benchmark.yaml \
  --parallel-components 2

# Score
python3 audit-agents/benchmark_score.py \
  --ground-truth benchmarks/yieldoor/benchmark.yaml \
  --hypotheses-dir benchmarks/yieldoor/bench_session_v10/hypotheses/yieldoor

python3 audit-agents/benchmark_score.py \
  --ground-truth benchmarks/yieldoor/benchmark.yaml \
  --findings-json benchmarks/yieldoor/bench_session_v10/findings_all.json
```

**Target metrics v10:**

| Metric | v9 (baseline) | v10 (target) | Improvement source |
|--------|--------------|-------------|-------------------|
| Detection recall | 94.1% | 95%+ | Few-shot + rejection rules |
| PoC-confirmed recall | 41.2% | **65-70%** | Iterative repair loop + templates |
| Hypotheses | 383 | **250-280** | Conditional hunters (less noise) |
| FP rate | ~40% | **<25%** | YAML validation + fewer noisy hunters |
| Time per component | ~90 min | **~55 min** | 7-8 hunters vs 12 |

---

## Phase Summary

| Phase | Tasks | Status | Time | Key Deliverable |
|-------|-------|--------|------|-----------------|
| 1. Obsidian-Wiki | 1-3 | DONE | -- | 101-page knowledge vault |
| 2. Graphify | 4-6 | DONE | -- | Structural recon in scope_intake |
| 3. Council v2 | 7-9 | DONE | -- | Karpathy 3-stage anonymous review |
| 4. Quick Wins | 10-14 | TODO | 1-2 days | Gates auto-mark, rejection injection, YAML validation |
| 5. PoC + Hunters | 15-16 | TODO | 3-5 days | Repair loop (41%→70%), conditional hunters |
| 6. RAG + Few-Shot | 17-18 | TODO | 1 week | Example bank, PromFuzz templates |
| 7. Strategic | 19-21 | TODO | 2 weeks | Semantic search, multi-model, new hunters |
