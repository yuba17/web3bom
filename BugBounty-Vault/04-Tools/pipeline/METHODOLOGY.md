# Bug Hunting Methodology v3.0
# Invariant-Driven, Multi-Fuzzer Pipeline

## Philosophy
- Understand the protocol like you DESIGNED it (50% of time)
- Question every assumption (30% of time)
- Verify with tools (15% of time)
- Report with quality (5% of time)

## Phase 0: TRIAGE (5 min)
```
[ ] Read bounty rules COMPLETELY
[ ] Check: pool size, deposit cost, PoC requirement
[ ] List exclusions (admin-only, MEV, known issues)
[ ] Verify code is LIVE (not old audit mirror)
[ ] Count nSLOC — estimate effort
[ ] Check previous audits — what was already found?
[ ] Decision: ENTER or SKIP (>50% confidence threshold)
```

## Phase 1: UNDERSTAND (2-4 hours, 50% of effort)

### 1.1 Read Every Line
```
[ ] Read ALL in-scope contracts line by line
[ ] For each function: WHO can call it? WHAT does it do? WHAT can go wrong?
[ ] Map token flows: where do tokens enter/exit the system?
[ ] Identify trust boundaries: what roles exist? what can each do?
```

### 1.2 Extract Protocol Promises
```
[ ] From NatSpec: every "must", "should", "always", "never"
[ ] From README: stated invariants and guarantees
[ ] From tests: what do existing tests verify?
[ ] From docs: design assumptions
→ Output: list of INVARIANT CANDIDATES
```

### 1.3 Map the Attack Surface
```
[ ] External entry points (public/external functions)
[ ] Cross-contract interactions
[ ] Oracle dependencies
[ ] Callback patterns (ERC721 receiver, flash loan, auction callback)
[ ] Admin/governance operations
[ ] Time-dependent logic
→ Output: ATTACK SURFACE MAP
```

## Phase 2: QUESTION (1-2 hours, 30% of effort)

### 2.1 For Each Invariant Candidate
```
"What if this invariant is VIOLATED? What's the impact?"
"Can I construct an input sequence that breaks it?"
"Is there a code path that doesn't enforce it?"
```

### 2.2 For Each Token Flow
```
"Can tokens leak to an unintended recipient?"
"Can tokens be locked permanently?"
"Can someone extract more than they deposited?"
"Does rounding favor the right party?"
```

### 2.3 For Each Assumption
```
"What if the oracle returns stale/wrong data?"
"What if the callback does something unexpected?"
"What if two transactions interact in the same block?"
"What if a dependent contract is paused/upgraded?"
```

### 2.4 Generate Hypotheses
```
Convert questions into SPECIFIC, TESTABLE hypotheses:
BAD:  "The oracle might be manipulable"
GOOD: "If assetPrice drops 50% between checkUpkeep and performUpkeep,
       the bid calculation at line 442 uses stale price, allowing
       bidder to pay 50% less than market value"
→ Output: 5-10 PRIORITIZED HYPOTHESES
```

## Phase 3: VERIFY (1-2 hours, 15% of effort)

### 3.1 Write Invariant Tests (Chimera framework)
```
For each invariant candidate:
1. Write property_* function in Properties.sol
2. Write handler action in TargetFunctions.sol
3. Connect in FoundryTester.t.sol
```

### 3.2 Progressive Fuzzing
```
Step 1: Foundry (5 min)
  forge test --match-contract Tester --fuzz-runs 256 -vvv
  → Quick feedback. If failure: INVESTIGATE.

Step 2: Medusa (30 min) — if Foundry passes
  medusa fuzz --config medusa.json
  → Coverage-guided. Finds precision/rounding bugs.

Step 3: Echidna (overnight) — if Medusa passes
  echidna . --contract CryticTester --config echidna.yaml
  → Grammar-based. Finds complex state sequences.
```

### 3.3 Manual PoC for Hypotheses
```
For top 3 hypotheses that aren't fuzzable:
- Write targeted forge test
- Use vm.warp, vm.prank, deal() to construct scenario
- If test passes (exploit works): REPORT
```

## Phase 4: VALIDATE (30 min)

### 4.1 Devil's Advocate
```
For each finding:
[ ] "Would a judge REJECT this? Why?"
[ ] "Is this a known issue or by-design?"
[ ] "Does the fix go against the protocol's design philosophy?"
[ ] "Is the impact REAL or theoretical?"
[ ] "Does this require admin/governance action?" (usually excluded)
```

### 4.2 Check Against Exclusions
```
[ ] Previous audit findings (known issues)
[ ] Admin-only bugs (usually excluded)
[ ] MEV/frontrunning (check if excluded)
[ ] Fee-on-transfer tokens (usually excluded)
[ ] Rounding dust (usually Low at best)
```

## Phase 5: REPORT (30 min)

### 5.1 Write Report
```
Use template from pipeline/templates/reports/
[ ] Clear title: [H/M-XX] One-sentence description
[ ] Summary: 2-3 sentences
[ ] Technical description with line numbers
[ ] Impact quantification
[ ] Runnable PoC (MANDATORY for most contests)
[ ] Fix recommendation
```

### 5.2 Submit
```
[ ] PoC compiles and runs with project's test suite
[ ] Severity correctly assessed
[ ] Not a duplicate of known issues
[ ] Confidence >50%
```

## Invariant Categories Checklist (use for EVERY protocol)

### Universal (always test)
```
[ ] Solvency: balance >= obligations
[ ] Conservation: no value created from nothing
[ ] Share price monotonicity (vaults)
[ ] Round-trip: deposit→withdraw gives ≤ original
[ ] Access control: admin functions restricted
[ ] Reentrancy guard cleared post-call
[ ] Total supply == sum of balances
```

### Lending Protocols
```
[ ] Debt rate >= lend rate (reserve factor)
[ ] Exchange rates monotonically increasing
[ ] Healthy positions can't be liquidated
[ ] Unhealthy positions CAN be liquidated
[ ] Liquidation penalty within bounds
[ ] Bad debt socialization works correctly
[ ] Min loan size enforced
[ ] Global lend/debt limits enforced
```

### DEX / Auctions
```
[ ] Price only moves in expected direction (Dutch: down)
[ ] Price within [start, end] bounds
[ ] Settlement amounts match calculations
[ ] No reentrancy via callbacks
[ ] Approval/allowance cleanup after settlement
[ ] Balance changes match transfer amounts
```

### Vaults (ERC4626)
```
[ ] preview* functions are conservative
[ ] maxWithdraw/maxRedeem bounded correctly
[ ] Deposit additivity
[ ] totalAssets == balanceOf + debt (or similar)
[ ] No first-depositor inflation attack
```

### NFT Collateral
```
[ ] NFT custody always deterministic (vault XOR other)
[ ] No orphaned debt (debt without collateral)
[ ] Collateral value > 0 for positions with debt
[ ] NFT approvals cleared after operations
```

## Tools Quick Reference

| Tool | Command | Best For |
|------|---------|----------|
| Foundry | `forge test --fuzz-runs 1000` | Quick iteration, familiar |
| Medusa | `medusa fuzz --config medusa.json` | Precision/rounding bugs |
| Echidna | `echidna . --contract T --config e.yaml` | Complex state sequences |
| Halmos | `halmos --contract T --function check_` | Mathematical proofs |
| Slither | `slither .` | Static analysis, quick wins |
