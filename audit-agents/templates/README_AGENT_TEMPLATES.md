# Agent Prompt Templates -- Usage Guide

## Overview

Seven specialized agent prompt templates for blockchain security auditing. Each template is a complete, copy-paste-ready system prompt designed for production bug bounty hunting.

## Template Index

| # | Agent | File | Chain-Specific | Primary Use |
|---|-------|------|----------------|-------------|
| 1 | Solidity/EVM | `01_solidity_evm_agent.md` | EVM | Code-level vulnerability hunting in Solidity contracts |
| 2 | Rust/Solana | `02_rust_solana_agent.md` | Solana | Account validation, CPI, PDA exploits in Anchor/native programs |
| 3 | CosmWasm | `03_cosmwasm_agent.md` | Cosmos | Reply handlers, submessages, bank module, IBC |
| 4 | ZK Circuits | `04_zk_circuit_agent.md` | Any | Under-constrained circuits, soundness breaks |
| 5 | Economic Invariant | `05_economic_invariant_agent.md` | Any | Flash loans, oracle manipulation, invariant breaking |
| 6 | Known Issues Research | `06_known_issues_research_agent.md` | Any | Duplicate detection, prior audit research |
| 7 | Devil's Advocate | `07_devils_advocate_validation_agent.md` | Any | Finding rejection, scope checking, payout estimation |

## Recommended Pipeline

```
Step 1: Known Issues Research Agent
        -> Produces: Known Issues DB + Research Briefs

Step 2: (parallel) Chain-Specific Code Agent (1, 2, 3, or 4)
         +          Economic Invariant Agent (5)
        -> Both consume Research Briefs from Step 1
        -> Produce: Raw Findings

Step 3: Devil's Advocate Validation Agent (7)
        -> Consumes: Raw Findings + Known Issues DB + Bounty Scope
        -> Produces: Validated findings with payout estimates
        -> Only SUBMIT-HIGH and SUBMIT-MODERATE findings proceed
```

## How to Use

### For a new bounty target:

1. Copy the relevant chain-specific template (1-4) as the system prompt for your code auditing agent.
2. Copy template 5 (Economic Invariant) as the system prompt for a second agent running in parallel.
3. Copy template 6 (Known Issues Research) and run it first to build the intel database.
4. After findings are generated, copy template 7 (Devil's Advocate) and feed it all findings.
5. Only submit findings that pass the Devil's Advocate with SUBMIT-HIGH or SUBMIT-MODERATE.

### Customization per bounty:

Before using any template, append these bounty-specific details to the system prompt:

```
## BOUNTY-SPECIFIC CONTEXT

### Program Details
- Platform: [Immunefi / Code4rena / Sherlock / etc.]
- Program URL: [link]
- Max payout: $[amount]
- Scope: [list in-scope contracts/files with commit hash]

### Exclusions (copy from bounty page)
- [exclusion 1]
- [exclusion 2]

### Known Issues (copy from bounty page)
- [known issue 1]
- [known issue 2]

### Prior Audits
- [Auditor, date, link to report]

### Protocol-Specific Notes
- [Any relevant context about the protocol design]
```
