---
tags: [protocol, moonwell, status]
date: 2026-03-16
---

# Moonwell Analysis — STATUS TRACKER

## Agents Completed: 9/11

| Agent | Target | Status | New Findings |
|---|---|---|---|
| 1. MToken | MToken.sol | DONE | F-01 (protocolSeizeShare) |
| 2. Comptroller | Comptroller.sol | DONE | F-03, F-08 (closeFactor, nonReentrant) |
| 3. MultiRewardDistributor | MRD.sol | DONE | Low-confidence only |
| 4. TemporalGovernor + MultichainGov | Governance | DONE | F-02 (quorum), F-07, F-10, F-13 |
| 5. OEV Wrapper Deep | ChainlinkOEVWrapper* | DONE | F-04, F-05, F-06 (oracle DoS, phase bypass, nonReentrant) |
| 6. Mamo Strategy | Strategy/Factory | DONE | F-11, F-12 (unsafe approve, initializeV2) |
| 7. Governance Deep | TemporalGov + MultichainGov | DONE | Confirmed F-02, added F-07 |
| 8. Manual scan | FeeSplitter, ReserveAutomation, Cypher | DONE | No high-confidence findings |
| 9. ERC4626 + Routers | Vaults, WETHRouter, WethUnwrapper | DONE | F-15, F-16 (WethUnwrapper, sweepRewards) |
| 10. stkWELL / StakedWell | Staking contracts | DONE | F-17 (EcosystemReserve unsafe transfer) |
| 11. xWELL Bridge | Cross-chain token | DONE | Confirmed F-12 (initializeV2) |

## ANALYSIS COMPLETE — 11/11 AGENTS FINISHED
## ~32,000 LOC analyzed across ~130 contracts
## Total findings: 17 (6 TIER 1, 11 TIER 2/3)

## TOP FINDINGS — READY TO SUBMIT

| # | Severity | Finding | Confianza | Report |
|---|---|---|---|---|
| F-01 | HIGH/MED | protocolSeizeShare sin upper bound | 85% | SUBMIT-F01.md |
| F-02 | HIGH/MED | Quorum retroactivo | 55% | SUBMIT-F02.md |
| F-06 | MEDIUM | OEVMorpho missing nonReentrant | 80% | SUBMIT-F06.md |

## SECONDARY FINDINGS (submit si quieres gastar más depósitos)

| # | Severity | Finding | Confianza |
|---|---|---|---|
| F-03 | MEDIUM | closeFactor sin bounds | 80% |
| F-04 | MEDIUM | OEV oracle DoS invalid round data | 75% |
| F-05 | MEDIUM | OEV bypass on phase change | 75% |
| F-08 | MEDIUM | Comptroller nonReentrant unused | 70% |
| F-09 | MEDIUM | ChainlinkOracle sin staleness | 70% |
| F-15 | LOW/MED | WethUnwrapper send() sin access control | 70% |
