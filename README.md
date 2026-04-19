# Web3 Bug Bounty Hunting

Autonomous pipeline for Web3 smart-contract security audits. Combines
LLM-driven hypothesis generation, invariant fuzzing (Foundry + Medusa +
Echidna + Halmos), and multi-stage finding validation (RedTeam + variant +
escalation hunts) to surface vulnerabilities in DeFi, staking, bridge,
and zk protocols.

## Entry point

```bash
python3 audit-agents/run_benchmark.py --repo <path> --components <name> --protocol <name>
```

Canonical modern flow. Lists 14 hunters (12 parallel + CrossChain + DeepDive)
per component, runs gates via `pipeline_gate.py`, emits Properties.sol +
TargetFunctions.sol for Chimera fuzzing, and produces finding reports under
`reports/`.

## Layout

- `audit-agents/` — Python orchestration (hunters, gates, fuzzing runners)
- `audit-agents/benchmark/` — runner, prompt builders, PoC pipeline, cross-component
- `audit-agents/plan/` — plan generator (hunter prompts, post-compile, CLI)
- `hunt_session/` — per-hunt state: `current_hunt.json`, gate status,
  hypotheses, fichas, findings
- `knowledge/` — shared knowledge base (state machine modeling, attack
  patterns, solodit cards)
- `reports/` — finding drafts in markdown, one per ID
- `docs/superpowers/` — specs and plans for system-level changes

## Documentation

- `CLAUDE.md` — project guidelines (pipeline gates, rejection rules,
  fuzzing phases, component checklist)
- `HUNT_TRACKER.md` — per-component progress ledger
- `WIKI.md` — auxiliary reference
- `docs/superpowers/specs/` — design documents
- `docs/superpowers/plans/` — implementation plans

## Testing

```bash
python3 -m pytest audit-agents/tests/ -q
```

Expects the full suite to pass (224 tests as of Phase 8).
