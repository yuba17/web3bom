# Bug Bounty Hunting Pipeline v1.0

## Architecture

```
NEW CONTEST/BOUNTY
       │
       ▼
┌──────────────┐
│  Phase 0:    │  5 min — Read rules, check scope, verify live code
│  TRIAGE      │
└──────┬───────┘
       ▼
┌──────────────┐
│  Phase 1:    │  30 min — Clone, map architecture, research known issues
│  SCOPE       │  Output: target_analysis.md
└──────┬───────┘
       ▼
┌──────────────┐
│  Phase 2:    │  2-4h — Hypothesis agents + invariant generation
│  HUNT        │  Output: hypotheses.md + invariant test files
└──────┬───────┘
       ▼
┌──────────────────────────────────────────────┐
│  Phase 3: FUZZ (progressive depth)           │
│                                              │
│  ┌─────────┐   ┌─────────┐   ┌──────────┐  │
│  │ Foundry  │──▶│ Medusa  │──▶│ Echidna  │  │
│  │ 5 min    │   │ 30 min  │   │ overnight│  │
│  │ 256 runs │   │ coverage│   │ grammar  │  │
│  └────┬─────┘   └────┬────┘   └────┬─────┘  │
│       │              │             │         │
│       ▼              ▼             ▼         │
│  ┌────────────────────────────────────────┐  │
│  │  Any failure? → Investigate → PoC      │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
       │
       ▼
┌──────────────┐
│  Phase 4:    │  1h — Devil's advocate validation
│  VALIDATE    │
└──────┬───────┘
       ▼
┌──────────────┐
│  Phase 5:    │  30 min — Format report, PoC, submit
│  REPORT      │
└──────────────┘
```

## Tools Required

- **Foundry** (forge) — Fast compilation + built-in invariant testing
- **Medusa** — Coverage-guided fuzzer (finds precision/rounding bugs)
- **Echidna** — Grammar-based fuzzer (finds complex state sequences)
- **Halmos** — Symbolic testing (mathematical proofs)
- **Slither** — Static analysis
- **Chimera** — Write-once framework for all fuzzers

## Directory Structure

```
pipeline/
├── README.md                    # This file
├── run_pipeline.sh              # Main pipeline script
├── templates/
│   ├── chimera/                 # Chimera framework template
│   │   ├── TargetFunctions.sol  # Handler actions template
│   │   ├── Properties.sol       # Invariant properties template
│   │   ├── Setup.sol            # Test setup template
│   │   └── CryticTester.sol     # Echidna/Medusa entry point
│   ├── foundry/
│   │   ├── InvariantBase.t.sol  # Foundry invariant base
│   │   └── Handler.t.sol       # Foundry handler template
│   └── reports/
│       ├── code4rena.md         # C4 report template
│       ├── cantina.md           # Cantina report template
│       └── immunefi.md          # Immunefi report template
├── configs/
│   ├── medusa.json              # Medusa configuration
│   ├── echidna.yaml             # Echidna configuration
│   └── foundry_invariant.toml   # Foundry invariant config
└── scripts/
    ├── generate_invariants.sh   # Claude agent invariant generator
    ├── analyze_target.sh        # Target analysis script
    └── install_tools.sh         # Tool installation script
```
