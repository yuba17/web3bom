#!/usr/bin/env python3
"""
pipeline_gate.py — Deterministic pipeline enforcer for the hunt system.

Checks that ALL required steps are completed before allowing progression.
Returns exit code 0 if gate passes, 1 if blocked.

Usage:
    python3 pipeline_gate.py --component <name> --gate <gate_name> [--repo <path>] [--fix]
    python3 pipeline_gate.py --component <name> --status          # Show full pipeline status
    python3 pipeline_gate.py --component <name> --gate all        # Check ALL gates

Component gates (in order):
    hunters     — All 9 hunters generated hypothesis YAMLs with solidity fields
    crosschain  — CrossChainHunter analyzed multi-chain deployments (or skip if single-chain)
    deepdive    — DeepDiveHunter ran after the 9 hunters
    merge       — merge_invariants.py ran, Properties.sol exists
    compile     — forge build passes
    phase1      — Foundry fuzz min 5K runs (evidence file exists)
    phase2      — Medusa fuzz min 15 min (corpus directory exists)
    phase3      — Fork test executed (for bounties >= $2K or broken invariant)
    phase4      — Echidna optimization (if optimize_* functions exist)
    phase5      — Halmos symbolic proof (if pure math functions exist)
    complete    — Component fully done, ready for next

Finding gates (after a bug is found):
    python3 pipeline_gate.py --finding <ID> --status
    python3 pipeline_gate.py --finding <ID> --fgate <gate_name>
    python3 pipeline_gate.py --finding <ID> --mark <gate_name>

    poc         — PoC exists and PASSES (Foundry fork test)
    escalation  — EscalationHunter executed (mandatory for Medium+)
    variant     — Variant hunt executed across full scope
    redteam     — RedTeam 4-attacker review with Round 0 calibration
    verify      — Code verified on-chain (deployed, not fixed, feature active)
    report      — ReportWriter generated DRAFT markdown
    submit      — report_finding.py registered in Bounty Radar
    reportable  — ALL finding gates passed, ready for platform submission

Each gate checks ALL previous gates too (cumulative).

Scope master operations:
    python3 pipeline_gate.py --scope-status                    # Show SCOPE_MASTER summary
    python3 pipeline_gate.py --scope-review -c <component>     # Mark component as re-reviewed

Auto-updates SCOPE_MASTER.md when:
    - Component passes 'complete' gate → state=DONE + review date added
    - Finding is queued → finding count updated in component entry
    - --scope-review is called → adds today's date without changing state
"""

# ─── Paths ───────────────────────────────────────────────────────────────────

from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
from state_manager import load_state, save_state as _sm_save_state
from gate.constants import *  # noqa: F401,F403
from gate.ficha import *  # noqa: F401,F403
from gate.scope_master import *  # noqa: F401,F403
from gate.gates_component import *  # noqa: F401,F403
from gate.gate_status import *  # noqa: F401,F403
from gate.gates_finding import *  # noqa: F401,F403
from gate.finding_queue import *  # noqa: F401,F403
from gate.cli import *  # noqa: F401,F403

# Marker attribute used by gate.gates_component._hunt_session_dir() to
# identify this module as the canonical shim when looking up the
# late-bound HUNT_SESSION_DIR (tests monkeypatch pipeline_gate.HUNT_SESSION_DIR).
import gate.gates_component as _gates_component  # noqa: F401


if __name__ == "__main__":
    from gate.cli import main
    main()
