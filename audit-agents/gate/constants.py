"""Constants for the gate pipeline: gate name lists, paths."""

from paths import HUNT_SESSION_DIR

SCOPE_MASTER_DIR = HUNT_SESSION_DIR / "context"

HUNTER_NAMES = [
    "AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
    "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
    "SignatureHunter", "DoSHunter",
]

GATE_ORDER = ["scope", "prepass", "hunters", "crosschain", "deepdive", "merge", "compile", "phase1", "phase2", "phase3", "phase4", "phase5", "complete"]
