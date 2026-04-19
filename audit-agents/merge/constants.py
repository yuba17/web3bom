"""Module-level constants for merge_invariants package."""

# Mapeo hunter → sufijo del archivo
HUNTER_FILE_MAP = {
    "MathHunter":           "Math",
    "AccessHunter":         "Access",
    "FlowHunter":           "Flow",
    "DomainHunter":         "Domain",
    "OracleHunter":         "Oracle",
    "DoSHunter":            "DoS",
    "WildcardHunter":       "Wildcard",
    "TrustBoundaryHunter":  "Trust",
    "SignatureHunter":       "Signature",
    "LogicHunter":          "Logic",
    "AdversarialHunter":    "Adversarial",
    "LibraryHunter":        "Library",
    "DeepDiveHunter":       "DeepDive",
    "CrossChainHunter":     "CrossChain",
    "EdgeHunter":           "Cross",
}

# EdgeHunter hypotheses need special handling: they reference TWO contracts
CROSS_COMPONENT_HUNTERS = {"EdgeHunter"}

# Default pragma — overridden by detect_pragma()
_PRAGMA = "pragma solidity ^0.8.0;"

# ── Hypothesis YAML validation (Task 12) ──────────────────────────────
REQUIRED_HYP_FIELDS = {"id", "description", "solidity"}

# Required structured evidence tables per hunter (added 2026-04)
HUNTER_REQUIRED_TABLES = {
    "MathHunter": ["decimal_analysis", "boundary_analysis"],
    "FlowHunter": ["derived_state_map"],
    "AccessHunter": ["state_var_lifecycle"],
    "DoSHunter": ["loop_termination"],
    "DomainHunter": ["parameter_consistency"],
    "TrustBoundaryHunter": ["integration_assumptions"],
}
