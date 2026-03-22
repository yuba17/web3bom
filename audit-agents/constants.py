#!/usr/bin/env python3
"""
constants.py — Single source of truth for Bounty Radar ↔ local status mappings.

Imported by: submit_finding.py, sync_state.py, report_finding.py
Must stay in sync with src/lib/constants.ts (TypeScript side).
"""

import hashlib

# ── Session token derivation ──────────────────────────────────────────────────
# Must match the algorithm in src/middleware.ts and src/lib/auth.ts:
#   sha256(password + ':bounty-radar')  →  hex string stored in br_session cookie
_TOKEN_SUFFIX = ":bounty-radar"


def derive_session_token(password: str) -> str:
    """Derives the br_session cookie value from BOUNTY_RADAR_PASSWORD.

    This is a one-way derivation — the raw password is never stored in the cookie.
    The middleware independently derives the expected token and compares.
    """
    return hashlib.sha256(f"{password}{_TOKEN_SUFFIX}".encode()).hexdigest()


# ── Radar status → local status ───────────────────────────────────────────────
# Authoritative mapping used by submit_finding.py and sync_state.py.
# Local status values used in current_hunt.json findings[].status.
RADAR_TO_LOCAL: dict[str, str] = {
    "DRAFT":     "confirmed",   # registered in Radar, no PoC yet
    "ANALYZING": "confirmed",   # same
    "VERIFIED":  "registered",  # analyst confirmed the finding
    "POC_READY": "registered",  # PoC exists, ready to submit
    "REPORTED":  "submitted",   # submitted to the platform
    "ACCEPTED":  "accepted",    # platform accepted it
    "REJECTED":  "rejected",    # platform rejected it
    "DUPLICATE": "duplicate",   # duplicate of another submission
    "PAID":      "paid",        # bounty paid out
}

# ── Severity mappings ─────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "unknown":  "MEDIUM",
}

REMOTE_SEVERITY: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "info",
}

# ── Allowed PATCH transitions (must match VALID_TRANSITIONS in constants.ts) ──
ALLOWED_PATCH: dict[str, list[str]] = {
    "DRAFT":     ["VERIFIED", "REPORTED"],
    "ANALYZING": ["POC_READY", "VERIFIED", "REPORTED"],
    "POC_READY": ["REPORTED"],
    "VERIFIED":  ["REPORTED", "POC_READY"],
    "REPORTED":  ["ACCEPTED", "REJECTED", "DUPLICATE"],
    "ACCEPTED":  ["PAID"],
    "REJECTED":  [],
    "DUPLICATE": [],
    "PAID":      [],
}

# ── Transitions that require delete+recreate ──────────────────────────────────
REQUIRES_RESET: dict[str, list[str]] = {
    "POC_READY": ["DRAFT", "VERIFIED", "ANALYZING"],
    "REPORTED":  ["DRAFT", "ANALYZING", "POC_READY", "VERIFIED"],
    "ACCEPTED":  ["DRAFT", "ANALYZING", "POC_READY", "VERIFIED", "REPORTED", "REJECTED", "DUPLICATE"],
    "REJECTED":  ["DRAFT", "ANALYZING", "POC_READY", "VERIFIED", "REPORTED", "ACCEPTED", "DUPLICATE"],
    "DUPLICATE": ["DRAFT", "ANALYZING", "POC_READY", "VERIFIED", "REPORTED", "ACCEPTED", "REJECTED"],
    "PAID":      ["DRAFT", "ANALYZING", "POC_READY", "VERIFIED", "REPORTED", "REJECTED", "DUPLICATE"],
}

# ── Category mappings ─────────────────────────────────────────────────────────
CATEGORY_MAP: dict[str, str] = {
    "lending":    "LENDING",
    "staking":    "STAKING",
    "oracle":     "ORACLE",
    "dex":        "DEX",
    "flash":      "OTHER",
    "vault":      "VAULT",
    "bridge":     "BRIDGE",
    "governance": "GOVERNANCE",
}
