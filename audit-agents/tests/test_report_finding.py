"""
Tests para report_finding.py y submit_finding.py
Corre con: python3 -m pytest audit-agents/tests/ -v
Sin dependencias externas — no toca Bounty Radar ni current_hunt.json
"""

import sys
import pytest
from pathlib import Path

# Añadir audit-agents al path
sys.path.insert(0, str(Path(__file__).parent.parent))

from report_finding import (
    estimate_payout,
    escape_telegram_md,
    COMPETITION_PCT,
    BUG_BOUNTY_PCT,
    SEVERITY_MAP,
)
from submit_finding import (
    RADAR_TO_LOCAL,
    ALLOWED_PATCH,
    REQUIRES_RESET,
)


# ── estimate_payout ───────────────────────────────────────────────────────────

class TestEstimatePayout:
    def test_competition_high_50k(self):
        mn, mx = estimate_payout("HIGH", 50000, "competition")
        assert mn == 3000
        assert mx == 7500

    def test_competition_critical_50k(self):
        mn, mx = estimate_payout("CRITICAL", 50000, "competition")
        assert mn == 10000
        assert mx == 25000

    def test_competition_medium_50k(self):
        mn, mx = estimate_payout("MEDIUM", 50000, "competition")
        assert mn == 1000
        assert mx == 3000

    def test_bug_bounty_high_50k(self):
        mn, mx = estimate_payout("HIGH", 50000, "bug_bounty")
        assert mn == 7500
        assert mx == 20000

    def test_bug_bounty_critical_50k(self):
        mn, mx = estimate_payout("CRITICAL", 50000, "bug_bounty")
        assert mn == 20000
        assert mx == 50000

    def test_zero_pool_returns_none(self):
        mn, mx = estimate_payout("HIGH", 0, "competition")
        assert mn is None
        assert mx is None

    def test_default_program_type_is_bug_bounty(self):
        # Sin program_type, debe usar bug_bounty
        mn_default, mx_default = estimate_payout("HIGH", 50000)
        mn_bb, mx_bb = estimate_payout("HIGH", 50000, "bug_bounty")
        assert mn_default == mn_bb
        assert mx_default == mx_bb

    def test_competition_lower_than_bug_bounty(self):
        # Competición siempre da menos que bug_bounty para misma severidad y pool
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            mn_c, mx_c = estimate_payout(sev, 100000, "competition")
            mn_b, mx_b = estimate_payout(sev, 100000, "bug_bounty")
            assert mx_c < mx_b, f"{sev}: competition max should be < bug_bounty max"

    def test_min_less_than_max(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            for ptype in ["competition", "bug_bounty"]:
                mn, mx = estimate_payout(sev, 50000, ptype)
                assert mn <= mx, f"{sev}/{ptype}: min={mn} should be <= max={mx}"


# ── escape_telegram_md ────────────────────────────────────────────────────────

class TestEscapeTelegramMd:
    def test_escapes_backticks(self):
        result = escape_telegram_md("`feeValue=0`")
        assert r"\`" in result
        assert "`" not in result.replace(r"\`", "")

    def test_escapes_brackets(self):
        result = escape_telegram_md("[VV-O-02] finding")
        assert r"\[" in result
        assert r"\]" in result

    def test_plain_text_unchanged(self):
        text = "Hello world this is a normal message"
        assert escape_telegram_md(text) == text

    def test_bold_asterisks_preserved(self):
        # Los asteriscos para *bold* NO deben escaparse
        text = "*Finding registrado* — HIGH"
        result = escape_telegram_md(text)
        assert "*" in result

    def test_real_finding_title(self):
        title = "[VV-O-02] Staked position health check sets `feeValue=0`"
        result = escape_telegram_md(title)
        assert r"\`" in result
        assert r"\[" in result


# ── Title length ──────────────────────────────────────────────────────────────

class TestTitleLength:
    def _build_title(self, finding_id, description):
        prefix_len = len(f"[{finding_id}] ")
        body = description[:120 - prefix_len].rstrip('.')
        return f"[{finding_id}] {body}"

    def test_title_max_120_short_id(self):
        title = self._build_title("VV-O-02", "x" * 200)
        assert len(title) <= 120

    def test_title_max_120_long_id(self):
        title = self._build_title("VERY-LONG-ID-01", "x" * 200)
        assert len(title) <= 120

    def test_title_includes_finding_id(self):
        title = self._build_title("GM-A-08", "Some description")
        assert "[GM-A-08]" in title

    def test_title_exact_120_chars(self):
        finding_id = "VV-O-02"
        description = "x" * 200
        title = self._build_title(finding_id, description)
        assert len(title) == 120

    def test_short_description_not_padded(self):
        title = self._build_title("VV-O-02", "Short desc")
        assert len(title) < 120
        assert "Short desc" in title


# ── Status mappings ───────────────────────────────────────────────────────────

class TestStatusMappings:
    def test_all_radar_statuses_have_local_mapping(self):
        expected = {"DRAFT", "ANALYZING", "POC_READY", "VERIFIED",
                    "REPORTED", "ACCEPTED", "REJECTED", "DUPLICATE", "PAID"}
        assert expected == set(RADAR_TO_LOCAL.keys())

    def test_reported_maps_to_submitted(self):
        assert RADAR_TO_LOCAL["REPORTED"] == "submitted"

    def test_accepted_maps_to_accepted(self):
        assert RADAR_TO_LOCAL["ACCEPTED"] == "accepted"

    def test_verified_and_poc_ready_map_to_registered(self):
        assert RADAR_TO_LOCAL["VERIFIED"] == "registered"
        assert RADAR_TO_LOCAL["POC_READY"] == "registered"

    def test_paid_maps_to_paid(self):
        assert RADAR_TO_LOCAL["PAID"] == "paid"


# ── State machine transitions ─────────────────────────────────────────────────

class TestStateMachine:
    def test_verified_can_go_to_reported(self):
        assert "REPORTED" in ALLOWED_PATCH["VERIFIED"]

    def test_reported_can_only_go_to_outcomes(self):
        allowed = set(ALLOWED_PATCH["REPORTED"])
        assert allowed == {"ACCEPTED", "REJECTED", "DUPLICATE"}

    def test_reported_requires_reset_to_go_back(self):
        assert "VERIFIED" in REQUIRES_RESET["REPORTED"]
        assert "POC_READY" in REQUIRES_RESET["REPORTED"]
        assert "DRAFT" in REQUIRES_RESET["REPORTED"]

    def test_terminal_states_have_no_forward_patch(self):
        # REJECTED y DUPLICATE no tienen transiciones hacia adelante vía PATCH
        assert ALLOWED_PATCH.get("REJECTED", []) == []
        assert ALLOWED_PATCH.get("DUPLICATE", []) == []

    def test_all_statuses_in_allowed_patch(self):
        # Todos los estados deben tener una entrada en ALLOWED_PATCH
        all_statuses = set(RADAR_TO_LOCAL.keys())
        for s in all_statuses:
            assert s in ALLOWED_PATCH, f"Status {s} missing from ALLOWED_PATCH"

    def test_no_self_transitions(self):
        # Ningún estado puede transicionar a sí mismo
        for status, targets in ALLOWED_PATCH.items():
            assert status not in targets, f"{status} → {status} self-transition not allowed"


# ── SEVERITY_MAP ──────────────────────────────────────────────────────────────

class TestSeverityMap:
    def test_lowercase_to_uppercase(self):
        assert SEVERITY_MAP["high"] == "HIGH"
        assert SEVERITY_MAP["critical"] == "CRITICAL"
        assert SEVERITY_MAP["medium"] == "MEDIUM"
        assert SEVERITY_MAP["low"] == "LOW"

    def test_unknown_maps_to_medium(self):
        assert SEVERITY_MAP["unknown"] == "MEDIUM"
