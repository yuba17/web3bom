"""Phase 2B shared fixtures."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture
def tmp_cards_dir(tmp_path: Path) -> Path:
    """Directory with 8 minimal Solodit-shaped YAML cards across 2 categories.

    Layout mirrors real knowledge/solodit_cards/: one YAML per
    (category, suffix) combination. Each YAML is a dict of
    `pattern-id-suffix: [bullet, bullet, ...]`.
    """
    cards = tmp_path / "cards"
    cards.mkdir()
    payloads = {
        "access_control_existing_incidents.yaml": {
            "access-001-new-incidents": [
                "Protocol X -- unrestricted setAdmin (high)",
                "Protocol Y -- init re-entry gave attacker control (critical)",
            ],
        },
        "access_control_new_patterns.yaml": {
            "access-020-new-patterns": [
                "Two-step ownership transfer missing accept step",
            ],
        },
        "access_control_r2_incidents.yaml": {
            "access-003-r2-incidents": [
                "Project Z -- role check bypassed via delegate call (medium)",
            ],
        },
        "access_control_r2_new_patterns.yaml": {
            "access-025-r2-new-patterns": [
                "Role revocation clears pending grants inconsistently",
            ],
        },
        "lending_existing_incidents.yaml": {
            "lending-001-new-incidents": [
                "Protocol L -- bad-debt socialization miscount (critical)",
            ],
        },
        "lending_new_patterns.yaml": {
            "lending-010-new-patterns": [
                "Interest accrual missing on partial repay",
            ],
        },
        "lending_r2_incidents.yaml": {
            "lending-002-r2-incidents": [
                "Protocol M -- liquidation close factor rounding (high)",
            ],
        },
        "lending_r2_new_patterns.yaml": {
            "lending-015-r2-new-patterns": [
                "Price cache stale across block boundary",
            ],
        },
    }
    for name, payload in payloads.items():
        (cards / name).write_text(yaml.safe_dump(payload, sort_keys=False))
    return cards


@pytest.fixture
def tmp_vault(tmp_path: Path) -> Path:
    """Empty vault-shaped directory with a `solodit/` subdir ready to receive pages."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "solodit").mkdir()
    return vault
