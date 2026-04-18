"""Phase 2B scaffolding smoke tests."""
from __future__ import annotations

from pathlib import Path

import yaml


def test_tmp_cards_dir_has_eight_files(tmp_cards_dir: Path):
    files = sorted(p.name for p in tmp_cards_dir.glob("*.yaml"))
    assert len(files) == 8
    assert "access_control_existing_incidents.yaml" in files
    assert "lending_r2_new_patterns.yaml" in files


def test_tmp_cards_yaml_loads(tmp_cards_dir: Path):
    payload = yaml.safe_load(
        (tmp_cards_dir / "access_control_existing_incidents.yaml").read_text()
    )
    assert "access-001-new-incidents" in payload
    assert isinstance(payload["access-001-new-incidents"], list)


def test_tmp_vault_has_solodit_subdir(tmp_vault: Path):
    assert (tmp_vault / "solodit").is_dir()
