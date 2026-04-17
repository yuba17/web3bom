"""Contract tests for benchmark output schemas over a frozen session."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml


# Extension point: adding a new language = adding a row here + dropping goldens
# and fixtures under `fixtures/<language>/<benchmark>/`. No test rewrites needed.
#   ("rust", "<benchmark>"),        # TODO(phase-2+): enable when Rust path migrated
#   ("move", "<benchmark>"),        # TODO(phase-2+): Aptos/Sui targets
#   ("cairo", "<benchmark>"),       # TODO(phase-2+): Starknet targets
LANGUAGE_BENCHMARK_MATRIX = [("solidity", "yieldoor")]


# Required top-level keys for every hypothesis file.
# PLAN vs REALITY delta:
#   Plan assumed {"title", "component", "confidence", "severity", "invariant"} at top-level.
#   Reality: top-level has {"component", "hypotheses"} for Leverager files, but only
#   {"hypotheses"} for ReserveLogic and Vault files — 'component' is optional.
#   Hypotheses are a nested list with per-item keys: id, tier, type, description,
#   attack_scenario, solidity_property, validated, priority, confidence, vulnerable_location.
#   Adjusted to the minimal guaranteed key: {"hypotheses"}.
HYP_REQUIRED = {"hypotheses"}


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_hyp_yaml_has_required_fields(language: str, benchmark: str, frozen_session_fixture):
    session = frozen_session_fixture("v12")
    hyp_dir = session / "hypotheses" / benchmark
    yamls = sorted(hyp_dir.glob("hyp_*.yaml"))
    assert yamls, f"No hypothesis files found in {hyp_dir}"
    errors: list[str] = []
    for yml in yamls:
        try:
            data = yaml.safe_load(yml.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{yml.name}: YAML parse error — {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{yml.name}: top-level must be a dict, got {type(data).__name__}")
            continue
        missing = HYP_REQUIRED - set(data.keys())
        if missing:
            errors.append(f"{yml.name}: missing keys {sorted(missing)}")
    assert not errors, "Schema failures:\n  " + "\n  ".join(errors)


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_hyp_yaml_solidity_section_present(language: str, benchmark: str, frozen_session_fixture):
    """Every yieldoor hypothesis should expose solidity_property on each hypothesis item.

    PLAN vs REALITY delta:
      Plan assumed a 'solidity' sub-dict at top level with key 'invariant_solidity'.
      Reality: each item in the 'hypotheses' list has a 'solidity_property' key directly.
      Adjusted to match actual schema.
    """
    if language != "solidity":
        pytest.skip(f"solidity-specific contract test")
    session = frozen_session_fixture("v12")
    hyp_dir = session / "hypotheses" / benchmark
    yamls = sorted(hyp_dir.glob("hyp_*.yaml"))
    missing: list[str] = []
    for yml in yamls:
        data = yaml.safe_load(yml.read_text())
        hypotheses = data.get("hypotheses")
        if not isinstance(hypotheses, list) or not hypotheses:
            missing.append(f"{yml.name}: no hypotheses list")
            continue
        items_without = [
            i
            for i, h in enumerate(hypotheses)
            if not (isinstance(h, dict) and "solidity_property" in h)
        ]
        if items_without:
            missing.append(f"{yml.name}: items without solidity_property at indices {items_without[:5]}")
    assert not missing, (
        (
            f"Hypotheses without solidity_property: {missing[:10]}"
            f" (and {len(missing)-10} more)"
        )
        if len(missing) > 10
        else f"Hypotheses without solidity_property: {missing}"
    )


FINDING_REQUIRED = {"id", "component", "severity", "confidence"}


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_findings_all_json_schema(language: str, benchmark: str, frozen_session_fixture):
    session = frozen_session_fixture("v12")
    path = session / "findings_all.json"
    assert path.exists(), f"Missing {path}"
    data = json.loads(path.read_text())
    # Top-level may be dict with 'findings' key OR a bare list — normalize
    findings = data.get("findings") if isinstance(data, dict) else data
    assert isinstance(findings, list), (
        f"Expected findings[] in {path}, got {type(findings).__name__}"
    )
    errors: list[str] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errors.append(f"findings[{i}]: not a dict")
            continue
        missing = FINDING_REQUIRED - set(f.keys())
        if missing:
            errors.append(f"findings[{i}] ({f.get('id','?')}): missing {sorted(missing)}")
    assert not errors, "Schema failures:\n  " + "\n  ".join(errors)


CHECKPOINT_REQUIRED = {"completed_steps", "failed_steps"}


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_checkpoint_json_schema(language: str, benchmark: str, frozen_session_fixture):
    session = frozen_session_fixture("v12")
    checkpoints = sorted(session.glob("checkpoint*.json"))
    assert checkpoints, f"No checkpoint*.json in {session}"
    errors: list[str] = []
    for cp in checkpoints:
        data = json.loads(cp.read_text())
        missing = CHECKPOINT_REQUIRED - set(data.keys())
        if missing:
            errors.append(f"{cp.name}: missing {sorted(missing)}")
        if not isinstance(data.get("completed_steps", []), list):
            errors.append(f"{cp.name}: completed_steps must be a list")
        # PLAN vs REALITY delta:
        #   Plan assumed failed_steps is a list. Reality: it's a dict mapping
        #   step_name -> error_message (or empty dict when no failures).
        #   Adjusted to accept dict.
        if not isinstance(data.get("failed_steps", {}), (list, dict)):
            errors.append(f"{cp.name}: failed_steps must be a list or dict")
    assert not errors, "Schema failures:\n  " + "\n  ".join(errors)


@pytest.mark.parametrize("language,benchmark", LANGUAGE_BENCHMARK_MATRIX)
def test_hunter_performance_schema(language: str, benchmark: str, frozen_session_fixture):
    session = frozen_session_fixture("v12")
    path = session / "hunter_performance.json"
    if not path.exists():
        # Fall back to current session if v12 lacks it
        path = session.parent / "bench_session" / "hunter_performance.json"
        if not path.exists():
            pytest.skip(f"hunter_performance.json not present in v12 or current session")
    data = json.loads(path.read_text())
    assert isinstance(data, dict), (
        f"Top-level must be dict, got {type(data).__name__}"
    )
    # PLAN vs REALITY delta:
    #   Plan assumed top-level was a dict keyed by hunter name.
    #   Reality: top-level has {"protocol", "generated_at", "hunters"} where
    #   "hunters" is a list of dicts, each with keys like hunter, total_hypotheses,
    #   validated_hypotheses, etc.
    #   Adjusted to validate the hunters list schema instead.
    hunters = data.get("hunters")
    assert isinstance(hunters, list), (
        f"Expected hunters[] list in hunter_performance.json, got {type(hunters).__name__}"
    )
    for i, record in enumerate(hunters):
        assert isinstance(record, dict), f"hunters[{i}] must be dict, got {type(record).__name__}"
        assert "hunter" in record, f"hunters[{i}] missing 'hunter' key"
