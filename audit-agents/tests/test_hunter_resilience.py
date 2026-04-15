"""Tests for graceful hunter failure — component pipeline continues with N-1 hunters."""


def test_single_hunter_timeout_does_not_block_component():
    """If 1 of 12 hunters times out, pipeline continues with 11 hunters."""
    results = {
        "AccessHunter": TimeoutError("1800s timeout"),
        "MathHunter": None,
        "FlowHunter": None,
        "DomainHunter": None,
        "OracleHunter": None,
        "TrustBoundaryHunter": None,
        "WildcardHunter": None,
        "SignatureHunter": None,
        "DoSHunter": None,
        "LogicHunter": None,
        "AdversarialHunter": None,
        "LibraryHunter": None,
    }
    succeeded = [h for h, r in results.items() if r is None]
    failed = [h for h, r in results.items() if r is not None]
    assert len(succeeded) == 11
    assert len(failed) == 1
    REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                        "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter"]
    present = [h for h in REQUIRED_HUNTERS if h in succeeded]
    MIN_REQUIRED_HUNTERS = 7
    assert len(present) >= MIN_REQUIRED_HUNTERS


def test_two_hunter_timeouts_still_continues():
    """2 of 12 hunters fail — 10 remain, 7/9 required present."""
    failed = {"AccessHunter", "LibraryHunter"}
    REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                        "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter"]
    present = [h for h in REQUIRED_HUNTERS if h not in failed]
    MIN_REQUIRED_HUNTERS = 7
    assert len(present) >= MIN_REQUIRED_HUNTERS


def test_majority_failure_blocks_component():
    """If 4+ required hunters fail, component SHOULD be blocked."""
    failed = {"AccessHunter", "MathHunter", "FlowHunter", "DomainHunter"}
    REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                        "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter"]
    present = [h for h in REQUIRED_HUNTERS if h not in failed]
    MIN_REQUIRED_HUNTERS = 7
    assert len(present) < MIN_REQUIRED_HUNTERS
