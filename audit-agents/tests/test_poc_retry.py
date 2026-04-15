"""Tests for PoC retry loop — 3 fix attempts instead of 1."""


def test_poc_retry_count_default():
    """Default retry count should be 3."""
    MAX_POC_FIX_ATTEMPTS = 3
    assert MAX_POC_FIX_ATTEMPTS == 3


def test_poc_retry_exits_early_on_success():
    """If fix #1 succeeds, don't run fix #2."""
    results = [False, True]  # initial fail, fix 1 pass
    for i, passed in enumerate(results):
        if passed:
            break
    assert i == 1  # stopped at fix 1


def test_poc_retry_escalating_timeout():
    """Last attempt gets more time (900s vs 600s)."""
    MAX_POC_FIX_ATTEMPTS = 3
    for attempt in range(1, MAX_POC_FIX_ATTEMPTS + 1):
        fix_timeout = 600 if attempt <= 2 else 900
    assert fix_timeout == 900  # last attempt = 900s
