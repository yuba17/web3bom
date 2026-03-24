"""Tests for scope_intake.py — bounty text parsing."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_parse_payouts():
    """Extract payout amounts from bounty text."""
    from scope_intake import parse_bounty_text

    text = """
    Critical: $250K - $2.5M
    High: $10K - $50K
    Medium: $3K-$10K
    Low: $1K-$3K
    """
    result = parse_bounty_text(text)
    assert result["payout"] != ""
    assert "$250K" in result["payout"] or "250" in result["payout"]


def test_parse_exclusions():
    """Extract exclusion rules."""
    from scope_intake import parse_bounty_text

    text = """
    Out of Scope:
    - Issues resulting solely from deployer parameter choices
    - Design choices of the protocols
    - Known issues from previous audits
    """
    result = parse_bounty_text(text)
    assert len(result["exclusions"]) >= 2


def test_parse_commits():
    """Extract commit hashes."""
    from scope_intake import parse_bounty_text

    text = "The audit covers commit 55d2d99 on branch main. Also check 7d638ad."
    result = parse_bounty_text(text)
    assert "55d2d99" in result["commits"]


def test_parse_empty_text():
    """Empty text returns empty fields, no crash."""
    from scope_intake import parse_bounty_text

    result = parse_bounty_text("")
    assert result["payout"] == ""
    assert result["exclusions"] == []
    assert result["commits"] == []
