"""Regression test for parse_fuzz_failures against real Foundry output.

Earlier versions of the regex expected the invariant name directly after
[FAIL...], but Foundry emits it at the END of the failure block (after the
[Sequence] and many sender=... lines). When that regex failed to match, the
pipeline logged "No fuzz failures in Phase 1" while the benchmark had actually
found real bugs — root cause of the 0-findings / 100%-recall contradiction.
"""
from __future__ import annotations

from pathlib import Path

from benchmark.component_pipeline.reporting import parse_fuzz_failures


FOUNDRY_FAIL_SNIPPET = """
Ran 2 tests for test/chimera/FoundryTester.sol:FoundryTester
[PASS] invariant_leverager_borrowedUSDBelowCap() (runs: 256, calls: 128000, reverts: 670)

Suite result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 74.98s (129.84s CPU time)

Failing tests:
Encountered 1 failing test in test/chimera/FoundryTester.sol:FoundryTester
[FAIL: panic: assertion failed (0x01)]
\t[Sequence] (original: 61, shrunk: 6)
\t\tsender=0x0000000000000000000000000000000000000264 addr=[test/chimera/FoundryTester.sol:FoundryTester]0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496 calldata=handler_withdraw(uint256,uint256,uint8) args=[132102026, 15518151, 210]
 invariant_leverager_noGhostTokenAccumulation() (runs: 1, calls: 500, reverts: 4)

Encountered a total of 1 failing tests, 1 tests succeeded

Ran 2 tests for test/chimera/FoundryTester.sol:FoundryTester
[PASS] invariant_something_else() (runs: 256, calls: 128000, reverts: 574)
[FAIL: panic: assertion failed (0x01)]
\t[Sequence] (original: 129, shrunk: 7)
\t\tsender=0xF3A151b1F16e898FA41a75A0f4493f9b6a624aAC addr=[test/chimera/FoundryTester.sol:FoundryTester]0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496 calldata=handler_skipTime(uint256) args=[65536]
 invariant_leverager_holdsNoTokens() (runs: 0, calls: 0, reverts: 3)
"""


def test_parse_foundry_fail_name_at_end_of_block(tmp_path: Path) -> None:
    log = tmp_path / "phase1_foundry.log"
    log.write_text(f"=== STDOUT ===\n{FOUNDRY_FAIL_SNIPPET}\n=== STDERR ===\n", encoding="utf-8")

    failures = parse_fuzz_failures(log)

    assert set(failures) == {
        "invariant_leverager_noGhostTokenAccumulation",
        "invariant_leverager_holdsNoTokens",
    }
    for name, trace in failures.items():
        assert "[FAIL" in trace
        assert name in trace


def test_parse_no_failures_returns_empty(tmp_path: Path) -> None:
    log = tmp_path / "clean.log"
    log.write_text(
        "=== STDOUT ===\n[PASS] invariant_foo() (runs: 256, calls: 128000, reverts: 0)\n"
        "=== STDERR ===\n",
        encoding="utf-8",
    )
    assert parse_fuzz_failures(log) == {}


def test_parse_missing_file_returns_empty(tmp_path: Path) -> None:
    assert parse_fuzz_failures(tmp_path / "does_not_exist.log") == {}
