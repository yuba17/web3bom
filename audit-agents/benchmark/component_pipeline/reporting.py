"""Fuzz log parsing — pure utility extracted from run_benchmark.parse_fuzz_failures.

Pure stdlib-only function. Used by runner.py for in-flight Phase 1 result
parsing and by run_benchmark shim for downstream callers.
"""

from __future__ import annotations

from pathlib import Path


def parse_fuzz_failures(phase1_log: Path, phase2_log: Path = None) -> dict[str, str]:
    """Parse Foundry/Medusa output to find which invariant functions failed.

    Returns dict mapping failed function names to their counterexample traces.
    e.g. {'invariant_xxx': 'Call sequence: sender=0xBEEF, vault.deposit(1000)...'}
    """
    failed = {}
    import re

    for log_path in [phase1_log, phase2_log]:
        if not log_path or not log_path.exists():
            continue
        content = log_path.read_text(encoding="utf-8", errors="replace")

        # Only parse the STDOUT section — avoid matching text from the prompt
        if "=== STDOUT ===" in content:
            content = content.split("=== STDOUT ===")[1]
            if "=== STDERR ===" in content:
                content = content.split("=== STDERR ===")[0]

        # Foundry format: [FAIL. Reason: ...] invariant_xxx() or property_xxx() (runs: ...)
        for m in re.finditer(r'\[FAIL[^\]]*\]\s+(invariant_\w+|check_\w+|property_\w+)\(\)', content):
            name = m.group(1)
            # Extract counterexample trace — everything from this FAIL line to next test or end
            fail_pos = m.start()
            # Look for the trace section after this failure
            trace_end = content.find("[PASS]", fail_pos + 1)
            trace_end2 = content.find("[FAIL", fail_pos + 1)
            if trace_end == -1:
                trace_end = len(content)
            if trace_end2 != -1 and trace_end2 < trace_end:
                trace_end = trace_end2
            trace = content[fail_pos:trace_end].strip()[:3000]
            failed[name] = trace

        # Medusa format: "assertion failed" or "property violated" with function name
        for m in re.finditer(r'(?:assertion failed|property violated).*?(invariant_\w+|check_\w+|property_\w+)', content):
            name = m.group(1)
            fail_pos = m.start()
            # Capture surrounding context as trace
            trace_start = max(0, fail_pos - 500)
            trace_end = min(len(content), fail_pos + 2000)
            trace = content[trace_start:trace_end].strip()[:3000]
            if name not in failed:
                failed[name] = trace

        # Also catch: "Failing tests:" section
        for m in re.finditer(r'FAIL.*?\]\s+(\w+)\(\)', content):
            name = m.group(1)
            if name.startswith(("invariant_", "check_", "echidna_", "property_")) and name not in failed:
                fail_pos = m.start()
                trace_end = content.find("\n\n", fail_pos + 1)
                if trace_end == -1:
                    trace_end = min(len(content), fail_pos + 2000)
                failed[name] = content[fail_pos:trace_end].strip()[:3000]

    return failed
