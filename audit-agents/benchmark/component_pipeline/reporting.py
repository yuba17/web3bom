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

        # Foundry format: [FAIL...] starts a failure block. The invariant name
        # appears at the END of the block (after [Sequence] + sender=... lines)
        # on a line like: " invariant_xxx() (runs: N, calls: M, reverts: K)".
        # Walk each [FAIL...] marker and search up to the next [FAIL/[PASS boundary.
        fail_markers = list(re.finditer(r'\[FAIL[^\]]*\]', content))
        name_re = re.compile(
            r'(invariant_\w+|check_\w+|property_\w+|echidna_\w+)\(\)\s*\(runs:'
        )
        for idx, m in enumerate(fail_markers):
            block_start = m.start()
            block_end = fail_markers[idx + 1].start() if idx + 1 < len(fail_markers) else len(content)
            next_pass = content.find("[PASS]", m.end(), block_end)
            if next_pass != -1:
                block_end = next_pass
            block = content[block_start:block_end]
            name_m = name_re.search(block)
            if name_m:
                failed[name_m.group(1)] = block.strip()[:3000]

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
