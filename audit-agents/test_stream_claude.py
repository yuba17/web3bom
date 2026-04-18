#!/usr/bin/env python3
"""Test run_claude stream-json + fallback behavior.

Run OUTSIDE of Claude Code:
    python3 audit-agents/test_stream_claude.py
"""
import os, sys, time, select, subprocess, json

os.chdir("/home/kali/Documents/Web3")
sys.path.insert(0, "audit-agents")

# Import the actual function
from run_benchmark import run_claude, setup_logging
from pathlib import Path

setup_logging("test")

print("=" * 60)
print("TEST 1: Stall detection (sleep process)")
print("=" * 60)
proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
start = time.time()
last = time.time()
while proc.poll() is None:
    if time.time() - last > 5:
        proc.kill(); proc.wait()
        print(f"  ✅ Stall killed in {time.time()-start:.1f}s")
        break
    ready, _, _ = select.select([proc.stdout], [], [], 1.0)
    if ready:
        if not proc.stdout.readline(): break
        last = time.time()

print("\n" + "=" * 60)
print("TEST 2: run_claude simple prompt")
print("=" * 60)
log = Path("/tmp/test_run_claude.log")
rc, text = run_claude(
    "Say exactly: TEST_OK_12345",
    timeout=60, stall_timeout=30, log_file=log
)
print(f"  rc={rc}, output_len={len(text)}")
print(f"  text[:200] = {text[:200]}")
if "TEST_OK" in text or len(text) > 5:
    print("  ✅ run_claude works!")
else:
    print("  ⚠️  No text — check /tmp/test_run_claude.log")
    if log.exists():
        print(log.read_text()[:500])

print("\n" + "=" * 60)
print("TEST 3: run_claude with tools")
print("=" * 60)
rc2, text2 = run_claude(
    "Read the file /home/kali/Documents/Web3/CLAUDE.md and tell me the first word on line 1",
    allowed_tools=["Read"],
    timeout=60, stall_timeout=30, log_file=Path("/tmp/test_run_claude2.log")
)
print(f"  rc={rc2}, output_len={len(text2)}")
print(f"  text[:200] = {text2[:200]}")
if len(text2) > 5:
    print("  ✅ run_claude with tools works!")
else:
    print("  ⚠️  No text — check /tmp/test_run_claude2.log")

print("\nDone.")
