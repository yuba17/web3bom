#!/usr/bin/env python3
"""Minimal test: what does claude -p stream-json actually output?"""
import os, subprocess, time

env = os.environ.copy()
env.pop("CLAUDECODE", None)

# Test A: stream-json
print("=== TEST A: stream-json ===")
proc = subprocess.Popen(
    ["claude", "-p", "Say hello", "--output-format", "stream-json"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
)
try:
    out, err = proc.communicate(timeout=30)
    print(f"STDOUT ({len(out)} bytes): {out[:500]}")
    print(f"STDERR ({len(err)} bytes): {err[:500]}")
    print(f"EXIT: {proc.returncode}")
except subprocess.TimeoutExpired:
    proc.kill()
    out, err = proc.communicate()
    print(f"TIMEOUT. STDOUT ({len(out)} bytes): {out[:500]}")
    print(f"STDERR ({len(err)} bytes): {err[:500]}")

print()

# Test B: text (known working)
print("=== TEST B: text ===")
proc2 = subprocess.Popen(
    ["claude", "-p", "Say hello", "--output-format", "text"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
)
try:
    out2, err2 = proc2.communicate(timeout=30)
    print(f"STDOUT ({len(out2)} bytes): {out2[:500]}")
    print(f"STDERR ({len(err2)} bytes): {err2[:500]}")
    print(f"EXIT: {proc2.returncode}")
except subprocess.TimeoutExpired:
    proc2.kill()
    out2, err2 = proc2.communicate()
    print(f"TIMEOUT. STDOUT ({len(out2)} bytes): {out2[:500]}")
    print(f"STDERR ({len(err2)} bytes): {err2[:500]}")

print()

# Test C: json
print("=== TEST C: json ===")
proc3 = subprocess.Popen(
    ["claude", "-p", "Say hello", "--output-format", "json"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
)
try:
    out3, err3 = proc3.communicate(timeout=30)
    print(f"STDOUT ({len(out3)} bytes): {out3[:500]}")
    print(f"STDERR ({len(err3)} bytes): {err3[:500]}")
    print(f"EXIT: {proc3.returncode}")
except subprocess.TimeoutExpired:
    proc3.kill()
    out3, err3 = proc3.communicate()
    print(f"TIMEOUT. STDOUT ({len(out3)} bytes): {out3[:500]}")
    print(f"STDERR ({len(err3)} bytes): {err3[:500]}")
