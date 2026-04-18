#!/usr/bin/env python3
"""
clippy_to_prepass.py — Convert cargo clippy JSON output to prepass YAML format.

Reads JSON lines from stdin (cargo clippy --message-format=json) and produces
a {name}_prepass.yaml file compatible with detection_engine.py output.

Also adds Soroban-specific exploit pattern detection by grepping source files.

Usage:
    cargo clippy -p endpoint-v2 --all-targets --message-format=json 2>/dev/null | \
        python3 clippy_to_prepass.py --name endpoint-v2 --output /path/to/results/ \
        --src-dir /path/to/crate/src
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def parse_clippy_json(lines: list[str]) -> list[dict]:
    """Parse clippy JSON output into finding dicts."""
    findings = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        if msg.get("reason") != "compiler-message":
            continue

        message = msg.get("message", {})
        level = message.get("level", "")
        if level not in ("warning", "error"):
            continue

        code = message.get("code", {})
        code_str = code.get("code", "") if isinstance(code, dict) else ""
        rendered = message.get("rendered", "")
        text = message.get("message", "")

        # Extract primary span
        spans = message.get("spans", [])
        primary = next((s for s in spans if s.get("is_primary")), spans[0] if spans else {})
        file_name = primary.get("file_name", "unknown")
        line_start = primary.get("line_start", 0)

        severity = "high" if level == "error" else "medium"

        findings.append({
            "id": code_str or f"clippy-{len(findings)}",
            "severity": severity,
            "description": text,
            "file": file_name,
            "line": line_start,
            "rendered": rendered[:500],
        })

    return findings


# Soroban-specific exploit patterns to grep for
SOROBAN_PATTERNS = [
    {
        "id": "SOROBAN-TTL-01",
        "pattern": r"\.set\(|\.update\(",
        "anti_pattern": "extend_ttl",
        "severity": "medium",
        "description": "Storage write without TTL extension — entry may expire and cause state loss",
        "check": "storage_without_ttl",
    },
    {
        "id": "SOROBAN-AUTH-01",
        "pattern": r"pub\s+fn\s+\w+",
        "anti_pattern": "require_auth",
        "severity": "high",
        "description": "Public function potentially missing require_auth() call",
        "check": "pub_fn_without_auth",
    },
    {
        "id": "SOROBAN-OVERFLOW-01",
        "pattern": r"wrapping_add|wrapping_sub|wrapping_mul",
        "anti_pattern": None,
        "severity": "high",
        "description": "Wrapping arithmetic detected — may cause silent overflow",
        "check": "simple_grep",
    },
    {
        "id": "SOROBAN-UNSAFE-01",
        "pattern": r"\bunsafe\s",
        "anti_pattern": None,
        "severity": "high",
        "description": "Unsafe block detected — review for memory safety",
        "check": "simple_grep",
    },
    {
        "id": "SOROBAN-UNWRAP-01",
        "pattern": r"\.unwrap\(\)",
        "anti_pattern": None,
        "severity": "medium",
        "description": "Unwrap call may panic — consider proper error handling in contract code",
        "check": "simple_grep",
    },
    {
        "id": "SOROBAN-PANIC-01",
        "pattern": r"panic!\(|todo!\(|unimplemented!\(",
        "anti_pattern": None,
        "severity": "medium",
        "description": "Explicit panic/todo macro — contract will trap on this path",
        "check": "simple_grep",
    },
    {
        "id": "SOROBAN-BYTES32-01",
        "pattern": r"BytesN<32>|bytes32|to_array|from_slice",
        "anti_pattern": None,
        "severity": "medium",
        "description": "bytes32/BytesN conversion detected — check truncation and padding correctness",
        "check": "simple_grep",
    },
    {
        "id": "SOROBAN-NONCE-01",
        "pattern": r"nonce|sequence|msg_id",
        "anti_pattern": None,
        "severity": "medium",
        "description": "Nonce/sequence handling detected — check replay protection and ordering",
        "check": "simple_grep",
    },
]


def scan_soroban_patterns(src_dir: Path) -> list[dict]:
    """Scan .rs source files for Soroban-specific exploit patterns.

    Returns list of finding dicts compatible with clippy findings.
    """
    findings: list[dict] = []

    if not src_dir.exists():
        return findings

    # Read all non-test .rs files
    rs_files: list[tuple[Path, str, list[str]]] = []
    for rs_file in sorted(src_dir.rglob("*.rs")):
        # Skip test files
        if "test" in rs_file.parts or rs_file.name.startswith("test_"):
            continue
        try:
            content = rs_file.read_text(encoding="utf-8")
            lines = content.splitlines()
            rs_files.append((rs_file, content, lines))
        except Exception:
            continue

    if not rs_files:
        return findings

    for pattern_def in SOROBAN_PATTERNS:
        check_type = pattern_def["check"]

        if check_type == "simple_grep":
            # Direct regex match — presence is the signal
            regex = re.compile(pattern_def["pattern"])
            for rs_file, content, lines in rs_files:
                for i, line in enumerate(lines, 1):
                    if regex.search(line):
                        findings.append({
                            "id": pattern_def["id"],
                            "severity": pattern_def["severity"],
                            "description": pattern_def["description"],
                            "file": str(rs_file),
                            "line": i,
                        })

        elif check_type == "pub_fn_without_auth":
            # Find public functions that don't call require_auth within their body
            fn_regex = re.compile(r"pub\s+fn\s+(\w+)")
            for rs_file, content, lines in rs_files:
                # Skip lib.rs (just re-exports) and mod files
                if rs_file.name in ("lib.rs", "mod.rs"):
                    continue
                in_fn = False
                fn_name = ""
                fn_line = 0
                brace_depth = 0
                fn_body = ""
                for i, line in enumerate(lines, 1):
                    if not in_fn:
                        m = fn_regex.search(line)
                        if m:
                            fn_name = m.group(1)
                            fn_line = i
                            in_fn = True
                            brace_depth = 0
                            fn_body = ""
                    if in_fn:
                        fn_body += line + "\n"
                        brace_depth += line.count("{") - line.count("}")
                        if brace_depth <= 0 and "{" in fn_body:
                            # Function body complete — check for auth
                            # Skip trivial getters, view functions, and test helpers
                            is_view = any(kw in fn_body for kw in [
                                "-> Result<", "-> bool", "-> u32", "-> u64", "-> i128",
                                "-> BytesN", "-> Bytes", "-> Address", "-> String",
                                "-> Vec<", "-> Map<",
                            ])
                            has_auth = "require_auth" in fn_body or "check_auth" in fn_body
                            has_write = any(kw in fn_body for kw in [
                                ".set(", ".update(", ".remove(", "transfer(",
                                "mint(", "burn(", "approve(",
                            ])
                            # Flag: public + writes state + no auth
                            if has_write and not has_auth and not is_view:
                                findings.append({
                                    "id": pattern_def["id"],
                                    "severity": pattern_def["severity"],
                                    "description": f"{pattern_def['description']}: `{fn_name}` writes state but has no require_auth",
                                    "file": str(rs_file),
                                    "line": fn_line,
                                })
                            in_fn = False

        elif check_type == "storage_without_ttl":
            # Find storage .set() calls not followed by extend_ttl in same function
            set_regex = re.compile(r"\.(set|update)\(")
            ttl_regex = re.compile(r"extend_ttl|bump\(")
            for rs_file, content, lines in rs_files:
                # Check per-function: if function does .set() but no extend_ttl
                fn_regex = re.compile(r"fn\s+(\w+)")
                in_fn = False
                fn_name = ""
                fn_line = 0
                brace_depth = 0
                fn_body = ""
                for i, line in enumerate(lines, 1):
                    if not in_fn:
                        m = fn_regex.search(line)
                        if m:
                            fn_name = m.group(1)
                            fn_line = i
                            in_fn = True
                            brace_depth = 0
                            fn_body = ""
                    if in_fn:
                        fn_body += line + "\n"
                        brace_depth += line.count("{") - line.count("}")
                        if brace_depth <= 0 and "{" in fn_body:
                            has_set = set_regex.search(fn_body) is not None
                            has_ttl = ttl_regex.search(fn_body) is not None
                            if has_set and not has_ttl:
                                findings.append({
                                    "id": pattern_def["id"],
                                    "severity": pattern_def["severity"],
                                    "description": f"{pattern_def['description']}: `{fn_name}` writes storage without TTL extension",
                                    "file": str(rs_file),
                                    "line": fn_line,
                                })
                            in_fn = False

    return findings


def main():
    parser = argparse.ArgumentParser(description="Convert clippy JSON to prepass YAML")
    parser.add_argument("--name", required=True, help="Component name")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--src-dir", default="", help="Path to crate src/ for Soroban pattern scanning")
    args = parser.parse_args()

    # Read clippy JSON from stdin
    lines = sys.stdin.readlines()
    findings = parse_clippy_json(lines)

    # Scan for Soroban-specific patterns if src-dir provided
    soroban_findings: list[dict] = []
    if args.src_dir:
        src_path = Path(args.src_dir)
        soroban_findings = scan_soroban_patterns(src_path)
        findings.extend(soroban_findings)

    # Write YAML output
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{args.name}_prepass.yaml"

    yaml_lines = [
        f"component: {args.name}",
        f"tool: cargo-clippy+soroban-patterns",
        f"total_findings: {len(findings)}",
        f"clippy_findings: {len(findings) - len(soroban_findings)}",
        f"soroban_pattern_findings: {len(soroban_findings)}",
        "findings:",
    ]
    for f in findings:
        yaml_lines.append(f"  - id: {f['id']}")
        yaml_lines.append(f"    severity: {f['severity']}")
        # Escape quotes in description for YAML safety
        desc = f['description'].replace('"', '\\"')
        yaml_lines.append(f'    description: "{desc}"')
        yaml_lines.append(f'    file: "{f["file"]}"')
        yaml_lines.append(f"    line: {f['line']}")

    out_path.write_text("\n".join(yaml_lines) + "\n")
    print(f"Prepass written to {out_path} ({len(findings)} findings: {len(findings) - len(soroban_findings)} clippy + {len(soroban_findings)} soroban patterns)")


if __name__ == "__main__":
    main()
