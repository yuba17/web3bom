#!/usr/bin/env python3
"""compile_fixer.py — Compile-fix loop for Properties.sol

After merge_invariants.py inserts hunter-generated Solidity into Properties.sol,
many invariants won't compile because hunters wrote code referencing variables
that don't exist in the Chimera setup.

This script:
1. Runs `forge build` and collects errors
2. Identifies which property_* functions have errors
3. Comments out broken functions (preserving them for manual review)
4. Repeats up to max_attempts times until compilation succeeds

Usage:
    python3 audit-agents/compile_fixer.py [--repo <path>] [--max-attempts 9] [--dry-run]
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


def run_forge_build(repo_path: Path) -> tuple[bool, str]:
    """Run forge build and return (success, stderr)."""
    result = subprocess.run(
        ["forge", "build"],
        capture_output=True, text=True,
        cwd=str(repo_path),
        env={**__import__("os").environ, "FOUNDRY_PROFILE": "chimera"},
        timeout=300,
    )
    return result.returncode == 0, result.stderr + result.stdout


def extract_error_lines(build_output: str, filename: str = "Properties.sol") -> set[int]:
    """Extract line numbers with errors from forge build output."""
    pattern = rf"{re.escape(filename)}:(\d+):\d+"
    return {int(m.group(1)) for m in re.finditer(pattern, build_output)}


def find_all_property_functions(source: str) -> list[tuple[str, int, int]]:
    """Find ALL property_*/optimize_* functions with their line ranges (1-indexed).
    Returns list of (function_name, start_line, end_line)."""
    functions = []
    lines = source.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        fn_match = re.match(r'\s*function\s+(property_\w+|optimize_\w+)\s*\(', line)
        if fn_match:
            fn_name = fn_match.group(1)
            fn_start = i + 1  # 1-indexed
            depth = 0
            j = i
            while j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                if depth <= 0 and j > i:
                    fn_end = j + 1  # 1-indexed
                    break
                j += 1
            else:
                fn_end = len(lines)
            functions.append((fn_name, fn_start, fn_end))
            i = j + 1
        else:
            i += 1
    return functions


def find_broken_functions(source: str, error_lines: set[int]) -> list[tuple[str, int, int]]:
    """Find property_*/optimize_* functions containing error lines.
    Also detects stray code between functions and attributes it to nearest function.
    Returns list of (function_name, start_line, end_line) 1-indexed."""
    all_fns = find_all_property_functions(source)
    if not all_fns:
        return []

    broken = []
    for fn_name, fn_start, fn_end in all_fns:
        if any(fn_start <= el <= fn_end for el in error_lines):
            broken.append((fn_name, fn_start, fn_end))

    # Check for errors BETWEEN functions (stray code from bad _clean_solidity_body)
    remaining_errors = set()
    for el in error_lines:
        if not any(fn_start <= el <= fn_end for _, fn_start, fn_end in all_fns):
            remaining_errors.add(el)

    if remaining_errors:
        # Map stray errors to the nearest PRECEDING function
        for el in remaining_errors:
            best_fn = None
            for fn_name, fn_start, fn_end in all_fns:
                if fn_end < el:
                    best_fn = (fn_name, fn_start, fn_end)
            if best_fn and best_fn not in broken:
                # Extend the function range to include the stray code up to the next function
                fn_name, fn_start, fn_end = best_fn
                next_fn_start = None
                for _, ns, _ in all_fns:
                    if ns > fn_end:
                        next_fn_start = ns
                        break
                extended_end = (next_fn_start - 1) if next_fn_start else fn_end + 20
                broken.append((fn_name, fn_start, extended_end))

    return broken


def auto_fix_common_errors(source: str, build_output: str) -> tuple[str, int]:
    """Try to fix common compilation errors before resorting to commenting out.
    Returns (fixed_source, num_fixes)."""
    fixes = 0

    # Fix 1: Remove nested function declarations (hunters wrap body in function)
    # Pattern: function invariant_xxx() public returns (bool) {
    nested_fn = re.compile(
        r'^(\s+)function\s+\w+\([^)]*\)\s*(?:public|internal|external)?\s*(?:returns\s*\([^)]*\))?\s*\{',
        re.MULTILINE
    )
    # Only remove if it's INSIDE a property_* function (indented more than 4 spaces)
    for m in nested_fn.finditer(source):
        indent = len(m.group(1))
        if indent >= 8:  # nested inside a property_* function
            source = source[:m.start()] + m.group(1) + "// (nested fn removed by compile_fixer)" + source[m.end():]
            fixes += 1

    # Fix 2: Remove 'return true;' remnants from invariant wrappers
    source = re.sub(r'^\s+return true;\s*$', '', source, flags=re.MULTILINE)

    # Fix 3: Fix unbalanced braces from nested function removal
    # Count braces per property_* function and add missing closing braces
    lines = source.split("\n")
    i = 0
    new_lines = []
    while i < len(lines):
        new_lines.append(lines[i])
        fn_match = re.match(r'\s*function\s+(property_\w+|optimize_\w+)\s*\(', lines[i])
        if fn_match:
            depth = 0
            j = i
            while j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                if depth <= 0 and j > i:
                    break
                j += 1
            # If we ran to end of file without closing, braces are unbalanced
            if j >= len(lines) - 1 and depth > 0:
                # Don't fix here - let comment_out handle it
                pass
        i += 1
    source = "\n".join(new_lines)

    # Fix 4: Replace common undeclared identifiers with their Chimera equivalents
    replacements = {
        'activeTokenIds': 'ghost_allTokenIds',
        'asset': 'vault.asset()',
        'ASSET': 'vault.asset()',
        'deal(': 'vm.deal(',
    }
    for old, new in replacements.items():
        if old in source:
            # Only replace within property_* functions (after merge marker)
            marker_pos = source.find("Invariantes añadidos por merge_invariants")
            if marker_pos > 0:
                before = source[:marker_pos]
                after = source[marker_pos:]
                count = after.count(old)
                if count > 0:
                    after = after.replace(old, new)
                    fixes += count
                    source = before + after

    # Fix 5: Remove unicode characters in string literals
    def replace_unicode_in_strings(match):
        s = match.group(0)
        s = s.replace('\u2014', '--').replace('\u2013', '-')
        s = s.replace('\u2018', "'").replace('\u2019', "'")
        s = s.replace('\u201c', '"').replace('\u201d', '"')
        return s.encode('ascii', 'replace').decode('ascii')

    source = re.sub(r'"[^"]*"', replace_unicode_in_strings, source)

    # Fix 6: Remove duplicate variable declarations within same scope
    # (ghost vars declared both in merge header and in function body)
    # This is handled by merge_invariants.py, but just in case

    return source, fixes


def comment_out_functions(source: str, broken_fns: list[tuple[str, int, int]]) -> str:
    """Comment out broken functions, preserving them for review."""
    lines = source.split("\n")

    for fn_name, start, end in broken_fns:
        # Look backwards from start for comment block
        comment_start = start - 1  # 0-indexed
        while comment_start > 0:
            prev = lines[comment_start - 1].strip()
            if prev.startswith("//") or prev.startswith("///") or prev == "":
                comment_start -= 1
            else:
                break

        # Comment out from comment_start to end (0-indexed)
        for idx in range(comment_start, end):
            if idx < len(lines):
                line = lines[idx]
                if line.strip() and not line.strip().startswith("/*"):
                    lines[idx] = f"    /* COMPILE_FIX: {line.strip()} */"

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Fix Properties.sol compilation errors")
    parser.add_argument("--repo", default=None, help="Repo path (auto-detected from current_hunt.json)")
    parser.add_argument("--max-attempts", type=int, default=9, help="Max fix attempts")
    parser.add_argument("--dry-run", action="store_true", help="Don't modify files")
    args = parser.parse_args()

    # Detect repo path
    if args.repo:
        repo_path = Path(args.repo)
    else:
        import json
        hunt_state = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"
        if hunt_state.exists():
            data = json.loads(hunt_state.read_text())
            repo_path = Path(data.get("repo_path", "."))
        else:
            repo_path = Path(".")

    properties_path = None
    for p in repo_path.rglob("Properties.sol"):
        if p.is_file() and "chimera" in str(p):
            properties_path = p
            break

    if not properties_path:
        print("✗ Properties.sol not found")
        return 1

    print(f"Properties.sol: {properties_path}")
    print(f"Repo: {repo_path}")

    # Phase 1: Try auto-fix first (smart replacements)
    print("\n--- Phase 1: Auto-fix common errors ---")
    source = properties_path.read_text()
    # Run a preliminary build to get errors
    success, output = run_forge_build(repo_path)
    if success:
        print("✅ Compilación exitosa sin fixes necesarios")
        return 0

    fixed_source, num_fixes = auto_fix_common_errors(source, output)
    if num_fixes > 0:
        print(f"  Auto-fixed {num_fixes} common errors")
        properties_path.write_text(fixed_source)
        # Try compiling after auto-fix
        success, output = run_forge_build(repo_path)
        if success:
            print("✅ Compilación exitosa después de auto-fix")
            return 0
        print(f"  Auto-fix no fue suficiente, continuando con comment-out loop...")
    else:
        print("  No auto-fixes aplicables")

    # Phase 2: Comment-out loop for remaining errors
    print("\n--- Phase 2: Comment-out broken functions ---")
    for attempt in range(1, args.max_attempts + 1):
        print(f"\n{'='*50}")
        print(f"  Compile attempt {attempt}/{args.max_attempts}")
        print(f"{'='*50}")

        success, output = run_forge_build(repo_path)

        if success:
            print(f"\n✅ Compilación exitosa en intento {attempt}")
            return 0

        error_lines = extract_error_lines(output)
        if not error_lines:
            print(f"✗ Build falló pero no se encontraron errores en Properties.sol:")
            print(output[-1000:])
            return 1

        print(f"  Errores en líneas: {sorted(error_lines)}")

        source = properties_path.read_text()
        broken_fns = find_broken_functions(source, error_lines)

        if not broken_fns:
            print(f"✗ Errores detectados pero no se pudieron mapear a funciones property_*/optimize_*")
            print(f"  Líneas con error: {sorted(error_lines)}")
            print(output[-2000:])
            return 1

        print(f"  Funciones rotas ({len(broken_fns)}):")
        for fn_name, start, end in broken_fns:
            print(f"    - {fn_name} (líneas {start}-{end})")

        # NEVER comment out original functions (those above the merge marker)
        merge_marker = "Invariantes añadidos por merge_invariants"
        source_text = properties_path.read_text()
        merge_line = None
        for idx, line in enumerate(source_text.split("\n"), 1):
            if merge_marker in line:
                merge_line = idx
                break

        if merge_line:
            protected = [(fn, s, e) for fn, s, e in broken_fns if s < merge_line]
            broken_fns = [(fn, s, e) for fn, s, e in broken_fns if s >= merge_line]
            if protected:
                print(f"  ⚠ Protegidas (originales): {[fn for fn, _, _ in protected]}")
                if not broken_fns:
                    print(f"  ✗ Solo funciones originales tienen errores — ghost var collision probable")
                    print(f"    Revisa ghost vars duplicadas entre originales y nuevas")
                    return 1

        if args.dry_run:
            print("  [DRY RUN] No se modifica nada")
            return 1

        new_source = comment_out_functions(source, broken_fns)
        properties_path.write_text(new_source)
        print(f"  → {len(broken_fns)} funciones comentadas")

    print(f"\n✗ No se logró compilar en {args.max_attempts} intentos")
    return 1


if __name__ == "__main__":
    sys.exit(main())
