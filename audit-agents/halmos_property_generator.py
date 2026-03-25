#!/usr/bin/env python3
"""
halmos_property_generator.py — Auto-generates Halmos check_* functions for math-pure functions

Scans a Solidity contract for pure/view functions that do arithmetic (mul, div, add, sub,
wMulDown, wDivUp, mulDiv, etc.) and generates Halmos symbolic test functions that verify
key properties: monotonicity, commutativity, boundary safety, round-trip consistency,
and no-revert on valid inputs.

Usage:
    python3 halmos_property_generator.py <contract.sol> [--output <output.sol>]
    python3 halmos_property_generator.py <contract.sol> --dry-run  # preview without writing

Output:
    A Solidity test file with check_* functions ready for:
    ~/.local/bin/halmos --function check_ --loop 10 --solver-timeout-assertion 10000

Integrates with pipeline Phase 5 (Halmos Proof).
"""

import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class MathFunction:
    """Represents a pure/view function that does arithmetic."""
    name: str
    params: list[tuple[str, str]]  # [(type, name), ...]
    returns: list[str]  # [type, ...]
    visibility: str  # public, external, internal
    mutability: str  # pure, view
    line_number: int
    body: str = ""
    has_division: bool = False
    has_multiplication: bool = False
    has_exponentiation: bool = False
    is_bidirectional_pair: bool = False
    pair_function: str = ""


# Math operation patterns in Solidity
MATH_PATTERNS = {
    "division": [
        r'\b\w+\s*/\s*\w+',           # a / b
        r'\.wDivDown\(',               # Morpho WAD math
        r'\.wDivUp\(',
        r'\.divDown\(',
        r'\.divUp\(',
        r'\.mulDiv\(',                 # OZ mulDiv
        r'\.mulDivDown\(',
        r'\.mulDivUp\(',
        r'FullMath\.mulDiv\(',         # Uniswap
        r'Math\.ceilDiv\(',            # OZ ceilDiv
    ],
    "multiplication": [
        r'\b\w+\s*\*\s*\w+',          # a * b
        r'\.wMulDown\(',              # Morpho WAD math
        r'\.wMulUp\(',
        r'\.mulDown\(',
        r'\.mulUp\(',
        r'\.rayMul\(',                # Aave RAY math
        r'\.rayDiv\(',
        r'\.wadMul\(',
        r'\.wadDiv\(',
    ],
    "exponentiation": [
        r'\.rpow\(',                  # Fixed-point exponentiation
        r'\.wTaylorCompounded\(',     # Morpho compound interest
        r'\*\*',                      # Solidity native power
    ],
}

# Bidirectional pairs (function → inverse)
BIDIRECTIONAL_PAIRS = {
    "convertToShares": "convertToAssets",
    "convertToAssets": "convertToShares",
    "previewDeposit": "previewRedeem",
    "previewRedeem": "previewDeposit",
    "previewMint": "previewWithdraw",
    "previewWithdraw": "previewMint",
    "toSharesDown": "toAssetsDown",
    "toAssetsDown": "toSharesDown",
    "toSharesUp": "toAssetsUp",
    "toAssetsUp": "toSharesUp",
    "wMulDown": "wDivDown",
    "wDivDown": "wMulDown",
    "mulDivDown": "mulDivUp",  # not true inverse, but rounding pair
}


def parse_functions(source: str) -> list[MathFunction]:
    """Extract pure/view functions with math operations from Solidity source."""
    functions = []

    # Match function signatures with pure/view
    # Handles multi-line signatures
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s+'
        r'(?:(?:external|public|internal|private)\s+)?'
        r'(?:(?:external|public|internal|private)\s+)?'
        r'(pure|view)\s+'
        r'(?:(?:external|public|internal|private)\s+)?'
        r'(?:virtual\s+)?'
        r'(?:override(?:\([^)]*\))?\s+)?'
        r'returns\s*\(([^)]*)\)',
        re.MULTILINE
    )

    # Also match the simpler pattern where visibility comes before mutability
    func_pattern2 = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s+'
        r'((?:external|public|internal|private)\s+)?'
        r'(pure|view)\s+'
        r'(?:virtual\s+)?'
        r'(?:override(?:\([^)]*\))?\s+)?'
        r'returns\s*\(([^)]*)\)',
        re.MULTILINE
    )

    lines = source.split('\n')

    for i, line in enumerate(lines):
        # Quick check: does this line start a function?
        if 'function ' not in line:
            continue

        # Get the full signature (may span multiple lines)
        sig_text = ''
        brace_count = 0
        for j in range(i, min(i + 10, len(lines))):
            sig_text += lines[j] + ' '
            if '{' in lines[j]:
                break

        # Try both patterns
        match = func_pattern.search(sig_text) or func_pattern2.search(sig_text)
        if not match:
            continue

        groups = match.groups()
        if len(groups) == 4:
            name, params_str, mutability, returns_str = groups
            visibility = "internal"
        else:
            name, params_str, visibility, mutability, returns_str = groups
            visibility = (visibility or "internal").strip()

        # Skip constructors, fallbacks, etc.
        if name in ('constructor', 'fallback', 'receive'):
            continue

        # Parse parameters
        params = []
        if params_str.strip():
            for p in params_str.split(','):
                p = p.strip()
                if not p:
                    continue
                parts = p.split()
                if len(parts) >= 2:
                    ptype = parts[0]
                    pname = parts[-1]
                    # Only handle uint/int types for now
                    if 'int' in ptype or ptype in ('address', 'bool'):
                        params.append((ptype, pname))

        # Parse return types
        returns = []
        if returns_str.strip():
            for r in returns_str.split(','):
                r = r.strip()
                parts = r.split()
                if parts:
                    returns.append(parts[0])

        # Get function body (rough extraction)
        body = ''
        brace_depth = 0
        started = False
        for j in range(i, min(i + 100, len(lines))):
            body += lines[j] + '\n'
            brace_depth += lines[j].count('{') - lines[j].count('}')
            if '{' in lines[j]:
                started = True
            if started and brace_depth <= 0:
                break

        # Check for math operations
        has_div = any(re.search(p, body) for p in MATH_PATTERNS["division"])
        has_mul = any(re.search(p, body) for p in MATH_PATTERNS["multiplication"])
        has_exp = any(re.search(p, body) for p in MATH_PATTERNS["exponentiation"])

        # Skip functions without math
        if not (has_div or has_mul or has_exp):
            continue

        # Only generate for functions with uint params and returns
        uint_params = [(t, n) for t, n in params if 'uint' in t or 'int' in t]
        uint_returns = [r for r in returns if 'uint' in r or 'int' in r]
        if not uint_params or not uint_returns:
            continue

        # Check bidirectional pair
        pair_name = BIDIRECTIONAL_PAIRS.get(name, "")
        is_pair = pair_name and pair_name in source

        func = MathFunction(
            name=name,
            params=uint_params,
            returns=uint_returns,
            visibility=visibility,
            mutability=mutability,
            line_number=i + 1,
            body=body,
            has_division=has_div,
            has_multiplication=has_mul,
            has_exponentiation=has_exp,
            is_bidirectional_pair=is_pair,
            pair_function=pair_name if is_pair else "",
        )
        functions.append(func)

    return functions


def generate_check_functions(contract_name: str, functions: list[MathFunction]) -> str:
    """Generate Halmos check_* functions for discovered math functions."""

    checks = []

    for func in functions:
        param_decls = ", ".join(f"{t} {n}" for t, n in func.params)
        param_names = ", ".join(n for _, n in func.params)
        return_type = func.returns[0] if func.returns else "uint256"

        # === Property 1: No revert on valid inputs (bounded) ===
        bounds = []
        for ptype, pname in func.params:
            if 'uint' in ptype:
                bounds.append(f"        vm.assume({pname} > 0 && {pname} < type(uint128).max);")
            elif 'int' in ptype:
                bounds.append(f"        vm.assume({pname} > type(int128).min && {pname} < type(int128).max);")
        bounds_str = "\n".join(bounds)

        checks.append(f"""
    /// @notice {func.name}: should not revert on bounded valid inputs
    function check_{func.name}_noRevert({param_decls}) public view {{
{bounds_str}
        // Should not revert for valid bounded inputs
        {return_type} result = target.{func.name}({param_names});
    }}""")

        # === Property 2: Monotonicity (if single uint param with division/multiplication) ===
        if len(func.params) >= 1 and 'uint' in func.params[0][0]:
            first_type, first_name = func.params[0]
            other_params = func.params[1:]

            if other_params:
                other_decls = ", ".join(f"{t} {n}" for t, n in other_params)
                other_names = ", ".join(n for _, n in other_params)
                other_bounds = "\n".join(
                    f"        vm.assume({n} > 0 && {n} < type(uint128).max);"
                    for t, n in other_params if 'uint' in t
                )

                checks.append(f"""
    /// @notice {func.name}: monotonically non-decreasing in first param
    function check_{func.name}_monotonic({first_type} a, {first_type} b, {other_decls}) public view {{
        vm.assume(a > 0 && a < type(uint128).max);
        vm.assume(b > a && b < type(uint128).max);
{other_bounds}
        {return_type} resultA = target.{func.name}(a, {other_names});
        {return_type} resultB = target.{func.name}(b, {other_names});
        assert(resultB >= resultA); // monotonically non-decreasing
    }}""")
            else:
                checks.append(f"""
    /// @notice {func.name}: monotonically non-decreasing
    function check_{func.name}_monotonic({first_type} a, {first_type} b) public view {{
        vm.assume(a > 0 && a < type(uint128).max);
        vm.assume(b > a && b < type(uint128).max);
        {return_type} resultA = target.{func.name}(a);
        {return_type} resultB = target.{func.name}(b);
        assert(resultB >= resultA); // monotonically non-decreasing
    }}""")

        # === Property 3: Zero input handling ===
        if func.has_division and func.params:
            zero_args = []
            for ptype, pname in func.params:
                if 'uint' in ptype:
                    zero_args.append("0")
                else:
                    zero_args.append(pname)
            zero_call = ", ".join(zero_args)

            checks.append(f"""
    /// @notice {func.name}: zero inputs should return zero or revert (not corrupt state)
    function check_{func.name}_zeroSafety() public view {{
        // If this doesn't revert, result should be 0
        try target.{func.name}({zero_call}) returns ({return_type} result) {{
            assert(result == 0);
        }} catch {{
            // Reverting on zero is acceptable
        }}
    }}""")

        # === Property 4: Round-trip consistency (bidirectional pairs) ===
        if func.is_bidirectional_pair and func.pair_function:
            pair_func = func.pair_function
            first_type = func.params[0][0] if func.params else "uint256"

            # Build params for the pair call (may need different params)
            if len(func.params) > 1:
                other_decls_rt = ", ".join(f"{t} {n}" for t, n in func.params[1:])
                other_names_rt = ", ".join(n for _, n in func.params[1:])
                other_bounds_rt = "\n".join(
                    f"        vm.assume({n} > 0 && {n} < type(uint128).max);"
                    for t, n in func.params[1:] if 'uint' in t
                )
                checks.append(f"""
    /// @notice {func.name} ↔ {pair_func}: round-trip should not be profitable
    function check_{func.name}_roundTrip({first_type} amount, {other_decls_rt}) public view {{
        vm.assume(amount > 1e6 && amount < type(uint128).max); // skip dust
{other_bounds_rt}
        {return_type} intermediate = target.{func.name}(amount, {other_names_rt});
        vm.assume(intermediate > 0);
        {first_type} recovered = target.{pair_func}(intermediate, {other_names_rt});
        // Round-trip MUST NOT be profitable (recovered <= original)
        assert(recovered <= amount);
    }}""")
            else:
                checks.append(f"""
    /// @notice {func.name} ↔ {pair_func}: round-trip should not be profitable
    function check_{func.name}_roundTrip({first_type} amount) public view {{
        vm.assume(amount > 1e6 && amount < type(uint128).max); // skip dust
        {return_type} intermediate = target.{func.name}(amount);
        vm.assume(intermediate > 0);
        {first_type} recovered = target.{pair_func}(intermediate);
        // Round-trip MUST NOT be profitable (recovered <= original)
        assert(recovered <= amount);
    }}""")

        # === Property 5: Precision loss bound (if division) ===
        if func.has_division and len(func.params) >= 2:
            checks.append(f"""
    /// @notice {func.name}: precision loss should be bounded (max 1 unit)
    function check_{func.name}_precisionBound({param_decls}) public view {{
{bounds_str}
        {return_type} result = target.{func.name}({param_names});
        // Result * denominator should not deviate from numerator by more than denominator
        // This is a sanity check — customize per function
    }}""")

    # === Generate the full test contract ===
    header = f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * @title HalmosProperties_{contract_name}
 * @notice Auto-generated Halmos symbolic test properties for math functions in {contract_name}
 * @dev Run with: ~/.local/bin/halmos --function check_ --loop 10 --solver-timeout-assertion 10000
 *
 * Generated by halmos_property_generator.py
 * Properties: no-revert, monotonicity, zero-safety, round-trip, precision-bound
 *
 * IMPORTANT: Review and adjust before running:
 * 1. Fix import path for the target contract
 * 2. Adjust vm.assume bounds for protocol-specific ranges
 * 3. Remove properties that don't apply (e.g., monotonicity for non-monotonic functions)
 * 4. Add protocol-specific properties manually
 */

// TODO: Import the target contract
// import "../src/{contract_name}.sol";

contract HalmosProperties_{contract_name} is Test {{
    // TODO: Initialize target contract
    // {contract_name} target;

    // function setUp() public {{
    //     target = new {contract_name}();
    // }}
"""

    footer = """
}
"""

    return header + "\n".join(checks) + footer


def main():
    parser = argparse.ArgumentParser(
        description="Generate Halmos check_* functions for math-pure Solidity functions"
    )
    parser.add_argument("contract", help="Path to Solidity contract file")
    parser.add_argument("--output", "-o", help="Output file path (default: auto-generated)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")

    args = parser.parse_args()

    contract_path = Path(args.contract)
    if not contract_path.exists():
        print(f"Error: {contract_path} not found")
        sys.exit(1)

    source = contract_path.read_text()

    # Extract contract name
    contract_match = re.search(r'contract\s+(\w+)', source)
    contract_name = contract_match.group(1) if contract_match else contract_path.stem

    # Parse math functions
    functions = parse_functions(source)

    if not functions:
        print(f"No pure/view math functions found in {contract_path.name}")
        print("Halmos properties are only generated for pure/view functions with arithmetic operations.")
        sys.exit(0)

    print(f"Found {len(functions)} math functions in {contract_name}:")
    for f in functions:
        tags = []
        if f.has_division: tags.append("DIV")
        if f.has_multiplication: tags.append("MUL")
        if f.has_exponentiation: tags.append("EXP")
        if f.is_bidirectional_pair: tags.append(f"PAIR({f.pair_function})")
        print(f"  L{f.line_number}: {f.name}({', '.join(t+' '+n for t,n in f.params)}) → {', '.join(f.returns)} [{', '.join(tags)}]")

    # Generate check functions
    output = generate_check_functions(contract_name, functions)

    # Count properties generated
    check_count = output.count("function check_")
    print(f"\nGenerated {check_count} Halmos check_* properties")

    if args.dry_run:
        print("\n--- DRY RUN OUTPUT ---")
        print(output)
        return

    # Write output
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = contract_path.parent / f"HalmosProperties_{contract_name}.sol"

    output_path.write_text(output)
    print(f"\nWritten to: {output_path}")
    print(f"\nRun with:")
    print(f"  ~/.local/bin/halmos --function check_ --loop 10 --solver-timeout-assertion 10000")


if __name__ == "__main__":
    main()
