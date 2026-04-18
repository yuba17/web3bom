#!/usr/bin/env python3
"""
[BENCHMARK-IMPROVE-4] Parameter Boundary Scanner

Extracts configurable parameters from Solidity contracts and generates
edge-case hypotheses. Addresses benchmark gaps M-03 and M-08:
- tickSpacing=1 → integer division yields 0
- decimals()=8 (WBTC) → interest truncation

Scans for:
1. Constructor arguments (immutable config)
2. Setter-configurable values (governance-changeable)
3. External calls that return config (decimals(), tickSpacing(), etc.)
4. Hardcoded magic numbers with implicit assumptions

Outputs YAML hypotheses for injection into hunter context.
"""

import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class Parameter:
    name: str
    source: str  # "constructor", "setter", "external_call", "magic_number"
    type_hint: str  # "uint256", "int24", "uint8", etc.
    location: str  # "Contract.sol:L42"
    used_in: list = field(default_factory=list)  # functions that use it
    division_contexts: list = field(default_factory=list)  # where it's used as divisor
    edge_values: list = field(default_factory=list)  # suggested edge cases


# Known DeFi parameters with dangerous edge values
KNOWN_EDGE_PARAMS = {
    "decimals": {"values": [6, 8, 18, 0], "risk": "precision loss with low decimals (USDC=6, WBTC=8)"},
    "tickSpacing": {"values": [1, 10, 60, 200], "risk": "integer division by tickSpacing/2 yields 0 when tickSpacing=1"},
    "fee": {"values": [0, 1, 100, 10000, 1000000], "risk": "zero fee bypasses, max fee DoS"},
    "maxLeverage": {"values": [1e18, 2e18, 100e18], "risk": "leverage=1 makes base=infinity, leverage=2 is boundary"},
    "minCollateral": {"values": [0, 1, 1e6], "risk": "zero collateral, dust amounts"},
    "duration": {"values": [0, 1, 2**32 - 1], "risk": "zero duration, single block, overflow"},
    "threshold": {"values": [0, 1, 100], "risk": "zero threshold bypasses all checks"},
    "slippage": {"values": [0, 1, 10000], "risk": "zero slippage = no protection, max = always revert"},
    "weight": {"values": [0, 1, 1e18], "risk": "zero weight, unity weight, max weight"},
    "ratePerSecond": {"values": [0, 1, 1e18 // 365 // 86400], "risk": "zero rate, dust rate, extreme rate"},
    "maxAmount": {"values": [0, 1, 2**256 - 1], "risk": "zero cap, dust cap, uncapped"},
}


def extract_constructor_params(source: str, filename: str) -> list[Parameter]:
    """Extract parameters from constructor arguments."""
    params = []
    # Match constructor with its parameters
    ctor_match = re.search(r'constructor\s*\(([^)]*)\)', source, re.DOTALL)
    if not ctor_match:
        return params

    ctor_args = ctor_match.group(1)
    line_num = source[:ctor_match.start()].count('\n') + 1

    # Parse each parameter
    for match in re.finditer(r'(u?int\d*|address|bool|bytes\d*)\s+(?:memory\s+|calldata\s+)?(\w+)', ctor_args):
        type_hint, name = match.group(1), match.group(2)
        # Find where this param is stored (assignment in constructor body)
        body_start = source.find('{', ctor_match.end())
        if body_start > 0:
            body_end = _find_matching_brace(source, body_start)
            body = source[body_start:body_end] if body_end > 0 else source[body_start:body_start + 2000]
            # Look for assignment patterns: stateVar = paramName
            assignments = re.findall(rf'(\w+)\s*=\s*{re.escape(name)}', body)
            stored_as = assignments[0] if assignments else name
        else:
            stored_as = name

        p = Parameter(
            name=stored_as,
            source="constructor",
            type_hint=type_hint,
            location=f"{filename}:L{line_num}",
        )
        _find_usage_contexts(source, stored_as, p, filename)
        _suggest_edge_values(p)
        params.append(p)

    return params


def extract_setter_params(source: str, filename: str) -> list[Parameter]:
    """Extract parameters set via setter functions (governance-configurable)."""
    params = []
    # Match setter patterns: function setX(type val) { stateVar = val; }
    setter_pattern = re.compile(
        r'function\s+set(\w+)\s*\(([^)]*)\)[^{]*\{([^}]{1,500})\}',
        re.DOTALL
    )
    for match in setter_pattern.finditer(source):
        setter_name = match.group(1)
        args = match.group(2)
        body = match.group(3)
        line_num = source[:match.start()].count('\n') + 1

        # Extract the parameter being set
        for arg_match in re.finditer(r'(u?int\d*|address|bool|bytes\d*)\s+(\w+)', args):
            type_hint, param_name = arg_match.group(1), arg_match.group(2)
            # What state variable does it set?
            assignments = re.findall(rf'(\w+)\s*=\s*{re.escape(param_name)}', body)
            stored_as = assignments[0] if assignments else param_name

            p = Parameter(
                name=stored_as,
                source="setter",
                type_hint=type_hint,
                location=f"{filename}:L{line_num}",
            )
            _find_usage_contexts(source, stored_as, p, filename)
            _suggest_edge_values(p)
            params.append(p)

    return params


def extract_external_params(source: str, filename: str) -> list[Parameter]:
    """Extract parameters fetched from external calls (decimals(), tickSpacing(), etc.)."""
    params = []
    # Match external calls that return config values
    external_patterns = [
        (r'\.decimals\(\)', "decimals", "uint8"),
        (r'\.tickSpacing\(\)', "tickSpacing", "int24"),
        (r'slot0\(\)', "slot0", "struct"),
        (r'\.totalSupply\(\)', "totalSupply", "uint256"),
        (r'\.balanceOf\(', "balanceOf", "uint256"),
        (r'\.latestRoundData\(\)', "oraclePrice", "int256"),
        (r'\.fee\(\)', "poolFee", "uint24"),
        (r'\.liquidity\(\)', "liquidity", "uint128"),
    ]

    for pattern, name, type_hint in external_patterns:
        for match in re.finditer(pattern, source):
            line_num = source[:match.start()].count('\n') + 1
            # Check if the result is used in division or comparison
            line_end = source.find('\n', match.end())
            line_context = source[match.start():line_end] if line_end > 0 else source[match.start():match.start() + 200]

            p = Parameter(
                name=name,
                source="external_call",
                type_hint=type_hint,
                location=f"{filename}:L{line_num}",
            )
            _find_usage_contexts(source, name, p, filename)
            # Also check the line context for immediate division
            if '/' in line_context or '%' in line_context:
                p.division_contexts.append(f"{filename}:L{line_num} (immediate)")
            _suggest_edge_values(p)

            # Deduplicate by name — only keep first occurrence
            if not any(existing.name == name for existing in params):
                params.append(p)

    return params


def extract_division_patterns(source: str, filename: str) -> list[dict]:
    """Find all division/modulo operations and identify the divisor source."""
    patterns = []
    for match in re.finditer(r'(\w+(?:\.\w+)*)\s*/\s*(\w+(?:\.\w+|\(\))*)', source):
        dividend, divisor = match.group(1), match.group(2)
        line_num = source[:match.start()].count('\n') + 1
        # Skip obvious safe divisions (by constants > 1)
        if re.match(r'^\d+$', divisor) and int(divisor) > 1:
            continue
        patterns.append({
            "dividend": dividend,
            "divisor": divisor,
            "location": f"{filename}:L{line_num}",
            "risk": f"If {divisor}=0 → revert. If {divisor}=1 → no-op. If {divisor} is very large → truncation to 0.",
        })

    for match in re.finditer(r'(\w+(?:\.\w+)*)\s*%\s*(\w+(?:\.\w+|\(\))*)', source):
        dividend, divisor = match.group(1), match.group(2)
        line_num = source[:match.start()].count('\n') + 1
        if re.match(r'^\d+$', divisor) and int(divisor) > 1:
            continue
        patterns.append({
            "dividend": dividend,
            "divisor": divisor,
            "location": f"{filename}:L{line_num}",
            "risk": f"If {divisor}=0 → revert. Negative modulo in Solidity truncates toward zero (not floor).",
        })

    return patterns


def _find_matching_brace(source: str, start: int) -> int:
    """Find the matching closing brace for an opening brace at position start."""
    depth = 0
    for i in range(start, min(start + 50000, len(source))):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_usage_contexts(source: str, var_name: str, param: Parameter, filename: str):
    """Find where a parameter is used, especially in division/comparison."""
    # Find functions that reference this variable
    func_pattern = re.compile(r'function\s+(\w+)\s*\([^)]*\)[^{]*\{', re.DOTALL)
    for func_match in func_pattern.finditer(source):
        func_name = func_match.group(1)
        body_start = source.find('{', func_match.end() - 1)
        body_end = _find_matching_brace(source, body_start) if body_start > 0 else -1
        if body_end < 0:
            continue
        body = source[body_start:body_end]
        if var_name in body:
            param.used_in.append(func_name)
            # Check for division context
            div_pattern = re.compile(rf'[/|%]\s*{re.escape(var_name)}(?:\s*[;,\)]|\s*[-+*/])')
            for div_match in div_pattern.finditer(body):
                line_num = source[:body_start + div_match.start()].count('\n') + 1
                param.division_contexts.append(f"{filename}:L{line_num} in {func_name}()")


def _suggest_edge_values(param: Parameter):
    """Suggest edge values based on parameter name and type."""
    name_lower = param.name.lower()

    # Check known params first
    for known_name, known_data in KNOWN_EDGE_PARAMS.items():
        if known_name.lower() in name_lower:
            param.edge_values = [
                {"value": v, "risk": known_data["risk"]}
                for v in known_data["values"]
            ]
            return

    # Generic suggestions by type
    if "int8" in param.type_hint or "uint8" in param.type_hint:
        param.edge_values = [
            {"value": 0, "risk": "zero value — may bypass or break math"},
            {"value": 1, "risk": "minimum non-zero — division may truncate"},
            {"value": 255, "risk": "max uint8 — overflow boundary"},
        ]
    elif "int24" in param.type_hint:
        param.edge_values = [
            {"value": 0, "risk": "zero — division/modulo by zero"},
            {"value": 1, "risk": "minimum — integer division truncates to zero"},
            {"value": -1, "risk": "negative — modulo correction needed"},
            {"value": 8388607, "risk": "max int24 — overflow boundary"},
        ]
    elif "int" in param.type_hint:
        param.edge_values = [
            {"value": 0, "risk": "zero — may bypass checks or break math"},
            {"value": 1, "risk": "minimum — rounding/truncation issues"},
            {"value": "type(uint256).max", "risk": "max — overflow in multiplication"},
        ]


def scan_contract(contract_path: Path) -> dict:
    """Main entry: scan a contract for parameter boundary issues."""
    source = contract_path.read_text()
    filename = contract_path.name

    params = []
    params.extend(extract_constructor_params(source, filename))
    params.extend(extract_setter_params(source, filename))
    params.extend(extract_external_params(source, filename))

    divisions = extract_division_patterns(source, filename)

    # Generate hypotheses
    hypotheses = []
    seen = set()

    for p in params:
        if not p.division_contexts and not p.edge_values:
            continue
        key = (p.name, p.source)
        if key in seen:
            continue
        seen.add(key)

        for edge in p.edge_values:
            hyp = {
                "parameter": p.name,
                "source": p.source,
                "type": p.type_hint,
                "defined_at": p.location,
                "edge_value": edge["value"],
                "risk": edge["risk"],
                "used_in_functions": p.used_in[:5],
                "division_contexts": p.division_contexts[:3],
            }
            hypotheses.append(hyp)

    # Add division-specific hypotheses
    for div in divisions:
        hypotheses.append({
            "parameter": div["divisor"],
            "source": "division_operand",
            "defined_at": div["location"],
            "risk": div["risk"],
            "used_in_functions": [],
            "division_contexts": [div["location"]],
        })

    return {
        "contract": filename,
        "parameters_found": len(params),
        "division_patterns": len(divisions),
        "hypotheses": hypotheses,
    }


def format_for_hunter_prompt(scan_result: dict) -> str:
    """Format scan results as text for injection into hunter prompts."""
    if not scan_result.get("hypotheses"):
        return ""

    lines = [
        f"# Parameter Boundary Analysis — {scan_result['contract']}",
        f"# {scan_result['parameters_found']} configurable parameters, "
        f"{scan_result['division_patterns']} division patterns found",
        "",
        "# EDGE CASES TO TEST (each may reveal truncation, overflow, or DoS):",
    ]

    # Group by parameter
    by_param = {}
    for hyp in scan_result["hypotheses"]:
        key = hyp["parameter"]
        if key not in by_param:
            by_param[key] = []
        by_param[key].append(hyp)

    for param_name, hyps in list(by_param.items())[:15]:  # cap at 15 params
        lines.append(f"\n## {param_name} ({hyps[0].get('source', '?')})")
        if hyps[0].get("defined_at"):
            lines.append(f"   Defined: {hyps[0]['defined_at']}")
        if hyps[0].get("used_in_functions"):
            lines.append(f"   Used in: {', '.join(hyps[0]['used_in_functions'][:5])}")
        if hyps[0].get("division_contexts"):
            lines.append(f"   ⚠ Division contexts: {hyps[0]['division_contexts'][:3]}")
        for hyp in hyps[:4]:  # max 4 edges per param
            val = hyp.get("edge_value", "?")
            risk = hyp.get("risk", "")
            lines.append(f"   - value={val}: {risk}")

    return "\n".join(lines)


def format_as_yaml(scan_result: dict) -> str:
    """Format as YAML for standalone output."""
    import yaml

    output = {
        "contract": scan_result["contract"],
        "scan_summary": {
            "parameters_found": scan_result["parameters_found"],
            "division_patterns": scan_result["division_patterns"],
            "hypotheses_generated": len(scan_result["hypotheses"]),
        },
        "hypotheses": scan_result["hypotheses"][:30],  # cap output
    }
    return yaml.dump(output, default_flow_style=False, allow_unicode=True, sort_keys=False)


def main():
    parser = argparse.ArgumentParser(description="Parameter Boundary Scanner")
    parser.add_argument("contract", type=Path, help="Path to Solidity contract")
    parser.add_argument("--format", choices=["yaml", "prompt", "json"], default="yaml",
                        help="Output format")
    parser.add_argument("--output", type=Path, help="Output file (default: stdout)")
    args = parser.parse_args()

    if not args.contract.exists():
        print(f"Error: {args.contract} not found", file=sys.stderr)
        sys.exit(1)

    result = scan_contract(args.contract)

    if args.format == "prompt":
        output = format_for_hunter_prompt(result)
    elif args.format == "json":
        import json
        output = json.dumps(result, indent=2, default=str)
    else:
        output = format_as_yaml(result)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
        print(f"✓ Output written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
