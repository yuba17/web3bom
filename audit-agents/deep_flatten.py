#!/usr/bin/env python3
"""
deep_flatten.py — Inlinea modifiers + funciones internas para ver la secuencia REAL de ejecución.

Para cada función, muestra: READ/WRITE/EXTERNAL en orden, inlineando calls internos.
Output se inyecta en el _context.md que leen los hunters.

Uso:
    python3 deep_flatten.py <sol_file> [--contract ContractName] [--functions fn1,fn2]
    python3 deep_flatten.py <sol_file> --critical-only   # solo funciones que mueven fondos

Requiere: pip install slither-analyzer
"""

import sys
import argparse
from pathlib import Path

try:
    from slither.slither import Slither
    HAS_SLITHER = True
except ImportError:
    HAS_SLITHER = False


# Patterns that indicate a function moves funds (critical for security)
CRITICAL_PATTERNS = {
    "transfer", "safeTransfer", "safeTransferFrom", "transferFrom",
    "call{value", "send(", "withdraw", "deposit", "mint", "burn",
    "swap", "liquidate", "repay", "borrow", "redeem", "claim",
}


def flatten_function(func, visited=None, depth=0, max_depth=10):
    """
    Recursively flatten a function, inlining internal calls and modifiers.
    Returns list of (depth, type, info) tuples.
    """
    if visited is None:
        visited = set()

    if func in visited or depth > max_depth:
        return []

    visited.add(func)
    entries = []

    # Contract and source location
    try:
        source_lines = func.source_mapping.lines if func.source_mapping else []
        line_range = f"L{source_lines[0]}-{source_lines[-1]}" if source_lines else "L?"
    except (AttributeError, IndexError):
        line_range = "L?"

    contract_name = func.contract_declarer.name if hasattr(func, 'contract_declarer') and func.contract_declarer else "?"

    entries.append((depth, "FUNC", f"[{contract_name}:{line_range}] {func.full_name}"))

    # Modifiers (inline them)
    try:
        for modifier in func.modifiers:
            entries.append((depth + 1, "MODIFIER", f"{modifier.full_name}"))
            # Recursively flatten modifier internals
            for call in getattr(modifier, 'internal_calls', []):
                if hasattr(call, 'contract_declarer'):
                    entries.extend(flatten_function(call, visited, depth + 2, max_depth))
    except AttributeError:
        pass

    # State variables read
    try:
        for var in func.state_variables_read:
            entries.append((depth + 1, "READ", var.name))
    except AttributeError:
        pass

    # State variables written
    try:
        for var in func.state_variables_written:
            entries.append((depth + 1, "WRITE", var.name))
    except AttributeError:
        pass

    # Internal calls (recursive inline)
    try:
        for call in func.internal_calls:
            if hasattr(call, 'contract_declarer'):
                entries.extend(flatten_function(call, visited, depth + 1, max_depth))
            elif hasattr(call, 'name'):
                entries.append((depth + 1, "INTERNAL", str(call)))
    except AttributeError:
        pass

    # External (high-level) calls — CRITICAL for security
    try:
        for (contract, ext_func) in func.high_level_calls:
            c_name = contract.name if hasattr(contract, 'name') else str(contract)
            f_name = ext_func.full_name if hasattr(ext_func, 'full_name') else str(ext_func)
            entries.append((depth + 1, "EXTERNAL", f"{c_name}.{f_name}"))
    except AttributeError:
        pass

    # Low-level calls
    try:
        for low_call in func.low_level_calls:
            entries.append((depth + 1, "LOW_CALL", str(low_call)))
    except AttributeError:
        pass

    return entries


def format_trace(entries):
    """Format flattened trace as readable string."""
    lines = []
    for depth, entry_type, info in entries:
        indent = "  " * depth
        if entry_type == "FUNC":
            lines.append(f"{indent}[{entry_type}] {info}")
        elif entry_type == "MODIFIER":
            lines.append(f"{indent}[{entry_type}] {info}")
        elif entry_type == "READ":
            lines.append(f"{indent}  READ: {info}")
        elif entry_type == "WRITE":
            lines.append(f"{indent}  WRITE: {info}")
        elif entry_type == "EXTERNAL":
            lines.append(f"{indent}  [EXTERNAL] {info}")
        elif entry_type == "LOW_CALL":
            lines.append(f"{indent}  [LOW_CALL] {info}")
        elif entry_type == "INTERNAL":
            lines.append(f"{indent}  [INTERNAL] {info}")
    return "\n".join(lines)


def is_critical_function(func):
    """Check if function involves fund movement."""
    try:
        # Check function name
        if any(p in func.name.lower() for p in CRITICAL_PATTERNS):
            return True

        # Check if it has external calls or transfers
        if func.high_level_calls or func.low_level_calls:
            return True

        # Check if internal calls touch transfers
        for call in func.internal_calls:
            if hasattr(call, 'name') and any(p in str(call).lower() for p in CRITICAL_PATTERNS):
                return True
    except AttributeError:
        pass
    return False


def analyze_contract(sol_file, contract_name=None, function_names=None, critical_only=False):
    """
    Main analysis: flatten functions and return formatted output.
    """
    if not HAS_SLITHER:
        return "ERROR: slither-analyzer no instalado. Instalar: pip install slither-analyzer"

    try:
        slither = Slither(sol_file)
    except Exception as e:
        return f"ERROR: Slither no pudo analizar {sol_file}: {e}"

    # Find the target contract
    contracts = slither.contracts
    if contract_name:
        matches = [c for c in contracts if c.name == contract_name]
        if not matches:
            available = [c.name for c in contracts]
            return f"ERROR: Contrato '{contract_name}' no encontrado. Disponibles: {available}"
        contract = matches[0]
    else:
        # Use the main contract (largest, non-interface, non-library)
        candidates = [c for c in contracts
                      if not c.is_interface and not c.is_library
                      and c.name not in ("Context", "Ownable", "ReentrancyGuard")]
        if not candidates:
            return f"ERROR: No se encontró contrato principal en {sol_file}"
        contract = max(candidates, key=lambda c: len(c.functions))

    # Select functions to analyze
    if function_names:
        functions = []
        for fn_name in function_names:
            found = [f for f in contract.functions if f.name == fn_name]
            if found:
                functions.append(found[0])
            else:
                print(f"  WARNING: función '{fn_name}' no encontrada en {contract.name}")
    elif critical_only:
        functions = [f for f in contract.functions
                     if f.visibility in ("public", "external")
                     and not f.is_constructor
                     and is_critical_function(f)]
    else:
        functions = [f for f in contract.functions
                     if f.visibility in ("public", "external")
                     and not f.is_constructor
                     and not f.view  # Skip pure view functions
                     and not f.pure]

    if not functions:
        return f"No se encontraron funciones relevantes en {contract.name}"

    # Generate flattened traces
    output_parts = [f"# Deep Flatten — {contract.name}\n"]
    output_parts.append(f"Funciones analizadas: {len(functions)}\n")

    for func in functions:
        entries = flatten_function(func)
        trace = format_trace(entries)

        # Mark critical functions
        is_crit = is_critical_function(func)
        crit_marker = " [CRITICAL — mueve fondos]" if is_crit else ""

        output_parts.append(f"\n## {func.full_name}{crit_marker}\n")
        output_parts.append(trace)

        # Add CEI analysis
        writes = [e for e in entries if e[1] == "WRITE"]
        externals = [e for e in entries if e[1] in ("EXTERNAL", "LOW_CALL")]
        if externals and writes:
            # Find indices
            first_external_idx = next(i for i, e in enumerate(entries) if e[1] in ("EXTERNAL", "LOW_CALL"))
            writes_after_external = [e for i, e in enumerate(entries) if e[1] == "WRITE" and i > first_external_idx]
            if writes_after_external:
                output_parts.append(f"\n  ⚠ CEI WARNING: {len(writes_after_external)} WRITE(s) después de EXTERNAL call:")
                for _, _, info in writes_after_external:
                    output_parts.append(f"    → WRITE: {info}")

    return "\n".join(output_parts)


def main():
    parser = argparse.ArgumentParser(description="Deep flatten — trace de ejecución aplanado")
    parser.add_argument("sol_file", type=str, help="Archivo .sol a analizar")
    parser.add_argument("--contract", "-c", type=str, help="Nombre del contrato (default: el más grande)")
    parser.add_argument("--functions", "-f", type=str, help="Funciones a analizar (comma-separated)")
    parser.add_argument("--critical-only", action="store_true",
                        help="Solo funciones que mueven fondos")
    parser.add_argument("--output", "-o", type=str, help="Archivo de salida (default: stdout)")
    args = parser.parse_args()

    function_names = args.functions.split(",") if args.functions else None

    result = analyze_contract(
        args.sol_file,
        contract_name=args.contract,
        function_names=function_names,
        critical_only=args.critical_only,
    )

    if args.output:
        Path(args.output).write_text(result)
        print(f"Output guardado en: {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
