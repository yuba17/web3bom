#!/usr/bin/env python3
"""
symmetric_analyzer.py — Detecta pares simétricos y genera tabla de asimetrías.

Usa Slither API para extraer state variables, events, y modifiers de cada función,
luego compara pares (deposit/withdraw, mint/burn, etc.) y reporta diferencias.

Output se puede inyectar en el _context.md que leen los hunters.

Uso:
    python3 symmetric_analyzer.py <sol_file> [--contract ContractName]
    python3 symmetric_analyzer.py <sol_file> --output context.md

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


# Known symmetric pairs (function name patterns)
SYMMETRIC_PAIRS = [
    ("deposit", "withdraw"),
    ("mint", "burn"),
    ("lock", "unlock"),
    ("stake", "unstake"),
    ("borrow", "repay"),
    ("open", "close"),
    ("increase", "decrease"),
    ("add", "remove"),
    ("enter", "exit"),
    ("subscribe", "unsubscribe"),
    ("wrap", "unwrap"),
    ("lend", "redeem"),
    ("supply", "withdraw"),
    ("join", "exit"),
    ("create", "destroy"),
    ("claim", "forfeit"),
]


def extract_function_profile(func):
    """
    Extract the security-relevant profile of a function:
    - State variables read/written
    - Events emitted
    - Modifiers applied
    - External calls made
    - Visibility
    """
    profile = {
        "name": func.full_name,
        "visibility": func.visibility,
        "state_vars_read": set(),
        "state_vars_written": set(),
        "events": set(),
        "modifiers": set(),
        "external_calls": set(),
        "has_reentrancy_guard": False,
    }

    try:
        for var in func.state_variables_read:
            profile["state_vars_read"].add(var.name)
    except AttributeError:
        pass

    try:
        for var in func.state_variables_written:
            profile["state_vars_written"].add(var.name)
    except AttributeError:
        pass

    try:
        for event in func.events_emitted if hasattr(func, 'events_emitted') else []:
            # events_emitted is not always available, fall back to solidity_signature
            if hasattr(event, 'name'):
                profile["events"].add(event.name)
            elif hasattr(event, 'full_name'):
                profile["events"].add(event.full_name)
    except (AttributeError, TypeError):
        pass

    try:
        for mod in func.modifiers:
            mod_name = mod.name if hasattr(mod, 'name') else str(mod)
            profile["modifiers"].add(mod_name)
            if "nonReentrant" in mod_name or "nonreentrant" in mod_name.lower():
                profile["has_reentrancy_guard"] = True
    except AttributeError:
        pass

    try:
        for (contract, ext_func) in func.high_level_calls:
            c_name = contract.name if hasattr(contract, 'name') else str(contract)
            f_name = ext_func.name if hasattr(ext_func, 'name') else str(ext_func)
            profile["external_calls"].add(f"{c_name}.{f_name}")
    except AttributeError:
        pass

    return profile


def find_symmetric_pairs(contract):
    """
    Find symmetric function pairs in a contract.
    Returns list of (func_a, func_b, pair_name) tuples.
    """
    # Build function name lookup (public/external only)
    functions = {}
    for func in contract.functions:
        if func.visibility in ("public", "external") and not func.is_constructor:
            functions[func.name.lower()] = func

    pairs = []
    seen = set()

    for name_a, name_b in SYMMETRIC_PAIRS:
        # Direct match
        if name_a in functions and name_b in functions:
            key = tuple(sorted([name_a, name_b]))
            if key not in seen:
                seen.add(key)
                pairs.append((functions[name_a], functions[name_b], f"{name_a}/{name_b}"))

        # Prefix match: e.g., depositETH/withdrawETH, addLiquidity/removeLiquidity
        for fn_name, func in functions.items():
            if fn_name.startswith(name_a) and fn_name not in (name_a,):
                suffix = fn_name[len(name_a):]
                counterpart = name_b + suffix
                if counterpart in functions:
                    key = tuple(sorted([fn_name, counterpart]))
                    if key not in seen:
                        seen.add(key)
                        pairs.append((func, functions[counterpart], f"{fn_name}/{counterpart}"))

    return pairs


def compare_pair(profile_a, profile_b):
    """
    Compare two function profiles and return asymmetries.
    Returns dict of dimension → {only_in_a, only_in_b, in_both}
    """
    comparison = {}

    # State variables written
    vars_a = profile_a["state_vars_written"]
    vars_b = profile_b["state_vars_written"]
    comparison["state_vars_written"] = {
        "only_a": vars_a - vars_b,
        "only_b": vars_b - vars_a,
        "both": vars_a & vars_b,
    }

    # State variables read
    reads_a = profile_a["state_vars_read"]
    reads_b = profile_b["state_vars_read"]
    comparison["state_vars_read"] = {
        "only_a": reads_a - reads_b,
        "only_b": reads_b - reads_a,
        "both": reads_a & reads_b,
    }

    # Events
    events_a = profile_a["events"]
    events_b = profile_b["events"]
    comparison["events"] = {
        "only_a": events_a - events_b,
        "only_b": events_b - events_a,
        "both": events_a & events_b,
    }

    # Modifiers
    mods_a = profile_a["modifiers"]
    mods_b = profile_b["modifiers"]
    comparison["modifiers"] = {
        "only_a": mods_a - mods_b,
        "only_b": mods_b - mods_a,
        "both": mods_a & mods_b,
    }

    # External calls
    ext_a = profile_a["external_calls"]
    ext_b = profile_b["external_calls"]
    comparison["external_calls"] = {
        "only_a": ext_a - ext_b,
        "only_b": ext_b - ext_a,
        "both": ext_a & ext_b,
    }

    # Reentrancy guard symmetry
    comparison["reentrancy_guard"] = {
        "a": profile_a["has_reentrancy_guard"],
        "b": profile_b["has_reentrancy_guard"],
        "symmetric": profile_a["has_reentrancy_guard"] == profile_b["has_reentrancy_guard"],
    }

    return comparison


def format_report(pairs_analysis):
    """Format the analysis as a readable report."""
    parts = ["# Symmetric Analysis Report\n"]

    if not pairs_analysis:
        parts.append("No se encontraron pares simétricos en el contrato.\n")
        return "\n".join(parts)

    parts.append(f"Pares encontrados: {len(pairs_analysis)}\n")

    total_asymmetries = 0

    for pair_name, profile_a, profile_b, comparison in pairs_analysis:
        name_a = profile_a["name"].split("(")[0]
        name_b = profile_b["name"].split("(")[0]

        parts.append(f"\n## Par: {pair_name}\n")

        has_asymmetry = False

        # State vars written
        sv = comparison["state_vars_written"]
        if sv["only_a"] or sv["only_b"]:
            has_asymmetry = True
            parts.append(f"### State Variables Written")
            parts.append(f"| Variable | {name_a} | {name_b} |")
            parts.append(f"|----------|:---:|:---:|")
            for v in sorted(sv["both"]):
                parts.append(f"| {v} | YES | YES |")
            for v in sorted(sv["only_a"]):
                parts.append(f"| **{v}** | **YES** | **NO** |")
                total_asymmetries += 1
            for v in sorted(sv["only_b"]):
                parts.append(f"| **{v}** | **NO** | **YES** |")
                total_asymmetries += 1
            parts.append("")
        else:
            parts.append(f"State vars written: SYMMETRIC ({len(sv['both'])} vars)\n")

        # Modifiers
        mod = comparison["modifiers"]
        if mod["only_a"] or mod["only_b"]:
            has_asymmetry = True
            parts.append(f"### Modifiers")
            for m in sorted(mod["only_a"]):
                parts.append(f"- **{m}**: solo en {name_a}, falta en {name_b}")
                total_asymmetries += 1
            for m in sorted(mod["only_b"]):
                parts.append(f"- **{m}**: solo en {name_b}, falta en {name_a}")
                total_asymmetries += 1
            parts.append("")

        # Reentrancy guard
        rg = comparison["reentrancy_guard"]
        if not rg["symmetric"]:
            has_asymmetry = True
            guard_a = "YES" if rg["a"] else "NO"
            guard_b = "YES" if rg["b"] else "NO"
            parts.append(f"### Reentrancy Guard")
            parts.append(f"- **{name_a}**: {guard_a}")
            parts.append(f"- **{name_b}**: {guard_b}")
            parts.append(f"- **ASYMMETRIC** — posible vector de reentrancy en la función sin guard\n")
            total_asymmetries += 1

        # Events
        ev = comparison["events"]
        if ev["only_a"] or ev["only_b"]:
            has_asymmetry = True
            parts.append(f"### Events")
            for e in sorted(ev["only_a"]):
                parts.append(f"- **{e}**: solo emitido en {name_a}")
                total_asymmetries += 1
            for e in sorted(ev["only_b"]):
                parts.append(f"- **{e}**: solo emitido en {name_b}")
                total_asymmetries += 1
            parts.append("")

        if not has_asymmetry:
            parts.append(f"**SYMMETRIC** — no se encontraron asimetrías en este par.\n")

    # Summary
    parts.append(f"\n---\n## Resumen")
    parts.append(f"- Pares analizados: {len(pairs_analysis)}")
    parts.append(f"- **Asimetrías encontradas: {total_asymmetries}**")
    if total_asymmetries > 0:
        parts.append(f"- Cada asimetría es un candidato a invariante. Investigar si es by-design o bug.")
    parts.append(f"\nBug real de referencia: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M\n")

    return "\n".join(parts)


def analyze(sol_file, contract_name=None):
    """Main analysis entry point."""
    if not HAS_SLITHER:
        return "ERROR: slither-analyzer no instalado. Instalar: pip install slither-analyzer"

    try:
        slither = Slither(sol_file)
    except Exception as e:
        return f"ERROR: Slither no pudo analizar {sol_file}: {e}"

    # Find target contract
    contracts = slither.contracts
    if contract_name:
        matches = [c for c in contracts if c.name == contract_name]
        if not matches:
            return f"ERROR: Contrato '{contract_name}' no encontrado."
        contract = matches[0]
    else:
        candidates = [c for c in contracts
                      if not c.is_interface and not c.is_library]
        if not candidates:
            return f"ERROR: No se encontró contrato principal."
        contract = max(candidates, key=lambda c: len(c.functions))

    # Find pairs
    pairs = find_symmetric_pairs(contract)

    if not pairs:
        return f"# Symmetric Analysis — {contract.name}\n\nNo se encontraron pares simétricos."

    # Analyze each pair
    pairs_analysis = []
    for func_a, func_b, pair_name in pairs:
        profile_a = extract_function_profile(func_a)
        profile_b = extract_function_profile(func_b)
        comparison = compare_pair(profile_a, profile_b)
        pairs_analysis.append((pair_name, profile_a, profile_b, comparison))

    return format_report(pairs_analysis)


def main():
    parser = argparse.ArgumentParser(description="Symmetric analyzer — detecta asimetrías en pares de funciones")
    parser.add_argument("sol_file", type=str, help="Archivo .sol a analizar")
    parser.add_argument("--contract", "-c", type=str, help="Nombre del contrato")
    parser.add_argument("--output", "-o", type=str, help="Archivo de salida")
    args = parser.parse_args()

    result = analyze(args.sol_file, contract_name=args.contract)

    if args.output:
        Path(args.output).write_text(result)
        print(f"Output guardado en: {args.output}")
    else:
        print(result)


if __name__ == "__main__":
    main()
