#!/usr/bin/env python3
"""
Protocol Analyzer — Layer 1: Structure Map
============================================
Parses Solidity source code using Slither and generates a structured
PROTOCOL_MODEL.md with contract architecture, public functions,
external calls, state variables, and their relationships.

This is the foundation layer — all subsequent analysis layers
(critical flows, cross-function, pattern matching, deep dive)
build on this output.

Usage:
    python protocol_analyzer.py --source ./revert-lend/src --name "revert-lend" --type lending
    python protocol_analyzer.py --source ./target/src --name "protocol" --type dex
"""

import argparse
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class FunctionInfo:
    name: str
    visibility: str  # public, external, internal, private
    modifiers: list[str] = field(default_factory=list)
    parameters: str = ""
    returns: str = ""
    state_mutability: str = ""  # view, pure, payable, nonpayable
    writes_state: list[str] = field(default_factory=list)
    reads_state: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    events_emitted: list[str] = field(default_factory=list)
    has_reentrancy_guard: bool = False
    line_start: int = 0
    line_end: int = 0


@dataclass
class ContractInfo:
    name: str
    file_path: str
    loc: int = 0
    inheritance: list[str] = field(default_factory=list)
    state_variables: list[dict] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    modifiers_defined: list[str] = field(default_factory=list)
    external_dependencies: list[str] = field(default_factory=list)
    is_interface: bool = False
    is_library: bool = False
    is_abstract: bool = False


# =============================================================================
# LAYER 1: SLITHER-BASED STRUCTURE EXTRACTION
# =============================================================================

def run_layer1_slither(source_dir: str) -> list[ContractInfo]:
    """Extract structure using Slither's Python API."""
    try:
        from slither.slither import Slither
        from slither.core.declarations import Function
        from slither.core.variables.state_variable import StateVariable
    except ImportError:
        print("[!] Slither not installed. Falling back to regex parser.")
        return run_layer1_regex(source_dir)

    contracts = []

    try:
        # Find the project root (where foundry.toml or hardhat.config lives)
        project_root = _find_project_root(source_dir)
        slither = Slither(project_root)

        # Filter to only contracts in the source directory
        source_path = Path(source_dir).resolve()

        for contract in slither.contracts:
            # Skip contracts outside our scope
            if contract.source_mapping and contract.source_mapping.filename:
                contract_path = Path(contract.source_mapping.filename.absolute).resolve()
                if not str(contract_path).startswith(str(source_path)):
                    continue

            info = ContractInfo(
                name=contract.name,
                file_path=str(contract.source_mapping.filename.relative)
                    if contract.source_mapping and contract.source_mapping.filename else "unknown",
                is_interface=contract.is_interface,
                is_library=contract.is_library,
                is_abstract=contract.is_abstract if hasattr(contract, 'is_abstract') else False,
            )

            # LOC
            if contract.source_mapping:
                info.loc = contract.source_mapping.lines.__len__() if contract.source_mapping.lines else 0

            # Inheritance
            info.inheritance = [c.name for c in contract.inheritance]

            # State variables
            for var in contract.state_variables:
                var_info = {
                    "name": var.name,
                    "type": str(var.type),
                    "visibility": var.visibility,
                    "is_constant": var.is_constant,
                    "is_immutable": var.is_immutable if hasattr(var, 'is_immutable') else False,
                }
                info.state_variables.append(var_info)

            # Events
            info.events = [e.name for e in contract.events]

            # Modifiers defined
            info.modifiers_defined = [m.name for m in contract.modifiers]

            # Functions
            for func in contract.functions_declared:
                if func.is_constructor:
                    func_name = "constructor"
                elif func.is_fallback:
                    func_name = "fallback"
                elif func.is_receive:
                    func_name = "receive"
                else:
                    func_name = func.name

                func_info = FunctionInfo(
                    name=func_name,
                    visibility=func.visibility,
                    state_mutability=func.view if hasattr(func, 'view') else "",
                    line_start=func.source_mapping.lines[0] if func.source_mapping and func.source_mapping.lines else 0,
                    line_end=func.source_mapping.lines[-1] if func.source_mapping and func.source_mapping.lines else 0,
                )

                # Modifiers
                func_info.modifiers = [m.name for m in func.modifiers]
                func_info.has_reentrancy_guard = any(
                    "reentrancy" in m.name.lower() or "nonreentrant" in m.name.lower()
                    for m in func.modifiers
                )

                # Parameters
                func_info.parameters = ", ".join(
                    f"{p.type} {p.name}" for p in func.parameters
                )

                # Returns
                func_info.returns = ", ".join(
                    str(r.type) for r in func.returns
                )

                # State variables written
                func_info.writes_state = list(set(
                    var.name for var in func.state_variables_written
                ))

                # State variables read
                func_info.reads_state = list(set(
                    var.name for var in func.state_variables_read
                ))

                # External calls (clean format, separate libraries)
                KNOWN_LIBRARIES = {"SafeERC20", "SafeCast", "FullMath", "Math", "Address", "Arrays"}
                try:
                    for call in func.high_level_calls:
                        if isinstance(call, tuple) and len(call) == 2:
                            target_contract, target_func = call
                            tc_name = target_contract.name if hasattr(target_contract, 'name') else str(target_contract)
                            # Extract clean function name
                            if hasattr(target_func, 'name'):
                                tf_name = target_func.name
                            elif hasattr(target_func, 'full_name'):
                                tf_name = target_func.full_name
                            else:
                                tf_name = str(target_func).split("function:")[-1].split(",")[0].strip() if "function:" in str(target_func) else str(target_func)
                            # Skip library calls — they're not reentrancy risk
                            if tc_name in KNOWN_LIBRARIES:
                                continue
                            func_info.external_calls.append(f"{tc_name}.{tf_name}()")
                        elif isinstance(call, str):
                            func_info.external_calls.append(call)
                        else:
                            # Try to extract something readable from the string repr
                            s = str(call)
                            if "function:" in s:
                                parts = s.split("function:")
                                if len(parts) > 1:
                                    fn = parts[1].split(",")[0].strip()
                                    func_info.external_calls.append(fn)
                except Exception:
                    pass
                try:
                    for call in func.low_level_calls:
                        # Extract just the target from low level calls
                        if isinstance(call, tuple) and len(call) >= 2:
                            node = call[0]
                            target_name = node.name if hasattr(node, 'name') else str(node)
                            func_info.external_calls.append(f"low_level → {target_name}")
                        else:
                            func_info.external_calls.append("low_level_call")
                except Exception:
                    pass
                # Deduplicate
                func_info.external_calls = list(dict.fromkeys(func_info.external_calls))

                # Events emitted
                try:
                    if hasattr(func, 'events_as_dict'):
                        func_info.events_emitted = list(func.events_as_dict.keys())
                    elif hasattr(func, '_events'):
                        func_info.events_emitted = [e.name for e in func._events]
                except Exception:
                    pass

                info.functions.append(func_info)

            # External dependencies (unique contracts called)
            ext_deps = set()
            for func in contract.functions_declared:
                for call in func.high_level_calls:
                    target_contract, _ = call
                    if target_contract.name != contract.name:
                        ext_deps.add(target_contract.name)
            info.external_dependencies = sorted(ext_deps)

            contracts.append(info)

    except Exception as e:
        print(f"[!] Slither failed: {e}")
        print("[!] Falling back to regex parser.")
        return run_layer1_regex(source_dir)

    return contracts


# =============================================================================
# LAYER 1: REGEX FALLBACK (when Slither fails)
# =============================================================================

def run_layer1_regex(source_dir: str) -> list[ContractInfo]:
    """Fallback: extract structure using regex patterns."""
    contracts = []
    source_path = Path(source_dir)

    for sol_file in sorted(source_path.rglob("*.sol")):
        # Skip test files, mocks, interfaces dirs
        rel_path = str(sol_file.relative_to(source_path))
        if any(skip in rel_path.lower() for skip in ["test", "mock", "script"]):
            continue

        content = sol_file.read_text(encoding="utf-8", errors="ignore")
        lines = content.split("\n")

        # Find contract declarations
        contract_pattern = re.compile(
            r'^\s*(abstract\s+)?(contract|interface|library)\s+(\w+)(\s+is\s+([^{]+))?',
            re.MULTILINE
        )

        for match in contract_pattern.finditer(content):
            is_abstract = match.group(1) is not None
            contract_type = match.group(2)
            name = match.group(3)
            inheritance_str = match.group(5) or ""

            info = ContractInfo(
                name=name,
                file_path=rel_path,
                loc=len(lines),
                is_interface=contract_type == "interface",
                is_library=contract_type == "library",
                is_abstract=is_abstract,
            )

            # Inheritance
            if inheritance_str:
                info.inheritance = [
                    i.strip().split("(")[0].strip()
                    for i in inheritance_str.split(",")
                ]

            # State variables (simplified)
            state_var_pattern = re.compile(
                r'^\s+(uint\d*|int\d*|address|bool|bytes\d*|string|mapping\([^)]+\))\s+'
                r'(public|private|internal)?\s*(\w+)',
                re.MULTILINE
            )
            for sv_match in state_var_pattern.finditer(content):
                info.state_variables.append({
                    "name": sv_match.group(3),
                    "type": sv_match.group(1),
                    "visibility": sv_match.group(2) or "internal",
                    "is_constant": False,
                    "is_immutable": False,
                })

            # Functions
            func_pattern = re.compile(
                r'^\s+function\s+(\w+)\s*\(([^)]*)\)\s*(public|external|internal|private)'
                r'([^{]*)\{',
                re.MULTILINE
            )
            for func_match in func_pattern.finditer(content):
                func_info = FunctionInfo(
                    name=func_match.group(1),
                    visibility=func_match.group(3),
                    parameters=func_match.group(2).strip(),
                )

                # Check modifiers in the function signature
                sig_extras = func_match.group(4)
                if sig_extras:
                    if "nonReentrant" in sig_extras:
                        func_info.has_reentrancy_guard = True
                    modifier_matches = re.findall(r'(\w+)(?:\([^)]*\))?', sig_extras)
                    func_info.modifiers = [
                        m for m in modifier_matches
                        if m not in ("returns", "view", "pure", "payable", "virtual", "override")
                    ]

                # Find line number
                func_pos = func_match.start()
                func_info.line_start = content[:func_pos].count("\n") + 1

                info.functions.append(func_info)

            # External calls (simplified)
            ext_call_pattern = re.compile(r'(\w+)\.(\w+)\(')
            ext_deps = set()
            for ec_match in ext_call_pattern.finditer(content):
                target = ec_match.group(1)
                if target[0].isupper() or target.startswith("I"):
                    ext_deps.add(target)
            info.external_dependencies = sorted(ext_deps)

            # Events
            event_pattern = re.compile(r'event\s+(\w+)\s*\(')
            info.events = [e.group(1) for e in event_pattern.finditer(content)]

            contracts.append(info)

    return contracts


# =============================================================================
# MARKDOWN GENERATION
# =============================================================================

def generate_protocol_model(contracts: list[ContractInfo], name: str, protocol_type: str) -> str:
    """Generate the PROTOCOL_MODEL.md content."""

    # Filter out interfaces and libraries for main analysis
    main_contracts = [c for c in contracts if not c.is_interface and not c.is_library]
    interfaces = [c for c in contracts if c.is_interface]
    libraries = [c for c in contracts if c.is_library]

    md = []
    md.append(f"# {name} — Protocol Model")
    md.append(f"**Type**: {protocol_type}")
    md.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    md.append(f"**Contracts in scope**: {len(main_contracts)}")
    md.append(f"**Total LOC**: {sum(c.loc for c in main_contracts)}")
    md.append("")

    # ---- CONTRACT OVERVIEW ----
    md.append("---")
    md.append("## 1. Contract Overview")
    md.append("")
    md.append("| Contract | File | LOC | Inherits | External Deps | Public/External Fns |")
    md.append("|----------|------|-----|----------|---------------|---------------------|")

    for c in sorted(main_contracts, key=lambda x: x.loc, reverse=True):
        pub_fns = [f for f in c.functions if f.visibility in ("public", "external")]
        inheritance = ", ".join(c.inheritance[:3])
        if len(c.inheritance) > 3:
            inheritance += f" +{len(c.inheritance) - 3} more"
        ext_deps = ", ".join(c.external_dependencies[:3])
        if len(c.external_dependencies) > 3:
            ext_deps += f" +{len(c.external_dependencies) - 3} more"
        md.append(f"| **{c.name}** | {c.file_path} | {c.loc} | {inheritance} | {ext_deps} | {len(pub_fns)} |")

    md.append("")

    if interfaces:
        md.append(f"**Interfaces**: {', '.join(i.name for i in interfaces)}")
        md.append("")
    if libraries:
        md.append(f"**Libraries**: {', '.join(l.name for l in libraries)}")
        md.append("")

    # ---- INHERITANCE TREE ----
    md.append("---")
    md.append("## 2. Inheritance Tree")
    md.append("")
    for c in main_contracts:
        if c.inheritance:
            chain = f"**{c.name}** → " + " → ".join(c.inheritance)
            md.append(f"- {chain}")
        else:
            md.append(f"- **{c.name}** (no inheritance)")
    md.append("")

    # ---- PUBLIC/EXTERNAL FUNCTIONS ----
    md.append("---")
    md.append("## 3. Public/External Functions")
    md.append("")

    for c in sorted(main_contracts, key=lambda x: x.loc, reverse=True):
        pub_fns = [f for f in c.functions if f.visibility in ("public", "external")]
        if not pub_fns:
            continue

        md.append(f"### {c.name} ({len(pub_fns)} functions)")
        md.append("")
        md.append("| Function | Visibility | Modifiers | Reentrancy Guard | Writes State | External Calls | Line |")
        md.append("|----------|-----------|-----------|------------------|-------------|----------------|------|")

        for f in pub_fns:
            modifiers = ", ".join(f.modifiers) if f.modifiers else "—"
            guard = "✅" if f.has_reentrancy_guard else "❌"
            writes = ", ".join(f.writes_state[:3]) if f.writes_state else "—"
            if len(f.writes_state) > 3:
                writes += f" +{len(f.writes_state) - 3}"
            ext_calls = ", ".join(f.external_calls[:2]) if f.external_calls else "—"
            if len(f.external_calls) > 2:
                ext_calls += f" +{len(f.external_calls) - 2}"
            md.append(f"| `{f.name}` | {f.visibility} | {modifiers} | {guard} | {writes} | {ext_calls} | L{f.line_start} |")

        md.append("")

    # ---- EXTERNAL DEPENDENCIES ----
    md.append("---")
    md.append("## 4. External Dependencies")
    md.append("")

    all_deps = {}
    for c in main_contracts:
        for func in c.functions:
            for call in func.external_calls:
                target = call.split(".")[0]
                if target not in all_deps:
                    all_deps[target] = []
                all_deps[target].append(f"{c.name}.{func.name}()")

    if all_deps:
        md.append("| External Contract | Called From |")
        md.append("|-------------------|------------|")
        for dep, callers in sorted(all_deps.items()):
            unique_callers = sorted(set(callers))
            callers_str = ", ".join(unique_callers[:4])
            if len(unique_callers) > 4:
                callers_str += f" +{len(unique_callers) - 4} more"
            md.append(f"| **{dep}** | {callers_str} |")
        md.append("")
    else:
        md.append("No external dependencies detected.")
        md.append("")

    # ---- STATE VARIABLES ----
    md.append("---")
    md.append("## 5. State Variables (mutable, non-constant)")
    md.append("")

    for c in sorted(main_contracts, key=lambda x: x.loc, reverse=True):
        mutable_vars = [
            v for v in c.state_variables
            if not v.get("is_constant") and not v.get("is_immutable")
        ]
        if not mutable_vars:
            continue

        md.append(f"### {c.name}")
        md.append("")
        md.append("| Variable | Type | Visibility | Written By | Read By |")
        md.append("|----------|------|-----------|------------|---------|")

        for var in mutable_vars:
            # Find which functions write/read this variable
            writers = []
            readers = []
            for func in c.functions:
                if var["name"] in func.writes_state:
                    writers.append(func.name)
                if var["name"] in func.reads_state:
                    readers.append(func.name)

            writers_str = ", ".join(writers[:3]) if writers else "—"
            if len(writers) > 3:
                writers_str += f" +{len(writers) - 3}"
            readers_str = ", ".join(readers[:3]) if readers else "—"
            if len(readers) > 3:
                readers_str += f" +{len(readers) - 3}"

            md.append(f"| `{var['name']}` | {var['type']} | {var['visibility']} | {writers_str} | {readers_str} |")

        md.append("")

    # ---- REENTRANCY GUARD COVERAGE ----
    md.append("---")
    md.append("## 6. Reentrancy Guard Coverage")
    md.append("")

    has_any_guard = False
    for c in main_contracts:
        ext_fns = [f for f in c.functions
                   if f.visibility in ("public", "external")
                   and f.external_calls
                   and f.name not in ("constructor",)]
        if not ext_fns:
            continue

        has_any_guard = True
        md.append(f"### {c.name}")
        md.append("")
        md.append("Functions with external calls:")
        md.append("")
        for f in ext_fns:
            status = "✅ GUARDED" if f.has_reentrancy_guard else "⚠️ NO GUARD"
            calls = ", ".join(f.external_calls[:3])
            md.append(f"- `{f.name}()` → {status} — calls: {calls}")
        md.append("")

    if not has_any_guard:
        md.append("No functions with external calls found.")
        md.append("")

    # ---- EVENTS COVERAGE ----
    md.append("---")
    md.append("## 7. Events")
    md.append("")
    for c in main_contracts:
        if c.events:
            md.append(f"### {c.name}")
            md.append(f"Events defined: {', '.join(c.events)}")
            md.append("")

    # ---- PLACEHOLDER FOR NEXT LAYERS ----
    md.append("---")
    md.append("## 8. Critical Flows (Layer 2)")
    md.append("*To be generated — run with --layer 2*")
    md.append("")
    md.append("---")
    md.append("## 9. Cross-Function Analysis (Layer 2.5)")
    md.append("*To be generated — run with --layer 2.5*")
    md.append("")
    md.append("---")
    md.append("## 10. Pattern Matches (Layer 3)")
    md.append("*To be generated — run with --layer 3*")
    md.append("")
    md.append("---")
    md.append("## 11. Deep Dive Findings (Layer 4)")
    md.append("*To be generated — run with --layer 4*")
    md.append("")

    return "\n".join(md)


# =============================================================================
# HELPERS
# =============================================================================

def _find_project_root(source_dir: str) -> str:
    """Walk up from source_dir to find foundry.toml or hardhat.config."""
    current = Path(source_dir).resolve()
    for _ in range(10):
        if (current / "foundry.toml").exists():
            return str(current)
        if (current / "hardhat.config.js").exists():
            return str(current)
        if (current / "hardhat.config.ts").exists():
            return str(current)
        if current.parent == current:
            break
        current = current.parent
    # Default to source_dir parent
    return str(Path(source_dir).resolve().parent)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Protocol Analyzer — Generate PROTOCOL_MODEL.md"
    )
    parser.add_argument("--source", required=True,
                        help="Path to source directory (e.g., ./revert-lend/src)")
    parser.add_argument("--name", required=True,
                        help="Protocol name (e.g., revert-lend)")
    parser.add_argument("--type", default="unknown",
                        help="Protocol type: lending, dex, staking, bridge, vault, oracle")
    parser.add_argument("--output", default=None,
                        help="Output path (default: source/../PROTOCOL_MODEL.md)")
    parser.add_argument("--no-slither", action="store_true",
                        help="Skip Slither, use regex fallback only")

    args = parser.parse_args()

    source_dir = os.path.abspath(args.source)
    if not os.path.isdir(source_dir):
        print(f"[!] Source directory not found: {source_dir}")
        sys.exit(1)

    print(f"[*] Protocol Analyzer — Layer 1: Structure Map")
    print(f"[*] Target: {args.name}")
    print(f"[*] Source: {source_dir}")
    print(f"[*] Type: {args.type}")
    print()

    # Run Layer 1
    if args.no_slither:
        print("[*] Using regex fallback (--no-slither)")
        contracts = run_layer1_regex(source_dir)
    else:
        print("[*] Parsing with Slither...")
        contracts = run_layer1_slither(source_dir)

    if not contracts:
        print("[!] No contracts found in scope.")
        sys.exit(1)

    main_contracts = [c for c in contracts if not c.is_interface and not c.is_library]
    print(f"[+] Found {len(main_contracts)} contracts, {len(contracts) - len(main_contracts)} interfaces/libraries")

    # Generate markdown
    md_content = generate_protocol_model(contracts, args.name, args.type)

    # Write output
    if args.output:
        output_path = args.output
    else:
        output_path = os.path.join(os.path.dirname(source_dir), "PROTOCOL_MODEL.md")

    Path(output_path).write_text(md_content, encoding="utf-8")
    print(f"[+] PROTOCOL_MODEL.md written to: {output_path}")
    print(f"[+] {len(md_content)} bytes, {md_content.count(chr(10))} lines")


if __name__ == "__main__":
    main()
