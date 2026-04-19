"""Pure Solidity code-generation helpers for merge_invariants package."""

import re


def id_to_function_name(inv_id: str, inv_type: str) -> str:
    """Convierte 'GH-01' + 'property' → 'property_gh_01'."""
    clean = inv_id.lower().replace('-', '_')
    if inv_type == "optimize":
        return f"optimize_{clean}"
    return f"property_{clean}"


def _wrap_comment(prefix: str, text) -> list[str]:
    """Wrap multiline text into /// comment lines."""
    if isinstance(text, list):
        text = " ".join(str(t) for t in text)
    text = str(text)
    result = []
    for i, line in enumerate(text.replace("\n", " ").split(". ")):
        line = line.strip()
        if not line:
            continue
        if i == 0:
            result.append(f"    /// {prefix}{line}.")
        else:
            result.append(f"    ///   {line}.")
    return result if result else [f"    /// {prefix}(none)"]


def _clean_solidity_body(body: str) -> str:
    """Strip wrapper function declarations from hunter-generated Solidity.

    Hunters sometimes emit a full function declaration in the `solidity` field:
        function property_foo() public view {
            ...body...
        }
    We need to extract just the body, since generate_property_function() wraps
    it in its own function declaration.
    """
    stripped = body.strip()
    # Match any Solidity function signature (including view/pure and returns)
    stripped = re.sub(
        r'function\s+\w+\([^)]*\)\s*'           # function name(args)
        r'(?:(?:public|internal|external|private|view|pure|payable|override)\s*)*'  # modifiers
        r'(?:returns\s*\([^)]*\)\s*)?'           # optional returns(...)
        r'\{',                                    # opening brace
        '// (inner logic)',
        stripped
    )
    while stripped.rstrip().endswith('}') and stripped.count('{') < stripped.count('}'):
        stripped = stripped.rstrip()[:-1].rstrip()
    stripped = re.sub(r'\breturn\s+true;\s*$', '', stripped.rstrip())
    return stripped.strip()


def _sanitize_solidity(text: str) -> str:
    """Sanitize non-ASCII chars that solc rejects."""
    text = text.replace('\u2014', '--').replace('\u2013', '-')
    text = text.replace('\u2018', "'").replace('\u2019', "'")
    text = text.replace('\u201c', '"').replace('\u201d', '"')
    return text.encode('ascii', 'replace').decode('ascii')


def generate_property_function(inv: dict, source: str) -> str:
    """Genera código Solidity de una función property_*."""
    inv_id = inv.get("id", "XX-00")
    desc = inv.get("description", "")
    attack = inv.get("attack_scenario", "")
    body = inv.get("solidity_property", inv.get("solidity", "    // TODO: implement")).rstrip()
    body = _clean_solidity_body(body)
    body = _sanitize_solidity(body)
    tier = inv.get("tier", 2)
    fn_name = id_to_function_name(inv_id, "property")

    tier_comment = "TIER 1 -- HARD FAIL" if tier == 1 else "TIER 2 -- NEEDS REVIEW"

    lines = [
        f"    // {tier_comment}",
    ]
    lines.extend(_wrap_comment(f"@notice {inv_id}: ", desc))
    if attack:
        lines.extend(_wrap_comment("Attack: ", attack))
    lines.append(f"    /// Source: {source}")
    lines.append(f"    function {fn_name}() public {{")

    for line in body.split("\n"):
        if line.strip():
            lines.append(f"        {line.strip()}")
        else:
            lines.append("")

    lines.append("    }")
    return "\n".join(lines)


def generate_optimize_function(inv: dict, source: str) -> str:
    """Genera código Solidity de una función optimize_*."""
    inv_id = inv.get("id", "XX-00")
    desc = inv.get("description", "")
    body = inv.get("solidity_property", inv.get("solidity", "    return 0;")).rstrip()
    fn_name = id_to_function_name(inv_id, "optimize")

    lines = [
        f"    // OPTIMIZATION",
        f"    /// @notice {inv_id}: {desc}",
        f"    /// Source: {source}",
        f"    function {fn_name}() public returns (int256) {{",
    ]

    for line in body.split("\n"):
        if line.strip():
            lines.append(f"        {line.strip()}")
        else:
            lines.append("")

    lines.append("    }")
    return "\n".join(lines)


def generate_ghost_var(var_decl) -> str:
    """Formatea una declaración de ghost variable."""
    if isinstance(var_decl, dict):
        # Handle dict format: {name: "x", type: "uint256", ...}
        name = var_decl.get("name", var_decl.get("variable", ""))
        typ = var_decl.get("type", "uint256")
        decl = f"{typ} {name};"
    else:
        decl = str(var_decl).strip()
        if not decl.endswith(";"):
            decl += ";"
    return f"    {decl}"
