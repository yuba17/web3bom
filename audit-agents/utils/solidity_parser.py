"""Lightweight Solidity parser for pattern-based analysis."""
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SolidityFunction:
    name: str
    visibility: str  # public, external, internal, private
    mutability: str  # view, pure, payable, nonpayable
    modifiers: list[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    body: str = ""
    has_external_call: bool = False
    has_state_change: bool = False
    has_ether_transfer: bool = False


@dataclass
class SolidityContract:
    name: str
    file_path: str
    source: str
    imports: list[str] = field(default_factory=list)
    functions: list[SolidityFunction] = field(default_factory=list)
    state_variables: list[str] = field(default_factory=list)
    inheritance: list[str] = field(default_factory=list)
    uses_proxy: bool = False
    solidity_version: str = ""


def parse_solidity(file_path: str) -> SolidityContract:
    """Parse a Solidity file into structured data for analysis."""
    path = Path(file_path)
    source = path.read_text(encoding="utf-8", errors="ignore")
    contract = SolidityContract(name="", file_path=file_path, source=source)

    # Extract pragma
    pragma = re.search(r'pragma\s+solidity\s+([^;]+);', source)
    if pragma:
        contract.solidity_version = pragma.group(1).strip()

    # Extract imports
    contract.imports = re.findall(r'import\s+["\']([^"\']+)["\']', source)
    contract.imports += re.findall(r'import\s+\{[^}]+\}\s+from\s+["\']([^"\']+)["\']', source)

    # Extract contract name and inheritance
    contract_match = re.search(r'contract\s+(\w+)(?:\s+is\s+([^{]+))?\s*\{', source)
    if contract_match:
        contract.name = contract_match.group(1)
        if contract_match.group(2):
            contract.inheritance = [i.strip() for i in contract_match.group(2).split(',')]

    # Check for proxy patterns
    proxy_indicators = ['Proxy', 'Upgradeable', 'delegatecall', 'implementation', 'IMPLEMENTATION_SLOT']
    contract.uses_proxy = any(indicator in source for indicator in proxy_indicators)

    # Extract functions
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s+'
        r'((?:public|external|internal|private)\s*)?'
        r'((?:view|pure|payable)\s*)?'
        r'((?:\w+\s*(?:\([^)]*\))?\s*)*)'
        r'(?:returns\s*\([^)]*\)\s*)?'
        r'\{',
        re.MULTILINE
    )
    lines = source.split('\n')
    for match in func_pattern.finditer(source):
        func = SolidityFunction(
            name=match.group(1),
            visibility=match.group(3).strip() if match.group(3) else "public",
            mutability=match.group(4).strip() if match.group(4) else "nonpayable",
        )
        # Extract modifiers
        if match.group(5):
            mod_text = match.group(5).strip()
            func.modifiers = [m.strip() for m in re.findall(r'(\w+)', mod_text) if m not in ('returns',)]

        # Line number
        func.line_start = source[:match.start()].count('\n') + 1

        # Extract body (simple brace matching)
        body_start = match.end()
        depth = 1
        pos = body_start
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        func.body = source[body_start:pos - 1]
        func.line_end = source[:pos].count('\n') + 1

        # Analyze body
        func.has_external_call = bool(re.search(r'\.(call|delegatecall|staticcall|transfer|send)\s*[({]', func.body))
        func.has_state_change = bool(re.search(r'(\w+\s*[\[\]]*\s*[+\-*/]?=\s)', func.body)) and func.mutability not in ('view', 'pure')
        func.has_ether_transfer = bool(re.search(r'\.(call\{value:|transfer\(|send\()', func.body))

        contract.functions.append(func)

    return contract
