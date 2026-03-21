# Web3 Audit Agents

Multi-agent smart contract security scanner. Each agent specializes in a vulnerability class.

## Agents

| Agent | Focus | Detects |
|---|---|---|
| **PatternScanner** | Known vulnerability patterns | delegatecall, selfdestruct, tx.origin, timestamp, abi.encodePacked |
| **ReentrancyDetector** | Reentrancy variants | Classic, cross-function, missing guards |
| **AccessControlDetector** | Access control (#1 vuln) | Missing modifiers, unprotected init, tx.origin auth, zero-address |
| **OracleDetector** | Oracle & flash loans | Spot price usage, stale oracle, balance-as-price, flash loan surface |
| **LogicDetector** | Business logic bugs | First depositor, rounding, unchecked returns, division order, unbounded loops |
| **GasOptimizer** | Gas & DoS | Storage in loops, long strings, optimization hints |
| **SlitherAnalyzer** | Slither integration | All Slither detectors (requires `slither-analyzer`) |

## Setup

```bash
bash setup.sh
```

Or manually:
```bash
pip install rich click pyyaml jinja2
# Optional for deeper analysis:
pip install slither-analyzer solc-select
```

## Usage

```bash
# Scan single file
python audit.py contract.sol

# Scan with markdown report
python audit.py contract.sol --report markdown -o report.md

# Scan directory
python audit.py contracts/ --recursive

# Run specific agents only
python audit.py contract.sol --agents reentrancy,access_control,oracle

# JSON report
python audit.py contract.sol --report json -o report.json
```

## Adding Custom Agents

1. Create a new file in `agents/`
2. Inherit from `BaseAgent`
3. Implement `analyze(contract) -> list[Finding]`
4. Register in `agents/__init__.py` and `audit.py`

## Test Contract

A deliberately vulnerable contract is included at `contracts/VulnerableVault.sol` for validation.
