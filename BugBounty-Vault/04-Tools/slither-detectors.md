---
tags: [tools, slither, static-analysis]
---

# Slither Detectors Reference

## Installation
```bash
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.26
solc-select use 0.8.26
```

## Usage
```bash
slither contract.sol                    # basic analysis
slither contract.sol --print human-summary  # high-level overview
slither contract.sol --print contract-summary
slither contract.sol --print function-summary
slither contract.sol --print call-graph     # visualize calls
slither contract.sol --detect reentrancy-eth,unprotected-upgrade
slither contract.sol --json output.json     # JSON output
slither . --filter-paths "test|mock"        # exclude test files
```

## Key Detectors (by severity)

### High
| Detector | What it finds |
|---|---|
| `reentrancy-eth` | Reentrancy with ETH transfer |
| `reentrancy-no-eth` | Reentrancy without ETH |
| `unprotected-upgrade` | Unprotected upgradeable proxy |
| `suicidal` | Unprotected selfdestruct |
| `arbitrary-send-eth` | Functions sending ETH to arbitrary address |
| `controlled-delegatecall` | Delegatecall with user-controlled input |
| `storage-array` | Signed storage integer array |

### Medium
| Detector | What it finds |
|---|---|
| `incorrect-equality` | Dangerous strict equality |
| `locked-ether` | Contract locks ETH with no withdraw |
| `tx-origin` | tx.origin usage |
| `unchecked-transfer` | Unchecked ERC20 transfer |
| `reentrancy-benign` | Benign reentrancy |
| `divide-before-multiply` | Precision loss |
| `unused-return` | Unused return values |

### Low
| Detector | What it finds |
|---|---|
| `missing-zero-check` | Missing zero address validation |
| `calls-loop` | Calls inside a loop |
| `timestamp` | Block timestamp dependence |
| `reentrancy-events` | Reentrancy affecting events |
| `assembly` | Assembly usage |
| `boolean-equal` | Boolean equality comparison |

## Custom Detectors
Slither supports custom detectors via plugins. See: https://github.com/crytic/slither/wiki/Adding-a-new-detector
