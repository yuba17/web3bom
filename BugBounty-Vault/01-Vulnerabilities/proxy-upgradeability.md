---
tags: [vulnerability, proxy, upgradeability]
severity: Critical
category: proxy
date: 2026-03-16
---

# Proxy & Upgradeability (SC10)

## Classification
- **OWASP SC**: SC10
- **Severity**: Critical
- **Impact**: Complete contract takeover or permanent bricking
- **Likelihood**: Medium

## Description
Upgradeable contracts use proxy patterns (Transparent, UUPS, Beacon) to allow logic updates. Misconfigurations can lead to:
- Uninitialized implementations (attacker takes control)
- Storage collisions between proxy and implementation
- Function selector clashing
- selfdestruct in implementation (bricks all proxies)

## Common Patterns

### Uninitialized Implementation
```solidity
// VULNERABLE — implementation can be initialized by attacker
contract MyContractV1 is Initializable, UUPSUpgradeable {
    function initialize(address admin) public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }
}

// FIXED — disable initializers in constructor
contract MyContractV1 is Initializable, UUPSUpgradeable {
    constructor() {
        _disableInitializers(); // blocks direct initialization
    }
    function initialize(address admin) public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }
}
```

### Storage Collision
```solidity
// V1
contract V1 {
    uint256 public value;  // slot 0
    address public owner;  // slot 1
}

// V2 — WRONG (inserts variable, shifts slots)
contract V2 {
    uint256 public value;    // slot 0
    uint256 public newVar;   // slot 1 — COLLISION with owner!
    address public owner;    // slot 2
}

// V2 — CORRECT (append only)
contract V2 {
    uint256 public value;    // slot 0
    address public owner;    // slot 1
    uint256 public newVar;   // slot 2 — new slot, no collision
}
```

### Storage Gap
```solidity
// Base contract must reserve storage for future variables
contract BaseV1 is Initializable {
    uint256 public value;
    uint256[49] private __gap; // reserve 49 slots
}
```

## Detection
- **Slither**: `unprotected-upgrade`
- **Manual**: Check for `initialize` without `initializer` modifier
- **Manual**: Compare storage layouts between versions

## Real-World Exploits
- Wormhole ($325M) — uninitialized implementation
- Audius ($6M) — uninitialized proxy storage
- Parity Wallet ($150M) — selfdestruct on library contract

## Checklist
- [ ] Implementation constructor calls `_disableInitializers()`
- [ ] Storage variables only appended, never inserted
- [ ] Base contracts use `__gap` pattern
- [ ] No selfdestruct in implementation
- [ ] `_authorizeUpgrade()` properly restricted (UUPS)
- [ ] Proxy admin != implementation admin (Transparent)
