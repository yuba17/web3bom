---
tags: [vulnerability, access-control]
severity: Critical
category: access-control
date: 2026-03-16
---

# Access Control Vulnerabilities (SC01)

## Classification
- **OWASP SC**: SC01
- **Severity**: Critical
- **Impact**: $953.2M in losses (2024). #1 vulnerability in Web3
- **Likelihood**: High

## Description
Broken access control occurs when functions that should be restricted (admin-only, owner-only) can be called by unauthorized users. This is the #1 killer in Web3 — over $1.6B lost in H1 2025 alone.

## Common Patterns

### Missing Access Control
```solidity
// VULNERABLE - anyone can call
function mint(address to, uint256 amount) external {
    _mint(to, amount);
}

// FIXED
function mint(address to, uint256 amount) external onlyOwner {
    _mint(to, amount);
}
```

### Incorrect Modifier Logic
```solidity
// VULNERABLE - wrong comparison
modifier onlyAdmin() {
    require(msg.sender != admin); // should be ==
    _;
}
```

### Unprotected Initialize
```solidity
// VULNERABLE - proxy not initialized
function initialize(address _owner) public {
    owner = _owner; // can be called by anyone after deployment
}

// FIXED
function initialize(address _owner) public initializer {
    owner = _owner;
}
```

### tx.origin Authentication
```solidity
// VULNERABLE - phishable
require(tx.origin == owner);

// FIXED
require(msg.sender == owner);
```

## Detection
- **Slither detectors**: `unprotected-upgrade`, `missing-zero-check`, `tx-origin`
- **Manual**: grep for `external`/`public` functions without modifiers on state-changing operations

## Real-World Exploits
- Wormhole ($325M) - unprotected `initialize` function
- Ronin Bridge ($625M) - compromised validator keys
- Poly Network ($610M) - cross-chain access control bypass

## Key Checklist
- [ ] All state-changing functions have proper access control
- [ ] `initialize()` uses `initializer` modifier
- [ ] No use of `tx.origin` for auth
- [ ] Role-based access properly configured
- [ ] Ownership transfer is two-step
