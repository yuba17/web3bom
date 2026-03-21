---
tags: [vulnerability, reentrancy]
severity: High
category: reentrancy
date: 2026-03-16
---

# Reentrancy (SC08)

## Classification
- **OWASP SC**: SC08
- **Severity**: High
- **Impact**: $35.7M in losses. Classic but still present
- **Likelihood**: Medium (dropping due to awareness, but cross-function variants still hit)

## Description
A contract makes an external call before updating its state. The called contract re-enters the original function (or another function sharing the same state) before the state update completes.

## Variants

### Classic Reentrancy
```solidity
// VULNERABLE
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}(""); // external call BEFORE state update
    require(ok);
    balances[msg.sender] -= amount; // state update AFTER
}

// FIXED - Checks-Effects-Interactions
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount; // state update BEFORE
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}
```

### Cross-Function Reentrancy
```solidity
// VULNERABLE - two functions share state
function withdraw() external {
    uint256 bal = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: bal}("");
    require(ok);
    balances[msg.sender] = 0;
}

function transfer(address to, uint256 amount) external {
    // attacker re-enters here during withdraw
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    balances[to] += amount;
}
```

### Read-Only Reentrancy
```solidity
// VULNERABLE - price read during callback
// Protocol A calls Protocol B which calls back to Protocol A
// Protocol A's state is stale during the callback
// Attacker exploits stale price/balance data
```

## Detection
- **Slither**: `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign`
- **Mythril**: detects classic patterns
- **Manual**: look for external calls before state updates, especially `.call{value:}`

## Mitigations
1. **Checks-Effects-Interactions** pattern (primary)
2. **ReentrancyGuard** (OpenZeppelin) — `nonReentrant` modifier
3. **Pull over Push** — let users withdraw instead of pushing funds

## Real-World Exploits
- The DAO ($60M, 2016) - the original reentrancy hack
- Curve Finance ($70M, 2023) - Vyper compiler reentrancy bug
- Fei Protocol ($80M, 2022) - cross-function reentrancy
