---
tags: [vulnerability, logic]
severity: High
category: business-logic
date: 2026-03-16
---

# Business Logic Errors (SC02)

## Classification
- **OWASP SC**: SC02
- **Severity**: High
- **Impact**: $63.8M in losses. Rising to #2 due to DeFi complexity
- **Likelihood**: High

## Description
Logic bugs are flaws in the intended behavior of the protocol. The code compiles and runs, but doesn't do what it should. These are the hardest to find with automated tools — manual review is essential.

## Common Patterns

### Incorrect Fee/Reward Calculation
```solidity
// VULNERABLE - rounding error allows free minting
function deposit(uint256 amount) external {
    uint256 shares = amount * totalShares / totalAssets; // if totalAssets > totalShares, small deposits get 0 shares but tokens are taken
    _mint(msg.sender, shares);
}
```

### Missing Edge Case
```solidity
// VULNERABLE - first depositor can manipulate share price
function deposit(uint256 amount) external {
    uint256 shares;
    if (totalSupply() == 0) {
        shares = amount; // first deposit sets the ratio
    } else {
        shares = amount * totalSupply() / totalAssets();
    }
    // Attacker: deposit 1 wei, donate 1M tokens, next depositor gets 0 shares
}
```

### Incorrect State Transitions
```solidity
// VULNERABLE - can claim rewards multiple times
function claim() external {
    uint256 reward = pendingRewards[msg.sender];
    token.transfer(msg.sender, reward);
    // MISSING: pendingRewards[msg.sender] = 0;
}
```

### Wrong Comparison Operators
```solidity
// VULNERABLE
require(block.timestamp > deadline); // should be >=, off by one

// VULNERABLE
require(amount < maxAmount); // should be <=
```

## Detection
- **Automated tools**: Very limited — logic bugs require understanding intent
- **Manual**: Compare docs/specs vs actual implementation
- **Fuzzing**: Invariant tests can catch unexpected states

## Key Areas to Check
- First/last depositor edge cases
- Rounding direction (should favor protocol, not user)
- Fee calculations at boundaries (0, 1 wei, max uint)
- State machine transitions
- Reward distribution fairness
- Liquidation threshold accuracy
