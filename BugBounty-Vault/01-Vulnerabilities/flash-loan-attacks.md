---
tags: [vulnerability, flash-loan, oracle]
severity: High
category: flash-loan
date: 2026-03-16
---

# Flash Loan Attacks (SC04) & Oracle Manipulation (SC03)

## Classification
- **OWASP SC**: SC03 (Oracle) + SC04 (Flash Loan)
- **Severity**: High
- **Impact**: Flash Loans $33.8M + Oracle $8.8M in losses
- **Likelihood**: High in DeFi protocols using on-chain price feeds

## Description
Flash loans allow borrowing massive amounts without collateral (repaid in same tx). Combined with oracle manipulation, attackers can skew prices, drain pools, and profit atomically.

## Attack Flow
```
1. Flash borrow $100M from Aave/dYdX
2. Dump token A on DEX → crash price
3. Use crashed price in target protocol (which reads DEX price)
4. Borrow/liquidate at manipulated price
5. Restore token A price
6. Repay flash loan
7. Profit
```

## Vulnerable Pattern
```solidity
// VULNERABLE - spot price from AMM
function getPrice() public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserve0 * 1e18 / reserve1; // manipulable in same tx
}

// FIXED - use TWAP or Chainlink
function getPrice() public view returns (uint256) {
    (, int256 price,,,) = chainlinkFeed.latestRoundData();
    require(price > 0, "Invalid price");
    return uint256(price);
}
```

## Oracle Security Checklist
- [ ] Never use spot prices from AMMs (getReserves)
- [ ] Use Chainlink or TWAP (time-weighted average)
- [ ] Validate oracle freshness (staleness check)
- [ ] Check for negative/zero prices
- [ ] Use multiple oracle sources with fallback
- [ ] Circuit breakers for extreme price movements

## Detection
- **Manual**: search for `getReserves()`, `balanceOf()` used as price
- **Slither**: custom detectors for oracle patterns

## Real-World Exploits
- bZx ($8M, 2020) - flash loan + oracle manipulation
- Harvest Finance ($34M, 2020) - USDC/USDT price manipulation
- Mango Markets ($114M, 2022) - oracle manipulation
