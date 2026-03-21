---
tags: [vulnerability, token, erc20]
severity: Medium
category: token-interactions
date: 2026-03-16
---

# Token Interaction Pitfalls

## Weird ERC20 Tokens

Not all ERC20 tokens behave the same. Protocols that assume standard behavior break with:

### Fee-on-Transfer Tokens (PAXG, STA)
```solidity
// VULNERABLE — assumes received == amount
token.transferFrom(user, address(this), amount);
balances[user] += amount; // credits more than received!

// FIXED — measure actual received
uint256 before = token.balanceOf(address(this));
token.safeTransferFrom(user, address(this), amount);
uint256 received = token.balanceOf(address(this)) - before;
balances[user] += received;
```

### Rebasing Tokens (stETH, AMPL, OHM)
```
Contract holds 100 stETH
Rebase happens: now has 101 stETH
Internal accounting still shows 100
1 stETH trapped forever
```
**Fix:** Use wrapped versions (wstETH) or update internal accounting on rebase.

### Non-standard Return Values (USDT, BNB)
```solidity
// USDT's transfer() doesn't return bool — this reverts!
bool success = IERC20(usdt).transfer(to, amount);

// FIXED — use SafeERC20
IERC20(usdt).safeTransfer(to, amount);
```

### Tokens That Block on Zero Transfer
Some tokens revert on `transfer(to, 0)`. Always check `amount > 0`.

### Pausable Tokens (USDT, USDC)
If token is paused, all transfers revert. Your protocol could get stuck.

### Blacklistable Tokens (USDC, USDT)
If a user/contract is blacklisted, transfers to/from them revert.

### ERC777 Tokens (Reentrancy via hooks)
ERC777 tokens call `tokensReceived()` hook on the receiver during transfer.
This is a **reentrancy vector** even for simple token transfers.

## Approval Issues

### Approval Race Condition
```solidity
// User has allowance of 100
// User calls approve(50) — wants to change to 50
// Before tx mines, spender front-runs transferFrom(100)
// After tx mines, spender calls transferFrom(50) — stole 150 total!

// MITIGATION: Set to 0 first, then new value
token.approve(spender, 0);
token.approve(spender, newAmount);
// OR use increaseAllowance/decreaseAllowance
```

### USDT Requires Zero Approval First
```solidity
// USDT reverts if you try to change non-zero approval to non-zero
token.approve(spender, 0); // must do this first
token.approve(spender, amount);
```

## Checklist
- [ ] Use SafeERC20 for all ERC20 interactions
- [ ] Account for fee-on-transfer tokens
- [ ] Use wrapped versions of rebasing tokens
- [ ] Handle zero-amount transfers
- [ ] Consider pausable/blacklistable token scenarios
- [ ] Set approval to 0 before changing (USDT compatibility)
- [ ] Add nonReentrant for ERC777 reentrancy protection

## Reference
- https://github.com/d-xo/weird-erc20 — comprehensive list of weird ERC20 behaviors
