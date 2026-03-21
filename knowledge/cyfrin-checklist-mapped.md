# Cyfrin Audit Checklist → Briefing Cross-Reference
# Source: github.com/Cyfrin/audit-checklist (117 items, verified)
# Purpose: Map external checklist to our briefings for gap analysis

## Mapped to: vault-erc4626.md
- SOL-AM-DA-1: Donation attack — relies on balance vs internal accounting
- SOL-Basics-Math-4: Division before multiplication (share calculation)
- SOL-Basics-Math-5: Rounding direction matters (deposit/withdraw)
- SOL-Basics-Math-6: Division by zero (empty vault)
- SOL-Basics-Math-12: Min/max values in calculation (first deposit edge)
- SOL-Basics-Payment-4: Minimum deposit/withdrawal amount

## Mapped to: lending.md
- SOL-AM-PMA-1: Price from token balance ratio (collateral valuation)
- SOL-AM-PMA-2: Price from DEX spot (oracle for lending)
- SOL-AM-ReentrancyAttack-1: View function stale value (read-only reentrancy on getPrice)
- SOL-AM-ReentrancyAttack-2: State change after external call (borrow/repay reentrancy)
- SOL-Basics-Math-5: Rounding direction (interest accrual, liquidation threshold)
- SOL-Basics-Function-5: Edge case inputs 0/max (borrow 0, repay max)

## Mapped to: oracle.md
- SOL-AM-PMA-1: Price from token balance ratio → use Chainlink
- SOL-AM-PMA-2: Price from DEX spot → use TWAP
- SOL-AM-MA-1: block.timestamp for time-sensitive (oracle freshness)
- SOL-AM-ReentrancyAttack-1: View function stale value during interaction

## Mapped to: flash-loan.md
- SOL-AM-DA-1: Donation attack (flash loan + donate to inflate)
- SOL-AM-FrA-2: Two-transaction safety (flash loan splits action across callbacks)
- SOL-AM-SandwichAttack-1: Slippage protection (flash loan sandwich)

## Mapped to: access-control.md
- SOL-Basics-AC-1: Clarify all actors and interactions
- SOL-Basics-AC-2: Functions lacking access controls
- SOL-Basics-AC-3: Whitelist requirements
- SOL-Basics-AC-4: Transfer of privileges (two-step)
- SOL-Basics-AC-5: State during privilege transfer
- SOL-Basics-AC-6: Inherited function accessibility
- SOL-Basics-AC-7: tx.origin vs msg.sender
- SOL-Basics-Function-6: Arbitrary user input (arbitrary call)
- SOL-Basics-Function-7: External vs public visibility
- SOL-Basics-Function-8: EOA vs contract restriction
- SOL-Basics-Function-9: Caller restriction
- SOL-AM-RP-1: Admin can pull assets (rug pull vector)

## Mapped to: bridge.md
- SOL-AM-ReplayAttack-1: Replay protection for failed transactions
- SOL-AM-ReplayAttack-2: Cross-chain replay (chain-specific domain separators)
- SOL-Basics-Function-1: Input validation (message validation)
- SOL-Basics-Function-6: Arbitrary user input (calldata injection)

## Mapped to: staking.md
- SOL-Basics-Math-2: Precision loss in time calculations (reward accrual)
- SOL-Basics-Math-3: Time unit casting to uint24 (epoch boundaries)
- SOL-Basics-AL-9: Huge array iteration (user array in reward distribution)
- SOL-AM-GA-1: External function relying on states changed by others (claim timing)
- SOL-AM-FrA-1: Get-or-create front-running (stake creation)

## Mapped to: dex-amm.md
- SOL-AM-PMA-1: Price from token balance ratio (AMM spot price)
- SOL-AM-SandwichAttack-1: Slippage protection
- SOL-AM-FrA-2: Two-transaction front-running (add/remove liquidity)
- SOL-Basics-Math-5: Rounding direction (swap calculations)
- SOL-Basics-Math-4: Division before multiplication (fee calculation)

## Mapped to: token-erc20.md
- SOL-Basics-Math-7: Underflow/overflow (transfer amounts)
- SOL-Basics-Type-1: Forced type casting (token decimals)
- SOL-AM-DOSA-3: Blacklisting functionality (USDC, USDT)
- SOL-AM-DOSA-5: Low decimal tokens causing DOS

## Mapped to: proxy/upgradeable (cross-cutting, relevant to all)
- SOL-Basics-PU-1 through PU-10: All proxy checks
- SOL-Basics-Initialization-1 through 3: Initialization checks

## GAPS: Items NOT covered by any briefing
- SOL-AM-DOSA-4: Queue processing DOS → needs new briefing or add to access-control
- SOL-AM-GA-2: Gas limit manipulation → add to dex-amm (DEX routing)
- SOL-AM-MA-2: Block properties for randomness → needs gaming/lottery briefing
- SOL-AM-SybilAttack-1: User count mechanism → needs governance briefing
- SOL-Basics-BR-1: CREATE vs CREATE2 → add to access-control
- SOL-Basics-Event-1: Missing events → informational, not a bug class
- SOL-Basics-AL-11: msg.value in loop → add to token-erc20 (multicall)
- All OpenZeppelin version issues → version-specific, not pattern-based
- All Solidity version issues → version-specific, not pattern-based
