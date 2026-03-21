---
tags: [protocol, lending, bounty-active]
platform: code4rena
bounty_max: $250,000
date_started: 2026-03-16
status: studying
chains: [base, optimism, moonbeam, moonriver]
---

# Moonwell — Code4rena Bug Bounty

## Overview
- **Type**: Lending/Borrowing (Compound v2 fork)
- **Chains**: Base, Optimism, Moonbeam, Moonriver
- **TVL**: Multi-chain, significant
- **Max Bounty**: $250,000 USDC (Critical)
- **High**: $15,000 - $20,000
- **Medium**: $1,000 - $5,000 (gratuity)
- **PoC Required**: Yes, for Critical and High
- **KYC Required**: Yes

## Payout Scaling (Funds at Risk)
- <$5M: 10% of bounty → Critical = $25K
- $5M-$10M: 25% → Critical = $62.5K
- $10M-$50M: 50% → Critical = $125K
- $50M-$250M: 75% → Critical = $187.5K
- >$250M: 100% → Critical = $250K
- **Critical minimum**: $100K regardless

## Architecture
Fork of Compound v2 with:
- Multi-chain governance (Moonbeam → Base/Optimism via Wormhole)
- Multi-reward distributor (multiple reward tokens per market)
- Chainlink oracles + composite oracles for LSTs
- **NEW: OEV (Oracle Extractable Value) wrappers** — price delay mechanism
- **NEW: Mamo Strategy system** — ERC4626 vaults + Morpho integration
- xWELL cross-chain token

## Priority Targets (Highest to Lowest)

### TIER 1 — Newest code, least audited, highest impact
1. **ChainlinkOEVWrapper.sol** (693 LOC) — NEW OEV mechanism
   - Price delay logic in latestRoundData()
   - Fee split math in _calculateCollateralSplit()
   - updatePriceEarlyAndLiquidate() flow
2. **ChainlinkCompositeOEVWrapper.sol** (662 LOC) — Composite OEV
3. **ChainlinkOEVMorphoWrapper.sol** (606 LOC) — Morpho variant
4. **Mamo Strategy contracts** — NEW strategy system
   - Slippage Price Checker
   - ERC20 Market and Morpho Vault Strategy
   - Strategy Factory contracts

### TIER 2 — Core lending, high funds at risk
5. **MToken.sol** (2222 LOC) — Core lending token
6. **Comptroller.sol** (1418 LOC) — Business logic
7. **MultiRewardDistributor.sol** (1249 LOC) — Reward distribution

### TIER 3 — Cross-chain governance
8. **TemporalGovernor.sol** (439 LOC) — Cross-chain executor
9. **MultichainGovernor.sol** (1329 LOC) — Governance hub
10. **WormholeBridgeAdapter.sol** — Token bridging
11. **xWELL.sol** — Cross-chain token with mint limits

### TIER 4 — Smaller surface area
12. WETHRouter.sol — ETH wrapper
13. ChainlinkOracle.sol — Price feeds
14. StakedWell/stkWELL — Staking
15. EcosystemReserve — Treasury

## Key Attack Vectors

### A. OEV Price Manipulation (TIER 1)
The OEV wrapper delays price updates unless someone pays for early access.
- Can stale prices be exploited for unfair liquidations?
- Can the fee split be manipulated?
- What if cachedRoundId is manipulated?

### B. Liquidation Logic (TIER 1-2)
- Can liquidations happen when they shouldn't?
- Can liquidation bonus be stolen via OEV wrapper?
- Cross-market liquidation edge cases

### C. Reward Distribution (TIER 2)
- Reward accrual with 0 supply/borrow
- Can rewards be claimed multiple times?
- Precision loss in reward calculations

### D. Cross-Chain Governance (TIER 3)
- Replay attacks on governance messages
- permissionlessUnpause() timing exploitation
- Vote counting edge cases

## Known Issues (OUT OF SCOPE — DO NOT REPORT)
- Wormhole going offline/malicious
- Governor turning malicious
- Pause Guardian malicious
- Timestamp drift <45 seconds between chains
- Double voting from timestamp drift
- Quorum set to zero
- enterMarkets not required for seizure
- Temporal Governor can't receive raw ETH
- Borrow rewards don't accrue without claim when speed not set
- Reward speed 0 → on accrual issue
- New markets require no CF + burned supply
- Gas limit governance issue

## Previous Audits
- Multiple audits listed at docs.moonwell.fi
- 2023-07 Code4rena contest: github.com/code-423n4/2023-07-moonwell
- All previous audit findings are OUT OF SCOPE

## Attack Plan
1. Start with OEV wrappers (newest, most complex)
2. Fork Base mainnet, reproduce liquidation flows
3. Focus on math precision in fee split calculations
4. Check Mamo strategy edge cases
5. Look for cross-contract interaction bugs between OEV + Comptroller + MToken
