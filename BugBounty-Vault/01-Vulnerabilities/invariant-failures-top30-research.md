# TOP 30 MOST COMMON INVARIANT FAILURES IN DEFI

Research compiled from: Solodit, Code4rena, Sherlock, Immunefi, Certora, Trail of Bits, Crytic/Properties, OWASP SC Top 10, Three Sigma, Halborn, Cyfrin, OpenZeppelin, and 50+ individual audit reports (2024-2025).

---

## Ranking Methodology

Frequency score = number of distinct protocols where this invariant violation was found as a High/Critical in public audits + bounty payouts. Cross-referenced across Solodit database, Code4rena reports, Sherlock contests, Immunefi writeups, and real-world exploit post-mortems.

---

## #1 — VAULT SHARE INFLATION / FIRST DEPOSITOR ATTACK

```
ID: SOLODIT-001
Source: Code4rena (GoGoPool, Astaria, 20+ others), Sherlock, Zellic (Perennial, Nukem)
Finding: First depositor can manipulate share price via donation to steal subsequent deposits
Invariant That Should Hold: convertToAssets(convertToShares(assets)) ~= assets (within 1 wei)
Category: Vault
Frequency: 50+ protocols (most common ERC4626 finding across ALL platforms)
Invariant as Code:
  assert(vault.convertToAssets(vault.convertToShares(amount)) >= amount - 1);
  assert(vault.totalSupply() == 0 || vault.totalAssets() > 0);
  // After any deposit: shares_received > 0
  assert(sharesReceived > 0);
```

**Why it keeps appearing:** Any vault without virtual shares/dead shares is vulnerable. OpenZeppelin added mitigations but custom vaults still miss it.

---

## #2 — PRICE ORACLE MANIPULATION / STALE PRICES

```
ID: SOLODIT-002
Source: OWASP SC02:2025, CertiK, Solodit (100+ findings), Immunefi (Enzyme, Mango Markets)
Finding: Protocol uses manipulable on-chain price (spot AMM price, stale Chainlink) for critical calculations
Invariant That Should Hold: oracle_price is within X% of true market price AND was updated within Y seconds
Category: Oracle
Frequency: 40+ protocols (34.3% of all machine-unauditable bugs per CertiK)
Invariant as Code:
  assert(block.timestamp - oracle.lastUpdated() <= MAX_STALENESS);
  assert(oracle.price() > 0);
  assert(oracle.price() >= minPrice && oracle.price() <= maxPrice);
  // For TWAP: assert(observationAge >= MIN_TWAP_WINDOW);
```

**Why it keeps appearing:** Protocols use spot prices or single-source oracles. $50M+ lost in 2024 alone.

---

## #3 — REENTRANCY (CROSS-FUNCTION AND READ-ONLY)

```
ID: SOLODIT-003
Source: OWASP SC03:2025, Solodit, Sherlock, Code4rena (Curve $73M, Penpie $27M)
Finding: External calls before state updates allow recursive calls; read-only reentrancy manipulates view function return values
Invariant That Should Hold: Contract state is consistent before AND after any external call
Category: Access Control
Frequency: 35+ protocols ($420M in losses by Q3 2025)
Invariant as Code:
  // System-level: no function can be re-entered during execution
  assert(!_locked);
  // Read-only: view functions return same value before and after external call
  assert(totalAssets_before == totalAssets_after); // during callback
```

**Why it keeps appearing:** Cross-function and read-only variants bypass traditional nonReentrant guards.

---

## #4 — ACCESS CONTROL / MISSING AUTHORIZATION

```
ID: SOLODIT-004
Source: OWASP SC01:2025 (#1 by losses), Solodit, Code4rena, Immunefi (Wormhole $10M, Aurora $6M)
Finding: Privileged functions callable by unauthorized addresses due to missing/incorrect access checks
Invariant That Should Hold: Only addresses with role R can execute function F
Category: Access Control
Frequency: 30+ protocols ($953.2M in losses per OWASP 2025)
Invariant as Code:
  // For every privileged function:
  assert(hasRole(REQUIRED_ROLE, msg.sender));
  // Post-upgrade: assert(owner() == expected_owner);
  // Proxy: assert(implementation() != address(0));
```

**Why it keeps appearing:** Proxy upgrades reset state, missing modifiers on new functions, compromised multisigs.

---

## #5 — ROUNDING DIRECTION INCONSISTENCY

```
ID: SOLODIT-005
Source: Crytic ERC4626 properties, Code4rena (30+ contests), Sherlock (Burve 2025), Raft Finance ($3.6M)
Finding: Deposit/withdraw use different rounding directions, allowing profit extraction via round-trip
Invariant That Should Hold: Rounding always favors the protocol (vault), never the user
Category: Math / Vault
Frequency: 30+ protocols
Invariant as Code:
  // Deposits: round shares DOWN (user gets fewer shares)
  assert(previewDeposit(assets) <= convertToShares(assets));
  // Withdrawals: round assets DOWN (user gets fewer assets)
  assert(previewRedeem(shares) <= convertToAssets(shares));
  // Mints: round assets UP (user pays more)
  assert(previewMint(shares) >= convertToAssets(shares));
  // Withdraws: round shares UP (user burns more shares)
  assert(previewWithdraw(assets) >= convertToShares(assets));
```

**Why it keeps appearing:** Solidity integer division always truncates. Custom math libraries often round inconsistently across functions.

---

## #6 — LIQUIDATION DOS / BLOCKED LIQUIDATIONS

```
ID: SOLODIT-006
Source: Cyfrin, Code4rena (25+ lending protocols), Sherlock
Finding: Liquidation can be blocked by: ERC721 callback revert, unbounded loops, token deny-lists, pending actions
Invariant That Should Hold: Any position meeting liquidation criteria MUST be liquidatable
Category: Lending
Frequency: 25+ protocols
Invariant as Code:
  // If health_factor < 1, liquidation MUST succeed
  if (healthFactor(user) < LIQUIDATION_THRESHOLD) {
    assert(liquidate(user) == SUCCESS);
  }
  // Liquidation must not depend on external callbacks
  // Liquidation must not iterate unbounded arrays
```

**Why it keeps appearing:** 35 distinct liquidation vulnerability sub-patterns identified (see Cyfrin research). Attackers use callbacks, front-running, token blacklists.

---

## #7 — BAD DEBT ACCUMULATION WITHOUT SOCIALIZATION

```
ID: SOLODIT-007
Source: Code4rena, Sherlock, Immunefi (Euler $196M), Solodit
Finding: Underwater positions (collateral < debt) cannot be profitably liquidated, accumulating protocol-level bad debt
Invariant That Should Hold: Protocol total assets >= protocol total liabilities (solvency)
Category: Lending
Frequency: 25+ protocols
Invariant as Code:
  assert(totalCollateralValue() >= totalDebtValue()); // protocol-level solvency
  // Per-position after liquidation:
  assert(position.collateral >= position.debt || badDebtHandled);
  // Insurance fund: assert(insuranceFund >= accumulatedBadDebt);
```

**Why it keeps appearing:** Dust positions too small to profitably liquidate. Insurance funds deplete. No socialization mechanism.

---

## #8 — INPUT VALIDATION FAILURES

```
ID: SOLODIT-008
Source: OWASP SC05:2025, Three Sigma (34.6% of exploits), Solodit, Code4rena
Finding: Functions accept parameters that violate logical preconditions (zero addresses, extreme values, wrong token)
Invariant That Should Hold: All function parameters satisfy documented preconditions before execution
Category: Access Control
Frequency: 25+ protocols (34.6% of direct contract exploits)
Invariant as Code:
  assert(amount > 0 && amount <= maxAllowed);
  assert(recipient != address(0));
  assert(token.isSupported());
  assert(deadline >= block.timestamp);
```

**Why it keeps appearing:** Most basic category but highest raw count. Forgotten checks on new functions.

---

## #9 — ERC20 SUPPLY CONSERVATION VIOLATION

```
ID: SOLODIT-009
Source: Crytic properties, Certora, Code4rena, Immunefi (Optimism $2M infinite mint)
Finding: sum(balances) != totalSupply after mint/burn/transfer edge cases; infinite minting via logic error
Invariant That Should Hold: sum(all balances) == totalSupply() at all times
Category: Token
Frequency: 20+ protocols
Invariant as Code:
  assert(sumOfAllBalances == token.totalSupply());
  assert(balanceOf(user) <= token.totalSupply());
  assert(balanceOf(address(0)) == 0);
```

**Why it keeps appearing:** Custom token implementations, rebasing tokens, fee-on-transfer tokens break assumptions.

---

## #10 — FLASH LOAN PRICE/STATE MANIPULATION

```
ID: SOLODIT-010
Source: OWASP SC04:2025, Solodit, Immunefi (Fei $800K, Euler $196M), Code4rena
Finding: Protocol reads state (balances, prices, shares) that can be manipulated within a single transaction via flash loan
Invariant That Should Hold: No critical calculation depends on values manipulable within one transaction
Category: Oracle / Lending
Frequency: 20+ protocols (83.3% of eligible exploits in 2024 used flash loans)
Invariant as Code:
  // Share price cannot change by more than X% in one block
  assert(abs(sharePrice_current - sharePrice_lastBlock) <= MAX_CHANGE_PER_BLOCK);
  // Deposits in same block as read should not affect price used
  assert(oracle.price() == oracle.priceAtBlock(block.number - 1));
```

---

## #11 — UNINITIALIZED PROXY / STORAGE COLLISION

```
ID: SOLODIT-011
Source: Immunefi (Wormhole $10M, Ronin $12M), Code4rena, Solodit
Finding: Proxy upgrade leaves critical state variables uninitialized (owner, threshold, implementation) or storage slots collide
Invariant That Should Hold: After upgrade, all critical state variables retain valid values
Category: Access Control
Frequency: 18+ protocols
Invariant as Code:
  assert(owner() != address(0));
  assert(implementation() != address(0));
  assert(multisigThreshold() > 0);
  // Storage layout: assert(slot(var) == expected_slot);
```

---

## #12 — REWARD DISTRIBUTION CALCULATION ERROR

```
ID: SOLODIT-012
Source: Code4rena, Sherlock, Immunefi (Notional $1.1M), Solodit
Finding: Rewards calculated incorrectly: wrong time period, wrong balance snapshot, precision loss on small stakes
Invariant That Should Hold: rewards_earned == integral(stake_amount * reward_rate, over time_staked)
Category: Staking
Frequency: 18+ protocols
Invariant as Code:
  assert(rewardPerToken_after >= rewardPerToken_before); // monotonically increasing
  assert(earned(user) <= totalRewardsDistributed);
  assert(sum(all_user_rewards) <= totalRewardsPool);
```

---

## #13 — DOUBLE-CLAIM / REPLAY OF REWARDS

```
ID: SOLODIT-013
Source: Code4rena, Sherlock, Solodit, Immunefi
Finding: User can claim rewards multiple times via: missing claim flag, cross-chain replay, re-entering claim function
Invariant That Should Hold: Each reward epoch can be claimed exactly once per eligible address
Category: Staking
Frequency: 15+ protocols
Invariant as Code:
  assert(hasClaimed[user][epoch] == false); // before claim
  // After claim:
  assert(hasClaimed[user][epoch] == true);
  assert(sum(claimed) <= totalAllocated);
```

---

## #14 — COLLATERAL RATIO VIOLATION AFTER OPERATION

```
ID: SOLODIT-014
Source: Code4rena, Sherlock, Solodit (all lending protocols)
Finding: User operation (borrow, withdraw collateral, trade) leaves position undercollateralized without triggering check
Invariant That Should Hold: After ANY user action, health_factor >= minimum_threshold
Category: Lending
Frequency: 15+ protocols
Invariant as Code:
  // After every non-liquidation user action:
  assert(healthFactor(msg.sender) >= MIN_HEALTH_FACTOR);
  assert(collateralValue(user) * LTV >= debtValue(user));
```

---

## #15 — AMM CONSTANT PRODUCT VIOLATION

```
ID: SOLODIT-015
Source: Code4rena, Sherlock, Solodit (Curve, Uniswap forks, custom AMMs)
Finding: k = x * y decreases after swap (should stay constant or increase from fees)
Invariant That Should Hold: k_after >= k_before for every swap
Category: DEX
Frequency: 15+ protocols
Invariant as Code:
  uint k_before = reserveX * reserveY;
  // ... swap executes ...
  uint k_after = reserveX_new * reserveY_new;
  assert(k_after >= k_before);
```

---

## #16 — BRIDGE MESSAGE REPLAY / MISSING CHAIN-ID

```
ID: SOLODIT-016
Source: Chainlink, Code4rena, Immunefi, Solodit (Polygon Plasma, Gnosis Omni, Ronin)
Finding: Cross-chain message can be replayed on different chain or re-submitted due to missing nonce/chainId validation
Invariant That Should Hold: Each cross-chain message is processed exactly once on exactly one destination chain
Category: Bridge
Frequency: 15+ protocols ($2B+ total bridge losses)
Invariant as Code:
  assert(!processedMessages[messageHash]);
  assert(msg.chainId == expectedDestinationChainId);
  assert(msg.nonce == expectedNonce[sender]++);
  // After processing: processedMessages[messageHash] = true;
```

---

## #17 — INTEREST ACCRUAL DURING PAUSE / UNFAIR LIQUIDATION

```
ID: SOLODIT-017
Source: Cyfrin, Code4rena, Sherlock
Finding: Interest keeps accruing while protocol is paused (users cannot repay), leading to instant liquidation on unpause
Invariant That Should Hold: Interest MUST NOT accrue when repayment is impossible
Category: Lending
Frequency: 12+ protocols
Invariant as Code:
  if (paused()) {
    assert(interestAccrued_now == interestAccrued_atPause);
  }
  // OR: grace period after unpause before liquidations enabled
  assert(!liquidatable(user) || block.timestamp > unpauseTime + GRACE_PERIOD);
```

---

## #18 — ARBITRARY EXTERNAL CALL / CALLDATA INJECTION

```
ID: SOLODIT-018
Source: Three Sigma, Immunefi (LI.FI $9M, Zapper $25K), Code4rena
Finding: Function accepts unchecked calldata/address and executes arbitrary external call, enabling unauthorized transferFrom
Invariant That Should Hold: External calls target only whitelisted addresses with validated function selectors
Category: Access Control
Frequency: 12+ protocols
Invariant as Code:
  assert(whitelistedTargets[target]);
  assert(allowedSelectors[bytes4(callData)]);
  // Never: target.call(userProvidedCallData);
```

---

## #19 — FEE-ON-TRANSFER TOKEN ACCOUNTING MISMATCH

```
ID: SOLODIT-019
Source: Code4rena (20+ contests), Sherlock, Solodit
Finding: Protocol assumes transferred amount == received amount, but fee-on-transfer tokens deliver less
Invariant That Should Hold: recorded_amount == actual_balance_change (not parameter amount)
Category: Token
Frequency: 12+ protocols
Invariant as Code:
  uint balBefore = token.balanceOf(address(this));
  token.transferFrom(user, address(this), amount);
  uint received = token.balanceOf(address(this)) - balBefore;
  assert(recorded_deposit == received); // NOT amount
```

---

## #20 — GOVERNANCE MANIPULATION / FLASH-LOAN VOTING

```
ID: SOLODIT-020
Source: Code4rena, Immunefi (Compound $25M at risk), Solodit
Finding: Attacker accumulates voting power via flash loan or delegation to pass malicious proposal
Invariant That Should Hold: Voting power snapshot must precede proposal creation; flash-loaned tokens cannot vote
Category: Access Control
Frequency: 10+ protocols
Invariant as Code:
  assert(votingPowerSnapshot[user] == balanceAt(user, proposalBlock - 1));
  assert(proposalBlock > snapshotBlock);
  // Quorum must represent genuine long-term holders
```

---

## #21 — PRECISION LOSS IN SHARE/REWARD CALCULATIONS

```
ID: SOLODIT-021
Source: Code4rena, Sherlock (Onyx $2.1M, Raft $3.6M), Solodit
Finding: Repeated small operations accumulate rounding dust that attacker extracts or that blocks withdrawals
Invariant That Should Hold: sum(shares) * pricePerShare ~= totalAssets (within acceptable dust threshold)
Category: Math
Frequency: 10+ protocols
Invariant as Code:
  // After N deposit/withdraw cycles:
  assert(abs(totalAssets() - totalSupply() * pricePerShare()) <= N * 1);
  // No user can profit from deposit-then-immediate-withdraw
  assert(assetsOut <= assetsIn); // for same-block round-trip
```

---

## #22 — LIQUIDATION WORSENS BORROWER HEALTH

```
ID: SOLODIT-022
Source: Cyfrin, Code4rena, Sherlock
Finding: Partial liquidation seizes best collateral, leaving position with worse health factor than before
Invariant That Should Hold: healthFactor_after >= healthFactor_before for any liquidation
Category: Lending
Frequency: 10+ protocols
Invariant as Code:
  uint hf_before = healthFactor(borrower);
  liquidate(borrower, collateralType, amount);
  assert(healthFactor(borrower) >= hf_before);
```

---

## #23 — VAULT totalAssets MANIPULATION

```
ID: SOLODIT-023
Source: Code4rena, Sherlock, Certora (Balancer V2 insolvency)
Finding: totalAssets() includes donated/manipulable balances, allowing share price manipulation
Invariant That Should Hold: totalAssets() reflects only legitimate deposits + earned yield
Category: Vault
Frequency: 10+ protocols
Invariant as Code:
  // totalAssets should not change from direct token transfer (donation)
  assert(vault.totalAssets() == tracked_deposits + earned_yield);
  // NOT: assert(vault.totalAssets() == token.balanceOf(address(vault)));
```

---

## #24 — MISSING SLIPPAGE/DEADLINE PROTECTION

```
ID: SOLODIT-024
Source: Code4rena (extremely common), Sherlock, Solodit
Finding: Swap/deposit/withdraw has no minimum output amount or deadline, enabling sandwich attacks
Invariant That Should Hold: User receives >= minAmountOut AND tx executes before deadline
Category: DEX / Vault
Frequency: 10+ protocols
Invariant as Code:
  assert(amountOut >= minAmountOut);
  assert(block.timestamp <= deadline);
```

---

## #25 — NON-18 DECIMAL TOKEN ACCOUNTING ERROR

```
ID: SOLODIT-025
Source: Cyfrin, Code4rena, Sherlock (USDC 6 decimals, WBTC 8 decimals)
Finding: Math assumes 18 decimals; 6-decimal tokens cause 1e12x over/under valuation
Invariant That Should Hold: All calculations normalize to common precision before arithmetic
Category: Math
Frequency: 10+ protocols
Invariant as Code:
  // Normalize: value_18 = amount * 10^(18 - token.decimals())
  assert(normalizedValue == amount * (10 ** (18 - decimals)));
```

---

## #26 — DONATION ATTACK ON SHARE PRICE

```
ID: SOLODIT-026
Source: Code4rena, Sherlock, Immunefi (Euler donate-to-reserve $196M)
Finding: Direct token transfer to vault/pool inflates share price, enabling various exploits
Invariant That Should Hold: Share price changes only through deposit/withdraw/legitimate yield, NOT direct transfers
Category: Vault
Frequency: 10+ protocols
Invariant as Code:
  // pricePerShare should not change from external token.transfer()
  uint pps_before = vault.convertToAssets(1e18);
  token.transfer(address(vault), donation);
  assert(vault.convertToAssets(1e18) == pps_before); // if using internal accounting
```

---

## #27 — FRONT-RUNNING LIQUIDATION PREVENTION

```
ID: SOLODIT-027
Source: Cyfrin, Code4rena, Sherlock
Finding: Liquidatable user front-runs liquidation tx by: self-liquidating minimum amount, incrementing nonce, resetting cooldown
Invariant That Should Hold: Once liquidatable, user cannot take actions that prevent liquidation
Category: Lending
Frequency: 8+ protocols
Invariant as Code:
  if (isLiquidatable(user)) {
    assert(!canUserModifyPosition(user)); // user actions restricted
  }
```

---

## #28 — L2 SEQUENCER DOWN / GRACE PERIOD MISSING

```
ID: SOLODIT-028
Source: Code4rena, Sherlock (Arbitrum, Optimism protocols)
Finding: After L2 sequencer restart, stale oracle prices + no grace period = unfair mass liquidations
Invariant That Should Hold: Users get grace period to add collateral after sequencer downtime
Category: Oracle / Lending
Frequency: 8+ protocols
Invariant as Code:
  if (sequencerJustRestarted()) {
    assert(block.timestamp > sequencerUptime + GRACE_PERIOD);
  }
  assert(!isOracleStaleAfterSequencerRestart(oracle));
```

---

## #29 — CROSS-CONTRACT STORAGE INCONSISTENCY

```
ID: SOLODIT-029
Source: Code4rena, Sherlock, Solodit
Finding: Two contracts share state but update it independently, creating inconsistency (e.g., debt in contract A != credit in contract B)
Invariant That Should Hold: sum(debits across all contracts) == sum(credits across all contracts)
Category: Vault / Lending
Frequency: 8+ protocols
Invariant as Code:
  assert(contractA.totalDebt() == contractB.totalCredit());
  assert(contractA.userBalance(user) + contractB.userBalance(user) == totalUserFunds);
```

---

## #30 — NO GAP BETWEEN BORROW LTV AND LIQUIDATION LTV

```
ID: SOLODIT-030
Source: Cyfrin, Code4rena, Sherlock
Finding: Borrow LTV == liquidation threshold means positions are immediately liquidatable after borrowing
Invariant That Should Hold: liquidation_threshold > borrow_LTV + safety_buffer
Category: Lending
Frequency: 8+ protocols
Invariant as Code:
  assert(LIQUIDATION_LTV > BORROW_LTV);
  assert(LIQUIDATION_LTV - BORROW_LTV >= MIN_SAFETY_BUFFER);
  // After borrowing at max LTV, user is NOT immediately liquidatable
  borrow(maxAmount);
  assert(healthFactor(user) > 1.0);
```

---

## SUMMARY: FREQUENCY DISTRIBUTION BY CATEGORY

| Category | Count in Top 30 | % of Findings |
|---|---|---|
| **Lending** | 9 | 30% |
| **Vault / ERC4626** | 6 | 20% |
| **Access Control** | 5 | 17% |
| **Math / Precision** | 4 | 13% |
| **Oracle** | 3 | 10% |
| **DEX / AMM** | 2 | 7% |
| **Bridge** | 1 | 3% |

---

## SUMMARY: TOP INVARIANT CATEGORIES BY FINANCIAL IMPACT

| Rank | Category | Est. Losses (2024-2025) |
|---|---|---|
| 1 | Access Control | $1.83B+ (59% of H1 2025) |
| 2 | Oracle Manipulation | $400M+ (dropping to $70M w/ improvements) |
| 3 | Reentrancy | $420M by Q3 2025 |
| 4 | Flash Loan (enabler) | 83.3% of eligible exploits in 2024 |
| 5 | Logic Errors | $63.8M per OWASP |
| 6 | Bridge Exploits | $2B+ cumulative |
| 7 | Vault/Share Attacks | $200M+ (Euler alone = $196M) |

---

## CRYTIC/PROPERTIES READY-TO-USE INVARIANTS

Pre-built test suites from Trail of Bits (install via `forge install crytic/properties`):

- **ERC20**: 25 properties covering supply conservation, transfer integrity, allowance management, burn/mint, pause
- **ERC721**: 19 properties covering ownership, transfer, burn, approval
- **ERC4626**: 37 properties covering rounding direction (10), sender independence (6), must-not-revert (8), functional accounting (4), security (2 — inflation attack + decimal check), approval (6)
- **ABDKMath64x64**: 67 properties covering addition, subtraction, multiplication, division, negation, absolute value, inverse, average

---

## OWASP SMART CONTRACT TOP 10 (2025) — FOR REFERENCE

1. **SC01**: Access Control Vulnerabilities — $953.2M
2. **SC02**: Price Oracle Manipulation — $8.8M
3. **SC03**: Reentrancy Attacks — $35.7M
4. **SC04**: Flash Loan Attacks — $33.8M
5. **SC05**: Lack of Input Validation — $14.6M
6. **SC06**: Logic Errors — $63.8M
7. **SC07**: Unchecked External Calls — $550.7K
8. **SC08**: (Front-running / MEV)
9. **SC09**: (Denial of Service)
10. **SC10**: Denial of Service — gas griefing (17.5% of DoS in 2025)

---

## SOURCES

- [Three Sigma — 2024 Most Exploited DeFi Vulnerabilities](https://threesigma.xyz/blog/exploit/2024-defi-exploits-top-vulnerabilities)
- [Halborn — Top 100 DeFi Hacks Report 2025](https://www.halborn.com/reports/top-100-defi-hacks-2025)
- [OWASP Smart Contract Top 10 2025](https://owasp.org/www-project-smart-contract-top-10/)
- [Crytic Properties — Pre-built Security Properties](https://github.com/crytic/properties)
- [Crytic Properties — Full Property List](https://github.com/crytic/properties/blob/main/PROPERTIES.md)
- [Trail of Bits — Invariant-Driven Development](https://blog.trailofbits.com/2025/02/12/the-call-for-invariant-driven-development/)
- [Trail of Bits — Reusable Properties for Ethereum Contracts](https://blog.trailofbits.com/2023/02/27/reusable-properties-ethereum-contracts-echidna/)
- [Certora — Formal Verification for DeFi](https://www.certora.com/blog/formal-verification)
- [OpenZeppelin — ERC4626 Inflation Attack Defense](https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks)
- [Cyfrin — DeFi Liquidation Vulnerabilities](https://www.cyfrin.io/blog/defi-liquidation-vulnerabilities-and-mitigation-strategies)
- [Cyfrin/Solodit Audit Checklist](https://github.com/Cyfrin/audit-checklist)
- [Chainlink — 7 Cross-Chain Bridge Vulnerabilities](https://chain.link/education-hub/cross-chain-bridge-vulnerabilities)
- [Immunefi Bug Bounty Writeups List](https://github.com/sayan011/Immunefi-bug-bounty-writeups-list)
- [Recon — How to Define Invariants](https://getrecon.substack.com/p/how-to-define-invariants)
- [Halborn — Read-Only Reentrancy](https://www.halborn.com/blog/post/what-is-read-only-reentrancy)
- [MixBytes — Inflation Attack Overview](https://mixbytes.io/blog/overview-of-the-inflation-attack)
- [ERC4626 Properties Chimera](https://github.com/giovannidisiena/properties-chimera)
- [Hacken — Uniswap V4 Truncated Oracle TWAP](https://hacken.io/discover/uniswap-v4-truncated-oracle/)
