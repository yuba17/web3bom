# Fee Distribution & Revenue Sharing — Combat Briefing

> Everything an auditor needs before reading a fee distribution, revenue sharing, dividend token, or fee-on-transfer contract.
> Covers: protocol fee accounting, reflection tokens, reward distribution (MasterChef/Synthetix patterns), fee-on-transfer handling, rebasing interactions, referral fee gaming, and fee tier manipulation.

---

## 1. Bugs Conocidos

### 1.1 Fee-on-Transfer Token Accounting Mismatch

```yaml
- id: fd-001
  pattern: fee-on-transfer-accounting
  titulo: "Protocol assumes amount sent equals amount received for fee-on-transfer tokens"
  causa_raiz: >
    When a token charges a transfer tax (e.g., SafeMoon, USDT with fee enabled),
    the amount received by the contract is less than the amount specified in
    transferFrom(). If the protocol records the input amount rather than
    measuring the actual balance change, it creates a phantom surplus in
    internal accounting. Over time, the last withdrawers cannot withdraw
    because the contract's real balance is less than the sum of recorded
    balances.
  como_funciona: |
    1. User deposits 1000 tokens with 5% transfer tax
    2. Contract receives 950 tokens but records balance[user] = 1000
    3. Repeat for N users: total recorded = N*1000, actual balance = N*950
    4. When users try to withdraw, the last ~5% of users get reverts
       (insufficient balance) or the protocol is insolvent by N*50 tokens
    5. In lending protocols: borrower borrows 1000 based on 1000 collateral
       recorded, but only 950 is actually deposited — instant bad debt
  invariante: |
    // After any deposit, recorded amount must equal actual balance change
    uint256 balBefore = token.balanceOf(address(this));
    token.transferFrom(user, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balBefore;
    assert(internalBalance[user] == received); // NOT amount
  que_mirar:
    - "Does the contract measure balanceOf before/after transfer?"
    - "Is the raw `amount` parameter used for internal accounting?"
    - "Does the protocol claim to support arbitrary ERC-20 tokens?"
    - "Are there safeTransferFrom calls where return value is ignored?"
    - "grep: transferFrom.*amount followed by balances[.*] = amount"
  como_se_arregla: >
    Measure actual received: uint256 received = balanceOf(after) - balanceOf(before).
    Use the `received` value for all internal accounting. Alternatively,
    explicitly blacklist fee-on-transfer tokens if they are not intended
    to be supported, with a whitelist check on deposit.
  trampas:
    - "USDT does NOT currently charge fees but has the capability — auditors often flag this as Medium but judges may downgrade to Low/QA if fee is currently 0"
    - "Some fee-on-transfer tokens have variable tax rates that change per block — even measuring balance diff can be stale"
    - "If the protocol docs explicitly state 'standard ERC-20 only', this is typically QA/Low"
    - "Rebasing tokens cause similar but distinct issues — don't conflate"
  solodit_ids:
    - fee-on-transfer-tokens-will-cause-users-to-lose-funds-codehawks-beedle-oracle-free-perpetual-lending-git
    - m-01-fee-on-transfer-tokens-will-not-behave-as-expected-code4rena-numoen-numoen-contest-git
    - m-1-it-doesnt-handle-fee-on-transferdeflationary-tokens-sherlock-bullvbear-bull-v-bear-git
    - accounting-errors-with-deflationary-tokens-halborn-lpbase-exchange-markdown
    - fee-on-transfer-can-block-several-functions-spearbit-gauntlet-pdf
  incidentes:
    - "Beedle (CodeHawks) — Fee-on-transfer tokens cause loss of user funds in lending pool; recorded collateral exceeds actual, enabling undercollateralized borrows (HIGH)"
    - "BullvBear (Sherlock) — Protocol doesn't handle fee-on-transfer/deflationary tokens, order settlement fails or loses funds (MEDIUM)"
    - "Numoen (C4) — Fee-on-transfer tokens cause accounting mismatch in AMM, LPs lose funds proportional to tax rate (MEDIUM)"
    - "GammaSwap (Halborn) — Core strategies and periphery incompatible with fee-on-transfer tokens (MEDIUM)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

### 1.2 Revenue Share Rounding Dust Accumulation

```yaml
- id: fd-002
  pattern: revenue-share-rounding-dust
  titulo: "Small fee amounts round to zero per recipient, accumulating as permanently locked dust"
  causa_raiz: >
    When distributing fees across N recipients (stakers, LPs, shareholders),
    integer division of small amounts produces zero for each recipient.
    The total distributed is 0 * N = 0, but the fee was deducted from
    the source. The difference accumulates as dust locked in the contract
    forever. Over thousands of operations, this can reach significant amounts.
    The problem is amplified with high-decimal tokens (18 decimals) distributed
    to many recipients with small shares.
  como_funciona: |
    1. Protocol collects 99 wei in fees from a swap
    2. 100 stakers each entitled to 99/100 = 0 (integer division)
    3. 99 wei remains in contract, distributed to nobody
    4. Repeat 10M times (common in high-volume DEXes): 990M wei = ~1e9 wei locked
    5. For 6-decimal tokens (USDC): 99 units / 100 = 0 per staker
       at $1 per USDC, after 10M ops: $990 permanently locked
    6. Accumulated dust is not claimable by anyone — no sweep function
  invariante: |
    // Track total distributed vs total collected
    uint256 totalCollected; // ghost: sum of all fees collected
    uint256 totalDistributed; // ghost: sum of all fees actually sent to recipients
    // Dust should be bounded, not grow unboundedly
    assert(totalCollected - totalDistributed <= MAX_ACCEPTABLE_DUST);
  que_mirar:
    - "Does distribution loop use integer division that can round to 0?"
    - "Is there a dust accumulator or remainder tracking variable?"
    - "Can accumulated dust be swept or redistributed?"
    - "What token decimals are supported? (6-decimal tokens = worse)"
    - "How many recipients can exist? (more recipients = more rounding)"
    - "grep: / totalSupply, / totalStaked, / numRecipients"
  como_se_arregla: >
    Use a cumulative reward-per-share accumulator (Synthetix pattern) with
    high precision multiplier (1e18 minimum). Track remainder from division
    and carry it forward to next distribution. Add sweep function for
    accumulated dust. Consider minimum distribution threshold.
  trampas:
    - "1 wei per operation is usually not exploitable — calculate total dust over realistic lifetime"
    - "If dust stays under $1 total over protocol lifetime, this is QA at best"
    - "Synthetix rewardPerToken pattern naturally handles this via high-precision accumulator"
    - "Don't confuse rounding dust with fee amounts too small to distribute — the latter is by design"
  solodit_ids:
    - l-04-undistributed-dust-of-fees-due-to-rounding-errors-pashov-audit-group-none-funnel_2025-08-27-markdown
    - feecollector-stakeholders-may-receive-less-fee-distribution-due-to-unnecessarily-precision-loss-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
    - m-08-lost-fees-due-to-precision-loss-in-fees-calculation-code4rena-kuiper-kuiper-contest-git
    - portion-of-revenue-to-be-distributed-for-gauges-remains-undistributed-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
  incidentes:
    - "Kuiper (C4) — Lost fees due to precision loss in fee calculation; division before multiplication causes cumulative loss across swaps (MEDIUM)"
    - "Funnel (Pashov) — Undistributed dust of fees due to rounding errors in fee split (LOW)"
    - "RAAC (CodeHawks) — FeeCollector stakeholders receive less fee distribution due to unnecessary precision loss (MEDIUM)"
    - "RAAC (CodeHawks) — Portion of revenue to be distributed for gauges remains undistributed (MEDIUM)"
  severidad: low-medium
  confianza: alta
  verificado: true
```

### 1.3 Flash-Loan Fee Farming (Stake-Before-Distribution)

```yaml
- id: fd-003
  pattern: flash-loan-fee-farming
  titulo: "Deposit/stake just before fee distribution snapshot, withdraw immediately after to capture disproportionate fees"
  causa_raiz: >
    If there is no lock period, cooldown, or time-weighted balance mechanism,
    an attacker can use flash loans to stake a massive amount right before
    a fee distribution event (notifyRewardAmount, epoch snapshot, dividend
    declaration), capture a proportional share of fees, then unstake and
    repay the flash loan in the same transaction. The attacker dilutes all
    legitimate stakers' fee share to near-zero for that period.
  como_funciona: |
    1. Attacker monitors mempool for notifyRewardAmount() or fee distribution tx
    2. Front-runs with: flash loan → stake massive amount
    3. Fee distribution executes: attacker gets fees proportional to their
       now-dominant stake (e.g., 99% of total staked)
    4. Attacker claims fees, unstakes, repays flash loan
    5. Net profit: ~99% of distributed fees minus flash loan fee (~0.09%)
    6. All legitimate long-term stakers split the remaining ~1% of fees
  invariante: |
    // User's claimable fee must be proportional to TIME-weighted stake
    // not just point-in-time stake
    // If user staked for < MIN_LOCK_PERIOD, claimable should be 0
    assert(block.timestamp - stakeTimestamp[user] >= MIN_LOCK_PERIOD || claimable[user] == 0);
  que_mirar:
    - "Is there a lock period / cooldown on staking?"
    - "Can stake + claim + unstake happen in same block?"
    - "Are fees distributed lump-sum or linearly over time?"
    - "Does the protocol use time-weighted average balance?"
    - "Can notifyRewardAmount be observed in mempool?"
    - "grep: stake.*getReward, deposit.*claim, no timelock/cooldown"
  como_se_arregla: >
    Enforce minimum lock period (block-based or time-based). Use time-weighted
    average balance for fee distribution (like veToken model). Distribute fees
    linearly over a duration (Synthetix rewardsDuration). Add warm-up period
    where new stakes earn 0 fees for N blocks.
  trampas:
    - "Linear distribution (Synthetix rewardsDuration) mitigates single-block extraction but NOT multi-block strategies"
    - "Private mempool (Flashbots) reduces front-running but does not eliminate: attacker can backrun instead"
    - "If the staking token is not flash-loanable (custom token, no DEX liquidity), risk is lower"
    - "Some protocols design for this intentionally (e.g., Curve gauge weight voting)"
  solodit_ids:
    - h-04-nftxlpstaking-is-subject-to-a-flash-loan-attack-that-can-steal-nearly-all-rewardsfees-that-have-accrued-for-a-particular-vault-code4rena-nftx-nftx-git
    - h-27-attacker-can-inflate-stake-rewards-as-he-wants-sherlock-elfi-git
    - a-flash-loan-fee-sandwich-attack-mixbytes-none-algebra-finance-markdown
    - h-08-dividend-reward-can-be-gamed-code4rena-spartan-protocol-spartan-protocol-contest-git
    - attacker-can-exploit-dividend-allocation-by-depositing-large-mounts-of-drvs-tokens-cyfrin-none-deriverse-dex-markdown
  incidentes:
    - "NFTX (C4) — Flash loan attack on LP staking captures nearly all accrued rewards/fees for a vault in one transaction (HIGH)"
    - "Spartan Protocol (C4) — Dividend reward can be gamed by depositing right before distribution (HIGH)"
    - "Algebra Finance (Mixbytes) — Flash loan fee sandwich attack on fee distribution (HIGH)"
    - "Elfi (Sherlock) — Attacker inflates stake rewards at will via flash-deposit-claim-withdraw (HIGH)"
    - "Buffer Finance — LPs game option expiry by staking before OTM expiry and withdrawing after 10-min lock (HIGH, Sherlock)"
  severidad: high-critical
  confianza: alta
  verificado: true
```

### 1.4 Dividend Token First Depositor — Pre-Deposit Fee Capture

```yaml
- id: fd-004
  pattern: first-depositor-fee-capture
  titulo: "First staker claims all accumulated pre-deposit fees"
  causa_raiz: >
    Fees accumulate in the contract before anyone has staked (e.g., protocol
    is deployed, starts collecting trading fees, but staking is not yet
    active). When the first user stakes, their rewardPerTokenPaid starts at
    the current (inflated) rewardPerToken, OR — worse — the accumulated
    fees are distributable to the first staker's full balance. If fees
    accumulated to the contract address itself (via balanceOf accounting),
    the first depositor captures all of them.
  como_funciona: |
    1. Protocol deploys fee distribution contract
    2. Trading/lending activity generates 10,000 USDC in fees before any stakers
    3. Fees accumulate in contract (balance or internal accounting)
    4. First user stakes 1 wei
    5. rewardPerToken = accumulatedFees * PRECISION / totalStaked(1 wei) = huge
    6. User claims: earned = huge * 1 / PRECISION = all accumulated fees
    7. Alternatively: if balanceOf-based, user deposits 1 wei, contract's
       balance includes pre-deposit fees, user's share = near 100%
  invariante: |
    // First staker should not be able to claim fees accumulated before staking opened
    // rewardPerTokenStored should be 0 or initialized correctly at first stake
    assert(rewardPerTokenStored == 0 || totalStaked > 0);
    // No single user should claim more than their time-proportional share
  que_mirar:
    - "What happens to fees collected before first stake?"
    - "Is rewardPerTokenStored initialized at deploy or at first stake?"
    - "Does the contract use balanceOf for fee calculations?"
    - "Is there a mechanism to seed/burn initial fees?"
    - "grep: totalSupply == 0, totalStaked == 0, first deposit special case"
  como_se_arregla: >
    Skip reward accumulation when totalStaked == 0 (Synthetix pattern —
    rewardPerToken returns early if totalSupply == 0). Alternatively, seed
    the staking pool with dead shares at deploy. Track pre-staking fees
    separately and distribute them to treasury or burn them.
  trampas:
    - "In Synthetix pattern, fees during totalSupply==0 are simply lost — this is a known design tradeoff, not a bug"
    - "If the protocol explicitly handles pre-staking fees (sends to treasury), this is not exploitable"
    - "Virtual shares/dead shares mitigate but don't fully eliminate if fee accumulation is via balanceOf"
  solodit_ids:
    - l-07-first-staker-post-zero-supply-claims-all-rewards-pashov-audit-group-none-resolv_2025-04-15-markdown
    - calling-stakingvaultnotifyrewardamount-on-empty-vault-leaves-ilv-stuck-cyfrin-none-illuvium-staking-markdown
    - rewards-allocated-during-periods-of-no-stakers-will-be-locked-in-the-contract-cantina-none-tea-pdf
    - inflation-attack-on-zero-total-stake-ottersec-none-thala-lsd-deps-pdf
  incidentes:
    - "Resolv (Pashov) — First staker post-zero-supply claims all accumulated rewards (LOW)"
    - "Illuvium (Cyfrin) — notifyRewardAmount on empty vault leaves ILV stuck permanently (MEDIUM)"
    - "TEA (Cantina) — Rewards allocated during periods of no stakers locked in contract forever (MEDIUM)"
    - "Thala LSD (OtterSec) — Inflation attack on zero total stake: first depositor manipulates exchange rate (MEDIUM)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

### 1.5 Fee Distribution to Zero Stakers — Fees Lost Forever

```yaml
- id: fd-005
  pattern: fee-distribution-zero-stakers
  titulo: "Fees distributed when no one is staked are permanently lost"
  causa_raiz: >
    When notifyRewardAmount() or fee distribution is triggered while
    totalSupply == 0, the rewardPerToken accumulator does not increase
    (division by zero guard returns early). The fees are marked as
    "distributed" internally but no one received them. They remain in
    the contract balance but are no longer tracked — permanently locked.
    This is the flip side of fd-004: instead of being captured by a first
    staker, the fees vanish entirely.
  como_funciona: |
    1. All stakers withdraw (totalSupply drops to 0)
    2. Protocol continues generating fees (trading, lending, etc.)
    3. Fee distribution triggers: notifyRewardAmount(1000 USDC)
    4. rewardPerToken() returns 0 (totalSupply == 0, no increment)
    5. rewardRate is set, but time passes with no one staking
    6. When someone finally stakes, rewardRate starts fresh but
       the previous period's fees are already "used up" in time
    7. Result: 1000 USDC permanently locked, no one can claim them
  invariante: |
    // Fees should not be distributed when totalSupply == 0
    // OR: fees during zero-supply period should be recoverable
    assert(totalSupply > 0 || pendingFees == feeBalance); // nothing distributed
  que_mirar:
    - "What happens in rewardPerToken() when totalSupply == 0?"
    - "Does notifyRewardAmount check totalSupply > 0?"
    - "Is there a mechanism to queue/pause fee distribution during zero-supply?"
    - "Can accumulated fees during zero-supply be swept to treasury?"
    - "grep: totalSupply == 0 return, rewardRate =, notifyReward"
  como_se_arregla: >
    Queue fee distribution until at least one staker exists. Revert
    notifyRewardAmount when totalSupply == 0, or accumulate fees and
    distribute them when the first staker arrives. Add sweep function
    for permanently locked fees.
  trampas:
    - "Synthetix design intentionally loses fees during zero-supply — this is documented behavior"
    - "If the protocol guarantees continuous staking (e.g., protocol-owned liquidity), this is not reachable"
    - "The amount lost depends on fee volume during zero-supply — may be negligible for low-volume protocols"
  solodit_ids:
    - rewards-allocated-during-periods-of-no-stakers-will-be-locked-in-the-contract-cantina-none-tea-pdf
    - infraredvault-rewards-are-lost-when-there-are-no-stakers-cantina-none-infrared-finance-pdf
    - potential-permanent-loss-of-rewards-when-there-s-no-staker-cantina-none-euler-pdf
    - rewards-are-calculated-as-distributed-even-if-there-are-no-stakers-locking-the-rewards-forever-cyfrin-none-cyfrin-templedao-v21-markdown
    - m-03-emissions-stuck-if-voternotifyrewardamount-is-called-without-voters-pashov-audit-group-none-kittenswap_2025-07-31-markdown
  incidentes:
    - "TempleDAO (Cyfrin) — Rewards calculated as distributed with no stakers, locking rewards forever (MEDIUM)"
    - "Infrared Finance (Cantina) — InfraredVault rewards lost when no stakers exist (MEDIUM)"
    - "Euler (Cantina) — Potential permanent loss of rewards when no staker exists (MEDIUM)"
    - "TEA (Cantina) — Rewards allocated during zero-staker periods locked in contract (MEDIUM)"
    - "KittenSwap (Pashov) — Emissions stuck if Voter.notifyRewardAmount() called without voters (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
```

### 1.6 Rebasing Token in Fee Vault

```yaml
- id: fd-006
  pattern: rebasing-token-fee-vault
  titulo: "Rebase changes balance but fee accounting uses cached/stale value"
  causa_raiz: >
    When a rebasing token (stETH, AMPL, OHM) is used as the fee token or
    staking token, its balanceOf changes automatically on every rebase
    without any transfer. If the fee distribution contract uses cached
    internal accounting (e.g., totalDeposited, lastBalance) instead of
    live balanceOf, the accounting diverges from reality after each rebase.
    Positive rebases create untracked surplus; negative rebases create
    phantom balances that cause withdrawal failures.
  como_funciona: |
    1. User deposits 1000 stETH, contract records internalBalance = 1000
    2. Positive rebase occurs: actual balanceOf(contract) = 1050
    3. Contract still thinks it has 1000 — 50 stETH is "ghost balance"
    4. Attacker can claim/sweep the 50 stETH surplus if any function
       reads balanceOf and transfers the excess
    5. OR: Negative rebase: balanceOf = 950, but users try to withdraw
       their recorded 1000 — last users get reverts
    6. Fee distribution based on stale totalDeposited over/under-distributes
  invariante: |
    // Internal accounting must stay synced with actual balance after rebase
    // OR: protocol must explicitly not support rebasing tokens
    uint256 actualBalance = token.balanceOf(address(this));
    assert(abs(int256(actualBalance) - int256(internalTotalBalance)) <= REBASE_TOLERANCE);
  que_mirar:
    - "Does the contract use internal balance tracking for a rebasing token?"
    - "Is there a sync() or rebalance() function to update internal state after rebase?"
    - "Can positive rebase surplus be extracted by anyone?"
    - "Does the protocol use wstETH (wrapped, non-rebasing) instead of stETH?"
    - "grep: lastBalance, totalDeposited, cached balance, balanceOf vs internal"
  como_se_arregla: >
    Use wrapped non-rebasing versions (wstETH instead of stETH, wAMPL instead
    of AMPL). If rebasing tokens must be supported, sync internal accounting
    on every interaction via a balanceOf check. Use share-based accounting
    that naturally tracks rebases. Add explicit rebase handlers.
  trampas:
    - "Most modern protocols use wstETH — check if the rebasing version is actually in scope"
    - "OHM rebasing was deprecated in favor of gOHM (wrapped) — historical issue"
    - "AMPL rebases can be extreme (both directions) — test with realistic rebase ranges"
    - "If protocol docs say 'standard ERC-20 only', rebasing incompatibility is typically QA"
  solodit_ids:
    - m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git
    - fee-on-transfer-and-rebasing-tokens-break-accounting-cyfrin-none-wannabet-markdown
    - incorrect-handling-of-fee-on-transfer-and-rebasing-tokens-penalizes-single-beneficiary-mixbytes-none-cryptolegacy-markdown
    - incorrect-lastbalance-update-in-treasury-token-transfer-for-rebasing-tokens-mixbytes-none-cryptolegacy-markdown
  incidentes:
    - "Size (C4) — Incompatibility with rebasing tokens on both base and quote tokens with varying impacts (MEDIUM)"
    - "WannaBet (Cyfrin) — Fee-on-transfer and rebasing tokens break accounting (MEDIUM)"
    - "CryptoLegacy (Mixbytes) — Incorrect lastBalance update in treasury token transfer for rebasing tokens, penalizes beneficiaries (MEDIUM)"
    - "Yieldy (C4) — Users can frontrun rebases even with warmUpPeriod > 0, capturing positive rebases and avoiding negative ones (MEDIUM)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

### 1.7 Multi-Token Fee Distribution Ordering Bug

```yaml
- id: fd-007
  pattern: multi-token-fee-distribution-ordering
  titulo: "Claiming fees in wrong order or claiming one token resets entitlement to others"
  causa_raiz: >
    When a protocol distributes fees in multiple tokens (e.g., ETH + USDC +
    protocol token), the claim mechanism may use a shared checkpoint
    (rewardPerTokenPaid) that, when updated for one token, also resets the
    user's earned amount for other tokens. Alternatively, the claim function
    iterates tokens in a specific order, and a revert on one token (e.g.,
    blacklisted USDC address) blocks claiming of all subsequent tokens.
  como_funciona: |
    1. Protocol distributes fees in Token A, Token B, Token C
    2. User claims Token A: shared checkpoint updates to current block
    3. Checkpoint update resets earned() calculation for Token B and C
    4. User's unclaimed Token B and C fees are permanently lost
    5. OR: claim loop iterates [A, B, C], Token B transfer reverts
       (user blacklisted on USDC), Token C claim never executes
    6. User loses all Token C fees due to Token B revert
  invariante: |
    // Each reward token must have independent checkpoint tracking
    // userRewardPerTokenPaid[user][tokenA] is independent of tokenB
    assert(userRewardPerTokenPaid[user][tokenA] != userRewardPerTokenPaid[user][tokenB]
           || tokenA == tokenB);
    // Claiming one token must not affect earned amount of another
  que_mirar:
    - "Is userRewardPerTokenPaid per-token or shared across all reward tokens?"
    - "Does the claim loop continue or revert on individual token transfer failure?"
    - "Can a user selectively claim one token without affecting others?"
    - "Is there a try/catch around individual token transfers in the loop?"
    - "grep: rewardPerTokenPaid\\[.*\\]\\[, getReward.*for.*loop, multi.*reward"
  como_se_arregla: >
    Use independent checkpoints per reward token (mapping(address => mapping(address => uint256))).
    Wrap individual token transfers in try/catch so one failure doesn't block others.
    Allow per-token claiming functions. Track earned amounts separately per token.
  trampas:
    - "Synthetix MultiRewards handles this correctly — compare against that pattern"
    - "If all reward tokens are non-reverting (no blacklists), the ordering issue is less critical"
    - "Some protocols intentionally use shared checkpoints for gas optimization — confirm if tokens are correlated"
  solodit_ids:
    - h-01-wrong-reward-token-calculation-in-masterchef-contract-code4rena-concur-finance-concur-finance-contest-git
    - h-1-stakingrewardsmanagertopup-misallocates-funds-to-stakingrewards-contracts-sherlock-telcoin-platform-audit-git
    - double-fee-accounting-ottersec-none-adrena-pdf
    - m-21-convexmasterchef-when-using-add-and-set-it-should-always-call-massupdatepools-to-update-all-pools-code4rena-aura-finance-aura-finance-git
  incidentes:
    - "Concur Finance (C4) — Wrong reward token calculation in MasterChef contract; reward accounting mixes token indices (HIGH)"
    - "Telcoin (Sherlock) — StakingRewardsManager::topUp misallocates funds to StakingRewards contracts (HIGH)"
    - "Adrena (OtterSec) — Double fee accounting across multiple reward tokens (HIGH)"
    - "Aura Finance (C4) — ConvexMasterChef add/set doesn't call massUpdatePools, causing stale reward calculations for all pools (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.8 Fee Sweep Race Condition

```yaml
- id: fd-008
  pattern: fee-sweep-race-condition
  titulo: "Sweeping protocol fees while distribution is in progress causes accounting desync"
  causa_raiz: >
    Protocol fees and user-claimable fees often share the same contract
    balance. When an admin sweeps protocol fees (via a withdraw or skim
    function), it reduces the contract's token balance. If a fee distribution
    is in progress (e.g., Synthetix rewardRate is active, or users have
    unclaimed fees), the sweep removes tokens that were earmarked for
    users. Users who claim after the sweep receive less or get reverts.
  como_funciona: |
    1. Contract has 10,000 USDC: 3,000 protocol fees + 7,000 user-claimable
    2. Admin calls sweepFees() to withdraw protocol's 3,000 USDC
    3. Due to shared balance, sweepFees uses balanceOf or a stale accounting
       variable, accidentally sweeping 3,000 from the user-claimable pool
    4. Users try to claim their 7,000 but only 7,000 USDC remains (correct)
       OR: sweepFees miscalculates and takes 5,000, leaving only 5,000
    5. Last users to claim get reverts — contract is insolvent by 2,000
  invariante: |
    // After any admin sweep, user-claimable balance must remain fully backed
    uint256 protocolFees = calculateProtocolFees();
    uint256 userClaimable = calculateTotalUserClaimable();
    assert(token.balanceOf(address(this)) >= userClaimable);
    // Sweep must only touch protocolFees, never userClaimable
  que_mirar:
    - "Is protocol fee tracked separately from user-claimable fees?"
    - "Does sweepFees use balanceOf or internal accounting?"
    - "Can sweep be called while rewards are actively distributing?"
    - "Is there a reentrancy between sweep and claim?"
    - "grep: sweep, skim, withdrawFees, collectProtocolFees, adminWithdraw"
  como_se_arregla: >
    Track protocol fees and user-claimable fees in separate state variables.
    sweepFees should only transfer min(balanceOf, protocolFeeAccrued).
    Add guard: require(balanceOf >= userClaimable + sweepAmount).
    Consider using separate contracts for protocol fee collection vs distribution.
  trampas:
    - "If protocol fees and user fees are in separate contracts, this is not applicable"
    - "Some protocols use emergencyWithdraw for this — different trust model (admin can rug)"
    - "Check if the sweep function has a timelock — reduces race window but doesn't eliminate"
  solodit_ids:
    - protocol-fees-are-double-counted-as-registry-balance-and-pool-reserve-spearbit-none-primitive-pdf
    - emergency-withdrawals-in-feecollector-will-break-fee-distribution-logic-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
    - h-02-protocol-fees-can-be-withdrawn-multiple-times-in-erc20quest-code4rena-rabbithole-rabbithole-quest-protocol-contest-git
    - withdraw-fee-is-transferred-to-the-user-instead-of-the-fee-vault-halborn-vaultka-waterusdc-and-vaultka-solana-programs-markdown
  incidentes:
    - "RabbitHole (C4) — Protocol fees can be withdrawn multiple times in Erc20Quest; no deduction from accounting after withdrawal (HIGH)"
    - "Primitive (Spearbit) — Protocol fees double-counted as registry balance and pool reserve, inflating withdrawable amount (HIGH)"
    - "RAAC (CodeHawks) — Emergency withdrawals in FeeCollector break fee distribution logic (MEDIUM)"
    - "Vaultka (Halborn) — Withdraw fee transferred to user instead of fee vault (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.9 Cumulative Reward Index Overflow

```yaml
- id: fd-009
  pattern: cumulative-reward-index-overflow
  titulo: "rewardPerTokenStored overflows with large fee amounts or long time periods"
  causa_raiz: >
    The reward accumulator (rewardPerTokenStored, accRewardPerShare) grows
    monotonically. If fees are large relative to totalStaked, or if the
    accumulator runs for a very long time, it can overflow uint256. In
    Solidity <0.8.0 (unchecked), this silently wraps to zero, corrupting
    all reward calculations. In Solidity >=0.8.0, it reverts, bricking
    all claim/stake/unstake operations. Uniswap V3 feeGrowthGlobal uses
    intentional uint256 overflow (unchecked math) but the subtraction
    must also be unchecked — mixing checked and unchecked causes issues.
  como_funciona: |
    1. Protocol has very low totalStaked (e.g., 1 wei) and large fee amount
    2. rewardPerToken += feeAmount * PRECISION / totalStaked
       = 1e18 * 1e18 / 1 = 1e36 per distribution
    3. After ~1e41 distributions (or one huge fee amount), accumulator
       approaches uint256.max (~1.15e77)
    4. Solidity 0.8+: next update reverts, freezing all staking operations
    5. Solidity <0.8: wraps to 0, everyone's earned() returns wrong values
    6. Uniswap V3 pattern: feeGrowthGlobal intentionally overflows but
       feeGrowthInside subtraction MUST be unchecked too
  invariante: |
    // Accumulator should not overflow
    // For Uniswap-style: subtraction must be unchecked
    // assert(newRewardPerToken >= oldRewardPerToken); // monotonicity
    // For checked math protocols:
    assert(rewardPerTokenStored < type(uint256).max / 2); // safety margin
  que_mirar:
    - "What Solidity version? (0.8+ = revert on overflow, <0.8 = wrap)"
    - "Is the accumulator using unchecked math intentionally (Uniswap pattern)?"
    - "What precision multiplier is used? (1e18 standard, 1e36 = faster overflow)"
    - "Can totalStaked reach very small values (no minimum enforced)?"
    - "Is there a maximum fee amount per distribution?"
    - "grep: unchecked, feeGrowth, accRewardPerShare, rewardPerToken"
  como_se_arregla: >
    For Synthetix pattern: enforce minimum totalStaked, cap fee amounts per
    distribution, use uint256 with 1e18 precision (safe for ~1e59 distributions).
    For Uniswap V3 pattern: ensure ALL arithmetic on feeGrowth values uses
    unchecked blocks — both accumulation AND subtraction. Document the
    intentional overflow behavior.
  trampas:
    - "uint256 with 1e18 precision is practically impossible to overflow in realistic scenarios — calculate actual threshold"
    - "Uniswap V3 feeGrowth overflow is BY DESIGN — the bug is when subtraction is NOT unchecked"
    - "Solidity 0.8+ with unchecked blocks is safe IF consistent — mixing checked/unchecked is the bug"
  solodit_ids:
    - potential-overflow-in-fee-growth-computation-trailofbits-none-tonco-clamm-dex-v16-pdf
    - h-14-concentratedliquiditypool-rangefeegrowth-and-secondsperliquidity-math-needs-to-be-unchecked-code4rena-sushi-sushi-git
    - h-11-concentratedliquiditypool-incorrect-feegrowthglobal-accounting-when-crossing-ticks-code4rena-sushi-sushi-git
    - fee-calculation-mismatch-in-positionnft-burn-operation-causes-incorrect-fee-growth-tracking-for-token1-trailofbits-none-tonco-clamm-dex-v16-pdf
    - h-02-openposition-use-stale-feegrowthinside0lastx128feegrowthinside1lastx128-code4rena-particle-protocol-particle-protocol-git
  incidentes:
    - "SushiSwap Trident (C4) — ConcentratedLiquidityPool rangeFeeGrowth math needs unchecked; checked subtraction reverts on intentional overflow (HIGH)"
    - "SushiSwap Trident (C4) — Incorrect feeGrowthGlobal accounting when crossing ticks causes fee loss (HIGH)"
    - "TONCO CLAMM (Trail of Bits) — Potential overflow in fee growth computation (MEDIUM)"
    - "Particle Protocol (C4) — openPosition uses stale feeGrowthInside values, causing incorrect fee accounting (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.10 Fee Exclusion Bypass

```yaml
- id: fd-010
  pattern: fee-exclusion-bypass
  titulo: "Addresses meant to be excluded from fees find workaround via intermediary or contract interaction"
  causa_raiz: >
    Reflection/tax tokens maintain an isExcludedFromFee mapping. Excluded
    addresses (DEX routers, protocol contracts, deployer) don't pay transfer
    tax. An attacker can route transfers through excluded intermediaries
    (create a contract that calls the excluded router) or exploit the
    exclusion check logic (from vs to — which one must be excluded?) to
    avoid paying fees entirely.
  como_funciona: |
    1. Token charges 5% tax on all transfers
    2. DEX router is excluded from fees (necessary for liquidity operations)
    3. Attacker creates a contract that wraps router calls
    4. Token._transfer checks: if(from.excluded || to.excluded) skip fee
    5. Attacker's contract calls router (excluded) which calls token.transfer
    6. Since router is the `from` in the final transfer, fee is skipped
    7. Attacker trades with zero fees, undercutting all other traders
    8. Alternatively: attacker gets added to exclusion list via governance
       manipulation or by being a "partner" contract
  invariante: |
    // Fee exclusion should only apply to specific hardcoded system addresses
    // Total fees collected must be proportional to total volume
    // assert(isExcluded[addr] => addr is known system contract);
    uint256 expectedFees = totalVolume * feeRate / 10000;
    assert(totalFeesCollected >= expectedFees * 95 / 100); // within 5% tolerance
  que_mirar:
    - "Is fee exclusion checked on sender, receiver, or both?"
    - "Can arbitrary addresses be added to exclusion list?"
    - "Is the exclusion list updatable after deploy (governance, owner)?"
    - "Can excluded addresses be used as intermediaries?"
    - "grep: isExcludedFromFee, _isExcluded, excludeFromFee, noFee"
  como_se_arregla: >
    Minimize exclusion list — only truly necessary addresses (LP pair, dead
    address). Make exclusion immutable after deployment if possible. Check
    both from AND to for exclusion (require BOTH to be non-excluded for fee
    to be charged). Use a whitelist pattern instead of blacklist.
  trampas:
    - "Most reflection token audits are for low-quality memecoins — confirm scope relevance"
    - "DEX router exclusion is functionally necessary — removing it breaks trading"
    - "Fee bypass via intermediary may not be profitable after gas costs on L1"
    - "On L2 (low gas), fee bypass becomes much more attractive"
  solodit_ids:
    - fee-distribution-bypasses-denylist-spearbit-none-buck-labs-pdf
    - volume-based-fee-can-be-bypassed-with-a-wrapper-contract-cyfrin-none-octodefi-markdown
    - insufficient-self-referral-protection-still-allows-multiple-account-self-referral-cyfrin-none-deriverse-dex-markdown
  incidentes:
    - "SafeMoon V1 (2021) — Multiple fee exclusion bypasses discovered; deployer address excluded from fees, enabling tax-free sells that crashed price ($5M+ impact)"
    - "Buck Labs (Spearbit) — Fee distribution bypasses denylist, allowing blacklisted addresses to receive fees (MEDIUM)"
    - "OctoDeFi (Cyfrin) — Volume-based fee can be bypassed with a wrapper contract (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
```

### 1.11 Transfer Tax Sandwich Attack

```yaml
- id: fd-011
  pattern: transfer-tax-sandwich
  titulo: "Sandwiching fee-on-transfer token trades for amplified MEV extraction"
  causa_raiz: >
    Fee-on-transfer tokens create unique MEV opportunities. The transfer tax
    creates a predictable price impact on DEX pools (each swap loses X% to
    tax). A sandwicher can predict the exact post-tax amount that reaches
    the pool and position their trades to extract maximum value. Additionally,
    some tokens have variable tax rates (higher for sells, lower for buys)
    which creates asymmetric sandwich opportunities.
  como_funciona: |
    1. Token has 10% sell tax, 5% buy tax (asymmetric)
    2. Victim submits buy order for 100 tokens with 15% slippage
    3. Sandwicher front-runs: buys tokens (5% tax = 95 received)
    4. Victim's buy executes at worse price due to front-run
    5. Sandwicher back-runs: sells tokens (10% tax = 90% received)
    6. Despite paying tax, sandwicher profits from price impact on victim
    7. Tax amplifies required slippage, making sandwiching more predictable
    8. Some tokens change tax rate based on block/time — creates gaming opportunities
  invariante: |
    // User's received amount must be within stated slippage tolerance
    // DEX accounting must reflect post-tax amounts
    uint256 received = token.balanceOf(user) - balBefore;
    assert(received >= minAmountOut); // user's slippage check
    // Pool reserves must account for tax deduction
  que_mirar:
    - "Does the token have asymmetric buy/sell tax?"
    - "Is tax rate variable (changes based on holder count, time, etc.)?"
    - "Does the DEX router account for tax in slippage calculations?"
    - "Can tax rate be changed by owner mid-transaction (reentrancy)?"
    - "grep: buyFee, sellFee, taxRate, _taxAmount, swapBack"
  como_se_arregla: >
    DEX routers should detect fee-on-transfer tokens and adjust slippage
    recommendations. Use deadline + slippage protection on all swaps.
    For token developers: use symmetric tax rates, make rates immutable
    or timelocked. DEX UIs should warn users about fee-on-transfer tokens.
  trampas:
    - "Most tax token sandwiches are MEV-bot-vs-bot — may not qualify for bug bounty"
    - "This is more of a DEX integration issue than a token vulnerability"
    - "Tokens with <1% tax are generally not worth sandwiching after gas"
    - "Flashbots/private mempools mitigate but don't eliminate"
  solodit_ids:
    - a-flash-loan-fee-sandwich-attack-mixbytes-none-algebra-finance-markdown
    - m-14-self-lending-does-not-work-with-paired-tokens-that-have-a-transfer-tax-because-addliquidityv2-does-not-account-for-fee-on-transfer-on-the-paired_lp_token-sherlock-peapods-git
    - fee-on-transfer-tokens-are-not-explicitly-denied-in-swap-spearbit-connext-pdf
  incidentes:
    - "Algebra Finance (Mixbytes) — Flash loan fee sandwich attack on concentrated liquidity fee distribution (HIGH)"
    - "PeaPods (Sherlock) — Self-lending with transfer tax tokens breaks addLiquidityV2 accounting (MEDIUM)"
    - "SafeMoon V2 (2023) — Burn bug allowed manipulation of LP reserves via transfer tax, $8.9M drained"
  severidad: medium-high
  confianza: media
  verificado: true
```

### 1.12 Protocol Fee Change Retroactivity

```yaml
- id: fd-012
  pattern: fee-change-retroactivity
  titulo: "Changing fee rate affects pending undistributed fees retroactively"
  causa_raiz: >
    When an admin updates the protocol fee rate (e.g., from 10% to 20%),
    the new rate is applied to ALL pending/undistributed fees, not just
    future ones. This happens because the fee calculation uses the current
    feeRate at time of claim/distribution rather than the rate at time of
    accrual. Users who accrued fees at the old rate unexpectedly receive
    less (if rate increased) or more (if decreased).
  como_funciona: |
    1. Protocol fee rate is 10%. User accrues 1000 USDC in fees over 30 days.
    2. Admin changes fee rate to 20% (legitimate governance action)
    3. User claims: contract calculates fee deduction using CURRENT 20% rate
    4. User expected to pay 100 USDC fee (10% of 1000), pays 200 USDC instead
    5. 100 USDC that should have been the user's goes to protocol
    6. Reverse: if rate decreases, protocol gets less than earned
    7. In extreme case: admin front-runs large claim by increasing fee rate
  invariante: |
    // Fee rate at time of accrual should be used, not current rate
    // OR: pending fees should be settled before rate change
    // assert(effectiveFeeRate == feeRateAtAccrualTime);
    // Practical: settle all pending before rate update
    function setFeeRate(uint256 newRate) {
        _settleAllPending(); // distribute at old rate first
        feeRate = newRate;
    }
  que_mirar:
    - "Is feeRate read at accrual time or claim time?"
    - "Does setFeeRate settle pending distributions first?"
    - "Is fee rate change timelocked?"
    - "Can admin front-run large claims by changing fee rate?"
    - "grep: setFee, updateFee, changeFee, feeRate =, protocolFee ="
  como_se_arregla: >
    Settle all pending fees at the old rate BEFORE applying the new rate.
    Use snapshots: record fee rate per epoch/period and calculate each
    period's fees at its applicable rate. Add timelock to fee changes
    so users can claim at old rate before change takes effect.
  trampas:
    - "If fees are distributed linearly (Synthetix), rate change mid-period affects remaining distribution — may be intended"
    - "Timelocked fee changes are standard governance practice — if timelock exists, this is likely low/QA"
    - "Fee increase by admin may be seen as 'trusted admin' and out of scope for many bug bounties"
  solodit_ids:
    - new-protocol-fee-applies-retroactively-on-debt-before-fee-change-cantina-none-sablier-pdf
    - incorrect-interest-calculation-due-to-performance-fee-rate-change-cantina-none-term-structure-pdf
    - m-01-the-pending-fee-should-be-settled-before-adjusting-the-fee-pashov-audit-group-none-radiant-june-markdown
    - pending-fee-not-cleared-and-overwritten-by-updates-via-updatefeetype-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
    - h-03-withdraw-does-not-take-into-account-the-pending-fee-pashov-audit-group-none-radiant-june-markdown
  incidentes:
    - "Sablier (Cantina) — New protocol fee applies retroactively on debt accrued before fee change (MEDIUM)"
    - "Term Structure (Cantina) — Incorrect interest calculation due to performance fee rate change (MEDIUM)"
    - "Radiant (Pashov) — Pending fee should be settled before adjusting fee; withdraw doesn't account for pending fee (HIGH)"
    - "RAAC (CodeHawks) — Pending fee not cleared and overwritten by updates via updateFeeType (MEDIUM)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

### 1.13 Fee Currency Mismatch / Stale Conversion Rate

```yaml
- id: fd-013
  pattern: fee-currency-mismatch
  titulo: "Fees collected in token A but distributed/accounted in token B with stale or manipulable conversion rate"
  causa_raiz: >
    Some protocols collect fees in the trading token (e.g., ETH) but
    distribute them in another token (e.g., protocol token or stablecoin).
    The conversion rate between the two tokens may be stale (cached oracle
    price), manipulable (spot DEX price), or completely absent (hardcoded).
    If the conversion rate is outdated or manipulable, fee accounting diverges
    from reality: users may receive inflated or deflated fee payouts.
  como_funciona: |
    1. Protocol collects 10 ETH in trading fees
    2. Fees converted to USDC for distribution at exchange rate from oracle
    3. Oracle price is stale (last updated 1 hour ago): ETH = $3,000
    4. Actual current price: ETH = $2,800 (ETH dumped)
    5. Protocol distributes 10 * $3,000 = $30,000 worth of USDC
    6. But 10 ETH is actually worth $28,000 — protocol overpays by $2,000
    7. OR: attacker manipulates spot price via flash loan before conversion
  invariante: |
    // Conversion rate must be fresh (within heartbeat) at time of swap
    // Total value distributed <= total value collected (at fair rates)
    assert(block.timestamp - oracle.lastUpdated() <= HEARTBEAT);
    // Dollar value of distributed fees <= dollar value of collected fees + tolerance
  que_mirar:
    - "Are fees converted between tokens? What rate is used?"
    - "Is the conversion rate from an oracle? How fresh?"
    - "Can the conversion rate be manipulated (spot price, TWAP window)?"
    - "Is the conversion done atomically or in separate steps?"
    - "grep: convert, swap, exchange, pricePerShare, getPrice in fee context"
  como_se_arregla: >
    Use Chainlink or TWAP oracle with staleness check for conversions.
    Add slippage protection on fee token swaps. Convert fees atomically
    (collect and swap in same tx). If using DEX for conversion, add
    minimum output check. Consider distributing fees in the same token
    they are collected in (no conversion needed).
  trampas:
    - "If fees are distributed in the same token they're collected, this pattern doesn't apply"
    - "Oracle manipulation for fee conversion is typically lower impact than for lending — fees are smaller"
    - "TWAP with long window (30 min+) is generally manipulation-resistant on liquid pairs"
    - "Stale conversion may benefit or harm users randomly — not always exploitable"
  solodit_ids:
    - fee-mismatch-ottersec-none-mayan-evm-pdf
    - trst-l-3-fee-mismatch-between-contracts-can-make-strategies-unusable-trust-security-none-brahma-markdown_
    - dividend-calculation-uses-stale-token-balance-in-subsequent-update-calls-after-fees_deposit-with-drvs-cyfrin-none-deriverse-dex-markdown
  incidentes:
    - "Mayan (OtterSec) — Fee mismatch between EVM and Solana sides causes incorrect fee accounting across chains (MEDIUM)"
    - "Brahma (Trust Security) — Fee mismatch between contracts makes strategies unusable (LOW)"
    - "Deriverse DEX (Cyfrin) — Dividend calculation uses stale token balance in subsequent update() calls after fees_deposit with DRVS (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
```

### 1.14 Referral Fee Manipulation / Self-Referral Loops

```yaml
- id: fd-014
  pattern: referral-fee-manipulation
  titulo: "Self-referral loops or referral gaming to extract referral bonuses"
  causa_raiz: >
    Protocols offer referral bonuses (e.g., 5% of fees to referrer) to
    incentivize user acquisition. If there's no self-referral check, an
    attacker creates two accounts: Account A refers Account B. All of B's
    activity generates referral fees for A. In extreme cases, the attacker
    routes ALL their activity through a self-referral loop, effectively
    getting a permanent fee discount equal to the referral bonus rate.
  como_funciona: |
    1. Protocol offers 5% referral fee on all trading fees
    2. Attacker creates Account A (referrer) and Account B (trader)
    3. Account B registers with Account A as referrer
    4. Account B does $1M in trading volume, paying $5,000 in fees
    5. Account A receives $250 in referral bonuses (5% of $5,000)
    6. Attacker effectively pays only $4,750 in fees (5% discount)
    7. With multiple accounts: A→B→C→D, each level extracts fees
    8. Multi-level referral: each level compounds the extraction
  invariante: |
    // Self-referral must be blocked
    assert(referrer[user] != user);
    // Referral chain must not loop back
    assert(!isCircularReferral(user, referrer[user]));
    // Total referral fees must not exceed configured rate
    assert(totalReferralFeesPaid <= totalFees * referralRate / 10000);
  que_mirar:
    - "Is there a check that referrer != msg.sender?"
    - "Can a user change their referrer after setting?"
    - "Is there a referral chain/tree with depth limits?"
    - "Are referral fees capped per referrer or globally?"
    - "Can referral fees exceed 100% of protocol fees?"
    - "grep: referrer, referral, setReferrer, registerReferral"
  como_se_arregla: >
    Require referrer != msg.sender (but this doesn't prevent multi-account).
    Use KYC/proof-of-humanity for referral eligibility. Cap total referral
    fees per address. Require minimum activity from referrer before earning
    bonuses. Make referral one-time and immutable. Enforce cooldown between
    referrer registration and first bonus.
  trampas:
    - "Self-referral with separate addresses is fundamentally unsolvable on-chain — it's a Sybil problem"
    - "Many protocols consider self-referral an acceptable cost of the referral program"
    - "If referral rate is < gas cost per operation on L1, self-referral is not profitable"
    - "On L2 (low gas), self-referral becomes very attractive even at low rates"
  solodit_ids:
    - insufficient-self-referral-protection-still-allows-multiple-account-self-referral-cyfrin-none-deriverse-dex-markdown
    - lack-of-self-referral-prevention-zokyo-none-filament-markdown
    - m-03-referral-bonus-cap-will-be-lower-than-what-was-intended-pashov-audit-group-none-ulti-november-markdown
    - m-14-incorrect-referral-fee-calculations-code4rena-secondswap-secondswap-git
    - m-03-in-case-of-no-referrer-platform-charges-referral-fee-to-themselves-instead-of-adding-it-back-to-remainingamount-shieldify-none-abster-freefall-markdown
  incidentes:
    - "Deriverse DEX (Cyfrin) — Insufficient self-referral protection; multiple-account self-referral still possible (MEDIUM)"
    - "Filament (Zokyo) — Lack of self-referral prevention allows users to capture referral bonuses for themselves (MEDIUM)"
    - "SecondSwap (C4) — Incorrect referral fee calculations cause over/under-payment of referral bonuses (MEDIUM)"
    - "Abster (Shieldify) — No referrer case charges referral fee to platform instead of returning to remainingAmount (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
```

### 1.15 Fee Tier Manipulation via Wash Trading or Flash Loans

```yaml
- id: fd-015
  pattern: fee-tier-manipulation
  titulo: "Volume-based fee tiers gamed via wash trading or flash loans to unlock lower fees"
  causa_raiz: >
    Some protocols offer tiered fee structures: high-volume traders pay lower
    fees (e.g., >$1M monthly volume = 0.05% fee vs 0.3% default). If volume
    is tracked per-address without Sybil resistance, an attacker can inflate
    their volume via wash trading (trading with themselves through different
    paths) or flash loans to reach higher tiers, then trade at discounted
    rates for actual profit-making trades.
  como_funciona: |
    1. Protocol fee tiers: <$100K = 0.3%, $100K-$1M = 0.1%, >$1M = 0.05%
    2. Attacker needs to reach >$1M tier to get 0.05% fee
    3. Attacker flash loans $2M, executes circular swap: ETH→USDC→ETH
    4. Volume tracker records $2M in volume for attacker's address
    5. Attacker now qualifies for 0.05% tier
    6. Attacker makes real trades at 0.05% instead of 0.3% — 6x fee reduction
    7. Cost: only the 0.3% fee on the wash trades ($6K) to unlock $1M+ of
       discounted trading. If attacker trades $10M: saves $25K in fees.
  invariante: |
    // Volume-based tier should require genuine bilateral volume
    // or use time-weighted metrics that are expensive to game
    // Fee tier changes should be timelocked
    assert(feeRate[user] == calculateTier(timeWeightedVolume[user]));
    // Wash trading detection: round-trip trades in same block should not count
  que_mirar:
    - "How is volume tracked? Per-address or per-position?"
    - "Can volume be inflated via circular swaps in same block?"
    - "Is there a time-weighted component to volume tracking?"
    - "Can fee tier be changed within a single transaction?"
    - "Are flash loan volumes counted toward tier qualification?"
    - "grep: volumeTracker, feeDiscount, feeTier, tradingVolume, userVolume"
  como_se_arregla: >
    Use time-weighted average volume (e.g., 30-day rolling average).
    Exclude same-block round-trip trades from volume calculations.
    Apply fee tier changes with a delay (next epoch, not instant).
    Cap maximum volume credit per block to prevent flash loan gaming.
    Consider requiring staked tokens instead of volume for fee discounts.
  trampas:
    - "If fee tiers are per-pool (not per-user), wash trading is more expensive and less attractive"
    - "On L1, gas costs for wash trading may exceed fee savings — check profitability"
    - "Some DEXes intentionally allow wash trading volume (market structure decision)"
    - "VIP/tier systems based on staking (not volume) are not vulnerable to this"
  solodit_ids:
    - volume-based-fee-can-be-bypassed-with-a-wrapper-contract-cyfrin-none-octodefi-markdown
    - wash-trades-to-steal-keeper-and-spot-trading-rewards-quantstamp-primex-finance-markdown
    - overlapping-fee-tiers-not-checked-acknowledged-consensys-none-usdi-markdown
    - default-fee-fallback-to-zero-when-no-fee-tier-matches-fixed-consensys-none-usdi-markdown
  incidentes:
    - "OctoDeFi (Cyfrin) — Volume-based fee can be bypassed with wrapper contract, avoiding fee tier requirements (MEDIUM)"
    - "Primex Finance (Quantstamp) — Wash trades to steal keeper and spot trading rewards; volume gaming via self-trades (HIGH)"
    - "USDi (Consensys) — Overlapping fee tiers not checked: certain volumes match multiple tiers, applying wrong fee (LOW)"
    - "USDi (Consensys) — Default fee fallback to zero when no fee tier matches, allowing free trades (MEDIUM)"
  severidad: medium-high
  confianza: media
  verificado: true
```

### 1.16 MasterChef Pool Weight Update Bug

```yaml
- id: fd-016
  pattern: masterchef-pool-weight-update
  titulo: "Adding or modifying pool allocation points without updating all pools first causes reward miscalculation"
  causa_raiz: >
    In MasterChef-style contracts, reward distribution across pools uses
    allocPoint per pool and totalAllocPoint globally. When add() or set()
    is called to create or modify a pool's weight, if massUpdatePools()
    is not called first, the existing pools have stale accRewardPerShare.
    The new totalAllocPoint applies retroactively to uncalculated periods,
    causing over/under-distribution of rewards to all pools.
  como_funciona: |
    1. Pool A has allocPoint=100, Pool B has allocPoint=100, total=200
    2. 1000 tokens distributed per block. Each pool gets 500/block.
    3. 10 blocks pass without massUpdatePools (accRewardPerShare is stale)
    4. Admin calls add(Pool C, allocPoint=100) — totalAllocPoint becomes 300
    5. Now massUpdatePools runs for Pool A: calculates 10 blocks of rewards
       using NEW totalAllocPoint=300 instead of OLD totalAllocPoint=200
    6. Pool A gets 10 * 1000 * 100/300 = 3,333 instead of correct 5,000
    7. Pool C effectively "steals" retroactive rewards from A and B
  invariante: |
    // totalAllocPoint change must be preceded by massUpdatePools
    // Sum of all distributed rewards == total reward supply
    uint256 sumDistributed;
    for (uint i = 0; i < poolCount; i++) {
        sumDistributed += pool[i].accRewardPerShare * pool[i].totalStaked / PRECISION;
    }
    assert(sumDistributed <= totalRewardBudget);
  que_mirar:
    - "Does add() call massUpdatePools() before changing totalAllocPoint?"
    - "Does set() call massUpdatePools() before changing allocPoint?"
    - "Can add/set be called by anyone or only owner?"
    - "Is there a _withUpdate parameter that can be set to false?"
    - "grep: add(.*allocPoint, set(.*allocPoint, totalAllocPoint, massUpdatePools"
  como_se_arregla: >
    ALWAYS call massUpdatePools() before modifying any pool's allocPoint
    or adding a new pool. Remove the _withUpdate parameter pattern — it
    should never be false. Consider using a snapshot-based approach where
    allocPoint changes take effect at next epoch boundary.
  trampas:
    - "Original SushiSwap MasterChef V1 had this bug — most forks copy it"
    - "If massUpdatePools is called regularly by keepers, the window is small"
    - "With many pools (50+), massUpdatePools gas cost becomes prohibitive — this is why _withUpdate=false exists"
    - "The impact depends on time between last update and add/set — if called in same block, no impact"
  solodit_ids:
    - m-21-convexmasterchef-when-using-add-and-set-it-should-always-call-massupdatepools-to-update-all-pools-code4rena-aura-finance-aura-finance-git
    - h-01-wrong-reward-token-calculation-in-masterchef-contract-code4rena-concur-finance-concur-finance-contest-git
    - m-8-unclaimed-rewards-when-emergency-withdrawing-are-not-redistributed-in-masterchef-and-mlumstaking-sherlock-magicsea-the-native-dex-on-the-iotaevm-git
    - m-17-convexmasterchefs-deposit-and-withdraw-can-be-reentered-drawing-all-reward-funds-from-the-contract-if-reward-token-allows-for-transfer-flow-control-code4rena-aura-finance-aura-finance-git
  incidentes:
    - "Aura Finance (C4) — ConvexMasterChef add()/set() doesn't call massUpdatePools(), causing stale reward calculations across all pools (MEDIUM)"
    - "Concur Finance (C4) — Wrong reward token calculation in MasterChef contract due to incorrect pool indexing (HIGH)"
    - "MagicSea (Sherlock) — Unclaimed rewards when emergency withdrawing are not redistributed in MasterChef (MEDIUM)"
    - "Aura Finance (C4) — ConvexMasterChef deposit/withdraw reentrancy via reward token callbacks draws all reward funds (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

---

## 2. Patrones de Detección Rápida (Grep Patterns)

```yaml
grep_patterns:
  fee_on_transfer:
    - "transferFrom.*amount.*balance.*=.*amount"
    - "safeTransferFrom.*amount[^;]*;[^b]*balance.*\\+.*amount"
    - "amount.*transferFrom(?!.*balanceOf)"
  fee_distribution:
    - "rewardPerToken|accRewardPerShare|feeGrowthGlobal"
    - "notifyRewardAmount|distributeReward|distributeFees"
    - "totalAllocPoint|allocPoint"
    - "rewardRate.*=|rewardsDuration"
  fee_accounting:
    - "protocolFee|managementFee|performanceFee"
    - "feeRate.*=|setFee|updateFee|changeFee"
    - "sweep|skim|collectFees|withdrawFees"
  exclusion_bypass:
    - "isExcludedFromFee|_isExcluded|noFee"
    - "excludeFromFee|includeInFee"
  referral:
    - "referrer|referral|setReferrer|registerReferral"
    - "referralFee|referralBonus|referralReward"
  rebasing:
    - "lastBalance|cachedBalance|storedBalance"
    - "rebase|sync|skim"
  fee_tiers:
    - "feeTier|feeDiscount|tradingVolume|volumeTracker"
    - "allocPoint|totalAllocPoint|massUpdatePools"
```

---

## 3. Invariantes Universales para Fee Distribution

```solidity
// INVARIANT FD-INV-001: Conservation of Fees
// Total fees collected must equal total distributed + total locked dust + protocol share
// ghost variables tracking cumulative values
uint256 ghost_totalFeesCollected;
uint256 ghost_totalFeesDistributed;
uint256 ghost_totalProtocolFees;

function invariant_feeConservation() public {
    uint256 contractBalance = feeToken.balanceOf(address(feeDistributor));
    uint256 unclaimedByUsers = calculateTotalUnclaimed();
    // What's in contract = unclaimed by users + undistributed + protocol fees pending
    assertGte(contractBalance, unclaimedByUsers, "FD-INV-001: contract insolvent for user claims");
    // Total distributed never exceeds total collected
    assertLte(ghost_totalFeesDistributed, ghost_totalFeesCollected, "FD-INV-001: distributed > collected");
}

// INVARIANT FD-INV-002: No User Claims More Than Entitled
// Per-user claim amount bounded by their proportional share
function invariant_noExcessClaim() public {
    for (uint i = 0; i < actors.length; i++) {
        uint256 userClaimed = ghost_totalClaimed[actors[i]];
        uint256 maxEntitled = calculateMaxEntitlement(actors[i]);
        assertLte(userClaimed, maxEntitled + DUST_TOLERANCE, "FD-INV-002: user claimed more than entitled");
    }
}

// INVARIANT FD-INV-003: Fee-on-Transfer Accounting
// Internal balance tracking matches actual token balance
function invariant_feeOnTransferAccounting() public {
    uint256 actualBalance = token.balanceOf(address(vault));
    uint256 internalBalance = vault.totalInternalBalance();
    assertGte(actualBalance, internalBalance, "FD-INV-003: internal balance exceeds actual (fee-on-transfer?)");
}

// INVARIANT FD-INV-004: rewardPerToken Monotonicity
// Accumulator must never decrease (in non-overflow designs)
function invariant_rewardPerTokenMonotonic() public {
    uint256 current = distributor.rewardPerTokenStored();
    assertGte(current, ghost_lastRewardPerToken, "FD-INV-004: rewardPerToken decreased");
    ghost_lastRewardPerToken = current;
}

// INVARIANT FD-INV-005: No Flash-Stake Fee Capture
// User staked for < MIN_LOCK blocks should have 0 claimable
function invariant_noFlashStakeFeeCapture() public {
    for (uint i = 0; i < actors.length; i++) {
        if (block.number - stakeBlock[actors[i]] < MIN_LOCK_BLOCKS) {
            assertEq(distributor.earned(actors[i]), 0, "FD-INV-005: flash-staker earned fees");
        }
    }
}

// INVARIANT FD-INV-006: Protocol Fee Isolation
// Sweeping protocol fees must not reduce user-claimable balance
function invariant_protocolFeeIsolation() public {
    uint256 userClaimable = calculateTotalUnclaimed();
    uint256 balance = feeToken.balanceOf(address(distributor));
    assertGte(balance, userClaimable, "FD-INV-006: sweep reduced user-claimable balance");
}
```

---

## 4. Checklist Rápido Pre-Audit

```markdown
## Fee Distribution Audit Checklist

### Token Compatibility
- [ ] Fee-on-transfer tokens: does protocol measure balanceOf before/after?
- [ ] Rebasing tokens: does protocol use wrapped versions or sync on every interaction?
- [ ] ERC-777 tokens: is there reentrancy protection on fee claim paths?
- [ ] Low-decimal tokens (USDC 6, WBTC 8): precision loss in fee calculations?

### Distribution Mechanism
- [ ] What pattern? (Synthetix rewardPerToken / MasterChef accRewardPerShare / Push-loop / Pull-claim)
- [ ] Precision of accumulator (1e18 minimum, 1e36 = overflow risk)
- [ ] What happens when totalSupply == 0? (lost fees vs queued)
- [ ] Is there a lock period / cooldown on staking before claiming?
- [ ] Can stake + claim + unstake happen in same block?

### Fee Rate Management
- [ ] How is fee rate updated? (timelock, governance, admin EOA)
- [ ] Does fee rate change settle pending fees first?
- [ ] Are fee rates bounded (min/max)?
- [ ] Is fee rate retroactively applied to pending distributions?

### Multi-Token / Multi-Pool
- [ ] Are reward checkpoints independent per token?
- [ ] Does claim failure on one token block others?
- [ ] Does add/set pool call massUpdatePools first?
- [ ] Is totalAllocPoint updated atomically with pool changes?

### Protocol Fee Separation
- [ ] Are protocol fees tracked separately from user fees?
- [ ] Can admin sweep protocol fees without affecting user claims?
- [ ] Is there a double-withdrawal guard on protocol fee collection?

### Economic Attacks
- [ ] Flash loan fee farming: can attacker stake-claim-unstake in one tx?
- [ ] Referral self-referral: can user refer themselves?
- [ ] Volume-based tier gaming: can volume be inflated via wash trades?
- [ ] First depositor: can first staker capture pre-existing fees?
- [ ] Fee exclusion bypass: can users route through excluded addresses?

### Rounding & Precision
- [ ] Division before multiplication in fee calculations?
- [ ] Rounding direction: does it favor protocol or user? (should favor protocol)
- [ ] Dust accumulation: is remainder tracked and redistributable?
- [ ] Can accumulated dust be swept?
```

---

## 5. Protocolos de Referencia

```yaml
reference_protocols:
  synthetix_staking_rewards:
    pattern: "rewardPerToken + userRewardPerTokenPaid"
    strengths: "battle-tested, linear distribution, no lump-sum gaming"
    weaknesses: "rewards lost during zero-supply periods, no flash-loan protection natively"
    key_functions: ["notifyRewardAmount", "rewardPerToken", "earned", "getReward"]
    known_issues: "rounding to zero if rewardsDuration > reward amount"

  masterchef_sushiswap:
    pattern: "accRewardPerShare + rewardDebt per user"
    strengths: "simple, gas efficient for single-token rewards"
    weaknesses: "add/set without massUpdatePools, no multi-token support natively"
    key_functions: ["add", "set", "massUpdatePools", "pendingReward", "deposit", "withdraw"]
    known_issues: "allocPoint change without massUpdatePools causes retroactive miscalculation"

  uniswap_v3_fee_growth:
    pattern: "feeGrowthGlobal + feeGrowthOutside per tick + position tracking"
    strengths: "granular per-position fee tracking, handles concentrated liquidity"
    weaknesses: "intentional uint256 overflow requires consistent unchecked math"
    key_functions: ["_updatePosition", "collect", "burn", "cross (tick crossing)"]
    known_issues: "stale feeGrowthInside on position open, checked/unchecked mismatch"

  convex_aura_fee_distribution:
    pattern: "MasterChef-based with extra reward multipliers (vlCVX/vlAURA boost)"
    strengths: "multi-token rewards, boost mechanics"
    weaknesses: "complex reward routing across multiple contracts, reentrancy surface"
    key_functions: ["earmarkRewards", "getReward", "deposit", "withdraw"]
    known_issues: "reward token callback reentrancy, massUpdatePools skipped in add/set"

  yearn_v2_v3_management_fees:
    pattern: "performance fee on profit + management fee on AUM (time-based)"
    strengths: "fee-on-profit aligns incentives, management fee is predictable"
    weaknesses: "fee calculation on harvest — if harvest is delayed, fees compound incorrectly"
    key_functions: ["report", "assess_fees", "process_report"]
    known_issues: "management fee accrual during zero-deposit periods, fee rate change retroactivity"

  reflection_tokens_safemoon:
    pattern: "transfer tax → reflect to all holders proportionally via total supply adjustment"
    strengths: "automatic distribution without claiming"
    weaknesses: "fee exclusion list, exchange rate manipulation, gas-intensive for large holder counts"
    key_functions: ["_transfer", "_reflectFee", "_getValues", "excludeFromReward"]
    known_issues: "excluded address accounting errors, tax rate manipulation, LP drain via fee bypass"
```

---

## 6. Relaciones con Otros Briefings

```yaml
related_briefings:
  - name: staking
    overlap: "fd-003 (flash-stake) extends staking-002, fd-004/fd-005 are staking reward edge cases"
    distinction: "This briefing focuses on the FEE side; staking briefing focuses on STAKE mechanics"

  - name: vault-erc4626
    overlap: "fd-001 (fee-on-transfer) and fd-006 (rebasing) apply to vault deposit/withdraw"
    distinction: "Vault briefing covers share price; this covers fee distribution to share holders"

  - name: dex-amm
    overlap: "fd-009 (feeGrowth overflow) is DEX-specific, fd-015 (fee tiers) applies to DEX protocols"
    distinction: "DEX briefing covers AMM math; this covers how collected fees reach users"

  - name: oracle
    overlap: "fd-013 (fee currency mismatch) involves oracle price staleness"
    distinction: "Oracle briefing covers price feeds; this covers fee conversion using those feeds"

  - name: mev-sandwich
    overlap: "fd-011 (transfer tax sandwich) is a specialized MEV pattern"
    distinction: "MEV briefing covers general sandwich; this covers fee-amplified sandwich"

  - name: gauge-voting-escrow
    overlap: "fd-003 (flash-stake) applies to gauge voting rewards"
    distinction: "Gauge briefing covers voting power; this covers fee distribution to voters"

  - name: lending
    overlap: "fd-001 (fee-on-transfer) causes bad debt in lending protocols"
    distinction: "Lending briefing covers collateral/debt; this covers how protocol fees are distributed"
```
