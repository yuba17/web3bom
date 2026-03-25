# Rollup & L2-Specific Vulnerabilities — Combat Briefing

> Attack surface: sequencer liveness and trust, L1<>L2 messaging integrity, forced transactions,
> block timing assumptions, data availability, ZK prover liveness, rollup upgrades, and L2-native
> token quirks (rebasing, gas tokens). Covers Arbitrum, zkSync Era, StarkNet, Polygon zkEVM,
> Scroll, Linea, Blast, Manta Pacific, and sovereign appchains (dYdX v4). OP Stack patterns
> are covered separately in `bridge-opstack.md` — this file focuses on non-OP-Stack and
> cross-rollup patterns.
> Sources: verified Solodit findings, Code4rena/Sherlock/CodeHawks audits, real incident
> postmortems, L2BEAT risk assessments.

---

## 1. Sequencer Liveness & Oracle Interaction

```yaml
- id: l2r-001
  pattern: sequencer-downtime-stale-oracle
  name: "Missing L2 sequencer uptime check allows stale Chainlink prices during sequencer outage"
  severity: medium
  causa_raiz: >
    On L2 rollups, when the sequencer goes offline, Chainlink oracle feeds stop being updated
    because no transactions can be processed. However, the oracle's latestRoundData() still
    returns the last known price with a "recent" updatedAt timestamp (set before the outage).
    Protocols that don't check the Chainlink Sequencer Uptime Feed treat stale prices as valid,
    enabling liquidations at wrong prices, cheap borrowing, or arbitrage during the outage.
  como_funciona: |
    1. Sequencer goes offline (hardware failure, congestion, bug)
    2. Chainlink price feeds on L2 freeze — no new rounds are posted
    3. Market moves significantly during the outage (e.g., ETH drops 20%)
    4. Sequencer comes back online — there's a brief window before feeds update
    5. Attacker submits transactions using the stale (pre-crash) price
    6. Opens undercollateralized borrows, avoids liquidation, or executes profitable swaps
    7. Once oracle updates, attacker's position is already established at the stale price
  invariante: |
    // Chainlink sequencer uptime feed must be checked before using price data
    (bool success, int256 answer, , uint256 startedAt, ) = sequencerUptimeFeed.latestRoundData();
    require(success && answer == 0, "Sequencer is down");
    require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not over");
    // Only then call the price feed
  que_mirar:
    - "Does the contract call latestRoundData() without checking sequencer uptime feed?"
    - "Is there a GRACE_PERIOD after sequencer restart before accepting prices?"
    - "grep: latestRoundData, sequencerUptimeFeed, AggregatorV3Interface"
    - "grep: isSequencerUp, GRACE_PERIOD_TIME, sequencerUp"
    - "Is the protocol deployed on Arbitrum, Optimism, Base, or other L2 with centralized sequencer?"
  como_se_arregla: >
    Integrate Chainlink's L2 Sequencer Uptime Feed. Before accepting any price, verify
    the sequencer is up AND a grace period (e.g., 3600 seconds) has elapsed since restart.
    During the grace period, pause price-sensitive operations (liquidations, borrows, swaps).
  trampas:
    - "Many auditors flag this as Medium but some contests downgrade to Low/QA because the sequencer restart grace period is short"
    - "On Arbitrum, block.number returns L1 block number — don't confuse with L2 block timing"
    - "Some protocols argue 'we trust the sequencer' — valid for centralized protocols, not for permissionless DeFi"
    - "The grace period length is debatable — too short = still vulnerable, too long = unnecessary DoS"
  confianza: alta
  verificado: true
  tags: [sequencer, oracle, chainlink, stale-price, L2, arbitrum, optimism]
  solodit_ids:
    - slug: "missing-l2-sequencer-uptime-checks-openzeppelin-none-fx-v2-audit-markdown"
    - slug: "missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-venus-multichain-support-markdown"
    - slug: "no-check-for-sequencer-uptime-can-lead-to-zeno-auctions-being-executed-at-lower-prices-or-may-result-in-incomplete-auctions-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - protocol: "f(x) Protocol"
      firm: "OpenZeppelin"
      impact: "MEDIUM"
      title: "Missing L2 Sequencer Uptime Checks"
      slug: "missing-l2-sequencer-uptime-checks-openzeppelin-none-fx-v2-audit-markdown"
    - protocol: "Venus Protocol"
      firm: "Quantstamp"
      impact: "MEDIUM"
      title: "Missing Checks for Sequencer Uptime When Fetching Chainlink Prices"
      slug: "missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-venus-multichain-support-markdown"
    - protocol: "Regnum Aurum (RAAC)"
      firm: "CodeHawks"
      impact: "MEDIUM"
      title: "No check for sequencer uptime can lead to auctions at wrong prices"
      slug: "no-check-for-sequencer-uptime-can-lead-to-zeno-auctions-being-executed-at-lower-prices-or-may-result-in-incomplete-auctions-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"

- id: l2r-002
  pattern: sequencer-downtime-fund-locking
  name: "Users cannot exit positions during sequencer outage — forced liquidation on restart"
  severity: high
  causa_raiz: >
    When the L2 sequencer goes offline, users cannot submit transactions to close positions,
    add collateral, or repay debt. If the underlying asset price moves during the outage,
    users may face liquidation immediately when the sequencer restarts — without ever having
    had the opportunity to act. The forced transaction mechanism (e.g., Arbitrum's delayed
    inbox) exists but has a 24-hour delay, making it useless for time-sensitive DeFi.
  como_funciona: |
    1. User has a leveraged position on an L2 lending protocol (e.g., 150% collateral ratio)
    2. Sequencer goes down for 4+ hours
    3. During the outage, ETH price drops 25% on L1/other venues
    4. User cannot add collateral or repay debt — no transactions processed on L2
    5. Sequencer restarts, oracle updates to the new (lower) price
    6. User's position is immediately underwater — liquidation bots execute
    7. User loses collateral they could have saved if they'd had access
  invariante: |
    // Protocol should not liquidate immediately after sequencer restart
    function liquidate(address user) external {
        require(sequencerUpFor() > LIQUIDATION_GRACE_PERIOD, "Grace period active");
        // ... proceed with liquidation
    }
    // LIQUIDATION_GRACE_PERIOD = e.g., 1 hour after sequencer restart
  que_mirar:
    - "Does the lending protocol have a grace period after sequencer restart before allowing liquidations?"
    - "Can users repay/add collateral through L1 force-inclusion during sequencer downtime?"
    - "grep: liquidate, isSequencerUp, gracePeriod, SEQUENCER_GRACE_PERIOD"
    - "Does the protocol pause liquidations when sequencer is detected as down?"
    - "Is there an L1 escape hatch for emergency position management?"
  como_se_arregla: >
    Implement a liquidation grace period: after sequencer restart, wait N hours before
    allowing liquidations. This gives users time to submit transactions through the normal
    L2 path or through the L1 force-inclusion mechanism. AAVE V3 on Arbitrum/Optimism
    implements this pattern via Chainlink's sequencer uptime feed.
  trampas:
    - "The grace period itself can be gamed — attacker takes on bad debt during the grace period knowing liquidation is delayed"
    - "L1 force-inclusion has its own delay (24h on Arbitrum) — doesn't help for fast-moving markets"
    - "Some protocols argue this is an 'infrastructure risk, not a smart contract bug' — but it's still a design flaw"
  confianza: alta
  verificado: true
  tags: [sequencer, liquidation, grace-period, fund-locking, L2]
  solodit_ids:
    - slug: "missing-l2-sequencer-uptime-checks-openzeppelin-none-fx-v2-audit-markdown"
  incidentes:
    - protocol: "Arbitrum One"
      firm: "Incident"
      impact: "INFRASTRUCTURE"
      date: "2023-06-07"
      title: "Sequencer downtime ~1h due to batch gas exhaustion bug"
      description: "Sequencer ran out of gas for batch posting, halting all L2 transactions"
    - protocol: "Arbitrum One"
      firm: "Incident"
      impact: "INFRASTRUCTURE"
      date: "2023-12-15"
      title: "Sequencer partial outage ~1.5h due to inscription traffic surge"
      description: "Sustained inscription traffic overwhelmed sequencer, stopping transaction relay"
```

---

## 2. Forced Transactions & Censorship Resistance

```yaml
- id: l2r-003
  pattern: forced-inclusion-censorship
  name: "L1 force-inclusion queue not honored — sequencer censors specific transactions"
  severity: high
  causa_raiz: >
    Rollups provide a force-inclusion mechanism (Arbitrum's delayed inbox, OP Stack's
    L1→L2 deposit flow) that lets users bypass a censoring sequencer by submitting
    transactions directly to L1. However, smart contracts that assume all transactions
    go through the sequencer may not handle force-included transactions correctly.
    Additionally, the delay between force-inclusion submission and actual L2 execution
    (24h on Arbitrum) creates a window where time-sensitive operations expire.
  como_funciona: |
    1. User tries to interact with an L2 protocol but sequencer ignores their transactions
    2. User submits via L1 force-inclusion (Arbitrum: sendL2Message to delayed inbox)
    3. After 24-hour delay, the transaction is force-included in an L2 batch
    4. But: the L2 protocol had a 12-hour deadline that already expired
    5. User's transaction executes but the opportunity (auction, deadline, etc.) is gone
    6. Or: the L2 contract uses msg.sender aliasing incorrectly, rejecting the force-included tx
  invariante: |
    // Contracts must handle both sequencer-submitted and force-included transactions
    // Force-included transactions have aliased msg.sender from L1
    function isValidSender(address sender) internal view returns (bool) {
        return sender == expectedSender
            || sender == AddressAliasHelper.applyL1ToL2Alias(expectedL1Sender);
    }
  que_mirar:
    - "Does the contract handle L1→L2 address aliasing for force-included transactions?"
    - "Are there time-sensitive operations that expire within the force-inclusion delay window?"
    - "grep: sendL2Message, delayedInbox, forceInclusion, AddressAliasHelper"
    - "grep: applyL1ToL2Alias, undoL1ToL2Alias, offset = 0x1111000000000000000000000000000000001111"
    - "Does the protocol's emergency withdrawal mechanism work through L1 force-inclusion?"
  como_se_arregla: >
    1. Handle address aliasing: recognize both the direct L2 address and the L1-aliased
    address for cross-layer calls. 2. Extend deadlines: any time-sensitive operation
    should account for the force-inclusion delay (e.g., add 24h buffer to deadlines).
    3. Implement L1 escape hatches that don't depend on L2 sequencer.
  trampas:
    - "Address aliasing adds 0x1111...1111 to the L1 sender address — forgetting this silently rejects force-included txs"
    - "On Arbitrum, the delayed inbox has a 24h inclusion guarantee — but sequencer CAN include it earlier"
    - "Force-inclusion doesn't help if the L2 contract itself is paused or in emergency mode"
  confianza: alta
  verificado: true
  tags: [forced-inclusion, censorship, address-aliasing, delayed-inbox, arbitrum]
  solodit_ids: []
  incidentes:
    - protocol: "Linea"
      firm: "Incident"
      impact: "CENSORSHIP"
      date: "2024-06-02"
      title: "Linea sequencer paused to censor attacker addresses after $2.6M exploit"
      description: "Consensys unilaterally paused the Linea sequencer to prevent the attacker from moving funds, demonstrating centralization risk"
```

---

## 3. L1→L2 Message Replay

```yaml
- id: l2r-004
  pattern: l1-to-l2-message-replay
  name: "L1→L2 deposit message replayed multiple times on L2 — double-spend"
  severity: critical
  causa_raiz: >
    L1→L2 messages (deposits) are processed by the L2 system contracts when they detect
    new entries in the L1 inbox. If the deduplication mechanism (nonce, hash, or
    processed-message mapping) is flawed, the same deposit can be credited multiple times
    on L2. This is especially dangerous during rollup upgrades or reorgs where the
    message processing state may be reset.
  como_funciona: |
    1. User deposits 100 ETH via L1 bridge contract
    2. L1 contract emits deposit event / writes to inbox with message hash H
    3. L2 system processes the message and credits 100 ETH to user
    4. Due to a bug in the processed-messages mapping (e.g., hash collision, migration gap):
       - The same message H is not marked as processed, OR
       - A reorg causes the processed-messages state to roll back
    5. Message H is processed again — user gets another 100 ETH
    6. User withdraws 200 ETH total, draining the bridge
  invariante: |
    // Every L1→L2 message must be processed exactly once
    mapping(bytes32 => bool) public processedMessages;

    function processDeposit(bytes32 msgHash, ...) internal {
        require(!processedMessages[msgHash], "Already processed");
        processedMessages[msgHash] = true;
        // ... credit deposit
    }
    // Invariant: processedMessages[hash] transitions false→true exactly once, never back
  que_mirar:
    - "Is there a processedMessages mapping or equivalent nonce-based deduplication?"
    - "Can the processedMessages mapping be reset during an upgrade or migration?"
    - "grep: processedMessages, executedMessages, isMessageProcessed, depositHash"
    - "Does the message hash include the L1 block number to prevent cross-reorg replay?"
    - "Are message hashes unique? Is there a risk of hash collision with crafted inputs?"
  como_se_arregla: >
    Use a monotonic nonce for L1→L2 messages. Mark each message as processed using
    a mapping that CANNOT be cleared during upgrades. Include the L1 block number,
    L1 tx hash, and log index in the message hash to prevent cross-reorg collisions.
  trampas:
    - "Hash collisions are theoretically possible but practically infeasible with keccak256 + unique inputs"
    - "The real risk is during rollup upgrades/migrations where storage slots may be remapped"
    - "Some rollups use a nonce counter instead of a mapping — different failure modes"
  confianza: alta
  verificado: true
  tags: [message-replay, deposit, bridge, double-spend, L1-to-L2]
  solodit_ids: []
  incidentes:
    - protocol: "Arbitrum Nitro"
      firm: "Bug Bounty (0xriptide)"
      impact: "CRITICAL"
      date: "2022-09"
      title: "Nitro bridge upgrade left inbox initialization vulnerable — $534M at risk"
      description: >
        During Arbitrum's Nitro upgrade, empty storage slots in the bridge contract
        allowed an attacker to set themselves as the recipient for L1→L2 deposits.
        0xriptide reported via Immunefi — $400K bounty paid. No funds were lost.
      payout: "$400,000"
```

---

## 4. L2→L1 Message Expiry & Withdrawal Failures

```yaml
- id: l2r-005
  pattern: l2-to-l1-withdrawal-expiry
  name: "L2→L1 withdrawal message expires before user can prove/finalize — funds stuck"
  severity: medium
  causa_raiz: >
    Optimistic rollup withdrawals require a multi-step process: initiate on L2, prove on L1
    after state root is posted, wait for challenge period, then finalize. If any step has
    an expiry window and the user misses it (due to L1 congestion, gas spikes, or
    unawareness), the withdrawal can become unfinalizeable. ZK rollups avoid this by
    finalizing immediately after proof verification, but may have their own finality delays.
  como_funciona: |
    1. User initiates withdrawal on L2 (burns L2 ETH, emits withdrawal message)
    2. State root containing the withdrawal is posted to L1
    3. User must prove the withdrawal within a window (e.g., 7 days from state root posting)
    4. If the state root is challenged and replaced, user must re-prove against new root
    5. The re-prove window may be shorter or the new root may not cover the user's L2 block
    6. User's withdrawal becomes permanently stuck — ETH burned on L2, not claimable on L1
  invariante: |
    // Every initiated withdrawal must remain provable indefinitely
    // OR have a recovery mechanism if the prove window closes
    function canWithdraw(bytes32 withdrawalHash) public view returns (bool) {
        WithdrawalState memory ws = withdrawals[withdrawalHash];
        return ws.initiated && (!ws.proven || ws.finalized || ws.canReprove());
    }
  que_mirar:
    - "Is there an expiry on the withdrawal prove/finalize steps?"
    - "What happens if the state root is challenged after the user proved but before finalization?"
    - "grep: proveWithdrawalTransaction, finalizeWithdrawalTransaction, FINALIZATION_PERIOD"
    - "Is there a recovery mechanism for expired withdrawals?"
    - "Can the admin/security council rescue stuck withdrawals?"
  como_se_arregla: >
    Never expire withdrawal proofs permanently. If a state root is challenged, allow
    the user to re-prove against any valid subsequent state root without a time limit.
    Implement an emergency withdrawal mechanism controlled by a security council as
    a last resort for stuck funds.
  trampas:
    - "OP Stack handles this with the FaultDisputeGame — see bridge-opstack.md for details"
    - "ZK rollups don't have this issue for proven batches — but unproven batches can still be reverted"
    - "The challenge period is 7 days on most optimistic rollups — users who don't check for a week can miss re-prove windows"
  confianza: media
  verificado: true
  tags: [withdrawal, expiry, prove, finalize, stuck-funds, optimistic-rollup]
  solodit_ids: []
  incidentes: []
```

---

## 5. Sequencer Fee Manipulation

```yaml
- id: l2r-006
  pattern: sequencer-fee-manipulation
  name: "Sequencer inflates L1 data fee passed to users — overcharging for calldata/blob posting"
  severity: medium
  causa_raiz: >
    L2 transaction fees have two components: L2 execution fee + L1 data posting fee.
    The L1 data fee depends on the L1 gas price and the size of the calldata/blob.
    A malicious or buggy sequencer can inflate the reported L1 gas price or add padding
    to the data, overcharging users. Smart contracts that rely on tx.gasprice or
    L1-reported fees for economic calculations may produce incorrect results.
  como_funciona: |
    1. Sequencer reports L1BaseFee = 100 gwei to the L2 system contract (GasPriceOracle)
    2. Actual L1 base fee is 30 gwei — sequencer is overreporting by 3.3x
    3. Every L2 transaction pays 3.3x more in L1 data fees than necessary
    4. The excess fee goes to the sequencer/operator as pure profit
    5. Users on L2 see high gas costs and may avoid time-sensitive transactions
    6. Protocols that use L1 fee estimates for pricing (e.g., oracle update cost reimbursement) overpay
  invariante: |
    // L1 data fee reported by the system contract should track actual L1 base fee
    // within a reasonable bound (e.g., 2x tolerance)
    uint256 reportedL1Fee = IL1Block(L1_BLOCK_ADDRESS).basefee();
    uint256 actualL1Fee = getActualL1BaseFee(); // from L1 oracle
    assert(reportedL1Fee <= actualL1Fee * 2); // max 2x overcharge
  que_mirar:
    - "How does the L2 system contract get the L1 base fee? Is it trusted input from the sequencer?"
    - "Can users verify the L1 fee independently?"
    - "grep: l1BaseFee, GasPriceOracle, getL1Fee, L1_FEE_OVERHEAD, l1FeeScalar"
    - "Does the protocol reimburse gas costs based on L2-reported L1 fees?"
    - "On Arbitrum: ArbGasInfo.getL1BaseFeeEstimate()"
  como_se_arregla: >
    L1 base fee should be set by the L1→L2 deposit mechanism (e.g., L1Block contract
    updated by the L1 deposit flow) rather than by the sequencer's self-report.
    OP Stack and Arbitrum do this via the derivation pipeline. Add upper bounds
    and rate limiting on fee parameter updates.
  trampas:
    - "On OP Stack, l1BaseFee is set by SystemConfig and updated by the batcher — relatively trustworthy"
    - "On Arbitrum, the sequencer has more control over fee parameters — but there's an L1 verification path"
    - "Post-EIP-4844, blob fees are a separate dimension — see l2r-012 for blob-specific issues"
    - "Fee manipulation is usually Low severity because it requires a compromised sequencer (trusted role)"
  confianza: media
  verificado: true
  tags: [sequencer, fee, gas, L1-data-fee, overcharge]
  solodit_ids: []
  incidentes: []
```

---

## 6. Fraud Proof & Challenge Window

```yaml
- id: l2r-007
  pattern: fraud-proof-timing-window
  name: "Challenge window too short for complex fraud proofs — invalid state root accepted"
  severity: high
  causa_raiz: >
    Optimistic rollups rely on a challenge period (typically 7 days) during which anyone
    can submit a fraud proof to dispute an invalid state root. Interactive fraud proof
    protocols (like Arbitrum's BOLD or OP Stack's FaultDisputeGame) require multiple
    rounds of bisection. If the challenge window doesn't account for worst-case
    interactive proof duration, L1 congestion, or the time needed to compute the proof,
    a valid challenge may not complete before the window closes.
  como_funciona: |
    1. Malicious validator posts an invalid state root to L1
    2. Honest challenger detects the fraud and initiates a challenge
    3. Interactive bisection protocol begins — requires multiple L1 transactions
    4. L1 gas spikes to 200+ gwei — each bisection step costs $500+
    5. The challenger's transactions queue up, delayed by high gas and congestion
    6. Challenge window closes before bisection completes
    7. Invalid state root is accepted as final — attacker can steal all bridge funds
  invariante: |
    // Challenge window must be long enough for worst-case interactive proof
    // Formal: challengeWindowEnd - challengeStart >= MAX_BISECTION_ROUNDS * MAX_ROUND_DURATION
    function isChallengeWindowSufficient() public view returns (bool) {
        return CHALLENGE_PERIOD >= MAX_BISECTION_ROUNDS * MAX_RESPONSE_TIME + BUFFER;
    }
  que_mirar:
    - "What is the challenge period length? Is it configurable?"
    - "How many bisection rounds are possible in worst case?"
    - "Is there a maximum response time per round? What happens if a party doesn't respond?"
    - "grep: challengePeriod, DISPUTE_GAME_FINALITY_DELAY, disputeGameFinalityDelaySeconds"
    - "Can L1 congestion prevent timely challenge submissions?"
    - "Is there a bond/stake requirement for challengers that might deter legitimate challenges?"
  como_se_arregla: >
    Set the challenge period conservatively (7+ days). Add clock extensions on each
    bisection step (like chess clocks). Allow gas-subsidized challenge transactions.
    Implement a guardian/security council that can pause finalization if a challenge
    is in progress.
  trampas:
    - "Arbitrum BOLD uses chess-clock timing — each move extends the clock, preventing timeout attacks"
    - "OP Stack FaultDisputeGame has similar time extension mechanics — see bridge-opstack.md"
    - "ZK rollups don't have this issue — validity proofs replace fraud proofs"
    - "The 7-day window is political as much as technical — shorter windows are riskier but improve UX"
  confianza: media
  verificado: true
  tags: [fraud-proof, challenge-window, bisection, optimistic-rollup, state-root]
  solodit_ids: []
  incidentes: []
```

---

## 7. ZK Rollup Proof Verification Gas

```yaml
- id: l2r-008
  pattern: zk-proof-verification-gas-limit
  name: "ZK proof verification exceeds L1 block gas limit — batch cannot be finalized"
  severity: high
  causa_raiz: >
    ZK rollup validity proofs (SNARK/STARK) require on-chain verification on L1.
    As batch sizes grow or proof systems become more complex, the verification gas
    cost can approach or exceed the L1 block gas limit (~30M gas). If verification
    is not aggregated or recursive, a single large batch may be unprovable on L1,
    permanently delaying finality. Additionally, the verifier contract may have bugs
    where certain valid proofs fail verification (false negative) or invalid proofs
    pass (false positive — catastrophic).
  como_funciona: |
    1. ZK prover generates a validity proof for a batch of 10,000 transactions
    2. Proof is submitted to L1 Verifier contract for on-chain verification
    3. Verification requires 25M gas — works today at 30M block gas limit
    4. EIP changes reduce block gas limit, or batch size grows, pushing verification to 35M gas
    5. Verification transaction cannot fit in any L1 block
    6. Batch is never finalized on L1 — withdrawals from this batch are permanently stuck
    7. Alternatively: a verifier bug causes valid proofs to fail, blocking all batches
  invariante: |
    // Proof verification must always fit within L1 block gas limit with margin
    function verifyProof(bytes calldata proof, ...) external returns (bool) {
        uint256 gasBefore = gasleft();
        bool result = _verifyProof(proof, ...);
        uint256 gasUsed = gasBefore - gasleft();
        // Gas used should be well below block gas limit
        // This is a design invariant, not a runtime check
        return result;
    }
    // Design invariant: gasUsed < BLOCK_GAS_LIMIT * 0.8
  que_mirar:
    - "What is the gas cost of proof verification? Does it scale with batch size?"
    - "Is proof aggregation/recursion used to keep verification cost constant?"
    - "grep: verifyProof, verify, Verifier, pairing, bn256, PLONK, Groth16"
    - "Is the verifier contract upgradeable? Can it be swapped if a bug is found?"
    - "Has the verifier been formally verified (Halo2, Circom, Cairo)?"
  como_se_arregla: >
    Use recursive proof composition to keep L1 verification cost constant regardless
    of batch size. The inner proof proves N transactions, and a constant-size outer
    proof proves the inner proof is valid. Ensure verification gas < 15M (half of
    block gas limit) for safety margin.
  trampas:
    - "Groth16 verification is ~230K gas (cheap) but requires trusted setup — most modern ZK rollups use it"
    - "PLONK/STARK verification is more expensive (1-5M gas) but no trusted setup"
    - "The real risk is verifier BUGS, not gas limits — see zkSync Code4rena audit for examples"
    - "Polygon zkEVM's emergency state was triggered by a prover bug, not a verifier bug (see l2r-014)"
  confianza: media
  verificado: true
  tags: [zk-rollup, proof-verification, gas-limit, verifier, finality]
  solodit_ids: []
  incidentes:
    - protocol: "Polygon zkEVM"
      firm: "Incident"
      impact: "INFRASTRUCTURE"
      date: "2024-03-22"
      title: "14-hour outage due to L1 reorg mishandling — emergency state activated"
      description: >
        Polygon zkEVM's synchronizer mishandled an Ethereum L1 reorg, causing the sequencer
        to process batches with incorrect timestamps. First use of the emergency state
        feature, requiring 6/8 Security Council approval for an upgrade to the prover/verifier.
```

---

## 8. Batch Ordering & Sequencer MEV

```yaml
- id: l2r-009
  pattern: sequencer-mev-batch-ordering
  name: "Centralized sequencer reorders transactions within a batch for MEV extraction"
  severity: medium
  causa_raiz: >
    Most L2 rollups have a single centralized sequencer that determines transaction
    ordering within each batch. Unlike L1 where block builders compete and MEV is
    partially redistributed via MEV-Boost, L2 sequencers have unilateral ordering
    power. They can sandwich user swaps, front-run arbitrage opportunities, or
    delay specific transactions to extract value — with no transparency or recourse.
  como_funciona: |
    1. User submits a large DEX swap on the L2 (buy 100 ETH worth of TOKEN)
    2. Sequencer sees the pending transaction in the mempool
    3. Sequencer inserts a buy-TOKEN transaction before the user's swap
    4. User's swap executes at a worse price (higher slippage)
    5. Sequencer sells TOKEN after the user's swap at the inflated price
    6. Sequencer profits from the sandwich — user loses to extra slippage
    7. All of this is invisible on-chain because sequencer controls ordering
  invariante: |
    // Fair ordering: transactions should be ordered by arrival time (FCFS)
    // This is a protocol-level property, not a smart contract assertion
    // Protocols can detect anomalies post-hoc:
    function detectSandwich(uint256 blockNum) external view returns (bool) {
        // Check if sequencer-controlled address has trades immediately
        // before and after a large user swap in the same block
        // This is a monitoring invariant, not a prevention mechanism
    }
  que_mirar:
    - "Does the L2 have a fair ordering policy (FCFS, encrypted mempool, or threshold encryption)?"
    - "Can the sequencer insert its own transactions at arbitrary positions in the batch?"
    - "grep: sequencer, batchPoster, submitBatch, processBatch"
    - "Is there a shared sequencer or decentralized sequencer network?"
    - "Does the protocol use private transaction pools or commit-reveal schemes?"
  como_se_arregla: >
    Implement fair ordering: 1. FCFS ordering with verifiable timestamps.
    2. Encrypted mempool (threshold encryption — transactions are encrypted until
    ordering is committed). 3. Shared sequencers (Espresso, Astria) that separate
    ordering from execution. 4. Application-level: use MEV-resistant DEX designs
    (batch auctions, oracle-based pricing).
  trampas:
    - "Sequencer MEV is hard to prove — the sequencer controls what gets included and in what order"
    - "Fair ordering is an active research area — no production rollup has fully solved this yet (as of 2025)"
    - "Arbitrum's FCFS policy is an 'honor system' — not enforced cryptographically"
    - "For bug bounties, sequencer MEV is usually out of scope (trusted operator assumption)"
  confianza: media
  verificado: true
  tags: [MEV, sequencer, batch-ordering, sandwich, frontrunning, L2]
  solodit_ids:
    - slug: "all-swaps-other-than-the-top-of-block-swap-will-revert-cyfrin-none-sorella-l2-angstrom-markdown"
  incidentes:
    - protocol: "Sorella Angstrom"
      firm: "Cyfrin"
      impact: "HIGH"
      title: "All swaps other than the top-of-block swap will revert"
      slug: "all-swaps-other-than-the-top-of-block-swap-will-revert-cyfrin-none-sorella-l2-angstrom-markdown"
```

---

## 9. Escape Hatch Race Condition

```yaml
- id: l2r-010
  pattern: escape-hatch-race-condition
  name: "Multiple users competing for limited escape hatch slots during sequencer failure"
  severity: medium
  causa_raiz: >
    When the sequencer goes offline permanently or is censoring users, the L1 escape
    hatch mechanism allows users to force-include transactions. However, if many users
    try to exit simultaneously, the L1 force-inclusion queue may become congested.
    Additionally, some escape hatches have per-block or per-epoch limits, creating
    a race condition where early submitters exit successfully and later ones don't.
  como_funciona: |
    1. Sequencer goes offline or starts censoring transactions
    2. 1000 users simultaneously try to withdraw via L1 force-inclusion
    3. L1 delayed inbox has throughput limits (e.g., N messages per L1 block)
    4. L1 gas spikes as all users compete for force-inclusion slots
    5. Gas costs become prohibitive — only whales can afford to exit
    6. Small users are stuck with funds on a potentially compromised L2
    7. If the L2 has a total exit period (e.g., 7 days), some users may not exit in time
  invariante: |
    // All users must be able to force-exit within a reasonable time
    // regardless of congestion
    function canForceExit(address user) public view returns (bool) {
        // User should always have a path to withdraw
        // even if the sequencer is permanently offline
        return true; // This is a liveness property, not a safety assertion
    }
  que_mirar:
    - "Is there a force-exit mechanism that works without sequencer cooperation?"
    - "Does the force-exit have throughput limits or per-block caps?"
    - "grep: forceWithdrawal, emergencyWithdraw, escapeHatch, forceExit"
    - "What happens if the force-exit queue is full? Do users lose priority?"
    - "Is there a time limit on the escape hatch (e.g., validium 7-day exit period)?"
  como_se_arregla: >
    Implement priority queues for force-exits based on time-in-queue (not gas price).
    Remove per-block caps during emergency mode. Allow batch force-exits to reduce
    per-user L1 gas cost. Ensure the escape hatch has no time limit for individual users.
  trampas:
    - "L2BEAT tracks 'exit window' risk for every rollup — check their risk assessment"
    - "Validiums (like Manta Pacific was) have the worst escape properties — if DA committee colludes, no exit possible"
    - "Most rollups have a security council that can intervene — but this is a centralization vector"
  confianza: media
  verificado: true
  tags: [escape-hatch, force-exit, race-condition, sequencer-failure, congestion]
  solodit_ids: []
  incidentes: []
```

---

## 10. Cross-L2 Message Atomicity

```yaml
- id: l2r-011
  pattern: cross-l2-atomicity-failure
  name: "Multi-rollup operation partially completes — funds stuck between L2s"
  severity: high
  causa_raiz: >
    Cross-L2 operations (e.g., swap token A on Arbitrum for token B on zkSync) involve
    multiple independent transactions on different rollups. There is no atomic
    cross-L2 execution — if one leg completes and the other fails (due to sequencer
    downtime, reverted transaction, or bridge failure), the operation is partially
    executed and funds may be stuck. Intent-based protocols and cross-chain bridges
    attempt to solve this but introduce their own trust assumptions.
  como_funciona: |
    1. User initiates cross-L2 swap: send 100 USDC on Arbitrum, receive 100 USDT on zkSync
    2. Leg 1: 100 USDC is locked/burned on Arbitrum — succeeds
    3. Bridge message sent from Arbitrum → L1 → zkSync
    4. Leg 2: zkSync sequencer is down — message cannot be delivered
    5. User has lost 100 USDC on Arbitrum but has no 100 USDT on zkSync
    6. Recovery requires: manual claim on zkSync when sequencer restarts, OR
       cancellation on Arbitrum (if the bridge supports cancellation, which many don't)
    7. If neither path exists, funds are permanently stuck
  invariante: |
    // Cross-L2 operations must be fully reversible if any leg fails
    // Timeout-based refund mechanism
    function claimRefund(bytes32 intentId) external {
        Intent memory intent = intents[intentId];
        require(block.timestamp > intent.deadline, "Not expired");
        require(!intent.fulfilled, "Already fulfilled");
        // Refund the source-chain funds
        IERC20(intent.sourceToken).transfer(intent.user, intent.amount);
    }
  que_mirar:
    - "Does the cross-L2 protocol have a timeout/refund mechanism if the destination leg fails?"
    - "What happens if the bridge message is never delivered?"
    - "grep: fulfill, claim, refund, timeout, deadline, intentId, orderId"
    - "Is there an escrow contract that holds funds until both legs confirm?"
    - "Can the user cancel a pending cross-L2 operation?"
  como_se_arregla: >
    Use intent-based architectures with solver networks: user expresses intent,
    solver fulfills atomically, user confirms. If solver doesn't fulfill within
    timeout, user gets refund. See Across, UniswapX, and other intent protocols.
    For trustless cross-L2: wait for L1 finality on both sides before releasing funds.
  trampas:
    - "Superchain interop (OP Stack) promises atomic cross-L2 execution but only within the Superchain (same bridge)"
    - "Intent-based protocols shift risk to solvers — but solver insolvency is a real risk"
    - "Cross-L2 atomicity is fundamentally impossible without a shared settlement layer"
  confianza: media
  verificado: true
  tags: [cross-L2, atomicity, intent, bridge, stuck-funds, multi-rollup]
  solodit_ids: []
  incidentes: []
```

---

## 11. Data Availability Committee Collusion

```yaml
- id: l2r-012
  pattern: dac-collusion-data-withholding
  name: "Data Availability Committee withholds data — users cannot prove state for escape hatch"
  severity: critical
  causa_raiz: >
    Validiums and optimistic chains with off-chain DA (like Manta Pacific pre-Celestia
    migration) rely on a Data Availability Committee (DAC) to store transaction data.
    If the DAC colludes or goes offline, users cannot reconstruct the L2 state needed
    to prove ownership and execute force-exits. The rollup degrades to a "trust me"
    system where the operator controls all funds.
  como_funciona: |
    1. L2 posts state roots to L1 but stores transaction data off-chain with DAC
    2. DAC consists of 5 members with 3/5 threshold for data attestation
    3. 3 DAC members collude with the L2 operator (or are compromised)
    4. They sign attestations for batches but don't actually store/serve the data
    5. Users cannot download transaction data to reconstruct Merkle proofs
    6. Without Merkle proofs, users cannot use the L1 escape hatch
    7. Operator can post a fraudulent state root that steals all funds
    8. No one can challenge because no one has the data to generate a fraud proof
  invariante: |
    // Data availability must be verifiable — either on-chain or via erasure coding + DAS
    // For validiums: DAC attestation count >= threshold
    function verifyDAC(bytes32 batchHash, bytes[] calldata signatures) external view returns (bool) {
        uint256 validSigs = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            if (isDACommitteeMember(recoverSigner(batchHash, signatures[i]))) {
                validSigs++;
            }
        }
        return validSigs >= dacThreshold;
    }
    // But this only proves the DAC SIGNED — not that they STORED the data
  que_mirar:
    - "Is the L2 a validium (off-chain DA) or a true rollup (on-chain DA)?"
    - "What is the DAC composition and threshold? Can a minority block data availability?"
    - "grep: dataAvailability, DAC, dacMembers, dacThreshold, attestation"
    - "Is there a fallback to on-chain DA if the DAC goes offline?"
    - "Check L2BEAT risk assessment for the DA layer classification"
  como_se_arregla: >
    1. Use on-chain DA (calldata or EIP-4844 blobs) for true rollup security.
    2. If using off-chain DA, use a decentralized DA layer (Celestia, EigenDA, Avail)
    instead of a permissioned DAC. 3. Implement data availability sampling (DAS)
    so light nodes can verify DA without downloading all data.
  trampas:
    - "Validiums trade security for cost — legitimate for low-value applications but dangerous for DeFi"
    - "Some chains claim to be 'rollups' but are actually validiums — check L2BEAT classification"
    - "Celestia/EigenDA add decentralization but introduce their own trust assumptions"
    - "DAC collusion is theoretical — no known incident yet, but the attack is well-understood"
  confianza: media
  verificado: true
  tags: [validium, DAC, data-availability, escape-hatch, collusion]
  solodit_ids: []
  incidentes: []
```

---

## 12. EIP-4844 Blob Fee Spike DoS

```yaml
- id: l2r-013
  pattern: blob-fee-spike-dos
  name: "Blob market saturation prevents batch posting — L2 finality delayed or halted"
  severity: medium
  causa_raiz: >
    After EIP-4844 (Dencun upgrade), rollups post batch data as blobs instead of calldata
    to reduce costs. However, the blob market has its own fee mechanism (excess_blob_gas)
    with exponential fee increases when demand exceeds the target (3 blobs/block).
    If many rollups or blob spammers saturate the blob market, blob fees can spike
    1000x in minutes, making batch posting prohibitively expensive. Sequencers may
    delay batch posting, extending the time until L2 transactions achieve L1 finality.
  como_funciona: |
    1. Normal blob fee: 1 wei — sequencer posts batches every few minutes
    2. Blob spam event: someone fills all blob slots for 100+ consecutive blocks
    3. Blob base fee increases exponentially (similar to EIP-1559 base fee)
    4. Blob fee reaches 100 gwei — posting a batch costs $10,000+ instead of $0.10
    5. Sequencer stops posting batches to avoid the cost
    6. L2 transactions continue executing but don't achieve L1 finality
    7. Users who want guaranteed finality (e.g., for L2→L1 withdrawals) are blocked
    8. Protocols with L1-finality-dependent logic may malfunction
  invariante: |
    // Batch posting should not be delayed more than MAX_BATCH_DELAY
    function isBatchPostingHealthy() external view returns (bool) {
        uint256 lastPostedBatch = rollupContract.lastBatchSequenceNumber();
        uint256 lastPostedTimestamp = rollupContract.batchTimestamp(lastPostedBatch);
        return block.timestamp - lastPostedTimestamp <= MAX_BATCH_DELAY;
    }
    // MAX_BATCH_DELAY = e.g., 24 hours
  que_mirar:
    - "Does the rollup have a fallback to calldata posting when blob fees are too high?"
    - "Is there a maximum delay tolerance for batch posting before triggering emergency mode?"
    - "grep: blobBaseFee, excess_blob_gas, submitBatch, submitBlobs, blobhash"
    - "Does the protocol assume frequent L1 finality for any logic?"
    - "What happens to in-flight withdrawals if batch posting is delayed?"
  como_se_arregla: >
    Implement automatic fallback to calldata posting when blob fees exceed a threshold.
    Set a maximum batch delay — if exceeded, the sequencer must post via calldata
    regardless of cost (possibly subsidized by the rollup's treasury). Monitor blob
    market conditions and adjust batch sizes dynamically.
  trampas:
    - "Blob fee spikes have been short-lived so far (March 2024 blobscription event was the worst)"
    - "EIP-7742 and future EIPs will increase the blob target, reducing spike risk"
    - "Calldata fallback is more expensive but guarantees liveness"
    - "This is primarily an infrastructure/economic risk, rarely in bug bounty scope"
  confianza: media
  verificado: true
  tags: [EIP-4844, blob, fee-spike, DoS, batch-posting, finality]
  solodit_ids: []
  incidentes:
    - protocol: "Multiple L2s"
      firm: "Incident"
      impact: "LOW"
      date: "2024-03-27"
      title: "Blobscription spam caused blob fees to spike 10,000x briefly"
      description: >
        Users minting 'blobscriptions' (NFT-like inscriptions using blob space) filled
        all blob slots for ~30 minutes, causing blob base fee to spike from 1 wei to
        ~10 gwei. Several L2 sequencers temporarily delayed batch posting.
```

---

## 13. Sequencer Key Compromise

```yaml
- id: l2r-014
  pattern: sequencer-key-compromise
  name: "Single sequencer key controls all L2 state transitions — key compromise = total fund loss"
  severity: critical
  causa_raiz: >
    Most L2 rollups operate with a single centralized sequencer controlled by one
    private key (or a small multisig). If this key is compromised, the attacker can:
    (a) censor all transactions, (b) reorder transactions for MEV, (c) in some designs,
    post invalid state roots. While fraud proofs or validity proofs prevent (c) in
    properly designed rollups, the sequencer key can still cause (a) and (b) permanently
    until the key is rotated — and key rotation requires governance action.
  como_funciona: |
    1. Attacker compromises the sequencer's private key (phishing, server breach, insider)
    2. Attacker sequences transactions: front-runs all DEX swaps, sandwiches every trade
    3. Attacker censors specific users (e.g., liquidation bots) to protect their own positions
    4. On ZK rollups: attacker can delay batch proving (DoS) but cannot steal funds
    5. On optimistic rollups without permissionless proposing: attacker can post invalid state roots
       and no honest proposer can override (if proposing is permissioned)
    6. Users must resort to L1 escape hatch — 7+ day delay, high gas costs
  invariante: |
    // Sequencer rotation must be possible without full governance delay
    // Emergency key rotation with security council approval
    function rotateSequencer(address newSequencer) external {
        require(msg.sender == securityCouncil, "Only security council");
        sequencer = newSequencer;
        emit SequencerRotated(newSequencer);
    }
  que_mirar:
    - "Is the sequencer a single EOA, multisig, or distributed set?"
    - "Can the sequencer be rotated in an emergency? By whom? How fast?"
    - "grep: sequencer, batchPoster, SEQUENCER_ROLE, setSequencer, proposeSequencer"
    - "Is proposing/proving permissioned or permissionless?"
    - "What happens if the sequencer key is compromised? Is there a kill switch?"
  como_se_arregla: >
    1. Use a multisig or MPC for the sequencer key — no single point of failure.
    2. Implement permissionless proposing: anyone can post state roots (not just the sequencer).
    3. Emergency sequencer rotation controlled by a diverse security council.
    4. Shared sequencer networks (Espresso, Astria) distribute sequencing across multiple operators.
  trampas:
    - "Sequencer key compromise is out of scope for most bug bounties (infrastructure, not smart contracts)"
    - "Permissionless proposing doesn't help if the attacker IS the sequencer — they control ordering"
    - "Key rotation takes time — attacker can extract maximum value before rotation completes"
  confianza: alta
  verificado: true
  tags: [sequencer, key-compromise, centralization, single-point-of-failure]
  solodit_ids: []
  incidentes:
    - protocol: "zkSync Era (Airdrop)"
      firm: "Incident"
      impact: "HIGH"
      date: "2025-04-15"
      title: "Compromised admin key minted 111M ZK tokens via sweepUnclaimed() — $5M stolen"
      description: >
        An admin key controlling zkSync's airdrop contracts was compromised. The attacker
        called sweepUnclaimed() to mint ~111M unclaimed ZK tokens. ZK token dropped 15-20%.
        Hacker returned funds after accepting a 10% bounty (~$570K).
      payout: "$570,000 bounty"
```

---

## 14. ZK Prover Liveness Failure

```yaml
- id: l2r-015
  pattern: zk-prover-liveness-failure
  name: "ZK prover goes offline — no one can prove batches, finality halted"
  severity: high
  causa_raiz: >
    ZK rollups require specialized provers to generate validity proofs for each batch.
    If the prover is centralized (single operator) and goes offline — due to hardware
    failure, software bug, or resource exhaustion — no new batches can be finalized on L1.
    The L2 continues operating (sequencer posts batches) but withdrawals to L1 cannot
    be processed because they require a finalized proof. This creates a liveness failure
    where L2→L1 withdrawals are blocked indefinitely.
  como_funciona: |
    1. ZK prover is a single GPU cluster operated by the rollup team
    2. Software bug or hardware failure takes the prover offline
    3. Sequencer continues accepting and ordering transactions on L2
    4. Batches are posted to L1 as "pending" but no validity proof is submitted
    5. L2→L1 withdrawals require proof finalization — they queue up
    6. After hours/days, users panic — L2 token prices drop due to exit uncertainty
    7. Prover is fixed and catches up — but the backlog of unproven batches takes days to clear
  invariante: |
    // Prover must finalize batches within MAX_PROVING_DELAY of submission
    function isProvingHealthy() external view returns (bool) {
        uint256 lastProvenBatch = rollup.lastProvenBatchNumber();
        uint256 lastSubmittedBatch = rollup.lastSubmittedBatchNumber();
        uint256 provingLag = lastSubmittedBatch - lastProvenBatch;
        return provingLag <= MAX_PROVING_LAG; // e.g., 100 batches
    }
  que_mirar:
    - "Is proving permissioned (single prover) or permissionless (anyone can prove)?"
    - "What is the maximum proving delay observed historically?"
    - "grep: prove, prover, verifyBatch, proveBatch, proofSubmitter"
    - "Is there a fallback proving mechanism (slower but redundant prover)?"
    - "Does the rollup have an emergency mode for prover failure?"
  como_se_arregla: >
    1. Implement permissionless proving: anyone can submit proofs, not just the designated prover.
    2. Multiple redundant provers from different operators (prover marketplace).
    3. Emergency mode: if proving lag exceeds threshold, activate security council oversight.
    4. Proof generation should be parallelizable across multiple machines.
  trampas:
    - "Permissionless proving requires publishing the proving key — potential for proving market manipulation"
    - "Prover failures are usually temporary (hours) — the economic damage is in the panic, not the technical failure"
    - "Some ZK rollups (StarkNet) have had multi-hour proving delays without incident"
  confianza: alta
  verificado: true
  tags: [zk-rollup, prover, liveness, finality, proving-lag]
  solodit_ids: []
  incidentes:
    - protocol: "Polygon zkEVM"
      firm: "Incident"
      impact: "INFRASTRUCTURE"
      date: "2024-03-22"
      title: "14-hour outage — sequencer and prover failure due to L1 reorg mishandling"
      description: >
        Polygon zkEVM's synchronizer mishandled an Ethereum L1 reorg. The sequencer
        processed batches with incorrect timestamps. Emergency state activated
        (first use ever), requiring 6/8 Security Council multisig approval for
        an emergency upgrade to fix the prover and verifier contracts.
    - protocol: "Linea"
      firm: "Incident"
      impact: "INFRASTRUCTURE"
      date: "2025-06"
      title: "Linea sequencer malfunction — temporary outage before airdrop"
      description: "Short sequencer outage highlighting ongoing centralization risks"
```

---

## 15. L2 Block Time Assumptions

```yaml
- id: l2r-016
  pattern: l2-block-time-assumption
  name: "Contract assumes L1 block time (12s) on L2 — timing logic breaks"
  severity: medium
  causa_raiz: >
    Smart contracts often hardcode assumptions about block time (12 seconds on Ethereum
    L1) for time-dependent logic: vesting schedules, auction durations, interest
    accrual, voting periods, etc. On L2s, block times vary dramatically:
    - Arbitrum: variable (0.25s-1s per block, ~250ms average)
    - OP Stack: 2 seconds per block (fixed)
    - zkSync Era: variable (1-13s)
    - StarkNet: variable (minutes per block historically)
    Contracts using block.number for timing will behave incorrectly on L2.
  como_funciona: |
    1. Lending protocol sets interest accrual: BLOCKS_PER_YEAR = 2_628_000 (assumes 12s blocks)
    2. Deployed on Arbitrum where block time is ~0.25 seconds
    3. Actual blocks per year = ~126_144_000 (48x more than expected)
    4. Interest accrues 48x faster than intended
    5. Borrower's debt grows 48x faster — liquidated within hours instead of months
    6. OR: vesting contract releases tokens 48x faster
    7. OR: governance voting period of 7 days (in blocks) completes in 3.5 hours
  invariante: |
    // Use block.timestamp for time-dependent logic, NOT block.number
    // Except where block.number is explicitly needed (e.g., snapshot governance)
    function accruedInterest(uint256 principal, uint256 rate) public view returns (uint256) {
        uint256 elapsed = block.timestamp - lastAccrualTimestamp;
        return principal * rate * elapsed / SECONDS_PER_YEAR / 1e18;
    }
    // NEVER: principal * rate * (block.number - lastAccrualBlock) / BLOCKS_PER_YEAR
  que_mirar:
    - "Does the contract use block.number for timing instead of block.timestamp?"
    - "Is BLOCKS_PER_YEAR or similar constant hardcoded?"
    - "grep: BLOCKS_PER_YEAR, blocksPerYear, BLOCK_TIME, block.number, blockNumber"
    - "Is the contract deployed on L2 where block times differ from L1?"
    - "Does block.number return L1 block number (Arbitrum pre-Nitro) or L2 block number?"
  como_se_arregla: >
    Use block.timestamp for all time-dependent calculations. If block.number is needed
    (e.g., governance snapshots), use the L2's actual block production rate, not L1's.
    For Arbitrum specifically: block.number returns the L2 block number (post-Nitro),
    not the L1 block number. block.timestamp tracks real time accurately on all L2s.
  trampas:
    - "On Arbitrum, block.number used to return L1 block number (pre-Nitro) — post-Nitro it returns L2 block number"
    - "OP Stack has a fixed 2s block time — block.number-based timing is 6x faster than L1 assumptions"
    - "block.timestamp on L2 is generally reliable but may have small variances from real time"
    - "This is a very common finding — often flagged as Medium in contests but sometimes downgraded to Low/QA"
  confianza: alta
  verificado: true
  tags: [block-time, block-number, timestamp, L2, arbitrum, timing]
  solodit_ids: []
  incidentes: []
```

---

## 16. Deposit Finality Confusion

```yaml
- id: l2r-017
  pattern: deposit-finality-confusion
  name: "L1 deposit confirmed but not yet processed on L2 — protocol shows stale balance"
  severity: medium
  causa_raiz: >
    L1→L2 deposits go through multiple stages: L1 transaction confirmed → L1 block
    finalized → L2 processes the deposit message → L2 state updated. The delay
    between L1 confirmation and L2 processing varies by rollup (seconds to minutes).
    Protocols that assume instant deposit finality may show incorrect balances, allow
    double-spending of the deposit, or fail to credit the deposit if the L2 processing
    is delayed or fails silently.
  como_funciona: |
    1. User deposits 10 ETH into L1 bridge contract — L1 tx confirms in block N
    2. User's frontend shows "10 ETH deposited" — but L2 hasn't processed it yet
    3. L2 system processes the deposit in block N+100 (10-15 minutes later)
    4. During the gap: user's L2 balance shows 0 ETH
    5. If the L2 protocol checks balance during this gap, operations fail unexpectedly
    6. Or: the deposit message fails on L2 (gas limit too low, contract error)
    7. User thinks deposit succeeded (L1 confirmed) but funds are stuck in the bridge
  invariante: |
    // L2 balance should reflect L1 deposits within MAX_DEPOSIT_DELAY
    // For each L1 deposit event, there must be a corresponding L2 credit event
    // within MAX_DEPOSIT_DELAY blocks/seconds
    function isDepositProcessed(bytes32 depositHash) public view returns (bool) {
        return processedDeposits[depositHash];
    }
  que_mirar:
    - "How long does it take for L1 deposits to be processed on L2?"
    - "What happens if the L2 deposit processing fails? Is there a retry mechanism?"
    - "grep: finalizeDeposit, processDeposit, retryDeposit, depositHash, claimDeposit"
    - "Does the UI show deposits as confirmed before L2 processing?"
    - "Is there a gas limit on the L2 deposit processing call that could cause failures?"
  como_se_arregla: >
    1. Implement deposit status tracking: pending → processing → confirmed.
    2. Add retry mechanism for failed L2 deposit processing.
    3. Never show a deposit as "complete" until L2 has confirmed processing.
    4. Set the L2 deposit gas limit high enough to cover all possible execution paths.
  trampas:
    - "On OP Stack, deposits are processed in the next L2 block — delay is ~2 seconds"
    - "On Arbitrum, retryable tickets handle failed deposits — but users must manually redeem"
    - "zkSync: deposits can take 15+ minutes depending on prover backlog"
    - "This is usually a UX issue, not a smart contract vulnerability — but can become one if protocols assume instant deposits"
  confianza: media
  verificado: true
  tags: [deposit, finality, L1-to-L2, delay, balance, UX]
  solodit_ids: []
  incidentes: []
```

---

## 17. Rollup Upgrade & State Migration

```yaml
- id: l2r-018
  pattern: rollup-upgrade-migration-bug
  name: "State migration bugs during rollup protocol upgrade — storage slots misaligned or reset"
  severity: critical
  causa_raiz: >
    Rollup upgrades (e.g., Arbitrum Classic→Nitro, Polygon zkEVM emergency upgrades)
    require migrating L2 state to a new execution environment. If the migration is
    not perfectly faithful — storage layout changes, new system contracts initialize
    incorrectly, or the state migration script has bugs — user balances, contract
    storage, or system state can be corrupted. This is especially dangerous because
    L2 upgrades often happen atomically without the ability to roll back.
  como_funciona: |
    1. Rollup team announces upgrade from version N to version N+1
    2. The upgrade requires migrating the state trie to a new format
    3. Migration script has a bug: some storage slots are not properly remapped
    4. Post-upgrade: affected contracts have corrupted storage
    5. Token balances read 0, positions show wrong collateral, oracles return stale prices
    6. Users cannot access their funds — contracts are in an inconsistent state
    7. Emergency rollback is extremely difficult on L2 (requires L1 governance action)
  invariante: |
    // Pre-upgrade and post-upgrade state must be equivalent for ALL user-facing contracts
    // For each contract C and storage slot S:
    // pre_upgrade_state[C][S] == post_upgrade_state[C][S]
    // (except for explicitly migrated slots documented in the upgrade spec)
    function verifyMigration(address contract_, bytes32 slot) external view returns (bool) {
        bytes32 postValue = vm.load(contract_, slot);
        bytes32 preValue = getPreUpgradeValue(contract_, slot);
        return postValue == preValue;
    }
  que_mirar:
    - "Does the upgrade change the execution environment (e.g., new VM, new state format)?"
    - "Is there a state migration script? Has it been audited?"
    - "grep: initialize, reinitialize, migration, upgrade, _gap, storageSlot"
    - "Are storage layouts preserved across the upgrade? Check for storage collisions"
    - "Is there a dry-run mechanism to test the upgrade on a fork before mainnet?"
    - "Can the upgrade be rolled back if issues are discovered?"
  como_se_arregla: >
    1. Audit the migration script as thoroughly as the protocol code itself.
    2. Dry-run the upgrade on a mainnet fork and verify ALL storage slots match.
    3. Implement canary contracts that check critical invariants post-upgrade.
    4. Keep the old execution environment available as a fallback for N days.
    5. Use a security council with emergency pause capability during the upgrade window.
  trampas:
    - "Arbitrum Nitro migration was one of the most complex L2 upgrades — the bridge bug discovered by 0xriptide was upgrade-specific"
    - "Polygon zkEVM's emergency upgrade (March 2024) was forced by a bug — not planned — highest risk scenario"
    - "OP Stack Bedrock upgrade also required careful state migration — several edge cases found in audits"
    - "Storage layout verification tools (e.g., OpenZeppelin Upgrades Plugin) help but don't cover all cases"
  confianza: alta
  verificado: true
  tags: [upgrade, migration, state, storage, rollup, critical]
  solodit_ids: []
  incidentes:
    - protocol: "Arbitrum Nitro"
      firm: "Bug Bounty (0xriptide)"
      impact: "CRITICAL"
      date: "2022-09"
      title: "Bridge initialization bug after Nitro upgrade — $534M at risk"
      description: >
        During the Nitro upgrade, the bridge contract's inbox had empty storage slots
        that should have been initialized. An attacker could have set themselves as
        the deposit recipient, intercepting all L1→L2 ETH deposits. Over 400,000 ETH
        crossed the bridge between the upgrade and the bug report. 0xriptide was paid
        ~$400K via Immunefi bug bounty.
      payout: "$400,000"
    - protocol: "Polygon zkEVM"
      firm: "Incident"
      impact: "HIGH"
      date: "2024-03-22"
      title: "Emergency upgrade after L1 reorg caused sequencer failure"
      description: >
        First use of Polygon zkEVM's emergency state. Required 6/8 Security Council
        approval to push an upgrade that fixed the prover and verifier.
        ~4,000 transactions affected during the 14-hour outage.
```

---

## 18. Blast-Style Rebasing Token on L2

```yaml
- id: l2r-019
  pattern: l2-rebasing-native-token
  name: "L2 native rebasing tokens (Blast WETH/USDB) break DeFi protocols that assume static balances"
  severity: high
  causa_raiz: >
    Blast L2 modifies the native ETH and stablecoin (USDB) to automatically rebase,
    accruing yield from L1 staking/T-Bill returns. Contracts deployed on Blast that
    don't explicitly opt into or handle the rebasing mechanism will experience
    unexpected balance changes. This breaks core DeFi assumptions: AMM invariants,
    lending collateral calculations, vault share accounting, and any logic that
    assumes balanceOf(address) is constant between transactions.
  como_funciona: |
    1. Lending protocol on Blast holds 1000 ETH as collateral in its contract
    2. ETH rebases: contract balance increases to 1004 ETH (0.4% yield)
    3. Protocol doesn't account for the rebase — internal accounting still shows 1000 ETH
    4. The extra 4 ETH is "phantom balance" — not tracked, not distributed
    5. Attacker exploits the discrepancy: borrows against the phantom balance, or
       manipulates share pricing by timing deposits around rebase events
    6. In AMMs: rebasing changes the reserves, shifting the price curve unexpectedly
    7. In vaults: share price changes without any deposit/withdrawal, breaking monotonicity
  invariante: |
    // Contract must track rebasing balance explicitly if deployed on Blast
    // Option 1: Configure yield mode to VOID (disable rebasing)
    // Option 2: Track yield separately and distribute it correctly
    IBlast(BLAST_PREDEPLOY).configureClaimableYield(); // or VOID mode

    function claimYield() external {
        uint256 yield = IBlast(BLAST_PREDEPLOY).claimYield(address(this), address(this));
        // Distribute yield to stakeholders correctly
    }
  que_mirar:
    - "Is the contract deployed on Blast? Does it hold ETH or USDB?"
    - "Does the contract configure yield mode (VOID, CLAIMABLE, or AUTOMATIC)?"
    - "grep: IBlast, configureClaimableYield, claimYield, YieldMode, BLAST_PREDEPLOY"
    - "Does the contract assume balanceOf is constant between transactions?"
    - "Are AMM reserve calculations affected by rebasing?"
    - "Does the contract use WETH? Blast WETH also rebases by default"
  como_se_arregla: >
    1. If you don't want rebasing: call IBlast.configureVoidYield() in the constructor.
    2. If you want yield: call IBlast.configureClaimableYield() and manually claim/distribute.
    3. Never assume balanceOf is constant — use internal accounting (similar to ERC4626 approach).
    4. For AMMs: adjust reserve tracking to account for rebasing (or use VOID mode).
  trampas:
    - "Blast is the only major L2 with native rebasing tokens — findings are NOT generalizable to other L2s"
    - "The default yield mode is AUTOMATIC for EOAs but VOID for contracts — but many contracts change this"
    - "WETH on Blast also rebases, unlike WETH on every other chain"
    - "Uniswap V3 on Blast explicitly does not support rebasing tokens in concentrated liquidity positions"
  confianza: alta
  verificado: true
  tags: [blast, rebasing, yield, WETH, USDB, balance, DeFi]
  solodit_ids: []
  incidentes:
    - protocol: "Munchables (on Blast)"
      firm: "Incident"
      impact: "CRITICAL"
      date: "2024-03-26"
      title: "Rogue developer exploited admin access to steal $62M in ETH"
      description: >
        A developer on the Munchables GameFi project (deployed on Blast) used admin
        access to assign themselves a large ETH balance in a previous, unverified
        implementation before launch. They later withdrew ~17,400 ETH ($62M).
        Blast team helped recover the funds by pressuring the developer.
      payout: "Funds recovered"
```

---

## 19. zkSync EVM Incompatibility

```yaml
- id: l2r-020
  pattern: zksync-evm-incompatibility
  name: "zkSync Era EVM differences cause unexpected behavior — CREATE, nonce, EXTCODEHASH divergences"
  severity: medium
  causa_raiz: >
    zkSync Era (and other ZK rollups) use a custom VM (EraVM) that is not 100% EVM
    equivalent. Key differences include: CREATE/CREATE2 address computation uses a
    different formula, deployment nonces start at 0 (not 1), EXTCODEHASH returns
    different values for empty accounts, legacy transactions lack EIP-155 replay
    protection by default, and gas costs differ for some opcodes. Contracts ported
    from L1 without accounting for these differences may produce incorrect results,
    fail to deploy, or have security vulnerabilities.
  como_funciona: |
    1. Factory contract uses CREATE2 to deploy child contracts at deterministic addresses
    2. The same bytecode and salt produce DIFFERENT addresses on zkSync vs Ethereum
       (because zkSync includes the bytecodeHash in the address computation)
    3. Frontend/SDK hardcodes the expected address from Ethereum's formula
    4. Transactions sent to the "expected" address go to a different contract (or no contract)
    5. Funds sent to the wrong address are lost or intercepted
    6. Similarly: contract expects nonce=1 for first child contract — but zkSync starts at 0
    7. Address prediction is off-by-one, breaking contract interactions
  invariante: |
    // On zkSync, CREATE2 address = keccak256(0xff ++ sender ++ salt ++ keccak256(bytecodeHash))
    // Note: bytecodeHash uses zkSync's hash, not keccak256(initCode)
    // This means addresses differ from Ethereum even with same inputs

    // Nonce invariant: first CREATE uses nonce=0, not nonce=1
    // Contract must not assume Ethereum's nonce behavior
  que_mirar:
    - "Does the contract use CREATE or CREATE2 for deployment? Are the addresses precomputed?"
    - "Does the contract assume nonces start at 1?"
    - "grep: CREATE, CREATE2, getDeployedAddress, keccak256, nonce, extcodehash"
    - "Does the contract rely on EXTCODEHASH for empty account checks?"
    - "Is EIP-155 (chain ID in signatures) enforced for legacy transactions?"
    - "Is the contract compiled with zksolc? Check for compiler-specific bugs (CVE-2024-45056, CVE-2024-38533)"
  como_se_arregla: >
    1. Use zkSync-specific address computation formulas for CREATE/CREATE2.
    2. Do not assume nonces start at 1 — use the NonceHolder system contract.
    3. Replace EXTCODEHASH checks with explicit code length checks.
    4. Enforce EIP-155 for all transaction types.
    5. Use the latest zksolc compiler version (1.5.3+) to avoid known compiler bugs.
  trampas:
    - "zkSync documents these differences but many teams miss them when porting"
    - "The Code4rena 2023-10-zksync audit found 6 high and 23 medium issues — many related to EVM divergences"
    - "Sherlock's 2024-04-titles audit flagged CREATE opcode differences on zkSync (issue #91)"
    - "zksolc compiler bugs (CVE-2024-45056, CVE-2024-38533) affected bitwise operations and stack addressing"
  confianza: alta
  verificado: true
  tags: [zkSync, EVM-incompatibility, CREATE, nonce, EXTCODEHASH, compiler]
  solodit_ids: []
  incidentes:
    - protocol: "Era Lend (on zkSync)"
      firm: "Incident"
      impact: "CRITICAL"
      date: "2023-07-25"
      title: "Read-only reentrancy exploit — $3.4M stolen"
      description: >
        Era Lend, a Compound fork on zkSync Era, was exploited via a read-only
        reentrancy attack on a faulty price oracle (SyncSwap-based). The attacker
        used the reentrancy to manipulate the oracle price and drain the USDC pool.
        CertiK warned other SyncSwap forks might be vulnerable.
      payout: "Funds not recovered"
    - protocol: "zkSync (Compiler)"
      firm: "CVE"
      impact: "MEDIUM"
      date: "2024-08"
      title: "CVE-2024-45056 — zksolc compiler mishandles XOR+SHL folding"
      description: >
        LLVM optimization incorrectly zero-extends instead of sign-extending a constant,
        producing wrong results for bitwise operations. No deployed contracts affected
        at time of disclosure. Fixed in zksolc 1.5.3.
```

---

## 20. Sovereign Rollup / Appchain Patterns

```yaml
- id: l2r-021
  pattern: sovereign-rollup-validator-set
  name: "Sovereign rollup validator set manipulation — stake-weighted ordering and censorship"
  severity: medium
  causa_raiz: >
    Sovereign rollups (like dYdX v4 on Cosmos SDK) and appchains use their own
    validator set for consensus and ordering, separate from Ethereum. Unlike shared
    sequencers, sovereign validators can collude for ordering manipulation, censor
    specific transaction types, or extract MEV through priority ordering. The
    validator set's economic security depends on the appchain's native token value,
    creating a circular dependency: low token value → low security → exploits →
    even lower token value.
  como_funciona: |
    1. Sovereign rollup has 100 validators with $50M total stake
    2. The rollup's DeFi TVL is $500M — 10x the validator stake
    3. Validator collusion to steal $500M requires corrupting 67% of stake ($33M)
    4. The attack is profitable: $500M stolen vs $33M at risk (15x ROI)
    5. Or: a single large validator (e.g., 15% stake) front-runs all DEX orders
    6. Users can't verify ordering fairness without replaying the entire chain
    7. Unlike Ethereum L2s, there's no L1 fallback or escape hatch to Ethereum
  invariante: |
    // Validator set economic security must exceed the value at risk
    // This is a protocol-level design invariant, not a code assertion
    function isSecuritySufficient() external view returns (bool) {
        uint256 totalStake = stakingContract.totalStaked();
        uint256 tvl = getTotalValueLocked();
        return totalStake * 3 >= tvl; // Stake should be >= 1/3 of TVL
    }
  que_mirar:
    - "Is the rollup sovereign (own validator set) or uses Ethereum for settlement?"
    - "What is the ratio of validator stake to TVL?"
    - "Can validators censor specific transaction types?"
    - "grep: validatorSet, stakeAmount, slashingCondition, proposerSelection"
    - "Is there economic extraction possible through ordering (front-running, sandwiching)?"
    - "What are the slashing conditions? Are they enforceable?"
  como_se_arregla: >
    1. Use Ethereum as the settlement/DA layer — inherit its security.
    2. If sovereign: ensure economic security (validator stake) exceeds TVL.
    3. Implement verifiable ordering (commit-reveal, threshold encryption).
    4. Use restaking (EigenLayer) to bootstrap validator economic security.
  trampas:
    - "dYdX v4 uses CometBFT consensus — validator collusion requires 67% stake, which is very high"
    - "Appchain security model is fundamentally different from L2 rollup — don't apply L2 assumptions"
    - "Cosmos IBC provides some interoperability guarantees but not the same as Ethereum settlement"
    - "For bug bounties, validator behavior is usually out of scope — focus on smart contract/module logic"
  confianza: media
  verificado: true
  tags: [sovereign-rollup, appchain, validator, consensus, dYdX, cosmos]
  solodit_ids: []
  incidentes: []
```

---

## Quick Reference — Checklist for L2 Deployment Audits

```yaml
# Copy-paste into your audit checklist for any L2 deployment

L2_DEPLOYMENT_CHECKLIST:
  sequencer_trust:
    - "[ ] Chainlink Sequencer Uptime Feed integrated (l2r-001)"
    - "[ ] Liquidation grace period after sequencer restart (l2r-002)"
    - "[ ] Force-inclusion mechanism tested and functional (l2r-003)"
    - "[ ] Sequencer key management reviewed (l2r-014)"

  messaging:
    - "[ ] L1→L2 message replay prevention (processed mapping, nonces) (l2r-004)"
    - "[ ] L2→L1 withdrawal cannot expire permanently (l2r-005)"
    - "[ ] Address aliasing handled for force-included transactions (l2r-003)"
    - "[ ] Deposit finality UX is accurate (l2r-017)"

  timing:
    - "[ ] No block.number for timing — use block.timestamp (l2r-016)"
    - "[ ] No hardcoded BLOCKS_PER_YEAR or similar constants (l2r-016)"
    - "[ ] Timeouts and deadlines account for L2 block time differences (l2r-016)"

  data_availability:
    - "[ ] Is this a rollup or validium? Check L2BEAT classification (l2r-012)"
    - "[ ] DAC composition and threshold are sufficient (l2r-012)"
    - "[ ] Blob fee spike fallback exists (l2r-013)"

  zk_specific:
    - "[ ] Proof verification gas < 50% of L1 block gas limit (l2r-008)"
    - "[ ] Prover liveness monitoring in place (l2r-015)"
    - "[ ] CREATE/CREATE2 address computation uses correct formula (l2r-020)"
    - "[ ] Compiler version is patched (zksolc >= 1.5.3) (l2r-020)"

  chain_specific:
    - "[ ] Blast: yield mode configured (VOID or CLAIMABLE) (l2r-019)"
    - "[ ] Blast: WETH rebasing handled (l2r-019)"
    - "[ ] zkSync: nonce behavior tested (starts at 0) (l2r-020)"
    - "[ ] zkSync: EXTCODEHASH differences handled (l2r-020)"
    - "[ ] Arbitrum: block.number returns L2 block (post-Nitro) (l2r-016)"

  upgrades:
    - "[ ] State migration script audited (l2r-018)"
    - "[ ] Storage layout preserved across upgrade (l2r-018)"
    - "[ ] Dry-run on mainnet fork before upgrade (l2r-018)"
    - "[ ] Emergency rollback plan exists (l2r-018)"

  cross_l2:
    - "[ ] Cross-L2 operations have timeout/refund mechanism (l2r-011)"
    - "[ ] No assumption of atomic cross-L2 execution (l2r-011)"
    - "[ ] Challenge window is sufficient for fraud proofs (l2r-007)"
```

---

## Solodit Search Strategies for L2 Findings

```yaml
# Effective queries to find L2-specific findings on Solodit
search_strategies:
  - query: "sequencer uptime Chainlink L2"
    tags: [l2r-001, l2r-002]
    expected_results: "10+ findings across multiple protocols"

  - query: "block.number Arbitrum assumption"
    tags: [l2r-016]
    expected_results: "5+ findings, mostly Medium severity"

  - query: "address aliasing L1 L2"
    tags: [l2r-003]
    expected_results: "3+ findings about msg.sender aliasing"

  - query: "CREATE opcode zkSync"
    tags: [l2r-020]
    expected_results: "2+ findings about address computation differences"

  - query: "Blast rebasing yield mode"
    tags: [l2r-019]
    expected_results: "5+ findings about WETH/USDB handling on Blast"

  - query: "fraud proof challenge period"
    tags: [l2r-007]
    expected_results: "3+ findings about challenge window adequacy"

  - query: "data availability committee validium"
    tags: [l2r-012]
    expected_results: "2+ findings about DAC trust assumptions"
```

---

## Cross-References

- **OP Stack specific patterns**: See `bridge-opstack.md` (19 patterns: ops-001..ops-019)
- **General bridge patterns**: See `bridge.md` and `cross-chain-messaging.md`
- **Oracle manipulation**: See `oracle.md` (includes general oracle patterns, not L2-specific)
- **Reentrancy**: See `reentrancy-patterns.md` (includes read-only reentrancy relevant to l2r-020)
- **Proxy/Upgrade patterns**: See `proxy-upgrade.md` and `diamond-advanced-proxy.md`
- **MEV patterns**: See `mev-sandwich.md` (includes L1 MEV, partially applicable to L2)
