# Governance Vulnerabilities — Combat Briefing

> Attack surface: proposal lifecycle, voting power, timelock, flash loan + delegation,
> veto/guardian, cross-chain governance, vote accounting bugs.
> Sources: verified Solodit findings from Sherlock/Code4rena/Spearbit audits.

---

## 1. Flash Loan & Vote Manipulation

```yaml
- id: gov-001
  pattern: flashloan-delegation-vote-bypass
  name: "Flash loan + delegated voting bypasses token-lock mitigations in one tx"
  severity: high
  causa_raiz: >
    Protocols protect against flash loan governance attacks by locking tokens during
    active proposals. But if voting power can be DELEGATED, an attacker borrows tokens,
    delegates to a pre-deployed attack contract (which already has voting rights),
    votes on the proposal, then repays — all in one transaction. The token lock
    only covers direct stakers, not delegated votes from borrowed tokens.
  como_funciona: |
    1. Attacker deploys attack contract with zero tokens (no lock applies)
    2. Flash borrows large token amount from lending protocol
    3. Delegates borrowed tokens to attack contract
    4. Attack contract votes on target proposal (passes quorum due to flash loan size)
    5. Repay flash loan — proposal state is already decided
    6. All in one tx — token lock never triggers because tokens were delegated, not staked
  invariante: >
    Voting power at block N must be snapshotted at block N-1 or earlier.
    Votes cast with tokens borrowed in the same block must not count.
    Formally: getPastVotes(account, block.number - 1) should be used, not balanceOf().
  que_mirar:
    - "Does castVote() use getPastVotes(voter, block.number - 1) or current balance?"
    - "Can delegation change in the same block as voting without checkpoint lag?"
    - "Is there a minimum token-holding period before voting power is active?"
    - "grep: getPastVotes, _getVotes, block.number, delegate, castVote"
    - "grep: ERC20Votes, ERC20VotesComp, _checkpoints, getPriorVotes"
  como_se_arregla: >
    Use ERC20Votes checkpoint pattern: votes always read from block.number - 1 snapshot.
    Never read live balance for governance. Require minimum hold period (e.g., 1 block)
    before delegated power becomes active.
  trampas:
    - "If the protocol uses snapshots, flash loans don't work — check if snapshots are actually block-based"
    - "Delegation-based attacks work even if direct staking is locked"
    - "Some protocols use timestamp-based snapshots — flash loans across the same second still work"
  confianza: alta
  verificado: true
  tags: [flash-loan, delegation, governance, voting-power, checkpoint]
  solodit_ids: [27294]
  incidentes:
    - protocol: "GovPool"
      firm: "Unknown"
      impact: "HIGH"
      title: "Attacker combines flashloan with delegated voting to decide proposal in single tx"
      detail: "Existing flash loan lock only covers stakers; delegated votes from borrowed tokens bypass it. Attack contract pre-deployed, delegation + vote + repay in one transaction."
      slug: "attacker-can-combine-flashloan-with-delegated-voting-to-decide-a-proposal-and-withdraw-their-tokens-while-the-proposal-is-still-in-locked-state"

- id: gov-002
  pattern: zero-balance-vote-drains-refund-vault
  name: "castVote callable by zero-balance addresses — gas refund vault drained"
  severity: medium
  causa_raiz: >
    Governor contracts that refund voters for their gas costs (as incentive to vote)
    often fail to check that the voter actually has voting power before issuing the refund.
    An attacker creates many addresses with zero tokens and calls castVote() from each —
    each call costs ~21k gas, earns the gas refund, and produces a zero-weight vote.
    The vault is drained with no governance impact but full cost to the protocol.
  como_funciona: |
    1. Protocol refunds gas to voters: after castVote(), vault.transfer(gasCost) to caller
    2. Attacker creates N wallets with 0 governance tokens
    3. Each wallet calls castVote() — vote weight is 0, but refund is paid
    4. Repeat with N wallets — drain refund vault
    5. No tokens needed, no risk, pure profit vs gas cost
  invariante: >
    For any call castVote(proposalId, support):
    require(getVotes(msg.sender, proposalSnapshot(proposalId)) > 0, "NoVotingPower")
    Gas refund (if any) must only be paid when votes > 0.
  que_mirar:
    - "Is there a check that voter has > 0 votes before issuing gas refund?"
    - "Is castVote() callable by anyone including zero-balance addresses?"
    - "grep: castVote, gasRefund, _refundGas, REFUND_BASE_GAS"
    - "Does the contract inherit GovernorBravo refund logic?"
  como_se_arregla: >
    Add: require(getVotes(msg.sender, proposalSnapshot(proposalId)) > 0, "NoVotingPower")
    before processing the vote and BEFORE issuing any gas refund.
  trampas:
    - "Zero-vote cast still emits VoteCast event — logs look legitimate"
    - "Bug only matters when gas refunds are enabled — check if REFUND_BASE_GAS > 0"
  confianza: alta
  verificado: true
  tags: [governance, gas-refund, voting-power, zero-balance, drain]
  solodit_ids: [3597]
  incidentes:
    - protocol: "FrankenDAO"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "castVote can be called by anyone even those without votes — drains gas refund vault"
      slug: "m-5-castvote-can-be-called-by-anyone-even-those-without-votes-sherlock-none-frankendao-git"

- id: gov-003
  pattern: vote-power-inflation-no-cap
  name: "Voting power can be inflated indefinitely via transfer/claim loops"
  severity: high
  causa_raiz: >
    ERC20Votes-based systems that don't use standard OZ checkpointing, or that allow
    voting power to be claimed/minted without a corresponding token burn or lock, can
    have their vote balances inflated arbitrarily. If _mint() or claimVotes() doesn't
    correctly deduct from a pool, the attacker accumulates infinite votes with finite tokens.
  como_funciona: |
    1. Protocol mints voting tokens on claim or transfer
    2. Claim function: votingToken.mint(user, amount) — no supply check
    3. Attacker calls claim() repeatedly — votes.balanceOf(attacker) grows unboundedly
    4. With inflated votes, attacker passes any proposal
    5. Root cause: total supply not tracked, or claim does not consume source tokens
  invariante: >
    sum(getVotes(all_users)) == token.totalSupply() at all times.
    No user's votes should exceed their token balance.
  que_mirar:
    - "Is voting power minted separately from governance tokens?"
    - "Does claim() decrement a source balance before minting votes?"
    - "grep: _mint, claimVotes, getVotes, totalSupply, VestingMerkle, CrosschainMerkle"
    - "Is there a separate 'votes' token that can be double-minted?"
  como_se_arregla: >
    Tie voting power strictly to token custody: use ERC20Votes where votes == balance.
    Never have a separate mint path for votes that doesn't consume tokens.
  trampas:
    - "Cross-chain vesting distributions are especially vulnerable — same Merkle proof accepted on multiple chains"
    - "Affects ContinuousVestingMerkle, PriceTierVestingMerkle, CrosschainMerkleDistributor patterns"
  confianza: alta
  verificado: true
  tags: [governance, vote-inflation, ERC20Votes, vesting, merkle]
  solodit_ids: [21226]
  incidentes:
    - protocol: "TokenSoft"
      firm: "Sherlock"
      impact: "HIGH"
      title: "Votes balance can be increased indefinitely across multiple vesting contracts"
      slug: "h-1-votes-balance-can-be-increased-indefinitely-in-multiple-contracts-sherlock-none-tokensoft-git"
```

---

## 2. Proposal Lifecycle & State Machine

```yaml
- id: gov-004
  pattern: proposal-counter-wrong-field
  name: "queue() increments proposalsCreated instead of proposalsPassed — score accounting broken"
  severity: medium
  causa_raiz: >
    Governance systems that reward proposers based on community scores (created vs passed)
    sometimes update the wrong counter. queue() (called when a proposal passes) should
    increment proposalsPassed, but if it increments proposalsCreated instead, proposers
    earn double creation credit and zero pass credit. Score multipliers then produce
    incorrect voting power boosts, which can be gamed.
  como_funciona: |
    1. Protocol computes votingPower += proposalsCreated * createdMultiplier
                                       + proposalsPassed * passedMultiplier
    2. queue() calls: userScoreData[proposer].proposalsCreated++ (WRONG)
    3. proposer.proposalsCreated is now 2 (created once + queued once)
    4. Attacker creates many proposals that reach queue — earns inflated proposalsCreated
    5. With createdMultiplier > 1, gains disproportionate voting power
  invariante: >
    After queue(proposalId): userScore[proposer].proposalsPassed == prev + 1.
    userScore[proposer].proposalsCreated must NOT change during queue().
  que_mirar:
    - "Does queue() touch proposalsPassed or proposalsCreated?"
    - "Does veto() decrement both counters when removing a malicious proposal?"
    - "grep: proposalsPassed, proposalsCreated, userCommunityScoreData, queue"
    - "grep: setProposalsPassedMultiplier, setProposalsCreatedMultiplier"
  como_se_arregla: >
    In queue(): increment proposalsPassed, not proposalsCreated.
    In veto(): decrement BOTH proposalsPassed and proposalsCreated (the proposal was both created and may have passed).
  trampas:
    - "The bug is invisible to users — the score looks reasonable unless you diff created vs passed"
    - "veto() not decrementing proposalsPassed is a separate but related issue (gov-005)"
  confianza: alta
  verificado: true
  tags: [governance, proposal-score, queue, accounting, voting-power]
  solodit_ids: [3596, 3599, 5670]
  incidentes:
    - protocol: "FrankenDAO"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "queue() should increase proposalsPassed instead of proposalsCreated"
      slug: "m-4-queue-should-increase-proposalspassed-instead-of-proposalscreated-sherlock-none-frankendao-git"
    - protocol: "FrankenDAO"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Veto function should decrease proposalsPassed — malicious proposer keeps score bonus"
      slug: "m-10-veto-function-should-decrease-proposalspassed-and-possibly-proposalscreated-sherlock-none-frankendao-git"

- id: gov-005
  pattern: delegate-trap-active-proposal
  name: "Malicious delegate keeps delegatees permanently locked via perpetual active proposals"
  severity: medium
  causa_raiz: >
    Many governance systems lock delegated tokens while the delegate has voted on an active
    proposal. If there is no upper bound on active proposals and creating proposals is cheap,
    a malicious delegate creates an endless stream of proposals to keep their delegatees
    permanently trapped — delegatees cannot unstake or re-delegate.
  como_funciona: |
    1. Alice delegates votes to Mallory
    2. Mallory creates Proposal 1, votes on it
    3. Alice tries to unstake: lockedWhileVotesCast() reverts (active proposal)
    4. Proposal 1 reaches end of voting period
    5. Mallory immediately creates Proposal 2, votes on it
    6. Alice still trapped — Mallory repeats indefinitely
    7. Alice can never unstake or change delegate
  invariante: >
    A delegatee must always have a path to unstake within a finite time window,
    regardless of delegate behavior. Either: max concurrent proposals per address,
    or lock tied to proposal creation time (not end of voting period).
  que_mirar:
    - "Can a single address vote on unlimited overlapping proposals?"
    - "Is unstaking gated on delegate's active proposals?"
    - "Is there a max proposal creation rate per address?"
    - "grep: lockedWhileVotesCast, activeProposals, getActiveProposals, unstake, undelegate"
  como_se_arregla: >
    Cap concurrent proposals per delegator or per governance system. Or allow unstaking
    after a fixed timeout regardless of active proposals. Or require bond per proposal
    to make perpetual creation expensive.
  trampas:
    - "Attack works even if attacker never wins any proposal — DoS is the goal"
    - "Bond requirements can mitigate cost but not prevent if attacker has enough tokens"
  confianza: alta
  verificado: true
  tags: [governance, delegation, lock, dos, active-proposal]
  solodit_ids: [3598]
  incidentes:
    - protocol: "FrankenDAO"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Delegate can keep delegatees trapped indefinitely by creating perpetual active proposals"
      slug: "m-6-delegate-can-keep-can-keep-delegatee-trapped-indefinitely-sherlock-none-frankendao-git"

- id: gov-006
  pattern: proposal-threshold-bypass-spam
  name: "Proposal threshold computed from live supply — snapshot manipulable, spam griefing possible"
  severity: medium
  causa_raiz: >
    proposalThreshold() computes the required votes as a % of CURRENT total supply
    (block.timestamp or block.number). If supply changes between proposal creation
    and threshold check, or if threshold is read from live state during castVote()
    rather than at proposal creation, an attacker can time proposals to bypass the
    threshold when supply is temporarily low (e.g., after burns or before mints).
  como_funciona: |
    1. proposalThreshold = totalSupply() * numerator / denominator
    2. Attacker waits for or causes a temporary supply decrease (burn, large unstake)
    3. Calls propose() while threshold is low — proposal accepted
    4. Supply recovers — proposer never had enough tokens for the normal threshold
    5. Proposal now active and valid despite bypassing the intended minimum
  invariante: >
    Proposal threshold must be evaluated at proposal creation time and stored.
    The stored threshold must be used for all subsequent validations on that proposal.
  que_mirar:
    - "Is proposalThreshold() called at proposal creation and stored, or re-evaluated live?"
    - "Does propose() use block.timestamp vs block.number for supply snapshot?"
    - "Is there a minimum hold time for proposal tokens?"
    - "grep: proposalThreshold, getPastTotalSupply, propose, block.timestamp"
  como_se_arregla: >
    Store proposalThreshold at creation: proposal.threshold = proposalThreshold().
    Use getPastTotalSupply(block.number - 1) in proposalThreshold(), never live supply.
    Require proposer to hold minimum tokens for N blocks before proposing.
  trampas:
    - "Block.timestamp in proposalThreshold() is vulnerable to manipulation on L2s with fast blocks"
    - "Even without manipulation, live supply creates race conditions between propose() and state changes"
  confianza: alta
  verificado: true
  tags: [governance, proposal-threshold, supply-snapshot, spam, griefing]
  solodit_ids: [38210]
  incidentes:
    - protocol: "Alchemix DAO"
      firm: "Unknown"
      impact: "MEDIUM"
      title: "Bypassing governance proposal threshold to spam malicious proposals as griefing attack"
      slug: "bypassing-the-governances-proposal-threshold-to-spam-malicious-proposal-as-a-griefing-attack"
```

---

## 3. Timelock

```yaml
- id: gov-007
  pattern: timelock-period-not-enforced
  name: "Admin/owner can call timelock-protected functions before delay expires"
  severity: high
  causa_raiz: >
    Functions marked as timelock-protected (requiring a waiting period before execution)
    sometimes have incorrect or missing timestamp checks. The delay is stored but never
    validated against block.timestamp at execution time — any call succeeds immediately.
    Or the delay comparison uses the wrong reference point (createdAt vs queuedAt).
  como_funciona: |
    1. Protocol documents: "admin must wait 7 days before calling sensitiveFunction()"
    2. Implementation: sensitiveFunction() reads timelockDeadline but never requires
       block.timestamp >= timelockDeadline
    3. Admin calls sensitiveFunction() immediately after proposal is created
    4. No delay enforced — admin extracts NFT/funds before anyone can react
  invariante: >
    For any timelock-protected function: require(block.timestamp >= timelockDeadline[id]).
    The deadline must be stored at queue time and validated at execute time.
  que_mirar:
    - "Is timelockDeadline actually checked with require() at execution time?"
    - "Is the deadline stored as createdAt + delay or queuedAt + delay?"
    - "grep: timelockDeadline, recoverTimelock, drawTimelock, lastResortTimelock"
    - "grep: require.*block.timestamp.*timelock, require.*deadline"
  como_se_arregla: >
    At execution: require(block.timestamp >= queueTime[id] + TIMELOCK_DELAY, "TooEarly").
    Both the queue time AND the delay must be stored on-chain at queue time.
  trampas:
    - "The delay is often stored correctly but the check is missing or uses wrong variable"
    - "recoverTimelock pattern is especially prone: admin 'last resort' often lacks the delay check"
  confianza: alta
  verificado: true
  tags: [timelock, governance, admin, delay-bypass, access-control]
  solodit_ids: [6394]
  incidentes:
    - protocol: "Unknown Raffle"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Admin does not have to wait to call lastResortTimelockOwnerClaimNFT()"
      slug: "h-01-admin-does-not-have-to-wait-to-call-lastresorttimelockownerclaiment-code4rena"

- id: gov-008
  pattern: timelock-setter-bypass
  name: "Timelock bypassed via setter — new value applied immediately instead of after delay"
  severity: medium
  causa_raiz: >
    Protocols apply timelocks to configuration changes (e.g., fee rate, oracle address,
    treasury address). But some setters are exempt from the timelock or apply changes
    immediately because they use a different code path (direct owner call vs governance
    proposal). The setter bypasses the delay that governance actions would have.
  como_funciona: |
    1. Protocol uses TimelockController for governance proposals (7-day delay)
    2. Owner also has setFee(uint256) — direct call, no timelock
    3. setFee() changes fee immediately without queuing
    4. Attacker (or compromised owner) front-runs a large user tx by setting fee to 100%
    5. User pays 100% fee; attacker reverts fee back (or keeps it)
    6. The governance timelock provided false security — setters bypass it
  invariante: >
    All state-changing setters (fee, oracle, treasury, whitelist) must go through
    the same TimelockController path as governance proposals.
    Direct owner setter calls must not exist for sensitive parameters.
  que_mirar:
    - "Can owner call setters directly, bypassing the timelock?"
    - "Is there a separate onlyOwner path and a governance path for the same parameter?"
    - "grep: onlyOwner.*set, TimelockController, TIMELOCK_ADMIN_ROLE, schedule, execute"
    - "Does the timelock control ALL privileged functions or just proposals?"
  como_se_arregla: >
    Route ALL sensitive setters through TimelockController.schedule() + execute().
    Remove direct onlyOwner setter paths entirely. Grant TIMELOCK_ADMIN_ROLE only to
    the timelock contract, not to EOAs or multisigs.
  trampas:
    - "Auditors approve the timelock thinking it covers everything — the direct path is easy to miss"
    - "Some setters are 'emergency only' and intentionally bypass timelock — these must be explicitly scoped"
  confianza: alta
  verificado: true
  tags: [timelock, setter-bypass, governance, fee, access-control]
  solodit_ids: [8749]
  incidentes:
    - protocol: "Unknown"
      firm: "Unknown"
      impact: "MEDIUM"
      title: "Some setters timelock can be bypassed via direct owner call"
      slug: "m-12-some-setters-timelock-can-be-bypassed"
```

---

## 4. Veto & Guardian

```yaml
- id: gov-009
  pattern: vetoer-address-zero-51-attack
  name: "Vetoer can be set to address(0) — veto power permanently lost, 51% attack possible"
  severity: high
  causa_raiz: >
    Governance systems with a veto guardian (address that can cancel any proposal) often
    allow the vetoer address to be changed via a one-step process without zero-address
    validation. A malicious governance vote or accidental call sets vetoer = address(0),
    permanently destroying the safeguard. Once veto is gone, a 51% majority can pass
    any proposal including treasury drains.
  como_funciona: |
    1. Protocol has vetoer = multisig (emergency backstop against malicious 51% attacks)
    2. Governance proposal: setVetoer(address(0)) — passes with bare majority
    3. vetoer = address(0) — veto() always reverts (onlyVetoer modifier)
    4. Second proposal: transferTreasury(attacker, all_funds)
    5. No veto possible — funds drained via legitimate governance
  invariante: >
    setVetoer(newVetoer) must require: newVetoer != address(0).
    Changing vetoer should be a 2-step process: propose → delay → execute.
    Veto power should require supermajority (>50%) to remove, not simple majority.
  que_mirar:
    - "Is there a zero-address check in setVetoer() or equivalent?"
    - "Is the vetoer change protected by a timelock or supermajority?"
    - "Can the vetoer renounce their power without a replacement?"
    - "grep: setVetoer, vetoer, onlyVetoer, _vetoer, burnVetoer"
  como_se_arregla: >
    require(newVetoer != address(0), "ZeroAddress"). Make vetoer changes a 2-step
    process via TimelockController with a longer delay than normal proposals.
    Require >66% quorum to change the vetoer.
  trampas:
    - "Nouns DAO had this exact issue — became a template for other DAOs that copied the vulnerability"
    - "Some protocols have 'burnVetoer()' by design — that IS the one legitimate zero-address path"
    - "The renounce-then-attack requires a 2-proposal sequence — watch for these in governance history"
  confianza: alta
  verificado: true
  tags: [governance, veto, guardian, zero-address, 51-percent-attack]
  solodit_ids: [3278]
  incidentes:
    - protocol: "Nouns Builder"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Loss of veto power can lead to 51% attack — missing zero address check in setVetoer"
      slug: "m-11-loss-of-veto-power-can-lead-to-51-attack-code4rena-nouns-builder-nouns-builder-contest-git"

- id: gov-010
  pattern: majority-bypass-cancel-chain
  name: "51% majority bypasses proposal safeguards by cancelling in-progress proposal mid-execution"
  severity: high
  causa_raiz: >
    Multi-step proposals (e.g., list NFT on Zora first, then OpenSea) have safeguards
    that only apply during execution. Cancelling a proposal mid-execution (after step 1
    but before step 2) leaves the system in an intermediate state where safeguards no
    longer apply — the token ownership check or listing lock is gone. A second proposal
    can then exploit the unguarded state.
  como_funciona: |
    [PartyDAO pattern]
    1. Safeguard: NFT cannot change owner during non-unanimous proposal execution
    2. Proposal A: step 1 = fractionalize NFT into ERC20 tokens
    3. 51% majority executes step 1 (NFT enters fractionalization contract)
    4. Mid-execution, majority cancels Proposal A — safeguard removed, no cleanup
    5. Proposal B: arbitrary call to fractionalization contract — redeem NFT at 0 price
    6. Majority redeems all fractionalized tokens and extracts NFT for free
  invariante: >
    Cancelling a multi-step proposal must either revert all completed steps (full rollback)
    OR leave the system in a state where all safeguards still apply.
    No intermediate state should be exploitable by a new proposal.
  que_mirar:
    - "Are there multi-step proposals with safeguards only during execution?"
    - "Does cancel() run cleanup logic to restore state from completed steps?"
    - "Can a cancelled in-progress proposal leave intermediate state accessible?"
    - "grep: InProgress, cancel, proposalState, _cancelProposal, progressData"
    - "grep: precious, preciousTokenId, ArbitraryCallsProposal"
  como_se_arregla: >
    In cancel(): if proposal is InProgress, run rollback handlers for each completed step.
    Or: lock all state changes from step 1 until the full proposal completes or is fully
    rolled back — never leave intermediate state accessible to other proposals.
  trampas:
    - "The cancel pathway is 'by design' — the safeguard bypass is the non-obvious consequence"
    - "Chaining two proposals (one to create state, one to exploit it) is common pattern — test for it"
    - "Acknowledged as known issue by PartyDAO but still exploitable — 'known issue' != 'safe'"
  confianza: alta
  verificado: true
  tags: [governance, multi-step, proposal-cancel, majority-attack, safeguard-bypass]
  solodit_ids: [3306, 3307, 3304]
  incidentes:
    - protocol: "PartyDAO"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Majority bypasses ArbitraryCallsProposal safeguards via cancel of in-progress proposal"
      slug: "h-05-arbitrarycallsproposal-and-listopenseaproposal-safeguards-bypassed-by-cancelling-in-progress-proposal-code4rena-party-party-contest-git"
    - protocol: "PartyDAO"
      firm: "Code4rena"
      impact: "HIGH"
      title: "51% majority steals precious NFT by chaining two proposals with fractionalization"
      slug: "h-06-a-majority-attack-can-steal-precious-nft-from-the-party-by-crafting-and-chaining-two-proposals-code4rena-party-party-contest-git"
    - protocol: "PartyDAO"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Majority bypasses Zora auction stage in OpenseaProposal and steals NFT"
      slug: "h-03-a-majority-attack-can-easily-bypass-zora-auction-stage-in-openseaproposal-and-steal-the-nft-code4rena-party-party-contest-git"
```

---

## 5. Cross-Chain Governance

```yaml
- id: gov-011
  pattern: onlygovernance-uncallable-satellite-chains
  name: "onlyGovernance functions permanently uncallable on satellite chains"
  severity: medium
  causa_raiz: >
    OZ Governor.execute() sets a flag (_governanceCall flag) that onlyGovernance reads.
    On the hub chain, execute() routes through Governor → TimelockController, and the
    flag is set correctly. On satellite chains, execution goes directly through
    TimelockController.execute() — bypassing Governor.execute() entirely. The flag is
    never set, so onlyGovernance reverts on all satellite calls. Any function with
    this modifier is permanently uncallable on satellite chains.
  como_funciona: |
    1. Protocol deploys Governor on hub, TimelockController on satellites
    2. Function f() has onlyGovernance modifier (relies on OZ internal _governanceCall)
    3. Hub: governance.execute() → timelock.execute() → f() ✓ (flag set)
    4. Satellite: timelock.execute() → f() ✗ (flag NOT set — OZ Governor never called)
    5. All governance updates to satellite-specific parameters permanently blocked
    6. Protocol can never update fees, roles, or config on satellite chains
  invariante: >
    Any function callable via governance on hub must also be callable via governance
    on satellite chains. onlyGovernance must not rely on OZ internal call routing.
  que_mirar:
    - "Does the protocol have onlyGovernance functions on satellite/L2 deployments?"
    - "Is there a Governor contract on each chain or only TimelockController?"
    - "grep: onlyGovernance, _governanceCall, SummerTimelockController, satellite"
    - "grep: Governor::execute vs TimelockController::execute"
  como_se_arregla: >
    Replace onlyGovernance with onlyTimelock (check msg.sender == timelockController)
    on satellite chains. Or deploy a minimal Governor on each satellite that routes
    through execute() correctly. Or use a cross-chain messaging solution (LayerZero/CCIP)
    to relay governance calls from hub to satellites.
  trampas:
    - "Works perfectly on the hub — only satellite deployments are broken"
    - "onlyGovernance is an OZ internal modifier that most devs treat as 'timelock only' — it's not"
  confianza: alta
  verificado: true
  tags: [cross-chain, governance, satellite, onlyGovernance, timelock]
  solodit_ids: [63466]
  incidentes:
    - protocol: "Summer.fi Governance V2"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Satellite chains can't execute onlyGovernance functions — permanently blocked"
      slug: "m-4-satellite-chains-cant-execute-onlygovernance-functions-sherlock-none-summer-fi-governance-v2-git"
```

---

## Quick Grep Targets — Governance Audits

```bash
# Flash loan + voting
grep -rn "getPastVotes\|getPriorVotes\|_getVotes\|castVote" src/
grep -rn "delegate\|ERC20Votes\|_checkpoints\|_delegate" src/
grep -rn "flashLoan\|flashCallback\|IERC3156" src/   # check if same block as vote

# Proposal lifecycle
grep -rn "proposalsCreated\|proposalsPassed\|userCommunityScoreData" src/
grep -rn "queue\|proposalState\|InProgress\|_cancelProposal" src/
grep -rn "proposalThreshold\|getPastTotalSupply\|block\.timestamp.*supply" src/

# Timelock
grep -rn "timelockDeadline\|recoverTimelock\|lastResortTimelock" src/
grep -rn "schedule\|execute\|TIMELOCK_ADMIN_ROLE\|TimelockController" src/
grep -rn "require.*block\.timestamp.*deadline\|require.*deadline.*block" src/

# Veto / guardian
grep -rn "setVetoer\|vetoer\|onlyVetoer\|burnVetoer\|_vetoer" src/
grep -rn "require.*newVetoer.*address(0)\|newVetoer != address" src/

# Cross-chain governance
grep -rn "onlyGovernance\|_governanceCall\|Governor::execute" src/
grep -rn "satellite\|hubChain\|crossChainGovernance" src/

# Vote accounting
grep -rn "lockedWhileVotesCast\|activeProposals\|getActiveProposals" src/
grep -rn "gasRefund\|REFUND_BASE_GAS\|_refundGas" src/
```

---

## Fuzzing Priorities

```
Priority 1 — Flash Loan Vote Bypass:
  Invariant: votes used in block N must come from snapshot at block N-1 or earlier
  How: in one tx — borrow tokens, delegate, castVote, repay. Check: did vote count?

Priority 2 — Proposal Counter Accounting:
  Invariant: after queue(id), proposalsPassed[proposer] == pre + 1; proposalsCreated unchanged
  How: unit test queue() → check both counters. Also test veto() decrements correctly.

Priority 3 — Timelock Deadline Enforcement:
  Invariant: execute(id) must revert if block.timestamp < queueTime[id] + DELAY
  How: queue proposal, immediately call execute() — must revert. Warp to deadline-1 — must revert.

Priority 4 — Delegate Trap:
  Invariant: delegatee can always unstake within VOTING_PERIOD + 1 blocks
  How: delegate → vote on max proposals → try unstake at each point. Should succeed eventually.

Priority 5 — Zero-Vote Gas Drain:
  Invariant: castVote() with 0 votes must not trigger gas refund
  How: call castVote from address with 0 tokens. Check vault balance before/after.
```
