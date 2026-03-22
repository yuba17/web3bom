# OP Stack Bridge Vulnerabilities — Combat Briefing

> Attack surface: withdrawal flow (OptimismPortal → CrossDomainMessenger), fault proof system
> (FaultDisputeGame, PreimageOracle, Cannon), gas accounting, sequencer trust, and Superchain
> interop. Relevant for Coinbase Base, Optimism Mainnet, Mantle, MorphL2, and any OP-fork.
> Sources: verified Solodit findings from Sherlock/Spearbit/Code4rena/OpenZeppelin audits.

---

## 1. Withdrawal Flow — OptimismPortal & CrossDomainMessenger

```yaml
- id: ops-001
  pattern: safecall-insufficient-gas-buffer
  name: "SafeCall.callWithMinGas does not reserve buffer for post-call continuation"
  severity: high
  causa_raiz: >
    callWithMinGas ensures the callee gets _minGas, but does NOT ensure enough gas
    remains in the caller after the call returns. If the remaining gas after
    L1CrossDomainMessenger calls the target is insufficient to write the success/failure
    marker, the withdrawal is marked neither successful nor failed — it is permanently
    bricked with no replay path.
  como_funciona: |
    1. User calls finalizeWithdrawalTransaction() expecting L1CDM replayability
    2. OptimismPortal calls L1CDM with a carefully chosen gas amount
    3. L1CDM calls the target — the call itself succeeds, consumes most gas
    4. On return, L1CDM lacks gas to write failedMessages[msgHash]=true
    5. Transaction reverts at the portal level — successfulMessages is also not set
    6. User can never retry: the withdrawal is bricked without entering failedMessages
  invariante: >
    For any withdrawal w: after finalizeWithdrawalTransaction(w) completes,
    either successfulMessages[hash(w)] == true OR failedMessages[hash(w)] == true.
    The "neither" state must be unreachable.
  que_mirar:
    - "Does OptimismPortal reserve a gas buffer AFTER the L1CDM call returns?"
    - "Is there a 5k-gas buffer between what OptimismPortal forwards and what L1CDM forwards?"
    - "Can a user craft _minGasLimit such that remaining gas post-call < storage write cost?"
    - "grep: callWithMinGas, RELAY_GAS_REQUIRED, RELAY_RESERVED_GAS"
    - "grep: successfulMessages, failedMessages, relayMessage"
  como_se_arregla: >
    Reserve at least 5_000 gas after the external call returns. The check should be:
    gasleft() >= RELAY_GAS_REQUIRED at each return point in relayMessage.
    Reference: Optimism PR #5352 (adds RELAY_RESERVED_GAS = 40_000).
  trampas:
    - "callWithMinGas guarantees the CALLEE gets gas — it says nothing about the CALLER's residual"
    - "The revert at portal level looks like a random OOG — easy to miss in traces"
    - "Normal users trigger this accidentally with low _minGasLimit; attackers can force it"
  confianza: alta
  verificado: true
  tags: [optimism-portal, cross-domain-messenger, gas, withdrawal, stuck-funds]
  solodit_ids: [18555]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      finder: "obront"
      title: "CrossDomainMessenger does not guarantee replayability, can lose user funds"
      slug: "m-1-crossdomainmessenger-does-not-successfully-guarantee-replayability-can-lose-user-funds-sherlock-none-optimism-update-git"

- id: ops-002
  pattern: revert-instead-of-return-bricks-replayability
  name: "revert opcode in gas-check path prevents failedMessages write — withdrawal stuck"
  severity: high
  causa_raiz: >
    L1CrossDomainMessenger uses `revert` instead of `return` when the gas condition fails.
    A `revert` bubbles up to OptimismPortal and reverts the entire transaction including
    the failedMessages write. `return` (with a false return value) would let the caller
    write the failure marker and preserve replayability.
  como_funciona: |
    1. Relayer calls finalizeWithdrawalTransaction() with just enough gas to pass
       the portal's gas check (callWithMinGas), but not enough for L1CDM
    2. L1CDM checks remaining gas: condition fails → executes revert
    3. The entire outer transaction reverts — OptimismPortal never marks withdrawal done
    4. Withdrawal is re-provable but the window has closed, or countdown resets
    5. Funds appear permanently bricked from the user's perspective
  invariante: >
    If L1CDM.relayMessage() fails the gas check, it MUST emit xDomainMessageFailed and
    write failedMessages[msgHash]=true before returning. It must NOT revert.
  que_mirar:
    - "Is the gas check in relayMessage a revert or a conditional return/emit?"
    - "grep: hasMinGas, gasleft(), RELAY_CALL_OVERHEAD, revert in relayMessage"
    - "Can an attacker force the gas-check branch to trigger via exact gas griefing?"
    - "Is there a try-catch around the external call to target?"
  como_se_arregla: >
    Replace `revert` with early return after emitting FailedRelayedMessage and writing
    failedMessages[msgHash]=true. The check must use `return` not `revert`.
  trampas:
    - "Very similar to ops-001 but different code path — one is the gas-forward gap, the other is revert vs return"
    - "OP forks that modify gas accounting often reintroduce this (Mantle, MorphL2)"
  confianza: alta
  verificado: true
  tags: [cross-domain-messenger, gas, revert, withdrawal, replayability]
  solodit_ids: [18558]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      finder: "HE1M"
      title: "Usage of revert in case of low gas in L1CrossDomainMessenger results in loss of funds"
      slug: "m-4-usage-of-revert-in-case-of-low-gas-in-l1crossdomainmessenger-can-result-in-loss-of-fund-sherlock-none-optimism-update-git"

- id: ops-003
  pattern: challenger-deletes-finalized-output
  name: "Challenger can delete L2 output older than finalization period — confirmed withdrawals re-stuck"
  severity: medium
  causa_raiz: >
    L2OutputOracle.deleteL2Outputs() has no lower bound on which output index can be deleted.
    A challenger (or governance) can delete an output root that is already past the 7-day
    finalization window, invalidating withdrawals that users had already treated as confirmed.
  como_funciona: |
    1. Proposer submits L2 output at index N for block B
    2. User proves withdrawal against output N and waits 7 days
    3. After 7 days, user expects to be able to finalize
    4. Challenger calls deleteL2Outputs(N) — deletes output N (no time check)
    5. finalizeWithdrawalTransaction() reverts: provenWithdrawals[hash].l2OutputIndex == N
       but that output no longer exists
    6. User must re-prove against new output root, resetting the 7-day clock
  invariante: >
    No output root older than FINALIZATION_PERIOD_SECONDS can be deleted.
    Formally: block.timestamp - L2OutputOracle.getL2Output(index).timestamp >= FINALIZATION_PERIOD_SECONDS
    → deleteL2Outputs(index) must revert.
  que_mirar:
    - "Does deleteL2Outputs check timestamp against finalizationPeriodSeconds?"
    - "Can the challenger role be compromised (multisig, EOA, governance)?"
    - "grep: deleteL2Outputs, FINALIZATION_PERIOD_SECONDS, l2Outputs"
    - "Is reproving guaranteed to succeed? Can the reprove window close?"
  como_se_arregla: >
    Add: require(l2Outputs[_l2OutputIndex].timestamp + FINALIZATION_PERIOD_SECONDS > block.timestamp,
    "Cannot delete finalized output"). Fixed in Optimism mainnet after this audit.
  trampas:
    - "Challenger role is 'trusted' in many deployments but still a valid attack surface for OP forks"
    - "Forks that copy L2OutputOracle without patching this are vulnerable"
  confianza: alta
  verificado: true
  tags: [l2-output-oracle, challenger, withdrawal, finalization-period]
  solodit_ids: [6506]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Challenger can override the 7-day finalization period"
      slug: "m-10-challenger-can-override-the-7-day-finalization-period-sherlock-optimism-optimism-git"

- id: ops-004
  pattern: output-root-reproposal-reprove-window-closes
  name: "Withdrawal stuck if output root reproposed and reprove window closes before user can act"
  severity: medium
  causa_raiz: >
    When a proven withdrawal's output root is challenged and a new root is proposed for the
    same L2 block, the user must re-prove against the new root. But reproval is only
    allowed against the SAME L2 block number. If proposals for that block are no longer
    available or the reprove window closes, the withdrawal is permanently unclaimable.
  como_funciona: |
    1. User proves withdrawal at output index N (block B)
    2. Output N is challenged and deleted by the challenger
    3. New output M is proposed for the same block B
    4. User must re-prove using output M — but the FINALIZATION_PERIOD restarts
    5. If block B is no longer covered by any current output, user cannot reprove
    6. Withdrawal bricked permanently
  invariante: >
    If provenWithdrawals[hash].l2OutputIndex is deleted, the user must always have
    a reprove path. The protocol must guarantee at least one valid output covers
    the proven block at any time after deletion.
  que_mirar:
    - "Is there a check that exactly one output root covers each L2 block at all times?"
    - "Can an output for a specific block be deleted and never reproposed?"
    - "Does the reproving logic enforce same-block-number only?"
    - "grep: proveWithdrawalTransaction, provenWithdrawals, l2OutputIndex"
  como_se_arregla: >
    Guarantee that deleted outputs are always reproposed before deletion is allowed.
    Or allow re-proving against any valid output for any block >= the original proven block.
  trampas:
    - "The attack is subtle — user must act quickly between deletion and re-proposal"
    - "In practice, the window can be very short on high-throughput L2s"
  confianza: media
  verificado: true
  tags: [withdrawal-proof, l2-output-oracle, reprove, stuck-funds]
  solodit_ids: [6509]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Withdrawal transactions can get stuck if output root is reproposed"
      slug: "m-13-withdrawal-transactions-can-get-stuck-if-output-root-is-reproposed-sherlock-optimism-optimism-git"

- id: ops-005
  pattern: l2cdm-pause-blocks-l1-deposits-no-replay
  name: "L2CrossDomainMessenger pause makes L1→L2 deposits unexecutable and non-replayable"
  severity: medium
  causa_raiz: >
    L1CrossDomainMessenger.sendMessage() can be called even when L2CDM is paused,
    because the pause modifier is only on L2CDM.relayMessage(). Deposits sent while
    L2CDM is paused will fail on L2 — but because L2CDM is paused, no retry info is
    saved. The deposited ETH is minted to the aliased L2CDM address and permanently lost.
  como_funciona: |
    1. Admin pauses L2CrossDomainMessenger (emergency, e.g. exploit detected)
    2. User calls L1CDM.sendMessage() (not paused) — sends ETH to L2
    3. L2 auto-deposit goes through L2CDM.relayMessage() — reverts due to pause
    4. No retry info written (failedMessages not set — pause causes revert before write)
    5. ETH minted to aliased L2CDM address — no withdrawal path from there
  invariante: >
    When L2CDM is paused, L1CDM.sendMessage() must revert or emit a warning.
    No ETH should be depositable to a paused L2CDM.
  que_mirar:
    - "Does L1CDM.sendMessage() check L2CDM pause state before accepting deposits?"
    - "If L2CDM.relayMessage() reverts (paused), does it still write failedMessages?"
    - "Where does the minted ETH go if relayMessage reverts on L2?"
    - "grep: paused, whenNotPaused, relayMessage, aliasedAddress"
  como_se_arregla: >
    L1CDM should check L2CDM pause state before accepting sendMessage calls.
    Alternatively, ensure L2CDM.relayMessage() writes failedMessages BEFORE the pause check
    so deposits can be replayed after unpause.
  trampas:
    - "ETH minted to aliased address is a permanent loss — there is no recovery path"
    - "OP forks that add custom pause logic without updating both sides are especially vulnerable"
  confianza: alta
  verificado: true
  tags: [cross-domain-messenger, pause, deposit, stuck-funds, l1-l2]
  solodit_ids: [6508]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Deposits from L1 to L2 using L1CrossDomainMessenger will fail and will not be replayable when L2CDM is paused"
      slug: "m-12-deposits-from-l1-to-l2-using-l1crossdomainmessenger-will-fail-and-will-not-be-replayable-when-l2crossdomainmessenger-is-paused-sherlock-optimism-optimism-git"

- id: ops-006
  pattern: portal-gas-overhead-underestimation
  name: "OptimismPortal forwards 5k less gas than intended — calls fail for integrators"
  severity: medium
  causa_raiz: >
    L1CrossDomainMessenger adds a 5k gas buffer when computing baseGas for a message.
    OptimismPortal forwards messages using a slightly different formula that does NOT add
    the same 5k buffer. Every forwarded call has ~5k less gas than the sender intended.
    Integrators (bridges, protocols) must overpay to avoid OOG, and some will silently fail.
  como_funciona: |
    1. Bridge protocol sends message via L1CDM with _minGasLimit = X
    2. L1CDM computes baseGas(X) — adds 5k buffer → actual forward = X+5k
    3. BUT if message comes through OptimismPortal directly, the 5k buffer is missing
    4. Target receives X-overhead gas instead of X
    5. Call OOGs for any target that needs exactly X gas
  invariante: >
    actualGasForwardedToTarget >= _minGasLimit - EPSILON for any relay path.
  que_mirar:
    - "Compare gas computation in OptimismPortal vs CrossDomainMessenger baseGas()"
    - "Is there an explicit buffer added in the portal relay path?"
    - "grep: baseGas, RELAY_GAS_REQUIRED, minimumGasLimit, _minGasLimit"
    - "Do OP fork versions preserve the 5k buffer in their portal implementations?"
  como_se_arregla: >
    Add explicit 5_000 gas buffer to OptimismPortal's gas forwarding calculation
    to match L1CDM's baseGas() formula. Or consolidate gas calculation in one place.
  trampas:
    - "Fails silently — caller sees success, target OOGs"
    - "Most integrators pad gas by default, hiding the bug until a tight-gas scenario"
  confianza: alta
  verificado: true
  tags: [optimism-portal, gas, overhead, integration]
  solodit_ids: [6504]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      finder: "GalloDaSballo"
      title: "Optimism Portal can run out of gas due to incorrect overhead estimation"
      slug: "m-8-optimism-portal-can-run-out-of-gas-due-to-incorrect-overhead-estimation-sherlock-optimism-optimism-git"

- id: ops-007
  pattern: target-permissioned-via-portal
  name: "Withdrawal target set to permissioned contract — portal delivers unauthorized call"
  severity: high
  causa_raiz: >
    OptimismPortal.finalizeWithdrawalTransaction() calls any _tx.target with any _tx.data.
    If a protocol has permissioned functions that trust msg.sender == OptimismPortal
    or msg.sender == L2CrossDomainMessenger alias, an attacker on L2 can craft a withdrawal
    targeting those functions with malicious calldata.
  como_funciona: |
    1. Protocol deploys a privileged contract C that checks: require(msg.sender == PORTAL)
    2. Attacker on L2 calls L2ToL1MessagePasser.initiateWithdrawal(target=C, data=maliciousCalldata)
    3. After 7 days, anyone calls finalizeWithdrawalTransaction() — portal calls C
    4. C.execute(maliciousCalldata) runs with the bridge's authority
    5. Example (Blast): target = ethYieldManager — attacker bricks withdrawal queue and
       steals claim IDs by calling requestWithdrawal/claimWithdrawal via portal
  invariante: >
    No contract should grant special permissions to the portal address alone.
    Callers through the bridge must be authenticated at the MESSAGE level, not the
    sender-address level. Otherwise any L2 user can impersonate the protocol.
  que_mirar:
    - "Are there contracts that check msg.sender == OptimismPortal or msg.sender == L1CDM?"
    - "Does the protocol's L1 side have permissioned functions callable from L2 withdrawal?"
    - "grep: require(msg.sender == portal), onlyBridge, address(optimismPortal)"
    - "Is there a blacklist of _tx.target addresses that the portal refuses to call?"
  como_se_arregla: >
    Gate permissioned functions on the L2 message sender (xDomainMessageSender())
    in addition to msg.sender. Or maintain an explicit target blacklist in OptimismPortal
    for protocol-owned privileged contracts on L1.
  trampas:
    - "This is an integration bug, not a portal bug — each protocol must audit their L1 contracts"
    - "Portal blacklists (like Blast's ethYieldManager fix) are protocol-specific, not universal"
    - "OP Stack documentation explicitly warns against trusting msg.sender alone"
  confianza: alta
  verificado: true
  tags: [optimism-portal, access-control, withdrawal, integration, l2-to-l1]
  solodit_ids: [29878]
  incidentes:
    - protocol: "Blast"
      firm: "Spearbit"
      impact: "CRITICAL"
      title: "Message can be passed through OptimismPortal to maliciously call ethYieldManager"
      detail: "Attacker crafts L2 withdrawal targeting ethYieldManager.requestWithdrawal/claimWithdrawal via portal, bricks all pending finalized Lido requests and caps the withdrawal queue"
      slug: "message-can-be-passed-through-optimismportal-to-maliciously-call-ethyieldmanager-spearbit-none-base-fault-proofs-no-mips-pdf"
```

---

## 2. FaultDisputeGame — Clock & Step Logic

```yaml
- id: ops-008
  pattern: step-callable-after-parent-resolved
  name: "FaultDisputeGame.step() callable after parentClaim already resolved — counteredBy overwritten"
  severity: low-medium
  causa_raiz: >
    The step() function does not check whether the parent subgame has already been resolved
    (resolvedSubgames[parentIndex] == true). An attacker can call step() after the chess clock
    has expired and the parent has been resolved as uncountered. The call succeeds, writes
    counteredBy = msg.sender, but produces no effect — the payout already happened.
    In adversarial setups this could allow subtle state corruption if logic is extended.
  como_funciona: |
    1. FaultDisputeGame runs — clock expires for a claim at parentIndex
    2. resolveClaim(parentIndex) executes — resolvedSubgames[parentIndex] = true
    3. Attacker calls step(parentIndex, ...) with a valid MIPS instruction proof
    4. step() succeeds — sets parent.counteredBy = attacker
    5. No funds move (payout done), but state is inconsistent: claim resolved as uncountered
       AND counteredBy is set to a non-zero address
  invariante: >
    step(claimIndex) must revert if resolvedSubgames[claimIndex] == true.
    Formally: resolvedSubgames[i] == true → any call to step(i, ...) must revert.
  que_mirar:
    - "Does step() check resolvedSubgames[parentIndex] before executing?"
    - "Can step() be called in the same block as resolveClaim()?"
    - "grep: resolvedSubgames, step, counteredBy, resolveClaim"
    - "Does the OP fork add any payout logic inside step() that would be affected?"
  como_se_arregla: >
    Add at start of step(): if (resolvedSubgames[_claimIndex]) revert ParentAlreadyResolved();
  trampas:
    - "Low severity on mainnet OP because no funds move — but Critical in forks that extend step() with payout logic"
    - "Stateful fuzzers (Medusa) can find this — call step() after resolveClaim() in same sequence"
  confianza: alta
  verificado: true
  tags: [fault-dispute-game, step, clock, state-corruption]
  solodit_ids: [36768]
  incidentes:
    - protocol: "Base Fault Proofs"
      firm: "Spearbit"
      impact: "LOW"
      title: "FaultDisputeGame.step function can be called after parentClaim is resolved"
      slug: "faultdisputegamestep-function-can-be-called-after-parentclaim-is-resolved-spearbit-none-base-fault-proofs-no-mips-pdf"

- id: ops-009
  pattern: clock-extension-exceeds-max-duration
  name: "CLOCK_EXTENSION doubled at split depth can push game beyond MAX_CLOCK_DURATION"
  severity: low-medium
  causa_raiz: >
    The FaultDisputeGame constructor validates: clockExtension <= maxClockDuration.
    But when granting clock extensions at the execution trace bisection root (SPLIT_DEPTH-1),
    the code grants 2 * CLOCK_EXTENSION. With clockExtension near maxClockDuration / 2,
    the doubled extension exceeds maxClockDuration and the game can run far beyond 7 days.
    The invariant that no game exceeds MAX_CLOCK_DURATION is violated.
  como_funciona: |
    1. Deploy FaultDisputeGame with clockExtension = 3.5 days, maxClockDuration = 7 days
    2. Constructor check passes: 3.5 <= 7 ✓
    3. During game, a claim reaches depth SPLIT_DEPTH - 1
    4. Code grants: extensionPeriod = CLOCK_EXTENSION * 2 = 7 days
    5. nextDuration = MAX_CLOCK_DURATION - extensionPeriod = 7 - 7 = 0
       OR the clock wraps and the extension exceeds 7 days
    6. Dispute game runs beyond the protocol's finalization window
  invariante: >
    For all claim depths d: clock granted at d <= MAX_CLOCK_DURATION.
    Specifically: if d == SPLIT_DEPTH - 1, then 2 * CLOCK_EXTENSION <= MAX_CLOCK_DURATION.
    Constructor must validate: 2 * clockExtension <= maxClockDuration.
  que_mirar:
    - "Does constructor validate clockExtension * 2 <= maxClockDuration (not just 1x)?"
    - "Is CLOCK_EXTENSION doubled anywhere in the clock grant logic?"
    - "grep: CLOCK_EXTENSION, extensionPeriod, SPLIT_DEPTH, clockExtension.raw() * 2"
    - "What is the configured ratio of CLOCK_EXTENSION to MAX_CLOCK_DURATION?"
  como_se_arregla: >
    Change constructor validation to: if (_clockExtension.raw() * 2 > _maxClockDuration.raw()) revert
    OR cap extensionPeriod: extensionPeriod = min(CLOCK_EXTENSION * 2, MAX_CLOCK_DURATION).
  trampas:
    - "The bug is in the CONSTRUCTOR validation, not the runtime — most auditors miss it"
    - "Only triggerable at exactly SPLIT_DEPTH - 1, so Foundry unit tests may miss it"
    - "OP forks with custom CLOCK_EXTENSION values are especially vulnerable"
  confianza: alta
  verificado: true
  tags: [fault-dispute-game, clock-extension, max-clock-duration, constructor]
  solodit_ids: [36773, 36633]
  incidentes:
    - protocol: "Base Fault Proofs"
      firm: "Spearbit"
      impact: "LOW"
      title: "_clockExtension and _maxClockDuration not validated correctly for doubled extension"
      slug: "clockextension-and-_maxclockduration-are-not-validated-correctly-in-disputegame-constructor-spearbit-none-base-fault-proofs-no-mips-pdf"
    - protocol: "Optimism"
      firm: "Code4rena"
      impact: "LOW"
      title: "CLOCK_EXTENSION feature can be abused to extend dispute game above 7 days"
      slug: "20-fdg-the-new-clock_extension-feature-can-be-abused-to-extend-the-dispute-game-above-7-days-code4rena-optimism-optimism-git"
```

---

## 3. PreimageOracle / Cannon — Proof System

```yaml
- id: ops-010
  pattern: preimage-oog-overwrites-correct-part
  name: "OOG in precompile call overwrites correct preimageParts with error result"
  severity: medium
  causa_raiz: >
    PreimageOracle.loadPrecompilePreimagePart() calls an arbitrary precompile with _input.
    If the precompile runs out of gas, it returns an error instead of the correct result.
    The function does NOT check whether the precompile succeeded — it stores whatever
    was returned (the error bytes) at the key. A subsequent call with the correct gas
    correctly computes the result, but the first (wrong) write has already claimed the slot.
    Because the key is based on keccak(precompile, input, partOffset), the correct value
    can never overwrite the slot.
  como_funciona: |
    1. Challenger calls loadPrecompilePreimagePart(precompile, input, offset) with low gas
    2. Precompile call OOGs — returns error bytes
    3. Function stores error_bytes at preimageParts[keccak(precompile||input||offset)]
    4. preimageParts[key] is now set (mapping write done — cannot be undone)
    5. Subsequent call with correct gas: stores correct_result at same key — BUT
       the contract may check "already set" and skip, or the first write wins
    6. Dispute game uses the corrupted preimage — incorrect MIPS execution proof
  invariante: >
    preimageParts[key] must only be set if the precompile call returned status == success.
    OOG or revert precompile calls must not write to preimageParts.
  que_mirar:
    - "Does loadPrecompilePreimagePart check precompile call success before storing?"
    - "Is there a CALL return value check or a staticcall with success bool?"
    - "grep: loadPrecompilePreimagePart, preimageParts, precompilePart, _precompile"
    - "Is the key space (partOffset, precompile, input) collision-resistant?"
  como_se_arregla: >
    After calling the precompile, check the success bool:
    (bool success, bytes memory result) = _precompile.staticcall{gas: _gasLimit}(_input);
    require(success, "PrecompileCallFailed");
    Then store result. Never store error bytes.
  trampas:
    - "Identified by Alexis Williams from Coinbase — Coinbase Base is the primary deployment"
    - "This corrupts the Cannon dispute game — severity is Critical if it blocks valid fault proofs"
    - "OP forks adding new precompiles (e.g. BLS, KZG) are especially vulnerable"
  confianza: alta
  verificado: true
  tags: [preimage-oracle, cannon, precompile, oog, fault-proof]
  solodit_ids: [36764]
  incidentes:
    - protocol: "Base Fault Proofs"
      firm: "Spearbit / Coinbase"
      impact: "MEDIUM"
      title: "PreimageOracle.loadPrecompilePreimagePart: OOG overwrites correct preimageParts"
      detail: "Identified by Alexis Williams (Coinbase) during Spearbit engagement"
      slug: "preimageoracleloadprecompilepreimagepart-an-outofgas-error-in-the-precompile-will-overwrite-cor-spearbit-none-base-fault-proofs-no-mips-pdf"

- id: ops-011
  pattern: lpp-proposal-double-initialization
  name: "Large Preimage Proposal (LPP) can be initialized multiple times — bond overwritten, funds lost"
  severity: low-medium
  causa_raiz: >
    PreimageOracle.initLPP() does not check whether a proposal with the same UUID
    already exists. If called twice with the same (_uuid, claimedSize), the proposalBonds
    mapping is ASSIGNED (not incremented) to msg.value. The original bond is lost —
    no storage is freed, the first bond is trapped forever with no withdrawal path.
  como_funciona: |
    1. Alice calls initLPP(uuid=42, claimedSize=1000) with 1 ETH bond
    2. proposalBonds[alice][42] = 1 ETH
    3. Metadata written to proposalMetadata[alice][42]
    4. Attacker (or Alice) calls initLPP(uuid=42, claimedSize=1000) again with 0.001 ETH
    5. proposalBonds[alice][42] = 0.001 ETH — original 1 ETH lost with no recovery
    6. Proposal proceeds with wrong bond, bond invariant broken
  invariante: >
    initLPP(uuid) must revert if proposalMetadata[msg.sender][uuid].claimedSize() != 0.
    Each (address, uuid) pair must be initialized at most once.
  que_mirar:
    - "Does initLPP check metaData.claimedSize() != 0 before writing?"
    - "Is the bond stored with += or = ?"
    - "grep: initLPP, proposalBonds, proposalMetadata, _uuid"
    - "Can the same uuid be re-used by the same address across multiple dispute games?"
  como_se_arregla: >
    Add at start of initLPP():
    if (proposalMetadata[msg.sender][_uuid].claimedSize() != 0) revert ProposalAlreadyExists();
  trampas:
    - "Low severity if proposer loses their own bond — but the bond mechanism is critical for Cannon security"
    - "OP Stack mainnet acknowledged and deferred fix"
  confianza: alta
  verificado: true
  tags: [preimage-oracle, lpp, cannon, bond, double-init]
  solodit_ids: [36772]
  incidentes:
    - protocol: "Base Fault Proofs"
      firm: "Spearbit"
      impact: "LOW"
      title: "Preimage proposals can be initialized multiple times — bond lost"
      slug: "preimage-proposals-can-be-initialized-multiple-times-spearbit-none-base-fault-proofs-no-mips-pdf"

- id: ops-012
  pattern: withdrawal-proof-index-bit-size-missing-check
  name: "Missing bit-size check on historySummaryIndex allows forged withdrawal proofs"
  severity: critical
  causa_raiz: >
    BeaconChainProofs.verifyWithdrawal() (and similar OP-adjacent withdrawal verifiers)
    uses a historySummaryIndex to select which historical Merkle tree to verify against.
    If the index is not validated to fit within the number of bits allocated in the Merkle
    proof (e.g., must fit in 5 bits for 2^5 = 32 leaves), an oversized index causes the
    proof to traverse into a sibling subtree. The verifier accepts the proof as valid even
    though it proves membership in the wrong tree — allowing withdrawal forgery.
  como_funciona: |
    1. EigenPod (or analogous OP bridge) calls verifyWithdrawal(historySummaryIndex, proof)
    2. historySummaryIndex = 32 (requires 6 bits, tree has 5-bit depth)
    3. Proof is crafted for a leaf in an ADJACENT subtree
    4. verifyWithdrawal walks the Merkle path using oversized index — lands in wrong subtree
    5. Proof passes — withdrawal credited without a real beacon-chain withdrawal
    6. Attacker drains bridge escrow
  invariante: >
    require(historySummaryIndex < 2**HISTORY_SUMMARY_PROOF_LENGTH,
            "Index exceeds Merkle tree capacity").
    For any verifyWithdrawal call, the index must fit in the expected bit width.
  que_mirar:
    - "Is historySummaryIndex (or analogous index) validated to fit within proof depth?"
    - "Does the Merkle proof verifier assume index < 2^depth?"
    - "grep: historySummaryIndex, HISTORY_SUMMARY_PROOF_LENGTH, verifyWithdrawal"
    - "Are there similar indices (validatorIndex, slotIndex) with the same pattern?"
  como_se_arregla: >
    Before using the index in Merkle proof verification:
    require(_historySummaryIndex < 2**HISTORY_SUMMARY_PROOF_LENGTH, "InvalidIndex");
    Apply the same check to ALL index parameters in all proof functions.
  trampas:
    - "Pattern generalizes: ANY Merkle proof verifier with integer indices is susceptible"
    - "Apply this check to OP Stack's withdrawal proof verifiers for any fork using Merkle inclusion"
    - "Severity is Critical when escrow funds are on the line"
  confianza: alta
  verificado: true
  tags: [merkle-proof, withdrawal-proof, index-validation, cannon, beacon-chain]
  solodit_ids: [53493]
  incidentes:
    - protocol: "EigenLayer"
      firm: "Hexens"
      impact: "CRITICAL"
      title: "[EIG-10] Withdrawal proofs can be forged due to missing index bit size check"
      slug: "eig-10-withdrawal-proofs-can-be-forged-due-to-missing-index-bit-size-check-hexens-none-eigenlayer-markdown"
```

---

## 4. Proof Verification — RLP & Storage Proofs

```yaml
- id: ops-013
  pattern: rlp-fixed-prefix-leading-zeros-fail
  name: "Fixed RLP prefix fails proof verification when value has leading zeros"
  severity: high
  causa_raiz: >
    Contracts that manually RLP-encode values for Merkle proof verification use fixed-length
    prefixes (e.g., 0xa0 for 32-byte values, 0x94 for 20-byte addresses). RLP is a
    length-prefix encoding — the prefix encodes the ACTUAL byte length. A value with
    leading zeros (e.g., an address starting with 0x00…) is shorter than 32/20 bytes in
    RLP canonical form. The fixed prefix is wrong, the proof fails, and the user's funds
    are permanently stuck.
  como_funciona: |
    1. User claims reward; their address = 0x0000...1234 (leading zeros)
    2. Prover contract calls proveStorage(abi.encodePacked(messageMappingSlot),
       bytes.concat(hex"94", bytes20(claimant)), l2StorageProof, l2StateRoot)
    3. hex"94" prefix assumes 20-byte address — but RLP canonical form of 0x0000...1234
       may omit leading zeros (e.g., encode as 18 bytes with prefix hex"92")
    4. Proof verification fails: encoded key doesn't match trie node
    5. User can never claim; funds permanently inaccessible
  invariante: >
    RLP encoding of any address or bytes32 value must use canonical length.
    For any value v: rlpEncode(v).length must equal 1 + len(v.stripLeadingZeros()).
  que_mirar:
    - "Is RLP encoding done with fixed prefixes (hex'94', hex'a0') or dynamically computed?"
    - "Does the contract handle addresses or hashes with leading zeros differently?"
    - "grep: hex\"94\", hex\"a0\", abi.encodePacked, proveStorage, SecureMerkleTrie"
    - "Are there tests with zero-padded addresses (e.g., 0x000000000000000000000000000000000000dead)?"
  como_se_arregla: >
    Use a proper RLP library that computes canonical length:
    bytes memory encoded = RLPWriter.writeBytes(abi.encodePacked(value));
    Never hardcode prefix bytes when encoding variable-length values.
  trampas:
    - "Works fine in testing with normal addresses; only breaks for the ~1/65536 users with leading zeros"
    - "Pattern appears in OP-adjacent bridges that implement custom MPT/RLP verification"
  confianza: alta
  verificado: true
  tags: [rlp-encoding, merkle-proof, storage-proof, leading-zeros, claim]
  solodit_ids: [46226]
  incidentes:
    - protocol: "Eco Inc"
      firm: "Unknown"
      impact: "HIGH"
      title: "Invalid RLP encoding causes proof verification failures for values with leading zeros"
      slug: "invalid-rlp-encoding-causes-proof-verification-failures-for-values-with-leading-zeros-eco-inc"

- id: ops-014
  pattern: cannon-storage-proof-bypass
  name: "Anyone can bypass faultDisputeGameIsResolved() storage proofs — drain escrowed funds"
  severity: critical
  causa_raiz: >
    proveWorldStateCannon() calls faultDisputeGameIsResolved() to check that the dispute
    game has resolved correctly before releasing escrow funds. The check uses
    SecureMerkleTrie.verifyInclusionProof(key, value, proof, root). An attacker can
    craft a Merkle proof that passes verification by controlling BOTH the proof bytes
    AND the root argument — if the root comes from user-supplied storage rather than
    a trusted source, the attacker proves membership in a fake tree.
  como_funciona: |
    1. Protocol stores "proven world state" in provenStates[chainId]
    2. proveWorldStateCannon() uses provenStates[chainId].storageRoot as the MPT root
    3. Attacker calls proveWorldStateCannon() with a crafted storageRoot and matching proof
    4. verifyInclusionProof passes — fake tree, fake proof, both attacker-controlled
    5. faultDisputeGameIsResolved() returns true for an unresolved or invalid game
    6. Attacker calls proveIntent() → escrow funds released to attacker
  invariante: >
    The storageRoot used in verifyInclusionProof must come from a trustworthy source
    (e.g., proven against L1 block hash, not from user input or settable storage).
  que_mirar:
    - "Is the storageRoot in verifyInclusionProof user-supplied or externally trusted?"
    - "Does proveWorldStateCannon() verify the storageRoot against an L1 block hash?"
    - "grep: verifyInclusionProof, faultDisputeGameIsResolved, proveWorldStateCannon, provenStates"
    - "Can provenStates[chainId].storageRoot be set by any caller?"
  como_se_arregla: >
    Validate storageRoot against a trusted L1 block hash obtained from an oracle.
    The proof root must be pinned to: keccak256(abi.encode(trustedL1BlockHash)).
    Never accept root as a parameter that could be user-controlled.
  trampas:
    - "The MPT verifier itself is correct — the bug is in how the ROOT is obtained"
    - "Applies to any cross-chain intent protocol that verifies OP Stack dispute game state"
  confianza: alta
  verificado: true
  tags: [storage-proof, merkle-proof, dispute-game, escrow, cannon, bypass]
  solodit_ids: [46225]
  incidentes:
    - protocol: "Eco Inc"
      firm: "Unknown"
      impact: "HIGH"
      title: "Anyone can bypass faultDisputeGameIsResolved() storage proofs to drain escrowed funds"
      slug: "anyone-can-bypass-faultdisputegameisresolved-storage-proofs-to-drain-protocol-escrowed-funds-for-cannon-specific-chains-eco-inc"

- id: ops-015
  pattern: proven-block-number-griefing
  name: "provenStates[chainId].blockNumber set to type(uint256).max — prevents all future proving"
  severity: high
  causa_raiz: >
    proveWorldStateCannon() updates provenStates[chainId].blockNumber to the proven block.
    The function accepts any blockNumber in the proof — it does not validate that the new
    block is greater than the current stored value, or that it matches the actual L1 state.
    An attacker calls proveWorldStateCannon() with blockNumber = type(uint256).max,
    setting the stored value to max. All future calls fail because no real block can exceed
    type(uint256).max, and the protocol requires blockNumber > stored value.
  como_funciona: |
    1. Protocol requires provenStates[chainId].blockNumber <= newBlock for valid proof
    2. Attacker calls proveWorldStateCannon(chainId, proof_with_blockNumber=MAX_UINT256)
    3. provenStates[chainId].blockNumber = MAX_UINT256
    4. All future proveWorldStateCannon() calls fail: newBlock < MAX_UINT256 always
    5. All solvers on chainId permanently unable to claim rewards
    6. All escrowed funds on chainId permanently locked
  invariante: >
    provenStates[chainId].blockNumber must only be set if the new value comes from
    a cryptographically verified L1 block. It must never exceed the current L1 block number.
  que_mirar:
    - "Is blockNumber in proveWorldStateCannon() validated against actual L1 block?"
    - "Is there a maximum blockNumber check (e.g., require(newBlock <= block.number))?"
    - "grep: provenStates, blockNumber, proveWorldStateCannon"
    - "Can any user call proveWorldStateCannon() with arbitrary proof parameters?"
  como_se_arregla: >
    Validate blockNumber against a trusted L1 oracle: require(_blockNumber <= block.number).
    Or gate proveWorldStateCannon() behind a whitelist of authorized solvers.
  trampas:
    - "Permanent DoS — no recovery path once set to MAX_UINT256"
    - "Different from ops-014: here the attack is DoS, not fund theft"
    - "Both ops-014 and ops-015 can be combined: first DoS the legit prover, then steal funds"
  confianza: alta
  verificado: true
  tags: [storage-proof, dos, griefing, proven-block, cannon, cross-chain]
  solodit_ids: [46224]
  incidentes:
    - protocol: "Eco Inc"
      firm: "Unknown"
      impact: "HIGH"
      title: "Anyone can set provenStates[chainId].blockNumber to MAX_UINT256 — prevents proving"
      slug: "anyone-can-arbitrarily-set-provenstateschainidblockNumber-in-proveworldstatecannon-to-prevent-proving-of-all-intents-eco-inc"
```

---

## 5. Sequencer — Gas Accounting & Trust

```yaml
- id: ops-016
  pattern: sequencer-l1-data-fee-underpricing
  name: "commitScalar miscalculation in GasPriceOracle — sequencer pays up to 100x more than collected"
  severity: high
  causa_raiz: >
    GasPriceOracle.sol computes l1DataFee (paid by users) using commitScalar to estimate
    the cost of calldata posted to L1 via commitBatch(). If commitScalar does not correctly
    account for all calldata overhead (batch metadata, encoding, signature overhead), the
    fee charged to users is substantially less than the real L1 cost borne by the sequencer.
    In blobspace scenarios (EIP-4844), blob header costs are often omitted entirely.
  como_funciona: |
    1. User submits L2 transaction — l1DataFee computed as: basefee * scalar * txDataLength
    2. Sequencer batches transactions and posts to L1 via commitBatch()
    3. Actual L1 cost: includes blob basefee, calldata overhead, commitBatch() function overhead
    4. commitScalar only accounts for raw txData bytes — misses ~50-200x overhead multiplier
    5. If most tx value comes from L1 cost (e.g., simple ETH transfers), sequencer loses money
    6. With heavy L2 traffic, sequencer net loss can be 100x per batch
  invariante: >
    l1DataFeeCharged(tx) >= actualL1CostAttributable(tx) - EPSILON.
    GasPriceOracle must include ALL commitBatch() calldata overhead in fee calculation.
  que_mirar:
    - "Does commitScalar account for blob basefee? blob header cost? ABI encoding overhead?"
    - "Is the scalar calibrated against current L1 gas market?"
    - "grep: commitScalar, l1DataFee, l1BaseFee, blobBaseFee, GasPriceOracle"
    - "Compare fee formula to actual commitBatch() calldata cost in recent txs (Etherscan)"
  como_se_arregla: >
    Audit the full commitBatch() calldata structure and include ALL overhead in the
    scalar computation. For EIP-4844 deployments, add separate blobBaseFee * blobScalar term.
    Formula should match: fee_per_byte * totalL1Bytes where totalL1Bytes includes metadata.
  trampas:
    - "The bug is in the OFF-CHAIN scalar calculation, not the on-chain formula"
    - "Exploitable by anyone — just use the L2 cheaply and let sequencer subsidize your txs"
    - "OP Stack forks must recalibrate commitScalar for their specific L1/L2 gas ratio"
  confianza: alta
  verificado: true
  tags: [sequencer, gas-price-oracle, l1-data-fee, commit-scalar, eip-4844]
  solodit_ids: [41872]
  incidentes:
    - protocol: "MorphL2"
      firm: "Sherlock"
      impact: "HIGH"
      finder: "PapaPitufo"
      title: "Sequencer underpaid because of incorrect commitScalar"
      slug: "h-3-sequencer-will-be-underpaid-because-of-incorrect-commitscalar-sherlock-morphl2-git"

- id: ops-017
  pattern: sequencer-dos-proposal-inflation
  name: "Malicious sequencer inflates governance proposals — DoS all future proposal execution"
  severity: medium
  causa_raiz: >
    Gov.sol._executeProposal() iterates from undeletedProposalStart to current proposal
    to prune all unexecuted previous proposals. There is no limit on proposals that can
    be created. A malicious sequencer creates millions of proposals, and _executeProposal()
    runs out of gas on the pruning loop, making it impossible to execute any proposal.
    Governance is permanently bricked.
  como_funciona: |
    1. Governance requires sequential proposal execution (old proposals pruned first)
    2. Malicious sequencer calls createProposal() millions of times (low cost)
    3. legitimate_proposal_id = N; undeletedProposalStart = 1
    4. _executeProposal(N) loops from 1 to N-1 — pruning loop OOGs at i=~2000
    5. Transaction reverts — no proposal can ever execute
    6. Protocol parameters permanently frozen; upgrades impossible
  invariante: >
    _executeProposal() must complete within block gas limit for any valid state.
    Either: cap on max proposal count, OR O(1) pruning (track executed bitmap, no loop).
  que_mirar:
    - "Does _executeProposal() iterate over unbounded proposal history?"
    - "Is there a maximum proposals-per-epoch limit enforced on-chain?"
    - "grep: undeletedProposalStart, _executeProposal, createProposal, pruning loop"
    - "Is createProposal() callable by anyone or only the sequencer?"
  como_se_arregla: >
    Cap max proposals to a bounded window (e.g., 1000 per epoch).
    Or replace the pruning loop with a bitmap: track executed[id] = true in O(1).
    Or implement lazy pruning: advance undeletedProposalStart only when accessed.
  trampas:
    - "Only works if proposal creation is cheap and rate-limited by the sequencer alone"
    - "OP Stack mainnet uses a different governance model — most relevant for OP forks with on-chain Gov"
  confianza: alta
  verificado: true
  tags: [sequencer, governance, dos, proposal-inflation, gas-loop]
  solodit_ids: [41882]
  incidentes:
    - protocol: "MorphL2"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Malicious sequencer can DoS proposal execution by inflating the amount of proposals"
      slug: "m-10-malicious-sequencer-can-dos-proposal-execution-by-inflating-the-amount-of-proposals-to-be-pruned-sherlock-morphl2-git"
```

---

## 6. Superchain Interop — SharedLockbox & Pause

```yaml
- id: ops-018
  pattern: interop-before-shared-lockbox-withdrawal-bricked
  name: "Interop enabled before SharedLockbox migration — more ETH withdrawable than escrowed"
  severity: medium
  causa_raiz: >
    Enabling Superchain interop on an L2 chain allows ETH to bridge IN from peer chains,
    increasing the L2 ETH supply. But the L1 OptimismPortal still only holds the ETH
    originally deposited into THAT chain. If users then withdraw the interop-bridged ETH,
    the portal can run out of ETH before all withdrawals are satisfied.
    The fix (SharedLockbox, which pools ETH across all portals) must be deployed BEFORE
    enabling interop — but the upgrade sequence allows these to be decoupled.
  como_funciona: |
    1. Chain A enables interop (L2 upgrade)
    2. 1000 ETH bridged from Chain B to Chain A via interop
    3. Chain A's L1 OptimismPortal holds only the original 500 ETH
    4. Users withdraw the interop ETH via Chain A's portal
    5. Portal runs out: 500 + partial 500 ETH withdrawable, remaining bricked
    6. SharedLockbox (pooling 500+500=1000 ETH) was not deployed first
  invariante: >
    At any time: sum(ETH in L1 portals for chain set) >= sum(ETH withdrawable by L2 users).
    If interop is enabled, SharedLockbox must be deployed first.
  que_mirar:
    - "Is there an upgrade guard that prevents interop enable before SharedLockbox deployment?"
    - "Does the upgrade sequence enforce SharedLockbox first in the transaction ordering?"
    - "grep: SharedLockbox, interop, ETH_LOCKBOX, enableInterop, optimismPortal.balance"
    - "What happens to withdrawal finalization if portal ETH balance < withdrawal amount?"
  como_se_arregla: >
    Add an on-chain precondition in the interop-enable upgrade tx:
    require(address(sharedLockbox) != address(0), "SharedLockbox must be deployed first").
    Or make the two upgrades atomic (single multicall tx).
  trampas:
    - "The bug is in UPGRADE SEQUENCING — hard to catch in code review without understanding the ops process"
    - "Affects any Superchain member that enables interop independently"
  confianza: alta
  verificado: true
  tags: [superchain, interop, shared-lockbox, withdrawal, upgrade-sequence]
  solodit_ids: [50078]
  incidentes:
    - protocol: "Optimism Interop"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "Withdrawals could be bricked if chain enabled interop before migrating to SharedLockbox"
      slug: "withdrawals-could-be-bricked-if-chain-enabled-interop-before-migrating-to-the-sharedlockbox-spearbit-none-optimism-pdf"

- id: ops-019
  pattern: superchain-config-pause-identifier-mismatch
  name: "SystemConfig.paused() uses wrong identifier when ETH_LOCKBOX feature toggles — accidental unpause"
  severity: low
  causa_raiz: >
    SystemConfig.paused() determines the chain identifier for the SuperchainConfig pause check
    based on whether ETH_LOCKBOX feature is enabled: if enabled, use ethLockbox address;
    otherwise, use optimismPortal address. If a chain transitions between these two states
    (feature flag toggled), the identifier changes. Any existing pause registered under the
    OLD identifier is silently ignored — the chain appears unpaused while the emergency is live.
  como_funciona: |
    1. Security council pauses chain using identifier = address(optimismPortal)
    2. Admin enables ETH_LOCKBOX feature (separate upgrade tx)
    3. SystemConfig.paused() now checks superchainConfig.paused(address(ethLockbox))
    4. The pause was registered under optimismPortal, not ethLockbox
    5. paused() returns false — chain appears live during an active emergency
    6. Users can transact normally; protocol is not actually paused
  invariante: >
    If superchainConfig.paused(identifier) was set to true, all subsequent calls to
    SystemConfig.paused() must return true until explicitly unpaused.
    Identifier changes must not silently invalidate existing pauses.
  que_mirar:
    - "Is the pause identifier stable across feature flag changes?"
    - "What happens to existing pause entries if ETH_LOCKBOX is enabled post-pause?"
    - "grep: isFeatureEnabled, ETH_LOCKBOX, paused, superchainConfig.paused, identifier"
    - "Is there a migration step that moves the pause entry to the new identifier?"
  como_se_arregla: >
    When enabling ETH_LOCKBOX, if the old identifier is paused, re-register the pause
    under the new identifier atomically in the same upgrade transaction. Or maintain a
    list of valid identifiers and check all of them in paused().
  trampas:
    - "Low severity in isolation — but catastrophic if a chain is silently unpaused during a live exploit"
    - "The window is short but real: between feature enable and manual re-pause"
  confianza: alta
  verificado: true
  tags: [superchain-config, pause, feature-flag, eth-lockbox, upgrade]
  solodit_ids: [62712]
  incidentes:
    - protocol: "Optimism U16"
      firm: "Spearbit"
      impact: "LOW"
      title: "Chain can be accidentally unpaused when changing the ETH_LOCKBOX feature"
      slug: "chain-can-be-accidentally-unpaused-when-changing-the-eth_lockbox-feature-spearbit-none-optimism-pdf"
```

---

## Quick Grep Targets — OP Stack Audits

```bash
# Withdrawal flow
grep -rn "callWithMinGas\|RELAY_GAS_REQUIRED\|RELAY_RESERVED_GAS" src/
grep -rn "successfulMessages\|failedMessages\|relayMessage" src/
grep -rn "finalizeWithdrawalTransaction\|proveWithdrawalTransaction" src/
grep -rn "deleteL2Outputs\|FINALIZATION_PERIOD\|l2Outputs\[" src/

# Fault proof / dispute game
grep -rn "resolvedSubgames\|counteredBy\|step(" src/
grep -rn "CLOCK_EXTENSION\|MAX_CLOCK_DURATION\|extensionPeriod\|clockExtension.raw\(\)" src/
grep -rn "SPLIT_DEPTH\|clockExtension.raw() \* 2" src/

# PreimageOracle / Cannon
grep -rn "loadPrecompilePreimagePart\|preimageParts\|initLPP\|proposalBonds" src/
grep -rn "verifyInclusionProof\|SecureMerkleTrie\|proveStorage\|proveWorldStateCannon" src/

# RLP / Merkle proofs
grep -rn 'hex"94"\|hex"a0"\|hex"80"' src/   # Fixed RLP prefixes
grep -rn "historySummaryIndex\|validatorIndex\|HISTORY_SUMMARY_PROOF" src/

# Sequencer / gas
grep -rn "commitScalar\|l1DataFee\|blobBaseFee\|GasPriceOracle" src/
grep -rn "undeletedProposalStart\|_executeProposal\|createProposal" src/

# Superchain / interop
grep -rn "SharedLockbox\|ETH_LOCKBOX\|isFeatureEnabled\|superchainConfig.paused" src/
grep -rn "enableInterop\|respectedGameType\|disputeGameBlacklist" src/
```

---

## Fuzzing Priorities

```
Priority 1 — Withdrawal Gas Invariants:
  Invariant: after finalizeWithdrawalTransaction(), successfulMessages[h] XOR failedMessages[h] == true
  How: fuzz _tx.gasLimit from 0 to 10M; check state after each finalize attempt

Priority 2 — Clock Arithmetic:
  Invariant: no dispute game runs longer than MAX_CLOCK_DURATION
  How: symbolic test — deploy FDG with clockExtension = maxClockDuration/2 - 1;
       advance to SPLIT_DEPTH - 1; verify total time <= MAX_CLOCK_DURATION

Priority 3 — PreimageOracle Idempotency:
  Invariant: preimageParts[key] != 0 after first load → second load with same key is no-op
  How: call loadPrecompilePreimagePart twice — second call must revert or produce same value

Priority 4 — Sequencer Fee Coverage:
  Invariant: l1DataFeeCharged(tx) >= estimatedL1Cost(tx) * 0.9
  How: replay real txs from Etherscan; compare charged fee vs actual batch calldata cost

Priority 5 — Storage Proof Root Manipulation:
  Invariant: proveWorldStateCannon(chainId, proof) cannot succeed with forged storageRoot
  How: fuzz storageRoot argument; any call with arbitrary root must revert
```
