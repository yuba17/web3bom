# Cross-Chain Bridge Vulnerabilities -- Combat Briefing

> Attack surface: message passing, token custody, finality assumptions, dispute resolution.
> Sources: invariant-registry/bridge/message_integrity.json, invariant-registry/bridge/dispute_games.json

---

## 1. Message Replay

```yaml
- id: bridge-001
  pattern: message-replay-double-finalize
  name: "Message replay -- same message processed twice"
  causa_raiz: "Missing or bypassable replay protection. The successfulMessages mapping is not checked, reset via proxy upgrade, or the message hash is not unique."
  como_funciona: |
    1. User initiates legitimate withdrawal on L2
    2. Message relayed and finalized on L1
    3. Attacker replays the same finalization tx (or a re-proved variant)
    4. Funds disbursed a second time
  invariante: "for all withdrawal w: finalize(w) succeeds at most once (INV-BRIDGE-005)"
  que_mirar:
    - "successfulMessages[hash] checked BEFORE execution, not after"
    - "Hash includes nonce, sender, target, value, data -- all fields"
    - "Proxy upgrade path cannot reset the finalization mapping"
    - "No alternate entry point that skips the replay guard"
  como_se_arregla: "Set successfulMessages[hash] = true before external call. Include monotonic nonce in hash preimage."
  trampas:
    - "Replay on a different chain pair is not a replay bug -- it is a message forgery bug"
    - "Failed messages that become retryable are not replays"
  incidentes:
    - "Harpie -- changeRecipientAddress signature lacks chain.id; attacker replays on target chain via Wintermute-style address creation (MEDIUM)"
    - "Stakehouse Protocol -- deployLPToken uses Clones.clone with no chain.id validation; cross-chain replay steals LP funds (MEDIUM)"
    - "Tenbin -- Redeem validates payer nonce but records usage as signer nonce; when payer != signer the payer nonce is never consumed, enabling endless replay (HIGH)"
    - "Barter DAO -- Protocol uses user token balance as nonce; once balance recovers from any source, same order re-executable within deadline (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-BRIDGE-005 (BASE-007)"
  verificado: true
  tags: [replay, withdrawal, finalization, nonce]
  relacionado_con: [bridge-007]
```

## 2. Message Forgery

```yaml
- id: bridge-002
  pattern: message-forgery-unauthorized-mint
  name: "Message forgery -- fake message without token lock"
  causa_raiz: "Insufficient sender validation on destination chain. crosschainMint callable by addresses other than the authorized bridge."
  como_funciona: |
    1. Attacker calls crosschainMint directly (bypassing bridge)
    2. Or attacker spoofs msg.sender via delegatecall/CREATE2 address collision
    3. Tokens minted on destination without any lock on source
    4. Total cross-chain supply inflated
  invariante: "crosschainMint(to, amount) reverts if msg.sender != L2_STANDARD_BRIDGE (INV-BRIDGE-012)"
  que_mirar:
    - "Access control on crosschainMint and crosschainBurn"
    - "Is the bridge address hardcoded or settable? If settable, who can change it?"
    - "Proxy delegatecall paths that could impersonate the bridge"
    - "CREATE2 address collision feasibility for the bridge address"
    - "relayMessage sender validation -- does it verify the cross-domain origin?"
  como_se_arregla: "Hardcode bridge address as immutable. Validate msg.sender == BRIDGE in modifier. Verify xDomainMessageSender on the messenger."
  trampas:
    - "If bridge address is a predeploy (e.g., 0x4200...), collision is infeasible -- not a real finding"
    - "Admin-settable bridge address may be intentional if behind timelock"
  incidentes:
    - "Derby -- XProvider onlySource checks against trustedRemoteConnext[_origin] but does not verify it != address(0); Connext slow path delivers address(0), allowing attacker to disrupt all vault state (HIGH)"
    - "Connext -- GnosisBase _verifySender checks msg.sender and messageSender but not messageSourceChainId; same mirrorConnector on future chain can spoof roots (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-BRIDGE-012, INV-BRIDGE-013 (BASE-056, BASE-057)"
  verificado: true
  tags: [forgery, access-control, mint, burn, authorization]
  relacionado_con: [bridge-005]
```

## 3. Validator/Relayer Collusion

```yaml
- id: bridge-003
  pattern: validator-relayer-collusion
  name: "Validator/relayer collusion to forge or censor messages"
  causa_raiz: "Trust concentrated in a small validator set or single relayer. No on-chain fraud proof or dispute mechanism to challenge false attestations."
  como_funciona: |
    1. Colluding validators sign a fraudulent message (e.g., fake deposit event)
    2. Relayer submits the message to destination chain
    3. Bridge accepts it because threshold signatures are met
    4. Funds released without corresponding lock on source
  invariante: "Only messages backed by verifiable source-chain state can trigger fund release"
  que_mirar:
    - "Multisig threshold vs total validator count (2-of-3 is weak)"
    - "Can a single entity control enough validators?"
    - "Is there a dispute/challenge window after relay?"
    - "Does the bridge verify state proofs or just signatures?"
    - "Relayer key management -- HSM, rotation policy?"
  como_se_arregla: "Use state proofs (Merkle/storage proofs) instead of or in addition to signatures. Add dispute windows. Require economic bonds from validators."
  trampas:
    - "Trusted relayer/validator is often explicitly out of scope in bounties"
    - "If the bounty says 'assume validators are honest', skip this"
  severidad: critical
  confianza: media
  fuente: "General bridge security model"
  verificado: false
  tags: [collusion, validator, relayer, trust-assumption, multisig]
  relacionado_con: [bridge-009]
```

## 4. Race Condition Between Lock and Mint

```yaml
- id: bridge-004
  pattern: lock-mint-race-condition
  name: "Race condition between lock on source and mint on destination"
  causa_raiz: "Asynchronous cross-chain messaging creates a window where source lock is confirmed but destination mint has not executed. Reorg on source can reverse the lock."
  como_funciona: |
    1. User locks tokens on source chain (tx included in block N)
    2. Relayer/sequencer observes lock, initiates mint on destination
    3. Source chain reorgs, block N replaced -- lock tx dropped
    4. Mint on destination already executed -- tokens created from nothing
  invariante: "sum(totalSupply[token][chain]) + inTransit[token] == trackedSupply[token] (INV-BRIDGE-009)"
  que_mirar:
    - "How many confirmations before relay? (1 confirmation = high reorg risk)"
    - "Does the bridge wait for source finality?"
    - "Is there a clawback mechanism on destination if source reverts?"
    - "L1-to-L2 deposits: are they force-included? (INV-BRIDGE-004)"
  como_se_arregla: "Wait for source chain finality before minting. Use optimistic relay with dispute window. Implement clawback for unfinalized messages."
  trampas:
    - "On L2 rollups, L1 deposits are guaranteed by the rollup -- not vulnerable to this"
    - "PoS chains with single-slot finality have minimal window"
  incidentes:
    - "Tigris Trade -- GovNFT.crossChain burns NFT on source, LZ endpoint fails on destination with low gas; same tokenId NFT exists on two chains simultaneously (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-BRIDGE-009 (BASE-049, BASE-050)"
  verificado: true
  tags: [race-condition, finality, reorg, lock-mint, supply-conservation]
  relacionado_con: [bridge-008]
```

## 5. Token Mapping Inconsistency

```yaml
- id: bridge-005
  pattern: token-mapping-mismatch
  name: "Token mapping inconsistency -- wrong token minted on destination"
  causa_raiz: "Token address mapping between chains is incorrect, stale, or manipulable. Attacker bridges worthless token but receives valuable token on destination."
  como_funciona: |
    1. Bridge maintains mapping: sourceToken => destinationToken
    2. Attacker deploys a token on source that maps to a high-value destination token
    3. Or: admin updates mapping incorrectly, creating arbitrage window
    4. Attacker locks worthless tokens, receives valuable tokens
  invariante: "relayERC20 increases destination totalSupply by exact amount for the correct token (INV-BRIDGE-010)"
  que_mirar:
    - "Is token mapping permissioned or permissionless?"
    - "Can mapping be updated after deployment? By whom?"
    - "Does the bridge verify token metadata (decimals, symbol) cross-chain?"
    - "Fee-on-transfer tokens: does amount received match amount credited? (INV-BRIDGE-011)"
    - "Decimal mismatch between source (6 decimals) and destination (18 decimals)"
  como_se_arregla: "Derive destination token address deterministically from source address. Validate token properties on both sides. Freeze mappings after initial setup."
  trampas:
    - "Canonical bridges with factory-deployed representations are generally safe"
    - "Custom token lists are admin-controlled -- often out of scope"
  severidad: critical
  confianza: alta
  fuente: "INV-BRIDGE-010, INV-BRIDGE-011 (BASE-053, BASE-054)"
  verificado: true
  tags: [token-mapping, decimals, fee-on-transfer, supply-integrity]
  relacionado_con: [bridge-002]
```

## 6. Failed Message Recovery Exploits

```yaml
- id: bridge-006
  pattern: failed-message-recovery-exploit
  name: "Failed message recovery exploits"
  causa_raiz: "Messages that fail on first relay are stored for retry. The retry path has weaker validation, or failed state can be manipulated to enable unauthorized recovery."
  como_funciona: |
    1. Attacker sends a message designed to fail on first relay (e.g., low gas)
    2. Message marked as failed: failedMessages[hash] = true
    3. Attacker exploits retry mechanism: changes parameters, replays with different recipient, or front-runs legitimate retry
    4. Funds routed to attacker instead of original sender
  invariante: "relayMessage with gas < required => failedMessages[hash] == true && successfulMessages[hash] == false (INV-BRIDGE-003)"
  que_mirar:
    - "Can anyone retry a failed message, or only the original sender?"
    - "Are retry parameters (recipient, amount) immutable from the original message?"
    - "Is the gas check accurate? EIP-150 1/64th rule edge cases (INV-BRIDGE-007, INV-BRIDGE-008)"
    - "Can a message be intentionally failed to grief the recipient?"
    - "Does retry clear the failed flag atomically with setting success flag?"
  como_se_arregla: "Lock all message parameters at initiation time. Only allow retry of exact original message. Ensure gas checks account for EIP-150."
  trampas:
    - "Messages that fail due to target contract reverting are expected behavior"
    - "Dust stuck from gas refund differences is not exploitable"
  incidentes:
    - "Toki Bridge -- revertReceive[chainId][sequence] collapses all IBC channels sharing same counterpartyChainId; two channels with same sequence overwrite each other, older user permanently unable to retry (MEDIUM)"
    - "Recall -- IPC bridge sends receipt on Transfer message failure but refund calls performCall on EOA which fails; EOA users' funds permanently trapped in gateway (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "INV-BRIDGE-001, INV-BRIDGE-002, INV-BRIDGE-003, INV-BRIDGE-007, INV-BRIDGE-008 (BASE-001 through BASE-036)"
  verificado: true
  tags: [retry, failed-message, gas-griefing, EIP-150, recovery]
  relacionado_con: [bridge-001, bridge-007]
```

## 7. Nonce Reordering/Skipping

```yaml
- id: bridge-007
  pattern: nonce-reorder-skip
  name: "Nonce reordering or skipping"
  causa_raiz: "Bridge uses sequential nonces but does not enforce ordering on destination, or enforces ordering and allows a skipped nonce to permanently block subsequent messages."
  como_funciona: |
    1. Messages sent with nonces N, N+1, N+2
    2. Relayer submits N+2 before N (reordering)
    3. If bridge enforces order: N+1 and N+2 blocked until N arrives (DoS)
    4. If bridge does not enforce order: nonce gap allows replay of skipped message later in unexpected context
  invariante: "Each nonce processed exactly once. No message permanently blocked by a skipped predecessor."
  que_mirar:
    - "Is nonce sequential or content-addressed (hash-based)?"
    - "Does the bridge enforce in-order processing?"
    - "Can a skipped nonce permanently block the queue?"
    - "Is there a timeout/bypass for stuck nonces?"
    - "Can the relayer selectively censor messages by withholding specific nonces?"
  como_se_arregla: "Use hash-based message IDs instead of sequential nonces. If sequential, implement skip-after-timeout. Separate nonce per sender."
  trampas:
    - "Out-of-order processing is often intentional for performance"
    - "L2 sequencer ordering is a separate trust assumption"
  severidad: high
  confianza: media
  fuente: "INV-BRIDGE-005 (nonce component of replay protection)"
  verificado: true
  tags: [nonce, ordering, DoS, censorship, sequencing]
  relacionado_con: [bridge-001, bridge-006]
```

## 8. Finality Assumption Violations

```yaml
- id: bridge-008
  pattern: finality-assumption-violation
  name: "Finality assumption violations -- reorg on source chain"
  causa_raiz: "Bridge accepts messages before source chain achieves economic or cryptographic finality. A deep reorg on source reverses the deposit but the destination mint is irreversible."
  como_funciona: |
    1. Bridge configured to relay after K confirmations
    2. Source chain experiences reorg deeper than K blocks
    3. Deposit transaction that was relayed is now reverted on source
    4. Minted tokens on destination have no backing
  invariante: "L1-to-L2 deposit transactions must always succeed on L2 (INV-BRIDGE-004)"
  que_mirar:
    - "Confirmation count vs chain's finality guarantee"
    - "Does the bridge distinguish between safe/finalized block tags?"
    - "Optimistic rollup: is withdrawal finalization gated by dispute period?"
    - "Does the bridge handle uncle/ommer blocks correctly?"
    - "Proof maturity delay: is it long enough? (INV-BRIDGE-006)"
  como_se_arregla: "Wait for finalized block tag (PoS) or sufficient confirmations (PoW). Gate withdrawals behind dispute period. Use state proofs anchored to finalized state."
  trampas:
    - "Ethereum PoS finalizes every ~13 minutes -- reorg beyond that requires 1/3 stake slashing"
    - "L1->L2 deposits on optimistic rollups are force-included and safe"
    - "Testnet reorgs do not reflect mainnet finality"
  incidentes:
    - "Uniswap -- NonlinearDutchDecayLib uses block.number which returns approximate L1 block on Arbitrum (12s blocks) instead of L2 block (0.25s blocks); orders that should decay in seconds take minutes (MEDIUM)"
    - "Renzo -- xRenzoBridge encodes L1 block.timestamp compared against L2 block.timestamp; Arbitrum timestamps up to 24h earlier cause valid price updates to be rejected as future timestamps (MEDIUM)"
    - "Optimism -- ResourceMetering.prevBoughtGas resets per block; attacker fills MAX_RESOURCE_LIMIT in same block, causing victim tx to revert at ~$10 cost per block (MEDIUM)"
    - "Optimism -- depositTransaction allows gasLimit=0; zero-gas deposits bypass resource metering and allow cheap ETH bridging without L2 gas cost (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-BRIDGE-004, INV-BRIDGE-006 (BASE-005, BASE-008)"
  verificado: true
  tags: [finality, reorg, confirmations, dispute-period, optimistic-rollup]
  relacionado_con: [bridge-004, bridge-009]
```

## 9. Dispute Game Resolution Manipulation

```yaml
- id: bridge-009
  pattern: dispute-game-manipulation
  name: "Dispute game resolution manipulation"
  causa_raiz: "Fault dispute games determine withdrawal validity in optimistic rollups. Manipulation of the game (clock, bonds, claim tree) can force incorrect resolution, enabling fraudulent withdrawals or blocking legitimate ones."
  como_funciona: |
    1. Attacker creates dispute game with fraudulent root claim
    2. Exploits game mechanics: lets clock expire on honest challenger, submits deep claim tree exceeding gas limits, or manipulates bond economics
    3. Game resolves DEFENDER_WINS (fraudulent claim accepted)
    4. Attacker finalizes withdrawal against the fraudulent state root
  invariante: |
    - After resolution: address(game).balance == 0 (INV-DISP-001, INV-DISP-006)
    - Creator locks exactly rootBond (INV-DISP-002, INV-DISP-007)
    - Defender wins => creator gets full bond back (INV-DISP-003, INV-DISP-008)
    - Challenger wins => creator loses bond (INV-DISP-004, INV-DISP-009)
    - All claims resolvable (INV-DISP-005, INV-DISP-010)
  que_mirar:
    - "Can the claim tree be made so deep that resolveClaim runs out of gas?"
    - "Clock management: can attacker force challenger's clock to expire?"
    - "Bond economics: is the cost of attack less than the profit from fraud?"
    - "Can bonds get stuck in the contract after resolution? (zero balance invariant)"
    - "Can excess ETH be sent when creating a game, getting trapped? (exact bond invariant)"
    - "Multi-party disputes: is bond distributed to the correct challenger?"
    - "Can resolution be front-run to flip the outcome?"
    - "SuperFaultDisputeGame: does it have the same properties as FaultDisputeGame?"
    - "Reentrancy during claim payout causing partial distribution"
    - "Circular claim dependencies blocking resolution"
  como_se_arregla: "Bound claim tree depth. Ensure all claims resolvable within block gas limit. Make attack cost exceed potential profit. Implement guardian override for emergency."
  trampas:
    - "Rounding dust left in contract after resolution may not be exploitable"
    - "Guardian/admin ability to blacklist games is usually by design"
    - "Bond amounts are governance-set -- 'too low' is a parameter issue, not a code bug"
  severidad: critical
  confianza: alta
  fuente: "INV-DISP-001 through INV-DISP-010 (BASE-009 through BASE-018)"
  verificado: true
  tags: [dispute-game, fault-proof, bonds, resolution, optimistic-rollup, FaultDisputeGame, SuperFaultDisputeGame]
  relacionado_con: [bridge-008]

- id: bridge-010
  pattern: cross-chain-channel-blocking-gas
  name: "Cross-chain channel/message blocking via gas or payload manipulation"
  severidad: high
  causa_raiz: >
    LayerZero, IBC, and similar ordered-message bridges enforce sequential processing.
    If one message cannot be delivered (gas exceeds destination block limit, payload
    too large to store on revert, or receiver reverts without try-catch), the entire
    channel is permanently blocked. Attacker crafts a single poisoned message to freeze
    all subsequent cross-chain traffic.
  como_funciona: |
    1. Attacker identifies bridge using ordered message channel (LayerZero NonblockingLzApp, IBC ordered channel)
    2. Attacker crafts message with one or more of:
       a. Oversized payload (e.g., excessively large _toAddress bytes) that exceeds destination block gas limit
       b. gasLimit set higher than destination chain's block gas limit
       c. Payload that consumes max allowed gas in receiver then fails, leaving insufficient gas for on-chain retry storage
    3. Message sent from source chain (succeeds due to higher gas limit, e.g., Arbitrum -> Optimism)
    4. On destination: message cannot be processed, retry mechanism also fails
    5. All subsequent messages on that channel are blocked (ordered delivery requirement)
  invariante: >
    For any cross-chain message m: if m fails on destination, the channel must remain
    unblocked for subsequent messages. No single message should permanently halt the channel.
  que_mirar:
    - "Does bridge use ordered message delivery (LayerZero blocking mode, IBC ordered channels)?"
    - "Is there a max payload size enforced ON-CHAIN (not just off-chain API)?"
    - "Is _toAddress or other user-supplied bytes unbounded in the LZ send path?"
    - "Can user set gasLimit exceeding destination chain block gas limit?"
    - "Does NonblockingLzApp try-catch handle ALL possible failure modes including OOG?"
    - "On IBC: if receiver reverts and retry storage needs >remaining gas, does tx revert entirely?"
    - "grep: excessivelySafeCall, _blockingLzReceive, nonblockingLzReceive, failedMessages"
    - "grep: lzReceive, _storeFailedMessage, retryMessage"
  como_se_arregla: >
    Enforce max payload size on-chain. Cap user-supplied gasLimit to destination block gas limit.
    Use nonblocking patterns with guaranteed-succeed fallback (store hash only, not full payload).
    Reserve gas for failure handling before calling receiver. Migrate to unordered channels.
  trampas:
    - "NonblockingLzApp pattern is meant to fix this, but if the nonblocking wrapper itself OOGs, it reverts to blocking"
    - "Different chains have vastly different block gas limits (Arbitrum ~32M, Optimism ~20M)"
  fuente: "Solodit / Code4rena, Sherlock, Shieldify, Halborn findings"
  confianza: alta
  verificado: true
  tags: [layerzero, channel-blocking, DoS, gas-limit, payload-size, ordered-delivery]
  relacionado_con: [bridge-006, bridge-007]
  incidentes:
    - protocol: "Tapioca DAO"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Attacker can block LayerZero channel due to variable gas cost of saving payload"
      detail: "BaseUSDO/BaseTOFT send LZ messages with unbounded payload; attacker sends with max payload size, nonblocking wrapper OOGs on store, channel permanently blocked"
    - protocol: "UXD Protocol"
      firm: "Sherlock"
      impact: "HIGH"
      title: "Excessively large _toAddress breaks LayerZero communication"
      detail: "OFTCore#sendFrom accepts arbitrary-length _toAddress bytes; Arbitrum->Optimism with huge _toAddress exceeds Optimism block gas limit, bypasses nonblocking pattern"
    - protocol: "Holograph"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Attacker locks operator out of pod by setting gas limit higher than dest block gas limit"
      detail: "No limit on user-set gasLimit; attacker sets >dest block gas limit; operator cannot execute job, loses bond"
    - protocol: "Toki Bridge"
      firm: "Shieldify"
      impact: "MEDIUM"
      title: "DoS via large payload storage exhaustion on IBC ordered channel"
      detail: "10KB payload + 5M gas receiver call; on revert, storing 10KB needs 6.4M gas exceeding remainder; IBC ordered channel blocks all subsequent transfers"
    - protocol: "LucidLabs (Contracts V1)"
      firm: "Halborn"
      impact: "MEDIUM"
      title: "Unhandled exceptions in CCIP message processing block cross-chain communication"
      detail: "CCIPAdapter._ccipReceive calls VotingController/AssetController which can revert; triggers Chainlink manual execution requirement, blocking governance"
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "L1 deposits via L1CrossDomainMessenger fail and are not replayable when L2CDM is paused"
      detail: "L2CrossDomainMessenger paused causes relayMessage to revert; no retry info saved; ETH minted to aliased L2CDM address, permanently lost to depositor"

- id: bridge-011
  pattern: cross-chain-gas-fee-miscalculation
  name: "Cross-chain gas fee or cost miscalculation causing message failure or fund loss"
  severidad: high
  causa_raiz: >
    Bridge or bridge-aggregator miscalculates destination gas costs: uses source chain
    gas config instead of destination, estimates fees with shorter payload than actual,
    omits required ETH payment for L1->L2 messaging, or fails to account for decimal
    dust removal in OFT transfers. The message either fails on destination (funds stuck)
    or costs the user more than expected.
  como_funciona: |
    1. Bridge estimates gas or fee using incorrect parameters:
       a. Source-chain baseGas/gasPerByte instead of destination values
       b. Stub payload (just message type) instead of actual payload with full struct
       c. Zero msg.value for L1->L2 calls that require ETH (ZkSync, Multichain anyCall)
       d. minAmountLD == amountLD without accounting for OFT dust removal
    2. Transaction sent from source chain (appears to succeed)
    3. On destination: execution reverts due to insufficient gas/fees
    4. Assets stuck in bridge limbo or permanently lost (no retry mechanism)
  invariante: >
    estimatedGas(message) >= actualGasConsumed(message) on destination chain.
    For OFT: minAmountLD <= removeDust(amountLD).
  que_mirar:
    - "Does gas estimation use destination chain config or source chain config?"
    - "Is the payload used for fee estimation the SAME structure as the actual payload?"
    - "For L1->L2 calls: is msg.value provided? Does contract have receive()/fallback()?"
    - "For OFT transfers: does minAmountLD account for decimalConversionRate dust removal?"
    - "grep: estimateFees, quoteLayerZero, l2TransactionBaseCost, requestL2Transaction"
    - "grep: _removeDust, decimalConversionRate, minAmountLD, SlippageExceeded"
    - "grep: anyCall, payNativeGasForContractCall, value:"
  como_se_arregla: >
    Use destination-chain gas parameters. Estimate with actual payload size (or max payload).
    For L1->L2: calculate and forward required ETH. For OFT: set minAmountLD = removeDust(amountLD).
    Add receive()/fallback() if contract needs to accept ETH for gas payments.
  trampas:
    - "Excess gas is usually refunded to LZ/relayer, not to user -- overpayment is wasteful but not critical"
    - "Underpayment is always worse: message fails silently"
    - "OFT dust removal only affects tokens where local decimals > shared decimals"
  fuente: "Solodit / Code4rena, Spearbit, Shieldify findings"
  confianza: alta
  verificado: true
  tags: [gas-estimation, fee-calculation, underpayment, OFT, dust-removal, L1-to-L2]
  relacionado_con: [bridge-006, bridge-010]
  incidentes:
    - protocol: "Holograph"
      firm: "Code4rena"
      impact: "HIGH"
      title: "LayerZeroModule uses source-chain gas config for destination, NFT stuck in limbo"
      detail: "baseGas and gasPerByte from source chain RelayerV2 DstConfig; when chains differ, lzReceive OOGs and NFT lost forever"
    - protocol: "Mozaic Archimedes"
      firm: "Trust Security"
      impact: "MEDIUM"
      title: "MozBridge estimates gas with stub payload, actual payload much larger"
      detail: "quoteLayerZeroFee encodes only message type (32 bytes); actual messages include full Snapshot struct; send() reverts with insufficient gas"
    - protocol: "Connext"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Multichain anyCall always fails - no gas fee paid"
      detail: "BaseMultichain._sendMessage calls anyCall without paying execution gas fee; no receive()/fallback() to accept ETH deposits"
    - protocol: "Connext"
      firm: "Spearbit"
      impact: "HIGH"
      title: "ZkSync hub connector fails - no ETH supplied for L1->L2 requestL2Transaction"
      detail: "msg.value is zero but ZkSync requires ETH for base cost + l2Value; all messages to ZkSync blocked"
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "Underpaying Optimism l2gas causes finalizeDeposit failure and fund loss"
      detail: "User-provided l2Gas insufficient for destination execution; no recovery mechanism"
    - protocol: "Brix Money"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Cross-chain unstake fails due to minAmountLD not accounting for LayerZero dust removal"
      detail: "minAmountLD == amountLD but OFT _removeDust truncates; SlippageExceeded revert blocks ~69% of transactions"

- id: bridge-012
  pattern: cross-chain-address-symmetry-assumption
  name: "Cross-chain address symmetry assumption breaks for AA wallets and multisigs"
  severidad: medium
  causa_raiz: >
    Bridge hardcodes msg.sender as destination recipient, assuming same address is
    controlled by same entity on all chains. Fails for: account abstraction wallets
    (different address per chain), multisigs (different deployment nonces), smart
    contract wallets via CREATE2 with different salts, and ZkSync's msg.sender preservation.
  como_funciona: |
    1. User with AA wallet / multisig / smart contract wallet initiates bridge transfer
    2. Bridge encodes msg.sender as destination recipient (no separate recipient parameter)
    3. On destination chain, same address is either:
       a. Not deployed (funds sent to EOA no one controls)
       b. Owned by a different entity (funds stolen)
       c. A different contract entirely (funds stuck)
    4. Assets permanently lost or stolen
  invariante: >
    Bridge recipient address must be explicitly specified by the user, not derived from msg.sender.
    Or: bridge must verify the user controls the destination address.
  que_mirar:
    - "Does bridge use msg.sender as destination recipient? (grep: abi.encode.*msg.sender)"
    - "Is there a separate _recipient or _to parameter for destination address?"
    - "Does protocol target L2s where msg.sender is preserved for L1->L2 calls (ZkSync)?"
    - "grep: bytes32(uint256(uint160(msg.sender))), to: msg.sender"
    - "grep: user: msg.sender, UnstakeMessage"
  como_se_arregla: >
    Allow user to specify destination recipient address explicitly. Add documentation
    warning for AA wallet users. For ZkSync L1->L2: never assume address control equivalence
    between chains for contract accounts.
  trampas:
    - "EOA addresses ARE the same across EVM chains -- this only affects contract wallets"
    - "Some protocols intentionally enforce same-address for compliance -- check if by design"
    - "ZkSync msg.sender preservation is a known feature, not a bug in ZkSync itself"
  fuente: "Solodit / Code4rena, Spearbit findings"
  confianza: alta
  verificado: true
  tags: [account-abstraction, multisig, address-symmetry, smart-wallet, ZkSync]
  relacionado_con: [bridge-002, bridge-005]
  incidentes:
    - protocol: "Ondo Finance"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Bridged funds lost for AA wallet users - msg.sender hardcoded as recipient"
      detail: "burnAndCallAxelar encodes msg.sender in payload; AA wallets have different address per chain; 4.4M Safe wallet users at risk of permanent fund loss"
    - protocol: "Brix Money"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Cross-chain unstake enforces address symmetry, incompatible with AA wallets"
      detail: "UnstakeMessenger.unstake() sets user: msg.sender; Hub chain sends assets to same address on spoke chain; Gnosis Safe / AA wallets get different addresses"
    - protocol: "Connext"
      firm: "Spearbit"
      impact: "HIGH"
      title: "ZkSync msg.sender preservation allows cross-chain address impersonation"
      detail: "msg.sender preserved for L1->L2; attacker deploys wallet at victim's address on L1 (same CREATE2 salt); gains control of victim's ZkSync delegate permissions and funds"

- id: bridge-013
  pattern: bridge-aggregator-arbitrary-call
  name: "Bridge aggregator/router allows arbitrary external calls leading to fund theft"
  severidad: critical
  causa_raiz: >
    Bridge aggregator (LiFi, Socket, etc.) accepts user-supplied bridge address,
    destination address, or calldata for cross-chain execution. Insufficient validation
    allows attacker to: call arbitrary contracts via bridge facets, trigger gateway
    token mints to attacker-controlled contracts, or approve attacker for token spending.
  como_funciona: |
    1. Aggregator accepts user-provided bridge address or destination call parameters
    2. Attacker either:
       a. Supplies malicious bridge address (function selector collision with real bridge)
       b. Crafts calldata that calls gateway.validateContractCallAndMint to mint tokens to Executor
       c. Sets callTo = gateway with calldata = approve(attacker, MAX)
    3. Tokens minted/approved to attacker-controlled address
    4. Attacker drains funds from Executor or approved contract
  invariante: >
    Bridge addresses must be immutable or whitelisted. External call targets in cross-chain
    execution must be restricted. No arbitrary approval possible via user-supplied calldata.
  que_mirar:
    - "Are bridge addresses supplied as function parameters or hardcoded/immutable?"
    - "Does destination executor allow arbitrary callTo address and callData?"
    - "Is the Axelar gateway address blacklisted from callTo targets?"
    - "Can user-supplied payload trigger validateContractCallAndMint on gateway?"
    - "Are tokens stuck in Executor if _executeWithToken reverts without recovery path?"
    - "grep: IOmniBridge(_bridgeData.bridge), callTo.call(callData), approve"
    - "grep: validateContractCallAndMint, _executeWithToken, IAxelarExecutable"
  como_se_arregla: >
    Hardcode bridge addresses as immutable in constructor. Whitelist allowed callTo targets.
    Blacklist gateway and token contracts from arbitrary calls. Implement token recovery
    for failed executions. Remove payable if native token bridging not supported.
  trampas:
    - "Function selector collision is extremely rare but not impossible -- verify critical interfaces"
    - "If aggregator is meant for API use only, direct contract interaction is still possible"
    - "Tokens stuck in Executor may be sweepable by owner -- check for sweep function"
  fuente: "Solodit / Spearbit (LI.FI audit 2022)"
  confianza: alta
  verificado: true
  tags: [aggregator, router, arbitrary-call, LiFi, Axelar, gateway, approval]
  relacionado_con: [bridge-002, bridge-005]
  incidentes:
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Bridge with Axelar can be stolen via malicious external call to gateway"
      detail: "Executor allows arbitrary callTo except erc20Proxy; attacker calls gateway.validateContractCallAndMint to mint tokens to Executor, then drains via crafted approve"
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Bridge addresses supplied as parameters - any address callable"
      detail: "OmniBridgeFacet accepts _bridgeData.bridge as parameter; function selector collision could call unintended contract; users tricked into signing malicious tx"
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Axelar tokens lost if destination execution fails - no recovery"
      detail: "_executeWithToken reverts on failure, no fallback to recovery address; tokens permanently stuck in Executor"
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "WormholeFacet accepts native token via payable but never bridges it"
      detail: "startBridgeTokensViaWormhole is payable; depositAsset allows native; _startBridge calls transferTokens without {value}; ETH stuck in Diamond"
    - protocol: "LI.FI"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "Wormhole chain IDs differ from EVM chain IDs - funds sent to wrong chain"
      detail: "block.chainid check uses EVM IDs but Wormhole uses own IDs (1=Solana); non-EVM recipients get truncated address; funds unrecoverable"

- id: bridge-014
  pattern: cross-chain-economic-state-manipulation
  name: "Cross-chain economic or state manipulation via bridge timing"
  severidad: high
  causa_raiz: >
    Cross-chain state synchronization is non-atomic. Attacker exploits the time gap
    between snapshot/sync operations across chains to manipulate economic values
    (LP price, supply counts, proposal parameters) by strategically bridging assets
    or submitting transactions during the sync window.
  como_funciona: |
    1. Protocol performs cross-chain state aggregation (snapshot LP supply, sync prices, collect votes)
    2. Attacker identifies the sync window and:
       a. Bridges tokens to make them "disappear" during snapshot (in-flight = uncounted)
       b. Bridges tokens to multiple chains to be counted multiple times
       c. Submits max-value parameter (e.g., l2BlockNumber = 2^64-1) to brick future updates
    3. Aggregated state is incorrect: inflated price, deflated supply, blocked proposals
    4. Attacker profits from the distorted state (withdraw at inflated LP price, block withdrawals)
  invariante: >
    Cross-chain aggregated state must account for in-flight assets.
    No single unverified input should be able to permanently brick state progression.
  que_mirar:
    - "Does protocol aggregate state across chains (LP supply, TVL, prices)?"
    - "Can tokens be in-flight (bridging) during snapshot/sync period?"
    - "Are cross-chain inputs (block numbers, timestamps, amounts) validated against bounds?"
    - "Can attacker bridge tokens just before a chain is snapshotted to count them on both chains?"
    - "Can a malicious proposer/relayer submit max-value inputs to overflow counters?"
    - "grep: snapshot, syncState, reportSnapshot, ProposeOutput, l2BlockNumber"
    - "grep: anyCall, OFT, bridgeLP, totalSupply, aggregated"
  como_se_arregla: >
    Lock bridging during snapshot windows. Track in-flight amounts. Validate all cross-chain
    inputs against reasonable bounds (e.g., l2BlockNumber < lastBlock + maxIncrement).
    Use commit-reveal for aggregation. Disable LP/token bridging during sync.
  trampas:
    - "Snapshot timing may be unpredictable -- consider if attacker can trigger it"
    - "LP token bridging is often a desired feature -- disabling it is a trade-off"
    - "Governance override may not react fast enough (minutes vs hours finalization)"
  fuente: "Solodit / Trust Security, Code4rena, TrailOfBits findings"
  confianza: alta
  verificado: true
  tags: [economic-attack, snapshot, state-sync, LP-manipulation, timing, bridge-timing]
  relacionado_con: [bridge-004, bridge-008]
  incidentes:
    - protocol: "Mozaic Archimedes"
      firm: "Trust Security"
      impact: "HIGH"
      title: "LP price manipulation by bridging tokens to hide them during snapshot"
      detail: "LP tokens are OFT bridgeable; attacker bridges with tiny gas (fails on dest) during snapshot window; supply appears low; settle uses inflated price; attacker withdraws at profit"
    - protocol: "Initia"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Malicious proposer DOSes bridge withdrawals with max l2BlockNumber"
      detail: "ProposeOutput accepts unverified l2BlockNumber; proposer sets 2^64-1; all subsequent proposals fail (must be > last); governance has minutes to react before finalization"
    - protocol: "Immutable Smart Contracts"
      firm: "TrailOfBits"
      impact: "MEDIUM"
      title: "Withdrawal queue forcibly activated to hinder bridge operation"
      detail: "RootERC20PredicateFlowRate activates global withdrawal queue when token flow rate exceeded; attacker exceeds rate for cheap token, blocking ALL withdrawals across all tokens"

- id: bridge-015
  pattern: cross-chain-state-root-proof-bug
  name: "Bridge state root or Merkle proof logic bug breaking cross-chain verification"
  severidad: high
  causa_raiz: >
    Implementation bug in state root assignment, Merkle tree finalization, or frame
    decoding causes bridge verification to silently fail. Output handling never executes
    because return value is not assigned, or consensus splits because invalid frames
    are accepted.
  como_funciona: |
    1. Bridge computes Merkle tree root or processes batcher frames for state verification
    2. Implementation bug: return value never assigned (Go nil return), or invalid frame accepted
    3. Consequence A: output handling never fires, state sync between L1/L2 breaks silently
    4. Consequence B: consensus split between implementations (reference vs production)
    5. Challenge mechanism disrupted or exploitable
  invariante: >
    handleTree must return non-nil storageRoot when tree is finalized.
    Frame decoding must reject frames missing mandatory fields (is_last byte).
  que_mirar:
    - "Does handleTree / finalizeWorkingTree assign the computed root to the return value?"
    - "Are all return paths in state proof functions verified to return correct values?"
    - "Does frame decoding enforce all mandatory fields per spec?"
    - "Can a missing/invalid field cause silent acceptance instead of rejection?"
    - "grep: storageRoot, treeRootHash, FinalizeWorkingTree, handleTree"
    - "grep: UnmarshalBinary, IsLast, ReadByte, io.EOF"
  como_se_arregla: >
    Add explicit return value assignment after tree finalization. Add unit tests that verify
    non-nil returns. Enforce all mandatory fields in frame decoding with explicit validation.
    Fuzz both reference and production implementations for consensus.
  trampas:
    - "Go's zero-value semantics make nil returns easy to miss -- not caught by compiler"
    - "Spec compliance bugs require reading the spec alongside the code"
  fuente: "Solodit / Code4rena, Sherlock findings"
  confianza: alta
  verificado: true
  tags: [state-root, merkle-proof, frame-decoding, consensus-split, Go, challenger]
  relacionado_con: [bridge-008, bridge-009]
  incidentes:
    - protocol: "Initia"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Storage root assignment missing in tree finalization - output handling never executes"
      detail: "handleTree computes treeRootHash but never assigns it to storageRoot return value; endBlockHandler checks storageRoot != nil (always false); cross-chain verification broken"
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Batcher frames incorrectly decoded - consensus split possible"
      detail: "UnmarshalBinary accepts frame with missing is_last byte (io.EOF treated as success); malicious sequencer can cause consensus split between op-node implementations"

- id: bridge-016
  pattern: cross-chain-reentrancy-finalization
  name: "Reentrancy during cross-chain message finalization causes fund loss"
  severidad: high
  causa_raiz: >
    Cross-chain message finalization (relayMessage, finalizeWithdrawal) has a reentrancy
    guard that can be weaponized. Attacker sends a message whose target contract calls
    back into the bridge during execution. The reentrancy guard causes the nested call
    to fail, but this failure is exploited to mark a legitimate withdrawal as "failed"
    while the attacker's message succeeds.
  como_funciona: |
    1. Attacker creates contract on L1 that calls finalizeWithdrawalTransaction when invoked
    2. Attacker sends L2->L1 message targeting their attack contract
    3. Message A: attacker's message is relayed, calls attack contract
    4. Attack contract calls finalizeWithdrawalTransaction for victim's withdrawal (message B)
    5. Reentrancy guard on relayMessage causes message B to fail
    6. Message B marked as failed in failedMessages (cannot be retried successfully)
    7. Victim's withdrawal permanently blocked; attacker's message succeeds
  invariante: >
    Reentrancy during relayMessage must not be able to affect the finalization status
    of other users' withdrawals. failedMessages must only be set for messages that
    genuinely failed due to their own execution.
  que_mirar:
    - "Does relayMessage have a reentrancy guard (ReentrancyGuard, reentrancyLock)?"
    - "Can the target contract of a relayed message call back into finalizeWithdrawalTransaction?"
    - "If nested finalization fails due to reentrancy guard, is the withdrawal marked as failed?"
    - "Can a failed withdrawal be retried? Or is it permanently marked?"
    - "grep: ReentrancyGuard, _reentrancyGuardEntered, relayMessage, finalizeWithdrawalTransaction"
    - "grep: failedMessages, successfulMessages, FAILED_L2_TO_L1"
  como_se_arregla: >
    Separate reentrancy guards per message hash (not global). Or: do not allow finalizeWithdrawal
    to be called as a target of relayMessage. Blacklist bridge's own address as message target.
  trampas:
    - "This requires the attacker to know the victim's withdrawal parameters in advance"
    - "Only affects bridges where reentrancy guard is shared across all message processing"
  fuente: "Solodit / Sherlock (Optimism audit)"
  confianza: alta
  verificado: true
  tags: [reentrancy, finalization, relayMessage, withdrawal, griefing]
  relacionado_con: [bridge-001, bridge-006]
  incidentes:
    - protocol: "Optimism"
      firm: "Sherlock"
      impact: "HIGH"
      title: "Reentrancy guard on relayMessage weaponized to block victim withdrawals"
      detail: "Attacker's L2->L1 message targets AttackContract; AttackContract calls finalizeWithdrawalTransaction for victim; reentrancy guard fails the nested call; victim's withdrawal marked failed and unrecoverable"

- id: bridge-017
  pattern: bridge-burn-before-destination-validation
  name: "Bridge burns tokens on source before destination can validate — permanent loss"
  causa_raiz: "Bridge burns or locks tokens on source chain immediately, then sends cross-chain message. If destination chain validation fails (blacklist, zero address, paused contract), tokens are already burned with no recovery mechanism. The asymmetric commit creates a window where tokens are destroyed but never minted."
  como_funciona: |
    1. User calls bridge sendDirect(amount, destinationChainSelector, destinationAddress).
    2. Source chain burns/locks tokens immediately (irreversible).
    3. Cross-chain message sent to destination.
    4. Destination ccipReceive() validates parameters (blacklist check, zero address check).
    5. Validation fails: destinationAddress is blacklisted or address(0).
    6. Destination reverts. Tokens already burned on source.
    7. No recovery mechanism exists. Funds permanently lost.
  invariante: |
    // All destination-side validations must also be checked on source side before burn
    // assert(sourceValidation == destinationValidation)
  que_mirar:
    - "Is there a burn/lock BEFORE the cross-chain message is sent?"
    - "Does the destination have validations NOT present on the source?"
    - "rg 'burn.*send|lock.*send' --type sol -- burn before cross-chain call?"
    - "Compare source-side checks vs destination-side checks for asymmetry"
    - "Is there a recovery mechanism for failed destination delivery?"
  como_se_arregla: "Replicate all destination validations on the source side before burning. Add a recovery/refund mechanism for failed cross-chain deliveries. Use a 2-phase commit: escrow on source, mint on destination, release escrow on confirmation."
  trampas:
    - "If destination always succeeds (no validation), not exploitable"
    - "Some bridges have retry mechanisms that may recover — check"
  incidentes:
    - "Colbfinance USC Offramp — sendDirect burns tokens then ccipReceive rejects blacklisted user, permanent loss (Low)"
    - "Colbfinance USC Offramp — missing zero address validation before burn, tokens lost when destinationAddress is address(0) (Low)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, burn, validation-asymmetry, permanent-loss, recovery, cross-chain]

- id: bridge-018
  pattern: bridge-default-zero-domain-mapping
  name: "Uninitialized chain-to-domain mapping defaults to valid chain ID 0"
  causa_raiz: "Bridge maps source chain IDs to destination domain IDs in a Solidity mapping. Uninitialized entries return default 0. If domain 0 is a valid destination (e.g., CCTP domain 0 = Ethereum mainnet), tokens are silently sent to the wrong chain instead of reverting."
  como_funciona: |
    1. Bridge has mapping(uint16 => uint32) chainIdToCCTPDomain.
    2. Admin forgets to initialize the mapping for Avalanche (chain 6).
    3. getCCTPDomain(6) returns 0 (Solidity default).
    4. CCTP domain 0 = Ethereum mainnet.
    5. User bridges USDC to Avalanche. Tokens sent to Ethereum instead.
    6. Funds potentially sent to wrong recipient or uncontrolled address on wrong chain.
  invariante: |
    // Domain 0 must only be valid for the actual chain 0 represents
    // require(domain != 0 || chainId == ETHEREUM_CHAIN_ID, "domain not configured");
  que_mirar:
    - "rg 'chainIdTo|domainMapping' --type sol"
    - "Can getCCTPDomain/getDomain return 0 for an unconfigured chain?"
    - "Is domain 0 a valid destination in the underlying bridge protocol?"
    - "Is there validation that the mapping entry has been explicitly set?"
  como_se_arregla: "Add require(domain != 0 || chainId == expectedEthereumId). Or use a sentinel value (type(uint32).max) as default and require domain != sentinel. Or require admin to set both bridge address and domain atomically."
  trampas:
    - "If domain 0 is not a valid destination in the protocol, default reverts naturally"
    - "If admin setup is atomic and tested, operational risk only"
  incidentes:
    - "Securitize Bridge CCTP — uninitialized chainIdToCCTPDomain returns 0 (Ethereum), USDC sent to wrong chain (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, mapping, default-zero, CCTP, wrong-chain, configuration]

- id: bridge-019
  pattern: bridge-lzreceive-native-value-unvalidated
  name: "LayerZero _lzReceive does not validate msg.value against intended native value"
  causa_raiz: "LayerZero V2 allows any executor to deliver verified messages. The receiving contract's _lzReceive() does not validate that msg.value matches the native value originally specified in executor options. A malicious or buggy executor delivers the message with zero or incorrect native value, but the contract processes it as if full value was received."
  como_funciona: |
    1. User sends cross-chain message with executor options specifying 1 ETH native value.
    2. Message verified by LayerZero DVN and stored for execution.
    3. Any party can execute verified messages (not just official executor).
    4. Malicious executor calls lzReceive with msg.value = 0.
    5. _lzReceive processes the message without checking msg.value.
    6. Recipient contract assumes it received 1 ETH but got 0.
    7. Protocol logic proceeds with incorrect value, causing fund loss or stuck assets.
  invariante: |
    // _lzReceive must validate msg.value matches encoded native value
    // (uint256 nativeValue, ...) = decode(executorOptions);
    // require(msg.value >= nativeValue, "insufficient native value");
  que_mirar:
    - "rg '_lzReceive' --type sol -- does it check msg.value?"
    - "Does the protocol rely on native value in cross-chain messages?"
    - "rg 'msg.value' in _lzReceive or lzCompose functions"
    - "LayerZero integration checklist: enforce-msgvalue-in-_lzreceive"
  como_se_arregla: "Validate msg.value in _lzReceive against the expected native value from the message or executor options. Follow LayerZero's integration checklist for msg.value enforcement."
  trampas:
    - "If no native value is expected in cross-chain messages, not applicable"
    - "Official LayerZero executors generally provide correct msg.value"
  incidentes:
    - "OnchainHeroes GenesisBridge — _lzReceive does not validate msg.value against intended native value, executor can deliver with zero ETH (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, layerzero, msg-value, executor, native-value, lzReceive]

- id: bridge-020
  pattern: bridge-refund-to-contract-locked
  name: "Bridge refund address set to contract — refunded tokens permanently locked"
  causa_raiz: "When initiating a cross-chain transfer, the refund address is set to the sending contract (address(this)) rather than the user. If the transfer fails or excess gas is refunded, tokens/ETH are sent to the contract which has no withdrawal function for these unaccounted funds."
  como_funciona: |
    1. Contract calls bridge.send() with refundAddress = address(this).
    2. Bridge transfer fails or has excess gas.
    3. Bridge protocol refunds tokens/ETH to the contract address.
    4. Contract has no function to withdraw refunded tokens.
    5. Tokens accumulate in contract with no recovery path.
    6. Over time, significant funds become permanently locked.
  invariante: |
    // Refund address must be the end user or a recoverable address
    // assert(refundAddress == user || contract.hasRescueFunction())
  que_mirar:
    - "rg 'refund.*address.*this|address.*this.*refund' --type sol"
    - "Does bridge send() use address(this) as refund recipient?"
    - "Is there a rescue/withdraw function for unaccounted tokens?"
    - "rg 'receive\\(\\)|fallback\\(\\)' --type sol -- can contract receive refunds?"
  como_se_arregla: "Set refund address to the user (msg.sender or the intended recipient). Or add a rescue function allowing admin to recover unaccounted tokens."
  trampas:
    - "If refunded tokens subsidize future fees (by design), may be acceptable"
    - "If contract has a generic rescue function, lower severity"
  incidentes:
    - "Camp CampTimelockEscrow — LayerZero refund address set to escrow contract, refunded tokens permanently locked (Low)"
    - "Malda — Across bridge depositor set to Rebalancer, failed transfers refund to Rebalancer with no recovery (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, refund, locked-funds, address-this, recovery, LayerZero, Across]

- id: bridge-021
  pattern: bridge-fee-approval-mismatch
  name: "Bridge approves transfer amount but not fee — insufficient allowance reverts"
  causa_raiz: "Bridge contract approves the fee adapter or token messenger for the transfer amount only, but the adapter pulls amount + fee. The approval is insufficient, causing every bridge transaction to revert. Alternatively, hardcoded fee parameters (maxFee=0 with fast finality) are incompatible with actual bridge protocol requirements."
  como_funciona: |
    1. Bridge calls safeApprove(token, feeAdapter, amount).
    2. feeAdapter.newIntent() pulls amount + fee from bridge.
    3. Allowance = amount < amount + fee. Transaction reverts.
    4. All cross-chain rebalancing operations fail permanently.
    5. Variant: maxFee hardcoded to 0 but CCTP fast finality requires minimum fee of 1.
    6. depositForBurn reverts because 0 < minimumFee.
  invariante: |
    // Approval must cover amount + maximum possible fee
    // assert(approval >= amount + maxFee)
  que_mirar:
    - "rg 'approve.*amount|safeApprove' --type sol in bridge contracts"
    - "Does the fee adapter pull more than the approved amount?"
    - "Are fee parameters (maxFee, finality) hardcoded or configurable?"
    - "rg 'depositForBurn|newIntent' --type sol -- check fee parameters"
  como_se_arregla: "Approve amount + fee (or type(uint256).max). Make fee parameters configurable rather than hardcoded. Query current minimum fees from the bridge protocol before sending."
  trampas:
    - "If fee is always 0 (standard finality), hardcoded 0 may be fine"
    - "Some bridge protocols deduct fee from amount, not from additional allowance"
  incidentes:
    - "Malda EverclearBridge — approves only transfer amount, feeAdapter pulls amount + fee, reverts (Medium)"
    - "Securitize Bridge CCTP — hardcoded maxFee=0 with fast finality incompatible, minimum fee is 1 (Medium)"
    - "Malda EverclearBridge — does not pull tokens from Rebalancer at all, all bridging fails (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, approval, fee, allowance, revert, CCTP, Everclear]

- id: bridge-022
  pattern: bridge-pending-messages-address-update
  name: "Updating bridge peer address strands pending cross-chain messages"
  causa_raiz: "Bridge validates incoming messages against a stored peer/bridge address. When admin updates the peer address (for upgrade or rotation), pending messages from the old address can no longer be delivered or retried because they fail the new peer validation."
  como_funciona: |
    1. Bridge has configurable peer address per chain: bridgeAddresses[chainId].
    2. Messages in flight from old bridge address.
    3. Admin calls setBridgeAddress(chainId, newAddress).
    4. Pending messages arrive with source = oldAddress.
    5. Validation: require(source == bridgeAddresses[chainId]) fails.
    6. Messages permanently undeliverable. Tokens locked in transit.
  invariante: |
    // No pending messages from old address should exist when updating
    // Or: maintain history of valid peer addresses
  que_mirar:
    - "rg 'setBridgeAddress|setPeer|setTrustedRemote' --type sol"
    - "Can bridge address be updated while messages are in flight?"
    - "Is there a check for pending messages before address update?"
    - "Does the bridge maintain a history of valid source addresses?"
  como_se_arregla: "Wait for all pending messages to be delivered before updating. Or maintain a list of historically valid peers for message validation. Or add a grace period during which both old and new addresses are accepted."
  trampas:
    - "If bridge has instant finality (no pending messages), not applicable"
    - "Admin responsibility — may be documented as operational procedure"
  incidentes:
    - "Securitize Bridge CCTP — pending/re-executable messages from old bridge address become undeliverable after setBridgeAddress (Low)"
    - "Threshold Network — missing Wormhole peer validation, no allowlist for source address (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, peer-update, pending-messages, stranded, configuration, migration]

- id: bridge-023
  pattern: bridge-bank-balance-not-credited
  name: "Bridge contract has token allowance but zero internal balance — transfers revert"
  causa_raiz: "Cross-chain bridge flow requires both ERC20 approval AND internal balance crediting (e.g., in a Bank contract). Bridge grants approval to downstream contract but forgets to credit its own internal balance. When downstream calls transferBalanceFrom, it checks internal balance (zero) rather than ERC20 balance, reverting all transfers."
  como_funciona: |
    1. L1BTCRedeemerWormhole receives tokens from Wormhole bridge.
    2. Grants thresholdBridge an allowance to withdraw.
    3. Does NOT credit its own balance in the Bank contract.
    4. Bridge.requestRedemption() calls bank.transferBalanceFrom(redeemer, amount).
    5. Bank checks redeemer's internal balance = 0. Reverts.
    6. All Wormhole redemptions permanently blocked.
  invariante: |
    // Before external transferBalanceFrom, internal balance must be credited
    // assert(bank.balanceOf(address(this)) >= amount)
  que_mirar:
    - "Does the bridge flow require BOTH ERC20 approval AND internal balance?"
    - "rg 'transferBalanceFrom|increaseBalance' --type sol"
    - "Is internal balance credited before downstream calls?"
    - "Dual accounting systems: ERC20 balance vs internal bank balance"
  como_se_arregla: "Call bank.increaseBalance() or equivalent before calling requestRedemption. Ensure both ERC20 and internal accounting are aligned."
  trampas:
    - "If downstream only checks ERC20 balance (not internal), not applicable"
    - "May be caught in integration testing"
  incidentes:
    - "Threshold Network — L1BTCRedeemerWormhole grants allowance but zero Bank balance, all Wormhole redemptions blocked (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [bridge, bank-balance, internal-accounting, dual-accounting, redemption, Wormhole]

- id: bridge-024
  pattern: l2-l2-cross-rollup-message-replay
  name: "L2→L2 cross-rollup message replay sin validación de destination chain"
  causa_raiz: >
    Bridges cross-rollup validan autenticidad del mensaje vía firma o merkle proof
    del source chain, pero no verifican que el mensaje esté dirigido al destination
    chain específico. Un atacante puede tomar un mensaje válido de Chain A → Chain B
    y resubmitirlo en Chain A → Chain C si ambas chains comparten el mismo nonce space
    o si la validación de nonce no incluye el destination chain ID. El relayer en
    Chain C lo acepta como legítimo, ejecutando cambios de estado no intencionados.
  como_funciona: |
    1. Bridge relayer mueve mensaje de Arbitrum → Optimism con nonce=42
    2. Mensaje es criptográficamente válido y contiene value/calldata
    3. Atacante intercepta el mensaje verificado (o lo observa en mempool/events)
    4. Atacante resubmite EL MISMO mensaje al bridge afirmando que proviene de Optimism → Base
    5. Nonce=42 se verifica en Base, pero nonce space no está aislado por (source, dest) pair
    6. Nonce 42 nunca fue usado en Base → pasa el check
    7. Contrato del atacante recibe tokens/calls dirigidos a un destinatario diferente
    8. O: xMsg.originDomain seteado por atacante sin chain-of-custody verification
  invariante: |
    // Message hash DEBE incluir source + destination chain IDs
    // messageHash = keccak256(abi.encode(payload, sourceChainId, destinationChainId))
    // Nonce tracking debe ser por (source chain, dest chain) — no global
    // assert(msg.destinationChainId == block.chainid)
  que_mirar:
    - "¿El nonce es global (uint256 nonce) o keyed por chain (mapping chainId => nonce)?"
    - "¿El destination chain ID está incluido en el message hash? grep: chainId, domainId, destinationChain"
    - "¿executeMessage verifica dstChainId contra el chain actual?"
    - "LayerZero: ¿_lzReceive verifica que dstChainId == expected chain?"
    - "Wormhole: ¿El VAA include targetChain o solo sourceChain?"
    - "¿Hay mapping(bytes32 messageHash => bool executed) sin gating por destination?"
  como_se_arregla: >
    Incluir source y destination chain IDs en el message hash.
    Usar nonce per (source chain, destination chain) pair.
    Verificar require(msg.destinationChainId == block.chainid) antes de ejecutar.
    Para Wormhole: validar targetChain en el parsing del VAA.
    Para LayerZero: incluir dstChainId en el payload y verificar en _lzReceive.
  trampas:
    - "Si nonce es por-source-chain solamente (no por destination), sigue vulnerable aunque chainId esté en el hash"
    - "Message replay en el MISMO chain ya cubierto en bridge-001 — este patrón es específicamente cross-chain (diferente destination)"
    - "Algunos bridges permiten el mismo mensaje en múltiples destinations (multicast) por diseño — verificar"
  incidentes:
    - "Connext (riesgo potencial): xMsg relayed Polygon → Arbitrum podría ser replayed Polygon → Optimism si nonce no incluye destination"
    - "Stargate v1 (vector identificado): nonce validation per-source, no per-destination pair — mitigado por whitelist de chains pero no por protocolo"
  severidad: critical
  confianza: alta
  verificado: false
  fuente: "Threat model cross-chain message replay, análisis bridges 2026"
  tags: [bridge, L2, cross-rollup, message-replay, nonce, destination-validation, LayerZero, Wormhole]
  relacionado_con: [bridge-001, bridge-005, bridge-010]
```

---

## 10. Real-World Incidents (Verified)

```yaml
- id: bridge-incident-001
  name: "OrbitChain exploit"
  fecha: "2024-01"
  perdida: "$81M"
  causa_raiz: "Incorrect input validation in cross-chain message handling"
  categoria: "Input validation"
  vector: "Cross-chain message forgery/manipulation due to insufficient validation of bridged data"
  leccion: "Always validate ALL fields of cross-chain messages. Input validation on bridge entry points is the last line of defense."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [bridge-002, bridge-005]
  tags: [input-validation, cross-chain, real-exploit]

- id: bridge-incident-002
  name: "SocketGateway exploit"
  fecha: "2024-01"
  perdida: "$3.3M"
  causa_raiz: "Lack of calldata validation in bridge router"
  categoria: "Input validation"
  vector: "Attacker crafted malicious calldata that bypassed router validation, enabling unauthorized token transfers from users who had approved the router"
  leccion: "Bridge routers with arbitrary calldata execution MUST validate every field. Residual approvals to routers amplify impact (see token-008)."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [bridge-002, token-008]
  tags: [calldata-validation, router, approval-exploit, real-exploit]
```

---

## Quick Reference: Invariant Cross-Map

| Bug Pattern | Key Invariants | Severity |
|---|---|---|
| Message replay | INV-BRIDGE-005 | Critical |
| Message forgery | INV-BRIDGE-012, INV-BRIDGE-013 | Critical |
| Validator collusion | (no on-chain invariant) | Critical |
| Lock-mint race | INV-BRIDGE-004, INV-BRIDGE-009 | Critical |
| Token mapping | INV-BRIDGE-010, INV-BRIDGE-011 | Critical |
| Failed message recovery | INV-BRIDGE-001, INV-BRIDGE-002, INV-BRIDGE-003, INV-BRIDGE-007, INV-BRIDGE-008 | High |
| Nonce reordering | INV-BRIDGE-005 (nonce component) | High |
| Finality violations | INV-BRIDGE-004, INV-BRIDGE-006 | Critical |
| Dispute game manipulation | INV-DISP-001 through INV-DISP-010 | Critical |

## Grep Targets

When auditing bridge code, search for these patterns:

```
relayMessage, finalizeWithdrawal, successfulMessages, failedMessages
crosschainMint, crosschainBurn, L2_STANDARD_BRIDGE
callWithMinGas, minGasLimit
FaultDisputeGame, SuperFaultDisputeGame, resolveClaim, resolve
rootBond, lockedBonds, claimCredit
OptimismPortal, CrossDomainMessenger, L2StandardBridge
DisputeGameFactory, anchorStateRegistry
```

---

## Solodit Verified Findings

### Maps to bridge-001 (message replay)
- **[HIGH] Reentrancy in MessageProxyForSchain leads to replay attacks** — `postIncomingMessages` calls receiver contract before updating `incomingMessageCounter`; attacker re-enters with same messages array during callback, executing transfers twice (SKALE IMA, C4)
- **[HIGH] Cross-chain signature replay due to user-supplied domainSeparator** — `_verifySig` accepts domainSeparator as input instead of computing internally; signatures replayable across chains where user nonce matches, with no deadline check making signatures valid indefinitely (NextGeneration Forwarder, C4)
- **[HIGH] Cross-chain replay attacks from missing chainId check** — Shardeum nodes don't validate chainId in transactions before execution; signed Ethereum transactions replayable on Shardeum if victim address has sufficient SHM balance (Shardeum, Immunefi)
- **[HIGH] Lack of replay protection in PPS oracle** — ECDSAPPSOracle signature schema missing nonce and block.chainid; once enough validators sign a price update, anyone can push outdated PPS price via replay, breaking share accounting in SuperVault (SuperVault, Spearbit)

### Maps to bridge-002 (message forgery)
- **[HIGH] Attacker mints arbitrary hTokens on RootChain** — `callOutSignedAndBridgeMultiple` with crafted DepositMultipleInputParams exploits weak validation of arrays (hTokens, tokens, amounts, deposits); attacker constructs parameters that pass branch checks but mint unbacked hTokens on root (Maia Ulysses, C4)
- **[HIGH] Cross-chain borrows using same collateral** — `borrowCrossChain` calculates collateral but doesn't lock it in lendStorage before sending via `_lzSend`; user fires multiple borrow requests to different chains before any confirmation arrives, multiplying borrowing power (Lend-V2, Sherlock)

### Maps to bridge-004 (lock-mint race / cross-chain state sync)
- **[HIGH] LayerZero global state sync overwrites** — Non-atomic cross-chain operations without locking mechanism allow concurrent state modifications; omniChainData changes on one chain get overwritten when delayed sync from another chain arrives with stale snapshot (Autonomint, Sherlock)
- **[HIGH] Hub missing liquidity check causes locked funds** — HubPool.getSendTokenMessage succeeds on hub even when spokeToken lacks liquidity; for cross-chain borrows, first leg succeeds but second reverts, permanently locking borrowed amount with utilization ratio exceeding 100% (Folks Finance, Immunefi)

### Maps to bridge-006 (failed message recovery)
- **[HIGH] LayerZeroAdapter executeMessages irrecoverable state** — executeMessages with limitToExecute processes one message but pops a different one from s_pendingMessagesToExecute storage; leads to permanent NFT locking in bridge contract (LayerZeroAdapter, Spearbit)

### Maps to bridge-007 (nonce reordering/skipping)
- **[HIGH] Invalid depositNonce in retrieveDeposit marks future nonces as executed** — Anyone can call `retrieveDeposit(x+y)` with future nonce; `executionHistory[nonce]` set to true on root, causing legitimate deposits later assigned that nonce to silently fail with funds stuck on branch (Maia BranchBridgeAgent, C4)

### Maps to bridge-008 (finality assumption / L2 sequencer)
- **[HIGH] UniV3 Oracle unsafe on L2 during sequencer downtime** — When sequencer goes down, TWAP extrapolates last known price across inactive period; on recovery, attacker exploits stale price via Arbitrum's delayed inbox forced inclusion before price updates (FranklinTempleton, Pashov)
- **[MEDIUM] L2 sequencer down pushes auction price to bad debt** — Liquidation auction price decay continues during sequencer downtime; on recovery, price may have dropped below 100% of debt, guaranteeing bad debt as all collateral seizable for less than total owed (Arcadia, Sherlock)
- **[MEDIUM] Missing L2 sequencer uptime check in oracle** — Protocol on Arbitrum/Optimism queries Chainlink without verifying sequencer status; during downtime, stale prices appear fresh, enabling exploitation of significant price movements (multiple: Renzo, Sentiment, Index Coop, Bond, Zaros)
- **[MEDIUM] Users unfairly liquidated after sequencer grace period** — Sequencer downtime blocks order creation/filling but not liquidation; when sequencer recovers, all price updates arrive instantly leaving users no time to add collateral (Zaros, CodeHawks)
- **[MEDIUM] L1 timestamps invalid on L2 chains** — L1 block.timestamp encoded in cross-chain message compared against L2 block.timestamp; Arbitrum timestamps can be up to 24h earlier than real time, causing valid price updates to be rejected as "future timestamps" (Renzo xRenzoBridge, C4)

### Maps to bridge-009 (dispute game manipulation)
- *(No new Solodit findings beyond existing coverage)*

### New patterns not in existing bugs
- **[HIGH] Remove owner calls replayable across chains** — `removeOwnerAtIndex` via `executeWithoutChainIdValidation` removes different owners on different chains where owner lists diverged due to chain-specific additions; can permanently brick account if only accessible owner is removed on a chain (CoinbaseSmartWallet, C4)
- **[HIGH] Adversary blocks cross-chain DAO deployment** — DAO address determined by CREATE opcode (deployer address + nonce); if two chains share deployer address, attacker front-runs counterpart deployment by creating DAO with matching nonce on destination, overwriting legitimate DAO data in factory (CrossChain DAO, Cantina)
- **[HIGH] Communication channel blocked by gas exhaustion** — LayerZero NonblockingLzApp stores failed messages for retry; _creditTill + post-processing loop for tokenId array exhausts remaining gas, causing permanent message blocking across the bridge channel (HoneyJarONFT, Cantina)
- **[HIGH] Virtual Account control theft via cross-chain address collision** — `fetchVirtualAccount` only checks caller address without considering which branch chain the call originates from; attacker controlling same address on different branch gains control of victim's Virtual Account and all its assets (Maia RootPort, C4)
- **[HIGH] Gas constant underestimation causes permanent anyExecute failure** — `TRANSFER_OVERHEAD = 24,000` but actual gas between gasLeft and gasAfterTransfer is ~70,000; condition `gasLeft - gasAfterTransfer > TRANSFER_OVERHEAD` always true, making every anyExecute revert via _forceRevert (Maia BranchBridgeAgent, C4)
- **[HIGH] MIN_FALLBACK_RESERVE insufficient for actual AnyCall gas** — Gas accounting doesn't include AnyCall executor overhead (~70k gas for admin ops + gas price premium); users underpay execution cost, causing anyFallback to always revert when executor checks budget (Maia BranchBridgeAgent, C4)
- **[HIGH] Reentrancy on retrySettlement via missing lock + open bridge agent factory** — `createBridgeAgent()` lacks access control allowing malicious router injection; combined with missing `lock` modifier on `retrySettlement()`, attacker re-enters via malicious BranchRouter to execute same settlement repeatedly, stealing funds (Maia RootBridgeAgent, C4)
- **[MEDIUM] Access-controlled functions unreachable during sequencer downtime** — L2 rollups with forced inclusion via L1 use address aliasing; access control modifiers don't check aliased sender, preventing emergency pause/ownership operations during sequencer outage (Wormhole NTT, Pashov)
