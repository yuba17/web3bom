grep_targets:
  - "nullifier"
  - "nullifierHash"
  - "nullifiers"
  - "isSpent"
  - "commitment"
  - "commitments"
  - "merkleRoot"
  - "roots"
  - "knownRoots"
  - "isKnownRoot"
  - "verifyProof"
  - "verifier"
  - "groth16"
  - "snark"
  - "deposit("
  - "withdraw("
  - "relayer"
  - "relayerFee"
  - "denomination"
  - "anonymitySet"
  - "shielded"
  - "note"
  - "poseidon"
  - "MiMC"
  - "pedersen"
  - "MerkleTree"
  - "insertLeaf"
  - "nextIndex"
  - "filledSubtrees"
  - "currentRootIndex"

# Privacy Mixer Vulnerabilities -- Combat Briefing

Briefing for auditors of privacy protocols, mixers, and anonymous transaction systems.
Covers 13 vulnerability patterns across nullifier handling, commitment schemes, Merkle tree
management, proof verification, relayer incentives, and anonymity set integrity.
Verified data sourced from Solodit/Cyfrin database and public incident reports.

---

## 1. Bugs Conocidos

```yaml
- id: prv-001
  titulo: "Nullifier Reuse — Double-Spend via Missing Nullifier Check"
  causa_raiz: |
    Privacy mixers use nullifiers (deterministic hashes derived from the note secret and
    commitment index) to prevent double-spending. The contract must record each nullifier
    on first withdrawal and reject any subsequent withdrawal with the same nullifier.
    If the nullifier mapping is not checked before processing a withdrawal, or if the
    check uses an incorrect hash (e.g., hashing different parameters than the circuit
    enforces), the same note can be withdrawn multiple times, draining the pool.
  como_funciona: |
    1. Alice deposits 1 ETH into the mixer, receiving a note (secret, nullifier).
    2. Alice generates a valid ZK proof for withdrawal with nullifierHash = H(secret, leafIndex).
    3. Contract processes withdrawal, sends 1 ETH, but does NOT mark nullifierHash as spent
       (or marks a different value).
    4. Alice submits the SAME proof again — contract accepts because nullifiers[nullifierHash]
       is still false.
    5. Alice repeats until the pool is drained.
  invariante: |
    // CRITICAL: every nullifier must be marked spent exactly once
    mapping(bytes32 => bool) internal ghost_nullifierSpent;

    function invariant_no_double_spend() public view {
        // After every withdrawal, the nullifier MUST be in the spent set
        // Check: pool balance >= (total deposits - total withdrawals) * denomination
        t(address(mixer).balance >= ghost_totalDeposits - ghost_totalWithdrawals,
          "PRV-001: pool balance less than expected — possible double spend");
    }
  que_mirar:
    - "Is nullifiers[nullifierHash] checked BEFORE sending funds?"
    - "Is nullifierHash set to true AFTER the check but BEFORE external calls (CEI)?"
    - "Does the circuit enforce nullifierHash = hash(secret, pathIndex) matching the contract?"
    - "Are there multiple withdrawal functions that might skip the nullifier check?"
    - "Can the contract be upgraded to remove the nullifier mapping?"
  como_se_arregla: |
    - Check `require(!nullifiers[_nullifierHash])` before any state change or transfer.
    - Set `nullifiers[_nullifierHash] = true` before external calls (CEI pattern).
    - Ensure the ZK circuit constrains the nullifier derivation identically to the contract.
    - Use ReentrancyGuard on withdraw to prevent reentrancy-based double-spend.
  trampas:
    - "The nullifier check exists but uses a different hash function than the circuit — still exploitable"
    - "Nullifier stored in a mapping that gets cleared during proxy upgrades"
    - "Multiple pool contracts sharing a verifier but NOT sharing nullifier state — cross-pool double-spend"
    - "Tornado Cash forks that modify the circuit but forget to update the contract-side nullifier derivation"
  solodit_ids:
    - the-protocol-can-be-drained-through-commitment-duplication-quantstamp-hinkal-protocol-markdown
    - proof-verification-dos-via-duplicate-nullifier-account-ottersec-none-elusiv-pdf
    - nullifier-trees-can-be-cleared-ottersec-none-elusiv-pdf
    - double-spending-of-funds-when-bridging-bridgedtoken-codehawks-zksync-era-git
  incidentes:
    - nombre: "Elusiv — nullifier trees can be cleared"
      solodit_id: "nullifier-trees-can-be-cleared-ottersec-none-elusiv-pdf"
      severidad: CRITICAL
      detalle: "Nullifier tree state could be reset by an attacker, allowing previously spent notes to be withdrawn again — total pool drain possible"
      auditor: "OtterSec"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Hinkal Protocol — commitment duplication drains protocol"
      solodit_id: "the-protocol-can-be-drained-through-commitment-duplication-quantstamp-hinkal-protocol-markdown"
      severidad: CRITICAL
      detalle: "Duplicate commitments allowed in Merkle tree, enabling the same deposit to be withdrawn multiple times until pool is empty"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [nullifier, double-spend, withdrawal, state-management]
  relacionado_con: [prv-003, prv-008]

- id: prv-002
  titulo: "Merkle Tree Root Staleness — Old Roots Allow Replaying Spent Notes"
  causa_raiz: |
    Mixers maintain a history of Merkle roots (typically the last 30-100) to allow
    withdrawals that were generated against a recent-but-not-current root. If the root
    history window is too large, or if old roots are never invalidated, an attacker can
    use a root from before a note was spent to bypass the Merkle inclusion proof. Combined
    with a separate nullifier issue or a different pool, stale roots enable replay attacks.
    Even without nullifier bugs, overly permissive root history can leak information about
    when deposits were made (timing analysis).
  como_funciona: |
    1. Pool maintains roots[0..99] as a circular buffer of historical Merkle roots.
    2. Alice deposits at time T1, tree root becomes R_T1.
    3. Time passes, 200 more deposits occur, root is now R_T200.
    4. R_T1 has been evicted from the circular buffer — legitimate withdrawals against
       R_T1 now fail (funds stuck).
    5. Conversely: if the buffer is too large (e.g., stores ALL roots forever),
       an attacker who finds a nullifier collision can use an arbitrarily old root.
    6. In multi-chain deployments: root from chain A may be accepted on chain B where
       the nullifier set is different — enabling cross-chain double-spend.
  invariante: |
    // Merkle root validity window must be bounded
    function invariant_root_freshness() public view {
        // The oldest accepted root should not be older than ROOT_HISTORY_SIZE deposits
        uint256 currentIndex = mixer.currentRootIndex();
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; i++) {
            bytes32 root = mixer.roots((currentIndex + i) % ROOT_HISTORY_SIZE);
            if (root != bytes32(0)) {
                t(mixer.isKnownRoot(root), "PRV-002: valid root rejected");
            }
        }
        // Roots outside the window must NOT be accepted
        // (tested via handler that tries stale roots)
    }
  que_mirar:
    - "How large is ROOT_HISTORY_SIZE? Tornado Cash uses 30 — larger values increase attack window"
    - "Is isKnownRoot checking a fixed-size circular buffer or an ever-growing mapping?"
    - "Can roots be manipulated by depositing zero-value or dust commitments to rotate the buffer?"
    - "In multi-chain: are roots synchronized across chains? Shared or independent nullifier sets?"
    - "Can an admin update the root directly (setRoot) bypassing the Merkle tree insert path?"
  como_se_arregla: |
    - Use a bounded circular buffer (30-100 entries) for root history.
    - Reject withdrawals against roots older than a configurable block/time threshold.
    - In multi-chain: never share roots without also sharing nullifier state.
    - Emit events on root rotation for off-chain monitoring.
  trampas:
    - "ROOT_HISTORY_SIZE = 30 is safe for Tornado Cash throughput — but high-volume forks may rotate too fast, locking legitimate withdrawals"
    - "Roots stored as mapping(uint256 => bytes32) look bounded but if currentRootIndex can overflow, all roots become valid"
    - "Some forks store roots in an array that grows unboundedly — wastes gas but is safe for replay"
  solodit_ids:
    - the-merkle-tree-reports-having-an-incorrect-root-hash-quantstamp-hinkal-protocol-markdown
    - incorrect-root-assignment-ottersec-none-light-protocol-pdf
    - using-storage-root-value-after-reset-ottersec-none-elusiv-pdf
  incidentes:
    - nombre: "Hinkal — incorrect Merkle root hash reported"
      solodit_id: "the-merkle-tree-reports-having-an-incorrect-root-hash-quantstamp-hinkal-protocol-markdown"
      severidad: HIGH
      detalle: "Merkle tree reported incorrect root hash after insertions, potentially allowing proofs against wrong tree state"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Light Protocol — incorrect root assignment"
      solodit_id: "incorrect-root-assignment-ottersec-none-light-protocol-pdf"
      severidad: HIGH
      detalle: "Root value assigned incorrectly after tree update, causing valid commitments to fail verification or stale roots to remain valid"
      auditor: "OtterSec"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [merkle-root, staleness, replay, circular-buffer, root-history]
  relacionado_con: [prv-001, prv-011]

- id: prv-003
  titulo: "Commitment Malleability — Forging Notes via Hash Collision or Weak Commitment"
  causa_raiz: |
    The commitment scheme in a mixer must be binding: given commitment C = H(secret, nullifier),
    it must be computationally infeasible to find a different (secret', nullifier') that
    produces the same C. If the hash function is weak (e.g., truncated, or uses a
    non-collision-resistant function like keccak on field elements without domain separation),
    or if the commitment structure allows duplicate leaves, an attacker can forge notes
    that pass Merkle inclusion proofs without ever depositing.
  como_funciona: |
    1. Mixer uses commitment = H(secret || nullifier) where H is a non-ZK-friendly hash
       or the inputs are not properly domain-separated.
    2. Attacker finds (secret', nullifier') where H(secret' || nullifier') = H(secret || nullifier)
       due to length-extension, concatenation ambiguity, or field element overflow.
    3. Attacker generates a valid ZK proof using secret' and nullifier' against the
       existing commitment in the Merkle tree.
    4. Contract verifies: commitment exists in tree (yes, original was deposited),
       proof is valid (yes, uses matching secret'/nullifier'), nullifier is new (yes,
       nullifier' != nullifier).
    5. Attacker withdraws without having deposited — OR original depositor also withdraws,
       creating money from nothing.
  invariante: |
    // The number of valid withdrawals must never exceed the number of deposits
    uint256 internal ghost_depositCount;
    uint256 internal ghost_withdrawCount;

    function invariant_conservation() public view {
        t(ghost_withdrawCount <= ghost_depositCount,
          "PRV-003: more withdrawals than deposits — commitment forgery");
        t(address(mixer).balance >= (ghost_depositCount - ghost_withdrawCount) * mixer.denomination(),
          "PRV-003: pool balance inconsistent with deposit/withdraw counts");
    }
  que_mirar:
    - "Is the commitment hash collision-resistant? Poseidon and MiMC are ZK-friendly but check parameter choices"
    - "Are commitment inputs (secret, nullifier) padded/domain-separated to prevent concatenation ambiguity?"
    - "Can the same commitment be inserted into the tree twice? (duplicate leaf check missing)"
    - "Is the field order of the hash function >= the field order of the SNARK circuit?"
    - "Are commitments generated client-side without validation? Malformed commitments may still be insertable"
  como_se_arregla: |
    - Use collision-resistant ZK-friendly hashes (Poseidon with correct round params, or Pedersen).
    - Domain-separate commitment inputs: C = H(domain_sep || secret || nullifier || leafIndex).
    - Check for duplicate commitments before insertion: require(!commitmentUsed[commitment]).
    - Ensure field consistency between hash function and SNARK circuit.
  trampas:
    - "Poseidon with too few rounds is faster but may not be collision-resistant — check security margin"
    - "MiMC-based commitments have known algebraic structure that advanced attackers can exploit"
    - "Client-side commitment generation bugs (wrong field, wrong endianness) create notes that can never be withdrawn — not a security bug but causes fund loss"
    - "Empty/zero commitments may collide with tree initialization values (all-zeros leaves)"
  solodit_ids:
    - the-protocol-can-be-drained-through-commitment-duplication-quantstamp-hinkal-protocol-markdown
    - empty-leaf-nodes-map-to-non-zero-commitments-quantstamp-hinkal-protocol-markdown
    - hash-collision-in-merkle-tree-ottersec-none-light-protocol-pdf
    - inclusion-of-duplicate-account-hash-ottersec-none-light-protocol-pdf
  incidentes:
    - nombre: "Hinkal — empty leaf maps to non-zero commitment"
      solodit_id: "empty-leaf-nodes-map-to-non-zero-commitments-quantstamp-hinkal-protocol-markdown"
      severidad: MEDIUM
      detalle: "Empty leaf nodes in the Merkle tree mapped to non-zero commitment values, potentially allowing collision with user commitments"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Light Protocol — hash collision in Merkle tree"
      solodit_id: "hash-collision-in-merkle-tree-ottersec-none-light-protocol-pdf"
      severidad: HIGH
      detalle: "Hash function parameters allowed collision between different account hashes in the Merkle tree, enabling state forgery"
      auditor: "OtterSec"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [commitment, hash-collision, malleability, duplicate-leaf, forgery]
  relacionado_con: [prv-001, prv-008]

- id: prv-004
  titulo: "Deposit Front-Running & Timing Deanonymization"
  causa_raiz: |
    Privacy in mixers depends on the anonymity set — the set of all deposits that a
    withdrawal could plausibly come from. If an attacker (or chain observer) can correlate
    a deposit transaction with a withdrawal based on timing, amount, gas price, or the
    depositor's on-chain behavior, the privacy guarantee collapses. Front-running a
    deposit transaction by inserting a known commitment before it allows the attacker to
    narrow the anonymity set. Similarly, withdrawing immediately after depositing (or
    using a unique denomination) makes correlation trivial.
  como_funciona: |
    1. Attacker monitors the mempool for deposit transactions to the mixer.
    2. Attacker sees Alice's deposit(commitment_alice) in the mempool.
    3. Attacker front-runs with deposit(commitment_attacker) so it appears in the tree
       at a known index adjacent to Alice's.
    4. Later, when a withdrawal occurs, the attacker checks: did the Merkle proof use
       a path adjacent to commitment_attacker? If yes, it's likely Alice.
    5. Alternatively: Alice deposits 1 ETH and withdraws 0.5 ETH + 0.5 ETH via the
       same relayer within 10 minutes — trivially linkable by timing analysis.
  invariante: |
    // Anonymity set size must be sufficient before withdrawal
    // This is a protocol-level invariant, hard to enforce purely on-chain
    // But we can check minimum deposit count per denomination:
    function invariant_minimum_anonymity_set() public view {
        // Require at least MIN_ANON_SET deposits before first withdrawal is allowed
        t(mixer.nextIndex() >= MIN_ANON_SET || ghost_withdrawCount == 0,
          "PRV-004: withdrawal before anonymity set threshold reached");
    }
  que_mirar:
    - "Is there a minimum waiting period between deposit and withdrawal?"
    - "Does the protocol support multiple denominations? Smaller denomination pools have weaker anonymity"
    - "Can the relayer see the full withdrawal request (recipient, nullifier) before submitting — enabling selective censorship?"
    - "Are deposit amounts fixed (Tornado-style) or variable (Railgun-style)? Variable amounts are harder to anonymize"
    - "Is there a rate limit on deposits that could be exploited to narrow anonymity sets?"
  como_se_arregla: |
    - Use fixed denominations (0.1, 1, 10, 100 ETH) to maximize anonymity set pooling.
    - Implement minimum time delay between deposit and withdrawal capability.
    - Use encrypted memos and relayer rotation to prevent correlation.
    - Consider compliance-compatible approaches (Railgun Privacy Pools / Proof of Innocence).
    - Warn users via UI about low-anonymity-set pools.
  trampas:
    - "Fixed denominations solve amount correlation but create UX friction — users split deposits, which can be correlated across multiple transactions"
    - "Timing analysis can be mitigated on-chain but NOT eliminated — the mempool is inherently public"
    - "High gas price on withdrawal correlates with urgency / market events — a side channel"
    - "Graph analysis (Chainalysis, Elliptic) can deanonymize even with good operational security"
  solodit_ids:
    - attackers-can-make-protocol-interactions-untraceable-for-users-quantstamp-hinkal-protocol-markdown
    - weak-privacy-due-to-hash-only-identity-obfuscation-mixbytes-none-cryptolegacy-markdown
  incidentes:
    - nombre: "Tornado Cash — Chainalysis deanonymization"
      severidad: INFO
      detalle: "Chainalysis demonstrated statistical deanonymization of Tornado Cash deposits using timing analysis, unique deposit amounts, and withdrawal patterns. Not a smart contract bug but a protocol-level privacy limitation. Used by law enforcement for OFAC sanctions (Aug 2022)."
      auditor: "N/A (research)"
      verificado: true
      fuente: "Public research / US Treasury OFAC"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io), public research"
  tags: [privacy, anonymity-set, front-running, timing-analysis, deanonymization]
  relacionado_con: [prv-009, prv-012]

- id: prv-005
  titulo: "Relayer Fee Manipulation — Extracting More Than Agreed Fee from Withdrawal"
  causa_raiz: |
    Mixers use relayers to submit withdrawal transactions on behalf of users (so the
    withdrawer doesn't need ETH in the recipient address, which would link them to a
    funded account). The relayer fee is typically specified in the ZK proof's public
    inputs and verified by the contract. If the fee parameter is NOT constrained by the
    circuit, or if the contract doesn't enforce fee bounds, a malicious relayer can
    extract the entire withdrawal amount as a "fee," leaving the user with nothing.
    Additionally, if the fee is denominated in the withdrawal token and the relayer
    can choose the recipient, the relayer can redirect funds.
  como_funciona: |
    1. User generates a withdrawal proof with fee = 0.01 ETH (1% of 1 ETH denomination).
    2. Malicious relayer modifies the fee parameter to 0.99 ETH before submitting.
    3. If the circuit does NOT bind the fee to the proof (fee is a public input not
       constrained in the circuit), the proof still verifies.
    4. Contract sends 0.01 ETH to recipient and 0.99 ETH to relayer.
    5. User loses 99% of their withdrawal.
    --- Alternative vector ---
    6. Relayer front-runs with a higher gas price transaction using THEIR recipient address
       but the user's proof. If the recipient is also not circuit-bound, relayer steals everything.
  invariante: |
    // Fee must be bounded and recipient must match proof
    function invariant_relayer_fee_bounded() public view {
        // After each withdrawal, check fee was reasonable
        t(ghost_lastFee <= MAX_RELAYER_FEE,
          "PRV-005: relayer fee exceeds maximum bound");
        t(ghost_lastRecipient == ghost_proofRecipient,
          "PRV-005: withdrawal recipient doesn't match proof recipient");
    }
  que_mirar:
    - "Is the fee parameter a public input to the ZK circuit, or just a contract parameter?"
    - "Does the circuit constrain: recipient, relayer, fee, refund — or are any of these mutable?"
    - "Can the relayer submit withdraw() with modified public inputs that still pass verifyProof?"
    - "Is there a MAX_FEE or fee cap in the contract?"
    - "Can the relayer choose gas price to make the withdrawal unprofitable for the user?"
  como_se_arregla: |
    - Bind fee, recipient, relayer address, and refund amount as public inputs in the ZK circuit.
    - Contract MUST verify that the proof's public inputs match the function parameters.
    - Set a protocol-level MAX_FEE (e.g., 5% of denomination).
    - Use commit-reveal scheme for relayer selection to prevent front-running.
  trampas:
    - "Tornado Cash correctly binds fee/recipient in the circuit — but many forks do NOT"
    - "A fee of 0 is valid in Tornado Cash (self-relay) — don't reject zero fees"
    - "Gas price spikes can make relaying unprofitable, causing withdrawal delays — not a bug"
    - "Relayer competition (multiple relayers) mitigates fee manipulation but not front-running"
  solodit_ids:
    - relayers-do-not-receive-their-fees-quantstamp-hinkal-protocol-markdown
    - gas-griefing-attacks-on-the-relayers-quantstamp-hinkal-protocol-markdown
    - no-on-chain-enforcement-of-most-fees-quantstamp-hinkal-protocol-markdown
    - m-02-constant-fee-for-relayer-kann-none-pulse-markdown
  incidentes:
    - nombre: "Hinkal — relayers do not receive fees"
      solodit_id: "relayers-do-not-receive-their-fees-quantstamp-hinkal-protocol-markdown"
      severidad: HIGH
      detalle: "Fee distribution logic skipped relayer payment under certain conditions, making relaying economically unviable and potentially halting withdrawals"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Hinkal — no on-chain enforcement of fees"
      solodit_id: "no-on-chain-enforcement-of-most-fees-quantstamp-hinkal-protocol-markdown"
      severidad: MEDIUM
      detalle: "Most fee parameters not enforced on-chain, allowing fee manipulation by relayers or bypass by users"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [relayer, fee-manipulation, front-running, public-inputs, circuit-binding]
  relacionado_con: [prv-008, prv-004]

- id: prv-006
  titulo: "Governance Attack on Mixer — Malicious Proposal Drains Pool or Seizes Control"
  causa_raiz: |
    Privacy protocols with on-chain governance (DAO) are vulnerable to hostile takeover
    via malicious proposals. The attacker creates a proposal that appears identical to a
    legitimate one but contains hidden logic — typically using CREATE2 + selfdestruct to
    deploy different code at the same address after the proposal passes. Once the
    attacker controls governance, they can: change the verifier contract (accept any proof),
    drain the pool, modify the Merkle tree, or upgrade proxy contracts to steal funds.
    The fundamental issue is that governance voters cannot fully verify proposal bytecode,
    especially when self-destructing proxy patterns are used.
  como_funciona: |
    1. Attacker creates ProposalContract at address X using CREATE2.
    2. ProposalContract looks identical to a previously approved proposal (same logic).
    3. Community votes to approve the proposal — it passes governance.
    4. Before execution, attacker calls selfdestruct on ProposalContract.
    5. Attacker deploys NEW malicious code at the same address X using CREATE2.
    6. Governance executes the proposal at address X — now running malicious code.
    7. Malicious code grants attacker 1,200,000 TORN votes (exceeding all legitimate votes ~700K).
    8. Attacker now controls governance: can drain staking pool, change verifier, upgrade proxy.
  invariante: |
    // Governance proposals must not use self-destructible contracts
    // This is hard to enforce on-chain — better as an off-chain monitoring invariant
    function invariant_governance_integrity() public view {
        // Check that verifier contract hasn't changed unexpectedly
        t(address(mixer.verifier()) == ghost_expectedVerifier,
          "PRV-006: verifier contract changed — possible governance attack");
        // Check that denomination hasn't changed
        t(mixer.denomination() == ghost_expectedDenomination,
          "PRV-006: denomination changed — possible governance attack");
    }
  que_mirar:
    - "Does the mixer have upgradeable components (proxy pattern)? Who controls upgrades?"
    - "Can governance change the verifier contract address?"
    - "Are governance proposals using CREATE2? Can the proposal contract self-destruct?"
    - "Is there a timelock between proposal approval and execution?"
    - "Can governance drain the pool directly (e.g., emergency withdrawal function)?"
    - "Is the TORN token or governance token transferable? Can voting power be flash-loaned?"
  como_se_arregla: |
    - Make critical components (verifier, Merkle tree, nullifier mapping) immutable.
    - Implement long timelocks (48-72h) between proposal approval and execution.
    - Verify proposal bytecode hash at execution time matches the hash at voting time.
    - Prevent proposals from using self-destructible contracts (check for SELFDESTRUCT opcode).
    - Use time-weighted voting to prevent flash-loan governance attacks.
  trampas:
    - "A timelock helps but doesn't prevent the attack if the community doesn't monitor pending proposals"
    - "CREATE2 + SELFDESTRUCT trick works because the address is deterministic but the code is not — EIP-6780 (Dencun) mitigates this by limiting SELFDESTRUCT"
    - "Post-Dencun (March 2024), SELFDESTRUCT only clears storage in the same transaction it was created — this attack vector is significantly harder on new chains"
    - "The Tornado Cash governance attack was reversed by the attacker themselves via a new proposal — but $900K+ had already been extracted"
  solodit_ids:
    - deposited-funds-can-be-drained-by-a-compromised-owner-quantstamp-hinkal-protocol-markdown
    - l-06-project-has-a-security-risk-from-dao-attack-using-the-proposal-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git
  incidentes:
    - nombre: "Tornado Cash Governance Attack (May 2023)"
      severidad: CRITICAL
      detalle: "Attacker used CREATE2 + selfdestruct to deploy a malicious governance proposal that granted 1.2M TORN votes. Seized full DAO control, drained ~483,000 TORN ($2.17M) from governance vault. Attacker converted ~$900K to ETH and laundered through the mixer. Later partially reversed via new proposal."
      auditor: "N/A (live exploit)"
      verificado: true
      fuente: "Halborn post-mortem, CoinDesk"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Public incident report"
  tags: [governance, create2, selfdestruct, hostile-takeover, proxy-upgrade, TORN]
  relacionado_con: [prv-008, prv-010]

- id: prv-007
  titulo: "Note Encryption Key Leakage — Viewing Key Exposure Reveals All Transactions"
  causa_raiz: |
    Privacy protocols encrypt note data (amount, asset, blinding factor) using the
    recipient's viewing key so only they can decode their own notes from on-chain data.
    If the viewing key is derived insecurely (e.g., from a weak entropy source, or
    stored in browser localStorage without encryption), or if the encryption scheme
    has a flaw (e.g., nonce reuse in symmetric encryption, or deterministic encryption
    without randomness), an attacker who obtains the viewing key can retroactively
    decrypt ALL past and future transactions for that user, destroying their privacy.
    Unlike spending keys, viewing keys cannot be "rotated" without migrating all notes.
  como_funciona: |
    1. Alice's viewing key vk_alice is stored in browser localStorage (unencrypted JSON).
    2. A malicious dApp or browser extension reads localStorage and exfiltrates vk_alice.
    3. Attacker scans all on-chain encrypted notes, decrypts them with vk_alice.
    4. Attacker now knows: all of Alice's deposit amounts, withdrawal times, counterparties,
       and current shielded balance.
    5. Attacker can sell this information, use it for targeted attacks, or provide it to
       authorities for prosecution.
    --- Alternative vector ---
    6. Encryption uses CTR mode with a reused nonce. Two notes encrypted under same
       key + nonce → XOR of plaintexts leaks both.
  invariante: |
    // This is primarily an off-chain security concern
    // On-chain, we can verify that encrypted notes are indistinguishable
    // (statistical test — not enforceable as a Solidity assertion)

    // What CAN be checked on-chain:
    function invariant_unique_note_encryption() public view {
        // Each encrypted note should be unique (no nonce reuse)
        // Ghost tracking of encrypted note hashes
        t(!ghost_seenEncryptedNote[currentEncryptedNote],
          "PRV-007: duplicate encrypted note detected — possible nonce reuse");
    }
  que_mirar:
    - "How is the viewing key derived? From a master key, from a mnemonic, or independently?"
    - "Where is the viewing key stored client-side? Is it encrypted at rest?"
    - "What encryption scheme is used for notes? AES-GCM with random nonce? ChaCha20?"
    - "Is there a deterministic component in note encryption that could enable dictionary attacks?"
    - "Can the viewing key be shared without exposing the spending key? (key separation)"
    - "Does the protocol support viewing key rotation without note migration?"
  como_se_arregla: |
    - Derive viewing keys from a master key using a proper KDF (HKDF, scrypt).
    - Encrypt viewing keys at rest using user password + hardware security module if available.
    - Use authenticated encryption (AES-256-GCM or XChaCha20-Poly1305) with random nonces.
    - Implement viewing key rotation with note migration path.
    - Never store viewing keys in plaintext in localStorage or cookies.
  trampas:
    - "Viewing key leakage destroys privacy but NOT funds — the spending key is separate"
    - "Some protocols (Zcash) intentionally share viewing keys with auditors — this is by design"
    - "Forward secrecy is impossible with viewing keys — all past transactions are retroactively decryptable"
    - "Note scanning performance requires trade-offs that may weaken encryption (e.g., trial decryption with reduced ciphertext)"
  solodit_ids:
    - etrp-7-improper-validation-of-message-padding-during-poseidon-decryption-in-eerc-sdk-hexens-none-avacloud-markdown
    - etrp-6-missing-constraints-on-message-padding-in-poseidon-decryption-circuit-hexens-none-avacloud-markdown
    - weak-privacy-due-to-hash-only-identity-obfuscation-mixbytes-none-cryptolegacy-markdown
  incidentes:
    - nombre: "Zcash Sapling — incoming viewing key design"
      severidad: INFO
      detalle: "Zcash Sapling introduced separate incoming/outgoing viewing keys. The original Sprout design used a single key that, if leaked, exposed all transaction history. Not exploited in the wild but recognized as a design-level privacy weakness."
      auditor: "Zcash team (internal)"
      verificado: true
      fuente: "Zcash ZIP-310, ZIP-316"
    - nombre: "AvaCloud EERC — improper Poseidon decryption padding"
      solodit_id: "etrp-7-improper-validation-of-message-padding-during-poseidon-decryption-in-eerc-sdk-hexens-none-avacloud-markdown"
      severidad: MEDIUM
      detalle: "Improper message padding validation in the Poseidon decryption circuit of the encrypted ERC (EERC) SDK could allow distinguishing encrypted notes"
      auditor: "Hexens"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io), Zcash documentation"
  tags: [viewing-key, encryption, nonce-reuse, key-leakage, privacy]
  relacionado_con: [prv-004, prv-010, prv-012]

- id: prv-008
  titulo: "Withdrawal Proof Verification Bypass — Invalid ZK Proof Accepted by Verifier"
  causa_raiz: |
    The ZK verifier contract is the security foundation of any mixer. It must reject
    ALL invalid proofs — a single bypass means unlimited fund theft. Verification
    bypasses occur due to: (1) incorrect pairing check implementation, (2) missing
    input validation (e.g., proof elements not on the curve), (3) accepting the zero/identity
    proof, (4) hash function mismatch between circuit and contract, (5) verifier deployed
    with wrong verification key (different circuit than intended). The Zcash Sprout
    counterfeiting bug (CVE-2019-7167) was exactly this: a soundness flaw in the SNARK
    construction that allowed forging proofs.
  como_funciona: |
    1. Verifier contract implements Groth16 pairing check: e(A, B) == e(alpha, beta) * e(C, delta) * e(pubInput, gamma).
    2. A bug in the pairing library causes certain malformed proof elements to pass
       the check even though they don't represent a valid proof.
    3. Attacker constructs a proof (A=0, B=0, C=0) — the pairing check becomes
       e(0, 0) == e(alpha, beta) * ... which may evaluate to 1 == 1 (identity element).
    4. Contract accepts the "proof" — attacker withdraws without a valid note.
    --- Alternative ---
    5. Verifier uses wrong verification key (vk) — perhaps the vk for a test circuit
       was deployed to mainnet. Any proof valid under the test circuit passes.
  invariante: |
    // Proof verification must reject trivially invalid proofs
    function invariant_proof_verification_strict() public {
        // A zero proof should ALWAYS be rejected
        uint256[8] memory zeroProof;
        bytes32 fakeRoot = mixer.roots(0);
        bytes32 fakeNullifier = keccak256("fake");
        bool accepted = mixer.verifier().verifyProof(
            zeroProof,
            [uint256(fakeRoot), uint256(fakeNullifier), uint256(uint160(address(this))), uint256(0), uint256(0), uint256(0)]
        );
        t(!accepted, "PRV-008: zero proof accepted — CRITICAL verifier bypass");
    }
  que_mirar:
    - "Is the verifier auto-generated by snarkjs/circom? Check the template version — older versions had bugs"
    - "Does the verifier check that proof points are on the correct elliptic curve?"
    - "Does the verifier reject the point at infinity (0, 0) as a valid proof element?"
    - "Is the verification key (vk) hardcoded or configurable? Can governance change it?"
    - "Does the verifier hash function match the circuit hash function (MiMC vs Poseidon)?"
    - "Are there multiple verifier contracts for different denominations? Are all correctly configured?"
  como_se_arregla: |
    - Use battle-tested verifier contracts (snarkjs Groth16 verifier, Semaphore verifier).
    - Add explicit checks: reject proof elements at point (0, 0) or not on curve.
    - Verify the verification key matches the intended circuit by hash comparison.
    - Make the verifier contract immutable (no upgrade path for the vk).
    - Run formal verification on the verifier contract (Certora, Halmos).
  trampas:
    - "The Groth16 verifier looks simple but subtle bugs in field arithmetic libraries (modular reduction) can break soundness"
    - "Gas-optimized verifiers that skip curve membership checks are faster but exploitable"
    - "Different BN254 implementations handle the point at infinity differently — test explicitly"
    - "The verification key MUST match the EXACT circuit that produced the proving key — even minor circuit changes require a new trusted setup"
  solodit_ids:
    - proof-verification-dos-via-hijacking-ottersec-none-elusiv-pdf
    - proof-verification-dos-via-missing-token-account-ottersec-none-elusiv-pdf
    - failure-to-verify-proof-vector-length-ottersec-none-code-inc-pdf
    - 07-missing-check-on-compressed-flags-allowing-proof-with-invalid-flag-to-pass-code4rena-unruggable-unruggable-git
    - h-01-range-check-fails-to-bind-limbs-to-value-enabling-invalid-witnesses-code4rena-succinct-succinct-git
  incidentes:
    - nombre: "Zcash Sprout Counterfeiting Bug (CVE-2019-7167)"
      severidad: CRITICAL
      detalle: "Soundness flaw in BCTV14 zk-SNARK construction used in Zcash Sprout. Allowed forging proofs to create unlimited shielded ZEC from nothing. Discovered by Ariel Gabizon, fixed secretly in the Sapling upgrade (Oct 2018). No evidence of exploitation. The fix was slipped into the Sapling network upgrade without public disclosure until Feb 2019."
      auditor: "Ariel Gabizon (Zcash internal)"
      verificado: true
      fuente: "CVE-2019-7167, Zcash Foundation disclosure"
    - nombre: "Elusiv — proof verification DoS via hijacking"
      solodit_id: "proof-verification-dos-via-hijacking-ottersec-none-elusiv-pdf"
      severidad: HIGH
      detalle: "Attacker could hijack the proof verification process on Elusiv (Solana-based privacy protocol), causing all legitimate withdrawals to fail"
      auditor: "OtterSec"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Aztec Connect — integer arithmetic flaw in DeFi interaction ($450K bounty)"
      severidad: CRITICAL
      detalle: "Vulnerability in output computation for DeFi interactions via Aztec Connect's escape hatch. Multiple valid decompositions of a single value within the ZK circuit could be exploited by a malicious sequencer. Fixed by adding constraints for consistent value decomposition. $450,000 bounty paid to lucash-dev."
      auditor: "lucash-dev (independent researcher)"
      verificado: true
      fuente: "Aztec Labs blog"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "CVE-2019-7167, Solodit (solodit.cyfrin.io)"
  tags: [verifier, proof-bypass, groth16, soundness, zero-proof, verification-key]
  relacionado_con: [prv-001, prv-003, prv-010]

- id: prv-009
  titulo: "Denomination Set Manipulation — Breaking Anonymity by Altering Pool Parameters"
  causa_raiz: |
    Mixers with configurable denomination sets (e.g., governance can add 0.5 ETH or
    remove 10 ETH pools) expose a privacy attack surface. If an attacker (or colluding
    governance) adds a new denomination with very few deposits, any withdrawal from
    that pool is trivially linkable. Conversely, removing a denomination forces users
    in that pool to either leave funds stuck or withdraw to a new pool — both
    deanonymizing events. Some protocols allow per-token denomination changes, which
    creates accounting mismatches.
  como_funciona: |
    1. Governance adds a new denomination: 7.3 ETH (unusual amount).
    2. Only Alice and Bob deposit into this pool.
    3. When a withdrawal occurs from the 7.3 ETH pool, it's trivially Alice or Bob.
    4. If Alice deposited recently and withdrawal happens immediately, it's almost
       certainly Alice.
    --- Alternative ---
    5. Governance removes the 1 ETH denomination.
    6. All 1 ETH depositors must now withdraw (forced deanonymization) or lose funds.
    7. Bulk withdrawals from a deprecated pool are trivially linkable by timing.
  invariante: |
    // Denomination changes must not strand funds
    function invariant_denomination_stability() public view {
        // Active denominations should not be removed while funds exist
        for (uint256 i = 0; i < ghost_activeDenominations.length; i++) {
            uint256 denom = ghost_activeDenominations[i];
            if (ghost_poolBalance[denom] > 0) {
                t(mixer.isDenominationActive(denom),
                  "PRV-009: denomination with funds was deactivated");
            }
        }
    }
  que_mirar:
    - "Can governance add/remove denominations? What's the timelock?"
    - "Are there minimum deposit thresholds per denomination pool?"
    - "Can denomination changes be used to split the anonymity set into trackable subsets?"
    - "Are denomination-specific pools sharing the same Merkle tree or separate trees?"
    - "What happens to funds in a removed denomination — stuck forever or gracefully migrated?"
  como_se_arregla: |
    - Use fixed, well-known denominations (powers of 10) that cannot be changed.
    - If denominations must be configurable, require minimum anonymity set size before activation.
    - Never remove a denomination — only deprecate (stop new deposits, allow withdrawals forever).
    - Emit clear events for denomination changes so monitoring tools can alert users.
  trampas:
    - "Variable-amount protocols (Railgun, Aztec) avoid denomination issues but face different anonymity challenges (amount correlation)"
    - "Adding more denominations seems like it increases privacy but actually fragments the anonymity set"
    - "Denomination pools with <100 deposits provide essentially no privacy"
    - "Cross-denomination correlation: depositing 10 ETH in the 10 ETH pool then withdrawing 10x from the 1 ETH pool is linkable"
  solodit_ids:
    - malicious-erc-20-tokens-can-create-unredeemable-commitments-quantstamp-hinkal-protocol-markdown
    - etrp-5-discrepancy-between-clear-text-and-amount-pct-when-depositing-fee-on-transfer-tokens-hexens-none-avacloud-markdown
  incidentes:
    - nombre: "Tornado Cash — denomination fragmentation analysis"
      severidad: INFO
      detalle: "Academic research showed that the 0.1 ETH pool had significantly less privacy than the 10 ETH pool due to fewer deposits. Low-denomination pools had anonymity sets 10-100x smaller, making timing analysis feasible."
      auditor: "Academic researchers"
      verificado: true
      fuente: "Academic papers on Tornado Cash privacy analysis"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io), academic research"
  tags: [denomination, anonymity-set, governance, pool-fragmentation]
  relacionado_con: [prv-004, prv-006]

- id: prv-010
  titulo: "Compliance Backdoor — Hidden Circuit Constraint Enables Tracing"
  causa_raiz: |
    A malicious or coerced development team can embed a trapdoor in the ZK circuit that
    allows a specific party (government, company) to break privacy without the proof
    being distinguishable from a normal one. This can take the form of: (1) a hidden
    input to the circuit that encodes the sender's identity, (2) a weak randomness
    source in the trusted setup that allows the setup participant to forge proofs,
    (3) a "compliance key" hardcoded in the circuit that can decrypt all notes.
    The fundamental issue is that ZK circuits are opaque to most auditors — verifying
    that a circuit does NOT contain a backdoor requires deep cryptographic review.
  como_funciona: |
    1. Circuit includes an unused-looking input `_reserved` that is constrained to equal
       H(sender_address, block_number) modulo a secret compliance key.
    2. Normal users generate proofs where `_reserved` is computed correctly but they don't
       understand what it encodes.
    3. The entity holding the compliance key can scan all proofs, compute
       H(candidate_address, block_number) for known addresses, and match.
    4. If a match is found, the sender is deanonymized.
    5. Users cannot detect this because the proof still verifies and the circuit is
       compiled to an opaque R1CS/PLONK system.
    --- Alternative ---
    6. Trusted setup ceremony has 1 participant who keeps their toxic waste (tau).
    7. With tau, they can forge proofs for arbitrary statements — including "I deposited
       1000 ETH" when they deposited nothing.
  invariante: |
    // Circuit backdoor detection is NOT possible via Solidity assertions
    // This requires circuit-level auditing (R1CS/PLONK constraint review)
    // On-chain, we can check:
    function invariant_verifier_immutable() public view {
        // Verifier bytecode hash must match known-good deployment
        bytes32 codeHash;
        address v = address(mixer.verifier());
        assembly { codeHash := extcodehash(v) }
        t(codeHash == EXPECTED_VERIFIER_CODE_HASH,
          "PRV-010: verifier contract bytecode changed — possible backdoor insertion");
    }
  que_mirar:
    - "Is the ZK circuit open-source and auditable? Has it been audited by ZK specialists?"
    - "Was the trusted setup ceremony multi-party with >100 independent participants?"
    - "Are there any 'reserved' or 'unused' inputs/outputs in the circuit?"
    - "Does the circuit have more public inputs than the contract uses?"
    - "Is there a compliance/regulatory module that can be enabled post-deployment?"
    - "Can the verifier be upgraded to accept a different circuit?"
  como_se_arregla: |
    - Open-source all circuits and verification keys.
    - Use transparent setup systems (STARKs, Halo2, PLONK with universal SRS) to eliminate trusted setup risk.
    - Multi-party trusted setup with >1000 participants (only 1 honest participant needed).
    - Independent circuit audits by multiple ZK-specialized firms.
    - Verifiable builds: deterministic circuit compilation from source.
  trampas:
    - "Even open-source circuits can have subtle backdoors in the constraint structure that only deep review reveals"
    - "Trusted setup ceremonies where ALL participants were from the same company provide no security"
    - "PLONK universal SRS eliminates per-circuit setup but still requires an honest ceremony"
    - "Regulatory pressure may force teams to add compliance features post-launch via governance upgrades"
    - "Zcash powers-of-tau ceremony had 87 participants — considered sufficient but not immune to state-level coercion"
  solodit_ids:
    - m-4-malicious-verifier-will-recover-private-witness-values-breaking-zero-knowledge-property-sherlock-brevis-pico-zkvm-git
    - h-4-weak-fiat-shamir-in-c-kzg-4844verify_cell_kzg_proof_batch-sherlock-fusaka-upgrade-git
  incidentes:
    - nombre: "Zcash Sprout — trusted setup concerns"
      severidad: INFO
      detalle: "Zcash's initial Sprout trusted setup had only 6 participants. The Sapling upgrade (2018) improved to 87+ participants via the Powers of Tau ceremony. If any single participant destroyed their toxic waste, the setup is secure. No evidence of compromise."
      auditor: "Zcash Foundation"
      verificado: true
      fuente: "Zcash documentation, Powers of Tau ceremony records"
    - nombre: "Brevis Pico zkVM — malicious verifier recovers private witnesses"
      solodit_id: "m-4-malicious-verifier-will-recover-private-witness-values-breaking-zero-knowledge-property-sherlock-brevis-pico-zkvm-git"
      severidad: MEDIUM
      detalle: "A malicious verifier could recover private witness values from proofs, breaking the zero-knowledge property of the Pico zkVM system"
      auditor: "Sherlock"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: media
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io), Zcash documentation"
  tags: [backdoor, trusted-setup, compliance, trapdoor, circuit-audit, zero-knowledge]
  relacionado_con: [prv-008, prv-007]

- id: prv-011
  titulo: "Merkle Tree Depth Overflow — Deposits Unrecoverable After Tree Fills"
  causa_raiz: |
    Mixers use a fixed-depth Merkle tree (typically 20-32 levels, supporting 2^20 to
    2^32 leaves). When the tree is full, new deposits fail. However, the failure mode
    matters: if the contract silently wraps the leaf index (nextIndex overflow), new
    commitments overwrite old ones — destroying the Merkle proofs for overwritten
    deposits and making those funds permanently unrecoverable. Even without overflow,
    if there is no check for tree capacity, deposits may succeed (gas spent) but the
    commitment is placed in an invalid position.
  como_funciona: |
    1. Merkle tree has depth 20, supporting 2^20 = 1,048,576 leaves.
    2. After 1,048,576 deposits, nextIndex = 1,048,576 = 2^20.
    3. If nextIndex is stored as uint32 and used as: position = nextIndex % (2^20),
       the next deposit goes to position 0 — OVERWRITING the first commitment.
    4. The original depositor at position 0 can no longer generate a valid Merkle proof
       because their leaf has been replaced.
    5. Funds at position 0 are permanently locked (no valid proof exists).
    --- Alternative ---
    6. Tree at half capacity: Hinkal bug where tree becomes entirely unusable at
       2^(depth-1) entries due to incorrect subtree computation.
  invariante: |
    // Tree must reject deposits when full
    function invariant_tree_capacity() public view {
        uint256 maxLeaves = 2 ** mixer.levels();
        t(mixer.nextIndex() <= maxLeaves,
          "PRV-011: nextIndex exceeds tree capacity — deposits are overwriting");
    }

    // Previously inserted commitments must remain in the tree
    function invariant_commitment_persistence() public view {
        for (uint256 i = 0; i < ghost_commitments.length; i++) {
            // Each deposited commitment should still be provable
            t(mixer.isKnownRoot(ghost_rootAtDeposit[i]) ||
              mixer.nextIndex() - ghost_indexAtDeposit[i] > ROOT_HISTORY_SIZE,
              "PRV-011: commitment no longer in any known root — overwritten");
        }
    }
  que_mirar:
    - "What is the tree depth? 2^depth = max deposits. Is this enough for the protocol's lifetime?"
    - "Is there a require(nextIndex < 2**levels) check in the deposit function?"
    - "What type is nextIndex? uint32 overflows at 4B, uint256 is safe"
    - "Does the filledSubtrees array handle the full tree edge case?"
    - "Can the tree be migrated to a new contract when full? How are old commitments handled?"
    - "Are there subtree computation bugs at specific tree fill levels (e.g., half-full, power-of-2 boundaries)?"
  como_se_arregla: |
    - Add `require(nextIndex < 2**levels, "Merkle tree is full")` in deposit function.
    - Use uint256 for nextIndex (overflow-safe for any practical tree depth).
    - Plan for tree migration: deploy new tree contract, keep old tree readable for withdrawals.
    - Monitor tree fill level and alert operators well before capacity.
    - Consider tree compaction or state expiry for very long-lived protocols.
  trampas:
    - "Tornado Cash 0.1 ETH pool on mainnet has depth 20 (~1M deposits) — far from full, not a real concern for Tornado specifically"
    - "High-volume L2 forks of Tornado could fill a depth-20 tree in months"
    - "The tree being full is an availability issue, not a direct fund-loss issue — UNLESS overflow causes overwriting"
    - "Some implementations use a separate 'tree is full' flag instead of checking nextIndex — the flag could be set incorrectly"
  solodit_ids:
    - commitments-can-be-overwritten-by-overflowing-the-tree-quantstamp-hinkal-protocol-markdown
    - all-funds-become-irredeemable-when-the-tree-is-halfway-populated-quantstamp-hinkal-protocol-markdown
    - utilization-of-incompatible-tree-height-ottersec-none-light-protocol-pdf
    - m-01-zktrie-maximum-depth-limit-is-not-enforced-in-scroll-code4rena-unruggable-unruggable-git
  incidentes:
    - nombre: "Hinkal — commitments overwritten by tree overflow"
      solodit_id: "commitments-can-be-overwritten-by-overflowing-the-tree-quantstamp-hinkal-protocol-markdown"
      severidad: CRITICAL
      detalle: "When the Merkle tree overflowed its capacity, new commitments overwrote existing ones, making overwritten deposits permanently unrecoverable"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Hinkal — all funds irredeemable at half capacity"
      solodit_id: "all-funds-become-irredeemable-when-the-tree-is-halfway-populated-quantstamp-hinkal-protocol-markdown"
      severidad: CRITICAL
      detalle: "Incorrect subtree computation caused the entire Merkle tree to become unusable when populated to 50% capacity, locking all deposited funds permanently"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Light Protocol — incompatible tree height"
      solodit_id: "utilization-of-incompatible-tree-height-ottersec-none-light-protocol-pdf"
      severidad: HIGH
      detalle: "Tree height parameter mismatch between different components caused insertion failures at certain tree sizes"
      auditor: "OtterSec"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [merkle-tree, overflow, tree-depth, fund-loss, overwrite, capacity]
  relacionado_con: [prv-002, prv-003]

- id: prv-012
  titulo: "Cross-Chain Privacy Leakage — Bridging Reveals Amount/Timing on Destination"
  causa_raiz: |
    When users bridge assets from a privacy pool on chain A to chain B, the bridge
    transaction on chain B is typically public (standard ERC-20 transfer). This creates
    a correlation point: the amount and timing of the bridge transaction on chain B
    can be matched against withdrawals from the privacy pool on chain A. Even if chain B
    also has a privacy pool, the bridge hop itself is a deanonymization event. Cross-chain
    privacy protocols that maintain shielded state across chains must synchronize
    nullifier sets — failure to do so enables cross-chain double-spending.
  como_funciona: |
    1. Alice deposits 10 ETH into Tornado Cash on Ethereum mainnet.
    2. Alice withdraws 10 ETH from Tornado Cash to a fresh address on mainnet.
    3. Alice bridges 10 ETH from mainnet to Arbitrum using a public bridge.
    4. Observer sees: 10 ETH withdrawn from Tornado → 10 ETH bridged to Arbitrum
       within same block. High confidence this is the same entity.
    5. On Arbitrum, Alice's "clean" address is now linked to a Tornado withdrawal.
    --- Alternative (nullifier sync failure) ---
    6. Privacy protocol deployed on both mainnet and L2 with independent nullifier sets.
    7. User deposits on mainnet, generates proof against mainnet Merkle root.
    8. User submits the SAME proof on L2 (different nullifier set) — double-spend.
  invariante: |
    // Cross-chain nullifier synchronization
    function invariant_cross_chain_nullifier_sync() public view {
        // If the protocol operates cross-chain, nullifiers must be global
        // Test: a nullifier spent on chain A must be rejected on chain B
        for (uint256 i = 0; i < ghost_spentNullifiers.length; i++) {
            bytes32 nullHash = ghost_spentNullifiers[i];
            t(mixer.nullifierHashes(nullHash) == true,
              "PRV-012: nullifier spent on other chain not synced to this chain");
        }
    }
  que_mirar:
    - "Does the protocol operate on multiple chains? Are nullifier sets shared or independent?"
    - "How are Merkle roots synchronized across chains? Is there a bridge/oracle?"
    - "Can a proof generated on chain A be submitted on chain B?"
    - "Is there a delay between cross-chain nullifier sync that allows a race condition?"
    - "Does the protocol's bridge maintain shielded state, or does it force a public transfer?"
  como_se_arregla: |
    - Maintain global nullifier set across all chains (via bridge messages or shared L1 state).
    - Use chain-specific domain separation in nullifier derivation: H(secret, pathIndex, chainId).
    - Implement cross-chain shielded transfers (e.g., Railgun's cross-chain model) that never expose amounts publicly.
    - Add time delays between withdrawal and bridging recommendations in the UI.
    - Consider same-chain DEX swaps (e.g., Uniswap) before bridging to break the trail.
  trampas:
    - "Chain-specific nullifier derivation prevents cross-chain double-spend but doesn't help with privacy leakage during bridging"
    - "Cross-chain privacy is an unsolved problem at scale — even Railgun acknowledges limitations"
    - "L2-to-L1 withdrawals have mandatory 7-day delays (optimistic rollups) which provide natural timing decorrelation"
    - "Using a CEX as the 'bridge' provides better privacy than on-chain bridges (CEX pools many users' funds)"
  solodit_ids:
    - double-spending-of-funds-when-bridging-bridgedtoken-codehawks-zksync-era-git
    - block-reorg-can-allow-for-double-spending-auditone-none-aurorafastbridge-markdown
  incidentes:
    - nombre: "OFAC sanctions — cross-chain tracing (Aug 2022)"
      severidad: INFO
      detalle: "US Treasury OFAC sanctioned Tornado Cash, demonstrating that cross-chain tracing was effective enough for law enforcement. Bridge transactions between chains were key evidence in linking Tornado Cash users to Lazarus Group hacks (Ronin, Harmony)."
      auditor: "N/A (law enforcement)"
      verificado: true
      fuente: "US Treasury OFAC, Chainalysis"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io), public research"
  tags: [cross-chain, bridge, privacy-leakage, nullifier-sync, double-spend, deanonymization]
  relacionado_con: [prv-001, prv-004]

- id: prv-013
  titulo: "Shielded Pool Accounting Mismatch — Total Deposited != Total Withdrawable + Fees"
  causa_raiz: |
    A shielded pool must maintain a strict accounting invariant: the contract's token/ETH
    balance must always equal (sum of all deposits) - (sum of all withdrawals) - (sum of
    all fees collected). If this invariant breaks, either: (1) the pool can be drained
    (deficit), or (2) funds are stuck forever (surplus). Common causes include: rounding
    errors in fee calculations, rebasing tokens changing balance without updating state,
    fee-on-transfer tokens where the actual deposited amount differs from the nominal
    amount, direct transfers to the contract (donation attack inflating balance), and
    inconsistent denomination handling.
  como_funciona: |
    1. Pool expects denomination = 1 ETH per deposit.
    2. User deposits a fee-on-transfer ERC-20 token where 1% is burned.
    3. Pool records commitment for 1 token but only receives 0.99 tokens.
    4. After 100 deposits: pool has 99 tokens but 100 commitments.
    5. The 100th withdrawal fails (insufficient balance) — funds stuck.
    --- Alternative (inflation attack) ---
    6. Attacker directly transfers 1 ETH to the mixer contract (not via deposit).
    7. Pool balance is now 1 ETH higher than tracked deposits.
    8. If any accounting logic uses address(this).balance instead of tracked state,
       it can be manipulated.
  invariante: |
    // CRITICAL: pool balance must always cover all outstanding withdrawals
    function invariant_pool_solvency() public view {
        uint256 expectedBalance = (ghost_totalDeposits - ghost_totalWithdrawals) *
                                   mixer.denomination();
        uint256 actualBalance = address(mixer).balance; // or token.balanceOf(mixer)
        // Allow small tolerance for rounding (1 wei per operation)
        t(actualBalance >= expectedBalance - ghost_totalOps,
          "PRV-013: pool insolvent — balance less than expected");
        t(actualBalance <= expectedBalance + 1 ether,
          "PRV-013: pool has unexplained surplus — possible donation attack");
    }
  que_mirar:
    - "Does the mixer support fee-on-transfer tokens? Is the actual received amount tracked?"
    - "Does the mixer support rebasing tokens (stETH, aTokens)? Balance changes without transactions"
    - "Can anyone send ETH/tokens directly to the contract? How does this affect accounting?"
    - "Are fees deducted from the withdrawal amount or paid separately?"
    - "Is the denomination in the contract consistent with the denomination in the ZK circuit?"
    - "Are there rounding issues in fee calculations (e.g., fee = amount * rate / 10000)?"
  como_se_arregla: |
    - Track actual received amounts (balanceBefore vs balanceAfter) for fee-on-transfer tokens.
    - Reject rebasing tokens explicitly or use wrapping (wstETH instead of stETH).
    - Use internal accounting (tracked deposits/withdrawals) instead of address(this).balance.
    - Ensure denomination in contract matches denomination in ZK circuit exactly.
    - Add a sweep function for excess balance (donations) controlled by governance.
  trampas:
    - "Tornado Cash only supports ETH (not tokens) in its core contract — ERC-20 versions are separate and need different accounting"
    - "Small rounding errors accumulate over millions of operations — what's dust today is a pool deficit tomorrow"
    - "Donation attacks inflate balance but don't create valid commitments — no double-spend, but can cause revert in ratio-based calculations"
    - "Fee-on-transfer tokens are increasingly rare but still exist (USDT has an optional fee flag)"
  solodit_ids:
    - malicious-erc-20-tokens-can-create-unredeemable-commitments-quantstamp-hinkal-protocol-markdown
    - funds-can-be-locked-if-sent-via-direct-transfers-quantstamp-hinkal-protocol-markdown
    - a-transaction-may-not-distribute-all-funds-quantstamp-hinkal-protocol-markdown
    - user-deposits-can-become-stuck-if-the-protocol-is-blacklisted-quantstamp-hinkal-protocol-markdown
  incidentes:
    - nombre: "Hinkal — malicious ERC-20 creates unredeemable commitments"
      solodit_id: "malicious-erc-20-tokens-can-create-unredeemable-commitments-quantstamp-hinkal-protocol-markdown"
      severidad: HIGH
      detalle: "Fee-on-transfer or malicious ERC-20 tokens could create commitments in the Merkle tree for an amount larger than what was actually deposited, causing later withdrawals to fail (insufficient balance)"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
    - nombre: "Hinkal — funds locked via direct transfers"
      solodit_id: "funds-can-be-locked-if-sent-via-direct-transfers-quantstamp-hinkal-protocol-markdown"
      severidad: MEDIUM
      detalle: "Tokens sent directly to the contract (not through deposit function) were permanently locked with no recovery mechanism"
      auditor: "Quantstamp"
      verificado: true
      fuente: "Solodit (solodit.cyfrin.io)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [accounting, solvency, fee-on-transfer, rebasing, donation-attack, balance-mismatch]
  relacionado_con: [prv-001, prv-003, prv-011]
```

---

## 2. Invariantes Clave (Resumen para Fuzzing)

### Conservation invariant (prv-001, prv-003, prv-013)

```solidity
// CRITICAL: The pool MUST be solvent at all times
// This is the single most important invariant for any mixer
uint256 totalDeposited = ghost_depositCount * mixer.denomination();
uint256 totalWithdrawn = ghost_withdrawCount * mixer.denomination();
assert(address(mixer).balance >= totalDeposited - totalWithdrawn);
assert(ghost_withdrawCount <= ghost_depositCount);
```

Historical hit rate: 5/13 patterns directly violate this invariant. Covers double-spend (prv-001),
commitment forgery (prv-003), tree overflow (prv-011), proof bypass (prv-008), accounting mismatch (prv-013).

### Nullifier uniqueness (prv-001)

```solidity
// CRITICAL: Each nullifier must be spent at most once
// Before withdrawal:
assert(!mixer.nullifierHashes(nullifierHash));
// After withdrawal:
assert(mixer.nullifierHashes(nullifierHash));
```

Historical hit rate: 3/13 patterns. Direct double-spend prevention.

### Merkle root validity (prv-002)

```solidity
// HIGH: Only recent roots should be accepted
// Current root must always be valid
assert(mixer.isKnownRoot(mixer.roots(mixer.currentRootIndex())));
// Roots beyond history window must be rejected
assert(!mixer.isKnownRoot(ancientRoot));
```

Historical hit rate: 2/13 patterns. Root staleness enables replay when combined with nullifier issues.

### Tree capacity (prv-011)

```solidity
// CRITICAL: Tree must not overflow
assert(mixer.nextIndex() < 2 ** mixer.levels());
// Every inserted commitment must be retrievable
// (no overwrite of existing leaves)
```

Historical hit rate: 2/13 patterns. Direct fund loss on overflow.

### Verifier integrity (prv-008, prv-010)

```solidity
// CRITICAL: Verifier must reject trivially invalid proofs
uint256[8] memory zeroProof;
assert(!verifier.verifyProof(zeroProof, publicInputs));
// Verifier bytecode must not change
assert(extcodehash(address(verifier)) == EXPECTED_HASH);
```

Historical hit rate: 3/13 patterns. Total pool drain if violated.

---

## 3. Checklist de Auditoría — Privacy Mixer

```
NULLIFIER & DOUBLE-SPEND
[ ] Is nullifierHash checked BEFORE transfer? (CEI pattern)
[ ] Is nullifierHash marked spent in the same transaction?
[ ] Does the circuit enforce nullifier = H(secret, pathIndex) matching the contract?
[ ] Can the nullifier mapping be cleared, reset, or migrated unsafely?
[ ] Are nullifier sets shared across chains / across pools?

MERKLE TREE
[ ] Is there a capacity check (nextIndex < 2^levels) on deposit?
[ ] What happens at tree capacity — revert or silent overwrite?
[ ] Are filledSubtrees computed correctly at all tree fill levels?
[ ] Is ROOT_HISTORY_SIZE appropriate (not too large, not too small)?
[ ] Can roots be set/modified directly (admin setRoot)?

COMMITMENT SCHEME
[ ] Is the hash function collision-resistant (Poseidon with correct rounds)?
[ ] Are commitment inputs domain-separated (no concatenation ambiguity)?
[ ] Can duplicate commitments be inserted into the tree?
[ ] Do empty tree leaves use a safe default (not colliding with valid commitments)?

ZK VERIFIER
[ ] Does the verifier reject the zero proof (A=0, B=0, C=0)?
[ ] Are proof points validated to be on the curve?
[ ] Does the verification key match the intended circuit?
[ ] Is the verifier immutable or upgradeable?
[ ] Are all public inputs (root, nullifier, recipient, fee, relayer) circuit-bound?

RELAYER
[ ] Is the fee parameter constrained by the circuit?
[ ] Is the recipient address constrained by the circuit?
[ ] Can the relayer front-run and redirect funds?
[ ] Is there a maximum fee cap?
[ ] Are relayers authenticated (whitelist) or permissionless?

POOL ACCOUNTING
[ ] Does pool balance always equal deposits - withdrawals?
[ ] Are fee-on-transfer tokens handled (actual vs nominal amount)?
[ ] Are rebasing tokens rejected or wrapped?
[ ] Can direct transfers inflate pool balance?
[ ] Are fees deducted consistently (from withdrawal, not from pool)?

GOVERNANCE & UPGRADES
[ ] Can governance change the verifier contract?
[ ] Can governance add/remove denominations?
[ ] Are proposals using CREATE2 / SELFDESTRUCT patterns?
[ ] Is there a timelock on governance actions?
[ ] Can governance drain the pool (emergency function)?

PRIVACY & ANONYMITY
[ ] What is the minimum anonymity set size before withdrawals are allowed?
[ ] Are there timing delays between deposit and withdrawal?
[ ] Is note encryption using authenticated encryption with random nonces?
[ ] Is the viewing key stored securely client-side?
[ ] Does bridging break the privacy chain?

CROSS-CHAIN
[ ] Are nullifier sets synchronized across chains?
[ ] Can proofs from chain A be replayed on chain B?
[ ] Is chainId included in nullifier derivation?
[ ] Is there a race condition in cross-chain nullifier sync?
```

---

## 4. Audit patterns for fast triage

```bash
# Nullifier handling
grep -rn "nullifier\|isSpent\|nullifierHash" src/ --include="*.sol"

# Merkle tree operations
grep -rn "insert\|nextIndex\|filledSubtrees\|currentRootIndex\|isKnownRoot" src/ --include="*.sol"

# Commitment scheme
grep -rn "commitment\|Poseidon\|MiMC\|Pedersen\|hashLeftRight" src/ --include="*.sol"

# ZK verifier calls
grep -rn "verifyProof\|verify(\|Verifier\|groth16\|plonk" src/ --include="*.sol"

# Relayer logic
grep -rn "relayer\|_relayer\|relayerFee\|fee\|recipient" src/ --include="*.sol"

# Pool accounting
grep -rn "denomination\|deposit\|withdraw\|balance\|transfer" src/ --include="*.sol"

# Governance/upgrade
grep -rn "upgradeProxy\|setVerifier\|changeVerifier\|owner\|admin\|governance" src/ --include="*.sol"

# Tree capacity
grep -rn "levels\|LEVELS\|TREE_DEPTH\|MAX_DEPOSITS\|nextIndex" src/ --include="*.sol"

# Cross-chain
grep -rn "chainId\|chain_id\|domainSeparator\|bridge\|crossChain" src/ --include="*.sol"

# Encryption (client-side note encryption)
grep -rn "encrypt\|decrypt\|viewingKey\|ephemeral\|nonce\|ciphertext" src/
```

---

## 5. Protocolos de Referencia

| Protocolo | Cadena | Modelo | Notas clave |
|-----------|--------|--------|-------------|
| Tornado Cash | ETH, BSC, Polygon | Fixed denomination, Groth16, MiMC | Referencia canónica. Governance attack (May 2023). OFAC sanctioned (Aug 2022). |
| Railgun | ETH, BSC, Polygon, Arbitrum | Variable amount, Poseidon, UTXO model | Privacy Pools / Proof of Innocence. No trusted setup (Groth16 with universal SRS). |
| Aztec (zk.money) | ETH L2 | Account-based, PLONK | $450K bounty for DeFi interaction bug. Shutdown Mar 2024. Building Aztec v3 (programmable privacy L2). |
| Zcash | Own chain | UTXO, Groth16 (Sapling), Halo2 (Orchard) | CVE-2019-7167 counterfeiting bug in Sprout. Sapling/Orchard are secure. |
| Light Protocol | Solana | Compressed accounts, Poseidon | OtterSec audit found hash collision, tree height, root assignment bugs. Solana-native privacy. |
| Hinkal | EVM multi-chain | Shielded DeFi, variable amount | Quantstamp audit found 8+ critical/high bugs: commitment duplication, tree overflow, accounting. |
| Elusiv | Solana | Privacy payments, Poseidon | OtterSec audit: nullifier trees clearable, proof verification DoS. Discontinued. |
| Nocturne | ETH | Stealth addresses + shielded pool | OtterSec snap audit. Protocol shut down. |
| Cyclone Protocol | IoTeX, BSC, Polygon | Tornado fork with yield farming | Fork of Tornado Cash with added DeFi composability. Reduced auditing. |
| Semaphore | EVM (library) | Identity groups, Poseidon | Not a mixer but foundational ZK identity primitive used by many privacy protocols. |
