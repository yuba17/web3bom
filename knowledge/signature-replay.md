# Signature & Replay Vulnerabilities -- Combat Briefing

> **Scope**: Solidity signature verification, replay attacks, permit abuse, and EIP-712 issues for bug bounty hunting.
> **Sources**: Solodit (solodit.cyfrin.io) -- 37 verified audit findings.
> **Last updated**: 2026-03-19

---

## Bug Patterns

```yaml
- id: sig-001
  pattern: signature-replay-same-chain
  name: "Signature replay attack (same chain, different context)"
  causa_raiz: "Signed messages lack sufficient context binding (nonce, contract address, or action-specific data). A valid signature for one action can be replayed to execute the same or different action again."
  como_funciona: "1. User signs a message authorizing action A (e.g., redeem deposits). 2. Transaction executes successfully. 3. Attacker replays the same signature to execute action A again because the contract does not mark the signature as consumed. 4. User's assets are drained or action is duplicated."
  invariante: "Every off-chain signature must be usable exactly once. After successful use, the signature (or its hash/nonce) must be marked as consumed and any replay must revert."
  que_mirar:
    - "Functions that accept signatures but do not store used hashes/nonces"
    - "Missing nonce increment after signature verification"
    - "batchId-based nonce systems where batchId itself is not validated"
    - "EIP-712 typed data that omits the contract address or action-specific fields"
    - "Functions like redeemDepositsAndInternalBalances that process signed redemptions"
  como_se_arregla: "Include a monotonically increasing nonce in the signed data. Increment the nonce on every successful use. Alternatively, store the hash of used signatures in a mapping and reject duplicates."
  trampas:
    - "The contract may use nonces but allow the same nonce across different batchIds -- check that ALL replay vectors are covered"
    - "Some replay protection exists but only for specific code paths, leaving others open"
  solodit_ids:
    - signature-missing-nonce-expiration-deadline-codehawks-sparkn-git
    - missing-nonce-validation-in-signature-verification-allows-transaction-replay-attacks-cyfrin-none-securitize-onofframp-bridge-markdown
    - 29-nonce-is-never-used-in-regards-to-the-weighted-signers-allowing-for-proofsignature-replay-code4rena-axelar-network-axelar-network-git
    - m-31-missing-nonce-reset-during-tss-address-update-allowing-signature-replay-sherlock-zetachain-cross-chain-git
    - h-05-signatures-can-be-replayed-in-withdraw-to-withdraw-more-tokens-than-the-user-originally-intended-code4rena-taiko-taiko-git
  incidentes:
    - "Solodit #36240: Beanstalk redeemDepositsAndInternalBalances -- no storage of used parameters allows replay (HIGH)"
    - "Solodit #6446: Biconomy SmartAccount -- first user transaction replayable due to batchId nonce bypass (HIGH)"
    - "Solodit #1579: Foundation NFTMarketPrivateSale -- EIP-712 private sale signature replayable if seller re-acquires NFT, no used-signature tracking (MEDIUM)"
    - "Solodit #1309: InsureDAO PoolTemplate -- Merkle proof replay in redeem(), only target+insured in hash allows cross-insurance replay (MEDIUM)"
    - "Solodit #6839: SeaDrop -- mintSigned signatures replayable up to maxMintsPerWallet, no per-signature invalidation (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [replay, nonce, signature-reuse, off-chain-signing]
  relacionado_con: [sig-002, sig-003]
```

```yaml
- id: sig-002
  pattern: cross-chain-signature-replay
  name: "Cross-chain signature replay (missing chainId in domain)"
  causa_raiz: "EIP-712 domain separator does not include chainId, or chainId is cached as immutable and not recalculated after a chain fork. Signatures valid on one chain can be replayed on another chain (fork or L2)."
  como_funciona: "1. User signs an EIP-712 message on Chain A. 2. Chain forks or protocol deploys on Chain B with same contract addresses. 3. Attacker takes the valid signature from Chain A and submits it on Chain B. 4. Signature verifies successfully because the domain separator matches (no chainId or stale chainId). 5. Attacker executes unauthorized action on Chain B."
  invariante: "EIP-712 domain separator must always include the current chainId. DOMAIN_SEPARATOR must be recomputed if block.chainid differs from the cached value at deployment."
  que_mirar:
    - "DOMAIN_SEPARATOR stored as immutable without runtime chainId check"
    - "EIP-712 typehash that omits chainId field"
    - "L1-to-L2 migration functions where signatures are verified without chain binding"
    - "Protocols deployed on multiple chains with identical contract addresses"
    - "Custom signing schemes that hash data without EIP-712 domain separator"
  como_se_arregla: "Always include chainId in the EIP-712 domain separator. Compute DOMAIN_SEPARATOR dynamically or cache with a chainId check: if (block.chainid != INITIAL_CHAIN_ID) return _computeDomainSeparator()."
  trampas:
    - "OpenZeppelin's EIP712 library handles this correctly since v4.x -- only flag custom implementations"
    - "Some protocols intentionally support cross-chain signatures (verify this is by design)"
  solodit_ids:
    - h-01-cross-chain-replay-in-borrowasset-swaptoborrow-kann-audits-none-rwa-markdown
    - m-01-join-signature-lacks-domain-separation-leading-to-cross-deploymentchain-replay-shieldify-none-soulsclub-revolver-markdown
    - lack-of-chainid-validation-allows-reuse-of-signatures-across-forks-trailofbits-advanced-blockchain-pdf
    - risk-of-reuse-of-signatures-across-forks-due-to-lack-of-chain-id-validation-trailofbits-none-maple-labs-pdf
    - h-01-cross-chain-signature-replay-attack-due-to-user-supplied-domainseparator-and-missing-deadline-check-code4rena-next-generation-next-generation-git
  incidentes:
    - "Solodit #38368: Aligned Layer -- missing chainId in signed data allows cross-chain replay (HIGH)"
    - "Solodit #27801: Bebop DEX -- DOMAIN_SEPARATOR stored as immutable, unsafe after chain fork (HIGH)"
    - "Solodit #60874: Level Finance LGO -- DOMAIN_SEPARATOR never initialized, signatures reusable across protocols (HIGH)"
    - "Solodit #13723: MCDEX Mai Protocol v2 -- signed order data reusable cross-chain, chainId not in signature (MEDIUM)"
    - "Solodit #36298: Beanstalk L2ContractMigrationFacet -- cross-chain replay in migration due to missing chainId (MEDIUM)"
    - "Solodit #6449: Biconomy VerifyingSingletonPaymaster -- getHash omits chainId, UserOperation replayable cross-chain (MEDIUM)"
    - "Solodit #8742: GolomTrader -- EIP712_DOMAIN_TYPEHASH computed in constructor with chainId, stale after hard fork (MEDIUM)"
    - "Solodit #7275: Brink EIP712SignerRecovery -- chainId passed as constructor param instead of block.chainid, deployer trust assumption (MEDIUM)"
    - "Solodit #3547: NFTPort Factory -- chainId not in signed data, signatures replayable across chains on multi-chain launch (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [cross-chain, chainId, domain-separator, EIP-712, fork, L2-migration]
  relacionado_con: [sig-001, sig-005]
```

```yaml
- id: sig-003
  pattern: missing-nonce-or-nonce-reuse
  name: "Missing nonce or nonce reuse in signed messages"
  causa_raiz: "The signed message does not include a nonce, or the nonce is not properly incremented/invalidated after use. This allows the same signature to be submitted multiple times."
  como_funciona: "1. User signs a message without a nonce (or with a reusable nonce). 2. Relayer or user submits the signed message. 3. Attacker copies the signature and submits it again. 4. Contract processes it again because there is no nonce to prevent replay. 5. Double-spend, double-redeem, or double-execution occurs."
  invariante: "Every signature-authenticated action must include a unique nonce. The nonce must be incremented atomically with the action execution. Replaying a used nonce must revert."
  que_mirar:
    - "Signed structs/messages that have no nonce field"
    - "Nonce stored per-address but not incremented after use"
    - "Nonce systems that allow gaps (e.g., bitmap nonces) without proper invalidation"
    - "batchId patterns where different batchIds share nonce space"
    - "Meta-transaction relayers that do not enforce nonce ordering"
  como_se_arregla: "Add a nonce field to the signed data. Use a mapping(address => uint256) nonce counter incremented on each use. For non-sequential nonces, use bitmap invalidation (like Permit2)."
  trampas:
    - "Some nonce schemes use bitmaps for gas efficiency -- verify the bitmap is properly set"
    - "ERC-2612 permit has built-in nonces -- the issue is in custom signing schemes"
  solodit_ids:
    - missing-signature-expiry-enables-perpetual-transaction-validity-codehawks-one-world-project-git
    - l-01-missing-deadline-and-nonce-in-signature-pashov-audit-group-none-hybux_2025-11-11-markdown
    - m-01-missing-time-limit-for-signature-kann-audits-none-rwa-markdown
  incidentes:
    - "Solodit #6446: Biconomy SmartAccount -- nonces[batchId] checked but batchId not validated, allowing replay via different batchIds (HIGH)"
    - "Solodit #36240: Beanstalk -- no nonce or hash storage for redeemDepositsAndInternalBalances (HIGH)"
    - "Solodit #6444: Biconomy VerifyingSingletonPaymaster -- paymaster signature replayable; attacker upgrades to MaliciousAccount and drains paymaster ETH (HIGH)"
    - "Solodit #6415: Ondo KYCRegistry -- no nonce in KYC signature, replay after revocation re-grants KYC (MEDIUM)"
    - "Solodit #1685: Rolla EIP712MetaTransaction -- failed tx does not increment nonce, signature replayable when conditions change (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [nonce, replay, meta-transaction, relayer]
  relacionado_con: [sig-001, sig-002]
```

```yaml
- id: sig-004
  pattern: ecrecover-returns-address-zero
  name: "ecrecover returns address(0) on invalid signature"
  causa_raiz: "The native ecrecover precompile returns address(0) when given an invalid signature instead of reverting. If the recovered address is not checked against address(0), an attacker can forge signatures for ownerless contracts or zero-address accounts."
  como_funciona: "1. Contract uses ecrecover(hash, v, r, s) to recover the signer. 2. Attacker provides an invalid/malformed signature. 3. ecrecover returns address(0) instead of reverting. 4. If the contract compares the recovered address against a stored owner that is address(0) (e.g., uninitialized or ownerless contract), the check passes. 5. Attacker gains unauthorized access."
  invariante: "The address recovered by ecrecover must always be checked: require(recoveredAddress != address(0) && recoveredAddress == expectedSigner)."
  que_mirar:
    - "Direct ecrecover calls without address(0) check"
    - "Contracts where the 'owner' or 'signer' can be address(0) (uninitialized state)"
    - "ERC-1271 isValidSignature implementations that fall through to ecrecover"
    - "Custom signature verification that does not use OpenZeppelin ECDSA library"
  como_se_arregla: "Use OpenZeppelin's ECDSA.recover() which reverts on invalid signatures. If using raw ecrecover, add require(recovered != address(0)) explicitly."
  trampas:
    - "OpenZeppelin ECDSA.recover() already handles this -- only flag raw ecrecover usage"
    - "The address(0) check alone is insufficient if signature malleability is also present"
  solodit_ids: []
  incidentes:
    - "Solodit #60156: AccessToken/Signer -- recoverSigner uses raw ecrecover, returns address(0) on invalid sig, allows false approval for ownerless contracts (MEDIUM)"
    - "Solodit #45173: Kakarot -- ecrecover returns valid address for out-of-range s values instead of address(0) (HIGH)"
    - "Solodit #7284: Astaria VaultImplementation -- ecrecover returns address(0) for phony sig, logic error (!= instead of ==) lets any borrower forge strategy (CRITICAL)"
    - "Solodit #870: Swivel -- ecrecover return value of 0 not checked, attacker sets o.maker to 0 to forge orders (HIGH)"
    - "Solodit #8753: GolomTrader validateOrder -- ecrecover return 0 not checked, bypassed when signer is 0 (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [ecrecover, address-zero, signature-validation, precompile]
  relacionado_con: [sig-005, sig-007]
```

```yaml
- id: sig-005
  pattern: eip712-domain-separator-issues
  name: "EIP-712 domain separator misconfiguration"
  causa_raiz: "The EIP-712 domain separator is incorrectly constructed, cached without invalidation, or broken by runtime state changes (e.g., token name update). This causes signature verification to fail or allows cross-context replay."
  como_funciona: "1. Protocol computes DOMAIN_SEPARATOR at deployment with initial parameters (name, version, chainId, verifyingContract). 2. A parameter changes at runtime (token name updated, chain forks, contract migrates). 3. DOMAIN_SEPARATOR is now stale. 4a. Legitimate signatures fail verification (DoS). 4b. Old signatures from pre-change context become valid in new context (replay)."
  invariante: "DOMAIN_SEPARATOR must reflect the current state of all its components at verification time. If any component can change, DOMAIN_SEPARATOR must be recomputed dynamically."
  que_mirar:
    - "DOMAIN_SEPARATOR stored as immutable but name/version can change"
    - "Token contracts with updateName() or updateSymbol() that do not recompute domain separator"
    - "Proxy contracts where verifyingContract is the proxy but domain was set in implementation"
    - "DOMAIN_SEPARATOR never initialized (left as bytes32(0))"
    - "Custom EIP-712 implementations that omit required fields"
  como_se_arregla: "Use OpenZeppelin's EIP712 library which handles dynamic recomputation. If caching, always check block.chainid and recompute on mismatch. If name is mutable, recompute DOMAIN_SEPARATOR on name change."
  trampas:
    - "Most modern implementations handle this correctly -- focus on custom or older implementations"
    - "Some protocols intentionally cache for gas savings and accept the fork risk"
  solodit_ids:
    - the-eip-712-domain-separator-is-missing-the-version-field-spearbit-none-sphinx-pdf
    - domainseparatorv4-not-updated-after-name-symbol-change-spearbit-connext-pdf
    - lyswp2-5-immutable-domain_separator-becomes-invalid-after-a-hard-fork-hexens-none-train-protocol-markdown
    - m-04-verifyingcontract-set-incorrectly-for-eip712-domain-separator-zachobront-none-hook-markdown
    - domain_separator-in-uniswapv2erc20-will-be-invalid-after-chain-forks-cantina-none-sweep-n-flip-pdf
  incidentes:
    - "Solodit #27801: Bebop -- DOMAIN_SEPARATOR cached as immutable, stale after chain fork (HIGH)"
    - "Solodit #60874: Level Finance -- DOMAIN_SEPARATOR never initialized (HIGH)"
    - "Solodit #64482: StandardToken -- updateNameAndSymbol breaks domain separator for permit (MEDIUM)"
    - "Solodit #7144: BridgeToken -- setDetails updates name/symbol but _CACHED_DOMAIN_SEPARATOR not recomputed, permit uses stale separator (MEDIUM)"
    - "Solodit #2507: Rubicon BathToken -- DOMAIN_SEPARATOR computed before name is set in initialize(), uses empty string (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [EIP-712, domain-separator, permit, immutable, name-change]
  relacionado_con: [sig-002, sig-006]
```

```yaml
- id: sig-006
  pattern: permit-frontrun-dos
  name: "Permit front-running causes DoS on permit-dependent functions"
  causa_raiz: "Functions that call permit() as part of their execution flow revert if the permit has already been consumed. An attacker can front-run the transaction, extract the permit signature from the mempool, and call permit() directly, causing the victim's transaction to revert."
  como_funciona: "1. User signs a permit and submits a transaction that calls permitAndDeposit() or similar. 2. Attacker sees the pending transaction in the mempool. 3. Attacker extracts (v, r, s, deadline, amount) from calldata. 4. Attacker front-runs by calling permit() directly with the same parameters. 5. The permit nonce advances. 6. Victim's transaction reverts because the permit nonce is now invalid. 7. User loses gas fees and the operation is denied."
  invariante: "Functions that use permit() must not revert if the permit has already been executed. They should wrap permit() in a try/catch or check allowance before calling permit()."
  que_mirar:
    - "Any function that calls IERC20Permit.permit() followed by transferFrom()"
    - "Router contracts with supplyWithPermit(), repayWithPermit(), depositWithPermit(), removeLiquidityWithPermit()"
    - "Batch operations that include permit as a step"
    - "Functions using Permit2 that can be front-run similarly"
    - "Whether the function has a fallback path (check allowance, skip permit if already granted)"
  como_se_arregla: "Wrap permit() in try/catch. If permit fails, check if allowance is already sufficient and proceed. OpenZeppelin's SafeERC20.safePermit does NOT solve this -- you need explicit try/catch with allowance fallback."
  trampas:
    - "This is a DoS (griefing) issue, typically Medium severity -- not a fund loss"
    - "Some judges consider this a known limitation of ERC-2612 and may downgrade"
    - "Verify the front-running is actually possible on the target chain (private mempools, L2 sequencers)"
  solodit_ids:
    - m-25-same-contract-multi-permits-fundamentally-cannot-be-solved-via-the-chosen-standards-code4rena-tapioca-dao-tapioca-dao-git
    - permit-call-success-check-enables-front-running-dos-cantina-none-eco-inc-pdf
    - m-10-erc-2612-permit-front-running-in-routerv2-enables-dos-of-liquidity-operations-code4rena-audit-507-audit-507-git
    - permit-signatures-can-be-front-run-to-execute-a-temporary-denial-of-service-attack-trailofbits-none-balancer-v3-pdf
    - permit-front-running-can-dos-requestmintwithpermit-spearbit-none-buck-labs-pdf
  incidentes:
    - "Solodit #58344: RouterV2 -- removeLiquidityWithPermit front-runnable, causes DoS (MEDIUM)"
    - "Solodit #52794: Router.sol -- depositWithPermit2 and repayWithPermit2 front-runnable (MEDIUM)"
    - "Solodit #38294: Manta Pool -- supplyWithPermit/repayWithPermit DoS via front-run (MEDIUM)"
    - "Solodit #38293: Manta Pool -- supplyWithPermit/repayWithPermit invalidated by attacker (MEDIUM)"
    - "Solodit #38322: zkSync -- DoS by front-runnable permit external call (MEDIUM)"
    - "Solodit #31669: TRANSFER_FROM_WITH_PERMIT command DOS via frontrunning (MEDIUM)"
    - "Solodit #49051: LoopFi SwapAction -- ERC20 permit transferFrom front-runnable (MEDIUM)"
    - "Solodit #49062: PositionAction increaseLever -- incorrect spender in permit causes revert (MEDIUM)"
    - "Solodit #61182: Hardcoded deadline in permit messes up structHash, invalid signature (MEDIUM)"
    - "Solodit #63340: flashMintWithPermit -- oracle price change between signing and execution invalidates permit amount (MEDIUM)"
    - "Solodit #64809: requestMintWithPermit -- permit front-runnable, causes DoS on mint flow (LOW)"
    - "Solodit #64483: StandardToken transferWithPermit -- DoS via front-running direct permit() call (LOW)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [permit, front-running, DoS, ERC-2612, griefing, Permit2]
  relacionado_con: [sig-005, sig-008]
```

```yaml
- id: sig-007
  pattern: signature-malleability
  name: "Signature malleability (s-value in upper half of curve)"
  causa_raiz: "ECDSA signatures have an inherent malleability: for every valid signature (r, s, v), there exists a second valid signature (r, n-s, v') where n is the secp256k1 curve order. If the contract does not enforce s to be in the lower half of the curve (s <= n/2), an attacker can produce a second valid signature for the same message."
  como_funciona: "1. User produces signature (v, r, s) for a message. 2. Attacker computes (v', r, secp256k1n - s) which is also valid for the same message. 3. If the contract uses the signature hash as a unique identifier (e.g., to prevent replay), the attacker bypasses replay protection with the malleable variant. 4. Action is executed twice or signature-based tracking is circumvented."
  invariante: "All signature verification must reject signatures where s > secp256k1n/2 (EIP-2). The ecrecover result must be identical regardless of signature form."
  que_mirar:
    - "Raw ecrecover usage without s-value range check"
    - "Custom ECDSA verification in Solidity, Go, or zkASM that omits the s <= n/2 check"
    - "Transaction processing in L2/rollup VMs (zkEVM, Kakarot) that accepts high-s values"
    - "Bridge or cross-chain signature verification (e.g., Bitcoin redemption signatures)"
    - "Signature-based deduplication where the sig hash is the unique key"
  como_se_arregla: "Use OpenZeppelin ECDSA.recover() which enforces low-s. For raw ecrecover, add: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0). For L2/zkVM, enforce EIP-2 in transaction processing."
  trampas:
    - "If replay protection uses nonces (not signature hashes), malleability alone is not exploitable"
    - "Many auditors flag this as informational if nonce-based replay protection exists"
    - "In zkEVM contexts, this can be higher severity because it affects consensus-level transaction validation"
  solodit_ids:
    - h-01-signature-malleability-of-evms-ecrecover-in-verify-code4rena-larvalabs-meebits-larvalabs-meebits-git
    - direct-usage-of-ecrecover-allows-for-signature-malleability-halborn-holograph-protocol-markdown
    - using-ecrecover-directly-vulnerable-to-signature-malleability-cyfrin-none-bima-markdown
    - ecdsa-signature-malleability-quantstamp-mezo-portal-markdown
    - l-03-direct-usage-of-ecrecover-allows-signature-malleability-code4rena-reality-cards-reality-cards-contest-git
  incidentes:
    - "Solodit #42171: NFT marketplace verify() -- ecrecover malleability, mitigated by offer cancellation but fragile (HIGH)"
    - "Solodit #3968: putForSale verify() -- same ecrecover malleability pattern (HIGH)"
    - "Solodit #35620: Custom ecrecover -- potential malleability without s-value check (MEDIUM)"
    - "Solodit #49758: zkEVM ecrecover.zkasm -- incorrect s-value limit check in zkASM implementation (MEDIUM)"
    - "Solodit #62040: recoverSigner -- malleability in unused function (MEDIUM)"
    - "Solodit #52084: Lombard consortium node -- malleability in Go signature verification (MEDIUM)"
    - "Solodit #45173: Kakarot -- three valid signatures instead of two due to non-standard ecrecover (HIGH)"
    - "Solodit #21369: zkEVM transaction processing -- does not reject malleable signatures at consensus level (HIGH)"
    - "Solodit #13780: tBTC -- high-s values accepted in Bitcoin redemption signatures (MEDIUM)"
    - "Solodit #3378: Harpie -- OpenZeppelin ECDSA < 4.7.3 vulnerability, signatures used for replay protection exploitable via malleability (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [malleability, ecrecover, s-value, EIP-2, secp256k1, zkEVM]
  relacionado_con: [sig-004, sig-001]
```

```yaml
- id: sig-008
  pattern: erc1271-isValidSignature-issues
  name: "ERC-1271 isValidSignature bypass or replay"
  causa_raiz: "Smart contract wallets use ERC-1271 isValidSignature() for signature verification. If the implementation lacks context binding (no contract address, no nonce, no action hash in the signed data), signatures can be replayed across accounts that share the same owner/validator."
  como_funciona: "1. User owns multiple smart contract wallets (Account A and Account B) with the same signing key. 2. User signs a message for Account A. 3. Attacker submits the same signature to Account B. 4. Account B's isValidSignature verifies the raw hash against the shared owner key -- it passes. 5. Attacker executes unauthorized action on Account B using Account A's signature."
  invariante: "isValidSignature must bind the signature to the specific contract instance. The signed hash must include the verifying contract's address, or the contract must validate that the signature was intended for it."
  que_mirar:
    - "isValidSignature implementations that verify raw hash without binding to address(this)"
    - "Accounts with shared owners/validators across multiple smart wallets"
    - "ERC-1271 + EIP-712 where the domain separator uses a different verifyingContract"
    - "Fallback from ERC-1271 to ECDSA without proper differentiation"
    - "Session keys or validators that are shared across account instances"
  como_se_arregla: "Include address(this) in the signed hash or use EIP-712 with verifyingContract set to the account address. Validate that the signature's domain matches the calling contract."
  trampas:
    - "If each account has unique owners, cross-account replay is not possible"
    - "Some protocols intentionally allow shared validation (e.g., multi-sig with same signers) -- verify intent"
  solodit_ids: []
  incidentes:
    - "Solodit #56710: zkSync SSO Clave ERC1271Handler -- insufficient checks in isValidSignature allow replay (HIGH)"
    - "Solodit #40900: Clave isValidSignature -- signature replay across accounts with shared owners (HIGH)"
    - "Solodit #6452: Biconomy SmartAccount -- wrong ERC1271_MAGIC_VALUE (0x20c13b0b vs 0x1626ba7e) and wrong function signature, isValidSignature always fails (MEDIUM)"
    - "Solodit #6443: Biconomy SmartAccount -- insufficient ERC-1271 signature validation allows arbitrary transactions, attacker can steal all funds (HIGH)"
    - "Solodit #63762: Sequence SessionSig -- session signatures replay across wallets due to missing wallet address in hash (MEDIUM)"
    - "Solodit #57707: FactCheckExchange -- EIP-7702 makes EOAs appear as contracts, ERC-1271 path fails (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [ERC-1271, smart-wallet, isValidSignature, account-abstraction, replay]
  relacionado_con: [sig-001, sig-004]
```

```yaml
- id: sig-009
  pattern: permit-token-mismatch
  name: "Permit signature does not bind to the correct token or spender"
  causa_raiz: "Permit2 or ERC-2612 permit verification does not check that the token address in the permit matches the expected token. An attacker crafts a permit for a worthless token and uses it where a valuable token is expected."
  como_funciona: "1. Vault accepts deposits via Permit2 transferFrom. 2. The permit verification does not validate that the token in the permit matches the vault's asset (e.g., USDC). 3. Attacker creates a permit for a worthless ERC20 token. 4. Attacker calls deposit with the worthless token's permit. 5. Vault credits the attacker as if they deposited USDC. 6. Attacker withdraws real USDC from the vault."
  invariante: "Permit-based transfers must validate that the token address in the permit/signature matches the expected token address. The spender must match the contract performing the transfer."
  que_mirar:
    - "Permit2.permitTransferFrom calls that do not specify or validate the token field"
    - "Vault deposit/repay functions that use permit without checking token == asset"
    - "Incorrect spender address in permit verification (e.g., proxy vs router)"
    - "Batch permit operations where token validation is skipped per-item"
  como_se_arregla: "Always specify the expected token address in the ISignatureTransfer.TokenPermissions struct. Validate that permit.token == expectedAsset. For spender, use address(this) or the correct downstream contract."
  trampas:
    - "Permit2 has a token field in the permit struct -- the issue is when the contract does not set/check it"
    - "This can be Critical if it allows direct fund theft from the vault"
  solodit_ids: []
  incidentes:
    - "Solodit #32261: Revert Lend V3Vault -- permit2 does not check token is USDC, attacker can steal all USDC (HIGH)"
    - "Solodit #49062: LoopFi PositionAction -- incorrect spender address in permit causes revert or bypass (MEDIUM)"
    - "Solodit #30529: Rental NFT -- malicious borrower uses permit() to hijack rented NFT with ERC-721 permit (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [permit2, token-mismatch, spender, ERC-2612, fund-theft]
  relacionado_con: [sig-006, sig-010]
```

```yaml
- id: sig-010
  pattern: permit-signature-theft-frontrun
  name: "Permit/Permit2 signature theft via front-running for fund extraction"
  causa_raiz: "Functions that accept permit signatures and perform swaps or transfers allow anyone to submit the signature. An attacker front-runs the victim's transaction, extracts the permit signature, and uses it with malicious parameters (e.g., amountOutMin = 0) to steal funds via MEV."
  como_funciona: "1. User signs a permit allowing a router/protocol to spend their tokens. 2. User submits a transaction with the permit and swap parameters (e.g., amountOutMin for slippage protection). 3. Attacker sees the pending tx, extracts the permit signature. 4. Attacker submits their own tx using the same permit but with amountOutMin = 0 or routing through an attacker-controlled pool. 5. Attacker sandwiches or extracts maximum MEV from the swap. 6. User's tokens are spent with no slippage protection."
  invariante: "Permit signatures must bind to the full transaction intent (recipient, minimum output, route). The contract must verify that the caller is the intended beneficiary or that critical parameters are inside the signed data."
  que_mirar:
    - "Router/swap functions that accept permit + swap params where swap params are NOT in the signed data"
    - "pullTokensWithPermit patterns where anyone can call with a valid permit"
    - "Permit2 batch operations where intent verification is missing"
    - "Functions where the permit signer and the beneficiary of the action can differ"
    - "Plugin/module architectures where permit2 signatures are passed to untrusted plugins"
  como_se_arregla: "Include critical parameters (minAmountOut, recipient, route hash) in the signed data. Alternatively, require msg.sender == permit signer. For Permit2, use the witness field to bind to transaction intent."
  trampas:
    - "This is a real fund-loss vector, not just griefing -- severity is High/Critical"
    - "Permit2's witness mechanism exists specifically to solve this -- check if it is used"
    - "On L2s with private mempools, front-running may not be possible -- verify per chain"
  solodit_ids: []
  incidentes:
    - "Solodit #53124: FlashSwapRouter -- attacker front-runs ERC-2612 swap with amountOutMin = 0, steals via MEV (HIGH)"
    - "Solodit #49644: BakerFi pullTokensWithPermit -- anyone can call with valid permit to steal tokens (HIGH)"
    - "Solodit #54669: SablierV2ProxyTarget -- permit2 signature reusable by malicious plugins to steal funds (HIGH)"
    - "Solodit #30445: Arcadia flashActionByCreditor -- permit-based flash action drains account assets (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [permit2, MEV, front-running, fund-theft, signature-theft, swap]
  relacionado_con: [sig-006, sig-009]
```

```yaml
- id: sig-011
  pattern: permit-deadline-hardcoded
  name: "Hardcoded or mismatched permit deadline breaks signature"
  causa_raiz: "The contract hardcodes the deadline parameter when calling permit() (e.g., block.timestamp + 300), but the user signed with a different deadline. The structHash mismatch causes the permit to always revert."
  como_funciona: "1. User signs a permit with deadline = X. 2. Contract calls permit() with deadline = block.timestamp + 300 (hardcoded). 3. The structHash computed on-chain uses the hardcoded deadline, which differs from the user's signed deadline. 4. Signature verification fails. 5. Transaction reverts -- permanent DoS for permit-based flows."
  invariante: "The deadline passed to permit() on-chain must exactly match the deadline the user included in their off-chain signature. No parameter of the signed struct may be altered between signing and verification."
  que_mirar:
    - "Hardcoded block.timestamp + N as deadline in permit() calls"
    - "Permit parameters derived from on-chain state that can change between signing and execution (oracle prices, exchange rates)"
    - "Mismatch between the struct fields signed off-chain and the values passed on-chain"
  como_se_arregla: "Accept the deadline as a function parameter from the user. Pass all permit parameters exactly as the user signed them. Never substitute or modify any field of the signed struct."
  trampas:
    - "This is a DoS issue, not a fund theft -- typically Medium severity"
    - "Some implementations use type(uint256).max as deadline which always works but has other implications"
  solodit_ids: []
  incidentes:
    - "Solodit #61182: Pledge function -- hardcoded block.timestamp + 300 as deadline breaks structHash (MEDIUM)"
    - "Solodit #63340: flashMintWithPermit -- oracle price change between signing and execution invalidates permit amount (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [permit, deadline, structHash, DoS, ERC-2612]
  relacionado_con: [sig-006, sig-005]
```

```yaml
- id: sig-012
  pattern: l2-migration-signature-issues
  name: "L2 migration signature verification flaws"
  causa_raiz: "During L1-to-L2 protocol migrations, signature-based redemption mechanisms have insufficient validation -- missing chainId, replayable signatures, or inability for contract accounts to produce required signatures."
  como_funciona: "1. Protocol migrates from L1 to L2, requiring users to sign redemption messages. 2. Signature verification omits chainId, allowing replay from L1 on L2 fork. 3. Alternatively, smart contract wallets on L1 cannot produce the required ECDSA signatures, locking their funds. 4. Users either lose funds to replay or are permanently stuck on L1."
  invariante: "Migration signatures must include chainId and the target L2 contract address. The system must support both EOA (ECDSA) and contract wallet (ERC-1271) signature verification."
  que_mirar:
    - "L1-to-L2 migration facets or bridges with signature-based redemption"
    - "Whether ERC-1271 is supported for contract wallet migration"
    - "Whether chainId is included in the migration signature"
    - "Whether the same signature can be used on both L1 and L2"
  como_se_arregla: "Include chainId and target contract address in all migration signatures. Support ERC-1271 for contract wallets. Use EIP-712 compliant signatures with proper domain separator."
  trampas:
    - "Contract wallets may have different addresses on L2 -- verify address mapping logic"
    - "Migration windows may be time-limited, adding urgency to fixes"
  solodit_ids: []
  incidentes:
    - "Solodit #36298: Beanstalk L2ContractMigrationFacet -- cross-chain replay in migration signatures (MEDIUM)"
    - "Solodit #36271: Beanstalk -- contract wallet users stuck on L1, cannot migrate beans (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit (solodit.cyfrin.io)"
  tags: [L2-migration, cross-chain, contract-wallet, ERC-1271, chainId]
  relacionado_con: [sig-002, sig-008]

- id: sig-013
  pattern: unsigned-parameters-in-signed-action
  name: "Critical action parameters excluded from signed data"
  causa_raiz: "The EIP-712 struct or hashed message omits parameters that affect the outcome of the action (e.g., duration, recipient, token amounts, contract address). An attacker reuses a valid signature while substituting unsigned parameters to change the action's effect."
  como_funciona: |
    1. Backend/user signs a struct covering SOME parameters (e.g., tokenId, amount, deadline).
    2. The function accepts ADDITIONAL parameters not in the signed struct (e.g., durationDays, route, target contract).
    3. Attacker intercepts or obtains the valid signature.
    4. Attacker calls the function with the same signed params but substitutes the unsigned params (e.g., 7-day term -> 30-day term, or replays across contracts that share the same signer).
    5. The signature passes verification, but the action executes with attacker-chosen parameters.
  invariante: |
    // Every parameter that affects the outcome must be in the signed struct
    bytes32 structHash = keccak256(abi.encode(TYPEHASH, ALL_ACTION_PARAMS));
    // If param X affects fees/duration/routing, assert X is in TYPEHASH
  que_mirar:
    - "Compare function parameters vs EIP-712 TYPEHASH fields — any mismatch is a finding"
    - "grep -rn 'TYPEHASH' --include='*.sol' and compare with function signatures"
    - "keccak256(abi.encode(TYPEHASH,... missing fields"
    - "Functions accepting user-supplied routing/duration/recipient not in signed data"
    - "Cross-contract replay: hash does not include address(this) or contract-specific identifier"
  como_se_arregla: "Include ALL parameters that affect the action outcome in the signed struct. Add address(this) to prevent cross-contract replay. If a parameter is intentionally unsigned, document why and ensure it cannot be exploited."
  trampas:
    - "LOW if the unsigned parameter has a narrow valid range enforced on-chain (e.g., enum with 2 values)"
    - "Some parameters may be intentionally flexible (e.g., gas limit) — verify actual impact"
  solodit_ids: []
  incidentes:
    - "Solodit #64685: PawnShop — durationDays not in signed quote, borrower swaps 7-day to 30-day term (LOW)"
    - "Solodit #3099: Rigor Community/Project — untyped data signing, keccak256(abi.encode()) without EIP-712 struct allows cross-context replay (HIGH)"
    - "Solodit #63684: NFTStaking — hash omits contract address, signature replayed across 3 staking contracts to inflate rarity weights (HIGH)"
    - "Solodit #41149: BaseRouter — _getRawData concatenates ops+params without separators, attacker reshuffles params across operations (HIGH)"
    - "Solodit #1579: Foundation NFTMarketPrivateSale — EIP-712 private sale signature reusable if seller re-acquires NFT, no used-signature tracking (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, unsigned-params, EIP-712, cross-contract, struct-mismatch]

- id: sig-014
  pattern: eip712-typehash-encoding-mismatch
  name: "EIP-712 typehash does not match actual abi.encode fields"
  causa_raiz: "The TYPEHASH string declares one set of fields (or field types), but the abi.encode used to build the structHash includes different fields, extra fields, or encodes nested structs incorrectly (e.g., passing struct directly instead of hashStruct). Signatures computed off-chain against the correct EIP-712 spec will never match on-chain verification."
  como_funciona: |
    1. Contract defines TYPEHASH = keccak256("MyStruct(uint256 a,uint256 b)").
    2. Contract computes structHash = keccak256(abi.encode(TYPEHASH, a, b, c)) — extra field c.
    3. Off-chain signer follows EIP-712 spec and hashes only (TYPEHASH, a, b).
    4. Hashes never match — all signature-based flows permanently revert (DoS).
    5. Alternatively: nested struct passed raw instead of as hashStruct — different hash, same DoS or bypass.
  invariante: |
    // TYPEHASH field count must equal abi.encode argument count (minus TYPEHASH itself)
    // Nested structs must use keccak256(abi.encode(NESTED_TYPEHASH, ...))
    assert(countFields(TYPEHASH_STRING) == countArgs(abi_encode_call) - 1);
  que_mirar:
    - "DOMAIN_TYPEHASH string fields vs abi.encode in _buildDomainSeparator"
    - "Struct TYPEHASH field count vs abi.encode argument count"
    - "Nested struct in EIP-712: look for raw struct passed to abi.encode instead of hashStruct"
    - "grep -rn 'TYPEHASH.*keccak256' --include='*.sol' — compare string with encode"
    - "Missing 'version' or extra 'version' field mismatch between DOMAIN_TYPEHASH and separator"
  como_se_arregla: "Ensure TYPEHASH string exactly matches the fields and types in abi.encode. For nested structs, compute hashStruct recursively per EIP-712 spec. Use reference implementations (OpenZeppelin EIP712) as ground truth."
  trampas:
    - "This is often a DoS (signatures never verify) rather than a bypass — severity depends on whether fallback paths exist"
    - "Some contracts never actually verify signatures on-chain (off-chain only) — no on-chain impact"
  solodit_ids: []
  incidentes:
    - "Solodit #58347: BlackHole VotingEscrow — DOMAIN_TYPEHASH has 3 fields but abi.encode has 4 (includes version), delegation signatures always fail (MEDIUM)"
    - "Solodit #27569: Brahma TypeHashHelper — incorrect typehash for Validation and Transaction structs, not EIP-712 compliant (MEDIUM)"
    - "Solodit #27422: Sparkn ProxyFactory — digest missing typeHash and hashStruct for data param, not EIP-712 compliant (MEDIUM)"
    - "Solodit #6840: SeaDrop mintSigned — MintParams struct passed raw to abi.encode instead of as hashStruct (MEDIUM)"
    - "Solodit #2507: Rubicon BathToken — DOMAIN_SEPARATOR computed with uninitialized name (empty string), permit always fails (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [EIP-712, typehash, encoding, DoS, struct-hash, domain-separator]

- id: sig-015
  pattern: signature-verification-bypass-privileged-or-zero
  name: "Signature verification skipped for privileged addresses or zero-address signer"
  causa_raiz: "The verification function has a short-circuit path that skips signature checks for privileged addresses, or returns success when the configured signer is address(0). An attacker either sets the creator field to a privileged address or exploits an uninitialized/zeroed signer to bypass all auth."
  como_funciona: |
    1. Contract has a list of privileged addresses that skip signature verification, OR signer config is address(0).
    2. For privileged skip: attacker puts a privileged address as the 'creator' field in their order — verification passes without a valid signature.
    3. For zero-signer: contract checks require(ECDSA.recover(hash, sig) == permitSigner), but permitSigner == address(0). Attacker sends an invalid signature, ecrecover returns address(0), check passes.
    4. Attacker executes arbitrary orders/actions with no valid authorization.
  invariante: |
    // Signer must never be address(0)
    require(configuredSigner != address(0), "signer not set");
    // Privileged skip must verify msg.sender == privileged, not just a field in the data
    require(msg.sender == privilegedAddr || verifySignature(data, sig), "unauthorized");
  que_mirar:
    - "if (privileged[creator]) return true — skips signature check based on data field, not msg.sender"
    - "permitSigner == address(0) allowing ecrecover(invalid) == address(0) to match"
    - "Uninitialized signer storage slots in upgradeable contracts"
    - "grep -rn 'return true' in signature verification functions"
    - "grep -rn 'address(0)' near ecrecover or ECDSA.recover"
  como_se_arregla: "Never skip signature verification based on user-supplied data fields. Privileged bypass must check msg.sender. Always require(signer != address(0)) before comparing recovered address. Initialize signer in constructor/initializer."
  trampas:
    - "Some protocols intentionally allow admin bypass — verify if msg.sender is checked (safe) vs data field (unsafe)"
    - "address(0) check may already exist via OpenZeppelin ECDSA — only flag raw ecrecover"
  solodit_ids: []
  incidentes:
    - "Solodit #64745: Order verification — skips signature check when creator is in privileged_addresses, any user can set creator field to privileged address (HIGH)"
    - "Solodit #63978: HarTokenSale — permitSigner set to address(0) disables all access controls, anyone can self-whitelist (MEDIUM)"
    - "Solodit #7284: Astaria VaultImplementation — ecrecover returns address(0) for phony sig, check uses != instead of ==, any borrower forges strategy (CRITICAL)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature-bypass, privileged, address-zero, ecrecover, access-control]

- id: sig-016
  pattern: failed-tx-nonce-not-consumed
  name: "Failed transaction does not consume nonce, enabling signature replay"
  causa_raiz: "When a meta-transaction or batched call reverts, the entire transaction rolls back including the nonce increment. The signature remains valid and can be replayed later when conditions change, potentially executing an action the user no longer intends."
  como_funciona: |
    1. User signs a meta-transaction with nonce N.
    2. Relayer submits the transaction; it reverts due to some condition (e.g., insufficient balance, price change).
    3. The revert rolls back the nonce increment — nonce is still N.
    4. Conditions change later (user receives funds, price returns to favorable level).
    5. Attacker replays the original signature — nonce N is still valid.
    6. Transaction executes successfully in a context the user did not intend.
  invariante: |
    // Nonce must be consumed regardless of inner call success
    // Pattern: increment nonce BEFORE execution, use try/catch for inner call
    nonces[signer]++;
    (bool success, bytes memory ret) = target.call(data);
    // Do NOT revert if inner call fails — emit event instead
  que_mirar:
    - "Meta-transaction executors that revert on inner call failure (require(success))"
    - "Nonce increment inside the same transaction that can revert"
    - "BEHAVIOR_REVERT_ON_ERROR in batched calls — partial execution possible after revert"
    - "Session-based signatures where nonce is consumed only on full success"
    - "grep -rn 'revert.*nonce\\|nonce.*revert' --include='*.sol'"
  como_se_arregla: "Always consume the nonce before executing the inner call. If the inner call fails, emit a failure event but do NOT revert the outer transaction. Alternatively, use a deadline-based expiry so stale signatures eventually become invalid."
  trampas:
    - "If the signature has a short deadline (e.g., 5 minutes), replay window may be too small to be practical"
    - "Some protocols intentionally allow retry of failed txs — verify if this is by design"
  solodit_ids: []
  incidentes:
    - "Solodit #1685: Rolla EIP712MetaTransaction — executeMetaTransaction reverts on failed low-level call, nonce unchanged, replay possible (HIGH)"
    - "Solodit #63761: Sequence Calls — session call with BEHAVIOR_REVERT_ON_ERROR fails, nonce not consumed, attacker replays partial call subset (HIGH)"
    - "Solodit #63768: Sequence — nonce consumption reverts on execution failure enabling signature replay (LOW)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [nonce, replay, meta-transaction, revert, failed-tx, session]

- id: sig-017
  pattern: abi-encodepacked-hash-collision
  name: "abi.encodePacked with dynamic types allows hash collision in signed data"
  causa_raiz: "The signed message hash uses abi.encodePacked with two or more dynamic types (string, bytes, arrays). Because encodePacked does not length-prefix dynamic types, an attacker can shift bytes between adjacent dynamic fields to produce the same hash for different inputs."
  como_funciona: |
    1. Contract hashes signed data: keccak256(abi.encodePacked(stringA, stringB)).
    2. abi.encodePacked("ab", "cd") == abi.encodePacked("a", "bcd") == abi.encodePacked("abcd", "").
    3. Attacker crafts different input values that produce the same hash.
    4. A signature valid for (stringA="ab", stringB="cd") is also valid for (stringA="a", stringB="bcd").
    5. Attacker uses the collision to bypass signedOnly modifiers or forge actions.
  invariante: |
    // Never use abi.encodePacked with multiple dynamic types
    // Use abi.encode instead (length-prefixed, no collisions)
    bytes32 hash = keccak256(abi.encode(param1, param2));
  que_mirar:
    - "keccak256(abi.encodePacked(... with 2+ dynamic args (string, bytes, dynamic arrays)"
    - "grep -rn 'encodePacked' --include='*.sol' near signature/hash verification"
    - "Factory contracts with signature-based deploy using encodePacked for hash"
    - "Operations arrays concatenated without length prefixes in _getRawData patterns"
  como_se_arregla: "Replace abi.encodePacked with abi.encode for all signature-related hashing. If encodePacked is needed for gas, ensure at most one dynamic type is present, or add explicit length prefixes."
  trampas:
    - "If all fields are fixed-size types (uint256, address, bytes32), encodePacked is safe"
    - "The collision may not be exploitable if other constraints (e.g., valid address) narrow the space"
  solodit_ids:
    - typed-signatures-implement-insecure-nonstandard-encodings-trailofbits-meson-protocol-pdf
    - hash-collisions-in-untyped-signatures-trailofbits-meson-protocol-pdf
    - m-1-abiencodepacked-allows-hash-collision-sherlock-nftport-nftport-git
    - non-injective-hash-encoding-in-getclaimkeyhash-trailofbits-paraspace-pdf
    - multichaincompact-and-batchcompact-incompatible-with-erc712-due-to-incorrect-hashing-spearbit-none-uniswap-the-compact-pdf
  incidentes:
    - "Solodit #3546: NFTPort Factory — abi.encodePacked with multiple dynamic types in signedOnly modifier, hash collision bypasses signature check (MEDIUM)"
    - "Solodit #41149: EYWA BaseRouter — _getRawData concatenates operation params without separators, different parameter splits produce same hash (HIGH)"
    - "Solodit #3547: NFTPort Factory — arbitrary data as signature in deploy/call methods combined with encodePacked collision (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [abi-encodePacked, hash-collision, signature-bypass, dynamic-types]

- id: sig-018
  pattern: eip7702-eoa-contract-detection-broken
  name: "EIP-7702/EIP-3074 breaks EOA vs contract signature verification logic"
  causa_raiz: "Signature verification distinguishes EOA from smart contract wallets using code size checks (isContract, extcodesize, msg.sender == tx.origin). EIP-7702 allows EOAs to temporarily delegate to code, making them appear as contracts. The isContract check returns true for an EOA, routing to ERC-1271 verification which fails or produces unexpected results."
  como_funciona: |
    1. Contract checks if signer.code.length > 0 to decide EOA (ECDSA) vs contract (ERC-1271).
    2. User activates EIP-7702 delegation, attaching code to their EOA.
    3. isContract(user) now returns true even though user has a private key.
    4. Contract routes to ERC-1271 isValidSignature() instead of ECDSA.recover().
    5. If the delegated code does not implement ERC-1271, the call reverts — DoS.
    6. If the delegated code has a permissive isValidSignature, unauthorized actions may pass.
  invariante: |
    // Do not rely on code size to distinguish signature types
    // Try ECDSA first, fall back to ERC-1271 if it fails
    // Or: accept both signature types regardless of code presence
  que_mirar:
    - "isContract() or extcodesize checks used to branch signature verification"
    - "msg.sender == tx.origin used to enforce EOA-only"
    - "grep -rn 'isContract\\|extcodesize\\|code.length' --include='*.sol' near signature flows"
    - "onlyEOA modifiers that may break under EIP-7702/3074"
  como_se_arregla: "Try ECDSA.recover first. If it fails or returns wrong address, fall back to ERC-1271 isValidSignature. Do not use code size as the sole discriminator. Alternatively, accept an explicit flag from the caller indicating signature type."
  trampas:
    - "EIP-7702 is post-Pectra only — verify target chain supports it before reporting"
    - "If protocol already handles both paths with try/catch, this is a non-issue"
    - "Severity depends on whether EIP-7702 is live on target chain — may be informational pre-Pectra"
  solodit_ids: []
  incidentes:
    - "Solodit #57707: FactCheckExchange — settleMatchedOrders uses isContract to route sig verification, breaks under EIP-7702 (MEDIUM)"
    - "Solodit #6662: Blueberry onlyEOAEx — tx.origin check to enforce EOA will not hold under EIP-3074 (MEDIUM)"
    - "Solodit #64214: Benefactors not supported by signature verification under EIP-7702 (LOW)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [EIP-7702, EIP-3074, EOA, isContract, ERC-1271, Pectra, signature-routing]

- id: sig-019
  pattern: multisig-duplicate-signer-weight-inflation
  name: "Multi-signature verification accepts duplicate signers to inflate weight"
  causa_raiz: "Weighted multi-signature verification (e.g., validator checkpoints, multisig wallets) iterates over a signatories array without checking for duplicates. A single signer can appear multiple times, accumulating their weight to single-handedly meet the threshold."
  como_funciona: |
    1. Checkpoint/multisig requires totalWeight >= threshold from N validators.
    2. submitCheckpoint accepts arrays of (signatories[], signatures[]).
    3. Each signatory's weight is added to totalWeight without checking if that signatory already contributed.
    4. Malicious validator submits their address K times where K * their_weight >= threshold.
    5. Single validator passes the checkpoint alone, bypassing the quorum requirement.
  invariante: |
    // Each signer must appear at most once
    for (uint i = 1; i < signatories.length; i++) {
        require(signatories[i] > signatories[i-1], "signatories must be sorted and unique");
    }
  que_mirar:
    - "Loops over signatories[] that accumulate weight without deduplication"
    - "grep -rn 'signatories\\|signatures.*length' --include='*.sol' in checkpoint/multisig"
    - "Validator weight accumulation without sorted-unique enforcement"
    - "submitCheckpoint, verifySignatures, checkQuorum patterns"
  como_se_arregla: "Require signatories array to be sorted in ascending order and check signatories[i] > signatories[i-1] for all i. Alternatively, use a bitmap or mapping to track seen signers."
  trampas:
    - "If signatures are verified against a fixed signer set with 1:1 mapping, duplicates are not possible"
    - "Some implementations sort off-chain — verify on-chain enforcement exists"
  solodit_ids: []
  incidentes:
    - "Solodit #65088: Recall SubnetActorCheckpointingFacet — no signature duplication check, single validator can satisfy quorum alone (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [multisig, duplicate-signer, quorum-bypass, validator, checkpoint, weight]

- id: sig-020
  pattern: kyc-allowlist-signature-replay-after-revocation
  name: "KYC/allowlist signature replayable after status revocation"
  causa_raiz: "Signature-based KYC or allowlist grants do not invalidate the signature after use. If KYC/allowlist status is later revoked, the original unexpired signature can be replayed to re-grant status, bypassing the revocation."
  como_funciona: |
    1. Admin backend signs a KYC approval for user with deadline T.
    2. User calls addKYCAddressViaSignature() — KYC granted.
    3. Admin revokes KYC status (e.g., sanctions, compliance issue).
    4. Before deadline T, user (or anyone with the signature) replays the same signature.
    5. Contract re-grants KYC because: signature is valid, deadline not passed, and the 'already verified' check was cleared by revocation.
    6. User regains access to protocol despite revocation.
  invariante: |
    // Signatures must be consumed/invalidated on first use
    mapping(bytes32 => bool) public usedSignatures;
    bytes32 sigHash = keccak256(abi.encode(sig));
    require(!usedSignatures[sigHash], "signature already used");
    usedSignatures[sigHash] = true;
  que_mirar:
    - "KYC/allowlist grant functions that accept signatures without tracking used signatures"
    - "Revocation functions that clear state but don't invalidate outstanding signatures"
    - "grep -rn 'addKYC\\|addToAllowlist\\|grantRole.*signature' --include='*.sol'"
    - "Mint allowlists using merkle proofs without per-address mint tracking"
    - "Time-based validity (deadline) without per-signature consumption tracking"
  como_se_arregla: "Track used signatures in a mapping and reject replays. Alternatively, use a nonce that is incremented on both grant and revocation (so revoking invalidates all prior signatures). Prefer short deadlines."
  trampas:
    - "If revocation is permanent and cannot be undone, replay may re-grant — check if this is intended"
    - "Merkle proofs with per-wallet mint limits may mitigate replay even without explicit tracking"
  solodit_ids: []
  incidentes:
    - "Solodit #6415: Ondo KYCRegistry — addKYCAddressViaSignature replayable after KYC revocation, user re-verifies before deadline (MEDIUM)"
    - "Solodit #8860: RabbitHole QuestFactory — mintReceipt signature replay, mitigated only by per-address mint limit (MEDIUM)"
    - "Solodit #6839: SeaDrop — mintSigned and mintAllowList lack replay protection, only indirect limit via maxMintsPerWallet (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [KYC, allowlist, replay, revocation, signature-reuse, mint]

- id: sig-021
  pattern: oracle-signature-no-nonce-replay
  name: "Oracle/price signature lacks nonce — stale prices replayed"
  causa_raiz: "Off-chain oracle or price feed signs messages including (strategy, price, timestamp) but no nonce or monotonic counter. A malicious user replays an older valid signature with a more favorable price to manipulate share accounting or vault valuations."
  como_funciona: |
    1. Oracle validators sign price update: keccak256(strategy, pps, timestamp).
    2. No nonce in signed data — signature is valid until expiry.
    3. Price changes from $1.00 to $0.90.
    4. Attacker replays old signature with pps=$1.00 (still within timestamp validity).
    5. Protocol uses stale inflated price for share calculations.
    6. Attacker withdraws at inflated price, extracting value from other users.
  invariante: |
    // Each price update must include a monotonically increasing nonce
    // require(nonce == lastNonce + 1, "invalid nonce");
  que_mirar:
    - "rg 'encodePacked.*price|encodePacked.*pps' --type sol"
    - "Is there a nonce in the oracle signature schema?"
    - "Does the signature include block.chainid and address(this)?"
    - "Can old signatures be replayed if timestamp is still valid?"
  como_se_arregla: "Add an auto-incrementing nonce to the signed message. Include chainId and contract address via EIP-712 domain separator. Reject signatures where timestamp < lastUpdate."
  trampas:
    - "Short expiry windows (5 minutes) may make replay impractical"
    - "If oracle is centralized and never re-signs, replay risk is limited to the validity window"
  solodit_ids: []
  incidentes:
    - "Superform v2 Periphery ECDSAPPSOracle — no nonce in signature schema, stale PPS price replay breaks share accounting (High)"
    - "Soulsclub Revolver — joinGame signature lacks chainId, address(this), currentRoundId; cross-chain and cross-round replay (Medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, oracle, nonce, replay, price-manipulation, stale-price]

- id: sig-022
  pattern: missing-domain-separator-cross-chain-replay
  name: "Signed digest lacks domain separator — cross-chain and cross-deployment replay"
  causa_raiz: "Signed message hash does not include EIP-712 domain separator (chainId, verifyingContract). Same signature is valid on every chain and every deployment using the same signer key. Particularly dangerous for hooks/adapters deployed identically via CREATE2/CREATE3 on multiple networks."
  como_funciona: |
    1. Contract hashes: keccak256(abi.encode(sender, params, nonce, expiry)).
    2. No chainId or address(this) in the hash.
    3. User signs quote on Chain A.
    4. Attacker replays signature on Chain B (same contract deployed via CREATE3).
    5. Signature verifies because all signed parameters are identical.
    6. Swap executes on Chain B without user's authorization.
  invariante: |
    // Signed digest must include EIP-712 domain with chainId and verifyingContract
    bytes32 digest = _hashTypedDataV4(structHash);
  que_mirar:
    - "rg 'keccak256.*abi.encode' --type sol near signature verification"
    - "Is block.chainid included in signed data?"
    - "Is address(this) included in signed data?"
    - "rg 'domainSeparator|DOMAIN_SEPARATOR|_hashTypedDataV4' --type sol"
    - "Is the contract deployed on multiple chains with same address?"
  como_se_arregla: "Adopt EIP-712 domain separator with chainId and verifyingContract. If intentionally omitting chainId for UX, document risks and use chain-specific signing keys."
  trampas:
    - "If the contract is only deployed on one chain, cross-chain replay is not possible"
    - "Some protocols intentionally omit chainId — verify if this is documented"
  solodit_ids: []
  incidentes:
    - "Uniswap Foundation KEM Hooks — signed swap digest lacks domain separator, cross-chain replay via CREATE3 (Medium)"
    - "Accountable Authorizable — _verify not EIP-712 compliant, mixes chainId in message not domain (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, domain-separator, EIP-712, cross-chain, replay, CREATE3]

- id: sig-023
  pattern: eip191-message-length-mismatch
  name: "EIP-191 signed message declares wrong byte length"
  causa_raiz: "When using EIP-191 personal_sign prefix, the declared message length does not match the actual encoded data length. This produces a different hash than what signers compute off-chain, causing all signature verifications to silently fail or produce wrong recoveries."
  como_funciona: |
    1. Contract builds message: keccak256(abi.encodePacked(rootHash, sxtBlockNumber, block.chainid)).
    2. Actual data: 32 bytes + 8 bytes + 32 bytes = 72 bytes.
    3. Contract prefixes with: "\\x19Ethereum Signed Message:\\n36" (declares 36 bytes).
    4. Off-chain signer uses correct 72 bytes.
    5. Hashes never match. All signature validations fail.
    6. Or: truncated hash matches a different message, enabling forgery.
  invariante: |
    // Declared message length must equal actual message length
    // "\\x19Ethereum Signed Message:\\n" + toString(actualLength) + message
    assert(declaredLength == actualMessageBytes.length);
  que_mirar:
    - "rg 'Ethereum Signed Message' --type sol"
    - "Does the declared \\n length match the actual encoded data size?"
    - "Count bytes: address=20, uint256=32, uint64=8, bytes32=32"
    - "Is abi.encodePacked used (variable length) or abi.encode (fixed 32 per param)?"
  como_se_arregla: "Calculate correct byte length. Or use EIP-712 instead of EIP-191 to avoid manual length calculation. Use OpenZeppelin's MessageHashUtils.toEthSignedMessageHash(bytes) which handles length automatically."
  trampas:
    - "If using EIP-712 (not personal_sign), this pattern does not apply"
    - "abi.encode pads everything to 32 bytes; abi.encodePacked uses actual sizes"
  solodit_ids: []
  incidentes:
    - "SXT — _validateSxtFulfillUnstake declares 36-byte length but actual message is 72 bytes, EIP-191 non-compliant (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, EIP-191, message-length, personal-sign, encoding]

- id: sig-024
  pattern: system-tx-signature-malleability-consensus-split
  name: "System transaction missing EIP-2 signature malleability check — consensus split"
  causa_raiz: "System transaction validation checks sender, gas price, gas limit, and tx type but does not enforce EIP-2 (low-s) signature requirement. A malicious block proposer can include a system transaction with the s-value flipped to the upper half of the curve. This passes static validation but fails during execution-layer validation, causing the system transaction to be rejected and breaking epoch/validator state changes."
  como_funciona: |
    1. System transaction signed with valid ECDSA signature.
    2. Block proposer flips s-value to upper half of secp256k1 curve.
    3. static_validate_system_transaction passes: only checks sender, gas, type.
    4. Execution layer validates EIP-2 (low-s) requirement: fails.
    5. System transaction rejected during execution.
    6. Epoch change / validator set update does not execute.
    7. Consensus split between nodes that apply vs reject the block.
  invariante: |
    // System transaction signature must have s in lower half of curve
    // assert(s <= secp256k1_N / 2)
  que_mirar:
    - "Does system transaction validation check signature malleability?"
    - "Is EIP-2 (low-s) enforced before the execution layer?"
    - "rg 'validate_system_transaction|system_tx' -- check signature validation"
    - "Is there a gap between static validation and execution validation?"
  como_se_arregla: "Add EIP-2 signature validation (low-s check) to static_validate_system_transaction before any other validation. Normalize signatures to low-s form."
  trampas:
    - "Only affects L1/L2 node implementations with system transactions"
    - "Requires malicious block proposer — not exploitable by regular users"
  solodit_ids: []
  incidentes:
    - "Monad — static_validate_system_transaction missing EIP-2 malleable signature check, consensus split possible (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, malleability, EIP-2, system-transaction, consensus, validator]

- id: sig-025
  pattern: no-nonce-invalidation-function
  name: "No mechanism for users to invalidate signed nonces — irrevocable signatures"
  causa_raiz: "Protocol uses nonce-based signature replay protection but provides no function for users to increment their nonce without executing the signed action. Once a user signs a message, they cannot cancel it — the signature remains valid until used or deadline expires."
  como_funciona: |
    1. User signs transaction with nonce N and deadline in 7 days.
    2. User changes mind (market conditions, error in parameters).
    3. User wants to cancel the pending signature.
    4. No function exists to increment nonce from N to N+1.
    5. Original signature remains valid for 7 days.
    6. Relayer or anyone with the signature can execute it within the deadline.
    7. User has no way to prevent execution of a transaction they no longer want.
  invariante: |
    // Users must be able to invalidate their current nonce
    // function invalidateNonce() external { nonces[msg.sender]++; }
  que_mirar:
    - "rg 'nonce.*increment|invalidateNonce|cancelNonce|revokeNonce' --type sol"
    - "Is there a public function to increment nonce without executing an action?"
    - "How long are signature deadlines? Longer = more critical"
    - "Can users cancel pending meta-transactions?"
  como_se_arregla: "Add a public function that increments the caller's nonce, invalidating all pending signatures. Or implement batch nonce invalidation (EIP-2612 style). Or use short deadlines (< 1 hour)."
  trampas:
    - "If deadlines are very short (minutes), practical risk is limited"
    - "If signatures are only held by trusted relayers, lower severity"
  solodit_ids: []
  incidentes:
    - "Securitize DSToken Rebasing — no function to invalidate nonce in SecuritizeSwap, signed transactions irrevocable until deadline (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, nonce, invalidation, cancellation, meta-transaction, revocation]

- id: sig-026
  pattern: permit-amount-oracle-dependent-mismatch
  name: "Permit amount calculated from oracle price at execution time mismatches signed amount"
  causa_raiz: "Function calculates the permit amount from a live oracle price, but the user signed the permit off-chain using the oracle price at signature time. Between signing and execution, the oracle price changes, making the signed amount incorrect. The permit either reverts (if wrapped in try/catch, falls back to allowance) or always fails."
  como_funciona: |
    1. User calculates fullPayout = previewMint(amount, asset) using current oracle price.
    2. User signs ERC-2612 permit for fullPayout amount.
    3. Oracle price changes before transaction is mined.
    4. Contract recalculates fullPayout with new price — different value.
    5. permit(owner, spender, newFullPayout, deadline, v, r, s) fails — signed for old amount.
    6. If try/catch: permit silently fails, falls back to pre-existing allowance.
    7. If no try/catch: entire transaction reverts.
  invariante: |
    // Permit amount must be a user-supplied parameter, not recalculated
    // function flashMintWithPermit(amount, permitAmount, deadline, v, r, s)
  que_mirar:
    - "rg 'permit.*preview|permit.*oracle|permit.*getPrice' --type sol"
    - "Is the permit amount recalculated at execution time?"
    - "Does the function accept the permit amount as a parameter or derive it?"
    - "Is there an oracle call between user signing and permit execution?"
  como_se_arregla: "Accept the expected permit amount as a function parameter (user-supplied, matching their signature). Validate that the supplied amount covers the required amount. Do not recalculate the permit amount from live oracle data."
  trampas:
    - "If permit is wrapped in try/catch and falls back to allowance, may be informational"
    - "Stablecoins with fixed price are not affected"
  solodit_ids: []
  incidentes:
    - "Colbfinance USC Engine — flashMintWithPermit recalculates fullPayout from oracle, mismatches signed permit amount (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [signature, permit, oracle, price-mismatch, ERC-2612, timing]

- id: sig-027
  pattern: nonce-reset-on-account-transfer-replay
  name: "Nonce reseteado al transferir cuenta/ownership — replay de mensajes firmados anteriores"
  causa_raiz: >
    El nonce de firma está vinculado al propietario actual de una cuenta. Cuando la
    cuenta cambia de propietario (vía transfer, notifyAccountTransfer, u otro mecanismo),
    el nonce se resetea a cero. Esto invalida la protección contra replay: mensajes
    firmados por el propietario anterior con nonce 0..N ahora pueden ser re-ejecutados
    contra la cuenta con el nuevo propietario, porque el counter volvió a 0. El atacante
    puede ser el propio anterior propietario (que firmó mensajes antes de transferir)
    o cualquiera que haya interceptado firmas previas.
  como_funciona: |
    1. Cuenta A es propiedad de Alice. Alice firma msg con nonce=5 (ejecutado),
       nonce=6 (ejecutado), nonce=7 (firmado pero no ejecutado aún).
    2. Alice transfiere la cuenta a Bob. El sistema hace nonce[accountId] = 0.
    3. El mensaje con nonce=0 (que Alice firmó para un retiro de 100 ETH hace tiempo)
       es válido nuevamente contra la cuenta de Bob.
    4. Atacante (o Alice misma) re-ejecuta el mensaje firmado previamente.
    5. Fondos de Bob se drenan usando una firma que Bob nunca autorizó.
  invariante: |
    // Al transferir una cuenta, el nonce NO debe resetearse
    // El nonce debe ser monotónicamente creciente y NUNCA decrecer
    // require(nonces[accountId] >= previousNonce, "nonce must not reset")
  que_mirar:
    - "notifyAccountTransfer(), transferAccount(), o cualquier función que cambie owner"
    - "Nonce almacenado por address (owner) en lugar de por account ID"
    - "Reseteo explícito: nonces[account] = 0 en código de transfer"
    - "Sistemas de account abstraction donde el signer cambia pero el accountId es estable"
    - "TSS address update, relayer key rotation, guardian change: cualquier cambio de firmante"
  como_se_arregla: "Nunca resetear nonces al transferir propiedad. Alternativamente: invalidar todas las firmas pendientes incrementando el nonce a un valor alto (e.g., uint256.max >> 1) o introduciendo un 'generation counter' en el dominio de firma que se incrementa al transferir."
  trampas:
    - "Si el nonce está ligado al address del owner (no al accountId), un nuevo owner empieza en nonce=0 naturalmente — el fix es ligar el nonce al accountId"
    - "Algunos sistemas intencionalmente resetan nonces para permitir reutilización de firmas post-transfer — verificar el diseño"
    - "Si no hay función de transferencia de cuenta, este bug no aplica"
  solodit_ids: []
  incidentes:
    - "ReyaNetwork — AccountModule::notifyAccountTransfer resetea nonce a 0; replay de mensajes firmados por owner anterior posible (Medium, Pashov Audit Group; impacto High)"
    - "ZetaChain Cross-Chain — update_tss (Solana) no resetea nonce del TSS anterior, permitiendo replay de firmas TSS previas con el nuevo signatario (Medium, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: ReyaNetwork M-03 (Pashov), ZetaChain M-31 (Sherlock)"
  tags: [nonce, replay, account-transfer, ownership, signature, account-abstraction]
  relacionado_con: [sig-001, sig-003, sig-004]

- id: sig-028
  pattern: delegatebysig-cross-era-replay
  name: "delegateBySig() sin era check — firma de delegación válida en una era anterior se re-ejecuta tras slash/unstake"
  causa_raiz: >
    Algunos tokens de governance usan un sistema de "eras" (épocas) para manejar eventos
    de slash o unstake masivo: cuando ocurre un slash, se incrementa el era counter y todos
    los balances se resetean. La función delegateBySig() permite delegar poder de voto
    mediante una firma EIP-712 off-chain. Si el typehash de delegateBySig no incluye el
    era actual, una firma firmada en la era N es válida en la era N+1 (post-slash).
    Un antiguo delegador que firmó "delegar a X en era 0" puede tener esa firma re-ejecutada
    en la era 1 sin su conocimiento ni consentimiento.
  como_funciona: |
    1. Era 0: Alice firma delegateBySig(delegatee=Attacker, nonce=0, deadline=far_future).
       La firma se ejecuta. Alice luego re-delega a Bob vía delegate() directo.
    2. Slash event: era counter incrementa de 0 a 1. Nonces reseteados.
    3. Era 1: Attacker re-ejecuta la firma de Alice del era 0 (mismo nonce=0, nuevo era=1).
    4. Firma es válida porque el domain separator no incluye el era.
    5. Alice ahora delega a Attacker en era 1 sin haberlo solicitado.
  invariante: |
    // EIP-712 typehash debe incluir el era actual:
    // keccak256("Delegation(address delegatee,uint256 nonce,uint256 deadline,uint256 era)")
    // require(era == currentEra, "signature from wrong era")
  que_mirar:
    - "Contratos con era counter o epoch counter que se incrementa ante slashing/redistribución"
    - "delegateBySig() o voteWithSig() cuyo typehash NO incluye el era/epoch actual"
    - "StRSRVotes, RSR staking, o cualquier protocolo de staking con función de seize/slash"
    - "Nonces reseteados junto con el era — firmas antiguas se vuelven válidas por primera vez"
    - "Función de 'seizeRSR' o equivalente que incrementa era counter"
  como_se_arregla: "Incluir el era actual en el EIP-712 typehash de delegateBySig. Alternativamente, incluirlo como parámetro explícito y verificar que coincida con el era actual del contrato."
  trampas:
    - "Esta vulnerabilidad es específica de protocolos con era/epoch + slash mechanism — rara en contratos simples"
    - "Si los nonces NO se resetean con el era, el replay no es posible aunque falte el era en el typehash"
    - "Impacto en Reserve Protocol clasificado como Low por el auditor — considerar severidad en contexto del protocolo específico"
  solodit_ids: []
  incidentes:
    - "Reserve Protocol StRSRVotes — delegateBySig() no verifica que la delegación ocurra en el era en que fue firmada; firma de era anterior re-ejecutable post-seize (Low, Code4rena 2024-07)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: Reserve L-10 (Code4rena 2024-07)"
  tags: [delegateBySig, era, epoch, slash, staking, EIP-712, governance, replay]
  relacionado_con: [sig-001, sig-002, sig-003]

- id: sig-029
  pattern: unauthorized-delegate-on-behalf-missing-ownership-check
  name: "delegate() sin verificación de ownership — cualquiera puede delegar en nombre de otro"
  causa_raiz: >
    La función delegate() (o delegateFor()) en contratos de veToken/NFT-voting permite
    delegar el poder de voto de un lock/NFT a otro. El bug: la función no verifica que
    msg.sender sea el propietario del lock desde el cual se delega. Cualquier address
    puede llamar delegate(fromLockId, toLockId) y redirigir el poder de voto de la
    víctima sin su consentimiento. Esto destruye la soberanía de voto y permite que
    un atacante centralice poder de voto hacia su propio lock.
  como_funciona: |
    1. Alice tiene lock NFT #100 con 1000 tokens de voting power.
    2. Attacker llama delegate(fromLockId=100, toLockId=Attacker_lock) sin ser owner del #100.
    3. El poder de voto de Alice (1000 tokens) se transfiere al lock del attacker.
    4. Attacker vota en propuestas con el power combinado.
    5. Attacker puede hacer esto para todos los holders y monopolizar governance.
  invariante: |
    // Quien delega DEBE ser el owner del lock fuente:
    // require(ownerOf(fromLockId) == msg.sender || isApprovedForAll(owner, msg.sender))
    // O si es vía sig: verificar la firma del owner del lock fuente
  que_mirar:
    - "Función delegate(fromId, toId) en veNFT/veLock contracts sin require(ownerOf(fromId) == msg.sender)"
    - "Función delegateVotes() que acepta un 'from' address sin verificar que sea msg.sender"
    - "NFT-based voting donde el tokenId se pasa como parámetro en delegate()"
    - "Contratos de escrow/vesting con delegate que no verifican el beneficiario"
    - "ERC-721 approve no cubre delegaciones si el contrato no lo chequea explícitamente"
  como_se_arregla: "Añadir require(ownerOf(fromLockId) == msg.sender || isApprovedForAll(ownerOf(fromLockId), msg.sender)) en la función delegate. Para delegación gasless, requerir firma EIP-712 del owner del lock fuente."
  trampas:
    - "Delegate en ERC20Votes estándar (OpenZeppelin) sí permite delegar PROPIO balance — es correcto"
    - "Este bug aplica solo a veNFT/lockId-based delegation, no a ERC20.delegate(address)"
    - "Si el protocolo intencionalmente permite que terceros (e.g., un operator aprobado) deleguen, verificar si hay un isApprovedForAll check"
  solodit_ids: []
  incidentes:
    - "Hyperstable vePeg — delegate() no tiene ownership check; cualquier dirección puede delegar los votos de cualquier lock a un lock arbitrario; attacker monopoliza governance (Critical, Pashov Audit Group 2025)"
    - "EYWA EscrowManager — moveVotes() no verifica hasVoted, permite inflar votos de un delegado transfiriendo NFT que ya votó (High, MixBytes)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Hyperstable C-01 (Pashov 2025), EYWA duplicate voting (MixBytes)"
  tags: [delegate, voting-power, NFT, veToken, access-control, governance, missing-ownership-check]
  relacionado_con: [sig-001, sig-003]
```

---

## Quick-Scan Grep Patterns

Use these to triage a new codebase fast:

```bash
# Raw ecrecover usage (potential malleability + address(0) issues)
grep -rn "ecrecover" --include="*.sol"

# DOMAIN_SEPARATOR cached as immutable
grep -rn "immutable.*DOMAIN_SEPARATOR\|DOMAIN_SEPARATOR.*immutable" --include="*.sol"

# Permit functions (front-running DoS targets)
grep -rn "\.permit(" --include="*.sol"

# Permit2 usage (token mismatch + signature theft vectors)
grep -rn "permit2\|permitTransferFrom\|ISignatureTransfer" --include="*.sol"

# Missing nonce check in signature verification
grep -rn "ecrecover\|ECDSA.recover\|isValidSignature" --include="*.sol" | grep -v "nonce"

# ERC-1271 implementations
grep -rn "isValidSignature\|ERC1271" --include="*.sol"

# EIP-712 domain separator computation
grep -rn "DOMAIN_SEPARATOR\|_domainSeparatorV4\|EIP712" --include="*.sol"

# Signature struct hashing (check for missing fields)
grep -rn "keccak256.*abi.encode" --include="*.sol"

# Hardcoded deadline in permit calls
grep -rn "block.timestamp.*permit\|permit.*block.timestamp" --include="*.sol"

# Permit with swap (signature theft via MEV)
grep -rn "WithPermit\|withPermit\|pullTokensWithPermit" --include="*.sol"
```

---

## Severity Decision Tree

1. **Can an attacker steal funds using a replayed or forged permit/signature?** -> Critical (sig-009, sig-010)
2. **Can signatures be replayed across chains to execute unauthorized actions?** -> Critical (sig-002)
3. **Can the same signature be used multiple times to drain funds?** -> Critical (sig-001, sig-003)
4. **Can ERC-1271 signatures be replayed across smart wallets?** -> High (sig-008)
5. **Can signature malleability bypass replay protection?** -> High (sig-007)
6. **Does ecrecover return address(0) enabling unauthorized access?** -> High (sig-004)
7. **Can permit transactions be front-run for DoS?** -> Medium (sig-006, sig-011)
8. **Are migration signatures missing chainId binding?** -> High (sig-012)

---

## Solodit Verified Finding Summary

> **Source**: Solodit (solodit.cyfrin.io)
> **Total verified signature findings**: 37
> **Breakdown by pattern**:
> - sig-001 (Signature replay): 2 findings
> - sig-002 (Cross-chain replay): 5 findings
> - sig-003 (Missing nonce): 2 findings (overlaps with sig-001)
> - sig-004 (ecrecover address(0)): 2 findings
> - sig-005 (Domain separator issues): 3 findings
> - sig-006 (Permit front-run DoS): 10 findings
> - sig-007 (Signature malleability): 9 findings
> - sig-008 (ERC-1271 issues): 2 findings
> - sig-009 (Permit token mismatch): 3 findings
> - sig-010 (Permit signature theft): 4 findings
> - sig-011 (Hardcoded deadline): 2 findings
> - sig-012 (L2 migration): 2 findings

**Key takeaway**: Permit front-running DoS (sig-006) is the most frequently reported pattern (10 findings), but it is Medium severity (griefing only). The highest-impact patterns are permit signature theft for MEV extraction (sig-010) and permit token mismatch (sig-009), which enable direct fund theft. Signature malleability (sig-007) remains prevalent especially in L2/zkEVM contexts where consensus-level enforcement is needed. Cross-chain replay (sig-002) is particularly dangerous for multi-chain protocols and L1-to-L2 migrations.

**Critical fund-loss patterns to prioritize**:
1. Permit2 token mismatch -- attacker deposits worthless token, withdraws real assets (sig-009)
2. Permit signature theft via front-running -- attacker steals user's swap with amountOutMin = 0 (sig-010)
3. Cross-chain signature replay -- signatures valid on chain A replayed on chain B (sig-002)
4. Same-chain signature replay -- missing nonce allows double execution (sig-001, sig-003)

---

## Cross-References

| Pattern | Solodit Finding IDs | Primary Vector |
|---|---|---|
| sig-001 | #36240, #6446 | Same-chain replay, missing nonce |
| sig-002 | #38368, #27801, #60874, #13723, #36298 | Cross-chain replay, stale domain separator |
| sig-003 | #6446, #36240 | Missing/reusable nonce |
| sig-004 | #60156, #45173 | ecrecover returns address(0) |
| sig-005 | #27801, #60874, #64482 | Domain separator misconfiguration |
| sig-006 | #58344, #52794, #38294, #38293, #38322, #31669, #49051, #49062, #61182, #63340 | Permit front-run DoS |
| sig-007 | #42171, #3968, #35620, #49758, #62040, #52084, #45173, #21369, #13780 | Signature malleability |
| sig-008 | #56710, #40900 | ERC-1271 replay across accounts |
| sig-009 | #32261, #49062, #30529 | Permit token/spender mismatch |
| sig-010 | #53124, #49644, #54669, #30445 | Permit signature theft for MEV/fund theft |
| sig-011 | #61182, #63340 | Hardcoded/mismatched deadline |
| sig-012 | #36298, #36271 | L2 migration signature flaws |
