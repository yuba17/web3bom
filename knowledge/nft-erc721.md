# NFT / ERC721 Vulnerabilities — Combat Briefing

> Attack surface: safeTransferFrom callbacks, NFT-as-collateral in lending, approval
> hijacking, tokenId accounting, UniswapV3 position NFTs, ERC721 receiver magic bytes.
> Especially relevant for protocols using Uniswap V3 NFTs as position tokens (Revert Lend).
> Sources: verified Solodit findings from Sherlock/Code4rena/Spearbit audits.

---

## 1. Callback Reentrancy (onERC721Received / onERC1155Received)

```yaml
- id: nft-001
  pattern: onerc721received-reentrancy
  name: "safeTransferFrom callback used for reentrancy — state not updated before transfer"
  severity: high
  causa_raiz: >
    ERC721.safeTransferFrom() calls onERC721Received() on the recipient BEFORE returning.
    If the protocol updates state (balance, shares, collateral count) AFTER the transfer,
    the callback can reenter and exploit the stale state. Classic CEI violation
    but harder to spot because the trigger is an NFT transfer, not an ETH send.
  como_funciona: |
    1. Protocol: removeCollateral(tokenId) → safeTransferFrom(protocol, attacker, tokenId)
    2. ERC721 calls attacker.onERC721Received() — still inside removeCollateral()
    3. Attacker reenters: removeCollateral(anotherTokenId) — state not yet updated
    4. Second removal succeeds (collateral count still shows 2, now 1)
    5. After both callbacks complete, state updated once — attacker extracted 2 NFTs, paid 1
  invariante: >
    For any function that calls safeTransferFrom(this, to, tokenId):
    all state updates (balances, collateral counts, debt) must complete BEFORE the call.
    Formally: state[user] must be final before any external call that triggers callbacks.
  que_mirar:
    - "Is safeTransferFrom called before state update (violates CEI)?"
    - "Are NFT transfers inside functions that also write debt/collateral state?"
    - "grep: safeTransferFrom, onERC721Received, removeCollateral, _transfer"
    - "grep: nonReentrant on functions that do safeTransferFrom"
    - "Is there a reentrancy guard on all NFT-transfer functions?"
  como_se_arregla: >
    Follow CEI strictly: update ALL state before safeTransferFrom.
    Add nonReentrant modifier to all functions that send NFTs.
    Consider using transferFrom (no callback) when recipient is known to be EOA or trusted.
  trampas:
    - "ERC721.transfer() (no callback) is NOT the same as safeTransferFrom — but contracts often mix them"
    - "ERC1155 has the same issue via onERC1155Received and onERC1155BatchReceived"
    - "The reentrancy can go through a DIFFERENT function than the one that started the transfer"
  confianza: alta
  verificado: true
  tags: [reentrancy, ERC721, safeTransferFrom, callback, CEI]
  solodit_ids: [6203, 18297]
  incidentes:
    - protocol: "Papr"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Reentrancy via removeCollateral/startLiquidationAuction/purchaseLiquidationAuctionNFT"
      detail: "Attacker reenters removeCollateral() inside onERC721Received during flash loan sequence, extracts multiple collateral NFTs"
      slug: "h-02-stealing-fund-by-applying-reentrancy-attack-on-removecollateral-code4rena-papr-papr-contest-git"
    - protocol: "Sudoswap (LSSVMPair)"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "balanceOf() circumvented via reentrancy with two ERC1155 pairs — double-spend"
      slug: "balanceof-can-be-circumvented-via-reentrancy-and-two-pairs-spearbit-none-sudoswap-pdf"

- id: nft-002
  pattern: onerc721received-permissionless-dos
  name: "Permissionless onERC721Received fills NFT array — unbounded loop causes DoS"
  severity: high
  causa_raiz: >
    A vault/protocol that accepts any NFT via onERC721Received() and pushes it to a
    storage array (nfts[]) without a whitelist allows a griefing attacker to fill the
    array with thousands of spam NFTs. Functions that iterate this array (withdraw, unlock,
    transfer) then run out of gas and revert — legitimate users permanently DoS'd.
  como_funciona: |
    1. Protocol accepts any NFT: onERC721Received() → nfts.push(tokenId)
    2. Attacker deploys 10,000 spam NFT contracts, sends one NFT each
    3. nfts.length = 10,001 — legitimate user's NFT buried at index 10,000
    4. unlockNFT(legitimateTokenId) → _removeNft() → for i in nfts: if nfts[i] == tokenId
    5. Loop OOGs before finding the token — transaction reverts permanently
    6. Legitimate user's collateral trapped forever
  invariante: >
    _removeNft(tokenId) must complete within block gas limit for any nfts.length.
    Either: max array length enforced, or O(1) lookup (mapping instead of array).
  que_mirar:
    - "Is onERC721Received() permissionless (no whitelist of accepted NFT contracts)?"
    - "Does the protocol store NFTs in an array that is iterated for removal?"
    - "grep: onERC721Received, nfts.push, _removeNft, nfts[i] == tokenId"
    - "Is there a mapping(tokenId => index) for O(1) lookup?"
  como_se_arregla: >
    Whitelist accepted NFT contracts in onERC721Received().
    Replace linear array scan with O(1) mapping: nftIndex[tokenId] = index.
    Or use EnumerableSet from OZ (maintains O(1) removal).
  trampas:
    - "The bug requires sending NFTs to the contract — only exploitable if anyone can transfer NFTs in"
    - "Protocol may intend to accept multiple NFT types — whitelist is the right fix, not rejecting all"
  confianza: alta
  verificado: true
  tags: [ERC721, onERC721Received, dos, unbounded-loop, gas, permissionless]
  solodit_ids: [192]
  incidentes:
    - protocol: "Unknown Vault"
      firm: "Unknown"
      impact: "HIGH"
      title: "Unbounded loop in _removeNft via permissionless onERC721Received — permanent DoS"
      slug: "h-04-unbounded-loop-in-_removenft-could-lead-to-a-griefingdos-attack"

- id: nft-003
  pattern: onerc721received-wrong-address-deposit
  name: "onERC721Received credits NFT to wrong address when transferred by approved operator"
  severity: high
  causa_raiz: >
    Protocols that accept NFT collateral via safeTransferFrom implement onERC721Received(operator, from, tokenId, data).
    If the protocol credits the NFT to `operator` instead of `from`, an approved operator
    can deposit someone else's NFT and become its credited owner in the protocol.
    The real owner loses their NFT; the operator gains control of the collateral position.
  como_funciona: |
    1. Alice approves Bob to manage her NFTs (setApprovalForAll or approve)
    2. Bob calls: nftContract.safeTransferFrom(alice, protocol, tokenId)
    3. Protocol.onERC721Received(operator=bob, from=alice, tokenId, data) is called
    4. Protocol credits: positions[bob][tokenId] = true  (should be alice)
    5. Bob now controls Alice's collateral position in the protocol
    6. Bob borrows against Alice's collateral, never repays — Alice's NFT liquidated
  invariante: >
    onERC721Received must credit tokenId to `from` (the original owner), not `operator`.
    position[from] += tokenId, never position[operator].
  que_mirar:
    - "In onERC721Received(operator, from, tokenId, data): which address is used for accounting?"
    - "Is 'from' or 'operator' stored as the new owner of the NFT in the protocol?"
    - "grep: onERC721Received, operator, from, positions, collateral, owner"
    - "Test: call safeTransferFrom where msg.sender != tokenOwner (approved operator)"
  como_se_arregla: >
    Use `from` parameter (the actual token owner) for all accounting in onERC721Received.
    Never use `operator` as the credited depositor.
  trampas:
    - "ERC721 spec: operator = caller of safeTransferFrom, from = previous owner. Easy to confuse."
    - "If data encodes recipient address, validate data.recipient == from or apply strict checks"
  confianza: alta
  verificado: true
  tags: [ERC721, onERC721Received, operator, from, accounting, collateral]
  solodit_ids: [6204]
  incidentes:
    - protocol: "Papr"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Collateral NFT deposited to wrong address when transferred by approved operator"
      slug: "h-03-collateral-nft-deposited-to-a-wrong-address-when-transferred-directly-to-paprcontroller-code4rena-papr-papr-contest-git"
```

---

## 2. onERC721Received — Magic Bytes & Interface

```yaml
- id: nft-004
  pattern: onerc721received-magic-bytes-not-checked
  name: "safeTransferFrom succeeds even if receiver returns wrong/no magic bytes"
  severity: medium
  causa_raiz: >
    ERC721 spec requires that contracts implementing onERC721Received return exactly
    IERC721Receiver.onERC721Received.selector (0x150b7a02). If the check is absent or
    incorrect (checking a different value), NFTs can be sent to contracts that don't
    actually support ERC721 — tokens get permanently locked. Custom ERC721 implementations
    that skip this check are particularly dangerous for position tokens.
  como_funciona: |
    1. Protocol's safeTransferFrom calls receiver.onERC721Received()
    2. Receiver is a smart contract without ERC721 support — its fallback returns bytes4(0)
    3. Protocol doesn't check return value (or checks wrong selector)
    4. Transfer succeeds — NFT is now owned by a contract that can never transfer it out
    5. Token is permanently locked
  invariante: >
    After safeTransferFrom to contract C:
    IERC721Receiver(C).onERC721Received(...) must return 0x150b7a02.
    Any other return value must revert the transfer.
  que_mirar:
    - "Does the custom safeTransferFrom check the return value of onERC721Received?"
    - "Is the checked selector IERC721Receiver.onERC721Received.selector (0x150b7a02)?"
    - "grep: onERC721Received, 0x150b7a02, selector, _checkOnERC721Received"
    - "Compare custom ERC721 impl against OZ ERC721._checkOnERC721Received()"
  como_se_arregla: >
    Use OZ's _checkOnERC721Received() verbatim. After calling onERC721Received(),
    require(retval == IERC721Receiver.onERC721Received.selector, "ERC721: transfer to non-ERC721Receiver").
  trampas:
    - "Custom ve-token implementations (vote escrow) often roll their own ERC721 and miss this"
    - "The bug only manifests when a user sends to a non-receiver contract — hard to test in isolation"
  confianza: alta
  verificado: true
  tags: [ERC721, safeTransferFrom, magic-bytes, receiver, locked-nft]
  solodit_ids: [8741]
  incidentes:
    - protocol: "VoteEscrowCore"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "safeTransferFrom does not check correct magic bytes — NFTs permanently lockable in non-receiver contracts"
      slug: "m-04-voteescrowcore-safetransferfrom-does-not-check-correct-magic-bytes-code4rena"
```

---

## 3. NFT as Collateral / Position Token

```yaml
- id: nft-005
  pattern: nft-collateral-pause-blocks-liquidation
  name: "NFT collateral pause or blacklist blocks liquidation — loan trapped indefinitely"
  severity: medium
  causa_raiz: >
    Lending protocols that use NFTs as collateral call safeTransferFrom or burn() on the
    NFT during liquidation. If the NFT contract is pausable or has a blacklist, an admin
    action on the NFT contract can make these calls revert. The loan becomes unliquidatable:
    the borrower cannot redeem (past deadline), the protocol cannot liquidate, collateral stuck.
  como_funciona: |
    1. Borrower deposits pausable NFT as collateral (e.g., RWA token, CryptoKitties)
    2. Loan expires unpaid
    3. NFT contract admin pauses the contract (or blacklists the protocol address)
    4. liquidate() calls NFT.burn(tokenId) or safeTransferFrom — reverts
    5. Loan permanently unresolvable: borrower keeps loan proceeds, protocol loses collateral
    6. Same attack works for CryptoKitties, CryptoPunks (non-standard transfers)
  invariante: >
    liquidate(loanId) must always succeed if loan is expired, regardless of NFT contract state.
    Protocol must not have single-point-of-failure dependency on NFT contract being unpaused.
  que_mirar:
    - "Is the NFT contract pausable or does it have a blacklist?"
    - "Does liquidation call burn() or safeTransferFrom on the NFT?"
    - "Is there a fallback liquidation path that doesn't require NFT transfer?"
    - "grep: whenNotPaused, blacklist, burn(tokenId), liquidate, CryptoKitties, CryptoPunks"
    - "Check if accepted NFTs include non-standard tokens (CryptoPunks use transferPunk, not safeTransferFrom)"
  como_se_arregla: >
    Whitelist only unpaused/non-blacklistable NFT contracts.
    Or: implement a fallback liquidation path that seizes collateral record without NFT transfer
    (protocol takes legal/operational claim, separate NFT recovery process).
    Add explicit handling for non-standard NFT transfer patterns.
  trampas:
    - "RWA (Real World Asset) tokens are DESIGNED to be pausable — this is not an edge case"
    - "The borrower can trigger this deliberately: deposit → take loan → ask admin to pause"
    - "CryptoKitties/Fighters have their own pause unrelated to the lending protocol"
  confianza: alta
  verificado: true
  tags: [NFT, collateral, liquidation, pause, blacklist, RWA, CryptoKitties]
  solodit_ids: [64684, 6317]
  incidentes:
    - protocol: "PawnShop (RWA)"
      firm: "Unknown"
      impact: "MEDIUM"
      title: "Liquidation blocked by pausing/blacklisting RWA NFT contract — loans trapped permanently"
      slug: "m-02-liquidation-can-be-blocked-by-pausing-or-blacklisting-the-nft-contract"
    - protocol: "Ajna"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "CryptoKitty and CryptoPunk NFTs can be paused, blocking borrow/repay/liquidate"
      slug: "m-20-cryptokitty-and-cryptofighter-nft-can-be-paused-which-block-borrowing-repaying-liquidating-sherlock-ajna-ajna-git"

- id: nft-006
  pattern: uniswap-v3-position-nft-valuation-wrong
  name: "UniswapV3 position NFT valued incorrectly — wrong price leads to false liquidations"
  severity: high
  causa_raiz: >
    Protocols that accept Uniswap V3 NFTs as collateral must value the underlying liquidity.
    If the oracle wrapper uses token0.price and token1.price independently without accounting
    for the position's tick range and current price relative to the range, liquidity can be
    mispriced. For out-of-range positions (single-asset), the value is calculated as if
    both tokens are present — over or under-valuing the collateral.
  como_funciona: |
    1. User deposits V3 NFT for token pair TOKEN0/TOKEN1 as collateral
    2. Current price moves above position's upper tick → position becomes 100% TOKEN1
    3. Oracle values position using: TOKEN0.price * amount0 + TOKEN1.price * amount1
    4. amount0 is read from position data — but at current price, amount0 ≈ 0
    5. If oracle reads stale amount0 (from last update), position appears to hold both tokens
    6. Collateral overvalued → protocol accepts undercollateralized loans
    7. OR: oracle undervalues → false liquidation of healthy positions
  invariante: >
    valueOfV3Position(tokenId) == amount0 * price0 + amount1 * price1
    where amount0 and amount1 are computed AT THE CURRENT SQRT PRICE, not at entry price.
    Must call pool.slot0() and compute amounts using LiquidityAmounts library.
  que_mirar:
    - "Is V3 position value computed at current sqrtPriceX96 or at a stale price?"
    - "Does the oracle handle out-of-range positions (single-asset composition) correctly?"
    - "grep: getTokenPrice, tokenId, sqrtPriceX96, LiquidityAmounts, getAmountsForLiquidity"
    - "grep: UniswapV3OracleWrapper, positionData, getOnchainPositionData"
    - "Is there TWAP manipulation protection on the V3 pool price used for valuation?"
  como_se_arregla: >
    Use LiquidityAmounts.getAmountsForLiquidity(sqrtRatioX96, sqrtRatioAX96, sqrtRatioBX96, liquidity)
    with sqrtRatioX96 from pool.slot0() at the time of valuation.
    Apply TWAP check: validate that slot0 price hasn't deviated >X% from TWAP.
  trampas:
    - "For Revert Lend: V3Oracle must handle full-range, in-range, and out-of-range positions differently"
    - "Spot price manipulation on the V3 pool directly affects collateral value"
    - "Flash loan → manipulate pool → liquidate → profit is a real attack path here"
  confianza: alta
  verificado: true
  tags: [uniswap-v3, position-nft, oracle, collateral, liquidation, sqrtPrice]
  solodit_ids: [15982]
  incidentes:
    - protocol: "ParaSpace"
      firm: "Code4rena"
      impact: "HIGH"
      title: "UniswapV3 tokens of certain pairs wrongly valued — wrong price leads to liquidations"
      slug: "h-09-uniswapv3-tokens-of-certain-pairs-will-be-wrongly-valued-leading-to-liquidations-code4rena-paraspace-paraspace-contest-git"

- id: nft-007
  pattern: v3-position-nft-same-bucket-collision
  name: "Multiple NFT positions on same pool bucket collide — one blocks the other's redemption"
  severity: medium
  causa_raiz: >
    Protocols that wrap NFT positions into a shared PositionManager map all positions
    to the same (pool, tickLower, tickUpper) key. When two users create NFTs for the
    same bucket, their LP positions are aggregated under one address in the underlying pool.
    Both users see the same lender address — operations on one position affect the other's
    deposit time, rewards accrual, and redemption path.
  como_funciona: |
    1. Alice creates NFT for USDC/ETH, tick range [A, B]
    2. Bob creates NFT for USDC/ETH, tick range [A, B] — same bucket
    3. PositionManager maps both to the same pool address → same lender in Ajna pool
    4. Bob's mint overwrites Alice's depositTime (or adds liquidity to same slot)
    5. Alice's bucket-level redemption reverts: multiple NFT owners share the slot
    6. Neither can independently manage their position
  invariante: >
    Each NFT must correspond to an independent, exclusively-owned position in the underlying pool.
    position[tokenId].lenderAddress must be unique per NFT — never shared with another tokenId.
  que_mirar:
    - "Does PositionManager aggregate positions from different users in the same bucket?"
    - "Is there a 1:1 mapping between NFT tokenId and underlying pool position?"
    - "grep: memorializePosition, bucket, tickLower, tickUpper, depositTime, lender"
    - "Can two tokenIds map to the same (pool, tick) key?"
  como_se_arregla: >
    Enforce unique sub-accounts per NFT: each NFT owns a sub-position ID that
    is never shared. Or reject memorializePosition if the bucket already has a
    position from a different tokenId.
  trampas:
    - "The bug only manifests with TWO users using the same tick range — uncommon but real in popular pools"
    - "Ajna-specific but pattern applies to any protocol that wraps V3/V2 LP NFTs in a shared manager"
  confianza: alta
  verificado: true
  tags: [ERC721, position-nft, bucket-collision, ajna, uniswap-v3, redemption]
  solodit_ids: [6319, 6318]
  incidentes:
    - protocol: "Ajna"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Memorializing NFT position on same bucket as previous NFT locks both from redemption"
      slug: "m-22-memorializing-an-nft-position-on-the-same-bucket-of-a-previously-memorialized-nft-locks-redemption-sherlock-ajna-ajna-git"
    - protocol: "Ajna"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "Minting NFT on same bucket changes deposit time of previous NFT holder"
      slug: "m-21-minting-an-nft-with-a-position-on-the-same-bucket-as-a-previously-minted-nft-changes-its-deposit-time-sherlock-ajna-ajna-git"
```

---

## 4. Approval & Ownership Hijacking

```yaml
- id: nft-008
  pattern: borrowed-nft-setapprovalforall-hijack
  name: "Borrower hijacks borrowed NFT via setApprovalForAll on recipient's safe/contract"
  severity: high
  causa_raiz: >
    Protocols that lend NFTs to borrowers via flash loans or collateral-backed loans
    transfer the NFT to the borrower's address. If the borrower's address is a Gnosis Safe
    or any contract with a fallback handler, the borrower can set a fallback handler
    that returns a valid ERC721 receiver response AND sets approvals for the attacker.
    The protocol later tries to reclaim the NFT — but the attacker already extracted it.
  como_funciona: |
    1. Protocol: borrow(tokenId) → safeTransferFrom(protocol, borrower, tokenId)
    2. Borrower is a Gnosis Safe with setFallbackHandler() available
    3. Borrower calls safe.setFallbackHandler(maliciousHandler)
    4. maliciousHandler implements onERC721Received() → also calls nft.setApprovalForAll(attacker, true)
    5. Protocol tries to reclaim: safeTransferFrom(borrower, protocol, tokenId) — but attacker already moved it
    6. Or: attacker uses approval to call transferFrom before reclaim
  invariante: >
    After protocol sends NFT to borrower and before reclaim:
    NFT must remain in borrower's address or a protocol-controlled escrow.
    Protocol should not depend on the borrower NOT setting approvals on the loaned NFT.
  que_mirar:
    - "Does the protocol transfer NFT custody to borrower during the loan?"
    - "Is the NFT held in a protocol escrow or directly in borrower's wallet?"
    - "grep: setFallbackHandler, onERC721Received, guard, flashLoan.*NFT"
    - "Does the guard (if any) validate the fallback handler address?"
  como_se_arregla: >
    Keep NFT custody in a protocol-controlled escrow during the loan.
    Never transfer NFT to borrower's address — only grant a usage permission.
    If transfer is required, use a Guard contract that restricts setFallbackHandler().
  trampas:
    - "Gnosis Safe guard validation is the correct fix — but guard must be set at loan inception, not later"
    - "Attack requires the borrower to be a smart contract (Safe) — EOA borrowers cannot exploit this"
    - "Some protocols verify setFallbackHandler is disabled — check the guard's allowlist"
  confianza: alta
  verificado: true
  tags: [ERC721, approval, gnosis-safe, fallback-handler, nft-hijack, flash-loan]
  solodit_ids: [30522]
  incidentes:
    - protocol: "Arcadia Finance"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Attacker hijacks borrowed ERC721/ERC1155 via setFallbackHandler on Gnosis Safe"
      slug: "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-code4rena"

- id: nft-009
  pattern: flash-loan-nft-previous-owner-approval
  name: "NFT flash loan: previous owner's leftover approval allows token theft after pool ownership change"
  severity: medium
  causa_raiz: >
    NFT pools/vaults that can be sold/transferred may retain previous owner approvals.
    The previous owner set approval on the pool's NFTs (via execute() or direct approve).
    After the pool is sold, the new owner deposits fresh NFTs. The previous owner still
    has approvals on those NFT IDs (if IDs overlap or approvals were set per-pool, not per-token).
    Previous owner uses flashLoan() to receive NFT, then uses stale approval to transfer it out.
  como_funciona: |
    1. Bob owns PrivatePool with NFTs [1,2,3], sets approval on attacker contract
    2. Bob sells pool to Alice (transferring ownership)
    3. Alice deposits NFT [4] into the pool
    4. Attacker uses flashLoan(4) → receives NFT 4 in onFlashLoan callback
    5. Attacker's contract calls execute() with stale approval → moves NFT out
    6. onFlashLoan completes → pool expects NFT back → it's gone → flash loan appears successful
  invariante: >
    When pool ownership changes, all existing approvals on pool assets must be cleared.
    flashLoan() must verify NFT returns after callback before marking loan complete.
  que_mirar:
    - "Does pool ownership transfer clear all existing NFT approvals?"
    - "Can previous owner use execute() after ownership transfer?"
    - "grep: flashLoan, onFlashLoan, execute, setApprovalForAll, transferOwnership"
    - "Is there a guard preventing execute() from previous owner after transfer?"
  como_se_arregla: >
    On pool ownership transfer: revoke all approvals (approve(address(0), tokenId) for all tokens).
    Restrict execute() to current owner only. Validate NFT returned in flashLoan via balance check.
  trampas:
    - "The attack requires the pool to have been sold — timing-dependent"
    - "execute() gives owner arbitrary call ability — scope should be tightly limited"
  confianza: alta
  verificado: true
  tags: [NFT, flash-loan, approval, pool-ownership, previous-owner]
  solodit_ids: [43394]
  incidentes:
    - protocol: "Caviar (PrivatePool)"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Pool tokens stolen via flashLoan by previous owner using stale approval"
      slug: "m-15-pool-tokens-can-be-stolen-via-privatepoolflashloan-function-from-previous-owner-code4rena-caviar-caviar-private-pools-contest-git"
```

---

## 5. TokenId & Merkle Criteria

```yaml
- id: nft-010
  pattern: merkle-criteria-wrong-tokenid
  name: "Merkle criteria accepts wrong tokenIds — fulfiller submits valid proof for wrong token"
  severity: medium
  causa_raiz: >
    Order systems (Seaport, OpenSea) allow sellers to specify a SET of acceptable tokenIds
    via a Merkle root. The fulfiller provides the actual tokenId + Merkle proof.
    If the verification doesn't check that the provided tokenId IS a leaf (vs. an internal
    node) of the tree, a fulfiller can submit a proof where an intermediate hash satisfies
    the verification — accepting a tokenId not in the original set.
  como_funciona: |
    1. Seller creates order: accept any tokenId in set {1, 2, 3} (Merkle root of these leaves)
    2. Attacker constructs tokenId = hash(leaf1, leaf2) — an intermediate node of the Merkle tree
    3. Submits proof: the siblings of this intermediate node form a valid proof to the root
    4. CriteriaResolution.verifyProof() passes — it proves the intermediate node is "in the tree"
    5. Order fulfilled with tokenId = intermediate_hash — seller receives wrong token
    6. Attacker keeps the desired NFTs, seller receives a useless/nonexistent tokenId
  invariante: >
    Only leaf nodes (actual tokenIds) must be valid fulfillment tokens.
    verifyProof(tokenId, proof, root) must additionally verify tokenId is a leaf, not internal node.
  que_mirar:
    - "Does Merkle proof verification check that the submitted value is a leaf vs internal node?"
    - "Is the tokenId hashed before being used as a leaf? (leaf = keccak(tokenId), not tokenId itself)"
    - "grep: CriteriaResolution, identifierOrCriteria, verifyProof, MerkleProof, leaf"
    - "Is there a double-hash protection (leaf = keccak(keccak(tokenId)))?"
  como_se_arregla: >
    Hash tokenId before using as leaf: leaf = keccak256(abi.encodePacked(tokenId)).
    Standard OZ MerkleProof uses keccak256(abi.encodePacked(leaf)) — the double hash
    prevents second pre-image attacks where internal nodes are mistaken for leaves.
  trampas:
    - "Standard OZ MerkleProof.verify() is safe — bug appears in custom implementations that skip leaf hashing"
    - "Seaport fixed this after the Code4rena finding"
  confianza: alta
  verificado: true
  tags: [ERC721, merkle-proof, tokenId, criteria, seaport, leaf-collision]
  solodit_ids: [2623]
  incidentes:
    - protocol: "OpenSea Seaport"
      firm: "Code4rena"
      impact: "MEDIUM"
      finder: "cmichel, frangio, Spearbit"
      title: "Merkle tree criteria can be resolved by wrong tokenIds via internal node collision"
      slug: "m-01-merkle-tree-criteria-can-be-resolved-by-wrong-tokenids-code4rena-opensea-seaport-seaport-contest-git"

- id: nft-011
  pattern: nft-reentrancy-mint-during-claim
  name: "Reentrancy in claim/mint path allows minting extra NFTs via onERC721Received callback"
  severity: high
  causa_raiz: >
    Protocols that mint NFTs as rewards (fighter NFTs, achievement tokens) update the
    numRoundsClaimed counter AFTER calling _safeMint() or safeTransferFrom(). The mint
    triggers onERC721Received on the recipient contract. Attacker reenters claimRewards()
    from the callback — numRoundsClaimed is still stale, allowing another claim.
  como_funciona: |
    1. Winner calls claimRewards(rounds=[1,2]) — expects 2 NFTs
    2. Protocol mints NFT for round 1: _safeMint(attacker, newTokenId)
    3. onERC721Received fires on attacker — attacker reenters claimRewards(rounds=[1])
    4. numRoundsClaimed[attacker] = 0 (not yet updated) — round 1 minted again
    5. Outer claimRewards continues: mints round 2
    6. Attacker has 3 NFTs from 2 rounds of winning
  invariante: >
    After claimRewards(rounds), attacker's NFT balance must equal
    sum(winningsPerRound[attacker][r] for r in rounds) — no more.
    numRoundsClaimed must be updated BEFORE any _safeMint call.
  que_mirar:
    - "Is numRoundsClaimed or equivalent updated before or after _safeMint/_safeTransfer?"
    - "Is there a nonReentrant guard on claimRewards or claim functions?"
    - "grep: claimRewards, _safeMint, numRoundsClaimed, nonReentrant, onERC721Received"
    - "Pattern: any function that mints NFT rewards and tracks claim state"
  como_se_arregla: >
    Update claim state (numRoundsClaimed[user] = newValue) BEFORE calling _safeMint.
    Add nonReentrant modifier to claimRewards.
    Use _mint instead of _safeMint when recipient is trusted (EOA with no callback).
  trampas:
    - "_mint does NOT call onERC721Received — safe for EOA recipients but breaks ERC721 compliance for contracts"
    - "The attack requires the recipient to be a smart contract with malicious onERC721Received"
  confianza: alta
  verificado: true
  tags: [ERC721, reentrancy, mint, claimRewards, onERC721Received, CEI]
  solodit_ids: [32190]
  incidentes:
    - protocol: "AI Arena"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Player mints extra fighter NFTs via reentrancy on claimRewards using onERC721Received"
      slug: "h-08-player-can-mint-more-fighter-nfts-during-claim-of-rewards-by-leveraging-reentrancy-code4rena-ai-arena-ai-arena-contest-git"
```

---

## Quick Grep Targets — NFT Audits

```bash
# Callback reentrancy
grep -rn "safeTransferFrom\|onERC721Received\|onERC1155Received" src/
grep -rn "_safeMint\|_safeTransfer" src/
grep -rn "nonReentrant" src/ | grep -v "nonReentrant.*function"  # find unguarded funcs

# Receiver validation
grep -rn "0x150b7a02\|IERC721Receiver\|_checkOnERC721Received" src/

# Approval hijacking
grep -rn "setApprovalForAll\|approve\|getApproved\|isApprovedForAll" src/
grep -rn "setFallbackHandler\|fallbackHandler\|execute(" src/  # Gnosis Safe patterns

# V3 Position valuation
grep -rn "sqrtPriceX96\|getAmountsForLiquidity\|LiquidityAmounts\|slot0" src/
grep -rn "getTokenPrice.*tokenId\|tokenId.*getPrice\|UniswapV3OracleWrapper" src/
grep -rn "tickLower\|tickUpper\|liquidity.*position\|positionData" src/

# Collateral custody
grep -rn "onERC721Received.*operator\|onERC721Received.*from" src/
grep -rn "positions\[operator\]\|collateral\[operator\]" src/  # should be [from]
grep -rn "pause\|blacklist\|whenNotPaused" src/  # NFT collateral pause risk

# TokenId accounting
grep -rn "tokenId.*push\|nfts\.push\|_removeNft\|nfts\[i\]" src/
grep -rn "bucket\|tickRange\|same.*tick\|memorializePosition" src/  # bucket collision
grep -rn "MerkleProof\|identifierOrCriteria\|leaf\|criteria" src/

# Claim reentrancy
grep -rn "numRoundsClaimed\|claimRewards.*_safeMint\|_safeMint.*claim" src/
```

---

## Fuzzing Priorities

```
Priority 1 — safeTransferFrom Reentrancy:
  Invariant: collateralCount[user] after removeCollateral(N tokenIds) == pre - N
  How: malicious receiver reenters removeCollateral in onERC721Received
       assert: tokenIds extracted == tokenIds paid for

Priority 2 — V3 Position Valuation at Extremes:
  Invariant: value(tokenId) == amount0 * price0 + amount1 * price1 (computed at current sqrtPriceX96)
  How: fuzz sqrtPriceX96 from 0 to max; for each price, compare oracle value vs on-chain LiquidityAmounts

Priority 3 — onERC721Received Permissiveness:
  Invariant: nfts.length <= WHITELIST_COUNT (if whitelist enforced)
  How: send 1000 NFTs from random contracts; call removeNft(legitimateId) — must not OOG

Priority 4 — Claim Reentrancy:
  Invariant: balance_after_claim == balance_before + expected_rewards_for_rounds
  How: malicious receiver reenters claim in onERC721Received; assert no extra NFTs minted

Priority 5 — Operator vs From in onERC721Received:
  Invariant: positions credited to `from`, never to `operator`
  How: call safeTransferFrom(owner, protocol, tokenId) via approved operator; check positions[operator] == 0
```
