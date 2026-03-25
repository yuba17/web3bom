# NFT Marketplace Vulnerabilities — Combat Briefing

> Attack surface: order-based NFT trading (signatures, fulfillment, cancellation), royalty
> enforcement (ERC-2981, custom), conduit/approval management, collection offers, partial fills,
> floor price oracles for NFT-backed lending, and cross-marketplace listing migration.
> Relevant for Seaport, Blur/Blend, LooksRare, X2Y2, Sudoswap, Reservoir, Foundation,
> Thirdweb, reNFT, and any custom marketplace or aggregator contract.
> Sources: verified Solodit findings from Code4rena/Sherlock/Spearbit/Cantina/Cyfrin audits.

---

## 1. Order Signature Replay & Reuse

```yaml
- id: nm-001
  pattern: order-signature-replay
  name: "Signed marketplace order executed multiple times or on wrong chain"
  severity: critical
  causa_raiz: >
    Marketplace orders are signed off-chain (EIP-712 or EIP-1271). If the signed data
    does not include a unique nonce that is consumed on-chain, or omits chainId / contract
    address from the domain separator, the same signature can be replayed: (a) multiple times
    on the same chain to drain the seller's approved tokens, (b) cross-chain if the marketplace
    is deployed at the same address on multiple chains, or (c) across marketplace versions if
    the domain separator doesn't change.
  como_funciona: |
    1. Seller signs an EIP-712 order: sell NFT #42 for 1 ETH, nonce=5
    2. Buyer fills the order — NFT transferred, payment sent
    3. Seller re-acquires NFT #42 (buys it back from secondary)
    4. Attacker replays the SAME signature — contract accepts because:
       a) nonce was not incremented/consumed, OR
       b) nonce is per-order-type, not global, OR
       c) signature hash was not stored in usedSignatures mapping
    5. NFT #42 sold again at the old price without seller's consent
    Cross-chain variant: same signature submitted on L2 where marketplace is deployed
    at the same address with the same domain separator.
  invariante: |
    // After a signed order is filled, the same signature MUST revert on second use
    function invariant_order_signature_single_use() internal {
        bytes32 orderHash = marketplace.getOrderHash(order);
        // First fill succeeds
        marketplace.fulfillOrder(order, signature);
        // Second fill MUST revert
        try marketplace.fulfillOrder(order, signature) {
            t(false, "ORDER-REPLAY: signature accepted twice");
        } catch {}
    }
  que_mirar:
    - "Is nonce incremented BEFORE or AFTER order execution? (must be before)"
    - "Is the order hash stored in a 'filled' or 'cancelled' mapping after execution?"
    - "Does EIP-712 domain include chainId AND verifyingContract?"
    - "Can the same nonce be used across different order types (listing vs bid)?"
    - "grep: ecrecover, ECDSA.recover, isValidSignature, EIP712, DOMAIN_SEPARATOR"
    - "grep: nonces, _nonce, filledAmount, orderStatus, isOrderFilled"
    - "Is the nonce space shared between maker and taker, or per-address?"
  como_se_arregla: >
    Include a monotonically increasing nonce in the signed data, increment it atomically
    on fill. Store orderHash in a filledOrCancelled mapping. Include chainId and
    verifyingContract in the EIP-712 domain separator. Seaport uses a counter-based
    nonce system where incrementCounter() invalidates ALL previous orders.
  trampas:
    - "A per-order nonce (not per-user) can still allow replay if the order is re-created with the same params"
    - "EIP-1271 (smart contract wallets) may have different replay assumptions than EOA signatures"
    - "Some marketplaces use off-chain order books — the replay may happen at the relay level, not on-chain"
    - "Seaport's counter system means ALL orders are invalidated on increment — this is by design, not a bug"
  solodit_ids:
    - m-02-the-signatures-are-replayable-code4rena-krystal-defi-krystal-defi-git
    - oin8-4-order-fulfillment-can-be-front-ran-to-steal-from-taker-using-reinitialization-hexens-none-1inch-markdown
    - h-08-users-can-avoid-paying-fees-while-trading-trustlessly-using-goloms-network-effects-code4rena-golom-golom-contest-git
  incidentes:
    - protocol: "OpenSea (Wyvern V1)"
      date: "2022-01"
      impact: "$1.7M+ in NFTs stolen"
      detail: "Inactive listings from Wyvern V1 remained valid on-chain. Attackers bought NFTs (BAYC, CoolCats) at stale prices from users who never cancelled old listings before migrating to Seaport."
    - protocol: "Foundation"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "EIP-712 private sale signature replayable if seller re-acquires NFT"
      slug: "h-02-creators-can-steal-sale-revenue-from-owners-sales-code4rena-foundation-foundation-git"
  confianza: alta
  verificado: true
```

---

## 2. Bid Spoofing / Phantom Bids

```yaml
- id: nm-002
  pattern: bid-without-balance-approval
  name: "Placing bids without sufficient token balance or approval — phantom bid attack"
  severity: high
  causa_raiz: >
    Marketplace allows placing bids (signed orders to buy) without verifying at bid-time
    that the bidder has sufficient ERC-20 balance AND approval to the marketplace/conduit.
    The bid appears valid in the UI, seller accepts, but the fill transaction reverts.
    This enables: (a) DoS on sellers who delist thinking they have a buyer, (b) price
    manipulation by placing high phantom bids to inflate perceived value, (c) griefing
    auction-style sales where phantom bids block real bidders.
  como_funciona: |
    1. Attacker signs a bid: "Buy NFT #100 for 50 WETH"
    2. Attacker has 0 WETH balance and 0 approval to marketplace
    3. Bid appears in marketplace UI — seller sees 50 WETH offer
    4. Seller delists from other marketplaces, accepts bid
    5. Fill transaction reverts: transferFrom(attacker, seller, 50 WETH) fails
    6. Seller lost visibility on other platforms, NFT now unlisted
    Variant: attacker places bid, gets approval, then revokes approval before fill.
    Variant: attacker uses flash loan to show balance at bid-time check, then moves funds.
  invariante: |
    // A bid that can be submitted to the order book MUST be fillable at submission time
    function invariant_bid_has_balance() internal {
        uint256 bidAmount = order.consideration[0].amount;
        address bidder = order.offerer;
        address currency = order.consideration[0].token;
        uint256 balance = IERC20(currency).balanceOf(bidder);
        uint256 allowance = IERC20(currency).allowance(bidder, address(marketplace));
        t(balance >= bidAmount, "BID-SPOOF: bidder lacks balance");
        t(allowance >= bidAmount, "BID-SPOOF: bidder lacks approval");
    }
  que_mirar:
    - "Does the marketplace validate bidder balance/approval at bid submission or only at fill?"
    - "Can bids be submitted entirely off-chain with no on-chain validation?"
    - "Is there an escrow mechanism for bids (WETH locked on bid)?"
    - "grep: balanceOf, allowance, transferFrom in bid/offer flow"
    - "Does the protocol use WETH wrapping at fill time (msg.value) or pre-approved ERC-20?"
  como_se_arregla: >
    Option 1: Escrow bid funds on-chain at bid time (like Foundation auctions).
    Option 2: Validate balance + approval on-chain at bid submission (gas cost).
    Option 3: Off-chain validation by the order book relay with periodic re-checks.
    Seaport relies on the conduit having approval — phantom bids are possible but the
    UI filters them. Blur requires WETH approval to the Blur pool before bidding.
  trampas:
    - "WETH balance checks can be manipulated with flash loans — check at fill time too"
    - "Some protocols intentionally allow 'soft' bids (no escrow) for UX — verify this is documented"
    - "Approval to a conduit (not the marketplace directly) means checking the wrong address"
    - "ERC-20 tokens with transfer hooks can revert selectively — balance exists but transfer fails"
  solodit_ids:
    - liquidator-can-bid-with-insufficient-cash-sigmaprime-none-derive-pdf
    - the-extra-data-encoded-stack-provided-to-advanced-orders-to-seaport-are-not-validated-properly-spearbit-none-astaria-pdf
  incidentes:
    - protocol: "Various NFT marketplaces"
      date: "2022-2023"
      impact: "UI manipulation, seller griefing"
      detail: "Phantom bids were a persistent issue on OpenSea and X2Y2 where off-chain order books accepted bids without on-chain balance verification, leading to failed fills and wasted gas."
  confianza: media
  verificado: true
```

---

## 3. Royalty Bypass via Private/Direct Transfer

```yaml
- id: nm-003
  pattern: royalty-bypass-private-sale
  name: "Transferring NFT outside marketplace to skip royalty enforcement"
  severity: medium
  causa_raiz: >
    ERC-2981 is informational only — it returns royalty info but does NOT enforce payment.
    If the marketplace is the sole enforcer of royalties (via consideration items in Seaport,
    or explicit royalty splits), any transfer that bypasses the marketplace (direct
    transferFrom, Gnosis Safe batch, custom P2P contract) skips royalty entirely.
    Operator filter registries (OpenSea's) tried to block non-royalty-enforcing marketplaces
    but are bypassable by wrapping the NFT or using a compliant-looking proxy.
  como_funciona: |
    1. Collection enforces 5% royalty via ERC-2981 + operator filter registry
    2. Seller lists NFT at 10 ETH on royalty-enforcing marketplace
    3. Buyer contacts seller off-chain, agrees to buy at 9.5 ETH (saves royalty)
    4. Seller calls transferFrom(seller, buyer, tokenId) directly — no marketplace involved
    5. Buyer sends 9.5 ETH via separate transaction
    6. Creator receives 0 royalty instead of 0.5 ETH
    Variant: Wrapper contract (ERC-721 wrapper) that holds the original NFT and issues
    a wrapped version that can be traded freely without operator filter restrictions.
  invariante: |
    // For protocols that ENFORCE royalties: every sale event must include royalty payment
    function invariant_royalty_always_paid() internal {
        (address receiver, uint256 royalty) = IERC2981(nft).royaltyInfo(tokenId, salePrice);
        uint256 receiverBalAfter = IERC20(currency).balanceOf(receiver);
        t(receiverBalAfter >= receiverBalBefore + royalty, "ROYALTY-SKIP: creator not paid");
    }
  que_mirar:
    - "Does the NFT use operator filter registry (OperatorFilterer)?"
    - "Can transferFrom be called directly without going through the marketplace?"
    - "Does the marketplace enforce royalty in consideration items or as a separate call?"
    - "grep: OperatorFilterer, setApprovalForAll, onlyAllowedOperator"
    - "grep: royaltyInfo, _payRoyalty, royaltyAmount, ROYALTY_BPS"
    - "Is there a wrapper contract that circumvents the operator filter?"
  como_se_arregla: >
    On-chain enforcement at the NFT level: override transferFrom/safeTransferFrom to
    only allow transfers through approved marketplace contracts (operator filter).
    Accept that royalties are inherently unenforceable for ERC-721 without transfer
    restrictions. Newer standards (ERC-721C by Limit Break) add programmable royalties
    at the token level.
  trampas:
    - "Operator filter only works for marketplace contracts — direct EOA-to-EOA transfers are always allowed in standard ERC-721"
    - "Some collections intentionally have 0 royalty — don't flag this as a bypass"
    - "Blur famously made royalties optional, leading to the royalty wars of 2023 — this is a design choice, not a bug"
    - "Wrapped NFTs break provenance tracking but are hard to prevent without breaking composability"
  solodit_ids:
    - absence-of-royalty-enforcement-ottersec-none-tensor-foundation-pdf
    - m-4-users-can-bypass-player-royalties-on-eip2981-compatible-markets-by-selling-clubs-as-a-whole-sherlock-none-footium-git
    - m-16-inappropriate-support-of-eip-2981-code4rena-foundation-foundation-contest-git
  incidentes:
    - protocol: "Blur vs OpenSea"
      date: "2023-02"
      impact: "Industry-wide royalty revenue decline ~80%"
      detail: "Blur made royalties optional (minimum 0.5%), causing a race to the bottom. OpenSea responded by making royalties optional too. Creator royalty revenue dropped from ~$200M/quarter to ~$40M/quarter."
    - protocol: "Sudoswap V1"
      date: "2022-07"
      impact: "Zero royalties on all trades"
      detail: "Sudoswap AMM launched with no royalty enforcement at all, sparking the royalty enforcement debate."
  confianza: alta
  verificado: true
```

---

## 4. Collection Offer Manipulation — Lowest-Value Item Fill

```yaml
- id: nm-004
  pattern: collection-offer-lowest-value-fill
  name: "Collection offer accepted with lowest-value item in the collection"
  severity: high
  causa_raiz: >
    A collection-wide offer (bid on ANY NFT in a collection) specifies a fixed price
    for any tokenId. If the collection has heterogeneous value distribution (e.g., rare
    traits worth 100x floor), the bidder intends to buy a floor-priced item but the
    seller can fill with ANY tokenId — including items that are worth far less than the
    bid price (damaged, low-trait, or even specially minted low-value items if the
    collection allows minting). The marketplace does not validate that the filled item
    meets any minimum quality criteria.
  como_funciona: |
    1. Bidder places collection offer: "Buy any CryptoPunk for 50 ETH"
    2. Bidder intends to get a floor Punk (~50 ETH value)
    3. Seller owns Punk #9999 (zombie trait, floor is 50 ETH) AND Punk #1234 (alien trait, worth 2000 ETH)
    4. MEV bot or arbitrageur sees the collection offer
    5. Bot buys the cheapest Punk available (45 ETH on another market) and fills the collection offer for 50 ETH
    6. Bot profits 5 ETH — this is expected behavior for floor items
    ATTACK variant (NFT lending):
    1. Protocol allows collection offers for NFT-backed loans
    2. Borrower takes a loan against Punk #1234 (alien, 2000 ETH value) at 50 ETH LTV
    3. Borrower replaces collateral with Punk #9999 (floor, 50 ETH value) via collection offer fill
    4. Loan is now undercollateralized — borrower defaults and keeps 2000 ETH item
  invariante: |
    // For collection offers with criteria, the filled item MUST match criteria
    function invariant_collection_offer_criteria() internal {
        // If using Merkle proof criteria (Seaport criteria resolver):
        bytes32 leaf = keccak256(abi.encodePacked(filledTokenId));
        t(MerkleProof.verify(proof, criteriaRoot, leaf), "COLLECTION-OFFER: tokenId not in criteria set");
    }
  que_mirar:
    - "Does the collection offer accept ANY tokenId or only those matching a criteria proof?"
    - "Is there a Merkle tree restricting which tokenIds can fill the offer?"
    - "Can the offer be filled with a tokenId that was minted AFTER the offer was created?"
    - "grep: criteria, identifierOrCriteria, CriteriaResolver, merkleRoot"
    - "grep: collectionOffer, floorBid, anyTokenId"
    - "For NFT lending: can collateral be swapped via collection offer fill?"
  como_se_arregla: >
    Use Seaport's criteria-based orders with a Merkle tree of acceptable tokenIds.
    For lending: require explicit tokenId in the loan offer, not collection-wide.
    For trait-based offers: include the trait criteria in the signed data and verify
    on-chain via oracle or Merkle proof.
  trampas:
    - "Collection offers on homogeneous collections (all items equal value) are safe — only heterogeneous collections have this risk"
    - "Seaport criteria resolvers ARE the mitigation — but the criteria tree must be correctly constructed"
    - "Floor price != individual item price. A collection offer at floor price is intended to get floor items"
  solodit_ids:
    - h-02-oraclepoolofferhandlers-_getfactors-allows-exact-tokenid-offer-terms-to-be-used-for-collection-offers-a-borrower-can-take-on-a-loan-with-incorrec
    - underlying-nfts-are-assigned-incorrect-nftid-for-collections-quantstamp-niftyapes-seller-financing-markdown
    - m-01-merkle-tree-criteria-can-be-resolved-by-wrong-tokenids-code4rena-opensea-opensea-seaport-contest-git
  incidentes:
    - protocol: "Seaport / OpenSea"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Merkle tree criteria can be resolved by wrong tokenIDs"
      slug: "m-01-merkle-tree-criteria-can-be-resolved-by-wrong-tokenids-code4rena-opensea-opensea-seaport-contest-git"
    - protocol: "Gondi (NFT lending)"
      firm: "Code4rena"
      impact: "HIGH"
      title: "OraclePoolOfferHandler allows exact tokenId terms used for collection offers — incorrect loan terms"
      slug: "h-02-oraclepoolofferhandlers-_getfactors-allows-exact-tokenid-offer-terms-to-be-used-for-collection-offers-a-borrower-can-take-on-a-loan-with-incorrec"
  confianza: alta
  verificado: true
```

---

## 5. Partial Fill Order Griefing

```yaml
- id: nm-005
  pattern: partial-fill-griefing
  name: "Filling tiny fractions of a partial order repeatedly to drain maker gas or reset state"
  severity: medium
  causa_raiz: >
    Seaport and similar protocols support partial fills: an order for 100 ERC-1155 tokens
    can be filled 1 at a time. Each fill is a separate transaction that costs gas for
    the contract to process (storage updates, event emission, consideration distribution).
    An attacker can fill orders with numerator=1, denominator=MAX to fill the minimum
    possible amount each time, forcing the order creator to pay gas for state updates
    or causing the order to be marked as "partially filled" (blocking other fills in
    some implementations). Additionally, truncation in fraction math can cause the order
    to be fillable for MORE than the original amount.
  como_funciona: |
    1. Seller creates partial-fill order: sell 1000 ERC-1155 tokens for 10 ETH total
    2. Attacker fills with fraction 1/1000 — buys 1 token for 0.01 ETH
    3. Repeat 999 times — each fill costs gas, emits events, updates storage
    4. Seller receives 9.99 ETH in 999 micro-transactions (gas-inefficient)
    TRUNCATION variant (Seaport H-01):
    1. Order: sell 7 tokens, numerator/denominator allows partial fill
    2. Attacker fills with specific fraction that causes truncation in _applyFractions
    3. filledNumerator resets due to overflow/truncation — order can be filled AGAIN
    4. Seller unknowingly sells more tokens than intended
  invariante: |
    // Total amount filled across all partial fills MUST NOT exceed the original order amount
    function invariant_partial_fill_bounded() internal {
        uint256 totalFilled = marketplace.getOrderFilledAmount(orderHash);
        uint256 originalAmount = order.offer[0].endAmount;
        t(totalFilled <= originalAmount, "PARTIAL-FILL: exceeded original order amount");
    }
    // Each partial fill must transfer a non-dust amount
    function invariant_partial_fill_minimum() internal {
        uint256 fillAmount = (order.offer[0].endAmount * numerator) / denominator;
        t(fillAmount >= MIN_FILL_AMOUNT, "PARTIAL-FILL: dust amount griefing");
    }
  que_mirar:
    - "How are fractions (numerator/denominator) applied to order amounts?"
    - "Is there truncation in the fraction math that could cause fill counter to wrap?"
    - "Is there a minimum fill amount to prevent dust fills?"
    - "grep: numerator, denominator, _applyFractions, filledNumerator, partialFill"
    - "grep: OrderStatus, totalFilled, remainingNumerator"
    - "Can partial fill + cancel + re-create order be used to drain more than intended?"
  como_se_arregla: >
    Set a minimum fill fraction (e.g., at least 1% of order per fill).
    Use safe math for fraction application — Seaport fixed the truncation issue in v1.2.
    Track filled amounts as absolute values (not fractions) to prevent truncation resets.
    Consider making partial fills opt-in, not default.
  trampas:
    - "Partial fills are a FEATURE in ERC-1155 orders — only a bug when they can exceed the original amount"
    - "ERC-721 orders are not partially fillable (1 NFT = 1 fill) — this pattern only applies to ERC-1155 or ERC-20 consideration"
    - "Gas griefing alone is usually Low severity unless it causes fund loss"
  solodit_ids:
    - h-01-truncation-in-ordervalidator-can-lead-to-resetting-the-fill-and-selling-more-tokens-code4rena-opensea-opensea-seaport-contest-git
    - double-counted-fees-in-partial-bid-claims-mixbytes-none-xpress-markdown
    - h-03-orderamount-not-accounted-when-filling-pashov-audit-group-none-sofamon-august-markdown
    - h-07-attacker-can-lock-lender-nfts-and-erc20-in-the-safe-if-the-offer-is-set-to-partial-code4rena-renft-renft-git
  incidentes:
    - protocol: "OpenSea (Seaport)"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Truncation in OrderValidator resets fill — seller sells more tokens than intended"
      slug: "h-01-truncation-in-ordervalidator-can-lead-to-resetting-the-fill-and-selling-more-tokens-code4rena-opensea-opensea-seaport-contest-git"
      detail: "Specific numerator/denominator values caused filledNumerator to truncate to 0 when checked against the order, allowing re-fills beyond the original amount."
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Partial fill offer locks lender NFTs and ERC-20 in safe"
      slug: "h-07-attacker-can-lock-lender-nfts-and-erc20-in-the-safe-if-the-offer-is-set-to-partial-code4rena-renft-renft-git"
  confianza: alta
  verificado: true
```

---

## 6. Floor Price Oracle Manipulation for NFT Lending

```yaml
- id: nm-006
  pattern: nft-floor-oracle-manipulation
  name: "Manipulating NFT floor price oracle to inflate collateral value in lending"
  severity: critical
  causa_raiz: >
    NFT-backed lending protocols (Blend, BendDAO, ParaSpace, JPEG'd) use floor price
    oracles to value collateral. Unlike fungible token oracles (Chainlink, Uniswap TWAP),
    NFT floor prices are derived from thin order books (lowest ask on OpenSea/Blur) or
    off-chain feeds. An attacker can manipulate the floor by: (a) placing and filling
    wash-trade listings at inflated prices, (b) removing all asks below target price,
    (c) manipulating the TWAP window by timing buys, (d) exploiting the oracle's
    reliance on a single marketplace's data.
  como_funciona: |
    1. Attacker owns 10 NFTs from collection X (floor: 5 ETH)
    2. Attacker lists all 10 at 50 ETH on the oracle's source marketplace
    3. Attacker buys 3 of their own listings (wash trade) — floor now shows 50 ETH
    4. Attacker deposits 1 NFT as collateral in lending protocol
    5. Oracle reports floor = 50 ETH → attacker borrows 25 ETH (50% LTV)
    6. Attacker defaults on loan — protocol left with NFT worth 5 ETH, lost 20 ETH
    Sandwich variant:
    1. Attacker sees pending loan creation tx in mempool
    2. Front-runs: buys floor items to inflate price
    3. Loan created at inflated valuation
    4. Back-runs: sells items back, price returns to normal
    5. Loan is instantly undercollateralized
  invariante: |
    // Floor price oracle must be resistant to short-term manipulation
    function invariant_floor_price_sanity() internal {
        uint256 currentFloor = oracle.getFloorPrice(collection);
        uint256 twap24h = oracle.getTwapFloor(collection, 24 hours);
        // Floor should not deviate more than 50% from 24h TWAP
        t(currentFloor <= twap24h * 150 / 100, "FLOOR-ORACLE: price spike >50% from TWAP");
        t(currentFloor >= twap24h * 50 / 100, "FLOOR-ORACLE: price crash >50% from TWAP");
    }
  que_mirar:
    - "What is the oracle source? Single marketplace or aggregated?"
    - "Is there a TWAP mechanism or is it spot floor price?"
    - "Can the floor price be updated in the same block as a loan creation?"
    - "Is there a circuit breaker for large price movements?"
    - "grep: floorPrice, getFloorPrice, updateFloor, twap, oraclePrice"
    - "grep: maxLTV, collateralValue, healthFactor, liquidationThreshold"
    - "Does the oracle use off-chain signatures (trusted reporter) or on-chain data?"
  como_se_arregla: >
    Use TWAP over multiple days (not hours). Aggregate from multiple marketplaces.
    Use Chainlink NFT floor price feeds where available. Implement circuit breakers
    for >20% price changes. Require a time delay between oracle update and loan
    creation. Cap LTV at conservative levels (30-40% for NFTs vs 80% for blue-chip
    fungible tokens). Use individual appraisals for high-value items, not floor price.
  trampas:
    - "Low-liquidity collections are more vulnerable but also less targeted (lower TVL)"
    - "Chainlink NFT floor feeds only exist for a few blue-chip collections"
    - "Some protocols use their own off-chain oracle — this introduces centralization but prevents manipulation"
    - "Flash loan attacks don't work if oracle requires multi-block TWAP"
  solodit_ids:
    - h-04-anyone-can-prevent-themselves-from-being-liquidated-as-long-as-they-hold-one-of-the-supported-nfts-code4rena-paraspace-paraspace-contest-git
    - borrowers-could-manipulate-the-floor-price-quantstamp-nemeos-markdown
    - h-01-avoidance-of-liquidation-via-malicious-oracle-code4rena-abracadabra-money-abranft-contest-git
    - dos-through-sandwich-attack-on-ceilingprice-zokyo-none-limit-break-markdown
  incidentes:
    - protocol: "BendDAO"
      date: "2022-08"
      impact: "Near-protocol insolvency, ~$50M at risk"
      detail: "During the NFT bear market, BAYC floor dropped rapidly. BendDAO's oracle lagged, liquidations cascaded, and bad debt accumulated because no one bid on liquidated NFTs. Protocol had to lower liquidation thresholds and accept bad debt."
    - protocol: "ParaSpace"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Anyone can prevent liquidation by holding a supported NFT"
      slug: "h-04-anyone-can-prevent-themselves-from-being-liquidated-as-long-as-they-hold-one-of-the-supported-nfts-code4rena-paraspace-paraspace-contest-git"
    - protocol: "Abracadabra (abrNFT)"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Avoidance of liquidation via malicious oracle"
      slug: "h-01-avoidance-of-liquidation-via-malicious-oracle-code4rena-abracadabra-money-abranft-contest-git"
  confianza: alta
  verificado: true
```

---

## 7. Conduit / Approval Persistence After Order Cancellation

```yaml
- id: nm-007
  pattern: conduit-approval-persistence
  name: "Marketplace approval persists after order cancellation — stale approval exploitable"
  severity: high
  causa_raiz: >
    Seaport uses a conduit system: users approve the conduit (not the marketplace directly)
    to transfer their assets. When a user cancels an order, the order is marked as cancelled
    on-chain but the conduit approval remains. If the user forgets to revoke the conduit
    approval AND signs a new order with the same conduit, the old approval allows the new
    order to execute. More broadly: any marketplace that requires setApprovalForAll()
    retains the ability to transfer ALL of the user's NFTs in that collection, not just
    the listed one. Cancelling a listing does not revoke this approval.
  como_funciona: |
    1. User calls setApprovalForAll(marketplace, true) to list NFT #42
    2. User cancels the listing — marketplace marks order as cancelled
    3. User's approval remains: marketplace can still transfer ANY of user's NFTs
    4. If marketplace contract has a vulnerability, or user signs another order
       inadvertently, the stale approval allows unauthorized transfers
    5. Attacker exploits marketplace bug to call transferFrom using the stale approval
    Seaport conduit variant:
    1. User opens conduit channel to marketplace zone
    2. User cancels order but doesn't close conduit channel
    3. A different zone (or compromised zone) can use the same conduit to transfer assets
  invariante: |
    // After all orders are cancelled, the approval SHOULD be revoked
    // (this is a best-practice check, not always enforced by marketplaces)
    function invariant_approval_matches_active_orders() internal {
        bool hasActiveOrders = marketplace.hasActiveOrders(user, nftContract);
        bool hasApproval = IERC721(nftContract).isApprovedForAll(user, conduit);
        // If no active orders, approval should not exist
        if (!hasActiveOrders) {
            t(!hasApproval, "STALE-APPROVAL: approval persists with no active orders");
        }
    }
  que_mirar:
    - "Does cancelling an order revoke the underlying approval/conduit?"
    - "Is setApprovalForAll used (blanket) or approve for specific tokenId?"
    - "Can the conduit be shared across multiple zones/marketplaces?"
    - "grep: setApprovalForAll, approve, conduit, openChannel, closeChannel"
    - "grep: cancel, cancelOrder, incrementCounter, _cancel"
    - "What happens to approvals when the marketplace is upgraded (proxy)?"
  como_se_arregla: >
    Educate users to revoke approvals after delisting. Marketplace UIs should prompt
    approval revocation on cancel. Use per-token approve() instead of setApprovalForAll()
    where feasible. Seaport's design accepts this tradeoff — the conduit is the trust
    boundary, not individual orders. Consider Permit2-style time-limited approvals.
  trampas:
    - "setApprovalForAll is standard UX for marketplaces — flagging it as a bug requires showing actual exploitation path"
    - "Conduit approvals are separate from order validity — a cancelled order with an active approval is normal"
    - "The real risk is when the conduit/marketplace contract itself has a vulnerability"
  solodit_ids:
    - h-04-approvals-not-cleared-after-key-transfer-code4rena-unlock-protocol-unlock-protocol-contest-git
    - h-02-unrevoked-approvals-allow-nft-recovery-by-previous-owner-code4rena-superposition-superposition-git
    - h-1-escrow-approvals-are-not-cleared-when-club-is-transferred-allowing-for-abuse-after-transfer-sherlock-none-footium-git
    - h-02-nft-transfer-approvals-are-not-removed-and-cannot-be-revoked-thus-leading-to-loss-of-nft-tokens-code4rena-visor-visor-contest-git
  incidentes:
    - protocol: "OpenSea (Wyvern)"
      date: "2022-01"
      impact: "$1.7M+ in NFTs stolen"
      detail: "Users who migrated from Wyvern to Seaport still had Wyvern approvals active. Attackers used stale Wyvern listings with active approvals to buy NFTs at old (low) prices."
    - protocol: "Visor Finance"
      firm: "Code4rena"
      impact: "HIGH"
      title: "NFT approvals not removed and cannot be revoked — leads to NFT loss"
      slug: "h-02-nft-transfer-approvals-are-not-removed-and-cannot-be-revoked-thus-leading-to-loss-of-nft-tokens-code4rena-visor-visor-contest-git"
  confianza: alta
  verificado: true
```

---

## 8. Order Cancellation Front-Running

```yaml
- id: nm-008
  pattern: order-cancel-frontrun
  name: "Seller's cancel transaction front-run by buyer's fill — NFT sold despite cancellation"
  severity: high
  causa_raiz: >
    Marketplace order cancellation and fulfillment are separate transactions competing for
    block inclusion. A seller who sees unfavorable conditions (floor price rising, so listing
    is underpriced) submits a cancel transaction. A buyer (or MEV bot) sees the cancel in
    the mempool and front-runs it with a fill transaction at the old price. The fill executes
    first, the cancel executes second (but order is already filled, cancel is no-op).
    The seller loses the NFT at the stale price.
  como_funciona: |
    1. Seller listed NFT at 5 ETH when floor was 5 ETH
    2. Floor rises to 10 ETH — seller submits cancel tx (gas: 20 gwei)
    3. MEV bot sees cancel in mempool, submits fill tx with 25 gwei gas
    4. Fill executes first — NFT sold for 5 ETH (50% below current floor)
    5. Cancel executes second — but order is already filled, cancel is no-op
    6. Seller lost 5 ETH of value
    Variant: Dutch auction — price is decreasing. Seller wants to cancel at current price
    but fill at a LOWER price (further in the auction) front-runs the cancel.
  invariante: |
    // If cancel tx and fill tx are in the same block, cancel MUST take priority
    // (this is impossible to enforce on-chain without a commit-reveal scheme)
    // Alternative: time-lock on fills after listing
    function invariant_cancel_priority() internal {
        // After cancel block, no fill should succeed
        uint256 cancelBlock = marketplace.getCancelBlock(orderHash);
        if (cancelBlock > 0 && block.number >= cancelBlock) {
            try marketplace.fulfillOrder(order, signature) {
                t(false, "CANCEL-FRONTRUN: order filled after cancel submitted");
            } catch {}
        }
    }
  que_mirar:
    - "Is there a time delay between listing and when the order becomes fillable?"
    - "Can the seller use Flashbots/private mempool to cancel without public mempool exposure?"
    - "Does the marketplace support 'gasless cancellation' (off-chain cancel via relay)?"
    - "grep: cancel, cancelOrder, incrementCounter, fulfillOrder, validateOrder"
    - "Is there a nonce-based bulk cancellation (Seaport's incrementCounter)?"
    - "Does the marketplace have an on-chain auction with explicit cancel protection?"
  como_se_arregla: >
    Seaport's incrementCounter() invalidates ALL orders atomically (MEV bots can't
    front-run individual cancels if the seller uses counter increment). Off-chain order
    books can remove the order before it reaches the chain. Dutch auctions should have
    explicit cancel protection with time locks. Private mempools (Flashbots Protect)
    prevent cancel tx from being visible. Consider commit-reveal scheme for high-value
    listings.
  trampas:
    - "This is an inherent MEV issue, not strictly a smart contract bug — severity depends on protocol design"
    - "Seaport's counter system mitigates this but at the cost of invalidating ALL orders"
    - "Off-chain order books (Reservoir, OpenSea) can remove orders before on-chain execution — different trust model"
    - "Some protocols accept this risk and put the burden on the seller to use private mempools"
  solodit_ids:
    - possible-frontrunning-of-buy-actions-by-changing-token-terms-quantstamp-camp-nft-markdown
    - m-20-user-can-cancel-or-modify-dutch-auctions-compromising-market-integrity-and-user-trust-sherlock-flayer-git
    - h-4-orders-from-other-market-makers-can-be-invalidated-sherlock-opyn-opyn-crab-netting-git
  incidentes:
    - protocol: "OpenSea"
      date: "2022-01 to 2022-06"
      impact: "Multiple NFTs sold below market price"
      detail: "Several high-profile cases where BAYC/MAYC owners tried to cancel listings but were front-run by MEV bots. OpenSea added warnings and eventually moved to Seaport with incrementCounter."
    - protocol: "Flayer"
      firm: "Sherlock"
      impact: "MEDIUM"
      title: "User can cancel or modify Dutch auctions, compromising market integrity"
      slug: "m-20-user-can-cancel-or-modify-dutch-auctions-compromising-market-integrity-and-user-trust-sherlock-flayer-git"
  confianza: alta
  verificado: true
```

---

## 9. Batch Order Atomicity Failure

```yaml
- id: nm-009
  pattern: batch-order-partial-execution
  name: "Batch/bundle execution partially fails — inconsistent state or lost funds"
  severity: high
  causa_raiz: >
    Marketplace aggregators (Reservoir, Gem, Blur) and advanced order types (Seaport
    matchOrders, fulfillAvailableOrders) execute multiple orders in a single transaction.
    If individual order fills within the batch can fail silently (try/catch, or non-reverting
    error handling), the batch may leave the caller in an inconsistent state: paid for N
    items but only received M < N. ETH sent as msg.value for the failed fills remains
    in the contract (or is not refunded). Some batch implementations use msg.value in
    a loop, allowing the same ETH to be "spent" on multiple items.
  como_funciona: |
    1. User calls batchFulfill([order1, order2, order3]) with msg.value = 15 ETH
    2. order1 fills successfully (5 ETH), order2 fills (5 ETH)
    3. order3 reverts (NFT already sold by someone else)
    4. Non-atomic implementation: tx succeeds, 5 ETH stuck in contract
    5. User received 2 NFTs, paid 15 ETH, lost 5 ETH
    msg.value reuse variant:
    1. Contract uses msg.value in a loop without tracking spent amounts
    2. Each iteration checks msg.value >= price (but msg.value doesn't decrease)
    3. User sends 5 ETH, buys 3 items at 5 ETH each — only paid once
  invariante: |
    // Batch execution: total ETH spent must equal sum of filled orders' prices
    function invariant_batch_eth_accounting() internal {
        uint256 totalPaid = msg.value;
        uint256 totalCost = sumFilledOrderPrices();
        uint256 refund = address(this).balance - preBalance;
        t(totalPaid == totalCost + refund, "BATCH: ETH accounting mismatch");
    }
    // msg.value must not be reused across loop iterations
    function invariant_no_msgvalue_reuse() internal {
        uint256 spent = 0;
        for (uint i = 0; i < orders.length; i++) {
            spent += orders[i].price;
            t(spent <= msg.value, "BATCH: cumulative spend exceeds msg.value");
        }
    }
  que_mirar:
    - "Is batch execution atomic (all-or-nothing) or partial (best-effort)?"
    - "Is msg.value used inside a loop without a running total of spent ETH?"
    - "Are failed fills refunded automatically or left in the contract?"
    - "grep: msg.value, batchFulfill, fulfillAvailableOrders, matchOrders"
    - "grep: try/catch blocks inside batch loops, address(this).balance"
    - "Does the batch function use delegatecall to sub-functions (preserving msg.value)?"
  como_se_arregla: >
    Track spent ETH with a running accumulator (not msg.value). Refund unused ETH
    at the end of batch execution. Use Seaport's fulfillAvailableOrders which handles
    partial fills correctly with refunds. For atomic batches: revert the entire tx on
    any failure. Never use msg.value inside a loop.
  trampas:
    - "fulfillAvailableOrders is DESIGNED to allow partial fills — this is a feature, not a bug"
    - "msg.value reuse is only exploitable if the contract also sends ETH (external calls) — check the full flow"
    - "Multicall/batch wrappers may introduce msg.value reuse even if individual functions are safe"
  solodit_ids:
    - h-02-use-of-msgvalue-inside-a-loop-pashov-audit-group-none-sofamon-august-markdown
    - h-02-_aggregatevalidfulfillmentofferitems-can-be-tricked-to-accept-invalid-inputs-code4rena-opensea-opensea-seaport-contest-git
    - m-02-wrong-items-length-assertion-in-basic-order-code4rena-opensea-opensea-seaport-contest-git
  incidentes:
    - protocol: "Thirdweb"
      date: "2023-12"
      impact: "Multiple marketplace contracts affected"
      detail: "Thirdweb disclosed a vulnerability in their marketplace contracts affecting ERC-721, ERC-1155, and AirdropERC20. The specific issue involved insufficient input validation in batch operations. Over 600 contracts were potentially affected."
    - protocol: "OpenSea (Seaport)"
      firm: "Code4rena"
      impact: "HIGH"
      title: "_aggregateValidFulfillmentOfferItems tricked to accept invalid inputs"
      slug: "h-02-_aggregatevalidfulfillmentofferitems-can-be-tricked-to-accept-invalid-inputs-code4rena-opensea-opensea-seaport-contest-git"
  confianza: alta
  verificado: true
```

---

## 10. ERC-2981 Royalty Overflow / Incorrect Calculation

```yaml
- id: nm-010
  pattern: erc2981-royalty-overflow
  name: "royaltyInfo returns amount exceeding sale price — drains buyer or marketplace"
  severity: high
  causa_raiz: >
    ERC-2981 royaltyInfo(tokenId, salePrice) returns (receiver, royaltyAmount). The
    standard does NOT constrain royaltyAmount to be <= salePrice. A malicious or buggy
    NFT contract can return royaltyAmount > salePrice. If the marketplace blindly pays
    the returned royalty without capping it, the marketplace/buyer overpays. Additionally,
    incorrect casting (uint256 to uint96 or vice versa) in royalty calculation can cause
    overflow/underflow, resulting in either 0 royalty or an enormous royalty amount.
  como_funciona: |
    1. Malicious NFT contract: royaltyInfo() returns (attacker, type(uint256).max)
    2. Marketplace lists NFT at 1 ETH
    3. Buyer purchases — marketplace calls royaltyInfo(tokenId, 1 ETH)
    4. Receives royaltyAmount = type(uint256).max
    5. Marketplace tries to transfer MAX ETH to attacker — reverts (DoS)
    OR if marketplace has a balance:
    5. Marketplace transfers its entire balance to the attacker
    Incorrect casting variant:
    1. NFT contract stores royalty as uint96 (common in ERC2981 implementations)
    2. Large salePrice * bps overflows uint96
    3. Truncated royalty is either 0 (creator loses) or wraps to huge value
  invariante: |
    // Royalty amount must never exceed sale price
    function invariant_royalty_bounded() internal {
        (, uint256 royaltyAmount) = IERC2981(nft).royaltyInfo(tokenId, salePrice);
        t(royaltyAmount <= salePrice, "ROYALTY-OVERFLOW: royalty exceeds sale price");
        // Also check it doesn't exceed the BPS cap (typically 10%)
        t(royaltyAmount <= salePrice * MAX_ROYALTY_BPS / 10000, "ROYALTY-OVERFLOW: exceeds max BPS");
    }
  que_mirar:
    - "Does the marketplace cap the royalty amount returned by royaltyInfo?"
    - "Is royalty calculation done in uint96 or uint256?"
    - "Can royaltyInfo be modified by the NFT owner after listing?"
    - "grep: royaltyInfo, _royaltyAmount, ROYALTY_BPS, type(uint96).max"
    - "grep: ERC2981, _setDefaultRoyalty, _setTokenRoyalty"
    - "Does the marketplace use a separate royalty registry or the NFT's built-in?"
  como_se_arregla: >
    Always cap royalty: min(royaltyAmount, salePrice * MAX_BPS / 10000).
    Use uint256 for all royalty calculations. Validate royaltyInfo return
    values before executing transfers. Consider using the EIP-2981 check:
    if royaltyAmount > salePrice, set royalty to 0 and emit warning.
    OpenZeppelin's ERC2981 uses uint96 for storage efficiency but computes in uint256.
  trampas:
    - "OpenZeppelin's ERC2981 implementation is safe — only flag custom implementations"
    - "A royalty of 0 is valid (no royalty) — don't flag it as underflow unless the collection intended royalties"
    - "Some marketplaces intentionally ignore ERC-2981 and use their own royalty registry"
    - "The royaltyInfo function is view — it can be non-deterministic if it reads state that changes between calls"
  solodit_ids:
    - inaccurate-royalty-calculation-in-werc721royaltyinfo-function-cantina-none-sweep-n-flip-pdf
    - m-7-erc721bridgable-and-erc1155bridgable-are-not-eip-2981-compliant-and-fail-to-correctly-collect-or-attribute-royalties-to-artists-sherlock-flayer-git
    - nft-sale-price-is-calculated-as-weth-spent-on-vtokens-purchase-and-is-overstated-this-way-in-royalty-deductions-cantina-none-nftx-pdf
    - linearity-assumption-on-the-royalty-can-lead-to-denial-of-service-cyfrin-sudoswap-markdown
    - m-16-inappropriate-support-of-eip-2981-code4rena-foundation-foundation-contest-git
  incidentes:
    - protocol: "Sudoswap V2"
      firm: "Cyfrin"
      impact: "HIGH"
      title: "Linearity assumption on royalty leads to denial of service"
      slug: "linearity-assumption-on-the-royalty-can-lead-to-denial-of-service-cyfrin-sudoswap-markdown"
      detail: "Sudoswap assumed royalty scales linearly with price. Some NFT contracts return non-linear royalties, causing reverts on certain trade sizes."
    - protocol: "NFTX"
      firm: "Cantina"
      impact: "HIGH"
      title: "NFT sale price overstated in royalty deductions"
      slug: "nft-sale-price-is-calculated-as-weth-spent-on-vtokens-purchase-and-is-overstated-this-way-in-royalty-deductions-cantina-none-nftx-pdf"
    - protocol: "Sweep n Flip"
      firm: "Cantina"
      impact: "HIGH"
      title: "Inaccurate royalty calculation in WERC721::royaltyInfo"
      slug: "inaccurate-royalty-calculation-in-werc721royaltyinfo-function-cantina-none-sweep-n-flip-pdf"
  confianza: alta
  verificado: true
```

---

## 11. Seaport Consideration Item Mismatch / Fulfillment Aggregation

```yaml
- id: nm-011
  pattern: consideration-item-mismatch
  name: "Seaport order with mismatched offer/consideration — aggregation bypass"
  severity: critical
  causa_raiz: >
    Seaport's fulfillment system allows arbitrary mapping between offer items and
    consideration items across multiple orders via FulfillmentComponent arrays. The
    _aggregateValidFulfillmentOfferItems and _aggregateValidFulfillmentConsiderationItems
    functions validate that items match, but complex multi-order fulfillments can trick
    the aggregation logic into accepting invalid combinations. An attacker can construct
    fulfillment arrays that cause a seller's NFT to be transferred to the attacker while
    routing payment to a different address (or not paying at all).
  como_funciona: |
    1. Seller lists NFT #42: offer=[NFT #42], consideration=[10 ETH to seller]
    2. Attacker creates a matching order with manipulated fulfillment components
    3. Attacker calls fulfillAdvancedOrder with crafted fulfillmentComponents array
    4. The aggregation function accepts the input because item types match superficially
    5. But the AMOUNT or RECIPIENT is wrong due to index manipulation
    6. Seller's NFT transferred to attacker, payment goes to wrong address or is reduced
    Basic order variant:
    1. Basic order format has fixed consideration items length assertion
    2. The assertion checks wrong length — allows extra consideration items
    3. Extra items drain additional funds from the buyer
  invariante: |
    // For every matched fulfillment: sum(offer amounts) == sum(consideration amounts)
    function invariant_fulfillment_balanced() internal {
        for (uint i = 0; i < fulfillments.length; i++) {
            uint256 offerTotal = sumOfferComponents(fulfillments[i].offerComponents);
            uint256 considerationTotal = sumConsiderationComponents(fulfillments[i].considerationComponents);
            t(offerTotal == considerationTotal, "FULFILLMENT: offer/consideration mismatch");
        }
    }
  que_mirar:
    - "How does _aggregateValidFulfillmentOfferItems validate item type matching?"
    - "Can fulfillmentComponent indices point to items from different orders?"
    - "Is the basic order consideration items length assertion correct?"
    - "grep: FulfillmentComponent, _aggregateValid, fulfillAdvancedOrder"
    - "grep: considerationItems.length, offerItems.length, BasicOrderParameters"
    - "Can CONTRACT order type generate fewer consideration items than expected?"
  como_se_arregla: >
    Seaport v1.2+ fixed the aggregation validation. The fix ensures item type, token,
    and identifier all match across aggregated components. Basic order length assertion
    was corrected. CONTRACT order types now have explicit validation that generated
    items meet minimum requirements.
  trampas:
    - "Seaport is heavily audited — most findings are from the initial Code4rena contest and are fixed in v1.2+"
    - "The fulfillment aggregation logic is intentionally complex to support arbitrary multi-order matching"
    - "CONTRACT order types are a separate trust model — the zone/contract can generate arbitrary items"
  solodit_ids:
    - h-02-_aggregatevalidfulfillmentofferitems-can-be-tricked-to-accept-invalid-inputs-code4rena-opensea-opensea-seaport-contest-git
    - m-02-wrong-items-length-assertion-in-basic-order-code4rena-opensea-opensea-seaport-contest-git
    - advance-orders-of-contract-order-types-can-generate-orders-with-less-consideration-items-that-spearbit-seaport-pdf
    - the-spent-offer-amounts-provided-to-orderfulfilled-for-collection-of-advanced-orders-is-not-the-spearbit-seaport-pdf
    - calls-to-pausablezone-sexecutematchadvancedorders-and-executematchorders-would-revert-if-un-spearbit-seaport-pdf
  incidentes:
    - protocol: "OpenSea (Seaport v1.1)"
      firm: "Code4rena"
      impact: "HIGH"
      title: "_aggregateValidFulfillmentOfferItems tricked to accept invalid inputs"
      slug: "h-02-_aggregatevalidfulfillmentofferitems-can-be-tricked-to-accept-invalid-inputs-code4rena-opensea-opensea-seaport-contest-git"
      detail: "The aggregation function did not properly validate that all items in a fulfillment component array shared the same item type, token, and identifier. An attacker could mix items from different orders."
    - protocol: "OpenSea (Seaport v1.1)"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Wrong items length assertion in basic order"
      slug: "m-02-wrong-items-length-assertion-in-basic-order-code4rena-opensea-opensea-seaport-contest-git"
    - protocol: "Seaport"
      firm: "Spearbit"
      impact: "MEDIUM"
      title: "Advanced orders of CONTRACT type can generate fewer consideration items"
      slug: "advance-orders-of-contract-order-types-can-generate-orders-with-less-consideration-items-that-spearbit-seaport-pdf"
  confianza: alta
  verificado: true
```

---

## 12. Zone / Validator Bypass in Restricted Orders

```yaml
- id: nm-012
  pattern: zone-validator-bypass
  name: "Restricted order zone validation circumvented — unauthorized fills"
  severity: high
  causa_raiz: >
    Seaport restricted orders require zone validation: the zone contract's
    validateOrder() must return the magic value for the fill to succeed. Zones enforce
    business logic (KYC, time restrictions, specific buyers). Bypass vectors:
    (a) zone contract does not validate all parameters (e.g., skips checking consideration),
    (b) zone's isValidOrder() can be called by anyone (no access control on who triggers
    validation), (c) zone relies on msg.sender being Seaport but doesn't verify the
    order actually originated from the expected flow. In rental protocols like reNFT,
    the zone validates rental parameters but can be tricked via tipping or extra items.
  como_funciona: |
    1. reNFT uses a Seaport zone to validate rental orders
    2. Zone checks: offer items match rental contract's expected NFTs
    3. Attacker creates order with valid offer items PLUS extra "tip" items
    4. Tips are malicious ERC-20 tokens that execute code on transfer
    5. Zone validates the base order (passes) but doesn't check tips
    6. Malicious tip token locks in the rental safe — assets trapped
    Variant (Astaria):
    1. ClearingHouse is a Seaport zone for liquidation auctions
    2. ClearingHouse cannot distinguish between genuine auction fill and direct Seaport call
    3. Attacker calls Seaport directly with a crafted order targeting ClearingHouse
    4. ClearingHouse executes without proper auction validation
  invariante: |
    // Zone must validate ALL items in the order, not just the primary offer/consideration
    function invariant_zone_validates_all_items() internal {
        // Tips/extra items must also pass zone validation
        for (uint i = 0; i < order.allItems.length; i++) {
            t(zone.isValidItem(order.allItems[i]), "ZONE-BYPASS: unvalidated item in order");
        }
    }
    // Zone must verify caller is Seaport AND order flow is legitimate
    function invariant_zone_caller_check() internal {
        t(msg.sender == address(seaport), "ZONE: caller is not Seaport");
        t(isLegitimateFlow(order), "ZONE: order not from expected flow");
    }
  que_mirar:
    - "Does the zone validate ALL items (including tips) or only the primary offer/consideration?"
    - "Can the zone be called directly (not through Seaport)?"
    - "Does the zone distinguish between different order types (auction vs listing vs rental)?"
    - "grep: ZoneInterface, validateOrder, isValidOrder, authorizeOrder, zone"
    - "grep: tips, extraData, additionalRecipients"
    - "For reNFT: does the guard validate all delegate calls from the rental safe?"
  como_se_arregla: >
    Zone must validate ALL items in the order, including tips. Use Seaport's SIP-7
    (zone + substandard) for more granular validation. Zone should verify the full
    order context, not just individual items. For rental protocols: guard must whitelist
    ALL delegate call targets, not just known contracts.
  trampas:
    - "Seaport zones are designed to be flexible — not all zones need to validate all items"
    - "The zone trust model assumes the zone implementer knows what to validate"
    - "reNFT's issues were specific to the rental use case, not Seaport itself"
  solodit_ids:
    - h-01-all-orders-can-be-hijacked-to-lock-rental-assets-forever-by-tipping-a-malicious-erc20-code4rena-renft-renft-git
    - h-06-escrow-contract-can-be-drained-by-creating-rentals-that-bypass-execution-invariant-checks-code4rena-renft-renft-git
    - clearinghouse-cannot-detect-if-a-call-from-seaport-comes-from-a-genuine-listing-or-auction-spearbit-astaria-pdf
    - h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallb
  incidentes:
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "All orders hijacked via malicious ERC-20 tip — rental assets locked forever"
      slug: "h-01-all-orders-can-be-hijacked-to-lock-rental-assets-forever-by-tipping-a-malicious-erc20-code4rena-renft-renft-git"
      detail: "Attacker tipped a malicious ERC-20 that on transfer executed code to lock the rental safe. Zone did not validate tip items."
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Attacker hijacks ERC721/ERC1155 via guard missing setFallbackHandler validation"
      slug: "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallb"
    - protocol: "Astaria"
      firm: "Spearbit"
      impact: "HIGH"
      title: "ClearingHouse cannot detect genuine vs crafted Seaport calls"
      slug: "clearinghouse-cannot-detect-if-a-call-from-seaport-comes-from-a-genuine-listing-or-auction-spearbit-astaria-pdf"
  confianza: alta
  verificado: true
```

---

## 13. Trait/Criteria-Based Order Spoofing

```yaml
- id: nm-013
  pattern: criteria-order-wrong-trait
  name: "Criteria-based order filled with item that doesn't match intended traits"
  severity: high
  causa_raiz: >
    Seaport criteria-based orders use a Merkle tree of acceptable tokenIds. The tree is
    constructed off-chain and the root is included in the signed order. The fulfiller
    provides the tokenId and a Merkle proof. Vulnerabilities arise when: (a) the Merkle
    tree is constructed incorrectly (includes wrong tokenIds), (b) the proof verification
    uses a different hashing scheme than the tree construction, (c) the criteria resolver
    accepts any tokenId when the criteria root is 0x0 (wildcard), or (d) tokenId encoding
    allows collision (e.g., tokenId 0 matches multiple items).
  como_funciona: |
    1. Buyer signs criteria order: "Buy any Punk with Alien trait for 100 ETH"
    2. Criteria root = Merkle root of [tokenId_1, tokenId_2, ..., tokenId_9] (the 9 alien punks)
    3. Attacker constructs a proof for tokenId_X that is NOT an alien punk
    4. Proof verifies because:
       a) Tree was constructed with keccak256(tokenId) but resolver uses keccak256(abi.encode(tokenId)) — hash collision
       b) criteria root is 0x0 which the resolver treats as "accept any tokenId"
       c) Second preimage attack on the Merkle tree allows crafting a valid proof for a non-leaf
    5. Attacker fills the 100 ETH order with a 5 ETH floor punk
    6. Buyer pays 100 ETH for a 5 ETH item
  invariante: |
    // Criteria resolution must only accept tokenIds that are in the intended set
    function invariant_criteria_resolution_correct() internal {
        // The filled tokenId must be a leaf in the Merkle tree
        bytes32 leaf = keccak256(abi.encodePacked(filledTokenId));
        t(MerkleProof.verify(proof, criteriaRoot, leaf), "CRITERIA: invalid proof");
        // criteriaRoot of 0 must not be treated as wildcard
        t(criteriaRoot != bytes32(0), "CRITERIA: zero root should not match all");
    }
  que_mirar:
    - "How is the criteria Merkle tree constructed? What hashing scheme?"
    - "Does criteria root of 0x0 match all tokenIds (wildcard)?"
    - "Is the Merkle proof verification using the same hash function as construction?"
    - "grep: CriteriaResolver, _applyCriteriaResolvers, criteria, identifierOrCriteria"
    - "grep: MerkleProof, merkleRoot, verifyProof"
    - "Can the criteria root be updated after the order is signed?"
  como_se_arregla: >
    Use consistent hashing: keccak256(abi.encodePacked(tokenId)) for both tree
    construction and proof verification. Reject criteria root of 0x0 (or document
    that it means "any tokenId"). Use OpenZeppelin's MerkleProof library. Include
    the trait data in the Merkle leaf (not just tokenId) if trait-based orders are
    supported. Seaport fixed this in v1.2.
  trampas:
    - "Criteria root of 0 meaning 'any' might be intentional for collection offers — check the documentation"
    - "The Merkle tree is constructed off-chain — bugs in the tree construction tool are harder to audit"
    - "This is only relevant for criteria-based orders, not standard tokenId orders"
  solodit_ids:
    - m-01-merkle-tree-criteria-can-be-resolved-by-wrong-tokenids-code4rena-opensea-opensea-seaport-contest-git
    - m-08-pre-check-is-not-correct-code4rena-golom-golom-contest-git
  incidentes:
    - protocol: "OpenSea (Seaport)"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Merkle tree criteria can be resolved by wrong tokenIDs"
      slug: "m-01-merkle-tree-criteria-can-be-resolved-by-wrong-tokenids-code4rena-opensea-opensea-seaport-contest-git"
      detail: "The criteria resolution logic allowed tokenIds not in the original trait set to pass verification under certain hashing conditions."
    - protocol: "Golom"
      firm: "Code4rena"
      impact: "MEDIUM"
      title: "Pre-check is not correct — criteria validation incomplete"
      slug: "m-08-pre-check-is-not-correct-code4rena-golom-golom-contest-git"
  confianza: alta
  verificado: true
```

---

## 14. NFT Lending Price Oracle Sandwich

```yaml
- id: nm-014
  pattern: nft-lending-oracle-sandwich
  name: "Sandwich attack on NFT floor price TWAP to manipulate loan creation/liquidation"
  severity: critical
  causa_raiz: >
    NFT-backed lending protocols that use on-chain price feeds (AMM-derived, Sudoswap
    pool, or NFTX vault token price) are vulnerable to sandwich attacks. The attacker
    manipulates the price source in the same block as the loan operation. Unlike off-chain
    oracles (Chainlink NFT feeds, signed price reports), on-chain sources can be moved
    atomically. TWAP helps but short TWAP windows (1 block, 1 minute) can still be
    manipulated with sufficient capital.
  como_funciona: |
    1. NFT lending protocol uses Sudoswap pool price as floor oracle
    2. Current pool price: 5 ETH per NFT
    3. Attacker bundles 3 transactions:
       TX1 (front): Buy 50 NFTs from pool → price rises to 20 ETH
       TX2 (victim): Attacker creates loan with 1 NFT collateral, borrows 10 ETH (50% LTV of 20 ETH)
       TX3 (back): Sell 50 NFTs back to pool → price drops to 5 ETH
    4. Net cost: swap fees (~2%). Net profit: 10 ETH borrowed - 5 ETH collateral value = 5 ETH
    5. Attacker defaults on loan. Protocol left with 5 ETH collateral for 10 ETH debt.
    TWAP bypass variant:
    1. If TWAP window is 10 minutes, attacker manipulates price for 10 minutes
    2. Uses multiple blocks to gradually move TWAP
    3. Creates loan at inflated TWAP, then stops manipulation
  invariante: |
    // Loan collateral value at creation must remain valid after the block
    function invariant_no_sandwich_loan() internal {
        uint256 priceAtCreation = oracle.getFloorPrice(collection);
        // Advance 1 block
        vm.roll(block.number + 1);
        uint256 priceNextBlock = oracle.getFloorPrice(collection);
        // Price should not have moved more than 10% in one block
        uint256 diff = priceAtCreation > priceNextBlock
            ? priceAtCreation - priceNextBlock
            : priceNextBlock - priceAtCreation;
        t(diff <= priceAtCreation / 10, "SANDWICH: >10% price move in 1 block");
    }
  que_mirar:
    - "Is the floor price oracle on-chain (AMM-based) or off-chain (Chainlink, signed)?"
    - "What is the TWAP window? Can it be manipulated within one block?"
    - "Is there a time delay between oracle read and loan creation?"
    - "grep: getFloorPrice, twapPrice, oraclePrice, getReserves"
    - "grep: createLoan, borrow, addCollateral, liquidate"
    - "Can the oracle be an arbitrary address chosen by the borrower?"
  como_se_arregla: >
    Use off-chain oracle with signed prices and freshness checks. If using on-chain
    oracle, require multi-block TWAP (24 hours minimum). Add a time delay between
    collateral deposit and borrowing. Implement circuit breakers for large price
    movements. Use Chainlink NFT floor price feeds where available.
    Cap LTV aggressively for NFTs (30-40%).
  trampas:
    - "Off-chain oracles introduce centralization risk — the oracle operator can rug"
    - "Long TWAP windows cause oracle lag — might not reflect rapid legitimate price changes"
    - "Some protocols accept this risk and use conservative LTV as mitigation"
  solodit_ids:
    - borrowers-could-manipulate-the-floor-price-quantstamp-nemeos-markdown
    - dos-through-sandwich-attack-on-ceilingprice-zokyo-none-limit-break-markdown
    - h-09-uniswapv3-tokens-of-certain-pairs-will-be-wrongly-valued-leading-to-liquidations-code4rena-paraspace-paraspace-contest-git
  incidentes:
    - protocol: "Blend (Blur)"
      date: "2023-05"
      impact: "Design consideration — mitigated by Dutch auction refinancing"
      detail: "Blur's Blend protocol uses a Dutch auction mechanism for refinancing instead of traditional liquidation, partly to mitigate oracle manipulation. However, the floor price still matters for initial loan terms."
    - protocol: "Nemeos"
      firm: "Quantstamp"
      impact: "MEDIUM"
      title: "Borrowers could manipulate the floor price"
      slug: "borrowers-could-manipulate-the-floor-price-quantstamp-nemeos-markdown"
    - protocol: "ParaSpace"
      firm: "Code4rena"
      impact: "HIGH"
      title: "UniswapV3 tokens wrongly valued — leads to incorrect liquidations"
      slug: "h-09-uniswapv3-tokens-of-certain-pairs-will-be-wrongly-valued-leading-to-liquidations-code4rena-paraspace-paraspace-contest-git"
  confianza: alta
  verificado: true
```

---

## 15. Listing Migration Attack — Stale Cross-Marketplace Listings

```yaml
- id: nm-015
  pattern: stale-listing-migration
  name: "Old marketplace listing still valid after user migrates to new marketplace"
  severity: critical
  causa_raiz: >
    When a marketplace upgrades (Wyvern → Seaport) or a user switches marketplaces
    (OpenSea → Blur), old listings signed for the previous marketplace may remain
    valid if: (a) the old marketplace contract is still active and user's approval is
    still granted, (b) the signed order didn't include an expiration timestamp, or
    (c) the user didn't explicitly cancel old orders on-chain. The user assumes
    their items are delisted when they moved to the new marketplace, but the old
    listing is still executable by anyone who has the signature.
  como_funciona: |
    1. User listed BAYC #1234 on OpenSea Wyvern for 10 ETH in June 2021
    2. OpenSea migrated to Seaport in June 2022
    3. User listed BAYC #1234 on Seaport for 100 ETH (floor went up 10x)
    4. User's Wyvern approval (setApprovalForAll) is still active
    5. Old Wyvern order signature is still valid on-chain
    6. Attacker finds old order signature (from event logs or off-chain cache)
    7. Attacker fills old Wyvern order: buys BAYC #1234 for 10 ETH
    8. User loses ~90 ETH of value
    Same-marketplace variant (Flayer):
    1. User lists NFT at 5 ETH, then "relists" at 10 ETH
    2. Relist function updates price but doesn't invalidate old listing mapping
    3. Both listings coexist — old one can still be filled at 5 ETH
  invariante: |
    // After migration/relist: old listing must be unfillable
    function invariant_old_listing_invalidated() internal {
        // Old marketplace should not be able to transfer the NFT
        vm.prank(oldMarketplace);
        try IERC721(nft).transferFrom(user, buyer, tokenId) {
            t(false, "STALE-LISTING: old marketplace can still transfer NFT");
        } catch {}
    }
    // Only one active listing per tokenId across all marketplaces
    function invariant_single_active_listing() internal {
        uint256 activeListings = countActiveListings(tokenId);
        t(activeListings <= 1, "STALE-LISTING: multiple active listings for same NFT");
    }
  que_mirar:
    - "Does the marketplace invalidate old listings when creating new ones?"
    - "Are approvals to the old marketplace/conduit still active?"
    - "Do signed orders have expiration timestamps?"
    - "grep: setApprovalForAll, isApprovedForAll, oldMarketplace"
    - "grep: listing.created, relist, updateListing, _listing"
    - "Can event logs from old marketplace be used to reconstruct valid order signatures?"
  como_se_arregla: >
    Include expiration timestamps in all signed orders. During marketplace migration,
    run a batch cancel of all old listings. Auto-cancel old listings when creating
    new ones on the same marketplace. Revoke approvals to deprecated marketplace
    contracts. Seaport's incrementCounter() cancels all previous orders atomically.
  trampas:
    - "Users are responsible for revoking approvals — marketplace can't force this"
    - "OpenSea specifically warned users to cancel Wyvern listings, but many didn't"
    - "This is partly a UX issue, not purely a smart contract bug"
    - "The old marketplace contract being immutable means it can't be 'turned off'"
  solodit_ids:
    - h-9-_listing-mapping-not-deleted-when-calling-listingsreserve-can-lead-to-a-token-being-sold-when-it-shouldnt-be-for-sale-sherlock-flayer-git
    - h-4-in-the-listingssolrelist-function-listingcreated-is-not-set-to-blocktimestamp-sherlock-flayer-git
    - completed-listings-can-be-re-entered-cantina-none-kim-exchange-pdf
    - h-04-optimisticlistingseaportpropose-sets-pendingbalances-of-newly-added-proposer-instead-of-previous-one-code4rena-tessera-tessera-versus-contest-git
  incidentes:
    - protocol: "OpenSea (Wyvern V1 → Seaport migration)"
      date: "2022-01"
      impact: "$1.7M+ stolen"
      detail: "At least 8 BAYC, multiple CoolCats, Mutant Apes, and other NFTs were purchased using stale Wyvern listings. Users had not cancelled old orders or revoked Wyvern approvals after migrating to Seaport. Total confirmed losses exceeded $1.7M."
    - protocol: "Flayer"
      firm: "Sherlock"
      impact: "HIGH"
      title: "_listing mapping not deleted when calling reserve — token sold when it shouldn't be"
      slug: "h-9-_listing-mapping-not-deleted-when-calling-listingsreserve-can-lead-to-a-token-being-sold-when-it-shouldnt-be-for-sale-sherlock-flayer-git"
    - protocol: "Flayer"
      firm: "Sherlock"
      impact: "HIGH"
      title: "relist() does not set listing.created to block.timestamp — old listing exploitable"
      slug: "h-4-in-the-listingssolrelist-function-listingcreated-is-not-set-to-blocktimestamp-sherlock-flayer-git"
    - protocol: "Kim Exchange"
      firm: "Cantina"
      impact: "HIGH"
      title: "Completed listings can be re-entered"
      slug: "completed-listings-can-be-re-entered-cantina-none-kim-exchange-pdf"
  confianza: alta
  verificado: true
```

---

## 16. Rental Marketplace — Asset Hijacking and Escrow Drain

```yaml
- id: nm-016
  pattern: rental-nft-hijack
  name: "Rented NFT hijacked via safe delegate call or guard bypass"
  severity: critical
  causa_raiz: >
    NFT rental protocols (reNFT, Double Protocol) hold rented assets in Gnosis Safes
    with guards that restrict what the borrower can do. The guard must prevent: (a)
    transferring the rented NFT out of the safe, (b) approving the NFT to an external
    address, (c) executing delegate calls that change the safe's module/guard/fallback
    handler. If the guard misses ANY delegate call target or ANY function selector, the
    borrower can hijack the rented asset. The attack surface is enormous because Gnosis
    Safe supports arbitrary delegate calls and module additions.
  como_funciona: |
    1. Lender deposits NFT into reNFT rental safe with a guard
    2. Borrower (safe owner) can call any function on the safe
    3. Guard is supposed to block: transfer, approve, setGuard, addModule, setFallbackHandler
    4. Guard does NOT validate setFallbackHandler(address) — MISSED selector
    5. Borrower calls setFallbackHandler(attacker_contract)
    6. Attacker contract now handles all unknown calls to the safe
    7. Attacker calls safe with transferFrom selector → routed to fallback handler
    8. Fallback handler transfers NFT to attacker — guard never triggered
    Variant (module attack):
    1. Borrower calls enableModule(attacker_module)
    2. Attacker module calls execTransactionFromModule() — bypasses guard entirely
    3. Module transfers all assets out of the safe
  invariante: |
    // Rental safe guard must block ALL state-changing calls that could remove the guard
    function invariant_guard_cannot_be_bypassed() internal {
        // After any borrower action, guard must still be active
        address currentGuard = safe.getGuard();
        t(currentGuard == address(rentalGuard), "RENTAL-HIJACK: guard removed/changed");
        // All rented NFTs must still be in the safe
        for (uint i = 0; i < rentedNfts.length; i++) {
            t(IERC721(rentedNfts[i].token).ownerOf(rentedNfts[i].tokenId) == address(safe),
              "RENTAL-HIJACK: rented NFT removed from safe");
        }
        // No new modules should be added
        t(safe.getModulesPaginated(address(0x1), 10).length == expectedModuleCount,
          "RENTAL-HIJACK: unauthorized module added");
    }
  que_mirar:
    - "Does the guard block setFallbackHandler, setGuard, enableModule, disableModule?"
    - "Does the guard validate delegate calls (not just direct calls)?"
    - "Can the borrower call execTransactionFromModule to bypass the guard?"
    - "grep: checkTransaction, checkAfterExecution, setFallbackHandler, enableModule"
    - "grep: GnosisSafe, Guard, delegatecall, execTransactionFromModule"
    - "Is the guard checking the 'to' address and 'data' selector for ALL call types?"
    - "Can the borrower self-destruct a contract that the guard relies on?"
  como_se_arregla: >
    Whitelist approach: only allow specific function calls, deny everything else.
    Block ALL delegate calls except to whitelisted contracts. Block ALL module
    operations. Block setFallbackHandler, setGuard. Use checkAfterExecution to verify
    state hasn't changed unexpectedly. Consider using a simpler custodial approach
    instead of Gnosis Safe for rental escrow.
  trampas:
    - "Gnosis Safe's flexibility is both a feature and a vulnerability — the guard must be exhaustive"
    - "New Safe versions may add new configuration functions that the guard doesn't know about"
    - "delegate calls to the safe itself (self-call) can bypass call-target restrictions"
    - "ERC-1155 has safeTransferFrom which triggers a callback — guard must also handle this"
  solodit_ids:
    - h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallb
    - h-01-all-orders-can-be-hijacked-to-lock-rental-assets-forever-by-tipping-a-malicious-erc20-code4rena-renft-renft-git
    - h-05-malicious-actor-can-steal-any-actively-rented-nft-and-freeze-the-rental-payments-of-the-affected-rentals-in-the-escrow-contract-code4rena-renft-r
    - h-06-escrow-contract-can-be-drained-by-creating-rentals-that-bypass-execution-invariant-checks-code4rena-renft-renft-git
    - h-07-attacker-can-lock-lender-nfts-and-erc20-in-the-safe-if-the-offer-is-set-to-partial-code4rena-renft-renft-git
  incidentes:
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Attacker hijacks any ERC721/ERC1155 via guard missing setFallbackHandler validation"
      slug: "h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallb"
      detail: "Guard did not validate the 'data' parameter for the setFallbackHandler function. Attacker could change the fallback handler to their own contract and then call transferFrom through it."
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Malicious actor steals any rented NFT and freezes rental payments"
      slug: "h-05-malicious-actor-can-steal-any-actively-rented-nft-and-freeze-the-rental-payments-of-the-affected-rentals-in-the-escrow-contract-code4rena-renft-r"
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      title: "Escrow drained by creating rentals that bypass execution invariant checks"
      slug: "h-06-escrow-contract-can-be-drained-by-creating-rentals-that-bypass-execution-invariant-checks-code4rena-renft-renft-git"
  confianza: alta
  verificado: true
```

---

## 17. Marketplace Router Reentrancy — Draining Approved Funds

```yaml
- id: nm-017
  pattern: marketplace-router-reentrancy
  name: "Reentrancy in marketplace router drains user funds via malicious pair/callback"
  severity: critical
  causa_raiz: >
    Marketplace routers (Sudoswap VeryFastRouter, LooksRare TransferManager, aggregator
    contracts) hold temporary approval from users to execute multi-step trades. If the
    router calls into an untrusted contract (malicious pair, malicious NFT with callback)
    during the trade, the untrusted contract can reenter the router and use the caller's
    still-active approval to drain additional assets. The router typically uses
    msg.sender's approval for the entire transaction — any reentrant call within that
    tx has the same approval context.
  como_funciona: |
    1. User approves VeryFastRouter to spend their ETH/WETH
    2. User calls router.swap([pair1, pair2]) — pair1 is legitimate, pair2 is malicious
    3. Router calls pair2.swapNFTsForToken() — pair2 is attacker-controlled
    4. pair2.swapNFTsForToken() reenters router.swap() using user's approval
    5. Reentrant call drains user's remaining WETH via the active approval
    6. Original tx continues but user has been drained
    LooksRare variant:
    1. TransferManager holds protocol-wide approval for all token transfers
    2. Protocol owner (or compromised admin) can call transferManager to drain any user
    3. Users approved TransferManager, trusting the marketplace — admin key is the risk
  invariante: |
    // Router balance after swap must equal pre-balance + expected output
    function invariant_router_no_drain() internal {
        uint256 userBalBefore = IERC20(weth).balanceOf(user);
        router.swap(pairs, nfts, amounts);
        uint256 userBalAfter = IERC20(weth).balanceOf(user);
        uint256 expectedCost = sumSwapCosts(pairs, nfts);
        // User should only spend what they expected
        t(userBalBefore - userBalAfter <= expectedCost * 101 / 100,
          "ROUTER-DRAIN: user lost more than expected (1% tolerance for fees)");
    }
  que_mirar:
    - "Does the router interact with arbitrary pair/pool contracts?"
    - "Is there a reentrancy guard on the router's swap functions?"
    - "Does the router validate that pair contracts are from the factory (clone check)?"
    - "grep: nonReentrant, reentrancyGuard, isValidPair, isFactoryClone"
    - "grep: transferFrom, safeTransferFrom inside router swap loops"
    - "Can the factory owner register malicious pairs?"
  como_se_arregla: >
    Add nonReentrant modifier to all router swap functions. Validate that pairs are
    legitimate factory clones (check with isClone() or registry lookup). Use pull
    pattern instead of push for ETH transfers. Consider per-tx approval instead of
    persistent approval (Permit2). Sudoswap fixed this by adding isValidPair checks
    and reentrancy guards in V2.
  trampas:
    - "Clone validation can be bypassed if the factory allows arbitrary bonding curves or extra data"
    - "Reentrancy guards only protect against same-function reentry — cross-function reentrancy needs global lock"
    - "NFT callbacks (onERC721Received) during router swaps are another reentrancy vector"
  solodit_ids:
    - malicious-pair-can-re-enter-veryfastrouter-to-drain-original-callers-funds-cyfrin-sudoswap-markdown_
    - the-protocol-owner-can-drain-users-currency-tokens-spearbit-looksrare-pdf
    - factory-owner-can-steal-user-funds-approved-to-the-router-spearbit-sudoswap-pdf
    - drain-tokens-condition-due-to-reentrancy-in-collectfees-spearbit-clober-pdf
    - clones-with-malicious-extradata-are-also-considered-valid-clones-spearbit-sudoswap-pdf
  incidentes:
    - protocol: "Sudoswap V2"
      firm: "Cyfrin"
      impact: "HIGH"
      title: "Malicious pair reenters VeryFastRouter to drain caller's funds"
      slug: "malicious-pair-can-re-enter-veryfastrouter-to-drain-original-callers-funds-cyfrin-sudoswap-markdown_"
    - protocol: "LooksRare"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Protocol owner can drain users' currency tokens via TransferManager"
      slug: "the-protocol-owner-can-drain-users-currency-tokens-spearbit-looksrare-pdf"
    - protocol: "Sudoswap"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Factory owner can steal user funds approved to the router"
      slug: "factory-owner-can-steal-user-funds-approved-to-the-router-spearbit-sudoswap-pdf"
    - protocol: "Sudoswap"
      firm: "Spearbit"
      impact: "HIGH"
      title: "Clones with malicious extradata considered valid — bypass pair validation"
      slug: "clones-with-malicious-extradata-are-also-considered-valid-clones-spearbit-sudoswap-pdf"
  confianza: alta
  verificado: true
```

---

## Quick Reference — Grep Patterns for NFT Marketplace Audits

```
# Order system
grep -rn "ecrecover\|ECDSA.recover\|isValidSignature" src/
grep -rn "nonce\|orderStatus\|filledAmount\|orderHash" src/
grep -rn "cancel\|incrementCounter\|invalidateNonce" src/

# Seaport-specific
grep -rn "FulfillmentComponent\|CriteriaResolver\|ZoneInterface" src/
grep -rn "validateOrder\|authorizeOrder\|isValidOrder" src/
grep -rn "conduit\|openChannel\|closeChannel" src/
grep -rn "numerator\|denominator\|partialFill\|_applyFractions" src/

# Royalties
grep -rn "royaltyInfo\|ERC2981\|ROYALTY_BPS\|royaltyAmount" src/
grep -rn "OperatorFilterer\|onlyAllowedOperator" src/

# Approvals
grep -rn "setApprovalForAll\|isApprovedForAll\|approve(" src/

# Rental/Safe
grep -rn "checkTransaction\|checkAfterExecution\|Guard" src/
grep -rn "setFallbackHandler\|enableModule\|disableModule" src/
grep -rn "execTransactionFromModule\|delegatecall" src/

# Floor oracle
grep -rn "floorPrice\|getFloorPrice\|twapFloor\|oraclePrice" src/

# Batch operations
grep -rn "msg.value.*loop\|for.*msg.value\|batch\|multicall" src/
```

---

## Protocol-Specific Attack Surface Summary

| Protocol | Key Risk Areas | Notable Audit Findings |
|----------|---------------|----------------------|
| **Seaport** | Fulfillment aggregation, criteria resolution, zone bypass, partial fill truncation | Code4rena: H-01 (truncation), H-02 (aggregation), M-01 (criteria), M-02 (basic order) |
| **Blur/Blend** | Floor oracle for lending, Dutch auction refinancing, pool approval management | Oracle manipulation for Blend loans, reward gaming |
| **LooksRare** | TransferManager admin drain, reward farming/wash trading, currency token approval | Spearbit: admin drain, fee rounding |
| **Sudoswap** | Router reentrancy, malicious pairs, royalty linearity, clone validation | Cyfrin: router drain. Spearbit: factory owner drain, clone bypass |
| **reNFT** | Guard bypass (setFallbackHandler, enableModule), tip injection, escrow drain | Code4rena: H-01 through H-07 — nearly complete compromise of rental system |
| **Foundation** | Creator revenue theft, multiple auctions for same NFT, royalty support | Code4rena: H-01 (multiple auctions), H-02 (creator steals revenue) |
| **Thirdweb** | Batch operation validation, cross-contract input validation | Dec 2023 disclosure affecting 600+ contracts |
| **Reservoir** | Aggregator msg.value handling, cross-marketplace order routing | Off-chain relay trust assumptions |
| **Golom** | Fee bypass, order pre-check failures, reward farming | Code4rena: H-08 (fee avoidance), M-08 (pre-check) |
| **Tessera** | Optimistic listing balance tracking, GroupBuy state machine | Code4rena: H-04 (pendingBalance), H-09 (ETH drain) |
