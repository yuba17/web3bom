# GameFi / Play-to-Earn / NFT-Fi Vulnerabilities — Combat Briefing

> Attack surface: in-game reward token economics, NFT attribute manipulation, NFT lending/borrowing
> protocols, rental mechanics, game outcome randomness, sybil farming, marketplace fee evasion,
> and cross-game asset bridging. Covers play-to-earn, move-to-earn, NFT-backed loans, NFT rentals,
> loot boxes, tournaments, and guild/scholarship custody.
> Sources: verified Solodit findings from Code4rena (AI Arena, reNFT, Forgeries, Wenwin, Papr,
> Caviar, Fractional, Astaria, BendDAO, Ajna), Sherlock (Flayer, Carapace, OpenQ), Spearbit
> (Astaria, LooksRare, Sudoswap), Pashov (HYBUX, OnchainHeroes), Shieldify (TollanUniverse,
> Soulsclub, Spellborne, Shiny). Real incidents: Axie Infinity/Ronin ($625M), ParaSpace ($5M risk),
> BendDAO liquidation cascade, Treasure DAO exploit.

---

## 1. Reward Token Inflation — Uncapped Minting of In-Game Currency

```yaml
- id: gfi-001
  titulo: "Uncapped reward token minting allows hyperinflation and economy drain"
  causa_raiz: >
    GameFi protocols mint reward tokens (NRN, SLP, GMT, MAGIC) to incentivize
    gameplay. If the minting function lacks a supply cap, rate limiter, or
    epoch-based emission schedule, an attacker (or the protocol itself over time)
    can mint unbounded tokens. This crashes the token price, devalues all player
    holdings, and can drain liquidity pools paired against the reward token.
    Common in play-to-earn where reward distribution is tied to game outcomes
    controlled by a centralized server.
  como_funciona: |
    1. Game server calls rewardContract.mint(player, amount) after each battle/action
    2. No per-epoch cap: mint() only checks hasRole(MINTER_ROLE), no totalMinted <= maxSupply
    3. Attacker finds way to trigger game outcomes rapidly (bot, exploit game logic)
    4. Each outcome mints reward tokens — 1000x normal rate via automation
    5. Attacker dumps tokens on DEX, draining paired liquidity (ETH/USDC side)
    6. All other players' token holdings become worthless
  invariante: |
    // totalSupply must never exceed the configured emission cap per epoch
    function invariant_rewardSupplyCapped() external {
        uint256 currentEpoch = rewardToken.currentEpoch();
        uint256 mintedThisEpoch = rewardToken.epochMinted(currentEpoch);
        uint256 epochCap = rewardToken.epochEmissionCap(currentEpoch);
        assert(mintedThisEpoch <= epochCap);
        assert(rewardToken.totalSupply() <= rewardToken.maxSupply());
    }
  que_mirar:
    - "Does mint() check totalSupply + amount <= maxSupply?"
    - "Is there a per-epoch or per-block emission rate limit?"
    - "Who has MINTER_ROLE? Is it a game server EOA (centralized risk)?"
    - "Can MINTER_ROLE be revoked? (AI Arena M-02: roles irrevocable)"
    - "grep: mint(, _mint(, totalSupply, maxSupply, emissionRate, epochCap"
  como_se_arregla: >
    Enforce hard supply cap in mint(): require(totalSupply() + amount <= MAX_SUPPLY).
    Use epoch-based emission with decreasing schedule (halving).
    Rate-limit mints per address per block/epoch. Use timelock on minter role changes.
  trampas:
    - "Legitimate high emission in early epochs is by design — check if cap exists, not if rate is 'high'"
    - "Token burns may offset mints — check net supply, not just gross mints"
    - "Governance-controlled emission changes are not bugs if behind timelock"
  solodit_ids:
    - m-02-minter-staker-spender-roles-can-never-be-revoked-code4rena-ai-arena-ai-arena-git
    - h-01-cross-contract-signature-replay-allows-users-to-inflate-rewards-pashov-audit-group-none-hybux_2025-11-11-markdown
  incidentes:
    - protocol: "Axie Infinity (SLP)"
      impact: "CRITICAL"
      detail: "SLP hyperinflation from uncapped breeding rewards crashed price from $0.36 to $0.003 (2021-2022), destroying $2B+ in player value"
      date: "2021-2022"
    - protocol: "STEPN (GMT/GST)"
      impact: "HIGH"
      detail: "GST token inflation from move-to-earn rewards exceeded burn rate, price collapsed 95% in 3 months"
      date: "2022-06"
  verificado: true
  confianza: alta
```

## 2. NFT Attribute Manipulation — Rerolling/Changing Traits After Mint

```yaml
- id: gfi-002
  titulo: "NFT attribute reroll with wrong fighterType bypasses limits and manipulates game stats"
  causa_raiz: >
    GameFi NFTs have on-chain attributes (strength, speed, weight) that determine
    battle outcomes. If the reroll function accepts a user-supplied fighterType
    parameter without validating it matches the NFT's actual type, attackers can
    reroll using a different type's attribute distribution, bypass per-type reroll
    limits (maxRerollsAllowed), and generate optimal stats. The DNA-to-attribute
    mapping depends on fighterType, so wrong type = different (better) stats.
  como_funciona: |
    1. Player owns a "Regular" fighter NFT (fighterType=0, maxRerolls=3)
    2. Player calls reRoll(tokenId, fighterType=1) — passes "Dendroid" type
    3. Contract checks numRerolls[tokenId] < maxRerollsAllowed[fighterType=1]
    4. Dendroid has higher maxRerolls (or different limit) — check passes even if Regular limit exceeded
    5. DNA is regenerated using fighterType=1 distribution — different attribute weights
    6. Player gets attributes from a rarer type's distribution on a common NFT
    7. Repeat: bypass Regular's maxRerolls by always passing fighterType=1
  invariante: |
    // reRoll must only accept the NFT's actual fighterType
    function invariant_rerollMatchesType() external {
        uint256 tokenId = 42; // ghost variable
        uint8 actualType = fighterFarm.fighters(tokenId).fighterType;
        // After any reRoll call, the fighterType used must equal actualType
        assert(lastRerollType[tokenId] == actualType);
    }
  que_mirar:
    - "Does reRoll() validate fighterType == fighters[tokenId].fighterType?"
    - "Is maxRerollsAllowed indexed by tokenId's type or user-supplied type?"
    - "Can DNA generation produce different results for different fighterTypes with same seed?"
    - "grep: reRoll, reroll, fighterType, dnaToIndex, createPhysicalAttributes, numRerolls"
    - "Is there a separate counter per fighterType or per tokenId?"
  como_se_arregla: >
    In reRoll(), read fighterType from storage (fighters[tokenId].fighterType) instead
    of accepting it as a parameter. Validate: require(fighterType == fighters[tokenId].fighterType).
    Index reroll limits by tokenId, not by user-supplied type.
  trampas:
    - "Different attribute distributions per type are by design — the bug is using wrong type, not having different types"
    - "Zero rerolls remaining is not a bug if the user legitimately used them all"
  solodit_ids:
    - h-04-since-you-can-reroll-with-a-different-fightertype-than-the-nft-you-own-you-can-reroll-bypassing-maxrerollsallowed-and-reroll-attributes-based-on-a-different-fightertype-code4rena-ai-arena-ai-arena-git
  incidentes:
    - protocol: "AI Arena"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "reRoll() accepted user-supplied fighterType without validation, allowing bypass of maxRerollsAllowed and attribute manipulation"
      date: "2024-02"
  verificado: true
  confianza: alta
```

## 3. Reward Claim Reentrancy — Minting Extra NFTs During Claim

```yaml
- id: gfi-003
  titulo: "Reentrancy during reward claim mints extra fighter NFTs via safeTransferFrom callback"
  causa_raiz: >
    When a reward claim function mints NFTs to the winner (e.g., MergingPool.claimRewards()),
    if it uses _safeMint or safeTransferFrom, the recipient's onERC721Received callback
    executes mid-claim. If the claim state (e.g., numRoundsClaimed) is not updated before
    the mint, the attacker can reenter claimRewards() from the callback and mint additional
    NFTs for rounds already claimed. Classic CEI violation in a GameFi context.
  como_funciona: |
    1. MergingPool.claimRewards() iterates through rounds, checks if user is winner
    2. For each winning round: calls fighterFarm.mintFromMergingPool() → _safeMint()
    3. _safeMint triggers attacker.onERC721Received() — still inside the loop
    4. Attacker reenters claimRewards() — numRoundsClaimed not yet incremented
    5. Second call mints the SAME round's NFTs again
    6. Attacker receives 2x (or Nx) the legitimate NFT rewards
  invariante: |
    // Each round's reward can only be claimed once per winner
    function invariant_noDoubleClaimRewards() external {
        // After claimRewards(), numRoundsClaimed[user] must equal roundId
        // and no round can yield more than winnersPerPeriod NFTs total
        for (uint256 r = 0; r < currentRound; r++) {
            assert(totalMintedForRound[r] <= winnersPerPeriod);
        }
    }
  que_mirar:
    - "Does claimRewards() update numRoundsClaimed BEFORE minting?"
    - "Does the mint function use _safeMint (callback) or _mint (no callback)?"
    - "Is there a nonReentrant modifier on claimRewards()?"
    - "grep: claimRewards, _safeMint, mintFromMergingPool, onERC721Received, numRoundsClaimed"
  como_se_arregla: >
    Update numRoundsClaimed before any external call (CEI pattern).
    Use nonReentrant modifier on claimRewards().
    Consider using _mint() instead of _safeMint() if recipient is known to be EOA.
  trampas:
    - "If the protocol uses _mint (no callback), reentrancy is not possible — check which mint variant is used"
    - "The reentrancy may yield duplicate NFTs that are worthless if attributes are identical"
    - "DoS variant: if winner is a contract that reverts in onERC721Received, no one can claim"
  solodit_ids:
    - h-08-player-can-mint-more-fighter-nfts-during-claim-of-rewards-by-leveraging-reentrancy-on-the-claimrewards-function-code4rena-ai-arena-ai-arena-git
    - h-02-stealing-fund-by-applying-reentrancy-attack-on-removecollateral-startliquidationauction-and-purchaseliquidationauctionnft-code4rena-backed-protocol-papr-contest-git
  incidentes:
    - protocol: "AI Arena"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Player reenters claimRewards() via onERC721Received callback to mint unlimited fighter NFTs from MergingPool"
      date: "2024-02"
  verificado: true
  confianza: alta
```

## 4. Game Outcome Oracle Manipulation — VRF/Randomness Exploits

```yaml
- id: gfi-004
  titulo: "Manipulable randomness source allows rigging game outcomes, loot boxes, and raffles"
  causa_raiz: >
    Games that use block.timestamp, block.prevrandao, blockhash, or transaction-ordering
    as randomness are manipulable by miners/validators and MEV searchers. Even with
    Chainlink VRF, if the contract allows the admin to change the VRF source, or if
    the fulfillment callback lacks validation, outcomes can be rigged. The draw organizer
    can manipulate participant lists to ensure a specific account wins.
  como_funciona: |
    1. Raffle/loot-box uses: winner = participants[uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % participants.length]
    2. Attacker (or validator) manipulates timestamp or transaction ordering
    3. Attacker brute-forces msg.sender (create2 addresses) to get favorable hash
    4. VRF variant: admin calls swapSource() to change randomness provider mid-draw
    5. New provider returns predictable value → admin-chosen winner
    6. Prize (NFT or token pool) goes to attacker instead of fair winner
  invariante: |
    // Randomness source must not change during an active draw
    function invariant_randomnessSourceStable() external {
        if (lottery.drawState() == DrawState.ACTIVE) {
            assert(lottery.randomnessSource() == lottery.drawStartSource());
        }
    }
    // Draw organizer cannot be a participant
    function invariant_organizerNotParticipant() external {
        address organizer = draw.owner();
        for (uint i = 0; i < draw.participantCount(); i++) {
            assert(draw.participants(i) != organizer);
        }
    }
  que_mirar:
    - "Is randomness derived from block.timestamp, prevrandao, or blockhash? (all manipulable)"
    - "Can the VRF source/provider be changed during an active draw?"
    - "Does the draw organizer have special access to participant list?"
    - "grep: block.timestamp, prevrandao, blockhash, requestRandomWords, fulfillRandomWords, swapSource"
    - "Is there a commit-reveal scheme or is it single-transaction randomness?"
  como_se_arregla: >
    Use Chainlink VRF v2+ with immutable configuration during active draws.
    Prevent randomness source changes while draw is active.
    Exclude organizer/admin from participant pool.
    Use commit-reveal for on-chain randomness where VRF is not available.
  trampas:
    - "Chainlink VRF is generally safe IF configuration is immutable — the bug is in admin ability to change it"
    - "block.prevrandao on PoS has 2^256 possible values but validators can withhold blocks (limited manipulation)"
    - "Multiple requests in short window can produce identical outcomes (TollanUniverse L-02)"
  solodit_ids:
    - h-02-draw-organizer-can-rig-the-draw-to-favor-certain-participants-such-as-their-own-account-code4rena-forgeries-forgeries-contest-git
    - m-01-undermining-the-fairness-of-the-protocol-in-swapsource-and-possibilities-for-stealing-a-jackpot-code4rena-wenwin-wenwin-contest-git
    - m-06-bad-source-of-randomness-code4rena-holograph-holograph-contest-git
    - m-06-changes-to-pyth-entropy-provider-used-by-scaledentropyprovider-allow-attacker-to-fix-jackpot-result-code4rena-megapot-megapot-git
    - c-03-number-of-available-spins-is-never-decreased-on-spin-or-if-spin-is-fulfilled-shieldify-none-guanciale-stake-markdown
    - l-02-multiple-requests-can-produce-identical-outcomes-within-a-short-window-shieldify-none-tollanuniverse-markdown
  incidentes:
    - protocol: "Forgeries (VRFNFTRandomDraw)"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Draw organizer can rig raffle by controlling participant list and timing of VRF request"
      date: "2023-01"
    - protocol: "Wenwin Lottery"
      firm: "Code4rena"
      impact: "MEDIUM"
      detail: "Admin can swap randomness source mid-draw via swapSource(), enabling jackpot theft"
      date: "2023-03"
  verificado: true
  confianza: alta
```

## 5. P2E Reward Stake Gaming — Zero Risk for Maximum Reward Points

```yaml
- id: gfi-005
  titulo: "Staking amount crafted to yield zero risk-at-stake on loss but full reward points on win"
  causa_raiz: >
    Play-to-earn battle systems often have a staking mechanism where players stake
    tokens before battles. On win, they earn reward points proportional to stake.
    On loss, a portion of stake is moved to "stakeAtRisk". If the stake amount is
    chosen such that the loss calculation rounds down to zero (due to integer division),
    the player risks nothing on losses but earns full reward points on wins.
    This is a precision/rounding exploit specific to GameFi battle economics.
  como_funciona: |
    1. RankedBattle._addResultPoints() calculates: curStakeAtRisk = (bpsLostPerLoss * stakeAmount) / 10000
    2. If stakeAmount < 10000 / bpsLostPerLoss, curStakeAtRisk rounds to zero
    3. Attacker stakes exactly this threshold amount (e.g., 1 NRN if bpsLostPerLoss = 10)
    4. On WIN: attacker gets full stakingFactor * eloFactor reward points
    5. On LOSS: curStakeAtRisk = 0, attacker loses nothing
    6. Over many battles, attacker accumulates reward points risk-free
    7. Claims NRN rewards at end of round — pure profit
  invariante: |
    // If a player has staked and loses, stakeAtRisk must be > 0
    function invariant_lossAlwaysCostsStake() external {
        // For any battle result that is a LOSS with stake > 0:
        // stakeAtRisk[round][fighter] must increase by > 0
        uint256 stakeAmount = rankedBattle.amountStaked(tokenId);
        if (stakeAmount > 0 && battleResult == 2) { // 2 = loss
            assert(stakeAtRisk.getStakeAtRisk(roundId, tokenId) > 0);
        }
    }
  que_mirar:
    - "Is curStakeAtRisk calculated with integer division that can round to zero?"
    - "Is there a minimum stake amount enforced?"
    - "Can stakingFactor/rewardPoints be earned with arbitrarily small stake?"
    - "grep: bpsLostPerLoss, stakeAtRisk, _addResultPoints, stakingFactor, curStakeAtRisk"
    - "Does the reward calculation use the same precision as the risk calculation?"
  como_se_arregla: >
    Enforce minimum stake amount that guarantees curStakeAtRisk >= 1.
    Round curStakeAtRisk UP (ceiling division) instead of down.
    Or: require(curStakeAtRisk > 0) when battleResult is a loss and stake > 0.
  trampas:
    - "Very small stakes that round to zero risk are the bug — large stakes are fine"
    - "If bpsLostPerLoss is 100% (10000 bps), rounding is not an issue — only affects partial-loss systems"
    - "The attacker needs many battles to accumulate meaningful rewards — but bots make this trivial"
  solodit_ids:
    - h-05-malicious-user-can-stake-an-amount-which-causes-zero-curstakeatrisk-on-a-loss-but-equal-rewardpoints-to-a-fair-user-on-a-win-code4rena-ai-arena-ai-arena-git
  incidentes:
    - protocol: "AI Arena"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Player stakes tiny NRN amount causing curStakeAtRisk=0 on losses, earning reward points risk-free across unlimited battles"
      date: "2024-02"
  verificado: true
  confianza: alta
```

## 6. NFT Rental Hijacking — Stealing Rented Assets via Guard Bypass

```yaml
- id: gfi-006
  titulo: "Rented NFT hijacked by bypassing Safe guard via setFallbackHandler during rental"
  causa_raiz: >
    NFT rental protocols like reNFT use Gnosis Safe wallets to custody rented NFTs.
    A guard contract prevents the renter from transferring the NFT out. However,
    if the guard does not validate ALL Safe module/handler changes, the renter
    can call setFallbackHandler() to set a malicious fallback that allows
    arbitrary delegatecall. Through delegatecall, the renter transfers the NFT
    out of the Safe, effectively stealing it from the lender.
  como_funciona: |
    1. Lender lists NFT for rent on reNFT protocol
    2. Renter fulfills order — NFT transferred to renter's Safe wallet with guard
    3. Guard blocks: transferFrom, safeTransferFrom, approve on rented NFTs
    4. Guard does NOT block: setFallbackHandler(maliciousContract)
    5. Renter calls setFallbackHandler(attacker_contract)
    6. Attacker contract has fallback that delegates to a contract calling transferFrom
    7. Renter triggers fallback → delegatecall executes in Safe context → NFT transferred out
    8. Rental period ends, stopRent() fails — NFT is gone
  invariante: |
    // Guard must block ALL Safe configuration changes during active rental
    function invariant_guardBlocksConfigChanges() external {
        bytes4[] memory blockedSelectors = new bytes4[](4);
        blockedSelectors[0] = bytes4(keccak256("setFallbackHandler(address)"));
        blockedSelectors[1] = bytes4(keccak256("setGuard(address)"));
        blockedSelectors[2] = bytes4(keccak256("enableModule(address)"));
        blockedSelectors[3] = bytes4(keccak256("disableModule(address)"));
        // All must be blocked by checkTransaction
        for (uint i = 0; i < blockedSelectors.length; i++) {
            assert(guard.isBlocked(blockedSelectors[i]));
        }
    }
  que_mirar:
    - "Does the rental guard block setFallbackHandler, setGuard, enableModule, disableModule?"
    - "Can the renter execute arbitrary transactions through the Safe?"
    - "Does checkTransaction validate the `to` address and function selector exhaustively?"
    - "grep: setFallbackHandler, setGuard, enableModule, checkTransaction, delegatecall"
    - "Is there a whitelist or blacklist approach? (blacklists miss new attack vectors)"
  como_se_arregla: >
    Guard must block ALL Safe configuration functions: setFallbackHandler, setGuard,
    enableModule, disableModule, execTransactionFromModule. Use whitelist approach
    (only allow known-safe operations) instead of blacklist.
  trampas:
    - "The guard may correctly block transferFrom but miss configuration changes — check exhaustively"
    - "delegatecall from Safe executes in Safe's storage context — it CAN move assets"
    - "Gnosis Safe modules can also bypass guards — check module management too"
  solodit_ids:
    - h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallbackhandler-code4rena-renft-renft-git
    - h-01-all-orders-can-be-hijacked-to-lock-rental-assets-forever-by-tipping-a-malicious-erc20-code4rena-renft-renft-git
  incidentes:
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Guard missing validation on setFallbackHandler allows renter to hijack any rented ERC721/ERC1155 via delegatecall"
      date: "2024-01"
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Malicious ERC20 tip locks rental assets forever by reverting in stopRent flow"
      date: "2024-01"
  verificado: true
  confianza: alta
```

## 7. NFT Rental Return Blocking — Paused/Blocklisted Token Prevents Stop

```yaml
- id: gfi-007
  titulo: "Paused or blocklisted NFT/payment token prevents rental return, trapping lender assets"
  causa_raiz: >
    NFT rental protocols require transferring the NFT back to the lender when
    the rental period ends (stopRent). If the NFT contract is pausable (CryptoKitties,
    CryptoFighters) or the payment ERC20 has a blocklist (USDC), and the transfer
    reverts, the entire stopRent transaction fails. The renter retains the NFT
    indefinitely while the lender cannot recover it. This extends to any ERC721
    where transfers can be externally blocked.
  como_funciona: |
    1. Lender rents out a CryptoKitty NFT via rental protocol
    2. CryptoKitties contract owner calls pause() — all transfers blocked
    3. Rental period expires, lender calls stopRent()
    4. stopRent() → safeTransferFrom(safe, lender, tokenId) → REVERTS (paused)
    5. Entire transaction reverts — rental state not updated
    6. Renter keeps using the NFT indefinitely while contract is paused
    7. Variant: USDC blocklist on renter's Safe address blocks payment transfer
  invariante: |
    // stopRent must always succeed or have a fallback recovery mechanism
    function invariant_rentalAlwaysRecoverable() external {
        if (block.timestamp > rental.endTime(rentalId)) {
            // After rental period, lender must be able to recover NFT
            // even if primary transfer fails
            assert(rental.hasRecoveryPath(rentalId));
        }
    }
  que_mirar:
    - "Does stopRent() handle revert from safeTransferFrom gracefully?"
    - "Is there a fallback/recovery mechanism if NFT transfer fails?"
    - "Does the protocol accept pausable NFTs (CryptoKitties, CryptoFighters)?"
    - "Does payment use USDC/USDT with blocklist capability?"
    - "grep: stopRent, reclaimRentalOrder, safeTransferFrom, try/catch, paused"
  como_se_arregla: >
    Use try/catch around NFT transfers in stopRent. If transfer fails, mark rental
    as reclaimable and allow lender to retry later. Maintain a whitelist of accepted
    NFT contracts that excludes pausable ones. Separate NFT return from payment settlement.
  trampas:
    - "CryptoKitties pause is admin-controlled and rare — but it HAS happened"
    - "If the protocol only accepts ERC721 from a whitelist, pausable tokens may be excluded by design"
    - "USDC blocklist requires lender/renter to be sanctioned — unlikely but possible"
  solodit_ids:
    - m-12-paused-erc721erc1155-could-cause-stoprent-to-revert-potentially-causing-issues-for-the-lender-code4rena-renft-renft-git
    - m-15-blocklisting-in-payment-erc20-can-cause-rented-nft-to-be-stuck-in-safe-code4rena-renft-renft-git
    - m-20-cryptokitty-and-cryptofighter-nft-can-be-paused-which-block-borrowing-repaying-liquidating-action-in-the-erc721pool-when-borrowers-still-forced-to-pay-the-compounding-interest-sherlock-ajna-ajna-git
    - m-02-liquidation-can-be-blocked-by-pausing-or-blacklisting-the-nft-contract-permanently-trapping-expired-loans-shieldify-none-shiny-markdown
  incidentes:
    - protocol: "reNFT"
      firm: "Code4rena"
      impact: "MEDIUM"
      detail: "Paused ERC721/ERC1155 causes stopRent to revert, lender cannot recover rented NFT"
      date: "2024-01"
    - protocol: "Ajna (ERC721Pool)"
      firm: "Sherlock"
      impact: "MEDIUM"
      detail: "CryptoKitty/CryptoFighter pause blocks borrow/repay/liquidate while interest accrues"
      date: "2023-05"
  verificado: true
  confianza: alta
```

## 8. Loot Box / Gacha Spin Counter Not Decremented

```yaml
- id: gfi-008
  titulo: "Spin/loot-box counter never decremented — unlimited free spins drain prize pool"
  causa_raiz: >
    Gacha/loot-box systems track available spins per user. If the spin counter
    is not decremented when a spin is executed or when a result is fulfilled
    (VRF callback), the user can spin unlimited times with a single purchase.
    The prize pool (tokens, NFTs) is drained completely. This is especially
    dangerous when VRF fulfillment is asynchronous — the counter must be
    decremented at request time, not fulfillment time.
  como_funciona: |
    1. User buys 1 spin: availableSpins[user] = 1
    2. User calls spin() — sends VRF request, but availableSpins NOT decremented
    3. Before VRF fulfills, user calls spin() again — availableSpins still 1
    4. Repeat N times — N pending VRF requests, all valid
    5. Each fulfillRandomWords() distributes a prize
    6. User drains entire prize pool from a single spin purchase
  invariante: |
    // availableSpins must be decremented BEFORE VRF request
    function invariant_spinsDecrementedOnRequest() external {
        uint256 totalRequests = lootBox.totalVRFRequests();
        uint256 totalSpinsPurchased = lootBox.totalSpinsPurchased();
        assert(totalRequests <= totalSpinsPurchased);
    }
  que_mirar:
    - "Is availableSpins decremented in spin() (request) or fulfillRandomWords() (callback)?"
    - "Can spin() be called multiple times before fulfillment?"
    - "Is there a pending request check that blocks new spins?"
    - "grep: availableSpins, numSpins, spin(), fulfillRandomWords, requestRandomWords"
    - "Does the contract track pending requests per user?"
  como_se_arregla: >
    Decrement availableSpins in spin() BEFORE requestRandomWords().
    Add: require(!hasPendingRequest[user]) to prevent concurrent spins.
    Track requestId → user mapping to prevent replay.
  trampas:
    - "If VRF callback reverts, the spin is lost — need recovery mechanism"
    - "Rate limiting by block does not help if multiple txs in same block"
    - "The bug may be in mockRequestRandom (test function left in production)"
  solodit_ids:
    - c-03-number-of-available-spins-is-never-decreased-on-spin-or-if-spin-is-fulfilled-shieldify-none-guanciale-stake-markdown
    - m-01-mockrequestrandom-can-bypass-single-processing-invariant-and-generate-multiple-results-for-the-same-logical-request-event-level-replay-shieldify-none-tollanuniverse-markdown
  incidentes:
    - protocol: "Guanciale Stake"
      firm: "Shieldify"
      impact: "CRITICAL"
      detail: "availableSpins never decremented on spin or fulfillment — unlimited free spins drain all prizes"
      date: "2024"
    - protocol: "TollanUniverse"
      firm: "Shieldify"
      impact: "MEDIUM"
      detail: "mockRequestRandom bypasses single-processing invariant, generating multiple results per request"
      date: "2024"
  verificado: true
  confianza: alta
```

## 9. In-Game Marketplace Fee Bypass — Trading Outside Protocol

```yaml
- id: gfi-009
  titulo: "NFT royalty/fee bypass via non-compliant marketplace or direct transfer"
  causa_raiz: >
    Game economies rely on marketplace fees (royalties, protocol fees) to fund
    treasury and creator rewards. EIP-2981 royalties are informational only —
    marketplaces can ignore them. If the NFT contract does not enforce fees
    at the transfer level (e.g., via _beforeTokenTransfer hook), users can
    trade NFTs peer-to-peer or on non-royalty-enforcing marketplaces, completely
    bypassing the protocol's fee structure. Cross-chain bridges that wrap NFTs
    also lose royalty enforcement on the destination chain.
  como_funciona: |
    1. Game NFT has 5% royalty set via EIP-2981 royaltyInfo()
    2. Official marketplace respects royalties — charges 5% on each sale
    3. User lists NFT on a marketplace that ignores EIP-2981 (e.g., SudoSwap v1)
    4. Sale executes: transferFrom(seller, buyer, tokenId) — no royalty check
    5. Or: user does OTC trade via direct approve() + transferFrom()
    6. Creator/protocol receives zero fees on the trade
    7. Cross-chain variant: ERC721Bridgable wraps NFT on L2 without royalty info
  invariante: |
    // Every transfer should route through fee-collecting mechanism
    // Note: this is unenforceable at ERC721 level without transfer hooks
    function invariant_royaltyEnforced() external {
        // Track total volume vs total royalties collected
        uint256 expectedRoyalties = (totalVolume * royaltyBps) / 10000;
        uint256 actualRoyalties = royaltyReceiver.balance;
        // Allow some gap for off-chain trades, but flag large discrepancy
        assert(actualRoyalties >= expectedRoyalties * 80 / 100);
    }
  que_mirar:
    - "Does the NFT use EIP-2981 (informational) or enforce fees in _beforeTokenTransfer?"
    - "Is there an operator filter (like OpenSea's) that blocks non-royalty marketplaces?"
    - "Does the bridged version of the NFT preserve royalty info?"
    - "grep: royaltyInfo, _beforeTokenTransfer, operatorFilterRegistry, setApprovalForAll"
    - "Can users bypass the operator filter by using approve() instead of setApprovalForAll?"
  como_se_arregla: >
    For maximum enforcement: implement fee in _beforeTokenTransfer or use operator
    filter registry. Accept that on-chain royalty enforcement has limitations.
    Use token-gated features (staking, gameplay) that require using the official
    marketplace. Consider soulbound mechanics for non-tradeable items.
  trampas:
    - "EIP-2981 non-compliance is not a 'bug' in the traditional sense — it's a design limitation"
    - "Operator filter can be circumvented via wrapper contracts"
    - "Some protocols intentionally make NFTs non-transferable (soulbound) — not a bug"
  solodit_ids:
    - m-7-erc721bridgable-and-erc1155bridgable-are-not-eip-2981-compliant-and-fail-to-correctly-collect-or-attribute-royalties-to-artists-sherlock-flayer-git
    - m-07-royalty-recipients-will-not-get-fair-share-of-royalties-code4rena-caviar-caviar-private-pools-git
    - call-to-royalty-engine-can-block-nft-auction-spearbit-astaria-pdf
  incidentes:
    - protocol: "Flayer (ERC721Bridgable)"
      firm: "Sherlock"
      impact: "MEDIUM"
      detail: "Bridged ERC721/ERC1155 not EIP-2981 compliant, royalties lost on L2 trades"
      date: "2024"
    - protocol: "Caviar Private Pools"
      firm: "Code4rena"
      impact: "MEDIUM"
      detail: "Royalty recipients don't get fair share when pool trades bypass royaltyInfo"
      date: "2023-04"
  verificado: true
  confianza: media
```

## 10. Staking NFT While Listed for Sale — Double-Use Asset Exploitation

```yaml
- id: gfi-010
  titulo: "NFT used simultaneously for staking rewards and marketplace listing — double value extraction"
  causa_raiz: >
    If a protocol allows staking an NFT for rewards while the same NFT remains
    listed on a marketplace (or approved for transfer), the owner extracts double
    value: staking rewards + sale price. When the NFT sells, the staking contract
    still considers it staked under the original owner. The new buyer may not be
    able to unstake, and rewards continue flowing to the seller. This is a state
    inconsistency between the staking contract and the NFT ownership.
  como_funciona: |
    1. User stakes NFT in StakingContract — NFT transferred to staking contract
    2. OR: staking uses approval-based model (NFT stays in user's wallet)
    3. User lists same NFT on OpenSea via setApprovalForAll
    4. NFT sells — transferred to buyer via marketplace
    5. Staking contract still has staked[tokenId] = originalOwner
    6. Original owner continues earning staking rewards for NFT they no longer own
    7. Buyer cannot stake or use the NFT in game (it's "staked" by someone else)
    8. Variant: user front-runs marketplace sale with unstake to get rewards + sale price
  invariante: |
    // Staked NFT must be owned by the staking contract, not approved-only
    function invariant_stakedNFTCustody() external {
        for (uint i = 0; i < stakedTokenIds.length; i++) {
            uint256 tokenId = stakedTokenIds[i];
            assert(nft.ownerOf(tokenId) == address(stakingContract));
        }
    }
  que_mirar:
    - "Does staking transfer the NFT to the contract or just check approval?"
    - "Does _beforeTokenTransfer hook auto-unstake on transfer?"
    - "Can a staked NFT be approved for a marketplace while staked?"
    - "grep: stake(, unstake(, setApprovalForAll, _beforeTokenTransfer, ownerOf"
    - "Is there a transfer lock while staked?"
  como_se_arregla: >
    Transfer NFT to staking contract on stake (custody model).
    If using approval model: implement _beforeTokenTransfer to auto-unstake on transfer.
    Block setApprovalForAll while NFT is staked.
    Verify ownerOf(tokenId) == staker on every reward claim.
  trampas:
    - "Custody-based staking (NFT transferred to contract) prevents this by design"
    - "Some protocols intentionally allow 'soft staking' where NFT stays in wallet — verify if double-use is intended"
    - "The bug requires the NFT to actually sell while staked — if staking blocks transfers, it's fine"
  solodit_ids:
    - double-claiming-of-accrued-rewards-via-unwinding-after-accrue-call-spearbit-none-infinifi-contracts-pdf
    - h-3-unbounded-_unlocktime-allows-the-attacker-to-get-a-huge-stakedtimebonus-and-dominate-the-voting-sherlock-3d-frankenpunks-frankendao-git
  incidentes:
    - protocol: "Multiple NFT staking protocols"
      impact: "HIGH"
      detail: "Approval-based staking allows listing on marketplace while earning staking rewards — double value extraction"
      date: "2022-2024"
  verificado: true
  confianza: media
```

## 11. NFT Lending Liquidation Cascade — Floor Price Drop Mass Liquidations

```yaml
- id: gfi-011
  titulo: "Floor price oracle manipulation or crash triggers mass liquidation of NFT-backed loans"
  causa_raiz: >
    NFT lending protocols (BendDAO, ParaSpace, Blur/Blend, Astaria) use floor
    price oracles to determine collateral value. When the floor price drops
    sharply (or is manipulated via wash trading/MEV), all loans backed by that
    collection become undercollateralized simultaneously. Mass liquidation auctions
    flood the market with supply, further crashing the floor — a death spiral.
    Stale oracle prices, incorrect pair decimal assumptions, and missing Chainlink
    staleness checks exacerbate the problem.
  como_funciona: |
    1. 1000 Bored Apes used as collateral across NFT lending protocol, floor = 80 ETH
    2. Whale dumps 20 Apes on OpenSea, crashing floor to 50 ETH
    3. Oracle updates: all loans with LTV > 62% (50/80) become liquidatable
    4. Liquidation bots trigger 300 auctions simultaneously
    5. Auction supply floods market — no buyers at 50 ETH, Apes sell at 30 ETH
    6. Floor crashes to 30 ETH — remaining 700 loans now liquidatable too
    7. Protocol accumulates bad debt (auction proceeds < outstanding debt)
    8. Lenders lose funds, protocol becomes insolvent
  invariante: |
    // Oracle price must be fresh and within reasonable bounds
    function invariant_oracleNotStale() external {
        (, , , uint256 updatedAt, ) = floorPriceOracle.latestRoundData();
        assert(block.timestamp - updatedAt < STALENESS_THRESHOLD);
    }
    // Protocol must have sufficient reserves to cover potential bad debt
    function invariant_noSystemBadDebt() external {
        uint256 totalDebt = lendingPool.totalOutstandingDebt();
        uint256 totalCollateralValue = lendingPool.totalCollateralValue();
        assert(totalCollateralValue >= totalDebt);
    }
  que_mirar:
    - "What oracle is used for floor price? (Chainlink NFT feed, TWAP, custom)"
    - "Is there a staleness check on oracle data?"
    - "Is there a liquidation delay/grace period?"
    - "Does the protocol have a bad debt socialization mechanism?"
    - "grep: latestRoundData, floorPrice, liquidate, healthFactor, auctionStart"
    - "Is there a maximum number of simultaneous liquidations?"
  como_se_arregla: >
    Implement oracle staleness checks (revert if updatedAt > threshold).
    Add liquidation grace period (e.g., 24h health check buffer).
    Use TWAP for floor price instead of spot (smooths manipulation).
    Implement bad debt socialization across lenders.
    Cap maximum liquidations per block to prevent cascades.
  trampas:
    - "Floor price drops are market events, not bugs — the bug is in missing protections against cascades"
    - "Some protocols intentionally use instant liquidation for capital efficiency"
    - "Chainlink NFT floor price feeds have limited coverage — many collections use custom oracles"
  solodit_ids:
    - strategyfloorfromchainlink-will-often-revert-due-to-stale-prices-spearbit-looksrare-pdf
    - h-09-uniswapv3-tokens-of-certain-pairs-will-be-wrongly-valued-leading-to-liquidations-code4rena-paraspace-paraspace-contest-git
    - h-02-isolaterepay-lack-of-check-onbehalf-nftowner-code4rena-benddao-benddao-git
    - if-a-collaterals-liquidation-auction-on-seaport-ends-without-a-winning-bid-the-call-to-liquidatorn-spearbit-astaria-pdf
    - incorrect-auction-end-validation-in-liquidatornftclaim-spearbit-astaria-pdf
  incidentes:
    - protocol: "BendDAO"
      impact: "HIGH"
      detail: "BAYC floor drop from 150 ETH to 72 ETH triggered liquidation cascade, protocol nearly insolvent with ~$5.5M bad debt risk"
      date: "2022-08"
    - protocol: "ParaSpace"
      impact: "HIGH"
      detail: "Exploiter attempted to manipulate NFT collateral valuation to drain ~$5M in lending pool"
      date: "2023-03"
    - protocol: "Astaria"
      firm: "Spearbit"
      impact: "HIGH"
      detail: "Liquidation auction on Seaport with no winning bid doesn't clear lien data, locking collateral"
      date: "2023"
  verificado: true
  confianza: alta
```

## 12. Tournament/Prize Pool Manipulation — Late Entry After Seeing Others

```yaml
- id: gfi-012
  titulo: "Late tournament entry after observing participants allows strategic gaming of prize pool"
  causa_raiz: >
    On-chain tournaments where entries are visible in the mempool or on-chain
    state allow late entrants to optimize their strategy. If the tournament
    doesn't commit entries before revealing opponents, a player can see all
    other entries and craft their entry to maximize win probability. This
    applies to prediction markets, battle brackets, and any competitive
    game where information asymmetry exists between early and late entrants.
  como_funciona: |
    1. Tournament opens: players submit predictions/entries on-chain
    2. All entries visible on-chain (or in mempool) before deadline
    3. Late entrant analyzes existing entries: sees distribution of predictions
    4. Late entrant calculates optimal entry to maximize expected payout
    5. In prediction markets: enters opposite of majority to capture full payout if contrarian wins
    6. In battle brackets: selects fighters/strategy that counters most opponents
    7. Guaranteed information advantage over early entrants
  invariante: |
    // Entries must be committed (hashed) before being revealed
    function invariant_commitRevealEnforced() external {
        if (tournament.phase() == Phase.SUBMISSION) {
            // All entries should be commitments (hashes), not plaintext
            for (uint i = 0; i < tournament.entryCount(); i++) {
                assert(tournament.entries(i).isCommitment == true);
            }
        }
    }
  que_mirar:
    - "Are entries submitted as plaintext or commit-reveal hashes?"
    - "Can entries be modified after submission?"
    - "Is there a submission deadline enforced on-chain?"
    - "grep: submit, commit, reveal, entry, deadline, tournament, bracket"
    - "Are prediction/battle parameters visible before tournament closes?"
  como_se_arregla: >
    Use commit-reveal scheme: players submit hash(entry + salt) during commit phase,
    reveal entry + salt during reveal phase. Enforce deadlines on-chain.
    Randomize matchups after all entries are committed.
  trampas:
    - "Some tournaments intentionally allow late entry — check if it's by design"
    - "Commit-reveal adds complexity and UX friction — may be intentional tradeoff"
    - "MEV protection (private mempools) partially mitigates but doesn't eliminate"
  solodit_ids:
    - m-02-late-participation-advantage-in-memepredictionmarket-pashov-audit-group-none-mcp_2025-08-07-markdown
    - m-02-high-level-heroes-can-receive-guaranteed-bonus-rewards-shieldify-none-onchainheroes-fishingvoyages-markdown
    - m-01-multiplier-configuration-can-break-distribution-invariant-and-permanently-freeze-game-resolution-and-claims-shieldify-none-abster-freefall-markdown
  incidentes:
    - protocol: "MemePredictionMarket"
      firm: "Pashov"
      impact: "MEDIUM"
      detail: "Late participants can see prediction distribution and enter strategically for guaranteed advantage"
      date: "2025"
    - protocol: "OnchainHeroes"
      firm: "Shieldify"
      impact: "MEDIUM"
      detail: "High-level heroes receive guaranteed bonus rewards by gaming fishing voyage timing"
      date: "2024"
  verificado: true
  confianza: media
```

## 13. Game Economy Drain via Token Conversion Arbitrage

```yaml
- id: gfi-013
  titulo: "In-game token conversion rates create arbitrage loop that drains economy reserves"
  causa_raiz: >
    GameFi protocols often have multiple tokens (governance token, reward token,
    in-game currency) with conversion mechanisms between them. If the exchange
    rates between these tokens are set by different mechanisms (one by AMM, one
    by admin, one by formula), arbitrage loops can form. An attacker converts
    token A → B → C → A, profiting on each conversion due to rate inconsistencies.
    Flash loans amplify this to drain the entire reserve in one transaction.
  como_funciona: |
    1. Game has: GOLD (in-game), GEM (premium), GOV (governance)
    2. GOLD → GEM conversion at fixed rate in game shop: 100 GOLD = 1 GEM
    3. GEM → GOV conversion via staking at rate based on totalStaked: variable rate
    4. GOV → GOLD conversion via DEX LP: market rate
    5. Attacker flash loans GOV tokens
    6. GOV → GOLD (DEX): gets 10,000 GOLD per GOV
    7. GOLD → GEM (shop): gets 100 GEM
    8. GEM → GOV (unstake): gets 2 GOV per GEM (200 GOV total)
    9. Net profit: started with 1 GOV, ended with 200 GOV (minus flash loan fee)
    10. Loop drains game shop's GEM reserves completely
  invariante: |
    // Cross-token conversion should not create profitable cycles
    function invariant_noArbitrageCycle() external {
        uint256 startGold = 10000e18;
        uint256 gems = shop.goldToGem(startGold);
        uint256 gov = staking.gemToGov(gems);
        uint256 endGold = dex.getAmountOut(gov, address(govToken), address(goldToken));
        assert(endGold <= startGold); // No profit from cycle
    }
  que_mirar:
    - "Are there multiple conversion paths between tokens?"
    - "Are rates set by different mechanisms (fixed vs market vs formula)?"
    - "Can conversions happen atomically (same transaction)?"
    - "grep: convert, exchange, swap, redeem, rate, pricePerToken"
    - "Is there a cooldown between conversions?"
  como_se_arregla: >
    Unify rate sources: all conversions should reference the same price oracle.
    Add cooldowns between conversions to prevent atomic arbitrage.
    Implement slippage/spread on fixed-rate conversions.
    Rate-limit conversions per address per epoch.
  trampas:
    - "Small arbitrage opportunities are normal in DeFi — the bug is when the entire reserve can be drained"
    - "Admin-set rates that are 'close enough' may still create profitable loops at scale"
    - "Flash loan amplification turns tiny arbitrage into catastrophic drain"
  solodit_ids:
    - m-04-its-possible-to-swap-nft-token-ids-without-fee-and-also-attacker-can-wrap-unwrap-all-the-nft-token-balance-of-the-pair-contract-and-steal-their-air-drops-for-those-token-ids-code4rena-caviar-caviar-contest-git
    - m-01-the-buy-functions-mechanism-enables-users-to-acquire-flash-loans-at-a-cheaper-fee-rate-code4rena-caviar-caviar-private-pools-git
  incidentes:
    - protocol: "Treasure DAO (MAGIC)"
      impact: "HIGH"
      detail: "Free minting exploit on Treasure marketplace allowed attacker to mint 100+ NFTs for free via listing price of 0 MAGIC"
      date: "2022-03"
    - protocol: "Multiple GameFi protocols"
      impact: "MEDIUM"
      detail: "Token conversion arbitrage between fixed-rate in-game shops and variable-rate DEX pools"
      date: "2022-2023"
  verificado: true
  confianza: media
```

## 14. NFT Lending — Collateral Deposited to Wrong Address

```yaml
- id: gfi-014
  titulo: "NFT collateral credited to operator instead of owner when deposited via approved transfer"
  causa_raiz: >
    NFT lending protocols accept collateral via safeTransferFrom, which triggers
    onERC721Received(operator, from, tokenId, data). If the protocol credits
    the collateral to `operator` (msg.sender of safeTransferFrom) instead of
    `from` (the actual NFT owner), an approved operator can deposit someone
    else's NFT and become the credited collateral owner. The real owner loses
    their NFT; the operator borrows against it and defaults.
  como_funciona: |
    1. Alice approves Bob to manage her NFTs (setApprovalForAll)
    2. Bob calls: nftContract.safeTransferFrom(alice, lendingProtocol, tokenId)
    3. Protocol.onERC721Received(operator=bob, from=alice, tokenId, data) fires
    4. Protocol credits: collateral[bob][tokenId] = true  (should be alice)
    5. Bob borrows max against Alice's NFT
    6. Bob defaults — Alice's NFT gets liquidated
    7. Alice lost her NFT, Bob got the loan proceeds
  invariante: |
    // Collateral must always be credited to the `from` parameter, not `operator`
    function invariant_collateralCreditedToFrom() external {
        // In onERC721Received(operator, from, tokenId, data):
        // collateralOwner[tokenId] must equal `from`, not `operator`
        assert(lendingPool.collateralOwner(lastDepositedTokenId) == lastFromAddress);
    }
  que_mirar:
    - "In onERC721Received, is collateral credited to `operator` or `from`?"
    - "Can an approved operator trigger deposit on behalf of the owner?"
    - "Does the protocol verify msg.sender == from for direct deposits?"
    - "grep: onERC721Received, operator, from, collateralOwner, _depositNFT"
  como_se_arregla: >
    Always credit collateral to the `from` parameter in onERC721Received.
    Alternatively, require direct deposit via a dedicated deposit() function
    where msg.sender is the NFT owner.
    Validate: require(from == expectedDepositor) in onERC721Received.
  trampas:
    - "setApprovalForAll is commonly used for marketplace integrations — the approval itself is not the bug"
    - "The bug only matters if the protocol uses onERC721Received for deposits (vs dedicated function)"
    - "Some protocols intentionally allow operator deposits — check documentation"
  solodit_ids:
    - h-03-collateral-nft-deposited-to-a-wrong-address-when-transferred-directly-to-paprcontroller-code4rena-backed-protocol-papr-contest-git
    - risk-of-locked-assets-due-to-use-of-_mint-instead-of-_safemint-trailofbits-none-arcadexyz-v3-pdf
  incidentes:
    - protocol: "Papr"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Collateral NFT credited to operator address instead of actual NFT owner when transferred directly to PaprController"
      date: "2023-01"
    - protocol: "Arcade.xyz v3"
      firm: "Trail of Bits"
      impact: "MEDIUM"
      detail: "Use of _mint instead of _safeMint risks locked assets when receiver is a contract"
      date: "2023"
  verificado: true
  confianza: alta
```

## 15. Guild/Scholarship Token Custody — Manager Rug-Pull

```yaml
- id: gfi-015
  titulo: "Guild manager can rug-pull scholar NFTs by exploiting custody or delegation model"
  causa_raiz: >
    In GameFi scholarship/guild systems, a manager (guild owner) delegates
    expensive NFTs to scholars (players) who play and share rewards. If the
    custody model gives the manager full control (approval, transfer rights)
    without on-chain enforcement of the revenue-sharing agreement, the manager
    can: (1) withdraw NFTs while scholars are actively playing, (2) front-run
    reward claims to steal scholar earnings, or (3) change revenue splits
    retroactively. The lack of on-chain escrow or timelock on manager actions
    enables unilateral rug-pulls.
  como_funciona: |
    1. Guild manager deposits 10 Axie NFTs into guild contract
    2. Manager assigns NFTs to scholars: scholar[tokenId] = scholarAddress
    3. Scholars play battles, earning SLP rewards credited to their accounts
    4. Manager calls withdrawNFT(tokenId) — no timelock, no scholar consent required
    5. Scholar's active game session breaks — NFT removed mid-battle
    6. Manager front-runs scholar's claimRewards() with a revenueSplit change: 100% to manager
    7. Scholar receives 0% of earned rewards
    8. Or: manager calls emergencyWithdraw() bypassing all checks
  invariante: |
    // NFT withdrawal must have a timelock when actively delegated to a scholar
    function invariant_withdrawalTimelock() external {
        for (uint i = 0; i < delegatedTokenIds.length; i++) {
            uint256 tokenId = delegatedTokenIds[i];
            if (guild.scholar(tokenId) != address(0)) {
                // Cannot withdraw if delegation is active and timelock not expired
                uint256 withdrawRequestTime = guild.withdrawRequestTime(tokenId);
                if (withdrawRequestTime > 0) {
                    assert(block.timestamp >= withdrawRequestTime + WITHDRAWAL_DELAY);
                }
            }
        }
    }
  que_mirar:
    - "Can the manager withdraw delegated NFTs instantly?"
    - "Is there a timelock on manager actions (withdraw, split change)?"
    - "Are reward splits enforced on-chain or just off-chain agreements?"
    - "grep: withdraw, delegate, scholar, manager, revenueSplit, emergencyWithdraw"
    - "Can the manager change revenue split retroactively for unclaimed rewards?"
  como_se_arregla: >
    Implement withdrawal timelock (e.g., 7 days) for delegated NFTs.
    Lock revenue split on-chain at delegation time — changes require scholar consent.
    Use escrow contract that releases NFT only after reward settlement.
    Emit events for all manager actions to enable off-chain monitoring.
  trampas:
    - "Centralized guild management is common and often 'by design' — the bug is missing protections"
    - "Emergency withdraw may be necessary for protocol upgrades — but should require multisig/timelock"
    - "Off-chain agreements (Discord/contracts) are not enforceable on-chain"
  solodit_ids:
    - m-01-malicious-nft-owners-can-rug-the-reservation-of-the-long-term-code4rena-coded-estate-coded-estate-git
    - h-07-logic-flaw-in-check_can_edit_short-allows-editing-short-term-rental-before-finalization-enabling-theft-of-users-deposited-funds-code4rena-coded-estate-coded-estate-git
    - m-14-lender-of-a-pay-order-lending-can-grief-renter-of-the-payment-code4rena-renft-renft-git
  incidentes:
    - protocol: "Axie Infinity Scholarships"
      impact: "HIGH"
      detail: "Guild managers routinely rug-pulled scholars by withdrawing Axies and changing revenue splits without notice — estimated $50M+ in scholar losses across ecosystem"
      date: "2021-2022"
    - protocol: "Coded Estate"
      firm: "Code4rena"
      impact: "MEDIUM"
      detail: "Malicious NFT owners can rug long-term rental reservations"
      date: "2024"
  verificado: true
  confianza: media
```

## 16. Cross-Game/Cross-Chain NFT Asset Bridging Exploits

```yaml
- id: gfi-016
  titulo: "Cross-chain NFT bridge allows minting duplicate or manipulated assets on destination chain"
  causa_raiz: >
    When game NFTs are bridged cross-chain, the source chain locks/burns the NFT
    and the destination chain mints a wrapped version. If: (1) the bridge doesn't
    verify the NFT attributes/metadata match, (2) the destination chain allows
    minting with arbitrary tokenIds, (3) approval state from source chain persists
    on destination, or (4) the bridge message can be replayed, an attacker can
    mint duplicate NFTs, bridge non-existent tokens, or steal already-bridged NFTs.
    One-way bridges that can't return NFTs cause permanent lock.
  como_funciona: |
    1. Attacker owns low-value NFT (tokenId=100, common rarity) on Chain A
    2. Attacker bridges NFT to Chain B via bridgeToken(nftContract, tokenId=100)
    3. Bridge mints wrapped NFT on Chain B with same tokenId
    4. Bridge message lacks attribute verification — attacker's contract reports
       different attributes for tokenId=100 on Chain B (legendary rarity)
    5. Attacker sells "legendary" wrapped NFT on Chain B marketplace
    6. Replay variant: attacker replays bridge message to mint second copy
    7. One-way variant: ERC721 bridged via generic bridge, no return path exists
       — user's NFT permanently locked
  invariante: |
    // Each tokenId must exist on exactly one chain at any time
    function invariant_noDuplicateAcrossChains() external {
        // Source chain: NFT must be locked/burned if bridged
        if (bridge.isBridged(tokenId)) {
            assert(nft.ownerOf(tokenId) == address(bridge) || nft.burned(tokenId));
        }
        // Destination chain: wrapped NFT must map 1:1 to locked source
        assert(wrappedNft.totalSupply() <= bridge.totalLocked());
    }
  que_mirar:
    - "Does the bridge verify NFT attributes/metadata or just tokenId?"
    - "Can the bridge message be replayed? (nonce/hash tracking)"
    - "Is there a return path (unlock on source when burned on destination)?"
    - "Does the wrapped NFT preserve approval state from source? (should NOT)"
    - "grep: bridgeToken, bridgeNFT, _mintWrapped, messageHash, nonce, lockNFT"
    - "Can arbitrary tokenIds be minted on destination without source verification?"
  como_se_arregla: >
    Include NFT attributes hash in bridge message — verify on destination.
    Track message hashes to prevent replay.
    Implement bidirectional bridge (lock-mint on outbound, burn-unlock on inbound).
    Clear all approvals on bridged NFTs.
    Validate tokenId exists and is owned by sender on source chain.
  trampas:
    - "Generic token bridges (LayerZero, Axelar) may not support ERC721 metadata — check if the bridge is designed for NFTs"
    - "Different tokenId encoding across chains is not a bug if properly mapped"
    - "One-way bridging may be intentional for some use cases (e.g., migration)"
  solodit_ids:
    - tokenbridgebridgetoken-allows-1-way-erc721-bridging-causing-users-to-permanently-lose-their-nfts-cyfrin-none-cyfrin-linea-markdown
    - m-05-failure-in-endpoint-can-cause-minting-more-than-one-nft-with-the-same-token-id-in-different-chains-code4rena-tigris-trade-tigris-trade-contest-git
    - a-user-can-steal-an-already-transfered-and-bridged-resdl-lock-because-of-approval-codehawks-stakelink-git
    - h-07-failed-job-cant-be-recovered-nft-may-be-lost-code4rena-holograph-holograph-contest-git
  incidentes:
    - protocol: "Ronin Bridge (Axie Infinity)"
      impact: "CRITICAL"
      detail: "Compromised validator keys allowed forged bridge messages, draining 173,600 ETH + 25.5M USDC ($625M) — largest bridge hack in history"
      date: "2022-03-23"
    - protocol: "Linea TokenBridge"
      firm: "Cyfrin"
      impact: "HIGH"
      detail: "bridgeToken allows one-way ERC721 bridging — users permanently lose NFTs with no return path"
      date: "2024"
    - protocol: "Holograph"
      firm: "Code4rena"
      impact: "HIGH"
      detail: "Failed cross-chain job can't be recovered — bridged NFT permanently lost"
      date: "2023"
    - protocol: "Tigris Trade"
      firm: "Code4rena"
      impact: "MEDIUM"
      detail: "LayerZero endpoint failure mints duplicate NFT with same tokenId on different chain"
      date: "2022"
  verificado: true
  confianza: alta
```

---

## Quick-Reference: Pattern Detection Cheatsheet

```
# GameFi reward token inflation
grep -rn "mint(\|_mint(" contracts/ | grep -v "test\|mock"
grep -rn "maxSupply\|MAX_SUPPLY\|totalSupply" contracts/
grep -rn "MINTER_ROLE\|onlyMinter\|hasRole" contracts/

# NFT attribute manipulation
grep -rn "reRoll\|reroll\|dnaToIndex\|fighterType\|createPhysicalAttributes" contracts/

# Claim reentrancy
grep -rn "_safeMint\|safeTransferFrom" contracts/ | grep -v "test"
grep -rn "claimRewards\|claim(" contracts/
grep -rn "nonReentrant\|reentrancyGuard" contracts/

# VRF/randomness
grep -rn "block.timestamp\|prevrandao\|blockhash\|requestRandomWords" contracts/
grep -rn "swapSource\|setRandomnessProvider\|fulfillRandomWords" contracts/

# Staking gaming (zero risk)
grep -rn "stakeAtRisk\|bpsLostPerLoss\|stakingFactor\|curStakeAtRisk" contracts/

# Rental guard bypass
grep -rn "setFallbackHandler\|setGuard\|enableModule\|checkTransaction" contracts/
grep -rn "delegatecall\|fallback()" contracts/

# Marketplace fee bypass
grep -rn "royaltyInfo\|_beforeTokenTransfer\|operatorFilterRegistry" contracts/

# NFT collateral wrong address
grep -rn "onERC721Received\|operator.*from\|collateralOwner" contracts/

# Cross-chain NFT
grep -rn "bridgeToken\|bridgeNFT\|_mintWrapped\|lockNFT" contracts/
grep -rn "messageHash\|nonce\|replayProtection" contracts/
```

---

## Cross-Reference Map

| Pattern | Related Briefings | Key Interaction |
|---------|------------------|-----------------|
| gfi-001 (reward inflation) | staking.md (staking-001, staking-002), token-erc20.md | Uncapped mint + DEX drain |
| gfi-002 (attribute manipulation) | nft-erc721.md (nft-003) | Wrong parameter = wrong stats |
| gfi-003 (claim reentrancy) | reentrancy-patterns.md, nft-erc721.md (nft-001) | _safeMint callback + state lag |
| gfi-004 (randomness) | oracle.md | VRF source mutability |
| gfi-005 (zero-risk staking) | staking.md (staking-001) | Integer division rounding |
| gfi-006 (rental hijack) | nft-erc721.md, access-control.md | Safe guard incomplete blacklist |
| gfi-007 (rental return block) | nft-erc721.md (nft-002) | Pausable token + external dependency |
| gfi-008 (spin counter) | — | Async VRF + missing decrement |
| gfi-009 (fee bypass) | nft-erc721.md | EIP-2981 informational only |
| gfi-010 (stake+list) | staking.md | Approval model vs custody model |
| gfi-011 (NFT liquidation) | lending.md, liquidation-mechanics.md, oracle.md | Floor price crash + cascade |
| gfi-012 (tournament gaming) | mev-sandwich.md | Information asymmetry |
| gfi-013 (economy arbitrage) | flash-loan.md, dex-amm.md | Multi-token rate mismatch |
| gfi-014 (wrong collateral credit) | nft-erc721.md (nft-003) | operator vs from confusion |
| gfi-015 (guild rug-pull) | access-control.md | Missing timelock on manager |
| gfi-016 (cross-chain NFT) | bridge.md, cross-chain-messaging.md | Message replay + one-way lock |
