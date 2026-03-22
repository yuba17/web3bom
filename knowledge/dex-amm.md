# DEX / AMM — Combat Briefing

> Everything an auditor needs before reading a DEX or AMM contract.
> Sources: universal/exploit_derived.json (INV-EXPLOIT-001, 005, 006, 016, 017, 021, 022), compositions/multi_actor.json (COMP-MULTI-001).

---

## 1. Bugs Conocidos

### 1.1 Constant Product Invariant Violation

```yaml
- id: dex-001
  pattern: constant-product-violation
  name: "Constant product (x*y=k) violated during swap or liquidity operation"
  causa_raiz: >
    The AMM's core invariant x*y=k (or its generalized form) must hold
    before and after every operation. Fee application errors, rounding
    in the wrong direction, or unchecked arithmetic in custom curves
    can cause k to decrease, allowing value extraction. Concentrated
    liquidity AMMs have per-tick invariants that are harder to verify.
  como_funciona: |
    1. Attacker finds a swap path where output amount is computed incorrectly
    2. Due to rounding favoring the user, k_after < k_before
    3. Repeated swaps in both directions extract the rounding difference
    4. OR: fee is subtracted from the wrong side of the equation,
       causing k to shrink by the fee amount on each swap
    5. Over thousands of swaps, LPs lose significant value
  invariante: "k_after >= k_before for every swap. Reserve product (on net reserves after fee deduction) must be monotonically non-decreasing. If fees stay in pool: k_after > k_before strictly (LP accrual). If fees exit pool separately: k_after == k_before (invariant preserved on net amounts). Never: k_after < k_before regardless of fee model."
  que_mirar:
    - "Is the invariant checked AFTER the swap, not just before?"
    - "Does fee application happen before or after the invariant check?"
    - "Is rounding direction consistent (always favor the pool)?"
    - "For concentrated liquidity: is the per-tick invariant maintained at boundaries?"
    - "Are flash swaps validated against the invariant on callback return?"
    - "Does the swap function use unchecked blocks for any math?"
  como_se_arregla: "Explicitly assert k_after >= k_before at the end of every swap. Round all intermediate calculations against the user. Apply fees before computing output amounts."
  trampas:
    - "Fees intentionally reduce output — k must increase by fee amount, not stay flat"
    - "Virtual reserves in concentrated liquidity mean k is per-range, not global"
    - "Rebasing tokens break the invariant naturally — pool must handle rebase"
  solodit_ids:
    - "m-05-the-constant-product-invariant-can-be-broken-code4rena-basin-basin-git"
    - "h-01-protocol-allows-creating-broken-tri-crypto-cpmm-pools-code4rena-mantra-mantra-git"
    - "h-11-stableswap-does-disjoint-swaps-breaking-the-underlying-invariant-code4rena-mantra-mantra-git"
    - "removeliquidity-logic-is-not-correct-for-generalized-well-functions-other-than-constantproduct-cyfrin-beanstalk-wells-markdown_"
  incidentes:
    - "MANTRA DEX -- Stableswap does disjoint swaps per isolated pair instead of full n-dimensional invariant curve, breaks stableswap invariant (HIGH)"
    - "MANTRA DEX -- Stableswap pool can be skewed free of fees via imbalanced deposits, effectively swapping without fee (HIGH)"
    - "TraderJoe -- Wrong calculation in LBRouter._getAmountsIn for JoePair V1 paths, excess tokens gifted to pair contract (HIGH)"
    - "Bunni v2 -- BunniSwapMath.computeSwap returns nonzero output with zero input, free tokens from rounding (HIGH)"
    - "Napier -- LP Tokens always valued at 3 PTs via hardcoded N_COINS=3, but Curve LP value increases over time (HIGH)"
    - "Cron Finance TWAMM -- Long-term swap proceeds lost when scaled proceeds overflow twice within order lifetime (HIGH)"
    - "Dango DEX -- Geometric pool passive order matching gives better prices to smaller swaps; splitting large swap into many small ones extracts value from passive LPs (HIGH)"
    - "Dango DEX -- XYK reflect_curve generates passive orders more favorable to takers than AMM curve, causing K to decrease over time (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-005 (rounding direction), INV-EXPLOIT-017 (integer overflow)"
  verificado: true
  tags: [constant-product, invariant, x-y-k, rounding, curve-math]
  relacionado_con: [dex-002, dex-003]
```

### 1.2 LP Token Mint/Burn Ratio Desync

```yaml
- id: dex-002
  pattern: lp-token-mint-burn-desync
  name: "LP token mint and burn produce inconsistent asset ratios"
  causa_raiz: >
    LP shares are minted proportional to the minimum ratio of deposited
    assets to reserves. If the burn formula uses a different calculation
    path, rounding direction, or does not account for accrued fees,
    mint-then-burn can extract value. First depositor attacks apply
    to LP tokens the same as ERC-4626 vaults.
  como_funciona: |
    1. Attacker deposits assets, receives LP tokens
    2. Due to different rounding in mint vs burn paths:
       mint rounds UP (user gets more shares) or burn rounds UP (user gets more assets)
    3. Attacker repeatedly mints and burns, extracting the rounding gap
    4. OR: first LP depositor donates to inflate LP share price (same as vault-001)
    5. Subsequent LPs receive 0 shares for their deposit
  invariante: "LP shares represent a pro-rata claim on pool reserves. Mint-then-immediate-burn must return <= deposited amount. No depositor should receive 0 shares for a non-dust deposit."
  que_mirar:
    - "Do mint and burn use the same formula (inverse of each other)?"
    - "Is there a MINIMUM_LIQUIDITY burn on first mint (UniV2 pattern)?"
    - "Does burn round DOWN (user receives less) and mint round DOWN (user receives fewer shares)?"
    - "Can LP tokens be minted with single-sided deposit? Different math path?"
    - "Is there a fee captured on mint/burn that could create asymmetry?"
  como_se_arregla: "Ensure mint and burn are strict mathematical inverses. Burn MINIMUM_LIQUIDITY on first mint. Round both operations against the user. Audit single-sided deposit math separately."
  trampas:
    - "UniV2 MINIMUM_LIQUIDITY (1000 wei) prevents first-depositor attack"
    - "Fee-on-transfer tokens cause natural desync — protocol must use actual received amounts"
    - "Imbalanced deposits in multi-asset pools intentionally cost more (swap fee applies)"
  solodit_ids: []
  incidentes:
    - "NUTS Finance SelfPeggingAsset -- First depositor inflation attack: 1 wei deposit + donation bypasses minMintAmount, victim gets 0 shares (CRITICAL)"
    - "Caviar -- First depositor breaks minting: donate to inflate share price, subsequent LPs get 0 tokens (HIGH)"
    - "Maple Finance -- First pool depositor front-run: attacker deposits 1 wei + donates 1M USDC, steals 0.5M from victim (HIGH)"
    - "Beanstalk Basin -- removeLiquidity logic only correct for ConstantProduct, other Well functions produce incorrect LP burn amounts (HIGH)"
    - "Cron Finance TWAMM -- LP join can be sandwiched: only min(ratio) used for LP mint, excess of one token not returned (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-002 (share inflation), INV-EXPLOIT-005 (rounding direction)"
  verificado: true
  tags: [LP-token, mint-burn, share-inflation, first-depositor, rounding]
  relacionado_con: [dex-001, dex-003]
```

### 1.3 Price Impact Manipulation (Thin Liquidity)

```yaml
- id: dex-003
  pattern: thin-liquidity-price-manipulation
  name: "Price manipulation via low liquidity pools used as oracles"
  causa_raiz: >
    Protocols that read spot price from AMM pools (via getReserves or
    slot0) are vulnerable when pool liquidity is thin. A flash loan
    can move the price by orders of magnitude in a single transaction.
    Any downstream protocol using that price for valuation, liquidation,
    or minting is exploitable.
  como_funciona: |
    1. Attacker takes flash loan of token A
    2. Swaps large amount of A into thin pool, crashing price of A (or inflating B)
    3. Downstream protocol reads manipulated spot price
    4. Attacker borrows/mints/liquidates at distorted price
    5. Attacker reverses the swap, repays flash loan, keeps profit
    6. Pool price returns to normal after the transaction
  invariante: "Spot price must not deviate from TWAP by more than MAX_DEVIATION_PCT (INV-EXPLOIT-001). Pool liquidity must exceed MIN_LIQUIDITY_THRESHOLD before trusting price (INV-EXPLOIT-021)."
  que_mirar:
    - "Does the protocol read spot price (getReserves, slot0) or TWAP?"
    - "What is the liquidity depth of the price source pool?"
    - "How much capital is needed to move price by 10%? By 50%?"
    - "Is there a deviation check between spot and TWAP?"
    - "Is the price source on the same chain (flash-loanable)?"
    - "Are there minimum liquidity requirements before enabling a market?"
  como_se_arregla: "Use TWAP oracles with sufficient observation window (30+ minutes). Cross-validate against Chainlink or other independent sources. Enforce minimum pool liquidity. Never use slot0 or getReserves for spot price in critical calculations."
  trampas:
    - "High liquidity pools (>$10M TVL) are expensive to manipulate for spot reads"
    - "TWAP with short window (< 10 min) is still manipulable across multiple blocks"
    - "Chainlink with proper staleness checks is generally safe"
  solodit_ids:
    - "on-chain-slippage-calculation-using-exchange-rate-derived-from-poolslot0-can-be-easily-manipulated-cyfrin-none-cyfrin-thermae-markdown"
    - "slippage-vulnerability-in-primex-protocol-for-swap-and-spot-trade-positions-quantstamp-primex-finance-markdown"
    - "m-01-twap-price-manipulation-pashov-audit-group-none-titanx-markdown"
    - "m-08-twap-can-be-manipulated-pashov-audit-group-none-ulti-november-markdown"
  incidentes:
    - "Connext SponsorVault -- Spot AMM price used for swap, attacker sandwiches to drain all native tokens from sponsor vault (CRITICAL)"
    - "Connext -- getPriceFromDex derives price with balanceOf instead of getReserves, manipulable via donation (HIGH)"
    - "Isomorph -- Velodrome pool routing: attacker manipulates secondary pool price to prevent liquidations (HIGH)"
    - "Olympusdao -- Single-sided vault deposit/withdraw exploitable: deposit-buy-withdraw cycle extracts value from IL (HIGH)"
    - "Tigris Trade -- StableVault treats all stablecoins as 1:1 but they have varying prices, arbitrageable with flash loans (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-001, INV-EXPLOIT-021, INV-EXPLOIT-006"
  verificado: true
  tags: [price-manipulation, thin-liquidity, flash-loan, oracle, spot-price, TWAP]
  relacionado_con: [dex-005, dex-006]
```

### 1.4 Sandwich Attack Amplification

```yaml
- id: dex-004
  pattern: sandwich-attack-amplification
  name: "Sandwich attack amplified by missing slippage or fee miscalculation"
  causa_raiz: >
    A sandwich attacker front-runs a victim swap to move the price,
    then back-runs to capture the difference. Protocols amplify this
    when they hardcode amountOutMin to 0, omit deadline checks, or
    have fee structures that don't penalize large price impacts.
    Router contracts that set slippage on behalf of users are
    especially dangerous.
  como_funciona: |
    1. Victim submits swap with amountOutMin = 0 (or protocol sets it)
    2. Attacker front-runs: buys token B, pushing price up
    3. Victim's swap executes at inflated price, receives minimal output
    4. Attacker back-runs: sells token B at higher price
    5. Profit = price impact caused by victim's trade
    6. If protocol hardcodes 0 slippage, every swap is sandwichable
  invariante: "amountOut >= amountOutMin AND amountOutMin > 0 (INV-EXPLOIT-016). Attacker must not profit from sandwiching (COMP-MULTI-001)."
  que_mirar:
    - "Does the protocol pass amountOutMin from user input or hardcode it?"
    - "Is amountOutMin ever set to 0 in the codebase?"
    - "Does the router calculate slippage internally from oracle price?"
    - "Are there swap aggregator integrations that lose user slippage params?"
    - "Is there dynamic fee adjustment based on price impact?"
  como_se_arregla: "Always pass user-specified amountOutMin through to the DEX call. Never hardcode to 0. Calculate a reasonable minimum from oracle price as a safety floor. Use Flashbots Protect or private mempools where available."
  trampas:
    - "Private mempools (Flashbots) partially mitigate but do not eliminate risk"
    - "Protocols computing slippage from oracle price internally may be acceptable"
    - "L2s with sequencer ordering have reduced but nonzero sandwich risk"
  solodit_ids:
    - "m-1-mev-bots-will-steal-from-users-due-to-an-incorrectly-manipulated-value-sherlock-peapods-git"
    - "missing-slippage-protection-on-syncswap-swaps-cantina-none-clave-pdf"
    - "harvesterharvest-swaps-have-no-slippage-parameters-consensys-brahma-fi-markdown"
    - "no-slippage-protection-on-uniswapv2-interactions-halborn-klimadao-klimadao-autocompounder-markdown"
  incidentes:
    - "Gacha Protocol -- _swap() computes minTokens on-chain from getAmountOut, 5% tolerance is meaningless against sandwich (HIGH)"
    - "Derby Vault -- claimTokens() and withdrawRewards() use IQuoter on-chain for slippage calculation, sandwichable (HIGH)"
    - "Blueberry IchiSpell -- withdrawals use MIN/MAX_SQRT_RATIO as sqrtPriceLimitX96, no real slippage protection (MEDIUM)"
    - "Asymmetry Finance VotiumStrategy -- buyCvx/sellCvx call Curve exchange_underlying with min_dy=0 (HIGH)"
    - "Olympus BLVault -- minTokenAmounts_ applied to pool exit but treasury skims wstETH, user has no slippage protection on net received (HIGH)"
    - "Spartan Protocol -- All AMM functions have no minAmountOut parameter, 100% sandwichable (HIGH)"
    - "Carapace -- accruePremiumAndExpireProtections() sandwichable, deposit-before/withdraw-after steals premium (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-016, COMP-MULTI-001"
  verificado: true
  tags: [sandwich, MEV, slippage, amountOutMin, front-run, back-run]
  relacionado_con: [dex-003, dex-007, dex-008]
```

### 1.5 TWAP Oracle Manipulation

```yaml
- id: dex-005
  pattern: twap-oracle-manipulation
  name: "TWAP oracle manipulated via sustained multi-block attack"
  causa_raiz: >
    TWAP is resistant to single-block manipulation but vulnerable to
    sustained attacks across multiple blocks. An attacker who can
    maintain a price distortion for N blocks (where N is a significant
    fraction of the TWAP window) can move the TWAP. Short observation
    windows (< 10 minutes) are especially vulnerable. Uniswap V3 TWAP
    uses geometric mean, which is more resistant but not immune.
  como_funciona: |
    1. Attacker moves pool price via large swap at block N
    2. Price remains distorted for blocks N+1 through N+M
    3. Each block the distorted price accumulates into the TWAP
    4. After M blocks, TWAP has moved enough to exploit downstream protocol
    5. Attacker triggers action in downstream protocol using manipulated TWAP
    6. Attacker reverses position, TWAP slowly recovers
  invariante: "TWAP observation window must be long enough that attack capital exceeds extractable profit. Price accumulator must use safe math (no overflow in cumulative price)."
  que_mirar:
    - "What is the TWAP observation window? (< 30 min is high risk)"
    - "Is it arithmetic mean (V2) or geometric mean (V3)?"
    - "Can the observation array be manipulated (uninitialized observations)?"
    - "What is the cost to maintain price distortion for the window duration?"
    - "Does the protocol validate TWAP freshness (observations exist for full window)?"
    - "Are there cardinality requirements (minimum observations initialized)?"
  como_se_arregla: "Use 30+ minute observation windows. Use V3 geometric mean TWAP (harder to manipulate). Cross-validate with Chainlink. Ensure sufficient observation cardinality. Reject TWAP if not enough historical observations exist."
  trampas:
    - "V3 geometric TWAP is much harder to manipulate than V2 arithmetic TWAP"
    - "On L2s with 2-second blocks, 30 minutes = 900 observations (high cardinality needed)"
    - "New pool with few observations may return unreliable TWAP — check initialization"
  solodit_ids:
    - "m-01-twap-price-manipulation-pashov-audit-group-none-titanx-markdown"
    - "m-08-twap-can-be-manipulated-pashov-audit-group-none-ulti-november-markdown"
    - "h-2-strategy-main-ticks-are-set-according-to-the-tick-in-slot0-leading-to-incorrect-allocation-and-loss-of-funds-sherlock-yieldoor-git"
    - "h-01-reallocation-depends-on-the-slot0-price-which-can-be-manipulated-code4rena-predy-predy-git"
  incidentes:
    - "Sentiment Update 2 -- Curve LP virtual_price manipulated via read-only reentrancy during remove_liquidity, triggers false liquidations (HIGH)"
    - "Notional -- Attacker flash-loans to bypass BPT threshold, triggers emergency settlement to DOS vault (MEDIUM)"
  severidad: critical
  confianza: media
  fuente: "INV-EXPLOIT-001, INV-EXPLOIT-021"
  verificado: true
  tags: [TWAP, oracle, multi-block, observation-window, geometric-mean]
  relacionado_con: [dex-003, dex-006, oracle-003]
```

### 1.6 Concentrated Liquidity Tick Boundary Errors

```yaml
- id: dex-006
  pattern: tick-boundary-error
  name: "Concentrated liquidity tick boundary crossing errors"
  causa_raiz: >
    Concentrated liquidity AMMs (Uniswap V3 style) maintain liquidity
    per tick range. When a swap crosses a tick boundary, the active
    liquidity must be updated. Errors in tick crossing logic — wrong
    direction of liquidity delta, off-by-one in tick index, or overflow
    in per-tick accounting — cause incorrect swap outputs. The KyberSwap
    exploit exploited tick boundary math for $46M.
  como_funciona: |
    1. Attacker crafts a swap that lands exactly on a tick boundary
    2. Tick crossing logic miscalculates: adds liquidity instead of removing,
       or applies delta in wrong direction
    3. Pool believes it has more liquidity than it does
    4. Subsequent swaps get better prices than they should
    5. Attacker extracts the difference via arbitrage
    6. OR: integer overflow in tick math at extreme tick values
  invariante: "Liquidity delta applied on upward tick crossing must be opposite of downward crossing. Sum of all active liquidity must equal sum of position liquidities in the active range."
  que_mirar:
    - "Does tick crossing add or subtract liquidityNet correctly based on direction?"
    - "Is there an off-by-one in tickLower/tickUpper boundaries (< vs <=)?"
    - "What happens at MIN_TICK and MAX_TICK?"
    - "Does the math overflow when sqrtPriceX96 approaches extremes?"
    - "Are initialized tick bitmaps handled correctly across word boundaries?"
    - "Is tick spacing enforced consistently?"
  como_se_arregla: "Follow Uniswap V3 reference implementation exactly for tick crossing. Test extensively at boundary conditions. Use formal verification for tick math. Fuzz with swaps that cross multiple ticks."
  trampas:
    - "Most protocols fork Uniswap V3 exactly — bugs are in the modifications"
    - "Custom tick spacing or fee tiers may introduce new boundary conditions"
    - "Single-tick swaps (no crossing) are generally safe"
  solodit_ids:
    - "limit-orders-can-be-incorrectly-filled-openzeppelin-none-openzeppelin-uniswap-hooks-v110-rc-1-audit-markdown"
    - "accrued-limit-order-fees-can-be-stolen-openzeppelin-none-openzeppelin-uniswap-hooks-v110-rc-1-audit-markdown"
    - "h-2-strategy-main-ticks-are-set-according-to-the-tick-in-slot0-leading-to-incorrect-allocation-and-loss-of-funds-sherlock-yieldoor-git"
  incidentes:
    - "Yieldoor -- Strategy main ticks set from slot0 tick which is off-by-one at tick boundaries, asymmetric position loses fees (HIGH)"
    - "Ouroboros UniswapV3Staker -- Full-range incentive makes concentrated LPs forfeit 99%+ of swap fees for minimal rewards (HIGH)"
    - "Sorella L2 Angstrom -- When current tick is exact multiple of tick spacing at upper bound, tick iterator skips boundary tick liquidity delta; enables complete reward theft (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-017 (KyberSwap $46M), INV-EXPLOIT-005 (rounding)"
  verificado: true
  tags: [concentrated-liquidity, tick-boundary, UniV3, sqrtPrice, liquidityNet]
  relacionado_con: [dex-001, dex-003]
```

### 1.7 Swap Deadline Missing

```yaml
- id: dex-007
  pattern: missing-swap-deadline
  name: "Swap transaction has no meaningful deadline parameter"
  causa_raiz: >
    If the deadline parameter is set to block.timestamp (always passes)
    or type(uint256).max, validators can hold the transaction in the
    mempool and execute it later when the price has moved against the
    user. This is equivalent to giving the validator a free option on
    the swap.
  como_funciona: |
    1. User submits swap with deadline = block.timestamp
    2. Validator sees profitable price movement developing
    3. Validator holds transaction for N blocks
    4. Price moves 5% against the user
    5. Validator includes the transaction — it passes deadline check
       (block.timestamp is always "now")
    6. User receives significantly less than expected
  invariante: "deadline > block.timestamp AND deadline < block.timestamp + MAX_WINDOW AND deadline != type(uint256).max (INV-EXPLOIT-022)."
  que_mirar:
    - "Is deadline passed through from user input to the DEX router?"
    - "Is block.timestamp used as deadline anywhere? (grep for 'block.timestamp' near swap calls)"
    - "Is type(uint256).max used as deadline?"
    - "Does the protocol set deadline internally? What value?"
    - "Are there any swap paths that bypass the deadline check?"
  como_se_arregla: "Always use a user-specified deadline representing current time + acceptable delay (e.g., 300 seconds). Never use block.timestamp as deadline. Validate deadline is reasonable (not max uint)."
  trampas:
    - "On L2s with sequencer ordering, deadline risk is reduced (sequencer chooses order)"
    - "Private mempool transactions cannot be held by validators"
    - "Some protocols have their own expiry mechanism separate from DEX deadline"
  solodit_ids: []
  incidentes:
    - "Hyperhyper -- PositionInteractionFacet sets deadline = block.timestamp + 30 minutes, MEV bots can hold and execute later (MEDIUM)"
    - "Backed Protocol PaprController -- buyAndReduceDebt and startLiquidationAuction have no deadline parameter for UniV3 swaps (MEDIUM)"
    - "Caviar -- All Pair.sol functions (buy, sell, add, remove) have no deadline check (MEDIUM)"
    - "Amun -- SingleTokenJoinV2._joinTokenSingle and SingleNativeTokenExitV2._exit use block.timestamp instead of user deadline (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "INV-EXPLOIT-022"
  verificado: true
  tags: [deadline, block-timestamp, validator, MEV, stale-transaction]
  relacionado_con: [dex-004, dex-008]
```

### 1.8 Slippage Protection Bypass

```yaml
- id: dex-008
  pattern: slippage-protection-bypass
  name: "Slippage protection is present but bypassable"
  causa_raiz: >
    Unlike missing slippage (dex-004), this pattern covers cases where
    slippage protection exists but can be circumvented. The check may
    be on the wrong variable (intermediate amount instead of final
    output), applied after fees are deducted, or bypassable via
    a different code path (multicall, flash swap callback).
  como_funciona: |
    1. Protocol checks amountOut >= minAmountOut
    2. But amountOut is computed BEFORE protocol fee deduction
    3. After fee, actual received amount is less than minAmountOut
    4. User receives less than their specified minimum
    5. OR: multicall batches swap + other operations,
       slippage check is on individual swap but not on net outcome
    6. OR: callback-based swaps (V3 style) apply slippage in the callback
       but attacker can manipulate state between swap and callback
  invariante: "Final amount received by user (after ALL fees and transfers) >= user-specified minimum. Slippage check must be on the terminal output, not an intermediate value."
  que_mirar:
    - "Is slippage checked on gross or net output (after fees)?"
    - "In multicall: is there a net slippage check across all operations?"
    - "In callback swaps: when is slippage validated relative to the callback?"
    - "Can fee-on-transfer tokens cause post-check balance to be lower?"
    - "Is there a code path that skips the slippage check entirely?"
    - "For multi-hop swaps: is slippage on final output or per-hop?"
  como_se_arregla: "Check slippage on the FINAL token balance change of the user, not intermediate amounts. For multicall, add an aggregate slippage check. Account for fee-on-transfer tokens by checking actual received balance."
  trampas:
    - "Per-hop slippage in multi-hop swaps is overly restrictive and may cause reverts"
    - "Fee-on-transfer tokens legitimately reduce received amount below expected"
    - "Some aggregators handle slippage at the aggregator level, not the DEX level"
  solodit_ids:
    - "on-chain-slippage-calculation-using-exchange-rate-derived-from-poolslot0-can-be-easily-manipulated-cyfrin-none-cyfrin-thermae-markdown"
    - "h-1-lack-of-slippage-protection-leads-to-loss-of-protocol-funds-sherlock-cork-protocol-git"
    - "lack-of-slippage-protection-in-liquidity-provision-cantina-none-marginal-pdf"
  incidentes:
    - "Notional Update 2 -- Settlement slippage minPrimary/minSecondary auto-computed and overwritten, caller's values ignored (HIGH)"
    - "Notional Update 2 -- Proportional redemption minExitAmounts set so low they provide no real protection (HIGH)"
    - "Connext -- Same slippageTol used for source and destination swaps, cannot protect both (MEDIUM)"
    - "Connext -- User cannot override slippage on destination if execute() runs before forceUpdateSlippage() (MEDIUM)"
    - "Uniswap V4 Periphery -- validateMaxInNegative skips slippage check when fee-rich positions make net delta positive; user overpays for increased liquidity (HIGH)"
  severidad: high
  confianza: alta
  fuente: "INV-EXPLOIT-016, INV-EXPLOIT-008 (fee mismatch)"
  verificado: true
  tags: [slippage, bypass, fee-deduction, multicall, net-output]
  relacionado_con: [dex-004, dex-007]
```

---

## 2. Cross-Cutting Patterns from Exploit Registry

### 2.1 Flash Loan + AMM State Manipulation

```yaml
- id: dex-009
  pattern: flash-loan-amm-state
  name: "Flash loan amplifies AMM price or reserve manipulation"
  causa_raiz: >
    Flash loans provide unlimited capital within a single transaction.
    Any AMM state variable readable and writable in the same transaction
    is exploitable. This includes reserves, sqrtPrice, accumulated fees,
    and liquidity counters.
  como_funciona: |
    1. Attacker flash borrows massive amount of token A
    2. Swaps into AMM, moving price and reserves drastically
    3. Downstream protocol reads manipulated AMM state
    4. Attacker extracts value from downstream protocol
    5. Reverses swap, repays flash loan
    6. Net profit = value extracted from downstream minus flash loan fee
  invariante: "Critical state variables must not be writable and readable in the same block for pricing purposes (INV-EXPLOIT-006)."
  que_mirar:
    - "Can reserves/price be read and manipulated in the same transaction?"
    - "Does the AMM expose sync() or skim() that can be abused?"
    - "Are there any downstream protocols using this AMM for pricing?"
    - "Is there a same-block guard on reserve reads?"
  como_se_arregla: "Use TWAP or commit-reveal for price reads. Implement same-block manipulation guards. Do not use reserve ratios as spot price for critical calculations."
  trampas:
    - "Flash swaps within the AMM itself are normal — the concern is downstream consumers"
    - "High-fee pools make manipulation more expensive but not impossible"
  solodit_ids: []
  incidentes:
    - "Sentiment Update 2 -- Curve LP virtual_price manipulated via read-only reentrancy during remove_liquidity, triggers false liquidations (HIGH)"
    - "Notional -- Attacker flash-loans to bypass BPT threshold, triggers emergency settlement to DOS vault (MEDIUM)"
    - "Notional -- Attacker enters vault without borrowing (no fee), front-runs reinvestReward, exits with stolen rewards (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-006, INV-EXPLOIT-001, INV-EXPLOIT-021"
  verificado: true
  tags: [flash-loan, reserves, state-manipulation, same-transaction, atomic]
  relacionado_con: [dex-003, dex-005]
```

### 2.2 Fee Accounting Mismatch

```yaml
- id: dex-010
  pattern: fee-accounting-mismatch
  name: "Fee computed in wrong units or applied inconsistently across paths"
  causa_raiz: >
    AMMs compute fees in basis points but consume them in token amounts
    (or vice versa). If the fee is applied to the input on one path
    but to the output on another, arbitrageurs can route through the
    cheaper path. Concentrated liquidity fee growth tracking per tick
    adds complexity and additional failure modes.
  como_funciona: |
    1. Path A: fee applied to input amount (standard)
    2. Path B: fee applied to output amount (cheaper for large trades)
    3. Arbitrageur routes through path B, paying less fee
    4. OR: fee shares (protocol fee, LP fee, referral) sum to > 100%
    5. Transaction reverts or underflows on fee deduction
    6. OR: feeGrowthGlobal overflows at extreme accumulated values
  invariante: "Total fee deducted <= transfer amount. Fee percentages sum <= 100%. Fee calculation unit matches consumption unit (INV-EXPLOIT-008)."
  que_mirar:
    - "Is fee applied to input or output? Is it consistent across all swap paths?"
    - "Do fee shares (protocol, LP, referral) sum to <= 10000 bps?"
    - "Can fee parameters be set to values that cause underflow?"
    - "Does feeGrowthGlobal use unchecked math? Can it overflow?"
    - "Are fees in the same denomination as the amounts they're deducted from?"
  como_se_arregla: "Apply fees consistently to the same side (input recommended). Validate fee parameter bounds on set. Use unchecked only with explicit overflow handling for fee accumulators."
  trampas:
    - "UniV3 feeGrowthGlobal intentionally wraps (overflow by design) — this is not a bug"
    - "Dynamic fees that change per-block are not a mismatch if applied consistently"
  solodit_ids:
    - "m-2-rounding-error-when-call-function-dodomultiswap-can-lead-to-revert-of-transaction-or-fund-of-user-sherlock-dodo-dodo-git"
    - "m-21-incorrect-rounding-in-computeswap-code4rena-bunni-august-bunni-august-git"
    - "m-1-pairs-with-max_fee-can-revert-due-to-rounding-inconsistencies-sherlock-rubicon-rubicon-finance-git"
    - "buck-takes-swap-fee-on-lp-operations-spearbit-none-buck-labs-pdf"
  incidentes:
    - "Velodrome Finance -- getAmountIn hardcodes 0.3% fee but pools have factory-set custom fees, math is wrong (MEDIUM)"
    - "Alchemix RevenueHandler -- Curve pool exchange_underlying min_dy misunderstood, precision loss enables sandwich on protocol funds (HIGH)"
    - "Backed Protocol PaprController -- buyAndReduceDebt swap fee paid by contract not user, DoS when contract has no balance (MEDIUM)"
    - "Vultisig ILOPool -- pool.collect() claims ALL Uniswap fees for all positions at once, first claimer gets everything (HIGH)"
  severidad: high
  confianza: alta
  fuente: "INV-EXPLOIT-008, INV-EXPLOIT-005"
  verificado: true
  tags: [fee, basis-points, unit-mismatch, fee-growth, overflow]
  relacionado_con: [dex-001, dex-008]

- id: dex-011
  pattern: on-chain-slippage-calculation
  name: "Slippage calculated on-chain from current pool state is useless"
  causa_raiz: >
    Protocol computes minAmountOut by querying the pool's current reserves
    (e.g., via Quoter, getAmountOut, or getReserves) in the SAME transaction
    as the swap. Since an attacker can manipulate reserves before the query,
    the computed minimum tracks the manipulated price, providing zero protection.
  como_funciona: |
    1. Protocol calls quoter.quoteExactInput() or router.getAmountOut() on-chain
    2. Applies a small percentage (e.g., 5%) as "slippage tolerance" to the result
    3. Uses this value as minAmountOut in the subsequent swap
    4. Attacker front-runs: swaps to move the price 30%
    5. Protocol's on-chain query returns the manipulated (lower) price
    6. Protocol sets minAmountOut to 95% of the ALREADY BAD price
    7. Swap executes at manipulated price, passing the useless slippage check
    8. Attacker back-runs to reverse, capturing the full spread
  invariante: "assert(amountOut >= userSpecifiedMinOut) where userSpecifiedMinOut is provided off-chain, NOT computed on-chain from pool state"
  que_mirar:
    - "getAmountOut.*reserve"
    - "quoteExactInput"
    - "quoter"
    - "minTokens.*getAmountOut"
    - "minAmountOut.*calculated"
    - "amountOutMinimum.*IQuoter"
  como_se_arregla: "minAmountOut MUST be calculated off-chain (frontend) using an independent price source and passed as a function parameter. Never derive slippage from the same pool being swapped."
  trampas:
    - "Using an oracle price on-chain to compute minAmountOut is acceptable if the oracle is manipulation-resistant (e.g., Chainlink)"
    - "On-chain TWAP-based slippage is ok if the TWAP window is long enough (30+ min)"
  solodit_ids:
    - "on-chain-slippage-calculation-using-exchange-rate-derived-from-poolslot0-can-be-easily-manipulated-cyfrin-none-cyfrin-thermae-markdown"
    - "h-1-lack-of-slippage-protection-leads-to-loss-of-protocol-funds-sherlock-cork-protocol-git"
  incidentes:
    - "Gacha Protocol -- _swap() calculates minTokens from getAmountOut on-chain, 5% slippage tolerance is meaningless (HIGH)"
    - "Derby -- Vault.claimTokens() and MainVault.withdrawRewards() use IQuoter on-chain for slippage, sandwichable (HIGH)"
    - "Blueberry Update -- IchiSpell uses sqrtPriceLimitX96 instead of proper minAmountOut, partial swaps result (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, amm, slippage, on-chain-calculation, sandwich, quoter, getAmountOut]

- id: dex-012
  pattern: reserve-order-mismatch
  name: "Uniswap V2 reserve order assumed but not validated"
  causa_raiz: >
    UniswapV2Pair.getReserves() returns (reserve0, reserve1) where token0
    is the numerically smaller address. Protocols that call getReserves()
    and assume a fixed token ordering (e.g., WETH is always reserve0) will
    swap reserve values when the assumption is wrong, producing incorrect
    price calculations, wrong swap amounts, or DoS.
  como_funciona: |
    1. Protocol calls pair.getReserves() and assigns (wethReserve, tokenReserve)
    2. But pair.token0() may be the other token if its address is smaller
    3. reserve0 and reserve1 are swapped relative to protocol's expectation
    4. getAmountOut is called with wrong reserveIn/reserveOut
    5. Result: wildly incorrect output amount, or minTokens so high the swap reverts
    6. If minTokens ends up too LOW, attacker extracts the difference via sandwich
  invariante: "assert(token0 == pair.token0() ? reserve0 : reserve1 == expectedReserveForToken0)"
  que_mirar:
    - "getReserves()"
    - "wethReserve.*tokenReserve"
    - "reserve0.*reserve1"
    - "getPair"
    - "token0()"
  como_se_arregla: "Always call pair.token0() to determine which reserve corresponds to which token. Sort token addresses before assigning reserves."
  trampas:
    - "On some chains/forks, WETH address may happen to be token0 in test pairs but not in production"
  solodit_ids: []
  incidentes:
    - "Gacha Protocol -- _swap() assigns (wethReserve, tokenReserve) without checking token0 ordering (CRITICAL)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v2, reserve-order, token0, getReserves, address-sorting]

- id: dex-013
  pattern: hardcoded-fee-in-router
  name: "Router uses hardcoded fee but pool has custom/dynamic fees"
  causa_raiz: >
    Router or library math assumes a fixed fee (e.g., UniV2's 0.3% = 997/1000)
    but the actual pool charges a different or dynamic fee set via the factory.
    This mismatch causes getAmountIn/getAmountOut to return incorrect values,
    either overcharging users or enabling fee-free arbitrage paths.
  como_funciona: |
    1. Router's getAmountIn hardcodes fee as 997/1000 (0.3%)
    2. Pool's actual fee is set via factory.getFee() and may be 0.01% to 1%
    3. If pool fee > hardcoded fee: router quotes less input than needed, swap may revert or produce partial fill
    4. If pool fee < hardcoded fee: router quotes more input than needed, user overpays
    5. Arbitrageur exploits the discrepancy to extract value
  invariante: "assert(routerFee == pool.actualFee) for every supported pool"
  que_mirar:
    - "997"
    - "1000"
    - "10000"
    - "getAmountOut.*hardcoded"
    - "getFee"
    - "swapFee"
    - "poolFee"
  como_se_arregla: "Query the pool's actual fee from the factory at runtime. Pass pool and factory references to getAmountIn/getAmountOut functions."
  trampas:
    - "Standard UniV2 forks with immutable 0.3% fee are not affected"
    - "Velodrome, Solidly, and similar forks commonly have variable fees"
  solodit_ids: []
  incidentes:
    - "Velodrome Finance -- UniswapV2Library.getAmountIn hardcodes 997 fee but pools have custom fees via factory (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, fee, hardcoded, router, getAmountIn, factory, dynamic-fee]

- id: dex-014
  pattern: reward-distribution-frontrun
  name: "Reward/fee distribution frontrunnable via deposit-claim-withdraw"
  causa_raiz: >
    Protocol distributes rewards or fees by updating a per-share accumulator
    (pointsPerShare, feeIntegral) in a single lump-sum transaction. An attacker
    who deposits a large amount just before the distribution captures a
    disproportionate share of rewards, then withdraws immediately after.
    This is the DEX equivalent of the vault donation attack applied to
    staking/LP reward pools.
  como_funciona: |
    1. Admin/keeper calls distributeRewards() or accruePremium() to add N reward tokens
    2. pointsPerShare increases by N / totalStaked in a single block
    3. Attacker front-runs: deposits massive amount, taking 50%+ of pool
    4. Distribution executes: attacker earns 50%+ of newly added rewards
    5. Attacker back-runs: withdraws stake + claimed rewards
    6. Net: attacker stole majority of rewards intended for long-term stakers
  invariante: "assert(rewardPerTokenIncreasePerBlock <= maxRewardRate) -- rewards must drip over time, not lump-sum"
  que_mirar:
    - "distributeRewards"
    - "depositFees"
    - "feeIntegral"
    - "pointsPerShare"
    - "accruePremium"
    - "rewardPerToken"
  como_se_arregla: "Use a rewardRate-based gradual release model (e.g., Synthetix StakingRewards pattern). Distribute rewards over a time window, not instantaneously. Enforce minimum lock duration."
  trampas:
    - "MIN_LOCK_DURATION > 1 block mitigates flash loan but not well-funded attackers"
    - "Synthetix-style drip over 7 days is generally safe"
  solodit_ids: []
  incidentes:
    - "Merit Circle -- front-run distributeRewards() to steal newly added rewards (MEDIUM)"
    - "Backd -- BkdLocker.depositFees() lump-sum distribution frontrunnable (MEDIUM)"
    - "Rubicon -- BathPair.rebalancePair() creates share price surge exploitable by front-run (HIGH)"
    - "Carapace -- accruePremiumAndExpireProtections() sandwichable for instant profit (HIGH)"
    - "OpenZeppelin Uniswap Hooks -- LimitOrderHook accrued fees stolen by large last-minute LP (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, rewards, frontrun, deposit-withdraw, pointsPerShare, staking, fee-distribution]
  relacionado_con: [dex-001, dex-008, staking-002]

- id: dex-015
  pattern: lp-token-sold-during-reinvest
  name: "LP/BPT tokens accidentally sold during reward reinvestment"
  causa_raiz: >
    Vault reinvest/compound functions swap reward tokens for underlying assets.
    The token validation (_isInvalidRewardToken) fails to exclude the pool's own
    LP/BPT tokens, allowing them to be accidentally or maliciously sold during
    the reinvestment process. Since LP tokens represent the vault's total value,
    selling them drains the vault.
  como_funciona: |
    1. Vault holds LP/BPT tokens representing its pool position
    2. Reward claim produces CRV, CVX, BAL, etc.
    3. Reinvest function swaps reward tokens to underlying
    4. Token validation does not exclude LP/BPT from sellable tokens
    5. Attacker (or misconfigured keeper) sells LP/BPT tokens as if they were rewards
    6. Vault loses its pool position, shareholders lose funds
  invariante: "assert(_isInvalidRewardToken(lpToken) == true) -- LP/BPT must never be sold"
  que_mirar:
    - "_isInvalidRewardToken"
    - "reinvestReward"
    - "compound"
    - "CURVE_POOL_TOKEN"
    - "BPT"
    - "sweep"
    - "sellToken"
  como_se_arregla: "Explicitly add LP/BPT tokens to the _isInvalidRewardToken blocklist. For sweep functions, exclude pool tokens. Use an allowlist of sellable tokens rather than a blocklist."
  trampas:
    - "Composable Balancer pools include BPT in the pool tokens array -- easy to miss"
    - "Protocol tokens that also serve as LP tokens (e.g., Curve LP = pool token)"
  solodit_ids: []
  incidentes:
    - "Notional Update 4 -- AuraStakingMixin._isInvalidRewardToken does not exclude BPT, can be sold during reinvestment (MEDIUM)"
    - "Gauntlet/Aera Vault -- sweep() allows Treasury to withdraw pool BPTs, bypassing all safeguards (CRITICAL)"
    - "Notional Update 2 -- EXACT_IN_BATCH allows arbitrary route, reward tokens or Convex deposit tokens can be sold (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, vault, reinvest, lp-token, bpt, reward, sweep, token-validation]

- id: dex-016
  pattern: read-only-reentrancy-lp-price
  name: "Read-only reentrancy manipulates LP token price during callback"
  causa_raiz: >
    Curve/Balancer pools send ETH (via .call) during remove_liquidity before
    updating internal state. A callback during the ETH transfer can read stale
    pool state (virtual_price, getRate, balances) that temporarily shows an
    incorrect value. Any protocol that reads pool price during this window
    gets a manipulated value.
  como_funciona: |
    1. Attacker calls pool.remove_liquidity() with ETH involved
    2. Pool sends ETH to attacker's contract via .call{value: ...}
    3. Attacker's receive() callback triggers before pool updates internal balances
    4. During callback, pool.get_virtual_price() returns stale (suppressed) value
    5. Downstream protocol reads manipulated virtual_price for collateral valuation
    6. Attacker triggers liquidation of healthy positions at suppressed price
    7. Pool finishes remove_liquidity, virtual_price returns to normal
  invariante: "assert(virtualPrice == expectedVirtualPrice within tolerance) OR use reentrancy guard on view functions"
  que_mirar:
    - "get_virtual_price"
    - "getRate"
    - "remove_liquidity"
    - "receive()"
    - "fallback()"
    - "raw_call"
  como_se_arregla: "Use Balancer's reentrancy guard check (burn minimum gas to trigger guard). Do not read Curve virtual_price in the same transaction as a liquidity removal. Use Chainlink oracle for LP pricing."
  trampas:
    - "Only affects pools with native ETH (not WETH) due to .call callback"
    - "Balancer pools with reentrancy guard since Aug 2023 are patched"
    - "Vyper < 0.3.1 had broken reentrancy guards making this worse"
  solodit_ids:
    - "h-1-liquidations-are-impossible-for-some-curve-pools-sherlock-notional-notional-update-2-git"
    - "h-1-h-01-wsteth-eth-curve-lp-token-price-can-be-manipulated-to-cause-unexpected-liquidations-sherlock-sentiment-sentiment-update-2-git"
    - "balancer-read-only-reentrancy-vulnerability-changes-from-dev-team-added-to-audit-spearbit-cron-finance-pdf"
  incidentes:
    - "Sentiment Update 2 -- wstETH-ETH Curve LP virtual_price suppressed via read-only reentrancy, triggers false liquidations ($potential millions) (HIGH)"
    - "Cron Finance TWAMM -- Balancer read-only reentrancy affects getVirtualReserves, getVirtualPriceOracle (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, reentrancy, read-only, virtual-price, curve, balancer, callback, liquidation]

- id: dex-017
  pattern: decimal-mismatch-in-swap-math
  name: "Decimal difference between tokens breaks swap/slippage math"
  causa_raiz: >
    Swap calculations, slippage checks, or LP valuation formulas assume all
    tokens have the same decimals (typically 18). When tokens with different
    decimals are paired (e.g., USDC/6 with WETH/18), the math produces values
    off by orders of magnitude, causing incorrect prices, broken slippage
    protection, or DoS via overflow/underflow.
  como_funciona: |
    1. Token A has 18 decimals, Token B has 6 decimals
    2. Swap math computes: minReceived = (amount * slippageTol) / DENOMINATOR
    3. amount is in Token A decimals (18), but minReceived is compared against Token B output (6 decimals)
    4. minReceived is 1e12 too large -- swap ALWAYS reverts (DoS)
    5. OR: minReceived is 1e12 too small -- slippage protection is meaningless
    6. LP valuation using oraclePrice without decimal normalization over/undervalues positions
  invariante: "assert(all amounts in swap math are normalized to same decimal base before comparison)"
  que_mirar:
    - "decimals()"
    - "10 **"
    - "primaryDecimals"
    - "secondaryDecimals"
    - "PRECISION"
    - "tokenPrecisionMultipliers"
    - "scaledDiv"
  como_se_arregla: "Normalize all token amounts to a common precision (e.g., 18 decimals) before performing math. Apply tokenPrecisionMultipliers from the pool's config. Check decimal compatibility at pool creation."
  trampas:
    - "Pairs of same-decimal tokens (WETH/DAI both 18) are not affected"
    - "cTokens have 8 decimals regardless of underlying -- easy to miss"
  solodit_ids: []
  incidentes:
    - "Notional Update 2 -- Curve vault undervalues LP when tokens have different decimals (HIGH)"
    - "Connext -- _slippageTol does not adjust for decimal differences, DoS or no protection (MEDIUM)"
    - "Illuminate -- Sense PT has IBT decimals (8) vs underlying (6), slippage check blocks redeem (HIGH)"
    - "Isomorph -- swapping 100 tokens to check price breaks for WBTC (8 decimals) due to massive value (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, decimals, precision, normalization, slippage, overflow, cross-token]

- id: dex-018
  pattern: uniswap-return-value-mishandled
  name: "Uniswap V3 swap return value not negated or misinterpreted"
  causa_raiz: >
    UniswapV3Pool.swap() returns (int256 amount0, int256 amount1) where the
    output amount is NEGATIVE for exact-input swaps (tokens going out of the pool
    to the user). If the caller does not negate the negative value before casting
    to uint256, the result overflows, causing DoS or incorrect amounts.
    Similarly, sqrtPriceLimitX96 does not revert on breach -- it causes partial
    fills, which is NOT slippage protection.
  como_funciona: |
    1. Protocol calls pool.swap() with exactInput
    2. Return value amount1 is negative (e.g., -1000 USDC going to user)
    3. Protocol casts int256(-1000) to uint256 WITHOUT negation
    4. Result: uint256(type(int256).min - 1000) = massive overflow value
    5. SafeCast or subsequent math reverts, causing complete DoS
    6. OR: sqrtPriceLimitX96 causes partial fill, leftover tokens stuck in contract
  invariante: "assert(amountOut == uint256(-(zeroForOne ? amount1 : amount0))) -- negate before cast"
  que_mirar:
    - "pool.swap("
    - "int256.*uint256"
    - "amount0.*amount1"
    - "sqrtPriceLimitX96"
    - "MIN_SQRT_RATIO"
    - "MAX_SQRT_RATIO"
    - "toUint128"
  como_se_arregla: "Always negate the negative return value before casting to uint256 (follow Uniswap SwapRouter reference). Use amountOutMinimum check AFTER the swap, not sqrtPriceLimitX96 as slippage protection."
  trampas:
    - "sqrtPriceLimitX96 is NOT a revert-on-breach parameter -- it is a partial-fill boundary"
    - "ExactOutput swaps return positive for the input side"
  solodit_ids: []
  incidentes:
    - "Maia DAO -- RootBridgeAgent._gasSwapIn/Out does not negate UniV3 return, DoS via overflow (MEDIUM)"
    - "Blueberry -- IchiSpell uses sqrtPriceLimitX96 as slippage but it causes partial swaps, not reverts (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v3, return-value, negation, overflow, sqrtPriceLimitX96, partial-swap]

- id: dex-019
  pattern: cross-chain-swap-token-stuck
  name: "Tokens stuck in protocol when cross-chain destination swap fails"
  causa_raiz: >
    Cross-chain DEX/bridge protocols perform a swap on the destination chain
    after bridging. If the destination swap reverts (due to slippage, manipulation,
    or changed conditions), the bridge's try-catch sends tokens to the protocol
    contract address instead of the user. These tokens become stuck or stealable.
  como_funciona: |
    1. User initiates cross-chain swap: source chain -> bridge -> destination swap
    2. Bridge delivers tokens to destination, calls protocol's completion function
    3. Destination swap reverts (e.g., price moved, attacker sandwiched)
    4. Bridge's try-catch catches the revert, sends tokens to fallback address (protocol contract)
    5. Tokens sit in protocol contract, not in user's wallet
    6. Attacker (or anyone) calls sweep/withdraw to steal the stuck tokens
    7. OR: user has no way to recover tokens, funds permanently lost
  invariante: "assert(tokenBalance(user) >= bridgedAmount OR tokenBalance(user) >= refundedAmount) -- user must receive tokens in all paths"
  que_mirar:
    - "sgReceive"
    - "onCall"
    - "try.*catch"
    - "CompleteBridgeTokens"
    - "swapAndComplete"
    - "fallback.*receiver"
  como_se_arregla: "On swap failure, send tokens directly to the user's wallet (not the protocol contract). Implement a user-claimable escrow for failed swaps. Never leave tokens in a sweepable contract."
  trampas:
    - "Stargate, Amarok, NXTP all have try-catch on destination -- each handles failure differently"
    - "If receiver is an Executor contract with proper access control, tokens may be safe"
  solodit_ids: []
  incidentes:
    - "LI.FI -- Destination chain swap failure leaves tokens in protocol, attacker drains via sandwich + sweep (HIGH)"
    - "Connext -- Users forced to accept any slippage on destination, no cancel function (HIGH)"
    - "DODO Cross-Chain DEX -- _doMixSwap returns original amount without swap when swapData empty, bypasses token type check (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, cross-chain, bridge, stuck-tokens, destination-swap, try-catch, sweep]

- id: dex-020
  pattern: pool-creation-validation-gap
  name: "Pool created with parameters incompatible with swap math"
  causa_raiz: >
    Pool factory allows creating pools with N assets or specific curve types
    but the swap/liquidity math only handles a subset of configurations. The
    pool is deployed and accepts deposits but swaps produce incorrect results
    or revert, permanently trapping funds or enabling arbitrage.
  como_funciona: |
    1. Factory allows creating 3-asset constant-product pool
    2. Swap math only handles 2-asset pairs (standard x*y=k)
    3. Pool is deployed, users deposit 3 tokens
    4. Swap between token A and C uses isolated pair math, not full 3-asset invariant
    5. Invariant breaks: attacker swaps A->B->C extracting value from the broken curve
    6. OR: removeLiquidity math designed for constant-product fails on stableswap Well functions
  invariante: "assert(pool.curveType is supported by swap/add/remove math for pool.numTokens)"
  que_mirar:
    - "createPool"
    - "initializePool"
    - "N_COINS"
    - "numTokens"
    - "poolType"
    - "Well.*function"
  como_se_arregla: "Validate at pool creation that the number of assets and curve type match what the swap math supports. Block unsupported combinations in the factory."
  trampas:
    - "2-asset pools with standard curves are typically safe"
    - "Generalized AMM frameworks (Beanstalk Wells, Balancer custom pools) are high-risk"
  solodit_ids: []
  incidentes:
    - "MANTRA DEX -- Factory allows 3-asset CPMM pools but swap math only handles 2-asset pairs (HIGH)"
    - "MANTRA DEX -- Stableswap does disjoint swaps breaking the n-dimensional invariant (HIGH)"
    - "Beanstalk/Basin -- removeLiquidity logic only correct for ConstantProduct, not other Well functions (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, pool-creation, factory, validation, curve-type, multi-asset, invariant-mismatch]

- id: dex-021
  pattern: stableswap-fee-bypass-via-imbalanced-deposit
  name: "Stableswap pool skewed free of fees via single-sided liquidity"
  causa_raiz: >
    Stableswap pools charge swap fees to maintain peg. But single-sided
    (imbalanced) liquidity deposits effectively perform a swap without paying
    the swap fee. An attacker can deposit one token, withdraw balanced, and
    repeat to arbitrage the pool or skew it for free.
  como_funciona: |
    1. Stableswap pool has tokens A and B in equal amounts (balanced)
    2. Attacker deposits a large amount of ONLY token A (single-sided)
    3. Pool does not charge swap fee on the imbalanced deposit
    4. Pool is now skewed: more A, less B
    5. Attacker withdraws proportionally (balanced): receives some A and some B
    6. Net effect: attacker swapped A for B without paying the swap fee
    7. Repeat to extract value or manipulate pool state
  invariante: "assert(feeCharged >= expectedSwapFee) for any operation that changes pool ratios"
  que_mirar:
    - "add_liquidity.*imbalanced"
    - "single.*deposit"
    - "calc_token_amount"
    - "fee.*deposit"
    - "coverage_ratio"
  como_se_arregla: "Charge an imbalance fee on single-sided deposits proportional to the implicit swap being performed. Curve V2 handles this via virtual_price adjustment."
  trampas:
    - "Balanced deposits (proportional) do not incur this issue"
    - "Small imbalances may be dust-level and not exploitable"
  solodit_ids: []
  incidentes:
    - "MANTRA DEX -- Stableswap pool can be skewed free of fees via imbalanced deposits (HIGH)"
    - "PlatypusFinance -- Multiple exploits targeting coverage ratio manipulation in stableswap (HIGH, $10.5M total)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, stableswap, fee-bypass, imbalanced-deposit, single-sided, coverage-ratio]

- id: dex-022
  pattern: uniswap-v3-solc-version-mismatch
  name: "Uniswap V3 math libraries ported to Solidity >=0.8 without unchecked"
  causa_raiz: >
    Uniswap V3 core libraries (TickMath, FullMath, LiquidityAmounts) were
    written for Solidity <0.8 which has unchecked arithmetic by default.
    These libraries intentionally rely on overflow/underflow behavior.
    When ported to >=0.8 without wrapping in unchecked{}, the math reverts
    on values that V3 handles correctly, causing DoS or incorrect results.
  como_funciona: |
    1. Protocol copies TickMath.sol, FullMath.sol from Uniswap V3 repo
    2. Changes pragma to >=0.8.0 for project compatibility
    3. Does NOT wrap function bodies in unchecked{}
    4. FullMath.mulDiv(type(uint).max, type(uint).max, type(uint).max) reverts instead of returning type(uint).max
    5. Swap or liquidity calculations that rely on overflow behavior revert
    6. Users cannot swap or add liquidity, causing DoS
  invariante: "assert(FullMath.mulDiv(a, b, c) returns same value as Uniswap V3 reference for all inputs)"
  que_mirar:
    - "pragma solidity ^0.8"
    - "FullMath"
    - "TickMath"
    - "LiquidityAmounts"
    - "mulDiv"
    - "unchecked"
  como_se_arregla: "Wrap all function bodies in unchecked{} blocks when porting Uniswap V3 math libraries to Solidity >=0.8. Use the official @uniswap/v3-core npm package which already handles this."
  trampas:
    - "Functions that don't rely on overflow (pure addition) don't need unchecked"
    - "Already patched in recent @uniswap/v3-core releases"
  solodit_ids: []
  incidentes:
    - "Astaria -- FullMathUniswap, LiquidityAmounts, TickMath ported to 0.8 without unchecked, reverts on edge cases (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v3, solidity, compiler, unchecked, overflow, FullMath, TickMath]

- id: dex-023
  pattern: admin-param-change-sandwichable
  name: "Admin parameter change causes AMM price shift exploitable via sandwich"
  causa_raiz: >
    When an admin/governance transaction changes a pool parameter (fee rate,
    amplification factor, liquidity sensitivity, weight) that affects the
    AMM's pricing, the parameter change transaction itself becomes sandwichable.
    An attacker positions themselves before the parameter change and profits
    from the price discontinuity.
  como_funciona: |
    1. Admin submits tx to change pool parameter (e.g., swap fee, amp factor, weights)
    2. Attacker sees pending admin tx in mempool
    3. Attacker front-runs: takes position that benefits from the parameter change
    4. Admin tx executes: pool price shifts due to new parameters
    5. Attacker back-runs: closes position at new price, captures the delta
    6. Cost of attack is minimal (just gas + swap fees)
  invariante: "assert(maxPriceImpact(paramChange) < threshold) OR use timelock with gradual change"
  que_mirar:
    - "setFee"
    - "setAmplification"
    - "updateWeights"
    - "rampA"
    - "setLsf"
    - "enableTrading"
  como_se_arregla: "Use gradual parameter changes (ramp over time, not instant). Apply timelock to parameter changes. Pause trading during weight changes. Use updateWeightsGradually instead of instant updates."
  trampas:
    - "Timelocked changes with >24h delay are generally safe due to arbitrage equilibrium"
    - "Curve's rampA already uses gradual change over days"
  solodit_ids: []
  incidentes:
    - "TermMax Market -- setLsf() causes AMM price shift, sandwichable (HIGH)"
    - "Gauntlet/Aera Vault -- enableTradingWithWeights allows instant weight change while trading is active (MEDIUM)"
    - "Gauntlet/Aera Vault -- finalize() front-runnable, attacker forces Treasury to accept bad token distribution (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, admin, parameter-change, sandwich, weights, amplification, fee, governance]

- id: dex-024
  pattern: permissionless-caller-controls-swap-params
  name: "Permissionless function lets caller control swap routing or recipient"
  causa_raiz: >
    A permissionless function (e.g., rebalance, reinvest, compound, settle)
    accepts caller-provided parameters for an internal swap: DEX address,
    route, fee tier, recipient, or calldata. A malicious caller can set
    parameters to route swaps through illiquid pools, set recipient to their
    own address, or craft calldata that drains tokens.
  como_funciona: |
    1. Permissionless function accepts swap parameters from caller
    2. Caller sets fee = 10000 (routes to illiquid pool) for easier sandwich
    3. OR: caller sets recipient in 0x order to their own address
    4. OR: caller provides EXACT_IN_BATCH route that sells vault's LP tokens
    5. Swap executes with caller's malicious parameters
    6. Protocol/vault loses funds to the caller
  invariante: "assert(swapRecipient == address(this)) AND assert(swapRoute uses approved pools only)"
  que_mirar:
    - "rebalance.*external"
    - "reinvestReward.*public"
    - "compound.*external"
    - "settle.*external"
    - "fee.*calldata"
    - "route.*calldata"
    - "recipient"
  como_se_arregla: "Hardcode swap recipient to the protocol contract. Validate DEX, fee tier, and route against an allowlist. For 0x/aggregator integrations, validate recipient field in the order data."
  trampas:
    - "If caller can only choose among pre-approved DEXes and fee tiers, risk is lower"
    - "Keeper-only functions with trusted EOA are less risky but still exploitable if key is compromised"
  solodit_ids: []
  incidentes:
    - "Notional -- 0x adaptor does not validate recipient, purchased tokens sent to attacker wallet (HIGH)"
    - "Redacted Cartel -- AutoPxGmx.compound lets caller choose fee tier, routes through illiquid pool (MEDIUM)"
    - "UXD Protocol -- rebalance lets caller specify payer account, drains approved users (HIGH)"
    - "Notional -- reinvestReward caller sets suboptimal DEX/slippage, vault gets less (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, permissionless, swap-params, recipient, routing, caller-controlled, reinvest]

- id: dex-025
  pattern: wrong-init-code-hash
  name: "Uniswap V2 pair address computed with wrong init code hash"
  causa_raiz: >
    CREATE2-based pair address computation uses an init code hash that must
    match the factory's actual pair bytecode. When protocols use the wrong
    hash (e.g., UniswapV2 hash on a SushiSwap factory, or vice versa),
    the computed pair address is incorrect. Swaps route to a non-existent
    or wrong pool, causing reverts or loss of funds.
  como_funciona: |
    1. Library uses CREATE2 to compute pair address: hash(0xff, factory, salt, INIT_CODE_HASH)
    2. INIT_CODE_HASH is hardcoded from wrong factory version (e.g., UniV2 hash on Sushi factory)
    3. Computed address does not match actual deployed pair
    4. Swap call to wrong address reverts (DoS) or succeeds on a different pool (wrong price)
    5. If a different contract happens to exist at that address, tokens may be lost
  invariante: "assert(computedPairAddress == factory.getPair(tokenA, tokenB))"
  que_mirar:
    - "init code hash"
    - "INIT_CODE_HASH"
    - "hex\"e18a"
    - "hex\"96e8"
    - "pairFor"
    - "CREATE2"
  como_se_arregla: "Use the correct init code hash for the target factory. Better yet, call factory.getPair() instead of computing addresses. When supporting multiple DEX forks, store init code hash per factory."
  trampas:
    - "Different chains may deploy same factory with different init code hashes"
    - "Upgradeable pair implementations change the hash"
  solodit_ids: []
  incidentes:
    - "Numoen -- UniswapV2Library uses SushiSwap init code hash instead of UniswapV2, computed pair addresses are wrong (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v2, init-code-hash, CREATE2, pair-address, factory, sushiswap]

- id: dex-026
  pattern: jit-liquidity-bypasses-anti-sandwich-hooks
  name: "JIT liquidity attack bypasses anti-sandwich or penalty hook mechanisms"
  causa_raiz: >
    Uniswap V4 hooks that attempt to prevent sandwich/JIT attacks (e.g.,
    AntiSandwichHook, LiquidityPenaltyHook) rely on per-position or per-address
    tracking. An attacker bypasses these by using secondary accounts, splitting
    liquidity across multiple positions, or exploiting the fee-donation mechanism
    itself. The donated penalty fees are distributed to in-range LPs at the current
    tick -- meaning the attacker's own concentrated position captures the penalty.
  como_funciona: |
    1. Hook imposes a penalty fee on liquidity added and removed within N blocks
    2. Penalty is donated to pool, distributed to in-range LPs at current tick
    3. Attack path A: Attacker uses Account1 to add liquidity (triggers penalty tracking)
       and Account2 (no tracking) to capture the donated fees as in-range LP
    4. Attack path B: Attacker adds tight-range liquidity via Account2 BEFORE the
       penalized Account1 removes liquidity. Account2 captures donated penalty fees.
    5. Attack path C: AntiSandwichHook charges extra fee on swaps after price moves,
       but attacker adds JIT liquidity to capture those extra fees, profiting more
       than the anti-sandwich mechanism costs
    6. Net result: JIT/sandwich protection is bypassed or even turned into profit source
  invariante: "assert(attacker_profit_with_hook <= attacker_profit_without_hook) -- hook must not create new profit vectors"
  que_mirar:
    - "LiquidityPenaltyHook"
    - "AntiSandwichHook"
    - "donate("
    - "beforeSwap.*fee"
    - "afterSwap.*donate"
    - "blockNumberOffset"
    - "modifyLiquidity.*penalty"
  como_se_arregla: "Do not donate penalties to current in-range LPs (attacker captures them). Instead, burn penalty tokens or send to treasury. For anti-sandwich hooks, ensure JIT liquidity cannot capture the extra fees by tracking liquidity addition timestamps in the same block."
  trampas:
    - "Single-account JIT penalties work; multi-account coordination is the bypass"
    - "Fee donation to pool is standard Uniswap V4 pattern but creates perverse incentives for penalties"
    - "Hooks that track by msg.sender can be bypassed by contract-based proxies"
  solodit_ids: []
  incidentes:
    - "OpenZeppelin Uniswap Hooks -- AntiSandwichHook bypassed via JIT liquidity that captures donated anti-sandwich fees (HIGH)"
    - "OpenZeppelin Uniswap Hooks -- LiquidityPenaltyHook bypassed using secondary accounts to capture donated penalties (HIGH)"
    - "OpenZeppelin Uniswap Hooks -- JIT Liquidity Penalty bypassed by splitting across positions (HIGH)"
    - "Super DCA -- Reward distribution via donate() to current tick exploitable by tick manipulation (MEDIUM)"
    - "Burve -- Attacker captures unclaimed fees by timing deposit with range re-entry and price manipulation (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v4, hooks, jit-liquidity, anti-sandwich, penalty-bypass, fee-donation, multi-account]

- id: dex-027
  pattern: bonding-curve-escrow-poisoning
  name: "Bonding curve escrow poisoned via deterministic address pre-funding"
  causa_raiz: >
    Bonding curve protocols (pump.fun style) use deterministic escrow addresses
    (PDAs on Solana, CREATE2 on EVM). The curve's invariant check requires that
    the escrow balance exactly matches the tracked reserves. An attacker sends
    tokens directly to the escrow address before the curve is created, breaking
    the invariant and causing permanent DoS. On EVM, predictable token deployment
    addresses via CREATE opcode enable pre-creation of Uniswap pools at manipulated
    prices before the official launch.
  como_funciona: |
    1. Attacker computes the deterministic escrow/PDA address for a token that hasn't been created yet
    2. Attacker sends SOL/ETH directly to that address
    3. When create_bonding_curve is called, real_sol_reserves initializes to 0
    4. Invariant check: require(escrow.balance == real_sol_reserves) fails because balance > 0
    5. Curve creation permanently fails (DoS)
    6. EVM variant: attacker precomputes token address from CREATE(deployer, nonce),
       creates Uniswap pair at manipulated price before official finalize()
    7. Official launch adds liquidity at wrong price, attacker arbitrages the difference
  invariante: "assert(escrow.balance >= real_reserves) -- use >= not == to tolerate donations. OR assert(pool.token0 == expectedToken AND pool was created by factory)"
  que_mirar:
    - "real_sol_reserves"
    - "sol_escrow"
    - "create_bonding_curve"
    - "invariant.*balance.*reserves"
    - "CREATE.*nonce"
    - "computeAddress"
    - "finalize"
    - "launchToUniswap"
  como_se_arregla: "Use >= instead of == for balance vs reserves checks (tolerate unsolicited transfers). On Solana, use close-and-recreate pattern for escrow. On EVM, use CREATE2 with salt including a secret or use factory.getPair() check before adding liquidity."
  trampas:
    - "PDAs on Solana are deterministic from seeds -- anyone can compute them"
    - "CREATE opcode addresses are deterministic from (sender, nonce) -- attacker can predict"
    - "Using == for balance checks is always fragile; selfdestruct/force-send breaks it"
  solodit_ids: []
  incidentes:
    - "Pump.fun audit -- Bonding Curve DOS through escrow pre-funding, deterministic PDA poisoned (HIGH)"
    - "Pump.fun audit -- Direct SOL transfers to bonding curve escrow break protocol invariant (HIGH)"
    - "DaosLive -- Predictable token deployment address via CREATE enables Uniswap pool exploit in finalize() (HIGH)"
    - "GroupcoinFactory -- Tokens can be launched to Uniswap v3 anytime due to logic error, allowing ETH drain (HIGH)"
    - "GroupcoinFactory -- Uniswap v3 launch enabled without raising enough ETH (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, bonding-curve, escrow, deterministic-address, pda, create2, dos, pre-funding, pump-fun]

- id: dex-028
  pattern: lp-token-transfer-resets-tracking
  name: "LP token transfer resets fee/penalty/lock tracking, enabling evasion"
  causa_raiz: >
    Protocols track per-LP metadata (deposit timestamp, deposit value, accumulated
    fees, lock duration) keyed by LP token holder address or NFT tokenId. When LP
    tokens are transferred to a new address, the tracking state is either reset to
    current values or not migrated at all. This allows: (1) fee evasion by resetting
    deposit value to current (higher) value, (2) lock/cool-off bypass by transferring
    to a fresh address with no cooldown, (3) penalty avoidance by moving tokens before
    penalty calculation.
  como_funciona: |
    1. Protocol tracks lpTokenDepositValue[user] at time of deposit
    2. On withdrawal, fee = f(currentValue - depositValue) -- "uplift fee"
    3. Attacker deposits at value V0, pool grows to V1
    4. Attacker transfers LP tokens to Account2
    5. Protocol resets depositValue[Account2] = V1 (current value)
    6. Account2 withdraws with uplift = V1 - V1 = 0, paying zero fees
    7. Lock/cool-off variant: swap pool requires N blocks before backstop withdrawal
    8. Attacker transfers LP tokens to Account2, which has no cooldown record
    9. Account2 immediately withdraws through backstop, bypassing cooldown
  invariante: "assert(lpMetadata is preserved or recalculated correctly on transfer) -- deposit value, lock time, and penalty state must follow the token"
  que_mirar:
    - "_transfer"
    - "_beforeTokenTransfer"
    - "onTransfer"
    - "depositValue.*transfer"
    - "coolOff.*transfer"
    - "lockPeriod"
    - "feeDataArray"
    - "lpTokenDepositValue"
  como_se_arregla: "Override _beforeTokenTransfer to propagate deposit metadata to receiver. For NFT-based LP: store metadata in the NFT, not in a mapping keyed by owner. For lock periods: make LP tokens non-transferable during lock or carry lock to new owner."
  trampas:
    - "ERC-20 LP tokens with no transfer hook are always vulnerable"
    - "ERC-721 LP NFTs can carry metadata but must update on transfer"
    - "Soulbound LP tokens prevent this entirely but reduce composability"
  solodit_ids: []
  incidentes:
    - "QuantAMM -- Fee evasion via LP Token Transfer resets deposit value, zeroing uplift fee (HIGH)"
    - "Pendulum Backstop Pool -- Cool-off period for deposits bypassed by transferring LP tokens to another address (HIGH)"
    - "Velar Artha -- User can sandwich own position close to reclaim all position fees via flash liquidity (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, lp-token, transfer, fee-evasion, lock-bypass, cooloff, deposit-tracking, metadata-reset]

- id: dex-029
  pattern: self-sandwich-fee-recapture
  name: "Self-sandwiching to recapture own borrowing/position fees via flash liquidity"
  causa_raiz: >
    In perpetual DEX or lending-integrated AMM designs, fees (borrowing fees,
    position fees, funding rates) accumulate in a position and are distributed
    to LPs only when the position is closed. Distribution is proportional to
    current LP share at the moment of closure, not time-weighted. An attacker
    flash-loans a large amount, adds it as liquidity, closes their own fee-bearing
    position (distributing fees mostly to themselves), then removes liquidity.
    Net effect: attacker pays zero or near-zero fees.
  como_funciona: |
    1. Attacker has open position accumulating $1000 in borrowing fees
    2. Attacker flash-loans large capital, adds as liquidity (now owns 90% of pool)
    3. Attacker closes their position -- $1000 in fees distributed to LPs
    4. Attacker receives $900 (90% of $1000) as LP
    5. Attacker removes liquidity, repays flash loan
    6. Net fee paid: $100 instead of $1000 (90% reduction)
    7. Works in any system where fee distribution is pro-rata at time of event
  invariante: "assert(feeDistribution is time-weighted) OR assert(LP cannot add and remove liquidity in same block as fee distribution event)"
  que_mirar:
    - "distributeFees"
    - "closePosition.*fees"
    - "borrowingFee.*LP"
    - "fundingRate.*distribute"
    - "addLiquidity.*removeLiquidity"
    - "flashLoan.*addLiquidity"
  como_se_arregla: "Use time-weighted fee distribution (track LP duration, not just LP share at distribution time). Add minimum LP duration before fee accrual. Distribute fees continuously via per-second accumulator, not lump-sum on position close."
  trampas:
    - "Synthetix-style continuous distribution prevents this"
    - "If flash loan fees exceed recaptured fees, attack is unprofitable"
    - "Some protocols intentionally allow this as a feature (buyback)"
  solodit_ids: []
  incidentes:
    - "Velar Artha -- User sandwiches own position close to reclaim all borrowing fees via flash liquidity (HIGH)"
    - "TermMax Market -- Malicious users steal swap fees from LPs via flash deposit-withdraw around fee event (HIGH)"
    - "TermMax Market -- provideLiquidity vulnerable to donation attacks (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, self-sandwich, fee-recapture, flash-liquidity, perpetual, borrowing-fees, time-weighted]

- id: dex-030
  pattern: bonding-curve-graduation-race
  name: "Bonding curve to DEX graduation exploitable via race conditions"
  causa_raiz: >
    Token launchpad protocols use a bonding curve for initial price discovery,
    then "graduate" the token to a DEX (Uniswap, Raydium) once a threshold is met.
    The graduation process (moving liquidity from bonding curve to DEX) has multiple
    race condition windows: (1) two-step enable-then-launch can be called out of
    order, (2) graduation transaction itself is sandwichable on the DEX side even
    if bonding curve side has slippage, (3) threshold can be met with insufficient
    ETH due to price vs. volume mismatch, (4) initial LP provided during graduation
    can be stuck or stolen.
  como_funciona: |
    1. Bonding curve sells tokens until price threshold is met
    2. enableLaunch() sets a commit block; launchToDex() should only work after
    3. Bug: launchToDex() check uses <= instead of <, or default value passes check
    4. Attacker calls launchToDex() without enableLaunch(), draining ETH from curve
    5. OR: graduation transaction adds liquidity to DEX without slippage protection
    6. Attacker sandwiches the graduation tx on the DEX side
    7. OR: threshold price is met but total ETH raised is insufficient for target liquidity
    8. DEX pool launches underfunded, attacker arbitrages the price gap
  invariante: "assert(launchEnabled == true AND block.number > commitBlock) before graduation. assert(dexLiquidityAdded >= minTargetLiquidity). assert(slippage protection on DEX liquidity addition)"
  que_mirar:
    - "enableUniswapV3Launch"
    - "launchGroupCoin"
    - "finalize"
    - "performFinalTrade"
    - "_sendToDex"
    - "commitLaunch"
    - "thresholdPrice"
    - "graduation"
    - "isFinalized"
  como_se_arregla: "Use strict ordering checks (require enableLaunch was called). Add slippage protection on both bonding curve AND DEX sides of graduation. Verify total ETH raised meets liquidity target, not just price threshold. Make graduation atomic where possible."
  trampas:
    - "Two-step commit-reveal patterns can have logic errors in the commit check"
    - "Slippage on bonding curve side does NOT protect the DEX liquidity addition"
    - "Initial LP from graduation is often permanently locked -- but not always"
  solodit_ids: []
  incidentes:
    - "GroupcoinFactory -- Tokens launched to Uniswap v3 anytime due to logic error in commit check, ETH drained (HIGH)"
    - "GroupcoinFactory -- Launch enabled without raising enough ETH, underfunded pool (HIGH)"
    - "LiquidityFreeLaunch -- Contract never finalizes due to incorrect order of operations in _sendToDex (HIGH)"
    - "NewMoon -- Lack of slippage protection during graduation in BondingCurvePool (MEDIUM)"
    - "DaosLive -- Predictable token address enables front-running finalize() to manipulate pool (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, bonding-curve, graduation, launchpad, race-condition, pump-fun, threshold, commit-reveal]

- id: dex-031
  pattern: internal-balance-drain-via-swap-recipient
  name: "Internal balance or contract tokens drained via swap facet recipient mismatch"
  causa_raiz: >
    Protocols with internal balance accounting (Diamond/facet patterns, Beanstalk-style)
    allow users to hold tokens in internal balances within the protocol contract. Swap
    facets that interact with external DEXes (Curve, Uniswap) have a toMode parameter
    controlling whether output goes to user's wallet or internal balance. When the swap
    function sends output directly to msg.sender via the DEX's recipient parameter but
    ALSO credits internal balance, or when it fails to validate the recipient, an attacker
    can drain other users' internal balances.
  como_funciona: |
    1. Protocol holds internal balances for users (e.g., Beanstalk Farm balances)
    2. CurveFacet.exchangeUnderlying() has fromMode (INTERNAL/EXTERNAL) and toMode parameters
    3. When toMode == INTERNAL, function should receive tokens to protocol contract, then credit internally
    4. Bug: function sends output directly to msg.sender via Curve's recipient param AND credits internal balance
    5. Attacker calls with toMode=INTERNAL: receives tokens AND gets internal credit (double spend)
    6. OR: function uses protocol contract's token balance for the swap output amount
    7. Any tokens sitting in the contract from other users' internal balances are accessible
  invariante: "assert(sum(internalBalances[all_users]) <= contract.tokenBalance) -- internal balance solvency"
  que_mirar:
    - "exchangeUnderlying"
    - "exchange("
    - "fromMode"
    - "toMode"
    - "LibTransfer"
    - "INTERNAL"
    - "EXTERNAL"
    - "receiveToken"
    - "sendToken"
    - "recipient.*msg.sender"
  como_se_arregla: "When toMode == INTERNAL, the swap recipient MUST be the protocol contract (address(this)), not msg.sender. Validate that output amount credited to internal balance matches actual tokens received by the contract."
  trampas:
    - "Protocols without internal balance accounting are not affected"
    - "If all operations use EXTERNAL mode, internal balances are never at risk"
    - "Diamond proxy patterns make it easy to miss that facets share state"
  solodit_ids: []
  incidentes:
    - "Beanstalk -- Internal balance tokens drained through CurveFacet.exchangeUnderlying, recipient mismatch between INTERNAL/EXTERNAL modes (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, internal-balance, diamond, facet, curve, recipient, double-credit, swap-mode]

- id: dex-032
  pattern: slippage-check-sign-inversion-on-net-delta
  name: "Slippage check skipped when net balance delta flips sign due to accrued fees"
  causa_raiz: >
    In Uniswap V4 and similar systems, modifyLiquidity returns a balance delta
    combining both the tokens required for the position change AND accrued fees.
    Slippage checks (validateMaxInNegative) only validate when the delta is negative
    (user pays). When accrued fees exceed the tokens needed for a liquidity increase,
    the net delta becomes positive, and slippage checks are silently skipped. An
    attacker can manipulate pool state to maximize the position cost while the
    accumulated fees mask the true cost from the slippage check.
  como_funciona: |
    1. LP has position with large accrued but uncollected fees (e.g., 100 USDC)
    2. LP calls increaseLiquidity, requiring 80 USDC of tokens
    3. Net balanceDelta = 80 (cost) - 100 (fees) = -20 (positive, user receives net)
    4. validateMaxInNegative sees positive delta, skips slippage check entirely
    5. Attacker front-runs: manipulates pool to increase cost to 200 USDC
    6. Net delta = 200 - 100 = 100 (still net cost, but was 80 before)
    7. In edge case where fees barely exceed cost, slippage can be 50%+ undetected
    8. User pays far more than expected but slippage check never fires
  invariante: "assert(positionCost <= maxTokensIn) -- check position cost SEPARATELY from fee collection"
  que_mirar:
    - "validateMaxInNegative"
    - "balanceDelta"
    - "modifyLiquidity"
    - "increaseLiquidity"
    - "feesOwed"
    - "SlippageCheck"
    - "amount0Delta.*amount1Delta"
  como_se_arregla: "Separate the position cost delta from fee collection delta. Apply slippage checks on the position cost component independently. Alternatively, check both components: maxTokensIn for cost AND minTokensOut for fees."
  trampas:
    - "Only affects positions with significant uncollected fees"
    - "Uniswap V4 periphery had this exact bug (now patched)"
    - "V3 does not combine fees and position cost in the same return value"
  solodit_ids: []
  incidentes:
    - "Uniswap V4 Periphery -- Slippage checks not enforced when fees accrued exceed tokens required for liquidity deposit (HIGH)"
    - "Uniswap V4 Periphery -- Same finding confirmed independently by two auditors (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dex, uniswap-v4, slippage, balance-delta, fees, sign-inversion, modifyLiquidity, periphery]

- id: dex-033
  pattern: zero-slippage-automated-add-liquidity-concentrated
  name: "amount0Min=0/amount1Min=0 en increaseLiquidity automático — peor en concentrated liquidity"
  causa_raiz: >
    Contratos que realizan compounding o rebalanceo automático de posiciones en AMMs de
    liquidez concentrada suelen llamar increaseLiquidity con amount0Min=0 y amount1Min=0
    porque el contrato no puede obtener el slippage del usuario en tiempo de ejecución.
    Esto expone el addLiquidity a sandwich MEV. En concentrated liquidity este ataque
    es materialmente peor que en AMMs clásicos por tres razones: (1) toda la liquidez
    va a un rango estrecho — un pequeño movimiento de precio cambia radicalmente la
    proporción token0/token1 requerida; (2) si el precio sale del rango durante el
    addLiquidity, el token del side que "sobra" queda completamente sin añadir como
    leftover en lugar de añadirse a precio peor; (3) el protocolo cobra su fee sobre
    la liquidez real añadida (menor), perdiendo también ingresos.
  como_funciona: |
    1. Contrato llama increaseLiquidity(tokenId, amount0Desired, amount1Desired, 0, 0, deadline)
       Confirmado en GaugeManager.sol línea 491: amount0Min=0, amount1Min=0
    2. Atacante front-runs: swap desplaza sqrtPriceX96 lejos del centro del rango
    3. increaseLiquidity ejecuta: el ratio deseado ya no coincide con el ratio del pool
    4. NPM añade liquidez en el ratio del pool actual (desplazado), devuelve como
       leftover el exceso del token menos demandado al precio manipulado
    5. Liquidez añadida < expected; leftover devuelto al owner (pérdida de compounding)
    6. Atacante back-runs: restaura precio, captura el diferencial creado
    DIFERENCIA VS AMM CLÁSICO: En UniV2, el LP siempre añade en la proporción actual.
    En V3, si el precio cae fuera del rango durante el addLiquidity, CERO del token
    "equivocado" se añade — todo es leftover, cero liquidity added del amount erróneo.
  invariante: "amountAdded0/amount0Desired >= MIN_ADD_EFFICIENCY (ej: 90%) para posiciones in-range"
  que_mirar:
    - "¿amount0Min y amount1Min son 0 en la llamada a increaseLiquidity o addLiquidity?"
    - "¿El contrato calcula amount0Min/amount1Min desde el TWAP antes del addLiquidity?"
    - "¿La misma transacción que hace el swap también hace el addLiquidity? (sandwichable conjuntamente)"
    - "¿Puede el usuario especificar minEfficiency como parámetro en la función compound/rebalance?"
    - "¿El contrato tiene algún check post-addLiquidity que detecte baja eficiencia?"
  como_se_arregla: "Derivar amount0Min/amount1Min desde el TWAP del pool antes del increaseLiquidity. Patrón: (exp0, exp1) = LiquidityAmounts.getAmountsForLiquidity(twapSqrtPriceX96, sqrtPriceLower, sqrtPriceUpper, targetLiq); amount0Min = exp0 * 98/100; amount1Min = exp1 * 98/100. Ver dex-034 para el fix pattern completo."
  trampas:
    - "Para posiciones out-of-range, amount0Min o amount1Min siendo 0 para el token inactivo es CORRECTO — solo un token se añade cuando el precio está fuera del rango; no reportar como bug"
    - "El swap previo en GaugeManager SÍ tiene validación TWAP (_validateSwap) — el problema es exclusivo del paso de addLiquidity posterior, no del swap"
    - "El sandwich del addLiquidity requiere capital para mover el precio del pool de la POSICIÓN (que puede ser muy líquido), no solo el pool de reward — evaluar según TVL del pool"
  severidad: medium
  confianza: alta
  fuente: "análisis GaugeManager.sol líneas 473-506 IncreaseLiquidityParams línea 491 revert-lend 2026-03-20"
  verificado: true
  tags: [slippage, addLiquidity, increaseLiquidity, concentrated-liquidity, sandwich, compound, MEV, automated]
  relacionado_con: [dex-004, dex-008, dex-005]

- id: dex-034
  pattern: twap-derived-slippage-add-liquidity-fix
  name: "Fix pattern: slippage mínimo seguro en increaseLiquidity automático derivado del TWAP"
  causa_raiz: >
    Contratos automáticos no pueden recibir slippage del usuario porque el usuario no
    está presente. La solución es derivar amount0Min/amount1Min desde el TWAP del pool
    antes del addLiquidity. Este es el mismo mecanismo que GaugeManager usa para los
    swaps de reward (_validateSwap con REWARD_TWAP_SECONDS=60) pero que no aplica al
    paso de increaseLiquidity. La ventana TWAP para el slippage de addLiquidity debe
    ser >= la del swap previo para que la protección sea coherente.
  como_funciona: |
    FIX PATTERN (pseudocode):
    // 1. Leer TWAP del pool de la posición (min 5 minutos para producción)
    uint32 twapSeconds = 300;
    (int56[] memory ticks,) = positionPool.observe([0, twapSeconds]);
    int24 twapTick = int24((ticks[0] - ticks[1]) / int56(uint56(twapSeconds)));
    uint160 twapSqrtPriceX96 = TickMath.getSqrtRatioAtTick(twapTick);

    // 2. Calcular amounts esperados al precio TWAP
    (uint256 exp0, uint256 exp1) = LiquidityAmounts.getAmountsForLiquidity(
        twapSqrtPriceX96, sqrtPriceLower, sqrtPriceUpper, targetLiquidity
    );

    // 3. Aplicar 2% de tolerancia y usar min(twap_derived, desired) para evitar
    //    reverts si el precio spot subió desde el TWAP
    uint256 amount0Min = Math.min(exp0 * 98/100, amount0Desired * 98/100);
    uint256 amount1Min = Math.min(exp1 * 98/100, amount1Desired * 98/100);

    // 4. increaseLiquidity con protección real
    npm.increaseLiquidity(IncreaseLiquidityParams(
        tokenId, amount0Desired, amount1Desired, amount0Min, amount1Min, deadline
    ));

    TRADEOFF: ventana más larga = más seguro vs. más reversions en volatilidad.
    60s (GaugeManager actual para swaps) es insuficiente; 300-600s para producción.
  invariante: "amount0Min > 0 OR amount1Min > 0 para posiciones in-range; derivado de TWAP, no hardcoded a 0"
  que_mirar:
    - "¿Está el patrón TWAP→getAmountsForLiquidity implementado antes del increaseLiquidity?"
    - "¿La ventana TWAP para el slippage de addLiquidity es >= la ventana del swap previo?"
    - "¿El fix aplica el min(twap_derived, desired * 0.98) para evitar reverts por precio subido?"
  como_se_arregla: "Implementar el fix pattern. Usar twapSeconds >= 300. Documentar en NatSpec que compound puede revertir durante alta volatilidad — es una feature de protección MEV."
  trampas:
    - "Una posición out-of-range solo añade UN token — el mínimo del otro token siendo 0 es correcto"
    - "Si el precio spot subió desde el TWAP, exp0 > amount0Desired — sin el min() causaría revert innecesario"
    - "Este pattern no protege si el propio TWAP fue manipulado (ver gauge-004) — verificar liquidez del pool"
  severidad: informational
  confianza: alta
  fuente: "análisis GaugeManager.sol _validateSwap() + _addLiquidity() revert-lend 2026-03-20"
  verificado: false
  tags: [slippage, addLiquidity, TWAP, fix-pattern, getAmountsForLiquidity, compound, increaseLiquidity]
  relacionado_con: [dex-033, dex-004]

- id: dex-035
  pattern: pool-initialization-price-frontrun
  name: "Attacker front-runs pool initialization to set a manipulated initial sqrtPrice"
  causa_raiz: >
    When a protocol creates a new Uniswap V3/V4 pool and adds initial liquidity in separate
    transactions, an attacker can observe the createPool() transaction in the mempool and
    race to call initialize() or createAndInitializePoolIfNecessary() with a drastically
    different sqrtPriceX96. The protocol's addLiquidity call then executes at the attacker's
    price, receiving almost none of one token in return (or minting LP shares worth much
    less). The attacker profits by arbing the pool back to fair price.
  como_funciona: |
    1. Protocol sends createPool(token0, token1, fee=3000) tx.
    2. Attacker sees tx in mempool. Calculates: protocol will call initialize(sqrtPriceX96_fair).
    3. Attacker front-runs with initialize(sqrtPriceX96_10000x_inflated).
    4. Protocol's initialize() reverts (pool already initialized) OR protocol's addLiquidity
       executes at the attacker's manipulated price.
    5. Protocol's liquidity is added at 10000x price — for in-range liquidity, protocol
       deposits almost entirely in one token (the underpriced one).
    6. Attacker arbs pool back to fair price, extracting the over-deposited token at a discount.
    7. OR: Protocol expects pool doesn't exist but it does — entire tx reverts, blocking launch.
  invariante: |
    // Pool sqrtPrice at time of addLiquidity must be within tolerance of expected price
    uint160 actualPrice = pool.slot0().sqrtPriceX96;
    uint160 expectedPrice = computeSqrtPriceFromOracle(token0, token1);
    assert(actualPrice >= expectedPrice * 98/100 && actualPrice <= expectedPrice * 102/100);
  que_mirar:
    - "Does the protocol call createPool() and initialize() in separate transactions?"
    - "Is there a check that the pool does not already exist before calling initialize?"
    - "Does addLiquidity verify the current pool price is within expected range?"
    - "Can anyone call createAndInitializePoolIfNecessary() with arbitrary sqrtPriceX96?"
    - "rg 'initialize.*sqrt|createPool|createAndInitialize' --type sol"
  como_se_arregla: "Combine pool creation, initialization, and initial liquidity in a single atomic transaction. Before addLiquidity, verify pool.slot0().sqrtPriceX96 is within 1-2% of expected price (derived from oracle or constructor parameter). Revert if price is out of bounds."
  trampas:
    - "createAndInitializePoolIfNecessary is atomic IF the pool doesn't exist — but if attacker creates it first, the protocol's call skips initialization and proceeds at the wrong price"
    - "The attack is only profitable if the initial liquidity is large enough to arb"
    - "For token launches (no oracle exists), use a price range check derived from expected tokenomics"
    - "Uniswap V4 pools: PoolManager.initialize is permissionless — same attack surface exists"
  solodit_ids: []
  incidentes:
    - "Serious Protocol (Pashov) — createPoolAndAddLiquidity does not handle pre-existing pool at wrong price, front-runnable initial price setting (HIGH)"
    - "Predy Finance (Code4rena) — reallocate() uses slot0 price which is front-runnable, LP position pushed out of range (HIGH)"
    - "Multiple meme token launches — Initial Uniswap pool creation front-run, attacker sets price 10x-100x higher, project's liquidity mostly extracted at launch (CRITICAL)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Serious Protocol Pashov audit, Predy Code4rena"
  tags: [dex, pool-initialization, frontrun, sqrtPrice, uniswap-v3, uniswap-v4, initial-price, MEV]
  relacionado_con: [dex-004, dex-006, dex-013]

- id: dex-036
  pattern: slot0-derived-slippage-reallocation-manipulation
  name: "On-chain slippage or reallocation logic based on pool.slot0 is front-runnable"
  causa_raiz: >
    pool.slot0().sqrtPriceX96 and pool.slot0().tick are point-in-time values that can be
    moved within a single block by a large swap. When a protocol uses slot0 to: (a) calculate
    minAmountOut for a swap, (b) decide whether to reallocate LP positions, or (c) compute
    the proportion of tokens to add as liquidity — the decision is manipulatable.
    An attacker can move slot0 to a desired value, trigger the protocol's function at the
    manipulated price, then restore price and profit from the protocol's mispriced action.
    This is distinct from oracle manipulation (here the victim IS the DEX, not a downstream oracle consumer).
  como_funciona: |
    1. Protocol's rebalance() calls pool.slot0() to check if current price is outside range.
    2. Attacker sandwiches: large swap moves price outside the range check threshold.
    3. Protocol triggers rebalance: removes liquidity at manipulated tick, re-adds at new range.
    4. Attacker swaps back: price returns to normal, attacker extracts the LP's tokens at discount.
    OR for slippage:
    1. Protocol computes minOut = slot0_price * amount * 0.99.
    2. Attacker pushes price down before calling. slot0_price is low → minOut is low.
    3. Swap executes with nearly zero slippage protection.
    4. Attacker profits from the bad execution price.
  invariante: |
    // Slippage parameters must not be derived from the same pool being swapped
    // Use TWAP with sufficient window, or require external oracle
    uint32 twapWindow = 300; // 5 minutes minimum
    int24 twapTick = OracleLibrary.consult(pool, twapWindow);
    // Do NOT use: pool.slot0().tick
  que_mirar:
    - "Does the protocol use pool.slot0().sqrtPriceX96 for minAmountOut calculation?"
    - "Does rebalance/reallocation logic check pool.slot0().tick against thresholds?"
    - "Is there a TWAP alternative available (OracleLibrary.consult, cardinality > 1)?"
    - "What is the minimum pool TVL — manipulation cost vs protocol TVL determines exploitability"
    - "rg 'slot0|getSqrtRatioAtTick|getCurrentTick' --type sol"
  como_se_arregla: "Replace slot0 price reads with TWAP (OracleLibrary.consult, window >= 300s). Increase cardinality before launch. For reallocation, add a check that spot price is within N% of TWAP before executing. Never compute slippage from the pool you are swapping in."
  trampas:
    - "For thin pools, even a 300s TWAP is manipulatable — cross-validate with Chainlink or secondary oracle"
    - "If the function is only callable by admin/keeper, manipulation requires MEV cooperation with keeper"
    - "Uniswap V3 observations array may be uninitialized (cardinality=1) — OracleLibrary.consult reverts"
    - "On L2s with centralized sequencers, sandwich attacks require sequencer cooperation — reduced risk"
  solodit_ids: []
  incidentes:
    - "Predy Finance (Code4rena H-01) — reallocate() uses slot0 tick to decide reallocation, front-runnable (HIGH)"
    - "Thermae (Cyfrin) — On-chain slippage derived from pool.slot0 allows sandwich of any swap (HIGH)"
    - "Revert Lend GaugeManager — TWAP window of 60s for swap validation insufficient, 300s minimum required (HIGH)"
    - "Yieldoor (Code4rena) — Strategy main ticks derived from slot0 tick off-by-one, asymmetric fee loss (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Predy Code4rena, Thermae Cyfrin audit"
  tags: [dex, slot0, TWAP, sandwich, slippage, reallocation, manipulation, front-run, oracle]
  relacionado_con: [dex-004, dex-033, dex-034]

- id: dex-037
  pattern: amm-fee-applied-to-wrong-asset-limit-order
  name: "AMM fee deducted from wrong token in limit order / swap math — one side overcharged"
  causa_raiz: >
    In order-book-style AMMs or limit order systems built on top of AMMs, the fee is
    supposed to be applied to the INPUT token of the swap. If the fee is applied to the
    wrong asset (e.g., to the base asset when it should be applied to the quote asset,
    or applied after conversion rather than before), one side of the trade pays double
    the fee while the other pays nothing. In extreme cases, the fee can be applied to
    an amount that is an order of magnitude off, making limit orders unprofitable or
    consistently giving the protocol more than its declared fee.
  como_funciona: |
    1. Limit order: user wants to sell 1000 USDC for ETH at price 2000 USDC/ETH.
    2. Fee: 0.3% on the USDC (input) side = 3 USDC fee, user gets ETH for 997 USDC.
    3. Buggy implementation: converts 1000 USDC → 0.5 ETH first, then charges 0.3% fee on ETH.
    4. Fee = 0.3% * 0.5 ETH = 0.0015 ETH ≈ 3 USDC equivalent (appears same but is not).
    5. But: if conversion uses a different price OR fee is on BASE not QUOTE:
       fee = 0.3% * base_quantity = off by the price ratio.
    6. User is systematically overcharged or undercharged depending on price direction.
    7. In Ellipsis Plasma: fee charged on base after converting from quote → wrong sign.
  invariante: |
    // Fee must be applied to the correct asset (input side)
    // For a buy (quote → base): fee on quote
    // For a sell (base → quote): fee on base
    assert(fee_token == input_token);
    assert(output_amount == (input_amount - fee) / price); // buy
    assert(output_amount == (input_amount - fee) * price); // sell
  que_mirar:
    - "In which token is the fee charged? Is it always the input token?"
    - "For limit order fill: is fee charged before or after price conversion?"
    - "Are buy-side and sell-side fee calculations symmetric?"
    - "Is there a case where fee is computed on `amountOut` instead of `amountIn`?"
    - "rg 'fee.*base|fee.*quote|getFee|applyFee|limitOrder.*fee' --type sol"
  como_se_arregla: "Always apply fees to the INPUT token, BEFORE price conversion. Verify buy and sell fee paths are symmetric. Write a unit test: buy(x) then sell(result) should return slightly less than x (fee extracted twice, once each direction)."
  trampas:
    - "Some AMMs intentionally charge fee on output (e.g., Curve charges on the output side) — verify which convention the protocol uses"
    - "If fee is small (0.01-0.05%), the error may be minor unless price ratio is extreme"
    - "In two-sided fee models (maker + taker), track which side each fee applies to separately"
    - "Off-by-one in fee direction becomes critical for high-value limit orders or bulk fill scenarios"
  solodit_ids: []
  incidentes:
    - "Ellipsis Plasma (OtterSec) — AMM fee incorrectly applied to base asset after quote conversion in get_limit_order_size_in_base_and_quote (HIGH)"
    - "Multiple DEX limit order extensions — fee applied to wrong token causes systematic over/underpayment (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Ellipsis Plasma OtterSec audit"
  tags: [dex, fee, limit-order, wrong-token, base-quote, asymmetric, swap-math]
  relacionado_con: [dex-003, dex-023]

- id: dex-038
  pattern: autorange-trigger-griefing-negative-tick-limit
  name: "AutoRange/AutoRangeAndCompound — negative lowerTickLimit/upperTickLimit permite rerange en posiciones in-range"
  causa_raiz: >
    En AutoRangeAndCompound, el trigger de rerange se evalúa como:
    `currentTick < tickLower - lowerTickLimit || currentTick >= tickUpper + upperTickLimit`.
    Si `lowerTickLimit` o `upperTickLimit` son NEGATIVOS, la condición se cumple incluso cuando
    la posición está DENTRO del rango activo. El owner configura esto explícitamente, pero puede
    ser un error de configuración que un keeper explota: fuerza un rerange pagado con los fondos
    del owner cuando no es necesario, incurriendo en fees de swap + slippage + protocol reward.
  como_funciona: |
    1. Owner configura lowerTickLimit = -100 (negativo).
    2. currentTick = tickLower - 50 → está in-range (50 ticks dentro del lower bound).
    3. Condición: currentTick < tickLower - (-100) = tickLower + 100 → TRUE (in-range trigger).
    4. Keeper llama execute() y fuerza un rerange:
       - Retira toda la liquidez del owner.
       - Hace un swap para rebalancear (con TWAP check pero slippage factored in).
       - Abre nueva posición centrada en el tick actual.
       - Cobra protocol reward (hasta maxRewardX64 del total de la posición).
    5. El owner paga: swap fees + protocol reward + gas — todo innecesariamente.
    Griefing continuo: keeper puede triggerear rerange en cada bloque si el precio oscila
    alrededor del punto de inflexión, drenando la posición del owner en protocol fees.
  invariante: |
    // Si currentTick está dentro de [tickLower, tickUpper), el rerange no debe ejecutarse
    // a menos que el owner haya configurado explícitamente lowerTickLimit/upperTickLimit negativos
    // → verificar que el UI/config no permite valores negativos inadvertidamente
    assert(
      config.lowerTickLimit >= 0 && config.upperTickLimit >= 0,
      "Negative tick limits enable in-range triggers — review config"
    );
    // Invariante de conservación: total value antes >= total value después - protocol fee
    assert(valueAfterRerange >= valueBeforeRerange * (Q64 - maxRewardX64) / Q64);
  que_mirar:
    - "¿Pueden lowerTickLimit/upperTickLimit ser negativos según el contrato? (int32, SÍ)"
    - "¿El UI/frontend valida que los tick limits sean >= 0?"
    - "¿Cuántas veces puede un keeper triggerear execute() en un período de tiempo?"
    - "¿Hay rate limiting o cooldown entre re-ranges?"
    - "rg 'lowerTickLimit|upperTickLimit|lowerTickDelta|upperTickDelta' --type sol"
    - "¿El configToken() valida que lowerTickDelta != upperTickDelta pero no valida tick limits?"
  como_se_arregla: "Documentar claramente el significado de tick limits negativos. Añadir validación en configToken() para advertir al owner cuando configura valores negativos. Considerar añadir cooldown entre re-ranges para limitar griefing."
  trampas:
    - "lowerTickLimit NEGATIVO es un feature intencional para posiciones que quieren re-rangear in-range — no siempre es un bug"
    - "El slippage está protegido por TWAP check (maxTWAPTickDifference), así que el peor caso es pérdida de fees + protocol reward, no sandwich total"
    - "El keeper (Revert controlled) es un actor de confianza — el riesgo real es misconfiguration del owner, no keeper malicioso"
    - "Solodit M-02: gas griefing via malicious onERC721Received ya documentado — este es diferente (valor extraído, no DOS)"
  solodit_ids: []
  incidentes:
    - "Revert Lend C4 (2024-03) M-02: gas griefing en AutoRange via onERC721Received (diferente vector, mismo contrato)"
    - "Revert Lend C4 (2024-03) M-23: AutoRange execution front-run para evitar protocol fee (relacionado)"
  severidad: medium
  confianza: media
  verificado: false
  fuente: "Análisis directo AutoRangeAndCompound.sol líneas 207-210, configToken() líneas 542-567"
  tags: [dex, concentrated-liquidity, automator, autorange, keeper, griefing, rerange, protocol-fee, uniswap-v3]
  relacionado_con: [dex-039, dex-040]

- id: dex-039
  pattern: autocompound-pool-swap-no-output-minimum
  name: "AutoRangeAndCompound.autoCompound — swap interno sin amountOutMin permite extracción de valor por sandwich"
  causa_raiz: >
    En `autoCompound()`, el swap para rebalancear fees antes de reinvertir usa `_poolSwap()` con
    `sqrtPriceLimitX96 = 0` (línea 470). Solo hay protección TWAP: si el tick actual está dentro
    de `maxTWAPTickDifference` del TWAP, el swap procede. Pero el TWAP check valida la POSICIÓN
    DEL PRECIO, no el OUTPUT del swap. Entre el TWAP check y la ejecución del swap, un sandwich
    puede mover el precio dentro del margen de tolerancia y extraer el slippage del compound.
  como_funciona: |
    1. Position tiene 1000 USDC y 0.5 ETH de fees acumulados.
    2. Para rebalancear, keeper indica swap de 300 USDC → ETH.
    3. autoCompound() chequea: |currentTick - TWAPTick| <= maxTWAPTickDifference (200 ticks = ~2%).
    4. TWAP check pasa ✓.
    5. Attacker sandwicha: compra ETH antes del swap (mueve precio hasta el límite del TWAP).
    6. _poolSwap() ejecuta con sqrtPriceLimitX96=0 → acepta cualquier precio dentro del pool.
    7. Attacker vende ETH después del swap: 300 USDC del compound → ~290 USDC de output real.
    8. 10 USDC (~3.3%) extraídos del owner por sandwich.
    Nota: TWAP de 60s (MIN_TWAP_SECONDS) y maxTWAPTickDifference=200 permiten 2% de movimiento
    legítimo, que puede ser suficiente para hacer el sandwich rentable en pools de bajo volumen.
  invariante: |
    // Output del swap en autoCompound debe ser >= valor equivalente al input
    // basado en precio justo (TWAP o spot con tolerancia)
    uint256 expectedOut = amountIn * twapPrice * (Q64 - slippageTolerance) / Q64;
    assert(amountOutDelta >= expectedOut);
    // Fuzz: comparar valor pre vs post compound
    assert(valueAfterCompound >= valueBeforeCompound - MAX_FEE_LOSS);
  que_mirar:
    - "¿_poolSwap() se llama con sqrtPriceLimitX96 = 0? → Línea 470 de AutoRangeAndCompound.sol"
    - "¿Cuánto es maxTWAPTickDifference en la instancia deployed? (200 = 2%, configurable)"
    - "¿Cuánto es TWAPSeconds? (mínimo 60s — manipulable en pools de bajo volumen)"
    - "¿El keeper puede elegir amountIn arbitrariamente? → Sí, es parámetro calldata"
    - "¿El pool de autocompound es el mismo pool del position? → Sí, liquidez del LP"
    - "rg '_poolSwap|sqrtPriceLimitX96' --type sol"
  como_se_arregla: "Calcular amountOutMin basado en TWAP price y pasar como sqrtPriceLimitX96 al pool swap. Alternativamente, limitar amountIn al mínimo necesario para rebalancear según la ratio del rango."
  trampas:
    - "El TWAP check SÍ protege contra manipulación masiva de precio — el sandwich debe mantenerse dentro del margen TWAP"
    - "En pools de alto volumen, el MEV no puede mantener el precio desplazado — riesgo bajo en mainnet liquidity"
    - "El compound es llamado por Revert keeper (confiable) — el riesgo real es front-run MEV, no keeper malicioso"
    - "Comparar con execute() que SÍ pasa amountOutMin a _routerSwap() — autoCompound es el caso más débil"
  solodit_ids: []
  incidentes:
    - "No se encontró incidente real equivalente en Solodit para este vector exacto"
  severidad: medium
  confianza: media
  verificado: false
  fuente: "Análisis directo AutoRangeAndCompound.sol líneas 453-477, _poolSwap Swapper.sol"
  tags: [dex, concentrated-liquidity, automator, autocompound, sandwich, mev, slippage, pool-swap, uniswap-v3]
  relacionado_con: [dex-038, dex-040]

- id: dex-040
  pattern: autorange-leftover-underflow-when-protocol-reward-exceeds-added
  name: "AutoRangeAndCompound execute() — underflow potencial en cálculo de leftover cuando protocolReward > amount añadido"
  causa_raiz: >
    En el path `!config.onlyFees` de `execute()`, el protocol reward se calcula sobre
    `amountAdded0/1` (lo que realmente entró en la nueva posición), y se resta de `state.amount0/1`
    (el total disponible ANTES de añadir). Si `amountAdded` es pequeño (e.g., precio muy fuera
    del nuevo rango) y el reward es alto (maxRewardX64 al máximo = 2%), la resta
    `state.amount0 - state.protocolReward0 - state.amountAdded0` puede underflow en Solidity
    si el compilador no usa checked arithmetic correctamente, O puede producir un leftover
    negativo lógico que hace que el owner no reciba sus fondos restantes.
  como_funciona: |
    1. execute() para un position con amount0=1000 USDC, amount1=0.5 ETH.
    2. Nuevo rango es muy estrecho: mintParams acepta maxAddAmount0=990 USDC, maxAddAmount1=0.495 ETH.
    3. Pero el precio se movió: solo se añadió amountAdded0=10 USDC, amountAdded1=0.49 ETH.
    4. protocolReward0 = amountAdded0 * rewardX64/Q64 = 10 * 0.02 = 0.2 USDC.
    5. Leftover cálculo: state.amount0 - state.protocolReward0 = 1000 - 0.2 = 999.8 USDC.
    6. Luego: leftover = 999.8 - amountAdded0 = 999.8 - 10 = 989.8 USDC → correcto aquí.
    PERO: el cálculo real en el código (líneas 299-312) es:
       state.amount0 -= protocolReward0  (after reward calc)
       then: leftover = state.amount0 - state.amountAdded0
    El problema es si state.amount0 ya se redujo por el swap previo y protocolReward0 > state.amount0 - amountAdded0.
    En ^0.8.0 esto hace revert (checked arithmetic) — pero bloquea la operación para el owner.
  invariante: |
    // state.amount0 después de reward debe ser >= amountAdded0
    assert(state.amount0 - state.protocolReward0 >= state.amountAdded0);
    assert(state.amount1 - state.protocolReward1 >= state.amountAdded1);
    // El leftover nunca puede ser negativo
    assert(state.amount0 >= state.protocolReward0 + state.amountAdded0);
  que_mirar:
    - "¿protocolReward se calcula sobre amountAdded pero se resta de amount (total)? → Líneas 299-311"
    - "¿Puede amountAdded ser mayor que maxAddAmount? (no, por diseño de aumenteLiquidity)"
    - "¿Puede el precio moverse entre el swap y el mint causando amountAdded mucho menor que maxAddAmount?"
    - "¿El onlyFees path tiene el mismo riesgo? (no — en onlyFees el reward se toma ANTES del mint)"
    - "rg 'protocolReward|amountAdded|leftover' AutoRangeAndCompound.sol"
  como_se_arregla: "En el path !onlyFees, verificar que state.amount0/1 >= protocolReward + amountAdded antes de restar. Alternativamente, calcular reward sobre el leftover en lugar de sobre amountAdded."
  trampas:
    - "En Solidity ^0.8.0, el underflow hace revert — no hay pérdida de fondos, pero SÍ hay DOS para el owner (la operación siempre falla)"
    - "El caso más realista es un edge case de precio extremo durante el mint — no trivial de triggerear"
    - "La condición requiere: precio se mueve DESPUÉS del swap pero DURANTE el mint → window pequeño"
    - "Si onlyFees=true, este path NO se ejecuta — solo relevante para onlyFees=false"
  solodit_ids: []
  incidentes:
    - "No se encontró incidente real equivalente confirmado"
  severidad: low
  confianza: baja
  verificado: false
  fuente: "Análisis directo AutoRangeAndCompound.sol líneas 254-312"
  tags: [dex, concentrated-liquidity, automator, autorange, leftover, underflow, protocol-reward, arithmetic, uniswap-v3]
  relacionado_con: [dex-038, dex-039]
```

---

## 2.3 Real-World Incidents (Verified)

```yaml
- id: dex-incident-001
  name: "KyberSwap exploit"
  fecha: "2023-11"
  perdida: "$48M"
  causa_raiz: "Precision loss in concentrated liquidity tick boundary math"
  categoria: "Tick boundary error / precision loss"
  vector: "Attacker exploited precision loss at tick boundaries in KyberSwap's concentrated liquidity implementation to drain pools"
  leccion: "CRITICAL: Tick boundary math is the #1 attack surface for concentrated liquidity DEXes. See dex-006. Fuzz with swaps that land exactly on tick boundaries."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-006, dex-001]
  tags: [precision-loss, tick-boundary, concentrated-liquidity, real-exploit]

- id: dex-incident-002
  name: "Curve exploit"
  fecha: "2023-07"
  perdida: "$41M"
  causa_raiz: "Vyper compiler bug causing reentrancy vulnerability"
  categoria: "Reentrancy (compiler-level)"
  vector: "Vyper compiler versions 0.2.15-0.3.0 had broken reentrancy locks. Attacker used reentrancy to manipulate pool state during add_liquidity/remove_liquidity."
  leccion: "Compiler bugs bypass code-level defenses. Always verify compiler version. Reentrancy guards must be tested at the bytecode level, not just source."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001, dex-002]
  tags: [reentrancy, vyper, compiler-bug, real-exploit]

- id: dex-incident-003
  name: "SushiSwap RouteProcessor exploit"
  fecha: "2023-04"
  perdida: "$3.3M+"
  causa_raiz: "Input validation failure in swap router"
  categoria: "Input validation / calldata manipulation"
  vector: "Malicious calldata to RouteProcessor contract bypassed validation, enabling unauthorized token transfers from users with existing approvals"
  leccion: "Router contracts with user approvals are HIGH VALUE targets. Validate ALL calldata fields. See also bridge-incident-002 (SocketGateway)."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-004, dex-008]
  tags: [input-validation, router, approval-exploit, real-exploit]

- id: dex-incident-004
  name: "Jimbo Protocol exploit"
  fecha: "2023-05"
  perdida: "$8M"
  causa_raiz: "Protocol-specific price manipulation"
  categoria: "Price manipulation"
  vector: "Attacker manipulated protocol-specific pricing mechanism to extract value from liquidity pools"
  leccion: "Custom pricing mechanisms that deviate from standard AMM math are high-risk. See dex-003."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-003, dex-009]
  tags: [price-manipulation, protocol-specific, real-exploit]

- id: dex-incident-005
  name: "Balancer exploit"
  fecha: "2023-08"
  perdida: "$2M"
  causa_raiz: "Rounding/logic error in pool math"
  categoria: "Rounding direction error"
  vector: "Rounding errors in pool math allowed value extraction through repeated operations"
  leccion: "ALL rounding must favor the pool. Fuzz with tiny amounts (1 wei, 2 wei) to detect rounding exploits. See dex-001."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001, dex-002]
  tags: [rounding, logic-error, pool-math, real-exploit]

- id: dex-incident-006
  name: "Bedrock_DeFi exploit"
  fecha: "2024-09"
  perdida: "$1.7M"
  causa_raiz: "Swap ETH/BTC at 1:1 ratio in mint function"
  categoria: "Decimal/price mismatch"
  vector: "Mint function treated ETH and BTC as equivalent value (1:1), allowing massive arbitrage"
  leccion: "NEVER assume token equivalence. Price and decimal normalization is mandatory for multi-asset operations."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001, dex-010]
  tags: [price-mismatch, mint, decimal-error, real-exploit]

- id: dex-incident-007
  name: "Penpiexyz_io exploit (DEX context)"
  fecha: "2024-09"
  perdida: "$27.3M"
  causa_raiz: "Reentrancy combined with reward manipulation in DEX/yield context"
  categoria: "Reentrancy + reward manipulation"
  vector: "Cross-function reentrancy during reward operations in a DEX yield aggregator"
  leccion: "DEX yield aggregators combining swap + stake + reward paths need global reentrancy guards."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-009]
  tags: [reentrancy, reward-manipulation, yield-aggregator, real-exploit]

- id: dex-incident-008
  name: "CloberDEX exploit"
  fecha: "2024-12"
  perdida: "$501K"
  causa_raiz: "Reentrancy vulnerability"
  categoria: "Reentrancy"
  vector: "Reentrancy during DEX operations allowed state manipulation and fund extraction"
  leccion: "Even orderbook DEXes are vulnerable to reentrancy. CEI pattern + global guards mandatory."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001]
  tags: [reentrancy, orderbook, real-exploit]

- id: dex-incident-009
  name: "Biswap V3Migrator exploit"
  fecha: "2023-06"
  perdida: "$72K"
  causa_raiz: "V3 migration contract exploit"
  categoria: "Migration logic flaw"
  vector: "V3Migrator contract had logic flaw exploitable during LP migration"
  leccion: "Migration contracts are one-time-use but permanent attack surface. Audit migration paths."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-002]
  tags: [migration, V3, real-exploit]

- id: dex-incident-010
  name: "SwaposV2 exploit"
  fecha: "2023-04"
  perdida: "$468K"
  causa_raiz: "K-value validation error"
  categoria: "Constant product violation"
  vector: "K-value (x*y=k) not properly validated, allowing swaps that reduced k"
  leccion: "EXACTLY the bug described in dex-001. k_after >= k_before must be asserted after EVERY swap."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001]
  tags: [k-value, constant-product, real-exploit]

- id: dex-incident-011
  name: "PlatypusFinance exploits (3 incidents)"
  fecha: "2023-02, 2023-07, 2023-10"
  perdida: "$8.5M + $51K + $2M"
  causa_raiz: "Business logic flaws in stableswap"
  categoria: "Business logic"
  vector: "Multiple exploits targeting Platypus stableswap business logic, including coverage ratio manipulation and liability calculation errors"
  leccion: "Stableswap-specific math (coverage ratios, liability tracking) is a distinct attack surface from constant-product AMMs. Requires specialized invariants."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001, dex-010]
  tags: [business-logic, stableswap, repeated-exploit, real-exploit]

- id: dex-incident-012
  name: "BelugaDex exploit"
  fecha: "2023-10"
  perdida: "$175K"
  causa_raiz: "Price manipulation"
  categoria: "Price manipulation via thin liquidity"
  vector: "Attacker manipulated pool price in thin liquidity conditions"
  leccion: "See dex-003. Minimum liquidity thresholds before enabling trading are essential."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-003, dex-009]
  tags: [price-manipulation, thin-liquidity, real-exploit]

- id: dex-incident-013
  name: "Palmswap exploit"
  fecha: "2023-07"
  perdida: "$900K"
  causa_raiz: "Business logic flaw"
  categoria: "Business logic"
  vector: "Logic flaw in perpetual DEX allowing profit extraction"
  leccion: "Perpetual DEX logic (funding rates, PnL calculation) needs dedicated invariants beyond spot AMM patterns."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001]
  tags: [business-logic, perpetual, real-exploit]

- id: dex-incident-014
  name: "SteamSwap exploit"
  fecha: "2024-06"
  perdida: "$91K"
  causa_raiz: "Logic flaw in swap"
  categoria: "Business logic"
  vector: "Logic error in swap implementation allowed value extraction"
  leccion: "Custom swap implementations that deviate from proven patterns are high risk."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-001]
  tags: [logic-flaw, swap, real-exploit]

- id: dex-incident-015
  name: "CurveBurner exploit"
  fecha: "2023-08"
  perdida: "$36K"
  causa_raiz: "Missing slippage protection in burn path"
  categoria: "Slippage protection bypass"
  vector: "Burn/fee distribution path lacked slippage protection, enabling sandwich attack"
  leccion: "Slippage protection needed on ALL swap paths including internal burns and fee conversions. See dex-008."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [dex-008, dex-004]
  tags: [slippage, burn, fee-conversion, real-exploit]

- id: dex-041
  pattern: rebalance-no-slippage-protection-concentrated-liquidity
  name: "Keeper/automator rebalanceAll() sin slippage protection — sandwich en retirada+redeposit de liquidez concentrada"
  causa_raiz: >
    En vaults de liquidez concentrada (Uniswap V3), cuando el keeper o automator ejecuta
    `rebalanceAll()` / `rerange()` / `rebalance()` para ajustar el rango de ticks, la operación
    implica: (1) retirar toda la liquidez del rango actual, (2) hacer un swap de rebalanceo,
    (3) depositar en el nuevo rango. Si amount0Min/amount1Min son cero en removeLiquidity y
    addLiquidity, cualquiera puede sandwichear la transacción completa, extrayendo valor del vault.
    La ausencia de checkDeviation o TWAP-check en el momento de rebalanceo es equivalente.
  como_funciona: |
    Pool tiene: token0=1000, token1=1000 en rango [tickA, tickB]
    Keeper llama rebalanceAll(tickC, tickD) — nuevo rango fuera del actual.
    Atacante: swap masivo token0→token1 antes del rebalanceo → precio se mueve.
    Keeper retira liquidez y redeposita al precio manipulado (recibe menos token1 de lo esperado).
    Atacante: swap inverso después → restaura precio, queda con profit extraído del vault.
    En RealWagmi: removeLiquidity y addLiquidity sin amount0Min/amount1Min → sandwich completo.
    En Maia DAO/Talos: init() no tiene el checkDeviation modifier que sí tienen deposit/rebalance.
  invariante: |
    // Todo rebalanceo debe verificar que el precio spot no desvía del TWAP
    // Y que los amounts recibidos/depositados son razonables
    int56[] memory tickCumulatives = pool.observe([secondsAgo, 0]);
    int24 twapTick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(int32(secondsAgo)));
    int24 deviation = currentTick > twapTick ? currentTick - twapTick : twapTick - currentTick;
    assert(deviation <= maxTWAPTickDifference); // Check ANTES del rebalanceo
    // También: amount0Received >= amount0Expected * (1 - slippageTolerance)
    assert(amount0Received >= amount0Min && amount1Received >= amount1Min);
  preguntas_clave:
    - "¿`rebalanceAll()` o función equivalente pasa amount0Min=0 a removeLiquidity/addLiquidity?"
    - "¿Hay TWAP-check o price deviation check antes de ejecutar el rebalanceo?"
    - "¿Quién puede llamar a rebalance — solo keeper confiable o cualquiera?"
    - "¿El init() inicial tiene la misma protección que deposit/rebalance posteriores?"
    - "rg 'rebalanceAll|rerange|rebalance' --type sol | grep -v 'amount.*Min'"
  como_se_arregla: >
    Agregar checkDeviation (verificación TWAP ± N ticks) al inicio de todas las funciones de
    rebalanceo incluyendo init(). Pasar amount0Min y amount1Min no-cero a removeLiquidity y
    addLiquidity calculados a partir del precio TWAP con tolerancia. Alternativamente, requerir
    que el caller pase sus propios parámetros de slippage (como en Uniswap Router).
  trampas:
    - "checkDeviation ya puede existir en deposit/rebalance pero NO en init() — el gap es específico"
    - "El keeper puede ser confiable hoy pero comprometido/griefed mañana — defensa en profundidad"
    - "Si la pool tiene muy poca liquidez, el TWAP puede manipularse con menos capital"
    - "Sherlock (RealWagmi) consideró HIGH por pérdida directa sin condiciones previas"
  solodit_ids: []
  incidentes:
    - "RealWagmi (Sherlock 2023-06, H-2): rebalanceAll sin slippage en removeLiquidity/addLiquidity — HIGH, solodit.xyz/issues/h-2-no-slippage-protection-when-withdrawing-and-providing-liquidity-in-rebalanceall-sherlock-none-realwagmi-git"
    - "Maia DAO/Talos (Code4rena 2023, H-10): TalosBaseStrategy.init() sin checkDeviation modifier presente en deposit/rebalance — HIGH, solodit.xyz/issues/h-10-talosbasestrategyinit-lacks-slippage-protection-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git"
    - "Radiant June (Pashov 2024, M-07): rebalance() en UniV3 LP sin slippage check, vulnerable a sandwich — MEDIUM, solodit.xyz/issues/m-07-lack-of-slippage-check-in-rebalance-function-pashov-audit-group-none-radiant-june-markdown"
    - "Arrakis (Sherlock 2023-06, M-3): slippage bypass en multi-fee-tier rebalancing — MEDIUM"
  severidad: high
  confianza: alta
  fuente: "Solodit"
  verificado: true
  relacionado_con: [dex-008, dex-042]
  tags: [dex, concentrated-liquidity, automator, keeper, rebalance, slippage, sandwich, uniswap-v3, twap, arrakis, realwagmi, maia-dao]

- id: dex-042
  pattern: autocompound-reward-swap-amountout-zero
  name: "Auto-compounder reinvierte fees/rewards con amountOutMin=0 — sandwich extrae valor de todos los holders"
  causa_raiz: >
    Los contratos de auto-compounding (AutoCompounder, estrategias que reinvierten rewards)
    ejecutan swaps de reward tokens → LP tokens sin protección de slippage: pasan `amountOutMin=0`
    al router. Esto permite que cualquier MEV bot sandwichee la transacción de compounding y
    extraiga valor que debería beneficiar a los LP holders. El problema se amplifica porque
    (1) compound es a menudo permissionless (cualquiera puede triggerearlo), (2) el swap suele
    ser en un pool de poca liquidez (reward token → WETH → LP token), (3) el timing del
    compounding es predecible (acumulación de rewards visible on-chain).
  como_funciona: |
    AutoCompounder acumula rewards R (e.g., VELO, OP, CRV).
    Keeper/anyone llama autoCompound() que swapea R → token0+token1 y redeposita.
    Sin amountOutMin: recibe R_in_value pero solo output = R_in_value * (1 - slippage%).
    Atacante sandwichea: compra token0 antes (sube precio), compound recibe menos, vende después.
    En Velodrome: AutoCompounder.sol#L78 pasa amountOutMin=0 en ambas piernas del swap.
    En Fuji: harvestRewards llama getSwapTransaction con minOutput=0 en todos los casos.
    El costo recae sobre todos los holders del vault/veNFT — extracción socializada.
  invariante: |
    // El output del swap de compounding debe ser >= valor equivalente al input (menos fee legítimo)
    uint256 valueIn = oracle.price(rewardToken) * amountIn / 1e18;
    uint256 valueOut = oracle.price(outputToken) * amountOut / 1e18;
    // Tolerance: pool fee (0.05%-1%) + max acceptable slippage
    uint256 maxSlippage = poolFee + 200; // 200 bps = 2%
    assert(valueOut >= valueIn * (10000 - maxSlippage) / 10000);
  preguntas_clave:
    - "¿El compound/harvest swap usa amountOutMin=0 o un valor hardcodeado bajo?"
    - "¿La función es permissionless (cualquiera puede triggerear el compound)?"
    - "¿Hay una verificación TWAP/oracle para calcular el amountOutMin esperado?"
    - "¿El reward token tiene suficiente liquidez para que el slippage sea significativo?"
    - "rg 'amountOutMin|minAmountOut|_minOut' --type sol | rg '= 0'"
    - "rg 'compound|harvest|reinvest' --type sol -l"
  como_se_arregla: >
    Calcular amountOutMin desde un oracle TWAP: amountOutMin = oraclePrice * amountIn * (1 - maxSlippage).
    Alternativamente, permitir que el keeper pase sus propios parámetros de slippage y validar
    que el caller no puede establecerlos en cero (permissioned compound con slippage verificado
    por el protocolo). Añadir un deadline. Considerar hacer compound solo permissioned-keeper
    para reducir superficie de ataque MEV.
  trampas:
    - "El compound puede ser infrecuente — el slippage por operación puede ser bajo en tokens líquidos"
    - "Si el reward token es muy ilíquido, el slippage es alto per-se — el límite debe ser más amplio"
    - "Algunos protocolos usan relayers que calculan amountOutMin off-chain — verificar si eso aplica"
    - "Velodrome clasificó esto como MEDIUM (no HIGH) porque requiere pools activos con liquidez"
  solodit_ids: []
  incidentes:
    - "Velodrome Finance (Spearbit 2023, MEDIUM): AutoCompounder.sol#L78 y #L91 pasan amountOutMin=0 al swap de VELO rewards — solodit.xyz/issues/lack-of-slippage-control-during-compounding-spearbit-none-velodrome-finance-pdf"
    - "Fuji Protocol (Consensys 2022): FujiVaultFTM.harvestRewards genera swap con minOutput=0 en todos los casos — solodit.xyz/issues/missing-slippage-protection-for-rewards-swap-consensys-fuji-protocol-markdown"
    - "Radiant V2 (OpenZeppelin 2023, MEDIUM): selfCompound y hunter claim con slippage tolerances demasiado grandes — solodit.xyz/issues/slippage-tolerances-may-be-too-large-openzeppelin-none-radiant-v2-audit-markdown"
  severidad: medium
  confianza: alta
  fuente: "Solodit"
  verificado: true
  relacionado_con: [dex-008, dex-041]
  tags: [dex, autocompound, keeper, slippage, sandwich, mev, amountOutMin, rewards, harvest, velodrome, fuji, permissionless]

- id: dex-incident-016
  name: "Arrakis SimpleManager price deviation check bypass"
  fecha: "2023-06"
  perdida: "Potencial drain de vault (no explotado en producción — Sherlock audit)"
  causa_raiz: "Price deviation check en SimpleManager bypasseable manipulando pool antes del check"
  categoria: "Slippage protection bypass + Keeper/operator exploit"
  vector: >
    El check de desviación de precio en SimpleManager se calcula contra el pool de Uniswap V3
    sobre el que se está haciendo el rebalanceo. Un operador malicioso puede manipular el precio
    del pool inmediatamente antes de llamar a rebalance(), pasando el check con precio manipulado,
    añadir liquidez al precio desfavorable, y luego backrunear para extraer valor del vault.
    El check compara spot price vs TWAP, pero si el TWAP es corto (pocos segundos), es
    manipulable en el mismo bloque. En Arrakis V2, el executor tiene acceso a parámetros de
    rebalanceo sin rate-limiting adecuado — con suficientes llamadas puede drenar el vault.
  leccion: >
    El check anti-manipulación debe basarse en TWAP de al menos 30 minutos, no spot price.
    El operador/executor debe estar sujeto a rate limiting (máximo loss por llamada Y por día).
    El check debe ser resistente a manipulación del mismo pool que protege.
    Ver Arrakis Valantis (2024): executor pudo drenar via rebalance + minting shares baratas.
  verificado: true
  fuente: "Solodit — Sherlock Arrakis 2023-06 (H-1, M-2, M-3)"
  relacionado_con: [dex-008, dex-041]
  tags: [arrakis, keeper, operator, rebalance, price-deviation, twap-manipulation, drain-vault, concentrated-liquidity, uniswap-v3, real-audit]

- id: dex-044
  pattern: autocompounder-fake-factory-reward-theft
  name: "AutoCompounder con ALLOWED_CALLER inyecta factory falsa para robar todos los rewards acumulados"
  causa_raiz: >
    Protocolos que permiten a un caller autorizado (ALLOWED_CALLER) llamar funciones de claim/compound
    en nombre de un AutoCompounder aceptan la factory como parámetro externo sin validar que sea
    la factory legítima del protocolo. El ALLOWED_CALLER puede pasar una factory maliciosa que
    devuelve un contrato arbitrario como destino de los rewards, redirigiendo todos los tokens
    acumulados al atacante en lugar de al compounder legítimo.
  como_funciona: |
    1. Protocolo tiene AutoCompounder que acumula rewards para usuarios.
    2. ALLOWED_CALLER (dirección autorizada) puede llamar claimRewards(factory, ...) en nombre del compounder.
    3. La función no valida que `factory` sea la factory oficial del protocolo.
    4. Atacante con rol ALLOWED_CALLER despliega FakeFactory que devuelve una dirección controlada.
    5. Llama claimRewards(fakeFactory, ...) → rewards van al contrato del atacante.
    6. Todos los rewards acumulados (potencialmente de múltiples usuarios) se drenan.
  invariante: >
    // Factory usada en claim/compound debe ser la factory oficial del protocolo
    address officialFactory = protocol.factory();
    // Si el compounder llama cualquier función con una factory externa, esa factory debe ser la oficial
    assert(factory == officialFactory);
    // Los rewards solo deben ir al beneficiario configurado, no a direcciones arbitrarias
  que_mirar:
    - "¿Las funciones de claim/compound aceptan `factory` como parámetro externo en lugar de usar la factory hardcoded?"
    - "¿El rol ALLOWED_CALLER o equivalente puede pasar parámetros de dirección sin validación?"
    - "¿Se valida que `factory.isPool()` o `factory.isRegistered()` antes de usar la dirección?"
    - "rg 'ALLOWED_CALLER\\|allowedCaller\\|authorizedCaller' --type sol"
    - "rg 'factory.*param\\|address.*factory' --type sol | rg 'claim\\|compound\\|reward'"
  como_se_arregla: >
    Hardcodear la factory oficial como constante inmutable en el constructor del AutoCompounder.
    Nunca aceptar addresses de factory como parámetros en funciones de claim/compound.
    Si se necesita flexibilidad, usar un registry oficial que solo el owner pueda actualizar.
    Añadir: `require(factory == OFFICIAL_FACTORY, "Invalid factory")`.
  trampas:
    - "El rol ALLOWED_CALLER puede ser semi-trusted (no el owner) — el bug existe aunque el caller sea conocido"
    - "El patrón aparece en cualquier protocolo con rewards multi-vault donde la factory se pasa como argumento"
    - "Buscar también en funciones de `harvest`, `compound`, `collectFees` que acepten address params"
    - "A veces el fix incorrecto valida solo que factory != address(0) en lugar de que sea la factory oficial"
  solodit_ids: []
  incidentes:
    - "Velodrome Finance — Spearbit 2023: ALLOWED_CALLER can steal all rewards from AutoCompounder using a fake factory (Medium) — solodit.xyz"
    - "Daoslive — Fee Theft via Arbitrary Contract Impersonation in collect() Function (High) — solodit.xyz"
    - "PoolTogether — Liquidators can be tricked to operate with LiquidationPairs that were deployed by an attacker (Medium) — solodit.xyz"
  severidad: high
  confianza: alta
  fuente: "Solodit: Velodrome Finance (Spearbit, M), Daoslive (H-04), PoolTogether (M-07)"
  verificado: true
  tags: [autocompounder, fake-factory, reward-theft, allowed-caller, access-control, velodrome, uniswap-v3, automator]
  relacionado_con: [dex-043, dex-041]

- id: dex-045
  pattern: v3-fee-collection-frontrun-deposit-capture
  name: "Front-run de collectEarnings() en V3: atacante deposita antes de la colecta para capturar fees acumuladas de otros LPs"
  causa_raiz: >
    En vaults que gestionan posiciones Uniswap V3, la función que colecta fees (collectEarnings,
    harvest, collectFees) es pública o llamable por keepers sin restricción de timing. Las fees
    se acumulan por tiempo en la posición. Un atacante puede monitorear el mempool, ver que
    collectEarnings() va a ejecutarse, y front-runear la transacción depositando al vault justo
    antes. La distribución de fees incluye al atacante en proporción a sus shares recién mintadas,
    permitiéndole capturar fees acumuladas por LPs legítimos que llevaban tiempo en el vault.
  como_funciona: |
    1. Vault V3 acumula fees en la posición (token0/token1) durante días/semanas.
    2. Atacante monitorea mempool y detecta transacción collectEarnings() de un keeper.
    3. Atacante front-corre con un gran depósito al vault → recibe shares proporcionales.
    4. collectEarnings() ejecuta: fees se distribuyen a todos los holders de shares incluyendo atacante.
    5. Atacante retira inmediatamente capturando fees acumuladas por otros LPs sin haberlas ganado.
    6. Variante: el atacante también puede re-entrar en el callback de la posición si el vault no usa ReentrancyGuard.
  invariante: >
    // Las fees colectadas deben distribuirse SOLO a shares que existían ANTES de la colecta
    uint256 sharesBefore = vault.totalSupply();
    uint256 attackerSharesBefore = vault.balanceOf(attacker);
    vault.collectEarnings();
    // Si el atacante depositó justo antes, su parte de fees no debe incluir fees pre-depósito
    // Una forma: snapshot de shares en el inicio de cada epoch de fees
    assert(vault.claimableFees(attacker) / vault.totalFees() <= attackerSharesBefore / sharesBefore);
  que_mirar:
    - "¿collectEarnings()/harvest() es llamable por cualquiera sin restricción de timing o snapshot?"
    - "¿Las fees se distribuyen pro-rata a shares actuales o a shares en el momento de acumulación?"
    - "¿Hay protección contra depósito-colecta-retiro en la misma transacción o mismo bloque?"
    - "¿El vault usa algún mecanismo de fee-epoch o checkpoint antes de distribuir?"
    - "rg 'collectFees\\|collectEarnings\\|harvest\\|collect' --type sol | rg 'totalSupply\\|shares'"
  como_se_arregla: >
    Implementar un sistema de fee-epochs: snapshot de shares antes de colectar, distribuir fees
    solo a holders del snapshot. Alternativamente, aplicar un cooldown mínimo entre depósito y
    elegibilidad para recibir fees colectadas. O usar un sistema de streaming donde las fees se
    acumulan por segundo por share (como Synthetix staking rewards) en lugar de en lotes.
  trampas:
    - "Este ataque también aplica a AutoCompound de Revert Lend — si el compounding es público y front-runeable"
    - "La variante con 're-entry en range re-entry' (Burve H-5) es más compleja: el atacante deposita cuando el pool tick re-entra al rango del vault"
    - "Distinguir de sandwich attack clásico: aquí no hay swap, solo timing de depósito vs colecta"
    - "Vaults con lockup mínimo post-depósito resuelven esto pero añaden UX friction"
  solodit_ids: []
  incidentes:
    - "Mellow Protocol — [H-03] UniV3Vault.sol#collectEarnings() can be front run (High, Code4rena 2023) — solodit.xyz"
    - "Burve — H-5: Attacker captures unclaimed fees by timing deposit with range re-entry and withdrawal (High) — solodit.xyz"
    - "Yearn Finance — Sandwich attack on user withdrawal: strategy fees sandwichable by timing deposit (High) — solodit.xyz"
  severidad: high
  confianza: alta
  fuente: "Solodit: Mellow Protocol (H-03, Code4rena), Burve (H-5), Yearn Finance (H)"
  verificado: true
  tags: [uniswap-v3, frontrun, fee-capture, collectEarnings, vault, deposit-timing, autocompound, mellow, burve]
  relacionado_con: [dex-041, dex-042, dex-009]

- id: dex-046
  pattern: operator-rebalance-no-rate-limit-vault-drain
  name: "Operador drena vault mediante llamadas repetidas a rebalance() sin rate limiting ni verificación de posición neta"
  causa_raiz: >
    Vaults de liquidez concentrada (Uniswap V3, Valantis SOT, etc.) con un rol de operador/executor
    semi-trusted que puede llamar rebalance() o setModule() sin cooldown. Cada llamada a rebalance
    incurre en costos reales: swap fees del AMM (0.05-1%), slippage en el swap interno, y a veces
    fees del protocolo. Un operador malicioso (o comprometido) puede llamar rebalance() repetidamente
    con parámetros válidos pero sub-óptimos, acumulando pérdidas que van al AMM/MEV bots mientras
    el vault pierde valor lentamente. La variante más severa (Arrakis H-3) permite al executor
    drenar 100% de las reservas en una sola transacción vía setModule() con un módulo malicioso.
  como_funciona: |
    1. Vault tiene operador/executor con permiso de llamar rebalance(newRange, swapData).
    2. No hay cooldown entre llamadas (ningún CHECK de tiempo mínimo entre rebalances).
    3. Operador llama rebalance() 100x en poco tiempo con rangos ligeramente distintos.
    4. Cada llamada: vault retira liquidez → swap para rebalancear → añade liquidez → paga fees AMM.
    5. Acumulación: 0.3% fee × 100 llamadas = 30% de los activos del vault perdidos en fees/slippage.
    6. Variante severa: setModule() sin validación permite reemplazar el módulo de liquidez por uno malicioso
       que drena el 100% en una llamada.
  invariante: >
    // Debe existir un cooldown mínimo entre rebalances
    uint256 lastRebalance = vault.lastRebalanceTimestamp();
    // assert(block.timestamp - lastRebalance >= MIN_REBALANCE_COOLDOWN)
    // El valor del vault no debe decrecer más de MAX_LOSS_BPS por rebalance
    uint256 valueBefore = vault.totalValue();
    vault.rebalance(...);
    uint256 valueAfter = vault.totalValue();
    assert(valueBefore - valueAfter <= valueBefore * MAX_LOSS_BPS / 10000);
  que_mirar:
    - "¿rebalance() tiene un cooldown o rate limit por tiempo o por bloque?"
    - "¿Se verifica que el nuevo rango es realmente mejor que el actual antes de ejecutar?"
    - "¿setModule() o equivalente que cambia la lógica del vault requiere timelock o multisig?"
    - "¿El operador puede elegir arbitrariamente el swap path y slippage del rebalance?"
    - "rg 'rebalance\\|setModule\\|executor\\|operator' --type sol | rg 'onlyOperator\\|onlyExecutor'"
  como_se_arregla: >
    Implementar MIN_REBALANCE_INTERVAL (e.g., 1 hora) entre llamadas a rebalance().
    Añadir validación de posición neta: el vault debe mejorar o mantener su rango de eficiencia.
    Para setModule(): usar timelock de 48h mínimo y multisig. Limitar el slippage máximo permitido
    por llamada. Considerar un circuit breaker que pause si el vault pierde >X% en 24h.
  trampas:
    - "El operador puede ser un contrato Gelato/Chainlink upkeep que se activa automáticamente — revisar las condiciones de trigger"
    - "La pérdida es gradual (Medium) vs inmediata (High) — depende de si setModule() está disponible"
    - "Arrakis H-3 es la variante más severa: executor puede drenar 100% vía setModule con módulo falso"
    - "En Revert Lend, los keepers de AutoRange tienen control sobre el nuevo rango — verificar si pueden elegir rangos sub-óptimos repetidamente"
  solodit_ids: []
  incidentes:
    - "Arrakis Finance — M-2: Lack of rebalance rate limiting allow operators to drain vaults (Medium, Spearbit 2023) — solodit.xyz"
    - "Arrakis Valantis SOT — H-3: Through rebalance(), an executor can drain 100% of vault reserves by minting (High) — solodit.xyz"
    - "Arrakis Valantis SOT — H-4: ArrakisMetaVault::setModule Malicious executor can drain the vault (High) — solodit.xyz"
    - "GammaSwap — [M-02] rebalancePosition() transaction is susceptible to frontrunning (Medium, 2024) — solodit.xyz"
  severidad: high
  confianza: alta
  fuente: "Solodit: Arrakis Finance (Spearbit M-2), Arrakis Valantis SOT (H-3, H-4), GammaSwap (M-02)"
  verificado: true
  tags: [vault, operator, rebalance, rate-limit, drain, arrakis, autorange, uniswap-v3, keeper, executor]
  relacionado_con: [dex-041, dex-042, dex-043]

- id: dex-047
  pattern: vault-owner-frontrun-automation-lower-incentive
  name: "VaultOwner front-corre al keeper de rebalance con setAutomation() para reducir la recompensa antes de que se ejecute"
  causa_raiz: >
    En protocolos con vaults de liquidez V3 donde el owner del vault puede ajustar la recompensa
    del keeper (maxFee, incentiveBPS, automationParams) en cualquier momento, el owner puede
    monitorear el mempool y front-correr la transacción del keeper para reducir la recompensa
    a cero (o al mínimo) justo antes de que ejecute el rebalance. El keeper realiza el trabajo
    costoso (rebalancear la posición) pero recibe una compensación inferior a la esperada.
    Caso inverso: el owner puede aumentar la fee esperada para atraer keepers y luego reducirla
    al ejecutar, pagando menos de lo prometido.
  como_funciona: |
    1. Vault tiene función setAutomation(params) que controla la fee/incentivo del keeper.
    2. Keeper ve que la vault está fuera de rango y que la fee es atractiva (e.g., 0.5%).
    3. Keeper construye y envía transacción rebalance().
    4. VaultOwner ve la tx del keeper en mempool y front-corre con setAutomation(fee=0.001%).
    5. Keeper ejecuta el rebalance pero recibe una fracción mínima de la fee esperada.
    6. Keepers aprenden que este vault no es rentable → no monitorean → posición queda desatendida.
    Resultado: keeper griefing indirecto — el vault se vuelve inoperable por falta de keepers.
  invariante: >
    // La fee del keeper no debe poder cambiar entre el momento en que el keeper la leyó y la ejecución
    // Solución: commitFee pattern — la fee se fija al momento de iniciar la transacción
    uint256 feeAtStart = vault.getKeeperFee();
    // La fee no debe reducirse en el mismo bloque o en los N bloques anteriores a la ejecución
    // assert(vault.feeLastChanged() + MIN_FEE_DELAY <= block.number);
  que_mirar:
    - "¿setAutomation()/setKeeperFee() puede llamarse en cualquier momento sin delay?"
    - "¿La fee del keeper se verifica al inicio de la transacción y se paga al final sin posibilidad de cambio intermedio?"
    - "¿Hay un timelock o delay mínimo entre cambios de parámetros de automatización?"
    - "¿El keeper puede especificar una fee mínima aceptable (minKeeperReward) como parámetro?"
    - "rg 'setAutomation\\|setKeeperFee\\|automationParams\\|keeperReward' --type sol"
  como_se_arregla: >
    Añadir un timelock mínimo (e.g., 1 hora o 300 bloques) entre llamadas a setAutomation().
    Permitir que el keeper especifique un parámetro `minReward` y revertir si la fee actual es menor.
    Usar un sistema de commit-reveal para la fee: el owner hace commit de la nueva fee con delay.
    Alternativamente, fijar la fee como porcentaje hardcoded del profit generado por el rebalance.
  trampas:
    - "Mimo DeFi M-07: esto es Medium porque el griefing no genera profit directo para el owner, solo perjudica al keeper"
    - "La variante Mimo H-02 (automation para vault no existente) es más severa — permite configurar trampas"
    - "En Revert Lend, los params de AutoExit/AutoRange incluyen maxGasTipCap y rewardX64 — verificar si son front-corredores"
    - "El impacto real depende de si hay competencia entre keepers: si solo hay 1 keeper, el griefing es DoS"
  solodit_ids: []
  incidentes:
    - "Mimo DeFi — [M-07] vaultOwner Can Front-Run rebalance() With setAutomation() To Lower Incentive (Medium, Code4rena 2023) — solodit.xyz"
    - "Mimo DeFi — [H-02] Automation/management can be set for not yet existing vault (High) — solodit.xyz"
    - "Primex Finance — Front-Run Keeper Rewards: keeper rewards front-runnable by observing mempool (Medium) — solodit.xyz"
  severidad: medium
  confianza: alta
  fuente: "Solodit: Mimo DeFi (M-07, Code4rena), Mimo DeFi (H-02), Primex Finance (M, keeper frontrun)"
  verificado: true
  tags: [keeper, frontrun, automation, setAutomation, incentive, griefing, vault-owner, autorange, autoexit, revert-lend]
  relacionado_con: [dex-043, dex-046]

- id: dex-043
  pattern: keeper-fee-claim-no-work-validation
  name: "Keeper recibe fee llamando función con arrays vacíos — ausencia de validación de trabajo realizado"
  causa_raiz: >
    Protocolos que pagan fees a keepers por ejecutar operaciones de mantenimiento (settle,
    execute, liquidate, rebalance) deben validar que el keeper efectivamente realizó trabajo.
    Si la función que emite el fee no valida que los arrays de parámetros son no-vacíos, o
    que el trabajo procesado fue positivo (N items > 0), cualquier address puede llamarla
    con arrays vacíos, recibir el fee sin hacer nada, y repetir indefinidamente hasta drenar
    el pool de fees del protocolo.
  como_funciona: |
    Perennial V2: KeeperFactory.settle(accounts[], versions[], maxCounts[]) paga una fee al caller.
    Si accounts=[], versions=[], maxCounts=[] → el bucle interno no itera, no se hace trabajo.
    Pero la fee se emite de todas formas porque el chequeo `if (length == 0) revert` falta.
    Atacante llama settle([], [], []) en un loop hasta drenar todas las keeper fees del contrato.
    Costo del ataque: solo gas por llamada. Ganancia: todas las fees acumuladas.
    Patrón genérico: cualquier función de la forma `payKeeperFee(doWork(params))` donde
    `doWork([])` devuelve success sin hacer nada.
  invariante: |
    // Si el keeper recibe una fee, debe haber procesado al menos 1 item
    uint256 itemsBefore = pendingSettlements.length; // o similar contador
    keeperFactory.settle(accounts, versions, maxCounts);
    uint256 itemsAfter = pendingSettlements.length;
    // Fee pagada debe ser proporcional a items procesados
    uint256 itemsProcessed = itemsBefore - itemsAfter;
    assert(itemsProcessed > 0 || feePaid == 0);
  preguntas_clave:
    - "¿La función que paga fee al keeper valida que `params.length > 0` antes de procesar?"
    - "¿El pago de fee ocurre antes o después de la validación del trabajo?"
    - "¿Puede el keeper llamar la función con parámetros mínimos (1 item dummy) que no hacen trabajo real?"
    - "¿Hay un rate limit o cooldown por address para reclamar fees?"
    - "rg 'keeperFee|payKeeper|asyncFee|settleReward' --type sol"
    - "rg 'settle\\|execute\\|request' --type sol | rg 'fee\\|reward\\|payment'"
  como_se_arregla: >
    Agregar validación al inicio: `require(accounts.length > 0, "no work")`.
    Pagar fee proporcional a items procesados (no flat fee por llamada).
    Considerar rate limiting por address. Alternativamente, calcular la fee solo después
    de confirmar que N > 0 items fueron efectivamente procesados, y revertir si N=0.
  trampas:
    - "Sherlock (Perennial V2 Update #1) clasificó esto como HIGH — fee drain directa sin trabajo"
    - "Si la fee es pequeña por llamada pero el protocolo tiene mucho TVL acumulado, el drain es grande"
    - "Buscar funciones en la misma familia: claim, harvest, collect, settle, execute, request"
    - "A veces el fix está en la función caller (KeeperFactory) no en el contrato de fees"
  solodit_ids: []
  incidentes:
    - "Perennial V2 Update #1 (Sherlock 2023-10, H-4): KeeperFactory.settle() con arrays vacíos paga fee sin trabajo — HIGH, solodit.xyz/issues/h-4-attacker-can-call-keeperfactorysettle-with-empty-arrays-as-input-parameters-to-steal-all-keeper-fees-sherlock-perennial-v2-update-1-git"
  severidad: high
  confianza: alta
  fuente: "Solodit"
  verificado: true
  relacionado_con: [dex-042]
  tags: [dex, keeper, fee-drain, access-control, empty-array, validation, permissionless, perennial, automator, settlement]
```

---

## 3. Invariant Checklist (Quick Reference)

| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| DEX-INV-001 | k_after >= k_before for every swap | 1 | constant product |
| DEX-INV-002 | LP mint-then-burn returns <= deposited | 1 | share math |
| DEX-INV-003 | reserve0 * reserve1 monotonically non-decreasing | 1 | core AMM |
| DEX-INV-004 | sum(LP balances) == LP totalSupply | 1 | token accounting |
| DEX-INV-005 | actual token balances >= internal reserves | 1 | INV-EXPLOIT-012 |
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0) | 1 | INV-EXPLOIT-016 |
| DEX-INV-007 | spot price deviation from TWAP < MAX_PCT | 2 | INV-EXPLOIT-001 |
| DEX-INV-008 | fee deducted <= amount transacted | 1 | INV-EXPLOIT-008 |
| DEX-INV-009 | no profit from sandwich (attacker_out <= attacker_in) | 1 | COMP-MULTI-001 |
| DEX-INV-010 | active liquidity == sum(position liquidity in active range) | 1 | tick math |

**Tier 1** = hard fail = confirmed bug. **Tier 2** = needs review, may have tolerance.

---

## 4. Grep Targets

```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp
swap(
getAmountOut
getAmountIn
mint(
burn(
flash(
MINIMUM_LIQUIDITY
feeGrowthGlobal
feeProtocol
observe(
consult(
tickBitmap
cross(
```

---

## 5. Fuzzing Priority

1. **Constant product**: k_after >= k_before after every swap (no tolerance)
2. **Solvency**: actual token balance >= internal reserve tracking
3. **Sandwich resistance**: attacker profit <= 0 across front-run + back-run
4. **LP share fairness**: mint-then-immediate-burn returns <= input (1 wei tolerance)
5. **Tick boundary**: swap across multiple ticks produces correct output
6. **Fee consistency**: total fees collected == sum(per-operation fees)
7. **Slippage enforcement**: final output >= user-specified minimum

Run Medusa for stateful multi-swap sequences. Use Echidna optimization to maximize sandwich profit.

---

## Solodit Verified Findings

> Source: Solodit audit database. Only findings adding new information beyond DeFiHackLabs incidents are included.

### Maps to dex-004 / dex-008 (Sandwich Attack / Slippage Protection Bypass)

- **[HIGH] Deposit and withdraw functions susceptible to sandwich attacks (Aera Vault)** — Vault deposit/withdraw functions interact with Balancer pools without slippage protection; attacker sandwiches vault rebalancing operations, not just user swaps.
- **[HIGH] Lack of slippage protection leads to loss of protocol funds (Cork Protocol)** — Protocol-level swaps during internal operations (not user-initiated) use zero slippage, making protocol treasury funds sandwichable.
- **[HIGH] No slippage protection when interacting with AMM** — amount0Min and amount1Min set to zero during Uniswap router interactions for swaps AND liquidity additions; both paths are sandwichable.
- **[HIGH] Insufficient slippage protection in redeemEarlyLv leads to MEV** — Flash swap-based early redemption has slippage check only on RA output, not on the intermediate swap, enabling MEV extraction on the unprotected leg.
- **[HIGH] Illuminate's PT doesn't respect users' slippage specifications** — Protocol accepts user slippage param but applies more permissive internal slippage, silently overriding user protection.
- **[HIGH] Missing Slippage Checks in get_lp_by_cake** — Swap functions lack oracle-price-based slippage validation; slippage check exists but is against zero, not a meaningful minimum.
- **[HIGH] Calling TermMaxMarket.setLsf leaks value via sandwich attack** — Admin parameter change (liquidity sensitivity factor) causes AMM price shift; attacker sandwiches the admin tx to extract the delta.
- **[HIGH] Attackers exploit yield distribution through onUnderlyingBalanceUpdate() sandwiching** — Vault yield accrual function is sandwichable; attacker deposits before yield event, captures disproportionate share, withdraws immediately after.
- **[HIGH] Uniswap V3 swap in commitAndClose susceptible to sandwich** — Vault closure triggers a large Uniswap swap with zero slippage protection, creating a guaranteed sandwich opportunity.
- **[HIGH] Sandwich attack on user withdrawal (Yearn SNX Strategy)** — Strategy uses AMM swap during user withdrawal; attacker front-runs withdrawal tx to manipulate swap price.
- **[MEDIUM] Attacker can force reduce minAmountOut from vault swaps** — Attacker manipulates oracle or price feed to lower the protocol-calculated minAmountOut, widening the sandwich window.
- **[MEDIUM] Sandwich attack on loan fulfillment temporarily prevents fund access** — Protocol doesn't withdraw from Aave immediately on loan creation; attacker can sandwich the delayed withdrawal to manipulate Aave liquidity.
- **[MEDIUM] Missing slippage parameter in buyToken()** — Bonding curve buy function lacks slippage param entirely; between getEthValueForTradeWithFee() query and execution, price can move.
- **[MEDIUM] Possible sandwich attack when buying a coin (GroupcoinFactory)** — buy() function has no slippage protection; msg.value is accepted but no minimum tokens output is enforced.
- **[MEDIUM] Sandwich attack on Astroport sweep** — Collector contract's sweep function swaps accumulated fees without slippage; anyone can trigger it and sandwich the swap.
- **[MEDIUM] reLPContract.reLP() susceptible to sandwich via user bond()** — User-triggered bond() calls reLP() which performs a large swap; attacker times their bond() to trigger the sandwichable reLP.
- **[MEDIUM] formPOL lacks slippage and deadline protection** — Protocol-owned liquidity formation swaps have neither slippage nor deadline checks.
- **[MEDIUM] Frontrunning in UniswapHandler calls** — UniswapHandler swap/addLiquidity/removeLiquidity calls to UniswapV2Router all lack slippage protection.

### Maps to dex-007 (Missing Swap Deadline)

- **[MEDIUM] Missing deadline checks allow pending transactions to be maliciously executed** — PaprController swap operations pass block.timestamp as deadline, making the check meaningless; validator can hold and execute at any future time.
- **[MEDIUM] Missing deadline check for AfEth actions** — AfEth deposit/withdraw execute on-chain swaps with no expiration deadline; stale transactions execute at unfavorable prices.

### Maps to dex-003 (Price Impact Manipulation / Thin Liquidity)

- **[HIGH] Reallocation depends on slot0 price, which can be manipulated** — LP position reallocation logic reads Uniswap V3 slot0 for range decisions; attacker manipulates slot0 via flash swap to force reallocation into an unfavorable range.
- **[HIGH] CoreSaltyFeed spot price can lead to price manipulation and undesired liquidations** — Protocol uses spot AMM price as one of its oracle feeds; when Chainlink is unavailable, spot price alone determines liquidations.
- **[HIGH] Pools subject to price manipulation leading to early liquidations** — Chainlink oracle combined with AMM-derived secondary price; attacker manipulates AMM price to trigger liquidations when Chainlink price is near boundary.
- **[HIGH] LP Token Price Manipulation Through Reserve (Steer Protocol)** — BondSteerOracle calculates LP token price from spot reserves rather than TWAP; direct reserve manipulation inflates LP valuation used as collateral.
- **[HIGH] Pool deviation check in SimpleManager on rebalance can be bypassed** — Price deviation guard compares against a manipulable reference; attacker moves price, then rebalances vault into attacker-favorable range.

### Maps to dex-001 (Constant Product Invariant Violation)

- **[HIGH] Stableswap pool can be skewed free of fees (MANTRA DEX)** — Imbalanced liquidity deposits to stableswap pool bypass swap fees; attacker deposits single-sided, then withdraws balanced, effectively swapping without paying fees and skewing pool state.
- **[HIGH] Stableswap does disjoint swaps, breaking the underlying invariant (MANTRA DEX)** — Multi-asset stableswap performs swaps by computing output from isolated pair math rather than the full n-dimensional invariant curve; this breaks the stableswap invariant and allows value extraction.
- **[HIGH] Wrong calculation in LBRouter._getAmountsIn (TraderJoe)** — Helper function for reverse-calculating input amounts has an error for JoePair (V1) paths; user loses excess tokens that are gifted to the pair contract rather than returned.

### Maps to dex-002 (LP Token Mint/Burn Ratio Desync)

- **[HIGH] Vault is vulnerable to inflation attack causing complete loss of user funds (NUMA)** — Classic first-depositor share inflation attack on vault; attacker front-runs first deposit with minimal deposit + large donation to inflate share price.
- **[HIGH] removeLiquidity logic not correct for generalized Well functions other than ConstantProduct** — Beanstalk's generalized AMM framework uses removeLiquidity math that only works for constant-product; other Well functions (e.g., stableswap) produce incorrect LP burn amounts, allowing value extraction.

### Maps to dex-009 (Flash Loan + AMM State Manipulation)

- **[HIGH] Attacker can profit by manipulating Uniswap liquidity (stNXM)** — Protocol reads Uniswap V3 liquidity state for pricing; attacker adds concentrated liquidity at a specific tick to manipulate the price feed, then extracts value from the staking protocol.
- **[HIGH] Vault: Attacker sandwich attacks himself on swaps in open/close/reduce position** — Attacker opens leveraged position via MarginDex (triggering a swap), sandwiches their own swap, creates bad debt that the protocol absorbs; self-sandwiching as a deliberate exploit strategy.

### Maps to dex-010 (Fee Accounting Mismatch)

- **[HIGH] Stableswap pool can be skewed free of fees (MANTRA DEX)** — Single-sided liquidity provision bypasses the swap fee that should be charged for imbalanced deposits; fee-free pool skewing.

### Maps to dex-006 (Tick Boundary Errors)

- **[HIGH] Bin Price Manipulation in CLMM** — CLMM bin-based price can be manipulated by adding liquidity to specific bins and then swapping to move the active bin; bin crossing logic does not adequately prevent concentrated manipulation.

### New patterns not in existing bugs

- **[HIGH] Protocol allows creating broken tri-crypto CPMM pools (MANTRA DEX)** — Pool creation logic allows 3-asset constant-product pools but the swap math only handles 2-asset pairs; broken pool is permanently exploitable for arbitrage. New pattern: pool creation validation mismatch with swap math.
- **[HIGH] MsgValueSimulator with non-zero msg.value calls sender itself, bypassing onlySelf check (zkSync)** — msg.value simulation in zkSync system contract causes recursive call to sender, bypassing onlySelf modifier. New pattern: L2/system-contract msg.value forwarding creates unintended self-calls.
- **[MEDIUM] Frontrunners exploit P2P matching by preventing DLL head from matching** — Attacker front-runs to prevent the head of a doubly-linked list from being matched in P2P lending, forcing liquidity into the pool at worse rates. New pattern: order-matching front-running in P2P systems.
- **[MEDIUM] Dilution of Donations in Tranche (Arcadia)** — Non-atomic donation process allows attacker to dilute a legitimate donation by depositing into the tranche between donation announcement and execution. New pattern: donation dilution via front-running in tranche-based systems.
- **[MEDIUM] Lack of rebalance rate limiting allows operators to drain vaults** — Vault operators (semi-trusted role) can call rebalance repeatedly with no cooldown; each rebalance incurs swap fees/slippage that accumulates as loss to depositors. New pattern: operator rebalance abuse via missing rate limiting.
- **[HIGH] Voting does not account for end of staking lock period (MagicSea)** — Users retain voting power after their staking lock expires; they can vote without any locked stake commitment. Not a traditional DEX bug but affects DEX governance/gauge weight decisions.
- **[MEDIUM] TRST-M-3: base to quote swaps trust GMX-provided minPrice/maxPrice** — Slippage protection relies on GMX vault's own price bounds which can be stale or manipulated; external price oracle should be used instead. New pattern: slippage protection delegated to the venue's own price feed rather than independent oracle.
- **[MEDIUM] Launchpad slippage not enforced properly during token graduation** — During bonding curve graduation to DEX, slippage is checked on the bonding curve side but not on the DEX liquidity provision; graduation transaction is sandwichable at the DEX layer.
- **[HIGH] Oracle Updates Vulnerable to Sandwich Attacks** — Oracle update transactions can be sandwiched; attacker deposits before oracle update, captures price change benefit, withdraws after. New pattern: oracle update sandwiching (distinct from swap sandwiching).
