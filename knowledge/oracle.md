# Oracle Vulnerabilities -- Combat Briefing

Briefing for smart contract auditors. Covers the 8 most exploited oracle bug patterns.
Verified data sourced from `invariant-registry/universal/exploit_derived.json`.

---

## 1. Bugs Conocidos

```yaml
- id: oracle-001
  pattern: chainlink-stale-heartbeat
  name: "Stale price data (Chainlink heartbeat not checked)"
  causa_raiz: >
    latestRoundData() returns updatedAt but callers never compare it against
    block.timestamp. When the Chainlink node stops posting (network congestion,
    feed deprecation, gas spike), the protocol keeps using the last posted price
    which can be hours or days old. Liquidations, borrows, and swaps execute at
    a price that no longer reflects reality.
  como_funciona: >
    1. Attacker monitors Chainlink feed for delayed updates.
    2. Real market price moves significantly from last posted price.
    3. Attacker borrows/swaps using the stale (favorable) price.
    4. When feed updates, protocol is left holding underwater positions.
  invariante: "block.timestamp - updatedAt < MAX_STALENESS && price > 0"
  que_mirar:
    - "latestRoundData() return values -- is updatedAt checked?"
    - "Is MAX_STALENESS defined per feed matching Chainlink heartbeat?"
    - "Is answeredInRound >= roundId checked?"
    - "Does protocol use deprecated latestAnswer() instead of latestRoundData()?"
    - "Fallback oracle path if staleness check fails?"
  como_se_arregla: >
    require(block.timestamp - updatedAt < heartbeat, "stale price");
    require(price > 0, "invalid price");
    require(answeredInRound >= roundId, "stale round");
    Heartbeat must match the specific Chainlink feed (ETH/USD=3600s, exotic=86400s).
  trampas:
    - "Some protocols have fallback oracles that silently handle staleness -- check full path"
    - "Heartbeat varies per feed and per chain -- don't assume 1h for all"
    - "updatedAt == 0 is a valid failure case (feed never initialized)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-015 (defihacklabs)"
  verificado: true
  incidentes_verificados:
    - nombre: "Zenterest"
      fecha: "Aug 2024"
      perdida: "$21K"
      detalle: "Price out of date - stale oracle used for lending decisions"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "CompoundUni"
      fecha: "Feb 2024"
      perdida: "$439.5K"
      detalle: "Oracle returned bad price due to stale/incorrect feed data"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  solodit_ids:
    - m-7-latestrounddata-has-no-check-for-round-completeness-sherlock-isomorph-isomorph-git
    - m-05-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-code4rena-mochi-mochi-contest-git
    - missing-chainlink-oracle-staleness-check-cyfrin-none-licredity-markdown
    - chainlink-oracle-data-may-be-stale-quantstamp-stakestone-vault-markdown
    - should-check-return-data-from-chainlink-aggregator-severity-medium-auditone-none-coinlend-markdown
    - m-15-lacking-validation-of-chainlink-oracle-queries-code4rena-vader-protocol-vader-protocol-contest-git
    - m-02-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-code4rena-phuture-finance-phuture-finance-contest-git
    - l-03-chainlinkadapter-does-not-check-for-round-completeness-which-may-lead-to-stale-data-pashov-none-fyde-markdown
  incidentes:
    - "Licredity — ChainlinkFeedLibrary.getPrice() ignores updatedAt and answeredInRound (MEDIUM)"
    - "API3 — ProductApi3ReaderProxyV1 returns block.timestamp masking stale underlying feeds (MEDIUM)"
    - "Tigris Trade — verifyPrice uses deprecated latestAnswer without staleness check (MEDIUM)"
    - "Connext — getPriceFromChainlink missing staleness and round completeness checks (MEDIUM)"
    - "USSD — calls to oracles across protocol don't check for stale prices (MEDIUM)"
    - "Yield — oracle data feed insufficiently validated, no staleness check (MEDIUM)"
    - "Sentiment — ChainlinkOracle.getPrice() allows stale price without freshness check (MEDIUM)"
    - "Isomorph — latestRoundData() has no check for round completeness (MEDIUM)"
    - "Juicebox — oracle data feed outdated yet used, impacts payment logic (HIGH)"
    - "vusd-stablecoin — stale oracle price not checked before token operations (MEDIUM)"
    - "Blueberry — Chainlink latestRoundData returns stale or incorrect result (MEDIUM)"
    - "Bond Protocol — _validateAndGetPrice missing sequencer AND staleness checks (MEDIUM)"
    - "Inverse Finance — Chainlink data feed not sufficiently validated (MEDIUM)"
    - "Tokemak — Tellor oracle price not verified for zero, staleness (MEDIUM)"
    - "Elytra — _getAtomicPrices() uses stale oracle prices without validation (MEDIUM)"
    - "Level — missing oracle updates in RewardsManager, prices stale (MEDIUM)"
    - "Hyperhyper Oracle — _getLastPrice has no staleness, no price>0, no L2 sequencer check (MEDIUM, Pashov)"
  tags: [chainlink, staleness, heartbeat, latestRoundData]
  relacionado_con: [oracle-004, oracle-005, oracle-007]

- id: oracle-002
  pattern: spot-price-flash-loan
  name: "Spot price manipulation via flash loan"
  causa_raiz: >
    Protocol reads price from AMM pool.getReserves() or slot0() within the same
    transaction where the attacker can manipulate reserves via flash loan. Spot
    price is instantaneous and reflects post-manipulation state. A single tx can
    move price arbitrarily in low-to-medium liquidity pools.
  como_funciona: >
    1. Attacker takes flash loan of token A.
    2. Swaps large amount into target AMM pool, skewing reserves.
    3. Calls protocol function that reads spot price (now manipulated).
    4. Borrows/mints/liquidates at inflated/deflated price.
    5. Reverses the swap, repays flash loan, keeps profit.
  invariante: "abs(spotPrice - twapPrice) / twapPrice <= MAX_DEVIATION_PCT"
  que_mirar:
    - "Does protocol read getReserves(), slot0(), or sqrtPriceX96 directly?"
    - "Is price used in same tx it can be manipulated?"
    - "Any cross-validation against TWAP or Chainlink?"
    - "Flash loan callback or composable entry point available?"
  como_se_arregla: >
    Never use spot price for valuation. Use TWAP (>=30 min window) or Chainlink.
    If spot price required, cross-validate against TWAP with deviation threshold.
    Add reentrancy guards to prevent same-tx manipulation.
  trampas:
    - "High liquidity pools (>$10M TVL) are expensive to manipulate -- cost/benefit matters"
    - "Legitimate large trades can trigger deviation on thin pools"
    - "Protocol using Chainlink only (no AMM reads) is not vulnerable to this"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-001 (defihacklabs)"
  verificado: true
  incidentes_verificados:
    - nombre: "BonqDAO"
      fecha: "Feb 2023"
      perdida: "$88M"
      detalle: "Direct oracle price manipulation on Tellor oracle feed"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Gamma"
      fecha: "Jan 2024"
      perdida: "$6.3M"
      detalle: "Price manipulation via flash loan on AMM pool"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Woofi"
      fecha: "Mar 2024"
      perdida: "$8M"
      detalle: "Price manipulation via oracle on WOO Finance"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "UwULend"
      fecha: "Jun 2024"
      perdida: "$19.3M"
      detalle: "Price manipulation on lending oracle allowing undercollateralized borrowing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "ZunamiProtocol"
      fecha: "Aug 2023"
      perdida: "$2M"
      detalle: "Price manipulation on AMM spot price"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "NeutraFinance"
      fecha: "Aug 2023"
      perdida: "~23 ETH"
      detalle: "Price manipulation on spot price feed"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "ConicFinance02"
      fecha: "Jul 2023"
      perdida: "$934K"
      detalle: "Price manipulation on Curve pool pricing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "BelugaDex"
      fecha: "Oct 2023"
      perdida: "$175K"
      detalle: "Price manipulation on DEX pool"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "GoodCompound"
      fecha: "Dec 2023"
      perdida: "$13K"
      detalle: "Price manipulation on Compound fork oracle"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "ElephantStatus"
      fecha: "Dec 2023"
      perdida: "$165K"
      detalle: "Price manipulation on protocol oracle"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "SellToken"
      fecha: "Various 2023"
      perdida: "~$400K combined"
      detalle: "Price manipulation across multiple token contracts"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "MorphoBlue"
      fecha: "Oct 2024"
      perdida: "$230K"
      detalle: "Overpriced asset in oracle used for lending valuation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Makina"
      fecha: "Jan 2026"
      perdida: "$5.1M"
      detalle: "Price oracle manipulation on protocol pricing feed"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "Moonwell"
      fecha: "Feb 2026"
      perdida: "$1.78M"
      detalle: "Faulty oracle returning incorrect price data"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "vETH"
      fecha: "Nov 2024"
      perdida: "$447K"
      detalle: "Vulnerable price dependency allowing manipulation"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "HYDT"
      fecha: "Oct 2024"
      perdida: "$5.8K"
      detalle: "Oracle price manipulation on token pricing"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
    - nombre: "AIZPTToken"
      fecha: "Oct 2024"
      perdida: "$20K"
      detalle: "Wrong price calculation in oracle logic"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  solodit_ids:
    - m-10-erc4626oracle-vulnerable-to-price-manipulation-sherlock-sentiment-sentiment-git
    - m-04-fallback-oracle-is-using-spot-price-in-uniswap-liquidity-pool-which-is-very-vulnerable-to-flashloan-price-manipulation-code4rena-paraspace-paraspace-contest-git
    - spot-price-manipulation-can-lead-to-unfair-liquidations-cyfrin-none-deriverse-dex-markdown
    - pools-can-be-subject-to-price-manipulation-leading-to-early-liquidations-or-arbitrage-openzeppelin-none-fx-v2-audit-markdown
  incidentes:
    - "Sense — LP pricing uses current pool balances, trivially manipulable via flash loan (HIGH)"
    - "Salty.IO — CoreSaltyFeed spot price manipulable, causes undesired liquidations (HIGH)"
    - "Deriverse DEX — spot price from order book used for perp liquidation without oracle (HIGH)"
  tags: [flash-loan, spot-price, AMM, getReserves, slot0]
  relacionado_con: [oracle-003, oracle-008, flash-001]

- id: oracle-003
  pattern: twap-short-window
  name: "TWAP manipulation (multi-block for short windows)"
  causa_raiz: >
    TWAP with a short observation window (e.g., 1-5 minutes) can be manipulated
    across multiple blocks by a well-funded attacker or validator. Post-merge
    Ethereum with 12s block times makes this easier: 5 min = 25 blocks. An
    attacker who can sustain price distortion for the window length controls
    the TWAP output.
  como_funciona: >
    1. Attacker identifies TWAP window length (e.g., 3 min).
    2. Sustains large swap position across multiple blocks (or bribes builder).
    3. TWAP output gradually shifts toward manipulated price.
    4. Once TWAP is sufficiently distorted, executes profitable action.
    5. Unwinds position after protocol action is locked in.
  invariante: "twapWindow >= 1800 seconds (30 minutes minimum for security-critical pricing)"
  que_mirar:
    - "What is the TWAP observation window? Under 30 min is risky."
    - "observe() secondsAgos parameter -- what values?"
    - "Can window be changed by admin? Is there a minimum?"
    - "Is TWAP the sole oracle or backed by Chainlink?"
  como_se_arregla: >
    Minimum 30 min TWAP window for any security-critical pricing.
    Prefer Chainlink for primary oracle, TWAP as secondary validation.
    Add manipulation cost analysis: if cost to manipulate < profit, window is too short.
  trampas:
    - "Very high liquidity pools make even short TWAP expensive to manipulate"
    - "Multi-block manipulation requires sustained capital or validator collusion"
    - "Post-PoS: proposer can manipulate last block of window more cheaply"
  severidad: high
  confianza: alta
  fuente: "INV-EXPLOIT-001 composition analysis"
  verificado: true
  incidentes_verificados:
    - nombre: "RodeoFinance"
      fecha: "Jul 2023"
      perdida: "$888K"
      detalle: "TWAP manipulation on short observation window oracle"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  solodit_ids:
    - m-10-taporacle-twap-duration-for-uniswap-oracle-should-be-at-least-30-mins-pashov-none-tapiocadao-markdown
    - m-08-twap-can-be-manipulated-pashov-audit-group-none-ulti-november-markdown
    - h-04-use-of-only-higher-price-in-seer-makes-it-vulnerable-to-price-manipulation-pashov-none-tapiocadao-markdown
    - m-06-uniswap-oracle-prices-can-be-manipulated-pashov-audit-group-none-ouroboros_2024-12-06-markdown
    - uniswap-oracle-are-very-easy-to-manipulate-on-l2-cantina-none-euler-pdf
  incidentes:
    - "Ouroboros — Uniswap V3 TWAP windows of 36s and 5min on low-liquidity pools (MEDIUM)"
    - "UXD Protocol — getPositionValue uses 15-second TWAP instead of 15-minute (HIGH)"
    - "Panoptic — TWAP misweights EMAs, anchoring to slow EMA lets insolvent accounts dodge (MEDIUM)"
    - "Morpho — same TWAP_INTERVAL for pools with different liquidity (MEDIUM)"
  tags: [TWAP, observation-window, multi-block, uniswap-v3]
  relacionado_con: [oracle-002, oracle-008, dex-005]

- id: oracle-004
  pattern: zero-negative-price
  name: "Zero or negative price returned from oracle"
  causa_raiz: >
    Chainlink latestRoundData() can return price <= 0 during feed failures,
    circuit breaker events, or uninitialized feeds. If protocol does not
    validate, arithmetic with zero price causes division by zero (revert or
    infinite minting) and negative price causes underflow or inverted logic.
  como_funciona: >
    1. Oracle feed returns 0 or negative value (circuit breaker, failure).
    2. Protocol uses price in division: amount / price = infinite tokens.
    3. Or protocol uses price in collateral check: 0 price = free borrowing.
    4. Attacker monitors for feed anomalies and acts immediately.
  invariante: "price > 0 for every oracle read, checked before any arithmetic"
  que_mirar:
    - "Is price > 0 explicitly checked after latestRoundData()?"
    - "How does protocol handle negative int256 from answer?"
    - "Is there a circuit breaker or fallback for price == 0?"
    - "Arithmetic using price -- division by price anywhere?"
  como_se_arregla: >
    require(price > 0, "invalid oracle price");
    Add fallback oracle for when primary returns invalid data.
    Consider circuit breaker that pauses protocol on invalid price.
  trampas:
    - "Solidity int256 can be negative -- casting to uint256 without check wraps around"
    - "Some feeds return minAnswer/maxAnswer bounds, not zero, on extreme events"
    - "Check Chainlink aggregator minAnswer -- if real price drops below, feed returns minAnswer (stale)"
  solodit_ids: []
  incidentes:
    - "Perennial V2 — empty orders create oracle version with price=0, corrupts accounting (HIGH)"
    - "Tokemak — Tellor oracle price=0 not checked, passes through to calculations (MEDIUM)"
    - "Sublime — PriceOracle does not filter outlier prices from Chainlink (HIGH)"
    - "Blueberry — oracle down or price=0 freezes all liquidations (MEDIUM)"
    - "NUTS Finance ChainlinkOracleProvider — int256 price cast to uint256 without negative check; zero price halts fallback (MEDIUM, MixBytes)"
  severidad: critical
  confianza: alta
  fuente: "Chainlink documentation + INV-EXPLOIT-015"
  verificado: true
  tags: [chainlink, zero-price, negative-price, validation]
  relacionado_con: [oracle-001, oracle-007]

- id: oracle-005
  pattern: l2-sequencer-downtime
  name: "L2 sequencer downtime (Chainlink sequencer uptime feed)"
  causa_raiz: >
    On L2s (Arbitrum, Optimism, Base), Chainlink feeds continue returning
    the last price even when the sequencer is down. When sequencer comes back
    up, there is a burst of pending transactions. Prices may have moved
    significantly during downtime. Without checking the sequencer uptime feed,
    protocol processes actions at stale prices in the grace period.
  como_funciona: >
    1. L2 sequencer goes down (outage, maintenance).
    2. Market price moves during downtime.
    3. Sequencer comes back up; Chainlink price hasn't updated yet.
    4. Attacker front-runs oracle update with actions at stale price.
    5. Borrows at old collateral value, liquidates at old prices, etc.
  invariante: >
    sequencer.isUp == true && block.timestamp - sequencer.startedAt > GRACE_PERIOD
  que_mirar:
    - "Is protocol deployed on L2?"
    - "Does it check Chainlink sequencer uptime feed?"
    - "Is there a grace period after sequencer restart?"
    - "Grace period length -- too short allows stale trades, too long freezes protocol"
  como_se_arregla: >
    Check sequencer uptime feed before using any Chainlink price on L2.
    Enforce grace period (typically 1 hour) after sequencer comes back up.
    (bool isUp, uint256 startedAt) from sequencer feed.
    require(isUp && block.timestamp - startedAt > GRACE_PERIOD).
  trampas:
    - "Only relevant for L2 deployments -- not applicable to L1"
    - "Some L2s have different sequencer feed addresses"
    - "Grace period too long (>2h) unnecessarily freezes the protocol"
  solodit_ids:
    - missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-venus-multichain-support-markdown
    - trst-m-3-no-check-for-active-arbitrum-sequencer-in-chainlink-oracle-trust-security-none-stella-markdown_
    - unchecked-chainlink-sequencer-uptime-zokyo-none-umami-markdown
    - missing-l2-sequencer-uptime-check-in-oracleadapter-cyfrin-none-yieldfi-markdown
    - missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-open-dollar-smart-contract-audit-markdown
  incidentes:
    - "Sentiment — WSTETH Oracle missing Arbitrum sequencer check (MEDIUM)"
    - "Bond Protocol — _validateAndGetPrice doesn't check Arbitrum sequencer (MEDIUM)"
    - "Yieldfi — OracleAdapter missing L2 sequencer uptime check (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "Chainlink L2 documentation + audit findings"
  verificado: true
  tags: [L2, sequencer, arbitrum, optimism, base, grace-period]
  relacionado_con: [oracle-001]

- id: oracle-006
  pattern: oracle-decimals-mismatch
  name: "Oracle decimals mismatch"
  causa_raiz: >
    Chainlink feeds return prices with varying decimals (USD feeds = 8 decimals,
    ETH feeds = 18 decimals). If protocol assumes fixed decimals or doesn't
    call aggregator.decimals(), price calculations are off by orders of magnitude.
    Combined with different token decimals (USDC=6, WETH=18), the error compounds.
  como_funciona: >
    1. Protocol reads ETH/USD price (8 decimals) but treats as 18 decimals.
    2. All valuations are 10^10 times too small.
    3. Collateral appears worthless; borrowers get liquidated incorrectly.
    4. Or: protocol reads price with wrong scaling, undervalues collateral,
       attacker borrows more than collateral is worth.
  invariante: "price is normalized to consistent decimals before any arithmetic"
  que_mirar:
    - "Does protocol call feed.decimals()?"
    - "Is there hardcoded assumption about oracle decimals?"
    - "Token decimals + oracle decimals combined correctly?"
    - "Cross-pair pricing (ETH/BTC via ETH/USD and BTC/USD) -- decimals aligned?"
  como_se_arregla: >
    Always read decimals() from the aggregator.
    Normalize: adjustedPrice = price * 10^(targetDecimals - feedDecimals).
    Test with feeds of different decimal counts (8 and 18).
  trampas:
    - "Most USD feeds are 8 decimals but verify per feed"
    - "ETH-denominated feeds are typically 18 decimals"
    - "Protocol may correctly handle decimals but have a bug in a single edge-case path"
  solodit_ids: []
  incidentes:
    - "Y2K Finance — pricefeed.decimals() handling only works for 8-decimal feeds (HIGH)"
    - "Sense — LP oracle assumes 18 decimals, undervalues non-18 tokens (HIGH)"
    - "Inverse Finance — Oracle assumes feed/token decimals limited to 18, overflows otherwise (MEDIUM)"
    - "Sentiment — UniV2LPOracle malfunctions if token0/token1 decimals != 18 (HIGH)"
    - "Sentiment — ChainlinkOracle.getPrice() wrong when USD feed decimals != 8 (HIGH)"
  severidad: high
  confianza: alta
  fuente: "Audit pattern (common finding in Code4rena/Sherlock)"
  verificado: true
  tags: [decimals, normalization, scaling, chainlink]
  relacionado_con: [oracle-004]

- id: oracle-007
  pattern: chainlink-deprecated-aggregator
  name: "Chainlink deprecated aggregator"
  causa_raiz: >
    Using deprecated Chainlink functions (latestAnswer(), getAnswer(),
    getTimestamp()) that lack round completeness data and return 0 on failure
    without revert. These functions were deprecated in favor of latestRoundData()
    which provides updatedAt, answeredInRound, and roundId for validation.
  como_funciona: >
    1. Protocol calls latestAnswer() which returns only the price int256.
    2. No way to check staleness (no updatedAt).
    3. No way to check round completeness (no answeredInRound).
    4. On failure, returns 0 silently -- no revert.
    5. Protocol uses 0 price, causing catastrophic mispricing.
  invariante: "Protocol uses latestRoundData(), not latestAnswer()/getAnswer()/getTimestamp()"
  que_mirar:
    - "Grep for latestAnswer, getAnswer, getTimestamp"
    - "Is latestRoundData() used with all return values checked?"
    - "Are unused return values explicitly ignored (not just missing)?"
  como_se_arregla: >
    Replace latestAnswer() with latestRoundData().
    Validate all fields: price > 0, updatedAt recent, answeredInRound >= roundId.
  trampas:
    - "Some wrapper contracts abstract away the Chainlink call -- check the wrapper"
    - "Third-party oracle adapters may use deprecated functions internally"
  severidad: medium
  confianza: alta
  fuente: "Chainlink migration docs + INV-EXPLOIT-015"
  verificado: true
  tags: [chainlink, deprecated, latestAnswer, migration]
  relacionado_con: [oracle-001, oracle-004]

- id: oracle-008
  pattern: uniswap-v3-twap-short-window
  name: "Uniswap V3 TWAP observation window too short"
  causa_raiz: >
    Uniswap V3 oracle.observe() requires sufficient observation history.
    If cardinality is not increased (default=1 on new pools), TWAP reverts or
    returns useless data. Even with sufficient cardinality, a window under 30
    minutes is manipulable by sustained trading across blocks. New pools may
    lack observations entirely.
  como_funciona: >
    1. Protocol configures TWAP window of e.g., 60 seconds.
    2. Attacker trades heavily for 5 blocks (60 seconds).
    3. TWAP reflects the manipulated price.
    4. Attacker uses manipulated TWAP for profitable protocol action.
    5. Alternative: pool has cardinality=1, observe() reverts, protocol has no price.
  invariante: >
    twapWindow >= 1800 && pool.observationCardinality >= twapWindow / blockTime + 1
    // blockTime: ~12s Ethereum mainnet, ~2s Base/Optimism, ~2s Arbitrum
    // L2 example: 1800s window on Base requires cardinality >= 1800/2 + 1 = 901
    // Using 12s on L2 underestimates cardinality by ~6x — pool will revert on observe()
  que_mirar:
    - "What secondsAgos values are passed to observe()?"
    - "Is pool.increaseObservationCardinalityNext() called during setup?"
    - "Can the TWAP window be configured by admin to dangerously low values?"
    - "What happens if observe() reverts (cardinality too low)?"
    - "Is the pool new with low trade history?"
  como_se_arregla: >
    Minimum 30 min window for security-critical pricing.
    Call increaseObservationCardinalityNext() during deployment.
    Add fallback if observe() reverts.
    Validate pool has sufficient history before trusting TWAP.
  trampas:
    - "High-liquidity pools are harder to manipulate even with short windows"
    - "Cardinality must be increased BEFORE observations are needed -- retroactive increase doesn't create history"
    - "Different Uniswap V3 deployments may have different defaults"
  severidad: high
  confianza: alta
  fuente: "INV-EXPLOIT-001 + INV-EXPLOIT-021 composition"
  verificado: true
  incidentes_verificados:
    - nombre: "ConicFinance"
      fecha: "Jul 2023"
      perdida: "$3.25M"
      detalle: "Read-only reentrancy used to manipulate oracle price during cross-contract callback"
      verificado: true
      fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  solodit_ids: []
  incidentes:
    - "Aloe — Oracle.consult manipulable by increasing observationCardinality with malicious seed (HIGH)"
    - "Yieldoor — checkPoolActivity() incorrect check, cardinality timestamp=1 not handled (MEDIUM)"
    - "Panoptic — anyone can call pokeOracle with manipulable currentTick to update internal oracle (MEDIUM)"
  tags: [uniswap-v3, TWAP, cardinality, observe, observation-window, read-only-reentrancy]
  relacionado_con: [oracle-002, oracle-003]

- id: oracle-009
  pattern: sandwich-oracle-update
  name: "Sandwich attack on oracle price updates"
  causa_raiz: >
    Chainlink oracles update on-chain with a deviation threshold (e.g., 0.5-2%)
    and a heartbeat. Pending oracle update transactions are visible in the mempool.
    An attacker front-runs the update by taking a position at the stale price, then
    back-runs to profit after the new price is posted. When multiple oracles are
    chained (e.g., stETH/ETH + ETH/USD), compounded deviation thresholds create
    larger exploitable windows. The protocol's arb-capture mechanism is bypassed
    because the attacker splits the trade across two transactions around the update.
  como_funciona: >
    1. Attacker monitors mempool for pending Chainlink price update tx.
    2. Front-runs: deposits/borrows/mints at the soon-to-be-stale favorable price.
    3. Oracle update tx lands, changing on-chain price by deviation threshold.
    4. Back-runs: closes position at new price, capturing the deviation as profit.
    5. With multi-oracle chains (e.g., OHM priced via stETH/ETH * ETH/OHM),
       compound deviation can exceed 2-4%, making sandwich highly profitable.
  invariante: >
    assert(actionPrice == oraclePrice_at_settlement);
    // No position opened and closed across a single oracle update should yield
    // risk-free profit exceeding gas costs
  que_mirar:
    - "Does protocol read oracle price at action time and settle later?"
    - "Are there multi-hop oracle chains? (stETH/ETH * ETH/USD)"
    - "grep: getTknOhmPrice, getOhmTknPrice, getPrice.*mul.*getPrice"
    - "grep: wstethOhmPrice, expectedWstethAmountOut"
    - "Is there arb-capture logic? Can it be bypassed with 2 txs?"
    - "What is the deviation threshold of each feed used?"
  como_se_arregla: >
    Use commit-reveal for large deposits/withdrawals.
    Apply cooldown period between deposit and withdrawal (minimum 1 block).
    Implement EIP-1559 private mempool or MEV-protection (Flashbots Protect).
    For arb-capture: use the WORST price seen in a rolling window, not spot oracle.
  trampas:
    - "Small deviation thresholds (<0.5%) may not be profitable after gas"
    - "Protocol with time-locked withdrawals is partially protected"
    - "Sandwich requires mempool visibility -- private/encrypted pools reduce risk"
  solodit_ids: []
  incidentes:
    - "Olympus -- sandwich oracle update to exploit vault wstETH/OHM pricing (HIGH)"
    - "Olympus -- compound oracle deviation across stETH/ETH + ETH/OHM chains (HIGH)"
    - "Bancor V2 -- oracle front-running depletes reserves via weight rebalancing (HIGH)"
    - "Bold/Liquity -- oracle drift arbitrage when deviation > redemption fee (MEDIUM)"
    - "CAP Labs — Chainlink oracle sandwiching: mint at stale price, oracle updates, burn at new price (MEDIUM, TrailOfBits)"
    - "Radiant — attacker exploits oracle price deviation threshold for arbitrage across deposit/withdraw (MEDIUM, Pashov)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, sandwich, front-running, mev, deviation-threshold, chainlink]

- id: oracle-010
  pattern: lp-bpt-pricing-formula-error
  name: "LP/BPT token pricing formula produces incorrect valuation"
  causa_raiz: >
    LP token and Balancer Pool Token (BPT) pricing requires specialized formulas
    that account for pool invariants, weights, and rates. Common errors include:
    (a) dividing by ETH price when result is already in USD,
    (b) using minPrice*rate for Balancer stable pools (incorrect -- works for Curve
    but overvalues Balancer BPT by 10-15%),
    (c) using totalSupply() instead of getActualSupply() for Balancer pools with
    pre-minted BPT, and (d) division-by-zero when reserve ratios are inverted.
    These math errors cause systematic over- or under-valuation of collateral.
  como_funciona: >
    1. Protocol prices LP/BPT tokens using a formula borrowed from another protocol
       (e.g., Curve formula applied to Balancer pool).
    2. Formula has unit error (USD/ETH mismatch), methodology error (minPrice*rate
       overvalues Balancer stable BPT), or supply error (totalSupply vs actualSupply).
    3. LP tokens are systematically overvalued by 10-50%.
    4. Attacker deposits overvalued LP as collateral, borrows beyond true value.
    5. Protocol left with bad debt when LP is liquidated at real value.
  invariante: >
    // LP oracle price should be within 5% of fair value
    assert(lpOraclePrice <= lpFairValue * 105 / 100);
    assert(lpOraclePrice >= lpFairValue * 95 / 100);
  que_mirar:
    - "grep: lpPrice, getPrice.*LP, CurveTricrypto, StableBPT"
    - "grep: getRate(), virtualPrice, pool.rate"
    - "grep: totalSupply.*getPrice, minPrice.*mulWad"
    - "grep: computeFairReserves, getActualSupply"
    - "Is the pricing formula sourced from the correct protocol? (Curve vs Balancer)"
    - "Does the formula divide by ETH price at the end? (USD vs ETH denomination)"
    - "Does it use totalSupply() or getActualSupply() for Balancer?"
  como_se_arregla: >
    For Balancer: use getActualSupply() not totalSupply().
    For Balancer stable BPT: do NOT use minPrice*rate (Curve-style).
    Use Balancer's recommended pricing methodology per pool type.
    For Curve tricrypto: verify final denomination (USD not ETH).
    Cross-validate LP price against on-chain DEX aggregator or known oracle.
  trampas:
    - "Formula may look correct for one pool type but fail for another"
    - "Balancer pre-minted BPT inflates totalSupply -- getActualSupply excludes it"
    - "Division by zero can occur when resA < resB in computeFairReserves"
  solodit_ids: []
  incidentes:
    - "Blueberry -- CurveTricryptoOracle divides by ETH price, returns ETH instead of USD (HIGH)"
    - "Blueberry -- Stable BPT uses minPrice*rate, overvalues by 12%, causes insolvency (HIGH)"
    - "Blueberry -- WeightedBPTOracle uses totalSupply instead of getActualSupply (MEDIUM)"
    - "ParaSpace -- UniswapV3 NFT position valued wrong, triggers incorrect liquidations (HIGH)"
    - "Blueberry -- BalancerPairOracle division by zero when resA < resB (MEDIUM)"
    - "Sense -- LP oracle assumes 18 decimals, breaks for non-18 tokens (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, lp-token, bpt, balancer, curve, pricing-formula]

- id: oracle-011
  pattern: expired-oracle-version-treated-valid
  name: "Expired or missing oracle version treated as valid"
  causa_raiz: >
    Keeper-based oracle systems (Pyth, Perennial) rely on keepers to commit price
    versions within a timeout. When keepers fail (network issues, no price at
    timestamp), the expired version is filled with the previous valid price but
    incorrectly marked as valid (price != 0 so valid=true check passes). Similarly,
    roundId-based systems (Chainlink) can freeze if no roundId falls within a
    required epoch window. Empty orders that skip oracle requests create ghost
    versions with price=0 that corrupt fee/funding accounting.
  como_funciona: >
    1. Market action requests oracle version at timestamp T.
    2. Keeper cannot commit price within timeout (no price available, downtime).
    3. System fills expired version with previous price, but marks it valid.
    4. Orders execute at stale price instead of being invalidated.
    5. Alternative: empty order skips oracle request, settlement uses price=0,
       corrupting all fee/funding calculations for that period.
  invariante: >
    // Expired versions must be marked invalid
    assert(version.timestamp + timeout >= block.timestamp || !version.valid);
    // No settlement should use price == 0
    assert(settlementPrice > 0 || orderInvalidated);
  que_mirar:
    - "grep: _commitRequested, timeout, _prices[version.timestamp]"
    - "grep: latestVersion, _global.latestIndex"
    - "grep: isEmpty().*oracle.request, !newOrder.isEmpty"
    - "grep: relevantEpochStartTimestamp, roundId, latestExecutedEpoch"
    - "How does the system handle expired oracle versions?"
    - "What happens when empty orders don't trigger oracle requests?"
    - "Is price=0 treated as invalid everywhere it's used?"
  como_se_arregla: >
    Mark expired versions explicitly invalid regardless of price value.
    Use a dedicated `valid` flag, not price != 0 as proxy for validity.
    Always request oracle version even for empty orders if they create
    settlement checkpoints. Add fallback oracle path for keeper failures.
  trampas:
    - "Previous price fill looks correct (nonzero) but semantically wrong"
    - "Empty orders seem harmless but create accounting gaps"
    - "Strict roundId matching can freeze system during Chainlink gaps"
  solodit_ids: []
  incidentes:
    - "Perennial V2 -- expired oracle version returned as valid with previous price (HIGH)"
    - "Perennial V2 -- empty orders use price=0, corrupting fee accounting (HIGH)"
    - "Float Capital -- no roundId in epoch window freezes entire market (HIGH)"
    - "Float Capital -- same issue, duplicate finding confirmed (MEDIUM)"
    - "Perennial V2 Fix Review -- provider switch + feed failure locks funds (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, keeper, pyth, perennial, oracle-version, expired, price-zero]

- id: oracle-012
  pattern: wrapped-asset-depeg-oracle
  name: "Using native asset oracle for wrapped/bridged token ignores depeg risk"
  causa_raiz: >
    Protocols price wrapped tokens (WBTC, wstETH, sUSD) using the oracle for
    the native asset (BTC/USD, ETH/USD, USD). If the bridge or wrapper
    mechanism fails, the wrapped token depegs from the native asset but the
    oracle continues reporting the native price. Similarly, stablecoins assumed
    to be $1.00 exactly (USDC, USDT) can deviate during stress events, but
    hardcoded peg assumptions bypass any oracle check.
  como_funciona: >
    1. Bridge connecting WBTC to BTC is compromised or paused.
    2. WBTC depegs from BTC (trades at $15K while BTC is $30K).
    3. Protocol's oracle still returns BTC/USD price for WBTC collateral.
    4. Attacker deposits depegged WBTC, valued at full BTC price.
    5. Borrows against inflated collateral value, extracts real assets.
    6. Protocol left with worthless WBTC collateral.
  invariante: >
    // Wrapped token price should use wrapper-specific feed
    assert(wrappedTokenPrice <= nativeAssetPrice);
    // Stablecoin price should come from oracle, not hardcoded
    assert(stablecoinPrice == oraclePrice && stablecoinPrice != HARDCODED_1e18);
  que_mirar:
    - "grep: BTC.*USD.*WBTC, wBTC.*getPrice, WBTC.*oracle"
    - "grep: 1e18.*USDC, 1e6.*price.*usdc, hardcoded.*stablecoin"
    - "grep: stEthPerToken, wstETH.*price"
    - "Is WBTC priced via BTC/USD feed without WBTC/BTC adjustment?"
    - "Are stablecoins assumed to be exactly $1.00?"
    - "Is there a WBTC/BTC or USDC/USD secondary feed for depeg detection?"
  como_se_arregla: >
    Use dedicated WBTC/BTC feed and multiply: WBTC_USD = WBTC/BTC * BTC/USD.
    Never hardcode stablecoin price to $1.00; use Chainlink USDC/USD feed.
    Add depeg circuit breaker: if wrapped/native ratio deviates >5%, pause.
    For stETH: use stETH/ETH feed, not assume 1:1 peg.
  trampas:
    - "WBTC has been stable historically -- depeg is tail risk but catastrophic"
    - "USDC briefly depegged to $0.87 during SVB crisis (March 2023)"
    - "wstETH/stETH has a known exchange rate via Lido contract, not 1:1"
  solodit_ids: []
  incidentes:
    - "Blueberry -- BTC/USD oracle prices WBTC, ignoring bridge depeg risk (MEDIUM)"
    - "Isomorph -- USDC hardcoded to $1.00 in Velodrome LP pricing (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, wrapped-token, wbtc, depeg, stablecoin, bridge]

- id: oracle-013
  pattern: chainlink-min-max-answer-circuit-breaker
  name: "Chainlink minAnswer/maxAnswer circuit breaker masks real price"
  causa_raiz: >
    Chainlink aggregators have hardcoded minAnswer and maxAnswer bounds. When the
    real price drops below minAnswer (e.g., LUNA crash) or exceeds maxAnswer, the
    oracle returns the bound value instead of the actual price. The returned price
    passes validation (price > 0, not stale) but is catastrophically wrong. If the
    protocol caches minAnswer at deployment and the aggregator is later updated,
    the cached bounds become stale. Additionally, when price hits circuit breaker
    bounds, the oracle effectively becomes stale but appears fresh.
  como_funciona: >
    1. Asset price crashes below Chainlink aggregator's minAnswer (e.g., $0.10).
    2. Oracle returns minAnswer (e.g., $1.00) instead of real price ($0.10).
    3. Price passes all standard validations (> 0, not stale, round complete).
    4. Attacker buys asset at real market price ($0.10).
    5. Deposits into protocol where oracle values it at minAnswer ($1.00).
    6. Borrows 10x the real collateral value, drains protocol.
  invariante: >
    // Price should not equal aggregator min/max bounds
    int192 minAnswer = AggregatorV3Interface(feed).minAnswer();
    int192 maxAnswer = AggregatorV3Interface(feed).maxAnswer();
    assert(price > minAnswer && price < maxAnswer);
  que_mirar:
    - "grep: minAnswer, maxAnswer, minPrice, maxPrice"
    - "grep: aggregator(), priceFeed.aggregator"
    - "Does protocol check if returned price equals minAnswer/maxAnswer?"
    - "Are min/max bounds cached at deployment? Can they go stale?"
    - "Is there a fallback if price hits circuit breaker bounds?"
  como_se_arregla: >
    Read minAnswer/maxAnswer from aggregator: check price != minAnswer && price != maxAnswer.
    Do NOT cache these at deployment -- read fresh from aggregator().minAnswer().
    Add fallback oracle (Pyth, TWAP) for when price hits bounds.
    Pause protocol operations if circuit breaker is detected.
  trampas:
    - "minAnswer/maxAnswer are on the aggregator, not the proxy -- must call aggregator()"
    - "Not all feeds have meaningful bounds -- check specific feed"
    - "After aggregator update, cached min/max become invalid"
  solodit_ids:
    - incorrect-prices-will-be-returned-if-the-nodetype-is-price_deviation_circuit_breaker-immunefi-folks-finance-git
    - lastgoodprice-updates-during-divergence-spearbit-none-buck-labs-pdf
    - mint-pricing-bypasses-oracle-validation-spearbit-none-buck-labs-pdf
    - oracle-update-front-running-allows-extraction-of-value-from-vaults-trailofbits-none-cap-labs-covered-agent-protocol-pdf
  incidentes:
    - "Blueberry -- aggregator hits minAnswer, returns wrong price for collapsed asset (MEDIUM)"
    - "Isomorph -- cached minAnswer/maxAnswer from aggregator become stale after update (MEDIUM)"
    - "Isomorph -- Velodrome vault permanently locked if price outside min/max (MEDIUM)"
    - "Cryptex — circuit breakers not considered on Arbitrum where ETH/USD has active minAnswer (MEDIUM, Pashov)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, chainlink, circuit-breaker, minAnswer, maxAnswer, luna]

- id: oracle-014
  pattern: oracle-revert-locks-protocol
  name: "Oracle revert causes protocol-wide DoS (no try/catch)"
  causa_raiz: >
    Protocol calls oracle.latestRoundData() or similar without try/catch. If the
    oracle reverts (Chainlink multisig pauses feed, aggregator changed, access
    denied), every protocol function that reads price also reverts. This freezes
    liquidations (most critical), deposits, withdrawals, and all user operations.
    Chainlink feeds cannot be changed after configuration in some protocols,
    making the DoS permanent.
  como_funciona: >
    1. Chainlink feed is paused, deprecated, or access-gated.
    2. latestRoundData() reverts instead of returning data.
    3. Every protocol function calling getPrice() reverts.
    4. Liquidations freeze -- underwater positions cannot be liquidated.
    5. Bad debt accumulates, potentially causing insolvency.
    6. Users cannot withdraw their funds.
  invariante: >
    // Oracle call should never revert the caller
    // Use try/catch with fallback
    try oracle.latestRoundData() returns (...) { ... }
    catch { return fallbackOracle.getPrice(); }
  que_mirar:
    - "grep: latestRoundData().*require, getPrice.*revert"
    - "Is latestRoundData() wrapped in try/catch?"
    - "Is there a fallback oracle path?"
    - "Can oracle feeds be updated after deployment?"
    - "What happens to liquidations if oracle reverts?"
    - "grep: try.*latestRoundData, catch.*fallback"
  como_se_arregla: >
    Wrap all oracle calls in try/catch.
    Implement fallback oracle (Pyth, TWAP, cached last-known-good price).
    Allow admin to update oracle feed addresses.
    Ensure liquidation path has independent price source.
    Use circuit breaker that pauses new positions but allows unwinding.
  trampas:
    - "Chainlink rarely reverts but the impact is catastrophic when it does"
    - "Some protocols intentionally revert to prevent stale price usage -- balance is needed"
    - "Fallback to cached price has its own risks (staleness)"
  solodit_ids: []
  incidentes:
    - "Blueberry -- oracle down or zero price freezes all liquidations (MEDIUM)"
    - "Inverse Finance -- Chainlink access blocked, protocol usability limited (MEDIUM)"
    - "Juicebox -- unhandled Chainlink revert locks all price oracle access permanently (MEDIUM)"
    - "Dipcoin -- stale oracle causes system-wide DoS on all market operations (HIGH)"
    - "Blueberry -- ICHI token unsupported by oracle, all LP positions revert (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, dos, revert, try-catch, fallback, liquidation-freeze]

- id: oracle-015
  pattern: oracle-storage-corruption
  name: "Oracle data corruption via storage collision or ABI mismatch"
  causa_raiz: >
    Oracle extension contracts use storage key derivation that allows collisions
    between metadata structs of one token and data structs of another. Alternatively,
    ABI struct definitions differ between caller and callee contracts (different
    field order/types), causing return data to be decoded into wrong fields. Both
    produce silently corrupted oracle data that passes validation but is wrong.
  como_funciona: >
    1. Oracle uses hash-based storage slots: hash(token, index) for snapshots.
    2. Counts struct of token A collides with Snapshot struct of token B.
    3. Attacker creates tokens with addresses that produce storage collisions.
    4. Writing oracle data for token A corrupts token B's historical snapshots.
    5. Alternative: caller contract defines BandConfig{a,b,c} but callee returns
       BandConfig{c,a,b} -- fields are silently swapped on decode.
  invariante: >
    // Storage keys must be collision-resistant
    assert(storageKey(tokenA, Counts) != storageKey(tokenB, Snapshot_i));
    // ABI struct layouts must match between caller and callee
  que_mirar:
    - "grep: keccak256.*token.*index, storage.*slot.*oracle"
    - "grep: struct.*BandConfig, struct.*OracleConfig"
    - "Are storage keys prefixed with type discriminator?"
    - "Do interface struct definitions match implementation?"
    - "Is the oracle extension upgradeable with storage gaps?"
  como_se_arregla: >
    Add type discriminator to storage key derivation: hash(type_prefix, token, index).
    Verify ABI struct layouts match between all caller/callee pairs.
    Add storage gaps in upgradeable oracle contracts.
    Use explicit field-by-field decoding instead of struct casting.
  trampas:
    - "Storage collisions are hard to detect without formal analysis"
    - "ABI mismatch compiles fine -- only detectable at runtime"
    - "Missing storage gaps only manifest on upgrade, not initial deployment"
  solodit_ids: []
  incidentes:
    - "Ekubo -- oracle storage key collision corrupts token price data (MEDIUM)"
    - "Buck Labs -- ABI struct mismatch in BandConfig between LiquidityWindow and PolicyManager (HIGH)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [oracle, storage-collision, abi-mismatch, corruption, upgradeable]

- id: oracle-016
  pattern: user-controlled-malicious-oracle
  name: "User-supplied or lazily-updated oracle allows price manipulation"
  causa_raiz: >
    Protocol allows users to specify their own oracle at loan creation, or accepts
    user-provided price feed data without verifying source authenticity. Alternatively,
    protocol uses admin-pushed prices with insufficient update frequency, creating
    windows where on-chain price diverges significantly from market. In some cases,
    the protocol uses a push-based oracle where the update function is publicly
    callable, allowing anyone to push a manipulated observation.
  como_funciona: >
    1. Borrower creates loan with a malicious oracle contract they control.
    2. Oracle returns favorable price to avoid liquidation.
    3. When loan should be liquidated, malicious oracle returns high collateral price.
    4. Alternative: user provides stale Pyth price feed data (hours old) to trade
       at favorable historical price. Protocol accepts without checking publish_time.
    5. Alternative: anyone calls pokeOracle() with manipulable currentTick.
  invariante: >
    // Oracle must be from approved whitelist
    assert(approvedOracles[oracle] == true);
    // User-provided price data must be recent
    assert(block.timestamp - priceData.publishTime < MAX_AGE);
  que_mirar:
    - "grep: oracle.*constructor, setOracle.*borrower, userOracle"
    - "grep: set_underlying_px, publishTime, confidence"
    - "grep: pokeOracle, updateOracle.*public, pushPrice"
    - "Can users specify custom oracle at position creation?"
    - "Is user-provided price feed data validated for freshness?"
    - "Is the oracle update function access-controlled?"
  como_se_arregla: >
    Whitelist approved oracles -- never let users specify arbitrary oracle addresses.
    For user-provided price data (Pyth): validate publishTime, confidence interval.
    Restrict oracle update functions to authorized keepers.
    For manual push oracles: enforce minimum update frequency.
  trampas:
    - "Lender may not realize the oracle is borrower-controlled"
    - "Pyth confidence interval check is often skipped"
    - "Manual oracle may work fine in low-volatility periods"
  solodit_ids: []
  incidentes:
    - "Abracadabra -- borrower sets malicious oracle to avoid liquidation (HIGH)"
    - "Deriverse DEX -- user provides old price feed, trades at stale price (MEDIUM)"
    - "Panoptic -- anyone can call pokeOracle with manipulable tick (MEDIUM)"
    - "Dipcoin -- NAV uses spot oracle instead of perpetual mark price (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, malicious-oracle, user-controlled, pyth, manual-update]

- id: oracle-017
  pattern: oracle-deviation-check-precision-loss
  name: "Oracle deviation check uses insufficient precision, bypassed by rounding"
  causa_raiz: >
    Spot-vs-oracle deviation checks use low-precision integer arithmetic (e.g.,
    PERCENTAGE_DECIMALS = 100 for basis points). Rounding truncation allows
    deviations up to 2x the intended threshold to pass the check. Similarly,
    oracle slippage parameters are reused for unrelated checks (e.g., primary/
    secondary token ratio), causing parameter changes to have unintended side effects.
  como_funciona: >
    1. Protocol sets max deviation at 1% using PERCENTAGE_DECIMALS = 100.
    2. Actual deviation is 1.99%, but integer math truncates to 1%.
    3. Deviation check passes even though real deviation exceeds threshold.
    4. Attacker manipulates spot price within the expanded tolerance window.
    5. Alternative: oraclePriceDeviationLimitPercent controls both oracle slippage
       AND deposit ratio checks -- changing one breaks the other.
  invariante: >
    // Deviation check must use sufficient precision
    // PERCENTAGE_DECIMALS should be >= 10000 (basis points) or 1e18
    assert(PERCENTAGE_DECIMALS >= 10000);
    // Deviation parameters should be single-purpose
  que_mirar:
    - "grep: PERCENTAGE_DECIMALS, deviationInPercentage, maxDeviation"
    - "grep: oraclePriceDeviationLimit, slippageRate.*ratio"
    - "grep: .mul(100).div, PRECISION.*100"
    - "What precision is used for deviation calculation?"
    - "Is the same deviation parameter used for multiple checks?"
    - "Are there rounding issues in the deviation formula?"
  como_se_arregla: >
    Use at least 1e4 (basis points) or 1e18 precision for deviation checks.
    Formula: deviation = abs(a - b) * 1e18 / a; compare against threshold in 1e18.
    Use separate parameters for oracle slippage vs deposit ratio checks.
    Add ceil-division for safety-critical deviation comparisons.
  trampas:
    - "Small values (< $1000) may legitimately exceed threshold due to dust"
    - "Basis points (1e4) is minimum; 1e18 is preferred for DeFi"
    - "Multi-purpose parameters seem like good design but create coupling bugs"
  solodit_ids: []
  incidentes:
    - "Notional -- PERCENTAGE_DECIMALS=100 allows 2x intended deviation (MEDIUM)"
    - "Notional -- oraclePriceDeviationLimitPercent reused for ratio check (MEDIUM)"
    - "f(x) v2 — minimum price deviation formula uses minPrice as denominator instead of anchorPrice (MEDIUM, OpenZeppelin)"
    - "Colbfinance USC Engine — MAX_PRICE_DEVIATION_UPPER_BOUND of 5% is too high for stablecoin minting (MEDIUM, Shieldify)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, deviation-check, precision, rounding, basis-points]

- id: oracle-018
  pattern: intra-tx-price-inconsistency
  name: "Oracle returns different prices within same transaction"
  causa_raiz: >
    Price feed state machine transitions during a single transaction cause the same
    fetchPrice() function to return different values on consecutive calls. This
    happens when status transitions (e.g., from usingChainlinkFallbackUntrusted to
    bothOraclesUntrusted) change which code path returns the price. First call
    returns lastGoodPrice, second call returns current Chainlink price. Also occurs
    when oracle adapters update lastGoodPrice with a disputed value during a
    divergence event, or when view-only paths bypass validation that write paths enforce.
  como_funciona: >
    1. Oracle status is usingChainlinkFallbackUntrusted, Chainlink moves >50%.
    2. First fetchPrice() call: returns lastGoodPrice, changes status to bothOraclesUntrusted.
    3. Second fetchPrice() call: status is now bothOraclesUntrusted, returns current Chainlink price.
    4. Two different prices in same transaction creates arbitrage opportunity.
    5. Alternative: view path (for minting) skips cross-validation that write path enforces.
       Attacker uses view path to mint at unvalidated favorable price.
  invariante: >
    // fetchPrice must return same value for all calls in same block
    uint256 price1 = oracle.fetchPrice();
    uint256 price2 = oracle.fetchPrice();
    assert(price1 == price2);
  que_mirar:
    - "grep: fetchPrice, lastGoodPrice, status.*bothOraclesUntrusted"
    - "grep: _changeStatus, Status., fallbackCaller"
    - "grep: latestPrice.*view, getPrice.*view.*vs.*write"
    - "Can fetchPrice() change internal state that affects next call?"
    - "Is there a view-only price path that bypasses validation?"
    - "Does lastGoodPrice update during divergence events?"
  como_se_arregla: >
    Cache oracle price per block: if already fetched this block, return cached value.
    Ensure status transitions don't change return value within same transaction.
    View and write paths must use identical validation logic.
    Never update lastGoodPrice during divergence/circuit-breaker events.
  trampas:
    - "Status transition logic is complex -- easy to miss edge cases"
    - "View functions that seem safe can bypass write-path validation"
    - "lastGoodPrice should only update when both oracles agree"
  solodit_ids: []
  incidentes:
    - "eBTC -- fetchPrice returns different prices in same tx on 50% Chainlink move (MEDIUM)"
    - "Buck Labs -- lastGoodPrice updates during oracle divergence (MEDIUM)"
    - "Buck Labs -- inconsistent OracleAdapter state transitions between 4 states (MEDIUM)"
    - "Buck Labs -- mint pricing bypasses oracle validation via view path (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, intra-transaction, price-inconsistency, state-machine, view-vs-write]

- id: oracle-019
  pattern: stale-heartbeat-mismatch
  name: "Heartbeat/staleness threshold misconfigured for specific feed"
  causa_raiz: >
    Protocol sets a single staleness threshold that doesn't match the actual heartbeat
    of the specific Chainlink feed being used. Common cases: (a) maxLatency=3600s
    but feed has 86400s heartbeat (NFT floor prices), causing constant reverts;
    (b) heartbeat set to 24h for a feed with 1h heartbeat, allowing 23h of staleness;
    (c) heartbeat set to 0 in configuration, disabling staleness checks entirely;
    (d) inconsistent thresholds between related feeds (OHM/ETH at 24h vs ETH/USD at 1h).
    The result is either permanent DoS or exploitable staleness windows.
  como_funciona: >
    1. Protocol configures maxStaleness = 3600s for all feeds.
    2. NFT floor price feed has 86400s heartbeat.
    3. Feed only updates every ~24h, but protocol rejects anything >1h old.
    4. Strategy reverts with PriceNotRecentEnough on nearly every call.
    5. Alternative: heartBeat = 0 passed to staleness check, making ANY price valid.
  invariante: >
    assert(configuredHeartbeat >= feedActualHeartbeat);
    assert(configuredHeartbeat <= feedActualHeartbeat * 2);
    assert(configuredHeartbeat > 0);
  que_mirar:
    - "grep: maxLatency, maxStaleness, HEARTBEAT_TIME, heartBeat"
    - "grep: heartbeat.*3600, heartbeat.*86400, heartbeat.*0"
    - "Is staleness threshold per-feed or global?"
    - "Does it match the actual Chainlink heartbeat for each feed?"
    - "Can heartbeat be set to 0 in configuration?"
    - "Are related feeds (base/quote) using consistent thresholds?"
  como_se_arregla: >
    Configure staleness threshold per-feed to match actual Chainlink heartbeat.
    Add 10% buffer over heartbeat (e.g., 3960s for 3600s heartbeat).
    Validate heartbeat > 0 in setter functions.
    Document heartbeat values for each feed used.
    Use consistent thresholds for related feed pairs.
  trampas:
    - "Goerli/testnet heartbeats differ from mainnet -- don't test only on testnet"
    - "NFT floor price feeds have 24h heartbeats (not 1h)"
    - "stETH/ETH has 24h heartbeat with 2% deviation -- very loose"
    - "heartbeat=0 may be intentional for push-based oracles but dangerous for Chainlink"
  solodit_ids:
    - incorrect-staleness-threshold-for-chainlink-price-feeds-zokyo-none-copra-markdown
    - m-07-oraclemodule-assumes-that-all-chainlink-feeds-have-a-heartbeat-of-24-hours-pashov-none-fyde-markdown
    - m-1-lack-of-price-freshness-check-in-chainlinkoraclesolgetprice-allows-a-stale-price-to-be-used-sherlock-sentiment-sentiment-git
    - m-04-omooraclegetusdvalue-price-feed-updates-may-be-incorrectly-marked-stale-pashov-audit-group-none-omo_2025-01-25-markdown
    - oracle-freshness-threshold-can-lead-to-stale-data-being-provided-zokyo-none-paribus-markdown
  incidentes:
    - "LooksRare -- maxLatency=3600s but floor price feeds have 86400s heartbeat (MEDIUM)"
    - "Olympus -- stETH/ETH has 24h heartbeat and 2% deviation, causes fund loss (MEDIUM)"
    - "Isomorph -- HEARTBEAT_TIME=24h is too loose for volatile assets (MEDIUM)"
    - "Olympus DAO -- inconsistent staleness between OHM and reserve token oracles (MEDIUM)"
    - "Level -- heartBeat=0 disables staleness check, causes reward claim failures (HIGH)"
    - "CAP Labs PriceOracle — single staleness period for all feeds; USDC/USD=86400s vs DAI/USD=3600s (HIGH, TrailOfBits)"
    - "Morpheus ChainLinkDataConsumer — same heartbeat for USDC/USD (24h) and ETH/USD (1h) (MEDIUM, C4)"
    - "Astera Oracle — _assetToTimeout[asset] used instead of _assetToTimeout[underlying] for tranched tokens (MEDIUM, Spearbit)"
    - "Elara Finance — maxDelayTime not initialized in constructor, defaults to 0, accepts any age (MEDIUM, Quantstamp)"
    - "Etherspot — updateCachedPrice checks cacheAge against nativeMaxAge but not tokenMaxAge (MEDIUM, Shieldify)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, heartbeat, staleness, misconfiguration, chainlink, per-feed]

- id: oracle-020
  pattern: oracle-committee-manipulation
  name: "Oracle committee/quorum manipulation via member management"
  causa_raiz: >
    Multi-party oracle systems where N members vote on reported values have
    governance vulnerabilities: (a) removeMember swaps array positions, allowing
    one member to vote multiple times in same epoch while another loses their vote;
    (b) quorum reduction can be front-run/back-run to push a faction's report;
    (c) front-running between competing oracle member groups to push their variant.
    Additionally, 1 wei donations can brick the reporting system by corrupting
    accounting in deposit-based oracle governance.
  como_funciona: >
    1. Oracle has N members who vote on price/beacon reports with quorum Q.
    2. Admin removes member at index I -- last member swapped to index I.
    3. If swapped member already voted, they can vote again at new index.
    4. If member at old last index hasn't voted, they can no longer vote.
    5. Alternative: two factions are 1 vote from quorum, front-running decides winner.
    6. Alternative: 1 wei forced deposit corrupts shares accounting, bricking oracle.
  invariante: >
    // Each member votes exactly once per epoch
    assert(votesPerMember[member][epoch] <= 1);
    // Quorum changes should not affect current epoch
    assert(quorumChangeEpoch > currentEpoch);
  que_mirar:
    - "grep: removeMember, deleteItem, swap.*last.*index"
    - "grep: quorum, setQuorum, memberCount"
    - "grep: reportBeacon, submitReport, vote.*epoch"
    - "Does removeMember preserve vote accounting?"
    - "Can quorum changes take effect in the current epoch?"
    - "Is the oracle committee governance time-locked?"
  como_se_arregla: >
    Use mapping-based membership, not array-swap deletion.
    Track votes by member address, not array index.
    Time-lock quorum changes to next epoch.
    Prevent member management during active voting period.
    Guard against forced ETH/token donations in accounting.
  trampas:
    - "Array swap deletion is a common Solidity pattern but dangerous for voting"
    - "Quorum reduction seems safe but enables back-running"
    - "1 wei attack is specific to deposit-receipt-based oracle governance"
  solodit_ids: []
  incidentes:
    - "Liquid Collective -- removeMember allows double voting via array swap (HIGH)"
    - "Liquid Collective -- quorum decrement enables front-running between factions (MEDIUM)"
    - "Liquid Collective -- reportBeacon front-running between oracle groups (MEDIUM)"
    - "Liquid Collective -- 1 wei donation bricks oracle reporting system (HIGH)"
    - "Initia — ApplyOracleUpdate doesn't check for duplicate validator votes; single validator can control price (MEDIUM, C4)"
    - "Crouton Finance — duplicate signatures bypass multi-signer threshold, single signer controls price (HIGH, Quantstamp)"
    - "Switchboard — PullFeedSubmitResponse doesn't verify oracles are from same queue (HIGH, OtterSec)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, committee, quorum, governance, voting, member-management]

- id: oracle-021
  pattern: twap-update-logic-error
  name: "TWAP update logic error produces stale or wrong average"
  causa_raiz: >
    Custom TWAP implementations contain logic errors: (a) update function returns
    early without updating when elapsed time exceeds the period (TWAP freezes forever);
    (b) initial cumulative prices calculated with integer division of reserves instead
    of UQ112x112 fixed-point (one value is always 0); (c) TWAP computed as
    observation-weighted average instead of true time-weighted average (irregular
    heartbeat creates bias); (d) token pair registered with wrong order, inverting
    the price; (e) post-swap rate recorded as if it applied for entire interval.
  como_funciona: >
    1. TWAP update function checks: if (elapsed > period) return early.
    2. Once period passes, TWAP never updates again -- frozen at last value.
    3. All protocol functions using TWAP operate on permanently stale price.
    4. Alternative: initial price0Cumulative = reserve1/reserve0 = 0 (integer division).
       TWAP starts at 0, causing massive mispricing.
    5. Alternative: post-swap lnImpliedRate used to close observation interval,
       making one large swap dominate the entire TWAP window.
  invariante: >
    // TWAP should update even when elapsed > period
    assert(twapUpdatedAt >= block.timestamp - twapPeriod);
    // Initial cumulative prices should use fixed-point math
    assert(price0CumulativeLast > 0 || price1CumulativeLast > 0);
  que_mirar:
    - "grep: elapsed.*period.*return, timeElapsed.*PERIOD"
    - "grep: price0CumulativeLast.*reserve, reserve.*div.*reserve"
    - "grep: registerPair.*token0.*token1, getPair.*factory"
    - "grep: lnImpliedRate.*beforeSwap, observation.*afterSwap"
    - "Does TWAP update handle elapsed > period correctly?"
    - "Are initial cumulative prices in UQ112x112 format?"
    - "Is token order validated against factory pair?"
    - "Is oracle updated before or after the swap?"
  como_se_arregla: >
    Fix update logic: if (elapsed >= period) update TWAP, don't return early.
    Initialize cumulative prices using UQ112x112: reserve1 * 2^112 / reserve0.
    Validate token order matches factory's getPair token0/token1 ordering.
    Use TWAP implementation: weight by time elapsed, not observation count.
    Update oracle observation with pre-swap rate, not post-swap.
  trampas:
    - "TWAP works fine for first period then freezes -- easy to miss in testing"
    - "Integer division of reserves looks correct but produces 0"
    - "Token order bug only manifests with certain address orderings"
  solodit_ids: []
  incidentes:
    - "Morpho -- SwapManager TWAP freezes after first period (HIGH)"
    - "Morpho -- initial cumulative prices wrong due to integer division (MEDIUM)"
    - "Vader -- TWAP averages wrong due to uninitialized weights (HIGH)"
    - "Vader -- TWAPOracle registers with wrong token order (HIGH)"
    - "Olympus DAO -- TWAP is observation-weighted, not time-weighted (MEDIUM)"
    - "Napier -- post-swap lnImpliedRate allows TWAP manipulation (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, twap, update-logic, cumulative-price, uq112, token-order]

- id: oracle-022
  pattern: oracle-price-scaling-math-error
  name: "Oracle price scaling or unit conversion math error"
  causa_raiz: >
    Custom oracle wrapper contracts contain math errors in price scaling: (a) failing
    to apply the scaler/WAD conversion set in constructor; (b) incorrect formula
    combining pricefeed decimals (only works for 8-decimal feeds but not others);
    (c) using SMA (simple moving average) without scaling to match upstream oracle
    decimals; (d) Uniswap-Chainlink rate comparison that always reverts for certain
    currency pairs due to denomination mismatch. These are not decimal-mismatch
    (oracle-006) but actual formula/logic errors in the math.
  como_funciona: >
    1. Oracle wrapper has scaler for normalizing price to WAD (18 decimals).
    2. SMAOracle.update() skips applying the scaler to latestPrice.
    3. Downstream contract receives unscaled price (e.g., 8 decimals).
    4. Protocol math treats it as 18 decimals, undervaluing by 1e10.
    5. Alternative: pricefeed.decimals() hardcoded to work with 8 decimals only.
       When a feed has 18 decimals, the normalization formula overflows or inverts.
  invariante: >
    // All prices must be in the expected denomination after scaling
    assert(price >= MIN_REASONABLE_PRICE && price <= MAX_REASONABLE_PRICE);
    // Scaling must be applied consistently
  que_mirar:
    - "grep: toWad, scaler, _spotDecimals, scaledPrice"
    - "grep: 10000.*price, price.*10000, nowPrice.*div"
    - "grep: SMAOracle, update.*latestPrice, _latestRoundData"
    - "grep: _checkUniswapRateDifference, ethDecimals"
    - "Is price scaling applied in ALL code paths?"
    - "Does formula work for feeds with both 8 and 18 decimals?"
    - "Is there a sanity bound on the output price?"
  como_se_arregla: >
    Apply scaler/WAD conversion in every code path that reads price.
    Test oracle wrapper with feeds of 8, 18, and edge-case decimals.
    Add sanity bounds: MIN_PRICE < result < MAX_PRICE.
    For cross-oracle comparison: normalize both to same denomination first.
  trampas:
    - "Constructor sets scaler but update() may not use it"
    - "Works perfectly for all 8-decimal feeds, breaks on first 18-decimal feed"
    - "Cross-oracle rate comparison can silently overflow for certain pairs"
  solodit_ids: []
  incidentes:
    - "Tracer -- SMAOracle.update() skips scaling, prices off by 1e10 (HIGH)"
    - "Y2K Finance -- pricefeed.decimals() math only works for 8 decimals (HIGH)"
    - "Notional -- Uniswap-Chainlink rate comparison always reverts for some currencies (HIGH)"
    - "Volt Protocol -- oracle price does not compound monthly APRs correctly (HIGH)"
    - "CAP Labs StakedCapAdapter — uses decimals count (18) instead of scaling factor (10^18) in price calculation (HIGH, TrailOfBits)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, scaling, math-error, wad, decimals, sma]

- id: oracle-023
  pattern: oracle-divergence-dos-liquidation
  name: "Oracle divergence/manipulation blocks time-critical operations"
  causa_raiz: >
    Protocols implement safety checks that revert when spot price diverges from
    oracle price beyond a threshold. While well-intentioned, these checks can be
    weaponized: an attacker manipulates spot price to trigger the divergence check,
    blocking liquidations, force exercises, and premium settlements. The operations
    blocked are precisely those that should execute during volatile markets. Time-
    dependent mechanisms (Dutch auctions, TWAP decay) also continue during oracle
    downtime, producing unfair execution prices when operations resume.
  como_funciona: >
    1. Protocol has divergence check: |spotPrice - oraclePrice| < threshold.
    2. Critical function (liquidation, force exercise) reverts if check fails.
    3. Attacker manipulates spot price (swap in pool) to exceed threshold.
    4. All liquidations revert with StaleOracle or similar error.
    5. Attacker's undercollateralized position survives through volatile period.
    6. Alternative: during sequencer downtime, Dutch auction price decays to near-zero.
       When operations resume, liquidation executes at heavily decayed unfair price.
  invariante: >
    // Liquidation must never be blocked by oracle divergence check
    // Divergence check should pause new positions, not liquidations
    assert(liquidationAlwaysExecutable || emergencyLiquidationPath);
  que_mirar:
    - "grep: StaleOracle, tickDelta, divergence.*revert"
    - "grep: liquidat.*revert, forceExercise.*revert"
    - "grep: auctionPrice.*decay, dutchAuction.*timestamp"
    - "Does the divergence check block liquidations?"
    - "Do time-dependent mechanisms pause during oracle downtime?"
    - "Is there an emergency liquidation path that bypasses checks?"
  como_se_arregla: >
    Divergence checks should block new positions, NOT liquidations.
    Implement emergency liquidation path with relaxed oracle requirements.
    Pause time-dependent mechanisms (auctions, TWAP decay) during oracle downtime.
    Add user-action grace period after oracle resumes (separate from oracle grace period).
  trampas:
    - "Divergence check seems like good security but weaponizable against liquidations"
    - "Dutch auction decay during downtime is especially unfair -- not widely known"
    - "User grace period vs oracle grace period are different concepts"
  solodit_ids: []
  incidentes:
    - "Panoptic -- spot manipulation triggers StaleOracle, blocks all liquidations (MEDIUM)"
    - "GTE -- liquidation stalls when top-of-book outside divergence band (MEDIUM)"
    - "Inverse Finance -- two-day low oracle used in liquidation, gameable in 2 blocks (MEDIUM)"
    - "f(x) v2 — spot price from single on-chain pool manipulable to trigger 1% deviation, blocking liquidations (HIGH, OpenZeppelin)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, divergence, dos, liquidation, dutch-auction, grace-period]

- id: oracle-024
  pattern: pyth-confidence-interval-mishandling
  name: "Pyth oracle confidence interval or staleness misconfigured"
  causa_raiz: >
    Pyth oracle integration errors include: (a) maxConf parameter treated as
    absolute price value instead of percentage (documented as 500 for "5%" but
    code compares scaled absolute confidence); (b) preview paths use different
    staleness threshold than live paths (up to 15 min stale for preview vs
    configured maxStaleness for live); (c) confidence interval not checked at
    all, accepting low-confidence prices as authoritative. Different from Chainlink
    staleness (oracle-001) because Pyth has unique confidence semantics.
  como_funciona: >
    1. Protocol configures Pyth maxConf = 500, intending 5% confidence threshold.
    2. Implementation compares absolute confidence value against 500 (in 18-decimal units).
    3. Actual threshold becomes astronomically tight or loose depending on price magnitude.
    4. High-confidence requirement causes constant reverts, or
       loose confidence allows manipulated/uncertain prices to pass.
    5. Alternative: preview quote accepts 15-min stale price, live quote rejects same price.
       External integrator uses preview path, gets stale price, makes bad decision.
  invariante: >
    // Confidence must be percentage-based, not absolute
    assert(price.conf * 10000 / price.price <= maxConfBps);
    // Preview and live paths must use same staleness
    assert(previewStaleness == liveStaleness);
  que_mirar:
    - "grep: maxConf, pythMaxConf, conf.*price, confidence.*threshold"
    - "grep: MAX_STALENESS_UPPER_BOUND, previewGetQuote, _previewFetchPrice"
    - "grep: publishTime, getPrice.*Pyth, updatePriceFeeds"
    - "Is maxConf treated as percentage or absolute value?"
    - "Do preview and live price paths use same staleness?"
    - "Is confidence interval validated at all?"
  como_se_arregla: >
    Implement confidence as percentage: require(price.conf * 10000 / price.price <= maxConfBps).
    Use same staleness threshold for preview and live paths.
    Always validate confidence interval is within acceptable bounds.
    Document maxConf units clearly in configuration.
  trampas:
    - "maxConf semantics differ from Chainlink deviation threshold"
    - "Preview paths are read-only but can mislead external integrators"
    - "Pyth confidence interval is unique -- no equivalent in Chainlink"
  solodit_ids: []
  incidentes:
    - "Buck Labs -- Pyth maxConf treated as absolute instead of percentage (MEDIUM)"
    - "Covenant -- preview quotes allow 15-min stale prices vs live quotes (LOW->MEDIUM)"
    - "stETH by EaseDeFi -- wrong price validation causes DoS and late manipulation (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [oracle, pyth, confidence-interval, staleness, preview, configuration]

- id: oracle-025
  pattern: pyth-atomic-same-tx-update-arbitrage
  name: "Pyth oracle updated atomically by user in same transaction enables arbitrage"
  causa_raiz: >
    Pyth oracles are pull-based: anyone can call updatePriceFeeds() with fresh
    off-chain price data. Unlike Chainlink where updates are pushed by nodes and
    visible in the mempool, Pyth updates can be bundled by the user into the same
    transaction as their protocol interaction. An attacker fetches two Pyth price
    snapshots (T1 and T2) where price moved significantly. In a single tx they:
    (1) interact with protocol at stale on-chain price, (2) push the new Pyth
    update, (3) interact again at the new price. This is atomic -- no mempool
    visibility, no front-running needed. The attack applies to any protocol that
    reads Pyth price and allows the caller to also push the update.
  como_funciona: >
    1. Attacker observes Pyth off-chain price has moved from $100 to $105.
    2. In a single transaction: addLiquidity() at old on-chain price ($100).
    3. Calls pyth.updatePriceFeeds() with the $105 price proof.
    4. Calls removeLiquidity() -- shares now valued at $105.
    5. Nets 5% profit minus fees, all atomic in one tx.
    6. Variant: deposit collateral at low price, push update, borrow at high price.
  invariante: >
    // Price used for action must not change within same transaction
    assert(priceAtDeposit == priceAtWithdrawal || block.number > depositBlock);
    // Or: use worst-of-two-epochs pricing for LP operations
  que_mirar:
    - "grep: updatePriceFeeds, parsePriceFeedUpdates, pyth.*update"
    - "grep: addLiquidity.*removeLiquidity, deposit.*withdraw in same function scope"
    - "Can the caller push a Pyth update AND interact in the same tx?"
    - "Is there a cooldown between deposit and withdrawal?"
    - "Does protocol use price-epoch system (worst price of last 2 epochs)?"
  como_se_arregla: >
    Implement price-epoch system: for deposits use highest price of last 2 epochs,
    for withdrawals use lowest. Alternatively, enforce minimum hold period (at least
    1 block) between deposit and withdrawal. Use maxOracleAge to reject very stale
    on-chain prices that indicate a pending large update. Track min/max prices per
    epoch and use adversarial pricing for each direction.
  trampas:
    - "Unlike Chainlink sandwich, no mempool visibility needed -- fully atomic"
    - "maxOracleAge alone doesn't prevent this -- attacker pushes fresh update"
    - "Works with any pull-based oracle (Pyth, API3 with OEV, RedStone)"
  solodit_ids: []
  incidentes:
    - "XPress/LPManager -- Pyth atomic update: addLiquidity at low, removeLiquidity at high in same tx (CRITICAL, MixBytes)"
    - "Hanji/LPManager -- identical pattern to XPress (CRITICAL, MixBytes)"
    - "CAP Labs -- oracle sandwiching on Chainlink mint/burn, recommends fee > deviation threshold (MEDIUM, TrailOfBits)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, pyth, pull-oracle, atomic-update, same-transaction, arbitrage, liquidity]

- id: oracle-026
  pattern: composite-oracle-arithmetic-overflow
  name: "Composite/multi-hop oracle overflow bricks price feed permanently"
  causa_raiz: >
    Composite oracle contracts chain multiple price feeds (e.g., stETH/ETH *
    ETH/USD or multi-leg Chainlink feeds). The intermediate multiplication uses
    high-precision fixed-point (e.g., 36-decimal scaling) and the result can
    overflow uint256 when any underlying feed reports a large value. For assets
    exceeding ~$100K in wei-denominated feeds, the product exceeds 2^256.
    The overflow causes a revert, not a wrong price, which permanently bricks
    every contract relying on this oracle -- including liquidation, lending,
    and pricing logic. Unlike oracle-006 (decimal mismatch, wrong price) this
    is a hard revert from arithmetic overflow.
  como_funciona: >
    1. Composite oracle normalizes each feed: rate = price * 10^(36 - feedDecimals).
    2. Multiplies compositePrice *= rate / SCALING_FACTOR (36-decimal fixed-point).
    3. When price > ~$100K in wei denomination, intermediate product exceeds 2^256.
    4. Solidity 0.8+ reverts with arithmetic overflow.
    5. Every downstream contract calling getPrice() also reverts permanently.
    6. Liquidations freeze, deposits/withdrawals freeze, protocol is bricked.
  invariante: >
    // Composite oracle must never revert for any plausible price range
    // Test: price feeds returning up to $1M equivalent should not overflow
    assert(compositeOracle.getPrice() > 0); // should never revert
  que_mirar:
    - "grep: compositePrice.*rate, SCALING_FACTOR.*36, SCALING_DECIMALS"
    - "grep: mulDiv, mul.*div.*PRECISION"
    - "Is intermediate multiplication done with overflow-safe mulDiv?"
    - "What is the maximum plausible price for each underlying feed?"
    - "Are there more than 2 feeds chained together?"
  como_se_arregla: >
    Use 512-bit safe math (OpenZeppelin's Math.mulDiv) for intermediate products.
    Reduce SCALING_DECIMALS from 36 to 18 if possible.
    Add explicit overflow checks with meaningful error messages.
    Test with maximum realistic prices for all underlying feeds.
  trampas:
    - "Works fine at current prices but breaks when asset price doubles"
    - "Only manifests with specific feed decimal combinations"
    - "36-decimal intermediate precision is common in composite oracles but dangerous"
  solodit_ids: []
  incidentes:
    - "NUTS Finance ChainlinkOracleComposite -- getPrice overflows at $100K, freezes all integrated contracts (HIGH, MixBytes)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, composite, overflow, multi-hop, arithmetic, dos, permanent-brick]

- id: oracle-027
  pattern: yield-bearing-wrapper-exchange-rate-assumption
  name: "Yield-bearing wrapper token exchange rate hardcoded or misassumed"
  causa_raiz: >
    Protocols integrate yield-bearing tokens (Pendle PT/SY, ERC4626 vaults,
    wstETH) but assume a fixed 1:1 exchange rate between the wrapper and its
    underlying. In reality: (a) Pendle SY != underlying YT due to slippage and
    accrued yield; (b) ERC4626 convertToAssets changes as yield accrues;
    (c) getPtToSyRate() returns values with market-specific decimals (not always
    1e18); (d) wstETH/stETH ratio increases over time. Using a hardcoded ratio
    or assuming fixed decimals in the rate function causes systematic mispricing
    of collateral, inflating borrowing capacity or preventing liquidation.
  como_funciona: >
    1. Protocol prices Pendle PT via: PT_price = getPtToSyRate * underlyingPrice / 1e18.
    2. Assumes 1 SY = 1 underlying (hardcoded), but actual ratio is 0.97.
    3. PT price is overstated by 3%, enabling overborrowing.
    4. Variant: getPtToSyRate returns 27-decimal value for certain markets, but
       code divides by 1e18 -> price inflated by 1e9.
    5. Variant: ERC4626 share price used as oracle; attacker donates to inflate
       convertToAssets, manipulating the oracle within same tx.
    6. Liquidation reverts or never triggers because collateral appears healthy.
  invariante: >
    // Exchange rate must be dynamically fetched, not assumed 1:1
    assert(syToUnderlyingRate == SY.exchangeRate()); // not hardcoded 1e18
    // Rate decimals must match the specific market
    assert(rateDecimals == market.rateDecimals());
  que_mirar:
    - "grep: getPtToSyRate, convertToAssets, exchangeRate, stEthPerToken"
    - "grep: 1e18.*underlyingPrice, / 1e18.*rate"
    - "Is the SY-to-underlying rate dynamically fetched or hardcoded?"
    - "Does getPtToSyRate decimal assumption hold for ALL markets?"
    - "Can convertToAssets be manipulated via donation in same tx?"
    - "Is wstETH priced as 1:1 with stETH?"
  como_se_arregla: >
    Query SY.exchangeRate() dynamically for each conversion.
    Read rate decimals from the specific Pendle market, not assume 1e18.
    For ERC4626 oracles: use TWAP of share price, not instantaneous convertToAssets.
    For wstETH: always multiply by stEthPerToken from Lido contract.
    Cross-validate derived price against direct Chainlink feed when available.
  trampas:
    - "Rate is close to 1:1 for new markets but diverges as yield accrues"
    - "Different Pendle markets return getPtToSyRate with different decimals"
    - "ERC4626 donation attack requires only small amount for low-TVL vaults"
  solodit_ids: []
  incidentes:
    - "USG Tangent OraclePendlePT -- assumes 1 SY = 1 underlying, overstates PT price (MEDIUM, Sherlock)"
    - "USG Tangent OraclePendlePT -- getPtToSyRate assumed 1e18 but some markets return 1e27 (MEDIUM, Sherlock)"
    - "Usual ETH0 -- no on-chain depeg check for LST collateral; wstETH price assumption breaks over time (MEDIUM, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, pendle, erc4626, yield-bearing, wrapper, exchange-rate, sy-token, wsteth]

- id: oracle-028
  pattern: batch-oracle-report-fee-double-counting
  name: "Batch oracle report processing causes fee double-counting"
  causa_raiz: >
    When an oracle system submits multiple asset price reports in a single batch
    transaction, each individual report triggers protocol fee calculation independently.
    The fee calculation uses the time elapsed since the last fee timestamp, but
    the timestamp only updates when the base asset report is processed. If non-base
    assets are processed first, each one accrues fees for the same time period,
    resulting in N-fold fee overcharge (where N is the number of non-base reports
    before the base report). This is a report-ordering vulnerability specific to
    multi-asset oracle update batches.
  como_funciona: >
    1. Oracle submits batch: [tokenA_report, tokenB_report, base_report].
    2. tokenA_report: calculateFee uses (block.timestamp - lastFeeTimestamp) -> accrues full period fees.
    3. tokenB_report: timestamp still not updated -> accrues same full period fees again.
    4. base_report: finally updates lastFeeTimestamp.
    5. Protocol charged 3x the intended fees for this batch.
    6. If there are 10 non-base assets, fees are 11x the intended amount.
  invariante: >
    // Fees should be calculated exactly once per time period
    uint256 feesBefore = totalFeesMinted;
    oracle.submitReports(reports);
    uint256 feesAfter = totalFeesMinted;
    assert(feesAfter - feesBefore <= expectedFeesForPeriod * 110 / 100); // 10% tolerance
  que_mirar:
    - "grep: submitReports, handleReport, calculateFee, feeTimestamp"
    - "grep: updateState.*baseAsset, timestamps.*vault"
    - "Does fee timestamp update only for base asset?"
    - "Are multiple reports processed in a single tx?"
    - "Does report ordering affect fee calculation?"
  como_se_arregla: >
    Update fee timestamp BEFORE processing any reports in the batch, or
    only calculate fees once per batch (not per report). Alternatively,
    process base asset report first to set the timestamp before other reports.
    Add batch-level fee calculation that considers all reports atomically.
  trampas:
    - "Individual report processing looks correct in isolation"
    - "Bug only manifests when multiple non-base reports precede base report"
    - "Fee overcharge compounds: more assets = worse overcharge"
  solodit_ids: []
  incidentes:
    - "Mellow Flexible Vaults -- Oracle.submitReports double-counts protocol fees for non-base assets (HIGH, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, batch-report, fee-calculation, double-counting, report-ordering, multi-asset]

- id: oracle-029
  pattern: oracle-aggregation-cherry-picking
  name: "Non-deterministic oracle selection allows user cherry-picking"
  causa_raiz: >
    Multi-oracle aggregation systems require users to submit price data from a
    subset of available oracles meeting a minimum weight threshold. When multiple
    valid subsets exist, a sophisticated user can choose the subset that produces
    the most favorable aggregated price. During volatile periods, oracle sources
    naturally diverge, widening the range of achievable prices. Additionally,
    mean-based outlier detection shifts the reference point based on which oracles
    are included, making the filter non-deterministic -- borderline values are
    included or excluded based on the specific combination submitted.
  como_funciona: >
    1. Protocol has 3 oracles weighted 1/1/1 with threshold 2.
    2. Oracle A reports $100, Oracle B reports $101, Oracle C reports $98.
    3. User wanting high price submits {A, B} -> aggregated $100.50.
    4. User wanting low price submits {B, C} -> aggregated $99.50.
    5. $1.00 difference exploitable across deposit/borrow cycle.
    6. Mean-based outlier detection compounds the issue: including/excluding
       one oracle shifts the mean, which changes which oracles pass the
       outlier filter, producing cascading non-determinism.
  invariante: >
    // All valid oracle subsets must produce prices within acceptable range
    // Or: require ALL oracles, not a subset
    assert(maxAggPrice - minAggPrice <= MAX_ACCEPTABLE_SPREAD);
  que_mirar:
    - "grep: collect.*price, aggregate.*oracle, weight.*threshold"
    - "grep: outlier.*mean, outlier.*average, filterPrice"
    - "Can users choose which oracle sources to submit?"
    - "Is there a minimum requirement to submit ALL available oracles?"
    - "Does outlier detection use mean-based or median-based filtering?"
  como_se_arregla: >
    Require users to submit ALL registered price feeds, not a subset.
    Use median-based outlier filtering instead of mean-based.
    Implement deterministic oracle selection (primary, secondary, fallback)
    where primary+secondary must agree within threshold.
    Prevent user from choosing which oracles to include.
  trampas:
    - "Works fine in low-volatility conditions when all oracles agree"
    - "Mean-based filtering is academically common but operationally fragile"
    - "Weight threshold seems secure but allows subset selection"
  solodit_ids: []
  incidentes:
    - "Bucket Protocol V2 -- non-deterministic oracle selection lets user cherry-pick favorable subset (LOW->MEDIUM, Quantstamp)"
    - "Bucket Protocol V2 -- mean-sensitive outlier detection produces non-deterministic aggregated price (LOW, Quantstamp)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, aggregation, cherry-picking, non-deterministic, outlier-detection, mean, median]

- id: oracle-030
  pattern: oracle-failure-silent-zero-propagation
  name: "Oracle failure silently returns zero, cascading through dependent calculations"
  causa_raiz: >
    When an oracle fails (stale data, feed down, access revoked), the error-handling
    returns 0 instead of reverting. This zero propagates through multiplication chains
    in dependent calculations (voting power, collateral value, reward accrual),
    silently producing zero output. Unlike oracle-004 (zero price FROM oracle), this
    pattern is about the protocol's error handler converting oracle failures to zero,
    then using that zero in critical calculations without any further check. The zero
    is semantically "no data" but is treated as "value is zero."
  como_funciona: >
    1. Oracle feed returns stale data or reverts.
    2. Protocol's getPriceAt() catches error, returns 0 (not revert).
    3. Downstream: votingPower = stake * getTokenPriceAt() = stake * 0 = 0.
    4. Operator loses all voting power despite having active stake.
    5. Votes pass with incorrect quorum because staked operators show 0 power.
    6. Variant: reward accrual uses stale oracle -> getAccruedYield() underpays.
    7. Variant: collateral valuation -> loan appears worthless, triggers false liquidation.
  invariante: >
    // Oracle failure must either revert or propagate a sentinel value
    // that downstream consumers check explicitly
    (bool success, uint256 price) = oracle.tryGetPrice();
    assert(success || operationReverted);
    // Zero price must never silently enter calculations
    assert(price > 0 || !priceUsedInCalculation);
  que_mirar:
    - "grep: return.*success.*0, return.*false.*0, catch.*return 0"
    - "grep: getPriceAt.*return.*0, getPrice.*catch"
    - "grep: stakeToVotingPower.*getTokenPrice, reward.*oracle.*price"
    - "Do oracle error handlers return 0 or revert?"
    - "Do downstream consumers check for zero price?"
    - "Is 0 a valid price in any supported asset?"
  como_se_arregla: >
    Oracle error handlers should revert, not return 0.
    If returning 0 is needed for non-critical paths, wrap in (bool success, uint256 price)
    and require callers to check success flag.
    Add explicit require(price > 0) before any multiplication.
    Separate "oracle unavailable" from "price is zero" with distinct return values.
  trampas:
    - "Returning 0 on failure seems safer than reverting but silently corrupts"
    - "Zero propagates through multiplication without triggering any check"
    - "Only manifests during actual oracle downtime -- hard to test"
  solodit_ids: []
  incidentes:
    - "Symbiotic -- ChainlinkPriceFeed.getPriceAt returns 0 on failure, zeroes operator voting power (MEDIUM, Cyfrin)"
    - "NUTS Finance -- zero price cast from negative passes through, halts liquidation (MEDIUM, MixBytes)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, silent-zero, error-handling, voting-power, cascading-failure, propagation]

- id: oracle-031
  pattern: flat-oracle-price-ignores-pool-imbalance
  name: "Oracle-priced AMM ignores pool imbalance, enabling infinite-size trades at flat price"
  causa_raiz: >
    Some DEX designs use oracle prices to center passive liquidity orders rather
    than using a constant-product (x*y=k) curve. When the pool reflects orders
    symmetrically around the oracle price with geometric spacing, an asymmetric
    liquidity deposit (all on one side) causes every ask order to be placed at
    the same oracle-derived price regardless of trade size. Unlike traditional
    AMMs where large trades move the price, the oracle-priced pool sells unlimited
    quantity at the flat oracle price. This is fundamentally different from spot
    price manipulation (oracle-002) because here the oracle price IS correct --
    the bug is that pool mechanics don't apply price impact.
  como_funciona: >
    1. Geometric pool reflects bid/ask orders around oracle-derived marginal price.
    2. Attacker deposits liquidity asymmetrically (e.g., only quote token).
    3. All ask-side orders collapse to the same price = oracle price.
    4. Attacker (or any user) can buy unlimited base tokens at flat oracle price.
    5. No price impact regardless of trade size.
    6. Liquidity providers suffer losses: sold all base tokens at no premium.
    7. Attacker can buy large amounts cheaply, then sell on other venues.
  invariante: >
    // Effective execution price must increase with trade size
    uint256 price_small = pool.getEffectivePrice(smallAmount);
    uint256 price_large = pool.getEffectivePrice(largeAmount);
    assert(price_large >= price_small);
  que_mirar:
    - "grep: reflect_curve, oracle_querier, marginal_price, geometric"
    - "grep: bid_starting_price, ask_starting_price, tick_spacing"
    - "Does pool pricing depend on reserve balances or only oracle?"
    - "What happens when liquidity is deposited asymmetrically?"
    - "Is there price impact proportional to trade size?"
  como_se_arregla: >
    Incorporate pool balance/inventory into price reflection logic.
    Apply price impact based on actual reserves, not just oracle price.
    Limit maximum order size per price level.
    Validate that ask prices increase with cumulative volume.
    Consider hybrid model: oracle-centered with balance-weighted spread.
  trampas:
    - "Symmetric deposits work fine -- bug only appears with asymmetric liquidity"
    - "Oracle price is correct -- the issue is the pool mechanics, not the oracle"
    - "Standard AMM invariant testing misses this because x*y=k doesn't apply"
  solodit_ids: []
  incidentes:
    - "Dango DEX -- asymmetric liquidity in geometric pool allows purchase at flat oracle price, unbounded size (HIGH, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, amm, geometric-pool, flat-price, price-impact, asymmetric-liquidity, passive-orders]

- id: oracle-032
  pattern: cross-oracle-decimal-normalization-in-comparison
  name: "Cross-oracle comparison fails due to different decimal precision between providers"
  causa_raiz: >
    When protocols use multiple oracle providers (e.g., API3 + eOracle, Chainlink +
    Pyth) for price validation or fallback, the raw prices from different providers
    may have different decimal precision. If the protocol compares these prices
    directly without normalizing decimals first, the delta calculation produces
    nonsensical results. A 5% divergence check between an 18-decimal price and an
    8-decimal price will always find them "divergent," causing the protocol to
    permanently fall back to one oracle or reject all prices. This differs from
    oracle-006 (single oracle decimal mismatch) because here both oracles return
    correct prices -- the comparison logic between them is broken.
  como_funciona: >
    1. Protocol queries API3 oracle: returns price with 18 decimals ($3000e18).
    2. Protocol queries eOracle: returns price with 8 decimals ($3000e8).
    3. Delta check: abs(3000e18 - 3000e8) / 3000e8 = enormous percentage.
    4. Exceeds maxPriceDelta threshold, API3 price is rejected.
    5. Protocol always falls back to eOracle regardless of which is fresher.
    6. If eOracle is stale, protocol uses stale price with no fallback.
    7. Variant: DoS when both oracles are required to agree but never can.
  invariante: >
    // Cross-oracle comparison must normalize decimals first
    uint256 priceA_normalized = priceA * 10**(targetDecimals - decimalsA);
    uint256 priceB_normalized = priceB * 10**(targetDecimals - decimalsB);
    uint256 delta = abs(priceA_normalized - priceB_normalized);
    assert(delta * BPS / priceB_normalized <= maxDeltaBps);
  que_mirar:
    - "grep: _absDiff.*Price, deltaBps, maxPriceDelta"
    - "grep: api3.*eOracle, chainlink.*pyth.*compare"
    - "grep: decimals.*getLatestPrice, feedDecimals.*compare"
    - "Are prices from different oracles normalized before comparison?"
    - "Do both oracle providers use the same decimal precision?"
    - "What happens when the delta check fails -- DoS or silent fallback?"
  como_se_arregla: >
    Normalize all oracle prices to a common precision (e.g., 18 decimals)
    BEFORE any comparison or delta calculation.
    Read decimals() from each provider dynamically.
    Test with oracle pairs that have different decimal precisions.
    Ensure fallback logic works correctly when comparison fails.
  trampas:
    - "Both oracles return correct prices -- the bug is only in comparison logic"
    - "Works fine when both providers happen to use same decimals"
    - "Manifests as permanent fallback to one oracle, not obvious as a bug"
  solodit_ids: []
  incidentes:
    - "Malda MixedPriceOracleV4 -- API3 (18 dec) vs eOracle (8 dec) comparison always divergent, permanent fallback (MEDIUM, Sherlock)"
    - "Malda -- getUnderlyingPrice DoS for tokens where oracle decimals differ (MEDIUM, Sherlock)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit R2"
  tags: [oracle, cross-oracle, decimal-normalization, comparison, api3, eoracle, multi-provider, fallback]

- id: oracle-033
  pattern: twap-zero-seconds-fallback-spot
  name: "twapSeconds=0 en configuración -> usa precio spot (slot0) en lugar de TWAP"
  causa_raiz: >
    _getReferencePoolPriceX96 usa twapSeconds=0 como señal para leer el precio spot
    desde slot0() en lugar de calcular TWAP via pool.observe(). Si un token se
    configura con twapSeconds=0 y mode=TWAP o TWAP_CHAINLINK_VERIFY, el oráculo
    usa el precio spot del pool (sqrtPriceX96) completamente manipulable con un
    flash loan en el mismo bloque. El modo CHAINLINK_TWAP_VERIFY es el que actúa
    de primario con Chainlink -- si el modo es TWAP_CHAINLINK_VERIFY con twapSeconds=0,
    el precio primario es spot y Chainlink solo verifica con maxDifference de margen.
  como_funciona: >
    1. Admin configura token con twapSeconds=0 y mode=TWAP_CHAINLINK_VERIFY.
    2. _getReferencePoolPriceX96 -> _getTWAPPriceX96 -> _getReferencePoolPriceX96(pool, 0).
    3. twapSeconds==0 entra al branch: (sqrtPriceX96,) = _getPoolSlot0(pool) -> precio spot.
    4. Atacante flash-loanea para mover sqrtPriceX96 en el pool de referencia.
    5. Oracle retorna precio spot manipulado como precio primario.
    6. _requireMaxDifference verifica vs Chainlink con maxDifference -- si la desviacion
       permitida es >= 5%, el precio manipulado puede pasar la verificacion.
    7. Vault valoriza posicion como colateral con precio inflado -> borrow excess.
  invariante: "twapSeconds > 0 para cualquier token configurado en modo TWAP o TWAP_CHAINLINK_VERIFY"
  que_mirar:
    - "Algun token tiene twapSeconds=0 con mode != CHAINLINK? (linea 444 V3Oracle.sol)"
    - "Puede setTokenConfig configurar twapSeconds=0 con mode=TWAP_CHAINLINK_VERIFY?"
    - "maxDifference del token es suficientemente amplio para que un precio spot manipulado pase la verificacion Chainlink?"
    - "El modo CHAINLINK_TWAP_VERIFY tiene el mismo riesgo? (No -- Chainlink es primario ahi)"
  como_se_arregla: "Anadir require(twapSeconds > 0) en setTokenConfig cuando mode != CHAINLINK. Si twapSeconds=0 es intencional para algun uso, forzar mode=CHAINLINK en ese caso para que no use el pool price como primario."
  trampas:
    - "El modo CHAINLINK puro (Mode.CHAINLINK) no usa TWAP en absoluto -- twapSeconds=0 es correcto e inofensivo para ese modo"
    - "El modo CHAINLINK_TWAP_VERIFY usa Chainlink como primario y TWAP como verificacion -- si el TWAP spot es manipulado, solo causa revert, no explotacion"
    - "El peligro real es TWAP_CHAINLINK_VERIFY con twapSeconds=0: spot manipulable como precio primario con Chainlink como safety net con margen"
  severidad: high
  confianza: alta
  fuente: "analisis V3Oracle.sol lineas 441-445 _getReferencePoolPriceX96() revert-lend 2026-03-20"
  verificado: true
  tags: [twap, slot0, spot-price, flash-loan, oracle-config, V3Oracle, twapSeconds]
  relacionado_con: [oracle-002, oracle-003, oracle-008]

- id: oracle-034
  pattern: aerodrome-slipstream-twap-low-liquidity
  name: "TWAP en pools Aerodrome Slipstream: ventana fija + baja liquidez = manipulable"
  causa_raiz: >
    V3Oracle acepta pools Aerodrome Slipstream como fuente de TWAP (via factory.getPool
    con tickSpacing como selector). Los pools Slipstream en pares exoticos o chains
    jovenes tienen tipicamente menos liquidez que los pools Uniswap V3 equivalentes.
    El costo de manipulacion de un TWAP escala con la liquidez del pool x la ventana
    en segundos. Un pool con $100K TVL es 100x mas barato de manipular que uno con
    $10M TVL a igual ventana. El tickSpacing tambien afecta la granularidad del TWAP:
    tickSpacing=1 -> precio cambia un tick a la vez (TWAP muy granular, susceptible a
    desplazamientos continuos); tickSpacing=200 -> precio salta 200 ticks cada crossing
    (TWAP mas grueso pero mas caro de mover). Una ventana twapSeconds "segura" para
    un pool de alta liquidez puede ser insegura para uno de baja liquidez.
  como_funciona: >
    1. Admin configura token con pool Slipstream de baja liquidez (ej: token exotico/WETH
       en pool reciente con $300K TVL) como oraculo TWAP con twapSeconds=1800.
    2. Mismo twapSeconds=1800 en un pool Uniswap V3 con $50M TVL es seguro.
    3. En el pool Slipstream de $300K: atacante mantiene swap distorsionado durante 30 min.
    4. Costo: proporcional a liquidez x tiempo. Con $300K, el costo puede ser viable.
    5. V3Oracle retorna precio sesgado -> posicion colateral overvalued -> borrow excess.
    6. Posicion queda undercollateralized al restaurarse el precio real.
  invariante: "TVL(pool_twap) x twapSeconds > max_extractable_value_from_protocol -- el costo de manipulacion debe ser mayor que el beneficio"
  que_mirar:
    - "Cual es el TVL actual de cada pool configurado en feedConfigs[token].pool?"
    - "Es un pool Slipstream con tickSpacing=1 (maxima granularidad de precio)?"
    - "twapSeconds es suficientemente largo dado el TVL concreto de ese pool?"
    - "El modo es CHAINLINK_TWAP_VERIFY (TWAP solo verifica, Chainlink es primario -- mas seguro) o TWAP_CHAINLINK_VERIFY (TWAP es primario -- expuesto)?"
    - "Hay incentivos activos en el pool que garanticen alta liquidez permanente?"
  como_se_arregla: "Para colateral de alto valor, preferir CHAINLINK_TWAP_VERIFY (Chainlink primario, TWAP como verificacion). Documentar requisito minimo de liquidez (ej: $5M TVL) antes de habilitar modo con TWAP primario. Usar tickSpacing alto (100-200) en pools oraculo."
  trampas:
    - "tickSpacing bajo (1) NO implica pool inseguro si tiene alta liquidez -- es la liquidez, no el tickSpacing, lo que determina el costo de manipulacion"
    - "Aerodrome puede tener farming activo con millones en incentivos -- la liquidez varia radicalmente segun el epoch de rewards; verificar en tiempo real"
    - "En modo CHAINLINK_TWAP_VERIFY, un TWAP manipulado solo causa revert del oracle (PriceDifferenceExceeded), no explotacion del vault"
  severidad: high
  confianza: media
  fuente: "analisis V3Oracle.sol setTokenConfig() + _getPool() + _getReferencePoolPriceX96() revert-lend 2026-03-20"
  verificado: false
  tags: [twap, aerodrome, slipstream, liquidity, oracle, tick-spacing, pool-selection, base-chain]
  relacionado_con: [oracle-003, oracle-008, oracle-002]

- id: oracle-035
  pattern: derived-price-out-of-range-position-valuation
  name: "derivedSqrtPriceX96 valua posicion en rango distinto al real -> liquidacion prematura o tardia"
  causa_raiz: >
    V3Oracle calcula el valor de la posicion usando derivedSqrtPriceX96 (calculado
    desde precios oracle Chainlink/TWAP) y NO el precio actual del pool (slot0).
    _getAmounts usa derivedSqrtPriceX96 para calcular la distribucion token0/token1
    de la posicion via LiquidityAmounts.getAmountsForLiquidity. Si el precio oracle
    difiere del precio del pool (dentro del maxPoolPriceDifference permitido), la
    valoracion puede poner la posicion en un rango diferente al real: oracle dice
    "in-range" (ambos tokens), pool real dice "out-of-range" (solo un token), o
    viceversa. Esto causa valoracion incorrecta del colateral.
  como_funciona: >
    Escenario A -- sobrecolateralizacion aparente (liquidacion tardia):
    1. Posicion tiene rango [tickLower=1000, tickUpper=1200], pool tick actual=1050 (in-range real).
    2. Oracle Chainlink tiene precio ligeramente menor -> derivedSqrtPrice -> tick=950 (under tickLower).
    3. _getAmounts con derivedSqrtPrice calcula: posicion out-of-range abajo -> solo token1.
    4. Oracle valua menos colateral del real -> puede triggear liquidacion innecesaria.
    Escenario B -- subcolateralizacion oculta (liquidacion prematura bloqueada):
    5. Posicion near upper boundary: pool tick=1195, oracle tick=1205 (over tickUpper).
    6. _getAmounts: solo token0 (out-of-range arriba) pero pool real tiene ambos tokens.
    7. Oracle subvalua el colateral -> posicion parece undercollateralized -> liquidacion prematura.
    8. Arbitrageurs deben mover el precio de vuelta antes de que se pueda liquidar correctamente.
  invariante: "La valoracion oracle de la posicion no debe diferir de la valoracion real en mas de maxPoolPriceDifference x position_value"
  que_mirar:
    - "maxPoolPriceDifference es generoso (>500 = 5%)? Mayor tolerancia = mayor riesgo de valoracion incorrecta en posiciones near-boundary"
    - "Hay posiciones con rangos estrechos (tickUpper - tickLower < 200 ticks)?"
    - "Los rangos de las posiciones estan cerca de los ticks actuales del pool (near-boundary = mayor impacto de divergencia oracle/pool)?"
    - "_populatePrices revierte si hay divergencia excesiva? Esto bloquea liquidaciones necesarias?"
  como_se_arregla: "Este es un tradeoff de diseno documentado: usar derivedSqrtPrice previene ataques de manipulacion del pool. Para mitigar liquidaciones prematuras por divergencia oracle, reducir maxPoolPriceDifference y usar siempre CHAINLINK_TWAP_VERIFY con oraculos de alta calidad."
  trampas:
    - "V3Oracle USA INTENCIONALMENTE derivedSqrtPriceX96 para prevenir manipulacion del pool -- esta documentado en el codigo (linea 522-529). No es un bug per se, es un tradeoff"
    - "maxPoolPriceDifference actua de circuit breaker: si spot y oracle divergen demasiado, _populatePrices reverts -- esto bloquea liquidaciones pero tambien bloquea explotacion"
    - "El comportamiento 'bloquear liquidaciones cuando el precio esta manipulado' es intencional: esperar a que arbitrageurs restauren el precio antes de liquidar"
  severidad: medium
  confianza: media
  fuente: "analisis V3Oracle.sol _getAmounts() + _populatePrices() lineas 515-533 y 549-557 revert-lend 2026-03-20"
  verificado: true
  tags: [oracle, twap, position-valuation, in-range, out-of-range, liquidation, concentrated-liquidity, derivedSqrtPrice]
  relacionado_con: [oracle-002, oracle-003, oracle-034]

- id: oracle-036
  pattern: v3-uncollected-fees-collateral-manipulation
  name: "V3 oracle incluye fees no cobrados en valor de colateral — inflables via swap donation"
  causa_raiz: >
    V3Oracle._getFees() calcula fees no cobrados (feeGrowthInside) + tokensOwed para
    ambos tokens y los suma al valor de la posicion. Cuando ignoreFees=false (posicion
    no stakeada), el valor total del colateral incluye feeValue. Un atacante puede
    inflar artificialmente los fees de una posicion haciendo swaps en el pool para
    generar fee growth — especialmente facil en pools de bajo volumen donde el atacante
    controla el flujo. O bien, la posicion tiene tokensOwed acumulados de una operacion
    anterior que el atacante no ha cobrado, y los usa como "colateral fantasma".
  como_funciona: |
    1. Atacante crea posicion V3 narrow-range con liquidez minima en pool de bajo TVL.
    2. Hace swaps circulares (flash loan) a traves del pool para generar fee growth dentro
       del rango de la posicion. Los fees se acumulan en feeGrowthInside.
    3. Deposita la posicion como colateral. Oracle la valua con incluir fees inflados.
    4. Pide prestado contra el valor inflado (liquidez + fees artificiales).
    5. Cobra los fees via transformer/decreaseLiquidityAndCollect despues del borrow.
    6. Colateral colapsa a solo el valor de liquidez minima. Posicion undercollateralizada.
    Variante tokensOwed:
    1. Posicion antigua con tokensOwed acumulados (collect() parcial).
    2. tokensOwed[0/1] persisten en NonfungiblePositionManager incluso si liquidity=0.
    3. Oracle suma tokensOwed a fees calculados — valores reales pero colectables en cualquier momento.
    4. Si transformer permite collect() sin health check, colateral desaparece post-borrow.
  invariante: |
    // fees no deben ser colectables despues del borrow sin health check
    // si fees son incluidos como colateral, collectFees() debe re-verificar health
    assert(feeCollect => healthCheckAfter);
    // feeValue no debe superar X% del valor total (cap de exposicion)
    assert(feeValue <= fullValue * MAX_FEE_COLLATERAL_RATIO);
  que_mirar:
    - "Puede el usuario llamar a decreaseLiquidityAndCollect() para cobrar fees despues de borrow()?"
    - "_requireLoanIsHealthy se llama despues de collect? (linea 687 V3Vault.sol: si)"
    - "Hay un cap en feeValue como porcentaje de collateralValue?"
    - "Pool del collateral tiene bajo TVL — swaps circulares son baratos para inflar fees?"
    - "ignoreFees=true solo para posiciones stakeadas — posiciones no stakeadas siempre incluyen fees"
    - "rg 'ignoreFees|feeValue|tokensOwed|getFees' --type sol"
  como_se_arregla: >
    Opcion 1: Cap feeValue al X% del collateral value total antes de usarla.
    Opcion 2: ignoreFees=true siempre (no incluir fees en collateral — mas conservador).
    Opcion 3: Verificar que despues de collect() se re-checkea health (ya implementado en V3Vault.sol:687).
    Nota: V3Vault ya tiene _requireLoanIsHealthy post-collect — reduce explotabilidad pero
    no elimina la ventana de inflacion previa al borrow.
  trampas:
    - "V3Vault.decreaseLiquidityAndCollect() YA llama _requireLoanIsHealthy despues — esto mitiga pero no elimina"
    - "La inflacion de fees via swaps circulares tiene costo real (fee del pool) — calcular si es rentable"
    - "En pools de alta liquidez, el costo de inflar fees supera el beneficio — atacar pools de bajo TVL"
    - "ignoreFees se lee de _isStaked() — solo staked positions excluyen fees"
  solodit_ids: []
  incidentes:
    - "Olympus RBS 2.0 (Sherlock) — BunniToken price uses fees in reserve validation inconsistently (MEDIUM)"
    - "ParaSpace (Code4rena H-05) — Attacker manipulates low TVL UniV3 pool to inflate collateral (HIGH)"
  severidad: high
  confianza: media
  verificado: false
  fuente: "Analisis V3Oracle._getFees() + V3Vault._checkLoanIsHealthy() revert-lend 2026-03-21. Solodit: Olympus oracle-M-2, ParaSpace oracle-H-05"
  tags: [oracle, v3-position, fees, collateral, fee-growth, tokensOwed, manipulation, lending]
  relacionado_con: [oracle-035, lending-034, lending-041]

- id: oracle-037
  pattern: v3-position-value-excludes-accumulated-fees
  name: "getPositionValue() no incluye fees acumulados — colateral subvalorado genera liquidaciones prematuras"
  causa_raiz: >
    La valoracion de posiciones V3 como colateral debe incluir tanto el valor de la
    liquidez (amounts calculados via getAmountsForLiquidity) como los fees acumulados
    (feeGrowthInside * liquidity, mas tokensOwed previos). Si la funcion de valoracion
    omite los fees acumulados, el colateral se subvalora, haciendo que posiciones saludables
    parezcan undercollateralizadas y sean liquidadas prematuramente. El patron es el opuesto
    a oracle-036 (sobre-conteo de fees): aqui el problema es no contarlos cuando deberian
    contarse, perjudicando al usuario honesto en lugar del atacante.
  como_funciona: |
    1. Usuario tiene posicion V3 en rango activo con $50K de liquidez y $10K de fees acumulados.
    2. Protocolo llama getPositionValue(tokenId) que solo calcula:
       value = amount0 * price0 + amount1 * price1  (solo liquidez)
    3. Ignora: tokensOwed0, tokensOwed1, feeGrowthInside acumulado.
    4. Colateral reportado: $50K. Valor real: $60K.
    5. Si usuario pide prestado $55K (sano en realidad: 60K/55K = 1.09 > 1.05 threshold),
       el protocolo lo ve como $50K colateral vs $55K deuda = unhealthy.
    6. Liquidacion ejecutada sobre posicion que ERA sana.
    7. Usuario pierde $5-10K en penalidad de liquidacion innecesaria.
    Variante impacto inverso (lending-046 direction):
    Si los fees SI se incluyen pero el usuario los extrae via collect() post-borrow sin
    re-valoracion, el colateral colapsa. El patron aqui es el problema OPUESTO.
  invariante: |
    // El valor de colateral debe incluir todos los activos reclamables de la posicion
    (uint256 amount0, uint256 amount1) = getAmountsForLiquidity(pos.liquidity, sqrtPrice, tickLower, tickUpper);
    (uint256 fees0, uint256 fees1) = getAccumulatedFees(tokenId);  // feeGrowthInside + tokensOwed
    uint256 fullValue = (amount0 + fees0) * price0 + (amount1 + fees1) * price1;
    uint256 reportedValue = oracle.getPositionValue(tokenId);
    // Permitir hasta 1% de diferencia por rounding
    assert(reportedValue >= fullValue * 99 / 100);
  que_mirar:
    - "¿getPositionValue() suma tokensOwed0 y tokensOwed1 al valor total?"
    - "¿Se calcula feeGrowthInside * liquidity para fees no reclamados aun?"
    - "¿Hay un flag ignoreFees que desactiva la inclusion de fees? ¿En que condiciones?"
    - "¿Los fees son incluidos solo para algunas categorias de posicion (staked vs non-staked)?"
    - "rg 'getPositionValue|tokensOwed|feeGrowthInside|_getFees|ignoreFees' --type sol"
    - "rg 'getLiquidityAmounts|getAmountsForLiquidity' --type sol — verificar si hay suma de fees despues"
  como_se_arregla: >
    Asegurar que getPositionValue() incluya TODOS los activos reclamables de la posicion:
    (1) amounts de liquidez via getAmountsForLiquidity con sqrtPrice apropiado,
    (2) fees acumulados via feeGrowthInside0Last/1Last * liquidity / Q128,
    (3) tokensOwed0/1 residuales del NonfungiblePositionManager.
    Usar derivedSqrtPrice (basado en TWAP Chainlink) en lugar de spot para resistir manipulacion.
    Revert Lend V3Oracle._getFees() implementa correctamente los tres componentes.
  trampas:
    - "Incluir fees puede ser explotado en la direccion opuesta (oracle-036): fees inflados artificialmente"
    - "El fix correcto balancea ambos lados: incluir fees reales, pero usar TWAP para el precio base"
    - "Algunos protocolos excluyen fees intencionalmente por simplicidad — verificar si hay documentacion"
    - "En posiciones out-of-range (currentTick fuera del rango), fees siguen acumulandose pero amounts=0"
    - "tokensOwed solo crece, nunca decrece espontaneamente — siempre representan valor real cobrable"
  solodit_ids: []
  incidentes:
    - "Omo_2025-01-25 (Pashov Audit Group) — H-12: getPositionValue() only retrieves liquidity token amounts, does not account for accumulated fees; positions undervalued as collateral (HIGH, Pashov)"
    - "Revert Lend (Code4rena 2024) — M-19: V3Oracle susceptible to price manipulation via spot sqrtPrice for amounts calculation; fees component correct but amounts manipulable (MEDIUM, Code4rena)"
    - "Astaria (Spearbit) — UNI_V3Validator.validateAndParse() uses slot0 for LP value via getLiquidityAmounts, no TWAP (MEDIUM, Spearbit)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Omo_2025-01-25 Pashov H-12 https://solodit.xyz/issues/h-12-getpositionvalue-does-not-consider-accumulated-fees-pashov-audit-group-none-omo_2025-01-25-markdown"
  tags: [oracle, v3-position, fees, collateral, tokensOwed, feeGrowthInside, undervaluation, premature-liquidation, position-valuation]
  relacionado_con: [oracle-036, oracle-035, lending-040, lending-045]

- id: oracle-038
  pattern: v3oracle-max-difference-bypass-uint16-max
  name: "V3Oracle: maxDifference=type(uint16).max deshabilita la verificacion cruzada Chainlink/TWAP"
  causa_raiz: >
    _requireMaxDifference() en V3Oracle tiene la condicion de bypass explicita:
    `if (...) && maxDifferenceX10000 < type(uint16).max`. Si maxDifference se configura
    como 65535 (type(uint16).max), la condicion siempre es false y la verificacion
    cruzada se salta completamente. En modo CHAINLINK_TWAP_VERIFY o TWAP_CHAINLINK_VERIFY,
    esto significa que el oraculo secundario (TWAP o Chainlink) nunca verifica al primario
    sin importar cuanto difieran. El admin puede fijar este valor al configurar un token
    con setTokenConfig(..., maxDifference=65535), degradando el oraculo a modo simple.
  como_funciona: |
    1. Admin llama setTokenConfig(token, feed, maxFeedAge, pool, twapSeconds,
       Mode.CHAINLINK_TWAP_VERIFY, 65535).
    2. V3Oracle almacena maxDifference=65535 (type(uint16).max) en feedConfigs[token].
    3. _requireMaxDifference(priceX96, verifyPriceX96, 65535):
       differenceX10000 / verifyPriceX96 = LARGE_VALUE
       Condicion: (verifyPriceX96 == 0 || LARGE_VALUE > 65535) && 65535 < 65535
       Segundo operando (65535 < 65535) = FALSE -> revert nunca ocurre.
    4. Oracle acepta precio Chainlink SIN verificar contra TWAP, aunque TWAP sea 10x diferente.
    5. Si Chainlink price feed es comprometido/stale pero answer > 0 y dentro de maxFeedAge,
       el precio incorrecto pasa sin resistencia.
    Escenario de explotacion con oracle feed comprometido:
    - Attacker compromete o manipula un feed Chainlink de baja liquidez.
    - TWAP muestra precio real, Chainlink muestra precio inflado 2x.
    - Con maxDifference=65535 la discrepancia pasa sin revert.
    - Vault valoriza colateral al precio Chainlink inflado -> excess borrow.
  invariante: "feedConfigs[token].maxDifference < type(uint16).max para cualquier token en modo CHAINLINK_TWAP_VERIFY o TWAP_CHAINLINK_VERIFY"
  que_mirar:
    - "grep: feedConfigs, maxDifference, setTokenConfig, 65535, type(uint16).max"
    - "Para cada token configurado: feedConfigs[token].maxDifference == 65535?"
    - "El modo del token es CHAINLINK_TWAP_VERIFY o TWAP_CHAINLINK_VERIFY (modos que usan dos oracles)?"
    - "Si maxDifference < 65535, cual es el porcentaje permitido? (maxDifference/100 = %). >20% es alto riesgo."
    - "Linea 172 V3Oracle.sol: `&& maxDifferenceX10000 < type(uint16).max` — esta condicion es el bypass"
  como_se_arregla: >
    Opcion 1: Remover la condicion de bypass del segundo operando. Si maxDifference=uint16.max
    fuera necesario para tokens de referencia (referenceToken usa CHAINLINK puro, no necesita maxDifference),
    restringir el bypass solo para mode==CHAINLINK.
    Opcion 2: En setTokenConfig, require(maxDifference < type(uint16).max) cuando
    mode == CHAINLINK_TWAP_VERIFY || mode == TWAP_CHAINLINK_VERIFY.
    Opcion 3: Documentar que maxDifference=uint16.max es intencional para "modo debug" con timelock de admin.
  trampas:
    - "El bypass existe INTENCIONALMENTE en el codigo: es un modo de operacion con verificacion desactivada, no un bug de implementacion"
    - "Mode.CHAINLINK puro no usa maxDifference (la verificacion cruzada no aplica) -- correcto que bypass funcione ahi"
    - "Si el admin es multisig con timelock, configurar maxDifference=65535 requiere governance -- riesgo reducido"
    - "Para el bug ser explotable sin admin compromise, el finding necesita demostrar que el DEFAULT para algun token es 65535"
  solodit_ids: []
  incidentes:
    - "Revert Lend V3Oracle -- maxDifference=type(uint16).max documentado como bypass de verificacion (linea 172 V3Oracle.sol); no hay incidente externo equivalente directo"
    - "Morpho Blue (Cantina) -- oracle price deviation enables arbitrage in high-LLTV markets; sin bypass explicito pero patron de 'maxDifference demasiado generoso' (MEDIUM, Cantina)"
    - "f(x) v2 (OpenZeppelin) -- pools subject to price manipulation when Chainlink anchor has wide deviation threshold vs actual price (HIGH, OZ)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Analisis directo V3Oracle.sol linea 172 _requireMaxDifference(). Solodit: Morpho Blue Cantina deviation-arbitrage, f(x) v2 OZ price-manipulation"
  tags: [oracle, chainlink, twap, cross-validation, bypass, maxDifference, uint16, V3Oracle, config]
  relacionado_con: [oracle-033, oracle-034, oracle-013]
```

---

## 2. Invariantes Clave

Derived from `invariant-registry/universal/exploit_derived.json` (INV-EXPLOIT-001, 015, 021).

### Spot vs TWAP deviation (INV-EXPLOIT-001)

```solidity
// CRITICAL: #1 DeFi exploit pattern (~25% of all hacks per defihacklabs)
assert(
    spotPrice <= twapPrice * (100 + MAX_DEVIATION_PCT) / 100 &&
    spotPrice >= twapPrice * (100 - MAX_DEVIATION_PCT) / 100
);
```

Historical hit rate: 45%. Composes with flash loan and thin liquidity attacks.

### Staleness + validity (INV-EXPLOIT-015)

```solidity
(, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
assert(price > 0 && block.timestamp - updatedAt < MAX_STALENESS);
```

Historical hit rate: 35%. MAX_STALENESS must match per-feed Chainlink heartbeat.

### Minimum liquidity threshold (INV-EXPLOIT-021)

```solidity
assert(
    poolLiquidity >= MIN_LIQUIDITY_THRESHOLD || !usingPoolForPricing
);
```

Historical hit rate: 35%. Protocols on new chains or exotic pairs are prime targets.

---

## 3. Checklist Rapido

Oracle audit -- run through for every target:

```
[ ] Grep: latestAnswer, getAnswer, getTimestamp (deprecated functions)
[ ] Grep: latestRoundData -- are ALL return values validated?
[ ] Check: price > 0 after every oracle read
[ ] Check: updatedAt freshness against feed-specific heartbeat
[ ] Check: answeredInRound >= roundId
[ ] Grep: getReserves, slot0, sqrtPriceX96 (spot price reads)
[ ] If spot price used: is TWAP or Chainlink cross-validation present?
[ ] Grep: observe, consult (TWAP reads) -- what window length?
[ ] If TWAP window < 30 min: flag as manipulable
[ ] Check: observationCardinality sufficient for window?
[ ] Check: feed.decimals() called or hardcoded assumption?
[ ] Check: token decimals + oracle decimals combined correctly?
[ ] If L2: sequencer uptime feed checked?
[ ] If L2: grace period after sequencer restart?
[ ] Check: fallback oracle path exists?
[ ] Check: circuit breaker for extreme price events?
[ ] Check: minAnswer/maxAnswer on Chainlink aggregator (hidden staleness)
```

### Grep patterns for fast triage

```bash
# Deprecated Chainlink
grep -rn "latestAnswer\|getAnswer\|getTimestamp" src/

# Spot price reads (flash loan vulnerable)
grep -rn "getReserves\|slot0\|sqrtPriceX96\|currentPrice" src/

# TWAP reads
grep -rn "observe\|consult\|price0CumulativeLast\|price1CumulativeLast" src/

# Staleness checks (should exist near latestRoundData)
grep -rn "updatedAt\|staleness\|heartbeat\|MAX_STALENESS" src/

# L2 sequencer
grep -rn "sequencer\|isSequencerUp\|GRACE_PERIOD" src/

# Decimals handling
grep -rn "\.decimals\(\)\|1e8\|1e18\|10\*\*8\|10\*\*18" src/
```

---

## Solodit Verified Findings

### Maps to oracle-001 (Chainlink stale heartbeat)

- **[HIGH] Oracle data feed outdated yet used, impacting payment logic (Solodit oracle-4)** -- Protocol uses outdated oracle price for payment/settlement calculations; no freshness check means payments execute at prices hours or days old, causing systematic over/underpayment.
- **[MEDIUM] Chainlink staleness checks missing across 15+ audit reports (Solodit oracle-0,1,2,5,8,9,10,11,12,13,14,15,16,17,18,19)** -- Consistently the most common oracle finding across all audited protocols; the specific miss is failing to check updatedAt return value from latestRoundData(). Multiple protocols also miss answeredInRound >= roundId check.

### Maps to oracle-002 (spot price flash loan manipulation)

- **[HIGH] Reallocation depends on slot0 price, manipulable via flash loan (Solodit oracle-32)** -- Vault reallocation between underlying pools uses Uniswap V3 slot0 (current tick) for pricing; attacker manipulates tick via flash swap, triggers reallocation at skewed price, reverses swap.
- **[HIGH] CoreSaltyFeed spot price leads to undesired liquidations (Solodit oracle-33)** -- Custom price feed reads spot price from Salty.io pool; attacker uses flash loan to crash spot price, triggering liquidations on healthy positions.
- **[HIGH] Domain pricing relies on manipulable pool price (Solodit oracle-42)** -- ENS-style domain pricing uses AMM spot price; attacker manipulates pool, buys domain at deflated price, restores pool. New context: spot price used for non-financial valuation (domain pricing).
- **[HIGH] LP token price manipulation through reserve (Solodit oracle-41)** -- LP token valuation uses reserve ratios directly; flash loan changes reserves, inflating LP token value used as collateral. Distinct from token-level manipulation because it targets the LP pricing formula itself.
- **[HIGH] Oracle updates sandwiched for atomic front-running (Solodit oracle-46)** -- Attacker detects pending oracle update in mempool, takes position before update, profits after; mitigated by only updating oracle once per block and using old value throughout.
- **[HIGH] Uniswap spot price (C-01 pattern) (Solodit oracle-47)** -- Direct use of Uniswap pool spot price for critical protocol operations; the most basic flash loan manipulation vector.
- **[HIGH] calc_withdraw_one_coin vulnerable to manipulation (Solodit oracle-53)** -- Curve pool's calc_withdraw_one_coin used for pricing; function depends on current pool balance which is manipulable via flash loan.
- **[MEDIUM] ERC4626Oracle vulnerable to price manipulation (Solodit oracle-24)** -- ERC4626 vault share price (convertToAssets) used as oracle; attacker donates to vault to inflate share price within a single transaction, manipulating the oracle output. Cross-reference: vault-002 donation attack used as oracle manipulation vector.

### Maps to oracle-003 (TWAP short window)

- **[HIGH] Oracle.sol manipulation via increasing Uniswap V3 observationCardinality (Solodit oracle-29)** -- Attacker increases observationCardinality on the target pool, then provides a malicious seed to Oracle.consult; the new observation slots contain attacker-controlled data that skews the TWAP. New insight: cardinality increase itself is an attack vector, not just defense.
- **[MEDIUM] TWAP reliance on arbitrarily short window for depeg prevention (Solodit oracle-38)** -- Stablecoin mint/redeem uses TWAP oracle with configurable window; admin can set dangerously short window, and even moderate windows are ineffective during rapid depeg events.
- **[MEDIUM] Providing large liquidity manipulates TWAP, DOSing uAD redeems (Solodit oracle-37)** -- Attacker adds massive liquidity to the TWAP pool, shifting the time-weighted average; not a flash loan but sustained capital deployment that distorts the TWAP for the observation window. New twist: liquidity addition (not swaps) as TWAP manipulation.

### Maps to oracle-004 (zero/negative price)

- **[MEDIUM] Chainlink aggregator minAnswer circuit breaker returns wrong price (Solodit oracle-3)** -- When asset price drops below aggregator's minAnswer (e.g., LUNA crash), oracle returns minAnswer instead of actual price; borrowers continue using asset at floor price far above real value. Key insight: price is nonzero and non-negative but still catastrophically wrong.
- **[HIGH] PriceOracle does not filter price feed outliers (Solodit oracle-34)** -- No bounds checking on returned price; malfunctioned oracle returns extreme values that pass > 0 check but are orders of magnitude wrong. Mitigation: compare against historical price with max deviation threshold.

### Maps to oracle-005 (L2 sequencer downtime)

- **[MEDIUM] L2 sequencer checks missing across 16+ audit reports (Solodit oracle-6,7,59,60,61,62,63,64,65,66,68,71,72,74,75,76)** -- Second most common oracle finding; protocols deployed on Arbitrum/Optimism/Base consistently miss the sequencer uptime feed check. Patterns include: missing check entirely, missing grace period, or checking sequencer but not enforcing grace period.
- **[MEDIUM] L2 sequencer down pushes auction price down, causing unfair liquidation (Solodit oracle-73)** -- During sequencer downtime, ongoing Dutch auction price decay continues; when sequencer resumes, collateral is liquidated at heavily decayed price. New insight: time-dependent mechanisms (auctions, TWAP) continue progressing during sequencer downtime.
- **[MEDIUM] User unfairly liquidated after L2 sequencer grace period (Solodit oracle-67)** -- During sequencer downtime, positions become unhealthy but liquidation is paused; immediately after grace period, accumulated price changes trigger liquidation before user can act. New pattern: no user-action grace period separate from oracle grace period.
- **[MEDIUM] UniswapV3 oracle vulnerability on L2 during sequencer downtime (Solodit oracle-70)** -- Uniswap V3 TWAP observations stop accumulating during sequencer downtime; when sequencer resumes, TWAP is stale and may not reflect price movement that occurred during downtime.

### Maps to oracle-006 (decimals mismatch)

- **[MEDIUM] Fee calculations break when token decimals differ from 18 (Solodit oracle-78)** -- calculateFee divides by 1e18 to cancel oracle scaling but ignores token decimals; for USDC (6 decimals), fee is 1e12 times too small. Key insight: the division cancels oracle decimals but creates a new error with token decimals.
- **[MEDIUM] Precision loss in tokenAmount to USD conversion leads to incorrect liquidation (Solodit oracle-79)** -- Fixed PRECISION_FACTOR + priceDecimal insufficient for high-decimal tokens; calculated loanValueUsd and collateralValueUsd truncate, causing wrong liquidation decisions.
- **[MEDIUM] Oracle pair price incorrect when Balancer oracle weight exceeds precision (Solodit oracle-80)** -- balancerOracleWeight set larger than BALANCER_ORACLE_WEIGHT_PRECISION causes weighted average price to overflow or invert, producing nonsensical combined price.

### Maps to oracle-008 (Uniswap V3 TWAP short window)

- **[HIGH] Maverick oracle can be manipulated (Solodit oracle-43)** -- Maverick AMM oracle has shorter default observation window than Uniswap V3; lower liquidity in Maverick pools makes even moderate TWAP windows insufficient. New context: non-Uniswap AMM oracles have different security assumptions.
- **[HIGH] Attacker manipulates low TVL UniV3 pool to borrow at inflated value (Solodit oracle-44)** -- UniV3 position used as collateral; oracle wrapper values position based on pool state that attacker manipulates. Combines TWAP manipulation with NFT position valuation.

### New patterns not in existing bugs

- **[HIGH] Read-only reentrancy on Balancer/Curve pools (Solodit oracle-55,56,57,58)** -- Balancer Vault getPoolTokens() and Curve pool virtual_price can be read during a callback (reentrancy) while reserves are in a manipulated mid-transaction state; oracle reads inflated values. Key insight: no state mutation needed -- just reading manipulated mid-tx state is sufficient. Mitigation: check Balancer's reentrancy guard via vault.manageUserBalance.
- **[HIGH] P2P rate manipulation via lazy-updated snapshot (Solodit oracle-28)** -- Morpho's P2P rate is a snapshot of Aave's mid-rate, updated lazily on interaction; attacker manipulates Aave supply/borrow rates via large deposit/borrow, triggers Morpho update to capture the manipulated mid-rate, then reverses the Aave manipulation. New pattern: lazy oracle update + upstream rate manipulation.
- **[HIGH] Flawed liquidation design: constructor-based contract detection bypass (Solodit oracle-54)** -- Liquidation restricted to EOAs via code.length check; attacker executes manipulation + liquidation from constructor where code.length = 0. New pattern: isContract check bypass via constructor execution.
- **[HIGH] Usage of manually updated prices risks insolvency (Solodit oracle-51)** -- Protocol uses admin-pushed prices instead of automated feeds; low update frequency during volatile periods creates exploitable windows. New pattern: manual oracle with insufficient update cadence.
- **[HIGH] Intra-transaction oracle tampering with LP pricing via flashloans (Solodit oracle-25)** -- LP token pricing reads pool reserves in same tx as manipulation; attacker flash-loans to skew reserves, LP price inflates, borrows against it, repays flash loan. Distinct from spot-price because it targets the LP valuation layer.
- **[MEDIUM] getOperatorPowerAt uses current prices for past stake calculations (Solodit oracle-82)** -- Historical stake power should use historical prices, but function uses current oracle price; operator ranking and reward distribution skew toward those whose assets appreciated. New pattern: temporal price mismatch (current price for historical calculation).
- **[MEDIUM] Consecutive symbol price updates exploited to drain funds (Solodit oracle-84)** -- During multi-step liquidation, price updates between steps maintain same UPnL but allow Party B to extract more profit per step; repeated updates compound the extraction. New pattern: mid-liquidation price update exploitation.
- **[MEDIUM] Corrupted oracle with WSTETH when >2 underlying tokens (Solodit oracle-85)** -- priceX96() forces cross-oracle validation even when direct feed exists; with WSTETH as one of 3+ underlyings, the cross-validation path produces incorrect results due to intermediate conversion errors. New pattern: multi-hop oracle validation failure.
- **[MEDIUM] Missing oracle updates in RewardsManager (Solodit oracle-86)** -- getAccruedYield() calculates rewards using oracle prices but doesn't call _tryUpdateOracle() first; stale oracle prices cause incorrect reward accrual. New pattern: oracle update missing in non-critical-path functions.
- **[MEDIUM] USD1 priced as $1 instead of pegged to USDT (Solodit oracle-87)** -- System assumes 1 USD1 = $1.00 exactly instead of 1 USD1 = 1 USDT at market rate; when USDT deviates from $1.00, arbitrage opportunities arise from the hardcoded assumption. New pattern: stablecoin peg assumption vs market reality.
