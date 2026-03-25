grep_targets:
  - "placeOrder"
  - "cancelOrder"
  - "matchOrders"
  - "fillOrder"
  - "limitOrder"
  - "marketOrder"
  - "orderBook"
  - "bestBid"
  - "bestAsk"
  - "tickSize"
  - "lotSize"
  - "makerFee"
  - "takerFee"
  - "partialFill"
  - "selfTrade"
  - "batchAuction"
  - "clearingPrice"
  - "settlement"
  - "marginAccount"
  - "isolatedMargin"
  - "crossMargin"

# Briefing: On-Chain Orderbook (CLOB) — Vulnerability Patterns

## Contexto del dominio
Los protocolos de orderbook on-chain (CLOB — Central Limit Order Book) implementan un motor de
matching directamente en la blockchain (o en una L1/L2 especializada). A diferencia de los AMM,
mantienen un libro de ordenes con bids y asks a precios discretos (ticks). Protocolos relevantes:

**EVM-based**: CLOBER, GTE, DittoETH, Secured Finance, Barter DAO, 0x Protocol, CoW Protocol (GPv2)
**Solana**: Serum v4, OpenBook, Phoenix
**Sui/Aptos**: DeepBook (Sui), Econia (Aptos)
**L1 propias**: Hyperliquid, dYdX v4 (Cosmos), Layer N
**Hybrid**: Vertex Protocol (AMM+orderbook), Deriverse DEX

Los bugs mas peligrosos involucran:
- Manipulacion del orden de matching (front-running, priority)
- Errores de accounting en partial fills y settlement
- Fee evasion mediante self-trading o structuring
- Ataques de griefing via dust fills y order cancellation
- Margin cross-contamination en perp orderbooks
- Rounding en tick/price conversions favoreciendo un lado

---

patterns:

### 1.1 Self-Trading / Wash Trading for Reward Theft

```yaml
- id: ob-001
  titulo: Self-Trading Wash Trading for Volume/Reward Manipulation
  causa_raiz: |
    El protocolo no impide que un usuario place ordenes matching en ambos lados del
    libro (buy y sell) para ejecutarlas contra si mismo. Si el protocolo distribuye
    rewards basados en volumen de trading (fee rebates, token mining, keeper rewards),
    el atacante infla el volumen sin riesgo real para capturar una porcion desproporcionada
    de los incentivos. El costo neto es solo el gas + spread entre sus propias ordenes.
  como_funciona: |
    1. Atacante crea cuenta A (maker) y cuenta B (taker), o usa la misma cuenta si no hay check
    2. Cuenta A coloca limit buy a precio P; cuenta B coloca limit sell a precio P
    3. Las ordenes se matchean: volumen inflado pero ninguna parte pierde fondos reales (spread = 0)
    4. El protocolo registra el volumen como trading legitimo
    5. Si hay fee rebates o volume-based rewards, atacante los reclama
    6. Repite miles de veces en un loop atomico (o con bot off-chain)
    7. Beneficio neto = rewards - (gas + maker/taker fees netos)
  invariante: |
    // No single address should be both maker and taker in the same fill
    function check_no_self_trade(address maker, address taker) internal {
        t(maker != taker, "OB-001: self-trade detected");
    }
    // Volume-weighted reward must correlate with unique counterparty volume
    function check_wash_trade_ratio(address trader) internal view {
        uint256 selfVolume = selfTradeVolume[trader];
        uint256 totalVolume = traderVolume[trader];
        // Self-trade volume should be 0 if protocol enforces self-trade prevention
        t(selfVolume == 0, "OB-001: wash trade volume detected");
    }
  que_mirar:
    - "Does the matching engine check if maker == taker (or same owner)?"
    - "Are rewards computed from raw volume or only from verified counterparty trades?"
    - "Can a user create multiple sub-accounts to bypass self-trade checks?"
    - "Is there a minimum time-in-book requirement before a maker order earns rebates?"
    - "In Solana programs: are maker and taker open_orders accounts checked for same owner?"
  como_se_arregla: |
    - Enforce SelfTradePreventionMode: CANCEL_PROVIDE, CANCEL_TAKE, or ABORT_TRANSACTION
    - Track volume per unique counterparty for reward computation
    - Add minimum time-in-book (e.g., 2 blocks) before maker fee rebate applies
    - Rate-limit order placement per account per epoch
  trampas:
    - "Some protocols intentionally allow self-trading for market-making flexibility (Serum v4 had explicit self-trade logic)"
    - "Sub-account systems (dYdX v4, Hyperliquid) make owner checks harder — need to check at wallet level, not sub-account"
    - "Zero-fee whitelisted pools (DeepBook) make wash trading literally free"
  solodit_ids:
    - "wash-trades-to-steal-keeper-and-spot-trading-rewards-quantstamp-primex-finance-markdown"
    - "self-trading-is-broken-ottersec-none-serum-v4-pdf"
    - "volume-overflow-risk-ottersec-none-mysten-deepbook-pdf"
    - "trading-improvements-and-features-ottersec-none-econia-pdf"
    - "m-01-flawed-zero-cost-trade-prevention-code4rena-gte-gte-git"
  incidentes:
    - "Primex Finance -- Wash trades to steal keeper and spot trading rewards via zero-cost self-matching (MEDIUM)"
    - "Serum v4 -- Self-trading logic broken in consume_events; special-case self-trade accounting fails silently (MEDIUM)"
    - "DeepBook (Sui) -- Whitelisted pools with zero fees enable unlimited wash trading to inflate volume metrics (MEDIUM)"
    - "Econia (Aptos) -- Self-trading causes abort in market::match; no graceful prevention mode (LOW)"
    - "Mango Markets (2022) -- Avraham Eisenberg manipulated MNGO perps via self-trading to inflate mark price, extracted $114M"
  severidad: high
  confianza: alta
  verificado: true
  tags: [wash-trading, self-trade, volume-mining, rewards, fee-rebate]
  relacionado_con: [ob-006]
```

### 1.2 Order Matching Priority Manipulation

```yaml
- id: ob-002
  titulo: Order Matching Priority Manipulation / Front-Running the Book
  causa_raiz: |
    En orderbooks on-chain, el orden de ejecucion de transacciones determina quien se
    matchea primero. Un atacante que ve una order grande pendiente en el mempool puede
    insertar su propia orden ANTES (front-run) para capturar el fill a un precio mas
    favorable. En sistemas off-chain matching (dYdX v4, Hyperliquid), el sequencer/validator
    controla el orden y puede extraer MEV.
  como_funciona: |
    1. Atacante monitorea el mempool (o el sequencer queue en L2/L1 propias)
    2. Detecta una market order grande que va a barrer varios niveles de precio
    3. Front-runs: inserta limit orders en los niveles que la market order va a consumir
    4. La market order del victim llena las ordenes del atacante a precios favorables
    5. Atacante cierra posicion en el otro lado del book, capturando el spread
    6. En sistemas con gas-priority ordering: higher gas = priority, cost = gas delta
    7. En sistemas con sequencer: el operador puede reordenar para beneficio propio
  invariante: |
    // Price-time priority must be strictly enforced
    function check_price_time_priority(
        uint256 existingOrderId, uint256 newOrderId,
        uint256 existingPrice, uint256 newPrice,
        uint256 existingTimestamp, uint256 newTimestamp
    ) internal {
        if (existingPrice == newPrice) {
            // At same price, earlier order must fill first
            t(existingTimestamp <= newTimestamp, "OB-002: time priority violated");
        }
    }
  que_mirar:
    - "Is the matching engine FIFO within each price level?"
    - "Can orders be inserted at the front of a price level queue?"
    - "Does the protocol use commit-reveal or batch auction to prevent front-running?"
    - "On L2/appchain: who controls transaction ordering? Is there a fair sequencing rule?"
    - "Are there gas-price based priority tiers that allow MEV extraction?"
  como_se_arregla: |
    - Implement batch auctions (CoW Protocol model) — all orders in a batch clear at uniform price
    - Use commit-reveal scheme for order placement (commit hash, reveal order after N blocks)
    - On appchains: enforce fair ordering (first-come-first-served at consensus layer)
    - Add minimum resting time before an order is eligible for matching
  trampas:
    - "Front-running prevention is fundamentally limited on transparent blockchains — mitigation, not elimination"
    - "Batch auctions shift the MEV to the solver/auctioneer selection process"
    - "Commit-reveal adds latency and complexity, often impractical for HFT-style books"
  solodit_ids:
    - "order-creation-can-run-out-of-gas-since-relying-on-previous-order-matchtype-codehawks-dittoeth-git"
    - "anyone-can-front-run-mixinexchangecorecancelorder-wont-fix-consensys-0x-v3-exchange-markdown"
    - "h-02-backstop-bid-side-frozen-by-tick-size-constraint-code4rena-gte-gte-git"
  incidentes:
    - "DittoETH -- Order creation runs out of gas because matching relies on previous order's matchtype, allowing griefing (MEDIUM)"
    - "0x v3 -- Anyone can front-run cancelOrder() because cancellation is not permissioned to maker only (MEDIUM, Won't Fix)"
    - "GTE -- Backstop bid-side frozen by tick-size constraint; orders cannot be placed at valid prices (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [front-running, MEV, priority, sequencer, matching-engine]
  relacionado_con: [ob-005, ob-008]
```

### 1.3 Partial Fill Dust Attack / Griefing

```yaml
- id: ob-003
  titulo: Partial Fill Dust Attack — Griefing Order Owners
  causa_raiz: |
    Un atacante llena una order con una cantidad minuscula (dust), dejando el resto de la
    order en el libro. Si el protocolo tiene un minimo de fill o un mecanismo de cancelacion
    automatica cuando el remaining cae por debajo de un umbral, el atacante puede forzar
    la cancelacion de la order completa llenando solo un dust amount. Tambien puede forzar
    al maker a gastar gas cancelando ordenes parcialmente llenas que ya no son economicamente
    viables.
  como_funciona: |
    1. Victim coloca limit order por 1000 USDC a precio P
    2. Atacante envia market order por 1 wei de USDC contra la limit order
    3. La order se llena parcialmente: 1 wei filled, 999.999999 USDC remaining
    4. Escenario A: si remaining < min_qty, protocolo cancela la order automaticamente
       → victim pierde su posicion en el book sin querer
    5. Escenario B: si no hay auto-cancel, victim tiene una order de dust que no vale
       la pena mantener — gasta gas para cancelarla
    6. Atacante repite contra multiples ordenes en el book, limpiando liquidez de un lado
    7. Con el lado limpio, puede mover el precio significativamente con una order real
  invariante: |
    // Partial fill must respect minimum fill quantity
    function check_min_fill(uint256 fillAmount, uint256 minFillAmount) internal {
        t(fillAmount >= minFillAmount, "OB-003: fill below minimum quantity");
    }
    // Order remaining after partial fill must be viable
    function check_remaining_viable(
        uint256 remainingAmount, uint256 minOrderSize
    ) internal {
        // Either completely filled or remaining is above minimum
        t(
            remainingAmount == 0 || remainingAmount >= minOrderSize,
            "OB-003: partial fill leaves non-viable dust"
        );
    }
  que_mirar:
    - "Is there a minimum fill amount enforced per trade?"
    - "What happens when remaining order amount < minOrderSize after partial fill?"
    - "Can the taker choose an arbitrarily small fill amount?"
    - "Does auto-cancellation of dust orders emit events that the maker can track?"
    - "Is there a minimum order size enforced at placement AND after each fill?"
  como_se_arregla: |
    - Enforce minimum fill amount per trade (e.g., 0.1% of original order size)
    - If partial fill would leave remaining < minOrderSize, fill the entire remainder
    - Charge a flat gas-compensation fee on each fill to make dust fills uneconomical
    - Allow makers to set their own minimum fill quantity per order
  trampas:
    - "Too high a minimum fill prevents legitimate small trades on illiquid markets"
    - "The economic viability depends on gas costs — on L2s with cheap gas, dust fills are cheaper to grief with"
    - "Some protocols handle this by rounding remaining to zero if < dust threshold"
  solodit_ids:
    - "griefing-attack-malicious-takers-can-force-order-cancellation-by-partial-filling-below-minimum-quantity-cyfrin-none-deriverse-dex-markdown"
    - "order-fill-griefing-via-small-partial-fills-cantina-none-royco-pdf"
    - "dos-attack-via-dust-executions-mixbytes-none-barter-dao-markdown"
    - "h-03-malicious-borrower-can-repeatedly-fill-then-kill-orders-to-permanently-lock-funds-of-lenders-and-other-borrowers-0x52-none-stusdcxbloom-markdown"
    - "forced-oldest-order-eviction-enables-griefing-cyfrin-none-deriverse-dex-markdown"
  incidentes:
    - "Deriverse DEX -- Malicious takers force order cancellation by partial filling below min_qty threshold (LOW)"
    - "Royco -- Order fill griefing via small partial fills bypassing remaining quantity check (LOW)"
    - "Barter DAO -- DoS attack via dust executions; frontrunner fills 1 wei, nonce check blocks legitimate fill (MEDIUM)"
    - "stUSDCxBloom -- Fill-then-kill attack: malicious borrower repeatedly fills and kills orders, permanently locking funds (HIGH)"
    - "Deriverse DEX -- Forced oldest-order eviction when book exceeds MAX_ORDERS; attacker spams to evict legitimate orders (LOW)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [dust, griefing, partial-fill, min-order-size, DoS]
  relacionado_con: [ob-012]
```

### 1.4 Price Tick Rounding Exploitation

```yaml
- id: ob-004
  titulo: Price Tick Rounding Exploitation — Rounding Direction Favors One Side
  causa_raiz: |
    Orderbooks discretizan precios en ticks (precio minimo = tickSize). Cuando un usuario
    coloca una order a un precio que no es multiplo exacto del tick, el protocolo redondea.
    Si redondea en la direccion incorrecta (e.g., buy order redondeada hacia arriba),
    el usuario obtiene un precio peor del esperado. Si redondea a favor del usuario
    (sell order redondeada hacia arriba), permite extraer valor del protocolo o contraparte.
    En sistemas con precios muy bajos (sub-penny), el rounding puede hacer que el
    fill amount sea 0 — tokens no retirables.
  como_funciona: |
    1. Tick size = 0.01 USDC. Usuario coloca sell order a 1.005 USDC
    2. Protocolo redondea a 1.01 (arriba) — seller obtiene mejor precio que el justo
    3. O: protocolo redondea a 1.00 (abajo) — buyer obtiene mejor precio
    4. Atacante identifica la direccion de rounding y coloca ordenes al limite del tick
    5. En cada fill, captura la diferencia de rounding
    6. Con precios muy bajos: limit order a precio 0.000001, fill amount redondea a 0
    7. Tokens quedan locked en el contrato, no retirables
  invariante: |
    // Rounding must always favor the protocol/maker, never the taker
    function check_tick_rounding(
        uint256 rawPrice, uint256 tickSize, uint256 roundedPrice
    ) internal {
        uint256 remainder = rawPrice % tickSize;
        if (remainder > 0) {
            // For buy orders: round DOWN (buyer pays less or equal)
            // For sell orders: round UP (seller receives more or equal)
            // But ALWAYS: protocol should not lose from rounding
            t(roundedPrice % tickSize == 0, "OB-004: price not aligned to tick");
        }
    }
    // Fill amount must be non-zero after rounding
    function check_nonzero_fill(uint256 fillAmount) internal {
        t(fillAmount > 0, "OB-004: fill amount rounded to zero");
    }
  que_mirar:
    - "Which direction does price rounding go for buys vs sells?"
    - "Is tickSize enforced at order creation or only at matching?"
    - "Can extremely low prices produce zero fill amounts due to rounding?"
    - "Does the protocol use mulDiv with rounding direction specified?"
    - "Are accumulated rounding errors tracked as protocol revenue or lost?"
  como_se_arregla: |
    - Enforce prices must be exact multiples of tickSize at order creation (reject non-aligned)
    - Always round against the taker: buy rounds down, sell rounds up
    - Reject fills where the computed token amount rounds to zero
    - Use FullMath.mulDivRoundingUp for sell-side calculations
  trampas:
    - "Tick-aligned enforcement at creation prevents rounding entirely — but limits price granularity"
    - "Some protocols use variable tick sizes by price range (like GTE) — verify consistency at boundaries"
    - "Overflow from very high prices interacting with tick math is a separate bug (see Aftermath)"
  solodit_ids:
    - "limit-order-rounding-ottersec-none-neutron-pdf"
    - "rounding-up-of-taker-fees-of-constituent-orders-may-exceed-collected-fee-spearbit-clober-pdf"
    - "h-02-backstop-bid-side-frozen-by-tick-size-constraint-code4rena-gte-gte-git"
    - "risk-of-arithmetic-overflow-ottersec-none-aftermath-orderbook-pdf"
    - "m-03-incorrect-price-for-negative-ticks-due-to-lack-of-rounding-down-code4rena-predy-predy-git"
  incidentes:
    - "Neutron -- Limit orders at extremely low prices produce zero withdrawable amounts due to rounding, tokens locked permanently (MEDIUM)"
    - "CLOBER -- Rounding up taker fees per constituent order exceeds total collected fee; protocol loses the difference (HIGH)"
    - "GTE -- Backstop bid-side frozen by tick-size constraint; valid prices cannot be expressed (HIGH)"
    - "Aftermath Orderbook -- Arithmetic overflow when bid price near u64 max interacts with TICK_SIZE math (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [rounding, tick-size, price-discretization, dust, overflow]
  relacionado_con: [ob-003, ob-012]
```

### 1.5 Order Cancellation Front-Running

```yaml
- id: ob-005
  titulo: Order Cancellation Front-Running — Filling Before Cancel Lands
  causa_raiz: |
    Un usuario intenta cancelar su limit order al ver el mercado moverse en su contra.
    Un atacante (o MEV bot) ve la cancelacion en el mempool y front-runs it con un
    market order que llena la limit order ANTES de que la cancelacion se ejecute.
    El victim queda filled a un precio desfavorable que ya no queria.
    Variante: el atacante cancela la order de OTRO usuario si cancelOrder() no verifica
    que msg.sender == order.maker.
  como_funciona: |
    1. User tiene limit buy order a 100 USDC por ETH (market ahora en 102)
    2. ETH cae a 95. User envia cancelOrder(orderId) — no quiere comprar a 100 cuando spot es 95
    3. MEV bot ve cancelOrder en mempool
    4. Bot front-runs: envia fillOrder(orderId) con higher gas
    5. Bot's fillOrder ejecuta primero — user compra ETH a 100 (5% peor que spot)
    6. User's cancelOrder falla porque order ya esta filled
    7. Bot vende ETH obtenido a 100 en el mercado a 95 — wait, bot VENDIO a 100 al user
    8. Resultado: user pagó 100 por algo que vale 95 = 5% loss
  invariante: |
    // cancelOrder must only be callable by the order maker
    function check_cancel_auth(address caller, address maker) internal {
        t(caller == maker, "OB-005: unauthorized cancel attempt");
    }
    // After a cancel tx is submitted, the order should not be fillable
    // (this requires architectural solution, not just a check)
  que_mirar:
    - "Does cancelOrder require msg.sender == order.maker?"
    - "Is there any commit-reveal or time-lock on order cancellation?"
    - "Can orders be cancelled via off-chain signature (gasless cancel)?"
    - "Does the protocol support Good-Till-Cancel with automatic expiry?"
    - "On L2/appchain: can the sequencer delay cancel transactions?"
  como_se_arregla: |
    - Strict auth: only order.maker (or authorized delegate) can cancel
    - Implement gasless cancel via signed message (EIP-712) — no mempool exposure
    - Use batch/frequent batch auctions where cancel/fill happen in same batch
    - Add cancel-by-epoch: orders automatically expire if not refreshed each epoch
    - On appchains: fair ordering guarantees at consensus layer
  trampas:
    - "Gasless cancel via signatures has its own replay risks (ob-014)"
    - "On L2s with private mempools, cancel front-running is less of an issue"
    - "Some protocols mark this as 'Won't Fix' because prevention requires fundamental architecture changes"
  solodit_ids:
    - "anyone-can-front-run-mixinexchangecorecancelorder-wont-fix-consensys-0x-v3-exchange-markdown"
    - "l-02-cancellation-can-be-front-run-cantina-none-pump-markdown"
    - "malicious-validators-can-prevent-orders-from-being-created-or-cancelled-sherlock-uniswap-v3-limit-orders-git"
  incidentes:
    - "0x v3 Exchange -- Anyone can front-run cancelOrder(); cancellation not restricted to maker (MEDIUM, Won't Fix)"
    - "Pump -- Cancellation can be front-run by MEV bots filling before cancel lands (LOW)"
    - "Uniswap V3 Limit Orders -- Malicious validators can prevent order cancellation by censoring cancel txs (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [front-running, cancel, MEV, mempool, authorization]
  relacionado_con: [ob-002, ob-010]
```

### 1.6 Maker/Taker Fee Bypass

```yaml
- id: ob-006
  titulo: Maker/Taker Fee Bypass — Structuring Orders to Pay Lower Fees
  causa_raiz: |
    Orderbooks tipicamente cobran fees diferentes a makers (liquidity providers) y takers
    (liquidity consumers). Makers pagan menos (o reciben rebates) porque proporcionan liquidez.
    Un atacante puede estructurar sus ordenes para siempre ser clasificado como maker
    (colocando limit orders que se llenan inmediatamente) o puede bypassear el calculo de fees
    completamente via errores en la logica de fee computation.
  como_funciona: |
    1. Taker fee = 0.1%, maker fee = -0.02% (rebate)
    2. Atacante quiere comprar 100 ETH al market
    3. En vez de market order (0.1% fee), coloca limit buy EXACTAMENTE al best ask price
    4. Si el matching engine lo clasifica como maker (porque es limit order), paga -0.02% rebate
    5. Resultado: atacante evita 0.1% fee y gana 0.02% rebate
    6. Variante: fee calculation has bug where fee = 0 for certain order sizes or price levels
    7. Variante: fee prepayment logic can be bypassed when fees_prepayment == 0
  invariante: |
    // Orders that cross the spread should ALWAYS pay taker fee
    function check_crossing_order_pays_taker_fee(
        uint256 buyPrice, uint256 bestAsk, uint256 feeCharged, uint256 takerFee
    ) internal {
        if (buyPrice >= bestAsk) {
            // This is a crossing order — it takes liquidity
            t(feeCharged >= takerFee, "OB-006: crossing order not paying taker fee");
        }
    }
    // Total fees collected >= sum of individual order fees
    function check_fee_conservation(
        uint256 totalCollected, uint256 sumIndividualFees
    ) internal {
        t(totalCollected >= sumIndividualFees, "OB-006: fee leakage");
    }
  que_mirar:
    - "How does the matching engine classify maker vs taker? Is it by order type or by crossing?"
    - "Can a limit order that immediately crosses the spread be classified as maker?"
    - "Are post-only orders enforced correctly (reject if would immediately fill)?"
    - "Is fee calculation vulnerable to rounding that makes fee = 0 for small amounts?"
    - "Can fee prepayment be set to 0 to skip fee logic entirely?"
  como_se_arregla: |
    - Classify maker/taker by whether the order CROSSES the spread, not by order type
    - Post-only orders: reject (don't match) if they would cross — never silently match at maker fee
    - Minimum fee per trade (at least 1 wei of fee token) to prevent rounding to zero
    - Audit fee prepayment path: ensure fees are still charged even when prepayment is zero
  trampas:
    - "Post-only orders that cross should be REJECTED, not converted to taker orders"
    - "Fee rounding per constituent order can accumulate to exceed total collected (CLOBER bug)"
    - "Referral discounts applied on top of fee calculation can make net fee negative"
  solodit_ids:
    - "rounding-up-of-taker-fees-of-constituent-orders-may-exceed-collected-fee-spearbit-clober-pdf"
    - "potential-bypass-of-fees-parameters-in-order-creation-quantstamp-1inch-fusion-markdown"
    - "improper-fee-configuration-ottersec-none-aftermath-orderbook-pdf"
    - "referral-discount-is-not-applied-when-fees_prepayment-is-zero-in-perpenginefill-cyfrin-none-deriverse-dex-markdown"
    - "m-12-perps-gtl-post-only-orders-skew-totalassets-accounting-minting-excessive-shares-and-rendering-the-gtl-vault-insolvent-code4rena-gte-gte-git"
  incidentes:
    - "CLOBER -- Rounding up taker fees per constituent order exceeds total collected fee; protocol insolvent on fee account (HIGH)"
    - "1inch Fusion -- Makers can bypass protocol fee and integrator fee parameters during order creation on Solana (MEDIUM)"
    - "Aftermath Orderbook -- Improper fee configuration allows miscalculated fees (LOW)"
    - "Deriverse DEX -- Referral discount not applied when fees_prepayment is zero; fee accounting incorrect (MEDIUM)"
    - "GTE -- Post-only GTL orders skew totalAssets accounting, minting excessive vault shares → vault insolvency (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [fees, maker-taker, rebate, post-only, fee-bypass]
  relacionado_con: [ob-001, ob-004]
```

### 1.7 Limit Order Stale Price Execution

```yaml
- id: ob-007
  titulo: Limit Order Stale Price Execution — Order Filled at Outdated Price
  causa_raiz: |
    Una limit order colocada cuando el mercado estaba en un nivel X se ejecuta mucho
    despues cuando el mercado se ha movido significativamente. Si el usuario no tiene
    mecanismo para actualizar o cancelar automaticamente la order, puede ser filled
    a un precio que ya no refleja su intencion. Esto es particularmente peligroso
    en orderbooks on-chain donde cancelar tiene costo de gas, y en mercados volatiles
    donde el precio puede moverse 10-50% en minutos.
  como_funciona: |
    1. Trader coloca limit buy para ETH a 2000 USDC cuando ETH spot = 2100
    2. Meses despues, ETH cae a 1500. La limit order sigue activa
    3. Alguien llena la order: trader compra ETH a 2000 cuando spot es 1500
    4. Perdida inmediata: 2000 - 1500 = 500 USDC por ETH
    5. Agravado cuando: el order no tiene expiry, el protocolo no notifica,
       o la order esta en una chain donde gas es caro para cancelar
    6. Variante MEV: bot detecta que spot ha cruzado un limit price,
       front-runs para fill la order exactamente cuando es mas desfavorable
  invariante: |
    // Orders should have a maximum lifetime
    function check_order_not_expired(
        uint256 orderTimestamp, uint256 orderExpiry
    ) internal view {
        if (orderExpiry > 0) {
            t(block.timestamp <= orderTimestamp + orderExpiry, "OB-007: order expired");
        }
    }
    // Fill price should not deviate too far from oracle price
    function check_fill_price_sanity(
        uint256 fillPrice, uint256 oraclePrice, uint256 maxDeviationBps
    ) internal {
        uint256 deviation = fillPrice > oraclePrice
            ? ((fillPrice - oraclePrice) * 10000) / oraclePrice
            : ((oraclePrice - fillPrice) * 10000) / oraclePrice;
        t(deviation <= maxDeviationBps, "OB-007: fill price deviates too much from oracle");
    }
  que_mirar:
    - "Do orders have a mandatory expiry/deadline?"
    - "Can block.timestamp be used as deadline (always passes, see Dopex finding)?"
    - "Is there an oracle sanity check on fill prices?"
    - "Does the protocol emit events when orders become 'stale' (far from market)?"
    - "Can orders be auto-cancelled when they become N% away from mid-market?"
  como_se_arregla: |
    - Mandatory order expiry (e.g., max 30 days for Good-Till-Cancel)
    - Oracle-based circuit breaker: reject fills where price deviates > X% from feed
    - Keeper that auto-cancels orders far from market (incentivized by gas refund)
    - Allow users to set sliding expiry (auto-cancel if not refreshed every N blocks)
  trampas:
    - "Using block.timestamp as deadline is equivalent to no deadline — it always passes"
    - "Oracle-based checks add oracle dependency risk to the orderbook"
    - "Some protocols intentionally allow GTC (Good-Till-Cancel) as a feature — user's responsibility"
  solodit_ids:
    - "m-19-using-blocktimestamp-as-the-deadlineexpiry-invites-mev-code4rena-dopex-dopex-git"
    - "expiry-buffer-extends-orders-beyond-user-intended-lifetime-quantstamp-dipcoin-perpetual-markdown"
    - "fill-or-kill-order-crashes-the-nord-server-cantina-none-layer-n-pdf"
  incidentes:
    - "Dopex -- Using block.timestamp as deadline/expiry provides no protection against MEV (MEDIUM)"
    - "Dipcoin Perpetual -- Internal expiry buffer extends order lifetime beyond what user specified (MEDIUM)"
    - "Layer N -- Fill-or-Kill order type not handled correctly; can add orders to book instead of only matching (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [stale-order, expiry, deadline, timestamp, GTC]
  relacionado_con: [ob-005, ob-010]
```

### 1.8 Batch Auction MEV — Solver/Auctioneer Extraction

```yaml
- id: ob-008
  titulo: Batch Auction MEV — Value Extraction by Solvers
  causa_raiz: |
    En batch auctions (CoW Protocol/GPv2, Axis Finance, 1inch Fusion), multiples ordenes
    se agrupan y ejecutan al mismo clearing price. El solver (quien encuentra la solucion
    optima) puede extraer valor eligiendo un clearing price que le beneficie, incluyendo
    ordenes propias en el batch, o excluyendo ordenes que competirian con las suyas.
    El mecanismo de seleccion de solver y la transparencia del batch crean superficies
    de MEV diferentes a las de un CLOB continuo.
  como_funciona: |
    1. Batch contiene ordenes: Alice buy 100 ETH @ up to 2050, Bob sell 100 ETH @ min 2000
    2. Fair clearing price = 2025 (midpoint). Surplus = 25 * 100 = 2500 USDC
    3. Solver malicioso: inserta su propia sell order a 2049, clearing price = 2049
    4. Alice recibe almost nothing of surplus; solver captures 2049 - 2000 = 4900 from Bob's perspective
    5. O: solver submits solution that excludes competidores and includes only self-matched trades
    6. O: solver sees encrypted bids before reveal (e.g., sealed-bid auction flaw)
    7. Surplus distribution: solver keeps disproportionate surplus vs protocol/users
  invariante: |
    // Clearing price must be within the range of all matched orders
    function check_clearing_price_bounds(
        uint256 clearingPrice,
        uint256 maxBuyPrice,
        uint256 minSellPrice
    ) internal {
        t(clearingPrice >= minSellPrice, "OB-008: clearing below min sell");
        t(clearingPrice <= maxBuyPrice, "OB-008: clearing above max buy");
    }
    // Surplus distribution must be fair (user gets >= X% of their surplus)
    function check_surplus_share(
        uint256 userSurplus, uint256 totalSurplus, uint256 minShareBps
    ) internal {
        uint256 shareBps = (userSurplus * 10000) / totalSurplus;
        t(shareBps >= minShareBps, "OB-008: user surplus share too low");
    }
  que_mirar:
    - "Who selects the solver? Is there a competitive auction for solver selection?"
    - "Can solvers include their own orders in the batch?"
    - "How is surplus distributed between users, solver, and protocol?"
    - "Is the batch execution atomic? Can solver revert and retry with different solution?"
    - "Are sealed bids actually sealed? Can solver/auctioneer decrypt before reveal?"
  como_se_arregla: |
    - Competitive solver auction with bonding (solver stakes collateral, slashed for bad solutions)
    - Enforce minimum surplus share for users (e.g., user gets >= 50% of their price improvement)
    - Solver cannot include own orders in batches they solve
    - Use verifiable encryption for sealed-bid auctions
    - Cap solver reward as fixed % of surplus, not whatever remains
  trampas:
    - "Solver MEV is an inherent trade-off in batch auction design — some extraction is expected"
    - "Off-chain solver competition (CoW Protocol model) shifts trust to the solver ranking mechanism"
    - "Settlement gas limits can make complex batches infeasible — solver simplifies, losing optimality"
  solodit_ids:
    - "m-8-settlement-of-batch-auction-can-exceed-the-gas-limit-sherlock-axis-finance-git"
    - "m-05-sellers-ability-to-decrypt-bids-before-reveal-could-result-in-a-much-hig-code4rena-size-size-git"
    - "m-07-mev-bots-can-win-all-the-auctions-when-auction-is-paused-code4rena-stader-labs-stader-labs-git"
  incidentes:
    - "Axis Finance -- Batch auction settlement can exceed gas limit; large batches fail to settle (MEDIUM)"
    - "SIZE -- Seller can decrypt bids before reveal period, defeating sealed-bid security (MEDIUM)"
    - "CoW Protocol (2023) -- Solver bonding pool debate: malicious solvers extracted surplus by including self-matched trades in solutions"
  severidad: high
  confianza: media
  verificado: true
  tags: [batch-auction, solver, MEV, clearing-price, surplus, CoW]
  relacionado_con: [ob-002, ob-009]
```

### 1.9 Cross-Market Atomic Arbitrage

```yaml
- id: ob-009
  titulo: Cross-Market Atomic Arbitrage via Same-TX Execution
  causa_raiz: |
    En un entorno on-chain donde multiples orderbooks o AMM pools existen para el mismo
    par de tokens, un atacante puede explotar discrepancias de precio atomicamente
    comprando en un venue y vendiendo en otro dentro de la misma transaccion.
    Si el orderbook no cuenta con proteccion contra este tipo de arbitraje atomico
    (e.g., via flash loans o composabilidad de contratos), el P&L del arbitrajista
    sale directamente del otro lado del book (los makers).
  como_funciona: |
    1. Orderbook A: best ask ETH/USDC = 2000. AMM B: spot ETH/USDC = 2010
    2. Atacante flashloanea 200,000 USDC
    3. Compra 100 ETH en orderbook A a 2000 (takers order, fills multiple makers)
    4. Vende 100 ETH en AMM B a ~2010
    5. Profit: (2010 - 2000) * 100 = 1000 USDC, minus fees and gas
    6. Todo en una transaccion: sin riesgo de inventario
    7. Los makers en orderbook A vendieron a 2000 cuando el "fair price" era 2010
    8. En perp orderbooks: el P&L desbalance va contra el insurance fund
  invariante: |
    // Oracle price sanity on fills — detect atomic arb
    function check_no_atomic_arb(
        uint256 fillPrice, uint256 oraclePrice, uint256 maxDevBps
    ) internal {
        uint256 deviation = fillPrice > oraclePrice
            ? ((fillPrice - oraclePrice) * 10000) / oraclePrice
            : ((oraclePrice - fillPrice) * 10000) / oraclePrice;
        t(deviation <= maxDevBps, "OB-009: fill price deviates from oracle, possible arb");
    }
  que_mirar:
    - "Can flash loans be used to fund orderbook fills?"
    - "Is there a cooldown between fill and withdrawal?"
    - "Does the protocol have anti-flash-loan guards (same-block checks)?"
    - "Are fills executable within a smart contract call (allows atomic arb)?"
    - "Does the protocol integrate with AMMs for routing? Shared liquidity = shared risk"
  como_se_arregla: |
    - Disallow flash-loaned funds for order margin/collateral (check balance at start of tx)
    - Add minimum settlement delay (fill in block N, withdraw in block N+1)
    - Rate-limit large fills per block per address
    - Cross-venue price check: reject fills that deviate > X% from oracle mid-price
  trampas:
    - "Arbitrage is generally considered healthy for price discovery — but atomic arb with zero risk is pure extraction"
    - "Hybrid AMM+orderbook protocols (Vertex) are especially vulnerable because both venues are in the same contract"
    - "Anti-flash-loan checks can be bypassed if attacker uses multi-block strategy instead"
  solodit_ids:
    - "global-4-arbitrage-attack-guardianaudits-gmx-markdown"
    - "m-7-attacker-can-exploit-thin-liquidity-in-xyk-pool-to-save-on-fees-code4rena-dango-dex-dango-dex-git"
  incidentes:
    - "GMX (2022) -- GLOBAL-4: Arbitrage attack via oracle delay, attacker buys before oracle update and sells after (HIGH)"
    - "Dango DEX -- Thin liquidity xyk pool exploited to save on fees via cross-venue routing (MEDIUM)"
    - "Mango Markets (2022) -- $114M extracted via self-trading on MNGO perps + cross-venue liquidation cascade"
  severidad: high
  confianza: media
  verificado: true
  tags: [atomic-arb, flash-loan, cross-venue, composability, hybrid]
  relacionado_con: [ob-001, ob-008]
```

### 1.10 Order Expiry Timestamp Manipulation

```yaml
- id: ob-010
  titulo: Order Expiry Timestamp Manipulation — block.timestamp Abuse
  causa_raiz: |
    Ordenes usan block.timestamp o block.number para determinar expiry. Miners/validators
    tienen cierta flexibilidad para manipular block.timestamp (dentro del margen aceptado
    por el consenso). Si una order usa block.timestamp como deadline (en vez de un valor
    futuro fijo), el deadline SIEMPRE pasa porque block.timestamp == "now" en el momento
    de ejecucion. Variante: el protocolo agrega un buffer interno al expiry del usuario,
    extendiendo la order mas alla de lo que el usuario queria.
  como_funciona: |
    1. Protocolo usa: require(block.timestamp <= order.deadline)
    2. Si order.deadline = block.timestamp (set at creation time), la condicion siempre es true
       en el bloque de creacion, pero puede fallar en el siguiente bloque
    3. Peor: si usan block.timestamp AS the deadline, la check es: block.timestamp <= block.timestamp → true always
    4. La order nunca expira — perpetual exposure al riesgo de fill a precio stale
    5. Variante: protocolo agrega expiryBuffer = 1 hora internamente
    6. User quiere order valida por 5 min, pero realmente es valida por 1h05min
    7. En ese tiempo extra, el mercado se mueve y la order se ejecuta a precio desfavorable
  invariante: |
    // Order deadline must be in the future (not block.timestamp)
    function check_deadline_in_future(uint256 deadline) internal view {
        t(deadline > block.timestamp, "OB-010: deadline is not in the future");
    }
    // No internal buffer should extend order beyond user's specified expiry
    function check_no_hidden_extension(
        uint256 userExpiry, uint256 effectiveExpiry
    ) internal {
        t(effectiveExpiry <= userExpiry, "OB-010: internal buffer extends order lifetime");
    }
  que_mirar:
    - "Is block.timestamp used as the deadline value (always passes)?"
    - "Does the protocol add an internal buffer/grace period to user-specified expiry?"
    - "On L2: who sets block.timestamp? Can the sequencer delay blocks to extend order lifetimes?"
    - "Are GTC (Good-Till-Cancel) orders capped at a maximum duration?"
    - "Is deadline = 0 treated as 'no expiry' or as 'already expired'?"
  como_se_arregla: |
    - Enforce deadline > block.timestamp + MIN_LIFETIME at order creation
    - Never add internal buffers that extend beyond user-specified expiry
    - GTC orders: cap at max duration (e.g., 90 days), require explicit renewal
    - Treat deadline = 0 as "no expiry" ONLY with explicit user opt-in
  trampas:
    - "On L2s with centralized sequencers, block.timestamp manipulation is different than L1"
    - "Requiring future deadlines blocks some legitimate use cases (immediate-or-cancel orders)"
    - "Some protocols accept block.timestamp as deadline for IOC orders — need to distinguish from limit orders"
  solodit_ids:
    - "m-19-using-blocktimestamp-as-the-deadlineexpiry-invites-mev-code4rena-dopex-dopex-git"
    - "expiry-buffer-extends-orders-beyond-user-intended-lifetime-quantstamp-dipcoin-perpetual-markdown"
  incidentes:
    - "Dopex -- block.timestamp used as deadline for swaps, providing zero MEV protection (MEDIUM)"
    - "Dipcoin Perpetual -- Expiry buffer extends orders beyond user-intended lifetime without user knowledge (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [timestamp, deadline, expiry, block-timestamp, MEV]
  relacionado_con: [ob-005, ob-007]
```

### 1.11 Margin Account Cross-Contamination

```yaml
- id: ob-011
  titulo: Margin Cross-Contamination — Isolated Position Affects Cross-Margin Balance
  causa_raiz: |
    Perp orderbooks con modos de margin (isolated y cross) mantienen cuentas de margin
    separadas. Si la logica de settlement, fee deduction, o PnL distribution no mantiene
    correctamente la separacion entre isolated y cross positions, las perdidas de una
    position isolated pueden contaminar el cross-margin balance, o viceversa.
    Esto rompe la garantia fundamental de isolated margin: "la perdida maxima esta limitada
    al margin depositado en esa posicion".
  como_funciona: |
    1. Trader tiene: cross-margin balance = 10,000 USDC, isolated position con 1,000 USDC margin
    2. La isolated position se liquida: perdida = 1,500 USDC (mas que el margin)
    3. Bug: los 500 USDC de deficit se cobran del cross-margin balance
    4. Cross-margin balance baja a 9,500 USDC — afecta health de TODAS las cross positions
    5. Variante: fee settlement en cross position debita incorrectamente de isolated margin
    6. Variante: cuando se cierra una cross position, el profit se acredita como
       isolated margin de otra posicion, quedando inaccesible
    7. En Elfi: positions sharing same margin token interact incorrectly during close
  invariante: |
    // Isolated margin balance must never affect cross-margin balance
    function check_margin_isolation(
        int256 crossMarginBefore, int256 crossMarginAfter,
        bool isIsolatedOperation
    ) internal {
        if (isIsolatedOperation) {
            t(crossMarginAfter == crossMarginBefore,
              "OB-011: isolated operation changed cross-margin balance");
        }
    }
    // Isolated loss cannot exceed isolated margin
    function check_isolated_max_loss(
        uint256 isolatedMargin, uint256 loss
    ) internal {
        t(loss <= isolatedMargin, "OB-011: isolated loss exceeds deposited margin");
    }
  que_mirar:
    - "Are isolated and cross margin balances stored in separate state variables?"
    - "When settling fees, does the code check which margin mode the position uses?"
    - "Can P&L from an isolated close flow into cross-margin accidentally?"
    - "When liquidating an isolated position, is the deficit socialized or capped?"
    - "Do multiple positions sharing the same margin token interfere with each other?"
  como_se_arregla: |
    - Strict separation: isolated and cross margins in completely separate structs
    - Deficit from isolated liquidation: cap at zero, send excess to insurance fund
    - Fee settlement: branch explicitly on margin mode with no shared code path
    - Test: close isolated position → cross-margin balance unchanged (and vice versa)
  trampas:
    - "Elfi had 7+ HIGH findings in cross-margin accounting — this is a systemic problem, not a single bug"
    - "Multi-collateral cross-margin is even harder: each collateral has its own P&L impact"
    - "Some protocols use a single 'available balance' concept that blurs the isolated/cross boundary"
  solodit_ids:
    - "h-32-in-cross-margin-mode-the-users-profit-calculation-is-incorrect-sherlock-elfi-git"
    - "m-3-incorrect-settlefee-process-for-cross-margin-account-sherlock-elfi-git"
    - "h-13-if-cross-positions-use-the-same-margin-token-as-collateral-and-close-witho-sherlock-elfi-git"
    - "h-8-cross-available-value-is-not-accounting-the-position-fees-sherlock-elfi-git"
    - "m-1-cross-positions-that-exceed-the-allowed-margin-can-be-opened-sherlock-elfi-git"
    - "h-24-excess-frombalance-removal-not-added-to-other-positions-frombalances-when-sherlock-elfi-git"
  incidentes:
    - "Elfi -- H-32: Cross margin profit calculation incorrect; user's P&L computed against wrong reference (HIGH)"
    - "Elfi -- H-13: Cross positions using same margin token as collateral; closing without specifying token causes accounting desync (HIGH)"
    - "Elfi -- H-8: Cross available value does not account for position fees; user can open more leverage than allowed (HIGH)"
    - "Elfi -- M-3: Settlement fee processed twice for cross-margin positions during close/decrease (MEDIUM)"
    - "Elfi -- H-24: Excess fromBalance removal not redistributed to other positions during close (HIGH)"
    - "Elfi -- M-1: Cross positions exceeding allowed margin can be opened due to missing check (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [margin, isolated, cross-margin, settlement, accounting, perps]
  relacionado_con: [ob-012, ob-013]
```

### 1.12 Settlement Netting Errors

```yaml
- id: ob-012
  titulo: Settlement Netting Errors — Multi-Order Settlement Miscalculation
  causa_raiz: |
    Cuando multiples ordenes se settlan en un solo batch o transaccion, el protocolo
    debe "netear" correctamente las obligaciones: si un usuario compro 100 ETH y vendio
    80 ETH en el mismo periodo, solo debe recibir 20 ETH neto. Errores en el netting
    causan doble-conteo, entregas insuficientes, o fondos que quedan stuck en el contrato.
    Agravado cuando ordenes parcialmente llenas se combinan con ordenes completas.
  como_funciona: |
    1. User tiene: Order A (buy 100 ETH filled), Order B (sell 50 ETH filled), Order C (buy 30 ETH, 50% filled = 15 ETH)
    2. Net obligation: user should receive 100 - 50 + 15 = 65 ETH
    3. Bug: settlement calcula 100 + 15 = 115 (ignora el sell)
    4. O: settlement calcula 100 - 50 + 30 = 80 (usa full order C amount instead of filled)
    5. O: rounding per-order acumula error en settlement netto → saldo no cuadra
    6. User puede explotar discrepancia para retirar mas de lo que le corresponde
    7. O: user recibe menos de lo esperado — fondos quedan en settlement contract
  invariante: |
    // Net settlement must equal sum of individual fills
    function check_settlement_netting(
        uint256 totalBuyFilled, uint256 totalSellFilled,
        int256 netSettlement
    ) internal {
        int256 expected = int256(totalBuyFilled) - int256(totalSellFilled);
        t(netSettlement == expected, "OB-012: settlement netting mismatch");
    }
    // Contract balance after settlement must not decrease more than net outflow
    function check_settlement_solvency(
        uint256 balanceBefore, uint256 balanceAfter, uint256 netOutflow
    ) internal {
        t(balanceBefore - balanceAfter <= netOutflow,
          "OB-012: settlement outflow exceeds expected");
    }
  que_mirar:
    - "Does settlement use filled amounts or original order amounts?"
    - "Are buys and sells netted correctly per user per token?"
    - "Is rounding per-order accumulated and reconciled at settlement?"
    - "Can a user have orders on both sides settled in the same batch?"
    - "Are partial fills tracked separately from full fills in settlement?"
  como_se_arregla: |
    - Track filled amounts (not order amounts) for settlement
    - Net buys and sells per user per token before executing transfers
    - Reconcile total transferred vs total expected after each settlement batch
    - Add invariant check: sum(settlements) == sum(fills) at end of each batch
  trampas:
    - "ERC20 tokens with transfer fees break netting assumptions — actual received != transferred"
    - "Multi-token settlement (e.g., ETH/USDC) requires netting per token, not per order"
    - "Cancelled orders during settlement batch: ensure cancelled amounts are excluded from netting"
  solodit_ids:
    - "redundant-state-updates-in-fill-function-cause-issues-cyfrin-none-deriverse-dex-markdown"
    - "makers-rebates-are-not-paid-in-case-of-swap-cyfrin-none-deriverse-dex-markdown"
    - "wrong-accounting-of-fee-in-perp-engine-cyfrin-none-deriverse-dex-markdown"
    - "decimal-mismatch-in-fee-prepayment-accounting-causes-incorrect-balance-tracking-cyfrin-none-deriverse-dex-markdown"
  incidentes:
    - "Deriverse DEX -- Redundant state updates in fill function cause data loss and incorrect accumulation across multiple order fills (MEDIUM)"
    - "Deriverse DEX -- Makers' rebates not paid during swap path; maker receives zero fee rebate when AMM route is taken (HIGH)"
    - "Deriverse DEX -- Wrong accounting of fee in perp engine; partial prepayment causes fee miscalculation (MEDIUM)"
    - "Deriverse DEX -- Decimal mismatch in fee prepayment accounting causes incorrect balance tracking (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [settlement, netting, accounting, partial-fill, batch]
  relacionado_con: [ob-003, ob-004]
```

### 1.13 Book Depth Manipulation for Liquidation Cascade

```yaml
- id: ob-013
  titulo: Book Depth Manipulation — Thinning Liquidity for Forced Liquidations
  causa_raiz: |
    En perp orderbooks, las liquidaciones se ejecutan contra el libro de ordenes.
    Si un atacante retira liquidez de un lado del book (cancelando sus propias ordenes
    o llenando ordenes existentes), el libro se queda thin. Cuando la siguiente liquidacion
    intenta ejecutarse, no hay suficiente liquidez para absorberla a un precio razonable.
    Resultado: la liquidacion se ejecuta a un precio mucho peor (slippage de liquidacion),
    o falla completamente si no hay ordenes para matchear.
  como_funciona: |
    1. Atacante identifica una posicion grande near-liquidation en el perp orderbook
    2. Paso 1: retira o llena TODAS las ordenes en el lado que la liquidacion necesita
       (e.g., para liquidar un long, necesita sells — atacante llena todos los sells)
    3. Book bid-side ahora vacio o muy thin
    4. Paso 2: empuja precio para triggear liquidacion (via oracle manipulation o direct sell)
    5. Liquidacion intenta ejecutarse pero no hay bids para absorberla
    6. Resultado A: liquidacion a precio de mercado terrible (massive slippage)
    7. Resultado B: liquidacion falla — posicion acumula bad debt, socializada a otros
    8. Resultado C: backstop liquidation activada, pero backstop tambien limitado por book depth
  invariante: |
    // Liquidation must execute within acceptable price range
    function check_liquidation_price_quality(
        uint256 liquidationPrice, uint256 oraclePrice, uint256 maxSlippageBps
    ) internal {
        uint256 slippageBps;
        if (liquidationPrice > oraclePrice) {
            slippageBps = ((liquidationPrice - oraclePrice) * 10000) / oraclePrice;
        } else {
            slippageBps = ((oraclePrice - liquidationPrice) * 10000) / oraclePrice;
        }
        t(slippageBps <= maxSlippageBps, "OB-013: liquidation slippage too high");
    }
    // Book depth must be sufficient for pending liquidations
    function check_min_book_depth(
        uint256 bookDepthUsd, uint256 totalLiquidatableUsd
    ) internal {
        t(bookDepthUsd >= totalLiquidatableUsd / 2,
          "OB-013: book depth insufficient for liquidations");
    }
  que_mirar:
    - "Does the protocol have a backstop liquidation mechanism when book is empty?"
    - "Can liquidations fall back to an AMM or insurance fund when book is thin?"
    - "Is there a maximum slippage on liquidation execution?"
    - "Can the same user cancel all their resting orders atomically to thin the book?"
    - "Does the protocol track book depth and pause liquidations when too thin?"
  como_se_arregla: |
    - Backstop liquidity provider: insurance fund acts as counterparty of last resort
    - Circuit breaker: if book depth < X% of open interest, pause new position openings
    - ADL (Auto-Deleverage): close profitable counter-positions instead of relying on book
    - Rate-limit order cancellations to prevent mass withdrawal of liquidity
    - Hybrid: fall back to AMM/oracle-priced liquidation when book is too thin
  trampas:
    - "Backstop liquidation itself can be blocked by tick-size constraints (GTE finding)"
    - "ADL is unpopular with traders but is the gold standard for preventing bad debt"
    - "Insurance fund depletion: if fund is small, attacker can drain it via repeated thin-book liquidations"
  solodit_ids:
    - "m-06-liquidation-stalls-when-top-of-book-is-outside-divergence-band-standard-backstop-allowing-under-margined-positions-to-persist-code4rena-gte-gte-git"
    - "h-02-backstop-bid-side-frozen-by-tick-size-constraint-code4rena-gte-gte-git"
    - "m-15-loss-for-protocol-by-incorrectly-assuming-the-position-has-been-fully-closed-code4rena-gte-gte-git"
    - "global-4-arbitrage-attack-guardianaudits-gmx-markdown"
  incidentes:
    - "GTE -- Liquidation stalls when top-of-book is outside divergence band; under-margined positions persist indefinitely (MEDIUM)"
    - "GTE -- Backstop bid-side frozen by tick-size constraint; backstop liquidations cannot execute (HIGH)"
    - "GTE -- Protocol incorrectly assumes position fully closed during backstop liquidation; loss for protocol (MEDIUM)"
    - "Hyperliquid (2025) -- Whale JELLY position with $200M notional caused liquidation cascade; HLP vault took $4M loss due to thin book"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [liquidation, book-depth, backstop, thin-liquidity, insurance-fund, ADL]
  relacionado_con: [ob-009, ob-011]
```

### 1.14 Permit-Based Order Creation — Signature Replay

```yaml
- id: ob-014
  titulo: Permit-Based Order Creation — Signature Replay for Unwanted Orders
  causa_raiz: |
    Protocolos que permiten crear ordenes via firma off-chain (EIP-712, permit) son
    vulnerables a replay si la firma no incluye un nonce unico por order, o si la
    firma puede ser reutilizada despues de una partial fill. Un atacante que obtiene
    una firma valida (de un partial fill, de un mempool, o de una chain diferente)
    puede replayarla para crear ordenes no deseadas a nombre del firmante.
  como_funciona: |
    1. Alice firma una limit order off-chain: "buy 100 ETH at 2000, valid until block N"
    2. La order se llena parcialmente (50 ETH) y se cancela por Alice
    3. Atacante tiene la firma original
    4. Si la firma no usa un nonce incrementado post-cancellation, atacante replays:
       crea nueva order "buy 100 ETH at 2000" a nombre de Alice
    5. Ahora Alice tiene exposure que no quiere
    6. Variante: firma de chain A replayada en chain B (missing chainId)
    7. Variante: private order parcialmente llenada pierde su private property —
       anyone can fill the remaining amount
  invariante: |
    // Each order signature must be single-use
    function check_signature_not_replayed(bytes32 orderHash) internal view {
        t(!usedSignatures[orderHash], "OB-014: signature already used");
    }
    // Signature must include chainId
    function check_chain_bound(uint256 signedChainId) internal view {
        t(signedChainId == block.chainid, "OB-014: wrong chain");
    }
    // Private order access control must persist through partial fills
    function check_private_order_fill_auth(
        address filler, address allowedSender, uint256 filledAmount
    ) internal {
        if (allowedSender != address(0)) {
            // Even after partial fill, only allowed sender can fill remainder
            t(filler == allowedSender, "OB-014: unauthorized fill of private order");
        }
    }
  que_mirar:
    - "Does the order signature include a unique nonce that is invalidated after use/cancel?"
    - "Is chainId included in the EIP-712 domain separator?"
    - "After partial fill, is the original signature still valid for the remaining amount?"
    - "Can a cancelled order's signature be reused to create a new order?"
    - "For private orders: does the allowedSender check persist after partial fill?"
  como_se_arregla: |
    - Use incrementing nonce per maker (not per order) — any new signature invalidates old ones
    - Include chainId in EIP-712 domain separator
    - After partial fill, require new signature for remaining amount
    - Private orders: check allowedSender on EVERY fill, not just first
    - Implement EIP-2612 style permit with nonce + deadline
  trampas:
    - "Order nonces vs account nonces: order-specific nonces allow multiple active orders but are harder to invalidate"
    - "Cross-chain replay: don't rely on EIP-155 alone; include chainId in order struct"
    - "Some protocols allow meta-transactions for order creation — each relay adds a replay surface"
  solodit_ids:
    - "h02-partially-filled-private-orders-can-be-filled-by-anyone-openzeppelin-1inch-limit-order-protocol-audit-markdown"
    - "lgo-is-vulnerable-to-replay-attacks-trailofbits-level-finance-pdf"
    - "lack-of-chainid-validation-allows-reuse-of-signatures-across-forks-trailofbits-advanced-blockchain-pdf"
    - "possible-replay-attacks-on-spokepoolperiphery-openzeppelin-none-periphery-changes-audit-markdown"
  incidentes:
    - "1inch Limit Order Protocol -- Partially-filled private orders can be filled by anyone; access control lost after first partial fill (HIGH)"
    - "Level Finance -- LGO vulnerable to replay attacks; signature reusable across transactions (HIGH)"
    - "Advanced Blockchain -- Lack of chainId validation allows signature reuse across chain forks (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [signature, replay, permit, EIP-712, nonce, private-order]
  relacionado_con: [ob-005, ob-010]
```

### 1.15 Fee-on-Transfer Token in Orderbook

```yaml
- id: ob-015
  titulo: Fee-on-Transfer Token in Orderbook — Fill Amount Mismatch
  causa_raiz: |
    Cuando un orderbook soporta tokens con fee-on-transfer (FOT), la cantidad recibida
    por el contrato es menor que la cantidad enviada por el user. Si el matching engine
    credita al taker/maker la cantidad original (sin descontar el fee del token), el
    contrato se queda insolvente: las obligaciones registradas superan el balance real.
    Cada fill con un FOT token amplifica el deficit.
  como_funciona: |
    1. Token X tiene 2% transfer fee
    2. Maker coloca sell order: 100 X at 10 USDC each
    3. Taker compra 100 X: envia 1000 USDC, protocolo intenta enviar 100 X al taker
    4. Maker deposito 100 X, pero contrato recibio solo 98 X (2% fee)
    5. Protocolo intenta transferir 100 X al taker — solo tiene 98 X
    6. Resultado A: transaccion reverts (DoS)
    7. Resultado B: si protocolo usa safeTransfer con fallback, taker recibe 98 X
       pero contrato registra 100 X como delivered — ahora insolvente
    8. Multiple fills: deficit acumula → eventual bank run when users try to withdraw
  invariante: |
    // Actual received amount must match credited amount
    function check_fot_accounting(
        uint256 balanceBefore, uint256 balanceAfter,
        uint256 expectedAmount
    ) internal {
        uint256 actualReceived = balanceAfter - balanceBefore;
        t(actualReceived >= expectedAmount, "OB-015: FOT token received less than expected");
    }
    // Contract solvency after fills
    function check_orderbook_solvency(
        address token, uint256 totalObligations
    ) internal view {
        uint256 balance = IERC20(token).balanceOf(address(this));
        t(balance >= totalObligations, "OB-015: orderbook insolvent");
    }
  que_mirar:
    - "Does the protocol use balance-before/after pattern for deposits?"
    - "Is the credited fill amount based on transfer amount or received amount?"
    - "Are FOT tokens explicitly blocked or handled?"
    - "Does the matching engine assume 1:1 transfer ratio?"
    - "Is there a whitelist of allowed tokens for the orderbook?"
  como_se_arregla: |
    - Use balance-before/after pattern: actual = balanceOf(after) - balanceOf(before)
    - Credit users based on actual received amount, not transfer amount
    - OR: explicitly block FOT tokens via whitelist (simpler, recommended for CLOBs)
    - Document clearly if FOT tokens are not supported
  trampas:
    - "Some tokens have configurable fees that can be turned on/off — token passes whitelist initially, then fee activates"
    - "Rebasing tokens have similar but different issues — supply changes without transfers"
    - "balance-before/after pattern adds gas cost per transfer; unacceptable for high-frequency orderbooks"
  solodit_ids:
    - "erc20-with-transfer-fees-not-handled-in-positionsmanager-cantina-none-evoq-pdf"
    - "contracts-do-not-support-tokens-with-fees-or-rebasing-tokens-cyfrin-none-tradable-onchain-v2-markdown"
    - "m-08-stakingtokensol-doesnt-properly-handle-fot-rebasing-tokens-or-those-wi-code4rena-olas-olas-git"
  incidentes:
    - "Evoq -- ERC20 transfer fees not handled in PositionsManager; internal accounting desyncs from real balance (MEDIUM)"
    - "Tradable Onchain v2 -- Contracts do not support tokens with fees or rebasing tokens; balance mismatch (MEDIUM)"
    - "Multiple protocols -- Generic FOT incompatibility found in dozens of Solidity codebases; standard pattern in audit reports"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [fee-on-transfer, FOT, rebasing, token-compatibility, solvency]
  relacionado_con: [ob-012]
```

### 1.16 Order ID Overflow / Orderbook State Corruption

```yaml
- id: ob-016
  titulo: Order ID Overflow — Orderbook State Corruption at Scale
  causa_raiz: |
    Los orderbooks asignan IDs secuenciales a cada order. Si el ID usa un tipo de dato
    demasiado pequeno (uint16, uint32), el orderbook puede alcanzar el maximo despues de
    suficientes ordenes. Cuando el ID overflow, nuevas ordenes sobrescriben las existentes,
    o el orderbook entra en estado invalido (linked list corruption, segment tree overflow).
    En DittoETH, el ID uint16 llega al maximo en 65K ordenes — funcion normal se rompe.
  como_funciona: |
    1. Orderbook usa uint16 para order IDs (max = 65535)
    2. Despues de 65535 ordenes colocadas, el siguiente ID wraps a 0
    3. Order ID 0 colisiona con el HEAD sentinel de la linked list
    4. Resultado: linked list del orderbook se corrompe
    5. Ordenes existentes se vuelven inaccesibles — fondos locked
    6. Nuevas ordenes sobreescriben data de ordenes antiguas
    7. Matching engine falla o produce resultados incorrectos
    8. En CLOBER: segment tree overflow cuando demasiadas ordenes en un grupo
  invariante: |
    // Order ID must never wrap around
    function check_order_id_no_overflow(uint256 currentId, uint256 maxId) internal {
        t(currentId < maxId, "OB-016: order ID at maximum, overflow imminent");
    }
    // New order ID must not collide with existing orders
    function check_no_id_collision(uint256 newId, bool exists) internal {
        t(!exists, "OB-016: order ID collision detected");
    }
    // Linked list integrity after each operation
    function check_linked_list_integrity(
        uint256 headId, uint256 tailId, uint256 orderCount
    ) internal view {
        // Walk the list and verify count matches
        uint256 counted = 0;
        uint256 current = headId;
        while (current != 0 && counted <= orderCount + 1) {
            current = orders[current].next;
            counted++;
        }
        t(counted == orderCount, "OB-016: linked list count mismatch");
    }
  que_mirar:
    - "What data type is used for order IDs? (uint16, uint32, uint64, uint256?)"
    - "What happens when the ID counter reaches the maximum value?"
    - "Does the protocol use a linked list, array, or tree for order storage?"
    - "Is there a migration or cleanup mechanism for expired/filled orders?"
    - "For segment trees: what is the maximum capacity?"
  como_se_arregla: |
    - Use uint256 for order IDs (practically infinite)
    - If using compact types for gas optimization, implement wraparound handling
    - Reuse IDs of cancelled/filled orders (free list pattern)
    - Add circuit breaker: halt new orders when ID space is > 90% consumed
    - Segment trees: use resizable structures or multiple trees
  trampas:
    - "uint16 IDs seem absurdly small but were used in DittoETH for storage packing"
    - "ID reuse with free lists adds complexity — must ensure no stale references to reused IDs"
    - "On high-throughput chains (Solana, Sei), 2^32 orders can be reached in months"
  solodit_ids:
    - "users-lose-funds-and-market-functionality-breaks-when-market-reachs-65k-id-codehawks-dittoeth-git"
    - "overflow-in-segmentedsegmenttree464-spearbit-clober-pdf"
    - "added-orderbooks-do-not-operate-with-their-initial-information-quantstamp-secured-finance-markdown"
  incidentes:
    - "DittoETH -- Users lose funds and market breaks at 65K order ID (uint16 overflow); linked list corrupted (HIGH)"
    - "CLOBER -- Overflow in SegmentedSegmentTree464; segment tree math breaks at boundary (HIGH)"
    - "Secured Finance -- Added orderbooks do not operate with initial information; initialization logic flawed (LOW)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [overflow, order-id, linked-list, segment-tree, state-corruption]
  relacionado_con: [ob-004, ob-012]
```

---

## 2. Protocol-Specific Notes

### 2.1 Serum / OpenBook (Solana)
- **Self-trade handling**: Serum v4 had special logic in `consume_events` for self-trades that was broken
- **Account ownership**: Missing ownership checks for vault accounts in `create_market`
- **Event consumption**: `consume_events` is a separate instruction, creating a window for state inconsistency
- **OpenBook**: Fork of Serum with fixes but inherits much of the same architecture
- **Key audit**: OtterSec audited Serum v4; findings include self-trade bugs and missing ownership checks

### 2.2 CLOBER (EVM)
- **Fee rounding**: Individual maker order fee rounding UP can exceed total collected taker fee
- **Reentrancy in collectFees**: No guard, allows token callback to drain fees
- **SegmentedSegmentTree464**: Custom data structure with overflow at boundaries
- **Group claim clashing**: Multiple orders in same group can clash during claim
- **Key audit**: Spearbit audited CLOBER; fee rounding and reentrancy findings

### 2.3 GTE (EVM — Code4rena)
- **Tick-size constraint**: Backstop bid-side frozen because valid prices cannot be expressed in tick-size
- **Liquidation stalls**: Top-of-book outside divergence band blocks both standard and backstop liquidation
- **Post-only orders**: GTL post-only orders skew totalAssets, minting excessive vault shares
- **Zero-cost trade prevention**: Validation logic incorrectly allows zero-cost trades through
- **Key audits**: Code4rena CLOB + Perps contests (2025)

### 2.4 DittoETH (EVM — CodeHawks)
- **Order ID overflow at 65K**: uint16 order IDs wrap, corrupting linked list
- **Matchtype gas griefing**: Order creation gas depends on previous order's matchtype, exploitable for DoS
- **Partially filled Short Records**: Cannot be liquidated or exited, permanent lock
- **Key audit**: CodeHawks + Code4rena; ID overflow is the most impactful finding

### 2.5 Deriverse DEX (Rust — Off-chain matching)
- **Partial fill dust griefing**: Taker fills below min_qty to force maker order cancellation
- **Order eviction**: When MAX_ORDERS exceeded, oldest order evicted regardless of value
- **Fill function state bugs**: Redundant state updates in fill cause data loss across fills
- **Fee accounting**: Multiple fee bugs in perp engine — prepayment, referral, decimal mismatch

### 2.6 dYdX v4 / Hyperliquid (App-chain)
- **Sequencer control**: Validator/sequencer determines transaction ordering — MEV at consensus layer
- **Sub-account system**: Multiple sub-accounts per wallet complicate self-trade prevention
- **Hyperliquid JELLY incident (2025)**: Whale opened $200M JELLY position, thin book caused HLP vault $4M loss during liquidation cascade
- **Off-chain matching**: Most logic is off-chain; on-chain settlement is the audit surface

### 2.7 CoW Protocol (GPv2)
- **Solver MEV**: Solvers can include self-matched trades, extract surplus from batch
- **Solution optimality**: No guarantee solver finds optimal clearing price; economic incentives misaligned
- **Batch settlement gas**: Large batches can exceed block gas limit, DoS on settlement
- **Off-chain order flow**: Most analysis is off-chain; on-chain surface is settlement contract

### 2.8 0x Protocol
- **Cancel front-running**: cancelOrder() not restricted to maker — anyone can race to front-run
- **Rounding accumulation**: Partial fills accumulate rounding errors in Cobb-Douglas calculations
- **EIP-712 signatures**: Order signatures need careful nonce and chainId handling

### 2.9 DeepBook (Sui / Move)
- **Volume overflow**: Zero-fee whitelisted pools enable unlimited wash trading
- **Trade proof bypass**: vault::settle_balance_manager trade_proof verification can be bypassed
- **Expired orders**: get_level2_range_and_ticks does not filter expired orders from book view

---

## 3. Checklist Rapido de Auditoria CLOB

```
[ ] Self-trade prevention: maker != taker enforced in matching engine?
[ ] Order ID overflow: what type? uint16/32/64/256? What happens at max?
[ ] Fee rounding: per-order rounding accumulates correctly vs total fee?
[ ] Partial fill: minimum fill amount enforced? Dust remaining handled?
[ ] Cancel authorization: only maker can cancel? Mempool-safe?
[ ] Expiry/deadline: using block.timestamp as value (always passes)?
[ ] Tick alignment: price validated as multiple of tickSize? Rounding direction?
[ ] Settlement netting: buys - sells computed correctly per user per token?
[ ] Linked list / tree integrity: corruption possible at boundaries?
[ ] FOT token support: balance-before/after or explicitly blocked?
[ ] Margin isolation: isolated ops cannot affect cross-margin balance?
[ ] Liquidation fallback: what happens when book is too thin to fill?
[ ] Batch auction: solver can include own orders? Surplus distribution fair?
[ ] Signature replay: nonce per order? chainId in domain? Partial fill replay?
[ ] Flash loan defense: can flash-loaned funds be used for order margin?
[ ] Reentrancy: fee collection and settlement guarded?
```

---

## 4. Invariantes Globales para Fuzzing

```solidity
// Solvency: orderbook contract balance >= sum of all user obligations
function invariant_orderbook_solvency() public view {
    uint256 totalObligations = _sumAllOpenOrderBalances();
    uint256 actualBalance = baseToken.balanceOf(address(orderbook));
    t(actualBalance >= totalObligations, "GLOBAL: orderbook insolvent");
}

// Order integrity: every active order is reachable from the book
function invariant_all_orders_reachable() public view {
    uint256 bookCount = _walkBookAndCount();
    uint256 activeCount = orderbook.activeOrderCount();
    t(bookCount == activeCount, "GLOBAL: unreachable orders exist");
}

// Fee conservation: total fees collected >= sum of individual fill fees
function invariant_fee_conservation() public view {
    uint256 totalCollected = orderbook.totalFeesCollected();
    uint256 sumIndividual = _sumAllFillFees();
    t(totalCollected >= sumIndividual, "GLOBAL: fee leakage detected");
}

// No free tokens: no operation should increase user balance without counterparty payment
function invariant_no_free_tokens() public {
    uint256 userBalBefore = baseToken.balanceOf(user);
    // ... execute operations ...
    uint256 userBalAfter = baseToken.balanceOf(user);
    if (userBalAfter > userBalBefore) {
        uint256 counterpartyPaid = _getCounterpartyPayment();
        t(counterpartyPaid > 0, "GLOBAL: user gained tokens without counterparty paying");
    }
}

// Price monotonicity: bids always < asks in a healthy book
function invariant_bid_ask_spread() public view {
    uint256 bestBid = orderbook.bestBid();
    uint256 bestAsk = orderbook.bestAsk();
    if (bestBid > 0 && bestAsk > 0) {
        t(bestBid < bestAsk, "GLOBAL: crossed book (bid >= ask)");
    }
}
```

---

## 5. Referencias y Fuentes

- **Spearbit**: CLOBER audit (fee rounding, reentrancy, segment tree)
- **OtterSec**: Serum v4, DeepBook, Aftermath Orderbook, Econia audits
- **Code4rena**: GTE CLOB + Perps contests (2025), DittoETH
- **CodeHawks**: DittoETH (order ID overflow, matchtype griefing)
- **Cyfrin**: Deriverse DEX (partial fill, state updates, fee accounting)
- **Quantstamp**: Primex Finance (wash trading), Dipcoin (expiry buffer), Secured Finance
- **OpenZeppelin**: 1inch Limit Order Protocol (private order bypass, signature issues)
- **ConsenSys**: 0x v3 Exchange (cancel front-running)
- **Cantina**: Royco (fill griefing), Layer N (Fill-or-Kill crash)
- **Trail of Bits**: 0x Protocol (rounding accumulation), Level Finance (replay)
- **Real incidents**: Mango Markets $114M (2022), Hyperliquid JELLY $4M (2025)
