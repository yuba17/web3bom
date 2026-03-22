grep_targets:
  - "strike"
  - "expiry"
  - "premium"
  - "optionType"
  - "exerciseOption"
  - "settleOption"
  - "putOption"
  - "callOption"
  - "impliedVolatility"
  - "delta"
  - "gamma"
  - "collateral"
  - "writeOption"
  - "underlyingAsset"
  - "settlementPrice"
  - "IVault"
  - "DOV"
  - "structuredProduct"
  - "tranches"
  - "senior"
  - "junior"
  - "leveragedToken"

# Briefing: Options & Structured Products

## Contexto del dominio
Los protocolos de opciones on-chain (Lyra, Hegic, Dopex, Premia, Ribbon Finance/Aevo,
Opyn, Panoptic) y productos estructurados (tranche protocols, leveraged tokens, DOVs —
Decentralized Options Vaults) tienen vulnerabilidades específicas en:
- Pricing y settlement de opciones (manipulation de settlement price)
- Collateral management (overclaim o undercollateralization)
- Ejercicio/expiración con timing específico
- Tranche accounting (senior/junior mix-up)
- Greek calculations incorrectas (delta hedging desync)

---

patterns:

- id: opt-001
  titulo: Settlement Price Manipulation — Oracle Spot vs TWAP en Expiración
  causa_raiz: |
    Al expirar una opción, el contrato necesita saber el precio del subyacente para
    determinar si la opción está in-the-money (ITM) o out-of-the-money (OTM).
    Si el settlement price usa el spot price en el bloque de expiración (en vez de TWAP),
    un atacante puede manipular el price en el momento exacto de la expiración.
  como_funciona: |
    1. Atacante compra calls con strike=$1000 en ETH/USD
    2. En el bloque de expiración, el precio real es $990 (OTM normalmente)
    3. Atacante usa un flashloan para comprar ETH masivamente en ese bloque
    4. Spot price sube a $1005 en ese bloque → opciones son ITM ($5 de ganancia)
    5. Atacante ejerce las opciones, repaga el flashloan, profit neto
    6. En el siguiente bloque, el precio vuelve a $990

    Variante más sutil: el protocol usa Chainlink con 24h heartbeat → el precio puede
    ser de hasta 24h antes → explotar la diferencia entre precio real y precio reportado
  invariante: |
    function check_settlement_price_validity(uint256 settlementPrice) internal view {
        uint256 twapPrice = getTWAP(3600); // TWAP 1 hora
        uint256 spotPrice = getSpotPrice();
        // El settlement price no debe divergir más de 1% del TWAP
        uint256 divergence = settlementPrice > twapPrice
            ? ((settlementPrice - twapPrice) * 10000) / twapPrice
            : ((twapPrice - settlementPrice) * 10000) / twapPrice;
        t(divergence <= 100, "OPT-001: settlement price diverges >1% from TWAP");
    }
  que_mirar:
    - "¿El settlement usa spot o TWAP?"
    - "¿Hay un período de 'price lock' antes de la expiración durante el cual no se puede manipular?"
    - "¿El oracle tiene staleness check?"
    - "¿Quién puede llamar a settle() después de la expiración? ¿Hay un período de disputa?"
  como_se_arregla: |
    - Usar TWAP de 1-4 horas como settlement price
    - Lock del precio X bloques antes de la expiración (no accept new price)
    - Sistema de disputa: cualquiera puede challenge el settlement price con prueba de TWAP
  trampas:
    - "Algunos protocolos tienen oracles 'agregados' (mediana de múltiples fuentes) — más resistentes pero más lentos"
    - "En opciones europeas (solo ejercicio en expiración), el manipulation window es exactamente el bloque de expiry"
    - "En opciones americanas, el atacante puede esperar el momento óptimo de spot manipulation"
  solodit_ids:
    - "h-01-settlement-price-can-be-manipulated-at-expiry-to-profit-from-options-sherlock-git"
    - "m-oracle-manipulation-at-expiry-allows-settling-otm-options-as-itm-code4rena-git"

- id: opt-002
  titulo: Option Writer Undercollateralization — Collateral Puede Usarse Pre-Settlement
  causa_raiz: |
    El writer de una opción debe depositar colateral para garantizar el pago si la opción
    es ejercida. Si el contrato permite que el writer retire colateral antes de que la
    opción expire (o lo usa en otras posiciones), y la opción se ejerce, no hay fondos
    para pagar al holder.
  como_funciona: |
    Variante A — Withdrawal parcial pre-expiry:
    1. Writer deposita 1 ETH de colateral para una call con strike=$2000 (precio actual $1900)
    2. Writer ve que la opción está lejos de ITM y retira 0.5 ETH de "excess collateral"
    3. ETH sube a $2500 antes de expiry
    4. Holder ejerce → paga $2000 por algo que vale $2500 → el writer debe pagar $500
    5. Pero el writer solo tiene 0.5 ETH de colateral → $500 de bad debt

    Variante B — Collateral reutilizado en otra posición:
    1. DOV (Decentralized Options Vault) usa el colateral de las opciones escritas para
       hacer farming en Aave mientras las opciones están activas
    2. El farming puede perder valor (slippage, token depeg)
    3. Al settlement, el colateral recuperado puede ser insuficiente para pagar ITM options
  invariante: |
    function check_collateral_adequacy(uint256 optionId) internal view {
        Option memory opt = options[optionId];
        if (!opt.expired) {
            uint256 maxPayout = calculateMaxPayout(opt); // worst case payout
            uint256 lockedCollateral = collateral[optionId];
            t(lockedCollateral >= maxPayout,
              "OPT-002: insufficient collateral for max payout");
        }
    }
  que_mirar:
    - "¿El colateral del writer puede ser retirado antes de la expiración?"
    - "¿El DOV usa el colateral depositado en estrategias de yield externas?"
    - "¿Qué pasa si el yield strategy pierde valor?"
    - "¿El cálculo de 'required collateral' es correcto para todas las opciones escritas?"
  como_se_arregla: |
    - El colateral del writer debe estar locked 100% hasta settlement
    - Si se usa en yield: solo en estrategias sin riesgo de pérdida (e.g., USDC en Aave stablecoins)
    - Mantener buffer: required collateral = max(current intrinsic value * 110%, initial required)
  trampas:
    - "Las opciones 'naked' (sin colateral completo) son un diseño intencional en algunos protocolos — el riesgo es compartido por el pool"
    - "Los DOVs de Ribbon Finance usan vault shares como colateral — hay que verificar que el vault share price es estable"
  solodit_ids:
    - "h-02-option-writer-can-withdraw-collateral-before-expiry-leaving-options-undercollateralized-sherlock-git"
    - "h-dov-yield-strategy-can-reduce-collateral-below-max-payout-code4rena-git"

- id: opt-003
  titulo: Early Exercise Bypass — American Options Ejercibles Pre-Snapshot
  causa_raiz: |
    Las opciones americanas pueden ejercerse en cualquier momento antes de la expiración.
    Si el contrato no verifica el estado de la posición al momento del ejercicio
    (snapshots de balances, liquidez del writer), el holder puede ejercer cuando es
    imposible que el writer pague, creando bad debt.
  como_funciona: |
    1. Writer tiene 1 ETH de colateral para una call con strike=$1000
    2. ETH sube a $3000 → opción muy ITM (pago = $2000)
    3. Writer está undercollateralized — debería ser liquidado
    4. Keeper no ha liquidado aún (timing)
    5. Holder ejerce → contrato intenta pagar $2000 pero solo tiene $1 ETH ($3000)
    6. Protocolo debe cubrir el déficit con insurance fund o hace partial fill → holder pierde

    Variante: el holder ejerce ANTES de que el writer sea notificado que está liquidated
    El writer puede estar en grace period → ejerce en el gap
  invariante: |
    function check_exercise_has_sufficient_collateral(uint256 optionId) internal view {
        uint256 intrinsicValue = getIntrinsicValue(optionId);
        uint256 writerCollateral = getWriterCollateral(optionId);
        t(writerCollateral >= intrinsicValue,
          "OPT-003: exercise would create undercollateralized position");
    }
  que_mirar:
    - "¿Qué pasa si se ejerce una opción cuyo writer no tiene suficiente colateral?"
    - "¿Hay un mecanismo de liquidación del writer antes del ejercicio?"
    - "¿El insurance fund cubre el déficit si el writer es insolvente?"
    - "¿Puede el writer ser liquidado en el mismo bloque que el ejercicio?"
  como_se_arregla: |
    - Antes de ejercer: verificar que el writer tiene suficiente colateral
    - Si no: revertir el ejercicio (no bad debt) y forzar liquidación del writer
    - O: ejercicio parcial con lo que hay, y reclamar el resto del insurance fund
  trampas:
    - "En opciones pool-based (Lyra, GMX options), el 'writer' es el pool — el pool se gestiona diferente"
    - "El ejercicio anticipado en opciones americanas puede ser subóptimo (better to sell than exercise) — considerar si es por diseño"
  solodit_ids:
    - "h-exercise-creates-bad-debt-when-writer-is-undercollateralized-sherlock-git"

- id: opt-004
  titulo: Premium Calculation Rounding — Opciones Gratuitas para Compradores
  causa_raiz: |
    El premium de una opción se calcula usando modelos de pricing (Black-Scholes
    aproximado, AMM-style). Si el cálculo tiene rounding hacia abajo y el monto
    es pequeño (opciones de bajo notional), el premium puede resultar en 0 tokens.
    Un atacante puede comprar muchas opciones "gratis" y beneficiarse si se vuelven ITM.
  como_funciona: |
    1. Un protocolo de opciones cobra premium en USDC (6 decimales)
    2. Para una opción de 0.001 ETH con premium calculado de 0.0000001 USDC
    3. En 6 decimales: 0.0000001 USDC = 0.0001 units → rounds to 0
    4. Atacante compra 1,000,000 opciones "gratis" (solo gas cost)
    5. Si ETH sube 1%, las opciones tienen valor → profit masivo con 0 costo de premium
  invariante: |
    function check_premium_nonzero(
        uint256 amount, uint256 strike, uint256 expiry
    ) internal view {
        uint256 premium = calculatePremium(amount, strike, expiry);
        t(premium > 0, "OPT-004: option premium rounds to zero");
    }
  que_mirar:
    - "¿El premium calculation puede resultar en 0 para amounts pequeños?"
    - "¿Hay un mínimo de premium hardcodeado?"
    - "¿Hay un mínimo de notional para crear opciones?"
    - "¿El modelo de pricing puede dar 0 para opciones muy OTM con tiempo corto?"
  como_se_arregla: |
    - Añadir: require(premium >= MIN_PREMIUM) después del cálculo
    - O: require(amount >= MIN_OPTION_SIZE) para evitar opciones de bajo notional
    - El mínimo premium debe ser al menos suficiente para cubrir el gas de settlement
  trampas:
    - "Las opciones muy OTM con expiración corta legítimamente tienen premium muy bajo — el mínimo no debe hacer imposibles estas opciones"
    - "El riesgo real es cuando MIN_PREMIUM = 0 y el modelo da 0 para casos edge"
  solodit_ids:
    - "m-option-premium-rounds-to-zero-for-small-notional-amounts-code4rena-git"

- id: opt-005
  titulo: Leveraged Token Rebalancing — Liquidación en Volatilidad Extrema
  causa_raiz: |
    Los leveraged tokens (3x Long ETH, 2x Short BTC) mantienen un apalancamiento
    constante mediante rebalancing. En períodos de alta volatilidad, múltiples
    rebalancings en la misma sesión pueden resultar en "decay" (pérdida de valor
    incluso si el subyacente vuelve al precio original). En casos extremos, el
    rebalancing puede fallar si el pool no tiene suficiente liquidez.
  como_funciona: |
    Variante A — Volatility decay (diseño, no bug, pero se puede explotar):
    1. 3x ETH token: ETH sube 10% → rebanced to 3x → valor +30%
    2. ETH baja 10% → rebanced to 3x → valor -30% del nuevo precio
    3. Net: ETH está en el mismo precio, pero 3x token vale (1.30 * 0.70) = 0.91 del inicio
    4. El decay es 9% con solo 2 movimientos opuestos del 10%
    5. Ataque: alguien puede inducir este decay deliberadamente con flash swaps

    Variante B — Rebalance DoS:
    1. El pool de liquidez del subyacente es pequeño
    2. El rebalance requiere comprar/vender 20% del pool
    3. El price impact del rebalance hace que el leveraged token pierda más de lo esperado
    4. En extremo: el rebalance consume todo el colateral del leveraged token (insolvencia)
  invariante: |
    function check_rebalance_solvency() internal view {
        uint256 navBefore = getNavPerShare();
        rebalance();
        uint256 navAfter = getNavPerShare();
        // El NAV no debe caer más de lo esperado por el delta del subyacente
        uint256 underlyingMove = abs(getUnderlyingReturn());
        uint256 maxExpectedDrop = underlyingMove * leverage * 110 / 100; // 10% buffer
        t(navAfter >= navBefore * (10000 - maxExpectedDrop) / 10000,
          "OPT-005: rebalance reduced NAV more than expected");
    }
  que_mirar:
    - "¿El rebalancing tiene circuit breakers para movimientos de precio extremos?"
    - "¿El protocolo puede quedar insolvente si el subyacente se mueve demasiado entre rebalances?"
    - "¿El MEV de front-running el rebalance extrae valor del pool?"
    - "¿Los holders del leveraged token entienden el volatility decay?"
  como_se_arregla: |
    - Pausa de rebalancing si el subyacente se mueve >X% en un solo bloque
    - Límite al precio impacto máximo del rebalance
    - Si el rebalance requiere más del Y% del pool, rechazar y forzar partial unwind
  trampas:
    - "El decay de volatilidad es matemáticamente inevitable — no es un bug, es una propiedad del instrumento"
    - "Los leveraged tokens de Binance/FTX tienen el mismo decay — es inherente al rebalancing diario"
  solodit_ids:
    - "m-leveraged-token-rebalance-can-drain-collateral-during-high-volatility-sherlock-git"

- id: opt-006
  titulo: Tranche Senior/Junior Accounting Desync — Junior Absorbe Pérdidas del Senior
  causa_raiz: |
    Los productos estructurados con tranches (senior=capital protegido, junior=riesgo)
    deben hacer que el senior reciba su capital primero en el settlement, y el junior
    recibe lo que sobra. Si el accounting de las pérdidas entre tranches está mal,
    el senior puede absorber pérdidas que debería absorber el junior.
  como_funciona: |
    Variante A — Pérdidas mal distribuidas:
    1. Vault tiene: 100 USDC senior (protected), 50 USDC junior (risk)
    2. Vault sufre 30% pérdidas → valor real = 105 USDC
    3. Senior debería recibir: 100 USDC (ninguna pérdida)
    4. Junior debería recibir: 5 USDC (absorbió 45 de las 45 USDC de pérdida)
    5. Bug: el cálculo de waterfall distribuye linealmente → senior recibe 70, junior recibe 35
    6. Senior pierde 30 USDC que el junior debería haber absorbido

    Variante B — Junior puede retirarse antes del settlement:
    1. Junior deposita 50 USDC durante el término del producto
    2. El producto se deteriora durante el término
    3. Junior retira su capital antes del settlement (el contrato lo permite)
    4. Al settlement, solo queda el senior capital → no hay buffer → senior toma las pérdidas
  invariante: |
    function check_senior_capital_protected(uint256 seniorDeposited) internal view {
        uint256 totalAssets = vault.totalAssets();
        uint256 juniorDeposited = vault.juniorTotalDeposited();
        // Senior capital está protegido mientras haya activos suficientes
        uint256 seniorProtected = min(seniorDeposited, totalAssets);
        t(seniorProtected >= seniorDeposited - juniorDeposited * juniorLossBuffer / 100,
          "OPT-006: senior tranche not adequately protected");
    }
  que_mirar:
    - "¿El waterfall de distribución de pérdidas está implementado correctamente?"
    - "¿Puede el junior retirarse durante el término del producto?"
    - "¿Hay un lockup del junior hasta el settlement?"
    - "¿El ratio junior/senior tiene un mínimo obligatorio (para garantizar la protección del senior)?"
  como_se_arregla: |
    - Junior capital locked hasta settlement
    - Ratio mínimo: junior >= X% del senior (si las pérdidas máximas esperadas son X%)
    - El waterfall debe calcularse sobre el valor final, no distribuir linealmente
  trampas:
    - "Los structured products 'principal protected notes' en DeFi frecuentemente tienen este bug"
    - "Si el junior deposita muy poco vs el senior, la protección del senior es teórica, no real"
  solodit_ids:
    - "h-03-junior-tranche-can-withdraw-before-settlement-leaving-senior-unprotected-sherlock-git"
    - "m-waterfall-distributes-losses-linearly-instead-of-junior-first-code4rena-git"

- id: opt-007
  titulo: DOV (Decentralized Options Vault) — Strike Selection Manipulada
  causa_raiz: |
    Los DOVs (Ribbon Finance, StakeDAO, Friktion) crean opciones automáticamente cada semana.
    El strike se selecciona como un porcentaje del precio actual (e.g., 10% OTM).
    Si el precio usado para calcular el strike puede ser manipulado justo antes del snapshot,
    se puede hacer que el vault cree opciones con un strike incorrecto (mucho más ITM o OTM).
  como_funciona: |
    Variante A — Strike muy OTM (beneficia al vault, perjudica al comprador):
    1. El vault selecciona strike = currentPrice * 1.10 (10% OTM)
    2. Atacante manipula el precio hacia abajo justo antes del snapshot
    3. Strike se fija en un precio muy por debajo del precio real
    4. Las opciones que vende el vault son muy ITM en el mercado real → vault tiene pérdidas

    Variante B — Strike muy ITM (perjudica al vault):
    1. Atacante manipula el precio hacia arriba antes del snapshot
    2. Strike se fija muy por encima del precio real
    3. Las opciones son muy OTM → nadie las compra → vault no genera yield
  invariante: |
    function check_strike_selection_validity(uint256 strike, uint256 currentPrice) internal view {
        uint256 minStrike = currentPrice * (100 - MAX_ITM_PCT) / 100;
        uint256 maxStrike = currentPrice * (100 + MAX_OTM_PCT) / 100;
        t(strike >= minStrike && strike <= maxStrike,
          "OPT-007: strike outside acceptable range from current price");
    }
  que_mirar:
    - "¿El snapshot de precio para el strike selection usa spot o TWAP?"
    - "¿Hay un buffer de tiempo entre el precio y la creación de las opciones?"
    - "¿Quién puede iniciar el commitNextOption()? ¿Tiene access control?"
    - "¿El vault puede crear opciones con strike manipulado en beneficio del operador?"
  como_se_arregla: |
    - Usar TWAP de 24 horas para la selección del strike
    - Añadir sanity check: el strike debe estar entre currentPrice * [0.85, 1.30]
    - Separar el snapshot de precio del deploy de opciones por al menos 1 hora
  trampas:
    - "Los vaults DOV deben usar TWAP, pero algunos usan Chainlink que puede estar hasta 24h stale"
    - "La selección del strike óptimo es un balance entre yield (más ITM = más premium) y risk (más ITM = más ejercicios)"
  solodit_ids:
    - "m-dov-strike-selection-uses-spot-price-manipulable-at-snapshot-code4rena-git"
    - "h-ribbon-finance-strike-price-can-be-manipulated-sherlock-git"

- id: opt-008
  titulo: Gamma Squeeze — Opciones ITM Sin Suficiente Liquidity para Settlement
  causa_raiz: |
    En momentos de alta volatilidad, muchas opciones pueden volverse ITM simultáneamente.
    Si el protocolo no tiene suficiente liquidez para pagar todas las opciones ITM
    (el pool está undercollateralized para el escenario de settlement masivo),
    los últimos en ejercer pierden fondos.
  como_funciona: |
    1. Protocolo de opciones pool-based: el pool escribe calls sobre ETH
    2. ETH sube 50% → todas las calls están profundamente ITM
    3. El pool debe pagar a todos los holders de calls
    4. La pool no tiene suficiente para pagar a todos → primeros en ejercer cobran full
    5. Últimos en ejercer reciben partial payout o nada
    6. Esto crea un "banco run" de ejercicios → todos ejercen simultáneamente cuando ven el riesgo
  invariante: |
    function check_pool_can_cover_all_itm() internal view {
        uint256 totalPayoutRequired = calculateTotalITMPayout(currentPrice);
        uint256 poolLiquidity = getAvailableLiquidity();
        t(poolLiquidity >= totalPayoutRequired,
          "OPT-008: pool undercollateralized for current ITM positions");
    }
  que_mirar:
    - "¿El protocolo tiene un cap en el open interest total vs el pool size?"
    - "¿Puede el pool estar undercollateralized si todas las opciones son ejercidas simultáneamente?"
    - "¿Hay un mecanismo de pari-passu si el pool es insuficiente?"
    - "¿El pool puede tomar prestado (leverage) para cubrir el shortfall?"
  como_se_arregla: |
    - Cap de open interest: totalOI < poolSize / (1 + maxExpectedLoss%)
    - Si el payout total excede el pool: distribución pari-passu (todos reciben proporcionalmente)
    - No usar leverage en el pool para cubrir shortfalls — aumenta el riesgo sistémico
  trampas:
    - "Este es un riesgo de diseño sistémico, no siempre un bug — algunos protocolos lo documentan"
    - "La solution de pari-passu reduce los incentivos para ejercer temprano, mitigando el banco run"
  solodit_ids:
    - "h-pool-undercollateralized-if-all-options-go-itm-simultaneously-sherlock-git"
