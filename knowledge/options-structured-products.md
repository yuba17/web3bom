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

- id: opt-009
  titulo: Panoptic — Reentrancy Cross-Contract en Liquidación Drena CollateralTracker
  causa_raiz: |
    En protocolos de opciones con múltiples contratos interrelacionados (PanopticPool,
    CollateralTracker, SFPM), una liquidación involucra llamadas entre contratos que
    actualizan shares y balances. Si el flujo de liquidación permite reentrancia entre
    contratos (e.g., via callbacks ERC1155/ERC777 o manipulación de Uniswap hooks),
    un atacante puede convertir "phantom shares" (shares inflados durante el proceso)
    en shares reales, drenando activos del CollateralTracker.
  como_funciona: |
    1. Atacante crea una posición que será liquidable (undercollateralized)
    2. Al ser liquidada, el flujo PanopticPool._liquidate() quema shares del liquidado
       y minta bonus shares al liquidador
    3. Durante el proceso, hay un momento donde el totalSupply de shares y el balance
       del CollateralTracker están desincronizados (shares quemados pero assets no movidos)
    4. Atacante usa reentrancia en ese gap para depositar/retirar, explotando el
       exchange rate inflado temporalmente
    5. Las "phantom shares" se convierten en shares reales respaldados por assets de otros usuarios
  invariante: |
    function check_no_reentrancy_during_liquidation() internal view {
        // CollateralTracker totalAssets / totalSupply ratio debe ser consistente
        // antes y después de cualquier operación atómica
        uint256 ratioBefore = (totalAssets * 1e18) / totalSupply;
        // ... después de la operación ...
        uint256 ratioAfter = (totalAssets * 1e18) / totalSupply;
        t(ratioAfter >= ratioBefore * 99 / 100,
          "OPT-009: exchange rate dropped during liquidation — possible reentrancy");
    }
  que_mirar:
    - "¿Hay reentrancy guards entre PanopticPool y CollateralTracker?"
    - "¿Las operaciones de mint/burn de shares son atómicas respecto al movimiento de assets?"
    - "¿Se puede triggerar un callback (ERC1155, Uniswap) durante la liquidación?"
    - "¿El exchange rate shares/assets es monotónico durante liquidación?"
  como_se_arregla: |
    - Reentrancy guard cross-contract compartido entre PanopticPool y CollateralTracker
    - Patrón checks-effects-interactions estricto: actualizar shares Y assets antes de llamadas externas
    - Lock global durante liquidación que impide depósitos/retiros concurrentes
  trampas:
    - "La reentrancia cross-contract es más sutil que la intra-contract — los guards individuales no protegen"
    - "En Panoptic, el SFPM interactúa con pools de Uniswap V3 que pueden triggerar callbacks"
  solodit_ids:
    - "h-02-cross-contract-reentrancy-in-liquidation-enables-conversion-of-phantom-shares-to-real-shares-draining-collateraltracker-assets-code4rena-panoptic-panoptic-git"
  incidentes: []
  verificado: true
  confianza: 92

- id: opt-010
  titulo: Panoptic — Liquidación Bloqueada por Posiciones con Ticks Extremos
  causa_raiz: |
    En protocolos de opciones basados en Uniswap V3 (Panoptic), las posiciones se definen
    por rangos de ticks. Si un usuario crea posiciones con legs de rango muy amplio
    (cerca de MIN_TICK/MAX_TICK), los cálculos de solvencia pueden revertir por overflow
    o por intentar acceder a ticks inválidos, haciendo la posición imposible de liquidar.
  como_funciona: |
    1. Atacante abre una posición con short legs que abarcan casi todo el rango de ticks
       (e.g., tickLower cerca de MIN_TICK, tickUpper cerca de MAX_TICK)
    2. La posición se vuelve insolvente (undercollateralized)
    3. Un liquidador intenta liquidar, pero getSolvencyTicks() o _getRequiredCollateral()
       revierten con Errors.InvalidTick porque los ticks están fuera del rango soportado
    4. La posición insolvente queda permanentemente sin poder liquidarse
    5. El protocolo acumula bad debt que socializa entre los demás LPs
  invariante: |
    function check_liquidation_always_possible(address account) internal view {
        // Si una cuenta es insolvente, la liquidación NO debe revertir
        if (!isSolvent(account)) {
            // Intentar liquidar — debe ejecutarse sin revert
            try panopticPool.liquidate(account) {
                // OK
            } catch {
                t(false, "OPT-010: insolvent account cannot be liquidated");
            }
        }
    }
  que_mirar:
    - "¿Hay validación de que tickLower/tickUpper están dentro de rangos seguros al abrir posición?"
    - "¿Los cálculos de collateral/solvency pueden revertir con ticks extremos?"
    - "¿Hay un máximo de ancho de rango por leg?"
    - "¿getRequiredCollateral puede producir division by zero con rangos extremos?"
  como_se_arregla: |
    - Validar rango de ticks al abrir posición: MAX_TICK_RANGE = usableTick(MAX_TICK) - usableTick(MIN_TICK)
    - Los cálculos de solvencia deben usar safe math y manejar edge cases de ticks
    - Fallback de liquidación: si el cálculo revierte, permitir liquidación de emergencia
  trampas:
    - "El rango máximo de ticks en Uniswap V3 es -887272 a +887272, pero no todos son válidos para todos los tickSpacings"
    - "Division by zero puede ocurrir cuando el rango de la leg es exactamente el tickSpacing"
  solodit_ids:
    - "m-08-wide-range-short-legs-can-revert-solvency-checks-and-block-liquidations-errorsinvalidtick-code4rena-panoptic-panoptic-git"
    - "m-01-liquidations-can-be-permanently-blocked-via-getliquidationbonus-unsigned-underflow-insolvent-but-unliquidatable-accounts-code4rena-panoptic-panoptic-git"
    - "m-05-division-by-zero-in-long-leg-collateral-requirement-can-block-solvency-checks-and-dispatchfrom-liquidationforce-exercise-for-tickspacin"
  incidentes: []
  verificado: true
  confianza: 95

- id: opt-011
  titulo: Panoptic — Premium Settlement Invertido (Sumar en vez de Restar)
  causa_raiz: |
    En protocolos de opciones con premia acumulada (como Panoptic), los long option holders
    deben pagar premia a los short option writers. Si la función de settlement tiene el signo
    invertido (suma premia al long en vez de restársela, o viceversa), los holders reciben
    premia que deberían pagar, drenando el pool.
  como_funciona: |
    1. El contrato calcula la premia adeudada por un long position holder
    2. settleLongPremium() debería RESTAR la premia del balance del holder y SUMARLA al writer
    3. Bug: la implementación SUMA la premia al holder en vez de restarla
    4. El holder recibe tokens extra en cada settlement
    5. Resultado: el pool se drena progresivamente porque la premia fluye en dirección incorrecta
    6. Los short writers nunca cobran su premia — pérdida directa de fondos
  invariante: |
    function check_premium_direction(uint256 longBalanceBefore, uint256 longBalanceAfter,
                                     uint256 writerBalanceBefore, uint256 writerBalanceAfter,
                                     uint256 premiumAmount) internal pure {
        // Después del settlement, el long debe tener MENOS y el writer MÁS
        t(longBalanceAfter <= longBalanceBefore,
          "OPT-011: long balance increased after premium settlement");
        t(writerBalanceAfter >= writerBalanceBefore,
          "OPT-011: writer balance decreased after premium settlement");
    }
  que_mirar:
    - "¿La dirección del flujo de premia es correcta? long paga → writer recibe"
    - "¿Se usa resta o suma al actualizar el balance del long holder?"
    - "¿El signo del delta de premia es consistente en todas las funciones de settlement?"
    - "¿Hay unit tests que verifiquen la dirección del flujo?"
  como_se_arregla: |
    - Verificar que settleLongPremium reste del long y sume al writer
    - Invariante: sum(premia_paid_by_longs) == sum(premia_received_by_writers)
    - Tests paramétricos que confirmen dirección correcta del flujo
  trampas:
    - "En sistemas complejos de premia con múltiples legs, el signo puede ser correcto para unas legs e incorrecto para otras"
    - "La premia 'owed' vs 'gross' vs 'net' puede confundir la dirección esperada"
  solodit_ids:
    - "h-01-settlelongpremium-is-incorrectly-implemented-premium-should-be-deducted-instead-of-added-code4rena-panoptic-panoptic-git"
  incidentes: []
  verificado: true
  confianza: 97

- id: opt-012
  titulo: Dopex — Precisión Incorrecta del Strike Price Rompe Bonding
  causa_raiz: |
    En protocolos que calculan el strike price on-chain (Dopex rDPX V2), el precio del
    subyacente se obtiene de un oracle y se redondea al múltiplo más cercano del step.
    Si el cálculo de precisión es incorrecto (e.g., división antes de multiplicación,
    o confusión de decimales entre oracle y token), el strike resultante puede ser 0
    o un valor absurdo, rompiendo el flujo de bonding/opciones.
  como_funciona: |
    1. Oracle retorna precio de rDPX en 8 decimales: e.g., 15.50 USDC = 1550000000
    2. El contrato calcula: strike = (price / roundingPrecision) * roundingPrecision
    3. Si roundingPrecision > price (e.g., precision=1e10 y price=1.55e9), el resultado es 0
    4. Con strike=0, las opciones put escritas por PerpetualAtlanticVault son gratuitas
    5. O peor: el bond() revierte porque no se puede crear una opción con strike=0
    6. Todo el sistema de bonding queda bloqueado hasta que el precio suba lo suficiente
  invariante: |
    function check_strike_nonzero_and_reasonable(uint256 currentPrice) internal view {
        uint256 strike = calculateStrike(currentPrice);
        t(strike > 0, "OPT-012: strike price rounds to zero");
        // Strike debe estar dentro de ±50% del precio actual
        t(strike >= currentPrice / 2 && strike <= currentPrice * 2,
          "OPT-012: strike price unreasonably far from current price");
    }
  que_mirar:
    - "¿El roundingPrecision puede ser mayor que el precio del token?"
    - "¿La conversión de decimales entre oracle y token es correcta?"
    - "¿Qué pasa con tokens de bajo precio (sub-$1)?"
    - "¿El strike puede ser 0 y aún así crear una opción válida?"
  como_se_arregla: |
    - require(strike > 0, "invalid strike") después del cálculo de redondeo
    - Usar roundUp en vez de roundDown: strike = ((price + precision - 1) / precision) * precision
    - Validar que roundingPrecision < minExpectedPrice
  trampas:
    - "El problema es más probable con tokens de bajo precio y alta roundingPrecision"
    - "Cambiar roundingPrecision requiere governance — si el precio cae rápido, el fix llega tarde"
  solodit_ids:
    - "h-01-improper-precision-of-strike-price-calculation-can-result-in-broken-protocol-code4rena-dopex-dopex-git"
  incidentes: []
  verificado: true
  confianza: 95

- id: opt-013
  titulo: Dopex — Profit Instantáneo en PerpetualAtlanticVaultLP (Deposit-Redeem Arbitrage)
  causa_raiz: |
    En vaults de opciones perpetuas (Dopex PerpetualAtlanticVaultLP), si la función de
    redención calcula el valor de las shares usando el balance actual del vault (que incluye
    premium recibido pero aún no distribuido), un atacante puede depositar justo antes de
    que se acredite premium, obtener shares, y redimir inmediatamente después para capturar
    parte del premium sin haber asumido riesgo.
  como_funciona: |
    1. PerpetualAtlanticVault acumula premium de las opciones escritas
    2. El premium aún no se ha distribuido al LP vault
    3. Atacante deposita una cantidad grande en el LP vault → recibe shares a precio "pre-premium"
    4. Se ejecuta la distribución de premium → el vault recibe WETH
    5. El exchange rate shares/assets sube inmediatamente
    6. Atacante redime sus shares al nuevo precio → profit = su porción del premium
    7. Todo en la misma transacción o bloque → zero risk para el atacante
  invariante: |
    function check_no_instant_profit(uint256 depositAmount) internal {
        uint256 sharesBefore = vault.balanceOf(attacker);
        vault.deposit(depositAmount, attacker);
        uint256 sharesReceived = vault.balanceOf(attacker) - sharesBefore;
        // Redimir inmediatamente
        uint256 assetsReturned = vault.redeem(sharesReceived, attacker, attacker);
        // No debe ser posible obtener más de lo depositado (ignorando fees)
        t(assetsReturned <= depositAmount,
          "OPT-013: instant profit possible via deposit-redeem");
    }
  que_mirar:
    - "¿El exchange rate de shares cambia en el mismo bloque que se deposita premium?"
    - "¿Hay un lockup period mínimo entre deposit y redeem?"
    - "¿El premium se distribuye de forma lineal o en lump sum?"
    - "¿La función previewRedeem refleja el premium pendiente?"
  como_se_arregla: |
    - Lockup de al menos 1 epoch entre deposit y redeem
    - Distribución lineal del premium (vesting) en vez de lump sum
    - Snapshot del balance al momento del deposit — solo gana premium posterior
  trampas:
    - "Si hay withdrawal fee, el atacante necesita que el premium capture supere la fee — calcular breakeven"
    - "JIT (just-in-time) liquidity es un patrón conocido en DeFi pero en opciones es más explotable"
  solodit_ids:
    - "h-05-users-can-get-immediate-profit-when-deposit-and-redeem-in-perpetualatlanticvaultlp-code4rena-dopex-dopex-git"
  incidentes: []
  verificado: true
  confianza: 94

- id: opt-014
  titulo: Opyn Crab Netting — Decimal Mismatch en debtToMint Invalida Settlement
  causa_raiz: |
    En estrategias estructuradas que convierten entre deuda (en ETH/WETH, 18 decimales)
    y collateral (en USDC, 6 decimales), la confusión de decimales en el cálculo puede
    producir valores orders-of-magnitude incorrectos. Si feeAdjustment usa decimales
    distintos a los esperados por la fórmula debtToMint, el monto de deuda calculado
    es absurdo — haciendo que deposits/withdrawals de la estrategia fallen o sean explotables.
  como_funciona: |
    1. Crab Netting Strategy calcula cuánta deuda (Squeeth) mintear para un depósito USDC
    2. La fórmula usa feeAdjustment como factor de ajuste (e.g., 1% = 10 en base 1000)
    3. Bug: el código trata feeAdjustment como si tuviera 18 decimales cuando tiene 3
    4. Resultado: debtToMint es ~1e15 veces mayor o menor de lo correcto
    5. Si es mayor: la estrategia mintea deuda masiva, quedando instantly undercollateralized
    6. Si es menor: la estrategia no mintea suficiente deuda, perdiendo exposure
  invariante: |
    function check_debt_to_mint_reasonable(uint256 depositAmount, uint256 debtMinted) internal view {
        uint256 currentDebtRatio = totalDebt * 1e18 / totalCollateral;
        uint256 expectedDebt = depositAmount * currentDebtRatio / 1e18;
        // El debt minted debe estar dentro del 5% del esperado
        uint256 diff = debtMinted > expectedDebt
            ? debtMinted - expectedDebt : expectedDebt - debtMinted;
        t(diff * 100 / expectedDebt <= 5,
          "OPT-014: debtToMint diverges >5% from expected ratio");
    }
  que_mirar:
    - "¿Todos los factores de la fórmula debtToMint están en los mismos decimales?"
    - "¿feeAdjustment, price, y amount usan la misma base?"
    - "¿Hay conversión explícita de decimales entre USDC (6) y ETH (18)?"
    - "¿Los unit tests prueban con valores reales (no solo 1e18)?"
  como_se_arregla: |
    - Documentar y validar los decimales de cada parámetro en la fórmula
    - require(feeAdjustment <= MAX_FEE_BPS) para detectar valores fuera de rango
    - Tests con valores reales de mercado (no solo potencias de 10)
  trampas:
    - "El mismatch de decimales puede no manifestarse en tests si se usan valores 'redondos' como 1e18"
    - "En mainnet, feeAdjustment se settea por governance — si el setter no entiende los decimales, el bug se activa"
  solodit_ids:
    - "h-1-debttomint-incorrectly-treats-feeadjustment-decimals-sherlock-opyn-opyn-crab-netting-git"
  incidentes: []
  verificado: true
  confianza: 93

- id: opt-015
  titulo: Opyn Crab — DoS por Arrays Ilimitados en Deposit/Withdraw Indices
  causa_raiz: |
    En protocolos de netting/batch (Opyn Crab Netting), los depósitos y retiros de usuarios
    se almacenan en arrays por usuario. Si no hay un límite en el número de entradas y no
    se limpian las entradas procesadas, los arrays crecen indefinidamente. Un atacante puede
    hacer miles de depósitos/retiros pequeños para que las funciones que iteran sobre estos
    arrays excedan el gas limit, bloqueando deposits/withdrawals para todos.
  como_funciona: |
    1. Crab Netting almacena cada deposit/withdraw del usuario en un array indexado
    2. Las funciones de netting iteran sobre TODOS los índices del usuario para calcular totales
    3. Atacante hace 10,000 depósitos de 1 wei cada uno
    4. Cualquier función que itere sobre los depósitos del atacante consume >30M gas → revert
    5. Si la función de netting procesa TODOS los usuarios en un loop, un solo usuario
       con arrays enormes bloquea el procesamiento para todos
    6. Los fondos quedan permanentemente bloqueados en el contrato
  invariante: |
    function check_array_bounded(address user) internal view {
        uint256 depositCount = getUserDepositCount(user);
        uint256 withdrawCount = getUserWithdrawCount(user);
        t(depositCount <= MAX_ENTRIES_PER_USER,
          "OPT-015: user deposit array exceeds safe limit");
        t(withdrawCount <= MAX_ENTRIES_PER_USER,
          "OPT-015: user withdraw array exceeds safe limit");
    }
  que_mirar:
    - "¿Los arrays de depósitos/retiros por usuario tienen un límite máximo?"
    - "¿Se limpian las entradas procesadas (delete o compact)?"
    - "¿Las funciones de netting/batch iteran sobre todos los usuarios en un solo tx?"
    - "¿Un usuario puede crear entradas de 0 o 1 wei?"
  como_se_arregla: |
    - Mínimo de depósito: require(amount >= MIN_DEPOSIT)
    - Compactar arrays: eliminar entradas procesadas después del netting
    - Limitar entradas por usuario: require(userDeposits.length < MAX_ENTRIES)
    - Procesar netting en batches paginados, no todo en un solo tx
  trampas:
    - "El atacante puede usar múltiples direcciones para distribuir el ataque si hay límite per-address"
    - "Incluso con cleanup, si el cleanup es manual y no automático, el admin debe intervenir"
  solodit_ids:
    - "h-3-adverary-can-dos-contract-by-making-a-large-number-of-depositswithdraws-then-removing-them-all-sherlock-opyn-opyn-crab-netting-git"
    - "m-2-denial-of-service-userdepositindex-and-userwithdrawindex-growing-indefinitely-sherlock-opyn-opyn-crab-netting-git"
  incidentes: []
  verificado: true
  confianza: 94

- id: opt-016
  titulo: Y2K Finance — Vault Counterparty Vacío Causa Pérdida Total de Depósitos
  causa_raiz: |
    En protocolos de opciones binarias con vaults counterparty (Y2K Finance: Risk vault vs
    Hedge vault), los depositantes de un vault apuestan contra los del otro. Si un vault
    tiene depósitos pero el counterparty vault está vacío, y el evento trigger ocurre,
    los depositantes del vault activo pierden todo su capital sin que nadie se beneficie
    (los fondos quedan atrapados o se queman).
  como_funciona: |
    1. Risk vault tiene 100 ETH depositados (apostando a que no habrá depeg)
    2. Hedge vault tiene 0 ETH (nadie apuesta a que sí habrá depeg)
    3. Ocurre un depeg → Risk vault pierde
    4. Los fondos del Risk vault deberían ir al Hedge vault, pero no hay depositantes
    5. Los 100 ETH del Risk vault quedan bloqueados en el contrato sin beneficiario
    6. Alternativa: el cálculo de payout divide por totalDeposits del hedge vault (0) → revert

    Variante: ambos vaults tienen depósitos pero el ratio es extremo (1000:1) →
    el vault pequeño recibe un payout absurdamente grande (1000x su depósito)
  invariante: |
    function check_counterparty_not_empty(uint256 epochId) internal view {
        uint256 riskDeposits = riskVault.totalDeposits(epochId);
        uint256 hedgeDeposits = hedgeVault.totalDeposits(epochId);
        // Al menos uno debe tener depósitos, y si uno tiene, el otro también debería
        if (riskDeposits > 0) {
            t(hedgeDeposits > 0,
              "OPT-016: hedge vault empty while risk vault has deposits");
        }
    }
  que_mirar:
    - "¿Qué pasa si un vault tiene depósitos y el counterparty está vacío?"
    - "¿El payout divide por totalDeposits del counterparty (puede ser 0)?"
    - "¿Hay un ratio mínimo entre los dos vaults para que la epoch sea válida?"
    - "¿Los depositantes pueden retirarse si el counterparty está vacío?"
  como_se_arregla: |
    - Epoch inválida si un vault está vacío: require(riskDeposits > 0 && hedgeDeposits > 0)
    - Si un vault está vacío al cierre, devolver fondos al otro vault (refund)
    - Ratio mínimo: el vault más pequeño debe ser >= X% del más grande
  trampas:
    - "En mercados de depeg, puede ser racional que nadie apueste a depeg — el hedge vault puede estar vacío legítimamente"
    - "Si se cancela la epoch por vault vacío, el otro lado pierde la oportunidad de hedge"
  solodit_ids:
    - "h-04-users-who-deposit-in-one-vault-can-lose-all-deposits-and-receive-nothing-when-counterparty-vault-has-no-deposits-code4rena-y2k-finance-y2k-finance-contest-git"
  incidentes: []
  verificado: true
  confianza: 93

- id: opt-017
  titulo: Delta Hedge Sign Reversal — Hedge en Dirección Opuesta Amplifica Riesgo
  causa_raiz: |
    En protocolos de opciones AMM que ejecutan delta hedging automático (Smilee Finance,
    Lyra), el monto del hedge se calcula como función del delta de las posiciones abiertas.
    Si la condición que determina el SIGNO del hedge (comprar vs vender el subyacente)
    tiene un error lógico, el protocolo hedgea en la dirección OPUESTA a la correcta,
    duplicando la exposición en vez de reducirla.
  como_funciona: |
    1. El protocolo tiene exposición neta de +100 delta (necesita VENDER 100 ETH para hedgear)
    2. La función deltaHedgeAmount() calcula correctamente |amount| = 100
    3. Bug: la condición if (currentDelta > targetDelta) está invertida
    4. En vez de vender 100 ETH, el protocolo COMPRA 100 ETH
    5. La exposición neta pasa de +100 a +200 delta (el doble de riesgo)
    6. Si ETH baja, el pool pierde el doble de lo que debería
    7. Un atacante puede triggerar esto deliberadamente manipulando el precio para
       forzar un rebalance en la dirección incorrecta
  invariante: |
    function check_hedge_reduces_delta(int256 deltaBefore, int256 deltaAfter) internal pure {
        // Después del hedge, el delta absoluto debe ser menor
        int256 absBefore = deltaBefore > 0 ? deltaBefore : -deltaBefore;
        int256 absAfter = deltaAfter > 0 ? deltaAfter : -deltaAfter;
        t(absAfter <= absBefore,
          "OPT-017: hedge increased absolute delta instead of reducing it");
    }
  que_mirar:
    - "¿La condición que determina buy vs sell en el hedge es correcta?"
    - "¿El signo del deltaHedgeAmount es consistente con la convención (positivo=buy, negativo=sell)?"
    - "¿Hay tests que prueban el hedge con delta positivo Y negativo?"
    - "¿Un usuario puede manipular el precio para forzar un rebalance con signo incorrecto?"
  como_se_arregla: |
    - Verificar post-condición: abs(delta_after) < abs(delta_before)
    - Test exhaustivo: probar hedge para todos los cuadrantes de delta (++, +-, -+, --)
    - Sanity check: si el hedge es > X% del pool, pausar y alertar
  trampas:
    - "El signo del delta depende de la convención: ¿delta positivo = largo o corto? Verificar documentación"
    - "En mercados con multiple tenors, el delta neto puede cambiar de signo entre el cálculo y la ejecución"
  solodit_ids:
    - "h-1-the-sign-of-delta-hedge-amount-can-be-reversed-by-malicious-user-due-to-incorrect-condition-in-financeigdeltadeltahedgeamount-sherlock-smilee-finance-git"
  incidentes: []
  verificado: true
  confianza: 95

- id: opt-018
  titulo: Put Option Fee Deducted en Expiración en vez de Ejercicio
  causa_raiz: |
    En protocolos de opciones P2P (Putty), las fees del protocolo deben cobrarse cuando
    la opción se ejerce (el momento en que hay un intercambio de valor). Si la fee se cobra
    en la expiración (cuando la opción NO se ejerce), el writer paga una fee por una opción
    que expiró sin valor — pagando por nada. Peor aún, si la opción se ejerce, NO se cobra
    fee — el protocolo pierde ingresos en el caso donde hay actividad real.
  como_funciona: |
    1. Writer crea un put option y deposita strike price como collateral
    2. La opción expira OTM (out-of-the-money) → el holder no ejerce
    3. Writer llama withdraw() para recuperar su collateral
    4. Bug: withdraw() cobra una fee del collateral al writer
    5. El writer pierde una parte de su collateral por una opción que nadie ejerció
    6. Conversamente: si la opción se ejerce, exercise() NO cobra fee
    7. El protocolo cobra fees cuando no hay valor creado y no cobra cuando sí lo hay
  invariante: |
    function check_fee_on_exercise_not_expiry(uint256 optionId) internal view {
        Option memory opt = options[optionId];
        if (opt.expired && !opt.exercised) {
            // Al expirar sin ejercicio, el writer debe recibir el 100% de su collateral
            uint256 withdrawable = getWithdrawableAmount(optionId);
            t(withdrawable == opt.collateralDeposited,
              "OPT-018: fee deducted on expiry instead of exercise");
        }
    }
  que_mirar:
    - "¿En qué función se cobra la protocol fee: exercise() o withdraw()?"
    - "¿El writer pierde parte de su collateral cuando la opción expira sin ser ejercida?"
    - "¿La fee se calcula sobre el strike o sobre el payout?"
    - "¿Hay fee tanto en exercise como en withdraw? ¿Debería haber?"
  como_se_arregla: |
    - Cobrar fee SOLO en exercise(), no en withdraw()
    - La fee debe calcularse sobre el payout (intrinsic value), no sobre el collateral total
    - withdraw() tras expiración devuelve 100% del collateral sin deducciones
  trampas:
    - "Algunos protocolos cobran fee tanto en exercise como en creation — esto es diferente a cobrar en expiry"
    - "La fee en withdraw incentiva a no retirar → fondos quedan en el contrato indefinidamente"
  solodit_ids:
    - "h-01-fee-is-being-deducted-when-put-is-expired-and-not-when-it-is-exercised-code4rena-putty-putty-contest-git"
  incidentes: []
  verificado: true
  confianza: 96

- id: opt-019
  titulo: Binary Options — LPs Gamean Expiración Retirando Liquidez Pre-Settlement
  causa_raiz: |
    En pools de opciones binarias (Buffer Finance), los LPs proveen liquidez que respalda
    los payouts de las opciones. Si los LPs pueden retirar su liquidez ENTRE la compra
    de la opción y su expiración, pueden observar si la opción será ITM y retirar antes
    del payout, dejando al pool sin fondos para pagar al ganador.
  como_funciona: |
    1. Pool tiene 1000 USDC de LPs, respalda opciones binarias de 5 min
    2. Trader compra una opción binaria por 100 USDC (payout 180 USDC si gana)
    3. El precio se mueve a favor del trader — la opción probablemente será ITM
    4. LPs ven que van a perder dinero → retiran liquidez del pool
    5. Al expirar, la opción es ITM pero el pool solo tiene 200 USDC (los demás LPs retiraron)
    6. El trader recibe un payout parcial o nada
    7. Los LPs que retiraron evitaron la pérdida — socializada al trader y a los LPs que se quedaron
  invariante: |
    function check_lp_cannot_withdraw_during_active_options() internal view {
        uint256 activeOptionsPayout = getTotalActiveOptionMaxPayout();
        uint256 availableLiquidity = pool.totalBalance() - pool.lockedAmount();
        // La liquidez disponible para retiro no debe incluir fondos backing opciones activas
        t(availableLiquidity >= activeOptionsPayout,
          "OPT-019: LP withdrawal would undercollateralize active options");
    }
  que_mirar:
    - "¿La liquidez que respalda opciones activas está locked?"
    - "¿Los LPs pueden retirar en cualquier momento o hay un lockup?"
    - "¿El pool trackea cuánta liquidez está comprometida en opciones activas?"
    - "¿Qué pasa si un LP retira justo antes de un settlement grande?"
  como_se_arregla: |
    - Lock de liquidez: al comprar opciones, el pool locks la liquidez necesaria para el max payout
    - Los LPs solo pueden retirar la porción no-locked
    - Cooldown period: LP withdrawal request + 24h delay
  trampas:
    - "El lock de liquidez reduce la eficiencia de capital — balance entre seguridad y yield para LPs"
    - "En opciones de corta duración (5 min), un lockup de 24h puede ser excesivo para LPs"
  solodit_ids:
    - "h-2-design-of-bufferbinarypool-allows-lps-to-game-option-expiry-sherlock-buffer-finance-buffer-finance-git"
    - "h-02-bufferbinarypool-can-permanently-lock-funds-on-early-exercise-0x52-none-buffer-markdown"
  incidentes: []
  verificado: true
  confianza: 93

- id: opt-020
  titulo: Dopex — Timing de Bond Elude Premium de Opciones Perpetuas
  causa_raiz: |
    En protocolos con opciones perpetuas vinculadas a bonding (Dopex rDPX V2), el premium
    de las opciones se calcula en base al tiempo transcurrido desde la última actualización.
    Si un usuario puede llamar a bond() justo después de un funding payment (cuando el
    premium acumulado pendiente es cercano a 0), obtiene bonding a precio reducido
    porque el premium no refleja el costo real del riesgo asumido.
  como_funciona: |
    1. PerpetualAtlanticVault cobra premium periódicamente (e.g., cada epoch)
    2. Al inicio de un nuevo epoch, el premium acumulado pendiente = 0
    3. Atacante monitorea la blockchain y llama bond() en el primer bloque del nuevo epoch
    4. El premium cobrado es proporcional al tiempo desde el último pago (= ~0 segundos)
    5. Atacante obtiene bonding con opciones put casi gratuitas (premium ~0)
    6. Las opciones tienen valor real pero costaron casi nada → profit a costa del pool de LPs
  invariante: |
    function check_premium_reflects_risk(uint256 timeSinceLastPayment, uint256 premiumCharged) internal view {
        uint256 fullEpochPremium = calculateFullEpochPremium();
        uint256 expectedMinPremium = fullEpochPremium * MIN_PREMIUM_PCT / 100;
        t(premiumCharged >= expectedMinPremium,
          "OPT-020: premium too low — possible timing exploit");
    }
  que_mirar:
    - "¿El premium se calcula pro-rata al segundo o por epoch completo?"
    - "¿Hay un premium mínimo por bond, independiente del timing?"
    - "¿bond() puede llamarse en cualquier momento del epoch?"
    - "¿El premium pendiente se resetea a 0 en cada epoch?"
  como_se_arregla: |
    - Premium mínimo: require(premium >= MIN_PREMIUM_PER_BOND)
    - Calcular premium para el epoch completo, no pro-rata al segundo
    - Si es pro-rata: cobrar al menos 1 día de premium como floor
  trampas:
    - "Pro-rata es justo para usuarios honestos — el fix no debe penalizar a quien bondea a mitad de epoch"
    - "MEV bots pueden automatizar este timing exploit con precisión de bloque"
  solodit_ids:
    - "m-12-user-can-avoid-paying-high-premium-price-by-correctly-timing-his-bond-call-code4rena-dopex-dopex-git"
  incidentes: []
  verificado: true
  confianza: 91
