grep_targets:
  - "fundingRate"
  - "markPrice"
  - "indexPrice"
  - "openPosition"
  - "closePosition"
  - "liquidatePosition"
  - "unrealizedPnl"
  - "realizedPnl"
  - "openInterest"
  - "skewScale"
  - "maxLeverage"
  - "maintenanceMargin"
  - "positionSize"
  - "entryPrice"
  - "clearinghouse"
  - "GLP"
  - "IMX"

# Briefing: Perpetuals & Derivatives

## Contexto del dominio
Los protocolos de perpetuos (GMX, dYdX, Synthetix Perps v2/v3, Kwenta, Apex, Vertex, DYDX v4, Hyperliquid) permiten trading con apalancamiento sin fecha de vencimiento. Los bugs más peligrosos involucran:
- Manipulación del precio de entrada/salida (mark price vs index price)
- Errores en funding rate que drenan el protocol insurance fund
- Liquidaciones parciales mal contabilizadas
- PnL computation errors entre longs y shorts
- AMM-style LP pools que asumen riesgo de contraparte (GLP, SNX)

---

patterns:

- id: perp-001
  titulo: Mark Price Manipulation via Spot Oracle
  causa_raiz: |
    El mark price se calcula usando spot oracle (Chainlink/Pyth) sin TWAP suficiente,
    o combinado con el precio del pool de liquidez interno. Un atacante puede manipular
    el spot price brevemente para forzar liquidaciones o abrir posiciones a precios favorables.
  como_funciona: |
    1. Atacante flashloanea capital masivo
    2. Manipula el pool de liquidez subyacente (spot price sube/baja)
    3. El mark price del perp refleja el spot manipulado
    4. Con mark price manipulado: (a) liquida posiciones de otros usuarios, o
       (b) abre posición long/short al precio manipulado, cierra cuando normaliza
    5. Repaga flashloan, retiene ganancia
  invariante: |
    // Mark price no debe divergir >X% del precio de referencia (índice) en un solo bloque
    function check_markPrice_divergence() internal view {
        uint256 markPrice = getMarkPrice(market);
        uint256 indexPrice = getIndexPrice(market);
        // Si mark/index diverge >5%, liquidaciones deberían pausarse
        uint256 divergenceBps = markPrice > indexPrice
            ? ((markPrice - indexPrice) * 10000) / indexPrice
            : ((indexPrice - markPrice) * 10000) / indexPrice;
        t(divergenceBps <= 500, "P-001: mark price diverges >5% from index");
    }
  que_mirar:
    - "¿Mark price usa spot directo o TWAP?"
    - "¿Hay circuit breakers si mark diverge mucho del índice?"
    - "¿Liquidaciones usan mark price o index price?"
    - "¿El pool interno de liquidez puede afectar el mark price?"
  como_se_arregla: |
    - Usar TWAP de al menos 15 minutos para mark price
    - Añadir circuit breaker: si mark/index > 5%, pausar liquidaciones
    - Liquidar usando max(mark, index) para el trader, min(mark, index) para el protocol
  trampas:
    - "Chainlink puede devolverse por delay hasta 24h — stale price attacks son más fáciles en perps"
    - "Los protocolos L2-native (Hyperliquid) pueden tener su propia lógica de mark price off-chain"
  solodit_ids: [6854, 7129, 34847, 28321]

- id: perp-002
  titulo: Funding Rate Manipulation — Skew Amplification
  causa_raiz: |
    El funding rate se calcula sobre el OI skew (openInterest_long - openInterest_short).
    Si un atacante puede manipular temporalmente el skew, puede extraer funding payments
    del insurance fund o de traders en la dirección contraria.
  como_funciona: |
    1. Atacante abre posición masiva en una dirección (e.g., long) → skew positivo
    2. Funding rate sube (shorts pagan longs) — el atacante cobra funding
    3. En el mismo bloque o siguiente, cierra la posición antes de pagar el siguiente funding tick
    4. Net: cobró funding sin asumir riesgo de precio por suficiente tiempo
    Variante (skewScale bug): si skewScale es muy pequeño, incluso una posición pequeña
    produce funding rate del 100%+/day → drain masivo
  invariante: |
    function check_funding_rate_bounds() internal view {
        int256 fundingRate = getCurrentFundingRate(market);
        // Funding rate anualizado no debe exceder ±900% (75% mensual)
        int256 maxAnnualRate = 9 * 1e18; // 900%
        t(fundingRate >= -maxAnnualRate && fundingRate <= maxAnnualRate,
          "P-002: funding rate out of realistic bounds");
    }
  que_mirar:
    - "¿skewScale tiene un valor mínimo razonable para el mercado?"
    - "¿El funding se aplica per-block o hay un mecanismo anti-flash?"
    - "¿Hay caps en el funding rate máximo?"
    - "¿El insurance fund puede ser drenado por funding extremo?"
  como_se_arregla: |
    - Establecer maxFundingRate por mercado basado en volatilidad histórica
    - Aplicar funding con tiempo mínimo de acumulación antes de ser cobrable
    - skewScale debe calibrarse con el TVL del mercado, no ser configurable a 0
  trampas:
    - "Synthetix Perps v2 tuvo exactamente este bug: skewScale muy pequeño en mercados nuevos"
    - "Los protocolos con funding por bloque son más vulnerables que los que lo calculan cada hora"
  solodit_ids: [55033, 28716, 29031]

- id: perp-003
  titulo: PnL Drift — Long/Short Accounting Desync
  causa_raiz: |
    Los protocolos de perps deben mantener que: total_long_PnL + total_short_PnL = 0
    (zero-sum entre traders). Si hay rounding asimétrico, acumulación de fees en
    una sola parte, o errores en price impact, el protocol/LP pool asume pérdidas inesperadas.
  como_funciona: |
    1. En cada open/close/liquidation, el protocolo calcula PnL por posición
    2. Si PnL_long se calcula con precisión distinta a PnL_short (e.g., diferentes
       rounding directions en notional value), la suma no es cero
    3. Tras muchas operaciones, el LP pool (GLP, SNX) absorbe las diferencias
    4. Con suficiente volumen, el insurance fund se drena lentamente
  invariante: |
    // Ghost variables acumulados durante el fuzz
    int256 internal totalLongPnl;
    int256 internal totalShortPnl;

    function check_pnl_conservation() internal view {
        // Total PnL de traders debe ser absorbido por el LP pool (no crear/destruir valor)
        int256 combined = totalLongPnl + totalShortPnl;
        int256 tolerance = int256(ghost_numOperations * 1e6); // 1 USDC por operación
        t(combined >= -tolerance && combined <= tolerance,
          "P-003: PnL not zero-sum, LP pool leaking");
    }
  que_mirar:
    - "¿El cálculo de PnL usa la misma dirección de redondeo para longs y shorts?"
    - "¿Las fees se incluyen en el PnL calculation o son separadas?"
    - "¿Qué pasa con posiciones de size 0 después de liquidación parcial?"
    - "¿El notional value usa mark price o entry price?"
  como_se_arregla: |
    - Siempre redondear PnL a favor del protocol (floor para traders)
    - Separar fees del PnL tracking completamente
    - Invariant tests end-to-end: sum(user PnL) + protocol_fees = 0
  trampas:
    - "Los protocolos con múltiples tipos de colateral (multi-collateral perps) multiplican la complejidad"
    - "El PnL drift se vuelve explotable cuando se puede usar flashloan para abrir/cerrar en misma tx"
  solodit_ids: [6092, 34616, 27954, 64088]

- id: perp-004
  titulo: Liquidation Price Calculation Error
  causa_raiz: |
    El precio de liquidación se precalcula al abrir posición. Si hay factores
    que cambian el precio de liquidación sin actualizar el stored value (funding
    acumulado, fees, price impact del close), las liquidaciones ocurren a precios
    incorrectos o se omiten posiciones ya insolventes.
  como_funciona: |
    Variante A — Late liquidation:
    1. Se abre posición con liquidationPrice calculado
    2. Funding acumulado reduce el equity de la posición
    3. La posición debería ser liquidable, pero liquidationPrice almacenado no refleja el funding
    4. Keeper no puede liquidar → bad debt crece

    Variante B — Early liquidation:
    1. La fórmula de liquidationPrice no descuenta correctamente el price impact del close
    2. Position se liquida antes de tiempo → trader pierde fondos por error del protocolo
  invariante: |
    function check_liquidation_integrity() internal {
        for (uint i = 0; i < positions.length; i++) {
            (uint256 markPrice,) = getMarkPrice(positions[i].market);
            if (isLiquidatable(positions[i], markPrice)) {
                // Si es liquidable, equity debe ser < maintenanceMargin
                int256 equity = getEquity(positions[i], markPrice);
                int256 maintMargin = int256(positions[i].size * maintenanceMarginRate / 1e18);
                t(equity < maintMargin,
                  "P-004: position marked liquidatable but equity >= maintenance margin");
            }
        }
    }
  que_mirar:
    - "¿La fórmula de liquidationPrice incluye funding acumulado?"
    - "¿Liquidación parcial actualiza el liquidationPrice del remainder?"
    - "¿Hay un caso donde isLiquidatable() y getEquity() divergen?"
    - "¿El price impact del close se considera en el equity calculation?"
  como_se_arregla: |
    - Recalcular equity on-chain en el momento de la liquidación (no usar stored liquidationPrice)
    - Incluir funding acumulado no cobrado en el equity check
    - Para liquidación parcial, actualizar todos los campos derivados de la posición
  trampas:
    - "Las liquidaciones de perps a veces tienen un 'grace period' — un bug puede hacer que nunca se llame al keeper"
    - "Con leverage 50x, un error del 2% en el precio de liquidación equivale a liquidar a leverage 100x de facto"
  solodit_ids: [7049, 5911, 64241, 28903]

- id: perp-005
  titulo: Open Interest Cap Bypass via Partial Close/Reopen
  causa_raiz: |
    Los perps tienen maxOpenInterest por mercado para limitar el riesgo del LP pool.
    Si el check solo ocurre al abrir posición (no al aumentar), o si hay una
    ventana donde la OI se reduce y se puede volver a aumentar en la misma tx,
    se puede superar el cap.
  como_funciona: |
    1. OI está al 100% del cap
    2. Atacante cierra parcialmente su posición (OI baja)
    3. En la misma tx (o sandwich), abre una posición nueva más grande
    4. La ventana entre el reduce y el check permite superar el cap
    Variante: si el cap solo se verifica en increasePosition() pero no en
    una función de "modify collateral" que puede implícitamente cambiar el size
  invariante: |
    function check_oi_cap() internal view {
        for (uint i = 0; i < markets.length; i++) {
            uint256 longOI = getLongOpenInterest(markets[i]);
            uint256 shortOI = getShortOpenInterest(markets[i]);
            uint256 maxOI = getMaxOpenInterest(markets[i]);
            t(longOI <= maxOI, "P-005: long OI exceeds cap");
            t(shortOI <= maxOI, "P-005: short OI exceeds cap");
        }
    }
  que_mirar:
    - "¿El check de OI cap está en todas las funciones que modifican size?"
    - "¿Hay una función de 'rebalance' o 'migrate' que no pasa por el check?"
    - "¿El cap se verifica pre o post actualización del state?"
    - "¿Collateral deposits que cambian el leverage implícitamente cambian la OI?"
  como_se_arregla: |
    - Verificar OI cap DESPUÉS de toda actualización de estado
    - Incluir el check en withdrawCollateral si puede aumentar el leverage efectivo
    - Considerar OI total (long + short) como el límite, no solo por dirección
  trampas:
    - "Algunos protocolos tienen OI caps diferentes para long vs short — el cap menor es el binding"
    - "En mercados de opciones perpetuas, el OI equivalente puede estar implícito en el delta"
  solodit_ids: [35156, 8801, 63991]

- id: perp-006
  titulo: Fee Accounting Desync — Undercollateralized Insurance Fund
  causa_raiz: |
    Los fees de trading (opening fee, closing fee, liquidation fee, funding fee)
    se acumulan en un insurance fund o distribuyen a LPs. Si hay un path donde
    los fees se cobran pero no se acreditan al destino correcto (o viceversa —
    se acreditan pero no se cobran al trader), el fondo queda descapitalizado.
  como_funciona: |
    Variante A — Fee skip on self-liquidation:
    1. Posición llega a margen cero justo cuando se va a cobrar la liquidation fee
    2. Fee se "cobra" del colateral pero no se transfiere (colateral insuficiente)
    3. Insurance fund no recibe el fee pero se lo descuenta en el PnL accounting

    Variante B — Double counting en referral:
    1. Protocolo tiene sistema de referrals que devuelve parte del fee al referrer
    2. El fee se acredita al insurance fund Y al referrer sin reducir en insurance fund
    3. Después de muchas operaciones, insurance fund tiene menos tokens de los contabilizados
  invariante: |
    function check_insurance_fund_solvency() internal view {
        uint256 accountedBalance = getInsuranceFundAccounting();
        uint256 actualBalance = USDC.balanceOf(address(insuranceFund));
        // Tolerancia para rounding pero no para drain
        t(actualBalance >= accountedBalance - TOLERANCE,
          "P-006: insurance fund actual balance < accounting balance");
    }
  que_mirar:
    - "¿Qué pasa cuando closePosition tiene menos colateral que la fee de cierre?"
    - "¿El sistema de referrals descuenta correctamente del insurance fund?"
    - "¿Hay doble conteo de fees en liquidaciones (liquidation fee + closing fee)?"
    - "¿El rebate a LPs es correcto en términos de contabilidad doble entrada?"
  como_se_arregla: |
    - Siempre: fee = min(fee_accrued, available_collateral) — nunca cobrar más de lo disponible
    - Referral rebates deben reducirse ANTES de acreditar al insurance fund
    - Tests de invariant end-to-end: sum(all fees paid) == sum(all fees distributed)
  trampas:
    - "Muchos protocolos acumulan fees en USDC pero las distribuciones son en el token del protocolo — la conversión puede introducir error"
    - "El 'negative PnL' de un trade no es un fee — confundirlos en la contabilidad es un bug frecuente"
  solodit_ids: [29988, 3513, 6674, 63993]

- id: perp-007
  titulo: Positions Remaining Open After Protocol Pause — Bad Debt Accumulation
  causa_raiz: |
    Cuando el protocolo se pausa (por hack, blackswan, oracle failure), las
    posiciones apalancadas siguen acumulando PnL virtual. Al despausarse, las
    posiciones insolventes durante la pausa no pueden liquidarse retroactivamente,
    creando bad debt que el insurance fund debe absorber.
  como_funciona: |
    1. Protocolo se pausa — oracle se congela o se desconecta
    2. El activo subyacente cae 40% durante la pausa (e.g., LUNA style)
    3. Al despausar, hay 100 posiciones long 50x que están insolventes
    4. Cada liquidación genera bad debt porque el colateral < deuda
    5. Insurance fund se drena — otros LPs asumen la pérdida (socialization)
  invariante: |
    // Simulación: pausa el protocolo por N bloques y verifica que no hay bad debt al despausar
    function check_pause_bad_debt(uint256 priceAtPause, uint256 priceAtUnpause) internal {
        // Si el precio cae más del maxDrawdown configurado, deben haber liquidaciones
        if (priceAtUnpause < priceAtPause * (10000 - maxDrawdown) / 10000) {
            // Todas las posiciones long con leverage > 1/maxDrawdown deben ser liquidables
            t(getAllLiquidatablePositions().length > 0 || totalLongOI == 0,
              "P-007: price crash should create liquidatable positions");
        }
    }
  que_mirar:
    - "¿Hay un mecanismo de 'emergency liquidation' que funcione durante pausa?"
    - "¿El protocolo cierra automáticamente posiciones demasiado apalancadas al despausar?"
    - "¿Cuánto bad debt puede absorber el insurance fund?"
    - "¿Hay un maxDrawdown configurable que limite el leverage máximo efectivo?"
  como_se_arregla: |
    - ADL (Auto-Deleveraging): cerrar posiciones más apalancadas automáticamente en crisis
    - Cap de leverage basado en volatilidad histórica del activo
    - Insurance fund sizing: debe cubrir al menos el maxDrawdown * maxOI
  trampas:
    - "Los perps en activos de larga cola (low-cap tokens) son mucho más vulnerables a esto"
    - "ADL puede crear MEV: saber que vas a ser ADL'd permite front-run tu propio close"
  solodit_ids: [35422, 64741]

- id: perp-008
  titulo: Isolated vs Cross Margin Confusion — Wrong Collateral Used
  causa_raiz: |
    Protocolos que soportan tanto isolated margin (colateral por posición) como cross margin
    (colateral compartido entre posiciones) pueden confundir el tipo de margen al calcular
    el equity o al ejecutar liquidaciones. El resultado es liquidar usando el colateral de
    otra posición, o no liquidar cuando debería.
  como_funciona: |
    1. Usuario tiene: posición A (isolated, colateral = 100 USDC) + posición B (cross, colateral = 500 USDC)
    2. Posición A se vuelve insolvente (equity < maintenanceMargin)
    3. El liquidador llama a liquidate(posicionA)
    4. El protocolo calcula equity incluyendo el colateral cross de posición B (bug)
    5. La liquidación se bloquea aunque posición A es insolvente en isolated mode
    6. Bad debt se acumula hasta que el cross account también sea insolvente
  invariante: |
    function check_isolated_margin_isolation() internal view {
        // Para cada posición isolated, su equity no puede depender de otras posiciones
        for (uint i = 0; i < isolatedPositions.length; i++) {
            uint256 equity = getIsolatedEquity(isolatedPositions[i]);  // solo su colateral
            uint256 equityWithCross = getEquityWithCross(isolatedPositions[i]);  // incluye cross
            // Deben ser idénticos para posiciones isolated
            t(equity == equityWithCross || !positions[i].isIsolated,
              "P-008: isolated position equity contaminated by cross margin");
        }
    }
  que_mirar:
    - "¿La función de equity usa el accountId completo o el positionId específico?"
    - "¿Hay un mapping de colateral que mezcle isolated y cross en el mismo bucket?"
    - "¿La liquidación verifica el modo de margen antes de calcular?"
    - "¿Modificar una posición cross puede afectar una posición isolated del mismo usuario?"
  como_se_arregla: |
    - Separar completamente los storage buckets de isolated vs cross collateral
    - La función isLiquidatable() debe ser parametrizada por margin mode
    - Tests explícitos: usuario con posición isolated insolvente + posición cross solvente → liquidación debe ocurrir
  trampas:
    - "Los protocolos que migran de isolated-only a cross añaden este bug retroactivamente"
    - "La misma confusión aplica a portfolio margin en opciones perpetuas"
  solodit_ids: [64016, 28458, 6854]

- id: perp-009
  titulo: Price Impact Asymmetry — Market Manipulation via Size
  causa_raiz: |
    El price impact (slippage) en perps con AMM interno (Synthetix, GMX) debe ser
    simétrico: abrir long + cerrar long debería ser un juego de suma cero para el protocolo.
    Si la fórmula de price impact es asimétrica, se puede extraer valor del LP pool
    abriendo y cerrando posiciones repetidamente.
  como_funciona: |
    1. El protocolo cobra price impact al abrir posición (mark price sube por la presión)
    2. Al cerrar la misma posición, el mark price ya bajó de vuelta (impacto inverso)
    3. Si el cálculo de PnL usa el mark price manipulado (alto al cerrar vs bajo al abrir),
       el trader muestra ganancia aunque el precio del activo no cambió
    4. Repitiendo el ciclo, se drena lentamente el LP pool
    Requiere: fórmula donde price_impact_open ≠ price_impact_close para el mismo size
  invariante: |
    function check_price_impact_symmetry(uint256 size) internal {
        uint256 markBefore = getMarkPrice(market);
        // Abrir y cerrar inmediatamente la misma posición
        uint256 entryPrice = simulateOpen(size);
        uint256 exitPrice = simulateClose(size);
        // El precio debe volver al nivel original (tolerancia para fees)
        t(exitPrice >= markBefore * 99 / 100 && exitPrice <= markBefore * 101 / 100,
          "P-009: price impact not symmetric — LP pool drainable");
    }
  que_mirar:
    - "¿skewScale o similar parámetro afecta open y close por igual?"
    - "¿La fórmula de mark price tiene componentes que no se revierten al cerrar?"
    - "¿Hay una dirección preferida (long-biased o short-biased) en el price impact?"
    - "¿El price impact se calcula sobre el size total o el cambio de OI?"
  como_se_arregla: |
    - La fórmula de price impact debe ser función de OI skew — abre en la dirección del skew paga más
    - Abrir en la dirección contraria al skew debería recibir rebate (no pagar)
    - Tests: open + immediate close = net loss equal to 2x opening fee (no más)
  trampas:
    - "En protocolos con precio de liquidez (GLP/GNS), el price impact puede ser 0 para sizes pequeños pero masivo para sizes grandes — la no-linealidad crea oportunidades"
    - "Si el protocolo cambia skewScale via governance, los LPs actuales asumen el impacto"
  solodit_ids: [55033, 28716, 6092]

- id: perp-010
  titulo: Stale Funding Rate on Position Migration / Transfer
  causa_raiz: |
    Cuando una posición se migra (upgrade de contrato), se transfiere (NFT-based positions),
    o se toca por primera vez después de un período largo, el funding rate acumulado
    puede no aplicarse correctamente. El usuario evita pagar funding o el protocolo
    pierde el ingreso correspondiente.
  como_funciona: |
    Variante — Transfer sin settle:
    1. Protocolo usa NFTs para representar posiciones (Synthetix v3, Vertex)
    2. Alice tiene posición long con 30 días de funding no cobrado
    3. Alice transfiere el NFT a Bob
    4. Cuando Bob cierra la posición, solo paga el funding desde la transferencia
    5. El funding de los 30 días previos (owed by Alice) se pierde para el protocolo

    Variante — Upgrade migration:
    1. Protocolo hace upgrade de accounting contract
    2. Las posiciones tienen fundingAccruedPerUnit almacenado en el contrato viejo
    3. El nuevo contrato calcula el delta desde un timestamp equivocado
    4. Usuarios pierden/ganan funding que no les corresponde
  invariante: |
    function check_funding_settlement_on_transfer() internal {
        // Si una posición cambia de owner, el funding debe estar settled
        address previousOwner = lastOwner[tokenId];
        address currentOwner = positionNFT.ownerOf(tokenId);
        if (previousOwner != currentOwner) {
            // El fundingIndex debe haberse actualizado en el bloque del transfer
            t(positions[tokenId].lastFundingIndex == getCurrentFundingIndex(),
              "P-010: funding not settled on position transfer");
        }
    }
  que_mirar:
    - "¿La función de transferencia de posición llama a _settleFunding() antes?"
    - "¿El contrato de upgrade tiene lógica de migración de fundingAccruedPerUnit?"
    - "¿Hay un gap temporal entre la transferencia y el primer acces al funding del nuevo owner?"
    - "¿El funding de posiciones inactivas por >N días se acumula correctamente?"
  como_se_arregla: |
    - En beforeTransfer() del NFT: siempre llamar _settleFunding(tokenId)
    - Durante upgrades: migrar el fundingAccruedPerUnit acumulado con snapshot del timestamp
    - No permitir transferencia de posiciones con funding no cobrado > threshold
  trampas:
    - "Los protocolos que usan ERC721 para posiciones heredan este problema si no overridean transferFrom"
    - "Funding acumulado de posiciones liquidadas puede quedar 'zombie' en el contrato"
  solodit_ids: [3545, 5643, 63998]

- id: perp-011
  titulo: Malicious Keeper Price Manipulation on Delayed Order Execution
  causa_raiz: |
    Los protocolos con órdenes diferidas (delayed orders / intent-based) confían en keepers
    para ejecutar las órdenes con el precio oracle correspondiente al momento de creación.
    Si el keeper puede elegir CUÁNDO ejecutar (dentro de una ventana) o manipular qué precio
    oracle se usa, puede front-run al trader seleccionando el precio más desfavorable.
  como_funciona: |
    1. Trader crea orden delayed (e.g., open long) con precio oracle del bloque B
    2. El keeper tiene una ventana de N bloques para ejecutar la orden
    3. El keeper observa movimientos de precio: en bloque B+3 el precio cae
    4. Keeper ejecuta la orden en B+3 pero usando el precio de B+3 (peor para el trader)
       o selecciona un precio de un oracle commit que beneficia al keeper
    5. Variante Flatmoney: keeper manipula directamente el Pyth price update que submitea,
       eligiendo entre múltiples updates válidos el que maximiza su beneficio
  invariante: |
    function check_keeper_price_fairness() internal {
        // El precio de ejecución no debe divergir significativamente del precio al crear la orden
        uint256 orderCreationPrice = getOrderCreationPrice(orderId);
        uint256 executionPrice = getExecutionPrice(orderId);
        uint256 divergenceBps = executionPrice > orderCreationPrice
            ? ((executionPrice - orderCreationPrice) * 10000) / orderCreationPrice
            : ((orderCreationPrice - executionPrice) * 10000) / orderCreationPrice;
        t(divergenceBps <= 100, "P-011: execution price diverges >1% from creation price");
    }
  que_mirar:
    - "¿El keeper puede elegir qué oracle price update incluir en la tx de ejecución?"
    - "¿La ventana de ejecución es demasiado amplia (>5 bloques)?"
    - "¿El keeper recibe recompensa variable según el resultado del trade?"
    - "¿Hay validación de que el precio oracle usado es el más cercano al timestamp de creación?"
  como_se_arregla: |
    - Vincular el precio de ejecución al bloque exacto de creación de la orden (no al de ejecución)
    - Si usa Pyth, exigir que el price update tenga timestamp dentro de ±1 bloque del request
    - Eliminar incentivos para que el keeper se beneficie del resultado del trade
  trampas:
    - "En Flatmoney, los keepers podían submitear cualquier Pyth price update válido — eligiendo el más favorable"
    - "Los protocolos en L2 con bloques de 2s tienen ventanas de manipulación más pequeñas pero no nulas"
  solodit_ids:
    - h-6-malicious-keepers-can-manipulate-the-price-when-executing-an-order-sherlock-flatmoney-git
    - m-31-keeper-can-make-depositsorderswithdrawals-fail-and-receive-feerewards-sherlock-none-gmx-git
  incidentes: []
  verificado: true
  confianza: 92

- id: perp-012
  titulo: Riskless Trades via Delay Check Bypass + Tight Stop-Loss
  causa_raiz: |
    Los protocolos con órdenes diferidas implementan un delay mínimo entre la creación y
    ejecución para prevenir front-running del oracle. Si este delay se puede bypasear
    (por L2 block.number quirks, o es demasiado corto), el trader puede abrir posiciones
    apalancadas con stop-loss muy ajustado, creando trades efectivamente sin riesgo:
    gana si el precio se mueve a su favor, pierde solo el fee si se mueve en contra.
  como_funciona: |
    1. Trader ve el precio futuro (mempool, L2 sequencer, oracle commit pending)
    2. Abre posición 100x long con stop-loss a 0.5% debajo del precio de entrada
    3. Si el precio sube: ganancia = 100x * subida — beneficio masivo
    4. Si el precio baja: stop-loss limita la pérdida al fee de apertura + 0.5% * size
    5. El ratio riesgo/recompensa está completamente a favor del atacante
    6. Variante: en Arbitrum/Optimism, block.number no refleja bloques L2 reales,
       haciendo que _checkDelay() sea inefectivo
  invariante: |
    function check_no_riskless_trades(uint256 entryPrice, uint256 stopLossPrice) internal {
        // Stop-loss no puede estar a menos de X% del precio de entrada
        uint256 minStopDistance = entryPrice * minStopLossDistanceBps / 10000;
        if (position.isLong) {
            t(entryPrice - stopLossPrice >= minStopDistance,
              "P-012: stop-loss too tight — enables riskless trades");
        }
    }
  que_mirar:
    - "¿El delay check usa block.number o block.timestamp? ¿Funciona en L2?"
    - "¿Hay un mínimo de distancia entre entry price y stop-loss?"
    - "¿Se puede crear y ejecutar una orden en el mismo bloque?"
    - "¿El protocolo cobra fee proporcional al leverage para desincentivar este patrón?"
  como_se_arregla: |
    - Usar block.timestamp en vez de block.number para delays (compatible con L2)
    - Imponer distancia mínima entre entry y stop-loss proporcional al leverage
    - Cobrar fee proporcional al notional (size * leverage), no solo al colateral
  trampas:
    - "En Arbitrum, block.number devuelve el bloque L1 — el delay puede ser de horas en vez de segundos"
    - "Tigris Trade tuvo exactamente este bug: delay check bypasseable + stop-loss a 0"
  solodit_ids:
    - h-10-user-can-abuse-tight-stop-losses-and-high-leverage-to-make-risk-free-trades-code4rena-tigris-trade-tigris-trade-contest-git
    - h-02-riskless-trades-due-to-delay-check-code4rena-tigris-trade-tigris-trade-contest-git
    - m-15-_checkdelay-will-not-work-properly-for-arbitrum-or-optimism-due-to-blocknumber-code4rena-tigris-trade-tigris-trade-contest-git
    - m-03-bypass-the-delay-security-check-to-win-risk-free-funds-code4rena-tigris-trade-tigris-trade-contest-git
  incidentes: []
  verificado: true
  confianza: 95

- id: perp-013
  titulo: Leverage Calculation Error on Position Size Increase
  causa_raiz: |
    Cuando un trader aumenta el tamaño de una posición existente, el nuevo leverage
    debe recalcularse considerando el colateral existente, PnL no realizado, y el
    nuevo size total. Si la fórmula calcula el leverage solo sobre el delta (no el total),
    o ignora el PnL acumulado, el usuario puede superar el leverage máximo permitido
    o robar fondos del protocolo.
  como_funciona: |
    Variante A — Leverage bypass (GainsNetwork):
    1. Trader tiene posición con 10x leverage, PnL = +50% del colateral
    2. Solicita aumentar size — el protocolo calcula leverage nuevo solo sobre el delta
    3. El leverage efectivo total excede el máximo permitido (e.g., 150x real vs 100x max)
    4. Si el precio se mueve en contra, la pérdida excede el colateral → bad debt

    Variante B — Theft via leverage update (GainsNetwork Critical):
    1. Trader abre posición y acumula beneficio
    2. Solicita "decrease" de tamaño via leverage update
    3. Error en cálculo: el protocolo envía más colateral del que debería al trader
    4. Pérdida neta para el vault / diamond contract
  invariante: |
    function check_leverage_bounds(bytes32 positionId) internal view {
        Position memory pos = getPosition(positionId);
        uint256 effectiveLeverage = (pos.size * 1e18) / pos.collateral;
        t(effectiveLeverage <= maxLeverage * 1e18,
          "P-013: effective leverage exceeds maximum");
        t(effectiveLeverage >= 1e18,
          "P-013: leverage below minimum (1x)");
    }
  que_mirar:
    - "¿La función increasePositionSize recalcula leverage sobre el total o solo el delta?"
    - "¿El PnL no realizado se incluye en el equity para el cálculo de leverage?"
    - "¿Se puede modificar leverage sin pasar por el check de maxLeverage?"
    - "¿Hay una función de 'update leverage' separada de 'increase/decrease size'?"
  como_se_arregla: |
    - Calcular leverage SIEMPRE como: (totalSize * entryPrice) / totalCollateral
    - Incluir unrealizedPnL en el cálculo del collateral efectivo
    - Validar leverage máximo DESPUÉS de cualquier modificación (no antes)
  trampas:
    - "Las funciones de 'update leverage' pueden ser un backdoor para bypass — no es lo mismo que increase/decrease size"
    - "El PnL no realizado puede ser negativo — incluirlo incorrectamente invierte la dirección del leverage"
  solodit_ids:
    - h-02-newleverage-wrongly-calculated-inside-requestincreasepositionsize-pashov-audit-group-none-gainsnetwork-may-markdown
    - c-01-decreasing-position-size-via-leverage-update-can-be-abused-to-steal-from-diamond-pashov-audit-group-none-gainsnetwork-may-markdown
    - m-04-wrong-rounding-direction-when-calculating-leverage-delta-for-counter-trades-pashov-audit-group-none-gainsnetwork_2025-05-26-markdown
  incidentes: []
  verificado: true
  confianza: 95

- id: perp-014
  titulo: ADL (Auto-Deleveraging) Factor Calculation Error
  causa_raiz: |
    El Auto-Deleveraging cierra posiciones ganadoras cuando el protocolo no puede pagar
    las ganancias (insurance fund agotado). El factor de ADL determina cuánto se reduce
    cada posición. Si se calcula incorrectamente (e.g., usar el ratio equivocado entre
    profit/OI, o no actualizar tras cambios de precio), las posiciones se cierran
    de más o de menos, causando pérdidas injustas o dejando el protocolo insolvente.
  como_funciona: |
    1. El mercado se mueve fuertemente en una dirección (e.g., shorts ganan masivamente)
    2. El insurance fund no puede cubrir las ganancias de los shorts
    3. Se activa ADL: el protocolo debe cerrar posiciones ganadoras proporcionalmente
    4. Si el autoDeleverageFactor se calcula mal (Zaros bug):
       - Factor demasiado alto: cierra más de lo necesario → traders ganan menos de lo justo
       - Factor demasiado bajo: no cierra suficiente → protocolo sigue insolvente
    5. Error típico: usar unrealizedPnL pre-fee en vez de post-fee, o no considerar
       las posiciones que ya fueron liquidadas
  invariante: |
    function check_adl_factor_correctness() internal view {
        uint256 adlFactor = getAutoDeleverageFactor(market);
        // ADL factor debe estar entre 0 y 1e18 (0% a 100%)
        t(adlFactor <= 1e18, "P-014: ADL factor exceeds 100%");
        // Si hay fondos suficientes, ADL factor debe ser 0
        if (getInsuranceFundBalance(market) >= getTotalUnrealizedProfit(market)) {
            t(adlFactor == 0, "P-014: ADL active when insurance fund is sufficient");
        }
    }
  que_mirar:
    - "¿El ADL factor se recalcula en cada liquidación o se cachea?"
    - "¿Las posiciones ya cerradas/liquidadas se excluyen del cálculo de OI para ADL?"
    - "¿El factor usa PnL bruto o neto de fees?"
    - "¿Hay un mecanismo de prioridad (más apalancadas primero)?"
  como_se_arregla: |
    - Recalcular ADL factor dinámicamente en cada ejecución, no cachear
    - Usar PnL post-fees y post-funding para el cálculo
    - Priorizar cierre de posiciones por leverage ratio (más apalancadas primero)
    - Test: tras ADL, el insurance fund debe poder cubrir el remaining PnL
  trampas:
    - "Zaros tuvo un bug donde el AutoDeleverageFactor se calculaba incorrectamente, dejando el protocolo insolvente"
    - "ADL puede crear un 'bank run': traders intentan cerrar antes de ser ADL'd, amplificando la crisis"
  solodit_ids:
    - incorrect-autodeleveragefactor-codehawks-zaros-part-2-git
    - the-protocol-is-insolvent-codehawks-zaros-part-2-git
  incidentes: []
  verificado: true
  confianza: 88

- id: perp-015
  titulo: Collateral Withdrawal Despite Pending Unrealized Profit — Liquidation Evasion
  causa_raiz: |
    Cuando un trader tiene una posición con profit no realizado, algunos protocolos permiten
    retirar colateral considerando el profit como equity. Si luego el precio se revierte,
    la posición queda sin colateral suficiente para cubrir la liquidación, generando bad debt
    que el protocolo/LPs deben absorber.
  como_funciona: |
    1. Trader abre posición long con 100 USDC de colateral
    2. Precio sube → posición muestra +200 USDC de profit no realizado
    3. Equity total = 300 USDC (colateral + unrealized PnL)
    4. Trader retira 250 USDC de colateral (protocolo lo permite porque equity > maintenanceMargin)
    5. Colateral real restante = 50 USDC (equity teórica = 50 + 200 unrealized = 250)
    6. Precio se revierte a nivel original → unrealized PnL = 0, equity = 50 USDC
    7. Si ahora el precio baja más, la posición genera bad debt con solo 50 USDC de colateral
  invariante: |
    function check_collateral_vs_unrealized_pnl() internal view {
        for (uint i = 0; i < positions.length; i++) {
            int256 unrealizedPnl = getUnrealizedPnl(positions[i]);
            uint256 collateral = getCollateral(positions[i]);
            // El colateral real NUNCA debe ser menor que initialMargin requerido
            // independientemente del unrealized PnL
            t(collateral >= getInitialMarginRequired(positions[i]),
              "P-015: collateral below initial margin, relying on unrealized PnL");
        }
    }
  que_mirar:
    - "¿La función withdrawCollateral descuenta unrealized PnL del equity disponible?"
    - "¿Hay un mínimo de colateral real (no virtual) que no se puede retirar?"
    - "¿El protocolo distingue entre realized y unrealized PnL para withdrawals?"
    - "¿Las pending fees (intent orders) se descuentan del collateral disponible?"
  como_se_arregla: |
    - No permitir retirar colateral si el remaining es menor al initialMargin requerido
    - Alternativamente: solo permitir retirar realized PnL, no unrealized
    - Incluir pending fees de intent orders en el cálculo de collateral disponible
  trampas:
    - "Zaros tuvo este bug: usuarios podían retirar todo el colateral cuando la posición tenía profit"
    - "Perennial V2: intent orders con fees pendientes no se descontaban del collateral, permitiendo withdraw total"
  solodit_ids:
    - user-can-withdraw-all-collateral-when-a-position-has-enough-profit-so-if-liquidated-no-collateral-can-be-deducted-codehawks-zaros-git
    - h-3-intent-orders-are-guaranteed-to-execute-but-fees-from-these-orders-are-not-accounted-in-collateral-allowing-user-to-withdraw-all-collateral-ignoring-these-pending-fees-sherlock-perennial-v2-update-4-git
  incidentes: []
  verificado: true
  confianza: 93

- id: perp-016
  titulo: Open Interest Double Counting on Limit Order Execution
  causa_raiz: |
    Cuando una orden limitada se ejecuta, el open interest (OI) se actualiza. Si la OI
    ya fue incrementada al crear la orden (como "reserva") y se incrementa de nuevo al
    ejecutarla, hay double-counting. Esto infla artificialmente la OI, afecta el funding
    rate, y puede bloquear nuevas posiciones si alcanza el cap.
  como_funciona: |
    1. Trader crea limit order para abrir long de 10 ETH
    2. El protocolo incrementa longOI += 10 ETH al crear la orden (reserva)
    3. Cuando el precio alcanza el límite, keeper ejecuta la orden
    4. La función de ejecución incrementa longOI += 10 ETH OTRA VEZ (bug)
    5. Resultado: longOI está inflada en 10 ETH extra
    6. Efecto cascada: funding rate se calcula sobre OI inflada → shorts pagan de más
    7. Variante: al cancelar la orden, solo se descuenta una vez → OI permanece inflada
  invariante: |
    function check_oi_consistency() internal view {
        uint256 sumPositionSizes = 0;
        for (uint i = 0; i < longPositions.length; i++) {
            sumPositionSizes += longPositions[i].size;
        }
        // La suma de position sizes debe igualar el OI reportado
        t(sumPositionSizes == getLongOpenInterest(market),
          "P-016: OI does not match sum of position sizes — double counting");
    }
  que_mirar:
    - "¿La OI se incrementa al crear la orden, al ejecutarla, o en ambas?"
    - "¿Al cancelar una orden pendiente, se revierte correctamente la OI reservada?"
    - "¿Las limit orders y market orders usan el mismo path de actualización de OI?"
    - "¿executeLimitOrder usa el size de la orden o recalcula el size al precio de ejecución?"
  como_se_arregla: |
    - Incrementar OI solo en un punto: preferiblemente al ejecutar la orden (no al crear)
    - Si se reserva OI al crear, la ejecución no debe incrementar de nuevo
    - Invariant test: sum(all_position_sizes) == reported_OI at all times
  trampas:
    - "Tigris Trade tuvo exactamente este bug en executeLimitOrder — OI inflada incorrectamente"
    - "GainsNetwork tuvo double counting al contar OI existente + OI nueva en la misma operación"
  solodit_ids:
    - m-21-executelimitorder-modifies-open-interest-with-a-wrong-position-value-code4rena-tigris-trade-tigris-trade-contest-git
    - m-02-double-counting-of-existing-open-interest-pashov-audit-group-none-gainsnetwork-may-markdown
  incidentes: []
  verificado: true
  confianza: 90

- id: perp-017
  titulo: Keeper Execution Fee Theft via EIP-150 63/64 Gas Rule
  causa_raiz: |
    Los keepers reciben una compensación por gas al ejecutar órdenes. Si la función
    payExecutionFee() usa la regla address.call{value: fee}() sin considerar que
    EIP-150 solo forwarda 63/64 del gas disponible, el keeper puede manipular el gas
    restante para recibir más fee del debido, o hacer que la ejecución falle reteniendo el fee.
  como_funciona: |
    1. Keeper ejecuta una orden con gas preciso para que la ejecución interna consuma
       casi todo el gas disponible
    2. Al llegar a payExecutionFee(), queda poco gas
    3. EIP-150: la call interna solo recibe 63/64 del gas restante
    4. Si la call falla (out of gas), el fee no se devuelve pero la orden sí se ejecutó
    5. Variante (GMX V2): keeper hace que la ejecución falle deliberadamente pero cobra
       el fee + rewards de todos modos (el error handling no revierte el pago)
  invariante: |
    function check_keeper_fee_fairness() internal {
        uint256 feesPaidToKeeper = ghost_totalKeeperFees;
        uint256 actualGasCost = ghost_totalKeeperGasCost;
        // Keepers no deben ganar más de 2x su costo real de gas
        t(feesPaidToKeeper <= actualGasCost * 2,
          "P-017: keeper fees exceed 2x actual gas cost");
    }
  que_mirar:
    - "¿payExecutionFee verifica que la call de pago fue exitosa?"
    - "¿El keeper puede hacer que la ejecución falle pero aún cobrar el fee?"
    - "¿Hay gas buffer suficiente para cubrir el 1/64 retenido por EIP-150?"
    - "¿El error handling del protocolo revierte TODA la tx si falla el pago?"
  como_se_arregla: |
    - Agregar gas buffer de al menos 100K gas antes de llamar payExecutionFee
    - Verificar success de la call y revertir si falla
    - En L2: incluir compensación por L1 rollup fees (calldata cost)
  trampas:
    - "En L2 (Arbitrum), el costo real incluye L1 calldata fees que no se reflejan en gasleft()"
    - "Elfi tuvo este bug: keepers robaban execution fee extra explotando EIP-150"
    - "GMX V2: keepers cobraban fee+rewards incluso cuando la orden fallaba"
  solodit_ids:
    - m-9-the-implementation-of-payexecutionfee-didnt-take-eip-150-into-consideration-keepers-can-steal-additional-execution-fee-from-users-sherlock-elfi-git
    - m-31-keeper-can-make-depositsorderswithdrawals-fail-and-receive-feerewards-sherlock-none-gmx-git
    - m-17-a-significant-105983-gas-cost-of-processexecutionfee-execution-is-not-accounted-in-the-keepers-compensation-sherlock-elfi-git
    - m-15-the-keeper-will-suffer-continuing-losses-due-to-miss-compensation-for-l1-rollup-fees-sherlock-elfi-git
  incidentes: []
  verificado: true
  confianza: 93

- id: perp-018
  titulo: Liquidation Blocked by Insufficient Incentive for Small/Dust Positions
  causa_raiz: |
    Las posiciones muy pequeñas (dust) no generan suficiente liquidation fee para cubrir
    el gas del keeper, haciendo que nadie tenga incentivo económico para liquidarlas.
    Estas posiciones pueden acumular bad debt indefinidamente, drenando el insurance fund
    o causando insolvencia del protocolo.
  como_funciona: |
    1. Trader abre muchas posiciones mínimas (e.g., 1 USDC de colateral cada una)
    2. El precio se mueve en contra → las posiciones son liquidables
    3. Liquidation fee por posición = ~0.1 USDC (1% de 10 USDC notional)
    4. Gas cost para liquidar en mainnet = ~5 USDC
    5. Nadie liquida → las posiciones acumulan bad debt
    6. Si hay suficientes dust positions, el bad debt agregado puede ser significativo
    7. Variante: después de partial liquidation, el remainder puede quedar como dust
  invariante: |
    function check_min_position_size() internal view {
        for (uint i = 0; i < positions.length; i++) {
            uint256 notional = positions[i].size * getMarkPrice(positions[i].market) / 1e18;
            t(notional >= minPositionSize,
              "P-018: position below minimum size — unliquidatable dust");
        }
    }
  que_mirar:
    - "¿Hay un tamaño mínimo de posición que cubra al menos 2x el costo de liquidación?"
    - "¿La liquidación parcial puede dejar un remainder menor al mínimo?"
    - "¿Las dust positions de un mismo usuario se pueden agregar y liquidar juntas?"
    - "¿El protocolo tiene un mecanismo de liquidación batch para reducir gas por posición?"
  como_se_arregla: |
    - Imponer minPositionSize que garantice liquidation fee > gas cost
    - Si partial liquidation deja remainder < minSize, cerrar toda la posición
    - Implementar batch liquidation para reducir gas por posición
    - Considerar liquidation fee fija mínima (no solo porcentual)
  trampas:
    - "Los protocolos en L2 tienen gas más barato pero aún hay un mínimo viable"
    - "El gas cost varía — en periodos de congestión, el mínimo efectivo sube y posiciones antes liquidables dejan de serlo"
  solodit_ids:
    - lack-of-incentives-to-liquidate-small-positions-openzeppelin-none-euler-vault-kit-evk-audit-markdown
    - m-05-no-incentive-to-liquidate-small-positions-could-result-in-protocol-going-underwater-code4rena-dyad-dyad-git
    - m-05-the-protocol-allows-borrowing-small-positions-that-can-create-bad-debt-code4rena-wise-lending-wise-lending-git
    - m-15-loss-for-protocol-by-incorrectly-assuming-the-position-has-been-fully-closed-code4rena-gte-gte-git
  incidentes: []
  verificado: true
  confianza: 90

- id: perp-019
  titulo: Margin Calculation Ignores Mark Price Impact — Under-Margined Positions
  causa_raiz: |
    Al abrir o modificar una posición, el margin requirement se calcula usando el mark price
    actual. Sin embargo, la propia operación de abrir la posición genera price impact
    (el mark price sube para longs, baja para shorts). Si el margin check usa el precio
    PRE-impact, la posición está under-margined desde el momento de apertura.
  como_funciona: |
    1. Trader abre long de 1000 ETH a mark price = $2000
    2. Margin check: requiere 1000 * 2000 / maxLeverage = $200,000 de colateral
    3. La orden se ejecuta con price impact: mark price sube a $2050 por el size
    4. El notional real es 1000 * 2050 = $2,050,000 — el margin debería ser $205,000
    5. La posición está under-margined en $5,000 desde el primer bloque
    6. Efecto: si el precio baja mínimamente, la posición genera bad debt
  invariante: |
    function check_margin_post_impact() internal view {
        for (uint i = 0; i < positions.length; i++) {
            uint256 postImpactPrice = simulatePriceImpact(positions[i].size, positions[i].isLong);
            uint256 requiredMargin = positions[i].size * postImpactPrice / maxLeverage;
            t(positions[i].collateral >= requiredMargin,
              "P-019: position under-margined after price impact");
        }
    }
  que_mirar:
    - "¿El margin check se ejecuta antes o después de calcular el price impact?"
    - "¿fillOrder usa mark price pre o post impact para el margin requirement?"
    - "¿Hay un 'margin buffer' adicional que cubra el price impact esperado?"
    - "¿El mismo issue aplica a increasePositionSize (la posición ya existe + delta)?"
  como_se_arregla: |
    - Calcular margin requirement usando el precio POST-impact (no pre-impact)
    - Añadir un margin buffer proporcional al price impact esperado
    - Verificar margin DESPUÉS de actualizar el estado (no antes)
  trampas:
    - "Zaros tuvo este bug en fillOrder: margin calculado sin considerar mark price impact"
    - "El price impact puede ser no-lineal — para sizes grandes, el under-margining es exponencialmente peor"
  solodit_ids:
    - margin-calculation-in-fillorder-does-not-consider-mark-price-impact-codehawks-zaros-git
    - sev-5-the-getaccountmarginrequirementusdandunrealizedpnlusd-function-returns-incorrect-margin-requirement-values-when-a-position-is-being-changed-codehawks-zaros-git
  incidentes: []
  verificado: true
  confianza: 91

- id: perp-020
  titulo: Fee Vault Drain via Misconfigured Fee Tiers or Referral Abuse
  causa_raiz: |
    Los protocolos de perps con fee tiers (descuentos por volumen), referral rebates,
    o fee redistribution a NFT holders pueden ser drenados si la configuración de fees
    permite que el total de descuentos + rebates + distribuciones exceda el fee cobrado.
    Especialmente peligroso cuando múltiples mecanismos de descuento se aplican aditivamente.
  como_funciona: |
    Variante A — Fee configuration drain (Tigris):
    1. Opening fee = 0.1%, closing fee = 0.1%, referral rebate = 50%, NFT distribution = 60%
    2. Total outflow = 50% + 60% = 110% del fee cobrado
    3. Cada trade drena 10% del fee del vault
    4. Con suficiente volumen, el vault se vacía completamente

    Variante B — Overcharging trigger fees (GainsNetwork):
    1. El protocolo cobra closing fee + trigger fee (stop-loss/take-profit)
    2. En ciertos paths, ambos fees se cobran dos veces por la misma operación
    3. El trader paga el doble y el exceso queda en un estado inconsistente

    Variante C — Fee tier manipulation:
    1. Protocolo no actualiza fee tier points durante ciertas operaciones
    2. Trader acumula volumen sin que se actualice su tier
    3. Cuando se actualiza, salta varios tiers de golpe obteniendo descuento retroactivo
  invariante: |
    function check_fee_distribution_solvency() internal view {
        // La suma de todas las distribuciones de fees no puede exceder el fee cobrado
        uint256 totalFeeCollected = ghost_totalFeesCollected;
        uint256 totalFeeDistributed = ghost_referralRebates + ghost_nftDistribution
            + ghost_lpFees + ghost_insuranceFees;
        t(totalFeeDistributed <= totalFeeCollected,
          "P-020: fee distributions exceed collected fees — vault draining");
    }
  que_mirar:
    - "¿Los porcentajes de referral + NFT + LP + insurance suman ≤100%?"
    - "¿Hay paths donde se cobran fees dobles (closing + trigger)?"
    - "¿Fee tiers se actualizan atómicamente con cada trade?"
    - "¿Puede un admin misconfigurarse los fees para que la suma exceda 100%?"
  como_se_arregla: |
    - Validar en el setter que referral% + nft% + lp% + insurance% <= 100%
    - Para trigger fees: cobrar MAX(closingFee, triggerFee), no la suma
    - Actualizar fee tier points atómicamente en cada operación
    - Test: vault balance post-trade >= vault balance pre-trade - max_possible_pnl
  trampas:
    - "Tigris Trade fue drenado por fee misconfiguration que permitía que las distribuciones excedieran el 100%"
    - "Los referral systems son un vector subestimado — el referrer puede ser el mismo trader (self-referral)"
  solodit_ids:
    - h-03-certain-fee-configuration-enables-vaults-to-be-drained-code4rena-tigris-trade-tigris-trade-contest-git
    - h-03-overcharging-of-closing-and-trigger-fees-pashov-audit-group-none-gainsnetwork-may-markdown
    - l-05-updatefeetierpoints-is-not-properly-called-during-several-operations-pashov-audit-group-none-gainsnetwork_2025-05-26-markdown
