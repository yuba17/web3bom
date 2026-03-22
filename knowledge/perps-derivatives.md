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
