grep_targets:
  - "resolve"
  - "outcome"
  - "conditionalToken"
  - "prediction"
  - "oracle"
  - "dispute"
  - "bond"
  - "redeem"
  - "splitPosition"
  - "mergePositions"
  - "reportOutcome"
  - "claimWinnings"
  - "marketClose"
  - "parimutuel"
  - "LMSR"
  - "CPMM"
  - "questionId"
  - "conditionId"
  - "negRisk"
  - "CTF"
  - "epoch"
  - "depeg"
  - "betAmount"
  - "wager"
  - "binaryOption"
  - "strikePrice"

# Briefing: Prediction Markets, Binary Options & Outcome-Based Protocols

## Contexto del dominio
Los mercados de prediccion on-chain (Polymarket, Augur, Gnosis CTF, Myriad) y protocolos
de opciones binarias / outcomes (Thales, Azuro, Y2K Finance, Overtime Markets, Xyro, PlotX)
tienen vulnerabilidades especificas en:
- Resolucion de mercados (oracle manipulation, dispute gaming, front-running de resolucion)
- Token accounting (minting/burning de outcome tokens, ERC-1155 conditional tokens, rounding)
- Market maker math (LMSR, CPMM, AMM de probabilidades)
- Timing exploits (last-second bets, stale prices en resolucion, epoch boundaries)
- Dispute/challenge systems (bond escalation, governance flash loans)
- Parimutuel pools (dilution, late entry, withdrawal timing)
- Cross-market arbitrage (probabilidades inconsistentes entre mercados correlacionados)

Protocolos relevantes:
- **Polymarket**: mercados de prediccion con CTF (Conditional Token Framework) + NegRisk adapter
- **Augur v1/v2**: dispute resolution system con REP token staking
- **Gnosis CTF**: ERC-1155 conditional tokens, splitPosition/mergePositions
- **UMA Optimistic Oracle**: dispute bonds con escalation exponencial
- **Thales / Overtime Markets**: opciones binarias en Optimism, mercados deportivos
- **Azuro**: apuestas deportivas con liquidity pools
- **Y2K Finance**: prediccion de depeg (insurance-adjacent) en Arbitrum
- **Xyro**: juegos up/down con oracles de precio
- **PlotX**: mercados de prediccion en Ethereum/Polygon
- **Reality.eth**: oracle de resolucion crowd-sourced para prediction markets
- **UBET**: funding pools con ERC-1155 para mercados de prediccion
- **Abster/FreeFall**: juegos de prediccion con multiplier packages

---

patterns:

- id: pm-001
  titulo: Resolution Oracle Manipulation — Influir en el Oracle para Ganar Apuestas
  causa_raiz: |
    El mercado de prediccion depende de un oracle externo (Chainlink, UMA, Reality.eth,
    un multisig, o un EOA) para resolver el outcome. Si el oracle puede ser manipulado
    (front-running del update, bribery del reporter, o uso de spot price manipulable),
    un atacante puede forzar una resolucion incorrecta y cobrar apuestas que deberia
    haber perdido. Es el equivalente a "oracle manipulation" pero aplicado a outcomes
    binarios donde el impacto es 100% (ganas todo o pierdes todo).
  como_funciona: |
    Escenario A — Precio spot en el bloque de resolucion:
    1. Mercado: "ETH > $2000 el 15 de marzo a las 00:00 UTC?"
    2. El precio real a las 00:00 UTC es $1995 (NO deberia resolver como YES)
    3. Atacante tiene posicion YES grande
    4. En el bloque de resolucion, atacante usa flash loan para comprar ETH masivamente
    5. sqrtPriceX96 / getReserves() sube a $2010 momentaneamente
    6. La funcion resolve() lee spot price → resuelve como YES
    7. Atacante cobra winnings, deshace el swap, paga flash loan, profit neto

    Escenario B — Oracle crowd-sourced (Reality.eth):
    1. Cualquiera puede proponer una respuesta depositando un bond
    2. Si nadie la disputa en X tiempo, se acepta como verdadera
    3. Atacante propone respuesta incorrecta con bond minimo
    4. Si el mercado es pequeno, nadie tiene incentivo economico para disputar
    5. La respuesta incorrecta se acepta → atacante gana
  invariante: |
    function check_resolution_oracle_integrity(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        if (m.resolved) {
            // El precio de resolucion debe estar dentro del rango de TWAP
            uint256 twapPrice = getTWAP(m.resolutionAsset, 3600);
            uint256 resolutionPrice = m.resolutionPrice;
            uint256 divergence = resolutionPrice > twapPrice
                ? ((resolutionPrice - twapPrice) * 10000) / twapPrice
                : ((twapPrice - resolutionPrice) * 10000) / twapPrice;
            t(divergence <= 200, "PM-001: resolution price diverges >2% from TWAP");
        }
    }
  que_mirar:
    - "Que oracle usa la funcion resolve()? Spot price, TWAP, Chainlink, crowd-sourced?"
    - "Puede cualquiera llamar a resolve() o solo un keeper/oracle autorizado?"
    - "Hay un periodo de dispute despues de la resolucion propuesta?"
    - "El oracle tiene staleness check? Un precio de hace 24h podria resolver un mercado incorrectamente"
    - "Se usa block.timestamp o block.number como referencia para el momento de resolucion?"
  como_se_arregla: |
    - Usar TWAP de minimo 30 minutos para mercados basados en precio
    - Implementar periodo de dispute obligatorio (24-48h) antes de finalizar resolucion
    - Para oracles crowd-sourced: escalation de bonds (Reality.eth/UMA style) con minimo significativo
    - Multiples fuentes de oracle con mediana (no promedio, resistente a outliers)
    - No permitir que la misma entidad proponga respuesta y tenga posicion en el mercado
  trampas:
    - "Chainlink no es manipulable por flash loan — pero SI puede estar stale o reportar precios de hace horas"
    - "UMA tiene bond escalation que hace el ataque exponencialmente caro — pero mercados pequenos pueden no tener suficiente incentivo para disputar"
    - "Reality.eth funciona bien para mercados con comunidad activa — falla en mercados obscuros sin watchers"
  solodit_ids:
    - m-1-controllerpeggedassetv2-outdated-price-may-be-used-which-can-lead-to-wrong-depeg-events-sherlock-none-y2k-git
    - h-09-depeg-event-can-happen-at-incorrect-price-code4rena-y2k-finance-y2k-finance-contest-git
    - l-06-stale-price-data-may-cause-incorrect-round-outcomes-pashov-audit-group-none-mcp_2025-08-07-markdown
    - h-1-an-update-gap-in-chainlinks-feed-can-malfunction-the-whole-market-sherlock-float-capital-float-capital-git
    - a-user-can-initiate-a-game-with-a-non-reliable-price-zokyo-none-xyro-markdown
  incidentes:
    - "Y2K Finance v1 — depeg event triggered con precio incorrecto de Chainlink (heartbeat gap), H-09, Code4rena 2022"
    - "Float Capital — Chainlink feed gap causes entire market to malfunction, H-1, Sherlock 2022"
    - "Xyro — user can initiate game with unreliable/stale price, Zokyo audit 2023"
    - "Augur v1 (2018) — mercados obscuros resueltos incorrectamente por falta de disputadores, ~$50K en mercados afectados"
  verificado: true
  confianza: alta

- id: pm-002
  titulo: Market Creation Griefing — Mercados Duplicados o Confusos para Atrapar Usuarios
  causa_raiz: |
    Si la creacion de mercados es permissionless (cualquiera puede crear un mercado),
    un atacante puede crear mercados que son casi identicos a mercados legitimos pero
    con parametros sutilmente diferentes (fecha de resolucion distinta, oracle diferente,
    o descripcion ambigua). Los usuarios depositan en el mercado falso pensando que es
    el real. El atacante controla la resolucion o el timing para robar fondos.

    Variante: mercados con un solo outcome posible (single-outcome market) donde el
    creador siempre gana porque la otra opcion es imposible.
  como_funciona: |
    1. Mercado legitimo: "Bitcoin > $100K el 31 de diciembre 2026?" (oracle: Chainlink BTC/USD)
    2. Atacante crea: "Bitcoin > $100K el 31 de diciembre 2026?" (oracle: su propia EOA)
    3. La UI del protocolo muestra ambos mercados con titulo identico
    4. Usuarios depositan en el mercado falso (mismo titulo, diferente oracle)
    5. Atacante resuelve el mercado a su favor usando su EOA como oracle
    6. Atacante cobra winnings de los usuarios atrapados

    Variante single-outcome:
    1. Atacante crea mercado: "El sol saldra manana?" con outcomes YES/NO
    2. Atacante apuesta todo a YES
    3. Mercado se resuelve como YES (obvious outcome) → atacante gana fees de los NO
    4. Nadie racional apostaria NO, pero bots/UI auto-deposit pueden caer
  invariante: |
    function check_market_not_duplicate(bytes32 newMarketId) internal view {
        bytes32 descHash = keccak256(abi.encodePacked(markets[newMarketId].description));
        // No deben existir 2 mercados con misma descripcion y distinto oracle
        for (uint i = 0; i < activeMarketIds.length; i++) {
            bytes32 existingHash = keccak256(abi.encodePacked(
                markets[activeMarketIds[i]].description));
            if (existingHash == descHash && activeMarketIds[i] != newMarketId) {
                t(markets[activeMarketIds[i]].oracle == markets[newMarketId].oracle,
                  "PM-002: duplicate market with different oracle");
            }
        }
    }
  que_mirar:
    - "Es la creacion de mercados permissionless? Cualquiera puede crear?"
    - "Hay validacion de que el oracle sea de una whitelist?"
    - "Se puede crear un mercado con un solo outcome valido?"
    - "La UI distingue mercados con misma descripcion pero parametros diferentes?"
    - "Hay un fee de creacion que desincentive spam de mercados?"
  como_se_arregla: |
    - Whitelist de oracles permitidos (solo Chainlink, UMA, Reality.eth verificados)
    - Fee de creacion significativo (e.g. $100) que se devuelve solo si el mercado tiene volumen real
    - Duplicate detection: hash de descripcion + parametros clave → revert si duplicado
    - Minimo 2 outcomes con probabilidad >0 al crear
    - Curating layer: DAO o curators validan mercados antes de que aparezcan en la UI
  trampas:
    - "Algunos protocolos usan 'market templates' pre-aprobados — esto mitiga parcialmente pero no elimina el riesgo si los templates son genericos"
    - "En Polymarket, Gnosis verifica mercados via UMIP — esto es off-chain pero efectivo"
    - "La creacion por DAO es mas segura pero limita la experiencia del usuario (menos mercados)"
  solodit_ids:
    - disallow-single-outcome-markets-cyfrin-none-myriad-markdown
    - markets-stuck-in-open-state-even-if-blocktimestamp-marketsmarketidclosesattimestamp-true-cyfrin-none-myriad-markdown
    - ambiguous-1-return-value-in-predictionmarketv3_4getmarketresolvedoutcome-cyfrin-none-myriad-markdown
  incidentes:
    - "Augur v1 (2018-2019) — mercados 'invalid' creados con descripciones ambiguas que resolvian como invalid, permitiendo que creadores que apostaron a INVALID ganasen, multiples instancias"
    - "Myriad — single-outcome markets posibles (Cyfrin audit), permitiendo mercados triviales donde creador siempre gana"
  verificado: true
  confianza: alta

- id: pm-003
  titulo: Outcome Token Minting Imbalance — Minting YES sin NO Correspondiente
  causa_raiz: |
    En el modelo de Conditional Token Framework (CTF / Gnosis), un mercado binario tiene
    tokens YES y NO. Para mantener la invariante de conservacion, por cada unidad de
    collateral depositada se DEBEN mintear exactamente 1 YES + 1 NO (via splitPosition).
    Si el contrato permite mintear YES sin mintear NO (o viceversa), se rompe la invariante
    de que totalYES == totalNO == totalCollateralDeposited, y el mercado se vuelve insolvente:
    no hay suficiente collateral para pagar a todos los ganadores.
  como_funciona: |
    1. Mercado tiene collateral pool de 1000 USDC
    2. Se han minteado 1000 YES + 1000 NO (correcto, 1:1)
    3. Bug: funcion alternativa permite mintear 500 YES adicionales sin depositar collateral
    4. Ahora hay 1500 YES + 1000 NO, pero solo 1000 USDC de collateral
    5. Si el mercado resuelve YES: los holders de YES esperan recibir 1 USDC por token
    6. Pero solo hay 1000/1500 = 0.667 USDC por YES token → perdida para holders legitimos

    Variante con mergePositions:
    1. mergePositions(1 YES + 1 NO) → devuelve 1 USDC de collateral
    2. Bug: merge permite que el ratio sea diferente (e.g., 1 YES + 0 NO → 1 USDC)
    3. Atacante mintea YES+NO, quema solo YES via merge, se queda con NO gratis
  invariante: |
    function check_outcome_token_balance(bytes32 conditionId) internal view {
        // En un mercado binario, totalYES == totalNO == collateral depositado
        uint256 totalYes = IERC1155(ctf).totalSupply(yesTokenId);
        uint256 totalNo = IERC1155(ctf).totalSupply(noTokenId);
        uint256 collateralLocked = collateralVault.balanceOf(conditionId);
        t(totalYes == totalNo, "PM-003: YES/NO token supply mismatch");
        t(totalYes == collateralLocked, "PM-003: tokens != collateral locked");
    }
  que_mirar:
    - "splitPosition() mintea exactamente la misma cantidad de TODOS los outcomes?"
    - "mergePositions() quema exactamente la misma cantidad de TODOS los outcomes?"
    - "Hay alguna funcion que mintee outcome tokens SIN pasar por splitPosition?"
    - "El redeemPositions() verifica que el mercado esta resuelto antes de pagar?"
    - "Puede el admin mintear outcome tokens directamente (bypass del split)?"
  como_se_arregla: |
    - splitPosition() SIEMPRE mintea exactamente 1 token de CADA outcome por unidad de collateral
    - mergePositions() SIEMPRE quema exactamente 1 token de CADA outcome por unidad de collateral devuelta
    - No tener funciones alternativas de mint/burn para outcome tokens
    - Invariante on-chain: sum(outcomeTokens[i].totalSupply()) == collateralLocked * numOutcomes
    - Access control en mint/burn: solo el contrato de mercado puede llamar
  trampas:
    - "En mercados multi-outcome (>2 outcomes), la invariante es diferente: sum(all_outcome_supplies) / numOutcomes == collateral"
    - "Gnosis CTF usa conditionId para agrupar outcomes — verificar que el conditionId es correcto en split/merge"
    - "NegRisk adapter de Polymarket invierte la logica (comprar NO = shortear YES) — la invariante se mantiene pero el token flow es diferente"
  solodit_ids:
    - unnecessary-transfer-in-predictionmarketv3_4mintandcreatemarket-cyfrin-none-myriad-markdown
    - m-4-using-wrong-format-of-questionid-for-negriskctfadapter-leads-to-loan-operations-on-resolved-multi-outcome-markets-sherlock-predictfun-lending-market-git
    - h-01-donations-to-marketmaker-will-completely-freeze-all-buysell-capability-of-market-0x52-none-ubet-markdown
  incidentes:
    - "UBET — donations to MarketMaker freeze all buy/sell capability, H-01 (0x52 audit 2023)"
    - "PredictFun — wrong questionId format for NegRiskCtfAdapter leads to operations on resolved markets, M-4 (Sherlock 2024)"
    - "Gnosis CTF (2020) — bug teorico: si splitPosition se llama con conditionId incorrecto, tokens se crean sin collateral backing"
  verificado: true
  confianza: alta

- id: pm-004
  titulo: Last-Second Bet Manipulation — Apostar Justo Antes del Cierre del Mercado
  causa_raiz: |
    En mercados con hora de cierre fija, un atacante puede esperar hasta el ultimo momento
    (ultimo bloque antes de closesAtTimestamp) cuando ya tiene informacion privilegiada
    sobre el outcome (por ejemplo, el precio ya se movio, o el evento ya ocurrio en el
    mundo real pero el oracle no ha reportado aun). Esto es especialmente critico en
    mercados deportivos y de precio donde el resultado puede saberse segundos antes
    del cierre on-chain.
  como_funciona: |
    1. Mercado de prediccion de precio: "ETH > $2000 a las 12:00 UTC?"
    2. El mercado cierra a las 12:00 UTC (block.timestamp >= closesAtTimestamp → no mas bets)
    3. A las 11:59:55, el precio de ETH en exchanges centralizados ya es $2015
    4. El oracle Chainlink aun no ha actualizado (heartbeat de 1200s)
    5. Atacante ve el precio real ($2015), compra YES masivamente en el ultimo bloque
    6. El mercado tiene CPMM → el precio de YES sube de $0.50 a $0.95
    7. Otros holders de YES se benefician pero el atacante compro al descuento
    8. Oracle actualiza → mercado resuelve YES → atacante profit

    En mercados deportivos:
    1. Partido termina, resultado conocido off-chain
    2. El keeper de resolucion aun no ha llamado a resolve()
    3. Atacante compra el outcome ganador antes de que resolve() se ejecute
  invariante: |
    function check_no_late_betting(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        // No se permiten bets en los ultimos N bloques antes del cierre
        uint256 LATE_BET_BUFFER = 300; // 5 minutos
        if (block.timestamp > m.closesAtTimestamp - LATE_BET_BUFFER) {
            // Verificar que no se aceptaron bets en el buffer period
            t(m.lastBetTimestamp <= m.closesAtTimestamp - LATE_BET_BUFFER,
              "PM-004: bet accepted in late-betting buffer period");
        }
    }
  que_mirar:
    - "Hay un buffer period antes del cierre del mercado donde no se aceptan bets?"
    - "El check de cierre es block.timestamp >= closesAtTimestamp o es estricto con buffer?"
    - "En mercados deportivos, se puede apostar despues de que el evento empezo?"
    - "Los bots pueden detectar el resultado off-chain antes de que el oracle lo reporte?"
    - "Hay slippage protection para compras grandes en el ultimo momento?"
  como_se_arregla: |
    - Buffer period: no aceptar bets en los ultimos X minutos antes de closesAtTimestamp
    - Para mercados deportivos: cerrar el mercado cuando el evento INICIA (no cuando termina)
    - Commit-reveal scheme: bets se commitean (hash) y se revelan despues del cierre
    - Limitar el size de bets en el ultimo 10% del periodo del mercado
    - TWAP para el precio de outcomes (no precio instantaneo del AMM)
  trampas:
    - "Un buffer demasiado largo reduce la liquidez del mercado — balance entre seguridad y UX"
    - "Commit-reveal agrega complejidad y gas costs — solo viable para mercados grandes"
    - "En blockchains con bloques de 2s (Optimism, Base), el buffer debe ser en segundos no en bloques"
    - "Bearish users can have advantage — si el boundary es inclusivo, bears ganan porque '>=' resuelve antes que el siguiente tick"
  solodit_ids:
    - m-02-late-participation-advantage-in-memepredictionmarket-pashov-audit-group-none-mcp_2025-08-07-markdown
    - operations-done-right-at-the-closesattimestamp-cyfrin-none-myriad-markdown
    - l-04-bearish-users-have-an-advantage-over-bullish-ones-pashov-audit-group-none-mcp_2025-08-07-markdown
    - user-can-play-knowing-the-starting-price-zokyo-none-xyro-markdown
    - users-can-make-a-safe-bet-in-updown-game-and-increase-their-chances-of-winning-zokyo-none-xyro-markdown
  incidentes:
    - "MCP (Meme Prediction Market) — late participation advantage, users betting near end with price knowledge, M-02 (Pashov 2025)"
    - "Myriad — operations at exact closesAtTimestamp boundary cause ambiguous behavior (Cyfrin audit)"
    - "Xyro — user can play knowing the starting price before the game begins, allows safe bets (Zokyo audit 2023)"
    - "PancakeSwap Prediction v2 (2022) — bots front-running oracle updates to bet on correct outcome, estimated $1M+ extracted"
  verificado: true
  confianza: alta

- id: pm-005
  titulo: Conditional Token Redemption Rounding — ERC-1155 con Errores de Redondeo
  causa_raiz: |
    Los conditional tokens (ERC-1155 en Gnosis CTF) se redimen despues de la resolucion
    del mercado. El calculo de payout por token puede tener errores de redondeo cuando
    el payout fraction no es 1:1 (por ejemplo, en mercados multi-outcome o con splits
    parciales). El redondeo en division entera de Solidity siempre trunca (round down),
    lo que puede dejar dust en el contrato o, peor, permitir que un atacante amplifique
    el error con muchas transacciones pequenas.
  como_funciona: |
    1. Mercado multi-outcome (3 outcomes: A, B, C)
    2. Collateral total: 1000 USDC
    3. Outcome A gana con payout weight de 33% (1/3)
    4. Holder tiene 10 tokens de outcome A
    5. Payout por token: 10 * 1000 / 3 = 3333... → truncado a 3333
    6. Dust: 10 * 1000 - 3333 * 3 = 1 wei de USDC perdida por claim

    Ataque de amplificacion:
    1. Atacante splitea 1 unidad de collateral → recibe 1 de cada outcome
    2. Resolucion: outcome A gana con payout fraction = p/q donde p/q causa truncation
    3. Atacante redime 1 token de A → recibe floor(1 * p / q) collateral
    4. Repite con muchos splits de 1 unidad → acumula el dust de truncation
    5. Si floor(p/q) > costo de split, profit neto
  invariante: |
    function check_redemption_solvency(bytes32 conditionId) internal view {
        uint256 totalCollateral = collateralVault.balanceOf(conditionId);
        uint256 totalRedeemed = redemptionTracker[conditionId];
        uint256 totalRedeemable = 0;
        for (uint i = 0; i < outcomeCount[conditionId]; i++) {
            uint256 supply = IERC1155(ctf).totalSupply(getTokenId(conditionId, i));
            uint256 payout = payoutNumerators[conditionId][i];
            uint256 denom = payoutDenominator[conditionId];
            totalRedeemable += (supply * payout) / denom;
        }
        // El collateral debe cubrir todo lo redeemable + lo ya redeemed
        t(totalCollateral >= totalRedeemable,
          "PM-005: insufficient collateral for all redemptions");
    }
  que_mirar:
    - "El calculo de payout usa mulDiv con rounding direction especificado?"
    - "Se redondea a favor del protocolo (down) o del usuario (up)?"
    - "Hay un minAmount para evitar claims de dust?"
    - "La fraccion de payout se normaliza correctamente (denominador comun)?"
    - "Puede un usuario hacer multiples claims pequenos para acumular rounding errors?"
  como_se_arregla: |
    - Usar OpenZeppelin Math.mulDiv con rounding DOWN para claims (favor del protocolo)
    - Establecer minAmount para redeem (e.g., 100 wei minimo)
    - Normalizar fracciones de payout antes de almacenarlas (maximal denominador)
    - Auditar que sum(floor(supply_i * payout_i / denom)) <= totalCollateral siempre
    - Considerar fixed-point math (e.g., 1e18 precision) para payout fractions
  trampas:
    - "En mercados binarios (50/50), el rounding es trivial y raramente explotable"
    - "El ataque solo es rentable si gas cost < dust acumulado — en L1 no es viable, en L2 (Optimism/Base/Arbitrum) puede serlo"
    - "Gnosis CTF v1 usa payout vectors normalizados — el rounding existe pero es de 1 wei por claim"
  solodit_ids:
    - consider-enforcing-a-minamount-to-prevent-rounding-exploits-cyfrin-none-myriad-markdown
    - add-explicit-check-to-prevent-underflow-revert-in-predictionmarketv3_4calcsellamount-cyfrin-none-myriad-markdown
    - consider-adding-share-based-sell-function-to-avoid-dust-shares-cyfrin-none-myriad-markdown
    - h-05-loss-of-precision-resulting-in-wrong-value-for-price-ratio-code4rena-y2k-finance-y2k-finance-contest-git
    - m-04-it-is-possible-that-receiver-and-treasury-can-receive-nothing-when-calling-withdraw-function-due-to-division-being-performed-before-multiplication-code4rena-y2k-finance-y2k-finance-contest-git
  incidentes:
    - "Y2K Finance v1 — loss of precision in price ratio calculation, H-05 (Code4rena 2022)"
    - "Y2K Finance v1 — division before multiplication causes receiver/treasury to receive nothing, M-04 (Code4rena 2022)"
    - "Myriad — rounding exploits possible without minAmount enforcement (Cyfrin audit)"
  verificado: true
  confianza: alta

- id: pm-006
  titulo: Binary Option Front-Running — Ver Oracle Update en Mempool y Apostar Antes
  causa_raiz: |
    En mercados de opciones binarias (Thales, Xyro, MCP) basados en precio, la
    resolucion depende de un oracle update (Chainlink, Pyth, API3). Si el oracle
    update es visible en el mempool ANTES de ejecutarse (no es private/encrypted),
    un atacante puede ver el precio que vendra, apostar en el outcome correcto, y
    luego dejar que el oracle update se mine. Esto es MEV puro aplicado a prediction markets.
  como_funciona: |
    1. Mercado binario: "ETH sube en la proxima hora?" (outcome UP o DOWN)
    2. El mercado usa Chainlink para resolver
    3. Chainlink node envia tx de update: nuevo precio = $2050 (era $2000)
    4. Atacante (searcher MEV) ve la tx de Chainlink en el mempool
    5. Atacante inserta su tx ANTES del update: compra UP tokens masivamente
    6. El oracle update se mina: ETH = $2050 → mercado resuelve UP
    7. Atacante redime UP tokens → profit

    Variante con Pyth:
    1. Pyth usa pull oracle — el usuario trae el precio firmado
    2. Atacante tiene acceso al precio firmado antes de submitearlo
    3. Atacante primero apuesta, luego submitea el precio que le conviene
  invariante: |
    function check_no_same_block_bet_and_resolve(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        // La apuesta y la resolucion no pueden ocurrir en el mismo bloque
        t(m.lastBetBlock < m.resolutionBlock,
          "PM-006: bet and resolution in same block (front-running)");
    }
  que_mirar:
    - "Puede un usuario apostar y resolver en el mismo bloque/tx?"
    - "El oracle update es visible en el mempool? (Chainlink si, Pyth depende)"
    - "Hay un lock period entre la ultima apuesta y la resolucion?"
    - "Se usa commit-reveal para las apuestas?"
    - "El protocolo corre en una L2 con sequencer privado (proteccion natural contra front-running)?"
  como_se_arregla: |
    - Lock period: no aceptar bets en los ultimos N bloques antes del oracle update
    - Commit-reveal scheme: bet se commitea (hash), se revela despues del oracle update
    - Usar L2 con sequencer privado (Optimism/Base — el sequencer no expone mempool)
    - Private mempools (Flashbots Protect, MEV Blocker) para oracle update txs
    - Verificar que lastBetBlock < resolutionBlock en el contrato
  trampas:
    - "En Optimism/Base, el sequencer es centralizado y no hay mempool publico — el front-running clasico no funciona, pero el sequencer PUEDE front-runnear"
    - "Chainlink en L2 usa un modelo diferente (no on-chain update visible) — verificar el mecanismo especifico"
    - "El commit-reveal agrega latencia y gas — solo viable para mercados >$10K de volumen"
  solodit_ids:
    - starttime-is-not-checked-allowing-games-with-past-prices-to-be-started-zokyo-none-xyro-markdown
    - l-01-later-prediction-rounds-may-not-start-at-expected-timestamp-pashov-audit-group-none-mcp_2025-08-07-markdown
    - m-2-an-update-gap-in-chainlinks-feed-can-malfunction-the-whole-market-sherlock-float-capital-float-capital-git
  incidentes:
    - "PancakeSwap Prediction (2021-2023) — bots front-running Chainlink updates para apostar en el outcome correcto, estimado $5M+ extraido de LPs"
    - "Float Capital — Chainlink update gap exploitable for market manipulation, M-2 (Sherlock 2022)"
    - "Xyro — games can start with past prices, allowing pre-knowledge bets (Zokyo audit)"
  verificado: true
  confianza: alta

- id: pm-007
  titulo: Market Maker Manipulation — Explotacion de LMSR/CPMM para Profit Garantizado
  causa_raiz: |
    Los automated market makers (AMM) de mercados de prediccion usan funciones de cost
    especificas: LMSR (Logarithmic Market Scoring Rule) o CPMM (Constant Product Market Maker
    adaptado a probabilidades). Estas funciones tienen propiedades matematicas que pueden
    explotarse: el parametro de liquidez (b en LMSR, k en CPMM) determina cuanto impacto
    tiene cada trade en el precio. Si el parametro es demasiado bajo, un atacante puede
    mover el precio drasticamente con poco capital. Si es demasiado alto, el LP pierde
    dinero subsidiando a traders informados.

    Bug especifico: en CPMM de prediction markets, si p(YES) + p(NO) != 1 (invariante rota),
    existe un arbitraje libre de riesgo.
  como_funciona: |
    LMSR exploitation:
    1. LMSR cost function: C = b * ln(sum(e^(q_i/b)))
    2. Si b es muy bajo (poca liquidez), un trade pequeno mueve el precio masivamente
    3. Atacante compra YES barato → precio sube de $0.30 a $0.90 con poco capital
    4. Atacante vende YES a $0.90 → profit neto (slippage en la venta es menor que el profit)
    5. Esto funciona si no hay otros traders que corrigan el precio rapidamente

    CPMM invariant break:
    1. p(YES) = yesReserve / totalReserve, p(NO) = noReserve / totalReserve
    2. Invariante: p(YES) + p(NO) == 1.0 (100%)
    3. Bug: despues de fees o rounding, p(YES) + p(NO) == 0.98
    4. Arbitraje: comprar YES a p=0.49 + comprar NO a p=0.49 = costo $0.98
    5. Un outcome SIEMPRE gana → payout $1.00 → profit $0.02 por unidad risk-free
  invariante: |
    function check_probability_sum(bytes32 marketId) internal view {
        uint256 pYes = getOutcomePrice(marketId, 0); // scaled 1e18
        uint256 pNo = getOutcomePrice(marketId, 1);  // scaled 1e18
        uint256 sum = pYes + pNo;
        // Sum of probabilities must be ~100% (allow 0.1% tolerance for rounding)
        uint256 deviation = sum > 1e18
            ? sum - 1e18
            : 1e18 - sum;
        t(deviation <= 1e15, "PM-007: probability sum deviates >0.1% from 100%");
    }
  que_mirar:
    - "Que AMM usa el mercado? LMSR, CPMM, o order book?"
    - "El parametro de liquidez (b/k) es configurable? Puede el admin cambiarlo mid-market?"
    - "p(YES) + p(NO) == 1 despues de trades con fees?"
    - "Hay slippage protection en las funciones de buy/sell?"
    - "El LP puede perder mas de su deposito (unbounded loss)?"
  como_se_arregla: |
    - Verificar on-chain que sum(p_i) == 1.0 despues de cada trade
    - Ajustar b/k dinamicamente basado en el volumen del mercado
    - Slippage protection: minAmountOut en buy/sell
    - Fee structure que no rompa la invariante de probabilidades
    - Para LMSR: b minimo que prevenga manipulacion con capital < $X
  trampas:
    - "LMSR tiene loss limitado por diseno (bounded loss = b * ln(n) donde n = numero de outcomes) — el LP puede perder pero esta acotado"
    - "CPMM de prediction markets es DIFERENTE al Uniswap AMM — no confundir invariantes"
    - "Fees intencionales que hacen p(YES)+p(NO) > 1 son 'vig' (vigorish) — no es un bug, es como el protocolo gana dinero"
  solodit_ids:
    - h-02-frontrunning-or-reorg-attacks-can-be-used-to-corrupt-initial-pricing-data-to-drain-funds-from-marketmaker-0x52-none-ubet-markdown
    - lack-of-slippage-protection-in-liquidity-functions-cyfrin-none-myriad-markdown
    - m-6-asymmetric-fee-structure-allows-market-participants-to-get-the-same-outcome-for-less-fee-sherlock-index-fun-order-book-git
  incidentes:
    - "UBET — frontrunning/reorg attacks corrupt initial pricing data to drain MarketMaker, H-02 (0x52 audit 2023)"
    - "Myriad — lack of slippage protection in liquidity functions (Cyfrin audit)"
    - "Augur v1 (2018) — LMSR parametro b demasiado bajo en mercados iniciales, permitiendo manipulacion barata de precios"
  verificado: true
  confianza: alta

- id: pm-008
  titulo: Dispute/Challenge System Gaming — Manipulacion de Bond Escalation
  causa_raiz: |
    Protocolos como UMA Optimistic Oracle y Reality.eth usan un sistema de dispute con
    bonds escalonados: proponer una respuesta requiere un bond, disputarla requiere un
    bond mayor. Si nadie disputa, la respuesta se acepta. El gaming ocurre cuando:
    1) El costo de disputar es mayor que el valor del mercado (no hay incentivo)
    2) El atacante controla multiples identidades para escalar bonds y agotar a los
       disputadores honestos
    3) El dispute period es demasiado corto para que alguien reaccione
  como_funciona: |
    Ataque por agotamiento de bonds:
    1. Mercado de $10K con dispute bond escalation: 100 → 200 → 400 → 800...
    2. Atacante propone respuesta incorrecta con bond de $100
    3. Honest actor disputa con bond de $200 y propone respuesta correcta
    4. Atacante re-disputa con bond de $400 (respuesta incorrecta de nuevo)
    5. Honest actor necesita $800 para disputar — puede que no tenga liquidez
    6. Si el honest actor no puede seguir escalando, la respuesta incorrecta se acepta
    7. Costo del atacante: $100 + $400 = $500. Ganancia: $10K del mercado

    Ataque por timing:
    1. Disputador propone respuesta a las 23:50 UTC
    2. Dispute period: 2 horas
    3. A las 01:49 (1 minuto antes de finalizar), nadie ha disputado
    4. La respuesta se finaliza automaticamente — no hubo tiempo suficiente en
       horarios donde los watchers estan offline
  invariante: |
    function check_dispute_bond_economics(bytes32 proposalId) internal view {
        Proposal memory p = proposals[proposalId];
        uint256 marketValue = markets[p.marketId].totalCollateral;
        uint256 minBondToAttack = calculateMinAttackCost(p.bondEscalation);
        // El costo minimo de un ataque de bond escalation debe ser > valor del mercado
        t(minBondToAttack > marketValue,
          "PM-008: bond escalation attack cheaper than market value");
    }
  que_mirar:
    - "Cual es el ratio bond_minimo / valor_del_mercado? Si bond << market_value, es atacable"
    - "Cuantas rondas de escalation se necesitan para que bonds > market_value?"
    - "El dispute period es suficiente? >24h para mercados grandes"
    - "Puede el mismo actor proponer Y disputar (sybil)?"
    - "Hay un arbitration layer final (e.g., DVM de UMA) como backstop?"
  como_se_arregla: |
    - Bond inicial proporcional al valor del mercado (e.g., 1% del TVL)
    - Escalation factor >= 2x por ronda
    - Dispute period minimo de 24h para mercados >$10K
    - Arbitration layer final: DVM de UMA, Kleros, o DAO vote
    - Sybil resistance: bond debe venir de stake lockeado, no de tokens fresh
    - Slashing: si la respuesta propuesta es incorrecta, el proposer pierde su bond
  trampas:
    - "UMA DVM es el backstop final — si el dispute llega al DVM, UMA token holders votan, y esto es caro de atacar (requiere >50% del UMA supply)"
    - "Reality.eth no tiene backstop automatico — depende de la comunidad para disputar"
    - "Bonds altos desincentivan la participacion legitima — hay un tradeoff real"
  solodit_ids:
    - m-2-collateral-can-already-be-seized-even-when-negriskmarket-is-not-fully-resolved-sherlock-predictfun-lending-market-git
    - m-10-challenger-can-override-the-7-day-finalization-period-sherlock-optimism-optimism-git
  incidentes:
    - "Reality.eth (2020) — mercados de bajo valor resueltos incorrectamente porque nadie tenia incentivo para disputar, multiples casos reportados en foros de Gnosis"
    - "UMA Optimistic Oracle (2021) — proposal spam para agotar disputadores en mercados pequenos, mitigado con bond escalation actualizado"
    - "Optimism fault dispute game — challenger can override 7-day finalization period, M-10 (Sherlock)"
    - "PredictFun — collateral seized on partially resolved negRisk markets, M-2 (Sherlock 2024)"
  verificado: true
  confianza: alta

- id: pm-009
  titulo: Position Token Transfer During Resolution — Vender Posicion Perdedora Antes de Finalizar
  causa_raiz: |
    Entre el momento en que un mercado "termina" (closesAtTimestamp) y el momento en
    que se resuelve oficialmente (alguien llama resolve()), hay un window donde las
    posiciones ya no se pueden crear pero SI se pueden transferir/vender. Si un actor
    tiene informacion sobre el outcome (vio el resultado off-chain pero on-chain aun
    no se resolvio), puede vender su posicion perdedora a un comprador desprevenido
    que espera que el mercado aun tenga incertidumbre.
  como_funciona: |
    1. Mercado: "Team A wins?" cierra a las 20:00 UTC
    2. El partido termina a las 19:45 → Team B gana
    3. On-chain, el mercado cerro pero no se resolvio aun (keeper no llamo resolve())
    4. Atacante tiene tokens YES (Team A wins) que van a valer $0
    5. Atacante lista los tokens YES en un DEX secundario / OTC
    6. Comprador desprevenido (bot, aggregator) compra los YES tokens a $0.10
    7. El keeper resuelve el mercado → Team B gana → YES tokens valen $0
    8. El comprador pierde $0.10 por token, el atacante extrajo valor

    Variante con ERC-1155:
    1. Conditional tokens son ERC-1155 → transferibles libremente
    2. Atacante puede crear un pool en SushiSwap para los outcome tokens
    3. Agregar liquidez con tokens perdedores + ETH antes de la resolucion
    4. Usuarios que swapean obtienen tokens que valen $0
  invariante: |
    function check_no_transfer_during_resolution(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        if (block.timestamp >= m.closesAtTimestamp && !m.resolved) {
            // Durante el periodo de resolucion, verificar que no hubo transfers
            // (esto requiere un hook en transfer que bloquee o registre)
            t(m.transfersDuringResolution == 0,
              "PM-009: tokens transferred between close and resolution");
        }
    }
  que_mirar:
    - "Los outcome tokens son transferibles despues de que el mercado cierra?"
    - "Hay un lock en transfers entre closesAtTimestamp y resolucion?"
    - "Los outcome tokens se listan en DEXes secundarios?"
    - "El contrato tiene un hook en ERC-1155 safeTransferFrom que bloquee en estado 'pending resolution'?"
    - "Cuanto tiempo pasa tipicamente entre cierre y resolucion?"
  como_se_arregla: |
    - Lockear transfers de outcome tokens entre closesAtTimestamp y resolucion
    - Automatizar resolucion (no depender de keeper manual) para minimizar el window
    - Hook en _beforeTokenTransfer que revierte si market.status == PENDING_RESOLUTION
    - Si transfers deben permitirse (composabilidad), marcar tokens con un flag de "pending" visible
  trampas:
    - "Bloquear transfers puede romper integraciones con DeFi (lending against outcome tokens)"
    - "En PredictFun, los CTF tokens se usan como collateral en lending — bloquear transfers romperia eso"
    - "Si el mercado tiene dispute period, el window se extiende aun mas (potencialmente dias)"
  solodit_ids:
    - l-07-new-rounds-can-start-while-current-round-is-active-trapping-funds-pashov-audit-group-none-mcp_2025-08-07-markdown
    - m-14-inconsistent-use-of-epochbegin-could-lock-user-funds-sherlock-none-y2k-git
    - unused-field-marketresolutionresolved-cyfrin-none-myriad-markdown
  incidentes:
    - "Polymarket (2024) — preocupaciones sobre insider trading en mercados politicos, outcomes conocidos antes de resolucion on-chain"
    - "MCP — new rounds can start while current round is active, trapping funds, L-07 (Pashov 2025)"
    - "Y2K Finance v2 — inconsistent use of epochBegin locks user funds, M-14 (Sherlock)"
  verificado: true
  confianza: media

- id: pm-010
  titulo: Multi-Outcome Market Arbitrage — Probabilidades Suman > 100%
  causa_raiz: |
    En mercados con multiples outcomes (e.g., eleccion con 5 candidatos), cada outcome
    tiene un precio que representa su probabilidad. La invariante fundamental es que
    sum(p_i) == 1.0 (100%). Si por fees, rounding, o AMM design la suma es > 100%,
    existe un arbitraje risk-free: comprar 1 unidad de CADA outcome cuesta sum(p_i) > $1,
    pero SIEMPRE uno de ellos gana y paga $1. Si sum < $1, el arbitraje es inverso:
    comprar todos los outcomes por < $1 garantiza $1 de payout.

    En la practica, sum > 100% es intencional en muchos protocolos (el exceso es la
    "commission" del market maker), pero si sum >> 100% o es dinamico, se puede explotar.
  como_funciona: |
    1. Mercado de 3 outcomes: A, B, C
    2. Precios: p(A) = 0.40, p(B) = 0.35, p(C) = 0.30
    3. Sum = 1.05 (5% overround — commission del market maker, normal)
    4. Bug: despues de un trade grande, p(A) = 0.20, p(B) = 0.15, p(C) = 0.15
    5. Sum = 0.50 (50% — roto)
    6. Atacante compra 1000 de CADA outcome: costo = 1000 * 0.50 = $500
    7. Uno de A/B/C SIEMPRE gana → payout = 1000 * $1 = $1000
    8. Profit = $1000 - $500 = $500 risk-free

    Variante con split/merge:
    1. splitPosition() deberia costar exactamente $1 por set completo de outcomes
    2. Si buy(A) + buy(B) + buy(C) en el AMM cuesta < $1 → comprar en AMM, merge, profit
    3. Si > $1 → split, sell individual tokens en AMM, profit
  invariante: |
    function check_no_free_arbitrage(bytes32 marketId) internal view {
        uint256 numOutcomes = outcomeCount[marketId];
        uint256 totalCost = 0;
        for (uint i = 0; i < numOutcomes; i++) {
            totalCost += getOutcomePrice(marketId, i); // scaled 1e18
        }
        // Buying all outcomes should cost >= 1.0 (no free money)
        // Allow up to 5% overround (commission)
        t(totalCost >= 0.95e18, "PM-010: outcome prices sum < 95% — free arbitrage");
        t(totalCost <= 1.10e18, "PM-010: outcome prices sum > 110% — excessive overround");
    }
  que_mirar:
    - "sum(p_i) == 1.0 despues de cada trade? O hay overround intencional?"
    - "El overround es constante o cambia con el volumen?"
    - "Puede un trade grande causar que sum(p_i) < 1.0?"
    - "Hay split/merge que permite arbitraje contra el AMM?"
    - "Las fees se aplican correctamente sin romper la invariante de probabilidades?"
  como_se_arregla: |
    - Invariante on-chain: sum(p_i) >= 0.95 y <= 1.05 despues de cada trade
    - Si el protocolo usa overround, este debe ser fijo y predecible
    - Separar fees del precio de outcomes (fee se aplica sobre el trade, no sobre el precio)
    - split/merge siempre a $1 exacto por set completo (arbitraje imposible via esta ruta)
    - Re-normalize precios despues de cada trade si es necesario
  trampas:
    - "Overround de 2-5% es estandar en bookmaking — no es un bug, es el business model"
    - "Pero si el overround es variable y puede caer a <100%, ESO es un bug"
    - "En AMMs tipo CPMM, el overround es 0% por diseno — la divergence de sum != 1 SI es un bug"
    - "LMSR naturalmente mantiene sum = 1 — pero la implementacion puede tener precision errors"
  solodit_ids:
    - m-6-asymmetric-fee-structure-allows-market-participants-to-get-the-same-outcome-for-less-fee-sherlock-index-fun-order-book-git
    - weight-and-poolweight-serves-different-meanings-throughout-the-codedocumentation-cyfrin-none-myriad-markdown
  incidentes:
    - "Index Fund Order Book — asymmetric fee structure allows getting same outcome for less fee, M-6 (Sherlock)"
    - "Augur v1 (2019) — rounding errors en mercados multi-outcome con 256 outcomes causaban sum(p_i) < 1.0 brevemente"
    - "Polymarket (2023) — discrepancias de precio entre CTF y AMM de outcomes permitieron arbitraje temporal"
  verificado: true
  confianza: alta

- id: pm-011
  titulo: Flash-Loan Governance of Resolution — Tomar Control del Dispute con Tokens Prestados
  causa_raiz: |
    Algunos protocolos de prediccion usan governance tokens para resolver disputas
    (UMA usa UMA token para DVM votes, Augur usa REP para dispute). Si un atacante
    puede tomar un flash loan del governance token, votar en una disputa, y devolver
    el loan en la misma transaccion, puede influir en la resolucion del mercado sin
    tener capital real comprometido.
  como_funciona: |
    1. Mercado de prediccion resuelve outcome A (propuesto por honest reporter)
    2. Atacante tiene posicion grande en outcome B (que perderia con resolucion A)
    3. El dispute se decide por voto de holders del governance token (e.g., REP, UMA)
    4. Atacante toma flash loan de governance tokens (e.g., 51% del supply de REP)
    5. En la misma tx: vota a favor de outcome B → outcome B gana el dispute
    6. Devuelve el flash loan
    7. Atacante cobra winnings de outcome B

    Variante con delegated voting:
    1. Protocolo usa vesting tokens con delegated voting (similar a Compound COMP)
    2. Atacante flash-loans tokens, delega a si mismo, vota, deshace delegacion
    3. Snapshot-based systems previenen esto SI el snapshot es > 1 bloque atras
  invariante: |
    function check_no_flash_loan_voting(address voter, bytes32 disputeId) internal view {
        // El votante debe haber tenido tokens ANTES de esta tx
        uint256 balanceAtSnapshot = governanceToken.getPastVotes(
            voter, disputes[disputeId].snapshotBlock);
        uint256 currentBalance = governanceToken.balanceOf(voter);
        // Si el balance actual es mucho mayor que el snapshot, es sospechoso
        t(currentBalance <= balanceAtSnapshot * 2,
          "PM-011: voter balance increased >2x since snapshot — possible flash loan");
    }
  que_mirar:
    - "El dispute/vote usa snapshot de un bloque anterior o balance actual?"
    - "Los governance tokens tienen flash loan/flash mint?"
    - "Hay un lock period despues de adquirir tokens antes de poder votar?"
    - "El token tiene checkpoint system (ERC20Votes) con getPastVotes()?"
    - "Es posible delegar y votar en la misma tx?"
  como_se_arregla: |
    - Usar snapshots de bloques anteriores (>1 bloque) para voting power
    - Implementar ERC20Votes con checkpoints — getPastVotes() no es manipulable por flash loan
    - Lock period: tokens adquiridos deben esperar N bloques antes de poder votar
    - Eliminar flash mint/flash loan del governance token
    - Weighted voting con time-locked stakes (mas peso cuanto mas tiempo staked)
  trampas:
    - "UMA DVM usa snapshots — no es vulnerable a flash loans directamente"
    - "Augur v2 usa fork mechanism (no simple voting) — mucho mas resistente pero mas lento"
    - "Si el governance token no tiene flash loan pool (no hay par en Aave/dydx), este ataque no es posible"
    - "Verificar que no se pueda hacer lo mismo con wrapped tokens o lending pools"
  solodit_ids:
    - attacker-can-combine-flashloan-with-delegated-voting-to-decide-a-proposal-and-withdraw-their-tokens-while-the-proposal-is-still-in-locked-state-cyfrin-none-cyfrin-dexe-markdown
    - m-01-reward-rates-can-be-changed-through-flash-borrows-code4rena-based-loans-based-loans-contest-git
  incidentes:
    - "Dexe Protocol — attacker combines flashloan with delegated voting to decide proposal (Cyfrin audit)"
    - "Beanstalk (2022) — flash loan de governance tokens para aprobar BIP-18, $182M robados. No es prediction market pero es el mismo vector aplicado a governance de DeFi"
    - "MakerDAO governance (2020) — concern teorico sobre flash loan de MKR para votar en executive spell, mitigado por governance delay"
  verificado: true
  confianza: alta

- id: pm-012
  titulo: Fee Extraction from Illiquid Markets — LP Fee Farming sin Volumen Real
  causa_raiz: |
    En mercados de prediccion con AMM y LP positions, los LPs ganan fees de cada trade.
    Si un atacante puede crear un mercado, ser el unico LP, y luego hacer wash trading
    (comprarse a si mismo outcome tokens), puede extraer fees del protocolo sin actividad
    real. Esto es especialmente problematico si el protocolo subsidia LPs con token rewards
    (liquidity mining) o si las fees vienen de un pool compartido.
  como_funciona: |
    Wash trading con rewards:
    1. Protocolo ofrece 1000 REWARD tokens/dia a LPs proporcional al volumen generado
    2. Atacante crea mercado obscuro, deposita 100 USDC como LP
    3. Atacante hace 1000 trades de $10 cada uno (compra YES, vende YES, repite)
    4. Volumen generado: $10K. Fees pagadas: $10K * 0.1% = $10 en fees
    5. Pero el atacante recibe share de REWARD tokens proporcional a su volumen
    6. Si rewards > fees pagadas → profit neto

    Fee extraction con pool compartido:
    1. Protocolo acumula todas las fees en un pool compartido y las redistribuye
    2. Atacante crea mercados basura y genera volumen falso
    3. Recibe una porcion desproporcionada del pool de fees
    4. Los LPs de mercados reales reciben menos fees de lo que merecen
  invariante: |
    function check_no_wash_trading(bytes32 marketId, address user) internal view {
        // Si el mismo usuario es buyer Y seller en volumen significativo, es wash trading
        uint256 buyVolume = userBuyVolume[marketId][user];
        uint256 sellVolume = userSellVolume[marketId][user];
        uint256 netVolume = buyVolume > sellVolume
            ? buyVolume - sellVolume
            : sellVolume - buyVolume;
        uint256 totalVolume = buyVolume + sellVolume;
        // Si el net volume es < 10% del total, es sospechoso
        if (totalVolume > 1000e18) { // solo para volumen significativo
            t(netVolume * 10 >= totalVolume,
              "PM-012: potential wash trading — net < 10% of gross volume");
        }
    }
  que_mirar:
    - "El protocolo tiene liquidity mining rewards proporcionales al volumen?"
    - "Puede un usuario ser LP y trader al mismo tiempo en el mismo mercado?"
    - "Las fees son por mercado o de un pool compartido?"
    - "Hay anti-wash-trading mechanisms (e.g., cooldown entre buy/sell)?"
    - "Puede un usuario crear mercados ilimitados sin costo?"
  como_se_arregla: |
    - Rewards basados en net positions (no volume bruto)
    - Fee por creacion de mercados (desincentiva spam)
    - Cooldown entre buy y sell del mismo outcome
    - Wash trading detection: si misma direccion compra y vende > X% del volumen, no cuenta para rewards
    - Fees por mercado (no pool compartido) para aislar mercados legitimos
  trampas:
    - "Wash trading es dificil de detectar on-chain si el atacante usa multiples addresses"
    - "Rewards basados en volumen son comunes en DeFi — el wash trading es un problema sistemico, no solo de prediction markets"
    - "Si el fee es pagado por el trader, el wash trading tiene costo neto (no es free) — solo es rentable si los rewards subsidian"
  solodit_ids:
    - m-03-missing-admin-input-sanitization-pashov-none-azuro-markdown
    - collectedfees-is-not-paid-out-anywhere-zokyo-none-xyro-markdown
    - the-calculateupdownrate-function-does-not-distribute-fees-zokyo-none-xyro-markdown
  incidentes:
    - "Azuro — missing admin input sanitization permite configuracion de fees incorrecta, M-03 (Pashov audit)"
    - "Xyro — CollectedFees is not paid out anywhere (fees acumuladas sin mecanismo de distribucion), Zokyo audit"
    - "Xyro — calculateUpDownRate does not distribute fees correctamente, Zokyo audit"
    - "Polymarket (2023-2024) — reportes de wash trading para manipular rankings y visibilidad de mercados"
  verificado: true
  confianza: media

- id: pm-013
  titulo: Invalid Market Resolution — Edge Cases con Null/Void/Invalid Outcomes
  causa_raiz: |
    No todos los mercados tienen una resolucion limpia YES/NO. Casos edge:
    - El evento no ocurrio (partido cancelado, candidato se retira)
    - El oracle no puede determinar el outcome (datos insuficientes)
    - La pregunta es ambigua y multiple interpretaciones son validas
    - El mercado se crea con parametros invalidos (fecha pasada, asset inexistente)

    Si el contrato no maneja el caso INVALID/VOID, los fondos pueden quedar lockeados
    permanentemente, o la resolucion puede favorecer a un lado arbitrariamente.
  como_funciona: |
    Fondos lockeados (no hay outcome INVALID):
    1. Mercado: "El partido X se jugara el 15 de marzo?"
    2. El partido se cancela por lluvia — ni YES ni NO es correcto
    3. El contrato solo permite resolver como YES o NO
    4. Si se resuelve YES → los NO holders pierden injustamente
    5. Si nadie resuelve → fondos lockeados indefinidamente

    Explotacion del outcome INVALID:
    1. Mercado tiene 3 outcomes: YES, NO, INVALID
    2. INVALID paga pro-rata (todos reciben su deposito de vuelta)
    3. Atacante crea mercado con pregunta ambigua
    4. Apuesta a INVALID (barato porque nadie espera invalido)
    5. Disputa la pregunta como "ambigua" → resuelve INVALID
    6. Si el token INVALID estaba barato → profit

    Funds lock con all-same-direction:
    1. Todos los usuarios apuestan YES (nadie apuesta NO)
    2. Mercado resuelve NO → no hay fondos para pagar a nadie (correcto)
    3. Mercado resuelve YES → todos deberian recibir su deposito pero las fees
       pueden hacer que no haya suficiente para todos
  invariante: |
    function check_void_handling(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        if (m.voided) {
            // En un mercado void, todos los depositantes deben poder retirar su deposito original
            uint256 totalDeposits = m.totalCollateral;
            uint256 contractBalance = collateralToken.balanceOf(address(this));
            t(contractBalance >= totalDeposits,
              "PM-013: voided market has insufficient balance for full refunds");
        }
        // Verificar que siempre hay un mecanismo de resolucion (no stuck forever)
        if (block.timestamp > m.closesAtTimestamp + MAX_RESOLUTION_DELAY) {
            t(m.resolved || m.voided,
              "PM-013: market stuck — not resolved after max delay");
        }
    }
  que_mirar:
    - "Hay un outcome INVALID/VOID en el contrato? Que pasa con los fondos?"
    - "Que pasa si nadie llama a resolve() despues del cierre?"
    - "Hay un timeout despues del cual el mercado se voida automaticamente?"
    - "Si todos apuestan en la misma direccion y pierden, que pasa con los fondos?"
    - "Las fees se cobran antes o despues de la resolucion? Reducen el collateral disponible?"
    - "Puede el admin/DAO forzar un void en caso de disputa irreconciliable?"
  como_se_arregla: |
    - Siempre incluir outcome INVALID/VOID que devuelve pro-rata
    - Timeout automatico: si no se resuelve en X dias, se voida automaticamente
    - Emergency void: admin/DAO puede forzar void con timelock
    - Si todos apuestan en misma direccion: devolver pro-rata (no hay counterparty)
    - No cobrar fees hasta despues de la resolucion exitosa
  trampas:
    - "En Augur, INVALID es un outcome real con mercado — esto creo un mercado de 'invalid hunting' donde gente apostaba a INVALID intencionalmente"
    - "Polymarket usa UMA para resolver disputas — si UMA no puede resolver, el mercado queda en limbo"
    - "El void no es 'gratis' para el protocolo — devolver depositos requiere que no se hayan usado fees del collateral"
  solodit_ids:
    - m-01-funds-lock-if-all-users-choose-same-direction-and-price-is-incorrect-pashov-audit-group-none-mcp_2025-08-07-markdown
    - h-04-users-who-deposit-in-one-vault-can-lose-all-deposits-and-receive-nothing-when-counterparty-vault-has-no-deposits-code4rena-y2k-finance-y2k-finance-contest-git
    - games-can-get-closed-without-a-reason-leading-to-players-not-being-paid-zokyo-none-xyro-markdown
    - h-02-end-epoch-cannot-be-triggered-preventing-winners-to-withdraw-code4rena-y2k-finance-y2k-finance-contest-git
    - m-01-multiplier-configuration-can-break-distribution-invariant-and-permanently-freeze-game-resolution-and-claims-shieldify-none-abster-freefall-markdown
  incidentes:
    - "MCP — funds lock if all users choose same direction and price is incorrect, M-01 (Pashov 2025)"
    - "Y2K Finance v1 — users deposit in one vault, receive nothing when counterparty vault has no deposits, H-04 (Code4rena 2022)"
    - "Y2K Finance v1 — end epoch cannot be triggered, preventing winners from withdrawing, H-02 (Code4rena 2022)"
    - "Xyro — games can get closed without a reason, leading to players not being paid (Zokyo audit)"
    - "Abster FreeFall — multiplier configuration breaks distribution invariant, permanently freezes game resolution and claims, M-01 (Shieldify audit)"
    - "Augur v1 (2018-2019) — 'invalid market' hunting fue una estrategia rentable, ~$100K+ en mercados resueltos como INVALID"
  verificado: true
  confianza: alta

- id: pm-014
  titulo: Parimutuel Pool Manipulation — Deposito de Ultimo Segundo para Diluir Otros
  causa_raiz: |
    En mercados parimutuel (todos los perdedores pagan a los ganadores pro-rata),
    el payout de cada ganador depende de cuantos otros apostaron en el outcome
    ganador. Si un atacante puede depositar una cantidad enorme en el ultimo momento
    (justo antes del cierre o justo antes de la resolucion), diluye el payout de
    los otros apostadores que entraron antes.

    La ventaja del late entry es que el atacante tiene mas informacion: ve las apuestas
    de otros y puede calcular el EV optimo antes de apostar.
  como_funciona: |
    1. Pool parimutuel: 100 USDC apostados a YES, 100 USDC a NO
    2. Si YES gana: cada YES holder recibe 200/100 = 2x (100% profit)
    3. En el ultimo bloque: whale deposita 900 USDC a YES
    4. Ahora: 1000 USDC a YES, 100 USDC a NO
    5. Si YES gana: cada YES holder recibe 1100/1000 = 1.1x (10% profit)
    6. Los holders originales de YES pasaron de 100% profit esperado a 10%
    7. El whale tiene informacion privilegiada (sabe que YES va a ganar)

    Variante con withdrawal timing:
    1. Protocolo permite retirar depositos antes del cierre
    2. Whale deposita en YES → otros ven la senal y depositan en YES tambien
    3. Whale retira su deposito de YES y deposita en NO
    4. Ahora NO tiene mejor odds porque todos siguieron al whale a YES
    5. Si el whale tenia informacion real → profit en NO
  invariante: |
    function check_no_late_deposit_dilution(bytes32 marketId) internal view {
        Market memory m = markets[marketId];
        // Los depositos en el ultimo 10% del periodo no deben ser >50% del total
        uint256 cutoff = m.opensAtTimestamp +
            (m.closesAtTimestamp - m.opensAtTimestamp) * 90 / 100;
        if (block.timestamp > cutoff) {
            uint256 lateDeposits = m.depositsAfterCutoff;
            uint256 totalDeposits = m.totalCollateral;
            t(lateDeposits * 2 <= totalDeposits,
              "PM-014: late deposits > 50% of total — dilution risk");
        }
    }
  que_mirar:
    - "Es parimutuel puro o tiene AMM? (parimutuel es mas vulnerable)"
    - "Puede un usuario depositar cantidades ilimitadas en el ultimo momento?"
    - "Hay un cap en deposit size o en late deposits?"
    - "Puede un usuario retirar su deposito y re-depositar en otro outcome?"
    - "Los depositos de otros usuarios son visibles on-chain? (informacion asimetrica)"
  como_se_arregla: |
    - Cap en deposits tardios: no mas de X% del total en el ultimo 10% del periodo
    - Decaying odds: las apuestas tardias reciben peores odds (penalizacion por timing)
    - No permitir withdrawals despues de que el mercado abre (commit es final)
    - Blind betting: depositos no son visibles hasta el cierre (commit-reveal pool)
    - Max deposit per address para prevenir whale manipulation
  trampas:
    - "En parimutuel puro, los late deposits son un feature (agregacion de informacion) — el 'bug' es cuando la informacion es asimetrica (insider knowledge)"
    - "Caps en depositos pueden limitar la liquidez del mercado — trade-off real"
    - "Blind betting requiere commit-reveal que agrega complejidad"
  solodit_ids:
    - m-02-late-participation-advantage-in-memepredictionmarket-pashov-audit-group-none-mcp_2025-08-07-markdown
    - h-01-claimreward-can-dos-by-iterating-predictions-blocking-funds-pashov-audit-group-none-mcp_2025-08-07-markdown
    - l-08-endmultiplerounds-lacks-round-end-timestamp-check-pashov-audit-group-none-mcp_2025-08-07-markdown
  incidentes:
    - "MCP — late participation advantage in prediction market, M-02 (Pashov 2025)"
    - "MCP — claimReward can DoS by iterating predictions, blocking funds (related: large number of late deposits cause gas issues), H-01 (Pashov 2025)"
    - "PlotX (2020-2021) — reportes de whale manipulation en pools parimutuel, depositos de ultimo segundo que diluian a otros participantes"
    - "PancakeSwap Prediction (2022) — bots que esperan al ultimo bloque para apostar con informacion privilegiada de precio"
  verificado: true
  confianza: alta

- id: pm-015
  titulo: Cross-Market Correlated Position — Explotar Mercados Correlacionados con Capital Unico
  causa_raiz: |
    Cuando un protocolo de prediccion ofrece multiples mercados que estan correlacionados
    (e.g., "ETH > $2000?" y "BTC > $30K?" — ambos correlacionados con crypto sentiment),
    un atacante puede tomar posiciones en mercados correlacionados que se benefician del
    mismo evento. Si el protocolo no tiene cross-margin o cross-market risk management,
    el atacante puede tener exposicion neta mucho mayor de lo que su capital individual sugiere.

    Mas critico: si el atacante puede CAUSAR el outcome en un mercado (e.g., manipular un
    oracle) y automaticamente ganar en todos los mercados correlacionados.
  como_funciona: |
    1. Protocolo tiene mercados: "ETH > $2000?" y "ETH > $1900?" y "ETH > $1800?"
    2. Atacante compra YES en los 3 mercados (alta correlacion)
    3. Atacante manipula el oracle de ETH a $2100 (via flash loan en un AMM que el oracle lee)
    4. Los 3 mercados resuelven YES → atacante gana en los 3
    5. El costo de manipulacion se paga una vez pero el profit es 3x

    Variante con hedging:
    1. Mercado A: "ETH > $2000?" — atacante compra YES
    2. Mercado B: "ETH volatility > 50%?" — atacante compra YES
    3. Atacante crea un flash crash de ETH (via large sell en pool)
    4. ETH cae a $1500 → mercado A pierde (NO wins)
    5. Pero la volatilidad sube a 80% → mercado B gana (YES wins)
    6. Si mercado B paga mas que la perdida en mercado A → profit neto
  invariante: |
    function check_cross_market_exposure(address user) internal view {
        uint256 totalExposure = 0;
        for (uint i = 0; i < userMarkets[user].length; i++) {
            bytes32 mId = userMarkets[user][i];
            uint256 positionValue = getUserPositionValue(mId, user);
            totalExposure += positionValue;
        }
        uint256 userCollateral = userDeposits[user];
        // La exposicion total no debe exceder N veces el collateral
        t(totalExposure <= userCollateral * MAX_LEVERAGE,
          "PM-015: cross-market exposure exceeds max leverage");
    }
  que_mirar:
    - "El protocolo tiene multiples mercados sobre el mismo subyacente?"
    - "Hay cross-margin entre mercados (positions se netean) o son independientes?"
    - "El oracle es compartido entre mercados correlacionados?"
    - "Un usuario puede manipular un oracle y ganar en multiples mercados?"
    - "Hay limites de posicion por usuario across all markets?"
  como_se_arregla: |
    - Cross-market position limits: max exposicion total across all markets
    - Oracle diversity: usar diferentes oracles para mercados correlacionados
    - Correlation-aware pricing: ajustar odds cuando mercados correlacionados tienen posiciones grandes del mismo usuario
    - Si los mercados comparten oracle, la manipulacion del oracle tiene impacto multiplicado — usar TWAP resistente
    - Position reporting: on-chain tracking de exposicion agregada por usuario
  trampas:
    - "La correlacion es un concepto estadistico — on-chain es muy dificil de medir en real-time"
    - "Cross-margin es un feature avanzado que pocos protocolos de prediccion implementan"
    - "El ataque requiere que el atacante pueda manipular el outcome — si el oracle es robusto, el vector no existe"
    - "En Polymarket, cada mercado usa UMA independiente — la correlacion no se trackea on-chain"
  solodit_ids:
    - m-4-using-wrong-format-of-questionid-for-negriskctfadapter-leads-to-loan-operations-on-resolved-multi-outcome-markets-sherlock-predictfun-lending-market-git
    - m-2-collateral-can-already-be-seized-even-when-negriskmarket-is-not-fully-resolved-sherlock-predictfun-lending-market-git
    - m-01-oracle-is-tracked-per-token-instead-of-per-pair-leading-to-surprise-results-code4rena-y2k-finance-y2k-finance-contest-git
  incidentes:
    - "Y2K Finance v1 — oracle tracked per token instead of per pair, leading to surprise results across correlated vaults, M-01 (Code4rena 2022)"
    - "PredictFun — wrong questionId format lets operations on resolved multi-outcome markets (cross-market interaction bug), M-4 (Sherlock 2024)"
    - "PredictFun — collateral seized on partially resolved negRisk market (multi-outcome resolution ordering issue), M-2 (Sherlock 2024)"
    - "Mango Markets (2022) — Avraham Eisenberg manipulo oracles de MNGO para tomar posiciones correlacionadas por $116M. No es prediction market pero el vector es identico"
  verificado: true
  confianza: media

- id: pm-016
  titulo: Claim Reward DoS — Iteracion sobre Predicciones Bloquea Fondos
  causa_raiz: |
    En muchos protocolos de prediccion, el claim de rewards requiere iterar sobre
    todas las predicciones/apuestas del usuario para calcular el payout total.
    Si un usuario (o atacante) ha hecho muchas predicciones pequenas, la funcion
    claimReward() puede exceder el gas limit del bloque y revertir, bloqueando
    los fondos del usuario permanentemente. Esto es un patrón clasico de DoS por
    gas pero es especialmente comun en prediction markets porque:
    1) Los usuarios naturalmente hacen muchas apuestas pequenas
    2) Los protocolos almacenan cada prediccion individualmente
    3) El claim itera sobre TODAS las predicciones, no solo las ganadoras
  como_funciona: |
    1. Protocolo almacena array de predicciones por usuario: userPredictions[user]
    2. claimReward() itera: for (i = 0; i < userPredictions[msg.sender].length; i++)
    3. Atacante hace 10,000 predicciones de 1 wei cada una (costo: gas de 10K txs)
    4. Cuando intenta claim: el loop de 10K iteraciones excede gas limit → revert
    5. Fondos del atacante (y potencialmente del pool) quedan lockeados

    Variante con ERC-1155 batch:
    1. Funcion de batch redeem itera sobre todos los tokenIds del usuario
    2. Si el usuario tiene posiciones en 1000 mercados, el batch revert
    3. No hay funcion de redeem individual → fondos lockeados
  invariante: |
    function check_claim_gas_bounded(address user) internal view {
        // El numero de predicciones por usuario debe estar acotado
        uint256 predictionCount = userPredictions[user].length;
        t(predictionCount <= MAX_PREDICTIONS_PER_USER,
          "PM-016: user has too many predictions — claim may DoS");
    }
  que_mirar:
    - "claimReward() tiene un loop unbounded sobre predicciones del usuario?"
    - "Hay un limite en el numero de predicciones por usuario?"
    - "Existe una funcion de claim parcial (claim N predicciones a la vez)?"
    - "El costo de crear una prediccion es suficiente para desincentivizar spam?"
    - "Los tokens ERC-1155 tienen batch redeem con limite de gas?"
  como_se_arregla: |
    - Paginated claims: claimReward(uint256 startIndex, uint256 count)
    - Limite de predicciones por usuario (e.g., max 100 por mercado)
    - Min bet size que desincentive spam (e.g., $1 minimo)
    - Claim individual por mercado (no claim-all global)
    - Pull pattern: cada prediccion se puede claim independientemente
  trampas:
    - "El DoS puede afectar a usuarios legitimos con muchas predicciones, no solo a atacantes"
    - "La solucion de 'paginated claims' requiere que el usuario haga multiples txs — peor UX"
    - "El min bet size debe balancear anti-spam con accesibilidad"
  solodit_ids:
    - h-01-claimreward-can-dos-by-iterating-predictions-blocking-funds-pashov-audit-group-none-mcp_2025-08-07-markdown
    - l-03-blacklisted-users-tokens-are-stuck-after-a-win-pashov-audit-group-none-mcp_2025-08-07-markdown
    - l-02-some-assets-may-be-locked-in-the-contract-if-treasury-is-address0-pashov-audit-group-none-mcp_2025-08-07-markdown
    - h-5-adversary-can-break-deposit-queue-and-cause-loss-of-funds-sherlock-none-y2k-git
    - m-5-malicious-user-can-make-rolloverqueue-never-get-processed-sherlock-none-y2k-git
  incidentes:
    - "MCP — claimReward() DoS by iterating predictions, blocking all funds, H-01 (Pashov 2025)"
    - "MCP — blacklisted users tokens stuck after win (claim mechanism fails for specific addresses), L-03 (Pashov 2025)"
    - "Y2K Finance v2 — adversary breaks deposit queue causing loss of funds, H-5 (Sherlock 2023)"
    - "Y2K Finance v2 — malicious user makes rollover queue never get processed, M-5 (Sherlock 2023)"
  verificado: true
  confianza: alta

- id: pm-017
  titulo: Reentrancy en Outcome Token Operations — ERC-1155 Callbacks Exploitables
  causa_raiz: |
    Los outcome tokens de prediction markets son frecuentemente ERC-1155 (Gnosis CTF,
    UBET, Abster). Las funciones safeTransferFrom y safeBatchTransferFrom de ERC-1155
    invocan callbacks (onERC1155Received) en el receptor. Si el contrato de prediction
    market actualiza estado (balances, pools, payouts) DESPUES de transferir tokens
    ERC-1155, un atacante puede re-entrar en el contrato durante el callback y explotar
    el estado inconsistente.
  como_funciona: |
    1. Funcion removeCollateral() en un funding pool:
       a. Calcula shares a quemar
       b. Transfiere ERC-1155 tokens al usuario via safeTransferFrom (callback!)
       c. Actualiza el state (quema shares, actualiza valueHighPoint)
    2. En el callback onERC1155Received, atacante re-entra:
       a. Llama a removeCollateral() de nuevo
       b. Las shares aun no se quemaron → puede retirar de nuevo
       c. Double-withdraw del collateral

    Variante con ParentFundingPool:
    1. removeChildShares() envia child shares antes de quemarlas
    2. Atacante re-entra → quema shares de otros usuarios
  invariante: |
    function check_reentrancy_safe(bytes32 marketId) internal view {
        // Verificar que el estado se actualiza ANTES de transfers externos
        // (checks-effects-interactions pattern)
        t(!_reentrancyGuardEntered,
          "PM-017: reentrancy detected during outcome token operation");
    }
  que_mirar:
    - "Las funciones que transfieren ERC-1155 siguen checks-effects-interactions?"
    - "Hay reentrancy guard en las funciones que hacen transfers de outcome tokens?"
    - "El contrato actualiza balances/shares ANTES o DESPUES del safeTransferFrom?"
    - "Hay callbacks en ERC-777 tokens usados como collateral?"
    - "Las funciones batch del ERC-1155 tienen proteccion adicional?"
  como_se_arregla: |
    - ReentrancyGuard (OpenZeppelin) en TODAS las funciones que hacen transfers
    - Checks-Effects-Interactions: actualizar estado ANTES de llamar safeTransferFrom
    - Preferir transfer() sobre safeTransferFrom() si el receptor no necesita callback
    - Auditar todos los paths que invocan onERC1155Received
  trampas:
    - "ERC-1155 callbacks son OBLIGATORIOS por el standard — no se puede simplemente no llamarlos"
    - "El reentrancy guard protege funciones individuales — pero cross-function reentrancy (entrar en funcion B desde callback de funcion A) requiere global guard"
    - "Read-only reentrancy no es detectada por ReentrancyGuard clasico"
  solodit_ids:
    - h-03-sending-child-shares-before-burning-shares-allow-reentrancy-vulnerability-in-parentfundingpoolremovechildshares-0x52-none-ubet-markdown
    - l-02-transferring-erc1155-tokens-before-applying-parent-return-ops-allowing-reentrancy-0x52-none-ubet-parlay-markdown
    - reentrance-to-drain-funds-if-approved-token-is-a-callback-token-erc777-zokyo-none-xyro-markdown
    - h-01-claim-allows-payouts-from-an-arbitrary-token-pool-not-the-games-token-shieldify-none-abster-freefall-markdown
  incidentes:
    - "UBET — sending child shares before burning allows reentrancy in ParentFundingPool#removeChildShares, H-03 (0x52 audit 2023)"
    - "UBET Parlay — transferring ERC-1155 tokens before applying parent return ops allowing reentrancy, L-02 (0x52 audit)"
    - "Xyro — reentrancy to drain funds if approved token is ERC-777 callback token (Zokyo audit 2023)"
    - "Abster FreeFall — claim allows payouts from arbitrary token pool (wrong pool used in claim), H-01 (Shieldify audit)"
  verificado: true
  confianza: alta

- id: pm-018
  titulo: Depeg Prediction Vault Imbalance — Asimetria entre Risk y Hedge Vaults
  causa_raiz: |
    En protocolos de prediccion de depeg (Y2K Finance), los usuarios depositan en
    vaults "risk" (apuestan a que NO habra depeg) o "hedge" (apuestan a que SI habra
    depeg). El payout de un lado depende de cuanto deposito el otro lado. Si un vault
    tiene depositos y el otro no (o muy pocos), los ganadores reciben nada o casi nada.

    Adicionalmente, el modelo de epochs (periodos fijos) crea edge cases en los
    boundaries: que pasa si el depeg ocurre entre epochs, o si un epoch empieza
    mientras el depeg ya esta en curso?
  como_funciona: |
    Vault imbalance:
    1. Risk vault: 1000 USDC depositados (apuestan a NO depeg)
    2. Hedge vault: 0 USDC depositados (nadie apuesta a depeg)
    3. Ocurre un depeg → hedge deberia ganar
    4. Pero hedge vault esta vacio → no hay nadie para cobrar
    5. Los risk vault users perdieron pero su dinero no fue a nadie → locked

    Epoch boundary:
    1. Epoch 1 termina a las 12:00 UTC, Epoch 2 empieza a las 12:01 UTC
    2. Depeg ocurre a las 12:00:30 UTC (entre epochs)
    3. Epoch 1 ya se resolvio como "no depeg" (antes de las 12:00)
    4. Epoch 2 empieza despues del depeg → ya empezo con depeg activo
    5. Ninguno de los dos epochs captura el depeg correctamente

    Fee drain:
    1. Fees se cobran del collateral del risk vault
    2. Si fees > collateral disponible, el vault se vuelve insolvente
    3. Los risk users no pueden retirar su deposito completo
  invariante: |
    function check_counterparty_vault_solvency(uint256 epochId) internal view {
        uint256 riskDeposits = riskVault.totalDeposits(epochId);
        uint256 hedgeDeposits = hedgeVault.totalDeposits(epochId);
        // Si un lado tiene depositos, el otro DEBE tener tambien
        // (o al menos manejar el caso de 0 deposits gracefully)
        if (riskDeposits > 0 && hedgeDeposits == 0) {
            // Verificar que risk users pueden retirar sus depositos
            uint256 riskBalance = collateralToken.balanceOf(address(riskVault));
            t(riskBalance >= riskDeposits,
              "PM-018: risk vault imbalanced — no hedge counterparty");
        }
    }
  que_mirar:
    - "Que pasa si un vault tiene depositos y el otro no?"
    - "Los fondos del perdedor se transfieren correctamente al ganador?"
    - "Hay gaps entre epochs donde un depeg no se captura?"
    - "Las fees se cobran del collateral? Pueden dejar insolvente al vault?"
    - "El oracle de depeg tiene staleness check?"
    - "Puede triggerEndEpoch() llamarse en un null epoch?"
  como_se_arregla: |
    - Si counterparty vault esta vacio, devolver fondos al otro lado (no lockear)
    - Epochs continuos sin gaps (epoch N+1 empieza cuando epoch N termina)
    - Fees se cobran separadamente del collateral (no reducen el payout pool)
    - Minimo deposito en ambos vaults para que el epoch sea valido
    - Null epoch detection: si un lado tiene 0 depositos, marcar como null y devolver
  trampas:
    - "Y2K Finance v2 (Carousel) resuelve parcialmente esto con auto-rollover — pero crea nuevos bugs de timing"
    - "El modelo de vault dual (risk/hedge) es inherentemente fragil en mercados con asimetria de participacion"
    - "Las fees sobre collateral son un design choice — pero crean edge cases de insolvencia"
  solodit_ids:
    - h-04-users-who-deposit-in-one-vault-can-lose-all-deposits-and-receive-nothing-when-counterparty-vault-has-no-deposits-code4rena-y2k-finance-y2k-finance-contest-git
    - h-07-risk-users-are-required-to-payout-if-the-price-of-the-pegged-asset-goes-higher-than-underlying-code4rena-y2k-finance-y2k-finance-contest-git
    - m-06-fees-are-taken-on-risk-collateral-code4rena-y2k-finance-y2k-finance-contest-git
    - m-2-controllerpeggedassetv2-triggerendepoch-function-can-be-called-even-if-epoch-is-null-epoch-leading-to-loss-of-funds-sherlock-none-y2k-git
    - m-13-null-epochs-will-freeze-rollovers-sherlock-none-y2k-git
    - m-11-arbitrum-sequencer-downtime-lasting-before-and-beyond-epoch-expiry-prevents-triggering-depeg-sherlock-none-y2k-git
    - h-4-when-rolling-over-user-will-lose-his-winnings-from-previous-epoch-sherlock-none-y2k-git
  incidentes:
    - "Y2K Finance v1 — users deposit in risk vault, hedge vault empty, all deposits lost with no counterparty, H-04 (Code4rena 2022, $50K+ at risk)"
    - "Y2K Finance v1 — risk users forced to payout when pegged asset goes HIGHER than underlying, H-07 (Code4rena 2022)"
    - "Y2K Finance v1 — fees taken on risk collateral reduce available payout, M-06 (Code4rena 2022)"
    - "Y2K Finance v2 — triggerEndEpoch can be called on null epoch, leading to loss of funds, M-2 (Sherlock 2023)"
    - "Y2K Finance v2 — null epochs freeze rollovers, M-13 (Sherlock 2023)"
    - "Y2K Finance v2 — Arbitrum sequencer downtime prevents triggering depeg, M-11 (Sherlock 2023)"
    - "Y2K Finance v2 — rolling over causes user to lose winnings from previous epoch, H-4 (Sherlock 2023)"
  verificado: true
  confianza: alta

---

## 2. Interacciones Peligrosas entre Componentes

```yaml
interaction_risks:
  - pair: [PredictionMarket, ConditionalTokenFramework]
    risk: "splitPosition/mergePositions desync con market state — tokens existentes para mercados ya resueltos"
    ejemplo: "PredictFun M-4: wrong questionId format for NegRiskCtfAdapter"

  - pair: [PredictionMarket, OracleResolution]
    risk: "Oracle update visible en mempool permite front-running de la resolucion"
    ejemplo: "PancakeSwap Prediction — Chainlink update front-running por bots MEV"

  - pair: [PredictionMarket, DisputeSystem]
    risk: "Bond escalation insuficiente permite resolver mercados incorrectamente"
    ejemplo: "Reality.eth — mercados de bajo valor sin disputadores"

  - pair: [PredictionAMM, CollateralPool]
    risk: "Donation/manipulation del MarketMaker corrompe pricing y bloquea trades"
    ejemplo: "UBET H-01 — donations freeze all buy/sell capability"

  - pair: [DepegVault, CounterpartyVault]
    risk: "Vault imbalance (uno vacio) lockea fondos del otro lado"
    ejemplo: "Y2K Finance H-04 — no counterparty deposits"

  - pair: [OutcomeToken, RewardDistribution]
    risk: "Claim iterativo sobre muchas predicciones causa DoS por gas"
    ejemplo: "MCP H-01 — claimReward DoS"

  - pair: [DisputeSystem, GovernanceToken]
    risk: "Flash loan de governance tokens permite controlar dispute votes"
    ejemplo: "Beanstalk 2022 — flash loan governance attack, $182M"

  - pair: [MultipleMarkets, SharedOracle]
    risk: "Manipulacion del oracle compartido impacta multiples mercados correlacionados"
    ejemplo: "Y2K M-01 — oracle per token instead of per pair"
```

---

## 3. Checklist de Auditoria Rapida

```
PREDICTION MARKET AUDIT CHECKLIST
═══════════════════════════════════

RESOLUCION
[ ] Que oracle se usa? Chainlink / UMA / Reality.eth / custom?
[ ] Hay staleness check en el oracle de resolucion?
[ ] Existe periodo de dispute despues de la resolucion propuesta?
[ ] Puede el mismo bloque tener bet + resolution? (front-running)
[ ] Hay buffer period antes del cierre donde no se aceptan bets?
[ ] Que pasa si el mercado no se resuelve? Hay timeout/void?

TOKENS Y ACCOUNTING
[ ] splitPosition mintea 1:1 para todos los outcomes?
[ ] mergePositions quema 1:1 para todos los outcomes?
[ ] Hay funciones de mint/burn que bypassen split/merge?
[ ] Rounding en redemption — mulDiv con direccion especificada?
[ ] sum(outcomeToken.totalSupply) == collateral locked?
[ ] minAmount para prevenir dust/rounding attacks?

MARKET MAKER
[ ] Que AMM se usa? LMSR / CPMM / order book?
[ ] sum(p_i) == 1.0 despues de cada trade (incluyendo fees)?
[ ] Slippage protection en buy/sell?
[ ] El parametro de liquidez es manipulable?
[ ] Donation attack en el AMM (can external deposits corrupt state)?

DISPUTE SYSTEM
[ ] Bond minimo vs valor del mercado — ratio adecuado?
[ ] Bond escalation factor >= 2x?
[ ] Dispute period >= 24h para mercados grandes?
[ ] Flash loan governance — usa snapshots o balance actual?
[ ] Hay backstop (arbitraje final) si el dispute no se resuelve?

TIMING
[ ] Buffer period antes del cierre?
[ ] Lock de transfers entre cierre y resolucion?
[ ] Puede haber late deposits que diluyan (parimutuel)?
[ ] Epochs continuos sin gaps?
[ ] Que pasa con eventos que ocurren entre epochs?

GAS Y DOS
[ ] claimReward tiene bounded loop?
[ ] Limite de predicciones por usuario?
[ ] Batch redeem tiene limite de gas?
[ ] Min bet size para prevenir spam?

REENTRANCY
[ ] ERC-1155 safeTransferFrom con callback — CEI pattern?
[ ] ReentrancyGuard en todas las funciones con transfers?
[ ] ERC-777 como collateral — callback reentrancy?

MARKET CREATION
[ ] Creacion permissionless o curated?
[ ] Duplicate market detection?
[ ] Single-outcome markets bloqueados?
[ ] Fee de creacion anti-spam?
```

---

## 4. Grep Patterns para Deteccion Rapida

```bash
# Resolution oracle
grep -rn "resolve\|reportOutcome\|settleMarket\|triggerEnd\|finalizeOutcome" contracts/

# Conditional tokens (Gnosis CTF)
grep -rn "splitPosition\|mergePositions\|reportPayouts\|redeemPositions\|getOutcomeSlotCount" contracts/

# Timing boundaries
grep -rn "closesAtTimestamp\|epochEnd\|marketClose\|deadline\|expiryTime\|roundEnd" contracts/

# Dispute/bond
grep -rn "dispute\|challenge\|bond\|escalat\|propose\|arbitrat" contracts/

# Parimutuel / pool
grep -rn "parimutuel\|pool.*bet\|wager\|stake.*outcome\|deposit.*side" contracts/

# AMM pricing
grep -rn "LMSR\|costFunction\|outcomePrice\|probability\|marginalPrice\|getPrice.*outcome" contracts/

# ERC-1155 callbacks (reentrancy surface)
grep -rn "onERC1155Received\|safeTransferFrom\|safeBatchTransfer\|_beforeTokenTransfer" contracts/

# Claim/redeem loops
grep -rn "claimReward\|claimWinnings\|redeemAll\|batchRedeem" contracts/

# NegRisk / multi-outcome
grep -rn "negRisk\|questionId\|conditionId\|outcomeCount\|numOutcomes" contracts/

# Y2K / depeg specific
grep -rn "triggerDepeg\|triggerEndEpoch\|epochBegin\|epochEnd\|rollover\|carousel" contracts/
```

---

## 5. Recursos y Referencias

```yaml
audits_clave:
  - protocolo: "Y2K Finance v1"
    auditor: "Code4rena"
    fecha: "Oct 2022"
    findings: "9 High, 16 Medium"
    link: "code4rena.com/reports/2022-09-y2k-finance"

  - protocolo: "Y2K Finance v2 (Earthquake)"
    auditor: "Sherlock"
    fecha: "Mar 2023"
    findings: "5 High, 14 Medium"
    link: "audits.sherlock.xyz/contests/y2k"

  - protocolo: "Augur v2"
    auditor: "OpenZeppelin"
    fecha: "2020"
    findings: "20+ Low/Medium (code quality focus)"
    link: "blog.openzeppelin.com/augur-core-v2-audit"

  - protocolo: "UBET"
    auditor: "0x52"
    fecha: "2023"
    findings: "3 High (reentrancy, pricing corruption, fee loss)"
    link: "solodit — 0x52 ubet audit"

  - protocolo: "Myriad (Prediction Market)"
    auditor: "Cyfrin"
    fecha: "2024"
    findings: "Multiple Medium/Low (slippage, rounding, market stuck)"
    link: "solodit — cyfrin myriad"

  - protocolo: "MCP (Meme Prediction Market)"
    auditor: "Pashov Audit Group"
    fecha: "Aug 2025"
    findings: "1 High (DoS), 3 Medium (late participation, gas)"
    link: "solodit — pashov mcp"

  - protocolo: "PredictFun Lending Market"
    auditor: "Sherlock"
    fecha: "2024"
    findings: "5 Medium (NegRisk adapter, collateral seizure, fees)"
    link: "audits.sherlock.xyz/contests/predictfun"

  - protocolo: "Xyro"
    auditor: "Zokyo"
    fecha: "2023"
    findings: "Multiple (reentrancy, price manipulation, fee issues)"
    link: "solodit — zokyo xyro"

  - protocolo: "Abster FreeFall"
    auditor: "Shieldify"
    fecha: "2024"
    findings: "1 High (arbitrary pool claim), 3 Medium (multiplier freeze, fee drain)"
    link: "solodit — shieldify abster"

  - protocolo: "Azuro"
    auditor: "Pashov"
    fecha: "2023"
    findings: "3 Medium (admin sanitization)"
    link: "solodit — pashov azuro"

  - protocolo: "Float Capital"
    auditor: "Sherlock"
    fecha: "2022"
    findings: "1 High, 4 Medium (Chainlink gap, USDC, funding rate)"
    link: "audits.sherlock.xyz/contests/float-capital"

incidentes_reales:
  - nombre: "Beanstalk Governance Attack"
    fecha: "Apr 2022"
    perdida: "$182M"
    detalle: "Flash loan de governance tokens para aprobar proposal malicioso — vector aplicable a cualquier dispute system con token voting"
    relevancia_pm: "Identico vector para flash loan governance de dispute resolution en prediction markets"

  - nombre: "Mango Markets Oracle Manipulation"
    fecha: "Oct 2022"
    perdida: "$116M"
    detalle: "Avraham Eisenberg manipulo oracle de MNGO para tomar posiciones correlacionadas"
    relevancia_pm: "Cross-market correlated position attack — vector PM-015"

  - nombre: "PancakeSwap Prediction Bot Exploitation"
    fecha: "2021-2023 (continuo)"
    perdida: "~$5M+ estimado (extraido de LPs)"
    detalle: "Bots front-running Chainlink updates para apostar en outcome correcto"
    relevancia_pm: "Binary option front-running — vector PM-006"

  - nombre: "Augur Invalid Market Hunting"
    fecha: "2018-2019"
    perdida: "~$100K+ en mercados afectados"
    detalle: "Creacion de mercados con preguntas ambiguas que resolvian como INVALID"
    relevancia_pm: "Market creation griefing + invalid resolution — vectores PM-002 y PM-013"
```
