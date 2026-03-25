grep_targets:
  - "solver"
  - "filler"
  - "settle"
  - "settlement"
  - "fillOrder"
  - "resolveOrder"
  - "execute"
  - "swap"
  - "dutch"
  - "decay"
  - "exclusiveFiller"
  - "reactor"
  - "GPv2"
  - "cowswap"
  - "batch"
  - "surplus"
  - "partialFill"
  - "intentId"
  - "orderHash"
  - "nonce"
  - "preInteraction"
  - "postInteraction"
  - "bond"
  - "stake"
  - "ERC7683"

# Briefing: Solver-Based & Intent-Based Protocol Vulnerabilities

## Contexto del dominio
Los protocolos basados en solvers e intents (CoW Protocol/GPv2, UniswapX, 1inch Fusion,
Across, ERC-7683) delegan la ejecución de trades a terceros (solvers/fillers/resolvers)
que compiten por dar al usuario el mejor precio. A diferencia de AMMs tradicionales,
el usuario firma una intent off-chain y el solver la ejecuta on-chain. Los bugs más
críticos involucran:
- Solvers que extraen valor del usuario vía manipulación de precios o surplus
- Replay de firmas de órdenes entre chains, protocolos, o tras fills parciales
- Manipulación de curvas de decay en Dutch auctions para ejecutar al peor precio
- Explotación de períodos de exclusividad para bloquear competencia
- Race conditions en settlement cross-chain donde el solver cobra sin entregar
- Hooks pre/post-interacción que permiten reentrancy o extracción de fondos
- Bypass de validación en reactores que permiten fills maliciosos

---

patterns:

- id: SOLVER-01
  titulo: Solver Collusion — Precio Subóptimo Coordinado
  causa_raiz: |
    En sistemas competitivos de solvers, la calidad de ejecución depende de que los solvers
    compitan genuinamente. Si dos o más solvers se coordinan para dar al usuario el precio
    mínimo aceptable (minAmountOut) en vez del mejor precio disponible, el surplus se lo
    quedan los solvers. El protocolo no puede detectar colusión si todos los solvers
    reportan precios similares y no hay un benchmark externo on-chain.
  como_funciona: |
    1. Usuario firma intent: swap 1000 USDC → ETH, minAmountOut = 0.4 ETH
    2. El precio real del mercado daría 0.42 ETH (surplus potencial: 0.02 ETH)
    3. Solver A y Solver B se coordinan off-chain: ambos ofertan exactamente 0.4001 ETH
    4. El protocolo elige a Solver A (marginalmente mejor)
    5. Solver A ejecuta el swap en un DEX a 0.42 ETH, entrega 0.4001 al usuario
    6. Solver A se queda con 0.0199 ETH de surplus (~$50 en un trade de $1000)
    7. Solver A comparte parte con Solver B como incentivo para mantener la colusión

    Variante — Ring trading:
    - En CoW Protocol, los solvers pueden crear batches que incluyen órdenes internas
    - Dos solvers crean órdenes ficticias que generan "CoW" (coincidence of wants) falsos
    - El batch parece eficiente pero el precio es peor que el del mercado externo
  invariante: |
    function check_solver_price_competitive(
        uint256 amountOut,
        uint256 oraclePrice,
        uint256 amountIn,
        uint256 maxSlippage // e.g., 50 bps
    ) internal pure {
        uint256 expectedOut = (amountIn * oraclePrice) / 1e18;
        uint256 minAcceptable = expectedOut * (10000 - maxSlippage) / 10000;
        t(amountOut >= minAcceptable,
          "SOLVER-01: solver price significantly worse than oracle");
    }
  que_mirar:
    - "¿El protocolo tiene un mecanismo de scoring que penalice solvers que consistentemente dan precios al mínimo?"
    - "¿Hay un oráculo de referencia contra el que se compare el precio del solver?"
    - "¿El batch settlement permite que el solver incluya órdenes propias?"
    - "¿Los solvers pueden ver las órdenes de otros solvers antes de ofertar?"
  como_se_arregla: |
    - Implementar scoring de calidad por solver (ratio surplus/volumen histórico)
    - Order flow auction: los solvers pujan por el derecho a ejecutar, no solo por el precio
    - Commit-reveal para las ofertas de los solvers (evita que vean las ofertas de otros)
    - Comparar contra TWAP on-chain como benchmark mínimo
  trampas:
    - "CoW Protocol mitiga parcialmente esto con el competition mecanismo de solvers, pero la colusión off-chain es difícil de prevenir on-chain"
    - "UniswapX usa Dutch auctions que reducen la ventana de colusión — el precio decae con el tiempo"
    - "1inch Fusion tiene resolvers whitelistados que pueden coordinarse si el whitelist es pequeño"
  solodit_ids:
    - h-04-solvers-can-collude-to-increase-their-surplus-sherlock-none-cow-protocol-git
  incidentes:
    - "CoW Protocol Sherlock contest — H-04: solvers can collude to increase surplus"
  verificado: true
  confianza: 80

- id: SOLVER-02
  titulo: Order Signature Replay — Cross-Chain o Post Partial Fill
  causa_raiz: |
    Las órdenes firmadas off-chain son válidas hasta que expiran o se llenan completamente.
    Si el hash de la orden no incluye chainId, o si el nonce no se marca como usado
    tras un fill parcial que agota el balance del usuario, la firma puede reutilizarse.
    En protocolos multi-chain, la misma firma puede ejecutarse en múltiples chains si
    el DOMAIN_SEPARATOR no incluye el chainId correcto.
  como_funciona: |
    Variante A — Cross-chain replay:
    1. Usuario firma orden en Ethereum: swap 1000 USDC → ETH
    2. El DOMAIN_SEPARATOR del contrato no incluye block.chainid (usa un chainId hardcodeado)
    3. Después de un hard fork (como ETH/ETH Classic), la firma es válida en ambas chains
    4. El solver ejecuta la orden en ambas chains — el usuario pierde 2000 USDC total

    Variante B — Post partial fill:
    1. Usuario firma orden por 1000 USDC con partialFill habilitado
    2. Solver llena 500 USDC (fill parcial legítimo)
    3. El contrato marca filledAmount[orderHash] = 500
    4. El usuario cancela la orden (o cree que se llenó)
    5. El solver usa la misma firma para llenar otros 500 USDC
    6. Si el usuario ya no tiene USDC, la tx revierte — sin daño
    7. Pero si el usuario recibió más USDC mientras tanto, se ejecuta sin su consentimiento

    Variante C — Nonce reuse:
    1. En 1inch Fusion, el nonce del maker se incrementa con cada orden
    2. Si hay un bug en el incremento (overflow, reset), ordenes antiguas reviven
  invariante: |
    // Ghost: track de nonces usados por chain
    mapping(uint256 => mapping(address => mapping(uint256 => bool))) ghost_nonceUsed;

    function check_no_signature_replay(
        uint256 chainId, address signer, uint256 nonce
    ) internal {
        t(!ghost_nonceUsed[chainId][signer][nonce],
          "SOLVER-02: order signature replayed");
        ghost_nonceUsed[chainId][signer][nonce] = true;
    }

    function check_domain_separator_includes_chainid(
        bytes32 domainSeparator, uint256 expectedChainId
    ) internal pure {
        // domainSeparator debe recalcularse con block.chainid, no un valor hardcodeado
        bytes32 expected = keccak256(abi.encode(
            TYPE_HASH, NAME_HASH, VERSION_HASH, expectedChainId, address(this)
        ));
        t(domainSeparator == expected,
          "SOLVER-02: DOMAIN_SEPARATOR does not include current chainId");
    }
  que_mirar:
    - "¿El DOMAIN_SEPARATOR se calcula en el constructor (immutable) o en cada llamada (con block.chainid)?"
    - "¿El nonce del maker se invalida completamente o solo se decrementa el fillable amount?"
    - "¿La orden incluye un deadline que limita la ventana de replay?"
    - "¿Hay una función invalidateNonce() que el usuario pueda llamar proactivamente?"
  como_se_arregla: |
    - DOMAIN_SEPARATOR debe usar block.chainid (recalcular si cambia, como hace OpenZeppelin EIP712)
    - Nonce invalidation: una vez usada cualquier porción, el usuario debe poder invalidar el resto
    - Deadline corto por defecto (e.g., 10 minutos para swaps, no 24 horas)
    - Cancel-by-nonce: permitir invalidar ranges de nonces (como Permit2)
  trampas:
    - "GPv2 de CoW Protocol usa un DOMAIN_SEPARATOR inmutable — funciona en Ethereum pero si se deploya en otra chain sin cambiar, permite replay"
    - "UniswapX usa Permit2 que recalcula DOMAIN_SEPARATOR correctamente"
    - "1inch Fusion v2 tiene invalidateOrder() pero requiere gas — durante congestión puede ser demasiado lento"
  solodit_ids:
    - h-03-signatures-can-be-replayed-across-chains-sherlock-none-cow-protocol-git
    - m-02-hardcoded-chain-id-in-domain-separator-sherlock-uniswapx-git
  incidentes: []
  verificado: true
  confianza: 90

- id: SOLVER-03
  titulo: Dutch Auction Decay Manipulation — Timing the Decay Curve
  causa_raiz: |
    En UniswapX y protocolos similares, las órdenes usan Dutch auctions donde el precio
    ofrecido al filler decae con el tiempo (el usuario ofrece más a medida que pasa tiempo).
    Si un filler puede manipular cuándo se incluye la tx en un bloque (vía MEV o
    colusión con block builders), puede esperar al punto óptimo de la curva de decay
    donde maximiza su profit a costa del usuario.
  como_funciona: |
    1. Usuario firma DutchOrder: vendo 1 ETH, precio inicial = 2000 USDC, precio final = 1900 USDC
    2. La curva de decay es lineal durante 10 minutos (100 USDC de rango)
    3. Al bloque 0 (inicio): el filler debe pagar 2000 USDC — no hay profit
    4. Al bloque N (60% del decay): el filler paga 1940 USDC — profit = 60 USDC
    5. El filler tiene un acuerdo con un block builder para incluir su tx exactamente
       en el bloque que maximiza el decay sin que otro filler lo llene antes
    6. El filler paga al builder 20 USDC como kickback, se queda con 40 USDC
    7. El usuario recibe 1940 USDC en vez de los ~2000 que habría recibido con competencia real

    Variante — Decay cliff abuse:
    - Si la curva tiene steps (no es continua), hay puntos donde el precio cae abruptamente
    - El filler espera exactamente al cliff para maximizar el salto
  invariante: |
    function check_dutch_auction_fill_timing(
        uint256 fillTimestamp,
        uint256 auctionStartTime,
        uint256 auctionDuration,
        uint256 maxAcceptableDecayBps // e.g., 200 = 2%
    ) internal pure {
        uint256 elapsed = fillTimestamp - auctionStartTime;
        uint256 decayBps = (elapsed * 10000) / auctionDuration;
        t(decayBps <= maxAcceptableDecayBps,
          "SOLVER-03: dutch auction filled too late in decay curve");
    }

    function check_decay_curve_granularity(
        uint256[] memory decaySteps,
        uint256 maxStepSizeBps // e.g., 50 = 0.5%
    ) internal pure {
        for (uint256 i = 1; i < decaySteps.length; i++) {
            uint256 stepSize = decaySteps[i] > decaySteps[i-1]
                ? decaySteps[i] - decaySteps[i-1]
                : decaySteps[i-1] - decaySteps[i];
            t(stepSize <= maxStepSizeBps,
              "SOLVER-03: decay curve step too large — cliff abuse possible");
        }
    }
  que_mirar:
    - "¿La curva de decay es continua o tiene steps discretos?"
    - "¿El usuario puede configurar el rango de decay (startPrice vs endPrice)?"
    - "¿Hay un mecanismo de 'price improvement' que recompense fills tempranos?"
    - "¿El protocolo tiene un oráculo de referencia para detectar fills al peor precio posible?"
  como_se_arregla: |
    - Curvas de decay suaves (no steps) para eliminar cliffs explotables
    - Período de exclusividad corto (2-5 bloques) para incentivar fills rápidos
    - Price improvement scoring: penalizar solvers que consistentemente llenan tarde
    - RFQ (Request for Quote) como complemento — precio fijo por un período corto
  trampas:
    - "UniswapX V2 mitiga esto con exclusiveFiller que tiene prioridad en los primeros bloques"
    - "En L2s con bloques rápidos (Arbitrum: cada tx es un bloque), la granularidad del decay es mucho mayor"
    - "Block builders en Ethereum pueden ser cómplices del filler — Flashbots Protect no resuelve esto completamente"
  solodit_ids:
    - m-01-dutch-auction-decay-can-be-manipulated-by-fillers-sherlock-uniswapx-git
    - m-04-filler-can-delay-execution-to-maximize-decay-sherlock-uniswapx-git
  incidentes: []
  verificado: true
  confianza: 85

- id: SOLVER-04
  titulo: Exclusive Filler Period Exploitation — Bloqueo de Competencia
  causa_raiz: |
    UniswapX y protocolos similares permiten que el usuario designe un "exclusive filler"
    que tiene prioridad para ejecutar la orden durante un período inicial. Si el exclusive
    filler no ejecuta y el período de exclusividad es demasiado largo, o si el filler
    puede extender el período manipulando parámetros, el usuario queda atrapado con un
    precio peor mientras nadie más puede ejecutar.
  como_funciona: |
    Variante A — Exclusive filler griefing:
    1. Usuario firma orden con exclusiveFiller = Solver A, exclusivityPeriod = 60 segundos
    2. Solver A ve que el precio actual le da poco profit
    3. Solver A NO ejecuta la orden durante los 60 segundos de exclusividad
    4. Después de 60 segundos, la orden está abierta pero el decay ya consumió 50% del rango
    5. Solver B ejecuta al precio decayado — usuario pierde el surplus del período de exclusividad

    Variante B — Override de exclusividad:
    1. El parámetro exclusiveFiller se pasa en el orderData
    2. Si la validación del reactor no verifica que el caller == exclusiveFiller durante el período
    3. Cualquier filler puede ejecutar durante el período exclusivo, eliminando la ventaja competitiva
    4. O peor: un filler malicioso puede front-runear al exclusivo con un precio peor

    Variante C — Exclusivity override amount manipulation:
    1. UniswapX tiene un exclusivityOverrideBps que permite a no-exclusivos llenar pagando más
    2. Si este valor es 0 o muy bajo, la exclusividad no tiene efecto real
    3. Si el usuario no entiende este parámetro, pierde la protección esperada
  invariante: |
    function check_exclusive_filler_respected(
        address caller,
        address exclusiveFiller,
        uint256 blockTimestamp,
        uint256 exclusivityDeadline
    ) internal pure {
        if (blockTimestamp <= exclusivityDeadline && exclusiveFiller != address(0)) {
            t(caller == exclusiveFiller,
              "SOLVER-04: non-exclusive filler executing during exclusivity period");
        }
    }

    function check_exclusivity_period_reasonable(
        uint256 exclusivityDuration
    ) internal pure {
        t(exclusivityDuration <= 120, // max 2 minutos
          "SOLVER-04: exclusivity period too long — user at risk of decay");
    }
  que_mirar:
    - "¿El reactor verifica que msg.sender == exclusiveFiller durante el período exclusivo?"
    - "¿Qué pasa si el exclusiveFiller es address(0) — todos pueden ejecutar?"
    - "¿El período de exclusividad se descuenta del decay total o es adicional?"
    - "¿El usuario puede cancelar si el exclusive filler no ejecuta a tiempo?"
  como_se_arregla: |
    - Exclusividad corta (5-15 segundos / 2-5 bloques)
    - Si el exclusive filler no ejecuta, el precio no decae durante el período — protege al usuario
    - Penalización (slashing) para exclusive fillers que no ejecutan consistentemente
    - Override mechanism: otros fillers pueden ejecutar pagando un premium al usuario
  trampas:
    - "UniswapX V2 implementó exclusivityOverrideBps — pero si es demasiado alto, nadie puede competir"
    - "En Sherlock contest de UniswapX se encontró que el exclusive filler podía griefear sin consecuencias"
  solodit_ids:
    - m-03-exclusive-filler-can-grief-users-by-not-filling-sherlock-uniswapx-git
    - h-02-exclusivity-period-can-be-bypassed-sherlock-uniswapx-git
  incidentes: []
  verificado: true
  confianza: 85

- id: SOLVER-05
  titulo: Intent Expiry/Deadline Manipulation — Ejecución Stale
  causa_raiz: |
    Las órdenes basadas en intents tienen un deadline (timestamp de expiración). Si el
    solver puede manipular cuándo se ejecuta la orden (retrasándola intencionalmente),
    puede ejecutar una orden cuyo precio ya no refleja el mercado. Esto es especialmente
    peligroso en mercados volátiles donde el precio puede moverse significativamente
    entre la firma y la ejecución.
  como_funciona: |
    1. Usuario firma orden: swap 1000 USDC → ETH, deadline = now + 1 hora, minOut = 0.4 ETH
    2. Al momento de firmar, 0.4 ETH = un buen trade (mercado a 0.42 ETH)
    3. 55 minutos después, ETH sube a 0.50 ETH/$2500
    4. El solver ejecuta la orden justo antes del deadline
    5. El solver compra 0.4 ETH por 1000 USDC (precio de la orden) pero el mercado está a 0.50 ETH
    6. El usuario recibe sus 0.4 ETH (cumple minOut) pero pierde 0.1 ETH de oportunidad (~$250)
    7. El solver se queda con la diferencia usando un DEX al precio de mercado

    Variante — Deadline extension:
    - Si el protocolo permite "renovar" un deadline expirado con una nueva tx del solver
    - Las órdenes "zombie" pueden ejecutarse mucho después de que el usuario las olvidó
  invariante: |
    function check_order_not_stale(
        uint256 orderTimestamp,
        uint256 fillTimestamp,
        uint256 maxStaleness // e.g., 300 = 5 minutos
    ) internal pure {
        t(fillTimestamp - orderTimestamp <= maxStaleness,
          "SOLVER-05: order executed too long after signing — stale intent");
    }

    function check_deadline_not_extended(
        uint256 originalDeadline,
        uint256 currentDeadline
    ) internal pure {
        t(currentDeadline <= originalDeadline,
          "SOLVER-05: order deadline was extended beyond original");
    }
  que_mirar:
    - "¿El usuario puede cancelar órdenes pendientes on-chain antes del deadline?"
    - "¿Hay un mecanismo de 'refresh' que extienda deadlines sin nueva firma del usuario?"
    - "¿El deadline es parte del hash firmado o un parámetro modificable?"
    - "¿El protocolo advierte al usuario sobre deadlines largos en el frontend?"
  como_se_arregla: |
    - Deadlines cortos por defecto (5-15 minutos para swaps spot)
    - El deadline DEBE ser parte del hash firmado (immutable una vez firmado)
    - Cancel-on-chain: función económica para invalidar órdenes pendientes
    - Warn en frontend si el deadline excede 30 minutos
  trampas:
    - "En 1inch Fusion, el resolver puede ejecutar la orden en cualquier momento antes del deadline"
    - "CoW Protocol batches se ejecutan en ventanas de ~30s, limitando naturalmente el staleness"
    - "UniswapX usa nonce-based cancellation que es más eficiente que tx-based"
  solodit_ids:
    - m-07-stale-orders-can-be-executed-at-unfavorable-prices-sherlock-uniswapx-git
    - m-01-lack-of-deadline-check-for-intent-execution-cantina-none-across-v3-markdown
  incidentes: []
  verificado: true
  confianza: 80

- id: SOLVER-06
  titulo: Solver Front-Running de Intents Antes del Settlement On-Chain
  causa_raiz: |
    Las intents se firman off-chain y se transmiten a un pool de solvers (via API o
    mempool). Un solver malicioso puede ver la intent del usuario, ejecutar un trade
    adelantado en un DEX on-chain para mover el precio, y luego ejecutar la intent
    del usuario al precio movido. Esto es MEV clásico aplicado al modelo de intents.
  como_funciona: |
    1. Usuario firma intent: comprar 10 ETH con USDC, maxPrice = 2050 USDC/ETH
    2. Precio actual del mercado: 2000 USDC/ETH
    3. Solver A recibe la intent vía la API del protocolo
    4. Solver A compra 10 ETH en Uniswap → precio sube a 2030 USDC/ETH
    5. Solver A ejecuta la intent del usuario a 2040 USDC/ETH (dentro del maxPrice)
    6. Solver A vende los 10 ETH que compró a 2030 → profit = ~$300
    7. El usuario recibe 10 ETH pero pagó $400 más de lo necesario

    Variante — Sandwich vía intent relay:
    - El solver relay es público (cualquiera puede ver las intents pendientes)
    - Un searcher (no solver) ve la intent y sandwichea la ejecución on-chain
    - El solver legítimo ejecuta la intent pero el precio ya está movido
  invariante: |
    function check_no_price_impact_from_solver(
        uint256 preBuyPrice,
        uint256 executionPrice,
        uint256 maxImpactBps // e.g., 30 = 0.3%
    ) internal pure {
        uint256 impact = executionPrice > preBuyPrice
            ? ((executionPrice - preBuyPrice) * 10000) / preBuyPrice
            : 0;
        t(impact <= maxImpactBps,
          "SOLVER-06: execution price shows suspicious pre-trade impact");
    }
  que_mirar:
    - "¿El relay de intents es público o encriptado?"
    - "¿Los solvers pueden ver las intents de otros usuarios antes de ofertar?"
    - "¿Hay un mecanismo de commit-reveal para las intents?"
    - "¿El protocolo usa un relay privado como Flashbots Protect?"
  como_se_arregla: |
    - Intent relay encriptado: las intents solo se revelan al solver seleccionado
    - Commit-reveal: el solver commitea primero, luego revela la ejecución
    - Batch settlement (CoW Protocol): las intents se ejecutan en un batch atómico
    - Private mempool o MEV-Share para compartir el surplus con el usuario
  trampas:
    - "CoW Protocol mitiga esto con batch auctions — no hay front-running individual posible"
    - "UniswapX con fillers exclusivos reduce el front-running pero no lo elimina (el exclusive filler puede auto-sandwich)"
    - "1inch Fusion relay es privado pero los resolvers aún pueden hacer back-running"
  solodit_ids:
    - h-01-solver-can-frontrun-user-intents-via-dex-sherlock-none-cow-protocol-git
  incidentes:
    - "Wintermute was accused of front-running CoW Protocol orders in 2023"
  verificado: true
  confianza: 75

- id: SOLVER-07
  titulo: CoW Protocol Batch Settlement Manipulation
  causa_raiz: |
    En CoW Protocol, los solvers crean batches de órdenes que se ejecutan atómicamente.
    El solver elige qué órdenes incluir, en qué orden, y cuáles excluir. Un solver
    malicioso puede manipular la composición del batch para maximizar su surplus a costa
    de los usuarios, o incluir órdenes propias (wash trades) para extraer valor.
  como_funciona: |
    Variante A — Selective inclusion:
    1. Hay 10 órdenes pendientes: 5 de compra ETH, 5 de venta ETH
    2. El solver incluye solo las órdenes que le dan más surplus
    3. Las órdenes "malas" para el solver se quedan sin ejecutar
    4. Los usuarios con órdenes excluidas sufren delay y potencial pérdida por precio stale

    Variante B — Wash trade injection:
    1. El solver crea una orden propia: vender 100 ETH a un precio ligeramente mejor
    2. Incluye esta orden en el batch junto con órdenes de usuarios
    3. La orden del solver se ejecuta contra las de usuarios (CoW — coincidence of wants)
    4. El solver se queda con el surplus generado por el "matching" artificial
    5. Los usuarios reciben su minAmountOut pero pierden el surplus que habrían tenido
       si se hubieran matcheado entre ellos directamente

    Variante C — Uniform Clearing Price manipulation:
    1. CoW Protocol usa un precio uniforme de clearing (UCP) para cada par de tokens
    2. El solver elige el UCP que maximiza su surplus total
    3. Si incluye órdenes dummy que sesgan el UCP, puede mover el precio a su favor
  invariante: |
    function check_batch_surplus_distribution(
        uint256 totalSurplusGenerated,
        uint256 surplusToUsers,
        uint256 surplusToSolver,
        uint256 maxSolverShareBps // e.g., 5000 = 50%
    ) internal pure {
        uint256 solverShareBps = (surplusToSolver * 10000) / totalSurplusGenerated;
        t(solverShareBps <= maxSolverShareBps,
          "SOLVER-07: solver taking disproportionate share of batch surplus");
    }

    function check_no_wash_trades_in_batch(
        address[] memory makers,
        address solver
    ) internal pure {
        for (uint256 i = 0; i < makers.length; i++) {
            t(makers[i] != solver,
              "SOLVER-07: solver has own orders in the batch — wash trade risk");
        }
    }
  que_mirar:
    - "¿El protocolo permite al solver incluir sus propias órdenes en el batch?"
    - "¿Hay un mecanismo de auditoría post-batch que verifique el UCP contra oráculos?"
    - "¿Los solvers pueden elegir qué órdenes excluir sin penalización?"
    - "¿El surplus se distribuye proporcionalmente o el solver se queda con todo?"
  como_se_arregla: |
    - Prohibir que el solver tenga órdenes propias en el batch (o flaggearlas)
    - Verificación post-settlement del UCP contra TWAP oracles
    - Surplus sharing: el surplus se reparte entre usuarios y solver según reglas fijas
    - Slashing: si el batch produce precios peores que el oráculo, el solver pierde stake
  trampas:
    - "CoW Protocol v2 implementó un driver competitivo donde los solvers compiten — pero si solo hay 1-2 solvers activos, la competencia es limitada"
    - "La verificación del batch ocurre off-chain (solver competition) — on-chain solo se verifica que cada orden individual cumple su minAmountOut"
    - "El surplus se calcula post-execution, no pre-execution — el solver puede manipular el cálculo"
  solodit_ids:
    - h-04-solvers-can-collude-to-increase-their-surplus-sherlock-none-cow-protocol-git
    - m-03-batch-settlement-allows-solver-orders-sherlock-none-cow-protocol-git
  incidentes:
    - "CoW Protocol solver competition exploit — solver Barter manipulated batch composition (2023)"
  verificado: true
  confianza: 85

- id: SOLVER-08
  titulo: GPv2 Trade Surplus Extraction por Solvers
  causa_raiz: |
    En GPv2 (CoW Protocol), el surplus es la diferencia entre el precio que el usuario
    aceptaría (limit price) y el precio real de ejecución. El protocolo intenta dar
    parte del surplus al usuario, pero el solver controla la ejecución y puede capturar
    el surplus de múltiples maneras: ejecutando a un precio ligeramente mejor que el
    limit pero mucho peor que el mercado, o usando interacciones externas que extraen valor.
  como_funciona: |
    1. Usuario firma GPv2Order: sell 1000 DAI, buyAmount >= 0.4 ETH (limit price)
    2. Precio real del mercado: 1 ETH = 2000 DAI → usuario debería recibir 0.5 ETH
    3. El solver ejecuta la orden y reporta buyAmount = 0.401 ETH
    4. El usuario recibe 0.401 ETH (cumple el limit de 0.4)
    5. El solver vendió 1000 DAI por 0.5 ETH en el mercado → surplus = 0.099 ETH (~$250)
    6. El solver se queda con el 100% del surplus

    Variante — Surplus via interaction:
    1. GPv2 permite pre-interactions y post-interactions en el settlement
    2. El solver añade una post-interaction que llama a un contrato propio
    3. El contrato propio ejecuta un swap adicional con los fondos "sobrantes"
    4. El surplus sale del settlement contract vía la interacción

    Variante — appData surplus extraction:
    1. GPv2Order tiene un campo appData que puede incluir partner fee
    2. Si el smart contract que firma la orden no valida appData, el solver pone su propia fee
    3. El surplus va al partner address del solver en vez del protocolo o usuario
  invariante: |
    function check_surplus_not_extracted(
        uint256 userBuyAmount,
        uint256 marketPrice,
        uint256 sellAmount,
        uint256 maxSurplusToSolverBps // e.g., 2000 = 20%
    ) internal pure {
        uint256 fairBuyAmount = (sellAmount * 1e18) / marketPrice;
        if (fairBuyAmount > userBuyAmount) {
            uint256 totalSurplus = fairBuyAmount - userBuyAmount;
            uint256 surplusLost = fairBuyAmount - userBuyAmount;
            // El solver no debería quedarse con más del maxSurplusToSolverBps
            // del surplus total
            t(userBuyAmount >= fairBuyAmount * (10000 - maxSurplusToSolverBps) / 10000,
              "SOLVER-08: solver extracting excessive surplus from trade");
        }
    }
  que_mirar:
    - "¿El protocolo implementa surplus sharing (parte del surplus va al usuario)?"
    - "¿Las pre/post-interactions pueden transferir tokens fuera del settlement contract?"
    - "¿El campo appData es validado por el contrato que firma la orden?"
    - "¿Hay un cap máximo en el surplus que el solver puede retener?"
  como_se_arregla: |
    - Surplus sharing obligatorio: mínimo 50% del surplus va al usuario
    - appData validation: el contrato que firma DEBE verificar appData en isValidSignature()
    - Limitar interactions a un whitelist de contratos aprobados
    - Post-settlement audit: comparar precio de ejecución vs TWAP para detectar extraction
  trampas:
    - "Trail of Bits encontró el bug de appData en Reserve Protocol CowSwapFiller"
    - "Pashov Audit Group lo encontró en Cove Protocol — isValidSignature ignoraba appData"
    - "CoW Protocol v2 implementó surplus sharing pero la implementación depende del solver driver off-chain"
  solodit_ids:
    - order-surplus-extraction-trailofbits-none-reserve-protocol-solidity-400-pdf
    - m-02-loss-of-surplus-if-erc-1271-order-allows-arbitrary-data-pashov-audit-group-none-cove_2024-12-30-markdown
    - l-03-validation-in-isvalidsignature-prevents-partial-fills-at-good-prices-pashov-audit-group-none-reserve_2025-06-02-markdown
  incidentes:
    - "Reserve Protocol CowSwapFiller — Trail of Bits audit"
    - "Cove Protocol — Pashov Audit Group"
  verificado: true
  confianza: 95

- id: SOLVER-09
  titulo: Partial Fill Rounding Errors Benefiting Solver
  causa_raiz: |
    Cuando una orden se llena parcialmente, las cantidades de input y output se calculan
    proporcionalmente. Si la división tiene truncamiento (Solidity siempre trunca), el
    solver puede elegir tamaños de fill que maximicen el error de redondeo a su favor.
    En miles de fills parciales pequeños, el rounding se acumula significativamente.
  como_funciona: |
    1. Orden original: sell 1000 USDC, buy >= 0.5 ETH (ratio 2000:1)
    2. Solver hace partial fill de 3 USDC:
       - buyAmount proporcional = 3 * 0.5 / 1000 = 0.0015 ETH
       - En Solidity: (3 * 5e17) / 1000e6 = con truncamiento puede perder wei
    3. El solver repite esto 333 veces con fills de 3 USDC cada uno
    4. Cada fill pierde 1 wei de ETH por truncamiento
    5. Total perdido por rounding: 333 wei (insignificante para ETH)
    6. PERO: con tokens de 6 decimales vendiendo tokens de 18 decimales, el rounding
       puede ser de hasta 1e12 wei por fill

    Variante — Inverse rounding:
    - El solver especifica el buyAmount en vez del sellAmount
    - El sellAmount se calcula por proporción inversa con redondeo que favorece al solver
    - El usuario paga más sellToken por la misma cantidad de buyToken
  invariante: |
    function check_partial_fill_rounding(
        uint256 originalSellAmount,
        uint256 originalBuyAmount,
        uint256 fillSellAmount,
        uint256 fillBuyAmount
    ) internal pure {
        // El ratio del fill no debe ser peor que el ratio original (con 1 wei tolerance)
        // originalBuyAmount / originalSellAmount <= fillBuyAmount / fillSellAmount
        // Cross multiply to avoid division:
        t(
            fillBuyAmount * originalSellAmount + 1 >= originalBuyAmount * fillSellAmount,
            "SOLVER-09: partial fill ratio worse than original order ratio"
        );
    }

    function check_cumulative_rounding(
        uint256 totalFilledSellAmount,
        uint256 totalFilledBuyAmount,
        uint256 originalSellAmount,
        uint256 originalBuyAmount,
        uint256 maxRoundingLossWei
    ) internal pure {
        uint256 expectedBuy = (totalFilledSellAmount * originalBuyAmount) / originalSellAmount;
        if (expectedBuy > totalFilledBuyAmount) {
            t(expectedBuy - totalFilledBuyAmount <= maxRoundingLossWei,
              "SOLVER-09: cumulative rounding loss exceeds threshold");
        }
    }
  que_mirar:
    - "¿La proporción del fill parcial se calcula con rounding up a favor del usuario?"
    - "¿Hay un tamaño mínimo de fill que haga el rounding insignificante?"
    - "¿El protocolo acumula el rounding error o lo resetea en cada fill?"
    - "¿Tokens con decimales muy diferentes (6 vs 18) amplifican el rounding?"
  como_se_arregla: |
    - Round UP a favor del usuario (el solver paga el rounding)
    - Tamaño mínimo de fill: e.g., mínimo 1% de la orden original
    - Acumular y verificar el rounding: si el total de fills no cumple el ratio original, revertir
    - Usar FullMath (mulDiv con rounding direction) como Uniswap V3
  trampas:
    - "GPv2 calcula filledAmount usando mulDiv pero la dirección de rounding depende de quién llama"
    - "En UniswapX, los fills parciales no existen (fill-or-kill por defecto) — pero las variantes sí los permiten"
    - "1inch Fusion v2 permite partial fills y el rounding favorece al resolver"
  solodit_ids:
    - m-05-partial-fill-rounding-favors-solver-sherlock-none-cow-protocol-git
    - l-01-rounding-error-in-partial-fill-calculation-cantina-none-1inch-fusion-markdown
  incidentes: []
  verificado: true
  confianza: 80

- id: SOLVER-10
  titulo: Cross-Chain Intent Settlement Race Conditions
  causa_raiz: |
    En intents cross-chain (Across, ERC-7683), el solver llena la orden en Chain B y
    reclama el reembolso en Chain A. Hay una ventana temporal entre el fill y el claim
    durante la cual pueden ocurrir race conditions: otro solver llena la misma orden,
    el usuario cancela, o el estado en Chain A cambia (liquidación, etc.).
  como_funciona: |
    Variante A — Double fill by different solvers:
    1. Intent: swap 1000 USDC (Chain A) → 1 ETH (Chain B)
    2. Solver A y Solver B ven la intent simultáneamente
    3. Ambos envían fill tx en Chain B en el mismo bloque
    4. Si no hay un lock on-chain, ambos fills se ejecutan
    5. El usuario recibe 2 ETH pero solo depositó 1000 USDC
    6. Uno de los solvers pierde 1 ETH sin poder reclamar reembolso

    Variante B — Fill + Cancel race:
    1. Solver llena la intent en Chain B (gasta 1 ETH)
    2. Antes de que el proof llegue a Chain A, el usuario cancela en Chain A
    3. El usuario recupera 1000 USDC en Chain A y ya recibió 1 ETH en Chain B
    4. El solver pierde 1 ETH sin reembolso

    Variante C — State change during settlement:
    1. Los fondos del usuario en Chain A están en un lending position
    2. Mientras el solver llena en Chain B, la posición en Chain A se liquida
    3. Los fondos para reembolsar al solver ya no existen
    4. El solver pierde capital
  invariante: |
    mapping(bytes32 => uint8) ghost_intentFillCount;

    function check_no_double_fill(bytes32 intentId) internal {
        ghost_intentFillCount[intentId]++;
        t(ghost_intentFillCount[intentId] <= 1,
          "SOLVER-10: intent filled more than once across chains");
    }

    function check_cancel_blocked_during_fill(
        bytes32 intentId,
        uint256 fillTimestamp,
        uint256 cancelTimestamp,
        uint256 settlementWindow
    ) internal pure {
        if (fillTimestamp > 0) {
            t(cancelTimestamp == 0 || cancelTimestamp > fillTimestamp + settlementWindow,
              "SOLVER-10: intent cancelled during active settlement window");
        }
    }
  que_mirar:
    - "¿Hay un lock atómico en Chain B que impida double fills?"
    - "¿El cancel en Chain A verifica si hay un fill pendiente en Chain B?"
    - "¿Qué pasa si el bridge message se pierde? ¿El solver pierde capital?"
    - "¿Hay un timeout después del cual el solver puede reclamar sin el proof completo?"
  como_se_arregla: |
    - Atomic fill: solo un solver puede llenar cada intentId (first-come-first-served on-chain)
    - Cancel grace period: después de que un solver inicia un fill, el cancel se bloquea por N bloques
    - Escrow en Chain A: los fondos del usuario se lockean al crear la intent, no al fill
    - Fallback: si el fill expira sin claim, el solver puede recuperar vía dispute resolution
  trampas:
    - "Across Protocol usa un 'optimistic' settlement donde el fill se asume válido y se puede disputar"
    - "ERC-7683 define un estándar pero no resuelve la sincronización cross-chain — cada implementación debe hacerlo"
    - "En chains rápidas (Solana, Arbitrum), la ventana de race condition es más corta pero no nula"
  solodit_ids:
    - h-01-double-fill-possible-across-chains-sherlock-none-across-v3-git
    - m-02-cancel-race-condition-with-fill-cantina-none-across-v3-markdown
  incidentes:
    - "Across Protocol v2 — double fill edge case in depositId handling"
  verificado: true
  confianza: 85

- id: SOLVER-11
  titulo: Solver Bond/Stake Slashing Evasion
  causa_raiz: |
    Los protocolos requieren que los solvers depositen un bond o stake como garantía
    de buen comportamiento. Si un solver actúa maliciosamente (no llena, da mal precio),
    su stake se recorta (slash). Pero si el solver puede retirar su stake antes de que
    el slashing se ejecute, o si el mecanismo de slashing tiene una ventana de delay
    explotable, el solver puede evadir la penalización.
  como_funciona: |
    Variante A — Withdrawal front-running:
    1. Solver A tiene 10 ETH stakeados como bond
    2. Solver A ejecuta un trade malicioso (extrae $5000 de surplus de usuarios)
    3. Alguien reporta la mala conducta — se inicia un proceso de slashing
    4. El slashing tiene un timelock de 24 horas (para permitir disputas)
    5. Solver A retira su stake en las 24 horas antes de que se ejecute el slash
    6. Cuando se ejecuta el slash, no hay fondos que recortar

    Variante B — Partial unstake:
    1. El solver mantiene exactamente el mínimo requerido de stake
    2. Ejecuta trades maliciosos cuyo profit excede el mínimo stake
    3. Pierde el stake pero gana más de lo que pierde — ataque rentable

    Variante C — Stake fragmentation:
    1. El solver usa 10 wallets diferentes, cada una con stake mínimo
    2. Si una es slasheada, las otras 9 siguen operando
    3. El costo de slashing es 1/10 del que debería ser
  invariante: |
    function check_stake_locked_during_dispute(
        address solver,
        uint256 stakeAmount,
        bool hasActiveFill,
        bool hasDisputeOpen
    ) internal pure {
        if (hasActiveFill || hasDisputeOpen) {
            t(stakeAmount > 0,
              "SOLVER-11: solver stake is 0 during active fill/dispute");
        }
    }

    function check_slashing_exceeds_profit(
        uint256 slashAmount,
        uint256 estimatedMaliciousProfit
    ) internal pure {
        t(slashAmount >= estimatedMaliciousProfit * 2,
          "SOLVER-11: slash amount insufficient to deter malicious behavior");
    }
  que_mirar:
    - "¿El stake tiene un unbonding period que bloquee retiros durante N días?"
    - "¿El slashing se ejecuta inmediatamente o tiene un delay?"
    - "¿El stake mínimo es suficiente para cubrir el máximo daño posible por un trade?"
    - "¿El protocolo identifica Sybil (múltiples wallets del mismo solver)?"
  como_se_arregla: |
    - Unbonding period: mínimo 7 días entre solicitar retiro y poder retirar
    - Immediate freeze: al iniciar un dispute, el stake se congela automáticamente
    - Proportional stake: el stake mínimo debe ser proporcional al volumen que el solver maneja
    - Slash > profit: el slash debe ser al menos 2x el máximo profit extraíble por trade
  trampas:
    - "CoW Protocol tiene un solver bond pero el slashing es gobernado off-chain (DAO vote)"
    - "1inch Fusion resolvers tienen un stake mínimo fijo — no proporcional al volumen"
    - "UniswapX no tiene stake — la penalización es exclusión del sistema (reputacional)"
  solodit_ids:
    - m-04-solver-can-unstake-before-slash-executes-sherlock-none-cow-protocol-git
    - h-01-insufficient-bond-allows-profitable-attacks-cantina-none-across-v3-markdown
  incidentes: []
  verificado: true
  confianza: 75

- id: SOLVER-12
  titulo: Pre-Interaction/Post-Interaction Hook Attacks en CoW Orders
  causa_raiz: |
    GPv2 permite que las órdenes incluyan pre-interactions (ejecutadas antes del swap)
    y post-interactions (ejecutadas después). Estas interacciones se ejecutan en el
    contexto del settlement contract, que tiene aprobaciones de tokens de muchos usuarios.
    Si la validación es insuficiente, un solver malicioso puede usar las interacciones
    para transferir tokens de otros usuarios o manipular el estado.
  como_funciona: |
    Variante A — Drain vía pre-interaction:
    1. El settlement contract tiene approve(MAX) de muchos usuarios para muchos tokens
    2. El solver crea una pre-interaction: transferFrom(victim, solver, all_USDC)
    3. La pre-interaction se ejecuta en el contexto del settlement contract
    4. Como el settlement contract tiene el approve del victim, el transferFrom funciona
    5. El solver drena todos los USDC del victim

    Variante B — State manipulation:
    1. El solver crea una pre-interaction que manipula un oracle
    2. La orden del usuario depende de ese oracle para su minAmountOut
    3. El oracle manipulado hace que el minAmountOut sea más bajo
    4. El solver ejecuta a un precio peor — el usuario pierde surplus

    Variante C — Reentrancy via post-interaction:
    1. La post-interaction llama a un contrato externo
    2. El contrato externo reentra al settlement para ejecutar otra orden
    3. La segunda ejecución usa el estado intermedio (antes de que el settlement finalice)
    4. El solver extrae valor de la diferencia entre estados
  invariante: |
    function check_interaction_safe(
        address target,
        bytes4 selector,
        address settlementContract
    ) internal pure {
        // Las interacciones no deben llamar al settlement contract ni a tokens directamente
        t(target != settlementContract,
          "SOLVER-12: interaction targets settlement contract — reentrancy risk");
        t(selector != IERC20.transferFrom.selector,
          "SOLVER-12: interaction uses transferFrom — drain risk");
        t(selector != IERC20.approve.selector,
          "SOLVER-12: interaction uses approve — approval manipulation risk");
    }

    function check_balances_after_interactions(
        address[] memory users,
        address token,
        uint256[] memory balancesBefore,
        uint256[] memory balancesAfter
    ) internal pure {
        for (uint256 i = 0; i < users.length; i++) {
            t(balancesAfter[i] >= balancesBefore[i],
              "SOLVER-12: user balance decreased during interactions");
        }
    }
  que_mirar:
    - "¿Las interacciones se ejecutan con delegatecall o call desde el settlement contract?"
    - "¿Hay un whitelist de targets y selectors permitidos en las interacciones?"
    - "¿El settlement contract tiene aprobaciones de tokens de usuarios no involucrados en el batch?"
    - "¿Hay un reentrancy guard en el settlement?"
  como_se_arregla: |
    - Whitelist de interacciones: solo contratos y funciones aprobados
    - No usar delegatecall para interacciones — solo call con fondos limitados
    - Reentrancy guard en el settlement contract
    - Revocar aprobaciones inmediatamente después del settlement
    - Separar el settlement contract de la custody de tokens
  trampas:
    - "GPv2Settlement.sol usa call (no delegatecall) pero ejecuta en su propio contexto — que tiene los approves"
    - "CoW Protocol v2 verificó esto parcialmente pero las interacciones siguen siendo un vector abierto"
    - "Trail of Bits documentó este vector como riesgo residual en su auditoría de CoW"
  solodit_ids:
    - h-02-pre-interaction-can-drain-approved-tokens-sherlock-none-cow-protocol-git
    - m-01-post-interaction-reentrancy-in-settlement-cantina-none-cow-protocol-markdown
  incidentes:
    - "CoW Protocol Sherlock contest — pre/post interaction hooks identified as critical vector"
  verificado: true
  confianza: 90

- id: SOLVER-13
  titulo: Fill-or-Kill vs Partial Fill Confusion — Griefing y Denegación de Servicio
  causa_raiz: |
    Algunas órdenes son fill-or-kill (se ejecutan completamente o no se ejecutan),
    mientras que otras permiten fills parciales. Si el protocolo no distingue
    claramente entre ambos modos, o si el solver puede tratar una orden fill-or-kill
    como parcial (o viceversa), surgen problemas de griefing y ejecución inesperada.
  como_funciona: |
    Variante A — Partial fill de orden fill-or-kill:
    1. Usuario firma orden fill-or-kill: swap 1000 USDC → ETH
    2. El solver llena solo 100 USDC (fill parcial)
    3. Si el contrato no verifica el flag fill-or-kill, la ejecución parcial se acepta
    4. El usuario recibe 0.05 ETH pero su nonce/orden se marca como "parcialmente llena"
    5. El usuario necesita enviar otra tx para el resto — pagando gas adicional

    Variante B — Fill-or-kill como griefing:
    1. Un solver malicioso ve una orden grande con partial fill habilitado
    2. Llena 1 wei (la cantidad mínima posible)
    3. La orden se marca como "partially filled" — ocupa un slot en el tracking
    4. El usuario paga gas por un fill de 1 wei que no tiene valor
    5. Si el protocolo tiene un límite de fills parciales por orden, los fills de 1 wei agotan el límite

    Variante C — Flag confusion:
    1. En GPv2, el flag partiallyFillable está en el orderFlags
    2. Si el solver manipula el flag al crear el settlement, puede ejecutar parcialmente
       una orden que el usuario firmó como fill-or-kill
    3. El hash de la orden incluye el flag pero si la verificación es incorrecta, se ignora
  invariante: |
    function check_fill_or_kill_respected(
        bool isPartiallyFillable,
        uint256 orderAmount,
        uint256 fillAmount
    ) internal pure {
        if (!isPartiallyFillable) {
            t(fillAmount == orderAmount,
              "SOLVER-13: fill-or-kill order not fully filled");
        }
    }

    function check_minimum_fill_size(
        uint256 fillAmount,
        uint256 orderAmount,
        uint256 minFillBps // e.g., 100 = 1%
    ) internal pure {
        uint256 minFill = (orderAmount * minFillBps) / 10000;
        t(fillAmount >= minFill || fillAmount == orderAmount,
          "SOLVER-13: fill amount too small — dust fill griefing");
    }
  que_mirar:
    - "¿El flag partiallyFillable es parte del hash firmado por el usuario?"
    - "¿Hay un tamaño mínimo de fill para evitar dust griefing?"
    - "¿El solver puede elegir el tamaño del fill parcial sin restricción?"
    - "¿Fills parciales de 1 wei cuestan gas al usuario sin darle valor?"
  como_se_arregla: |
    - El flag fill-or-kill debe ser parte del hash firmado (inmutable)
    - Tamaño mínimo de fill: al menos 0.1% de la orden original o un mínimo absoluto en USD
    - Rate limiting: máximo N fills parciales por orden
    - Si un fill parcial no cubre el gas del usuario, revertir
  trampas:
    - "GPv2 incluye partiallyFillable en el order hash — pero la verificación on-chain debe matchear"
    - "UniswapX es fill-or-kill por defecto — reduce este vector"
    - "1inch Fusion permite fills parciales y el tamaño mínimo no está enforced on-chain"
  solodit_ids:
    - m-06-fill-or-kill-flag-not-enforced-in-settlement-sherlock-none-cow-protocol-git
    - l-02-dust-fills-can-grief-partial-fill-orders-cantina-none-1inch-fusion-markdown
  incidentes: []
  verificado: true
  confianza: 80

- id: SOLVER-14
  titulo: UniswapX Reactor Validation Bypass
  causa_raiz: |
    En UniswapX, los "reactors" son contratos que validan y ejecutan las órdenes.
    Diferentes tipos de órdenes usan diferentes reactors (DutchOrderReactor,
    ExclusiveDutchOrderReactor, LimitOrderReactor). Si la validación del reactor
    tiene un bypass — por ejemplo, no verificando que el caller es un filler
    autorizado, o no validando los parámetros del output — el filler puede ejecutar
    órdenes con parámetros manipulados.
  como_funciona: |
    Variante A — Output token manipulation:
    1. Usuario firma DutchOrder: sell 1 ETH, buy >= 2000 USDC
    2. La orden especifica outputToken = USDC
    3. El reactor valida que el filler entrega >= 2000 tokens del outputToken
    4. Pero si el reactor no verifica que el outputToken en el fill == outputToken en la orden
    5. El filler entrega 2000 de un token basura (valor = $0) en vez de USDC
    6. La validación pasa (2000 >= 2000) pero el usuario recibe un token sin valor

    Variante B — Reactor address spoofing:
    1. La orden especifica reactor = DutchOrderReactor (address legítimo)
    2. El Permit2 transferFrom se ejecuta basándose en la firma del usuario
    3. Si la validación de que el contrato llamante es el reactor correcto falla
    4. Un contrato malicioso puede usar la firma para extraer tokens del usuario

    Variante C — Resolve callback manipulation:
    1. En UniswapX V2, las órdenes usan un callback resolve() para determinar outputs
    2. El resolver es un contrato que el filler proporciona
    3. Si el reactor no valida el resolver, un resolver malicioso puede retornar outputs de 0
    4. El usuario pierde sus inputTokens sin recibir nada válido
  invariante: |
    function check_reactor_output_validation(
        address expectedOutputToken,
        address actualOutputToken,
        uint256 expectedMinOutput,
        uint256 actualOutput
    ) internal pure {
        t(actualOutputToken == expectedOutputToken,
          "SOLVER-14: output token mismatch in reactor fill");
        t(actualOutput >= expectedMinOutput,
          "SOLVER-14: output amount below minimum in reactor");
    }

    function check_reactor_is_authorized(
        address reactor,
        mapping(address => bool) storage authorizedReactors
    ) internal view {
        t(authorizedReactors[reactor],
          "SOLVER-14: order executed by unauthorized reactor");
    }
  que_mirar:
    - "¿El reactor valida que el token entregado es el mismo token especificado en la orden?"
    - "¿El Permit2 witness incluye el address del reactor y la firma lo cubre?"
    - "¿El resolve() callback puede ser arbitrario o está restringido?"
    - "¿Hay un registry de reactores autorizados?"
  como_se_arregla: |
    - Output validation estricta: token address + amount + recipient verificados contra la orden
    - Reactor registry: solo reactores registrados pueden usar las firmas Permit2
    - Resolve callback whitelisting: solo resolvers aprobados pueden determinar outputs
    - La firma del usuario debe cubrir el reactor address específico
  trampas:
    - "UniswapX V2 mejoró la validación del reactor respecto a V1 — pero los resolvers custom siguen siendo un vector"
    - "En el Sherlock contest de UniswapX se encontraron múltiples bypasses en la validación"
    - "El Permit2 witness type es crítico — un mismatch permite replay entre diferentes reactores"
  solodit_ids:
    - h-01-reactor-validation-bypass-allows-token-theft-sherlock-uniswapx-git
    - m-02-resolver-callback-can-return-malicious-outputs-sherlock-uniswapx-git
  incidentes: []
  verificado: true
  confianza: 85

- id: SOLVER-15
  titulo: Solver Inventory Risk Creating Market Manipulation
  causa_raiz: |
    Los solvers mantienen un inventario de tokens para poder llenar órdenes rápidamente.
    Si un solver acumula una posición grande en un token (por llenar muchas órdenes en
    una dirección), tiene incentivo económico para manipular el precio de ese token
    para liquidar su posición con profit. El solver tiene información privilegiada
    (ve las órdenes pendientes) que puede usar para anticipar movimientos de mercado.
  como_funciona: |
    1. Solver acumula 1000 ETH de inventario por llenar muchas órdenes de venta de ETH
    2. Solver ve que hay 500 órdenes pendientes de compra de ETH → demanda alta
    3. Solver compra más ETH en DEXes antes de llenar las órdenes → sube el precio
    4. Solver llena las órdenes de compra al precio inflado (dentro del maxPrice del usuario)
    5. Solver vende su inventario extra al precio inflado → profit

    Variante — Information asymmetry:
    1. El solver ve el orderflow completo (todas las intents pendientes)
    2. Identifica un desbalance: muchas más órdenes de compra que de venta
    3. Posiciona su inventario anticipando el movimiento
    4. Cuando ejecuta el batch, el precio se mueve a su favor
    5. Esto es efectivamente front-running del orderflow agregado
  invariante: |
    function check_solver_inventory_bounded(
        address solver,
        address token,
        uint256 currentBalance,
        uint256 maxInventory
    ) internal pure {
        t(currentBalance <= maxInventory,
          "SOLVER-15: solver inventory exceeds safe threshold");
    }

    function check_solver_not_trading_own_book(
        address solver,
        address[] memory orderMakers,
        address[] memory orderTakers
    ) internal pure {
        for (uint256 i = 0; i < orderMakers.length; i++) {
            t(orderMakers[i] != solver && orderTakers[i] != solver,
              "SOLVER-15: solver trading against own inventory in batch");
        }
    }
  que_mirar:
    - "¿El protocolo limita el inventario máximo que un solver puede mantener?"
    - "¿Los solvers pueden ver el orderflow completo antes de ejecutar?"
    - "¿Hay reglas que impidan al solver hacer trades propios en el mismo batch?"
    - "¿El protocolo monitorea si los precios del solver coinciden con manipulación pre-settlement?"
  como_se_arregla: |
    - Inventory limits: cap máximo de tokens que un solver puede acumular
    - Chinese wall: el solver no debe ver todas las órdenes — solo las que le asignan
    - Anti-frontrunning: commit-reveal para el orderflow
    - Solver rotation: cambiar qué solver ejecuta cada batch aleatoriamente
  trampas:
    - "Este es un problema de diseño más que un bug de código — difícil de enforcer on-chain"
    - "CoW Protocol monitorea esto off-chain vía el solver competition framework"
    - "En la práctica, los grandes solvers como Wintermute tienen este conflicto de interés permanentemente"
  solodit_ids: []
  incidentes:
    - "Wintermute accusations of front-running CoW Protocol orderflow (2023)"
    - "Jump Trading inventory manipulation allegations in FTX era"
  verificado: false
  confianza: 65

- id: SOLVER-16
  titulo: Intent-Based MEV Extraction — Backrunning Intents
  causa_raiz: |
    Cuando un solver ejecuta una intent grande on-chain (e.g., swap de $1M en un DEX),
    el trade mueve el precio. Un searcher MEV que monitorea las txs del solver puede
    backrun la ejecución: comprar el token que bajó de precio inmediatamente después
    y vender cuando se recupera. El solver no pierde directamente, pero el usuario
    podría haber recibido mejor precio si el MEV se hubiera capturado para él.
  como_funciona: |
    1. Solver ejecuta intent del usuario: swap 500 ETH → USDC en Uniswap V3
    2. El trade mueve el precio de ETH/USDC en el pool (-0.3%)
    3. Searcher MEV ve la tx en el mempool (o en el bundle del block builder)
    4. Searcher coloca una tx inmediatamente después: compra ETH al precio deprimido
    5. Arbitrageurs restauran el precio → searcher vende con profit
    6. MEV extraído: ~$1500 (que el usuario podría haber recibido como mejor precio)

    Variante — Solver es su propio searcher:
    1. El solver ejecuta el swap del usuario y coloca su propio backrun en el mismo bloque
    2. El solver captura el MEV además del surplus
    3. El protocolo no puede distinguir entre el swap legítimo y el backrun del solver
  invariante: |
    function check_no_backrun_in_same_block(
        uint256 fillBlockNumber,
        address solver,
        uint256 solverBalanceBefore,
        uint256 solverBalanceAfter,
        uint256 expectedSurplus
    ) internal pure {
        uint256 actualSurplus = solverBalanceAfter > solverBalanceBefore
            ? solverBalanceAfter - solverBalanceBefore
            : 0;
        t(actualSurplus <= expectedSurplus * 120 / 100, // max 20% over expected
          "SOLVER-16: solver captured more surplus than expected — possible backrun");
    }
  que_mirar:
    - "¿El solver ejecuta el swap vía un private mempool (Flashbots)?"
    - "¿Hay transacciones del solver o sus addresses asociadas en el mismo bloque?"
    - "¿El protocolo usa MEV-Share para retornar MEV al usuario?"
    - "¿El solver puede elegir en qué DEX/pool ejecutar (favoreciendo pools con más MEV extraíble)?"
  como_se_arregla: |
    - MEV-Share o MEV Blocker: el solver envía vía relay que comparte MEV con el usuario
    - Batch execution: ejecutar múltiples intents en un solo tx (reduce MEV per intent)
    - Private execution: usar Flashbots Protect o relay privado
    - MEV rebate: el protocolo cobra un fee al solver y lo devuelve al usuario
  trampas:
    - "CoW Protocol batch settlement reduce el MEV individual pero no lo elimina (el batch entero puede ser backruneado)"
    - "UniswapX solvers que usan Flashbots pueden evitar backruns de terceros pero hacer los propios"
    - "MEV-Share no está disponible en todas las chains — en L2s no hay PBS"
  solodit_ids:
    - m-08-solver-can-extract-mev-from-user-intents-sherlock-none-cow-protocol-git
    - l-01-backrunning-of-intent-settlement-transactions-cantina-none-across-v3-markdown
  incidentes:
    - "Documented MEV extraction from CoW Protocol settlements (Flashbots research, 2023)"
  verificado: true
  confianza: 75

- id: SOLVER-17
  titulo: ERC-7683 Cross-Chain Intent Standard Vulnerabilities
  causa_raiz: |
    ERC-7683 define un estándar para órdenes cross-chain con tipos CrossChainOrder y
    GaslessCrossChainOrder. Las implementaciones tempranas tienen bugs en:
    - Type hash mismatch entre el witness de Permit2 y el tipo real de la orden
    - Encoding inconsistente de orderData (abi.encode vs abi.encodePacked)
    - Falta de validación de fillDeadline vs orderDeadline
    - Ambigüedad en quién paga el gas (gasless vs gas-paying orders)
  como_funciona: |
    Variante A — Permit2 witness type mismatch:
    1. ERC-7683 define CrossChainOrder y GaslessCrossChainOrder como tipos diferentes
    2. El PERMIT2_ORDER_TYPE se declara como "CrossChainOrder witness..."
    3. Pero el witness hash se calcula desde GaslessCrossChainOrder
    4. Permit2 valida el hash pero con el type string incorrecto
    5. Consecuencia: firmas de un tipo pueden aceptarse como otro tipo

    Variante B — fillDeadline vs orderDeadline confusion:
    1. CrossChainOrder tiene orderDeadline (cuándo expira para el solver en origin)
    2. Y fillDeadline (cuándo expira el fill en destination)
    3. Si fillDeadline > orderDeadline, el solver puede llenar en destination
       después de que la orden expiró en origin
    4. El usuario ya recuperó sus fondos (orden expirada) pero el solver también entregó

    Variante C — orderData encoding:
    1. El campo orderData es bytes (libre para cada implementación)
    2. Si dos implementaciones codifican diferente (abi.encode vs abi.encodePacked)
    3. Una firma válida para implementación A puede ser reinterpretada por implementación B
    4. Cross-protocol replay con semántica diferente
  invariante: |
    function check_erc7683_deadlines_consistent(
        uint32 orderDeadline,
        uint32 fillDeadline
    ) internal pure {
        t(fillDeadline <= orderDeadline,
          "SOLVER-17: fillDeadline exceeds orderDeadline — stale fill possible");
    }

    function check_erc7683_witness_type_matches(
        bytes32 computedTypeHash,
        bytes32 declaredTypeHash
    ) internal pure {
        t(computedTypeHash == declaredTypeHash,
          "SOLVER-17: ERC-7683 witness type hash mismatch — signature confusion");
    }

    function check_erc7683_orderdata_encoding(
        bytes memory orderData,
        bytes memory reencoded
    ) internal pure {
        t(keccak256(orderData) == keccak256(reencoded),
          "SOLVER-17: ERC-7683 orderData encoding inconsistency");
    }
  que_mirar:
    - "¿El PERMIT2_ORDER_TYPE string matchea exactamente el tipo del struct usado como witness?"
    - "¿fillDeadline y orderDeadline se validan uno contra otro?"
    - "¿orderData tiene un schema fijo o es libre?"
    - "¿Las implementaciones de diferentes protocolos usan el mismo encoding para orderData?"
  como_se_arregla: |
    - Validar que PERMIT2_ORDER_TYPE == tipo real del struct (test en deploy)
    - Enforcer: fillDeadline <= orderDeadline (on-chain)
    - Definir schema estricto para orderData con versionado
    - Test cross-implementation: verificar que firmas no son intercambiables entre protocolos
  trampas:
    - "Uniswap/Across fueron los primeros en implementar ERC-7683 — bugs tempranos son esperados"
    - "El estándar está en draft — puede cambiar y romper implementaciones existentes"
    - "Permit2 witness validation es complejo — off-by-one en el type string causa rechazo silencioso"
  solodit_ids:
    - m-01-erc7683-permit2-witness-type-mismatch-cantina-none-across-v3-markdown
    - m-03-filldeadline-exceeds-orderdeadline-allows-stale-fills-cantina-none-across-v3-markdown
    - h-01-cross-protocol-signature-replay-via-orderdata-encoding-sherlock-none-erc7683-git
  incidentes: []
  verificado: true
  confianza: 80
