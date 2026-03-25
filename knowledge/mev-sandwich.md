grep_targets:
  - "slippage"
  - "minAmountOut"
  - "amountOutMinimum"
  - "deadline"
  - "block.timestamp"
  - "sqrtPriceLimitX96"
  - "getAmountOut"
  - "slot0"
  - "sqrtPriceX96"
  - "tick"
  - "priceImpact"
  - "frontrun"
  - "sandwich"
  - "backrun"
  - "MEV"
  - "TWAP"
  - "observe"
  - "commit"
  - "reveal"
  - "maxSlippage"

# Briefing: MEV & Sandwich Attacks

## Contexto del dominio
MEV (Maximal Extractable Value) es el valor que los validators/miners pueden extraer
reordenando, incluyendo o excluyendo transacciones. Los ataques de sandwich son la
forma más común: el atacante front-runnea una tx del usuario, luego back-runnea para
capturar el slippage. Los bugs de MEV son sobre todo:
- Parámetros de slippage en 0 (o calculados sin protección)
- Funciones de rebalanceo/harvest sandwicheables
- Oracles basados en slot0 (manipulables en un solo bloque)
- Operaciones sin deadline (ejecutables indefinidamente después)
- Sistemas de commit-reveal con timing expuesto

---

patterns:

- id: mev-001
  titulo: minAmountOut = 0 — Slippage Protection Deshabilitada
  causa_raiz: |
    Las llamadas a DEXs (Uniswap, Curve, Balancer) tienen un parámetro de slippage
    mínimo (minAmountOut, amountOutMinimum). Si este se fija en 0, se acepta cualquier
    output price, haciendo la tx trivialmente sandwicheable. El atacante puede
    desviar el 100% del output como slippage.
  como_funciona: |
    1. Protocolo llama: uniswap.swap(tokenIn, tokenOut, amountIn, minAmountOut=0)
    2. Atacante ve la tx en mempool: front-run comprando tokenOut (precio sube)
    3. La swap del protocolo ejecuta al precio inflado → recibe menos tokenOut
    4. Atacante back-run vendiendo tokenOut (precio baja de vuelta) → profit
    5. El protocolo recibe casi nada de tokenOut (todo fue slippage)

    Ejemplo real Yearn-style vault:
    1. harvest() llama swap(WETH → USDC, minOut=0) para reinvertir rewards
    2. Atacante sandwich: extrae ~2-5% del harvest como slippage cada vez
    3. Con harvests frecuentes → drain significativo del yield de los LPs
  invariante: |
    function check_swap_has_slippage_protection(
        address tokenIn, address tokenOut, uint256 amountIn, uint256 minAmountOut
    ) internal view {
        uint256 expectedOut = getExpectedOutput(tokenIn, tokenOut, amountIn);
        uint256 minAcceptable = expectedOut * 95 / 100; // máximo 5% slippage
        t(minAmountOut >= minAcceptable,
          "MEV-001: minAmountOut too low — sandwich attack possible");
    }
  que_mirar:
    - "amountOutMin: 0 o amountOutMinimum: 0 en llamadas a DEX"
    - "minOut calculado con slot0 (manipulable) en vez de TWAP"
    - "Funciones de harvest/rebalance sin slippage param configurable"
    - "Estrategias de yield que compran tokens de reward sin protección"
  como_se_arregla: |
    - Calcular minAmountOut usando TWAP: expectedOut * (1 - maxSlippage) / 1
    - Para vaults: permitir al owner configurar maxSlippage (default 1-2%)
    - Si la swap es crítica (liquidación), usar slippage ≤ 5%; si es harvest, ≤ 1%
    - Usar quoter de Uniswap V3 como estimación, luego aplicar el descuento
  trampas:
    - "El TWAP para minAmountOut debe ser suficientemente largo (15+ min) para no ser manipulable"
    - "Algunas funciones tienen slippage por diseño — el límite debe ser razonable, no 0"
    - "En Curve stable pools el slippage debería ser < 0.01% — un minAmountOut del 99% es razonable"
  solodit_ids:
    - "m-3-spot-dex-cant-handle-fee-on-transfer-tokens-sherlock-none-unstoppable-git"
    - "h-harvest-function-is-susceptible-to-mev-sandwich-attack-code4rena-git"
    - "m-swap-without-slippage-protection-allows-sandwich-attacks-sherlock-git"

- id: mev-002
  titulo: Deadline = block.timestamp — Transacción Ejecutable Indefinidamente
  causa_raiz: |
    Los swaps en Uniswap/otros DEXs tienen un `deadline` param: si la tx no se ejecuta
    antes del deadline, revierte. Si se usa `deadline = block.timestamp` (o type(uint256).max),
    la tx nunca expira — el validator puede retrasarla horas o días y ejecutarla cuando
    sea más favorable (ya con un precio diferente que permite más extracción).
  como_funciona: |
    1. Usuario envía swap con deadline = block.timestamp (o sin deadline efectivo)
    2. El mempool está congestionado — la tx queda pendiente
    3. El precio del token cambia significativamente durante las 2 horas de espera
    4. Un searcher/validator la ejecuta cuando el precio ha movido en su favor
    5. O simplemente: la tx ejecuta a un precio muy diferente al momento de envío
    6. El usuario sufre slippage adicional que no anticipó

    Más crítico: en flashbots/MEV-boost, el builder puede guardar txs y ejecutarlas
    cuando los precios estén alineados para extraer más valor
  invariante: |
    function check_deadline_validity(uint256 deadline) internal view {
        // Deadline no debe ser block.timestamp ni type(uint256).max
        t(deadline > block.timestamp, "MEV-002: deadline already passed");
        t(deadline < block.timestamp + MAX_DEADLINE_FUTURE, "MEV-002: deadline too far in future");
        // MAX_DEADLINE_FUTURE = 20 minutos típicamente
    }
  que_mirar:
    - "deadline: block.timestamp en llamadas a DEX"
    - "deadline: type(uint256).max (nunca expira)"
    - "Funciones que pasan el deadline como parámetro del usuario sin validación"
    - "Contratos que hardcodean el deadline en el deploy (puede ser en el pasado con el tiempo)"
  como_se_arregla: |
    - Pedir al usuario que especifique el deadline en la tx misma
    - Añadir validación: require(deadline > block.timestamp + MIN_DEADLINE_BUFFER)
    - Para operaciones internas del protocolo: deadline = block.timestamp + 5 minutos
  trampas:
    - "El deadline correcto depende del contexto: para una tx urgente, 1 minuto; para un rebalanceo semanal, 1 hora"
    - "block.timestamp + 1 es solo marginalmente mejor — el validator puede manipular timestamp ±15s"
  solodit_ids:
    - "m-deadline-set-to-block-timestamp-allows-validators-to-hold-and-execute-transactions-sherlock-git"
    - "m-05-swap-deadline-set-to-block-timestamp-allows-mev-exploitation-code4rena-git"

- id: mev-003
  titulo: Oracle Basado en slot0 — Precio Manipulable en Un Solo Bloque
  causa_raiz: |
    Uniswap V3's `slot0.sqrtPriceX96` refleja el precio ACTUAL después de todos los
    swaps del bloque actual. Un atacante puede manipularlo en el mismo bloque donde
    se lee usando un flashloan: compra masiva → precio sube → protocolo lee el precio
    inflado → toma una decisión basada en él → atacante vende → precio vuelve.
    TWAP (usando `observe()`) es resistente porque promedia precios pasados.
  como_funciona: |
    1. Protocolo calcula el valor de colateral usando: sqrtPriceX96 de slot0
    2. Atacante, en el mismo bloque:
       a. Flash-borrow 10M USDC
       b. Compra ETH masivamente en el pool de Uniswap V3 → precio ETH sube 5%
       c. Llama al protocolo: "mi colateral de ETH vale 5% más"
       d. Pide prestado más USDC usando el colateral sobrevaluado
       e. Devuelve el flashloan
    3. Resultado: atacante tomó deuda con colateral inflado → undercollateralized
  invariante: |
    function check_price_uses_twap_not_spot(address pool) internal view {
        (uint160 spot,,,,,, ) = IUniswapV3Pool(pool).slot0();
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(seconds);
        int56 tickDiff = tickCumulatives[1] - tickCumulatives[0];
        int24 twapTick = int24(tickDiff / int56(uint56(TWAP_DURATION)));
        uint160 twapPrice = getSqrtRatioAtTick(twapTick);
        uint256 divergence = abs(int256(uint256(spot)) - int256(uint256(twapPrice)));
        t(divergence * 10000 / uint256(twapPrice) <= 200, // max 2% divergence
          "MEV-003: spot price diverges >2% from TWAP — potential manipulation");
    }
  que_mirar:
    - "IUniswapV3Pool(pool).slot0() como fuente de precio sin TWAP backup"
    - "sqrtPriceX96 usado directamente para calcular collateral value o liquidation price"
    - "getAmountsForLiquidity con slot0 en vez de TWAP price"
    - "Código que usa getCurrentTick() para lógica de negocio crítica"
  como_se_arregla: |
    - Usar OracleLibrary.consult(pool, TWAP_PERIOD) de @uniswap/v3-periphery
    - TWAP mínimo de 30 minutos para colateral; 1 hora para settlement
    - Si se necesita precio actual (UI/display), usar slot0; si es para seguridad, usar TWAP
    - Añadir circuit breaker: revert si slot0 diverge >X% del TWAP (indica manipulation)
  trampas:
    - "Las pools de Uniswap con poco volumen tienen TWAP menos confiable — manipular el TWAP es más barato"
    - "El TWAP tiene latencia — no refleja movimientos de precio recientes → usar con caution para liquidaciones"
    - "Chainlink es generalmente mejor que el TWAP de Uniswap para precios de colateral"
  solodit_ids:
    - "h-01-slot0-price-manipulation-allows-draining-collateral-code4rena-git"
    - "m-uniswap-slot0-used-as-price-oracle-vulnerable-to-manipulation-sherlock-git"
    - "h-4-victims-fund-can-be-stolen-due-to-rounding-error-and-exchange-rate-manipulation-sherlock-napier-git"

- id: mev-004
  titulo: Rebalance / Harvest Sandwicheable — Función Pública Sin Slippage
  causa_raiz: |
    Las funciones públicas de harvest() o rebalance() en vaults/estrategias mueven
    grandes cantidades de tokens. Si cualquiera puede llamarlas (sin slippage protection),
    un MEV bot puede sandwich cada llamada: compra el token de salida antes, luego
    llama al harvest, luego vende. El vault recibe menos tokens de los debidos.
  como_funciona: |
    1. Vault tiene 1000 WETH de rewards pendientes para convertir a USDC
    2. MEV bot ve la tx harvest() en mempool
    3. Bot front-runs: compra WETH con USDC → precio de WETH sube en el pool
    4. harvest() ejecuta: vende 1000 WETH pero a precio peor → recibe menos USDC
    5. Bot back-runs: vende WETH que compró → precio vuelve → profit del spread
    6. El vault recibió ~2-5% menos USDC en cada harvest

    Daño total sobre un año con harvests frecuentes: potencialmente 10-20% del yield
  invariante: |
    function handler_harvest() external {
        uint256 expectedReturns = estimateHarvestReturns();
        uint256 balanceBefore = USDC.balanceOf(address(vault));
        vault.harvest();
        uint256 balanceAfter = USDC.balanceOf(address(vault));
        uint256 actualReturns = balanceAfter - balanceBefore;
        // Los retornos reales no deben ser menos del 97% de lo esperado
        t(actualReturns >= expectedReturns * 97 / 100,
          "MEV-004: harvest returns significantly below expected — possible sandwich");
    }
  que_mirar:
    - "harvest() o rebalance() público sin slippage parameter ni access control"
    - "Función que vende tokens rewards sin minAmountOut configurable"
    - "Keepers externos que pueden trigger harvest — cualquiera puede llamar"
    - "Funciones de 'compound' en staking que convierten rewards a LP tokens"
  como_se_arregla: |
    - Añadir minAmountOut al harvest(): require(received >= expected * (1 - maxSlippage))
    - Si harvest es público: añadir cooldown entre harvests (no se puede llamar en el mismo bloque que el front-run)
    - Usar Flashbots/MEV-blocker para enviar la tx directamente al builder
    - Permitir solo a keepers whitelisted hacer harvest (off-chain slippage calculation)
  trampas:
    - "Los vaults de Yearn usan keepers con slippage calculation off-chain — el keeper calcula el minAmountOut antes de la tx"
    - "El cooldown no protege de sandwich si el bot espera al siguiente bloque también"
    - "En L2 con sequencer, el front-running es más difícil (no hay mempool pública)"
  solodit_ids:
    - "h-08-staking-unstaking-and-rebalancetoweight-can-be-sandwiched-mainly-reth-deposit-code4rena-asymmetry-finance-asymmetry-contest-git"
    - "m-harvest-is-sandwichable-because-minout-is-not-set-correctly-code4rena-git"

- id: mev-005
  titulo: Liquidation Front-Run — Competencia de Liquidadores y Priority Fee Race
  causa_raiz: |
    Cuando una posición se vuelve liquidable, múltiples liquidadores compiten para
    ser el primero. Esto crea una "priority fee war" donde todos suben el gas para
    ganar la liquidación. Si el protocolo tiene un reward fijo de liquidación,
    el ganador puede pagar más gas de lo que ganó. Si el protocolo tiene descuento
    variable, el front-runner puede manipular el precio antes de liquidar.
  como_funciona: |
    Variante A — Priority fee race:
    1. Posición liquidable aparece con recompensa de 100 USDC
    2. 5 liquidadores compiten → pagan 80/90/95/99/100 USDC en gas para ganar
    3. Solo el que pagó 100 USDC gana → no profit, solo el trabajo
    4. Esto desincentiva la liquidación → posiciones malas no se liquidan → bad debt

    Variante B — Sandwich de liquidación:
    1. Liquidador ve que ETH puede caer y triggear una liquidación
    2. Liquidador vende ETH en el DEX (baja precio) → trigger liquidation
    3. Liquidador ejecuta la liquidación (ganando la recompensa)
    4. Liquidador compra ETH de vuelta (precio vuelve)
    5. Doble profit: market manipulation + liquidation reward
  invariante: |
    function check_liquidation_incentive_positive(uint256 liquidationReward, uint256 gasUsed) internal view {
        uint256 gasCost = gasUsed * tx.gasprice;
        t(liquidationReward > gasCost * 120 / 100, // 20% profit mínimo para el liquidador
          "MEV-005: liquidation reward too low to cover gas costs");
    }
  que_mirar:
    - "¿La recompensa de liquidación es suficiente para cubrir gas en congestion?"
    - "¿Hay un mecanismo para que las liquidaciones sean asignadas (no carrera libre)?"
    - "¿El precio de liquidación puede ser manipulado justo antes de ejecutar?"
    - "¿El protocolo usa Dutch auction para la recompensa de liquidación?"
  como_se_arregla: |
    - Dutch auction de la recompensa: a medida que la posición se deteriora más, la recompensa sube
    - Esto hace que los liquidadores esperen hasta que la recompensa cubra su gas
    - Defender contra sandwich: usar Chainlink para liquidation trigger, no el spot price del DEX
  trampas:
    - "Aave y Compound usan bonificaciones fijas (5-10%) — funcionan bien con suficiente volumen"
    - "En L2 (gas cheap), las liquidaciones son más competitivas — la bonificación puede ser menor"
    - "El sandwich de liquidación requiere mover el precio del oráculo — en Chainlink es casi imposible"
  solodit_ids:
    - "m-liquidation-bonus-too-low-to-cover-gas-costs-creates-bad-debt-sherlock-git"
    - "h-liquidation-can-be-sandwiched-to-profit-using-price-manipulation-code4rena-git"

- id: mev-006
  titulo: Just-in-Time (JIT) Liquidity — Extracción de Fees Sin Riesgo
  causa_raiz: |
    En Uniswap V3, los LP añaden liquidez en un rango. Un atacante puede observar
    una tx grande pendiente, añadir liquidez concentrada justo en el rango del swap,
    cobrar los fees de esa swap, y retirar la liquidez inmediatamente. El LP no
    asume IL (porque retira antes de que el precio cambie), pero roba los fees de
    los LPs legítimos que sí asumen riesgo.
  como_funciona: |
    1. Swap grande de Alice: 1M USDC → ETH visible en mempool
    2. JIT bot: en el mismo bloque, antes de Alice:
       - Añade 10M en liquidez concentrada alrededor del precio actual
    3. Alice's swap ejecuta → el JIT bot captura la mayoría de los fees
    4. JIT bot retira toda su liquidez en el mismo bloque → no hay IL
    5. Los LPs "honestos" que estaban activos solo capturan una fracción de los fees
    6. Sin pérdida directa para Alice, pero el protocolo de yield de LPs pierde fees
  invariante: |
    // No hay un check on-chain directo — es un ataque de nivel de protocolo
    // La defensa es en el diseño del protocolo LP:
    function check_lp_minimum_hold_time(uint256 mintBlock, uint256 currentBlock) internal view {
        uint256 minHoldBlocks = getMinLPHoldBlocks(); // e.g., 1 epoch = 100 bloques
        t(currentBlock >= mintBlock + minHoldBlocks,
          "MEV-006: LP trying to remove liquidity before minimum hold period");
    }
  que_mirar:
    - "¿El protocolo de LP permite mint + burn en el mismo bloque?"
    - "¿Hay algún incentivo para los LPs de larga duración vs los JIT?"
    - "¿El protocolo de yield basado en Uniswap V3 concentra liquidez en un solo rango?"
    - "¿Los LPs del protocolo compiten con JIT bots por los mismos fees?"
  como_se_arregla: |
    - Minimum hold period para LPs: no se puede retirar liquidez dentro del mismo bloque/epoch
    - Fee tier más alta para LPs de larga duración (pero esto es complejo de implementar)
    - Diseñar el rango de liquidez para que sea menos atractivo para JIT (rangos amplios)
  trampas:
    - "JIT liquidity no perjudica directamente al swapper — perjudica al yield del protocolo LP"
    - "En Uniswap V4, los hooks pueden implementar el minimum hold period nativamente"
  solodit_ids:
    - "m-jit-liquidity-attack-can-steal-fees-from-protocol-lps-code4rena-git"

- id: mev-007
  titulo: Commit-Reveal Timing Attack — Reveal Window Explotable
  causa_raiz: |
    Los sistemas de commit-reveal (lotteries, auctions, random selection) tienen una
    fase de commit (hash del valor) y una fase de reveal (mostrar el valor). Si la
    ventana de reveal es conocida y hay un incentivo económico, el atacante puede:
    - Esperar a ver reveals de otros antes de decidir si revela el suyo
    - Calcular el resultado antes del reveal y actuar en consecuencia
    - Censurar reveals de otros para ganar por default
  como_funciona: |
    Variante A — Last reveal wins:
    1. 100 usuarios commitean un número para una lotería
    2. La fase de reveal dura 1 hora
    3. Atacante espera a que todos revelen → puede calcular el resultado actual
    4. Si el resultado le favorece → revela → gana
    5. Si no → no revela y pierde solo el depósito, pero puede haberlo jugado gratis

    Variante B — Griefing (censurar reveals):
    1. En una subasta de commit-reveal, el ganador se determina en el reveal
    2. El segundo mejor bidder puede griefear al ganador comprando todo el bloque
    3. El ganador no puede incluir su reveal → cae al valor default → segundo bidder gana
  invariante: |
    function check_reveal_window_not_gameable(bytes32 commitment, uint256 revealBlock) internal view {
        // El commitment debe poder verificarse en múltiples bloques (no solo el reveal block)
        t(block.number <= revealBlock + MAX_REVEAL_WINDOW,
          "MEV-007: reveal window expired");
        t(commitments[commitment] != 0,
          "MEV-007: invalid commitment");
    }
  que_mirar:
    - "¿Puede el último en revelar ver los resultados de los demás antes de decidir?"
    - "¿Hay un incentivo para NO revelar (partial refund si no revelas)?"
    - "¿El sistema de commit-reveal es resistente a un atacante que compra espacio en todos los bloques del reveal window?"
    - "¿Hay penalización suficiente por no revelar (para evitar especulación gratuita)?"
  como_se_arregla: |
    - Usar VRF (Chainlink VRF) en vez de commit-reveal para randomness crítico
    - Si commit-reveal es necesario: no-reveal = penalización del 100% del depósito
    - La penalización debe ser mayor que el profit esperado de la especulación
    - Tiempo de reveal: tiempo fijo, no extensible
  trampas:
    - "El commit-reveal es seguro si la penalización por no-reveal es mayor que el valor del secreto"
    - "En protocolos de governance, el commit-reveal puede ser reemplazado por snapshot off-chain"
  solodit_ids:
    - "m-commit-reveal-scheme-allows-last-revealer-to-gain-advantage-code4rena-git"
    - "h-commit-reveal-not-binding-attacker-can-choose-to-not-reveal-sherlock-git"

- id: mev-008
  titulo: Transaction Ordering Dependency — Estado Depende de Orden de Txs
  causa_raiz: |
    El estado del contrato puede ser diferente dependiendo del orden en que se
    ejecutan las transacciones en el mismo bloque. Si un protocolo tiene funciones
    que cambian el estado de manera que beneficia a quien ejecuta primero, el
    validador o un searcher pueden reordenar para extraer valor.
  como_funciona: |
    Variante A — Governance vote timing:
    1. Una proposal de governance va a pasar mañana
    2. La proposal aumenta las tarifas del protocolo del 0.1% al 0.3%
    3. Un MEV bot sabe que la proposal pasará → front-runs comprando tokens del protocolo
    4. Después del vote → los tokens suben → bot vende

    Variante B — Price-sensitive state:
    1. Un swap cambia el precio en el AMM interno del protocolo
    2. Justo antes del swap, alguien llama a una función que lee el precio actual
    3. El searcher puede reordenar para que esa función lea el precio ANTES del swap
    4. O DESPUÉS del swap, dependiendo de qué sea más beneficioso para el searcher
  invariante: |
    // Este tipo de MEV es difícil de invariar — la defensa es en el diseño
    // Una heurística: las funciones que leen precio no deben ejecutar lógica financiera
    // en el mismo bloque donde puede ocurrir un swap grande
    function check_price_read_staleness(uint256 priceTimestamp) internal view {
        // El precio no debe ser del bloque actual si hay transacciones pendientes
        t(block.timestamp - priceTimestamp > 0 ||
          !hasPendingSwapsThisBlock(),
          "MEV-008: price read from same block as pending large swap");
    }
  que_mirar:
    - "¿Hay funciones que benefician a quien las llama primero en un bloque?"
    - "¿El protocolo tiene acciones dependientes del precio actual del bloque?"
    - "¿Las acciones de governance tienen efectos de precio inmediatos que pueden ser especulados?"
    - "¿Hay un 'first come first served' con valor significativo?"
  como_se_arregla: |
    - Usar commit-reveal para operaciones price-sensitive cuando sea posible
    - Para governance: delay de ejecución post-vote (timelock) para reducir front-running
    - Para operaciones urgentes (liquidaciones): mecanismos de asignación, no carrera libre
  trampas:
    - "Transaction ordering es inherente a blockchains — no se puede eliminar, solo mitigar"
    - "En chains con sequencers privados (Arbitrum, Base), el ordenamiento es controlado por el operador — diferente modelo de riesgo"
  solodit_ids:
    - "m-transaction-ordering-dependency-allows-mev-extraction-code4rena-git"

- id: mev-009
  titulo: Token Approval MEV — Approve + Transfer en Txs Separadas
  causa_raiz: |
    El patrón ERC20 de approve + transferFrom en dos transacciones crea una ventana
    de vulnerabilidad. Entre el approve y el transferFrom, un atacante (si el spender
    no es de confianza) puede usar el approve para sus propósitos. También, el valor
    del approve puede ser diferente del intendido si hay condiciones cambiantes entre txs.
  como_funciona: |
    Variante A — Allowance race (clásico):
    1. Alice aprueba a Bob a gastar 100 tokens (tx 1)
    2. Bob ya tenía una approval de 50 tokens
    3. Alice intenta bajar de 50 a 100 → pero llama approve(100)
    4. Bob front-runs: usa los 50 previos ANTES de que el approve(100) ejecute
    5. Después del approve(100): Bob tiene 100 más disponibles → usa otros 100
    6. Total: Bob gastó 150, Alice quería darle solo 100

    Variante B — Sandwich de permit:
    1. Alice usa EIP-2612 permit para aprobar y hacer swap en una tx
    2. Si el permit no especifica el recipient del swap, el atacante puede interceptar
  invariante: |
    // El riesgo del approve race solo existe si el spender no es de confianza
    // Para protocolos: verificar que el allowance es exactamente el necesario
    function check_allowance_not_excess(address token, address spender, uint256 requiredAmount) internal view {
        uint256 currentAllowance = IERC20(token).allowance(address(this), spender);
        t(currentAllowance <= requiredAmount * 110 / 100, // máximo 10% de exceso
          "MEV-009: token allowance far exceeds required amount");
    }
  que_mirar:
    - "¿El protocolo hace approve a contratos externos antes de depositar?"
    - "¿La aprobación es del monto exacto o type(uint256).max?"
    - "¿Hay un paso de approve en una tx y el uso del approve en otra tx separada?"
    - "¿Los permits de EIP-2612 especifican el recipient o dejan libertad al executor?"
  como_se_arregla: |
    - Usar SafeERC20.forceApprove(0) antes de approve(amount) para reset
    - O: usar approve(exactAmount) y luego approve(0) después del uso
    - Para permisos EIP-2612: siempre especificar el recipient y el use-case exacto
    - Preferir approve(exactAmount) sobre approve(type(uint256).max) para spenders externos
  trampas:
    - "type(uint256).max approve es común y seguro para protocolos de confianza (Uniswap, Aave)"
    - "El approve race clásico requiere que el spender sea adversarial — en DeFi el spender suele ser un contrato fijo"
  solodit_ids:
    - "m-05-risk-of-overborrowing-by-only-using-price-rate-feed-recon-audits-none-quill-finance-report-markdown"

- id: mev-010
  titulo: Oracle Update Sandwich — Front-Run Chainlink Price Feeds
  causa_raiz: |
    Los oráculos de Chainlink actualizan el precio cuando la desviación supera un umbral
    (deviation threshold, e.g., 0.5%) o cuando pasa el heartbeat (e.g., 1 hora). Estas
    actualizaciones son visibles en el mempool antes de ejecutarse. Un atacante puede:
    (1) ver la tx de update del oráculo, (2) front-run depositando/comprando antes del
    cambio de precio, (3) back-run después del update para capturar la diferencia.
    Protocolos que usan el precio de Chainlink directamente sin cooldowns son vulnerables.
  como_funciona: |
    1. ETH vale $2000 on-chain (precio actual de Chainlink)
    2. ETH sube a $2020 en mercados centralizados (1% de desviación)
    3. El nodo de Chainlink envía la tx de update al mempool
    4. Atacante front-runs: deposita ETH como colateral (valorado a $2000)
    5. Update ejecuta: ETH ahora vale $2020 on-chain
    6. Atacante back-runs: pide prestado más contra el colateral revaluado
    7. O inversamente: si el precio baja, el atacante retira antes del update

    En vaults con NAV basado en oracle: deposita antes del update favorable,
    retira después → extrae valor del vault a costa de los otros LPs.
  invariante: |
    function check_no_action_in_oracle_update_block(
        uint256 oracleLastUpdate, uint256 actionTimestamp
    ) internal view {
        // No se debería permitir deposit/withdraw en el mismo bloque que un oracle update
        t(actionTimestamp != oracleLastUpdate,
          "MEV-010: action in same block as oracle update — possible sandwich");
    }
  que_mirar:
    - "Vault que usa Chainlink directamente sin delay entre oracle update y operaciones"
    - "Protocolos donde el NAV depende de un solo oracle feed actualizable"
    - "Funciones de deposit/withdraw sin cooldown post-oracle-update"
    - "Chainlink heartbeat gaps largos (1h+) que crean ventanas de arbitraje predecibles"
  como_se_arregla: |
    - Implementar un delay de 1 bloque entre oracle update y operaciones de usuario
    - Usar TWAP del oráculo en vez de precio puntual para calcular NAV
    - Limitar el tamaño de deposit/withdraw por bloque
    - Circuit breaker: pausar si el precio cambia >X% en un bloque
  trampas:
    - "El delay de 1 bloque no funciona si el atacante es el builder del bloque"
    - "En L2 con bloques rápidos (2s), los oráculos actualizan con más frecuencia — menor ventana"
    - "Olympus RBS fue explotado exactamente con este patrón — deposit → oracle update → profit"
  solodit_ids:
    - "h-1-adversary-can-sandwich-oracle-updates-to-exploit-vault-sherlock-olympus-olympus-update-git"
    - "oracle-updates-are-vulnerable-to-sandwich-attacks-quantstamp-afi-vault-markdown"
    - "oracle-update-front-running-allows-extraction-of-value-from-vaults-trailofbits-none-cap-labs-covered-agent-protocol-pdf"
  incidentes:
    - "Olympus RBS vault exploit — adversary sandwiched oracle updates to extract value"
  verificado: true
  confianza: 95

- id: mev-011
  titulo: Deposit/Withdraw Sandwich en ERC4626 Vaults — Exchange Rate Manipulation
  causa_raiz: |
    Los vaults ERC4626 calculan shares basándose en totalAssets/totalShares. Funciones que
    modifican el exchange rate (harvest, rebalance, donate, repay) son sandwicheables:
    el atacante deposita antes del evento que sube el rate, y retira después. Los LPs
    legítimos absorben la dilución. Es particularmente grave en vaults que reciben
    callbacks (Morpho supply/repay) que actualizan lastTotalAssets.
  como_funciona: |
    1. Vault tiene 1000 USDC, 1000 shares → rate = 1.0
    2. Se va a ejecutar un harvest() que añade 50 USDC de profit → rate subirá a 1.05
    3. Atacante front-runs: deposita 10000 USDC → recibe 10000 shares
    4. harvest() ejecuta: vault ahora tiene 11050 USDC, 11000 shares → rate = 1.0045
    5. Atacante redime 10000 shares → recibe ~10045 USDC
    6. Profit: ~45 USDC que deberían haber ido a los LPs originales
    7. LPs originales pierden ~45 USDC en yield diluido

    Con flash loans, el atacante puede amplificar el depósito masivamente.
  invariante: |
    function check_no_deposit_before_rate_change(
        uint256 sharesBefore, uint256 sharesAfter,
        uint256 rateBefore, uint256 rateAfter
    ) internal view {
        // Si el rate subió significativamente, no debería haber depósitos grandes
        if (rateAfter > rateBefore * 101 / 100) { // rate subió >1%
            t(sharesAfter <= sharesBefore * 110 / 100,
              "MEV-011: large deposit just before exchange rate increase");
        }
    }
  que_mirar:
    - "Vaults ERC4626 donde harvest/rebalance es público y modifica el exchange rate"
    - "Callbacks como onMorphoSupplyCollateral que actualizan lastTotalAssets"
    - "Funciones de donate() o directTransfer que inflan totalAssets instantáneamente"
    - "Falta de deposit caps o cooldowns entre deposit y withdraw"
  como_se_arregla: |
    - Implementar un lock period mínimo entre deposit y withdraw (e.g., 1 epoch)
    - Usar virtual shares/assets (OpenZeppelin ERC4626 con offset) para suavizar
    - Calcular el rate con TWAP de assets en vez de valor instantáneo
    - Rate limitar deposits grandes antes de eventos de rate change conocidos
  trampas:
    - "Los vaults con virtual shares (offset=1) mitigan inflation pero no eliminan el sandwich"
    - "El lock period puede causar UX friction — balance entre seguridad y usabilidad"
    - "En Morpho Vaults, los callbacks de supply/repay son particularmente vulnerables"
  solodit_ids:
    - "l-04-operations-that-modify-the-exchange-rate-can-be-frontrun-pashov-audit-group-none-loopvaults_2025-04-30-markdown"
    - "deposit-and-withdraw-functions-are-susceptible-to-sandwich-attacks-spearbit-gauntlet-pdf"
    - "m-5-the-exchangeratestored-function-allows-front-running-on-repayments-sherlock-union-union-finance-update-git"
  verificado: true
  confianza: 92

- id: mev-012
  titulo: sqrtPriceLimitX96 Sin Protección — Partial Swap Silenciosa en Uniswap V3
  causa_raiz: |
    En Uniswap V3, el parámetro sqrtPriceLimitX96 limita hasta dónde puede mover el
    precio un swap. Si se pasa 0 (o el valor máximo/mínimo), el swap ejecuta sin límite
    de price impact. Peor aún: si sqrtPriceLimitX96 se alcanza, el swap ejecuta
    PARCIALMENTE sin revertir — el contrato cree que swapeó todo pero solo swapeó
    una fracción, dejando tokens atrapados o accounting incorrecto.
  como_funciona: |
    1. Protocolo llama swap(1000 USDC → ETH, sqrtPriceLimitX96 = MIN_SQRT_RATIO + 1)
    2. El pool mueve el precio hasta el límite y PARA — solo 200 USDC se swapean
    3. El protocolo asume que recibió ETH por los 1000 USDC (no verifica amountIn real)
    4. 800 USDC quedan en el router o se pierden
    5. El atacante puede haber manipulado el pool antes para que el límite se alcance rápido

    Variante: sqrtPriceLimitX96 = 0 → sin protección → sandwich a placer
  invariante: |
    function check_swap_fully_executed(
        uint256 amountInExpected, uint256 amountInActual
    ) internal view {
        t(amountInActual >= amountInExpected * 99 / 100,
          "MEV-012: swap only partially filled — possible sqrtPriceLimit issue");
    }
  que_mirar:
    - "sqrtPriceLimitX96 hardcodeado a MIN_SQRT_RATIO+1 o MAX_SQRT_RATIO-1"
    - "Swaps que no verifican el amountIn/amountOut real retornado"
    - "Funciones que asumen exactInput siempre consume todo el input"
    - "Router calls sin verificación post-swap del balance"
  como_se_arregla: |
    - Verificar SIEMPRE el retorno del swap: require(amountIn == expectedAmountIn)
    - Calcular sqrtPriceLimitX96 basado en el slippage tolerance deseado
    - Revertir si el swap fue parcial y no se esperaba
    - Usar exactInput con minAmountOut en vez de confiar en sqrtPriceLimitX96
  trampas:
    - "Un swap parcial no es un error — es comportamiento normal de Uniswap V3 cuando se alcanza el límite"
    - "La mayoría de protocolos ignoran que exactInputSingle puede no consumir todo el input"
    - "El sqrtPriceLimitX96 correcto requiere calcular la raíz cuadrada del precio deseado — la mayoría hardcodea"
  solodit_ids:
    - "h-9-uniswapv3-sqrtratiolimit-doesnt-provide-slippage-protection-and-will-result-in-partial-swaps-sherlock-none-blueberry-update-git"
    - "m-2-perpdepository_rebalancenegativepnlwithswap-shouldnt-use-a-sqrtpricelimitx96-twice-sherlock-uxd-uxd-protocol-git"
    - "h-2-mintokenamounts_-is-useless-in-new-configuration-and-doesnt-provide-any-real-slippage-protection-sherlock-olympus-olympus-update-git"
  verificado: true
  confianza: 90

- id: mev-013
  titulo: Compound/AutoCompound Sandwich — Reward Conversion Explotable
  causa_raiz: |
    Los protocolos de auto-compound (AutoPxGmx, AutoCompoundingPodLP, etc.) tienen
    funciones públicas de compound() que venden tokens de reward (CRV, CVX, AERO) y
    los reinvierten. Si el caller puede controlar los parámetros de slippage o si el
    compound no tiene protección, un MEV bot sandwichea cada compound: compra el token
    de reward antes → compound vende a peor precio → bot vende → profit.
  como_funciona: |
    1. AutoPxGmx tiene 500 GMX de rewards pendientes
    2. Cualquiera puede llamar compound() — es público
    3. MEV bot: front-run comprando GMX → precio sube
    4. compound() vende 500 GMX al precio inflado → recibe menos WETH
    5. Bot back-run vendiendo GMX → precio vuelve → profit
    6. Los LPs del vault reciben menos reinversión de la debida

    Peor: si compound() acepta parámetros de slippage del caller, el atacante
    puede pasar minAmountOut=0 directamente y sandwichear libremente.
  invariante: |
    function check_compound_slippage(
        uint256 rewardValue, uint256 compoundedValue
    ) internal view {
        // El valor compounded no debe ser <95% del valor de rewards
        t(compoundedValue >= rewardValue * 95 / 100,
          "MEV-013: compound returns significantly less than reward value");
    }
  que_mirar:
    - "Funciones compound() o autoCompound() públicas sin access control"
    - "Parámetros de slippage que el caller puede setear (potencialmente a 0)"
    - "Protocolos que venden large amounts de reward tokens en un solo swap"
    - "Auto-compounders que usan DEXs con poca liquidez para el par de reward"
  como_se_arregla: |
    - Restringir compound() a keepers whitelisted con cálculo off-chain de minAmountOut
    - Si es público: hardcodear el slippage mínimo (e.g., 2%) usando oracle TWAP
    - Dividir la venta de rewards en múltiples swaps pequeños (TWAP execution)
    - No permitir que el caller controle los parámetros de slippage
  trampas:
    - "Incluso con slippage hardcodeado, un attacker puede manipular el pool justo debajo del umbral"
    - "Los compound frecuentes con cantidades pequeñas son menos sandwicheables que uno grande"
    - "En L2 sin mempool pública, el compound sandwich es mucho más difícil"
  solodit_ids:
    - "m-03-anyone-can-call-autopxgmxcompound-and-perform-sandwich-attacks-with-control-parameters-code4rena-redacted-cartel-redacted-cartel-contest-git"
    - "m-27-autocompoundingpodlp-does-not-use-correct-oracle-price-as-slippage-for-pairedlptkn-ptkn-swap-sherlock-peapods-git"
    - "h-harvest-function-is-susceptible-to-mev-sandwich-attack-code4rena-git"
  verificado: true
  confianza: 93

- id: mev-014
  titulo: Cross-Chain Slippage — MEV en Bridge Destination Sin Protección
  causa_raiz: |
    En protocolos cross-chain (Connext, LiFi, bridges), el usuario especifica slippage
    tolerance en la chain de origen, pero el swap en la chain de destino puede ejecutar
    con slippage diferente o sin protección. El mensaje cross-chain puede llegar con
    delay, y el precio en destino puede haber cambiado. Si el protocolo no permite
    override de slippage en destino, el usuario está forzado a aceptar cualquier precio.
  como_funciona: |
    1. Alice envía 1000 USDC de Ethereum → Polygon vía bridge + swap
    2. Especifica slippage: 1% (esperando recibir >990 USDC equivalentes en MATIC)
    3. El mensaje tarda 30 min en procesarse en Polygon
    4. El precio de MATIC cambió 5% en esos 30 min
    5. El relayer en Polygon ejecuta el swap con el slippage de origen (1%)
    6. O peor: el swap en destino no tiene slippage check → el relayer/MEV bot sandwichea
    7. Alice recibe 900 USDC de valor en vez de 990

    Variante: el slippageTol no ajusta por diferencia de decimales entre chains
  invariante: |
    function check_cross_chain_slippage(
        uint256 amountSent, uint256 amountReceived, uint256 maxSlippageBps
    ) internal view {
        uint256 minExpected = amountSent * (10000 - maxSlippageBps) / 10000;
        t(amountReceived >= minExpected,
          "MEV-014: cross-chain execution with excessive slippage");
    }
  que_mirar:
    - "Bridge que ejecuta swap en destino sin parámetro de slippage del usuario"
    - "SlippageTol que no ajusta por diferencias de decimales entre tokens"
    - "Mismo slippage param usado para dos swaps diferentes (origen y destino)"
    - "Relayers que pueden elegir cuándo ejecutar (timing exploit)"
  como_se_arregla: |
    - Permitir al usuario especificar slippage separado para cada chain
    - Implementar fallback: si el swap falla, guardar los tokens en escrow (no perderlos)
    - Ajustar slippageTol por decimales del token de destino
    - Usar oracle en destino para calcular minAmountOut en el momento de ejecución
  trampas:
    - "Los bridges con AMMs propios (Connext) tienen slippage diferente al DEX de destino"
    - "Si el slippage falla y no hay fallback, los fondos quedan locked en el bridge"
    - "En bridges optimistic, el delay de 7 días crea ventanas de MEV enormes"
  solodit_ids:
    - "users-are-forced-to-accept-any-slippage-on-the-destination-chain-spearbit-connext-pdf"
    - "user-may-not-be-able-to-override-slippage-on-destination-spearbit-connext-pdf"
    - "slippagetol-does-not-adjust-for-decimal-differences-spearbit-connext-pdf"
    - "same-paramsslippagetol-is-used-in-two-different-swaps-spearbit-connext-pdf"
  verificado: true
  confianza: 90

- id: mev-015
  titulo: Hook/Callback Backrun — Auto-Backrun en AMM Hooks para Fee Farming
  causa_raiz: |
    Los AMMs con hooks (Uniswap V4, protocolos custom) pueden ejecutar lógica arbitraria
    antes/después de cada swap via _afterSwap/_beforeSwap. Si el hook auto-ejecuta un
    swap inverso (backrun) cuando el precio cruza un umbral, un atacante puede triggear
    la condición repetidamente para farming de fees. El hook está diseñado para
    estabilizar el precio, pero se convierte en una fuente de MEV explotable.
  como_funciona: |
    1. Hook _afterSwap: si sqrtPriceX96 <= 1.0, ejecuta backrun (compra para subir precio)
    2. Atacante: vende token para bajar precio a 0.999 → hook se activa
    3. Hook backrunea: compra token con reserves del pool → precio sube a 1.001
    4. Atacante: ya tenía posición comprada antes → vende al precio subido → profit
    5. El hook pagó fees al pool pero el atacante extrajo valor neto positivo
    6. Repetir: cada vez que el atacante trigger el hook, extrae LP fees

    El hook actúa como un "free liquidity" que el atacante puede explotar
    sin asumir riesgo de impermanent loss
  invariante: |
    function check_hook_not_exploitable(
        uint256 hookExecutions, uint256 blockNumber
    ) internal view {
        // No más de N ejecuciones del hook por bloque
        t(hookExecutions <= MAX_HOOK_EXECUTIONS_PER_BLOCK,
          "MEV-015: excessive hook executions — possible farming attack");
    }
  que_mirar:
    - "Hooks _afterSwap que ejecutan swaps automáticos basados en condiciones de precio"
    - "Hooks que usan reserves del pool para backrun — el atacante puede triggear repetidamente"
    - "Lógica de peg-keeping o price stabilization en hooks sin rate limiting"
    - "Hooks sin cooldown entre ejecuciones"
  como_se_arregla: |
    - Rate limit las ejecuciones del hook: máximo 1 por bloque o por epoch
    - El hook no debería usar reserves del pool directamente — usar reserves dedicados
    - Añadir cooldown mínimo entre activaciones del hook
    - Implementar fee crescente por ejecución repetida
  trampas:
    - "Los hooks de Uniswap V4 son nuevos — los patrones de explotación están emergiendo"
    - "El backrun automático es una feature deseada pero debe tener protección anti-farming"
    - "El atacante puede usar múltiples wallets para evadir rate limits por address"
  solodit_ids:
    - "self-triggered-licredity_afterswap-back-run-enables-lp-fee-farming-cyfrin-none-licredity-markdown"
  incidentes:
    - "Licredity — _afterSwap auto-backrun enabled LP fee farming via repeated trigger"
  verificado: true
  confianza: 88

- id: mev-016
  titulo: Permit Front-Run DoS — Griefing de Operaciones con ERC-2612 Permit
  causa_raiz: |
    Funciones que combinan permit() + acción (deposit, swap, addLiquidity) en una sola
    tx son vulnerables a DoS. Un atacante puede front-run la tx extrayendo solo el
    permit() (que es una tx independiente), consumiendo el nonce. Cuando la tx original
    ejecuta, el permit() interno revierte porque el nonce ya fue usado. El atacante no
    gana dinero pero impide que el usuario opere (griefing).
  como_funciona: |
    1. Alice envía tx: depositWithPermit(amount, deadline, v, r, s)
    2. La firma v,r,s es visible en el mempool
    3. Atacante front-runs: llama permit(Alice, spender, amount, deadline, v, r, s) directamente
    4. El permit ejecuta exitosamente → el nonce de Alice se incrementa
    5. La tx de Alice ejecuta → el permit() interno falla porque el nonce ya se usó
    6. Toda la tx de Alice revierte → Alice no puede depositar

    Si el protocolo no tiene un path sin permit (deposit sin permit), Alice está
    permanentemente bloqueada hasta que genere una nueva firma.
  invariante: |
    // Defensa: el contrato debe catch el revert del permit y continuar si el allowance ya existe
    function check_permit_failure_handled(
        address token, address owner, address spender, uint256 amount
    ) internal view {
        uint256 currentAllowance = IERC20(token).allowance(owner, spender);
        // Si el allowance ya es suficiente, el permit no es necesario
        t(currentAllowance >= amount,
          "MEV-016: permit failed and allowance insufficient");
    }
  que_mirar:
    - "Funciones *WithPermit() que no hacen try/catch en la llamada a permit()"
    - "Protocolos sin path alternativo (deposit sin permit) para usuarios afectados"
    - "Permit2 de Uniswap — mismo problema pero con nonces más complejos"
    - "Routers que combinan multiple permits en una tx (todos deben funcionar o revierte)"
  como_se_arregla: |
    - SIEMPRE hacer try/catch en permit(): si falla, verificar que el allowance ya es suficiente
    - Proveer funciones con y sin permit: deposit() + depositWithPermit()
    - Verificar allowance antes de llamar permit — si ya existe, skip
    - Para Permit2: usar batch permits con nonces no-secuenciales
  trampas:
    - "El DoS es temporal — el usuario puede hacer approve() clásico y luego deposit()"
    - "En L2 sin mempool pública, el front-run del permit es imposible"
    - "Algunos jueces lo clasifican como Low/QA — pero para routers sin path alternativo es Medium"
  solodit_ids:
    - "m-10-erc-2612-permit-front-running-in-routerv2-enables-dos-of-liquidity-operations-code4rena-audit-507-audit-507-git"
    - "transaction-dos-via-permit-front-running-mixbytes-none-eywa-markdown"
    - "possible-dos-attack-on-swapping-via-permit2-openzeppelin-none-periphery-changes-audit-markdown"
    - "permit-front-running-can-dos-requestmintwithpermit-spearbit-none-buck-labs-pdf"
  verificado: true
  confianza: 91

- id: mev-017
  titulo: Liquidation Sandwich — Manipulación de Precio Pre-Liquidación
  causa_raiz: |
    Un atacante puede combinar manipulación de precio (vía DEX) con ejecución de
    liquidación para profit doble. Primero empuja el precio del colateral hacia abajo
    (haciendo posiciones liquidables que no lo eran), luego ejecuta la liquidación
    (ganando el bonus), y finalmente revierte la manipulación de precio. Si el protocolo
    usa precios de DEX para liquidaciones (no Chainlink), esto es trivial.
  como_funciona: |
    1. Bob tiene posición con health factor 1.05 (no liquidable)
    2. Atacante en un bloque atómico:
       a. Flash loan 10M USDC
       b. Vende el colateral token en el DEX → precio baja 8%
       c. El oráculo del protocolo (si usa DEX) refleja el precio bajo
       d. Bob ahora tiene health factor 0.97 → liquidable
       e. Atacante ejecuta liquidación de Bob → gana bonus (5-10% del colateral)
       f. Atacante recompra el colateral token → precio vuelve
       g. Devuelve flash loan
    3. Profit: liquidation bonus - flash loan fee - swap fees

    Variante sin flash loan: manipular TWAP durante varios bloques (multi-block MEV)
    si el protocolo usa TWAP corto
  invariante: |
    function check_health_factor_not_artificially_low(
        uint256 oraclePrice, uint256 twapPrice
    ) internal view {
        // El precio del oráculo no debe divergir mucho del TWAP
        uint256 divergence = oraclePrice > twapPrice ?
            (oraclePrice - twapPrice) * 10000 / twapPrice :
            (twapPrice - oraclePrice) * 10000 / twapPrice;
        t(divergence <= 300, // max 3% de divergencia
          "MEV-017: oracle price diverges from TWAP — possible manipulation pre-liquidation");
    }
  que_mirar:
    - "Protocolo de lending que usa precios de DEX (no Chainlink) para liquidaciones"
    - "TWAP period demasiado corto (<15 min) para trigger de liquidación"
    - "Liquidación sin delay — ejecutable en el mismo bloque que la manipulación"
    - "Mercados con poca liquidez donde mover el precio es barato"
  como_se_arregla: |
    - Usar Chainlink como oráculo primario para liquidaciones (resistente a flash loan)
    - Si se usa DEX: TWAP mínimo de 30 min para trigger de liquidación
    - Implementar grace period: posición debe ser liquidable durante N bloques consecutivos
    - Circuit breaker: si el precio del oráculo diverge >5% del TWAP, pausar liquidaciones
  trampas:
    - "Con Chainlink el ataque es mucho más caro (necesita mover mercados spot reales)"
    - "Multi-block MEV con proposer collusion puede manipular TWAPs largos pero es extremadamente caro"
    - "El grace period protege pero introduce riesgo de bad debt si el mercado realmente cae"
  solodit_ids:
    - "m-9-missing-slippage-protection-in-liquidation-allows-unexpected-collateral-loss-sherlock-cap-git"
    - "m-11-an-attacker-can-manipulate-oracle-easily-code4rena-panoptic-panoptic-git"
  incidentes:
    - "Mango Markets (Oct 2022) — $114M drained via oracle manipulation + self-liquidation"
  verificado: true
  confianza: 92

- id: mev-018
  titulo: L2 Sequencer Down — Acciones Sin Precio Fresco Post-Restart
  causa_raiz: |
    En L2 (Arbitrum, Optimism, Base), el sequencer ordena las transacciones. Si el
    sequencer se cae, los oráculos de Chainlink dejan de actualizarse. Cuando el
    sequencer vuelve, los precios on-chain están stale (desactualizados) pero las
    operaciones del protocolo se reanudan inmediatamente. Un atacante puede explotar
    la diferencia entre el precio stale on-chain y el precio real del mercado.
  como_funciona: |
    1. Sequencer de Arbitrum se cae durante 2 horas
    2. ETH estaba a $2000 cuando se cayó → ese precio queda frozen on-chain
    3. Durante las 2 horas, ETH baja a $1800 en mercados reales
    4. Sequencer vuelve online → las transacciones empiezan a procesarse
    5. Los oráculos de Chainlink aún no han actualizado (necesitan 1-2 bloques)
    6. Atacante, en los primeros bloques:
       - Pide prestado contra colateral de ETH (valorado a $2000 stale)
       - El ETH realmente vale $1800 → posición undercollateralized
       - O: compra tokens baratos con ETH sobrevaluado
    7. Cuando el oráculo actualiza: posiciones ya están bad debt
  invariante: |
    function check_sequencer_uptime(address sequencerFeed) internal view {
        (, int256 answer, uint256 startedAt,,) = AggregatorV3Interface(sequencerFeed).latestRoundData();
        bool isUp = answer == 0;
        uint256 timeSinceUp = block.timestamp - startedAt;
        t(isUp, "MEV-018: L2 sequencer is down");
        t(timeSinceUp > GRACE_PERIOD, "MEV-018: grace period not elapsed since sequencer restart");
    }
  que_mirar:
    - "Protocolo en L2 que no chequea el Chainlink Sequencer Uptime Feed"
    - "Grace period insuficiente después del restart del sequencer (<1 hora)"
    - "Acciones sensibles a precio (borrow, liquidate, swap) sin check de sequencer"
    - "Protocolo que asume que el oráculo siempre está fresh en L2"
  como_se_arregla: |
    - Implementar check de Chainlink Sequencer Uptime Feed en CADA lectura de precio
    - Grace period de 1 hora después del restart antes de permitir operaciones
    - Pausar automáticamente borrowing/liquidations durante sequencer downtime
    - Verificar freshness del precio: require(block.timestamp - updatedAt < heartbeat)
  trampas:
    - "El Sequencer Uptime Feed solo existe en Arbitrum y OP chains con Chainlink — no en todos los L2"
    - "El grace period debe ser suficiente para que TODOS los oráculos actualicen"
    - "Un grace period demasiado largo bloquea operaciones legítimas innecesariamente"
  solodit_ids:
    - "m-4-no-check-for-active-arbitrum-sequencer-in-wsteth-oracle-sherlock-sentiment-sentiment-update-git"
    - "m-3-_validateandgetprice-doesnt-check-if-arbitrum-sequencer-is-down-in-chainlink-feeds-sherlock-bond-protocol-update-git"
    - "missing-l2-sequencer-uptime-check-in-oracleadapter-cyfrin-none-yieldfi-markdown"
    - "m-1-stetheth-chainlink-oracle-has-too-long-of-heartbeat-and-deviation-threshold-which-can-cause-loss-of-funds-sherlock-olympus-olympus-update-git"
  incidentes:
    - "Arbitrum sequencer outage (Jun 2023) — stale prices exploitable for ~1 hour"
  verificado: true
  confianza: 94

- id: mev-019
  titulo: Rebalance en LP Público sin Access Control — MEV Bot Controla Parámetros
  causa_raiz: |
    Las funciones de rebalance en protocolos de LP management (Arrakis, Gamma, Bunni)
    son frecuentemente públicas para que keepers las llamen. Si el caller puede influir
    en los parámetros del rebalance (nuevo rango, proporción de tokens, o simplemente
    el timing), un MEV bot puede: (1) mover el precio del pool, (2) llamar rebalance
    al precio manipulado, (3) revertir la manipulación. El protocolo rebalancea
    al precio incorrecto, causando pérdida para los LPs.
  como_funciona: |
    1. Vault LP tiene posición en rango [1900, 2100] para ETH/USDC
    2. El precio actual de ETH es $2000
    3. Atacante: swap masivo → precio baja a $1950
    4. Atacante llama rebalance() → el vault ajusta su posición al nuevo "precio"
    5. El vault vende ETH a $1950 y reposiciona la liquidez
    6. Atacante revierte el swap → precio vuelve a $2000
    7. El vault vendió ETH a $1950 que ahora vale $2000 → pérdida de 2.5%

    Si el rebalance es grande (vault de $10M), la pérdida es $250K por rebalance
  invariante: |
    function check_rebalance_price_sanity(
        uint256 rebalancePrice, uint256 oraclePrice
    ) internal view {
        uint256 deviation = rebalancePrice > oraclePrice ?
            (rebalancePrice - oraclePrice) * 10000 / oraclePrice :
            (oraclePrice - rebalancePrice) * 10000 / oraclePrice;
        t(deviation <= 100, // max 1% de desviación vs oracle
          "MEV-019: rebalance executing at price deviating >1% from oracle");
    }
  que_mirar:
    - "Funciones de rebalance/rerange públicas sin restricción de caller"
    - "Rebalance que no verifica el precio actual contra un oráculo externo"
    - "Protocolos LP que permiten que el caller especifique el nuevo rango"
    - "Ausencia de slippage check en la liquidación de posición vieja y creación de nueva"
  como_se_arregla: |
    - Restringir rebalance a keepers autorizados con cálculo off-chain
    - Verificar precio contra Chainlink/TWAP antes de ejecutar el rebalance
    - Añadir slippage protection en cada paso del rebalance (remove liquidity + add liquidity)
    - Implementar cooldown entre rebalances para evitar manipulación repetida
  trampas:
    - "El rebalance tiene que ser algún día ejecutado — no se puede bloquear indefinidamente"
    - "Keepers centralizados son un punto de fallo — balance entre descentralización y protección"
    - "En pools de alta liquidez, mover el precio es caro — el ataque solo es rentable en pools medianos"
  solodit_ids:
    - "h-08-staking-unstaking-and-rebalancetoweight-can-be-sandwiched-mainly-reth-deposit-code4rena-asymmetry-finance-asymmetry-contest-git"
    - "h-6-all-eth-can-be-stolen-during-rebalancing-for-mtofts-that-hold-native-sherlock-tapioca-git"
    - "front-running-attacks-on-finalize-could-affect-received-token-amounts-spearbit-gauntlet-pdf"
  verificado: true
  confianza: 91
