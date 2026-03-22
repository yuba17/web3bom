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
