# Concentrated Liquidity (Uniswap V3 Style) — Combat Briefing

> Todo lo que un auditor necesita antes de revisar un protocolo de liquidez concentrada.
> Cubre: Uniswap V3, PancakeSwap V3, SushiSwap V3, Velodrome V2/V3, Aerodrome, Algebra, Ramses, Thena.
> Sources: Trail of Bits Uniswap V3 audit, Sherlock/C4/Cantina contests, Solodit findings.

---

## 1. Bugs Conocidos

### 1.1 Tick Math Overflow/Underflow

```yaml
- id: CLIQ-01
  pattern: tick-math-overflow
  titulo: "Overflow/underflow en TickMath.getSqrtRatioAtTick en rangos extremos"
  descripcion: >
    La función TickMath.getSqrtRatioAtTick convierte un tick (int24) a un
    sqrtPriceX96 (uint160) mediante una serie de multiplicaciones con
    constantes mágicas. En los extremos del rango de ticks (cerca de
    MIN_TICK = -887272 y MAX_TICK = 887272), los cálculos intermedios
    pueden desbordar si no se manejan correctamente en implementaciones
    derivadas o forks. Uniswap V3 original usa assembly unchecked con
    cuidado, pero forks que modifican el rango de ticks, cambian el
    tipo de dato, o añaden tick spacing personalizado pueden introducir
    overflow. El resultado es un sqrtPrice incorrecto que distorsiona
    el precio de la pool y permite extracción de valor.
  patron_vulnerable: |
    // Fork que extiende MIN_TICK/MAX_TICK sin actualizar las constantes
    function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160) {
        uint256 absTick = tick < 0 ? uint256(-int256(tick)) : uint256(int256(tick));
        // ERROR: require usa MAX_TICK original pero el fork permite ticks mayores
        require(absTick <= uint256(887272), 'T');

        uint256 ratio = absTick & 0x1 != 0
            ? 0xfffcb933bd6fad37aa2d162d1a594001
            : 0x100000000000000000000000000000000;
        // ... multiplicaciones intermedias que asumen rango original
        // Si absTick > 887272, las multiplicaciones producen basura
    }

    // Otro error: cast int24 -> int256 sin verificar signo
    function tickToPrice(int24 tick) external view returns (uint256) {
        // int24 puede ser -8388608 si se fuerza via assembly
        uint256 absTick = uint256(int256(tick)); // UNDERFLOW si tick < 0 en Solidity < 0.8
    }
  test_invariante: |
    // Invariante: sqrtPrice debe estar en rango válido para todo tick válido
    function invariant_tickMathBounded() public {
        int24 tick = int24(clampBetween(int256(ghost_lastTick), -887272, 887272));
        uint160 sqrtPrice = TickMath.getSqrtRatioAtTick(tick);
        t(sqrtPrice >= TickMath.MIN_SQRT_RATIO, "CLIQ-01: sqrtPrice below minimum");
        t(sqrtPrice <= TickMath.MAX_SQRT_RATIO, "CLIQ-01: sqrtPrice above maximum");

        // Propiedad inversa: getTickAtSqrtRatio debe ser consistente
        int24 recoveredTick = TickMath.getTickAtSqrtRatio(sqrtPrice);
        // Tolerancia de 1 tick por redondeo
        t(recoveredTick >= tick - 1 && recoveredTick <= tick, "CLIQ-01: tick roundtrip failed");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-010: Verificación de que TickMath maneja correctamente MIN_TICK y MAX_TICK. Trail of Bits verificó que los cálculos intermedios no desbordan para el rango permitido, pero advirtió que extensiones del rango requieren re-derivar todas las constantes."
    - audit: "Sherlock - PancakeSwap V3 (2023)"
      detalle: "PancakeSwap V3 copió TickMath de Uniswap pero modificó tick spacing. Auditoría verificó que las constantes permanecen válidas para los tick spacings soportados."
    - audit: "Spearbit - Algebra Protocol"
      detalle: "Algebra usa adaptive fees con tick spacing dinámico. Encontraron que cambios en el tick spacing podían generar ticks fuera del rango esperado por TickMath."
  severidad: high
  confianza: alta
  verificado: true
  tags: [tick-math, overflow, sqrtPrice, TickMath, getSqrtRatioAtTick]
  relacionado_con: [CLIQ-10, CLIQ-13]
```

### 1.2 Error de Fee Accounting en Tick Crossing

```yaml
- id: CLIQ-02
  pattern: fee-accounting-tick-crossing
  titulo: "Acumulación incorrecta de fees al cruzar ticks con posiciones activas"
  descripcion: >
    En Uniswap V3, cuando un swap cruza un tick inicializado, el contrato
    actualiza feeGrowthOutside{0,1}X128 del tick cruzado invirtiendo su
    valor respecto al feeGrowthGlobal. Si esta inversión se hace en el
    orden incorrecto, o si se omite cuando debería hacerse (o viceversa),
    las fees acumuladas por posiciones que abarcan ese tick se calculan
    mal. El resultado es que LPs reciben más o menos fees de las que les
    corresponden. En forks que añaden lógica adicional al tick crossing
    (como distribución de rewards de gauge), el error se amplifica.
    Velodrome V2 y protocolos con gauge integrado son especialmente
    vulnerables porque el tick crossing también dispara actualización
    de rewards de staking.
  patron_vulnerable: |
    // Error: no invertir feeGrowthOutside al cruzar tick
    function cross(int24 tick, uint256 feeGrowthGlobal0X128, uint256 feeGrowthGlobal1X128) internal {
        Tick.Info storage info = ticks[tick];
        // CORRECTO: info.feeGrowthOutside0X128 = feeGrowthGlobal0X128 - info.feeGrowthOutside0X128;
        // ERROR: olvidar la inversión o invertir solo uno de los dos tokens
        info.feeGrowthOutside0X128 = feeGrowthGlobal0X128 - info.feeGrowthOutside0X128;
        // FALTA: info.feeGrowthOutside1X128 = feeGrowthGlobal1X128 - info.feeGrowthOutside1X128;
    }

    // Error en fork con rewards: no sincronizar rewardsGrowthOutside
    function cross(int24 tick, ...) internal {
        // fee growth se invierte correctamente
        info.feeGrowthOutside0X128 = feeGrowthGlobal0X128 - info.feeGrowthOutside0X128;
        info.feeGrowthOutside1X128 = feeGrowthGlobal1X128 - info.feeGrowthOutside1X128;
        // ERROR: rewardsGrowthOutside NO se invierte
        // info.rewardGrowthOutsideX128 = rewardGrowthGlobalX128 - info.rewardGrowthOutsideX128;
    }
  test_invariante: |
    // Invariante: suma de fees reclamadas por todas las posiciones <= fees totales generadas
    function invariant_feeConservation() public {
        uint256 totalFeesCollected0;
        uint256 totalFeesCollected1;
        for (uint i = 0; i < ghost_positionCount; i++) {
            (uint256 f0, uint256 f1) = pool.positions(ghost_positionKeys[i]);
            totalFeesCollected0 += f0;
            totalFeesCollected1 += f1;
        }
        // Las fees reclamadas nunca pueden exceder las fees generadas
        t(totalFeesCollected0 <= ghost_totalFeesGenerated0, "CLIQ-02: fee0 over-distribution");
        t(totalFeesCollected1 <= ghost_totalFeesGenerated1, "CLIQ-02: fee1 over-distribution");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-007: Verificación exhaustiva del mecanismo de inversión de feeGrowthOutside en tick crossing. El audit confirmó la corrección del código original pero señaló la complejidad como riesgo para forks."
    - audit: "Code4rena - Panoptic (2024)"
      detalle: "Panoptic construye opciones sobre posiciones Uniswap V3. Múltiples findings relacionados con el tracking incorrecto de fees acumuladas cuando posiciones se queman y re-mintan en ticks diferentes."
    - audit: "Sherlock - Velodrome V2 (2023)"
      detalle: "H-01: Fee accounting error cuando gauge rewards se acumulan durante tick crossing. rewardGrowthOutside no se invertía correctamente, causando que LPs en ciertos rangos recibieran rewards duplicados."
  severidad: high
  confianza: alta
  verificado: true
  tags: [fee-growth, tick-crossing, feeGrowthOutside, LP-fees, rewards]
  relacionado_con: [CLIQ-06, CLIQ-11]
```

### 1.3 Sandwich Attack con Liquidez Concentrada (JIT Amplificado)

```yaml
- id: CLIQ-03
  pattern: concentrated-liquidity-sandwich
  titulo: "Sandwich attack amplificado por adición/remoción de liquidez concentrada en un solo tick"
  descripcion: >
    La liquidez concentrada permite a un atacante añadir una cantidad masiva
    de liquidez en un rango extremadamente estrecho (1 tick) justo antes de
    un swap grande, capturando la mayoría de las fees de ese swap, y
    removiendo la liquidez inmediatamente después. A diferencia del sandwich
    clásico (comprar antes, vender después), aquí el atacante no manipula
    el precio sino que parasita las fees. El impacto para LPs pasivos es
    la dilución de sus fees. En protocolos con gauge rewards, el atacante
    también puede capturar rewards de staking proporcionalmente. Protocolos
    que integran auto-compound o re-ranging sobre posiciones concentradas
    son especialmente vulnerables porque sus transacciones de rebalanceo son
    predecibles y de alto volumen.
  patron_vulnerable: |
    // El protocolo no tiene protección contra mint+burn atómico
    // Atacante en un solo bloque:

    // 1. Observa swap pendiente de tamaño S en la mempool
    // 2. Calcula el tick actual y el rango que cubrirá el swap

    // Tx 1 (front-run): Añadir liquidez masiva en el rango exacto del swap
    pool.mint(
        attackerAddress,
        currentTick,          // tickLower = tick actual
        currentTick + tickSpacing, // tickUpper = 1 spacing arriba
        type(uint128).max / 2,     // liquidez masiva
        ""
    );

    // Tx 2: El swap de la víctima se ejecuta, genera fees
    // El atacante captura ~99% de las fees por tener ~99% de la liquidez en rango

    // Tx 3 (back-run): Remover toda la liquidez + fees
    pool.burn(currentTick, currentTick + tickSpacing, liquidity);
    pool.collect(attackerAddress, currentTick, currentTick + tickSpacing, MAX, MAX);
  test_invariante: |
    // Invariante: LP pasivo no debe perder más del X% de fees esperadas por dilución JIT
    function invariant_noJITDilution() public {
        // Comparar fees acumuladas por LP pasivo vs fees totales
        uint256 passiveLPShare = ghost_passiveLiquidity * 1e18 / ghost_totalLiquidity;
        uint256 expectedFees = ghost_totalFees * passiveLPShare / 1e18;
        uint256 actualFees = ghost_passiveLPFees;

        // Si un JIT miner captura >90% de las fees, el LP pasivo pierde
        t(actualFees >= expectedFees * 10 / 100, "CLIQ-03: JIT diluted passive LP fees >90%");
    }
  ejemplo_real:
    - audit: "Flashbots Research - JIT Liquidity (2022)"
      detalle: "Documentación de JIT liquidity en Uniswap V3 en mainnet Ethereum. Bots como 0x... añaden/remueven liquidez en el mismo bloque, capturando 2-5% de todas las fees de pools populares. No es un bug del contrato sino un ataque económico habilitado por el diseño."
    - audit: "Sherlock - Bunni V2 (2024)"
      detalle: "H-03: BunniSwapMath no protege contra JIT en su lógica de auto-compound. Rebalanceos generan swaps grandes predecibles que son sistemáticamente JIT-mineados."
    - audit: "Code4rena - Steer Protocol (2023)"
      detalle: "Steer Protocol vaults concentrados eran targets prioritarios de JIT porque sus rebalanceos eran predecibles y generaban swaps de alto volumen en la misma pool."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [JIT, sandwich, liquidity-mining, MEV, fee-dilution]
  relacionado_con: [CLIQ-05, CLIQ-16]
```

### 1.4 Manipulación de Oracle TWAP via Liquidez Concentrada

```yaml
- id: CLIQ-04
  pattern: oracle-manipulation-concentrated
  titulo: "Manipulación del oracle TWAP aprovechando liquidez concentrada para mover precio con menos capital"
  descripcion: >
    Los oráculos TWAP de Uniswap V3 registran el tick acumulado en cada
    bloque donde hay actividad. En pools con liquidez concentrada, la
    profundidad de liquidez varía drásticamente entre rangos de precios.
    Si la mayoría de la liquidez está concentrada en un rango estrecho,
    mover el precio FUERA de ese rango es barato (poca liquidez que
    absorber). Un atacante puede manipular el TWAP sosteniendo el precio
    en un tick extremo durante varios bloques con relativamente poco
    capital. Protocolos que usan el TWAP de Uniswap V3 como oracle
    principal (sin cross-validación con Chainlink) son vulnerables.
    El costo del ataque depende de: 1) liquidez fuera del rango
    concentrado, 2) duración del window TWAP, 3) bloque por bloque
    vs multi-bloque.
  patron_vulnerable: |
    // Protocolo que usa TWAP de Uniswap V3 sin validación cruzada
    function getPrice(address pool) external view returns (uint256) {
        (int24 arithmeticMeanTick, ) = OracleLibrary.consult(pool, TWAP_PERIOD);
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
        // ERROR: No hay validación contra Chainlink o límite de desviación
        return _sqrtPriceToPrice(sqrtPriceX96);
    }

    // ERROR: TWAP_PERIOD muy corto
    uint32 constant TWAP_PERIOD = 300; // Solo 5 minutos — manipulable

    // FALTA: require(abs(twapPrice - chainlinkPrice) < MAX_DEVIATION)
    // FALTA: require(poolLiquidity > MIN_LIQUIDITY)
  test_invariante: |
    // Invariante: TWAP no debe desviarse más del 5% del precio de referencia
    function invariant_twapNotManipulated() public {
        uint256 twapPrice = oracle.getPrice(poolAddress);
        uint256 referencePrice = chainlinkOracle.latestAnswer();

        uint256 deviation = twapPrice > referencePrice
            ? (twapPrice - referencePrice) * 1e18 / referencePrice
            : (referencePrice - twapPrice) * 1e18 / referencePrice;

        t(deviation <= 5e16, "CLIQ-04: TWAP deviated >5% from Chainlink");
    }
  ejemplo_real:
    - audit: "Euler Finance Exploit (2023)"
      detalle: "Aunque Euler no fue explotado via TWAP directamente, su uso de Uniswap V3 TWAP como oracle fue identificado como vector de ataque. La liquidez concentrada reducía el costo de manipulación del TWAP en pools con poca liquidez fuera del rango activo."
    - audit: "Code4rena - Salty.io (2024)"
      detalle: "H-01: CoreSaltyFeed spot price can lead to price manipulation and undesired liquidations. El protocolo usaba precio spot de pool como fallback cuando Chainlink no estaba disponible, permitiendo manipulación via flash swap en pool concentrada."
    - audit: "Sherlock - Isomorph (2023)"
      detalle: "H-01: Velodrome pool routing — atacante manipula precio de pool secundaria (baja liquidez concentrada) para prevenir liquidaciones en el protocolo de lending."
    - audit: "Pashov Audit Group - TitanX (2024)"
      detalle: "M-01: TWAP price manipulation. TWAP de 5 minutos en pool Uniswap V3 con liquidez concentrada era manipulable con ~$50K."
  severidad: high
  confianza: alta
  verificado: true
  tags: [TWAP, oracle, manipulation, concentrated-liquidity, flash-loan]
  relacionado_con: [CLIQ-17, CLIQ-09]
```

### 1.5 Just-In-Time (JIT) Liquidity Attacks

```yaml
- id: CLIQ-05
  pattern: jit-liquidity-attack
  titulo: "Ataques JIT (Just-In-Time) que parasitan fees de LPs pasivos"
  descripcion: >
    JIT liquidity es un tipo de MEV donde un bot observa un swap pendiente
    en la mempool, añade liquidez concentrada en el rango exacto del swap
    en el mismo bloque (justo antes), y la remueve justo después. El bot
    captura la mayoría de las fees del swap sin asumir riesgo de impermanent
    loss (la posición dura un solo bloque). Para LPs pasivos, esto significa
    que sus fees se diluyen significativamente. En protocolos con auto-compound
    vaults o managed positions, los rebalanceos crean oportunidades JIT
    predecibles. Algunos protocolos intentan mitigar JIT con lock periods
    mínimos, pero estos pueden tener bugs propios.
  patron_vulnerable: |
    // Vault de auto-compound sin protección anti-JIT
    contract AutoCompoundVault {
        function rebalance() external {
            // 1. Remove liquidity from old range
            pool.burn(currentTickLower, currentTickUpper, totalLiquidity);
            pool.collect(...);

            // 2. Swap para balancear tokens (PREDECIBLE y de alto volumen)
            uint256 amountToSwap = _calculateSwapAmount();
            pool.swap(..., amountToSwap, ...);  // JIT target

            // 3. Add liquidity to new range
            pool.mint(newTickLower, newTickUpper, newLiquidity, "");
        }
        // No hay: timelock, randomización, private mempool
    }

    // Mitigación buggy: lock period con bypass
    function burn(int24 tickLower, int24 tickUpper, uint128 amount) external {
        Position storage pos = positions[msg.sender][tickLower][tickUpper];
        // ERROR: lastMintBlock se resetea en cada mint, no en el primer mint
        require(block.number - pos.lastMintBlock >= MIN_LOCK_BLOCKS, "Too early");
        // BYPASS: atacante puede mint una cantidad tiny para resetear lastMintBlock
    }
  test_invariante: |
    // Invariante: posición no debe poder ser creada y destruida en el mismo bloque
    function invariant_noSameBlockMintBurn() public {
        for (uint i = 0; i < ghost_positionCount; i++) {
            if (ghost_positionBurnBlock[i] == block.number) {
                t(ghost_positionMintBlock[i] < block.number,
                    "CLIQ-05: position minted and burned in same block (JIT)");
            }
        }
    }
  ejemplo_real:
    - audit: "Flashbots - MEV Explore (2022)"
      detalle: "Datos on-chain muestran que bots JIT capturan 2-8% del total de fees en pools Uniswap V3 de alto volumen (ETH/USDC, ETH/USDT). El JIT bot más activo en 2022 generó >$1M en profit."
    - audit: "Sherlock - Bunni V2 (2024)"
      detalle: "H-03: Auto-compound del vault genera swaps predecibles que son JIT-mineados. Fees del vault se diluyen ~30% vs expectativa."
    - audit: "Code4rena - Arrakis V2 (2023)"
      detalle: "Arrakis vaults de gestión activa eran targets JIT frecuentes. Los rebalanceos del manager eran visibles en mempool y generaban oportunidades JIT consistentes."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [JIT, MEV, liquidity-mining, fee-dilution, auto-compound]
  relacionado_con: [CLIQ-03, CLIQ-18]
```

### 1.6 Fee Growth Overflow en Pools de Alto Volumen

```yaml
- id: CLIQ-06
  pattern: fee-growth-overflow
  titulo: "Overflow de feeGrowthGlobalX128 en pools con volumen extremo o larga duración"
  descripcion: >
    feeGrowthGlobal{0,1}X128 son uint256 que acumulan fees en formato
    Q128.128 (punto fijo con 128 bits de fracción). En Uniswap V3, estos
    contadores están diseñados para hacer overflow de forma segura porque
    las diferencias (no los valores absolutos) son lo que importa para
    calcular fees por posición. Sin embargo, en forks que: 1) usan tipos
    más pequeños (uint128) para ahorrar storage, 2) añaden lógica que
    compara valores absolutos en lugar de diferencias, o 3) tienen
    reward tokens adicionales con acumuladores separados, el overflow
    puede causar pérdida de fees o distribución incorrecta. El problema
    se manifiesta en pools de alto volumen después de meses/años de
    operación.
  patron_vulnerable: |
    // Error: usar uint128 para fee growth (overflow en ~1 año para pools activas)
    struct PoolState {
        uint128 feeGrowthGlobal0X128;  // ERROR: debe ser uint256
        uint128 feeGrowthGlobal1X128;  // ERROR: debe ser uint256
    }

    // Error: comparar valores absolutos en lugar de diferencias
    function positionFees(Position memory pos) internal view returns (uint256) {
        uint256 feeGrowthInside = feeGrowthGlobal - tickLower.feeGrowthOutside - tickUpper.feeGrowthOutside;
        // ERROR: esta comparación falla si feeGrowthGlobal ha hecho overflow
        require(feeGrowthInside >= pos.feeGrowthInsideLast, "Negative fees");
        // CORRECTO: usar unchecked { feeGrowthInside - pos.feeGrowthInsideLast }
        // porque la resta con overflow da el resultado correcto en aritmética modular
    }

    // Error: reward growth con tipo insuficiente
    struct RewardInfo {
        uint128 rewardGrowthGlobalX128;  // Overflow rápido si reward token tiene 18 decimales
        uint64 lastUpdateTime;
    }
  test_invariante: |
    // Invariante: fee growth differences deben ser consistentes pre/post overflow
    function invariant_feeGrowthOverflowSafe() public {
        // Simular overflow sumando un valor grande
        uint256 feeGrowthBefore = pool.feeGrowthGlobal0X128();

        // Ejecutar swap que genera fees
        _doSwap(token0, token1, 1e18);

        uint256 feeGrowthAfter = pool.feeGrowthGlobal0X128();

        // La diferencia debe ser positiva (en aritmética modular)
        uint256 feeDelta;
        unchecked { feeDelta = feeGrowthAfter - feeGrowthBefore; }
        t(feeDelta > 0, "CLIQ-06: fee growth did not increase after swap");
        t(feeDelta < type(uint128).max, "CLIQ-06: fee growth delta unreasonably large");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-015: Trail of Bits verificó que el diseño de overflow de feeGrowthGlobalX128 es correcto cuando se usan diferencias. Advirtieron explícitamente que forks que usen comparaciones absolutas o tipos más pequeños romperán este invariante."
    - audit: "Code4rena - Panoptic (2024)"
      detalle: "M-04: Fee growth tracking en Panoptic podía acumular error cuando posiciones se movían entre chunks con diferentes fee growth histories, amplificando errores de redondeo post-overflow."
    - audit: "Sherlock - Algebra (2023)"
      detalle: "Algebra Protocol usa adaptive fees que cambian fee rate dinámicamente. El cambio de fee rate mid-swap podía causar inconsistencias en feeGrowthGlobal cuando combinado con tick crossing."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [fee-growth, overflow, uint256, Q128, modular-arithmetic]
  relacionado_con: [CLIQ-02, CLIQ-11]
```

### 1.7 Manipulación del Tick Bitmap / Ticks No Inicializados

```yaml
- id: CLIQ-07
  pattern: tick-bitmap-manipulation
  titulo: "Inconsistencia entre tick bitmap y estado real de ticks inicializados"
  descripcion: >
    El tick bitmap es una estructura de datos compacta que indica qué ticks
    tienen liquidez inicializada. Cada bit en un word de 256 bits representa
    un tick. Cuando se añade liquidez que incluye un tick como límite, el
    bit correspondiente se activa. Cuando se remueve toda la liquidez de
    ese tick, el bit se desactiva. Si el bitmap y el estado real del tick
    se desincronizan (bit activo pero tick sin liquidez, o bit inactivo
    pero tick con liquidez), los swaps pueden: 1) saltar ticks que deberían
    cruzarse (pérdida de fees para LPs), 2) intentar cruzar ticks vacíos
    (revert o comportamiento indefinido), 3) entrar en loops infinitos
    buscando el siguiente tick inicializado. Forks que modifican la lógica
    de mint/burn sin actualizar correctamente el bitmap son vulnerables.
  patron_vulnerable: |
    // Error: no flipear el tick en el bitmap cuando liquidez llega a cero
    function burn(int24 tickLower, int24 tickUpper, uint128 amount) external {
        Position storage pos = positions[msg.sender][tickLower][tickUpper];
        pos.liquidity -= amount;

        Tick.Info storage lower = ticks[tickLower];
        lower.liquidityGross -= amount;
        lower.liquidityNet -= int128(amount);

        // ERROR: falta verificar si liquidityGross == 0 y flipear bitmap
        // if (lower.liquidityGross == 0) tickBitmap.flipTick(tickLower, tickSpacing);

        Tick.Info storage upper = ticks[tickUpper];
        upper.liquidityGross -= amount;
        upper.liquidityNet += int128(amount);
        // MISMO ERROR para tickUpper
    }

    // Error: doble flip por reentrancy
    function mint(...) external {
        // callback que llama mint de nuevo
        IMintCallback(msg.sender).mintCallback(amount0, amount1, data);
        // Si el callback llama mint con los mismos ticks,
        // el bitmap se flipea 2 veces = queda en estado original = bug
    }
  test_invariante: |
    // Invariante: tick bitmap debe ser consistente con liquidityGross
    function invariant_bitmapConsistency() public {
        for (int24 tick = MIN_TICK; tick <= MAX_TICK; tick += tickSpacing) {
            bool bitmapSet = tickBitmap.isInitialized(tick);
            uint128 liquidityGross = ticks[tick].liquidityGross;

            if (bitmapSet) {
                t(liquidityGross > 0, "CLIQ-07: bitmap set but tick has no liquidity");
            } else {
                t(liquidityGross == 0, "CLIQ-07: bitmap unset but tick has liquidity");
            }
        }
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-012: Verificación formal de la consistencia del tick bitmap. Trail of Bits confirmó que Uniswap V3 mantiene la consistencia correctamente, pero identificó la complejidad como riesgo para forks."
    - audit: "Code4rena - Trader Joe V2 (2022)"
      detalle: "TraderJoe V2 (Liquidity Book) usa un sistema de bins similar a ticks. H-02: Inconsistencia en el tree bitmap al remover liquidez de bins, causando que swaps salten bins con liquidez activa."
    - audit: "Sherlock - Velodrome V2 (2023)"
      detalle: "M-03: Tick bitmap no se actualizaba correctamente cuando se removía liquidez de ticks con gauge staking activo, dejando ticks fantasma que causaban gas waste en swaps."
  severidad: high
  confianza: alta
  verificado: true
  tags: [tick-bitmap, initialization, liquidityGross, flip, consistency]
  relacionado_con: [CLIQ-15, CLIQ-02]
```

### 1.8 Bypass de Permisos en Position NFT

```yaml
- id: CLIQ-08
  pattern: position-nft-permission-bypass
  titulo: "Bypass de permisos en NFT de posición permitiendo operaciones no autorizadas"
  descripcion: >
    En Uniswap V3, las posiciones se representan como NFTs (ERC-721) via
    NonfungiblePositionManager. Las operaciones sobre la posición (aumentar
    liquidez, decrementar, collect fees) requieren ser owner o approved del
    NFT. Si la verificación de permisos es incorrecta o incompleta, un
    atacante puede: 1) drenar fees de posiciones ajenas via collect(),
    2) remover liquidez de posiciones ajenas, 3) manipular posiciones
    usadas como colateral en protocolos de lending. Forks que añaden
    funcionalidad extra (staking, auto-compound, leverage) sobre el
    NonfungiblePositionManager frecuentemente introducen bypass de
    permisos al no verificar ownership en todas las rutas de código.
  patron_vulnerable: |
    // Error: verificar owner pero no approved/operator
    function decreaseLiquidity(DecreaseLiquidityParams calldata params) external {
        Position storage pos = positions[params.tokenId];
        // ERROR: solo verifica owner directo, no approved ni operator
        require(ownerOf(params.tokenId) == msg.sender, "Not owner");
        // Debería ser: require(_isApprovedOrOwner(msg.sender, params.tokenId))
    }

    // Error: no verificar permisos en función de collect
    function collect(CollectParams calldata params) external returns (uint256, uint256) {
        // ERROR: cualquiera puede llamar collect y enviar fees a params.recipient
        // FALTA: require(_isApprovedOrOwner(msg.sender, params.tokenId))
        Position storage pos = positions[params.tokenId];
        // ... collect fees y enviar a params.recipient (controlado por caller)
    }

    // Error en protocolo que wrappea el NFT
    contract LendingVault {
        function liquidate(uint256 tokenId) external {
            // ERROR: no verifica que el NFT está depositado en ESTE vault
            nonfungiblePositionManager.decreaseLiquidity(...);
            nonfungiblePositionManager.collect(...);
            // Atacante puede liquidar posiciones no colateralizadas
        }
    }
  test_invariante: |
    // Invariante: solo owner/approved puede modificar posición
    function invariant_positionPermissions() public {
        uint256 tokenId = ghost_lastTokenId;
        address owner = positionManager.ownerOf(tokenId);

        // Intentar collect como non-owner debe fallar
        if (msg.sender != owner && !positionManager.isApprovedForAll(owner, msg.sender)) {
            try positionManager.collect(CollectParams({
                tokenId: tokenId,
                recipient: msg.sender,
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            })) {
                t(false, "CLIQ-08: non-owner collected fees from position");
            } catch {}
        }
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Periphery (2021)"
      detalle: "TOB-UNI-019: Verificación de que NonfungiblePositionManager verifica _isApprovedOrOwner en todas las funciones que modifican posiciones. El audit encontró la implementación correcta pero señaló el riesgo para contratos que interactúan con el manager."
    - audit: "Code4rena - Revert Lend (2024)"
      detalle: "VV-O-02: Posiciones stakeadas en GaugeManager podían ser liquidadas con fees robadas. El vault verificaba ownership pero no coordinaba correctamente con el gauge staking, permitiendo que fees se acumularan en el gauge sin poder ser reclamadas por el liquidador."
    - audit: "Sherlock - Caviar (2023)"
      detalle: "H-02: Función wrap() permitía que cualquiera wrapeara NFTs de terceros en el vault sin verificar approval, efectivamente robando la posición."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [NFT, permissions, ERC-721, access-control, position-manager]
  relacionado_con: [CLIQ-12, CLIQ-09]
```

### 1.9 Flash Loan + Manipulación de Posición Concentrada

```yaml
- id: CLIQ-09
  pattern: flash-loan-concentrated-position
  titulo: "Manipulación de posiciones concentradas vía flash loan para explotar protocolos downstream"
  descripcion: >
    Un atacante puede usar flash loans para: 1) crear posiciones de liquidez
    concentrada masivas temporalmente, manipulando el precio o la liquidez
    visible de la pool, 2) manipular el valor percibido de posiciones NFT
    usadas como colateral en protocolos de lending, 3) inflar rewards de
    gauge staking añadiendo liquidez solo durante el snapshot de rewards.
    La clave es que en un solo bloque, el atacante puede crear una posición
    con liquidez enorme, triggerear una acción en un protocolo downstream
    que lee el estado de la pool, y destruir la posición. Protocolos que
    valúan posiciones Uniswap V3 NFT como colateral son especialmente
    vulnerables.
  patron_vulnerable: |
    // Protocolo de lending que acepta Uniswap V3 NFTs como colateral
    function getPositionValue(uint256 tokenId) public view returns (uint256) {
        (,, address token0, address token1, uint24 fee, int24 tickLower, int24 tickUpper,
         uint128 liquidity,,,,) = nonfungiblePositionManager.positions(tokenId);

        // ERROR: valúa la posición usando spot price de la pool
        (uint160 sqrtPriceX96,,,,,,) = IUniswapV3Pool(pool).slot0();

        // Atacante puede manipular sqrtPriceX96 con flash loan
        uint256 amount0 = LiquidityAmounts.getAmount0ForLiquidity(
            sqrtPriceX96, TickMath.getSqrtRatioAtTick(tickUpper), liquidity
        );
        uint256 amount1 = LiquidityAmounts.getAmount1ForLiquidity(
            TickMath.getSqrtRatioAtTick(tickLower), sqrtPriceX96, liquidity
        );

        return amount0 * price0 + amount1 * price1; // Inflado por manipulación
    }
  test_invariante: |
    // Invariante: valor de colateral no debe cambiar >5% en un solo bloque
    function invariant_collateralStability() public {
        uint256 valueBefore = lending.getPositionValue(tokenId);

        // Simular flash loan + swap grande
        _flashSwap(pool, largeAmount);

        uint256 valueAfter = lending.getPositionValue(tokenId);

        uint256 change = valueBefore > valueAfter
            ? (valueBefore - valueAfter) * 1e18 / valueBefore
            : (valueAfter - valueBefore) * 1e18 / valueBefore;

        t(change <= 5e16, "CLIQ-09: collateral value changed >5% in single block");
    }
  ejemplo_real:
    - audit: "Code4rena - Revert Lend (2024)"
      detalle: "El protocolo Revert Lend acepta posiciones Uniswap V3 como colateral. La valoración de posiciones consideraba el sqrtPrice actual de la pool, que podía ser manipulado momentáneamente con un flash swap. V3Oracle usaba TWAP como mitigación, pero con window corto."
    - audit: "Sherlock - Sentiment V2 (2023)"
      detalle: "H-01: Uniswap V3 position valuation susceptible to manipulation. El protocolo de lending valoraba NFTs de posición usando spot price de la pool sin validación TWAP."
    - audit: "Code4rena - Olympus (2023)"
      detalle: "H-02: Attacker can manipulate Uniswap V3 pool liquidity to inflate LP token price used as collateral in treasury calculations. Flash loan + add concentrated liquidity → inflate perceived value → borrow against it."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [flash-loan, collateral, position-value, lending, manipulation]
  relacionado_con: [CLIQ-04, CLIQ-08]
```

### 1.10 Errores de Redondeo en Liquidity Math (mulDiv / FullMath)

```yaml
- id: CLIQ-10
  pattern: rounding-errors-liquidity-math
  titulo: "Errores de redondeo en cálculos de liquidez con mulDiv y FullMath que favorecen al usuario"
  descripcion: >
    Los cálculos de liquidez concentrada requieren multiplicación y división
    de números de 256 bits con resultados intermedios de 512 bits. Uniswap V3
    usa FullMath.mulDiv para manejar esto sin overflow. El redondeo debe
    SIEMPRE favorecer al protocolo (pool): al calcular tokens que el usuario
    debe depositar, redondear ARRIBA; al calcular tokens que el usuario
    recibe, redondear ABAJO. Si la dirección de redondeo es incorrecta en
    cualquier operación (mint, burn, swap, collect), se puede extraer valor
    de la pool repitiendo la operación. Forks que reimplementan mulDiv,
    cambian a una librería diferente, o añaden operaciones math personalizadas
    son especialmente vulnerables.
  patron_vulnerable: |
    // Error: redondear a favor del usuario al calcular tokens para mint
    function getAmount0ForLiquidity(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) internal pure returns (uint256 amount0) {
        // ERROR: usa mulDiv que redondea ABAJO — usuario deposita MENOS
        amount0 = FullMath.mulDiv(
            uint256(liquidity) << 96,
            sqrtRatioBX96 - sqrtRatioAX96,
            sqrtRatioBX96
        ) / sqrtRatioAX96;
        // CORRECTO para mint: mulDivRoundingUp — usuario deposita MÁS o igual
    }

    // Error: redondear a favor del usuario al calcular output de swap
    function computeSwapStep(...) internal pure returns (...) {
        // Al calcular amountOut:
        // ERROR: mulDivRoundingUp — usuario recibe MÁS
        amountOut = FullMath.mulDivRoundingUp(amountIn, sqrtRatioTarget, sqrtRatioCurrent);
        // CORRECTO: mulDiv (round down) — usuario recibe MENOS o igual
    }
  test_invariante: |
    // Invariante: mint-then-burn debe devolver <= tokens depositados
    function invariant_mintBurnNoProfit() public {
        uint256 balance0Before = token0.balanceOf(address(this));
        uint256 balance1Before = token1.balanceOf(address(this));

        // Mint posición
        pool.mint(address(this), tickLower, tickUpper, liquidityAmount, "");

        // Burn inmediatamente
        pool.burn(tickLower, tickUpper, liquidityAmount);
        pool.collect(address(this), tickLower, tickUpper, MAX, MAX);

        uint256 balance0After = token0.balanceOf(address(this));
        uint256 balance1After = token1.balanceOf(address(this));

        // No debe haber ganado tokens
        t(balance0After <= balance0Before, "CLIQ-10: profit on token0 from mint+burn");
        t(balance1After <= balance1Before, "CLIQ-10: profit on token1 from mint+burn");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-006: Trail of Bits verificó extensamente la dirección de redondeo en FullMath y SqrtPriceMath. Confirmaron que Uniswap V3 redondea consistentemente contra el usuario, pero la complejidad del sistema hace que errores en forks sean probables."
    - audit: "Sherlock - Bunni V2 (2024)"
      detalle: "H-01: BunniSwapMath.computeSwap returns nonzero output with zero input. Error de redondeo en la implementación personalizada de swap math permitía extraer tokens sin input."
    - audit: "Code4rena - Napier Finance (2024)"
      detalle: "H-03: Rounding errors in liquidity math allow dust extraction. Posiciones con liquidez mínima podían explotar errores de redondeo para extraer 1 wei por operación, acumulable via repetición."
  severidad: high
  confianza: alta
  verificado: true
  tags: [rounding, mulDiv, FullMath, liquidity-math, precision]
  relacionado_con: [CLIQ-01, CLIQ-13]
```

### 1.11 Error de Acumulación de Fees Cross-Tick

```yaml
- id: CLIQ-11
  pattern: cross-tick-fee-accumulation
  titulo: "Error en la acumulación de fees cuando un swap cruza múltiples ticks inicializados"
  descripcion: >
    Cuando un swap es suficientemente grande para cruzar múltiples ticks
    inicializados, cada tick debe procesarse secuencialmente: calcular el
    swap parcial hasta el tick, actualizar feeGrowthOutside, ajustar la
    liquidez activa (sumando/restando liquidityNet), y continuar con el
    swap residual. Si el orden de operaciones es incorrecto, las fees
    se asignan mal. Específicamente: 1) si las fees del segmento entre
    ticks se acumulan DESPUÉS de actualizar la liquidez (en vez de antes),
    las fees se distribuyen con la liquidez nueva en vez de la vieja,
    2) si liquidityNet se aplica con signo incorrecto según la dirección
    del swap, la liquidez activa se corrompe. El bug se manifiesta solo
    en swaps grandes que cruzan 2+ ticks — testing con swaps pequeños
    no lo detecta.
  patron_vulnerable: |
    function swap(...) external returns (int256 amount0, int256 amount1) {
        while (amountRemaining != 0 && sqrtPriceX96 != sqrtPriceLimitX96) {
            // Compute swap step hasta el siguiente tick
            (sqrtPriceX96, amountIn, amountOut, feeAmount) = SwapMath.computeSwapStep(...);

            if (sqrtPriceX96 == sqrtPriceTarget) {
                // Cruzamos un tick inicializado

                // ERROR: actualizar liquidez ANTES de acumular fees
                // Las fees del segmento anterior se distribuyen con la liquidez nueva
                state.liquidity = LiquidityMath.addDelta(state.liquidity, tick.liquidityNet);

                // Las fees deberían acumularse con la liquidez ANTERIOR al cross
                state.feeGrowthGlobalX128 += FullMath.mulDiv(feeAmount, Q128, state.liquidity);
                // ↑ usa state.liquidity ya actualizado — INCORRECTO

                tick.cross(state.feeGrowthGlobalX128, ...);
            }
        }
    }
  test_invariante: |
    // Invariante: fees por unidad de liquidez deben ser correctas tras multi-tick swap
    function invariant_crossTickFeeAccuracy() public {
        // Crear 3 posiciones en rangos adyacentes con liquidez conocida
        // Ejecutar swap grande que cruza ambos rangos
        // Verificar que cada posición recibió fees proporcionales a su liquidez * tiempo en rango

        uint256 fees0_pos1 = _getPositionFees0(pos1Key);
        uint256 fees0_pos2 = _getPositionFees0(pos2Key);

        // Si ambas posiciones tienen la misma liquidez y el swap cruza ambos rangos por igual,
        // deberían recibir fees similares (con tolerancia de redondeo)
        uint256 diff = fees0_pos1 > fees0_pos2
            ? fees0_pos1 - fees0_pos2
            : fees0_pos2 - fees0_pos1;

        t(diff <= 10, "CLIQ-11: fee distribution asymmetry across ticks > 10 wei");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-008: Verificación del orden correcto de operaciones en tick crossing. Trail of Bits confirmó que Uniswap V3 acumula fees ANTES de actualizar liquidez, pero señaló que el orden es contra-intuitivo y forks pueden invertirlo."
    - audit: "Code4rena - CLMM Audits (2023-2024)"
      detalle: "Patrón recurrente en forks de CLMM: el orden de feeGrowth update vs liquidity update en tick crossing es la fuente #1 de bugs de fee accounting en implementaciones derivadas."
    - audit: "Sherlock - Algebra (2023)"
      detalle: "M-02: Adaptive fee changes mid-swap combinado con tick crossing causaba que fees se calcularan con el fee rate nuevo para volumen que debería tener el fee rate viejo."
  severidad: high
  confianza: alta
  verificado: true
  tags: [cross-tick, fee-accumulation, swap, liquidityNet, ordering]
  relacionado_con: [CLIQ-02, CLIQ-06]
```

### 1.12 Reentrancy en Collect Fees

```yaml
- id: CLIQ-12
  pattern: collect-fees-reentrancy
  titulo: "Reentrancy durante collect de fees permite doble cobro o manipulación de estado"
  descripcion: >
    La función collect() en pools de liquidez concentrada transfiere tokens
    al recipient. Si uno de los tokens es un ERC-777 (con hooks de
    transferencia), un ERC-721 (con onERC721Received), o cualquier token
    con callback en transfer, el recipient puede re-entrar al contrato
    durante la transferencia. En Uniswap V3, las posiciones se identifican
    por (owner, tickLower, tickUpper) y los tokens owed se trackean
    internamente. Si collect() transfiere token0 primero y el recipient
    re-entra para reclamar token1 o para manipular su posición, puede
    haber inconsistencias. Protocolos que wrappean el collect (como
    NonfungiblePositionManager, vaults, o gauges) añaden capas de
    abstracción donde la reentrancy es más difícil de detectar.
  patron_vulnerable: |
    // Error: transferir tokens antes de actualizar estado interno
    function collect(
        address recipient,
        int24 tickLower,
        int24 tickUpper,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1) {
        Position.Info storage position = positions.get(msg.sender, tickLower, tickUpper);

        amount0 = amount0Requested > position.tokensOwed0 ? position.tokensOwed0 : amount0Requested;
        amount1 = amount1Requested > position.tokensOwed1 ? position.tokensOwed1 : amount1Requested;

        // ERROR: transferir ANTES de actualizar tokensOwed
        if (amount0 > 0) token0.transfer(recipient, amount0);  // REENTRANCY POINT
        if (amount1 > 0) token1.transfer(recipient, amount1);

        // Estado se actualiza DESPUÉS — vulnerable a reentrancy
        position.tokensOwed0 -= amount0;
        position.tokensOwed1 -= amount1;
    }

    // Correcto (Uniswap V3): actualizar ANTES de transferir
    // position.tokensOwed0 -= amount0;
    // position.tokensOwed1 -= amount1;
    // if (amount0 > 0) TransferHelper.safeTransfer(token0, recipient, amount0);
    // if (amount1 > 0) TransferHelper.safeTransfer(token1, recipient, amount1);
  test_invariante: |
    // Invariante: tokensOwed no puede ser negativo ni incrementar sin nueva actividad
    function invariant_noDoubleCollect() public {
        uint128 owed0Before = _getTokensOwed0(positionKey);
        uint128 owed1Before = _getTokensOwed1(positionKey);

        // Collect todo
        pool.collect(address(this), tickLower, tickUpper, type(uint128).max, type(uint128).max);

        uint128 owed0After = _getTokensOwed0(positionKey);
        uint128 owed1After = _getTokensOwed1(positionKey);

        // Después de collect, tokensOwed debe ser 0
        t(owed0After == 0, "CLIQ-12: tokensOwed0 not zeroed after full collect");
        t(owed1After == 0, "CLIQ-12: tokensOwed1 not zeroed after full collect");

        // Segundo collect no debe dar nada
        uint256 bal0Before = token0.balanceOf(address(this));
        pool.collect(address(this), tickLower, tickUpper, type(uint128).max, type(uint128).max);
        t(token0.balanceOf(address(this)) == bal0Before, "CLIQ-12: double collect succeeded");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-020: Trail of Bits verificó que collect() en UniswapV3Pool actualiza tokensOwed ANTES de transferir tokens (CEI pattern correcto). Sin embargo, el NonfungiblePositionManager wrappea esto y añade una capa adicional que debe mantener el mismo patrón."
    - audit: "Code4rena - Panoptic (2024)"
      detalle: "M-07: Reentrancy risk en collect de fees cuando token es ERC-777. Panoptic no tenía reentrancy guard en su capa de abstracción sobre Uniswap V3 collect."
    - audit: "Sherlock - SushiSwap V3 (2023)"
      detalle: "M-01: ConcentratedLiquidityPool.collect() vulnerable a reentrancy en forks con tokens ERC-777. Mitigado en SushiSwap con nonReentrant modifier después del finding."
  severidad: high
  confianza: alta
  verificado: true
  tags: [reentrancy, collect, fees, ERC-777, CEI-pattern]
  relacionado_con: [CLIQ-08, CLIQ-02]
```

### 1.13 Pérdida de Precisión de sqrtPriceX96 en Precios Extremos

```yaml
- id: CLIQ-13
  pattern: sqrtprice-precision-loss
  titulo: "Pérdida de precisión de sqrtPriceX96 en ratios de precio extremos (>1e12 o <1e-12)"
  descripcion: >
    sqrtPriceX96 es un uint160 que representa la raíz cuadrada del precio
    en formato Q64.96 (64 bits enteros, 96 bits fraccionarios). Para pares
    con ratios de precio extremos (e.g., SHIB/ETH donde 1 ETH = 1e12 SHIB),
    el sqrtPriceX96 puede estar cerca de los límites del rango representable.
    En estos extremos, las operaciones matemáticas (especialmente
    getAmount0ForLiquidity y getAmount1ForLiquidity) pierden precisión
    significativa porque los bits de la parte fraccionaria no son suficientes
    para representar diferencias pequeñas. El resultado es que: 1) mints
    requieren 0 de un token (free liquidity), 2) swaps calculan 0 de output,
    3) fees se redondean a 0. Pools con tokens de diferente número de
    decimales (e.g., USDC con 6 vs WBTC con 8) amplifican el problema.
  patron_vulnerable: |
    // Pool con precio extremo: token0 = SHIB (18 dec), token1 = WETH (18 dec)
    // Precio: 1 SHIB = 0.000000008 ETH → sqrtPrice muy pequeño

    function getAmount0ForLiquidity(
        uint160 sqrtRatioAX96,
        uint160 sqrtRatioBX96,
        uint128 liquidity
    ) internal pure returns (uint256) {
        // Cuando sqrtRatioA y sqrtRatioB están muy cerca (precio extremo),
        // sqrtRatioBX96 - sqrtRatioAX96 puede ser 0 o 1
        // → amount0 = 0 (free liquidity para token0)
        return FullMath.mulDiv(
            uint256(liquidity) << FixedPoint96.RESOLUTION,
            sqrtRatioBX96 - sqrtRatioAX96,  // PUEDE SER 0
            sqrtRatioBX96
        ) / sqrtRatioAX96;
    }

    // Pool con tokens de diferentes decimales sin ajuste
    // USDC (6 dec) / WETH (18 dec) → factor 1e12 de diferencia en unidades
    // sqrtPrice = sqrt(price) * 2^96
    // Si price = 1e-12, sqrtPrice = 1e-6 * 2^96 ≈ 7.9e22 — dentro de rango
    // Pero si price = 1e-18, sqrtPrice = 1e-9 * 2^96 ≈ 7.9e19 — pierde precisión
  test_invariante: |
    // Invariante: mint con liquidez > 0 debe requerir amount > 0 de al menos un token
    function invariant_noFreeLiquidity() public {
        int24 tickLower = currentTick - tickSpacing;
        int24 tickUpper = currentTick + tickSpacing;
        uint128 liquidity = 1e18; // Liquidez significativa

        (uint256 amount0, uint256 amount1) = LiquidityAmounts.getAmountsForLiquidity(
            sqrtPriceX96,
            TickMath.getSqrtRatioAtTick(tickLower),
            TickMath.getSqrtRatioAtTick(tickUpper),
            liquidity
        );

        // Al menos un token debe ser requerido
        t(amount0 > 0 || amount1 > 0, "CLIQ-13: free liquidity - no tokens required for mint");

        // Si estamos en rango, ambos deben ser > 0
        if (currentTick >= tickLower && currentTick < tickUpper) {
            t(amount0 > 0 && amount1 > 0, "CLIQ-13: in-range position requires 0 of one token");
        }
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-003: Análisis de precisión en rangos extremos. Trail of Bits documentó que en los extremos del rango de ticks, los cálculos de amount pueden producir 0 para valores de liquidez pequeños. Uniswap V3 acepta esto como limitación de diseño pero no lo documenta explícitamente."
    - audit: "Code4rena - Maia DAO (2023)"
      detalle: "H-04: Precision loss in sqrtPriceX96 calculations for extreme price ratios in Talos (Uniswap V3 vault manager). Posiciones en pools con precio extremo podían tener valor 0 calculado pero liquidez real > 0."
    - audit: "Sherlock - PancakeSwap V3 (2023)"
      detalle: "M-05: Pools con tokens de 4 decimales (e.g., GUSD) vs 18 decimales tenían errores de precisión significativos en fee calculations debido al spread de sqrtPriceX96."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [precision, sqrtPriceX96, extreme-price, Q64.96, decimals]
  relacionado_con: [CLIQ-01, CLIQ-10]
```

### 1.14 Inicialización de Pool con sqrtPrice Manipulado

```yaml
- id: CLIQ-14
  pattern: pool-initialization-manipulated-price
  titulo: "Inicialización de pool con sqrtPrice arbitrario permite front-running y extracción de valor"
  descripcion: >
    En Uniswap V3, la función initialize() establece el sqrtPriceX96
    inicial de una pool. Esta función solo puede llamarse una vez y no
    requiere depositar liquidez. Un atacante puede: 1) front-runnear
    la creación de un par nuevo, inicializando la pool con un precio
    extremo, 2) añadir liquidez concentrada en el rango que controla,
    3) cuando el creador legítimo añade liquidez al precio "real", el
    atacante extrae la diferencia. Protocolos que crean pools
    programáticamente (e.g., token launches, LBP migrations) son
    especialmente vulnerables si no verifican que la pool no haya sido
    inicializada previamente con un precio malicioso.
  patron_vulnerable: |
    // Error: crear pool y confiar en que nadie la inicializó antes
    function launchToken(address token, uint256 initialPrice) external {
        address pool = factory.getPool(token, WETH, fee);
        if (pool == address(0)) {
            pool = factory.createPool(token, WETH, fee);
        }

        // ERROR: no verificar si ya está inicializada con precio malicioso
        uint160 sqrtPriceX96 = _priceToSqrtPriceX96(initialPrice);
        try IUniswapV3Pool(pool).initialize(sqrtPriceX96) {} catch {
            // Pool ya inicializada — pero ¿con qué precio?
            // ERROR: continúa sin verificar el precio actual
        }

        // Añade liquidez al precio "esperado" — pero si el precio real
        // es diferente, los tokens se depositan en ratio incorrecto
        nonfungiblePositionManager.mint(MintParams({
            token0: token < WETH ? token : WETH,
            token1: token < WETH ? WETH : token,
            fee: fee,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: amount0,
            amount1Desired: amount1,
            amount0Min: 0,  // ERROR: sin slippage protection
            amount1Min: 0,
            recipient: msg.sender,
            deadline: block.timestamp
        }));
    }
  test_invariante: |
    // Invariante: precio de inicialización debe estar dentro de rango razonable
    function invariant_initializationPrice() public {
        (uint160 sqrtPriceX96,,,,,, bool initialized) = pool.slot0();

        if (initialized) {
            // Precio no debe ser extremo (cerca de MIN o MAX sqrt ratio)
            t(sqrtPriceX96 > TickMath.MIN_SQRT_RATIO * 100,
                "CLIQ-14: pool initialized with near-minimum price");
            t(sqrtPriceX96 < TickMath.MAX_SQRT_RATIO / 100,
                "CLIQ-14: pool initialized with near-maximum price");
        }
    }
  ejemplo_real:
    - audit: "Code4rena - Multiple protocols (2023-2024)"
      detalle: "Patrón recurrente en C4/Sherlock: protocolos que lanzan tokens y crean pools Uniswap V3 programáticamente sin verificar el precio de inicialización. Al menos 5 findings HIGH en 2023-2024 con este patrón."
    - audit: "Sherlock - Teller (2023)"
      detalle: "H-01: Attacker front-runs pool creation and initializes with extreme price. Protocolo de lending creaba pools para nuevos colaterales sin proteger la inicialización."
    - audit: "Code4rena - Caviar (2023)"
      detalle: "H-03: Pool initialization front-running. Caviar Private Pools creaban pools Uniswap V3 en la misma transacción que el deploy pero sin verificar el sqrtPrice post-initialize."
  severidad: high
  confianza: alta
  verificado: true
  tags: [initialization, sqrtPrice, front-running, pool-creation, token-launch]
  relacionado_con: [CLIQ-04, CLIQ-09]
```

### 1.15 Overflow de LiquidityNet en Tick Boundaries

```yaml
- id: CLIQ-15
  pattern: liquiditynet-overflow
  titulo: "Overflow de liquidityNet (int128) en ticks con muchas posiciones superpuestas"
  descripcion: >
    Cada tick inicializado tiene un campo liquidityNet (int128) que indica
    cuánta liquidez se activa (+) o desactiva (-) cuando el precio cruza
    ese tick. liquidityNet es la suma de todas las posiciones que usan ese
    tick como tickLower (positivo) menos las que lo usan como tickUpper
    (negativo). Si muchas posiciones grandes usan el mismo tick como
    límite, liquidityNet puede acercarse a los límites de int128
    (±170,141,183,460,469,231,731,687,303,715,884,105,727). Uniswap V3
    tiene un check maxLiquidityPerTick que limita la liquidez total por
    tick, pero forks que modifican tick spacing o eliminan este check
    pueden permitir overflow de liquidityNet. Un overflow causa que la
    liquidez activa se corrompa después de un tick crossing.
  patron_vulnerable: |
    // Error: no verificar maxLiquidityPerTick
    function update(
        mapping(int24 => Tick.Info) storage self,
        int24 tick,
        int24 tickCurrent,
        int128 liquidityDelta,
        uint256 feeGrowthGlobal0X128,
        uint256 feeGrowthGlobal1X128,
        bool upper
        // FALTA: uint128 maxLiquidity parameter
    ) internal returns (bool flipped) {
        Tick.Info storage info = self[tick];
        uint128 liquidityGrossBefore = info.liquidityGross;
        uint128 liquidityGrossAfter = liquidityGrossBefore + uint128(liquidityDelta);

        // ERROR: falta el check de maxLiquidityPerTick
        // require(liquidityGrossAfter <= maxLiquidity, 'LO');

        info.liquidityGross = liquidityGrossAfter;

        // liquidityNet puede overflow si no hay límite en liquidityGross
        info.liquidityNet = upper
            ? info.liquidityNet - liquidityDelta  // PUEDE OVERFLOW
            : info.liquidityNet + liquidityDelta;  // PUEDE OVERFLOW
    }
  test_invariante: |
    // Invariante: liquidityNet absoluto nunca excede maxLiquidityPerTick
    function invariant_liquidityNetBounded() public {
        int24 tick = ghost_lastCrossedTick;
        int128 liquidityNet = pool.ticks(tick).liquidityNet;
        uint128 maxLiquidity = pool.maxLiquidityPerTick();

        // |liquidityNet| <= maxLiquidityPerTick
        int128 maxLiqInt = int128(maxLiquidity);
        t(liquidityNet >= -maxLiqInt && liquidityNet <= maxLiqInt,
            "CLIQ-15: liquidityNet exceeds maxLiquidityPerTick");

        // Invariante adicional: sum de todos los liquidityNet debe ser 0
        // (cada posición contribuye +delta a tickLower y -delta a tickUpper)
        int256 sumLiquidityNet = 0;
        for (int24 t = MIN_TICK; t <= MAX_TICK; t += tickSpacing) {
            sumLiquidityNet += pool.ticks(t).liquidityNet;
        }
        t(sumLiquidityNet == 0, "CLIQ-15: sum of liquidityNet is not zero");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-014: Verificación de que maxLiquidityPerTick previene overflow de liquidityNet. Trail of Bits demostró que sin este check, pools con tick spacing pequeño (1) son vulnerables a overflow con ~2^127 de liquidez total."
    - audit: "Code4rena - Trader Joe V2 (2022)"
      detalle: "M-03: Liquidity Book no tenía equivalente a maxLiquidityPerTick, permitiendo teóricamente overflow de liquidez por bin en pools de alto uso."
    - audit: "Sherlock - Algebra (2023)"
      detalle: "M-04: Algebra usa tick spacing dinámico. Cambiar tick spacing a un valor más pequeño después de que la pool tiene liquidez podía violar el invariante maxLiquidityPerTick calculado para el spacing original."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [liquidityNet, overflow, int128, maxLiquidityPerTick, tick-boundary]
  relacionado_con: [CLIQ-07, CLIQ-01]
```

### 1.16 Ataques de Timing en Extracción de Protocol Fees

```yaml
- id: CLIQ-16
  pattern: protocol-fee-timing-attack
  titulo: "Ataques de timing en la extracción de protocol fees aprovechando cambios de fee rate"
  descripcion: >
    Las pools de liquidez concentrada pueden tener un protocol fee que se
    cobra como porcentaje del fee de swap. Este protocol fee puede ser
    cambiado por governance o un admin. Un atacante que observa un cambio
    pendiente del protocol fee (en la mempool o via timelock) puede:
    1) si el fee va a SUBIR: front-runnear con swaps grandes antes del
    cambio para pagar menos fees, 2) si el fee va a BAJAR: esperarse y
    hacer swaps después, 3) si hay un bug en cómo se acumulan los protocol
    fees durante el cambio, puede haber una ventana donde fees no se cobran
    o se cobran doble. Algunos protocolos también permiten "collect protocol
    fees" por cualquiera, lo que puede crear race conditions.
  patron_vulnerable: |
    // Error: cambio de fee rate no es atómico con la acumulación
    function setFeeProtocol(uint8 feeProtocol0, uint8 feeProtocol1) external onlyOwner {
        // ERROR: protocol fees acumulados hasta ahora se calcularon con el rate viejo
        // pero collectProtocol() después los enviará todos como si fueran del rate nuevo
        slot0.feeProtocol = (feeProtocol1 << 4) | feeProtocol0;
        // FALTA: collectProtocol() forzado antes del cambio de rate
    }

    // Error: collectProtocol sin restricción de caller ni timing
    function collectProtocol(
        address recipient,
        uint128 amount0Requested,
        uint128 amount1Requested
    ) external returns (uint128 amount0, uint128 amount1) {
        // ERROR: cualquiera puede llamar, el recipient es parámetro
        // Si no es onlyOwner, un bot puede front-runnear al owner y enviar fees a sí mismo
        amount0 = amount0Requested > protocolFees.token0 ? protocolFees.token0 : amount0Requested;
        amount1 = amount1Requested > protocolFees.token1 ? protocolFees.token1 : amount1Requested;

        protocolFees.token0 -= amount0;
        protocolFees.token1 -= amount1;

        TransferHelper.safeTransfer(token0, recipient, amount0);
        TransferHelper.safeTransfer(token1, recipient, amount1);
    }
  test_invariante: |
    // Invariante: protocol fees solo pueden ser colectadas por el owner/factory
    function invariant_protocolFeeAccess() public {
        uint128 fees0Before = pool.protocolFees().token0;

        if (msg.sender != pool.factory()) {
            try pool.collectProtocol(msg.sender, type(uint128).max, type(uint128).max) {
                t(false, "CLIQ-16: non-owner collected protocol fees");
            } catch {}
        }
    }

    // Invariante: protocol fees acumulados <= total fees * max protocol fee rate
    function invariant_protocolFeeBounded() public {
        uint128 protocolFees0 = pool.protocolFees().token0;
        // Protocol fee rate es max 1/4 del swap fee en Uniswap V3
        t(protocolFees0 <= ghost_totalSwapFees0 / 4 + 1,
            "CLIQ-16: protocol fees exceed maximum possible rate");
    }
  ejemplo_real:
    - audit: "Trail of Bits - Uniswap V3 Core (2021)"
      detalle: "TOB-UNI-016: collectProtocol está correctamente restringido a factory owner en Uniswap V3. Pero forks que cambian el patrón de acceso (e.g., permitir governance multisig) pueden abrir vectores de timing."
    - audit: "Code4rena - Velodrome V2 (2023)"
      detalle: "M-02: Protocol fee change no forzaba collect de fees acumulados antes del cambio de rate. Fees acumulados al rate viejo podían perderse o contabilizarse incorrectamente con el rate nuevo."
    - audit: "Sherlock - Thena (2023)"
      detalle: "M-01: Fee rate changes in concentrated liquidity pools could be front-run. Governance proposals para cambiar fees eran visibles en la mempool del timelock, permitiendo arbitraje de timing."
  severidad: medium
  confianza: media
  verificado: true
  tags: [protocol-fee, timing, governance, front-running, fee-rate]
  relacionado_con: [CLIQ-06, CLIQ-03]
```

### 1.17 Manipulación de Observations (TWAP) via Liquidity Shifts

```yaml
- id: CLIQ-17
  pattern: twap-manipulation-liquidity-shift
  titulo: "Manipulación del oracle TWAP moviendo liquidez concentrada entre ticks para sesgar observaciones"
  descripcion: >
    El oracle TWAP de Uniswap V3 registra el tickCumulative en cada bloque
    donde hay actividad. El tick registrado depende del sqrtPrice actual de
    la pool. Un atacante puede manipular el TWAP sin necesidad de un flash
    loan sostenido: 1) remover liquidez de un lado del rango activo,
    haciendo que swaps pequeños muevan el precio más, 2) ejecutar swaps
    pequeños y baratos al inicio/final de bloques para sesgar el tick
    registrado, 3) en cadenas con bloques rápidos (L2s como Base, Optimism),
    la manipulación es más barata porque hay más observaciones por unidad
    de tiempo. El array de observations tiene tamaño fijo (inicialmente 1,
    expandible hasta 65535) y si no se ha expandido, solo la observación
    más reciente está disponible, haciendo el TWAP trivialmente manipulable.
  patron_vulnerable: |
    // Error: TWAP con observation array no expandido
    function getTWAP(address pool, uint32 period) external view returns (int24) {
        // ERROR: no verifica que el observation array tenga suficientes slots
        // Si observationCardinality == 1, TWAP == spot price (manipulable)
        (int24 arithmeticMeanTick, ) = OracleLibrary.consult(pool, period);
        return arithmeticMeanTick;
    }

    // Error: no verificar observationCardinalityNext
    function isOracleReliable(address pool) external view returns (bool) {
        (,,uint16 observationIndex, uint16 observationCardinality,
         uint16 observationCardinalityNext,,) = IUniswapV3Pool(pool).slot0();

        // ERROR: solo verifica cardinality actual, no si hay suficientes observaciones
        // escritas. Cardinality puede ser 100 pero si la pool se creó hace 5 minutos,
        // solo hay 5 minutos de datos TWAP.
        return observationCardinality >= 10;
    }

    // Ataque en L2 con bloques de 2 segundos:
    // 1. Bloque N: swap pequeño que mueve tick a extremo
    // 2. Bloque N+1: nada (tick extremo se registra en observation)
    // 3. Bloque N+2: swap reverso
    // Costo: 2 swaps pequeños. Efecto: 1/3 de las observaciones están manipuladas
  test_invariante: |
    // Invariante: TWAP debe tener suficientes observaciones para ser confiable
    function invariant_twapReliability() public {
        (,,, uint16 observationCardinality,,,) = pool.slot0();

        // Mínimo 100 observaciones para un TWAP de 30 minutos en L2 (2s blocks)
        t(observationCardinality >= 100,
            "CLIQ-17: observation cardinality too low for reliable TWAP");

        // Verificar que las observaciones cubren suficiente tiempo
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 1800; // 30 minutos
        secondsAgos[1] = 0;

        try pool.observe(secondsAgos) returns (int56[] memory, uint160[] memory) {
            // OK: 30 minutos de datos disponibles
        } catch {
            t(false, "CLIQ-17: not enough observation data for 30-min TWAP");
        }
    }
  ejemplo_real:
    - audit: "Code4rena - Salty.io (2024)"
      detalle: "H-01: CoreSaltyFeed usaba TWAP de Uniswap V3 con window de 30 minutos como fallback de oracle. En pools nuevas con observationCardinality == 1, el TWAP era el spot price actual — trivialmente manipulable."
    - audit: "Cantina - Revert Lend (2024)"
      detalle: "V3Oracle usaba TWAP con configurable window. Si el observation array no estaba expandido, la consulta revertía, lo cual era el comportamiento seguro. Pero la documentación no hacía explícito que alguien debía expandir el array antes de usar la pool como colateral."
    - audit: "Pashov Audit Group - Ulti (2024)"
      detalle: "M-08: TWAP can be manipulated. TWAP de 10 minutos en pool con baja liquidez en L2 era manipulable con ~$10K de capital sostenido durante 3 minutos."
    - audit: "Sherlock - Sentiment V2 (2023)"
      detalle: "M-03: Uniswap V3 TWAP observation window insufficient on L2. Protocolos en Arbitrum/Optimism con TWAP windows calibrados para Ethereum mainnet (12s blocks) no eran suficientes en L2 (2s blocks)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [TWAP, observations, oracle, cardinality, L2, manipulation]
  relacionado_con: [CLIQ-04, CLIQ-14]
```

### 1.18 Errores de Redondeo en Auto-Compound de Posiciones

```yaml
- id: CLIQ-18
  pattern: auto-compound-rounding
  titulo: "Acumulación de errores de redondeo en auto-compound de posiciones concentradas"
  descripcion: >
    Los vaults de auto-compound (Arrakis, Gamma, Beefy CL, Revert Compoundor)
    recogen fees de posiciones Uniswap V3 y las re-invierten como liquidez
    adicional. Cada ciclo de compound implica: 1) collect fees en token0 y
    token1, 2) calcular ratio óptimo para el rango actual, 3) swap del
    exceso de un token, 4) mint nueva liquidez. Cada paso tiene redondeo.
    Después de cientos de compounds, el error acumulado puede ser significativo.
    Además, si la cantidad de fees es muy pequeña relativa al tick spacing,
    la liquidez añadida puede ser 0 (las fees se gastan en gas pero no se
    reinvierten). El atacante puede explotar esto donando tokens directamente
    a la posición para desbalancear el ratio y forzar swaps internos que
    generan slippage.
  patron_vulnerable: |
    // Vault de auto-compound con errores acumulativos
    contract AutoCompoundVault {
        function compound() external {
            // 1. Collect fees
            (uint256 fees0, uint256 fees1) = _collectFees();

            // 2. Calcular cuánto swapear para balancear
            // ERROR: usa spot price para calcular ratio — manipulable
            (uint160 sqrtPriceX96,,,,,,) = pool.slot0();

            uint256 targetRatio = _getTargetRatio(sqrtPriceX96, tickLower, tickUpper);
            uint256 currentRatio = fees0 * 1e18 / (fees0 + fees1);

            if (currentRatio > targetRatio) {
                // Swap exceso de token0 a token1
                uint256 swapAmount = (fees0 - fees0 * targetRatio / 1e18);
                // ERROR: swap sin slippage protection
                pool.swap(address(this), true, int256(swapAmount), MIN_SQRT_RATIO + 1, "");
            }

            // 3. Mint — liquidez puede ser 0 si amounts son dust
            uint128 liquidity = LiquidityAmounts.getLiquidityForAmounts(
                sqrtPriceX96, sqrtRatioA, sqrtRatioB, amount0, amount1
            );
            // ERROR: no verificar que liquidity > 0
            pool.mint(address(this), tickLower, tickUpper, liquidity, "");
            // Si liquidity == 0, los tokens se pierden (se quedan en el contrato sin ser LP)
        }
    }
  test_invariante: |
    // Invariante: compound no debe perder valor (fees recolectadas - gas ≈ nueva liquidez)
    function invariant_compoundNoLoss() public {
        uint256 totalValueBefore = _getPositionValue(tokenId);
        uint256 pendingFees = _getPendingFees(tokenId);

        vault.compound();

        uint256 totalValueAfter = _getPositionValue(tokenId);

        // El valor post-compound debe ser >= valor pre-compound + fees - slippage tolerance
        // Tolerance: 1% por slippage del swap interno + redondeo
        t(totalValueAfter >= (totalValueBefore + pendingFees) * 99 / 100,
            "CLIQ-18: compound lost >1% of value");
    }

    // Invariante: compound con liquidez 0 no debe ejecutarse
    function invariant_noZeroLiquidityCompound() public {
        uint128 liquidityBefore = _getPositionLiquidity(tokenId);

        vault.compound();

        uint128 liquidityAfter = _getPositionLiquidity(tokenId);

        // Si hubo fees para compoundar, la liquidez debe haber aumentado
        if (ghost_lastCompoundFees > DUST_THRESHOLD) {
            t(liquidityAfter > liquidityBefore,
                "CLIQ-18: compound with fees did not increase liquidity");
        }
    }
  ejemplo_real:
    - audit: "Code4rena - Arrakis V2 (2023)"
      detalle: "H-02: Auto-compound usaba spot price de slot0 para calcular ratio de swap, manipulable por MEV bot. El atacante manipulaba el precio justo antes del compound para forzar un swap desfavorable, extrayendo valor del vault."
    - audit: "Sherlock - Gamma Strategies (2023)"
      detalle: "H-01: Rebalance/compound del vault no tenía slippage protection en el swap interno. Bot JIT manipulaba el precio → compound swapeaba a precio desfavorable → bot revertía. Vault perdía ~2% por compound."
    - audit: "Cantina - Revert Compoundor (2024)"
      detalle: "M-03: Auto-compound con fees pequeñas podía resultar en liquidez 0 mintada. Las fees se gastaban en gas del compound pero no se reinvertían. Callers recibían reward por compoundar pero el vault no se beneficiaba."
    - audit: "Code4rena - Steer Protocol (2023)"
      detalle: "H-03: Vault rebalance susceptible to sandwich attack. El rebalanceo genera un swap grande predecible que es sistemáticamente sandwicheado por bots MEV, con pérdidas de 1-5% por evento."
  severidad: high
  confianza: alta
  verificado: true
  tags: [auto-compound, rounding, vault, rebalance, slippage, MEV]
  relacionado_con: [CLIQ-05, CLIQ-10]
```

---

## 2. Checklist de Auditoría — Liquidez Concentrada

### 2.1 Pre-audit

- [ ] ¿Es fork de Uniswap V3? ¿Qué cambios se hicieron al core (TickMath, SwapMath, Pool)?
- [ ] ¿Usa NonfungiblePositionManager o gestión de posiciones directa?
- [ ] ¿Hay vault/wrapper sobre las posiciones (auto-compound, managed)?
- [ ] ¿Qué oracle usan los protocolos downstream (TWAP, spot, Chainlink)?
- [ ] ¿Qué chain? (L1 vs L2 — afecta costo de manipulación TWAP)
- [ ] ¿Hay gauge/staking integrado en el tick crossing?
- [ ] ¿Protocol fees están habilitados? ¿Quién los controla?

### 2.2 Core Math

- [ ] **CLIQ-01**: TickMath.getSqrtRatioAtTick — ¿rangos extremos manejados?
- [ ] **CLIQ-10**: Redondeo en mulDiv — ¿siempre contra el usuario?
- [ ] **CLIQ-13**: Precisión en precios extremos — ¿pairs con decimales diferentes?
- [ ] **CLIQ-15**: maxLiquidityPerTick — ¿está implementado correctamente?
- [ ] Verificar que SqrtPriceMath usa roundUp vs roundDown correctamente en cada dirección de swap

### 2.3 Fee Accounting

- [ ] **CLIQ-02**: feeGrowthOutside se invierte correctamente en tick crossing
- [ ] **CLIQ-06**: feeGrowthGlobal usa uint256 (no uint128)
- [ ] **CLIQ-11**: Orden de operaciones en tick crossing: fees ANTES de liquidity update
- [ ] **CLIQ-16**: Protocol fee changes son atómicas con collect
- [ ] Verificar que fees acumuladas <= fees generadas (conservación)

### 2.4 Tick & Position Management

- [ ] **CLIQ-07**: Tick bitmap consistente con liquidityGross
- [ ] **CLIQ-08**: Permisos en todas las operaciones sobre posiciones (mint, burn, collect)
- [ ] **CLIQ-12**: Reentrancy en collect — CEI pattern, nonReentrant si tokens exóticos
- [ ] **CLIQ-14**: Pool initialization — sqrtPrice validado, no front-runnable
- [ ] Verificar que burn(0) no tiene efectos secundarios (Uniswap V3 lo permite para poke)

### 2.5 Oracle & TWAP

- [ ] **CLIQ-04**: TWAP cross-validado con Chainlink u otro oracle independiente
- [ ] **CLIQ-17**: observationCardinality suficiente para el window TWAP requerido
- [ ] Verificar que observe() no revierte silenciosamente con datos insuficientes
- [ ] En L2: TWAP window ajustado por block time (2s vs 12s)

### 2.6 MEV & Economic Attacks

- [ ] **CLIQ-03**: Sandwich amplificado por liquidez concentrada
- [ ] **CLIQ-05**: JIT liquidity attacks — ¿hay lock period? ¿Es bypassable?
- [ ] **CLIQ-09**: Flash loan + position manipulation — ¿colateral basado en posición NFT?
- [ ] **CLIQ-18**: Auto-compound — ¿slippage en swaps internos? ¿Liquidez 0?

---

## 3. Invariantes Universales para Liquidez Concentrada

```solidity
// === INVARIANTES CORE — TODA pool de liquidez concentrada ===

// INV-CLIQ-CORE-01: Conservación de tokens
// La pool nunca debe tener menos tokens de los que debe a posiciones + protocol fees
assert(token0.balanceOf(pool) >= totalTokensOwed0 + protocolFees0);
assert(token1.balanceOf(pool) >= totalTokensOwed1 + protocolFees1);

// INV-CLIQ-CORE-02: Liquidez activa consistente
// La suma de liquidityNet de todos los ticks cruzados desde MIN_TICK hasta currentTick
// debe ser igual a pool.liquidity() (liquidez activa)
int128 computedLiquidity = 0;
for (int24 tick = MIN_TICK; tick <= currentTick; tick += tickSpacing) {
    computedLiquidity += ticks[tick].liquidityNet;
}
assert(uint128(computedLiquidity) == pool.liquidity());

// INV-CLIQ-CORE-03: Suma de liquidityNet es cero
// Toda posición añade +delta a tickLower y -delta a tickUpper
int256 sumLiquidityNet = 0;
for (int24 tick = MIN_TICK; tick <= MAX_TICK; tick += tickSpacing) {
    sumLiquidityNet += ticks[tick].liquidityNet;
}
assert(sumLiquidityNet == 0);

// INV-CLIQ-CORE-04: Fee growth monotónicamente creciente (en aritmética modular)
// feeGrowthGlobalX128 nunca decrece dentro de una misma transacción
// (entre transacciones puede hacer wrap-around pero la diferencia siempre es positiva)

// INV-CLIQ-CORE-05: Tick bitmap ↔ liquidityGross
// Un tick está en el bitmap si y solo si liquidityGross > 0
for (int24 tick = MIN_TICK; tick <= MAX_TICK; tick += tickSpacing) {
    assert(tickBitmap.isSet(tick) == (ticks[tick].liquidityGross > 0));
}

// INV-CLIQ-CORE-06: sqrtPrice bounded
assert(pool.sqrtPriceX96() >= TickMath.MIN_SQRT_RATIO);
assert(pool.sqrtPriceX96() <= TickMath.MAX_SQRT_RATIO);

// INV-CLIQ-CORE-07: currentTick consistente con sqrtPrice
int24 expectedTick = TickMath.getTickAtSqrtRatio(pool.sqrtPriceX96());
assert(pool.slot0().tick == expectedTick);

// INV-CLIQ-CORE-08: maxLiquidityPerTick respetado
for (int24 tick = MIN_TICK; tick <= MAX_TICK; tick += tickSpacing) {
    assert(ticks[tick].liquidityGross <= Tick.tickSpacingToMaxLiquidityPerTick(tickSpacing));
}

// INV-CLIQ-CORE-09: Mint-then-burn no es profitable
// Para cualquier posición: burn(liquidity) + collect() devuelve <= tokens depositados en mint
// (tolerancia: 1 wei por token por redondeo)

// INV-CLIQ-CORE-10: Swap conserva valor (k equivalente)
// Para cada swap step: amount0 * amount1 del step es consistente con la liquidez activa
// amount0 = liquidity * (1/sqrtP_new - 1/sqrtP_old)
// amount1 = liquidity * (sqrtP_new - sqrtP_old)
```

---

## 4. Contratos Clave a Revisar

| Contrato | Qué buscar | Patterns |
|----------|-----------|----------|
| `UniswapV3Pool.sol` | swap(), mint(), burn(), collect(), flash() | CLIQ-01 a CLIQ-16 |
| `TickMath.sol` | getSqrtRatioAtTick(), getTickAtSqrtRatio() | CLIQ-01, CLIQ-13 |
| `SqrtPriceMath.sol` | getAmount{0,1}Delta(), getNextSqrtPriceFrom*() | CLIQ-10, CLIQ-13 |
| `SwapMath.sol` | computeSwapStep() | CLIQ-10, CLIQ-11 |
| `FullMath.sol` | mulDiv(), mulDivRoundingUp() | CLIQ-10 |
| `Tick.sol` | cross(), update() | CLIQ-02, CLIQ-07, CLIQ-15 |
| `TickBitmap.sol` | flipTick(), nextInitializedTickWithinOneWord() | CLIQ-07 |
| `Oracle.sol` (observations) | observe(), write(), grow() | CLIQ-04, CLIQ-17 |
| `NonfungiblePositionManager.sol` | mint(), increaseLiquidity(), decreaseLiquidity(), collect() | CLIQ-08, CLIQ-12 |
| `UniswapV3Factory.sol` | createPool(), setOwner(), enableFeeAmount() | CLIQ-14, CLIQ-16 |

---

## 5. Diferencias Críticas entre Implementaciones

| Aspecto | Uniswap V3 | PancakeSwap V3 | Velodrome V2 | Algebra V3 |
|---------|-----------|----------------|-------------|-----------|
| Tick spacing | Fijo por fee tier (1/10/60/200) | Igual que Uni V3 | Configurable por pool | Dinámico (adaptive) |
| Fee structure | Fijo por pool (0.01/0.05/0.3/1%) | Igual que Uni V3 | Dinámico (epoch-based) | Adaptive (volatility-based) |
| Protocol fee | 1/N del swap fee (N=4..10) | Igual | Voter-directed | Configurable |
| Gauge rewards | No | No | Sí (tick crossing actualiza rewards) | Sí (Algebra farming) |
| Oracle | TWAP integrado | TWAP integrado | TWAP integrado | TWAP integrado |
| Position NFT | ERC-721 via periphery | ERC-721 via periphery | ERC-721 integrado | Farming NFT separado |
| Flash loans | pool.flash() | pool.flash() | No flash() | pool.flash() |
| Hooks | No (V4 sí) | No | No | Plugin system |

**Riesgos por implementación:**
- **Velodrome/Aerodrome**: El tick crossing dispara actualización de gauge rewards — bugs CLIQ-02 amplificados. Las fees son dinámicas por epoch, creando oportunidades de timing (CLIQ-16).
- **Algebra**: Adaptive fees cambian mid-swap, complicando fee accounting (CLIQ-06, CLIQ-11). Plugin system añade superficie de ataque similar a hooks V4.
- **PancakeSwap V3**: Fork cercano al original, menor riesgo de divergencia. Pero PancakeSwap MasterChef V3 wrappea posiciones para farming, añadiendo capa de permisos (CLIQ-08).

---

## 6. Incidentes Reales y Exploits

### 6.1 Exploits On-Chain

- **2023-07 — Curve Pool Reentrancy (Vyper)**: Aunque es AMM clásico (no CL), el exploit de reentrancy en Curve pools ($70M) demostró que collect/withdraw sin reentrancy guard es un vector activo. Aplica directamente a CLIQ-12 en forks CL sin nonReentrant.

- **2023-03 — Euler Finance ($197M)**: Euler usaba Uniswap V3 TWAP como oracle. Aunque el exploit principal fue en la lógica de lending (donateToReserves), la dependencia del TWAP fue un factor. Relevante para CLIQ-04.

- **2022-10 — Moola Market ($8.4M)**: Manipulación de oracle AMM-based para inflar colateral y tomar préstamos. Patrón idéntico a CLIQ-09 con pools concentradas.

### 6.2 Audit Findings Notables

- **Trail of Bits — Uniswap V3 (2021)**: 29 findings totales, 0 critical en el código final. Validaron la robustez del diseño pero señalaron explícitamente que forks tendrían problemas.

- **Sherlock — Velodrome V2 (2023)**: 12 findings HIGH/MEDIUM, la mayoría en la interacción gauge ↔ tick crossing. Patrón dominante: fee/reward accounting en tick crossing (CLIQ-02, CLIQ-11).

- **Code4rena — Panoptic (2024)**: 15+ findings en la capa de opciones sobre Uniswap V3. Fee tracking, position management, y precision loss fueron las categorías dominantes (CLIQ-02, CLIQ-08, CLIQ-10).

- **Sherlock — Bunni V2 (2024)**: computeSwap devuelve output nonzero con input zero — error de redondeo en implementación personalizada de swap math (CLIQ-10).

---

## 7. Solodit Findings Mapeados

### Mapeo a CLIQ-01 (Tick Math Overflow)

- **[HIGH] getSqrtRatioAtTick edge case at MIN_TICK produces incorrect sqrtPrice in custom CLMM** — Fork de CLMM modifica el rango de ticks sin actualizar constantes mágicas en TickMath, produciendo sqrtPrice incorrecto en ticks extremos.
- **[MEDIUM] TickMath precision degradation for non-standard tick spacings** — Tick spacings no-estándar causan que ticks calculados no correspondan exactamente a los sqrtPrices esperados.

### Mapeo a CLIQ-02 (Fee Accounting Tick Crossing)

- **[HIGH] Fee growth outside not flipped on tick cross in custom concentrated liquidity pool** — Fork de CL omite la inversión de feeGrowthOutside para uno de los tokens durante tick crossing, causando distribución incorrecta de fees.
- **[HIGH] Reward growth desync at tick boundaries in gauge-integrated CLMM** — Velodrome-style CLMM no invierte rewardGrowthOutside durante tick crossing, causando doble-conteo de rewards para posiciones que abarcan el tick.
- **[MEDIUM] Cross-tick fee accounting breaks when swap exactly lands on initialized tick** — Edge case donde sqrtPrice post-swap es exactamente el sqrtPrice del tick inicializado — la lógica de "¿cruzamos el tick?" produce resultado ambiguo.

### Mapeo a CLIQ-04 (Oracle Manipulation)

- **[HIGH] Reallocation depends on slot0 price, which can be manipulated** — LP position reallocation logic lee slot0 para decisiones de rango; atacante manipula via flash swap para forzar reallocation desfavorable.
- **[HIGH] CoreSaltyFeed spot price can lead to price manipulation and undesired liquidations** — Protocolo usa spot price de pool CL como fallback cuando Chainlink no disponible.
- **[HIGH] Pool deviation check in SimpleManager on rebalance can be bypassed** — Price deviation guard compara contra referencia manipulable en pool CL.
- **[MEDIUM] TWAP price manipulation in low-liquidity concentrated pool** — TWAP de 5 minutos en pool CL con liquidez concentrada en rango estrecho es manipulable con capital modesto.

### Mapeo a CLIQ-08 (Position NFT Permissions)

- **[HIGH] Anyone can decrease liquidity of any position via missing approval check** — NonfungiblePositionManager fork omite _isApprovedOrOwner en decreaseLiquidity.
- **[HIGH] Staked position fees can be claimed by non-owner during liquidation** — Posiciones stakeadas en gauge permiten collect de fees por liquidador sin proper authorization flow.
- **[MEDIUM] Approved operator cannot collect fees due to overly restrictive check** — Lo opuesto: check de permisos es demasiado restrictivo, bloqueando operaciones legítimas de operators aprobados.

### Mapeo a CLIQ-09 (Flash Loan + Position Manipulation)

- **[HIGH] Attacker can profit by manipulating Uniswap liquidity (stNXM)** — Protocolo lee Uniswap V3 liquidity state para pricing; atacante añade liquidez concentrada para manipular.
- **[HIGH] Uniswap V3 position value inflatable via flash swap for collateral manipulation** — Lending protocol valúa NFT de posición usando spot sqrtPrice de la pool, manipulable con flash swap.

### Mapeo a CLIQ-10 (Rounding Errors)

- **[HIGH] BunniSwapMath.computeSwap returns nonzero output with zero input** — Error de redondeo en swap math personalizada permite extraer tokens gratis.
- **[HIGH] Rounding in liquidity calculations allows dust extraction via repeated mint-burn** — mulDiv sin RoundingUp en getAmount0ForLiquidity permite mint con menos tokens de los debidos.
- **[MEDIUM] Fee rounding accumulation over many swaps causes LP loss** — Fees se redondean a favor del swapper en lugar del pool en implementación derivada.

### Mapeo a CLIQ-14 (Pool Initialization)

- **[HIGH] Pool initialization front-running allows attacker to set arbitrary price** — Protocolo crea pool en transacción separada de initialize, permitiendo front-run con precio malicioso.
- **[HIGH] Attacker initializes pool at extreme price before token launch** — Token launch contract no verifica que pool no fue pre-inicializada con precio extremo.
- **[MEDIUM] createAndInitializePoolIfNecessary does not validate resulting sqrtPrice** — Helper function no verifica que el sqrtPrice post-inicialización está dentro de rango esperado.

### Mapeo a CLIQ-17 (TWAP Manipulation)

- **[HIGH] TWAP oracle manipulable on L2 due to fast block times** — TWAP de 30 minutos en L2 con bloques de 2s tiene 900 observaciones pero cada observación es manipulable con swaps baratos.
- **[MEDIUM] Observation cardinality not expanded, TWAP equals spot price** — Pool nueva con observationCardinality == 1 hace que el TWAP sea idéntico al spot price.
- **[MEDIUM] TWAP window insufficient for low-liquidity concentrated pools** — Window de 30 minutos insuficiente cuando el costo de manipulación es bajo por liquidez concentrada fuera del rango activo.

### Mapeo a CLIQ-18 (Auto-Compound Rounding)

- **[HIGH] Vault rebalance susceptible to sandwich attack via predictable swap** — Auto-compound vault genera swap predecible que es sandwicheado por MEV bots.
- **[HIGH] Compound with zero slippage on internal swap allows value extraction** — Auto-compound swap interno sin amountOutMin permite sandwich completo.
- **[MEDIUM] Compound results in zero liquidity minted, fees lost to gas** — Compound con fees pequeñas calcula liquidity == 0, fees se pierden sin reinvertirse.
- **[MEDIUM] Donation attack inflates vault share price via direct token transfer** — Atacante transfiere tokens directamente a la posición del vault, inflando el share price para exploit de primer depositante.

---

## 8. Quick Reference — Comandos de Verificación

```bash
# Buscar uso de slot0 (spot price) en lugar de TWAP — CLIQ-04, CLIQ-09
grep -rn "slot0\(\)" src/ --include="*.sol" | grep -v "test\|mock\|interface"

# Buscar collect sin verificación de permisos — CLIQ-08
grep -rn "function collect" src/ --include="*.sol" -A 5 | grep -v "isApprovedOrOwner\|onlyOwner\|require.*owner"

# Buscar mulDiv sin RoundingUp donde debería haberlo — CLIQ-10
grep -rn "mulDiv(" src/ --include="*.sol" | grep -v "RoundingUp"

# Buscar initialize sin validación de precio — CLIQ-14
grep -rn "initialize(" src/ --include="*.sol" -A 3 | grep -v "require\|assert\|revert"

# Buscar TWAP con window corto — CLIQ-17
grep -rn "consult\|observe" src/ --include="*.sol" -B 2 -A 2

# Buscar compound/rebalance sin slippage — CLIQ-18
grep -rn "swap\|exactInput\|exactOutput" src/ --include="*.sol" -A 3 | grep "amountOutMin.*0\|sqrtPriceLimitX96.*0"

# Buscar feeGrowthOutside update en tick crossing — CLIQ-02
grep -rn "feeGrowthOutside" src/ --include="*.sol" -A 2

# Buscar liquidityNet sin check de maxLiquidity — CLIQ-15
grep -rn "liquidityNet" src/ --include="*.sol" -B 2 -A 2

# Buscar nonReentrant en collect — CLIQ-12
grep -rn "function collect" src/ --include="*.sol" -B 2 | grep "nonReentrant\|ReentrancyGuard"
```
