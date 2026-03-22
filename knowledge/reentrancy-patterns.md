grep_targets:
  - "nonReentrant"
  - "ReentrancyGuard"
  - "reentrancy"
  - ".call{"
  - ".call("
  - "transfer("
  - "send("
  - "safeTransfer"
  - "onERC721Received"
  - "onERC1155Received"
  - "tokensReceived"
  - "receive()"
  - "fallback()"
  - "callback"
  - "hook"
  - "flashLoan"
  - "uniswapV3SwapCallback"
  - "pancakeV3SwapCallback"
  - "locked"
  - "status"

# Briefing: Reentrancy Patterns

## Contexto del dominio
La reentrancia ocurre cuando un contrato externo puede volver a llamar al contrato
original antes de que este termine su ejecución. Los ataques clásicos (The DAO, 2016)
son ampliamente conocidos, pero los patrones modernos son más sutiles:
- Cross-function reentrancy (entrar por una función diferente)
- Cross-contract reentrancy (entrar a través de otro contrato del protocolo)
- Read-only reentrancy (leer estado inconsistente sin modificarlo)
- Callback reentrancy en ERC721/ERC1155/ERC777
- Reentrancy en flashloans y swaps callbacks

---

patterns:

- id: re-001
  titulo: CEI Violation — Estado Actualizado Después de la Llamada Externa
  causa_raiz: |
    El patrón Checks-Effects-Interactions (CEI) requiere: (1) checks (validar), (2) effects
    (actualizar estado), (3) interactions (llamadas externas). Si el estado se actualiza
    DESPUÉS de una llamada externa (violación CEI), el atacante puede re-entrar durante
    la llamada externa con el estado viejo aún visible.
  como_funciona: |
    1. Alice llama withdraw(100 ETH)
    2. Contrato: verifica balance[Alice] >= 100 ✓
    3. Contrato: envía 100 ETH a Alice → Alice.receive() se dispara
    4. Dentro de receive(): Alice vuelve a llamar withdraw(100 ETH)
    5. balance[Alice] TODAVÍA es 100 (no se actualizó aún) → segunda extracción
    6. El contrato finalmente actualiza balance[Alice] = 0 pero ya se fue el doble
  invariante: |
    // Ghost: balance antes y después de withdraw
    mapping(address => uint256) internal ghost_balanceBefore;

    function handler_withdraw(uint256 amount) external {
        ghost_balanceBefore[msg.sender] = vault.balanceOf(msg.sender);
        uint256 ethBefore = address(this).balance;
        vault.withdraw(amount);
        // El balance del contrato debe haber caído en exactamente `amount`
        t(address(vault).balance == ethBefore - amount || amount == 0,
          "RE-001: vault balance dropped more than withdrawn amount");
        // El balance del usuario en el contrato debe haberse reducido
        t(vault.balanceOf(msg.sender) <= ghost_balanceBefore[msg.sender] - amount,
          "RE-001: user balance not properly reduced after withdraw");
    }
  que_mirar:
    - "Estado actualizado DESPUÉS de .call{value}, safeTransfer, o callbacks"
    - "Funciones de withdraw/claim sin nonReentrant"
    - "transfer() y send() en Solidity tienen gas limit de 2300 — pero pueden ejecutar receive()"
    - "Los módulos de Gnosis Safe usan delegatecall — la reentrancy puede ser cross-module"
  como_se_arregla: |
    - Siempre CEI: actualizar estado ANTES de transferir
    - Añadir nonReentrant modifier como segunda línea de defensa
    - Para ETH: usar pull-over-push cuando sea posible
  trampas:
    - "nonReentrant no protege contra cross-function reentrancy si las dos funciones no comparten el lock"
    - "El patrón mutex (locked = true) solo protege el contrato actual, no contratos hermanos"
    - "Los callbacks ERC721/ERC1155 pueden disparar reentrancy en funciones que parecen seguras"
  solodit_ids:
    - "m-21-concurrewardpool-possible-reentrancy-when-claiming-rewards-code4rena-concur-finance-concur-finance-contest-git"
    - "balanceof-can-be-circumvented-via-reentrancy-and-two-pairs-spearbit-sudoswap-lssvm2-pdf"
    - "process-the-same-withdrawal-request-quantstamp-stakestone-vault-markdown"

- id: re-002
  titulo: Cross-Function Reentrancy — Entrar por Función Diferente con Estado Inconsistente
  causa_raiz: |
    El nonReentrant de una función protege esa función específica. Si el contrato tiene
    dos funciones A y B que comparten estado, y A hace una llamada externa, el atacante
    puede re-entrar por B (que no está lockeada por el mutex de A). B ve el estado
    inconsistente de A y lo explota.
  como_funciona: |
    Escenario lending protocol:
    1. Alice llama repay(loan) → actualiza debtBalance a 0, luego envía colateral de vuelta
    2. Durante el envío del colateral (llamada externa), Alice re-entra por borrow()
    3. borrow() verifica: debtBalance = 0 → Alice puede pedir prestado de nuevo
    4. Pero los fondos del repay ya están en vuelo → Alice tiene cero deuda y nuevo préstamo
    5. Alice recibe el colateral + el nuevo préstamo sin haber pagado la primera deuda

    Escenario más sutil:
    - A deposita colateral, B calcula el ratio de colateral
    - A hace llamada externa ANTES de registrar el colateral
    - Durante la llamada, atacante llama B → B ve ratio sin el colateral nuevo → liquidación incorrecta
  invariante: |
    bool internal ghost_inExternalCall;

    modifier trackExternalCall() {
        ghost_inExternalCall = true;
        _;
        ghost_inExternalCall = false;
    }

    function check_no_state_access_during_external_call() internal view {
        // Todas las funciones sensibles deben verificar que no hay llamada externa en progreso
        t(!ghost_inExternalCall || msg.sender == address(this),
          "RE-002: state accessed during external call — possible cross-function reentrancy");
    }
  que_mirar:
    - "¿El nonReentrant es a nivel de contrato (comparte el lock) o a nivel de función?"
    - "¿Hay funciones en el mismo contrato que comparten estado con una función que hace llamadas externas?"
    - "¿Los pares de funciones deposit/withdraw, borrow/repay comparten el mutex?"
    - "¿El protocolo usa módulos separados que no comparten el ReentrancyGuard?"
  como_se_arregla: |
    - Usar un mutex a nivel de contrato que bloquea TODAS las funciones sensibles
    - OZ ReentrancyGuard.nonReentrant bloquea solo la función decorada — verificar si es suficiente
    - Para protocolos con múltiples contratos: usar un ReentrancyGuard compartido (singleton)
    - Alternativa: CEI estricto elimina el riesgo incluso sin nonReentrant
  trampas:
    - "Uniswap V3 usa un 'locked' flag global — esto protege contra cross-function reentrancy dentro del pool"
    - "Los protocolos multi-contract con callbacks entre contratos tienen la mayor superficie de cross-function reentrancy"
    - "Los delegates en Gnosis Safe pueden explotar cross-function reentrancy entre módulos"
  solodit_ids:
    - "h-02-cross-function-reentrancy-via-callback-allows-double-borrow-sherlock-git"
    - "m-cross-function-reentrancy-between-deposit-and-withdraw-code4rena-git"

- id: re-003
  titulo: Read-Only Reentrancy — Lectura de Estado Inconsistente Sin Modificarlo
  causa_raiz: |
    Los contratos externos que leen estado de un protocolo durante una llamada externa
    pueden ver un estado inconsistente, incluso si no modifican ese estado. El contrato
    víctima no tiene nonReentrant (porque no modifica estado), pero el estado que expone
    es temporalmente incorrecto durante la llamada.
  como_funciona: |
    Escenario Curve/Balancer attack (real, $2M+ robados):
    1. Protocolo A usa Curve pool para obtener el precio de un LP token
    2. Curve pool expone get_virtual_price() — precio del LP token
    3. Durante un add_liquidity() en Curve, el precio temporalmente es incorrecto
    4. El atacante, en el mismo bloque: llama add_liquidity() en Curve, en el callback
       llama al Protocolo A que lee get_virtual_price()
    5. get_virtual_price() devuelve el valor con los nuevos tokens pero SIN los shares
       minted aún → precio inflado temporalmente
    6. Protocolo A acepta el colateral inflado → atacante pide prestado de más
  invariante: |
    function check_price_not_in_reentrancy(address curvePool) internal {
        // En Curve, _reentrancy_guard_locked() puede verificar si el pool está en reentrancy
        if (ICurvePool(curvePool).reentrancy_guard_locked()) {
            revert("RE-003: reading Curve price during reentrancy window");
        }
    }
  que_mirar:
    - "¿El protocolo lee precios de Curve/Balancer/TWAP dentro de un callback?"
    - "¿get_virtual_price() de Curve se llama sin verificar si el pool está lockeado?"
    - "¿El protocolo usa el balance del LP token como precio sin verificar el estado del pool?"
    - "¿Hay funciones 'view' que leen estado que puede ser inconsistente durante reentrancy?"
  como_se_arregla: |
    - Para Curve: verificar que el pool no esté en estado de reentrancy usando el lock expuesto
    - Para Balancer: usar el vault.reentrancyGuardEntered() check
    - No usar precios de AMMs como oracle primario para colateral — usar Chainlink
    - Si se usa AMM price: solo en funciones que no son llamadas desde callbacks
  trampas:
    - "Las read-only reentrancy no modifican estado → nonReentrant no ayuda en el contrato víctima"
    - "La defensa está del lado del protocolo que LEE el precio, no del protocolo de AMM"
    - "Balancer V2 tuvo exactamente este bug — se arregló exponiendo reentrancyGuardEntered()"
  solodit_ids:
    - "h-read-only-reentrancy-in-curve-pool-allows-price-manipulation-sherlock-git"
    - "m-balancer-read-only-reentrancy-allows-price-manipulation-code4rena-git"

- id: re-004
  titulo: ERC721 safeTransferFrom — onERC721Received Callback Reentrancy
  causa_raiz: |
    ERC721.safeTransferFrom() llama a onERC721Received() en el receptor si es un contrato.
    Esta callback se ejecuta DURANTE la transferencia, antes de que la tx del sender
    complete. Si el contrato que transfiere el NFT tiene estado inconsistente en ese
    momento (violación CEI), el callback puede explotar ese estado.
  como_funciona: |
    Escenario NFT marketplace:
    1. Marketplace tiene: function buy(uint256 tokenId) — cobra precio, transfiere NFT
    2. buy() hace: (1) cobra el precio (OK), (2) transfiere NFT con safeTransferFrom
    3. safeTransferFrom llama onERC721Received en el comprador malicioso
    4. Dentro del callback: comprador vuelve a llamar buy() con el mismo tokenId
    5. El estado de "tokenId vendido" no se actualizó aún → doble venta
    6. Comprador recibe el NFT dos veces (o recibe fondos del segundo comprador)

    Escenario staking NFT:
    1. stake(tokenId) transfiere el NFT al contrato con safeTransferFrom
    2. El callback onERC721Received() actualiza el balance del staker
    3. PERO el balance se actualiza DENTRO del callback (antes de que stake() termine)
    4. Un atacante puede hacer unstake() dentro del onERC721Received() callback
  invariante: |
    function check_nft_transfer_safe(uint256 tokenId) internal {
        address ownerBefore = nft.ownerOf(tokenId);
        nft.safeTransferFrom(address(this), recipient, tokenId);
        address ownerAfter = nft.ownerOf(tokenId);
        // El ownership debe cambiar exactamente una vez
        t(ownerAfter == recipient && ownerBefore != recipient,
          "RE-004: NFT ownership transfer not atomic");
    }
  que_mirar:
    - "¿El contrato usa safeTransferFrom para NFTs y actualiza estado después del transfer?"
    - "¿El estado de 'NFT vendido/staked' se actualiza ANTES del safeTransferFrom?"
    - "¿Funciones críticas tienen nonReentrant cuando transfieren NFTs?"
    - "¿onERC721Received puede ser controlado por un atacante que usa un contrato malicioso?"
  como_se_arregla: |
    - CEI: actualizar el estado del token (e.g., ownerOf interno) ANTES de llamar safeTransferFrom
    - O: usar transferFrom (sin callback) y verificar que el receptor es de confianza
    - Añadir nonReentrant a todas las funciones que llaman safeTransferFrom
  trampas:
    - "transferFrom (sin 'safe') no llama el callback — más seguro contra reentrancy pero menos seguro para receptores de contrato que no saben recibir NFTs"
    - "ERC1155 tiene el mismo patrón con onERC1155Received y onERC1155BatchReceived"
  solodit_ids:
    - "balanceof-can-be-circumvented-via-reentrancy-and-two-pairs-spearbit-sudoswap-lssvm2-pdf"
    - "h-reentrancy-via-onerc721received-allows-double-claim-sherlock-git"

- id: re-005
  titulo: Flash Loan Callback Reentrancy — executeOperation Explota Estado Pre-Repago
  causa_raiz: |
    Los flash loans (Aave, dYdX, Uniswap V3 flashSwap) ejecutan un callback en el
    borrower durante el préstamo. El contrato del flash loan no ha registrado el repago
    aún. Si el protocolo víctima usa el flash loan provider como oracle de liquidez o
    de precios, el estado durante el callback puede ser inconsistente.
  como_funciona: |
    Variante A — Precio durante flash loan:
    1. Atacante toma flash loan de 10M ETH de Uniswap V3
    2. La pool tiene temporalmente 10M ETH menos
    3. Precio calculado por AMM cambia masivamente durante el callback
    4. Protocolo víctima lee el precio del pool (slot0) → precio manipulado
    5. Atacante usa ese precio manipulado para su beneficio

    Variante B — Estado del protocolo durante callback:
    1. Protocolo tiene: función deposit() que emite shares, y flashLoan()
    2. Atacante llama flashLoan() → en executeOperation(), llama deposit()
    3. El total de shares puede ser inconsistente durante el flash loan
    4. El precio por share calculado durante el callback puede estar inflado/deflado
  invariante: |
    function check_flashloan_not_during_callback() internal view {
        // Usar un flag que indique si estamos dentro de un flash loan callback
        t(!inFlashLoanCallback,
          "RE-005: critical function called during flash loan callback");
    }
  que_mirar:
    - "¿El protocolo lee precios de pools que pueden estar en medio de un flash swap?"
    - "¿El callback de flashLoan puede llamar a funciones de otro protocolo que lee estado del pool?"
    - "¿Las funciones deposit/withdraw tienen nonReentrant que bloquea el callback de flashLoan?"
    - "¿El protocolo usa UniswapV2/V3 callback (uniswapV2Call, uniswapV3SwapCallback) y el estado es correcto en ese momento?"
  como_se_arregla: |
    - No usar precios spot de pools que soportan flash loans como oracle de colateral
    - Para flash loans internos: usar un flag `flashLoanInProgress` que bloquee otras operaciones
    - Usar TWAP con período suficientemente largo para que el flash loan no lo afecte (30+ min)
  trampas:
    - "El TWAP no es afectado por flash loans — el precio solo se actualiza al final del bloque"
    - "Chainlink es completamente resistente a flash loans — recomendado para colateral"
    - "Los flash loans de Aave V3 sí tienen fee (0.05%) lo que reduce pero no elimina el incentivo"
  solodit_ids:
    - "h-01-slot0-price-manipulation-allows-draining-collateral-code4rena-git"
    - "h-flash-loan-callback-can-be-used-to-manipulate-price-and-drain-funds-sherlock-git"

- id: re-006
  titulo: Cross-Contract Reentrancy — Protocolo A Llama a B que Re-Entra en A
  causa_raiz: |
    Cuando un protocolo tiene múltiples contratos que interactúan, el ReentrancyGuard
    de un contrato no protege a los otros. Si el contrato A llama al contrato B,
    y B tiene un callback que llama de vuelta al contrato A (a través de un tercero
    o directamente), el mutex de A no está activado para esta segunda llamada a A.
  como_funciona: |
    Escenario (similar a real EigenLayer bug):
    1. Protocolo tiene: Vault.sol (con ReentrancyGuard) y Strategy.sol (sin mutex compartido)
    2. Vault.withdraw() llama Strategy.withdraw() (llamada a contrato hermano)
    3. Strategy.withdraw() hace una llamada externa a un token con hooks
    4. El hook del token llama de vuelta a Vault.deposit() (contrato diferente al original)
    5. Vault.deposit() no está lockeado por el mutex de Vault.withdraw() (son funciones distintas)
    6. Estado de Vault está inconsistente → depósito con estado corrupto
  invariante: |
    // Usar un lock compartido entre todos los contratos del protocolo
    address constant REENTRANCY_LOCK = address(0xDEAD);

    function check_no_cross_contract_reentrancy() internal view {
        t(!IReentrancyLock(REENTRANCY_LOCK).isLocked(),
          "RE-006: cross-contract reentrancy detected");
    }
  que_mirar:
    - "¿El protocolo tiene múltiples contratos que se llaman entre sí? ¿Comparten el ReentrancyGuard?"
    - "¿Una llamada externa desde el contrato B puede ejecutar código que llama al contrato A?"
    - "¿Los contratos de estrategia/módulo tienen su propio ReentrancyGuard separado del vault principal?"
    - "¿El deposit y el withdraw del mismo protocolo están en contratos diferentes?"
  como_se_arregla: |
    - Singleton ReentrancyGuard: todos los contratos del protocolo consultan el mismo lock
    - Diseño de "hub and spoke": el hub tiene el lock, los spokes lo respetan
    - Alternativa: CEI estricto en todos los contratos elimina el riesgo
  trampas:
    - "EigenLayer tuvo esta vulnerabilidad — el fix fue un lock compartido entre todos los contratos del protocolo"
    - "Los protocolos proxy con múltiples implementation contracts tienen el mismo riesgo"
    - "Las libraries que hacen delegatecall comparten el storage del caller — si tienen callbacks, aplica el mismo riesgo"
  solodit_ids:
    - "h-cross-contract-reentrancy-between-vault-and-strategy-allows-double-withdrawal-sherlock-git"
    - "m-reentrancy-guard-not-shared-across-contracts-allows-cross-contract-attack-code4rena-git"

- id: re-007
  titulo: Reentrancy en Liquidación — Colateral Recuperado Antes de Deuda Registrada
  causa_raiz: |
    Las funciones de liquidación en lending protocols realizan múltiples operaciones:
    (1) verificar que la posición es liquidable, (2) repagar la deuda, (3) transferir
    el colateral al liquidador. Si el colateral se transfiere con un callback y el
    estado de la deuda no está completamente actualizado, el liquidador puede
    manipular el estado para obtener más colateral de lo debido.
  como_funciona: |
    1. liquidate(borrower) verifica: posición es liquidable ✓
    2. Contrato: calcula colateralToTransfer = deuda * (1 + liquidationBonus)
    3. Contrato: transfiere colateral al liquidador (safeTransfer con callback)
    4. En el callback: liquidador llama liquidate() otra vez con el mismo borrower
    5. La deuda del borrower AÚN NO se redujo → posición aún parece liquidable
    6. Liquidador recibe el doble del colateral por la misma deuda
    7. Después de ambas liquidaciones: deuda = 0, colateral = 0, pero se pagó 2x colateral
  invariante: |
    function check_liquidation_solvency_post() internal view {
        // Después de una liquidación, el protocolo no debe quedar con menos activos de lo esperado
        uint256 totalDebt = getTotalDebt();
        uint256 totalCollateral = getTotalCollateral();
        // La relación debt/collateral no debe haber empeorado
        t(totalDebt * 1e18 / totalCollateral <= PROTOCOL_MAX_LTV,
          "RE-007: protocol undercollateralized after liquidation — possible reentrancy");
    }
  que_mirar:
    - "¿La función de liquidación actualiza la deuda del borrower ANTES de transferir el colateral?"
    - "¿El colateral se transfiere con safeTransfer (con callback) o con transfer (sin callback)?"
    - "¿La función de liquidación tiene nonReentrant?"
    - "¿Hay una ventana donde la posición parece liquidable aunque ya se esté procesando su liquidación?"
  como_se_arregla: |
    - En liquidate(): (1) marcar posición como "en liquidación", (2) actualizar deuda, (3) transferir colateral
    - Usar un estado "liquidating" que bloquea re-liquidaciones de la misma posición
    - Añadir nonReentrant a la función de liquidación
  trampas:
    - "Las liquidaciones parciales son más vulnerables — la posición puede parecer aún liquidable después de una liquidación parcial"
    - "El colateral puede ser un NFT — safeTransfer para ERC721 SIEMPRE tiene callback"
  solodit_ids:
    - "h-reentrancy-in-liquidation-allows-stealing-collateral-via-double-liquidation-sherlock-git"
    - "m-liquidation-function-missing-nonreentrant-allows-callback-exploit-code4rena-git"

- id: re-008
  titulo: Uniswap V3 SwapCallback — Reentrancy desde la Pool Durante Swap
  causa_raiz: |
    Uniswap V3 llama a uniswapV3SwapCallback() en el caller durante un swap, antes de
    que el swap complete y antes de que se registre la liquidez cambiada. Si el protocolo
    que llama al swap hace cosas en el callback que asumen que el swap ya completó,
    o si el callback llama de vuelta al pool con un estado inconsistente, hay reentrancy.
  como_funciona: |
    Escenario legitimate pero peligroso:
    1. Protocolo llama IUniswapV3Pool.swap(...)
    2. Uniswap llama de vuelta: uniswapV3SwapCallback(amount0Delta, amount1Delta, data)
    3. El protocolo DEBE enviar los tokens requeridos en el callback
    4. Si el protocolo usa los tokens del balance del contrato (que incluye el colateral de usuarios)
       y la contabilidad interna no está sincronizada, hay un problema

    Ataque activo:
    1. Un contrato malicioso llama directamente a uniswapV3SwapCallback del protocolo víctima
    2. El callback no verifica que fue llamado por la pool legítima de Uniswap
    3. El atacante provee datos arbitrarios → el callback envía tokens del protocolo al atacante
  invariante: |
    function uniswapV3SwapCallback(
        int256 amount0Delta, int256 amount1Delta, bytes calldata data
    ) external override {
        // CRÍTICO: verificar que el caller es la pool legítima
        address pool = abi.decode(data, (address));
        t(msg.sender == pool, "RE-008: callback not from expected Uniswap V3 pool");
        // Verificar que el pool fue deployado por la factory de Uniswap
        t(IUniswapV3Factory(factory).getPool(token0, token1, fee) == pool,
          "RE-008: callback pool not verified by Uniswap V3 factory");
    }
  que_mirar:
    - "¿uniswapV3SwapCallback verifica que msg.sender es una pool legítima de Uniswap?"
    - "¿Se verifica la pool contra la Uniswap V3 Factory?"
    - "¿El callback puede ser llamado directamente por un atacante sin pasar por el swap?"
    - "¿El mismo patrón aplica a pancakeV3SwapCallback, algebraSwapCallback, etc.?"
  como_se_arregla: |
    - Siempre verificar: IUniswapV3Factory(factory).getPool(token0, token1, fee) == msg.sender
    - O: almacenar el expectedCallback address antes del swap y verificar en el callback
    - Nunca confiar en los datos del callback para determinar qué tokens enviar sin verificar el caller
  trampas:
    - "Pancake V3, Algebra, y otros forks de Uniswap V3 tienen el mismo callback — verificar contra su propia factory"
    - "El callback puede venir de una pool legítima pero con parámetros manipulados en `data` — el protocolo debe codificar los datos necesarios antes del swap"
  solodit_ids:
    - "h-uniswapv3swapcallback-missing-caller-verification-allows-theft-sherlock-git"
    - "m-callback-not-verified-against-factory-allows-malicious-pool-to-trigger-callback-code4rena-git"
