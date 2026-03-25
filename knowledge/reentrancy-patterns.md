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

- id: re-009
  titulo: ERC-777 tokensReceived/tokensToSend Hook Reentrancy — Transfer Hooks como Vector de Ataque
  causa_raiz: |
    ERC-777 tokens tienen hooks obligatorios: tokensToSend() se llama en el sender ANTES
    del transfer, y tokensReceived() se llama en el receiver DESPUÉS. Estos hooks son
    invisibles para el protocolo que simplemente llama transfer/transferFrom — el código
    parece un ERC-20 transfer normal pero ejecuta código arbitrario del atacante. Muchos
    protocolos asumen que transfer() es atómica y no tiene side effects.
  como_funciona: |
    Escenario (Inverse Finance $15.6M hack, abril 2022):
    1. Protocolo lending acepta token ERC-777 como colateral
    2. Atacante deposita colateral ERC-777 y pide prestado stablecoins
    3. Al hacer withdraw() del colateral, el protocolo llama transfer(atacante, colateral)
    4. tokensReceived() se dispara en el contrato del atacante DURANTE el transfer
    5. Dentro del hook: atacante re-entra en borrow() — la deuda ya se pagó pero el
       colateral aún no se descontó del balance interno → puede pedir prestado de nuevo
    6. Repite N veces en la misma tx → drena el pool

    Escenario Caviar (Code4rena finding):
    1. buy() function calcula precio, transfiere tokens ERC-777 al protocolo
    2. tokensToSend() se dispara en el comprador ANTES de que los tokens se muevan
    3. El comprador re-entra en buy() con el precio aún no actualizado → descuento masivo
  invariante: |
    // Verificar que el protocolo no es vulnerable a ERC-777 hooks
    function check_no_erc777_reentrancy() internal {
        uint256 balanceBefore = token.balanceOf(address(vault));
        // Si el token tiene hooks ERC-777, cualquier transfer puede re-entrar
        t(!ghost_inExternalCall,
          "RE-009: state accessed during ERC-777 hook — reentrancy vector");
    }
  que_mirar:
    - "¿El protocolo acepta tokens arbitrarios como colateral? ¿Puede alguien depositar un ERC-777?"
    - "¿transfer/transferFrom se llaman ANTES de actualizar el estado interno?"
    - "¿Hay una whitelist de tokens o se acepta cualquier ERC-20 (que podría ser ERC-777)?"
    - "¿Las funciones que transfieren tokens tienen nonReentrant?"
    - "¿El protocolo usa safeTransfer de OZ? (No protege contra ERC-777 hooks)"
  como_se_arregla: |
    - Añadir nonReentrant a TODAS las funciones que hacen transfer/transferFrom
    - CEI estricto: actualizar balance interno ANTES del transfer
    - Considerar whitelist de tokens si el protocolo no necesita soportar ERC-777
    - Verificar si el token implementa ERC-1820 registry (señal de ERC-777)
  trampas:
    - "Los ERC-777 son backward-compatible con ERC-20 — un token puede parecer ERC-20 pero tener hooks"
    - "USDT, USDC, DAI no son ERC-777 pero tokens como imBTC sí lo son"
    - "El hook tokensToSend() se ejecuta ANTES del transfer — incluso CEI puede no ser suficiente si el estado ya se leyó"
    - "Polygon zkEVM tuvo un bug crítico con ERC-777 en el bridge (Hexens audit)"
  solodit_ids:
    - "1-erc777-re-entrancy-attack-hexens-none-polygonzkevm-markdown"
    - "h-01-reentrancy-in-buy-function-for-erc777-tokens-allows-buying-funds-with-considerable-discount-code4rena-caviar-caviar-contest-git"
    - "m-04-erc777-reentrancy-when-withdrawing-can-be-used-to-withdraw-all-collateral-code4rena-inverse-finance-inverse-finance-contest-git"
    - "m-07-attacker-can-steal-rtoken-holders-funds-by-performing-reentrancy-attack-during-redeem-function-token-transfers-code4rena-reserve-reserve-contest-git"
  incidentes:
    - "Inverse Finance — $15.6M perdidos (abril 2022) — ERC-777 reentrancy en lending market"
    - "imBTC/Lendf.me — $25M perdidos (abril 2020) — ERC-777 tokensToSend hook en Compound fork"
  verificado: true
  confianza: 95

- id: re-010
  titulo: Read-Only Reentrancy en Balancer/Curve — Manipulación de Precios vía Estado Inconsistente
  causa_raiz: |
    Los pools de Balancer V2 y Curve exponen funciones view (getRate(), get_virtual_price())
    que calculan el precio del LP token basándose en balances internos. Durante una
    join/exit/swap, estos balances se actualizan ANTES de que el pool complete la operación.
    Un contrato externo que lea estos precios durante el callback ve un valor temporal
    inflado o deflado. El pool tiene nonReentrant en sus funciones de estado, pero las
    funciones view no están protegidas (son read-only).
  como_funciona: |
    Escenario Balancer (real, múltiples protocolos afectados):
    1. Atacante hace join al Balancer pool con mucho ETH
    2. Balancer actualiza los balances internos (totalSupply sube)
    3. Balancer transfiere tokens — en el callback (receive() por ETH):
       a. Los balances ya subieron pero los BPT tokens aún no se minted
       b. getRate() retorna un valor INFLADO (más ETH por BPT de lo real)
    4. Protocolo víctima (lending/staking) lee getRate() → acepta colateral sobre-valorado
    5. Atacante pide prestado más de lo que debería con colateral inflado
    6. El join completa, getRate() vuelve a la normalidad, atacante tiene deuda sub-colateralizada

    Escenario Curve (Vyper reentrancy, julio 2023):
    1. Bug en el compilador Vyper 0.2.15-0.3.0: el @nonreentrant decorator con el mismo
       key NO impedía reentrancy entre funciones con ese key
    2. remove_liquidity() y add_liquidity() compartían @nonreentrant("lock") pero el
       compilador generaba código que no verificaba el lock correctamente
    3. Atacante podía re-entrar desde remove_liquidity() a add_liquidity() → robar fondos
    4. $70M+ en riesgo, varios pools drenados (alETH, msETH, pETH)
  invariante: |
    function check_no_read_only_reentrancy_balancer(address balancerVault) internal view {
        // Balancer V2 expone un método para verificar el estado del reentrancy guard
        try IVault(balancerVault).manageUserBalance(new IVault.UserBalanceOp[](0)) {
            // Si no revierte, el vault no está en reentrancy
        } catch {
            // Si revierte con BAL#400 (REENTRANCY), estamos dentro de un callback
            revert("RE-010: reading Balancer state during reentrancy window");
        }
    }

    function check_no_read_only_reentrancy_curve(address curvePool) internal view {
        // Curve pools (post-fix) exponen withdraw_admin_fees() como check
        // Si el pool está en reentrancy, esta llamada revierte
        try ICurvePool(curvePool).withdraw_admin_fees() {} catch {}
    }
  que_mirar:
    - "¿El protocolo lee getRate(), get_virtual_price(), o totalSupply de Balancer/Curve dentro de un callback?"
    - "¿Se usa el precio del LP token como oracle para colateral sin verificar reentrancy?"
    - "¿El protocolo llama a estos precio durante un join/exit/swap callback?"
    - "¿Los pools de Curve usan Vyper 0.2.15-0.3.0? (vulnerable al bug del compilador)"
    - "¿Hay un check de reentrancy antes de leer el precio? (Balancer: manageUserBalance, Curve: withdraw_admin_fees)"
  como_se_arregla: |
    - Para Balancer: llamar IVault.manageUserBalance([]) antes de leer getRate() — revierte si en reentrancy
    - Para Curve: verificar la versión de Vyper del pool y si expone reentrancy check
    - No usar precios de AMM como oracle primario — usar Chainlink como fuente principal
    - Si se usa AMM price: cachear el precio en un bloque donde no hay callback activo
  trampas:
    - "El ataque no modifica el estado del protocolo víctima directamente — solo LEE un precio incorrecto"
    - "Las funciones view no pueden tener nonReentrant (no modifican estado)"
    - "Balancer V2 añadió ensureNotInVaultContext() como mitigación — verificar que se usa"
    - "El bug de Vyper fue del COMPILADOR, no del código — los pools tenían @nonreentrant correcto"
  solodit_ids:
    - "h-13-balancerpairoracle-can-be-manipulated-using-read-only-reentrancy-sherlock-none-blueberry-update-git"
    - "balancer-read-only-reentrancy-vulnerability-changes-from-dev-team-added-to-audit-spearbit-cron-finance-pdf"
    - "read-only-reentrancy-cyfrin-beanstalk-wells-markdown"
    - "m-03-read-only-reentrancy-is-possible-code4rena-angle-protocol-angle-protocol-invitational-git"
    - "m-3-read-only-reentrancy-in-bondfixedtermteller-sherlock-bond-bond-protocol-git"
  incidentes:
    - "Curve/Vyper reentrancy — $70M+ en riesgo, ~$50M drenados (julio 2023) — bug del compilador Vyper"
    - "Sturdy Finance — $800K drenados (junio 2023) — read-only reentrancy vía Balancer"
    - "Sentiment Protocol — $1M drenados (abril 2023) — read-only reentrancy vía Balancer getRate()"
  verificado: true
  confianza: 98

- id: re-011
  titulo: ERC-1155 Batch Callback Reentrancy — onERC1155Received y onERC1155BatchReceived
  causa_raiz: |
    ERC-1155 requiere callbacks tanto para transfers individuales (onERC1155Received)
    como para batch transfers (onERC1155BatchReceived). Los batch transfers son
    especialmente peligrosos porque el callback se ejecuta UNA VEZ después de
    múltiples cambios de estado — si el estado intermedio no es consistente, el
    callback puede explotarlo. Además, muchos protocolos implementan el check
    para onERC1155Received pero olvidan onERC1155BatchReceived (o viceversa).
  como_funciona: |
    Escenario Bridge Mutual (ConsenSys finding):
    1. Bridge permite depósitos de tokens ERC-1155 como colateral
    2. deposit() transfiere el ERC-1155 al bridge con safeTransferFrom
    3. onERC1155Received() se dispara en el receptor (el bridge es el receptor)
    4. Pero el bridge también permite que el depositor sea un contrato —
       y safeTransferFrom llama el callback en el RECEPTOR, no en el sender
    5. Si el bridge re-envía tokens a otro contrato como parte del depósito,
       ese contrato puede re-entrar antes de que el depósito se registre

    Escenario ParentFundingPool (0x52 finding):
    1. removeChildShares() envía ERC-1155 shares al child pool
    2. El transfer dispara onERC1155Received en el child pool
    3. Dentro del callback: child pool llama de vuelta al parent
    4. Parent aún no quemó los shares internamente → el child puede
       reclamar shares que ya se "removieron" → doble gasto
  invariante: |
    function check_erc1155_transfer_safe(uint256 tokenId, uint256 amount) internal {
        uint256 balBefore = erc1155.balanceOf(address(vault), tokenId);
        erc1155.safeTransferFrom(address(this), address(vault), tokenId, amount, "");
        uint256 balAfter = erc1155.balanceOf(address(vault), tokenId);
        t(balAfter == balBefore + amount,
          "RE-011: ERC-1155 balance inconsistent after safeTransferFrom — possible reentrancy");
    }
  que_mirar:
    - "¿El protocolo usa safeTransferFrom o safeBatchTransferFrom para ERC-1155?"
    - "¿El estado se actualiza ANTES o DESPUÉS del transfer?"
    - "¿Hay nonReentrant en funciones que hacen transfers ERC-1155?"
    - "¿Se implementa onERC1155BatchReceived además de onERC1155Received?"
    - "¿El protocolo permite depósitos de tokens ERC-1155 arbitrarios?"
  como_se_arregla: |
    - CEI: actualizar estado interno ANTES de llamar safeTransferFrom/safeBatchTransferFrom
    - Añadir nonReentrant a todas las funciones que transfieren ERC-1155
    - Implementar AMBOS callbacks (onERC1155Received y onERC1155BatchReceived) con checks
    - Considerar usar transferFrom sin "safe" si el receptor es conocido y de confianza
  trampas:
    - "safeBatchTransferFrom dispara UN callback después de TODOS los transfers — el estado puede ser parcialmente actualizado"
    - "El callback se llama en el RECEPTOR, no en el sender — el atacante debe controlar el receptor"
    - "Muchos protocolos heredan ERC1155Holder de OZ pero no protegen sus propias funciones contra reentrancy desde el callback"
  solodit_ids:
    - "re-entrancy-issue-for-erc1155-fixed-consensys-bridge-mutual-markdown"
    - "h-03-sending-child-shares-before-burning-shares-allow-reentrancy-vulnerability-in-parentfundingpoolremovechildshares-0x52-none-ubet-markdown"
    - "l-02-transferring-erc1155-tokens-before-applying-parent-return-ops-allowing-reentrancy-0x52-none-ubet-parlay-markdown"
    - "m-05-when-rewardtoken-is-erc1155erc777-an-attacker-can-reenter-and-cause-funds-to-be-stuck-in-the-contract-forever-code4rena-rabbithole-rabbithole-quest-protocol-contest-git"
  verificado: true
  confianza: 90

- id: re-012
  titulo: _safeMint Reentrancy — Callback onERC721Received Durante Mint Permite Doble-Claim
  causa_raiz: |
    ERC721._safeMint() llama internamente a onERC721Received() en el receptor DESPUÉS
    de crear el token pero ANTES de que la función que llamó _safeMint() termine.
    Si la función caller actualiza estado DESPUÉS de _safeMint(), el callback puede
    re-entrar y explotar el estado pre-actualización. Es una variante sutil del
    patrón re-004 pero específica al minting, donde el tokenId recién creado ya
    existe pero las contabilidades asociadas aún no se registraron.
  como_funciona: |
    Escenario XDEFI (Code4rena H-02, real):
    1. Protocolo staking: stake() → _safeMint(tokenId) → registra rewards para tokenId
    2. _safeMint llama onERC721Received en el contrato del atacante
    3. El tokenId YA EXISTE (fue minted) pero las rewards aún no se registraron
    4. Dentro del callback: atacante llama claimRewards(tokenId)
    5. claimRewards ve tokenId válido → calcula rewards (puede ser basado en totalSupply
       que ya incluye el nuevo token) → transfiere rewards
    6. La función stake() continúa y registra rewards = 0 para tokenId → rewards ya fueron robadas

    Escenario genérico (pack opening, AI Arena):
    1. openPack() mints un NFT con _safeMint → callback
    2. En el callback: atacante llama openPack() de nuevo
    3. El counter de "packs opened" aún no se incrementó → puede abrir más de lo permitido
  invariante: |
    uint256 internal ghost_totalMinted;

    function check_safemint_reentrancy() internal {
        uint256 supplyBefore = nft.totalSupply();
        // Verificar que no hubo mints inesperados durante un callback
        t(nft.totalSupply() == ghost_totalMinted,
          "RE-012: unexpected mint detected — possible _safeMint reentrancy");
    }
  que_mirar:
    - "¿El protocolo usa _safeMint en lugar de _mint? (safeMint tiene callback, _mint no)"
    - "¿El estado asociado al tokenId se actualiza DESPUÉS de _safeMint?"
    - "¿Las funciones de mint tienen nonReentrant?"
    - "¿Hay lógica de claim/reward que depende del tokenId inmediatamente después del mint?"
    - "¿Hay límites de mint que se verifican antes del mint pero se actualizan después?"
  como_se_arregla: |
    - Usar _mint() en lugar de _safeMint() si el receptor es conocido o es un EOA verificado
    - Si se usa _safeMint(): actualizar TODO el estado antes de llamarla (CEI estricto)
    - Añadir nonReentrant a la función que llama _safeMint()
    - Registrar rewards/estado ANTES del mint, no después
  trampas:
    - "_mint() no tiene callback — es segura contra reentrancy pero puede quemar NFTs si se envían a contratos que no saben recibirlos"
    - "El tokenId puede existir en el mapping de ownerOf antes de que el protocolo registre metadata/rewards para él"
    - "AI Arena perdió ~$2M por este patrón exacto — claimRewards reentrancy vía _safeMint"
  solodit_ids:
    - "h-02-the-reentrancy-vulnerability-in-_safemint-can-allow-an-attacker-to-steal-all-rewards-code4rena-xdefi-xdefi-contest-git"
    - "h-08-player-can-mint-more-fighter-nfts-during-claim-of-rewards-by-leveraging-reentrancy-on-the-claimrewards-function-code4rena-ai-arena-ai-arena-git"
    - "reentrancy-vulnerability-in-the-createreceivable-function-allowing-multiple-asset-minting-zokyo-none-isle-finance-markdown"
    - "reentrancy-of-fee-payment-can-be-used-to-circumvent-max-mints-per-wallet-check-spearbit-seadrop-pdf"
  incidentes:
    - "AI Arena — ~$2M en riesgo — _safeMint reentrancy permitía mint ilimitado de fighters"
  verificado: true
  confianza: 95

- id: re-013
  titulo: Reentrancy Guard Bypass — Evasión del Mutex por Caminos Alternativos
  causa_raiz: |
    Los reentrancy guards (nonReentrant modifier, locked flag) protegen solo el
    camino de ejecución que los activa. Si existe un camino alternativo para llegar
    a la misma lógica sin pasar por el guard, el atacante puede re-entrar sin
    que el lock lo bloquee. Esto incluye: ejecuteBatch en TimelockController,
    rageQuit con NFT callbacks, delegatecall desde módulos, y hooks de protocolos
    externos que invocan funciones sin el modifier.
  como_funciona: |
    Escenario PartyDAO (Code4rena M-06, real):
    1. rageQuit() tiene nonReentrant y transfiere NFTs de vuelta al usuario
    2. El usuario recibe tokens ERC-721/ERC-1155 que disparan callbacks
    3. En el callback: el usuario NO puede re-entrar a rageQuit() (mutex activo)
    4. PERO: el callback puede llamar a burn() que internamente llama _rageQuit()
       (la función interna sin el modifier) → bypass del nonReentrant

    Escenario Ethena TimelockController (Cyfrin finding):
    1. executeBatch() ejecuta múltiples operaciones secuencialmente
    2. La primera operación activa un nonReentrant en el contrato target
    3. La segunda operación en el MISMO batch puede llamar al mismo contrato
    4. PERO: el nonReentrant se reseteó entre operaciones del batch → re-entry

    Escenario Uniswap The Compact (Spearbit finding):
    1. deposit() usa un reentrancy lock basado en transient storage (EIP-1153)
    2. El lock se resetea al final de la transacción (TSTORE es per-tx)
    3. Si el callback del deposit ejecuta otra transacción interna que llama
       deposit() de nuevo, el lock de transient storage ya se reseteó → double-spend
  invariante: |
    function check_reentrancy_guard_coverage() internal view {
        // Verificar que TODAS las funciones sensibles comparten el mismo lock
        // y que no hay caminos alternativos que bypassen el guard
        t(vault.reentrancyLocked(),
          "RE-013: reentrancy guard not active during sensitive operation");
    }
  que_mirar:
    - "¿Hay funciones internas (_fn) que duplican lógica de funciones externas (fn) sin el modifier?"
    - "¿El protocolo usa executeBatch o multicall que ejecuta múltiples calls secuenciales?"
    - "¿Hay delegatecall desde módulos que puede invocar funciones sin pasar por el guard?"
    - "¿El reentrancy guard usa storage (persistente) o transient storage (per-tx, EIP-1153)?"
    - "¿Hooks de protocolos externos pueden invocar funciones sin el nonReentrant?"
  como_se_arregla: |
    - Auditar TODOS los caminos que llegan a lógica sensible — no solo los entry points públicos
    - Para batch/multicall: mantener el lock activo durante TODO el batch, no por operación
    - Para transient storage locks: verificar que el lock persiste dentro de la misma tx (TLOAD/TSTORE)
    - Para delegatecall: el lock está en el storage del caller, no del callee — verificar que aplica
  trampas:
    - "executeBatch de OZ TimelockController es un vector conocido — cada operación es independiente"
    - "Los guards de transient storage (EIP-1153) son más eficientes en gas pero tienen semántica diferente al storage"
    - "delegatecall comparte storage → el lock del caller aplica, pero solo si el callee LEE el mismo slot"
  solodit_ids:
    - "m-06-reentrancy-guard-in-ragequit-can-be-bypassed-code4rena-partydao-party-dao-invitational-git"
    - "re-entrancy-protection-can-be-evaded-via-timelockcontrollerexecutebatch-cyfrin-none-ethena-timelock-markdown"
    - "attacker-can-bypass-reentrancy-lock-to-double-spend-deposit-spearbit-none-uniswap-the-compact-pdf"
  verificado: true
  confianza: 92

- id: re-014
  titulo: Transient Storage (EIP-1153) Reentrancy — Implicaciones de TSTORE/TLOAD en Guards
  causa_raiz: |
    EIP-1153 introduce TSTORE/TLOAD para almacenamiento temporal que se limpia al final
    de cada transacción. Los reentrancy guards basados en transient storage son más baratos
    en gas (~100 gas vs ~5000 para SSTORE), pero tienen implicaciones de seguridad
    diferentes. El principal riesgo: si un protocolo usa hooks que crean nuevas "frames"
    de ejecución o si la semántica del lock cambia entre llamadas internas, el guard
    puede no comportarse como se espera.
  como_funciona: |
    Escenario BunniHub (Cyfrin finding, real):
    1. BunniHub usa reentrancy guard basado en transient storage
    2. Un pool malicioso tiene un hook que ejecuta código arbitrario
    3. El hook llama a BunniHub.deposit() para un pool DIFERENTE (legítimo)
    4. El reentrancy guard bloquea re-entry al MISMO pool pero NO a pools diferentes
    5. El hook manipula los balances del pool legítimo durante la ejecución del pool malicioso
    6. Resultado: drain de todos los balances y reservas del pool legítimo

    Escenario genérico — TSTORE vs SSTORE:
    1. Guard con SSTORE: locked = true persiste entre llamadas, subcalls, y delegatecalls
    2. Guard con TSTORE: locked = true persiste SOLO durante la transacción actual
    3. Si un callback crea un CREATE o STATICCALL que resulta en una nueva tx → TSTORE se limpia
    4. En la práctica: dentro de una misma tx, TSTORE funciona igual que SSTORE
    5. El riesgo real: guards per-key (por pool, por token) que solo protegen UN recurso
  invariante: |
    function check_transient_guard_per_resource() internal {
        // Verificar que el reentrancy guard protege TODOS los recursos, no solo uno
        // Un guard per-pool puede permitir reentrancy cross-pool
        t(hub.globalReentrancyLocked(),
          "RE-014: transient reentrancy guard does not protect cross-resource reentrancy");
    }
  que_mirar:
    - "¿El protocolo usa transient storage (EIP-1153) para reentrancy guards?"
    - "¿El guard es global (todas las funciones) o per-resource (per-pool, per-token)?"
    - "¿Hay hooks que permiten código arbitrario de terceros durante una operación?"
    - "¿Un callback desde un recurso A puede afectar el estado de un recurso B sin activar el guard de B?"
    - "¿El guard de transient storage se hereda correctamente en delegatecalls?"
  como_se_arregla: |
    - Para guards per-resource: añadir un guard GLOBAL adicional que bloquee toda la operación
    - Verificar que hooks no pueden interactuar con otros recursos del mismo protocolo
    - No confiar en que el hook de un pool es benigno — tratar TODOS los hooks como maliciosos
    - Considerar un guard híbrido: SSTORE para el global, TSTORE para per-resource (gas optimization)
  trampas:
    - "TSTORE es per-transaction, no per-call — dentro de la misma tx funciona como SSTORE"
    - "El riesgo NO es que TSTORE se limpie prematuramente — es que el guard sea demasiado granular"
    - "Uniswap V4 usa transient storage para locks — su modelo es 'lock the entire protocol' que es seguro"
    - "BunniHub usaba lock per-pool — esto permitió reentrancy cross-pool que drenó pools legítimos"
  solodit_ids:
    - "pools-configured-with-a-malicious-hook-can-bypass-the-bunnihub-re-entrancy-guard-to-drain-all-raw-balances-and-vault-reserves-of-legitimate-pools-cyfrin-none-bunni-markdown"
    - "attacker-can-bypass-reentrancy-lock-to-double-spend-deposit-spearbit-none-uniswap-the-compact-pdf"
  verificado: true
  confianza: 90

- id: re-015
  titulo: Governance/Voting Reentrancy — Re-entry Durante ragequit, vote, o proposal Execution
  causa_raiz: |
    Los contratos de governance (DAOs, voting modules) transfieren tokens/NFTs como
    parte de operaciones de voto, ragequit, o ejecución de proposals. Estas transferencias
    disparan callbacks que pueden re-entrar en el sistema de governance con el estado
    de votación inconsistente. Especialmente peligroso cuando: (a) el voting power
    depende del balance de tokens que se están transfiriendo, (b) la ejecución de
    proposals tiene side-effects que afectan el voting power.
  como_funciona: |
    Escenario VoteModule bypass (Spearbit/EthereX, real):
    1. Usuario stakea tokens para obtener voting power con unlockTime = 90 días
    2. vote() transfiere rewards/fees al voter como incentivo
    3. En el callback de la transferencia: usuario llama withdraw()
    4. withdraw() verifica unlockTime — pero el estado del lock se actualizó
       durante el callback con el timestamp del voto (más reciente)
    5. Resultado: bypass del unlockTime → retiro inmediato de stake

    Escenario The DAO (junio 2016, $60M):
    1. splitDAO() — función para salir de la DAO con tu share de ETH
    2. splitDAO transfiere ETH al usuario → callback receive()
    3. Dentro de receive(): usuario llama splitDAO() de nuevo
    4. Su balance de DAO tokens aún no se redujo → extrae ETH múltiples veces
    5. Primera demostración pública de reentrancy → Ethereum fork (ETH/ETC split)
  invariante: |
    function check_voting_power_consistency() internal view {
        uint256 totalVotes = governance.totalVotingPower();
        uint256 totalStaked = token.totalSupply();
        // El total voting power no debe exceder el total de tokens staked
        t(totalVotes <= totalStaked,
          "RE-015: voting power exceeds total staked — possible governance reentrancy");
    }
  que_mirar:
    - "¿Las funciones de governance (vote, propose, execute, ragequit) transfieren tokens con callbacks?"
    - "¿El voting power se recalcula durante o después de la transferencia?"
    - "¿Los proposals pueden ejecutar código arbitrario que re-entre en el governance contract?"
    - "¿Hay un lock period que se verifica ANTES de una transferencia pero se actualiza DESPUÉS?"
    - "¿execute() de proposals tiene nonReentrant?"
  como_se_arregla: |
    - nonReentrant en TODAS las funciones de governance (vote, propose, execute, ragequit, withdraw)
    - Actualizar voting power ANTES de transferir tokens
    - Para execute(): usar un flag de "executing" que bloquee cambios en el governance state
    - Separar el claim de rewards del acto de votar (pull pattern)
  trampas:
    - "The DAO hack ($60M, 2016) fue el primer exploit público de reentrancy — y fue en governance"
    - "Las DAOs modernas usan snapshot voting (off-chain) que es inmune a este ataque"
    - "Pero las DAOs on-chain (Compound Governor, OZ Governor) siguen siendo vulnerables si customize execute()"
    - "Los NFT-based governance (vote with NFT) tienen doble riesgo: ERC721 callback + voting power"
  solodit_ids:
    - "its-possible-to-withdraw-from-votemodule-bypassing-unlocktime-spearbit-none-etherex-contracts-pdf"
    - "m-06-reentrancy-guard-in-ragequit-can-be-bypassed-code4rena-partydao-party-dao-invitational-git"
  incidentes:
    - "The DAO — $60M perdidos (junio 2016) — reentrancy en splitDAO() vía receive() callback"
    - "Beanstalk — $182M flash loan governance attack (abril 2022) — no reentrancy pero relacionado"
  verificado: true
  confianza: 88

- id: re-016
  titulo: Flash Loan + Reentrancy Combo — Amplificación de Impacto con Capital Prestado
  causa_raiz: |
    Los flash loans permiten pedir prestado cantidades masivas sin colateral. Cuando
    se combinan con reentrancy, el atacante amplifica el impacto: en lugar de
    re-entrar con su propio balance (limitado), re-entra con millones prestados.
    El callback del flash loan (executeOperation, uniswapV2Call) es el vector
    de reentrancy — y el capital prestado manipula precios, infla shares, o
    drena pools. La combinación flash loan + reentrancy es responsable de
    la mayoría de los exploits >$10M.
  como_funciona: |
    Escenario Arcadia (Sherlock H-2, real):
    1. Atacante toma flash loan de $10M en USDC de Aave
    2. Deposita los $10M en Arcadia vault → recibe shares
    3. Arcadia vault llama flashAction() que permite ejecutar acciones en un callback
    4. En el callback executeOperation(): atacante deposita MÁS tokens en el vault
    5. Las shares del paso 2 aún no se contabilizaron → el precio por share está inflado
    6. Atacante retira con shares sobre-valoradas → drena el vault
    7. Repaga el flash loan y se queda con el diferencial

    Escenario genérico (first-depositor + reentrancy):
    1. Flash loan → depósito masivo → infla share price → callback
    2. En callback: víctima deposita con precio inflado → recibe pocas shares
    3. Atacante retira con shares correctas → steal la diferencia
    4. Todo en una tx → flash loan repagado → profit
  invariante: |
    bool internal ghost_inFlashLoan;
    uint256 internal ghost_flashLoanAmount;

    function check_no_flash_loan_amplified_reentrancy() internal view {
        if (ghost_inFlashLoan) {
            // Durante un flash loan, las operaciones de deposit/withdraw deben estar bloqueadas
            t(false, "RE-016: deposit/withdraw called during flash loan callback");
        }
    }
  que_mirar:
    - "¿El protocolo ofrece flash loans O interactúa con protocolos que los ofrecen?"
    - "¿El callback del flash loan puede llamar a funciones de deposit/withdraw del protocolo?"
    - "¿El precio de shares se calcula usando balances que incluyen el flash loan?"
    - "¿Hay protección contra first-depositor attack que podría amplificarse con flash loan?"
    - "¿Las funciones críticas verifican si hay un flash loan en progreso?"
  como_se_arregla: |
    - Bloquear deposit/withdraw durante callbacks de flash loan propios
    - No calcular precios basados en balance actual del contrato (puede incluir flash loan temporal)
    - Usar TWAP o Chainlink para precios — inmunes a flash loans
    - Implementar delay de 1 bloque entre deposit y withdraw (anti-sandwich)
    - Para protocolos que ofrecen flash loans: flag inFlashLoan que bloquee funciones sensibles
  trampas:
    - "El flash loan amplifica CUALQUIER vulnerabilidad de reentrancy — convierte un Low en un Critical"
    - "Aave V3 cobra 0.05% fee — pero $10M * 0.05% = $5K, nada comparado con $1M de profit"
    - "dYdX flash loans son GRATIS — ideal para atacantes"
    - "El callback executeOperation() recibe los fondos ANTES de que se espere el repago — ventana de ataque"
  solodit_ids:
    - "h-2-reentrancy-in-flashaction-allows-draining-liquidity-pools-sherlock-arcadia-git"
    - "h-01-reentrancy-in-buy-function-for-erc777-tokens-allows-buying-funds-with-considerable-discount-code4rena-caviar-caviar-contest-git"
  incidentes:
    - "Cream Finance — $130M drenados (octubre 2021) — flash loan + reentrancy + price manipulation"
    - "Pancake Bunny — $45M (mayo 2021) — flash loan + price manipulation (no reentrancy directa)"
    - "Arcadia — draining liquidity pools via flashAction reentrancy (Sherlock finding)"
  verificado: true
  confianza: 93

- id: re-017
  titulo: Reentrancy en Fee-on-Transfer y Rebasing Tokens — Balances Inesperados como Vector
  causa_raiz: |
    Los tokens con fee-on-transfer (e.g., USDT con fee activado, STA, PAXG) o rebasing
    (e.g., stETH, aTokens de Aave, AMPL) cambian el balance del receptor de formas
    inesperadas. Si el protocolo asume que transfer(100) resulta en +100 en el balance
    del receptor, el balance real puede ser diferente. Esto crea ventanas donde el
    estado interno y el balance real divergen — y si hay un callback en ese momento
    (ERC-777, ERC-1155, o receive()), el atacante explota la divergencia.
  como_funciona: |
    Escenario fee-on-transfer + reentrancy:
    1. Protocolo tiene: depositFor(user, amount) que llama token.transferFrom(user, vault, amount)
    2. El token cobra 1% fee → vault recibe 99, pero el protocolo registra 100
    3. Si el token tiene hooks (ERC-777 compatible), el callback ve:
       - Estado interno: user depositó 100
       - Balance real: vault tiene 99
    4. El callback re-entra en withdraw(100) → el protocolo envía 100 (tiene de otros usuarios)
    5. Vault queda con -1 de déficit → insolvencia gradual

    Escenario rebasing + read-only reentrancy:
    1. stETH (Lido) hace rebase diario — todos los balances cambian
    2. Protocolo lee balance de stETH como colateral
    3. Si el rebase ocurre DURANTE una tx que tiene callbacks:
       a. Balance pre-rebase ≠ balance post-rebase
       b. El colateral calculado es incorrecto temporalmente
  invariante: |
    function check_actual_transfer_amount(address token, uint256 intended) internal {
        uint256 balBefore = IERC20(token).balanceOf(address(vault));
        IERC20(token).transferFrom(msg.sender, address(vault), intended);
        uint256 received = IERC20(token).balanceOf(address(vault)) - balBefore;
        // El protocolo DEBE registrar `received`, no `intended`
        t(vault.internalBalance(token) == received,
          "RE-017: internal balance != actual received — fee-on-transfer/rebasing token issue");
    }
  que_mirar:
    - "¿El protocolo registra el amount del parámetro o mide el balance real antes/después del transfer?"
    - "¿Se acepta USDT (puede tener fee activada por governance), stETH, AMPL, o tokens desconocidos?"
    - "¿Hay callbacks durante transfers de tokens que cobran fee?"
    - "¿El protocolo usa wstETH (wrapped, no rebasing) o stETH directamente (rebasing)?"
    - "¿Las funciones de liquidación calculan correctamente el colateral con tokens rebasing?"
  como_se_arregla: |
    - Siempre medir el balance real: balanceAfter - balanceBefore = amount received
    - No registrar el amount del parámetro como depósito — medir delta real
    - Para rebasing tokens: usar wrappers (wstETH, waUSDC) que convierten a balance fijo
    - Documentar explícitamente qué tokens soporta el protocolo y NO soportar tokens fee-on-transfer sin manejo especial
  trampas:
    - "USDT tiene un mecanismo de fee que actualmente está en 0% — pero puede activarse por governance de Tether"
    - "stETH rebase cambia balances de TODOS los holders en el mismo bloque — puede afectar múltiples protocolos simultáneamente"
    - "AMPL rebasa TODO el supply — un balance puede subir o bajar sin que nadie llame transfer"
    - "Los fee-on-transfer tokens son raros pero muchos bounties los listan en scope"
  solodit_ids:
    - "m-05-when-rewardtoken-is-erc1155erc777-an-attacker-can-reenter-and-cause-funds-to-be-stuck-in-the-contract-forever-code4rena-rabbithole-rabbithole-quest-protocol-contest-git"
    - "unsafe-external-calls-made-during-proportional-lp-fee-transfers-can-be-used-to-reenter-wrapper-contracts-cyfrin-none-vii-markdown"
  verificado: true
  confianza: 85

- id: re-018
  titulo: Cross-Contract Reentrancy vía Hooks de Protocolo — Uniswap V4, Balancer, Hooks Arbitrarios
  causa_raiz: |
    Los protocolos modernos (Uniswap V4, Balancer V3) permiten hooks personalizados que
    se ejecutan durante operaciones del pool (beforeSwap, afterSwap, beforeAddLiquidity, etc.).
    Estos hooks son contratos de terceros que ejecutan código ARBITRARIO durante la
    operación del pool. Si el hook llama de vuelta al protocolo o a contratos que
    interactúan con el pool, se crea un vector de reentrancy cross-contract que el
    pool operator puede no anticipar.
  como_funciona: |
    Escenario Uniswap V4 hooks:
    1. Pool A tiene un hook malicioso configurado por el pool deployer
    2. Usuario swapea en Pool A → beforeSwap() hook se ejecuta
    3. El hook llama a otro contrato que interactúa con Pool A o Pool B
    4. Si Pool B comparte estado con Pool A (e.g., mismo token, mismo router),
       el hook puede manipular estado compartido
    5. afterSwap() hook se ejecuta con estado ya manipulado

    Escenario BunniHub cross-pool (Cyfrin finding, real):
    1. BunniHub gestiona múltiples pools con hooks configurables
    2. El reentrancy guard es PER-POOL (no global)
    3. Hook del Pool A (malicioso) llama a BunniHub.deposit() para Pool B (legítimo)
    4. El guard de Pool A está activo, pero Pool B no está protegido
    5. El hook manipula los balances de Pool B → drain de reservas legítimas
    6. Fix: hacer el reentrancy guard GLOBAL, no per-pool
  invariante: |
    function check_hook_reentrancy(address pool, address hook) internal view {
        // Verificar que el hook no está re-entrando al protocolo
        t(!IProtocol(protocol).isOperationInProgress(),
          "RE-018: hook attempting to reenter protocol during operation");
        // Verificar que el hook no interactúa con otros pools del mismo protocolo
        t(!IProtocol(protocol).isAnyPoolLocked(),
          "RE-018: hook interacting with another pool during operation");
    }
  que_mirar:
    - "¿El protocolo permite hooks de terceros? ¿Qué funciones puede llamar el hook?"
    - "¿El reentrancy guard es global o per-resource (per-pool, per-token)?"
    - "¿Los hooks pueden interactuar con OTROS pools/vaults del mismo protocolo?"
    - "¿beforeX y afterX hooks comparten el mismo lock?"
    - "¿El protocolo asume que los hooks son benignos? (NUNCA asumirlo)"
    - "¿Los hooks tienen acceso a balances internos o solo a parámetros del swap/deposit?"
  como_se_arregla: |
    - Guard GLOBAL que bloquee todo el protocolo durante una operación (no per-pool)
    - Limitar las operaciones que un hook puede ejecutar (no permitir deposit/withdraw en otros pools)
    - Ejecutar hooks en un contexto restringido (no darles acceso a llamar al protocolo de vuelta)
    - Documentar explícitamente qué puede y qué no puede hacer un hook
    - Considerar un allowlist de hooks auditados
  trampas:
    - "Uniswap V4 mitiga esto con su singleton design — todos los pools comparten un lock global"
    - "Los hooks de terceros son el vector más nuevo y menos audited de reentrancy cross-contract"
    - "Un hook malicioso puede parecer benigno en aislamiento pero ser devastador en combinación con otro pool"
    - "Los protocolos que permiten hooks arbitrarios DEBEN tratar cada hook como potencialmente malicioso"
  solodit_ids:
    - "pools-configured-with-a-malicious-hook-can-bypass-the-bunnihub-re-entrancy-guard-to-drain-all-raw-balances-and-vault-reserves-of-legitimate-pools-cyfrin-none-bunni-markdown"
    - "vlts3-14-read-only-reentrancy-in-withdraw-can-lead-to-swap-fee-manipulation-hexens-none-valantis-markdown"
    - "m-6-malicious-adapters-can-exploit-message-batching-via-adapter-side-reentrancy-to-cause-message-loss-for-any-other-pool-sherlock-centrifuge-protocol-v3-audit-git"
  verificado: true
  confianza: 92
