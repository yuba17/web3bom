grep_targets:
  - "SafeERC20"
  - "safeTransfer"
  - "safeTransferFrom"
  - "safeApprove"
  - "forceApprove"
  - ".transfer("
  - ".transferFrom("
  - ".approve("
  - "balanceOf"
  - "decimals()"
  - "IERC20"
  - "ERC20"
  - "tokensReceived"
  - "tokensToSend"
  - "IERC777"
  - "permit("
  - "DOMAIN_SEPARATOR"
  - "nonces("
  - "ERC2612"
  - "allowance"
  - "increaseAllowance"
  - "decreaseAllowance"
  - "type(uint256).max"
  - "1e18"
  - "10**18"
  - "10**decimals"
  - "flashLoan"
  - "flashMint"

# Briefing: Weird ERC-20 Token Patterns

## Contexto del dominio
Los tokens ERC-20 "estándar" siguen la interfaz definida en EIP-20, pero en la práctica
decenas de tokens populares se desvían del estándar de formas que rompen asunciones comunes
de los protocolos DeFi. Estas desviaciones son la fuente #1 de bugs de integración en auditorías.

El problema fundamental: los protocolos asumen que TODOS los tokens se comportan como el
ERC-20 de OpenZeppelin. Pero tokens con billones de dólares de capitalización (USDT, USDC,
stETH, AMPL, cUSDCv3) violan estas asunciones de formas críticas.

Referencia canónica: Trail of Bits "Weird ERC-20 Tokens" (https://github.com/d-xo/weird-erc20)
documenta 20+ desviaciones. Este briefing mapea cada una a patrones de ataque concretos.

### Categorías de desviación:
1. **Transfer semantics** — return values, fees, rebasing, self-transfer, zero-amount
2. **Approval semantics** — race conditions, permit front-running, approve-to-zero requirement
3. **Callback hooks** — ERC-777 tokensReceived/tokensToSend, gas limits
4. **Address/proxy** — double-entry points, upgradeable, pausable, blacklistable
5. **Supply mechanics** — flash-mintable, deflationary, inflationary
6. **Type/precision** — non-standard decimals, non-bool returns

---

patterns:

- id: we-001
  titulo: Missing Return Value (USDT-style) — transfer/approve No Retornan bool
  causa_raiz: |
    El estándar EIP-20 especifica que transfer() y approve() deben retornar bool.
    Sin embargo, USDT (Tether) en Ethereum no retorna nada en transfer() ni approve().
    BNB y otros tokens tampoco. Si el protocolo hace `require(token.transfer(...))` con
    una interfaz que espera `bool`, la llamada revierte porque el ABI decoder espera
    datos de retorno que no existen. Con Solidity >=0.8, esto causa un revert silencioso.
  como_funciona: |
    1. Protocolo define interfaz: `function transfer(address, uint256) external returns (bool)`
    2. Protocolo llama: `require(IERC20(usdt).transfer(user, amount))`
    3. USDT.transfer() ejecuta la transferencia exitosamente pero no retorna nada
    4. El ABI decoder de Solidity espera 32 bytes de retorno (bool), recibe 0 bytes
    5. La transacción revierte — el usuario no puede retirar sus fondos
    6. Resultado: fondos permanentemente bloqueados en el contrato
  invariante: |
    // Verificar que todas las transferencias usan SafeERC20
    // No hay invariante de fuzzing — es un patrón estático detectable por grep
    // Pseudo-assertion para test:
    function check_transfer_uses_safe(address token, address to, uint256 amount) internal {
        uint256 balBefore = IERC20(token).balanceOf(to);
        // Si esto revierte con USDT, el protocolo es vulnerable
        IERC20(token).safeTransfer(to, amount);
        uint256 balAfter = IERC20(token).balanceOf(to);
        t(balAfter >= balBefore, "WE-001: safeTransfer must not silently fail");
    }
  que_mirar:
    - "Buscar .transfer( y .transferFrom( sin SafeERC20 — TODAS las instancias"
    - "Buscar .approve( sin SafeERC20 — USDT approve también carece de return"
    - "Verificar que SafeERC20 está imported Y se usa con `using SafeERC20 for IERC20`"
    - "Interfaces custom que definen transfer con returns (bool) — pueden ocultar el problema"
    - "Contratos que usan IERC20 de OZ pero llaman .transfer() directamente sin safe wrapper"
  como_se_arregla: |
    Usar OpenZeppelin SafeERC20 para TODAS las interacciones con tokens:
    ```solidity
    using SafeERC20 for IERC20;
    token.safeTransfer(to, amount);
    token.safeTransferFrom(from, to, amount);
    token.safeApprove(spender, amount); // deprecated, usar forceApprove
    token.forceApprove(spender, amount); // OZ 5.x
    ```
    SafeERC20 usa `abi.encodeCall` + low-level call y verifica:
    - Si hay return data, debe decodificar a `true`
    - Si no hay return data (USDT), la llamada fue exitosa (no revert)
  trampas:
    - "Si el protocolo SOLO soporta tokens con whitelist y USDT no está en la lista, es informational"
    - "Solidity >=0.8 con interfaces que esperan bool SIEMPRE revertirá con USDT — no es un 'maybe'"
    - "No confundir con tokens que retornan false en vez de revertir — ese es un problema distinto (we-018)"
    - "SafeERC20 de OZ v3 vs v4 vs v5 tiene diferencias — verificar la versión"
  solodit_ids:
    - "transfertransferfrom-are-used-instead-of-their-counterparts-from-safeerc20-zokyo-none-tradable-markdown"
    - "m-02-erc20-return-values-not-checked-code4rena-yaxis-yaxis-contest-git"
    - "m-04-erc20-transfer-not-all-tokens-return-boolean-kann-none-wild-protocol-markdown"
    - "unhandled-return-value-of-erc20-transfer-in-transfer-and-withdraw-functions-quantstamp-fdusd-on-eth-blockchain-markdown"
    - "lack-of-return-value-validation-in-erc20-transfer-zokyo-none-repl-markdown"
    - "m-01-unchecked-approve-return-causes-permanent-fund-loss-in-udasol-code4rena-garden-garden-git"
  incidentes:
    - "USDT (Tether) — Innumerables protocolos DeFi rotos por no usar SafeERC20 (2019-presente)"
    - "TransitSwap — $21M robados (Oct 2022), explotando transferFrom sin validación de retorno"
    - "Reality Cards — Fondos permanentemente bloqueados por unchecked ERC20 transfers (High)"
    - "Amun — Estado actualizado sin transferencia real por return value no verificado (Medium)"
    - "Sense WstETHAdapter — wrapUnderlying return value ignorado causa monto cero downstream (High)"
  verificado: true
  confianza: alta

- id: we-002
  titulo: Fee-on-Transfer Tokens — Monto Recibido < Monto Enviado
  causa_raiz: |
    Algunos tokens cobran una comisión en cada transferencia (SafeMoon, PAXG, STA, tokens
    con reflection). Si un protocolo asume que `transferFrom(user, contract, 100)` deposita
    exactamente 100 tokens, la contabilidad interna diverge de la realidad. Tras N operaciones,
    el protocolo se vuelve insolvente — los últimos usuarios no pueden retirar.
  como_funciona: |
    1. Token cobra 3% fee en cada transfer
    2. Usuario deposita 1000 tokens → protocolo registra deposit = 1000
    3. Realmente recibe 970 tokens (30 de fee)
    4. Contabilidad interna: 1000. Balance real: 970. Drift: 30
    5. Repetir con 100 usuarios → drift acumulado = 3000 tokens
    6. Últimos usuarios intentan withdraw → revert por insufficient balance
    7. Protocolo insolvente: debe 100,000 pero solo tiene 97,000
  invariante: |
    // CRITICAL: medir balance antes/después, no confiar en el amount
    function check_fee_on_transfer(address token, address from, uint256 amount) internal {
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(from, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;
        // Si received < amount, hay fee-on-transfer
        // El protocolo DEBE usar `received` para contabilidad, no `amount`
        t(ghost_internalBalance[token] <= IERC20(token).balanceOf(address(this)),
          "WE-002: internal accounting exceeds real balance — FoT token drift");
    }
  que_mirar:
    - "¿El protocolo mide balanceOf antes/después de transferFrom, o confía en el amount?"
    - "Buscar: `token.transferFrom(user, address(this), amount)` seguido de contabilidad usando `amount`"
    - "Patrón correcto: `uint256 before = token.balanceOf(address(this)); transferFrom(...); uint256 received = token.balanceOf(address(this)) - before;`"
    - "¿Hay whitelist de tokens? Si sí, ¿excluye explícitamente FoT tokens?"
    - "Vaults ERC-4626: deposit(assets) que usa `assets` en vez de medir received"
  como_se_arregla: |
    Siempre medir balance antes/después:
    ```solidity
    uint256 balanceBefore = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 actualReceived = token.balanceOf(address(this)) - balanceBefore;
    // Usar actualReceived para toda la contabilidad interna
    ```
    O documentar explícitamente que FoT tokens no son soportados y validar en whitelist.
  trampas:
    - "Si el protocolo documenta 'no fee-on-transfer tokens supported', es informational máximo"
    - "Algunos tokens tienen fee configurable — puede ser 0% hoy y 5% mañana (e.g., USDT tiene fee mechanism dormido)"
    - "El patrón balance-before/after tiene su propia vulnerabilidad: donation attack (alguien envía tokens al contrato entre las dos lecturas)"
    - "Algunos jueces consideran esto QA si hay whitelist. Verificar rules del contest"
  solodit_ids:
    - "fee-on-transfer-tokens-will-cause-users-to-lose-funds-codehawks-beedle-oracle-free-perpetual-lending-git"
    - "m-8-complete-debt-size-is-not-paid-off-for-fee-on-transfer-tokens-but-users-arent-warned-sherlock-blueberry-blueberry-git"
    - "m-01-fee-on-transfer-tokens-will-not-behave-as-expected-code4rena-numoen-numoen-contest-git"
    - "m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git"
  incidentes:
    - "Beedle — FoT tokens causan insolvencia en deposit/withdraw accounting (High, Codehawks)"
    - "Blueberry — type(uint256).max repayment falla silenciosamente para FoT tokens (Medium, Sherlock)"
    - "Numoen — FoT tokens causan revert en mint() por strict balance check (Medium, Code4rena)"
    - "SIZE — Incompatibilidad con FoT/deflationary/rebasing en base y quote tokens (Medium, Code4rena)"
    - "Harpie — FoT tokens causan insolvencia del Vault, usuarios tardíos no pueden retirar (Medium)"
    - "Allo V2 — Tokens que transfieren menos que amount rompen distribución de grants (Medium)"
    - "SafeMoon — Múltiples protocolos que integraron SafeMoon sin medir received (2021-2022)"
  verificado: true
  confianza: alta

- id: we-003
  titulo: Rebasing Tokens (stETH, AMPL, OHM) — Balance Cambia Sin Transfer
  causa_raiz: |
    Los tokens rebasing cambian el balanceOf() de todos los holders sin emitir Transfer events
    ni requerir transacciones. stETH hace rebase diario positivo (rewards), AMPL hace rebase
    positivo/negativo según su target price, OHM rebasa en cada epoch. Si un protocolo cachea
    balances en storage o usa contabilidad interna basada en amounts, la divergencia con el
    balance real causa pérdida de fondos.
  como_funciona: |
    Escenario stETH positivo:
    1. Usuario deposita 100 stETH → protocolo registra deposit = 100
    2. Rebase positivo: balance real sube a 105 stETH
    3. Usuario retira 100 stETH → protocolo envía 100
    4. 5 stETH de yield quedan atrapados en el contrato (nadie puede reclamarlos)
    5. Si muchos usuarios, el yield atrapado se acumula → pérdida significativa

    Escenario AMPL negativo:
    1. Usuario deposita 100 AMPL → protocolo registra deposit = 100
    2. Rebase negativo: balance real baja a 80 AMPL
    3. Usuario retira 100 AMPL → revert (solo hay 80)
    4. O peor: si hay múltiples usuarios, el primero retira 100 de los 80, dejando 0
    5. Todos los demás usuarios pierden sus fondos
  invariante: |
    // Para protocolos que soportan rebasing tokens:
    function check_rebasing_accounting() internal {
        uint256 realBalance = IERC20(rebasingToken).balanceOf(address(vault));
        uint256 internalTotal = vault.totalInternalBalance();
        // Con rebasing tokens, internal accounting DEBE sincronizarse con realBalance
        // Tolerancia: 1 wei por operación (rounding)
        t(realBalance + 1e6 >= internalTotal,
          "WE-003: internal accounting exceeds real balance after rebase");
    }
  que_mirar:
    - "¿El protocolo cachea token.balanceOf() en storage y lo reutiliza entre transacciones?"
    - "¿Usa wrapped versions (wstETH en vez de stETH)? wstETH NO rebasa"
    - "¿Tiene sync() o skim() para reconciliar diferencias post-rebase?"
    - "¿La contabilidad es share-based (como ERC-4626) o amount-based?"
    - "Buscar: mapping(address => uint256) deposits — si almacena amounts, vulnerable"
  como_se_arregla: |
    Opción 1 (recomendada): Usar wrapped non-rebasing versions (wstETH, no stETH).
    Opción 2: Usar contabilidad basada en shares, no en amounts.
    Opción 3: Implementar sync() que reconcilie contabilidad con balanceOf real.
    Opción 4: Documentar que rebasing tokens no son soportados y validar en whitelist.
  trampas:
    - "wstETH NO es rebasing — solo stETH raw rebasa. No reportar wstETH como rebasing"
    - "Si el protocolo usa share-based accounting (ERC-4626 style), puede ser seguro"
    - "Uniswap V2 usa skim() para esto — si el protocolo tiene mecanismo similar, verificar que funcione"
    - "Aave aTokens rebasan positivamente — verificar si el protocolo maneja esto"
    - "Si solo soportan tokens whitelisteados y ninguno es rebasing, es informational"
  solodit_ids:
    - "h-05-making-_totalsupply-and-_totalshares-imbalance-significantly-by-providing-fake-income-leads-to-stealing-fund-code4rena-lybra-finance-lybra-finance-git"
    - "m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git"
  incidentes:
    - "Lybra Finance — Manipulación de _totalSupply/_totalShares por rebase fake income, robo de fondos (High, Code4rena)"
    - "stETH/Curve — $100M+ de desvinculación parcial por asunciones incorrectas sobre rebasing (Jun 2022)"
    - "AMPL/Aave — AMPL listado y luego des-listado de Aave por incompatibilidad con rebasing negativo"
    - "Olympus DAO — Múltiples issues con OHM rebasing en protocolos que lo integraron (2021-2022)"
    - "SIZE — Incompatibilidad con rebasing tokens en base y quote tokens (Medium, Code4rena)"
  verificado: true
  confianza: alta

- id: we-004
  titulo: ERC-777 Hooks Reentrancy — tokensReceived/tokensToSend como Vector de Reentrada
  causa_raiz: |
    ERC-777 tokens implementan hooks obligatorios: tokensToSend() se llama en el sender
    ANTES de la transferencia, y tokensReceived() se llama en el receiver DESPUÉS.
    Si un contrato interactúa con un token ERC-777 sin protección de reentrancy, el
    atacante registra un hook en el ERC-1820 Registry y usa el callback para re-entrar
    al contrato con estado inconsistente.
  como_funciona: |
    1. Atacante registra contrato malicioso como implementador de tokensReceived() en ERC-1820
    2. Atacante deposita tokens ERC-777 en el protocolo víctima
    3. Atacante llama withdraw()
    4. Protocolo llama token.transfer(atacante, amount) → dispara tokensReceived()
    5. Dentro de tokensReceived(), atacante re-entra a withdraw()
    6. El balance del atacante TODAVÍA no se ha actualizado (CEI violation)
    7. Segunda withdraw() también pasa → atacante extrae el doble
    8. Después del callback, el balance se actualiza una sola vez → protocolo insolvente
  invariante: |
    // Ghost variable para detectar reentrancy
    uint256 internal ghost_enterCount;

    function handler_withdraw(uint256 amount) external {
        ghost_enterCount++;
        t(ghost_enterCount == 1, "WE-004: reentrancy detected via ERC-777 hook");
        vault.withdraw(amount);
        ghost_enterCount--;
    }
  que_mirar:
    - "¿El protocolo acepta cualquier token ERC-20 o solo whitelisteados?"
    - "¿Hay nonReentrant en funciones de withdraw/claim/transfer?"
    - "¿El token list incluye tokens ERC-777 compatibles (imBTC, sETH old)?"
    - "¿El protocolo viola CEI (actualiza estado después de transferencia)?"
    - "Buscar: token.transfer() o token.send() ANTES de actualizar balance/state"
    - "ERC-777 tokens son backward-compatible con ERC-20 — parecen ERC-20 normales"
  como_se_arregla: |
    1. Seguir CEI estrictamente: actualizar estado ANTES de transferir tokens
    2. Añadir nonReentrant modifier a todas las funciones que mueven tokens
    3. Si es posible, rechazar tokens ERC-777 o solo aceptar whitelist
    4. Recordar: nonReentrant protege la misma función, pero cross-function
       reentrancy necesita lock compartido
  trampas:
    - "ERC-777 está deprecated pero tokens existentes siguen circulando (imBTC, etc.)"
    - "Si el protocolo tiene whitelist sin tokens ERC-777, no es un finding"
    - "nonReentrant en UNA función no protege contra cross-function reentrancy"
    - "El hook se dispara incluso si el receptor es un EOA (si registró implementador en ERC-1820)"
    - "Algunos tokens tienen dual ERC-20/ERC-777 interfaz — verificar en ERC-1820 Registry"
  solodit_ids:
    - "1-erc777-re-entrancy-attack-hexens-none-polygonzkevm-markdown"
    - "h-01-reentrancy-in-buy-function-for-erc777-tokens-allows-buying-funds-with-considerable-discount-code4rena-caviar-caviar-contest-git"
    - "m-05-when-rewardtoken-is-erc1155erc777-an-attacker-can-reenter-and-cause-funds-to-be-stuck-in-the-contract-forever-code4rena-rabbithole-rabbithole-quest-protocol-contest-git"
    - "m-04-auction-created-by-erc777-tokens-with-tax-can-be-stolen-by-re-entrancy-attack-code4rena-size-size-contest-git"
    - "m-06-the-lender-can-draw-out-extra-credit-token-from-borrowers-account-code4rena-debt-dao-debt-dao-contest-git"
    - "h-2-reentrancy-in-flashaction-allows-draining-liquidity-pools-sherlock-arcadia-git"
  incidentes:
    - "imBTC/Lendf.me — $25M robados via ERC-777 reentrancy en tokensToSend() (Abril 2020)"
    - "imBTC/Uniswap V1 — $300K drenados del pool imBTC/ETH por ERC-777 reentrancy (Abril 2020)"
    - "Caviar — Compra de NFTs con descuento significativo via reentrancy ERC-777 (High, Code4rena)"
    - "Arcadia — Draining de liquidity pools via flashAction + reentrancy (High, Sherlock)"
    - "PolygonZkEVM — ERC-777 re-entrancy attack en bridge (Hexens audit)"
  verificado: true
  confianza: alta

- id: we-005
  titulo: Permit (ERC-2612) Front-Running — DoS y Griefing via Permit Replay
  causa_raiz: |
    ERC-2612 permit() permite aprobar tokens con una firma off-chain en vez de una tx on-chain.
    El problema: la firma permit es pública una vez que se envía la transacción al mempool.
    Un front-runner puede extraer la firma de la tx pendiente, llamar permit() directamente,
    y cuando la tx original se ejecuta, el permit() falla porque el nonce ya fue consumido.
    Si el protocolo wrappea permit+action en una sola tx sin try/catch, toda la operación revierte.
  como_funciona: |
    Escenario DoS:
    1. Usuario firma permit(spender=protocol, amount=1000, nonce=5)
    2. Usuario envía tx: protocol.depositWithPermit(1000, v, r, s)
    3. Front-runner ve la tx en mempool, extrae (v, r, s)
    4. Front-runner llama token.permit(user, protocol, 1000, deadline, v, r, s) directamente
    5. Permit ejecuta OK, nonce del usuario avanza a 6
    6. La tx original llega → llama permit() con nonce=5 → REVERT (nonce inválido)
    7. El depósito del usuario falla — DoS

    Escenario más grave (raro):
    - Si el protocolo usa permit para cambiar allowance de un valor a otro,
      el front-runner puede usar el allowance antes del cambio + después del cambio
  invariante: |
    // Verificar que permit failures no bloquean la operación principal
    function check_permit_resilient(address token, uint256 amount) internal {
        // Si permit falla, la operación debe continuar si ya hay allowance suficiente
        try IERC20Permit(token).permit(owner, spender, amount, deadline, v, r, s) {
            // OK
        } catch {
            // Debe verificar allowance existente y continuar
            t(IERC20(token).allowance(owner, spender) >= amount,
              "WE-005: permit failed and no fallback to existing allowance");
        }
    }
  que_mirar:
    - "¿El protocolo usa permit() seguido de transferFrom() en la misma tx?"
    - "¿Hay try/catch alrededor del permit()?"
    - "Buscar: `token.permit(...)` sin try/catch — vulnerable a front-running DoS"
    - "¿La función revierte si permit falla, o verifica allowance existente como fallback?"
    - "Patrón seguro: try { token.permit(...) } catch {} // si falla, usa allowance pre-existente"
  como_se_arregla: |
    Envolver permit() en try/catch:
    ```solidity
    function depositWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        try IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {}
        // Si permit falla (front-run), el transferFrom usará allowance pre-existente
        token.safeTransferFrom(msg.sender, address(this), amount);
    }
    ```
  trampas:
    - "Muchos jueces consideran permit front-running como Low/Info si solo es DoS temporal"
    - "El usuario puede simplemente enviar approve() clásico como workaround — no es permanent DoS"
    - "Solo es Medium+ si el front-running permite robo de fondos, no solo griefing"
    - "Si el protocolo NO usa permit, no es un finding"
    - "DAI tiene permit con firma diferente (no ERC-2612 estándar) — verificar compatibilidad"
  solodit_ids:
    - "m-10-erc-2612-permit-front-running-in-routerv2-enables-dos-of-liquidity-operations-code4rena-audit-507-audit-507-git"
    - "transaction-dos-via-permit-front-running-mixbytes-none-eywa-markdown"
    - "possible-dos-attack-on-swapping-via-permit2-openzeppelin-none-periphery-changes-audit-markdown"
    - "permit-front-running-can-dos-requestmintwithpermit-spearbit-none-buck-labs-pdf"
  incidentes:
    - "Múltiples protocolos DeFi — Permit front-running DoS reportado en 50+ auditorías (2022-presente)"
    - "EYWA — DoS via permit front-running en bridge operations (Medium, Mixbytes)"
    - "OpenZeppelin Periphery — DoS on swapping via Permit2 front-running (Medium, OZ audit)"
  verificado: true
  confianza: alta

- id: we-006
  titulo: Double-Entry Point Tokens (TUSD-style) — Dos Direcciones, Un Token
  causa_raiz: |
    Algunos tokens tienen dos contratos que apuntan al mismo balance subyacente:
    un contrato legacy y un contrato proxy/nuevo. TrueUSD (TUSD) es el ejemplo canónico.
    Si un protocolo trackea balances por dirección de token, el mismo token puede
    contarse dos veces — depositando via address A y retirando via address B.
  como_funciona: |
    1. Token X tiene dos direcciones: 0xAAA (legacy) y 0xBBB (nuevo proxy)
    2. Ambas apuntan al mismo balance subyacente (son el mismo token)
    3. Protocolo acepta depósitos de ambas direcciones como tokens "diferentes"
    4. Atacante deposita 100 via 0xAAA → protocolo registra 100 de tokenA
    5. El balance subyacente del contrato es 100
    6. Atacante retira 100 de 0xBBB → protocolo tenía 0 de tokenB registrado...
       ...pero si el protocolo lee balanceOf(0xBBB, protocol) = 100, permite retiro
    7. Atacante extrajo el doble, o drenó fondos de otros usuarios
  invariante: |
    // Verificar que no hay double-counting por múltiples addresses
    function check_no_double_entry(address tokenA, address tokenB) internal {
        // Si tokenA y tokenB son el mismo underlying, el balance combinado
        // no debe exceder el balance real
        uint256 balA = IERC20(tokenA).balanceOf(address(vault));
        uint256 balB = IERC20(tokenB).balanceOf(address(vault));
        uint256 internalA = vault.getInternalBalance(tokenA);
        uint256 internalB = vault.getInternalBalance(tokenB);
        t(internalA + internalB <= balA || internalA + internalB <= balB,
          "WE-006: possible double-counting via dual-address token");
    }
  que_mirar:
    - "¿El protocolo permite cualquier token, o hay whitelist?"
    - "¿Hay validación de que dos 'tokens diferentes' no son el mismo subyacente?"
    - "Buscar: mapping(address => mapping(address => uint256)) — token-indexed balances"
    - "¿El protocolo usa la dirección del token como key para contabilidad interna?"
    - "Tokens conocidos con dual-entry: TUSD (legacy + proxy), algunos wrapped tokens"
  como_se_arregla: |
    1. Mantener whitelist de tokens aceptados, sin duplicados
    2. Verificar que dos tokens "diferentes" no comparten el mismo underlying
    3. Para lending protocols: implementar sweepToken() con protección contra TUSD-style
    4. Compound V2 fue afectado y añadió un fix específico para TUSD
  trampas:
    - "Este pattern es raro — pocos tokens tienen double-entry. No reportar sin token específico"
    - "Si el protocolo tiene whitelist curada, no es un finding a menos que TUSD esté en ella"
    - "El escenario requiere que AMBAS direcciones sean aceptadas por el protocolo"
    - "Verificar si el protocolo ya tiene protección (e.g., Compound's sweepToken guard)"
  solodit_ids:
    - "m-4-two-address-tokens-can-be-withdrawn-by-the-payer-even-when-the-stream-has-began-sherlock-nouns-nounsdao-git"
    - "protocol-fees-are-double-counted-as-registry-balance-and-pool-reserve-spearbit-none-primitive-pdf"
  incidentes:
    - "Compound TUSD — El equipo de seguridad descubrió que TUSD dual-address podía drenar cTokens. Se añadió protección a sweepToken() (2022)"
    - "Nouns DAO — Two-address tokens permiten que el payer retire fondos de streams ya iniciados (Medium, Sherlock)"
    - "Primitive — Protocol fees double-counted como registry balance Y pool reserve (Spearbit)"
  verificado: true
  confianza: media

- id: we-007
  titulo: Pausable Tokens (USDC, USDT) — Transferencias Bloqueadas por Pausa
  causa_raiz: |
    USDC y USDT (entre otros) tienen función pause() que bloquea TODAS las transferencias.
    Si un protocolo depende de transferir estos tokens para operaciones críticas (liquidaciones,
    retiros, repagos de deuda), una pausa del token puede dejar al protocolo en estado
    inconsistente o impedir liquidaciones necesarias, causando bad debt.
  como_funciona: |
    Escenario liquidación:
    1. Lending protocol usa USDC como collateral
    2. Posición queda undercollateralized → necesita liquidación
    3. Liquidador intenta liquidar → llama protocol.liquidate()
    4. Protocol intenta transferir USDC colateral al liquidador
    5. USDC está pausado → transfer revierte
    6. Liquidación falla → bad debt se acumula
    7. Precio sigue bajando → el protocolo acumula deuda irrecuperable
    8. Cuando USDC se des-pausa, el daño ya está hecho

    Escenario retiro:
    1. Usuario tiene 1M USDC en vault
    2. USDC se pausa por compliance
    3. Usuario no puede retirar — fondos bloqueados indefinidamente
  invariante: |
    // No hay invariante de fuzzing directo — es un riesgo de diseño
    // Pero se puede testear:
    function check_liquidation_not_blocked() internal {
        // Simular pausa del token
        // vm.prank(usdcAdmin); usdc.pause();
        // Verificar que liquidación tiene path alternativo
        // Este es un test de diseño, no un invariante de fuzzing
    }
  que_mirar:
    - "¿Las funciones críticas (liquidate, withdraw, repay) pueden revertir si el token está pausado?"
    - "¿Hay mecanismo alternativo para liquidaciones cuando el token está pausado?"
    - "¿El protocolo maneja gracefully la pausa del token (cola de retiros, liquidación parcial)?"
    - "Buscar: funciones que llaman transfer/transferFrom de USDC/USDT sin manejo de fallos"
    - "¿Hay timelock en retiros que podría expirar durante una pausa?"
  como_se_arregla: |
    1. Para liquidaciones: permitir liquidación parcial con tokens alternativos
    2. Para retiros: implementar queue/claim pattern — el usuario marca retiro,
       claim se ejecuta cuando el token se des-pausa
    3. Documentar el riesgo y tener plan de contingencia
    4. Considerar circuit breakers propios del protocolo
  trampas:
    - "USDC ha sido pausado exactamente 0 veces en mainnet — el riesgo es teórico pero real"
    - "Muchos jueces consideran esto Low/Info a menos que el impacto sea liquidation failure"
    - "Si el protocolo explícitamente documenta este riesgo como aceptado, es informational"
    - "No confundir con blacklist (we-008) — pausa afecta a TODOS, blacklist es por dirección"
  solodit_ids:
    - "dos-of-meta-vault-withdrawals-during-points-phase-if-one-vault-is-paused-or-attempted-redemption-exceeds-the-maximum-cyfrin-none-strata-markdown"
  incidentes:
    - "USDT (Tether) — Función pause() existe y ha sido usada en testnets. Millones de dólares en protocolos dependen de USDT transferable"
    - "Strata — DoS de withdrawals de meta-vault durante pausa de vault subyacente (Cyfrin audit)"
    - "MakerDAO — Documentó extensivamente el riesgo de USDC pause en el diseño de PSM y D3M"
  verificado: true
  confianza: media

- id: we-008
  titulo: Blacklistable Tokens (USDC, USDT) — Direcciones Bloqueadas
  causa_raiz: |
    USDC y USDT pueden blacklistear (bloquear) direcciones específicas. Si la dirección
    del protocolo o de un usuario clave es blacklisteada, las transferencias desde/hacia
    esa dirección fallan. Esto puede bloquear liquidaciones, retiros, o hacer que fondos
    queden permanentemente atrapados.
  como_funciona: |
    Escenario protocolo blacklisteado:
    1. Protocolo DeFi tiene 50M USDC en su smart contract
    2. Circle (emisor de USDC) blacklistea la dirección del contrato (OFAC, etc.)
    3. Todas las transferencias USDC desde/hacia el contrato fallan
    4. 50M USDC permanentemente atrapados — todos los usuarios pierden sus fondos

    Escenario usuario blacklisteado:
    1. Usuario tiene posición de lending con USDC como collateral
    2. La dirección del usuario es blacklisteada
    3. Liquidador intenta enviar USDC repayment → revierte
    4. O: protocolo intenta enviar USDC colateral al usuario → revierte
    5. Fondos quedan stuck en un limbo
  invariante: |
    // Test: verificar que blacklist no bloquea operaciones críticas
    function check_blacklist_resilient(address user) internal {
        // En fork test:
        // vm.prank(usdcAdmin); usdc.blacklist(user);
        // Verificar que el protocolo tiene path alternativo
        // E.g., usuario puede designar dirección alternativa para recibir fondos
    }
  que_mirar:
    - "¿El protocolo hardcodea la dirección de recepción de fondos?"
    - "¿Hay mecanismo para que un usuario blacklisteado designe receptor alternativo?"
    - "¿Las liquidaciones dependen de transferir tokens AL deudor?"
    - "Buscar: transferencias directas a msg.sender sin opción de recipient alternativo"
    - "¿Hay pull-over-push pattern? (usuario claim en vez de protocolo push)"
  como_se_arregla: |
    1. Permitir que usuarios designen dirección alternativa de recepción
    2. Usar pull-over-push: marcar fondos como claimable, usuario elige cuándo/dónde
    3. Para liquidaciones: permitir que el liquidador especifique recipient
    4. Implementar fallback mechanism si transfer falla
  trampas:
    - "Muchos jueces consideran esto Low si es solo un usuario individual bloqueado"
    - "Si la DIRECCIÓN DEL PROTOCOLO es blacklisteable → High (todos los fondos en riesgo)"
    - "USDC blacklisting es real y se usa regularmente (OFAC sanctions)"
    - "Si el protocolo solo usa ETH/WETH, no es aplicable"
    - "Tornado Cash fue sanctioned — las direcciones del smart contract fueron blacklisteadas"
  solodit_ids:
    - "m-3-front-run-of-addblacklist-function-sherlock-telcoin-telcoin-update-git"
    - "h-8-bounties-can-be-broken-by-funding-them-with-malicious-erc20-tokens-sherlock-openq-openq-git"
    - "m-02-liquidation-can-be-blocked-by-pausing-or-blacklisting-the-nft-contract-permanently-trapping-expired-loans-shieldify-none-shiny-markdown"
  incidentes:
    - "Tornado Cash — USDC blacklisteó direcciones del mixer contract tras sanctions OFAC (Aug 2022)"
    - "MakerDAO — Diseño de D3M (Direct Deposit Module) para USDC consideró riesgo de blacklist como existencial"
    - "Telcoin — Front-run de addBlacklist permite escapar antes del bloqueo (Medium, Sherlock)"
    - "Shiny — Liquidación bloqueada permanentemente por blacklist de NFT contract (Medium, Shieldify)"
    - "Circle blacklisteó $100M+ en USDC asociados a wallets sanctioned (2022-presente)"
  verificado: true
  confianza: alta

- id: we-009
  titulo: Upgradeable Tokens — Comportamiento Puede Cambiar Post-Integración
  causa_raiz: |
    Muchos tokens populares usan proxy patterns (USDC usa AdminUpgradeableProxy, USDT
    tiene capacidad de upgrade). El emisor puede cambiar la implementación del token
    en cualquier momento, alterando transfer logic, añadiendo fees, cambiando decimals,
    o introduciendo comportamiento incompatible con el protocolo que lo integró.
  como_funciona: |
    1. Protocolo integra TokenX con comportamiento estándar ERC-20
    2. Audita el código y verifica que es seguro
    3. 6 meses después, el emisor de TokenX upgradea la implementación
    4. Nueva implementación añade fee-on-transfer de 1%
    5. Protocolo no se entera → contabilidad comienza a divergir
    6. Alternativamente: nueva implementación cambia decimals de 18 a 6
    7. Todas las operaciones de math del protocolo se rompen
  invariante: |
    // No hay invariante de fuzzing directo — es un riesgo de diseño
    // Pero se puede verificar estáticamente:
    // 1. ¿El token usa proxy pattern?
    // 2. ¿Quién controla el admin del proxy?
    // 3. ¿Hay timelock en upgrades?
  que_mirar:
    - "¿El token address es un proxy? Verificar con: Etherscan → 'Read as Proxy'"
    - "¿Quién es el admin del proxy? ¿Es un multisig con timelock?"
    - "Buscar: delegatecall, implementation(), upgradeTo(), en el contrato del token"
    - "¿El protocolo tiene mecanismo para pausar si detecta cambio en el token?"
    - "USDC es upgradeable — Circle puede cambiar la implementación"
  como_se_arregla: |
    1. Documentar el riesgo de upgrade como assumption de trust
    2. Implementar circuit breakers que detecten cambios de comportamiento
    3. Monitorear eventos de upgrade en los tokens integrados
    4. Preferir tokens inmutables cuando sea posible
    5. Para tokens upgradeable: verificar timelock y governance del admin
  trampas:
    - "Este es generalmente un riesgo de trust, no un bug — la mayoría de jueces lo marcan Info/QA"
    - "Solo es finding si el protocolo asume inmutabilidad y no tiene protección"
    - "WETH no es upgradeable. ETH no es un token. DAI sí tiene módulos upgradeables"
    - "La pregunta no es 'puede cambiar' sino '¿qué pasa si cambia y no hay protección?'"
  solodit_ids:
    - "m-1-uupsupgradeable-vulnerability-in-openzeppelin-contracts-sherlock-kyberswap-git"
  incidentes:
    - "USDC V2 upgrade — Circle upgradeó USDC de V1 a V2, añadiendo gasless sends. Protocolos que dependían del bytecode exacto se rompieron"
    - "TUSD — Múltiples upgrades que cambiaron comportamiento, afectando protocolos integrados"
  verificado: true
  confianza: media

- id: we-010
  titulo: Non-Standard Decimals — Tokens con decimals != 18 Causan Errores de Math
  causa_raiz: |
    La mayoría del código DeFi asume decimals=18. Pero USDC/USDT tienen 6 decimals,
    WBTC tiene 8, y algunos tokens tienen 0, 2, o 24. Si las conversiones de precisión
    no manejan correctamente los decimals, las operaciones matemáticas producen resultados
    incorrectos — precios inflados/deflados, montos de liquidación incorrectos, o underflows.
  como_funciona: |
    Escenario: protocolo asume 18 decimals
    1. Protocolo calcula: value = amount * price / 1e18
    2. Para USDC (6 decimals): amount = 1_000_000 (1 USDC)
    3. price = 1e18 (1 USD en 18 decimals)
    4. value = 1_000_000 * 1e18 / 1e18 = 1_000_000
    5. Protocolo interpreta 1_000_000 como 1e-12 tokens (casi cero)
    6. Resultado: 1 USDC vale prácticamente nada en el protocolo
    7. O inversamente: si la math va al revés, 1 USDC vale 1e12 tokens → overflow

    Escenario cross-token:
    1. Protocolo compara collateral (WBTC, 8 dec) vs debt (USDC, 6 dec)
    2. Sin normalización: 1 WBTC (1e8) parece valer solo 100x más que 1 USDC (1e6)
    3. Pero 1 WBTC = ~$60,000 y 1 USDC = $1 → factor debería ser 60,000x
  invariante: |
    // Verificar que las conversiones de decimals son correctas
    function check_decimal_normalization(address tokenA, address tokenB) internal {
        uint8 decA = IERC20Metadata(tokenA).decimals();
        uint8 decB = IERC20Metadata(tokenB).decimals();
        // Cualquier math que combine tokenA y tokenB DEBE normalizar
        // E.g., amountB_normalized = amountB * 10**(decA - decB)
        uint256 oneA = 10 ** decA; // 1 token de A
        uint256 oneB = 10 ** decB; // 1 token de B
        uint256 priceA = oracle.getPrice(tokenA);
        uint256 priceB = oracle.getPrice(tokenB);
        // Value de 1 tokenA y 1 tokenB deben ser razonables
        uint256 valueA = oneA * priceA / (10 ** decA);
        uint256 valueB = oneB * priceB / (10 ** decB);
        t(valueA > 0 && valueB > 0, "WE-010: zero value after decimal normalization");
    }
  que_mirar:
    - "¿El protocolo hardcodea 1e18 o 10**18 en cálculos de conversión?"
    - "¿Lee decimals() dinámicamente o asume 18?"
    - "Buscar: / 1e18, * 1e18, 10**18 hardcodeados sin considerar decimals del token"
    - "¿Hay tests con USDC (6 dec), WBTC (8 dec), y tokens de 18 dec?"
    - "¿El protocolo usa scaleFactor = 10**(18 - token.decimals()) correctamente?"
    - "Overflow risk: 10**decimals con tokens de 24+ decimals puede overflow en uint256"
  como_se_arregla: |
    Siempre normalizar usando decimals() del token:
    ```solidity
    uint256 decimals = IERC20Metadata(token).decimals();
    uint256 normalizedAmount = amount * 10**(18 - decimals); // Solo si decimals <= 18
    ```
    Para conversiones cross-token:
    ```solidity
    uint256 value = amount * price / 10**tokenDecimals;
    ```
  trampas:
    - "La mayoría de protocolos manejan esto correctamente — verificar antes de reportar"
    - "decimals() es opcional en ERC-20 — algunos tokens no lo implementan"
    - "Tokens con decimals=0 son especialmente problemáticos — cada unidad es indivisible"
    - "Si el protocolo solo acepta tokens de 18 decimals via whitelist, no es finding"
    - "Cuidado con underflow en 10**(18 - decimals) si decimals > 18"
  solodit_ids:
    - "incorrect-bondstablecoin-pair-decimals-assumptions-in-oracleunigeodistribution-cyfrin-none-bunni-markdown"
    - "h-9-swapping-100-tokens-in-depositreceipt_eth-and-depositreciept-usdc-breaks-usage-of-wbtc-lp-and-other-high-value-tokens-sherlock-isomorph-isomorph-git"
    - "m-5-exponential-and-logarithmic-price-adapters-will-return-incorrect-pricing-when-moving-from-higher-dp-token-to-lower-dp-token-sherlock-none-index-update-git"
  incidentes:
    - "Isomorph — Swapping 100 tokens en DepositReceipt_USDC rompe el uso de WBTC LP y otros high-value tokens (High, Sherlock)"
    - "Bunni — Decimal assumptions incorrectas en oracle distribution para pares bond/stablecoin (Cyfrin)"
    - "Index — Pricing incorrecto al mover de token con más decimals a token con menos (Medium, Sherlock)"
    - "Múltiples protocolos — USDC de 6 decimals causa cálculos de liquidación incorrectos (recurrente)"
  verificado: true
  confianza: alta

- id: we-011
  titulo: Transfer-to-Self — Comportamiento Inesperado en Transferencias a Uno Mismo
  causa_raiz: |
    Algunos tokens tienen comportamiento inesperado cuando from == to en transferFrom().
    Ciertos tokens revierten, otros reducen el balance (la deducción se aplica pero no el
    crédito si el orden interno es deducir-primero), y otros funcionan normalmente. Si un
    protocolo no previene self-transfers, puede causar pérdida de fondos o DoS.
  como_funciona: |
    Escenario con token que deduce-primero:
    1. Protocolo llama token.transferFrom(vault, vault, amount) — self-transfer
    2. Token internamente: balance[vault] -= amount  (paso 1)
    3. Token internamente: balance[vault] += amount  (paso 2)
    4. Si el token tiene fee: balance[vault] -= amount, balance[vault] += (amount - fee)
    5. Resultado: vault perdió fee sin mover nada → leak de fondos

    Escenario con token que revierte:
    1. Protocolo internamente decide transferir de poolA a poolB
    2. poolA y poolB son el mismo contrato (edge case)
    3. Token revierte en self-transfer → operación bloqueada → DoS
  invariante: |
    // Verificar que self-transfers no causan pérdida
    function check_self_transfer(address token) internal {
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        // Solo si el protocolo puede hacer self-transfers:
        try IERC20(token).transfer(address(this), 1) {
            uint256 balAfter = IERC20(token).balanceOf(address(this));
            t(balAfter == balBefore, "WE-011: self-transfer changed balance");
        } catch {
            // Token revierte en self-transfer — puede causar DoS
        }
    }
  que_mirar:
    - "¿Hay paths donde from == to en transferFrom?"
    - "¿El protocolo valida que sender != recipient?"
    - "Buscar: transferFrom(address(this), address(this), ...) o transfer(address(this), ...)"
    - "¿Hay funciones de rebalance/consolidation que mueven tokens dentro del mismo contrato?"
  como_se_arregla: |
    ```solidity
    require(from != to, "self-transfer not allowed");
    // O simplemente: if (from == to) return; // no-op
    ```
  trampas:
    - "La mayoría de tokens ERC-20 de OpenZeppelin manejan self-transfer correctamente"
    - "Solo es finding si el protocolo tiene un path real donde from == to"
    - "Generalmente Low/Info a menos que cause pérdida de fondos"
  solodit_ids:
    - "m-2-transferfrom-uses-allowance-even-if-spender-from-sherlock-surge-surge-git"
  incidentes:
    - "Surge — transferFrom usa allowance incluso si spender == from, causando gasto innecesario de allowance (Medium, Sherlock)"
    - "Varios tokens custom — self-transfer causa accounting errors en protocolos de yield"
  verificado: true
  confianza: media

- id: we-012
  titulo: Zero-Amount Transfer Revert — Tokens que Revierten en transfer(0)
  causa_raiz: |
    Algunos tokens (LEND legacy, ciertos tokens custom) revierten cuando se intenta
    transferir 0 tokens. Si un protocolo no filtra amount=0 antes de llamar transfer,
    operaciones legítimas pueden fallar — por ejemplo, claiming 0 rewards, o retiro
    cuando el balance es 0.
  como_funciona: |
    1. Protocolo tiene función claimRewards()
    2. Usuario no tiene rewards acumulados → pendingRewards = 0
    3. Protocolo llama: token.transfer(user, 0)
    4. Token revierte en amount=0 → toda la transacción falla
    5. Si claimRewards() está bundleado con otras operaciones (compound, etc.),
       la operación completa revierte → DoS
  invariante: |
    // Verificar que el protocolo maneja amount=0 gracefully
    function check_zero_transfer(address token, address to) internal {
        try IERC20(token).transfer(to, 0) {
            // OK — token acepta zero transfer
        } catch {
            // Token revierte en zero transfer — el protocolo DEBE filtrar
            // Verificar que el protocolo tiene: if (amount > 0) transfer(...)
        }
    }
  que_mirar:
    - "¿El protocolo filtra amount=0 antes de llamar transfer/transferFrom?"
    - "Buscar funciones de claim/withdraw donde el amount puede ser 0 legítimamente"
    - "Buscar: token.transfer(user, amount) sin `if (amount > 0)` guard"
    - "¿Hay batch operations donde uno de N transfers puede ser 0?"
  como_se_arregla: |
    ```solidity
    if (amount > 0) {
        token.safeTransfer(recipient, amount);
    }
    ```
  trampas:
    - "Esto es casi siempre Low/Info — DoS temporal, no pérdida de fondos"
    - "OpenZeppelin ERC-20 permite transfer(0) — solo tokens custom revierten"
    - "Si el protocolo ya tiene `if (amount > 0)` guard, no es finding"
    - "USDC, USDT, DAI, WETH todos permiten zero transfers"
  solodit_ids:
    - "m-10-unable-to-deposit-to-trancheadaptor-under-certain-conditions-sherlock-napier-git"
  incidentes:
    - "Napier — Unable to deposit to TrancheAdaptor bajo ciertas condiciones por zero-amount check (Medium, Sherlock)"
    - "LEND (Aave V1 legacy token) — Revert on zero transfer causó DoS en protocolos integrados"
  verificado: true
  confianza: media

- id: we-013
  titulo: Large Approval Race Condition — approve(0)-then-approve(X) Requerido
  causa_raiz: |
    USDT en Ethereum tiene un check especial en approve(): si el allowance actual es
    != 0 Y el nuevo allowance también es != 0, la transacción REVIERTE. Esto fuerza
    a hacer approve(0) primero y luego approve(newAmount). Si un protocolo llama
    approve(newAmount) directamente cuando ya hay un allowance existente, la tx falla
    con USDT.
  como_funciona: |
    1. Protocolo previamente aprobó router para gastar 1000 USDT
    2. Protocolo necesita aprobar 2000 USDT ahora
    3. Protocolo llama: usdt.approve(router, 2000)
    4. USDT: require(allowance == 0 || newAllowance == 0) → REVERT
    5. La operación falla — fondos pueden quedar stuck si esta aprobación
       es necesaria para un retiro o liquidación
  invariante: |
    // Verificar que approve usa forceApprove o approve(0) primero
    function check_approve_pattern(address token, address spender, uint256 amount) internal {
        // Primero resetear a 0
        IERC20(token).safeApprove(spender, 0);
        IERC20(token).safeApprove(spender, amount);
        t(IERC20(token).allowance(address(this), spender) == amount,
          "WE-013: approve pattern failed");
    }
  que_mirar:
    - "¿El protocolo usa approve() directamente o SafeERC20/forceApprove?"
    - "Buscar: .approve(spender, amount) donde amount > 0 y puede haber allowance previo"
    - "¿Hay approve() en loops o en funciones que se llaman repetidamente?"
    - "OpenZeppelin v5: usar forceApprove() que hace approve(0) + approve(amount) internamente"
    - "Buscar: safeApprove — OZ v4 safeApprove revierte si allowance != 0 y amount != 0"
  como_se_arregla: |
    Opción 1 (OZ v5): `token.forceApprove(spender, amount);`
    Opción 2: `token.safeApprove(spender, 0); token.safeApprove(spender, amount);`
    Opción 3: Usar approve(type(uint256).max) una sola vez en setup
  trampas:
    - "OZ safeApprove también tiene este problema — revierte si current allowance != 0"
    - "forceApprove (OZ v5+) es la solución correcta"
    - "Si el protocolo solo aprueba una vez (en constructor/initialize), no hay race"
    - "USDC NO tiene este problema — solo USDT y algunos tokens custom"
    - "Este finding es generalmente Low/Medium dependiendo del impacto"
  solodit_ids:
    - "m-6-feebuybacksubmit-method-may-fail-if-all-allowance-is-not-used-by-referral-contract-sherlock-telcoin-telcoin-update-git"
    - "multiple-erc4626router-and-erc4626routerbase-functions-will-always-revert-spearbit-astaria-pdf"
    - "infinite-token-approvals-create-additional-security-risk-quantstamp-vusd-stablecoin-markdown"
  incidentes:
    - "Telcoin — feeBuybackSubmit falla si no todo el allowance es usado por referral contract (Medium, Sherlock)"
    - "Astaria — ERC4626Router functions siempre revert por approval pattern incorrecto (Spearbit)"
    - "Múltiples protocolos — USDT approve race condition causó transacciones fallidas (recurrente)"
  verificado: true
  confianza: alta

- id: we-014
  titulo: Transfer Hooks con Gas Limits — Callbacks que Exceden Gas Stipend
  causa_raiz: |
    Cuando se usan low-level calls con gas stipend limitado (e.g., .transfer() que solo
    da 2300 gas), tokens con hooks de transferencia (ERC-777 tokensReceived, tokens con
    callbacks custom) pueden fallar silenciosamente porque el callback consume más gas
    del disponible. Esto es especialmente peligroso con tokens que wrappean operaciones
    complejas en sus hooks.
  como_funciona: |
    1. Protocolo usa .transfer() para enviar ETH a un contrato con receive() complejo
    2. .transfer() da solo 2300 gas → suficiente para log pero no para storage writes
    3. El receiver tiene un receive() que actualiza state → consume >2300 gas
    4. La transferencia falla silenciosamente (Solidity <0.8) o revierte (>=0.8)
    5. Fondos quedan stuck en el protocolo

    Escenario token con hook:
    1. Token tiene hook onTransferReceived() que hace logging + state update
    2. Si el caller limita gas, el hook falla → transfer revierte
    3. Protocolo no puede enviar tokens al usuario → fondos stuck
  invariante: |
    // Verificar que las transferencias no fallan por gas
    function check_transfer_gas(address token, address to, uint256 amount) internal {
        uint256 gasBefore = gasleft();
        IERC20(token).safeTransfer(to, amount);
        uint256 gasUsed = gasBefore - gasleft();
        // Si gasUsed > 100K, el token tiene hooks pesados
        // No es un invariante exacto — es un detector
    }
  que_mirar:
    - "¿El protocolo usa .transfer() o .send() para ETH? Ambos limitan a 2300 gas"
    - "Buscar: .transfer( y .send( para ETH — deberían ser .call{value:}()"
    - "¿Hay gas limits hardcodeados en llamadas a tokens?"
    - "¿Los recipients pueden ser contratos con receive() hooks pesados?"
  como_se_arregla: |
    Para ETH: usar `.call{value: amount}("")` en vez de `.transfer(amount)`.
    Para tokens: no limitar gas en llamadas a transfer/transferFrom.
    Considerar pull-over-push pattern para evitar el problema completamente.
  trampas:
    - "Desde EIP-1884 (Istanbul), SLOAD cuesta 800 gas — receive() con cualquier state read puede fallar con 2300 gas"
    - ".call{value:}() pasa todo el gas restante — resuelve el problema pero abre reentrancy"
    - "Usar .call{value:}() + nonReentrant es el patrón recomendado"
    - "Para tokens ERC-20, safeTransfer() no limita gas — este issue es más relevante para ETH"
  solodit_ids:
    - "static-gaslimit-will-result-in-overpayment-cyfrin-none-yieldfi-markdown"
  incidentes:
    - "King of the Ether — Fallback function con más de 2300 gas causó fondos stuck (2016)"
    - "Múltiples protocolos — .transfer() fallando con contratos multisig como recipients (recurrente)"
    - "YieldFi — Static gas limit resulta en overpayment (Cyfrin audit)"
    - "Post-Istanbul upgrade (EIP-1884) — Múltiples contratos broken por aumento de gas cost de SLOAD"
  verificado: true
  confianza: media

- id: we-015
  titulo: Deflationary/Inflationary Supply — Burn-on-Transfer o Auto-Mint Mechanisms
  causa_raiz: |
    Tokens deflacionarios queman una porción de cada transfer (reduciendo totalSupply).
    Tokens inflacionarios pueden emitir nuevos tokens automáticamente (rebasing positivo,
    farming rewards). Si un protocolo no anticipa cambios en totalSupply o en el balance
    que no corresponden a transfers registrados, la contabilidad se rompe.
    Esto se superpone con we-002 (FoT) y we-003 (rebasing) pero es distinto:
    aquí el problema es totalSupply cambiante, no solo balance.
  como_funciona: |
    Escenario deflacionario:
    1. Token quema 2% de cada transfer → totalSupply decrece
    2. Protocolo usa totalSupply para calcular share price: price = totalAssets / totalSupply
    3. Cada transfer reduce totalSupply → share price sube artificialmente
    4. Últimos holders reciben más de lo que les corresponde
    5. Protocolo no tiene suficientes tokens para pagar a todos → insolvente

    Escenario inflacionario:
    1. Token emite 1% por epoch a todos los holders (como OHM staking)
    2. Protocolo no acumula los nuevos tokens en su contabilidad
    3. Tokens "extras" quedan en el contrato sin dueño
    4. O peor: alguien los extrae con skim/sweep function
  invariante: |
    // Verificar solvencia con supply cambiante
    function check_deflationary_solvency() internal {
        uint256 realBalance = IERC20(token).balanceOf(address(vault));
        uint256 totalOwed = vault.totalDeposited(); // lo que se debe a usuarios
        t(realBalance >= totalOwed,
          "WE-015: vault owes more than it has — possible deflationary drift");
    }
  que_mirar:
    - "¿El protocolo usa totalSupply() en cálculos internos?"
    - "¿Hay share-based accounting que dependa de totalSupply estable?"
    - "Buscar: token.totalSupply() usado en denominadores de cálculos"
    - "¿El protocolo maneja tokens con auto-burn (BabyDoge, SafeMoon, reflection tokens)?"
  como_se_arregla: |
    1. No usar totalSupply() para cálculos internos — usar balance del contrato
    2. Medir balance antes/después de cada transfer (como FoT fix)
    3. Whitelist: excluir tokens deflacionarios/inflacionarios
    4. Si se soportan: usar share-based accounting inmune a supply changes
  trampas:
    - "Se superpone mucho con we-002 y we-003 — verificar que el finding es DISTINTO"
    - "Reflection tokens (SafeMoon-style) son un caso especial: parte del fee se redistribuye a holders"
    - "Si el protocolo tiene whitelist sin tokens deflacionarios, no es finding"
    - "El burn puede ser configurable — 0% hoy, 5% mañana"
  solodit_ids:
    - "m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git"
  incidentes:
    - "SafeMoon — Reflection mechanism causó accounting errors en DEXes y lending protocols que lo integraron (2021-2022)"
    - "SIZE — Incompatibilidad explícita con inflationary/deflationary tokens documentada (Medium, Code4rena)"
    - "Múltiples reflection tokens — Protocolos DeFi asumieron supply constante, causando insolvencia gradual"
  verificado: true
  confianza: media

- id: we-016
  titulo: Multiple Address Tokens (Proxied) — Mismo Underlying Accesible via Múltiples Contratos
  causa_raiz: |
    Similar a we-006 (double-entry) pero más general: tokens con proxy pattern pueden
    tener múltiples entry points. Algunos tokens migrados mantienen el contrato legacy
    activo. Si el protocolo trackea por address y ambas addresses apuntan al mismo
    balance, hay riesgo de double-counting, bypass de límites, o arbitraje interno.
  como_funciona: |
    1. TokenV1 en 0xAAA fue migrado a TokenV2 en 0xBBB (proxy apunta a nueva impl)
    2. Pero 0xAAA sigue activo y funcional (por backward compatibility)
    3. Protocolo lista TokenV2 (0xBBB) como collateral
    4. Atacante deposita via TokenV1 (0xAAA) si el protocolo lo acepta
    5. Si el protocolo no detecta que es el mismo token, contabilidad se rompe
    6. Posible: depositar por V1, retirar por V2, multiplicar balance

    Escenario lending:
    1. Token listado como collateral via addressA
    2. Mismo token depositado como collateral via addressB
    3. Protocolo cuenta collateral doble → puede pedir prestado más de lo permitido
  invariante: |
    // Verificar que no hay duplicate listings
    function check_no_duplicate_token(address[] memory tokens) internal {
        for (uint i = 0; i < tokens.length; i++) {
            for (uint j = i + 1; j < tokens.length; j++) {
                // Verificar que dos tokens no comparten storage
                // Heurística: si balanceOf(address) es idéntico para ambos, sospechoso
                t(tokens[i] != tokens[j], "WE-016: duplicate token address");
            }
        }
    }
  que_mirar:
    - "¿El protocolo acepta tokens arbitrarios o solo whitelisteados?"
    - "¿Hay validación de unicidad de tokens al listarlos?"
    - "¿Tokens en la whitelist tienen versiones proxy/legacy?"
    - "Verificar en Etherscan si algún token tiene proxy con múltiples implementations"
  como_se_arregla: |
    1. Whitelist curada con verificación manual de cada token
    2. Verificar que no hay dos entries para el mismo underlying
    3. Para protocolos permissionless: implementar check de unicidad
  trampas:
    - "Es raro en la práctica — pocos tokens tienen múltiples addresses activas"
    - "Se superpone con we-006 — asegurarse de que el finding es distinto"
    - "Si el protocolo tiene whitelist curada, no es finding"
  solodit_ids:
    - "m-4-two-address-tokens-can-be-withdrawn-by-the-payer-even-when-the-stream-has-began-sherlock-nouns-nounsdao-git"
  incidentes:
    - "TUSD — Migración de TrueUSD dejó dos addresses activas, afectando Compound y otros (2022)"
    - "SNX (Synthetix) — Proxy pattern con addressResolver complicó integraciones"
  verificado: true
  confianza: baja

- id: we-017
  titulo: Flash-Mintable Tokens (DAI, ERC-3156) — Mint Temporal de Supply Ilimitado
  causa_raiz: |
    DAI y otros tokens implementan flash mint: crear tokens de la nada, usarlos dentro
    de una transacción, y destruirlos al final. Si un protocolo usa totalSupply() o
    balanceOf(address) para tomar decisiones de governance, pricing, o access control,
    un flash mint puede manipular estos valores temporalmente para explotar el protocolo.
  como_funciona: |
    Escenario governance:
    1. Token de governance tiene flashMint()
    2. Protocolo: para votar necesitas >5% de totalSupply
    3. Atacante flash-mints 1B tokens → totalSupply sube a 2B
    4. Atacante tiene 1B de 2B = 50% → pasa cualquier propuesta
    5. Atacante ejecuta propuesta maliciosa en la misma tx
    6. Al final de la tx, tokens flash-minted se destruyen

    Escenario price manipulation:
    1. AMM usa reserves para calcular precio
    2. Flash mint tokens → depositar en AMM → manipular precio
    3. Protocolo lee precio del AMM → toma decisión con precio manipulado
    4. Retirar de AMM → repay flash mint → profit
  invariante: |
    // Verificar que totalSupply no cambió drásticamente dentro de una tx
    function check_no_flash_mint_manipulation() internal {
        uint256 supplyBefore = IERC20(token).totalSupply();
        // ... operación del protocolo ...
        uint256 supplyAfter = IERC20(token).totalSupply();
        t(supplyAfter <= supplyBefore * 110 / 100,
          "WE-017: totalSupply changed >10% — possible flash mint manipulation");
    }
  que_mirar:
    - "¿El protocolo usa totalSupply() para decisiones de governance o pricing?"
    - "¿El token tiene flashLoan() o flashMint() function?"
    - "¿El protocolo lee balanceOf/totalSupply en la misma tx que toma decisiones?"
    - "Buscar: token.totalSupply() en funciones de governance, oracle, o access control"
    - "DAI tiene flashMint sin fee — supply ilimitado temporalmente"
  como_se_arregla: |
    1. No usar totalSupply() para decisiones de seguridad
    2. Usar TWAP (time-weighted average) en vez de spot values
    3. Implementar snapshot-based governance (checkpoint antes del voto)
    4. Para pricing: usar oracles externos, no balances/supply del token
  trampas:
    - "DAI flash mint tiene un ceiling configurable — verificar el límite actual"
    - "Si el protocolo usa snapshot-based governance, flash mint no afecta"
    - "Este attack requiere que el protocolo lea totalSupply en la misma tx"
    - "Si el token no tiene flash mint, no es aplicable"
  solodit_ids:
    - "front-running-attacks-on-finalize-could-affect-received-token-amounts-spearbit-gauntlet-pdf"
  incidentes:
    - "bZx — Flash loan + supply manipulation para manipular precios en AMMs ($8M, Feb 2020)"
    - "DAI flashMint — MakerDAO implementó ceiling para limitar la exposición"
    - "Múltiples governance attacks — Flash-minted tokens usados para pasar propuestas maliciosas"
  verificado: true
  confianza: media

- id: we-018
  titulo: Non-ERC20 Return Types — Tokens que Retornan uint256, bytes32, o Nada
  causa_raiz: |
    Más allá de tokens que no retornan nada (we-001), existen tokens que retornan
    tipos inesperados: uint256 en vez de bool (e.g., retornan el amount transferido),
    bytes32 (tokens legacy), o múltiples valores. Si el protocolo decodifica la
    respuesta como bool y recibe otro tipo, el ABI decoder puede interpretar
    incorrectamente: un uint256 != 0 se decodifica como true, pero un uint256 == 0
    (transferencia de 0 tokens exitosa) se decodifica como false → falso negativo.
  como_funciona: |
    1. Token retorna uint256 (amount transferido) en vez de bool
    2. Protocolo: `bool success = token.transfer(to, amount)`
    3. Si amount > 0: el ABI decoder lee bytes32 con valor != 0 → true ✓
    4. Si amount == 0: el ABI decoder lee bytes32 con valor 0 → false ✗
    5. Protocolo interpreta false como "transfer failed" → revert
    6. Pero la transferencia de 0 tokens SÍ fue exitosa → DoS

    Escenario bytes32:
    1. Token legacy retorna bytes32 (hash de la operación)
    2. El ABI decoder espera bool (1 byte útil, 31 bytes padding)
    3. Si el hash tiene el último byte == 0x00 → false
    4. Protocolo piensa que la transferencia falló → operación bloqueada
  invariante: |
    // SafeERC20 maneja esto — el invariante es estático
    // Verificar que TODAS las interacciones con tokens usan SafeERC20
    // que hace low-level call y verifica bytes length antes de decodificar
  que_mirar:
    - "¿El protocolo hace casting directo de return value a bool?"
    - "Buscar: bool success = IERC20(token).transfer(...) — potencialmente inseguro"
    - "¿Se usa SafeERC20 que maneja return types variables?"
    - "Buscar interfaces custom con returns (bool) que pueden no matchear la implementación real"
    - "Verificar tokens legacy que podrían retornar bytes32"
  como_se_arregla: |
    Usar SafeERC20 que maneja todos los casos:
    ```solidity
    // SafeERC20 internamente:
    // 1. Hace low-level call
    // 2. Si returndata.length == 0: asume success (para USDT-style)
    // 3. Si returndata.length >= 32: decodifica como bool
    // 4. Si returndata.length < 32 y > 0: revierte (return type corrupto)
    ```
  trampas:
    - "Se superpone con we-001 — distinguir: we-001 es 'no return', we-018 es 'wrong return type'"
    - "SafeERC20 de OZ maneja AMBOS casos — si se usa SafeERC20, ninguno es finding"
    - "En la práctica, pocos tokens retornan tipos exóticos — verificar el token específico"
    - "Si el protocolo solo soporta tokens de whitelist conocidos, probablemente no aplica"
  solodit_ids:
    - "m-04-erc20-transfer-not-all-tokens-return-boolean-kann-none-wild-protocol-markdown"
    - "m-02-erc20-return-values-not-checked-code4rena-yaxis-yaxis-contest-git"
  incidentes:
    - "Tokens legacy (pre-ERC20 final) — Algunos tokens de 2017 retornan bytes32 en vez de bool"
    - "Wild Protocol — No todos los tokens retornan bool, causando incompatibilidad (Medium)"
    - "BNB — Token no retorna valor en transfer() — rompió integraciones que esperaban bool"
  verificado: true
  confianza: media

---

## Quick Reference: Token Compatibility Matrix

```
Token         | Return | FoT  | Rebase | 777  | Pause | Blacklist | Decimals | Upgrade | FlashMint | Approve(0)
─────────────-+--------+------+--------+------+-------+-----------+----------+---------+-----------+-----------
USDT          | NO ❌  | fee* |   No   |  No  |  Yes  |    Yes    |    6     |   Yes   |    No     | REQUIRED
USDC          | Yes    |  No  |   No   |  No  |  Yes  |    Yes    |    6     |   Yes   |    No     | No
DAI           | Yes    |  No  |   No   |  No  |  No   |    No     |   18     |   No**  |   Yes     | No
WETH          | Yes    |  No  |   No   |  No  |  No   |    No     |   18     |   No    |    No     | No
WBTC          | Yes    |  No  |   No   |  No  |  Yes  |    Yes    |    8     |   No    |    No     | No
stETH         | Yes    |  No  |  YES   |  No  |  No   |    No     |   18     |   No    |    No     | No
wstETH        | Yes    |  No  |   No   |  No  |  No   |    No     |   18     |   No    |    No     | No
AMPL          | Yes    |  No  |  YES   |  No  |  No   |    No     |    9     |   No    |    No     | No
imBTC         | Yes    |  No  |   No   | YES  |  No   |    No     |   18     |   No    |    No     | No
TUSD          | Yes    |  No  |   No   |  No  |  No   |    No     |   18     |   Yes   |    No     | No
SafeMoon      | Yes    | YES  |   No   |  No  |  No   |    No     |    9     |   No    |    No     | No
PAXG          | Yes    | YES  |   No   |  No  |  No   |    No     |   18     |   No    |    No     | No
cUSDCv3       | Yes    |  No  |  YES†  |  No  |  Yes  |    No     |    6     |   No    |    No     | No
BNB           | NO ❌  |  No  |   No   |  No  |  No   |    No     |   18     |   No    |    No     | No

* USDT tiene fee mechanism pero actualmente es 0%. Puede activarse.
** DAI usa módulos de MakerDAO que son upgradeables.
† cUSDCv3 (Compound V3) tiene balance cambiante por interest accrual — similar a rebase.
```

## Checklist Rápido para Auditoría

```
Al auditar un protocolo que acepta ERC-20 tokens:

□ ¿Usa SafeERC20 para TODAS las interacciones de token? (we-001, we-018)
□ ¿Mide balance antes/después de transferFrom? (we-002, we-015)
□ ¿Usa wrapped versions de rebasing tokens (wstETH)? (we-003)
□ ¿Tiene nonReentrant en funciones que mueven tokens? (we-004)
□ ¿Envuelve permit() en try/catch? (we-005)
□ ¿Previene tokens con double-entry point? (we-006, we-016)
□ ¿Maneja gracefully token pause? (we-007)
□ ¿Tiene fallback para blacklisted addresses? (we-008)
□ ¿Documenta riesgo de token upgrades? (we-009)
□ ¿Normaliza correctamente los decimals? (we-010)
□ ¿Previene self-transfers? (we-011)
□ ¿Filtra amount=0 antes de transfer? (we-012)
□ ¿Usa forceApprove o approve(0) pattern? (we-013)
□ ¿Usa .call{value:}() en vez de .transfer()? (we-014)
□ ¿Evita depender de totalSupply() para pricing/governance? (we-017)
```

## Severity Guide

```
CRITICAL:
- we-001 (missing return) + USDT como token principal → fondos stuck permanentemente
- we-004 (ERC-777 reentrancy) + sin nonReentrant → drain completo
- we-006 (double-entry) + lending protocol → drain de pool

HIGH:
- we-002 (FoT) + sin balance check → insolvencia gradual
- we-003 (rebasing) + amount-based accounting → pérdida de yield o insolvencia
- we-010 (decimals) + cross-token math → liquidaciones incorrectas

MEDIUM:
- we-005 (permit front-running) → DoS temporal
- we-007 (pausable) → bloqueo temporal de operaciones
- we-008 (blacklist) → fondos de usuarios individuales stuck
- we-013 (approve race) + USDT → operaciones fallidas

LOW/INFO:
- we-009 (upgradeable) → riesgo de trust, no bug actual
- we-011 (self-transfer) → edge case raro
- we-012 (zero transfer revert) → DoS menor
- we-014 (gas stipend) → solo con ETH y .transfer()
- we-017 (flash mint) → requiere governance attack vector
```

## Referencia Canónica

- Trail of Bits "Weird ERC-20 Tokens": https://github.com/d-xo/weird-erc20
- OpenZeppelin SafeERC20: https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#SafeERC20
- EIP-20 (ERC-20 Standard): https://eips.ethereum.org/EIPS/eip-20
- EIP-777 (ERC-777 Standard): https://eips.ethereum.org/EIPS/eip-777
- EIP-2612 (Permit): https://eips.ethereum.org/EIPS/eip-2612
- SWC-116 (Timestamp Manipulation) — related to rebasing tokens
- Crytic Properties: https://github.com/crytic/properties (ERC-20 invariants)
