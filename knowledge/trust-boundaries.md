# Trust Boundary Vulnerabilities — Bug Patterns

## Quick Reference

```
grep_targets:
  - safeTransferFrom
  - transferFrom
  - balanceOf(address(this))
  - safeApprove
  - forceApprove
  - tokensReceived
  - tokensToSend
  - ERC777
  - IERC1363
  - blacklist
  - blocklist
  - isBlacklisted
  - delegatecall
  - _disableInitializers
  - _authorizeUpgrade
  - function initialize
  - selfdestruct
  - abi.encodePacked
  - unchecked
  - assembly
  - .call{value
  - .call(
  - feeOnTransfer
  - rebase
  - elastic
```

---

## 1. Token Quirks — Fee-on-Transfer

```yaml
- id: tb-001
  titulo: Fee-on-transfer token — amount received != amount sent
  causa_raiz: |
    Los contratos asumen que token.transferFrom(from, to, amount) resulta en que `to`
    recibe exactamente `amount`. Con tokens FoT (PAXG, STA, ciertos BEP20), se descuenta
    un fee y `to` recibe `amount - fee`. El contrato registra `amount` pero sólo tiene
    `amount - fee`, creando un déficit que crece con cada operación.
  como_funciona: |
    1. Usuario deposita 100 PAXG (fee=0.02%). Contrato acredita 100, recibe 99.98.
    2. Siguiente depósito igual → saldo real = 199.96, saldo contabilizado = 200.
    3. Primer retiro de 100 → paga 100 pero sólo tiene 99.98 → revert o drain del siguiente.
    O: protocolo calcula rewards basados en 200 cuando sólo hay 199.96 → insolvencia.
  invariante: |
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(from, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    // received <= amount siempre; usar received, no amount
  que_mirar:
    - safeTransferFrom / transferFrom sin medir balance antes+después
    - Funciones deposit/stake que acreditan `amount` en vez de `received`
    - Reward calculations que usan el parámetro `amount` directamente
    - Lack of explicit "no FoT tokens" in scope/docs
  como_se_arregla: |
    Medir balanceBefore y balanceAfter alrededor de transferFrom.
    Usar `received = after - before` para todas las contabilidades internas.
    Alternativa: whitelist de tokens que no sean FoT.
  trampas:
    - La mayoría de protocolos DeFi mainstream usan USDC/WETH — no son FoT.
    - El impacto real depende de si el token en scope puede ser FoT (verificar docs del protocolo).
    - Algunos auditores marcan esto como LOW/INFO si el protocolo explícitamente excluye FoT.
  solodit_ids:
    - "incompatibility-with-fee-on-transfer-tokens-mixbytes-none-yearn-finance-markdown"
    - "incompatibility-with-fee-on-transfer-or-rebasing-tokens-mixbytes-none-resolv-markdown"
    - "m-02-fee-on-transfer-tokens-can-lead-to-incorrect-approval-code4rena-kuiper-kuiper-contest-git_"
    - "inconsistent-fee-deduction-for-fee-on-transfer-tokens-zokyo-none-aarna-markdown"
    - "m-3-spot-dex-cant-handle-fee-on-transfer-tokens-sherlock-none-unstoppable-git"
  incidentes:
    - "Yearn Finance (MixBytes) — transferFrom asume amount exacto, recibe amount - fee"
    - "Resolv (MixBytes) — safeTransferFrom sin medir balance delta"
    - "Kuiper (C4) — createBasket no ajusta amount real antes de calcular approvals"
    - "Aarna (Zokyo) — fee del protocolo calculado sobre nominal, no sobre recibido"
    - "Unstoppable (Sherlock) — Dca.vy/LimitOrder.vy/TrailingStopDex.vy tres contratos afectados"
```

---

## 2. Token Quirks — ERC777 Callback Reentrancy

```yaml
- id: tb-002
  titulo: ERC777 tokensReceived / tokensToSend permite reentrancia
  causa_raiz: |
    ERC777 notifica al receptor (tokensReceived) y al emisor (tokensToSend) con hooks
    antes/después del transfer. Si el contrato no usa nonReentrant, un atacante registra
    un contrato como receptor ERC777, el hook llama de vuelta al contrato ANTES de que
    se actualicen los balances → ataque clásico de reentrancia CEI violado.
  como_funciona: |
    1. Protocolo acepta ERC777 como reward token.
    2. Atacante registra hook: tokensReceived() → llama a claim() de nuevo.
    3. Primera claim: se transfieren rewards → antes de actualizar balance → hook dispara.
    4. Segunda claim dentro del hook: misma reward balance visible → claim doble.
    5. Resultado: drain del reward pool.
  invariante: |
    // Siempre CEI: actualizar estado ANTES de la transferencia
    rewardDebt[msg.sender] = earned;  // PRIMERO
    rewardToken.safeTransfer(msg.sender, earned);  // DESPUÉS
    // O usar nonReentrant modifier
  que_mirar:
    - Reward claim / withdraw sin nonReentrant y con ERC777 como posible reward token
    - Transfer a recipient antes de actualizar balances internos
    - Protocolos que aceptan reward tokens arbitrarios (cualquier ERC20)
    - ERC1363 (otro token con callbacks) — mismo vector
  como_se_arregla: |
    Aplicar patrón CEI estricto: todos los cambios de estado antes de cualquier transfer.
    Añadir nonReentrant modifier a funciones de claim/withdraw.
    Si el token puede ser ERC777, usar reentrancyGuard explícito.
  trampas:
    - ERC777 ya no es popular post-2022, pero sigue siendo un vector con tokens heredados.
    - USDC/USDT no son ERC777, pero protocolos con reward tokens configurables sí son vulnerables.
    - GearBox demostró que ERC777 como colateral puede bloquear liquidaciones (DOS, no drain).
  solodit_ids:
    - "balanceof-can-be-circumvented-via-reentrancy-and-two-pairs-spearbit-sudoswap-lssvm2-pdf"
    - "m-21-concurrewardpool-possible-reentrancy-when-claiming-rewards-code4rena-concur-finance-concur-finance-contest-git"
    - "reentrance-to-drain-funds-if-approved-token-is-a-callback-token-erc777-zokyo-none-xyro-markdown"
    - "usage-of-erc777-token-can-block-liquidation-mixbytes-none-gearbox-protocol-markdown"
  incidentes:
    - "Sudoswap LSSVM2 (Spearbit) — ERC1155 onERC1155BatchReceived reentrancy bypasses balanceOf"
    - "Concur Finance (C4) — ConcurRewardPool claim rewards sin CEI, callback permite doble claim"
    - "Xyro (Zokyo) — finalizeGame() con 2 jugadores, ERC777 tokensReceived re-entra antes del segundo pago"
    - "GearBox (MixBytes) — ERC777 colateral bloquea liquidaciones indefinidamente (griefing + bad debt)"
```

---

## 3. Token Quirks — USDC/USDT Blocklist Congela Protocolo

```yaml
- id: tb-003
  titulo: Blocklist de USDC/USDT bloquea retiros o liquidaciones del protocolo
  causa_raiz: |
    USDC y USDT tienen función de blacklist/blocklist: el emisor puede bloquear cualquier
    address. Si el contrato o un usuario clave es bloqueado, transfer() revierte → función
    de retiro o liquidación revierte → fondos quedan congelados indefinidamente.
  como_funciona: |
    Path A (usuario bloqueado): Ganador de lotería/subasta bloqueado → transfer() revierte
    → nadie puede completar la distribución → protocolo atascado.
    Path B (protocolo bloqueado): Circle bloquea el propio contrato del protocolo →
    todos los usuarios pierden acceso a sus fondos.
    Path C (griefing): Atacante fuerza al lender/borrower a ser blacklisted → DoS de
    liquidaciones → bad debt acumula.
  invariante: |
    // No se puede invariar on-chain, pero arquitecturalmente:
    // nunca push tokens a usuarios en flujos críticos — usar pull pattern
    // mapping(address => uint256) public claimable;
    // function claim() external { ... token.safeTransfer(msg.sender, amount); }
  que_mirar:
    - Loop de distribución que hace push de USDC a múltiples addresses
    - Liquidación o resolución que transfiere directamente al liquidado (puede estar blocked)
    - Vault que usa USDC como único asset sin mecanismo de fallback
    - Funciones críticas sin try/catch alrededor del transfer
  como_se_arregla: |
    Pull-over-push: en vez de enviar tokens, registrar en un mapping y dejar que el usuario
    los recoja. Si el usuario está bloqueado, sus fondos están disponibles cuando se desbloquee.
    Para liquidaciones: usar try/catch; si transfer falla, registrar como claimable.
  trampas:
    - Circle rara vez bloquea direcciones de contratos DeFi — el riesgo es real pero bajo.
    - El riesgo más práctico es el griefing de liquidaciones en lending protocols.
    - Verificar si el protocolo tiene USDC como único colateral o tiene alternativas.
  solodit_ids: [7252, 6314, 64684]
  incidentes:
    - "CLOBER (Solodit #7252) — USDC blacklist DoS en OrderBook"
    - "Ajna (Solodit #6314) — borrower/kicker blacklisted bloquea cobros"
    - "Shiny (Solodit #64684) — liquidación bloqueada por blacklist NFT"
    - "Cooler — H-4: lender fuerza default al prestatario vía blacklist"
```

---

## 4. Token Quirks — Rebasing Tokens Rompen Balance Cacheado

```yaml
- id: tb-004
  titulo: Tokens rebasing (aToken, stETH) rompen contabilidad si se cachea el balance
  causa_raiz: |
    Tokens como aToken de Aave o stETH de Lido incrementan su balance automáticamente
    con el tiempo (rebasing positivo) sin emitir Transfer events. Si el contrato cachea
    el balance en storage en vez de llamar a balanceOf() cada vez, el valor cacheado
    queda desactualizado → underestima activos → shares sobreemitidas o pérdida de yield.
  como_funciona: |
    1. Vault deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea balance=1000.
    2. 30 días pasan: balance real de aUSDC = 1050 (5% yield).
    3. totalAssets() retorna 1000 en vez de 1050 → pricePerShare subestimado.
    4. Usuario que deposita en este momento recibe shares de más → diluye a los existentes.
    5. Cuando alguien hace harvest, los 50 USDC "extra" aparecen como profit inesperado.
  invariante: |
    assert(totalAssets() >= IERC20(rebasingToken).balanceOf(address(this)));
    // NUNCA cachear balance de token rebasing en storage
  que_mirar:
    - Variables como cachedBalance, storedBalance, lastBalance con tokens tipo aToken/stETH
    - totalAssets() que no llama a balanceOf() en tiempo real
    - Estrategias de yield que integran Aave, Compound, Lido, Frax
    - Contratos que "snapshottean" balances al depositar y los usan para calcular shares
  como_se_arregla: |
    Siempre leer balance directamente: IERC20(aToken).balanceOf(address(this)).
    Si se necesita tracking de depósitos (para profit): usar depositedAmount como base,
    no el balance del rebasing token.
    Para stETH: considerar wstETH (no-rebasing) como alternativa.
  trampas:
    - cToken de Compound NO es rebasing — su balance es fijo, sube el exchangeRate.
    - wstETH NO es rebasing — el precio sube, no el balance.
    - Sólo stETH "nativo" y aToken son rebasing en el sentido estricto.
  solodit_ids:
    - "m-04-auction-wont-work-correctly-with-fee-on-transfer-rebasing-tokens-pashov-none-rolling-dutch-auction-markdown"
    - "m-07-protocol-does-not-work-with-erc20-tokens-that-have-a-mechanism-for-balance-modifications-outside-of-transfers-pashov-none-zerem-markdown"
    - "h-05-aaves-share-tokens-are-rebasing-breaking-current-strategy-code-code4rena-sublime-sublime-contest-git"
    - "h-04-aavevault-does-not-update-tvl-on-depositwithdraw-code4rena-mellow-protocol-mellow-protocol-contest-git"
    - "m-03-protocol-markets-are-incompatible-with-rebasing-tokens-code4rena-wildcat-protocol-wildcat-protocol-git"
  incidentes:
    - "Rolling Dutch Auction (Pashov) — createAuction guarda reserveAmount pero balance rebasa: stale data"
    - "Zerem (Pashov) — tokens Ampleforth-style invalidan todos los locked amount calculations"
    - "Sublime (C4) — AaveYield.lockTokens usa balance delta de aTokens que reba continuamente"
    - "Mellow Protocol (C4) — AaveVault.tvl cacheado, no se actualiza en deposit/withdraw"
    - "Wildcat Protocol (C4) — markets cachean balances de usuarios, incompatible con rebasing"
```

---

## 5. Proxy/Upgrade — Implementación No Inicializada

```yaml
- id: tb-005
  titulo: Contrato upgradeable sin _disableInitializers() — takeover de implementación
  causa_raiz: |
    En contratos UUPS/TransparentProxy, el deploy sube la implementación a la chain por
    separado del proxy. Si la implementación no llama a `_disableInitializers()` en su
    constructor, cualquiera puede llamar a `initialize()` directamente en la implementación
    → se convierte en "owner" de la implementación → puede llamar a upgradeTo(malicious)
    → destruye el proxy o roba fondos.
  como_funciona: |
    1. DevTeam deploya Implementation.sol sin _disableInitializers() en constructor.
    2. Atacante detecta la implementación sin inicializar.
    3. Llama a initialize(attacker_address) en la implementación directamente.
    4. Ahora attacke es "owner" del contrato de implementación.
    5. En UUPS: attacke llama upgradeTo(maliciousImpl) desde la implementación.
    6. Proxy ahora apunta a código malicioso → protocolo comprometido.
  invariante: |
    // En constructor de la implementación:
    constructor() { _disableInitializers(); }
    // Verifica que initializer no sea callable en la implementación deployed
  que_mirar:
    - Contratos que heredan de UUPSUpgradeable o Initializable sin _disableInitializers()
    - Constructor vacío o ausente en implementaciones upgradeable
    - Proxy patterns donde la implementación está deployed por separado
    - OpenZeppelin < 4.3.2 (no tenía _disableInitializers automático)
  como_se_arregla: |
    Añadir en constructor: constructor() { _disableInitializers(); }
    O: usar OpenZeppelin >= 4.3.2 que lo hace automático con el flag @custom:oz-upgrades-unsafe-allow
  trampas:
    - Sólo crítico si la implementación tiene lógica de upgrade (UUPS).
    - En TransparentProxy, el admin es el proxy — el daño es limitado si no hay upgradeTo en impl.
    - La mayoría de audits modernos lo cogen rápido — buscar en implementaciones menos obvias.
  solodit_ids:
    - "upgradeable-contracts-must-disable-initializers-in-the-implementation-contracts-sigmaprime-none-swell-pdf"
    - "missing-call-to-_disableinitializers-zokyo-none-symbiosis-markdown"
    - "h-09-potential-dos-in-contracts-inheriting-uupsupgradeablesol-code4rena-notional-notional-git"
    - "frontrunners-can-corrupt-the-initialization-of-the-timelock-and-berachaingovernance-contracts-spearbit-none-berachain-governance-pdf"
  incidentes:
    - "Swell (Sigma Prime) — implementaciones upgradeable sin _disableInitializers en constructor"
    - "Symbiosis (Zokyo) — missing _disableInitializers, clasificado Medium con TVL en producción"
    - "Notional (C4) — GovernanceAction/PauseRouter/NoteERC20 heredan UUPS sin protección → DOS permanente via selfdestruct"
    - "Berachain Governance (Spearbit) — deploy en 2 txns separadas, frontrunnig puede inicializar con params maliciosos"
```

---

## 6. Proxy/Upgrade — _authorizeUpgrade Sin Control de Acceso

```yaml
- id: tb-006
  titulo: _authorizeUpgrade() vacía o sin acceso control — cualquiera puede upgradar
  causa_raiz: |
    En contratos UUPS, la función _authorizeUpgrade() debe proteger quién puede
    ejecutar upgrades. Si se deja vacía (sin revert, sin onlyOwner), cualquier address
    puede llamar upgradeTo() y reemplazar la lógica del protocolo por código arbitrario.
  como_funciona: |
    1. Dev implementa _authorizeUpgrade(address) internal override {} (vacío).
    2. UUPS.upgradeTo() llama a _authorizeUpgrade() — no revierte.
    3. Cualquier EOA llama upgradeTo(malicious) → proxy apunta a código del atacante.
    4. Atacante drena todos los fondos del proxy.
  invariante: |
    // _authorizeUpgrade DEBE tener guard:
    function _authorizeUpgrade(address) internal override onlyOwner {}
    // O: onlyRole(UPGRADER_ROLE), etc.
  que_mirar:
    - function _authorizeUpgrade con cuerpo vacío
    - _authorizeUpgrade sin modifier de acceso (onlyOwner, onlyRole, etc.)
    - Contratos que heredan UUPSUpgradeable sin override visible de _authorizeUpgrade
  como_se_arregla: |
    Siempre añadir guard: function _authorizeUpgrade(address) internal override onlyOwner {}
    Si el protocolo quiere multi-sig: onlyRole(UPGRADER_ROLE) con timelock.
  trampas:
    - OZ UUPSUpgradeable base revierte si no hay override — pero sólo en versiones recientes.
    - Buscar también en contratos intermedios que hereden UUPS y hagan override sin guard.
  solodit_ids: []
  incidentes:
    - "Nomad Bridge ($190M) — trusted root set to 0x00 durante upgrade"
    - "Curve ($70M) — Vyper compiler reentrancy bug expuesto tras upgrade"
    - "Múltiples Code4rena — _authorizeUpgrade() {} vacío en contratos UUPS"
```

---

## 7. External Call Trust — Delegatecall a Target Arbitrario

```yaml
- id: tb-007
  titulo: delegatecall a address controlada por usuario → corrupción de storage / drain
  causa_raiz: |
    delegatecall ejecuta el código del target en el contexto de storage del caller.
    Si el target es controlado por un usuario (no whitelisted), puede ejecutar código
    arbitrario: sobreescribir mappings de balance, llamarse a sí mismo como owner, etc.
    El caller pierde el control de todo su storage.
  como_funciona: |
    1. Protocolo expone: function execute(address target, bytes data) { target.delegatecall(data); }
    2. Atacante pasa target=maliciousContract con lógica: balances[attacker] = type(uint256).max
    3. delegatecall ejecuta en el storage del protocolo → balance del atacante inflado
    4. Atacante retira todos los fondos.
  invariante: |
    // Sólo hacer delegatecall a contratos whitelisted y auditados
    require(isApprovedLibrary[target], "target not whitelisted");
    (bool ok,) = target.delegatecall(data);
  que_mirar:
    - delegatecall con parámetro de address provisto por el caller
    - Contratos de "ejecutor" o "dispatcher" que hacen delegatecall
    - Multicall/batch implementations que iteran sobre calls arbitrarios
    - Target de delegatecall que es upgradeable (puede cambiar lógica post-whitelist)
  como_se_arregla: |
    Whitelist estricta de targets para delegatecall.
    Preferir call() sobre delegatecall() cuando el storage del caller no es necesario.
    Si se necesita delegatecall extensible: library pattern con storage offset aislado.
  trampas:
    - LI.FI ($7M) pasó por un token bridge que hacía delegatecall a targets arbitrarios.
    - Algunos protocolos usan delegatecall intencionalmente en módulos — verificar whitelist.
  solodit_ids:
    - "delegatecall-to-untrusted-contract-quantstamp-blexio-markdown"
    - "incomplete-error-handling-for-failed-delegatecall-quantstamp-ssvnetwork-markdown"
  incidentes:
    - "blex.io (Quantstamp) — Market.sol actúa como proxy pero delegatecall a contratos no controlados"
    - "SSV.network (Quantstamp) — CoreLib.delegateCall() no revertía en fallo, calls fallidas silenciosas"
    - "LI.FI ($7M) — arbitrary delegatecall a contract no whitelisted"
```

---

## 8. External Call Trust — Batch Loop Sin Error Isolation

```yaml
- id: tb-008
  titulo: Loop de distribución sin try/catch — un revert bloquea todo el batch
  causa_raiz: |
    Contratos que distribuyen tokens/ETH a múltiples recipients en un loop sin manejo
    de errores. Si UN recipient revierte (blocklisted, contrato sin receive(), paused),
    todo el loop revierte y NINGÚN otro recipient recibe su pago.
    Un actor malicioso puede forzar el revert deliberadamente para bloquear el protocolo.
  como_funciona: |
    1. DAO distribuye rewards a 50 holders en un loop.
    2. Atacante compra 1 token, convierte su address en una que revierte en receive().
    3. Cuando el loop llega al atacante → revert → ninguno de los 50 cobra.
    4. El atacante puede sostener el bloqueo indefinidamente con costo mínimo.
  invariante: |
    // Patrón correcto: pull-over-push
    mapping(address => uint256) public pendingRewards;
    function claimReward() external {
        uint256 amount = pendingRewards[msg.sender];
        pendingRewards[msg.sender] = 0;
        token.safeTransfer(msg.sender, amount);
    }
  que_mirar:
    - Loop for/while con safeTransfer / call{value} a recipients externos
    - Distribuciones de dividendos o rewards que hacen push a todos los holders
    - Funciones de settlement que transfieren a ganadores de forma automática
    - Uso de transfer() en vez de call{value} para ETH (transfer tiene gas limit)
  como_se_arregla: |
    Siempre usar pull-over-push para distribuciones.
    Si push es necesario: envolver cada transfer en try/catch y registrar fallidos para retry.
    Para ETH: usar call{value} en vez de transfer() (evita gas limit issues).
  trampas:
    - En L2 (Optimism, Base) el gas es barato — el griefing puede ser más viable.
    - "Recipient reverts" también ocurre con contratos que no tienen fallback().
  solodit_ids: []
  incidentes:
    - "Venus Protocol (Solodit #64684) — DoS por revert en refund de bids"
    - "Sparkn (Solodit) — winner blacklisted no puede recibir fondos"
    - "Multiple Sherlock/C4 — batch ETH distribution blocked by single reverting recipient"
```

---

## 9. EVM/Compiler — abi.encodePacked Collision

```yaml
- id: tb-009
  titulo: abi.encodePacked con múltiples tipos dinámicos → hash collision
  causa_raiz: |
    abi.encodePacked concatena argumentos sin padding. Con dos strings/bytes dinámicos,
    encodePacked("a","bc") == encodePacked("ab","c") → mismo hash → misma signature.
    Usado en control de acceso o validación → bypass completo.
  como_funciona: |
    1. Sistema permite acciones si keccak256(abi.encodePacked(role, target)) == expected.
    2. role="admin" + target="x" → mismo hash que role="admi" + target="nx".
    3. Atacante encuentra la colisión y usa role no válido para pasar la check.
    4. O: en merkle trees, hojas y nodos interiores tienen el mismo formato → second preimage.
  invariante: |
    // Siempre usar abi.encode en vez de abi.encodePacked para múltiples tipos dinámicos:
    keccak256(abi.encode(typeA, typeB))  // seguro
    keccak256(abi.encodePacked(typeA, typeB))  // vulnerable si ambos son dinámicos
  que_mirar:
    - abi.encodePacked con dos o más parámetros string o bytes
    - Funciones de verificación de signature/hash que usan encodePacked
    - Merkle trees donde leaves y nodes tienen el mismo formato de hash
    - Permisos o roles encoded en un hash combinado
  como_se_arregla: |
    Reemplazar abi.encodePacked por abi.encode cuando hay múltiples tipos dinámicos.
    En Merkle: añadir un byte de tipo (0x00 para leaf, 0x01 para node) antes del hash.
  trampas:
    - Con tipos fijos (uint256, address) abi.encodePacked es seguro — no hay ambigüedad.
    - Sólo vulnerable cuando ambos parámetros son dinámicos (string, bytes, arrays).
  solodit_ids: []
  incidentes:
    - "OpenSea Seaport — abi.encodePacked en order hash (mitigado en diseño)"
    - "Multiple Sherlock/C4 — role/permission collision via encodePacked"
    - "Merkle airdrop — second preimage attack via leaf/node format collision"
```

---

## 10. Token Quirks — Approve() Race Condition (USDT)

```yaml
- id: tb-010
  titulo: USDT approve() requiere reset a 0 — race condition en allowance
  causa_raiz: |
    USDT en Ethereum (y algunos clones) no permite cambiar allowance de X a Y si X > 0.
    Requiere que primero se setee a 0 y luego a Y. Si el contrato usa
    token.approve(spender, newAmount) directamente, revierte con USDT. Además, hay una
    race condition: si el spender ve la tx de reduce-allowance en mempool, puede front-run
    gastando la allowance vieja antes de que se ejecute la nueva.
  como_funciona: |
    Escenario revert: contract hace approve(spender, 1000) cuando allowance era 500
    → USDT revierte → operación falla → fondos atascados o protocolo roto.
    Escenario race: user llama approve(spender, 100) para bajar de 500 a 100.
    Spender front-runs: usa los 500 primero, luego tiene 100 más = 600 gastados.
  invariante: |
    // Usar SafeERC20.forceApprove() o safeIncreaseAllowance / safeDecreaseAllowance
    // o el patrón manual: approve(0) → approve(newAmount)
  que_mirar:
    - token.approve(spender, amount) con tokens que pueden ser USDT
    - Contratos que esperan poder cambiar allowance directamente
    - Uso de safeApprove() de OZ v3 (deprecada — también require 0-first)
    - Contratos que manejan USDT como stablecoin principal
  como_se_arregla: |
    Usar SafeERC20.forceApprove(token, spender, amount) de OZ v4+.
    O secuencia manual: token.approve(spender, 0); token.approve(spender, amount);
  trampas:
    - USDC sí permite cambios directos de allowance — sólo USDT (y sus forks) tiene esta restricción.
    - forceApprove() no resuelve la race condition — sólo el patrón allowance + nonce lo hace.
    - En la práctica el race condition requiere spender activo monitoreando mempool.
  solodit_ids: [64933]
  incidentes:
    - "Garden (Solodit #64933) — unchecked approve() return con USDT causa fund loss"
    - "Multiple protocols — approve(spender, amount) reverts con USDT cuando allowance > 0"
```

---

## Attack Scenarios Summary

| ID | Patrón | Severity | Likelihood |
|----|--------|----------|------------|
| tb-001 | Fee-on-transfer balance discrepancy | High | High (si token es FoT) |
| tb-002 | ERC777 callback reentrancy | High | Medium |
| tb-003 | USDC/USDT blocklist freeze | Medium | Low |
| tb-004 | Rebasing token cached balance | High | High (con Aave/Lido) |
| tb-005 | Uninitialized proxy implementation | Critical | Medium |
| tb-006 | _authorizeUpgrade() sin acceso control | Critical | Low (rare oversight) |
| tb-007 | delegatecall a target arbitrario | Critical | Low (requiere diseño roto) |
| tb-008 | Batch loop sin error isolation | Medium | Medium |
| tb-009 | abi.encodePacked collision | High | Low |
| tb-010 | USDT approve() race/revert | Medium | Medium |
