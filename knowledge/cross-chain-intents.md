grep_targets:
  - "lzReceive"
  - "ccipReceive"
  - "xCall"
  - "relayMessage"
  - "sendMessage"
  - "executeMessage"
  - "validateMessage"
  - "nonce"
  - "messageHash"
  - "bridgeToken"
  - "lockAndMint"
  - "burnAndRelease"
  - "intent"
  - "fillOrder"
  - "solver"
  - "relayer"
  - "DOMAIN_SEPARATOR"
  - "destinationChain"

# Briefing: Cross-Chain & Intents

## Contexto del dominio
Los protocolos cross-chain (LayerZero, CCIP, Axelar, Wormhole, Hyperlane, IBC) y
los sistemas de intents (Across, UniswapX, 1inch Fusion, CoW Protocol, Socket)
mueven valor entre cadenas. Los bugs más críticos involucran:
- Message replay entre cadenas (mismo mensaje ejecutado 2+ veces)
- Validación insuficiente del origen del mensaje
- Intent fill sin verificar que el usuario recibió fondos
- Timing attacks que explotan diferencias de timestamp entre cadenas
- Nonce management cross-chain que permite skip o replay

---

patterns:

- id: cc-001
  titulo: Cross-Chain Message Replay — Missing Nonce or Chain ID Check
  causa_raiz: |
    Un mensaje bridge válido en Chain A puede ser re-enviado en Chain A (o enviado a Chain B
    si es multi-chain), si el contrato receptor no verifica que el mensaje ya fue procesado.
    La mayoría de bridge frameworks proveen nonce, pero si el contrato no lo persiste
    correctamente, el replay es posible.
  como_funciona: |
    1. Usuario envía mensaje cross-chain: bridge(amount=1000 USDC, dst=Chain B)
    2. El relayer entrega el mensaje en Chain B — el contrato marca el nonce como usado
    3. El atacante vuelve a llamar al contrato de destino con el mismo mensaje (raw calldata)
    4. Si el check de nonce usa un mapping que puede ser borrado (reset), o si hay
       una función de migración que limpia los nonces, el replay funciona
    Variante (chain ID missing):
    - Protocolo deployado en 5 chains con mismo address
    - Mensaje diseñado para Chain B se entrega también en Chain C (no verifica chainId en el payload)
  invariante: |
    // Ghost: set de message hashes procesados
    mapping(bytes32 => bool) internal ghost_processedMessages;

    function check_no_message_replay(bytes memory message) internal {
        bytes32 msgHash = keccak256(message);
        t(!ghost_processedMessages[msgHash],
          "CC-001: cross-chain message replayed");
        ghost_processedMessages[msgHash] = true;
    }
  que_mirar:
    - "¿El mapping de nonces procesados puede ser reseteado (upgrade, migración)?"
    - "¿El payload del mensaje incluye chainId del origen Y del destino?"
    - "¿Hay una función de 'retry' que no verifica si ya fue ejecutado?"
    - "¿El hash del mensaje incluye el contract address de destino?"
  como_se_arregla: |
    - Incluir en el hash: srcChainId + dstChainId + srcAddress + dstAddress + nonce + payload
    - El mapping de nonces usados NUNCA debe borrarse (ni en upgrades)
    - Si se hace upgrade, migrar el mapping completo al nuevo storage slot
  trampas:
    - "LayerZero usa nonces per-pathway (srcChainId, srcAddress) — si el pathway es único, un contrato diferente en la misma chain puede tener el mismo nonce"
    - "Wormhole sequence numbers son por emitter — no son globales al protocolo"
  solodit_ids: [6511, 6655, 34498, 7099]

- id: cc-002
  titulo: Unvalidated Message Origin — Spoofed Sender
  causa_raiz: |
    El contrato receptor confía en el campo `sender` del mensaje sin verificar que
    proviene del contrato correcto en la cadena de origen. Un atacante puede crear
    un contrato malicioso en la cadena de origen que envíe mensajes con un `sender`
    arbitrario, o puede aprovechar la función de "bypass" del endpoint del bridge.
  como_funciona: |
    Variante A — Fake sender:
    1. El protocolo verifica: require(msg.sender == bridgeEndpoint)
    2. Pero NO verifica que el sender dentro del payload == trustedContract
    3. Atacante despliega un contrato en Chain A que envía un mensaje con sender=0x0 (cualquiera)
    4. El mensaje llega a Chain B y se ejecuta como si viniera del contrato autorizado

    Variante B — Bridge endpoint spoofed:
    1. El protocolo solo verifica que el endpoint del bridge llame a la función
    2. Pero el endpoint del bridge acepta mensajes de cualquier application
    3. Atacante crea una "application" en el bridge que envía mensajes al protocolo víctima
    4. El bridge entrega el mensaje (porque el protocolo es un endpoint válido del bridge)
  invariante: |
    function check_message_origin(address srcAddress, uint16 srcChainId) internal view {
        // El sender debe estar en el whitelist de trusted remotes
        t(trustedRemotes[srcChainId] == srcAddress,
          "CC-002: message from untrusted origin");
    }
  que_mirar:
    - "¿El contrato verifica TANTO msg.sender (endpoint local) COMO el srcAddress del mensaje?"
    - "¿El trustedRemotes mapping está inicializado para todas las chains configuradas?"
    - "¿Hay una función setter del trustedRemotes que no tenga timelock?"
    - "¿El protocolo usa 'owner can set trusted remote' sin un delay mínimo?"
  como_se_arregla: |
    - Siempre verificar: (1) msg.sender == localBridgeEndpoint, (2) srcAddress == trustedRemote[srcChainId]
    - Inicializar trustedRemotes en el constructor o deployment script (no en un tx posterior)
    - Añadir timelock de 48h a cambios en trustedRemotes
  trampas:
    - "LayerZero v1 tenía una función setTrustedRemote sin access control en algunos adaptadores"
    - "Wormhole no valida automáticamente el sender — el protocolo DEBE hacerlo en _verifyVAA"
    - "CCIP verifica la chain de origen pero NO la address del sender dentro del message"
  solodit_ids: [49753, 8856, 6096, 3627]

- id: cc-003
  titulo: Intent Fill Without Verification — Griefing o Double Claim
  causa_raiz: |
    En sistemas de intents, el solver/relayer llena la orden en la cadena de destino
    y reclama el pago en la cadena de origen. Si la verificación del fill en la cadena
    de origen es insuficiente o manipulable, el solver puede reclamar sin haber llenado,
    o el usuario puede bloquear el pago después de recibir los fondos.
  como_funciona: |
    Variante A — Fill sin entrega real:
    1. Solver dice "llené el intent #42 en Chain B"
    2. El contrato en Chain A verifica un proof, pero el proof puede ser forjado
    3. Solver reclama el pago en Chain A sin haber entregado en Chain B

    Variante B — Double claim via fast path + slow path:
    1. Across tiene fast path (solver paga inmediatamente, reclama vía bridge) y slow path (espera)
    2. Si el depositId se puede usar tanto en fast como en slow path, el solver cobra dos veces
    3. El depositId debe marcarse como "claimed" al primer fill

    Variante C — User griefing:
    1. Solver llena el intent en Chain B
    2. Antes de que el solver reclame en Chain A, el usuario llama a "cancel"
    3. El cancel devuelve los fondos al usuario en Chain A
    4. El solver pierde el capital que puso en Chain B
  invariante: |
    mapping(bytes32 => bool) internal ghost_filledIntents;

    function check_no_double_fill(bytes32 intentId) internal {
        t(!ghost_filledIntents[intentId],
          "CC-003: intent filled more than once");
        ghost_filledIntents[intentId] = true;
    }

    function check_fill_verified(bytes32 intentId, address recipient, uint256 amount) internal view {
        // Si el intent está marcado como filled, el recipient debe haber recibido el amount
        if (ghost_filledIntents[intentId]) {
            t(token.balanceOf(recipient) >= ghost_recipientBalanceBefore[recipient] + amount,
              "CC-003: intent marked filled but recipient balance unchanged");
        }
    }
  que_mirar:
    - "¿El fill proof incluye el destinatario real y el amount real?"
    - "¿Qué pasa si el solver llena con amount menor al solicitado?"
    - "¿El tiempo de expiración del intent puede correrse o resetearse?"
    - "¿Hay un estado 'pending fill' que bloquee cancelaciones mientras el solver actúa?"
  como_se_arregla: |
    - Fill proof debe incluir: intentId + recipient + amount + destinationChain + blockNumber
    - Una vez en estado "being filled", el usuario no puede cancelar por X bloques
    - Marcar intentIds como used en el momento del claim, no del fill
  trampas:
    - "Across protocol tuvo exactamente la variante B en v2 — depositId podía reclamarse en ambos paths"
    - "En UniswapX, el filler puede cambiar la dirección de entrega si la orden no especifica recipient exacto"
  solodit_ids: [64933, 7252, 64684]

- id: cc-004
  titulo: Bridge Token Lock/Mint Accounting Desync
  causa_raiz: |
    En bridges de lock-and-mint, los tokens nativos se lockean en Chain A y se mintean
    wrapped tokens en Chain B. Si el accounting entre las dos chains diverge (por mensaje
    perdido, retry incorrecto, o bug en el unlock), se pueden mintear más tokens de los
    que están lockeados → inflación del supply.
  como_funciona: |
    Variante A — Lost unlock message:
    1. Usuario hace unlock(tokens) en Chain B (quema los wrapped tokens)
    2. El mensaje de "release en Chain A" se pierde (timeout del relayer)
    3. El usuario llama a "retry" que envía un nuevo mensaje
    4. Si ambos mensajes llegan, se liberan el doble de tokens en Chain A
    5. El bridge tiene menos tokens lockeados de los que debería

    Variante B — Reentrancy en el lock:
    1. Los tokens tienen hook en transfer (ERC777 o ERC677)
    2. Durante el lock() en Chain A, el hook llama de vuelta al bridge
    3. La segunda llamada también lockea tokens pero no incrementa el counter todavía
    4. Se mintean tokens extras en Chain B sin el backing correspondiente
  invariante: |
    function check_bridge_backing() internal view {
        uint256 lockedOnChainA = bridge.totalLocked(token);
        uint256 mintedOnChainB = wrappedToken.totalSupply();
        // Con tolerancia para mensajes en tránsito
        t(mintedOnChainB <= lockedOnChainA + MAX_IN_FLIGHT_AMOUNT,
          "CC-004: wrapped token supply exceeds locked backing");
    }
  que_mirar:
    - "¿El retry del mensaje verifica que el mensaje original no fue ya procesado?"
    - "¿El lock() sigue CEI? (actualiza el counter ANTES de hacer el transfer)"
    - "¿El unlock() en Chain A puede ser llamado sin el mensaje de Chain B?"
    - "¿Hay un mecanismo de reconciliación si los totales divergen?"
  como_se_arregla: |
    - Incluir messageId único en cada mensaje; el unlock verifica que no fue ya procesado
    - CEI en lock: actualizar balance ANTES de aceptar el transfer
    - Limitar el in-flight amount máximo (cap en cuánto puede estar "en el puente")
  trampas:
    - "Wormhole tuvo este bug en 2022 — $320M robados por mint sin lock correspondiente"
    - "Los bridges que soportan fee-on-transfer tokens tienen un accounting desync por diseño si no ajustan por el fee"
  solodit_ids: [6511, 7099, 34498, 5822]

- id: cc-005
  titulo: Timing Attack — Finality Difference Between Chains
  causa_raiz: |
    Chain A tiene finality en 12 segundos (Ethereum), Chain B en 400ms (Solana).
    Si el protocolo asume que un mensaje enviado desde Chain B ya es final cuando
    se recibe en Chain A, un reorganización en Chain B puede invalidar el mensaje
    mientras los efectos en Chain A ya ocurrieron.
  como_funciona: |
    1. Atacante hace una transacción en Chain B (p.ej., envía 1000 USDC a un bridge)
    2. El relayer (rápido) entrega el mensaje en Chain A antes de que Chain B sea final
    3. En Chain A: se mintean 1000 USDC wrapped
    4. El atacante hace reorg en Chain B (si es una chain con bajo hashrate/stake)
    5. La transacción de envío en Chain B desaparece — pero los tokens en Chain A ya existen
    6. El atacante tiene los tokens originales en Chain B Y los wrapped en Chain A
    Más realista: el atacante vende los wrapped en Chain A inmediatamente (mismo bloque)
  invariante: |
    function check_finality_requirements(uint16 srcChainId, uint256 srcBlockNumber) internal view {
        uint256 requiredConfirmations = finalityConfirmations[srcChainId];
        uint256 currentBlock = getLatestBlock(srcChainId);
        t(currentBlock >= srcBlockNumber + requiredConfirmations,
          "CC-005: message processed before source chain finality");
    }
  que_mirar:
    - "¿Cuántas confirmaciones requiere el protocolo por chain origen?"
    - "¿Las confirmaciones requeridas están hardcodeadas o son configurables?"
    - "¿Hay chains en la lista de soporte con finality probabilística alta?"
    - "¿El protocolo permite override de las confirmaciones requeridas?"
  como_se_arregla: |
    - Establecer confirmations mínimas basadas en la seguridad real de cada chain
    - Ethereum: mínimo 64 bloques (2 épocas para finality dura)
    - Chains con bajo TVL: usar TWAP de confirmaciones del bridge
    - No permitir reducir confirmations por debajo de un mínimo hardcodeado
  trampas:
    - "PoS Ethereum tiene finality real a los ~12 minutos (2 épocas) — no en cada bloque"
    - "Las chains OP Stack tienen finality en Ethereum L1, no en el L2 — diferente timeline"
    - "Avalanche tiene 'fast finality' pero solo si el stake es suficientemente alto ese bloque"
  solodit_ids: [35156, 8801, 29031]

- id: cc-006
  titulo: Cross-Chain Reentrancy via Async Callback
  causa_raiz: |
    Los mensajes cross-chain son asincrónicos: se envía en Chain A y se recibe en Chain B
    en un bloque posterior. Si el contrato en Chain A envía un mensaje a Chain B y luego
    recibe un callback de Chain B (por otro mensaje), puede que el estado en Chain A
    no haya finalizado cuando el callback llega.
  como_funciona: |
    1. UserA llama deposit() en Protocol-Chain-A
    2. Protocol-Chain-A envía mensaje a Protocol-Chain-B: "monta posición"
    3. Protocol-Chain-A actualiza el balance de UserA
    4. Protocol-Chain-B procesa el mensaje, envía callback: "posición montada, aquí los shares"
    5. El callback llega a Protocol-Chain-A ANTES de que alguna otra tx confirm el estado
    6. El callback puede hacer que se dupliquen los shares (el state de Chain-A no era final)
    Nota: esto requiere un diseño específico, pero puentes como LayerZero blocked delivery
    (bloqueado retry) pueden crear estas situaciones.
  invariante: |
    // El protocolo no debe estar en un estado intermedio cuando recibe un callback
    bool internal ghost_expectingCallback;

    function check_no_callback_reentrancy() internal view {
        // Solo debería haber un callback procesándose a la vez
        t(!ghost_expectingCallback,
          "CC-006: callback received during active cross-chain operation");
    }
  que_mirar:
    - "¿El protocolo envía mensajes Y puede recibir callbacks en la misma función?"
    - "¿Hay un mutex o state variable que bloquee operaciones durante mensajes en tránsito?"
    - "¿Los callbacks pueden llegar en orden diferente al que se enviaron los mensajes?"
    - "¿Qué pasa si el callback de la tx N llega antes que el de la tx N-1?"
  como_se_arregla: |
    - State machine explícita: IDLE → PENDING_CROSS_CHAIN → COMPLETED
    - Rechazar callbacks cuando el estado es IDLE (no había una operación pendiente)
    - Ordenar callbacks por sequence number (no procesar out-of-order)
  trampas:
    - "LayerZero en modo 'ordered delivery' garantiza orden, pero en modo default no"
    - "El atacante puede controlar cuándo se entrega un mensaje bloqueado (blocked delivery exploit)"
  solodit_ids: [7252, 64933, 6096]

- id: cc-007
  titulo: Gas Stipend Exhaustion — Cross-Chain Message Failure Loop
  causa_raiz: |
    Los mensajes cross-chain especifican un gas stipend para la ejecución en la cadena
    de destino. Si el gas es insuficiente, el mensaje falla. Dependiendo del bridge,
    el mensaje puede quedarse en estado "failed" permanentemente (funds stuck), o
    puede ser retriable pero el atacante puede forzar el fallo repetidamente.
  como_funciona: |
    Variante A — Stuck funds:
    1. El frontend calcula mal el gas necesario
    2. El mensaje llega a Chain B pero falla por out-of-gas
    3. Los tokens en Chain A están lockeados, los de Chain B no se mintearon
    4. Si el bridge no tiene retry mechanism con gas re-estimate, los fondos están atascados

    Variante B — Griefing via gas manipulation:
    1. El atacante puede hacer que la función receptora use más gas del especificado
    2. Por ejemplo, si el receptor llama a un contrato externo cuyo gas cost es variable
    3. El atacante infla el gas cost del contrato externo → el mensaje siempre falla
    4. Los fondos quedan atascados hasta que el owner intervenga
  invariante: |
    function check_message_deliverability(uint256 specifiedGas, bytes memory payload) internal pure {
        // Estimación conservadora del gas necesario
        uint256 estimatedGas = estimateExecutionGas(payload);
        t(specifiedGas >= estimatedGas * 120 / 100,
          "CC-007: gas stipend too low for reliable delivery (20% buffer required)");
    }
  que_mirar:
    - "¿El gas del mensaje es fijo o se estima dinámicamente?"
    - "¿Qué pasa con los fondos si el mensaje falla por gas?"
    - "¿Hay un mecanismo de retry con gas aumentado?"
    - "¿El receptor hace llamadas externas cuyo gas es variable?"
  como_se_arregla: |
    - Siempre añadir 20% buffer al gas estimado
    - Tener un fallback: si el mensaje falla, los fondos se liberan después de un timeout
    - El retry debe permitir al usuario especificar más gas
    - Los receptores no deben hacer llamadas externas con gas variable
  trampas:
    - "Optimism tiene precompiles con gas diferente en diferentes versiones del sistema — puede cambiar sin aviso"
    - "El gas de SSTORE puede cambiar con hard forks (EIP-1884, EIP-2929) — cálculos hardcodeados quedan incorrectos"
  solodit_ids: [64016, 3627, 5822]

- id: cc-008
  titulo: Intent Expiry Race Condition — Order Filled After Expiry
  causa_raiz: |
    Las órdenes de intents tienen un timestamp de expiración. Si la verificación de
    expiración usa block.timestamp en la cadena de destino (que puede diferir de la
    cadena de origen), o si hay un gap entre cuando el solver verifica la expiración
    y cuando se ejecuta el fill, la orden puede ejecutarse expirada.
  como_funciona: |
    Variante A — Timestamp difference between chains:
    1. Intent expira a timestamp T en Chain A (Ethereum)
    2. El solver verifica en Chain A: block.timestamp < T ✓ → envía fill transaction
    3. La transacción llega a Chain A a timestamp T+2 segundos (después de expiry)
    4. Si el check on-chain usa `<` en lugar de `<=`, hay un gap de 1 segundo explotable
    5. El solver pierde fondos (llena la orden pero no puede reclamar pago)

    Variante B — Solver MEV:
    1. Intent con expiry en bloque N
    2. En bloque N-1, el intent es lleno por el solver
    3. El solver puede observar si la tx será incluida en bloque N (después de expiry)
    4. Si hay reorg y la tx va al bloque N, el fill ocurre después de expiración
  invariante: |
    function check_intent_expiry(bytes32 intentId, uint256 expiryTimestamp) internal view {
        t(block.timestamp < expiryTimestamp,
          "CC-008: intent filled after expiry");
        t(expiryTimestamp >= block.timestamp + MIN_INTENT_DURATION,
          "CC-008: intent expiry too close to current time");
    }
  que_mirar:
    - "¿El check de expiración usa `<` o `<=`?"
    - "¿Qué chain/timestamp se usa como referencia para la expiración?"
    - "¿Hay un buffer entre la expiración del intent y la disponibilidad para cancelar?"
    - "¿Qué pasa con los fondos del solver si su fill se revierte post-expiración?"
  como_se_arregla: |
    - Usar `< expiryTimestamp - BUFFER` donde BUFFER es el worst-case block time
    - Los timestamps de expiración deben ser siempre en la cadena de origen
    - Reembolso automático al solver si el fill no puede reclamarse por expiración
  trampas:
    - "En L2s con sequencer, el timestamp puede manipularse dentro de ciertos límites"
    - "CoW Protocol usa batch settlement — los intents que expiran en medio del batch crean edge cases"
  solodit_ids: [49753, 35422, 64741]

- id: cc-009
  titulo: Cross-Chain Access Control — Admin Keys per Chain
  causa_raiz: |
    Los protocolos multi-chain frecuentemente tienen un "governance hub" en una chain
    (generalmente Ethereum mainnet) que controla los parámetros en otras chains vía
    mensajes cross-chain. Si el receptor en la chain destino no valida correctamente
    que el mensaje viene del governance hub, cualquiera puede ejercer control de admin.
  como_funciona: |
    1. El protocolo tiene un Timelock en Ethereum que envía mensajes a los contratos en L2
    2. El contrato L2 verifica: require(msg.sender == bridgeEndpoint, "only bridge")
    3. Pero no verifica que el originador del mensaje en L1 sea el Timelock
    4. Un atacante envía un mensaje desde cualquier contrato en L1 con calldata de admin
    5. El bridge lo entrega al contrato L2 — el check pasa (msg.sender == bridge)
    6. El atacante ejecuta funciones administrativas sin pasar por governance
  invariante: |
    function check_governance_message_origin(
        address srcSender, uint16 srcChainId
    ) internal view {
        t(srcChainId == GOVERNANCE_CHAIN_ID,
          "CC-009: governance message from wrong chain");
        t(srcSender == GOVERNANCE_TIMELOCK,
          "CC-009: governance message from non-timelock address");
    }
  que_mirar:
    - "¿El contrato receptor verifica TANTO el srcChainId COMO el srcSender?"
    - "¿El GOVERNANCE_TIMELOCK address está hardcodeado o es configurable?"
    - "¿Hay funciones admin que tienen un path directo (no solo vía bridge)?"
    - "¿El setter de GOVERNANCE_TIMELOCK también verifica el origen del mensaje?"
  como_se_arregla: |
    - Always: require(srcChainId == expectedChainId && srcSender == expectedSender)
    - Hardcodear el governance address en immutable, no en storage
    - El upgrade del governance address debe requerir la firma del propio governance
  trampas:
    - "Algunos adaptadores de LayerZero soportan múltiples 'trusted remote' por chain — un address comprometido afecta a todos"
    - "CCIP tiene concept de 'sender' pero muchos protocolos solo verifican la chain, no el sender"
  solodit_ids: [8856, 6655, 34498]

- id: cc-010
  titulo: Solver/Relayer Censorship — Liveness Failure
  causa_raiz: |
    Los sistemas de intents y bridges con relayers permisionados pueden ser censurados
    si los relayers rechazan procesar ciertas transacciones. Si no hay un path de
    fallback sin permiso, los usuarios pueden quedar con fondos atascados indefinidamente.
  como_funciona: |
    Variante A — Relayer strike:
    1. El único relayer autorizado es el protocolo mismo
    2. El protocolo es hackeado y el relayer se apaga
    3. Miles de mensajes pendientes quedan sin entregar
    4. No hay mecanismo para que otros los entreguen

    Variante B — Economic censorship:
    1. El relayer es permisionless pero requiere pago en un token específico
    2. El token del relayer se vuelve muy caro o deja de estar disponible
    3. Los usuarios no pueden pagar el fee → mensajes atascados

    Variante C — Solver cartel:
    1. En un sistema de intents con pocos solvers, los solvers coordinan para ignorar
       intents de ciertos usuarios o de ciertos tokens
    2. No hay mecanismo de "self-serve" que el usuario pueda usar como fallback
  invariante: |
    function check_liveness_guarantee(bytes32 intentId, uint256 submissionBlock) internal view {
        uint256 expiryBlock = submissionBlock + MAX_DELIVERY_BLOCKS;
        if (block.number > expiryBlock && !isDelivered(intentId)) {
            // Después del timeout, cualquiera debe poder cancelar y devolver fondos
            t(isRefundable(intentId),
              "CC-010: intent stuck beyond deadline with no refund path");
        }
    }
  que_mirar:
    - "¿Hay un timeout después del cual el usuario puede reclamar un refund sin el relayer?"
    - "¿El timeout es razonable para el caso de censura (días, no horas)?"
    - "¿Los usuarios pueden ser su propio relayer en último recurso?"
    - "¿Hay un mecanismo de escalada si el relayer principal falla?"
  como_se_arregla: |
    - Siempre incluir un "pessimistic path": si el intent no se llena en X tiempo, el usuario puede reclamar
    - El timeout debe ser largo (7 días) pero debe existir
    - Para bridges: permitir que cualquiera entregue el mensaje (permissionless delivery)
  trampas:
    - "Algunos protocolos tienen el timeout pero require pagar una penalización para usarlo (anti-spam) — si el token del protocolo cae, nadie puede pagar la penalización"
    - "Across Protocol tiene un 'optimistic' path que puede ser bloqueado por el HubPool owner durante 'liveness' failures"
  solodit_ids: [63991, 29031, 63998]
