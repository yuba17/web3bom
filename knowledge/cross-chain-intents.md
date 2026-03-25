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

- id: cc-011
  titulo: Dutch Auction Decay Miscalculation on L2 — Wrong block.number Reference
  causa_raiz: |
    Los sistemas de intents con Dutch auction decay (UniswapX, 1inch Fusion) calculan el
    precio decreciente en función de block.number o block.timestamp. En L2s como Arbitrum,
    block.number devuelve el número de bloque L1 aproximado (no el L2), causando que el
    decay sea ~48x más lento de lo esperado (12s vs 0.25s block time).
  como_funciona: |
    1. Un maker crea una orden UniswapX en Arbitrum con un decay de 8 segundos
    2. El contrato calcula blockDelta = currentBlock - startBlock
    3. En Arbitrum, block.number avanza cada ~12 segundos (L1), no cada 0.25s (L2)
    4. El decay que debería completarse en 8 segundos tarda ~6.4 minutos
    5. El filler obtiene un precio mucho más favorable del esperado porque el decay casi no avanza
    6. El maker pierde valor porque vende a un precio cercano al precio inicial durante mucho más tiempo
  invariante: |
    function check_decay_block_reference(uint256 startBlock, uint256 decayBlocks) internal view {
        // En L2s, verificar que se usa el block number correcto
        uint256 elapsed = block.number - startBlock;
        // Si el decay debería durar N bloques L2 pero usa L1 blocks, elapsed será ~48x menor
        t(elapsed <= decayBlocks * 2,
          "CC-011: decay block reference likely using wrong chain's block number");
    }
  que_mirar:
    - "¿El contrato usa block.number o block.timestamp para el decay?"
    - "¿En qué L2 está deployado? Arbitrum devuelve L1 block.number por defecto"
    - "¿Hay lógica condicional por chainId para ajustar el block reference?"
    - "¿El decay curve usa NonlinearDutchDecayLib u otra librería que asuma block time fijo?"
  como_se_arregla: |
    - En Arbitrum: usar ArbSys(100).arbBlockNumber() para obtener el L2 block number
    - Preferir block.timestamp sobre block.number (más portable entre chains)
    - Si se usa block.number, parametrizar el block time por chainId
  trampas:
    - "UniswapX tuvo exactamente este bug en NonlinearDutchDecayLib.sol#L38 — fixeado en PR 280"
    - "Optimism y Base SÍ devuelven L2 block.number, pero Arbitrum NO — no asumir comportamiento uniforme entre L2s"
  solodit_ids:
    - incorrect-use-of-l1-blocknumber-on-arbitrum-cantina-none-uniswap-pdf
  incidentes: []
  verificado: true
  confianza: 95

- id: cc-012
  titulo: Permit2 Front-Running DoS on Intent Deposits
  causa_raiz: |
    Cuando un protocolo de intents usa Permit2 para transferir tokens del usuario,
    un atacante puede front-run la transacción del usuario ejecutando el permit
    directamente en el contrato Permit2. Esto consume el nonce/allowance del permit,
    causando que la transacción original del usuario reverta.
  como_funciona: |
    1. El usuario firma un Permit2 para depositar tokens en el SpokePool de Across
    2. La transacción se envía al mempool con el signature + calldata
    3. Un atacante extrae el signature del mempool
    4. El atacante llama directamente a Permit2.permit() con el signature del usuario
    5. El permit se consume (nonce marcado como usado)
    6. La transacción original del usuario reverta porque el permit ya fue usado
    7. El atacante no gana fondos directamente, pero puede griefear sistemáticamente
    Variante agravada: si el contrato no tiene fallback a transferFrom con allowance
    previa, el usuario queda completamente bloqueado.
  invariante: |
    function check_permit2_fallback(address token, address user, uint256 amount) internal view {
        // El contrato debe poder operar tanto con Permit2 como con allowance directa
        uint256 allowance = IERC20(token).allowance(user, address(this));
        bool hasPermit2 = IPermit2(PERMIT2).allowance(user, token, address(this)).amount >= amount;
        t(allowance >= amount || hasPermit2,
          "CC-012: no fallback if Permit2 front-run — user funds stuck");
    }
  que_mirar:
    - "¿El contrato tiene un path alternativo si el permit2 falla (try/catch)?"
    - "¿La función acepta tanto permit como allowance directa?"
    - "¿El permit signature está en el mempool público o usa private relay?"
    - "¿Hay un wrapper que haga try permit → fallback transferFrom?"
  como_se_arregla: |
    - Envolver la llamada a permit en try/catch: si falla, verificar que ya hay allowance
    - Ofrecer dos funciones: depositWithPermit2() y deposit() con allowance directa
    - Usar flashbots/private mempool para transacciones con permits
  trampas:
    - "Across Protocol SpokePoolPeriphery.sol tenía este bug exacto en SwapProxy.performSwap()"
    - "El atacante no roba fondos pero puede hacer DoS selectivo contra usuarios específicos"
    - "DAI y tokens con permit no-EIP-2612 son especialmente vulnerables si la interfaz asume EIP-2612 estándar"
  solodit_ids:
    - possible-dos-attack-on-swapping-via-permit2-openzeppelin-none-periphery-changes-audit-markdown
    - 16-deposittointentwithpermit-rejects-noneip-2612-tokens-like-dai-code4rena-sequence-sequence-git
  incidentes: []
  verificado: true
  confianza: 90

- id: cc-013
  titulo: CoW Protocol ERC-1271 appData Surplus Extraction
  causa_raiz: |
    En CoW Protocol, el campo appData de una orden puede contener información de partner fees.
    Si un contrato implementa ERC-1271 isValidSignature() pero ignora el campo appData
    al verificar la firma, un atacante puede modificar el appData para redirigir el surplus
    de la orden a su propia dirección vía partner fees infladas.
  como_funciona: |
    1. Un vault/protocolo crea una orden CoW con isValidSignature() que valida precio, tokens, amounts
    2. El isValidSignature() NO valida el campo appData (lo ignora)
    3. Un solver malicioso o un MEV bot copia la orden pero cambia appData
    4. El nuevo appData contiene un partnerFee del 100% apuntando al atacante
    5. isValidSignature() retorna válido (porque no mira appData)
    6. CoW Protocol ejecuta la orden y envía todo el surplus al atacante vía partner fee
    7. El usuario/vault recibe el minAmount pero pierde todo el surplus
  invariante: |
    function check_cowswap_appdata_validated(
        bytes32 orderHash, bytes32 appData, bytes32 expectedAppData
    ) internal pure {
        t(appData == expectedAppData,
          "CC-013: CoW order appData not validated — surplus extraction possible");
    }
  que_mirar:
    - "¿El isValidSignature() del contrato valida el campo appData?"
    - "¿El contrato usa GPv2Order.Data completo o ignora ciertos campos?"
    - "¿Hay un hash precomputado del appData esperado que se compare?"
    - "¿El contrato interactúa con CowSwapFiller, CowSwapClone, o similar?"
  como_se_arregla: |
    - Incluir appData en la verificación de isValidSignature() — hashear el GPv2Order completo
    - Pre-computar y almacenar el appData esperado; rechazar cualquier otro
    - Si el contrato no necesita partner fees, forzar appData = bytes32(0)
  trampas:
    - "Trail of Bits encontró esto en Reserve Protocol CowSwapFiller — partnerFee podía drenar surplus"
    - "Pashov Audit Group lo encontró en Cove Protocol — el isValidSignature ignoraba appData"
    - "Es un bug sutil: la orden se ejecuta correctamente, el usuario recibe su minAmount, pero pierde potencialmente mucho surplus"
  solodit_ids:
    - order-surplus-extraction-trailofbits-none-reserve-protocol-solidity-400-pdf
    - m-02-loss-of-surplus-if-erc-1271-order-allows-arbitrary-data-pashov-audit-group-none-cove_2024-12-30-markdown
    - l-03-validation-in-isvalidsignature-prevents-partial-fills-at-good-prices-pashov-audit-group-none-reserve_2025-06-02-markdown
  incidentes: []
  verificado: true
  confianza: 95

- id: cc-014
  titulo: Solver Signature Bypass — Malicious Settlement Execution
  causa_raiz: |
    En protocolos de settlement basados en solvers, la verificación de firma del maker
    puede tener un fallback que acepta órdenes sin firma válida. Si el flag isMaker se
    configura incorrectamente por defecto, el solver puede ejecutar órdenes fabricadas
    sin que el maker las haya firmado.
  como_funciona: |
    1. El protocolo tiene settleSingle() que verifica la firma del maker
    2. validateSignature() intenta recover la firma; si falla, verifica que isMaker == false
    3. Por defecto, en validateOrder(), isMaker se inicializa como true
    4. El solver envía una firma inválida → recover falla → el check es "¿isMaker es false?"
    5. Como isMaker es true por defecto (bug), el check pasa incorrectamente
    6. El solver ejecuta una orden fabricada: transfiere tokens del maker sin su consentimiento
    7. El maker pierde sus tokens aprobados al contrato de settlement
  invariante: |
    function check_maker_signature_valid(
        address maker, bytes32 orderHash, bytes memory signature
    ) internal pure {
        address recovered = ECDSA.recover(orderHash, signature);
        t(recovered == maker,
          "CC-014: order executed without valid maker signature");
    }
  que_mirar:
    - "¿La verificación de firma tiene un fallback que acepta la orden sin firma válida?"
    - "¿El flag isMaker/isOrder se inicializa correctamente?"
    - "¿Qué pasa si ecrecover devuelve address(0)? ¿Se acepta la orden?"
    - "¿El solver puede elegir qué path de verificación usar?"
  como_se_arregla: |
    - Revert si la firma no es válida — sin fallbacks
    - Verificar que recovered != address(0) && recovered == maker
    - No usar flags booleanos para bypass de verificación
  trampas:
    - "Liquorice tenía exactamente este bug: isMaker=true por defecto causaba bypass de la verificación"
    - "En protocolos con ERC-1271, el fallback a contract signature puede ser abusado si el contrato no implementa isValidSignature correctamente"
  solodit_ids:
    - solver-can-bypass-maker-signature-verification-mixbytes-none-liquorice-markdown
  incidentes: []
  verificado: true
  confianza: 90

- id: cc-015
  titulo: Solver Fill Amount Overflow — Trader Spends More Than Expected
  causa_raiz: |
    Cuando el solver especifica el fill amount en la ejecución del settlement, puede
    establecer un valor mayor al esperado por el trader. Si no hay un upper-bound check,
    el trader gasta más tokens de lo que autorizó conceptualmente (aunque el allowance
    técnicamente lo permita).
  como_funciona: |
    1. Un trader tiene allowance al BalanceManager por 1000 USDC
    2. La orden del trader dice: vender 500 USDC por 0.25 ETH
    3. El solver establece SolverData.curFillAmount = 1000 (el máximo del allowance)
    4. El contrato transfiere 1000 USDC del trader (no los 500 de la orden)
    5. El trader recibe más del token de destino, pero gastó el doble de lo esperado
    6. Si el ratio es desfavorable, el trader pierde valor neto
    Variante: en partial fills, el solver puede inflar cada fill para drenar el allowance completo.
  invariante: |
    function check_fill_within_order_bounds(
        uint256 fillAmount, uint256 orderAmount, uint256 totalFilled
    ) internal pure {
        t(totalFilled + fillAmount <= orderAmount,
          "CC-015: fill amount exceeds order total");
    }
  que_mirar:
    - "¿El settlement verifica que curFillAmount <= order.amount - alreadyFilled?"
    - "¿El allowance del trader al contrato es unlimited (common pattern)?"
    - "¿settleSingle y settle tienen las mismas validaciones de bounds?"
    - "¿El solver puede llamar settle múltiples veces con el mismo orderId?"
  como_se_arregla: |
    - Verificar upper bound: fillAmount <= remainingOrderAmount en cada settlement
    - Trackear fills acumulados por orderId; revert si excede el total
    - Implementar el check tanto en settle() como en settleSingle()
  trampas:
    - "Liquorice settlement.settle() no verificaba upper bound pero settleSingle() sí — inconsistencia explotable"
    - "Si el trader usa unlimited approval (common en DeFi), el impacto es mucho mayor"
  solodit_ids:
    - liquoricesettlementsettle-does-not-check-for-upper-bound-when-using-solverdata-mixbytes-none-liquorice-markdown
  incidentes: []
  verificado: true
  confianza: 90

- id: cc-016
  titulo: Cross-Chain Gas Cost Asymmetry Attack — Spam Cheap Chain, Execute Expensive Chain
  causa_raiz: |
    En bridges como Across, los relayers son reembolsados en la chain que eligen o via el
    HubPool en Ethereum. Un atacante puede crear muchos depósitos pequeños en una chain
    barata (e.g., Solana, Polygon) que generen refund leaves que deben ejecutarse en una
    chain cara (Ethereum), imponiendo costos desproporcionados al dataworker.
  como_funciona: |
    1. El atacante deposita 100 veces 0.01 ETH en Polygon (gas cost: ~$0.001 por tx)
    2. Cada depósito genera un refund leaf para el relayer en Ethereum (gas cost: ~$5 por tx)
    3. El dataworker (servicio público) debe ejecutar 100 refund leaves en Ethereum
    4. Costo del atacante: ~$0.10 total en Polygon
    5. Costo impuesto al dataworker: ~$500 en gas de Ethereum
    6. El dataworker puede quedar insolvente o dejar de procesar refunds legítimos
    7. Usuarios legítimos sufren delays o pérdida de fondos
  invariante: |
    function check_deposit_covers_execution_cost(
        uint256 depositAmount, uint256 estimatedRefundGas, uint256 gasPrice
    ) internal pure {
        uint256 executionCost = estimatedRefundGas * gasPrice;
        t(depositAmount > executionCost * 2,
          "CC-016: deposit amount too small relative to cross-chain execution cost");
    }
  que_mirar:
    - "¿Hay un monto mínimo de depósito que cubra el gas de ejecución en la chain de destino?"
    - "¿El protocolo permite elegir la chain de reembolso sin restricción?"
    - "¿Los refund leaves se agregan en batches para amortizar gas?"
    - "¿El dataworker puede filtrar depósitos que no son económicamente viables?"
  como_se_arregla: |
    - Monto mínimo de depósito dinámico basado en gas estimado de la chain de destino
    - Fee mínimo que cubra el costo de ejecución cross-chain
    - Rate limiting por depositor en chains baratas
    - Agregar refund leaves en merkle trees para reducir gas por leaf
  trampas:
    - "OpenZeppelin encontró este bug en Across SVM Spoke — depósitos baratos en Solana generaban refunds caros en Ethereum"
    - "El atacante puede usar muchas wallets para bypass rate limits por address"
  solodit_ids:
    - exploitation-of-cost-asymmetries-across-chains-to-impose-high-gas-costs-on-refund-execution-openzeppelin-none-svm-spoke-audit-markdown
    - m-15-if-across-bridging-fails-all-funds-intended-for-bridging-will-become-locked-sherlock-malda-git
  incidentes: []
  verificado: true
  confianza: 90

- id: cc-017
  titulo: ERC-7683 Permit2 Witness Type Mismatch — Invalid Cross-Chain Order Signatures
  causa_raiz: |
    La integración de ERC-7683 (estándar de cross-chain orders) con Permit2 requiere
    especificar el tipo de datos witness correcto en permitWitnessTransferFrom(). Si el
    PERMIT2_ORDER_TYPE especifica CrossChainOrder pero el witness fue hasheado desde
    GaslessCrossChainOrder (o viceversa), las firmas son técnicamente inválidas o
    pueden ser reusadas entre tipos de orden diferentes.
  como_funciona: |
    1. El usuario firma una GaslessCrossChainOrder con Permit2 witness
    2. El contrato llama a permitWitnessTransferFrom con witnessTypeString = "CrossChainOrder"
    3. Pero el witness hash fue computado desde GaslessCrossChainOrder (tipo diferente)
    4. Permit2 valida el hash incorrecto — puede aceptar firmas que no deberían ser válidas
    5. Variante: si el encoding es compatible por coincidencia, ordenes de un tipo pueden
       ejecutarse como otro tipo, cambiando la semántica (e.g., gasless vs gas-paying)
  invariante: |
    function check_witness_type_matches(
        string memory declaredType, string memory actualType
    ) internal pure {
        t(keccak256(bytes(declaredType)) == keccak256(bytes(actualType)),
          "CC-017: Permit2 witness type mismatch");
    }
  que_mirar:
    - "¿El PERMIT2_ORDER_TYPE coincide con el tipo real del struct que se hashea como witness?"
    - "¿Hay múltiples tipos de orden (CrossChainOrder, GaslessCrossChainOrder) que comparten el mismo witness type?"
    - "¿El witness hash incluye todos los campos del struct, o solo un subset?"
    - "¿Una firma para OrderTypeA podría ser válida para OrderTypeB?"
  como_se_arregla: |
    - Asegurarse de que el witnessTypeString coincida exactamente con el struct del witness
    - Tener PERMIT2_ORDER_TYPE separado para cada tipo de orden
    - Incluir el orderType como campo en el witness hash para disambiguación
  trampas:
    - "OpenZeppelin encontró esto en Across ERC7683Across.sol — el tipo decía CrossChainOrder pero el witness era GaslessCrossChainOrder"
    - "ERC-7683 define dos tipos de orden: CrossChainOrder y GaslessCrossChainOrder — cada uno necesita su propio type string para Permit2"
  solodit_ids:
    - incorrect-parameters-passed-to-permitwitnesstransferfrom-openzeppelin-none-across-audit-markdown
  incidentes: []
  verificado: true
  confianza: 90

- id: cc-018
  titulo: Intent Proving State Poisoning — Block Number Griefing
  causa_raiz: |
    En protocolos de intents cross-chain que usan proofs de estado mundial (world state proofs),
    el mapping provenStates[chainId].blockNumber puede ser sobreescrito por cualquiera con un
    valor arbitrariamente alto, bloqueando todas las pruebas futuras de intents en esa chain.
  como_funciona: |
    1. Un solver cumple intents y necesita probar su ejecución llamando proveIntent()
    2. Antes de probar un intent, debe llamar proveWorldStateCannon() para validar el state root
    3. proveWorldStateCannon() escribe provenStates[chainId].blockNumber con el bloque probado
    4. Un atacante llama proveWorldStateCannon() con blockNumber = type(uint256).max
    5. Si la función no verifica que el nuevo block sea mayor que el actual de forma segura,
       o si acepta cualquier block con un DisputeGame resuelto, el mapping se corrompe
    6. Todas las llamadas futuras a proveIntent() fallan porque requieren blockNumber >= provenBlock
    7. Los solvers no pueden cobrar sus rewards — pérdida masiva de fondos
  invariante: |
    function check_proven_block_reasonable(
        uint256 chainId, uint256 newBlock
    ) internal view {
        uint256 currentBlock = provenStates[chainId].blockNumber;
        // El nuevo block no debe saltar más de MAX_BLOCK_JUMP
        t(newBlock <= currentBlock + MAX_BLOCK_JUMP || currentBlock == 0,
          "CC-018: proven block number jumped unreasonably — possible griefing");
    }
  que_mirar:
    - "¿Quién puede llamar a proveWorldState()? ¿Es permissionless?"
    - "¿El blockNumber nuevo se valida contra el blockNumber actual (debe ser razonable)?"
    - "¿Hay un check de que newBlock > currentBlock pero también newBlock < currentBlock + MAX_JUMP?"
    - "¿El DisputeGame/fault proof puede ser forzado a resolver con un block falso?"
  como_se_arregla: |
    - Restringir proveWorldState() a solvers registrados o a un caller autorizado
    - Validar que newBlock está en un rango razonable (currentBlock, currentBlock + MAX_JUMP)
    - No permitir sobreescribir provenStates si el nuevo block es menor que el actual
  trampas:
    - "Cantina encontró esto en Eco Inc Prover.sol — cualquiera podía setear blockNumber a type(uint256).max"
    - "El atacante no necesita fondos ni ser solver — la función era completamente permissionless"
  solodit_ids:
    - anyone-can-arbitrarily-set-provenstateschainidblocknumber-in-proveworldstatecannon-to-prevent-proving-of-all-intents-cantina-none-eco-inc-pdf
  incidentes: []
  verificado: true
  confianza: 95

- id: cc-019
  titulo: Aggregator/Router Arbitrary Call Injection — Token Theft via Unwhitelisted Calldata
  causa_raiz: |
    Los routers de bridges y aggregadores (LI.FI, Socket, Squid) ejecutan swaps en la chain
    de destino usando calldata proporcionada externamente. Si el router no whitelistea las
    addresses de destino de los calls, un atacante puede inyectar calldata que llame a
    funciones arbitrarias (approve, transfer) en tokens que el router tiene en custodia.
  como_funciona: |
    1. El router (e.g., LI.FI Executor) recibe tokens del bridge en la chain de destino
    2. El router ejecuta swaps usando _executeSwaps() con calldata del usuario
    3. La función permite llamar a cualquier address excepto una (erc20Proxy)
    4. El atacante construye calldata que llama a: token.approve(attacker, type(uint256).max)
    5. El router ejecuta el approve — ahora el atacante tiene allowance ilimitado
    6. El atacante llama a token.transferFrom(router, attacker, balance) y roba los fondos
    Variante Axelar: el atacante puede enviar un mensaje cross-chain falso que se ejecute
    en el Executor, robando los tokens del bridge.
  invariante: |
    function check_swap_target_whitelisted(address target) internal view {
        t(isWhitelistedDex[target],
          "CC-019: swap target not in DEX whitelist — arbitrary call possible");
        t(target != address(0),
          "CC-019: swap target is zero address");
    }
  que_mirar:
    - "¿_executeSwaps() tiene un whitelist de addresses permitidas?"
    - "¿El router puede recibir tokens y ejecutar calls arbitrarios en el mismo contexto?"
    - "¿El router hereda de IAxelarExecutable u otro receptor de bridge?"
    - "¿Hay tokens residuales (leftover) en el router entre transacciones?"
    - "¿El function selector del calldata se valida (no solo la address)?"
  como_se_arregla: |
    - Whitelist de DEX addresses permitidas — revert si el target no está en la lista
    - Validar el function selector del calldata (solo swap/exchange, no approve/transfer)
    - No mantener tokens residuales en el router (sweep al final de cada tx)
    - Separar el ejecutor de swaps del receptor de bridge (diferentes contratos)
  trampas:
    - "LI.FI perdió $11.6M en julio 2024 exactamente por este patrón — calldata arbitrario en el swap facet"
    - "Spearbit encontró que LI.FI Executor.sol no whitelisteaba addresses mientras SwapperV2.sol sí"
    - "El bridge con Axelar era especialmente peligroso porque el Executor heredaba IAxelarExecutable"
  solodit_ids:
    - executeswaps-ofexecutorsol-doesnt-have-a-whitelist-spearbit-lifi-pdf
    - bridge-with-axelar-can-be-stolen-with-malicious-external-call-spearbit-lifi-pdf
    - too-generic-calls-in-genericbridgefacet-allow-stealing-of-tokens-spearbit-lifi-pdf
    - improve-dexallowlist-spearbit-lifi-pdf
  incidentes:
    - "LI.FI hack julio 2024 — $11.6M robados via arbitrary call injection en swap facet"
  verificado: true
  confianza: 95

- id: cc-020
  titulo: Approval Source Ambiguity in Permit2 — Executor Chooses Spending Path
  causa_raiz: |
    En protocolos que soportan tanto Permit2 como allowance directa (ERC-20 approve),
    si la elección del mecanismo de aprobación (usePermit2 flag) no es parte del hash
    de la orden firmada por el maker, el executor/solver puede elegir qué path usar.
    Esto permite explotar allowances que el maker no esperaba que se consumieran.
  como_funciona: |
    1. Un maker firma una orden y tiene: (a) allowance limitada al vault, (b) allowance ilimitada a Permit2
    2. El maker espera que se use la allowance limitada al vault (por seguridad)
    3. El executor ve usePermit2=true/false no es parte de la firma
    4. El executor elige usePermit2=true → usa la allowance ilimitada de Permit2
    5. El executor ejecuta la orden por más del monto esperado usando la allowance ilimitada
    Variante: si el maker revoca la allowance directa pero tiene Permit2 activo, el executor
    puede seguir ejecutando vía Permit2 contra la voluntad del maker.
  invariante: |
    function check_approval_source_signed(
        bytes32 orderHash, bool usePermit2, bytes32 signedOrderHash
    ) internal pure {
        // El hash de la orden debe incluir el flag usePermit2
        bytes32 expectedHash = keccak256(abi.encode(signedOrderHash, usePermit2));
        t(orderHash == expectedHash,
          "CC-020: approval source not part of signed order — executor can choose path");
    }
  que_mirar:
    - "¿El flag usePermit2 es parte del hash de la orden firmada?"
    - "¿El executor puede elegir entre Permit2 y transferFrom directo?"
    - "¿El maker tiene allowance a Permit2 ilimitada (common pattern)?"
    - "¿El contrato verifica que el maker autorizó específicamente el path usado?"
  como_se_arregla: |
    - Incluir usePermit2 en el order hash que firma el maker
    - O: usar exclusivamente un mecanismo (solo Permit2 o solo allowance directa)
    - Si se soportan ambos, que el maker especifique cuál en la orden
  trampas:
    - "MixBytes encontró esto en Barter DAO — usePermit2 no era parte del order hash"
    - "Los usuarios de DeFi frecuentemente tienen allowance ilimitada a Permit2 sin saberlo"
    - "Revocar la allowance directa no protege si Permit2 sigue activo — muchos usuarios no lo saben"
  solodit_ids:
    - approval-source-ambiguity-mixbytes-none-barter-dao-markdown
    - cowexecutor-dos-via-approval-manipulation-mixbytes-none-barter-dao-markdown
  incidentes: []
  verificado: true
  confianza: 85
