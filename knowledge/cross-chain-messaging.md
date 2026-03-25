# Cross-Chain Messaging Protocols — Bug Patterns

> Attack surface: message authentication, gas estimation, compose/callback flows, executor trust,
> message ordering, and protocol-specific quirks in LayerZero V1/V2, Wormhole, Hyperlane, Axelar,
> and Chainlink CCIP. This briefing covers MESSAGING PROTOCOLS — not token bridges (see bridge.md)
> or OP Stack withdrawal flows (see bridge-opstack.md).
> Sources: Code4rena, Sherlock, Spearbit, Trust Security, Halborn, Cyfrin audits; real-world exploits.

## Quick Reference

```
grep_targets:
  - lzReceive
  - _lzReceive
  - _nonblockingLzReceive
  - _blockingLzReceive
  - nonblockingLzReceive
  - lzCompose
  - _lzCompose
  - sendCompose
  - endpoint
  - ILayerZeroEndpoint
  - EndpointV2
  - setTrustedRemote
  - trustedRemoteLookup
  - setPeer
  - OApp
  - OFTCore
  - adapterParams
  - OptionsBuilder
  - addExecutorLzReceiveOption
  - addExecutorLzComposeOption
  - _storeFailedMessage
  - storedPayload
  - retryMessage
  - failedMessages
  - parseVAA
  - verifyVM
  - guardianSet
  - verifySignatures
  - ccipReceive
  - _ccipReceive
  - CCIPReceiver
  - Client.EVM2AnyMessage
  - RateLimiter
  - TokenPool
  - interchainSecurityModule
  - ISM
  - Mailbox
  - dispatch
  - process
  - handle
  - executeWithToken
  - validateContractCall
  - IAxelarGateway
  - _execute
  - _executeWithToken
  - commandId
  - sourceChain
  - sourceAddress
```

---

## 1. LayerZero V1 Blocking Receive DoS

```yaml
- id: ccm-001
  titulo: Canal LayerZero V1 bloqueado permanentemente por mensaje envenenado
  causa_raiz: |
    LayerZero V1 usa un sistema de entrega ORDENADO. Si un mensaje falla en lzReceive()
    en destino, se almacena en storedPayload y TODOS los mensajes posteriores del mismo
    canal quedan bloqueados hasta que se reintente el mensaje fallido. Un atacante puede
    enviar deliberadamente un mensaje que siempre falla (gas insuficiente, payload
    oversized, receiver que revierte) para bloquear permanentemente el canal.
  como_funciona: |
    1. Atacante identifica protocolo usando LayerZero V1 con modo blocking (por defecto).
    2. Atacante envía mensaje con gas limit extremadamente bajo o payload que excede
       el gas limit del bloque de la cadena destino.
    3. En destino, Endpoint.lzReceive() falla y almacena el payload en storedPayload[].
    4. Todos los mensajes posteriores del mismo srcChainId + srcAddress quedan bloqueados.
    5. Si el mensaje fallido es irrecuperable (e.g., receiver siempre revierte), el canal
       queda permanentemente muerto.
    Variante NonblockingLzApp: el patrón try-catch supuestamente mitiga esto, pero si el
    try-catch mismo consume más gas del disponible (e.g., almacenar payload grande en
    failedMessages), el catch falla y VUELVE al modo blocking.
  invariante: |
    // Ningún mensaje individual puede bloquear permanentemente el canal
    // Post-condición: tras cualquier lzReceive, el canal debe aceptar nuevos mensajes
    assert(endpoint.hasStoredPayload(srcChainId, srcAddress) == false ||
           canRetryStoredPayload(srcChainId, srcAddress));
  que_mirar:
    - "¿El protocolo usa LzApp (blocking) o NonblockingLzApp?"
    - "Si usa NonblockingLzApp, ¿hay gas suficiente para el try-catch + almacenar payload?"
    - "¿Existe validación de tamaño de payload antes de enviar?"
    - "¿Se puede setear gasLimit arbitrariamente bajo desde el lado sender?"
    - "grep: _blockingLzReceive, storedPayload, retryPayload, _storeFailedMessage"
    - "grep: excessivelySafeCall, nonblockingLzReceive, failedMessages"
  como_se_arregla: |
    Usar NonblockingLzApp con gas reservado para el almacenamiento de mensajes fallidos.
    Validar tamaño mínimo de payload y gas limit mínimo en el sender.
    En V2 el problema se resuelve con el modelo non-blocking por defecto.
    Cap máximo de payload on-chain, no solo off-chain.
  trampas:
    - "NonblockingLzApp NO es inmune — si el catch OOGs, revierte al blocking"
    - "Diferentes cadenas tienen gas limits muy distintos (Arbitrum ~32M, Optimism ~20M)"
    - "En LZ V2 este patrón se eliminó — el Endpoint es non-blocking por diseño"
  solodit_ids:
    - "h-02-attacker-can-block-layerzero-channel-code4rena-tapioca-tapioca-git"
    - "h-01-layerzero-channel-can-be-blocked-by-setting-low-gas-parameters-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git"
    - "m-12-non-blocking-layerzero-cross-chain-buy-operations-can-be-blocked-pashov-audit-group-none-stationx-markdown"
  incidentes:
    - "Tapioca DAO (C4, HIGH) — BaseUSDO/BaseTOFT envían mensajes LZ con payload unbounded; atacante envía max payload, wrapper OOGs al almacenar, canal permanentemente bloqueado"
    - "Maia/Ulysses (C4, HIGH) — callOut prefixed functions sin check de gas mínimo; atacante pasa 0 gas en adapter params, storedPayload bloquea todas las operaciones cross-chain"
    - "UXD Protocol (Sherlock, HIGH) — OFTCore#sendFrom acepta _toAddress de longitud arbitraria; Arbitrum->Optimism con _toAddress enorme excede gas limit de Optimism"
    - "Holograph (C4, HIGH) — Sin límite en gasLimit definido por usuario; atacante pone gasLimit > block gas limit de destino; operador no puede ejecutar job, pierde bond"
```

---

## 2. LayerZero V2 Executor Gas Manipulation

```yaml
- id: ccm-002
  titulo: Gas insuficiente para lzReceive/lzCompose en LayerZero V2 causa fondos atascados
  causa_raiz: |
    En LayerZero V2, el sender especifica opciones de gas para el Executor en destino
    mediante OptionsBuilder. Si el gas especificado para lzReceive o lzCompose es
    insuficiente para la ejecución real, el mensaje falla en destino. Aunque V2 es
    non-blocking (no bloquea el canal), los fondos/tokens ya quemados en origen quedan
    sin contrapartida en destino. El Executor entrega exactamente el gas especificado.
  como_funciona: |
    1. Protocolo usa addExecutorLzReceiveOption(gasLimit) con valor hardcodeado o
       estimación incorrecta (e.g., basada en payload stub en vez de payload real).
    2. Mensaje enviado: tokens quemados en origen, Endpoint acepta el mensaje.
    3. Executor en destino llama lzReceive() con exactamente gasLimit especificado.
    4. Si la lógica de _lzReceive consume más gas (e.g., mints, swaps, callbacks),
       la ejecución revierte.
    5. V2 almacena el mensaje como "failed" — requiere retry manual, pero si la lógica
       SIEMPRE consume más gas del asignado, el retry también falla.
    Variante lzCompose: si se usa compose messaging (lzCompose), el gas para compose
    se especifica SEPARADAMENTE. Olvidar addExecutorLzComposeOption() o poner gas
    insuficiente deja el compose step sin ejecutar.
  invariante: |
    // Gas estimado >= gas real consumido en destino
    // Para cada tipo de mensaje, el gas option debe cubrir el worst case
    uint256 estimatedGas = _getGasForMessageType(msgType);
    uint256 actualGas = gasleft(); // medido en test
    assert(estimatedGas >= actualGas);
  que_mirar:
    - "¿Gas hardcodeado o calculado dinámicamente según payload?"
    - "¿Se usa addExecutorLzComposeOption() cuando hay compose messages?"
    - "¿El gas estimation usa el payload REAL o un stub más corto?"
    - "¿Hay enforceOptions() en OApp para prevenir gas insuficiente?"
    - "grep: addExecutorLzReceiveOption, addExecutorLzComposeOption, OptionsBuilder"
    - "grep: enforceOptions, _lzReceive, lzCompose, sendCompose"
  como_se_arregla: |
    Usar enforceOptions() para establecer gas mínimo por tipo de mensaje.
    Calcular gas basándose en worst-case payload, no en stubs.
    Testear con gas profiling real en cada cadena destino.
    Para compose: siempre incluir addExecutorLzComposeOption con gas suficiente.
  trampas:
    - "50,000 gas puede ser suficiente para un transfer simple, pero NO para mint+swap+callback"
    - "Diferentes chains tienen costos de gas distintos — lo que funciona en Ethereum puede fallar en Arbitrum y viceversa"
    - "enforceOptions() es la defensa de V2, pero solo funciona si se configura correctamente"
  solodit_ids:
    - "h-31-on-ulysses-omnichain-retrievedeposit-might-never-be-able-to-trigger-the-fallback-function-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git"
    - "h-02-decentbridgeexecutor-permits-arbitrary-calls-code4rena-decent-decent-git"
  incidentes:
    - "Decent Protocol (C4, HIGH) — DecentBridgeExecutor permite calls arbitrarias que fuerzan OOG sin importar gas limit; canal LZ V2 bloqueado permanentemente para compose"
    - "Mozaic Archimedes (Trust Security, MEDIUM) — MozBridge estima gas con payload stub (32 bytes); payload real incluye Snapshot struct completo; send() revierte por gas insuficiente"
    - "Holograph (C4, HIGH) — LayerZeroModule usa gas config de la cadena origen para destino; cuando las chains difieren, lzReceive OOGs y NFT perdido para siempre"
```

---

## 3. Trusted Remote / Peer Misconfiguration

```yaml
- id: ccm-003
  titulo: Suplantación cross-chain por trustedRemote/peer mal configurado o sin validar
  causa_raiz: |
    En LayerZero V1, setTrustedRemote() define qué dirección en qué chain puede enviar
    mensajes al contrato. En V2, setPeer() cumple la misma función. Si la configuración
    es incorrecta (dirección equivocada, address(0), falta de configuración en una chain),
    un atacante puede enviar mensajes desde una dirección no autorizada o explotar la
    ausencia de validación para suplantar al contrato legítimo en la chain origen.
  como_funciona: |
    1. Protocolo despliega en Chain A y Chain B, pero olvida configurar trustedRemote
       en una dirección, o lo configura con address(0).
    2. Atacante despliega contrato en Chain B con la misma interfaz.
    3. Si trustedRemoteLookup[srcChainId] == 0 y el check es débil (== en vez de !=),
       cualquier mensaje pasa la validación.
    4. Atacante envía mensaje falso: mint tokens, ejecutar governance, mover fondos.
    Variante: en setTrustedRemote V2 (ULN), el path incluye AMBAS direcciones
    (remote + local) concatenadas. Si se invierte el orden o se omite la local,
    la validación falla en silencio y acepta mensajes de cualquiera.
  invariante: |
    // trustedRemote nunca debe ser address(0) para una chain activa
    // Solo mensajes del peer configurado deben ser aceptados
    require(trustedRemoteLookup[srcChainId].length > 0, "No trusted remote");
    require(keccak256(trustedRemoteLookup[srcChainId]) ==
            keccak256(abi.encodePacked(srcAddress, address(this))), "Invalid remote");
  que_mirar:
    - "¿setTrustedRemote verifica que la dirección no es address(0)?"
    - "¿El path incluye remote + local en el orden correcto (abi.encodePacked)?"
    - "¿Quién puede llamar setTrustedRemote/setPeer? ¿Solo owner?"
    - "¿Se configura en AMBAS direcciones (A→B y B→A)?"
    - "grep: setTrustedRemote, trustedRemoteLookup, setPeer, _getPeerOrRevert"
    - "grep: isTrustedRemote, _origin, srcChainId"
  como_se_arregla: |
    Validar que trustedRemote nunca sea address(0) ni bytes(0).
    Usar scripts de deploy que configuren TODOS los peers en todas las chains atómicamente.
    Incluir la dirección local en el path (ULN V2 format).
    Usar setPeer con validación de que el peer ya existe en destino.
  trampas:
    - "En V2 los peers se almacenan como bytes32 — asegurarse de hacer el padding correcto para direcciones EVM (bytes32(uint256(uint160(addr))))"
    - "Si el contrato tiene setPeer público sin onlyOwner, cualquiera puede cambiar el peer"
    - "Verificar que el peer se configura BIDIRECCIONALMENTE — si solo se configura A→B pero no B→A, los mensajes de retorno fallan"
  solodit_ids:
    - "missing-source-validation-in-ccip-message-handling-cyfrin-none-yieldfi-markdown"
    - "m-05-bridge-watcher-can-forge-arbitrary-message-and-drain-bridge-code4rena-taiko-taiko-git"
    - "usage-of-txorigin-ottersec-none-folks-finance-x-chain-pdf"
  incidentes:
    - "Derby Finance (Sherlock, HIGH) — XProvider.onlySource verifica trustedRemoteConnext[_origin] pero no verifica que != address(0); Connext slow path entrega address(0), permitiendo manipulación total del vault state"
    - "Connext (Spearbit, MEDIUM) — GnosisBase._verifySender verifica msg.sender y messageSender pero NO messageSourceChainId; connector en otra chain con misma dirección puede spoofear roots"
    - "YieldFi (Cyfrin, MEDIUM) — Falta validación de source en handling de mensajes CCIP; cualquier chain puede enviar mensajes al handler"
```

---

## 4. Wormhole VAA Forgery and Replay

```yaml
- id: ccm-004
  titulo: Falsificación o replay de Wormhole VAA por validación insuficiente
  causa_raiz: |
    Wormhole usa Verified Action Approvals (VAAs) firmados por un quorum de Guardians
    para autenticar mensajes cross-chain. La validación requiere verificar firmas del
    guardian set, sequence number (anti-replay), emitter chain/address, y consistencyLevel.
    Si cualquiera de estas verificaciones falta o tiene un bypass, un atacante puede
    forjar o replayar VAAs para ejecutar acciones no autorizadas (mint, withdraw, governance).
  como_funciona: |
    Replay:
    1. Protocolo procesa VAA pero no marca el hash como "consumido" en un mapping.
    2. Atacante toma un VAA legítimo ya procesado y lo resubmite.
    3. Sin check de replay (isCompleted[hash]), la acción se ejecuta otra vez.
    Forgery (Wormhole hack 2022):
    1. Atacante encuentra bypass en la verificación de firmas de Guardians.
    2. En el caso real, el contrato Solana usaba una syscall deprecada
       (load_instruction_at) que no validaba la dirección del system program.
    3. Atacante inyecta un set de Guardians falso y firma su propio VAA.
    4. VAA aceptado como válido → mint de 120K wETH ($326M).
  invariante: |
    // Cada VAA se procesa exactamente una vez
    require(!isCompleted[vaaHash], "Already processed");
    isCompleted[vaaHash] = true;
    // Firmas deben ser de guardians activos con quorum alcanzado
    require(verifySignatures(vaa) == true);
    require(signaturesCount >= guardianSet.length * 2 / 3 + 1);
  que_mirar:
    - "¿Se verifica isCompleted/isConsumed ANTES de ejecutar la acción?"
    - "¿La verificación de firmas usa el guardian set ACTUAL (no uno expirado)?"
    - "¿Se valida emitterChainId + emitterAddress para impedir replay cross-chain?"
    - "¿El sequence number se trackea por emitter para evitar gaps?"
    - "grep: parseAndVerifyVM, verifyVM, isCompleted, parseVAA"
    - "grep: guardianSetIndex, guardianSet, consistencyLevel"
  como_se_arregla: |
    Marcar VAA como consumido ANTES de ejecutar la acción (checks-effects-interactions).
    Validar guardian set index contra el set actual del core bridge.
    Verificar emitterChainId + emitterAddress match el contrato esperado en la chain origen.
    Usar sequence numbers monotónicos por emitter.
  trampas:
    - "El Wormhole hack de 2022 fue en Solana (Sealevel), no en EVM — el vector exacto no aplica a contratos Solidity"
    - "En EVM, la verificación de firmas es estándar via ecrecover — difícil de bypass, pero la falta de check del guardian set index es el riesgo real"
    - "No confundir VAA replay (mismo VAA dos veces) con message replay (misma acción, diferente VAA)"
  solodit_ids:
    - "invalid-message-replay-design-ottersec-none-olympus-dao-pdf"
  incidentes:
    - "Wormhole Hack (Feb 2022, $326M) — Contrato Solana usaba load_instruction_at deprecada para verificar firmas; atacante inyectó guardian set falso, firmó VAA para mintear 120K wETH"
    - "Nomad Bridge (Aug 2022, $190M) — Upgrade de Replica contract inicializó trusted root a 0x00; cualquier mensaje con proof vacío era aceptado como válido; hack 'crowd-sourced' donde cientos de atacantes copiaron el tx del exploiter original"
```

---

## 5. Adapter Params / Options Gas Griefing

```yaml
- id: ccm-005
  titulo: Gas limit en adapterParams controlado por usuario causa fondos atascados
  causa_raiz: |
    En LayerZero V1, adapterParams contiene el gasLimit que el Relayer usa para ejecutar
    lzReceive en destino. Si el usuario puede controlar este valor sin validación
    (minDstGas no configurado o no chequeado), puede especificar gas insuficiente.
    Los tokens se queman en origen pero la ejecución en destino falla. Si no hay
    mecanismo de retry o el retry también requiere el mismo gas insuficiente, los fondos
    quedan permanentemente atascados.
  como_funciona: |
    1. Protocolo expone función de envío cross-chain que acepta adapterParams del usuario.
    2. Atacante o usuario descuidado pasa adapterParams con gasLimit = 1 (o muy bajo).
    3. Tokens quemados/bloqueados en cadena origen.
    4. Relayer en destino intenta ejecutar con gas = 1 → lzReceive revierte.
    5. En modo blocking: canal bloqueado (ver ccm-001).
    6. En modo non-blocking: mensaje almacenado como fallido, pero retryPayload
       también falla si el gasLimit original era too low.
    7. Fondos perdidos para el usuario.
  invariante: |
    // Gas limit mínimo siempre configurado y validado
    uint16 version = 1;
    uint256 gasLimit = abi.decode(adapterParams, (uint16, uint256));
    require(gasLimit >= minDstGasLookup[dstChainId][packetType], "Gas too low");
  que_mirar:
    - "¿minDstGasLookup está configurado para cada chain y packet type?"
    - "¿Se valida adapterParams en _checkGasLimit() o equivalente?"
    - "¿El usuario puede pasar bytes(0) como adapterParams (default gas)?"
    - "¿Hay rescue/recovery mechanism para fondos de mensajes fallidos?"
    - "grep: adapterParams, minDstGasLookup, _checkGasLimit, useCustomAdapterParams"
    - "grep: setMinDstGas, bytes memory _adapterParams"
  como_se_arregla: |
    Configurar minDstGasLookup para cada dstChainId y packetType.
    Activar _checkGasLimit() en cada send().
    Considerar hardcodear adapterParams si los usuarios no necesitan controlar el gas.
    Implementar refund mechanism para mensajes permanentemente fallidos.
  trampas:
    - "El default gas (cuando adapterParams = bytes(0)) puede ser 200K — suficiente para transfers simples pero no para lógica compleja"
    - "Validar que minDstGasLookup se configura en el deploy, no solo en documentación"
    - "En V2 esto se reemplaza por enforceOptions — distinto mecanismo, mismo riesgo si no se configura"
  solodit_ids:
    - "h-02-attacker-can-block-layerzero-channel-code4rena-tapioca-tapioca-git"
    - "h-31-on-ulysses-omnichain-retrievedeposit-might-never-be-able-to-trigger-the-fallback-function-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git"
    - "pause-modifier-in-bridge-receiver-functions-causes-receiver-failures-for-in-flight-messages-cyfrin-none-securitize-onofframp-bridge-markdown"
  incidentes:
    - "Maia Ulysses (C4, HIGH) — callOut functions no validan gas mínimo; atacante pasa adapter params con gas 0; canal bloqueado, retrieve deposit nunca triggerea fallback"
    - "Tapioca (C4, HIGH) — Falta check de gas mínimo en adapter params; atacante envía mensaje con gas insuficiente, NonblockingLzApp catch OOGs"
    - "Securitize (Cyfrin, MEDIUM) — pause modifier en bridge receiver causa failure para mensajes in-flight; tokens stuck en origen sin retry path"
```

---

## 6. Message Replay Across Chains (Missing Chain ID)

```yaml
- id: ccm-006
  titulo: Replay de mensaje cross-chain por chain ID ausente en hash
  causa_raiz: |
    El hash del mensaje cross-chain no incluye el chain ID de destino (o el de origen).
    Un mensaje válido para Chain A puede ser replayeado en Chain B si ambas chains
    tienen el mismo contrato desplegado (misma dirección por CREATE2). El atacante
    simplemente retransmite el mismo mensaje con las mismas firmas a otra chain.
  como_funciona: |
    1. Protocolo envía mensaje de Chain A → Chain B con payload = hash(sender, nonce, data).
    2. El hash NO incluye destinationChainId.
    3. Atacante observa el mensaje relayeado en Chain B.
    4. Atacante retransmite el MISMO mensaje a Chain C (donde el contrato existe con
       la misma dirección).
    5. Chain C acepta el mensaje porque el hash y las firmas son válidos.
    6. Acción ejecutada dos veces: double-mint, double-withdraw, etc.
  invariante: |
    // El hash del mensaje DEBE incluir source chain ID Y destination chain ID
    bytes32 messageHash = keccak256(abi.encodePacked(
        srcChainId, dstChainId, sender, nonce, payload
    ));
    require(!processedMessages[messageHash], "Already processed");
    processedMessages[messageHash] = true;
  que_mirar:
    - "¿El hash del mensaje incluye srcChainId Y dstChainId?"
    - "¿El contrato verifica que block.chainid == expectedDestChainId?"
    - "¿Se usan CREATE2 deployments con salt que incluya chain ID?"
    - "¿Las firmas del mensaje incluyen chain-specific data?"
    - "grep: keccak256, messageHash, chainId, block.chainid"
    - "grep: abi.encodePacked.*nonce.*payload"
  como_se_arregla: |
    Incluir srcChainId + dstChainId en el hash del mensaje.
    Verificar block.chainid en el receiver contra el dstChainId esperado.
    Usar EIP-712 domain separator con chainId para firmas.
    Nonce per-chain, no global.
  trampas:
    - "LayerZero, Wormhole, CCIP ya incluyen chain IDs en sus mensajes nativos — este bug aparece en implementaciones CUSTOM sobre estos protocolos"
    - "CREATE2 deployments en múltiples chains con misma dirección amplifica el riesgo"
    - "block.chainid puede cambiar en forks (e.g., Ethereum Classic vs Ethereum post-merge)"
  solodit_ids:
    - "invalid-message-replay-design-ottersec-none-olympus-dao-pdf"
    - "l-06-uln302-verifiable-conflates-distinct-failure-states-with-verified-breaking-off-chain-relayer-logic-code4rena-layerzero-layerzero-git"
  incidentes:
    - "Harpie — changeRecipientAddress signature sin chain.id; atacante replica en cadena objetivo via creación de dirección estilo Wintermute (MEDIUM)"
    - "Stakehouse Protocol — deployLPToken usa Clones.clone sin validación de chain.id; replay cross-chain roba LP funds (MEDIUM)"
    - "Olympus DAO (OtterSec) — diseño de replay de mensajes inválido; messageId no incluye chain-specific data"
```

---

## 7. Destination Revert with Source Funds Locked

```yaml
- id: ccm-007
  titulo: Revert en destino con fondos ya bloqueados/quemados en origen
  causa_raiz: |
    El patrón burn-on-source → mint-on-destination es inherentemente asíncrono. Si el
    mensaje falla en destino (receiver revierte, gas insuficiente, contrato pausado,
    chain down), los tokens ya quemados en origen no tienen contrapartida. Sin un
    mecanismo de fallback/refund robusto, los fondos se pierden permanentemente.
    El problema se amplifica cuando el protocolo no implementa retry, o cuando el retry
    requiere condiciones que no pueden cumplirse.
  como_funciona: |
    1. Usuario inicia transfer cross-chain: tokens quemados/bloqueados en Chain A.
    2. Mensaje enviado a Chain B via LayerZero/Wormhole/CCIP.
    3. En Chain B, _lzReceive() o ccipReceive() revierte por:
       - Contrato pausado en destino (modifier whenNotPaused en receiver)
       - Gas insuficiente para la ejecución
       - Slippage check falla (minAmountLD < receivedAmount)
       - Receiver tiene lógica que depende de estado externo que cambió
    4. Sin fallback: tokens quemados en A, nada minteado en B → pérdida total.
    5. Con fallback defectuoso: retry path existe pero requiere gas que el executor
       no provee, o el retry path tiene su propio revert.
  invariante: |
    // Conservation: tokens burned on source == tokens minted/refunded
    // Si mint en destino falla, DEBE existir refund path en origen
    assert(
      tokensMintedOnDestination[messageId] == tokensBurnedOnSource[messageId] ||
      tokensRefundedOnSource[messageId] == tokensBurnedOnSource[messageId]
    );
  que_mirar:
    - "¿Qué pasa si _lzReceive revierte? ¿Hay fallback/retry?"
    - "¿El receiver tiene modifiers que pueden causar revert (whenNotPaused, onlyWhitelisted)?"
    - "¿Existe un mecanismo de refund en origen si destino falla permanentemente?"
    - "¿El fallback function del sender es reachable desde el executor?"
    - "grep: _nonblockingLzReceive, failedMessages, retryMessage, _fallback"
    - "grep: whenNotPaused, onlyRole, require.*msg.sender"
  como_se_arregla: |
    Implementar fallback bidireccional: si destino falla, enviar mensaje de vuelta a
    origen para desbloquear/re-mintear tokens.
    No usar modifiers que puedan bloquear el receiver (e.g., pausable en lzReceive).
    Garantizar que el retry siempre es posible con gas suficiente.
    Separar la recepción del mensaje (siempre succeed) de la ejecución de la lógica
    (puede fallar con recovery).
  trampas:
    - "Pausar el receiver es un pattern común de seguridad pero puede causar stuck funds para mensajes in-flight"
    - "El retry en LZ V1 requiere retryPayload con el MISMO gas del original — si era insuficiente, el retry también falla"
    - "CCIP tiene manual execution como fallback, pero requiere que alguien pague gas"
  solodit_ids:
    - "pause-modifier-in-bridge-receiver-functions-causes-receiver-failures-for-in-flight-messages-cyfrin-none-securitize-onofframp-bridge-markdown"
    - "fuel1-2-sent-funds-may-get-stuck-inside-of-the-bridge-hexens-none-fuel-markdown"
    - "m-26-zeta-token-supply-keeps-growing-on-failed-onreceive-contract-calls-sherlock-zetachain-cross-chain-git"
  incidentes:
    - "ZetaChain (Sherlock, MEDIUM) — onReceive de ZetaToken falla pero el supply sigue creciendo; tokens minteados sin contrapartida, supply inflación"
    - "Fuel Bridge (Hexens, HIGH) — Fondos enviados al bridge quedan stuck; sin mechanism de recovery si destino no procesa"
    - "Securitize (Cyfrin, MEDIUM) — pause modifier en bridge receiver causa failure permanente para mensajes in-flight; tokens bloqueados en origen sin refund"
    - "Tigris Trade (Code4rena, MEDIUM) — GovNFT.crossChain quema NFT en origen; LZ endpoint falla en destino con low gas; mismo tokenId NFT existe en dos chains simultáneamente"
```

---

## 8. lzCompose Sender Validation Bypass

```yaml
- id: ccm-008
  titulo: Falta de validación de _srcChainSender en lzCompose permite ejecución arbitraria
  causa_raiz: |
    En LayerZero V2, los mensajes compuestos (lzCompose) permiten ejecutar lógica
    adicional después de que lzReceive entrega el mensaje. El compose message incluye
    _srcChainSender (la dirección que originó el mensaje), pero si el contrato receptor
    no valida este campo, CUALQUIER persona puede construir un _toeComposeMsg y enviar
    compose messages arbitrarios a través del Endpoint, ejecutando acciones no autorizadas.
  como_funciona: |
    1. Protocolo implementa lzCompose() que ejecuta acciones basándose en el payload.
    2. La función NO verifica que _srcChainSender sea una dirección autorizada.
    3. Atacante construye un _toeComposeMsg con payload malicioso.
    4. Atacante envía el compose message via endpoint.sendCompose().
    5. El contrato receptor ejecuta la acción sin verificar el origen.
    6. Resultado: mint arbitrario, transfer de fondos, cambio de estado no autorizado.
  invariante: |
    // Compose messages DEBEN validar el sender
    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable {
        require(_from == address(this), "Invalid compose sender");
        // o: require(authorizedSenders[_from], "Unauthorized");
        address srcChainSender = OFTComposeMsgCodec.composeFrom(_message);
        require(srcChainSender == trustedSender, "Invalid src sender");
    }
  que_mirar:
    - "¿lzCompose verifica _from y/o srcChainSender del compose message?"
    - "¿Cualquier contrato puede llamar lzCompose o solo el Endpoint?"
    - "¿El payload del compose message se decodifica sin validar el origen?"
    - "grep: lzCompose, _toeComposeMsg, composeFrom, OFTComposeMsgCodec"
    - "grep: sendCompose, _lzCompose, composeSender"
  como_se_arregla: |
    Siempre verificar que msg.sender == address(endpoint) en lzCompose.
    Validar _from == address(this) (o la dirección OApp esperada).
    Verificar srcChainSender contra un set de senders autorizados.
    Usar OFTComposeMsgCodec.composeFrom() para extraer y validar el sender.
  trampas:
    - "En V2, lzCompose es llamado por el Endpoint, no directamente por el usuario — pero el Endpoint forwarda sin filtrar srcChainSender"
    - "El compose message es un mecanismo NUEVO de V2 — muchos protocolos migrados de V1 no entienden este flujo"
    - "Verificar _from != verificar srcChainSender — son campos distintos"
  solodit_ids:
    - "h-01-multiple-lzcompose-messages-did-not-verify-the-legality-of-srcchainssender-sherlock-tapioca-tapioca-git"
  incidentes:
    - "Tapioca (Sherlock 2024, HIGH) — Múltiples módulos usan lzCompose sin verificar _srcChainSender; atacante puede construir _toeComposeMsg arbitrario y ejecutar cualquier acción cross-chain: transferir fondos, modificar estado del protocolo"
```

---

## 9. Oracle/Relayer Collusion in LayerZero V1

```yaml
- id: ccm-009
  titulo: Colusión Oracle + Relayer en LayerZero V1 permite forja de mensajes
  causa_raiz: |
    LayerZero V1 separa la verificación de mensajes en dos roles: el Oracle (provee
    block header/hash) y el Relayer (provee el proof + payload). El modelo de seguridad
    asume que Oracle y Relayer son INDEPENDIENTES — si uno es malicioso pero el otro es
    honesto, el mensaje falso no pasa. Pero si AMBOS coluden (o son controlados por la
    misma entidad), pueden forjar mensajes arbitrarios sin que exista un lock real en
    la chain origen.
  como_funciona: |
    1. En LZ V1, el Endpoint acepta un mensaje si:
       - Oracle confirma que el block hash es válido
       - Relayer provee proof que el mensaje existe en ese bloque
    2. Si Oracle y Relayer coluden:
       - Oracle provee un block hash falso (de un bloque que no contiene el mensaje)
       - Relayer provee un proof fabricado que "demuestra" el mensaje en ese bloque
    3. El Endpoint acepta el mensaje → acción ejecutada sin respaldo real.
    4. No hay dispute mechanism ni fraud proof — la verificación es instantánea.
    En la práctica: la mayoría de protocolos LZ V1 usaban el DEFAULT Oracle (Chainlink)
    y el DEFAULT Relayer (LayerZero Labs). La colusión requería comprometer ambos, lo cual
    es difícil pero no imposible (single point of failure si ambos son LayerZero-operated).
  invariante: |
    // Modelo de seguridad requiere independencia Oracle-Relayer
    // En V2 esto se reemplaza por DVNs (Decentralized Verifier Networks)
    assert(oracleAddress != relayerAddress);
    assert(oracleOwner != relayerOwner);
    // Verificación real: el block hash debe existir en la chain origen
  que_mirar:
    - "¿El protocolo usa Oracle y Relayer defaults o custom?"
    - "¿Quién controla el Oracle y Relayer? ¿Son la misma entidad?"
    - "¿Se puede cambiar Oracle/Relayer sin timelock?"
    - "¿Existe dispute window después de la verificación?"
    - "grep: setConfig, CONFIG_TYPE_ORACLE, CONFIG_TYPE_RELAYER, uln"
    - "grep: ILayerZeroOracle, ILayerZeroRelayer, updateHash"
  como_se_arregla: |
    Migrar a LayerZero V2 con DVNs (múltiples verificadores independientes).
    Configurar al menos 2 DVNs de diferentes proveedores.
    Añadir timelock a cambios de Oracle/Relayer config.
    Considerar verificación adicional on-chain (light client, state proof).
  trampas:
    - "En la práctica, la colusión Oracle+Relayer nunca ocurrió en LZ V1 — pero es un riesgo teórico real"
    - "Muchos bounties consideran 'trusted relayer' fuera de scope — verificar reglas del bounty"
    - "V2 con DVNs reduce pero no elimina el riesgo — si todos los DVNs son del mismo operador, es equivalente"
    - "Este es un riesgo de TRUST MODEL, no de código — difícil de reportar como bug, mejor como design concern"
  solodit_ids: []
  incidentes:
    - "No hay incidentes reales de colusión Oracle+Relayer en LZ V1 — el vector es teórico pero reconocido por LayerZero como motivación para migrar a V2 DVN model"
    - "Analogía: Ronin Bridge ($625M, 2022) — validators controlados por Axie Infinity (5 de 9); misma entidad controlaba el quorum, resultando en la mayor pérdida de bridge en la historia"
```

---

## 10. Chainlink CCIP Token Pool Manipulation

```yaml
- id: ccm-010
  titulo: Bypass de rate limiter o desync de balance en token pools de Chainlink CCIP
  causa_raiz: |
    Chainlink CCIP usa Token Pools para gestionar la liquidez de tokens cross-chain.
    Cada pool tiene un RateLimiter que limita el volumen de transfers por ventana de
    tiempo. Si el rate limiter no se configura correctamente, tiene bugs en el cálculo
    de la ventana, o el pool balance se desincroniza con el balance real del token,
    un atacante puede extraer más tokens de los que deberían estar disponibles.
    En CCIP v1.5+, los token issuers pueden deplegar pools SIN rate limits (self-serve),
    creando riesgo de drenaje ilimitado si el pool es comprometido.
  como_funciona: |
    Escenario Rate Limiter Bypass:
    1. Rate limiter permite X tokens por ventana de T segundos.
    2. Atacante observa que el cálculo de ventana tiene off-by-one o no acumula
       correctamente transfers pequeños.
    3. Atacante envía muchos transfers justo bajo el threshold individual pero
       excediendo el total → drena el pool.
    Escenario Balance Desync:
    1. Token pool trackea balance internamente (s_liquidityBalance).
    2. Alguien envía tokens directamente al pool contract (sin pasar por lock/release).
    3. Balance interno != token.balanceOf(pool) → accounting corrupto.
    4. Release puede fallar (insufficient liquidity) o dar más de lo que debería.
  invariante: |
    // Rate limiter: total transferred en ventana <= maxCapacity
    RateLimiter.TokenBucket memory bucket = pool.currentOutboundRateLimiterState();
    assert(bucket.tokens <= bucket.capacity);
    // Balance sync: internal tracking == actual balance
    assert(pool.getLiquidity() <= token.balanceOf(address(pool)));
  que_mirar:
    - "¿El token pool tiene rate limiter configurado (capacity > 0, rate > 0)?"
    - "¿El rate limiter se aplica en AMBAS direcciones (outbound + inbound)?"
    - "¿getLiquidity() usa balance interno o token.balanceOf()?"
    - "¿Self-serve pools pueden deployarse sin rate limits?"
    - "grep: RateLimiter, TokenBucket, currentOutboundRateLimiterState"
    - "grep: lockOrBurn, releaseOrMint, s_liquidityBalance, provideLiquidity"
  como_se_arregla: |
    Configurar rate limiters con capacity y rate apropiados para el volumen esperado.
    Sincronizar balance interno con balanceOf periódicamente.
    Implementar circuit breaker global que pause transfers si se detecta anomalía.
    Para self-serve pools: requerir rate limits mínimos en el factory.
  trampas:
    - "CCIP rate limiter tiene un token bucket algorithm — el bucket se recarga continuamente, no por ventanas discretas"
    - "Admin puede cambiar rate limits — esto es by design, no un bug (pero el timelock importa)"
    - "Self-serve pools en CCIP v1.5+ son responsabilidad del token issuer, no de Chainlink"
  solodit_ids:
    - "missing-source-validation-in-ccip-message-handling-cyfrin-none-yieldfi-markdown"
  incidentes:
    - "LucidLabs (Halborn, MEDIUM) — CCIPAdapter._ccipReceive llama VotingController/AssetController que pueden revert; triggerea Chainlink manual execution requirement, bloqueando governance cross-chain"
    - "CCIP v1.5 Audit (Cyfrin, 2024) — Multiple findings around self-serve token pool design, rate limiter configuration, and token listing without endorsement validation"
```

---

## 11. Hyperlane ISM Bypass

```yaml
- id: ccm-011
  titulo: Custom Interchain Security Module (ISM) de Hyperlane acepta mensajes inválidos
  causa_raiz: |
    Hyperlane permite a cada aplicación configurar su propio ISM (Interchain Security
    Module) para validar mensajes entrantes. Los ISM types incluyen: Multisig, Merkle,
    Aggregation, Routing, y Custom. Si una aplicación implementa un ISM custom con
    lógica de validación débil, o si el ISM routing envía mensajes a un ISM por defecto
    que es demasiado permisivo, un atacante puede enviar mensajes que pasan la validación
    sin estar respaldados por consenso real.
  como_funciona: |
    Escenario ISM Custom Débil:
    1. Protocolo implementa ISM custom que verifica solo 1 firma (de N posibles).
    2. Atacante compromete 1 signer (o es el signer malicioso).
    3. Atacante envía mensaje arbitrario con firma válida del signer comprometido.
    4. ISM.verify() retorna true → Mailbox.process() ejecuta el mensaje.
    Escenario ISM Routing:
    1. RoutingISM mapea originChainId → ISM específico.
    2. Para una chain no configurada, fallback al ISM por defecto (que puede ser un
       MultisigISM con threshold bajo o un TrustedRelayerISM).
    3. Atacante envía mensaje desde chain no configurada → pasa por ISM permisivo.
    Escenario Aggregation:
    1. AggregationISM requiere M-of-N ISMs para validar.
    2. Si M es demasiado bajo (1-of-3), comprometer un solo ISM es suficiente.
  invariante: |
    // ISM.verify() debe validar contra un quorum real
    // No debe haber fallback a un ISM trivial
    require(ism.verify(metadata, message) == true, "ISM verification failed");
    // El threshold debe ser > N/2
    require(threshold > totalValidators / 2, "Threshold too low");
  que_mirar:
    - "¿El protocolo usa ISM por defecto o custom?"
    - "¿Cuál es el threshold del MultisigISM? ¿Quiénes son los validators?"
    - "¿El RoutingISM tiene fallback para chains no configuradas?"
    - "¿AggregationISM tiene threshold suficientemente alto?"
    - "grep: interchainSecurityModule, IInterchainSecurityModule, verify"
    - "grep: Mailbox, process, handle, ISM, MultisigISM, RoutingISM"
    - "grep: setInterchainSecurityModule, defaultIsm"
  como_se_arregla: |
    Usar MultisigISM con threshold >= 2/3 + 1 de validators totales.
    No implementar ISM custom a menos que sea absolutamente necesario (y auditado).
    RoutingISM debe revert para chains no configuradas, NO fallback a ISM permisivo.
    AggregationISM con M >= ceil(N/2) + 1.
  trampas:
    - "TrustedRelayerISM es un solo signer — apropiado para testing, NUNCA para producción"
    - "El ISM por defecto de Hyperlane es razonablemente seguro — el riesgo está en custom ISMs de las aplicaciones"
    - "Cambiar el ISM de una aplicación puede invalidar mensajes in-flight"
  solodit_ids: []
  incidentes:
    - "No hay exploits públicos de ISM bypass en Hyperlane mainnet — el framework es relativamente nuevo"
    - "Analogía: Nomad Bridge ($190M) — trusted root inicializado a 0x00 es conceptualmente equivalente a un ISM que acepta cualquier mensaje"
    - "Hyperlane V3 introdujo ISM modularidad mejorada precisamente para mitigar estos riesgos"
```

---

## 12. Multi-Chain Governance Attacks

```yaml
- id: ccm-012
  titulo: Acción de governance en chain A ejecutada de forma diferente en chain B
  causa_raiz: |
    Protocolos multi-chain tienen governance en una chain (típicamente Ethereum) y
    ejecutan decisiones en múltiples chains via mensajes cross-chain. Si el mensaje de
    governance puede ser interceptado, retrasado, reordenado, o ejecutado parcialmente,
    el estado entre chains puede divergir. Esto permite ataques donde el estado de
    governance en chain A dice una cosa pero chain B ejecuta otra.
  como_funciona: |
    Escenario Reordenamiento:
    1. Governance envía: (1) cambiar oracle a OracleNew, (2) actualizar precios.
    2. Mensajes enviados via LayerZero/Axelar a chains B, C, D.
    3. En Chain B, mensaje (2) llega antes que (1) → precios actualizados con oracle viejo.
    4. En Chain C, mensaje (1) llega pero (2) se pierde → oracle cambiado pero sin precios.
    Escenario Ejecución Parcial:
    1. Governance propone cambio que afecta 5 chains.
    2. Mensaje falla en 2 chains (gas, pausa, etc.) pero ejecuta en 3.
    3. Estado inconsistente: protocolo funciona con reglas diferentes en diferentes chains.
    Escenario Timelock Bypass:
    1. Governance en Chain A tiene timelock de 48h.
    2. Mensaje cross-chain a Chain B se ejecuta inmediatamente (sin timelock local).
    3. Atacante front-runs la governance action en Chain B antes de que se ejecute en A.
  invariante: |
    // Governance state debe ser consistente across chains
    // Cada chain debe tener timelock local
    require(block.timestamp >= proposalTimestamp + TIMELOCK_DURATION, "Timelock active");
    // Mensajes de governance deben ser idempotentes
    require(!executed[proposalId], "Already executed");
    executed[proposalId] = true;
  que_mirar:
    - "¿Hay timelock en CADA chain o solo en la chain de governance?"
    - "¿Los mensajes de governance son idempotentes (ejecutar dos veces = mismo resultado)?"
    - "¿Qué pasa si un mensaje de governance falla en una chain?"
    - "¿Existe rollback mechanism para governance actions parcialmente ejecutadas?"
    - "grep: timelock, TimelockController, executeGovernance, queueAction"
    - "grep: proposalId, executed, crossChainExecute"
  como_se_arregla: |
    Timelock local en CADA chain (no solo en la chain de governance).
    Mensajes de governance idempotentes y con nonce.
    Batch execution: todas las chains deben confirmar antes de que cualquiera ejecute.
    Fallback: si una chain falla, pausar la ejecución en las demás hasta resolver.
  trampas:
    - "El reordenamiento de mensajes cross-chain es NORMAL — no asumir orden de llegada"
    - "Timelock cross-chain tiene latencia inherente — el atacante tiene más ventana para front-run"
    - "Protocolos grandes (Aave, Compound) usan sistemas como Temporal Governor (Moonwell) para manejar esto"
  solodit_ids:
    - "m-03-all-reallocate-cross-chain-token-and-rewards-will-be-lost-for-the-users-using-the-account-abstraction-wallet-code4rena-nudgexyz-nudgexyz-git"
  incidentes:
    - "Moonwell (Code4rena, MEDIUM) — Temporal Governor con timelock de Wormhole; si guardian set cambia entre envío y ejecución, el proposal puede ser inejecutable"
    - "NudgeXYZ (Code4rena, MEDIUM) — Reallocate cross-chain tokens perdidos para usuarios con AA wallets; governance no contempló que msg.sender != wallet address"
```

---

## 13. Cross-Chain Reentrancy via Callbacks

```yaml
- id: ccm-013
  titulo: Reentrancy cross-chain via callback de destino a origen
  causa_raiz: |
    Cuando un protocolo envía un mensaje cross-chain y espera un callback (respuesta
    asíncrona desde destino), el estado en origen puede estar en un punto intermedio
    cuando el callback llega. Si el callback triggerea lógica que asume estado final
    (no intermedio), o si el atacante puede fabricar un callback antes del legítimo,
    se produce una reentrancy conceptual: la lógica en origen se re-ejecuta con
    estado inconsistente.
  como_funciona: |
    1. Protocolo en Chain A: lock tokens, enviar mensaje a Chain B, estado = PENDING.
    2. Chain B: ejecuta acción, envía callback a Chain A.
    3. ANTES de que el callback legítimo llegue, atacante envía callback falso
       (posible si la validación de origen del callback es débil).
    4. Chain A recibe callback falso: estado = PENDING → ejecuta acción de completar.
    5. Tokens desbloqueados en A sin que la acción se completara realmente en B.
    6. Callback legítimo llega: estado ya no es PENDING → puede fallar o ejecutar
       segunda vez (double unlock).
    Variante Asíncrona:
    Sin callback falso, el pattern es: enviar A→B y B→A en la misma transacción
    conceptual. Si el estado en A se modifica por el segundo mensaje mientras el
    primero aún está en tránsito, el invariante se rompe.
  invariante: |
    // Estado PENDING es read-only — no permite modificaciones hasta callback
    require(operationState[opId] == State.PENDING, "Not pending");
    operationState[opId] = State.COMPLETED;
    // Callback debe venir del peer autorizado
    require(msg.sender == address(endpoint));
    require(_origin.sender == authorizedPeer);
  que_mirar:
    - "¿El protocolo usa pattern request-callback (ida y vuelta cross-chain)?"
    - "¿El estado es mutable entre request y callback?"
    - "¿El callback valida que viene del peer autorizado Y que la operación existe?"
    - "¿Puede un usuario cancelar/modificar la operación mientras el callback está en tránsito?"
    - "grep: callback, onResponse, _fallback, requestId, operationState"
    - "grep: PENDING, COMPLETED, State, requestCallback"
  como_se_arregla: |
    Lock estado como PENDING inmediatamente, no permitir modificaciones.
    Callback DEBE venir del peer autorizado (trustedRemote/peer) — sin excepciones.
    Usar nonces/requestIds únicos para ligar request con callback.
    Idempotency: callback ejecutado dos veces = mismo resultado.
  trampas:
    - "Cross-chain reentrancy es conceptual — no es reentrancy clásica en una tx, sino entre dos mensajes asíncronos"
    - "El 'atacante' puede ser simplemente latencia de red: callback legítimo llega tarde y el usuario ya canceló"
    - "No hay exploit real documentado de cross-chain reentrancy — pero Ackee Blockchain y Immunefi lo identifican como riesgo emergente"
  solodit_ids:
    - "h-1-pushvaultamounts-can-be-called-multiple-times-if-in-the-right-state-sherlock-derby-derby-git"
  incidentes:
    - "Derby Finance (Sherlock, HIGH) — pushVaultAmounts puede llamarse múltiples veces si el estado está en la condición correcta; race condition entre mensajes cross-chain permite manipular allocations"
    - "Ackee Blockchain (Research, 2023) — Paper teórico sobre cross-chain reentrancy via composability de bridges; sin exploit real pero describe vectores viables"
```

---

## 14. Gas Price Oracle Manipulation for Cross-Chain Fees

```yaml
- id: ccm-014
  titulo: Manipulación del oracle de gas price para underpay fees cross-chain
  causa_raiz: |
    Los protocolos de mensajería cross-chain cobran fees basadas en el gas price de la
    cadena destino. Si el oracle de gas price es manipulable (e.g., basado en un TWAP
    corto, un feed Chainlink stale, o un valor reportado por el relayer), el atacante
    puede hacer que el protocolo subestime el costo de ejecución en destino. El relayer
    pierde dinero ejecutando mensajes sub-costeados, o simplemente no los ejecuta
    (DoS económico).
  como_funciona: |
    1. Protocolo usa oracle de gas para calcular fee: fee = destGasPrice * gasLimit.
    2. Atacante manipula el oracle: reporta gas price artificialmente bajo.
    3. Usuarios envían mensajes pagando fee reducida.
    4. Relayer en destino debe pagar gas REAL (más alto) → opera a pérdida.
    5. Relayer deja de ejecutar mensajes → DoS para todo el protocolo.
    Variante inversa: atacante infla el gas price para cobrar fees excesivas y
    profit como relayer (menos relevante para seguridad, más para UX).
  invariante: |
    // Fee cobrado >= costo real de ejecución en destino
    uint256 estimatedFee = gasOracle.getGasPrice(dstChainId) * gasLimit;
    uint256 actualCost = tx.gasprice * gasUsed; // en destino
    assert(estimatedFee >= actualCost * (100 - TOLERANCE_PCT) / 100);
  que_mirar:
    - "¿De dónde viene el gas price de destino? ¿Oracle, Chainlink, relayer-reported?"
    - "¿El gas price oracle tiene staleness check?"
    - "¿El relayer puede subsidiar o se niega a ejecutar si fee < cost?"
    - "¿Hay mecanismo de reembolso si el fee estimado fue insuficiente?"
    - "grep: gasOracle, dstGasPrice, estimateFee, quoteSend, nativeFee"
    - "grep: setDstGasPrice, gasPriceInWei, dstConfig"
  como_se_arregla: |
    Usar Chainlink gas price feeds con staleness check.
    Añadir buffer de seguridad al fee estimado (e.g., 120% del costo esperado).
    Relayer con minimum fee threshold: no ejecutar si fee < cost * 1.1.
    Mecanismo de repricing para mensajes cuyo fee se volvió insuficiente.
  trampas:
    - "El gas price en L2s (Arbitrum, Optimism) incluye L1 data cost — los oracles que solo reportan L2 gas subestiman"
    - "En períodos de congestión, el gas price puede cambiar 10x entre envío y ejecución"
    - "LayerZero V2 Executors asumen el riesgo de gas — el usuario paga basado en quote, el Executor absorbe la diferencia"
  solodit_ids: []
  incidentes:
    - "Holograph (C4, HIGH) — LayerZeroModule usa gas config de cadena ORIGEN para estimar fees de DESTINO; NFTs stuck cuando las configs difieren significativamente"
    - "Connext (Spearbit, HIGH) — Multichain anyCall siempre falla porque no se paga gas fee de ejecución; sin receive()/fallback() para aceptar ETH deposits para gas"
```

---

## 15. Axelar Gateway executeWithToken Validation

```yaml
- id: ccm-015
  titulo: Validación insuficiente de executeWithToken/validateContractCall en Axelar
  causa_raiz: |
    Axelar usa un Gateway contract para recibir mensajes cross-chain. Los contratos
    receptor deben implementar IAxelarExecutable con _execute() o _executeWithToken().
    El Gateway emite commandId que debe validarse via validateContractCall() o
    validateContractCallAndMint() ANTES de ejecutar la lógica. Si la validación se
    omite, se hace después, o el commandId es reusable, un atacante puede ejecutar
    acciones no autorizadas o replayear comandos.
  como_funciona: |
    Escenario Validation Bypass:
    1. Contrato implementa _execute() pero no llama validateContractCall() primero.
    2. Atacante llama execute() directamente con payload arbitrario.
    3. Sin validación, el payload se ejecuta como si fuera un mensaje legítimo del Gateway.
    Escenario Aggregator Exploit:
    1. Bridge aggregator (e.g., LI.FI) acepta callTo como parámetro del usuario.
    2. Atacante pasa callTo = axelarGateway, callData = validateContractCallAndMint(...).
    3. Executor del aggregator llama al Gateway, mintea tokens al atacante.
    4. Fondos del Executor drenados.
  invariante: |
    // validateContractCall DEBE llamarse antes de cualquier acción
    require(
        gateway.validateContractCall(commandId, sourceChain, sourceAddress, payloadHash),
        "Not approved by gateway"
    );
    // commandId solo puede usarse una vez
    // (validateContractCall retorna false en segundo uso)
  que_mirar:
    - "¿_execute() llama validateContractCall() antes de ejecutar lógica?"
    - "¿executeWithToken usa validateContractCallAndMint() correctamente?"
    - "¿El contrato hereda de AxelarExecutable (que hace la validación automática)?"
    - "¿Hay paths que bypasean la herencia de AxelarExecutable?"
    - "grep: validateContractCall, validateContractCallAndMint, commandId"
    - "grep: IAxelarExecutable, _execute, _executeWithToken, gateway"
    - "grep: sourceChain, sourceAddress, payloadHash"
  como_se_arregla: |
    Siempre heredar de AxelarExecutable (no reimplementar la validación manualmente).
    Blacklist la dirección del Gateway como target en aggregadores/routers.
    No exponer execute/executeWithToken como public sin require de Gateway validation.
  trampas:
    - "AxelarExecutable ya maneja la validación internamente — el riesgo es reimplementar sin la validación"
    - "commandId es one-time-use por diseño — validateContractCall retorna false en segundo call"
    - "sourceChain en Axelar es un STRING, no un uint16 — comparaciones de strings son case-sensitive"
  solodit_ids:
    - "m-02-executor-can-deliver-cross-chain-messages-with-unvalidated-native-value-shieldify-none-onchainheroes-genesisbridge-markdown"
  incidentes:
    - "LI.FI (Spearbit, MEDIUM) — Axelar gateway no blacklisted en callTo targets del Executor; atacante puede triggear validateContractCallAndMint para mintear tokens al Executor y luego drenarlos"
    - "Ondo Finance (C4, MEDIUM) — burnAndCallAxelar encodes msg.sender en payload; AA wallets tienen dirección diferente en destino; fondos perdidos permanentemente"
```

---

## 16. Message Ordering Assumptions

```yaml
- id: ccm-016
  titulo: Protocolo asume orden de llegada de mensajes cross-chain cuando no la hay
  causa_raiz: |
    La mayoría de protocolos de mensajería cross-chain (LayerZero V2, Wormhole, CCIP,
    Axelar) NO garantizan orden de entrega. Un mensaje enviado después puede llegar antes.
    Si la lógica del protocolo depende del orden (e.g., primero configurar, luego ejecutar;
    primero depositar, luego retirar), el desorden puede causar estado inconsistente,
    reverts, o exploits.
  como_funciona: |
    1. Protocolo envía Mensaje 1 (config update) y Mensaje 2 (execute action).
    2. Asume: Mensaje 1 llega primero, configura; Mensaje 2 llega segundo, ejecuta.
    3. En realidad, Mensaje 2 llega primero → ejecuta con config VIEJA.
    4. Resultado: acción ejecutada con parámetros incorrectos.
    Ejemplo: cambiar oracle address y luego actualizar precio.
    Si el precio llega antes del cambio de oracle, usa el oracle viejo.
  invariante: |
    // Si el orden importa, usar sequence numbers explícitos
    require(lastProcessedSequence[srcChainId] + 1 == messageSequence, "Out of order");
    lastProcessedSequence[srcChainId] = messageSequence;
    // O: hacer cada mensaje idempotente e independiente del orden
  que_mirar:
    - "¿El protocolo envía mensajes que dependen del orden de llegada?"
    - "¿Hay una secuencia de config → execute que requiere orden?"
    - "¿Se usan nonces secuenciales con enforcement en destino?"
    - "¿Cada mensaje es auto-contenido o depende del estado dejado por un mensaje anterior?"
    - "grep: sequence, nonce, lastProcessed, messageOrder"
    - "grep: require.*nonce, incrementNonce"
  como_se_arregla: |
    Diseñar mensajes idempotentes e independientes del orden cuando sea posible.
    Si el orden es necesario, implementar sequence enforcement en destino.
    Batch multiple steps en un solo mensaje cross-chain.
    Usar pattern de two-phase commit: prepare en destino, confirm después.
  trampas:
    - "LayerZero V1 era ORDENADO por defecto (blocking) — V2 es desordenado"
    - "CCIP garantiza orden DENTRO de un lane (src→dst pair) pero no entre lanes"
    - "El desorden puede ser de SEGUNDOS o de HORAS dependiendo de congestión y relayers"
  solodit_ids:
    - "h-1-pushvaultamounts-can-be-called-multiple-times-if-in-the-right-state-sherlock-derby-derby-git"
  incidentes:
    - "Derby Finance (Sherlock, HIGH) — pushVaultAmounts puede ejecutarse múltiples veces en el estado correcto porque mensajes cross-chain no tienen ordering enforced"
```

---

## 17. OFT Dust Removal and Decimal Mismatch

```yaml
- id: ccm-017
  titulo: Pérdida de fondos por dust removal o mismatch de decimales en OFT cross-chain
  causa_raiz: |
    LayerZero OFT (Omnichain Fungible Token) usa "shared decimals" para normalizar
    tokens entre chains con diferentes decimales. La función _removeDust() trunca el
    amount al granularity de shared decimals. Si minAmountLD se calcula sin considerar
    esta truncación, o si los decimales locales vs compartidos no están alineados,
    el transfer puede: (a) revertir con SlippageExceeded porque receivedAmount <
    minAmountLD, o (b) perder dust silenciosamente en cada transfer.
  como_funciona: |
    1. Token tiene 18 decimales locales pero 6 shared decimals.
    2. decimalConversionRate = 10^(18-6) = 10^12.
    3. Usuario envía 1.000000000001 tokens (1e18 + 1 wei).
    4. _removeDust() trunca a 1.000000 (1e18) — pierde 1 wei.
    5. Si minAmountLD = amountLD (sin removeDust), el transfer REVIERTE porque
       receivedAmount (1e18) < minAmountLD (1e18 + 1).
    6. ~69% de amounts aleatorios tienen dust → 69% de txs revert.
  invariante: |
    // minAmountLD debe ser <= removeDust(amountLD)
    uint256 amountSD = amountLD / decimalConversionRate;
    uint256 cleanAmountLD = amountSD * decimalConversionRate;
    assert(minAmountLD <= cleanAmountLD);
    // Dust perdido debe ser devuelto al sender, no quemado
  que_mirar:
    - "¿El protocolo usa OFT con shared decimals diferentes a local decimals?"
    - "¿minAmountLD se calcula DESPUÉS de removeDust?"
    - "¿Hay refund de dust al sender?"
    - "¿decimalConversionRate está configurado correctamente?"
    - "grep: _removeDust, decimalConversionRate, sharedDecimals, SlippageExceeded"
    - "grep: minAmountLD, amountSD, amountLD, amountReceivedLD"
  como_se_arregla: |
    Calcular minAmountLD = removeDust(amountLD) * (100 - slippageBps) / 100.
    O: aplicar removeDust al amount ANTES de calcular minAmount.
    Devolver dust al sender en vez de quemarlo.
    Documentar claramente que amounts con dust serán truncados.
  trampas:
    - "Si localDecimals == sharedDecimals, decimalConversionRate = 1 y no hay dust — no es un bug"
    - "USDC (6 decimals) con sharedDecimals = 6 → sin truncación"
    - "Tokens con 18 decimals y sharedDecimals = 8 tienen la mayor pérdida de dust"
  solodit_ids:
    - "bridging-dstoken-back-and-forth-between-chains-causes-totalissuance-cap-to-be-reached-preventing-further-issuances-and-cross-chain-transfers-cyfrin-none-securitize-bridge-cctp-markdown"
  incidentes:
    - "Brix Money (C4, MEDIUM) — Cross-chain unstake falla porque minAmountLD == amountLD sin contabilizar dust removal de LayerZero; SlippageExceeded revert bloquea ~69% de transacciones"
    - "Securitize (Cyfrin, MEDIUM) — DSToken bridgeado back-and-forth acumula truncation errors hasta alcanzar totalIssuance cap; previene futuras issuances y transfers cross-chain"
```

---

## 18. Cross-Chain Address Symmetry Assumption

```yaml
- id: ccm-018
  titulo: Protocolo asume que msg.sender tiene la misma dirección en todas las chains
  causa_raiz: |
    Muchos protocolos cross-chain hardcodean msg.sender como recipient en la chain destino,
    asumiendo que la misma dirección es controlada por el mismo usuario en todas las chains
    EVM. Esto falla para: Account Abstraction (AA) wallets (dirección diferente por chain),
    multisigs (deployment nonces diferentes), smart contract wallets via CREATE2 con
    diferente salt, y ZkSync que preserva msg.sender en L1→L2 calls (permitiendo spoofing).
  como_funciona: |
    1. Usuario con Safe wallet (o AA wallet) inicia bridge transfer.
    2. Protocolo encodifica msg.sender como recipient en destino (sin parámetro separado).
    3. En chain destino, la misma dirección es:
       a. No desplegada → fondos enviados a EOA que nadie controla.
       b. Controlada por otra entidad → fondos robados.
       c. Un contrato diferente → fondos stuck.
    4. Resultado: pérdida permanente de fondos.
  invariante: |
    // El recipient DEBE ser un parámetro explícito, no derivado de msg.sender
    function bridgeTokens(
        uint256 amount,
        address recipient,  // ← DEBE existir
        uint16 dstChainId
    ) external {
        // ...
    }
  que_mirar:
    - "¿El bridge usa msg.sender como recipient en destino?"
    - "¿Hay parámetro _to o _recipient separado?"
    - "¿Se documenta el riesgo para AA wallets?"
    - "¿El protocolo target L2s con msg.sender preservation (ZkSync)?"
    - "grep: abi.encode.*msg.sender, to: msg.sender, user: msg.sender"
    - "grep: bytes32(uint256(uint160(msg.sender)))"
  como_se_arregla: |
    Siempre aceptar recipient como parámetro explícito.
    Documentar riesgos para AA/contract wallets.
    Para ZkSync L1→L2: nunca asumir equivalencia de dirección entre chains para contracts.
  trampas:
    - "EOA addresses SÍ son iguales en todas las chains EVM — solo contract wallets son diferentes"
    - "Algunos protocolos usan same-address enforcement intencionalmente para compliance"
    - "4.4M Safe wallet users afectados potencialmente"
  solodit_ids:
    - "m-03-all-reallocate-cross-chain-token-and-rewards-will-be-lost-for-the-users-using-the-account-abstraction-wallet-code4rena-nudgexyz-nudgexyz-git"
  incidentes:
    - "Ondo Finance (C4, MEDIUM) — burnAndCallAxelar encodes msg.sender en payload; AA wallets tienen dirección diferente por chain; fondos perdidos para 4.4M Safe wallet users potencialmente"
    - "Brix Money (C4, MEDIUM) — Cross-chain unstake enforces address symmetry; incompatible con Gnosis Safe / AA wallets"
    - "Connext (Spearbit, HIGH) — ZkSync msg.sender preservation permite impersonación cross-chain; atacante despliega wallet en dirección de víctima en L1 via CREATE2; gana control de permisos de delegación y fondos en ZkSync"
```
