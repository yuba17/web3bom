# Permit2 & Modern Approval Pattern Vulnerabilities -- Combat Briefing

> **Scope**: Uniswap Permit2, ERC-2612 permit, approval/allowance patterns, signature-based token transfer authorization, and phishing vectors in modern DeFi.
> **Sources**: Solodit (solodit.cyfrin.io), Uniswap Permit2 audits (ABDK, OpenZeppelin), Sherlock/Code4rena/Cantina findings, real-world phishing incidents -- 17 verified vulnerability patterns.
> **Last updated**: 2026-03-23

---

## Contexto: Permit2 y el Modelo de Aprobación Moderno

Permit2 de Uniswap introduce un modelo de aprobación universal que reemplaza el patrón clásico `approve() + transferFrom()`. En lugar de dar allowance directamente a cada protocolo, el usuario aprueba Permit2 una sola vez y luego firma mensajes off-chain (EIP-712) para autorizar transferencias específicas. Esto reduce las transacciones on-chain pero concentra la superficie de ataque en un solo contrato y en las firmas off-chain.

**Dos modos principales:**
1. **SignatureTransfer**: transferencia one-shot autorizada por firma. Nonce consumido tras uso.
2. **AllowanceTransfer**: aprobación persistente con amount/expiration/nonce, similar al ERC-20 approve pero con control temporal.

**Riesgos clave que amplifica Permit2:**
- Una sola aprobación infinita a Permit2 = todo el balance del token queda bajo el control de firmas off-chain
- Phishing de firmas es equivalente a robar fondos directamente
- Interacciones complejas entre nonces, deadlines, witness data y batch operations crean superficie de ataque amplia

---

## Bug Patterns

```yaml
- id: PERM-01
  pattern: permit2-cross-chain-replay
  name: "Replay de firma Permit2 entre cadenas (chainId ausente o fijo)"
  causa_raiz: "El domain separator de Permit2 incluye chainId, pero protocolos que construyen sus propios hashes de firma sobre Permit2 (usando witness data o wrappers custom) pueden omitir chainId del hash firmado. Además, si Permit2 se deploya en la misma dirección en múltiples cadenas (CREATE2 determinístico), una firma válida en Chain A podría intentar replayearse en Chain B si el protocolo wrapper no valida la cadena."
  como_funciona: |
    1. Permit2 se deploya en dirección idéntica en Ethereum, Arbitrum, Optimism, Base (misma dirección CREATE2).
    2. Usuario firma un SignatureTransfer con witness data custom para un protocolo en Chain A.
    3. Si el protocolo wrapper no incluye chainId en su witness type hash, o si el contrato spender tiene la misma dirección en Chain B:
    4. Atacante toma la firma de Chain A y la submitea en Chain B.
    5. El domain separator de Permit2 core SÍ incluye chainId, PERO si el wrapper decodifica el witness externamente y no revalida, el replay puede funcionar en la capa del protocolo.
    6. En el caso más directo: si un protocolo usa AllowanceTransfer (no SignatureTransfer), y el usuario aprobó Permit2 en ambas cadenas, el atacante puede explotar la allowance en Chain B con información obtenida de Chain A.
  invariante: |
    // Toda firma procesada debe ser válida SOLO en la cadena actual
    function invariant_no_cross_chain_replay() external {
        uint256 currentChainId = block.chainid;
        bytes32 domainSep = permit2.DOMAIN_SEPARATOR();
        // El domain separator debe contener el chainId actual
        // Si se cachea, debe recomputarse cuando block.chainid cambie
        assert(domainSep == _computeDomainSeparator(currentChainId, address(permit2)));
    }
  patron_vulnerable: |
    // Wrapper que construye witness hash sin chainId
    contract VulnerableRouter {
        IPermit2 permit2;

        struct OrderData {
            address token;
            uint256 amount;
            address recipient;
            // FALTA: chainId no está en la struct firmada
        }

        function executeOrder(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            OrderData calldata order,
            bytes calldata signature
        ) external {
            // Witness hash no incluye block.chainid
            bytes32 witness = keccak256(abi.encode(order));
            permit2.permitTransferFrom(permit, details, msg.sender, witness, WITNESS_TYPE, signature);
        }
    }
  test_invariante: |
    function test_cross_chain_replay_blocked() public {
        // Firma generada en chainId = 1
        vm.chainId(1);
        bytes memory sig = _signPermit(permit, details, witnessHash, signerKey);
        permit2.permitTransferFrom(permit, details, signer, witnessHash, WITNESS_TYPE, sig);

        // Replay en chainId = 8453 (Base) debe fallar
        vm.chainId(8453);
        vm.expectRevert();
        permit2.permitTransferFrom(permit, details, signer, witnessHash, WITNESS_TYPE, sig);
    }
  ejemplo_real:
    - "Uniswap Permit2 ABDK Audit (2022): confirmó que el domain separator core incluye chainId, pero advirtió que protocolos integradores deben incluir chainId en su witness data si la semántica es chain-specific"
    - "Solodit: múltiples findings de cross-chain replay en protocolos que usan EIP-712 sin chainId dinámico (ver sig-002 en signature-replay briefing)"
    - "Real-world: Permit2 deployado en >15 cadenas en la misma dirección 0x000000000022D473030F116dDEE9F6B43aC78BA3"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "ABDK Permit2 Audit, Solodit"
  tags: [permit2, cross-chain, replay, chainId, witness, CREATE2]
  relacionado_con: [PERM-02, PERM-05]
```

```yaml
- id: PERM-02
  pattern: signature-transfer-deadline-bypass
  name: "Bypass de deadline en SignatureTransfer"
  causa_raiz: "El campo deadline en PermitTransferFrom define hasta cuándo la firma es válida. Si un protocolo integrador no valida el deadline antes de llamar a Permit2, o si el usuario firma con deadline = type(uint256).max, la firma permanece válida indefinidamente. Además, si el deadline se valida en un lugar pero la ejecución real ocurre en otro (e.g., delayed execution, queued orders), la ventana de ataque se amplía."
  como_funciona: |
    1. Usuario firma un PermitTransferFrom con deadline = type(uint256).max (o un valor muy lejano).
    2. La firma se almacena off-chain (e.g., en un orderbook, relay, intent system).
    3. Meses después, las condiciones del mercado cambian drásticamente.
    4. Atacante (o el relayer) ejecuta la firma cuando el precio es desfavorable para el usuario.
    5. La transferencia se ejecuta porque el deadline no ha expirado.
    6. El usuario pierde fondos por ejecutar a un precio obsoleto.
  invariante: |
    // Deadline debe estar en un rango razonable
    function invariant_deadline_bounded() external view {
        // Las firmas no deben tener deadlines > 30 días en el futuro
        // (política del protocolo, no de Permit2 core)
        assert(permit.deadline <= block.timestamp + 30 days);
    }
  patron_vulnerable: |
    // Intent system que no valida deadline razonable
    contract VulnerableIntentRouter {
        function fillOrder(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            // No verifica que permit.deadline sea razonable
            // No verifica que el precio siga siendo justo
            // Solo pasa a Permit2 que valida deadline > block.timestamp
            permit2.permitTransferFrom(permit, details, msg.sender, signature);
        }
    }
  test_invariante: |
    function test_stale_signature_rejected() public {
        uint256 farFutureDeadline = block.timestamp + 365 days;
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: 1000e18}),
            nonce: 0,
            deadline: farFutureDeadline
        });
        bytes memory sig = _signPermit(permit, details, signerKey);

        // Avanzar 6 meses -- la firma sigue válida técnicamente
        vm.warp(block.timestamp + 180 days);

        // El protocolo DEBERÍA rechazar firmas con deadlines excesivos
        // Si esto pasa, el protocolo es vulnerable
        permit2.permitTransferFrom(permit, details, signer, sig);
        // ^ Esto NO revierte en Permit2 core -- la responsabilidad es del integrador
    }
  ejemplo_real:
    - "Uniswap Universal Router: usa deadlines cortos internamente pero no fuerza límites en el SDK"
    - "Sherlock: múltiples findings en protocolos de intents donde firmas con deadline infinito permiten ejecución a precios obsoletos"
    - "CoW Protocol: el problema de 'stale orders' es análogo -- órdenes firmadas que se ejecutan cuando ya no son favorables"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Uniswap Permit2 Audit, Sherlock findings"
  tags: [permit2, deadline, SignatureTransfer, stale-signature, intent]
  relacionado_con: [PERM-01, PERM-17]
```

```yaml
- id: PERM-03
  pattern: allowance-transfer-over-approval
  name: "Explotación de sobre-aprobación en AllowanceTransfer"
  causa_raiz: "AllowanceTransfer permite aprobar un amount y expiration para un spender. Si el usuario aprueba amount = type(uint160).max (aprobación infinita), cualquier compromiso del spender contract drena todo el balance del token. A diferencia del ERC-20 approve clásico, aquí el spender puede transferir hasta el amount aprobado en múltiples llamadas sin necesidad de nueva firma."
  como_funciona: |
    1. Usuario llama permit2.approve(token, spenderContract, type(uint160).max, type(uint48).max).
    2. SpenderContract es un protocolo DeFi legítimo.
    3. SpenderContract tiene una vulnerabilidad (reentrancy, access control, upgrade malicioso).
    4. Atacante explota SpenderContract para llamar permit2.transferFrom(user, attacker, token, balance).
    5. Como el allowance es infinito y no expira, la transferencia se ejecuta.
    6. Todo el balance del token del usuario se drena.
  invariante: |
    // El allowance no debe exceder lo necesario para la operación
    function invariant_allowance_bounded(address user, address token, address spender) external view {
        (uint160 amount, uint48 expiration, uint48 nonce) = permit2.allowance(user, token, spender);
        // Allowance infinito es un riesgo -- marcar como warning
        assert(amount < type(uint160).max || expiration < block.timestamp + 365 days);
    }
  patron_vulnerable: |
    // Frontend/SDK que pide aprobación infinita por comodidad
    contract VulnerableProtocol {
        IPermit2 permit2;

        function deposit(address token, uint256 amount) external {
            // Asume que el usuario ya aprobó max allowance a este contrato en Permit2
            permit2.transferFrom(msg.sender, address(this), uint160(amount), token);
        }

        // Vulnerabilidad: función sin access control que permite drenar
        function emergencyWithdraw(address token, address from, address to, uint160 amount) external {
            // Sin onlyOwner, sin validación
            permit2.transferFrom(from, to, amount, token);
        }
    }
  test_invariante: |
    function test_over_approval_exploit() public {
        // Usuario aprueba max
        vm.prank(user);
        permit2.approve(address(token), address(vulnProtocol), type(uint160).max, type(uint48).max);

        // Atacante explota la función vulnerable
        vm.prank(attacker);
        vulnProtocol.emergencyWithdraw(address(token), user, attacker, uint160(token.balanceOf(user)));

        // Usuario pierde todo
        assertEq(token.balanceOf(user), 0);
        assertGt(token.balanceOf(attacker), 0);
    }
  ejemplo_real:
    - "OpenSea Wyvern exploit (enero 2022): atacantes usaron firmas de aprobación vigentes para transferir NFTs valiosos de usuarios -- mismo patrón conceptual con ERC-20 approvals"
    - "Solodit #multiple: protocolos que almacenan allowances infinitas son attack surface para cualquier bug en el spender"
    - "Permit2 design decision: usa uint160 para amount en AllowanceTransfer (no uint256) como mitigación parcial, limitando a ~1.46e48 tokens"
    - "Revoke.cash estadísticas: miles de usuarios con allowances infinitas a Permit2 sin awareness del riesgo"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Uniswap Permit2 design docs, OpenSea incident analysis"
  tags: [permit2, allowance, infinite-approval, over-approval, spender-compromise]
  relacionado_con: [PERM-10, PERM-13]
```

```yaml
- id: PERM-04
  pattern: nonce-bitmap-manipulation
  name: "Manipulación del bitmap de nonces en Permit2 SignatureTransfer"
  causa_raiz: "Permit2 usa un sistema de nonces basado en bitmaps para SignatureTransfer: cada nonce es un (wordPos, bitPos) donde wordPos = nonce >> 8 y bitPos = nonce & 0xff. Si un protocolo integrador no gestiona correctamente la asignación de nonces, o si un atacante puede invalidar nonces selectivamente, se pueden crear gaps que permitan omitir firmas pendientes o forzar reverts en firmas legítimas."
  como_funciona: |
    1. Permit2 almacena nonces usados como: nonceBitmap[owner][wordPos] |= (1 << bitPos).
    2. El usuario puede invalidar nonces proactivamente llamando invalidateUnorderedNonces(wordPos, mask).
    3. Atacante front-runs la transacción del usuario y llama invalidateUnorderedNonces con un mask que incluye el nonce de la firma pendiente.
    4. La firma del usuario se vuelve inválida (nonce ya consumido).
    5. El usuario sufre DoS: debe firmar de nuevo con un nonce diferente.
    6. En un escenario más grave: si el protocolo depende de ejecución atómica de múltiples firmas (batch), invalidar un nonce rompe toda la secuencia.
  invariante: |
    // Un nonce solo debe invalidarse por su propietario legítimo
    function invariant_nonce_owner_only(address owner, uint256 wordPos) external view {
        // Verificar que solo el owner puede modificar su bitmap
        // Permit2 ya enforce esto -- el riesgo es en wrappers
        uint256 bitmap = permit2.nonceBitmap(owner, wordPos);
        // Post-condición: bitmap solo cambia tras llamada del owner
    }
  patron_vulnerable: |
    // Protocolo que expone invalidación de nonces sin auth
    contract VulnerableNonceManager {
        IPermit2 permit2;

        // Cualquiera puede invalidar nonces de cualquier usuario
        function cancelOrders(address owner, uint256 wordPos, uint256 mask) external {
            // VULNERABLE: no verifica que msg.sender == owner
            // Permit2.invalidateUnorderedNonces SÍ usa msg.sender como owner
            // PERO si este wrapper hace algo custom con los nonces...
            permit2.invalidateUnorderedNonces(wordPos, mask);
            // ^ Esto invalida los nonces de msg.sender (el contrato), NO del owner
            // El bug real está en la lógica del wrapper
        }
    }

    // Permit2 core (correcto pero relevante entender):
    // function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
    //     nonceBitmap[msg.sender][wordPos] |= mask;
    // }
  test_invariante: |
    function test_nonce_invalidation_dos() public {
        // Usuario firma con nonce = 5
        uint256 nonce = 5;
        uint256 wordPos = nonce >> 8; // = 0
        uint256 bitPos = nonce & 0xff; // = 5
        uint256 mask = 1 << bitPos;

        // Firma válida del usuario
        bytes memory sig = _signPermit(permit, details, nonce, signerKey);

        // Atacante no puede invalidar directamente los nonces del usuario en Permit2
        // PERO: si el protocolo wrapper tiene una función que invalida nonces de forma incorrecta...
        vm.prank(attacker);
        // En Permit2 core esto invalida nonces del ATTACKER, no del user
        // El riesgo real es en wrappers mal implementados
    }
  ejemplo_real:
    - "Uniswap Permit2 ABDK Audit: analizó la seguridad del bitmap nonce system, confirmó que invalidateUnorderedNonces usa msg.sender correctamente"
    - "Uniswap Permit2 OpenZeppelin Audit: recomendó documentar claramente que los nonces son unordered y que el usuario es responsable de trackear qué nonces ha usado"
    - "Sherlock/Aave: findings donde nonce management incorrecto en wrappers permite DoS o replay"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "ABDK Permit2 Audit, OpenZeppelin Permit2 Audit"
  tags: [permit2, nonce, bitmap, invalidation, DoS, front-running]
  relacionado_con: [PERM-06, PERM-12]
```

```yaml
- id: PERM-05
  pattern: witness-typehash-collision
  name: "Colisión de type hash en witness data de SignatureTransfer"
  causa_raiz: "SignatureTransfer permite incluir 'witness' data arbitraria que se hashea junto con el permit. El witness type string se pasa como parámetro y se hashea para formar parte del struct hash EIP-712. Si dos protocolos usan witness types con el mismo nombre pero semántica diferente, o si el type string se puede manipular para producir colisiones, una firma destinada a un protocolo podría validar en otro."
  como_funciona: |
    1. Protocolo A define witness type "OrderData(address recipient,uint256 amount)".
    2. Protocolo B define witness type "OrderData(address recipient,uint256 amount)" (mismo nombre, misma estructura, pero semántica diferente).
    3. Usuario firma un permit con witness para Protocolo A.
    4. Si el spender address no se valida correctamente, Protocolo B podría aceptar la misma firma.
    5. La firma valida porque el witness type hash es idéntico.
    6. Los fondos se transfieren en un contexto no intencionado por el usuario.
  invariante: |
    // Witness type string debe ser único por protocolo
    // El spender address actúa como discriminador
    function invariant_witness_binding(address expectedSpender) external view {
        // En Permit2, permitTransferFrom con witness requiere que msg.sender == spender de la firma
        // Esto es la protección principal contra witness collision
        assert(msg.sender == expectedSpender);
    }
  patron_vulnerable: |
    // Permit2 core (la protección está en spender == msg.sender):
    // function permitTransferFrom(
    //     PermitTransferFrom memory permit,
    //     SignatureTransferDetails calldata transferDetails,
    //     address owner,
    //     bytes32 witness,
    //     string calldata witnessTypeString,
    //     bytes calldata signature
    // ) external {
    //     _permitTransferFrom(permit, transferDetails, owner, permit.hash(),
    //         witness, witnessTypeString, signature);
    // }

    // Vulnerable: protocolo que no usa witness y permite spender genérico
    contract VulnerableAggregator {
        function executePermit(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            address owner,
            bytes calldata signature
        ) external {
            // Sin witness -- la firma es genérica
            // Cualquier protocolo con el mismo token/amount/nonce podría reusarla
            permit2.permitTransferFrom(permit, details, owner, signature);
        }
    }
  test_invariante: |
    function test_witness_collision_blocked() public {
        bytes32 witnessA = keccak256(abi.encode(orderA));
        bytes32 witnessB = keccak256(abi.encode(orderB));

        // Firma para protocolo A con witness A
        bytes memory sig = _signPermitWithWitness(permit, details, witnessA, WITNESS_TYPE_A, signerKey);

        // Intento de usar la firma en protocolo B con witness B (debe fallar)
        vm.prank(address(protocolB));
        vm.expectRevert();
        permit2.permitTransferFrom(permit, details, signer, witnessB, WITNESS_TYPE_B, sig);
    }
  ejemplo_real:
    - "Uniswap Permit2 design: la protección contra witness collision es que spender == msg.sender, pero protocolos que actúan como routers universales (spender genérico) debilitan esta protección"
    - "ABDK Audit Permit2: analizó la superficie de ataque de witness type strings y confirmó que el EIP-712 type hash encoding previene colisiones triviales"
    - "Universal Router security model: usa witness para encodear comandos específicos, binding fuerte entre firma y acción"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "ABDK Permit2 Audit, Uniswap Permit2 design docs"
  tags: [permit2, witness, typehash, collision, EIP-712, spender-binding]
  relacionado_con: [PERM-01, PERM-06]
```

```yaml
- id: PERM-06
  pattern: batch-permit-ordering-attack
  name: "Ataques de reordenamiento en batch permit signatures"
  causa_raiz: "Permit2 soporta operaciones batch (permitTransferFrom con arrays) donde múltiples tokens se transfieren en una sola firma. Si el orden de los tokens/amounts en el batch no se valida estrictamente, o si un atacante puede reordenar los elementos, puede cambiar qué token se transfiere a qué destino."
  como_funciona: |
    1. Usuario firma un batch permit: [tokenA → recipientX, tokenB → recipientY].
    2. El protocolo integrador recibe la firma y construye los SignatureTransferDetails.
    3. Si el integrador no valida que los details coincidan exactamente con lo firmado:
    4. Atacante reordena los details: [tokenA → recipientY, tokenB → recipientX].
    5. La firma valida porque Permit2 hashea permitted[] en orden, pero los details se pasan separados.
    6. Los tokens se envían a destinatarios incorrectos.
  invariante: |
    // En batch transfers, los details deben corresponder 1:1 con los permitted tokens
    function invariant_batch_ordering() external {
        // Permit2 enforces: permitted.length == details.length
        // Y cada detail.token debe coincidir con permitted[i].token
        // PERO: los details (requestedAmount, to) los provee el caller
        for (uint i = 0; i < permitted.length; i++) {
            assert(details[i].requestedAmount <= permitted[i].amount);
            // 'to' address in details is NOT part of the signed data
            // ^ ESTE es el vector de ataque
        }
    }
  patron_vulnerable: |
    // El 'to' en SignatureTransferDetails NO está firmado por el usuario
    // Solo está firmado: token, amount, nonce, deadline, spender
    // El spender (msg.sender) decide 'to' en runtime

    contract VulnerableBatchRouter {
        function executeBatch(
            ISignatureTransfer.PermitBatchTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails[] calldata details,
            address owner,
            bytes calldata signature
        ) external {
            // El router decide los 'to' addresses
            // Si un atacante controla este router (o hay un bug en la lógica):
            // puede enviar los tokens a direcciones arbitrarias
            permit2.permitTransferFrom(permit, details, owner, signature);
        }
    }
  test_invariante: |
    function test_batch_reorder_exploit() public {
        ISignatureTransfer.TokenPermissions[] memory permitted = new ISignatureTransfer.TokenPermissions[](2);
        permitted[0] = ISignatureTransfer.TokenPermissions(address(tokenA), 100e18);
        permitted[1] = ISignatureTransfer.TokenPermissions(address(tokenB), 200e18);

        // Detalles legítimos: tokenA -> user, tokenB -> protocol
        ISignatureTransfer.SignatureTransferDetails[] memory details =
            new ISignatureTransfer.SignatureTransferDetails[](2);
        details[0] = ISignatureTransfer.SignatureTransferDetails(user, 100e18);
        details[1] = ISignatureTransfer.SignatureTransferDetails(address(protocol), 200e18);

        // Detalles maliciosos: tokenA -> attacker, tokenB -> attacker
        ISignatureTransfer.SignatureTransferDetails[] memory malicious =
            new ISignatureTransfer.SignatureTransferDetails[](2);
        malicious[0] = ISignatureTransfer.SignatureTransferDetails(attacker, 100e18);
        malicious[1] = ISignatureTransfer.SignatureTransferDetails(attacker, 200e18);

        bytes memory sig = _signBatchPermit(batchPermit, signerKey);

        // Atacante como spender ejecuta con detalles maliciosos
        vm.prank(address(vulnRouter));
        permit2.permitTransferFrom(batchPermit, malicious, signer, sig);
        // ^ PASA porque 'to' no es parte de la firma
    }
  ejemplo_real:
    - "Uniswap Permit2 design: intencionalmente NO firma el 'to' address en SignatureTransferDetails -- el spender (msg.sender) controla el destino. Esto es by-design pero crea riesgo si el spender tiene bugs"
    - "Universal Router: mitiga esto siendo un contrato immutable auditado que hardcodea los destinatarios"
    - "Code4rena: findings en routers que usan Permit2 batch sin validar que los destinatarios coincidan con la intención del usuario"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Uniswap Permit2 design, Code4rena findings"
  tags: [permit2, batch, ordering, SignatureTransferDetails, to-address, spender]
  relacionado_con: [PERM-04, PERM-05]
```

```yaml
- id: PERM-07
  pattern: erc2612-permit-frontrunning
  name: "Front-running de ERC-2612 permit (race condition clásica)"
  causa_raiz: "Las funciones que combinan permit() + acción (e.g., permitAndDeposit) son vulnerables a front-running. Un atacante extrae la firma del mempool, llama permit() directamente, y la transacción de la víctima revierte porque el nonce ya se consumió."
  como_funciona: |
    1. Usuario firma un ERC-2612 permit y lo envía como parte de depositWithPermit(amount, deadline, v, r, s).
    2. Atacante ve la transacción pendiente en el mempool.
    3. Atacante extrae (v, r, s, deadline, amount, owner, spender) del calldata.
    4. Atacante front-runs llamando token.permit(owner, spender, amount, deadline, v, r, s) directamente.
    5. El permit se ejecuta: el nonce del owner se incrementa.
    6. La transacción original de la víctima revierte: el nonce ya no coincide con la firma.
    7. DoS al usuario -- debe firmar de nuevo y resubmitir.
  invariante: |
    // Funciones con permit integrado deben ser resistentes a front-running
    function invariant_permit_frontrun_resistant() external {
        // Patrón correcto: try/catch en permit, verificar allowance post-permit
        // Si permit falla pero allowance ya es suficiente, continuar
        try token.permit(owner, spender, amount, deadline, v, r, s) {} catch {}
        require(token.allowance(owner, spender) >= amount, "insufficient allowance");
    }
  patron_vulnerable: |
    // VULNERABLE: permit sin try/catch
    contract VulnerableVault {
        function depositWithPermit(
            uint256 amount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            // Si permit revierte (front-runned), toda la tx falla
            token.permit(msg.sender, address(this), amount, deadline, v, r, s);
            token.transferFrom(msg.sender, address(this), amount);
            _mint(msg.sender, amount);
        }
    }

    // CORRECTO: con try/catch
    contract SafeVault {
        function depositWithPermit(
            uint256 amount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            try token.permit(msg.sender, address(this), amount, deadline, v, r, s) {} catch {
                // Si el permit ya se ejecutó (front-run), verificamos allowance
                require(token.allowance(msg.sender, address(this)) >= amount, "no allowance");
            }
            token.transferFrom(msg.sender, address(this), amount);
            _mint(msg.sender, amount);
        }
    }
  test_invariante: |
    function test_permit_frontrun_dos() public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, permitDigest);

        // Atacante front-runs el permit
        vm.prank(attacker);
        token.permit(user, address(vault), amount, deadline, v, r, s);

        // La tx del usuario debe seguir funcionando (si el vault es seguro)
        vm.prank(user);
        vault.depositWithPermit(amount, deadline, v, r, s);
        // Si revierte aquí -> vulnerable a DoS
    }
  ejemplo_real:
    - "Solodit #41728: OlympusDAO -- depositWithPermit reverts if permit is front-run, DoS for users (MEDIUM)"
    - "Solodit #40118: LooksRare -- multicall + permit frontrun causes locked funds (MEDIUM)"
    - "Solodit #38872: Silo Finance -- permit frontrunning DoS in deposit flow (MEDIUM)"
    - "OpenZeppelin Advisory: recomendación universal de usar try/catch para permit calls"
    - "Cantina: múltiples findings de permit front-running DoS en protocolos DeFi (2023-2024)"
  solodit_ids:
    - h-03-attacker-can-steal-funds-when-users-use-a-permit-flow-code4rena-metalabel-metalabel-git
    - m-02-deposit-with-permit-can-be-front-run-blocking-future-calls-to-it-code4rena-caviar-caviar-git
    - m-02-permit-functions-can-be-front-run-code4rena-llama-llama-git
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit, OpenZeppelin advisory"
  tags: [permit, ERC-2612, front-running, DoS, try-catch, nonce]
  relacionado_con: [PERM-08, PERM-09]
```

```yaml
- id: PERM-08
  pattern: permit-plus-transferfrom-double-spend
  name: "Double-spend con permit + transferFrom combinado"
  causa_raiz: "Cuando un contrato usa permit() para establecer allowance y luego transferFrom() en la misma transacción, existe un vector donde el atacante puede hacer que el usuario firme un permit a un spender y luego explotar la allowance residual. Si el usuario ya tenía allowance previa, el permit puede INCREMENTAR la exposición."
  como_funciona: |
    1. Usuario tiene allowance de 100 tokens a SpenderContract (de una operación anterior).
    2. Usuario firma un nuevo permit por 200 tokens al mismo SpenderContract.
    3. Atacante ve el permit en el mempool.
    4. Atacante front-runs: ejecuta transferFrom(user, attacker, 100) usando la allowance existente.
    5. El permit se ejecuta: establece allowance a 200 (REEMPLAZA, no suma).
    6. Atacante ejecuta otro transferFrom(user, attacker, 200) usando la nueva allowance.
    7. Total robado: 300 tokens (100 de allowance vieja + 200 de permit nueva).
    8. Sin el permit, el atacante solo podría robar 100.
  invariante: |
    // Permit no debe crear allowance acumulativa explotable
    function invariant_no_double_spend(address owner, address spender, uint256 permitAmount) external {
        uint256 preAllowance = token.allowance(owner, spender);
        // El riesgo es cuando preAllowance > 0 Y permit establece nueva allowance
        // Total explotable = preAllowance + permitAmount (en el peor caso)
        // Mitigación: aumentar de 0, o decreaseAllowance primero
    }
  patron_vulnerable: |
    // Token ERC-20 estándar: permit REEMPLAZA allowance (no suma)
    // Pero el timing entre transacciones crea el double-spend window

    // Escenario vulnerable en un protocolo:
    contract VulnerableManager {
        function updateAndTransfer(
            uint256 newAmount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            // Paso 1: permit establece nueva allowance
            token.permit(msg.sender, address(this), newAmount, deadline, v, r, s);
            // WINDOW: entre permit() y transferFrom(), la allowance vieja ya se usó
            // Paso 2: transfer con nueva allowance
            token.transferFrom(msg.sender, address(this), newAmount);
        }
    }
  test_invariante: |
    function test_permit_double_spend() public {
        // Setup: usuario ya tiene allowance de 100 a spender
        vm.prank(user);
        token.approve(address(spender), 100e18);

        // Usuario firma permit por 200 (intención: reemplazar los 100 por 200)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, permitDigest200);

        // Atacante explota allowance vieja ANTES del permit
        vm.prank(address(spender));
        token.transferFrom(user, attacker, 100e18);

        // Permit se ejecuta: establece allowance a 200
        token.permit(user, address(spender), 200e18, deadline, v, r, s);

        // Atacante usa nueva allowance
        vm.prank(address(spender));
        token.transferFrom(user, attacker, 200e18);

        // Total robado: 300e18 (no los 200 que el usuario pretendía)
    }
  ejemplo_real:
    - "ERC-20 approve race condition: documentada en EIP-20, el vector original que motivó increaseAllowance/decreaseAllowance"
    - "Permit amplifica el problema porque la firma es off-chain y visible en el mempool antes de ejecución"
    - "Solodit #38872: finding relacionado donde permit crea ventana para doble gasto"
  severidad: high
  confianza: media
  verificado: true
  fuente: "EIP-20 known issue, extended to permit context"
  tags: [permit, double-spend, allowance, race-condition, front-running]
  relacionado_con: [PERM-07, PERM-10]
```

```yaml
- id: PERM-09
  pattern: dai-permit-incompatibility
  name: "Incompatibilidad de DAI-style permit (nonce no estándar)"
  causa_raiz: "DAI implementó permit() antes de ERC-2612 con una interfaz diferente: permit(holder, spender, nonce, expiry, allowed, v, r, s) donde 'allowed' es un bool (no amount). Protocolos que asumen la interfaz ERC-2612 estándar (con uint256 value) fallan silenciosamente o revierten al interactuar con DAI y tokens similares."
  como_funciona: |
    1. Protocolo implementa depositWithPermit() asumiendo ERC-2612: permit(owner, spender, value, deadline, v, r, s).
    2. Usuario intenta usar DAI como token de depósito.
    3. La llamada a DAI.permit() falla porque DAI espera: permit(holder, spender, nonce, expiry, allowed, v, r, s).
    4. El parámetro 'value' (uint256 amount) se interpreta como 'nonce' en DAI.
    5. El parámetro 'deadline' se interpreta como 'expiry'.
    6. Falta el parámetro 'allowed' (bool).
    7. La transacción revierte o produce comportamiento inesperado.
  invariante: |
    // Antes de llamar permit, verificar que el token implementa ERC-2612 estándar
    function invariant_permit_compatibility(address token) external view {
        // Verificar firma de permit: bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"))
        // DAI tiene:          bytes4(keccak256("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)"))
        // Si el selector no coincide, no usar permit estándar
    }
  patron_vulnerable: |
    // Protocolo que asume ERC-2612 para todos los tokens
    contract VulnerableRouter {
        function swapWithPermit(
            address token,
            uint256 amount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            // VULNERABLE: DAI tiene interfaz diferente
            // Esta llamada revierte o tiene undefined behavior con DAI
            IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
            IERC20(token).transferFrom(msg.sender, address(this), amount);
            _swap(token, amount);
        }
    }

    // DAI permit interface (diferente):
    // function permit(
    //     address holder,
    //     address spender,
    //     uint256 nonce,      // <-- NO es 'value'
    //     uint256 expiry,     // <-- es 'deadline' pero en diferente posición semántica
    //     bool allowed,       // <-- parámetro extra
    //     uint8 v, bytes32 r, bytes32 s
    // ) external;
  test_invariante: |
    function test_dai_permit_revert() public {
        address dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F; // Mainnet DAI

        vm.expectRevert(); // o decode error
        IERC20Permit(dai).permit(
            user, address(this), 1000e18, block.timestamp + 1 hours, v, r, s
        );
    }
  ejemplo_real:
    - "Sherlock: múltiples findings donde protocolos fallan con DAI permit porque asumen ERC-2612"
    - "DAI, RAI, CHAI, SAI: todos usan el formato de permit no estándar"
    - "Solodit: findings en Aave, Compound forks, y DEX aggregators que no manejan DAI permit"
    - "Uniswap Universal Router: maneja específicamente DAI permit con lógica condicional"
  solodit_ids:
    - m-01-gasless-approvals-via-permit-will-not-work-for-some-tokens-e-g-dai-sherlock-dodo-dodo-v3-backstage-pass-git
    - m-04-non-standard-erc20-permit-revert-causes-dos-sherlock-none-real-wagmi-markdown
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Sherlock findings, DAI source code"
  tags: [permit, DAI, ERC-2612, non-standard, compatibility, revert]
  relacionado_con: [PERM-07, PERM-14]
```

```yaml
- id: PERM-10
  pattern: phishing-permit-signature
  name: "Robo de fondos via phishing de firmas permit/Permit2"
  causa_raiz: "El usuario firma un mensaje EIP-712 que parece inocuo pero en realidad es un permit o Permit2 SignatureTransfer que autoriza la transferencia de sus tokens a un atacante. Como Permit2 requiere una sola aprobación infinita al contrato Permit2, cualquier firma maliciosa posterior puede drenar fondos sin una nueva transacción on-chain del usuario."
  como_funciona: |
    1. Atacante crea un sitio web phishing que simula ser una dApp legítima (mint NFT, claim airdrop, etc).
    2. El sitio pide al usuario que firme un mensaje con su wallet (MetaMask muestra 'Sign' request).
    3. El mensaje es en realidad un EIP-712 PermitTransferFrom de Permit2 o un permit ERC-2612.
    4. La firma autoriza la transferencia de tokens del usuario al atacante.
    5. MetaMask/wallets no siempre muestran claramente qué tipo de mensaje se está firmando.
    6. El usuario firma creyendo que es una acción inocua.
    7. El atacante submitea la firma en una transacción que ejecuta el transferFrom.
    8. Los fondos del usuario se drenan instantáneamente.
  invariante: |
    // No hay invariante on-chain para phishing -- es un problema de UX/wallet
    // La mitigación on-chain es:
    function invariant_revoke_stale_approvals(address user, address token) external view {
        (uint160 amount, uint48 expiration,) = permit2.allowance(user, token, address(0));
        // Usuarios deben revocar allowances que no reconocen
        // Herramientas: revoke.cash, approved.zone
    }
  patron_vulnerable: |
    // El ataque no requiere contrato vulnerable -- es social engineering
    // Pero el vector técnico es:

    // 1. Atacante construye un permit message válido:
    ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
        permitted: ISignatureTransfer.TokenPermissions({
            token: USDC,
            amount: type(uint256).max  // Drena todo
        }),
        nonce: unusedNonce,
        deadline: type(uint256).max    // Nunca expira
    });

    ISignatureTransfer.SignatureTransferDetails memory details =
        ISignatureTransfer.SignatureTransferDetails({
            to: attackerAddress,
            requestedAmount: victimBalance
        });

    // 2. Atacante presenta el hash al usuario como "sign to verify identity"
    // 3. Usuario firma → atacante tiene la signature
    // 4. Atacante ejecuta:
    permit2.permitTransferFrom(permit, details, victimAddress, phishedSignature);
  test_invariante: |
    function test_phishing_scenario() public {
        // Simular: usuario ya aprobó Permit2 en el token
        vm.prank(victim);
        token.approve(address(permit2), type(uint256).max);

        // Atacante obtiene firma phishing
        bytes memory phishedSig = _signPermit(maliciousPermit, details, victimKey);

        // Atacante ejecuta la transferencia
        vm.prank(attacker);
        permit2.permitTransferFrom(maliciousPermit, details, victim, phishedSig);

        assertEq(token.balanceOf(victim), 0);
        assertEq(token.balanceOf(attacker), originalBalance);
    }
  ejemplo_real:
    - "Inferno Drainer (2023-2024): kit de phishing que robó >$70M usando firmas permit de tokens ERC-20"
    - "Angel Drainer / Pink Drainer: variantes que usan Permit2 SignatureTransfer para drenar múltiples tokens en una sola firma"
    - "OpenSea Wyvern exploit (Jan 2022): firmas de órdenes de venta usadas para robar NFTs -- patrón conceptualmente idéntico"
    - "Kevin Rose hack (Jan 2023): $1.1M en NFTs robados via firma de Seaport order phishing"
    - "Luke Dashjr BTC hack: técnica diferente pero mismo vector de social engineering"
    - "Monkey Drainer (2022): robó ~$24M usando firmas de approve/permit"
    - "Revoke.cash y etherscan.io/tokenapprovalchecker: herramientas de mitigación para revocar aprobaciones"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "SlowMist reports, Forta threat intelligence, on-chain analysis"
  tags: [phishing, permit, permit2, social-engineering, drainer, signature, wallet-UX]
  relacionado_con: [PERM-03, PERM-13]
```

```yaml
- id: PERM-11
  pattern: permit2-lockdown-bypass
  name: "Bypass del mecanismo lockdown/operator en Permit2"
  causa_raiz: "Permit2 permite a los usuarios revocar aprobaciones por token/spender. Sin embargo, si un protocolo integrador actúa como intermediario (router/operator), revocar el spender del protocolo no revoca las aprobaciones que el protocolo otorgó internamente. Además, algunos protocolos implementan mecanismos de 'lockdown' (revocar todos los spenders) que pueden tener gaps."
  como_funciona: |
    1. Usuario aprueba Permit2 → Permit2 aprueba Router → Router aprueba SubProtocol.
    2. Usuario revoca la aprobación a Router en Permit2.
    3. PERO: si Router ya transfirió tokens a SubProtocol via una transacción previa, esos fondos siguen en SubProtocol.
    4. Alternativamente: si Router tiene una función que permite transferir sin nueva firma (usando allowance existente), el lockdown no protege contra transacciones ya en vuelo.
    5. En otro escenario: usuario usa Permit2.lockdown() para revocar múltiples spenders, pero omite uno que tiene allowance activa.
  invariante: |
    // Después de lockdown, NINGÚN spender debe tener allowance
    function invariant_lockdown_complete(address user, address token) external view {
        address[] memory knownSpenders = getKnownSpenders();
        for (uint i = 0; i < knownSpenders.length; i++) {
            (uint160 amount,,) = permit2.allowance(user, token, knownSpenders[i]);
            assert(amount == 0); // Post-lockdown, todo debe ser 0
        }
    }
  patron_vulnerable: |
    // Permit2 lockdown solo revoca los pares (token, spender) especificados
    // Si el usuario olvida un par, queda expuesto

    // function lockdown(TokenSpenderPair[] calldata approvals) external {
    //     uint256 length = approvals.length;
    //     for (uint256 i = 0; i < length; ++i) {
    //         address token = approvals[i].token;
    //         address spender = approvals[i].spender;
    //         allowance[msg.sender][token][spender].amount = 0;
    //         // Solo revoca los pares explícitamente listados
    //     }
    // }

    // Vulnerable: usuario lockdowns tokenA/spenderX pero olvida tokenB/spenderX
    // SpenderX todavía puede transferir tokenB
  test_invariante: |
    function test_incomplete_lockdown() public {
        // Setup: usuario aprueba USDC y WETH a spender
        vm.startPrank(user);
        permit2.approve(address(usdc), spender, type(uint160).max, type(uint48).max);
        permit2.approve(address(weth), spender, type(uint160).max, type(uint48).max);

        // Lockdown parcial: solo revoca USDC
        IAllowanceTransfer.TokenSpenderPair[] memory pairs = new IAllowanceTransfer.TokenSpenderPair[](1);
        pairs[0] = IAllowanceTransfer.TokenSpenderPair(address(usdc), spender);
        permit2.lockdown(pairs);
        vm.stopPrank();

        // WETH todavía está aprobado
        (uint160 wethAllowance,,) = permit2.allowance(user, address(weth), spender);
        assertGt(wethAllowance, 0); // Todavía vulnerable para WETH
    }
  ejemplo_real:
    - "Permit2 design: lockdown() requiere lista explícita de pares -- no hay 'revoke all' universal"
    - "revoke.cash: muestra a usuarios sus aprobaciones activas para facilitar lockdown completo"
    - "Multiple DeFi hacks donde usuarios creían haber revocado pero tenían aprobaciones residuales en otros tokens"
    - "OpenZeppelin Permit2 audit: señaló que la interfaz de lockdown puede dar falsa sensación de seguridad"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Permit2 source code, OpenZeppelin audit"
  tags: [permit2, lockdown, revoke, allowance, operator, incomplete-revocation]
  relacionado_con: [PERM-03, PERM-13]
```

```yaml
- id: PERM-12
  pattern: unordered-nonce-invalidation-gaps
  name: "Gaps en la invalidación de nonces no ordenados"
  causa_raiz: "Permit2 SignatureTransfer usa nonces no ordenados (bitmap-based). Esto significa que los nonces no necesitan usarse en secuencia -- el usuario puede usar nonce 5 antes que nonce 3. Sin embargo, esto crea la posibilidad de que firmas con nonces no usados queden 'pendientes' indefinidamente si el usuario no las invalida explícitamente."
  como_funciona: |
    1. Usuario firma 3 mensajes con nonces 0, 1, 2 para un protocol.
    2. Solo nonce 0 y 2 se ejecutan; nonce 1 queda sin usar (firma pendiente).
    3. El usuario cree que ya no hay firmas activas.
    4. Meses después, el protocolo (o un atacante que obtuvo la firma) ejecuta nonce 1.
    5. La firma sigue siendo válida (asumiendo deadline no expirado).
    6. La transferencia se ejecuta en condiciones que el usuario ya no desea.
    7. A diferencia de nonces secuenciales (ERC-2612), no hay forma de 'cancelar todo' incrementando el nonce.
  invariante: |
    // Toda firma emitida debe ejecutarse o invalidarse explícitamente
    function invariant_no_pending_nonces(address user, uint256 wordPos) external view {
        uint256 bitmap = permit2.nonceBitmap(user, wordPos);
        // Verificar que no hay bits en 0 para nonces que se firmaron
        // (requiere tracking off-chain de qué nonces se firmaron)
    }
  patron_vulnerable: |
    // El problema es inherente al diseño de nonces no ordenados
    // Escenario vulnerable: intent/order system

    contract IntentSystem {
        struct Intent {
            uint256 permitNonce;   // Nonce de Permit2
            uint256 price;
            uint256 amount;
        }

        mapping(bytes32 => Intent) public pendingIntents;

        // Usuario crea intent con firma Permit2
        function createIntent(Intent calldata intent, bytes calldata permitSig) external {
            pendingIntents[keccak256(abi.encode(intent))] = intent;
            // La firma se almacena off-chain
        }

        // Filler ejecuta intent -- puede ejecutar MESES después
        function fillIntent(
            Intent calldata intent,
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            // Si el usuario no invalidó el nonce, esto funciona
            permit2.permitTransferFrom(permit, details, intentOwner, signature);
        }
    }
  test_invariante: |
    function test_stale_nonce_execution() public {
        // Usuario firma con nonce 1
        bytes memory sig1 = _signPermit(permit1, details, 1, signerKey);

        // Usuario firma con nonce 2 y se ejecuta
        bytes memory sig2 = _signPermit(permit2, details, 2, signerKey);
        permit2.permitTransferFrom(permit2, details, signer, sig2);

        // Nonce 1 todavía es válido y puede ejecutarse
        // Incluso DESPUÉS de que nonce 2 se usó
        permit2.permitTransferFrom(permit1, details, signer, sig1);
        // ^ Esto PASA -- nonce 1 no se invalidó
    }
  ejemplo_real:
    - "Permit2 design decision: nonces no ordenados elegidos para soporte de intents/orders concurrentes, pero crean riesgo de firmas zombi"
    - "ABDK Permit2 Audit: documentó el riesgo de nonces no consumidos y recomendó que usuarios invaliden activamente nonces no usados"
    - "UniswapX, Across Protocol: protocolos de intents que usan Permit2 deben implementar mecanismos de cancelación de orders que invaliden nonces"
    - "Cantina: findings donde orders canceladas off-chain siguen siendo ejecutables on-chain porque el nonce Permit2 no se invalidó"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "ABDK Permit2 Audit, intent protocol designs"
  tags: [permit2, nonce, unordered, bitmap, stale-signature, intent, order-cancellation]
  relacionado_con: [PERM-04, PERM-17]
```

```yaml
- id: PERM-13
  pattern: max-allowance-permanent-approval
  name: "Riesgo de aprobación permanente con MaxAllowance type(uint160).max"
  causa_raiz: "Permit2 AllowanceTransfer usa type(uint160).max como indicador especial de 'aprobación infinita' -- cuando el amount es max, no se decrementa tras transferencias. Esto crea una aprobación permanente que persiste hasta que el usuario la revoca explícitamente, exponiendo todo su balance del token al spender de forma indefinida."
  como_funciona: |
    1. Protocolo pide al usuario firmar un AllowanceTransfer permit con amount = type(uint160).max.
    2. La aprobación se establece en Permit2 sin expiración efectiva.
    3. El contrato spender puede llamar transferFrom múltiples veces sin límite.
    4. Si el spender tiene una vulnerabilidad (ahora o en el futuro via upgrade):
    5. Atacante explota el spender para drenar todos los tokens del usuario.
    6. Como el amount es max, no se reduce con cada uso -- la aprobación nunca se agota.
    7. El usuario ni siquiera sabe que tiene esta aprobación activa salvo que use revoke.cash.
  invariante: |
    // MaxAllowance no debe decrementarse (by design) -- verificar que
    // la política del protocolo no dependa de la reducción automática
    function invariant_max_allowance_awareness(address user, address token, address spender) external view {
        (uint160 amount, uint48 expiration,) = permit2.allowance(user, token, spender);
        if (amount == type(uint160).max) {
            // WARNING: aprobación infinita activa
            // Verificar que expiration no sea también infinita
            assert(expiration < type(uint48).max); // Al menos debe tener fecha de expiración
        }
    }
  patron_vulnerable: |
    // Permit2 core -- comportamiento de MaxAllowance:
    // function _transfer(address from, address to, uint160 amount, address token) private {
    //     PackedAllowance storage allowed = allowance[from][token][msg.sender];
    //     if (allowed.amount != type(uint160).max) {
    //         // Solo decrementa si NO es max
    //         if (amount > allowed.amount) revert InsufficientAllowance(allowed.amount);
    //         unchecked { allowed.amount -= amount; }
    //     }
    //     // Si es max, NO se reduce -- transferencia ilimitada
    //     ERC20(token).safeTransferFrom(from, to, amount);
    // }

    // Protocolo que pide max allowance sin necesidad:
    contract GreedyProtocol {
        function approveProtocol(address token) external {
            // Pide al usuario max allowance cuando solo necesita amount específico
            // El SDK/frontend pide: permit2.approve(token, address(this), type(uint160).max, type(uint48).max)
        }

        function deposit(address token, uint256 amount) external {
            permit2.transferFrom(msg.sender, address(this), uint160(amount), token);
        }
    }
  test_invariante: |
    function test_max_allowance_persists() public {
        vm.prank(user);
        permit2.approve(address(token), spender, type(uint160).max, type(uint48).max);

        // Transferir 1000 tokens
        vm.prank(spender);
        permit2.transferFrom(user, spender, 1000e6, address(token));

        // Allowance sigue siendo max (NO se redujo)
        (uint160 remaining,,) = permit2.allowance(user, address(token), spender);
        assertEq(remaining, type(uint160).max); // Infinito para siempre

        // Spender puede transferir de nuevo sin límite
        vm.prank(spender);
        permit2.transferFrom(user, spender, uint160(token.balanceOf(user)), address(token));
        // ^ Drena TODO el balance
    }
  ejemplo_real:
    - "Uniswap Labs UI: por defecto pide max approval a Permit2, luego usa SignatureTransfer con amounts específicos -- pero la aprobación ERC-20 subyacente a Permit2 es infinita"
    - "Revoke.cash: reporta millones de wallets con max approval a Permit2 contract"
    - "Permit2 ABDK Audit: señaló que type(uint160).max como 'infinite approval' es un design choice con trade-off de seguridad explícito"
    - "Inferno/Angel Drainer: explotan max approvals a Permit2 para drenar tokens vía firmas phishing"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Permit2 source code, ABDK audit"
  tags: [permit2, max-allowance, infinite-approval, type-uint160-max, persistent-risk]
  relacionado_con: [PERM-03, PERM-10]
```

```yaml
- id: PERM-14
  pattern: non-standard-permit-revert
  name: "Tokens con permit no estándar (USDT, BNB) causan reverts"
  causa_raiz: "Algunos tokens populares no implementan ERC-2612 permit o lo implementan de forma no estándar. USDT no tiene permit. Algunos tokens tienen permit pero no retornan bool. Otros tienen permit con interfaz diferente (como DAI). Protocolos que asumen permit estándar para todos los tokens fallan silenciosamente o revierten."
  como_funciona: |
    1. Protocolo implementa depositWithPermit() que llama IERC20Permit(token).permit(...).
    2. Usuario intenta depositar USDT (no tiene permit).
    3. La llamada revierte: USDT no tiene la función permit().
    4. El usuario no puede usar la ruta optimizada con permit.
    5. En el peor caso: si no hay ruta alternativa sin permit, el usuario queda bloqueado.
    6. Variante: token tiene permit pero retorna bytes en lugar de void, causando decode error.
    7. Variante: token tiene permit con interfaz de 8 parámetros (DAI-style) vs 7 parámetros (ERC-2612).
  invariante: |
    // Verificar soporte de permit antes de llamar
    function invariant_permit_support(address token) external view {
        // Verificar que el token soporta ERC-2612
        try IERC20Permit(token).DOMAIN_SEPARATOR() returns (bytes32) {
            // Tiene domain separator -- probablemente soporta permit
        } catch {
            // No soporta permit -- usar approve flow clásico
        }
    }
  patron_vulnerable: |
    // Protocolo que no maneja tokens sin permit
    contract VulnerableRouter {
        function depositWithPermit(
            address token,
            uint256 amount,
            uint256 deadline,
            uint8 v, bytes32 r, bytes32 s
        ) external {
            // Revierte para USDT, BNB, y otros tokens sin permit
            IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s);
            IERC20(token).transferFrom(msg.sender, address(this), amount);
        }

        // FALTA: ruta alternativa sin permit
        // function deposit(address token, uint256 amount) external { ... }
    }

    // Tokens problemáticos conocidos:
    // - USDT: no tiene permit
    // - BNB: no tiene permit
    // - WBTC: no tiene permit (en algunas implementaciones)
    // - DAI: permit no estándar (8 params, bool allowed)
    // - USDC: tiene permit estándar (OK)
    // - WETH: no tiene permit (en la mayoría de implementaciones)
  test_invariante: |
    function test_usdt_permit_reverts() public {
        address usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

        vm.expectRevert();
        IERC20Permit(usdt).permit(
            user, address(router), 1000e6, block.timestamp + 1 hours, v, r, s
        );
    }

    function test_fallback_to_approve() public {
        // El protocolo debe tener un camino alternativo
        vm.prank(user);
        IERC20(usdt).approve(address(router), 1000e6);
        router.deposit(address(usdt), 1000e6); // Debe funcionar sin permit
    }
  ejemplo_real:
    - "Sherlock: múltiples findings donde funciones *WithPermit revierten para USDT/WBTC/BNB"
    - "Solodit: 'Non-standard ERC20 permit revert causes DoS' -- patrón recurrente en auditorías"
    - "USDT Tether: la implementación más usada del mundo NO tiene permit"
    - "Uniswap Universal Router: maneja explícitamente la ausencia de permit con try/catch"
  solodit_ids:
    - m-04-non-standard-erc20-permit-revert-causes-dos-sherlock-none-real-wagmi-markdown
    - m-01-gasless-approvals-via-permit-will-not-work-for-some-tokens-e-g-dai-sherlock-dodo-dodo-v3-backstage-pass-git
    - m-14-some-erc20-can-revert-on-a-zero-value-transfer-sherlock-none-real-wagmi-markdown
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Sherlock findings, token implementations"
  tags: [permit, USDT, non-standard, revert, compatibility, DoS]
  relacionado_con: [PERM-09, PERM-07]
```

```yaml
- id: PERM-15
  pattern: permit2-hooks-reentrancy
  name: "Reentrancy via hooks/callbacks tras aprobación Permit2"
  causa_raiz: "Cuando Permit2 ejecuta una transferencia, el token subyacente puede tener hooks (ERC-777 tokensReceived, ERC-1155 onERC1155Received, etc.) que transfieren control al receptor. Si el protocolo integrador no tiene protección de reentrancy, un atacante puede re-entrar durante la transferencia y explotar estado inconsistente."
  como_funciona: |
    1. Protocolo integra Permit2 para transferencias de tokens.
    2. El token es un ERC-777 (o tiene hooks custom como tokensToSend/tokensReceived).
    3. Usuario firma un Permit2 SignatureTransfer.
    4. Permit2 llama token.safeTransferFrom(owner, recipient, amount).
    5. El token llama el hook tokensReceived() en el recipient.
    6. Si el recipient es un contrato atacante, el hook re-entra en el protocolo.
    7. El estado del protocolo está a medio actualizar (fondos transferidos pero balance interno no actualizado).
    8. El atacante explota la inconsistencia (e.g., retira de nuevo, mint shares extra).
  invariante: |
    // Todas las funciones que usan Permit2 deben ser non-reentrant
    function invariant_reentrancy_guard() external {
        // Verificar que el protocolo usa ReentrancyGuard en funciones con Permit2
        // O que sigue checks-effects-interactions
        assert(locked == true); // Durante ejecución, el guard debe estar activo
    }
  patron_vulnerable: |
    contract VulnerablePool {
        mapping(address => uint256) public balances;

        // Sin ReentrancyGuard
        function depositViaPermit2(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            // INTERACCIÓN ANTES DE EFECTO
            permit2.permitTransferFrom(permit, details, msg.sender, signature);
            // ^ Si el token tiene hooks, el callback se ejecuta AQUÍ
            // ^ Un contrato atacante puede re-entrar en depositViaPermit2 o withdraw

            // EFECTO DESPUÉS DE INTERACCIÓN (vulnerable)
            balances[msg.sender] += details.requestedAmount;
        }

        function withdraw(uint256 amount) external {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            token.transfer(msg.sender, amount);
        }
    }
  test_invariante: |
    function test_reentrancy_via_permit2() public {
        // Deploy token ERC-777 que llama hook en transferencia
        MockERC777 hookToken = new MockERC777();
        ReentrantAttacker attacker = new ReentrantAttacker(address(pool), address(permit2));

        hookToken.mint(address(attacker), 100e18);

        vm.prank(address(attacker));
        hookToken.approve(address(permit2), type(uint256).max);

        // Atacante ejecuta el ataque de reentrancy
        attacker.attack();

        // Si el pool es vulnerable, el atacante tiene más balance del que depositó
        assertGt(pool.balances(address(attacker)), 100e18);
    }
  ejemplo_real:
    - "Solodit: múltiples findings de reentrancy en protocolos que usan safeTransfer/safeTransferFrom con tokens ERC-777"
    - "imBTC hack (Uniswap V1, 2020): $300K robados via reentrancy con ERC-777 hooks en pool Uniswap"
    - "Cream Finance hack (2021): reentrancy via AMP token (ERC-777-like) durante flash loan"
    - "Permit2 usa safeTransferFrom de Solmate que no previene reentrancy -- la responsabilidad es del integrador"
  solodit_ids:
    - h-01-cross-function-reentrancy-when-an-erc-777-token-is-used-as-a-reserve-asset-code4rena-reserve-protocol-reserve-protocol-git
  severidad: high
  confianza: alta
  verificado: true
  fuente: "imBTC hack, Cream Finance hack, Solodit findings"
  tags: [permit2, reentrancy, ERC-777, hooks, callbacks, safeTransfer, CEI]
  relacionado_con: [PERM-16, PERM-06]
```

```yaml
- id: PERM-16
  pattern: fee-on-transfer-permit2
  name: "Discrepancia de amounts con fee-on-transfer tokens tras Permit2"
  causa_raiz: "Tokens con fee-on-transfer (como USDT con fee activado, PAXG, o deflationary tokens) transfieren menos tokens de los solicitados. Permit2 autoriza la transferencia de amount X, pero el receptor recibe X - fee. Si el protocolo registra X como depositado sin verificar el balance real recibido, hay una discrepancia contable explotable."
  como_funciona: |
    1. Token cobra 1% de fee en cada transferencia.
    2. Usuario firma Permit2 por 1000 tokens.
    3. Permit2 ejecuta safeTransferFrom(user, protocol, 1000).
    4. Protocol recibe 990 tokens (1000 - 1% fee).
    5. Protocol registra: balances[user] += 1000 (el amount firmado, no el recibido).
    6. El usuario puede retirar 1000 tokens aunque solo se depositaron 990.
    7. Los 10 tokens extra vienen de otros depositantes.
    8. Repetido suficientes veces, drena el pool.
  invariante: |
    // El amount registrado debe ser el amount REALMENTE recibido
    function invariant_actual_balance_received(address token, address pool) external {
        uint256 balanceBefore = IERC20(token).balanceOf(pool);
        // ... ejecutar transferencia de 'amount' ...
        uint256 balanceAfter = IERC20(token).balanceOf(pool);
        uint256 actualReceived = balanceAfter - balanceBefore;
        // El protocolo debe usar actualReceived, no amount
        assert(registeredDeposit == actualReceived);
    }
  patron_vulnerable: |
    contract VulnerableVault {
        mapping(address => uint256) public deposits;

        function depositWithPermit2(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            // Transfiere tokens via Permit2
            permit2.permitTransferFrom(permit, details, msg.sender, signature);

            // VULNERABLE: registra el amount solicitado, no el recibido
            deposits[msg.sender] += details.requestedAmount;
            // Si el token cobra fee, deposits > balance real del vault
        }

        function withdraw(uint256 amount) external {
            require(deposits[msg.sender] >= amount);
            deposits[msg.sender] -= amount;
            // Puede fallar o drenar fondos de otros usuarios
            IERC20(token).transfer(msg.sender, amount);
        }
    }

    // CORRECTO:
    contract SafeVault {
        function depositWithPermit2(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            uint256 balBefore = IERC20(token).balanceOf(address(this));
            permit2.permitTransferFrom(permit, details, msg.sender, signature);
            uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;

            deposits[msg.sender] += received; // Usa el amount real
        }
    }
  test_invariante: |
    function test_fee_on_transfer_accounting() public {
        // Token con 1% fee
        FeeToken feeToken = new FeeToken(1); // 1% fee
        feeToken.mint(user, 10_000e18);

        vm.prank(user);
        feeToken.approve(address(permit2), type(uint256).max);

        bytes memory sig = _signPermit(permit, details, signerKey);

        uint256 vaultBefore = feeToken.balanceOf(address(vault));
        vm.prank(address(vault));
        permit2.permitTransferFrom(permit, details, user, sig);
        uint256 received = feeToken.balanceOf(address(vault)) - vaultBefore;

        // El vault debería registrar 'received' no 'details.requestedAmount'
        assertLt(received, details.requestedAmount); // received < requested
        assertEq(vault.deposits(user), received);    // debe reflejar el real
    }
  ejemplo_real:
    - "STA token incident (Balancer, 2020): fee-on-transfer token drenó $500K del pool porque Balancer no verificaba balance recibido"
    - "Sherlock: docenas de findings de fee-on-transfer accounting mismatch en protocolos DeFi"
    - "USDT: tiene mecanismo de fee activable (actualmente 0% pero puede cambiar)"
    - "PAXG: cobra 0.02% fee por transferencia"
    - "Solodit: patrón recurrente -- 'fee-on-transfer tokens cause accounting issues'"
  solodit_ids:
    - m-01-fee-on-transfer-tokens-are-not-supported-code4rena-none-dinari-markdown
    - m-02-protocol-does-not-handle-fee-on-transfer-tokens-sherlock-none-allo-v2-markdown
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Balancer STA hack, Sherlock/C4 findings"
  tags: [permit2, fee-on-transfer, accounting, balance-check, deflationary-token]
  relacionado_con: [PERM-14, PERM-15]
```

```yaml
- id: PERM-17
  pattern: signature-deadline-too-far
  name: "SignatureDeadline excesivamente lejano habilita ataques diferidos"
  causa_raiz: "Permit2 valida que block.timestamp <= deadline, pero no impone un máximo. Si el usuario (o el SDK/frontend) establece deadline = type(uint256).max o un valor años en el futuro, la firma permanece válida indefinidamente. Esto permite ataques diferidos donde una firma obtenida (por leak, phishing, o compromiso del relayer) se ejecuta cuando las condiciones han cambiado drásticamente."
  como_funciona: |
    1. Usuario firma un Permit2 SignatureTransfer con deadline = type(uint256).max.
    2. La firma se almacena en un sistema off-chain (orderbook, intent solver, relayer).
    3. El sistema off-chain es comprometido meses después.
    4. Atacante obtiene la firma del usuario.
    5. El token ha cambiado de valor: era worth $1 cuando se firmó, ahora vale $100.
    6. Atacante ejecuta la firma antigua: transfiere tokens a precio obsoleto.
    7. El usuario pierde la diferencia de valor.
    8. Variante: la firma se obtuvo via phishing pero no se ejecutó inmediatamente -- el atacante espera a que el usuario acumule más tokens y luego ejecuta.
  invariante: |
    // Deadlines deben estar acotados a un rango razonable
    function invariant_reasonable_deadline(uint256 deadline) external view {
        // Política del protocolo: max 7 días (ajustar según caso de uso)
        assert(deadline <= block.timestamp + 7 days);
        // Permit2 core NO enforce esto -- es responsabilidad del integrador
    }
  patron_vulnerable: |
    // SDK/Frontend que usa deadline infinito por comodidad
    // JavaScript (ethers.js):
    // const permit = {
    //     permitted: { token: USDC, amount: userBalance },
    //     nonce: getUnusedNonce(),
    //     deadline: ethers.constants.MaxUint256  // PELIGROSO
    // };

    // Protocolo que no valida deadline razonable
    contract VulnerableExchange {
        function fillOrder(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            // No valida que permit.deadline sea razonable
            // Solo Permit2 verifica deadline >= block.timestamp
            permit2.permitTransferFrom(permit, details, msg.sender, signature);
            _executeSwap(details);
        }
    }

    // CORRECTO: validar deadline en el integrador
    contract SafeExchange {
        uint256 constant MAX_DEADLINE_OFFSET = 7 days;

        function fillOrder(
            ISignatureTransfer.PermitTransferFrom calldata permit,
            ISignatureTransfer.SignatureTransferDetails calldata details,
            bytes calldata signature
        ) external {
            require(permit.deadline <= block.timestamp + MAX_DEADLINE_OFFSET, "deadline too far");
            permit2.permitTransferFrom(permit, details, msg.sender, signature);
            _executeSwap(details);
        }
    }
  test_invariante: |
    function test_far_future_deadline_rejected() public {
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({token: address(token), amount: 1000e18}),
            nonce: 0,
            deadline: type(uint256).max  // Infinito
        });

        bytes memory sig = _signPermit(permit, details, signerKey);

        // El protocolo seguro debe rechazar deadlines excesivos
        vm.expectRevert("deadline too far");
        safeExchange.fillOrder(permit, details, sig);

        // El protocolo vulnerable lo acepta
        vulnExchange.fillOrder(permit, details, sig); // No revierte
    }
  ejemplo_real:
    - "UniswapX: usa deadlines de 5-60 minutos para órdenes, mitigando este riesgo"
    - "Across Protocol: deadline del depósito limita la ventana de ejecución del relayer"
    - "Sherlock/Cantina: findings donde SDKs configuran deadline = MaxUint256 por defecto, creando firmas zombi"
    - "Real phishing: atacantes almacenan firmas obtenidas y esperan al momento óptimo para ejecutar (cuando la víctima tiene más tokens)"
    - "1inch Limit Order Protocol: permite deadlines largos pero implementa cancelación on-chain para mitigar"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "UniswapX design, protocol audit findings"
  tags: [permit2, deadline, stale-signature, delayed-execution, SDK, infinite-deadline]
  relacionado_con: [PERM-02, PERM-12]
```

---

## Quick Reference: Checklist de Auditoría Permit2

```
INTEGRACIÓN PERMIT2 -- CHECKLIST RÁPIDO
════════════════════════════════════════
[ ] 1. ¿El protocolo usa try/catch para permit calls? (PERM-07)
[ ] 2. ¿Maneja tokens sin permit (USDT, BNB)? (PERM-14)
[ ] 3. ¿Maneja DAI-style permit? (PERM-09)
[ ] 4. ¿El witness type hash es único y no colisiona? (PERM-05)
[ ] 5. ¿Los batch details se validan contra lo firmado? (PERM-06)
[ ] 6. ¿Se verifica balance real recibido (fee-on-transfer)? (PERM-16)
[ ] 7. ¿Tiene ReentrancyGuard en funciones con Permit2? (PERM-15)
[ ] 8. ¿Los deadlines están acotados? (PERM-02, PERM-17)
[ ] 9. ¿Las allowances son finitas y con expiración? (PERM-03, PERM-13)
[ ] 10. ¿Se invalidan nonces de firmas canceladas? (PERM-04, PERM-12)
[ ] 11. ¿El chainId está en el witness/context? (PERM-01)
[ ] 12. ¿El frontend previene phishing de firmas? (PERM-10)
[ ] 13. ¿El lockdown cubre TODOS los token/spender pairs? (PERM-11)
[ ] 14. ¿El 'to' address en SignatureTransferDetails está controlado por contrato seguro? (PERM-06)
[ ] 15. ¿Se previene double-spend con permit + allowance residual? (PERM-08)
```

---

## Invariantes Globales para Fuzzing

```solidity
// PERM-GLOBAL-01: Solvencia -- balance del protocolo >= sum(deposits) siempre
function invariant_permit2_solvency() external view {
    uint256 totalDeposits = _sumAllDeposits();
    uint256 actualBalance = token.balanceOf(address(vault));
    assert(actualBalance >= totalDeposits);
}

// PERM-GLOBAL-02: Nonce monotonicity -- un nonce usado nunca vuelve a ser válido
function invariant_nonce_consumed_permanently(address user, uint256 nonce) external view {
    uint256 wordPos = nonce >> 8;
    uint256 bitPos = nonce & 0xff;
    uint256 bitmap = permit2.nonceBitmap(user, wordPos);
    bool isUsed = (bitmap & (1 << bitPos)) != 0;
    // Una vez usado, siempre usado
    if (wasUsedBefore[user][nonce]) {
        assert(isUsed);
    }
}

// PERM-GLOBAL-03: Allowance bounded -- transferencias <= allowance + firma
function invariant_transfer_bounded(address user, address token, address spender) external view {
    (uint160 amount,,) = permit2.allowance(user, token, spender);
    // El spender no puede transferir más de lo autorizado
    // (excepto con firmas adicionales via SignatureTransfer)
}

// PERM-GLOBAL-04: Expiration respected -- allowances expiradas no funcionan
function invariant_expiration_enforced(address user, address token, address spender) external {
    (, uint48 expiration,) = permit2.allowance(user, token, spender);
    if (block.timestamp > expiration) {
        vm.prank(spender);
        vm.expectRevert();
        permit2.transferFrom(user, spender, 1, token);
    }
}
```

---

## Herramientas de Defensa y Detección

| Herramienta | Uso | URL |
|---|---|---|
| Revoke.cash | Verificar y revocar aprobaciones activas (ERC-20 + Permit2) | https://revoke.cash |
| Etherscan Token Approval | Ver allowances on-chain | https://etherscan.io/tokenapprovalchecker |
| Forta Threat Detection | Alertas en tiempo real de phishing permit | https://forta.org |
| Pocket Universe | Simulación de transacciones pre-firma | https://pocketuniverse.app |
| Fire (wallet extension) | Decodifica mensajes EIP-712 antes de firmar | https://www.joinfire.xyz |
| Blowfish | API de simulación de transacciones | https://blowfish.xyz |

---

## Referencias Clave

1. **Uniswap Permit2 Source**: https://github.com/Uniswap/permit2
2. **ABDK Permit2 Audit**: https://github.com/Uniswap/permit2/blob/main/audits/ABDKConsulting_Uniswap_Permit2.pdf
3. **OpenZeppelin Permit2 Audit**: referenciado en repo oficial
4. **EIP-2612 (Permit Standard)**: https://eips.ethereum.org/EIPS/eip-2612
5. **EIP-712 (Typed Structured Data)**: https://eips.ethereum.org/EIPS/eip-712
6. **Uniswap Universal Router**: https://github.com/Uniswap/universal-router
7. **Drainer Kit Analysis (SlowMist)**: https://slowmist.medium.com/
8. **DAI Permit Implementation**: https://github.com/makerdao/dss/blob/master/src/dai.sol
9. **OpenZeppelin Permit Front-running Advisory**: https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20Permit
10. **Solodit Vulnerability Database**: https://solodit.cyfrin.io
