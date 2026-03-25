# Multisig Wallet & Smart Contract Wallet -- Combat Briefing

> **Scope**: Gnosis Safe / Safe{Wallet}, module-based wallet systems, multisig implementations, transaction guards, fallback handlers, social recovery modules, CREATE2 factory deployments, and EIP-1271 signature validation.
> **Sources**: Solodit -- 42 verified audit findings. Protocols: Hats Protocol/Safe (Sherlock 2023), reNFT (C4 2024-01), Brahma (C4 2023-09, Spearbit 2023), Biconomy (C4 2023-01), Ambire (C4 2023-10), Solv Vault Guardian (Quantstamp 2024), Alchemy Modular Account (Quantstamp 2024), Matter Labs Guardian Recovery (OpenZeppelin 2025), Clave (Cantina 2024).
> **Last updated**: 2026-03-22

---

## Conceptos clave antes de huntar

**Arquitectura Gnosis Safe / Safe{Wallet}**:
```
SafeProxy (ERC-1967 minimal proxy)
  └── GnosisSafe (singleton implementation)
        ├── OwnerManager   ← linked list de owners, threshold
        ├── ModuleManager  ← linked list de modules (execTransactionFromModule)
        ├── GuardManager   ← transaction guard (checkTransaction / checkAfterExecution)
        ├── FallbackManager ← fallback handler para calls no reconocidas
        ├── execTransaction() ← entry point principal, requiere N-of-M firmas
        └── execTransactionFromModule() ← bypass de firmas, solo modules habilitados
```

**Flujo de una transacción Safe**:
```
1. Owners firman off-chain (EIP-712 typed data)
2. Relayer/owner llama execTransaction(to, value, data, operation, ...)
3. Guard.checkTransaction() ← pre-check (si hay guard)
4. Safe verifica N firmas >= threshold
5. Safe ejecuta: CALL o DELEGATECALL al target
6. Guard.checkAfterExecution() ← post-check (si hay guard)
7. Nonce++ (SIEMPRE, incluso si la tx interna revierte con safeTxGas > 0)
```

**Trust boundaries criticos**:
- `modules` ejecutan sin firmas -- un module malicioso = game over
- `guard` solo aplica a `execTransaction`, NO a `execTransactionFromModule`
- `fallbackHandler` recibe delegatecall context -- puede leer/escribir storage del Safe
- `DELEGATECALL` desde el Safe ejecuta codigo externo en el contexto del Safe
- El Safe es un proxy -- la implementation (singleton) es compartida por TODOS los Safes
- `nonce` es secuencial estricto -- un gap bloquea todas las txs pendientes

---

## 1. Signature Replay Across Chains

```yaml
- id: msw-001
  pattern: cross-chain-signature-replay
  name: "Replay de transaccion Safe en otra chain con mismo address"
  causa_raiz: >
    Cuando un Safe se deploya con CREATE2 usando los mismos owners/threshold/salt
    en multiples chains (comun con Safe{Wallet}), las transacciones firmadas en
    una chain pueden ejecutarse en otra si el domainSeparator no incluye chainId,
    o si la firma usa un hash que no incorpora chainId correctamente. Gnosis Safe
    incluye chainId en el domainSeparator, pero lo cachea en el constructor --
    si la chain hace un fork (como ETH/ETC o post-merge), el valor cacheado es
    incorrecto.
  como_funciona: |
    1. Safe S deployado en Chain A y Chain B con mismos owners y misma address
    2. Owner firma tx T para Chain A (transferir 100 ETH a address X)
    3. Atacante observa la firma en el mempool o post-ejecucion
    4. Atacante submite la misma firma en Chain B
    5. Si domainSeparator no usa chainId o usa el valor cacheado pre-fork, la firma es valida
    6. Los 100 ETH de Chain B se transfieren a address X
  invariante: |
    // domainSeparator DEBE recalcularse si chainId cambia
    function invariant_domainSeparator_includes_chainId() external {
        bytes32 ds = safe.domainSeparator();
        // Verificar que incluye block.chainid actual
        bytes32 expected = keccak256(abi.encode(
            DOMAIN_SEPARATOR_TYPEHASH,
            block.chainid,
            address(safe)
        ));
        t(ds == expected, "DOMAIN_SEPARATOR must include current chainId");
    }
  que_mirar:
    - "domainSeparator() -- ¿es inmutable o se recalcula con block.chainid?"
    - "¿El constructor cachea chainId? Buscar: chainId = block.chainid en constructor"
    - "¿Hay un fallback que recalcula si chainId != cachedChainId?"
    - "Buscar: DOMAIN_SEPARATOR_TYPEHASH sin chainId en el encoding"
    - "grep -r 'domainSeparator\\|DOMAIN_SEPARATOR' --include='*.sol'"
  como_se_arregla: >
    Recalcular domainSeparator en cada llamada comparando block.chainid con el
    valor cacheado. Safe v1.3+ incluye esta proteccion, pero versiones anteriores
    no. Para forks de Safe, verificar que el patron de recalculo esta presente.
  trampas:
    - "Safe v1.3+ ya recalcula domainSeparator si chainId cambia -- verificar version"
    - "El replay cross-chain requiere mismo address en ambas chains -- comun con CREATE2 pero no universal"
    - "No confundir con nonce replay (el nonce es per-chain, no cross-chain)"
  solodit_ids:
    - m-03-cross-chain-signature-replay-attack-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - risk-of-replay-attacks-across-chains-spearbit-brink-pdf
    - m-01-join-signature-lacks-domain-separation-leading-to-cross-deploymentchain-replay-shieldify-none-soulsclub-revolver-markdown
    - protocol-vulnerable-to-cross-chain-signature-replay-cyfrin-none-cryptoart-markdown
  incidentes:
    - "Omni Bridge (2021) -- replay de mensajes cross-chain por falta de chainId, $2M en riesgo"
    - "Post-Merge ETH/ETC -- contratos con domainSeparator cacheado en constructor vulnerables a replay"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Biconomy C4, Brink Spearbit, SoulsClub Shieldify"
  tags: [replay, cross-chain, domainSeparator, chainId, CREATE2, signature]
  relacionado_con: [msw-008, msw-009]
```

## 2. Module Exploitation

```yaml
- id: msw-002
  pattern: malicious-module-drain
  name: "Module malicioso drena Safe via execTransactionFromModule"
  causa_raiz: >
    Los modules de un Safe pueden ejecutar transacciones SIN firmas de owners.
    execTransactionFromModule() solo verifica que msg.sender esta en la linked list
    de modules. Si un atacante logra que se habilite un module malicioso (via social
    engineering, phishing de firma, o explotando otro module), tiene control total
    del Safe sin necesidad de comprometer owners.
  como_funciona: |
    1. Atacante crea contrato MaliciousModule con funcion drain()
    2. Atacante convence a owners de firmar enableModule(MaliciousModule)
       (disfrazado como "upgrade de seguridad" o en un batch tx)
    3. MaliciousModule queda habilitado en el Safe
    4. MaliciousModule llama safe.execTransactionFromModule(attacker, balance, "", CALL)
    5. Todo el ETH/tokens del Safe se transfiere al atacante
    6. No se requiere ninguna firma adicional -- el module tiene permisos absolutos
  invariante: |
    // Solo modules conocidos y auditados deben estar habilitados
    function invariant_no_unknown_modules() external {
        address[] memory modules = safe.getModulesPaginated(SENTINEL, 20);
        for (uint i = 0; i < modules.length; i++) {
            t(knownModules[modules[i]], "Unknown module enabled on Safe");
        }
    }
  que_mirar:
    - "enableModule() -- ¿quien puede llamarlo? Solo el Safe via execTransaction"
    - "execTransactionFromModule() -- ¿tiene guard? En Safe standard, NO"
    - "¿Hay un timelock o delay para enableModule?"
    - "Buscar: modules que llaman enableModule dentro de su propia logica"
    - "grep -r 'enableModule\\|execTransactionFromModule' --include='*.sol'"
  como_se_arregla: >
    Implementar un ModuleGuard que filtre operaciones de modules. Usar timelock
    para enableModule (e.g., 48h delay). Verificar que ningun module existente
    puede llamar enableModule sin aprobacion de owners.
  trampas:
    - "enableModule solo es callable por el Safe mismo (via execTransaction con firmas) -- el bug real es que se firma sin revisar"
    - "Algunos protocols (Brahma, Zodiac) usan modules legitimamente -- no todos son maliciosos"
    - "Si otro module ya habilitado tiene un bug, puede usarse para habilitar un module malicioso sin firmas"
  solodit_ids:
    - h-4-if-another-module-adds-a-module-the-safe-will-be-bricked-sherlock-hats-hats-git
    - h-6-if-another-module-adds-a-module-the-safe-will-be-bricked-sherlock-hats-hats-git
    - console-can-brick-its-sub-accounts-in-some-scenarios-if-it-removes-itself-as-a-module-spearbit-none-brahma-pdf
    - bypass-solv-vault-guardian-checks-using-module-execution-quantstamp-solv-protocol-vault-guardian-markdown
    - changes-in-modules-not-detected-spearbit-none-brahma-pdf
  incidentes:
    - "Radiant Capital (Oct 2024) -- $50M robados. Atacantes comprometieron 3 de 11 signers del multisig via malware, luego ejecutaron transferOwnership para drenar pools."
    - "Ronin Bridge (Mar 2022) -- $625M. 5 de 9 validators comprometidos (4 internos + 1 Axie DAO). Atacante uso las claves para firmar withdrawals."
    - "Harmony Bridge (Jun 2022) -- $100M. Multisig 2-of-5 comprometido, atacante obtuvo 2 claves privadas."
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Hats Sherlock, Brahma Spearbit, Solv Quantstamp"
  tags: [module, enableModule, execTransactionFromModule, social-engineering, drain]
  relacionado_con: [msw-003, msw-012]
```

## 3. Guard Bypass via Module or Delegatecall

```yaml
- id: msw-003
  pattern: guard-bypass-module-delegatecall
  name: "Transaction guard evadido via execTransactionFromModule o reentrancy"
  causa_raiz: >
    El transaction guard de Safe (checkTransaction/checkAfterExecution) SOLO se
    ejecuta en execTransaction(). Las transacciones ejecutadas via
    execTransactionFromModule() NO pasan por el guard. Ademas, si el guard usa
    un nonce hash para vincular pre/post checks, un atacante puede abusar de
    reentrancy durante la ejecucion de la tx para ejecutar operaciones prohibidas
    entre checkTransaction y checkAfterExecution.
  como_funciona: |
    1. Safe tiene un Guard que prohibe transferencias > 10 ETH (checkTransaction)
    2. Atacante habilita un module (o usa uno existente)
    3. Module llama execTransactionFromModule(attacker, 100 ETH, "", CALL)
    4. El Guard NUNCA se invoca -- la transferencia de 100 ETH se ejecuta
    5. Alternativamente: durante execTransaction, el target hace callback al Safe
       que ejecuta una operacion prohibida entre checkTransaction y checkAfterExecution
  invariante: |
    // execTransactionFromModule DEBE respetar el mismo guard
    function invariant_module_tx_respects_guard() external {
        uint256 balBefore = address(safe).balance;
        // Simular module tx
        vm.prank(address(module));
        safe.execTransactionFromModule(attacker, 100 ether, "", Enum.Operation.Call);
        uint256 balAfter = address(safe).balance;
        // Si el guard prohibe > 10 ETH, esto deberia revertir
        t(balBefore - balAfter <= 10 ether, "Module bypassed guard limit");
    }
  que_mirar:
    - "¿El guard se aplica en execTransactionFromModule? En Safe standard, NO"
    - "¿El guard usa un txHash como nonce entre pre/post? ¿Se puede manipular?"
    - "¿Hay reentrancy durante execTransaction que permita llamar execTransactionFromModule?"
    - "Buscar: checkTransaction solo en execTransaction, no en execTransactionFromModule"
    - "grep -r 'checkTransaction\\|checkAfterExecution\\|Guard' --include='*.sol'"
  como_se_arregla: >
    Implementar un ModuleGuard separado (Safe v1.5+) o un wrapper de
    execTransactionFromModule que aplique el guard. Para reentrancy: el guard
    debe trackear un flag de ejecucion en curso y revertir si se llama
    checkTransaction durante otra checkTransaction.
  trampas:
    - "Safe v1.5 introduce ModuleGuard separado -- verificar si el protocolo lo usa"
    - "Algunos guards usan un hash-based nonce que se resetea, no un boolean -- mas susceptible a reentrancy"
    - "El guard puede ser un contrato actualizable -- la logica podria cambiar"
  solodit_ids:
    - m-17-attacker-can-perform-malicious-transactions-in-the-safe-because-reentrancy-is-not-implemented-correctly-in-the-checktransaction-and-checkafterexecution-function-in-hsg-sherlock-hats-hats-git
    - m-1-attacker-can-perform-malicious-transactions-in-the-safe-because-reentrancy-is-not-implemented-correctly-in-the-checktransaction-and-checkafterexecution-function-in-hsg-sherlock-hats-hats-git
    - h-3-signers-can-bypass-checks-to-add-new-modules-to-a-safe-by-abusing-reentrancy-sherlock-hats-hats-git
    - h-7-signers-can-bypass-checks-to-add-new-modules-to-a-safe-by-abusing-reentrancy-sherlock-hats-hats-git
    - bypass-solv-vault-guardian-checks-using-module-execution-quantstamp-solv-protocol-vault-guardian-markdown
  incidentes:
    - "reNFT (C4 2024-01) -- Guard validaba setFallbackHandler pero no lo bloqueaba via module, permitiendo hijack de NFTs rentados"
    - "Hats Protocol (Sherlock 2023) -- Reentrancy entre checkTransaction/checkAfterExecution permitia ejecutar transacciones prohibidas"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Hats Sherlock (multiple findings), Solv Quantstamp"
  tags: [guard, bypass, module, reentrancy, checkTransaction, checkAfterExecution]
  relacionado_con: [msw-002, msw-007]
```

## 4. Threshold Manipulation via Owner Swap Chain

```yaml
- id: msw-004
  pattern: threshold-manipulation-owner-swap
  name: "Reduccion de threshold a 1 via cadena de swapOwner/removeOwner"
  causa_raiz: >
    El Safe permite cambiar threshold con changeThreshold(), addOwner(),
    removeOwner(), y swapOwner(). Si un atacante controla una minoria de owners
    y puede ejecutar multiples transacciones en secuencia (o en un batch via
    MultiSend), puede encadenar operaciones para: swap owners legitimos por
    owners controlados, y luego reducir threshold a 1. Una vez threshold=1,
    una sola firma basta para drenar el Safe.
  como_funciona: |
    1. Safe tiene 5 owners con threshold 3 (3-of-5)
    2. Atacante controla 3 owners (mayoria, via phishing/malware)
    3. Atacante firma batch MultiSend:
       a) swapOwner(owner4 -> attackerAddr1)
       b) swapOwner(owner5 -> attackerAddr2)
       c) changeThreshold(1)
    4. Ahora el Safe es 1-of-5, todos controlados por atacante
    5. Atacante drena el Safe con una sola firma
  invariante: |
    // Threshold nunca debe bajar en una sola transaccion
    function invariant_threshold_monotonic_per_tx() external {
        uint256 thresholdBefore = safe.getThreshold();
        // ... execute transaction ...
        uint256 thresholdAfter = safe.getThreshold();
        // Threshold puede subir (mas seguro) pero no bajar abruptamente
        t(thresholdAfter >= thresholdBefore - 1,
          "Threshold dropped more than 1 in single tx");
    }
  que_mirar:
    - "¿changeThreshold puede llamarse en un batch con swapOwner?"
    - "¿Hay un timelock para cambios de threshold?"
    - "¿Hay un minimum threshold forzado?"
    - "Buscar: MultiSend con changeThreshold en la data"
    - "grep -r 'changeThreshold\\|swapOwner\\|removeOwner' --include='*.sol'"
  como_se_arregla: >
    Implementar un timelock para changeThreshold() (e.g., 48h). Establecer un
    threshold minimo que no pueda reducirse por debajo de cierto valor (e.g.,
    max(2, owners.length/2)). Separar cambios de owners de cambios de threshold
    en transacciones distintas.
  trampas:
    - "Si el atacante ya controla la mayoria, esto es 'by design' (mayoria puede hacer cualquier cosa)"
    - "El ataque real es el compromiso de owners, no la mecanica de changeThreshold"
    - "Protocols que wrappean el Safe (Hats, Brahma) pueden tener checks adicionales"
  solodit_ids:
    - h-9-signers-can-bypass-checks-and-change-threshold-within-a-transaction-sherlock-hats-hats-git
    - h-1-signers-can-bypass-checks-and-change-threshold-within-a-transaction-sherlock-hats-hats-git
    - h-2-safe-can-be-bricked-because-threshold-is-updated-with-validsignercount-instead-of-newthreshold-sherlock-hats-hats-git
    - m-9-safe-threshold-can-be-set-above-target-threshold-causing-transactions-to-revert-sherlock-hats-hats-git
    - m-11-mediumoutdated-state-_removesigner-incorrectly-updates-signercount-and-safe-threshold-sherlock-hats-hats-git
  incidentes:
    - "Radiant Capital (Oct 2024) -- Atacantes comprometieron 3 de 11 signers, suficiente para ejecutar transacciones con threshold 3"
    - "Harmony Bridge (Jun 2022) -- 2-of-5 multisig, atacante solo necesito 2 claves para drenar $100M"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Hats Sherlock (multiple threshold findings)"
  tags: [threshold, swapOwner, changeThreshold, MultiSend, batch, owner-compromise]
  relacionado_con: [msw-002, msw-010]
```

## 5. Nonce Gap Griefing

```yaml
- id: msw-005
  pattern: nonce-gap-griefing-dos
  name: "Bloqueo de transacciones pendientes via nonce gap"
  causa_raiz: >
    El Safe usa un nonce secuencial estricto -- la siguiente transaccion DEBE usar
    nonce = currentNonce. Si un atacante (que puede ser un owner minoritario) logra
    ejecutar una transaccion con el nonce actual antes que las transacciones
    pendientes legitimamente firmadas, TODAS las firmas pendientes se invalidan
    porque el nonce ya fue consumido. Esto es un DoS permanente contra transacciones
    ya firmadas.
  como_funciona: |
    1. Owners firman tx A con nonce=5 (transferir 100 ETH a proveedor)
    2. Antes de que A se ejecute, un owner malicioso (1 de N) crea y ejecuta tx B con nonce=5
       (tx B puede ser una operacion trivial, como una llamada vacia)
    3. Tx B se ejecuta, nonce incrementa a 6
    4. Tx A ahora tiene nonce=5, que es invalido -- la tx es irrecuperable
    5. Los owners deben re-firmar todo con nonce=6
    6. El atacante puede repetir indefinidamente (DoS permanente)
  invariante: |
    // Todas las transacciones pendientes con nonce actual deben poder ejecutarse
    function invariant_pending_tx_executable() external {
        uint256 currentNonce = safe.nonce();
        // Si hay txs pendientes firmadas, al menos una debe ser ejecutable
        // (no se puede verificar on-chain directamente, pero se puede trackear)
        t(currentNonce == expectedNonce, "Nonce advanced unexpectedly");
    }
  que_mirar:
    - "¿El nonce es estrictamente secuencial? En Safe standard, SI"
    - "¿Hay mecanismo de nonce por grupo (como ERC-4337 nonce keys)?"
    - "¿Un owner minoritario puede ejecutar una tx solo? Necesita threshold firmas"
    - "En un 1-of-N, cualquier owner puede griefear"
    - "grep -r 'nonce\\|nonce()' --include='*.sol'"
  como_se_arregla: >
    Usar nonce por canal/grupo (como ERC-4337 con key|seq split) para permitir
    transacciones paralelas. Alternativamente, implementar un queue on-chain donde
    las txs firmadas se registran y no pueden ser invalidadas por otras txs.
  trampas:
    - "En un N-of-N o alto threshold, un solo owner no puede ejecutar nada -- el griefing requiere mayoria"
    - "El front-running del nonce requiere gas y acceso al mempool"
    - "Safe{Wallet} UI mitiga parcialmente mostrando el nonce actual"
  solodit_ids:
    - m-08-transaction-can-fail-due-to-batchid-collision-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - 03-nonce-consumption-reverts-on-execution-failure-enabling-signature-replay-attacks-code4rena-sequence-sequence-git
    - m-9-anyone-can-cancel-other-accounts-nonces-and-groups-leading-to-griefing-their-intents-sherlock-perennial-v2-update-3-git
  incidentes:
    - "GovernorBravo-based DAOs (multiple 2022-2023) -- proposals bloqueados por nonce griefing en multisig de ejecucion"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: Biconomy C4, Sequence C4, Perennial Sherlock"
  tags: [nonce, griefing, DoS, pending-tx, front-running, sequential-nonce]
  relacionado_con: [msw-001, msw-013]
```

## 6. Delegatecall to Selfdestruct

```yaml
- id: msw-006
  pattern: delegatecall-selfdestruct-proxy
  name: "Destruccion de Safe proxy via delegatecall a contrato con selfdestruct"
  causa_raiz: >
    El Safe permite ejecutar transacciones con operation=DELEGATECALL, que ejecuta
    codigo externo en el contexto del Safe proxy. Si el codigo ejecutado contiene
    selfdestruct (o SELFDESTRUCT opcode), el proxy se destruye permanentemente,
    congelando todos los fondos. Historicamente, esto fue el vector del hack de
    Parity Multisig ($150M congelados). Post-Dencun (EIP-6780), selfdestruct
    solo destruye si se crea y destruye en la misma transaccion, pero el riesgo
    persiste en chains que no implementaron EIP-6780.
  como_funciona: |
    1. Atacante deploya contrato SelfDestructor con function destroy() { selfdestruct(attacker); }
    2. Atacante convence a owners de firmar delegatecall al SelfDestructor
       (disfrazado como "upgrade" o "migration helper")
    3. Safe ejecuta delegatecall a SelfDestructor.destroy()
    4. selfdestruct se ejecuta en el contexto del Safe proxy
    5. El proxy se destruye -- todos los fondos (ETH, tokens, NFTs) quedan inaccesibles
    6. No hay forma de recuperar los fondos (el address ya no tiene codigo)
  invariante: |
    // DELEGATECALL targets deben estar en whitelist
    function invariant_delegatecall_whitelist() external {
        // Track all delegatecall targets
        // Solo contratos auditados y conocidos deben ser targets de delegatecall
        t(whitelistedDelegatecallTargets[lastDelegatecallTarget],
          "Delegatecall to non-whitelisted target");
    }
  que_mirar:
    - "¿El Safe permite DELEGATECALL? Si, via execTransaction con operation=1"
    - "¿Hay whitelist de targets para delegatecall?"
    - "¿El guard bloquea delegatecall a contratos no verificados?"
    - "Buscar: selfdestruct en contratos que podrian ser targets de delegatecall"
    - "grep -r 'delegatecall\\|Operation.DelegateCall\\|operation == 1' --include='*.sol'"
    - "grep -r 'selfdestruct\\|SELFDESTRUCT' --include='*.sol'"
  como_se_arregla: >
    Implementar una whitelist de targets permitidos para delegatecall en el guard.
    Prohibir delegatecall a contratos que contengan SELFDESTRUCT opcode. Post-Dencun
    (EIP-6780), selfdestruct es menos peligroso pero aun puede causar problemas
    en L2s que no hayan adoptado el EIP.
  trampas:
    - "EIP-6780 (Dencun) cambia la semantica de selfdestruct -- solo destruye en misma tx de CREATE"
    - "Muchas L2 (Arbitrum, Optimism pre-Ecotone) no implementaron EIP-6780 inmediatamente"
    - "La implementacion de Safe (singleton) es un riesgo -- si alguien la destruye, TODOS los Safes que la usan se rompen (Parity bug)"
  solodit_ids:
    - selfdestruct-risks-in-delegatecall-spearbit-brink-pdf
    - h-01-destruction-of-the-smartaccount-implementation-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - h-01-vaultproxy-implementation-can-be-initialized-by-anyone-and-self-destructed-code4rena-stader-labs-stader-labs-git
    - h-1-vaults-can-be-bricked-by-selfdestructing-implementations-using-forged-immutable-args-sherlock-rio-vesting-escrow-git
  incidentes:
    - "Parity Multisig Library Freeze (Nov 2017) -- $150M ETH congelados permanentemente. Un usuario llamo initWallet() en la libreria singleton (WalletLibrary) y luego selfdestruct. TODOS los multisigs Parity que usaban esa libreria quedaron bricked."
    - "Parity Multisig Hack (Jul 2017) -- $30M ETH robados. initWallet() no tenia proteccion contra re-inicializacion, permitiendo a atacante tomar ownership de cualquier multisig Parity."
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit: Brink Spearbit, Biconomy C4, Stader C4"
  tags: [delegatecall, selfdestruct, proxy, singleton, Parity, brick, EIP-6780]
  relacionado_con: [msw-003, msw-008]
```

## 7. Fallback Handler Hijack

```yaml
- id: msw-007
  pattern: fallback-handler-hijack
  name: "Cambio de fallbackHandler a contrato malicioso para interceptar llamadas"
  causa_raiz: >
    El Safe delega llamadas no reconocidas a un fallbackHandler via delegatecall
    (en Safe v1.1-1.2) o via call con msg.sender prepended (v1.3+). Si un atacante
    logra cambiar el fallbackHandler a un contrato malicioso, puede interceptar
    llamadas ERC-721/ERC-1155 tokenReceived, EIP-1271 isValidSignature, y
    cualquier otra llamada al Safe que no matchee una funcion conocida.
    En versiones con delegatecall, el handler malicioso puede leer/escribir
    storage del Safe directamente.
  como_funciona: |
    1. Safe tiene fallbackHandler = CompatibilityFallbackHandler (legitimo)
    2. Atacante logra que se ejecute setFallbackHandler(maliciousHandler)
       (via batch tx, module, o guard bypass)
    3. MaliciousHandler implementa onERC721Received() que aprueba tokens al atacante
    4. Cuando alguien envia un NFT al Safe, se llama onERC721Received()
    5. MaliciousHandler ejecuta approve(attacker, tokenId) en el contexto del Safe
    6. Atacante roba el NFT
  invariante: |
    function invariant_fallback_handler_unchanged() external {
        // Leer fallback handler del storage slot
        bytes32 slot = 0x6c9a6c4a39284e37ed1cf53d1e01a4af0e08cd84a2cc24db0e318b8aef;
        address handler = address(uint160(uint256(vm.load(address(safe), slot))));
        t(handler == expectedFallbackHandler,
          "Fallback handler changed to unknown contract");
    }
  que_mirar:
    - "¿setFallbackHandler es callable por modules?"
    - "¿El guard bloquea cambios al fallbackHandler?"
    - "¿El fallbackHandler usa delegatecall o call? (delegatecall = mas peligroso)"
    - "¿El handler actual tiene funciones que modifican estado?"
    - "grep -r 'setFallbackHandler\\|fallbackHandler\\|internalSetFallbackHandler' --include='*.sol'"
  como_se_arregla: >
    El guard debe bloquear llamadas a setFallbackHandler() excepto con timelock.
    Usar una whitelist de handlers permitidos. En Safe v1.3+, el fallback usa
    call (no delegatecall) lo que limita el dano, pero un handler malicioso
    aun puede retornar datos falsos (e.g., isValidSignature siempre true).
  trampas:
    - "Safe v1.3+ cambio de delegatecall a call para el fallbackHandler -- verificar version"
    - "El setFallbackHandler solo es callable por el Safe (via execTransaction) -- requiere firmas"
    - "Pero un module puede cambiar el handler via execTransactionFromModule si tiene permisos"
  solodit_ids:
    - h-02-an-attacker-is-able-to-hijack-any-erc721-erc1155-he-borrows-because-guard-is-missing-validation-on-the-address-supplied-to-function-call-setfallbackhandler-code4rena-renft-renft-git
    - fallback-handler-can-call-into-sensitive-functions-of-fallback-handler-itself-spearbit-none-biconomy-nexus-pdf
    - fallback-can-be-used-for-direct-unauthorised-calls-to-fallback-handlers-spearbit-none-biconomy-nexus-pdf
    - m-01-fallback-handlers-can-trick-users-into-calling-functions-of-the-ambireaccount-contract-code4rena-ambire-ambire-git
    - fallback-handlers-can-be-installed-with-invalid-calltype-codehawks-biconomy-nexus-git
  incidentes:
    - "reNFT (C4 2024-01) -- H-02: Guard no validaba address en setFallbackHandler, permitiendo hijack de NFTs ERC-721/ERC-1155 rentados"
    - "Biconomy Nexus (Spearbit 2024) -- Fallback handler podia llamar funciones sensibles de si mismo via delegatecall"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: reNFT C4, Biconomy Nexus Spearbit, Ambire C4"
  tags: [fallbackHandler, hijack, delegatecall, ERC721, ERC1155, isValidSignature]
  relacionado_con: [msw-003, msw-009]
```

## 8. CREATE2 Address Prediction Front-Running

```yaml
- id: msw-008
  pattern: create2-frontrun-safe-deployment
  name: "Front-running de deployment CREATE2 para controlar Safe antes que el usuario"
  causa_raiz: >
    Safe usa SafeProxyFactory con CREATE2 para deployar Safes en addresses
    predecibles. El address depende de: bytecode del proxy + salt (derivado de
    owners, threshold, initializer). Si un atacante puede predecir el address
    antes del deployment, puede deployar el Safe primero con sus propios owners
    y recibir fondos enviados a esa address antes de que el usuario real lo deploye.
    Tambien: si el initializer incluye un callback, el atacante puede front-run
    el createProxyWithNonce para deployar con parametros distintos al mismo address.
  como_funciona: |
    1. Usuario calcula su futuro Safe address con owners=[A,B,C], threshold=2
    2. Usuario comparte el address (para recibir fondos antes de deployar)
    3. Atacante ve la tx pendiente de createProxyWithNonce en el mempool
    4. Atacante front-runs con createProxyWithNonce usando mismo salt pero
       owners=[attacker], threshold=1 (si el salt no incluye los parametros)
    5. El Safe se deploya en el mismo address pero controlado por el atacante
    6. Fondos enviados al address van al Safe del atacante
  invariante: |
    function invariant_create2_deterministic() external {
        // El address calculado DEBE corresponder a los parametros reales
        address predicted = factory.calculateCreateProxyWithNonceAddress(
            singleton, initializer, saltNonce
        );
        // Verificar que el Safe en esa address tiene los owners esperados
        IGnosisSafe deployed = IGnosisSafe(predicted);
        t(deployed.isOwner(expectedOwner1), "Deployed Safe has wrong owners");
        t(deployed.getThreshold() == expectedThreshold, "Wrong threshold");
    }
  que_mirar:
    - "¿El salt incluye msg.sender? Si no, cualquiera puede crear el Safe con el mismo salt"
    - "¿El initializer (setup()) esta incluido en el hash de CREATE2?"
    - "¿Hay proteccion contra front-running del deployment?"
    - "Buscar: createProxyWithNonce sin msg.sender en el salt"
    - "grep -r 'createProxyWithNonce\\|CREATE2\\|create2' --include='*.sol'"
  como_se_arregla: >
    Incluir msg.sender en el salt de CREATE2 para que solo el deployer original
    pueda crear el proxy en esa address. Safe v1.3+ incluye msg.sender en el
    salt de createProxyWithNonce. Tambien: no enviar fondos a un address hasta
    que el Safe este efectivamente deployado y verificado.
  trampas:
    - "Safe v1.3+ incluye msg.sender en salt -- front-running no funciona directamente"
    - "Si el usuario deposita fondos pre-deployment, el riesgo es real"
    - "CREATE2 address collision es extremadamente dificil (2^160 brute force)"
  solodit_ids:
    - h-03-attacker-can-gain-control-of-counterfactual-wallet-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - m-03-create2-address-collision-during-pool-deployment-allows-for-complete-draining-of-the-pool-code4rena-panoptic-panoptic-git
    - m-2-create2-address-collision-against-an-account-will-allow-complete-draining-of-lending-pools-sherlock-arcadia-git
    - anyone-can-deploy-a-console-with-the-same-set-of-parameters-but-with-a-different-_policycommit-spearbit-none-brahma-pdf
  incidentes:
    - "Wintermute (Sep 2022) -- $160M robados. No fue front-running de CREATE2, sino vanity address generado con Profanity (weak RNG). El address de un hot wallet fue comprometido porque la clave privada era derivable del vanity prefix."
    - "Biconomy (C4 2023-01) -- H-03: Atacante podia ganar control de counterfactual wallet deployando con parametros maliciosos antes que el usuario."
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Biconomy C4, Panoptic C4, Arcadia Sherlock, Brahma Spearbit"
  tags: [CREATE2, front-running, counterfactual, salt, SafeProxyFactory, deployment]
  relacionado_con: [msw-001, msw-015]
```

## 9. EIP-1271 Signature Validation Bypass

```yaml
- id: msw-009
  pattern: eip1271-isvalidsignature-bypass
  name: "Bypass de isValidSignature (EIP-1271) permite firmas falsas"
  causa_raiz: >
    EIP-1271 permite a contratos (como Safes) validar firmas via isValidSignature(hash, signature).
    Implementaciones incorrectas pueden: retornar magic value para cualquier input,
    no verificar que las firmas cumplan el threshold, usar ecrecover sin verificar
    address(0), o permitir que el fallbackHandler (que implementa isValidSignature)
    sea reemplazado por un contrato que siempre retorna true. Esto permite a
    atacantes forjar firmas validas para el Safe en protocolos que confian en EIP-1271.
  como_funciona: |
    1. Protocolo DeFi verifica firma del Safe via isValidSignature(hash, sig)
    2. Safe delega al fallbackHandler (CompatibilityFallbackHandler)
    3. Handler verifica las firmas contra owners y threshold
    4. BUG: Si el handler no verifica correctamente (e.g., address(0) como owner,
       threshold check off-by-one, o handler reemplazado), retorna magic value
    5. Atacante crea una firma invalida que pasa la verificacion
    6. Protocolo DeFi acepta la firma y ejecuta la operacion (swap, borrow, etc.)
  invariante: |
    function invariant_eip1271_rejects_invalid_sigs() external {
        bytes32 hash = keccak256("test");
        bytes memory invalidSig = abi.encodePacked(uint8(0), bytes32(0), bytes32(0));
        bytes4 result = safe.isValidSignature(hash, invalidSig);
        t(result != bytes4(0x1626ba7e),
          "isValidSignature accepted invalid signature");
    }
  que_mirar:
    - "¿isValidSignature verifica todas las firmas contra owners reales?"
    - "¿Maneja el caso de ecrecover retornando address(0)?"
    - "¿El threshold check es correcto (>= vs >)?"
    - "¿address(0) puede ser owner? Si si, firmas invalidas pasan"
    - "grep -r 'isValidSignature\\|0x1626ba7e\\|EIP1271' --include='*.sol'"
  como_se_arregla: >
    isValidSignature debe: (1) verificar que el numero de firmas validas >= threshold,
    (2) verificar que ecrecover no retorna address(0), (3) verificar que cada
    signer es un owner activo, (4) retornar bytes4(0) para CUALQUIER input invalido.
    Usar la implementacion de Safe como referencia (checkNSignatures).
  trampas:
    - "Safe v1.3+ tiene una implementacion solida de isValidSignature -- el bug suele estar en forks o wrappers"
    - "Si address(0) NO puede ser owner (Safe lo prohibe), el ecrecover-to-0 no es explotable"
    - "Algunos protocolos pasan el messageHash sin re-hashing con domainSeparator"
  solodit_ids:
    - eip-1271-non-compliance-and-denial-of-service-risk-for-account-abstraction-wallets-in-council-safe-cantina-none-op-labs-pdf
    - m-06-doesnt-follow-erc1271-standard-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - m-7-if-a-hat-is-owned-by-address0-phony-signatures-will-be-accepted-by-the-safe-sherlock-hats-hats-git
    - h-7-hatssignergatebase-valid-signer-threshold-can-be-bypassed-because-hsg-checks-signatures-differently-from-safe-which-allows-exploitation-sherlock-hats-hats-git
    - potential-signature-replay-attack-in-erc1271handler-openzeppelin-none-sso-account-oidc-recovery-solidity-audit-markdown
    - l-18-contract-wallets-incompatible-with-eip-1271-signature-verification-pashov-audit-group-none-hyperhyper_2025-03-30-markdown
  incidentes:
    - "Hats Protocol (Sherlock 2023) -- M-07: Si un hat era owned by address(0), firmas phony eran aceptadas por el Safe. H-07: HatsSignerGate verificaba firmas de forma diferente a Safe, permitiendo bypass del threshold."
    - "OP Labs (Cantina 2024) -- EIP-1271 non-compliance causaba DoS para AA wallets en Council Safe"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Hats Sherlock, Biconomy C4, OP Labs Cantina, OZ Matter Labs"
  tags: [EIP-1271, isValidSignature, ecrecover, address-zero, threshold, forgery]
  relacionado_con: [msw-001, msw-007]
```

## 10. Owner Enumeration Timing

```yaml
- id: msw-010
  pattern: owner-enumeration-timing-attack
  name: "Lectura de owners durante cambio de ownership produce estado inconsistente"
  causa_raiz: >
    El Safe almacena owners en una linked list (sentinel -> owner1 -> owner2 -> ... -> sentinel).
    Durante una transaccion que modifica la lista de owners (addOwner, removeOwner,
    swapOwner), si hay un callback externo (e.g., via guard o target de la tx),
    la lectura de getOwners() o isOwner() puede retornar un estado parcialmente
    actualizado. Esto es especialmente peligroso en guards que verifican la lista
    de owners en checkAfterExecution -- si un owner fue removido pero el guard
    lee la lista antes de la actualizacion completa, el check pasa incorrectamente.
  como_funciona: |
    1. Safe tiene owners [A, B, C] con threshold 2
    2. Se ejecuta removeOwner(B) con threshold=2
    3. Guard.checkAfterExecution() lee getOwners()
    4. Si el guard cacheo la lista en checkTransaction() y compara en checkAfterExecution(),
       puede haber discrepancia si la linked list esta parcialmente actualizada
    5. El guard acepta un estado donde threshold > ownerCount (brickea el Safe)
       o donde un owner invalido aun aparece como valido
  invariante: |
    function invariant_threshold_le_ownercount() external {
        uint256 threshold = safe.getThreshold();
        address[] memory owners = safe.getOwners();
        t(threshold <= owners.length, "Threshold exceeds owner count");
        t(threshold >= 1, "Threshold is zero");
    }
  que_mirar:
    - "¿El guard lee getOwners() en checkTransaction Y checkAfterExecution?"
    - "¿Hay reentrancy entre los checks del guard?"
    - "¿La linked list puede estar en estado intermedio durante un callback?"
    - "Buscar: getOwners() en funciones que se llaman durante execTransaction"
    - "grep -r 'getOwners\\|isOwner\\|ownerCount' --include='*.sol'"
  como_se_arregla: >
    El guard debe usar un snapshot de owners en checkTransaction y comparar
    contra el estado final en checkAfterExecution. No confiar en lecturas
    intermedias. Tambien: Safe de forma nativa verifica que threshold <= ownerCount
    despues de removeOwner.
  trampas:
    - "Safe internamente garantiza threshold <= ownerCount en removeOwner -- el bug esta en guards/wrappers"
    - "La linked list de Safe es atomica dentro de cada operacion -- no hay estado intermedio DENTRO de addOwner"
    - "El problema real es reentrancy: callback durante la tx permite leer estado parcial"
  solodit_ids:
    - m-11-mediumoutdated-state-_removesigner-incorrectly-updates-signercount-and-safe-threshold-sherlock-hats-hats-git
    - m-7-mediumoutdated-state-_removesigner-incorrectly-updates-signercount-and-safe-threshold-sherlock-hats-hats-git
    - m-16-owners-can-be-swapped-even-though-they-still-wear-their-signer-hats-sherlock-hats-hats-git
    - m-6-swap-signer-fails-if-final-owner-is-invalid-due-to-off-by-one-error-in-loop-sherlock-hats-hats-git
    - h-5-other-module-can-add-owners-to-safe-that-push-us-above-maxsigners-bricking-safe-sherlock-hats-hats-git
  incidentes:
    - "Hats Protocol (Sherlock 2023) -- Multiple findings: _removeSigner incorrectamente actualizaba signerCount y threshold, causando estados inconsistentes donde el Safe quedaba bricked."
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: Hats Protocol Sherlock (multiple audit rounds)"
  tags: [owner, linked-list, enumeration, timing, reentrancy, threshold, brick]
  relacionado_con: [msw-004, msw-003]
```

## 11. MultiSend Batch Atomicity Issues

```yaml
- id: msw-011
  pattern: multisend-partial-execution
  name: "Ejecucion parcial de batch MultiSend causa estado inconsistente"
  causa_raiz: >
    MultiSend permite ejecutar multiples operaciones atomicamente en una sola
    transaccion Safe. Sin embargo, si una operacion interna usa call (no
    delegatecall) y revierte, el comportamiento depende de la implementacion:
    MultiSend original revierte todo el batch si cualquier sub-tx revierte,
    pero algunas implementaciones o wrappers permiten ejecucion parcial (catch
    errors). Esto causa estados inconsistentes donde la primera mitad de un
    batch se ejecuto pero la segunda no.
  como_funciona: |
    1. Owner firma batch MultiSend:
       a) Approve USDC al contrato X (100K USDC)
       b) Llamar X.deposit(100K USDC) que transferia los tokens
    2. Si X.deposit() revierte pero approve() ya se ejecuto:
       a) En MultiSend standard: todo revierte (seguro)
       b) En MultiSend con try/catch o implementacion custom: approve se ejecuta, deposit no
    3. Los 100K USDC quedan aprobados a X sin que el deposit se haya realizado
    4. Atacante (o cualquiera con acceso a X) puede llamar transferFrom y robar los tokens
  invariante: |
    function invariant_multisend_atomic() external {
        // Si una sub-tx revierte, TODAS deben revertir
        uint256 balBefore = token.balanceOf(address(safe));
        try safe.execTransaction(
            multiSend, 0, multiSendData, Enum.Operation.DelegateCall,
            safeTxGas, 0, 0, address(0), payable(0), signatures
        ) {
            // Si llega aqui, todas las sub-txs se ejecutaron
        } catch {
            // Si revierte, ninguna sub-tx se ejecuto
            uint256 balAfter = token.balanceOf(address(safe));
            t(balAfter == balBefore, "Partial execution detected");
        }
    }
  que_mirar:
    - "¿MultiSend revierte si alguna sub-tx falla? ¿O usa try/catch?"
    - "¿Hay implementaciones custom de MultiSend que permitan ejecucion parcial?"
    - "¿El batch incluye approve + action? Patron peligroso si no es atomico"
    - "Buscar: MultiSend con try/catch o success check que continua"
    - "grep -r 'multiSend\\|MultiSend\\|multisend' --include='*.sol'"
  como_se_arregla: >
    Usar siempre MultiSend que revierte todo el batch si cualquier sub-tx falla
    (implementacion standard de Safe). No usar MultiSendCallOnly para operaciones
    que modifiquen estado critico. Verificar que approve + action siempre estan
    en el mismo batch atomico.
  trampas:
    - "MultiSend standard de Safe es atomico por defecto -- el bug esta en forks/wrappers"
    - "MultiSendCallOnly prohibe delegatecall, no permite ejecucion parcial"
    - "Si safeTxGas > 0, la tx interna puede revertir pero la tx de Safe NO revierte (nonce avanza)"
  solodit_ids:
    - m-01-griefing-attacks-on-handleops-and-multisend-logic-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git
    - multicall-when-inherited-to-erc4626routerbase-does-not-bubble-up-the-reverts-correctly-spearbit-none-astaria-pdf
    - full-batched-repayments-done-with-evc-s-batch-call-may-fail-when-max-supply-is-exceeded-cantina-none-euler-pdf
  incidentes:
    - "Biconomy (C4 2023-01) -- Griefing en MultiSend logic causaba DoS en handleOps"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: Biconomy C4, Astaria Spearbit, Euler Cantina"
  tags: [MultiSend, batch, atomicity, partial-execution, approve, state-inconsistency]
  relacionado_con: [msw-005, msw-014]
```

## 12. Recovery Module Social Engineering

```yaml
- id: msw-012
  pattern: recovery-module-takeover
  name: "Modulo de recovery social permite takeover del Safe"
  causa_raiz: >
    Los modulos de recovery social permiten que guardianes designados cambien los
    owners del Safe si el owner original pierde acceso. Si la logica de recovery
    tiene bugs (e.g., nonce no incrementado entre recoveries, falta de timelock,
    recovery data no limpiada en uninstall), un guardian malicioso o un atacante
    que comprometa guardianes puede tomar control del Safe sin conocimiento del
    owner real.
  como_funciona: |
    1. Safe tiene RecoveryModule con 3 guardianes (2-of-3 para recovery)
    2. Atacante compromete 2 guardianes (phishing, SIM swap, etc.)
    3. Atacante inicia recovery: propone nuevos owners controlados por atacante
    4. BUG 1: No hay timelock -- recovery se ejecuta inmediatamente
    5. BUG 2: pendingRecoveryData no se limpia en onUninstall -- si el modulo
       se reinstala, la recovery pendiente se ejecuta inmediatamente
    6. Atacante es ahora owner del Safe, drena fondos
  invariante: |
    function invariant_recovery_requires_delay() external {
        // Recovery DEBE tener un periodo de espera
        uint256 recoveryDelay = recoveryModule.getRecoveryDelay();
        t(recoveryDelay >= 48 hours, "Recovery delay too short");

        // pendingRecovery DEBE estar vacio despues de uninstall
        recoveryModule.onUninstall(abi.encode(safe));
        t(recoveryModule.getPendingRecovery(address(safe)) == bytes32(0),
          "Pending recovery not cleared on uninstall");
    }
  que_mirar:
    - "¿El recovery module tiene timelock? ¿Cuanto?"
    - "¿El owner puede cancelar un recovery en curso?"
    - "¿El nonce de recovery se incrementa correctamente?"
    - "¿onUninstall limpia pendingRecoveryData?"
    - "grep -r 'recovery\\|guardian\\|RecoveryModule\\|socialRecovery' --include='*.sol'"
  como_se_arregla: >
    Timelock minimo de 48h-7d para recovery. Owner debe poder cancelar recovery
    durante el timelock. pendingRecoveryData DEBE limpiarse en onUninstall.
    Recovery nonce debe incrementarse en cada intento (exitoso o no) para prevenir
    replay.
  trampas:
    - "Un timelock muy largo (30d) puede ser peor -- si el owner muere, los fondos quedan atrapados"
    - "La seguridad del recovery depende de la seguridad de los guardianes, no del smart contract"
    - "Algunos recovery modules usan DKIM (email) -- verificar fortaleza del oracle"
  solodit_ids:
    - failure-to-clear-pendingrecoverydata-in-onuninstall-allows-immediate-account-recovery-upon-reconnection-openzeppelin-none-matter-labs-guardian-recovery-validator-audit-markdown
    - guardian-can-overwrite-recovery-process-and-render-it-useless-openzeppelin-none-matter-labs-guardian-recovery-validator-audit-markdown
    - cloudrecoverymodule-never-increments-the-recovery-nonce-cantina-none-clave-pdf
    - disallow-changing-cloud-guardian-during-recovery-cantina-none-clave-pdf
    - incomplete-recovery-process-due-to-missing-validator-attachment-openzeppelin-none-matter-labs-guardian-recovery-validator-audit-markdown
    - uninstall-process-might-revert-due-to-pending-guardian-acceptance-openzeppelin-none-matter-labs-guardian-recovery-validator-audit-markdown
  incidentes:
    - "Matter Labs Guardian Recovery (OZ 2025) -- pendingRecoveryData no se limpiaba en onUninstall, permitiendo recovery inmediata al reinstalar el modulo"
    - "Clave (Cantina 2024) -- Recovery nonce nunca se incrementaba en cloudRecoveryModule, permitiendo replay de recovery requests"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Matter Labs OZ audit, Clave Cantina"
  tags: [recovery, guardian, social-recovery, takeover, timelock, nonce, uninstall]
  relacionado_con: [msw-002, msw-004]
```

## 13. Gas Estimation Manipulation

```yaml
- id: msw-013
  pattern: gas-estimation-manipulation
  name: "Manipulacion de gas estimation causa revert de transacciones Safe"
  causa_raiz: >
    Gnosis Safe usa un patron de gas estimation donde el relayer/executor estima
    el gas necesario off-chain via eth_estimateGas o Safe.requiredTxGas(). Si el
    contrato target tiene logica que consume gas diferente entre simulacion y
    ejecucion real (e.g., storage que cambia entre estimacion y ejecucion, o
    gas costs que dependen de block.number), la tx real puede revertir por
    insufficient gas. Ademas, si safeTxGas se configura incorrectamente, la tx
    interna puede revertir silenciosamente (Safe consume el nonce y emite evento
    de exito pero la operacion interna fallo).
  como_funciona: |
    1. Relayer estima gas para tx Safe via eth_estimateGas (off-chain)
    2. Estimacion retorna G gas necesarios
    3. Atacante front-runs la estimacion con una tx que modifica storage del target
       (e.g., escribe a un slot que estaba cold, ahora caliente -- ahorra gas)
    4. La estimacion fue para el estado pre-frontrun, pero la ejecucion es post-frontrun
    5. Alternativamente: safeTxGas se configura bajo, la tx interna revierte por OOG
    6. Pero la tx Safe NO revierte (si safeTxGas > 0), el nonce avanza, y los owners
       piensan que la tx se ejecuto exitosamente
  invariante: |
    function invariant_tx_internal_success() external {
        // Si safeTxGas > 0, verificar que la operacion interna tambien tuvo exito
        (bool success, ) = safe.execTransaction{gas: txGas}(
            to, value, data, operation, safeTxGas, 0, 0,
            address(0), payable(0), signatures
        );
        // success = true solo significa que la tx Safe no revirtio
        // Necesitamos verificar que la operacion interna tambien tuvo exito
        // Esto requiere checkear el evento ExecutionSuccess vs ExecutionFailure
    }
  que_mirar:
    - "¿safeTxGas > 0? Si si, la tx interna puede revertir sin revertir la tx Safe"
    - "¿El gas limit del execute es mayor que safeTxGas + overhead?"
    - "¿El target tiene logica gas-variable (e.g., acceso a storage frio/caliente)?"
    - "¿El evento emitido es ExecutionSuccess o ExecutionFailure?"
    - "grep -r 'safeTxGas\\|requiredTxGas\\|ExecutionFailure' --include='*.sol'"
  como_se_arregla: >
    Usar safeTxGas=0 siempre que sea posible (todo el gas se pasa a la operacion
    interna y si revierte, toda la tx revierte). Si safeTxGas > 0 es necesario,
    verificar el evento ExecutionSuccess/ExecutionFailure en el frontend.
    Implementar gas overhead buffer (e.g., +20% sobre la estimacion).
  trampas:
    - "safeTxGas=0 es el default en Safe v1.3+ -- la mayoria de los Safes no tienen este problema"
    - "El front-running de gas estimation es teoricamente posible pero dificil en la practica"
    - "Los relayers profesionales (Gelato, OZ Defender) manejan gas estimation correctamente"
  solodit_ids:
    - gas-estimation-can-fail-in-finalizewithdrawaltransaction-openzeppelin-none-mantle-v2-solidity-contracts-audit-markdown
    - gas-estimate-is-calculated-incorrectly-in-gateway-spearbit-none-centrifuge-pdf
    - incorrect-gas-estimation-ottersec-none-caldera-pdf
  incidentes:
    - "Safe historico -- Multiples reports de txs que aparecen exitosas en la UI pero la operacion interna fallo (safeTxGas > 0 con gas insuficiente)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit: Mantle OZ, Centrifuge Spearbit, Caldera OtterSec"
  tags: [gas, estimation, safeTxGas, silent-revert, front-running, relayer]
  relacionado_con: [msw-005, msw-011]
```

## 14. Approval via Safe Batch Transaction

```yaml
- id: msw-014
  pattern: hidden-approval-in-batch
  name: "Aprobacion maliciosa oculta en batch MultiSend"
  causa_raiz: >
    Una transaccion MultiSend puede contener decenas de sub-operaciones. Si un
    owner malicioso (o un atacante que inyecta data en el batch) incluye un
    approve(attacker, type(uint256).max) en medio de operaciones legitimas, los
    otros owners pueden firmarlo sin notar la aprobacion maliciosa. Esto es
    especialmente peligroso porque Safe{Wallet} UI puede no mostrar claramente
    cada sub-operacion de un batch complejo.
  como_funciona: |
    1. Owner A propone batch MultiSend:
       a) Swap 1000 USDC -> ETH via Uniswap (legitimo)
       b) approve(attacker, type(uint256).max, USDC) (oculto entre operaciones)
       c) Claim rewards de Aave (legitimo)
    2. Owner B y C firman el batch -- la UI muestra "3 operations" sin detalle
    3. El batch se ejecuta: swap + approve malicioso + claim
    4. Atacante tiene approval infinito de USDC del Safe
    5. Atacante llama transferFrom(safe, attacker, safe.usdcBalance) cuando quiera
  invariante: |
    function invariant_no_unexpected_approvals() external {
        // Trackear todas las allowances del Safe
        uint256 allowance = token.allowance(address(safe), suspiciousAddress);
        t(allowance == 0 || allowance == expectedAllowance,
          "Unexpected token approval from Safe");
    }
  que_mirar:
    - "¿El batch contiene approve() o increaseAllowance() calls?"
    - "¿La UI/guard decodifica y muestra CADA sub-operacion del MultiSend?"
    - "¿Hay un guard que bloquee approve() a addresses no whitelisted?"
    - "Buscar: abi.encodeWithSelector(IERC20.approve.selector, ...) en batch data"
    - "grep -r 'approve\\|increaseAllowance\\|multiSend' --include='*.sol'"
  como_se_arregla: >
    Implementar un guard que decodifique el MultiSend data y verifique que no
    contiene approve() a addresses no whitelisted. Safe{Wallet} deberia mostrar
    cada sub-operacion con colores/warnings para operaciones peligrosas (approve,
    transfer, delegatecall). Brahma Console implementa policy checks que
    validan cada operacion del batch.
  trampas:
    - "Esto es mas un vector de social engineering que un bug de smart contract"
    - "Un guard bien implementado (como Brahma PolicyValidator) previene esto on-chain"
    - "La responsabilidad es compartida: UI + guard + review humano"
  solodit_ids:
    - batch-approval-duplicate-permissions-vulnerability-in-approvebatchwithsignature-cantina-none-coinbase-pdf
    - malicious-orders-can-approve-existing-orders-on-behalf-of-any-signer-trailofbits-none-multisignature-wallet-pdf
    - changes-between-signing-and-execution-could-yield-results-that-are-outside-the-bounds-of-the-spearbit-none-brahma-pdf
  incidentes:
    - "Safe{Wallet}/Bybit (Feb 2025) -- Supply chain attack: atacantes comprometieron la infraestructura de Safe{Wallet} UI (frontend), inyectando JS malicioso que modificaba los batch transactions en la UI antes de que los signers los firmaran. $1.5B robados de Bybit multisig. El contrato Safe era correcto -- el ataque fue en la capa de presentacion."
    - "Trail of Bits Multisig Wallet audit -- Malicious orders podian aprobar ordenes en nombre de cualquier signer"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Coinbase Cantina, ToB Multisig Wallet, Brahma Spearbit"
  tags: [approval, MultiSend, batch, social-engineering, UI, hidden-operation, supply-chain]
  relacionado_con: [msw-011, msw-002]
```

## 15. Proxy Factory Salt Collision

```yaml
- id: msw-015
  pattern: proxy-factory-salt-collision
  name: "Collision de salt en SafeProxyFactory permite deploy de Safe diferente en misma address"
  causa_raiz: >
    Si la SafeProxyFactory no incluye el initializer (parametros de setup como
    owners/threshold) en el salt de CREATE2, dos deployments con distinto
    initializer pero mismo saltNonce producen el mismo address. Si la primera
    tx revierte (o se front-runea), la segunda puede deployar un Safe con
    parametros diferentes en la address esperada. Mas criticamente: si el
    factory usa abi.encodePacked para combinar los parametros del salt, puede
    haber colisiones por la falta de padding (ABI encoding ambiguity).
  como_funciona: |
    1. Factory calcula salt = keccak256(abi.encodePacked(initializer, saltNonce))
    2. Dos initializers diferentes pueden producir el mismo packed encoding:
       e.g., abi.encodePacked(bytes("AB"), bytes("C")) == abi.encodePacked(bytes("A"), bytes("BC"))
    3. Atacante encuentra un initializer que produce el mismo salt pero con sus owners
    4. Atacante deploya el Safe primero con sus owners en la address predicha
    5. El usuario original intenta deployar -- revierte porque address ya tiene codigo
    6. El usuario NO sabe que el Safe en esa address no es suyo
  invariante: |
    function invariant_salt_includes_all_params() external {
        // El salt DEBE incluir TODOS los parametros que definen el Safe
        bytes32 salt1 = factory.calculateSalt(initializer1, saltNonce);
        bytes32 salt2 = factory.calculateSalt(initializer2, saltNonce);
        // Si initializer1 != initializer2, salt1 != salt2
        if (keccak256(initializer1) != keccak256(initializer2)) {
            t(salt1 != salt2, "Different initializers produced same salt");
        }
    }
  que_mirar:
    - "¿El factory usa abi.encodePacked o abi.encode para el salt?"
    - "¿El salt incluye msg.sender? (previene front-running)"
    - "¿El salt incluye el initializer completo?"
    - "¿Hay validation de que el deployment fue exitoso (code.length > 0)?"
    - "grep -r 'createProxyWithNonce\\|abi.encodePacked.*salt\\|CREATE2' --include='*.sol'"
  como_se_arregla: >
    Usar abi.encode (no abi.encodePacked) para evitar encoding ambiguity.
    Incluir msg.sender en el salt. Incluir el hash completo del initializer
    en el salt. Verificar post-deployment que los parametros del Safe (owners,
    threshold) son los esperados.
  trampas:
    - "Safe v1.3+ incluye msg.sender y el initializer hash en el salt -- salt collision es practicamente imposible"
    - "abi.encodePacked collision requiere encontrar dos inputs que colisionen -- computacionalmente costoso"
    - "Si el bytecode del proxy es fijo (como en Safe), la collision solo puede venir del salt"
  solodit_ids:
    - grief-through-salt-collision-due-to-abiencodepacked-on-createpointsprogram-spearbit-none-royco-pdf
    - anyone-can-deploy-a-console-with-the-same-set-of-parameters-but-with-a-different-_policycommit-spearbit-none-brahma-pdf
    - registerwallet-doesnt-verify-the-wallet-is-a-real-safe-spearbit-none-brahma-pdf
    - l-01-factorydeployrentalsafe-can-be-front-run-to-revert-safe-creation-code4rena-renft-renft-git
  incidentes:
    - "Brahma (Spearbit 2023) -- Cualquiera podia deployar una Console con mismos parametros pero diferente _policyCommit, creando una Console sin policy checks"
    - "Royco (Spearbit 2024) -- Salt collision via abi.encodePacked en createPointsProgram, permitiendo griefing"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: Royco Spearbit, Brahma Spearbit, reNFT C4"
  tags: [CREATE2, salt, collision, abi.encodePacked, factory, front-running, deployment]
  relacionado_con: [msw-008, msw-001]
```

## 16. Supply Chain Attack on Wallet UI

```yaml
- id: msw-016
  pattern: supply-chain-wallet-ui-attack
  name: "Compromiso de UI/frontend de wallet modifica transacciones antes de firmar"
  causa_raiz: >
    Las wallets multisig dependen de una UI (web app, extension, o hosted service)
    para mostrar transacciones a los signers. Si el frontend es comprometido
    (supply chain attack via NPM dependency, CDN hijack, insider threat), el
    atacante puede modificar las transacciones mostradas a los signers: la UI
    muestra "Transfer 100 USDC to provider" pero la transaccion real es
    "Transfer all USDC to attacker". Los signers firman lo que VEN, no lo que
    realmente se ejecuta. Este vector es independiente de la seguridad del
    smart contract.
  como_funciona: |
    1. Atacante compromete la build pipeline de Safe{Wallet} UI
       (e.g., via NPM dependency maliciosa, compromiso de CI/CD)
    2. La UI modificada intercepta createTransaction() y reemplaza el 'to' y 'data'
    3. El signer ve en la UI: "Send 1 ETH to 0xProvedor..."
    4. El transaction data real es: "Send all ETH to 0xAtacante..."
    5. El signer firma con hardware wallet -- el HW wallet muestra el hash, no el contenido
    6. Con threshold firmas, la tx se ejecuta y drena el Safe
  invariante: |
    // No hay invariante on-chain -- el ataque es off-chain
    // Mitigacion: verificar tx data en multiples interfaces independientes
    // Invariante conceptual: lo que el signer ve == lo que firma == lo que se ejecuta
    function invariant_conceptual_signer_verification() external pure {
        // Este invariante NO puede verificarse on-chain
        // Requiere: hardware wallet con display de datos completos (EIP-712)
        // + verificacion en interfaz independiente (CLI, otra UI, Etherscan)
        revert("Off-chain verification required");
    }
  que_mirar:
    - "¿La wallet UI se serve via CDN? ¿Puede ser interceptada?"
    - "¿Los signers verifican la tx data en una segunda interfaz (Etherscan, CLI)?"
    - "¿Los hardware wallets muestran los datos completos de la tx (EIP-712 structured data)?"
    - "¿El frontend tiene Content Security Policy estricto?"
    - "¿Las dependencies de NPM estan pinned y auditadas?"
  como_se_arregla: >
    Multiples capas: (1) Verificar tx data en al menos 2 interfaces independientes
    antes de firmar. (2) Usar hardware wallets con display EIP-712 completo.
    (3) Self-host la UI de Safe o usar un CLI. (4) Implementar Subresource
    Integrity (SRI) en todos los scripts. (5) Usar on-chain transaction guards
    que limiten operaciones permitidas.
  trampas:
    - "Este vector es IMPOSIBLE de mitigar solo con smart contracts -- es un problema de la capa de presentacion"
    - "Los hardware wallets actuales no muestran EIP-712 structured data de forma legible"
    - "No confundir con un bug del contrato Safe -- el contrato funciona correctamente"
  solodit_ids:
    - supply-chain-vulnerability-in-github-actions-workflow-configuration-spearbit-none-thala-vciso-pdf
    - governance-can-backdoor-new-safes-via-malicious-upgrade-spearbit-none-brahma-pdf
    - upgrade-of-trustedvalidator-could-circumvent-policy-checks-spearbit-none-brahma-pdf
  incidentes:
    - "Safe{Wallet}/Bybit (Feb 2025) -- $1.5B robados. Atacantes (atribuidos a Lazarus Group/DPRK) comprometieron la infraestructura de Safe{Wallet}, inyectando codigo malicioso en el frontend que modificaba las transacciones del multisig de Bybit. Los signers firmaron transacciones que parecian legitimas pero contenian transferencias al atacante."
    - "Ledger Connect Kit (Dec 2023) -- Supply chain attack via NPM. Un ex-empleado de Ledger fue phished, y el atacante publico una version maliciosa del Connect Kit que drenaba wallets de usuarios que interactuaban con dApps que usaban la libreria."
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Incidente real Bybit Feb 2025, Ledger Connect Kit Dec 2023"
  tags: [supply-chain, UI, frontend, signing, hardware-wallet, off-chain, social-engineering]
  relacionado_con: [msw-014, msw-002]
```

---

## Quick Grep Cheatsheet

```bash
# Ownership & threshold
grep -r 'addOwnerWithThreshold\|removeOwner\|swapOwner\|changeThreshold' --include='*.sol'
grep -r 'getOwners\|isOwner\|getThreshold\|ownerCount' --include='*.sol'

# Modules
grep -r 'enableModule\|disableModule\|execTransactionFromModule' --include='*.sol'
grep -r 'getModulesPaginated\|isModuleEnabled' --include='*.sol'

# Guards
grep -r 'setGuard\|checkTransaction\|checkAfterExecution\|Guard' --include='*.sol'
grep -r 'TransactionGuard\|ModuleGuard\|guard()' --include='*.sol'

# Fallback handler
grep -r 'setFallbackHandler\|fallbackHandler\|internalSetFallbackHandler' --include='*.sol'
grep -r 'onERC721Received\|onERC1155Received\|isValidSignature' --include='*.sol'

# Signatures & EIP-1271
grep -r 'isValidSignature\|0x1626ba7e\|checkNSignatures\|checkSignatures' --include='*.sol'
grep -r 'ecrecover\|ECDSA.recover\|SignatureDecoder' --include='*.sol'
grep -r 'domainSeparator\|DOMAIN_SEPARATOR\|EIP712' --include='*.sol'

# Nonces & replay
grep -r 'nonce\|nonce()\|_nonce' --include='*.sol'
grep -r 'chainId\|block.chainid' --include='*.sol'

# CREATE2 & deployment
grep -r 'createProxyWithNonce\|CREATE2\|create2\|SafeProxyFactory' --include='*.sol'
grep -r 'abi.encodePacked.*salt\|keccak256.*salt' --include='*.sol'

# Delegatecall & MultiSend
grep -r 'delegatecall\|Operation.DelegateCall\|operation == 1' --include='*.sol'
grep -r 'multiSend\|MultiSend\|multisend' --include='*.sol'
grep -r 'selfdestruct\|SELFDESTRUCT' --include='*.sol'

# Recovery
grep -r 'recovery\|guardian\|RecoveryModule\|socialRecovery' --include='*.sol'
grep -r 'pendingRecovery\|recoveryNonce\|startRecovery' --include='*.sol'

# Gas
grep -r 'safeTxGas\|requiredTxGas\|ExecutionFailure\|ExecutionSuccess' --include='*.sol'
```

## Fuzzing Priorities

```
HIGH VALUE para invariants:
1. threshold <= ownerCount SIEMPRE (post addOwner/removeOwner/swapOwner)
2. modules habilitados ⊆ whitelist conocida
3. fallbackHandler == expectedHandler (no cambio inesperado)
4. execTransactionFromModule solo callable por modules habilitados
5. domainSeparator incluye block.chainid actual
6. isValidSignature rechaza firmas invalidas (address(0) como signer)
7. nonce es estrictamente monotono creciente (+1 por tx)
8. MultiSend batch es atomico (todo o nada)
9. delegatecall targets ⊆ whitelist (no selfdestruct)
10. pendingRecovery se limpia en onUninstall de recovery module

HANDLERS criticos:
- execTransaction(to, value, data, DELEGATECALL, ...) → ¿se puede apuntar a selfdestruct?
- enableModule(malicious) → ¿quien puede llamarlo?
- setFallbackHandler(malicious) → ¿el guard lo bloquea?
- swapOwner(prevOwner, oldOwner, newOwner) × N → ¿se puede encadenar para takeover?
- changeThreshold(1) → ¿se puede combinar con swapOwner en un batch?
- isValidSignature(hash, emptySig) → ¿retorna magic value?
- execTransactionFromModule(to, value, data, operation) → ¿respeta el guard?
- recovery.startRecovery(newOwners) → ¿tiene timelock? ¿necesita quorum de guardianes?
```

## Incidentes Historicos Clave

| Fecha | Incidente | Monto | Vector | Leccion |
|-------|-----------|-------|--------|---------|
| Jul 2017 | Parity Multisig Hack | $30M | initWallet() sin proteccion de re-init | **SIEMPRE** proteger initializers con initialized flag |
| Nov 2017 | Parity Multisig Freeze | $150M | selfdestruct de singleton library | **NUNCA** hacer implementation publica initializable + destructible |
| Mar 2022 | Ronin Bridge | $625M | 5/9 validators comprometidos | Threshold 5/9 con validators internos = centralizado |
| Jun 2022 | Harmony Bridge | $100M | 2/5 multisig comprometido | Threshold 2/5 es inaceptable para bridges |
| Sep 2022 | Wintermute | $160M | Vanity address (Profanity weak RNG) | No usar vanity address generators no auditados |
| Oct 2024 | Radiant Capital | $50M | 3/11 signers comprometidos via malware | Malware en dispositivos de signers = game over |
| Feb 2025 | Bybit/Safe{Wallet} | $1.5B | Supply chain attack en Safe UI | UI compromised > smart contract security |

## Decision Tree: ¿Es Explotable?

```
¿El Safe tiene modules habilitados?
  ├── SI → ¿Los modules tienen permisos excesivos? → MSW-002, MSW-003
  └── NO → ¿El threshold es bajo (1/N o 2/N)?
              ├── SI → ¿Los owners estan en cold storage? → MSW-004
              └── NO → ¿Hay guard?
                          ├── SI → ¿El guard cubre modules? → MSW-003
                          └── NO → ¿Se usa delegatecall? → MSW-006
                                    ├── SI → ¿Hay whitelist? → MSW-006
                                    └── NO → ¿Firma off-chain? → MSW-001, MSW-009

¿El Safe se deployó con CREATE2?
  ├── SI → ¿Salt incluye msg.sender + initializer? → MSW-008, MSW-015
  └── NO → Standard deployment, menor riesgo CREATE2

¿Hay recovery module?
  ├── SI → ¿Timelock >= 48h? ¿Nonce se incrementa? → MSW-012
  └── NO → Recovery social no aplica
```
