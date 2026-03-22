# ERC-4337 Account Abstraction -- Combat Briefing

> **Scope**: ERC-4337 smart wallets, paymasters, session keys, bundler interactions, and Coinbase-specific extensions (MagicSpend, SpendPermissionManager).
> **Sources**: Solodit -- 29 verified audit findings. Protocols: Coinbase SmartWallet (C4 2024-03), Biconomy (C4 2023-01), EtherSpot Modular (Pashov/Cyfrin 2025), Sequence (C4 2025-10).
> **Last updated**: 2026-03-22

---

## Conceptos clave antes de huntar

**Flujo ERC-4337**:
```
Bundler → EntryPoint.handleOps()
           ├── validateUserOp()   ← firma, nonce, gas pre-flight
           ├── validatePaymasterUserOp()  ← paymaster acepta pagar
           ├── execute callData   ← acción real del usuario
           └── postOp()           ← paymaster cobra gas real
```

**Contratos Coinbase Smart Wallet**:
- `CoinbaseSmartWallet.sol` — cuenta ERC-4337 multi-owner, WebAuthn + ECDSA
- `MagicSpend.sol` — paymaster que actúa también como withdrawal vault
- `SpendPermissionManager.sol` — sistema de permisos delegados a DApps

**Trust boundaries críticos**:
- `EntryPoint` es el único caller legítimo de `validateUserOp` y `validatePaymasterUserOp`
- `msg.sender` dentro de `validateUserOp` ES el EntryPoint, no el usuario
- El `userOpHash` lo construye el EntryPoint — el wallet no puede asumirlo correcto sin verificarlo

---

## 1. Paymaster

```yaml
- id: aa-001
  pattern: paymaster-drain-via-upgraded-sender
  name: "Paymaster ETH drained via upgraded malicious sender"
  causa_raiz: >
    El paymaster firma un UserOperation para un sender específico. Si el sender
    puede auto-upgradear su implementación (delegatecall a Upgrader), puede
    sustituir su lógica por un MaliciousAccount que reutiliza la firma original
    del paymaster sin restricción. El paymaster no verifica que el sender
    no haya cambiado su lógica entre validación y ejecución.
  como_funciona: |
    1. Paymaster emite firma X autorizando UserOp para sender A (comportamiento normal)
    2. Sender A ejecuta delegatecall a Upgrader, cambia implementación a MaliciousAccount
    3. MaliciousAccount reproduce la misma UserOp con la firma X del paymaster
    4. El paymaster valida la firma (sigue siendo válida para ese userOpHash)
    5. El paymaster paga el gas de una operación maliciosa — su depósito se drena
  invariante: >
    paymaster.deposit() solo decrece por operaciones del sender original cuya
    implementación no ha cambiado desde la validación.
  que_mirar:
    - "¿Puede el sender cambiar su implementación entre validateUserOp y execute?"
    - "El paymaster verifica sender address, pero NO la implementación del sender"
    - "Buscar: upgradeTo / upgradeToAndCall en el sender sin restricción de timing"
    - "¿El paymaster cachea el sender.code o solo verifica la dirección?"
  como_se_arregla: >
    El paymaster debe incluir el initCode o codehash del sender en el hash firmado.
    Alternativamente, prohibir upgrades durante un UserOp en curso via reentrancy guard.
  trampas:
    - "El paymaster puede ser legítimamente multi-sender — no confundir con bug"
    - "Si el sender es un proxy con timelock de upgrade, el riesgo es menor"
  incidentes:
    - "Solodit #6444: Biconomy VerifyingSingletonPaymaster -- sender upgrades a MaliciousAccount y reutiliza firma del paymaster para drenar depósito ETH (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit #6444 (Code4rena 2023-01-biconomy)"
  tags: [paymaster, drain, upgrade, delegatecall, signature-reuse]
  relacionado_con: [aa-002, aa-013]
```

```yaml
- id: aa-002
  pattern: paymaster-balance-race-two-loop
  name: "Paymaster balance insuficiente por race en dos bucles de EntryPoint"
  causa_raiz: >
    EntryPoint.handleOps() ejecuta dos bucles: primero valida TODAS las ops
    (llamando validatePaymasterUserOp para cada una), luego ejecuta TODAS las ops.
    El check de balance del paymaster ocurre en el primer bucle, pero si múltiples
    ops del mismo paymaster se validan antes de que ninguna se ejecute, el balance
    puede agotarse entre validación y ejecución de las últimas ops.
    Además, un atacante puede front-run el withdraw del paymaster entre ambos bucles.
  como_funciona: |
    1. Bundler incluye N UserOps de un paymaster en un mismo batch
    2. EntryPoint valida todas N: cada una pasa el check de balance individualmente
    3. Atacante front-run: llama paymaster.withdrawTo() vaciando el depósito
    4. EntryPoint ejecuta las ops -- el paymaster no tiene fondos para postOp()
    5. EntryPoint revierte o el paymaster queda insolvente para futuros usuarios
  invariante: >
    paymaster.balance >= sum(maxCost de todas las UserOps validadas pero aún no ejecutadas)
  que_mirar:
    - "¿El paymaster tiene withdraw() sin delay o timelock?"
    - "¿El balance check en validatePaymasterUserOp es optimista (solo verifica el suyo)?"
    - "Buscar: address(this).balance < withdrawAmount en validatePaymasterUserOp"
    - "¿El mismo paymaster puede estar en múltiples UserOps del mismo batch?"
  como_se_arregla: >
    El EntryPoint v0.7 añade un lock de depósito durante handleOps. Para paymasters
    custom: añadir un mecanismo de lock que impida withdrawals entre validation y postOp.
    O limitar el número de UserOps por paymaster por batch.
  trampas:
    - "En EntryPoint v0.7+ el depósito se lockea automáticamente -- verificar versión"
    - "Si withdraw() tiene un delay de cooldown, el ataque es menos práctico"
  incidentes:
    - "Solodit #32023: Coinbase MagicSpend -- balance check en validatePaymasterUserOp no garantiza fondos en postOp() si hay front-run de withdraw (MEDIUM)"
    - "Solodit #32024: Coinbase MagicSpend -- front-run de la firma del paymaster causa DoS y pérdida de fee al usuario (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #32023, #32024 (Code4rena 2024-03-coinbase)"
  tags: [paymaster, balance, race-condition, front-run, two-loop, MagicSpend]
  relacionado_con: [aa-001, aa-003]
```

```yaml
- id: aa-003
  pattern: paymaster-double-withdrawal-excess
  name: "Double withdrawal del exceso de gas en MagicSpend"
  causa_raiz: >
    Cuando MagicSpend actúa como paymaster, el exceso de ETH del withdrawRequest
    (la parte no consumida por gas) se registra en _gasMaxCostExcess[user].
    El usuario puede reclamar este exceso con withdrawGasExcess() O recibirlo
    automáticamente en postOp(). El bug: postOp() no resetea _gasMaxCostExcess
    a cero después de reembolsar, permitiendo un segundo claim via withdrawGasExcess().
  como_funciona: |
    1. Usuario ejecuta UserOp con withdrawRequest de 0.1 ETH, gas cuesta 0.03 ETH
    2. Exceso (0.07 ETH) se registra en _gasMaxCostExcess[user] = 0.07 ETH
    3. postOp() reembolsa automáticamente 0.07 ETH al usuario
    4. postOp() NO resetea _gasMaxCostExcess[user] (bug)
    5. Usuario llama withdrawGasExcess() y cobra otro 0.07 ETH
    6. MagicSpend pierde 0.07 ETH por cada UserOp ejecutada
  invariante: >
    sum(ETH retirado por usuario) <= sum(ETH depositado en withdrawRequest por usuario).
    Después de postOp(), _gasMaxCostExcess[user] == 0.
  que_mirar:
    - "¿postOp() resetea _gasMaxCostExcess[user] = 0 antes de transferir?"
    - "¿Existe withdrawGasExcess() o función equivalente de claim manual?"
    - "¿Ambos paths (postOp + manual) pueden ejecutarse en la misma UserOp?"
    - "Buscar: _gasMaxCostExcess mapping + withdrawGasExcess function"
  como_se_arregla: >
    En postOp(), resetear _gasMaxCostExcess[user] = 0 ANTES de transferir el exceso.
    Patrón check-effects-interactions: delete el estado antes del call externo.
  trampas:
    - "El finding puede estar fixeado en versiones posteriores de MagicSpend -- verificar commit"
    - "Si postOp es llamado por el EntryPoint, el reentrancy directo no aplica, pero el double-claim sí"
  incidentes:
    - "Solodit #40749: Coinbase MagicSpend -- postOp() no resetea _gasMaxCostExcess, doble withdrawal del exceso de ETH (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #40749 (Coinbase SpendPermission audit)"
  tags: [paymaster, double-withdrawal, MagicSpend, excess-gas, state-reset]
  relacionado_con: [aa-002]
```

```yaml
- id: aa-004
  pattern: paymaster-gas-collection-offchain
  name: "Escape de pago de gas via diseño de cobro off-chain"
  causa_raiz: >
    Algunos paymasters diseñan el cobro de gas de forma diferida: _postOp() solo
    emite un evento, y los admins procesan el cobro manualmente después. Si el
    usuario puede hacer que su UserOp se ejecute con éxito pero el cobro off-chain
    falle (dirección incorrecta, token bloqueado, permiso revocado), obtiene la
    transacción gratis. El contrato no tiene garantía on-chain de que el cobro ocurra.
  como_funciona: |
    1. Paymaster acepta sponsorizar UserOp si admin firma aprobación
    2. postOp() solo emite evento GasTankPaymaster_UserOperationSponsored
    3. Admin procesa el evento off-chain y llama repaySponsoredTransaction()
    4. Atacante: revoca el permiso del token DESPUES de la UserOp, antes del cobro
    5. repaySponsoredTransaction() falla (token no aprobado / zero balance)
    6. Atacante obtuvo transacción gratis
  invariante: >
    Si validatePaymasterUserOp() retorna éxito, el gas correspondiente DEBE ser cobrado
    on-chain en el mismo flujo de handleOps(), no de forma diferida.
  que_mirar:
    - "¿postOp() solo emite eventos en lugar de hacer transferFrom()?"
    - "¿El cobro real depende de una llamada posterior de un admin off-chain?"
    - "¿El usuario puede revocar allowance o vaciar su balance entre UserOp y cobro?"
    - "Buscar: emit en postOp() sin transferencia de tokens"
  como_se_arregla: >
    El cobro debe ocurrir dentro de postOp() directamente, o el paymaster debe
    pre-retener fondos en validatePaymasterUserOp() que se liberan en postOp().
    No depender de procesamiento off-chain para garantizar el pago de gas.
  trampas:
    - "Algunos paymasters sponsorizan intencionalmente (usuario no paga) -- solo es bug si el protocolo asume cobro"
    - "Paymasters con depósito pre-cargado en EntryPoint no tienen este problema"
  incidentes:
    - "Solodit #62850: EtherSpot GasTankPaymaster -- _postOp() no cobra gas on-chain, cobro diferido via evento permite escape de pago revocando allowance (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit #62850 (EtherSpot Modular Accounts audit 2025)"
  tags: [paymaster, gas-escape, off-chain-collection, postOp, sponsorship]
  relacionado_con: [aa-002]
```

---

## 2. validateUserOp

```yaml
- id: aa-005
  pattern: validateUserOp-signature-not-consumed
  name: "Firma de UserOp no consumida en validateUserOp -- replay sin nonce"
  causa_raiz: >
    ERC-4337 provee protección contra replay via el nonce del EntryPoint para
    el flujo estándar. Pero algunos módulos de validación implementan su propia
    lógica de validateUserOp que verifica callData (ResourceLock, SessionKey, etc.)
    sin consumir la firma ni incrementar un nonce propio. Esto permite replay
    de la misma UserOp si el nonce del EntryPoint aún no fue usado para ese dato.
  como_funciona: |
    1. Módulo custom implementa validateUserOp con verificación de ResourceLock
    2. ResourceLock contiene validAfter/validUntil pero no un nonce único
    3. EntryPoint provee nonce para el flujo estándar, pero el módulo valida
       contra callData extraído del ResourceLock -- path paralelo sin nonce
    4. Atacante reutiliza la misma UserOp firmada mientras sea válida en tiempo
    5. Mismo callData se ejecuta múltiples veces contra el smart wallet
  invariante: >
    Cada combinación única (sessionKey, callData, smartWallet) debe poder
    ejecutarse como máximo una vez. La firma debe marcarse como consumida.
  que_mirar:
    - "¿validateUserOp en módulo custom verifica nonce propio además del EntryPoint?"
    - "¿La firma del ResourceLock/SessionKey se marca como usada en storage?"
    - "Buscar: struct con validAfter/validUntil pero sin nonce o usedSignatures mapping"
    - "¿El módulo tiene un path de validación paralelo al EntryPoint nonce?"
  como_se_arregla: >
    Añadir mapping(bytes32 => bool) usedSignatures en el módulo.
    Hash único = keccak256(chainId, smartWallet, sessionKey, callData, validAfter, validUntil).
    Marcar como usada antes de ejecutar (CEI pattern).
  trampas:
    - "El nonce del EntryPoint protege contra replay del userOpHash completo -- el bug ocurre cuando el módulo valida datos DENTRO del callData por un path separado"
    - "Si validUntil es en el pasado, el replay falla igualmente -- confirmar ventana de validez"
  incidentes:
    - "Solodit #61409: EtherSpot ResourceLockValidator -- validateUserOp no consume la firma del ResourceLock, replay posible dentro de la ventana validAfter/validUntil (CRITICAL)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit #61409 (EtherSpot Modular Accounts, Pashov/Cyfrin 2025)"
  tags: [validateUserOp, replay, signature-consumption, session-key, ResourceLock]
  relacionado_con: [aa-006, aa-010]
```

```yaml
- id: aa-006
  pattern: validateUserOp-insufficient-binding
  name: "validateUserOp sin binding entre userOpHash y callData -- ejecución no autorizada"
  causa_raiz: >
    validateUserOp() recibe (userOp, userOpHash). Algunos módulos verifican la
    firma contra userOpHash pero no verifican que userOpHash corresponde
    realmente al hash del userOp proporcionado. O verifican el sender pero no
    que el sessionKey pertenece a ese sender específico. Cualquier desconexión
    entre lo que se firma y lo que se ejecuta permite inyectar callData malicioso.
  como_funciona: |
    1. Módulo verifica que signer es un sessionKey registrado (check A)
    2. Módulo verifica que msg.sender == userOp.sender (check B)
    3. FALTA: verificar que userOpHash == EntryPoint.getUserOpHash(userOp)
    4. Atacante construye un userOp con callData malicioso pero reutiliza
       un userOpHash de una UserOp legítima anterior
    5. Los checks A y B pasan; el callData malicioso se ejecuta
  invariante: >
    validateUserOp DEBE verificar: (1) la firma es válida sobre userOpHash,
    (2) userOpHash == keccak256(userOp fields) según el EntryPoint,
    (3) el firmante tiene permiso sobre ese sender específico.
  que_mirar:
    - "¿El módulo llama entryPoint.getUserOpHash(userOp) y compara con userOpHash recibido?"
    - "¿Verifica que sessionKey pertenece a op.sender, no a cualquier wallet?"
    - "¿Se verifica que msg.sender (EntryPoint) es el caller legítimo?"
    - "Buscar: recover(userOpHash, signature) sin validar que userOpHash es correcto"
  como_se_arregla: >
    Añadir: require(userOpHash == IEntryPoint(entryPoint).getUserOpHash(userOp)).
    Añadir: require(sessionKeyData.wallet == op.sender).
    Verificar siempre que msg.sender == address(entryPoint).
  trampas:
    - "El EntryPoint llama validateUserOp con el hash correcto -- el bug surge cuando el módulo NO confía en esto y necesita re-verificarlo para paths custom"
    - "Si el módulo solo se usa como hook (no como validator primario), el riesgo puede ser menor"
  incidentes:
    - "Solodit #61410: EtherSpot ResourceLockValidator -- validateUserOp sin checks suficientes permite drenar balances del wallet con callData malicioso (CRITICAL)"
    - "Solodit #61396: EtherSpot CredibleAccountModule -- no verifica que userOpHash es el hash real del userOp ni que sessionKey pertenece al sender (HIGH)"
    - "Solodit #61411: EtherSpot CredibleAccountModule -- no verifica mismatch entre userOp y userOpHash, ni validez del sender (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit #61410, #61396, #61411 (EtherSpot Modular Accounts, Pashov/Cyfrin 2025)"
  tags: [validateUserOp, callData-injection, userOpHash, sender-binding, authorization]
  relacionado_con: [aa-005, aa-007]
```

```yaml
- id: aa-007
  pattern: validateUserop-internal-function-public
  name: "Función interna de validateUserOp expuesta como public -- manipulación de estado"
  causa_raiz: >
    validateUserOp() llama funciones auxiliares (validateSessionKeyParams,
    validateResourceLock, etc.) que modifican estado crítico (tokens bloqueados,
    sesiones activas, allowances). Si estas funciones auxiliares son public
    en lugar de internal/private, cualquier address puede llamarlas directamente
    y manipular el estado sin pasar por la validación de la UserOp.
  como_funciona: |
    1. CredibleAccountModule.validateSessionKeyParams() es public
    2. Esta función marca tokens de un usuario como "claimed" en sessionData
    3. Atacante llama validateSessionKeyParams() directamente con cualquier datos
    4. Los tokens del usuario quedan marcados como claimed sin haber ejecutado nada
    5. Usuario no puede usar sus tokens en una UserOp legítima posterior
  invariante: >
    Toda función que modifique estado de sesiones, tokens o permisos DEBE ser
    internal o private. Si necesita ser callable externamente, requiere el mismo
    nivel de autenticación que validateUserOp (msg.sender == EntryPoint).
  que_mirar:
    - "¿Hay funciones public en módulos de validación que modifiquen sessionData?"
    - "¿validateSessionKeyParams, consumeResourceLock o similares son public?"
    - "Buscar: function validate* public o function consume* public en módulos ERC-4337"
    - "¿Qué estado cambia cada función auxiliar llamada dentro de validateUserOp?"
  como_se_arregla: >
    Cambiar visibilidad a internal. Si debe ser callable externamente, añadir:
    require(msg.sender == address(entryPoint) || msg.sender == address(this)).
  trampas:
    - "La función puede parecer solo de lectura pero modificar estado con side effects"
    - "En Solidity, funciones public pueden ser llamadas tanto internamente como externamente -- revisar todos los callers"
  incidentes:
    - "Solodit #61407: EtherSpot CredibleAccountModule -- validateSessionKeyParams() es public, atacante marca tokens del usuario como claimed sin ejecutar UserOp (CRITICAL)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit #61407 (EtherSpot Modular Accounts, Pashov/Cyfrin 2025)"
  tags: [validateUserOp, visibility, public-function, session-state, access-control]
  relacionado_con: [aa-006, aa-010]
```

```yaml
- id: aa-008
  pattern: validateUserop-ecrecover-zero-address
  name: "ecrecover/ECDSA.recover retorna address(0) en validateUserOp"
  causa_raiz: >
    ecrecover() nativo retorna address(0) para firmas inválidas en lugar de revertir.
    Si validateUserOp usa ecrecover sin verificar que el resultado != address(0),
    y si un owner/signer puede ser address(0) (uninitialized, revocado, o slot vacío),
    el check signer == owner pasa con firma arbitraria.
  como_funciona: |
    1. _validateSignature() llama ECDSA.recover(userOpHash, sig) → retorna address(0)
    2. Check: if (isAdmin(signer)) return 0  -- isAdmin verifica si signer está en owners[]
    3. Si owners[] tiene un slot vacío (address(0)) o el admin fue revocado dejando address(0):
       el check pasa
    4. Atacante ejecuta cualquier UserOp con firma inválida/nula
  invariante: >
    ecrecover/ECDSA.recover SIEMPRE debe ir seguido de require(recovered != address(0)).
    Los owners mapping/array no deben contener address(0).
  que_mirar:
    - "¿_validateSignature usa ecrecover directo sin check de address(0)?"
    - "¿Usa ECDSA.recover() (que revierte) o ECDSA.tryRecover() (que retorna address(0))?"
    - "¿El mapping de owners puede contener address(0) por inicialización o por remoción?"
    - "Buscar: address signer = ECDSA.recover(...) sin require(signer != address(0))"
  como_se_arregla: >
    Usar OpenZeppelin ECDSA.recover() que revierte en firma inválida.
    Si se usa tryRecover(), añadir: require(recovered != address(0), 'Invalid sig').
    Nunca almacenar address(0) en arrays/mappings de owners.
  trampas:
    - "ECDSA.recover() de OZ revierte -- solo es bug con ecrecover nativo o ECDSA.tryRecover()"
    - "Si owners mapping requiere registro explícito, address(0) no puede estar -- verificar el path de inicialización"
  incidentes:
    - "Solodit #53328: OmoAgen Smart Wallet -- _validateSignature usa ECDSA.recover sin check address(0), firma inválida puede pasar si signer es address(0) (HIGH)"
    - "Solodit #63399: SignaturePaymaster -- validatePaymasterUserOp usa ECDSA.tryRecover sin revert ni check address(0) (LOW/MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit #53328, #63399"
  tags: [validateUserOp, ecrecover, address-zero, ECDSA, signature-validation]
  relacionado_con: [aa-006]
```

```yaml
- id: aa-009
  pattern: validateUserop-missing-entrypoint-access-control
  name: "validateUserOp callable por cualquier address -- nonce manipulation / DoS"
  causa_raiz: >
    validateUserOp DEBE ser llamado solo por el EntryPoint. Si el módulo no
    verifica que msg.sender == address(entryPoint), cualquier address puede
    llamarlo directamente, incrementar nonces del usuario, y causar que las
    UserOps legítimas del usuario fallen por nonce incorrecto.
  como_funciona: |
    1. JWTRecovery.validateUserOp() carece de onlyEntryPoint modifier
    2. Atacante llama validateUserOp() directamente con cualquier userOp
    3. El nonce del usuario se incrementa: nonce[account] = currentNonce + 1
    4. La UserOp legítima del usuario falla: EntryPoint rechaza por nonce incorrecto
    5. DoS: el usuario debe recalcular y reenviar con el nonce correcto
  invariante: >
    validateUserOp SOLO puede ser llamado por address(entryPoint).
    require(msg.sender == address(entryPoint), 'not from EntryPoint').
  que_mirar:
    - "¿validateUserOp tiene modifier onlyEntryPoint o check equivalente?"
    - "¿Qué estado modifica validateUserOp internamente (nonces, locks)?"
    - "Buscar: function validateUserOp(...) external sin require(msg.sender == entryPoint)"
    - "¿Módulos de recuperación (JWT, social recovery) heredan el access control?"
  como_se_arregla: >
    Añadir: require(msg.sender == address(entryPoint), 'account: not from EntryPoint').
    O usar el modifier _requireFromEntryPoint() de las bases de OpenZeppelin AA.
  trampas:
    - "El bug puede ser solo DoS si validateUserOp no hace transferencias -- valorar impacto real"
    - "Algunos módulos son llamados internamente por el wallet (no por EntryPoint) por diseño -- verificar el flow"
  incidentes:
    - "Solodit #62122: Etherspot JWTRecovery -- validateUserOp sin access control permite a cualquier address incrementar nonce del usuario, causando DoS de UserOps legítimas (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #62122 (EtherSpot Modular Accounts audit 2025)"
  tags: [validateUserOp, access-control, nonce, DoS, entrypoint]
  relacionado_con: [aa-007]
```

---

## 3. Session Keys

```yaml
- id: aa-010
  pattern: session-key-cross-owner-impersonation
  name: "Session key owner firma consumiendo sesión de otro owner"
  causa_raiz: >
    Cuando un wallet tiene múltiples sesiones activas, validateUserOp verifica
    que el firmante es un sessionKey registrado del wallet (check correcto).
    Pero no verifica que el sessionKey en el callData de claim() es el mismo
    sessionKey que firmó la operación. Un sessionKey válido puede firmar mensajes
    que consumen el sessionKey de otro owner.
  como_funciona: |
    1. Wallet W tiene dos sesiones: sessionKeyA (owner A) y sessionKeyB (owner B)
    2. validateUserOp verifica: firmante es sessionKey registrado de W ✓
    3. callData: claim(sessionKey=sessionKeyA)  -- owner B firma consumiendo el key de A
    4. No hay check: ¿el firmante de este claim ES sessionKeyA?
    5. Owner B drena los tokens asignados a la sesión de owner A
  invariante: >
    Si la función consume/invalida sessionKeyX, la firma de la UserOp DEBE
    pertenecer a sessionKeyX. El firmante y la sessionKey afectada deben coincidir.
  que_mirar:
    - "¿claim() o consume() verifican que msg firmante == sessionKey afectada?"
    - "¿validateUserOp compara sessionKeySigner con la sessionKey en callData?"
    - "Buscar: claim(sessionKey) donde sessionKey es parámetro libre, no derivado del firmante"
    - "¿Un wallet con N sesiones puede cross-consumir sesiones entre owners?"
  como_se_arregla: >
    En claim(sessionKey, ...): require(recoverSigner(hash, sig) == sessionKey).
    O derivar sessionKey del firmante: address sessionKey = recoverSigner(...);
    y usar esa dirección como clave, no un parámetro externo.
  trampas:
    - "Si solo hay una sesión activa por wallet, el cross-claim no aplica -- verificar si el protocolo permite múltiples sesiones simultáneas"
  incidentes:
    - "Solodit #62848: EtherSpot CredibleAccountModule -- sessionKey owner firma consumiendo sessionKey de otro owner del mismo wallet (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit #62848 (EtherSpot Modular Accounts, Pashov/Cyfrin 2025)"
  tags: [session-key, impersonation, multi-owner, claim, authorization]
  relacionado_con: [aa-011, aa-005]
```

```yaml
- id: aa-011
  pattern: session-key-memory-storage-mismatch
  name: "Memory vs storage en session state -- sesiones nunca expiran"
  causa_raiz: >
    Solidity: asignar una struct de storage a una variable memory crea una COPIA.
    Modificar la copia no afecta al storage original. Si validateUserOp carga
    sessionData en memory y luego modifica sd.live = false, el storage no cambia.
    La sesión queda permanentemente activa pese a ser consumida/expirada.
  como_funciona: |
    1. validateUserOp ejecuta:
       SessionData memory sd = sessionData[key][wallet];  // COPIA en memoria
       sd.live = false;  // modifica la copia, NO el storage
    2. La sesión debería quedar inactiva tras su uso
    3. El storage sessionData[key][wallet].live sigue siendo true
    4. Atacante reutiliza la misma sesión indefinidamente
    5. Tokens pueden drenarse múltiples veces con la misma sesión "expirada"
  invariante: >
    Después de consumir una sesión, sessionData[key][wallet].live == false en storage.
    La sesión no debe poder ejecutarse más de una vez si live=false es la guard.
  que_mirar:
    - "¿sessionData se carga con memory o storage keyword?"
    - "Buscar: SessionData memory sd = sessionData[...] seguido de sd.live = false"
    - "¿Los cambios de estado de sesión usan 'storage' pointer o 'memory' copy?"
    - "Grep: 'memory sd' o 'memory session' en módulos de validación"
  como_se_arregla: >
    Cambiar a storage pointer:
    SessionData storage sd = sessionData[key][wallet];
    sd.live = false;  // ahora modifica el storage directamente
  trampas:
    - "El bug solo aplica si live/active es la única guard -- si hay nonce de EntryPoint también, el replay puede estar bloqueado de otra forma"
    - "En Solidity >= 0.8.x el compilador no advierte sobre esto -- requiere revisión manual"
  incidentes:
    - "Solodit #61406: EtherSpot CredibleAccountModule -- SessionData memory en validateUserOp, sd.live = false no persiste en storage, sesiones nunca se invalidan (CRITICAL)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit #61406 (EtherSpot Modular Accounts, Pashov/Cyfrin 2025)"
  tags: [session-key, memory-storage, state-update, Solidity-pitfall, never-expires]
  relacionado_con: [aa-005, aa-010]
```

---

## 4. Cross-Chain / Owner Management

```yaml
- id: aa-012
  pattern: remove-owner-cross-chain-index-replay
  name: "removeOwnerAtIndex replay cross-chain -- borra owner diferente por índice"
  causa_raiz: >
    CoinbaseSmartWallet permite removeOwnerAtIndex(index, owner) tanto via
    transacción directa como via executeWithoutChainIdValidation() (para operaciones
    que deben ser consistentes entre chains). Si un usuario usa ambos métodos en
    chains diferentes, el array de owners puede tener índices distintos en cada chain.
    Una llamada removeOwnerAtIndex en chain B remueve el owner EN ESE ÍNDICE de chain B,
    que puede ser diferente al owner en ese índice en chain A.
  como_funciona: |
    1. Chain A: owners = [keyA, keyB, keyC]. Usuario añade keyD on-chain.
    2. Chain B: usuarios usa executeWithoutChainIdValidation -- owners = [keyA, keyB] (diferente estado)
    3. Usuario quiere eliminar keyB (index=1) en ambas chains
    4. En chain A: removeOwnerAtIndex(1) elimina keyB ✓
    5. En chain B: removeOwnerAtIndex(1) elimina keyB ✓ (coincide aquí)
    6. Si los índices difieren: elimina owner equivocado, potencialmente el único owner → lockout
  invariante: >
    removeOwnerAtIndex(index, owner) DEBE requerir que owners[index] == owner
    como validación de seguridad. Nunca solo por índice.
  que_mirar:
    - "¿removeOwnerAtIndex verifica owners[index] == owner antes de eliminar?"
    - "¿executeWithoutChainIdValidation está disponible? ¿Qué ops permite?"
    - "¿El array de owners puede divergir entre chains por uso de ambos métodos?"
    - "¿Hay protección de last-owner (no eliminar si es el único)?"
  como_se_arregla: >
    Añadir: require(owners[index] == owner, 'owner mismatch').
    Esta verificación ya previene el bug: si el índice tiene un owner diferente, revierte.
    Añadir también: require(owners.length > 1, 'cannot remove last owner').
  trampas:
    - "Si el usuario solo usa un método (solo on-chain O solo executeWithoutChainId), los índices son consistentes y el bug no aplica"
    - "La severidad varía: puede ser desde confusión hasta lockout permanente si se elimina el último owner"
  incidentes:
    - "Solodit #32022: Coinbase SmartWallet -- removeOwnerAtIndex replay cross-chain elimina owner diferente en cada chain, combined con falta de last-owner guard puede causar lockout (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit #32022 (Code4rena 2024-03-coinbase)"
  tags: [owner-management, cross-chain, removeOwner, index, replay, lockout]
  relacionado_con: [aa-013]
```

```yaml
- id: aa-013
  pattern: userop-cross-chain-replay-missing-chainid
  name: "UserOperation replay cross-chain por chainId ausente en paymaster hash"
  causa_raiz: >
    EIP-4337 requiere que la firma del paymaster dependa del chainId para
    prevenir replay cross-chain. Si el paymaster calcula el hash de la
    UserOperation sin incluir chainId (o con chainId cacheado como immutable),
    la misma UserOp firmada en chain A puede ejecutarse en chain B donde el
    mismo paymaster está deployado con la misma dirección.
  como_funciona: |
    1. Paymaster en chain A firma UserOp: getHash omite chainId
    2. Usuario obtiene firma válida del paymaster para chain A
    3. Atacante replica la misma UserOp en chain B (mismo paymaster, misma dirección)
    4. Paymaster en chain B valida -- la firma verifica porque no hay chainId en el hash
    5. La UserOp se ejecuta en chain B sin autorización del paymaster de chain B
    6. Paymaster de chain B pierde depósito, usuario obtiene transacción gratis en chain B
  invariante: >
    getHash(userOp) del paymaster DEBE incluir block.chainid.
    La firma del paymaster no debe ser válida en ninguna otra chain.
  que_mirar:
    - "¿getHash() o _getHash() del paymaster incluye block.chainid o chainId?"
    - "¿DOMAIN_SEPARATOR del paymaster se calcula con chainId dinámico?"
    - "¿El paymaster está deployado en múltiples chains con la misma dirección?"
    - "Buscar: getHash sin chainId + paymaster multi-chain"
  como_se_arregla: >
    Incluir block.chainid en el hash: keccak256(abi.encode(block.chainid, sender, nonce, callData, ...)).
    O usar EIP-712 domain separator con chainId dinámico.
  trampas:
    - "Si el paymaster solo opera en una chain, el replay cross-chain no aplica en la práctica"
    - "Biconomy: el chainId también falta en el SmartAccount, no solo en el paymaster -- revisar ambos"
  incidentes:
    - "Solodit #6449: Biconomy VerifyingSingletonPaymaster -- getHash() omite chainId, UserOperation replayable en cualquier chain donde el paymaster esté deployado (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #6449 (Code4rena 2023-01-biconomy)"
  tags: [cross-chain, chainId, replay, paymaster, UserOperation, domain-separator]
  relacionado_con: [aa-012, sig-002]
```

---

## 5. SpendPermission (Coinbase-específico)

```yaml
- id: aa-014
  pattern: spend-permission-erc6492-drain
  name: "ERC-6492 execution path permite drain via ownerIndex manipulation"
  causa_raiz: >
    ERC-6492 define un path para validar firmas de wallets aún no deployados:
    si la verificación ERC-1271 falla, el contrato intenta deployar el wallet
    y re-verificar. SpendPermissionManager usa approveWithSignature() que
    sigue el path ERC-6492. Si la firma inicialmente falla, el contrato puede
    ser forzado a ejecutar initCode con parámetros del atacante, incluyendo
    ownerIndex manipulado que añade al atacante como owner del wallet víctima.
  como_funciona: |
    1. SpendPermissionManager tiene seteo como owner en el SmartWallet víctima
    2. El owner legítimo firma una approval para un spender
    3. Atacante llama approveWithSignature() con signature malformada
    4. ERC-6492 path: la verificación falla → se intenta deploy con initCode del atacante
    5. initCode manipula ownerIndex → añade atacante como owner del SmartWallet
    6. Atacante con owner role puede drenar todos los fondos del wallet
  invariante: >
    approveWithSignature() NUNCA debe ejecutar calldata arbitrario ni modificar
    la lista de owners como side effect de la verificación de firma.
  que_mirar:
    - "¿approveWithSignature sigue path ERC-6492 con deploy + retry?"
    - "¿El initCode en el path ERC-6492 puede ser suministrado por el atacante?"
    - "¿SpendPermissionManager tiene owner role en el wallet target?"
    - "Buscar: _erc6492_magic o ERC6492 en contratos de permiso/aprobación"
  como_se_arregla: >
    No usar el path de deploy de ERC-6492 en funciones de aprobación sensibles.
    Si se usa ERC-6492, validar que el initCode viene de una factory de confianza.
    Separar la verificación de firma del potencial deploy.
  trampas:
    - "ERC-6492 es legítimo para verificar firmas de wallets no deployados -- el bug está en qué side-effects se permiten durante la verificación"
    - "Si SpendPermissionManager NO es owner del wallet, el impacto es menor"
  incidentes:
    - "Solodit #41992: Coinbase SpendPermissionManager -- ERC-6492 path con ownerIndex manipulado permite al atacante añadirse como owner del SmartWallet víctima y drenar fondos (CRITICAL/HIGH)"
  severidad: critical
  confianza: media
  verificado: true
  fuente: "Solodit #41992 (Coinbase SpendPermission audit)"
  tags: [SpendPermission, ERC-6492, owner-manipulation, drain, Coinbase]
  relacionado_con: [aa-012, aa-015]
```

```yaml
- id: aa-015
  pattern: spend-permission-dos-manager-removed
  name: "DoS en SpendPermission cuando el manager es removido de owners"
  causa_raiz: >
    isApproved() verifica si un spend permission sigue válido, entre otras cosas
    verificando que SpendPermissionManager aún es owner del wallet. Si el usuario
    (o un atacante con acceso al wallet) remueve SpendPermissionManager de la
    lista de owners, isApproved() retorna false para TODOS los permisos de ese
    wallet, incluso los que fueron correctamente aprobados. Las DApps que usan
    isApproved() para pre-validar bloquean al usuario aunque el permiso sea válido.
  como_funciona: |
    1. Usuario (o atacante) llama removeOwner(SpendPermissionManager) en el wallet
    2. isApproved() internamente verifica isOwner(wallet, SpendPermissionManager)
    3. Retorna false para todos los permisos del wallet, independientemente de su estado
    4. DApps que llaman isApproved() antes de spend() bloquean las transacciones
    5. El usuario no puede gastar aunque tenga permisos válidos aprobados
  invariante: >
    isApproved() debe reflejar si el permiso fue aprobado y no revocado,
    independientemente del estado actual de owner del SpendPermissionManager.
    O documentar explícitamente que remover el manager invalida todos los permisos.
  que_mirar:
    - "¿isApproved() verifica isOwner(wallet, spendPermissionManager)?"
    - "¿Qué ocurre si SpendPermissionManager es removido como owner?"
    - "¿DApps pueden llamar isApproved() y bloquear spend() basándose en ello?"
    - "¿El protocolo documenta que el manager debe permanecer como owner?"
  como_se_arregla: >
    Separar la validación de ownership del SpendPermissionManager de la validación
    del permiso individual. O añadir un evento/flag cuando el manager es removido
    para que DApps puedan distinguir el caso. O validar en spend() directamente
    sin depender de isApproved() como pre-check.
  trampas:
    - "Si el usuario remueve el manager intencionalmente, podría ser 'by design' -- verificar spec"
    - "El DoS puede requerirse que el atacante controle el wallet -- verificar who can call removeOwner"
  incidentes:
    - "Solodit #46544: Coinbase SpendPermissionManager -- isApproved() retorna false cuando manager removido de owners, DoS para DApps que dependen de isApproved como pre-validación (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #46544 (Coinbase SpendPermission audit)"
  tags: [SpendPermission, DoS, isApproved, owner-removal, Coinbase]
  relacionado_con: [aa-014]
```

```yaml
- id: aa-016
  pattern: spend-permission-malicious-wallet-interface
  name: "Wallet malicioso con interfaz CoinbaseSmartWallet vacía roba fondos de apps"
  causa_raiz: >
    SpendPermissionManager._execute() llama CoinbaseSmartWallet(account).execute()
    asumiendo que account es un CoinbaseSmartWallet legítimo. Si se permite que
    cualquier contrato con la misma interfaz sea un "account", un atacante puede
    deployar un wallet malicioso cuyo execute() no transfiere fondos reales pero
    retorna éxito. La DApp cree haber cobrado al usuario, pero no recibió nada.
  como_funciona: |
    1. Atacante deploya MaliciousWallet con función execute() que no hace nada (o hace algo malicioso)
    2. DApp llama SpendPermissionManager.spend(maliciousWallet, ...) con un permiso
    3. _execute() llama MaliciousWallet.execute(target, value, data)
    4. execute() retorna éxito sin transferir tokens
    5. DApp cree haber cobrado; MaliciousWallet no transfirió nada
    6. DApp provee servicio gratis al operador del MaliciousWallet
  invariante: >
    SpendPermissionManager debe verificar que account es un CoinbaseSmartWallet
    desplegado por la factory oficial, no cualquier contrato con la misma interfaz.
  que_mirar:
    - "¿_execute() verifica que account fue deployado por una factory de confianza?"
    - "¿Hay whitelist de wallets o verificación de factory?"
    - "¿Se puede registrar cualquier dirección como account en SpendPermissionManager?"
    - "Buscar: CoinbaseSmartWallet(payable(account)).execute sin validación de account"
  como_se_arregla: >
    Verificar que account es un wallet legítimo: require(factory.isDeployed(account)).
    O verificar el bytecode hash del account contra el expected bytecode.
    O usar allowlist de wallets verificados.
  trampas:
    - "La DApp pierde dinero (servicio gratis), no el usuario -- evaluar si el bug scope incluye pérdida de la DApp"
    - "Requiere que el atacante pueda registrar un spend permission -- verificar quién puede hacer approve"
  incidentes:
    - "Solodit #46546: Coinbase SpendPermissionManager -- wallet malicioso con execute() vacío permite a apps ser robadas proveyendo servicios sin cobro (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit #46546 (Coinbase SpendPermission audit)"
  tags: [SpendPermission, malicious-wallet, interface-spoofing, factory, Coinbase]
  relacionado_con: [aa-014, aa-015]
```

---

## 6. Bundler

```yaml
- id: aa-017
  pattern: bundler-dos-insufficient-gas
  name: "DoS de UserOps por bundler malicioso con gas insuficiente"
  causa_raiz: >
    handleOps() en EntryPoint toma un parámetro de gas total para el bundle.
    Un bundler malicioso puede submitir un bundle con gas suficiente para pasar
    la validación pero insuficiente para la ejecución. El bundle falla, el usuario
    pierde el fee de preflight, y sus UserOps son descartadas. El bundler puede
    repetir esto indefinidamente contra usuarios objetivo.
  como_funciona: |
    1. Bundler malicioso incluye UserOps de usuarios objetivo en un bundle
    2. Submitir handleOps() con gasLimit que pasa la fase de validación (barato)
    3. La fase de ejecución (más cara) falla por out of gas
    4. Usuarios pagan preflight fee pero sus transacciones no se ejecutan
    5. Bundler repite el ataque: DoS selectivo a usuarios específicos
  invariante: >
    El bundler honesto debe proveer suficiente gas para ejecución completa.
    Protocolo-level: el EntryPoint debe compensar al usuario si el bundler
    provee gas insuficiente.
  que_mirar:
    - "¿El protocolo depende de bundlers de confianza o permisionless?"
    - "¿Hay mecanismo de compensación si handleOps falla por gas insuficiente?"
    - "¿El usuario pierde fees si el bundle falla?"
    - "En contexto de Coinbase: ¿usa bundlers propios (confianza alta) o externos?"
  como_se_arregla: >
    Usar bundlers de confianza (permissioned bundler set).
    En EntryPoint: añadir compensación al usuario si el bundler provee gas insuficiente.
    Fuera del alcance del contrato -- mitigación a nivel de infraestructura.
  trampas:
    - "Este ataque requiere bundler malicioso -- en ecosistemas con bundlers permissioned no aplica"
    - "La pérdida de fee puede ser pequeña -- evaluar si el protocolo tiene bundlers propios"
  incidentes:
    - "Solodit #6451: Biconomy EntryPoint -- bundler malicioso submitia bundle con gas insuficiente, DoS de UserOps y pérdida de fee del usuario (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit #6451 (Code4rena 2023-01-biconomy)"
  tags: [bundler, DoS, gas, handleOps, EntryPoint, permissionless]
  relacionado_con: [aa-002]
```

---

## Quick Grep Targets

```bash
# Paymaster
grep -r "address(this).balance" --include="*.sol"   # balance checks en paymaster
grep -r "postOp\|_postOp" --include="*.sol"         # lógica de cobro post-ejecución
grep -r "_gasMaxCostExcess\|gasExcess" --include="*.sol"  # double-withdrawal
grep -r "validatePaymasterUserOp" --include="*.sol"  # entry points del paymaster

# validateUserOp
grep -r "validateUserOp" --include="*.sol"           # todos los validators
grep -r "ECDSA.tryRecover\|ecrecover" --include="*.sol"  # sin check address(0)
grep -rn "memory sd\|memory session\|memory lock" --include="*.sol"  # memory/storage bug
grep -r "function validate.*public" --include="*.sol"  # funciones de validación públicas

# Session Keys
grep -r "sessionData\|sessionKey\|SessionData" --include="*.sol"
grep -r "\.live\|\.active\|\.consumed" --include="*.sol"  # state flags de sesión

# Cross-chain
grep -r "executeWithoutChainIdValidation\|removeOwnerAtIndex" --include="*.sol"
grep -r "chainId\|block.chainid" --include="*.sol"  # verificar presencia en hashes

# SpendPermission (Coinbase)
grep -r "SpendPermissionManager\|isApproved\|approveWithSignature" --include="*.sol"
grep -r "ERC6492\|_erc6492\|6492" --include="*.sol"
grep -r "CoinbaseSmartWallet.*execute\|factory.isDeployed" --include="*.sol"
```

## Fuzzing Priorities

```
HIGH VALUE para invariants:
1. paymaster.balance >= sum(gasMaxCostExcess pendiente) -- double-withdrawal
2. session.live == false después de cualquier consume/validateUserOp
3. owners[index] == owner antes de removeOwnerAtIndex
4. validateUserOp solo callable por address(entryPoint)
5. approveWithSignature no modifica owners[] como side effect

HANDLERS críticos:
- validateUserOp(userOp, userOpHash) -- probar con userOpHash != hash(userOp)
- removeOwnerAtIndex(i, wrongOwner) -- ¿revierte? ¿elimina el wrong owner?
- claim(sessionKeyDeOtro) -- ¿puede consumir sesión ajena?
- withdrawGasExcess() dos veces seguidas -- double-withdrawal
```
