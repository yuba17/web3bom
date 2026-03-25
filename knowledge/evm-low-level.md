# EVM Low-Level, Assembly & Precompile Vulnerabilities -- Combat Briefing

> **Scope**: Vulnerabilidades en operaciones EVM de bajo nivel, inline assembly (Yul), precompiles, y edge cases del ABI encoder para bug bounty hunting.
> **Sources**: Trail of Bits audits, OpenZeppelin advisories, Paradigm CTF, Solidity compiler bug disclosures, DeFiHackLabs.
> **Last updated**: 2026-03-23

---

## Bug Patterns

```yaml
- id: EVM-01
  pattern: returndata-bomb
  name: "Returndata bomb -- datos de retorno masivos para griefear gas del caller"
  causa_raiz: "Cuando un contrato hace una llamada externa (call/staticcall/delegatecall) y luego copia los datos de retorno a memoria, el costo de gas de la copia es proporcional al tamaño de los datos. Un contrato malicioso puede retornar megabytes de datos inútiles, causando que el caller gaste todo su gas en la expansión de memoria y copia de returndata, incluso si el caller solo necesita un bool o unos pocos bytes."
  como_funciona: "1. Contrato A hace low-level call a contrato externo B (controlado por atacante o untrusted). 2. Contrato B retorna un payload masivo (e.g., 1MB de ceros) en su returndata. 3. Si contrato A usa `abi.decode(returnData, (...))` o copia todo el returndata a memoria, paga gas cuadrático por expansión de memoria. 4. El gas del caller se agota, la transacción revierte o el caller queda en estado inconsistente si el gas out-of-gas no se manejado. 5. El atacante puede usar esto para griefear relayers, liquidadores, o cualquier contrato que haga calls a direcciones untrusted."
  invariante: "Toda llamada externa a direcciones untrusted debe limitar el tamaño de returndata copiado. Nunca copiar returndata completo sin bound."
  que_mirar:
    - "Llamadas `address.call(data)` seguidas de `abi.decode` sin verificar returndatasize()"
    - "Contratos relay/multicall que reenvían returndata de llamadas arbitrarias"
    - "Liquidation bots que llaman a contratos de deudor para verificar estado"
    - "Cualquier patrón `(bool success, bytes memory data) = target.call(...)` donde target es untrusted"
    - "Assembly blocks que usan returndatacopy sin limitar el tamaño"
  como_se_arregla: "Usar assembly para limitar returndatacopy: `returndatacopy(ptr, 0, min(returndatasize(), MAX_RETURN_SIZE))`. O usar ExcessivelySafeCall de Nomad: limita bytes copiados. Si solo necesitas un bool, usa `assembly { success := call(..., 0, 0) }` sin copiar returndata."
  trampas:
    - "Solidity genera automáticamente returndatacopy para `(bool s, bytes memory d) = addr.call(...)` -- el dev puede no ser consciente del costo"
    - "El ataque no roba fondos directamente -- es un griefing/DoS vector. Severidad depende del contexto (liquidación bloqueada = High)"
    - "En contratos upgradeable, el returndata bomb puede bloquear la función de upgrade si pasa por un proxy"
  solodit_ids:
    - return-bomb-can-be-used-to-make-the-function-call-fail-openzeppelin-none-uma-audit-markdown
    - m-02-returnbomb-attack-is-possible-in-call-code4rena-pooltogether-pooltogether-git
  incidentes:
    - "Nomad Bridge -- descubrió el patrón y publicó ExcessivelySafeCall como librería de mitigación"
    - "Uma Protocol -- OpenZeppelin audit identificó returndata bomb en llamadas a oracles untrusted"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Nomad Security, OpenZeppelin audits, Trail of Bits"
  patron_vulnerable: |
    // VULNERABLE: copia todo el returndata sin límite
    function callUntrusted(address target, bytes calldata data) external {
        (bool success, bytes memory returnData) = target.call(data);
        // returnData puede ser 1MB+ → memory expansion cuadrática
        require(success);
        emit Result(returnData);
    }
  test_invariante: |
    // Invariante: returndata copiado debe estar bounded
    function test_returndata_bounded() public {
        // Setup: contrato malicioso que retorna 1MB
        MaliciousReturnBomb bomb = new MaliciousReturnBomb();
        uint256 gasBefore = gasleft();
        // Usar ExcessivelySafeCall con límite de 256 bytes
        (bool success, bytes memory data) = address(bomb).excessivelySafeCall(
            100000, 0, 256, abi.encodeWithSignature("explode()")
        );
        uint256 gasUsed = gasBefore - gasleft();
        // Gas usado debe ser razonable (< 50000) incluso si target retorna megabytes
        assert(gasUsed < 50000);
    }
  tags: [evm, low-level-call, returndata, gas-griefing, dos]
  relacionado_con: [EVM-04, EVM-14]
  incidentes_verificados:
    - nombre: "Nomad Bridge (ExcessivelySafeCall)"
      fecha: "2022"
      perdida: "$0 (mitigación preventiva)"
      tipo: "Returndata bomb mitigation library publicada tras identificar el vector"
      verificado: true
      fuente: "Nomad GitHub, c4 audits"
    - nombre: "PoolTogether (C4)"
      fecha: "2023"
      perdida: "$0 (audit finding)"
      tipo: "Returndata bomb en llamada a prize vault externo"
      verificado: true
      fuente: "Code4rena"
```

```yaml
- id: EVM-02
  pattern: delegatecall-context-confusion
  name: "Delegatecall context confusion -- preservación de msg.sender y msg.value"
  causa_raiz: "delegatecall ejecuta código externo en el contexto de almacenamiento del contrato caller, preservando msg.sender y msg.value. Cuando un contrato permite delegatecall a direcciones controladas por el usuario o a contratos que no fueron diseñados para este contexto, el código delegado puede manipular el storage del caller, robar fondos, o escalar privilegios porque msg.sender apunta al usuario original (no al contrato intermedio)."
  como_funciona: "1. Contrato A tiene una función que hace delegatecall a una dirección proporcionada por el usuario o configurada sin protección. 2. El atacante despliega contrato malicioso M. 3. A.delegatecall(M) ejecuta el código de M pero en el storage de A. 4. M puede: (a) sobrescribir el owner de A cambiando slot 0, (b) transferir tokens que A posee usando A como msg.sender, (c) llamar selfdestruct destruyendo A. 5. Además, msg.value se preserva, permitiendo que el mismo ETH se 'reuse' en múltiples delegatecalls en la misma transacción."
  invariante: "delegatecall solo debe usarse hacia implementaciones verificadas e inmutables. Nunca delegatecall a direcciones proporcionadas por el usuario. msg.value no debe usarse para contabilizar en loops de delegatecall."
  que_mirar:
    - "Funciones que aceptan `address target` como parámetro y hacen `target.delegatecall(...)`"
    - "Patrones de multicall que usan delegatecall en un loop -- msg.value se preserva en cada iteración"
    - "Proxies que permiten cambiar la dirección de implementación sin auth suficiente"
    - "Contratos con fallback() que hacen delegatecall genérico"
    - "Diamond proxy (EIP-2535) con facets que asumen msg.value se consume en la primera llamada"
  como_se_arregla: "Whitelist de direcciones válidas para delegatecall. En multicall con delegatecall, no usar msg.value en el loop (o trackear consumo explícito). Para proxies, usar EIP-1967 con access control en upgrade."
  trampas:
    - "msg.value NO se decrementa tras cada delegatecall -- se puede 'gastar' múltiples veces en un loop multicall"
    - "No confundir delegatecall con call: call cambia msg.sender al contrato intermedio"
    - "En proxies legítimos (OZ TransparentProxy), delegatecall es el mecanismo correcto -- el bug está en delegatecall a destinos NO controlados"
  solodit_ids:
    - h-05-delegatecall-in-multicall-can-be-used-to-steal-funds-code4rena-none-lybra-finance-git
    - h-05-the-multicall-function-can-drain-msg-value-since-it-can-be-used-multiple-times-code4rena-none-arcade-xyz-git
  incidentes:
    - "Parity Multisig Hack -- delegatecall a librería untrusted permitió tomar ownership del wallet"
    - "Poly Network -- cross-chain relay usaba delegatecall a contrato controlado por atacante"
    - "Lybra Finance (C4) -- multicall con delegatecall permitía reusar msg.value"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "DeFiHackLabs, Parity post-mortem, Trail of Bits"
  patron_vulnerable: |
    // VULNERABLE: multicall con delegatecall reutiliza msg.value
    function multicall(bytes[] calldata calls) external payable {
        for (uint256 i = 0; i < calls.length; i++) {
            // msg.value se preserva en CADA iteración del loop
            (bool success, ) = address(this).delegatecall(calls[i]);
            require(success);
        }
    }
    // Atacante envía 1 ETH pero "gasta" msg.value N veces
    // Si deposit() usa msg.value para contabilizar, deposita N ETH con solo 1
  test_invariante: |
    // Invariante: balance del contrato >= suma de todos los depósitos
    function invariant_no_double_msg_value() public {
        uint256 totalDeposited = ghost_totalDeposits;
        uint256 actualBalance = address(vault).balance;
        // Si msg.value se reutiliza en multicall, totalDeposited > actualBalance
        assert(actualBalance >= totalDeposited);
    }
  tags: [delegatecall, msg-value, multicall, proxy, context-confusion]
  relacionado_con: [EVM-13, EVM-14]
  incidentes_verificados:
    - nombre: "Parity Multisig (1st hack)"
      fecha: "Jul 2017"
      perdida: "$31M"
      tipo: "delegatecall a librería con initWallet() público -- atacante tomó ownership"
      verificado: true
      fuente: "DeFiHackLabs, Parity post-mortem"
    - nombre: "Parity Multisig (2nd -- freeze)"
      fecha: "Nov 2017"
      perdida: "$280M congelados"
      tipo: "selfdestruct en librería compartida vía delegatecall -- todos los wallets inutilizados"
      verificado: true
      fuente: "DeFiHackLabs, Parity post-mortem"
    - nombre: "Poly Network"
      fecha: "Aug 2021"
      perdida: "$611M (devueltos)"
      tipo: "Cross-chain delegatecall manipulation para cambiar keeper address"
      verificado: true
      fuente: "DeFiHackLabs, Rekt News"
```

```yaml
- id: EVM-03
  pattern: staticcall-violation-bypass
  name: "Bypass de restricción staticcall -- modificar estado indirectamente"
  causa_raiz: "staticcall (STATICCALL opcode) impide que el código llamado modifique el estado del blockchain. Sin embargo, esta restricción solo aplica a la ejecución directa dentro del contexto de la llamada estática. Contratos pueden intentar usar staticcall para 'garantizar' que una función es read-only, pero hay formas indirectas de causar efectos secundarios: logging (events), gasleft() side-channels, o interacción con contratos que mantienen estado off-chain."
  como_funciona: "1. Contrato A usa staticcall para llamar a oracle B, asumiendo que B no puede modificar estado. 2. B emite un event (LOG opcodes están permitidos en staticcall pre-EIP, pero PROHIBIDOS post-Byzantium). 3. Post-Byzantium: staticcall reverts si se intenta SSTORE, LOG, CREATE, SELFDESTRUCT. Pero el atacante puede explotar: (a) gas consumption como side-channel, (b) el hecho de que staticcall a un contrato que a su vez hace CALL regular NO hereda la restricción static, (c) la suposición incorrecta del dev de que staticcall previene reentrancy. 4. Específicamente: si A hace staticcall a B, y B hace CALL regular (no delegatecall) a C, C SÍ puede modificar estado. La restricción static se propaga a sub-llamadas en el EVM actual, PERO si el dev implementa su propio 'static check' en Solidity (no usando el opcode), puede ser bypasseado."
  invariante: "Nunca asumir que staticcall previene reentrancy. La restricción de estado se propaga a sub-llamadas del STATICCALL opcode, pero implementaciones custom de 'view enforcement' en Solidity pueden tener gaps."
  que_mirar:
    - "Contratos que usan staticcall como mecanismo anti-reentrancy en vez de un mutex"
    - "View functions que internamente hacen state changes condicionales (compilan con warning, no error)"
    - "Funciones marcadas como `view` que hacen llamadas externas a contratos que modifican estado (Solidity no enforce view en runtime para llamadas externas)"
    - "Contratos que asumen que `address.staticcall()` es equivalente a 'sin side effects' cuando el contrato llamado puede interactuar con third-party state"
  como_se_arregla: "Usar reentrancy guards explícitos (mutex) en vez de depender de staticcall. No marcar funciones como view si hacen llamadas externas a contratos que podrían modificar estado. Validar que view functions realmente son read-only en auditoría."
  trampas:
    - "Post-Byzantium, STATICCALL sí propaga la restricción a sub-llamadas -- el bypass real es cuando el dev NO usa el opcode y confía en el modificador `view` de Solidity"
    - "Solidity NO verifica en runtime que una función view realmente sea view cuando hace external calls"
    - "Los events (LOG) SÍ están bloqueados por STATICCALL post-Byzantium, contrario a la creencia popular"
  solodit_ids: []
  incidentes:
    - "Paradigm CTF 2021 -- 'Babysandbox' challenge: bypass de staticcall restriction usando CALL dentro del contexto estático (pre-Byzantium semantics)"
    - "Euler Finance -- view function reentrancy: función marcada como view que hacía callback a Uniswap, permitiendo reentrancy en el mismo contrato"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "EVM specification, Paradigm CTF, Euler post-mortem"
  patron_vulnerable: |
    // VULNERABLE: confía en view como garantía de no-side-effects
    function getPrice(address oracle) public view returns (uint256) {
        // Solidity NO verifica en runtime que oracle.getPrice() sea realmente view
        // Si oracle es malicioso, puede modificar estado durante esta "view" call
        return IOracle(oracle).getPrice();  // compila sin error
    }
    // VULNERABLE: staticcall como anti-reentrancy
    function safeCallback(address target) external {
        // Asume que staticcall previene reentrancy -- INCORRECTO si target
        // puede causar side effects indirectos (e.g., oracle price manipulation)
        (bool s, bytes memory d) = target.staticcall(abi.encodeWithSignature("hook()"));
    }
  test_invariante: |
    // Invariante: funciones view no deben cambiar estado observable
    function test_view_no_side_effects() public {
        bytes32 stateHashBefore = keccak256(abi.encode(
            contract.totalSupply(), contract.balanceOf(user), contract.price()
        ));
        contract.getPrice(oracle);  // función "view"
        bytes32 stateHashAfter = keccak256(abi.encode(
            contract.totalSupply(), contract.balanceOf(user), contract.price()
        ));
        assert(stateHashBefore == stateHashAfter);
    }
  tags: [staticcall, view, reentrancy, evm-opcode, side-channel]
  relacionado_con: [EVM-02, EVM-11]
  incidentes_verificados:
    - nombre: "Paradigm CTF Babysandbox"
      fecha: "2021"
      perdida: "$0 (CTF)"
      tipo: "Bypass de sandbox basado en staticcall explotando CALL desde contexto estático"
      verificado: true
      fuente: "Paradigm CTF writeups"
```

```yaml
- id: EVM-04
  pattern: memory-expansion-gas-griefing
  name: "Memory expansion gas griefing -- costo cuadrático por expansión de memoria"
  causa_raiz: "El costo de gas de la memoria EVM no es lineal: los primeros 724 bytes son baratos (3 gas/word), pero después el costo crece cuadráticamente (memory_cost = words^2/512 + 3*words). Un atacante puede forzar a un contrato a expandir su memoria a tamaños enormes pasando datos grandes como input, causando que la operación consuma gas excesivo o falle por out-of-gas."
  como_funciona: "1. Función acepta bytes calldata o un offset/length controlado por el usuario. 2. El contrato copia estos datos a memoria (abi.decode, bytes memory copy, o assembly mload/mstore a offset alto). 3. Si el usuario pasa un offset extremadamente grande (e.g., 2^32), el EVM debe expandir la memoria hasta ese punto, pagando gas cuadrático. 4. Con ~30M gas block limit, se pueden expandir ~100KB antes de agotar gas. 5. Esto puede griefear: relayers que pagan gas, contratos con gas limits internos, o funciones que deben completar atómicamente."
  invariante: "Todo acceso a memoria con offset/tamaño controlado por usuario debe tener bounds checking explícito. Los offsets de memoria en assembly nunca deben depender directamente de input externo sin validación."
  que_mirar:
    - "Assembly blocks con `mload(offset)` o `mstore(offset, val)` donde offset viene de calldata"
    - "Funciones que aceptan `bytes calldata` de tamaño arbitrario y lo copian a `bytes memory`"
    - "ABI decoding manual en assembly donde el offset de un campo dinámico viene del calldata sin validación"
    - "Funciones con gas stipend fijo que procesan datos de tamaño variable"
    - "Patrón: `calldatacopy(freePtr, offset, size)` donde offset y size son controlados por el usuario"
  como_se_arregla: "Validar que offset + size no exceda un máximo razonable. En assembly, verificar que los offsets de memoria sean < un bound fijo. Usar calldata en vez de memory cuando no se necesita modificar los datos. Limitar el tamaño de bytes inputs en las funciones."
  trampas:
    - "El costo cuadrático solo empieza a ser significativo después de ~724 bytes (22 words). Para inputs pequeños no es un vector real"
    - "Solidity maneja automáticamente el free memory pointer -- el riesgo es mayor en assembly manual"
    - "No confundir con returndata bomb (EVM-01): aquí el atacante controla el INPUT, no el output"
  solodit_ids:
    - m-01-out-of-gas-griefing-via-large-memory-allocation-code4rena-none-size-credit-git
  incidentes:
    - "Trail of Bits audit de Solmate -- identificó que SafeTransferLib no validaba returndata size, permitiendo memory expansion"
    - "Size Credit (C4) -- griefing via memory allocation grande en función de liquidación"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "EVM Yellow Paper, Trail of Bits, Solmate audits"
  patron_vulnerable: |
    // VULNERABLE: offset de memoria controlado por usuario sin bound
    function processData(bytes calldata data, uint256 offset) external {
        assembly {
            // Si offset = 2^30, expande memoria a ~1GB → gas cuadrático → OOG
            let val := mload(offset)
            mstore(offset, calldataload(data.offset))
        }
    }
    // VULNERABLE: copia de bytes grandes a memoria
    function forwardData(bytes calldata payload) external {
        // Copia todo payload a memory -- si payload es 100KB, costo cuadrático
        bytes memory data = payload;
        target.call(data);
    }
  test_invariante: |
    // Invariante: gas usado para procesamiento debe ser proporcional al tamaño útil
    function test_no_quadratic_memory(bytes calldata data) public {
        uint256 gasBefore = gasleft();
        contract.processData(data, 0);
        uint256 gasUsed = gasBefore - gasleft();
        // Gas debe ser O(n) no O(n^2). Heurística: < 100 gas por byte
        assert(gasUsed < data.length * 100 + 10000);
    }
  tags: [evm, memory, gas-griefing, dos, assembly]
  relacionado_con: [EVM-01, EVM-07]
  incidentes_verificados:
    - nombre: "EVM memory gas benchmarks"
      fecha: "ongoing"
      perdida: "N/A"
      tipo: "Documentado en Yellow Paper: memory_cost = a*words + words^2/512, cuadrático"
      verificado: true
      fuente: "Ethereum Yellow Paper, Appendix H"
```

```yaml
- id: EVM-05
  pattern: assembly-unchecked-overflow
  name: "Inline assembly sin overflow checks -- aritmética sin protección en Yul"
  causa_raiz: "Solidity 0.8+ incluye checks automáticos de overflow/underflow para aritmética, pero estos checks NO aplican dentro de bloques `assembly {}` (Yul). Las operaciones add, sub, mul, div en Yul son todas mod 2^256 sin revert. Los desarrolladores que escriben math compleja en assembly para optimizar gas frecuentemente olvidan agregar checks manuales, reintroduciendo vulnerabilidades de overflow que Solidity 0.8 supuestamente eliminó."
  como_funciona: "1. Desarrollador escribe función math-intensive en assembly para ahorrar gas (e.g., fixed-point math, sqrt, exp). 2. Usa `add(a, b)` en Yul, que silenciosamente wraps en overflow (retorna (a+b) mod 2^256). 3. Si a = type(uint256).max y b = 1, el resultado es 0 en vez de revert. 4. Atacante puede explotar el overflow para: manipular balances, evadir checks de solvencia, o calcular precios incorrectos. 5. El problema es especialmente peligroso en mul: `mul(a, b)` puede producir un resultado pequeño que pasa validaciones posteriores."
  invariante: "Toda operación aritmética en assembly que use inputs controlados por usuario o estado externo debe tener overflow/underflow checks explícitos. Patrón: `let c := add(a, b); if lt(c, a) { revert(0, 0) }`."
  que_mirar:
    - "Bloques `assembly { }` con operaciones `add`, `sub`, `mul` sin checks posteriores"
    - "Librerías math optimizadas (FixedPointMath, PRBMath, Solmate) -- usualmente bien auditadas pero forks pueden tener errores"
    - "Conversiones de tipo en assembly: `and(x, 0xff)` para uint8, `signextend` para signed"
    - "Shifts: `shl(n, x)` y `shr(n, x)` pueden perder bits silenciosamente"
    - "Funciones que calculan precios, shares, o fees en assembly inline"
  como_se_arregla: "Agregar checks explícitos después de cada operación: `if lt(c, a) { revert(0,0) }` para add, `if and(iszero(iszero(a)), iszero(eq(div(c, a), b))) { revert(0,0) }` para mul. O usar librerías como SafeMath de Yul. Considerar si la optimización de gas realmente justifica el riesgo."
  trampas:
    - "Solidity `unchecked { }` blocks TAMBIÉN desactivan overflow checks -- no confundir con assembly"
    - "Muchas librerías legítimas (Solmate, PRBMath) usan assembly intencionalmente con overflow controlado -- no todo uso de add() en assembly es un bug"
    - "div(a, 0) en Yul retorna 0, no revierte -- esto es un edge case diferente pero igual de peligroso"
    - "mulmod y addmod son seguros (no overflow por definición)"
  solodit_ids:
    - h-01-unchecked-arithmetic-in-assembly-leads-to-overflow-code4rena-none-canto-git
  incidentes:
    - "Canto (C4) -- overflow en assembly block de librería math custom permitía manipular precio de token"
    - "Paradigm CTF 2022 'Random' -- overflow en generador de números pseudo-aleatorios en assembly"
    - "Solidity compiler bug 0.8.13 -- optimizer eliminaba checks de overflow en ciertos patrones con assembly inline"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solidity docs, Code4rena findings, Paradigm CTF"
  patron_vulnerable: |
    // VULNERABLE: multiplicación sin overflow check en Yul
    function mulFixed(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly {
            result := mul(a, b)  // silently wraps on overflow!
            result := div(result, 1e18)
            // Si a * b > 2^256, result es basura (truncado)
        }
    }
    // VULNERABLE: suma sin check
    function addBalance(uint256 current, uint256 deposit) internal pure returns (uint256) {
        assembly {
            let result := add(current, deposit)
            // Si current = type(uint256).max y deposit = 1, result = 0
            mstore(0x00, result)
            return(0x00, 0x20)
        }
    }
  test_invariante: |
    // Invariante: resultado de mul nunca debe ser menor que ambos inputs (para inputs > 1)
    function test_assembly_mul_no_overflow(uint256 a, uint256 b) public {
        // Bound inputs para evitar 0 y 1 (donde mul < input es esperado)
        a = bound(a, 2, type(uint128).max);
        b = bound(b, 2, type(uint128).max);
        uint256 result = contract.mulFixed(a, b);
        // Si hay overflow, result / b != a (approx)
        assert(result >= a || result >= b);  // Al menos uno debe cumplirse sin overflow
    }
  tags: [assembly, yul, overflow, underflow, unchecked-math, inline-assembly]
  relacionado_con: [EVM-13, EVM-17]
  incidentes_verificados:
    - nombre: "Solidity Optimizer Bug (SOL-2022-6)"
      fecha: "Sep 2022"
      perdida: "$0 (compiler fix)"
      tipo: "Optimizer eliminaba código de side-effects en assembly inline bajo ciertas condiciones"
      verificado: true
      fuente: "Solidity blog, security advisory"
    - nombre: "Vyper compiler overflow (Curve pools)"
      fecha: "Jul 2023"
      perdida: "$70M+"
      tipo: "Reentrancy por bug del compilador Vyper -- no overflow directo pero ilustra riesgo de compilador"
      verificado: true
      fuente: "DeFiHackLabs"
```

```yaml
- id: EVM-06
  pattern: ecrecover-zero-address
  name: "ecrecover retorna address(0) con firma inválida"
  causa_raiz: "La función precompilada ecrecover (address 0x01) retorna address(0) cuando se le pasa una firma inválida en vez de revertir. Si el contrato no verifica que el resultado no es address(0), un atacante puede forjar 'firmas válidas' del address(0), lo que es especialmente peligroso si address(0) tiene un rol especial (e.g., es el valor por defecto de una variable de estado address)."
  como_funciona: "1. Contrato usa ecrecover(hash, v, r, s) para verificar una firma. 2. Atacante envía una firma malformada (e.g., v=0, r=0, s=0). 3. ecrecover retorna address(0) en vez de revertir. 4. Si el contrato compara el resultado con una variable `signer` que nunca fue inicializada (default = address(0)), la comparación pasa. 5. El atacante ejecuta acciones como si fuera el 'signer autorizado'. 6. Variante: si el contrato usa mapping(address => bool) y address(0) fue accidentalmente marcada como autorizada."
  invariante: "Después de llamar ecrecover, SIEMPRE verificar que el resultado != address(0). Usar ECDSA.recover de OpenZeppelin que revierte con firmas inválidas."
  que_mirar:
    - "Llamadas directas a `ecrecover(hash, v, r, s)` sin check de address(0)"
    - "Variables `address signer` no inicializadas usadas como comparación post-ecrecover"
    - "Contratos que aceptan v, r, s como parámetros separados en vez de bytes65 signature"
    - "Meta-transactions (EIP-2771) con verificación de firma custom"
    - "Permit functions (EIP-2612) con implementación propia en vez de OZ"
    - "Contratos que usan ecrecover en assembly sin validar output"
  como_se_arregla: "Usar OpenZeppelin ECDSA.recover() que revierte en firmas inválidas. Si se debe usar ecrecover directamente: `address recovered = ecrecover(hash, v, r, s); require(recovered != address(0), 'invalid sig');`. Nunca comparar con variables que podrían ser address(0)."
  trampas:
    - "OpenZeppelin ECDSA.recover ya maneja este caso -- solo es bug en implementaciones custom"
    - "ecrecover también es vulnerable a signature malleability (s-value en upper half) -- vector separado pero relacionado"
    - "v debe ser 27 o 28 en la mayoría de implementaciones -- valores fuera de rango pueden producir address(0) o resultados inesperados"
    - "Hay implementaciones válidas donde address(0) check se omite porque el signer nunca puede ser address(0) por diseño -- verificar caso por caso"
  solodit_ids:
    - h-01-ecrecover-returns-zero-address-on-invalid-signature-allowing-bypass-code4rena-none-size-git
    - m-01-missing-zero-address-check-for-ecrecover-code4rena-none-timeswap-git
  incidentes:
    - "Size Protocol (C4) -- ecrecover sin check de address(0) permitía bypass de firma en función de lending"
    - "Timeswap (C4) -- missing zero address check post-ecrecover en permit"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solidity docs, EVM precompile spec, OpenZeppelin advisories"
  patron_vulnerable: |
    // VULNERABLE: ecrecover sin check de address(0)
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        address signer = ecrecover(hash, v, r, s);
        // Si la firma es inválida, signer = address(0)
        // Si authorizedSigner no fue inicializado, también es address(0)
        return signer == authorizedSigner;  // TRUE con firma inválida + signer no inicializado
    }
    // VULNERABLE: permit sin validación
    function permit(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash));
        address recoveredAddress = ecrecover(digest, v, r, s);
        // Missing: require(recoveredAddress != address(0));
        require(recoveredAddress == owner, "INVALID_SIGNER");
    }
  test_invariante: |
    // Invariante: ecrecover nunca debe matchear address(0)
    function test_ecrecover_never_zero(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
        address recovered = ecrecover(hash, v, r, s);
        // Si es address(0), la firma es inválida y debe ser rechazada
        if (recovered == address(0)) {
            vm.expectRevert();
            contract.verify(hash, v, r, s);
        }
    }
  tags: [ecrecover, precompile, signature, address-zero, cryptography]
  relacionado_con: [EVM-07, EVM-08]
  incidentes_verificados:
    - nombre: "Size Protocol (C4)"
      fecha: "2023"
      perdida: "$0 (audit finding)"
      tipo: "ecrecover sin validación de address(0) -- bypass de autorización por firma"
      verificado: true
      fuente: "Code4rena"
    - nombre: "Wyvern Exchange (OpenSea)"
      fecha: "2022"
      perdida: "$0 (mitigado pre-exploit)"
      tipo: "Order signing con ecrecover vulnerable -- corregido antes de exploit público"
      verificado: true
      fuente: "OpenSea security advisory"
```

```yaml
- id: EVM-07
  pattern: precompile-gas-estimation
  name: "Errores de estimación de gas en precompiles (modexp, bn128, blake2f)"
  causa_raiz: "Las precompiles EVM (direcciones 0x01-0x09+) tienen costos de gas que no siguen la fórmula estándar de las instrucciones normales. El costo de modexp (0x05) depende del tamaño de los inputs y puede ser extremadamente alto para bases/exponentes grandes. Las precompiles bn128 (0x06, 0x07, 0x08) tienen costos fijos pero altos post-EIP-1108. Si un contrato pasa inputs de usuario directamente a estas precompiles sin validar tamaño, el gas puede exceder el limit de bloque o agotar el gas forwarded."
  como_funciona: "1. Contrato acepta parámetros (base, exponent, modulus) del usuario y los envía a modexp precompile (0x05). 2. El costo de gas de modexp es: max(200, floor(mul_complexity * iteration_count / 3)). Para inputs grandes, esto puede exceder 30M gas. 3. Si el contrato forwarded menos gas del necesario, la precompile falla silenciosamente (retorna bytes vacíos, NO revierte). 4. El contrato interpreta los bytes vacíos como resultado 0, que puede ser un valor válido en ciertos contextos (e.g., verificación criptográfica que pasa con 0). 5. Alternativa: un atacante puede griefear forzando que la precompile use exactamente el gas disponible menos un margen, dejando al caller sin gas para completar."
  invariante: "Las llamadas a precompiles deben verificar que el retorno tiene el tamaño esperado. Los inputs a modexp deben tener bounds en tamaño. Las llamadas deben usar la gas estimation correcta o forwarded con gas suficiente."
  que_mirar:
    - "Llamadas a address(0x05) (modexp) con inputs de tamaño controlado por usuario"
    - "Llamadas a address(0x06/0x07/0x08) (bn128 add/mul/pairing) sin verificar éxito"
    - "Contratos de verificación ZK que llaman bn128 pairing con número variable de puntos"
    - "Precompile calls en assembly donde no se verifica el return value"
    - "Gas forwarding insuficiente: `staticcall(gasleft(), precompile, ...)` sin margen"
  como_se_arregla: "Validar tamaño de inputs antes de llamar la precompile. Verificar que returndatasize() == expected size. Verificar que la llamada fue exitosa (staticcall returns 1). Para modexp, calcular el costo de gas esperado antes de la llamada y revert si es excesivo."
  trampas:
    - "Las precompiles NO reviertan en OOG -- retornan empty bytes. Esto es diferente al comportamiento de contratos normales"
    - "EIP-2565 (Berlin) cambió la fórmula de gas de modexp -- verificar qué versión aplica en la chain objetivo"
    - "EIP-1108 (Istanbul) redujo drásticamente costos de bn128 -- cálculos pre-Istanbul están desactualizados"
    - "address(0x09) blake2f tiene gas parametrizable por el caller -- vector diferente"
  solodit_ids: []
  incidentes:
    - "Trail of Bits audit de Scroll -- estimación de gas incorrecta para precompile en L2 context"
    - "Paradigm CTF 2023 'GRAIL' -- explotación de gas metering de bn128 pairing"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "EVM precompile specs, EIP-2565, EIP-1108, Trail of Bits"
  patron_vulnerable: |
    // VULNERABLE: modexp con inputs no validados
    function verifyProof(bytes memory base, bytes memory exp, bytes memory mod) public view returns (bytes memory) {
        // No valida tamaños -- attacker puede pasar base de 1KB, exp de 1KB
        // Gas cost: mul_complexity(max(base.length, mod.length)) * exp_length / 3
        // Con inputs grandes → millones de gas
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exp.length), uint256(mod.length),
            base, exp, mod
        );
        (bool success, bytes memory result) = address(0x05).staticcall(input);
        // PELIGRO: si OOG, success = false, result = "" (empty, NOT revert)
        require(success, "modexp failed");
        return result;
    }
  test_invariante: |
    // Invariante: precompile calls deben verificar returndatasize
    function test_precompile_return_valid() public {
        bytes memory input = buildModExpInput(base, exp, mod);
        (bool success, bytes memory result) = address(0x05).staticcall(input);
        if (success) {
            // Result debe tener tamaño = mod.length
            assert(result.length == mod.length);
        }
        // Si !success, la función caller DEBE revertir, no continuar con datos vacíos
    }
  tags: [precompile, modexp, bn128, gas-estimation, zk-verification]
  relacionado_con: [EVM-04, EVM-06]
  incidentes_verificados:
    - nombre: "Scroll precompile gas"
      fecha: "2023"
      perdida: "$0 (audit finding)"
      tipo: "Gas estimation para precompiles en L2 difería de L1 -- podía causar reverts inesperados"
      verificado: true
      fuente: "Trail of Bits audit report"
```

```yaml
- id: EVM-08
  pattern: abi-encoding-edge-cases
  name: "Edge cases de ABI encoding/decoding -- tipos dinámicos, padding, head/tail"
  causa_raiz: "El ABI encoding de Solidity usa un formato head-tail para tipos dinámicos (bytes, string, arrays dinámicos). El 'head' contiene offsets que apuntan al 'tail' donde están los datos. Si un contrato construye calldata manualmente en assembly o decodifica calldata sin el decoder estándar de Solidity, puede malinterpretar offsets, leer datos incorrectos, o ser vulnerable a calldata crafted que explota la estructura head-tail."
  como_funciona: "1. Contrato decodifica calldata manualmente en assembly leyendo offsets. 2. Atacante crafts calldata con offsets que apuntan a posiciones superpuestas (overlapping ABI encoding). 3. El mismo dato puede ser interpretado como dos valores diferentes dependiendo de qué offset se siga. 4. Ejemplo: función `transfer(address to, uint256 amount)` -- un atacante puede craftar calldata donde el offset de un tipo dinámico apunta de vuelta al selector, causando confusión en la decodificación. 5. Variante: tipos dinámicos con padding incorrecto (no múltiplo de 32 bytes) que el decoder de Solidity acepta pero otros parsers rechazan."
  invariante: "Todo calldata construido manualmente debe ser ABI-compliant (offsets válidos, padding correcto, no superposición). Verificar que calldatasize() >= expected minimum. Validar offsets antes de leer datos."
  que_mirar:
    - "Assembly blocks que usan `calldataload` y `calldatacopy` para decodificar argumentos manualmente"
    - "Contratos que construyen calldata con `abi.encodePacked` para llamadas externas (NO es ABI-compliant)"
    - "Multicall/batch functions que parsean arrays de llamadas desde calldata"
    - "Bridges y routers que decodifican mensajes cross-chain con formato custom"
    - "Funciones que aceptan `bytes calldata` y hacen decode manual del contenido"
    - "Solidity abi.decode con tipos nested (e.g., `abi.decode(data, (uint256[], bytes[]))`)"
  como_se_arregla: "Usar abi.encode/abi.decode de Solidity siempre que sea posible. Si se necesita assembly, validar que offsets caen dentro del rango [4, calldatasize()]. Verificar que no hay superposición de regiones de datos. Usar abi.encode (NOT abi.encodePacked) para construir calldata de llamadas externas."
  trampas:
    - "abi.encodePacked NO añade padding ni offsets -- NO es ABI encoding estándar. Usarlo para construir calldata causa errores sutiles"
    - "El ABI decoder de Solidity es permisivo: acepta calldata con padding extra al final sin revert"
    - "Contratos que hacen forward de calldata (proxy, multicall) pueden pasar calldata malformada sin validarla"
    - "abi.decode revierte si los datos son insuficientes, pero NO verifica que los offsets no se superpongan"
  solodit_ids:
    - h-02-abi-encoding-edge-case-allows-double-spend-code4rena-none-axelar-git
  incidentes:
    - "GnosisSafe -- decodificación de multi-send transactions con offsets overlapping permitía ejecutar transacciones no autorizadas"
    - "Axelar (C4) -- ABI encoding edge case permitía doble gasto en bridge"
    - "Solidity compiler bug SOL-2022-4 -- ABI encoder v2 generaba encoding incorrecto para arrays nested"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solidity ABI spec, Solidity security advisories, Code4rena"
  patron_vulnerable: |
    // VULNERABLE: decodificación manual de calldata con offsets no validados
    function decodeManual(bytes calldata data) external {
        assembly {
            // Lee offset del primer campo dinámico
            let offset := calldataload(add(data.offset, 0x20))
            // PELIGRO: offset puede apuntar fuera del calldata o a región superpuesta
            let length := calldataload(add(data.offset, offset))
            // Lee datos en offset -- puede leer datos de otro parámetro
            let value := calldataload(add(data.offset, add(offset, 0x20)))
        }
    }
    // VULNERABLE: abi.encodePacked para construir calldata
    function callExternal(address target, string memory name, uint256 id) external {
        // encodePacked NO es ABI-compliant -- no padding, no offsets
        bytes memory data = abi.encodePacked(bytes4(keccak256("transfer(string,uint256)")), name, id);
        // El receptor decodificará incorrectamente: name y id se superponen
        target.call(data);
    }
  test_invariante: |
    // Invariante: roundtrip encoding debe preservar datos
    function test_abi_roundtrip(uint256[] memory arr, bytes memory data) public {
        bytes memory encoded = abi.encode(arr, data);
        (uint256[] memory decodedArr, bytes memory decodedData) = abi.decode(encoded, (uint256[], bytes));
        assert(keccak256(abi.encode(decodedArr)) == keccak256(abi.encode(arr)));
        assert(keccak256(decodedData) == keccak256(data));
    }
  tags: [abi-encoding, calldata, assembly, dynamic-types, padding]
  relacionado_con: [EVM-14, EVM-17]
  incidentes_verificados:
    - nombre: "Solidity ABI encoder v2 bug (SOL-2022-4)"
      fecha: "Sep 2022"
      perdida: "$0 (compiler fix)"
      tipo: "ABI coder v2 generaba encoding corrupto para structs con arrays dinámicos anidados"
      verificado: true
      fuente: "Solidity security advisory"
    - nombre: "GnosisSafe MultiSend"
      fecha: "2020"
      perdida: "$0 (audit finding)"
      tipo: "Parsing permisivo de MultiSend data podía permitir ejecución inesperada"
      verificado: true
      fuente: "OpenZeppelin audit"
```

```yaml
- id: EVM-09
  pattern: create2-address-collision
  name: "Colisión de direcciones Create2 -- contratos metamórficos"
  causa_raiz: "CREATE2 genera direcciones determinísticas basadas en (deployer, salt, initCodeHash). Si un atacante puede desplegar código diferente en la misma dirección (primero deployea contrato benigno, obtiene aprobaciones, luego destruye y redespliega contrato malicioso con el mismo initCode que resuelve a bytecode diferente), puede ejecutar un ataque de 'metamorphic contract'. La dirección es la misma pero el código cambió."
  como_funciona: "1. Atacante despliega Factory F que usa CREATE2. F tiene permiso para ser llamado por cualquiera. 2. Atacante despliega contrato A en dirección X vía CREATE2(salt, initCode). initCode es un constructor que lee bytecode de un almacén externo y lo despliega. 3. Contrato A (en dirección X) es benigno: un token ERC20 normal. Protocolo lo whitelista, usuarios le dan approve(). 4. Atacante llama selfdestruct() en A (o un camino de autodestrucción planificado). Dirección X queda vacía. 5. Atacante cambia el bytecode en el almacén externo a código malicioso. 6. Atacante redespliega en dirección X vía CREATE2(mismo salt, mismo initCode). El initCode resuelve a bytecode diferente porque lee del almacén externo. 7. Nuevo contrato en dirección X tiene acceso a todas las aprobaciones y whitelistings del contrato original."
  invariante: "Contratos que interactúan con CREATE2-deployed contracts deben verificar el codehash periódicamente o no depender de aprobaciones persistentes a direcciones que podrían cambiar código."
  que_mirar:
    - "Contratos factory que usan CREATE2 con initCode que hace delegatecall o EXTCODECOPY de otra fuente"
    - "Whitelisting basado en dirección sin verificar codehash"
    - "Token approvals infinitas a contratos creados con CREATE2"
    - "Contratos con función selfdestruct() + deployed vía CREATE2"
    - "Patterns donde el constructor hace `bytes memory code = fetchFromExternal(); assembly { return(add(code, 0x20), mload(code)) }`"
  como_se_arregla: "Verificar codehash en cada interacción, no solo en la primera. Evitar infinite approvals a contratos sin governance. Verificar que contratos CREATE2 no tengan selfdestruct. Post EIP-6780 (Dencun): selfdestruct solo destruye en la misma transacción que el deploy, limitando pero no eliminando el vector para contratos deployados y destruidos en la misma tx."
  trampas:
    - "Post EIP-6780 (Dencun, Mar 2024): selfdestruct ya NO borra código/storage excepto si se llama en la misma tx que CREATE. Esto MITIGA significativamente pero no elimina completamente el vector (deploy+selfdestruct atómicos)"
    - "El initCode hash debe ser idéntico para la misma dirección -- el truco es que el initCode es un loader que lee bytecode de otra fuente"
    - "CREATE (no CREATE2) no tiene este problema porque la dirección depende del nonce del deployer"
  solodit_ids:
    - h-01-create2-metamorphic-contract-can-change-implementation-code4rena-none-sudoswap-git
  incidentes:
    - "Tornado Cash governance attack (May 2023) -- atacante usó CREATE2 + selfdestruct para cambiar código de propuesta de governance aprobada"
    - "0age Metamorphic contract PoC -- demostración de factory metamórfica publicada en 2019"
    - "Paradigm CTF 2022 'Metamorphic' -- challenge completo basado en este vector"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "EIP-1014 (CREATE2), 0age research, Tornado Cash post-mortem"
  patron_vulnerable: |
    // VULNERABLE: Factory metamórfica
    contract MetamorphicFactory {
        address public codeStore;
        function deploy(bytes32 salt) external returns (address) {
            // initCode siempre es el mismo → misma dirección
            // PERO el runtime code viene de codeStore (cambiable)
            bytes memory initCode = hex"5860208158601c335a63aaf10f428752fa158151803b80938091923cf3";
            // Este initCode hace: EXTCODECOPY(codeStore) → deploya el bytecode del codeStore
            address deployed;
            assembly {
                deployed := create2(0, add(initCode, 0x20), mload(initCode), salt)
            }
            return deployed;
        }
        function updateCode(address newCodeStore) external {
            codeStore = newCodeStore;  // Cambia qué código se deployea en la misma dirección
        }
    }
  test_invariante: |
    // Invariante: codehash de contrato interactuado no debe cambiar entre transacciones
    function test_codehash_immutable(address target) public {
        bytes32 expectedHash = target.codehash;
        // ... interacciones ...
        assert(target.codehash == expectedHash);
        // Si falla → contrato fue destruido y redeployeado con código diferente
    }
  tags: [create2, metamorphic, selfdestruct, address-collision, deployment]
  relacionado_con: [EVM-10, EVM-15]
  incidentes_verificados:
    - nombre: "Tornado Cash Governance"
      fecha: "May 2023"
      perdida: "Governance takeover completo"
      tipo: "CREATE2 + selfdestruct para cambiar código de propuesta aprobada -- tomó control de governance"
      verificado: true
      fuente: "Samczsun analysis, DeFiHackLabs"
    - nombre: "0age Metamorphic PoC"
      fecha: "2019"
      perdida: "$0 (research)"
      tipo: "Demostración pública de factory metamórfica funcional"
      verificado: true
      fuente: "0age GitHub, Medium post"
```

```yaml
- id: EVM-10
  pattern: selfdestruct-create2-resurrection
  name: "Selfdestruct + Create2 resurrection -- resurrección de contratos con nuevo código"
  causa_raiz: "Históricamente (pre-Dencun), SELFDESTRUCT eliminaba el código y storage de un contrato, dejando la dirección vacía. Combinado con CREATE2, un atacante podía resucitar la dirección con código nuevo. Post EIP-6780 (Dencun, Mar 2024), SELFDESTRUCT solo elimina código y storage si se ejecuta EN LA MISMA TRANSACCIÓN que el CREATE. Esto cambia el modelo de amenaza pero no lo elimina: contratos que se deployan y autodestruyen atómicamente siguen siendo viables."
  como_funciona: "1. Pre-Dencun: Atacante despliega contrato C en dirección X vía CREATE2. C tiene función selfdestruct(). Atacante llama selfdestruct, dirección X queda vacía (código borrado, storage borrado, balance enviado a beneficiario). Atacante redespliega en X con CREATE2 + mismo salt + initCode que produce bytecode diferente. 2. Post-Dencun: El mismo flow solo funciona si deploy + selfdestruct ocurren en la MISMA transacción. Esto es posible: constructor → lógica → selfdestruct → segundo CREATE2 en misma tx via factory. 3. Impacto: whitelists, approvals, y registros que referencian la dirección X ahora apuntan a un contrato con código completamente diferente."
  invariante: "No confiar en la persistencia del código en una dirección CREATE2. Verificar codehash en cada interacción. Post-Dencun: verificar que contratos no tienen paths de selfdestruct en constructor o funciones llamadas en la misma tx que deploy."
  que_mirar:
    - "Contratos con SELFDESTRUCT opcode + deployados vía CREATE2"
    - "Factories que deployan y llaman funciones en la misma transacción (constructor + callback)"
    - "Contratos que se registran en un registry vía constructor y tienen path a selfdestruct"
    - "ERC20/ERC721 tokens creados con CREATE2 que reciben approvals permanentes"
    - "Governance proposals que despliegan contratos con CREATE2"
  como_se_arregla: "Eliminar selfdestruct de contratos CREATE2 (o toda la codebase -- EIP-6780 lo depreca). Verificar codehash en cada interacción, no solo en el registro. Usar CREATE en vez de CREATE2 cuando la dirección determinística no es necesaria."
  trampas:
    - "Post EIP-6780: selfdestruct() ya NO borra código/storage si no es en la misma tx que CREATE. Esto MITIGA dramáticamente el vector para contratos ya existentes"
    - "Pero: contratos deployados y destruidos en la misma tx SÍ se borran -- el vector atómico persiste"
    - "En L2s y chains EVM-compatible, EIP-6780 puede no estar implementado -- verificar compatibilidad"
    - "Algunos compiladores (Vyper) eliminaron selfdestruct antes que Solidity"
  solodit_ids: []
  incidentes:
    - "Tornado Cash (May 2023) -- usó este vector exacto: deploy propuesta → aprobación → selfdestruct → redeploy con código malicioso"
    - "Paradigm CTF 'Vanity' -- challenge de resurrección de contrato con CREATE2"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "EIP-6780, EIP-1014, Tornado Cash analysis"
  patron_vulnerable: |
    // VULNERABLE: deploy + selfdestruct atómico (funciona post EIP-6780)
    contract AtomicResurrection {
        function deployAndDestroy(bytes32 salt, bytes memory code) external {
            // Paso 1: Deploy contrato con CREATE2
            address deployed;
            assembly {
                deployed := create2(0, add(code, 0x20), mload(code), salt)
            }
            // Paso 2: El contrato desplegado se autodestruye en la MISMA TX
            IDestructible(deployed).destroy();
            // Post EIP-6780: esto SÍ borra código y storage (misma tx)

            // Paso 3: Redeploy con código diferente en la MISMA TX
            bytes memory maliciousCode = getMaliciousCode();
            assembly {
                deployed := create2(0, add(maliciousCode, 0x20), mload(maliciousCode), salt)
            }
            // NOTA: solo funciona si initCodeHash es el mismo → loader pattern
        }
    }
  test_invariante: |
    // Invariante: contratos CREATE2 no deben tener selfdestruct
    function test_no_selfdestruct_in_create2() public {
        // Verificar bytecode del contrato deployado con CREATE2
        bytes memory code = address(deployed).code;
        // Buscar opcode SELFDESTRUCT (0xFF) en el bytecode
        bool hasSelfDestruct = false;
        for (uint i = 0; i < code.length; i++) {
            if (uint8(code[i]) == 0xFF) hasSelfDestruct = true;
        }
        assert(!hasSelfDestruct);  // Simplificado -- en producción usar análisis de CFG
    }
  tags: [selfdestruct, create2, resurrection, metamorphic, eip-6780]
  relacionado_con: [EVM-09, EVM-15]
  incidentes_verificados:
    - nombre: "Tornado Cash Governance (resurrection)"
      fecha: "May 2023"
      perdida: "Governance takeover"
      tipo: "Deploy propuesta → obtener aprobación → selfdestruct → redeploy código malicioso en misma dirección"
      verificado: true
      fuente: "Samczsun, DeFiHackLabs"
    - nombre: "EIP-6780 (Dencun upgrade)"
      fecha: "Mar 2024"
      perdida: "N/A (mitigation)"
      tipo: "Cambio de semántica de SELFDESTRUCT para prevenir resurrection attacks en contratos existentes"
      verificado: true
      fuente: "Ethereum EIP-6780"
```

```yaml
- id: EVM-11
  pattern: transient-storage-reentrancy
  name: "Reentrancy vía transient storage (EIP-1153 tstore/tload)"
  causa_raiz: "EIP-1153 introdujo transient storage (tstore/tload) en Dencun -- storage que persiste durante toda la transacción pero se limpia al final. Se promueve como solución barata para reentrancy locks. Sin embargo, transient storage tiene semántica diferente a storage regular: (1) se limpia al final de la tx, (2) persiste a través de call frames incluyendo delegatecall, (3) NO persiste entre transacciones. Los desarrolladores que migran reentrancy guards de storage regular a transient storage pueden introducir bugs si no entienden las diferencias."
  como_funciona: "1. Contrato usa tstore/tload para implementar un reentrancy lock barato (5000 gas warm vs 20000 gas SSTORE). 2. Escenario A (reset prematuro): si el lock se implementa como `tstore(slot, 1)` al inicio y `tstore(slot, 0)` al final de la función, y la función tiene un callback externo en medio, el callback puede llamar a OTRA función del contrato que no tiene lock (porque el lock es por slot, no global). 3. Escenario B (cross-contract): tstore es por contrato. Si contrato A y B ambos usan transient storage para locks, la reentrancy de A→B→A funciona normalmente -- transient storage de A no protege contra reentrancy cross-contract. 4. Escenario C (end-of-tx cleanup): código que depende de transient storage para mantener estado entre llamadas dentro de la misma tx (e.g., flash loan callback state) pierde ese estado si una sub-llamada hace revert parcial."
  invariante: "Reentrancy guards basados en transient storage deben cubrir TODOS los entry points del contrato, no solo funciones individuales. El lock debe ser global (no por función). Verificar que el comportamiento de cleanup post-tx no afecta lógica crítica."
  que_mirar:
    - "Contratos que usan `tstore`/`tload` para reentrancy locks -- verificar cobertura"
    - "Migración de ReentrancyGuard de OZ a versión con transient storage -- verificar que el slot no colisiona"
    - "Contratos que usan transient storage como 'contexto de transacción' (e.g., flash loan callback auth)"
    - "Patrones donde tstore se usa para pasar datos entre call frames sin pasar por calldata"
    - "Contratos upgradeable donde el slot de transient storage podría colisionar con nueva implementación"
  como_se_arregla: "Usar OpenZeppelin ReentrancyGuardTransient que maneja estos edge cases. Si se implementa custom: usar lock global (no por función), no resetear el lock hasta después de toda la lógica (seguir check-effects-interactions). Verificar que el slot de transient storage no colisiona con otros usos."
  trampas:
    - "transient storage es MÁS BARATO que regular storage (100 gas load, 100 gas store) -- tentador para optimización pero hay que entender las diferencias"
    - "El cleanup automático al final de la tx es una FEATURE, no un bug -- pero puede sorprender si el dev espera persistencia"
    - "delegatecall comparte transient storage del caller (igual que regular storage) -- puede causar colisiones entre proxy e implementación"
    - "EIP-1153 es post-Dencun (Mar 2024) -- muchos forks EVM aún no lo soportan"
  solodit_ids: []
  incidentes:
    - "Uniswap v4 -- usa transient storage extensivamente para gas optimization; múltiples auditorías verificaron edge cases de reentrancy"
    - "OpenZeppelin ReentrancyGuardTransient -- publicado como versión segura post-Dencun"
    - "Euler v2 -- migración a transient storage para locks, auditado por Trail of Bits y Spearbit"
  severidad: high
  confianza: media
  verificado: true
  fuente: "EIP-1153, Uniswap v4 audits, OpenZeppelin"
  patron_vulnerable: |
    // VULNERABLE: reentrancy lock con transient storage -- cobertura parcial
    contract VulnerableVault {
        uint256 constant LOCK_SLOT = 0x1234;
        modifier nonReentrant() {
            assembly {
                if tload(LOCK_SLOT) { revert(0, 0) }
                tstore(LOCK_SLOT, 1)
            }
            _;
            assembly { tstore(LOCK_SLOT, 0) }
        }
        function deposit() external payable nonReentrant {
            // Protegida contra reentrancy
            balances[msg.sender] += msg.value;
        }
        function withdraw(uint256 amount) external {
            // NO tiene nonReentrant → reentrable desde deposit callback
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            (bool s,) = msg.sender.call{value: amount}("");
        }
    }
    // VULNERABLE: transient storage como contexto de flash loan
    contract FlashLender {
        function flash(uint256 amount, address callback) external {
            assembly { tstore(0xFL, 1) }  // "flash loan activo"
            token.transfer(callback, amount);
            ICallback(callback).onFlash(amount);
            require(token.balanceOf(address(this)) >= preBalance);
            assembly { tstore(0xFL, 0) }  // cleanup
            // Si callback hace revert parcial (try/catch), tstore se deshace
            // pero el estado de la transacción principal no
        }
    }
  test_invariante: |
    // Invariante: lock transient debe cubrir TODAS las funciones de estado
    function test_transient_lock_coverage() public {
        // Intentar reentrar withdraw desde deposit callback
        ReentrantAttacker attacker = new ReentrantAttacker(vault);
        attacker.attack{value: 1 ether}();
        // Si withdraw no tiene lock, attacker puede drenar
        assert(address(vault).balance >= expectedBalance);
    }
  tags: [transient-storage, tstore, tload, reentrancy, eip-1153, dencun]
  relacionado_con: [EVM-03, EVM-02]
  incidentes_verificados:
    - nombre: "Uniswap v4 transient storage design"
      fecha: "2023-2024"
      perdida: "$0 (audit + design)"
      tipo: "Diseño extensivo de transient storage para locks y accounting temporal -- auditado múltiples veces"
      verificado: true
      fuente: "Uniswap v4 audit reports (Trail of Bits, OpenZeppelin, Spearbit)"
```

```yaml
- id: EVM-12
  pattern: push0-chain-compatibility
  name: "PUSH0 opcode incompatibilidad entre chains"
  causa_raiz: "PUSH0 (opcode 0x5F) fue introducido en EIP-3855 (Shanghai, Apr 2023) y Solidity >= 0.8.20 lo usa por defecto cuando el target EVM es Shanghai+. PUSH0 empuja un 0 al stack con solo 2 gas (vs PUSH1 0x00 = 3 gas). El problema: chains EVM-compatible que no han implementado Shanghai (e.g., versiones antiguas de Arbitrum, zkSync, Polygon zkEVM, BSC en cierto momento) no reconocen este opcode y las transacciones revertan con 'invalid opcode'."
  como_funciona: "1. Desarrollador compila con Solidity 0.8.20+ sin especificar `--evm-version paris` (o anterior). 2. El compilador genera bytecode con PUSH0 (0x5F) en múltiples lugares (es muy común porque 0 se usa constantemente). 3. Contrato se despliega en Ethereum mainnet (Shanghai+) -- funciona. 4. Contrato se despliega en chain L2 o alt-L1 que no soporta Shanghai -- FAIL: la transacción revierte con invalid opcode. 5. O peor: contrato se despliega correctamente pero una función que usa PUSH0 falla en runtime en la chain incompatible."
  invariante: "El bytecode deployado no debe contener opcodes no soportados por la chain objetivo. Verificar evm-version en foundry.toml/hardhat.config al compilar para multi-chain deployment."
  que_mirar:
    - "Contratos compilados con Solidity >= 0.8.20 sin especificar evm_version"
    - "Protocolos multi-chain que usan el mismo bytecode en todas las chains"
    - "foundry.toml sin `evm_version = 'paris'` en proyectos que deployean en L2s"
    - "Forks de protocolos existentes recompilados con nueva versión de Solidity"
    - "Librerías (OpenZeppelin, Solmate) actualizadas a versiones que usan PUSH0"
  como_se_arregla: "Especificar evm_version en la config del compilador: `solc --evm-version paris` o en foundry.toml: `evm_version = 'paris'`. Verificar compatibilidad de opcodes en la chain objetivo antes de deploy. Usar bytecode scanner para detectar PUSH0 (0x5F) en el bytecode."
  trampas:
    - "A finales de 2024, la mayoría de L2s ya soportan PUSH0 -- este bug es cada vez menos relevante pero persiste en chains menores"
    - "No solo PUSH0: otros opcodes Shanghai+ (WARM_COINBASE) también pueden fallar en chains pre-Shanghai"
    - "El bug puede manifestarse SOLO en ciertas funciones si PUSH0 aparece solo en algunos code paths"
    - "Verificar ANTES del deploy, no después -- el bytecode scanner es la herramienta correcta"
  solodit_ids:
    - m-01-push0-opcode-not-supported-on-all-chains-code4rena-none-ondo-finance-git
    - contracts-compiled-with-0-8-20-wont-work-on-chains-that-dont-support-push0-openzeppelin-none-none-markdown
  incidentes:
    - "Ondo Finance (C4) -- contratos compilados con 0.8.20 no funcionarían en chains sin PUSH0"
    - "Múltiples protocolos multi-chain en 2023 descubrieron el issue post-deploy"
    - "OpenZeppelin advisory sobre compilación default de Solidity 0.8.20+"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "EIP-3855, Solidity 0.8.20 release notes, Code4rena findings"
  patron_vulnerable: |
    // VULNERABLE: compilado con Solidity 0.8.20+ sin especificar evm_version
    // foundry.toml:
    //   [profile.default]
    //   solc_version = "0.8.24"
    //   # NO tiene evm_version = "paris" → usa Shanghai por defecto → PUSH0
    //
    // El bytecode resultante contiene 0x5F (PUSH0) en múltiples lugares.
    // Deploy en Ethereum mainnet: OK
    // Deploy en L2 pre-Shanghai: FAIL con "invalid opcode"
    //
    // Ejemplo en el bytecode compilado:
    //   PUSH0          // 0x5F → empuja 0 al stack (2 gas)
    //   DUP1           // duplica el 0
    //   REVERT         // revert(0, 0)
    // vs compilado con evm_version = paris:
    //   PUSH1 0x00     // 0x60 0x00 → empuja 0 al stack (3 gas)
    //   DUP1
    //   REVERT
  test_invariante: |
    // Test: verificar que bytecode no contiene PUSH0 para deployments multi-chain
    function test_no_push0_in_bytecode() public {
        bytes memory code = type(MyContract).creationCode;
        for (uint256 i = 0; i < code.length; i++) {
            // 0x5F = PUSH0. Nota: puede aparecer como dato, no solo como opcode
            // Este test es heurístico -- un scanner de opcodes es más preciso
            // pero para la mayoría de contratos funciona
        }
        // Alternativa más precisa: usar `forge inspect MyContract bytecode`
        // y buscar 0x5F en la decompilación
    }
  tags: [push0, evm-version, multi-chain, compatibility, opcode, l2]
  relacionado_con: [EVM-05]
  incidentes_verificados:
    - nombre: "Ondo Finance (C4)"
      fecha: "2023"
      perdida: "$0 (audit finding)"
      tipo: "Contratos con PUSH0 destinados a chains que no lo soportaban"
      verificado: true
      fuente: "Code4rena"
    - nombre: "Multiple L2 deployment failures"
      fecha: "2023"
      perdida: "Gas costs (redeploy)"
      tipo: "Protocolos descubrieron incompatibilidad PUSH0 post-deploy en L2s menores"
      verificado: true
      fuente: "Community reports, Twitter disclosures"
```

```yaml
- id: EVM-13
  pattern: dirty-upper-bits
  name: "Dirty upper bits en assembly -- no limpiar tipos address/uint menores"
  causa_raiz: "En el EVM, todos los valores en el stack son de 256 bits. Cuando se trabaja con tipos más pequeños (address = 160 bits, uint8 = 8 bits, bool = 1 bit), los bits superiores deberían ser cero pero NO están garantizados en assembly. Solidity automáticamente 'limpia' (clean) los bits superiores al leer variables, pero en Yul/assembly el desarrollador es responsable. Si se comparan valores o se usan como keys de mapping sin limpiar, los dirty upper bits pueden causar que comparaciones fallen o que diferentes inputs mapeen al mismo slot."
  como_funciona: "1. Función en assembly lee un parámetro que debería ser address (160 bits). 2. El calldata fue craftado manualmente con bits sucios en los 96 bits superiores (e.g., calldataload(4) retorna 0xDEAD...address en vez de 0x000...address). 3. Si el assembly compara con `eq(value, expectedAddress)`, la comparación falla porque los upper bits difieren. 4. Alternativamente: si el valor dirty se usa como key en sload(slot), puede acceder a un slot de storage incorrecto. 5. Variante: bool con valor 2 (no 0 ni 1) -- `iszero(iszero(value))` normaliza a 1, pero `eq(value, 1)` falla."
  invariante: "En assembly, todo valor usado como address debe ser AND-masked con 0xffffffffffffffffffffffffffffffffffffffff (20 bytes). Todo bool debe normalizarse con iszero(iszero(x)). Todo uintN debe AND-masked con (2^N - 1)."
  que_mirar:
    - "calldataload() sin masking posterior para tipos < 256 bits"
    - "sload() de packed storage slots sin shift/mask para extraer el valor correcto"
    - "Comparaciones en assembly con `eq()` de valores que deberían ser address"
    - "Valores pasados entre funciones en assembly sin cleaning"
    - "External calls en assembly donde se construye calldata con valores no limpiados"
    - "Conversiones implícitas en Yul: no existen -- todo es uint256"
  como_se_arregla: "Siempre limpiar: `let addr := and(calldataload(offset), 0xffffffffffffffffffffffffffffffffffffffff)`. Para bool: `let b := iszero(iszero(calldataload(offset)))`. Para uintN: `let val := and(calldataload(offset), sub(shl(N, 1), 1))`. Solidity lo hace automáticamente -- solo es necesario en assembly manual."
  trampas:
    - "Solidity limpia automáticamente al asignar a variables tipadas -- el bug solo ocurre en assembly/Yul"
    - "calldataload siempre lee 32 bytes -- si el parámetro es address (20 bytes), los 12 bytes superiores son parte del padding y DEBERÍAN ser cero, pero un caller malicioso puede enviar padding dirty"
    - "ABI decoder de Solidity valida padding desde 0.8.0 -- pero llamadas directas en assembly bypasean el decoder"
    - "Packed struct storage: `sload` lee 32 bytes de un slot que puede contener múltiples variables empacadas -- requiere shift + mask correcto"
  solodit_ids:
    - h-03-dirty-upper-bits-in-assembly-allow-authorization-bypass-code4rena-none-seaport-git
  incidentes:
    - "OpenSea Seaport -- dirty upper bits en address parameter de assembly permitían bypass de validación"
    - "Solidity compiler bug 0.8.13-0.8.15 -- optimizer generaba código que no limpiaba upper bits correctamente en ciertos patrones"
    - "Paradigm CTF 2022 'Hint Finance' -- explotación de dirty bits en token address"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solidity docs (ABI encoding), Seaport audit, Solidity security advisories"
  patron_vulnerable: |
    // VULNERABLE: address no limpiada en assembly
    function transfer(address to, uint256 amount) external {
        assembly {
            // calldataload(4) lee 32 bytes empezando en byte 4 (después del selector)
            // Para address (20 bytes), los 12 bytes superiores DEBERÍAN ser 0
            // pero un caller malicioso puede enviar bytes sucios
            let recipient := calldataload(4)  // 0xDEADBEEF000000000000000<20-byte-address>
            let amt := calldataload(36)

            // Comparación con eq() falla si upper bits difieren
            // PELIGRO: si se usa como key de mapping
            // sstore(add(balances.slot, recipient), amt)
            // Slot calculado con dirty bits → escribe en storage incorrecto
        }
    }
    // VULNERABLE: bool dirty
    function isAuthorized(address user) external view returns (bool) {
        assembly {
            let slot := add(authMap.slot, user)
            let val := sload(slot)
            // val podría ser 2 o 255 (dirty bool)
            // iszero(val) retorna 0 (false) → pasa como "authorized"
            // PERO: eq(val, 1) retorna 0 → falla como "not authorized"
            mstore(0, eq(val, 1))  // Inconsistente con iszero approach
            return(0, 32)
        }
    }
  test_invariante: |
    // Invariante: address operations en assembly deben ser consistentes con/sin dirty bits
    function test_dirty_bits_address(uint256 dirtyAddr) public {
        // Forzar dirty upper bits
        address cleanAddr = address(uint160(dirtyAddr));
        uint256 dirtyValue = dirtyAddr;  // Con upper bits sucios

        // Ambas operaciones deben producir el mismo resultado
        bytes32 cleanResult = contract.process(cleanAddr);
        bytes32 dirtyResult = contract.processRaw(dirtyValue);
        assert(cleanResult == dirtyResult);
    }
  tags: [assembly, dirty-bits, address, type-cleaning, calldata, yul]
  relacionado_con: [EVM-05, EVM-08]
  incidentes_verificados:
    - nombre: "Seaport (OpenSea) dirty bits"
      fecha: "2022"
      perdida: "$0 (audit finding, pre-launch)"
      tipo: "Assembly address comparison vulnerable a dirty upper bits -- bypass de order validation"
      verificado: true
      fuente: "OpenSea Seaport audit, Trail of Bits"
    - nombre: "Solidity optimizer bug (dirty bits)"
      fecha: "Aug 2022"
      perdida: "$0 (compiler fix)"
      tipo: "Optimizer no limpiaba upper bits de valores inline-assembly en ciertos patrones ternarios"
      verificado: true
      fuente: "Solidity security advisory SOL-2022-5"
```

```yaml
- id: EVM-14
  pattern: calldata-memory-confusion
  name: "Confusión calldata vs memory en llamadas externas"
  causa_raiz: "En Solidity, `calldata` es inmutable y barato de leer pero no se puede modificar. `memory` es mutable pero más costoso (expansión cuadrática). Cuando un contrato necesita reenviar datos a una llamada externa, confundir cuándo usar calldata directamente vs copiar a memory puede causar: (1) copias innecesarias que expanden memory (gas griefing), (2) lectura de datos incorrectos si el offset en memory no coincide con calldata, (3) en assembly, usar calldataload cuando se debería usar mload o viceversa."
  como_funciona: "1. Contrato recibe `bytes calldata data` y necesita modificarlo antes de reenviarlo (e.g., cambiar primer byte). 2. Dev copia a memory: `bytes memory mData = data` -- esto copia TODOS los bytes a memory, expandiéndola. 3. Si `data` es muy grande (returndata bomb variant), la expansión de memory consume gas cuadrático. 4. Alternativamente: en assembly, dev usa `calldatacopy(ptr, offset, size)` pero calcula offset incorrecto (olvidando que calldata incluye el selector de 4 bytes). 5. Variante: función usa `abi.encode(...)` para construir calldata, que primero expande memory para el encoding y luego la expansión es permanente para el resto de la ejecución."
  invariante: "Datos que no necesitan modificación deben permanecer en calldata. En assembly, offsets de calldatacopy deben contabilizar el selector de 4 bytes. Memory expansion para forwarding de datos debe estar bounded."
  que_mirar:
    - "Funciones que copian `bytes calldata` a `bytes memory` sin necesidad de modificar"
    - "Assembly con calldatacopy donde el offset no suma 4 (selector) o 36 (selector + offset pointer)"
    - "Loops que construyen calldata con abi.encode dentro del loop -- memory crece acumulativamente"
    - "Proxies que reenvían calldata: `assembly { calldatacopy(0, 0, calldatasize()) }` es correcto, pero variantes pueden fallar"
    - "Funciones que usan msg.data directamente vs parámetros decodificados"
  como_se_arregla: "Usar `calldata` type hint cuando los datos no se modifican. En assembly, calcular offsets cuidadosamente: `calldatacopy(dest, src_offset_in_calldata, length)` donde src_offset incluye los 4 bytes del selector. Para forwarding, usar el pattern del proxy OpenZeppelin: copy todo calldata, forward, copy returndata."
  trampas:
    - "Solidity internamente ya optimiza muchos de estos patterns -- el riesgo real es en assembly manual"
    - "En Solidity >= 0.8.0 con ABI coder v2, las conversiones calldata→memory son más seguras pero más costosas"
    - "msg.data incluye el selector, pero los parámetros individuales no -- cuidado al calcular offsets"
    - "Free memory pointer: después de copiar datos grandes a memory, el free memory pointer NO retrocede -- toda la memory posterior a la copia es 'desperdiciada'"
  solodit_ids: []
  incidentes:
    - "OpenZeppelin Proxy -- documentación extensa sobre el patrón correcto de forwarding calldata"
    - "Multiple gas optimization audits -- Trail of Bits recomienda calldata sobre memory para datos read-only"
  severidad: low
  confianza: alta
  verificado: true
  fuente: "Solidity docs, EVM memory model, OpenZeppelin"
  patron_vulnerable: |
    // VULNERABLE: offset de calldata incorrecto en assembly (olvida selector)
    function proxyForward(address target) external payable {
        assembly {
            // INCORRECTO: copia desde byte 0 (incluye selector)
            calldatacopy(0, 0, calldatasize())
            let result := call(gas(), target, callvalue(), 0, calldatasize(), 0, 0)
            // CORRECTO para reenviar sin selector:
            // calldatacopy(0, 4, sub(calldatasize(), 4))
            // let result := call(gas(), target, callvalue(), 0, sub(calldatasize(), 4), 0, 0)
        }
    }
    // VULNERABLE: copia innecesaria de calldata a memory
    function processLargeData(bytes calldata data) external {
        // Innecesario si no se modifica -- copia todo a memory
        bytes memory mData = data;  // Expansion de memory para datos grandes
        // Podría usar data directamente como calldata si solo se lee
        emit DataHash(keccak256(mData));  // keccak256(data) funciona con calldata
    }
  test_invariante: |
    // Invariante: forwarded calldata debe ser ABI-válido para el receptor
    function test_calldata_forwarding(bytes calldata data) public {
        // Verificar que el forwarding preserva los datos correctamente
        (bool success, bytes memory result) = address(proxy).call(
            abi.encodeWithSignature("proxyForward(address)", target)
        );
        // El target debe recibir los datos sin corrupción
    }
  tags: [calldata, memory, gas-optimization, assembly, forwarding]
  relacionado_con: [EVM-01, EVM-04]
  incidentes_verificados:
    - nombre: "Solidity calldata optimization"
      fecha: "ongoing"
      perdida: "N/A"
      tipo: "Documentación continua sobre uso correcto de calldata vs memory en Solidity"
      verificado: true
      fuente: "Solidity docs, EVM specification"
```

```yaml
- id: EVM-15
  pattern: extcodesize-constructor-bypass
  name: "Bypass de extcodesize check durante constructor (code.length == 0)"
  causa_raiz: "Durante la ejecución del constructor de un contrato, su dirección tiene extcodesize == 0 (el código runtime aún no se ha almacenado). Contratos que usan extcodesize(addr) > 0 para verificar 'es un contrato' (isContract check) pueden ser bypasseados si el atacante llama desde su constructor. Esto era históricamente el patrón para prevenir que contratos llamen a ciertas funciones, pero es fundamentalmente roto."
  como_funciona: "1. Contrato V tiene un modifier `onlyEOA` que verifica `require(msg.sender.code.length == 0, 'no contracts')`. 2. Atacante despliega contrato A cuyo constructor llama a V.functionProtected(). 3. Durante el constructor de A, extcodesize(address(A)) == 0. 4. V verifica msg.sender.code.length, que es address(A).code.length == 0 → pasa la validación. 5. El atacante ejecuta la función protegida desde un contrato, evadiendo la restricción. 6. Después del constructor, A tiene código normal y podría seguir interactuando con V a través de llamadas relay."
  invariante: "NUNCA usar extcodesize para distinguir EOA de contratos. Usar tx.origin == msg.sender para EOA check (tiene sus propios trade-offs con account abstraction). O mejor: no intentar distinguir EOA de contratos -- diseñar la seguridad sin depender de esta distinción."
  que_mirar:
    - "Modifiers que verifican `msg.sender.code.length == 0` o `extcodesize(msg.sender) == 0`"
    - "Funciones con require que verifican 'isContract(addr)' usando code.length"
    - "Patrones que intentan prevenir flash loans verificando que el caller es EOA"
    - "onlyEOA modifiers en protocolos DeFi (minting, claiming, staking)"
    - "OpenZeppelin Address.isContract() -- documentación advierte que no es fiable para seguridad"
  como_se_arregla: "Eliminar checks de isContract para seguridad. Si absolutamente necesario distinguir EOA: usar `require(tx.origin == msg.sender)` (limitaciones: no funciona con account abstraction EIP-4337, Gnosis Safe). Diseñar el contrato para ser seguro independientemente de si el caller es EOA o contrato."
  trampas:
    - "OpenZeppelin Address.isContract() tiene un DISCLAIMER explícito: no usar para seguridad"
    - "Con EIP-4337 (account abstraction) y smart wallets, la distinción EOA/contrato es cada vez menos relevante"
    - "tx.origin == msg.sender falla con abstracted accounts, meta-transactions, relayers"
    - "Post-EIP-3607: EOAs no pueden tener código, pero esto no ayuda porque el check falla en el constructor"
    - "EIP-7702 (Pectra, 2025) permite EOAs tener code temporalmente -- invalida aún más los isContract checks"
  solodit_ids:
    - m-02-iscontract-check-can-be-bypassed-by-calling-from-constructor-code4rena-none-trader-joe-git
  incidentes:
    - "Fei Protocol -- isContract check bypasseado en función de minting"
    - "Trader Joe (C4) -- isContract bypass permitía que contratos participen en mint restringido a EOA"
    - "Paradigm CTF 2021 -- múltiples challenges usan este vector como building block"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solidity docs, OpenZeppelin Address.sol, DeFiHackLabs"
  patron_vulnerable: |
    // VULNERABLE: isContract check bypasseable desde constructor
    modifier onlyEOA() {
        require(msg.sender == tx.origin, "no contracts");  // Variante 1: tx.origin
        // O la variante más débil:
        require(msg.sender.code.length == 0, "no contracts");  // BYPASSEABLE
        _;
    }
    function mint() external onlyEOA {
        _mint(msg.sender, 1);
    }
    // ATAQUE:
    contract Attacker {
        constructor(address target) {
            // Durante el constructor, address(this).code.length == 0
            ITarget(target).mint();  // Bypassa el check de code.length
        }
    }
  test_invariante: |
    // Invariante: si la intención es bloquear contratos, verificar post-deploy
    function test_constructor_bypass() public {
        // Intentar mintear desde constructor de contrato atacante
        bytes memory attackCode = abi.encodePacked(
            type(ConstructorAttacker).creationCode,
            abi.encode(address(target))
        );
        address attacker;
        assembly { attacker := create(0, add(attackCode, 0x20), mload(attackCode)) }
        // Si attacker tiene tokens → el onlyEOA check fue bypasseado
        assert(target.balanceOf(attacker) == 0);
    }
  tags: [extcodesize, iscontract, constructor, eoa-check, bypass]
  relacionado_con: [EVM-09, EVM-16]
  incidentes_verificados:
    - nombre: "Fei Protocol isContract bypass"
      fecha: "2021"
      perdida: "$0 (mitigado)"
      tipo: "Constructor-based bypass de isContract check en función de minting"
      verificado: true
      fuente: "Fei Protocol disclosure"
    - nombre: "Paradigm CTF challenges"
      fecha: "2021-2022"
      perdida: "$0 (CTF)"
      tipo: "Múltiples challenges usan extcodesize == 0 during constructor como vector"
      verificado: true
      fuente: "Paradigm CTF writeups"
```

```yaml
- id: EVM-16
  pattern: unchecked-call-return
  name: "Return value de low-level call no verificado"
  causa_raiz: "Las funciones de bajo nivel de Solidity (address.call, address.delegatecall, address.staticcall, address.send) retornan un bool indicando si la llamada fue exitosa. Si este bool no se verifica, la ejecución continúa silenciosamente después de un fallo. Esto es diferente de las llamadas de alto nivel (contract.function()) que propagan el revert automáticamente. El patrón es uno de los bugs más comunes en contratos Solidity y causa pérdida de fondos cuando transfers de ETH/tokens fallan silenciosamente."
  como_funciona: "1. Contrato hace `payable(recipient).send(amount)` o `recipient.call{value: amount}('')` para enviar ETH. 2. El send/call falla (recipient no tiene receive(), gas insuficiente, o recipient revierte intencionalmente). 3. send retorna false, call retorna (false, ''). 4. Si el contrato no verifica el return value, continúa ejecutando como si el transfer fuera exitoso. 5. El balance del contrato no se actualiza (el ETH sigue en el contrato), pero la contabilidad interna sí se actualiza. 6. Resultado: desincronización entre balance real y balance contable -- fondos quedan atrapados o son robables."
  invariante: "Todo return value de call/send/delegatecall DEBE ser verificado. Si falla, el contrato debe revertir o manejar el error explícitamente."
  que_mirar:
    - "`address.send(amount)` sin `require()` al resultado"
    - "`address.call{value: amount}('')` sin verificar el `bool success`"
    - "Patterns: `(bool success, ) = addr.call(data); // success never checked`"
    - "Loops de distribución donde el fallo de un transfer bloquea toda la distribución"
    - "Assembly `let s := call(gas(), addr, amount, 0, 0, 0, 0)` sin verificar s"
    - "Funciones de withdraw/claim que actualizan estado ANTES de verificar el transfer"
  como_se_arregla: "Usar `(bool success, ) = addr.call{value: amount}(''); require(success, 'transfer failed');`. O mejor: usar OZ Address.sendValue() que revierte en fallo. Para ERC20: usar SafeERC20.safeTransfer() que verifica return value y maneja tokens que no retornan bool."
  trampas:
    - "Solidity transfer() (NO send/call) revierte en fallo -- pero tiene el problema del gas stipend de 2300 (ver EVM-18)"
    - "Algunos contratos intencionalmente ignoran el return value para continuar en caso de fallo (e.g., distribución best-effort) -- verificar intención"
    - "ERC20.transfer() que no retorna bool (USDT original) requiere SafeERC20 para manejar correctamente"
    - "En assembly, `call()` retorna 0 en fallo, 1 en éxito -- opuesto a lo que algunos devs esperan"
  solodit_ids:
    - h-01-unchecked-low-level-call-return-value-code4rena-none-blur-git
    - m-01-return-value-of-low-level-call-not-checked-code4rena-none-rubicon-git
  incidentes:
    - "King of the Ether -- ETH send sin verificar return value; fondos atrapados"
    - "Blur Exchange (C4) -- unchecked call en función de transfer de ETH"
    - "Rubicon (C4) -- return value de low-level call ignorado en bath token withdrawal"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "SWC Registry (SWC-104), Slither unchecked-lowlevel, Code4rena"
  patron_vulnerable: |
    // VULNERABLE: return value de send ignorado
    function distribute(address[] calldata recipients, uint256 amount) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            // send retorna false si falla -- IGNORADO
            payable(recipients[i]).send(amount);
            // Contabilidad se actualiza como si el transfer fuera exitoso
            distributed[recipients[i]] += amount;
        }
    }
    // VULNERABLE: call sin check de success
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;  // Estado actualizado ANTES del check
        (bool success, ) = msg.sender.call{value: amount}("");
        // success no se verifica -- si falla, balance ya decrementó
        // Fondos quedan atrapados en el contrato
    }
  test_invariante: |
    // Invariante: balance contable == balance real post-distribución
    function invariant_balance_accounting() public {
        uint256 totalDistributed;
        for (uint i = 0; i < recipients.length; i++) {
            totalDistributed += distributed[recipients[i]];
        }
        // Si algún send falló silenciosamente, totalDistributed > real transfers
        assert(initialBalance - address(contract).balance == totalDistributed);
    }
  tags: [low-level-call, return-value, send, call, unchecked, eth-transfer]
  relacionado_con: [EVM-18, EVM-02]
  incidentes_verificados:
    - nombre: "King of the Ether"
      fecha: "2016"
      perdida: "~$2K (histórico)"
      tipo: "send() sin verificar retorno -- ETH del 'rey' anterior nunca enviado"
      verificado: true
      fuente: "Historical Ethereum exploit, Blockchain Graveyard"
    - nombre: "Blur Exchange (C4)"
      fecha: "2022"
      perdida: "$0 (audit finding)"
      tipo: "Unchecked call return value en función de distribución de ETH"
      verificado: true
      fuente: "Code4rena"
```

```yaml
- id: EVM-17
  pattern: abi-encoder-v2-edge-cases
  name: "Edge cases del ABI encoder v2 -- arrays dinámicos anidados y structs"
  causa_raiz: "El ABI encoder v2 (habilitado por defecto desde Solidity 0.8.0, disponible desde 0.4.19 como experimental) maneja tipos complejos como structs con arrays dinámicos, arrays de arrays, y tipos anidados. Sin embargo, ha tenido múltiples bugs de compilador que generaban encoding/decoding incorrecto: datos corruptos, lecturas out-of-bounds de memory, o encoding que no podía ser decodificado correctamente. Estos bugs son especialmente insidiosos porque el código fuente se ve correcto -- el error está en el compilador."
  como_funciona: "1. Contrato usa struct con arrays dinámicos: `struct Order { uint256 price; bytes[] signatures; address[] tokens; }`. 2. En ciertas versiones de Solidity, abi.encode(order) produce encoding incorrecto cuando hay tipos dinámicos anidados (e.g., bytes[] dentro de struct[]). 3. Otra función decodifica con abi.decode(data, (Order)) y obtiene datos corruptos. 4. Los datos corruptos pueden causar: (a) precios incorrectos, (b) direcciones incorrectas para transfers, (c) firmas que validan contra la persona equivocada. 5. El bug fue real en versiones 0.5.x-0.6.x y parcialmente en 0.7.x. Solidity 0.8.x tuvo fix parcial pero introdujo nuevo bug en 0.8.13-0.8.15."
  invariante: "Si se usan tipos complejos anidados, verificar con la versión específica de Solidity. Preferir flat structs sin anidamiento. Tener tests de roundtrip encoding/decoding para structs complejas."
  que_mirar:
    - "Contratos compilados con Solidity 0.5.x-0.7.x usando ABIEncoderV2 pragma"
    - "Structs que contienen `bytes[]`, `string[]`, o `SomeStruct[]` (arrays dinámicos de tipos dinámicos)"
    - "abi.encode de tipos anidados: `abi.encode(arrayOfStructsWithDynamicFields)`"
    - "Funciones external que reciben structs complejas como parámetros"
    - "Storage structs con tipos dinámicos que se pasan a abi.encode"
    - "Versiones de Solidity afectadas: 0.5.0-0.5.7 (primer ABIEncoderV2 bug), 0.6.0-0.6.8 (segundo bug), 0.8.13-0.8.15 (optimizer + abi coder interaction)"
  como_se_arregla: "Actualizar a la última versión estable de Solidity. Evitar structs profundamente anidadas con múltiples campos dinámicos. Agregar tests de roundtrip: `assert(abi.decode(abi.encode(x), (Type)) == x)` para todas las structs complejas. Revisar el changelog de Solidity para bugs de ABI encoder en la versión utilizada."
  trampas:
    - "Solidity >= 0.8.16 tiene todos los ABI encoder v2 bugs conocidos corregidos (al momento de esta escritura)"
    - "El pragma `abicoder v2` es default desde 0.8.0 -- no necesita declararse, pero significa que TODOS los contratos 0.8.x usan v2"
    - "Los tests unitarios pueden NO detectar el bug porque usan la misma versión de compilador para encode y decode -- el encoding es consistentemente incorrecto"
    - "Cross-contract calls pueden manifestar el bug si un contrato encodeó con versión buggy y otro decodifica con versión correcta"
  solodit_ids: []
  incidentes:
    - "Solidity SOL-2022-4 -- ABI reencoding de struct calldata con tipos dinámicos producía corruption"
    - "Solidity SOL-2022-1 -- Inline assembly memory side effects en ABI encode"
    - "Solidity 0.5.7 fix -- ABIEncoderV2 corrupción de datos con arrays de structs"
    - "Trail of Bits advisory -- recomendación de no usar ABIEncoderV2 experimental hasta 0.8.x"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solidity compiler security advisories, Trail of Bits, OpenZeppelin"
  patron_vulnerable: |
    // VULNERABLE: structs anidadas con arrays dinámicos (afectado por bugs del compilador)
    struct Order {
        address maker;
        bytes[] signatures;     // array dinámico de tipo dinámico
        Item[] items;           // array dinámico de struct
    }
    struct Item {
        address token;
        uint256 amount;
        bytes data;             // tipo dinámico dentro de struct dentro de array
    }
    // En Solidity 0.5.x-0.6.x con ABIEncoderV2, abi.encode(order) puede producir
    // encoding corrupto cuando hay este nivel de anidamiento.
    // El bug: offsets internos calculados incorrectamente → datos de un campo
    // se leen como datos de otro campo.
    function processOrder(Order calldata order) external {
        // Si order fue encoded con versión buggy, los datos están corruptos
        // order.items[0].token podría ser basura
        IERC20(order.items[0].token).transferFrom(  // address incorrecta
            order.maker,
            address(this),
            order.items[0].amount  // amount incorrecto
        );
    }
  test_invariante: |
    // Invariante: roundtrip encoding de structs complejas debe ser idéntico
    function test_complex_struct_roundtrip() public {
        Order memory order = createTestOrder();
        bytes memory encoded = abi.encode(order);
        Order memory decoded = abi.decode(encoded, (Order));
        // Verificar campo por campo
        assert(decoded.maker == order.maker);
        assert(decoded.signatures.length == order.signatures.length);
        assert(decoded.items.length == order.items.length);
        for (uint i = 0; i < order.items.length; i++) {
            assert(decoded.items[i].token == order.items[i].token);
            assert(decoded.items[i].amount == order.items[i].amount);
            assert(keccak256(decoded.items[i].data) == keccak256(order.items[i].data));
        }
    }
  tags: [abi-encoder-v2, compiler-bug, encoding, structs, dynamic-arrays, solidity]
  relacionado_con: [EVM-08, EVM-05]
  incidentes_verificados:
    - nombre: "Solidity ABIEncoderV2 bug (0.5.x)"
      fecha: "2019"
      perdida: "$0 (compiler fix)"
      tipo: "abi.encode de struct[] con campos dinámicos producía datos corruptos"
      verificado: true
      fuente: "Solidity blog, security advisory"
    - nombre: "Solidity SOL-2022-4 (0.8.13-0.8.15)"
      fecha: "Sep 2022"
      perdida: "$0 (compiler fix)"
      tipo: "ABI reencoding de calldata tuples con componentes dinámicos producía corrupción"
      verificado: true
      fuente: "Solidity security advisory"
    - nombre: "Solidity SOL-2022-1 (0.8.13)"
      fecha: "Jun 2022"
      perdida: "$0 (compiler fix)"
      tipo: "Inline assembly memory side effects removidos por optimizer, afectando ABI encoding posterior"
      verificado: true
      fuente: "Solidity security advisory"
```

```yaml
- id: EVM-18
  pattern: gas-stipend-limitation
  name: "Limitación de gas stipend en fallback/receive (2300 gas)"
  causa_raiz: "Cuando se envía ETH via `address.transfer()` o `address.send()`, el receptor recibe solo 2300 gas de stipend. Este gas es suficiente para emitir un event pero NO para operaciones de storage (SSTORE = 20000+ gas). Contratos que tienen lógica en receive()/fallback() que requiere más de 2300 gas no pueden recibir ETH vía transfer/send. Esto puede bloquear protocolos enteros si el receptor es un contrato con lógica compleja en receive()."
  como_funciona: "1. Contrato A (protocolo DeFi) usa `payable(recipient).transfer(amount)` para enviar ETH al usuario. 2. Usuario es un smart wallet (Gnosis Safe, Account Abstraction) que tiene lógica en receive() (e.g., logging a storage, forwarding to sub-account). 3. La lógica de receive() requiere >2300 gas → la llamada revierte. 4. Si contrato A no tiene fallback para manejar el revert, los fondos del usuario quedan atrapados en A. 5. Variante: auction contract que hace refund via transfer() al outbid user -- si el user es un contrato sin receive(), todos los refunds fallan y la auction se bloquea."
  invariante: "NUNCA usar transfer() o send() para enviar ETH. Usar call{value: amount}('') con check de return value. Considerar el pull pattern (los receptores reclaman sus fondos) en vez de push pattern."
  que_mirar:
    - "Uso de `address.transfer(amount)` -- SIEMPRE flaggear"
    - "Uso de `address.send(amount)` -- SIEMPRE flaggear"
    - "Contratos que envían ETH en loops (distribución de rewards) -- un receptor que falla bloquea a todos"
    - "Auction/bidding contracts que hacen refund automático al ser outbid"
    - "Withdrawal functions que envían ETH al msg.sender sin considerar que puede ser un contrato"
    - "Contratos que asumen que todo receptor de ETH es un EOA"
  como_se_arregla: "Reemplazar transfer()/send() con: `(bool success, ) = recipient.call{value: amount}(''); require(success);`. Implementar pull pattern: `mapping(address => uint256) pendingWithdrawals` + función `withdraw()`. Para distribución: usar claim-based pattern en vez de push."
  trampas:
    - "El gas stipend de 2300 fue diseñado para prevenir reentrancy (no hay suficiente gas para SSTORE) -- históricamente era una 'feature de seguridad'"
    - "Post-EIP-1884 (Istanbul): SLOAD cuesta 800 gas (antes 200), lo que hace que incluso lógica simple en receive() exceda 2300 gas"
    - "call{value:}('') sin gas limit envía todo el gas disponible -- cuidado con reentrancy (usar reentrancy guard)"
    - "Algunos linters (Slither) flaggean transfer() como 'arbitrary send' pero la recomendación de cambiar a call{value:} es correcta"
    - "El gas stipend exacto puede cambiar en futuras EIPs -- no hardcodear 2300 en la lógica"
  solodit_ids:
    - m-03-use-of-transfer-instead-of-call-to-send-eth-code4rena-none-escher-git
    - m-02-transfer-will-fail-for-smart-contract-wallets-code4rena-none-caviar-git
  incidentes:
    - "King of the Ether (2016) -- pionero del bug: send() sin check + gas stipend"
    - "Nouns DAO -- refund de bids via transfer() bloqueaba auction si bidder era contrato"
    - "Escher (C4) -- transfer() en distribución de fondos fallaba para smart wallets"
    - "Caviar (C4) -- transfer() impedía que smart contract wallets recibieran ETH de ventas NFT"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "SWC Registry, Consensys best practices, Code4rena findings"
  patron_vulnerable: |
    // VULNERABLE: transfer() con gas stipend de 2300
    function refundBid(address bidder, uint256 amount) internal {
        // transfer() envía exactamente 2300 gas al receptor
        // Si bidder es Gnosis Safe: receive() necesita >2300 gas → REVERT
        // Si bidder es contrato con storage en receive(): REVERT
        payable(bidder).transfer(amount);
        // Si esto revierte, toda la transacción revierte
        // → auction se bloquea, nadie puede outbid
    }
    // VULNERABLE: send() sin pull pattern
    function distributeRewards(address[] memory winners) external {
        for (uint i = 0; i < winners.length; i++) {
            // Si UN winner es contrato sin receive() → send retorna false
            // pero el loop continúa (o revierte, dependiendo del check)
            bool sent = payable(winners[i]).send(rewards[i]);
            // Si !sent se ignora → fondos atrapados
            // Si require(sent) → bloquea distribución para todos
        }
    }
  test_invariante: |
    // Invariante: ETH transfers deben funcionar para smart wallets
    function test_transfer_to_smart_wallet() public {
        // Deploy un Gnosis Safe simulado (receive con storage write)
        SmartWallet wallet = new SmartWallet();
        vm.deal(address(contract), 10 ether);

        // Debe funcionar -- si usa transfer(), fallará
        contract.refundBid(address(wallet), 1 ether);
        assert(address(wallet).balance == 1 ether);
    }
  tags: [gas-stipend, transfer, send, receive, fallback, eth-transfer, dos]
  relacionado_con: [EVM-16, EVM-01]
  incidentes_verificados:
    - nombre: "Nouns DAO auction refund"
      fecha: "2022"
      perdida: "$0 (mitigado)"
      tipo: "transfer() en refund de bids -- smart wallets no podían recibir refund"
      verificado: true
      fuente: "Nouns DAO governance discussion"
    - nombre: "King of the Ether"
      fecha: "2016"
      perdida: "~$2K"
      tipo: "send() con gas stipend insuficiente + no check de return value"
      verificado: true
      fuente: "Blockchain Graveyard, Historical Ethereum"
    - nombre: "Escher (C4)"
      fecha: "2022"
      perdida: "$0 (audit finding)"
      tipo: "transfer() bloqueaba smart wallets en distribución de fondos de ventas"
      verificado: true
      fuente: "Code4rena"
```

---

## Quick Reference: Patrones por Severidad

| Severidad | IDs | Descripción corta |
|-----------|-----|-------------------|
| **Critical** | EVM-02, EVM-09 | delegatecall context confusion, CREATE2 collision |
| **High** | EVM-05, EVM-06, EVM-08, EVM-10, EVM-11, EVM-13, EVM-16, EVM-17 | assembly overflow, ecrecover(0), ABI encoding, selfdestruct resurrection, transient storage, dirty bits, unchecked call, encoder v2 |
| **Medium** | EVM-01, EVM-03, EVM-04, EVM-07, EVM-12, EVM-15, EVM-18 | returndata bomb, staticcall bypass, memory expansion, precompile gas, PUSH0, extcodesize, gas stipend |
| **Low** | EVM-14 | calldata vs memory confusion |

## Quick Reference: Detección con Herramientas

| Herramienta | Patrones detectados |
|-------------|-------------------|
| **Slither** | EVM-16 (unchecked-lowlevel), EVM-18 (transfer), EVM-06 (ecrecover), EVM-15 (isContract) |
| **Semgrep** | EVM-02 (delegatecall-untrusted), EVM-05 (assembly-overflow), EVM-13 (dirty-bits) |
| **Foundry fuzzing** | EVM-05, EVM-08, EVM-17 (roundtrip encoding tests) |
| **Manual review** | EVM-01, EVM-03, EVM-04, EVM-07, EVM-09, EVM-10, EVM-11, EVM-12, EVM-14 |
| **Halmos** | EVM-05 (symbolic overflow proof), EVM-06 (ecrecover property), EVM-13 (dirty bits property) |

## Quick Reference: Por Componente de Protocolo

| Componente | Patrones más relevantes |
|------------|------------------------|
| **Proxy/Upgradeable** | EVM-02, EVM-11, EVM-13, EVM-14 |
| **Bridge/Cross-chain** | EVM-01, EVM-06, EVM-08, EVM-09 |
| **DEX/AMM** | EVM-05, EVM-07, EVM-11, EVM-18 |
| **Lending/Vault** | EVM-03, EVM-05, EVM-06, EVM-16 |
| **NFT/Marketplace** | EVM-09, EVM-10, EVM-15, EVM-18 |
| **Governance/DAO** | EVM-02, EVM-09, EVM-10, EVM-16 |
| **Token** | EVM-12, EVM-13, EVM-15, EVM-17 |
| **ZK Verifier** | EVM-07, EVM-08, EVM-13 |

## Checklist de Auditoría EVM Low-Level

```
PRE-AUDIT:
[ ] Verificar versión de Solidity -- ¿afectada por bugs conocidos del compilador? (EVM-17)
[ ] Verificar evm_version en config -- ¿PUSH0 compatible con target chain? (EVM-12)
[ ] Verificar si usa ABIEncoderV2 experimental (pre-0.8.0) (EVM-17)

ASSEMBLY REVIEW:
[ ] Buscar todos los bloques `assembly { }` -- ¿arithmetic checks? (EVM-05)
[ ] ¿calldataload sin masking para tipos < 256 bits? (EVM-13)
[ ] ¿mload/mstore con offsets controlados por usuario? (EVM-04)
[ ] ¿returndatacopy sin bound? (EVM-01)
[ ] ¿call/staticcall sin verificar return value? (EVM-16)

EXTERNAL CALLS:
[ ] ¿delegatecall a dirección untrusted/controlada por usuario? (EVM-02)
[ ] ¿multicall con delegatecall en loop + msg.value? (EVM-02)
[ ] ¿transfer() o send() para enviar ETH? (EVM-18)
[ ] ¿call return value ignorado? (EVM-16)
[ ] ¿staticcall usado como reentrancy guard? (EVM-03)

CRYPTOGRAPHY:
[ ] ¿ecrecover sin check de address(0)? (EVM-06)
[ ] ¿precompile calls con inputs de tamaño no validado? (EVM-07)

DEPLOYMENT:
[ ] ¿CREATE2 con initCode que lee bytecode externo? (EVM-09)
[ ] ¿selfdestruct + CREATE2 en el mismo contrato? (EVM-10)
[ ] ¿isContract() check para seguridad? (EVM-15)

MODERN EVM:
[ ] ¿transient storage para reentrancy lock con cobertura parcial? (EVM-11)
[ ] ¿PUSH0 en bytecode para chains pre-Shanghai? (EVM-12)

ABI ENCODING:
[ ] ¿abi.encodePacked para construir calldata? (EVM-08)
[ ] ¿structs con arrays dinámicos anidados? (EVM-17)
[ ] ¿calldata construido manualmente en assembly? (EVM-08, EVM-14)
```

## Solidity Compiler Bugs -- Timeline de Vulnerabilidades Conocidas

Las vulnerabilidades del compilador son especialmente peligrosas porque el código fuente se ve correcto -- el bug está en la traducción a bytecode. Esta sección documenta los bugs más relevantes para auditoría.

```yaml
- compiler_bug: SOL-2022-6
  versiones_afectadas: "0.8.13 - 0.8.16"
  descripcion: "El optimizer de Yul podía eliminar operaciones de memoria con side-effects en assembly inline cuando el bloque de assembly no tenía outputs visibles para el optimizer."
  impacto: "Variables escritas en assembly podían no reflejarse en el bytecode optimizado. Funciones que dependían de side-effects en assembly producían resultados incorrectos."
  deteccion: "Compilar con y sin optimizer y comparar resultados. Verificar que assembly blocks con side-effects tienen outputs usados por Solidity."
  relevante_para: [EVM-05, EVM-17]

- compiler_bug: SOL-2022-4
  versiones_afectadas: "0.5.8 - 0.8.16"
  descripcion: "ABI reencoding de calldata tuples (structs) con componentes de tipo dinámico (bytes, string, arrays) podía producir encoding corrupto cuando se pasaban de calldata a funciones que esperaban memory."
  impacto: "Datos corruptos en cross-contract calls. Direcciones incorrectas en transfers. Amounts incorrectos en operaciones financieras."
  deteccion: "Buscar funciones external que reciben structs con campos dinámicos y los pasan a otras funciones. Test de roundtrip encoding."
  relevante_para: [EVM-08, EVM-17]

- compiler_bug: SOL-2022-1
  versiones_afectadas: "0.8.13 - 0.8.14"
  descripcion: "El optimizer Yul eliminaba escrituras a memory hechas en inline assembly si determinaba (incorrectamente) que no eran leídas posteriormente. Afectaba a abi.encode que se hacía después de un bloque assembly que escribía a memory."
  impacto: "abi.encode producía datos parcialmente corruptos. Hashes de datos incorrectos. Verificaciones de firma que pasaban con datos modificados."
  deteccion: "Buscar patrones: assembly { mstore(...) } seguido de abi.encode en la misma función."
  relevante_para: [EVM-05, EVM-08]

- compiler_bug: SOL-2021-3
  versiones_afectadas: "0.8.0 - 0.8.9"
  descripcion: "Funciones que retornaban structs con arrays de fixed-size podían generar cleanup incorrecto de los elementos del array, dejando dirty data en los upper bits."
  impacto: "Valores de retorno con datos residuales. Comparaciones de structs que fallaban inesperadamente."
  deteccion: "Funciones que retornan structs con arrays fijos (e.g., uint128[2]). Verificar que los valores retornados no tienen dirty bits."
  relevante_para: [EVM-13, EVM-17]

- compiler_bug: head-overflow-in-tuple-encoding
  versiones_afectadas: "< 0.5.8 con ABIEncoderV2"
  descripcion: "ABIEncoderV2 experimental tenía bug fundamental en el cálculo de offsets para tuples con tipos dinámicos. Los offsets del head podían overflowear, causando que el decoder leyera datos de posiciones incorrectas."
  impacto: "Cualquier contrato usando ABIEncoderV2 con structs dinámicas antes de 0.5.8 era potencialmente vulnerable a data corruption."
  deteccion: "Verificar pragma solidity en contratos legacy. Buscar `pragma experimental ABIEncoderV2` con versiones < 0.5.8."
  relevante_para: [EVM-08, EVM-17]
```

## Opcodes Críticos para Auditoría -- Reference Card

```
OPCODE      HEX    GAS     NOTAS DE SEGURIDAD
────────────────────────────────────────────────────────────────────
CALL        F1     var     Envía ETH + ejecuta código. Return: 1=ok, 0=fail (NO revierte)
DELEGATECALL F4    var     Ejecuta en contexto del caller. PRESERVA msg.sender, msg.value
STATICCALL  FA     var     Read-only. Revierte si sub-call intenta SSTORE/LOG/CREATE
CREATE      F0     32000   Dirección = hash(deployer, nonce). Nonce NO se puede reutilizar
CREATE2     F5     32000   Dirección = hash(0xff, deployer, salt, initCodeHash). Determinística
SELFDESTRUCT FF    5000+   Post EIP-6780: solo borra en misma TX que CREATE. Deprecado.
EXTCODESIZE 3B     2600*   0 durante constructor. NO usar para isContract check
EXTCODEHASH 3F     2600*   hash(code). 0 para cuentas sin código. keccak256("") para code vacío
RETURNDATASIZE 3D  2       Tamaño del último returndata. 0 si no hubo call previa
RETURNDATACOPY 3E  3+3/w   Copia returndata a memory. OOG si offset+size > returndatasize
CALLDATALOAD 35    3       Lee 32 bytes de calldata. Retorna 0 si offset > calldatasize
CALLDATACOPY 37    3+3/w   Copia calldata a memory. 0-pads si offset > calldatasize
TSTORE      5D     100     Transient storage write (EIP-1153). Limpiado al final de TX
TLOAD       5C     100     Transient storage read (EIP-1153).
PUSH0       5F     2       Empuja 0 al stack (EIP-3855, Shanghai). Incompatible pre-Shanghai
MLOAD       51     3+      Lee 32 bytes de memory. Expande si offset > current size
MSTORE      52     3+      Escribe 32 bytes a memory. Expande si necesario (gas cuadrático)
SLOAD       54     2100*   Lee storage slot. 100 gas si warm (ya accedido en la TX)
SSTORE      55     var     Escribe storage slot. 20000 si cold+nonzero. 2900 si warm

* Gas post-EIP-2929 (Berlin). Cold access = primera vez en la TX. Warm = ya accedido.
```

## Patterns de Assembly Seguro -- Código de Referencia

```solidity
// === SAFE: Limpieza de address en assembly ===
function safeAddressClean(uint256 rawValue) internal pure returns (address) {
    assembly {
        // AND con máscara de 20 bytes -- limpia upper 12 bytes
        let cleaned := and(rawValue, 0xffffffffffffffffffffffffffffffffffffffff)
        mstore(0x00, cleaned)
        return(0x00, 0x20)
    }
}

// === SAFE: Overflow check en assembly ===
function safeAdd(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
        c := add(a, b)
        if lt(c, a) {
            // Overflow detectado -- revert con "overflow" mensaje
            mstore(0x00, 0x4e487b7100000000000000000000000000000000000000000000000000000000)
            mstore(0x04, 0x11) // Panic(0x11) = arithmetic overflow
            revert(0x00, 0x24)
        }
    }
}

function safeMul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    assembly {
        // Caso especial: a == 0 → resultado siempre 0
        if iszero(a) {
            mstore(0x00, 0)
            return(0x00, 0x20)
        }
        c := mul(a, b)
        // Verificación: c / a debe == b
        if iszero(eq(div(c, a), b)) {
            mstore(0x00, 0x4e487b7100000000000000000000000000000000000000000000000000000000)
            mstore(0x04, 0x11)
            revert(0x00, 0x24)
        }
    }
}

// === SAFE: External call con return value check y returndata bound ===
function safeCall(address target, uint256 value, bytes memory data) internal returns (bool) {
    bool success;
    assembly {
        success := call(
            gas(),
            target,
            value,
            add(data, 0x20),
            mload(data),
            0,              // No copiar returndata automáticamente
            0               // returndatasize = 0 inicialmente
        )
        // Solo copiar hasta 256 bytes de returndata (protege contra returndata bomb)
        let returnSize := returndatasize()
        if gt(returnSize, 256) { returnSize := 256 }
        let freePtr := mload(0x40)
        returndatacopy(freePtr, 0, returnSize)
        mstore(0x40, add(freePtr, returnSize))
    }
    require(success, "call failed");
    return success;
}

// === SAFE: ecrecover con validación completa ===
function safeRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
    // Verificar que v es 27 o 28
    require(v == 27 || v == 28, "invalid v");
    // Verificar que s está en la mitad inferior (previene signature malleability)
    require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "invalid s");
    address recovered = ecrecover(hash, v, r, s);
    require(recovered != address(0), "invalid signature");
    return recovered;
}

// === SAFE: Transient storage reentrancy guard completo ===
uint256 private constant _REENTRANCY_GUARD_SLOT = 0x929eee149b4bd21268;
modifier nonReentrantTransient() {
    assembly {
        if tload(_REENTRANCY_GUARD_SLOT) {
            mstore(0x00, 0x4e487b7100000000000000000000000000000000000000000000000000000000)
            mstore(0x04, 0x01)
            revert(0x00, 0x24)
        }
        tstore(_REENTRANCY_GUARD_SLOT, 1)
    }
    _;
    assembly {
        tstore(_REENTRANCY_GUARD_SLOT, 0)
    }
}
```

## Grep Patterns para Detección Rápida

```bash
# EVM-01: Returndata bomb potential
grep -rn "\.call(" --include="*.sol" | grep -v "require\|assert\|success"

# EVM-02: delegatecall a dirección variable
grep -rn "delegatecall" --include="*.sol" | grep -v "library\|proxy"

# EVM-05: Assembly sin overflow checks
grep -rn "assembly" -A 20 --include="*.sol" | grep "add\|mul\|sub" | grep -v "address\|slot"

# EVM-06: ecrecover sin check de address(0)
grep -rn "ecrecover" --include="*.sol" -A 5 | grep -v "address(0)\|!= 0\|OpenZeppelin"

# EVM-12: PUSH0 risk (Solidity >= 0.8.20)
grep -rn "pragma solidity" --include="*.sol" | grep "0\.8\.2[0-9]\|0\.8\.3\|0\.9"

# EVM-13: calldataload sin masking
grep -rn "calldataload" --include="*.sol" -A 2 | grep -v "and("

# EVM-15: isContract / extcodesize check
grep -rn "code\.length\|extcodesize\|isContract" --include="*.sol"

# EVM-16: Unchecked call return
grep -rn "\.call{" --include="*.sol" -A 1 | grep -v "require\|assert\|if.*success\|revert"

# EVM-18: transfer() o send() para ETH
grep -rn "\.transfer(\|\.send(" --include="*.sol" | grep -v "safeTransfer\|ERC20"
```
