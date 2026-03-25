# SignatureHunter — AbstractMultisigIsm Analysis

## Tu Identidad
Eres el **SignatureHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Signature replay, permit abuse, EIP-712 issues, nonce handling, ecrecover validation, approval/allowance patterns, Permit2, meta-transactions**

## Tu Objetivo
Analizar `AbstractMultisigIsm` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/isms/multisig/AbstractMultisigIsm.sol`
**Dominio**: proxy


```solidity
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

/*@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@  HYPERLANE  @@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
@@@@@@@@@       @@@@@@@@*/

// ============ External Imports ============
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// ============ Internal Imports ============
import {IMultisigIsm} from "../../interfaces/isms/IMultisigIsm.sol";
import {PackageVersioned} from "../../PackageVersioned.sol";

/**
 * @title AbstractMultisig
 * @notice Manages per-domain m-of-n Validator sets
 * @dev See ./AbstractMerkleRootMultisigIsm.sol and ./AbstractMessageIdMultisigIsm.sol
 * for concrete implementations of `digest` and `signatureAt`.
 * @dev See ./StaticMultisigIsm.sol for concrete implementations.
 */
abstract contract AbstractMultisig is PackageVersioned {
    /**
     * @notice Returns the digest to be used for signature verification.
     * @param _metadata ABI encoded module metadata
     * @param _message Formatted Hyperlane message (see Message.sol).
     * @return digest The digest to be signed by validators
     */
    function digest(
        bytes calldata _metadata,
        bytes calldata _message
    ) internal view virtual returns (bytes32);

    /**
     * @notice Returns the signature at a given index from the metadata.
     * @param _metadata ABI encoded module metadata
     * @param _index The index of the signature to return
     * @return signature Packed encoding of signature (65 bytes)
     */
    function signatureAt(
        bytes calldata _metadata,
        uint256 _index
    ) internal pure virtual returns (bytes calldata);

    /**
     * @notice Returns the number of signatures in the metadata.
     * @param _metadata ABI encoded module metadata
     * @return count The number of signatures
     */
    function signatureCount(
        bytes calldata _metadata
    ) public pure virtual returns (uint256);
}

/**
 * @title AbstractMultisigIsm
 * @notice Manages per-domain m-of-n Validator sets of AbstractMultisig that are used to verify
 * interchain messages.
 */
abstract contract AbstractMultisigIsm is AbstractMultisig, IMultisigIsm {
    // ============ Virtual Functions ============
    // ======= OVERRIDE THESE TO IMPLEMENT =======

    /**
     * @notice Returns the set of validators responsible for verifying _message
     * and the number of signatures required
     * @dev Can change based on the content of _message
     * @dev Signatures provided to `verify` must be consistent with validator ordering
     * @param _message Hyperlane formatted interchain message
     * @return validators The array of validator addresses
     * @return threshold The number of validator signatures needed
     */
    function validatorsAndThreshold(
        bytes calldata _message
    ) public view virtual returns (address[] memory, uint8);

    // ============ Public Functions ============

    /**
     * @notice Requires that m-of-n validators verify a merkle root,
     * and verifies a merkle proof of `_message` against that root.
     * @dev Optimization relies on the caller sorting signatures in the same order as validators.
     * @dev Employs https://www.geeksforgeeks.org/two-pointers-technique/ to minimize gas usage.
     * @param _metadata ABI encoded module metadata
     * @param _message Formatted Hyperlane message (see Message.sol).
     */
    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) public view returns (bool) {
        bytes32 _digest = digest(_metadata, _message);
        (
            address[] memory _validators,
            uint8 _threshold
        ) = validatorsAndThreshold(_message);
        require(_threshold > 0, "No MultisigISM threshold present for message");

        uint256 _validatorCount = _validators.length;
        uint256 _validatorIndex = 0;
        // Assumes that signatures are ordered by validator
        for (uint256 i = 0; i < _threshold; ++i) {
            address _signer = ECDSA.recover(_digest, signatureAt(_metadata, i));
            // Loop through remaining validators until we find a match
            while (
                _validatorIndex < _validatorCount &&
                _signer != _validators[_validatorIndex]
            ) {
                ++_validatorIndex;
            }
            // Fail if we never found a match
            require(_validatorIndex < _validatorCount, "!threshold");
            ++_validatorIndex;
        }
        return true;
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre AbstractMultisigIsm
Buscando 'AbstractMultisigIsm' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (64ms)


### HIGH findings en dominio proxy
Buscando 'AbstractMultisigIsm signatureAt signatureCount validatorsAndThreshold' [SQLite FTS5] (dominio: proxy)...
Sin resultados para los criterios dados. (40ms)

### Cross-domain HIGH relevantes
Buscando 'AbstractMultisigIsm signatureAt signatureCount validatorsAnd' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (5ms)

## Briefing del Dominio (proxy)
### Briefing principal: proxy

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Standard OpenZeppelin TransparentUpgradeableProxy and UUPS are safe for proxy-vs-implementation overlap -- focus on CUSTOM proxies
  ⚠ The real danger is between V1 and V2 of the IMPLEMENTATION, not proxy vs implementation
  ⚠ Enums and small types packed together can shift unexpectedly
  ⚠ reinitializer(version) is legitimate for V2 migration -- only flag if the version number allows re-calling
  ⚠ On TransparentProxy, the impact is lower because upgrade logic is in the proxy, not implementation
  ⚠ Some protocols intentionally leave implementation uninitialized if it has no selfdestruct path
  ⚠ OpenZeppelin v5 UUPSUpgradeable forces you to override _authorizeUpgrade (compile error if you don't) -- but the override can still be empty
  ⚠ The auth check might be present but bypass-able (e.g., checks a role that was not properly set up)
  ⚠ Transparent proxies are NOT affected -- upgrade logic is in the proxy admin
  ⚠ On L2s with sequencer-ordered transactions (Optimism, Arbitrum), front-running is harder but not impossible
  ⚠ Some protocols use a two-phase deploy intentionally with a deployer whitelist -- verify the whitelist is enforced
  ⚠ This is often reported as Medium, not Critical, because it requires monitoring the mempool at deploy time

## Contexto Chimera (OBLIGATORIO — lee antes de escribir Solidity)

Tu código se insertará en un archivo `PropertiesX.sol` que hereda de `Properties.sol`.
Properties.sol hereda del Setup (variables de estado, contratos, actores).
NO escribas `function invariant_...()` — solo el BODY. merge_invariants.py genera el wrapper.

### Variables y contratos disponibles (heredados de Setup):
```solidity
  MockHyperlaneEnvironment internal environment;
  uint32 internal constant ORIGIN = 1;
  uint32 internal constant DESTINATION = 2;
  TestInterchainGasPaymaster internal igp;
  InterchainAccountRouter internal originRouter;
  InterchainAccountRouter internal destRouter;
  bytes32 internal routerOverride;
  bytes32 internal ismOverride;
  ERC20Test internal feeToken;
  OwnableMulticall internal ica;
  MockMailbox internal originMailbox;
  MockMailbox internal destMailbox;
  uint256 internal ghost_totalMsgValueSent;
  uint256 internal ghost_routerBalanceBefore;
  uint256 internal ghost_callRemoteCount;
  uint256 internal ghost_handleCount;
  uint256 internal ghost_commitRevealCount;
  address internal constant ATTACKER = address(0xbabe);
  address internal constant USER1 = address(0x1111);
  address internal constant USER2 = address(0x2222);
```

### Funciones públicas del contrato target (getters y setters disponibles):
```solidity
  function signatureCount(bytes calldata _metadata) public pure virtual returns (uint256);
  function validatorsAndThreshold(bytes calldata _message) public view virtual returns (address[] memory, uint8);
  function verify(bytes calldata _metadata, bytes calldata _message) public view returns (bool);
```

### Ghost variables existentes (ya declaradas, puedes usarlas):
```solidity
  ghost_routerBalanceBefore = address(originRouter).balance;
```

### Helpers internos disponibles:
```solidity
  _setupChimera() internal;
```

### Assertion helpers (de chimera/Asserts.sol):
```solidity
t(bool condition, string memory msg)    // assert true
eq(uint256 a, uint256 b, string memory msg)  // assert ==
gte(uint256 a, uint256 b, string memory msg) // assert >=
lte(uint256 a, uint256 b, string memory msg) // assert <=
gt(uint256 a, uint256 b, string memory msg)  // assert >
lt(uint256 a, uint256 b, string memory msg)  // assert <
```

### REGLAS para tu código Solidity:
1. **Solo el body** — NO escribas `function invariant_...()`. Solo las líneas internas.
2. **Usa EXACTAMENTE las variables de arriba** — NO inventes nombres. Si no está listado, NO existe.
3. **Usa los getters listados arriba** — Si necesitas un valor del contrato, busca en la lista de funciones públicas.
4. **Usa helpers Chimera** — `t()`, `eq()`, `gte()`, NO `require()` ni `assert()`.
5. **Sin caracteres unicode** en strings — usa `--` en vez de `—`, ASCII puro.
6. **Si necesitas ghost vars nuevas**, declara en el campo `ghost_vars` del YAML, NO en el body.
7. **Si una función no está en la lista de arriba, NO LA USES.** Compilará mal.

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Signature replay) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `AMI` (ej: AMI-01, AMI-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_AbstractMultisigIsm_SignatureHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: AMI-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "AMI-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Signature & Permit Deep Check (OBLIGATORIO — para CADA uso de firma/permit en el contrato)

### Checklist ecrecover / ECDSA (7 items):
1. ¿`ecrecover` valida que el resultado NO es `address(0)`? (firma inválida retorna 0)
2. ¿Se usa OpenZeppelin ECDSA.recover() o se llama ecrecover directamente? (OZ previene malleable sigs)
3. ¿Se normaliza el valor `s`? (EIP-2: s debe estar en lower half → previene signature malleability)
4. ¿El `v` se valida como 27 o 28? (valores inválidos = comportamiento indefinido)
5. ¿Se usa `abi.encodePacked` con tipos de longitud variable? (collision: abi.encodePacked("ab","c") == abi.encodePacked("a","bc"))
6. ¿Hay protección contra front-running de la firma? (otro usuario puede ver la firma en mempool y usarla primero)
7. ¿La firma tiene deadline/expiry? (firma sin expiración = válida eternamente)

### Checklist EIP-712 / Domain Separator (5 items):
1. ¿El `DOMAIN_SEPARATOR` incluye `chainId`? (sin chainId → replay cross-chain post-fork)
2. ¿Se recalcula el `DOMAIN_SEPARATOR` si `chainId` cambia? (o está cacheado inmutablemente?)
3. ¿El `DOMAIN_SEPARATOR` incluye `address(this)`? (sin → replay en otro contrato del mismo protocolo)
4. ¿Los typeHash son correctos y únicos por función? (copy-paste de typeHash = replay entre funciones)
5. ¿Se hashea TODO el struct (no campos parciales)?

### Checklist Nonce (4 items):
1. ¿El nonce se incrementa ANTES del efecto? (si se incrementa después y hay revert parcial → replay)
2. ¿El nonce es per-address o global? (global = DoS: alguien consume tu nonce)
3. ¿Se puede usar nonce=0 como primer valor? (algunos contratos empiezan en 1, skip del 0 = confusión)
4. ¿Hay nonce-gap attack? (saltar nonces para invalidar firmas legítimas de otros usuarios)

### Checklist Permit / Permit2 (6 items):
1. ¿`permit()` puede ser front-runned? (atacante ve permit en mempool, lo ejecuta antes, luego hace transferFrom)
   → Mitigación: usar try/catch en permit, verificar allowance después
2. ¿Se verifica que el `permit` fue exitoso? (algunos tokens no implementan permit correctamente)
3. ¿Hay interacción con Permit2 (Uniswap)? Si sí: ¿se valida que la allowance de Permit2 es correcta?
4. ¿Approval infinita (`type(uint256).max`) se usa sin necesidad? (riesgo si el contrato es comprometido)
5. ¿Se revocan approvals después de usarlas? (allowance residual = attack surface)
6. ¿transferFrom puede ser llamada por alguien que NO debería tener acceso a los fondos?
   Bug real: Morpho Bundler3 ($2.6M) — approve iba al adapter en vez de al Bundler → cualquiera podía usar la allowance.

### Checklist Meta-Transactions / Gasless (3 items):
1. ¿El relayer puede censurar transacciones? (no reenviar la meta-tx)
2. ¿Se valida que msg.sender en el contexto correcto? (ERC-2771: _msgSender() vs msg.sender confusion)
3. ¿El gas price de la meta-tx puede ser manipulado para hacer DoS?

### Attack Patterns de Alta Prioridad:
- **Permit front-run**: usuario firma permit → atacante la usa primero → drains funds
- **Cross-chain replay**: firma válida en L1 reusada en L2 (o viceversa)
- **Same-chain replay**: firma sin nonce o con nonce reutilizable
- **Signature phishing**: usuario firma algo que parece inocuo pero autoriza transfer
- **Approval confusion**: approve va a contrato equivocado (Morpho Bundler3)
- **Deadline bypass**: firmas sin expiración usadas meses después en condiciones diferentes

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
