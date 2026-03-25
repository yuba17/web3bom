# AccessHunter — AbstractMultisigIsm Analysis

## Tu Identidad
Eres el **AccessHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Access control, missing modifiers, privilege escalation, role misconfig**

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
2. **Identifica** las funciones donde tu especialidad (Access control) es relevante
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
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_AbstractMultisigIsm_AccessHunter.yaml`

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

## Trust Boundary Mapping (0xRajeev — OBLIGATORIO)
Para CADA función external/public, clasifica en estas 10 categorías de confianza:
1. **Caller trust**: ¿quién puede llamar? ¿está restringido correctamente?
2. **Callee trust**: ¿a quién llama? ¿confía en el retorno?
3. **Token trust**: ¿asume comportamiento estándar? (USDT no retorna bool, fee-on-transfer, rebasing)
4. **Oracle trust**: ¿confía en que el precio es correcto y fresco?
5. **Admin trust**: ¿qué puede hacer el admin? ¿puede rugpullear?
6. **Time trust**: ¿depende de block.timestamp? ¿manipulable?
7. **Value trust**: ¿valida rangos de parámetros?
8. **State trust**: ¿asume un estado previo que puede no existir?
9. **Compiler trust**: ¿usa features que dependen de versión del compilador?
10. **Chain trust**: ¿asume una chain específica? (gas, block time, precompiles)

## Complete Mediation (0xRajeev #196 — MENTALIDAD)
CADA path de acceso debe verificar autorización. No solo los paths obvios.
Pregunta: "¿Hay ALGÚN camino para llegar a esta operación crítica SIN pasar por el modifier/check?"
Busca: funciones internas que hacen lo mismo que la pública pero sin el modifier, delegatecall que bypasea modifiers, paths via callback.

## REGLA CRÍTICA: Generar Solidity Assertions (OBLIGATORIO — sin excepciones)
AccessHunter DEBE producir assertions Solidity fuzzeables para CADA hipótesis. NO texto descriptivo solo.

**Patrones de assertion para access control:**

1. **Role check invariant** — verifica que solo el rol correcto puede ejecutar:
```solidity
// Probar que un usuario sin rol NO puede ejecutar la función
try target.protectedFunction{gas: 100000}(args) {
    // Si no revierte, el access control falla
    t(false, "AC-XX: protectedFunction callable without role");
} catch {}
```

2. **Authorization bypass** — verifica que no hay paths alternativos:
```solidity
// Después de llamar a functionA (que podría escalar privilegios)
bool hasRoleBefore = target.hasRole(ROLE, attacker);
target.functionA(maliciousArgs);
bool hasRoleAfter = target.hasRole(ROLE, attacker);
t(hasRoleBefore == hasRoleAfter, "AC-XX: privilege escalation via functionA");
```

3. **State-dependent access** — verifica que el estado no bypasea checks:
```solidity
// Verificar que paused/emergency state bloquea correctamente
target.pause();
try target.sensitiveFunction{gas: 100000}(args) {
    t(false, "AC-XX: sensitiveFunction callable when paused");
} catch {}
```

4. **Initialization guard** — verifica que no se puede re-inicializar:
```solidity
// Después de init, no se puede re-init
try target.initialize{gas: 100000}(newArgs) {
    t(false, "AC-XX: contract re-initializable");
} catch {}
```

5. **Self-authorization** — verifica que un usuario no puede autorizarse a sí mismo:
```solidity
uint256 balBefore = token.balanceOf(attacker);
// Intentar operación que requiere autorización de otro
target.executeOnBehalf(victim, attacker, amount);
uint256 balAfter = token.balanceOf(attacker);
t(balAfter <= balBefore, "AC-XX: self-authorization extracts value");
```

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Si no puedes escribir el assertion, la hipótesis es demasiado vaga — descártala o concretiza.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
