# FlowHunter — AbstractMultisigIsm Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

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
2. **Identifica** las funciones donde tu especialidad (Reentrancy) es relevante
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
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_AbstractMultisigIsm_FlowHunter.yaml`

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

## Flash Loan Hypothesis (OBLIGATORIO — responde para CADA función que modifica estado)
Después de tu análisis libre, pasa por estas 12 preguntas para cada función relevante:
1. ¿Lee estado manipulable? (getReserves, slot0, balanceOf, get_virtual_price)
2. ¿Ese estado afecta movimiento de fondos?
3. ¿Se puede leer y consumir en la misma tx? (sin delays/timelocks)
4. ¿Hay verificación post-acción? (patrón FREI-PI)
5. ¿Tiene reentrancy guard?
6. ¿Si es callback, verifica initiator? (no solo msg.sender == pool)
7. ¿Usa spot price (manipulable) o TWAP (más seguro)?
8. ¿Reward/share se calcula por balance instantáneo?
9. ¿Hay cap/threshold cruzable atómicamente? (pasar de "sano" a "liquidable" en 1 tx)
10. ¿Permite self-liquidation con bonus > flash fee?
11. ¿Fee rounding a zero con montos pequeños?
12. ¿Checkpoint usa storage (persistente) o memory (se pierde)?

>80% de los exploits flash loan siguen: FLASH → MANIPULATE STATE → EXTRACT VALUE → RESTORE → REPAY.
Si una función responde "sí" a las preguntas 1+2+3, es un candidato fuerte.

## Tabla de Tokens con Callbacks (REFERENCIA — consulta al analizar transfers/mints)
| Estándar | Función que dispara callback | Callback en receptor |
|----------|------------------------------|---------------------|
| ERC-721 | safeMint, safeTransferFrom | onERC721Received |
| ERC-1155 | safeTransferFrom, safeBatchTransferFrom | onERC1155Received, onERC1155BatchReceived |
| ERC-777 | send, transfer (DEPRECADO pero existe) | tokensReceived (via ERC-1820 registry) |
| ERC-677 | transferAndCall (LINK, xDAI) | onTokenTransfer |
| ETH nativo | transfer, call{value} | receive(), fallback() |

⚠ Las funciones "safe" son PARADÓJICAMENTE más peligrosas — ejecutan callbacks al receptor.
⚠ Read-only reentrancy: funciones view que leen state de un pool durante callback cuando el state es inconsistente (ChainSecurity/Curve).

## State Machine Model (OBLIGATORIO — output incluido en hyp_*.yaml)
Modela el componente como una máquina de estados finita (FSM). Este output es CRÍTICO — lo usará DeepDiveHunter.

**Paso 1 — Identificar estados:**
Lista TODOS los estados posibles del contrato/posición/usuario. Ejemplos:
  - Vault: EMPTY → ACTIVE → PAUSED → MIGRATING
  - Position: OPEN → HEALTHY → UNDERWATER → LIQUIDATABLE → LIQUIDATED → CLOSED
  - Order: PENDING → FILLED → PARTIALLY_FILLED → CANCELLED → EXPIRED

**Paso 2 — Mapear transiciones:**
Para CADA par de estados, identifica qué función(es) ejecutan la transición:
```
HEALTHY → UNDERWATER: price drop (oracle update, no función directa)
UNDERWATER → LIQUIDATABLE: cuando ltv > lltv (automático por precio)
LIQUIDATABLE → LIQUIDATED: liquidate() / preLiquidate()
OPEN → CLOSED: withdraw() con amount=totalBalance
```

**Paso 3 — Buscar anomalías (AQUÍ ESTÁN LOS BUGS):**
1. **Transiciones ilegales**: ¿Se puede ir de LIQUIDATED → ACTIVE? ¿De CLOSED → OPEN sin nuevo depósito?
2. **Estados stuck (fondos atrapados)**: ¿Hay algún estado sin transición de salida? ¿Puede un usuario quedar atrapado?
3. **Race conditions**: ¿Dos transiciones concurrentes pueden dejar el estado inconsistente?
4. **Transiciones faltantes**: ¿Debería existir PAUSED → EMERGENCY_WITHDRAW pero no existe?
5. **Bypass de estados**: ¿Se puede saltar de PENDING directamente a FILLED sin validación intermedia?

**Output requerido en el YAML:**
```yaml
state_machine:
  states: [EMPTY, ACTIVE, UNDERWATER, LIQUIDATABLE, LIQUIDATED]
  transitions:
    - from: EMPTY, to: ACTIVE, via: "deposit()", guard: "amount > 0"
    - from: ACTIVE, to: UNDERWATER, via: "oracle price drop", guard: "none (automatic)"
  anomalies:
    - type: stuck_state, state: LIQUIDATED, description: "residual dust puede quedar atrapado"
    - type: illegal_transition, from: LIQUIDATED, to: ACTIVE, via: "deposit() no verifica estado"
```

Bug real: Rari Fuse — posición liquidada podía re-depositarse y crear deuda fantasma.
Bug real: Compound v2 — cToken stuck en PAUSED sin función de unpause por admin key loss.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
