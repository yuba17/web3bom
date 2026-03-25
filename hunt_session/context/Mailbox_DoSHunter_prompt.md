# DoSHunter — Mailbox Analysis

## Tu Identidad
Eres el **DoSHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Denial of service, gas griefing, unbounded loops, blocked withdrawals, revert-based DoS, resource exhaustion, emergency function blocking**

## Tu Objetivo
Analizar `Mailbox` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/Mailbox.sol`
**Dominio**: access


## Asset Flow Map
### Money IN (deposits/receives)
- L241 process(): IMessageRecipient(recipient).handle{value: msg.value}(
- L308 dispatch(): if (msg.value < requiredValue) {
- L309 dispatch(): requiredValue = msg.value;
- L312 dispatch(): hook.postDispatch{value: msg.value - requiredValue}(metadata, message);
```solidity
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ Internal Imports ============
import {Versioned} from "./upgrade/Versioned.sol";
import {Indexed} from "./libs/Indexed.sol";
import {Message} from "./libs/Message.sol";
import {TypeCasts} from "./libs/TypeCasts.sol";
import {IInterchainSecurityModule, ISpecifiesInterchainSecurityModule} from "./interfaces/IInterchainSecurityModule.sol";
import {IPostDispatchHook} from "./interfaces/hooks/IPostDispatchHook.sol";
import {IMessageRecipient} from "./interfaces/IMessageRecipient.sol";
import {IMailbox} from "./interfaces/IMailbox.sol";
import {PackageVersioned} from "./PackageVersioned.sol";

// ============ External Imports ============
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract Mailbox is
    IMailbox,
    Indexed,
    Versioned,
    OwnableUpgradeable,
    PackageVersioned
{
    // ============ Libraries ============

    using Message for bytes;
    using TypeCasts for bytes32;
    using TypeCasts for address;

    // ============ Constants ============

    // Domain of chain on which the contract is deployed
    uint32 public immutable localDomain;

    // ============ Public Storage ============

    // A monotonically increasing nonce for outbound unique message IDs.
    uint32 public nonce;

    // The latest dispatched message ID used for auth in post-dispatch hooks.
    bytes32 public latestDispatchedId;

    // The default ISM, used if the recipient fails to specify one.
    IInterchainSecurityModule public defaultIsm;

    // The default post dispatch hook, used for post processing of opting-in dispatches.
    IPostDispatchHook public defaultHook;

    // The required post dispatch hook, used for post processing of ALL dispatches.
    IPostDispatchHook public requiredHook;

    // Mapping of message ID to delivery context that processed the message.
    struct Delivery {
        address processor;
        uint48 blockNumber;
    }

    mapping(bytes32 messageId => Delivery delivery) internal deliveries;

    // ============ Events ============

    /**
     * @notice Emitted when the default ISM is updated
     * @param module The new default ISM
     */
    event DefaultIsmSet(address indexed module);

    /**
     * @notice Emitted when the default hook is updated
     * @param hook The new default hook
     */
    event DefaultHookSet(address indexed hook);

    /**
     * @notice Emitted when the required hook is updated
     * @param hook The new required hook
     */
    event RequiredHookSet(address indexed hook);

    // ============ Constructor ============
    constructor(uint32 _localDomain) {
        localDomain = _localDomain;
    }

    // ============ Initializers ============
    function initialize(
        address _owner,
        address _defaultIsm,
        address _defaultHook,
        address _requiredHook
    ) external initializer {
        __Ownable_init();
        setDefaultIsm(_defaultIsm);
        setDefaultHook(_defaultHook);
        setRequiredHook(_requiredHook);
        transferOwnership(_owner);
    }

    // ============ External Functions ============
    /**
     * @notice Dispatches a message to the destination domain & recipient
     * using the default hook and empty metadata.
     * @param _destinationDomain Domain of destination chain
     * @param _recipientAddress Address of recipient on destination chain as bytes32
     * @param _messageBody Raw bytes content of message body
     * @return The message ID inserted into the Mailbox's merkle tree
     */
    function dispatch(
        uint32 _destinationDomain,
        bytes32 _recipientAddress,
        bytes calldata _messageBody
    ) external payable override returns (bytes32) {
        return
            dispatch(
                _destinationDomain,
                _recipientAddress,
                _messageBody,
                _messageBody[0:0],
                defaultHook
            );
    }

    /**
     * @notice Dispatches a message to the destination domain & recipient.
     * @param destinationDomain Domain of destination chain
     * @param recipientAddress Address of recipient on destination chain as bytes32
     * @param messageBody Raw bytes content of message body
     * @param hookMetadata Metadata used by the post dispatch hook
     * @return The message ID inserted into the Mailbox's merkle tree
     */
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata hookMetadata
    ) external payable override returns (bytes32) {
        return
            dispatch(
                destinationDomain,
                recipientAddress,
                messageBody,
                hookMetadata,
                defaultHook
            );
    }

    /**
     * @notice Computes quote for dipatching a message to the destination domain & recipient
     * using the default hook and empty metadata.
     * @param destinationDomain Domain of destination chain
     * @param recipientAddress Address of recipient on destination chain as bytes32
     * @param messageBody Raw bytes content of message body
     * @return fee The payment required to dispatch the message
     */
    function quoteDispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody
    ) external view returns (uint256 fee) {
        return
            quoteDispatch(
                destinationDomain,
                recipientAddress,
                messageBody,
                messageBody[0:0],
                defaultHook
            );
    }

    /**
     * @notice Computes quote for dispatching a message to the destination domain & recipient.
     * @param destinationDomain Domain of destination chain
     * @param recipientAddress Address of recipient on destination chain as bytes32
     * @param messageBody Raw bytes content of message body
     * @param defaultHookMetadata Metadata used by the default post dispatch hook
     * @return fee The payment required to dispatch the message
     */
    function quoteDispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata defaultHookMetadata
    ) external view returns (uint256 fee) {
        return
            quoteDispatch(
                destinationDomain,
                recipientAddress,
                messageBody,
                defaultHookMetadata,
                defaultHook
            );
    }

    /**
     * @notice Attempts to deliver `_message` to its recipient. Verifies
     * `_message` via the recipient's ISM using the provided `_metadata`.
     * @param _metadata Metadata used by the ISM to verify `_message`.
     * @param _message Formatted Hyperlane message (refer to Message.sol).
     */
    function process(
        bytes calldata _metadata,
        bytes calldata _message
    ) external payable override {
        /// CHECKS ///

        // Check that the message was intended for this mailbox.
        require(_message.version() == VERSION, "Mailbox: bad version");
        require(
            _message.destination() == localDomain,
            "Mailbox: unexpected destination"
        );

        // Check that the message hasn't already been delivered.
        bytes32 _id = _message.id();
        require(delivered(_id) == false, "Mailbox: already delivered");

        // Get the recipient's ISM.
        address recipient = _message.recipientAddress();
        IInterchainSecurityModule ism = recipientIsm(recipient);

        /// EFFECTS ///

        deliveries[_id] = Delivery({
            processor: msg.sender,
            blockNumber: uint48(block.number)
        });
        emit Process(_message.origin(), _message.sender(), recipient);
        emit ProcessId(_id);

        /// INTERACTIONS ///

        // Verify the message via the interchain security module.
        require(
            ism.verify(_metadata, _message),
            "Mailbox: ISM verification failed"
        );

        // Deliver the message to the recipient.
        IMessageRecipient(recipient).handle{value: msg.value}(
            _message.origin(),
            _message.sender(),
            _message.body()
        );
    }

    /**
     * @notice Returns the account that processed the message.
     * @param _id The message ID to check.
     * @return The account that processed the message.
     */
    function processor(bytes32 _id) external view returns (address) {
        return deliveries[_id].processor;
    }

    /**
     * @notice Returns the account that processed the message.
     * @param _id The message ID to check.
     * @return The number of the block that the message was processed at.
     */
    function processedAt(bytes32 _id) external view returns (uint48) {
        return deliveries[_id].blockNumber;
    }

    // ============ Public Functions ============

    /**
     * @notice Dispatches a message to the destination domain & recipient.
     * @param destinationDomain Domain of destination chain
     * @param recipientAddress Address of recipient on destination chain as bytes32
     * @param messageBody Raw bytes content of message body
     * @param metadata Metadata used by the post dispatch hook
     * @param hook Custom hook to use instead of the default
     * @return The message ID inserted into the Mailbox's merkle tree
     */
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata,
        IPostDispatchHook hook
    ) public payable virtual returns (bytes32) {
        if (address(hook) == address(0)) {
            hook = defaultHook;
        }

        /// CHECKS ///

        // Format the message into packed bytes.
        bytes memory message = _buildMessage(
            destinationDomain,
            recipientAddress,
            messageBody
        );
        bytes32 id = message.id();

        /// EFFECTS ///

        latestDispatchedId = id;
        nonce += 1;
        emit Dispatch(msg.sender, destinationDomain, recipientAddress, message);
        emit DispatchId(id);

        /// INTERACTIONS ///
        uint256 requiredValue = requiredHook.quoteDispatch(metadata, message);
        // if underpaying, defer to required hook's reverting behavior
        if (msg.value < requiredValue) {
            requiredValue = msg.value;
        }
        requiredHook.postDispatch{value: requiredValue}(metadata, message);
        hook.postDispatch{value: msg.value - requiredValue}(metadata, message);

        return id;
    }

    /**
     * @notice Computes quote for dispatching a message to the destination domain & recipient.
     * @dev This function sums the quotes from requiredHook and hook, assuming both return
     * values denominated in the same currency. When using ERC-20 fee tokens (via
     * StandardHookMetadata.feeToken), this works because:
     * - Native-only hooks reject non-zero feeToken metadata via supportsMetadata
     * - The requiredHook (typically ProtocolFee) returns 0 when protocolFee is 0
     *
     * IMPORTANT: Mixing fee denominations (native + ERC-20) in a single dispatch is not
     * supported. Callers must ensure all hooks in the chain use the same fee denomination.
     *
     * @param destinationDomain Domain of destination chain
     * @param recipientAddress Address of recipient on destination chain as bytes32
     * @param messageBody Raw bytes content of message body
     * @param metadata Metadata used by the post dispatch hook
     * @param hook Custom hook to use instead of the default
     * @return fee The payment required to dispatch the message
     */
    function quoteDispatch(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody,
        bytes calldata metadata,
        IPostDispatchHook hook
    ) public view returns (uint256 fee) {
        if (address(hook) == address(0)) {
            hook = defaultHook;
        }

        bytes memory message = _buildMessage(
            destinationDomain,
            recipientAddress,
            messageBody
        );
        return
            requiredHook.quoteDispatch(metadata, message) +
            hook.quoteDispatch(metadata, message);
    }

    /**
     * @notice Returns true if the message has been processed.
     * @param _id The message ID to check.
     * @return True if the message has been delivered.
     */
    function delivered(bytes32 _id) public view override returns (bool) {
        return deliveries[_id].blockNumber > 0;
    }

    /**
     * @notice Sets the default ISM for the Mailbox.
     * @param _module The new default ISM. Must be a contract.
     */
    function setDefaultIsm(address _module) public onlyOwner {
        require(
            Address.isContract(_module),
            "Mailbox: default ISM not contract"
        );
        defaultIsm = IInterchainSecurityModule(_module);
        emit DefaultIsmSet(_module);
    }

    /**
     * @notice Sets the default post dispatch hook for the Mailbox.
     * @param _hook The new default post dispatch hook. Must be a contract.
     */
    function setDefaultHook(address _hook) public onlyOwner {
        require(
            Address.isContract(_hook),
            "Mailbox: default hook not contract"
        );
        defaultHook = IPostDispatchHook(_hook);
        emit DefaultHookSet(_hook);
    }

    /**
     * @notice Sets the required post dispatch hook for the Mailbox.
     * @param _hook The new default post dispatch hook. Must be a contract.
     */
    function setRequiredHook(address _hook) public onlyOwner {
        require(
            Address.isContract(_hook),
            "Mailbox: required hook not contract"
        );
        requiredHook = IPostDispatchHook(_hook);
        emit RequiredHookSet(_hook);
    }

    /**
     * @notice Returns the ISM to use for the recipient, defaulting to the
     * default ISM if none is specified.
     * @param _recipient The message recipient whose ISM should be returned.
     * @return The ISM to use for `_recipient`.
     */
    function recipientIsm(
        address _recipient
    ) public view returns (IInterchainSecurityModule) {
        // use low-level staticcall in case of revert or empty return data
        (bool success, bytes memory returnData) = _recipient.staticcall(
            abi.encodeCall(
                ISpecifiesInterchainSecurityModule.interchainSecurityModule,
                ()
            )
        );
        // check if call was successful and returned data
        if (success && returnData.length != 0) {
            // check if returnData is a valid address
            address ism = abi.decode(returnData, (address));
            // check if the ISM is a contract
            if (ism != address(0)) {
                return IInterchainSecurityModule(ism);
            }
        }
        // Use the default if a valid one is not specified by the recipient.
        return defaultIsm;
    }

    // ============ Internal Functions ============
    function _buildMessage(
        uint32 destinationDomain,
        bytes32 recipientAddress,
        bytes calldata messageBody
    ) internal view returns (bytes memory) {
        return
            Message.formatMessage(
                VERSION,
                nonce,
                localDomain,
                msg.sender.addressToBytes32(),
                destinationDomain,
                recipientAddress,
                messageBody
            );
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Mailbox
Buscando 'Mailbox' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (29ms)

 1. [GAS] [G-27] Do not import the whole library, when only a few functions from that libr — zkSync
 2. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` — Nucleus_2024-12-14
 3. [GAS] [G-30] Unnecessary variables in `Mailbox.sol` — zkSync
 4. [GAS] [G-43] `public` functions which are not called by the contract should be declare — zkSync
 5. [LOW] [05] — zkSync

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [GAS] [G-27] Do not import the whole library, when only a few functions from that library are being used (zkSync)
   
**File:** `Mailbox.sol`

[File: code/contracts/ethereum/contracts/state-transition/chain-deps/facets/Mailbox.sol](https://github.com/code-423n4/2024-...

2. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` (Nucleus_2024-12-14)
   ## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_bridge()` and `_quote()` in the `MultiChainHyperlaneTellerWithMultiAssetSupp...

3. [GAS] [G-30] Unnecessary variables in `Mailbox.sol` (zkSync)
   
**Function `_proveL2LogInclusion`:**

Variables `calculatedRootHash` and `actualRootHash` are used only once, which means they don't need to be decla...

4. [GAS] [G-43] `public` functions which are not called by the contract should be declared as `external` (zkSync)
   
**File:** `Mailbox.sol`

When `public` function is never called internally and is only expected to be invoked externally, it is more gas-efficient to...

5. [LOW] [05] (zkSync)
   
It is not needed to have modifier `senderCanCallFunction` for the function `deposit` in both `L1ERC20Bridge` and `L1ETHBridge`, because they call the...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio access
Buscando 'Mailbox dispatch dispatch quoteDispatch quoteDispatch' [SQLite FTS5] (dominio: access)...
Top 2 findings relevantes: (186ms)
 1. [HIGH] Permission in method description doesn't match implementation — Basilisk
 2. [HIGH] Potential DoS of messages in the `postDispatch` function — DIA
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox dispatch dispatch quoteDispatch quoteDispatch | Dominio: access
Los siguientes 2 findings de protocolos similares son relevantes:
1. [HIGH] Permission in method description doesn't match implementation (Basilisk)
   **Occurs**:
Basilisk-node/pallets/lbp/src/lib.rs:516-568
Dispatch origin restrictions described in comments must match method implementation
**Recom...
2. [HIGH] Potential DoS of messages in the `postDispatch` function (DIA)
   ##### Description
The `postDispatch()` function of the `ProtocolFeeHook` contract lacks access control check.
The function updates the `messageValida...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'Mailbox dispatch dispatch quoteDispatch quoteDispatch' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (9ms)
 1. [HIGH] Issue with Fee Payment During Interchain Callback — DIA
 2. [HIGH] Proxy has public methods that shadow implementation — NuCypher
 3. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, resul — RealWagmi
 4. [HIGH] Message Verification — DIA
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox dispatch dispatch quoteDispatch quoteDispatch | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:
1.

## Briefing del Dominio (access)
### Briefing principal: access

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Some functions are intentionally permissionless (liquidation, keeper calls) -- verify it SHOULD be restricted
  ⚠ Access control may be enforced deeper in the call stack via an internal function
  ⚠ Not always exploitable by attacker -- more of a governance risk
  ⚠ Some protocols intentionally use single-step for simplicity (low value contracts)
  ⚠ reinitializer(version) is legitimate for upgrade migrations -- only flag if version is re-callable
  ⚠ Standard OpenZeppelin TransparentUpgradeableProxy and UUPS are safe by default
  ⚠ Focus on custom proxy implementations
  ⚠ Emergency pause mechanisms intentionally skip timelock -- this is expected
  ⚠ Cap decreases are often instant by design (reducing exposure is safe)
  ⚠ Centralization concerns are often out of scope for bug bounties unless the bounty explicitly covers governance
  ⚠ Multi-sig is considered trusted in most bounty programs
  ⚠ tx.origin == msg.sender as an anti-contract guard is a different pattern (not auth bypass, but can be bypassed via constructor calls)


### Grep targets adicionales (dex)
```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp

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
  function initialize(address _owner, address _defaultIsm, address _defaultHook, address _requiredHook) external;
  function dispatch(uint32 _destinationDomain, bytes32 _recipientAddress, bytes calldata _messageBody) external payable override returns (bytes32);
  function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody, bytes calldata hookMetadata) external payable override returns (bytes32);
  function quoteDispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody) external view returns (uint256 fee);
  function quoteDispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody, bytes calldata defaultHookMetadata) external view returns (uint256 fee);
  function process(bytes calldata _metadata, bytes calldata _message) external payable override;
  function processor(bytes32 _id) external view returns (address);
  function processedAt(bytes32 _id) external view returns (uint48);
  function dispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody, bytes calldata metadata, IPostDispatchHook hook) public payable virtual returns (bytes32);
  function quoteDispatch(uint32 destinationDomain, bytes32 recipientAddress, bytes calldata messageBody, bytes calldata metadata, IPostDispatchHook hook) public view returns (uint256 fee);
  function delivered(bytes32 _id) public view override returns (bool);
  function setDefaultIsm(address _module) public;
  function setDefaultHook(address _hook) public;
  function setRequiredHook(address _hook) public;
  function recipientIsm(address _recipient) public view returns (IInterchainSecurityModule);
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
2. **Identifica** las funciones donde tu especialidad (Denial of service) es relevante
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
ID prefix para este componente: `M` (ej: M-01, M-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Mailbox_DoSHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: M-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "M-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## DoS / Griefing Deep Check (OBLIGATORIO — la clase de vuln MÁS IGNORADA, 2,279 findings en Solodit)

### Sección 1: Unbounded Loops & Gas Exhaustion (8 items)
Para CADA loop (for, while) en el contrato:
1. ¿El loop itera sobre un array cuyo tamaño puede crecer sin límite? (usuarios, tokens, markets, orders)
2. ¿Hay un cap máximo en el tamaño del array? ¿Es razonable para el gas limit del bloque?
3. ¿Hay operaciones storage-write DENTRO del loop? (cada SSTORE = 5K-20K gas)
4. ¿Hay external calls DENTRO del loop? (cada call = variable gas, puede revert y bloquear el loop)
5. ¿La función afectada es una función CRÍTICA? (withdraw, liquidate, claim, emergencyWithdraw)
6. ¿Un atacante puede inflar el array a bajo costo? (crear muchas posiciones pequeñas, registrar muchos tokens)
7. ¿El patrón pull-over-push se usa correctamente? (no enviar a N usuarios en 1 tx → dejar que cada uno retire)
8. ¿Hay paginación o batch limits para operaciones sobre colecciones grandes?

Bug real: GovernorBravo — iteración sobre todas las proposals sin límite → gas DoS.
Bug real: Nouns DAO — iteración sobre voters bloqueó settleAuction().

### Sección 2: Revert-Based DoS — Bloqueo de Funciones Críticas (7 items)
1. ¿Alguna función de SALIDA (withdraw, repay, unstake, emergencyWithdraw) hace external call que puede revert?
   - ¿La función envía ETH con transfer/send a una dirección que puede ser un contrato sin receive()?
   - ¿La función llama a un token que puede pausarse/bloquearse? (USDC blocklist, pausable tokens)
2. ¿Una función de liquidación depende de que el liquidado coopere? (callback, approve, token transfer)
3. ¿Hay un require/assert en una función de emergencia que puede fallar en condiciones extremas?
4. ¿Un oracle caído (reverts) bloquea withdrawals? (Chainlink puede revert si no hay respuesta)
5. ¿Un safety check (health factor, collateral ratio) puede impedir que un usuario repague su deuda?
6. ¿Hay try/catch alrededor de calls que pueden fallar? ¿O un revert en el call propaga y bloquea todo?
7. ¿Funciones de governance/timelock pueden quedar permanentemente bloqueadas? (propuesta que revierte en execute)

Bug real: Akutars — $34M bloqueados porque refund() dependía de transfer() a contratos sin receive().
Bug real: Safety margin en repay impedía repago → usuarios forzados a liquidación ($3M Rari Fuse).

### Sección 3: Front-Running & Grief (5 items)
1. ¿Un atacante puede front-run una transacción para hacerla revert? (sandwich the tx, manipular estado previo)
2. ¿Hay operaciones donde el first-mover gana y puede bloquear a otros? (claim, initialize, createPool)
3. ¿Se puede inflar el gas cost de una transacción ajena? (returnbomb: retornar datos enormes en un callback)
4. ¿Existe donation attack que cambia el estado para hacer revert la tx de la víctima?
5. ¿Un atacante puede crear dust positions para bloquear operaciones batch?

Bug real: ERC-4626 inflation — first depositor envía dust para hacer revert todos los deposits siguientes.
Bug real: returnbomb — contrato malicioso retorna 2MB de datos en callback, agotando gas del caller.

### Sección 4: Resource Exhaustion & State Bloat (5 items)
1. ¿Se pueden crear entidades (positions, orders, tokens) sin costo mínimo? → spam attack
2. ¿Hay storage que crece sin mecanismo de limpieza? (mappings que solo crecen, nunca se borran)
3. ¿El protocolo depende de un keeper/relayer? ¿Qué pasa si el keeper no actúa? (liquidaciones pendientes)
4. ¿Hay rate limiting en funciones que consumen recursos? (createMarket, addToken, registerOracle)
5. ¿Deadline/expiry de operaciones pendientes? ¿O quedan en pending para siempre?

### Sección 5: Emergency & Recovery Blocking (4 items)
1. ¿La función pause() puede ser llamada pero unpause() no existe o requiere multisig con keys perdidas?
2. ¿El modo emergencia permite SIEMPRE retirar fondos? ¿O el emergency también se puede bloquear?
3. ¿Hay timelock que puede quedar permanentemente en estado pendiente? (no se puede cancelar ni ejecutar)
4. ¿Shutdown/migration path funciona si el contrato principal está en un estado inesperado?

Bug real: Compound cETH — admin key loss + pause sin unpause alternativo = fondos bloqueados.
Bug real: Wormhole — guardian set update bloqueado por quorum issue → bridge congelado.

### Solidity Assertion Patterns para DoS

1. **Unbounded loop gas check:**
```solidity
// Verificar que la función no excede gas razonable para N entradas
uint256 gasBefore = gasleft();
target.processAll();
uint256 gasUsed = gasBefore - gasleft();
// Si gasUsed crece linealmente con N, escalar a 100+ entradas bloqueará la tx
t(gasUsed < 5_000_000, "DOS-XX: processAll exceeds 5M gas");
```

2. **Revert-based withdrawal block:**
```solidity
// Crear un contrato que revierte en receive()
RevertOnReceive blocker = new RevertOnReceive();
// Depositar como blocker, luego intentar withdraw
target.deposit{value: 1 ether}(address(blocker));
try target.withdraw(address(blocker), 1 ether) {
    // Si withdraw tiene try/catch o pull pattern, OK
} catch {
    t(false, "DOS-XX: withdraw blocked by reverting receiver");
}
```

3. **Emergency function always callable:**
```solidity
// Poner el contrato en el peor estado posible
_putContractInBadState();
// emergencyWithdraw DEBE funcionar siempre
try target.emergencyWithdraw{gas: 500000}() {
    // OK — emergency funciona
} catch {
    t(false, "DOS-XX: emergencyWithdraw blocked in bad state");
}
```

4. **Array growth → gas DoS:**
```solidity
// Añadir N elementos y medir gas de operación afectada
for (uint i = 0; i < 100; i++) {
    target.addElement(i);
}
uint256 gasBefore = gasleft();
target.processElements();
uint256 gasFor100 = gasBefore - gasleft();
// Proyectar: si 100 elem = X gas, 10K elem = 100X gas > block limit
t(gasFor100 < 500_000, "DOS-XX: processElements scales linearly — DoS at ~10K elements");
```

5. **Oracle failure doesn't block withdrawals:**
```solidity
// Simular oracle caído (reverts)
mockOracle.setShouldRevert(true);
// Withdraw DEBE funcionar aún sin oracle
try target.withdraw{gas: 300000}(user, amount) {
    // OK — withdraw no depende de oracle
} catch {
    t(false, "DOS-XX: withdraw blocked when oracle is down");
}
```

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Los DoS bugs son los más fuzzeables — gas measurements + try/catch patterns son directos.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
