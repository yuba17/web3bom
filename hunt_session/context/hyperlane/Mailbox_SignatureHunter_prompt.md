# SignatureHunter — Mailbox Analysis

## Tu Identidad
Eres el **SignatureHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Signature replay, permit abuse, EIP-712 issues, nonce handling, ecrecover validation, approval/allowance patterns, Permit2, meta-transactions**

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
ID prefix para este componente: `M` (ej: M-01, M-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Mailbox_SignatureHunter.yaml`

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
