# OracleHunter — Bridge Analysis

## Tu Identidad
Eres el **OracleHunter** del equipo de bug hunting de base-bridge.
Tu especialidad: **Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies**

## Tu Objetivo
Analizar `Bridge` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/bridge/base/src/Bridge.sol`
**Dominio**: crosschain


```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {OwnableRoles} from "solady/auth/OwnableRoles.sol";
import {Initializable} from "solady/utils/Initializable.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {ReentrancyGuardTransient} from "solady/utils/ReentrancyGuardTransient.sol";

import {BridgeValidator} from "./BridgeValidator.sol";
import {Twin} from "./Twin.sol";
import {Call} from "./libraries/CallLib.sol";
import {IncomingMessage, MessageLib, MessageType} from "./libraries/MessageLib.sol";
import {MessageStorageLib} from "./libraries/MessageStorageLib.sol";
import {SVMBridgeLib} from "./libraries/SVMBridgeLib.sol";
import {Ix, Pubkey, SVMLib} from "./libraries/SVMLib.sol";
import {SolanaTokenType, TokenLib, Transfer} from "./libraries/TokenLib.sol";

/// @title Bridge
///
/// @notice Cross-chain bridge enabling bidirectional communication and token transfers between Solana and Base.
contract Bridge is ReentrancyGuardTransient, Initializable, OwnableRoles {
    //////////////////////////////////////////////////////////////
    ///                       Constants                        ///
    //////////////////////////////////////////////////////////////

    /// @notice Pubkey of the remote bridge program on Solana.
    ///
    /// @dev Used to identify messages originating directly from the Solana bridge program itself (rather than from
    ///      user Twin contracts). When a message's sender equals this pubkey, it indicates the message contains
    ///      bridge-level operations such as wrapped token registration that require special handling.
    Pubkey public immutable REMOTE_BRIDGE;

    /// @notice Address of the Twin beacon used for deploying upgradeable Twin contract proxies.
    ///
    /// @dev Each Solana user gets their own deterministic Twin contract deployed via beacon proxy using their
    ///      Solana pubkey as the salt. Twin contracts act as execution contexts for Solana users on Base,
    ///      allowing them to execute arbitrary calls and receive tokens. The beacon pattern enables
    ///      upgradeability of all Twin contract implementations simultaneously.
    address public immutable TWIN_BEACON;

    /// @notice Address of the CrossChainERC20Factory.
    ///
    /// @dev It's primarily used to check if a local token was deployed by the bridge. If so, we know we can mint /
    ///      burn. Otherwise the token interaction is a transfer.
    address public immutable CROSS_CHAIN_ERC20_FACTORY;

    /// @notice Address of the BridgeValidator contract. Messages will be pre-validated there by our oracle & bridge
    ///         partner.
    address public immutable BRIDGE_VALIDATOR;

    /// @notice Guardian Role to pause the bridge.
    uint256 public constant GUARDIAN_ROLE = 1 << 0;

    //////////////////////////////////////////////////////////////
    ///                       Storage                          ///
    //////////////////////////////////////////////////////////////

    /// @notice Mapping of message hashes to boolean values indicating successful execution. A message will only be
    ///         present in this mapping if it has successfully been executed, and therefore cannot be executed again.
    mapping(bytes32 messageHash => bool success) public successes;

    /// @notice Mapping of message hashes to boolean values indicating failed execution attempts. A message will be
    ///         present in this mapping if and only if it has failed to execute at least once. Successfully executed
    ///         messages on first attempt won't appear here.
    mapping(bytes32 messageHash => bool failure) public failures;

    /// @notice Mapping of Solana owner pubkeys to their Twin contract addresses.
    mapping(Pubkey owner => address twinAddress) public twins;

    /// @notice Whether the bridge is paused.
    bool public paused;

    //////////////////////////////////////////////////////////////
    ///                       Events                           ///
    //////////////////////////////////////////////////////////////

    /// @notice Emitted whenever a message is successfully relayed and executed.
    ///
    /// @param submitter   The caller that executed the message
    /// @param messageHash Keccak256 hash of the message that was successfully relayed.
    event MessageSuccessfullyRelayed(address indexed submitter, bytes32 indexed messageHash);

    /// @notice Emitted whenever a message fails to be relayed.
    ///
    /// @param submitter   The caller that attempted execution of the message
    /// @param messageHash Keccak256 hash of the message that failed to be relayed.
    event FailedToRelayMessage(address indexed submitter, bytes32 indexed messageHash);

    /// @notice Emitted whenever the bridge is paused or unpaused.
    ///
    /// @param paused Whether the bridge is paused.
    event PauseSwitched(bool paused);

    //////////////////////////////////////////////////////////////
    ///                       Errors                           ///
    //////////////////////////////////////////////////////////////

    /// @notice Thrown when the bridge is paused.
    error Paused();

    /// @notice Thrown when `validateMessage` is called with a message hash that has not been pre-validated.
    error InvalidMessage();

    /// @notice Thrown when the sender is not the entrypoint.
    error SenderIsNotEntrypoint();

    /// @notice Thrown when a zero address is detected
    error ZeroAddress();

    /// @notice Thrown when the borsch-encoded message to bridge is too large to fit in a Solana account
    error SerializedMessageTooBig();

    //////////////////////////////////////////////////////////////
    ///                       Modifiers                        ///
    //////////////////////////////////////////////////////////////

    modifier whenNotPaused() {
        require(!paused, Paused());
        _;
    }

    modifier isValidIxs(Ix[] calldata ixs) {
        SVMLib.validateIxs(ixs);
        _;
    }

    //////////////////////////////////////////////////////////////
    ///                       Public Functions                 ///
    //////////////////////////////////////////////////////////////

    /// @notice Constructs the Bridge contract.
    ///
    /// @param remoteBridge           The pubkey of the remote bridge on Solana.
    /// @param twinBeacon             The address of the Twin beacon.
    /// @param crossChainErc20Factory The address of the CrossChainERC20Factory.
    /// @param bridgeValidator        The address of the contract used to validate Bridge messages
    constructor(Pubkey remoteBridge, address twinBeacon, address crossChainErc20Factory, address bridgeValidator) {
        require(twinBeacon != address(0), ZeroAddress());
        require(crossChainErc20Factory != address(0), ZeroAddress());
        require(bridgeValidator != address(0), ZeroAddress());

        REMOTE_BRIDGE = remoteBridge;
        TWIN_BEACON = twinBeacon;
        CROSS_CHAIN_ERC20_FACTORY = crossChainErc20Factory;
        BRIDGE_VALIDATOR = bridgeValidator;

        _disableInitializers();
    }

    /// @notice Initializes the Bridge contract with an owner and guardians with bridge pausing permissions.
    ///
    /// @param owner     The owner of the Bridge contract.
    /// @param guardians An array of guardian addresses approved to pause the Bridge.
    function initialize(address owner, address[] calldata guardians) external initializer {
        require(owner != address(0), ZeroAddress());

        // Initialize ownership
        _initializeOwner(owner);

        // Initialize guardians
        for (uint256 i; i < guardians.length; i++) {
            require(guardians[i] != address(0), ZeroAddress());
            _grantRoles(guardians[i], GUARDIAN_ROLE);
        }
    }

    /// @notice Bridges a call to the Solana bridge.
    ///
    /// @param ixs The instructions to execute on Solana.
    function bridgeCall(Ix[] calldata ixs) external nonReentrant whenNotPaused isValidIxs(ixs) {
        bytes memory data = SVMBridgeLib.serializeCall(ixs);
        require(data.length <= SVMLib.MAX_SOLANA_DATA_LENGTH, SerializedMessageTooBig());
        MessageStorageLib.sendMessage({sender: msg.sender, data: data});
    }

    /// @notice Bridges a transfer with an optional list of instructions to the Solana bridge.
    ///
    /// @dev If `localToken` is a wrapped version of a Solana asset, `remoteToken` is an optional arg.
    ///      If the received `remoteToken` is bytes32(0), the bridge will override it with the correct value
    ///      automatically
    ///
    /// @param transfer The token transfer to execute.
    /// @param ixs      The optional Solana instructions.
    function bridgeToken(Transfer memory transfer, Ix[] calldata ixs)
        external
        payable
        nonReentrant
        whenNotPaused
        isValidIxs(ixs)
    {
        // IMPORTANT: The `TokenLib.initializeTransfer` function might modify the `transfer.remoteAmount` field to
        //            account for potential transfer fees.
        SolanaTokenType transferType =
            TokenLib.initializeTransfer({transfer: transfer, crossChainErc20Factory: CROSS_CHAIN_ERC20_FACTORY});

        bytes memory data = SVMBridgeLib.serializeTransfer({transfer: transfer, tokenType: transferType, ixs: ixs});
        require(data.length <= SVMLib.MAX_SOLANA_DATA_LENGTH, SerializedMessageTooBig());
        MessageStorageLib.sendMessage({sender: msg.sender, data: data});
    }

    /// @notice Relays messages sent from Solana to Base.
    ///
    /// @param messages The messages to relay.
    function relayMessages(IncomingMessage[] calldata messages) external nonReentrant whenNotPaused {
        for (uint256 i; i < messages.length; i++) {
            _validateAndRelay(messages[i]);
        }
    }

    /// @notice Relays a message sent from Solana to Base.
    ///
    /// @dev This function can only be called from `_validateAndRelay`.
    ///
    /// @param message The message to relay.
    function __relayMessage(IncomingMessage calldata message) external {
        _assertSenderIsEntrypoint();

        // Special case where the message sender is directly the Solana bridge.
        // For now this is only the case when a Wrapped Token is deployed on Solana and is being registered on Base.
        // When this happens the message is guaranteed to be a single operation that encode the parameters of the
        // `registerRemoteToken` function.
        if (message.sender == REMOTE_BRIDGE) {
            Call memory call = abi.decode(message.data, (Call));
            (address localToken, Pubkey remoteToken, uint8 scalarExponent) =
                abi.decode(call.data, (address, Pubkey, uint8));

            TokenLib.registerRemoteToken({
                localToken: localToken, remoteToken: remoteToken, scalarExponent: scalarExponent
            });
            return;
        }

        // For simple transfers, skip the twin logic.
        // This avoids the need to deploy a Twin contract for users that only want to transfer tokens.
        if (message.ty == MessageType.Transfer) {
            Transfer memory transfer = abi.decode(message.data, (Transfer));
            TokenLib.finalizeTransfer({transfer: transfer, crossChainErc20Factory: CROSS_CHAIN_ERC20_FACTORY});
            return;
        }

        // For calls, get (and deploy if needed) the Twin contract.
        address twinAddress = twins[message.sender];
        if (twinAddress == address(0)) {
            twinAddress = LibClone.deployDeterministicERC1967BeaconProxy({
                beacon: TWIN_BEACON, salt: Pubkey.unwrap(message.sender)
            });
            twins[message.sender] = twinAddress;
        }

        if (message.ty == MessageType.Call) {
            Call memory call = abi.decode(message.data, (Call));
            Twin(payable(twinAddress)).execute(call);
        } else if (message.ty == MessageType.TransferAndCall) {
            (Transfer memory transfer, Call memory call) = abi.decode(message.data, (Transfer, Call));
            TokenLib.finalizeTransfer({transfer: transfer, crossChainErc20Factory: CROSS_CHAIN_ERC20_FACTORY});
            Twin(payable(twinAddress)).execute(call);
        }
    }

    /// @notice Pauses or unpauses the bridge.
    ///
    /// @dev This function can only be called by a guardian.
    ///
    /// @param isPaused Boolean representing the desired paused status
    function setPaused(bool isPaused) external onlyRoles(GUARDIAN_ROLE) {
        paused = isPaused;
        emit PauseSwitched(isPaused);
    }

    /// @notice Get the current root of the MMR.
    ///
    /// @return The current root of the MMR.
    function getRoot() external view returns (bytes32) {
        return MessageStorageLib.getMessageStorageLibStorage().root;
    }

    /// @notice Get the next outgoing Message nonce.
    ///
    /// @return The next outgoing Message nonce.
    function getNextNonce() external view returns (uint64) {
        return MessageStorageLib.getMessageStorageLibStorage().nextNonce;
    }

    /// @notice Generates a Merkle proof for a specific leaf in the MMR.
    ///
    /// @dev This function may consume significant gas for large MMRs (O(log N) storage reads).
    ///
    /// @param leafIndex The 0-indexed position of the leaf to prove.
    ///
    /// @return proof          Array of sibling hashes for the proof.
    function generateProof(uint64 leafIndex) external view returns (bytes32[] memory proof) {
        return MessageStorageLib.generateProof(leafIndex);
    }

    /// @notice Predict the address of the Twin contract for a given Solana sender pubkey.
    ///
    /// @param sender The Solana sender's pubkey.
    ///
    /// @return The predicted address of the Twin contract for the given Solana sender pubkey.
    function getPredictedTwinAddress(Pubkey sender) external view returns (address) {
        return LibClone.predictDeterministicAddressERC1967BeaconProxy({
            beacon: TWIN_BEACON, salt: Pubkey.unwrap(sender), deployer: address(this)
        });
    }

    /// @notice Get the deposit amount for a given local token and remote token.
    ///
    /// @param localToken  The address of the local token.
    /// @param remoteToken The pubkey of the remote token.
    ///
    /// @return _ The deposit amount for the given local token and remote token.
    function deposits(address localToken, Pubkey remoteToken) external view returns (uint256) {
        return TokenLib.getTokenLibStorage().deposits[localToken][remoteToken];
    }

    /// @notice Get the scalar used to convert local token amounts to remote token amounts.
    ///
    /// @param localToken  The address of the local token.
    /// @param remoteToken The pubkey of the remote token.
    ///
    /// @return _ The scalar used to convert local token amounts to remote token amounts.
    function scalars(address localToken, Pubkey remoteToken) external view returns (uint256) {
        return TokenLib.getTokenLibStorage().scalars[localToken][remoteToken];
    }

    /// @notice Returns the message hash of a given message to be used as its ID
    ///
    /// @param message The `IncomingMessage` to retrieve the message hash for
    ///
    /// @return messageHash The hash of `message`
    function getMessageHash(IncomingMessage calldata message) public pure returns (bytes32) {
        return MessageLib.getMessageHashCd(message);
    }

    //////////////////////////////////////////////////////////////
    ///                   Internal Functions                   ///
    //////////////////////////////////////////////////////////////

    /// @inheritdoc ReentrancyGuardTransient
    function _useTransientReentrancyGuardOnlyOnMainnet() internal pure override returns (bool) {
        return false;
    }

    //////////////////////////////////////////////////////////////
    ///                    Private Functions                   ///
    //////////////////////////////////////////////////////////////

    function _validateAndRelay(IncomingMessage calldata message) private {
        bytes32 messageHash = getMessageHash(message);

        // Check that the message has not already been relayed.
        if (successes[messageHash]) {
            return;
        }

        require(BridgeValidator(BRIDGE_VALIDATOR).validMessages(messageHash), InvalidMessage());

        try this.__relayMessage{gas: message.gasLimit}(message) {
            // Register the message as successfully relayed.
            delete failures[messageHash];
            successes[messageHash] = true;
            emit MessageSuccessfullyRelayed(msg.sender, messageHash);
        } catch {
            // Register the message as failed to relay.
            failures[messageHash] = true;
            emit FailedToRelayMessage(msg.sender, messageHash);
        }
    }

    /// @notice Asserts that the caller is the entrypoint.
    function _assertSenderIsEntrypoint() private view {
        require(msg.sender == address(this), SenderIsNotEntrypoint());
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Bridge
Buscando 'Bridge' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (16ms)

 1. [LOW] Unused imports — Yieldfi
 2. [HIGH] FEE COLLECTOR VAULT CHECK MISSING CAN LEAD TO DOS IN PHOTONMSG — NGL Bridge + Gorples Bridge
 3. [LOW] Lack of a double-step transferOwnership pattern — EVM Bridge Contracts
 4. [HIGH] Permanent failure to bridge wrapped ERC721 using Bridge::sendERC721UsingNative f — Sweep n Flip
 5. [LOW] Bridge address can not be changed if needed — Beyond

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bridge | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] Unused imports (Yieldfi)
   **Description:** Consider removing the following unused imports:

- contracts/bridge/Bridge.sol [Line: 7](https://github.com/YieldFiLabs/contracts/blo...

2. [HIGH] FEE COLLECTOR VAULT CHECK MISSING CAN LEAD TO DOS IN PHOTONMSG (NGL Bridge + Gorples Bridge)
   ##### Description

The `Initialize` statement of the `gorples-bridge` program allows the initialization of the bridge config account. This requires tw...

3. [LOW] Lack of a double-step transferOwnership pattern (EVM Bridge Contracts)
   ##### Description

The current ownership transfer process for the `pontis-bridge-nft.sol` , `pontis-bridge-fee-manager.sol` , `pontis-bridge-controlle...

4. [HIGH] Permanent failure to bridge wrapped ERC721 using Bridge::sendERC721UsingNative function  (Sweep n Flip)
   ## Bridge.sol Vulnerability Overview

## Context
**File:** Bridge.sol  
**Line:** 159  

## Description
The `sendERC721UsingNative` function of `Bridg...

5. [LOW] Bridge address can not be changed if needed (Beyond)
   **Severity**: Low	

**Status**: Resolved

**Description**

The `bridge` address used within the `WrappedERC20.sol` smart contract is set via construct...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio crosschain
Buscando 'Bridge bridgeCall bridgeToken relayMessages __relayMessage' [SQLite FTS5] (dominio: crosschain)...
Top 6 findings relevantes: (34ms)
 1. [HIGH] H-2: Legacy withdrawals can be relayed twice, causing double spending of bridged — Optimism Update
 2. [HIGH] BVM_ETH and MNT Deposited in Messengers Can Be Stolen — Mantle V2 Solidity Contracts Audit
 3. [HIGH] Withdrawing discounted ETH from L2 always fails — DRAFT
 4. [HIGH] H-1: All migrated withdrarwals that require more than 135,175 gas may be bricked — Optimism Update
 5. [HIGH] H-3: Causing users lose their fund during finalizing withdrawal transaction — Optimism
 6. [HIGH] Token Bridge Reentrancy Can Corrupt Token Accounting — Linea Bridge Audit
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Bridge bridgeCall bridgeToken relayMessages __relayMessage | Dominio: crosschain
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] H-2: Legacy withdrawals can be relayed twice, causing double spending of bridged assets (Optimism Update)
   Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/87 
## Found by 
Jeiwan
## Summary
`L2CrossDomainMessenger.relayMessage` c...
2. [HIGH] BVM_ETH and MNT Deposited in Messengers Can Be Stolen (Mantle V2 Solidity Contracts Audit)
   In the [`L2CrossDomainMessenger`](https://github.com/mantlenetworkio/mantle-v2/blob/e29d360904db5e5ec81888885f7b7250f8255895/packages/contracts-bedroc...
3. [HIGH] Withdrawing discounted ETH from L2 always fails (DRAFT)
   ## Security Audit Report
## DRAFT5.1.7: Negative ETH Withdrawal Issue
### Severity: Critical Risk
**Context:**  
- `OptimismPortal.sol#L387`  
- `Cro...
4. [HIGH] H-1: All migrated withdrarwals that require more than 135,175 gas may be bricked (Optimism Update)
   Source: https://github.com/sherlock-audit/2023-0

## Briefing del Dominio (crosschain)
### Briefing principal: crosschain

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ LayerZero usa nonces per-pathway (srcChainId, srcAddress) — si el pathway es único, un contrato diferente en la misma chain puede tener el mismo nonce
  ⚠ Wormhole sequence numbers son por emitter — no son globales al protocolo
  ⚠ LayerZero v1 tenía una función setTrustedRemote sin access control en algunos adaptadores
  ⚠ Wormhole no valida automáticamente el sender — el protocolo DEBE hacerlo en _verifyVAA
  ⚠ CCIP verifica la chain de origen pero NO la address del sender dentro del message
  ⚠ Across protocol tuvo exactamente la variante B en v2 — depositId podía reclamarse en ambos paths
  ⚠ En UniswapX, el filler puede cambiar la dirección de entrega si la orden no especifica recipient exacto
  ⚠ Wormhole tuvo este bug en 2022 — $320M robados por mint sin lock correspondiente
  ⚠ Los bridges que soportan fee-on-transfer tokens tienen un accounting desync por diseño si no ajustan por el fee
  ⚠ PoS Ethereum tiene finality real a los ~12 minutos (2 épocas) — no en cada bloque
  ⚠ Las chains OP Stack tienen finality en Ethereum L1, no en el L2 — diferente timeline
  ⚠ Avalanche tiene 'fast finality' pero solo si el stake es suficientemente alto ese bloque


### Grep targets adicionales (bridge)
```yaml
- id: bridge-004
  pattern: lock-mint-race-condition
  name: "Race condition between lock on source and mint on destination"
  causa_raiz: "Asynchronous cross-chain messaging creates a window where source lock is confirmed but destination mint has not executed. Reorg on source can reverse the lock."
  como_funciona: |
    1. User locks tokens on source chain (tx included in block N)
    2. Relayer/sequencer observes lock, initiates mint on destination
    3. Source chain reorgs, block N replaced -- lock tx dropped
    4. Mint on destination already executed -- tokens created from nothing
  invariante: "sum(totalSupply[token][chain]) + inTransit[token] == trackedSupply[token] (INV-BRIDGE-009)"
  que_mirar:



## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Price manipulation) es relevante
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
ID prefix para este componente: `B` (ej: B-01, B-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Bridge_OracleHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: B-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "B-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Oracle Deep Check (OBLIGATORIO — para cada fuente de precio)
NOTA: Flash Loan Hypothesis (12 preguntas) es responsabilidad de FlowHunter. NO la dupliques aquí.
Enfócate en tu especialidad: ORÁCULOS y fuentes de precio.
Para CADA llamada a latestRoundData() o equivalente:
1. ¿Se verifica updatedAt contra un heartbeat? ¿El heartbeat es ESPECÍFICO por feed o genérico?
2. ¿Se chequea answeredInRound >= roundId?
3. ¿Se chequea price > 0?
4. ¿Hay check de L2 sequencer down? (Arbitrum/Optimism/Base: sequencerUptimeFeed)
5. ¿Existe minAnswer/maxAnswer que clampea el precio en flash crashes?
6. ¿El oracle puede ser sandwicheado? (front-run de oracle update para explotar el vault)

Oracle-Liquidity Mismatch (cmichel/Rari): ¿cuánto capital se necesita para manipular el oracle vs cuánto se puede extraer? Si manipulación < extracción → explotable.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
