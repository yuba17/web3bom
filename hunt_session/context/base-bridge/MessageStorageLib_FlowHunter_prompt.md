# FlowHunter — MessageStorageLib Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de base.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

## Tu Objetivo
Analizar `MessageStorageLib` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/bridge/base/src/libraries/MessageStorageLib.sol`
**Dominio**: crosschain


```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EfficientHashLib} from "solady/utils/EfficientHashLib.sol";

/// @notice Storage layout used by this library.
///
/// @custom:storage-location erc7201:coinbase.storage.MessageStorageLib
///
/// @custom:field nextNonce Number of messages sent.
/// @custom:field root Current MMR root hash.
/// @custom:field nodes All nodes (leaves and internal) in the MMR.
struct MessageStorageLibStorage {
    uint64 nextNonce;
    bytes32 root;
    bytes32[] nodes;
}

/// @notice Struct representing a message to the Solana bridge.
///
/// @custom:field nonce Unique nonce for the message.
/// @custom:field sender Sender address.
/// @custom:field data Message data to be passed to the Solana bridge.
struct Message {
    uint64 nonce;
    address sender;
    bytes data;
}

library MessageStorageLib {
    //////////////////////////////////////////////////////////////
    ///                       Constants                        ///
    //////////////////////////////////////////////////////////////

    /// @notice A bit to be used in bitshift operations
    uint256 private constant _BIT = 1;

    //////////////////////////////////////////////////////////////
    ///                       Events                           ///
    //////////////////////////////////////////////////////////////

    /// @notice Emitted when a message is registered.
    ///
    /// @param messageHash The message's hash.
    /// @param mmrRoot The root of the MMR after the message is registered.
    /// @param message The message.
    event MessageInitiated(bytes32 indexed messageHash, bytes32 indexed mmrRoot, Message message);

    //////////////////////////////////////////////////////////////
    ///                       Errors                           ///
    //////////////////////////////////////////////////////////////

    /// @notice Thrown when failing to locate a leaf in the MMR structure
    error LeafNotFound();

    /// @notice Thrown when trying to generate a proof for an empty MMR
    error EmptyMMR();

    /// @notice Thrown when the leaf index is out of bounds
    error LeafIndexOutOfBounds();

    /// @notice Thrown when a sibling node index is out of bounds
    error SiblingNodeOutOfBounds();

    //////////////////////////////////////////////////////////////
    ///                       Constants                        ///
    //////////////////////////////////////////////////////////////

    /// @dev Slot for the `MessageStorageLibStorage` struct in storage.
    ///      Computed from:
    ///         keccak256(abi.encode(uint256(keccak256("coinbase.storage.MessageStorageLib")) - 1)) &
    ///         ~bytes32(uint256(0xff))
    ///
    ///      Follows ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201).
    bytes32 private constant _MESSAGE_STORAGE_LIB_STORAGE_LOCATION =
        0x4f00c1a67879b7469d7dd58849b9cbcdedefec3f3b862c2933a36197db136100;

    /// @notice Maximum number of peaks possible in the MMR
    uint256 private constant _MAX_PEAKS = 64;

    //////////////////////////////////////////////////////////////
    ///                       Internal Functions               ///
    //////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `MessageStorageLibStorage` struct.
    ///
    /// @return $ A storage reference to the `MessageStorageLibStorage` struct.
    function getMessageStorageLibStorage() internal pure returns (MessageStorageLibStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _MESSAGE_STORAGE_LIB_STORAGE_LOCATION
        }
    }

    /// @notice Generates an MMR inclusion proof for a specific leaf.
    ///
    /// @dev This function may consume significant gas for large MMRs (O(log N) storage reads).
    ///
    /// @param leafIndex The 0-indexed position of the leaf to prove.
    ///
    /// @return proof Array of sibling hashes for the proof.
    function generateProof(uint64 leafIndex) internal view returns (bytes32[] memory proof) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        require($.nextNonce != 0, EmptyMMR());
        require(leafIndex < $.nextNonce, LeafIndexOutOfBounds());

        (uint256 leafNodePos, uint256 mountainHeight, uint64 leafIdxInMountain, bytes32[] memory otherPeaks) =
            _generateProofData(leafIndex);

        // Generate intra-mountain proof directly
        bytes32[] memory intraMountainProof = new bytes32[](mountainHeight);
        uint256 currentPathNodePos = leafNodePos;

        for (uint256 hClimb = 0; hClimb < mountainHeight; hClimb++) {
            bool isRightChildInSubtree = (leafIdxInMountain >> hClimb) & 1 == 1;

            uint256 siblingNodePos;
            uint256 parentNodePos;

            if (isRightChildInSubtree) {
                parentNodePos = currentPathNodePos + 1;
                siblingNodePos = parentNodePos - (_BIT << (hClimb + 1));
            } else {
                parentNodePos = currentPathNodePos + (_BIT << (hClimb + 1));
                siblingNodePos = parentNodePos - 1;
            }

            require(siblingNodePos < $.nodes.length, SiblingNodeOutOfBounds());

            intraMountainProof[hClimb] = $.nodes[siblingNodePos];
            currentPathNodePos = parentNodePos;
        }

        // Combine proof elements
        proof = new bytes32[](intraMountainProof.length + otherPeaks.length);
        uint256 proofIndex = 0;

        for (uint256 i = 0; i < intraMountainProof.length; i++) {
            proof[proofIndex++] = intraMountainProof[i];
        }

        for (uint256 i = 0; i < otherPeaks.length; i++) {
            proof[proofIndex++] = otherPeaks[i];
        }
    }

    /// @notice Sends a message to the Solana bridge.
    ///
    /// @param sender The message's sender address.
    /// @param data Message data to be passed to the Solana bridge.
    function sendMessage(address sender, bytes memory data) internal {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        Message memory message = Message({nonce: $.nextNonce, sender: sender, data: data});
        bytes32 messageHash = _hashMessage(message);
        bytes32 mmrRoot = _appendLeafToMmr({leafHash: messageHash, originalLeafCount: $.nextNonce});

        unchecked {
            ++$.nextNonce;
        }

        emit MessageInitiated({messageHash: messageHash, mmrRoot: mmrRoot, message: message});
    }

    //////////////////////////////////////////////////////////////
    ///                     Private Functions                  ///
    //////////////////////////////////////////////////////////////

    /// @notice Computes the hash of a message.
    ///
    /// @param message The message to hash.
    ///
    /// @return The keccak256 hash of the encoded message.
    function _hashMessage(Message memory message) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(message.nonce, message.sender, message.data));
    }

    /// @notice Appends a new leaf to the MMR.
    ///
    /// @param leafHash The hash of the leaf to append.
    /// @param originalLeafCount The amount of MMR leaves before the append.
    ///
    /// @return newRoot The new root of the MMR after the append is complete.
    function _appendLeafToMmr(bytes32 leafHash, uint64 originalLeafCount) private returns (bytes32) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        // Add the leaf to the nodes array
        $.nodes.push(leafHash);

        // The MMR position of the leaf we just added
        uint256 newLeafNodeIndex = $.nodes.length - 1;

        // Form parent nodes by merging when possible
        _createParentNodes(newLeafNodeIndex, originalLeafCount);

        // Update and return the new root
        bytes32 newRoot = _calculateRoot(originalLeafCount + 1);
        $.root = newRoot;
        return newRoot;
    }

    /// @notice Creates parent nodes by merging when the binary representation allows it.
    ///
    /// @param leafNodeIndex The index of the newly added leaf node.
    /// @param originalLeafCount The original leaf count before adding the new leaf.
    function _createParentNodes(uint256 leafNodeIndex, uint64 originalLeafCount) private {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        uint256 currentNodeIndex = leafNodeIndex;
        uint256 currentHeight = 0;

        // Loop to create parent nodes when merging is possible
        while (_hasCompleteMountainAtHeight(originalLeafCount, currentHeight)) {
            uint256 leftSiblingIndex = _calculateLeftSiblingIndex(currentNodeIndex, currentHeight);

            // Get the hashes to merge
            bytes32 leftNodeHash = $.nodes[leftSiblingIndex];
            bytes32 rightNodeHash = $.nodes[currentNodeIndex];

            // Create and store the parent node
            bytes32 parentNodeHash = _hashInternalNode(leftNodeHash, rightNodeHash);
            $.nodes.push(parentNodeHash);

            // Update for next iteration
            currentNodeIndex = $.nodes.length - 1;
            currentHeight++;
        }
    }

    /// @notice Optimized single traversal to get leaf position and other peaks.
    ///
    /// @param leafIndex The 0-indexed position of the leaf to prove.
    ///
    /// @return leafNodePos Position of the leaf in the _nodes array.
    /// @return mountainHeight Height of the mountain containing the leaf.
    /// @return leafIdxInMountain Position of leaf within its mountain.
    /// @return otherPeaks Hashes of other mountain peaks.
    function _generateProofData(uint64 leafIndex)
        private
        view
        returns (uint256 leafNodePos, uint256 mountainHeight, uint64 leafIdxInMountain, bytes32[] memory otherPeaks)
    {
        // First pass: find the leaf mountain
        (leafNodePos, mountainHeight, leafIdxInMountain) = _findLeafMountain(leafIndex);

        // Second pass: collect other peaks
        otherPeaks = _collectOtherPeaks(leafIndex);
    }

    /// @notice Finds leaf mountain with minimal local variables
    ///
    /// @param leafIndex The 0-indexed position of the leaf to prove.
    ///
    /// @return Position of the leaf in the _nodes array.
    /// @return Height of the mountain containing the leaf.
    /// @return Position of leaf within its mountain.
    function _findLeafMountain(uint64 leafIndex) private view returns (uint256, uint256, uint64) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        uint256 nodeOffset = 0;
        uint64 leafOffset = 0;
        uint256 maxHeight = _calculateMaxPossibleHeight($.nextNonce);

        for (uint256 h = maxHeight + 1; h > 0; h--) {
            uint256 height = h - 1;

            if (($.nextNonce >> height) & 1 == 1) {
                uint64 mountainLeaves = uint64(_BIT << height);

                if (leafIndex >= leafOffset && leafIndex < leafOffset + mountainLeaves) {
                    // Found the mountain
                    uint64 localLeafIdx = leafIndex - leafOffset;
                    uint256 localNodePos = 2 * uint256(localLeafIdx) - _popcount(localLeafIdx);
                    return (nodeOffset + localNodePos, height, localLeafIdx);
                }

                nodeOffset += _calculateTreeSize(height);
                leafOffset += mountainLeaves;
            }
        }

        revert LeafNotFound();
    }

    /// @notice Collects other mountain peaks.
    ///
    /// @param leafIndex The 0-indexed position of the leaf to prove.
    ///
    /// @return Hashes of other mountain peaks in left-to-right order.
    function _collectOtherPeaks(uint64 leafIndex) private view returns (bytes32[] memory) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        bytes32[] memory tempPeaks = new bytes32[](_MAX_PEAKS);
        uint256 peakCount = 0;
        uint256 nodeOffset = 0;
        uint64 leafOffset = 0;
        uint256 maxHeight = _calculateMaxPossibleHeight($.nextNonce);

        // Collect peaks in left-to-right order (largest to smallest mountain)
        for (uint256 h = maxHeight + 1; h > 0; h--) {
            uint256 height = h - 1;

            if (($.nextNonce >> height) & 1 == 1) {
                uint64 mountainLeaves = uint64(_BIT << height);
                bool isLeafMountain = (leafIndex >= leafOffset && leafIndex < leafOffset + mountainLeaves);
                uint256 treeSize = _calculateTreeSize(height);

                if (!isLeafMountain) {
                    uint256 peakPos = nodeOffset + treeSize - 1;
                    tempPeaks[peakCount++] = $.nodes[peakPos];
                }

                nodeOffset += treeSize;
                leafOffset += mountainLeaves;
            }
        }

        // Use assembly to truncate tempPeaks to exact size
        assembly ("memory-safe") {
            mstore(tempPeaks, peakCount)
        }

        return tempPeaks;
    }

    /// @notice Calculates the current root by "bagging the peaks".
    ///
    /// @param currentLeafCount Number of leaves to compute the root for.
    ///
    /// @return The MMR root.
    function _calculateRoot(uint64 currentLeafCount) private view returns (bytes32) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        uint256 nodeCount = $.nodes.length;

        if (nodeCount == 0) {
            return bytes32(0);
        }

        uint256[] memory peakIndices = _getPeakNodeIndicesForLeafCount(currentLeafCount);

        if (peakIndices.length == 0) {
            return bytes32(0);
        }

        // Single peak case: return the peak directly
        if (peakIndices.length == 1) {
            return $.nodes[peakIndices[0]];
        }

        return _hashPeaksSequentially(peakIndices);
    }

    /// @notice Hashes all peaks sequentially from left to right.
    ///
    /// @param peakIndices Array of peak node indices (ordered from leftmost to rightmost).
    ///
    /// @return The final root hash after hashing all peaks.
    function _hashPeaksSequentially(uint256[] memory peakIndices) private view returns (bytes32) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();

        // Start with the leftmost peak (first in our left-to-right list)
        bytes32 currentRoot = $.nodes[peakIndices[0]];

        // Sequentially hash with the next peak to the right
        for (uint256 i = 1; i < peakIndices.length; i++) {
            bytes32 nextPeakHash = $.nodes[peakIndices[i]];
            // Bagging peaks must be ORDERED (non-commutative) to bind each
            // peak to its mountain position/size. Do not sort here.
            currentRoot = _hashOrderedPair(currentRoot, nextPeakHash);
        }

        return currentRoot;
    }

    /// @notice Gets the indices of all peak nodes in the MMR.
    ///
    /// @return The indices of the peak nodes ordered from leftmost to rightmost.
    function _getPeakNodeIndices() private view returns (uint256[] memory) {
        MessageStorageLibStorage storage $ = getMessageStorageLibStorage();
        return _getPeakNodeIndicesForLeafCount($.nextNonce);
    }

    /// @notice Gets the indices of all peak nodes in the MMR for a specific leaf count.
    ///
    /// @param leafCount The number of leaves to calculate peaks for.
    ///
    /// @return The indices of the peak nodes ordered from leftmost to rightmost.
    function _getPeakNodeIndicesForLeafCount(uint64 leafCount) private pure returns (uint256[] memory) {
        if (leafCount == 0) {
            return new uint256[](0);
        }

        uint256[] memory tempPeakIndices = new uint256[](_MAX_PEAKS);
        uint256 peakCount = 0;
        uint256 nodeOffset = 0;

        uint256 maxHeight = _calculateMaxPossibleHeight(leafCount);

        // Process each possible height from largest to smallest (left-to-right)
        for (uint256 height = maxHeight + 1; height > 0; height--) {
            uint256 currentHeight = height - 1;
            if (_hasCompleteMountainAtHeight(leafCount, currentHeight)) {
                uint256 peakIndex = _calculatePeakIndex(nodeOffset, currentHeight);
                tempPeakIndices[peakCount] = peakIndex;
                peakCount++;

                // Update state for next iteration
                nodeOffset += _calculateTreeSize(currentHeight);
            }
        }

        // Use assembly to truncate tempPeakIndices to exact size
        assembly ("memory-safe") {
            mstore(tempPeakIndices, peakCount)
        }

        return tempPeakIndices;
    }

    /// @notice Calculates the index of the left sibling node
    ///
    /// @param currentNodeIndex The index of the current node
    /// @param height The height of the current level
    ///
    /// @return leftSiblingIndex The index of the left sibling node
    function _calculateLeftSiblingIndex(uint256 currentNodeIndex, uint256 height) private pure returns (uint256) {
        uint256 leftSubtreeSize = _calculateTreeSize(height);
        return currentNodeIndex - leftSubtreeSize;
    }

    /// @notice Calculates the maximum possible height for the given number of leaves.
    ///
    /// @param leafCount Number of leaves in the MMR.
    ///
    /// @return The maximum possible height.
    function _calculateMaxPossibleHeight(uint64 leafCount) private pure returns (uint256) {
        if (leafCount == 0) return 0;

        uint256 maxHeight = 0;
        uint64 temp = leafCount;
        while (temp > 0) {
            maxHeight++;
            temp >>= 1;
        }
        return maxHeight > 0 ? maxHeight - 1 : 0;
    }

    /// @notice Checks if there's a complete mountain at the given height.
    ///
    /// @param leafCount Number of remaining leaves.
    /// @param height Height to check.
    ///
    /// @return True if there's a complete mountain at this height.
    function _hasCompleteMountainAtHeight(uint64 leafCount, uint256 height) private pure returns (bool) {
        return (leafCount >> height) & 1 == 1;
    }

    /// @notice Calculates the peak index for a mountain at the given height.
    ///
    /// @param nodeOffset Current offset in the nodes array.
    /// @param height Height of the mountain.
    ///
    /// @return Index of the peak node.
    function _calculatePeakIndex(uint256 nodeOffset, uint256 height) private pure returns (uint256) {
        uint256 mountainSize = _calculateTreeSize(height);
        return nodeOffset + mountainSize - 1;
    }

    /// @notice Calculates the number of nodes in a complete mountain of given height.
    ///
    /// @param height Height of the mountain.
    ///
    /// @return Number of nodes in the mountain.
    function _calculateTreeSize(uint256 height) private pure returns (uint256) {
        return (_BIT << (height + 1)) - 1;
    }

    /// @notice Hashes two node hashes together for intra-mountain merges.
    ///
    /// @dev Uses sorted inputs for commutative hashing: H(left, right) == H(right, left).
    ///      This is only used within a single mountain where sibling ordering
    ///      may not be deterministic.
    function _hashInternalNode(bytes32 left, bytes32 right) private pure returns (bytes32) {
        if (left < right) {
            return EfficientHashLib.hash(left, right);
        }
        return EfficientHashLib.hash(right, left);
    }

    /// @notice Ordered hash for bagging peaks left-to-right (non-commutative).
    ///
    /// @dev The order is significant to bind each peak to its position and size.
    function _hashOrderedPair(bytes32 left, bytes32 right) private pure returns (bytes32) {
        return EfficientHashLib.hash(left, right);
    }

    /// @notice Calculates the population count (number of 1 bits) in a uint64.
    ///
    /// @param x The number to count bits in.
    ///
    /// @return The number of 1 bits.
    function _popcount(uint64 x) private pure returns (uint256) {
        uint256 count = 0;
        while (x != 0) {
            count += x & 1;
            x >>= 1;
        }
        return count;
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre MessageStorageLib
Buscando 'MessageStorageLib' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (13ms)


### HIGH findings en dominio crosschain
Buscando 'MessageStorageLib getMessageStorageLibStorage generateProof sendMessage _hashMes' [SQLite FTS5] (dominio: crosschain)...

Top 6 findings relevantes: (78ms)

 1. [HIGH] Add _mirrorConnector to_sendMessage ofBaseMultichain — Connext
 2. [HIGH] Users Can Lose Refund by Default — Scroll Phase 1 Audit
 3. [HIGH] Messages destined for ZkSync cannot be processed — Connext
 4. [HIGH] Cross-chain messaging via Multichain protocol will fail — Connext
 5. [HIGH] [H-01] Incorrect access control logic in `onlyDeposit` modifier — Nexus_2024-11-29
 6. [HIGH] User’s Funds Would Stuck if the Message Claim Failed on the Destination Layer — Linea Message Service

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: MessageStorageLib getMessageStorageLibStorage generateProof sendMessage _hashMes | Dominio: crosschain
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] Add _mirrorConnector to_sendMessage ofBaseMultichain (Connext)
   ## High Risk Report

## Severity: High Risk

### Context
BaseMultichain.sol#L39-L47

### Description
The function `_sendMessage()` of `BaseMultichain`...

2. [HIGH] Users Can Lose Refund by Default (Scroll Phase 1 Audit)
   In the `L1ScrollMessenger`, the `sendMessage` functions allow a user to initiate a transaction on L2 from L1. There are two `sendMessage` implementati...

3. [HIGH] Messages destined for ZkSync cannot be processed (Connext)
   ## Severity: High Risk

## Context
ZkSyncHubConnector.sol#L49-L72

## Description
For ZkSync chain, L2 to L1 communication is free, but L1 to L2 commu...

4. [HIGH] Cross-chain messaging via Multichain protocol will fail (Connext)
   ## Security Assessment

## Severity: 
**High Risk**

## Context: 
`BaseMultichain.sol#L39-L47`

## Description: 
Multichain v6 is supported by Connext...

5. [HIGH] [H-01] Incorrect access control logic in `onlyDeposit` modifier (Nexus_2024-11-29)
   ## Severity

**Impact:** Medium

**Likelihood:** High

## Description

The `onlyDeposit` modifier in both Messaging and MessagingBera contracts contai...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'MessageStorageLib getMessageStorageLibStorage generateProof ' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (2ms)

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
ID prefix para este componente: `MSL` (ej: MSL-01, MSL-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_MessageStorageLib_FlowHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: MSL-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "MSL-01: value decreased");
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
