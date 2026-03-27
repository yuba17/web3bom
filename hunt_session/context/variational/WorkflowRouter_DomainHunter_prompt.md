# DomainHunter — WorkflowRouter Analysis

## Tu Identidad
Eres el **DomainHunter** del equipo de bug hunting de chainlink-pa-v2.
Tu especialidad: **Protocol-specific invariants, cross-component interactions, economic attacks**

## Tu Objetivo
Analizar `WorkflowRouter` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/chainlink-pa-v2/src/WorkflowRouter.sol`
**Dominio**: access


```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IERC165, IReceiver} from "@chainlink/contracts/src/v0.8/keystone/interfaces/IReceiver.sol";
import {ITypeAndVersion} from "@chainlink/contracts/src/v0.8/shared/interfaces/ITypeAndVersion.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Caller} from "src/Caller.sol";
import {PausableWithAccessControl} from "src/PausableWithAccessControl.sol";
import {Errors} from "src/libraries/Errors.sol";
import {Roles} from "src/libraries/Roles.sol";

contract WorkflowRouter is PausableWithAccessControl, Caller, IReceiver, ITypeAndVersion {
  using EnumerableSet for EnumerableSet.AddressSet;
  using EnumerableSet for EnumerableSet.Bytes32Set;

  /// @notice This error is thrown when the workflow ID is not allowlisted.
  /// @param workflowId The unauthorized workflow ID.
  error WorkflowIdNotAllowlisted(bytes32 workflowId);
  /// @notice This error is thrown when a target is not allowlisted.
  /// @param workflowId The workflow ID associated with the unauthorized target.
  /// @param target The unauthorized target address.
  error TargetNotAllowlisted(bytes32 workflowId, address target);
  /// @notice This error is thrown when the function selector is not allowlisted.
  /// @param workflowId The workflow ID associated with the unauthorized function selector.
  /// @param target The target address associated with the unauthorized function selector.
  /// @param selector The invalid function selector.
  error SelectorNotAllowlisted(bytes32 workflowId, address target, bytes4 selector);

  /// @notice This event is emitted when a function selector is allowlisted for a workflow ID and target.
  /// @param workflowId The workflow ID associated with the allowlisted function selector.
  /// @param target The target address associated with the allowlisted function selector.
  /// @param selector The function selector that was allowlisted.
  event SelectorAllowlisted(bytes32 indexed workflowId, address indexed target, bytes4 indexed selector);
  /// @notice This event is emitted when a workflow id is removed from the allowlist.
  /// @param workflowId The workflow ID that was removed from the allowlist.
  event WorkflowIdRemovedFromAllowlist(bytes32 indexed workflowId);
  /// @notice This event is emitted when a target is removed from the allowlist.
  /// @param workflowId The workflow ID associated with the removed target.
  /// @param target The target address that was removed from the allowlist.
  event TargetRemovedFromAllowlist(bytes32 indexed workflowId, address indexed target);
  /// @notice This event is emitted when a function selector is removed from the allowlist.
  /// @param workflowId The workflow ID associated with the removed function selector.
  /// @param target The target address associated with the removed function selector.
  /// @param selector The function selector that was removed from the allowlist.
  event SelectorRemovedFromAllowlist(bytes32 indexed workflowId, address indexed target, bytes4 indexed selector);

  /// @notice Parameters to allowlist a target and selector for a workflow ID.
  struct TargetSelectors {
    address target; // The target address to allowlist for the workflow ID.
    bytes4[] selectors; // The function selectors to allowlist for the target and workflow ID.
  }

  /// @notice Parameters to set a workflow ID for a specific workflow type.
  struct AllowlistedWorkflow {
    bytes32 workflowId; // The unique identifier of the workflow.
    TargetSelectors[] targetSelectors; // The target and selector pairs that are allowlisted for the workflow ID.
  }

  /// @inheritdoc ITypeAndVersion
  string public constant override typeAndVersion = "WorkflowRouter 1.0.0-dev";

  /// @notice Set of allowlisted workflow IDs.
  EnumerableSet.Bytes32Set private s_allowlistedWorkflowIds;

  /// @notice Struct to store the allowlisted targets and selectors for a workflow ID.
  struct WorkflowInfo {
    // Set of allowlisted targets.
    EnumerableSet.AddressSet allowlistedTargets;
    // Mapping of allowlisted targets to their corresponding allowlisted function selectors.
    mapping(address target => EnumerableSet.Bytes32Set selectors) allowlistedSelectors;
  }

  /// @notice Mapping of allowlisted workflowId to its allowlisted targets and selectors.
  mapping(bytes32 workflowId => WorkflowInfo info) private s_workflowInfos;

  constructor(
    uint48 adminRoleTransferDelay,
    address admin
  ) PausableWithAccessControl(adminRoleTransferDelay, admin) {}

  /// @inheritdoc IReceiver
  /// @dev precondition - the contract must not be paused.
  /// @dev precondition - the caller must have the FORWARDER_ROLE.
  /// @dev precondition - the workflow ID extracted from the metadata must correspond to a supported workflow type.
  function onReport(
    bytes calldata metadata,
    bytes calldata report
  ) external whenNotPaused onlyRole(Roles.FORWARDER_ROLE) {
    // Metadata structure:
    // - Offset 32, size 32: workflow_id (bytes32)
    // - Offset 64, size 10: workflow_name (bytes10)
    // - Offset 74, size 20: workflow_owner (address)
    bytes32 workflowId = bytes32(metadata[:32]);
    if (workflowId == bytes32(0)) {
      revert Errors.InvalidZeroValue();
    }

    if (!s_allowlistedWorkflowIds.contains(workflowId)) {
      revert WorkflowIdNotAllowlisted(workflowId);
    }

    (address target, bytes memory data) = abi.decode(report, (address, bytes));
    bytes4 selector;

    assembly ("memory-safe") {
      selector := mload(add(data, 32))
    }

    if (!s_workflowInfos[workflowId].allowlistedSelectors[target].contains(selector)) {
      if (!s_workflowInfos[workflowId].allowlistedTargets.contains(target)) {
        revert TargetNotAllowlisted(workflowId, target);
      }
      revert SelectorNotAllowlisted(workflowId, target, selector);
    }

    _call(target, data);
  }

  // ================================================================================================
  // │                                        Configuration                                         │
  // ================================================================================================

  /// @notice Applies updates to the allowlisted workflows, targets, and selectors.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @dev precondition - at least one of the removes or adds lists must be non empty.
  /// @dev precondition - workflow IDs in the removes list must already be allowlisted.
  /// @dev precondition - workflow IDs in the adds list must not be zero.
  /// @dev Although sets are unbounded, in practice the removes and adds lists should be kept to a reasonable length to
  /// avoid running into block gas limits when processing the updates.
  /// @param removes An array of workflow IDs to remove from the allowlist.
  /// @param adds An array of AllowlistedWorkflow structs representing the workflow IDs, targets, and selectors to add
  /// to the allowlist.
  function applyAllowlistedWorkflowsUpdates(
    bytes32[] calldata removes,
    AllowlistedWorkflow[] calldata adds
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (removes.length == 0 && adds.length == 0) {
      revert Errors.EmptyList();
    }

    for (uint256 i; i < removes.length; ++i) {
      bytes32 workflowId = removes[i];
      _applyAllowlistedTargetsUpdates(
        workflowId, s_workflowInfos[workflowId].allowlistedTargets.values(), new TargetSelectors[](0)
      );
      s_allowlistedWorkflowIds.remove(workflowId);

      emit WorkflowIdRemovedFromAllowlist(workflowId);
    }

    for (uint256 i; i < adds.length; ++i) {
      bytes32 workflowId = adds[i].workflowId;

      if (workflowId == bytes32(0)) {
        revert Errors.InvalidZeroValue();
      }

      s_allowlistedWorkflowIds.add(workflowId);
      _applyAllowlistedTargetsUpdates(workflowId, new address[](0), adds[i].targetSelectors);
    }
  }

  /// @notice Applies updates to the allowlisted targets for a workflow ID.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @param workflowId The workflow ID to apply the target updates for.
  /// @param removes An array of target addresses to remove from the allowlist for the specified workflow ID.
  /// @param adds An array of TargetSelectors structs representing the targets and selectors to add to the allowlist for
  /// the specified workflow ID.
  function applyAllowlistedTargetsUpdates(
    bytes32 workflowId,
    address[] calldata removes,
    TargetSelectors[] calldata adds
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _applyAllowlistedTargetsUpdates(workflowId, removes, adds);
  }

  /// @dev precondition - the workflow ID must be allowlisted.
  /// @dev precondition - at least one of the removes or adds lists must be non empty.
  /// @dev precondition - targets in the removes list must already be allowlisted for the specified workflow ID.
  /// @dev precondition - targets in the adds list must not be zero.
  /// @param workflowId The workflow ID to apply the target updates for.
  /// @param removes An array of target addresses to remove from the allowlist for the specified workflow ID.
  function _applyAllowlistedTargetsUpdates(
    bytes32 workflowId,
    address[] memory removes,
    TargetSelectors[] memory adds
  ) private {
    if (!s_allowlistedWorkflowIds.contains(workflowId)) {
      revert WorkflowIdNotAllowlisted(workflowId);
    }
    if (removes.length == 0 && adds.length == 0) {
      revert Errors.EmptyList();
    }

    for (uint256 i; i < removes.length; ++i) {
      address target = removes[i];
      bytes4[] memory removedSelectors;
      bytes32[] memory allowlistedSelectors = s_workflowInfos[workflowId].allowlistedSelectors[target].values();
      // This is a safe cast since both arrays are in memory and therefore each element is stored in a 32 bytes slot.
      assembly ("memory-safe") {
        removedSelectors := allowlistedSelectors
      }

      _applyAllowlistedSelectorsUpdates(workflowId, target, removedSelectors, new bytes4[](0));
      s_workflowInfos[workflowId].allowlistedTargets.remove(target);

      emit TargetRemovedFromAllowlist(workflowId, target);
    }

    for (uint256 i; i < adds.length; ++i) {
      address target = adds[i].target;

      if (target == address(0)) {
        revert Errors.InvalidZeroAddress();
      }

      s_workflowInfos[workflowId].allowlistedTargets.add(target);
      _applyAllowlistedSelectorsUpdates(workflowId, target, new bytes4[](0), adds[i].selectors);
    }
  }

  /// @notice Applies updates to the allowlisted selectors for a workflow ID and target.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @param workflowId The workflow ID to apply the selector updates for.
  /// @param target The target address to apply the selector updates for.
  /// @param removes An array of function selectors to remove from the allowlist for the specified workflow ID and
  /// target.
  /// @param adds An array of function selectors to add to the allowlist for the specified workflow ID and target.
  function applyAllowlistedSelectorsUpdates(
    bytes32 workflowId,
    address target,
    bytes4[] calldata removes,
    bytes4[] calldata adds
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _applyAllowlistedSelectorsUpdates(workflowId, target, removes, adds);
  }

  /// @dev precondition - the workflow ID must be allowlisted.
  /// @dev precondition - the target must be allowlisted for the specified workflow ID.
  /// @dev precondition - at least one of the removes or adds lists must be non empty.
  /// @dev precondition - function selectors in the removes list must already be allowlisted for the specified workflow
  /// ID and target.
  /// @dev precondition - function selectors in the adds list must not be zero.
  /// @param workflowId The workflow ID to apply the selector updates for.
  /// @param target The target address to apply the selector updates for.
  /// @param removes An array of function selectors to remove from the allowlist for the specified workflow ID and
  /// target.
  /// @param adds An array of function selectors to add to the allowlist for the specified workflow ID and
  /// target.
  function _applyAllowlistedSelectorsUpdates(
    bytes32 workflowId,
    address target,
    bytes4[] memory removes,
    bytes4[] memory adds
  ) private {
    if (!s_allowlistedWorkflowIds.contains(workflowId)) {
      revert WorkflowIdNotAllowlisted(workflowId);
    }
    if (!s_workflowInfos[workflowId].allowlistedTargets.contains(target)) {
      revert TargetNotAllowlisted(workflowId, target);
    }
    if (removes.length == 0 && adds.length == 0) {
      revert Errors.EmptyList();
    }

    for (uint256 i; i < removes.length; ++i) {
      bytes4 selector = removes[i];
      if (!s_workflowInfos[workflowId].allowlistedSelectors[target].remove(bytes32(selector))) {
        revert SelectorNotAllowlisted(workflowId, target, selector);
      }

      emit SelectorRemovedFromAllowlist(workflowId, target, selector);
    }

    for (uint256 i; i < adds.length; ++i) {
      bytes4 selector = adds[i];

      if (selector == bytes4(0)) {
        revert Errors.InvalidZeroValue();
      }

      if (s_workflowInfos[workflowId].allowlistedSelectors[target].add(bytes32(selector))) {
        emit SelectorAllowlisted(workflowId, target, selector);
      }
    }
  }

  // ================================================================================================
  // │                                           Getters                                            │
  // ================================================================================================

  /// @notice Getter function to retrieve the allowlisted workflow IDs.
  function getAllowlistedWorkflowIds() external view returns (bytes32[] memory workflowIds) {
    return s_allowlistedWorkflowIds.values();
  }

  /// @notice Getter function to retrieve the allowlisted targets for a workflow ID.
  /// @param workflowId The workflow ID to retrieve the allowlisted targets for.
  /// @return targets An array of allowlisted target addresses for the specified workflow ID.
  function getAllowlistedTargets(
    bytes32 workflowId
  ) external view returns (address[] memory targets) {
    return s_workflowInfos[workflowId].allowlistedTargets.values();
  }

  /// @notice Getter function to retrieve the allowlisted function selectors for a workflow ID and target.
  /// @param workflowId The workflow ID to retrieve the allowlisted function selectors for.
  /// @param target The target address to retrieve the allowlisted function selectors for.
  /// @return selectors An array of allowlisted function selectors for the specified workflow ID and target
  function getAllowlistedSelectors(
    bytes32 workflowId,
    address target
  ) external view returns (bytes4[] memory selectors) {
    bytes32[] memory allowlistedSelectors = s_workflowInfos[workflowId].allowlistedSelectors[target].values();
    assembly ("memory-safe") {
      selectors := allowlistedSelectors
    }

    return selectors;
  }

  /// @inheritdoc IERC165
  function supportsInterface(
    bytes4 interfaceId
  ) public view override(PausableWithAccessControl, IERC165) returns (bool) {
    return super.supportsInterface(interfaceId) || interfaceId == type(IReceiver).interfaceId;
  }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre WorkflowRouter
Buscando 'WorkflowRouter' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)


### HIGH findings en dominio access
Buscando 'WorkflowRouter onReport applyAllowlistedWorkflowsUpdates applyAllowlistedTargets' [SQLite FTS5] (dominio: access)...
Sin resultados para los criterios dados. (3ms)

### Cross-domain HIGH relevantes
Buscando 'WorkflowRouter onReport applyAllowlistedWorkflowsUpdates app' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (3ms)

 1. [HIGH] iOS client is susceptible to URI scheme hijacking — Uniswap Mobile Wallet
 2. [HIGH] CryptoPunks can be stolen via mint frontrunning — Paribus
 3. [HIGH] Lack of clear state program check allows any vault to be drained — StakerDao wAlgo
 4. [HIGH] Incorrect vault bytecode usage — StakerDao wAlgo

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: WorkflowRouter onReport applyAllowlistedWorkflowsUpdates app | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] iOS client is susceptible to URI scheme hijacking (Uniswap Mobile Wallet)
   ## Diﬃculty: High

## Type: Data Exposure

### Target: ios/Uniswap/Info.plist

### Description
The Uniswap mobile app defines the `uniswap://` URI sch...

2. [HIGH] CryptoPunks can be stolen via mint frontrunning (Paribus)
   **Severity**: Critical

**Status**:  Resolved

**Description**

Since the CryptoPunks NFT collection not implementing the ERC721 standard, depositing ...

3. [HIGH] Lack of clear state program check allows any vault to be drained (StakerDao wAlgo)
   ## Data Validation

**Type:** Data Validation  
**Target:** app-vault.teal  

**Difficulty:** Low  

## Description
The vault authorization can be abu...

4. [HIGH] Incorrect vault bytecode usage (StakerDao wAlgo)
   ## Configuration

**Type:** Configuration  
**Target:** vault.js  

**Difficulty:** High  

## Description

app-vault requires the vault bytecode to g...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

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

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Protocol-specific invariants) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `WR` (ej: WR-01, WR-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_WorkflowRouter_DomainHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: WR-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "WR-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
