# TrustBoundaryHunter — Oracle Analysis

## Tu Identidad
Eres el **TrustBoundaryHunter** del equipo de bug hunting de variational.
Tu especialidad: **Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions**

## Tu Objetivo
Analizar `Oracle` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `variational-audit/src/Oracle.sol`
**Dominio**: access


## Asset Flow Map
### Money IN (deposits/receives)
- L280 transferFromOLPToPool(): bool fromSuccess = usdc.transferFrom(olpWallet, address(this), amount);
- L301 atomicDeposit(): bool fromSuccess = usdc.transferFrom(partyOneAddress, address(this), partyOneAmountRequested);

### Money OUT (withdrawals/sends)
- L303 atomicDeposit(): bool toSuccess = usdc.transfer(poolAddress, partyOneAmountRequested);
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";
import "lib/openzeppelin-contracts/contracts/security/ReentrancyGuard.sol";
import "lib/openzeppelin-contracts/contracts/security/Pausable.sol";
import "lib/openzeppelin-contracts/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "./interfaces/IOracle.sol";
import "./SettlementPool.sol";
import "./interfaces/ISettlementPoolFactory.sol";
import "./library/Fees.sol";
import "./library/Errors.sol";
import "./library/TreasuryManagement.sol";
import "./library/SettlementPools.sol";

contract Oracle is AccessControl, ReentrancyGuard, IOracle, Pausable {
    bytes32 public constant PROVIDER_ROLE = keccak256("PROVIDER_ROLE");
    ISettlementPoolFactory public override factory;
    uint256 private numProviders = 0;

    mapping(uint128 => address) private pools;
    mapping(uint128 => bool) public atomic_deposits_processed;

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender); // make the deployer admin
    }

    function collectFees(
        Fees.CollectionRequest[] memory requests
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        (
            Fees.CollectionRequest[] memory successfulRequests,
            Errors.ProcessingError[] memory failedRequests,
            uint successCount,
            uint failureCount
        ) = _processFeeRequests(requests);

        // Emit results
        emit FeeBatchProcessed(
            _truncateCollectionRequestsArray(successfulRequests, successCount),
            _truncateProcessingErrorsArray(failedRequests, failureCount)
        );
    }

    /**
     * @notice Truncates an array of CollectionRequest structs to the specified length.
     * @param array The array to truncate.
     * @param length The desired length.
     * @return A new array containing the truncated CollectionRequest structs.
     */
    function _truncateCollectionRequestsArray(
        Fees.CollectionRequest[] memory array,
        uint length
    ) internal pure returns (Fees.CollectionRequest[] memory) {
        Fees.CollectionRequest[] memory truncated = new Fees.CollectionRequest[](length);
        for (uint i = 0; i < length; i++) {
            truncated[i] = array[i];
        }
        return truncated;
    }


    /**
     * @notice Truncates an array of FeeProcessingError structs to the specified length.
     * @param array The array to truncate.
     * @param length The desired length.
     * @return A new array containing the truncated FeeProcessingError structs.
     */
    function _truncateProcessingErrorsArray(
        Errors.ProcessingError[] memory array,
        uint length
    ) internal pure returns (Errors.ProcessingError[] memory) {
        Errors.ProcessingError[] memory truncated = new Errors.ProcessingError[](length);
        for (uint i = 0; i < length; i++) {
            truncated[i] = array[i];
        }
        return truncated;
    }


    /**
     * @notice Processes fee collection requests.
     * @param requests The collection requests to process.
     * @return successfulRequests Truncated array of successful requests.
     * @return failedRequests Truncated array of failed requests with reasons.
     * @return successCount The number of successful requests.
     * @return failureCount The number of failed requests.
     */
    function _processFeeRequests(
        Fees.CollectionRequest[] memory requests
    ) internal returns (
        Fees.CollectionRequest[] memory successfulRequests,
        Errors.ProcessingError[] memory failedRequests,
        uint successCount,
        uint failureCount
    ) {
        successfulRequests = new Fees.CollectionRequest[](requests.length);
        failedRequests = new Errors.ProcessingError[](requests.length);
        successCount = 0;
        failureCount = 0;

        for (uint i = 0; i < requests.length; i++) {
            address poolAddress = factory.getPool(requests[i].poolUuid);
            require(poolAddress != address(0), "no pool mapping found for given poolUuid");

            try SettlementPool(poolAddress).withdrawFees(
                msg.sender, // only provider role can withdraw
                requests[i].amountRequested,
                requests[i].feesBatchId
            ) {
                successfulRequests[successCount] = requests[i];
                successCount++;
            } catch Error(string memory reason) {
                failedRequests[failureCount] = Errors.ProcessingError({
                    requestId: requests[i].feesBatchId,
                    failureReason: reason
                });
                failureCount++;
            } catch {
                failedRequests[failureCount] = Errors.ProcessingError({
                    requestId: requests[i].feesBatchId,
                    failureReason: "low-level error"
                });
                failureCount++;
            }
        }

        return (
            successfulRequests,
            failedRequests,
            successCount,
            failureCount
        );
    }


    /**
     * @notice Processes a batch of deposit requests for a single requestor.
     * @param requestor The address for which the deposits are made.
     * @param deposits The deposit requests to process.
     */
    function processTreasuryManagementDeposits(
        address requestor,
        TreasuryManagement.Deposit[] memory deposits
    ) external nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        uint depositsLength = deposits.length;

        uint128[] memory successfulTransferUuids = new uint128[](depositsLength);
        Errors.ProcessingError[] memory failedTransfers = new Errors.ProcessingError[](depositsLength);
        uint successCount = 0;
        uint failureCount = 0;

        for (uint i = 0; i < depositsLength; i++) {
            address poolAddress = factory.getPool(deposits[i].poolUuid);
            require(poolAddress != address(0), "Invalid poolUuid");

            try SettlementPool(poolAddress).depositUSDCNoEvent(
                requestor,
                deposits[i].amountRequested,
                deposits[i].transferUuid
            ) {
                successfulTransferUuids[successCount] = deposits[i].transferUuid;
                successCount++;
            } catch Error(string memory reason) {
                failedTransfers[failureCount] = Errors.ProcessingError({
                    requestId: deposits[i].transferUuid,
                    failureReason: reason
                });
                failureCount++;
            } catch {
                failedTransfers[failureCount] = Errors.ProcessingError({
                    requestId: deposits[i].transferUuid,
                    failureReason: "low-level error"
                });
                failureCount++;
            }
        }

        emit DepositsProcessed(
            requestor,
            _truncateUint128Array(successfulTransferUuids, successCount),
            _truncateProcessingErrorsArray(failedTransfers, failureCount)
        );
    }

    /**
     * @notice Processes a batch of withdrawal requests for a single requestor.
     * @param requestor The address for which the withdrawals are made.
     * @param withdrawals The withdrawal requests to process.
     */
    function processTreasuryManagementWithdrawals(
        address requestor,
        TreasuryManagement.Withdrawal[] memory withdrawals
    ) external nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        uint withdrawalsLength = withdrawals.length;

        uint128[] memory successfulTransferUuids = new uint128[](withdrawalsLength);
        Errors.ProcessingError[] memory failedTransfers = new Errors.ProcessingError[](withdrawalsLength);
        uint successCount = 0;
        uint failureCount = 0;

        for (uint i = 0; i < withdrawalsLength; i++) {
            address poolAddress = factory.getPool(withdrawals[i].poolUuid);
            require(poolAddress != address(0), "Invalid poolUuid");

            try SettlementPool(poolAddress).withdrawUSDCNoEvent(
                requestor,
                withdrawals[i].amountRequested,
                withdrawals[i].transferUuid
            ) {
                successfulTransferUuids[successCount] = withdrawals[i].transferUuid;
                successCount++;
            } catch Error(string memory reason) {
                failedTransfers[failureCount] = Errors.ProcessingError({
                    requestId: withdrawals[i].transferUuid,
                    failureReason: reason
                });
                failureCount++;
            } catch {
                failedTransfers[failureCount] = Errors.ProcessingError({
                    requestId: withdrawals[i].transferUuid,
                    failureReason: "low-level error"
                });
                failureCount++;
            }
        }

        emit WithdrawalsProcessed(
            requestor,
            _truncateUint128Array(successfulTransferUuids, successCount),
            _truncateProcessingErrorsArray(failedTransfers, failureCount)
        );
    }

    /**
     * @notice Truncates an array of uint128 values to the specified length.
     * @param array The array to truncate.
     * @param length The desired length.
     * @return A new array containing the truncated values.
     */
    function _truncateUint128Array(
        uint128[] memory array,
        uint length
    ) internal pure returns (uint128[] memory) {
        uint128[] memory truncated = new uint128[](length);
        for (uint i = 0; i < length; i++) {
            truncated[i] = array[i];
        }
        return truncated;
    }

    function withdrawUSDC(
        address requestor,
        uint256 amountRequested,
        uint128 poolUuid,
        uint128 transferUuid
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        address poolAddress = getPool(poolUuid);
        SettlementPool pool = SettlementPool(poolAddress);
        pool.withdrawUSDC(
            requestor,
            amountRequested,
            transferUuid
        );
    }

    function transferFromOLPToPool(
        address olpWallet,
        address poolAddress,
        uint256 amount,
        uint128 poolUuid,
        uint128 rfqUuid,
        uint128 parentQuoteUuid
    ) external nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        require(olpWallet != address(0), "Oracle: OLP wallet address cannot be zero");
        require(poolAddress != address(0), "Oracle: SettlementPool address cannot be zero");
        require(amount > 0, "Oracle: Transfer amount must be greater than zero");

        IERC20 usdc = factory.usdcAddress();
        bool fromSuccess = usdc.transferFrom(olpWallet, address(this), amount);
        require(fromSuccess, "Vault: Transfer from OLP wallet failed");
        bool toSuccess = usdc.transfer(poolAddress, amount);
        require(toSuccess, "Vault: Transfer to Settlement Pool failed");
        emit OLPToPoolTransfer(olpWallet, poolAddress, poolUuid, amount, rfqUuid, parentQuoteUuid);
    }

    function atomicDeposit(
        address partyOneAddress,
        address partyTwoAddress,
        uint256 partyOneAmountRequested,
        uint256 partyTwoAmountRequested,
        uint128 poolUuid,
        uint128 rfqUuid,
        uint128 parentQuoteUuid
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        address poolAddress = getPool(poolUuid);
        SettlementPool pool = SettlementPool(poolAddress);
        if (partyOneAmountRequested > 0 && partyTwoAmountRequested == 0) {
            require(atomic_deposits_processed[parentQuoteUuid] == false, "this transfer has already been processed");
            IERC20 usdc = factory.usdcAddress();
            bool fromSuccess = usdc.transferFrom(partyOneAddress, address(this), partyOneAmountRequested);
            require(fromSuccess, "Transfer from creator wallet failed");
            bool toSuccess = usdc.transfer(poolAddress, partyOneAmountRequested);
            require(toSuccess, "Transfer to Settlement Pool failed");
            if (parentQuoteUuid != 0) {
                atomic_deposits_processed[parentQuoteUuid] = true;
            }
        }
        require(
            (partyOneAddress == pool.creatorAddress() && pool.checkOtherAddress(partyTwoAddress)) ||
            (pool.checkOtherAddress(partyOneAddress) && partyTwoAddress == pool.creatorAddress()),
            "incorrect addresses provided"
        );
        pool.depositUSDCAtomic(
            partyOneAddress,
            partyTwoAddress,
            partyOneAmountRequested,
            partyTwoAmountRequested,
            rfqUuid,
            parentQuoteUuid
        );
    }

    function batchAtomicDeposit(
        uint128 poolUuid,
        address creatorPartyAddress,
        uint256 creatorPartyAmountRequested,
        SettlementPools.AtomicDepositBatchItem[] calldata items
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        address poolAddress = factory.getPool(poolUuid);
        require(poolAddress != address(0), "no pool mapping found for given poolUuid");
        SettlementPool pool = SettlementPool(poolAddress);
        require((creatorPartyAddress == pool.creatorAddress()), "incorrect creator address provided");
        for (uint i = 0; i < items.length; i++) {
            require(pool.checkOtherAddress(items[i].otherPartyAddress), "incorrect other address provided");
        }
        pool.batchDepositUSDCAtomic(
            creatorPartyAddress,
            creatorPartyAmountRequested,
            items
        );
    }

    function depositUSDC(
        address sender,
        uint256 amount,
        uint128 poolUuid,
        uint128 transferUuid
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        address poolAddress = getPool(poolUuid);
        SettlementPool pool = SettlementPool(poolAddress);
        pool.depositUSDCOnBehalfOfParty(
            sender,
            amount,
            transferUuid
        );
    }

    function createPool(
        address creatorAddress,
        address[] calldata otherAddresses,
        uint128 poolUuid,
        uint128 rfqUuid,
        uint128 parentQuoteUuid,
        address feePaidBy,
        uint256 feeAmount
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        require(pools[poolUuid] == address(0), "Pool already exists for the given UUID");
        address poolAddress = factory.createPool(
            creatorAddress,
            otherAddresses,
            poolUuid,
            rfqUuid,
            parentQuoteUuid,
            msg.sender,
            feePaidBy,
            feeAmount
        );
        pools[poolUuid] = poolAddress;
    }

    function addOtherParty(
        uint128 poolUuid,
        address otherAddress
    ) external override nonReentrant whenNotPaused onlyRole(PROVIDER_ROLE) {
        address poolAddress = factory.getPool(poolUuid);
        require(poolAddress != address(0), "no pool mapping found for given poolUuid");
        SettlementPool pool = SettlementPool(poolAddress);
        pool.addOtherParty(otherAddress);
    }

    function setSettlementPoolFactory(
        address factoryAddress
    ) external override nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        require(factoryAddress != address(0), "Factory address cannot be zero");
        require(factoryAddress != address(factory), "New factory must be different");
        factory = ISettlementPoolFactory(factoryAddress);
        emit FactoryUpdated(factoryAddress);
    }

    function getPool(uint128 poolUuid) public view returns (address) {
        address poolAddress = pools[poolUuid];
        require(poolAddress != address(0), "Pool not found for the given UUID");
        return poolAddress;
    }

    // Owner admin functions
    function addProvider(
        address provider
    ) external override nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            !hasRole(PROVIDER_ROLE, provider),
            "Oracle: Provider already added."
        );

        _grantRole(PROVIDER_ROLE, provider);
        numProviders++;

        emit ProviderAdded(provider);
    }

    function removeProvider(
        address provider
    ) external override nonReentrant whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            hasRole(PROVIDER_ROLE, provider),
            "Oracle: Address is not a recognized provider."
        );
        require(numProviders > 1, "Oracle: Cannot remove the only provider.");

        _revokeRole(PROVIDER_ROLE, provider);
        numProviders--;

        emit ProviderRemoved(provider);
    }

    // Override grantRole to ensure numProviders is updated when PROVIDER_ROLE is granted
    function grantRole(bytes32 role, address account) public override whenNotPaused onlyRole(getRoleAdmin(role)) {
        super.grantRole(role, account);

        if (role == PROVIDER_ROLE) {
            require(!hasRole(PROVIDER_ROLE, account), "Oracle: Provider already added.");
            numProviders++;
            emit ProviderAdded(account);
        }
    }

    // Override revokeRole to ensure numProviders is updated when PROVIDER_ROLE is revoked
    function revokeRole(bytes32 role, address account) public override whenNotPaused onlyRole(getRoleAdmin(role)) {
        if (role == PROVIDER_ROLE) {
            require(hasRole(PROVIDER_ROLE, account), "Oracle: Address is not a recognized provider.");
            require(numProviders > 1, "Oracle: Cannot remove the only provider.");
            numProviders--;
            emit ProviderRemoved(account);
        }
        super.revokeRole(role, account);
    }

    // Allows Default Admin to pause the contract
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    // Allows Default Admin to unpause the contract
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
}
```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Oracle
Buscando 'Oracle' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (8ms)

 1. [MEDIUM] Absence Of Oracle Account Validation — Switchboard On-chain
 2. [LOW] Oracles can be invalid in at most one way — Drift Protocol
 3. [HIGH] [H-01] A malicious signed price can be injected in `assets.price_tick()` — Starknet Perpetual
 4. [HIGH] Incorrect Oracle Garbage Collection — Switchboard_evm
 5. [LOW] [02] Silent Skipping of Inactive Oracles — Kinetiq

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Oracle | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [MEDIUM] Absence Of Oracle Account Validation (Switchboard On-chain)
   ## Randomness Commit Implementation Overview

In the current implementation, `RandomnessCommit` instruction takes an oracle account as a parameter and...

2. [LOW] Oracles can be invalid in at most one way (Drift Protocol)
   ## Drift Protocol Security Assessment

**Difficulty:** High  
**Type:** Patching  
**Target:** programs/drift/src/math/oracle.rs  

## Description
The...

3. [HIGH] [H-01] A malicious signed price can be injected in `assets.price_tick()` (Starknet Perpetual)
   

<https://github.com/code-423n4/2025-03-starknet/blob/512889bd5956243c00fc3291a69c3479008a1c8a/workspace/apps/perpetuals/contracts/src/core/component...

4. [HIGH] Incorrect Oracle Garbage Collection (Switchboard_evm)
   ## Oracle Heartbeat Vulnerability

`oracleHeartbeat` performs garbage collection on a valid oracle instead of an expired one. Each oracle has a field ...

5. [LOW] [02] Silent Skipping of Inactive Oracles (Kinetiq)
   
**Contract Name:** `OracleManager.sol`

**Function Name:** `generatePerformance`

**Description:**
The `generatePerformance` function skips inactive ...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio access
Buscando 'Oracle collectFees _truncateCollectionRequestsArray _truncateProcessingErrorsArr' [SQLite FTS5] (dominio: access)...
Top 6 findings relevantes: (23ms)
 1. [HIGH] Lack of Access Control in RequestBandPrice Function — Elys Modules
 2. [HIGH] Ability To Update Signer Key — Switchboard On-chain
 3. [HIGH] H-4: Attacker can call `KeeperFactory#settle` with empty arrays as input paramet — Perennial V2 Update #1
 4. [HIGH] Lack of a two-step process for admin role transfers — Folks Finance Capital Market Protocol v2
 5. [HIGH] A user’s balance can be bonded against their will — Wonderland Prophet
 6. [HIGH] Ine�ective access control can lead to user funds being stolen — Wonderland Prophet
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Oracle collectFees _truncateCollectionRequestsArray _truncateProcessingErrorsArr | Dominio: access
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Lack of Access Control in RequestBandPrice Function (Elys Modules)
   ##### Description
This function is intended to request price data from the Band Oracle, but it appears to lack sufficient access control measures. Th...
2. [HIGH] Ability To Update Signer Key (Switchboard On-chain)
   ## OracleSetConfigs Instruction
In the `OracleSetConfigs` instruction, the oracle authority may change the `secp256k1_signer` of the enclave after ve...
3. [HIGH] H-4: Attacker can call `KeeperFactory#settle` with empty arrays as input parameters to steal all keeper fees (Perennial V2 Update #1)
   Source: https://github.com/sherlock-audit/2023-10-perennial-judging/issues/50 
## Found by 
Emmanuel, rvierdiiev
## Summary
Anyone can call `KeeperFa...
4. [HIGH] Lack of a two-step process for admin role transfers (Folks Finance Capital Market Protocol v2)
   ## Security Assessment Report
## Difficulty: High
## Type: Data Validation
## Target
- `pool_ma

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
2. **Identifica** las funciones donde tu especialidad (Trust boundary analysis: token quirks (ERC777) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
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
ID prefix para este componente: `O` (ej: O-01, O-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Oracle_TrustBoundaryHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: O-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "O-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Compiler Version Check (OBLIGATORIO)
1. Verifica la versión de Solidity del contrato
2. Consulta https://docs.soliditylang.org/en/latest/bugs.html — ¿hay bugs conocidos para esa versión?
3. Si usa Vyper: verificar que NO es 0.2.15-0.3.0 (reentrancy lock failure → $69M Curve hack 2023)

## Weird ERC-20 Checklist (d-xo — OBLIGATORIO si el contrato interactúa con tokens)
Para cada token que el contrato maneja, verificar:
- ¿Retorna bool en transfer/approve? (USDT, BNB, OMG NO retornan)
- ¿Requiere approve(0) antes de re-approve? (USDT, KNC)
- ¿Revierte en transfer de valor 0? (LEND)
- ¿Es rebasing? (stETH, AMPL — balance cambia sin transfer)
- ¿Tiene fee-on-transfer? (amount recibido < amount enviado)
- ¿Tiene blocklist? (USDC, USDT — pueden bloquear el contrato)
- ¿Usa SafeERC20 para todas las interacciones?

Si el contrato asume comportamiento estándar ERC-20 y acepta tokens arbitrarios → HIGH risk.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
