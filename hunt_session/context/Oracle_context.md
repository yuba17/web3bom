# Contexto de Hunt — Oracle

**Protocolo**: variational
**Dominio**: access
**LOC**: 414
**Archivo**: variational-audit/src/Oracle.sol
**Generado**: 2026-03-23T11:44:58.445108Z

## Solodit Context
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

## Briefing del Dominio
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

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar variational-audit/src/Oracle.sol: Invalid compilation: 
[Errno 2] No such file or directory: 'solc'


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `grantRole()` (L438)
```solidity
    function grantRole(bytes32 role, address account) public override whenNotPaused onlyRole(getRoleAdmin(role)) {
        super.grantRole(role, account);

        if (role == PROVIDER_ROLE) {
            require(!hasRole(PROVIDER_ROLE, account), "Oracle: Provider already added.");
            numProviders++;
            emit ProviderAdded(account);
        }
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `revokeRole()` (L449)
```solidity
    function revokeRole(bytes32 role, address account) public override whenNotPaused onlyRole(getRoleAdmin(role)) {
        if (role == PROVIDER_ROLE) {
            require(hasRole(PROVIDER_ROLE, account), "Oracle: Address is not a recognized provider.");
            require(numProviders > 1, "Oracle: Cannot remove the only provider.");
            numProviders--;
            emit ProviderRemoved(account);
        }
        super.revokeRole(role, account);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

