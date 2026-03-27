# Contexto de Hunt — SettlementPool

**Protocolo**: variational
**Dominio**: reentrancy
**LOC**: 283
**Archivo**: variational-audit/src/SettlementPool.sol
**Generado**: 2026-03-23T11:49:25.234277Z

## Solodit Context
### Findings sobre SettlementPool
Buscando 'SettlementPool' [SQLite FTS5] (dominio: general)...

Top 2 findings relevantes: (1ms)

 1. [LOW] [I-04] Not used event can be removed — Cadmos
 2. [LOW] [I-03] Check for zero balance in `cancelDeposit` — Cadmos

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: SettlementPool | Dominio: general
Los siguientes 2 findings de protocolos similares son relevantes:

1. [LOW] [I-04] Not used event can be removed (Cadmos)
   The `ForcedTransfer` event in `SettlementPool` is not used and can be removed....

2. [LOW] [I-03] Check for zero balance in `cancelDeposit` (Cadmos)
   The `cancelDeposit` method in `SettlementPool` is missing a check if the caller has more than zero balance....

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio reentrancy
Buscando 'SettlementPool _totalBalance _oracle _depositUSDCOnBehalf checkOtherAddress' [SQLite FTS5] (dominio: reentrancy)...
Top 6 findings relevantes: (8ms)
 1. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amoun — Kinetiq_2025-02-26
 2. [HIGH] L2ContractMigrationFacet doesn't increase total Stalk and Roots — Beanstalk: The Finale
 3. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken  — Astera
 4. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken  — Cod3x lend
 5. [HIGH] [C-02] Pending stake not accounted for in liquidity calculations — Coinflip_2025-02-19
 6. [HIGH] Incorrect `pricePerShare` calculation on zero totalSupply — Umami
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: SettlementPool _totalBalance _oracle _depositUSDCOnBehalf checkOtherAddress | Dominio: reentrancy
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amount (Kinetiq_2025-02-26)
## Severity
**Impact:** High
**Likelihood:** Medium
## Description
`OracleManager::generatePerformance` is supposed to be called once every hour ...
2. [HIGH] L2ContractMigrationFacet doesn't increase total Stalk and Roots (Beanstalk: The Finale)
   ## Summary
L2ContractMigrationFacet is used to migrate deposits owned by smart contracts.
Problem is that it increases balance of Stalk and Roots as...
3. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken transfers in- (Astera)
   ## Security Issue: Reward Distribution Index Overflow
**Severity:** High Risk  
**Context:** `RewardsDistributor.sol#L501`  
## Description
The rewa...
4. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken transfers inDefinetely (Cod3x lend)
   **Severity:** High Risk  
**Context:** RewardsDistributor.sol#L501  
**Description:**  
The reward formula in Reward Distributors (RewardsDistribut...
5. [HIGH] [C-02] Pending stake not accounted for in liquidity calculations (Coinflip_2025-02-19)
   ## Severity
**Impact:** High
**Likelihood:** High
## Description
The `Staking` contract uses `IERC20(token).balanceOf(address(this))` to determine...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'SettlementPool _totalBalance _oracle _depositUSDCOnBehalf ch' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (9ms)
 1. [HIGH] [H-03] Storage root assignment missing in tree finalization — Initia
 2. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amoun — Kinetiq_2025-02-26
 3. [HIGH] [H-01] UniswapConfig getters return wrong token config if token config does not  — Based Loans
 4. [HIGH] L2ContractMigrationFa

## Briefing del Dominio
### Briefing principal: reentrancy

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ nonReentrant no protege contra cross-function reentrancy si las dos funciones no comparten el lock
  ⚠ El patrón mutex (locked = true) solo protege el contrato actual, no contratos hermanos
  ⚠ Los callbacks ERC721/ERC1155 pueden disparar reentrancy en funciones que parecen seguras
  ⚠ Uniswap V3 usa un 'locked' flag global — esto protege contra cross-function reentrancy dentro del pool
  ⚠ Los protocolos multi-contract con callbacks entre contratos tienen la mayor superficie de cross-function reentrancy
  ⚠ Los delegates en Gnosis Safe pueden explotar cross-function reentrancy entre módulos
  ⚠ Las read-only reentrancy no modifican estado → nonReentrant no ayuda en el contrato víctima
  ⚠ La defensa está del lado del protocolo que LEE el precio, no del protocolo de AMM
  ⚠ Balancer V2 tuvo exactamente este bug — se arregló exponiendo reentrancyGuardEntered()
  ⚠ transferFrom (sin 'safe') no llama el callback — más seguro contra reentrancy pero menos seguro para receptores de contrato que no saben recibir NFTs
  ⚠ ERC1155 tiene el mismo patrón con onERC1155Received y onERC1155BatchReceived
  ⚠ El TWAP no es afectado por flash loans — el precio solo se actualiza al final del bloque


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

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar variational-audit/src/SettlementPool.sol: Invalid compilation: 
[Errno 2] No such file or directory: 'solc'


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `checkOtherAddress()` (L118)
```solidity
    function checkOtherAddress(address addr) external view override returns (bool) {
        return otherAddresses[addr];
    }
```

*Original no encontrado en lib/ — verificar manualmente*

