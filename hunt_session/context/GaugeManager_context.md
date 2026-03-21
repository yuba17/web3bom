# Contexto de Hunt — GaugeManager

**Protocolo**: revert-lend
**Dominio**: staking
**LOC**: 447
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/GaugeManager.sol
**Generado**: 2026-03-21T03:09:09.897352Z

## Solodit Context
Buscando 'staking' [SQLite FTS5] (dominio: staking)...

Top 5 findings relevantes: (16ms)

 1. [LOW] StakedSui Object Merge — Volo
 2. [LOW] Limit Bypass via stake_coins — Tortuga
 3. [LOW] Limit Bypass Through Stake Coins Invocation — Tortugal TIP
 4. [LOW] Incorrect Removal Of Pending Deposit Stake — Hubble Farms
 5. [LOW] Validator deactivation / reactivation does not consider next_delta_stake during  — Monad

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GaugeManager | Dominio: staking
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] StakedSui Object Merge (Volo)
   ## Staking Pool Functionality

## Description
`staking_pool::join_staked_sui` facilitates the merging of Staked Sui objects when their metadata matche...

2. [LOW] Limit Bypass via stake_coins (Tortuga)
   ## Stake Router Overview

The `stake_router` provides two entrypoints to stake coins:

- **`stake_router::stake_coins`**: A permissionless staking end...

3. [LOW] Limit Bypass Through Stake Coins Invocation (Tortugal TIP)
   ## Stake Router Overview

The `stake_router` provides two entry points to stake coins:

- **`stake_router::stake_coins`**  
  A permissionless staking...

4. [LOW] Incorrect Removal Of Pending Deposit Stake (Hubble Farms)
   ## Stake Operations Overview

In `stake_operations`, `convert_stake_to_amount` converts a stake (represented as a decimal) into an equivalent amount o...

5. [LOW] Validator deactivation / reactivation does not consider next_delta_stake during the boundary pe- (Monad)
   ## Risk Assessment

**Severity:** Low Risk

**Context:** No context files were provided by the reviewer.

## Description

Issue found in commit hash `...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


## Briefing del Dominio
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Reward-Per-Share Rounding Exploitation
### 1.2 Stake Just Before Distribution (Timing Attack)
### 1.3 Reward Donation Inflation
### 1.4 Double-Claim Prevention Failure
### 1.5 Cooldown / Unstake Bypass
### 1.6 Reward Token Exhaustion / Insolvency
### 1.9 ERC721 Position Staking (Gauge Style)
### 2.1 Cross-Function Reentrancy in Staking
### 2.2 Emergency Withdraw Accounting Break

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ 1 wei rounding per operation is generally not exploitable unless repeatable cheaply
  ⚠ Penalty mechanisms may intentionally reduce effective rewards — not a rounding bug
  ⚠ Rebasing staking tokens naturally cause accumulator drift
  ⚠ Contracts without lock periods are vulnerable by design — confirm this is unintentional
  ⚠ Linear distribution (Synthetix rewardsDuration) mitigates single-block extraction but not multi-block flash loans
  ⚠ Private mempool (Flashbots) reduces but does not eliminate risk
  ⚠ Protocols with same staking and reward token are more vulnerable
  ⚠ Some protocols intentionally accept donations as extra yield — verify design intent
  ⚠ Virtual shares offset mitigates share-price inflation but not reward accumulator inflation
  ⚠ Standard Synthetix pattern is safe IF modifiers are applied correctly
  ⚠ ERC-20 transfers (no hooks) do not enable reentrancy — only flag for ERC-777 or native ETH
  ⚠ Leftover rewards from previous epoch rolled into new epoch is expected in some designs

## CHECKLIST DE INVARIANTES
| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| INV-STAKE-001 | totalStaked == sum(balanceOf(all_stakers)) | 1 | reward_distribution.json |
| INV-STAKE-002 | rewardPerToken monotonically increases | 1 | reward_distribution.json |
| INV-STAKE-003 | claimed <= earned(user) at call time | 1 | reward_distribution.json |
| INV-STAKE-004 | unstake(amount) reduces balance by exactly amount | 2 | reward_distribution.json |
| INV-STAKE-005 | unstake r
