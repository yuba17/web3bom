# Contexto de Hunt — CoreAdapter

**Protocolo**: morpho-bundler3
**Dominio**: trust
**LOC**: 45
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/CoreAdapter.sol
**Generado**: 2026-03-22T21:08:02.788884Z

## Solodit Context
### Findings sobre CoreAdapter
Buscando 'CoreAdapter' [SQLite FTS5] (dominio: general)...

Top 3 findings relevantes: (7ms)

 1. [LOW] nativeTransfer() and erc20Transfer() cannot be used to skim remaining balances d — Morpho Bundler v3
 2. [LOW] EthereumGeneralAdapter1.wrapStEth() leaves dust amounts of stETH behind due to L — Morpho Bundler v3
 3. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows  — Morpho Bundler v3

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: CoreAdapter | Dominio: general
Los siguientes 3 findings de protocolos similares son relevantes:

1. [LOW] nativeTransfer() and erc20Transfer() cannot be used to skim remaining balances due to zero (Morpho Bundler v3)
   ## Amount Check

**Severity:** Low Risk  
**Context:** CoreAdapter.sol#L54, CoreAdapter.sol#L70  

**Description:**  
In CoreAdapter, the `nativeTrans...

2. [LOW] EthereumGeneralAdapter1.wrapStEth() leaves dust amounts of stETH behind due to Lido's 1-2 wei (Morpho Bundler v3)
   ## Corner Case

**Severity:** Low Risk  
**Context:** CoreAdapter.sol#L68-L72, EthereumGeneralAdapter1.sol#L111-L115  
**Description:** 

When `Ethere...

3. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows stealing funds (Morpho Bundler v3)
   ## Security Report

## Severity: Low Risk

### Context
`ParaswapAdapter.sol#L55`

### Description
The `ParaswapAdapter` contract has several functions...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'CoreAdapter nativeTransfer erc20Transfer initiator reenterBundler3' [SQLite FTS5] (dominio: trust)...
Top 6 findings relevantes: (100ms)
 1. [HIGH] Usage of msg.value in a loop. — Tokensfarm
 2. [HIGH] Usage of msg.value in the loop. — Tokensfarm
 3. [HIGH] TokenDrop: Unprotected initialize() function — PoolTogether - Pods
 4. [HIGH] [H-03]  Wrong implementation of `EIP712MetaTransaction` — Rolla
 5. [HIGH] 18_deploy_RollupRevenueVault.ts – Deployment Script Leaves Contract Uninitialize — Linea - Burn Mechanism
 6. [HIGH] Owner is not initialized — Lyopay
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: CoreAdapter nativeTransfer erc20Transfer initiator reenterBundler3 | Dominio: trust
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Usage of msg.value in a loop. (Tokensfarm)
   **Description**
Perpetual Tokens FarmSDK.sol, function notice Reduced StakeWithout StakeId(), line 1433.
TokensFarmSDK.sol, function notice ReducedSt...
2. [HIGH] Usage of msg.value in the loop. (Tokensfarm)
   **Description**
Perpetual TokensFarmSDK.sol, function notice Reduced StakeWithoutStakeld(), line 1433.
TokensFarmSDK.sol, function notice Reduced Sta...
3. [HIGH] TokenDrop: Unprotected initialize() function (PoolTogether - Pods)
   #### Description
The `TokenDrop.initialize()` function is unprotected and can be called multiple times.
**code/pods-v3-contracts/contracts/TokenDr...
4. [HIGH] [H-03]  Wrong implementation of `EIP712MetaTransaction` (Rolla)
   _Submitted by WatchPug_
1.  `EIP712MetaTransaction` is a utils contract that intended to be inherited by concrete (actual) contracts, therefore. it's...
5. [HIGH] 18_deploy_RollupRevenueVault.ts – Deployment Script Leaves Contract Uninitialized; fallback Does Not Enforce msg.value > 0 ✓ Fixed (Linea - Burn Mechanism)
   ...
Export to GitHub ...
Set external GitHub Repo ...
Export to Clipboard (json)
Export to Clipboard (text)
#### Resolution
Fixed in commit [831...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'CoreAdapter nativeTransfer erc20Transfer initiator reenterB

## Briefing del Dominio
### Briefing principal: trust

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ La mayoría de protocolos DeFi mainstream usan USDC/WETH — no son FoT.
  ⚠ El impacto real depende de si el token en scope puede ser FoT (verificar docs del protocolo).
  ⚠ Algunos auditores marcan esto como LOW/INFO si el protocolo explícitamente excluye FoT.
  ⚠ ERC777 ya no es popular post-2022, pero sigue siendo un vector con tokens heredados.
  ⚠ USDC/USDT no son ERC777, pero protocolos con reward tokens configurables sí son vulnerables.
  ⚠ GearBox demostró que ERC777 como colateral puede bloquear liquidaciones (DOS, no drain).
  ⚠ Circle rara vez bloquea direcciones de contratos DeFi — el riesgo es real pero bajo.
  ⚠ El riesgo más práctico es el griefing de liquidaciones en lending protocols.
  ⚠ Verificar si el protocolo tiene USDC como único colateral o tiene alternativas.
  ⚠ cToken de Compound NO es rebasing — su balance es fijo, sube el exchangeRate.
  ⚠ wstETH NO es rebasing — el precio sube, no el balance.
  ⚠ Sólo stETH "nativo" y aToken son rebasing en el sentido estricto.

## CHECKLIST DE INVARIANTES
```yaml
- id: tb-003
  titulo: Blocklist de USDC/USDT bloquea retiros o liquidaciones del protocolo
  causa_raiz: |
    USDC y USDT tienen función de blacklist/blocklist: el emisor puede bloquear cualquier
    address. Si el contrato o un usuario clave es bloqueado, transfer() revierte → función
    de retiro o liquidación revierte → fondos quedan congelados indefinidamente.
  como_funciona: |
    Path A (usuario bloqueado): Ganador de lotería/subasta bloqueado → transfer() revierte
    → nadie puede completar la distribución → protocolo atascado.
    Path B (protocolo bloqueado): Circle bloquea el propio contrato del protocolo →
    todos los usuarios pierden acceso a sus fondos.
    Path C (griefing): Atacante fuerza al lender/borrower a ser blacklisted → DoS de
    liquidaciones → bad debt acumula.
  invariante: |
    // No se puede invariar on-chain, pero arquitecturalmente:
 
