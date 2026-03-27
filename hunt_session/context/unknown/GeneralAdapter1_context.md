# Contexto de Hunt — GeneralAdapter1

**Protocolo**: morpho-bundler3
**Dominio**: trust
**LOC**: 210
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/GeneralAdapter1.sol
**Generado**: 2026-03-22T21:08:32.918715Z

## Solodit Context
### Findings sobre GeneralAdapter1
Buscando 'GeneralAdapter1' [SQLite FTS5] (dominio: general)...

Top 2 findings relevantes: (46ms)

 1. [MEDIUM] Non-whitelisted users can mint vault shares with permissioned tokens through the — Morpho
 2. [MEDIUM] GeneralAdapter1.morphoRepay() incorrectly fetches the borrowShares of initiator  — Morpho Bundler v3

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GeneralAdapter1 | Dominio: general
Los siguientes 2 findings de protocolos similares son relevantes:

1. [MEDIUM] Non-whitelisted users can mint vault shares with permissioned tokens through the bundler  (Morpho)
   ## Context
- GeneralAdapter1.sol#L57-L68
- GeneralAdapter1.sol#L224-L246

## Description
In PR 233, `GeneralAdapter1.erc20WrapperDepositFor()` was mod...

2. [MEDIUM] GeneralAdapter1.morphoRepay() incorrectly fetches the borrowShares of initiator instead of onBe- (Morpho Bundler v3)
   ## Half

**Severity:** Medium Risk  
**Context:** GeneralAdapter1.sol#L309-L312, GeneralAdapter1.sol#L316  

**Description:**  
When `GeneralAdapter1....

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'GeneralAdapter1 erc4626Mint erc4626Deposit erc4626Withdraw erc4626Redeem' [SQLite FTS5] (dominio: trust)...
Top 1 findings relevantes: (5ms)
 1. [HIGH] Unvalidated Variable Parameters Allow Fee Manipulation — P2P.org
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: GeneralAdapter1 erc4626Mint erc4626Deposit erc4626Withdraw erc4626Redeem | Dominio: trust
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] Unvalidated Variable Parameters Allow Fee Manipulation (P2P.org)
   ##### Description
This issue has been identified within the `deposit` and `withdraw` functions of the `P2pLendingProxy` contract. 
It is impossible t...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'GeneralAdapter1 erc4626Mint erc4626Deposit erc4626Withdraw e' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (2ms)

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
 
