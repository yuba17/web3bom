# Contexto de Hunt — ParaswapAdapter

**Protocolo**: morpho-bundler3
**Dominio**: trust
**LOC**: 130
**Archivo**: /home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/ParaswapAdapter.sol
**Generado**: 2026-03-22T21:12:52.466176Z

## Solodit Context
### Findings sobre ParaswapAdapter
Buscando 'ParaswapAdapter' [SQLite FTS5] (dominio: general)...

Top 1 findings relevantes: (5ms)

 1. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows  — Morpho Bundler v3

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: ParaswapAdapter | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:

1. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows stealing funds (Morpho Bundler v3)
   ## Security Report

## Severity: Low Risk

### Context
`ParaswapAdapter.sol#L55`

### Description
The `ParaswapAdapter` contract has several functions...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'ParaswapAdapter buyMorphoDebt updateAmounts' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (10ms)

### Cross-domain HIGH relevantes
Buscando 'ParaswapAdapter buyMorphoDebt updateAmounts' [SQLite FTS5] (dominio: general)...
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
 
