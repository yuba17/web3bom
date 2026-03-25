# Contexto de Hunt — Bundler3

**Protocolo**: morpho-bundler3
**Dominio**: trust
**LOC**: 36
**Archivo**: /home/kali/Documents/Web3/morpho-bundler3/src/Bundler3.sol
**Generado**: 2026-03-23T16:20:32.206894Z

## Solodit Context
### Findings sobre Bundler3
Buscando 'Bundler3' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (14ms)


### HIGH findings en dominio trust
Buscando 'Bundler3 multicall reenter _multicall' [SQLite FTS5] (dominio: trust)...

Top 6 findings relevantes: (111ms)

 1. [HIGH] ETH left in threednsregcontrol contract can be stolen  — 3DNS Inc
 2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commi — 3DNS Inc
 3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of A — SphereX Audit
 4. [HIGH] Signature does not take all parameters into account and can be reused — Common Pool
 5. [HIGH] Denial-of-Service (DoS) by Opening a Credit Account on Behalf of the CreditFacad — Gearbox
 6. [HIGH] [H-01] Excess Payment When Plugin Owner Reduces Price — Bullasv2

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bundler3 multicall reenter _multicall | Dominio: trust
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] ETH left in threednsregcontrol contract can be stolen  (3DNS Inc)
   ## Multicall Vulnerability Analysis

**Context:** `Multicall.sol#L19-L29`  
The `multicall()` function can (recursively) call itself via `functionDele...

2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commitment  (3DNS Inc)
   ## Commitment Orderflow Vulnerability Analysis

## Context
- CommitmentOrderflow.sol#L140
- Multicall.sol#L23

## Description

### ThreeDNSRegControl ...

3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of All Likely Loop Lengths and Combinations (SphereX Audit)
   The current implementation requires explicit permission for each possible loop length if a protected method (internal, public, or external) is invoked...

4. [HIGH] Signature does not take all parameters into account and can be reused (Common Pool)
   ##### Description

The `CommonPool`'s `allocateFunds` function accepts a Deposit / Withdraw payload and a corresponding signature (it is a structure m...

5. [HIGH] Denial-of-Service (DoS) by Opening a Credit Account on Behalf of the CreditFacade Contract (Gearbox)
   ## Description

Malicious actors can create a Denial-of-Service (DoS) condition on the Gearbox protocol by opening a new `creditAccount` on behalf o...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'Bundler3 multicall reenter _multicall' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (6ms)

 1. [HIGH] ETH left in threednsregcontrol contract can be stolen  — 3DNS Inc
 2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commi — 3DNS Inc
 3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of A — SphereX Audit
 4. [HIGH] Signature does not take all parameters into account and can be reused — Common Pool

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bundler3 multicall reenter _multicall | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] ETH left in threednsregcontrol contract can be stolen  (3DNS Inc)
   ## Multicall Vulnerability Analysis

**Context:** `Multicall.sol#L19-L29`  
The `multicall()` function can (recursively) call itself via `functionDele...

2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commitment  (3DNS Inc)
   ## Commitment Orderflow Vulnerability Analysis

## Context
- CommitmentOrderflow.sol#L140
- Multicall.sol#L23

## Description

### ThreeDNSRegControl ...

3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of All Likely Loop Lengths and Combinations (SphereX 

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
 

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

No se encontraron funciones relevantes en Bundler3



