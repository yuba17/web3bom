# Contexto de Hunt — Bridge

**Protocolo**: base-bridge
**Dominio**: crosschain
**LOC**: 161
**Archivo**: /home/kali/Documents/Web3/bridge/base/src/Bridge.sol
**Generado**: 2026-03-27T18:39:02.108777Z

## Solodit Context
### Findings sobre Bridge
Buscando 'Bridge' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (16ms)

 1. [LOW] Unused imports — Yieldfi
 2. [HIGH] FEE COLLECTOR VAULT CHECK MISSING CAN LEAD TO DOS IN PHOTONMSG — NGL Bridge + Gorples Bridge
 3. [LOW] Lack of a double-step transferOwnership pattern — EVM Bridge Contracts
 4. [HIGH] Permanent failure to bridge wrapped ERC721 using Bridge::sendERC721UsingNative f — Sweep n Flip
 5. [LOW] Bridge address can not be changed if needed — Beyond

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bridge | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] Unused imports (Yieldfi)
   **Description:** Consider removing the following unused imports:

- contracts/bridge/Bridge.sol [Line: 7](https://github.com/YieldFiLabs/contracts/blo...

2. [HIGH] FEE COLLECTOR VAULT CHECK MISSING CAN LEAD TO DOS IN PHOTONMSG (NGL Bridge + Gorples Bridge)
   ##### Description

The `Initialize` statement of the `gorples-bridge` program allows the initialization of the bridge config account. This requires tw...

3. [LOW] Lack of a double-step transferOwnership pattern (EVM Bridge Contracts)
   ##### Description

The current ownership transfer process for the `pontis-bridge-nft.sol` , `pontis-bridge-fee-manager.sol` , `pontis-bridge-controlle...

4. [HIGH] Permanent failure to bridge wrapped ERC721 using Bridge::sendERC721UsingNative function  (Sweep n Flip)
   ## Bridge.sol Vulnerability Overview

## Context
**File:** Bridge.sol  
**Line:** 159  

## Description
The `sendERC721UsingNative` function of `Bridg...

5. [LOW] Bridge address can not be changed if needed (Beyond)
   **Severity**: Low	

**Status**: Resolved

**Description**

The `bridge` address used within the `WrappedERC20.sol` smart contract is set via construct...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio crosschain
Buscando 'Bridge bridgeCall bridgeToken relayMessages __relayMessage' [SQLite FTS5] (dominio: crosschain)...
Top 6 findings relevantes: (34ms)
 1. [HIGH] H-2: Legacy withdrawals can be relayed twice, causing double spending of bridged — Optimism Update
 2. [HIGH] BVM_ETH and MNT Deposited in Messengers Can Be Stolen — Mantle V2 Solidity Contracts Audit
 3. [HIGH] Withdrawing discounted ETH from L2 always fails — DRAFT
 4. [HIGH] H-1: All migrated withdrarwals that require more than 135,175 gas may be bricked — Optimism Update
 5. [HIGH] H-3: Causing users lose their fund during finalizing withdrawal transaction — Optimism
 6. [HIGH] Token Bridge Reentrancy Can Corrupt Token Accounting — Linea Bridge Audit
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Bridge bridgeCall bridgeToken relayMessages __relayMessage | Dominio: crosschain
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] H-2: Legacy withdrawals can be relayed twice, causing double spending of bridged assets (Optimism Update)
   Source: https://github.com/sherlock-audit/2023-03-optimism-judging/issues/87 
## Found by 
Jeiwan
## Summary
`L2CrossDomainMessenger.relayMessage` c...
2. [HIGH] BVM_ETH and MNT Deposited in Messengers Can Be Stolen (Mantle V2 Solidity Contracts Audit)
   In the [`L2CrossDomainMessenger`](https://github.com/mantlenetworkio/mantle-v2/blob/e29d360904db5e5ec81888885f7b7250f8255895/packages/contracts-bedroc...
3. [HIGH] Withdrawing discounted ETH from L2 always fails (DRAFT)
   ## Security Audit Report
## DRAFT5.1.7: Negative ETH Withdrawal Issue
### Severity: Critical Risk
**Context:**  
- `OptimismPortal.sol#L387`  
- `Cro...
4. [HIGH] H-1: All migrated withdrarwals that require more than 135,175 gas may be bricked (Optimism Update)
   Source: https://github.com/sherlock-audit/2023-0

## Briefing del Dominio
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
  invariante: "sum(totalSupply[token][chain]) + inTransit[token] == trackedSupply[token] (INV-BRIDGE-

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar /home/kali/Documents/Web3/bridge/base/src/Bridge.sol: Invalid compilation: 
Compilation failed. Can you run build command?
/home/kali/Documents/Web3/bridge/base/out/build-info is not a directory.


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `_useTransientReentrancyGuardOnlyOnMainnet()` (L340)
```solidity
    function _useTransientReentrancyGuardOnlyOnMainnet() internal pure override returns (bool) {
        return false;
    }
```

*Original no encontrado en lib/ — verificar manualmente*

