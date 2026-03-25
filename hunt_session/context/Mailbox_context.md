# Contexto de Hunt — Mailbox

**Protocolo**: hyperlane
**Dominio**: access
**LOC**: 362
**Archivo**: /home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/Mailbox.sol
**Generado**: 2026-03-24T18:09:38.779924Z

## Solodit Context
### Findings sobre Mailbox
Buscando 'Mailbox' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (29ms)

 1. [GAS] [G-27] Do not import the whole library, when only a few functions from that libr — zkSync
 2. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` — Nucleus_2024-12-14
 3. [GAS] [G-30] Unnecessary variables in `Mailbox.sol` — zkSync
 4. [GAS] [G-43] `public` functions which are not called by the contract should be declare — zkSync
 5. [LOW] [05] — zkSync

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [GAS] [G-27] Do not import the whole library, when only a few functions from that library are being used (zkSync)
   
**File:** `Mailbox.sol`

[File: code/contracts/ethereum/contracts/state-transition/chain-deps/facets/Mailbox.sol](https://github.com/code-423n4/2024-...

2. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` (Nucleus_2024-12-14)
   ## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_bridge()` and `_quote()` in the `MultiChainHyperlaneTellerWithMultiAssetSupp...

3. [GAS] [G-30] Unnecessary variables in `Mailbox.sol` (zkSync)
   
**Function `_proveL2LogInclusion`:**

Variables `calculatedRootHash` and `actualRootHash` are used only once, which means they don't need to be decla...

4. [GAS] [G-43] `public` functions which are not called by the contract should be declared as `external` (zkSync)
   
**File:** `Mailbox.sol`

When `public` function is never called internally and is only expected to be invoked externally, it is more gas-efficient to...

5. [LOW] [05] (zkSync)
   
It is not needed to have modifier `senderCanCallFunction` for the function `deposit` in both `L1ERC20Bridge` and `L1ETHBridge`, because they call the...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio access
Buscando 'Mailbox dispatch dispatch quoteDispatch quoteDispatch' [SQLite FTS5] (dominio: access)...
Top 2 findings relevantes: (186ms)
 1. [HIGH] Permission in method description doesn't match implementation — Basilisk
 2. [HIGH] Potential DoS of messages in the `postDispatch` function — DIA
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox dispatch dispatch quoteDispatch quoteDispatch | Dominio: access
Los siguientes 2 findings de protocolos similares son relevantes:
1. [HIGH] Permission in method description doesn't match implementation (Basilisk)
   **Occurs**:
Basilisk-node/pallets/lbp/src/lib.rs:516-568
Dispatch origin restrictions described in comments must match method implementation
**Recom...
2. [HIGH] Potential DoS of messages in the `postDispatch` function (DIA)
   ##### Description
The `postDispatch()` function of the `ProtocolFeeHook` contract lacks access control check.
The function updates the `messageValida...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'Mailbox dispatch dispatch quoteDispatch quoteDispatch' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (9ms)
 1. [HIGH] Issue with Fee Payment During Interchain Callback — DIA
 2. [HIGH] Proxy has public methods that shadow implementation — NuCypher
 3. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, resul — RealWagmi
 4. [HIGH] Message Verification — DIA
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Mailbox dispatch dispatch quoteDispatch quoteDispatch | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:
1.

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

# Deep Flatten — Mailbox

Funciones analizadas: 8


## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [OwnableUpgradeable:L74-77] transferOwnership(address)
  [MODIFIER] onlyOwner()

## process(bytes,bytes) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L202-246] process(bytes,bytes)
    READ: VERSION
    READ: localDomain
    WRITE: deliveries
    [EXTERNAL] Message.TMP_50(address) = LIBRARY_CALL, dest:Message, function:Message.recipientAddress(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_46(bytes32) = LIBRARY_CALL, dest:Message, function:Message.id(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_54(uint32) = LIBRARY_CALL, dest:Message, function:Message.origin(bytes), arguments:['_message'] 
    [EXTERNAL] IInterchainSecurityModule.TMP_58(bool) = HIGH_LEVEL_CALL, dest:ism(IInterchainSecurityModule), function:verify, arguments:['_metadata', '_message']  
    [EXTERNAL] Message.TMP_40(uint8) = LIBRARY_CALL, dest:Message, function:Message.version(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_43(uint32) = LIBRARY_CALL, dest:Message, function:Message.destination(bytes), arguments:['_message'] 
    [EXTERNAL] IMessageRecipient.HIGH_LEVEL_CALL, dest:TMP_60(IMessageRecipient), function:handle, arguments:['TMP_61', 'TMP_62', 'TMP_63'] value:msg.value 
    [EXTERNAL] Message.TMP_55(bytes32) = LIBRARY_CALL, dest:Message, function:Message.sender(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_62(bytes32) = LIBRARY_CALL, dest:Message, function:Message.sender(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_61(uint32) = LIBRARY_CALL, dest:Message, function:Message.origin(bytes), arguments:['_message'] 
    [EXTERNAL] Message.TMP_63(bytes) = LIBRARY_CALL, dest:Message, function:Message.body(bytes), arguments:['_message'] 

## dispatch(uint32,bytes32,bytes,bytes,IPostDispatchHook) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L277-315] dispatch(uint32,bytes32,bytes,bytes,IPostDispatchHook)
    READ: defaultHook
    READ: nonce
    READ: requiredHook
    WRITE: latestDispatchedId
    WRITE: nonce
    [EXTERNAL] Message.TMP_69(bytes32) = LIBRARY_CALL, dest:Message, function:Message.id(bytes), arguments:['message'] 
    [EXTERNAL] IPostDispatchHook.TMP_72(uint256) = HIGH_LEVEL_CALL, dest:requiredHook(IPostDispatchHook), function:quoteDispatch, arguments:['metadata', 'message']  
    [EXTERNAL] IPostDispatchHook.HIGH_LEVEL_CALL, dest:hook(IPostDispatchHook), function:postDispatch, arguments:['metadata', 'message'] value:TMP_75 
    [EXTERNAL] IPostDispatchHook.HIGH_LEVEL_CALL, dest:requiredHook(IPostDispatchHook), function:postDispatch, arguments:['metadata', 'message'] value:requiredValue 

## quoteDispatch(uint32,bytes32,bytes,bytes,IPostDispatchHook) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L335-354] quoteDispatch(uint32,bytes32,bytes,bytes,IPostDispatchHook)
    READ: defaultHook
    READ: requiredHook
    [EXTERNAL] IPostDispatchHook.TMP_81(uint256) = HIGH_LEVEL_CALL, dest:requiredHook(IPostDispatchHook), function:quoteDispatch, arguments:['metadata', 'message']  
    [EXTERNAL] IPostDispatchHook.TMP_82(uint256) = HIGH_LEVEL_CALL, dest:hook(IPostDispatchHook), function:quoteDispatch, arguments:['metadata', 'message']  

## setDefaultIsm(address) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L369-376] setDefaultIsm(address)
  [MODIFIER] onlyOwner()
    WRITE: defaultIsm
    [EXTERNAL] Address.TMP_85(bool) = LIBRARY_CALL, dest:Address, function:Address.isContract(address), arguments:['_module'] 

## setDefaultHook(address) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L382-389] setDefaultHook(address)
  [MODIFIER] onlyOwner()
    WRITE: defaultHook
    [EXTERNAL] Address.TMP_90(bool) = LIBRARY_CALL, dest:Address, function:Address.isContract(address), arguments:['_hook'] 

## setRequiredHook(address) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L395-402] setRequiredHook(address)
  [MODIFIER] onlyOwner()
    WRITE: requiredHook
    [EXTERNAL] Address.TMP_95(bool) = LIBRARY_CALL, dest:Address, function:Address.isContract(address), arguments:['_hook'] 

## recipientIsm(address) [CRITICAL — mueve fondos]

[FUNC] [Mailbox:L410-431] recipientIsm(address)
    READ: defaultIsm
    [LOW_CALL] TUPLE_0(bool,bytes) = LOW_LEVEL_CALL, dest:_recipient, function:staticcall, arguments:['TMP_100']  


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `delivered()` (L361)
```solidity
    function delivered(bytes32 _id) public view override returns (bool) {
        return deliveries[_id].blockNumber > 0;
    }
```

*Original no encontrado en lib/ — verificar manualmente*

## Symmetric Analysis
# Symmetric Analysis — Mailbox

No se encontraron pares simétricos.
