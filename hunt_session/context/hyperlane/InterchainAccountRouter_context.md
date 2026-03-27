# Contexto de Hunt — InterchainAccountRouter

**Protocolo**: hyperlane
**Dominio**: trust
**LOC**: 748
**Archivo**: /home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/middleware/InterchainAccountRouter.sol
**Generado**: 2026-03-24T13:29:03.596674Z

## Solodit Context
### Findings sobre InterchainAccountRouter
Buscando 'InterchainAccountRouter' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (41ms)


### HIGH findings en dominio trust
Buscando 'InterchainAccountRouter callRemote callRemote getLocalInterchainAccount getRemot' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (16ms)

### Cross-domain HIGH relevantes
Buscando 'InterchainAccountRouter callRemote callRemote getLocalInterc' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

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

# Deep Flatten — InterchainAccountRouter

Funciones analizadas: 21


## verify(bytes,bytes) [CRITICAL — mueve fondos]

[FUNC] [AbstractRoutingIsm:L38-43] verify(bytes,bytes)
    [EXTERNAL] IInterchainSecurityModule.TMP_758(bool) = HIGH_LEVEL_CALL, dest:TMP_757(IInterchainSecurityModule), function:verify, arguments:['_metadata', '_message']  

## approveFeeTokenForHook(address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L109-111] approveFeeTokenForHook(address,address)
    [EXTERNAL] SafeERC20.LIBRARY_CALL, dest:SafeERC20, function:SafeERC20.forceApprove(IERC20,address,uint256), arguments:['TMP_771', '_hook', 'TMP_773'] 

## getDeployedInterchainAccount(uint32,address,address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L113-127] getDeployedInterchainAccount(uint32,address,address,address)
    [EXTERNAL] TypeCasts.TMP_776(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_router'] 
    [EXTERNAL] TypeCasts.TMP_775(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 

## getDeployedInterchainAccount(uint32,bytes32,bytes32,address,bytes32) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L129-157] getDeployedInterchainAccount(uint32,bytes32,bytes32,address,bytes32)
    READ: implementation
    [EXTERNAL] Address.TMP_781(bool) = LIBRARY_CALL, dest:Address, function:Address.isContract(address), arguments:['_account'] 
    [EXTERNAL] MinimalProxy.TMP_783(bytes) = LIBRARY_CALL, dest:MinimalProxy, function:MinimalProxy.bytecode(address), arguments:['implementation'] 
    [EXTERNAL] TypeCasts.TMP_778(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 
    [EXTERNAL] Create2.TMP_784(address) = LIBRARY_CALL, dest:Create2, function:Create2.deploy(uint256,bytes32,bytes), arguments:['0', '_deploySalt', '_bytecode'] 

## getLocalInterchainAccount(uint32,address,address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L159-177] getLocalInterchainAccount(uint32,address,address,address)
    [EXTERNAL] TypeCasts.TMP_788(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 
    [EXTERNAL] TypeCasts.TMP_789(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_router'] 
    [EXTERNAL] TypeCasts.TMP_790(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 

## quoteGasPayment(uint32,uint256) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L179-190] quoteGasPayment(uint32,uint256)
    READ: hook
    [EXTERNAL] StandardHookMetadata.TMP_796(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.overrideGasLimit(uint256), arguments:['_gasLimit'] 

## callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L192-220] callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes)
    READ: hook
    [EXTERNAL] InterchainAccountMessage.TMP_800(bytes) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.encode(address,bytes32,CallLib.Call[]), arguments:['msg.sender', '_ism', '_calls'] 

## domains() [CRITICAL — mueve fondos]

[FUNC] [Router:L26-28] domains()
    READ: _routers
    [EXTERNAL] EnumerableMapExtended.TMP_840(uint32[]) = LIBRARY_CALL, dest:EnumerableMapExtended, function:EnumerableMapExtended.uint32Keys(EnumerableMapExtended.UintToBytes32Map), arguments:['_routers'] 

## routers(uint32) [CRITICAL — mueve fondos]

[FUNC] [Router:L36-39] routers(uint32)
    READ: _routers
    [EXTERNAL] EnumerableMapExtended.TUPLE_7(bool,bytes32) = LIBRARY_CALL, dest:EnumerableMapExtended, function:EnumerableMapExtended.tryGet(EnumerableMapExtended.UintToBytes32Map,uint256), arguments:['_routers', '_domain'] 

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [OwnableUpgradeable:L74-77] transferOwnership(address)
  [MODIFIER] onlyOwner()

## handle(uint32,bytes32,bytes) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L134-168] handle(uint32,bytes32,bytes)
  [MODIFIER] onlyMailbox()
    [EXTERNAL] InterchainAccountMessage.TMP_946(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.ism(bytes), arguments:['_message'] 
    [EXTERNAL] OwnableMulticall.HIGH_LEVEL_CALL, dest:ica(OwnableMulticall), function:multicall, arguments:['calls'] value:msg.value 
    [EXTERNAL] OwnableMulticall.HIGH_LEVEL_CALL, dest:ica(OwnableMulticall), function:setCommitment, arguments:['TMP_952']  
    [EXTERNAL] InterchainAccountMessage.TMP_942(InterchainAccountMessage.MessageType) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.messageType(bytes), arguments:['_message'] 
    [EXTERNAL] InterchainAccountMessage.TMP_952(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.commitment(bytes), arguments:['_message'] 
    [EXTERNAL] InterchainAccountMessage.TMP_944(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.owner(bytes), arguments:['_message'] 
    [EXTERNAL] InterchainAccountMessage.TMP_950(CallLib.Call[]) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.calls(bytes), arguments:['_message'] 
    [EXTERNAL] TypeCasts.TMP_947(address) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.bytes32ToAddress(bytes32), arguments:['_ism'] 
    [EXTERNAL] InterchainAccountMessage.TMP_945(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.salt(bytes), arguments:['_message'] 

## route(bytes) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L170-191] route(bytes)
    READ: CCIP_READ_ISM
    READ: mailbox
    [EXTERNAL] InterchainAccountMessage.TMP_956(InterchainAccountMessage.MessageType) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.messageType(bytes), arguments:['_body'] 
    [EXTERNAL] TypeCasts.TMP_959(address) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.bytes32ToAddress(bytes32), arguments:['TMP_958'] 
    [EXTERNAL] InterchainAccountMessageReveal.TMP_958(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessageReveal, function:InterchainAccountMessageReveal.revealIsm(bytes), arguments:['_body'] 
    [EXTERNAL] InterchainAccountMessage.TMP_960(bytes32) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.ism(bytes), arguments:['_body'] 
    [EXTERNAL] IMailbox.TMP_968(IInterchainSecurityModule) = HIGH_LEVEL_CALL, dest:mailbox(IMailbox), function:defaultIsm, arguments:[]  
    [EXTERNAL] TypeCasts.TMP_961(address) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.bytes32ToAddress(bytes32), arguments:['TMP_960'] 
    [EXTERNAL] Message.TMP_955(bytes) = LIBRARY_CALL, dest:Message, function:Message.body(bytes), arguments:['_message'] 

## getLocalInterchainAccount(uint32,address,address,address) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L202-215] getLocalInterchainAccount(uint32,address,address,address)
    [EXTERNAL] TypeCasts.TMP_971(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_router'] 
    [EXTERNAL] TypeCasts.TMP_970(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 

## getRemoteInterchainAccount(uint32,address,bytes32) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L248-256] getRemoteInterchainAccount(uint32,address,bytes32)
    READ: isms
    [EXTERNAL] TypeCasts.TMP_976(address) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.bytes32ToAddress(bytes32), arguments:['REF_266'] 
    [EXTERNAL] TypeCasts.TMP_975(address) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.bytes32ToAddress(bytes32), arguments:['TMP_974'] 

## getLocalInterchainAccount(uint32,bytes32,bytes32,address,bytes32) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L319-338] getLocalInterchainAccount(uint32,bytes32,bytes32,address,bytes32)
    [EXTERNAL] TypeCasts.TMP_980(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 

## getRemoteInterchainAccount(address,address,address,bytes32) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L375-399] getRemoteInterchainAccount(address,address,address,bytes32)
    READ: localDomain
    [EXTERNAL] Create2.TMP_998(address) = LIBRARY_CALL, dest:Create2, function:Create2.computeAddress(bytes32,bytes32,address), arguments:['_salt', '_bytecodeHash', '_router'] 
    [EXTERNAL] TypeCasts.TMP_995(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['TMP_994'] 
    [EXTERNAL] TypeCasts.TMP_996(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 
    [EXTERNAL] Create2.TMP_991(address) = LIBRARY_CALL, dest:Create2, function:Create2.computeAddress(bytes32,bytes32,address), arguments:['TMP_988', 'TMP_990', '_router'] 
    [EXTERNAL] TypeCasts.TMP_993(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 

## callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes,bytes32,IPostDispatchHook) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L530-560] callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes,bytes32,IPostDispatchHook)
    [EXTERNAL] InterchainAccountMessage.TMP_1006(bytes) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.encode(address,bytes32,CallLib.Call[],bytes32), arguments:['msg.sender', '_ism', '_calls', '_salt'] 

## callRemoteCommitReveal(uint32,bytes32,bytes32,bytes32,bytes,IPostDispatchHook,bytes32,bytes32) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L579-632] callRemoteCommitReveal(uint32,bytes32,bytes32,bytes32,bytes,IPostDispatchHook,bytes32,bytes32)
    READ: COMMIT_TX_GAS_USAGE
    [EXTERNAL] InterchainAccountMessage.TMP_1016(bytes) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.encodeReveal(bytes32,bytes32), arguments:['_ccipReadIsm', '_commitment'] 
    [EXTERNAL] StandardHookMetadata.TMP_1014(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.formatMetadata(uint256,uint256,address,bytes), arguments:['0', 'COMMIT_TX_GAS_USAGE', 'TMP_1012', 'TMP_1013'] 
    [EXTERNAL] TypeCasts.TMP_1008(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['msg.sender'] 
    [EXTERNAL] InterchainAccountMessage.TMP_1009(bytes) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.encodeCommitment(bytes32,bytes32,bytes32,bytes32), arguments:['TMP_1008', '_ism', '_commitment', '_salt'] 

## callRemoteCommitReveal(uint32,bytes32,uint256) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L656-682] callRemoteCommitReveal(uint32,bytes32,uint256)
    READ: hook
    READ: isms
    [EXTERNAL] StandardHookMetadata.TMP_1023(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.formatMetadata(uint256,uint256,address,bytes), arguments:['0', '_gasLimit', 'msg.sender', 'TMP_1022'] 

## quoteGasPayment(address,uint32,uint256) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L777-794] quoteGasPayment(address,uint32,uint256)
    READ: hook
    [EXTERNAL] StandardHookMetadata.TMP_1035(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.formatWithFeeToken(uint256,uint256,address,address), arguments:['0', '_gasLimit', 'msg.sender', '_feeToken'] 

## quoteGasForCommitReveal(uint32,uint256) [CRITICAL — mueve fondos]

[FUNC] [InterchainAccountRouter:L802-813] quoteGasForCommitReveal(uint32,uint256)
    READ: COMMIT_TX_GAS_USAGE
    READ: hook
    [EXTERNAL] StandardHookMetadata.TMP_1040(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.overrideGasLimit(uint256), arguments:['COMMIT_TX_GAS_USAGE'] 



## Symmetric Analysis
# Symmetric Analysis — InterchainAccountRouter

No se encontraron pares simétricos.
