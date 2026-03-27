# Contexto de Hunt — AbstractInterchainAccountRouter

**Protocolo**: hyperlane
**Dominio**: trust
**LOC**: 279
**Archivo**: /home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/middleware/AbstractInterchainAccountRouter.sol
**Generado**: 2026-03-24T16:42:11.885919Z

## Solodit Context
### Findings sobre AbstractInterchainAccountRouter
Buscando 'AbstractInterchainAccountRouter' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (6ms)


### HIGH findings en dominio trust
Buscando 'AbstractInterchainAccountRouter interchainSecurityModule enrollRemoteRouterAndIs' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (26ms)

### Cross-domain HIGH relevantes
Buscando 'AbstractInterchainAccountRouter interchainSecurityModule enr' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (6ms)

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

# Deep Flatten — AbstractInterchainAccountRouter

Funciones analizadas: 9


## domains() [CRITICAL — mueve fondos]

[FUNC] [Router:L26-28] domains()
    READ: _routers
    [EXTERNAL] EnumerableMapExtended.TMP_303(uint32[]) = LIBRARY_CALL, dest:EnumerableMapExtended, function:EnumerableMapExtended.uint32Keys(EnumerableMapExtended.UintToBytes32Map), arguments:['_routers'] 

## routers(uint32) [CRITICAL — mueve fondos]

[FUNC] [Router:L36-39] routers(uint32)
    READ: _routers
    [EXTERNAL] EnumerableMapExtended.TUPLE_4(bool,bytes32) = LIBRARY_CALL, dest:EnumerableMapExtended, function:EnumerableMapExtended.tryGet(EnumerableMapExtended.UintToBytes32Map,uint256), arguments:['_routers', '_domain'] 

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [OwnableUpgradeable:L74-77] transferOwnership(address)
  [MODIFIER] onlyOwner()

## approveFeeTokenForHook(address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L109-111] approveFeeTokenForHook(address,address)
    [EXTERNAL] SafeERC20.LIBRARY_CALL, dest:SafeERC20, function:SafeERC20.forceApprove(IERC20,address,uint256), arguments:['TMP_403', '_hook', 'TMP_405'] 

## getDeployedInterchainAccount(uint32,address,address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L113-127] getDeployedInterchainAccount(uint32,address,address,address)
    [EXTERNAL] TypeCasts.TMP_407(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 
    [EXTERNAL] TypeCasts.TMP_408(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_router'] 

## getDeployedInterchainAccount(uint32,bytes32,bytes32,address,bytes32) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L129-157] getDeployedInterchainAccount(uint32,bytes32,bytes32,address,bytes32)
    READ: implementation
    [EXTERNAL] MinimalProxy.TMP_415(bytes) = LIBRARY_CALL, dest:MinimalProxy, function:MinimalProxy.bytecode(address), arguments:['implementation'] 
    [EXTERNAL] Address.TMP_413(bool) = LIBRARY_CALL, dest:Address, function:Address.isContract(address), arguments:['_account'] 
    [EXTERNAL] Create2.TMP_416(address) = LIBRARY_CALL, dest:Create2, function:Create2.deploy(uint256,bytes32,bytes), arguments:['0', '_deploySalt', '_bytecode'] 
    [EXTERNAL] TypeCasts.TMP_410(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 

## getLocalInterchainAccount(uint32,address,address,address) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L159-177] getLocalInterchainAccount(uint32,address,address,address)
    [EXTERNAL] TypeCasts.TMP_420(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_owner'] 
    [EXTERNAL] TypeCasts.TMP_421(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_router'] 
    [EXTERNAL] TypeCasts.TMP_422(bytes32) = LIBRARY_CALL, dest:TypeCasts, function:TypeCasts.addressToBytes32(address), arguments:['_ism'] 

## quoteGasPayment(uint32,uint256) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L179-190] quoteGasPayment(uint32,uint256)
    READ: hook
    [EXTERNAL] StandardHookMetadata.TMP_428(bytes) = LIBRARY_CALL, dest:StandardHookMetadata, function:StandardHookMetadata.overrideGasLimit(uint256), arguments:['_gasLimit'] 

## callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes) [CRITICAL — mueve fondos]

[FUNC] [AbstractInterchainAccountRouter:L192-220] callRemoteWithOverrides(uint32,bytes32,bytes32,CallLib.Call[],bytes)
    READ: hook
    [EXTERNAL] InterchainAccountMessage.TMP_432(bytes) = LIBRARY_CALL, dest:InterchainAccountMessage, function:InterchainAccountMessage.encode(address,bytes32,CallLib.Call[]), arguments:['msg.sender', '_ism', '_calls'] 


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `_handle()` (L272)
```solidity
    function _handle(uint32, bytes32, bytes calldata) internal pure override {
        assert(false);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

## Symmetric Analysis
# Symmetric Analysis — AbstractInterchainAccountRouter

No se encontraron pares simétricos.
