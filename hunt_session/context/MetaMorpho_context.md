# Contexto de Hunt — MetaMorpho

**Protocolo**: metamorpho
**Dominio**: trust
**LOC**: 542
**Archivo**: /home/kali/Documents/Web3/metamorpho/src/MetaMorpho.sol
**Generado**: 2026-03-24T22:57:54.817405Z

## Solodit Context
### Findings sobre MetaMorpho
Buscando 'MetaMorpho' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (10ms)

 1. [LOW] Allocator can drain the MetaMorpho vault if a future IRM queries token balance  — Morpho
 2. [MEDIUM] Wrong rounding direction for tosupply in _supplymorpho  — Morpho
 3. [LOW] MetaMorphoAdapter and MorphoBlueAdapter do not check asset comparability with th — Morpho Vaults v2
 4. [LOW] VaultV2 could end up minting shares > 0 that are not backed by MetaMorpho shares — Morpho Vaults v2
 5. [LOW] Inconsistent use of msg.sender  — Morpho

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: MetaMorpho | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] Allocator can drain the MetaMorpho vault if a future IRM queries token balance  (Morpho)
   ## MetaMorpho Vault Allocator Role

## Context
MetaMorpho.sol#L368-L417

## Description
The Allocator role in the MetaMorpho vault is responsible for ...

2. [MEDIUM] Wrong rounding direction for tosupply in _supplymorpho  (Morpho)
   ## Context
**File:** MetaMorpho.sol  
**Line:** 807

## Description
A property that a `_supplyMorpho` call should have is that immediately after the d...

3. [LOW] MetaMorphoAdapter and MorphoBlueAdapter do not check asset comparability with the parent vault (Morpho Vaults v2)
   ## Severity: Low Risk

## Context
- `MetaMorphoAdapter.sol#L28-L33`
- `MorphoBlueAdapter.sol#L56`
- `MorphoBlueAdapter.sol#L73`

## Description
`MetaM...

4. [LOW] VaultV2 could end up minting shares > 0 that are not backed by MetaMorpho shares (Morpho Vaults v2)
   ## Severity: Low Risk

## Context
MetaMorphoAdapter.sol#L53-L66

## Description
The current implementation of the `MetaMorphoAdapter` adapter does not...

5. [LOW] Inconsistent use of msg.sender  (Morpho)
   ## Context
**File:** MetaMorpho.sol#L781

## Description
The MetaMorpho contract uses the inherited `_msgSender()` function whenever it needs to read ...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'MetaMorpho setCurator setIsAllocator setSkimRecipient submitTimelock' [SQLite FTS5] (dominio: trust)...
Top 2 findings relevantes: (20ms)
 1. [HIGH] H-3: Unit isn't recalculated on curve modification with setCurvePoint — Merit Circle
 2. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions — Morpho Vaults v2
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: MetaMorpho setCurator setIsAllocator setSkimRecipient submitTimelock | Dominio: trust
Los siguientes 2 findings de protocolos similares son relevantes:
1. [HIGH] H-3: Unit isn't recalculated on curve modification with setCurvePoint (Merit Circle)
   Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/101 
## Found by 
bin2chen, Jeiwan, Lambda, Ch\_301, hyh
## Summary
T...
2. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions (Morpho Vaults v2)
   ## Severity: High Risk
## Context
(No context files were provided by the reviewer)
## Description
This finding describes the potential side effects ...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'MetaMorpho setCurator setIsAllocator setSkimRecipient submit' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (53ms)
 1. [HIGH] H-3: Unit isn't recalculated on curve modification with setCurvePoint — Merit Circle
 2. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions — Morpho Vaults v2
 3. [HIGH] Failure to enforce minimum oracle stake requirement — Advanced Blockchain
 4. [HIGH] Act

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

# Deep Flatten — MetaMorpho

Funciones analizadas: 54


## withdrawQueue(uint256) [CRITICAL — mueve fondos]

[FUNC] [IMetaMorphoBase:L67-67] withdrawQueue(uint256)

## withdrawQueueLength() [CRITICAL — mueve fondos]

[FUNC] [IMetaMorphoBase:L70-70] withdrawQueueLength()

## updateWithdrawQueue(uint256[]) [CRITICAL — mueve fondos]

[FUNC] [IMetaMorphoBase:L164-164] updateWithdrawQueue(uint256[])

## multicall(bytes[]) [CRITICAL — mueve fondos]

[FUNC] [Multicall:L16-22] multicall(bytes[])
    [EXTERNAL] Address.TMP_1193(bytes) = LIBRARY_CALL, dest:Address, function:Address.functionDelegateCall(address,bytes), arguments:['TMP_1192', 'REF_206'] 

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [Ownable2Step:L35-38] transferOwnership(address)
  [MODIFIER] onlyOwner()
    WRITE: _pendingOwner

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [Ownable:L84-89] transferOwnership(address)
  [MODIFIER] onlyOwner()

## permit(address,address,uint256,uint256,uint8,bytes32,bytes32) [CRITICAL — mueve fondos]

[FUNC] [ERC20Permit:L44-67] permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
    READ: PERMIT_TYPEHASH
    [EXTERNAL] ECDSA.TMP_1231(address) = LIBRARY_CALL, dest:ECDSA, function:ECDSA.recover(bytes32,uint8,bytes32,bytes32), arguments:['hash', 'v', 'r', 's'] 

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC20:L109-113] transfer(address,uint256)

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC20:L154-159] transferFrom(address,address,uint256)

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L41-41] transfer(address,uint256)

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L78-78] transferFrom(address,address,uint256)

## totalAssets() [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L116-118] totalAssets()
    READ: _asset
    [EXTERNAL] IERC20.TMP_1334(uint256) = HIGH_LEVEL_CALL, dest:_asset(IERC20), function:balanceOf, arguments:['TMP_1333']  

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L131-133] maxDeposit(address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L136-138] maxMint(address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L141-143] maxWithdraw(address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L146-148] maxRedeem(address)

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L151-153] previewDeposit(uint256)

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L156-158] previewMint(uint256)

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L161-163] previewWithdraw(uint256)

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L166-168] previewRedeem(uint256)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L171-181] deposit(uint256,address)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L188-198] mint(uint256,address)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L201-211] withdraw(uint256,address,address)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [ERC4626:L214-224] redeem(uint256,address,address)

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L79-79] maxDeposit(address)

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L96-96] previewDeposit(uint256)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L109-109] deposit(uint256,address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L117-117] maxMint(address)

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L134-134] previewMint(uint256)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L147-147] mint(uint256,address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L156-156] maxWithdraw(address)

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L174-174] previewWithdraw(uint256)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L188-188] withdraw(uint256,address,address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L198-198] maxRedeem(address)

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L215-215] previewRedeem(uint256)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L229-229] redeem(uint256,address,address)

## submitTimelock(uint256) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L215-228] submitTimelock(uint256)
  [MODIFIER] onlyOwner()
    READ: pendingTimelock
    READ: timelock
    [EXTERNAL] PendingLib.LIBRARY_CALL, dest:PendingLib, function:PendingLib.update(PendingUint192,uint184,uint256), arguments:['pendingTimelock', 'TMP_1434', 'timelock'] 

## submitGuardian(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L259-270] submitGuardian(address)
  [MODIFIER] onlyOwner()
    READ: guardian
    READ: pendingGuardian
    READ: timelock
    [EXTERNAL] PendingLib.LIBRARY_CALL, dest:PendingLib, function:PendingLib.update(PendingAddress,address,uint256), arguments:['pendingGuardian', 'newGuardian', 'timelock'] 

## submitCap(MarketParams,uint256) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L275-291] submitCap(MarketParams,uint256)
  [MODIFIER] onlyCuratorRole()
    READ: MORPHO
    READ: config
    READ: pendingCap
    READ: timelock
    [EXTERNAL] SafeCast.TMP_1488(uint184) = LIBRARY_CALL, dest:SafeCast, function:SafeCast.toUint184(uint256), arguments:['newSupplyCap'] 
    [EXTERNAL] MarketParamsLib.TMP_1474(Id) = LIBRARY_CALL, dest:MarketParamsLib, function:MarketParamsLib.id(MarketParams), arguments:['marketParams'] 
    [EXTERNAL] PendingLib.LIBRARY_CALL, dest:PendingLib, function:PendingLib.update(PendingUint192,uint184,uint256), arguments:['REF_269', 'TMP_1490', 'timelock'] 
    [EXTERNAL] MorphoLib.TMP_1478(uint256) = LIBRARY_CALL, dest:MorphoLib, function:MorphoLib.lastUpdate(IMorpho,Id), arguments:['MORPHO', 'id'] 
    [EXTERNAL] SafeCast.TMP_1490(uint184) = LIBRARY_CALL, dest:SafeCast, function:SafeCast.toUint184(uint256), arguments:['newSupplyCap'] 

## submitMarketRemoval(MarketParams) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L294-305] submitMarketRemoval(MarketParams)
  [MODIFIER] onlyCuratorRole()
    READ: config
    READ: pendingCap
    READ: timelock
    WRITE: config
    [EXTERNAL] MarketParamsLib.TMP_1495(Id) = LIBRARY_CALL, dest:MarketParamsLib, function:MarketParamsLib.id(MarketParams), arguments:['marketParams'] 

## updateWithdrawQueue(uint256[]) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L325-365] updateWithdrawQueue(uint256[])
  [MODIFIER] onlyAllocatorRole()
    READ: MORPHO
    READ: config
    READ: pendingCap
    READ: withdrawQueue
    WRITE: config
    WRITE: withdrawQueue
    [EXTERNAL] MorphoLib.TMP_1530(uint256) = LIBRARY_CALL, dest:MorphoLib, function:MorphoLib.supplyShares(IMorpho,Id,address), arguments:['MORPHO', 'id_scope_1', 'TMP_1529'] 

## reallocate(MarketAllocation[]) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L368-417] reallocate(MarketAllocation[])
  [MODIFIER] onlyAllocatorRole()
    READ: MORPHO
    READ: config
    [EXTERNAL] UtilsLib.TMP_1565(uint256) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.zeroFloorSub(uint256,uint256), arguments:['totalWithdrawn', 'totalSupplied'] 
    [EXTERNAL] UtilsLib.TMP_1541(uint256) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.zeroFloorSub(uint256,uint256), arguments:['supplyAssets', 'REF_318'] 
    [EXTERNAL] UtilsLib.TMP_1566(uint256) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.zeroFloorSub(uint256,uint256), arguments:['REF_332', 'supplyAssets'] 
    [EXTERNAL] IMorpho.TUPLE_21(uint256,uint256) = HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:supply, arguments:['REF_328', 'suppliedAssets', '0', 'TMP_1556', '']  
    [EXTERNAL] IMorpho.TUPLE_20(uint256,uint256) = HIGH_LEVEL_CALL, dest:MORPHO(IMorpho), function:withdraw, arguments:['REF_323', 'withdrawn', 'shares', 'TMP_1546', 'TMP_1547']  
    [EXTERNAL] MarketParamsLib.TMP_1540(Id) = LIBRARY_CALL, dest:MarketParamsLib, function:MarketParamsLib.id(MarketParams), arguments:['REF_314'] 

## withdrawQueueLength() [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L457-459] withdrawQueueLength()
    READ: withdrawQueue

## acceptCap(MarketParams) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L472-480] acceptCap(MarketParams)
  [MODIFIER] afterTimelock(uint256)
    READ: pendingCap
    [EXTERNAL] MarketParamsLib.TMP_1586(Id) = LIBRARY_CALL, dest:MarketParamsLib, function:MarketParamsLib.id(MarketParams), arguments:['marketParams'] 
    [EXTERNAL] MarketParamsLib.TMP_1583(Id) = LIBRARY_CALL, dest:MarketParamsLib, function:MarketParamsLib.id(MarketParams), arguments:['marketParams'] 

## skim(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L483-491] skim(address)
    READ: skimRecipient
    [EXTERNAL] IERC20.TMP_1593(uint256) = HIGH_LEVEL_CALL, dest:TMP_1591(IERC20), function:balanceOf, arguments:['TMP_1592']  
    [EXTERNAL] SafeERC20.LIBRARY_CALL, dest:SafeERC20, function:SafeERC20.safeTransfer(IERC20,address,uint256), arguments:['TMP_1594', 'skimRecipient', 'amount'] 

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L502-504] maxDeposit(address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L508-512] maxMint(address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L517-519] maxWithdraw(address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L524-528] maxRedeem(address)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L531-541] deposit(uint256,address)
    WRITE: lastTotalAssets

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L544-554] mint(uint256,address)
    WRITE: lastTotalAssets

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L557-568] withdraw(uint256,address,address)
    [EXTERNAL] UtilsLib.TMP_1616(uint256) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.zeroFloorSub(uint256,uint256), arguments:['newTotalAssets', 'assets'] 

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L571-582] redeem(uint256,address,address)
    [EXTERNAL] UtilsLib.TMP_1623(uint256) = LIBRARY_CALL, dest:UtilsLib, function:UtilsLib.zeroFloorSub(uint256,uint256), arguments:['newTotalAssets', 'assets'] 

## totalAssets() [CRITICAL — mueve fondos]

[FUNC] [MetaMorpho:L585-589] totalAssets()
    READ: MORPHO
    READ: withdrawQueue
    [EXTERNAL] MorphoBalancesLib.TMP_1630(uint256) = LIBRARY_CALL, dest:MorphoBalancesLib, function:MorphoBalancesLib.expectedSupplyAssets(IMorpho,MarketParams,address), arguments:['MORPHO', 'TMP_1628', 'TMP_1629'] 


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `decimals()` (L496)
```solidity
    function decimals() public view override(ERC20, ERC4626) returns (uint8) {
        return ERC4626.decimals();
    }
```

**Original** en `lib/openzeppelin-contracts/certora/harnesses/ERC20WrapperHarness.sol`:
```solidity


    function decimals() public view override(ERC20Wrapper, ERC20) returns (uint8) {
        return super.decimals();
    }
```

### Override: `maxDeposit()` (L502)
```solidity
    function maxDeposit(address) public view override returns (uint256) {
        return _maxDeposit();
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function maxDeposit(address receiver) external view returns (uint maxAssets);
    function previewDeposit(uint assets) external view returns (uint shares);
    function deposit(uint assets, address receiver) external returns (uint shares);
    function maxMint(address receiver) external view returns (uint maxShares);
    function previewMint(uint shares) external view returns (uint assets);
    function mint(uint shares, address receiver) external returns (uint assets);
    function maxWithdraw(address owner) external view returns (uint maxAssets);
    function previewWithdraw(uint assets) external view returns (uint shares);
    function withdraw(uint assets, address receiver, address owner) external returns (uint shares);
    function maxRedeem(address owner) external view returns (
```

### Override: `maxMint()` (L508)
```solidity
    function maxMint(address) public view override returns (uint256) {
        uint256 suppliable = _maxDeposit();

        return _convertToShares(suppliable, Math.Rounding.Floor);
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function maxMint(address receiver) external view returns (uint maxShares);
    function previewMint(uint shares) external view returns (uint assets);
    function mint(uint shares, address receiver) external returns (uint assets);
    function maxWithdraw(address owner) external view returns (uint maxAssets);
    function previewWithdraw(uint assets) external view returns (uint shares);
    function withdraw(uint assets, address receiver, address owner) external returns (uint shares);
    function maxRedeem(address owner) external view returns (uint maxShares);
    function previewRedeem(uint shares) external view returns (uint assets);
    function redeem(uint shares, address receiver, address owner) external returns (uint assets);
}

abstract contract ERC4626Prop is Test {
    uint 
```

### Override: `maxWithdraw()` (L517)
```solidity
    function maxWithdraw(address owner) public view override returns (uint256 assets) {
        (assets,,) = _maxWithdraw(owner);
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function maxWithdraw(address owner) external view returns (uint maxAssets);
    function previewWithdraw(uint assets) external view returns (uint shares);
    function withdraw(uint assets, address receiver, address owner) external returns (uint shares);
    function maxRedeem(address owner) external view returns (uint maxShares);
    function previewRedeem(uint shares) external view returns (uint assets);
    function redeem(uint shares, address receiver, address owner) external returns (uint assets);
}

abstract contract ERC4626Prop is Test {
    uint internal _delta_;

    address internal _underlying_;
    address internal _vault_;

    bool internal _vaultMayBeEmpty;
    bool internal _unlimitedAmount;

    //
    // asset
    //

    // asset
    // "MUST NOT revert."
    functi
```

### Override: `maxRedeem()` (L524)
```solidity
    function maxRedeem(address owner) public view override returns (uint256) {
        (uint256 assets, uint256 newTotalSupply, uint256 newTotalAssets) = _maxWithdraw(owner);

        return _convertToSharesWithTotals(assets, newTotalSupply, newTotalAssets, Math.Rounding.Floor);
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function maxRedeem(address owner) external view returns (uint maxShares);
    function previewRedeem(uint shares) external view returns (uint assets);
    function redeem(uint shares, address receiver, address owner) external returns (uint assets);
}

abstract contract ERC4626Prop is Test {
    uint internal _delta_;

    address internal _underlying_;
    address internal _vault_;

    bool internal _vaultMayBeEmpty;
    bool internal _unlimitedAmount;

    //
    // asset
    //

    // asset
    // "MUST NOT revert."
    function prop_asset(address caller) public {
        vm.prank(caller); IERC4626(_vault_).asset();
    }
```

### Override: `deposit()` (L531)
```solidity
    function deposit(uint256 assets, address receiver) public override returns (uint256 shares) {
        uint256 newTotalAssets = _accrueFee();

        // Update `lastTotalAssets` to avoid an inconsistent state in a re-entrant context.
        // It is updated again in `_deposit`.
        lastTotalAssets = newTotalAssets;

        shares = _convertToSharesWithTotals(assets, totalSupply(), newTotalAssets, Math.Rounding.Floor);

        _deposit(_msgSender(), receiver, assets, shares);
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function deposit(uint assets, address receiver) external returns (uint shares);
    function maxMint(address receiver) external view returns (uint maxShares);
    function previewMint(uint shares) external view returns (uint assets);
    function mint(uint shares, address receiver) external returns (uint assets);
    function maxWithdraw(address owner) external view returns (uint maxAssets);
    function previewWithdraw(uint assets) external view returns (uint shares);
    function withdraw(uint assets, address receiver, address owner) external returns (uint shares);
    function maxRedeem(address owner) external view returns (uint maxShares);
    function previewRedeem(uint shares) external view returns (uint assets);
    function redeem(uint shares, address receiver, address owner) 
```

### Override: `mint()` (L544)
```solidity
    function mint(uint256 shares, address receiver) public override returns (uint256 assets) {
        uint256 newTotalAssets = _accrueFee();

        // Update `lastTotalAssets` to avoid an inconsistent state in a re-entrant context.
        // It is updated again in `_deposit`.
        lastTotalAssets = newTotalAssets;

        assets = _convertToAssetsWithTotals(shares, totalSupply(), newTotalAssets, Math.Rounding.Ceil);

        _deposit(_msgSender(), receiver, assets, shares);
    }
```

**Original** en `lib/erc4626-tests/ERC4626.test.sol`:
```solidity

    function mint(address to, uint value) external;
    function burn(address from, uint value) external;
}

abstract contract ERC4626Test is ERC4626Prop {
    function setUp() public virtual;

    uint constant N = 4;

    struct Init {
        address[N] user;
        uint[N] share;
        uint[N] asset;
        int yield;
    }
```

### Override: `withdraw()` (L557)
```solidity
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256 shares) {
        uint256 newTotalAssets = _accrueFee();

        // Do not call expensive `maxWithdraw` and optimistically withdraw assets.

        shares = _convertToSharesWithTotals(assets, totalSupply(), newTotalAssets, Math.Rounding.Ceil);

        // `newTotalAssets - assets` may be a little off from `totalAssets()`.
        _updateLastTotalAssets(newTotalAssets.zeroFloorSub(assets));


```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function withdraw(uint assets, address receiver, address owner) external returns (uint shares);
    function maxRedeem(address owner) external view returns (uint maxShares);
    function previewRedeem(uint shares) external view returns (uint assets);
    function redeem(uint shares, address receiver, address owner) external returns (uint assets);
}

abstract contract ERC4626Prop is Test {
    uint internal _delta_;

    address internal _underlying_;
    address internal _vault_;

    bool internal _vaultMayBeEmpty;
    bool internal _unlimitedAmount;

    //
    // asset
    //

    // asset
    // "MUST NOT revert."
    function prop_asset(address caller) public {
        vm.prank(caller); IERC4626(_vault_).asset();
    }
```

### Override: `redeem()` (L571)
```solidity
    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256 assets) {
        uint256 newTotalAssets = _accrueFee();

        // Do not call expensive `maxRedeem` and optimistically redeem shares.

        assets = _convertToAssetsWithTotals(shares, totalSupply(), newTotalAssets, Math.Rounding.Floor);

        // `newTotalAssets - assets` may be a little off from `totalAssets()`.
        _updateLastTotalAssets(newTotalAssets.zeroFloorSub(assets));

     
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function redeem(uint shares, address receiver, address owner) external returns (uint assets);
}

abstract contract ERC4626Prop is Test {
    uint internal _delta_;

    address internal _underlying_;
    address internal _vault_;

    bool internal _vaultMayBeEmpty;
    bool internal _unlimitedAmount;

    //
    // asset
    //

    // asset
    // "MUST NOT revert."
    function prop_asset(address caller) public {
        vm.prank(caller); IERC4626(_vault_).asset();
    }
```

### Override: `totalAssets()` (L585)
```solidity
    function totalAssets() public view override returns (uint256 assets) {
        for (uint256 i; i < withdrawQueue.length; ++i) {
            assets += MORPHO.expectedSupplyAssets(_marketParams(withdrawQueue[i]), address(this));
        }
    }
```

**Original** en `lib/erc4626-tests/ERC4626.prop.sol`:
```solidity

    function totalAssets() external view returns (uint totalManagedAssets);
    function convertToShares(uint assets) external view returns (uint shares);
    function convertToAssets(uint shares) external view returns (uint assets);
    function maxDeposit(address receiver) external view returns (uint maxAssets);
    function previewDeposit(uint assets) external view returns (uint shares);
    function deposit(uint assets, address receiver) external returns (uint shares);
    function maxMint(address receiver) external view returns (uint maxShares);
    function previewMint(uint shares) external view returns (uint assets);
    function mint(uint shares, address receiver) external returns (uint assets);
    function maxWithdraw(address owner) external view returns (uint maxAssets);
    fu
```

## Symmetric Analysis
# Symmetric Analysis Report

Pares encontrados: 3


## Par: deposit/withdraw

### State Variables Written
| Variable | deposit | withdraw |
|----------|:---:|:---:|
| **lastTotalAssets** | **YES** | **NO** |


## Par: supplyqueue/withdrawqueue

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: supplyqueuelength/withdrawqueuelength

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


---
## Resumen
- Pares analizados: 3
- **Asimetrías encontradas: 1**
- Cada asimetría es un candidato a invariante. Investigar si es by-design o bug.

Bug real de referencia: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M

