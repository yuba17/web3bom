# Contexto de Hunt — VaultV2

**Protocolo**: vault-v2
**Dominio**: vault
**LOC**: 556
**Archivo**: /home/kali/Documents/Web3/vault-v2/src/VaultV2.sol
**Generado**: 2026-03-24T22:57:40.046190Z

## Solodit Context
### Findings sobre VaultV2
Buscando 'VaultV2' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (37ms)

 1. [LOW] isInRegistry does not check whether parent vault was deployed by a designated Va — Morpho Adapter Registries
 2. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions — Morpho Vaults v2
 3. [LOW] VaultV2 could end up minting shares > 0 that are not backed by MetaMorpho shares — Morpho Vaults v2
 4. [LOW] Extra check can be added when setting vic — Morpho Vaults v2
 5. [LOW] Zero shares could be minted for a non-zero provided asset — Morpho Vaults v2 Fix Review

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: VaultV2 | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] isInRegistry does not check whether parent vault was deployed by a designated VaultV2 factory (Morpho Adapter Registries)
   ## Low Risk Severity Report

## Context
- **Files**: 
  - MorphoMarketV1Registry.sol#L18-L21 
  - MorphoVaultV1Registry.sol#L19-L22

## Description
Bo...

2. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions (Morpho Vaults v2)
   ## Severity: High Risk

## Context
(No context files were provided by the reviewer)

## Description
This finding describes the potential side effects ...

3. [LOW] VaultV2 could end up minting shares > 0 that are not backed by MetaMorpho shares (Morpho Vaults v2)
   ## Severity: Low Risk

## Context
MetaMorphoAdapter.sol#L53-L66

## Description
The current implementation of the `MetaMorphoAdapter` adapter does not...

4. [LOW] Extra check can be added when setting vic (Morpho Vaults v2)
   ## Severity: Low Risk

## Context
- IVic.sol#L4-L6
- VaultV2.sol#L198-L202
- IManualVic.sol#L25

## Description
Currently, there is only one implement...

5. [LOW] Zero shares could be minted for a non-zero provided asset (Morpho Vaults v2 Fix Review)
   ## Severity: Low Risk

## Context
VaultV2.sol#L692

## Description
In the mint and deposit flow of the VaultV2, there might be cases where the share t...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio vault
Buscando 'VaultV2 adaptersLength totalAssets DOMAIN_SEPARATOR absoluteCap' [SQLite FTS5] (dominio: vault)...
Top 6 findings relevantes: (243ms)
 1. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions — Morpho Vaults v2
 2. [HIGH] H-11: Differences between actual and cached total assets can be arbitraged — Tokemak
 3. [HIGH] [C-06] `borrow()` should decrease `totalAssets` value — Omo_2025-01-25
 4. [HIGH] [H-04] `_increaseBalance()` mints fewer shares than expected — Karak-June
 5. [HIGH] Multiple instances where Vault's `totalAssets()` is not properly scaled to ZAROS — Part 2
 6. [HIGH] Revenue accounting ignores losses — Tenbin
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: VaultV2 adaptersLength totalAssets DOMAIN_SEPARATOR absoluteCap | Dominio: vault
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Side effects of underlying directly donated to the VaultV2 or adapters positions (Morpho Vaults v2)
   ## Severity: High Risk
## Context
(No context files were provided by the reviewer)
## Description
This finding describes the potential side effects ...
2. [HIGH] H-11: Differences between actual and cached total assets can be arbitraged (Tokemak)
   Source: https://github.com/sherlock-audit/2023-06-tokemak-judging/issues/611 
## Found by 
0x007, 0xWeiss, Ch\_301, Flora, Kalyan-Singh, caelumimperi...
3. [HIGH] [C-06] `borrow()` should decrease `totalAssets` value (Omo_2025-01-25)
   ## Severity
**Impact:** High
**Likelihood:** High
## Description
The `OmoVault.sol` contract has a `borrow()` us

## Briefing del Dominio
### Briefing principal: vault
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Share Inflation / First Depositor Attack
### 1.2 Donation Attack (Direct Transfer Breaks Accounting)
### 1.3 Rounding Direction Exploitation
### 1.4 Roundtrip Extraction (Deposit Then Redeem for Profit)
### 1.5 Zero Amount Edge Cases (Free Shares/Assets)
### 1.6 Approval/Allowance Bypass on Redeem/Withdraw
### 1.7 Share Price Manipulation
### 1.8 Preview Function Inconsistency

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ OZ ERC4626 v4.9+ with _decimalsOffset() is protected — check the offset value
  ⚠ Vaults with pre-seeded dead shares in constructor are already mitigated
  ⚠ Some vaults use internal shares that differ from ERC20 totalSupply
  ⚠ Protocols using internal accounting are NOT vulnerable even without virtual shares
  ⚠ Rebasing tokens legitimately change balanceOf — don't flag as donation
  ⚠ Some protocols have intentional donate() functions for yield distribution
  ⚠ 1 wei rounding per operation is expected and acceptable — it is NOT a bug
  ⚠ The bug is when rounding consistently favors the user over the vault
  ⚠ With virtual shares offset, the rounding error per operation is negligible
  ⚠ Fee-on-transfer tokens cause apparent profit from vault perspective — use standard ERC20 for testing
  ⚠ State changes between deposit and redeem (yield accrual) can legitimately change the result — test atomically
  ⚠ Some vaults intentionally revert on zero — that is acceptable per EIP

## CHECKLIST DE INVARIANTES
Run through this when you encounter an ERC-4626 vault. Each "NO" is a lead to investigate.
### First Depositor Protection
- [ ] Does the vault use virtual shares/assets offset (e.g., `_decimalsOffset()`)?
- [ ] OR does it burn MINIMUM_LIQUIDITY to dead address on first mint?
- [ ] OR does it enforce a minimum first deposit amount?
- [ ] If NONE of the above: **vault-001 is likely exploitable**
### Donation Resistance
- [ ] Does `totalAssets()` use internal accounting (not 

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

# Deep Flatten — VaultV2

Funciones analizadas: 39


## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L12-12] deposit(uint256,address)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L13-13] mint(uint256,address)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L14-14] withdraw(uint256,address,address)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L15-15] redeem(uint256,address,address)

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L16-16] previewDeposit(uint256)

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L17-17] previewMint(uint256)

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L18-18] previewWithdraw(uint256)

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L19-19] previewRedeem(uint256)

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L20-20] maxDeposit(address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L21-21] maxMint(address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L22-22] maxWithdraw(address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L23-23] maxRedeem(address)

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L11-11] transfer(address,uint256)

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L12-12] transferFrom(address,address,uint256)

## multicall(bytes[]) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L280-289] multicall(bytes[])
    [LOW_CALL] TUPLE_1(bool,bytes) = LOW_LEVEL_CALL, dest:TMP_4, function:delegatecall, arguments:['REF_10']  

## setAdapterRegistry(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L401-414] setAdapterRegistry(address)
    READ: adapters
    WRITE: adapterRegistry
    [EXTERNAL] IAdapterRegistry.TMP_85(bool) = HIGH_LEVEL_CALL, dest:TMP_84(IAdapterRegistry), function:isInRegistry, arguments:['REF_45']  

## addAdapter(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L416-427] addAdapter(address)
    READ: adapterRegistry
    READ: adapters
    READ: isAdapter
    WRITE: adapters
    WRITE: isAdapter
    [EXTERNAL] IAdapterRegistry.TMP_94(bool) = HIGH_LEVEL_CALL, dest:TMP_93(IAdapterRegistry), function:isInRegistry, arguments:['account']  

## increaseAbsoluteCap(bytes,uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L515-522] increaseAbsoluteCap(bytes,uint256)
    READ: caps
    WRITE: caps
    [EXTERNAL] MathLib.TMP_178(uint128) = LIBRARY_CALL, dest:MathLib, function:MathLib.toUint128(uint256), arguments:['newAbsoluteCap'] 

## accrueInterest() [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L636-644] accrueInterest()
    READ: _totalAssets
    READ: firstTotalAssets
    READ: managementFeeRecipient
    READ: performanceFeeRecipient
    WRITE: _totalAssets
    WRITE: firstTotalAssets
    WRITE: lastUpdate
    [EXTERNAL] MathLib.TMP_271(uint128) = LIBRARY_CALL, dest:MathLib, function:MathLib.toUint128(uint256), arguments:['newTotalAssets'] 

## accrueInterestView() [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L652-681] accrueInterestView()
    READ: _totalAssets
    READ: adapters
    READ: asset
    READ: firstTotalAssets
    READ: lastUpdate
    READ: managementFee
    READ: managementFeeRecipient
    READ: maxRate
    READ: performanceFee
    READ: performanceFeeRecipient
    READ: totalSupply
    READ: virtualShares
    [EXTERNAL] MathLib.TMP_312(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['TMP_311', 'managementFee', 'WAD'] 
    [EXTERNAL] IERC20.TMP_282(uint256) = HIGH_LEVEL_CALL, dest:TMP_280(IERC20), function:balanceOf, arguments:['TMP_281']  
    [EXTERNAL] MathLib.TMP_291(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.zeroFloorSub(uint256,uint256), arguments:['newTotalAssets', '_totalAssets'] 
    [EXTERNAL] MathLib.TMP_305(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['interest', 'performanceFee', 'WAD'] 
    [EXTERNAL] MathLib.TMP_288(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['TMP_287', 'maxRate', 'WAD'] 
    [EXTERNAL] IAdapter.TMP_285(uint256) = HIGH_LEVEL_CALL, dest:TMP_284(IAdapter), function:realAssets, arguments:[]  
    [EXTERNAL] MathLib.TMP_296(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['performanceFeeAssets', 'TMP_294', 'TMP_295'] 
    [EXTERNAL] MathLib.TMP_299(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['managementFeeAssets', 'TMP_297', 'TMP_298'] 
    [EXTERNAL] MathLib.TMP_290(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.min(uint256,uint256), arguments:['realAssets', 'maxTotalAssets'] 

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L684-688] previewDeposit(uint256)
    READ: totalSupply
    READ: virtualShares
    [EXTERNAL] MathLib.TMP_317(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['assets', 'TMP_315', 'TMP_316'] 

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L691-695] previewMint(uint256)
    READ: totalSupply
    READ: virtualShares
    [EXTERNAL] MathLib.TMP_322(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivUp(uint256,uint256,uint256), arguments:['shares', 'TMP_320', 'TMP_321'] 

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L698-702] previewWithdraw(uint256)
    READ: totalSupply
    READ: virtualShares
    [EXTERNAL] MathLib.TMP_327(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivUp(uint256,uint256,uint256), arguments:['assets', 'TMP_325', 'TMP_326'] 

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L705-709] previewRedeem(uint256)
    READ: totalSupply
    READ: virtualShares
    [EXTERNAL] MathLib.TMP_332(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivDown(uint256,uint256,uint256), arguments:['shares', 'TMP_330', 'TMP_331'] 

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L726-728] maxDeposit(address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L731-733] maxMint(address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L736-738] maxWithdraw(address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L741-743] maxRedeem(address)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L748-753] deposit(uint256,address)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L756-761] mint(uint256,address)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L777-782] withdraw(uint256,address,address)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L785-790] redeem(uint256,address,address)

## forceDeallocate(address,bytes,uint256,address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L822-831] forceDeallocate(address,bytes,uint256,address)
    READ: forceDeallocatePenalty
    [EXTERNAL] MathLib.TMP_386(uint256) = LIBRARY_CALL, dest:MathLib, function:MathLib.mulDivUp(uint256,uint256,uint256), arguments:['assets', 'REF_171', 'WAD'] 

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L836-846] transfer(address,uint256)
    READ: balanceOf
    WRITE: balanceOf

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L849-868] transferFrom(address,address,uint256)
    READ: allowance
    READ: balanceOf
    WRITE: allowance
    WRITE: balanceOf

## canReceiveShares(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L910-912] canReceiveShares(address)
    READ: receiveSharesGate
    [EXTERNAL] IReceiveSharesGate.TMP_457(bool) = HIGH_LEVEL_CALL, dest:TMP_456(IReceiveSharesGate), function:canReceiveShares, arguments:['account']  

## canSendShares(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L914-916] canSendShares(address)
    READ: sendSharesGate
    [EXTERNAL] ISendSharesGate.TMP_462(bool) = HIGH_LEVEL_CALL, dest:TMP_461(ISendSharesGate), function:canSendShares, arguments:['account']  

## canReceiveAssets(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L918-921] canReceiveAssets(address)
    READ: receiveAssetsGate
    [EXTERNAL] IReceiveAssetsGate.TMP_470(bool) = HIGH_LEVEL_CALL, dest:TMP_469(IReceiveAssetsGate), function:canReceiveAssets, arguments:['account']  

## canSendAssets(address) [CRITICAL — mueve fondos]

[FUNC] [VaultV2:L923-925] canSendAssets(address)
    READ: sendAssetsGate
    [EXTERNAL] ISendAssetsGate.TMP_475(bool) = HIGH_LEVEL_CALL, dest:TMP_474(ISendAssetsGate), function:canSendAssets, arguments:['account']  



## Symmetric Analysis
# Symmetric Analysis Report

Pares encontrados: 5


## Par: deposit/withdraw

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: increasetimelock/decreasetimelock

State vars written: SYMMETRIC (1 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: increaseabsolutecap/decreaseabsolutecap

State vars written: SYMMETRIC (1 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: increaserelativecap/decreaserelativecap

State vars written: SYMMETRIC (1 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: addadapter/removeadapter

State vars written: SYMMETRIC (2 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


---
## Resumen
- Pares analizados: 5
- **Asimetrías encontradas: 0**

Bug real de referencia: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M

