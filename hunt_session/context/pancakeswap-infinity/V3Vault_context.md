# Contexto de Hunt — V3Vault

**Protocolo**: revert-lend
**Dominio**: vault
**LOC**: 1010
**Archivo**: /home/kali/Documents/Web3/revert-lend/src/V3Vault.sol
**Generado**: 2026-03-24T01:48:16.861846Z

## Solodit Context
### Findings sobre V3Vault
Buscando 'V3Vault' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (2ms)

 1. [GAS] [G-08] Cache calculations instead of re-calculating. Saves 3 checked subtraction — Revert Lend
 2. [GAS] [G-06] Cache state variable outside of the else block to save 1 sload — Revert Lend
 3. [MEDIUM] [M-08] `DailyLendIncreaseLimitLeft` and `dailyDebtIncreaseLimitLeft` are not adj — Revert Lend
 4. [GAS] [G-04] Refactor `borrow` function to avoid 1 sload — Revert Lend
 5. [MEDIUM] [M-14] `V3Vault` is not ERC-4626 compliant — Revert Lend

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: V3Vault | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [GAS] [G-08] Cache calculations instead of re-calculating. Saves 3 checked subtractions. (Revert Lend)
   
### Instance 1

Cache `block.timestamp - lastRateUpdate` to save 1 checked subtraction.

```solidity
File : V3Vault.sol

1188:    + oldDebtExchangeRa...

2. [GAS] [G-06] Cache state variable outside of the else block to save 1 sload (Revert Lend)
   
Cache `transformedTokenId` outside of the else block saves 1 sload (~100 gas) on above if statement false.

```solidity
File : V3Vault.sol

441: if (...

3. [MEDIUM] [M-08] `DailyLendIncreaseLimitLeft` and `dailyDebtIncreaseLimitLeft` are not adjusted accurately (Revert Lend)
   
<https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L807-L949> 

<https://github.com/code-423n4/2024-03-revert-lend/blob/mai...

4. [GAS] [G-04] Refactor `borrow` function to avoid 1 sload (Revert Lend)
   
Since `transformedTokenId == tokenId`, check that both should be equal. We can use `tokenId` instead of `transformedTokenId` and check `tokenId` for ...

5. [MEDIUM] [M-14] `V3Vault` is not ERC-4626 compliant (Revert Lend)
   
<https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L301-L309>

<https://github.com/code...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio vault
Buscando 'V3Vault vaultInfo lendInfo loanInfo ownerOf' [SQLite FTS5] (dominio: vault)...
Top 2 findings relevantes: (14ms)
 1. [HIGH] H-2: `LIEN_TOKEN.ownerOf(i)` should be `LIEN_TOKEN.ownerOf(liensRemaining[i])` — Astaria
 2. [HIGH] H-3: buyoutLien() will cause the vault to fail to processEpoch() — Astaria
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: V3Vault vaultInfo lendInfo loanInfo ownerOf | Dominio: vault
Los siguientes 2 findings de protocolos similares son relevantes:
1. [HIGH] H-2: `LIEN_TOKEN.ownerOf(i)` should be `LIEN_TOKEN.ownerOf(liensRemaining[i])` (Astaria)
   Source: https://github.com/sherlock-audit/2022-10-astaria-judging/issues/259 
## Found by 
\_\_141345\_\_, 0xRajeev
## Summary
In `endAuction()`, t...
2. [HIGH] H-3: buyoutLien() will cause the vault to fail to processEpoch() (Astaria)
   Source: https://github.com/sherlock-audit/2022-10-astaria-judging/issues/245 
## Found by 
bin2chen
## Summary
LienToken#buyoutLien() did not reduce...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'V3Vault vaultInfo lendInfo loanInfo ownerOf' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (2ms)
 1. [HIGH] [H-02] currentLoanOwner can manipulate loanInfo when any lenders try to buyout — Backed Protocol
 2. [HIGH] [H-03] `V3Vault::transform` does not validate the `data` input and allows a depo — Revert Lend
 3. [HIGH] Income is erroneously calculated using accumulated income — Parabol Labs - Protocol Contracts
 4. [HIGH] H-3: Creditor can maliciously burn UniV3 position to permanently lock funds — Real W

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

# Deep Flatten — V3Vault

Funciones analizadas: 43


## borrow(uint256,uint256) [CRITICAL — mueve fondos]

[FUNC] [IVault:L77-79] borrow(uint256,uint256)

## repay(uint256,uint256,bool) [CRITICAL — mueve fondos]

[FUNC] [IVault:L79-82] repay(uint256,uint256,bool)

## liquidate(IVault.LiquidateParams) [CRITICAL — mueve fondos]

[FUNC] [IVault:L91-96] liquidate(IVault.LiquidateParams)

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L78-81] maxDeposit(address)

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L96-96] previewDeposit(uint256)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L109-109] deposit(uint256,address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L116-116] maxMint(address)

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L133-134] previewMint(uint256)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L145-147] mint(uint256,address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L153-155] maxWithdraw(address)

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L173-174] previewWithdraw(uint256)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L186-187] withdraw(uint256,address,address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L196-197] maxRedeem(address)

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L214-214] previewRedeem(uint256)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [IERC4626:L226-228] redeem(uint256,address,address)

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L39-41] transfer(address,uint256)

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [IERC20:L73-77] transferFrom(address,address,uint256)

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [Ownable2Step:L33-37] transferOwnership(address)
  [MODIFIER] onlyOwner()
    WRITE: _pendingOwner

## transferOwnership(address) [CRITICAL — mueve fondos]

[FUNC] [Ownable:L66-70] transferOwnership(address)
  [MODIFIER] onlyOwner()

## multicall(bytes[]) [CRITICAL — mueve fondos]

[FUNC] [Multicall:L26-36] multicall(bytes[])
    [EXTERNAL] Address.TMP_972(bytes) = LIBRARY_CALL, dest:Address, function:Address.functionDelegateCall(address,bytes), arguments:['TMP_970', 'TMP_971'] 

## transfer(address,uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC20:L110-113] transfer(address,uint256)

## transferFrom(address,address,uint256) [CRITICAL — mueve fondos]

[FUNC] [ERC20:L154-158] transferFrom(address,address,uint256)

## totalAssets() [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L275-285] totalAssets()
    READ: asset
    READ: debtSharesTotal
    [EXTERNAL] IERC20.TMP_1058(uint256) = HIGH_LEVEL_CALL, dest:TMP_1056(IERC20), function:balanceOf, arguments:['TMP_1057']  

## maxDeposit(address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L297-300] maxDeposit(address)

## maxMint(address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L300-310] maxMint(address)

## maxWithdraw(address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L310-313] maxWithdraw(address)

## maxRedeem(address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L316-323] maxRedeem(address)

## previewDeposit(uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L323-326] previewDeposit(uint256)

## previewMint(uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L326-332] previewMint(uint256)

## previewWithdraw(uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L332-338] previewWithdraw(uint256)

## previewRedeem(uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L338-344] previewRedeem(uint256)

## deposit(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L347-350] deposit(uint256,address)

## mint(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L350-356] mint(uint256,address)

## withdraw(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L356-362] withdraw(uint256,address,address)

## redeem(uint256,address,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L363-368] redeem(uint256,address,address)

## create(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L374-382] create(uint256,address)
    READ: nonfungiblePositionManager
    [EXTERNAL] INonfungiblePositionManager.HIGH_LEVEL_CALL, dest:nonfungiblePositionManager(INonfungiblePositionManager), function:safeTransferFrom, arguments:['msg.sender', 'TMP_1075', 'tokenId', 'TMP_1076']  

## borrow(uint256,uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L570-623] borrow(uint256,uint256)
    READ: asset
    READ: dailyDebtIncreaseLimitLeft
    READ: debtSharesTotal
    READ: globalDebtLimit
    READ: loans
    READ: minLoanSize
    READ: tokenOwner
    READ: transformedTokenId
    READ: transformerAllowList
    WRITE: dailyDebtIncreaseLimitLeft
    WRITE: debtSharesTotal
    WRITE: loans
    [EXTERNAL] SafeERC20.LIBRARY_CALL, dest:SafeERC20, function:SafeERC20.safeTransfer(IERC20,address,uint256), arguments:['TMP_1173', 'msg.sender', 'assets'] 

## decreaseLiquidityAndCollect(IVault.DecreaseLiquidityAndCollectParams) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L623-676] decreaseLiquidityAndCollect(IVault.DecreaseLiquidityAndCollectParams)
    READ: loans
    READ: nonfungiblePositionManager
    READ: tokenOwner
    READ: transformedTokenId
    [EXTERNAL] INonfungiblePositionManager.TUPLE_32(uint256,uint256) = HIGH_LEVEL_CALL, dest:nonfungiblePositionManager(INonfungiblePositionManager), function:decreaseLiquidity, arguments:['TMP_1182']  
    [EXTERNAL] SafeCast.TMP_1196(uint128) = LIBRARY_CALL, dest:SafeCast, function:SafeCast.toUint128(uint256), arguments:['TMP_1195'] 
    [EXTERNAL] INonfungiblePositionManager.TUPLE_33(uint256,uint256) = HIGH_LEVEL_CALL, dest:nonfungiblePositionManager(INonfungiblePositionManager), function:collect, arguments:['collectParams']  
    [EXTERNAL] SafeCast.TMP_1198(uint128) = LIBRARY_CALL, dest:SafeCast, function:SafeCast.toUint128(uint256), arguments:['TMP_1197'] 

## repay(uint256,uint256,bool) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L684-689] repay(uint256,uint256,bool)

## liquidate(IVault.LiquidateParams) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L708-769] liquidate(IVault.LiquidateParams)
    READ: dailyDebtIncreaseLimitLeft
    READ: debtSharesTotal
    READ: loans
    READ: tokenOwner
    READ: transformedTokenId
    WRITE: dailyDebtIncreaseLimitLeft
    WRITE: debtSharesTotal

## remove(uint256,address,bytes) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L774-791] remove(uint256,address,bytes)
    READ: loans
    READ: nonfungiblePositionManager
    READ: tokenOwner
    [EXTERNAL] INonfungiblePositionManager.HIGH_LEVEL_CALL, dest:nonfungiblePositionManager(INonfungiblePositionManager), function:safeTransferFrom, arguments:['TMP_1224', 'recipient', 'tokenId', 'data']  

## withdrawReserves(uint256,address) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L798-821] withdrawReserves(uint256,address)
  [MODIFIER] onlyOwner()
    READ: Q32
    READ: asset
    READ: reserveProtectionFactorX32
    [EXTERNAL] SafeERC20.LIBRARY_CALL, dest:SafeERC20, function:SafeERC20.safeTransfer(IERC20,address,uint256), arguments:['TMP_1234', 'receiver', 'amount'] 

## unstakePosition(uint256) [CRITICAL — mueve fondos]

[FUNC] [V3Vault:L1365-1368] unstakePosition(uint256)
    READ: gaugeManager
    READ: tokenOwner
    READ: transformedTokenId
    [EXTERNAL] IGaugeManager.HIGH_LEVEL_CALL, dest:TMP_1491(IGaugeManager), function:unstakePosition, arguments:['tokenId']  


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `lendInfo()` (L219)
```solidity
    function lendInfo(address account) external view override returns (uint256 amount) {
        (, uint256 newLendExchangeRateX96) = _calculateGlobalInterest();
        amount = _convertToAssets(balanceOf(account), newLendExchangeRateX96, Math.Rounding.Down);
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `ownerOf()` (L258)
```solidity
    function ownerOf(uint256 tokenId) external view override returns (address owner) {
        return tokenOwner[tokenId];
    }
```

**Original** en `lib/permit2/lib/forge-std/test/StdCheats.t.sol`:
```solidity


    function ownerOf(uint256 tokenId) public view virtual returns (address) {
        address owner = _owners[tokenId];
        return owner;
    }
```

### Override: `loanCount()` (L264)
```solidity
    function loanCount(address owner) external view override returns (uint256) {
        return ownedTokens[owner].length;
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `loanAtIndex()` (L271)
```solidity
    function loanAtIndex(address owner, uint256 index) external view override returns (uint256) {
        return ownedTokens[owner][index];
    }
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `decimals()` (L277)
```solidity
    function decimals() public view override(IERC20Metadata, ERC20) returns (uint8) {
        return assetDecimals;
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/mocks/ERC20DecimalsMock.sol`:
```solidity


    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }
```

### Override: `totalAssets()` (L284)
```solidity
    function totalAssets() external view override returns (uint256) {
        (uint256 debtExchangeRateX96,) = _calculateGlobalInterest();
        // Round debt up to avoid understating liabilities in share pricing/accounting.
        uint256 debt = _convertToAssets(debtSharesTotal, debtExchangeRateX96, Math.Rounding.Up);
        return IERC20(asset).balanceOf(address(this)) + debt;
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol`:
```solidity


/**
 * @dev Implementation of the ERC4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[EIP-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}
```

### Override: `convertToShares()` (L292)
```solidity
    function convertToShares(uint256 assets) external view override returns (uint256 shares) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToShares(assets, lendExchangeRateX96, Math.Rounding.Down);
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol`:
```solidity


/**
 * @dev Implementation of the ERC4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[EIP-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}
```

### Override: `convertToAssets()` (L298)
```solidity
    function convertToAssets(uint256 shares) external view override returns (uint256 assets) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToAssets(shares, lendExchangeRateX96, Math.Rounding.Down);
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol`:
```solidity


/**
 * @dev Implementation of the ERC4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[EIP-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}
```

### Override: `maxDeposit()` (L304)
```solidity
    function maxDeposit(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _maxDepositAssets(lendExchangeRateX96);
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol`:
```solidity


/**
 * @dev Implementation of the ERC4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[EIP-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}
```

### Override: `maxMint()` (L310)
```solidity
    function maxMint(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        uint256 maxGlobalDeposit = _maxDepositAssets(lendExchangeRateX96);
        return _convertToShares(maxGlobalDeposit, lendExchangeRateX96, Math.Rounding.Down);
    }
```

**Original** en `lib/permit2/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol`:
```solidity


/**
 * @dev Implementation of the ERC4626 "Tokenized Vault Standard" as defined in
 * https://eips.ethereum.org/EIPS/eip-4626[EIP-4626].
 *
 * This extension allows the minting and burning of "shares" (represented using the ERC20 inheritance) in exchange for
 * underlying "assets" through standardized {deposit}
```

## Symmetric Analysis
# Symmetric Analysis Report

Pares encontrados: 4


## Par: deposit/withdraw

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: stakeposition/unstakeposition

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


## Par: borrow/repay

### State Variables Written
| Variable | borrow | repay |
|----------|:---:|:---:|
| **dailyDebtIncreaseLimitLeft** | **YES** | **NO** |
| **debtSharesTotal** | **YES** | **NO** |
| **loans** | **YES** | **NO** |


## Par: increaseallowance/decreaseallowance

State vars written: SYMMETRIC (0 vars)

**SYMMETRIC** — no se encontraron asimetrías en este par.


---
## Resumen
- Pares analizados: 4
- **Asimetrías encontradas: 3**
- Cada asimetría es un candidato a invariante. Investigar si es by-design o bug.

Bug real de referencia: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M

