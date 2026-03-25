# AccessHunter — GeneralAdapter1 Analysis

## Tu Identidad
Eres el **AccessHunter** del equipo de bug hunting de morpho-bundler3.
Tu especialidad: **Access control, missing modifiers, privilege escalation, role misconfig**

## Tu Objetivo
Analizar `GeneralAdapter1` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/GeneralAdapter1.sol`
**Dominio**: trust


## Asset Flow Map
### Money IN (deposits/receives)
- L363 permit2TransferFrom(): Permit2Lib.PERMIT2.transferFrom(initiator, receiver, amount.toUint160(), token);
- L381 erc20TransferFrom(): SafeERC20.safeTransferFrom(IERC20(token), initiator, receiver, amount);

### Money OUT (withdrawals/sends)
- L396 wrapNative(): if (receiver != address(this)) SafeERC20.safeTransfer(IERC20(address(WRAPPED_NATIVE)), receiver, amount);

### Approvals (attack surface)
- L60 erc4626Mint(): SafeERC20.forceApprove(underlyingToken, vault, type(uint256).max);
- L64 erc4626Mint(): SafeERC20.forceApprove(underlyingToken, vault, 0);
- L87 erc4626Deposit(): SafeERC20.forceApprove(underlyingToken, vault, type(uint256).max);
- L91 erc4626Deposit(): SafeERC20.forceApprove(underlyingToken, vault, 0);
- L197 morphoSupply(): SafeERC20.forceApprove(IERC20(marketParams.loanToken), address(MORPHO), type(uint256).max);
- L225 morphoSupplyCollateral(): SafeERC20.forceApprove(IERC20(marketParams.collateralToken), address(MORPHO), type(uint256).max);
- L286 morphoRepay(): SafeERC20.forceApprove(IERC20(marketParams.loanToken), address(MORPHO), type(uint256).max);
- L344 morphoFlashLoan(): SafeERC20.forceApprove(IERC20(token), address(MORPHO), type(uint256).max);

### Minting/Burning
- L62 erc4626Mint(): uint256 assets = IERC4626(vault).mint(shares, receiver);

### Balance Reads (manipulation vectors)
- L83 erc4626Deposit(): if (assets == type(uint256).max) assets = underlyingToken.balanceOf(address(this));
- L133 erc4626Redeem(): if (shares == type(uint256).max) shares = IERC4626(vault).balanceOf(owner);
- L192 morphoSupply(): assets = IERC20(marketParams.loanToken).balanceOf(address(this));
- L220 morphoSupplyCollateral(): if (assets == type(uint256).max) assets = IERC20(marketParams.collateralToken).balanceOf(address(this));
- L276 morphoRepay(): assets = IERC20(marketParams.loanToken).balanceOf(address(this));
- L359 permit2TransferFrom(): if (amount == type(uint256).max) amount = IERC20(token).balanceOf(initiator);
- L377 erc20TransferFrom(): if (amount == type(uint256).max) amount = IERC20(token).balanceOf(initiator);
- L391 wrapNative(): if (amount == type(uint256).max) amount = address(this).balance;
- L405 unwrapNative(): if (amount == type(uint256).max) amount = WRAPPED_NATIVE.balanceOf(address(this));
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.28;

import {IWNative} from "../interfaces/IWNative.sol";
import {IERC4626} from "../../lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {MarketParams, IMorpho} from "../../lib/morpho-blue/src/interfaces/IMorpho.sol";
import {CoreAdapter, ErrorsLib, IERC20, SafeERC20, Address} from "./CoreAdapter.sol";
import {MathRayLib} from "../libraries/MathRayLib.sol";
import {SafeCast160} from "../../lib/permit2/src/libraries/SafeCast160.sol";
import {Permit2Lib} from "../../lib/permit2/src/libraries/Permit2Lib.sol";
import {MorphoBalancesLib} from "../../lib/morpho-blue/src/libraries/periphery/MorphoBalancesLib.sol";
import {MarketParamsLib} from "../../lib/morpho-blue/src/libraries/MarketParamsLib.sol";
import {MorphoLib} from "../../lib/morpho-blue/src/libraries/periphery/MorphoLib.sol";

/// @custom:security-contact security@morpho.org
/// @notice Chain agnostic adapter contract n°1.
contract GeneralAdapter1 is CoreAdapter {
    using SafeCast160 for uint256;
    using MarketParamsLib for MarketParams;
    using MathRayLib for uint256;

    /* IMMUTABLES */

    /// @notice The address of the Morpho contract.
    IMorpho public immutable MORPHO;

    /// @dev The address of the wrapped native token.
    IWNative public immutable WRAPPED_NATIVE;

    /* CONSTRUCTOR */

    /// @param bundler3 The address of the Bundler3 contract.
    /// @param morpho The address of the Morpho protocol.
    /// @param wNative The address of the canonical native token wrapper.
    constructor(address bundler3, address morpho, address wNative) CoreAdapter(bundler3) {
        require(morpho != address(0), ErrorsLib.ZeroAddress());
        require(wNative != address(0), ErrorsLib.ZeroAddress());

        MORPHO = IMorpho(morpho);
        WRAPPED_NATIVE = IWNative(wNative);
    }

    /* ERC4626 ACTIONS */

    /// @notice Mints shares of an ERC4626 vault.
    /// @dev Underlying tokens must have been previously sent to the adapter.
    /// @dev Assumes the given vault implements EIP-4626.
    /// @param vault The address of the vault.
    /// @param shares The amount of vault shares to mint.
    /// @param maxSharePriceE27 The maximum amount of assets to pay to get 1 share, scaled by 1e27.
    /// @param receiver The address to which shares will be minted.
    function erc4626Mint(address vault, uint256 shares, uint256 maxSharePriceE27, address receiver)
        external
        onlyBundler3
    {
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(shares != 0, ErrorsLib.ZeroShares());

        IERC20 underlyingToken = IERC20(IERC4626(vault).asset());
        SafeERC20.forceApprove(underlyingToken, vault, type(uint256).max);

        uint256 assets = IERC4626(vault).mint(shares, receiver);

        SafeERC20.forceApprove(underlyingToken, vault, 0);

        require(assets.rDivUp(shares) <= maxSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Deposits underlying token in an ERC4626 vault.
    /// @dev Underlying tokens must have been previously sent to the adapter.
    /// @dev Assumes the given vault implements EIP-4626.
    /// @param vault The address of the vault.
    /// @param assets The amount of underlying token to deposit. Pass `type(uint).max` to deposit the adapter's balance.
    /// @param maxSharePriceE27 The maximum amount of assets to pay to get 1 share, scaled by 1e27.
    /// @param receiver The address to which shares will be minted.
    function erc4626Deposit(address vault, uint256 assets, uint256 maxSharePriceE27, address receiver)
        external
        onlyBundler3
    {
        require(receiver != address(0), ErrorsLib.ZeroAddress());

        IERC20 underlyingToken = IERC20(IERC4626(vault).asset());
        if (assets == type(uint256).max) assets = underlyingToken.balanceOf(address(this));

        require(assets != 0, ErrorsLib.ZeroAmount());

        SafeERC20.forceApprove(underlyingToken, vault, type(uint256).max);

        uint256 shares = IERC4626(vault).deposit(assets, receiver);

        SafeERC20.forceApprove(underlyingToken, vault, 0);

        require(assets.rDivUp(shares) <= maxSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Withdraws underlying token from an ERC4626 vault.
    /// @dev Assumes the given `vault` implements EIP-4626.
    /// @dev If `owner` is the initiator, they must have previously approved the adapter to spend their vault shares.
    /// Otherwise, vault shares must have been previously sent to the adapter.
    /// @param vault The address of the vault.
    /// @param assets The amount of underlying token to withdraw.
    /// @param minSharePriceE27 The minimum number of assets to receive per share, scaled by 1e27.
    /// @param receiver The address that will receive the withdrawn assets.
    /// @param owner The address on behalf of which the assets are withdrawn. Can only be the adapter or the initiator.
    function erc4626Withdraw(address vault, uint256 assets, uint256 minSharePriceE27, address receiver, address owner)
        external
        onlyBundler3
    {
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(owner == address(this) || owner == initiator(), ErrorsLib.UnexpectedOwner());
        require(assets != 0, ErrorsLib.ZeroAmount());

        uint256 shares = IERC4626(vault).withdraw(assets, receiver, owner);
        require(assets.rDivDown(shares) >= minSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Redeems shares of an ERC4626 vault.
    /// @dev Assumes the given `vault` implements EIP-4626.
    /// @dev If `owner` is the initiator, they must have previously approved the adapter to spend their vault shares.
    /// Otherwise, vault shares must have been previously sent to the adapter.
    /// @param vault The address of the vault.
    /// @param shares The amount of vault shares to redeem. Pass `type(uint).max` to redeem the owner's shares.
    /// @param minSharePriceE27 The minimum number of assets to receive per share, scaled by 1e27.
    /// @param receiver The address that will receive the withdrawn assets.
    /// @param owner The address on behalf of which the shares are redeemed. Can only be the adapter or the initiator.
    function erc4626Redeem(address vault, uint256 shares, uint256 minSharePriceE27, address receiver, address owner)
        external
        onlyBundler3
    {
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(owner == address(this) || owner == initiator(), ErrorsLib.UnexpectedOwner());

        if (shares == type(uint256).max) shares = IERC4626(vault).balanceOf(owner);

        require(shares != 0, ErrorsLib.ZeroShares());

        uint256 assets = IERC4626(vault).redeem(shares, receiver, owner);
        require(assets.rDivDown(shares) >= minSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /* MORPHO CALLBACKS */

    /// @notice Receives supply callback from the Morpho contract.
    /// @param data Bytes containing an abi-encoded Call[].
    function onMorphoSupply(uint256, bytes calldata data) external {
        morphoCallback(data);
    }

    /// @notice Receives supply collateral callback from the Morpho contract.
    /// @param data Bytes containing an abi-encoded Call[].
    function onMorphoSupplyCollateral(uint256, bytes calldata data) external {
        morphoCallback(data);
    }

    /// @notice Receives repay callback from the Morpho contract.
    /// @param data Bytes containing an abi-encoded Call[].
    function onMorphoRepay(uint256, bytes calldata data) external {
        morphoCallback(data);
    }

    /// @notice Receives flashloan callback from the Morpho contract.
    /// @param data Bytes containing an abi-encoded Call[].
    function onMorphoFlashLoan(uint256, bytes calldata data) external {
        morphoCallback(data);
    }

    /* MORPHO ACTIONS */

    /// @notice Supplies loan asset on Morpho.
    /// @dev Either `assets` or `shares` should be zero. Most usecases should rely on `assets` as an input so the
    /// adapter is guaranteed to have `assets` tokens pulled from its balance, but the possibility to mint a specific
    /// amount of shares is given for full compatibility and precision.
    /// @dev Loan tokens must have been previously sent to the adapter.
    /// @param marketParams The Morpho market to supply assets to.
    /// @param assets The amount of assets to supply. Pass `type(uint).max` to supply the adapter's loan asset balance.
    /// @param shares The amount of shares to mint.
    /// @param maxSharePriceE27 The maximum amount of assets supplied per minted share, scaled by 1e27.
    /// @param onBehalf The address that will own the increased supply position.
    /// @param data Arbitrary data to pass to the `onMorphoSupply` callback. Pass empty data if not needed.
    function morphoSupply(
        MarketParams calldata marketParams,
        uint256 assets,
        uint256 shares,
        uint256 maxSharePriceE27,
        address onBehalf,
        bytes calldata data
    ) external onlyBundler3 {
        // Do not check `onBehalf` against the zero address as it's done in Morpho.
        require(onBehalf != address(this), ErrorsLib.AdapterAddress());

        if (assets == type(uint256).max) {
            assets = IERC20(marketParams.loanToken).balanceOf(address(this));
            require(assets != 0, ErrorsLib.ZeroAmount());
        }

        // Morpho's allowance is not reset as it is trusted.
        SafeERC20.forceApprove(IERC20(marketParams.loanToken), address(MORPHO), type(uint256).max);

        (uint256 suppliedAssets, uint256 suppliedShares) = MORPHO.supply(marketParams, assets, shares, onBehalf, data);

        require(suppliedAssets.rDivUp(suppliedShares) <= maxSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Supplies collateral on Morpho.
    /// @dev Collateral tokens must have been previously sent to the adapter.
    /// @param marketParams The Morpho market to supply collateral to.
    /// @param assets The amount of collateral to supply. Pass `type(uint).max` to supply the adapter's collateral
    /// balance.
    /// @param onBehalf The address that will own the increased collateral position.
    /// @param data Arbitrary data to pass to the `onMorphoSupplyCollateral` callback. Pass empty data if not needed.
    function morphoSupplyCollateral(
        MarketParams calldata marketParams,
        uint256 assets,
        address onBehalf,
        bytes calldata data
    ) external onlyBundler3 {
        // Do not check `onBehalf` against the zero address as it's done at Morpho's level.
        require(onBehalf != address(this), ErrorsLib.AdapterAddress());

        if (assets == type(uint256).max) assets = IERC20(marketParams.collateralToken).balanceOf(address(this));

        require(assets != 0, ErrorsLib.ZeroAmount());

        // Morpho's allowance is not reset as it is trusted.
        SafeERC20.forceApprove(IERC20(marketParams.collateralToken), address(MORPHO), type(uint256).max);

        MORPHO.supplyCollateral(marketParams, assets, onBehalf, data);
    }

    /// @notice Borrows assets on Morpho.
    /// @dev Either `assets` or `shares` should be zero. Most usecases should rely on `assets` as an input so the
    /// initiator is guaranteed to borrow `assets` tokens, but the possibility to mint a specific amount of shares is
    /// given for full compatibility and precision.
    /// @dev Initiator must have previously authorized the adapter to act on their behalf on Morpho.
    /// @param marketParams The Morpho market to borrow assets from.
    /// @param assets The amount of assets to borrow.
    /// @param shares The amount of shares to mint.
    /// @param minSharePriceE27 The minimum amount of assets borrowed per borrow share minted, scaled by 1e27.
    /// @param receiver The address that will receive the borrowed assets.
    function morphoBorrow(
        MarketParams calldata marketParams,
        uint256 assets,
        uint256 shares,
        uint256 minSharePriceE27,
        address receiver
    ) external onlyBundler3 {
        (uint256 borrowedAssets, uint256 borrowedShares) =
            MORPHO.borrow(marketParams, assets, shares, initiator(), receiver);

        require(borrowedAssets.rDivDown(borrowedShares) >= minSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Repays assets on Morpho.
    /// @dev Either `assets` or `shares` should be zero. Most usecases should rely on `assets` as an input so the
    /// adapter is guaranteed to have `assets` tokens pulled from its balance, but the possibility to burn a specific
    /// amount of shares is given for full compatibility and precision.
    /// @dev Loan tokens must have been previously sent to the adapter.
    /// @param marketParams The Morpho market to repay assets to.
    /// @param assets The amount of assets to repay. Pass `type(uint).max` to repay the adapter's loan asset balance.
    /// @param shares The amount of shares to burn. Pass `type(uint).max` to repay the initiator's entire debt.
    /// @param maxSharePriceE27 The maximum amount of assets repaid per borrow share burned, scaled by 1e27.
    /// @param onBehalf The address of the owner of the debt position.
    /// @param data Arbitrary data to pass to the `onMorphoRepay` callback. Pass empty data if not needed.
    function morphoRepay(
        MarketParams calldata marketParams,
        uint256 assets,
        uint256 shares,
        uint256 maxSharePriceE27,
        address onBehalf,
        bytes calldata data
    ) external onlyBundler3 {
        // Do not check `onBehalf` against the zero address as it's done at Morpho's level.
        require(onBehalf != address(this), ErrorsLib.AdapterAddress());

        if (assets == type(uint256).max) {
            assets = IERC20(marketParams.loanToken).balanceOf(address(this));
            require(assets != 0, ErrorsLib.ZeroAmount());
        }

        if (shares == type(uint256).max) {
            shares = MorphoLib.borrowShares(MORPHO, marketParams.id(), onBehalf);
            require(shares != 0, ErrorsLib.ZeroAmount());
        }

        // Morpho's allowance is not reset as it is trusted.
        SafeERC20.forceApprove(IERC20(marketParams.loanToken), address(MORPHO), type(uint256).max);

        (uint256 repaidAssets, uint256 repaidShares) = MORPHO.repay(marketParams, assets, shares, onBehalf, data);

        require(repaidAssets.rDivUp(repaidShares) <= maxSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Withdraws assets on Morpho.
    /// @dev Either `assets` or `shares` should be zero. Most usecases should rely on `assets` as an input so the
    /// initiator is guaranteed to withdraw `assets` tokens, but the possibility to burn a specific amount of shares is
    /// given for full compatibility and precision.
    /// @dev Initiator must have previously authorized the maodule to act on their behalf on Morpho.
    /// @param marketParams The Morpho market to withdraw assets from.
    /// @param assets The amount of assets to withdraw.
    /// @param shares The amount of shares to burn. Pass `type(uint).max` to burn all the initiator's supply shares.
    /// @param minSharePriceE27 The minimum amount of assets withdraw per burn share, scaled by 1e27.
    /// @param receiver The address that will receive the withdrawn assets.
    function morphoWithdraw(
        MarketParams calldata marketParams,
        uint256 assets,
        uint256 shares,
        uint256 minSharePriceE27,
        address receiver
    ) external onlyBundler3 {
        if (shares == type(uint256).max) {
            shares = MorphoLib.supplyShares(MORPHO, marketParams.id(), initiator());
            require(shares != 0, ErrorsLib.ZeroAmount());
        }

        (uint256 withdrawnAssets, uint256 withdrawnShares) =
            MORPHO.withdraw(marketParams, assets, shares, initiator(), receiver);

        require(withdrawnAssets.rDivDown(withdrawnShares) >= minSharePriceE27, ErrorsLib.SlippageExceeded());
    }

    /// @notice Withdraws collateral from Morpho.
    /// @dev Initiator must have previously authorized the adapter to act on their behalf on Morpho.
    /// @param marketParams The Morpho market to withdraw collateral from.
    /// @param assets The amount of collateral to withdraw. Pass `type(uint).max` to withdraw the initiator's collateral
    /// balance.
    /// @param receiver The address that will receive the collateral assets.
    function morphoWithdrawCollateral(MarketParams calldata marketParams, uint256 assets, address receiver)
        external
        onlyBundler3
    {
        if (assets == type(uint256).max) assets = MorphoLib.collateral(MORPHO, marketParams.id(), initiator());
        require(assets != 0, ErrorsLib.ZeroAmount());

        MORPHO.withdrawCollateral(marketParams, assets, initiator(), receiver);
    }

    /// @notice Triggers a flash loan on Morpho.
    /// @param token The address of the token to flash loan.
    /// @param assets The amount of assets to flash loan.
    /// @param data Arbitrary data to pass to the `onMorphoFlashLoan` callback.
    function morphoFlashLoan(address token, uint256 assets, bytes calldata data) external onlyBundler3 {
        require(assets != 0, ErrorsLib.ZeroAmount());
        // Morpho's allowance is not reset as it is trusted.
        SafeERC20.forceApprove(IERC20(token), address(MORPHO), type(uint256).max);

        MORPHO.flashLoan(token, assets, data);
    }

    /* PERMIT2 ACTIONS */

    /// @notice Transfers with Permit2.
    /// @param token The address of the ERC20 token to transfer.
    /// @param receiver The address that will receive the tokens.
    /// @param amount The amount of token to transfer. Pass `type(uint).max` to transfer the initiator's balance.
    function permit2TransferFrom(address token, address receiver, uint256 amount) external onlyBundler3 {
        require(receiver != address(0), ErrorsLib.ZeroAddress());

        address initiator = initiator();
        if (amount == type(uint256).max) amount = IERC20(token).balanceOf(initiator);

        require(amount != 0, ErrorsLib.ZeroAmount());

        Permit2Lib.PERMIT2.transferFrom(initiator, receiver, amount.toUint160(), token);
    }

    /* TRANSFER ACTIONS */

    /// @notice Transfers ERC20 tokens from the initiator.
    /// @notice Initiator must have given sufficient allowance to the Adapter to spend their tokens.
    /// @param token The address of the ERC20 token to transfer.
    /// @param receiver The address that will receive the tokens.
    /// @param amount The amount of token to transfer. Pass `type(uint).max` to transfer the initiator's balance.
    function erc20TransferFrom(address token, address receiver, uint256 amount) external onlyBundler3 {
        require(receiver != address(0), ErrorsLib.ZeroAddress());

        address initiator = initiator();
        if (amount == type(uint256).max) amount = IERC20(token).balanceOf(initiator);

        require(amount != 0, ErrorsLib.ZeroAmount());

        SafeERC20.safeTransferFrom(IERC20(token), initiator, receiver, amount);
    }

    /* WRAPPED NATIVE TOKEN ACTIONS */

    /// @notice Wraps native tokens to wNative.
    /// @dev Native tokens must have been previously sent to the adapter.
    /// @param amount The amount of native token to wrap. Pass `type(uint).max` to wrap the adapter's balance.
    /// @param receiver The account receiving the wrapped native tokens.
    function wrapNative(uint256 amount, address receiver) external onlyBundler3 {
        if (amount == type(uint256).max) amount = address(this).balance;

        require(amount != 0, ErrorsLib.ZeroAmount());

        WRAPPED_NATIVE.deposit{value: amount}();
        if (receiver != address(this)) SafeERC20.safeTransfer(IERC20(address(WRAPPED_NATIVE)), receiver, amount);
    }

    /// @notice Unwraps wNative tokens to the native token.
    /// @dev Wrapped native tokens must have been previously sent to the adapter.
    /// @param amount The amount of wrapped native token to unwrap. Pass `type(uint).max` to unwrap the adapter's
    /// balance.
    /// @param receiver The account receiving the native tokens.
    function unwrapNative(uint256 amount, address receiver) external onlyBundler3 {
        if (amount == type(uint256).max) amount = WRAPPED_NATIVE.balanceOf(address(this));

        require(amount != 0, ErrorsLib.ZeroAmount());

        WRAPPED_NATIVE.withdraw(amount);
        if (receiver != address(this)) Address.sendValue(payable(receiver), amount);
    }

    /* INTERNAL FUNCTIONS */

    /// @dev Triggers `_multicall` logic during a callback.
    function morphoCallback(bytes calldata data) internal {
        require(msg.sender == address(MORPHO), ErrorsLib.UnauthorizedSender());
        // No need to approve Morpho to pull tokens because it should already be approved max.

        reenterBundler3(data);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
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

## Briefing del Dominio (trust)
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
    // nunca push tokens a usuarios en flujos críticos — usar pull pattern
    // mapping(address => uint256) public claimable;
    // function claim() external { ... token.safeTransfer(msg.sender, amount); }
  que_mirar:

## GREP TARGETS
```yaml
- id: tb-004
  titulo: Tokens rebasing (aToken, stETH) rompen contabilidad si se cachea el balance
  causa_raiz: |
    Tokens como aToken de Aave o stETH de Lido incrementan su balance automáticamente
    con el tiempo (rebasing positivo) sin emitir Transfer events. Si el contrato cachea
    el balance en storage en vez de llamar a balanceOf() cada vez, el valor cacheado
    queda desactualizado → underestima activos → shares sobreemitidas o pérdida de yield.
  como_funciona: |
    1. Vault deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea balance=1000.
    2. 30 días pasan: balance real de aUSDC = 1050 (5% yield).
    3. totalAssets() retorna 1000 en vez de 1050 → pricePerShare subestimado.
    4. Usuario que deposita en este momento recibe shares de más → diluye a los existentes.
    5. Cuando alguien hace harvest, los 50 USDC "extra" aparecen como profit inesperado.
  invariante: |

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Access control) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `GA` (ej: GA-01, GA-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_GeneralAdapter1_AccessHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: GA-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "GA-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
