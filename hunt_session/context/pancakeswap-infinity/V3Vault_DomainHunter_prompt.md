# DomainHunter — V3Vault Analysis

## Tu Identidad
Eres el **DomainHunter** del equipo de bug hunting de revert-lend.
Tu especialidad: **Protocol-specific invariants, cross-component interactions, economic attacks**

## Tu Objetivo
Analizar `V3Vault` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/revert-lend/src/V3Vault.sol`
**Dominio**: vault
⚠ CONTRATO TRUNCADO: se muestran los primeros 60,000 chars. Usa el Read tool en /home/kali/Documents/Web3/revert-lend/src/V3Vault.sol para leer el resto.

## Asset Flow Map
### Money IN (deposits/receives)
- L388 create(): nonfungiblePositionManager.safeTransferFrom(msg.sender, address(this), tokenId, abi.encode(recipient));
- L811 remove(): nonfungiblePositionManager.safeTransferFrom(address(this), recipient, tokenId, data);
- L1060 _pullAssetFromSender(): SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), assets);

### Money OUT (withdrawals/sends)
- L637 borrow(): SafeERC20.safeTransfer(IERC20(asset), msg.sender, assets);
- L835 withdrawReserves(): SafeERC20.safeTransfer(IERC20(asset), receiver, amount);
- L998 _withdraw(): SafeERC20.safeTransfer(IERC20(asset), receiver, assets);

### Approvals (attack surface)
- L542 _transform(): nonfungiblePositionManager.approve(transformer, tokenId);
- L567 _transform(): nonfungiblePositionManager.approve(address(0), newTokenId);
- L570 _transform(): try nonfungiblePositionManager.approve(address(0), tokenId) {} catch {}
- L1406 _stake(): nonfungiblePositionManager.approve(gaugeManager, tokenId);

### Minting/Burning
- L965 _deposit(): _mint(receiver, shares);
- L997 _withdraw(): _burn(owner, shares);

### Balance Reads (manipulation vectors)
- L221 lendInfo(): amount = _convertToAssets(balanceOf(account), newLendExchangeRateX96, Math.Rounding.Down);
- L288 totalAssets(): return IERC20(asset).balanceOf(address(this)) + debt;
- L1080 _maxWithdrawAssets(): uint256 ownerShareBalance = balanceOf(owner);
- L1095 _getBalanceAndReserves(): balance = IERC20(asset).balanceOf(address(this));
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "v3-core/interfaces/IUniswapV3Factory.sol";
import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-core/libraries/FullMath.sol";
import "v3-core/libraries/TickMath.sol";
import "v3-core/libraries/FixedPoint128.sol";

import "v3-periphery/libraries/LiquidityAmounts.sol";
import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";

import "./interfaces/IVault.sol";
import "./interfaces/IV3Oracle.sol";
import "./interfaces/IInterestRateModel.sol";
import "./interfaces/IGaugeManager.sol";
import "./utils/Constants.sol";

/// @title Revert Lend Vault for token lending / borrowing using Uniswap V3 LP positions as collateral
/// @notice The vault manages ONE ERC20 (eg. USDC) asset for lending / borrowing, but collateral positions can be composed of any 2 tokens configured each with a collateralFactor > 0
/// Vault implements IERC4626 Vault Standard and is itself a ERC20 which represent shares of total lending pool
contract V3Vault is ERC20, Multicall, Ownable2Step, IVault, IERC721Receiver, Constants {
    using Math for uint256;

    uint32 public constant MAX_COLLATERAL_FACTOR_X32 = 3_865_470_566; // floor(Q32 * 90 / 100)

    uint32 public constant MIN_LIQUIDATION_PENALTY_X32 = 85_899_345; // floor(Q32 * 2 / 100)
    uint32 public constant MAX_LIQUIDATION_PENALTY_X32 = 429_496_729; // floor(Q32 * 10 / 100)

    uint32 public constant MIN_RESERVE_PROTECTION_FACTOR_X32 = 42_949_672; // floor(Q32 / 100)

    uint32 public constant MAX_DAILY_LEND_INCREASE_X32 = 429_496_729; // floor(Q32 / 10)
    uint32 public constant MAX_DAILY_DEBT_INCREASE_X32 = 429_496_729; // floor(Q32 / 10)

    uint256 public constant BORROW_SAFETY_BUFFER_X32 = 4_080_218_931; // floor(Q32 * 95 / 100)

    /// @notice Uniswap v3 position manager
    INonfungiblePositionManager public immutable nonfungiblePositionManager;

    /// @notice Uniswap v3 factory
    IUniswapV3Factory public immutable factory;

    /// @notice interest rate model implementation
    IInterestRateModel public immutable interestRateModel;

    /// @notice oracle implementation
    IV3Oracle public immutable oracle;

    /// @notice underlying asset for lending / borrowing
    address public immutable override asset;

    /// @notice decimals of underlying token (are the same as ERC20 share token)
    uint8 private immutable assetDecimals;

    // events
    event ApprovedTransform(uint256 indexed tokenId, address owner, address target, bool isActive);

    event Add(uint256 indexed tokenId, address owner, uint256 oldTokenId); // when a token is added replacing another token - oldTokenId > 0
    event Remove(uint256 indexed tokenId, address owner, address recipient);

    event ExchangeRateUpdate(uint256 debtExchangeRateX96, uint256 lendExchangeRateX96);
    // Deposit and Withdraw events are defined in IERC4626
    event WithdrawCollateral(
        uint256 indexed tokenId, address owner, address recipient, uint128 liquidity, uint256 amount0, uint256 amount1
    );
    event Borrow(uint256 indexed tokenId, address owner, uint256 assets, uint256 shares);
    event Repay(uint256 indexed tokenId, address repayer, address owner, uint256 assets, uint256 shares);
    event Liquidate(
        uint256 indexed tokenId,
        address liquidator,
        address owner,
        uint256 value,
        uint256 cost,
        uint256 amount0,
        uint256 amount1,
        uint256 reserve,
        uint256 missing
    ); // shows exactly how liquidation amounts were divided

    // admin events
    event WithdrawReserves(uint256 amount, address receiver);
    event SetTransformer(address transformer, bool active);
    event SetLimits(
        uint256 minLoanSize,
        uint256 globalLendLimit,
        uint256 globalDebtLimit,
        uint256 dailyLendIncreaseLimitMin,
        uint256 dailyDebtIncreaseLimitMin
    );
    event SetReserveFactor(uint32 reserveFactorX32);
    event SetReserveProtectionFactor(uint32 reserveProtectionFactorX32);
    event SetTokenConfig(address token, uint32 collateralFactorX32, uint32 collateralValueLimitFactorX32);

    event SetEmergencyAdmin(address emergencyAdmin);
    event SetGaugeManager(address indexed gaugeManager);

    // configured tokens
    struct TokenConfig {
        uint32 collateralFactorX32; // how much this token is valued as collateral
        uint32 collateralValueLimitFactorX32; // how much asset equivalent may be lent out given this collateral
        uint192 totalDebtShares; // how much debt shares are theoretically backed by this collateral
    }

    mapping(address => TokenConfig) public tokenConfigs;

    // total of debt shares - increases when borrow - decreases when repay
    uint256 public debtSharesTotal;

    // exchange rates are Q96 at the beginning - 1 share token per 1 asset token
    uint256 public lastDebtExchangeRateX96 = Q96;
    uint256 public lastLendExchangeRateX96 = Q96;

    uint256 public globalDebtLimit;
    uint256 public globalLendLimit;

    // minimal size of loan (to protect from non-liquidatable positions because of gas-cost)
    uint256 public minLoanSize;

    // daily lend increase limit handling
    uint256 public dailyLendIncreaseLimitMin;
    uint256 public dailyLendIncreaseLimitLeft;

    // daily debt increase limit handling
    uint256 public dailyDebtIncreaseLimitMin;
    uint256 public dailyDebtIncreaseLimitLeft;

    // lender balances are handled with ERC-20 mint/burn

    // loans are handled with this struct
    struct Loan {
        uint256 debtShares;
    }

    mapping(uint256 => Loan) public override loans; // tokenID -> loan mapping

    // storage variables to handle enumerable token ownership
    mapping(address => uint256[]) private ownedTokens; // Mapping from owner address to list of owned token IDs
    mapping(uint256 => uint256) private ownedTokensIndex; // Mapping from token ID to index of the owner tokens list (for removal without loop)
    mapping(uint256 => address) private tokenOwner; // Mapping from token ID to owner

    // transform-mode sentinel. Intentionally used instead of a global nonReentrant modifier so trusted transformers
    // can call back into borrow() for the same token during transform in a single transaction.
    uint256 public override transformedTokenId; // stores currently transformed token (is always reset to 0 after tx)

    mapping(address => bool) public transformerAllowList; // contracts allowed to transform positions (selected audited contracts e.g. V3Utils)
    mapping(address => mapping(uint256 => mapping(address => bool))) public transformApprovals; // owners permissions for other addresses to call transform on owners behalf (e.g. AutoRangeAndCompound contract)

    // last time exchange rate was updated
    uint64 public lastExchangeRateUpdate;

    // percentage of interest which is kept in the protocol for reserves
    uint32 public reserveFactorX32;

    // percentage of lend amount which needs to be in reserves before withdrawn
    uint32 public reserveProtectionFactorX32 = MIN_RESERVE_PROTECTION_FACTOR_X32;

    // when limits where last reset
    uint32 public dailyLendIncreaseLimitLastReset;
    uint32 public dailyDebtIncreaseLimitLastReset;

    // address which can call special emergency actions without timelock
    address public emergencyAdmin;
    address public gaugeManager;

    constructor(
        string memory name,
        string memory symbol,
        address _asset,
        INonfungiblePositionManager _nonfungiblePositionManager,
        IInterestRateModel _interestRateModel,
        IV3Oracle _oracle
    ) ERC20(name, symbol) {
        asset = _asset;
        assetDecimals = IERC20Metadata(_asset).decimals();
        nonfungiblePositionManager = _nonfungiblePositionManager;
        factory = IUniswapV3Factory(_nonfungiblePositionManager.factory());
        interestRateModel = _interestRateModel;
        oracle = _oracle;
    }

    ////////////////// EXTERNAL VIEW FUNCTIONS

    /// @notice Retrieves global information about the vault
    /// @return debt Total amount of debt asset tokens
    /// @return lent Total amount of lent asset tokens
    /// @return balance Balance of asset token in contract
    /// @return reserves Amount of reserves
    function vaultInfo()
        external
        view
        override
        returns (
            uint256 debt,
            uint256 lent,
            uint256 balance,
            uint256 reserves,
            uint256 debtExchangeRateX96,
            uint256 lendExchangeRateX96
        )
    {
        (debtExchangeRateX96, lendExchangeRateX96) = _calculateGlobalInterest();
        (balance, reserves) = _getBalanceAndReserves(debtExchangeRateX96, lendExchangeRateX96);

        debt = _convertToAssets(debtSharesTotal, debtExchangeRateX96, Math.Rounding.Up);
        lent = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @notice Retrieves lending information for a specified account.
    /// @param account The address of the account for which lending info is requested.
    /// @return amount Amount of lent assets for the account
    function lendInfo(address account) external view override returns (uint256 amount) {
        (, uint256 newLendExchangeRateX96) = _calculateGlobalInterest();
        amount = _convertToAssets(balanceOf(account), newLendExchangeRateX96, Math.Rounding.Down);
    }

    /// @notice Retrieves details of a loan identified by its token ID.
    /// @param tokenId The unique identifier of the loan - which is the corresponding UniV3 Position
    /// @return debt Amount of debt for this position
    /// @return fullValue Current value of the position priced as asset token
    /// @return collateralValue Current collateral value of the position priced as asset token
    /// @return liquidationCost If position is liquidatable - cost to liquidate position - otherwise 0
    /// @return liquidationValue If position is liquidatable - the value of the (partial) position which the liquidator recieves - otherwise 0
    function loanInfo(uint256 tokenId)
        public
        view
        override
        returns (
            uint256 debt,
            uint256 fullValue,
            uint256 collateralValue,
            uint256 liquidationCost,
            uint256 liquidationValue
        )
    {
        (uint256 newDebtExchangeRateX96,) = _calculateGlobalInterest();

        debt = _convertToAssets(loans[tokenId].debtShares, newDebtExchangeRateX96, Math.Rounding.Up);

        bool isHealthy;
        (isHealthy, fullValue, collateralValue,) = _checkLoanIsHealthy(tokenId, debt, false);

        if (!isHealthy) {
            (liquidationValue, liquidationCost,) = _calculateLiquidation(debt, fullValue, collateralValue);
        }
    }

    /// @notice Retrieves owner of a loan
    /// @param tokenId The unique identifier of the loan - which is the corresponding UniV3 Position
    /// @return owner Owner of the loan
    function ownerOf(uint256 tokenId) external view override returns (address owner) {
        return tokenOwner[tokenId];
    }

    /// @notice Retrieves count of loans for owner (for enumerating owners loans)
    /// @param owner Owner address
    function loanCount(address owner) external view override returns (uint256) {
        return ownedTokens[owner].length;
    }

    /// @notice Retrieves tokenid of loan at given index for owner (for enumerating owners loans)
    /// @param owner Owner address
    /// @param index Index
    function loanAtIndex(address owner, uint256 index) external view override returns (uint256) {
        return ownedTokens[owner][index];
    }

    ////////////////// OVERRIDDEN EXTERNAL VIEW FUNCTIONS FROM ERC20
    /// @inheritdoc IERC20Metadata
    function decimals() public view override(IERC20Metadata, ERC20) returns (uint8) {
        return assetDecimals;
    }

    ////////////////// OVERRIDDEN EXTERNAL VIEW FUNCTIONS FROM ERC4626

    /// @inheritdoc IERC4626
    function totalAssets() external view override returns (uint256) {
        (uint256 debtExchangeRateX96,) = _calculateGlobalInterest();
        // Round debt up to avoid understating liabilities in share pricing/accounting.
        uint256 debt = _convertToAssets(debtSharesTotal, debtExchangeRateX96, Math.Rounding.Up);
        return IERC20(asset).balanceOf(address(this)) + debt;
    }

    /// @inheritdoc IERC4626
    function convertToShares(uint256 assets) external view override returns (uint256 shares) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToShares(assets, lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @inheritdoc IERC4626
    function convertToAssets(uint256 shares) external view override returns (uint256 assets) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToAssets(shares, lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @inheritdoc IERC4626
    function maxDeposit(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _maxDepositAssets(lendExchangeRateX96);
    }

    /// @inheritdoc IERC4626
    function maxMint(address) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        uint256 maxGlobalDeposit = _maxDepositAssets(lendExchangeRateX96);
        return _convertToShares(maxGlobalDeposit, lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @inheritdoc IERC4626
    function maxWithdraw(address owner) external view override returns (uint256) {
        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _maxWithdrawAssets(owner, debtExchangeRateX96, lendExchangeRateX96);
    }

    /// @inheritdoc IERC4626
    function maxRedeem(address owner) external view override returns (uint256) {
        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        uint256 assets = _maxWithdrawAssets(owner, debtExchangeRateX96, lendExchangeRateX96);
        return _convertToShares(assets, lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @inheritdoc IERC4626
    function previewDeposit(uint256 assets) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToShares(assets, lendExchangeRateX96, Math.Rounding.Down);
    }

    /// @inheritdoc IERC4626
    function previewMint(uint256 shares) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToAssets(shares, lendExchangeRateX96, Math.Rounding.Up);
    }

    /// @inheritdoc IERC4626
    function previewWithdraw(uint256 assets) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToShares(assets, lendExchangeRateX96, Math.Rounding.Up);
    }

    /// @inheritdoc IERC4626
    function previewRedeem(uint256 shares) external view override returns (uint256) {
        (, uint256 lendExchangeRateX96) = _calculateGlobalInterest();
        return _convertToAssets(shares, lendExchangeRateX96, Math.Rounding.Down);
    }

    ////////////////// OVERRIDDEN EXTERNAL FUNCTIONS FROM ERC4626

    /// @inheritdoc IERC4626
    function deposit(uint256 assets, address receiver) external override returns (uint256) {
        (, uint256 shares) = _deposit(receiver, assets, false);
        return shares;
    }

    /// @inheritdoc IERC4626
    function mint(uint256 shares, address receiver) external override returns (uint256) {
        (uint256 assets,) = _deposit(receiver, shares, true);
        return assets;
    }

    /// @inheritdoc IERC4626
    function withdraw(uint256 assets, address receiver, address owner) external override returns (uint256) {
        (, uint256 shares) = _withdraw(receiver, owner, assets, false);
        return shares;
    }

    /// @inheritdoc IERC4626
    function redeem(uint256 shares, address receiver, address owner) external override returns (uint256) {
        (uint256 assets,) = _withdraw(receiver, owner, shares, true);
        return assets;
    }

    ////////////////// EXTERNAL FUNCTIONS

    /// @notice Creates a new collateralized position (transfer approved position)
    /// @param tokenId The token ID associated with the new position.
    /// @param recipient Address to recieve the position in the vault
    function create(uint256 tokenId, address recipient) external override {
        if (recipient == address(0)) {
            revert InvalidConfig();
        }
        nonfungiblePositionManager.safeTransferFrom(msg.sender, address(this), tokenId, abi.encode(recipient));
    }

    /// @notice Whenever a token is recieved it either creates a new loan, or modifies an existing one when in transform mode.
    /// @inheritdoc IERC721Receiver
    function onERC721Received(
        address,
        /*operator*/
        address from,
        uint256 tokenId,
        bytes calldata data
    )
        external
        override
        returns (bytes4)
    {
        // only Uniswap v3 NFTs allowed - sent from other contract
        if (msg.sender != address(nonfungiblePositionManager) || from == address(this)) {
            revert WrongContract();
        }

        (uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) = _updateGlobalInterest();

        uint256 oldTokenId = transformedTokenId;

        if (oldTokenId == 0) {
            // New deposit path.
            if (tokenOwner[tokenId] == address(0)) {
                address owner = from;
                if (data.length != 0) {
                    // NOTE FOR AUDITS:
                    // Raw ERC721 deposits may override owner via callback data.
                    // This is intentionally flexible for integrator/operator flows and is an accepted trust assumption:
                    // whoever can trigger safeTransferFrom for the NFT can also choose the callback payload.
                    owner = abi.decode(data, (address));
                }
                if (owner == address(0)) {
                    revert InvalidConfig();
                }
                loans[tokenId] = Loan(0);
                _addTokenToOwner(owner, tokenId);
                emit Add(tokenId, owner, 0);
            }
        } else {
            // NOTE FOR AUDITS:
            // We intentionally do not bind replacement-NFT migration to a specific operator contract here.
            // Some valid transformers route NFT moves through helper/proxy contracts, so strict operator pinning
            // would break supported integrations. Safety relies on transform-mode scoping + final custody checks.
            // if in transform mode - and a new position is sent - current position is replaced and returned
            if (tokenId != oldTokenId) {
                // Replacement migrations are only safe for freshly introduced tokenIds. Reusing a token that already
                // has vault ownership or debt state would overwrite its live loan accounting.
                if (tokenOwner[tokenId] != address(0) || loans[tokenId].debtShares != 0) {
                    revert Unauthorized();
                }

                address owner = tokenOwner[oldTokenId];

                // set transformed token to new one
                transformedTokenId = tokenId;

                uint256 debtShares = loans[oldTokenId].debtShares;

                // copy debt to new token
                loans[tokenId] = Loan(debtShares);

                _addTokenToOwner(owner, tokenId);
                emit Add(tokenId, owner, oldTokenId);

                // remove debt from old loan
                _cleanupLoan(oldTokenId, debtExchangeRateX96, lendExchangeRateX96);

                // sets data of new loan
                _updateAndCheckCollateral(tokenId, debtExchangeRateX96, lendExchangeRateX96, 0, debtShares);
            }
        }

        return IERC721Receiver.onERC721Received.selector;
    }

    /// @notice Allows another address to call transform on behalf of owner (on a given token)
    /// @param tokenId The token to be permitted
    /// @param target The address to be allowed
    /// @param isActive If it allowed or not
    function approveTransform(uint256 tokenId, address target, bool isActive) external override {
        if (tokenOwner[tokenId] != msg.sender) {
            revert Unauthorized();
        }
        transformApprovals[msg.sender][tokenId][target] = isActive;
        emit ApprovedTransform(tokenId, msg.sender, target, isActive);
    }

    function transform(uint256 tokenId, address transformer, bytes calldata data)
        external
        override
        returns (uint256 newTokenId)
    {
        return _transform(tokenId, transformer, data, false, 0, 0, 0);
    }

    function transformWithRewardCompound(
        uint256 tokenId,
        address transformer,
        bytes calldata data,
        RewardCompoundParams calldata rewardParams
    ) external override returns (uint256 newTokenId) {
        return _transform(
            tokenId,
            transformer,
            data,
            true,
            rewardParams.minAeroReward,
            rewardParams.aeroSplitBps,
            rewardParams.deadline
        );
    }

    function _transform(
        uint256 tokenId,
        address transformer,
        bytes calldata data,
        bool compoundRewardsFirst,
        uint256 minAeroReward,
        uint256 aeroSplitBps,
        uint256 deadline
    ) internal returns (uint256 newTokenId) {
        if (tokenId == 0 || !transformerAllowList[transformer]) {
            revert TransformNotAllowed();
        }
        if (transformedTokenId != 0) {
            revert Reentrancy();
        }
        // Enter scoped transform mode and block unrelated state-changing paths until reset below.
        transformedTokenId = tokenId;

        (uint256 newDebtExchangeRateX96,) = _updateGlobalInterest();

        address loanOwner = tokenOwner[tokenId];

        // only the owner of the loan or any approved caller can call this
        if (loanOwner != msg.sender && !transformApprovals[loanOwner][tokenId][msg.sender]) {
            revert Unauthorized();
        }

        if (
            compoundRewardsFirst && gaugeManager != address(0)
                && IGaugeManager(gaugeManager).tokenIdToGauge(tokenId) != address(0)
        ) {
            IGaugeManager(gaugeManager).compoundRewards(tokenId, minAeroReward, aeroSplitBps, deadline);
        }

        bool wasStaked = _unstakeIfNeeded(tokenId);

        // give access to transformer
        nonfungiblePositionManager.approve(transformer, tokenId);

        (bool success,) = transformer.call(data);
        if (!success) {
            revert TransformFailed();
        }

        // may have changed in the meantime
        newTokenId = transformedTokenId;

        // if token has changed - and operator was approved for old token - take over for new token
        if (tokenId != newTokenId && transformApprovals[loanOwner][tokenId][msg.sender]) {
            transformApprovals[loanOwner][newTokenId][msg.sender] = true;
            delete transformApprovals[loanOwner][tokenId][msg.sender];
        }

        // NOTE FOR AUDITS:
        // No operator-pinning is enforced by design for transformer flexibility; custody is enforced here.
        // check owner not changed (NEEDED because token could have been moved somewhere else in the meantime)
        address owner = nonfungiblePositionManager.ownerOf(newTokenId);
        if (owner != address(this)) {
            revert Unauthorized();
        }

        // remove access for transformer
        nonfungiblePositionManager.approve(address(0), newTokenId);
        if (tokenId != newTokenId) {
            // old token may be burned during transform; clear approval best-effort
            try nonfungiblePositionManager.approve(address(0), tokenId) {} catch {}
        }

        uint256 debt = _convertToAssets(loans[newTokenId].debtShares, newDebtExchangeRateX96, Math.Rounding.Up);

        if (wasStaked) {
            // Re-check health in the final staked custody state because staking realizes pre-stake fees.
            _stake(newTokenId);
        }
        _requireLoanIsHealthy(newTokenId, debt);

        transformedTokenId = 0;
    }

    /// @notice Borrows specified amount using token as collateral
    /// @param tokenId The token ID to use as collateral
    /// @param assets How much assets to borrow
    function borrow(uint256 tokenId, uint256 assets) external override {
        // Allowed callback path: transform() -> allowed transformer -> borrow() for the same tokenId.
        bool isTransformMode = tokenId != 0 && transformedTokenId == tokenId && transformerAllowList[msg.sender];

        address owner = tokenOwner[tokenId];

        // if not in transform mode - must be called from owner
        if (!isTransformMode && owner != msg.sender) {
            revert Unauthorized();
        }

        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

        _resetDailyDebtIncreaseLimit(newLendExchangeRateX96, false);

        Loan storage loan = loans[tokenId];

        uint256 shares = _convertToShares(assets, newDebtExchangeRateX96, Math.Rounding.Up);

        uint256 loanDebtShares = loan.debtShares + shares;
        loan.debtShares = loanDebtShares;
        debtSharesTotal = debtSharesTotal + shares;

        if (debtSharesTotal > _convertToShares(globalDebtLimit, newDebtExchangeRateX96, Math.Rounding.Down)) {
            revert GlobalDebtLimit();
        }
        if (assets > dailyDebtIncreaseLimitLeft) {
            revert DailyDebtIncreaseLimit();
        } else {
            dailyDebtIncreaseLimitLeft = dailyDebtIncreaseLimitLeft - assets;
        }

        _updateAndCheckCollateral(
            tokenId, newDebtExchangeRateX96, newLendExchangeRateX96, loanDebtShares - shares, loanDebtShares
        );

        uint256 debt = _convertToAssets(loanDebtShares, newDebtExchangeRateX96, Math.Rounding.Up);

        if (debt < minLoanSize) {
            revert MinLoanSize();
        }

        // only does check health here if not in transform mode
        if (!isTransformMode) {
            _requireLoanIsHealthy(tokenId, debt);
        }

        // fails if not enough asset available
        // it may use all balance of the contract (because "virtual" reserves do not need to be stored in contract)
        // if called from transform mode - send funds to transformer contract
        SafeERC20.safeTransfer(IERC20(asset), msg.sender, assets);

        emit Borrow(tokenId, owner, assets, shares);
    }

    function decreaseLiquidityAndCollect(DecreaseLiquidityAndCollectParams calldata params)
        external
        override
        returns (uint256 amount0, uint256 amount1)
    {
        // this method is not allowed during transform - can be called directly on nftmanager if needed from transform contract
        if (transformedTokenId != 0) {
            revert TransformNotAllowed();
        }

        address owner = tokenOwner[params.tokenId];

        if (owner != msg.sender) {
            revert Unauthorized();
        }

        bool wasStaked = _unstakeIfNeeded(params.tokenId);

        (uint256 newDebtExchangeRateX96,) = _updateGlobalInterest();

        if (params.liquidity != 0) {
            (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(
                INonfungiblePositionManager.DecreaseLiquidityParams(
                    params.tokenId, params.liquidity, params.amount0Min, params.amount1Min, params.deadline
                )
            );
        }

        INonfungiblePositionManager.CollectParams memory collectParams = INonfungiblePositionManager.CollectParams(
            params.tokenId,
            params.recipient,
            params.feeAmount0 == type(uint128).max
                ? type(uint128).max
                : SafeCast.toUint128(amount0 + params.feeAmount0),
            params.feeAmount1 == type(uint128).max ? type(uint128).max : SafeCast.toUint128(amount1 + params.feeAmount1)
        );

        (amount0, amount1) = nonfungiblePositionManager.collect(collectParams);

        if (wasStaked) {
            // Re-check health in the final staked custody state because staking realizes pre-stake fees.
            _stake(params.tokenId);
        }

        uint256 debt = _convertToAssets(loans[params.tokenId].debtShares, newDebtExchangeRateX96, Math.Rounding.Up);
        _requireLoanIsHealthy(params.tokenId, debt);

        emit WithdrawCollateral(params.tokenId, owner, params.recipient, params.liquidity, amount0, amount1);
    }

    /// @notice Repays borrowed tokens. Can be denominated in assets or debt share amount
    /// @param tokenId The token ID to use as collateral
    /// @param amount How many assets/debt shares to repay
    /// @param isShare Is amount specified in assets or debt shares.
    /// @return assets The amount of the assets repayed
    /// @return shares The amount of the shares repayed
    function repay(uint256 tokenId, uint256 amount, bool isShare)
        external
        override
        returns (uint256 assets, uint256 shares)
    {
        (assets, shares) = _repay(tokenId, amount, isShare);
    }

    // state used in liquidation function to avoid stack too deep errors
    struct LiquidateState {
        uint256 newDebtExchangeRateX96;
        uint256 newLendExchangeRateX96;
        uint256 debt;
        bool isHealthy;
        uint256 liquidationValue;
        uint256 liquidatorCost;
        uint256 reserveCost;
        uint256 missing;
        uint256 fullValue;
        uint256 collateralValue;
        uint256 feeValue;
    }

    /// @notice Liquidates position - needed assets are depending on current price.
    /// Sufficient assets need to be approved to the contract for the liquidation to succeed.
    /// @param params The params defining liquidation
    /// @return amount0 The amount of the first type of asset collected.
    /// @return amount1 The amount of the second type of asset collected.
    function liquidate(LiquidateParams calldata params) external override returns (uint256 amount0, uint256 amount1) {
        // liquidation is not allowed during transformer mode
        if (transformedTokenId != 0) {
            revert TransformNotAllowed();
        }

        LiquidateState memory state;

        (state.newDebtExchangeRateX96, state.newLendExchangeRateX96) = _updateGlobalInterest();

        _resetDailyDebtIncreaseLimit(state.newLendExchangeRateX96, false);

        uint256 debtShares = loans[params.tokenId].debtShares;

        state.debt = _convertToAssets(debtShares, state.newDebtExchangeRateX96, Math.Rounding.Up);

        (state.isHealthy, state.fullValue, state.collateralValue, state.feeValue) =
            _checkLoanIsHealthy(params.tokenId, state.debt, false);
        if (state.isHealthy) {
            revert NotLiquidatable();
        }

        _unstakeIfNeeded(params.tokenId);

        (state.liquidationValue, state.liquidatorCost, state.reserveCost) =
            _calculateLiquidation(state.debt, state.fullValue, state.collateralValue);

        // calculate reserve (before transfering liquidation money - otherwise calculation is off)
        if (state.reserveCost != 0) {
            state.missing = _handleReserveLiquidation(
                state.reserveCost, state.newDebtExchangeRateX96, state.newLendExchangeRateX96
            );
        }

        if (state.liquidatorCost != 0) {
            _pullAssetFromSender(state.liquidatorCost);
        }

        debtSharesTotal = debtSharesTotal - debtShares;

        // Replenish daily borrow headroom only by assets actually paid into the vault.
        dailyDebtIncreaseLimitLeft = dailyDebtIncreaseLimitLeft + state.liquidatorCost;

        // send promised collateral tokens to liquidator
        (amount0, amount1) = _sendPositionValue(
            params.tokenId, state.liquidationValue, state.fullValue, state.feeValue, params.recipient, params.deadline
        );

        if (amount0 < params.amount0Min || amount1 < params.amount1Min) {
            revert SlippageError();
        }

        // remove debt from loan
        _cleanupLoan(params.tokenId, state.newDebtExchangeRateX96, state.newLendExchangeRateX96);

        emit Liquidate(
            params.tokenId,
            msg.sender,
            tokenOwner[params.tokenId],
            state.fullValue,
            state.liquidatorCost,
            amount0,
            amount1,
            state.reserveCost,
            state.missing
        );
    }

    /// @notice Removes position from the vault (only possible when all repayed)
    /// @param tokenId The token ID to use as collateral
    /// @param recipient Address to recieve NFT
    /// @param data Optional data to send to reciever
    function remove(uint256 tokenId, address recipient, bytes calldata data) external {
        address owner = tokenOwner[tokenId];
        if (owner != msg.sender) {
            revert Unauthorized();
        }

        if (loans[tokenId].debtShares != 0) {
            revert NeedsRepay();
        }

        _unstakeIfNeeded(tokenId);

        _removeTokenFromOwner(owner, tokenId);
        nonfungiblePositionManager.safeTransferFrom(address(this), recipient, tokenId, data);
        emit Remove(tokenId, owner, recipient);
    }

    ////////////////// ADMIN FUNCTIONS only callable by owner

    /// @notice withdraw protocol reserves (onlyOwner)
    /// only allows to withdraw excess reserves (> globalLendAmount * reserveProtectionFactor)
    /// @param amount amount to withdraw
    /// @param receiver receiver address
    function withdrawReserves(uint256 amount, address receiver) external onlyOwner {
        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

        uint256 protected = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up)
            * reserveProtectionFactorX32 / Q32;
        (uint256 balance, uint256 reserves) = _getBalanceAndReserves(newDebtExchangeRateX96, newLendExchangeRateX96);
        uint256 unprotected = reserves > protected ? reserves - protected : 0;
        uint256 available = balance > unprotected ? unprotected : balance;

        if (amount > available) {
            revert InsufficientLiquidity();
        }

        if (amount != 0) {
            SafeERC20.safeTransfer(IERC20(asset), receiver, amount);
        }

        emit WithdrawReserves(amount, receiver);
    }

    /// @notice configure transformer contract (onlyOwner)
    /// @param transformer address of transformer contract
    /// @param active should the transformer be active?
    function setTransformer(address transformer, bool active) external onlyOwner {
        // protects protocol from owner trying to set dangerous transformer
        if (
            transformer == address(0) || transformer == address(this) || transformer == asset
                || transformer == address(nonfungiblePositionManager)
        ) {
            revert InvalidConfig();
        }

        transformerAllowList[transformer] = active;
        emit SetTransformer(transformer, active);
    }

    /// @notice set limits (this doesnt affect existing loans) - this method can be called by owner OR emergencyAdmin
    /// @param _minLoanSize min size of a loan - trying to create smaller loans will revert
    /// @param _globalLendLimit global limit of lent amount
    /// @param _globalDebtLimit global limit of debt amount
    /// @param _dailyLendIncreaseLimitMin min daily increasable amount of lent amount
    /// @param _dailyDebtIncreaseLimitMin min daily increasable amount of debt amount
    function setLimits(
        uint256 _minLoanSize,
        uint256 _globalLendLimit,
        uint256 _globalDebtLimit,
        uint256 _dailyLendIncreaseLimitMin,
        uint256 _dailyDebtIncreaseLimitMin
    ) external {
        if (msg.sender != emergencyAdmin && msg.sender != owner()) {
            revert Unauthorized();
        }

        minLoanSize = _minLoanSize;
        globalLendLimit = _globalLendLimit;
        globalDebtLimit = _globalDebtLimit;
        dailyLendIncreaseLimitMin = _dailyLendIncreaseLimitMin;
        dailyDebtIncreaseLimitMin = _dailyDebtIncreaseLimitMin;

        (, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

        // force reset daily limits with new values
        _resetDailyLendIncreaseLimit(newLendExchangeRateX96, true);
        _resetDailyDebtIncreaseLimit(newLendExchangeRateX96, true);

        emit SetLimits(
            _minLoanSize, _globalLendLimit, _globalDebtLimit, _dailyLendIncreaseLimitMin, _dailyDebtIncreaseLimitMin
        );
    }

    /// @notice sets reserve factor - percentage difference between debt and lend interest (onlyOwner)
    /// @param _reserveFactorX32 reserve factor multiplied by Q32
    function setReserveFactor(uint32 _reserveFactorX32) external onlyOwner {
        // _reserveFactorX32 is uint32, while Q32 == 2^32. Therefore reserveFactorX32 <= Q32 - 1 by type,
        // and Q32 - reserveFactorX32 in _calculateGlobalInterest() cannot underflow.
        // update interest to be sure that reservefactor change is applied from now on
        _updateGlobalInterest();
        reserveFactorX32 = _reserveFactorX32;
        emit SetReserveFactor(_reserveFactorX32);
    }

    /// @notice sets reserve protection factor - percentage of globalLendAmount which can't be withdrawn by owner (onlyOwner)
    /// @param _reserveProtectionFactorX32 reserve protection factor multiplied by Q32
    function setReserveProtectionFactor(uint32 _reserveProtectionFactorX32) external onlyOwner {
        if (_reserveProtectionFactorX32 < MIN_RESERVE_PROTECTION_FACTOR_X32) {
            revert InvalidConfig();
        }
        reserveProtectionFactorX32 = _reserveProtectionFactorX32;
        emit SetReserveProtectionFactor(_reserveProtectionFactorX32);
    }

    /// @notice Sets or updates the configuration for a token (onlyOwner)
    /// @param token Token to configure
    /// @param collateralFactorX32 collateral factor for this token mutiplied by Q32
    /// @param collateralValueLimitFactorX32 how much of it maybe used as collateral measured as percentage of total lent assets mutiplied by Q32
    function setTokenConfig(address token, uint32 collateralFactorX32, uint32 collateralValueLimitFactorX32)
        external
        onlyOwner
    {
        if (collateralFactorX32 > MAX_COLLATERAL_FACTOR_X32) {
            revert CollateralFactorExceedsMax();
        }
        TokenConfig storage config = tokenConfigs[token];
        config.collateralFactorX32 = collateralFactorX32;
        config.collateralValueLimitFactorX32 = collateralValueLimitFactorX32;
        emit SetTokenConfig(token, collateralFactorX32, collateralValueLimitFactorX32);
    }

    /// @notice Updates emergency admin address (onlyOwner)
    /// @param admin Emergency admin address
    function setEmergencyAdmin(address admin) external onlyOwner {
        emergencyAdmin = admin;
        emit SetEmergencyAdmin(admin);
    }

    ////////////////// INTERNAL FUNCTIONS

    function _deposit(address receiver, uint256 amount, bool isShare)
        internal
        returns (uint256 assets, uint256 shares)
    {
        (, uint256 newLendExchangeRateX96) = _updateGlobalInterest();

        _resetDailyLendIncreaseLimit(newLendExchangeRateX96, false);

        if (isShare) {
            shares = amount;
            assets = _convertToAssets(shares, newLendExchangeRateX96, Math.Rounding.Up);
        } else {
            assets = amount;
            shares = _convertToShares(assets, newLendExchangeRateX96, Math.Rounding.Down);
        }

        uint256 newTotalAssets = _convertToAssets(totalSupply() + shares, newLendExchangeRateX96, Math.Rounding.Up);
        if (newTotalAssets > globalLendLimit) {
            revert GlobalLendLimit();
        }
        if (assets > dailyLendIncreaseLimitLeft) {
            revert DailyLendIncreaseLimit();
        }

        dailyLendIncreaseLimitLeft = dailyLendIncreaseLimitLeft - assets;
        _pullAssetFromSender(assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // withdraws lent tokens. can be denominated in token or share amount
    function _withdraw(address receiver, address owner, uint256 amount, bool isShare)
        internal
        returns (uint256 assets, uint256 shares)
    {
        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();
        _resetDailyLendIncreaseLimit(newLendExchangeRateX96, false);

        if (isShare) {
            shares = amount;
            assets = _convertToAssets(amount, newLendExchangeRateX96, Math.Rounding.Down);
        } else {
            assets = amount;
            shares = _convertToShares(amount, newLendExchangeRateX96, Math.Rounding.Up);
        }

        // if caller has allowance for owners shares - may call withdraw
        if (msg.sender != owner) {
            _spendAllowance(owner, msg.sender, shares);
        }

        (uint256 balance,) = _getBalanceAndReserves(newDebtExchangeRateX96, newLendExchangeRateX96);
        if (balance < assets) {
            revert InsufficientLiquidity();
        }

        // fails if not enough shares
        _burn(owner, shares);
        SafeERC20.safeTransfer(IERC20(asset), receiver, assets);

        // when amounts are withdrawn - they may be deposited again
        dailyLendIncreaseLimitLeft = dailyLendIncreaseLimitLeft + assets;

        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function _repay(uint256 tokenId, uint256 amount, bool isShare) internal returns (uint256 assets, uint256 shares) {
        (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) = _updateGlobalInterest();
        _resetDailyDebtIncreaseLimit(newLendExchangeRateX96, false);

        Loan storage loan = loans[tokenId];

        uint256 currentShares = loan.debtShares;

        if (isShare) {
            shares = amount;
            assets = _convertToAssets(amount, newDebtExchangeRateX96, Math.Rounding.Up);
        } else {
            assets = amount;
            shares = _convertToShares(amount, newDebtExchangeRateX96, Math.Rounding.Down);
        }

        if (shares == 0) {
            revert NoSharesRepayed();
        }

        // if too much repayed - just set to max
        if (shares > currentShares) {
            shares = currentShares;
            assets = _convertToAssets(shares, newDebtExchangeRateX96, Math.Rounding.Up);
        }

        _pullAssetFromSender(assets);

        uint256 loanDebtShares = currentShares - shares;
        loan.debtShares = loanDebtShares;
        debtSharesTotal = debtSharesTotal - shares;

        // when amounts are repayed - they maybe borrowed again
        dailyDebtIncreaseLimitLeft = dailyDebtIncreaseLimitLeft + assets;

        _updateAndCheckCollateral(
            tokenId, newDebtExchangeRateX96, newLendExchangeRateX96, loanDebtShares + shares, loanDebtShares
        );

        // if not fully repayed - check for loan size
        if (currentShares != shares) {
            // if resulting loan is too small - revert
            if (_convertToAssets(loanDebtShares, newDebtExchangeRateX96, Math.Rounding.Up) < minLoanSize) {
                revert MinLoanSize();
            }
        }

        emit Repay(tokenId, msg.sender, tokenOwner[tokenId], assets, shares);
    }

    function _pullAssetFromSender(uint256 assets) internal {
        if (assets == 0) {
            return;
        }
        SafeERC20.safeTransferFrom(IERC20(asset), msg.sender, address(this), assets);
    }

    function _maxDepositAssets(uint256 lendExchangeRateX96) internal view returns (uint256) {
        uint256 value = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);
        if (value >= globalLendLimit) {
            return 0;
        }
        uint256 maxGlobalDeposit = globalLendLimit - value;
        if (maxGlobalDeposit > dailyLendIncreaseLimitLeft) {
            return dailyLendIncreaseLimitLeft;
        }
        return maxGlobalDeposit;
    }

    function _maxWithdrawAssets(address owner, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96)
        internal
        view
        returns (uint256)
    {
        uint256 ownerShareBalance = balanceOf(owner);
        uint256 ownerAssetBalance = _convertToAssets(ownerShareBalance, lendExchangeRateX96, Math.Rounding.Down);
        (uint256 balance,) = _getBalanceAndReserves(debtExchangeRateX96, lendExchangeRateX96);
        if (balance > ownerAssetBalance) {
            return ownerAssetBalance;
        }
        return balance;
    }

    // checks how much balance is available
    function _getBalanceAndReserves(uint256 debtExchangeRateX96, uint256 lendExchangeRateX96)
        internal
        view
        returns (uint256 balance, uint256 reserves)
    {
        balance = IERC20(asset).balanceOf(address(this));
        uint256 debt = _convertToAssets(debtSharesTotal, debtExchangeRateX96, Math.Rounding.Up);
        uint256 lent = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);
        reserves = balance + debt > lent ? balance + debt - lent : 0;
    }

    // removes correct amount from position to send to liquidator
    function _sendPositionValue(
        uint256 tokenId,
        uint256 liquidationValue,
        uint256 fullValue,
        uint256 feeValue,
        address recipient,
        uint256 deadline
    ) internal returns (uint256 amount0, uint256 amount1) {
        uint128 liquidity;
        uint128 fees0;
        uint128 fees1;

        // if full position is liquidated - no analysis needed
        if (liquidationValue == fullValue) {
            (,,,,,,, liquidity,,,,) = nonfungiblePositionManager.positions(tokenId);
            fees0 = type(uint128).max;
            fees1 = type(uint128).max;
        } else {
            (liquidity, fees0, fees1) = oracle.getLiquidityAndFees(tokenId);

            // only take needed fees
            if (liquidationValue <= feeValue) {
                liquidity = 0;
                fees0 = SafeCast.toUint128(liquidationValue * fees0 / feeValue);
                fees1 = SafeCast.toUint128(liquidationValue * fees1 / feeValue);
            } else {
                // take all fees and needed liquidity
                fees0 = type(uint128).max;
                fees1 = type(uint128).max;
                liquidity = SafeCast.toUint128((liquidationValue - feeValue) * liquidity / (fullValue - feeValue));
            }
        }

        if (liquidity != 0) {
            nonfungiblePositionManager.decreaseLiquidity(
                INonfungiblePositionManager.DecreaseLiquidityParams(tokenId, liquidity, 0, 0, deadline)
            );
        }

        (amount0, amount1) = nonfungiblePositionManager.collect(
            INonfungiblePositionManager.CollectParams(tokenId, recipient, fees0, fees1)
        );
    }

    // cleans up loan when it is closed because of replacement, repayment or liquidation
    // the position is kept in the contract, but can be removed with remove() method
    // because loanShares are 0
    function _cleanupLoan(uint256 tokenId, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96) internal {
        _updateAndCheckCollateral(tokenId, debtExchangeRateX96, lendExchangeRateX96, loans[tokenId].debtShares, 0);
        delete loans[tokenId];
    }

    // calculates amount which needs to be payed to liquidate position
    //  if position is too valuable - not all of the position is liquididated - only needed amount
    //  if position is not valuable enough - missing part is covered by reserves - if not enough reserves - collectively by other borrowers
    function _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue)
        internal
        pure
        returns (uint256 liquidationValue, uint256 liquidatorCost, uint256 reserveCost)
    {
        // in a standard liquidation - liquidator pays complete debt (and get part or all of position)
        // if position has less than enough value - liquidation cost maybe less - rest is payed by protocol or lenders collectively
        liquidatorCost = debt;

        // position value needed to pay debt at max penalty
        uint256 maxPenaltyValue = debt * (Q32 + MAX_LIQUIDATION_PENALTY_X32) / Q32;

        // if position is more valuable than debt with max penalty
        if (fullValue >= maxPenaltyValue) {
            if (collateralValue != 0) {
                // position value when position started to be liquidatable
                uint256 startLiquidationValue = debt * fullValue / collateralValue;
                uint256 penaltyFractionX96 =
                    (Q96 - ((fullValue - maxPenaltyValue) * Q96 / (startLiquidationValue - maxPenaltyValue)));
                uint256 penaltyX32 = MIN_LIQUIDATION_PENALTY_X32
                    + (MAX_LIQUIDATION_PENALTY_X32 - MIN_LIQUIDATION_PENALTY_X32) * penaltyFractionX96 / Q96;

                liquidationValue = debt * (Q32 + penaltyX32) / Q32;
            } else {
                liquidationValue = maxPenaltyValue;
            }
        } else {
            uint256 penalty = debt * MAX_LIQUIDATION_PENALTY_X32 / Q32;

            // if value is enough to pay penalty
            if (fullValue > penalty) {
                liquidatorCost = fullValue - penalty;
            } else {
                // this extreme case leads to free liquidation
                liquidatorCost = 0;
            }

            liquidationValue = fullValue;
            reserveCost = debt - liquidatorCost; // Remaining to pay is taken from reserves
        }
    }

    // calculates if there are enough reserves to cover liquidaton - if not its shared between lenders
    function _handleReserveLiquidation(
        uint256 reserveCost,
        uint256 newDebtExchangeRateX96,
        uint256 newLendExchangeRateX96
    ) internal returns (uint256 missing) {
        (, uint256 reserves) = _getBalanceAndReserves(newDebtExchangeRateX96, newLendExchangeRateX96);

        // if not enough - democratize debt
        if (reserveCost > reserves) {
            missing = reserveCost - reserves;

            uint256 totalLent = _convertToAssets(totalSupply(), newLendExchangeRateX96, Math.Rounding.Up);
            uint256 preHaircutDailyDebtCap =
                _calculateDailyIncreaseLimit(newLendExchangeRateX96, dailyDebtIncreaseLimitMin, MAX_DAILY_DEBT_INCREASE_X32);

            // this lines distribute missing amount and remove it from all lent amount proportionally
            newLendExchangeRateX96 = (totalLent - missing) * newLendExchangeRateX96 / totalLent;
            lastLendExchangeRateX96 = newLendExchangeRateX96;

            // A reserve socialization haircut reduces the lender base mid-day.
            // Rescale remaining daily debt headroom so it tracks the post-haircut cap while preserving already-used budget.
            uint256 postHaircutDailyDebtCap =
                _calculateDailyIncreaseLimit(newLendExchangeRateX96, dailyDebtIncreaseLimitMin, MAX_DAILY_DEBT_INCREASE_X32);
            if (
                dailyDebtIncreaseLimitLastReset == uint32(block.timestamp / 1 days)
                    && postHaircutDailyDebtCap < preHaircutDailyDebtCap
            ) {
                uint256 capReduction = preHaircutDailyDebtCap - postHaircutDailyDebtCap;
                dailyDebtIncreaseLimitLeft =
                    capReduction >= dailyDebtIncreaseLimitLeft ? 0 : dailyDebtIncreaseLimitLeft - capReduction;
            }

            emit ExchangeRateUpdate(newDebtExchangeRateX96, newLendExchangeRateX96);
        }
    }

    function _calculateTokenCollateralFactorX32(uint256 tokenId) internal view returns (uint32) {
        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(tokenId);
        uint32 factor0X32 = tokenConfigs[token0].collateralFactorX32;
        uint32 factor1X32 = tokenConfigs[token1].collateralFactorX32;
        return factor0X32 > factor1X32 ? factor1X32 : factor0X32;
    }

    function _updateGlobalInterest() internal returns (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96) {
        // only needs to be updated once per block (when needed)
        if (block.timestamp > lastExchangeRateUpdate) {
            (newDebtExchangeRateX96, newLendExchangeRateX96) = _calculateGlobalInterest();
            lastDebtExchangeRateX96 = newDebtExchangeRateX96;
            lastLendExchangeRateX96 = newLendExchangeRateX96;
            lastExchangeRateUpdate = uint64(block.timestamp); // never overflows in a loooooong time
            emit ExchangeRateUpdate(newDebtExchangeRateX96, newLendExchangeRateX96);
        } else {
            newDebtExchangeRateX96 = lastDebtExchangeRateX96;
            newLendExchangeRateX96 = lastLendExchangeRateX96;
        }
    }

    function _calculateGlobalInterest()
        internal
        view
        returns (uint256 newDebtExchangeRateX96, uint256 newLendExchangeRateX96)
    {
        uint256 oldDebtExchangeRateX96 = lastDebtExchangeRateX96;
        uint256 oldLendExchangeRateX96 = lastLendExchangeRateX96;

        // always growing or equal
        uint256 lastRateUpdate = lastExchangeRateUpdate;
        uint256 timeElapsed = (block.timestamp - lastRateUpdate);

        if (timeElapsed != 0 && lastRateUpdate != 0) {
            (uint256 balance,) = _getBalanceAndReserves(oldDebtExchangeRateX96, oldLendExchangeRateX96);
            uint256 debt = _convertToAssets(debtSharesTotal, oldDebtExchangeRateX96, Math.Rounding.Up);
            (uint256 borrowRateX64, uint256 supplyRateX64) = interestRateModel.getRatesPerSecondX64(balance, debt);
            // Safe by type bound documented in setReserveFactor(): reserveFactorX32 is always <= Q32 - 1.
            supplyRateX64 = supplyRateX64.mulDiv(Q32 - reserveFactorX32, Q32);

            newDebtExchangeRateX96 = oldDebtExchangeRateX96 + oldDebtExchangeRateX96 * timeElapsed * borrowRateX64 / Q64;
            newLendExchangeRateX96 = oldLendExchangeRateX96 + oldLendExchangeRateX96 * timeElapsed * supplyRateX64 / Q64;
        } else {
            newDebtExchangeRateX96 = oldDebtExchangeRateX96;
            newLendExchangeRateX96 = oldLendExchangeRateX96;
        }
    }

    function _requireLoanIsHealthy(uint256 tokenId, uint256 debt) internal view {
        (bool isHealthy,,,) = _checkLoanIsHealthy(tokenId, debt, true);
        if (!isHealthy) {
            revert CollateralFail();
        }
    }

    // updates collateral token configs - and check if limit is not surpassed (check is only done on increasing debt shares)
    function _updateAndCheckCollateral(
        uint256 tokenId,
        uint256 debtExchangeRateX96,
        uint256 lendExchangeRateX96,
        uint256 oldShares,
        uint256 newShares
    ) internal {
        if (oldShares != newShares) {
            (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(tokenId);

            // remove previous collateral - add new collateral
            if (oldShares > newShares) {
                uint192 difference = SafeCast.toUint192(oldShares - newShares);
                tokenConfigs[token0].totalDebtShares -= difference;
                tokenConfigs[token1].totalDebtShares -= difference;
            } else {
                uint192 difference = SafeCast.toUint192(newShares - oldShares);
                tokenConfigs[token0].totalDebtShares += difference;
                tokenConfigs[token1].totalDebtShares += difference;

                // check if current value of used collateral is more than allowed limit
                // if collateral is decreased - never revert
                uint256 lentAssets = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up);
                uint256 collateralValueLimitFactorX32 = tokenConfigs[token0].collateralValueLimitFactorX32;
                if (
                    collateralValueLimitFactorX32 < type(uint32).max
                        && _convertToAssets(tokenConfigs[token0].totalDebtShares, debtExchangeRateX96, Math.Rounding.Up)
                            > lentAssets * collateralValueLimitFactorX32 / Q32
                ) {
                    revert CollateralValueLimit();
                }
                collateralValueLimitFactorX32 = tokenConfigs[token1].collateralValueLimitFactorX32;
                if (
                    collateralValueLimitFactorX32 < type(uint32).max
                        && _convertToAssets(tokenConfigs[token1].totalDebtShares, debtExchangeRateX96, Math.Rounding.Up)
                            > lentAssets * collateralValueLimitFactorX32 / Q32
                ) {
                    revert CollateralValueLimit();
                }
            }
        }
    }

    function _resetDailyLendIncreaseLimit(uint256 newLendExchangeRateX96, bool force) internal {
        // daily lend limit reset handling
        uint32 time = uint32(block.timestamp / 1 days);
        if (force || time > dailyLendIncreaseLimitLastReset) {
            dailyLendIncreaseLimitLeft =
                _calculateDailyIncreaseLimit(newLendExchangeRateX96, dailyLendIncreaseLimitMin, MAX_DAILY_LEND_INCREASE_X32);
            dailyLendIncreaseLimitLastReset = time;
        }
    }

    function _resetDailyDebtIncreaseLimit(uint256 newLendExchangeRateX96, bool force) internal {
        // daily debt limit reset handling
        uint32 time = uint32(block.timestamp / 1 days);
        if (force || time > dailyDebtIncreaseLimitLastReset) {
            dailyDebtIncreaseLimitLeft =
                _calculateDailyIncreaseLimit(newLendExchangeRateX96, dailyDebtIncreaseLimitMin, MAX_DAILY_DEBT_INCREASE_X32);
            dailyDebtIncreaseLimitLastReset = time;
        }
    }

    function _calculateDailyIncreaseLimit(uint256 lendExchangeRateX96, uint256 minLimit, uint256 limitFactorX32)
        private
        view
        returns (uint256)
    {
        uint256 limit = _convertToAssets(totalSupply(), lendExchangeRateX96, Math.Rounding.Up) * limitFactorX32 / Q32;
        return minLimit > limit ? minLimit : limit;
    }

    /// @notice Sets gauge manager address once (owner only)
    /// @dev Safety note: this only validates that `_gaugeManager` is a contract and then permanently locks it.
    /// @dev GaugeManager enforces `msg.sender == address(vault)`, so configuring a manager deployed for a different
    ///      vault will make stake/unstake/reward-precompound paths revert Unauthorized and cannot be corrected afterward.
    /// @dev This one-time lock without vault-binding handshake is an accepted operational/trust risk.
    function setGaugeManager(address _gaugeManager) external onlyOwner {
        if (gaugeManager != address(0)) {
            revert GaugeManagerAlreadySet();
        }
        if (_gaugeManager == address(0) || _gaugeManager.code.length == 0) {
            revert InvalidConfig();
        }

        gaugeManager = _gaugeManager;
        emit SetGaugeManager(_gaugeManager);
    }

    function stakePosition(uint256 tokenId) external override {
        _requireGaugeManagerSet();
        if (tokenOwner[tokenId] != msg.sender) {
            revert NotDepositor();
        }

        _
```

## Contexto de Solodit (bugs similares en protocolos similares)
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

## Briefing del Dominio (vault)
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
- [ ] Does `totalAssets()` use internal accounting (not `balanceOf`)?
- [ ] Is there a sweep/skim function for excess donated tokens?
- [ ] Is exchange rate change limited per block?
### Rounding Direction
- [ ] Does `deposit` / `mint` round UP (against user) on assets consumed?
- [ ] Does `withdraw` / `redeem` round DOWN (against user) on assets returned?
- [ ] Is `mulDivUp` used for entry, `mulDivDown` for exit?
- [ ] Do all zero inputs return zero outputs?
- [ ] Do all nonzero inputs produce nonzero outputs?
### Roundtrip Safety
- [ ] Is `redeem(deposit(X))` <= X for any X?
- [ ] Is `deposit(redeem(S))` <= S for any S?
- [ ] Is `mint` cost >= `redeem` yield for same share amount?


### Grep targets adicionales (nft)
```yaml
- id: nft-008
  pattern: borrowed-nft-setapprovalforall-hijack
  name: "Borrower hijacks borrowed NFT via setApprovalForAll on recipient's safe/contract"
  severity: high
  causa_raiz: >
    Protocols that lend NFTs to borrowers via flash loans or collateral-backed loans
    transfer the NFT to the borrower's address. If the borrower's address is a Gnosis Safe
    or any contract with a fallback handler, the borrower can set a fallback handler
    that returns a valid ERC721 receiver response AND sets approvals for the attacker.
    The protocol later tries to reclaim the NFT — but the attacker already extracted it.
  como_funciona: |

## Contexto Chimera (OBLIGATORIO — lee antes de escribir Solidity)

Tu código se insertará en un archivo `PropertiesX.sol` que hereda de `Properties.sol`.
Properties.sol hereda del Setup (variables de estado, contratos, actores).
NO escribas `function invariant_...()` — solo el BODY. merge_invariants.py genera el wrapper.

### Variables y contratos disponibles (heredados de Setup):
```solidity
  int256 public _price;
  V3Vault public vault;
  V3Oracle public oracle;
  InterestRateModel public irm;
  GaugeManager public gaugeManager;
  ForkMockChainlink public usdcFeed;
  ForkMockChainlink public wethFeed;
  IUniswapV3Pool public wethUsdcPool;
  address public wethUsdcGauge;
  address public aeroUsdcPool;
  address public aeroWethPool;
  address public alice = address(0xA11CE);
  address public bob = address(0xB0B);
  address public carol = address(0xCA401);
  uint256[] internal _tokenIds;
  int256 public price;
  uint8 public decimals;
  MockAerodromePositionManager public npm;
  MockAerodromeFactory public factory;
  ChimeraMockERC20 public usdc;
  ChimeraMockERC20 public dai;
  ChimeraMockERC20 public aero;
  ChimeraMockWETH public weth;
  address public usdcDaiPool;
  address public wethUsdcPool;
  MockGauge public usdcDaiGauge;
  MockGauge public wethUsdcGauge;
  address public alice = address(0x1);
  address public bob = address(0x2);
  address public admin; // deployer = admin
  address internal carol = address(0x4);
  ChimeraMockIRM public irm;
  ChimeraMockChainlink public usdcFeed;
  ChimeraMockChainlink public daiFeed;
  ChimeraMockChainlink public ethFeed;
  uint256 internal _nextTokenSalt;
  uint8 public decimals_;
  uint256 internal _nextId = 1;
  address public token0;
  address public token1;
  int24 public tickSpacing;
  address internal constant MOCK_GAUGE = 0x0000000000000000000000000000000000009999;
  MinimalMockNPM public npm;
  MinimalMockIRM public irm;
  MinimalMockGaugeManager public mockGaugeManager;
  MockTransformer public mockTransformer;
  MinimalMockERC20 public usdc;
  MinimalMockERC20 public dai;
  MinimalMockChainlink public usdcFeed;
  MinimalMockChainlink public daiFeed;
```

### Funciones públicas del contrato target (getters y setters disponibles):
```solidity
  function vaultInfo() external view override returns ( uint256 debt, uint256 lent, uint256 balance, uint256 reserves, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96 );
  function lendInfo(address account) external view override returns (uint256 amount);
  function loanInfo(uint256 tokenId) public view override returns ( uint256 debt, uint256 fullValue, uint256 collateralValue, uint256 liquidationCost, uint256 liquidationValue );
  function ownerOf(uint256 tokenId) external view override returns (address owner);
  function loanCount(address owner) external view override returns (uint256);
  function loanAtIndex(address owner, uint256 index) external view override returns (uint256);
  function decimals() public view override;
  function totalAssets() external view override returns (uint256);
  function convertToShares(uint256 assets) external view override returns (uint256 shares);
  function convertToAssets(uint256 shares) external view override returns (uint256 assets);
  function maxDeposit(address) external view override returns (uint256);
  function maxMint(address) external view override returns (uint256);
  function maxWithdraw(address owner) external view override returns (uint256);
  function maxRedeem(address owner) external view override returns (uint256);
  function previewDeposit(uint256 assets) external view override returns (uint256);
  function previewMint(uint256 shares) external view override returns (uint256);
  function previewWithdraw(uint256 assets) external view override returns (uint256);
  function previewRedeem(uint256 shares) external view override returns (uint256);
  function deposit(uint256 assets, address receiver) external override returns (uint256);
  function mint(uint256 shares, address receiver) external override returns (uint256);
  function withdraw(uint256 assets, address receiver, address owner) external override returns (uint256);
  function redeem(uint256 shares, address receiver, address owner) external override returns (uint256);
  function create(uint256 tokenId, address recipient) external override;
  function onERC721Received(address, /*operator*/ address from, uint256 tokenId, bytes calldata data) external override returns (bytes4);
  function approveTransform(uint256 tokenId, address target, bool isActive) external override;
  function transform(uint256 tokenId, address transformer, bytes calldata data) external override returns (uint256 newTokenId);
  function transformWithRewardCompound(uint256 tokenId, address transformer, bytes calldata data, RewardCompoundParams calldata rewardParams) external override returns (uint256 newTokenId);
  function borrow(uint256 tokenId, uint256 assets) external override;
  function decreaseLiquidityAndCollect(DecreaseLiquidityAndCollectParams calldata params) external override returns (uint256 amount0, uint256 amount1);
  function repay(uint256 tokenId, uint256 amount, bool isShare) external override returns (uint256 assets, uint256 shares);
  function liquidate(LiquidateParams calldata params) external override returns (uint256 amount0, uint256 amount1);
  function remove(uint256 tokenId, address recipient, bytes calldata data) external;
  function withdrawReserves(uint256 amount, address receiver) external;
  function setTransformer(address transformer, bool active) external;
  function setLimits(uint256 _minLoanSize, uint256 _globalLendLimit, uint256 _globalDebtLimit, uint256 _dailyLendIncreaseLimitMin, uint256 _dailyDebtIncreaseLimitMin) external;
  function setReserveFactor(uint32 _reserveFactorX32) external;
  function setReserveProtectionFactor(uint32 _reserveProtectionFactorX32) external;
  function setTokenConfig(address token, uint32 collateralFactorX32, uint32 collateralValueLimitFactorX32) external;
  function setEmergencyAdmin(address admin) external;
  function setGaugeManager(address _gaugeManager) external;
  function stakePosition(uint256 tokenId) external override;
  function unstakePosition(uint256 tokenId) external override;
```

### Ghost variables existentes (ya declaradas, puedes usarlas):
```solidity
  uint256 internal ghost_totalDeposited;
  uint256 internal ghost_totalWithdrawn;
  uint256 internal ghost_totalBorrowed;
  uint256 internal ghost_totalRepaid;
  uint256 internal ghost_totalLiquidated;
  uint256 internal ghost_lastDebtRateX96;
  uint256 internal ghost_lastLendRateX96;
  uint256 internal ghost_lastSharePrice;
  uint256 internal ghost_positionsCreated;
  uint256 internal ghost_positionsRemoved;
  mapping(address => uint256) internal ghost_userDeposited;
  mapping(address => uint256) internal ghost_userWithdrawn;
  uint256 internal ghost_numOps;
  uint256[] internal ghost_allTokenIds;
  bool internal ghost_liquidationInProgress;
  uint256 internal ghost_lastLiquidatedTokenId;
  uint256 internal ghost_lastDepositAssets;
  uint256 internal ghost_lastDepositShares;
  uint256 internal ghost_lastLendExchangeRateX96;
  uint256 internal ghost_lastDebtExchangeRateX96;
  uint256 inflows = ghost_totalDeposited + ghost_totalRepaid + ghost_totalLiquidated;
  uint256 outflows = ghost_totalWithdrawn + ghost_totalBorrowed;
  uint256 totalInterest = lent > ghost_totalDeposited ? lent - ghost_totalDeposited : 0;
  for (uint256 i = 0; i < ghost_allTokenIds.length; i++) {
  (uint256 shares) = vault.loans(ghost_allTokenIds[i]);
  (uint256 debtShares) = vault.loans(ghost_lastLiquidatedTokenId);
  uint256 tokenId = ghost_allTokenIds[i];
  for (uint256 i = 0; i < ghost_allTokenIds.length && i < 10; i++) {
  for (uint256 i = 0; i < ghost_allTokenIds.length && i < 5; i++) {
  if (gm != address(0) && ghost_allTokenIds.length > 0) {
  for (uint256 i = 0; i < ghost_allTokenIds.length && i < 20; i++) {
  /* COMPILE_FIX: for (uint256 i = 0; i < ghost_allTokenIds.length && i < 5; i++) { */
  /* COMPILE_FIX: uint256 tokenId = ghost_allTokenIds[i]; */
  /* COMPILE_FIX: uint256 tolerance = ghost_numOps + 1; */
  uint256 tid = ghost_allTokenIds[i];
  uint256 redeemAssets = ghost_lastDepositShares * lendRate / Q96;
  /* COMPILE_FIX: for (uint256 i = 0; i < ghost_allTokenIds.length; i++) { */
  /* COMPILE_FIX: uint256 tid = ghost_allTokenIds[i]; */
  uint256 tolerance = ghost_numOps > 0 ? ghost_numOps : 1;
  (uint256 s) = vault.loans(ghost_allTokenIds[i]);
```

### Helpers internos disponibles:
```solidity
  _clampAmount(uint256 seed, uint256 maxVal) internal pure returns (uint256);
  _createPosition(address owner) internal returns (uint256 tokenId);
  _pickActor(uint256 seed) internal view returns (address);
  _pickToken(uint256 seed) internal view returns (uint256 tokenId, bool ok);
  _createRealPosition(address owner) internal returns (uint256 tokenId);
```

### Assertion helpers (de chimera/Asserts.sol):
```solidity
t(bool condition, string memory msg)    // assert true
eq(uint256 a, uint256 b, string memory msg)  // assert ==
gte(uint256 a, uint256 b, string memory msg) // assert >=
lte(uint256 a, uint256 b, string memory msg) // assert <=
gt(uint256 a, uint256 b, string memory msg)  // assert >
lt(uint256 a, uint256 b, string memory msg)  // assert <
```

### REGLAS para tu código Solidity:
1. **Solo el body** — NO escribas `function invariant_...()`. Solo las líneas internas.
2. **Usa EXACTAMENTE las variables de arriba** — NO inventes nombres. Si no está listado, NO existe.
3. **Usa los getters listados arriba** — Si necesitas un valor del contrato, busca en la lista de funciones públicas.
4. **Usa helpers Chimera** — `t()`, `eq()`, `gte()`, NO `require()` ni `assert()`.
5. **Sin caracteres unicode** en strings — usa `--` en vez de `—`, ASCII puro.
6. **Si necesitas ghost vars nuevas**, declara en el campo `ghost_vars` del YAML, NO en el body.
7. **Si una función no está en la lista de arriba, NO LA USES.** Compilará mal.

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Protocol-specific invariants) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `VV` (ej: VV-01, VV-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_V3Vault_DomainHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: VV-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "VV-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Symmetric Inspection (OBLIGATORIO — después de tu análisis de dominio)
Identifica TODOS los pares simétricos del contrato. Pares comunes:
  deposit/withdraw, mint/burn, lock/unlock, stake/unstake, borrow/repay, open/close

Para CADA par, verifica estas 5 dimensiones:
1. **State variables**: ¿ambas funciones actualizan las mismas variables (en dirección opuesta)?
2. **Validaciones**: ¿mismas validaciones (o su inversa lógica)?
3. **Events**: ¿ambas emiten el evento correspondiente?
4. **Modifiers**: ¿mismos modifiers aplicados (nonReentrant, whenNotPaused)?
5. **Edge cases**: ¿amount=0, amount=max, balance=0 manejados simétricamente?

Cualquier asimetría es un candidato a invariante. Documenta qué variable/check/event falta en qué función.
Bug real: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M.

## Constraint Inference (0xRajeev — OBLIGATORIO)
Para cada validación/require que encuentres:
1. Observa qué se valida en N-1 code paths que hacen algo similar.
2. El path que NO tiene esa validación es el bug candidato.
Ejemplo: si 5 de 6 funciones de withdraw verifican healthFactor, la 6ta que no lo hace es sospechosa.

## Traza Hacia Atrás (samczsun — MENTALIDAD)
No empieces preguntando "¿hay un bug aquí?". Empieza preguntando:
"¿De dónde puede SALIR valor del protocolo?" (withdraw, redeem, liquidate, claim, transfer).
Para cada punto de salida, traza HACIA ATRÁS: ¿qué condiciones se deben cumplir? ¿Se pueden manipular?

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
