# DeepDiveHunter — V3Vault Deep Analysis

## Tu Identidad
Eres el **DeepDiveHunter** del equipo de bug hunting de revert-lend.
No escaneas patrones — PIENSAS como samczsun. Trazas hacia atrás desde puntos de salida de valor.

## Tu Input
Tienes los resultados de 9 hunters que ya analizaron este componente.
Tu trabajo: encontrar lo que ELLOS NO VIERON. Profundidad, no amplitud.
**IMPORTANTE**: FlowHunter incluye un State Machine Model (FSM) en su output. ÚSALO:
- Busca transiciones ilegales que los otros hunters no detectaron
- Busca estados stuck donde fondos quedan atrapados
- Busca bypasses de estados intermedios (saltar validaciones)

## Contrato
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
// ... TRUNCATED
```

## Convergence Map

- **address()**: flagged by 5 hunters (AccessHunter, DoSHunter, DomainHunter, FlowHunter, WildcardHunter), 50 mentions
- **ownerof()**: flagged by 4 hunters (AccessHunter, DomainHunter, FlowHunter, WildcardHunter), 21 mentions
- **loans()**: flagged by 4 hunters (DoSHunter, DomainHunter, FlowHunter, WildcardHunter), 20 mentions
- **debtsharestotal()**: flagged by 4 hunters (DoSHunter, DomainHunter, FlowHunter, WildcardHunter), 12 mentions
- **loaninfo()**: flagged by 4 hunters (DoSHunter, DomainHunter, FlowHunter, WildcardHunter), 9 mentions


## Existing Hypotheses (DO NOT DUPLICATE)

- [VV-AC-01] (AccessHunter, 85%): Only the vault-recorded owner of a tokenId can call borrow() outside transform mode
- [VV-AC-02] (AccessHunter, 90%): Only the vault-recorded owner can call decreaseLiquidityAndCollect for their tokenId
- [VV-AC-03] (AccessHunter, 90%): Only the vault-recorded owner can call remove() for their tokenId
- [VV-AC-04] (AccessHunter, 85%): Transform can only be called by owner or an address with explicit transformApprovals for that tokenId
- [VV-AC-05] (AccessHunter, 90%): transformedTokenId sentinel must be 0 outside of an active transform call -- no stuck transform mode
- [VV-AC-06] (AccessHunter, 70%): Transform approval auto-migration: when tokenId changes during transform, old approvals are correctly transferred and old ones deleted
- [VV-AC-07] (AccessHunter, 95%): setGaugeManager can only be called once -- subsequent calls must revert
- [VV-AC-08] (AccessHunter, 85%): Liquidation is blocked during transform mode (transformedTokenId != 0)
- [VV-AC-09] (AccessHunter, 75%): emergencyAdmin can call setLimits but NOT other admin functions (withdrawReserves, setTransformer, setTokenConfig, setReserveFactor)
- [VV-AC-10] (AccessHunter, 90%): Only tokens from nonfungiblePositionManager are accepted via onERC721Received -- other NFT contracts must be rejected
- [VV-AC-11] (AccessHunter, 95%): setTransformer cannot set dangerous addresses (address(0), vault itself, asset, NPM) as transformers
- [VV-AC-12] (AccessHunter, 85%): Token ownership count (loanCount) must match the actual number of tokens stored for each owner
- [VV-AC-13] (AccessHunter, 80%): unstakePosition can only be called by token owner or during active transform for that token
- [VV-AC-14] (AccessHunter, 90%): approveTransform can only be called by the token owner -- no delegation path
- [VV-AC-15] (AccessHunter, 85%): stakePosition can only be called by the position owner -- not by approved transformers or other roles
- [VV-DOS-01] (DoSHunter, 75%): liquidate() calls _checkLoanIsHealthy() which calls oracle.getValue(). If the oracle
reverts (e.g., stale Chainlink feed, invalid pool, misconfigured token), ALL liquidations
are blocked. Unlike withdraw/deposit which don't need oracle, liquidation is the only
mechanism to prevent bad debt. A prolonged oracle outage = unrecoverable bad debt.

Path: liquidate() -> _checkLoanIsHealthy() -> oracle.getValue() -> REVERT

The protocol has NO emergency liquidation path that bypasses the oracle.
There is no try/catch around the oracle call in _checkLoanIsHealthy.

- [VV-DOS-02] (DoSHunter, 70%): liquidate() calls _unstakeIfNeeded() which calls gaugeManager.unstakeIfStaked().
If GaugeManager reverts (e.g., gauge is paused, gauge contract is bricked, Aerodrome
upgrade breaks interface), staked positions CANNOT be liquidated.

Path: liquidate() -> _unstakeIfNeeded() -> gaugeManager.unstakeIfStaked() -> REVERT

There is no try/catch around this call. A broken GaugeManager permanently blocks
liquidation of all staked positions.

CRITICAL: setGaugeManager() is one-time-only (line 1370: GaugeManagerAlreadySet).
If the configured GaugeManager bricks, it CANNOT be replaced.

- [VV-DOS-03] (DoSHunter, 65%): Nearly every function in V3Vault calls _updateGlobalInterest() or _calculateGlobalInterest()
which calls interestRateModel.getRatesPerSecondX64(). If IRM reverts, the following
functions ALL revert: deposit, mint, withdraw, redeem, borrow, repay, liquidate,
create (onERC721Received), transform, decreaseLiquidityAndCollect, remove (indirectly),
stakePosition (via loanInfo), and ALL view functions.

The IRM is immutable (set in constructor), so it cannot be replaced.

A bricked IRM = entire vault frozen permanently with no recovery path.

- [VV-DOS-04] (DoSHunter, 55%): An attacker can exhaust dailyDebtIncreaseLimitLeft by borrowing and immediately repaying
in a loop. Repay adds back to dailyDebtIncreaseLimitLeft (line 1081), but borrow subtracts
from it (line 658). However, the check is `assets > dailyDebtIncreaseLimitLeft` (line 655),
so net-zero borrow+repay should not drain. BUT: if exchange rate changes between borrow and
repay (same block = no change, different block = change), the repay may return fewer assets
than borrowed (rounding), slowly draining the limit.

More directly: an attacker with enough collateral just borrows the entire limit legitimately,
blocking all other users from borrowing for the rest of the day.

The daily limit resets based on `block.timestamp / 1 days` (line 1389-1390).

- [VV-DOS-05] (DoSHunter, 70%): repay() at line 1088-1092 checks that if partial repay leaves remaining debt < minLoanSize,
it reverts with MinLoanSize(). This means a borrower whose debt is between minLoanSize and
2*minLoanSize CANNOT partially repay -- they must fully repay in one tx.

If the borrower does not have enough assets for full repay, they are stuck:
- Cannot partial repay (MinLoanSize revert)
- Cannot full repay (insufficient funds)
- Position accrues interest and eventually gets liquidated

This is especially problematic if minLoanSize is set high by emergencyAdmin.

- [VV-DOS-06] (DoSHunter, 60%): _withdraw() at line 1033-1035 checks `balance < assets` and reverts InsufficientLiquidity.
When utilization is ~100% (all assets are borrowed), lenders CANNOT withdraw.

The protocol relies on interest rate increases to incentivize repayment, but:
- If borrowers are insolvent, they won't repay
- If oracle is down, liquidation is blocked
- There is NO emergency withdrawal that bypasses liquidity check
- There is NO withdrawal queue mechanism

Lender funds can be locked indefinitely when utilization hits 100%.

- [VV-DOS-07] (DoSHunter, 65%): _transform() at lines 617-620: if the position was staked before transform, it re-stakes
after transform via _stake(). If _stake() fails (GaugeManager revert, gauge removed,
NFT approval issue), the entire transform reverts.

This means a user with a staked position CANNOT use any transformer (AutoRange,
LeverageTransformer, etc.) if GaugeManager staking is broken.

Combined with the one-time GaugeManager lock, this is permanent.

- [VV-DOS-08] (DoSHunter, 60%): stakePosition() at line 1391 checks loan health AFTER staking. Staking changes the
valuation model: _checkLoanIsHealthy() passes ignoreFees=true for staked positions
(line 1429), meaning fee value is EXCLUDED from collateral.

If a position's health depends on accumulated fees, staking it immediately makes it
unhealthy. The stakePosition function reverts with CollateralFail.

But the deeper issue: what if someone ELSE calls a path that stakes the position
(e.g., transform with wasStaked=true re-stakes at line 619), and the position was
healthy before but unhealthy after staking due to fee exclusion?
The transform would revert even though the user didn't explicitly request staking.

- [VV-DOS-09] (DoSHunter, 50%): An attacker can front-run a large deposit by depositing the remaining dailyLendIncreaseLimitLeft
themselves, causing the victim's deposit to revert with DailyLendIncreaseLimit.

The attacker can then withdraw immediately (withdrawal adds back to the limit at line 1043),
but the victim's tx already reverted.

Cost to attacker: only gas fees (deposit + withdraw in same block = no interest cost).
The limit resets daily at block.timestamp / 1 days boundary.

- [VV-DOS-10] (DoSHunter, 45%): _updateAndCheckCollateral() updates tokenConfigs[token].totalDebtShares on both borrow
AND repay. On repay (line 1083-1085), oldShares > newShares, so the difference is
SUBTRACTED from totalDebtShares. The collateral limit check only triggers when
newShares > oldShares (increasing debt).

However, consider: repay calls _updateAndCheckCollateral with
(loanDebtShares + shares, loanDebtShares) where shares was already subtracted.
Wait -- line 1083: oldShares = loanDebtShares + shares (before repay), newShares = loanDebtShares (after).
So oldShares > newShares -> subtraction path, no limit check. This is correct.

BUT: if SafeCast.toUint192 overflows (debtShares difference > type(uint192).max),
the subtraction at line 1346 reverts. This would block repay if totalDebtShares
somehow got into an inconsistent state. Unlikely but worth checking.

- [VV-DOS-11] (DoSHunter, 70%): remove() at line 853 calls nonfungiblePositionManager.safeTransferFrom() to return
the NFT to the user. If the recipient is a contract that reverts in onERC721Received(),
or if the NFT manager is paused/upgraded, the remove() call fails.

Additionally, remove() first calls _unstakeIfNeeded() (line 850). If the position
is staked and GaugeManager.unstakeIfStaked() reverts, the user cannot remove their
position even after fully repaying debt.

Combined: fully repaid user with staked position + broken GaugeManager = NFT stuck forever.

- [VV-DOS-12] (DoSHunter, 40%): _transform() at line 586 uses a low-level call:
  (bool success,) = transformer.call(data);

The transformer is from transformerAllowList (set by owner), so it's trusted.
However, if a transformer is compromised or has a bug, it could return a huge
amount of data (returnbomb). The low-level call copies ALL return data to memory,
consuming gas proportional to return data size.

With (bool success,) pattern, Solidity still copies return data to memory before
discarding it. A malicious transformer could return 2MB+ of data, consuming all
remaining gas and causing the transform to fail.

Mitigation: transformers are admin-curated, so this requires compromised transformer.

- [VV-D-01] (DomainHunter, 85%): Solvency invariant: vault balance + outstanding debt >= total lent amount (lender claims)
- [VV-D-02] (DomainHunter, 90%): Debt exchange rate monotonicity: debtExchangeRateX96 must never decrease (only exception: zero debt)
- [VV-D-03] (DomainHunter, 85%): Lend exchange rate monotonicity with socialization exception: lendExchangeRateX96 must never decrease except during reserve socialization (bad debt haircut)
- [VV-D-04] (DomainHunter, 90%): Debt shares total conservation: sum of all individual loan debtShares must equal debtSharesTotal
- [VV-D-05] (DomainHunter, 80%): Token ownership consistency: every tokenId in ownedTokens has correct tokenOwner mapping and vice versa
- [VV-D-06] (DomainHunter, 85%): No position can have debt without being tracked in vault ownership (orphan debt prevention)
- [VV-D-07] (DomainHunter, 80%): Liquidation only possible for unhealthy positions: collateralValue < debt
- [VV-D-08] (DomainHunter, 75%): ERC4626 roundtrip safety: redeem(deposit(X)) <= X for any X (no value extraction via deposit-then-redeem)
- [VV-D-09] (DomainHunter, 70%): Collateral value limit tracking: totalDebtShares per token config must equal sum of debtShares for positions using that token
- [VV-D-10] (DomainHunter, 90%): Transform mode isolation: transformedTokenId must be 0 outside of an active transform() call
- [VV-D-11] (DomainHunter, 65%): Daily limit replenishment symmetry: borrow replenishes on repay, deposit replenishes on withdraw
- [VV-D-12] (DomainHunter, 70%): Reserve protection: withdrawReserves cannot drain below protected amount (reserveProtectionFactorX32 * lentAmount)
- [VV-D-13] (DomainHunter, 60%): Symmetric pair: borrow/repay must conserve debtSharesTotal (borrow adds X shares, repay removes at most X shares for same asset amount)
- [VV-D-14] (DomainHunter, 75%): Liquidation penalty bounds: liquidation penalty must be between MIN_LIQUIDATION_PENALTY_X32 (2%) and MAX_LIQUIDATION_PENALTY_X32 (10%)
- [VV-D-15] (DomainHunter, 80%): NFT custody invariant: for every tracked position, the NFT must be owned by either the vault or the gaugeManager (if staked)
- [VV-F-01] (FlowHunter, 90%): Solvency invariant: vault asset balance + total debt >= total lent amount. If this breaks, lenders cannot be made whole -- funds have leaked.
- [VV-F-02] (FlowHunter, 85%): debtSharesTotal must equal sum of all individual loan debtShares. If mismatch, debt accounting is broken -- borrowers owe different total than vault tracks.
- [VV-F-03] (FlowHunter, 75%): Transform reentrancy sentinel must be 0 outside of transform calls. If transformedTokenId != 0 persists, the vault is in a corrupted state that blocks liquidations, removes, and decreaseLiquidityAndCollect.
- [VV-F-04] (FlowHunter, 80%): Exchange rates must be monotonically non-decreasing. If debtExchangeRateX96 or lendExchangeRateX96 decrease (outside of bad debt socialization), interest accounting is broken and lenders lose value.
- [VV-F-05] (FlowHunter, 70%): Borrow must not send assets without increasing debtSharesTotal. After borrow(), the outflow of assets MUST correspond to an increase in global debt tracking.
- [VV-F-06] (FlowHunter, 65%): Liquidation must not be possible for healthy positions. If a position with collateralValue >= debt passes the liquidation check, the protocol allows theft of solvent borrowers' collateral.
- [VV-F-07] (FlowHunter, 80%): Token ownership consistency: every tokenId in vault must have exactly one owner, and the NFT must be held by either the vault or the gaugeManager (if staked). If NFT escapes custody, collateral is gone but debt remains.
- [VV-F-08] (FlowHunter, 85%): Repay must reduce debtSharesTotal by exactly the shares repaid. Over-repayment is capped at currentShares (L1069-1072), so debtSharesTotal should never underflow.
- [VV-F-09] (FlowHunter, 55%): Daily limit accounting: dailyDebtIncreaseLimitLeft must be replenished on repay and liquidation. If borrow reduces it but repay/liquidation don't restore it, the limit becomes a monotonically decreasing DoS vector.
- [VV-F-10] (FlowHunter, 70%): Transform callback borrow during transform must not bypass health check permanently. After transform completes, health check at L621 must verify the FINAL state including any borrows made during the callback.
- [VV-F-11] (FlowHunter, 75%): Withdrawal must not extract more assets than the caller's share entitlement. The vault must not allow extracting more than convertToAssets(balanceOf(owner)) even across multiple txs.
- [VV-F-12] (FlowHunter, 50%): Reserve withdrawal protection: withdrawReserves cannot drain below reserveProtectionFactor percentage of lent assets. If this invariant breaks, lender liquidity is compromised.
- [VV-F-13] (FlowHunter, 85%): Token replacement during transform must conserve debt. When onERC721Received replaces oldTokenId with newTokenId during transform, the debt must be exactly copied -- no inflation or deflation.
- [VV-F-14] (FlowHunter, 80%): Liquidation must fully clear the loan. After liquidate(), loans[tokenId].debtShares must be 0, and debtSharesTotal must have decreased by exactly the old debtShares.
- [VV-F-15] (FlowHunter, 80%): Share price monotonicity for lenders: the value of 1 share (lendExchangeRateX96) should not decrease except during bad debt socialization events. Lenders should always earn, never lose (outside of socialized losses).
- [VV-W-01] (WildcardHunter, 75%): transformedTokenId must always be zero outside of a transform() call -- if it stays nonzero, the vault is in a broken reentrancy state that blocks liquidations and other operations
- [VV-W-02] (WildcardHunter, 85%): A loan with zero debtShares must never have its tokenId tracked in tokenConfigs totalDebtShares -- cleanup must always decrement both token0 and token1 totalDebtShares to prevent phantom collateral accounting
- [VV-W-03] (WildcardHunter, 80%): Transform token replacement must never allow a tokenId that already has an owner or debt in the vault -- reusing an existing vault tokenId would overwrite its loan state
- [VV-W-04] (WildcardHunter, 65%): Daily lend/debt increase limits must never allow more lending/borrowing than the configured percentage of total lent assets per day -- limits should reset correctly at day boundaries
- [VV-W-05] (WildcardHunter, 90%): Exchange rates must be monotonically non-decreasing -- debtExchangeRateX96 and lendExchangeRateX96 can only stay same or increase over time (except during reserve socialization haircut)
- [VV-W-06] (WildcardHunter, 70%): The vault must never hold an NFT that it does not track in tokenOwner -- orphaned NFTs would be permanently locked with no way to retrieve them
- [VV-W-07] (WildcardHunter, 70%): Reserve socialization haircut in _handleReserveLiquidation must never reduce lendExchangeRate to zero or below a minimum threshold -- complete lender wipeout should be impossible
- [VV-W-08] (WildcardHunter, 60%): The Multicall inherited by V3Vault must not allow batching of state-changing calls that bypass the transformedTokenId reentrancy guard -- multicall could let an attacker chain borrow() + liquidate() in a single tx
- [VV-W-09] (WildcardHunter, 85%): Token replacement during transform must preserve debt accounting -- the sum of all loans debtShares plus the debtSharesTotal delta must remain consistent across the replacement
- [VV-W-10] (WildcardHunter, 72%): Staked position health check must use ignoreFees=true valuation consistently -- if a staked position is valued WITH fees for some operations and WITHOUT fees for others, there is a valuation gap exploitable for borrowing more than the true collateral value
- [VV-W-11] (WildcardHunter, 65%): onERC721Received must reject any NFT that is not from the configured nonfungiblePositionManager -- accepting arbitrary ERC721 tokens would pollute vault state
- [VV-W-12] (WildcardHunter, 90%): After liquidation, the liquidated position must have zero debtShares -- partial liquidation is not supported, every liquidation clears the full debt


## Already Debunked (DO NOT REPEAT)

- [VV-AC-FP-01]: onERC721Received allows owner override via callback data (L460-464). This is intentional per the NOTE FOR AUDITS comment -- whoever can trigger safeTransferFrom controls the payload. Not a bug.
- [VV-AC-FP-02]: onERC721Received replacement path (L474-504) does not bind to specific operator. This is intentional per NOTE FOR AUDITS -- some transformers use helper/proxy contracts. Safety relies on transform-mode scoping.
- [VV-AC-FP-03]: repay() has no access control (anyone can repay any loan). This is intentional and standard DeFi pattern -- allowing third-party repayment is a feature, not a bug. No economic harm from repaying someone else's debt.
- [VV-DOS-FP-01]: ownedTokens[owner] grows with each position added. However, there is NO loop
over this array in any critical function. _removeTokenFromOwner uses swap-and-pop
(O(1)). The only iteration would be from an external caller using loanCount +
loanAtIndex, which is a view function and does not affect on-chain operations.

The external enumerability is by design for frontends. Not a DoS vector.

- [VV-DOS-FP-02]: Daily limits reset at block.timestamp / 1 days boundary. An attacker cannot
prevent the reset. The reset happens automatically on the first operation of
the new day. The _resetDailyLendIncreaseLimit and _resetDailyDebtIncreaseLimit
functions check `time > dailyXIncreaseLimitLastReset` which is always true
after midnight UTC.

The only griefing is within a single day (exhaust the limit), but the limit
is proportional to total lent assets (10% by default), so draining it requires
significant capital.

- [VV-DOS-FP-03]: V3Vault inherits Multicall, but each sub-call in a multicall uses the same
msg.sender and operates independently. A failed sub-call reverts the entire
multicall, but this is standard behavior and doesn't create new DoS vectors
beyond what individual functions already have.

- [VV-D-FP-01]: Donation attack via direct ERC20 transfer to vault: totalAssets() uses balanceOf(address(this)) + debt. Direct donation would increase balance, inflating totalAssets and share price. However, this does NOT cause first-depositor attack because the vault starts with Q96 exchange rate (not calculated from balance/supply). The exchange rate is only updated via _updateGlobalInterest which uses the IRM, not raw balance. Donations just increase reserves, which benefit the protocol.
- [VV-D-FP-02]: minLoanSize bypass via partial repay: repay() checks if resulting loan < minLoanSize and reverts. An attacker cannot create dust loans that are too expensive to liquidate. However, a position can START with 0 debt (just collateral, no borrow) which is fine -- minLoanSize only applies when there IS debt.
- [VV-D-FP-03]: borrow() health check skip in transform mode: During _transform, the transformer can call borrow() and the health check is skipped. This is by design -- the health check happens AFTER the transform completes (line 621). The transformer might temporarily make the position unhealthy during its operation. The final check after transform ensures the result is healthy.
- [?]: Donations increase balance but not totalSupply. They go to reserves (balance + debt - lent). Lender share price is not inflated because _convertToShares uses lendExchangeRateX96 (from interest model), not balance/supply ratio directly.
- [?]: By design -- L460-464 comments explicitly. Whoever triggers safeTransferFrom controls the payload. This is intentional for integrator flows.
- [?]: By design at L595-598. When token is replaced during transform, the caller's approval is moved to the new tokenId. Prevents the caller from losing access to the transformed position.
- [VV-M-FP-01]: 
- [VV-M-FP-02]: 
- [VV-M-FP-03]: 
- [VV-O-FP-01]: The oracle intentionally reverts when pool spot price diverges from oracle-derived price
by more than maxPoolPriceDifference. This blocks liquidations temporarily but is a
FEATURE to prevent price manipulation attacks. Arbitrageurs restore the price. This is
documented in the oracle comments and is an accepted tradeoff.

- [VV-O-FP-02]: Staked positions have their fees directed to the gauge. The vault correctly passes
ignoreFees=true to the oracle for staked positions. This means staked positions have
lower collateral value, which is correct behavior -- the fees are not available to the
vault for liquidation recovery.

- [VV-O-FP-03]: The IRM returns rates based on utilization (balance vs debt). With mocks, utilization can
reach 100% producing extreme rates. This is a mock artifact, not an oracle bug. Test with
fork and real IRM for realistic rates.

- [FP-SIG-01]: 
- [FP-SIG-02]: 
- [FP-SIG-03]: 
- [?]: 
- [?]: 
- [?]: 
- [VV-W-FP-01]: Transform approval migration (lines 595-598): when tokenId changes during transform, approvals are copied from old to new token for the same msg.sender. Initially suspected this could allow unauthorized transform access, but the copy only happens for the CALLER (msg.sender) who already had approval. The old approval is deleted. This is correct behavior -- the caller who initiated the transform retains their approval on the replacement token.
- [VV-W-FP-02]: onERC721Received owner override via data parameter (lines 459-464): initially flagged as potential ownership hijack. But the comment at line 460-463 explicitly states this is intentional -- whoever can trigger safeTransferFrom for the NFT can also choose the callback payload. This is an accepted trust assumption for integrator/operator flows. The caller must already control the NFT to transfer it.
- [VV-W-FP-03]: Multicall + borrow reentrancy: considered whether multicall([borrow(token1, x), borrow(token2, y)]) could bypass per-token limits. But borrow checks are per-token (health, minLoanSize) and global (globalDebtLimit, dailyDebtIncreaseLimitLeft). Multicall batches are sequential within the same tx, so global limits correctly accumulate. No bypass found.


## Tu Proceso (OBLIGATORIO — sigue las 4 secciones en orden)

### Sección 1: Design Assumption Analysis
Para cada función crítica: ¿qué asume el developer que nunca pasará?
Lista cada asunción. Para cada una: construye un escenario concreto que la viole.

### Sección 2: Cross-Function State Analysis
Para cada PAR de funciones críticas: ¿qué pasa si se llaman en orden inesperado?
¿Qué estado deja A que hace que B se comporte diferente?

### Sección 3: Value Exit Trace (metodología samczsun)
Identifica TODOS los puntos donde sale valor del protocolo.
Para CADA uno, traza HACIA ATRÁS: ¿qué condiciones deben cumplirse? ¿se pueden manipular?

### Sección 4: State Machine Attack Paths
Usa el FSM del FlowHunter. Para cada anomalía reportada:
- ¿El stuck state puede causar pérdida de fondos? ¿Cuánto?
- ¿La transición ilegal se puede explotar con una secuencia concreta de txs?
- ¿Hay un ataque de 2+ pasos que abuse del orden de transiciones?
Si FlowHunter NO incluyó FSM, constrúyelo tú a partir del código.

### Sección 5: Convergence Deep-Dive
Donde 2+ hunters señalaron lo mismo: ¿hay un bug más profundo detrás?

## Output
Escribe en: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_V3Vault_DeepDiveHunter.yaml`

**MÁXIMO 5 hipótesis.** Cada una DEBE tener:
- `solidity` field estándar (Chimera assertions — OBLIGATORIO para merge_invariants.py)
- `poc_sketch` field (outline de test Foundry)
- `call_stack` field (traza de ejecución)
- `confidence` >= 60%

ID prefix: `VV-DD` (ej: VV-DD-01)

## Reglas
- NO dupliques IDs o descripciones de la lista de hipótesis existentes
- NO repitas false positives ya debunked
- CADA hipótesis necesita un `poc_sketch` concreto — si no puedes escribirlo, es demasiado vaga
- Prefiere 2 excelentes sobre 5 mediocres
- `validated: true` solo si confidence >= 60%
