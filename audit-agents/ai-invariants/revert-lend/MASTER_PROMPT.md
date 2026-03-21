# INVARIANT GENERATION — revert-lend

## ROLE

You are an elite Web3 security auditor specialized in invariant-based testing.
Your job is to deeply understand this protocol and generate SPECIFIC invariants
that would catch real bugs — the kind that pay $50K-$1M+ bounties.

## PROTOCOL CLASSIFICATION

**Primary type detected: AMM / DEX (hybrid: ERC20 Token, Lending Pool, Staking / Rewards)** (score: 75%, matched: 9/12 keywords)
Secondary: ERC20 Token, Lending Pool, Staking / Rewards

## SOURCE FILES

automators\AutoExit.sol, automators\Automator.sol, GaugeManager.sol, InterestRateModel.sol, interfaces\aerodrome\IAerodromeNonfungiblePositionManager.sol, interfaces\aerodrome\IAerodromeSlipstreamFactory.sol, interfaces\aerodrome\IAerodromeSlipstreamPool.sol, interfaces\aerodrome\IGauge.sol, interfaces\IGaugeManager.sol, interfaces\IInterestRateModel.sol, interfaces\IProtocolFeeController.sol, interfaces\IV3Oracle.sol, interfaces\IVault.sol, transformers\AutoRangeAndCompound.sol, transformers\LeverageTransformer.sol, transformers\Transformer.sol, transformers\V3Utils.sol, utils\ChainlinkFeedCombinator.sol, utils\Constants.sol, utils\FlashloanLiquidator.sol, utils\Swapper.sol, V3Oracle.sol

## PUBLIC FUNCTIONS

  - `execute(ExecuteParams calldata params)` external
  - `configToken(uint256 tokenId, PositionConfig calldata config)` external
  - `setWithdrawer(address _withdrawer)` public
  - `setOperator(address _operator, bool _active)` public
  - `setTWAPConfig(uint16 _maxTWAPTickDifference, uint32 _TWAPSeconds)` public
  - `withdrawBalances(address[] calldata tokens, address to)` external
  - `withdrawETH(address to)` external
  - `setGauge(address pool, address gauge)` external
  - `setRewardBasePool(address baseToken, address pool)` external
  - `stakePosition(uint256 tokenId)` external
  - `unstakePosition(uint256 tokenId)` external
  - `unstakeIfStaked(uint256 tokenId)` external
  - `claimRewards(uint256 tokenId, address recipient)` external
  - `compoundRewards(uint256 tokenId,
        uint256 minAeroReward,
        uint256 aeroSplitBps,
        uint256 deadline)` external
  - `setCompoundReward(uint64 _totalRewardX64)` external
  - `onERC721Received(address, address from, uint256 tokenId, bytes calldata)` external
  - `getUtilizationRateX64(uint256 cash, uint256 debt)` public
  - `getRatesPerSecondX64(uint256 cash, uint256 debt)` public
  - `setValues(uint256 baseRatePerYearX64,
        uint256 multiplierPerYearX64,
        uint256 jumpMultiplierPerYearX64,
        uint256 _kinkX64)` public
  - `getPool(address tokenA, address tokenB, int24 tickSpacing)` external
  - `slot0()` external
  - `deposit(uint256 tokenId)` external
  - `poolToGauge(address pool)` external
  - `withdrawer()` external
  - `isTokenConfigured(address token)` external
  - `transformedTokenId()` external
  - `transformWithRewardCompound(uint256 tokenId,
        address transformer,
        bytes calldata data,
        RewardCompoundParams calldata rewardParams)` external
  - `decreaseLiquidityAndCollect(DecreaseLiquidityAndCollectParams calldata params)` external
  - `liquidate(LiquidateParams calldata params)` external
  - `executeWithVault(ExecuteParams calldata params, address vault)` external
  - `executeWithVaultAndRewardCompound(ExecuteParams calldata params,
        address vault,
        IVault.RewardCompoundParams calldata rewardParams)` external
  - `autoCompoundWithVault(AutoCompoundParams calldata params, address vault)` external
  - `autoCompoundWithVaultAndRewardCompound(AutoCompoundParams calldata params,
        address vault,
        IVault.RewardCompoundParams calldata rewardParams)` external
  - `autoCompound(AutoCompoundParams calldata params)` external
  - `setAutoCompoundReward(uint64 _totalRewardX64)` external
  - `leverageUp(LeverageUpParams calldata params)` external
  - `leverageDown(LeverageDownParams calldata params)` external
  - `setVault(address _vault)` external
  - `executeWithPermit(uint256 tokenId, Instructions memory instructions, uint8 v, bytes32 r, bytes32 s)` public
  - `swap(SwapParams calldata params)` external
  - `swapAndMint(SwapAndMintParams calldata params)` external
  - `swapAndIncreaseLiquidity(SwapAndIncreaseLiquidityParams calldata params)` external
  - `latestRoundData()` external
  - `decimals()` external
  - `uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData)` external
  - `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data)` external
  - `getValue(uint256 tokenId, address token, bool ignoreFees)` external
  - `getTokenValue(address tokenIn, uint256 amountIn, address tokenOut)` external
  - `getPositionBreakdown(uint256 tokenId)` external
  - `getLiquidityAndFees(uint256 tokenId)` external
  - `setMaxPoolPriceDifference(uint16 _maxPoolPriceDifference)` external
  - `setTokenConfig(address token,
        AggregatorV3Interface feed,
        uint32 maxFeedAge,
        IUniswapV3Pool pool,
        uint32 twapSeconds,
        Mode mode,
        uint16 maxDifference)` external
  - `setOracleMode(address token, Mode mode)` external
  - `setSequencerUptimeFeed(address feed)` external
  - `setEmergencyAdmin(address admin)` external

## KEY STATE VARIABLES

isActive, token0Swap, token1Swap, onlyFees, positionConfigs, tokenId, amountRemoveMin0, amountRemoveMin1, deadline, token0, token1, amount0, amount1, feeAmount0, feeAmount1, amountOutMin, amountInDelta, amountOutDelta, swapAmount, isSwap

## Registry invariants that matched this target

These are GENERIC invariants from our knowledge base that pattern-matched.
Use them as STARTING POINTS, but generate SPECIFIC ones for this protocol.

- **[CRITICAL] INV-EXPLOIT-002**: Share inflation / first depositor attack prevention (confidence: 84%)
  Natural: Empty vaults must enforce minimum liquidity (burn initial shares to dead address) or use virtual shares/assets offset. The first depositor must not be able to manipulate the share exchange rate to steal from subsequent depositors. Share price must not be manipulable when totalSupply is near zero.
- **[CRITICAL] INV-ERC20-013**: Transfer should update accounting correctly (confidence: 100%)
  Natural: Valid transfers should update accounting correctly.
- **[CRITICAL] INV-ERC20-014**: TransferFrom should update accounting correctly (confidence: 100%)
  Natural: Valid transferFrom calls should update accounting correctly.
- **[CRITICAL] INV-V4626-002**: Zero supply iff zero assets (confidence: 100%)
  Natural: totalAssets must be zero if and only if totalSupply is zero. A vault with shares but no assets (or assets but no shares) indicates a critical accounting desync — the first depositor attack or a rounding drain.
- **[CRITICAL] INV-ERC20-017**: TransferFrom should decrease allowance correctly (confidence: 100%)
  Natural: After transferFrom, allowances should be updated correctly. Infinite allowance (type(uint256).max) may remain unchanged.
- **[CRITICAL] INV-EXPLOIT-013**: Unchecked return value on ERC20 transfer (confidence: 83%)
  Natural: All ERC20 transfer, transferFrom, and approve calls must check return values or use SafeERC20 wrappers. Tokens that return false on failure (instead of reverting) will silently fail, allowing state to advance without actual token movement. USDT notably does not return a value at all.
- **[CRITICAL] INV-ERC20-001**: Constant supply for non-mintable/non-burnable tokens (confidence: 100%)
  Natural: Total supply should be constant for non-mintable and non-burnable tokens.
- **[CRITICAL] INV-ERC20-002**: User balance must not exceed total supply (confidence: 100%)
  Natural: No user balance should be greater than the token's total supply.
- **[CRITICAL] INV-ERC20-003**: Sum of user balances must not exceed total supply (confidence: 100%)
  Natural: The sum of users balances should not be greater than the token's total supply.
- **[CRITICAL] INV-ERC20-009**: Transfer of more than balance should revert (confidence: 100%)
  Natural: Transfers for more than account balance should not be allowed.
- **[CRITICAL] INV-ERC20-010**: TransferFrom of more than balance should revert (confidence: 100%)
  Natural: TransferFrom for more than account balance should not be allowed.
- **[CRITICAL] INV-ERC20-021**: Mint should update balance and total supply correctly (confidence: 100%)
  Natural: User balance and total supply should be updated correctly after minting.
- **[CRITICAL] INV-EXPLOIT-018**: Token approval not cleared after use / dangerous approvals (confidence: 72%)
  Natural: Token approvals granted by a contract to external addresses must be carefully managed. Residual approvals left after operations can be exploited. Approvals to arbitrary-execution contracts are especially dangerous. The Coinbase hack exploited an accidental approval to a 0x swapper.
- **[HIGH] INV-ERC20-007**: Self transfer should not break accounting (confidence: 100%)
  Natural: Self transfers should not break accounting.
- **[HIGH] INV-ERC20-008**: Self transferFrom should not break accounting (confidence: 100%)
  Natural: Self transferFrom should not break accounting.


## SOURCE CODE


// ========== automators\AutoExit.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "./Automator.sol";

/// @title AutoExit
/// @notice Lets a v3 position to be automatically removed (limit order) or swapped to the opposite token (stop loss order) when it reaches a certain tick.
/// A revert controlled bot (operator) is responsable for the execution of optimized swaps (using external swap router)
/// Positions need to be approved (approve or setApprovalForAll) for the contract and configured with configToken method
contract AutoExit is Automator {
    event Executed(
        uint256 indexed tokenId,
        address account,
        bool isSwap,
        uint256 amountReturned0,
        uint256 amountReturned1,
        address token0,
        address token1
    );
    event PositionConfigured(
        uint256 indexed tokenId,
        bool isActive,
        bool token0Swap,
        bool token1Swap,
        int24 token0TriggerTick,
        int24 token1TriggerTick,
        uint64 token0SlippageX64,
        uint64 token1SlippageX64,
        bool onlyFees,
        uint64 maxRewardX64
    );

    constructor(
        INonfungiblePositionManager _npm,
        address _operator,
        address _withdrawer,
        uint32 _TWAPSeconds,
        uint16 _maxTWAPTickDifference,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Automator(_npm, _operator, _withdrawer, _TWAPSeconds, _maxTWAPTickDifference, _universalRouter, _zeroxAllowanceHolder) {}

    // define how stoploss / limit should be handled
    struct PositionConfig {
        bool isActive; // if position is active
        // should swap token to other token when triggered
        bool token0Swap;
        bool token1Swap;
        // when should action be triggered (when this tick is reached - allow execute)
        int24 token0TriggerTick; // when tick is below this one
        int24 token1TriggerTick; // when tick is equal or above this one
        // max price difference from current pool price for swap / Q64
        uint64 token0SlippageX64; // when token 0 is swapped to token 1
        uint64 token1SlippageX64; // when token 1 is swapped to token 0
        bool onlyFees; // if only fees maybe used for protocol reward
        uint64 maxRewardX64; // max allowed reward percentage of fees or full position
    }

    // configured tokens
    mapping(uint256 => PositionConfig) public positionConfigs;

    /// @notice params for execute()
    struct ExecuteParams {
        uint256 tokenId; // tokenid to process
        bytes swapData; // if its a swap order - must include swap data
        uint256 amountRemoveMin0; // min amount to be removed from liquidity
        uint256 amountRemoveMin1; // min amount to be removed from liquidity
        uint256 deadline; // for uniswap operations
        uint64 rewardX64; // which reward will be used for protocol, can be max configured amount (considering onlyFees)
    }

    struct ExecuteState {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        int24 currentTick;
        uint160 sqrtPriceX96;
        uint128 liquidity;
        uint256 amount0;
        uint256 amount1;
        uint256 feeAmount0;
        uint256 feeAmount1;
        uint256 amountOutMin;
        uint256 amountInDelta;
        uint256 amountOutDelta;
        IUniswapV3Pool pool;
        uint256 swapAmount;
        int24 tick;
        bool isSwap;
        bool isAbove;
        address owner;
    }

    /**
     * @notice Handle token (must be in correct state)
     * Can only be called only from configured operator account
     * Swap needs to be done with max price difference from current pool price - otherwise reverts
     */
    function execute(ExecuteParams calldata params) external {
        if (!operators[msg.sender]) {
            revert Unauthorized();
        }

        PositionConfig memory config = positionConfigs[params.tokenId];

        if (!config.isActive) {
            revert NotConfigured();
        }

        if (params.rewardX64 > config.maxRewardX64) {
            revert ExceedsMaxReward();
        }

        ExecuteState memory state;

        // get position info
        (,, state.token0, state.token1, state.fee, state.tickLower, state.tickUpper, state.liquidity,,,,) =
            nonfungiblePositionManager.positions(params.tokenId);

        // so can be executed only once
        if (state.liquidity == 0) {
            revert NoLiquidity();
        }

        state.pool = _getPool(state.token0, state.token1, state.fee);
        (, state.tick) = _getPoolSlot0(state.pool);

        // not triggered
        if (config.token0TriggerTick <= state.tick && state.tick < config.token1TriggerTick) {
            revert NotReady();
        }

        state.isAbove = state.tick >= config.token1TriggerTick;
        state.isSwap = !state.isAbove && config.token0Swap || state.isAbove && config.token1Swap;

        // decrease full liquidity for given position - and return fees as well
        (state.amount0, state.amount1, state.feeAmount0, state.feeAmount1) = _decreaseFullLiquidityAndCollect(
            params.tokenId, state.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline
        );

        // swap to other token
        if (state.isSwap) {
            if (params.swapData.length == 0) {
                revert MissingSwapData();
            }

            // reward is taken before swap - if from fees only
            if (config.onlyFees) {
                state.amount0 -= state.feeAmount0 * params.rewardX64 / Q64;
                state.amount1 -= state.feeAmount1 * params.rewardX64 / Q64;
            }

            state.swapAmount = state.isAbove ? state.amount1 : state.amount0;
            if (state.swapAmount != 0) {
                (state.sqrtPriceX96, state.currentTick) = _getPoolSlot0(state.pool);

                // checks if price in valid oracle range and calculates amountOutMin
                state.amountOutMin = _validateSwap(
                    !state.isAbove,
                    state.swapAmount,
                    state.pool,
                    state.currentTick,
                    state.sqrtPriceX96,
                    TWAPSeconds,
                    maxTWAPTickDifference,
                    state.isAbove ? config.token1SlippageX64 : config.token0SlippageX64
                );

                (state.amountInDelta, state.amountOutDelta) = _routerSwap(
                    Swapper.RouterSwapParams(
                        state.isAbove ? IERC20(state.token1) : IERC20(state.token0),
                        state.isAbove ? IERC20(state.token0) : IERC20(state.token1),
                        state.swapAmount,
                        state.amountOutMin,
                        params.swapData
                    )
                );

                state.amount0 =
                    state.isAbove ? state.amount0 + state.amountOutDelta : state.amount0 - state.amountInDelta;
                state.amount1 =
                    state.isAbove ? state.amount1 - state.amountInDelta : state.amount1 + state.amountOutDelta;
            }

            // when swap and !onlyFees - protocol reward is removed only from target token (to incentivize optimal swap done by operator)
            if (!config.onlyFees) {
                if (state.isAbove) {
                    state.amount0 -= state.amount0 * params.rewardX64 / Q64;
                } else {
                    state.amount1 -= state.amount1 * params.rewardX64 / Q64;
                }
            }
        } else {
            // reward is taken as configured
            state.amount0 -= (config.onlyFees ? state.feeAmount0 : state.amount0) * params.rewardX64 / Q64;
            state.amount1 -= (config.onlyFees ? state.feeAmount1 : state.amount1) * params.rewardX64 / Q64;
        }

        state.owner = nonfungiblePositionManager.ownerOf(params.tokenId);
        if (state.amount0 != 0) {
            _transferToken(state.owner, IERC20(state.token0), state.amount0, true);
        }
        if (state.amount1 != 0) {
            _transferToken(state.owner, IERC20(state.token1), state.amount1, true);
        }

        // delete config for position
        delete positionConfigs[params.tokenId];
        emit PositionConfigured(params.tokenId, false, false, false, 0, 0, 0, 0, false, 0);

        // log event
        emit Executed(
            params.tokenId, msg.sender, state.isSwap, state.amount0, state.amount1, state.token0, state.token1
        );
    }

    // function to configure a token to be used with this runner
    // it needs to have approvals set for this contract beforehand
    function configToken(uint256 tokenId, PositionConfig calldata config) external {
        if (config.isActive) {
            if (config.token0TriggerTick >= config.token1TriggerTick) {
                revert InvalidConfig();
            }
        }

        address owner = nonfungiblePositionManager.ownerOf(tokenId);
        if (owner != msg.sender) {
            revert Unauthorized();
        }

        positionConfigs[tokenId] = config;

        emit PositionConfigured(
            tokenId,
            config.isActive,
            config.token0Swap,
            config.token1Swap,
            config.token0TriggerTick,
            config.token1TriggerTick,
            config.token0SlippageX64,
            config.token1SlippageX64,
            config.onlyFees,
            config.maxRewardX64
        );
    }
}


// ========== automators\Automator.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "v3-core/interfaces/IUniswapV3Factory.sol";
import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-core/libraries/TickMath.sol";

import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "../../lib/IWETH9.sol";
import "../utils/Swapper.sol";
import "../interfaces/IVault.sol";
import "../interfaces/IProtocolFeeController.sol";

abstract contract Automator is Ownable2Step, Swapper, IProtocolFeeController {
    uint32 public constant MIN_TWAP_SECONDS = 60; // 1 minute
    uint32 public constant MAX_TWAP_TICK_DIFFERENCE = 200; // 2%

    // admin events
    event OperatorChanged(address newOperator, bool active);
    event TWAPConfigChanged(uint32 TWAPSeconds, uint16 maxTWAPTickDifference);

    // configurable by owner
    mapping(address => bool) public operators;

    address public override withdrawer;
    uint32 public TWAPSeconds;
    uint16 public maxTWAPTickDifference;

    error ZeroAddress();

    constructor(
        INonfungiblePositionManager npm,
        address _operator,
        address _withdrawer,
        uint32 _TWAPSeconds,
        uint16 _maxTWAPTickDifference,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Swapper(npm, _universalRouter, _zeroxAllowanceHolder) {
        setOperator(_operator, true);
        setWithdrawer(_withdrawer);
        setTWAPConfig(_maxTWAPTickDifference, _TWAPSeconds);
    }

    /**
     * @notice Owner controlled function to set withdrawer address
     * @param _withdrawer withdrawer
     */
    function setWithdrawer(address _withdrawer) public virtual override onlyOwner {
        if (_withdrawer == address(0)) {
            revert InvalidConfig();
        }
        emit WithdrawerChanged(_withdrawer);
        withdrawer = _withdrawer;
    }

    /**
     * @notice Owner controlled function to activate/deactivate operator address
     * @param _operator operator
     * @param _active active or not
     */
    function setOperator(address _operator, bool _active) public onlyOwner {
        emit OperatorChanged(_operator, _active);
        operators[_operator] = _active;
    }

    /**
     * @notice Owner controlled function to increase TWAPSeconds / decrease maxTWAPTickDifference
     */
    function setTWAPConfig(uint16 _maxTWAPTickDifference, uint32 _TWAPSeconds) public onlyOwner {
        if (_TWAPSeconds < MIN_TWAP_SECONDS) {
            revert InvalidConfig();
        }
        if (_maxTWAPTickDifference > MAX_TWAP_TICK_DIFFERENCE) {
            revert InvalidConfig();
        }
        emit TWAPConfigChanged(_TWAPSeconds, _maxTWAPTickDifference);
        TWAPSeconds = _TWAPSeconds;
        maxTWAPTickDifference = _maxTWAPTickDifference;
    }

    /**
     * @notice Withdraws token balance (accumulated protocol fee)
     * @param tokens Addresses of tokens to withdraw
     * @param to Address to send to
     */
    function withdrawBalances(address[] calldata tokens, address to) external virtual override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 i;
        uint256 count = tokens.length;
        address token;
        uint256 balance;
        for (; i < count; ++i) {
            token = tokens[i];
            balance = IERC20(token).balanceOf(address(this));
            if (balance != 0) {
                _transferToken(to, IERC20(token), balance, true);
            }
        }
    }

    /**
     * @notice Withdraws ETH balance
     * @param to Address to send to
     */
    function withdrawETH(address to) external override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 balance = address(this).balance;
        if (balance != 0) {
            (bool sent,) = to.call{value: balance}("");
            if (!sent) {
                revert EtherSendFailed();
            }
        }
    }

    function _decreaseFullLiquidityAndCollect(
        uint256 tokenId,
        uint128 liquidity,
        uint256 amountRemoveMin0,
        uint256 amountRemoveMin1,
        uint256 deadline
    ) internal returns (uint256 amount0, uint256 amount1, uint256 feeAmount0, uint256 feeAmount1) {
        if (liquidity != 0) {
            // store in temporarely "misnamed" variables - see comment below
            (feeAmount0, feeAmount1) = nonfungiblePositionManager.decreaseLiquidity(
                INonfungiblePositionManager.DecreaseLiquidityParams(
                    tokenId, liquidity, amountRemoveMin0, amountRemoveMin1, deadline
                )
            );
        }
        (amount0, amount1) = nonfungiblePositionManager.collect(
            INonfungiblePositionManager.CollectParams(tokenId, address(this), type(uint128).max, type(uint128).max)
        );

        // fee amount is what was collected additionally to liquidity amount
        feeAmount0 = amount0 - feeAmount0;
        feeAmount1 = amount1 - feeAmount1;
    }

    // transfers token (or unwraps WETH and sends ETH)
    function _transferToken(address to, IERC20 token, uint256 amount, bool unwrap) internal {
        if (unwrap && address(weth) == address(token)) {
            weth.withdraw(amount);
            (bool sent,) = to.call{value: amount}("");
            if (!sent) {
                revert EtherSendFailed();
            }
        } else {
            SafeERC20.safeTransfer(token, to, amount);
        }
    }

    // needed for WETH unwrapping
    receive() external payable {
        if (msg.sender != address(weth)) {
            revert NotWETH();
        }
    }
}


// ========== GaugeManager.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "./interfaces/IVault.sol";
import "./interfaces/IGaugeManager.sol";
import "./interfaces/aerodrome/IAerodromeSlipstreamFactory.sol";
import "./interfaces/aerodrome/IAerodromeSlipstreamPool.sol";
import "./interfaces/aerodrome/IGauge.sol";
import "./utils/Swapper.sol";

/// @notice Gauge helper for vaulted positions.
contract GaugeManager is Ownable2Step, ReentrancyGuard, IERC721Receiver, Swapper, IGaugeManager {
    using SafeERC20 for IERC20;

    uint64 public constant MAX_REWARD_X64 = 368_934_881_474_191_032; // floor(Q64 / 50)
    // Reward compounding validates each fixed route hop against both TWAP deviation and a minimum output bound
    // derived from the current pool price before executing the swap.
    uint32 private constant REWARD_TWAP_SECONDS = 60;
    uint16 private constant REWARD_MAX_TWAP_TICK_DIFFERENCE = 200;
    uint64 private constant REWARD_MAX_PRICE_DIFFERENCE_X64 = 368_934_881_474_191_032; // floor(Q64 / 50)

    IERC20 public immutable aeroToken;
    IVault public immutable vault;
    address public override withdrawer;
    uint64 public totalRewardX64 = MAX_REWARD_X64; // 2%

    mapping(address => address) public override poolToGauge;
    mapping(uint256 => address) public override tokenIdToGauge;
    mapping(address => address) public override rewardBasePools;

    struct CompoundState {
        address gauge;
        address owner;
        address token0;
        address token1;
        IUniswapV3Pool positionPool;
        uint256 aeroAmount;
        uint256 spentAero;
        uint256 amount0Out;
        uint256 amount1Out;
        uint256 maxAddAmount0;
        uint256 maxAddAmount1;
        uint256 amountAdded0;
        uint256 amountAdded1;
        uint256 rewardAmount0;
        uint256 rewardAmount1;
    }

    constructor(
        INonfungiblePositionManager _npm,
        IERC20 _aeroToken,
        IVault _vault,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Swapper(_npm, _universalRouter, _zeroxAllowanceHolder) {
        if (address(_aeroToken) == address(0) || address(_vault) == address(0)) {
            revert InvalidConfig();
        }

        aeroToken = _aeroToken;
        vault = _vault;
        withdrawer = msg.sender;

        emit WithdrawerChanged(msg.sender);
    }

    function setGauge(address pool, address gauge) external override onlyOwner {
        if (pool == address(0) || gauge == address(0)) {
            revert InvalidConfig();
        }

        (bool success, bytes memory data) =
            pool.staticcall(abi.encodeWithSelector(IAerodromeSlipstreamPool.gauge.selector));
        if (!success || data.length < 32 || abi.decode(data, (address)) != gauge) {
            revert InvalidPool();
        }

        poolToGauge[pool] = gauge;
        emit GaugeSet(pool, gauge);
    }

    function setRewardBasePool(address baseToken, address pool) external override onlyOwner {
        if (baseToken == address(0) || baseToken == address(aeroToken)) {
            revert InvalidConfig();
        }

        if (pool == address(0)) {
            delete rewardBasePools[baseToken];
            emit RewardBasePoolSet(baseToken, address(0));
            return;
        }

        IAerodromeSlipstreamPool slipstreamPool = IAerodromeSlipstreamPool(pool);
        address token0 = slipstreamPool.token0();
        address token1 = slipstreamPool.token1();
        if (!(token0 == address(aeroToken) && token1 == baseToken || token0 == baseToken && token1 == address(aeroToken)))
        {
            revert InvalidPool();
        }

        address resolved = IAerodromeSlipstreamFactory(factory).getPool(token0, token1, slipstreamPool.tickSpacing());
        if (resolved != pool) {
            revert InvalidPool();
        }

        rewardBasePools[baseToken] = pool;
        emit RewardBasePoolSet(baseToken, pool);
    }

    function setWithdrawer(address _withdrawer) external override onlyOwner {
        if (_withdrawer == address(0)) {
            revert InvalidConfig();
        }
        withdrawer = _withdrawer;
        emit WithdrawerChanged(_withdrawer);
    }

    function withdrawBalances(address[] calldata tokens, address to) external override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 i;
        uint256 count = tokens.length;
        address token;
        uint256 balance;
        for (; i < count; ++i) {
            token = tokens[i];
            balance = IERC20(token).balanceOf(address(this));
            if (balance != 0) {
                IERC20(token).safeTransfer(to, balance);
            }
        }
    }

    function withdrawETH(address to) external override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 balance = address(this).balance;
        if (balance != 0) {
            (bool sent,) = to.call{value: balance}("");
            if (!sent) {
                revert EtherSendFailed();
            }
        }
    }

    function stakePosition(uint256 tokenId) external override nonReentrant {
        _requireVaultCaller();
        if (tokenIdToGauge[tokenId] != address(0)) {
            revert InvalidConfig();
        }

        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) {
            revert Unauthorized();
        }

        if (nonfungiblePositionManager.ownerOf(tokenId) != address(vault)) {
            revert Unauthorized();
        }

        (,, address token0, address token1, uint24 feeOrTickSpacing,,,,,,,) =
            nonfungiblePositionManager.positions(tokenId);

        IUniswapV3Pool pool = _getPool(token0, token1, feeOrTickSpacing);
        address gauge = poolToGauge[address(pool)];
        if (gauge == address(0)) {
            revert NotConfigured();
        }

        uint256 token0Before = IERC20(token0).balanceOf(address(this));
        uint256 token1Before = IERC20(token1).balanceOf(address(this));
        nonfungiblePositionManager.safeTransferFrom(address(vault), address(this), tokenId);
        nonfungiblePositionManager.approve(gauge, tokenId);
        IGauge(gauge).deposit(tokenId);
        // Slipstream CLGauge.deposit triggers NPM.collect to msg.sender, so any pre-stake accrued token0/token1
        // fees are realized during staking and forwarded here to the position owner.
        _sendDepositDeltas(token0, token1, owner, token0Before, token1Before);

        // NOTE FOR AUDITS:
        // We intentionally do not enforce `ownerOf(tokenId) == gauge` post-deposit here.
        // Some gauge implementations may custody via intermediate contracts/wrappers while still exposing
        // the configured gauge as the canonical integration endpoint for getReward/withdraw.
        // This is an accepted trust-boundary assumption on configured gauges.
        // Vault-side `_stake()` still enforces that custody leaves the vault to block no-op managers.
        tokenIdToGauge[tokenId] = gauge;
        emit PositionStaked(tokenId, owner, gauge);
    }

    function unstakePosition(uint256 tokenId) external override nonReentrant {
        _requireVaultCaller();

        bool wasStaked = _unstakePosition(tokenId);
        if (!wasStaked) {
            revert NotStaked();
        }
    }

    function unstakeIfStaked(uint256 tokenId) external override nonReentrant returns (bool wasStaked) {
        _requireVaultCaller();
        return _unstakePosition(tokenId);
    }

    function _unstakePosition(uint256 tokenId) internal returns (bool wasStaked) {
        address gauge = tokenIdToGauge[tokenId];
        if (gauge == address(0)) {
            return false;
        }

        address owner = vault.ownerOf(tokenId);
        _claimAndSendRewardsBestEffort(gauge, tokenId, owner);
        IGauge(gauge).withdraw(tokenId);
        // Intentionally no token0/token1 forwarding on plain unstake:
        // while staked in Slipstream gauge, swap fees accrue to gauge-side accounting (not as NFT collectable fees),
        // and CLGauge.deposit already collects any pre-stake NFT fees when staking.
        nonfungiblePositionManager.safeTransferFrom(address(this), address(vault), tokenId, abi.encode(owner));
        delete tokenIdToGauge[tokenId];
        emit PositionUnstaked(tokenId, owner, gauge);
        return true;
    }

    function claimRewards(uint256 tokenId, address recipient)
        external
        override
        nonReentrant
        returns (uint256 aeroAmount)
    {
        address owner = _requireVaultOrOwner(tokenId);
        address gauge = _requireStakedGauge(tokenId);

        if (recipient == address(0)) {
            recipient = owner;
        }
        aeroAmount = _claimAndSendRewards(gauge, tokenId, recipient);
        emit RewardsClaimed(tokenId, owner, aeroAmount);
    }

    function compoundRewards(
        uint256 tokenId,
        uint256 minAeroReward,
        uint256 aeroSplitBps,
        uint256 deadline
    ) external override nonReentrant returns (uint256 aeroAmount, uint256 amountAdded0, uint256 amountAdded1) {
        address owner = _requireVaultOrOwner(tokenId);
        if (aeroSplitBps > 10_000) {
            revert InvalidConfig();
        }

        CompoundState memory state;
        state.gauge = _requireStakedGauge(tokenId);
        uint24 feeOrTickSpacing;
        (,, state.token0, state.token1, feeOrTickSpacing,,,,,,,) = nonfungiblePositionManager.positions(tokenId);
        state.positionPool = _getPool(state.token0, state.token1, feeOrTickSpacing);
        state.owner = owner;

        state.aeroAmount = _claimRewardsToSelf(state.gauge, tokenId);
        if (state.aeroAmount < minAeroReward) {
            revert NotEnoughReward();
        }
        if (state.aeroAmount == 0) {
            return (0, 0, 0);
        }

        IGauge(state.gauge).withdraw(tokenId);
        state = _swapAeroForPosition(state, aeroSplitBps);
        state = _addLiquidity(state, tokenId, deadline);
        uint256 token0BeforeDeposit = IERC20(state.token0).balanceOf(address(this));
        uint256 token1BeforeDeposit = IERC20(state.token1).balanceOf(address(this));
        nonfungiblePositionManager.approve(state.gauge, tokenId);
        IGauge(state.gauge).deposit(tokenId);
        // Aerodrome deposit can realize NFT fees to msg.sender; forward those user-owned proceeds before
        // accounting for compounding leftovers so they do not become protocol-withdrawable dust.
        _sendDepositDeltas(state.token0, state.token1, state.owner, token0BeforeDeposit, token1BeforeDeposit);
        _sendLeftoversAndRewards(state);

        emit RewardsCompounded(tokenId, state.owner, state.aeroAmount, state.amountAdded0, state.amountAdded1);
        return (state.aeroAmount, state.amountAdded0, state.amountAdded1);
    }

    function setCompoundReward(uint64 _totalRewardX64) external override onlyOwner {
        if (_totalRewardX64 > totalRewardX64) {
            revert InvalidConfig();
        }
        totalRewardX64 = _totalRewardX64;
        emit CompoundRewardUpdated(msg.sender, _totalRewardX64);
    }

    function _claimAndSendRewards(address gauge, uint256 tokenId, address recipient)
        internal
        returns (uint256 aeroAmount)
    {
        aeroAmount = _claimRewardsToSelf(gauge, tokenId);
        _sendAeroIfAny(recipient, aeroAmount);
    }

    function _claimAndSendRewardsBestEffort(address gauge, uint256 tokenId, address recipient) internal {
        uint256 aeroAmount = _claimRewardsToSelfBestEffort(gauge, tokenId);
        _sendAeroIfAny(recipient, aeroAmount);
    }

    function _claimRewardsToSelf(address gauge, uint256 tokenId) internal returns (uint256 aeroAmount) {
        uint256 aeroBefore = aeroToken.balanceOf(address(this));
        IGauge(gauge).getReward(tokenId);
        aeroAmount = aeroToken.balanceOf(address(this)) - aeroBefore;
    }

    function _claimRewardsToSelfBestEffort(address gauge, uint256 tokenId) internal returns (uint256 aeroAmount) {
        uint256 aeroBefore = aeroToken.balanceOf(address(this));
        // Liveness over reward payout: unstake/remove/liquidation must not depend on a successful reward claim.
        try IGauge(gauge).getReward(tokenId) {
            uint256 aeroAfter = aeroToken.balanceOf(address(this));
            if (aeroAfter > aeroBefore) {
                aeroAmount = aeroAfter - aeroBefore;
            }
        } catch {}
    }

    function _requireVaultCaller() internal view {
        if (msg.sender != address(vault)) {
            revert Unauthorized();
        }
    }

    function _requireVaultOrOwner(uint256 tokenId) internal returns (address owner) {
        owner = vault.ownerOf(tokenId);
        if (msg.sender != address(vault) && msg.sender != owner) {
            revert Unauthorized();
        }
    }

    function _requireStakedGauge(uint256 tokenId) internal view returns (address gauge) {
        gauge = tokenIdToGauge[tokenId];
        if (gauge == address(0)) {
            revert NotStaked();
        }
    }

    function _sendAeroIfAny(address recipient, uint256 amount) internal {
        if (amount != 0) {
            aeroToken.safeTransfer(recipient, amount);
        }
    }

    function _sendDepositDeltas(
        address token0,
        address token1,
        address recipient,
        uint256 token0Before,
        uint256 token1Before
    ) internal {
        uint256 token0After = IERC20(token0).balanceOf(address(this));
        uint256 token1After = IERC20(token1).balanceOf(address(this));
        if (token0After > token0Before) {
            IERC20(token0).safeTransfer(recipient, token0After - token0Before);
        }
        if (token1After > token1Before) {
            IERC20(token1).safeTransfer(recipient, token1After - token1Before);
        }
    }

    function _swapAeroForPosition(
        CompoundState memory state,
        uint256 aeroSplitBps
    ) internal returns (CompoundState memory) {
        uint256 requestedAero0 = state.aeroAmount * aeroSplitBps / 10_000;
        uint256 requestedAero1 = state.aeroAmount - requestedAero0;

        (uint256 spentAero0, uint256 amount0Out) =
            _swapAeroToTarget(state.positionPool, state.token0, state.token1, requestedAero0);
        (uint256 spentAero1, uint256 amount1Out) =
            _swapAeroToTarget(state.positionPool, state.token1, state.token0, requestedAero1);

        state.spentAero = spentAero0 + spentAero1;
        state.amount0Out = amount0Out;
        state.amount1Out = amount1Out;
        return state;
    }

    function _swapAeroToTarget(IUniswapV3Pool positionPool, address targetToken, address otherToken, uint256 amountIn)
        internal
        returns (uint256 spentAero, uint256 amountOut)
    {
        if (amountIn == 0) {
            return (0, 0);
        }

        if (targetToken == address(aeroToken)) {
            return (amountIn, amountIn);
        }

        address directPool = rewardBasePools[targetToken];
        if (directPool != address(0)) {
            amountOut = _swapThroughPool(IUniswapV3Pool(directPool), address(aeroToken), targetToken, amountIn);
            return (amountIn, amountOut);
        }

        address intermediatePool = rewardBasePools[otherToken];
        if (intermediatePool == address(0)) {
            revert NotConfigured();
        }

        uint256 intermediateAmount =
            _swapThroughPool(IUniswapV3Pool(intermediatePool), address(aeroToken), otherToken, amountIn);
        amountOut = _swapThroughPool(positionPool, otherToken, targetToken, intermediateAmount);
        return (amountIn, amountOut);
    }

    function _swapThroughPool(IUniswapV3Pool pool, address tokenIn, address tokenOut, uint256 amountIn)
        internal
        returns (uint256 amountOut)
    {
        if (amountIn == 0) {
            return 0;
        }

        address poolToken0 = IAerodromeSlipstreamPool(address(pool)).token0();
        address poolToken1 = IAerodromeSlipstreamPool(address(pool)).token1();
        bool swap0For1;
        if (poolToken0 == tokenIn && poolToken1 == tokenOut) {
            swap0For1 = true;
        } else if (poolToken0 == tokenOut && poolToken1 == tokenIn) {
            swap0For1 = false;
        } else {
            revert InvalidPool();
        }

        (uint160 sqrtPriceX96, int24 currentTick) = _getPoolSlot0(pool);
        uint256 amountOutMin = _validateSwap(
            swap0For1,
            amountIn,
            pool,
            currentTick,
            sqrtPriceX96,
            REWARD_TWAP_SECONDS,
            REWARD_MAX_TWAP_TICK_DIFFERENCE,
            REWARD_MAX_PRICE_DIFFERENCE_X64
        );
        (, amountOut) = _poolSwap(
            PoolSwapParams({
                pool: pool,
                token0: IERC20(poolToken0),
                token1: IERC20(poolToken1),
                fee: _poolFeeOrTickSpacing(pool),
                swap0For1: swap0For1,
                amountIn: amountIn,
                amountOutMin: amountOutMin
            })
        );
    }

    function _poolFeeOrTickSpacing(IUniswapV3Pool pool) internal view returns (uint24 feeOrTickSpacing) {
        int24 tickSpacing = IAerodromeSlipstreamPool(address(pool)).tickSpacing();
        if (tickSpacing <= 0) {
            revert InvalidPool();
        }
        assembly ("memory-safe") {
            feeOrTickSpacing := tickSpacing
        }
    }

    function _addLiquidity(CompoundState memory state, uint256 tokenId, uint256 deadline)
        internal
        returns (CompoundState memory)
    {
        uint256 rewardX64 = totalRewardX64;
        state.maxAddAmount0 = state.amount0Out * Q64 / (rewardX64 + Q64);
        state.maxAddAmount1 = state.amount1Out * Q64 / (rewardX64 + Q64);

        if (state.maxAddAmount0 != 0) {
            IERC20(state.token0).safeIncreaseAllowance(address(nonfungiblePositionManager), state.maxAddAmount0);
        }
        if (state.maxAddAmount1 != 0) {
            IERC20(state.token1).safeIncreaseAllowance(address(nonfungiblePositionManager), state.maxAddAmount1);
        }

        if (state.maxAddAmount0 != 0 || state.maxAddAmount1 != 0) {
            (, state.amountAdded0, state.amountAdded1) = nonfungiblePositionManager.increaseLiquidity(
                INonfungiblePositionManager.IncreaseLiquidityParams(
                    tokenId, state.maxAddAmount0, state.maxAddAmount1, 0, 0, deadline
                )
            );
            state.rewardAmount0 = state.amountAdded0 * rewardX64 / Q64;
            state.rewardAmount1 = state.amountAdded1 * rewardX64 / Q64;
        }

        if (state.maxAddAmount0 != 0) {
            IERC20(state.token0).safeApprove(address(nonfungiblePositionManager), 0);
        }
        if (state.maxAddAmount1 != 0) {
            IERC20(state.token1).safeApprove(address(nonfungiblePositionManager), 0);
        }

        return state;
    }

    function _sendLeftoversAndRewards(CompoundState memory state) internal {
        uint256 leftoverAero = state.aeroAmount - state.spentAero;
        if (leftoverAero != 0) {
            aeroToken.safeTransfer(state.owner, leftoverAero);
        }

        uint256 leftover0 = state.amount0Out - state.amountAdded0 - state.rewardAmount0;
        uint256 leftover1 = state.amount1Out - state.amountAdded1 - state.rewardAmount1;
        if (leftover0 != 0) {
            IERC20(state.token0).safeTransfer(state.owner, leftover0);
        }
        if (leftover1 != 0) {
            IERC20(state.token1).safeTransfer(state.owner, leftover1);
        }
        // protocol rewards (rewardAmount0/rewardAmount1) remain in this contract and can be collected
        // through withdrawBalances by the configured withdrawer.
    }

    function onERC721Received(address, address from, uint256 tokenId, bytes calldata)
        external
        view
        override
        returns (bytes4)
    {
        if (msg.sender != address(nonfungiblePositionManager)) {
            revert WrongContract();
        }
        // Accept only protocol-managed custody hops:
        // - Vault -> GaugeManager during stake flow (mapping not set yet)
        // - Gauge -> GaugeManager during unstake flow (mapping points to source gauge)
        if (from != address(vault) && from != tokenIdToGauge[tokenId]) {
            revert Unauthorized();
        }
        return IERC721Receiver.onERC721Received.selector;
    }
}


// ========== InterestRateModel.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

import "./interfaces/IInterestRateModel.sol";
import "./utils/Constants.sol";

/// @title Model for interest rate calculation used in Vault
/// @notice Calculates both borrow and supply rate
contract InterestRateModel is Ownable, IInterestRateModel, Constants {

    uint256 public constant YEAR_SECS = 31557600; // taking into account leap years

    uint256 public constant MAX_BASE_RATE_X64 = Q64 / 10; // 10%
    uint256 public constant MAX_MULTIPLIER_X64 = Q64 * 2; // 200%

    event SetValues(
        uint256 baseRatePerYearX64, uint256 multiplierPerYearX64, uint256 jumpMultiplierPerYearX64, uint256 kinkX64
    );

    // all values are multiplied by Q64
    uint64 public multiplierPerSecondX64;
    uint64 public baseRatePerSecondX64;
    uint64 public jumpMultiplierPerSecondX64;
    uint64 public kinkX64;

    /// @notice Creates interest rate model
    /// @param baseRatePerYearX64 Base rate per year multiplied by Q64
    /// @param multiplierPerYearX64 Multiplier for utilization rate below kink multiplied by Q64
    /// @param jumpMultiplierPerYearX64 Multiplier for utilization rate above kink multiplied by Q64
    /// @param _kinkX64 Kink percentage multiplied by Q64
    constructor(
        uint256 baseRatePerYearX64,
        uint256 multiplierPerYearX64,
        uint256 jumpMultiplierPerYearX64,
        uint256 _kinkX64
    ) {
        setValues(baseRatePerYearX64, multiplierPerYearX64, jumpMultiplierPerYearX64, _kinkX64);
    }

    /// @notice Returns utilization rate X64 given cash and debt
    /// @param cash Current available cash
    /// @param debt Current debt
    /// @return Utilization rate between 0 and Q64
    function getUtilizationRateX64(uint256 cash, uint256 debt) public pure returns (uint256) {
        if (debt == 0) {
            return 0;
        }
        return debt * Q64 / (cash + debt);
    }

    /// @notice Returns interest rates X64 given cash and debt
    /// @param cash Current available cash
    /// @param debt Current debt
    /// @return borrowRateX64 borrow rate multiplied by Q64
    /// @return supplyRateX64 supply rate multiplied by Q64
    function getRatesPerSecondX64(uint256 cash, uint256 debt)
        public
        view
        override
        returns (uint256 borrowRateX64, uint256 supplyRateX64)
    {
        uint256 utilizationRateX64 = getUtilizationRateX64(cash, debt);

        if (utilizationRateX64 <= kinkX64) {
            borrowRateX64 = (utilizationRateX64 * multiplierPerSecondX64 / Q64) + baseRatePerSecondX64;
        } else {
            uint256 normalRateX64 = (uint256(kinkX64) * multiplierPerSecondX64 / Q64) + baseRatePerSecondX64;
            uint256 excessUtilX64 = utilizationRateX64 - kinkX64;
            borrowRateX64 = (excessUtilX64 * jumpMultiplierPerSecondX64 / Q64) + normalRateX64;
        }

        supplyRateX64 = utilizationRateX64 * borrowRateX64 / Q64;
    }

    /// @notice Update interest rate values (onlyOwner)
    /// @param baseRatePerYearX64 Base rate per year multiplied by Q64
    /// @param multiplierPerYearX64 Multiplier for utilization rate below kink multiplied by Q64
    /// @param jumpMultiplierPerYearX64 Multiplier for utilization rate above kink multiplied by Q64
    /// @param _kinkX64 Kink percentage multiplied by Q64
    function setValues(
        uint256 baseRatePerYearX64,
        uint256 multiplierPerYearX64,
        uint256 jumpMultiplierPerYearX64,
        uint256 _kinkX64
    ) public onlyOwner {
        if (
            baseRatePerYearX64 > MAX_BASE_RATE_X64 || multiplierPerYearX64 > MAX_MULTIPLIER_X64
                || jumpMultiplierPerYearX64 > MAX_MULTIPLIER_X64
        ) {
            revert InvalidConfig();
        }

        baseRatePerSecondX64 = SafeCast.toUint64(baseRatePerYearX64 / YEAR_SECS);
        multiplierPerSecondX64 = SafeCast.toUint64(multiplierPerYearX64 / YEAR_SECS);
        jumpMultiplierPerSecondX64 = SafeCast.toUint64(jumpMultiplierPerYearX64 / YEAR_SECS);
        kinkX64 = SafeCast.toUint64(_kinkX64);

        emit SetValues(baseRatePerYearX64, multiplierPerYearX64, jumpMultiplierPerYearX64, _kinkX64);
    }
}


// ========== interfaces\aerodrome\IAerodromeNonfungiblePositionManager.sol ==========
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

/// @notice Aerodrome Slipstream position manager keeps Uniswap V3-compatible ABI.
interface IAerodromeNonfungiblePositionManager is INonfungiblePositionManager {}


// ========== interfaces\aerodrome\IAerodromeSlipstreamFactory.sol ==========
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

interface IAerodromeSlipstreamFactory {
    function getPool(address tokenA, address tokenB, int24 tickSpacing) external view returns (address pool);
}


// ========== interfaces\aerodrome\IAerodromeSlipstreamPool.sol ==========
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

interface IAerodromeSlipstreamPool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            bool unlocked
        );

    function fee() external view returns (uint24);

    function positions(bytes32 key)
        external
        view
        returns (
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        );

    function observations(uint256 index)
        external
        view
        returns (uint32 blockTimestamp, int56 tickCumulative, uint160 secondsPerLiquidityPostWriteX128, bool initialized);

    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityPostWriteX128s);

    function tickSpacing() external view returns (int24);

    function token0() external view returns (address);
    function token1() external view returns (address);
    function feeGrowthGlobal0X128() external view returns (uint256);
    function feeGrowthGlobal1X128() external view returns (uint256);

    function ticks(int24 tick)
        external
        view
        returns (
            uint128 liquidityGross,
            int128 liquidityNet,
            int128 stakedLiquidityNet,
            uint256 feeGrowthOutside0X128,
            uint256 feeGrowthOutside1X128,
            uint256 rewardGrowthOutsideX128,
            int56 tickCumulativeOutside,
            uint160 secondsPerLiquidityOutsideX128,
            uint32 secondsOutside,
            bool initialized
        );

    function gauge() external view returns (address);
}


// ========== interfaces\aerodrome\IGauge.sol ==========
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

interface IGauge {
    function deposit(uint256 tokenId) external;
    function withdraw(uint256 tokenId) external;
    function getReward(uint256 tokenId) external;
}


// ========== interfaces\IGaugeManager.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "./IProtocolFeeController.sol";

interface IGaugeManager is IProtocolFeeController {
    event PositionStaked(uint256 indexed tokenId, address indexed owner, address indexed gauge);
    event PositionUnstaked(uint256 indexed tokenId, address indexed owner, address indexed gauge);
    event RewardsClaimed(uint256 indexed tokenId, address indexed owner, uint256 aeroAmount);
    event RewardsCompounded(
        uint256 indexed tokenId, address indexed owner, uint256 aeroAmount, uint256 amountAdded0, uint256 amountAdded1
    );
    event CompoundRewardUpdated(address account, uint64 totalRewardX64);
    event GaugeSet(address indexed pool, address indexed gauge);
    event RewardBasePoolSet(address indexed baseToken, address indexed pool);

    function poolToGauge(address pool) external view returns (address);
    function tokenIdToGauge(uint256 tokenId) external view returns (address);
    function rewardBasePools(address baseToken) external view returns (address pool);

    function setGauge(address pool, address gauge) external;
    function setRewardBasePool(address baseToken, address pool) external;

    function stakePosition(uint256 tokenId) external;
    function unstakePosition(uint256 tokenId) external;
    function unstakeIfStaked(uint256 tokenId) external returns (bool wasStaked);

    function claimRewards(uint256 tokenId, address recipient) external returns (uint256 aeroAmount);

    function compoundRewards(
        uint256 tokenId,
        uint256 minAeroReward,
        uint256 aeroSplitBps,
        uint256 deadline
    ) external returns (uint256 aeroAmount, uint256 amountAdded0, uint256 amountAdded1);

    function setCompoundReward(uint64 _totalRewardX64) external;
}


// ========== interfaces\IInterestRateModel.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IInterestRateModel {
    // gets borrow and supply interest rate per second
    function getRatesPerSecondX64(uint256 cash, uint256 debt)
        external
        view
        returns (uint256 borrowRateX64, uint256 supplyRateX64);
}


// ========== interfaces\IProtocolFeeController.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IProtocolFeeController {
    event WithdrawerChanged(address newWithdrawer);

    function withdrawer() external view returns (address);
    function setWithdrawer(address _withdrawer) external;
    function withdrawBalances(address[] calldata tokens, address to) external;
    function withdrawETH(address to) external;
}


// ========== interfaces\IV3Oracle.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

interface IV3Oracle {
    function isTokenConfigured(address token) external view returns (bool configured);

    function getTokenValue(address tokenIn, uint256 amountIn, address tokenOut) external view returns (uint256 value);

    // gets value and prices for a given v3 nft denominated in token
    // reverts if any involved token is not configured
    // reverts if prices are not valid given oracle configuration
    function getValue(uint256 tokenId, address token, bool ignoreFees)
        external
        view
        returns (uint256 value, uint256 feeValue, uint256 price0X96, uint256 price1X96);

    // gets breakdown of position specifying liquidity amounts and available fee amounts
    function getPositionBreakdown(uint256 tokenId)
        external
        view
        returns (
            address token0,
            address token1,
            uint24 fee,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1,
            uint128 fees0,
            uint128 fees1
        );

    // gets liquidity and uncollected fees from position
    function getLiquidityAndFees(uint256 tokenId)
        external
        view
        returns (uint128 liquidity, uint128 fees0, uint128 fees1);
}


// ========== interfaces\IVault.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC4626.sol";

interface IVault is IERC4626 {
    function transformedTokenId() external view returns (uint256 tokenId);

    function loans(uint256 tokenId) external view returns (uint256 debtShares);

    function vaultInfo()
        external
        view
        returns (
            uint256 debt,
            uint256 lent,
            uint256 balance,
            uint256 reserves,
            uint256 debtExchangeRateX96,
            uint256 lendExchangeRateX96
        );
    function lendInfo(address account) external view returns (uint256 amount);
    function loanInfo(uint256 tokenId)
        external
        view
        returns (
            uint256 debt,
            uint256 fullValue,
            uint256 collateralValue,
            uint256 liquidationCost,
            uint256 liquidationValue
        );

    function ownerOf(uint256 tokenId) external returns (address);

    // functions for iterating over owners loans
    function loanCount(address owner) external view returns (uint256);
    function loanAtIndex(address owner, uint256 index) external view returns (uint256);

    function create(uint256 tokenId, address recipient) external;

    function approveTransform(uint256 tokenId, address target, bool active) external;
    function transform(uint256 tokenId, address transformer, bytes calldata data) external returns (uint256);

    struct RewardCompoundParams {
        uint256 minAeroReward;
        uint256 aeroSplitBps;
        uint256 deadline;
    }

    function transformWithRewardCompound(
        uint256 tokenId,
        address transformer,
        bytes calldata data,
        RewardCompoundParams calldata rewardParams
    ) external returns (uint256 newTokenId);

    function gaugeManager() external view returns (address);
    function setGaugeManager(address _gaugeManager) external;
    function stakePosition(uint256 tokenId) external;
    function unstakePosition(uint256 tokenId) external;

    // params for decreasing liquidity of collateralized position
    struct DecreaseLiquidityAndCollectParams {
        uint256 tokenId;
        uint128 liquidity;
        // min amount to accept from liquidity removal
        uint256 amount0Min;
        uint256 amount1Min;
        // amount to remove from fees additional to the liquidity amounts
        uint128 feeAmount0; // (if uint256(128).max - all fees)
        uint128 feeAmount1; // (if uint256(128).max - all fees)
        uint256 deadline;
        address recipient;
    }

    function decreaseLiquidityAndCollect(DecreaseLiquidityAndCollectParams calldata params)
        external
        returns (uint256 amount0, uint256 amount1);

    function borrow(uint256 tokenId, uint256 amount) external;
    function repay(uint256 tokenId, uint256 amount, bool isShare) external returns (uint256 assets, uint256 shares);

    struct LiquidateParams {
        // token to liquidate
        uint256 tokenId;
        // min amount to recieve
        uint256 amount0Min;
        uint256 amount1Min;
        // recipient of rewarded tokens
        address recipient;
        // for uniswap functions
        uint256 deadline;
    }

    function liquidate(LiquidateParams calldata params) external returns (uint256 amount0, uint256 amount1);
}


// ========== transformers\AutoRangeAndCompound.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "../interfaces/aerodrome/IAerodromeSlipstreamPool.sol";
import "../automators/Automator.sol";
import "../transformers/Transformer.sol";

/// @title AutoRangeAndCompound
/// @notice Allows operator of AutoRangeAndCompound contract (Revert controlled bot) to change range for configured positions
/// And optionally to autocompound position (depending on configuration)
/// Positions need to be approved (setApprovalForAll) for the contract and configured with configToken method
/// When executed a new position is created and automatically configured the same way as the original position
/// When position is inside Vault - transform is called
contract AutoRangeAndCompound is Transformer, Automator, ReentrancyGuard {
    event RangeChanged(uint256 indexed oldTokenId, uint256 indexed newTokenId);
    event PositionConfigured(
        uint256 indexed tokenId,
        int32 lowerTickLimit,
        int32 upperTickLimit,
        int32 lowerTickDelta,
        int32 upperTickDelta,
        uint64 token0SlippageX64,
        uint64 token1SlippageX64,
        bool onlyFees,
        bool autoCompound,
        uint64 maxRewardX64,
        uint128 autoCompoundMin0,
        uint128 autoCompoundMin1,
        uint128 autoCompoundRewardMin
    );
    event AutoCompounded(
        uint256 indexed tokenId,
        uint256 amountAdded0,
        uint256 amountAdded1,
        uint256 reward0,
        uint256 reward1,
        address token0,
        address token1
    );

    // config changes
    event AutoCompoundRewardUpdated(address account, uint64 totalRewardX64);

    constructor(
        INonfungiblePositionManager _npm,
        address _operator,
        address _withdrawer,
        uint32 _TWAPSeconds,
        uint16 _maxTWAPTickDifference,
        address _universalRouter,
        address _zeroxAllowanceHolder
    )
        Automator(
            _npm, _operator, _withdrawer, _TWAPSeconds, _maxTWAPTickDifference, _universalRouter, _zeroxAllowanceHolder
        )
    {}

    // defines when and how a position can be changed by operator
    // when a position is adjusted config for the position is cleared and copied to the newly created position
    struct PositionConfig {
        // needs more than int24 because it can be [-type(uint24).max,type(uint24).max]
        int32 lowerTickLimit; // if negative also in-range positions may be adjusted / if 0 out of range positions may be adjusted
        int32 upperTickLimit; // if negative also in-range positions may be adjusted / if 0 out of range positions may be adjusted
        int32 lowerTickDelta; // this amount is added to current tick (floored to tickspacing) to define lowerTick of new position
        int32 upperTickDelta; // this amount is added to current tick (floored to tickspacing) to define upperTick of new position
        uint64 token0SlippageX64; // max price difference from current pool price for swap / Q64 for token0
        uint64 token1SlippageX64; // max price difference from current pool price for swap / Q64 for token1
        bool onlyFees; // if only fees maybe used for protocol reward
        bool autoCompound; // if this position can be autocompounded
        uint64 maxRewardX64; // max allowed reward percentage of fees or full position
        uint128 autoCompoundMin0; // min amount0 to add in autoCompound increaseLiquidity
        uint128 autoCompoundMin1; // min amount1 to add in autoCompound increaseLiquidity
        uint128 autoCompoundRewardMin; // min claimed AERO when pre-compounding staked rewards
    }

    // configured tokens
    mapping(uint256 => PositionConfig) public positionConfigs;

    /// @notice params for execute()
    struct ExecuteParams {
        uint256 tokenId;
        bool swap0To1;
        uint256 amountIn; // if this is set to 0 no swap happens
        bytes swapData;
        uint256 amountRemoveMin0; // min amount to be removed from liquidity
        uint256 amountRemoveMin1; // min amount to be removed from liquidity
        uint256 amountAddMin0; // min amount to be added to liquidity
        uint256 amountAddMin1; // min amount to be added to liquidity
        uint256 deadline; // for uniswap operations
        uint64 rewardX64; // which reward will be used for protocol, can be max configured amount (considering onlyFees)
    }

    struct ExecuteState {
        address owner;
        address realOwner;
        IUniswapV3Pool pool;
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        int24 currentTick;
        uint160 sqrtPriceX96;
        uint256 amount0;
        uint256 amount1;
        uint256 feeAmount0;
        uint256 feeAmount1;
        uint256 maxAddAmount0;
        uint256 maxAddAmount1;
        uint256 amountAdded0;
        uint256 amountAdded1;
        uint128 liquidity;
        uint256 protocolReward0;
        uint256 protocolReward1;
        uint256 amountOutMin;
        uint256 amountInDelta;
        uint256 amountOutDelta;
        uint256 newTokenId;
    }

    // reward handling for autocompound
    uint64 public constant MAX_REWARD_X64 = 368_934_881_474_191_032; // floor(Q64 / 50)
    uint64 public totalRewardX64 = MAX_REWARD_X64; // 2%

    /**
     * @notice Adjust token (which is in a Vault) - via transform method
     * Can only be called from configured operator account - vault must be configured as well
     * Swap needs to be done with max price difference from current pool price - otherwise reverts
     */
    function executeWithVault(ExecuteParams calldata params, address vault) external {
        if (!operators[msg.sender] || !vaults[vault]) {
            revert Unauthorized();
        }
        IVault(vault).transform(params.tokenId, address(this), abi.encodeCall(AutoRangeAndCompound.execute, (params)));
    }

    /**
     * @notice Adjust token in a vault and compound staked gauge rewards first (if position is currently staked)
     * Can only be called from configured operator account - vault must be configured as well
     */
    function executeWithVaultAndRewardCompound(
        ExecuteParams calldata params,
        address vault,
        IVault.RewardCompoundParams calldata rewardParams
    ) external {
        if (!operators[msg.sender] || !vaults[vault]) {
            revert Unauthorized();
        }
        IVault(vault)
            .transformWithRewardCompound(
                params.tokenId, address(this), abi.encodeCall(AutoRangeAndCompound.execute, (params)), rewardParams
            );
    }

    /**
     * @notice Adjust token directly (must be in correct state)
     * Can only be called only from configured operator account, or vault via transform
     * Swap needs to be done with max price difference from current pool price - otherwise reverts
     */
    function execute(ExecuteParams calldata params) external {
        if (!operators[msg.sender]) {
            if (vaults[msg.sender]) {
                _validateCaller(nonfungiblePositionManager, params.tokenId);
            } else {
                revert Unauthorized();
            }
        }

        PositionConfig memory config = positionConfigs[params.tokenId];

        if (config.lowerTickDelta == config.upperTickDelta) {
            revert NotConfigured();
        }

        if (params.rewardX64 > config.maxRewardX64) {
            revert ExceedsMaxReward();
        }

        ExecuteState memory state;

        // get position info
        (,, state.token0, state.token1, state.fee, state.tickLower, state.tickUpper, state.liquidity,,,,) =
            nonfungiblePositionManager.positions(params.tokenId);

        (state.amount0, state.amount1, state.feeAmount0, state.feeAmount1) = _decreaseFullLiquidityAndCollect(
            params.tokenId, state.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline
        );

        // if only fees reward is removed before adding
        if (config.onlyFees) {
            state.protocolReward0 = state.feeAmount0 * params.rewardX64 / Q64;
            state.protocolReward1 = state.feeAmount1 * params.rewardX64 / Q64;
            state.amount0 -= state.protocolReward0;
            state.amount1 -= state.protocolReward1;
        }

        if (params.amountIn > (params.swap0To1 ? state.amount0 : state.amount1)) {
            revert SwapAmountTooLarge();
        }

        // get pool info
        state.pool = _getPool(state.token0, state.token1, state.fee);
        (state.sqrtPriceX96, state.currentTick) = _getPoolSlot0(state.pool);

        if (
            state.currentTick < state.tickLower - config.lowerTickLimit
                || state.currentTick >= state.tickUpper + config.upperTickLimit
        ) {
            // check TWAP deviation (this is done for swap and non-swap operations)
            // operation is only allowed when price is close to TWAP price to prevent sandwich attacks
            state.amountOutMin = _validateSwap(
                params.swap0To1,
                params.amountIn,
                state.pool,
                state.currentTick,
                state.sqrtPriceX96,
                TWAPSeconds,
                maxTWAPTickDifference,
                params.swap0To1 ? config.token0SlippageX64 : config.token1SlippageX64
            );

            if (params.amountIn != 0) {
                (state.amountInDelta, state.amountOutDelta) = _routerSwap(
                    Swapper.RouterSwapParams(
                        params.swap0To1 ? IERC20(state.token0) : IERC20(state.token1),
                        params.swap0To1 ? IERC20(state.token1) : IERC20(state.token0),
                        params.amountIn,
                        state.amountOutMin,
                        params.swapData
                    )
                );

                state.amount0 =
                    params.swap0To1 ? state.amount0 - state.amountInDelta : state.amount0 + state.amountOutDelta;
                state.amount1 =
                    params.swap0To1 ? state.amount1 + state.amountOutDelta : state.amount1 - state.amountInDelta;

                // update tick
                (state.sqrtPriceX96, state.currentTick) = _getPoolSlot0(state.pool);
            }

            int24 tickSpacing = IAerodromeSlipstreamPool(address(state.pool)).tickSpacing();
            int24 baseTick = state.currentTick - (((state.currentTick % tickSpacing) + tickSpacing) % tickSpacing);

            if (
                baseTick + config.lowerTickDelta == state.tickLower
                    && baseTick + config.upperTickDelta == state.tickUpper
            ) {
                revert SameRange();
            }

            // max amount to add - removing max potential fees (if config.onlyFees - the have been removed already)
            state.maxAddAmount0 = config.onlyFees ? state.amount0 : state.amount0 * Q64 / (params.rewardX64 + Q64);
            state.maxAddAmount1 = config.onlyFees ? state.amount1 : state.amount1 * Q64 / (params.rewardX64 + Q64);

            INonfungiblePositionManager.MintParams memory mintParams = INonfungiblePositionManager.MintParams(
                address(state.token0),
                address(state.token1),
                state.fee,
                SafeCast.toInt24(baseTick + config.lowerTickDelta), // reverts if out of valid range
                SafeCast.toInt24(baseTick + config.upperTickDelta), // reverts if out of valid range
                state.maxAddAmount0,
                state.maxAddAmount1,
                params.amountAddMin0,
                params.amountAddMin1,
                address(this), // is sent to real recipient aftwards
                params.deadline
            );

            // approve npm
            SafeERC20.safeIncreaseAllowance(
                IERC20(state.token0), address(nonfungiblePositionManager), state.maxAddAmount0
            );
            SafeERC20.safeIncreaseAllowance(
                IERC20(state.token1), address(nonfungiblePositionManager), state.maxAddAmount1
            );

            // mint is done to address(this) first - its not a safemint
            (state.newTokenId,, state.amountAdded0, state.amountAdded1) = _mintPosition(mintParams);

            // remove remaining approval
            SafeERC20.safeApprove(IERC20(state.token0), address(nonfungiblePositionManager), 0);
            SafeERC20.safeApprove(IERC20(state.token1), address(nonfungiblePositionManager), 0);

            state.owner = nonfungiblePositionManager.ownerOf(params.tokenId);

            // get the real owner - if owner is vault - for sending leftover tokens
            state.realOwner = state.owner;
            if (vaults[state.owner]) {
                state.realOwner = IVault(state.owner).ownerOf(params.tokenId);
            }

            // send the new nft to the owner / vault
            nonfungiblePositionManager.safeTransferFrom(address(this), state.owner, state.newTokenId);

            // protocol reward is calculated based on added amount (to incentivize optimal swap done by operator)
            if (!config.onlyFees) {
                state.protocolReward0 = state.amountAdded0 * params.rewardX64 / Q64;
                state.protocolReward1 = state.amountAdded1 * params.rewardX64 / Q64;
                state.amount0 -= state.protocolReward0;
                state.amount1 -= state.protocolReward1;
            }

            // send leftover to real owner
            if (state.amount0 - state.amountAdded0 != 0) {
                _transferToken(state.realOwner, IERC20(state.token0), state.amount0 - state.amountAdded0, true);
            }
            if (state.amount1 - state.amountAdded1 != 0) {
                _transferToken(state.realOwner, IERC20(state.token1), state.amount1 - state.amountAdded1, true);
            }

            // copy token config for new token
            positionConfigs[state.newTokenId] = config;
            emit PositionConfigured(
                state.newTokenId,
                config.lowerTickLimit,
                config.upperTickLimit,
                config.lowerTickDelta,
                config.upperTickDelta,
                config.token0SlippageX64,
                config.token1SlippageX64,
                config.onlyFees,
                config.autoCompound,
                config.maxRewardX64,
                config.autoCompoundMin0,
                config.autoCompoundMin1,
                config.autoCompoundRewardMin
            );

            // delete config for old position
            delete positionConfigs[params.tokenId];
            emit PositionConfigured(params.tokenId, 0, 0, 0, 0, 0, 0, false, false, 0, 0, 0, 0);

            emit RangeChanged(params.tokenId, state.newTokenId);
        } else {
            revert NotReady();
        }
    }

    /// @notice params for autoCompound()
    struct AutoCompoundParams {
        // tokenid to autocompound
        uint256 tokenId;
        // swap direction - calculated off-chain
        bool swap0To1;
        // swap amount - calculated off-chain - if this is set to 0 no swap happens
        uint256 amountIn;
        // for uniswap operations
        uint256 deadline;
    }

    // state used during autocompound execution
    struct AutoCompoundState {
        address owner;
        address realOwner;
        uint256 amount0;
        uint256 amount1;
        uint256 maxAddAmount0;
        uint256 maxAddAmount1;
        uint256 amount0Fees;
        uint256 amount1Fees;
        uint256 priceX96;
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 compounded0;
        uint256 compounded1;
        int24 tick;
        uint160 sqrtPriceX96;
        uint256 amountInDelta;
        uint256 amountOutDelta;
    }

    /**
     * @notice Autocompound position (which is in a Vault) - via transform method
     * Can only be called from configured operator account - vault must be configured as well
     * Swap needs to be done with max price difference from current pool price - otherwise reverts
     */
    function autoCompoundWithVault(AutoCompoundParams calldata params, address vault) external {
        if (!operators[msg.sender] || !vaults[vault]) {
            revert Unauthorized();
        }
        IVault(vault).transform(params.tokenId, address(this), abi.encodeCall(AutoRangeAndCompound.autoCompound, (params)));
    }

    /**
     * @notice Autocompound position in a vault and compound staked gauge rewards first (if position is currently staked)
     * Can only be called from configured operator account - vault must be configured as well
     */
    function autoCompoundWithVaultAndRewardCompound(
        AutoCompoundParams calldata params,
        address vault,
        IVault.RewardCompoundParams calldata rewardParams
    ) external {
        if (!operators[msg.sender] || !vaults[vault]) {
            revert Unauthorized();
        }
        PositionConfig memory config = positionConfigs[params.tokenId];
        IVault.RewardCompoundParams memory adjustedRewardParams = rewardParams;
        adjustedRewardParams.minAeroReward = config.autoCompoundRewardMin;
        IVault(vault)
            .transformWithRewardCompound(
                params.tokenId, address(this), abi.encodeCall(AutoRangeAndCompound.autoCompound, (params)), adjustedRewardParams
            );
    }

    /**
     * @notice Autocompound position directly (must be in correct state)
     * Can only be called only from configured operator account, or vault via transform
     * Swap needs to be done with max price difference from current pool price - otherwise reverts
     */
    function autoCompound(AutoCompoundParams calldata params) external nonReentrant {
        if (!operators[msg.sender]) {
            if (vaults[msg.sender]) {
                _validateCaller(nonfungiblePositionManager, params.tokenId);
            } else {
                revert Unauthorized();
            }
        }

        PositionConfig memory config = positionConfigs[params.tokenId];
        if (!config.autoCompound) {
            revert NotConfigured();
        }

        AutoCompoundState memory state;

        // collect fees - if the position doesn't have operator set or is called from vault - it won't work
        (state.amount0, state.amount1) = nonfungiblePositionManager.collect(
            INonfungiblePositionManager.CollectParams(
                params.tokenId, address(this), type(uint128).max, type(uint128).max
            )
        );

        // Minimum fee thresholds gate autocompound execution.
        if (state.amount0 < config.autoCompoundMin0 || state.amount1 < config.autoCompoundMin1) {
            revert NotEnoughReward();
        }

        // get position info
        (,, state.token0, state.token1, state.fee, state.tickLower, state.tickUpper,,,,,) =
            nonfungiblePositionManager.positions(params.tokenId);

        // only if there are balances to work with - start autocompounding process
        if (state.amount0 != 0 || state.amount1 != 0) {
            uint256 amountIn = params.amountIn;

            // if a swap is requested - check TWAP oracle
            if (amountIn != 0) {
                IUniswapV3Pool pool = _getPool(state.token0, state.token1, state.fee);
                (state.sqrtPriceX96, state.tick) = _getPoolSlot0(pool);

                // how many seconds are needed for TWAP protection
                uint32 tSecs = TWAPSeconds;
                if (tSecs != 0) {
                    if (!_hasMaxTWAPTickDifference(pool, tSecs, state.tick, maxTWAPTickDifference)) {
                        // if there is no valid TWAP - disable swap
                        amountIn = 0;
                    }
                }
                // if still needed - do swap
                if (amountIn != 0) {
                    // no slippage check done - because protected by TWAP check
                    (state.amountInDelta, state.amountOutDelta) = _poolSwap(
                        Swapper.PoolSwapParams(
                            pool, IERC20(state.token0), IERC20(state.token1), state.fee, params.swap0To1, amountIn, 0
                        )
                    );
                    state.amount0 =
                        params.swap0To1 ? state.amount0 - state.amountInDelta : state.amount0 + state.amountOutDelta;
                    state.amount1 =
                        params.swap0To1 ? state.amount1 + state.amountOutDelta : state.amount1 - state.amountInDelta;
                }
            }

            uint256 rewardX64 = totalRewardX64;

            state.maxAddAmount0 = state.amount0 * Q64 / (rewardX64 + Q64);
            state.maxAddAmount1 = state.amount1 * Q64 / (rewardX64 + Q64);

            // deposit liquidity into tokenId
            if (state.maxAddAmount0 != 0 || state.maxAddAmount1 != 0) {
                // approve npm
                SafeERC20.safeIncreaseAllowance(
                    IERC20(state.token0), address(nonfungiblePositionManager), state.maxAddAmount0
                );
                SafeERC20.safeIncreaseAllowance(
                    IERC20(state.token1), address(nonfungiblePositionManager), state.maxAddAmount1
                );

                (, state.compounded0, state.compounded1) = nonfungiblePositionManager.increaseLiquidity(
                    INonfungiblePositionManager.IncreaseLiquidityParams(
                        params.tokenId, state.maxAddAmount0, state.maxAddAmount1, 0, 0, params.deadline
                    )
                );

                // remove remaining approval
                SafeERC20.safeApprove(IERC20(state.token0), address(nonfungiblePositionManager), 0);
                SafeERC20.safeApprove(IERC20(state.token1), address(nonfungiblePositionManager), 0);

                // fees are always calculated based on added amount (to incentivize optimal swap)
                state.amount0Fees = state.compounded0 * rewardX64 / Q64;
                state.amount1Fees = state.compounded1 * rewardX64 / Q64;
            }

            state.owner = nonfungiblePositionManager.ownerOf(params.tokenId);

            // get the real owner - if owner is vault - for sending leftover tokens
            state.realOwner = state.owner;
            if (vaults[state.owner]) {
                state.realOwner = IVault(state.owner).ownerOf(params.tokenId);
            }

            // return remaining tokens for owner
            state.amount0 = state.amount0 - state.compounded0 - state.amount0Fees;
            if (state.amount0 > 0) {
                _transferToken(state.realOwner, IERC20(state.token0), state.amount0, true);
            }
            state.amount1 = state.amount1 - state.compounded1 - state.amount1Fees;
            if (state.amount1 > 0) {
                _transferToken(state.realOwner, IERC20(state.token1), state.amount1, true);
            }
        }

        emit AutoCompounded(
            params.tokenId,
            state.compounded0,
            state.compounded1,
            state.amount0Fees,
            state.amount1Fees,
            state.token0,
            state.token1
        );
    }

    // function to configure a token to be used with this runner
    // it needs to have approvals set for this contract beforehand
    function configToken(uint256 tokenId, address vault, PositionConfig calldata config) external {
        _validateOwner(nonfungiblePositionManager, tokenId, vault);

        // lower tick must be always below or equal to upper tick - if they are equal - range adjustment is deactivated
        if (config.lowerTickDelta > config.upperTickDelta) {
            revert InvalidConfig();
        }

        positionConfigs[tokenId] = config;

        emit PositionConfigured(
            tokenId,
            config.lowerTickLimit,
            config.upperTickLimit,
            config.lowerTickDelta,
            config.upperTickDelta,
            config.token0SlippageX64,
            config.token1SlippageX64,
            config.onlyFees,
            config.autoCompound,
            config.maxRewardX64,
            config.autoCompoundMin0,
            config.autoCompoundMin1,
            config.autoCompoundRewardMin
        );
    }

    /**
     * @notice Management method to lower autocompound reward(onlyOwner)
     * @param _totalRewardX64 new total reward (can't be higher than current total reward)
     */
    function setAutoCompoundReward(uint64 _totalRewardX64) external onlyOwner {
        if (_totalRewardX64 > totalRewardX64) {
            revert InvalidConfig();
        }
        totalRewardX64 = _totalRewardX64;
        emit AutoCompoundRewardUpdated(msg.sender, _totalRewardX64);
    }
}


// ========== transformers\LeverageTransformer.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../utils/Swapper.sol";
import "../interfaces/IVault.sol";
import "../transformers/Transformer.sol";

/// @title LeverageTransformer
/// @notice Functionality to leverage / deleverage positions direcly in one tx
contract LeverageTransformer is Transformer, Swapper {
    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _universalRouter,
        address _zeroxAllowanceHolder
    )
        Swapper(_nonfungiblePositionManager, _universalRouter, _zeroxAllowanceHolder)
    {}

    struct LeverageUpParams {
        // which token to leverage
        uint256 tokenId;
        // how much to borrow
        uint256 borrowAmount;
        // how much of borrowed lend token should be swapped to token0
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // how much of borrowed lend token should be swapped to token1
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // for adding liquidity slippage
        uint256 amountAddMin0;
        uint256 amountAddMin1;
        // recipient for leftover tokens
        address recipient;
        // for all uniswap deadlineable functions
        uint256 deadline;
    }

    // method called from transform() method in Vault
    function leverageUp(LeverageUpParams calldata params) external {
        _validateCaller(nonfungiblePositionManager, params.tokenId);

        uint256 amount = params.borrowAmount;

        address token = IVault(msg.sender).asset();

        IVault(msg.sender).borrow(params.tokenId, amount);

        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);

        uint256 amount0 = token == token0 ? amount : 0;
        uint256 amount1 = token == token1 ? amount : 0;

        if (params.amountIn0 != 0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token), IERC20(token0), params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            if (token == token1) {
                amount1 -= amountIn;
            }
            amount -= amountIn;
            amount0 += amountOut;
        }
        if (params.amountIn1 != 0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token), IERC20(token1), params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            if (token == token0) {
                amount0 -= amountIn;
            }
            amount -= amountIn;
            amount1 += amountOut;
        }

        SafeERC20.safeIncreaseAllowance(IERC20(token0), address(nonfungiblePositionManager), amount0);
        SafeERC20.safeIncreaseAllowance(IERC20(token1), address(nonfungiblePositionManager), amount1);

        INonfungiblePositionManager.IncreaseLiquidityParams memory increaseLiquidityParams = INonfungiblePositionManager
            .IncreaseLiquidityParams(
            params.tokenId, amount0, amount1, params.amountAddMin0, params.amountAddMin1, params.deadline
        );
        (, uint256 added0, uint256 added1) = nonfungiblePositionManager.increaseLiquidity(increaseLiquidityParams);

        SafeERC20.safeApprove(IERC20(token0), address(nonfungiblePositionManager), 0);
        SafeERC20.safeApprove(IERC20(token1), address(nonfungiblePositionManager), 0);

        // send leftover tokens
        if (amount0 > added0) {
            SafeERC20.safeTransfer(IERC20(token0), params.recipient, amount0 - added0);
        }
        if (amount1 > added1) {
            SafeERC20.safeTransfer(IERC20(token1), params.recipient, amount1 - added1);
        }
        if (token != token0 && token != token1 && amount != 0) {
            SafeERC20.safeTransfer(IERC20(token), params.recipient, amount);
        }
    }

    struct LeverageDownParams {
        // which token to leverage
        uint256 tokenId;
        // for removing - remove liquidity amount
        uint128 liquidity;
        uint256 amountRemoveMin0;
        uint256 amountRemoveMin1;
        // collect fee amount (if type(uint128).max - ALL)
        uint128 feeAmount0;
        uint128 feeAmount1;
        // how much of token0 should be swapped to lend token
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0; // encoded data for swap
        // how much of token1 should be swapped to lend token
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1; // encoded data for swap
        // recipient for leftover tokens
        address recipient;
        // for all uniswap deadlineable functions
        uint256 deadline;
    }

    // method called from transform() method in Vault
    function leverageDown(LeverageDownParams calldata params) external {
        _validateCaller(nonfungiblePositionManager, params.tokenId);

        address token = IVault(msg.sender).asset();
        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);

        uint256 amount0;
        uint256 amount1;

        if (params.liquidity != 0) {
            INonfungiblePositionManager.DecreaseLiquidityParams memory decreaseLiquidityParams = INonfungiblePositionManager
                .DecreaseLiquidityParams(
                params.tokenId, params.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline
            );
            (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(decreaseLiquidityParams);
        }

        INonfungiblePositionManager.CollectParams memory collectParams = INonfungiblePositionManager.CollectParams(
            params.tokenId,
            address(this),
            params.feeAmount0 == type(uint128).max ? type(uint128).max : SafeCast.toUint128(amount0 + params.feeAmount0),
            params.feeAmount1 == type(uint128).max ? type(uint128).max : SafeCast.toUint128(amount1 + params.feeAmount1)
        );
        (amount0, amount1) = nonfungiblePositionManager.collect(collectParams);

        uint256 amount = token == token0 ? amount0 : (token == token1 ? amount1 : 0);

        if (params.amountIn0 != 0 && token != token0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token0), IERC20(token), params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            amount0 -= amountIn;
            amount += amountOut;
        }
        if (params.amountIn1 != 0 && token != token1) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token1), IERC20(token), params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            amount1 -= amountIn;
            amount += amountOut;
        }

        SafeERC20.safeIncreaseAllowance(IERC20(token), msg.sender, amount);
        (uint256 repayedAmount,) = IVault(msg.sender).repay(params.tokenId, amount, false);
        SafeERC20.safeApprove(IERC20(token), msg.sender, 0);

        // send leftover tokens
        if (amount > repayedAmount) {
            SafeERC20.safeTransfer(IERC20(token), params.recipient, amount - repayedAmount);
        }
        if (amount0 != 0 && token != token0) {
            SafeERC20.safeTransfer(IERC20(token0), params.recipient, amount0);
        }
        if (amount1 != 0 && token != token1) {
            SafeERC20.safeTransfer(IERC20(token1), params.recipient, amount1);
        }
    }
}


// ========== transformers\Transformer.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "../utils/Constants.sol";
import "../interfaces/IVault.sol";

abstract contract Transformer is Ownable2Step, Constants {
    event VaultSet(address newVault);

    // configurable by owner
    mapping(address => bool) public vaults;

    /**
     * @notice Owner controlled function to activate vault address
     * @param _vault vault
     */
    function setVault(address _vault) external onlyOwner {
        emit VaultSet(_vault);
        vaults[_vault] = true;
    }

    // validates if caller is owner (direct or indirect for a given position)
    function _validateOwner(INonfungiblePositionManager nonfungiblePositionManager, uint256 tokenId, address vault)
        internal
    {
        // vault can not be owner
        if (vaults[msg.sender]) {
            revert Unauthorized();
        }

        address owner;
        if (vault != address(0)) {
            if (!vaults[vault]) {
                revert Unauthorized();
            }
            owner = IVault(vault).ownerOf(tokenId);
        } else {
            owner = nonfungiblePositionManager.ownerOf(tokenId);
        }

        if (owner != msg.sender) {
            revert Unauthorized();
        }
    }

    // validates if caller is allowed to process position
    function _validateCaller(INonfungiblePositionManager nonfungiblePositionManager, uint256 tokenId) internal view {
        if (vaults[msg.sender]) {
            uint256 transformedTokenId = IVault(msg.sender).transformedTokenId();
            if (tokenId != transformedTokenId) {
                revert Unauthorized();
            }
        } else {
            address owner = nonfungiblePositionManager.ownerOf(tokenId);
            if (owner != msg.sender && owner != address(this)) {
                revert Unauthorized();
            }
        }
    }
}


// ========== transformers\V3Utils.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

import "../utils/Swapper.sol";
import "../transformers/Transformer.sol";

/// @title v3Utils v1.1
/// @notice Utility functions for Uniswap V3 positions
/// It does not hold any ERC20 or NFTs.
/// It can be simply redeployed when new / better functionality is implemented
contract V3Utils is Transformer, Swapper, IERC721Receiver {
    using SafeCast for uint256;

    // events
    event CompoundFees(uint256 indexed tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);
    event ChangeRange(uint256 indexed tokenId, uint256 newTokenId);
    event WithdrawAndCollectAndSwap(uint256 indexed tokenId, address token, uint256 amount);
    event SwapAndMint(uint256 indexed tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);
    event SwapAndIncreaseLiquidity(uint256 indexed tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

    /// @notice Constructor
    /// @param _nonfungiblePositionManager Uniswap v3 position manager
    /// @param _universalRouter Uniswap Universal Router
    /// @param _zeroxAllowanceHolder 0x Protocol AllowanceHolder contract
    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Swapper(_nonfungiblePositionManager, _universalRouter, _zeroxAllowanceHolder) {}

    /// @notice Action which should be executed on provided NFT
    enum WhatToDo {
        CHANGE_RANGE,
        WITHDRAW_AND_COLLECT_AND_SWAP,
        COMPOUND_FEES
    }

    /// @notice Complete description of what should be executed on provided NFT - different fields are used depending on specified WhatToDo
    struct Instructions {
        // what action to perform on provided Uniswap v3 position
        WhatToDo whatToDo;
        // target token for swaps (if this is address(0) no swaps are executed)
        address targetToken;
        // for removing liquidity slippage
        uint256 amountRemoveMin0;
        uint256 amountRemoveMin1;
        // amountIn0 is used for swap and also as minAmount0 for decreased liquidity + collected fees
        uint256 amountIn0;
        // if token0 needs to be swapped to targetToken - set values
        uint256 amountOut0Min;
        bytes swapData0; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // amountIn1 is used for swap and also as minAmount1 for decreased liquidity + collected fees
        uint256 amountIn1;
        // if token1 needs to be swapped to targetToken - set values
        uint256 amountOut1Min;
        bytes swapData1; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // collect fee amount for COMPOUND_FEES / CHANGE_RANGE / WITHDRAW_AND_COLLECT_AND_SWAP (if uint256(128).max - ALL)
        uint128 feeAmount0;
        uint128 feeAmount1;
        // for creating new positions with CHANGE_RANGE
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        // remove liquidity amount for COMPOUND_FEES (in this case should be probably 0) / CHANGE_RANGE / WITHDRAW_AND_COLLECT_AND_SWAP
        uint128 liquidity;
        // for adding liquidity slippage
        uint256 amountAddMin0;
        uint256 amountAddMin1;
        // for all uniswap deadlineable functions
        uint256 deadline;
        // left over tokens will be sent to this address
        address recipient;
        // recipient of newly minted nft (the incoming NFT will ALWAYS be returned to from)
        address recipientNFT;
        // if tokenIn or tokenOut is WETH - unwrap
        bool unwrap;
        // data sent with returned token to IERC721Receiver (optional)
        bytes returnData;
        // data sent with minted token to IERC721Receiver (optional)
        bytes swapAndMintReturnData;
    }

    /// @notice Execute instruction with EIP712 permit
    /// @param tokenId Token to process
    /// @param instructions Instructions to execute
    /// @param v Signature values for EIP712 permit
    /// @param r Signature values for EIP712 permit
    /// @param s Signature values for EIP712 permit
    /// @return newTokenId Id of position (if a new one was created)
    function executeWithPermit(uint256 tokenId, Instructions memory instructions, uint8 v, bytes32 r, bytes32 s)
        public
        returns (uint256 newTokenId)
    {
        if (nonfungiblePositionManager.ownerOf(tokenId) != msg.sender) {
            revert Unauthorized();
        }

        nonfungiblePositionManager.permit(address(this), tokenId, instructions.deadline, v, r, s);
        return execute(tokenId, instructions);

        // NOTE: previous operator can not be reset as operator set by permit can not change operator - so this operator will stay until reset
    }

    /// @notice ERC721 callback function. Called on safeTransferFrom and does manipulation as configured in encoded Instructions parameter.
    /// At the end the NFT (and any newly minted NFT) is returned to sender. The leftover tokens are sent to instructions.recipient.
    function onERC721Received(address, /*operator*/ address from, uint256 tokenId, bytes calldata data)
        external
        override
        returns (bytes4)
    {
        // only Uniswap v3 NFTs allowed
        if (msg.sender != address(nonfungiblePositionManager)) {
            revert WrongContract();
        }

        // not allowed to send to itself
        if (from == address(this)) {
            revert SelfSend();
        }

        Instructions memory instructions = abi.decode(data, (Instructions));

        execute(tokenId, instructions);

        // return token to owner (this line guarantees that token is returned to originating owner)
        nonfungiblePositionManager.safeTransferFrom(address(this), from, tokenId, instructions.returnData);

        return IERC721Receiver.onERC721Received.selector;
    }

    /// @notice Execute instruction by pulling approved NFT instead of direct safeTransferFrom call from owner
    /// @param tokenId Token to process
    /// @param instructions Instructions to execute
    /// @return newTokenId Id of position (if a new one was created)
    function execute(uint256 tokenId, Instructions memory instructions) public returns (uint256 newTokenId) {
        _validateCaller(nonfungiblePositionManager, tokenId);

        (,, address token0, address token1,,,, uint128 liquidity,,,,) = nonfungiblePositionManager.positions(tokenId);

        uint256 amount0;
        uint256 amount1;
        if (instructions.liquidity != 0) {
            (amount0, amount1) = _decreaseLiquidity(
                tokenId,
                instructions.liquidity,
                instructions.deadline,
                instructions.amountRemoveMin0,
                instructions.amountRemoveMin1
            );
        }
        (amount0, amount1) = _collectFees(
            tokenId,
            IERC20(token0),
            IERC20(token1),
            instructions.feeAmount0 == type(uint128).max
                ? type(uint128).max
                : (amount0 + instructions.feeAmount0).toUint128(),
            instructions.feeAmount1 == type(uint128).max
                ? type(uint128).max
                : (amount1 + instructions.feeAmount1).toUint128()
        );

        // check if enough tokens are available for swaps
        if (amount0 < instructions.amountIn0 || amount1 < instructions.amountIn1) {
            revert AmountError();
        }

        if (instructions.whatToDo == WhatToDo.COMPOUND_FEES) {
            if (instructions.targetToken == token0) {
                (liquidity, amount0, amount1) = _swapAndIncrease(
                    SwapAndIncreaseLiquidityParams(
                        tokenId,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.deadline,
                        IERC20(token1),
                        instructions.amountIn1,
                        instructions.amountOut1Min,
                        instructions.swapData1,
                        0,
                        0,
                        "",
                        instructions.amountAddMin0,
                        instructions.amountAddMin1
                    ),
                    IERC20(token0),
                    IERC20(token1),
                    instructions.unwrap
                );
            } else if (instructions.targetToken == token1) {
                (liquidity, amount0, amount1) = _swapAndIncrease(
                    SwapAndIncreaseLiquidityParams(
                        tokenId,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.deadline,
                        IERC20(token0),
                        0,
                        0,
                        "",
                        instructions.amountIn0,
                        instructions.amountOut0Min,
                        instructions.swapData0,
                        instructions.amountAddMin0,
                        instructions.amountAddMin1
                    ),
                    IERC20(token0),
                    IERC20(token1),
                    instructions.unwrap
                );
            } else {
                // no swap is done here
                (liquidity, amount0, amount1) = _swapAndIncrease(
                    SwapAndIncreaseLiquidityParams(
                        tokenId,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.deadline,
                        IERC20(address(0)),
                        0,
                        0,
                        "",
                        0,
                        0,
                        "",
                        instructions.amountAddMin0,
                        instructions.amountAddMin1
                    ),
                    IERC20(token0),
                    IERC20(token1),
                    instructions.unwrap
                );
            }
            emit CompoundFees(tokenId, liquidity, amount0, amount1);
        } else if (instructions.whatToDo == WhatToDo.CHANGE_RANGE) {
            if (instructions.targetToken == token0) {
                (newTokenId,,,) = _swapAndMint(
                    SwapAndMintParams(
                        IERC20(token0),
                        IERC20(token1),
                        instructions.fee,
                        instructions.tickLower,
                        instructions.tickUpper,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.recipientNFT,
                        instructions.deadline,
                        IERC20(token1),
                        instructions.amountIn1,
                        instructions.amountOut1Min,
                        instructions.swapData1,
                        0,
                        0,
                        "",
                        instructions.amountAddMin0,
                        instructions.amountAddMin1,
                        instructions.swapAndMintReturnData
                    ),
                    instructions.unwrap
                );
            } else if (instructions.targetToken == token1) {
                (newTokenId,,,) = _swapAndMint(
                    SwapAndMintParams(
                        IERC20(token0),
                        IERC20(token1),
                        instructions.fee,
                        instructions.tickLower,
                        instructions.tickUpper,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.recipientNFT,
                        instructions.deadline,
                        IERC20(token0),
                        0,
                        0,
                        "",
                        instructions.amountIn0,
                        instructions.amountOut0Min,
                        instructions.swapData0,
                        instructions.amountAddMin0,
                        instructions.amountAddMin1,
                        instructions.swapAndMintReturnData
                    ),
                    instructions.unwrap
                );
            } else {
                // no swap is done here
                (newTokenId,,,) = _swapAndMint(
                    SwapAndMintParams(
                        IERC20(token0),
                        IERC20(token1),
                        instructions.fee,
                        instructions.tickLower,
                        instructions.tickUpper,
                        amount0,
                        amount1,
                        instructions.recipient,
                        instructions.recipientNFT,
                        instructions.deadline,
                        IERC20(address(0)),
                        0,
                        0,
                        "",
                        0,
                        0,
                        "",
                        instructions.amountAddMin0,
                        instructions.amountAddMin1,
                        instructions.swapAndMintReturnData
                    ),
                    instructions.unwrap
                );
            }
            emit ChangeRange(tokenId, newTokenId);
        } else if (instructions.whatToDo == WhatToDo.WITHDRAW_AND_COLLECT_AND_SWAP) {
            uint256 targetAmount;
            if (token0 != instructions.targetToken) {
                (uint256 amountInDelta, uint256 amountOutDelta) = _routerSwap(
                    Swapper.RouterSwapParams(
                        IERC20(token0),
                        IERC20(instructions.targetToken),
                        amount0,
                        instructions.amountOut0Min,
                        instructions.swapData0
                    )
                );
                if (amountInDelta < amount0) {
                    _transferToken(instructions.recipient, IERC20(token0), amount0 - amountInDelta, instructions.unwrap);
                }
                targetAmount += amountOutDelta;
            } else {
                targetAmount += amount0;
            }
            if (token1 != instructions.targetToken) {
                (uint256 amountInDelta, uint256 amountOutDelta) = _routerSwap(
                    Swapper.RouterSwapParams(
                        IERC20(token1),
                        IERC20(instructions.targetToken),
                        amount1,
                        instructions.amountOut1Min,
                        instructions.swapData1
                    )
                );
                if (amountInDelta < amount1) {
                    _transferToken(instructions.recipient, IERC20(token1), amount1 - amountInDelta, instructions.unwrap);
                }
                targetAmount += amountOutDelta;
            } else {
                targetAmount += amount1;
            }

            // send complete target amount
            if (targetAmount != 0 && instructions.targetToken != address(0)) {
                _transferToken(
                    instructions.recipient, IERC20(instructions.targetToken), targetAmount, instructions.unwrap
                );
            }

            emit WithdrawAndCollectAndSwap(tokenId, instructions.targetToken, targetAmount);
        } else {
            revert NotSupportedWhatToDo();
        }
    }

    /// @notice Params for swap() function
    struct SwapParams {
        IERC20 tokenIn;
        IERC20 tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        address recipient; // recipient of tokenOut and leftover tokenIn (if any leftover)
        bytes swapData;
        bool unwrap; // if tokenIn or tokenOut is WETH - unwrap
    }

    /// @notice Swaps amountIn of tokenIn for tokenOut - returning at least minAmountOut
    /// @param params Swap configuration
    /// @return amountOut Output amount of tokenOut
    /// If tokenIn is wrapped native token - both the token or the wrapped token can be sent (the sum of both must be equal to amountIn)
    /// Optionally unwraps any wrapped native token and returns native token instead
    function swap(SwapParams calldata params) external payable returns (uint256 amountOut) {
        if (params.tokenIn == params.tokenOut) {
            revert SameToken();
        }
        _prepareAddApproved(params.tokenIn, IERC20(address(0)), IERC20(address(0)), params.amountIn, 0, 0);

        uint256 amountInDelta;
        (amountInDelta, amountOut) = _routerSwap(
            Swapper.RouterSwapParams(
                params.tokenIn, params.tokenOut, params.amountIn, params.minAmountOut, params.swapData
            )
        );

        // send swapped amount of tokenOut
        if (amountOut != 0) {
            _transferToken(params.recipient, params.tokenOut, amountOut, params.unwrap);
        }

        // if not all was swapped - return leftovers of tokenIn
        uint256 leftOver = params.amountIn - amountInDelta;
        if (leftOver != 0) {
            _transferToken(params.recipient, params.tokenIn, leftOver, params.unwrap);
        }
    }

    /// @notice Params for swapAndMint() function
    struct SwapAndMintParams {
        IERC20 token0;
        IERC20 token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        // how much is provided of token0 and token1
        uint256 amount0;
        uint256 amount1;
        address recipient; // recipient of leftover tokens
        address recipientNFT; // recipient of nft
        uint256 deadline;
        // source token for swaps (maybe either address(0), token0, token1 or another token)
        // if swapSourceToken is another token than token0 or token1 -> amountIn0 + amountIn1 of swapSourceToken are expected to be available
        IERC20 swapSourceToken;
        // if swapSourceToken needs to be swapped to token0 - set values
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0;
        // if swapSourceToken needs to be swapped to token1 - set values
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1;
        // min amount to be added after swap
        uint256 amountAddMin0;
        uint256 amountAddMin1;
        // data to be sent along newly created NFT when transfered to recipientNFT (sent to IERC721Receiver callback)
        bytes returnData;
    }

    /// @notice Does 1 or 2 swaps from swapSourceToken to token0 and token1 and adds as much as possible liquidity to a newly minted position. Newly minted NFT and leftover tokens are returned to recipient.
    /// @param params Swap and mint configuration
    /// @return tokenId The ID of the token that represents the minted position
    /// @return liquidity The amount of liquidity for this position
    /// @return amount0 The amount of token0
    /// @return amount1 The amount of token1
    function swapAndMint(SwapAndMintParams calldata params)
        external
        payable
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        if (params.token0 == params.token1) {
            revert SameToken();
        }
        _prepareAddApproved(
            params.token0,
            params.token1,
            params.swapSourceToken,
            params.amount0,
            params.amount1,
            params.amountIn0 + params.amountIn1
        );

        (tokenId, liquidity, amount0, amount1) = _swapAndMint(params, msg.value != 0);
    }

    /// @notice Params for swapAndIncreaseLiquidity() function
    struct SwapAndIncreaseLiquidityParams {
        uint256 tokenId;
        // how much is provided of token0 and token1
        uint256 amount0;
        uint256 amount1;
        address recipient; // recipient of leftover tokens
        uint256 deadline;
        // source token for swaps (maybe either address(0), token0, token1 or another token)
        // if swapSourceToken is another token than token0 or token1 -> amountIn0 + amountIn1 of swapSourceToken are expected to be available
        IERC20 swapSourceToken;
        // if swapSourceToken needs to be swapped to token0 - set values
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0;
        // if swapSourceToken needs to be swapped to token1 - set values
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1;
        // min amount to be added after swap
        uint256 amountAddMin0;
        uint256 amountAddMin1;
    }

    /// @notice Does 1 or 2 swaps from swapSourceToken to token0 and token1 and adds as much as possible liquidity to any existing position (no need to be position owner). Sends any leftover tokens to recipient.
    /// @param params Swap and increase liquidity configuration
    /// @return liquidity The amount of liquidity added
    /// @return amount0 The amount of token0 added
    /// @return amount1 The amount of token1 added
    function swapAndIncreaseLiquidity(SwapAndIncreaseLiquidityParams calldata params)
        external
        payable
        returns (uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);
        _prepareAddApproved(
            IERC20(token0),
            IERC20(token1),
            params.swapSourceToken,
            params.amount0,
            params.amount1,
            params.amountIn0 + params.amountIn1
        );

        (liquidity, amount0, amount1) = _swapAndIncrease(params, IERC20(token0), IERC20(token1), msg.value != 0);
    }

    function _prepareAddApproved(
        IERC20 token0,
        IERC20 token1,
        IERC20 otherToken,
        uint256 amount0,
        uint256 amount1,
        uint256 amountOther
    ) internal {
        (uint256 needed0, uint256 needed1, uint256 neededOther) =
            _prepareAdd(token0, token1, otherToken, amount0, amount1, amountOther);

        if (needed0 != 0) {
            SafeERC20.safeTransferFrom(token0, msg.sender, address(this), needed0);
        }
        if (needed1 != 0) {
            SafeERC20.safeTransferFrom(token1, msg.sender, address(this), needed1);
        }
        if (neededOther != 0) {
            SafeERC20.safeTransferFrom(otherToken, msg.sender, address(this), neededOther);
        }
    }

    // checks if required amounts are provided and are exact - wraps any provided ETH as WETH
    // if less or more provided reverts
    function _prepareAdd(
        IERC20 token0,
        IERC20 token1,
        IERC20 otherToken,
        uint256 amount0,
        uint256 amount1,
        uint256 amountOther
    ) internal returns (uint256 needed0, uint256 needed1, uint256 neededOther) {
        uint256 amountAdded0;
        uint256 amountAdded1;
        uint256 amountAddedOther;

        // wrap ether sent
        if (msg.value != 0) {
            weth.deposit{value: msg.value}();

            if (address(weth) == address(token0)) {
                amountAdded0 = msg.value;
                if (amountAdded0 > amount0) {
                    revert TooMuchEtherSent();
                }
            } else if (address(weth) == address(token1)) {
                amountAdded1 = msg.value;
                if (amountAdded1 > amount1) {
                    revert TooMuchEtherSent();
                }
            } else if (address(weth) == address(otherToken)) {
                amountAddedOther = msg.value;
                if (amountAddedOther > amountOther) {
                    revert TooMuchEtherSent();
                }
            } else {
                revert NoEtherToken();
            }
        }

        // calculate missing token amounts
        if (amount0 > amountAdded0) {
            needed0 = amount0 - amountAdded0;
        }
        if (amount1 > amountAdded1) {
            needed1 = amount1 - amountAdded1;
        }
        if (
            amountOther > amountAddedOther && address(otherToken) != address(0) && token0 != otherToken
                && token1 != otherToken
        ) {
            neededOther = amountOther - amountAddedOther;
        }
    }

    // swap and mint logic
    function _swapAndMint(SwapAndMintParams memory params, bool unwrap)
        internal
        returns (uint256 tokenId, uint128 liquidity, uint256 added0, uint256 added1)
    {
        (uint256 total0, uint256 total1) = _swapAndPrepareAmounts(params, unwrap);

        INonfungiblePositionManager.MintParams memory mintParams = INonfungiblePositionManager.MintParams(
            address(params.token0),
            address(params.token1),
            params.fee,
            params.tickLower,
            params.tickUpper,
            total0,
            total1,
            params.amountAddMin0,
            params.amountAddMin1,
            address(this), // is sent to real recipient aftwards
            params.deadline
        );

        // mint is done to address(this) because it is not a safemint and safeTransferFrom needs to be done manually afterwards
        (tokenId, liquidity, added0, added1) = _mintPosition(mintParams);
        nonfungiblePositionManager.safeTransferFrom(address(this), params.recipientNFT, tokenId, params.returnData);

        emit SwapAndMint(tokenId, liquidity, added0, added1);

        _returnLeftoverTokens(params.recipient, params.token0, params.token1, total0, total1, added0, added1, unwrap);
    }

    // swap and increase logic
    function _swapAndIncrease(SwapAndIncreaseLiquidityParams memory params, IERC20 token0, IERC20 token1, bool unwrap)
        internal
        returns (uint128 liquidity, uint256 added0, uint256 added1)
    {
        (uint256 total0, uint256 total1) = _swapAndPrepareAmounts(
            SwapAndMintParams(
                token0,
                token1,
                0,
                0,
                0,
                params.amount0,
                params.amount1,
                params.recipient,
                params.recipient,
                params.deadline,
                params.swapSourceToken,
                params.amountIn0,
                params.amountOut0Min,
                params.swapData0,
                params.amountIn1,
                params.amountOut1Min,
                params.swapData1,
                params.amountAddMin0,
                params.amountAddMin1,
                ""
            ),
            unwrap
        );

        INonfungiblePositionManager.IncreaseLiquidityParams memory increaseLiquidityParams = INonfungiblePositionManager
            .IncreaseLiquidityParams(
            params.tokenId, total0, total1, params.amountAddMin0, params.amountAddMin1, params.deadline
        );

        (liquidity, added0, added1) = nonfungiblePositionManager.increaseLiquidity(increaseLiquidityParams);

        emit SwapAndIncreaseLiquidity(params.tokenId, liquidity, added0, added1);

        _returnLeftoverTokens(params.recipient, token0, token1, total0, total1, added0, added1, unwrap);
    }

    // swaps available tokens and prepares max amounts to be added to nonfungiblePositionManager
    function _swapAndPrepareAmounts(SwapAndMintParams memory params, bool unwrap)
        internal
        returns (uint256 total0, uint256 total1)
    {
        if (params.swapSourceToken == params.token0) {
            if (params.amount0 < params.amountIn1) {
                revert AmountError();
            }
            (uint256 amountInDelta, uint256 amountOutDelta) = _routerSwap(
                Swapper.RouterSwapParams(
                    params.token0, params.token1, params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            total0 = params.amount0 - amountInDelta;
            total1 = params.amount1 + amountOutDelta;
        } else if (params.swapSourceToken == params.token1) {
            if (params.amount1 < params.amountIn0) {
                revert AmountError();
            }
            (uint256 amountInDelta, uint256 amountOutDelta) = _routerSwap(
                Swapper.RouterSwapParams(
                    params.token1, params.token0, params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            total1 = params.amount1 - amountInDelta;
            total0 = params.amount0 + amountOutDelta;
        } else if (address(params.swapSourceToken) != address(0)) {
            (uint256 amountInDelta0, uint256 amountOutDelta0) = _routerSwap(
                Swapper.RouterSwapParams(
                    params.swapSourceToken, params.token0, params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            (uint256 amountInDelta1, uint256 amountOutDelta1) = _routerSwap(
                Swapper.RouterSwapParams(
                    params.swapSourceToken, params.token1, params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            total0 = params.amount0 + amountOutDelta0;
            total1 = params.amount1 + amountOutDelta1;

            // return third token leftover if any
            uint256 leftOver = params.amountIn0 + params.amountIn1 - amountInDelta0 - amountInDelta1;

            if (leftOver != 0) {
                _transferToken(params.recipient, params.swapSourceToken, leftOver, unwrap);
            }
        } else {
            total0 = params.amount0;
            total1 = params.amount1;
        }

        if (total0 != 0) {
            SafeERC20.safeApprove(params.token0, address(nonfungiblePositionManager), 0);
            SafeERC20.safeIncreaseAllowance(params.token0, address(nonfungiblePositionManager), total0);
        }
        if (total1 != 0) {
            SafeERC20.safeApprove(params.token1, address(nonfungiblePositionManager), 0);
            SafeERC20.safeIncreaseAllowance(params.token1, address(nonfungiblePositionManager), total1);
        }
    }

    // returns leftover token balances
    function _returnLeftoverTokens(
        address to,
        IERC20 token0,
        IERC20 token1,
        uint256 total0,
        uint256 total1,
        uint256 added0,
        uint256 added1,
        bool unwrap
    ) internal {
        uint256 left0 = total0 - added0;
        uint256 left1 = total1 - added1;

        // return leftovers
        if (left0 != 0) {
            _transferToken(to, token0, left0, unwrap);
        }
        if (left1 != 0) {
            _transferToken(to, token1, left1, unwrap);
        }
    }

    // transfers token (or unwraps WETH and sends ETH)
    function _transferToken(address to, IERC20 token, uint256 amount, bool unwrap) internal {
        if (unwrap && address(weth) == address(token)) {
            weth.withdraw(amount);
            (bool sent,) = to.call{value: amount}("");
            if (!sent) {
                revert EtherSendFailed();
            }
        } else {
            SafeERC20.safeTransfer(token, to, amount);
        }
    }

    // decreases liquidity from uniswap v3 position
    function _decreaseLiquidity(
        uint256 tokenId,
        uint128 liquidity,
        uint256 deadline,
        uint256 token0Min,
        uint256 token1Min
    ) internal returns (uint256 amount0, uint256 amount1) {
        if (liquidity != 0) {
            (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(
                INonfungiblePositionManager.DecreaseLiquidityParams(tokenId, liquidity, token0Min, token1Min, deadline)
            );
        }
    }

    // collects specified amount of fees from uniswap v3 position
    function _collectFees(uint256 tokenId, IERC20 token0, IERC20 token1, uint128 collectAmount0, uint128 collectAmount1)
        internal
        returns (uint256 amount0, uint256 amount1)
    {
        uint256 balanceBefore0 = token0.balanceOf(address(this));
        uint256 balanceBefore1 = token1.balanceOf(address(this));
        (amount0, amount1) = nonfungiblePositionManager.collect(
            INonfungiblePositionManager.CollectParams(tokenId, address(this), collectAmount0, collectAmount1)
        );
        uint256 balanceAfter0 = token0.balanceOf(address(this));
        uint256 balanceAfter1 = token1.balanceOf(address(this));

        // reverts for fee-on-transfer tokens
        if (balanceAfter0 - balanceBefore0 != amount0) {
            revert CollectError();
        }
        if (balanceAfter1 - balanceBefore1 != amount1) {
            revert CollectError();
        }
    }

    // needed for WETH unwrapping
    receive() external payable {
        if (msg.sender != address(weth)) {
            revert NotWETH();
        }
    }
}


// ========== utils\ChainlinkFeedCombinator.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "../../lib/AggregatorV3Interface.sol";
import "v3-core/libraries/FullMath.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title Helper contract which allows to combine 2 chainlink feeds into 1 like wstETH/ETH and ETH/USD
contract ChainlinkFeedCombinator is AggregatorV3Interface {
  
    uint256 immutable firstDecimalsDivisor;
    uint8 immutable secondDecimals;
    AggregatorV3Interface immutable firstFeed;
    AggregatorV3Interface immutable secondFeed;

    constructor(AggregatorV3Interface first, AggregatorV3Interface second) {
        firstDecimalsDivisor = 10 ** first.decimals();
        secondDecimals = second.decimals();

        firstFeed = first;
        secondFeed = second;
    }

    function latestRoundData() external override view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) {
        (uint80 firstRoundId, int256 firstAnswer,uint256 firstStartedAt, uint256 firstUpdatedAt, uint80 firstAnsweredInRound) = firstFeed.latestRoundData();
        int256 secondAnswer;
        (roundId, secondAnswer, startedAt, updatedAt, answeredInRound) = secondFeed.latestRoundData();

        // take oldest values - roundId and answeredInRound dont make much sense but will be returned from the corresponding feed (which has the older data)
        if (updatedAt > firstUpdatedAt) {
            roundId = firstRoundId;
            startedAt = firstStartedAt;
            updatedAt = firstUpdatedAt;
            answeredInRound = firstAnsweredInRound;
        }

        // only do calculation with valid values - otherwise returns 0
        if (firstAnswer > 0 && secondAnswer > 0) {
            answer = SafeCast.toInt256(
                FullMath.mulDiv(SafeCast.toUint256(firstAnswer), SafeCast.toUint256(secondAnswer), firstDecimalsDivisor)
            );
        }
    }

    function decimals() external override view returns (uint8) {
        return secondDecimals;
    }
}


// ========== utils\Constants.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

abstract contract Constants {
    uint256 internal constant Q32 = 2 ** 32;
    uint256 internal constant Q64 = 2 ** 64;
    uint256 internal constant Q96 = 2 ** 96;
    uint256 internal constant Q128 = 2 ** 128;
    uint256 internal constant Q160 = 2 ** 160;

    error Unauthorized();
    error Reentrancy();
    error NotConfigured();
    error NotReady();
    error InvalidConfig();
    error TWAPCheckFailed();
    error WrongContract();
    error InvalidToken();

    error SwapFailed();
    error SlippageError();
    error MissingSwapData();
    error SwapAmountTooLarge();

    error ExceedsMaxReward();
    error InvalidPool();
    error ChainlinkPriceError();
    error PriceDifferenceExceeded();
    error SequencerDown();
    error SequencerGracePeriodNotOver();
    error SequencerUptimeFeedInvalid();

    error CollateralFail();
    error MinLoanSize();
    error GlobalDebtLimit();
    error GlobalLendLimit();
    error DailyDebtIncreaseLimit();
    error DailyLendIncreaseLimit();
    error InsufficientLiquidity();
    error NotLiquidatable();
    error InterestNotUpdated();
    error TransformNotAllowed();
    error TransformFailed();
    error CollateralFactorExceedsMax();
    error CollateralValueLimit();
    error NoLiquidity();
    error DebtChanged();
    error NeedsRepay();
    error NoSharesRepayed();

    error SelfSend();
    error NotSupportedWhatToDo();
    error SameToken();
    error AmountError();
    error CollectError();
    error TransferError();

    error TooMuchEtherSent();
    error NoEtherToken();
    error EtherSendFailed();
    error NotWETH();

    error NotEnoughReward();
    error SameRange();
    error NotSupportedFeeTier();

    error GaugeManagerNotSet();
    error GaugeManagerAlreadySet();
    error NotDepositor();
    error NotStaked();
}


// ========== utils\FlashloanLiquidator.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-core/interfaces/callback/IUniswapV3FlashCallback.sol";

import "../interfaces/IVault.sol";
import "./Swapper.sol";

/// @title Helper contract which allows atomic liquidation and needed swaps by using UniV3 Flashloan
contract FlashloanLiquidator is Swapper, IUniswapV3FlashCallback {
    // NOTE FOR AUDITS:
    // This helper is intentionally designed to be stateless between calls. Any unsolicited/dust token balance that
    // ends up here is treated as out-of-protocol and recoverability is not guaranteed by design.
    address private activeFlashPool;
    bytes32 private activeFlashDataHash;

    struct FlashCallbackData {
        uint256 tokenId;
        uint256 liquidationCost;
        IVault vault;
        IUniswapV3Pool flashLoanPool;
        IERC20 asset;
        RouterSwapParams swap0;
        RouterSwapParams swap1;
        address liquidator;
        uint256 minReward;
        uint256 deadline;
    }

    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Swapper(_nonfungiblePositionManager, _universalRouter, _zeroxAllowanceHolder) {}

    struct LiquidateParams {
        uint256 tokenId; // loan to liquidate
        IVault vault; // vault where the loan is
        IUniswapV3Pool flashLoanPool; // pool which is used for flashloan - may not be used in the swaps below
        uint256 amount0In; // how much of token0 to swap to asset (0 if no swap should be done)
        bytes swapData0; // swap data for token0 swap
        uint256 amount1In; // how much of token1 to swap to asset (0 if no swap should be done)
        bytes swapData1; // swap data for token1 swap
        uint256 minReward; // min reward amount (works as a global slippage control for complete operation)
        uint256 deadline; // deadline for uniswap operations
    }

    /// @notice Liquidates a loan, using a Uniswap Flashloan
    function liquidate(LiquidateParams calldata params) external {
        if (activeFlashPool != address(0)) {
            revert Unauthorized();
        }

        (,,, uint256 liquidationCost, uint256 liquidationValue) = params.vault.loanInfo(params.tokenId);
        if (liquidationValue == 0) {
            revert NotLiquidatable();
        }

        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);
        address asset = params.vault.asset();

        address flashToken0 = params.flashLoanPool.token0();
        address flashToken1 = params.flashLoanPool.token1();
        bool isAsset0 = flashToken0 == asset;
        if (!isAsset0 && flashToken1 != asset) {
            revert InvalidPool();
        }
        bytes memory data = abi.encode(
            FlashCallbackData(
                params.tokenId,
                liquidationCost,
                params.vault,
                params.flashLoanPool,
                IERC20(asset),
                RouterSwapParams(IERC20(token0), IERC20(asset), params.amount0In, 0, params.swapData0),
                RouterSwapParams(IERC20(token1), IERC20(asset), params.amount1In, 0, params.swapData1),
                msg.sender,
                params.minReward,
                params.deadline
            )
        );
        activeFlashPool = address(params.flashLoanPool);
        activeFlashDataHash = keccak256(data);
        params.flashLoanPool.flash(address(this), isAsset0 ? liquidationCost : 0, !isAsset0 ? liquidationCost : 0, data);
        activeFlashPool = address(0);
        activeFlashDataHash = bytes32(0);
    }

    function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData) external override {
        if (msg.sender != activeFlashPool || keccak256(callbackData) != activeFlashDataHash) {
            revert Unauthorized();
        }

        FlashCallbackData memory data = abi.decode(callbackData, (FlashCallbackData));
        if (msg.sender != address(data.flashLoanPool)) {
            revert Unauthorized();
        }

        address poolToken0 = data.flashLoanPool.token0();
        address poolToken1 = data.flashLoanPool.token1();
        if (!_isFactoryPool(data.flashLoanPool, poolToken0, poolToken1)) {
            revert Unauthorized();
        }
        if (address(data.asset) != poolToken0 && address(data.asset) != poolToken1) {
            revert InvalidPool();
        }

        SafeERC20.safeIncreaseAllowance(data.asset, address(data.vault), data.liquidationCost);
        data.vault
            .liquidate(
                IVault.LiquidateParams(
                    data.tokenId, data.swap0.amountIn, data.swap1.amountIn, address(this), data.deadline
                )
            );
        SafeERC20.safeApprove(data.asset, address(data.vault), 0);

        // do swaps
        _routerSwap(data.swap0);
        _routerSwap(data.swap1);

        // transfer lent amount + fee (only one token can have fee) - back to pool
        SafeERC20.safeTransfer(data.asset, msg.sender, data.liquidationCost + (fee0 + fee1));

        // return all leftover tokens to liquidator
        if (data.swap0.tokenIn != data.asset) {
            _transferBalanceIfNonZero(data.swap0.tokenIn, data.liquidator);
        }
        if (data.swap1.tokenIn != data.asset) {
            _transferBalanceIfNonZero(data.swap1.tokenIn, data.liquidator);
        }
        uint256 assetBalance = data.asset.balanceOf(address(this));
        if (assetBalance < data.minReward) {
            revert NotEnoughReward();
        }
        if (assetBalance != 0) {
            SafeERC20.safeTransfer(data.asset, data.liquidator, assetBalance);
        }
    }

    function _isFactoryPool(IUniswapV3Pool pool, address poolToken0, address poolToken1) internal view returns (bool) {
        // Uniswap style: resolve by fee.
        if (address(_getPool(poolToken0, poolToken1, pool.fee())) == address(pool)) {
            return true;
        }

        // Slipstream style: resolve by tickSpacing.
        (bool success, bytes memory tickSpacingData) =
            address(pool).staticcall(abi.encodeWithSignature("tickSpacing()"));
        if (!success || tickSpacingData.length < 32) {
            return false;
        }

        int24 tickSpacing = abi.decode(tickSpacingData, (int24));
        if (tickSpacing <= 0) {
            return false;
        }

        return address(_getPool(poolToken0, poolToken1, _toTickSpacingU24(tickSpacing))) == address(pool);
    }

    function _transferBalanceIfNonZero(IERC20 token, address recipient) internal {
        uint256 balance = token.balanceOf(address(this));
        if (balance != 0) {
            SafeERC20.safeTransfer(token, recipient, balance);
        }
    }

    function _toTickSpacingU24(int24 tickSpacing) internal pure returns (uint24 value) {
        assembly ("memory-safe") {
            value := tickSpacing
        }
    }
}


// ========== utils\Swapper.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

import "v3-core/interfaces/IUniswapV3Factory.sol";
import "v3-core/interfaces/callback/IUniswapV3SwapCallback.sol";
import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-core/libraries/TickMath.sol";
import "v3-core/libraries/FullMath.sol";

import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "../interfaces/aerodrome/IAerodromeSlipstreamFactory.sol";

import "../../lib/IWETH9.sol";
import "../../lib/IUniversalRouter.sol";
import "../utils/Constants.sol";

// base functionality to do swaps with different routing protocols
abstract contract Swapper is IUniswapV3SwapCallback, Constants {
    event Swap(address indexed tokenIn, address indexed tokenOut, uint256 amountIn, uint256 amountOut);

    // Aerodrome Slipstream NPM mint selector:
    // mint((address,address,int24,int24,int24,uint256,uint256,uint256,uint256,address,uint256,uint160))
    bytes4 private constant AERODROME_MINT_SELECTOR = 0xb5007d1f;

    /// @notice Wrapped native token address
    IWETH9 public immutable weth;

    address public immutable factory;

    /// @notice Uniswap v3 position manager
    INonfungiblePositionManager public immutable nonfungiblePositionManager;

    /// @notice Uniswap Universal Router
    address public immutable universalRouter;

    /// @notice 0x Protocol AllowanceHolder contract
    address public immutable zeroxAllowanceHolder;

    /// @notice Constructor
    /// @param _nonfungiblePositionManager Uniswap v3 position manager
    /// @param _universalRouter Uniswap Universal Router
    /// @param _zeroxAllowanceHolder 0x Protocol AllowanceHolder contract
    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) {
        weth = IWETH9(_nonfungiblePositionManager.WETH9());
        factory = _nonfungiblePositionManager.factory();
        nonfungiblePositionManager = _nonfungiblePositionManager;
        universalRouter = _universalRouter;
        zeroxAllowanceHolder = _zeroxAllowanceHolder;
    }

    // swap data for uni - must include sweep for input token
    struct UniversalRouterData {
        bytes commands;
        bytes[] inputs;
        uint256 deadline;
    }

    struct RouterSwapParams {
        IERC20 tokenIn;
        IERC20 tokenOut;
        uint256 amountIn;
        uint256 amountOutMin;
        bytes swapData;
    }

    // general swap function which uses external router with off-chain calculated swap instructions
    // does slippage check with amountOutMin param
    // returns token amounts deltas after swap
    function _routerSwap(RouterSwapParams memory params)
        internal
        returns (uint256 amountInDelta, uint256 amountOutDelta)
    {
        if (
            params.amountIn == 0 || params.swapData.length == 0 || address(params.tokenOut) == address(0)
                || address(params.tokenIn) == address(0)
        ) {
            return (0, 0);
        }

        uint256 balanceInBefore = params.tokenIn.balanceOf(address(this));
        uint256 balanceOutBefore = params.tokenOut.balanceOf(address(this));

        // Check if this is Universal Router data by looking at first 32 bytes
        bool isUniversalRouter;
        bytes memory swapData = params.swapData;
        address uniRouter = universalRouter;
        assembly ("memory-safe") {
            let firstWord := mload(add(swapData, 32))
            isUniversalRouter := eq(firstWord, uniRouter)
        }

        if (isUniversalRouter) {
            // Handle Universal Router case
            (, bytes memory routerData) = abi.decode(params.swapData, (address, bytes));
            UniversalRouterData memory data = abi.decode(routerData, (UniversalRouterData));
            SafeERC20.safeTransfer(params.tokenIn, universalRouter, params.amountIn);
            IUniversalRouter(universalRouter).execute(data.commands, data.inputs, data.deadline);
        } else {
            // For 0x v2, use raw data
            SafeERC20.safeIncreaseAllowance(params.tokenIn, zeroxAllowanceHolder, params.amountIn);
            (bool success,) = zeroxAllowanceHolder.call(params.swapData);
            if (!success) {
                revert SwapFailed();
            }
            SafeERC20.safeApprove(params.tokenIn, zeroxAllowanceHolder, 0);
        }

        amountInDelta = balanceInBefore - params.tokenIn.balanceOf(address(this));
        amountOutDelta = params.tokenOut.balanceOf(address(this)) - balanceOutBefore;

        if (amountOutDelta < params.amountOutMin) {
            revert SlippageError();
        }

        emit Swap(address(params.tokenIn), address(params.tokenOut), amountInDelta, amountOutDelta);
    }

    struct PoolSwapParams {
        IUniswapV3Pool pool;
        IERC20 token0;
        IERC20 token1;
        uint24 fee;
        bool swap0For1;
        uint256 amountIn;
        uint256 amountOutMin;
    }

    struct AerodromeMintParams {
        address token0;
        address token1;
        int24 tickSpacing;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
        uint160 sqrtPriceX96;
    }

    // execute swap directly on specified pool
    // amounts must be available on the contract for both tokens
    function _poolSwap(PoolSwapParams memory params) internal returns (uint256 amountInDelta, uint256 amountOutDelta) {
        if (params.amountIn != 0) {
            (int256 amount0Delta, int256 amount1Delta) = params.pool
                .swap(
                    address(this),
                    params.swap0For1,
                    int256(params.amountIn),
                    (params.swap0For1 ? TickMath.MIN_SQRT_RATIO + 1 : TickMath.MAX_SQRT_RATIO - 1),
                    abi.encode(
                        params.swap0For1 ? params.token0 : params.token1,
                        params.swap0For1 ? params.token1 : params.token0,
                        params.fee
                    )
                );
            if (params.swap0For1) {
                amountInDelta = SafeCast.toUint256(amount0Delta);
                amountOutDelta = SafeCast.toUint256(-amount1Delta);
            } else {
                amountInDelta = SafeCast.toUint256(amount1Delta);
                amountOutDelta = SafeCast.toUint256(-amount0Delta);
            }

            // amountMin slippage check
            if (amountOutDelta < params.amountOutMin) {
                revert SlippageError();
            }
        }
    }

    // validate if swap can be done with specified oracle parameters - if not possible reverts
    // if possible returns minAmountOut
    function _validateSwap(
        bool swap0For1,
        uint256 amountIn,
        IUniswapV3Pool pool,
        int24 currentTick,
        uint160 sqrtPriceX96,
        uint32 twapPeriod,
        uint16 maxTickDifference,
        uint64 maxPriceDifferenceX64
    ) internal view returns (uint256 amountOutMin) {
        if (!_hasMaxTWAPTickDifference(pool, twapPeriod, currentTick, maxTickDifference)) {
            revert TWAPCheckFailed();
        }

        uint256 priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, Q96);
        if (swap0For1) {
            amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), priceX96, Q160);
        } else {
            amountOutMin = FullMath.mulDiv(amountIn * (Q64 - maxPriceDifferenceX64), Q32, priceX96);
        }
    }

    function _hasMaxTWAPTickDifference(IUniswapV3Pool pool, uint32 twapPeriod, int24 currentTick, uint16 maxDifference)
        internal
        view
        returns (bool)
    {
        (int24 twapTick, bool twapOk) = _getTWAPTick(pool, twapPeriod);
        if (twapOk) {
            int256 res = twapTick - currentTick;
            int256 maxDifferenceInt = int256(uint256(maxDifference));
            return res >= -maxDifferenceInt && res <= maxDifferenceInt;
        } else {
            return false;
        }
    }

    function _getTWAPTick(IUniswapV3Pool pool, uint32 twapSeconds) internal view returns (int24, bool) {
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 0;
        secondsAgos[1] = twapSeconds;

        try pool.observe(secondsAgos) returns (int56[] memory tickCumulatives, uint160[] memory) {
            int56 delta = tickCumulatives[0] - tickCumulatives[1];
            int256 twapSecondsInt = int256(uint256(twapSeconds));
            int24 tick = SafeCast.toInt24(int256(delta) / twapSecondsInt);
            if (delta < 0 && int256(delta) % twapSecondsInt != 0) tick--;
            return (tick, true);
        } catch {
            return (0, false);
        }
    }

    function _getPoolSlot0(IUniswapV3Pool pool) internal view returns (uint160 sqrtPriceX96, int24 tick) {
        (bool success, bytes memory data) = address(pool).staticcall(abi.encodeWithSelector(pool.slot0.selector));
        if (!success || data.length < 64) {
            revert InvalidPool();
        }

        uint256 word0;
        uint256 word1;
        assembly ("memory-safe") {
            word0 := mload(add(data, 32))
            word1 := mload(add(data, 64))
        }

        sqrtPriceX96 = SafeCast.toUint160(word0);
        assembly ("memory-safe") {
            tick := signextend(2, word1)
        }
    }

    function _mintPosition(INonfungiblePositionManager.MintParams memory params)
        internal
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        AerodromeMintParams memory aerodromeParams = AerodromeMintParams({
            token0: params.token0,
            token1: params.token1,
            tickSpacing: _toTickSpacing(params.fee),
            tickLower: params.tickLower,
            tickUpper: params.tickUpper,
            amount0Desired: params.amount0Desired,
            amount1Desired: params.amount1Desired,
            amount0Min: params.amount0Min,
            amount1Min: params.amount1Min,
            recipient: params.recipient,
            deadline: params.deadline,
            sqrtPriceX96: 0
        });

        // Try Aerodrome mint first. On Uniswap this selector is missing and call reverts.
        (bool aerodromeSuccess, bytes memory aerodromeData) = address(nonfungiblePositionManager).call(
            abi.encodeWithSelector(AERODROME_MINT_SELECTOR, aerodromeParams)
        );
        if (aerodromeSuccess) {
            return abi.decode(aerodromeData, (uint256, uint128, uint256, uint256));
        }

        // Fallback to canonical Uniswap V3 mint.
        (bool uniswapSuccess, bytes memory uniswapData) =
            address(nonfungiblePositionManager).call(abi.encodeWithSelector(INonfungiblePositionManager.mint.selector, params));
        if (uniswapSuccess) {
            return abi.decode(uniswapData, (uint256, uint128, uint256, uint256));
        }

        // Bubble the most informative revert data.
        if (uniswapData.length > 0) {
            _revertWithData(uniswapData);
        }
        _revertWithData(aerodromeData);
    }

    function _revertWithData(bytes memory revertData) private pure {
        if (revertData.length == 0) {
            revert SwapFailed();
        }
        assembly ("memory-safe") {
            revert(add(revertData, 32), mload(revertData))
        }
    }

    // swap callback function where amount for swap is payed
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external override {
        require(amount0Delta > 0 || amount1Delta > 0); // swaps entirely within 0-liquidity regions are not supported

        // check if really called from pool
        (address tokenIn, address tokenOut, uint24 fee) = abi.decode(data, (address, address, uint24));
        if (address(_getPool(tokenIn, tokenOut, fee)) != msg.sender) {
            revert Unauthorized();
        }

        // transfer needed amount of tokenIn
        int256 amountInDelta = amount0Delta > 0 ? amount0Delta : amount1Delta;
        SafeERC20.safeTransfer(IERC20(tokenIn), msg.sender, SafeCast.toUint256(amountInDelta));
    }

    // get pool for token
    function _getPool(address tokenA, address tokenB, uint24 fee) internal view returns (IUniswapV3Pool) {
        // Aerodrome uses getPool(tokenA, tokenB, tickSpacing) and stores tickSpacing in the `fee` field of positions().
        (bool success, bytes memory data) = factory.staticcall(
            abi.encodeWithSelector(IAerodromeSlipstreamFactory.getPool.selector, tokenA, tokenB, _toTickSpacing(fee))
        );
        if (success && data.length >= 32) {
            address poolAddress = abi.decode(data, (address));
            if (poolAddress != address(0)) {
                return IUniswapV3Pool(poolAddress);
            }
        }

        // Uniswap v3 uses getPool(tokenA, tokenB, fee).
        (success, data) =
            factory.staticcall(abi.encodeWithSelector(IUniswapV3Factory.getPool.selector, tokenA, tokenB, fee));
        if (success && data.length >= 32) {
            return IUniswapV3Pool(abi.decode(data, (address)));
        }

        return IUniswapV3Pool(address(0));
    }

    function _toTickSpacing(uint24 fee) internal pure returns (int24 tickSpacing) {
        assembly ("memory-safe") {
            tickSpacing := fee
        }
    }
}


// ========== V3Oracle.sol ==========
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "v3-core/interfaces/IUniswapV3Factory.sol";
import "v3-core/interfaces/IUniswapV3Pool.sol";

import "v3-core/libraries/FullMath.sol";
import "v3-core/libraries/TickMath.sol";

import "v3-periphery/libraries/LiquidityAmounts.sol";

import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

import "../lib/AggregatorV3Interface.sol";

import "./interfaces/IV3Oracle.sol";
import "./interfaces/aerodrome/IAerodromeSlipstreamFactory.sol";
import "./utils/Constants.sol";

/// @title V3Oracle to be used in V3Vault to calculate position values
/// @notice It uses both chainlink and uniswap v3 TWAP and provides emergency fallback mode
contract V3Oracle is IV3Oracle, Ownable2Step, Constants {
    uint256 private constant SEQUENCER_GRACE_PERIOD_TIME = 600; // 10mins

    event TokenConfigUpdated(address indexed token, TokenConfig config);
    event OracleModeUpdated(address indexed token, Mode mode);
    event SetMaxPoolPriceDifference(uint16 maxPoolPriceDifference);
    event SetEmergencyAdmin(address emergencyAdmin);
    event SetSequencerUptimeFeed(address sequencerUptimeFeed);

    enum Mode {
        NOT_SET,
        CHAINLINK_TWAP_VERIFY, // using chainlink for price and TWAP to verify
        TWAP_CHAINLINK_VERIFY, // using TWAP for price and chainlink to verify
        CHAINLINK, // using only chainlink directly
        TWAP // using TWAP directly

    }

    address public immutable factory;
    INonfungiblePositionManager public immutable nonfungiblePositionManager;

    // common token which is used in TWAP pools
    address public immutable referenceToken;
    uint8 public immutable referenceTokenDecimals;

    // common token which is used in chainlink feeds as "pair" (address(0) if USD or another non-token reference)
    address public immutable chainlinkReferenceToken;

    struct TokenConfig {
        AggregatorV3Interface feed; // chainlink feed
        uint32 maxFeedAge;
        uint8 feedDecimals;
        uint8 tokenDecimals;
        uint32 twapSeconds;
        IUniswapV3Pool pool; // reference pool
        bool isToken0;
        Mode mode;
        uint16 maxDifference; // max price difference x10000
    }

    // token => config mapping
    mapping(address => TokenConfig) public feedConfigs;

    uint16 public maxPoolPriceDifference; // max price difference between oracle derived price and pool price x10000

    // address which can call special emergency actions without timelock
    address public emergencyAdmin;

    // feed to check sequencer up on L2s - address(0) when not needed
    address public sequencerUptimeFeed;

    // constructor: sets owner of contract
    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _referenceToken,
        address _chainlinkReferenceToken
    ) {
        nonfungiblePositionManager = _nonfungiblePositionManager;
        factory = _nonfungiblePositionManager.factory();
        referenceToken = _referenceToken;
        referenceTokenDecimals = IERC20Metadata(_referenceToken).decimals();
        chainlinkReferenceToken = _chainlinkReferenceToken;
    }

    /// @notice Gets value and prices of a uniswap v3 lp position in specified token
    /// @dev uses configured oracles and verfies price on second oracle - if fails - reverts
    /// @dev all involved tokens must be configured in oracle - otherwise reverts
    /// @param tokenId tokenId of position
    /// @param token address of token in which value and prices should be given
    /// @param ignoreFees if true, skips fee-growth fee calculation and returns feeValue as 0
    /// @return value value of complete position at current oracle prices
    /// @return feeValue value of positions fees only at current oracle prices
    /// @return price0X96 price of token0
    /// @return price1X96 price of token1
    function getValue(uint256 tokenId, address token, bool ignoreFees)
        external
        view
        override
        returns (uint256 value, uint256 feeValue, uint256 price0X96, uint256 price1X96)
    {
        PositionState memory state = _loadPositionState(tokenId);
        _populatePrices(state);
        (uint256 amount0, uint256 amount1) = _getAmounts(state);
        uint128 fees0;
        uint128 fees1;
        if (!ignoreFees) {
            (fees0, fees1) = _getFees(state);
        }

        // get price of quote token
        uint256 priceTokenX96;
        if (state.token0 == token) {
            priceTokenX96 = state.price0X96;
        } else if (state.token1 == token) {
            priceTokenX96 = state.price1X96;
        } else {
            (priceTokenX96,) = _getReferenceTokenPriceX96(token, state.cachedChainlinkReferencePriceX96);
        }

        // calculate outputs
        uint256 amount0WithFees = amount0 + fees0;
        uint256 amount1WithFees = amount1 + fees1;
        value = _sumMulDiv(state.price0X96, amount0WithFees, state.price1X96, amount1WithFees, priceTokenX96);
        if (!ignoreFees) {
            feeValue = _sumMulDiv(state.price0X96, fees0, state.price1X96, fees1, priceTokenX96);
        }
        price0X96 = FullMath.mulDiv(state.price0X96, Q96, priceTokenX96);
        price1X96 = FullMath.mulDiv(state.price1X96, Q96, priceTokenX96);
    }

    /// @notice Quotes an arbitrary token amount into another configured token
    /// @dev Reverts when either token lacks usable oracle configuration
    function getTokenValue(address tokenIn, uint256 amountIn, address tokenOut)
        external
        view
        override
        returns (uint256 value)
    {
        if (amountIn == 0 || tokenIn == tokenOut) {
            return amountIn;
        }

        uint256 cachedChainlinkReferencePriceX96;
        uint256 priceInX96;
        uint256 priceOutX96;
        (priceInX96, cachedChainlinkReferencePriceX96) =
            _getReferenceTokenPriceX96(tokenIn, cachedChainlinkReferencePriceX96);
        (priceOutX96,) = _getReferenceTokenPriceX96(tokenOut, cachedChainlinkReferencePriceX96);
        value = FullMath.mulDiv(amountIn, priceInX96, priceOutX96);
    }

    function isTokenConfigured(address token) external view override returns (bool configured) {
        configured = token == referenceToken || feedConfigs[token].mode != Mode.NOT_SET;
    }

    function _requireMaxDifference(uint256 priceX96, uint256 verifyPriceX96, uint16 maxDifferenceX10000)
        internal
        pure
    {
        uint256 differenceX10000 =
            priceX96 >= verifyPriceX96 ? (priceX96 - verifyPriceX96) * 10000 : (verifyPriceX96 - priceX96) * 10000;

        // if invalid price or too big difference - revert
        if (
            (verifyPriceX96 == 0 || differenceX10000 / verifyPriceX96 > maxDifferenceX10000)
                && maxDifferenceX10000 < type(uint16).max
        ) {
            revert PriceDifferenceExceeded();
        }
    }

    /// @notice Gets breakdown of a uniswap v3 position (tokens and fee tier, liquidity, current liquidity amounts, uncollected fees)
    /// @param tokenId tokenId of position
    /// @return token0 token0 of position
    /// @return token1 token1 of position
    /// @return fee fee tier of position
    /// @return liquidity liquidity of position
    /// @return amount0 current amount token0
    /// @return amount1 current amount token1
    /// @return fees0 current token0 fees of position
    /// @return fees1 current token1 fees of position
    function getPositionBreakdown(uint256 tokenId)
        external
        view
        override
        returns (
            address token0,
            address token1,
            uint24 fee,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1,
            uint128 fees0,
            uint128 fees1
        )
    {
        PositionState memory state = _loadPositionState(tokenId);
        _populatePrices(state);
        (token0, token1, fee) = (state.token0, state.token1, state.fee);
        (amount0, amount1) = _getAmounts(state);
        (fees0, fees1) = _getFees(state);
        liquidity = state.liquidity;
    }

    /// @notice Gets liquidity and uncollected fees
    /// @param tokenId tokenId of position
    /// @return liquidity liquidity of position
    /// @return fees0 current token0 fees of position
    /// @return fees1 current token1 fees of position
    function getLiquidityAndFees(uint256 tokenId)
        external
        view
        override
        returns (uint128 liquidity, uint128 fees0, uint128 fees1)
    {
        PositionState memory state = _loadPositionState(tokenId);
        liquidity = state.liquidity;
        (fees0, fees1) = _getFees(state);
    }

    /// @notice Sets the max pool difference parameter (onlyOwner)
    /// @param _maxPoolPriceDifference Set max allowable difference between pool price and derived oracle pool price
    function setMaxPoolPriceDifference(uint16 _maxPoolPriceDifference) external onlyOwner {
        maxPoolPriceDifference = _maxPoolPriceDifference;
        emit SetMaxPoolPriceDifference(_maxPoolPriceDifference);
    }

    /// @notice Sets or updates the feed configuration for a token (onlyOwner)
    /// @param token Token to configure
    /// @param feed Chainlink feed to this token (matching chainlinkReferenceToken)
    /// @param maxFeedAge Max allowable chainlink feed age
    /// @param pool TWAP reference pool (matching referenceToken)
    /// @param twapSeconds TWAP period to use
    /// @param mode Mode how both oracle should be used
    /// @param maxDifference Max allowable difference between both oracle prices
    function setTokenConfig(
        address token,
        AggregatorV3Interface feed,
        uint32 maxFeedAge,
        IUniswapV3Pool pool,
        uint32 twapSeconds,
        Mode mode,
        uint16 maxDifference
    ) external onlyOwner {
        // can not be unset
        if (mode == Mode.NOT_SET) {
            revert InvalidConfig();
        }

        uint8 feedDecimals = feed.decimals();
        uint8 tokenDecimals = IERC20Metadata(token).decimals();

        TokenConfig memory config;

        if (token != referenceToken) {
            if (mode == Mode.CHAINLINK) {
                config = TokenConfig(
                    feed, maxFeedAge, feedDecimals, tokenDecimals, 0, IUniswapV3Pool(address(0)), false, mode, 0
                );
            } else {
                address token0 = pool.token0();
                address token1 = pool.token1();
                if (!(token0 == token && token1 == referenceToken || token0 == referenceToken && token1 == token)) {
                    revert InvalidPool();
                }
                bool isToken0 = token0 == token;
                config = TokenConfig(
                    feed, maxFeedAge, feedDecimals, tokenDecimals, twapSeconds, pool, isToken0, mode, maxDifference
                );
            }
        } else {
            config = TokenConfig(
                feed, maxFeedAge, feedDecimals, tokenDecimals, 0, IUniswapV3Pool(address(0)), false, Mode.CHAINLINK, 0
            );
        }

        feedConfigs[token] = config;

        emit TokenConfigUpdated(token, config);
        emit OracleModeUpdated(token, mode);
    }

    /// @notice Updates the oracle mode for a given token  - this method can be called by owner OR emergencyAdmin
    /// @param token Token to configure
    /// @param mode Mode to set
    function setOracleMode(address token, Mode mode) external {
        if (msg.sender != emergencyAdmin && msg.sender != owner()) {
            revert Unauthorized();
        }

        // can not be unset
        if (mode == Mode.NOT_SET) {
            revert InvalidConfig();
        }

        feedConfigs[token].mode = mode;
        emit OracleModeUpdated(token, mode);
    }

    /// @notice Sets sequencer uptime feed for L2 where needed
    /// @param feed Sequencer uptime feed
    function setSequencerUptimeFeed(address feed) external onlyOwner {
        sequencerUptimeFeed = feed;
        emit SetSequencerUptimeFeed(feed);
    }

    /// @notice Updates emergency admin address (onlyOwner)
    /// @param admin Emergency admin address
    function setEmergencyAdmin(address admin) external onlyOwner {
        emergencyAdmin = admin;
        emit SetEmergencyAdmin(admin);
    }

    // Returns the price for a token using the selected oracle mode given as reference token value
    // The price is calculated using Chainlink, Uniswap v3 TWAP, or both based on the mode
    function _getReferenceTokenPriceX96(address token, uint256 cachedChainlinkReferencePriceX96)
        internal
        view
        returns (uint256 priceX96, uint256 chainlinkReferencePriceX96)
    {
        if (token == referenceToken) {
            return (Q96, cachedChainlinkReferencePriceX96);
        }

        TokenConfig memory feedConfig = feedConfigs[token];
        Mode mode = feedConfig.mode;

        if (mode == Mode.NOT_SET) {
            revert NotConfigured();
        }

        uint256 verifyPriceX96;

        bool usesChainlink = (
            mode == Mode.CHAINLINK_TWAP_VERIFY || mode == Mode.TWAP_CHAINLINK_VERIFY
                || mode == Mode.CHAINLINK
        );
        bool usesTWAP = (
            mode == Mode.CHAINLINK_TWAP_VERIFY || mode == Mode.TWAP_CHAINLINK_VERIFY
                || mode == Mode.TWAP
        );

        if (usesChainlink) {
            uint256 chainlinkPriceX96 = _getChainlinkPriceX96(token);
            chainlinkReferencePriceX96 = cachedChainlinkReferencePriceX96 == 0
                ? _getChainlinkPriceX96(referenceToken)
                : cachedChainlinkReferencePriceX96;

            if (referenceTokenDecimals > feedConfig.tokenDecimals) {
                chainlinkPriceX96 = (10 ** (referenceTokenDecimals - feedConfig.tokenDecimals)) * chainlinkPriceX96
                    * Q96 / chainlinkReferencePriceX96;
            } else if (referenceTokenDecimals < feedConfig.tokenDecimals) {
                chainlinkPriceX96 = chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96
                    / (10 ** (feedConfig.tokenDecimals - referenceTokenDecimals));
            } else {
                chainlinkPriceX96 = chainlinkPriceX96 * Q96 / chainlinkReferencePriceX96;
            }

            if (mode == Mode.TWAP_CHAINLINK_VERIFY) {
                verifyPriceX96 = chainlinkPriceX96;
            } else {
                priceX96 = chainlinkPriceX96;
            }
        }

        if (usesTWAP) {
            uint256 twapPriceX96 = _getTWAPPriceX96(feedConfig);
            if (mode == Mode.CHAINLINK_TWAP_VERIFY) {
                verifyPriceX96 = twapPriceX96;
            } else {
                priceX96 = twapPriceX96;
            }
        }

        if (mode == Mode.CHAINLINK_TWAP_VERIFY || mode == Mode.TWAP_CHAINLINK_VERIFY) {
            _requireMaxDifference(priceX96, verifyPriceX96, feedConfig.maxDifference);
        }
    }

    // calculates chainlink price given feedConfig
    function _getChainlinkPriceX96(address token) internal view returns (uint256) {
        if (token == chainlinkReferenceToken) {
            return Q96;
        }

        // sequencer check on chains where needed
        if (sequencerUptimeFeed != address(0)) {
            (, int256 sequencerAnswer, uint256 startedAt,,) =
                AggregatorV3Interface(sequencerUptimeFeed).latestRoundData();

            // Answer == 0: Sequencer is up
            // Answer == 1: Sequencer is down
            if (sequencerAnswer == 1) {
                revert SequencerDown();
            }

            // Make sure - feed result is valid
            if (startedAt == 0) {
                revert SequencerUptimeFeedInvalid();
            }

            // Make sure the grace period has passed after the
            // sequencer is back up.
            uint256 timeSinceUp = block.timestamp - startedAt;
            if (timeSinceUp <= SEQUENCER_GRACE_PERIOD_TIME) {
                revert SequencerGracePeriodNotOver();
            }
        }

        TokenConfig memory feedConfig = feedConfigs[token];

        // if stale data - revert
        (, int256 answer,, uint256 updatedAt,) = feedConfig.feed.latestRoundData();
        if (updatedAt + feedConfig.maxFeedAge < block.timestamp || answer <= 0) {
            revert ChainlinkPriceError();
        }

        return SafeCast.toUint256(answer) * Q96 / (10 ** feedConfig.feedDecimals);
    }

    // calculates TWAP price given feedConfig
    function _getTWAPPriceX96(TokenConfig memory feedConfig) internal view returns (uint256 poolTWAPPriceX96) {
        // get reference pool price
        uint256 priceX96 = _getReferencePoolPriceX96(feedConfig.pool, feedConfig.twapSeconds);

        if (feedConfig.isToken0) {
            poolTWAPPriceX96 = priceX96;
        } else {
            poolTWAPPriceX96 = Q96 * Q96 / priceX96;
        }
    }

    // Calculates the reference pool price with scaling factor of 2^96
    // It uses either the latest slot price or TWAP based on twapSeconds
    function _getReferencePoolPriceX96(IUniswapV3Pool pool, uint32 twapSeconds) internal view returns (uint256) {
        uint160 sqrtPriceX96;
        // if twap seconds set to 0 just use pool price
        if (twapSeconds == 0) {
            (sqrtPriceX96,) = _getPoolSlot0(pool);
        } else {
            uint32[] memory secondsAgos = new uint32[](2);
            secondsAgos[0] = 0; // from (before)
            secondsAgos[1] = twapSeconds; // from (before)
            (int56[] memory tickCumulatives,) = pool.observe(secondsAgos); // pool observe may fail when there is not enough history available (only use pool with enough history!)
            int56 delta = tickCumulatives[0] - tickCumulatives[1];
            int256 twapSecondsInt = int256(uint256(twapSeconds));
            int24 tick = SafeCast.toInt24(int256(delta) / twapSecondsInt);
            if (delta < 0 && int256(delta) % twapSecondsInt != 0) tick--;
            sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        }

        return FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, Q96);
    }

    struct PositionState {
        uint256 tokenId;
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
        IUniswapV3Pool pool;
        uint160 sqrtPriceX96;
        int24 tick;
        uint160 sqrtPriceX96Lower;
        uint160 sqrtPriceX96Upper;
        uint256 price0X96;
        uint256 price1X96;
        uint160 derivedSqrtPriceX96;
        uint256 cachedChainlinkReferencePriceX96;
    }

    function _loadPositionState(uint256 tokenId) internal view returns (PositionState memory state) {
        (
            ,
            ,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        ) = nonfungiblePositionManager.positions(tokenId);
        state.tokenId = tokenId;
        state.token0 = token0;
        state.token1 = token1;
        state.fee = fee;
        state.tickLower = tickLower;
        state.tickUpper = tickUpper;
        state.liquidity = liquidity;
        state.feeGrowthInside0LastX128 = feeGrowthInside0LastX128;
        state.feeGrowthInside1LastX128 = feeGrowthInside1LastX128;
        state.tokensOwed0 = tokensOwed0;
        state.tokensOwed1 = tokensOwed1;
        state.pool = _getPool(token0, token1, fee);
        (state.sqrtPriceX96, state.tick) = _getPoolSlot0(state.pool);
    }

    // gets prices according to oracle configuration (this reverts if any price is configured wrongly)
    function _populatePrices(PositionState memory state) internal view {
        (state.price0X96, state.cachedChainlinkReferencePriceX96) =
            _getReferenceTokenPriceX96(state.token0, state.cachedChainlinkReferencePriceX96);
        (state.price1X96, state.cachedChainlinkReferencePriceX96) =
            _getReferenceTokenPriceX96(state.token1, state.cachedChainlinkReferencePriceX96);

        // checks derived pool price for price manipulation attacks
        // this prevents manipulations of pool to get distorted proportions of collateral tokens - for borrowing
        // when a pool is in this state, liquidations will be disabled - but arbitrageurs (or liquidator himself)
        // will move price back to reasonable range and enable liquidation
        uint256 derivedPoolPriceX96 = FullMath.mulDiv(state.price0X96, Q96, state.price1X96);

        // current pool price
        uint256 priceX96 = FullMath.mulDiv(state.sqrtPriceX96, state.sqrtPriceX96, Q96);
        _requireMaxDifference(priceX96, derivedPoolPriceX96, maxPoolPriceDifference);

        // calculate derived sqrt price
        state.derivedSqrtPriceX96 = SafeCast.toUint160(Math.sqrt(derivedPoolPriceX96) * (2 ** 48));
    }

    function _sumMulDiv(uint256 a, uint256 b, uint256 c, uint256 d, uint256 denominator)
        internal
        pure
        returns (uint256 result)
    {
        uint256 q1 = FullMath.mulDiv(a, b, denominator);
        uint256 q2 = FullMath.mulDiv(c, d, denominator);
        uint256 r1 = mulmod(a, b, denominator);
        uint256 r2 = mulmod(c, d, denominator);

        result = q1 + q2 + (r1 + r2) / denominator;
    }

    // calculate position amounts given derived price from oracle
    function _getAmounts(PositionState memory state) internal pure returns (uint256 amount0, uint256 amount1) {
        if (state.liquidity != 0) {
            state.sqrtPriceX96Lower = TickMath.getSqrtRatioAtTick(state.tickLower);
            state.sqrtPriceX96Upper = TickMath.getSqrtRatioAtTick(state.tickUpper);
            (amount0, amount1) = LiquidityAmounts.getAmountsForLiquidity(
                state.derivedSqrtPriceX96, state.sqrtPriceX96Lower, state.sqrtPriceX96Upper, state.liquidity
            );
        }
    }

    // calculate uncollected position fees
    function _getFees(PositionState memory state) internal view returns (uint128 fees0, uint128 fees1) {
        (fees0, fees1) = _getUncollectedFees(state, state.tick);
        fees0 += state.tokensOwed0;
        fees1 += state.tokensOwed1;
    }

    // calculate uncollected fees
    function _getUncollectedFees(PositionState memory position, int24 tick)
        internal
        view
        returns (uint128 fees0, uint128 fees1)
    {
        (uint256 feeGrowthInside0LastX128, uint256 feeGrowthInside1LastX128) = _getFeeGrowthInside(
            position.pool,
            position.tickLower,
            position.tickUpper,
            tick,
            position.pool.feeGrowthGlobal0X128(),
            position.pool.feeGrowthGlobal1X128()
        );

        // allow overflow - this is as designed by uniswap - see PositionValue library (for solidity < 0.8)
        uint256 feeGrowth0;
        uint256 feeGrowth1;
        unchecked {
            feeGrowth0 = feeGrowthInside0LastX128 - position.feeGrowthInside0LastX128;
            feeGrowth1 = feeGrowthInside1LastX128 - position.feeGrowthInside1LastX128;
        }

        fees0 = SafeCast.toUint128(FullMath.mulDiv(feeGrowth0, position.liquidity, Q128));
        fees1 = SafeCast.toUint128(FullMath.mulDiv(feeGrowth1, position.liquidity, Q128));
    }

    // calculate fee growth for uncollected fees calculation
    function _getFeeGrowthInside(
        IUniswapV3Pool pool,
        int24 tickLower,
        int24 tickUpper,
        int24 tickCurrent,
        uint256 feeGrowthGlobal0X128,
        uint256 feeGrowthGlobal1X128
    ) internal view returns (uint256 feeGrowthInside0X128, uint256 feeGrowthInside1X128) {
        (uint256 lowerFeeGrowthOutside0X128, uint256 lowerFeeGrowthOutside1X128) =
            _getFeeGrowthOutside(pool, tickLower);
        (uint256 upperFeeGrowthOutside0X128, uint256 upperFeeGrowthOutside1X128) =
            _getFeeGrowthOutside(pool, tickUpper);

        // allow overflow - this is as designed by uniswap - see PositionValue library (for solidity < 0.8)
        unchecked {
            if (tickCurrent < tickLower) {
                feeGrowthInside0X128 = lowerFeeGrowthOutside0X128 - upperFeeGrowthOutside0X128;
                feeGrowthInside1X128 = lowerFeeGrowthOutside1X128 - upperFeeGrowthOutside1X128;
            } else if (tickCurrent < tickUpper) {
                feeGrowthInside0X128 = feeGrowthGlobal0X128 - lowerFeeGrowthOutside0X128 - upperFeeGrowthOutside0X128;
                feeGrowthInside1X128 = feeGrowthGlobal1X128 - lowerFeeGrowthOutside1X128 - upperFeeGrowthOutside1X128;
            } else {
                feeGrowthInside0X128 = upperFeeGrowthOutside0X128 - lowerFeeGrowthOutside0X128;
                feeGrowthInside1X128 = upperFeeGrowthOutside1X128 - lowerFeeGrowthOutside1X128;
            }
        }
    }

    function _getPoolSlot0(IUniswapV3Pool pool) internal view returns (uint160 sqrtPriceX96, int24 tick) {
        (bool success, bytes memory data) = address(pool).staticcall(abi.encodeWithSelector(pool.slot0.selector));
        if (!success || data.length < 64) {
            revert InvalidPool();
        }

        uint256 word0;
        uint256 word1;
        assembly ("memory-safe") {
            word0 := mload(add(data, 32))
            word1 := mload(add(data, 64))
        }

        sqrtPriceX96 = SafeCast.toUint160(word0);
        // slot0() ABI-encodes signed int24 as a sign-extended 32-byte word.
        assembly ("memory-safe") {
            tick := signextend(2, word1)
        }
    }

    function _getFeeGrowthOutside(IUniswapV3Pool pool, int24 tick)
        internal
        view
        returns (uint256 feeGrowthOutside0X128, uint256 feeGrowthOutside1X128)
    {
        (bool success, bytes memory data) = address(pool).staticcall(abi.encodeWithSelector(pool.ticks.selector, tick));
        if (!success) {
            revert InvalidPool();
        }

        // Uniswap v3 ticks() => 8 outputs.
        if (data.length == 256) {
            (, , feeGrowthOutside0X128, feeGrowthOutside1X128,,,,) =
                abi.decode(data, (uint128, int128, uint256, uint256, int56, uint160, uint32, bool));
            return (feeGrowthOutside0X128, feeGrowthOutside1X128);
        }

        // Aerodrome Slipstream ticks() => 10 outputs (extra staked/reward fields).
        if (data.length == 320) {
            (, , , feeGrowthOutside0X128, feeGrowthOutside1X128,,,,,) =
                abi.decode(data, (uint128, int128, int128, uint256, uint256, uint256, int56, uint160, uint32, bool));
            return (feeGrowthOutside0X128, feeGrowthOutside1X128);
        }

        revert InvalidPool();
    }

    // helper method to get pool for token
    function _getPool(address tokenA, address tokenB, uint24 fee) internal view returns (IUniswapV3Pool) {
        // Aerodrome uses getPool(tokenA, tokenB, tickSpacing) and stores tickSpacing in positions().fee.
        (bool success, bytes memory data) = factory.staticcall(
            abi.encodeWithSelector(IAerodromeSlipstreamFactory.getPool.selector, tokenA, tokenB, _toTickSpacing(fee))
        );
        if (success && data.length >= 32) {
            address poolAddress = abi.decode(data, (address));
            if (poolAddress != address(0)) {
                return IUniswapV3Pool(poolAddress);
            }
        }

        // Uniswap v3 uses getPool(tokenA, tokenB, fee).
        (success, data) = factory.staticcall(
            abi.encodeWithSelector(IUniswapV3Factory.getPool.selector, tokenA, tokenB, fee)
        );
        if (success && data.length >= 32) {
            return IUniswapV3Pool(abi.decode(data, (address)));
        }

        return IUniswapV3Pool(address(0));
    }

    function _toTickSpacing(uint24 fee) internal pure returns (int24 tickSpacing) {
        assembly ("memory-safe") {
            tickSpacing := fee
        }
    }
}



---

# INSTRUCTIONS — Follow this EXACT procedure

## PHASE 1: DEEP READ (mandatory)

Read ALL the source code above. For each contract file, understand:
- What does this contract do?
- Where does money flow in and out?
- What external calls does it make?
- What trust assumptions does it have?
- What math operations could have precision issues?

Write a Protocol Model (5-10 lines) documenting your understanding.

## PHASE 2: CONSULT KNOWLEDGE BASE

Before generating invariants, READ these files from our knowledge base to understand
what patterns have caught real bugs in protocols of this type:

  - `C:\Users\Yuba\Documents\Web3/invariant-registry/universal/conservation_of_value.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/universal/exploit_derived.json`
  - `C:\Users\Yuba\Documents\Web3/BugBounty-Vault/01-Vulnerabilities/defi-invariant-catalog.md`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/token/erc20_core.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/lending/pool_accounting.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/lending/collateral_accounting.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/lending/liquidation_logic.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/lending/interest_rate.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/lending/loan_accounting.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/staking/reward_distribution.json`
  - `C:\Users\Yuba\Documents\Web3/invariant-registry/universal/reentrancy_safety.json`
  - `C:\Users\Yuba\Documents\Web3/BugBounty-Vault/01-Vulnerabilities/DeFiHackLabs-Invariant-Extraction.md`

For each file, extract the patterns most relevant to THIS specific protocol.
Don't copy generic invariants — understand the PATTERN and apply it specifically.

## PHASE 3: GENERATE INVARIANTS — Category by Category

For each category below, follow this procedure:

```
1. Generate AT LEAST 5 SPECIFIC invariants for this category.
   5 is the MINIMUM, not the ceiling. If you see more valid invariants, KEEP GOING.
   A complex component like a vault or lending pool can easily have 10-15 per category.
2. Each invariant must be:
   - SPECIFIC to this protocol's code (reference actual function/variable names)
   - Expressible as a Chimera assertion (t(), eq(), gte(), lte(), gt(), lt())
   - Tied to a concrete attack scenario (what happens if it breaks?)
3. If you have fewer than 5:
   - THINK DEEPER: consider edge cases, multi-step attacks, flash loan scenarios,
     cross-function interactions, rounding in specific math operations
   - Try one more time to find additional invariants
4. If after 2 rounds of deep thinking you still have fewer than 5:
   - That's OK. Some categories won't have 5 valid invariants for every protocol.
   - Quality > quantity. 2 precise invariants > 5 vague ones.
   - Move to the next category.
5. If you have MORE than 5 — GREAT. Include them all.
   The more specific invariants we have, the more attack surface we cover.
   There is NO upper limit. Only stop when you've exhausted real possibilities.
```

### Categories to analyze:


#### Category: Solvency / Balance Integrity

The protocol must always hold enough tokens to cover its obligations. Real token balance >= internal accounting. No money created from nothing.

**Real exploits that this would have caught:**
    - Euler Finance $197M: self-liquidation created bad debt, protocol became insolvent
    - Sonne Finance $20M: first depositor inflated share price, subsequent depositors got 0 shares

**What to check in THIS protocol:**
    - token.balanceOf(protocol) >= internal accounting total
    - sum of all user claims <= total protocol holdings
    - no path to withdraw more than deposited (accounting level)
    - totalAssets consistency with real balances


#### Category: Constant Product / AMM Invariant

k = reserve0 * reserve1 must never decrease from swaps. Only increases from fees.

**Real exploits that this would have caught:**
    - Various DEX hacks: price manipulation via reserve manipulation

**What to check in THIS protocol:**
    - k_after >= k_before for every swap
    - reserves match actual token balances
    - fee accounting: fees increase k, not decrease


#### Category: Rounding Direction Consistency

All rounding must favor the protocol, never the user. Deposits/mints round UP (user pays more), withdrawals/redeems round DOWN (user gets less).

**Real exploits that this would have caught:**
    - BalancerV2: precision loss in StableMath accumulated across thousands of swaps
    - KyberSwap $46M: precision loss in concentrated liquidity tick math

**What to check in THIS protocol:**
    - shares received from deposit <= previewDeposit result
    - assets needed for mint >= previewMint result
    - assets received from withdraw <= previewWithdraw result
    - mulDiv direction: UP for debt, DOWN for credit


#### Category: Fee Accounting Integrity

Fees collected must equal fees distributed. No fee evasion paths.

**Real exploits that this would have caught:**
    - FutureSwap $394K: fee unit mismatch (basis points vs percentage)
    - MTToken: unbounded fee percentage sum

**What to check in THIS protocol:**
    - fees collected >= fees distributed
    - fee percentage within valid bounds (0-100%)
    - no path to avoid paying fees
    - fee-on-transfer tokens handled correctly


#### Category: Access Control Integrity

Only authorized addresses can call privileged functions. No path to escalate privileges without going through governance.

**Real exploits that this would have caught:**
    - TempleDAO $2.3M: migrateStake() had zero access control
    - CorkProtocol $12M: missing access control on critical function
    - DeltaPrime $4.75M: arbitrary calldata forwarding bypassed access control

**What to check in THIS protocol:**
    - admin-only functions revert when called by non-admin
    - no function increases another user's debt without authorization
    - ownership transfer requires 2-step or timelock
    - no arbitrary calldata forwarding to token contracts


#### Category: Economic / Flash Loan Attack Vectors

No profit possible from atomic (single-tx) operations. Flash loan + protocol interaction should not yield net profit.

**Real exploits that this would have caught:**
    - Curve LlamaLend $240K: flash loan inflated collateral value
    - Makina $5.1M: flash loan TWAP manipulation
    - PRXVT: staking + flash loan extracted disproportionate rewards

**What to check in THIS protocol:**
    - no profit from deposit + action + withdraw in same tx
    - no profit from manipulating oracle price in same block
    - no flash-loan-stake-claim-unstake attack path
    - donation to protocol does not create extractable value for attacker


#### Category: Cross-Function / Interaction Invariants

State consistency across function calls. Calling function A then B must not create invalid states that neither function alone would allow.

**Real exploits that this would have caught:**
    - Euler: donateToReserves → liquidateSelf sequence enabled extraction
    - DoughFinance $1.81M: callback forwarded calldata to Aave on behalf of other users

**What to check in THIS protocol:**
    - reentrancy: external calls don't allow re-entry to manipulate state
    - function ordering: no sequence of valid calls produces invalid state
    - callback safety: callbacks don't allow state manipulation
    - read-only reentrancy: view functions return consistent values during external calls


#### Category: Supply Conservation

totalSupply must equal sum of all balanceOf. Mints increase supply, burns decrease supply, transfers conserve.

**Real exploits that this would have caught:**
    - Various: supply inflation bugs allowing unbacked minting

**What to check in THIS protocol:**
    - totalSupply == sum of all balanceOf (exact)
    - mint increases totalSupply by exact amount
    - burn decreases totalSupply by exact amount
    - transfer: sender decrease == receiver increase


#### Category: Debt Accounting Integrity

Total borrows must equal sum of individual debts. Interest only increases debt. No path to reduce debt without actual repayment.

**Real exploits that this would have caught:**
    - Venus THE: borrowBehalf increased victim's debt without authorization
    - AlkemiEarn: self-liquidation zeroed attacker debt but kept collateral

**What to check in THIS protocol:**
    - totalBorrows >= sum of all individual debts (within rounding)
    - interest accrual only increases debt, never decreases
    - debt can only decrease through repay() or liquidate()
    - no path to create unbacked debt


#### Category: Liquidation Safety

Liquidation must improve protocol health. Self-liquidation must not yield profit. Liquidation bonus must not exceed collateral value.

**Real exploits that this would have caught:**
    - Euler $197M: donateToReserves + self-liquidation for profit
    - Compound: liquidation of healthy positions

**What to check in THIS protocol:**
    - only unhealthy positions can be liquidated
    - liquidation reduces debt and increases protocol health
    - self-liquidation yields no profit to the liquidator-borrower
    - liquidation bonus <= seized collateral value


#### Category: Interest Rate Bounds

Interest rates must stay within reasonable bounds. Utilization rate must be [0, 1]. Interest must accrue monotonically.

**Real exploits that this would have caught:**
    - Revert Lend mock artifact: 740%/day vs 5%/year real rate caused false invariant breaks

**What to check in THIS protocol:**
    - interest rate >= 0 and <= MAX_RATE
    - utilization = borrows / supply, always in [0, 1e18]
    - interest accrual monotonically increases borrow index
    - no interest charged on zero borrows


#### Category: Oracle Safety / Price Feed Dependency

Oracle prices must be validated (freshness, bounds, circuit breakers). Spot price must not be used for critical calculations.

**Real exploits that this would have caught:**
    - Moonwell $1.78M: oracle failure led to wrong liquidation prices
    - Makina $5.1M: TWAP manipulation via flash loan

**What to check in THIS protocol:**
    - oracle price freshness check (revert if stale)
    - price within reasonable bounds (not 0, not astronomical)
    - TWAP used instead of spot for critical decisions
    - fallback oracle if primary fails


#### Category: Reward Distribution Integrity

Total rewards distributed must not exceed total rewards notified. Proportional to stake amount and duration.

**Real exploits that this would have caught:**
    - PRXVT: staking + flash loan extracted disproportionate rewards

**What to check in THIS protocol:**
    - sum of all earned() <= total rewards notified
    - rewards proportional to stake amount and time
    - no double-claim possible
    - claiming does not affect other users' pending rewards



## PHASE 4: OUTPUT FORMAT

Generate the complete Chimera harness code. ALL output must be in this exact format:

### OUTPUT 1: INVARIANT TABLE

A summary table of all generated invariants (AFTER Phase 5 verification):

```
| # | Category | ID | Tier | Severity | Description | Attack if broken | Verified |
|---|----------|----|------|----------|-------------|------------------|----------|
| 1 | solvency | INV-001 | 1 | Critical | ... | ... | Yes |
| 2 | rounding | INV-002 | 2 | High | ... (tolerance: 1 wei) | ... | Fixed |
```

Tier 1 = hard fail, any violation is a confirmed bug (fund loss, access bypass)
Tier 2 = needs tolerance for dust/rounding, violation needs manual review

### OUTPUT 2: BeforeAfter.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {Setup} from "./Setup.sol";

abstract contract BeforeAfter is Setup {
    struct Vars {
        // Ghost variables — track state before/after each operation
        // MUST include all values referenced in Properties.sol
    }

    Vars internal _before;
    Vars internal _after;

    // Cumulative ghost variables (for conservation invariants)
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    // ... add protocol-specific cumulative trackers

    modifier updateGhosts {
        __before();
        _;
        __after();
    }

    function __before() internal {
        // Snapshot all tracked values
    }

    function __after() internal {
        // Snapshot all tracked values after operation
    }
}
```

### OUTPUT 3: Properties.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {Asserts} from "@chimera/Asserts.sol";
import {BeforeAfter} from "./BeforeAfter.sol";

abstract contract Properties is BeforeAfter, Asserts {

    // ==================== SOLVENCY (Tier 1 — hard fail) ====================

    function invariant_INV001_description() public {
        // Use: t(), eq(), gt(), gte(), lt(), lte()
        // NO assert() or require() — not compatible with all fuzzers
        // Properties must NOT modify state
    }

    // ==================== NEXT CATEGORY ====================
    // ... group invariants by category with clear headers
}
```

### OUTPUT 4: TargetFunctions.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {vm} from "@chimera/Hevm.sol";
import {Properties} from "./Properties.sol";

abstract contract TargetFunctions is Properties {

    // Handler for each public function
    // MUST use: updateGhosts modifier OR manual __before()/__after()
    // MUST use: between() for input clamping
    // MUST include boundary values: 0, 1, type(uint256).max, balance-1

    function handler_functionName(uint256 param) public updateGhosts asActor {
        // Clamp input
        param = between(param, 0, maxReasonableValue);

        // Execute
        target.functionName(param);

        // Inline assertion (optional — for function-specific properties)
    }
}
```

### OUTPUT 5: optimize_* functions (for Echidna optimization mode)

```solidity
// Add these to TargetFunctions.sol or a separate OptimizationTargets.sol

// Echidna will try to MAXIMIZE the return value
// If it finds a positive value = potential exploit

function optimize_attacker_profit() public view returns (int256) {
    // Return: attacker's balance change from initial state
    // Positive = attacker extracted value = BUG
    return int256(currentAttackerBalance) - int256(initialAttackerBalance);
}
```

### OUTPUT 6: Setup.sol

```solidity
// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {BaseSetup} from "@chimera/BaseSetup.sol";
import {vm} from "@chimera/Hevm.sol";
import {ActorManager} from "@recon/ActorManager.sol";
import {AssetManager} from "@recon/AssetManager.sol";
import {Utils} from "@recon/Utils.sol";

abstract contract Setup is BaseSetup, ActorManager, AssetManager, Utils {
    // Protocol contract instances

    function setup() internal virtual override {
        // Deploy all protocol contracts
        // Add 3 actors: user1, attacker (high balance), keeper/liquidator
        // Configure realistic initial state (not empty)
        // Approve tokens, deal balances
    }
}
```

## PHASE 5: VERIFICATION (mandatory — do NOT skip)

After generating all invariants and code, verify EVERY single one against this checklist.
This phase exists because invariants that reference non-existent variables/functions are
WORSE than no invariants — they waste fuzzing time on compilation errors.

### For EACH invariant, check ALL 5 points:

```
VERIFICATION CHECKLIST (per invariant):

[ ] 1. VARIABLE EXISTS — Every variable referenced in the assertion actually exists
       in the source code. Search for the exact name. If it's a ghost variable,
       verify it's declared in BeforeAfter.sol.

[ ] 2. FUNCTION EXISTS — Every function called in the assertion/handler actually exists
       in the protocol contracts. Search for the exact signature.
       DO NOT invent functions like "target.getHealth()" if the protocol uses "isHealthy()".

[ ] 3. TYPE CORRECT — uint256 vs int256, address vs contract type, etc.
       Casting must be explicit. No implicit bool→uint conversions.

[ ] 4. ATTACK REALISTIC — The BREAKS_IF scenario is actually possible:
       - Does the attacker have access to the required functions?
       - Is the attack NOT admin-only? (admin bugs are usually excluded from bounties)
       - Can this actually be executed atomically or does it require unrealistic setup?

[ ] 5. NOT DUPLICATE — This invariant is genuinely different from every other invariant
       in the set. Two invariants testing the same property with different names = waste.
```

### Verification procedure:

1. Go through each invariant in your table
2. For any that FAIL a checklist item:
   - Fix it if the fix is obvious (wrong variable name → correct name)
   - REMOVE it if it's fundamentally broken (references non-existent logic)
   - REPLACE it with a better invariant for that category if possible
3. After verification, update the INVARIANT TABLE with a new column: VERIFIED (Yes/No/Fixed)
4. The final Properties.sol and TargetFunctions.sol must ONLY contain verified invariants

### Common mistakes to catch:

- Using `totalAssets()` when the protocol calls it `getTotalAssets()`
- Using `balanceOf(address)` on a contract that doesn't inherit ERC20
- Referencing `msg.sender` inside an invariant (invariants are called by the fuzzer, not users)
- Using `assert()` instead of `t()` / `gte()` / etc.
- Ghost variables declared but never populated in `__before()` / `__after()`
- Handler calling a function with wrong number of arguments
- Assuming a function returns a value when it returns void
- Checking oracle price in an invariant without the protocol actually using an oracle

## PHASE 6: EMERGENT CATEGORIES (optional)

If during your deep read (Phase 1) you noticed something unusual in the code that
doesn't fit any predefined category — a custom mechanism, a novel DeFi primitive,
a cross-protocol interaction — you SHOULD create additional invariants for it.

This is where the highest-value bugs live: in the code that's unique to THIS protocol,
that no generic invariant template would cover.

Examples of emergent patterns:
- Custom bonding curve math → verify curve properties
- Epoch-based state machine → verify valid state transitions
- Permit/meta-transaction → verify signature validation
- Custom oracle aggregation → verify aggregation logic
- Novel liquidation mechanism → verify it can't be gamed

## ANTI-PATTERNS — DO NOT generate these:

1. **Generic ERC20 compliance** tests (transfer, approve, etc.) unless the protocol
   implements a custom ERC20 — these are already covered by crytic/properties
2. **Admin-only attack scenarios** — most bounty programs exclude these
3. **"totalSupply == sum of balances"** as a standalone invariant — too generic,
   already in our registry
4. **View function revert checks** (maxDeposit must not revert) — low value,
   rarely pays bounties
5. **Invariants that require unrealistic gas** (iterating over all users on-chain)
6. **Copy-pasted invariants** from the registry with names changed — must be SPECIFIC

## CRITICAL RULES

1. **Chimera assertion helpers ONLY**: t(), eq(), gt(), gte(), lt(), lte() — NEVER assert()/require()
2. **Properties MUST NOT modify state** — they are called as view checks
3. **Handlers MUST use updateGhosts** or manual __before()/__after()
4. **Boundary value injection**: 5% chance of 0, 5% chance of 1, 5% chance of max
5. **3 actors minimum**: honest user, attacker (large balance), keeper/liquidator
6. **Every invariant needs BREAKS_IF**: if you can't describe the attack, it's noise
7. **Reference ACTUAL names** from the code — no placeholder "target.someFunction()"
8. **Tier 1 invariants** (hard fail = confirmed bug) vs **Tier 2** (needs tolerance for dust)
9. **Time limits on warp**: max 7 days per step, max 90 days total
10. **optimize_* functions**: at least 2 for Echidna — one for attacker profit, one for protocol loss
11. **Verified only**: ONLY include invariants that passed Phase 5 verification
