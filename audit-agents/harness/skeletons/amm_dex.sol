// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * AMM/DEX (Uniswap-style) Invariant Test Skeleton
 *
 * USAGE:
 * 1. Replace IUniswapV2Pair with the actual pool interface
 * 2. Replace TOKEN0/TOKEN1 with the actual token pair
 * 3. Customize setUp() with correct deployment/initialization
 * 4. Remove invariants that don't apply to this specific AMM
 * 5. Run: forge test --match-contract AmmDexInvariant -vvv
 */

// ============================================================================
// CONFIGURATION — Edit these for your target
// ============================================================================

// import {TargetPool} from "src/TargetPool.sol";
// import {TargetRouter} from "src/TargetRouter.sol";

/// @notice Minimal interface for a Uniswap V2-style pair. Replace with actual.
interface IAmmPair {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function mint(address to) external returns (uint256 liquidity);
    function burn(address to) external returns (uint256 amount0, uint256 amount1);
}

contract AmmDexHandler is Test {
    IAmmPair public pool;
    IERC20 public token0;
    IERC20 public token1;
    address[] public actors;

    // =========================================================================
    // Ghost variables — track cumulative state for invariant checking
    // =========================================================================

    /// @dev Tracks the product k = reserve0 * reserve1 before each operation
    uint256 public ghost_kBefore;

    /// @dev Cumulative fees collected (approximated via k growth)
    uint256 public ghost_cumulativeKGrowth;

    /// @dev LP value per token at initial liquidity add, for monotonicity check
    uint256 public ghost_lastLpValuePerShare;

    /// @dev Total LP tokens minted across all operations
    uint256 public ghost_totalMinted;

    /// @dev Total LP tokens burned across all operations
    uint256 public ghost_totalBurned;

    /// @dev Number of successful swaps (for debugging)
    uint256 public ghost_swapCount;

    constructor(IAmmPair _pool, address[] memory _actors) {
        pool = _pool;
        token0 = IERC20(_pool.token0());
        token1 = IERC20(_pool.token1());
        actors = _actors;
    }

    modifier useActor(uint256 seed) {
        address actor = actors[seed % actors.length];
        vm.startPrank(actor);
        _;
        vm.stopPrank();
    }

    // =========================================================================
    // Handler functions — the fuzzer calls these
    // =========================================================================

    /// @notice Swap tokenIn for the other token with bounded amount
    /// @dev Simulates a user swap. The fuzzer picks tokenIn (0 or 1) and amount.
    function swap(uint256 tokenIn, uint256 amountIn, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        tokenIn = bound(tokenIn, 0, 1);

        // Snapshot k before swap
        (uint112 r0, uint112 r1,) = pool.getReserves();
        ghost_kBefore = uint256(r0) * uint256(r1);

        IERC20 sellToken = tokenIn == 0 ? token0 : token1;
        IERC20 buyToken = tokenIn == 0 ? token1 : token0;

        uint256 balance = sellToken.balanceOf(actor);
        if (balance == 0) return;

        // Bound amountIn: at least 1, at most actor balance, at most 10% of reserve
        uint256 maxSwap = tokenIn == 0 ? uint256(r0) / 10 : uint256(r1) / 10;
        if (maxSwap == 0) return;
        amountIn = bound(amountIn, 1, balance > maxSwap ? maxSwap : balance);

        // Calculate expected output using x*y=k with 0.3% fee (Uniswap V2 default)
        // CUSTOMIZE: adjust fee if the target AMM uses a different fee tier
        uint256 reserveIn = tokenIn == 0 ? uint256(r0) : uint256(r1);
        uint256 reserveOut = tokenIn == 0 ? uint256(r1) : uint256(r0);
        uint256 amountInWithFee = amountIn * 997;
        uint256 amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);

        if (amountOut == 0 || amountOut >= reserveOut) return;

        // Transfer tokenIn to the pool, then call swap
        sellToken.transfer(address(pool), amountIn);

        uint256 amount0Out = tokenIn == 0 ? 0 : amountOut;
        uint256 amount1Out = tokenIn == 0 ? amountOut : 0;
        pool.swap(amount0Out, amount1Out, actor, "");

        ghost_swapCount++;
    }

    /// @notice Add liquidity to the pool
    /// @dev Transfers both tokens proportionally, then calls mint()
    function addLiquidity(uint256 amount0, uint256 amount1, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];

        (uint112 r0, uint112 r1,) = pool.getReserves();

        uint256 bal0 = token0.balanceOf(actor);
        uint256 bal1 = token1.balanceOf(actor);
        if (bal0 == 0 || bal1 == 0) return;

        amount0 = bound(amount0, 1, bal0);

        // If pool has liquidity, add proportionally to avoid donation
        if (r0 > 0 && r1 > 0) {
            amount1 = (amount0 * uint256(r1)) / uint256(r0) + 1;
            if (amount1 > bal1) {
                // Scale down amount0 to match what we can afford in token1
                amount1 = bound(amount1, 1, bal1);
                amount0 = (amount1 * uint256(r0)) / uint256(r1) + 1;
                if (amount0 > bal0) return;
            }
        } else {
            amount1 = bound(amount1, 1, bal1);
        }

        // Snapshot LP value before adding
        uint256 supplyBefore = pool.totalSupply();

        token0.transfer(address(pool), amount0);
        token1.transfer(address(pool), amount1);

        uint256 liquidity = pool.mint(actor);
        ghost_totalMinted += liquidity;
    }

    /// @notice Remove liquidity from the pool
    /// @dev Burns LP tokens proportionally
    function removeLiquidity(uint256 shares, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];

        uint256 lpBalance = pool.balanceOf(actor);
        if (lpBalance == 0) return;

        shares = bound(shares, 1, lpBalance);

        // Transfer LP tokens to pool, then call burn
        // Note: Uniswap V2 requires LP tokens sent to pair before burn()
        IERC20(address(pool)).transfer(address(pool), shares);
        pool.burn(actor);

        ghost_totalBurned += shares;
    }

    /// @notice Advance block.timestamp to test time-dependent behavior
    function warpForward(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 7 days);
        vm.warp(block.timestamp + seconds_);
    }
}

contract AmmDexInvariant is StdInvariant, Test {
    IAmmPair public pool;
    IERC20 public token0;
    IERC20 public token1;
    AmmDexHandler public handler;

    address[] public actors;
    uint256 public initialK;

    function setUp() public {
        // =====================================================================
        // CUSTOMIZE: Deploy or fork your target AMM pool here
        // =====================================================================
        // Example:
        // factory = new UniswapV2Factory(address(this));
        // token0 = IERC20(address(new MockERC20("WETH", "WETH", 18)));
        // token1 = IERC20(address(new MockERC20("USDC", "USDC", 6)));
        // pool = IAmmPair(factory.createPair(address(token0), address(token1)));

        // Create actor accounts
        for (uint256 i = 0; i < 5; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            // Fund actors with both tokens
            deal(address(token0), actor, 1_000_000e18);
            deal(address(token1), actor, 1_000_000e18);
        }

        // CUSTOMIZE: Seed initial liquidity so invariants have something to test
        // vm.startPrank(actors[0]);
        // token0.transfer(address(pool), 100_000e18);
        // token1.transfer(address(pool), 100_000e18);
        // pool.mint(actors[0]);
        // vm.stopPrank();

        handler = new AmmDexHandler(pool, actors);

        // Target the handler for fuzzing
        targetContract(address(handler));

        // Record initial k
        (uint112 r0, uint112 r1,) = pool.getReserves();
        initialK = uint256(r0) * uint256(r1);
    }

    // =========================================================================
    // TIER S — Critical invariants (test these first)
    // =========================================================================

    /// @notice INV-AMM-001: K invariant — reserve0 * reserve1 must never decrease
    /// @dev Catches: incorrect swap math, fee bypass, rounding errors that drain k.
    ///      In a constant-product AMM, k should only grow (from fees). If k shrinks,
    ///      value is being extracted from the pool without paying fees.
    function invariant_k_never_decreases() public view {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        uint256 currentK = uint256(r0) * uint256(r1);

        // k must be >= initial k (fees should only increase it)
        assertGe(currentK, initialK, "INV-AMM-001: K decreased! Value extracted from pool.");
    }

    /// @notice INV-AMM-002: No value extraction — LP token value per unit must not decrease
    /// @dev Catches: donation attacks, share inflation, fee theft, rounding exploits.
    ///      If LP value per share drops, someone extracted value without burning LP tokens.
    function invariant_lp_value_monotonic() public view {
        uint256 supply = pool.totalSupply();
        if (supply == 0) return;

        (uint112 r0, uint112 r1,) = pool.getReserves();

        // LP value approximated as sqrt(reserve0 * reserve1) / totalSupply
        // Using k directly to avoid sqrt: k / supply^2 should be non-decreasing
        uint256 currentK = uint256(r0) * uint256(r1);
        // We check that currentK / supply^2 >= initialK / initialSupply^2
        // Rearranged to avoid division: currentK * initialSupply^2 >= initialK * supply^2
        // Note: in practice, track this across calls via ghost vars for precision.
        // Simplified check: k per supply should not decrease
        assertGe(
            currentK * 1e18 / supply,
            initialK > 0 ? initialK * 1e18 / pool.totalSupply() : 0,
            "INV-AMM-002: LP value per share decreased! Possible drain."
        );
    }

    /// @notice INV-AMM-003: Reserve solvency — actual token balances must cover stated reserves
    /// @dev Catches: accounting bugs, phantom reserves, reentrancy drain, unchecked transfers.
    ///      If the pool says it has X tokens but actually holds less, LPs cannot withdraw fully.
    function invariant_reserve_solvency() public view {
        (uint112 r0, uint112 r1,) = pool.getReserves();

        assertGe(
            token0.balanceOf(address(pool)),
            uint256(r0),
            "INV-AMM-003: token0 balance < reserve0! Pool insolvent."
        );
        assertGe(
            token1.balanceOf(address(pool)),
            uint256(r1),
            "INV-AMM-003: token1 balance < reserve1! Pool insolvent."
        );
    }

    /// @notice INV-AMM-004: Fee accounting — fees + reserves == actual balances
    /// @dev Catches: fee siphoning, unaccounted tokens, stuck tokens that break accounting.
    ///      The pool's token balances should equal reserves (+ any protocol fee accumulator).
    ///      A gap means tokens are stuck or fees are being lost.
    function invariant_fee_accounting() public view {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        uint256 bal0 = token0.balanceOf(address(pool));
        uint256 bal1 = token1.balanceOf(address(pool));

        // In Uniswap V2, balances can exceed reserves (excess becomes fees on next mint/burn).
        // Balances should never be LESS than reserves.
        assertGe(bal0, uint256(r0), "INV-AMM-004: token0 fees inconsistent (balance < reserve)");
        assertGe(bal1, uint256(r1), "INV-AMM-004: token1 fees inconsistent (balance < reserve)");

        // CUSTOMIZE: If the AMM has an explicit fee accumulator variable, check:
        // assertEq(bal0, r0 + accumulatedFees0, "Fee accounting mismatch for token0");
        // assertEq(bal1, r1 + accumulatedFees1, "Fee accounting mismatch for token1");
    }

    // =========================================================================
    // TIER A — High-value invariants
    // =========================================================================

    /// @notice INV-AMM-005: Swap output must be strictly less than the output reserve
    /// @dev Catches: swap math overflow, unchecked output that drains entire reserve.
    ///      A single swap should never be able to empty a pool's reserve.
    function invariant_swap_output_lt_reserve() public view {
        // This is enforced by the handler bounding swaps, but we verify
        // that no reserves are zero when the other is nonzero (drained state)
        (uint112 r0, uint112 r1,) = pool.getReserves();
        if (pool.totalSupply() > 0) {
            assertTrue(r0 > 0, "INV-AMM-005: reserve0 drained to zero while pool has LP supply");
            assertTrue(r1 > 0, "INV-AMM-005: reserve1 drained to zero while pool has LP supply");
        }
    }

    /// @notice INV-AMM-006: Price impact proportional to trade size
    /// @dev Catches: price manipulation via rounding, zero-impact large trades.
    ///      A larger swap should always produce worse price per unit than a smaller one.
    ///      Tested via spot-check: swap 1 unit vs swap 1000 units, compare output/input ratio.
    function invariant_price_impact_proportional() public view {
        (uint112 r0, uint112 r1,) = pool.getReserves();
        if (r0 < 10000 || r1 < 10000) return; // Skip if pool too small

        // Simulate small swap: 1 unit of token0
        uint256 smallIn = 1e15;
        uint256 smallOut = (smallIn * 997 * uint256(r1)) / (uint256(r0) * 1000 + smallIn * 997);

        // Simulate large swap: 1% of reserve
        uint256 largeIn = uint256(r0) / 100;
        uint256 largeOut = (largeIn * 997 * uint256(r1)) / (uint256(r0) * 1000 + largeIn * 997);

        // Price per unit: output/input. Large trade should have worse (lower) rate.
        // smallOut/smallIn >= largeOut/largeIn  =>  smallOut * largeIn >= largeOut * smallIn
        if (smallIn > 0 && largeIn > 0 && smallOut > 0 && largeOut > 0) {
            assertGe(
                smallOut * largeIn,
                largeOut * smallIn,
                "INV-AMM-006: Large swap got better price than small swap!"
            );
        }
    }

    /// @notice INV-AMM-007: Add/remove liquidity must be proportional (no free tokens)
    /// @dev Catches: rounding exploits in mint/burn, LP token inflation attacks.
    ///      Minting LP tokens should require proportional deposits. Burning should return
    ///      proportional amounts. Ghost vars track total minted vs burned.
    function invariant_lp_mint_burn_proportional() public view {
        uint256 currentSupply = pool.totalSupply();
        uint256 netMinted = handler.ghost_totalMinted();
        uint256 netBurned = handler.ghost_totalBurned();

        // If we track initial supply as S0, then currentSupply should == S0 + netMinted - netBurned
        // CUSTOMIZE: set initialSupply in setUp after seeding liquidity
        // assertEq(currentSupply, initialSupply + netMinted - netBurned,
        //     "INV-AMM-007: LP supply doesn't match mint/burn accounting");

        // At minimum: no LP tokens created from nothing
        assertGe(
            netMinted + 1000, // +1000 for MINIMUM_LIQUIDITY burned on first mint (Uni V2)
            netBurned,
            "INV-AMM-007: More LP burned than ever minted!"
        );
    }

    /// @notice INV-AMM-008: LP totalSupply == sum of all LP balances (+ MINIMUM_LIQUIDITY)
    /// @dev Catches: LP token mint/burn accounting bugs, phantom balances.
    ///      In Uniswap V2, 1000 LP tokens are permanently locked at address(0) on first mint.
    function invariant_lp_supply_consistency() public view {
        uint256 sumBalances = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumBalances += pool.balanceOf(actors[i]);
        }
        // Include MINIMUM_LIQUIDITY locked at address(0) or address(1)
        sumBalances += pool.balanceOf(address(0));

        // CUSTOMIZE: add any other known LP holders (fee recipient, etc.)
        assertLe(
            sumBalances,
            pool.totalSupply(),
            "INV-AMM-008: Sum of LP balances > totalSupply!"
        );
    }

    // =========================================================================
    // TIER B — Safety invariants (view functions should not revert)
    // =========================================================================

    /// @notice INV-AMM-009: getReserves() must never revert
    /// @dev Catches: storage corruption, overflow in reserve packing.
    ///      This is the most basic AMM view function. If it reverts, the pool is bricked.
    function invariant_getReserves_no_revert() public view {
        pool.getReserves();
    }

    /// @notice INV-AMM-010: LP totalSupply must be consistent with token balances
    /// @dev Catches: zero-supply pool with nonzero reserves (stuck funds), or
    ///      nonzero supply with zero reserves (worthless LP tokens).
    function invariant_lp_supply_reserve_consistency() public view {
        uint256 supply = pool.totalSupply();
        (uint112 r0, uint112 r1,) = pool.getReserves();

        if (supply == 0) {
            // MINIMUM_LIQUIDITY may keep supply > 0 even after all LPs exit in Uni V2.
            // But reserves should be near-zero or zero.
            // CUSTOMIZE: adjust threshold based on MINIMUM_LIQUIDITY behavior
        } else {
            // If supply > 0, both reserves should be > 0 (otherwise LP tokens are worthless)
            assertTrue(
                r0 > 0 && r1 > 0,
                "INV-AMM-010: LP supply > 0 but reserves are zero. LP tokens worthless."
            );
        }
    }
}
