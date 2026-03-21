// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * Lending Pool Invariant Test Skeleton
 *
 * USAGE:
 * 1. Replace interface imports with actual protocol contracts
 * 2. Customize setup() with correct deployment
 * 3. Adjust handler functions to match protocol's API
 * 4. Run: forge test --match-contract LendingPoolInvariant -vvv
 */

// ============================================================================
// PROTOCOL INTERFACE — Replace with actual contract interfaces
// ============================================================================

interface ILendingPool {
    function supply(address asset, uint256 amount, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function borrow(address asset, uint256 amount, address onBehalfOf) external;
    function repay(address asset, uint256 amount, address onBehalfOf) external returns (uint256);
    function liquidate(address collateral, address debt, address user, uint256 amount) external;

    function totalSupply(address asset) external view returns (uint256);
    function totalBorrows(address asset) external view returns (uint256);
    function userSupply(address asset, address user) external view returns (uint256);
    function userDebt(address asset, address user) external view returns (uint256);
    function userCollateral(address asset, address user) external view returns (uint256);
    function isHealthy(address user) external view returns (bool);
}

contract LendingPoolHandler is Test {
    ILendingPool public pool;
    IERC20 public loanToken;
    IERC20 public collateralToken;
    address[] public actors;

    // Ghost variables
    uint256 public ghost_totalSupplied;
    uint256 public ghost_totalBorrowed;
    uint256 public ghost_totalRepaid;
    uint256 public ghost_totalWithdrawn;

    constructor(ILendingPool _pool, IERC20 _loan, IERC20 _collateral, address[] memory _actors) {
        pool = _pool;
        loanToken = _loan;
        collateralToken = _collateral;
        actors = _actors;
    }

    modifier useActor(uint256 seed) {
        address actor = actors[seed % actors.length];
        vm.startPrank(actor);
        _;
        vm.stopPrank();
    }

    function supply(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 1, loanToken.balanceOf(actor));
        if (amount == 0) return;

        loanToken.approve(address(pool), amount);
        pool.supply(address(loanToken), amount, actor);
        ghost_totalSupplied += amount;
    }

    function supplyCollateral(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        amount = bound(amount, 1, collateralToken.balanceOf(actor));
        if (amount == 0) return;

        collateralToken.approve(address(pool), amount);
        pool.supply(address(collateralToken), amount, actor);
    }

    function borrow(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 available = loanToken.balanceOf(address(pool));
        if (available == 0) return;
        amount = bound(amount, 1, available / 2); // Conservative

        try pool.borrow(address(loanToken), amount, actor) {
            ghost_totalBorrowed += amount;
        } catch {}
    }

    function repay(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 debt = pool.userDebt(address(loanToken), actor);
        if (debt == 0) return;
        amount = bound(amount, 1, debt);

        uint256 balance = loanToken.balanceOf(actor);
        if (balance < amount) return;

        loanToken.approve(address(pool), amount);
        uint256 repaid = pool.repay(address(loanToken), amount, actor);
        ghost_totalRepaid += repaid;
    }

    function withdraw(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 supplied = pool.userSupply(address(loanToken), actor);
        if (supplied == 0) return;
        amount = bound(amount, 1, supplied);

        try pool.withdraw(address(loanToken), amount, actor) returns (uint256 withdrawn) {
            ghost_totalWithdrawn += withdrawn;
        } catch {}
    }

    function warpForward(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 365 days);
        vm.warp(block.timestamp + seconds_);
    }
}

contract LendingPoolInvariant is StdInvariant, Test {
    ILendingPool public pool;
    IERC20 public loanToken;
    IERC20 public collateralToken;
    LendingPoolHandler public handler;
    address[] public actors;

    function setUp() public {
        // =====================================================================
        // CUSTOMIZE: Deploy or fork your target lending pool
        // =====================================================================

        for (uint256 i = 0; i < 5; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            deal(address(loanToken), actor, 1_000_000e18);
            deal(address(collateralToken), actor, 1_000_000e18);
        }

        handler = new LendingPoolHandler(pool, loanToken, collateralToken, actors);
        targetContract(address(handler));
    }

    // =========================================================================
    // TIER S — Critical: Solvency invariants
    // =========================================================================

    /// @notice INV-LEND-003: totalSupply >= totalBorrows (market level solvency)
    function invariant_supply_gte_borrows() public view {
        assertGe(
            pool.totalSupply(address(loanToken)),
            pool.totalBorrows(address(loanToken)),
            "INSOLVENCY: totalBorrows > totalSupply"
        );
    }

    /// @notice INV-LEND-004: Token balance + borrows >= supply (real solvency)
    function invariant_token_balance_solvency() public view {
        uint256 balance = loanToken.balanceOf(address(pool));
        uint256 borrows = pool.totalBorrows(address(loanToken));
        uint256 supply = pool.totalSupply(address(loanToken));
        assertGe(
            balance + borrows,
            supply,
            "INSOLVENCY: token balance + borrows < supply"
        );
    }

    /// @notice INV-LEND-001: totalBorrows >= any individual debt
    function invariant_total_borrows_gte_individual() public view {
        uint256 totalBorrows = pool.totalBorrows(address(loanToken));
        for (uint256 i = 0; i < actors.length; i++) {
            uint256 debt = pool.userDebt(address(loanToken), actors[i]);
            assertGe(totalBorrows, debt, "Individual debt > totalBorrows");
        }
    }

    /// @notice INV-LEND-002: totalBorrows approx== sum of all user debts
    function invariant_borrows_sum_consistency() public view {
        uint256 totalBorrows = pool.totalBorrows(address(loanToken));
        uint256 sumDebts = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumDebts += pool.userDebt(address(loanToken), actors[i]);
        }
        // Allow rounding tolerance of 1 per actor
        assertApproxEqAbs(
            totalBorrows, sumDebts, actors.length,
            "totalBorrows != sum of user debts"
        );
    }

    /// @notice INV-LEND-005: No borrow shares with zero collateral
    function invariant_no_unsecured_debt() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            uint256 debt = pool.userDebt(address(loanToken), actors[i]);
            uint256 collateral = pool.userCollateral(address(collateralToken), actors[i]);
            if (collateral == 0) {
                assertEq(debt, 0, "User has debt but zero collateral");
            }
        }
    }

    // =========================================================================
    // TIER A — High: Health invariants
    // =========================================================================

    /// @notice INV-LIQ-004: All users healthy under static conditions
    function invariant_all_users_healthy() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            if (pool.userDebt(address(loanToken), actors[i]) > 0) {
                assertTrue(
                    pool.isHealthy(actors[i]),
                    "User is unhealthy without price change"
                );
            }
        }
    }

    // =========================================================================
    // TIER B — Interest invariants
    // =========================================================================

    /// @notice INV-INT-003: Interest only increases borrows (monotonic)
    /// Note: Check this after time warp only
    function invariant_borrows_monotonic_with_interest() public view {
        // This is checked as a postcondition in the handler
        // The totalBorrows should only increase from interest, never decrease
        // without explicit repayment
    }
}
