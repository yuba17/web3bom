// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Liquidation PoC template — open position + price drop + attempt liquidation
abstract contract LiquidationSetup is Test {
    address attacker = makeAddr("attacker");
    address borrower = makeAddr("borrower");
    address liquidator = makeAddr("liquidator");

    // Override with protocol-specific logic
    function _openPosition(address user, uint256 collateral, uint256 debt) internal virtual;
    function _getHealthFactor(address user) internal view virtual returns (uint256);
    function _liquidate(address liquidator_, address borrower_, uint256 amount) internal virtual;
    function _setOraclePrice(uint256 newPrice) internal virtual;

    // Standard liquidation test flow
    function _testLiquidationScenario(
        uint256 collateral,
        uint256 debt,
        uint256 priceDropPct // in basis points, e.g., 5000 = 50%
    ) internal {
        // 1. Open healthy position
        _openPosition(borrower, collateral, debt);
        uint256 healthBefore = _getHealthFactor(borrower);
        assertGt(healthBefore, 1e18, "Position should start healthy");

        // 2. Drop price to make position unhealthy
        _setOraclePrice(1e18 * (10000 - priceDropPct) / 10000);
        uint256 healthAfter = _getHealthFactor(borrower);
        assertLt(healthAfter, 1e18, "Position should be unhealthy after price drop");

        // 3. Liquidate
        _liquidate(liquidator, borrower, debt);
    }

    // Edge case: self-liquidation
    function _testSelfLiquidation(uint256 collateral, uint256 debt) internal {
        _openPosition(attacker, collateral, debt);
        _setOraclePrice(0.5e18); // 50% price drop
        _liquidate(attacker, attacker, debt); // self-liquidate
    }

    // Edge case: liquidation at exact boundary
    function _testBoundaryLiquidation(uint256 collateral, uint256 debt) internal {
        _openPosition(borrower, collateral, debt);
        // Find exact price that makes health factor = 1.0
        // Then drop by 1 wei to trigger liquidation
    }
}
