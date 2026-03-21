// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Setup.sol";

/// @title Chimera-Compatible Properties (Invariants)
/// @notice Define all invariant properties here. Each property MUST be a view/pure function
///         that returns true if the invariant holds.
/// @dev For Foundry: prefix with `invariant_` or call from random walk.
///      For Echidna: prefix with `echidna_` and return bool.
///      For Medusa: prefix with `property_` and return bool.
abstract contract Properties is Setup {

    // ═══════════════════════════════════════════════════════════
    // CATEGORY A: SOLVENCY — "Does the protocol have enough?"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_solvency() public view returns (bool) {
        return token.balanceOf(address(vault)) >= vault.totalOwed();
    }

    function property_conservation() public view returns (bool) {
        return ghost_totalDeposited >= ghost_totalWithdrawn;
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY B: ACCOUNTING — "Do the numbers add up?"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_totalSupplyConsistency() public view returns (bool) {
        uint256 sum;
        for (uint256 i; i < _actors.length; i++) {
            sum += vault.balanceOf(_actors[i]);
        }
        return sum == vault.totalSupply();
    }

    function property_debtSharesConsistency() public view returns (bool) {
        // sum of individual loans == global total
        return computedTotal == vault.debtSharesTotal();
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY C: MONOTONICITY — "Do things only go up?"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_exchangeRateMonotonic() public view returns (bool) {
        return vault.exchangeRate() >= ghost_prevExchangeRate;
    }

    function property_sharePriceMonotonic() public view returns (bool) {
        if (vault.totalSupply() == 0) return true;
        uint256 price = vault.totalAssets() * 1e18 / vault.totalSupply();
        return price >= ghost_lastSharePrice;
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY D: STATE MACHINE — "Are transitions valid?"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_noReentrancy() public view returns (bool) {
        return vault.reentrancyGuard() == false;
    }

    function property_validState() public view returns (bool) {
        return uint8(vault.state()) <= uint8(type(State).max);
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY E: BOUNDS — "Are values within expected ranges?"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_interestRateBounded() public view returns (bool) {
        return vault.borrowRate() <= MAX_RATE;
    }

    function property_collateralFactorBounded() public view returns (bool) {
        return vault.collateralFactor() <= MAX_CF;
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY F: ROUND-TRIP — "No free value from cycles"
    // ═══════════════════════════════════════════════════════════

    /*
    function property_noFreeProfit() public view returns (bool) {
        // After deposit(x) then redeem(all), user gets <= x
        return ghost_totalWithdrawn <= ghost_totalDeposited;
    }
    */

    // ═══════════════════════════════════════════════════════════
    // CATEGORY G: DUTCH AUCTION SPECIFIC
    // ═══════════════════════════════════════════════════════════

    /*
    function property_auctionPriceDecay() public view returns (bool) {
        if (!auction.isActive(asset)) return true;
        uint256 price = auction.getCurrentPrice(asset);
        return price <= auction.getStartPrice(asset)
            && price >= auction.getEndPrice(asset);
    }

    function property_auctionSettlement() public view returns (bool) {
        // bidder pays at least the auction price
        return ghost_totalPaid >= ghost_totalReceived * minPriceMultiplier / 1e18;
    }

    function property_auctionBalanceConsistency() public view returns (bool) {
        // auction contract balance decreases by bid amount
        return true;
    }
    */

    // ═══════════════════════════════════════════════════════════
    // AGGREGATE CHECK — Call all properties
    // ═══════════════════════════════════════════════════════════

    function _assertAllProperties() internal virtual {
        // Override and call all property_* functions with assertTrue()
    }
}
