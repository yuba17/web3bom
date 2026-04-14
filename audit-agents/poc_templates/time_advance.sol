// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Time advancement patterns for time-dependent vulnerabilities
abstract contract TimeAdvanceSetup is Test {
    address attacker = makeAddr("attacker");

    // Advance time by specific duration
    function _advanceTime(uint256 seconds_) internal {
        vm.warp(block.timestamp + seconds_);
        vm.roll(block.number + seconds_ / 12); // ~12s per block
    }

    // Common time boundaries
    uint256 constant ONE_HOUR = 3600;
    uint256 constant ONE_DAY = 86400;
    uint256 constant ONE_WEEK = 604800;
    uint256 constant THIRTY_DAYS = 30 days;
    uint256 constant ONE_YEAR = 365 days;

    // Test epoch boundary crossing
    function _crossEpochBoundary(uint256 epochDuration) internal {
        uint256 currentEpoch = block.timestamp / epochDuration;
        uint256 nextEpochStart = (currentEpoch + 1) * epochDuration;
        vm.warp(nextEpochStart);
        vm.roll(block.number + (nextEpochStart - block.timestamp) / 12);
    }

    // Test interest accrual over time
    function _accrueInterest(uint256 duration) internal {
        _advanceTime(duration);
        // Call protocol's accrual function after time advance
    }

    // Flash loan in same block (no time advance)
    function _sameBlockAttack() internal virtual {
        // Actions in same block — no time passes
        // Useful for: flash loan, sandwich, MEV
    }
}
