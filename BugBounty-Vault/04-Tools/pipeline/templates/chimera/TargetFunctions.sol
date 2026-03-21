// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Properties.sol";

/// @title Chimera-Compatible Target Functions (Handler)
/// @notice Wraps protocol functions with bounded inputs and ghost tracking.
/// @dev Each function represents one action the fuzzer can take.
///      Use `useActor(seed)` for multi-user scenarios.
///      Use `bound()` for every fuzzed parameter.
///      Use try/catch for graceful failure handling.
abstract contract TargetFunctions is Properties {

    // ═══════════════════════════════════════════════════════════
    // HANDLER ACTIONS — Override with protocol-specific actions
    // ═══════════════════════════════════════════════════════════

    /*
    // Example for a lending protocol:

    function handler_deposit(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        amount = bound(amount, 1, 1e24);
        deal(address(token), _currentActor, amount);
        token.approve(address(vault), amount);

        try vault.deposit(amount, _currentActor) {
            ghost_totalDeposited += amount;
            ghost_callsSucceeded++;
        } catch {
            ghost_callsFailed++;
        }
    }

    function handler_withdraw(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        uint256 maxW = vault.maxWithdraw(_currentActor);
        if (maxW == 0) return;
        amount = bound(amount, 1, maxW);

        try vault.withdraw(amount, _currentActor, _currentActor) {
            ghost_totalWithdrawn += amount;
            ghost_callsSucceeded++;
        } catch {
            ghost_callsFailed++;
        }
    }

    function handler_borrow(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        amount = bound(amount, 1e6, 10_000e6);
        try vault.borrow(tokenId, amount) {
            ghost_totalBorrowed += amount;
            ghost_callsSucceeded++;
        } catch {
            ghost_callsFailed++;
        }
    }

    function handler_repay(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        amount = bound(amount, 1e6, 50_000e6);
        token.approve(address(vault), type(uint256).max);
        try vault.repay(tokenId, amount, false) {
            ghost_totalRepaid += amount;
            ghost_callsSucceeded++;
        } catch {
            ghost_callsFailed++;
        }
    }

    function handler_advanceTime(uint256 secondsSeed) external {
        uint256 elapsed = bound(secondsSeed, 1, 7 days);
        vm.warp(block.timestamp + elapsed);
    }

    // For Dutch auctions:
    function handler_bid(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        amount = bound(amount, 1, auction.getAvailableAmount(asset));
        if (amount == 0) return;
        try auction.bid(asset, amount, "") {
            ghost_callsSucceeded++;
        } catch {
            ghost_callsFailed++;
        }
    }

    function handler_startAuction(uint256 seed) external {
        // Only callable by AUCTION_WORKER_ROLE
        // ...
    }
    */
}
