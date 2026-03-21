// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @title Chimera-Compatible Setup
/// @notice Base setup for invariant testing. Deploy protocol, configure actors, set initial state.
/// @dev Inherit this in your TargetFunctions and Properties contracts.
///      Compatible with Foundry, Echidna, and Medusa.
abstract contract Setup is Test {
    // ═══════════════════════════════════════════════════════════
    // PROTOCOL CONTRACTS — Override in concrete implementation
    // ═══════════════════════════════════════════════════════════

    // Example:
    // YourVault public vault;
    // YourToken public token;
    // YourOracle public oracle;

    // ═══════════════════════════════════════════════════════════
    // ACTORS
    // ═══════════════════════════════════════════════════════════

    address[] internal _actors;
    address internal _currentActor;

    modifier useActor(uint256 seed) {
        _currentActor = _actors[seed % _actors.length];
        vm.startPrank(_currentActor);
        _;
        vm.stopPrank();
    }

    function _addActor(address actor) internal {
        _actors.push(actor);
    }

    function _getActor(uint256 seed) internal view returns (address) {
        return _actors[seed % _actors.length];
    }

    // ═══════════════════════════════════════════════════════════
    // GHOST VARIABLES — Track state across calls
    // ═══════════════════════════════════════════════════════════

    // Accounting ghosts
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_totalBorrowed;
    uint256 public ghost_totalRepaid;

    // Rate tracking
    uint256 public ghost_prevExchangeRate;

    // Operation counters
    uint256 public ghost_callsSucceeded;
    uint256 public ghost_callsFailed;

    // ═══════════════════════════════════════════════════════════
    // SETUP — Override with protocol-specific deployment
    // ═══════════════════════════════════════════════════════════

    function _setupProtocol() internal virtual;

    function setUp() public virtual {
        _setupProtocol();
    }
}
