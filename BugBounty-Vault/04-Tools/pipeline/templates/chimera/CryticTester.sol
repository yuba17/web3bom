// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// import "./TargetFunctions.sol";

/// @title Echidna/Medusa Tester (Chimera-compatible)
/// @notice Entry point for Echidna and Medusa fuzzing.
/// @dev For Echidna: functions prefixed with `echidna_` must return bool.
///      For Medusa: functions prefixed with `property_` return bool (from Properties.sol).
///
/// ECHIDNA CONFIG (echidna.yaml):
/// ```yaml
/// testMode: "property"
/// testLimit: 100000
/// seqLen: 100
/// corpusDir: "echidna-corpus"
/// deployer: "0x30000"
/// sender: ["0x10000", "0x20000", "0x30000"]
/// ```
///
/// MEDUSA CONFIG (medusa.json):
/// ```json
/// {
///   "fuzzing": {
///     "testLimit": 100000,
///     "callSequenceLength": 100,
///     "corpusDirectory": "medusa-corpus",
///     "testing": {
///       "propertyTesting": { "enabled": true },
///       "assertionTesting": { "enabled": true }
///     }
///   }
/// }
/// ```
///
/// USAGE:
/// echidna . --contract CryticTester --config echidna.yaml
/// medusa fuzz --config medusa.json

/*
contract CryticTester is TargetFunctions {

    constructor() {
        _setupProtocol();  // Deploy in constructor for Echidna/Medusa
    }

    // ═══════════════════════════════════════════════════════════
    // ECHIDNA PROPERTIES (must return bool, prefix echidna_)
    // ═══════════════════════════════════════════════════════════

    function echidna_solvency() public view returns (bool) {
        return property_solvency();
    }

    function echidna_conservation() public view returns (bool) {
        return property_conservation();
    }

    function echidna_exchangeRateMonotonic() public view returns (bool) {
        return property_exchangeRateMonotonic();
    }

    function echidna_totalSupplyConsistency() public view returns (bool) {
        return property_totalSupplyConsistency();
    }

    // Add all properties here with echidna_ prefix
}
*/
