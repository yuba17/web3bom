// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {BaseSetup} from "@chimera/BaseSetup.sol";
import {vm} from "@chimera/Hevm.sol";

// Protocol imports
import {V3Vault} from "../../src/V3Vault.sol";
import {V3Oracle} from "../../src/V3Oracle.sol";
import {InterestRateModel} from "../../src/InterestRateModel.sol";
import {GaugeManager} from "../../src/GaugeManager.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {INonfungiblePositionManager} from "v3-periphery/interfaces/INonfungiblePositionManager.sol";
import {IVault} from "../../src/interfaces/IVault.sol";

/// @title Setup - Revert Lend test deployment with 3 actors (v2)
/// @notice Mock-based setup for fast invariant iteration. Migrate to fork for final validation.
abstract contract Setup is BaseSetup {
    // ===== Protocol contracts =====
    V3Vault public vault;
    V3Oracle public oracle;
    InterestRateModel public interestRateModel;
    GaugeManager public gaugeManager;
    INonfungiblePositionManager public npm;
    address public assetToken;

    // ===== Actors =====
    address internal constant DEPLOYER = address(0xD0);
    address internal constant LENDER = address(0xA1);      // Honest lender
    address internal constant ATTACKER = address(0xA2);     // Attacker with high balance
    address internal constant KEEPER = address(0xA3);       // Liquidator/keeper

    // ===== Test NFT token IDs =====
    uint256 internal constant TOKEN_ID_1 = 1;
    uint256 internal constant TOKEN_ID_2 = 2;
    uint256 internal constant TOKEN_ID_3 = 3;

    // ===== Boundary value constants =====
    uint256 internal constant ZERO = 0;
    uint256 internal constant ONE = 1;
    uint256 internal constant TINY = 100;                    // 100 wei
    uint256 internal constant SMALL = 1e6;                   // 1 USDC
    uint256 internal constant MEDIUM = 1000e6;               // 1000 USDC
    uint256 internal constant LARGE = 1_000_000e6;           // 1M USDC
    uint256 internal constant MAX_UINT = type(uint256).max;

    // ===== IRM Parameters =====
    // Realistic parameters: 2% base, 20% slope, 200% jump, 80% kink
    uint256 internal constant Q64_VAL = 2 ** 64;
    uint256 internal constant BASE_RATE_PER_YEAR_X64 = Q64_VAL * 2 / 100;     // 2%
    uint256 internal constant MULTIPLIER_PER_YEAR_X64 = Q64_VAL * 20 / 100;   // 20%
    uint256 internal constant JUMP_MULT_PER_YEAR_X64 = Q64_VAL * 200 / 100;   // 200%
    uint256 internal constant KINK_X64 = Q64_VAL * 80 / 100;                  // 80%

    function setup() internal virtual override {
        // NOTE: This is the MOCK setup for fast iteration.
        // For final validation, use ForkSetup.sol with real contracts on Base mainnet.

        vm.startPrank(DEPLOYER);

        // 1. Deploy InterestRateModel
        interestRateModel = new InterestRateModel(
            BASE_RATE_PER_YEAR_X64,
            MULTIPLIER_PER_YEAR_X64,
            JUMP_MULT_PER_YEAR_X64,
            KINK_X64
        );

        // 2. Deploy mock asset token, NPM, and oracle
        // In mock mode, these would be mock contracts
        // In fork mode, use real deployed addresses

        // 3. Deploy V3Vault
        // vault = new V3Vault(
        //     "Revert Lend USDC",
        //     "rlUSDC",
        //     assetToken,
        //     npm,
        //     interestRateModel,
        //     oracle
        // );

        // 4. Configure vault limits
        // vault.setLimits(
        //     1e6,           // minLoanSize: 1 USDC
        //     10_000_000e6,  // globalLendLimit: 10M USDC
        //     5_000_000e6,   // globalDebtLimit: 5M USDC
        //     1_000_000e6,   // dailyLendIncreaseLimitMin: 1M USDC
        //     500_000e6      // dailyDebtIncreaseLimitMin: 500K USDC
        // );

        // 5. Set reserve factor (10%)
        // vault.setReserveFactor(uint32(2 ** 32 * 10 / 100));

        // 6. Configure collateral tokens
        // vault.setTokenConfig(token0, collateralFactor, collateralValueLimit);
        // vault.setTokenConfig(token1, collateralFactor, collateralValueLimit);

        // 7. Fund actors
        // deal(assetToken, LENDER, 10_000_000e6);
        // deal(assetToken, ATTACKER, 10_000_000e6);
        // deal(assetToken, KEEPER, 1_000_000e6);

        // 8. Approve vault for all actors
        // vm.stopPrank();
        // vm.startPrank(LENDER);
        // IERC20(assetToken).approve(address(vault), type(uint256).max);
        // vm.stopPrank();
        // vm.startPrank(ATTACKER);
        // IERC20(assetToken).approve(address(vault), type(uint256).max);
        // vm.stopPrank();
        // vm.startPrank(KEEPER);
        // IERC20(assetToken).approve(address(vault), type(uint256).max);

        vm.stopPrank();
    }

    // ===== Helper: Clamp amount with boundary value injection =====
    /// @notice Boundary value injection per CLAUDE.md: 5% zeros, 5% ones, 5% max, 20% tiny
    function _clampAmount(uint256 amount, uint256 maxVal) internal pure returns (uint256) {
        if (amount % 20 == 0) return ZERO;           // 5% zeros
        if (amount % 20 == 1) return ONE;             // 5% ones
        if (amount % 20 == 2) return maxVal;          // 5% max
        if (amount % 5 == 0) return TINY;             // 20% tiny values
        return amount % maxVal;                       // 65% random bounded
    }

    // ===== Helper: Select actor =====
    function _selectActor(uint8 actorSeed) internal pure returns (address) {
        uint8 idx = actorSeed % 3;
        if (idx == 0) return LENDER;
        if (idx == 1) return ATTACKER;
        return KEEPER;
    }

    // ===== Helper: Select token ID =====
    function _selectTokenId(uint8 tokenSeed) internal pure returns (uint256) {
        uint8 idx = tokenSeed % 3;
        if (idx == 0) return TOKEN_ID_1;
        if (idx == 1) return TOKEN_ID_2;
        return TOKEN_ID_3;
    }
}
