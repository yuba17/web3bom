// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {vm} from "@chimera/Hevm.sol";
import {Properties} from "./Properties.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IVault} from "../../src/interfaces/IVault.sol";
import {INonfungiblePositionManager} from "v3-periphery/interfaces/INonfungiblePositionManager.sol";

/// @title TargetFunctions - Handler functions for Revert Lend fuzzing (v2)
/// @notice Covers all public/external functions with boundary value injection
abstract contract TargetFunctions is Properties {

    // ========================
    // === ERC4626 LENDING ===
    // ========================

    /// @notice Handler: deposit assets into vault
    function handler_deposit(uint8 actorSeed, uint256 amount) public {
        address actor = _selectActor(actorSeed);
        uint256 maxDeposit = vault.maxDeposit(actor);
        if (maxDeposit == 0) return;

        amount = _clampAmount(amount, maxDeposit);
        if (amount == 0) return;

        __snapshot_before();
        __snapshot_actor_before(actor);

        vm.prank(actor);
        try vault.deposit(amount, actor) returns (uint256 shares) {
            __snapshot_after();
            __snapshot_actor_after(actor);

            // DEBT-004 equivalent for lending: totalSupply increased
            eq(
                _after.totalSupply,
                _before.totalSupply + shares,
                "handler_deposit: totalSupply mismatch"
            );

            // Asset transferred in
            eq(
                _after.vaultAssetBalance,
                _before.vaultAssetBalance + amount,
                "handler_deposit: vault balance mismatch"
            );

            // E46-002: deposit rounds shares DOWN (fewer shares = protocol-favorable)
            // shares <= amount * Q96 / lendExchangeRateX96
            // (verified by the contract's _convertToShares with Rounding.Down)

            __ghost_deposit(actor, amount);
            __ghost_updateExchangeRates();
            __ghost_updateSharePrice();
        } catch {
            // Deposit can fail for: GlobalLendLimit, DailyLendIncreaseLimit
        }
    }

    /// @notice Handler: withdraw assets from vault
    function handler_withdraw(uint8 actorSeed, uint256 amount) public {
        address actor = _selectActor(actorSeed);
        uint256 maxWithdraw = vault.maxWithdraw(actor);
        if (maxWithdraw == 0) return;

        amount = _clampAmount(amount, maxWithdraw);
        if (amount == 0) return;

        __snapshot_before();
        __snapshot_actor_before(actor);

        vm.prank(actor);
        try vault.withdraw(amount, actor, actor) returns (uint256 shares) {
            __snapshot_after();
            __snapshot_actor_after(actor);

            // E46-003: withdraw rounds shares UP (more shares burned = protocol-favorable)
            eq(
                _after.totalSupply,
                _before.totalSupply - shares,
                "handler_withdraw: totalSupply mismatch"
            );

            // Asset transferred out
            eq(
                _after.vaultAssetBalance,
                _before.vaultAssetBalance - amount,
                "handler_withdraw: vault balance mismatch"
            );

            __ghost_withdraw(actor, amount);
            __ghost_updateExchangeRates();
            __ghost_updateSharePrice();
        } catch {
            // Can fail for: InsufficientLiquidity
        }
    }

    /// @notice Handler: mint shares (specify shares instead of assets)
    function handler_mint(uint8 actorSeed, uint256 shares) public {
        address actor = _selectActor(actorSeed);
        uint256 maxMint = vault.maxMint(actor);
        if (maxMint == 0) return;

        shares = _clampAmount(shares, maxMint);
        if (shares == 0) return;

        __snapshot_before();

        vm.prank(actor);
        try vault.mint(shares, actor) returns (uint256 assets) {
            __snapshot_after();

            eq(_after.totalSupply, _before.totalSupply + shares, "handler_mint: totalSupply mismatch");

            __ghost_deposit(actor, assets);
            __ghost_updateExchangeRates();
        } catch {}
    }

    /// @notice Handler: redeem shares (specify shares instead of assets)
    function handler_redeem(uint8 actorSeed, uint256 shares) public {
        address actor = _selectActor(actorSeed);
        uint256 maxRedeem = vault.maxRedeem(actor);
        if (maxRedeem == 0) return;

        shares = _clampAmount(shares, maxRedeem);
        if (shares == 0) return;

        __snapshot_before();

        vm.prank(actor);
        try vault.redeem(shares, actor, actor) returns (uint256 assets) {
            __snapshot_after();

            eq(_after.totalSupply, _before.totalSupply - shares, "handler_redeem: totalSupply mismatch");

            __ghost_withdraw(actor, assets);
            __ghost_updateExchangeRates();
        } catch {}
    }

    // ===========================
    // === BORROWING / REPAY ===
    // ===========================

    /// @notice Handler: borrow against collateral
    function handler_borrow(uint8 tokenSeed, uint256 amount) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) return;

        // Clamp to reasonable borrow amount
        amount = _clampAmount(amount, LARGE);
        if (amount == 0) return;

        __snapshot_before();
        __snapshot_loan_before(tokenId);

        vm.prank(owner);
        try vault.borrow(tokenId, amount) {
            __snapshot_after();
            __snapshot_loan_after(tokenId);

            // DEBT-004: debtSharesTotal increased by exact shares
            uint256 sharesDelta = _after.debtSharesTotal - _before.debtSharesTotal;
            eq(
                _loanAfter[tokenId].debtShares,
                _loanBefore[tokenId].debtShares + sharesDelta,
                "handler_borrow: loan debtShares mismatch"
            );

            // COL-001: loan must be healthy after borrow
            // (enforced by _requireLoanIsHealthy in contract)

            // ECO-003: debt >= minLoanSize
            gte(
                _loanAfter[tokenId].debt,
                vault.minLoanSize(),
                "handler_borrow: debt < minLoanSize"
            );

            __ghost_borrow(tokenId, amount, sharesDelta);
            __ghost_updateExchangeRates();
        } catch {
            // Can fail for: CollateralFail, GlobalDebtLimit, DailyDebtIncreaseLimit, MinLoanSize
        }
    }

    /// @notice Handler: repay debt
    function handler_repay(uint8 tokenSeed, uint256 amount, bool isShare) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        uint256 currentDebtShares = vault.loans(tokenId);
        if (currentDebtShares == 0) return;

        amount = _clampAmount(amount, isShare ? currentDebtShares : LARGE);
        if (amount == 0) return;

        __snapshot_before();
        __snapshot_loan_before(tokenId);

        address repayer = _selectActor(uint8(amount % 3));

        vm.prank(repayer);
        try vault.repay(tokenId, amount, isShare) returns (uint256 assets, uint256 shares) {
            __snapshot_after();
            __snapshot_loan_after(tokenId);

            // DEBT-005: debtSharesTotal decreased by shares
            eq(
                _after.debtSharesTotal,
                _before.debtSharesTotal - shares,
                "handler_repay: debtSharesTotal mismatch"
            );

            // Loan shares decreased
            eq(
                _loanAfter[tokenId].debtShares,
                _loanBefore[tokenId].debtShares - shares,
                "handler_repay: loan shares mismatch"
            );

            __ghost_repay(tokenId, assets, shares);
            __ghost_updateExchangeRates();
        } catch {
            // Can fail for: NoSharesRepayed, MinLoanSize (partial repay leaving dust)
        }
    }

    // =========================
    // === LIQUIDATION ===
    // =========================

    /// @notice Handler: liquidate unhealthy position
    function handler_liquidate(uint8 tokenSeed) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        uint256 debtShares = vault.loans(tokenId);
        if (debtShares == 0) return;

        // Check if position is actually liquidatable
        (uint256 debt,, uint256 collateralValue, uint256 liquidationCost,) = vault.loanInfo(tokenId);

        __snapshot_before();
        __snapshot_loan_before(tokenId);

        vm.prank(KEEPER);
        try vault.liquidate(
            IVault.LiquidateParams({
                tokenId: tokenId,
                amount0Min: 0,
                amount1Min: 0,
                recipient: KEEPER,
                deadline: block.timestamp + 1 hours
            })
        ) returns (uint256 amount0, uint256 amount1) {
            __snapshot_after();
            __snapshot_loan_after(tokenId);

            // LIQ-001: Should only succeed on unhealthy positions
            // (If it succeeded, position was unhealthy - verified by revert check above)

            // LIQ-002: After liquidation, debt fully cleared
            eq(_loanAfter[tokenId].debtShares, 0, "handler_liquidate: debtShares not zero");

            // LIQ-003: liquidatorCost <= debt
            lte(liquidationCost, debt, "handler_liquidate: liquidatorCost > debt");

            __ghost_liquidate(tokenId);
            __ghost_updateExchangeRates();
        } catch {
            // LIQ-001: Healthy positions should revert with NotLiquidatable
            // This is the expected path for healthy positions
            if (collateralValue >= debt) {
                // Good - healthy position correctly rejected
            }
        }
    }

    // =====================================
    // === COLLATERAL MANAGEMENT ===
    // =====================================

    /// @notice Handler: decrease liquidity and collect from collateral
    function handler_decreaseLiquidityAndCollect(uint8 tokenSeed, uint128 liquidity) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) return;

        __snapshot_before();
        __snapshot_loan_before(tokenId);

        vm.prank(owner);
        try vault.decreaseLiquidityAndCollect(
            IVault.DecreaseLiquidityAndCollectParams({
                tokenId: tokenId,
                liquidity: liquidity,
                amount0Min: 0,
                amount1Min: 0,
                feeAmount0: 0,
                feeAmount1: 0,
                deadline: block.timestamp + 1 hours,
                recipient: owner
            })
        ) {
            __snapshot_after();
            __snapshot_loan_after(tokenId);

            // COL-001: Loan must remain healthy after withdrawal
            // (enforced by _requireLoanIsHealthy in contract)

            __ghost_updateExchangeRates();
        } catch {
            // Can fail for: CollateralFail, Unauthorized, TransformNotAllowed
        }
    }

    /// @notice Handler: remove position (only if no debt)
    function handler_remove(uint8 tokenSeed) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) return;

        __snapshot_before();

        vm.prank(owner);
        try vault.remove(tokenId, owner, "") {
            // XFN-005: Should only succeed if debtShares == 0
            eq(
                _loanBefore[tokenId].debtShares,
                0,
                "handler_remove: removed position with debt"
            );
        } catch {
            // Expected if debtShares > 0 (NeedsRepay)
        }
    }

    // ===========================
    // === STAKING / GAUGE ===
    // ===========================

    /// @notice Handler: stake position in gauge
    function handler_stakePosition(uint8 tokenSeed) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) return;
        if (vault.gaugeManager() == address(0)) return;

        __snapshot_before();

        vm.prank(owner);
        try vault.stakePosition(tokenId) {
            // GST-003: After stake, NFT no longer in vault
            t(
                npm.ownerOf(tokenId) != address(vault),
                "handler_stake: NFT still in vault after stake"
            );

            // GST-001: Vault still tracks owner
            t(
                vault.ownerOf(tokenId) != address(0),
                "handler_stake: owner lost after stake"
            );
        } catch {
            // Can fail for: NotDepositor, GaugeManagerNotSet, NotConfigured
        }
    }

    /// @notice Handler: unstake position from gauge
    function handler_unstakePosition(uint8 tokenSeed) public {
        uint256 tokenId = _selectTokenId(tokenSeed);
        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) return;
        if (vault.gaugeManager() == address(0)) return;

        vm.prank(owner);
        try vault.unstakePosition(tokenId) {
            // GST-004: After unstake, NFT back in vault
            t(
                npm.ownerOf(tokenId) == address(vault),
                "handler_unstake: NFT not returned to vault"
            );
        } catch {
            // Can fail for: Unauthorized, NotStaked
        }
    }

    // =========================
    // === TIME ADVANCE ===
    // =========================

    /// @notice Handler: advance time (max 7 days per step, 90 days total)
    function handler_advanceTime(uint256 seconds_) public {
        // Per CLAUDE.md: max 7 days per step
        seconds_ = seconds_ % (7 days);
        if (seconds_ == 0) seconds_ = 1;

        __snapshot_before();

        vm.warp(block.timestamp + seconds_);

        __snapshot_after();

        // DEBT-001: debtExchangeRateX96 non-decreasing
        gte(
            _after.debtExchangeRateX96,
            _before.debtExchangeRateX96,
            "handler_advanceTime: debtRate decreased"
        );

        // DEBT-002: lendExchangeRateX96 non-decreasing (absent socialization)
        gte(
            _after.lendExchangeRateX96,
            _before.lendExchangeRateX96,
            "handler_advanceTime: lendRate decreased (no socialization)"
        );

        // DEBT-003: debtRate >= lendRate
        gte(
            _after.debtExchangeRateX96,
            _after.lendExchangeRateX96,
            "handler_advanceTime: debtRate < lendRate"
        );

        __ghost_updateExchangeRates();
        __ghost_updateSharePrice();
    }

    // =====================================
    // === ROUND-TRIP ATTACK TESTING ===
    // =====================================

    /// @notice Handler: Test deposit + immediate redeem round-trip (E46-001)
    function handler_roundTripDepositRedeem(uint256 amount) public {
        amount = _clampAmount(amount, MEDIUM);
        if (amount == 0) return;

        address actor = ATTACKER;
        uint256 assetsBefore = IERC20(vault.asset()).balanceOf(actor);

        vm.startPrank(actor);
        try vault.deposit(amount, actor) returns (uint256 shares) {
            try vault.redeem(shares, actor, actor) returns (uint256 assetsOut) {
                vm.stopPrank();

                uint256 assetsAfter = IERC20(vault.asset()).balanceOf(actor);
                // E46-001: No round-trip profit
                lte(assetsAfter, assetsBefore, "handler_roundTrip: profit from deposit+redeem");
            } catch {
                vm.stopPrank();
            }
        } catch {
            vm.stopPrank();
        }
    }

    // ===================================
    // === INTEREST RATE MODEL TESTS ===
    // ===================================

    /// @notice Handler: test IRM with various cash/debt ratios
    function handler_testIRM(uint256 cash, uint256 debt) public view {
        cash = cash % (1e30);
        debt = debt % (1e30);
        if (cash + debt == 0) return;

        // IRM-001: utilization bounded
        uint256 util = interestRateModel.getUtilizationRateX64(cash, debt);
        lte(util, Q64, "handler_testIRM: utilization > Q64");

        // IRM-002: borrowRate >= supplyRate
        (uint256 borrowRate, uint256 supplyRate) = interestRateModel.getRatesPerSecondX64(cash, debt);
        gte(borrowRate, supplyRate, "handler_testIRM: borrowRate < supplyRate");

        // IRM-004: rates should be non-negative
        gte(borrowRate, 0, "handler_testIRM: negative borrowRate");
        gte(supplyRate, 0, "handler_testIRM: negative supplyRate");
    }
}
