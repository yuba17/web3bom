// SPDX-License-Identifier: GPL-2.0
pragma solidity ^0.8.0;

import {Setup} from "./Setup.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title BeforeAfter - Ghost variables for Revert Lend invariant testing (v2)
/// @notice Captures state snapshots before/after operations and tracks cumulative ghost variables
abstract contract BeforeAfter is Setup {

    // ===== Before/After Snapshot Struct =====
    struct Vars {
        // Vault-level state
        uint256 vaultAssetBalance;        // IERC20(asset).balanceOf(vault)
        uint256 totalSupply;              // vault.totalSupply() (lend shares)
        uint256 debtSharesTotal;          // vault.debtSharesTotal()
        uint256 debtExchangeRateX96;      // from vaultInfo()
        uint256 lendExchangeRateX96;      // from vaultInfo()
        uint256 debt;                     // total debt in asset terms
        uint256 lent;                     // total lent in asset terms
        uint256 balance;                  // available balance
        uint256 reserves;                 // protocol reserves
        uint256 totalAssets;              // vault.totalAssets()
        uint256 transformedTokenId;       // vault.transformedTokenId()
        // Per-actor state (indexed by actor address in mapping below)
        // Per-loan state (indexed by tokenId in mapping below)
    }

    Vars internal _before;
    Vars internal _after;

    // Per-actor snapshots
    struct ActorVars {
        uint256 shares;          // vault.balanceOf(actor)
        uint256 assetBalance;    // IERC20(asset).balanceOf(actor)
    }
    mapping(address => ActorVars) internal _actorBefore;
    mapping(address => ActorVars) internal _actorAfter;

    // Per-loan snapshots
    struct LoanVars {
        uint256 debtShares;      // vault.loans(tokenId)
        uint256 debt;            // from loanInfo
        uint256 fullValue;       // from loanInfo
        uint256 collateralValue; // from loanInfo
    }
    mapping(uint256 => LoanVars) internal _loanBefore;
    mapping(uint256 => LoanVars) internal _loanAfter;

    // ===== Ghost Variables for Cumulative Tracking =====

    // Cumulative amounts per actor
    mapping(address => uint256) public ghost_cumulativeDeposits;
    mapping(address => uint256) public ghost_cumulativeWithdrawals;
    mapping(address => uint256) public ghost_cumulativeBorrows;
    mapping(address => uint256) public ghost_cumulativeRepays;

    // System-wide totals
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_totalBorrowed;
    uint256 public ghost_totalRepaid;
    uint256 public ghost_totalLiquidations;

    // SOL-002: track sum of individual loan debt shares
    mapping(uint256 => uint256) public ghost_loanDebtShares;
    uint256 public ghost_sumAllLoanDebtShares;
    uint256[] public ghost_activeTokenIds;
    mapping(uint256 => bool) public ghost_tokenIdActive;

    // COL-002: track per-token totalDebtShares
    mapping(address => uint256) public ghost_tokenConfigTotalDebtShares;

    // DEBT-001/002: exchange rate monotonicity tracking
    uint256 public ghost_prevDebtExchangeRateX96;
    uint256 public ghost_prevLendExchangeRateX96;

    // E46-004: share price tracking
    uint256 public ghost_prevSharePrice; // totalAssets * 1e18 / totalSupply

    // TRF-002: transform sentinel tracking
    bool public ghost_inTransform;

    // Operation counter for tolerance scaling
    uint256 public ghost_operationCount;

    // ===== Snapshot Functions =====

    function __snapshot_before() internal {
        _before.vaultAssetBalance = IERC20(vault.asset()).balanceOf(address(vault));
        _before.totalSupply = vault.totalSupply();
        _before.debtSharesTotal = vault.debtSharesTotal();
        _before.totalAssets = vault.totalAssets();
        _before.transformedTokenId = vault.transformedTokenId();

        (
            _before.debt,
            _before.lent,
            _before.balance,
            _before.reserves,
            _before.debtExchangeRateX96,
            _before.lendExchangeRateX96
        ) = vault.vaultInfo();
    }

    function __snapshot_after() internal {
        _after.vaultAssetBalance = IERC20(vault.asset()).balanceOf(address(vault));
        _after.totalSupply = vault.totalSupply();
        _after.debtSharesTotal = vault.debtSharesTotal();
        _after.totalAssets = vault.totalAssets();
        _after.transformedTokenId = vault.transformedTokenId();

        (
            _after.debt,
            _after.lent,
            _after.balance,
            _after.reserves,
            _after.debtExchangeRateX96,
            _after.lendExchangeRateX96
        ) = vault.vaultInfo();
    }

    function __snapshot_actor_before(address actor) internal {
        _actorBefore[actor].shares = vault.balanceOf(actor);
        _actorBefore[actor].assetBalance = IERC20(vault.asset()).balanceOf(actor);
    }

    function __snapshot_actor_after(address actor) internal {
        _actorAfter[actor].shares = vault.balanceOf(actor);
        _actorAfter[actor].assetBalance = IERC20(vault.asset()).balanceOf(actor);
    }

    function __snapshot_loan_before(uint256 tokenId) internal {
        _loanBefore[tokenId].debtShares = vault.loans(tokenId);
        (
            _loanBefore[tokenId].debt,
            _loanBefore[tokenId].fullValue,
            _loanBefore[tokenId].collateralValue,
            ,
        ) = vault.loanInfo(tokenId);
    }

    function __snapshot_loan_after(uint256 tokenId) internal {
        _loanAfter[tokenId].debtShares = vault.loans(tokenId);
        (
            _loanAfter[tokenId].debt,
            _loanAfter[tokenId].fullValue,
            _loanAfter[tokenId].collateralValue,
            ,
        ) = vault.loanInfo(tokenId);
    }

    // ===== Ghost Update Helpers =====

    function __ghost_deposit(address actor, uint256 assets) internal {
        ghost_cumulativeDeposits[actor] += assets;
        ghost_totalDeposited += assets;
        ghost_operationCount++;
    }

    function __ghost_withdraw(address actor, uint256 assets) internal {
        ghost_cumulativeWithdrawals[actor] += assets;
        ghost_totalWithdrawn += assets;
        ghost_operationCount++;
    }

    function __ghost_borrow(uint256 tokenId, uint256 assets, uint256 shares) internal {
        ghost_cumulativeBorrows[vault.ownerOf(tokenId)] += assets;
        ghost_totalBorrowed += assets;

        ghost_loanDebtShares[tokenId] += shares;
        ghost_sumAllLoanDebtShares += shares;
        if (!ghost_tokenIdActive[tokenId]) {
            ghost_activeTokenIds.push(tokenId);
            ghost_tokenIdActive[tokenId] = true;
        }
        ghost_operationCount++;
    }

    function __ghost_repay(uint256 tokenId, uint256 assets, uint256 shares) internal {
        ghost_cumulativeRepays[vault.ownerOf(tokenId)] += assets;
        ghost_totalRepaid += assets;

        ghost_loanDebtShares[tokenId] -= shares;
        ghost_sumAllLoanDebtShares -= shares;
        ghost_operationCount++;
    }

    function __ghost_liquidate(uint256 tokenId) internal {
        uint256 oldShares = ghost_loanDebtShares[tokenId];
        ghost_sumAllLoanDebtShares -= oldShares;
        ghost_loanDebtShares[tokenId] = 0;
        ghost_totalLiquidations++;
        ghost_operationCount++;
    }

    function __ghost_updateExchangeRates() internal {
        (,,,, uint256 dRate, uint256 lRate) = vault.vaultInfo();
        ghost_prevDebtExchangeRateX96 = dRate;
        ghost_prevLendExchangeRateX96 = lRate;
    }

    function __ghost_updateSharePrice() internal {
        uint256 supply = vault.totalSupply();
        if (supply > 0) {
            ghost_prevSharePrice = vault.totalAssets() * 1e18 / supply;
        }
    }
}
