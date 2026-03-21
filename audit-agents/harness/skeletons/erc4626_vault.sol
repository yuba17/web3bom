// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * ERC4626 Vault Invariant Test Skeleton
 *
 * USAGE:
 * 1. Replace TARGET_VAULT with the actual vault contract
 * 2. Replace TARGET_ASSET with the underlying asset
 * 3. Customize setup() with correct deployment/initialization
 * 4. Remove invariants that don't apply to this specific vault
 * 5. Run: forge test --match-contract ERC4626VaultInvariant -vvv
 */

// ============================================================================
// CONFIGURATION — Edit these for your target
// ============================================================================

// import {TargetVault} from "src/TargetVault.sol";
// import {TargetAsset} from "src/TargetAsset.sol";

contract ERC4626VaultHandler is Test {
    IERC4626 public vault;
    IERC20 public asset;
    address[] public actors;

    // Ghost variables for tracking
    uint256 public ghost_sumDeposited;
    uint256 public ghost_sumWithdrawn;
    mapping(address => uint256) public ghost_depositedByUser;

    constructor(IERC4626 _vault, address[] memory _actors) {
        vault = _vault;
        asset = IERC20(vault.asset());
        actors = _actors;
    }

    modifier useActor(uint256 seed) {
        address actor = actors[seed % actors.length];
        vm.startPrank(actor);
        _;
        vm.stopPrank();
    }

    // --- State-changing functions ---

    function deposit(uint256 assets, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        assets = bound(assets, 1, asset.balanceOf(actor));
        if (assets == 0) return;

        uint256 maxDep = vault.maxDeposit(actor);
        if (maxDep == 0) return;
        assets = bound(assets, 1, maxDep);

        asset.approve(address(vault), assets);
        uint256 shares = vault.deposit(assets, actor);

        ghost_sumDeposited += assets;
        ghost_depositedByUser[actor] += assets;
    }

    function mint(uint256 shares, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 maxMint = vault.maxMint(actor);
        if (maxMint == 0) return;
        shares = bound(shares, 1, maxMint);

        uint256 assetsNeeded = vault.previewMint(shares);
        if (assetsNeeded > asset.balanceOf(actor)) return;

        asset.approve(address(vault), assetsNeeded);
        vault.mint(shares, actor);

        ghost_sumDeposited += assetsNeeded;
    }

    function withdraw(uint256 assets, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 maxWith = vault.maxWithdraw(actor);
        if (maxWith == 0) return;
        assets = bound(assets, 1, maxWith);

        vault.withdraw(assets, actor, actor);
        ghost_sumWithdrawn += assets;
    }

    function redeem(uint256 shares, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];
        uint256 maxRedeem = vault.maxRedeem(actor);
        if (maxRedeem == 0) return;
        shares = bound(shares, 1, maxRedeem);

        uint256 assets = vault.redeem(shares, actor, actor);
        ghost_sumWithdrawn += assets;
    }

    // --- Helper for time advancement ---

    function warpForward(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 365 days);
        vm.warp(block.timestamp + seconds_);
    }
}

contract ERC4626VaultInvariant is StdInvariant, Test {
    IERC4626 public vault;
    IERC20 public asset;
    ERC4626VaultHandler public handler;

    address[] public actors;
    uint256 public lastPricePerShare;

    function setUp() public {
        // =====================================================================
        // CUSTOMIZE: Deploy or fork your target vault here
        // =====================================================================
        // Example:
        // asset = IERC20(address(new MockERC20("USDC", "USDC", 6)));
        // vault = IERC4626(address(new TargetVault(address(asset))));

        // Create actor accounts
        for (uint256 i = 0; i < 5; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            // Fund actors with asset tokens
            deal(address(asset), actor, 1_000_000e18);
        }

        handler = new ERC4626VaultHandler(vault, actors);

        // Target the handler for fuzzing
        targetContract(address(handler));

        // Record initial share price
        if (vault.totalSupply() > 0) {
            lastPricePerShare = vault.convertToAssets(1e18);
        }
    }

    // =========================================================================
    // TIER S — Critical invariants (test these first)
    // =========================================================================

    /// @notice INV-V4626-001: Share price must never decrease (no donation attack)
    function invariant_share_price_monotonic() public view {
        if (vault.totalSupply() == 0) return;
        uint256 currentPrice = vault.convertToAssets(1e18);
        assertGe(currentPrice, lastPricePerShare, "Share price decreased!");
    }

    /// @notice INV-V4626-002: totalAssets == 0 iff totalSupply == 0
    function invariant_zero_supply_iff_zero_assets() public view {
        if (vault.totalAssets() == 0) {
            assertEq(vault.totalSupply(), 0, "totalAssets=0 but totalSupply!=0");
        }
        if (vault.totalSupply() == 0) {
            assertEq(vault.totalAssets(), 0, "totalSupply=0 but totalAssets!=0");
        }
    }

    /// @notice INV-V4626-003: Underlying token balance >= internal cash accounting
    function invariant_solvency() public view {
        assertGe(
            asset.balanceOf(address(vault)),
            vault.totalAssets(),
            "Vault insolvent: token balance < totalAssets"
        );
    }

    /// @notice INV-V4626-006: totalSupply == sum of all balanceOf
    function invariant_total_supply_consistency() public view {
        uint256 sumBalances = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumBalances += vault.balanceOf(actors[i]);
        }
        // Note: may not equal exactly due to fee receiver, etc.
        assertLe(sumBalances, vault.totalSupply(), "Sum of balances > totalSupply");
    }

    // =========================================================================
    // TIER A — High-value invariants
    // =========================================================================

    /// @notice INV-V4626-004: convertToShares must not vary by caller
    function invariant_convertToShares_caller_independent() public view {
        if (vault.totalSupply() == 0) return;
        uint256 testAmount = 1e18;
        uint256 expected = vault.convertToShares(testAmount);
        for (uint256 i = 0; i < actors.length; i++) {
            vm.prank(actors[i]);
            uint256 result = vault.convertToShares(testAmount);
            assertEq(result, expected, "convertToShares varies by caller");
        }
    }

    /// @notice INV-V4626-005: convertToAssets must not vary by caller
    function invariant_convertToAssets_caller_independent() public view {
        if (vault.totalSupply() == 0) return;
        uint256 testShares = 1e18;
        uint256 expected = vault.convertToAssets(testShares);
        for (uint256 i = 0; i < actors.length; i++) {
            vm.prank(actors[i]);
            uint256 result = vault.convertToAssets(testShares);
            assertEq(result, expected, "convertToAssets varies by caller");
        }
    }

    // =========================================================================
    // TIER B — Safety invariants (view functions)
    // =========================================================================

    /// @notice INV-V4626-027: asset() must not revert
    function invariant_asset_no_revert() public view {
        vault.asset();
    }

    /// @notice INV-V4626-028: totalAssets() must not revert
    function invariant_totalAssets_no_revert() public view {
        vault.totalAssets();
    }

    /// @notice INV-V4626-009: maxDeposit must not revert
    function invariant_maxDeposit_no_revert() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            vault.maxDeposit(actors[i]);
        }
    }

    /// @notice INV-V4626-010: maxMint must not revert
    function invariant_maxMint_no_revert() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            vault.maxMint(actors[i]);
        }
    }

    /// @notice INV-V4626-011: maxWithdraw must not revert
    function invariant_maxWithdraw_no_revert() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            vault.maxWithdraw(actors[i]);
        }
    }

    /// @notice INV-V4626-012: maxRedeem must not revert
    function invariant_maxRedeem_no_revert() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            vault.maxRedeem(actors[i]);
        }
    }
}
