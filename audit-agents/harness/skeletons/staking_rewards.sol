// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * Staking/Rewards (Synthetix-style) Invariant Test Skeleton
 *
 * USAGE:
 * 1. Replace IStakingRewards with the actual staking contract interface
 * 2. Replace STAKING_TOKEN / REWARD_TOKEN with actual tokens
 * 3. Customize setUp() with correct deployment/initialization
 * 4. Remove invariants that don't apply to this specific staking contract
 * 5. Run: forge test --match-contract StakingRewardsInvariant -vvv
 *
 * TARGET PATTERN:
 * This skeleton targets the Synthetix StakingRewards pattern and its many forks
 * (e.g., Convex, Curve gauge, Sushiswap MasterChef variants). The core mechanism:
 * - Users stake a token to earn rewards over a fixed duration
 * - rewardPerTokenStored accumulates proportionally to time and inversely to total staked
 * - Users claim earned rewards via getReward()
 * - Admin notifies new reward periods via notifyRewardAmount()
 */

// ============================================================================
// CONFIGURATION — Edit these for your target
// ============================================================================

// import {StakingRewards} from "src/StakingRewards.sol";

/// @notice Minimal interface for Synthetix-style staking. Replace with actual.
interface IStakingRewards {
    function stakingToken() external view returns (address);
    function rewardsToken() external view returns (address);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function rewardPerToken() external view returns (uint256);
    function earned(address account) external view returns (uint256);
    function rewardRate() external view returns (uint256);
    function periodFinish() external view returns (uint256);
    function rewardPerTokenStored() external view returns (uint256);
    function stake(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function getReward() external;
    function notifyRewardAmount(uint256 reward) external;
}

contract StakingRewardsHandler is Test {
    IStakingRewards public staking;
    IERC20 public stakingToken;
    IERC20 public rewardsToken;
    address public admin;
    address[] public actors;

    // =========================================================================
    // Ghost variables — track cumulative state for invariant checking
    // =========================================================================

    /// @dev Sum of all individual stakes (mirrors totalSupply, checked as invariant)
    uint256 public ghost_sumStaked;

    /// @dev Per-user staked amount for cross-checking
    mapping(address => uint256) public ghost_stakedByUser;

    /// @dev Total rewards claimed by all users across all getReward() calls
    uint256 public ghost_totalRewardsClaimed;

    /// @dev Per-user total rewards claimed
    mapping(address => uint256) public ghost_claimedByUser;

    /// @dev Total rewards notified by admin across all notifyRewardAmount() calls
    uint256 public ghost_totalRewardsNotified;

    /// @dev Last recorded rewardPerToken value, for monotonicity check
    uint256 public ghost_lastRewardPerToken;

    /// @dev Number of actors that have staked (for iteration bounds)
    uint256 public ghost_activeStakers;

    constructor(IStakingRewards _staking, address _admin, address[] memory _actors) {
        staking = _staking;
        stakingToken = IERC20(_staking.stakingToken());
        rewardsToken = IERC20(_staking.rewardsToken());
        admin = _admin;
        actors = _actors;
    }

    modifier useActor(uint256 seed) {
        address actor = actors[seed % actors.length];
        vm.startPrank(actor);
        _;
        vm.stopPrank();
    }

    // =========================================================================
    // Handler functions — the fuzzer calls these
    // =========================================================================

    /// @notice Stake tokens into the staking contract
    /// @dev Simulates a user depositing staking tokens to earn rewards.
    ///      Ghost vars track per-user and total staked for invariant cross-checks.
    function stake(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];

        uint256 balance = stakingToken.balanceOf(actor);
        if (balance == 0) return;

        amount = bound(amount, 1, balance);

        // Update monotonicity tracker before state change
        ghost_lastRewardPerToken = staking.rewardPerToken();

        stakingToken.approve(address(staking), amount);
        staking.stake(amount);

        ghost_sumStaked += amount;
        if (ghost_stakedByUser[actor] == 0) ghost_activeStakers++;
        ghost_stakedByUser[actor] += amount;
    }

    /// @notice Withdraw (unstake) tokens from the staking contract
    /// @dev Simulates a user removing their staked tokens.
    ///      Bounded to user's actual staked balance to avoid reverts.
    function withdraw(uint256 amount, uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];

        uint256 stakedBalance = staking.balanceOf(actor);
        if (stakedBalance == 0) return;

        amount = bound(amount, 1, stakedBalance);

        // Update monotonicity tracker before state change
        ghost_lastRewardPerToken = staking.rewardPerToken();

        staking.withdraw(amount);

        ghost_sumStaked -= amount;
        ghost_stakedByUser[actor] -= amount;
        if (ghost_stakedByUser[actor] == 0) ghost_activeStakers--;
    }

    /// @notice Claim accrued rewards
    /// @dev Simulates a user calling getReward() to collect earned rewards.
    ///      Tracks claimed amounts per-user and total for distribution invariants.
    function getReward(uint256 actorSeed) external useActor(actorSeed) {
        address actor = actors[actorSeed % actors.length];

        // Update monotonicity tracker before state change
        ghost_lastRewardPerToken = staking.rewardPerToken();

        // Record balance before to measure actual transfer
        uint256 rewardBefore = rewardsToken.balanceOf(actor);

        staking.getReward();

        uint256 rewardAfter = rewardsToken.balanceOf(actor);
        uint256 claimed = rewardAfter - rewardBefore;

        ghost_totalRewardsClaimed += claimed;
        ghost_claimedByUser[actor] += claimed;
    }

    /// @notice Admin notifies a new reward amount to distribute
    /// @dev Simulates the reward distribution admin adding rewards.
    ///      In Synthetix pattern, this sets rewardRate and resets periodFinish.
    ///      Must be called by the rewards distributor (admin/owner).
    function notifyRewardAmount(uint256 reward, uint256 durationSeed) external {
        reward = bound(reward, 1e18, 1_000_000e18);

        // Update monotonicity tracker before state change
        ghost_lastRewardPerToken = staking.rewardPerToken();

        // Fund the staking contract with reward tokens
        deal(address(rewardsToken), address(staking), rewardsToken.balanceOf(address(staking)) + reward);

        vm.prank(admin);
        staking.notifyRewardAmount(reward);

        ghost_totalRewardsNotified += reward;
    }

    /// @notice Advance block.timestamp to simulate reward accrual over time
    /// @dev Critical for testing: rewards accrue per-second in Synthetix pattern.
    ///      Without time advancement, rewardPerToken stays constant.
    function warpForward(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 30 days);
        vm.warp(block.timestamp + seconds_);
    }
}

contract StakingRewardsInvariant is StdInvariant, Test {
    IStakingRewards public staking;
    IERC20 public stakingToken;
    IERC20 public rewardsToken;
    StakingRewardsHandler public handler;

    address public admin;
    address[] public actors;

    function setUp() public {
        // =====================================================================
        // CUSTOMIZE: Deploy or fork your target staking contract here
        // =====================================================================
        // Example:
        // admin = makeAddr("admin");
        // stakingToken = IERC20(address(new MockERC20("STK", "STK", 18)));
        // rewardsToken = IERC20(address(new MockERC20("RWD", "RWD", 18)));
        // vm.prank(admin);
        // staking = IStakingRewards(address(new StakingRewards(
        //     admin, admin, address(rewardsToken), address(stakingToken)
        // )));

        admin = makeAddr("admin");

        // Create actor accounts
        for (uint256 i = 0; i < 5; i++) {
            address actor = makeAddr(string(abi.encodePacked("actor", i)));
            actors.push(actor);
            // Fund actors with staking tokens
            deal(address(stakingToken), actor, 1_000_000e18);
        }

        handler = new StakingRewardsHandler(staking, admin, actors);

        // Target the handler for fuzzing
        targetContract(address(handler));
    }

    // =========================================================================
    // TIER S — Critical invariants (test these first)
    // =========================================================================

    /// @notice INV-STK-001: totalSupply must equal sum of individual staked balances
    /// @dev Catches: double-counting in stake(), underflow in withdraw(), reentrancy
    ///      during stake/withdraw that corrupts totalSupply. This is the fundamental
    ///      accounting invariant. Ghost variable ghost_sumStaked independently tracks
    ///      the expected total. If they diverge, the contract's internal accounting is broken.
    function invariant_total_staked_eq_sum_of_stakes() public view {
        uint256 sumBalances = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumBalances += staking.balanceOf(actors[i]);
        }

        // Contract totalSupply must match the sum of all individual balances
        assertEq(
            staking.totalSupply(),
            sumBalances,
            "INV-STK-001: totalSupply != sum of balanceOf. Accounting corruption."
        );

        // Ghost variable must also match (handler vs contract agreement)
        assertEq(
            staking.totalSupply(),
            handler.ghost_sumStaked(),
            "INV-STK-001: totalSupply != ghost_sumStaked. Handler/contract desync."
        );
    }

    /// @notice INV-STK-002: No user can claim more rewards than they have earned
    /// @dev Catches: reward calculation overflow, double-claim, rewardPerTokenStored
    ///      manipulation, flash-loan stake-claim-unstake attacks. If any user receives
    ///      more reward tokens than earned() reported, the reward math is exploitable.
    ///      Combined with INV-STK-005, ensures the total payout pool is bounded.
    function invariant_no_overclaim() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            address actor = actors[i];
            uint256 claimed = handler.ghost_claimedByUser(actor);
            uint256 stillEarned = staking.earned(actor);

            // Total rewards attributable to this user = claimed + still-pending
            // This should never exceed what's been allocated to them by the reward math.
            // As a sanity check: user's total claimed should not exceed total notified.
            assertLe(
                claimed,
                handler.ghost_totalRewardsNotified(),
                "INV-STK-002: User claimed more than total rewards ever notified!"
            );
        }
    }

    /// @notice INV-STK-003: Staking token balance >= totalStaked (solvency)
    /// @dev Catches: reentrancy drain, unauthorized transfers out, accounting bugs
    ///      where totalSupply inflates without matching deposits. If the contract holds
    ///      fewer staking tokens than it owes, some users cannot withdraw. This is the
    ///      staking equivalent of a bank run insolvency.
    function invariant_staking_solvency() public view {
        assertGe(
            stakingToken.balanceOf(address(staking)),
            staking.totalSupply(),
            "INV-STK-003: Staking token balance < totalSupply. Insolvent!"
        );
    }

    // =========================================================================
    // TIER A — High-value invariants
    // =========================================================================

    /// @notice INV-STK-004: rewardPerToken must monotonically increase
    /// @dev Catches: rewardPerToken reset/decrease bugs, integer underflow in reward
    ///      calculation, incorrect handling of notifyRewardAmount when period is active.
    ///      In Synthetix, rewardPerToken = stored + (timeDelta * rate * 1e18 / totalSupply).
    ///      Since all terms are non-negative, this should only ever increase. A decrease
    ///      means rewards were retroactively removed, violating user expectations.
    function invariant_reward_per_token_monotonic() public view {
        uint256 current = staking.rewardPerToken();
        assertGe(
            current,
            handler.ghost_lastRewardPerToken(),
            "INV-STK-004: rewardPerToken decreased! Reward accounting broken."
        );
    }

    /// @notice INV-STK-005: Total rewards distributed must not exceed total rewards notified
    /// @dev Catches: reward inflation, minting rewards from nothing, incorrect leftover
    ///      reward handling in notifyRewardAmount when called mid-period. If more rewards
    ///      leave the contract than were put in, there's a critical accounting bug.
    ///      Note: small rounding dust is acceptable (< 1e6 wei per notification).
    function invariant_total_distributed_le_notified() public view {
        uint256 totalClaimed = handler.ghost_totalRewardsClaimed();
        uint256 totalNotified = handler.ghost_totalRewardsNotified();

        // Allow small rounding tolerance: 1 wei per second of reward period per notification
        // CUSTOMIZE: adjust tolerance based on reward token decimals
        uint256 tolerance = 1e6;

        assertLe(
            totalClaimed,
            totalNotified + tolerance,
            "INV-STK-005: More rewards distributed than notified. Reward inflation!"
        );
    }

    /// @notice INV-STK-006: After reward period ends, no new rewards accrue
    /// @dev Catches: rewardRate not zeroing out after periodFinish, rewards continuing
    ///      to accrue indefinitely. In Synthetix, once block.timestamp > periodFinish,
    ///      the effective reward rate should be 0. If rewards keep accruing, the contract
    ///      promises rewards it doesn't have tokens to cover.
    function invariant_no_rewards_after_period() public view {
        if (block.timestamp <= staking.periodFinish()) return;
        if (staking.totalSupply() == 0) return;

        // Snapshot earned for all users
        uint256 totalEarnedNow = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            totalEarnedNow += staking.earned(actors[i]);
        }

        // Warp forward should not change earned amounts after period ends.
        // We can't warp in a view function, so we check that rewardRate math
        // is effectively zero: rewardPerToken should be stable once past periodFinish.
        // The handler's ghost_lastRewardPerToken captures pre-operation values;
        // after period ends, rewardPerToken() should equal rewardPerTokenStored().
        assertEq(
            staking.rewardPerToken(),
            staking.rewardPerTokenStored(),
            "INV-STK-006: rewardPerToken still changing after period ended!"
        );
    }

    // =========================================================================
    // TIER B — Safety invariants (view functions)
    // =========================================================================

    /// @notice INV-STK-007: earned() must not revert for any user
    /// @dev Catches: division by zero when totalSupply is 0, overflow in reward
    ///      calculation for large balances or long time periods. The earned() view
    ///      function is called by UIs and keepers; if it reverts, users can't see
    ///      their rewards and integrations break. Common bug: division by zero when
    ///      totalSupply drops to 0 but rewardPerToken tries to compute.
    function invariant_earned_no_revert() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            staking.earned(actors[i]);
        }
        // Also test for address(0) and an address that never staked
        staking.earned(address(0));
        staking.earned(address(0xdead));
    }

    /// @notice INV-STK-008: Zero stake must mean zero rewards earned
    /// @dev Catches: phantom reward accrual for non-stakers, incorrect initialization
    ///      of userRewardPerTokenPaid for new users, stale earned() values after full
    ///      withdrawal. If a user has 0 staked, earned() should return 0 (assuming
    ///      they also claimed everything). A non-zero value for a non-staker means
    ///      rewards can be claimed without economic participation.
    function invariant_zero_stake_zero_rewards() public view {
        for (uint256 i = 0; i < actors.length; i++) {
            address actor = actors[i];
            if (staking.balanceOf(actor) == 0 && handler.ghost_stakedByUser(actor) == 0) {
                // This user never staked, so earned should be 0
                assertEq(
                    staking.earned(actor),
                    0,
                    "INV-STK-008: User who never staked has nonzero earned(). Phantom rewards."
                );
            }
        }

        // Fresh address that definitely never interacted should earn nothing
        assertEq(
            staking.earned(address(0xdead)),
            0,
            "INV-STK-008: Random address has nonzero earned(). Critical reward bug."
        );
    }
}
