// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/*//////////////////////////////////////////////////////////////
    INVARIANT TESTING TEMPLATE — Based on Recon/zigtur methodology

    Process (Cap Protocol 100-property model):
    1. IDENTIFY invariants from docs/NatSpec (see checklist below)
    2. BUILD handlers that wrap every user-facing function
    3. TRACK ghost variables for cross-call accounting
    4. DEFINE properties in 5 categories
    5. FUZZ with depth=1000, runs=1000+
    6. DEBUG failures → write PoC → submit finding

    Categories:
    A. Solvency & Accounting (balance >= owed)
    B. State Machine (valid transitions only)
    C. User Operations (no unexpected reverts/effects)
    D. Monotonicity (counters/prices only go up)
    E. Doomsday (extreme scenarios, manipulation)
//////////////////////////////////////////////////////////////*/

import {Test, console2} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";

/*//////////////////////////////////////////////////////////////
                        1. ACTOR MANAGEMENT
    Multi-actor fuzzing: randomly switch between users
    Pattern from Cap Protocol / Recon-Fuzz
//////////////////////////////////////////////////////////////*/

abstract contract ActorManager is Test {
    address[] internal actors;
    address internal currentActor;
    uint256 internal currentActorIndex;

    modifier useActor(uint256 actorSeed) {
        currentActorIndex = bound(actorSeed, 0, actors.length - 1);
        currentActor = actors[currentActorIndex];
        vm.startPrank(currentActor);
        _;
        vm.stopPrank();
    }

    function _addActor(address actor) internal {
        actors.push(actor);
    }

    function _getActor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, actors.length - 1)];
    }
}

/*//////////////////////////////////////////////////////////////
                        2. HANDLER TEMPLATE
    Wraps every protocol function with:
    - Input bounding (bound())
    - Actor management (useActor)
    - Ghost variable tracking
    - Pre/post condition checks
//////////////////////////////////////////////////////////////*/

abstract contract BaseHandler is ActorManager {
    // ═══════════════════════ GHOST VARIABLES ═══════════════════════
    // Track cumulative state across fuzz sequences for invariant checks

    // Accounting ghosts
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_totalBorrowed;
    uint256 public ghost_totalRepaid;
    uint256 public ghost_totalFeesPaid;

    // Per-actor ghosts
    mapping(address => uint256) public ghost_userDeposited;
    mapping(address => uint256) public ghost_userWithdrawn;

    // Operation counters (for monotonicity checks)
    uint256 public ghost_depositCount;
    uint256 public ghost_withdrawCount;
    uint256 public ghost_lastSharePrice;

    // Call success/failure tracking
    uint256 public ghost_callsSucceeded;
    uint256 public ghost_callsFailed;

    // ═══════════════════════ HANDLER ACTIONS ═══════════════════════
    // Each function wraps a protocol function with bounded inputs

    /*
    Example handler action for a vault deposit:

    function deposit(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        // 1. Bound inputs to valid ranges
        amount = bound(amount, 1, 1e24);

        // 2. Setup: mint tokens, approve
        deal(address(token), currentActor, amount);
        token.approve(address(vault), amount);

        // 3. Record pre-state
        uint256 sharesBefore = vault.balanceOf(currentActor);

        // 4. Execute (try/catch for failure tracking)
        try vault.deposit(amount, currentActor) returns (uint256 shares) {
            // 5. Update ghost variables
            ghost_totalDeposited += amount;
            ghost_userDeposited[currentActor] += amount;
            ghost_depositCount++;
            ghost_callsSucceeded++;

            // 6. Inline postconditions (per-call properties)
            assert(vault.balanceOf(currentActor) >= sharesBefore);
        } catch {
            ghost_callsFailed++;
        }
    }

    function withdraw(uint256 actorSeed, uint256 amount) external useActor(actorSeed) {
        uint256 maxWithdraw = vault.maxWithdraw(currentActor);
        if (maxWithdraw == 0) return; // Skip if nothing to withdraw
        amount = bound(amount, 1, maxWithdraw);

        uint256 balanceBefore = token.balanceOf(currentActor);

        try vault.withdraw(amount, currentActor, currentActor) returns (uint256 shares) {
            ghost_totalWithdrawn += amount;
            ghost_userWithdrawn[currentActor] += amount;
            ghost_withdrawCount++;
            ghost_callsSucceeded++;

            assert(token.balanceOf(currentActor) == balanceBefore + amount);
        } catch {
            ghost_callsFailed++;
        }
    }
    */
}

/*//////////////////////////////////////////////////////////////
                    3. INVARIANT TEST TEMPLATE
    Define all invariant_ functions here
    Each is checked after EVERY fuzzed call
//////////////////////////////////////////////////////////////*/

abstract contract InvariantTestBase is StdInvariant, Test {

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY A: SOLVENCY & ACCOUNTING
    // "Does the protocol have enough to cover obligations?"
    // ═══════════════════════════════════════════════════════════════

    /*
    // A.1: Protocol solvency — balance >= total owed
    function invariant_A1_solvency() public view {
        assertGe(
            token.balanceOf(address(vault)),
            vault.totalOwed(),
            "SOLVENCY BROKEN: vault balance < total owed"
        );
    }

    // A.2: Conservation — no value created from nothing
    function invariant_A2_conservation() public view {
        assertGe(
            handler.ghost_totalDeposited(),
            handler.ghost_totalWithdrawn(),
            "CONSERVATION BROKEN: withdrawn > deposited"
        );
    }

    // A.3: Sum of balances == totalSupply (ERC20)
    function invariant_A3_balanceSum() public view {
        uint256 sum;
        for (uint256 i; i < handler.actors.length; i++) {
            sum += vault.balanceOf(handler.actors[i]);
        }
        assertEq(sum, vault.totalSupply(), "BALANCE SUM != TOTAL SUPPLY");
    }

    // A.4: Total owed == sum of positive earmarks (Chainlink Reserves pattern)
    function invariant_A4_earmarkAccounting() public view {
        uint256 sumPositive;
        for (uint256 i; i < providers.length; i++) {
            int96 balance = reserves.getServiceProvider(providers[i]).linkBalance;
            if (balance > 0) sumPositive += uint256(int256(balance));
        }
        assertEq(sumPositive, reserves.getTotalLinkAmountOwed());
    }

    // A.5: Fee accounting — fees collected <= total volume
    function invariant_A5_feeBounds() public view {
        assertLe(
            handler.ghost_totalFeesPaid(),
            handler.ghost_totalDeposited() * MAX_FEE_BPS / 10000,
            "FEES EXCEEDED MAXIMUM"
        );
    }
    */

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY B: STATE MACHINE
    // "Are all states and transitions valid?"
    // ═══════════════════════════════════════════════════════════════

    /*
    // B.1: Only valid state transitions
    function invariant_B1_validStates() public view {
        uint8 status = uint8(protocol.status());
        assertTrue(
            status <= uint8(type(Status).max),
            "INVALID STATE"
        );
    }

    // B.2: Terminal states are irreversible
    function invariant_B2_terminalImmutable() public view {
        if (ghost_wasFinalized) {
            assertEq(
                uint8(protocol.status()),
                uint8(Status.FINALIZED),
                "FINALIZED STATE WAS REVERSED"
            );
        }
    }

    // B.3: Pause enforcement — operations blocked when paused
    function invariant_B3_pauseEnforcement() public view {
        // Tested via handler: if paused, all user ops should revert
    }
    */

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY C: USER OPERATIONS
    // "Can users always do what they should? Never do what they shouldn't?"
    // ═══════════════════════════════════════════════════════════════

    /*
    // C.1: Round-trip — deposit then withdraw gives <= original (no free profit)
    function invariant_C1_roundTrip() public view {
        for (uint256 i; i < handler.actors.length; i++) {
            address actor = handler.actors[i];
            assertGe(
                handler.ghost_userDeposited(actor),
                handler.ghost_userWithdrawn(actor),
                "FREE PROFIT: user withdrew more than deposited"
            );
        }
    }

    // C.2: Rounding direction — always favors protocol (prevents drain)
    // Key insight from Balancer $100M hack: test across SEQUENCES, not single calls
    function invariant_C2_roundingDirection() public view {
        // After many deposit/withdraw cycles, protocol should have >= expected
        uint256 expectedMin = handler.ghost_totalDeposited() - handler.ghost_totalWithdrawn();
        assertGe(
            token.balanceOf(address(vault)),
            expectedMin,
            "ROUNDING DRAIN: protocol lost value over sequences"
        );
    }

    // C.3: No operation makes a healthy user liquidatable (Cap Protocol pattern)
    function invariant_C3_noSurpriseLiquidation() public view {
        for (uint256 i; i < handler.actors.length; i++) {
            if (handler.ghost_wasHealthy[handler.actors[i]]) {
                assertTrue(
                    protocol.isHealthy(handler.actors[i]),
                    "HEALTHY USER BECAME LIQUIDATABLE"
                );
            }
        }
    }
    */

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY D: MONOTONICITY & BOUNDS
    // "Do values that should only increase actually only increase?"
    // ═══════════════════════════════════════════════════════════════

    /*
    // D.1: Share price never decreases (ERC4626)
    function invariant_D1_sharePriceMonotonic() public {
        if (vault.totalSupply() > 0) {
            uint256 currentPrice = vault.totalAssets() * 1e18 / vault.totalSupply();
            assertGe(currentPrice, ghost_lastSharePrice, "SHARE PRICE DECREASED");
            ghost_lastSharePrice = currentPrice;
        }
    }

    // D.2: Interest/utilization index only increases (lending)
    function invariant_D2_indexMonotonic() public view {
        assertGe(
            protocol.utilizationIndex(),
            ghost_lastUtilizationIndex,
            "UTILIZATION INDEX DECREASED"
        );
    }

    // D.3: Counters never decrease
    function invariant_D3_counterMonotonic() public view {
        assertGe(handler.ghost_depositCount(), ghost_lastDepositCount);
    }

    // D.4: Dutch auction price only decreases over time
    function invariant_D4_auctionPriceDecay() public view {
        if (auction.isActive()) {
            uint256 currentPrice = auction.getCurrentPrice();
            assertLe(currentPrice, auction.getStartPrice(), "AUCTION PRICE ABOVE START");
            assertGe(currentPrice, auction.getEndPrice(), "AUCTION PRICE BELOW END");
        }
    }
    */

    // ═══════════════════════════════════════════════════════════════
    // CATEGORY E: DOOMSDAY SCENARIOS
    // "What happens under extreme conditions?"
    // ═══════════════════════════════════════════════════════════════

    /*
    // E.1: Borrow-repay in same block shouldn't change utilization (Cap Protocol)
    function invariant_E1_sameBlockManipulation() public view {
        // Tracked in handler: if borrow+repay in same block, utilization unchanged
    }

    // E.2: Max operations don't brick the contract
    function invariant_E2_maxBorrowNeverReverts() public view {
        // Handler tracks: protocol.maxBorrow() should never revert
        assertEq(handler.ghost_maxBorrowReverts(), 0, "maxBorrow() REVERTED");
    }

    // E.3: View functions never revert (Cap Protocol pattern)
    function invariant_E3_viewsSafe() public view {
        assertEq(handler.ghost_totalAssetsReverts(), 0, "totalAssets() REVERTED");
        assertEq(handler.ghost_maxWithdrawReverts(), 0, "maxWithdraw() REVERTED");
    }

    // E.4: Liquidation always improves health (or system detects bad debt)
    function invariant_E4_liquidationImproves() public view {
        // Tracked in handler: post-liquidation health >= pre-liquidation health
    }

    // E.5: First depositor attack protection
    function invariant_E5_firstDepositor() public view {
        if (vault.totalSupply() > 0 && vault.totalSupply() < 1000) {
            // With very low shares, check that large deposits get fair shares
            // Donation attack: attacker inflates share price to steal from next depositor
        }
    }
    */
}

/*//////////////////////////////////////////////////////////////
                    4. DUTCH AUCTION HANDLER
    Specific to Chainlink Payment Abstraction V2
//////////////////////////////////////////////////////////////*/

abstract contract DutchAuctionHandler is BaseHandler {
    /*
    // Ghost variables specific to Dutch auction
    uint256 public ghost_totalAuctionsFilled;
    uint256 public ghost_totalTokensConverted;
    uint256 public ghost_totalLinkReceived;
    mapping(uint256 => uint256) public ghost_auctionStartPrice;
    mapping(uint256 => uint256) public ghost_auctionFillPrice;

    // Action: Create/start auction
    function startAuction(uint256 actorSeed, uint256 tokenAmount) external useActor(actorSeed) {
        tokenAmount = bound(tokenAmount, MIN_AUCTION, MAX_AUCTION);
        // ... create auction
        ghost_auctionStartPrice[auctionId] = auction.getStartPrice();
    }

    // Action: Fill auction (permissionless)
    function fillAuction(uint256 actorSeed, uint256 auctionId, uint256 amount) external useActor(actorSeed) {
        auctionId = bound(auctionId, 0, nextAuctionId - 1);
        if (!auction.isActive(auctionId)) return;

        uint256 currentPrice = auction.getCurrentPrice(auctionId);
        amount = bound(amount, 1, auction.getRemainingAmount(auctionId));

        uint256 linkBefore = linkToken.balanceOf(address(reserves));

        try auction.fill(auctionId, amount) {
            ghost_totalAuctionsFilled++;
            ghost_totalTokensConverted += amount;
            ghost_totalLinkReceived += linkToken.balanceOf(address(reserves)) - linkBefore;
            ghost_auctionFillPrice[auctionId] = currentPrice;
            ghost_callsSucceeded++;

            // Inline property: fill price <= start price (price only decays)
            assert(currentPrice <= ghost_auctionStartPrice[auctionId]);
        } catch {
            ghost_callsFailed++;
        }
    }

    // Action: Advance time (for price decay)
    function advanceTime(uint256 seconds_) external {
        seconds_ = bound(seconds_, 1, 1 days);
        vm.warp(block.timestamp + seconds_);
    }

    // Action: Manipulate oracle price (simulate market movement)
    function setOraclePrice(uint256 price) external {
        price = bound(price, 1e6, 1e12); // $0.01 to $10,000
        mockOracle.setLatestAnswer(int256(price));
    }
    */
}

/*//////////////////////////////////////////////////////////////
                    5. SETUP CHECKLIST
    Before fuzzing a new protocol, answer these:
//////////////////////////////////////////////////////////////*/

/*
INVARIANT IDENTIFICATION CHECKLIST (from Recon methodology):

[ ] 1. READ all NatSpec comments — extract every "must", "should", "always", "never"
[ ] 2. READ the README — extract stated guarantees and assumptions
[ ] 3. MAP all state variables — for each, ask "what range is valid?"
[ ] 4. MAP all state transitions — for each, ask "what transitions are forbidden?"
[ ] 5. LIST all user-facing functions — for each, ask:
      - What preconditions must hold?
      - What postconditions are guaranteed?
      - Can this revert unexpectedly?
[ ] 6. IDENTIFY token flows — where do tokens enter/exit? Any leaks?
[ ] 7. IDENTIFY trust boundaries — who is trusted? What can untrusted actors do?
[ ] 8. CHECK existing tests — what invariants does the project already test? What's MISSING?

PROPERTY TYPES (4 categories from Recon):
1. Valid States: "X is always within range [a, b]"
2. State Transitions: "X can only go from A to B, never B to A"
3. Variable Transitions: "X only increases" or "X changes by exactly delta"
4. High-Level: "sum(deposits) >= sum(withdrawals)" across all users

HANDLER DESIGN RULES:
- ALWAYS use bound() on every fuzzed input
- ALWAYS use try/catch to track failures
- ALWAYS update ghost variables AFTER successful calls
- USE useActor() modifier for multi-user scenarios
- SKIP invalid states early (if balance == 0 return) to help fuzzer find meaningful sequences
- DEAL tokens as needed (don't rely on pre-minted balances)

CONFIGURATION:
- Start with: runs=256, depth=50 (fast iteration)
- Scale to: runs=10000, depth=5000 (deep search)
- Set fail_on_revert=false (let fuzzer explore revert paths)
- Use targetSelector() to focus on critical functions
- Use excludeContract() on all non-handler contracts

DEBUGGING FAILURES:
1. Foundry outputs the exact call sequence that broke the invariant
2. Copy the sequence into a unit test
3. Add console.log to trace state changes
4. Identify the root cause → write PoC → submit finding
*/
