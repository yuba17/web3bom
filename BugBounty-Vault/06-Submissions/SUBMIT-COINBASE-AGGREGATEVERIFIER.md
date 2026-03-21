# AggregateVerifier: Bond Permanently Locked When Parent Game Invalidated With PROOF_THRESHOLD=2

## Summary

In [`AggregateVerifier.sol#L453`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L453), the `proofCount < PROOF_THRESHOLD` check is placed **outside** the if/else branch that handles parent game invalidation. When `PROOF_THRESHOLD=2` and a parent game resolves as `CHALLENGER_WINS`, the function correctly sets the child's status but then reverts with `NotEnoughProofs()`, making the game permanently unresolvable and the bond permanently locked with zero recovery paths.

## Finding Description

The [`resolve()`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L432-L464) function in `AggregateVerifier.sol` has a misplaced proof threshold check:

```solidity
function resolve() external returns (GameStatus) {
    if (status != GameStatus.IN_PROGRESS) revert ClaimAlreadyResolved();

    GameStatus parentGameStatus = _getParentGameStatus();
    if (parentGameStatus == GameStatus.IN_PROGRESS) revert ParentGameNotResolved();

    bool isChallenged = counteredByIntermediateRootIndexPlusOne > 0;

    if (parentGameStatus == GameStatus.CHALLENGER_WINS) {
        status = GameStatus.CHALLENGER_WINS;          // ← Correctly sets status
    } else {
        if (!gameOver()) revert GameNotOver();
        status = isChallenged ? GameStatus.CHALLENGER_WINS : GameStatus.DEFENDER_WINS;
    }

    // BUG: This check applies to BOTH paths, including parent invalidation
    if (proofCount < PROOF_THRESHOLD) revert NotEnoughProofs();  // ← L453: ALWAYS reverts

    resolvedAt = Timestamp.wrap(uint64(block.timestamp));         // ← NEVER reached
    emit Resolved(status);
    return status;
}
```

The [constructor validates](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L276) that `PROOF_THRESHOLD` must be 1 or 2. When set to 2, `initializeWithInitData()` submits exactly 1 proof (TEE), setting `proofCount=1`. A second proof (ZK) is expected later via [`verifyProposalProof()`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L407-L429).

If the parent game is invalidated before the second proof arrives, **all four recovery paths are simultaneously blocked:**

**Path 1 — `resolve()`:** Reverts at [L453](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L453) because `proofCount(1) < PROOF_THRESHOLD(2)`, even though status was correctly set to `CHALLENGER_WINS`.

**Path 2 — `claimCredit()` normal resolution ([L601-602](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L601-L602)):** Requires `resolvedAt.raw() != 0`. Since `resolve()` always reverts, `resolvedAt` is never set.

**Path 3 — `claimCredit()` 14-day fallback ([L603-604](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L603-L604)):** Requires `expectedResolution.raw() == type(uint64).max`. But during initialization, [`_decreaseExpectedResolution()`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L761-L777) sets `expectedResolution = block.timestamp + 7 days`. This branch is never entered.

**Path 4 — `verifyProposalProof()` to add second proof ([L412](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L412)):** After 7 days, `gameOver()` returns true and reverts with `GameOver()`. The window where both conditions align (parent invalidated + game not yet over) may not exist, and even if it does, it requires a valid ZK proof generated and submitted within that narrow window.

### Execution Trace

```
1. initializeWithInitData():
   - L372: expectedResolution = type(uint64).max
   - L394: _proofVerifiedUpdate() → proofCount = 1
   - L755: _decreaseExpectedResolution() → delay = 7 days
   - L776: expectedResolution = now + 7 days

2. Guardian blacklists parent game (or parent resolves CHALLENGER_WINS)

3. After 7 days, resolve():
   - L434: status == IN_PROGRESS ✓
   - L443: parentGameStatus == CHALLENGER_WINS → status = CHALLENGER_WINS ✓
   - L453: proofCount(1) < PROOF_THRESHOLD(2) → REVERT NotEnoughProofs ✗

4. claimCredit():
   - L601: expectedResolution != type(uint64).max → true
   - L602: resolvedAt == 0 → REVERT GameNotResolved ✗

5. verifyProposalProof():
   - L412: gameOver() == true → REVERT GameOver ✗

   ALL PATHS BLOCKED. Bond permanently locked.
```

**Note:** The existing test suite at [`BaseTest.t.sol#L40`](https://github.com/base-org/contracts/blob/27731f5/test/multiproof/BaseTest.t.sol#L40) hardcodes `PROOF_THRESHOLD=1`, so this code path was never tested.

## Impact Explanation

**High** — This is a permanent, irreversible loss of user funds (bond ETH) with no admin recovery mechanism.

- **Direct fund loss:** Bond ETH deposited during game creation is permanently irrecoverable in `DELAYED_WETH`
- **No admin recovery:** There is no emergency withdrawal, admin override, or governance mechanism to unlock the bond
- **Irreversible:** All four recovery paths (resolve, claimCredit normal, claimCredit fallback, add proof) are simultaneously and permanently blocked
- **Scope:** Affects all games deployed with `PROOF_THRESHOLD=2`, which is a valid configuration explicitly allowed by the [constructor](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L276)

## Likelihood Explanation

**High** — Parent game invalidation is a **normal operational event**, not an edge case:

- The Guardian is expected to blacklist invalid games as part of standard security operations
- Games can resolve as `CHALLENGER_WINS` through the normal dispute process
- With `PROOF_THRESHOLD=2`, any child game that has only 1 proof (the normal state after initialization) when its parent is invalidated will have its bond permanently locked
- The multiproof system is specifically designed to support threshold=2 (TEE + ZK) — this is not a misconfiguration but the intended dual-proof mode
- The timing window between initialization (1 proof) and ZK proof submission is the entire 7-day finalization period — any parent invalidation during this window triggers the bug

## Proof of Concept

Save as `test/multiproof/BondLockPoC.t.sol` and run with:
```bash
forge test --match-contract BondLockPoC -vvv
```

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { BaseTest } from "./BaseTest.t.sol";
import { AggregateVerifier } from "src/multiproof/AggregateVerifier.sol";
import { Claim, GameStatus, GameType, Hash, Proposal, Timestamp } from "src/dispute/lib/Types.sol";
import { IDisputeGame } from "interfaces/dispute/IDisputeGame.sol";

/// @title BondLockPoC
/// @notice Proof of Concept: bonds permanently locked when PROOF_THRESHOLD=2
///         and parent game invalidated. Three tests demonstrate:
///         1. resolve() reverts with NotEnoughProofs
///         2. 14-day fallback is also blocked
///         3. Control test with threshold=1 works correctly
contract BondLockPoC is BaseTest {

    /// @notice Override to deploy with PROOF_THRESHOLD=2
    function _deployAndSetAggregateVerifier() internal override {
        AggregateVerifier impl = new AggregateVerifier({
            anchorStateRegistry: anchorStateRegistry,
            delayedWETH: delayedWETH,
            disputeGameFactory: factory,
            gameType: AGGREGATE_VERIFIER_GAME_TYPE,
            teeVerifier: teeVerifier,
            zkVerifier: zkVerifier,
            blockInterval: BLOCK_INTERVAL,
            intermediateBlockInterval: INTERMEDIATE_BLOCK_INTERVAL,
            l2ChainId: L2_CHAIN_ID,
            proofThreshold: 2  // THE KEY: threshold requires 2 proofs
        });
        factory.setImplementation(AGGREGATE_VERIFIER_GAME_TYPE, impl);
    }

    /// @notice TEST 1: Bond locked when parent invalidated with PROOF_THRESHOLD=2
    function test_bondPermanentlyLockedWhenParentInvalidated() public {
        // Create parent game with 1 proof
        (AggregateVerifier parentGame,) = _createGameWithProof(TEE_PROVER);

        // Create child game with 1 proof (normal initialization flow)
        (AggregateVerifier childGame,) = _createChildGameWithProof(parentGame, TEE_PROVER);

        // Verify initial state
        assertEq(childGame.proofCount(), 1, "Child should have exactly 1 proof after init");
        assertEq(childGame.resolvedAt().raw(), 0, "Should not be resolved yet");

        // Guardian blacklists parent game
        anchorStateRegistry.blacklistDisputeGame(IDisputeGame(address(parentGame)));

        // Wait for child game to be over (7 days)
        vm.warp(block.timestamp + 7 days + 1);
        assertTrue(childGame.gameOver(), "Child game should be over");

        // resolve() REVERTS — proofCount(1) < PROOF_THRESHOLD(2)
        vm.expectRevert(abi.encodeWithSignature("NotEnoughProofs()"));
        childGame.resolve();

        // claimCredit() ALSO REVERTS — resolvedAt == 0
        vm.expectRevert(abi.encodeWithSignature("GameNotResolved()"));
        childGame.claimCredit();

        // BOND IS PERMANENTLY LOCKED — no function can recover it
        assertEq(childGame.resolvedAt().raw(), 0, "Game is permanently unresolvable");
    }

    /// @notice TEST 2: Even after 14 days, the fallback path is blocked
    function test_fourteenDayFallbackBlocked() public {
        (AggregateVerifier parentGame,) = _createGameWithProof(TEE_PROVER);
        (AggregateVerifier childGame,) = _createChildGameWithProof(parentGame, TEE_PROVER);

        anchorStateRegistry.blacklistDisputeGame(IDisputeGame(address(parentGame)));

        // Wait 15 days (beyond the 14-day fallback)
        vm.warp(block.timestamp + 15 days);

        // resolve() still reverts
        vm.expectRevert(abi.encodeWithSignature("NotEnoughProofs()"));
        childGame.resolve();

        // claimCredit() still reverts because:
        // expectedResolution = initTime + 7 days (NOT type(uint64).max)
        // So it takes Path A which requires resolvedAt != 0
        vm.expectRevert(abi.encodeWithSignature("GameNotResolved()"));
        childGame.claimCredit();
    }

    /// @notice TEST 3: Control — with PROOF_THRESHOLD=1, resolution works correctly
    function test_controlThreshold1ResolvesCorrectly() public {
        // Redeploy with threshold=1
        AggregateVerifier impl = new AggregateVerifier({
            anchorStateRegistry: anchorStateRegistry,
            delayedWETH: delayedWETH,
            disputeGameFactory: factory,
            gameType: AGGREGATE_VERIFIER_GAME_TYPE,
            teeVerifier: teeVerifier,
            zkVerifier: zkVerifier,
            blockInterval: BLOCK_INTERVAL,
            intermediateBlockInterval: INTERMEDIATE_BLOCK_INTERVAL,
            l2ChainId: L2_CHAIN_ID,
            proofThreshold: 1  // Control: threshold=1
        });
        factory.setImplementation(AGGREGATE_VERIFIER_GAME_TYPE, impl);

        (AggregateVerifier parentGame,) = _createGameWithProof(TEE_PROVER);
        (AggregateVerifier childGame,) = _createChildGameWithProof(parentGame, TEE_PROVER);

        anchorStateRegistry.blacklistDisputeGame(IDisputeGame(address(parentGame)));

        vm.warp(block.timestamp + 7 days + 1);

        // With threshold=1, resolve() SUCCEEDS
        GameStatus result = childGame.resolve();
        assertEq(uint8(result), uint8(GameStatus.CHALLENGER_WINS));
        assertTrue(childGame.resolvedAt().raw() != 0, "Game should be resolved");
    }

    // ========== HELPERS ==========

    function _createGameWithProof(address prover)
        internal
        returns (AggregateVerifier game, Claim rootClaim)
    {
        currentL2BlockNumber += BLOCK_INTERVAL;
        rootClaim = Claim.wrap(keccak256(abi.encode(currentL2BlockNumber)));

        Proposal memory startingAnchor =
            anchorStateRegistry.getAnchorRoot(AGGREGATE_VERIFIER_GAME_TYPE);

        bytes memory proof = _buildMockProof(
            startingAnchor.outputRoot.raw(),
            startingAnchor.l2BlockNumber,
            rootClaim.raw(),
            currentL2BlockNumber
        );

        bytes memory initData = abi.encodePacked(uint32(0), proof);

        vm.deal(prover, INIT_BOND);
        vm.prank(prover);
        game = AggregateVerifier(
            address(
                factory.createWithInitData{ value: INIT_BOND }(
                    AGGREGATE_VERIFIER_GAME_TYPE,
                    rootClaim,
                    abi.encode(currentL2BlockNumber, _mockIntermediateRoots()),
                    initData
                )
            )
        );
    }

    function _createChildGameWithProof(AggregateVerifier parentGame, address prover)
        internal
        returns (AggregateVerifier game, Claim rootClaim)
    {
        currentL2BlockNumber += BLOCK_INTERVAL;
        rootClaim = Claim.wrap(keccak256(abi.encode(currentL2BlockNumber)));

        uint256 parentIndex = factory.gameCount() - 1;

        bytes memory proof = _buildMockProof(
            parentGame.rootClaim().raw(),
            parentGame.l2SequenceNumber(),
            rootClaim.raw(),
            currentL2BlockNumber
        );

        bytes memory initData = abi.encodePacked(uint32(parentIndex), proof);

        vm.deal(prover, INIT_BOND);
        vm.prank(prover);
        game = AggregateVerifier(
            address(
                factory.createWithInitData{ value: INIT_BOND }(
                    AGGREGATE_VERIFIER_GAME_TYPE,
                    rootClaim,
                    abi.encode(currentL2BlockNumber, _mockIntermediateRoots()),
                    initData
                )
            )
        );
    }

    function _buildMockProof(
        bytes32 startRoot,
        uint256 startBlock,
        bytes32 endRoot,
        uint256 endBlock
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(0), // ProofType.TEE
            bytes32(0), // l1OriginHash (mock)
            bytes32(0), // l1OriginNumber (mock)
            startRoot,
            startBlock,
            endRoot,
            endBlock
        );
    }

    function _mockIntermediateRoots() internal pure returns (bytes32[] memory) {
        bytes32[] memory roots = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            roots[i] = keccak256(abi.encode("intermediate", i));
        }
        return roots;
    }
}
```

## Recommendation

Move the `proofCount < PROOF_THRESHOLD` check inside the `else` branch. When a parent game is invalidated, the child should resolve as `CHALLENGER_WINS` regardless of how many proofs it has — the game is being marked invalid due to its parent, not due to insufficient proofs:

```diff
     if (parentGameStatus == GameStatus.CHALLENGER_WINS) {
         status = GameStatus.CHALLENGER_WINS;
     } else {
         if (!gameOver()) revert GameNotOver();
+        if (proofCount < PROOF_THRESHOLD) revert NotEnoughProofs();
         status = isChallenged ? GameStatus.CHALLENGER_WINS : GameStatus.DEFENDER_WINS;
     }

-    if (proofCount < PROOF_THRESHOLD) revert NotEnoughProofs();
```

This is a 1-line move that preserves the proof threshold enforcement for the normal resolution path while allowing parent-invalidated games to resolve correctly and return bonds.

## Deployment Note

The AggregateVerifier multiproof system is currently deployed on Sepolia testnet (chain 11155111) and is **not yet on Ethereum mainnet**. The `DisputeGameFactory` on mainnet does not have game type 621 registered. This report is submitted proactively to prevent the bug from reaching production. Per the program rules: "At its sole discretion, Coinbase can decide to award a bounty for a contract that is not in scope of the program if it finds the reported vulnerability to be valuable."

## References

- **Repository:** [base-org/contracts](https://github.com/base-org/contracts) (branch: master, commit: `27731f5`)
- **Vulnerable line:** [`AggregateVerifier.sol#L453`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L453) — `if (proofCount < PROOF_THRESHOLD) revert NotEnoughProofs();`
- **`resolve()` function:** [`L432-L464`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L432-L464)
- **`claimCredit()` function:** [`L594-L622`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L594-L622)
- **`_decreaseExpectedResolution()`:** [`L761-L777`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L761-L777)
- **`verifyProposalProof()` gameOver check:** [`L412`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L412)
- **`PROOF_THRESHOLD` validation:** [`L276`](https://github.com/base-org/contracts/blob/27731f5/src/multiproof/AggregateVerifier.sol#L276)
- **Test gap:** [`BaseTest.t.sol#L40`](https://github.com/base-org/contracts/blob/27731f5/test/multiproof/BaseTest.t.sol#L40) — hardcodes `PROOF_THRESHOLD=1`, never tests threshold=2
