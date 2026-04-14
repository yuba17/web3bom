// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Oracle manipulation PoC template — slot0 manipulation + TWAP bypass
abstract contract OracleManipulationSetup is Test {
    address attacker = makeAddr("attacker");

    // Uniswap V3 slot0 manipulation pattern
    function _manipulateSlot0(address pool, int24 targetTick) internal {
        // Large swap to move price to target tick
        // vm.prank(attacker);
        // router.exactInputSingle(ISwapRouter.ExactInputSingleParams({
        //     tokenIn: token0,
        //     tokenOut: token1,
        //     fee: 3000,
        //     recipient: attacker,
        //     deadline: block.timestamp,
        //     amountIn: LARGE_AMOUNT,
        //     amountOutMinimum: 0,
        //     sqrtPriceLimitX96: targetSqrtPrice
        // }));
    }

    // Chainlink oracle staleness exploit
    function _makeOracleStale(address oracle) internal {
        // Advance time past heartbeat
        vm.warp(block.timestamp + 3601); // > 1 hour heartbeat
    }

    // Flash loan + oracle read in same block
    function _flashLoanOracleAttack() internal virtual {
        // 1. Flash loan large amount
        // 2. Swap to manipulate spot price
        // 3. Call vulnerable function that reads spot price
        // 4. Swap back
        // 5. Repay flash loan
        // Profit = value extracted from protocol using manipulated price
    }
}
