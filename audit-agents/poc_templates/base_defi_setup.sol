// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Base DeFi PoC setup — deploy pool + tokens + oracle + initial liquidity
/// Replace {PLACEHOLDER} values with actual contract addresses/values
abstract contract BaseDeFiSetup is Test {
    // Actors
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    address admin = makeAddr("admin");

    // Common DeFi tokens (fork mode)
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address constant DAI  = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    // Override in concrete test
    function _deployProtocol() internal virtual;
    function _seedLiquidity() internal virtual;

    function setUp() public virtual {
        // Fork mainnet at recent block
        // vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        _deployProtocol();
        _seedLiquidity();

        // Fund actors
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }

    // Helpers
    function _fundERC20(address token, address to, uint256 amount) internal {
        deal(token, to, amount);
    }

    function _approveMax(address token, address owner, address spender) internal {
        vm.prank(owner);
        (bool ok,) = token.call(abi.encodeWithSignature("approve(address,uint256)", spender, type(uint256).max));
        require(ok, "approve failed");
    }
}
