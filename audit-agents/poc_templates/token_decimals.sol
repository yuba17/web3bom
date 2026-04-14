// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/// @notice Token decimals edge case template — deploy tokens with specific decimals (6, 8, 18)
abstract contract TokenDecimalsSetup is Test {
    address attacker = makeAddr("attacker");

    // Deploy mock ERC20 with specific decimals
    function _deployToken(string memory name, uint8 decimals) internal returns (address) {
        MockERC20 token = new MockERC20(name, name, decimals);
        return address(token);
    }

    // Common decimal combinations that expose bugs
    function _testDecimalPair(uint8 decimals0, uint8 decimals1) internal virtual;

    // Standard test matrix
    function _runDecimalMatrix() internal {
        uint8[4] memory decimals = [uint8(6), 8, 18, 24];
        for (uint i = 0; i < decimals.length; i++) {
            for (uint j = i; j < decimals.length; j++) {
                _testDecimalPair(decimals[i], decimals[j]);
            }
        }
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}
