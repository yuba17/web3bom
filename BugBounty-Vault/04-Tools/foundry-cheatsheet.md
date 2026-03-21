---
tags: [tools, foundry]
---

# Foundry Cheatsheet

## Installation
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Core Commands
```bash
# Compile
forge build

# Test
forge test                          # run all tests
forge test -vvvv                    # max verbosity (traces)
forge test --match-test testExploit # run specific test
forge test --gas-report             # gas usage report

# Fuzz Testing
forge test --fuzz-runs 10000        # increase fuzz iterations

# Fork Testing (test against live mainnet state)
forge test --fork-url $ETH_RPC_URL
forge test --fork-url $ETH_RPC_URL --fork-block-number 18000000

# Deploy
forge create src/Contract.sol:Contract --rpc-url $RPC --private-key $PK

# Verify
forge verify-contract <address> src/Contract.sol:Contract --etherscan-api-key $KEY

# Cast (interact with chain)
cast call <address> "balanceOf(address)" <wallet> --rpc-url $RPC
cast send <address> "transfer(address,uint256)" <to> <amount> --rpc-url $RPC --private-key $PK
cast storage <address> <slot> --rpc-url $RPC
cast block latest --rpc-url $RPC
cast tx <txhash> --rpc-url $RPC
cast decode-error <data>                 # decode revert data
```

## Writing PoC Exploits
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

interface ITarget {
    function deposit() external payable;
    function withdraw(uint256) external;
}

contract ExploitTest is Test {
    ITarget target;

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", 18000000);
        target = ITarget(0x...);
    }

    function testExploit() public {
        // Fund attacker
        vm.deal(address(this), 100 ether);

        // Execute attack
        target.deposit{value: 1 ether}();
        target.withdraw(10 ether); // exploit

        // Verify profit
        assertGt(address(this).balance, 100 ether);
    }
}
```

## Useful Cheatcodes
```solidity
vm.prank(address)          // next call as address
vm.startPrank(address)     // all calls as address
vm.deal(address, amount)   // set ETH balance
vm.warp(timestamp)         // set block.timestamp
vm.roll(blockNumber)       // set block.number
vm.expectRevert()          // expect next call to revert
vm.expectEmit()            // expect event emission
deal(token, who, amount)   // set ERC20 balance (forge-std)
```

## Invariant Testing
```solidity
contract InvariantTest is Test {
    function setUp() public {
        targetContract(address(vault));
    }

    function invariant_totalAssets() public {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
}
```
