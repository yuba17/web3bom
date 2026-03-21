# ChainlinkOEVMorphoWrapper missing nonReentrant modifier, inconsistent with sibling contracts

## Summary

`ChainlinkOEVMorphoWrapper.updatePriceEarlyAndLiquidate()` lacks the `nonReentrant` modifier that both `ChainlinkOEVWrapper` and `ChainlinkCompositeOEVWrapper` apply to the same function. The contract does not inherit `ReentrancyGuard` at all, despite performing multiple external calls including token transfers and Morpho Blue liquidation.

## Vulnerability Detail

The three OEV wrapper contracts share the same pattern but differ in reentrancy protection:

**ChainlinkOEVWrapper.sol** — Protected:
```solidity
contract ChainlinkOEVWrapper is Ownable, AggregatorV3Interface, ReentrancyGuard {
    function updatePriceEarlyAndLiquidate(...) external nonReentrant { ... }
}
```

**ChainlinkCompositeOEVWrapper.sol** — Protected:
```solidity
contract ChainlinkCompositeOEVWrapper is Ownable, AggregatorV3Interface, ReentrancyGuard {
    function updatePriceEarlyAndLiquidate(...) external nonReentrant { ... }
}
```

**ChainlinkOEVMorphoWrapper.sol** — NOT Protected:
```solidity
contract ChainlinkOEVMorphoWrapper is OwnableUpgradeable, AggregatorV3Interface {
    // Does NOT inherit ReentrancyGuard
    function updatePriceEarlyAndLiquidate(...) external { // NO nonReentrant
        ...
        IERC20(marketParams.loanToken).safeTransferFrom(...);  // external call 1
        morphoBlue.liquidate(...);                              // external call 2
        loanToken.transfer(msg.sender, ...);                   // external call 3
        EIP20Interface(marketParams.collateralToken).transfer(msg.sender, ...); // external call 4
        EIP20Interface(marketParams.collateralToken).transfer(feeRecipient, ...); // external call 5
    }
}
```

The function performs 5+ external calls. If any token involved has transfer hooks (ERC-777, fee-on-transfer tokens with callbacks, or non-standard tokens), the caller could reenter.

## Impact

- Reentrancy via token callbacks during `updatePriceEarlyAndLiquidate` in Morpho Blue markets
- The `cachedRoundId` has already been updated before the external calls, so price state is committed — but the fee distribution logic could be reentered
- This is a defense-in-depth violation that the team clearly intended to protect against (they added it to the other two wrappers)

## Recommended Mitigation

Add `ReentrancyGuardUpgradeable` (since the contract uses upgradeable pattern):

```solidity
import {ReentrancyGuardUpgradeable} from "@openzeppelin-contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

contract ChainlinkOEVMorphoWrapper is OwnableUpgradeable, AggregatorV3Interface, ReentrancyGuardUpgradeable {

    function initializeV2(...) external reinitializer(2) {
        ...
        __ReentrancyGuard_init();
    }

    function updatePriceEarlyAndLiquidate(...) external nonReentrant {
        ...
    }
}
```
