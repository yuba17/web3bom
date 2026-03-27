# WildcardHunter — Dispatcher Analysis

## Tu Identidad
Eres el **WildcardHunter** del equipo de bug hunting de pancakeswap-infinity.
Tu especialidad: **Novel bugs, unconventional vectors, assumption violations, composability risks**

## Tu Objetivo
Analizar `Dispatcher` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/pancakeswap/infinity-universal-router/src/base/Dispatcher.sol`
**Dominio**: dex


```solidity
// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {V2SwapRouter} from "../modules/pancakeswap/v2/V2SwapRouter.sol";
import {V3SwapRouter} from "../modules/pancakeswap/v3/V3SwapRouter.sol";
import {InfinitySwapRouter} from "../modules/pancakeswap/infinity/InfinitySwapRouter.sol";
import {StableSwapRouter} from "../modules/pancakeswap/StableSwapRouter.sol";
import {Payments} from "../modules/Payments.sol";
import {RouterImmutables} from "../base/RouterImmutables.sol";
import {V3ToInfinityMigrator} from "../modules/V3ToInfinityMigrator.sol";
import {BytesLib} from "../libraries/BytesLib.sol";
import {Commands} from "../libraries/Commands.sol";
import {Lock} from "./Lock.sol";
import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {IAllowanceTransfer} from "permit2/src/interfaces/IAllowanceTransfer.sol";
import {ActionConstants} from "infinity-periphery/src/libraries/ActionConstants.sol";
import {BaseActionsRouter} from "infinity-periphery/src/base/BaseActionsRouter.sol";
import {CalldataDecoder} from "infinity-periphery/src/libraries/CalldataDecoder.sol";
import {PoolKey} from "infinity-core/src/types/PoolKey.sol";
import {ICLPoolManager} from "infinity-core/src/pool-cl/interfaces/ICLPoolManager.sol";
import {IBinPoolManager} from "infinity-core/src/pool-bin/interfaces/IBinPoolManager.sol";

/// @title Decodes and Executes Commands
/// @notice Called by the UniversalRouter contract to efficiently decode and execute a singular command
abstract contract Dispatcher is
    Payments,
    V2SwapRouter,
    V3SwapRouter,
    StableSwapRouter,
    InfinitySwapRouter,
    V3ToInfinityMigrator,
    Lock
{
    using BytesLib for bytes;
    using CalldataDecoder for bytes;

    error InvalidCommandType(uint256 commandType);
    error BalanceTooLow();

    /// @notice Executes encoded commands along with provided inputs.
    /// @param commands A set of concatenated commands, each 1 byte in length
    /// @param inputs An array of byte strings containing abi encoded inputs for each command
    function execute(bytes calldata commands, bytes[] calldata inputs) external payable virtual;

    /// @notice Public view function to be used instead of msg.sender, as the contract performs self-reentrancy and at
    /// times msg.sender == address(this). Instead msgSender() returns the initiator of the lock
    function msgSender() public view override(BaseActionsRouter) returns (address) {
        return _getLocker();
    }

    /// @notice Decodes and executes the given command with the given inputs
    /// @param commandType The command type to execute
    /// @param inputs The inputs to execute the command with
    /// @dev inputs must be ABI encoded using abi.encode() to ensure proper padding. WARNING: Direct calldata
    //       manipulation or abi.encodePacked() can result in incorrect data reads.
    /// @dev 2 masks are used to enable use of a nested-if statement in execution for efficiency reasons
    /// @return success True on success of the command, false on failure
    /// @return output The outputs or error messages, if any, from the command
    function dispatch(bytes1 commandType, bytes calldata inputs) internal returns (bool success, bytes memory output) {
        uint256 command = uint8(commandType & Commands.COMMAND_TYPE_MASK);

        success = true;

        // 0x00 <= command < 0x21
        if (command < Commands.EXECUTE_SUB_PLAN) {
            // 0x00 <= command < 0x10
            if (command < Commands.INFI_SWAP) {
                // 0x00 <= command < 0x08
                if (command < Commands.V2_SWAP_EXACT_IN) {
                    if (command == Commands.V3_SWAP_EXACT_IN) {
                        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
                        address recipient;
                        uint256 amountIn;
                        uint256 amountOutMin;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountIn := calldataload(add(inputs.offset, 0x20))
                            amountOutMin := calldataload(add(inputs.offset, 0x40))
                            // 0x60 offset is the path, decoded below
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        bytes calldata path = inputs.toBytes(3);
                        address payer = payerIsUser ? msgSender() : address(this);
                        v3SwapExactInput(map(recipient), amountIn, amountOutMin, path, payer);
                        return (success, output);
                    } else if (command == Commands.V3_SWAP_EXACT_OUT) {
                        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
                        address recipient;
                        uint256 amountOut;
                        uint256 amountInMax;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountOut := calldataload(add(inputs.offset, 0x20))
                            amountInMax := calldataload(add(inputs.offset, 0x40))
                            // 0x60 offset is the path, decoded below
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        bytes calldata path = inputs.toBytes(3);
                        address payer = payerIsUser ? msgSender() : address(this);
                        v3SwapExactOutput(map(recipient), amountOut, amountInMax, path, payer);
                        return (success, output);
                    } else if (command == Commands.PERMIT2_TRANSFER_FROM) {
                        // equivalent: abi.decode(inputs, (address, address, uint160))
                        address token;
                        address recipient;
                        uint160 amount;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            amount := calldataload(add(inputs.offset, 0x40))
                        }
                        permit2TransferFrom(token, msgSender(), map(recipient), amount);
                        return (success, output);
                    } else if (command == Commands.PERMIT2_PERMIT_BATCH) {
                        IAllowanceTransfer.PermitBatch calldata permitBatch;
                        assembly {
                            // this is a variable length struct, so calldataload(inputs.offset) contains the
                            // offset from inputs.offset at which the struct begins
                            permitBatch := add(inputs.offset, calldataload(inputs.offset))
                        }
                        bytes calldata data = inputs.toBytes(1);
                        (success, output) = address(PERMIT2).call(
                            abi.encodeWithSignature(
                                "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)",
                                msgSender(),
                                permitBatch,
                                data
                            )
                        );
                        return (success, output);
                    } else if (command == Commands.SWEEP) {
                        // equivalent:  abi.decode(inputs, (address, address, uint256))
                        address token;
                        address recipient;
                        uint160 amountMin;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            amountMin := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.sweep(token, map(recipient), amountMin);
                        return (success, output);
                    } else if (command == Commands.TRANSFER) {
                        // equivalent:  abi.decode(inputs, (address, address, uint256))
                        address token;
                        address recipient;
                        uint256 value;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            value := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.pay(token, map(recipient), value);
                        return (success, output);
                    } else if (command == Commands.PAY_PORTION) {
                        // equivalent:  abi.decode(inputs, (address, address, uint256))
                        address token;
                        address recipient;
                        uint256 bips;
                        assembly {
                            token := calldataload(inputs.offset)
                            recipient := calldataload(add(inputs.offset, 0x20))
                            bips := calldataload(add(inputs.offset, 0x40))
                        }
                        Payments.payPortion(token, map(recipient), bips);
                        return (success, output);
                    } else {
                        // placeholder area for command 0x07
                        revert InvalidCommandType(command);
                    }
                } else {
                    // 0x08 <= command < 0x10
                    if (command == Commands.V2_SWAP_EXACT_IN) {
                        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
                        address recipient;
                        uint256 amountIn;
                        uint256 amountOutMin;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountIn := calldataload(add(inputs.offset, 0x20))
                            amountOutMin := calldataload(add(inputs.offset, 0x40))
                            // 0x60 offset is the path, decoded below
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        address[] calldata path = inputs.toAddressArray(3);
                        address payer = payerIsUser ? msgSender() : address(this);
                        v2SwapExactInput(map(recipient), amountIn, amountOutMin, path, payer);
                        return (success, output);
                    } else if (command == Commands.V2_SWAP_EXACT_OUT) {
                        // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bool))
                        address recipient;
                        uint256 amountOut;
                        uint256 amountInMax;
                        bool payerIsUser;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountOut := calldataload(add(inputs.offset, 0x20))
                            amountInMax := calldataload(add(inputs.offset, 0x40))
                            // 0x60 offset is the path, decoded below
                            payerIsUser := calldataload(add(inputs.offset, 0x80))
                        }
                        address[] calldata path = inputs.toAddressArray(3);
                        address payer = payerIsUser ? msgSender() : address(this);
                        v2SwapExactOutput(map(recipient), amountOut, amountInMax, path, payer);
                        return (success, output);
                    } else if (command == Commands.PERMIT2_PERMIT) {
                        // equivalent: abi.decode(inputs, (IAllowanceTransfer.PermitSingle, bytes))
                        IAllowanceTransfer.PermitSingle calldata permitSingle;
                        assembly {
                            permitSingle := inputs.offset
                        }
                        bytes calldata data = inputs.toBytes(6); // PermitSingle takes first 6 slots (0..5)
                        (success, output) = address(PERMIT2).call(
                            abi.encodeWithSignature(
                                "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
                                msgSender(),
                                permitSingle,
                                data
                            )
                        );
                        return (success, output);
                    } else if (command == Commands.WRAP_ETH) {
                        // equivalent: abi.decode(inputs, (address, uint256))
                        address recipient;
                        uint256 amount;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amount := calldataload(add(inputs.offset, 0x20))
                        }
                        Payments.wrapETH(map(recipient), amount);
                        return (success, output);
                    } else if (command == Commands.UNWRAP_WETH) {
                        // equivalent: abi.decode(inputs, (address, uint256))
                        address recipient;
                        uint256 amountMin;
                        assembly {
                            recipient := calldataload(inputs.offset)
                            amountMin := calldataload(add(inputs.offset, 0x20))
                        }
                        Payments.unwrapWETH9(map(recipient), amountMin);
                        return (success, output);
                    } else if (command == Commands.PERMIT2_TRANSFER_FROM_BATCH) {
                        IAllowanceTransfer.AllowanceTransferDetails[] calldata batchDetails;
                        (uint256 length, uint256 offset) = inputs.toLengthOffset(0);
                        assembly {
                            batchDetails.length := length
                            batchDetails.offset := offset
                        }
                        permit2TransferFrom(batchDetails, msgSender());
                        return (success, output);
                    } else if (command == Commands.BALANCE_CHECK_ERC20) {
                        // equivalent: abi.decode(inputs, (address, address, uint256))
                        address owner;
                        address token;
                        uint256 minBalance;
                        assembly {
                            owner := calldataload(inputs.offset)
                            token := calldataload(add(inputs.offset, 0x20))
                            minBalance := calldataload(add(inputs.offset, 0x40))
                        }
                        success = (ERC20(token).balanceOf(owner) >= minBalance);
                        if (!success) output = abi.encodePacked(BalanceTooLow.selector);
                        return (success, output);
                    } else {
                        // placeholder area for command 0x0f
                        revert InvalidCommandType(command);
                    }
                }
            } else {
                // 0x10 <= command < 0x21
                if (command == Commands.INFI_SWAP) {
                    // pass the calldata provided to InfinitySwapRouter._executeActions (defined in BaseActionsRouter)
                    _executeActions(inputs);
                    return (success, output);
                    // This contract MUST be approved to spend the token since its going to be doing the call on the position manager
                } else if (command == Commands.V3_POSITION_MANAGER_PERMIT) {
                    _checkV3PermitCall(inputs);
                    (success, output) = address(V3_POSITION_MANAGER).call(inputs);
                    return (success, output);
                } else if (command == Commands.V3_POSITION_MANAGER_CALL) {
                    _checkV3PositionManagerCall(inputs, msgSender());
                    /// @dev ensure there's follow-up action if v3 position's removed token are sent to router contract
                    (success, output) = address(V3_POSITION_MANAGER).call(inputs);
                    return (success, output);
                } else if (command == Commands.INFI_CL_INITIALIZE_POOL) {
                    // equivalent: abi.decode(inputs, (PoolKey, uint160)) where PoolKey is
                    // (Currency currency0, Currency currency1, IHooks hooks, IPoolManager poolManager, uint24 fee, bytes32 parameters)
                    PoolKey calldata poolKey;
                    uint160 sqrtPriceX96;
                    assembly {
                        poolKey := inputs.offset
                        sqrtPriceX96 := calldataload(add(inputs.offset, 0xc0)) // poolKey has 6 variable, so it takes 192 space = 0xc0
                    }
                    (success, output) =
                        address(clPoolManager).call(abi.encodeCall(ICLPoolManager.initialize, (poolKey, sqrtPriceX96)));
                } else if (command == Commands.INFI_BIN_INITIALIZE_POOL) {
                    // equivalent: abi.decode(inputs, (PoolKey, uint24)) where PoolKey is
                    // (Currency currency0, Currency currency1, IHooks hooks, IPoolManager poolManager, uint24 fee, bytes32 parameters)
                    PoolKey calldata poolKey;
                    uint24 activeId;
                    assembly {
                        poolKey := inputs.offset
                        activeId := calldataload(add(inputs.offset, 0xc0)) // poolKey has 6 variable, so it takes 192 space = 0xc0
                    }
                    (success, output) =
                        address(binPoolManager).call(abi.encodeCall(IBinPoolManager.initialize, (poolKey, activeId)));
                } else if (command == Commands.INFI_CL_POSITION_CALL) {
                    _checkInfiClPositionManagerCall(inputs);
                    (success, output) = address(INFI_CL_POSITION_MANAGER).call{value: address(this).balance}(inputs);
                    return (success, output);
                } else if (command == Commands.INFI_BIN_POSITION_CALL) {
                    _checkInfiBinPositionManagerCall(inputs);
                    (success, output) = address(INFI_BIN_POSITION_MANAGER).call{value: address(this).balance}(inputs);
                    return (success, output);
                } else {
                    // placeholder area for commands 0x15-0x20
                    revert InvalidCommandType(command);
                }
            }
        } else {
            // 0x21 <= command
            if (command == Commands.EXECUTE_SUB_PLAN) {
                (bytes calldata _commands, bytes[] calldata _inputs) = inputs.decodeCommandsAndInputs();
                (success, output) = (address(this)).call(abi.encodeCall(Dispatcher.execute, (_commands, _inputs)));
                return (success, output);
            } else if (command == Commands.STABLE_SWAP_EXACT_IN) {
                // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bytes, bool))
                address recipient;
                uint256 amountIn;
                uint256 amountOutMin;
                bool payerIsUser;
                assembly {
                    recipient := calldataload(inputs.offset)
                    amountIn := calldataload(add(inputs.offset, 0x20))
                    amountOutMin := calldataload(add(inputs.offset, 0x40))
                    // 0x60 offset is the path and 0x80 is the flag, decoded below
                    payerIsUser := calldataload(add(inputs.offset, 0xa0))
                }
                address[] calldata path = inputs.toAddressArray(3);
                uint256[] calldata flag = inputs.toUintArray(4);
                address payer = payerIsUser ? msgSender() : address(this);
                stableSwapExactInput(map(recipient), amountIn, amountOutMin, path, flag, payer);
                return (success, output);
            } else if (command == Commands.STABLE_SWAP_EXACT_OUT) {
                // equivalent: abi.decode(inputs, (address, uint256, uint256, bytes, bytes, bool))
                address recipient;
                uint256 amountOut;
                uint256 amountInMax;
                bool payerIsUser;
                assembly {
                    recipient := calldataload(inputs.offset)
                    amountOut := calldataload(add(inputs.offset, 0x20))
                    amountInMax := calldataload(add(inputs.offset, 0x40))
                    // 0x60 offset is the path and 0x80 is the flag, decoded below
                    payerIsUser := calldataload(add(inputs.offset, 0xa0))
                }
                address[] calldata path = inputs.toAddressArray(3);
                uint256[] calldata flag = inputs.toUintArray(4);
                address payer = payerIsUser ? msgSender() : address(this);

                /// @dev structured this way as stack too deep by Yul
                uint256 amountIn = stableSwapExactOutputAmountIn(amountOut, amountInMax, path, flag);
                stableSwapExactOutput(map(recipient), amountIn, amountOut, path, flag, payer);
                return (success, output);
            } else {
                // placeholder area for commands 0x24-0x3f
                revert InvalidCommandType(command);
            }
        }
    }

    /// @notice Calculates the recipient address for a command
    /// @param recipient The recipient or recipient-flag for the command
    /// @return output The resultant recipient for the command
    function map(address recipient) internal view returns (address) {
        if (recipient == ActionConstants.MSG_SENDER) {
            return msgSender();
        } else if (recipient == ActionConstants.ADDRESS_THIS) {
            return address(this);
        } else {
            return recipient;
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Dispatcher
Buscando 'Dispatcher' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (33ms)

 1. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` — Nucleus_2024-12-14
 2. [LOW] Race condition in dispatch.Subscribe can crash the node during startup / restart — Berachain Beaconkit
 3. [LOW] ThresholdsVeriﬁer is initialized using the compiler contract instead of the comp — Arkis DeFi Prime Brokerage Protocol
 4. [LOW] Race condition in broker.Broker results in panic — Berachain Beaconkit
 5. [GAS] Re-order high usage function to top of dispatch order  — Omni X

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Dispatcher | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [MEDIUM] [M-03] Custom hook not applied in `_bridge()` and `_quote()` (Nucleus_2024-12-14)
   ## Severity

**Impact:** High

**Likelihood:** Low

## Description

The `_bridge()` and `_quote()` in the `MultiChainHyperlaneTellerWithMultiAssetSupp...

2. [LOW] Race condition in dispatch.Subscribe can crash the node during startup / restart (Berachain Beaconkit)
   ## Severity: Low Risk

## Context
File: `mod/async/pkg/dispatcher/dispatcher.go#L71`

Subscribe on broker will access map subscriptions.  
```go
b.sub...

3. [LOW] ThresholdsVeriﬁer is initialized using the compiler contract instead of the compliance contract (Arkis DeFi Prime Brokerage Protocol)
   ## Diﬃculty: Low

## Type: Data Validation

## Description
The `ThresholdsVerifier` contract constructor accepts an address for the compliance contrac...

4. [LOW] Race condition in broker.Broker results in panic (Berachain Beaconkit)
   ## Severity: Low Risk

## Context
`mod/async/pkg/broker/broker.go#L127-L133`

## Description
The `broker.Broker` struct includes the following map: `s...

5. [GAS] Re-order high usage function to top of dispatch order  (Omni X)
   ## OmniXMultisender.sol#L92-L100

## Description
Functions expected to be the most called within a contract should ideally be put at the top of the fu...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio dex
Buscando 'Dispatcher' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (68ms)

### Cross-domain HIGH relevantes
Buscando 'Dispatcher' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (2ms)
 1. [HIGH] Proxy has public methods that shadow implementation — NuCypher
 2. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, resul — RealWagmi
 3. [HIGH] Issue with Fee Payment During Interchain Callback — DIA
 4. [HIGH] Permission in method description doesn't match implementation — Basilisk
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Dispatcher | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:
1. [HIGH] Proxy has public methods that shadow implementation (NuCypher)
   ## Auditing and Logging Report
## Type: 
Auditing and Logging
## Target: 
- Issuer.sol
- MinersEscrow.sol
- MiningAdjucator.sol
## Difficulty: 
Low...
2. [HIGH] H-5: The `_estimateWithdrawalLp` function might return a very large value, result in users losing significant incentives or being unable to withdraw from the Dispatcher contract (RealWagmi)
   Source: https://github.com/sherlock-audit/2023-06-real-wagmi-judging/issues/142 
## Found by 
crimson-rat-reach, duc, qpzm
## Summary
The `_estimateW...
3. [HIGH] Issue with Fee Payment During Interchain Callback (DIA)
   ##### Description
In the `OracleRequestRecipient.handle()` function the `msg.value` parameter is missing [in the call](https://github.com/diadata-org/...
4. [HIGH] Permission in method description doesn't match implementation (Basilisk)
   **Occurs**:
B

## Briefing del Dominio (dex)
### Briefing principal: dex
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Constant Product Invariant Violation
### 1.2 LP Token Mint/Burn Ratio Desync
### 1.3 Price Impact Manipulation (Thin Liquidity)
### 1.4 Sandwich Attack Amplification
### 1.5 TWAP Oracle Manipulation
### 1.6 Concentrated Liquidity Tick Boundary Errors
### 1.7 Swap Deadline Missing
### 1.8 Slippage Protection Bypass
### 2.1 Flash Loan + AMM State Manipulation
### 2.2 Fee Accounting Mismatch

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Fees intentionally reduce output — k must increase by fee amount, not stay flat
  ⚠ Virtual reserves in concentrated liquidity mean k is per-range, not global
  ⚠ Rebasing tokens break the invariant naturally — pool must handle rebase
  ⚠ UniV2 MINIMUM_LIQUIDITY (1000 wei) prevents first-depositor attack
  ⚠ Fee-on-transfer tokens cause natural desync — protocol must use actual received amounts
  ⚠ Imbalanced deposits in multi-asset pools intentionally cost more (swap fee applies)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate for spot reads
  ⚠ TWAP with short window (< 10 min) is still manipulable across multiple blocks
  ⚠ Chainlink with proper staleness checks is generally safe
  ⚠ Private mempools (Flashbots) partially mitigate but do not eliminate risk
  ⚠ Protocols computing slippage from oracle price internally may be acceptable
  ⚠ L2s with sequencer ordering have reduced but nonzero sandwich risk

## CHECKLIST DE INVARIANTES
| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| DEX-INV-001 | k_after >= k_before for every swap | 1 | constant product |
| DEX-INV-002 | LP mint-then-burn returns <= deposited | 1 | share math |
| DEX-INV-003 | reserve0 * reserve1 monotonically non-decreasing | 1 | core AMM |
| DEX-INV-004 | sum(LP balances) == LP totalSupply | 1 | token accounting |
| DEX-INV-005 | actual token balances >= internal reserves | 1 | INV-EXPLOIT-012 |
| DEX-INV-006 | amountOut >= amountOutMin (when set > 0) | 1 | INV-EXPLOIT-016 |
| DEX-INV-007 | spot price deviation from TWAP < MAX_PCT | 2 | INV-EXPLOIT-001 |
| DEX-INV-008 | fee deducted <= amount transacted | 1 | INV-EXPLOIT-008 |
| DEX-INV-009 | no profit from sandwich (attacker_out <= attacker_in) | 1 | COMP-MULTI-001 |
| DEX-INV-010 | active liquidity == sum(position liquidity in active range) | 1 | tick math |
**Tier 1** = hard fail = confirmed bug. **Tier 2** = needs review, may have tolerance.
---

## GREP TARGETS
```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp
swap(
getAmountOut
getAmountIn

## INCIDENTES REALES (protocolos afectados)
```yaml
- id: dex-incident-001
  name: "KyberSwap exploit"
  fecha: "2023-11"
  perdida: "$48M"
  causa_raiz: "Precision loss in concentrated liquidity tick boundary math"
  categoria: "Tick boundary error / precision loss"
  vector: "Attacker exploited precision loss at tick boundaries in KyberSwap's concentrated liquidity implementation to drain pools"
  leccion: "CRITICAL: Tick boundary math is the #1 attack surface for concentrated liquidity DEXes. See dex-006. Fuzz with swaps that land exactly on tick boundaries."
  verificado: true

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Novel bugs) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `D` (ej: D-01, D-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Dispatcher_WildcardHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: D-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "D-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Deadlock Analysis (OBLIGATORIO — después de tu búsqueda creativa)
Para cada safety check, margin, cap, o límite en el contrato:
1. ¿Puede BLOQUEAR una operación de emergencia? (repay, withdraw, liquidate, unstake)
2. ¿Hay un escenario donde el usuario NO PUEDE deshacer su posición?
3. ¿El safety mechanism puede dejar fondos permanentemente bloqueados?
4. ¿Un cap que protege al protocolo puede impedir que un usuario se salve de liquidación?

Bug real: Safety margin aplicado al cálculo de repago impedía que usuarios repagaran → liquidados sin poder hacer nada.
Busca: require/assert/if que revierten en funciones de salida (withdraw, repay, unstake, emergencyWithdraw).

## Composability Attack (samczsun — "Two Rights Make A Wrong")
Para cada interacción con un contrato externo:
1. ¿Qué ASUME este contrato sobre el comportamiento del otro?
2. ¿Bajo qué condiciones esa asunción se viola?
3. ¿Se puede crear un estado donde ambos contratos son internamente consistentes pero juntos son inseguros?
Bug real: SushiSwap MISO — msg.value reutilizado en loop de batch. Auction y batch handler eran seguros individualmente.

## "Reimplementa de Memoria" (cmichel — MENTALIDAD)
Después de leer el contrato, pregúntate: ¿podría reimplementar esto desde cero sin mirar el código?
Si tu versión mental DIFIERE del código real en algún punto → ese punto es un candidato a bug.
La gap entre "qué debería hacer" y "qué realmente hace" es donde viven los bugs novedosos.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
