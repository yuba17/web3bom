# MathHunter — Transfers Analysis

## Tu Identidad
Eres el **MathHunter** del equipo de bug hunting de commerce-payments.
Tu especialidad: **Overflow, rounding, precision, exchange rate math, share price manipulation**

## Tu Objetivo
Analizar `Transfers` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/commerce-payments/contracts/transfers/Transfers.sol`
**Dominio**: reentrancy


## Asset Flow Map
### Money IN (deposits/receives)
- L137 <top-level>: if (msg.value > neededAmount) {
- L138 <top-level>: revert InvalidNativeAmount(int256(msg.value - neededAmount));
- L139 <top-level>: } else if (msg.value < neededAmount) {
- L140 <top-level>: revert InvalidNativeAmount(-int256(neededAmount - msg.value));
- L160 transferNative(): if (msg.value > 0) {
- L165 transferNative(): succeedPayment(_intent, msg.value, NATIVE_CURRENCY, _msgSender());
- L252 transferTokenPreApproved(): erc20.safeTransferFrom(_msgSender(), address(this), neededAmount);
- L265 transferTokenPreApproved(): // @dev Wraps msg.value into wrapped token and transfers to recipient.
- L281 wrapAndTransfer(): if (msg.value > 0) {
- L283 wrapAndTransfer(): wrappedNativeCurrency.deposit{value: msg.value}();
- L289 wrapAndTransfer(): succeedPayment(_intent, msg.value, NATIVE_CURRENCY, _msgSender());
- L370 unwrapAndTransferPreApproved(): wrappedNativeCurrency.safeTransferFrom(_msgSender(), address(this), neededAmount);
- L405 swapAndTransferUniswapV3Native(): amountSwapped = swapTokens(_intent, address(wrappedNativeCurrency), msg.value, poolFeesTier);
- L491 swapAndTransferUniswapV3TokenPreApproved(): tokenIn.safeTransferFrom(_msgSender(), address(this), maxWillingToPay);
- L549 subsidizedTransferToken(): erc20.safeTransferFrom(_signatureTransferData.owner, address(this), neededAmount);
- L601 swapTokens(): if (msg.value > 0) {
- L602 swapTokens(): payerBalanceBefore = _msgSender().balance + msg.value;
- L617 swapTokens(): uniswap_inputs[0] = abi.encode(address(uniswap), msg.value);
- L667 swapTokens(): try uniswap.execute{value: msg.value}(uniswap_commands, uniswap_inputs, _intent.deadline) {
- L690 swapTokens(): if (msg.value > 0) {
- L811 receive(): accepts ETH via payable receive

### Money OUT (withdrawals/sends)
- L663 swapTokens(): IERC20(tokenIn).safeTransfer(address(uniswap), maxAmountWillingToPay);
- L731 transferFundsToDestinations(): requestedCurrency.safeTransfer(_intent.recipient, _intent.recipientAmount);
- L734 transferFundsToDestinations(): requestedCurrency.safeTransfer(feeDestinations[_intent.operator], _intent.feeAmount);
- L762 sendNative(): (bool success, bytes memory data) = payable(destination).call{value: amount}("");

### Balance Reads (manipulation vectors)
- L184 transferToken(): uint256 payerBalance = erc20.balanceOf(_msgSender());
- L199 transferToken(): uint256 balanceBefore = erc20.balanceOf(address(this));
- L236 transferTokenPreApproved(): uint256 payerBalance = erc20.balanceOf(_msgSender());
- L249 transferTokenPreApproved(): uint256 balanceBefore = erc20.balanceOf(address(this));
- L310 unwrapAndTransfer(): uint256 payerBalance = wrappedNativeCurrency.balanceOf(_msgSender());
- L357 unwrapAndTransferPreApproved(): uint256 payerBalance = wrappedNativeCurrency.balanceOf(_msgSender());
- L436 swapAndTransferUniswapV3Token(): uint256 balanceBefore = tokenIn.balanceOf(address(this));
- L472 swapAndTransferUniswapV3TokenPreApproved(): uint256 payerBalance = tokenIn.balanceOf(_msgSender());
- L488 swapAndTransferUniswapV3TokenPreApproved(): uint256 balanceBefore = tokenIn.balanceOf(address(this));
- L524 subsidizedTransferToken(): uint256 payerBalance = erc20.balanceOf(_signatureTransferData.owner);
- L546 subsidizedTransferToken(): uint256 balanceBefore = erc20.balanceOf(address(this));
- L603 swapTokens(): routerBalanceBefore = address(uniswap).balance + IERC20(wrappedNativeCurrency).balanceOf(address(uniswap));
- L604 swapTokens(): feeBalanceBefore = IERC20(tokenOut).balanceOf(feeDestinations[_intent.operator]);
- L605 swapTokens(): recipientBalanceBefore = IERC20(tokenOut).balanceOf(_intent.recipient);
- L626 swapTokens(): payerBalanceBefore = IERC20(tokenIn).balanceOf(_msgSender()) + maxAmountWillingToPay;
- L627 swapTokens(): routerBalanceBefore = IERC20(tokenIn).balanceOf(address(uniswap));
- L645 swapTokens(): feeBalanceBefore = IERC20(tokenOut).balanceOf(feeDestinations[_intent.operator]);
- L646 swapTokens(): recipientBalanceBefore = IERC20(tokenOut).balanceOf(_intent.recipient);
- L694 swapTokens(): IERC20(wrappedNativeCurrency).balanceOf(address(uniswap));
- L696 swapTokens(): payerBalanceAfter = IERC20(tokenIn).balanceOf(_msgSender());
- L697 swapTokens(): routerBalanceAfter = IERC20(tokenIn).balanceOf(address(uniswap));
- L774 revertIfInexactTransfer(): uint256 balanceAfter = token.balanceOf(target);
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@uniswap/universal-router/contracts/interfaces/IUniversalRouter.sol";
import {Commands as UniswapCommands} from "@uniswap/universal-router/contracts/libraries/Commands.sol";
import {Constants as UniswapConstants} from "@uniswap/universal-router/contracts/libraries/Constants.sol";
import "../interfaces/IWrappedNativeCurrency.sol";
import "../interfaces/ITransfers.sol";
import "../interfaces/IERC7597.sol";
import "../utils/Sweepable.sol";
import "../permit2/src/Permit2.sol";

// Uniswap error selectors, used to surface information when swaps fail
// Pulled from @uniswap/universal-router/out/V3SwapRouter.sol/V3SwapRouter.json after compiling with forge
bytes32 constant V3_INVALID_SWAP = keccak256(hex"316cf0eb");
bytes32 constant V3_TOO_LITTLE_RECEIVED = keccak256(hex"39d35496");
bytes32 constant V3_TOO_MUCH_REQUESTED = keccak256(hex"739dbe52");
bytes32 constant V3_INVALID_AMOUNT_OUT = keccak256(hex"d4e0248e");
bytes32 constant V3_INVALID_CALLER = keccak256(hex"32b13d91");

// @inheritdoc ITransfers
contract Transfers is Context, Ownable, Pausable, ReentrancyGuard, Sweepable, ITransfers {
    using SafeERC20 for IERC20;
    using SafeERC20 for IWrappedNativeCurrency;

    // @dev Map of operator addresses and fee destinations.
    mapping(address => address) private feeDestinations;

    // @dev Map of operator addresses to a map of transfer intent ids that have been processed
    mapping(address => mapping(bytes16 => bool)) private processedTransferIntents;

    // @dev Represents native token of a chain (e.g. ETH or MATIC)
    address private immutable NATIVE_CURRENCY = address(0);

    // @dev Uniswap on-chain contract
    IUniversalRouter private immutable uniswap;

    // @dev permit2 SignatureTransfer contract address. Used for tranferring tokens with a signature instead of a full transaction.
    // See: https://github.com/Uniswap/permit2
    Permit2 public immutable permit2;

    // @dev Canonical wrapped token for this chain. e.g. (wETH or wMATIC).
    IWrappedNativeCurrency private immutable wrappedNativeCurrency;

    // @param _uniswap The address of the Uniswap V3 swap router
    // @param _wrappedNativeCurrency The address of the wrapped token for this chain
    constructor(
        IUniversalRouter _uniswap,
        Permit2 _permit2,
        address _initialOperator,
        address _initialFeeDestination,
        IWrappedNativeCurrency _wrappedNativeCurrency
    ) {
        require(
            address(_uniswap) != address(0) &&
                address(_permit2) != address(0) &&
                address(_wrappedNativeCurrency) != address(0) &&
                _initialOperator != address(0) &&
                _initialFeeDestination != address(0),
            "invalid constructor parameters"
        );
        uniswap = _uniswap;
        permit2 = _permit2;
        wrappedNativeCurrency = _wrappedNativeCurrency;

        // Sets an initial operator to enable immediate payment processing
        feeDestinations[_initialOperator] = _initialFeeDestination;
    }

    // @dev Raises errors if the intent is invalid
    // @param _intent The intent to validate
    modifier validIntent(TransferIntent calldata _intent, address sender) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                _intent.recipientAmount,
                _intent.deadline,
                _intent.recipient,
                _intent.recipientCurrency,
                _intent.refundDestination,
                _intent.feeAmount,
                _intent.id,
                _intent.operator,
                block.chainid,
                sender,
                address(this)
            )
        );

        bytes32 signedMessageHash;
        if (_intent.prefix.length == 0) {
            // Use 'default' message prefix.
            signedMessageHash = ECDSA.toEthSignedMessageHash(hash);
        } else {
            // Use custom message prefix.
            signedMessageHash = keccak256(abi.encodePacked(_intent.prefix, hash));
        }

        address signer = ECDSA.recover(signedMessageHash, _intent.signature);

        if (signer != _intent.operator) {
            revert InvalidSignature();
        }

        if (_intent.deadline < block.timestamp) {
            revert ExpiredIntent();
        }

        if (_intent.recipient == address(0)) {
            revert NullRecipient();
        }

        if (processedTransferIntents[_intent.operator][_intent.id]) {
            revert AlreadyProcessed();
        }

        _;
    }

    // @dev Raises an error if the operator in the transfer intent is not registered.
    // @param _intent The intent to validate
    modifier operatorIsRegistered(TransferIntent calldata _intent) {
        if (feeDestinations[_intent.operator] == address(0)) revert OperatorNotRegistered();

        _;
    }

    modifier exactValueSent(TransferIntent calldata _intent) {
        // Make sure the correct value was sent
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        if (msg.value > neededAmount) {
            revert InvalidNativeAmount(int256(msg.value - neededAmount));
        } else if (msg.value < neededAmount) {
            revert InvalidNativeAmount(-int256(neededAmount - msg.value));
        }

        _;
    }

    // @inheritdoc ITransfers
    function transferNative(TransferIntent calldata _intent)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _msgSender())
        operatorIsRegistered(_intent)
        exactValueSent(_intent)
    {
        // Make sure the recipient wants the native currency
        if (_intent.recipientCurrency != NATIVE_CURRENCY) revert IncorrectCurrency(NATIVE_CURRENCY);

        if (msg.value > 0) {
            // Complete the payment
            transferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, msg.value, NATIVE_CURRENCY, _msgSender());
    }

    // @inheritdoc ITransfers
    function transferToken(
        TransferIntent calldata _intent,
        Permit2SignatureTransferData calldata _signatureTransferData
    ) external override nonReentrant whenNotPaused validIntent(_intent, _msgSender()) operatorIsRegistered(_intent) {
        // Make sure the recipient wants a token and the payer is sending it
        if (
            _intent.recipientCurrency == NATIVE_CURRENCY ||
            _signatureTransferData.permit.permitted.token != _intent.recipientCurrency
        ) {
            revert IncorrectCurrency(_signatureTransferData.permit.permitted.token);
        }

        // Make sure the payer has enough of the payment token
        IERC20 erc20 = IERC20(_intent.recipientCurrency);
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 payerBalance = erc20.balanceOf(_msgSender());
        if (payerBalance < neededAmount) {
            revert InsufficientBalance(neededAmount - payerBalance);
        }

        if (neededAmount > 0) {
            // Make sure the payer is transferring the right amount to this contract
            if (
                _signatureTransferData.transferDetails.to != address(this) ||
                _signatureTransferData.transferDetails.requestedAmount != neededAmount
            ) {
                revert InvalidTransferDetails();
            }

            // Record our balance before (most likely zero) to detect fee-on-transfer tokens
            uint256 balanceBefore = erc20.balanceOf(address(this));

            // Transfer the payment token to this contract
            permit2.permitTransferFrom(
                _signatureTransferData.permit,
                _signatureTransferData.transferDetails,
                _msgSender(),
                _signatureTransferData.signature
            );

            // Make sure this is not a fee-on-transfer token
            revertIfInexactTransfer(neededAmount, balanceBefore, erc20, address(this));

            // Complete the payment
            transferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, neededAmount, _intent.recipientCurrency, _msgSender());
    }

    // @inheritdoc ITransfers
    function transferTokenPreApproved(TransferIntent calldata _intent)
        external
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _msgSender())
        operatorIsRegistered(_intent)
    {
        // Make sure the recipient wants a token
        if (_intent.recipientCurrency == NATIVE_CURRENCY) {
            revert IncorrectCurrency(_intent.recipientCurrency);
        }

        // Make sure the payer has enough of the payment token
        IERC20 erc20 = IERC20(_intent.recipientCurrency);
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 payerBalance = erc20.balanceOf(_msgSender());
        if (payerBalance < neededAmount) {
            revert InsufficientBalance(neededAmount - payerBalance);
        }

        // Make sure the payer has approved this contract for a sufficient transfer
        uint256 allowance = erc20.allowance(_msgSender(), address(this));
        if (allowance < neededAmount) {
            revert InsufficientAllowance(neededAmount - allowance);
        }

        if (neededAmount > 0) {
            // Record our balance before (most likely zero) to detect fee-on-transfer tokens
            uint256 balanceBefore = erc20.balanceOf(address(this));

            // Transfer the payment token to this contract
            erc20.safeTransferFrom(_msgSender(), address(this), neededAmount);

            // Make sure this is not a fee-on-transfer token
            revertIfInexactTransfer(neededAmount, balanceBefore, erc20, address(this));

            // Complete the payment
            transferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, neededAmount, _intent.recipientCurrency, _msgSender());
    }

    // @inheritdoc ITransfers
    // @dev Wraps msg.value into wrapped token and transfers to recipient.
    function wrapAndTransfer(TransferIntent calldata _intent)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _msgSender())
        operatorIsRegistered(_intent)
        exactValueSent(_intent)
    {
        // Make sure the recipient wants to receive the wrapped native currency
        if (_intent.recipientCurrency != address(wrappedNativeCurrency)) {
            revert IncorrectCurrency(NATIVE_CURRENCY);
        }

        if (msg.value > 0) {
            // Wrap the sent native currency
            wrappedNativeCurrency.deposit{value: msg.value}();

            // Complete the payment
            transferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, msg.value, NATIVE_CURRENCY, _msgSender());
    }

    // @inheritdoc ITransfers
    // @dev Requires _msgSender() to have approved this contract to use the wrapped token.
    // @dev Unwraps into native token and transfers native token (e.g. ETH) to _intent.recipient.
    function unwrapAndTransfer(
        TransferIntent calldata _intent,
        Permit2SignatureTransferData calldata _signatureTransferData
    ) external override nonReentrant whenNotPaused validIntent(_intent, _msgSender()) operatorIsRegistered(_intent) {
        // Make sure the recipient wants the native currency and that the payer is
        // sending the wrapped native currency
        if (
            _intent.recipientCurrency != NATIVE_CURRENCY ||
            _signatureTransferData.permit.permitted.token != address(wrappedNativeCurrency)
        ) {
            revert IncorrectCurrency(_signatureTransferData.permit.permitted.token);
        }

        // Make sure the payer has enough of the wrapped native currency
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 payerBalance = wrappedNativeCurrency.balanceOf(_msgSender());
        if (payerBalance < neededAmount) {
            revert InsufficientBalance(neededAmount - payerBalance);
        }

        if (neededAmount > 0) {
            // Make sure the payer is transferring the right amount of the wrapped native currency to the contract
            if (
                _signatureTransferData.transferDetails.to != address(this) ||
                _signatureTransferData.transferDetails.requestedAmount != neededAmount
            ) {
                revert InvalidTransferDetails();
            }

            // Transfer the payer's wrapped native currency to the contract
            permit2.permitTransferFrom(
                _signatureTransferData.permit,
                _signatureTransferData.transferDetails,
                _msgSender(),
                _signatureTransferData.signature
            );

            // Complete the payment
            unwrapAndTransferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, neededAmount, address(wrappedNativeCurrency), _msgSender());
    }

    // @inheritdoc ITransfers
    // @dev Requires _msgSender() to have approved this contract to use the wrapped token.
    // @dev Unwraps into native token and transfers native token (e.g. ETH) to _intent.recipient.
    function unwrapAndTransferPreApproved(TransferIntent calldata _intent)
        external
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _msgSender())
        operatorIsRegistered(_intent)
    {
        // Make sure the recipient wants the native currency
        if (_intent.recipientCurrency != NATIVE_CURRENCY) {
            revert IncorrectCurrency(address(wrappedNativeCurrency));
        }

        // Make sure the payer has enough of the wrapped native currency
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 payerBalance = wrappedNativeCurrency.balanceOf(_msgSender());
        if (payerBalance < neededAmount) {
            revert InsufficientBalance(neededAmount - payerBalance);
        }

        // Make sure the payer has approved this contract for a sufficient transfer
        uint256 allowance = wrappedNativeCurrency.allowance(_msgSender(), address(this));
        if (allowance < neededAmount) {
            revert InsufficientAllowance(neededAmount - allowance);
        }

        if (neededAmount > 0) {
            // Transfer the payer's wrapped native currency to the contract
            wrappedNativeCurrency.safeTransferFrom(_msgSender(), address(this), neededAmount);

            // Complete the payment
            unwrapAndTransferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, neededAmount, address(wrappedNativeCurrency), _msgSender());
    }

    /*------------------------------------------------------------------*\
    | Swap and Transfer
    \*------------------------------------------------------------------*/

    // @inheritdoc ITransfers
    function swapAndTransferUniswapV3Native(TransferIntent calldata _intent, uint24 poolFeesTier)
        external
        payable
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _msgSender())
        operatorIsRegistered(_intent)
    {
        // Make sure a swap is actually required, otherwise the payer should use `wrapAndTransfer` or `transferNative`
        if (
            _intent.recipientCurrency == NATIVE_CURRENCY || _intent.recipientCurrency == address(wrappedNativeCurrency)
        ) {
            revert IncorrectCurrency(NATIVE_CURRENCY);
        }

        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;

        uint256 amountSwapped = 0;
        if (neededAmount > 0) {
            // Perform the swap
            amountSwapped = swapTokens(_intent, address(wrappedNativeCurrency), msg.value, poolFeesTier);
        }

        // Complete the payment
        succeedPayment(_intent, amountSwapped, NATIVE_CURRENCY, _msgSender());
    }

    // @inheritdoc ITransfers
    function swapAndTransferUniswapV3Token(
        TransferIntent calldata _intent,
        Permit2SignatureTransferData calldata _signatureTransferData,
        uint24 poolFeesTier
    ) external override nonReentrant whenNotPaused validIntent(_intent, _msgSender()) operatorIsRegistered(_intent) {
        IERC20 tokenIn = IERC20(_signatureTransferData.permit.permitted.token);

        // Make sure a swap is actually required
        if (address(tokenIn) == _intent.recipientCurrency) {
            revert IncorrectCurrency(address(tokenIn));
        }

        // Make sure the transfer is to this contract
        if (_signatureTransferData.transferDetails.to != address(this)) {
            revert InvalidTransferDetails();
        }

        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 maxWillingToPay = _signatureTransferData.transferDetails.requestedAmount;

        uint256 amountSwapped = 0;
        if (neededAmount > 0) {
            // Record our balance before (most likely zero) to detect fee-on-transfer tokens
            uint256 balanceBefore = tokenIn.balanceOf(address(this));

            // Transfer the payer's tokens to this contract
            permit2.permitTransferFrom(
                _signatureTransferData.permit,
                _signatureTransferData.transferDetails,
                _msgSender(),
                _signatureTransferData.signature
            );

            // Make sure this is not a fee-on-transfer token
            revertIfInexactTransfer(maxWillingToPay, balanceBefore, tokenIn, address(this));

            // Perform the swap
            amountSwapped = swapTokens(_intent, address(tokenIn), maxWillingToPay, poolFeesTier);
        }

        // Complete the payment
        succeedPayment(_intent, amountSwapped, address(tokenIn), _msgSender());
    }

    // @inheritdoc ITransfers
    function swapAndTransferUniswapV3TokenPreApproved(
        TransferIntent calldata _intent,
        address _tokenIn,
        uint256 maxWillingToPay,
        uint24 poolFeesTier
    ) external override nonReentrant whenNotPaused validIntent(_intent, _msgSender()) operatorIsRegistered(_intent) {
        IERC20 tokenIn = IERC20(_tokenIn);

        // Make sure a swap is actually required
        if (address(tokenIn) == _intent.recipientCurrency) {
            revert IncorrectCurrency(address(tokenIn));
        }

        // Make sure the payer has enough of the payment token
        uint256 payerBalance = tokenIn.balanceOf(_msgSender());
        if (payerBalance < maxWillingToPay) {
            revert InsufficientBalance(maxWillingToPay - payerBalance);
        }

        // Make sure the payer has approved this contract for a sufficient transfer
        uint256 allowance = tokenIn.allowance(_msgSender(), address(this));
        if (allowance < maxWillingToPay) {
            revert InsufficientAllowance(maxWillingToPay - allowance);
        }

        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;

        uint256 amountSwapped = 0;
        if (neededAmount > 0) {
            // Record our balance before (most likely zero) to detect fee-on-transfer tokens
            uint256 balanceBefore = tokenIn.balanceOf(address(this));

            // Transfer the payment token to this contract
            tokenIn.safeTransferFrom(_msgSender(), address(this), maxWillingToPay);

            // Make sure this is not a fee-on-transfer token
            revertIfInexactTransfer(maxWillingToPay, balanceBefore, tokenIn, address(this));

            // Perform the swap
            amountSwapped = swapTokens(_intent, address(tokenIn), maxWillingToPay, poolFeesTier);
        }

        // Complete the payment
        succeedPayment(_intent, amountSwapped, address(tokenIn), _msgSender());
    }

    // @inheritdoc ITransfers
    function subsidizedTransferToken(
        TransferIntent calldata _intent,
        EIP2612SignatureTransferData calldata _signatureTransferData
    )
        external
        override
        nonReentrant
        whenNotPaused
        validIntent(_intent, _signatureTransferData.owner)
        operatorIsRegistered(_intent)
    {
        // Make sure the recipient wants a token
        if (_intent.recipientCurrency == NATIVE_CURRENCY) {
            revert IncorrectCurrency(_intent.recipientCurrency);
        }

        // Check the balance of the payer
        IERC20 erc20 = IERC20(_intent.recipientCurrency);
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;
        uint256 payerBalance = erc20.balanceOf(_signatureTransferData.owner);
        if (payerBalance < neededAmount) {
            revert InsufficientBalance(neededAmount - payerBalance);
        }

        // Permit this contract to spend the payer's tokens
        IERC7597(_intent.recipientCurrency).permit({
            owner: _signatureTransferData.owner,
            spender: address(this),
            value: neededAmount,
            deadline: _intent.deadline,
            signature: _signatureTransferData.signature
        });

        // Check the payer has approved this contract for a sufficient transfer
        uint256 allowance = erc20.allowance(_signatureTransferData.owner, address(this));
        if (allowance < neededAmount) {
            revert InsufficientAllowance(neededAmount - allowance);
        }

        if (neededAmount > 0) {
            // Record our balance before (most likely zero) to detect fee-on-transfer tokens
            uint256 balanceBefore = erc20.balanceOf(address(this));

            // Transfer the payment token to this contract
            erc20.safeTransferFrom(_signatureTransferData.owner, address(this), neededAmount);

            // Make sure this is not a fee-on-transfer token
            revertIfInexactTransfer(neededAmount, balanceBefore, erc20, address(this));

            // Complete the payment
            transferFundsToDestinations(_intent);
        }

        succeedPayment(_intent, neededAmount, _intent.recipientCurrency, _signatureTransferData.owner);
    }

    function swapTokens(
        TransferIntent calldata _intent,
        address tokenIn,
        uint256 maxAmountWillingToPay,
        uint24 poolFeesTier
    ) internal returns (uint256) {
        // If the seller is requesting native currency, we need to swap for the wrapped
        // version of that currency first, then unwrap it and send it to the seller.
        address tokenOut = _intent.recipientCurrency == NATIVE_CURRENCY
            ? address(wrappedNativeCurrency)
            : _intent.recipientCurrency;

        // Figure out the total output needed from the swap
        uint256 neededAmount = _intent.recipientAmount + _intent.feeAmount;

        // Parameters and shared inputs for the universal router
        bytes memory uniswap_commands;
        bytes[] memory uniswap_inputs;
        bytes memory swapPath = abi.encodePacked(tokenOut, poolFeesTier, tokenIn);
        bytes memory swapParams = abi.encode(address(uniswap), neededAmount, maxAmountWillingToPay, swapPath, false);
        bytes memory transferToRecipient = abi.encode(
            _intent.recipientCurrency,
            _intent.recipient,
            _intent.recipientAmount
        );
        bytes memory collectFees = abi.encode(
            _intent.recipientCurrency,
            feeDestinations[_intent.operator],
            _intent.feeAmount
        );

        // The payer's and router's balances before this transaction, used to calculate the amount consumed by the swap
        uint256 payerBalanceBefore;
        uint256 routerBalanceBefore;

        // The fee and recipient balances of the output token, to detect fee-on-transfer tokens
        uint256 feeBalanceBefore;
        uint256 recipientBalanceBefore;

        // Populate the commands and inputs for the universal router
        if (msg.value > 0) {
            payerBalanceBefore = _msgSender().balance + msg.value;
            routerBalanceBefore = address(uniswap).balance + IERC20(wrappedNativeCurrency).balanceOf(address(uniswap));
            feeBalanceBefore = IERC20(tokenOut).balanceOf(feeDestinations[_intent.operator]);
            recipientBalanceBefore = IERC20(tokenOut).balanceOf(_intent.recipient);

            // Paying with ETH, merchant wants tokenOut
            uniswap_commands = abi.encodePacked(
                bytes1(uint8(UniswapCommands.WRAP_ETH)),
                bytes1(uint8(UniswapCommands.V3_SWAP_EXACT_OUT)),
                bytes1(uint8(UniswapCommands.TRANSFER)),
                bytes1(uint8(UniswapCommands.TRANSFER)),
                bytes1(uint8(UniswapCommands.UNWRAP_WETH)), // for the payer refund
                bytes1(uint8(UniswapCommands.SWEEP))
            );
            uniswap_inputs = new bytes[](6);
            uniswap_inputs[0] = abi.encode(address(uniswap), msg.value);
            uniswap_inputs[1] = swapParams;
            uniswap_inputs[2] = collectFees;
            uniswap_inputs[3] = transferToRecipient;
            uniswap_inputs[4] = abi.encode(address(uniswap), 0);
            uniswap_inputs[5] = abi.encode(UniswapConstants.ETH, _msgSender(), 0);
        } else {
            // No need to check fee/recipient balance of the output token before,
            // since we know WETH and ETH are not fee-on-transfer
            payerBalanceBefore = IERC20(tokenIn).balanceOf(_msgSender()) + maxAmountWillingToPay;
            routerBalanceBefore = IERC20(tokenIn).balanceOf(address(uniswap));

            if (_intent.recipientCurrency == NATIVE_CURRENCY) {
                // Paying with token, merchant wants ETH
                uniswap_commands = abi.encodePacked(
                    bytes1(uint8(UniswapCommands.V3_SWAP_EXACT_OUT)),
                    bytes1(uint8(UniswapCommands.UNWRAP_WETH)), // for the recipient
                    bytes1(uint8(UniswapCommands.TRANSFER)),
                    bytes1(uint8(UniswapCommands.TRANSFER)),
                    bytes1(uint8(UniswapCommands.SWEEP))
                );
                uniswap_inputs = new bytes[](5);
                uniswap_inputs[0] = swapParams;
                uniswap_inputs[1] = abi.encode(address(uniswap), neededAmount);
                uniswap_inputs[2] = collectFees;
                uniswap_inputs[3] = transferToRecipient;
                uniswap_inputs[4] = abi.encode(tokenIn, _msgSender(), 0);
            } else {
                feeBalanceBefore = IERC20(tokenOut).balanceOf(feeDestinations[_intent.operator]);
                recipientBalanceBefore = IERC20(tokenOut).balanceOf(_intent.recipient);

                // Paying with token, merchant wants tokenOut
                uniswap_commands = abi.encodePacked(
                    bytes1(uint8(UniswapCommands.V3_SWAP_EXACT_OUT)),
                    bytes1(uint8(UniswapCommands.TRANSFER)),
                    bytes1(uint8(UniswapCommands.TRANSFER)),
                    bytes1(uint8(UniswapCommands.SWEEP))
                );
                uniswap_inputs = new bytes[](4);
                uniswap_inputs[0] = swapParams;
                uniswap_inputs[1] = collectFees;
                uniswap_inputs[2] = transferToRecipient;
                uniswap_inputs[3] = abi.encode(tokenIn, _msgSender(), 0);
            }

            // Send the input tokens to Uniswap for the swap
            IERC20(tokenIn).safeTransfer(address(uniswap), maxAmountWillingToPay);
        }

        // Perform the swap
        try uniswap.execute{value: msg.value}(uniswap_commands, uniswap_inputs, _intent.deadline) {
            // Disallow fee-on-transfer tokens as the output token, since we want to guarantee exact settlement
            if (_intent.recipientCurrency != NATIVE_CURRENCY) {
                revertIfInexactTransfer(
                    _intent.feeAmount,
                    feeBalanceBefore,
                    IERC20(tokenOut),
                    feeDestinations[_intent.operator]
                );
                revertIfInexactTransfer(
                    _intent.recipientAmount,
                    recipientBalanceBefore,
                    IERC20(tokenOut),
                    _intent.recipient
                );
            }

            // Calculate and return how much of the input token was consumed by the swap. The router
            // could have had a balance of the input token prior to this transaction, which would have
            // been swept to the payer. This amount, if any, must be accounted for so we don't underflow
            // and assume that negative amount of the input token was consumed by the swap.
            uint256 payerBalanceAfter;
            uint256 routerBalanceAfter;
            if (msg.value > 0) {
                payerBalanceAfter = _msgSender().balance;
                routerBalanceAfter =
                    address(uniswap).balance +
                    IERC20(wrappedNativeCurrency).balanceOf(address(uniswap));
            } else {
                payerBalanceAfter = IERC20(tokenIn).balanceOf(_msgSender());
                routerBalanceAfter = IERC20(tokenIn).balanceOf(address(uniswap));
            }
            return (payerBalanceBefore + routerBalanceBefore) - (payerBalanceAfter + routerBalanceAfter);
        } catch Error(string memory reason) {
            revert SwapFailedString(reason);
        } catch (bytes memory reason) {
            bytes32 reasonHash = keccak256(reason);
            if (reasonHash == V3_INVALID_SWAP) {
                revert SwapFailedString("V3InvalidSwap");
            } else if (reasonHash == V3_TOO_LITTLE_RECEIVED) {
                revert SwapFailedString("V3TooLittleReceived");
            } else if (reasonHash == V3_TOO_MUCH_REQUESTED) {
                revert SwapFailedString("V3TooMuchRequested");
            } else if (reasonHash == V3_INVALID_AMOUNT_OUT) {
                revert SwapFailedString("V3InvalidAmountOut");
            } else if (reasonHash == V3_INVALID_CALLER) {
                revert SwapFailedString("V3InvalidCaller");
            } else {
                revert SwapFailedBytes(reason);
            }
        }
    }

    function transferFundsToDestinations(TransferIntent calldata _intent) internal {
        if (_intent.recipientCurrency == NATIVE_CURRENCY) {
            if (_intent.recipientAmount > 0) {
                sendNative(_intent.recipient, _intent.recipientAmount, false);
            }
            if (_intent.feeAmount > 0) {
                sendNative(feeDestinations[_intent.operator], _intent.feeAmount, false);
            }
        } else {
            IERC20 requestedCurrency = IERC20(_intent.recipientCurrency);
            if (_intent.recipientAmount > 0) {
                requestedCurrency.safeTransfer(_intent.recipient, _intent.recipientAmount);
            }
            if (_intent.feeAmount > 0) {
                requestedCurrency.safeTransfer(feeDestinations[_intent.operator], _intent.feeAmount);
            }
        }
    }

    function unwrapAndTransferFundsToDestinations(TransferIntent calldata _intent) internal {
        uint256 amountToWithdraw = _intent.recipientAmount + _intent.feeAmount;
        if (_intent.recipientCurrency == NATIVE_CURRENCY && amountToWithdraw > 0) {
            wrappedNativeCurrency.withdraw(amountToWithdraw);
        }
        transferFundsToDestinations(_intent);
    }

    function succeedPayment(
        TransferIntent calldata _intent,
        uint256 spentAmount,
        address spentCurrency,
        address sender
    ) internal {
        processedTransferIntents[_intent.operator][_intent.id] = true;
        emit Transferred(_intent.operator, _intent.id, _intent.recipient, sender, spentAmount, spentCurrency);
    }

    function sendNative(
        address destination,
        uint256 amount,
        bool isRefund
    ) internal {
        (bool success, bytes memory data) = payable(destination).call{value: amount}("");
        if (!success) {
            revert NativeTransferFailed(destination, amount, isRefund, data);
        }
    }

    function revertIfInexactTransfer(
        uint256 expectedDiff,
        uint256 balanceBefore,
        IERC20 token,
        address target
    ) internal view {
        uint256 balanceAfter = token.balanceOf(target);
        if (balanceAfter - balanceBefore != expectedDiff) {
            revert InexactTransfer();
        }
    }

    // @notice Registers an operator with a custom fee destination.
    function registerOperatorWithFeeDestination(address _feeDestination) external {
        feeDestinations[_msgSender()] = _feeDestination;

        emit OperatorRegistered(_msgSender(), _feeDestination);
    }

    // @notice Registers an operator, using the operator's address as the fee destination.
    function registerOperator() external {
        feeDestinations[_msgSender()] = _msgSender();

        emit OperatorRegistered(_msgSender(), _msgSender());
    }

    function unregisterOperator() external {
        delete feeDestinations[_msgSender()];

        emit OperatorUnregistered(_msgSender());
    }

    // @notice Allows the owner to pause the contract.
    function pause() external onlyOwner {
        _pause();
    }

    // @notice Allows the owner to un-pause the contract.
    function unpause() external onlyOwner {
        _unpause();
    }

    // @dev Required to be able to unwrap WETH
    receive() external payable {
        require(msg.sender == address(wrappedNativeCurrency), "only payable for unwrapping");
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Transfers
Buscando 'Transfers' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (15ms)

 1. [LOW] Incorrect Transfer Types Check — Sui Axelar (Gateway V2)
 2. [MEDIUM] Untracked Transfer Recipient — Near IAH
 3. [HIGH] Missing Validation For Fee Amount — Solana ZK Token
 4. [MEDIUM] Maximum Transfer Amount Is Bypassable — Mavia Token
 5. [HIGH] Flaw in Full Transfer Checks — Aptos Securitize

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Transfers | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] Incorrect Transfer Types Check (Sui Axelar (Gateway V2))
   ## Error in Assertion within `transfer::its_transfer`

There is an error in the assertion within `transfer::its_transfer`. `its_transfer` is specifica...

2. [MEDIUM] Untracked Transfer Recipient (Near IAH)
   ## Vulnerability Analysis: sbt_soul_transfer Behavior

The issue pertains to `sbt_soul_transfer`’s behavior during the resumption of an ongoing Soulbo...

3. [HIGH] Missing Validation For Fee Amount (Solana ZK Token)
   ## Process Set Transfer Fee

In `process_set_transfer_fee`, `fee_to_encrypt` represents the fee to encrypt in a token confidential transfer, and it is...

4. [MEDIUM] Maximum Transfer Amount Is Bypassable (Mavia Token)
   **Update**
Marked as "Acknowledged" by the client. The client provided the following explanation:

> This is the intended behavior. The limit amount i...

5. [HIGH] Flaw in Full Transfer Checks (Aptos Securitize)
   ## Compliance Service Pre-Deposit Check Regulated

In `compliance_service::pre_deposit_check_regulated`, the `get_force_full_transfer` condition check...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio reentrancy
Buscando 'Transfers transferNative transferToken transferTokenPreApproved wrapAndTransfer' [SQLite FTS5] (dominio: reentrancy)...
Top 6 findings relevantes: (19ms)
 1. [HIGH] Reentrancy Vulnerabilities May Drain Tokens — Sushi
 2. [HIGH] [H-03] denial of service — Sublime
 3. [HIGH] Lack of return value checks can lead to unexpected results — Origin Dollar
 4. [HIGH] Token Bridging doesn't work with Wormhole fees — Lido
 5. [HIGH] Inconsistencies In Calculation Of Fee Amount — VTVL
 6. [HIGH] [H-02] ProtocolDAO lacks a method to take out GGP — GoGoPool
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: Transfers transferNative transferToken transferTokenPreApproved wrapAndTransfer | Dominio: reentrancy
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Reentrancy Vulnerabilities May Drain Tokens (Sushi)
   ## Description
There is a potential reentrancy bug in `FuroVesting.stopVesting()` that allows draining the token balance of the contract for any ERC2...
2. [HIGH] [H-03] denial of service (Sublime)
   _Submitted by certora_
<https://github.com/code-423n4/2021-12-sublime/blob/main/contracts/Pool/Pool.sol#L645>
if the borrow token is address(0) (ethe...
3. [HIGH] Lack of return value checks can lead to unexpected results (Origin Dollar)
   ## Type: Denial of Service
## Target: Several Contracts
### Difficulty: Medium
### Description
Several function calls do not check the return value....
4. [HIGH] Token Bridging doesn't work with Wormhole fees (Lido)
   ##### Description
Line 
- https://github.com/certusone/wormhole/blob/9bc408ca1912e7000c5c2085215be9d44713028b/ethereum/contracts/bridge/Bridge.sol#L93...
5. [HIGH] Inconsistencies In Calculation Of Fee Amount (VTVL)
   ## VTVLVesting Token Transfer Issue
In `VTVLVesting::_transferToken`, the `_realFeeAmount` parameter passed to the USDC token transfer function is no...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene l

## Briefing del Dominio (reentrancy)
### Briefing principal: reentrancy

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ nonReentrant no protege contra cross-function reentrancy si las dos funciones no comparten el lock
  ⚠ El patrón mutex (locked = true) solo protege el contrato actual, no contratos hermanos
  ⚠ Los callbacks ERC721/ERC1155 pueden disparar reentrancy en funciones que parecen seguras
  ⚠ Uniswap V3 usa un 'locked' flag global — esto protege contra cross-function reentrancy dentro del pool
  ⚠ Los protocolos multi-contract con callbacks entre contratos tienen la mayor superficie de cross-function reentrancy
  ⚠ Los delegates en Gnosis Safe pueden explotar cross-function reentrancy entre módulos
  ⚠ Las read-only reentrancy no modifican estado → nonReentrant no ayuda en el contrato víctima
  ⚠ La defensa está del lado del protocolo que LEE el precio, no del protocolo de AMM
  ⚠ Balancer V2 tuvo exactamente este bug — se arregló exponiendo reentrancyGuardEntered()
  ⚠ transferFrom (sin 'safe') no llama el callback — más seguro contra reentrancy pero menos seguro para receptores de contrato que no saben recibir NFTs
  ⚠ ERC1155 tiene el mismo patrón con onERC1155Received y onERC1155BatchReceived
  ⚠ El TWAP no es afectado por flash loans — el precio solo se actualiza al final del bloque


### Grep targets adicionales (trust)
```yaml
- id: tb-004
  titulo: Tokens rebasing (aToken, stETH) rompen contabilidad si se cachea el balance
  causa_raiz: |
    Tokens como aToken de Aave o stETH de Lido incrementan su balance automáticamente
    con el tiempo (rebasing positivo) sin emitir Transfer events. Si el contrato cachea
    el balance en storage en vez de llamar a balanceOf() cada vez, el valor cacheado
    queda desactualizado → underestima activos → shares sobreemitidas o pérdida de yield.
  como_funciona: |
    1. Vault deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea balance=1000.
    2. 30 días pasan: balance real de aUSDC = 1050 (5% yield).
    3. totalAssets() retorna 1000 en vez de 1050 → pricePerShare subestimado.



## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Overflow) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
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
ID prefix para este componente: `T` (ej: T-01, T-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Transfers_MathHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: T-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "T-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Decimal Universality (OBLIGATORIO — después de tu análisis matemático)
Para CADA operación aritmética que involucre tokens o precios:
- ¿Funciona con 6 decimales (USDC, USDT)?
- ¿Funciona con 8 decimales (WBTC)?
- ¿Funciona con 18 decimales (WETH, DAI)?
- ¿Funciona con 2 decimales (tokens exóticos)?
- ¿minOut/slippage protection funciona correctamente para TODOS los tokens?
- ¿Hay divisiones donde numerador tiene menos decimales que denominador? (resultado trunca a 0)

Bug real: slippage check hardcodeado para USDC (6 dec) aplicado a WETH (18 dec) → protección inefectiva.
Bug real: price = tokenAmount * oraclePrice / 1e18 con tokenAmount de 6 dec → pierde 12 dec de precisión.

## Bidirectional Rounding Check (Sec3/Josselin Feist — OBLIGATORIO)
Para cada función BIDIRECCIONAL (swap A→B y B→A, mint/redeem, deposit/withdraw):
1. Localiza cada "rounding signature" (multiplicación seguida de división)
2. ¿Se redondea CONSISTENTEMENTE? (down en output, up en fee — o viceversa)
3. ¿Un round-trip (A→B→A) puede ser rentable para el atacante? Si deposit(X) y luego withdraw da > X → bug
4. "Round in favor of protocol" tiene side effects: atacantes pueden extraer valor de OTROS USUARIOS (no del pool)

## Fuzz para Maximizar (Dacian — MENTALIDAD)
Cuando escribas invariantes de math, piensa en modo OPTIMIZACIÓN no solo VERIFICACIÓN:
- No solo "¿hay precision loss?" sino "¿cuál es el INPUT que MAXIMIZA la precision loss?"
- Escribe una función optimize_precisionLoss() que Echidna pueda maximizar

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
