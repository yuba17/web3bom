# TrustBoundaryHunter — InterchainAccountRouter Analysis

## Tu Identidad
Eres el **TrustBoundaryHunter** del equipo de bug hunting de hyperlane.
Tu especialidad: **Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions**

## Tu Objetivo
Analizar `InterchainAccountRouter` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/hyperlane-monorepo/solidity/contracts/middleware/InterchainAccountRouter.sol`
**Dominio**: trust


## Asset Flow Map
### Money IN (deposits/receives)
- L163 handle(): ica.multicall{value: msg.value}(calls);
- L617 callRemoteCommitReveal(): msg.value
- L749 _dispatchMessageWithHook(): msg.value

### Balance Reads (manipulation vectors)
- L630 callRemoteCommitReveal(): address(this).balance
```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.13;

/*@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@  HYPERLANE  @@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
@@@@@@@@@       @@@@@@@@*/

// ============ Internal Imports ============
import {OwnableMulticall} from "./libs/OwnableMulticall.sol";
import {InterchainAccountMessage, InterchainAccountMessageReveal} from "./libs/InterchainAccountMessage.sol";
import {CallLib} from "./libs/Call.sol";
import {AbstractInterchainAccountRouter} from "./AbstractInterchainAccountRouter.sol";
import {TypeCasts} from "../libs/TypeCasts.sol";
import {StandardHookMetadata} from "../hooks/libs/StandardHookMetadata.sol";
import {Router} from "../client/Router.sol";
import {IPostDispatchHook} from "../interfaces/hooks/IPostDispatchHook.sol";
import {IInterchainSecurityModule} from "../interfaces/IInterchainSecurityModule.sol";
import {CommitmentReadIsm} from "../isms/ccip-read/CommitmentReadIsm.sol";
import {Message} from "../libs/Message.sol";
import {AbstractRoutingIsm} from "../isms/routing/AbstractRoutingIsm.sol";

// ============ External Imports ============
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

/*
 * @title A contract that allows accounts on chain A to call contracts via a
 * proxy contract on chain B.
 * @dev ISMs enrolled alongside routers via _enrollRemoteRouterAndIsm, domains always match router table
 */
contract InterchainAccountRouter is
    AbstractInterchainAccountRouter,
    AbstractRoutingIsm
{
    // ============ Libraries ============

    using TypeCasts for address;
    using TypeCasts for bytes32;
    using InterchainAccountMessage for bytes;
    using Message for bytes;
    using StandardHookMetadata for bytes;

    // ============ Constants ============

    CommitmentReadIsm public immutable CCIP_READ_ISM;
    uint public immutable COMMIT_TX_GAS_USAGE;

    /**
     * @notice Emitted when a commit-reveal interchain call is dispatched to a remote domain
     * @param commitment The commitment that was dispatched
     */
    event CommitRevealDispatched(bytes32 indexed commitment);

    // ============ Constructor ============
    constructor(
        address _mailbox,
        address _hook,
        address _owner,
        uint _commit_tx_gas_usage,
        string[] memory _commitment_urls
    ) Router(_mailbox) {
        setHook(_hook);
        _transferOwnership(_owner);

        bytes memory bytecode = _implementationBytecode(address(this));
        implementation = Create2.deploy(0, bytes32(0), bytecode);
        bytecodeHash = _proxyBytecodeHash(implementation);

        CCIP_READ_ISM = new CommitmentReadIsm(_owner, _commitment_urls);
        COMMIT_TX_GAS_USAGE = _commit_tx_gas_usage;
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Uses the default router and ISM addresses for the destination
     * domain, reverting if none have been configured
     * @dev Recommend using CallLib.build to format the interchain calls.
     * @param _destination The remote domain of the chain to make calls on
     * @param _calls The sequence of calls to make
     * @return The Hyperlane message ID
     */
    function callRemote(
        uint32 _destination,
        CallLib.Call[] calldata _calls
    ) public payable returns (bytes32) {
        return callRemote(_destination, _calls, bytes(""));
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Uses the default router and ISM addresses for the destination
     * domain, reverting if none have been configured
     * @dev Recommend using CallLib.build to format the interchain calls.
     * @param _destination The remote domain of the chain to make calls on
     * @param _calls The sequence of calls to make
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @return The Hyperlane message ID
     */
    function callRemote(
        uint32 _destination,
        CallLib.Call[] calldata _calls,
        bytes memory _hookMetadata
    ) public payable returns (bytes32) {
        bytes32 _router = routers(_destination);
        bytes32 _ism = isms[_destination];
        return
            callRemoteWithOverrides(
                _destination,
                _router,
                _ism,
                _calls,
                _hookMetadata
            );
    }

    /**
     * @notice Handles dispatched messages by relaying calls to the interchain account
     * @param _origin The origin domain of the interchain account
     * @param _sender The sender of the interchain message
     * @param _message The InterchainAccountMessage containing the account
     * owner, ISM, and sequence of calls to be relayed
     * @dev Does not need to be onlyRemoteRouter, as this application is designed
     * to receive messages from untrusted remote contracts.
     */
    function handle(
        uint32 _origin,
        bytes32 _sender,
        bytes calldata _message
    ) external payable override onlyMailbox {
        InterchainAccountMessage.MessageType _messageType = _message
            .messageType();
        if (_messageType == InterchainAccountMessage.MessageType.REVEAL) {
            // If the message is a reveal,
            // the commitment should have been executed in the `verify` method of the ISM
            // that verified this message. The commitment is deleted in `revealAndExecute`.
            // Simply return.
            return;
        }

        bytes32 _owner = _message.owner();
        bytes32 _salt = _message.salt();
        bytes32 _ism = _message.ism();

        OwnableMulticall ica = getDeployedInterchainAccount(
            _origin,
            _owner,
            _sender,
            _ism.bytes32ToAddress(),
            _salt
        );

        if (_messageType == InterchainAccountMessage.MessageType.CALLS) {
            CallLib.Call[] memory calls = _message.calls();
            ica.multicall{value: msg.value}(calls);
        } else {
            // This is definitely a message of type COMMITMENT
            ica.setCommitment(_message.commitment());
        }
    }

    function route(
        bytes calldata _message
    ) public view override returns (IInterchainSecurityModule) {
        bytes calldata _body = _message.body();
        InterchainAccountMessage.MessageType _messageType = _body.messageType();

        // If the ISM is not set, we need to check if the message is a reveal
        // If it is, we need to set the ISM to the CCIP read ISM
        // Otherwise, we need to set the ISM to the default ISM
        address _ism;
        if (_messageType == InterchainAccountMessage.MessageType.REVEAL) {
            _ism = InterchainAccountMessageReveal
                .revealIsm(_body)
                .bytes32ToAddress();
            _ism = _ism == address(0) ? address(CCIP_READ_ISM) : _ism;
        } else {
            _ism = InterchainAccountMessage.ism(_body).bytes32ToAddress();
            _ism = _ism == address(0) ? address(mailbox.defaultIsm()) : _ism;
        }

        return IInterchainSecurityModule(_ism);
    }

    /**
     * @notice Returns the local address of an interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @param _origin The remote origin domain of the interchain account
     * @param _router The remote origin InterchainAccountRouter
     * @param _owner The remote owner of the interchain account
     * @param _ism The local address of the ISM
     * @return The local address of the interchain account
     */
    function getLocalInterchainAccount(
        uint32 _origin,
        address _owner,
        address _router,
        address _ism
    ) external view override returns (OwnableMulticall) {
        return
            getLocalInterchainAccount(
                _origin,
                _owner.addressToBytes32(),
                _router.addressToBytes32(),
                _ism
            );
    }

    /**
     * @notice Returns the remote address of a locally owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @dev This function will only work if the destination domain is
     * EVM compatible
     * @param _destination The remote destination domain of the interchain account
     * @param _owner The local owner of the interchain account
     * @return The remote address of the interchain account
     */
    function getRemoteInterchainAccount(
        uint32 _destination,
        address _owner
    ) external view returns (address) {
        return
            getRemoteInterchainAccount(
                _destination,
                _owner,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Returns the remote address of a locally owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @dev This function will only work if the destination domain is
     * EVM compatible
     * @param _destination The remote destination domain of the interchain account
     * @param _owner The local owner of the interchain account
     * @param _userSalt A user provided salt. Allows control over account derivation.
     * @return The remote address of the interchain account
     */
    function getRemoteInterchainAccount(
        uint32 _destination,
        address _owner,
        bytes32 _userSalt
    ) public view returns (address) {
        address _router = routers(_destination).bytes32ToAddress();
        address _ism = isms[_destination].bytes32ToAddress();
        return getRemoteInterchainAccount(_owner, _router, _ism, _userSalt);
    }

    // ============ Public Functions ============

    /**
     * @notice Returns and deploys (if not already) an interchain account
     * @param _origin The remote origin domain of the interchain account
     * @param _owner The remote owner of the interchain account
     * @param _router The remote origin InterchainAccountRouter
     * @param _ism The local address of the ISM
     * @return The address of the interchain account
     */
    function getDeployedInterchainAccount(
        uint32 _origin,
        bytes32 _owner,
        bytes32 _router,
        address _ism
    ) public returns (OwnableMulticall) {
        return
            getDeployedInterchainAccount(
                _origin,
                _owner,
                _router,
                _ism,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Returns the local address of a remotely owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @param _origin The remote origin domain of the interchain account
     * @param _owner The remote owner of the interchain account
     * @param _router The remote InterchainAccountRouter
     * @param _ism The local address of the ISM
     * @return The local address of the interchain account
     */
    function getLocalInterchainAccount(
        uint32 _origin,
        bytes32 _owner,
        bytes32 _router,
        address _ism
    ) public view returns (OwnableMulticall) {
        return
            getLocalInterchainAccount(
                _origin,
                _owner,
                _router,
                _ism,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Returns the local address of a remotely owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @param _origin The remote origin domain of the interchain account
     * @param _owner The remote owner of the interchain account
     * @param _router The remote InterchainAccountRouter
     * @param _ism The local address of the ISM
     * @param _userSalt A user provided salt. Allows control over account derivation.
     * @return The local address of the interchain account
     */
    function getLocalInterchainAccount(
        uint32 _origin,
        bytes32 _owner,
        bytes32 _router,
        address _ism,
        bytes32 _userSalt
    ) public view returns (OwnableMulticall) {
        return
            OwnableMulticall(
                _getLocalInterchainAccount(
                    _getSalt(
                        _origin,
                        _owner,
                        _router,
                        _ism.addressToBytes32(),
                        _userSalt
                    )
                )
            );
    }

    /**
     * @notice Returns the remote address of a locally owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @dev This function will only work if the destination domain is
     * EVM compatible
     * @param _owner The local owner of the interchain account
     * @param _router The remote InterchainAccountRouter
     * @param _ism The remote address of the ISM
     * @return The remote address of the interchain account
     */
    function getRemoteInterchainAccount(
        address _owner,
        address _router,
        address _ism
    ) public view returns (address) {
        return
            getRemoteInterchainAccount(
                _owner,
                _router,
                _ism,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Returns the remote address of a locally owned interchain account
     * @dev This interchain account is not guaranteed to have been deployed
     * @dev This function will only work if the destination domain is
     * EVM compatible
     * @param _owner The local owner of the interchain account
     * @param _router The remote InterchainAccountRouter
     * @param _ism The remote address of the ISM
     * @param _userSalt Salt provided by the user, allows control over account derivation.
     * @return The remote address of the interchain account
     */
    function getRemoteInterchainAccount(
        address _owner,
        address _router,
        address _ism,
        bytes32 _userSalt
    ) public view returns (address) {
        require(_router != address(0), "no router specified for destination");

        // replicate router constructor Create2 derivation
        address _implementation = Create2.computeAddress(
            bytes32(0),
            keccak256(_implementationBytecode(_router)),
            _router
        );

        bytes32 _bytecodeHash = _proxyBytecodeHash(_implementation);
        bytes32 _salt = _getSalt(
            localDomain,
            _owner.addressToBytes32(),
            address(this).addressToBytes32(),
            _ism.addressToBytes32(),
            _userSalt
        );
        return Create2.computeAddress(_salt, _bytecodeHash, _router);
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Recommend using CallLib.build to format the interchain calls
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _calls The sequence of calls to make
     * @return The Hyperlane message ID
     */
    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls
    ) public payable returns (bytes32) {
        return
            callRemoteWithOverrides(
                _destination,
                _router,
                _ism,
                _calls,
                bytes(""),
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Recommend using CallLib.build to format the interchain calls
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _calls The sequence of calls to make
     * @return The Hyperlane message ID
     */
    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls,
        bytes32 _userSalt
    ) public payable returns (bytes32) {
        return
            callRemoteWithOverrides(
                _destination,
                _router,
                _ism,
                _calls,
                bytes(""),
                _userSalt
            );
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Recommend using CallLib.build to format the interchain calls
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _calls The sequence of calls to make
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @return The Hyperlane message ID
     */
    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls,
        bytes memory _hookMetadata
    ) public payable override returns (bytes32) {
        return
            callRemoteWithOverrides(
                _destination,
                _router,
                _ism,
                _calls,
                _hookMetadata,
                InterchainAccountMessage.EMPTY_SALT
            );
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Recommend using CallLib.build to format the interchain calls
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _calls The sequence of calls to make
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @param _userSalt Salt provided by the user, allows control over account derivation.
     * @return The Hyperlane message ID
     */
    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls,
        bytes memory _hookMetadata,
        bytes32 _userSalt
    ) public payable returns (bytes32) {
        return
            callRemoteWithOverrides(
                _destination,
                _router,
                _ism,
                _calls,
                _hookMetadata,
                _userSalt,
                hook
            );
    }

    /**
     * @notice Dispatches a sequence of remote calls to be made by an owner's
     * interchain account on the destination domain
     * @dev Recommend using CallLib.build to format the interchain calls
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _calls The sequence of calls to make
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @param _salt Salt which allows control over account derivation.
     * @param _hook The hook to use after sending our message to the mailbox
     * @return The Hyperlane message ID
     */
    function callRemoteWithOverrides(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        CallLib.Call[] calldata _calls,
        bytes memory _hookMetadata,
        bytes32 _salt,
        IPostDispatchHook _hook
    ) public payable returns (bytes32) {
        emit RemoteCallDispatched(
            _destination,
            msg.sender,
            _router,
            _ism,
            _salt
        );
        bytes memory _body = InterchainAccountMessage.encode(
            msg.sender,
            _ism,
            _calls,
            _salt
        );
        return
            _dispatchMessageWithHook(
                _destination,
                _router,
                _body,
                _hookMetadata,
                _hook
            );
    }

    /**
     * @notice Dispatches a commitment and reveal message to the destination domain.
     *  Useful for when we want to keep calldata secret (e.g. when executing a swap
     * @dev The commitment message is dispatched first, followed by the reveal message.
     * To find the calladata, the user must fetch the calldata from the url provided by the OffChainLookupIsm
     * specified in the _ccipReadIsm parameter.
     * The revealed calladata is executed by the `revealAndExecute` function, which will be called the OffChainLookupIsm in its `verify` function.
     * @param _destination The remote domain of the chain to make calls on
     * @param _router The remote router address
     * @param _ism The remote ISM address
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @param _salt Salt which allows control over account derivation.
     * @param _hook The hook to use after sending our message to the mailbox
     * @param _commitment The commitment to dispatch
     * @return _commitmentMsgId The Hyperlane message ID of the commitment message
     * @return _revealMsgId The Hyperlane message ID of the reveal message
     */
    function callRemoteCommitReveal(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        bytes32 _ccipReadIsm,
        bytes memory _hookMetadata,
        IPostDispatchHook _hook,
        bytes32 _salt,
        bytes32 _commitment
    ) public payable returns (bytes32 _commitmentMsgId, bytes32 _revealMsgId) {
        bytes memory _commitmentMsg = InterchainAccountMessage
            .encodeCommitment({
                _owner: msg.sender.addressToBytes32(),
                _ism: _ism,
                _commitment: _commitment,
                _userSalt: _salt
            });

        emit RemoteCallDispatched(
            _destination,
            msg.sender,
            _router,
            _ism,
            _salt
        );
        emit CommitRevealDispatched(_commitment);

        _commitmentMsgId = _dispatchMessageWithValue(
            _destination,
            _router,
            _commitmentMsg,
            StandardHookMetadata.formatMetadata(
                0,
                COMMIT_TX_GAS_USAGE,
                address(this),
                bytes("")
            ),
            _hook,
            msg.value
        );

        bytes memory _revealMsg = InterchainAccountMessage.encodeReveal({
            _ism: _ccipReadIsm,
            _commitment: _commitment
        });
        _revealMsgId = _dispatchMessageWithValue(
            _destination,
            _router,
            _revealMsg,
            _hookMetadata,
            _hook,
            address(this).balance
        );
    }

    function callRemoteCommitReveal(
        uint32 _destination,
        bytes32 _router,
        bytes32 _ism,
        bytes memory _hookMetadata,
        IPostDispatchHook _hook,
        bytes32 _salt,
        bytes32 _commitment
    ) public payable returns (bytes32 _commitmentMsgId, bytes32 _revealMsgId) {
        return
            callRemoteCommitReveal(
                _destination,
                _router,
                _ism,
                bytes32(0),
                _hookMetadata,
                _hook,
                _salt,
                _commitment
            );
    }

    function callRemoteCommitReveal(
        uint32 _destination,
        bytes32 _commitment,
        uint _gasLimit
    ) public payable returns (bytes32 _commitmentMsgId, bytes32 _revealMsgId) {
        bytes32 _router = routers(_destination);
        bytes32 _ism = isms[_destination];

        bytes memory hookMetadata = StandardHookMetadata.formatMetadata(
            0,
            _gasLimit,
            msg.sender,
            bytes("")
        );

        return
            callRemoteCommitReveal(
                _destination,
                _router,
                _ism,
                bytes32(0),
                hookMetadata,
                hook,
                InterchainAccountMessage.EMPTY_SALT,
                _commitment
            );
    }

    /**
     * @notice Dispatches an InterchainAccountMessage to the remote router
     * @param _destination The remote domain
     * @param _router The address of the remote InterchainAccountRouter
     * @param _body The InterchainAccountMessage body
     */
    function _dispatchMessage(
        uint32 _destination,
        bytes32 _router,
        bytes memory _body
    ) private returns (bytes32) {
        return
            _dispatchMessageWithMetadata(
                _destination,
                _router,
                _body,
                bytes("")
            );
    }

    /**
     * @notice Dispatches an InterchainAccountMessage to the remote router with hook metadata
     * @param _destination The remote domain
     * @param _router The address of the remote InterchainAccountRouter
     * @param _body The InterchainAccountMessage body
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     */
    function _dispatchMessageWithMetadata(
        uint32 _destination,
        bytes32 _router,
        bytes memory _body,
        bytes memory _hookMetadata
    ) private returns (bytes32) {
        return
            _dispatchMessageWithHook(
                _destination,
                _router,
                _body,
                _hookMetadata,
                hook
            );
    }

    /**
     * @notice Dispatches an InterchainAccountMessage to the remote router with hook metadata
     * @param _destination The remote domain
     * @param _router The address of the remote InterchainAccountRouter
     * @param _body The InterchainAccountMessage body
     * @param _hookMetadata The hook metadata to override with for the hook set by the owner
     * @param _hook The hook to use after sending our message to the mailbox
     */
    function _dispatchMessageWithHook(
        uint32 _destination,
        bytes32 _router,
        bytes memory _body,
        bytes memory _hookMetadata,
        IPostDispatchHook _hook
    ) private returns (bytes32) {
        return
            _dispatchMessageWithValue(
                _destination,
                _router,
                _body,
                _hookMetadata,
                _hook,
                msg.value
            );
    }

    /**
     * @notice Returns the gas payment required to dispatch a message to the given domain's router.
     * @param _destination The domain of the destination router.
     * @return _gasPayment Payment computed by the registered hooks via MailboxClient.
     */
    function quoteGasPayment(
        uint32 _destination
    ) public view returns (uint256 _gasPayment) {
        return
            _Router_quoteDispatch(
                _destination,
                bytes(""),
                bytes(""),
                address(hook)
            );
    }

    /**
     * @notice Returns the ERC20 token payment required to dispatch a message.
     * @param _feeToken The ERC20 token to pay gas fees in.
     * @param _destination The domain of the destination router.
     * @param _gasLimit The gas limit that the calls will use.
     * @return _gasPayment Payment amount in the specified token.
     */
    function quoteGasPayment(
        address _feeToken,
        uint32 _destination,
        uint256 _gasLimit
    ) public view returns (uint256 _gasPayment) {
        return
            _Router_quoteDispatch(
                _destination,
                new bytes(0),
                StandardHookMetadata.formatWithFeeToken(
                    0,
                    _gasLimit,
                    msg.sender,
                    _feeToken
                ),
                address(hook)
            );
    }

    /**
     * @notice Returns the payment required to commit reveal to the destination router.
     * @param _destination The domain of the destination router.
     * @param gasLimit The gas limit that the reveal calls will use.
     * @return _gasPayment Payment computed by the registered hooks via MailboxClient.
     */
    function quoteGasForCommitReveal(
        uint32 _destination,
        uint256 gasLimit
    ) external view returns (uint256 _gasPayment) {
        return
            _Router_quoteDispatch(
                _destination,
                new bytes(0),
                StandardHookMetadata.overrideGasLimit(COMMIT_TX_GAS_USAGE),
                address(hook)
            ) + quoteGasPayment(_destination, gasLimit);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre InterchainAccountRouter
Buscando 'InterchainAccountRouter' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (41ms)


### HIGH findings en dominio trust
Buscando 'InterchainAccountRouter callRemote callRemote getLocalInterchainAccount getRemot' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (16ms)

### Cross-domain HIGH relevantes
Buscando 'InterchainAccountRouter callRemote callRemote getLocalInterc' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

## Briefing del Dominio (trust)
### Briefing principal: trust

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ La mayoría de protocolos DeFi mainstream usan USDC/WETH — no son FoT.
  ⚠ El impacto real depende de si el token en scope puede ser FoT (verificar docs del protocolo).
  ⚠ Algunos auditores marcan esto como LOW/INFO si el protocolo explícitamente excluye FoT.
  ⚠ ERC777 ya no es popular post-2022, pero sigue siendo un vector con tokens heredados.
  ⚠ USDC/USDT no son ERC777, pero protocolos con reward tokens configurables sí son vulnerables.
  ⚠ GearBox demostró que ERC777 como colateral puede bloquear liquidaciones (DOS, no drain).
  ⚠ Circle rara vez bloquea direcciones de contratos DeFi — el riesgo es real pero bajo.
  ⚠ El riesgo más práctico es el griefing de liquidaciones en lending protocols.
  ⚠ Verificar si el protocolo tiene USDC como único colateral o tiene alternativas.
  ⚠ cToken de Compound NO es rebasing — su balance es fijo, sube el exchangeRate.
  ⚠ wstETH NO es rebasing — el precio sube, no el balance.
  ⚠ Sólo stETH "nativo" y aToken son rebasing en el sentido estricto.

## CHECKLIST DE INVARIANTES
```yaml
- id: tb-003
  titulo: Blocklist de USDC/USDT bloquea retiros o liquidaciones del protocolo
  causa_raiz: |
    USDC y USDT tienen función de blacklist/blocklist: el emisor puede bloquear cualquier
    address. Si el contrato o un usuario clave es bloqueado, transfer() revierte → función
    de retiro o liquidación revierte → fondos quedan congelados indefinidamente.
  como_funciona: |
    Path A (usuario bloqueado): Ganador de lotería/subasta bloqueado → transfer() revierte
    → nadie puede completar la distribución → protocolo atascado.
    Path B (protocolo bloqueado): Circle bloquea el propio contrato del protocolo →
    todos los usuarios pierden acceso a sus fondos.
    Path C (griefing): Atacante fuerza al lender/borrower a ser blacklisted → DoS de
    liquidaciones → bad debt acumula.
  invariante: |
    // No se puede invariar on-chain, pero arquitecturalmente:
    // nunca push tokens a usuarios en flujos críticos — usar pull pattern
    // mapping(address => uint256) public claimable;
    // function claim() external { ... token.safeTransfer(msg.sender, amount); }
  que_mirar:

## GREP TARGETS
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
    4. Usuario que deposita en este momento recibe shares de más → diluye a los existentes.
    5. Cuando alguien hace harvest, los 50 USDC "extra" aparecen como profit inesperado.
  invariante: |


### Grep targets adicionales (dex)
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



## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Trust boundary analysis: token quirks (ERC777) es relevante
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
ID prefix para este componente: `IAR` (ej: IAR-01, IAR-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_InterchainAccountRouter_TrustBoundaryHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: IAR-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "IAR-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Compiler Version Check (OBLIGATORIO)
1. Verifica la versión de Solidity del contrato
2. Consulta https://docs.soliditylang.org/en/latest/bugs.html — ¿hay bugs conocidos para esa versión?
3. Si usa Vyper: verificar que NO es 0.2.15-0.3.0 (reentrancy lock failure → $69M Curve hack 2023)

## Weird ERC-20 Checklist (d-xo — OBLIGATORIO si el contrato interactúa con tokens)
Para cada token que el contrato maneja, verificar:
- ¿Retorna bool en transfer/approve? (USDT, BNB, OMG NO retornan)
- ¿Requiere approve(0) antes de re-approve? (USDT, KNC)
- ¿Revierte en transfer de valor 0? (LEND)
- ¿Es rebasing? (stETH, AMPL — balance cambia sin transfer)
- ¿Tiene fee-on-transfer? (amount recibido < amount enviado)
- ¿Tiene blocklist? (USDC, USDT — pueden bloquear el contrato)
- ¿Usa SafeERC20 para todas las interacciones?

Si el contrato asume comportamiento estándar ERC-20 y acepta tokens arbitrarios → HIGH risk.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
