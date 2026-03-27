# MathHunter — CoinbaseSmartWallet Analysis

## Tu Identidad
Eres el **MathHunter** del equipo de bug hunting de smart-wallet.
Tu especialidad: **Overflow, rounding, precision, exchange rate math, share price manipulation**

## Tu Objetivo
Analizar `CoinbaseSmartWallet` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/smart-wallet/src/CoinbaseSmartWallet.sol`
**Dominio**: trust


## Asset Flow Map
### Money OUT (withdrawals/sends)
- L304 _call(): (bool success, bytes memory result) = target.call{value: value}(data);
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IAccount} from "account-abstraction/interfaces/IAccount.sol";

import {UserOperation, UserOperationLib} from "account-abstraction/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

import {ERC1271} from "./ERC1271.sol";
import {MultiOwnable} from "./MultiOwnable.sol";

/// @title Coinbase Smart Wallet
///
/// @notice ERC-4337-compatible smart account, based on Solady's ERC4337 account implementation
///         with inspiration from Alchemy's LightAccount and Daimo's DaimoAccount.
///
/// @author Coinbase (https://github.com/coinbase/smart-wallet)
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
contract CoinbaseSmartWallet is ERC1271, IAccount, MultiOwnable, UUPSUpgradeable, Receiver {
    /// @notice A wrapper struct used for signature validation so that callers
    ///         can identify the owner that signed.
    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `MultiOwnable.ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }

    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    /// @notice Reserved nonce key (upper 192 bits of `UserOperation.nonce`) for cross-chain replayable
    ///         transactions.
    ///
    /// @dev MUST BE the `UserOperation.nonce` key when `UserOperation.calldata` is calling
    ///      `executeWithoutChainIdValidation`and MUST NOT BE `UserOperation.nonce` key when `UserOperation.calldata` is
    ///      NOT calling `executeWithoutChainIdValidation`.
    ///
    /// @dev Helps enforce sequential sequencing of replayable transactions.
    uint256 public constant REPLAYABLE_NONCE_KEY = 8453;

    /// @notice Thrown when `initialize` is called but the account already has had at least one owner.
    error Initialized();

    /// @notice Thrown when a call is passed to `executeWithoutChainIdValidation` that is not allowed by
    ///         `canSkipChainIdValidation`
    ///
    /// @param selector The selector of the call.
    error SelectorNotAllowed(bytes4 selector);

    /// @notice Thrown in validateUserOp if the key of `UserOperation.nonce` does not match the calldata.
    ///
    /// @dev Calls to `this.executeWithoutChainIdValidation` MUST use `REPLAYABLE_NONCE_KEY` and
    ///      calls NOT to `this.executeWithoutChainIdValidation` MUST NOT use `REPLAYABLE_NONCE_KEY`.
    ///
    /// @param key The invalid `UserOperation.nonce` key.
    error InvalidNonceKey(uint256 key);

    /// @notice Thrown when an upgrade is attempted to an implementation that does not exist.
    ///
    /// @param implementation The address of the implementation that has no code.
    error InvalidImplementation(address implementation);

    /// @notice Reverts if the caller is not the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert Unauthorized();
        }

        _;
    }

    /// @notice Reverts if the caller is neither the EntryPoint, the owner, nor the account itself.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) {
            _checkOwner();
        }

        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @dev Subclass MAY override this modifier for better funds management (e.g. send to the
    ///      EntryPoint more than the minimum required, so that in future transactions it will not
    ///      be required to send again).
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    constructor() {
        // Implementation should not be initializable (does not affect proxies which use their own storage).
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        _initializeOwners(owners);
    }

    /// @notice Initializes the account with the `owners`.
    ///
    /// @dev Reverts if the account has had at least one owner, i.e. has been initialized.
    ///
    /// @param owners Array of initial owners for this account. Each item should be
    ///               an ABI encoded Ethereum address, i.e. 32 bytes with 12 leading 0 bytes,
    ///               or a 64 byte public key.
    function initialize(bytes[] calldata owners) external payable virtual {
        if (nextOwnerIndex() != 0) {
            revert Initialized();
        }

        _initializeOwners(owners);
    }

    /// @inheritdoc IAccount
    ///
    /// @notice ERC-4337 `validateUserOp` method. The EntryPoint will
    ///         call `UserOperation.sender.call(UserOperation.callData)` only if this validation call returns
    ///         successfully.
    ///
    /// @dev Signature failure should be reported by returning 1 (see: `this._isValidSignature`). This
    ///      allows making a "simulation call" without a valid signature. Other failures (e.g. invalid signature format)
    ///      should still revert to signal failure.
    /// @dev Reverts if the `UserOperation.nonce` key is invalid for `UserOperation.calldata`.
    /// @dev Reverts if the signature format is incorrect or invalid for owner type.
    ///
    /// @param userOp              The `UserOperation` to validate.
    /// @param userOpHash          The `UserOperation` hash, as computed by `EntryPoint.getUserOpHash(UserOperation)`.
    /// @param missingAccountFunds The missing account funds that must be deposited on the Entrypoint.
    ///
    /// @return validationData The encoded `ValidationData` structure:
    ///                        `(uint256(validAfter) << (160 + 48)) | (uint256(validUntil) << 160) | (success ? 0 : 1)`
    ///                        where `validUntil` is 0 (indefinite) and `validAfter` is 0.
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        uint256 key = userOp.nonce >> 64;

        if (bytes4(userOp.callData) == this.executeWithoutChainIdValidation.selector) {
            userOpHash = getUserOpHashWithoutChainId(userOp);
            if (key != REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }

            // Check for upgrade calls in the batch and validate implementation has code
            bytes[] memory calls = abi.decode(userOp.callData[4:], (bytes[]));
            for (uint256 i; i < calls.length; i++) {
                bytes memory callData = calls[i];
                bytes4 selector = bytes4(callData);

                if (selector == UUPSUpgradeable.upgradeToAndCall.selector) {
                    address newImplementation;
                    assembly {
                        // Skip reading the first 32 bytes (length prefix) + 4 bytes (function selector)
                        newImplementation := mload(add(callData, 36))
                    }
                    if (newImplementation.code.length == 0) revert InvalidImplementation(newImplementation);
                }
            }
        } else {
            if (key == REPLAYABLE_NONCE_KEY) {
                revert InvalidNonceKey(key);
            }
        }

        // Return 0 if the recovered address matches the owner.
        if (_isValidSignature(userOpHash, userOp.signature)) {
            return 0;
        }

        // Else return 1
        return 1;
    }

    /// @notice Executes `calls` on this account (i.e. self call).
    ///
    /// @dev Can only be called by the Entrypoint.
    /// @dev Reverts if the given call is not authorized to skip the chain ID validtion.
    /// @dev `validateUserOp()` will recompute the `userOpHash` without the chain ID before validating
    ///      it if the `UserOperation.calldata` is calling this function. This allows certain UserOperations
    ///      to be replayed for all accounts sharing the same address across chains. E.g. This may be
    ///      useful for syncing owner changes.
    ///
    /// @param calls An array of calldata to use for separate self calls.
    function executeWithoutChainIdValidation(bytes[] calldata calls) external payable virtual onlyEntryPoint {
        for (uint256 i; i < calls.length; i++) {
            bytes calldata call = calls[i];
            bytes4 selector = bytes4(call);
            if (!canSkipChainIdValidation(selector)) {
                revert SelectorNotAllowed(selector);
            }

            _call(address(this), 0, call);
        }
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The address to call.
    /// @param value  The value to send with the call.
    /// @param data   The data of the call.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        virtual
        onlyEntryPointOrOwner
    {
        _call(target, value, data);
    }

    /// @notice Executes batch of `Call`s.
    ///
    /// @dev Can only be called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrOwner {
        for (uint256 i; i < calls.length; i++) {
            _call(calls[i].target, calls[i].value, calls[i].data);
        }
    }

    /// @notice Returns the address of the EntryPoint v0.6.
    ///
    /// @return The address of the EntryPoint v0.6
    function entryPoint() public view virtual returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    /// @notice Computes the hash of the `UserOperation` in the same way as EntryPoint v0.6, but
    ///         leaves out the chain ID.
    ///
    /// @dev This allows accounts to sign a hash that can be used on many chains.
    ///
    /// @param userOp The `UserOperation` to compute the hash for.
    ///
    /// @return The `UserOperation` hash, which does not depend on chain ID.
    function getUserOpHashWithoutChainId(UserOperation calldata userOp) public view virtual returns (bytes32) {
        return keccak256(abi.encode(UserOperationLib.hash(userOp), entryPoint()));
    }

    /// @notice Returns the implementation of the ERC1967 proxy.
    ///
    /// @return $ The address of implementation contract.
    function implementation() public view returns (address $) {
        assembly {
            $ := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
    }

    /// @notice Returns whether `functionSelector` can be called in `executeWithoutChainIdValidation`.
    ///
    /// @param functionSelector The function selector to check.
    ////
    /// @return `true` is the function selector is allowed to skip the chain ID validation, else `false`.
    function canSkipChainIdValidation(bytes4 functionSelector) public pure returns (bool) {
        if (
            functionSelector == MultiOwnable.addOwnerPublicKey.selector
                || functionSelector == MultiOwnable.addOwnerAddress.selector
                || functionSelector == MultiOwnable.removeOwnerAtIndex.selector
                || functionSelector == MultiOwnable.removeLastOwner.selector
                || functionSelector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            return true;
        }
        return false;
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if the call reverted.
    /// @dev Implementation taken from
    /// https://github.com/alchemyplatform/light-account/blob/43f625afdda544d5e5af9c370c9f4be0943e4e90/src/common/BaseLightAccount.sol#L125
    ///
    /// @param target The target call address.
    /// @param value  The call value to user.
    /// @param data   The raw call data.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /// @inheritdoc ERC1271
    ///
    /// @dev Used by both `ERC1271.isValidSignature` AND `IAccount.validateUserOp` signature validation.
    /// @dev Reverts if owner at `ownerIndex` is not compatible with `signature` format.
    ///
    /// @param signature ABI encoded `SignatureWrapper`.
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                // technically should be impossible given owners can only be added with
                // addOwnerAddress and addOwnerPublicKey, but we leave incase of future changes.
                revert InvalidEthereumAddressOwner(ownerBytes);
            }

            address owner;
            assembly ("memory-safe") {
                owner := mload(add(ownerBytes, 32))
            }

            return SignatureCheckerLib.isValidSignatureNow(owner, hash, sigWrapper.signatureData);
        }

        if (ownerBytes.length == 64) {
            (uint256 x, uint256 y) = abi.decode(ownerBytes, (uint256, uint256));

            WebAuthn.WebAuthnAuth memory auth = abi.decode(sigWrapper.signatureData, (WebAuthn.WebAuthnAuth));

            return WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: x, y: y});
        }

        revert InvalidOwnerBytesLength(ownerBytes);
    }

    /// @inheritdoc UUPSUpgradeable
    ///
    /// @dev Authorization logic is only based on the `msg.sender` being an owner of this account,
    ///      or `address(this)`.
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre CoinbaseSmartWallet
Buscando 'CoinbaseSmartWallet' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (14ms)

 1. [GAS] The usage of the [0:4] operator in CoinbaseSmartWallet is redundant  — Coinbase
 2. [LOW] [L-04] Missing check for passkey associated with `CoinbaseSmartWallet._validateS — Coinbase
 3. [LOW] _transferFrom() does not revert for not-yet-deployed tokens  — Coinbase
 4. [LOW] Simplify conditional execution  — Coinbase
 5. [LOW] [N-03] Incorrect comment associated with `CoinbaseSmartWallet._validateSignature — Coinbase

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: CoinbaseSmartWallet | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [GAS] The usage of the [0:4] operator in CoinbaseSmartWallet is redundant  (Coinbase)
   ## Code Review: CoinbaseSmartWallet

## Context
- CoinbaseSmartWallet.sol#L148
- CoinbaseSmartWallet.sol#L184

## Description
CoinbaseSmartWallet make...

2. [LOW] [L-04] Missing check for passkey associated with `CoinbaseSmartWallet._validateSignature()` (Coinbase)
   Neither passkey nor an address goes through checks as implemented in [MultiOwnable._initializeOwners()](https://github.com/code-423n4/2024-03-coinbase...

3. [LOW] _transferFrom() does not revert for not-yet-deployed tokens  (Coinbase)
   ## Context
- `SpendPermissionManager.sol#L492-L497`
- `SpendPermissionManager.sol#L507-L509`
- `CoinbaseSmartWallet.sol#L282-L289`

## Description
Whe...

4. [LOW] Simplify conditional execution  (Coinbase)
   ## Code Review Note

## Context
`CoinbaseSmartWalletFactory.sol#L53`

## Description
The current implementation uses an explicit comparison with `fals...

5. [LOW] [N-03] Incorrect comment associated with `CoinbaseSmartWallet._validateSignature()` (Coinbase)
   The comment below is inaccurate,

https://github.com/code-423n4/2024-03-coinbase/blob/main/src/SmartWallet/CoinbaseSmartWallet.sol#L301-L306

```solid...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'CoinbaseSmartWallet validateUserOp executeWithoutChainIdValidation execute execu' [SQLite FTS5] (dominio: trust)...
Top 6 findings relevantes: (37ms)
 1. [HIGH] [H-01] Remove owner calls can be replayed to remove a different owner at the sam — Coinbase
 2. [HIGH] [C-08] In `ResourceLockValidator`, the `validateUserOp()` Function Lacks Suffici — Etherspot Credibleaccountmodule
 3. [HIGH] userOp validation is skipped in simulation mode for smart contract user accounts — Fastlane Atlas
 4. [HIGH] `_execute` allows you to execute unsuccessful tasks in the future — CloudWalk
 5. [HIGH] [H-02] In `CredibleAccountModule` the `validateUserOp()` Function Is Not Authent — Etherspot Credibleaccountmodule
 6. [HIGH] [C-07] In `ResourceLockValidator` the `validateUserOp()` Function Is Not Consumi — Etherspot Credibleaccountmodule
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: CoinbaseSmartWallet validateUserOp executeWithoutChainIdValidation execute execu | Dominio: trust
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] [H-01] Remove owner calls can be replayed to remove a different owner at the same index, leading to severe issues when combined with lack of last owner guard (Coinbase)
Users are able to upgrade their account's owners via either directly onto the contract with a regular transaction or via an ERC-4337 EntryPoint trans...
2. [HIGH] [C-08] In `ResourceLockValidator`, the `validateUserOp()` Function Lacks Sufficient Checks, Allowing Draining of `ModularEtherspotWallet` Balances (Etherspot Credibleaccountmodule)
## Severity
Critical Risk
## Summary
This is a collection of issues with different root causes, we grouped them in a single insta

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


### Grep targets adicionales (erc4337)
```yaml
- id: aa-012
  pattern: remove-owner-cross-chain-index-replay
  name: "removeOwnerAtIndex replay cross-chain -- borra owner diferente por índice"
  causa_raiz: >
    CoinbaseSmartWallet permite removeOwnerAtIndex(index, owner) tanto via
    transacción directa como via executeWithoutChainIdValidation() (para operaciones
    que deben ser consistentes entre chains). Si un usuario usa ambos métodos en
    chains diferentes, el array de owners puede tener índices distintos en cada chain.
    Una llamada removeOwnerAtIndex en chain B remueve el owner EN ESE ÍNDICE de chain B,
    que puede ser diferente al owner en ese índice en chain A.
  como_funciona: |



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
ID prefix para este componente: `CSW` (ej: CSW-01, CSW-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_CoinbaseSmartWallet_MathHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: CSW-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "CSW-01: value decreased");
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
