# OracleHunter — MagicSpend Analysis

## Tu Identidad
Eres el **OracleHunter** del equipo de bug hunting de smart-wallet.
Tu especialidad: **Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies**

## Tu Objetivo
Analizar `MagicSpend` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/MagicSpend/src/MagicSpend.sol`
**Dominio**: erc4337


## Asset Flow Map
### Money IN (deposits/receives)
- L118 receive(): accepts ETH via payable receive

### Money OUT (withdrawals/sends)
- L370 _withdraw(): SafeTransferLib.safeTransfer(asset, to, amount);

### Balance Reads (manipulation vectors)
- L33 <top-level>: /// @notice address(this).balance divided by maxWithdrawDenominator expresses the max WithdrawRequest.amount
- L86 <top-level>: /// @notice Thrown if WithdrawRequest.amount exceeds address(this).balance / maxWithdrawDenominator.
- L347 _validateRequest(): uint256 maxAllowed = address(this).balance / maxWithdrawDenominator;
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Ownable} from "solady/src/auth/Ownable.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";
import {SafeTransferLib} from "solady/src/utils/SafeTransferLib.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";

/// @title MagicSpend
///
/// @author Coinbase (https://github.com/coinbase/magic-spend)
///
/// @notice ERC4337 Paymaster implementation compatible with Entrypoint v0.6.
///
/// @dev See https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters.
contract MagicSpend is Ownable, IPaymaster {
    /// @notice Signed withdraw request allowing accounts to withdraw funds from this contract.
    struct WithdrawRequest {
        /// @dev The signature associated with this withdraw request.
        bytes signature;
        /// @dev The asset to withdraw.
        address asset;
        /// @dev The requested amount to withdraw.
        uint256 amount;
        /// @dev Unique nonce used to prevent replays.
        uint256 nonce;
        /// @dev The maximum expiry the withdraw request remains valid for.
        uint48 expiry;
    }

    /// @notice address(this).balance divided by maxWithdrawDenominator expresses the max WithdrawRequest.amount
    /// allowed for a native asset withdraw.
    ///
    /// @dev Helps prevent withdraws in the same transaction leading to reverts and hurting paymaster reputation.
    uint256 public maxWithdrawDenominator;

    /// @notice Track the amount of native asset available to be withdrawn per user.
    mapping(address user => uint256 amount) internal _withdrawable;

    /// @dev Mappings keeping track of already used nonces per user to prevent replays of withdraw requests.
    mapping(uint256 nonce => mapping(address user => bool used)) internal _nonceUsed;

    /// @notice Emitted after validating a withdraw request and funds are about to be withdrawn.
    ///
    /// @param account The account address.
    /// @param asset   The asset withdrawn.
    /// @param amount  The amount withdrawn.
    /// @param nonce   The request nonce.
    event MagicSpendWithdrawal(address indexed account, address indexed asset, uint256 amount, uint256 nonce);

    /// @notice Emitted when the `maxWithdrawDenominator` is set.
    ///
    /// @param newDenominator The new maxWithdrawDenominator value.
    event MaxWithdrawDenominatorSet(uint256 newDenominator);

    /// @notice Thrown when the withdraw request signature is invalid.
    ///
    /// @dev The withdraw request signature MUST be:
    ///         - an ECDSA signature following EIP-191 (version 0x45)
    ///         - performed over the content specified in `getHash()`
    ///         - signed by the current owner of this contract
    error InvalidSignature();

    /// @notice Thrown when trying to use a withdraw request after its expiry has been reached.
    error Expired();

    /// @notice Thrown when trying to replay a withdraw request with the same nonce.
    ///
    /// @param nonce The already used nonce.
    error InvalidNonce(uint256 nonce);

    /// @notice Thrown during validation in the context of ERC4337, when the withdraw request amount is insufficient
    ///         to sponsor the transaction gas.
    ///
    /// @param requested The withdraw request amount.
    /// @param maxCost   The max gas cost required by the Entrypoint.
    error RequestLessThanGasMaxCost(uint256 requested, uint256 maxCost);

    /// @notice Thrown when the withdraw request `asset` is not ETH (zero address).
    ///
    /// @param asset The requested asset.
    error UnsupportedPaymasterAsset(address asset);

    /// @notice Thrown if WithdrawRequest.amount exceeds address(this).balance / maxWithdrawDenominator.
    ///
    /// @param requestedAmount The requested amount excluding gas.
    /// @param maxAllowed      The current max allowed withdraw.
    error WithdrawTooLarge(uint256 requestedAmount, uint256 maxAllowed);

    /// @notice Thrown when trying to withdraw funds but nothing is available.
    error NoExcess();

    /// @notice Thrown when `postOp()` is called a second time with `PostOpMode.postOpReverted`.
    ///
    /// @dev This should only really occur if, for unknown reasons, the transfer of the withdrawable
    ///      funds to the user account failed (i.e. this contract's ETH balance is insufficient or
    ///      the user account refused the funds or ran out of gas on receive).
    error UnexpectedPostOpRevertedMode();

    /// @dev Requires that the caller is the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) revert Unauthorized();
        _;
    }

    /// @notice Deploy the contract and set its initial owner.
    ///
    /// @param owner_ The initial owner of this contract.
    /// @param maxWithdrawDenominator_ The initial maxWithdrawDenominator.
    constructor(address owner_, uint256 maxWithdrawDenominator_) {
        Ownable._initializeOwner(owner_);
        _setMaxWithdrawDenominator(maxWithdrawDenominator_);
    }

    /// @notice Receive function allowing ETH to be deposited in this contract.
    receive() external payable {}

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32, uint256 maxCost)
        external
        onlyEntryPoint
        returns (bytes memory context, uint256 validationData)
    {
        WithdrawRequest memory withdrawRequest = abi.decode(userOp.paymasterAndData[20:], (WithdrawRequest));
        uint256 withdrawAmount = withdrawRequest.amount;

        if (withdrawAmount < maxCost) {
            revert RequestLessThanGasMaxCost(withdrawAmount, maxCost);
        }

        if (withdrawRequest.asset != address(0)) {
            revert UnsupportedPaymasterAsset(withdrawRequest.asset);
        }

        _validateRequest(userOp.sender, withdrawRequest);

        bool sigFailed = !isValidWithdrawSignature(userOp.sender, withdrawRequest);
        validationData = (sigFailed ? 1 : 0) | (uint256(withdrawRequest.expiry) << 160);

        // NOTE: Do not include the gas part in withdrawable funds as it will be handled in `postOp()`.
        _withdrawable[userOp.sender] += withdrawAmount - maxCost;
        context = abi.encode(maxCost, userOp.sender);
    }

    /// @inheritdoc IPaymaster
    function postOp(IPaymaster.PostOpMode mode, bytes calldata context, uint256 actualGasCost)
        external
        onlyEntryPoint
    {
        // `PostOpMode.postOpReverted` should never happen.
        // The flow here can only revert if there are > maxWithdrawDenominator
        // withdraws in the same transaction, which should be highly unlikely.
        // If the ETH transfer fails, the entire bundle will revert due an issue in the EntryPoint
        // https://github.com/eth-infinitism/account-abstraction/pull/293
        if (mode == PostOpMode.postOpReverted) {
            revert UnexpectedPostOpRevertedMode();
        }

        (uint256 maxGasCost, address account) = abi.decode(context, (uint256, address));

        // Compute the total remaining funds available for the user accout.
        // NOTE: Take into account the user operation gas that was not consumed.
        uint256 withdrawable = _withdrawable[account] + (maxGasCost - actualGasCost);

        // Send the all remaining funds to the user accout.
        delete _withdrawable[account];
        if (withdrawable > 0) {
            SafeTransferLib.forceSafeTransferETH(account, withdrawable, SafeTransferLib.GAS_STIPEND_NO_STORAGE_WRITES);
        }
    }

    /// @notice Allows the sender to withdraw any available funds associated with their account.
    ///
    /// @dev Can be called back during the `UserOperation` execution to sponsor funds for non-gas related
    ///      use cases (e.g., swap or mint).
    function withdrawGasExcess() external {
        uint256 amount = _withdrawable[msg.sender];
        // we could allow 0 value transfers, but prefer to be explicit
        if (amount == 0) revert NoExcess();

        delete _withdrawable[msg.sender];
        _withdraw(address(0), msg.sender, amount);
    }

    /// @notice Allows the caller to withdraw funds by calling with a valid `withdrawRequest`.
    ///
    /// @param withdrawRequest The withdraw request.
    function withdraw(WithdrawRequest memory withdrawRequest) external {
        if (block.timestamp > withdrawRequest.expiry) {
            revert Expired();
        }

        if (!isValidWithdrawSignature(msg.sender, withdrawRequest)) {
            revert InvalidSignature();
        }

        _validateRequest(msg.sender, withdrawRequest);

        // reserve funds for gas, will credit user with difference in post op
        _withdraw(withdrawRequest.asset, msg.sender, withdrawRequest.amount);
    }

    /// @notice Withdraws funds from this contract.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param asset  The asset to withdraw.
    /// @param to     The beneficiary address.
    /// @param amount The amount to withdraw.
    function ownerWithdraw(address asset, address to, uint256 amount) external onlyOwner {
        _withdraw(asset, to, amount);
    }

    /// @notice Transfers ETH from this contract into the EntryPoint.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param amount The amount to deposit on the the Entrypoint.
    function entryPointDeposit(uint256 amount) external payable onlyOwner {
        SafeTransferLib.safeTransferETH(entryPoint(), amount);
    }

    /// @notice Withdraws ETH from the EntryPoint.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param to     The beneficiary address.
    /// @param amount The amount to withdraw from the Entrypoint.
    function entryPointWithdraw(address payable to, uint256 amount) external onlyOwner {
        IEntryPoint(entryPoint()).withdrawTo(to, amount);
    }

    /// @notice Adds stake to the EntryPoint.
    ///
    /// @dev Reverts if not called by the owner of the contract. Calling this while an unstake
    ///      is pending will first cancel the pending unstake.
    ///
    /// @param amount              The amount to stake in the Entrypoint.
    /// @param unstakeDelaySeconds The duration for which the stake cannot be withdrawn. Must be
    ///                            equal to or greater than the current unstake delay.
    function entryPointAddStake(uint256 amount, uint32 unstakeDelaySeconds) external payable onlyOwner {
        IEntryPoint(entryPoint()).addStake{value: amount}(unstakeDelaySeconds);
    }

    /// @notice Unlocks stake in the EntryPoint.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    function entryPointUnlockStake() external onlyOwner {
        IEntryPoint(entryPoint()).unlockStake();
    }

    /// @notice Withdraws stake from the EntryPoint.
    ///
    /// @dev Reverts if not called by the owner of the contract. Only call this after the unstake delay
    ///      has passed since the last `entryPointUnlockStake` call.
    ///
    /// @param to The beneficiary address.
    function entryPointWithdrawStake(address payable to) external onlyOwner {
        IEntryPoint(entryPoint()).withdrawStake(to);
    }

    /// @notice Sets maxWithdrawDenominator.
    ///
    /// @dev Reverts if not called by the owner of the contract.
    ///
    /// @param newDenominator The new value for maxWithdrawDenominator.
    function setMaxWithdrawDenominator(uint256 newDenominator) external onlyOwner {
        _setMaxWithdrawDenominator(newDenominator);
    }

    /// @notice Returns whether the `withdrawRequest` signature is valid for the given `account`.
    ///
    /// @dev Does not validate nonce or expiry.
    ///
    /// @param account         The account address.
    /// @param withdrawRequest The withdraw request.
    ///
    /// @return `true` if the signature is valid, else `false`.
    function isValidWithdrawSignature(address account, WithdrawRequest memory withdrawRequest)
        public
        view
        returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNow(
            owner(), getHash(account, withdrawRequest), withdrawRequest.signature
        );
    }

    /// @notice Returns the hash to be signed for a given `account` and `withdrawRequest` pair.
    ///
    /// @dev Returns an EIP-191 compliant Ethereum Signed Message (version 0x45), see
    ///      https://eips.ethereum.org/EIPS/eip-191.
    ///
    /// @param account         The account address.
    /// @param withdrawRequest The withdraw request.
    ///
    /// @return The hash to be signed for the given `account` and `withdrawRequest`.
    function getHash(address account, WithdrawRequest memory withdrawRequest) public view returns (bytes32) {
        return SignatureCheckerLib.toEthSignedMessageHash(
            abi.encode(
                address(this),
                account,
                block.chainid,
                withdrawRequest.asset,
                withdrawRequest.amount,
                withdrawRequest.nonce,
                withdrawRequest.expiry
            )
        );
    }

    /// @notice Returns whether the `nonce` has been used by the given `account`.
    ///
    /// @param account The account address.
    /// @param nonce   The nonce to check.
    ///
    /// @return `true` if the nonce has already been used by the account, else `false`.
    function nonceUsed(address account, uint256 nonce) external view returns (bool) {
        return _nonceUsed[nonce][account];
    }

    /// @notice Returns the canonical ERC-4337 EntryPoint v0.6 contract.
    function entryPoint() public pure returns (address) {
        return 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    }

    function _setMaxWithdrawDenominator(uint256 newDenominator) internal {
        maxWithdrawDenominator = newDenominator;

        emit MaxWithdrawDenominatorSet(newDenominator);
    }

    /// @notice Validate the `withdrawRequest` against the given `account`.
    ///
    /// @dev Runs all non-signature validation checks.
    /// @dev Reverts if the withdraw request nonce has already been used.
    ///
    /// @param account         The account address.
    /// @param withdrawRequest The withdraw request to validate.
    function _validateRequest(address account, WithdrawRequest memory withdrawRequest) internal {
        if (_nonceUsed[withdrawRequest.nonce][account]) {
            revert InvalidNonce(withdrawRequest.nonce);
        }

        uint256 maxAllowed = address(this).balance / maxWithdrawDenominator;
        if (withdrawRequest.asset == address(0) && withdrawRequest.amount > maxAllowed) {
            revert WithdrawTooLarge(withdrawRequest.amount, maxAllowed);
        }

        _nonceUsed[withdrawRequest.nonce][account] = true;

        // This is emitted ahead of fund transfer, but allows a consolidated code path
        emit MagicSpendWithdrawal(account, withdrawRequest.asset, withdrawRequest.amount, withdrawRequest.nonce);
    }

    /// @notice Withdraws funds from this contract.
    ///
    /// @dev Callers MUST validate that the withdraw is legitimate before calling this method as
    ///      no validation is performed here.
    ///
    /// @param asset  The asset to withdraw.
    /// @param to     The beneficiary address.
    /// @param amount The amount to withdraw.
    function _withdraw(address asset, address to, uint256 amount) internal {
        if (asset == address(0)) {
            SafeTransferLib.safeTransferETH(to, amount);
        } else {
            SafeTransferLib.safeTransfer(asset, to, amount);
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre MagicSpend
Buscando 'MagicSpend' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (21ms)

 1. [LOW] MagicSpend.withdraw() calls are exposed to frontrun attacks — Coinbase Session Keys
 2. [MEDIUM] [M-02] Users can front run the signature of the paymaster operation leading to s — Coinbase
 3. [MEDIUM] [M-01] Balance check during `MagicSpend` validation cannot ensure that `MagicSpe — Coinbase
 4. [LOW] Accounting for _gasMaxCostExcess can be more precise  — Coinbase
 5. [LOW] [N-02] Comment mismatch on future enhanced asset support in MagicSpend — Coinbase

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: MagicSpend | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] MagicSpend.withdraw() calls are exposed to frontrun attacks (Coinbase Session Keys)
   ## Severity: Low Risk

## Context
**File:** PermissionCallableAllowedContractNativeTokenRecurringAllowance.sol  
**Line Range:** L130-L140

## Descrip...

2. [MEDIUM] [M-02] Users can front run the signature of the paymaster operation leading to some problems (Coinbase)
   
The paymaster is an extension of the eip-4337, normally the paymaster is willing to pay a user transaction if the account can return the amount of ga...

3. [MEDIUM] [M-01] Balance check during `MagicSpend` validation cannot ensure that `MagicSpend` has enough balance to cover the requested fund (Coinbase)
   
[Balance check](https://github.com/code-423n4/2024-03-coinbase/blob/e0573369b865d47fed778de00a7b6df65ab1744e/src/MagicSpend/MagicSpend.sol#L130-L135)...

4. [LOW] Accounting for _gasMaxCostExcess can be more precise  (Coinbase)
   ## MagicSpend Contract Analysis

## Context
- MagicSpend.sol#L68
- MagicSpend.sol#L78-L80

## Description
In the MagicSpend contract, the `_gasMaxCost...

5. [LOW] [N-02] Comment mismatch on future enhanced asset support in MagicSpend (Coinbase)
   MagicSpend.sol, initially documented to support only ETH withdrawals, inherently possesses a broader capability to manage multiple asset types, includ...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio erc4337
Buscando 'MagicSpend validatePaymasterUserOp withdrawGasExcess withdraw ownerWithdraw' [SQLite FTS5] (dominio: erc4337)...
Top 6 findings relevantes: (212ms)
 1. [HIGH] Users can double withdraw their excess ETH  — Coinbase
 2. [HIGH] [H-03] Users Can Escape Paying for the TX Gas — Etherspot Gastankpaymastermodule Extended
 3. [HIGH] [H-05] Paymaster ETH can be drained with malicious sender — Biconomy
 4. [HIGH] [H-01] `finalizeVaultEndedWithdrawals()` will fail when last withdrawal request  — Saffron
 5. [HIGH] Function `claimEffectiveBalance()` may consistently revert, making it impossible — Casimir
 6. [HIGH] mod/state-transition/pkg/core/state/ExpectedWithdrawals returns error if non-0x0 — Berachain Beaconkit
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: MagicSpend validatePaymasterUserOp withdrawGasExcess withdraw ownerWithdraw | Dominio: erc4337
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Users can double withdraw their excess ETH  (Coinbase)
   ## MagicSpend Contract Analysis
## Context
MagicSpend.sol#L74-L91
## Description
When the MagicSpend contract is used as an ERC-4337 compatible paym...
2. [HIGH] [H-03] Users Can Escape Paying for the TX Gas (Etherspot Gastankpaymastermodule Extended)
## Severity
High Risk
## Description
The current implementation of Paymaster is not taking the amount of gas paid by the paymaster for the tx exec...
3. [HIGH] [H-05] Paymaster ETH can be drained with malicious sender (Biconomy)
[contracts/smart-contract-wallet/paymasters/verifying/singleton/VerifyingSingletonPaymaster.sol#L97-L111](https://g

## Briefing del Dominio (erc4337)
### Briefing principal: erc4337

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ El paymaster puede ser legítimamente multi-sender — no confundir con bug
  ⚠ Si el sender es un proxy con timelock de upgrade, el riesgo es menor
  ⚠ En EntryPoint v0.7+ el depósito se lockea automáticamente -- verificar versión
  ⚠ Si withdraw() tiene un delay de cooldown, el ataque es menos práctico
  ⚠ El finding puede estar fixeado en versiones posteriores de MagicSpend -- verificar commit
  ⚠ Si postOp es llamado por el EntryPoint, el reentrancy directo no aplica, pero el double-claim sí
  ⚠ Algunos paymasters sponsorizan intencionalmente (usuario no paga) -- solo es bug si el protocolo asume cobro
  ⚠ Paymasters con depósito pre-cargado en EntryPoint no tienen este problema
  ⚠ El nonce del EntryPoint protege contra replay del userOpHash completo -- el bug ocurre cuando el módulo valida datos DENTRO del callData por un path separado
  ⚠ Si validUntil es en el pasado, el replay falla igualmente -- confirmar ventana de validez
  ⚠ El EntryPoint llama validateUserOp con el hash correcto -- el bug surge cuando el módulo NO confía en esto y necesita re-verificarlo para paths custom
  ⚠ Si el módulo solo se usa como hook (no como validator primario), el riesgo puede ser menor

## CHECKLIST DE INVARIANTES
```yaml
- id: aa-010
  pattern: session-key-cross-owner-impersonation
  name: "Session key owner firma consumiendo sesión de otro owner"
  causa_raiz: >
    Cuando un wallet tiene múltiples sesiones activas, validateUserOp verifica
    que el firmante es un sessionKey registrado del wallet (check correcto).
    Pero no verifica que el sessionKey en el callData de claim() es el mismo
    sessionKey que firmó la operación. Un sessionKey válido puede firmar mensajes
    que consumen el sessionKey de otro owner.
  como_funciona: |
    1. Wallet W tiene dos sesiones: sessionKeyA (owner A) y sessionKeyB (owner B)
    2. validateUserOp verifica: firmante es sessionKey registrado de W ✓
    3. callData: claim(sessionKey=sessionKeyA)  -- owner B firma consumiendo el key de A
    4. No hay check: ¿el firmante de este claim ES sessionKeyA?
    5. Owner B drena los tokens asignados a la sesión de owner A
  invariante: >
    Si la función consume/invalida sessionKeyX, la firma de la UserOp DEBE
    pertenecer a sessionKeyX. El firmante y la sessionKey afectada deben coincidir.
  que_mirar:

## GREP TARGETS
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
    1. Chain A: owners = [keyA, keyB, keyC]. Usuario añade keyD on-chain.
    2. Chain B: usuarios usa executeWithoutChainIdValidation -- owners = [keyA, keyB] (diferente estado)
    3. Usuario quiere eliminar keyB (index=1) en ambas chains



## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Price manipulation) es relevante
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
ID prefix para este componente: `MS` (ej: MS-01, MS-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_MagicSpend_OracleHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: MS-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "MS-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Oracle Deep Check (OBLIGATORIO — para cada fuente de precio)
NOTA: Flash Loan Hypothesis (12 preguntas) es responsabilidad de FlowHunter. NO la dupliques aquí.
Enfócate en tu especialidad: ORÁCULOS y fuentes de precio.
Para CADA llamada a latestRoundData() o equivalente:
1. ¿Se verifica updatedAt contra un heartbeat? ¿El heartbeat es ESPECÍFICO por feed o genérico?
2. ¿Se chequea answeredInRound >= roundId?
3. ¿Se chequea price > 0?
4. ¿Hay check de L2 sequencer down? (Arbitrum/Optimism/Base: sequencerUptimeFeed)
5. ¿Existe minAnswer/maxAnswer que clampea el precio en flash crashes?
6. ¿El oracle puede ser sandwicheado? (front-run de oracle update para explotar el vault)

Oracle-Liquidity Mismatch (cmichel/Rari): ¿cuánto capital se necesita para manipular el oracle vs cuánto se puede extraer? Si manipulación < extracción → explotable.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
