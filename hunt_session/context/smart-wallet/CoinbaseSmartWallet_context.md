# Contexto de Hunt — CoinbaseSmartWallet

**Protocolo**: smart-wallet
**Dominio**: trust
**LOC**: 169
**Archivo**: /home/kali/Documents/Web3/smart-wallet/src/CoinbaseSmartWallet.sol
**Generado**: 2026-03-27T16:44:44.528257Z

## Solodit Context
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

## Briefing del Dominio
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
 

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

# Deep Flatten — CoinbaseSmartWallet

Funciones analizadas: 1


## getUserOpHashWithoutChainId(UserOperation) [CRITICAL — mueve fondos]

[FUNC] [CoinbaseSmartWallet:L263-265] getUserOpHashWithoutChainId(UserOperation)
    [EXTERNAL] UserOperationLib.TMP_2259(bytes32) = LIBRARY_CALL, dest:UserOperationLib, function:UserOperationLib.hash(UserOperation), arguments:['userOp'] 


## Dependency Overrides — Assumptions de Librerías

El protocolo overridea estas funciones de librerías externas.
Verifica que el override NO viole las assumptions de la librería original.

### Override: `_isValidSignature()` (L318)
```solidity
    function _isValidSignature(bytes32 hash, bytes calldata signature) internal view virtual override returns (bool) {
        SignatureWrapper memory sigWrapper = abi.decode(signature, (SignatureWrapper));
        bytes memory ownerBytes = ownerAtIndex(sigWrapper.ownerIndex);

        if (ownerBytes.length == 32) {
            if (uint256(bytes32(ownerBytes)) > type(uint160).max) {
                // technically should be impossible given owners can only be added with
                // addOwne
```

*Original no encontrado en lib/ — verificar manualmente*

### Override: `_authorizeUpgrade()` (L352)
```solidity
    function _authorizeUpgrade(address) internal view virtual override(UUPSUpgradeable) onlyOwner {}
```

**Original** en `lib/p256-verifier/lib/openzeppelin-contracts/contracts/mocks/proxy/UUPSUpgradeableMock.sol`:
```solidity

    function _authorizeUpgrade(address) internal override {}
```

### Override: `_domainNameAndVersion()` (L355)
```solidity
    function _domainNameAndVersion() internal pure override(ERC1271) returns (string memory, string memory) {
        return ("Coinbase Smart Wallet", "1");
    }
```

**Original** en `lib/webauthn-sol/lib/solady/src/utils/EIP712.sol`:
```solidity


    /// @dev Please override this function to return the domain name and version.
    /// ```
    ///     function _domainNameAndVersion()
    ///         internal
    ///         pure
    ///         virtual
    ///         returns (string memory name, string memory version)
    ///     {
    ///         name = "Solady";
    ///         version = "1";
    ///     }
```

## Symmetric Analysis
# Symmetric Analysis — CoinbaseSmartWallet

No se encontraron pares simétricos.
