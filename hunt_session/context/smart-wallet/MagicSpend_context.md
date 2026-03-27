# Contexto de Hunt — MagicSpend

**Protocolo**: smart-wallet
**Dominio**: erc4337
**LOC**: 158
**Archivo**: /home/kali/Documents/Web3/MagicSpend/src/MagicSpend.sol
**Generado**: 2026-03-27T18:07:33.586888Z

## Solodit Context
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

## Briefing del Dominio
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
    3. callD

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar /home/kali/Documents/Web3/MagicSpend/src/MagicSpend.sol: Invalid compilation: 
Compilation failed. Can you run build command?
/home/kali/Documents/Web3/MagicSpend/out/build-info is not a directory.



