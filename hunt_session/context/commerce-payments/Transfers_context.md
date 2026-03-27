# Contexto de Hunt — Transfers

**Protocolo**: commerce-payments
**Dominio**: reentrancy
**LOC**: 581
**Archivo**: /home/kali/Documents/Web3/commerce-payments/contracts/transfers/Transfers.sol
**Generado**: 2026-03-27T14:51:44.344253Z

## Solodit Context
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

## Briefing del Dominio
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
    3. totalAssets() retorna 1000 en vez de 105

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar /home/kali/Documents/Web3/commerce-payments/contracts/transfers/Transfers.sol: Invalid compilation: 
Invalid solc compilation Error: Source "@openzeppelin/contracts/token/ERC20/IERC20.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:4:1:
  |
4 | import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:5:1:
  |
5 | import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/security/Pausable.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:6:1:
  |
6 | import "@openzeppelin/contracts/security/Pausable.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/security/ReentrancyGuard.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:7:1:
  |
7 | import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/utils/cryptography/ECDSA.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:8:1:
  |
8 | import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/access/Ownable.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/transfers/Transfers.sol:9:1:
  |
9 | import "@openzeppelin/contracts/access/Ownable.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/utils/Context.sol" not found: File not found. Searched the following locations: "".
  --> commerce-payments/contracts/transfers/Transfers.sol:10:1:
   |
10 | import "@openzeppelin/contracts/utils/Context.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@uniswap/universal-router/contracts/interfaces/IUniversalRouter.sol" not found: File not found. Searched the following locations: "".
  --> commerce-payments/contracts/transfers/Transfers.sol:11:1:
   |
11 | import "@uniswap/universal-router/contracts/interfaces/IUniversalRouter.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@uniswap/universal-router/contracts/libraries/Commands.sol" not found: File not found. Searched the following locations: "".
  --> commerce-payments/contracts/transfers/Transfers.sol:12:1:
   |
12 | import {Commands as UniswapCommands} from "@uniswap/universal-router/contracts/libraries/Commands.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@uniswap/universal-router/contracts/libraries/Constants.sol" not found: File not found. Searched the following locations: "".
  --> commerce-payments/contracts/transfers/Transfers.sol:13:1:
   |
13 | import {Constants as UniswapConstants} from "@uniswap/universal-router/contracts/libraries/Constants.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "commerce-payments/contracts/permit2/src/Permit2.sol" not found: File not found. Searched the following locations: "".
  --> commerce-payments/contracts/transfers/Transfers.sol:18:1:
   |
18 | import "../permit2/src/Permit2.sol";
   | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/interfaces/IERC2612.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/interfaces/IERC7597.sol:4:1:
  |
4 | import "@openzeppelin/contracts/interfaces/IERC2612.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "commerce-payments/contracts/permit2/src/interfaces/ISignatureTransfer.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/interfaces/ITransfers.sol:4:1:
  |
4 | import "../permit2/src/interfaces/ISignatureTransfer.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/token/ERC20/IERC20.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/interfaces/IWrappedNativeCurrency.sol:4:1:
  |
4 | import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/utils/Context.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/utils/Sweepable.sol:4:1:
  |
4 | import "@openzeppelin/contracts/utils/Context.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/access/Ownable.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/utils/Sweepable.sol:5:1:
  |
5 | import "@openzeppelin/contracts/access/Ownable.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/token/ERC20/IERC20.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/utils/Sweepable.sol:6:1:
  |
6 | import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Error: Source "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol" not found: File not found. Searched the following locations: "".
 --> commerce-payments/contracts/utils/Sweepable.sol:7:1:
  |
7 | import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^





