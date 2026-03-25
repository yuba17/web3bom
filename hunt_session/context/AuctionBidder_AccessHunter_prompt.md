# AccessHunter — AuctionBidder Analysis

## Tu Identidad
Eres el **AccessHunter** del equipo de bug hunting de chainlink-pa-v2.
Tu especialidad: **Access control, missing modifiers, privilege escalation, role misconfig**

## Tu Objetivo
Analizar `AuctionBidder` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/chainlink-pa-v2/src/AuctionBidder.sol`
**Dominio**: dex


```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {ITypeAndVersion} from "@chainlink/contracts/src/v0.8/shared/interfaces/ITypeAndVersion.sol";
import {IAuctionCallback} from "src/interfaces/IAuctionCallback.sol";
import {IBaseAuction} from "src/interfaces/IBaseAuction.sol";

import {Caller} from "src/Caller.sol";
import {PausableWithAccessControl} from "src/PausableWithAccessControl.sol";
import {Common} from "src/libraries/Common.sol";
import {Errors} from "src/libraries/Errors.sol";
import {Roles} from "src/libraries/Roles.sol";

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @title Auction Bidder v1.0.0 Contract.
/// @notice This contract is responsible for bidding on auctions and executing arbitrary logic to solve the auction.
contract AuctionBidder is PausableWithAccessControl, Caller, IAuctionCallback, ITypeAndVersion {
  using SafeERC20 for IERC20;

  /// @notice This event is emitted when the auction contract is set.
  /// @param auction The address of the auction contract.
  event AuctionContractSet(address indexed auction);
  /// @notice This event is emitted when the receiver address is set.
  /// @param receiver The address of the receiver.
  event ReceiverSet(address indexed receiver);

  /// @notice This error is thrown when an invalid auction contract is provided.
  error InvalidAuctionContract(address auction);

  /// @inheritdoc ITypeAndVersion
  string public constant override typeAndVersion = "AuctionBidder 1.0.0-dev";

  /// @notice The auction contract.
  IBaseAuction private s_auction;

  /// @notice Optional receiver address. This address will receive any leftover funds after bidding.
  address private s_receiver;

  constructor(
    uint48 adminRoleTransferDelay,
    address admin,
    address auction,
    address receiver
  ) PausableWithAccessControl(adminRoleTransferDelay, admin) {
    _setAuction(auction);

    if (receiver != address(0)) {
      _setReceiver(receiver);
    }
  }

  // ================================================================================================
  // │                                    Auction Participation                                     │
  // ================================================================================================

  /// @notice Bids on the auction contract and optionally executes arbitrary pre-bid logic.
  /// @dev precondition - the contract must not be paused.
  /// @dev precondition - the caller must have the AUCTION_BIDDER_ROLE.
  /// @param assetIn The address of the asset to bid with.
  /// @param amount The amount of the asset to bid.
  /// @param solution The list of calls to execute to solve the bid.
  function bid(
    address assetIn,
    uint256 amount,
    Call[] calldata solution
  ) external whenNotPaused onlyRole(Roles.AUCTION_BIDDER_ROLE) {
    IBaseAuction auction = s_auction;
    address assetOut = auction.getAssetOut();

    bytes memory data;

    if (solution.length > 0) {
      data = abi.encode(solution);
    } else {
      IERC20(assetOut).forceApprove(address(auction), s_auction.getAssetOutAmount(assetIn, amount, block.timestamp));
    }

    auction.bid(assetIn, amount, data);

    uint256 assetOutBalance = IERC20(assetOut).balanceOf(address(this));

    if (assetOutBalance > 0) {
      address receiver = s_receiver;

      if (receiver != address(0)) {
        IERC20(assetOut).safeTransfer(receiver, assetOutBalance);
      }
    }
  }

  /// @inheritdoc IAuctionCallback
  /// @dev precondition - the contract must not be paused.
  /// @dev precondition - the caller must be the auction contract.
  function auctionCallback(
    address from,
    address assetOut,
    uint256 amountOut,
    bytes calldata data
  ) external whenNotPaused {
    if (msg.sender != address(s_auction) || from != address(this)) {
      revert Errors.AccessForbidden();
    }

    (Call[] memory calls) = abi.decode(data, (Call[]));

    _multiCall(calls);

    IERC20(assetOut).forceApprove(msg.sender, amountOut);
  }

  /// @notice Withdraws any tokens from the contract.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @dev precondition - the `to` address must not be the zero address.
  /// @param assetAmounts The asset and amounts to withdraw.
  /// @param to The address to send the withdrawn tokens to.
  function withdraw(
    Common.AssetAmount[] calldata assetAmounts,
    address to
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (to == address(0)) {
      revert Errors.InvalidZeroAddress();
    }

    for (uint256 i = 0; i < assetAmounts.length; ++i) {
      Common.AssetAmount memory assetAmount = assetAmounts[i];
      IERC20(assetAmount.asset).safeTransfer(to, assetAmount.amount);
    }
  }

  // ================================================================================================
  // │                                        Configuration                                         │
  // ================================================================================================

  /// @notice Sets the auction contract.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @param auction The address of the auction contract.
  function setAuction(
    address auction
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _setAuction(auction);
  }

  /// @notice Internal function to set the auction contract.
  /// @dev precondition - the auction address must not be zero.
  /// @dev precondition - the auction contract must implement the IBaseAuction interface.
  /// @param auction The address of the auction contract.
  function _setAuction(
    address auction
  ) private {
    if (auction == address(0)) {
      revert Errors.InvalidZeroAddress();
    }
    if (!IERC165(auction).supportsInterface(type(IBaseAuction).interfaceId)) {
      revert InvalidAuctionContract(auction);
    }
    if (address(s_auction) == auction) {
      revert Errors.ValueNotUpdated();
    }

    s_auction = IBaseAuction(auction);

    emit AuctionContractSet(auction);
  }

  /// @notice Sets the receiver address.
  /// @dev precondition - the caller must have the DEFAULT_ADMIN_ROLE.
  /// @param receiver The address of the receiver.
  function setReceiver(
    address receiver
  ) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _setReceiver(receiver);
  }

  /// @notice Internal function to set the receiver address.
  /// @dev precondition - the receiver address must be different from the current one.
  /// @param receiver The address of the receiver.
  function _setReceiver(
    address receiver
  ) private {
    if (receiver == s_receiver) {
      revert Errors.ValueNotUpdated();
    }

    s_receiver = receiver;

    emit ReceiverSet(receiver);
  }

  // ================================================================================================
  // │                                           Getters                                            │
  // ================================================================================================

  /// @notice Getter function to retrieve the auction contract address.
  /// @return auction The address of the auction contract.
  function getAuction() external view returns (IBaseAuction auction) {
    return s_auction;
  }

  /// @notice Getter function to retrieve the receiver address.
  /// @return receiver The address of the receiver.
  function getReceiver() external view returns (address receiver) {
    return s_receiver;
  }

  /// @inheritdoc IERC165
  function supportsInterface(
    bytes4 interfaceId
  ) public view virtual override returns (bool) {
    return interfaceId == type(IAuctionCallback).interfaceId || super.supportsInterface(interfaceId);
  }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre AuctionBidder
Buscando 'AuctionBidder' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (4ms)


### HIGH findings en dominio dex
Buscando 'AuctionBidder auctionCallback withdraw setAuction _setAuction' [SQLite FTS5] (dominio: dex)...

Top 6 findings relevantes: (372ms)

 1. [HIGH] sweep function should prevent Treasury from withdrawing pool’s BPTs — Gauntlet
 2. [HIGH] Withdrawal shares of msg.sender are burnt incorrectly in _removeLiquidity flow — Hyperdrive February 2024
 3. [HIGH] LPs can split their liquidity withdrawal to get more tokens  — TermMax
 4. [HIGH] H-19: No slippage for withdrawal without swapping path — GMX
 5. [HIGH] [H-02] Missing `fromToken != toToken` check — Marginswap
 6. [HIGH] [H-02] Underflow of `lpPosition.points` during withdrawLP causes huge reward min — Neo Tokyo

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: AuctionBidder auctionCallback withdraw setAuction _setAuction | Dominio: dex
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] sweep function should prevent Treasury from withdrawing pool’s BPTs (Gauntlet)
   ## Severity: Critical Risk

## Context
AeraVaultV1.sol#L559-L561

## Description
The current `sweep()` implementation allows the vault owner (the Trea...

2. [HIGH] Withdrawal shares of msg.sender are burnt incorrectly in _removeLiquidity flow (Hyperdrive February 2024)
   ## Severity: High Risk

## Context
- HyperdriveLP .sol#L279-L296
- HyperdriveLP .sol#L397-L402

## Description
When `_removeLiquidity` is called, the ...

3. [HIGH] LPs can split their liquidity withdrawal to get more tokens  (TermMax)
   ## Context
(No context files were provided by the reviewer)

## Summary
When LPs split their liquidity withdrawal into several pieces, they may get mo...

4. [HIGH] H-19: No slippage for withdrawal without swapping path (GMX)
   Source: https://github.com/sherlock-audit/2023-02-gmx-judging/issues/70 

## Found by 
bin2chen, rvierdiiev

## Summary
No slippage for withdrawal wit...

5. [HIGH] [H-02] Missing `fromToken != toToken` check (Marginswap)
   
Attacker calls `MarginRouter.crossSwapExactTokensForTokens` with a fake pair and the same token[0] == token[1].
`crossSwapExactTokensForTokens(1000 W...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'AuctionBidder auctionCallback withdraw setAuction _setAuctio' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (11ms)

 1. [HIGH] [H-01] `finalizeVaultEndedWithdrawals()` will fail when last withdrawal request  — Saffron
 2. [HIGH] Function `claimEffectiveBalance()` may consistently revert, making it impossible — Casimir
 3. [HIGH] mod/state-transition/pkg/core/state/ExpectedWithdrawals returns error if non-0x0 — Berachain Beaconkit
 4. [HIGH] Disabling Withdrawals by Withdrawing Zero-Value FA — Aptos Securitize

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: AuctionBidder auctionCallback withdraw setAuction _setAuctio | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] [H-01] `finalizeVaultEndedWithdrawals()` will fail when last withdrawal request is less than 100 wei (Saffron)
   **Severity**

**Impact:** High, the issue will prevent withdrawal of stETH

**Likelihood:** Medium, when last withdrawal request is < 100 wei

**Descr...

2. [HIGH] Function `claimEffectiveBalance()` may consistently revert, making it impossible to complete queue withdrawals (Casimir)
   **Description:** The function attempts to remove the withdrawal at index `0`, while it uses the withdrawal at index `i` to call `completeQueuedWithdra...

3. [HIGH] mod/state-transition/pkg/core/state/ExpectedWithdrawals returns error if non-0x01 wi

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
2. **Identifica** las funciones donde tu especialidad (Access control) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `AB` (ej: AB-01, AB-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_AuctionBidder_AccessHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: AB-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "AB-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
