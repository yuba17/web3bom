# FlowHunter — GPV2CompatibleAuction Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de chainlink-pa-v2.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

## Tu Objetivo
Analizar `GPV2CompatibleAuction` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/chainlink-pa-v2/src/GPV2CompatibleAuction.sol`
**Dominio**: dex


```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IGPV2CompatibleAuction} from "src/interfaces/IGPV2CompatibleAuction.sol";
import {IGPV2Settlement} from "src/interfaces/IGPV2Settlement.sol";

import {BaseAuction} from "src/BaseAuction.sol";
import {Errors} from "src/libraries/Errors.sol";
import {Roles} from "src/libraries/Roles.sol";

import {GPv2Order} from "@cowprotocol/libraries/GPv2Order.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title GPV2 Compatible Auction v1.0.0 Contract.
/// @notice This contract extends the BaseAuction contract to provide compatibility with CowProtocol settlement contract
/// via EIP-1271 signed orders.
contract GPV2CompatibleAuction is BaseAuction, IERC1271, IGPV2CompatibleAuction {
  using SafeERC20 for IERC20;

  /// @notice This event is emitted when the CowSwap vault relayer address is set.
  /// @param cowSwapVaultRelayer The address of the CowSwap vault relayer.
  event GPV2VaultRelayerSet(address indexed cowSwapVaultRelayer);
  /// @notice This event is emitted when the GPv2Settlement contract address is set.
  /// @param gpV2Settlement The address of the GPv2Settlement contract.
  event GPV2SettlementSet(address indexed gpV2Settlement);

  /// @notice This error is thrown when the CowProtocol order ID does not match the order details.
  /// @param orderId The CowProtocol order ID.
  error InvalidOrderId(bytes32 orderId);
  /// @notice This error is thrown when the verified CowProtocol order's buy token is not the configured asset out.
  /// @param buyToken The CowProtocol order's buy token.
  /// @param assetOut The address of the configured asset out.
  error InvalidBuyToken(address buyToken, address assetOut);
  /// @notice This error is thrown when the verified CowProtocol order's receiver is not the configured asset out
  /// receiver.
  /// @param receiver The CowProtocol order's receiver.
  /// @param assetOutReceiver The address of the configured asset out receiver.
  error InvalidReceiver(address receiver, address assetOutReceiver);
  /// @notice This error is thrown when there are insufficient assets in balance to settle the CowProtocol order.
  /// @param assetIn The CowProtocol order's sell token.
  /// @param amountIn The requested amount (sell token).
  /// @param assetInBalance The available balance of the asset.
  error InsufficientAssetInBalance(address assetIn, uint256 amountIn, uint256 assetInBalance);
  /// @notice This error is thrown when the CowProtocol order's buy amount is lower than the current auction price.
  /// @param amountOut The requested amount of asset out (buy amount).
  /// @param minAmountOut The minimum required amount of asset out.
  error InsufficientBuyAmount(uint256 amountOut, uint256 minAmountOut);
  /// @notice This error is thrown when the CowProtocol order is expired.
  /// @param validTo The order's valid to timestamp.
  /// @param currentTime The current block timestamp.
  error ExpiredOrder(uint32 validTo, uint256 currentTime);
  /// @notice This error is thrown when the CowProtocol order fee amount is non-zero.
  error InvalidFeeAmount();
  /// @notice This error is thrown when the CowProtocol order kind is not a sell order.
  /// @param orderKind The order kind.
  error InvalidOrderKind(bytes32 orderKind);
  /// @notice This error is thrown when the CowProtocol order is not partially fillable.
  error OrderNotPartiallyFillable();
  /// @notice This error is thrown when the CowProtocol order does not use direct ERC20 balances.
  error InvalidTokenBalanceMarker();

  /// @notice The CowSwap vault relayer address.
  address private immutable i_gpV2VaultRelayer;
  /// @notice The GPv2Settlement contract address.
  IGPV2Settlement private immutable i_gpV2Settlement;

  constructor(
    BaseAuction.ConstructorParams memory params,
    address gpV2VaultRelayer,
    address gpV2Settlement
  ) BaseAuction(params) {
    if (gpV2VaultRelayer == address(0) || gpV2Settlement == address(0)) {
      revert Errors.InvalidZeroAddress();
    }

    i_gpV2VaultRelayer = gpV2VaultRelayer;
    i_gpV2Settlement = IGPV2Settlement(gpV2Settlement);

    emit GPV2VaultRelayerSet(gpV2VaultRelayer);
    emit GPV2SettlementSet(gpV2Settlement);
  }

  /// @inheritdoc BaseAuction
  function _onAuctionStart(
    address asset
  ) internal override {
    super._onAuctionStart(asset);

    // Approve the CowSwap vault relayer to transfer the auctioned asset.
    IERC20(asset).forceApprove(i_gpV2VaultRelayer, IERC20(asset).balanceOf(address(this)));
  }

  /// @inheritdoc BaseAuction
  function _onAuctionEnd(
    address asset,
    bool hasFeeAggregator
  ) internal override {
    super._onAuctionEnd(asset, hasFeeAggregator);

    /// Revoke the CowSwap vault relayer's allowance to transfer the auctioned asset.
    IERC20(asset).forceApprove(i_gpV2VaultRelayer, 0);
  }

  /// @inheritdoc IERC1271
  /// @dev precondition - The function must not be reentered from the bid() function.
  /// @dev precondition - The order ID must match the provided hash.
  /// @dev precondition - The signature must decode to a valid GPv2Order.Data struct.
  /// @dev precondition - The order's sell token must be a valid auction.
  /// @dev precondition - The order's buy token must be the configured asset out.
  /// @dev precondition - The order's receiver must be the auction contract.
  /// @dev precondition - The contract must have sufficient approved balance of the order's sell token to cover the sell
  /// amount.
  /// @dev precondition - The order's buy amount must be greater than or equal to the current auction price.
  /// @dev precondition - The order must not be expired.
  /// @dev precondition - The order kind must be a sell order.
  /// @dev precondition - The order must be partially fillable.
  function isValidSignature(
    bytes32 hash,
    bytes memory signature
  ) external view whenNotPaused returns (bytes4 magicValue) {
    GPv2Order.Data memory order = abi.decode(signature, (GPv2Order.Data));

    if (s_entered) {
      revert Errors.ReentrantCall();
    }
    if (hash != GPv2Order.hash(order, i_gpV2Settlement.domainSeparator())) {
      revert InvalidOrderId(hash);
    }
    uint256 auctionStart = s_auctionStarts[address(order.sellToken)];
    if (auctionStart == 0) {
      revert InvalidAuction(address(order.sellToken));
    }
    if (address(order.buyToken) != s_assetOut) {
      revert InvalidBuyToken(address(order.buyToken), s_assetOut);
    }
    if (order.receiver != address(this)) {
      revert InvalidReceiver(order.receiver, address(this));
    }
    if (order.sellAmount == 0) {
      revert Errors.InvalidZeroAmount();
    }
    uint256 assetInBalance = order.sellToken.balanceOf(address(this));
    if (order.sellAmount > assetInBalance) {
      revert InsufficientAssetInBalance(address(order.sellToken), order.sellAmount, assetInBalance);
    }
    uint256 elapsedTime = block.timestamp - auctionStart;
    AssetParams memory assetParams = s_assetParams[address(order.sellToken)];
    if (elapsedTime > assetParams.auctionDuration) {
      revert InvalidAuction(address(order.sellToken));
    }
    (uint256 sellTokenUsdPrice,,) = _getAssetPrice(address(order.sellToken), true);
    uint256 minBuyAmount = _getAssetOutAmount(assetParams, sellTokenUsdPrice, order.sellAmount, elapsedTime, true);
    if (order.buyAmount < minBuyAmount) {
      revert InsufficientBuyAmount(order.buyAmount, minBuyAmount);
    }
    if (order.validTo < block.timestamp) {
      revert ExpiredOrder(order.validTo, block.timestamp);
    }
    // Non zero fee amounts are not supported in this auction implementation.
    if (order.feeAmount > 0) {
      revert InvalidFeeAmount();
    }
    if (order.kind != GPv2Order.KIND_SELL) {
      revert InvalidOrderKind(order.kind);
    }
    if (!order.partiallyFillable) {
      revert OrderNotPartiallyFillable();
    }
    if (order.sellTokenBalance != GPv2Order.BALANCE_ERC20 || order.buyTokenBalance != GPv2Order.BALANCE_ERC20) {
      revert InvalidTokenBalanceMarker();
    }

    return IERC1271.isValidSignature.selector;
  }

  /// @inheritdoc IGPV2CompatibleAuction
  /// @dev precondition - the caller must have the ORDER_MANAGER_ROLE.
  function invalidateOrders(
    bytes[] calldata orderUids
  ) external onlyRole(Roles.ORDER_MANAGER_ROLE) {
    for (uint256 i = 0; i < orderUids.length; i++) {
      i_gpV2Settlement.invalidateOrder(orderUids[i]);
    }
  }

  /// @notice Getter function to retrieve the CowSwap vault relayer address.
  function getGPV2VaultRelayer() external view returns (address) {
    return i_gpV2VaultRelayer;
  }

  /// @notice Getter function to retrieve the GPv2Settlement contract address.
  function getGPV2Settlement() external view returns (IGPV2Settlement) {
    return i_gpV2Settlement;
  }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre GPV2CompatibleAuction
Buscando 'GPV2CompatibleAuction' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (2ms)


### HIGH findings en dominio dex
Buscando 'GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidSignature invalidateO' [SQLite FTS5] (dominio: dex)...
Sin resultados para los criterios dados. (102ms)

### Cross-domain HIGH relevantes
Buscando 'GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidS' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (20ms)

 1. [HIGH] [H-06] Funds are permanently stuck in OptimisticListingSeaport.sol contract if a — Tessera
 2. [HIGH] Expired token groups not synchronized with ERC1155 balance tracking — Radius Technology EVMAuth
 3. [HIGH] [H-02] Partial signature replay/frontrunning attack on session calls — Sequence
 4. [HIGH] H-8: It is possible to DoS batch auctions by submitting invalid AltBn128 points  — Axis Finance

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GPV2CompatibleAuction _onAuctionStart _onAuctionEnd isValidS | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] [H-06] Funds are permanently stuck in OptimisticListingSeaport.sol contract if active proposal is executed after new proposal is pending. (Tessera)
   
`\_constructOrder` is called in `propose()`, OptimisticListingSeaport.sol. It fills the order params stored in proposedListings\[\_vault].

    {
   ...

2. [HIGH] Expired token groups not synchronized with ERC1155 balance tracking (Radius Technology EVMAuth)
   ## Diﬃculty: Low

## Type: Data Validation

## Description
The *pruneGroups* function removes expired token groups from the custom group tracking syst...

3. [HIGH] [H-02] Partial signature replay/frontrunning attack on session calls (Sequence)
   

<https://github.com/code-423n4/2025-10-sequence/blob/b0e5fb15bf6735ec9aaba02f5eca28a7882d815d/src/modules/Calls.sol# L36-L48>

<https://github.com/c...

4. [HIGH] H-8: It is possible to DoS batch auctions by submitting invalid AltBn128 points when bidding (Axis Finance)
   Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/147 

## Found by 
hash, underdog
## Summary

Bidders can submit invalid...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

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
2. **Identifica** las funciones donde tu especialidad (Reentrancy) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `GPVCA` (ej: GPVCA-01, GPVCA-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_GPV2CompatibleAuction_FlowHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: GPVCA-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "GPVCA-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
