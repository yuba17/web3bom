# AccessHunter — PriceManager Analysis

## Tu Identidad
Eres el **AccessHunter** del equipo de bug hunting de chainlink-pa-v2.
Tu especialidad: **Access control, missing modifiers, privilege escalation, role misconfig**

## Tu Objetivo
Analizar `PriceManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/chainlink-pa-v2/src/PriceManager.sol`
**Dominio**: oracle


```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.26;

import {IVerifierProxy} from "@chainlink/contracts/src/v0.8/llo-feeds/v0.5.0/interfaces/IVerifierProxy.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";
import {IPriceManager} from "src/interfaces/IPriceManager.sol";

import {EmergencyWithdrawer} from "src/EmergencyWithdrawer.sol";
import {LinkReceiver} from "src/LinkReceiver.sol";
import {PausableWithAccessControl} from "src/PausableWithAccessControl.sol";
import {Errors} from "src/libraries/Errors.sol";
import {Roles} from "src/libraries/Roles.sol";

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @title PriceManager Contract.
/// @notice This contract implements functionality to verify and store Data Streams reports from
/// the Data Streams API. It also provides a fallback mechanism to use Chainlink data feeds in case
/// the Data Streams prices are stale.
abstract contract PriceManager is LinkReceiver, EmergencyWithdrawer, IPriceManager {
  using EnumerableSet for EnumerableSet.AddressSet;
  using SafeCast for int256;
  using SafeCast for uint256;

  /// @notice This event is emitted when an asset is added to the allow list
  /// @param asset The address of the asset that was added to the allow list
  event AssetAddedToAllowlist(address asset);
  /// @notice This event is emitted when an asset is removed from the allowlist
  /// @param asset The address of the asset that was removed from the allowlist
  event AssetRemovedFromAllowlist(address asset);
  /// @notice This event is emitted when the VerifierProxy address is set.
  /// @param verifierProxy The address of the new VerifierProxy contract.
  event VerifierProxySet(address verifierProxy);
  /// @notice This event is emitted when a new asset price is transmitted.
  /// @param asset The address of the asset.
  /// @param price The new price of the asset, scaled to 18 decimals.
  event PriceTransmitted(address indexed asset, uint256 price);
  /// @notice This event is emitted when Data Streams feed information is updated.
  /// @param asset The address of the asset.
  /// @param feedInfo The data streams and data feeds infos for the asset.
  event FeedInfoUpdated(address indexed asset, FeedInfo feedInfo);

  /// @notice This error is thrown when an unsupported report version is encountered.
  /// @param reportVersion The unsupported report version.
  error InvalidFeedVersion(bytes32 dataStreamsFeedId, uint16 reportVersion);
  /// @notice This error is thrown when trying to set an invalid feed decimals e.g. zero for a Streams data or a
  /// different value that the on-chain data feed.
  /// @param dataStreamsFeedId The dataStreamsFeedId with invalid decimals.
  error InvalidFeedDecimals(bytes32 dataStreamsFeedId);
  /// @notice This error is thrown when trying to transmit a report for a feed that is not allowlisted.
  /// @param dataStreamsFeedId The non-allowlisted dataStreamsFeedId.
  error FeedNotAllowlisted(bytes32 dataStreamsFeedId);

  /// @notice Data Streams report schema v3 (crypto streams).
  struct ReportV3 {
    bytes32 dataStreamsFeedId; //                 Unique identifier for the data stream.
    uint32 validFromTimestamp; // ───╮ Start timestamp of price validity period (seconds).
    uint32 observationsTimestamp; // │ End timestamp of price validity period (seconds).
    uint192 nativeFee; // ───────────╯ Verification cost in native blockchain tokens.
    uint192 linkFee; // ─────────────╮ Verification cost in LINK tokens.
    uint32 expiresAt; //─────────────╯ Timestamp when this report expires (seconds).
    int192 price; //                   DON consensus median price.
    int192 bid; //                     Simulated buy impact price at X% liquidity depth.
    int192 ask; //                     Simulated sell impact price at X% liquidity depth.
  }

  /// @notice The parameters for adding or updating feed information.
  struct FeedInfo {
    bytes32 dataStreamsFeedId; //                       Unique identifier for the data stream.
    AggregatorV3Interface usdDataFeed; // ─╮ Address of the data feed usd feed.
    uint32 stalenessThreshold; //          │ Maximum age of the price data (seconds).
    uint8 dataStreamsFeedDecimals; // ─────╯ Number of decimals in the reported price.
  }

  /// @notice The parameters for adding or updating feed information.
  struct ApplyFeedInfoUpdateParams {
    address asset; // Address of the asset.
    FeedInfo feedInfo; // The asset feeds configurations.
  }

  /// @notice Stored price information.
  struct DataStreamsPriceInfo {
    uint224 usdPrice; // ─╮ USD price scaled to 18 decimals.
    uint32 timestamp; // ─╯ Timestamp of the price (seconds).
  }

  /// @notice The Data Streams report schema version supported by this contract.
  uint256 private constant STREAMS_REPORT_V3 = 3;
  /// @notice The number of decimals to which prices are scaled to (18).
  uint256 internal constant PRICE_DECIMALS = 18;

  /// @notice The Data Streams VerifierProxy contract.
  IVerifierProxy internal immutable i_streamsVerifierProxy;

  /// @notice Array of all the enabled auction for this contract.
  EnumerableSet.AddressSet internal s_allowlistedAssets;

  /// @notice Mapping of asset addresses to their USD data feed contracts.
  mapping(address asset => FeedInfo feedInfo) internal s_feedInfo;
  /// @notice Mapping of Data Streams feed IDs to asset.
  mapping(bytes32 dataStreamsFeedId => address asset) internal s_dataStreamsFeedIdToAsset;
  /// @notice Mapping of asset to data streams transmitted price.
  mapping(address asset => DataStreamsPriceInfo streamsPrice) internal s_dataStreamsPrice;

  constructor(
    uint48 adminRoleTransferDelay,
    address admin,
    address verifierProxy,
    address linkToken,
    ApplyFeedInfoUpdateParams[] memory feedsInfo
  ) LinkReceiver(linkToken) EmergencyWithdrawer(adminRoleTransferDelay, admin) {
    if (verifierProxy == address(0)) {
      revert Errors.InvalidZeroAddress();
    }

    i_streamsVerifierProxy = IVerifierProxy(verifierProxy);

    if (feedsInfo.length > 0) {
      _applyFeedInfoUpdates(feedsInfo, new address[](0));
    }

    emit VerifierProxySet(verifierProxy);
  }

  // ================================================================================================
  // │                                      Price Transmission                                      │
  // ================================================================================================

  /// @inheritdoc IPriceManager
  /// @dev - The function does not handle LINK fee payment to the VerifierProxy, it is assumed that fees are waived.
  function transmit(
    bytes[] calldata unverifiedReports
  ) external onlyRole(Roles.PRICE_ADMIN_ROLE) {
    if (unverifiedReports.length == 0) {
      revert Errors.EmptyList();
    }

    for (uint256 i; i < unverifiedReports.length; ++i) {
      // Decode the unverified report.
      (, bytes memory reportData,,,) =
        abi.decode(unverifiedReports[i], (bytes32[3], bytes, bytes32[], bytes32[], bytes32));

      bytes32 dataStreamsFeedId = bytes32(reportData);

      if (s_dataStreamsFeedIdToAsset[dataStreamsFeedId] == address(0)) {
        revert FeedNotAllowlisted(dataStreamsFeedId);
      }
    }

    // Verify report through the proxy, decode & store prices.
    bytes[] memory verifiedReports = i_streamsVerifierProxy.verifyBulk(unverifiedReports, abi.encode(i_linkToken));

    for (uint256 i; i < verifiedReports.length; ++i) {
      ReportV3 memory report = abi.decode(verifiedReports[i], (ReportV3));
      address asset = s_dataStreamsFeedIdToAsset[report.dataStreamsFeedId];
      FeedInfo storage feedInfo = s_feedInfo[asset];

      uint256 usdPrice = int256(report.price).toUint256();

      if (report.observationsTimestamp < block.timestamp - feedInfo.stalenessThreshold) {
        revert Errors.StaleFeedData();
      }

      // Scale price to 18 decimals.
      uint8 feedDecimals = feedInfo.dataStreamsFeedDecimals;
      if (feedDecimals < PRICE_DECIMALS) {
        usdPrice = (usdPrice * 10 ** (PRICE_DECIMALS - feedDecimals));
      } else if (feedDecimals > PRICE_DECIMALS) {
        usdPrice = (usdPrice / 10 ** (feedDecimals - PRICE_DECIMALS));
      }

      if (usdPrice == 0) {
        revert Errors.ZeroFeedData();
      }

      s_dataStreamsPrice[asset] =
        DataStreamsPriceInfo({usdPrice: usdPrice.toUint224(), timestamp: report.observationsTimestamp});

      emit PriceTransmitted(asset, usdPrice);
    }
  }

  // ================================================================================================
  // │                                       Feeds Management                                       │
  // ================================================================================================

  /// @notice Adds, updates or removes feeds information.
  /// @dev precondition - the caller must have the ASSET_ADMIN_ROLE.
  /// @param adds List of feed information to add or update.
  /// @param removes List of assets to remove.
  function applyFeedInfoUpdates(
    ApplyFeedInfoUpdateParams[] memory adds,
    address[] memory removes
  ) external onlyRole(Roles.ASSET_ADMIN_ROLE) {
    _applyFeedInfoUpdates(adds, removes);
  }

  /// @notice Internal function to add, update or remove feeds information.
  /// @dev precondition - the adds and removes lists must not both be empty.
  /// @dev precondition - removed asset must be already allowlisted.
  /// @dev precondition - added/updated feed asset address must not be zero.
  /// @dev precondition - added/updated feed data feed address and data streams feed id must not both be zero.
  /// @dev precondition - added/updated feed decimals must be greater than zero.
  /// @dev precondition - added/updated when data streams feed id is set it must be of version 3.
  /// @param adds List of feed information to add or update (allowlists new assets).
  /// @param removes List of assets to remove (removes assets from allowlist and clean up feed info state).
  function _applyFeedInfoUpdates(
    ApplyFeedInfoUpdateParams[] memory adds,
    address[] memory removes
  ) internal {
    if (adds.length == 0 && removes.length == 0) {
      revert Errors.EmptyList();
    }

    for (uint256 i; i < removes.length; ++i) {
      address asset = removes[i];

      _onFeedInfoUpdate(asset, true);

      if (!s_allowlistedAssets.remove(asset)) {
        revert Errors.AssetNotAllowlisted(asset);
      }

      delete s_dataStreamsFeedIdToAsset[s_feedInfo[asset].dataStreamsFeedId];
      delete s_feedInfo[asset];
      delete s_dataStreamsPrice[asset];

      emit AssetRemovedFromAllowlist(asset);
    }

    for (uint256 i; i < adds.length; ++i) {
      FeedInfo memory feedInfo = adds[i].feedInfo;
      address asset = adds[i].asset;

      _onFeedInfoUpdate(asset, false);

      if (asset == address(0)) {
        revert Errors.InvalidZeroAddress();
      }

      if (
        feedInfo.stalenessThreshold == 0
          || (feedInfo.dataStreamsFeedId == bytes32(0) && feedInfo.usdDataFeed == AggregatorV3Interface(address(0)))
      ) {
        revert Errors.InvalidZeroValue();
      }

      if (feedInfo.dataStreamsFeedId != bytes32(0)) {
        bytes32 dataStreamsFeedId = feedInfo.dataStreamsFeedId;

        if (feedInfo.dataStreamsFeedDecimals == 0) {
          revert InvalidFeedDecimals(dataStreamsFeedId);
        }

        uint16 version = uint16(bytes2(dataStreamsFeedId));

        if (version != STREAMS_REPORT_V3) {
          revert InvalidFeedVersion(dataStreamsFeedId, version);
        }

        // Look up previous owner of this feed ID before overwriting; clean up that asset's data streams state
        // if the feed ID is being rotated to a different asset.
        address previousAssetForFeedId = s_dataStreamsFeedIdToAsset[feedInfo.dataStreamsFeedId];
        if (previousAssetForFeedId != address(0) && previousAssetForFeedId != asset) {
          FeedInfo storage previousAssetFeedInfo = s_feedInfo[previousAssetForFeedId];

          // Since the rotation is causing the Data Streams feed to be removed for the previous asset, we need to ensure
          // there is still a valid price source for that asset.
          if (address(previousAssetFeedInfo.usdDataFeed) == address(0)) {
            revert Errors.InvalidZeroValue();
          }

          previousAssetFeedInfo.dataStreamsFeedId = bytes32(0);
          previousAssetFeedInfo.dataStreamsFeedDecimals = 0;
          delete s_dataStreamsPrice[previousAssetForFeedId];
        }

        if (previousAssetForFeedId != asset) s_dataStreamsFeedIdToAsset[feedInfo.dataStreamsFeedId] = asset;
      }

      FeedInfo storage existingFeedInfo = s_feedInfo[asset];

      if (s_allowlistedAssets.add(asset)) {
        emit AssetAddedToAllowlist(asset);
      } else if (existingFeedInfo.dataStreamsFeedId != feedInfo.dataStreamsFeedId) {
        // If we are updating the feed ID for an already allowlisted asset, we need to clean up the old feed ID to asset
        // mapping and the old price, as they will no longer be valid.
        delete s_dataStreamsFeedIdToAsset[existingFeedInfo.dataStreamsFeedId];
        delete s_dataStreamsPrice[asset];
      }

      s_feedInfo[asset] = FeedInfo({
        dataStreamsFeedId: feedInfo.dataStreamsFeedId,
        usdDataFeed: feedInfo.usdDataFeed,
        dataStreamsFeedDecimals: feedInfo.dataStreamsFeedDecimals,
        stalenessThreshold: feedInfo.stalenessThreshold
      });

      emit FeedInfoUpdated(asset, feedInfo);
    }
  }

  /// @dev This empty hook is provided to allow inheriting contracts to implement custom logic that should be executed
  /// when feed information is updated, e.g. adding state dependant checks, emitting additional events, updating
  /// auxiliary state, etc.
  /// @param asset The address of the asset whose feed information was updated.
  /// @param isRemoved Whether the feed information was removed or added/updated - true if removed, false if added or
  /// updated.
  function _onFeedInfoUpdate(
    address asset,
    bool isRemoved
  ) internal virtual {}

  // ================================================================================================
  // │                                           Getters                                            │
  // ================================================================================================

  /// @notice Getter function to retrieve the address of the Data Streams VerifierProxy contract.
  /// @return streamsVerifierProxy The address of the Data Streams VerifierProxy contract.
  function getStreamsVerifierProxy() external view returns (IVerifierProxy streamsVerifierProxy) {
    return i_streamsVerifierProxy;
  }

  /// @notice Getter function to retrieve the list of allowlisted assets.
  /// @return allowlistedAssets List of allowlisted assets.
  function getAllowlistedAssets() external view returns (address[] memory allowlistedAssets) {
    return s_allowlistedAssets.values();
  }

  /// @notice Getter function to retrieve feed information for a given feed ID.
  /// @param asset The address of the asset.
  /// @return feedInfo The feed information associated with the feed ID.
  function getFeedInfo(
    address asset
  ) external view returns (FeedInfo memory feedInfo) {
    return s_feedInfo[asset];
  }

  /// @notice Getter function to retrieve the asset address for a given Data Streams feed ID.
  /// @param dataStreamsFeedId The Data Streams feed ID.
  /// @return asset The address of the asset associated with the feed ID.
  function getAssetFromDataStreamsFeedId(
    bytes32 dataStreamsFeedId
  ) external view returns (address asset) {
    return s_dataStreamsFeedIdToAsset[dataStreamsFeedId];
  }

  /// @notice Getter function to retrieve the latest price and timestamp for a given asset.
  /// @param asset The address of the asset.
  /// @return price The latest price of the asset, scaled to 18 decimals.
  /// @return updatedAt The timestamp of the latest price update.
  /// @return isValid Whether the returned price is valid or not (non-zero and not stale).
  function getAssetPrice(
    address asset
  ) external view returns (uint256 price, uint256 updatedAt, bool isValid) {
    return _getAssetPrice(asset, false);
  }

  /// @notice Internal function to retrieve the latest price and timestamp for a given asset.
  /// @dev This function is virtual as some additional checks may be warranted on certain chains, e.g.
  /// sequencer uptime checks on L2s.
  /// @dev The function prioritizes the Data Streams price, but if it is stale and a Chainlink data feed is configured,
  /// it will return the most recent price between the Data Streams report and the data feed, scaled to 18 decimals.
  /// @dev Precondition: if `withValidation` is enabled, the scaled price must be non-zero and must not be stale.
  /// @param asset The address of the asset.
  /// @param withValidation Whether to perform price validation or not (non-zero answer and staleness).
  /// @return price The latest price of the asset, scaled to 18 decimals.
  /// @return updatedAt The timestamp of the latest price update.
  /// @return isValid Whether the returned price is valid or not (non-zero and not stale).
  function _getAssetPrice(
    address asset,
    bool withValidation
  ) internal view virtual returns (uint256 price, uint256 updatedAt, bool isValid) {
    DataStreamsPriceInfo memory priceInfo = s_dataStreamsPrice[asset];
    FeedInfo memory feedInfo = s_feedInfo[asset];
    uint256 minTimestamp = block.timestamp - feedInfo.stalenessThreshold;

    // Prioritize Data Streams price.
    price = priceInfo.usdPrice;
    updatedAt = priceInfo.timestamp;

    // If the Data Streams price is stale and a Data Feed is configured, fetch the Data Feed price
    if (updatedAt < minTimestamp && feedInfo.usdDataFeed != AggregatorV3Interface(address(0))) {
      (, int256 answer,, uint256 dataFeedUpdatedAt,) = feedInfo.usdDataFeed.latestRoundData();

      // Use the most recent timestamp between the Data Streams price and the Data Feed price for validation and
      // return values.
      if (updatedAt < dataFeedUpdatedAt) {
        updatedAt = dataFeedUpdatedAt;
        price = answer.toUint256();

        uint8 decimals = feedInfo.usdDataFeed.decimals();

        if (decimals < PRICE_DECIMALS) {
          price = (price * 10 ** (PRICE_DECIMALS - decimals));
        } else if (decimals > PRICE_DECIMALS) {
          price = (price / 10 ** (decimals - PRICE_DECIMALS));
        }
      }
    }

    bool isZero = price == 0;
    bool isStale = updatedAt < minTimestamp;
    isValid = !isZero && !isStale;

    // Perform price validation if enabled.
    if (withValidation) {
      if (isZero) {
        revert Errors.ZeroFeedData();
      }
      if (isStale) {
        revert Errors.StaleFeedData();
      }
    }

    return (price, updatedAt, isValid);
  }

  /// @inheritdoc IERC165
  function supportsInterface(
    bytes4 interfaceId
  ) public view virtual override(PausableWithAccessControl) returns (bool) {
    return (PausableWithAccessControl.supportsInterface(interfaceId) || interfaceId == type(IPriceManager).interfaceId);
  }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre PriceManager
Buscando 'PriceManager' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (4ms)


### HIGH findings en dominio oracle
Buscando 'PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpdates _onFeedInfoUpda' [SQLite FTS5] (dominio: oracle)...
Sin resultados para los criterios dados. (35ms)

### Cross-domain HIGH relevantes
Buscando 'PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpd' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (3ms)

 1. [HIGH] Non-context-aware JSON Parsing — Proximity Labs
 2. [HIGH] Risk of Passing Incorrect Context to Firewall Policies — Ironblocks Onchain Firewall Audit
 3. [HIGH] ​Lack of ​chainID — Yield Protocol
 4. [HIGH] [H01] Attackers can prevent honest users from performing an instant withdraw fro — Futureswap V2 Audit

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: PriceManager transmit applyFeedInfoUpdates _applyFeedInfoUpd | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] Non-context-aware JSON Parsing (Proximity Labs)
   ## Custom JSON Parsing in Near-Eth Contract

Custom JSON parsing is used within the Near-Eth Contract. This parsing method is non-context-aware, which...

2. [HIGH] Risk of Passing Incorrect Context to Firewall Policies (Ironblocks Onchain Firewall Audit)
   The on\-chain firewall system is designed to support meta\-transactions. The [FirewallConsumerBase](https://github.com/ironblocks/onchain-firewall/blo...

3. [HIGH] ​Lack of ​chainID (Yield Protocol)
   ## Type: Timing  
**Target:** ERC20Permit.sol  

## Difficulty: Low  
Implements the draft ERC 2612 via the ERC20Permit contract it inherits from. Thi...

4. [HIGH] [H01] Attackers can prevent honest users from performing an instant withdraw from the Wallet contract (Futureswap V2 Audit)
   An attacker who sees an honest user’s call to [`MessageProcessor.instantWithdraw`](https://github.com/futureswap/fs_core/blob/96255fc4a550a5f34681c117...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio (oracle)
### Briefing principal: oracle

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Some protocols have fallback oracles that silently handle staleness -- check full path
  ⚠ Heartbeat varies per feed and per chain -- don't assume 1h for all
  ⚠ updatedAt == 0 is a valid failure case (feed never initialized)
  ⚠ High liquidity pools (>$10M TVL) are expensive to manipulate -- cost/benefit matters
  ⚠ Legitimate large trades can trigger deviation on thin pools
  ⚠ Protocol using Chainlink only (no AMM reads) is not vulnerable to this
  ⚠ Very high liquidity pools make even short TWAP expensive to manipulate
  ⚠ Multi-block manipulation requires sustained capital or validator collusion
  ⚠ Post-PoS: proposer can manipulate last block of window more cheaply
  ⚠ Solidity int256 can be negative -- casting to uint256 without check wraps around
  ⚠ Some feeds return minAnswer/maxAnswer bounds, not zero, on extreme events
  ⚠ Check Chainlink aggregator minAnswer -- if real price drops below, feed returns minAnswer (stale)

## CHECKLIST DE INVARIANTES
Oracle audit -- run through for every target:
```
[ ] Grep: latestAnswer, getAnswer, getTimestamp (deprecated functions)
[ ] Grep: latestRoundData -- are ALL return values validated?
[ ] Check: price > 0 after every oracle read
[ ] Check: updatedAt freshness against feed-specific heartbeat
[ ] Check: answeredInRound >= roundId
[ ] Grep: getReserves, slot0, sqrtPriceX96 (spot price reads)
[ ] If spot price used: is TWAP or Chainlink cross-validation present?
[ ] Grep: observe, consult (TWAP reads) -- what window length?
[ ] If TWAP window < 30 min: flag as manipulable
[ ] Check: observationCardinality sufficient for window?
[ ] Check: feed.decimals() called or hardcoded assumption?
[ ] Check: token decimals + oracle decimals combined correctly?
[ ] If L2: sequencer uptime feed checked?
[ ] If L2: grace period after sequencer restart?
[ ] Check: fallback oracle path exists?
[ ] Check: circuit breaker for extreme price events?
[ ] Check: minAnswer/maxAnswer on Chainlink aggregator (hidden staleness)
```

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Access control) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `PM` (ej: PM-01, PM-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_PriceManager_AccessHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: PM-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "PM-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
