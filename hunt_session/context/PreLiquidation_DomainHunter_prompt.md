# DomainHunter — PreLiquidation Analysis

## Tu Identidad
Eres el **DomainHunter** del equipo de bug hunting de morpho-pre-liquidation.
Tu especialidad: **Protocol-specific invariants, cross-component interactions, economic attacks**

## Tu Objetivo
Analizar `PreLiquidation` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/morpho-pre-liquidation/src/PreLiquidation.sol`
**Dominio**: liquidation-mechanics


## Asset Flow Map
### Money IN (deposits/receives)
- L196 onMorphoRepay(): ERC20(LOAN_TOKEN).safeTransferFrom(liquidator, address(this), repaidAssets);

### Approvals (attack surface)
- L111 preLiquidationParams(): ERC20(_marketParams.loanToken).safeApprove(morpho, type(uint256).max);
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.27;

import {Id, MarketParams, IMorpho, Position, Market} from "../lib/morpho-blue/src/interfaces/IMorpho.sol";
import {IMorphoRepayCallback} from "../lib/morpho-blue/src/interfaces/IMorphoCallbacks.sol";
import {IPreLiquidation, PreLiquidationParams} from "./interfaces/IPreLiquidation.sol";
import {IPreLiquidationCallback} from "./interfaces/IPreLiquidationCallback.sol";
import {IOracle} from "../lib/morpho-blue/src/interfaces/IOracle.sol";

import {ORACLE_PRICE_SCALE} from "../lib/morpho-blue/src/libraries/ConstantsLib.sol";
import {SharesMathLib} from "../lib/morpho-blue/src/libraries/SharesMathLib.sol";
import {SafeTransferLib} from "../lib/solmate/src/utils/SafeTransferLib.sol";
import {WAD, MathLib} from "../lib/morpho-blue/src/libraries/MathLib.sol";
import {UtilsLib} from "../lib/morpho-blue/src/libraries/UtilsLib.sol";
import {ERC20} from "../lib/solmate/src/tokens/ERC20.sol";
import {EventsLib} from "./libraries/EventsLib.sol";
import {ErrorsLib} from "./libraries/ErrorsLib.sol";

/// @title PreLiquidation
/// @author Morpho Labs
/// @custom:contact security@morpho.org
/// @notice A linear LIF and linear LCF pre-liquidation contract for Morpho.
contract PreLiquidation is IPreLiquidation, IMorphoRepayCallback {
    using SharesMathLib for uint256;
    using MathLib for uint256;
    using SafeTransferLib for ERC20;

    /* IMMUTABLE */

    /// @notice The address of the Morpho contract.
    IMorpho public immutable MORPHO;
    /// @notice The id of the Morpho Market specific to the PreLiquidation contract.
    Id public immutable ID;

    // Market parameters
    address internal immutable LOAN_TOKEN;
    address internal immutable COLLATERAL_TOKEN;
    address internal immutable ORACLE;
    address internal immutable IRM;
    uint256 internal immutable LLTV;

    // Pre-liquidation parameters
    uint256 internal immutable PRE_LLTV;
    uint256 internal immutable PRE_LCF_1;
    uint256 internal immutable PRE_LCF_2;
    uint256 internal immutable PRE_LIF_1;
    uint256 internal immutable PRE_LIF_2;
    address internal immutable PRE_LIQUIDATION_ORACLE;

    /// @notice The Morpho market parameters specific to the PreLiquidation contract.
    function marketParams() public view returns (MarketParams memory) {
        return MarketParams({
            loanToken: LOAN_TOKEN,
            collateralToken: COLLATERAL_TOKEN,
            oracle: ORACLE,
            irm: IRM,
            lltv: LLTV
        });
    }

    /// @notice The pre-liquidation parameters specific to the PreLiquidation contract.
    function preLiquidationParams() external view returns (PreLiquidationParams memory) {
        return PreLiquidationParams({
            preLltv: PRE_LLTV,
            preLCF1: PRE_LCF_1,
            preLCF2: PRE_LCF_2,
            preLIF1: PRE_LIF_1,
            preLIF2: PRE_LIF_2,
            preLiquidationOracle: PRE_LIQUIDATION_ORACLE
        });
    }

    /* CONSTRUCTOR */

    /// @dev Initializes the PreLiquidation contract.
    /// @param morpho The address of the Morpho contract.
    /// @param id The id of the Morpho market on which pre-liquidations will occur.
    /// @param _preLiquidationParams The pre-liquidation parameters.
    /// @dev The following requirements should be met:
    /// - preLltv < LLTV;
    /// - preLCF1 <= preLCF2;
    /// - preLCF1 <= 1;
    /// - 1 <= preLIF1 <= preLIF2 <= 1 / LLTV.
    constructor(address morpho, Id id, PreLiquidationParams memory _preLiquidationParams) {
        require(IMorpho(morpho).market(id).lastUpdate != 0, ErrorsLib.NonexistentMarket());
        MarketParams memory _marketParams = IMorpho(morpho).idToMarketParams(id);
        require(_preLiquidationParams.preLltv < _marketParams.lltv, ErrorsLib.PreLltvTooHigh());
        require(_preLiquidationParams.preLCF1 <= _preLiquidationParams.preLCF2, ErrorsLib.PreLCFDecreasing());
        require(_preLiquidationParams.preLCF1 <= WAD, ErrorsLib.PreLCFTooHigh());
        require(WAD <= _preLiquidationParams.preLIF1, ErrorsLib.PreLIFTooLow());
        require(_preLiquidationParams.preLIF1 <= _preLiquidationParams.preLIF2, ErrorsLib.PreLIFDecreasing());
        require(_preLiquidationParams.preLIF2 <= WAD.wDivDown(_marketParams.lltv), ErrorsLib.PreLIFTooHigh());

        MORPHO = IMorpho(morpho);

        ID = id;

        LOAN_TOKEN = _marketParams.loanToken;
        COLLATERAL_TOKEN = _marketParams.collateralToken;
        ORACLE = _marketParams.oracle;
        IRM = _marketParams.irm;
        LLTV = _marketParams.lltv;

        PRE_LLTV = _preLiquidationParams.preLltv;
        PRE_LCF_1 = _preLiquidationParams.preLCF1;
        PRE_LCF_2 = _preLiquidationParams.preLCF2;
        PRE_LIF_1 = _preLiquidationParams.preLIF1;
        PRE_LIF_2 = _preLiquidationParams.preLIF2;
        PRE_LIQUIDATION_ORACLE = _preLiquidationParams.preLiquidationOracle;

        ERC20(_marketParams.loanToken).safeApprove(morpho, type(uint256).max);
    }

    /* PRE-LIQUIDATION */

    /// @notice Pre-liquidates the given borrower on the market of this contract and with the parameters of this
    /// contract.
    /// @param borrower The owner of the position.
    /// @param seizedAssets The amount of collateral to seize.
    /// @param repaidShares The amount of shares to repay.
    /// @param data Arbitrary data to pass to the `onPreLiquidate` callback. Pass empty data if not needed.
    /// @return seizedAssets The amount of collateral seized.
    /// @return repaidAssets The amount of debt repaid.
    /// @dev Either `seizedAssets` or `repaidShares` should be zero.
    /// @dev Reverts if the account is still liquidatable on Morpho after the pre-liquidation (withdrawCollateral will
    /// fail). This can happen if either the LIF is bigger than 1/LLTV, or if the account is already unhealthy on
    /// Morpho.
    /// @dev The pre-liquidation close factor (preLCF) is the maximum proportion of debt that can be pre-liquidated at
    /// once. It increases linearly from preLCF1 at preLltv to preLCF2 at LLTV.
    /// @dev The pre-liquidation incentive factor (preLIF) is the factor by which the repaid debt is multiplied to
    /// compute the seized collateral. It increases linearly from preLIF1 at preLltv to preLIF2 at LLTV.
    function preLiquidate(address borrower, uint256 seizedAssets, uint256 repaidShares, bytes calldata data)
        external
        returns (uint256, uint256)
    {
        require(UtilsLib.exactlyOneZero(seizedAssets, repaidShares), ErrorsLib.InconsistentInput());

        MORPHO.accrueInterest(marketParams());

        Market memory market = MORPHO.market(ID);
        Position memory position = MORPHO.position(ID, borrower);

        uint256 collateralPrice = IOracle(PRE_LIQUIDATION_ORACLE).price();
        uint256 collateralQuoted = uint256(position.collateral).mulDivDown(collateralPrice, ORACLE_PRICE_SCALE);
        uint256 borrowed = uint256(position.borrowShares).toAssetsUp(market.totalBorrowAssets, market.totalBorrowShares);

        // The two following require-statements ensure that collateralQuoted is different from zero.
        require(borrowed <= collateralQuoted.wMulDown(LLTV), ErrorsLib.LiquidatablePosition());
        // The following require-statement is equivalent to checking that ltv > PRE_LLTV.
        require(borrowed > collateralQuoted.wMulDown(PRE_LLTV), ErrorsLib.NotPreLiquidatablePosition());

        uint256 ltv = borrowed.wDivUp(collateralQuoted);
        uint256 quotient = (ltv - PRE_LLTV).wDivDown(LLTV - PRE_LLTV);
        uint256 preLIF = quotient.wMulDown(PRE_LIF_2 - PRE_LIF_1) + PRE_LIF_1;

        if (seizedAssets > 0) {
            uint256 seizedAssetsQuoted = seizedAssets.mulDivUp(collateralPrice, ORACLE_PRICE_SCALE);

            repaidShares =
                seizedAssetsQuoted.wDivUp(preLIF).toSharesUp(market.totalBorrowAssets, market.totalBorrowShares);
        } else {
            seizedAssets = repaidShares.toAssetsDown(market.totalBorrowAssets, market.totalBorrowShares).wMulDown(
                preLIF
            ).mulDivDown(ORACLE_PRICE_SCALE, collateralPrice);
        }

        // Note that the pre-liquidation close factor can be greater than WAD (100%).
        // In this case the position can be fully pre-liquidated.
        uint256 preLCF = quotient.wMulDown(PRE_LCF_2 - PRE_LCF_1) + PRE_LCF_1;

        uint256 repayableShares = uint256(position.borrowShares).wMulDown(preLCF);
        require(repaidShares <= repayableShares, ErrorsLib.PreLiquidationTooLarge(repaidShares, repayableShares));

        bytes memory callbackData = abi.encode(seizedAssets, borrower, msg.sender, data);
        (uint256 repaidAssets,) = MORPHO.repay(marketParams(), 0, repaidShares, borrower, callbackData);

        emit EventsLib.PreLiquidate(ID, msg.sender, borrower, repaidAssets, repaidShares, seizedAssets);

        return (seizedAssets, repaidAssets);
    }

    /// @notice Morpho callback after repay call.
    /// @dev During pre-liquidation, Morpho will call the `onMorphoRepay` callback function in `PreLiquidation` using
    /// the provided `data`.
    function onMorphoRepay(uint256 repaidAssets, bytes calldata callbackData) external {
        require(msg.sender == address(MORPHO), ErrorsLib.NotMorpho());
        (uint256 seizedAssets, address borrower, address liquidator, bytes memory data) =
            abi.decode(callbackData, (uint256, address, address, bytes));

        MORPHO.withdrawCollateral(marketParams(), seizedAssets, borrower, liquidator);

        if (data.length > 0) {
            IPreLiquidationCallback(liquidator).onPreLiquidate(repaidAssets, data);
        }

        ERC20(LOAN_TOKEN).safeTransferFrom(liquidator, address(this), repaidAssets);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre PreLiquidation
Buscando 'PreLiquidation' [SQLite FTS5] (dominio: general)...

Top 2 findings relevantes: (6ms)

 1. [LOW] Liquidations May Fail Due to Underflow in `CurveConvexLib.checkReentrancyContext — Notional Finance
 2. [MEDIUM] M-6: No slippage check for liquidators when they burn USG from their account wit — USG - Tangent

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation | Dominio: general
Los siguientes 2 findings de protocolos similares son relevantes:

1. [LOW] Liquidations May Fail Due to Underflow in `CurveConvexLib.checkReentrancyContext()` (Notional Finance)
   ##### Description
`CurveConvexLib.checkReentrancyContext()` is called during liquidations to check whether the reentrancy flag in Curve pools is enabl...

2. [MEDIUM] M-6: No slippage check for liquidators when they burn USG from their account without Swapping first. (USG - Tangent)
   
Source: https://github.com/sherlock-audit/2025-08-usg-tangent-judging/issues/178 

## Found by 
3rdeye, BADROBINX, Bigsam, Brene, Pro\_King, Tigerfra...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio liquidation-mechanics
Buscando 'PreLiquidation marketParams preLiquidationParams preLiquidate onMorphoRepay' [SQLite FTS5] (dominio: liquidation-mechanics)...
Top 1 findings relevantes: (39ms)
 1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` — Catalyst
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation marketParams preLiquidationParams preLiquidate onMorphoRepay | Dominio: liquidation-mechanics
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` (Catalyst)
   **Severity**
**Impact:** Medium
**Likelihood:** High
**Description**
When market is created, it is allowed that `params.premint` and the `...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'PreLiquidation marketParams preLiquidationParams preLiquidat' [SQLite FTS5] (dominio: general)...
Top 1 findings relevantes: (12ms)
 1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` — Catalyst
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation marketParams preLiquidationParams preLiquidat | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` (Catalyst)
   **Severity**
**Impact:** Medium
**Likelihood:** High
**Description**
When market is created, it is allowed that `params.premint` and the `...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio (liquidation-mechanics)
Sin briefing disponible

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Protocol-specific invariants) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
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
ID prefix para este componente: `PL` (ej: PL-01, PL-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_PreLiquidation_DomainHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: PL-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "PL-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Symmetric Inspection (OBLIGATORIO — después de tu análisis de dominio)
Identifica TODOS los pares simétricos del contrato. Pares comunes:
  deposit/withdraw, mint/burn, lock/unlock, stake/unstake, borrow/repay, open/close

Para CADA par, verifica estas 5 dimensiones:
1. **State variables**: ¿ambas funciones actualizan las mismas variables (en dirección opuesta)?
2. **Validaciones**: ¿mismas validaciones (o su inversa lógica)?
3. **Events**: ¿ambas emiten el evento correspondiente?
4. **Modifiers**: ¿mismos modifiers aplicados (nonReentrant, whenNotPaused)?
5. **Edge cases**: ¿amount=0, amount=max, balance=0 manejados simétricamente?

Cualquier asimetría es un candidato a invariante. Documenta qué variable/check/event falta en qué función.
Bug real: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M.

## Constraint Inference (0xRajeev — OBLIGATORIO)
Para cada validación/require que encuentres:
1. Observa qué se valida en N-1 code paths que hacen algo similar.
2. El path que NO tiene esa validación es el bug candidato.
Ejemplo: si 5 de 6 funciones de withdraw verifican healthFactor, la 6ta que no lo hace es sospechosa.

## Traza Hacia Atrás (samczsun — MENTALIDAD)
No empieces preguntando "¿hay un bug aquí?". Empieza preguntando:
"¿De dónde puede SALIR valor del protocolo?" (withdraw, redeem, liquidate, claim, transfer).
Para cada punto de salida, traza HACIA ATRÁS: ¿qué condiciones se deben cumplir? ¿Se pueden manipular?

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
