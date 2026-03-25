# FlowHunter — LeverageTransformer Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de revert-lend.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

## Tu Objetivo
Analizar `LeverageTransformer` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/revert-lend/src/transformers/LeverageTransformer.sol`
**Dominio**: lending


```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../utils/Swapper.sol";
import "../interfaces/IVault.sol";
import "../transformers/Transformer.sol";

/// @title LeverageTransformer
/// @notice Functionality to leverage / deleverage positions direcly in one tx
contract LeverageTransformer is Transformer, Swapper {
    constructor(
        INonfungiblePositionManager _nonfungiblePositionManager,
        address _universalRouter,
        address _zeroxAllowanceHolder
    )
        Swapper(_nonfungiblePositionManager, _universalRouter, _zeroxAllowanceHolder)
    {}

    struct LeverageUpParams {
        // which token to leverage
        uint256 tokenId;
        // how much to borrow
        uint256 borrowAmount;
        // how much of borrowed lend token should be swapped to token0
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // how much of borrowed lend token should be swapped to token1
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1; // encoded data from 0x api call (address,bytes) - allowanceTarget,data
        // for adding liquidity slippage
        uint256 amountAddMin0;
        uint256 amountAddMin1;
        // recipient for leftover tokens
        address recipient;
        // for all uniswap deadlineable functions
        uint256 deadline;
    }

    // method called from transform() method in Vault
    function leverageUp(LeverageUpParams calldata params) external {
        _validateCaller(nonfungiblePositionManager, params.tokenId);

        uint256 amount = params.borrowAmount;

        address token = IVault(msg.sender).asset();

        IVault(msg.sender).borrow(params.tokenId, amount);

        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);

        uint256 amount0 = token == token0 ? amount : 0;
        uint256 amount1 = token == token1 ? amount : 0;

        if (params.amountIn0 != 0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token), IERC20(token0), params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            if (token == token1) {
                amount1 -= amountIn;
            }
            amount -= amountIn;
            amount0 += amountOut;
        }
        if (params.amountIn1 != 0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token), IERC20(token1), params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            if (token == token0) {
                amount0 -= amountIn;
            }
            amount -= amountIn;
            amount1 += amountOut;
        }

        SafeERC20.safeIncreaseAllowance(IERC20(token0), address(nonfungiblePositionManager), amount0);
        SafeERC20.safeIncreaseAllowance(IERC20(token1), address(nonfungiblePositionManager), amount1);

        INonfungiblePositionManager.IncreaseLiquidityParams memory increaseLiquidityParams = INonfungiblePositionManager
            .IncreaseLiquidityParams(
            params.tokenId, amount0, amount1, params.amountAddMin0, params.amountAddMin1, params.deadline
        );
        (, uint256 added0, uint256 added1) = nonfungiblePositionManager.increaseLiquidity(increaseLiquidityParams);

        SafeERC20.safeApprove(IERC20(token0), address(nonfungiblePositionManager), 0);
        SafeERC20.safeApprove(IERC20(token1), address(nonfungiblePositionManager), 0);

        // send leftover tokens
        if (amount0 > added0) {
            SafeERC20.safeTransfer(IERC20(token0), params.recipient, amount0 - added0);
        }
        if (amount1 > added1) {
            SafeERC20.safeTransfer(IERC20(token1), params.recipient, amount1 - added1);
        }
        if (token != token0 && token != token1 && amount != 0) {
            SafeERC20.safeTransfer(IERC20(token), params.recipient, amount);
        }
    }

    struct LeverageDownParams {
        // which token to leverage
        uint256 tokenId;
        // for removing - remove liquidity amount
        uint128 liquidity;
        uint256 amountRemoveMin0;
        uint256 amountRemoveMin1;
        // collect fee amount (if type(uint128).max - ALL)
        uint128 feeAmount0;
        uint128 feeAmount1;
        // how much of token0 should be swapped to lend token
        uint256 amountIn0;
        uint256 amountOut0Min;
        bytes swapData0; // encoded data for swap
        // how much of token1 should be swapped to lend token
        uint256 amountIn1;
        uint256 amountOut1Min;
        bytes swapData1; // encoded data for swap
        // recipient for leftover tokens
        address recipient;
        // for all uniswap deadlineable functions
        uint256 deadline;
    }

    // method called from transform() method in Vault
    function leverageDown(LeverageDownParams calldata params) external {
        _validateCaller(nonfungiblePositionManager, params.tokenId);

        address token = IVault(msg.sender).asset();
        (,, address token0, address token1,,,,,,,,) = nonfungiblePositionManager.positions(params.tokenId);

        uint256 amount0;
        uint256 amount1;

        if (params.liquidity != 0) {
            INonfungiblePositionManager.DecreaseLiquidityParams memory decreaseLiquidityParams = INonfungiblePositionManager
                .DecreaseLiquidityParams(
                params.tokenId, params.liquidity, params.amountRemoveMin0, params.amountRemoveMin1, params.deadline
            );
            (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(decreaseLiquidityParams);
        }

        INonfungiblePositionManager.CollectParams memory collectParams = INonfungiblePositionManager.CollectParams(
            params.tokenId,
            address(this),
            params.feeAmount0 == type(uint128).max ? type(uint128).max : SafeCast.toUint128(amount0 + params.feeAmount0),
            params.feeAmount1 == type(uint128).max ? type(uint128).max : SafeCast.toUint128(amount1 + params.feeAmount1)
        );
        (amount0, amount1) = nonfungiblePositionManager.collect(collectParams);

        uint256 amount = token == token0 ? amount0 : (token == token1 ? amount1 : 0);

        if (params.amountIn0 != 0 && token != token0) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token0), IERC20(token), params.amountIn0, params.amountOut0Min, params.swapData0
                )
            );
            amount0 -= amountIn;
            amount += amountOut;
        }
        if (params.amountIn1 != 0 && token != token1) {
            (uint256 amountIn, uint256 amountOut) = _routerSwap(
                Swapper.RouterSwapParams(
                    IERC20(token1), IERC20(token), params.amountIn1, params.amountOut1Min, params.swapData1
                )
            );
            amount1 -= amountIn;
            amount += amountOut;
        }

        SafeERC20.safeIncreaseAllowance(IERC20(token), msg.sender, amount);
        (uint256 repayedAmount,) = IVault(msg.sender).repay(params.tokenId, amount, false);
        SafeERC20.safeApprove(IERC20(token), msg.sender, 0);

        // send leftover tokens
        if (amount > repayedAmount) {
            SafeERC20.safeTransfer(IERC20(token), params.recipient, amount - repayedAmount);
        }
        if (amount0 != 0 && token != token0) {
            SafeERC20.safeTransfer(IERC20(token0), params.recipient, amount0);
        }
        if (amount1 != 0 && token != token1) {
            SafeERC20.safeTransfer(IERC20(token1), params.recipient, amount1);
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre LeverageTransformer
Buscando 'LeverageTransformer' [SQLite FTS5] (dominio: general)...

Top 1 findings relevantes: (18ms)

 1. [MEDIUM] [M-21] Dangerous use of deadline parameter — Revert Lend

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:

1. [MEDIUM] [M-21] Dangerous use of deadline parameter (Revert Lend)
   
<https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/transformers/AutoCompound.sol#L159-L172> 

<http...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio lending
Buscando 'LeverageTransformer leverageUp leverageDown' [SQLite FTS5] (dominio: lending)...
Top 1 findings relevantes: (6ms)
 1. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens — Tapioca DAO
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer leverageUp leverageDown | Dominio: lending
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens (Tapioca DAO)
Pathway for [`sendForLeverage`](https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L323) -> [`leverageDown`](https...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'LeverageTransformer leverageUp leverageDown' [SQLite FTS5] (dominio: general)...
Top 3 findings relevantes: (1ms)
 1. [HIGH] [H-28] TOFT and USDO Modules Can Be Selfdestructed — Tapioca DAO
 2. [HIGH] [H-33] `BaseTOFTLeverageModule.sol`: `leverageDownInternal` tries to burn tokens — Tapioca DAO
 3. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens — Tapioca DAO
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: LeverageTransformer leverageUp leverageDown | Dominio: general
Los siguientes 3 findings de protocolos similares son relevantes:
1. [HIGH] [H-28] TOFT and USDO Modules Can Be Selfdestructed (Tapioca DAO)
<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L184-L...
2. [HIGH] [H-33] `BaseTOFTLeverageModule.sol`: `leverageDownInternal` tries to burn tokens from wrong address (Tapioca DAO)
<https://github.com/Tapioca-DAO/tapiocaz-audit/blob/bcf61f79464cfdc0484aa272f9f6e28d5de36a8f/contracts/tOFT/modules/BaseTOFTLeverageModule.sol#L212> ...
3. [HIGH] [H-46] TOFT leverageDown always fails if TOFT is a wrapper for native tokens (Tapioca DAO)
Pathway for [`sendForLeverage`](https://github.com/Tapioca-DAO/tapiocaz-audit/blob/master/contracts/tOFT/BaseTOFT.sol#L323) -> [`leverageDown`](https...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio (lending)

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Rounding dust (1 wei per operation) is normal in integer math -- allow tolerance of max(numPayments, numLoans) + 1
  ⚠ Mock oracles produce unrealistic AUM values -- always confirm on fork
  ⚠ Some protocols batch-accrue via 'touch()' -- verify it covers all paths
  ⚠ Open-term vs fixed-term loans have different accrual mechanics
  ⚠ Interest accrual over long periods can legitimately make positions unhealthy -- not a bug
  ⚠ Oracle price updates between check and execution create edge cases
  ⚠ Rounding can make unrealizedLosses slightly exceed AUM -- allow tolerance of numLoans + 1
  ⚠ Mock liquidation tests often miss the real oracle impact
  ⚠ Partial liquidity scenarios are complex but not bugs -- check the partialLiquidity flag logic
  ⚠ Queue processing in batches may leave dust -- tolerance needed
  ⚠ Rounding tolerance needed: max(numPayments, numLoans) + 1 for interest aggregates
  ⚠ Open-term and fixed-term have different aggregate tracking -- check both

## CHECKLIST DE INVARIANTES
When you open a new lending protocol's code, check these in order:
### Architecture (5 min)
- [ ] Map the contract hierarchy: Vault/Pool -> LoanManager -> Loan
- [ ] Identify: where is `totalAssets` computed? Is it `balanceOf` or internal tracking?
- [ ] Identify: ERC4626 vault? Custom share math?
- [ ] Identify: oracle source and type (Chainlink, TWAP, custom)
- [ ] Identify: interest rate model (linear, kinked, adaptive)
- [ ] Identify: withdrawal mechanism (instant, queued/cyclical, timelock)
### Interest Accrual (10 min)
- [ ] Is `accrueInterest()` called FIRST in every state-changing function?
- [ ] Does the interest accumulator only increase? (INV-INT-005)
- [ ] Is there a MAX interest rate cap? (INV-INT-004)
- [ ] Can `lastAccrualTimestamp` ever be in the future? (INV-INT-002)
- [ ] Fixed-term: is `domainEnd` == earliest payment due date? (INV-LOAN-014)
- [ ] Open-term: is `payment.startDate` == `dateFunded` or `datePaid`? (INV-LOAN-034)
### Share/Exchange Rate (10 min)
- [ ] `sum(balanceOf) == totalSupply`? (INV-POOL-007)
- [ ] `totalAssets >= totalSupply` (exchange rate >= 1)? (INV-POOL-003)
- [ ] First depositor inflation protection? (dead shares, virtual offset)
- [ ] `convertToShares` and `convertToAssets` are inverse? (INV-POOL-004, INV-POOL-005)

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Reentrancy) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `LT` (ej: LT-01, LT-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_LeverageTransformer_FlowHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: LT-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "LT-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
