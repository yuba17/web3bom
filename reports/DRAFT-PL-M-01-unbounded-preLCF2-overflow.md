# Missing Upper Bound on `preLCF2` Causes Arithmetic Overflow in `preLiquidate()`

## Severity

Low

## Relevant Context

The `PreLiquidation` constructor validates bounds for all pre-liquidation parameters except `preLCF2`, which has no upper bound. The constructor checks `preLCF1 <= preLCF2` (L88) and `preLCF1 <= WAD` (L89), but unlike `preLIF2` which is bounded by `WAD / LLTV` (L92), `preLCF2` can be set to any value up to `type(uint256).max`.

## Finding Description

When `preLCF2` is set to an extremely large value (e.g., `type(uint256).max`), the computation at L169 of `preLiquidate()` will always revert due to arithmetic overflow:

```solidity
uint256 preLCF = quotient.wMulDown(PRE_LCF_2 - PRE_LCF_1) + PRE_LCF_1;
```

`wMulDown(x, y)` computes `(x * y) / WAD` using Solidity 0.8.27 checked arithmetic. When `PRE_LCF_2 - PRE_LCF_1 ≈ type(uint256).max`, the multiplication `quotient * (PRE_LCF_2 - PRE_LCF_1)` overflows `uint256` for any `quotient > 0`. Since `quotient > 0` for every position in the pre-liquidation zone (`ltv > preLltv`), **every call to `preLiquidate()` reverts**, making the contract permanently unusable.

Note the asymmetry in constructor validation:

| Parameter | Lower Bound | Upper Bound | Overflow Protected? |
|-----------|-------------|-------------|---------------------|
| `preLIF1` | `>= WAD` | `<= preLIF2` | Yes |
| `preLIF2` | `>= preLIF1` | `<= WAD / LLTV` (L92) | **Yes — bounded** |
| `preLCF1` | N/A | `<= WAD` (L89) | Yes |
| `preLCF2` | `>= preLCF1` | **None** | **No — can overflow** |

The comment at L167 states: *"the pre-liquidation close factor can be greater than WAD (100%)"*, indicating the design intentionally allows values > 1.0. However, the lack of any upper bound allows values so extreme that the arithmetic overflows.

## Impact

A `PreLiquidation` contract deployed with extreme `preLCF2` via the `PreLiquidationFactory`:
1. Passes all constructor validation and is registered as `isPreLiquidation[addr] = true`
2. Cannot execute any pre-liquidation — `preLiquidate()` always reverts with arithmetic overflow
3. Is permanently broken (all parameters are immutable)

A borrower who authorizes such a contract via `MORPHO.setAuthorization()` will not have pre-liquidation protection, causing their position to skip directly to Morpho's regular liquidation (which has worse terms — higher close factor and liquidation incentive).

## Proof of Concept

```solidity
function test_PL_M_01_unboundedPreLCF2_overflow_DoS() public {
    PreLiquidationParams memory params = PreLiquidationParams({
        preLltv: 0.7 ether,
        preLCF1: 0.5 ether,
        preLCF2: type(uint256).max,  // No upper bound — passes constructor
        preLIF1: WAD,
        preLIF2: MathLib.wDivDown(WAD, lltv),
        preLiquidationOracle: address(oracle)
    });

    // Deploys successfully — constructor accepts extreme preLCF2
    preLiquidation = factory.createPreLiquidation(id, params);
    assertTrue(factory.isPreLiquidation(address(preLiquidation)));

    // Setup: borrower at 75% LTV (between preLltv=70% and LLTV=80%)
    _setupPosition(100 ether, 75 ether);

    // preLiquidate() ALWAYS reverts — overflow in L169
    vm.prank(LIQUIDATOR);
    vm.expectRevert();  // Arithmetic overflow
    preLiquidation.preLiquidate(BORROWER, 0, 1, hex"");
}

// Control test: same setup with reasonable preLCF2 succeeds
function test_PL_M_01_reasonable_preLCF2_works() public {
    PreLiquidationParams memory params = PreLiquidationParams({
        preLltv: 0.7 ether,
        preLCF1: 0.5 ether,
        preLCF2: WAD,  // 100% — reasonable
        preLIF1: WAD,
        preLIF2: MathLib.wDivDown(WAD, lltv),
        preLiquidationOracle: address(oracle)
    });

    preLiquidation = factory.createPreLiquidation(id, params);
    _setupPosition(100 ether, 75 ether);

    vm.prank(LIQUIDATOR);
    preLiquidation.preLiquidate(BORROWER, 1 ether, 0, hex"");
    // Succeeds without revert
}
```

Both tests pass: the overflow test confirms the DoS, the control test confirms normal operation with bounded `preLCF2`.

## Recommendation

Add an upper bound check for `preLCF2` in the constructor, consistent with the existing bound on `preLIF2`:

```solidity
require(_preLiquidationParams.preLCF2 <= type(uint256).max / WAD, ErrorsLib.PreLCFTooHigh());
```

Or, for a tighter practical bound:

```solidity
// Ensure preLCF computation in preLiquidate() cannot overflow
// quotient <= WAD, so (PRE_LCF_2 - PRE_LCF_1) * WAD must not overflow
require(_preLiquidationParams.preLCF2 <= type(uint256).max / WAD, ErrorsLib.PreLCFTooHigh());
```
