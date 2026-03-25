# Math Libraries & Fixed-Point Arithmetic Combat Briefing

> What you need to know BEFORE auditing fixed-point math, arithmetic libraries, and numerical computation in Solidity.
> Covers: PRBMath, FullMath (Uniswap), ABDKMath, Solmate FixedPointMathLib, OpenZeppelin Math, WadRayMath (Aave), LogExpMath (Balancer), and custom implementations.
> Sources: Uniswap V3 core, Aave V2/V3, Compound V2, Balancer V2, Morpho Blue, Euler Finance, PRBMath docs, real audit findings.

---

## 1. Bugs Conocidos

### Rounding & Precision

```yaml
- id: ml-001
  pattern: rounding-direction-inconsistency
  titulo: "Rounding direction inconsistent — protocol rounds in favor of user instead of protocol"
  causa_raiz: >
    Fixed-point arithmetic in Solidity truncates (rounds toward zero) by default.
    Protocols must explicitly choose rounding direction: deposits/mints round DOWN
    (fewer shares for depositor), withdrawals/burns round UP (more assets needed to
    redeem). When a protocol uses mulDiv or mulWad without specifying roundUp for
    debt-increasing operations, users extract dust per operation. Over thousands of
    operations, dust accumulates into meaningful value extraction.
  como_funciona:
    - "1. Protocol uses mulDivDown (default) for BOTH deposit share calculation AND withdrawal asset calculation."
    - "2. Attacker deposits minimal amounts repeatedly — each deposit rounds DOWN, giving slightly fewer shares than owed."
    - "3. BUT on withdrawal, asset calculation also rounds DOWN — attacker gets slightly more assets per share."
    - "4. Net effect: each deposit+withdraw cycle extracts 1 wei of rounding error from the vault."
    - "5. With flash loans and gas-cheap L2s, attacker runs thousands of cycles to drain vault reserves."
    - "6. The last depositors cannot fully withdraw — vault is insolvent by the accumulated dust."
  invariante: |
    // Protocol-favorable rounding: round DOWN when giving to user, round UP when taking from user
    // Deposits: shares = assets * totalShares / totalAssets → roundDown (fewer shares minted)
    // Withdrawals: assets = shares * totalAssets / totalShares → roundDown (fewer assets returned)
    // Borrows: debtShares = amount * totalDebtShares / totalDebt → roundUp (more debt recorded)
    // Repays: amount = debtShares * totalDebt / totalDebtShares → roundUp (more repayment required)
    function check_rounding_direction_ml001() internal {
        uint256 assetsIn = 1000;
        uint256 sharesMinted = vault.previewDeposit(assetsIn);
        uint256 assetsOut = vault.previewRedeem(sharesMinted);
        t(assetsOut <= assetsIn, "ML-001: withdraw must not exceed deposit for same shares");
    }
  que_mirar:
    - "Does the protocol use mulDivUp for debt-increasing paths (borrow, mint debt shares)?"
    - "Does it use mulDivDown for user-favorable paths (deposit shares, withdrawal assets)?"
    - "Are there separate roundUp/roundDown variants of the math function being used?"
    - "grep for: mulDiv, mulWad, divWad — check if roundUp variant exists and is used correctly"
    - "In ERC4626 vaults: check convertToShares (should round DOWN) and convertToAssets (should round DOWN for user, UP for protocol)"
  como_se_arregla: >
    Use mulDivUp/mulWadUp for operations that increase protocol claims (debt shares, required
    repayment). Use mulDivDown/mulWadDown for operations that give value to users (deposit
    shares, withdrawal amounts). Follow OpenZeppelin Math.Rounding pattern or Solmate
    FixedPointMathLib.mulDivUp/mulDivDown.
  trampas:
    - "1 wei per operation is usually not exploitable on mainnet (gas cost > profit) — but on L2s with sub-cent gas, it can be"
    - "Some protocols intentionally round in favor of users for UX — verify this is documented"
    - "ERC4626 standard explicitly requires specific rounding for each function — check the spec"
    - "convertToShares rounding DOWN and convertToAssets rounding DOWN is correct for ERC4626 (both favor protocol)"
  solodit_ids:
    - "h-1-incorrect-rounding-direction-in-geometric-pool-ask_exact_amount_out-allows-theft-of-funds-sherlock-dango-dex-git"
    - "m-1-wrong-direction-of-rounding-in-redeem-may-lead-to-drain-if-exchange-rate-grows-large-sherlock-malda-git"
    - "incorrect-rounding-direction-in-supervaultconverttoassets-spearbit-none-superform-v2-periphery-pdf"
    - "incorrect-rounding-directions-spearbit-none-pendle-core-v3-pdf"
    - "rounding-directions-are-not-applied-correctly-in-_calcmm-part-2-spearbit-none-pendle-core-v3-pdf"
    - "rounding-in-favor-of-the-violator-can-subject-liquidators-to-losses-during-partial-liquidation-cyfrin-none-vii-markdown"
    - "l-01-price-impact-amount-rounds-in-favor-of-user-pashov-audit-group-none-shred_2026-01-31-markdown"
    - "inconsistent-rounding-in-apply_isolated_margin-functions-favors-users-in-some-cases-quantstamp-dipcoin-perpetual-markdown"
    - "compensationpricefinder-amount-delta-rounding-directions-are-not-consistent-with-uniswap-cyfrin-none-sorella-l2-angstrom-markdown"
    - "l-04-double-floor-rounding-in-borrow-path-slightly-favors-users-pashov-audit-group-none-tangent_2025-10-30-markdown"
  incidentes:
    - "Pendle Core V3 (Spearbit) — Multiple rounding direction issues in _calcPM and _calcMM allowing dust extraction"
    - "Malda (Sherlock) — Wrong rounding in redeem allows drain when exchange rate is large (Medium)"
    - "Dango DEX (Sherlock) — Incorrect rounding in geometric pool ask_exact_amount_out allows theft of funds (High)"
    - "Superform V2 (Spearbit) — Incorrect rounding in SuperVault.convertToAssets"
  severidad: medium-high
  confianza: alta
  verificado: true

- id: ml-002
  pattern: phantom-overflow-muldiv
  titulo: "Intermediate multiplication overflow in mulDiv — result fits in uint256 but a*b overflows"
  causa_raiz: >
    When computing (a * b) / c, if a * b > type(uint256).max, Solidity 0.8+ reverts
    even though the final result after division would fit in uint256. This happens
    frequently with fixed-point math: multiplying two 1e18-scaled values produces a
    1e36-scaled intermediate that can overflow for values > ~1.15e38. The correct
    implementation uses 512-bit intermediate multiplication (as in Uniswap FullMath
    or OpenZeppelin Math.mulDiv). Protocols that use naive (a * b) / c or import
    FullMath from pre-0.8 Solidity without wrapping in unchecked blocks will revert.
  como_funciona:
    - "1. Protocol uses a function like: return (amount * price) / PRECISION where amount and price are uint256."
    - "2. User provides amount = 1e30 (1 trillion tokens with 18 decimals), price = 1e20 (100 USD scaled 1e18)."
    - "3. Intermediate: 1e30 * 1e20 = 1e50 > type(uint256).max ≈ 1.15e77 — this specific case fits, but with larger values it overflows."
    - "4. In practice: amount = type(uint256).max / 2, price = 3 → intermediate overflows, result would be ~1.5 which fits."
    - "5. Transaction reverts. If this is in a liquidation path, position becomes unliquidatable — bad debt accrues."
    - "6. If in a withdrawal path, user funds are permanently locked."
  invariante: |
    // FullMath.mulDiv should handle any a, b, c where result fits in uint256
    function check_muldiv_no_overflow_ml002(uint256 a, uint256 b, uint256 c) internal {
        if (c == 0) return;
        // If result fits in uint256, mulDiv should not revert
        (bool success,) = address(this).staticcall(
            abi.encodeWithSignature("safeMulDiv(uint256,uint256,uint256)", a, b, c)
        );
        // Compare naive vs safe: if naive reverts but safe doesn't, we found the bug
        if (success) {
            uint256 result = FullMath.mulDiv(a, b, c);
            t(result <= type(uint256).max, "ML-002: mulDiv overflow");
        }
    }
  que_mirar:
    - "grep for: (a * b) / c, amount * price / PRECISION, shares * totalAssets / totalShares"
    - "Is the protocol using Uniswap FullMath.mulDiv or OpenZeppelin Math.mulDiv? Or naive multiplication?"
    - "If importing FullMath from Uniswap V3: is it wrapped in unchecked{}? FullMath relies on overflow behavior (pre-0.8)"
    - "Check if Solidity version is 0.8+ — if FullMath was written for 0.7, it WILL revert on intermediate overflow"
    - "Look for large token amounts (SHIB has 1e15 supply with 18 decimals = 1e33 raw), high-precision oracles"
  como_se_arregla: >
    Use Uniswap V3 FullMath.mulDiv (properly ported to 0.8+ with unchecked blocks),
    OpenZeppelin Math.mulDiv, or Solmate FixedPointMathLib.mulDiv. These use 512-bit
    intermediate math via assembly. Never use (a * b) / c for user-supplied values.
  trampas:
    - "FullMath from Uniswap V3 was written for Solidity 0.7 — importing it in 0.8+ without unchecked{} breaks it completely"
    - "The bug only manifests with large values — normal test cases with small numbers will pass"
    - "Some protocols limit token decimals to 18 and amounts to uint128 — in those cases, overflow is impossible and this is a false positive"
    - "OpenZeppelin Math.mulDiv handles the edge case correctly in all Solidity versions"
  solodit_ids:
    - "m-10-the-fullmath-library-is-unable-to-handle-intermediate-overflows-due-to-overflow-thats-desired-but-never-reached-sherlock-uxd-uxd-protocol-git"
    - "h-06-incorrect-solidity-version-in-fullmathsol-can-cause-permanent-freezing-of-assets-for-arithmetic-underflow-induced-revert-code4rena-good-entry-good-entry-git"
    - "fullmath-requires-overflow-behavior-spearbit-morpho-pdf"
    - "muldiv-can-round-down-to-0-in-realistic-cases-allowing-for-tax-avoidance-codehawks-tadle-git"
  incidentes:
    - "Good Entry (Code4rena) — Incorrect Solidity version in FullMath.sol causes permanent freezing of assets (High, $50K+ pool)"
    - "UXD Protocol (Sherlock) — FullMath library unable to handle intermediate overflows in 0.8+ (Medium)"
    - "Morpho (Spearbit) — FullMath requires overflow behavior that 0.8+ Solidity prevents"
  severidad: high
  confianza: alta
  verificado: true

- id: ml-003
  pattern: division-before-multiplication
  titulo: "Division before multiplication causes precision loss — truncation compounds through operations"
  causa_raiz: >
    Solidity integer division truncates toward zero. When division is performed before
    multiplication, the truncation error gets amplified by the subsequent multiplication.
    Example: (a / b) * c loses up to (b-1) * c / b precision, while (a * c) / b loses
    only up to b-1. With large multipliers or iterated calculations (compound interest,
    reward distribution), the precision loss can represent significant value.
  como_funciona:
    - "1. Protocol computes user reward as: (userStake / totalStake) * rewardAmount."
    - "2. If userStake = 999, totalStake = 1000, rewardAmount = 1e18: result = 0 * 1e18 = 0."
    - "3. Correct computation: (999 * 1e18) / 1000 = 999e15 — user loses entire reward."
    - "4. More subtle: compound interest computed as ((principal / 1e18) * rate) / 1e18 — each iteration loses precision."
    - "5. Over 365 daily compounds, loss can be 0.1-1% of principal depending on values."
    - "6. Attacker can exploit by manipulating totalStake to maximize truncation against specific users."
  invariante: |
    // For any reward calculation: (a * b) / c should be used, never (a / c) * b
    function check_div_before_mul_ml003(uint256 userStake, uint256 totalStake, uint256 reward) internal {
        if (totalStake == 0 || reward == 0) return;
        uint256 wrongWay = (userStake / totalStake) * reward;
        uint256 rightWay = (userStake * reward) / totalStake; // may overflow — use mulDiv in production
        t(rightWay >= wrongWay, "ML-003: sanity — rightWay always >= wrongWay");
        // If difference is > 1% of rightWay, this is exploitable
        if (rightWay > 0) {
            uint256 lossPercent = ((rightWay - wrongWay) * 10000) / rightWay;
            t(lossPercent < 100, "ML-003: precision loss > 1%");
        }
    }
  que_mirar:
    - "grep for patterns: variable / CONSTANT * variable, or any division followed by multiplication on the result"
    - "Compound interest: is the per-period rate computed by dividing annual rate first?"
    - "Reward per token: is (reward / totalStaked) * userStake used instead of (reward * userStake) / totalStaked?"
    - "Fee calculations: (amount / FEE_DENOMINATOR) * feePercent vs (amount * feePercent) / FEE_DENOMINATOR"
    - "Look for intermediate variables that store division results before multiplying"
  como_se_arregla: >
    Always multiply before dividing. Use mulDiv for operations where intermediate
    multiplication might overflow. If multiple divisions are needed, accumulate all
    multiplications first, then divide once at the end. For compound interest, use
    exponentiation libraries (rpow from DSMath) rather than iterative multiply-divide.
  trampas:
    - "Sometimes division before multiplication is INTENTIONAL for gas optimization — verify impact is < 1 wei"
    - "If the divisor is small (e.g., 100 for percentage), the truncation error may be negligible"
    - "Multiplying first can cause overflow — must use mulDiv or check bounds"
    - "In loops, even tiny per-iteration errors compound — don't dismiss 1 wei errors in iterated contexts"
  solodit_ids:
    - "h-02-division-before-multiplication-could-lead-to-users-losing-50-in-withdrawalqueue-code4rena-gondi-gondi-git"
    - "m-06-division-before-multiplication-incurs-unnecessary-precision-loss-code4rena-numoen-numoen-contest-git"
    - "h-01-precision-loss-in-the-invariant-function-can-lead-to-loss-of-funds-code4rena-numoen-numoen-contest-git"
    - "m-7-calculating-new-rewards-is-susceptible-to-precision-loss-due-to-division-before-multiplication-sherlock-ajna-ajna-git"
    - "h-02-division-before-multiplication-can-lead-to-zero-rounding-of-return-amount-code4rena-illuminate-illuminate-git"
    - "m-2-fluidlocker_getunlockingpercentage-divides-before-multiplying-suffering-a-significant-precision-error-sherlock-superfluid-locking-contract-git"
    - "divide-before-multiply-loses-precision-in-fivefiftyrule_updateentityallowance-and-leads-to-caps-being-exceeded-cyfrin-none-remora-dynamic-tokens-markdown"
    - "compounding-precision-loss-in-_hypetoexlst-increasingly-delays-withdrawals-as-protocol-yields-spearbit-none-kinetiq-lst-protocol-pdf"
  incidentes:
    - "Gondi (Code4rena) — Division before multiplication causes users to lose 50% in WithdrawalQueue (High)"
    - "Numoen (Code4rena) — Precision loss in invariant function leads to loss of funds (High)"
    - "Illuminate (Code4rena) — Division before multiplication causes zero rounding of return amount (High)"
    - "Superfluid (Sherlock) — FluidLocker._getUnlockingPercentage divides before multiplying, significant precision error (Medium)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

### Scale & Type Errors

```yaml
- id: ml-004
  pattern: wad-ray-scale-mismatch
  titulo: "WAD/RAY scale mismatch — mixing 1e18 and 1e27 scaled values without conversion"
  causa_raiz: >
    Aave-style protocols use two fixed-point scales: WAD (1e18, for amounts/prices)
    and RAY (1e27, for interest rates/indexes). Operations between WAD and RAY values
    require explicit conversion (wadToRay, rayToWad). When a developer multiplies a
    WAD-scaled value by a RAY-scaled value using plain multiplication, the result is
    scaled to 1e45 — which overflows uint256 for values > ~1.15e32. Or if they divide
    without adjusting scale, the result is off by 1e9. This affects interest accrual,
    health factor calculations, and liquidation thresholds.
  como_funciona:
    - "1. Protocol stores interest index as RAY (1e27) and user balance as WAD (1e18)."
    - "2. Developer computes accrued balance as: balance.wadMul(interestIndex) — uses wadMul (divides by 1e18)."
    - "3. Correct: balance.rayMul(interestIndex) — divides by 1e27."
    - "4. Result is off by 1e9 — balance appears 1 billion times larger than reality."
    - "5. User can borrow against massively inflated collateral value."
    - "6. Or vice versa: using rayMul where wadMul is needed → balance appears 1e9 times smaller → instant liquidation."
  invariante: |
    // After any interest accrual, scaled balance should be within reasonable bounds
    function check_scale_consistency_ml004(uint256 scaledBalance, uint256 index) internal {
        // index is RAY-scaled (1e27), result of rayMul should be WAD-scaled
        uint256 actualBalance = scaledBalance.rayMul(index);
        // Sanity: balance should not exceed total supply of any reasonable token
        t(actualBalance < 1e36, "ML-004: balance exceeds sane bounds — likely scale mismatch");
        // Cross-check: wadMul gives different result
        uint256 wrongBalance = scaledBalance.wadMul(index);
        t(wrongBalance != actualBalance, "ML-004: wadMul and rayMul should differ for RAY-scaled index");
    }
  que_mirar:
    - "grep for: wadMul, rayMul, wadDiv, rayDiv — are they used with the correct operand scales?"
    - "Is the interest index stored as RAY (1e27)? Check all operations that use it — must use rayMul/rayDiv"
    - "Are oracle prices WAD-scaled? Check that price * amount uses wadMul, not rayMul"
    - "Look for custom math that hardcodes 1e18 or 1e27 — verify the constant matches the operand's scale"
    - "In Aave forks: check all uses of liquidityIndex and variableBorrowIndex — these are RAY"
  como_se_arregla: >
    Use explicit type wrappers (Wad, Ray) or naming conventions (_wad, _ray suffix) to
    prevent mixing. Use Aave WadRayMath consistently: wadMul/wadDiv for WAD×WAD, rayMul/rayDiv
    for RAY×RAY, wadToRay/rayToWad for conversions. Code review should flag any arithmetic
    between values of different scales.
  trampas:
    - "Some protocols use 1e18 for everything (Compound-style) — WAD/RAY mismatch is impossible there"
    - "Custom math libraries may use different scale constants — check the actual values"
    - "The error is always exactly 1e9 — if you see values off by ~1e9, suspect this pattern"
    - "Aave V3 uses both WAD and RAY — every fork must be checked for correct usage"
  solodit_ids:
    - "mix-of-scaled-and-non-scaled-parameters-in-_aftertokentransfer-spearbit-none-astera-pdf"
    - "mix-of-scaled-and-non-scaled-parameters-in-_aftertokentransfer-spearbit-none-cod3x-lend-pdf"
    - "scaled-allowance-mismatch-enables-over-approval-exploit-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "Cod3x Lend (Spearbit) — Mix of scaled and non-scaled parameters in _afterTokenTransfer"
    - "Astera (Spearbit) — Mix of scaled and non-scaled parameters in _afterTokenTransfer"
    - "RegnumAurum (CodeHawks) — Scaled allowance mismatch enables over-approval exploit"
    - "Multiple Aave forks — Interest index applied with wadMul instead of rayMul, inflating/deflating balances"
  severidad: critical
  confianza: alta
  verificado: true

- id: ml-005
  pattern: unchecked-cast-truncation
  titulo: "Unsafe downcast from uint256 to uint128/uint96/uint80 silently truncates large values"
  causa_raiz: >
    Solidity 0.8+ does NOT revert on explicit type casting — only on arithmetic overflow.
    Casting uint256(type(uint128).max + 1) to uint128 silently produces 0. Protocols
    that pack multiple values into a single storage slot (common gas optimization) use
    uint128, uint96, uint80, uint48, uint32 — and if the source uint256 exceeds the
    target range, the value wraps around silently. This can truncate balances, timestamps,
    prices, or amounts to absurdly small values.
  como_funciona:
    - "1. Protocol stores user balance as uint128 for gas optimization (two balances per slot)."
    - "2. User deposits amount that fits in uint256 but exceeds uint128.max (≈3.4e38)."
    - "3. Cast: uint128(amount) silently truncates — stored balance wraps to a small number."
    - "4. User's actual deposited tokens are in the contract, but recorded balance is near zero."
    - "5. Funds are effectively locked — user cannot withdraw more than the truncated balance."
    - "6. Alternatively: if a debt amount truncates, borrower owes near-zero and keeps the borrowed tokens."
  invariante: |
    // Every downcast should be checked: value must fit in target type
    function check_safe_downcast_ml005(uint256 value, uint8 targetBits) internal {
        if (targetBits == 128) {
            t(value <= type(uint128).max, "ML-005: uint128 truncation");
        } else if (targetBits == 96) {
            t(value <= type(uint96).max, "ML-005: uint96 truncation");
        } else if (targetBits == 80) {
            t(value <= type(uint80).max, "ML-005: uint80 truncation");
        }
    }
  que_mirar:
    - "grep for: uint128(, uint96(, uint80(, uint48(, uint32(, int128(, int256( — any explicit cast"
    - "Are there SafeCast wrappers (OpenZeppelin SafeCast)? If not, every cast is suspect"
    - "Check what values are being cast — balances, amounts, prices, timestamps?"
    - "Look at struct packing: if a struct uses uint128 for balance, check all write paths"
    - "Uniswap V3 uses uint128 for liquidity — check all paths that compute liquidity"
  como_se_arregla: >
    Use OpenZeppelin SafeCast (toUint128, toUint96, etc.) which reverts on truncation.
    Or add explicit require(value <= type(uint128).max, "overflow") before every cast.
    Never cast user-supplied or computed values without bounds checking.
  trampas:
    - "For timestamps, uint32 overflows in 2106 — not a current concern but uint48 is better"
    - "For token amounts with 18 decimals, uint128.max ≈ 3.4e38 ≈ 3.4e20 tokens — exceeds any real supply"
    - "The real risk is in intermediate calculations: amount * price might exceed uint128 even if each fits"
    - "Some protocols intentionally limit amounts to safe ranges via input validation — check if limits exist"
  solodit_ids:
    - "m-7-unsafe-casting-within-_purchase-function-can-result-in-overflow-sherlock-axis-finance-git"
    - "m-05-unsafe-casting-from-uint256-to-uint16-could-cause-ticket-prizes-to-become-much-smaller-than-intended-code4rena-wenwin-wenwin-contest-git"
    - "m-08-unsafe-downcasting-operation-truncate-users-input-code4rena-escher-escher-contest-git"
    - "h-01-truncation-in-ordervalidator-can-lead-to-resetting-the-fill-and-selling-more-tokens-code4rena-opensea-opensea-seaport-contest-git"
    - "unsafe-casting-between-uint256-and-int256-values-cantina-none-eco-inc-pdf"
    - "unsafe-cast-from-uint256-to-int256-could-overflow-cantina-none-flood-pdf"
    - "unsafe-downcast-in-valkyriesubscribertoint256-could-silently-overflow-cyfrin-none-paladin-valkyrie-markdown"
    - "silent-truncation-on-int224-cast-without-bounds-checks-quantstamp-api3-data-feed-proxy-combinators-markdown"
    - "unchecked-uint256-to-uint128-down-cast-may-truncate-very-large-deposits-quantstamp-camp-markdown"
    - "m-1-unsafe-type-casting-of-poolvalue-can-malfunction-the-whole-market-sherlock-float-capital-float-capital-git"
    - "silent-truncation-in-permit2-transfers-mixbytes-none-barter-dao-markdown"
  incidentes:
    - "OpenSea Seaport (Code4rena) — Truncation in OrderValidator resets fill, allowing re-selling of tokens (High)"
    - "Axis Finance (Sherlock) — Unsafe casting in _purchase causes overflow (Medium)"
    - "WenWin (Code4rena) — Unsafe uint256→uint16 cast makes ticket prizes much smaller than intended (Medium)"
    - "Float Capital (Sherlock) — Unsafe uint256→int256 cast of poolValue can malfunction whole market (Medium)"
    - "Eco Inc (Cantina) — Unsafe casting between uint256 and int256 values"
  severidad: high
  confianza: alta
  verificado: true

- id: ml-006
  pattern: decimal-normalization-error
  titulo: "Decimal normalization error — assuming all tokens use 18 decimals"
  causa_raiz: >
    ERC20 tokens have varying decimals: USDC/USDT use 6, WBTC uses 8, most ERC20 use 18,
    some use 24+. Protocols that hardcode 1e18 scaling or assume token.decimals() == 18
    produce wildly incorrect results for non-18-decimal tokens. A USDC amount of 1e6
    (1 USDC) treated as 1e18 scaling becomes 0.000000000001 USDC — a 1e12 error. This
    breaks oracle price calculations, collateral valuations, swap amounts, and fee
    computations.
  como_funciona:
    - "1. Protocol computes collateral value as: amount * price / 1e18, assuming both are 18-decimal scaled."
    - "2. User deposits 1000 USDC (amount = 1000e6 = 1e9 raw units)."
    - "3. Price from oracle is 1e18 (1 USD in WAD). Computation: 1e9 * 1e18 / 1e18 = 1e9."
    - "4. Protocol interprets 1e9 as 1e9 in 18-decimal space = 0.000000001 — a $0 valuation."
    - "5. User's 1000 USDC collateral is valued at ~$0. Cannot borrow anything."
    - "6. OR reverse: WBTC (8 decimals) amount multiplied by 18-decimal price → value inflated by 1e10."
    - "7. User deposits 1 WBTC, protocol values it at $30,000 * 1e10 = $300 trillion → unlimited borrowing."
  invariante: |
    // Token amounts must be normalized to a common scale before comparison/arithmetic
    function check_decimal_normalization_ml006(address token, uint256 rawAmount) internal {
        uint8 decimals = IERC20Metadata(token).decimals();
        uint256 normalized = rawAmount * (10 ** (18 - decimals));
        // Verify protocol's internal representation matches expected normalization
        uint256 protocolValue = vault.getTokenValue(token, rawAmount);
        uint256 expectedValue = normalized * oracle.getPrice(token) / 1e18;
        // Allow 0.1% tolerance for oracle price differences
        t(protocolValue > expectedValue * 999 / 1000, "ML-006: undervaluation — possible decimal error");
        t(protocolValue < expectedValue * 1001 / 1000, "ML-006: overvaluation — possible decimal error");
    }
  que_mirar:
    - "grep for hardcoded: 1e18, 10**18, 1 ether — are these used as denominators for non-18-decimal tokens?"
    - "Does the protocol call token.decimals() and adjust? Or does it assume 18?"
    - "Check oracle price feeds: Chainlink returns 8 decimals for USD pairs — is this handled?"
    - "Look for: 10**(18 - decimals) or 10**(decimals) — correct normalization pattern"
    - "Check USDC (6), USDT (6), WBTC (8) paths specifically — most common non-18 tokens"
    - "In deployment scripts: does the protocol test with 6-decimal tokens or only 18?"
  como_se_arregla: >
    Always read token.decimals() and normalize. Store the decimal count at initialization
    time (immutable). Use a helper: normalizeAmount(token, amount) = amount * 10**(18 - decimals).
    Chainlink feeds: check feed.decimals() and normalize. Test with USDC, WBTC, and DAI
    (6, 8, 18 decimals) in all integration tests.
  trampas:
    - "Some tokens have dynamic decimals (rare, but bridged tokens on L2 can differ)"
    - "Chainlink feed decimals differ by pair: ETH/USD = 8, ETH/BTC = 18 — check each feed"
    - "10**(18 - decimals) reverts for tokens with >18 decimals — need to handle that case"
    - "Some protocols are intentionally 18-decimal-only and document it — verify scope before reporting"
  solodit_ids:
    - "h-1-protocol-assumes-18-decimals-collateral-sherlock-taurus-taurus-git"
    - "h-6-curve-vault-will-undervalue-or-overvalue-the-lp-pool-tokens-if-it-comprises-tokens-with-different-decimals-sherlock-notional-notional-update-2-git"
    - "claim-will-underflow-and-revert-for-all-tokens-without-18-decimals-spearbit-astaria-pdf"
    - "m-02-price-will-not-always-be-18-decimals-as-expected-and-outlined-in-the-comments-code4rena-caviar-caviar-contest-git"
    - "m-15-oracle-assumes-token-and-feed-decimals-will-be-limited-to-18-decimals-code4rena-inverse-finance-inverse-finance-contest-git"
    - "tokensaleproposalbuy-implicitly-assumes-that-buy-token-has-18-decimals-resulting-in-a-potential-total-loss-scenario-for-dao-pool-cyfrin-none-cyfrin-dexe-markdown"
    - "l-22-non-18-decimal-tokens-cause-incorrect-price-calculations-pashov-audit-group-none-elytra_2025-07-10-markdown"
    - "h-02-bloompool_normalize-price-will-cause-severe-mis-pricing-for-rwas-that-are-not-18-dp-0x52-none-stusdcxbloom-markdown"
    - "decimal-mismatch-in-fee-prepayment-accounting-causes-incorrect-balance-tracking-cyfrin-none-deriverse-dex-markdown"
    - "multiplication-could-overflow-in-rebasinglibrary-for-tokens-with-greater-than-18-decimals-cyfrin-none-securitize-dstoken-rebasing-markdown"
  incidentes:
    - "Taurus (Sherlock) — Protocol assumes 18 decimals for collateral, all non-18 collateral mispriced (High)"
    - "Notional V2 (Sherlock) — Curve vault under/overvalues LP tokens with different-decimal components (High)"
    - "Astaria (Spearbit) — claim() underflows and reverts for all tokens without 18 decimals"
    - "Bloom (0x52) — BloomPool.normalize causes severe mispricing for RWAs not 18dp (High)"
    - "DEXE (Cyfrin) — tokenSaleProposal.buy assumes 18 decimals, total loss for DAO pool"
  severidad: high-critical
  confianza: alta
  verificado: true
```

### Arithmetic Operations

```yaml
- id: ml-007
  pattern: sqrt-precision-loss
  titulo: "Square root precision loss — Babylonian method with insufficient iterations or wrong initial guess"
  causa_raiz: >
    The Babylonian (Newton-Raphson) method for integer square root converges quadratically
    but requires enough iterations to reach full precision for large uint256 inputs.
    Uniswap V3 SqrtPriceMath uses Q64.96 fixed-point square roots (sqrtPriceX96) where
    precision errors directly translate to incorrect tick boundaries and swap amounts.
    Custom sqrt implementations may use too few iterations, wrong initial guesses, or
    fail to handle edge cases (0, 1, type(uint256).max). Off-by-one errors in sqrt
    result in wrong liquidity calculations and price boundaries.
  como_funciona:
    - "1. Protocol uses custom sqrt with only 7 Newton-Raphson iterations (enough for uint128, not uint256)."
    - "2. For values > 2^128, the result can be off by thousands."
    - "3. In AMM context: sqrtPrice error of 1 means the price boundary is slightly wrong."
    - "4. Liquidity calculations use sqrtPrice — small error amplified by large liquidity amounts."
    - "5. Attacker positions liquidity at tick boundaries where sqrt error changes the expected price range."
    - "6. Result: liquidity is active in a different range than expected, causing unexpected losses."
  invariante: |
    // For any sqrt implementation: result * result <= n < (result + 1) * (result + 1)
    function check_sqrt_precision_ml007(uint256 n) internal {
        uint256 root = Math.sqrt(n);
        t(root * root <= n, "ML-007: sqrt too large");
        // Check (root+1)^2 > n — avoiding overflow
        if (root < type(uint128).max) {
            t((root + 1) * (root + 1) > n, "ML-007: sqrt too small");
        }
    }
  que_mirar:
    - "Is the protocol using a well-tested sqrt (OpenZeppelin, Solmate, PRBMath)? Or custom?"
    - "How many Newton-Raphson iterations? 8 is minimum for full uint256 precision"
    - "Does it handle sqrt(0) = 0 and sqrt(1) = 1 correctly?"
    - "In Uniswap V3 forks: is TickMath.getSqrtRatioAtTick identical to the original?"
    - "Check for ceil variant: sqrtCeil should return root + 1 if root^2 < n"
    - "grep for: sqrt, sqrtPrice, sqrtRatio, babylonian, newton"
  como_se_arregla: >
    Use established libraries: OpenZeppelin Math.sqrt (8+ iterations, handles all edge cases),
    Solmate FixedPointMathLib.sqrt, or PRBMath sqrt. For Uniswap V3 forks, use the exact
    original TickMath and SqrtPriceMath — do not modify. If custom sqrt is needed, ensure
    at least 8 iterations and verify with property: root^2 <= n < (root+1)^2.
  trampas:
    - "For most practical DeFi values (< 2^128), 7 iterations is sufficient — only ultra-large values expose the bug"
    - "Solmate sqrt uses a lookup table + 7 iterations — correct for all uint256 values"
    - "Off-by-one in sqrt matters for tick boundaries but may be negligible for simple swap calculations"
    - "sqrtPriceX96 in Uniswap is Q64.96 — standard sqrt won't work, need Q-format-aware implementation"
  solodit_ids:
    - "price_sqrt-can-be-manipulated-by-swapping-through-an-empty-pool-trailofbits-none-tonco-clamm-dex-v16-pdf"
    - "precision-loss-on-large-values-transformed-between-log2-scale-and-the-normal-scale-cyfrin-beanstalk-wells-markdown_"
  incidentes:
    - "TONCO CLAMM (Trail of Bits) — price_sqrt can be manipulated by swapping through an empty pool"
    - "Multiple Uniswap V3 forks — Modified TickMath without proper testing causes tick boundary errors"
  severidad: medium
  confianza: media
  verificado: true

- id: ml-008
  pattern: exp-power-edge-cases
  titulo: "Exponential/power function edge cases — exp() overflow, pow(0,0), extreme inputs"
  causa_raiz: >
    Exponential functions (e^x) and power functions (x^n) in fixed-point math have
    well-known edge cases: exp(x) overflows for x > ~135 (in WAD scale), pow(0,0) is
    mathematically ambiguous, pow(base, large_exp) overflows, and ln(0) is undefined.
    Libraries like PRBMath and Balancer LogExpMath handle these, but custom implementations
    or incorrect input bounds can trigger reverts or return wrong values. In DeFi, these
    functions appear in compound interest (continuously compounded), bonding curves (x^n),
    and time-weighted calculations.
  como_funciona:
    - "1. Protocol uses continuous compound interest: balance * exp(rate * time)."
    - "2. If rate = 100% APY (1e18) and time = 1 year (365 days), rate * time = 3.15e25."
    - "3. exp(3.15e25) vastly overflows uint256 — library reverts or returns garbage."
    - "4. All operations that depend on interest accrual (borrow, repay, liquidate) revert."
    - "5. Protocol is frozen — users cannot interact with their positions."
    - "6. For pow(0, 0): some libraries return 1, others return 0, others revert — inconsistent behavior."
  invariante: |
    // exp() should handle all valid inputs without reverting, and revert clearly on overflow
    function check_exp_bounds_ml008(int256 x) internal {
        // PRBMath exp: valid for x in [-41.446e18, 135.305e18]
        if (x > 135305999368893231589) return; // expected to revert above this
        if (x < -41446531673892822313) return; // expected to return 0 below this
        // Should not revert
        (bool success, bytes memory data) = address(mathLib).staticcall(
            abi.encodeWithSignature("exp(int256)", x)
        );
        t(success, "ML-008: exp() reverted for valid input");
        if (success) {
            int256 result = abi.decode(data, (int256));
            t(result >= 0, "ML-008: exp() returned negative value");
        }
    }
  que_mirar:
    - "What library is used for exp/pow? PRBMath, Solmate, LogExpMath (Balancer), or custom?"
    - "Are input bounds validated BEFORE calling exp/pow? Or does the library handle it?"
    - "grep for: exp(, pow(, rpow(, wadExp(, LogExpMath.pow — check input ranges"
    - "For compound interest: can rate * time exceed the exp() input bound?"
    - "Does the protocol clamp extreme rates? (e.g., max 1000% APY)"
    - "Check edge: what happens when time = 0? When rate = 0? When both are 0?"
  como_se_arregla: >
    Use established libraries with clear input bounds: PRBMath.exp (handles up to ~135.3),
    Solmate wadExp (similar bounds), Balancer LogExpMath (different valid range). Validate
    inputs before calling. For compound interest, clamp rate * time to the library's max.
    For pow(0, 0), define expected behavior explicitly.
  trampas:
    - "PRBMath exp returns 0 for very negative inputs — this is correct mathematical behavior, not a bug"
    - "Compound interest with realistic rates (1-20% APY) and time (1 year) will never overflow exp()"
    - "The real risk is protocols that allow arbitrary rate setting by governance or untrusted parties"
    - "Some libraries use different valid ranges — check the specific library's documentation"
  solodit_ids:
    - "incorrect-upper-bound-check-in-wexpx-can-produce-an-overflowed-result-cantina-none-morpho-pdf"
    - "m-6-interest-accrual-can-get-stuck-when-wadexp-underflows-to-0-causing-division-by-zero-sherlock-monolith-stablecoin-factory-git"
    - "m-5-exponential-and-logarithmic-price-adapters-will-return-incorrect-pricing-when-moving-from-higher-dp-token-to-lower-dp-token-sherlock-none-index-update-git"
    - "m-1-liquidation-bonus-scales-exponentially-instead-of-linearly-sherlock-wagmileverage-v2-git"
  incidentes:
    - "Morpho (Cantina) — Incorrect upper bound check in wExp(x) produces overflowed result"
    - "Monolith (Sherlock) — Interest accrual stuck when wadExp underflows to 0, causing division by zero (Medium)"
    - "Index Update (Sherlock) — Exponential price adapter returns incorrect pricing for different decimal tokens (Medium)"
  severidad: medium-high
  confianza: alta
  verificado: true

- id: ml-009
  pattern: fixedpoint-multiplication-overflow
  titulo: "Fixed-point mulWad/mulDiv overflow — near-max values cause revert in critical paths"
  causa_raiz: >
    mulWad(a, b) computes (a * b) / 1e18. Even with 512-bit intermediate math, if both
    a and b are close to type(uint256).max, the result exceeds uint256. For mulDiv(a, b, c),
    the result can overflow when c is small relative to a * b. Protocols that don't bound
    inputs can have critical paths (withdrawal, liquidation, interest accrual) revert for
    large positions, effectively locking funds.
  como_funciona:
    - "1. Protocol uses mulWad for interest calculation: accruedDebt = debt.mulWad(interestMultiplier)."
    - "2. After long time without interaction, interestMultiplier grows very large (e.g., 1e30 for 1000x)."
    - "3. debt = 1e30 (large position), interestMultiplier = 1e30 → intermediate = 1e60."
    - "4. Result after dividing by 1e18 = 1e42 — fits in uint256."
    - "5. But if debt = 1e50, interestMultiplier = 1e30 → intermediate = 1e80 > uint256.max."
    - "6. mulWad reverts. Liquidation fails. Position accrues bad debt indefinitely."
  invariante: |
    // Critical paths should never revert due to overflow
    function check_mulwad_bounds_ml009(uint256 a, uint256 b) internal {
        // mulWad should not revert if result fits in uint256
        uint256 maxResult = type(uint256).max;
        // If a * b / 1e18 would fit, it should succeed
        if (a <= maxResult / b || b == 0) {
            uint256 result = a.mulWad(b);
            t(true, "ML-009: mulWad succeeded");
        }
    }
  que_mirar:
    - "What happens to critical paths (liquidation, repay, withdraw) when amounts are very large?"
    - "Can interest multipliers grow unbounded? Is there a maximum age or rate cap?"
    - "grep for: mulWad, mulDiv, mulDivDown — trace the inputs to find maximum possible values"
    - "Check for positions that have been dormant for years — interest accumulation can create huge multipliers"
    - "Is there a self-liquidation mechanism that caps exposure before overflow?"
  como_se_arregla: >
    Cap interest multipliers to a sane maximum (e.g., 100x). Add position hygiene:
    if a position hasn't been touched in N months, allow anyone to trigger a state
    update. Use libraries with clear overflow behavior. For critical paths, add
    try/catch to prevent permanent lockout.
  trampas:
    - "In practice, most protocols cap interest rates — compute max multiplier over max duration to check if overflow is possible"
    - "Solmate mulWad uses assembly and reverts with 0 — can be hard to debug"
    - "If the protocol has a position size limit, overflow may be mathematically impossible — do the math"
    - "Some overflows are only reachable after centuries of compounding — not a real bug"
  solodit_ids:
    - "l-03-uint256-overflow-in-reward-calculations-for-tokens-with-high-decimals-pashov-audit-group-none-reserve_2026-02-27-markdown"
    - "multiplication-could-overflow-in-rebasinglibrary-for-tokens-with-greater-than-18-decimals-cyfrin-none-securitize-dstoken-rebasing-markdown"
  incidentes:
    - "Securitize (Cyfrin) — Multiplication overflow in RebasingLibrary for tokens with >18 decimals"
    - "Reserve (Pashov) — uint256 overflow in reward calculations for tokens with high decimals"
  severidad: medium
  confianza: media
  verificado: true
```

### Signed Arithmetic & Accumulators

```yaml
- id: ml-010
  pattern: signed-unsigned-confusion
  titulo: "Signed/unsigned confusion — int256 cast to uint256 loses negative values, or vice versa"
  causa_raiz: >
    DeFi protocols use int256 for values that can be negative: PnL, price deltas,
    funding rates, position changes. Converting between int256 and uint256 requires
    careful handling: int256(-1) cast to uint256 becomes type(uint256).max (a huge
    positive number). Conversely, uint256 values > type(int256).max cast to int256
    produce negative values. Price feeds (Chainlink returns int256), AMM position
    accounting, and perpetual funding rates are common sources.
  como_funciona:
    - "1. Protocol reads Chainlink price: int256 answer = feed.latestAnswer()."
    - "2. Cast to uint256 for internal math: uint256 price = uint256(answer)."
    - "3. If Chainlink returns negative price (can happen during oracle issues), uint256(-1e8) = type(uint256).max - 1e8 + 1."
    - "4. Protocol now uses an astronomically large price — collateral valued at infinity."
    - "5. User borrows against the inflated collateral — unlimited borrowing."
    - "6. When oracle recovers, user is massively underwater — protocol absorbs bad debt."
  invariante: |
    // int256 to uint256 conversion must check for negative values
    function check_signed_cast_ml010(int256 value) internal {
        if (value < 0) {
            // Should revert or handle, never silently cast
            (bool success,) = address(this).staticcall(
                abi.encodeWithSignature("unsafeCast(int256)", value)
            );
            t(!success, "ML-010: negative int256 silently cast to uint256");
        } else {
            uint256 result = uint256(value);
            t(int256(result) == value, "ML-010: roundtrip cast failed");
        }
    }
  que_mirar:
    - "grep for: uint256(int, int256(uint — any cross-sign cast"
    - "Chainlink feeds: is answer checked for > 0 before casting to uint256?"
    - "PnL calculations: can positions have negative value? Is the negative handled?"
    - "Perpetual funding rates: negative funding rate cast to uint256 → huge positive number"
    - "Look for SafeCast usage — if absent, all cross-sign casts are suspect"
    - "Subtraction results stored in uint256 — if a > b, a - b underflows in 0.8+"
  como_se_arregla: >
    Always validate sign before casting: require(value >= 0, "negative value"). Use
    OpenZeppelin SafeCast.toUint256(int256) which reverts on negative. For values that
    can legitimately be negative, keep them as int256 throughout the computation chain.
    Never mix signed and unsigned in the same arithmetic expression.
  trampas:
    - "Solidity 0.8+ reverts on uint256 underflow (a - b when a < b) — this is NOT the same as signed cast issues"
    - "Some protocols handle negative PnL as separate logic paths — the cast may never receive negative input"
    - "Chainlink answer can be negative for certain feed types — but not for major pairs like ETH/USD"
    - "int256(type(uint256).max) is negative — but no real value should reach that"
  solodit_ids:
    - "unsafe-casting-between-uint256-and-int256-values-cantina-none-eco-inc-pdf"
    - "unsafe-cast-from-uint256-to-int256-could-overflow-cantina-none-flood-pdf"
    - "unsafe-downcast-in-valkyriesubscribertoint256-could-silently-overflow-cyfrin-none-paladin-valkyrie-markdown"
    - "m-1-unsafe-type-casting-of-poolvalue-can-malfunction-the-whole-market-sherlock-float-capital-float-capital-git"
  incidentes:
    - "Float Capital (Sherlock) — Unsafe type casting of poolValue (int256→uint256) malfunctions whole market (Medium)"
    - "Eco Inc (Cantina) — Unsafe casting between uint256 and int256 values"
    - "Flood (Cantina) — Unsafe cast from uint256 to int256 could overflow"
  severidad: high
  confianza: alta
  verificado: true

- id: ml-011
  pattern: cumulative-sum-overflow
  titulo: "Cumulative accumulator overflow — rewardPerToken or price accumulator wraps after long operation"
  causa_raiz: >
    Many DeFi protocols track cumulative values that only increase: rewardPerTokenStored
    (staking), priceCumulativeLast (Uniswap V2 TWAP), cumulativeInterest (lending).
    In Solidity 0.8+, these accumulators revert on overflow instead of wrapping. Since
    they never decrease, given enough time or large enough rates, they will hit uint256.max
    and brick the contract. Uniswap V2 used Solidity 0.5 where overflow wraps — the TWAP
    math depends on this wrapping behavior. Forks using 0.8+ break this intentional design.
  como_funciona:
    - "1. Uniswap V2 accumulates price0CumulativeLast += price * timeElapsed every block."
    - "2. In Solidity 0.5/0.6, this wraps on overflow — TWAP is computed as (cumB - cumA) which works with wrapping."
    - "3. A fork recompiles with Solidity 0.8+ — overflow now reverts instead of wrapping."
    - "4. After enough time, priceCumulativeLast overflows → all swaps revert → pool is bricked."
    - "5. For reward accumulators: rewardPerTokenStored = cumReward / totalStaked. If cumReward grows without bound, it overflows."
    - "6. Once overflowed, no user can claim rewards — all claimReward() calls revert."
  invariante: |
    // Accumulators that depend on wrapping must be in unchecked blocks
    function check_accumulator_safety_ml011(uint256 accumulator, uint256 increment) internal {
        // If in unchecked{}, wrapping is fine. If not, check distance from max.
        uint256 headroom = type(uint256).max - accumulator;
        // If increment could exceed headroom in realistic time, flag it
        // Example: if increment is per-second and we need 10 years of headroom
        uint256 tenYearsSeconds = 10 * 365 days;
        t(headroom / increment > tenYearsSeconds, "ML-011: accumulator overflow within 10 years");
    }
  que_mirar:
    - "grep for: += in cumulative variables — priceCumulative, rewardPerToken, cumulativeInterest"
    - "Is the Solidity version 0.8+? If so, are cumulative updates in unchecked{} blocks?"
    - "Uniswap V2 forks: CRITICAL — price accumulators MUST use unchecked{} in 0.8+"
    - "Staking contracts: does rewardPerTokenStored grow without bound? What's the max after 10 years?"
    - "Is the accumulator ever reset? If not, what's the maximum value after infinite time?"
    - "Look for: overflow is expected, by design — if comments say this, verify unchecked{} is present"
  como_se_arregla: >
    For intentional wrapping (Uniswap V2 TWAP): wrap the accumulator update in unchecked{}.
    For non-wrapping accumulators: ensure the growth rate is bounded such that overflow
    cannot occur in the contract's expected lifetime (e.g., 100 years). For reward
    accumulators: periodically reset or use a per-epoch design. Alternatively, use
    uint256 with realistic bounds: 1e18 reward per second for 100 years ≈ 3.15e27, safely below uint256.max.
  trampas:
    - "Uniswap V2 TWAP wrapping is INTENTIONAL and correct — reporting it as a bug in the original is a false positive"
    - "In forks using 0.8+ without unchecked{}, the wrapping behavior is BROKEN — this IS a real bug in the fork"
    - "rewardPerTokenStored overflow is theoretical for most protocols — compute the actual max before reporting"
    - "uint256.max ≈ 1.15e77 — even at 1e18 per second, overflow takes 3.6e51 seconds (effectively forever)"
  solodit_ids:
    - "m-07-_updatetwav-and-_gettwav-will-revert-when-cumulativeprice-overflows-code4rena-nibbl-nibbl-contest-git"
    - "h-02-uniswapv2priceoraclesol-currentcumulativeprices-will-revert-when-pricecumulative-addition-overflow-code4rena-phuture-finance-phuture-finance-contest-git"
    - "m-20-price-accumulators-overflow-in-gtelaunchpadv2pair-contract-causes-amm-wide-dos-code4rena-gte-gte-git"
    - "tickmath-might-revert-in-solidity-version-08-spearbit-timeless-pdf"
    - "overflow-is-possible-when-calculating-timeweightedaveragetick-value-mixbytes-none-liquorice-markdown"
    - "h-06-get_fee_growth_inside-in-tickrs-should-allow-for-underflowoverflow-but-doesnt-code4rena-superposition-superposition-git"
    - "m-2-readding-the-reward-token-causes-userrewardpertokenpaid-to-be-incorrect-for-some-users-resulting-in-them-receiving-too-many-rewards-sherlock-symmio-staking-and-vesting-git"
  incidentes:
    - "Nibbl (Code4rena) — _updateTWAV/_getTWAV reverts when cumulativePrice overflows in 0.8+ (Medium)"
    - "Phuture Finance (Code4rena) — UniswapV2PriceOracle currentCumulativePrices reverts on overflow (High)"
    - "GTE (Code4rena) — Price accumulators overflow in LaunchpadV2Pair causes AMM-wide DoS (Medium)"
    - "Superposition (Code4rena) — get_fee_growth_inside should allow underflow/overflow but doesn't (High)"
    - "Timeless (Spearbit) — TickMath might revert in Solidity 0.8 due to missing unchecked blocks"
  severidad: high
  confianza: alta
  verificado: true
```

### Precision & Approximation

```yaml
- id: ml-012
  pattern: log-ln-approximation-error
  titulo: "Log2/ln approximation errors — concentrated liquidity tick math and bonding curve precision"
  causa_raiz: >
    Logarithmic functions in Solidity are implemented as piecewise approximations
    (Uniswap V3 TickMath) or Taylor series (Balancer LogExpMath). These approximations
    have precision limits: TickMath.getTickAtSqrtRatio has ±1 tick error documented in
    the code. Protocols that use tick values in pricing calculations without accounting
    for this error can produce incorrect swap amounts. Custom log implementations may
    have larger errors or undefined behavior at boundary inputs (log(0), log(1)).
  como_funciona:
    - "1. Protocol computes tick from sqrtPrice using TickMath.getTickAtSqrtRatio."
    - "2. This function has documented ±1 tick precision error."
    - "3. Protocol uses the tick directly for price computation without the ±1 buffer."
    - "4. At tick boundaries, the ±1 error means a position may be active when it should be inactive (or vice versa)."
    - "5. For concentrated liquidity, this means fees are earned/not earned incorrectly at tick edges."
    - "6. In bonding curves using log: small precision error in log amplified by exp in reverse direction."
  invariante: |
    // Tick from sqrtPrice should roundtrip within ±1
    function check_log_precision_ml012(uint160 sqrtPriceX96) internal {
        if (sqrtPriceX96 < TickMath.MIN_SQRT_RATIO || sqrtPriceX96 >= TickMath.MAX_SQRT_RATIO) return;
        int24 tick = TickMath.getTickAtSqrtRatio(sqrtPriceX96);
        uint160 reconstructed = TickMath.getSqrtRatioAtTick(tick);
        // Reconstructed sqrtPrice should be <= original (rounds down)
        t(reconstructed <= sqrtPriceX96, "ML-012: tick→sqrtPrice should round down");
        // And next tick's sqrtPrice should be > original
        uint160 nextTick = TickMath.getSqrtRatioAtTick(tick + 1);
        t(nextTick > sqrtPriceX96, "ML-012: next tick sqrtPrice should exceed original");
    }
  que_mirar:
    - "Is the protocol using Uniswap V3 TickMath unmodified? Any changes to the lookup tables?"
    - "Does the protocol rely on exact tick values or allow ±1 buffer?"
    - "Balancer LogExpMath: what's the precision guarantee? Is it documented?"
    - "Custom log/ln implementations: what order Taylor series? How many terms?"
    - "grep for: getTickAtSqrtRatio, log2, ln, LogExpMath — check usage context"
    - "Are boundary ticks (MIN_TICK, MAX_TICK) handled correctly?"
  como_se_arregla: >
    Use unmodified Uniswap V3 TickMath for tick calculations. Account for ±1 tick
    error in all downstream computations. For custom log implementations, use enough
    terms for the required precision and validate against known values. Add boundary
    checks: log(0) should revert, log(1) should return 0 exactly.
  trampas:
    - "±1 tick error in TickMath is documented and expected — reporting it as a bug in Uniswap V3 itself is a false positive"
    - "The error matters more for protocols that use ticks for non-AMM purposes (pricing, oracles)"
    - "Balancer LogExpMath has 1e-18 precision which is sufficient for most DeFi applications"
    - "Custom implementations may be correct but unverifiable without extensive property testing"
  solodit_ids:
    - "precision-loss-on-large-values-transformed-between-log2-scale-and-the-normal-scale-cyfrin-beanstalk-wells-markdown_"
    - "h-03-yieldmathsol-log2-or-code4rena-yield-yield-contest-git"
    - "m-01-out-of-scope-missing-unchecked-block-in-tickmath-library-pashov-audit-group-none-ulti-november-markdown"
    - "tickmath-might-revert-in-solidity-version-08-spearbit-timeless-pdf"
  incidentes:
    - "Beanstalk Wells (Cyfrin) — Precision loss on large values transformed between log2 scale and normal scale"
    - "Yield Protocol (Code4rena) — YieldMath.sol log2 uses >= where > is correct, off-by-one (High)"
    - "Timeless (Spearbit) — TickMath might revert in Solidity 0.8 without unchecked blocks"
  severidad: medium
  confianza: media
  verificado: true

- id: ml-013
  pattern: percentage-precision-loss
  titulo: "Fee/percentage calculation precision loss — small amounts produce zero fees"
  causa_raiz: >
    Percentage calculations using integer division truncate: (amount * feePercent) / FEE_BASE.
    When amount * feePercent < FEE_BASE, the result is 0 — zero fee collected. With a
    typical FEE_BASE of 10000 (basis points), any amount where amount * fee < 10000
    produces zero fee. For a 0.3% fee (30 bps), amounts < 334 produce zero fee. On L2s
    with cheap gas, attackers can split large operations into many small ones, each
    paying zero fee, to completely avoid fees.
  como_funciona:
    - "1. Protocol charges 0.3% swap fee: fee = (amount * 30) / 10000."
    - "2. Attacker wants to swap 1,000,000 tokens without paying fees."
    - "3. Instead of one swap, attacker does 3,000 swaps of 333 tokens each."
    - "4. Each swap: fee = (333 * 30) / 10000 = 9990 / 10000 = 0 — zero fee."
    - "5. Total: 999,000 tokens swapped, zero fees paid. Protocol loses $3,000 in fees."
    - "6. On mainnet, gas cost makes this impractical. On L2s (Base, Arbitrum), gas is sub-cent."
  invariante: |
    // Fee should never round to zero for non-zero amount (or have a minimum fee)
    function check_fee_precision_ml013(uint256 amount, uint256 feeRate, uint256 feeBase) internal {
        if (amount == 0 || feeRate == 0) return;
        uint256 fee = (amount * feeRate) / feeBase;
        // Either fee > 0, or amount is genuinely below minimum
        if (amount * feeRate >= feeBase) {
            t(fee > 0, "ML-013: fee rounded to zero for non-dust amount");
        }
    }
  que_mirar:
    - "grep for: * fee / FEE_BASE, * FEE / 10000, * percent / 100 — percentage calculations"
    - "What's the minimum amount that produces non-zero fee? Is it economically meaningful?"
    - "Is there a minimum fee enforced? (e.g., fee = max(calculatedFee, MIN_FEE))"
    - "On which chain is this deployed? L2 fee avoidance is much more practical than mainnet"
    - "Can operations be split into many small ones? Or is there a minimum operation size?"
    - "Check if fee is computed as roundUp — (amount * feeRate + feeBase - 1) / feeBase"
  como_se_arregla: >
    Use mulDivUp for fee calculations (round up, never zero). Or enforce a minimum fee:
    fee = max((amount * feeRate) / feeBase, minFee). Or enforce minimum operation size.
    For L2 deployments, fee precision is especially important — consider higher-precision
    fee bases (1e6 or 1e18 instead of 10000).
  trampas:
    - "On mainnet, the gas cost of many small transactions usually exceeds the fee savings — may not be exploitable"
    - "On L2s, this is a real concern — verify deployment chain before dismissing"
    - "Some protocols have minimum swap/deposit amounts that prevent this attack"
    - "roundUp for fees is always correct — but some protocols intentionally round down for user experience"
  solodit_ids:
    - "m-03-rounding-error-in-buyquote-might-result-in-free-tokens-code4rena-caviar-caviar-contest-git"
    - "m-3-the-precision-loss-in-the-fee-percentage-for-connecting-offers-results-in-the-borrower-paying-less-than-the-expected-fee-sherlock-debita-finance-v3-git"
    - "rounding-up-of-taker-fees-of-constituent-orders-may-exceed-collected-fee-spearbit-clober-pdf"
    - "m-01-the-user-who-withdraws-liquidity-from-a-particular-pool-is-able-to-claim-more-rewards-than-they-should-by-carefully-selecting-a-decreaseshareamount-value-such-that-the-virtualrewardstoremove-is-rounded-down-to-zero-code4rena-saltyio-saltyio-git"
    - "redstonenavproviderrate-can-return-zero-for-non-zero-oracle-input-due-to-rounding-in-helpernormalizerate-cyfrin-none-securitize-public-stock-ramp-markdown"
  incidentes:
    - "Caviar (Code4rena) — Rounding error in buyQuote results in free tokens (Medium)"
    - "Debita Finance V3 (Sherlock) — Fee precision loss means borrower pays less than expected (Medium)"
    - "SaltyIO (Code4rena) — Carefully chosen decreaseShareAmount rounds virtualRewardsToRemove to zero (Medium)"
    - "Securitize (Cyfrin) — RedstoneNAVProvider.rate returns zero for non-zero oracle input due to rounding"
  severidad: medium
  confianza: alta
  verificado: true

- id: ml-014
  pattern: unchecked-block-pitfalls
  titulo: "SafeMath removal pitfalls — Solidity 0.8+ unchecked blocks masking real overflows"
  causa_raiz: >
    Solidity 0.8+ has built-in overflow/underflow checks, making SafeMath unnecessary.
    However, developers use unchecked{} blocks for gas optimization. When too much code
    is placed inside unchecked{}, real overflow/underflow bugs are silently masked.
    Common pattern: copying Uniswap V3 libraries (FullMath, TickMath) that NEED unchecked{}
    for their algorithm, but then adding custom code inside the same unchecked{} block.
    The custom code may have legitimate overflow risks that are now invisible.
  como_funciona:
    - "1. Developer imports FullMath and wraps the entire library in unchecked{} for gas savings."
    - "2. They add a custom helper function inside the same unchecked{} scope."
    - "3. The helper computes: balance = balance - withdrawal. In unchecked{}, if withdrawal > balance, this wraps to a huge number."
    - "4. User with balance = 100 withdraws 200 → balance wraps to type(uint256).max - 99."
    - "5. User now has near-infinite balance — drains the protocol."
    - "6. Without unchecked{}, Solidity 0.8+ would have reverted. The unchecked{} hid a real bug."
  invariante: |
    // After any subtraction in unchecked blocks, verify result is sane
    function check_unchecked_subtraction_ml014(uint256 before, uint256 delta) internal {
        unchecked {
            uint256 after_ = before - delta;
            // This check is OUTSIDE the unchecked — will catch wrapping
        }
        // Re-compute with checks
        if (delta > before) {
            // Should have reverted — if we got here, unchecked masked the underflow
            t(false, "ML-014: unchecked block masked underflow");
        }
    }
  que_mirar:
    - "grep for: unchecked { — examine ALL code inside the block, not just the intended optimization"
    - "Is the unchecked block minimal? Or does it wrap entire functions/libraries?"
    - "Look for subtraction inside unchecked — the most dangerous operation"
    - "Look for multiplication inside unchecked — can overflow silently"
    - "Are there user-controlled inputs flowing into unchecked arithmetic?"
    - "FullMath, TickMath from Uniswap V3: these NEED unchecked — but verify no custom code was added inside"
  como_se_arregla: >
    Minimize unchecked{} blocks to the exact operations that need them. Never put
    subtractions with user-controlled operands inside unchecked{} unless you've proven
    the subtraction cannot underflow. Use named helpers: uncheckedAdd, uncheckedSub that
    document WHY the check is unnecessary. For Uniswap library imports, keep them in
    separate files — don't add custom code in the same unchecked scope.
  trampas:
    - "unchecked{} for loop increments (i++) is a standard gas optimization — not a bug"
    - "FullMath.mulDiv REQUIRES unchecked for intermediate overflow — this is correct, not a bug"
    - "Some unchecked subtractions are provably safe due to prior checks — verify the full context"
    - "Gas savings from unchecked is ~100 gas per operation — may not be worth the risk in critical paths"
  solodit_ids:
    - "unchecked-may-cause-underoverflows-spearbit-astaria-pdf"
    - "04-unchecked-amount-feeamount-allows-256-bit-overflow-in-permit-flow-code4rena-sequence-sequence-git"
    - "use-unchecked-intickmathsol-andfullmathsol-spearbit-overlay-pdf"
    - "tickmath-might-revert-in-solidity-version-08-spearbit-timeless-pdf"
  incidentes:
    - "Sequence (Code4rena) — Unchecked amount + feeAmount allows 256-bit overflow in permit flow (Medium)"
    - "Astaria (Spearbit) — unchecked blocks may cause under/overflows"
    - "Overlay (Spearbit) — TickMath and FullMath need unchecked blocks to function correctly"
  severidad: high
  confianza: alta
  verificado: true

- id: ml-015
  pattern: muldiv-phantom-zero
  titulo: "mulDiv phantom zero — result should be non-zero but rounds to 0 for small numerators"
  causa_raiz: >
    mulDiv(a, b, c) computes (a * b) / c with full precision. But when a * b < c, the
    result is 0 — even though both a and b are non-zero. This creates "phantom zero"
    scenarios where a user's share, reward, or fee is computed as zero despite having
    a non-zero stake. This is especially dangerous in reward distribution, share-based
    accounting, and price calculations with high-decimal denominators. The mulDivDown
    variant always rounds toward zero, making this worse.
  como_funciona:
    - "1. Staking protocol distributes rewards: userReward = mulDiv(totalReward, userStake, totalStake)."
    - "2. totalReward = 1000 (small distribution), userStake = 1, totalStake = 1e18."
    - "3. mulDiv(1000, 1, 1e18) = 1000 / 1e18 = 0. User gets nothing."
    - "4. This reward is now orphaned — it stays in the contract forever, or is redistributed to larger stakers."
    - "5. Attacker with large stake claims disproportionate share of rewards."
    - "6. Over many reward distributions, small stakers systematically lose 100% of rewards."
  invariante: |
    // If both inputs are non-zero and result is 0, flag for review
    function check_phantom_zero_ml015(uint256 a, uint256 b, uint256 c) internal {
        if (a == 0 || b == 0 || c == 0) return;
        uint256 result = FullMath.mulDiv(a, b, c);
        // If a * b >= c, result should be > 0
        // Check without overflow: a >= c / b (approximately)
        if (b > 0 && a >= (c + b - 1) / b) {
            t(result > 0, "ML-015: phantom zero — non-zero inputs produced zero result");
        }
    }
  que_mirar:
    - "grep for: mulDiv, mulDivDown, mulWad — check what happens when the numerator product is tiny"
    - "Reward distribution: what's the minimum staking amount that earns any reward?"
    - "Share minting: can a deposit be so small that zero shares are minted? Can this be exploited for inflation attack?"
    - "Price calculations: can price * amount / precision round to zero for small trades?"
    - "Is there a minimum amount check? (require shares > 0 after calculation)"
    - "First depositor attack: deposit 1 wei → mint 1 share → donate tokens → inflate share price → next deposit rounds to 0 shares"
  como_se_arregla: >
    Add require(result > 0, "zero amount") after critical mulDiv calls. Enforce minimum
    deposit/stake amounts. Use mulDivUp for reward calculations (ensures non-zero for
    non-zero inputs). For vault shares: require minimum initial deposit or use virtual
    offset (OpenZeppelin ERC4626 with _decimalsOffset).
  trampas:
    - "Zero result for truly dust amounts (1 wei) may be acceptable — check economic significance"
    - "First depositor inflation attack is a separate pattern (related but distinct) — don't conflate"
    - "Some protocols use virtual shares (dead shares) to prevent phantom zero — check if this exists"
    - "mulDivUp always rounds up — but this means fees are always non-zero, which may be the desired behavior"
  solodit_ids:
    - "muldiv-can-round-down-to-0-in-realistic-cases-allowing-for-tax-avoidance-codehawks-tadle-git"
    - "c-02-calculation-for-owedamount-will-round-down-to-zero-pashov-none-lizardstarking-markdown"
    - "m-4-singularityremoveasset-share-can-become-zero-due-to-rounding-down-and-any-user-can-be-extracted-some-amount-of-asset-sherlock-tapioca-git"
    - "liquidity_poolamountforshare1-wei-may-round-down-to-zero-mixbytes-none-resolv-markdown"
    - "h-04-an-attacker-can-massively-inflate-the-share-value-pashov-audit-group-none-peapods_2024-11-16-markdown"
    - "h-03-first-depositor-can-break-minting-of-shares-code4rena-caviar-caviar-contest-git"
    - "first-vault-deposit-can-cause-excessive-rounding-spearbit-astaria-pdf"
  incidentes:
    - "Tadle (CodeHawks) — mulDiv rounds to 0 in realistic cases, allowing complete tax avoidance"
    - "LizardStaking (Pashov) — owedAmount calculation rounds to zero, user loses entire reward (Critical)"
    - "Tapioca (Sherlock) — Singularity.removeAsset share becomes zero due to rounding, funds extractable (Medium)"
    - "Resolv (Mixbytes) — liquidity_pool.amountForShare(1 wei) rounds to zero"
    - "Caviar (Code4rena) — First depositor can break minting of shares via share inflation (High)"
  severidad: medium-high
  confianza: alta
  verificado: true
```

---

## 2. Library Quick Reference

```yaml
# Key math libraries and their characteristics
libraries:
  - name: "Uniswap V3 FullMath"
    file: "FullMath.sol"
    key_functions: ["mulDiv", "mulDivRoundingUp"]
    precision: "512-bit intermediate, exact uint256 result"
    solidity_version: "Originally 0.7.6 — MUST use unchecked{} in 0.8+"
    gotchas:
      - "Importing without unchecked in 0.8+ causes revert on intermediate overflow"
      - "mulDiv(0, x, 0) reverts — denominator zero not handled"
    used_by: ["Uniswap V3", "SushiSwap V3", "PancakeSwap V3", "most concentrated liquidity DEXs"]

  - name: "Uniswap V3 TickMath"
    file: "TickMath.sol"
    key_functions: ["getSqrtRatioAtTick", "getTickAtSqrtRatio"]
    precision: "±1 tick for getTickAtSqrtRatio"
    solidity_version: "Originally 0.7.6 — MUST use unchecked{} in 0.8+"
    gotchas:
      - "getTickAtSqrtRatio has documented ±1 tick imprecision"
      - "MIN_TICK = -887272, MAX_TICK = 887272 — inputs outside range revert"
      - "Uses bitwise operations that rely on unchecked overflow behavior"
    used_by: ["All Uniswap V3 forks", "Concentrated liquidity protocols"]

  - name: "Aave WadRayMath"
    file: "WadRayMath.sol"
    key_functions: ["wadMul", "wadDiv", "rayMul", "rayDiv", "wadToRay", "rayToWad"]
    precision: "WAD = 1e18, RAY = 1e27, half-up rounding"
    solidity_version: "0.8+ compatible"
    gotchas:
      - "Mixing WAD and RAY operations produces 1e9 error"
      - "No overflow protection — large values can revert"
      - "rayToWad truncates 9 decimal places"
    used_by: ["Aave V2/V3", "Spark Protocol", "all Aave forks"]

  - name: "Aave PercentageMath"
    file: "PercentageMath.sol"
    key_functions: ["percentMul", "percentDiv"]
    precision: "Basis points (1e4), half-up rounding"
    solidity_version: "0.8+ compatible"
    gotchas:
      - "PERCENTAGE_FACTOR = 1e4 — only 2 decimal places of precision"
      - "percentMul(small_amount, small_percentage) can round to zero"
    used_by: ["Aave V2/V3", "lending protocols using basis points"]

  - name: "Solmate FixedPointMathLib"
    file: "FixedPointMathLib.sol"
    key_functions: ["mulWadDown", "mulWadUp", "divWadDown", "divWadUp", "mulDivDown", "mulDivUp", "sqrt", "lnWad", "expWad"]
    precision: "WAD = 1e18, 512-bit intermediate for mulDiv"
    solidity_version: "0.8+ native"
    gotchas:
      - "Errors return 0 instead of reverting in some functions — check assembly"
      - "expWad valid range: [-42139678854452767551, 135305999368893231588]"
      - "lnWad(0) returns undefined — check input"
    used_by: ["Morpho Blue", "many modern DeFi protocols"]

  - name: "PRBMath"
    file: "PRBMath.sol"
    key_functions: ["mulDiv", "exp2", "log2", "ln", "exp", "pow", "sqrt"]
    precision: "SD59x18 (signed 59.18 fixed point), UD60x18 (unsigned 60.18)"
    solidity_version: "0.8+ native"
    gotchas:
      - "exp upper bound: ~133.084258667509499441 (UD60x18)"
      - "SD59x18 can represent negative values — watch signed/unsigned conversion"
      - "Type-safe wrappers prevent scale confusion but add gas overhead"
    used_by: ["Sablier", "various DeFi protocols"]

  - name: "Balancer LogExpMath"
    file: "LogExpMath.sol"
    key_functions: ["pow", "exp", "log", "ln"]
    precision: "18 decimal fixed-point, ~1e-18 error for typical inputs"
    solidity_version: "0.7.x originally, ported to 0.8+"
    gotchas:
      - "exp valid range: x in [-41.446e18, 130.7e18]"
      - "pow(0, y) = 0 for y > 0, but pow(0, 0) behavior varies"
      - "Uses Taylor series — more iterations = more gas but better precision"
    used_by: ["Balancer V2", "weighted pool math"]

  - name: "OpenZeppelin Math"
    file: "Math.sol"
    key_functions: ["mulDiv", "sqrt", "log2", "log10", "log256", "ceilDiv"]
    precision: "Exact for mulDiv (512-bit intermediate), floor for sqrt"
    solidity_version: "0.8+ native"
    gotchas:
      - "mulDiv can revert if result overflows uint256 (unlike FullMath which wraps)"
      - "Rounding parameter controls up/down — make sure correct variant is used"
    used_by: ["OpenZeppelin contracts", "ERC4626 reference implementation"]

  - name: "Compound Exponential/Double"
    file: "Exponential.sol, ExponentialNoError.sol"
    key_functions: ["mul_ScalarTruncate", "mulExp", "divScalarByExpTruncate", "getExp"]
    precision: "Mantissa = 1e18 (similar to WAD)"
    solidity_version: "0.5.x-0.8.x (various versions)"
    gotchas:
      - "Old versions used SafeMath — newer versions rely on 0.8+ checks"
      - "truncate() loses precision — used extensively in cToken math"
      - "Interest rate per block → per year conversion is approximate"
    used_by: ["Compound V2", "all Compound forks (Venus, Benqi, Moonwell)"]
```

---

## 3. Attack Patterns Summary

```yaml
attack_patterns:
  - name: "Share inflation / first depositor"
    math_root_cause: "mulDiv rounds to zero when totalShares = 0 + 1 donated share"
    severity: critical
    related_ids: [ml-015, ml-001]
    defense: "Virtual shares offset (OpenZeppelin ERC4626 _decimalsOffset)"

  - name: "Fee avoidance via splitting"
    math_root_cause: "Integer division truncation on small amounts produces zero fee"
    severity: medium
    related_ids: [ml-013]
    defense: "Minimum fee, roundUp, or minimum operation size"

  - name: "Interest rate manipulation via precision loss"
    math_root_cause: "Division before multiplication in compound interest computation"
    severity: high
    related_ids: [ml-003, ml-008]
    defense: "Multiply first, use rpow/exp for compounding"

  - name: "Oracle price inflation via decimal confusion"
    math_root_cause: "Hardcoded 1e18 scale applied to 6-decimal token"
    severity: critical
    related_ids: [ml-006, ml-004]
    defense: "Read decimals(), normalize all values to common scale"

  - name: "Liquidation DoS via overflow"
    math_root_cause: "Intermediate multiplication overflows in critical path"
    severity: high
    related_ids: [ml-002, ml-009]
    defense: "Use mulDiv with 512-bit intermediate, cap position sizes"

  - name: "Accumulator bricking"
    math_root_cause: "Cumulative value overflows in 0.8+ without unchecked{}"
    severity: high
    related_ids: [ml-011]
    defense: "unchecked{} for intentional wrapping, bound accumulator growth rate"
```

---

## 4. Grep Cheatsheet

```bash
# Rounding direction issues
grep -rn "mulDiv\|mulWad\|divWad" --include="*.sol" | grep -v "Up\|Down\|Round"

# Division before multiplication
grep -rn "/ .*\*\|\.div(.*\.mul(" --include="*.sol"

# Unsafe downcasts (no SafeCast)
grep -rn "uint128(\|uint96(\|uint80(\|uint48(\|uint32(\|int128(\|int256(uint" --include="*.sol" | grep -v "SafeCast\|type("

# Unchecked blocks — inspect contents
grep -rn "unchecked {" -A 10 --include="*.sol"

# Hardcoded decimal assumptions
grep -rn "1e18\|10\*\*18\|1 ether" --include="*.sol" | grep -iv "comment\|test"

# WAD/RAY mixing
grep -rn "wadMul\|wadDiv\|rayMul\|rayDiv" --include="*.sol"

# Signed/unsigned casts
grep -rn "uint256(int\|int256(uint\|int128(uint" --include="*.sol"

# Accumulator updates without unchecked
grep -rn "+=" --include="*.sol" | grep -i "cumulative\|accum\|total\|reward"

# exp/pow/sqrt usage
grep -rn "\.exp(\|\.pow(\|\.sqrt(\|wadExp\|rpow\|LogExpMath" --include="*.sol"

# Zero-amount edge cases
grep -rn "require.*> 0\|assert.*> 0\|if.*== 0" --include="*.sol" | grep -i "amount\|shares\|balance"
```

---

## 5. Major Incidents Reference

```yaml
incidents:
  - protocol: "Euler Finance"
    date: "2023-03-13"
    loss: "$197M"
    math_component: >
      While primarily a logic bug (donateToReserves + liquidation), the exploit
      leveraged precision in debt/collateral accounting. The attacker manipulated
      health factor calculations through donated reserves, causing self-liquidation
      at favorable rates. The math-related aspect: collateral valuation during
      liquidation used exchange rates that could be manipulated via donation.
    related_patterns: [ml-001, ml-015]

  - protocol: "Balancer V2"
    date: "2023-08-22"
    loss: "$2M+ (mitigated to ~$200K)"
    math_component: >
      Rate providers returned manipulable rates used in pool pricing math.
      The boosted pools used linear math with rate multiplication that could be
      flash-manipulated, creating arbitrage between the pool's internal pricing
      and market prices.
    related_patterns: [ml-004, ml-009]

  - protocol: "Compound V2 (COMP distribution)"
    date: "2021-09-30"
    loss: "$80M+ in excess COMP distributed"
    math_component: >
      The Comptroller's _updateCompSupplyIndex used block-based interest accrual
      with division-before-multiplication patterns. A governance proposal changed
      the COMP distribution, but the index calculation had accumulated precision
      errors that resulted in massively over-distributing COMP tokens.
    related_patterns: [ml-003, ml-013]

  - protocol: "Harvest Finance"
    date: "2020-10-26"
    loss: "$33.8M"
    math_component: >
      Flash loan manipulated Curve pool price, which was used directly in share
      price calculation. The vault's convertToAssets used the manipulated price
      without time-weighting, allowing deposit at low price and immediate
      withdrawal at high price. Math: share_price = totalAssets / totalShares
      where totalAssets was spot-price-dependent.
    related_patterns: [ml-006, ml-013]

  - protocol: "Raft Protocol"
    date: "2023-11-10"
    loss: "$3.3M"
    math_component: >
      Precision error in the flash mint function allowed minting unbacked
      stablecoins. The rounding in the fee calculation produced zero fee for
      certain amounts, enabling zero-cost flash minting that was used to
      manipulate the protocol's internal accounting.
    related_patterns: [ml-013, ml-015]
```

---

## 6. Testing Strategies

```yaml
testing:
  - name: "Property-based testing with boundary values"
    description: >
      For any math function f(a, b): test with a,b in {0, 1, 2, WAD-1, WAD, WAD+1,
      type(uint128).max, type(uint256).max, type(uint256).max - 1}. These boundaries
      catch rounding, overflow, and truncation issues.
    tool: "Foundry fuzz with bounded inputs"

  - name: "Roundtrip invariants"
    description: >
      For convertible operations: deposit → withdraw should return original amount (±1 wei).
      encode → decode should be identity. normalize → denormalize should preserve value.
      Any deviation > expected tolerance is a bug.
    tool: "Foundry / Echidna / Medusa"

  - name: "Monotonicity checks"
    description: >
      Share price should be monotonically non-decreasing (no actions reduce it, only
      losses/fees can). Interest index should be monotonically non-decreasing.
      Accumulator should be monotonically non-decreasing.
    tool: "Echidna assertion mode"

  - name: "Commutative property"
    description: >
      For operations that should commute: swap(A→B→A) should return ≤ original amount.
      deposit(X) + deposit(Y) should give same shares as deposit(X+Y) (within tolerance).
    tool: "Foundry differential testing"

  - name: "Cross-implementation comparison"
    description: >
      Compare protocol's math against reference implementation (OpenZeppelin, Solmate,
      Python mpmath). If results diverge by more than 1 wei, investigate.
    tool: "Foundry + Python scripts, Halmos symbolic execution"

  - name: "Extreme value stress testing"
    description: >
      Test with: 1 wei deposits, type(uint256).max amounts, 0 totalSupply,
      1 totalSupply (share inflation), amounts just below and above type(uint128).max,
      time jumps of 365 days, interest rates of 0% and 1000%.
    tool: "Foundry fuzz with custom value generators"
```

---

## 7. Decision Tree — Is This a Real Math Bug?

```
1. Does the math function produce an INCORRECT result?
   ├── YES → Is the error exploitable? (can an attacker profit or cause loss?)
   │   ├── YES → What's the minimum capital needed? Gas cost?
   │   │   ├── Profitable on L2 → MEDIUM+ (fee avoidance, rounding exploitation)
   │   │   ├── Profitable on L1 → HIGH+ (significant capital at risk)
   │   │   └── Only profitable with flash loans → assess flash loan availability
   │   └── NO → Is it a DoS? (function reverts for valid inputs?)
   │       ├── YES → Is the function critical? (liquidation, withdrawal, repay?)
   │       │   ├── YES → HIGH (fund locking / bad debt accrual)
   │       │   └── NO → LOW (inconvenience, workaround exists)
   │       └── NO → INFO/QA (precision improvement, defense-in-depth)
   └── NO → Is there a REVERT where there shouldn't be?
       ├── YES → Same DoS analysis as above
       └── NO → NOT A BUG (math is correct, move on)

Key question: "Can a user lose more than gas costs due to this math error?"
If YES → report. If NO → document as informational and move on.
```
