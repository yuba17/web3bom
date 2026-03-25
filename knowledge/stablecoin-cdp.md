# Stablecoin & CDP Mechanisms — Bug Patterns

## Quick Reference

```
grep_targets:
  - openTrove
  - closeTrove
  - adjustTrove
  - borrowerOperations
  - TroveManager
  - StabilityPool
  - liquidate
  - liquidateTroves
  - batchLiquidateTroves
  - redeemCollateral
  - redemptionRate
  - redemptionFee
  - baseRate
  - debtCeiling
  - mintCap
  - debtToken
  - stabilityFee
  - accrueInterest
  - drip
  - jug
  - vat
  - CDPVault
  - collateralRatio
  - ICR
  - TCR
  - MCR
  - CCR
  - recoveryMode
  - flashMint
  - flashLoan
  - badDebt
  - socializeDebt
  - surplusPool
  - pegKeeper
  - pegStability
  - LLAMMA
  - softLiquidation
  - totalActiveDebt
  - totalDebt
  - collateralPrice
  - getPrice
  - fetchPrice
```

---

## 1. Manipulación de Collateral Ratio via Flash Loan

```yaml
- id: cdp-001
  titulo: Flash loan infla el valor del colateral para borrowear al máximo y dejar bad debt
  causa_raiz: |
    En sistemas CDP donde el collateral ratio se calcula en tiempo real usando el
    balance de colateral y un oracle de precio, un atacante puede usar flash loans
    para temporalmente inflar el valor de su colateral (via donación al pool de
    precio, manipulación de TWAP corto, o deposit masivo). Con el collateral ratio
    inflado, el atacante borrowea el máximo de stablecoin permitido, repaga el flash
    loan, y el colateral real queda muy por debajo del ratio requerido. El protocolo
    queda con una posición underwater que genera bad debt.
  como_funciona: |
    1. Atacante toma flash loan de $10M en ETH.
    2. Deposita ETH como colateral en el CDP, obteniendo un collateral ratio alto.
    3. Mintea stablecoins hasta el límite del MCR (Minimum Collateral Ratio).
    4. Retira parte del colateral (si el protocolo lo permite en la misma tx).
    5. Repaga el flash loan con el colateral retirado + stablecoins minteadas.
    6. La posición residual queda con colateral insuficiente → bad debt inmediato.
    Variante: en protocolos con oracle manipulable, el atacante infla el precio del
    colateral via manipulación de pool AMM, borrowea al máximo con precio inflado,
    y cuando el precio se normaliza la posición es insolvent.
  invariante: |
    // Después de cualquier operación, la posición debe estar sana
    uint256 collateralValue = position.collateral * oracle.getPrice(collateralToken);
    uint256 debtValue = position.debt;
    assert(collateralValue * 100 >= debtValue * MCR); // MCR en porcentaje
    // Flash loan resistance: verificar que el colateral no fue depositado en el mismo bloque
    assert(position.lastDepositBlock < block.number || position.debt == 0);
  que_mirar:
    - Operaciones de deposit + borrow en la misma transacción sin restricción
    - Falta de delay entre deposit de colateral y capacidad de borrow
    - Oracle de precio que puede ser manipulado en un solo bloque (spot price sin TWAP)
    - Posibilidad de withdraw parcial de colateral después de borrowear
    - Ausencia de health check post-operación
  como_se_arregla: |
    Usar oracle TWAP (mínimo 30 minutos) para valorar colateral.
    Prohibir borrow en el mismo bloque que un deposit (o usar delay).
    Health check obligatorio al final de CADA operación que modifique colateral o deuda.
    Flash loan guard: si el colateral fue depositado en el bloque actual, no permitir borrow.
  trampas:
    - No todos los protocolos son vulnerables — muchos ya usan Chainlink (no manipulable intra-bloque).
    - Si el protocolo usa un oracle que no depende de liquidez on-chain, la manipulación de AMM no sirve.
    - La variante de "depositar y retirar" requiere que el protocolo permita ambas ops sin health check intermedio.
    - En Liquity-style con sorted troves y redemption, el atacante necesita que nadie lo redima antes.
  solodit_ids:
    - "h-2-reentrancy-in-flashaction-allows-draining-liquidity-pools-sherlock-arcadia-git"
    - "m-13-flashloan-end-result-isnt-controlled-sherlock-ajna-ajna-git"
    - "h-01-availability-of-deposit-invariant-can-be-bypassed-code4rena-loopfi-loopfi-git"
  incidentes:
    - "Arcadia (Sherlock) — reentrancy en flashAction() permite drenar pools de liquidez via colateral inflado"
    - "Ajna (Sherlock) — resultado de flashloan no verificado, permite manipular estado post-flash"
    - "LoopFi (C4) — invariante de deposit puede bypasearse, permitiendo posiciones inseguras"
    - "Beanstalk (2022) — flash loan de $1B para obtener governance tokens y drenar $182M del protocolo"
```

---

## 2. Errores de Precisión en Liquidation Threshold

```yaml
- id: cdp-002
  titulo: Redondeo en el cálculo del collateral ratio permite posiciones underwater sin liquidación
  causa_raiz: |
    El cálculo del Individual Collateral Ratio (ICR) implica multiplicaciones y
    divisiones con decimales (precio del colateral × cantidad / deuda). Los errores de
    redondeo pueden hacer que una posición técnicamente underwater aparezca como
    solvente, o viceversa. Si el redondeo favorece al borrower, posiciones con CR
    ligeramente bajo el threshold no son liquidables. Si favorece al liquidador,
    posiciones sanas pueden ser liquidadas injustamente.
    Adicionalmente, si no hay gap entre el max borrow LTV y el liquidation threshold,
    un usuario puede borrowear al máximo y ser liquidable inmediatamente (por acumulación
    de intereses o fees de originación).
  como_funciona: |
    1. Protocolo calcula ICR = (collateral * price) / debt.
    2. Con tokens de 6 decimales (USDC) y colateral de 18 decimales, la división trunca.
    3. Posición con CR real de 149.99% aparece como 150% (threshold) → no liquidable.
    4. Precio cae ligeramente → posición debería ser liquidada pero el truncamiento la protege.
    5. Acumulación de estas posiciones "protegidas por rounding" genera bad debt sistémico.
    Variante LoopFi: CDPVault no escala takeCollateral con tokenScale, enviando
    cantidad incorrecta de colateral al liquidador.
  invariante: |
    // El gap entre max borrow LTV y liquidation threshold debe existir
    assert(maxBorrowLTV + originationFee + maxSingleBlockInterest < liquidationThreshold);
    // Collateral ratio debe calcularse con suficiente precisión
    // Usar WAD math (1e18) para todas las operaciones intermedias
    uint256 icr = (collateral * price * 1e18) / debt;
    assert(icr >= MCR * 1e16 || isLiquidatable(position));
  que_mirar:
    - Diferencia de decimales entre colateral y debt token (6 vs 18 decimales)
    - Cálculo de ICR sin escalar a WAD antes de la comparación
    - Gap entre max borrow LTV y liquidation threshold (debe ser > 0)
    - Fee de originación NO incluida en el health check post-borrow
    - Truncamiento en lugar de redondeo hacia el lado seguro (hacia el protocolo)
  como_se_arregla: |
    Usar WAD math (1e18) para todos los cálculos intermedios de collateral ratio.
    Redondear SIEMPRE a favor del protocolo (hacia abajo para ICR, hacia arriba para deuda).
    Enforcer gap mínimo entre max borrow LTV y liquidation threshold.
    Aplicar origination fee ANTES del health check.
  trampas:
    - En protocolos con 18 decimales en ambos tokens, el rounding es típicamente <1 wei — no explotable.
    - El finding real suele estar en tokens con 6 decimales (USDC, USDT) donde la pérdida de precisión es significativa.
    - No confundir con rounding dust — la pregunta es si el rounding permite EVITAR liquidación, no si hay 1 wei de error.
    - Verificar que el protocolo no tiene ya un buffer explícito (algunos añaden 0.01% de margen).
  solodit_ids:
    - "m-4-attackers-may-skip-the-collateral-ratio-recovery-duration-to-inflate-collateralization-ratios-and-steal-funds-sherlock-surge-surge-git"
    - "h-04-users-may-be-liquidated-right-after-taking-maximal-debt-code4rena-backed-protocol-papr-contest-git"
    - "m-11-cdpvaultliquidateposition-does-not-scale-takecollateral-with-tokenscale-therefore-it-might-send-the-wrong-amount-of-collateral-to-the-l"
    - "h-1-protocol-assumes-18-decimals-collateral-sherlock-taurus-taurus-git"
  incidentes:
    - "Surge (Sherlock) — atacantes saltan la duración de recuperación de collateral ratio para inflar ratios y robar fondos"
    - "Backed/Papr (C4) — usuarios liquidados inmediatamente después de tomar deuda máxima por falta de gap LTV/threshold"
    - "LoopFi (C4) — CDPVault.liquidatePosition no escala takeCollateral con tokenScale"
    - "Taurus (Sherlock) — protocolo asume 18 decimales en colateral, falla con tokens de 6 decimales"
```

---

## 3. Exploits en Mecanismo de Redemption

```yaml
- id: cdp-003
  titulo: Mecanismo de redención permite arbitraje o extrae valor de posiciones de otros usuarios
  causa_raiz: |
    En protocolos estilo Liquity, los holders de la stablecoin pueden redimirla por
    colateral subyacente a precio de oracle. Las redenciones se procesan contra los
    troves con menor collateral ratio primero. Vulnerabilidades surgen cuando:
    (a) el fee de redención no cubre la desviación del oracle, permitiendo arbitraje,
    (b) el ordenamiento de troves es manipulable,
    (c) la redención no actualiza correctamente la deuda del trove afectado,
    (d) el precio usado para la redención difiere del precio real de mercado.
  como_funciona: |
    Escenario de arbitraje por oracle drift (Liquity V2 / BOLD):
    1. Oracle tiene deviation threshold del 1% (actualiza solo si precio cambia >1%).
    2. Base redemption fee es 0.5%.
    3. Precio real de ETH sube 0.9% pero oracle no actualiza (dentro del threshold).
    4. Redeemer compra BOLD en mercado, redime por ETH a precio oracle (0.9% más bajo).
    5. Vende ETH en mercado → profit neto = 0.9% - 0.5% fee = 0.4%.
    6. Los trove owners pierden colateral a precio incorrecto.
    Escenario de redención con deuda stale (Roots):
    1. totalActiveDebt no se actualiza antes de openTrove.
    2. Nuevo trove se abre con deuda calculada sobre totalActiveDebt stale.
    3. La deuda real del sistema es mayor → redención calcula colateral incorrecto.
  invariante: |
    // Post-redemption: el trove afectado debe mantener deuda >= 0 y colateral proporcional
    assert(trove.debt >= 0);
    assert(trove.collateral * price >= trove.debt * MCR || trove.debt == 0);
    // Redemption fee debe cubrir oracle deviation
    assert(redemptionFee >= oracleDeviationThreshold);
    // totalActiveDebt debe actualizarse antes de cualquier operación
    assert(totalActiveDebt == sum(allTroveDebts) + accruedInterest);
  que_mirar:
    - Comparación entre base redemption fee y oracle deviation threshold
    - Si totalActiveDebt se actualiza (accrueInterest) ANTES de operaciones de trove
    - Ordenamiento de troves por ICR — ¿es manipulable con operaciones de frontrunning?
    - Precio usado en redemption vs precio real de mercado (¿hay lag?)
    - Redención parcial que deja trove con dust debt (incobrable)
  como_se_arregla: |
    Base redemption fee >= oracle deviation threshold (previene arbitraje por drift).
    Llamar accrueInterest() antes de CUALQUIER operación que lea totalActiveDebt.
    Minimum debt check post-redemption: si deuda restante < minDebt, cerrar trove completo.
    Usar oracle con heartbeat corto para redenciones (<1h).
  trampas:
    - El arbitraje por oracle drift es teórico si la liquidez de la stablecoin en DEX no es suficiente.
    - Redemption fees dinámicas (como en Liquity V1) ya mitigan esto parcialmente — verificar si la fee se ajusta.
    - En Liquity V2, cada branch tiene su propia base rate → la mitigación es por branch.
    - No confundir "redención" con "liquidación" — son mecanismos completamente distintos.
  solodit_ids:
    - "m-05-oracles-with-a-deviation-threshold-above-the-base-redemption-fee-are-subject-to-redemption-arbitrage-due-to-oracle-drift-recon-audits-n"
    - "h-02-stale-totalactivedebt-used-in-opentrove-causing-incorrect-debt-update-pashov-audit-group-none-roots_2025-02-09-mark"
    - "unfair-token-redemptions-when-an-underlying-stablecoin-depegs-quantstamp-vusd-stablecoin-markdown"
    - "h-01-loss-of-user-funds-when-completing-cash-redemptions-code4rena-ondo-finance-ondo-finance-contest-git"
  incidentes:
    - "BOLD/Liquity V2 (Recon Audits) — oracles con deviation threshold > base redemption fee permiten arbitraje por oracle drift"
    - "Roots (Pashov) — totalActiveDebt stale en openTrove causa actualizaciones de deuda incorrectas"
    - "VUSD (Quantstamp) — redenciones injustas cuando un stablecoin subyacente se depega"
    - "Ondo Finance (C4) — pérdida de fondos de usuarios al completar redenciones de CASH"
```

---

## 4. Errores en Acumulación de Stability Fee / Interest

```yaml
- id: cdp-004
  titulo: Stability fee / interest se calcula incorrectamente por acumulación discontinua o bypass
  causa_raiz: |
    Los protocolos CDP cobran stability fees (intereses) que se acumulan sobre la deuda.
    La acumulación suele hacerse en función del tiempo transcurrido desde la última
    actualización (pattern drip/jug de MakerDAO). Errores comunes:
    (a) Interés no se acumula antes de operaciones críticas → deuda subestimada.
    (b) Llamadas frecuentes a accrueInterest truncan el interés por integer math.
    (c) Actualización de rate antes de actualizar la deuda → base incorrecta.
    (d) Reseteo de acumulación al cambiar parámetros de rate.
  como_funciona: |
    Escenario truncamiento por llamadas frecuentes (Accountable/Cyfrin):
    1. APR = 5%, calculado como: newDebt = debt * (1 + APR/365/86400) ^ seconds.
    2. Si seconds = 1 (llamada cada segundo), (1 + 5%/31536000) ≈ 1.0000000016.
    3. Con debt = 1000 USDC (6 decimales), incremento = 0.0000016 → truncado a 0.
    4. Atacante llama accrueInterest() cada bloque → interés real = 0.
    5. Borrower usa la posición sin pagar fees.
    Escenario rate update before debt (ZeroLend):
    1. Usuario repaga deuda parcialmente.
    2. Función actualiza interest rate ANTES de actualizar la deuda.
    3. El nuevo rate se calcula sobre la deuda PRE-repago (más alta).
    4. Siguiente usuario paga interés sobre base inflada.
  invariante: |
    // accrueInterest debe llamarse antes de cualquier operación de deuda
    // Interest acumulado debe ser monotónicamente creciente
    uint256 prevAccruedInterest = totalAccruedInterest;
    accrueInterest();
    assert(totalAccruedInterest >= prevAccruedInterest);
    // Post-repago: rate debe calcularse sobre deuda ACTUALIZADA
    // totalDebt = sum(allTroveDebts) siempre
    assert(totalActiveDebt == computedSumOfAllDebts());
  que_mirar:
    - Orden de operaciones en repay/borrow: ¿se llama accrueInterest() PRIMERO?
    - Integer truncation con tokens de 6 decimales y rates bajos
    - Función set_rate o updateRate: ¿resetea el acumulador o preserva el interés pendiente?
    - Interés compuesto vs simple: ¿inconsistencia entre posición individual y pool?
    - Posibilidad de llamar accrueInterest() externamente (para forzar truncamiento)
  como_se_arregla: |
    Usar RAY math (1e27) para cálculos de interés — suficiente precisión para rates bajos.
    Patrón: accrueInterest() → operación → recalcular rate. Nunca al revés.
    Al cambiar rate: calcular y aplicar interés pendiente ANTES de cambiar el rate.
    Minimum accrual period: no acumular si delta_t < threshold (e.g., 1 hora).
  trampas:
    - El truncamiento solo es relevante con tokens de pocos decimales (6) y rates bajos (<10% APR).
    - Con tokens de 18 decimales, incluso 1 segundo de interés sobre 1 ETH de deuda produce algo > 0.
    - El patrón drip() de MakerDAO usa rpow() con RAY precision — bien implementado, difícil de romper.
    - No confundir "interés no acumulado" con "interés acumulado pero no cobrado" (puede ser by design).
  solodit_ids:
    - "h-10-interest-rate-is-updated-before-updating-the-debt-when-repaying-debt-sherlock-zerolend-one-git"
    - "m-02-users-can-avoid-paying-fees-if-they-manage-to-update-their-accrued-fees-periodically-code4rena-inverse-finance-inverse-finance-contest-"
    - "h-10-debt-position-interest-is-compounded-while-pool-interest-is-simple-causing-inconsistency-between-expectedliquidity_-and-availableliquid"
    - "m-06-set_rate-resets-accrued-fees-causing-fee-loss-pashov-audit-group-none-yieldbasis_2025-03-26-markdown"
  incidentes:
    - "ZeroLend One (Sherlock) — interest rate actualizado antes de actualizar la deuda en repay, distorsiona índice"
    - "Inverse Finance (C4) — usuarios evitan fees actualizando accrued fees periódicamente"
    - "LoopFi (C4) — interés compuesto en posición vs simple en pool causa inconsistencia en expectedLiquidity"
    - "YieldBasis (Pashov) — set_rate() resetea fees acumulados, causando pérdida de fees"
    - "Bima (Sherlock) — interest accrued se elimina de totalActiveDebt al llamar openTrove"
```

---

## 5. Manipulación de Oracle para CDP

```yaml
- id: cdp-005
  titulo: Manipulación del oracle de precio del colateral para evitar liquidación o liquidar a otros
  causa_raiz: |
    Los CDPs dependen de oracles para determinar el valor del colateral. Si el oracle
    es manipulable (spot price de AMM, TWAP corto, oracle sin staleness check), un
    atacante puede:
    (a) Inflar precio → borrowear más de lo que el colateral vale realmente.
    (b) Deprimir precio → liquidar posiciones sanas de otros usuarios y quedarse con
    el bonus de liquidación.
    (c) Explotar stale prices → operar con precio desactualizado para arbitraje.
    La gravedad es máxima en CDPs porque el oracle es el ÚNICO mecanismo de defensa
    contra posiciones insolventes.
  como_funciona: |
    Escenario stale oracle (USUAL ETH0):
    1. Protocolo acepta LST como colateral pero no verifica desviación on-chain.
    2. LST sufre slashing → valor real cae 5%.
    3. Oracle Chainlink tiene heartbeat de 24h y threshold 0.5% → no actualiza.
    4. Protocolo valora colateral 5% por encima del valor real durante horas.
    5. Borrowers al límite de LTV son realmente insolventes pero no liquidables.
    Escenario oracle manipulation (Blueberry):
    1. IchiLpOracle usa cálculo inválido que retorna precio inflado.
    2. Atacante deposita LP tokens como colateral, valorados más de lo real.
    3. Borrowea stablecoins al máximo → retira LP → posición insolvente.
  invariante: |
    // Oracle debe tener staleness check
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    assert(block.timestamp - updatedAt < STALE_THRESHOLD);
    assert(price > 0);
    // Precio no debe cambiar más de X% entre bloques consecutivos (circuit breaker)
    uint256 deviation = abs(newPrice - lastPrice) * 10000 / lastPrice;
    assert(deviation < MAX_DEVIATION_BPS);
  que_mirar:
    - Oracle que usa spot price de AMM sin TWAP
    - Falta de staleness check (latestRoundData sin validar updatedAt)
    - Oracle compuesto (precio × exchange rate) con heartbeats distintos
    - Falta de circuit breaker para cambios bruscos de precio
    - Oracle fallback que puede retornar precio de 0
    - L2: falta de check de sequencer uptime
  como_se_arregla: |
    Usar Chainlink con staleness check y sequencer uptime check en L2.
    TWAP mínimo 30 min para oracles on-chain (Uniswap V3 TWAP).
    Circuit breaker: si precio cambia > X% en un período, pausar operaciones.
    Oracle fallback con prioridad: Chainlink → TWAP → pausa.
  trampas:
    - Chainlink en mainnet es MUY difícil de manipular — el riesgo real es staleness, no manipulación.
    - En L2 (Arbitrum, Optimism), el sequencer down es un vector real — verificar si hay L2 check.
    - No todos los "oracle manipulations" son viables — calcular el costo del ataque vs beneficio.
    - El oracle de Liquity V2 usa dual oracle (Chainlink + fallback) con validación cruzada.
  solodit_ids:
    - "m-1-lack-of-on-chain-deviation-check-for-lst-can-lead-to-loss-of-assets-sherlock-usual-eth0-git"
    - "m-3-ichilporacle-returns-inflated-price-due-to-invalid-calculation-sherlock-blueberry-blueberry-git"
    - "m-01-eth_price_fallback_2-review-recon-audits-none-bold-report-markdown"
    - "mint-pricing-bypasses-oracle-validation-spearbit-none-buck-labs-pdf"
  incidentes:
    - "USUAL ETH0 (Sherlock) — sin verificación on-chain de desviación de LST, pérdida de activos"
    - "Blueberry (Sherlock) — IchiLpOracle retorna precio inflado, permite overborrowing"
    - "BOLD (Recon Audits) — eth_price_fallback_2 review, oracle fallback puede ser explotado"
    - "Buck Labs (Spearbit) — mint pricing bypasses oracle validation"
    - "MakerDAO Black Thursday (2020) — oracle Medianizer no actualizó por gas extremo, liquidaciones a precio 0"
```

---

## 6. Fallos en Mecanismo de Peg Maintenance

```yaml
- id: cdp-006
  titulo: Mecanismo de estabilización de peg falla bajo estrés o es explotable
  causa_raiz: |
    Las stablecoins CDP usan varios mecanismos para mantener el peg:
    - Redención directa (Liquity): redimir 1 LUSD por $1 de ETH → piso de precio.
    - PegKeeper (crvUSD): contrato que minta/quema crvUSD para estabilizar en pools Curve.
    - Stability Pool (Liquity): pool que absorbe liquidaciones y recicla la stablecoin.
    - Arbitraje de mint/burn (MakerDAO): mint DAI a $1 de colateral, burn para recuperar.
    Cuando estos mecanismos fallan — por congestión de red, falta de liquidez en el
    Stability Pool, o PegKeeper que no responde a tiempo — la stablecoin puede depegarse
    significativamente, causando liquidaciones cascada o pérdida de confianza.
  como_funciona: |
    Escenario Terra/UST (algorithmic death spiral):
    1. Stablecoin mantiene peg via mint/burn con token de governance (LUNA).
    2. Pérdida de confianza → massive redemptions de UST.
    3. Cada redemption minta más LUNA → precio de LUNA cae.
    4. Caída de LUNA reduce la capacidad de absorber redemptions.
    5. Death spiral: UST depeg → más redemptions → más LUNA minted → LUNA colapsa.
    6. Supply de LUNA pasa de 1B a 6T en 3 días. Pérdida total: $45B.
    Escenario crvUSD (junio 2024):
    1. PegKeeper no responde rápido a presión upward en el peg.
    2. Demanda inesperada de liquidaciones genera presión de compra de crvUSD.
    3. crvUSD se depega hacia arriba temporalmente.
    4. Mercados siloed en Curve Lend tienen dependencias compartidas → liquidaciones
       en cascade en mercado de sUSDe por el depeg de crvUSD.
    Escenario Malt Finance (C4):
    1. En Recovery Mode, usuarios no pueden remover liquidez.
    2. Mecanismo de estabilización depende de que usuarios puedan operar libremente.
    3. Bloqueo de liquidez → peg no puede mantenerse → pérdidas sistémicas.
  invariante: |
    // El mecanismo de peg debe ser bidireccional y funcional
    // StabilityPool debe tener suficiente liquidez para absorber liquidaciones
    assert(stabilityPool.totalDeposits() > 0 || alternativeLiquidationPath.exists());
    // PegKeeper: diferencia entre precio y peg debe reducirse después de intervención
    uint256 deviation = abs(stablecoinPrice - TARGET_PEG);
    // Si deviation > threshold, el mecanismo debe poder actuar
    assert(deviation <= MAX_ACCEPTABLE_DEVIATION || pegKeeper.canAct());
  que_mirar:
    - StabilityPool vacío → ¿qué pasa con las liquidaciones? ¿hay fallback?
    - PegKeeper con rate limit que impide responder a eventos grandes
    - Dependencia circular entre token de governance y stablecoin (death spiral risk)
    - Recovery Mode que bloquea operaciones necesarias para estabilización
    - Minting/burning en stability mode — ¿se permite o se bloquea?
  como_se_arregla: |
    Múltiples líneas de defensa: StabilityPool + liquidación directa + redemption.
    No depender de un solo mecanismo. No usar backing circular (token propio).
    PegKeeper con capacidad de respuesta proporcional al tamaño del depeg.
    Recovery Mode no debe bloquear operaciones de estabilización.
  trampas:
    - La mayoría de CDPs over-collateralized (Liquity, MakerDAO) son resistentes a death spirals.
    - El riesgo es principalmente para stablecoins algorítmicas o parcialmente colateralizadas.
    - Depeg temporal (<2%) en eventos de mercado extremos es "normal" y no necesariamente un bug.
    - No confundir depeg en mercado secundario con fallo del mecanismo de redención.
  solodit_ids:
    - "h-02-unable-to-remove-liquidity-in-recovery-mode-code4rena-malt-finance-malt-finance-contest-git"
    - "m-01-minting-of-ftoken-and-xtoken-allowed-during-stability-mode-pashov-audit-group-none-rwfx_2025-08-20-markdown"
    - "h-08-incorrect-assumption-of-stablecoin-market-stability-code4rena-tigris-trade-tigris-trade-contest"
    - "h-07-risk-users-are-required-to-payout-if-the-price-of-the-pegged-asset-goes-higher-than-underlying-code4rena-y2k-finance-y2k-finance-contes"
  incidentes:
    - "Terra/UST (mayo 2022) — death spiral algorítmica, pérdida de $45B, LUNA de $80 a ~$0 en 3 días"
    - "crvUSD (junio 2024) — PegKeeper no responde a tiempo, upward depeg causa liquidaciones cascade en mercados sUSDe"
    - "Malt Finance (C4) — Recovery Mode bloquea remoción de liquidez, impide estabilización"
    - "Tigris Trade (C4) — asunción incorrecta de estabilidad de mercado de stablecoins"
    - "Y2k Finance (C4) — risk users deben pagar si el pegged asset sube por encima del underlying"
```

---

## 7. Socialización de Bad Debt Incorrecta

```yaml
- id: cdp-007
  titulo: Bad debt no se socializa correctamente — insolvencia sistémica o pérdida concentrada
  causa_raiz: |
    Cuando una posición es liquidada pero el colateral no cubre la deuda total, queda
    "bad debt" — deuda que nadie debe. Este bad debt debe ser socializado (distribuido
    entre todos los depositantes/lenders) o absorbido por un fondo de reserva. Si el
    protocolo no tiene mecanismo de socialización, o lo implementa incorrectamente:
    (a) El bad debt se acumula como "phantom debt" → protocolo parece tener más activos de los reales.
    (b) El último en retirar pierde todo (bank run incentive).
    (c) Nuevos depositantes subsidian las pérdidas de posiciones antiguas.
    CDPVault de LoopFi: liquidatePositionBadDebt() seteaba profit=0 al llamar
    pool.repayCreditAccount(), perdiendo el tracking de la pérdida real.
  como_funciona: |
    Escenario BendDAO (C4):
    1. NFT colateral (e.g., Bored Ape) cae de precio drásticamente.
    2. Liquidación: NFT vale $30K, deuda es $50K → bad debt de $20K.
    3. BendDAO NO tiene mecanismo de bad debt handling.
    4. Los $20K de bad debt quedan como "deuda fantasma" en el sistema.
    5. El protocolo reporta totalBorrows = $50K pero solo tiene $30K de colateral.
    6. Últimos withdrawers no pueden retirar → insolvencia.
    Escenario ZeroLend (Sherlock):
    1. Bad debt se acumula.
    2. La pérdida NO se comparte entre todos los suppliers.
    3. El último en withdraw absorbe toda la pérdida → pérdida concentrada masiva.
    4. Esto crea incentivo perverso: primeros en detectar bad debt retiran rápido (bank run).
  invariante: |
    // Si colateral de una posición es 0 y deuda > 0, bad debt debe socializarse
    if (positions[user].collateral == 0 && positions[user].debt > 0) {
        // La deuda debe reducir totalAssets o incrementar un loss reserve
        assert(totalAssets_post < totalAssets_pre || lossReserve_post > lossReserve_pre);
        // La posición debe cerrarse (deuda = 0)
        assert(positions[user].debt == 0);
    }
    // Solvencia: totalAssets >= totalDebt siempre (después de socialización)
    assert(totalAssets() >= totalDebt() || badDebtSocialized);
  que_mirar:
    - Función de liquidación: ¿qué pasa cuando colateral < deuda?
    - ¿Existe función explícita de bad debt handling/socialization?
    - ¿totalSupplyAssets se reduce cuando hay bad debt?
    - ¿Los últimos withdrawers pueden retirar sus fondos completos?
    - ¿El protocolo tiene reservas para absorber bad debt?
    - CDPVault: ¿liquidatePositionBadDebt calcula profit/loss correctamente?
  como_se_arregla: |
    Socialización automática: cuando bad debt se confirma, reducir totalSupplyAssets
    proporcionalmente entre todos los suppliers (como Aave V3).
    Reserva de bad debt: acumular fees en un fondo de reserva para absorber pérdidas.
    Cerrar posición completamente cuando colateral = 0 (no dejar phantom debt).
  trampas:
    - Bad debt en cantidades pequeñas es inevitable en lending — el issue es si se MANEJA.
    - No confundir "bad debt posible" con "bad debt no manejado" — el primero es un riesgo aceptado.
    - Algunos protocolos socializan bad debt via share price reduction (ERC4626 style) — verificar que funciona.
    - La socialización debe ser instantánea, no lazy (lazy permite bank run antes de la distribución).
  solodit_ids:
    - "h-05-bad-debt-is-never-handled-which-places-insolvency-risks-on-benddao-code4rena-benddao-benddao-git"
    - "h-7-when-bad-debt-accumulated-loss-not-shared-amongst-all-suppliers-last-to-withdraw-loses-huge"
    - "h-12-cdpvaultsolliquidatepositionbaddebt-doesnt-correctly-handle-profit-and-loss-code4rena-loopfi-loopfi-git"
    - "m-4-bad-debt-shortfall-liquidation-leaves-liquidated-user-in-a-negative-collateral-balance-which-can-cause-bank-run-and-loss-of-funds-for-th"
    - "m-9-bad-debt-may-persist-even-after-complete-liquidation-in-velo-vault-due-to-truncation-sherlock-isomorph-isomorph-git"
  incidentes:
    - "BendDAO (C4) — bad debt nunca manejado, riesgo de insolvencia sistémica"
    - "ZeroLend One (Sherlock) — bad debt acumulado no se comparte entre suppliers, último en retirar pierde todo"
    - "LoopFi (C4) — CDPVault.liquidatePositionBadDebt() setea profit=0, perdiendo tracking de pérdida real"
    - "Perennial V2 (Sherlock) — bad debt liquidation deja usuario con colateral negativo, causa bank run"
    - "Isomorph (Sherlock) — bad debt persiste después de liquidación completa por truncamiento"
    - "Panoptic (C4) — retirar antes de evento de bad debt incrementa pérdidas para LPs restantes"
```

---

## 8. Accounting Incorrecto en Multi-Collateral

```yaml
- id: cdp-008
  titulo: Múltiples tipos de colateral manejados con parámetros incorrectos o sin normalización
  causa_raiz: |
    Protocolos CDP que aceptan múltiples tipos de colateral (MakerDAO multi-collateral,
    Liquity V2 con branches, DYAD con vaults) deben manejar cada tipo con sus propios
    parámetros: decimales, oracle, MCR, liquidation bonus, stability fee. Errores
    comunes:
    (a) Asumir que todos los colaterales tienen 18 decimales.
    (b) Usar el mismo MCR para colaterales con volatilidades distintas.
    (c) No normalizar precios a la misma base antes de sumar colaterales.
    (d) Tratar colateral exógeno y endógeno con las mismas reglas.
  como_funciona: |
    Escenario DYAD (C4):
    1. DYAD tiene vaults de colateral exógeno (WETH) y endógeno (Kerosene).
    2. Liquidation check requiere "suficiente colateral exógeno".
    3. VaultManagerV2::liquidate() NO verifica correctamente el colateral exógeno.
    4. Posición con 100% Kerosene (endógeno) y 0% WETH pasa el health check.
    5. Si Kerosene se deprecia, la posición no tiene colateral real → bad debt.
    Escenario Bima (Cantina):
    1. Protocolo asume 18 decimales para todos los derivados de BTC.
    2. WBTC tiene 8 decimales.
    3. Cálculo de colateral multiplica por factor incorrecto.
    4. Con 8 decimales: colateral sobrevaluado por factor 10^10.
    5. Usuario puede mintear stablecoins masivamente con poco colateral real.
  invariante: |
    // Cada tipo de colateral debe normalizarse a 18 decimales antes de sumar
    uint256 normalizedCollateral;
    for (uint i = 0; i < collateralTypes.length; i++) {
        uint256 decimals = IERC20Metadata(collateralTypes[i]).decimals();
        uint256 value = collateralAmounts[i] * prices[i] * 10**(18 - decimals) / 1e18;
        normalizedCollateral += value;
    }
    // Colateral exógeno >= porcentaje mínimo de deuda total
    assert(exogenousCollateralValue >= totalDebt * minExogenousRatio / 100);
  que_mirar:
    - Diferentes decimales entre colaterales (WBTC=8, ETH=18, USDC=6)
    - ¿Se normaliza a una base común antes de calcular ICR?
    - ¿El MCR es global o por tipo de colateral?
    - ¿El protocolo distingue colateral exógeno de endógeno?
    - ¿Las liquidaciones manejan múltiples colaterales en la posición?
  como_se_arregla: |
    Normalizar SIEMPRE a 18 decimales antes de cualquier operación aritmética.
    MCR específico por tipo de colateral basado en volatilidad histórica.
    Separar health checks para colateral exógeno vs endógeno.
    Verificar decimals() on-chain, no hardcodear.
  trampas:
    - En testnets, los tokens mock suelen tener 18 decimales — el bug aparece solo en mainnet con tokens reales.
    - El bug de WBTC (8 decimales) es extremadamente común y se repite en muchos protocolos.
    - Verificar si el protocolo ya usa un tokenScale factor — puede estar bien implementado pero mal aplicado.
    - No todos los multi-collateral CDPs suman colaterales — algunos tratan cada vault independientemente.
  solodit_ids:
    - "h-07-missing-enough-exogenous-collateral-check-in-vaultmanagerv2liquidate-makes-the-liquidation-revert-even-if-dyad-minted-non-kerosene-valu"
    - "all-highly-liquid-btc-derivatives-that-do-not-have-18-decimals-cannot-be-used-as-a-collateral-to-mint-stable-coins-cantina-none-bima-pdf"
    - "h-1-protocol-assumes-18-decimals-collateral-sherlock-taurus-taurus-git"
    - "h-02-cdpvaultsolliquidatepositionbaddebt-doesnt-correctly-handle-profit-and-loss-code4rena-loopfi-loopfi-git"
  incidentes:
    - "DYAD (C4) — falta de check de colateral exógeno en liquidate(), posiciones endógenas pasan health check"
    - "Bima (Cantina) — derivados BTC con != 18 decimales no pueden usarse como colateral, cálculos incorrectos"
    - "Taurus (Sherlock) — protocolo asume 18 decimales, falla con colateral de 6/8 decimales"
    - "LoopFi (C4) — CDPVault.liquidatePositionBadDebt() maneja profit/loss incorrectamente con múltiples colaterales"
```

---

## 9. Exploits en Governance Parameter Changes

```yaml
- id: cdp-009
  titulo: Cambio de parámetros de governance afecta posiciones activas sin protección
  causa_raiz: |
    Los protocolos CDP tienen parámetros ajustables por governance: stability fee,
    MCR, liquidation bonus, debt ceiling. Cuando estos parámetros se cambian,
    posiciones que eran sanas bajo los parámetros anteriores pueden quedar
    instantáneamente underwater. Si no hay período de gracia o cooldown,
    governance (o un governance attack via flash loan) puede liquidar masivamente.
    Variante: keeper con privilegios puede escalar a admin via parámetros no validados.
  como_funciona: |
    Escenario Taurus (Sherlock):
    1. Keeper tiene permiso para actualizar rewardProportion parameter.
    2. No hay input validation → keeper puede setear rewardProportion = 100%.
    3. Con 100%, el keeper paga TODOS los loans usando rewards del protocolo.
    4. Keeper escala privilegios de "distribuidor de rewards" a "controller de deuda".
    Escenario governance attack (genérico):
    1. Governance reduce MCR de 150% a 110% para "mejorar capital efficiency".
    2. Posiciones entre 110% y 150% de CR están ahora al límite.
    3. Cualquier movimiento de precio las liquida.
    4. Atacante deposita en Stability Pool antes del cambio.
    5. Cambio ejecutado → liquidaciones masivas → atacante obtiene colateral con descuento.
    Escenario Beanstalk (2022):
    1. Flash loan de $1B para obtener 67% de voting power (Stalk tokens).
    2. Ejecuta emergency governance proposal que drena todo el protocolo.
    3. $182M extraídos en una sola transacción.
  invariante: |
    // Los cambios de parámetros deben tener timelock
    assert(block.timestamp >= proposalTimestamp + TIMELOCK_DELAY);
    // Parámetros críticos deben tener bounds
    assert(newMCR >= MIN_MCR && newMCR <= MAX_MCR);
    assert(newStabilityFee <= MAX_STABILITY_FEE);
    // Governance voting no debe usar flash-loanable tokens
    assert(votingPower[msg.sender] == snapshotAtBlock(proposalBlock));
  que_mirar:
    - ¿Los parámetros críticos tienen timelock?
    - ¿Hay bounds validation en los setters de parámetros? (min/max)
    - ¿El governance voting usa snapshot o balance actual? (flash loan resistant?)
    - ¿Un keeper/admin puede cambiar parámetros sin governance?
    - ¿Hay período de gracia para posiciones afectadas por cambio de parámetros?
    - Input validation en funciones de admin/keeper
  como_se_arregla: |
    Timelock de 48h+ para cambios de parámetros críticos (MCR, stability fee).
    Bounds explícitos en setters: require(newMCR >= 110 && newMCR <= 500).
    Governance voting con snapshot en bloque de proposal (anti-flash loan).
    Período de gracia: posiciones tienen X bloques para ajustarse después de cambio.
  trampas:
    - No todos los cambios de governance son ataques — la mayoría son legítimos.
    - El riesgo de governance attack con flash loan requiere que el token sea líquido en DEX.
    - Timelock de >48h puede ser insuficiente si el mercado se mueve rápido.
    - Protocolos immutable (Liquity V1) eliminan este vector completamente.
  solodit_ids:
    - "h-2-missing-input-validation-for-_rewardproportion-parameter-allows-keeper-to-escalate-his-privileges-and-pay-back-all-loans-sherlock-taurus"
    - "m-4-a-malicious-admin-can-steal-all-users-collateral-sherlock-taurus-taurus-git"
    - "m-6-user-can-prevent-liquidations-by-frontrunning-the-tx-and-slightly-increasing-their-collateral-sherlock-taurus-taurus-git"
    - "temporal-collateral-ratio-inflation-during-reward-distribution-spearbit-none-buck-labs-smart-contracts-pdf"
  incidentes:
    - "Beanstalk (abril 2022) — flash loan de $1B para governance attack, $182M drenados en 1 tx"
    - "Taurus (Sherlock) — keeper escala privilegios via rewardProportion sin input validation"
    - "Taurus (Sherlock) — admin malicioso puede robar todo el colateral de usuarios"
    - "Buck Labs (Spearbit) — inflación temporal de collateral ratio durante distribución de rewards"
```

---

## 10. Flash Mint Attacks

```yaml
- id: cdp-010
  titulo: Flash mint de stablecoins permite manipulación de protocolos integrados o governance
  causa_raiz: |
    Algunos stablecoins (DAI via MakerDAO, GHO via Aave, BOLD via Liquity V2)
    soportan flash mint: mintear tokens temporalmente dentro de una transacción
    sin colateral, siempre que se quemen al final. A diferencia de flash loans
    (limitados por la liquidez del pool), flash mints pueden crear cantidades
    ilimitadas. Si un protocolo integrado no maneja esto:
    (a) Voting power inflado temporalmente (si la stablecoin tiene governance weight).
    (b) Manipulación de precios en pools donde la stablecoin tiene alta liquidez.
    (c) Exploits en protocolos que asumen supply constante intra-bloque.
    (d) Bypass de rate limits basados en totalSupply.
  como_funciona: |
    Escenario governance manipulation via flash mint:
    1. Protocolo X usa balance de DAI como voting weight.
    2. Atacante flash-mintea 100M DAI (sin colateral, gratis).
    3. Vota en una proposal de governance de protocolo X.
    4. Quema los 100M DAI al final de la tx.
    5. Proposal pasa con votos inflados.
    Escenario price manipulation:
    1. Protocolo Y usa Curve DAI/USDC pool para pricing.
    2. Atacante flash-mintea 500M DAI.
    3. Swapea en el pool → precio de DAI se deprime temporalmente.
    4. Otro protocolo lee precio deprimido → liquidaciones incorrectas.
    5. Atacante recompra DAI barato, quema para repagar flash mint.
    Escenario debt ceiling bypass:
    1. Protocolo tiene debt ceiling de 100M stablecoins.
    2. Flash mint de 100M + borrow regular de 100M = 200M stablecoins en circulación intra-tx.
    3. Si el ceiling se chequea solo en borrow, no en flash mint, se bypasea.
  invariante: |
    // Flash mint callback: tokens deben quemarse al final
    uint256 supplyBefore = totalSupply();
    // ... flash mint callback ...
    assert(totalSupply() <= supplyBefore); // supply no debe crecer permanentemente
    // Flash mint no debe afectar governance snapshots
    assert(getVotes(msg.sender) == snapshotVotes(msg.sender, snapshotBlock));
    // Debt ceiling debe incluir flash minted tokens
    assert(totalSupply() + flashMintedAmount <= debtCeiling);
  que_mirar:
    - ¿La stablecoin soporta ERC-3156 flash mint?
    - ¿Hay cap en la cantidad de flash mint? (maxFlashLoan)
    - ¿El debt ceiling incluye tokens flash-minted?
    - ¿Protocolos downstream usan balanceOf() o totalSupply() intra-transacción?
    - ¿La governance usa snapshots o balance actual?
    - ¿Hay fee por flash mint?
  como_se_arregla: |
    Cap explícito en maxFlashLoan (no ilimitado).
    Fee por flash mint (aunque sea mínima — previene spam).
    Governance con snapshots en bloques anteriores (no balance actual).
    Protocolos integrados: no confiar en totalSupply() intra-bloque.
    Debt ceiling que incluye flash minted tokens.
  trampas:
    - DAI flash mint tiene fee de 0% y cap configurable — verificar valores actuales.
    - GHO de Aave tiene FlashMinter con facilitatorBucketCapacity — puede limitar.
    - La manipulación de precio via flash mint requiere pools con poca liquidez relativa.
    - No todos los flash mints son exploits — muchos usos son legítimos (arbitraje, refinancing).
    - Si el protocolo downstream usa TWAP o Chainlink, el flash mint no afecta el precio.
  solodit_ids:
    - "h-02-the-flashloan-protection-for-zappers-is-insufficient-we-can-operate-on-troves-we-dont-own-recon-audits-none-bold-report-markdown"
    - "m-2-mint-limit-is-not-reduced-when-the-vault-is-burning-tau-sherlock-taurus-taurus-git"
    - "h-13-flashlendersolflashloan-should-use-mintprofit-to-mint-fees-as-the-current-implementation-may-lead-to-locked-up-weth-in-poolv3-code4rena"
  incidentes:
    - "Liquity V2 / BOLD (Recon Audits) — protección de flashloan para Zappers insuficiente, operar troves ajenos"
    - "Taurus (Sherlock) — mint limit no se reduce al quemar TAU, permite bypass de debt ceiling"
    - "LoopFi (C4) — Flashlender.flashLoan() debería usar mintProfit(), implementación actual bloquea WETH en PoolV3"
    - "Beanstalk (2022) — flash loan (no mint) para governance attack, $182M. Mismo vector aplica a flash mint"
```

---

## 11. Bypass de Debt Ceiling

```yaml
- id: cdp-011
  titulo: Mintear más stablecoins de las que el debt ceiling permite
  causa_raiz: |
    Los debt ceilings limitan la cantidad total de stablecoins que pueden existir
    en el sistema (o por tipo de colateral). Bypasses ocurren cuando:
    (a) El ceiling se chequea en el momento incorrecto (antes de fees, no después).
    (b) Operaciones que incrementan deuda no verifican el ceiling (liquidaciones, interest accrual).
    (c) El ceiling se calcula sobre una variable desactualizada (stale totalDebt).
    (d) Flash mints no cuentan contra el ceiling.
    (e) Batch operations permiten que la suma exceda el ceiling aunque cada operación individual no lo haga.
  como_funciona: |
    Escenario Taurus (Sherlock):
    1. Vault tiene mintLimit de 1M TAU.
    2. currentMinted tracks cuánto se ha minteado.
    3. Función burn() reduce supply pero NO reduce currentMinted.
    4. Después de burn, el ceiling efectivo es mintLimit - currentMinted > supply real.
    5. Se puede mintear más TAU de lo que el ceiling debería permitir.
    6. Over-minting diluye el valor de TAU existente.
    Escenario interest accrual:
    1. Debt ceiling = 100M. TotalDebt = 99M.
    2. Interés acumulado = 2M → totalDebt real = 101M.
    3. Pero accrueInterest() no checkea debt ceiling.
    4. Nuevo borrower mintea 1M más (checkea contra 99M stale, no 101M real).
    5. TotalDebt real = 102M > ceiling de 100M.
  invariante: |
    // totalDebt NUNCA debe exceder debtCeiling
    assert(totalDebt() <= debtCeiling);
    // currentMinted debe reflejar supply real
    assert(currentMinted >= totalSupply()); // accounting consistency
    // Post-mint check (no pre-mint)
    // Incluir interés acumulado en el check
    accrueInterest();
    assert(totalDebt() + mintAmount <= debtCeiling);
  que_mirar:
    - ¿burn() reduce el counter de minted? (o solo el supply)
    - ¿accrueInterest() puede empujar totalDebt sobre el ceiling?
    - ¿El debt ceiling check es pre-mint o post-mint?
    - ¿Incluye interés acumulado en el cálculo?
    - ¿Flash mints cuentan contra el ceiling?
    - ¿Hay debt ceilings por tipo de colateral Y global?
  como_se_arregla: |
    Accrual de interés antes del ceiling check.
    burn() debe reducir currentMinted (o usar supply real, no counter).
    Post-mint assertion: require(totalDebt() <= ceiling).
    Debt ceiling global + per-collateral-type ceilings.
  trampas:
    - En MakerDAO, cada ilk (tipo de colateral) tiene su propio debt ceiling — el bug puede estar en uno solo.
    - El debt ceiling "soft" (que se ajusta automáticamente) es más resistente pero más complejo.
    - Interés acumulado que empuja sobre el ceiling no siempre es un bug — puede ser "by design" con rate limiting.
    - Verificar si el ceiling aplica a gross debt (incluyendo fees) o net debt (principal only).
  solodit_ids:
    - "m-2-mint-limit-is-not-reduced-when-the-vault-is-burning-tau-sherlock-taurus-taurus-git"
    - "m-05-totalsupply-may-exceed-libbasketstoragebasketstoragemaxcap-code4rena-amun-amun-contest-git"
    - "m-1-the-maximum-size-of-an-ichi-vault-spell-position-can-be-arbitrarily-surpassed-sherlock-blueberry-blueberry-git"
    - "h-07-malicious-borrower-cycle-exploits-to-inflate-interest-rates-code4rena-loopfi-loopfi-git"
  incidentes:
    - "Taurus (Sherlock) — mint limit no se reduce al quemar TAU, bypass efectivo del debt ceiling"
    - "Amun (C4) — totalSupply puede exceder maxCap del basket storage"
    - "Blueberry (Sherlock) — tamaño máximo de posición ICHI vault puede superarse arbitrariamente"
    - "LoopFi (C4) — borrower malicioso cicla operaciones para inflar interest rates, efectivamente inflando deuda sobre ceiling"
```

---

## 12. Recovery Mode Exploits

```yaml
- id: cdp-012
  titulo: Recovery Mode permite liquidaciones injustas o bloquea operaciones críticas
  causa_raiz: |
    Protocolos estilo Liquity implementan "Recovery Mode" cuando el Total Collateral
    Ratio (TCR) del sistema cae por debajo de un umbral (típicamente 150%). En Recovery
    Mode, las reglas de liquidación se relajan: posiciones con ICR < TCR pueden ser
    liquidadas (no solo < MCR). Esto protege al sistema pero crea vectors de ataque:
    (a) Liquidaciones injustas de posiciones que serían sanas en modo normal.
    (b) Operaciones bloqueadas que impiden a usuarios protegerse.
    (c) Manipulación del TCR para entrar/salir de Recovery Mode estratégicamente.
    (d) Flash loan para temporalmente deprimir TCR y liquidar targets específicos.
  como_funciona: |
    Escenario Malt Finance (C4):
    1. Protocolo entra en Recovery Mode por caída de precio de colateral.
    2. En Recovery Mode, remoción de liquidez está BLOQUEADA.
    3. Usuarios no pueden retirar su liquidez para protegerse.
    4. Los que proporcionaron liquidez quedan atrapados.
    5. El mecanismo de estabilización no puede funcionar sin liquidez removible.
    6. Sistema se degrada sin posibilidad de recuperación → pérdidas masivas.
    Escenario frontrunning de liquidación (Taurus):
    1. Protocolo está cerca de Recovery Mode threshold.
    2. Atacante detecta que una liquidación va a ocurrir.
    3. Frontrunea la liquidación incrementando ligeramente su colateral.
    4. Su transacción pasa primero → su posición ya no es liquidable.
    5. El liquidador original gasta gas sin éxito.
    6. La posición sigue siendo frágil pero iliquidable temporalmente.
    Escenario TCR manipulation:
    1. TCR del sistema = 152% (justo sobre el threshold de 150%).
    2. Atacante abre posición grande con bajo CR → TCR cae a 148%.
    3. Sistema entra en Recovery Mode → posiciones de OTROS usuarios con ICR < 148% son liquidables.
    4. Atacante liquida esas posiciones, obtiene bonus de liquidación.
    5. Cierra su propia posición → TCR vuelve a subir.
  invariante: |
    // En Recovery Mode, solo posiciones con ICR < TCR son liquidables
    if (isRecoveryMode()) {
        // Posiciones con ICR >= TCR NO deben ser liquidables
        assert(!isLiquidatable(position) || getICR(position) < getTCR());
    }
    // Recovery Mode no debe bloquear operaciones de estabilización
    assert(canRemoveLiquidity || !isRecoveryMode()); // invertido si RM bloquea
    // TCR no debe ser manipulable por una sola posición grande
    uint256 tcrImpact = abs(newTCR - oldTCR);
    assert(tcrImpact < MAX_SINGLE_POSITION_TCR_IMPACT || isAdmin);
  que_mirar:
    - ¿Qué operaciones se bloquean en Recovery Mode? (withdraw, remove liquidity, close trove)
    - ¿La liquidación en Recovery Mode verifica ICR < TCR correctamente?
    - ¿Se puede manipular el TCR abriendo/cerrando posiciones grandes?
    - ¿Hay protección contra frontrunning de liquidaciones? (minimum collateral changes)
    - ¿El TCR se calcula con oracle actualizado?
    - ¿Los trove owners pueden ajustar sus posiciones en Recovery Mode?
  como_se_arregla: |
    Recovery Mode no debe bloquear operaciones defensivas (retiros, repagos).
    Minimum position size para limitar TCR manipulation por una sola posición.
    Anti-frontrunning: cooldown después de incremento de colateral antes de que surta efecto.
    TCR calculation con oracle actualizado (no cached).
  trampas:
    - Recovery Mode es un mecanismo de defensa legítimo — el issue es en los edge cases, no en el concepto.
    - En Liquity V1, Recovery Mode ha funcionado correctamente en crisis reales — es un diseño probado.
    - La manipulación de TCR requiere capital significativo — calcular el costo del ataque.
    - No confundir "liquidación en Recovery Mode" con "liquidación injusta" — el TCR check es la protección.
    - Liquity V2 tiene branches independientes — Recovery Mode es por branch, no global.
  solodit_ids:
    - "h-02-unable-to-remove-liquidity-in-recovery-mode-code4rena-malt-finance-malt-finance-contest-git"
    - "m-6-user-can-prevent-liquidations-by-frontrunning-the-tx-and-slightly-increasing-their-collateral-sherlock-taurus-taurus-git"
    - "m-3-account-can-not-be-liquidated-when-price-fall-by-99-sherlock-taurus-taurus-git"
    - "m-04-borrowing-from-branches-can-be-disabled-by-one-whale-or-early-depositor-recon-audits-none-bold-report-markdown"
  incidentes:
    - "Malt Finance (C4) — Recovery Mode bloquea remoción de liquidez, sistema no puede estabilizarse"
    - "Taurus (Sherlock) — usuario previene liquidación con frontrunning de incremento de colateral"
    - "Taurus (Sherlock) — cuenta no puede ser liquidada cuando precio cae 99%"
    - "BOLD (Recon Audits) — una whale o early depositor puede deshabilitar borrowing en un branch entero"
```

---

## 13. Errores en Price Curves / Bonding Curves para Stablecoins

```yaml
- id: cdp-013
  titulo: Bonding curve o price curve calculada incorrectamente permite mint/redeem a precio incorrecto
  causa_raiz: |
    Algunas stablecoins usan bonding curves (curvas de precio programáticas) para
    determinar el precio de mint/burn. LLAMMA de crvUSD usa soft liquidation con
    bandas de precio. f(x) Protocol usa split de exposición entre fToken (estable)
    y xToken (leveraged). Errores en la fórmula de la curva, en los ticks/bandas,
    o en la transición entre estados permiten:
    (a) Mint a precio inflado (recibir más tokens de lo correcto).
    (b) Redeem a precio deflado (extraer más colateral de lo correcto).
    (c) Manipulación de bandas/ticks para forzar soft liquidation de otros.
    (d) Exploits en empty ticks/bandas que permiten inflación.
  como_funciona: |
    Escenario crvUSD LLAMMA empty ticks (Curve Finance/MixBytes):
    1. LLAMMA usa bandas de precio para soft liquidation.
    2. Tick vacío (sin liquidez) tiene cálculo de precio degenerado.
    3. Atacante explota el tick vacío para inflar el valor de su posición.
    4. Inflation attack similar a first-depositor en vaults ERC4626.
    Escenario f(x) Protocol (RWf(x)):
    1. Protocolo divide exposición entre fToken (estable) y xToken (leveraged).
    2. Durante stability mode, minting de fToken y xToken debería bloquearse.
    3. Bug permite minting durante stability mode.
    4. Mint en stability mode distorsiona la curva de precio.
    5. xToken holders sufren pérdidas desproporcionadas.
    Escenario bonding curve haircut (Buck Labs):
    1. Haircut parameter < 1 crea oportunidad de arbitraje.
    2. Mint a precio con haircut → redeem sin haircut → profit.
    3. Repetir hasta drenar las reservas del protocolo.
  invariante: |
    // Bonding curve: precio de mint >= precio de redeem (no arbitraje)
    uint256 mintPrice = bondingCurve.getMintPrice(amount);
    uint256 redeemPrice = bondingCurve.getRedeemPrice(amount);
    assert(mintPrice >= redeemPrice); // spread no-negativo
    // LLAMMA: liquidez en banda no debe ser 0 cuando se opera
    assert(bandLiquidity[currentBand] > 0 || operation == DEPOSIT);
    // Total value conserved: totalCollateral * price >= totalStablecoinSupply
    assert(totalCollateralValue() >= totalSupply());
  que_mirar:
    - Ticks/bandas vacíos — ¿qué pasa con el cálculo de precio?
    - Haircut/spread entre mint y redeem — ¿puede ser negativo?
    - Stability mode — ¿qué operaciones están permitidas?
    - Transición entre bandas — ¿hay salto de precio discontinuo?
    - First depositor en una banda — ¿inflation attack posible?
    - Invariante de conservación: ¿valor total de colateral >= supply de stablecoin?
  como_se_arregla: |
    Manejar ticks vacíos explícitamente (skip o revert, nunca cálculo con 0).
    Spread mínimo positivo entre mint y redeem prices.
    Bloquear operaciones durante stability mode de forma completa y consistente.
    First-depositor protection en bandas nuevas (minimum liquidity).
  trampas:
    - LLAMMA de crvUSD es extremadamente complejo — muchos "bugs" son comportamiento esperado.
    - La soft liquidation de LLAMMA implica pérdida permanente by design — no es un bug.
    - Bonding curves lineales son más simples pero tienen slippage predecible (no es un bug).
    - No confundir impermanent loss en LLAMMA con un exploit — es el costo de la soft liquidation.
    - f(x) Protocol tiene diferentes modos (normal, stability, liquidation) — verificar transiciones.
  solodit_ids:
    - "inflation-attack-on-empty-ticks-mixbytes-none-curve-finance-markdown"
    - "m-01-minting-of-ftoken-and-xtoken-allowed-during-stability-mode-pashov-audit-group-none-rwfx_2025-08-20-markdown"
    - "haircut-1-can-create-arbitrage-opportunity-spearbit-none-buck-labs-pdf"
    - "any-attempt-to-liquidate-a-user-will-fail-because-stabilitypool-does-not-hold-crvusd-during-operational-lifecycle-codehawks-regnum-aurum-acq"
  incidentes:
    - "Curve Finance (MixBytes) — inflation attack en ticks vacíos de LLAMMA"
    - "RWf(x) (Pashov) — minting de fToken/xToken permitido durante stability mode"
    - "Buck Labs (Spearbit) — haircut < 1 crea oportunidad de arbitraje mint/redeem"
    - "Regnum Aurum (CodeHawks) — StabilityPool no tiene crvUSD durante lifecycle, liquidaciones fallan"
    - "Nirvana Finance (2022, Solana) — flash loan de $10M explota bonding curve, drena $3.5M"
```

---

## 14. Self-Liquidation para Profit

```yaml
- id: cdp-014
  titulo: Borrower se auto-liquida para extraer profit del bonus de liquidación
  causa_raiz: |
    Los protocolos CDP ofrecen un bonus de liquidación (típicamente 5-10%) para
    incentivar liquidadores. Si un borrower puede liquidarse a sí mismo (directamente
    o via proxy), puede:
    (a) Borrowear al máximo, dejar que la posición se vuelva liquidable.
    (b) Liquidarse con otra wallet → recibir el bonus.
    (c) El costo neto es menor que el bonus → profit neto.
    Esto es especialmente grave cuando el bonus de liquidación es fijo (no dinámico)
    o cuando no hay penalty suficiente que haga la auto-liquidación unprofitable.
  como_funciona: |
    Escenario LoopFi (C4):
    1. Liquidation penalty es X%, pero liquidación no aplica la penalty al calcular colateral.
    2. Borrower abre posición con CR justo sobre MCR.
    3. Espera a que precio baje ligeramente → posición liquidable.
    4. Con segunda wallet, liquida su propia posición.
    5. Recibe colateral + bonus - deuda repagada = profit neto.
    6. El protocolo pierde el valor del bonus (los otros lenders lo pagan).
    Escenario Licredity (Cyfrin):
    1. Borrower usa proxy contract para auto-liquidarse.
    2. Proxy contract puede recibir colateral y redirigirlo al borrower original.
    3. Como la liquidación es "desde otra dirección", el protocolo no la bloquea.
    4. El bad debt generado lo absorben los lenders.
  invariante: |
    // Self-liquidation check: liquidador != borrower (incluyendo proxies)
    // Más robusto: asegurar que liquidación SIEMPRE sea NPV-negative para el borrower
    uint256 collateralReceived = liquidationCollateral + liquidationBonus;
    uint256 debtRepaid = positionDebt;
    // El borrower debe perder más de lo que gana
    assert(collateralReceived < positionCollateralValue); // siempre pierde colateral neto
    // Penalty > bonus para el mismo usuario
    assert(liquidationPenalty > liquidationBonus);
  que_mirar:
    - ¿El protocolo permite que msg.sender == borrower en liquidate()?
    - ¿Se puede usar un proxy/contract intermedio para liquidar?
    - ¿El liquidation bonus es fijo o proporcional al riesgo?
    - ¿La penalty cubre el bonus? (penalty - bonus > 0)
    - ¿Hay minimum time entre borrow y liquidation eligibility?
    - ¿El colateral seized incluye correctamente la penalty?
  como_se_arregla: |
    Dynamic liquidation bonus: menor bonus para posiciones cerca del threshold.
    Penalty > bonus: asegurar que el borrower siempre pierde neto.
    Anti-proxy: verificar que el liquidador no es un contrato creado por el borrower (difícil).
    Minimum holding period: posición no liquidable hasta N bloques después de borrow.
  trampas:
    - Bloquear msg.sender == borrower es insuficiente — cualquiera puede usar un proxy.
    - El mecanismo más robusto es hacer la liquidación NPV-negativa para el borrower, no identity checks.
    - En Liquity V1, la auto-liquidación no es profitable porque el SP absorbe y redistribuye.
    - Algunos protocolos permiten "self-liquidation" intencionalmente como feature (graceful exit).
  solodit_ids:
    - "h-02-liquidation-doesnt-account-for-penalty-when-calculating-collateral-to-give-allowing-users-to-profit-by-borrowing-and-self-liquidating-c"
    - "self-triggered-licredity_afterswap-back-run-enables-lp-fee-farming-cyfrin-none-licredity-markdown"
    - "h-06-malicious-borrower-can-evade-full-liquidation-in-cdpvaultliquidateposition-by-repaying-small-amounts-of-debt-code4rena-loopfi-loopfi-gi"
    - "added-liquidation-fee-could-turn-the-loc-insolvent-openzeppelin-none-anvil-audit-markdown"
  incidentes:
    - "LoopFi (C4) — liquidación no cuenta penalty al calcular colateral, permite profit por auto-liquidación"
    - "Licredity (Cyfrin) — proxy-based self-liquidation crea bad debt para lenders"
    - "LoopFi (C4) — borrower evade full liquidation repagando cantidades pequeñas de deuda"
    - "Anvil (OpenZeppelin) — liquidation fee añadida puede volver el LoC insolvente"
    - "Euler Labs EVK (Cantina) — self-liquidations de posiciones apalancadas pueden ser rentables"
```

---

## 15. Dust Positions y Posiciones No-Liquidables

```yaml
- id: cdp-015
  titulo: Posiciones pequeñas sin incentivo de liquidación acumulan bad debt sistémico
  causa_raiz: |
    Los liquidadores son actores racionales económicos: solo liquidan si el profit
    (bonus de liquidación) cubre el costo (gas + capital). Posiciones con deuda
    muy pequeña ("dust") generan un bonus de liquidación menor que el gas cost.
    Resultado: nadie las liquida, se vuelven underwater, y acumulan bad debt que
    nadie paga. Con suficientes dust positions, el protocolo puede volverse
    insolvente gradualmente.
  como_funciona: |
    Escenario genérico (DYAD, Wise Lending, Foundry DeFi Stablecoin):
    1. Usuario abre posición con deuda mínima: $10 USDC.
    2. Collateral ratio = 150% → $15 de colateral.
    3. Precio cae → posición underwater. Bonus de liquidación = $1.50.
    4. Gas cost en mainnet ≈ $5-50 dependiendo de congestión.
    5. Bonus ($1.50) < gas ($5+) → nadie liquida.
    6. Posición acumula interés y bad debt indefinidamente.
    7. Con 1000 dust positions, bad debt = $10K+ que nadie paga.
    Escenario Peapods (Sherlock):
    1. Liquidador malicioso deja intencionalmente dust collateral en posición.
    2. La posición tiene deuda > 0 pero colateral ≈ 0.
    3. Bad debt handling no se activa porque colateral != 0.
    4. Phantom debt permanece en el sistema.
  invariante: |
    // Minimum position size
    assert(position.debt >= MIN_DEBT || position.debt == 0);
    // Post-liquidation: posición debe estar clean (debt = 0) o above MCR
    uint256 postLiqICR = getICR(position);
    assert(position.debt == 0 || postLiqICR >= MCR);
    // No dust collateral after liquidation
    assert(position.collateral == 0 || position.collateral >= MIN_COLLATERAL);
  que_mirar:
    - ¿Existe minimum debt (minLoanSize, MIN_DEBT)?
    - ¿La liquidación parcial puede dejar dust debt?
    - ¿La liquidación parcial puede dejar dust collateral?
    - ¿Bad debt handling se activa con collateral > 0 pero < deuda?
    - ¿El gas cost de liquidación se considera en el diseño del bonus?
    - ¿Hay keeper bot subsidiado que liquide posiciones sin profit?
  como_se_arregla: |
    Minimum debt threshold: require(debt >= MIN_DEBT || debt == 0).
    Full liquidation below threshold: si deuda restante < MIN_DEBT, liquidar completo.
    No dejar dust: si collateral < MIN_COLLATERAL post-liquidation, seized todo.
    Gas-aware liquidation bonus: bonus = max(fixed%, minGasCost).
  trampas:
    - En L2 (Arbitrum, Base) el gas es 100x más barato — dust positions son menos problemáticas.
    - No confundir "no incentive to liquidate" con "impossible to liquidate" — el primero es económico, el segundo es un bug de código.
    - Algunos protocolos usan liquidation bots subsidiados (no dependen del bonus) — menos riesgo.
    - El MIN_DEBT debe ser lo suficientemente alto para cubrir gas + slippage en el peor caso.
  solodit_ids:
    - "m-05-no-incentive-to-liquidate-small-positions-could-result-in-protocol-going-underwater-code4rena-dyad-dyad-git"
    - "m-05-the-protocol-allows-borrowing-small-positions-that-can-create-bad-debt-code4rena-wise-lending-wise-lending-git"
    - "there-is-no-incentive-to-liquidate-small-positions-codehawks-foundry-defi-stablecoin-codehawks-audit-contest-git"
    - "m-03-no-minloansize-means-liquidators-will-have-no-incentive-to-liquidate-small-positions-code4rena-revert-lend-revert-lend-git"
    - "m-02-no-incentive-to-liquidate-when-cr-1-as-asset-received-dyad-burned-code4rena-dyad-dyad-git"
  incidentes:
    - "DYAD (C4) — sin incentivo para liquidar posiciones pequeñas, protocolo puede ir underwater"
    - "Wise Lending (C4) — protocolo permite borrowing de posiciones pequeñas que crean bad debt"
    - "Foundry DeFi Stablecoin (CodeHawks) — sin incentivo para liquidar small positions"
    - "Revert Lend (C4) — sin minLoanSize, liquidadores no tienen incentivo para posiciones pequeñas"
    - "DYAD (C4) — sin incentivo para liquidar cuando CR <= 1, asset recibido < DYAD quemado"
    - "Peapods (Sherlock) — liquidador malicioso deja dust collateral, bad debt no se maneja"
```

---

## 16. Stability Pool — Reward Manipulation y Accounting Errors

```yaml
- id: cdp-016
  titulo: StabilityPool rewards manipulables o accounting incorrecto en absorción de liquidaciones
  causa_raiz: |
    El Stability Pool (SP) es el mecanismo principal de absorción de liquidaciones
    en protocolos Liquity-style. Los depositantes en el SP reciben colateral liquidado
    con descuento + rewards de token nativo. Vulnerabilidades surgen cuando:
    (a) El cálculo de rewards es manipulable (deposit justo antes de liquidación).
    (b) La absorción de liquidación no actualiza correctamente los shares.
    (c) Batch interest management tiene rounding errors.
    (d) El SP no tiene suficientes fondos para cubrir liquidaciones.
  como_funciona: |
    Escenario Regnum Aurum (CodeHawks):
    1. StabilityPool supuestamente absorbe liquidaciones con crvUSD.
    2. Pero el SP no tiene crvUSD durante el lifecycle operacional.
    3. Cualquier intento de liquidar falla porque el SP no puede cubrir.
    4. Posiciones underwater permanecen indefinidamente → bad debt sistémico.
    Escenario Bima (Cantina):
    1. TroveManager actualiza RewardIntegral para SP depositors.
    2. La lógica de actualización es incorrecta.
    3. Usuarios reciben MENOS rewards de lo esperado.
    4. Rewards "perdidos" quedan bloqueados en el contrato.
    Escenario BOLD (Recon Audits):
    1. Batch management tiene rounding error en interest calculation.
    2. La deuda de un trove puede ser "perdonada" y cargada al batch.
    3. Batch absorbe costos que no debería → otros trove owners perjudicados.
  invariante: |
    // SP must have enough tokens to cover liquidations
    assert(stabilityPool.totalDeposits() >= pendingLiquidationDebt || hasAlternativePath);
    // Rewards must be proportional to deposit share
    uint256 expectedReward = totalRewards * userDeposit / totalDeposits;
    uint256 actualReward = stabilityPool.getDepositorCollateralGain(user);
    assert(actualReward >= expectedReward - DUST_TOLERANCE);
    // Post-liquidation: SP deposits reduced by absorbed debt
    assert(spDeposits_post == spDeposits_pre - absorbedDebt);
  que_mirar:
    - ¿El SP tiene tokens suficientes para cubrir liquidaciones?
    - ¿Los rewards se calculan proporcionalmente a los deposits?
    - ¿Hay protección contra JIT (Just-In-Time) deposits antes de liquidaciones?
    - ¿El batch interest rounding favorece al protocolo o al usuario?
    - ¿Los SP deposits se reducen correctamente después de absorción?
    - ¿Qué pasa si el SP está vacío durante una liquidación?
  como_se_arregla: |
    SP must always have stablecoins (invariante fundamental).
    JIT protection: deposits tienen cooldown antes de ser elegibles para rewards.
    Rounding en batch management: favorecer al protocolo (round down rewards, round up debt).
    Fallback liquidation: si SP vacío, usar redistribución directa entre troves.
  trampas:
    - El SP de Liquity V1 funciona correctamente — los bugs son en FORKS de Liquity.
    - JIT deposit protection ya existe en Liquity V1 (offset by 0 al depositar) — verificar si el fork lo copió.
    - Rounding en batch es típicamente < 1 wei — solo reportable si es acumulable.
    - El SP vacío es un edge case extremo — pero si ocurre, TODO el sistema de liquidación falla.
  solodit_ids:
    - "any-attempt-to-liquidate-a-user-will-fail-because-stabilitypool-does-not-hold-crvusd-during-operational-lifecycle-codehawks-regnum-aurum-acq"
    - "reward-manipulation-vulnerability-in-stabilitypool-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "trovemanagers-rewardintegral-update-logic-is-flawed-users-may-be-receiving-less-rewards-than-expected-cantina-none-bima-pdf"
    - "h-01-bold-batch-shares-math-can-be-rebased-by-combining-rounding-errors-and-setbatchmanagerannualinterestrate-to-borrow-for-free-recon-audit"
    - "m-03-batch-management-rounding-error-can-cause-debt-from-being-forgiven-to-a-trove-and-charged-to-the-batch-recon-audits-none-bold-report-ma"
  incidentes:
    - "Regnum Aurum (CodeHawks) — StabilityPool no tiene crvUSD, liquidaciones fallan completamente"
    - "Regnum Aurum (CodeHawks) — reward manipulation vulnerability en StabilityPool"
    - "Bima (Cantina) — TroveManager RewardIntegral update incorrecto, usuarios reciben menos rewards"
    - "BOLD/Liquity V2 (Recon Audits) — batch shares math rebaseable combinando rounding + setRate → borrow gratis"
    - "BOLD (Recon Audits) — rounding error en batch management perdona deuda a un trove y la carga al batch"
```

---

## 17. Trove/CDP Operation Ordering Attacks

```yaml
- id: cdp-017
  titulo: Orden de operaciones en trove/CDP explota protección insuficiente de flashloan o stale state
  causa_raiz: |
    Las operaciones de trove (open, adjust, close, delegate) requieren protecciones
    contra flash loans y reentrancy. Si un protocolo usa Zappers (contratos helper)
    para simplificar operaciones de trove, estos Zappers pueden ser explotados si:
    (a) La protección anti-flashloan es insuficiente (solo checkea en el bloque actual).
    (b) Un atacante puede operar troves que no le pertenecen via el Zapper.
    (c) El estado se lee antes de accrueInterest() → operaciones con datos stale.
    (d) Operaciones atómicas permiten secuencias que violan invariantes transitorios.
  como_funciona: |
    Escenario BOLD Zappers (Recon Audits):
    1. Liquity V2 usa Zappers para abstraer operaciones de trove.
    2. Flashloan protection checkea si el trove fue modificado en el mismo bloque.
    3. Pero la protección es insuficiente — no cubre todos los paths.
    4. Atacante usa flash loan para operar en el trove de OTRO usuario via Zapper.
    5. Puede adjustar, cerrar, o transferir troves que no le pertenecen.
    Escenario Lybra Finance (C4):
    1. Atacante provee "fake income" al protocol.
    2. Esto desbalancea _totalSupply y _totalShares del stablecoin.
    3. Con el desbalance, posteriores operaciones de mint/burn extraen valor.
    4. El atacante roba fondos de otros depositantes.
  invariante: |
    // Solo el owner del trove puede operarlo (o un delegado autorizado)
    assert(msg.sender == troveOwner || isApprovedDelegate(msg.sender, troveOwner));
    // Flash loan protection: trove no modificado en este bloque
    assert(troveLastModifiedBlock[troveId] < block.number);
    // State consistency: accrueInterest antes de leer cualquier dato
    accrueInterest();
    // Post-operation: trove es válido
    assert(getICR(troveId) >= MCR || troveDebt(troveId) == 0);
  que_mirar:
    - Zappers/Router contracts: ¿verifican ownership del trove?
    - Flash loan protection: ¿checkea bloque actual o algo más robusto?
    - ¿accrueInterest() se llama antes de TODAS las lecturas de estado?
    - ¿Se puede combinar operaciones para bypasear checks individuales?
    - ¿El Zapper puede ser llamado por cualquiera o solo por el trove owner?
    - ¿El protocolo usa onBehalf patterns sin validación adecuada?
  como_se_arregla: |
    Ownership check robusto en CADA operación de trove (no solo en el Zapper).
    Flash loan protection multi-block: require(lastModified + cooldown < block.number).
    accrueInterest() al inicio de CADA función pública.
    Zappers con AccessControl: solo trove owner o approved delegates.
  trampas:
    - Los Zappers son contratos auxiliares — muchos auditores se centran solo en el core y los ignoran.
    - La protección anti-flash loan por bloque es insuficiente si el atacante puede operar en el bloque siguiente.
    - El "fake income" attack requiere que el protocolo use share/supply ratio manipulable.
    - Verificar que el approve/delegate system no permite delegaciones permanentes a contratos maliciosos.
  solodit_ids:
    - "h-02-the-flashloan-protection-for-zappers-is-insufficient-we-can-operate-on-troves-we-dont-own-recon-audits-none-bold-report-markdown"
    - "h-05-making-_totalsupply-and-_totalshares-imbalance-significantly-by-providing-fake-income-leads-to-stealing-fund-code4rena-lybra-finance-ly"
    - "h-01-bold-batch-shares-math-can-be-rebased-by-combining-rounding-errors-and-setbatchmanagerannualinterestrate-to-borrow-for-free-recon-audit"
    - "h-01-receivecollateral-can-be-called-by-anyone-code4rena-yeti-finance-yeti-finance-contest-git"
  incidentes:
    - "BOLD/Liquity V2 (Recon Audits) — flashloan protection insuficiente, operar troves ajenos via Zapper"
    - "Lybra Finance (C4) — fake income desbalancea totalSupply/totalShares, permite robo de fondos"
    - "BOLD (Recon Audits) — batch shares math rebaseable, borrow gratis combinando rounding + setRate"
    - "Yeti Finance (C4) — receiveCollateral() puede ser llamado por cualquiera, robo de colateral"
```

---

## 18. Liquidation DoS — Bloqueo de Liquidaciones

```yaml
- id: cdp-018
  titulo: Liquidaciones bloqueadas por revert, falta de liquidez, o frontrunning
  causa_raiz: |
    Si las liquidaciones no pueden ejecutarse cuando son necesarias, el protocolo
    acumula posiciones underwater que generan bad debt. Las liquidaciones pueden
    bloquearse por:
    (a) Revert en la función de liquidación por error de código.
    (b) Falta de liquidez en el mercado para vender el colateral.
    (c) Borrower frontrunea la liquidación para hacerla revertir.
    (d) Colateral pausado (e.g., USDC blacklist) impide transferencia.
    (e) Función de liquidación con gas cost excesivo (loop unbounded).
  como_funciona: |
    Escenario Vii (Spearbit):
    1. Atacante detecta que su posición va a ser liquidada.
    2. Frontrunea la tx de liquidación con una operación que hace la liquidación revertir.
    3. La posición permanece underwater pero no liquidable.
    4. Bad debt se acumula mientras la posición es "protegida" por el frontrunning.
    Escenario Isomorph (Sherlock):
    1. Colateral es un token pausable (e.g., USDC).
    2. USDC issuer blacklistea la dirección del vault.
    3. Liquidación intenta transferir el colateral → revert porque está pausado/blacklisted.
    4. Posición underwater permanece indefinidamente.
    5. El préstamo no puede cerrarse ni liquidarse → bad debt permanente.
    Escenario Exactly Protocol (Sherlock):
    1. Market::liquidate() falla cuando la mayoría de la liquidez está borrowed.
    2. La función intenta transferFrom antes de que los fondos estén disponibles.
    3. Con alta utilización del pool, las liquidaciones simplemente revierten.
  invariante: |
    // Liquidation must always be possible for underwater positions
    // (can't assert this statically, but in fuzzing:)
    if (getICR(position) < MCR) {
        // La siguiente llamada a liquidate() NO debe revertir
        // Simular: try liquidate(position) → must succeed
        assert(liquidateSucceeds(position));
    }
    // Colateral transfer must not revert
    assert(IERC20(collateral).transfer(liquidator, amount)); // must not revert
  que_mirar:
    - ¿La función liquidate() puede revertir por algún path?
    - ¿El colateral es un token pausable (USDC, USDT)?
    - ¿Hay frontrunning protection? (minimum change between blocks)
    - ¿La liquidación funciona con alta utilización del pool?
    - ¿Hay gas limit en loops de liquidación (batchLiquidateTroves)?
    - ¿Qué pasa si el oracle retorna 0 durante la liquidación?
  como_se_arregla: |
    try/catch en transferencias de colateral con fallback (e.g., credit to internal balance).
    Anti-frontrunning: minimum state change cooldown.
    Liquidación parcial cuando hay baja liquidez (no all-or-nothing).
    Gas-bounded batch liquidation con límite de iteraciones.
    Fallback liquidation path si el primario falla.
  trampas:
    - La liquidación DoS requiere que NADIE pueda liquidar — si hay un path alternativo, no es DoS.
    - Tokens pausables (USDC) son un riesgo conocido y a menudo documentado como "known issue".
    - Frontrunning protection en L2 es menos relevante (secuenciador FIFO en Arbitrum/Optimism).
    - No confundir "gas expensive" con "DoS" — la liquidación puede ser cara pero funcional.
  solodit_ids:
    - "h-6-outstanding-loans-cannot-be-closed-or-liquidated-if-collateral-is-paused-sherlock-isomorph-isomorph-git"
    - "m-11-market-liquidate-fails-when-most-liquidity-is-borrowed-due-to-wrong-transferfrom-order"
    - "h-1-liquidations-are-impossible-for-some-curve-pools-sherlock-notional-notional-update-2-git"
    - "m-20-fixed-reward-percentage-for-liquidators-in-the-eusd-vault-may-cause-a-liquidation-crisis-code4rena-lybra-finance-lybra-finance-git"
    - "h-11-it-is-nearly-impossble-for-liquidators-to-use-liquidateposition-to-fully-pay-off-a-non-bad-debt-position-code4rena-loopfi-loopfi-git"
  incidentes:
    - "Isomorph (Sherlock) — loans no pueden cerrarse ni liquidarse si colateral está pausado"
    - "Exactly Protocol (Sherlock) — liquidate() falla cuando mayoría de liquidez está borrowed"
    - "Notional (Sherlock) — liquidaciones imposibles para ciertos Curve pools"
    - "Lybra Finance (C4) — percentage fijo de reward para liquidadores causa crisis de liquidación"
    - "LoopFi (C4) — casi imposible para liquidadores pagar completamente posiciones non-bad-debt"
    - "Vii (Spearbit) — atacante hace revertir liquidaciones, causando bad debt"
```
