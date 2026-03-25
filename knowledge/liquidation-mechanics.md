# Liquidation Mechanics — Bug Patterns

## Quick Reference

```
grep_targets:
  - liquidate
  - liquidation
  - liquidationBonus
  - liquidationThreshold
  - liquidationPenalty
  - closeFactor
  - closeFactorBps
  - healthFactor
  - isHealthy
  - _healthCheck
  - collateralFactor
  - collateralValueUSD
  - debtValueUSD
  - getLiquidationBonus
  - getHealthFactor
  - _calculateHealth
  - _isLiquidatable
  - badDebt
  - bad_debt
  - socializedLoss
  - repayBorrowFresh
  - seizeColl
  - seizeCollateral
  - liquidatePosition
  - partialLiquidation
  - fullLiquidation
  - maxLiquidatable
  - minDebt
  - dustThreshold
  - auctionPrice
  - startAuction
  - gracePeriod
  - sequencerUptimeFeed
  - L2_SEQUENCER_GRACE_PERIOD
  - donateToReserves
  - stakeNFT
  - gaugeManager
```

---

## 1. Liquidation Cascade / Death Spiral

```yaml
- id: liq-001
  titulo: Cascada de liquidaciones amplifica ventas y genera bad debt sistémico
  causa_raiz: |
    En protocolos de lending, cuando una liquidación vende colateral en el mercado, el precio
    del colateral baja. Esto hace que OTRAS posiciones usando el mismo colateral también se
    vuelvan liquidables. Si el mercado es ilíquido o el colateral es el token nativo del
    protocolo (e.g., XVS en Venus, COMP en Compound), la cascada se auto-amplifica:
    liquidación → venta → precio baja → más liquidaciones → más ventas → death spiral.
    El protocolo termina con bad debt masivo porque el colateral se vende a precios
    cada vez más bajos.
  como_funciona: |
    1. Mercado cae 20% en 1 hora — cientos de posiciones entran en zona liquidable.
    2. Liquidadores compiten para liquidar, vendiendo colateral seized en DEXes.
    3. La venta masiva deprime aún más el precio del colateral.
    4. Posiciones que estaban sanas con 20% de margen ahora son liquidables.
    5. La cascada continúa hasta que: (a) se agota la liquidez de liquidadores,
       (b) el colateral pierde tanto valor que las liquidaciones generan bad debt,
       o (c) el protocolo pausa operaciones.
    Caso real Venus (mayo 2021): precio de XVS manipulado de $70 a $144, usado como
    colateral para borrowear BTC/ETH, luego XVS colapsa → $100M+ de bad debt.
  invariante: |
    // Después de una liquidación, el protocolo NO debe estar peor
    uint256 totalBadDebtBefore = protocol.totalBadDebt();
    liquidate(position);
    uint256 totalBadDebtAfter = protocol.totalBadDebt();
    t(totalBadDebtAfter <= totalBadDebtBefore + DUST,
      "LIQ-001: liquidation increased total bad debt");
  que_mirar:
    - Colateral que es el token nativo del protocolo (XVS, COMP, MKR)
    - Sin circuit breaker o rate limiter en liquidaciones masivas
    - Liquidation bonus alto (>10%) que incentiva cascada rápida
    - Sin mecanismo de socialización de bad debt (insurance fund, backstop)
    - Oracles que siguen precios spot sin smoothing durante crash
  como_se_arregla: |
    Rate limiter en liquidaciones por bloque o por epoch.
    Insurance fund / backstop module que absorba bad debt antes de socializar.
    Circuit breaker: si precio cae >X% en N bloques, pausar liquidaciones.
    Usar TWAP para valorar colateral durante liquidaciones (suaviza cascada).
    Limitar LTV máximo para colateral de baja liquidez.
  trampas:
    - La cascada es un riesgo de DISEÑO, no necesariamente un bug de código.
    - Reportar como "liquidation cascade possible" sin cuantificar impacto = QA.
    - El verdadero bug es cuando el protocolo NO tiene mecanismo de mitigación.
    - Venus tenía Chainlink oracle — el problema fue liquidez insuficiente en CEX.
  solodit_ids:
    - "cascading-liquidation-violates-whitepaper-github-venusprotocol-venus-protocol-issues-48"
  incidentes:
    - "Venus Protocol (mayo 2021) — XVS pump-and-dump generó $100M+ bad debt; colateral nativo usado como collateral sin cap de supply"
    - "MakerDAO Black Thursday (marzo 2020) — ETH -43% en horas, cascada de liquidaciones con $8.32M seized a bid=0 DAI"
    - "Compound DAI incident (nov 2020) — DAI en Coinbase Pro pumpeó a $1.30 por baja liquidez, liquidaciones incorrectas de posiciones sanas"
```

---

## 2. Partial Liquidation Accounting Errors

```yaml
- id: liq-002
  titulo: Liquidación parcial no ajusta correctamente deuda/colateral residual
  causa_raiz: |
    Cuando un protocolo permite liquidar solo una fracción de la posición (close factor < 100%),
    la aritmética de cuánta deuda se repaga, cuánto colateral se seized, y cuánto queda
    debe ser perfecta. Errores comunes: (1) seized collateral calculado con rounding a favor
    del liquidador, (2) deuda residual no actualizada, (3) close factor aplicado a deuda
    total pero seized calculado sobre deuda parcial, (4) posición queda en peor estado
    (health factor MÁS bajo) después de la liquidación parcial.
  como_funciona: |
    Escenario A — Posición queda peor:
    1. Posición tiene HF=0.98 (liquidable, close factor 50%).
    2. Liquidador repaga 50% de deuda y seize 50% de colateral + bonus.
    3. Pero el bonus sale del colateral restante → HF del residual < 0.98.
    4. Posición inmediatamente liquidable otra vez → loop hasta 100% liquidada.

    Escenario B — Bad debt por partial:
    1. Posición insolvent (colateral < deuda). Full liquidation forzaría al liquidador a cubrir bad debt.
    2. Liquidador hace liquidación parcial → se lleva colateral sin cubrir bad debt proporcional.
    3. Bad debt queda huérfano en el protocolo.
  invariante: |
    // Después de liquidación parcial, HF debe mejorar o mantenerse
    uint256 hfBefore = getHealthFactor(user);
    partialLiquidate(user, repayAmount);
    uint256 hfAfter = getHealthFactor(user);
    t(hfAfter >= hfBefore || hfAfter >= 1e18,
      "LIQ-002: partial liquidation worsened health factor");
  que_mirar:
    - close factor < 100% combinado con liquidation bonus > 0
    - Rounding direction en seized = repayAmount * bonus / collateralPrice
    - Si partial liquidation de posición insolvent ignora bad debt proporcional
    - Si la liquidación puede dejar "dust" de deuda imposible de repagar
    - Funciones donde closeFactor se aplica a debtShares pero seized usa debtAmount
  como_se_arregla: |
    Verificar post-liquidation que HF mejoró (o forzar full liquidation si no).
    En posiciones insolventes, partial liquidation debe cubrir bad_debt proporcional.
    Usar rounding a favor del protocolo (round down en seized, round up en repay).
    Minimum repay amount para evitar dust positions post-liquidation.
  trampas:
    - Aave V3 usa close factor de 100% si HF < 0.95, lo cual mitiga este vector.
    - El "worsening HF" puede ser by design en algunos protocolos (documentado).
    - No confundir rounding dust (1 wei) con bug real de accounting.
  solodit_ids:
    - "joshuajee-the-liquidator-can-pay-more-than-50-of-the-debt-and-seize-more-collateral-even-when-the-health-factor-is-greater-than-095-sherlock-2024-06-new-scope-judging-issues-196"
    - "h-04-shrines-recovery-mode-can-be-weaponized-as-leverage-to-liquidate-healthy-troves-code4rena-opus-opus-git"
    - "liquidation-cannot-be-closed-even-with-healthy-position-due-to-strict-debt-check-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "NewScope (Sherlock) — Liquidador puede repagar >50% de deuda y seize más colateral cuando HF>0.95 vía doble liquidación parcial"
    - "Opus (C4) — Recovery mode weaponizado para liquidar troves sanos vía partial liquidation"
    - "Inverse Finance (C4) — Liquidation should make borrower healthier pero no lo hace"
    - "Blueberry — totalLend not updated on liquidation, permanently inflated (medium)"
```

---

## 3. Liquidation Bonus Exceeding Collateral — Bad Debt Creation

```yaml
- id: liq-003
  titulo: Bonus de liquidación > colateral restante genera bad debt no contabilizado
  causa_raiz: |
    Cuando una posición está muy underwater (colateral vale menos que deuda), el
    liquidation bonus (5-15% típico) puede hacer que el colateral seized no cubra
    ni siquiera la deuda repagada. El liquidador recibe bonus del colateral, pero
    no hay colateral suficiente para cubrir toda la deuda → bad debt queda sin dueño.
    Si el protocolo no tiene mecanismo de socialización (insurance fund, bad debt
    module), el bad debt se acumula silenciosamente y los últimos withdrawers pierden.
  como_funciona: |
    1. Posición: colateral=$900, deuda=$1000 (insolvent, $100 bad debt).
    2. Liquidación con 10% bonus: liquidador repaga $818 de deuda,
       seized = $818 * 1.10 = $900 (todo el colateral).
    3. Deuda restante: $1000 - $818 = $182 de deuda sin colateral.
    4. Esta deuda nunca se repaga → bad debt del protocolo.
    5. Si no hay insurance fund, los depositantes absorben la pérdida.

    Variante: liquidation bonus calculado ANTES de verificar si hay suficiente
    colateral → arithmetic underflow/revert → posición unliquidatable.
  invariante: |
    // El bonus nunca debe exceder el colateral disponible
    uint256 seized = repayAmount * (1e18 + bonus) / price;
    t(seized <= userCollateral[account],
      "LIQ-003: seized with bonus exceeds available collateral");

    // Bad debt debe ser contabilizado explícitamente
    if (debtValue > collateralValue) {
        uint256 badDebt = debtValue - collateralValue;
        t(protocol.recognizedBadDebt() >= badDebt,
          "LIQ-003: bad debt not accounted for");
    }
  que_mirar:
    - Cálculo de seized amount cuando posición está underwater
    - Qué pasa si seized > userCollateral (revert? cap? bad debt?)
    - ¿Existe bad debt socialization module?
    - ¿El protocolo revierte la liquidación si no hay suficiente colateral?
    - Liquidation bonus hardcodeado vs dinámico según profundidad underwater
  como_se_arregla: |
    Cap seized a min(seized_with_bonus, totalCollateral).
    Si posición insolvent → liquidación sin bonus, seized = todo el colateral.
    Bad debt module que socialice pérdidas entre depositantes o insurance fund.
    Reducir bonus progresivamente conforme posición se acerca a insolvencia.
    Euler V2 usa "soft liquidation" con bonus dinámico que se reduce a 0 en insolvencia.
  trampas:
    - Aave socializa bad debt reduciendo el aToken exchange rate — es by design.
    - Algunos protocolos prefieren dejar posiciones insolvent sin liquidar (MakerDAO DSR).
    - La ausencia de bad debt module no siempre es un bug — puede ser design trade-off documentado.
  solodit_ids:
    - "proxy-based-self-liquidation-creates-bad-debt-for-lenders-cyfrin-none-licredity-markdown"
    - "attackers-can-make-liquidation-revert-and-put-protocol-at-risk-due-to-bad-debt-code4rena-2024-01-salty-findings-issues-248"
  incidentes:
    - "Euler Finance (marzo 2023) — donateToReserves() creó bad debt masivo sin health check, $197M robados"
    - "Venus Protocol (mayo 2021) — Posiciones con XVS colateral quedaron underwater, $100M+ bad debt"
    - "Aave (nov 2022) — CRV short squeeze en Aave V2, $1.6M bad debt por posición de Avraham Eisenberg"
    - "Salty (C4) — Atacante puede hacer que liquidation revierte, forzando bad debt"
    - "Licredity (Cyfrin) — Self-liquidation vía proxy crea bad debt para lenders"
```

---

## 4. Self-Liquidation Profit Extraction

```yaml
- id: liq-004
  titulo: Usuario se auto-liquida para extraer liquidation bonus de su propio colateral
  causa_raiz: |
    Si un protocolo no verifica que msg.sender != borrower (o equivalente vía proxy/contract),
    un usuario puede: (1) depositar colateral, (2) borrowear al máximo LTV, (3) manipular
    su posición para que sea liquidable (e.g., oracle update, interest accrual), (4) liquidar
    su propia posición con otra cuenta → cobrar el liquidation bonus a costa del protocolo.
    El profit viene de que el bonus se paga del colateral pero la deuda se cancela —
    si el usuario controla ambos lados, extrae valor neto.
  como_funciona: |
    1. Atacante deposita $10,000 de colateral, borrowea $7,500 (LTV 75%).
    2. Espera a que interest accrual suba deuda a $7,600 (HF < 1.0).
    3. Desde otra wallet, liquida su propia posición:
       - Repaga $7,600 de deuda
       - Seize $7,600 * 1.05 = $7,980 de colateral (5% bonus)
    4. Resultado neto: perdió $10,000 colateral, recuperó $7,980 colateral + $7,500 borrowed.
       Total out: $15,480. Total in: $10,000. Profit: $5,480.
    5. Pero el protocolo pierde porque: depositantes contribuyeron al colateral que se seized.

    Variante con flash loan:
    1. Flash loan $7,600 → repay deuda → seize $7,980 → repay flash loan → profit $380.
  invariante: |
    // Self-liquidation check
    t(liquidator != borrower && !isProxy(liquidator, borrower),
      "LIQ-004: self-liquidation detected");

    // O alternativamente: profit from self-liquidation must be zero
    uint256 netValueBefore = collateral[user] - debt[user];
    selfLiquidate();
    uint256 netValueAfter = collateral[user] - debt[user] + seized;
    t(netValueAfter <= netValueBefore + DUST,
      "LIQ-004: self-liquidation extracted value");
  que_mirar:
    - ¿Se verifica msg.sender != borrower en liquidate()?
    - ¿Se puede liquidar a través de un proxy/contract que oculte la relación?
    - ¿El liquidation bonus es lo suficientemente bajo como para que self-liquidation no sea profitable?
    - ¿Hay un cooldown entre borrow y liquidation eligibility?
    - Flash loan + self-liquidation en una tx
  como_se_arregla: |
    Prohibir self-liquidation explícitamente: require(msg.sender != borrower).
    Aplicar borrow fee que supere el liquidation bonus (hace self-liquidation net negative).
    Cooldown period: posición no liquidable hasta N bloques después del último borrow.
    Liquidation bonus dinámico que empieza en 0 y sube con el tiempo underwater.
  trampas:
    - Prohibir self-liquidation por msg.sender es insuficiente — atacante usa contrato intermediario.
    - En algunos protocolos, self-liquidation es by design (Aave permite).
    - El profit real depende del LTV, bonus, y fees — modelar numéricamente.
    - Si origination fee > bonus, self-liquidation no es profitable.
  solodit_ids:
    - "proxy-based-self-liquidation-creates-bad-debt-for-lenders-cyfrin-none-licredity-markdown"
  incidentes:
    - "Licredity (Cyfrin) — Self-liquidation via proxy crea bad debt porque el bonus se extrae del pool"
    - "Euler Finance (2023) — Self-collateralized borrow + donateToReserves = self-inflicted liquidation con profit masivo"
```

---

## 5. Flash Loan Liquidation / Oracle Manipulation

```yaml
- id: liq-005
  titulo: Flash loan para manipular precio y forzar liquidaciones falsas
  causa_raiz: |
    Si el oracle de un protocolo de lending lee precios spot de un pool DEX (no TWAP,
    no Chainlink), un atacante puede usar un flash loan para mover el precio temporalmente,
    liquidar posiciones sanas a precio manipulado, y repagar el flash loan en la misma tx.
    El atacante profit = liquidation bonus - flash loan fee - gas.
  como_funciona: |
    1. Flash loan $50M de USDC desde Aave/dYdX.
    2. Dump USDC en Uniswap ETH/USDC pool → precio de ETH sube vs USDC.
    3. En el mismo bloque, el oracle del protocolo lee el precio spot inflado.
    4. Posiciones que tenían ETH como deuda ahora parecen underwater
       (su deuda vale más).
    5. Atacante liquida esas posiciones, seize colateral con bonus.
    6. Repay flash loan. Net profit del bonus.

    Variante Mango Markets: no flash loan sino open positions en perp DEX,
    pump price de MNGO 13x en CEX, use inflated value as collateral,
    borrow $114M de otros assets.
  invariante: |
    // Oracle no debe ser manipulable en un solo bloque
    uint256 price = oracle.getPrice(token);
    uint256 twap = oracle.getTWAP(token, 30 minutes);
    t(price * 100 / twap > 90 && price * 100 / twap < 110,
      "LIQ-005: spot price deviates >10% from TWAP");
  que_mirar:
    - ¿El oracle usa precio spot de un pool? ¿Cuál pool? ¿Cuánta liquidez?
    - ¿Se puede mover el precio >5% con un flash loan de tamaño razonable?
    - ¿El protocolo usa Chainlink o TWAP con ventana >10 min?
    - ¿Se puede triggear un oracle update en el mismo bloque que la liquidación?
    - ¿Hay protección contra manipulación intra-bloque?
  como_se_arregla: |
    Usar Chainlink como oracle primario (resistente a manipulación intra-bloque).
    TWAP con ventana >= 30 min para cualquier oracle on-chain.
    Deviation check: revert si precio spot difiere >X% del TWAP.
    Rate limiter: máximo Y liquidaciones por bloque/epoch.
  trampas:
    - Chainlink NO es inmune — tiene heartbeat de 1h y deviation threshold de 0.5-1%.
    - TWAP de 30 min puede ser manipulado por atacante con capital sostenido.
    - El costo real del ataque depende de la liquidez del pool target.
    - Mango Markets NO usó flash loan — fue capital real mantenido durante minutos.
  solodit_ids:
    - "users-can-become-immediately-liquidatable-after-executing-an-action-trailofbits-none-aave-v4-pdf"
  incidentes:
    - "Mango Markets (oct 2022) — Eisenberg manipuló MNGO 13x en CEX, borroweó $114M contra colateral inflado"
    - "Cream Finance (oct 2021) — Oracle de yUSD manipulado via donation directa al vault, $136M robados"
    - "Venus Protocol (mayo 2021) — XVS pumpeado en Binance, usado como colateral, $100M bad debt"
    - "UwULend (jun 2024) — Oracle price manipulation, $19.3M pérdidas"
    - "WiseLending (ene 2024) — Bad healthFactor check + manipulación, $464K"
```

---

## 6. Liquidation Front-Running / MEV Extraction

```yaml
- id: liq-006
  titulo: MEV bots front-run oracle updates para extraer liquidation bonus
  causa_raiz: |
    Los oracle updates (Chainlink) y las transacciones de liquidación viajan por el
    mempool público. Un MEV bot puede: (1) ver un oracle update pendiente que hará
    posiciones liquidables, (2) insertar su tx de liquidación DESPUÉS del oracle update
    pero ANTES de que el borrower pueda añadir colateral. En L2 con sequencer centralizado,
    el operador del sequencer puede hacer esto directamente. En MakerDAO Black Thursday,
    bots manipularon el mempool para ganar auctions a bid=0.
  como_funciona: |
    Escenario A — Front-run oracle update:
    1. Chainlink keeper envía tx de oracle update (ETH $2000 → $1800).
    2. MEV bot ve la tx en el mempool.
    3. Bot envía liquidate(victima) justo después del oracle update.
    4. Borrower no puede reaccionar (su tx de addCollateral queda detrás).

    Escenario B — MakerDAO Black Thursday (auction manipulation):
    1. Red Ethereum congestionada, gas a 200+ gwei.
    2. Keeper bots con gas fijo (50 gwei) no pueden ejecutar bids.
    3. Un bot con gas ilimitado envía bid=0 DAI y espera el timer.
    4. Sin competencia, gana $8.32M de ETH por 0 DAI.
    5. Evidencia de "Hammerbots" que congestionaron el mempool deliberadamente.
  invariante: |
    // Auction debe tener precio mínimo o Dutch auction mechanism
    t(auction.currentBid() >= auction.debtAmount() * MIN_BID_RATIO / 1e18,
      "LIQ-006: auction bid below minimum threshold");

    // Liquidation debe tener delay mínimo después de oracle update
    t(block.timestamp >= lastOracleUpdate + GRACE_PERIOD,
      "LIQ-006: liquidation too soon after oracle update");
  que_mirar:
    - ¿Hay MEV protection (private mempool, Flashbots, commit-reveal)?
    - ¿Las auctions tienen precio mínimo o Dutch auction decreciente?
    - ¿Hay grace period entre oracle update y liquidation eligibility?
    - En L2, ¿el sequencer puede reordenar txs para liquidar primero?
    - ¿Los keeper bots usan gas dinámico o fijo?
  como_se_arregla: |
    Dutch auction con precio decreciente desde premium hasta descuento.
    Precio mínimo en auction = X% del debt value.
    Grace period post-oracle-update (Aave V3 implementa esto en L2).
    Private mempool (Flashbots Protect) para oracle updates.
    MakerDAO Liquidations 2.0 (post-Black Thursday): Dutch auction que empieza alto.
  trampas:
    - MEV extraction de liquidaciones es un problema sistémico de Ethereum — no siempre es bug del protocolo.
    - Reportar "MEV possible on liquidations" sin path concreto = invalid.
    - El verdadero bug es cuando el DISEÑO del protocolo facilita el MEV (auction sin precio mínimo).
    - Black Thursday fue combinación de red congestionada + keeper mal configurado + auction mal diseñada.
  solodit_ids: []
  incidentes:
    - "MakerDAO Black Thursday (marzo 2020) — $8.32M de ETH liquidado a bid=0 DAI; Hammerbots manipularon mempool"
    - "Compound (nov 2020) — MEV bots front-running liquidations en posiciones con DAI inflado"
```

---

## 7. Health Factor Boundary Precision Errors

```yaml
- id: liq-007
  titulo: Errores de precisión en health factor boundary (1.0) impiden o permiten liquidaciones indebidas
  causa_raiz: |
    Health factor se calcula como (collateralValue * liquidationThreshold) / debtValue.
    En Solidity, esta operación involucra multiplicaciones y divisiones con 1e18 de
    precisión. Rounding errors pueden hacer que una posición con HF=1.000000000000000001
    sea liquidable (falso positivo) o que una posición con HF=0.999999999999999999 no sea
    liquidable (falso negativo). Cuando close factor cambia en HF=0.95, un error de 1 wei
    puede determinar si se liquida 50% o 100%.
  como_funciona: |
    Escenario A — Boundary exacto:
    1. Posición con HF = exactamente 1e18.
    2. Check: if (healthFactor < 1e18) → liquidatable.
    3. Posición NO es liquidable por un wei.
    4. Pero el interest accrual de 1 segundo la hace liquidable.
    5. Si no se accrua interest antes del check → posición escapa.

    Escenario B — Close factor threshold:
    1. Aave V3: HF < 0.95e18 → close factor = 100%. HF >= 0.95e18 → close factor = 50%.
    2. Rounding en HF calculation: 0.9500000000000000001 por rounding.
    3. Close factor = 50% en vez de 100% → posición no se liquida completamente.
    4. Residual queda underwater sin incentivo suficiente para liquidar.

    Escenario C — Aave V3.3 (Sherlock):
    1. Bug real: HF == 0.95e18 exacto causa revert en validación.
    2. Posición con HF exactamente 0.95 no puede ser liquidada.
  invariante: |
    // Precision check en health factor calculation
    uint256 hf = (collateral * liqThreshold) / debt;
    // Debe usar >= o <= consistentemente, nunca mezclar < y <=
    bool liquidatable_strict = (hf < HEALTH_FACTOR_THRESHOLD);
    bool liquidatable_loose = (hf <= HEALTH_FACTOR_THRESHOLD);
    // Verificar que el protocolo es consistente en todas las funciones
  que_mirar:
    - ¿El check es < 1e18 o <= 1e18? ¿Es consistente en todas las funciones?
    - ¿Se accrua interest ANTES de calcular health factor?
    - ¿Hay close factor breakpoints (0.95 en Aave)? ¿Qué pasa en el boundary exacto?
    - Rounding direction en multiplicación y división del HF
    - ¿El protocolo usa wadMul/wadDiv? ¿Rounding up o down?
  como_se_arregla: |
    Usar >= para liquidation threshold (HF <= 1e18 → liquidatable, no <).
    Accrue interest ANTES de cada health check.
    Test fuzzing con valores boundary: HF = 1e18, 1e18-1, 1e18+1, 0.95e18.
    Considerar tolerance band: liquidatable si HF < 1e18 + epsilon.
  trampas:
    - 1 wei de diferencia en HF rara vez tiene impacto práctico — es un edge case.
    - Pero en close factor boundaries (50% vs 100%), sí puede tener impacto significativo.
    - Este tipo de bug suele ser Medium, no High, excepto si bloquea todas las liquidaciones.
  solodit_ids:
    - "alert-lead-wolverine-improper-validation-of-liquidation-calls-can-lead-to-failure-in-liquidating-users-with-health-factor-exactly-at-095-sherlock-2025-01-aave-v3-3-judging-issues-171"
  incidentes:
    - "Aave V3.3 (Sherlock ene 2025) — HF exactamente 0.95 causa revert en validación de liquidación"
    - "Backed Protocol (audit) — Users liquidated right after taking maximal debt, no LTV gap"
    - "Sentiment (audit) — originationFee makes borrower liquidatable immediately"
```

---

## 8. Underwater Position Blocking (Dust Positions)

```yaml
- id: liq-008
  titulo: Posiciones demasiado pequeñas para liquidar rentablemente — bad debt acumulado
  causa_raiz: |
    Liquidar una posición tiene costos: gas (~$5-50 en L1, $0.01-0.1 en L2), complejidad
    de tx, y capital lock durante la ejecución. Si el liquidation bonus de una posición
    es menor que el costo de gas, ningún liquidador tiene incentivo económico para liquidarla.
    Posiciones "dust" (e.g., $10 de deuda) con HF < 1.0 se quedan indefinidamente sin
    liquidar, acumulando bad debt que se socializa entre todos los depositantes.
  como_funciona: |
    1. Usuario abre posición con $20 de colateral, borrowea $15.
    2. Precio cae → posición underwater. HF = 0.8.
    3. Liquidation bonus = 5% → liquidador ganaría $0.75.
    4. Gas cost de la tx de liquidación = $10 en L1.
    5. Resultado: nadie liquida. $15 de bad debt se queda en el protocolo.
    6. Repite 1000 veces: $15,000 de bad debt invisible.

    Variante: atacante deliberadamente crea miles de dust positions underwater
    para acumular bad debt sistémico y explotar a los depositantes.
  invariante: |
    // Minimum position size enforcement
    t(userDebt[account] == 0 || userDebt[account] >= MIN_DEBT,
      "LIQ-008: dust debt position below minimum");

    // Minimum collateral check
    t(userCollateral[account] == 0 || userCollateral[account] >= MIN_COLLATERAL,
      "LIQ-008: dust collateral position below minimum");
  que_mirar:
    - ¿Hay minimum borrow amount? ¿Se aplica después de partial repay/liquidation?
    - ¿Puede un partial repay dejar dust debt por debajo del mínimo?
    - ¿Hay incentivo extra para liquidar small positions (gas subsidy)?
    - ¿El protocolo tiene "dust sweep" que socialice micro bad debt?
    - Costo de gas en L2 vs L1 — en L2, $10 de deuda sí puede liquidarse
  como_se_arregla: |
    Minimum borrow amount: require(debtAmount >= MIN_DEBT) en borrow() y liquidate().
    Si partial repay/liquidation deja dust → forzar full repay/liquidation.
    Gas subsidy para liquidadores de small positions (insurance fund paga gas).
    Periodic dust sweep: socializar bad debt < threshold entre todos los depositantes.
  trampas:
    - En L2 (Arbitrum, Base, Optimism), gas es 100-1000x más barato → dust threshold es más bajo.
    - No confundir "no profitable to liquidate" con "impossible to liquidate".
    - Atacante necesita capital para crear miles de dust positions → costo de ataque puede ser alto.
    - Aave V3 tiene minimum debt check que mitiga esto.
  solodit_ids:
    - "there-is-no-incentive-to-liquidate-small-positions-github-cyfrin-2023-07-foundry-defi-stablecoin-issues-1096"
  incidentes:
    - "Foundry DeFi Stablecoin (Cyfrin) — Sin incentivo para liquidar posiciones pequeñas, bad debt acumula"
    - "Multiple protocols — Dust positions acumulando bad debt en Aave V2, Compound V2 durante 2021-2022"
```

---

## 9. Liquidation During Oracle / Sequencer Downtime

```yaml
- id: liq-009
  titulo: Oracle o sequencer L2 caído impide liquidaciones — bad debt se acumula sin control
  causa_raiz: |
    En L2 (Arbitrum, Optimism, Base), si el sequencer se cae, las transacciones no se
    procesan. Mientras tanto, precios pueden moverse violentamente en L1/CEX. Cuando el
    sequencer vuelve, todas las posiciones que se volvieron underwater durante el downtime
    son liquidables instantáneamente — pero los borrowers no tuvieron oportunidad de
    añadir colateral. Sin grace period, esto es injusto. CON grace period mal implementado,
    los borrowers evitan la liquidación y crean bad debt.
  como_funciona: |
    Escenario A — Sin grace period (unfair liquidation):
    1. Sequencer Arbitrum se cae 2 horas.
    2. ETH cae 20% en L1 durante el downtime.
    3. Sequencer vuelve → oracle actualiza con precio 20% menor.
    4. Cientos de posiciones liquidables instantáneamente.
    5. Borrowers no pudieron añadir colateral → liquidados injustamente.

    Escenario B — Grace period mal implementado:
    1. Sequencer vuelve online. Grace period de 1 hora activado.
    2. Durante grace period, liquidaciones están bloqueadas.
    3. Atacante VE que su posición está underwater.
    4. En vez de añadir colateral, retira lo que puede y deja bad debt.
    5. Cuando grace period termina, solo queda bad debt.

    Escenario C — Aloe (Sherlock):
    1. Protocolo no tiene handling de sequencer down.
    2. Atacante manipula precios mientras sequencer está down (pocos participantes).
    3. Cuando sequencer vuelve, atacante liquida posiciones basándose en precios manipulados.
  invariante: |
    // Grace period check
    if (sequencer.isDown() || block.timestamp < sequencer.lastUptime() + GRACE_PERIOD) {
        // No liquidations allowed
        revert("LIQ-009: sequencer grace period active");
    }

    // Borrowing also paused during grace period
    if (block.timestamp < sequencer.lastUptime() + GRACE_PERIOD) {
        revert("LIQ-009: no borrowing during grace period");
    }
  que_mirar:
    - ¿El protocolo está deployed en L2? ¿Usa sequencer uptime feed de Chainlink?
    - ¿Hay grace period después de que el sequencer vuelve?
    - ¿El grace period también bloquea borrows (no solo liquidaciones)?
    - ¿Qué pasa con interest accrual durante sequencer downtime?
    - ¿El oracle reporta stale prices con sequencer down?
  como_se_arregla: |
    Integrar Chainlink L2 Sequencer Uptime Feed.
    Grace period de 1h después de sequencer restart:
      - Bloquear liquidaciones Y borrows durante grace period.
      - Permitir deposits/repayments (mejorar posiciones).
    Pausar interest accrual durante sequencer downtime (o usar rate cap).
    Aave V3 implementa esto en su versión L2.
  trampas:
    - El grace period debe ser corto (1h max) — demasiado largo permite que borrowers huyan.
    - Bloquear solo liquidaciones sin bloquear borrows permite arbitraje durante grace period.
    - En mainnet L1, este vector no aplica (no hay sequencer).
    - Algunos L2 (zkSync, StarkNet) tienen modelos diferentes de sequencer.
  solodit_ids:
    - "panprog-no-handling-of-l2-sequencer-down-situation-which-can-lead-to-intentional-bad-debt-creation-and-other-malicious-actions-while-sequencer-is-down-or-just-after-it-becomes-active-again-sherlock-2023-10-aloe-judging-issues-55"
    - "roguereddwarf-missing-sequencer-uptime-feed-check-can-cause-unfair-liquidations-on-arbitrum-sherlock-2023-05-perennial-judging-issues-37"
  incidentes:
    - "Aloe (Sherlock oct 2023) — Sin handling de sequencer down, permite bad debt creation intencional post-restart"
    - "Perennial (Sherlock mayo 2023) — Missing sequencer uptime check permite liquidaciones injustas en Arbitrum"
    - "Arbitrum sequencer outage (jun 2023, dic 2023) — Múltiples protocolos afectados por falta de grace period"
```

---

## 10. Multi-Collateral Liquidation Ordering

```yaml
- id: liq-010
  titulo: Orden de seize de colateral en multi-collateral determina si queda bad debt
  causa_raiz: |
    En protocolos que permiten depositar múltiples tipos de colateral (Aave, Compound V3,
    Silo), cuando se liquida una posición, el liquidador puede elegir QUÉ colateral seized.
    Si elige el colateral más líquido/valioso primero, el residual queda con colateral
    ilíquido/volátil que nadie quiere liquidar → bad debt. Si el protocolo no controla
    el orden de liquidación, el liquidador optimiza su profit a costa del protocolo.
  como_funciona: |
    1. Posición con 3 colaterales: $5000 ETH, $3000 stETH, $2000 de token ilíquido.
    2. Deuda total: $8000. HF < 1.0.
    3. Liquidador elige seized = ETH (más líquido, más fácil de vender).
    4. Repaga $5000 de deuda, seize $5000 ETH + bonus.
    5. Residual: deuda=$3000, colateral=$3000 stETH + $2000 token ilíquido.
    6. Segundo liquidador elige stETH. Residual: deuda=$X, colateral=token ilíquido.
    7. Nadie quiere liquidar el token ilíquido → bad debt.

    Variante: protocolo fuerza orden de liquidación pero lo hace
    al revés (colateral ilíquido primero) → liquidadores no participan en absoluto.
  invariante: |
    // Después de liquidación parcial, ratio de colateral líquido debe mantenerse
    uint256 liquidRatioBefore = liquidCollateral[user] * 1e18 / totalCollateral[user];
    liquidate(user, amount, chosenCollateral);
    uint256 liquidRatioAfter = liquidCollateral[user] * 1e18 / totalCollateral[user];
    t(liquidRatioAfter >= liquidRatioBefore - TOLERANCE,
      "LIQ-010: liquidation depleted liquid collateral disproportionately");
  que_mirar:
    - ¿El liquidador elige qué colateral seized o el protocolo determina el orden?
    - ¿Cada tipo de colateral tiene diferente liquidation bonus?
    - ¿Hay colateral ilíquido o exótico aceptado (NFTs, LP tokens, rebasing tokens)?
    - ¿Puede un liquidador depleting el colateral bueno y dejar solo el malo?
    - ¿Se verifica solvencia post-liquidation considerando liquidez residual?
  como_se_arregla: |
    Forzar orden de liquidación: seized proporcional entre todos los colaterales.
    O: forzar liquidación del colateral menos líquido primero (incentiva diversificación).
    Diferentes LTV por tipo de colateral (más bajo para ilíquidos).
    Compound V3 resuelve esto con single-collateral per market.
  trampas:
    - Aave V2/V3 permite al liquidador elegir — es by design, mitigado por diferentes LTV.
    - El riesgo real depende de la composición de colateral en el protocolo.
    - "Colateral ilíquido" es relativo — un token con $1M de liquidez puede ser ilíquido para posiciones de $10M.
  solodit_ids: []
  incidentes:
    - "Aave V2 (nov 2022) — CRV como colateral con baja liquidez; posición masiva de Avi Eisenberg generó $1.6M bad debt porque nadie podía liquidar CRV en volumen"
    - "Iron Bank / Cream Finance — Whitelisted borrowing de tokens ilíquidos sin colateral proporcional"
```

---

## 11. Liquidation Auction Price Manipulation

```yaml
- id: liq-011
  titulo: En sistemas de subasta (MakerDAO, Euler), manipulación del precio de clearing
  causa_raiz: |
    Protocolos que usan subastas para liquidaciones (Dutch auction descendente o English
    auction ascendente) son vulnerables a manipulación del precio final. En Dutch auctions,
    el precio baja con el tiempo — un atacante puede bloquear participantes (DoS, gas war)
    para comprar colateral a precio mínimo. En English auctions (MakerDAO Clip/Flip),
    la falta de competencia permite bids extremadamente bajos.
  como_funciona: |
    Escenario A — Dutch auction (Euler pre-hack, Aave V4):
    1. Liquidación inicia con precio alto (e.g., 110% del debt).
    2. Precio decrece linealmente durante 30 min hasta 80% del debt.
    3. Atacante usa gas war para DoS otros bidders.
    4. Espera hasta que precio sea 85% → compra colateral a 15% de descuento.
    5. Si hay flash loan, todo en una tx.

    Escenario B — English auction (MakerDAO Flip, Black Thursday):
    1. Liquidación abre bid a debt amount.
    2. Periodo de 6h para que bidders suban el precio.
    3. Red congestionada → nadie puede biddar.
    4. Atacante gana con bid = 0 DAI (o muy bajo).
    5. $8.32M de ETH por 0 DAI.

    Escenario C — MakerDAO Liquidations 2.0 (Clip, Dutch auction post-fix):
    1. Precio empieza MUY alto (e.g., 3x oracle price) y baja exponencialmente.
    2. Incentivo: comprar cuando precio = fair market value.
    3. Mitigación: incluso si atacante bloquea, precio nunca baja de cierto floor.
  invariante: |
    // Auction price must be bounded
    t(auction.currentPrice() >= auction.floorPrice(),
      "LIQ-011: auction price below floor");

    // Auction duration must be bounded
    t(block.timestamp - auction.startTime() <= auction.maxDuration(),
      "LIQ-011: auction exceeded max duration");
  que_mirar:
    - ¿Qué tipo de auction usa el protocolo? (Dutch, English, fixed spread)
    - ¿Hay precio mínimo/floor en la auction?
    - ¿Qué pasa si nadie bids? ¿Timeout? ¿Bad debt module?
    - ¿El auction mechanism es resistente a gas wars / mempool manipulation?
    - ¿El precio inicial de la auction está linked al oracle?
  como_se_arregla: |
    Dutch auction con exponential decay y floor price (MakerDAO Clip).
    Precio inicial = X * oraclePrice (donde X = 1.5-3x para dar margen).
    Floor price = debtAmount (nunca vender colateral por menos de la deuda).
    Timeout: si nadie bids en T tiempo, socializar bad debt vía insurance fund.
    Aave V4 usa "gradual Dutch auction" con soft liquidation.
  trampas:
    - Dutch auctions son generalmente más MEV-resistant que English auctions.
    - MakerDAO ya migró de Flip (English) a Clip (Dutch) post-Black Thursday.
    - El "floor price" puede crear deadlock si colateral vale menos que deuda.
    - Euler V2 usa "linear liquidation bonus" en vez de auction — más predecible.
  solodit_ids: []
  incidentes:
    - "MakerDAO Black Thursday (marzo 2020) — English auction sin floor, $8.32M seized a bid=0 DAI"
    - "MakerDAO Liquidations 2.0 (Clip) — Dutch auction con exponential decay como fix post-Black Thursday"
    - "Euler V1 (pre-hack) — Dutch auction con bug en donateToReserves bypass → explotado para $197M"
```

---

## 12. Grace Period / Delay Exploitation

```yaml
- id: liq-012
  titulo: Explotación del periodo de gracia entre estado underwater y elegibilidad de liquidación
  causa_raiz: |
    Algunos protocolos implementan un "grace period" entre cuando una posición se vuelve
    unhealthy y cuando puede ser liquidada. La intención es dar tiempo al borrower para
    reaccionar. Pero un atacante puede usar este periodo para: (1) retirar más colateral,
    (2) abrir nuevas posiciones, (3) explotar el delta entre precio actual y precio
    al final del grace period. Si el grace period no restringe ciertas operaciones,
    el borrower puede empeorar su posición deliberadamente.
  como_funciona: |
    1. Posición se vuelve unhealthy (HF = 0.99) por caída de precio.
    2. Grace period de 1 hora activado — liquidaciones bloqueadas.
    3. En vez de añadir colateral, borrower retira activos del protocolo.
    4. O: borrower abre posiciones apalancadas en otro protocolo usando los borrowed funds.
    5. Grace period termina. Posición ahora tiene HF = 0.5 (mucho peor).
    6. Liquidación genera bad debt masivo que no existía al inicio del grace period.

    Variante (CAP Protocol, Sherlock):
    1. Liquidator puede resetear liquidationStart_agent a 0 vía partial liquidation.
    2. Esto reinicia el grace period → posición permanece unliquidatable indefinidamente.
  invariante: |
    // Durante grace period, solo deposit/repay permitidos
    if (isInGracePeriod(user)) {
        t(!isWithdrawal(operation) && !isBorrow(operation),
          "LIQ-012: withdrawal/borrow during grace period");
    }

    // Grace period no debe ser reseteable
    uint256 gpStart = gracePeriodStart[user];
    partialLiquidate(user, smallAmount);
    t(gracePeriodStart[user] == gpStart,
      "LIQ-012: grace period was reset by partial liquidation");
  que_mirar:
    - ¿Qué operaciones están permitidas durante el grace period?
    - ¿Puede el borrower retirar colateral o borrowear más durante grace period?
    - ¿El grace period es reseteable por alguna operación?
    - ¿El interest accrual continúa durante el grace period?
    - ¿Hay un max duration para el grace period?
  como_se_arregla: |
    Durante grace period: bloquear withdrawals y borrows, permitir solo deposits y repays.
    Grace period no reseteable por partial operations.
    Max duration: grace period expira después de T tiempo, sin extensiones.
    Si posición empeora durante grace period, liquidación inmediata permitida.
  trampas:
    - Grace period es un trade-off: protege borrowers pero puede crear riesgo sistémico.
    - No todos los protocolos necesitan grace period (Aave L1 no tiene).
    - El grace period de Aave en L2 es específicamente para sequencer downtime.
    - Protocolos con governance-set grace period pueden tener values extremos.
  solodit_ids:
    - "m-1-attackerpartial-liquidator-can-extend-liquidation-action-by-resetting-liquidationstart_agent-to-0-sherlock-cap-git"
  incidentes:
    - "CAP Protocol (Sherlock) — Partial liquidator resetea liquidationStart_agent a 0, extendiendo acción de liquidación indefinidamente"
```

---

## 13. Interest Accrual During Liquidation

```yaml
- id: liq-013
  titulo: Interés acumulado entre health check y ejecución de liquidación cambia accounting
  causa_raiz: |
    En protocolos de lending, el interest accrues continuamente. Si la función liquidate()
    primero verifica health factor y luego ejecuta la liquidación en pasos separados
    (o en un bloque diferente), el interés acumulado entre ambos pasos puede cambiar
    la deuda lo suficiente como para alterar el resultado. Peor aún: si liquidate()
    NO llama accrueInterest() primero, usa datos stale para calcular seized amount.
  como_funciona: |
    Escenario A — Interest no accrued antes de liquidation:
    1. Last accrual fue hace 1 hora. Interest rate = 10%/año.
    2. Deuda "almacenada" = $10,000. Deuda real (con interest) = $10,011.
    3. Liquidador llama liquidate() que NO accrua primero.
    4. Health factor calculado con deuda vieja ($10,000) → HF parece más alto.
    5. Si HF > 1.0 con deuda vieja, posición no es liquidable aunque sí lo es realmente.

    Escenario B — Interest accrual entre steps (MakerDAO):
    1. Stability fee accrued entre bite() y tend()/dent() en auction.
    2. El tab (deuda total) cambia durante la auction.
    3. Bidder calcula bid basado en tab al inicio, pero tab real es mayor.
    4. Auction economics se desestabilizan.

    Escenario C — Evoq (Spearbit):
    1. Cached borrow index usado en liquidation logic.
    2. Index no se actualiza antes de liquidar → discrepancia con pool real.
    3. Liquidador repaga cantidad incorrecta de deuda.
  invariante: |
    // Interest MUST be accrued before any liquidation
    uint256 debtBefore = userDebt[account]; // stale
    accrueInterest();
    uint256 debtAfter = userDebt[account]; // fresh
    t(debtAfter >= debtBefore,
      "LIQ-013: interest accrual reduced debt (impossible)");

    // Health factor must use fresh debt
    uint256 hf = calculateHealthFactor(account); // uses debtAfter
    if (hf >= 1e18) revert("not liquidatable with fresh interest");
  que_mirar:
    - ¿liquidate() llama accrueInterest() como primer paso?
    - ¿Hay funciones de liquidación que usen cached interest indexes?
    - ¿El interest rate model se actualiza ANTES de calcular health factor?
    - ¿En auction-based liquidation, se actualiza la deuda durante la auction?
    - ¿La función isLiquidatable() usa la misma lógica que liquidate()?
  como_se_arregla: |
    Modifier o primer call: accrueInterest() antes de CUALQUIER operación en liquidate().
    Snapshot deuda al momento de iniciar liquidación (para auctions).
    Usar indexes actualizados, nunca cached, en cálculos de liquidación.
    Verificar consistencia: isLiquidatable() y liquidate() deben usar el mismo state.
  trampas:
    - El interest de 1 hora suele ser < $1 en posiciones normales — edge case para posiciones masivas.
    - En protocolos con rates muy altos (perps, stablecoins), el impacto puede ser significativo.
    - No confundir "interest not accrued" con "interest accrued pero no reflejado en UI".
  solodit_ids:
    - "0xarno-attacker-can-manipulate-interest-distribution-by-exploiting-asset-transfers-and-fee-accrual-mechanism-sherlock-2024-08-sentiment-v2-judging-issues-541"
  incidentes:
    - "Sentiment V2 (Sherlock ago 2024) — Atacante manipula distribución de interés explotando mecanismo de accrual durante liquidación"
    - "Evoq (Spearbit) — Cached borrow index en liquidation logic causa discrepancia con pool subyacente"
    - "ZeroLend One (Sherlock) — Interest rate updated BEFORE debt updated when repaying — afecta liquidaciones subsecuentes"
    - "Roots (audit) — Stale totalActiveDebt cached antes de _accrueActiveInterests en operaciones de liquidación"
```

---

## 14. Liquidation of Staked / Locked Positions (NFT Collateral in Gauges)

```yaml
- id: liq-014
  titulo: Posición NFT stakeada en gauge no puede liquidarse — colateral inaccesible
  causa_raiz: |
    En protocolos como Revert Lend, el colateral es un NFT (Uniswap V3 LP position) que
    puede estar stakeado en un gauge (e.g., Aerodrome) para ganar rewards. Cuando la posición
    se vuelve liquidable, el vault necesita acceder al NFT para transferirlo al liquidador.
    Si el NFT está stakeado en un gauge, la liquidación puede fallar porque:
    (1) el vault no puede unstake del gauge, (2) el unstake revierte por lógica del gauge,
    (3) las fees/rewards no se contabilizan durante la liquidación.

    Caso real VV-O-02: en Revert Lend, cuando una posición stakeada se liquida, el
    feeValue se calcula como 0 porque las fees están en el gauge, no en el NFT.
    El liquidador recibe las fees sin pagar por ellas.
  como_funciona: |
    Escenario A — VV-O-02 (Revert Lend, staked liquidation fee theft):
    1. Usuario stakea su Uniswap V3 NFT en Aerodrome gauge via GaugeManager.
    2. Posición acumula trading fees (e.g., $500 de fees en la posición).
    3. Posición se vuelve liquidable (precio cae).
    4. Liquidador llama liquidate() en V3Vault.
    5. V3Vault calcula feeValue = fees en el NFT = 0 (fees están en el gauge).
    6. fullValue = positionValue + feeValue. Pero feeValue = 0.
    7. Liquidador paga menos, pero al hacer unstake, recibe las fees.
    8. Las fees ($500) fueron robadas del borrower por el liquidador.

    Escenario B — Gauge DoS:
    1. Posición stakeada en gauge malicioso o pausado.
    2. liquidate() intenta unstake del gauge → reverts.
    3. Posición es unliquidatable → bad debt acumula.
  invariante: |
    // Fees deben incluirse en fullValue durante liquidación
    (uint256 fullValue, uint256 feeValue, , ) = _getFullValue(tokenId);
    // feeValue debe incluir fees en gauge, no solo fees en NFT
    t(feeValue >= accruedFeesInGauge[tokenId],
      "LIQ-014: feeValue ignores gauge-accrued fees");

    // Liquidación de posición stakeada siempre debe ser posible
    bool wasStaked = isStaked(tokenId);
    liquidate(params);
    // Si estaba stakeada, debe haberse unstakedado
    t(!isStaked(tokenId),
      "LIQ-014: position still staked after liquidation");
  que_mirar:
    - ¿El protocolo permite staking de colateral NFT en gauges/farms?
    - ¿liquidate() maneja el unstake del gauge correctamente?
    - ¿Las fees acumuladas en el gauge se incluyen en la valoración durante liquidación?
    - ¿gauge.withdraw() puede revertir? ¿Hay try/catch?
    - ¿El gauge tiene una función de emergency withdraw?
    - ¿compoundRewards() puede ser llamado sin health check?
  como_se_arregla: |
    Incluir fees del gauge en feeValue durante cálculo de liquidación.
    try/catch en gauge.withdraw() con fallback a emergency withdraw.
    Si unstake falla, marcar posición para liquidación manual por governance.
    Verificar health DESPUÉS de cualquier operación de compound/restake.
  trampas:
    - El NFT como colateral es inherentemente más complejo que tokens ERC20.
    - Las fees en el gauge pueden cambiar entre health check y liquidation execution.
    - No todos los gauges implementan emergency withdraw.
    - En Revert Lend, el GaugeManager actúa como intermediario — la lógica de unstake es indirecta.
  solodit_ids: []
  incidentes:
    - "Revert Lend VV-O-02+VV-O-05 (Cantina 2024) — Liquidación de posición stakeada con feeValue=0; liquidador roba fees del borrower (High)"
    - "Revert Lend GM-A-08 — gauge.withdraw() sin try/catch; gauge malicioso puede hacer DoS de liquidación"
    - "Revert Lend GM-D-03 — setGauge no migra tokenIdToGauge; posiciones permanentemente bloqueadas en gauge antiguo"
```

---

## 15. Donation / Reserve Manipulation to Force Liquidations

```yaml
- id: liq-015
  titulo: Donación directa a contrato manipula exchange rate y fuerza liquidaciones
  causa_raiz: |
    En protocolos que calculan el valor del colateral usando un exchange rate interno
    (totalAssets / totalSupply), un atacante puede donar tokens directamente al contrato
    (sin usar deposit()) para inflar el exchange rate. Esto puede hacer que posiciones
    que usaban el token como DEUDA se vuelvan liquidables (su deuda vale más) o que
    posiciones que usaban el token como colateral parezcan más sanas de lo que son.
    El caso más extremo: Euler Finance, donde donateToReserves() eliminaba eTokens
    sin health check → creaba bad debt artificial.
  como_funciona: |
    Escenario Euler (el hack de $197M):
    1. Atacante flash loan 30M DAI → deposita en Euler → recibe 19.5M eDAI.
    2. Usa mint() para auto-borrowear: 195.6M eDAI, 200M dDAI (10x leverage permitido).
    3. Llama donateToReserves(100M eDAI) → transfiere eTokens a reservas SIN health check.
    4. Posición ahora: 95.6M eDAI colateral vs 200M dDAI deuda → masivamente underwater.
    5. Pero esto era intencional: el atacante liquida su PROPIA posición desde otra cuenta.
    6. Liquidation bonus sobre posición artificial → extrae fondos del pool.
    7. Repite para múltiples pools → $197M total.

    La vulnerabilidad core: donateToReserves() no verificaba que la posición
    del donante quedara healthy después de la donación.
  invariante: |
    // Después de CUALQUIER operación que reduce colateral, health check
    function donateToReserves(uint256 amount) external {
        // ... transfer logic ...
        require(checkHealth(msg.sender), "LIQ-015: donation made position unhealthy");
    }

    // Exchange rate no debe cambiar más de X% en una tx
    uint256 rateBefore = totalAssets() * 1e18 / totalSupply();
    operation();
    uint256 rateAfter = totalAssets() * 1e18 / totalSupply();
    t(rateAfter * 100 / rateBefore > 90 && rateAfter * 100 / rateBefore < 110,
      "LIQ-015: exchange rate moved >10% in single tx");
  que_mirar:
    - ¿Hay funciones que reduzcan colateral/shares sin health check? (donate, burn, transfer)
    - ¿Se puede enviar tokens directamente al contrato (via transfer) para cambiar exchange rate?
    - ¿El protocolo permite self-collateralization (usar borrowed tokens como colateral)?
    - ¿Hay funciones admin que muevan fondos sin verificar solvencia de posiciones?
    - ¿donateToReserves(), sweep(), skim() tienen health checks?
  como_se_arregla: |
    Health check después de TODA operación que reduce colateral del usuario.
    Prohibir self-collateralization (no permitir borrowear token X contra token X).
    Rate limiter en cambios de exchange rate (max X% por bloque).
    Virtual accounting: no usar balance real del contrato, usar variable interna.
  trampas:
    - Euler fue auditado múltiples veces — el bug estaba en una función "inocua" (donate).
    - El self-collateralization era un FEATURE de Euler, no un bug — pero habilitó el exploit.
    - Donation attacks son diferentes de first-depositor inflation attacks (ver vault-erc4626.md).
    - El fix real fue agregar health check en donateToReserves — una línea de código.
  solodit_ids: []
  incidentes:
    - "Euler Finance (marzo 2023) — donateToReserves() sin health check + self-collateralization + 10x leverage = $197M hack"
    - "Cream Finance (oct 2021) — Donación directa de 4pool tokens a yUSD vault infló exchange rate, $136M robados"
    - "Salty (C4 ene 2024) — Attacker puede hacer liquidation revert para forzar bad debt en protocolo"
```
