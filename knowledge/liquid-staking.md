# Liquid Staking Tokens (LST) — Bug Patterns

## Quick Reference

```
grep_targets:
  - stETH
  - wstETH
  - rETH
  - sfrxETH
  - frxETH
  - cbETH
  - getSharesByPooledEth
  - getPooledEthByShares
  - exchangeRate
  - getExchangeRate
  - convertToAssets
  - submitWithdrawals
  - requestWithdrawals
  - claimWithdrawals
  - unstakeRequest
  - WithdrawalQueue
  - slashing
  - validatorBalance
  - totalPooledEther
  - totalShares
  - IStETH
  - IRocketPool
  - ILido
  - stakingRewards
  - rewardRate
  - getRate
  - getLSTRate
```

---

## 1. stETH/wstETH ~1:1 Peg Assumption

```yaml
- id: lst-001
  titulo: stETH/ETH asumido en 1:1 — slippage, slashing o depeg no contemplados
  causa_raiz: |
    Protocolos que aceptan stETH como colateral o como base de cálculo asumen que
    1 stETH ≈ 1 ETH. En situaciones de slashing masivo, problemas de liquidez en Curve,
    o eventos de mercado extremos, stETH puede tradearse con descuento significativo
    (2-5% en condiciones normales de mercado, hasta 30%+ en eventos de crisis).
    El protocolo sobrevalora el colateral → puede estar bajo-colateralizado.
  como_funciona: |
    1. Protocolo acepta stETH como colateral a ratio 1:1 con ETH.
    2. Evento de slashing masivo: stETH se depegs a 0.92 ETH.
    3. Colateral vale 8% menos de lo asumido → posiciones antes "sanas" son insolventes.
    4. Liquidadores no pueden cubrir la deuda → bad debt acumula.
    Ejemplo Asymmetry Finance: wstETH deposit assumes ~1=1 peg → arbitrage exploit.
  invariante: |
    // Siempre usar oracle de precio para stETH, no asumir 1:1
    uint256 ethValue = stETHAmount * stETH_ETH_price / 1e18;
    // Usar Chainlink stETH/ETH feed o TWAP de Curve stETH pool
  que_mirar:
    - Colateral valued as: stETHAmount (sin conversión a ETH via oracle)
    - Código que asume stETH.balanceOf == ETH value
    - Pools de liquidez que usan stETH como si fuera ETH sin slippage adjustment
    - Protocolos que prestan ETH contra stETH sin buffer de depeg
  como_se_arregla: |
    Usar Chainlink stETH/ETH price feed (corazón ~24h, threshold 0.5%).
    Añadir buffer de depeg (e.g., LTV máximo 75% en vez de 95% para stETH).
    TWAP de Curve stETH/ETH pool como alternativa on-chain.
  trampas:
    - wstETH SÍ fluctúa en precio contra ETH — usar wstETH/ETH Chainlink feed, no 1:1.
    - En condiciones normales el depeg es mínimo (<0.5%) — el riesgo es tail risk.
    - Algunos protocolos aceptan wstETH como WETH-equivalent intencionalmente (documentado).
  solodit_ids:
    - "m-14-stetheth-feed-being-used-opens-up-to-2-way-deposit-withdrawal-arbitrage-code4rena-renzo-renzo-git"
    - "m-05-risk-of-overborrowing-by-only-using-price-rate-feed-recon-audits-none-quill-finance-report-markdown"
    - "m-1-lack-of-on-chain-deviation-check-for-lst-can-lead-to-loss-of-assets-sherlock-usual-eth0-git"
  incidentes:
    - "Renzo (C4) — stETH/ETH es market rate feed (no exchange rate), abre arbitraje bidireccional en ezETH"
    - "Quill Finance (ReconAudits) — price * rate compuesto de dos feeds con heartbeats distintos → overborrowing"
    - "Usual ETH0 (Sherlock) — sin verificación on-chain de desviación del LST, pérdida de activos si depeg"
```

---

## 2. LST Exchange Rate Manipulation

```yaml
- id: lst-002
  titulo: LST exchange rate manipulable o leído desde fuente insegura
  causa_raiz: |
    El exchange rate de LSTs (wstETH → ETH, rETH → ETH, sfrxETH → frxETH) se calcula
    on-chain mediante funciones del propio contrato LST. Si un protocolo lee este rate
    en el mismo bloque donde ocurre una transacción grande (o si el rate se puede
    manipular via donation/rebase), el protocolo puede ser engañado sobre el valor real.
  como_funciona: |
    1. Protocolo llama wstETH.stEthPerToken() para valorar colateral.
    2. Atacante manipula el Lido oracle (si es posible) o usa rate en punto extremo.
    3. Colateral sobrevaluado → borrow más de lo permitido.
    Riesgo más práctico: Chainlink wstETH/ETH feed usada incorrectamente (stETH/ETH × wstETH/stETH)
    → errores de composición si las feeds tienen diferentes heartbeats.
  invariante: |
    // Siempre usar Chainlink directamente para wstETH/ETH, no componer feeds:
    // MAL: chainlink_stETH_USD * wstETH.stEthPerToken()  (heartbeats distintos)
    // BIEN: chainlink_wstETH_USD directa (una sola feed)
  que_mirar:
    - Composición de múltiples Chainlink feeds para derivar el precio de un LST
    - Uso de wstETH.getStETHByWstETH() o rETH.getExchangeRate() como precio directo
    - Oracle que no tiene staleness check (latestRoundData sin validar timestamp)
    - Precio calculado con TWAP muy corto (<30 min) en un LST pool con poca liquidez
  como_se_arregla: |
    Usar feeds Chainlink dedicadas por LST: wstETH/USD, rETH/USD, cbETH/USD.
    Validar freshness: require(block.timestamp - updatedAt < STALE_THRESHOLD).
    Si se componen feeds, asegurar que ambas tienen el mismo heartbeat y threshold.
  trampas:
    - El exchange rate de wstETH onchain (stEthPerToken) es difícil de manipular en mainnet.
    - El riesgo principal es feeds Chainlink stale o composición incorrecta, no manipulación directa.
    - En L2 (Arbitrum, Optimism), el secuenciador puede caer y dejar las feeds stale.
  solodit_ids:
    - "h-4-victims-fund-can-be-stolen-due-to-rounding-error-and-exchange-rate-manipulation-sherlock-napier-git"
    - "exchangerate-can-be-manipulated-leading-to-inflation-attack-cantina-none-opalprotocol-pdf"
    - "h-3-early-depositors-to-bufferbinarypool-can-manipulate-exchange-rates-to-steal-funds-from-later-depositors-sherlock-buffer-finance-buffer-finance-git"
  incidentes:
    - "Napier (Sherlock) — rounding + exchange rate manipulation combinados → robo de fondos de víctimas"
    - "OpalProtocol (Cantina) — Omnipool._exchangeRate manipulable durante deposit → inflation attack clásico"
    - "Buffer Finance (Sherlock) — primer depositor dona tokens para inflar totalTokenXBal/totalSupply ratio"
```

---

## 3. Withdrawal Queue — DoS y Fondos Bloqueados

```yaml
- id: lst-003
  titulo: Withdrawal queue de LST puede bloquearse o desincronizarse
  causa_raiz: |
    Los protocolos de LST (Lido, RocketPool, EigenLayer, etc.) tienen withdrawal queues
    con latencia. Si un protocolo integrado asume que los retiros son instantáneos, o si
    la queue puede llenarse/desbordarse, los fondos quedan bloqueados durante el periodo
    de espera (days-weeks). Un atacante puede explotar esto para DoS o para forzar
    liquidaciones durante el lock period.
  como_funciona: |
    Escenario DoS: Protocolo hace unstake cuando usuario retira → si queue está llena,
    el retiro falla → usuario atascado.
    Escenario accounting: Queue tiene claim pendiente de epoch N. Nuevo epoch N+1 llega
    con nuevo exchange rate. El claim de N se aplica con rate de N+1 → accounting error.
    Escenario whale DoS (WinWin, Solodit #): gran retiro bloquea la queue para todos.
  invariante: |
    // El protocolo no debe asumir retiros instantáneos de LSTs con withdrawal queues.
    // Siempre separar "retiro iniciado" de "fondos disponibles":
    pendingWithdrawal[user] = true;
    withdrawalAmount[requestId] = amount;
    // Reclamar en tx separada cuando la queue lo permite
  que_mirar:
    - Integración con Lido requestWithdrawals() / claimWithdrawals() sin manejo de latencia
    - Asunción de que el unstake es atómico (una sola tx)
    - Fondos en queue no incluidos en totalAssets() del vault
    - Race condition entre epoch change y claim de withdrawal
  como_se_arregla: |
    Tratar withdrawals de LST como asíncronos: almacenar el requestId, procesar en dos txs.
    Incluir fondos en queue en totalAssets() (marcados como "pending").
    Timeouts para requests no reclamados (para evitar DoS permanente).
  trampas:
    - Lido V2 tiene withdrawal queue con latencia variable (1-5 días normalmente).
    - EigenLayer tiene withdrawal delay de ~7 días (configurable por operador).
    - El exchange rate al momento del claim puede diferir del momento del request.
  solodit_ids:
    - "liquidity-withdrawal-can-be-blocked-consensys-bridge-mutual-markdown"
    - "whale-withdrawals-can-get-the-hexstrategy-contract-into-a-dos-state-halborn-winwin-winwin-protocol-markdown"
    - "users-funds-are-locked-temporarily-in-the-prioritypool-contract-cyfrin-none-cyfrin-stake-link-markdown"
    - "updatewithdrawalqueue-can-run-out-of-gas-fixed-consensys-bridge-mutual-markdown"
  incidentes:
    - "Bridge Mutual (Consensys) — LP puede quedar bloqueado permanentemente bajo condiciones de liquidez"
    - "WinWin Protocol (Halborn) — whale withdrawal pone HEXStrategy en DOS; FIFO queue sin límite de gas"
    - "Stake Link (Cyfrin) — fondos bloqueados en PriorityPool cuando hay cola sin suficiente liquidez"
    - "Bridge Mutual (Consensys) — _updateWithdrawalQueue unbounded loop → gas limit → protocolo bloqueado"
```

---

## 4. Slashing — Colateral LST No Contempla Reducción por Slashing

```yaml
- id: lst-004
  titulo: Slashing de validadores reduce el valor real del LST sin actualización inmediata
  causa_raiz: |
    Los LSTs representan ETH stakeado en validadores. Si un validador es slashed, el
    balance del validador se reduce → el exchange rate del LST baja. Este ajuste puede
    tardar horas/días en reflejarse en el oracle. Durante ese lag, el protocolo valora
    el LST con el rate pre-slashing → colateral sobrevaluado → posibles préstamos
    por encima del valor real.
  como_funciona: |
    1. Gran evento de slashing en Ethereum (e.g., bugs en cliente, MEV mal configurado).
    2. Exchange rate de rETH baja 0.5% por slashing.
    3. Chainlink oracle no ha actualizado (heartbeat = 24h, desviación = 0.5% → sin update).
    4. Protocolo de lending valora rETH con el precio antiguo (0.5% más alto).
    5. Borrowers que estaban al límite de LTV ahora están efectivamente under-collateralized.
    6. Liquidadores tampoco pueden actuar durante el lag → acumula bad debt.
  invariante: |
    // Añadir buffer de seguridad para eventos de slashing:
    uint256 maxLTV_LST = 70;  // en vez de 80+ — buffer para slashing + depeg
    // Verificar que el oracle tiene heartbeat adecuado para eventos de slashing
  que_mirar:
    - LTV (Loan-to-Value) máximo para LSTs sin buffer de slashing
    - Oracle heartbeat > 1h para LSTs (slashing puede afectar rápido)
    - Protocolos que asumen el exchange rate del LST es siempre mayor o igual al anterior
    - No hay liquidation buffer adicional para LSTs vs ETH nativo
  como_se_arregla: |
    Usar LTV conservador para LSTs: max 70-75% (vs 80-85% para ETH).
    Circuit breaker: si exchange rate cae >X% en una sola actualización → pause.
    Oracle con threshold bajo (0.1-0.2%) para capturar slashing más rápido.
  trampas:
    - El slashing individual de validadores es pequeño (max 1-2 ETH por validador).
    - Slashing masivo coordinado sería necesario para impacto significativo en el rate.
    - La mayoría de LSTs tienen seguros o coberturas de slashing integradas.
  solodit_ids:
    - "m-7-if-slash-validator-occurs-unstaking_queues-unstake-amount-will-not-be-accurate-sherlock-andromeda-validator-staking-ado-and-vesting-ado-git"
    - "m-01-eth_price_fallback_2-review-recon-audits-none-bold-report-markdown"
    - "h-08-staking-unstaking-and-rebalancetoweight-can-be-sandwiched-mainly-reth-deposit-code4rena-asymmetry-finance-asymmetry-contest-git"
  incidentes:
    - "Andromeda Validator Staking (Sherlock) — slashing cambia .balance pero queue guardó .initial_balance → usuarios reciben de más"
    - "Bold Report (ReconAudits) — RETHPriceFeed.sol fallback usa min(market,canonical) pero redemption fee < oracle drift → arbitraje"
    - "Asymmetry Finance (C4) — rETH deposit vía Uniswap pool sandwicheable durante rebalanceToWeight"
```

---

## 5. Reentrancy en Callbacks LST

```yaml
- id: lst-005
  titulo: Reentrancy a través de callbacks de LST (staking/unstaking con hooks externos)
  causa_raiz: |
    Algunos protocolos LST o integraciones emiten callbacks durante el stake/unstake
    (e.g., notificaciones a otros contratos del ecosistema). Si el protocolo integrado
    no protege contra reentrancy y el callback llega en mitad de un cambio de estado,
    un atacante puede re-entrar y explotar el estado intermedio.
  como_funciona: |
    1. Protocolo llama stakeProtocol.stake(amount) → stakeProtocol emite callback al caller.
    2. Caller procesa callback antes de actualizar su propio estado (CEI violado).
    3. Atacante que controla un hook puede re-llamar al protocolo con estado inconsistente.
    4. Resultado: double-claim de rewards o manipulación de balance.
  invariante: |
    // Patrón CEI + nonReentrant para cualquier función que llame a LST contracts
    function stakeAndReward() external nonReentrant {
        rewards[msg.sender] = 0;  // PRIMERO actualizar estado
        lst.stake(amount);        // DESPUÉS la llamada externa
    }
  que_mirar:
    - Funciones que llaman a LST contracts sin nonReentrant
    - Estado actualizado DESPUÉS de la llamada al LST (CEI violado)
    - Sistemas de LST con callbacks/hooks configurables
    - Protocolos multi-LST donde un LST puede ser malicioso
  como_se_arregla: |
    Aplicar patrón CEI estricto: actualizar todos los balances antes de llamadas externas.
    Añadir nonReentrant a funciones de stake/unstake/claim.
  trampas:
    - Lido stETH no tiene callbacks — el riesgo es bajo en integraciones directas con Lido.
    - EigenLayer sí tiene callbacks más complejos (operator hooks) — mayor superficie.
  solodit_ids:
    - "process-the-same-withdrawal-request-quantstamp-stakestone-vault-markdown"
  incidentes:
    - "StakeStone Vault (Quantstamp) — processWithdrawals() sin reentrancy guard, mismo withdrawal procesado 2 veces"
    - "Lybra Finance — reentrancy risks con external liquid staking calls"
    - "Stakehouse Protocol — reentrancy en distributeETHRewards"
```

---

## 6. Falsa Suposición de Monotonía del Exchange Rate

```yaml
- id: lst-006
  titulo: Protocolo asume que el exchange rate de LST sólo sube — nunca baja
  causa_raiz: |
    Los exchange rates de LSTs normalmente suben con el tiempo (yield de staking).
    Algunos contratos asumen esto explícitamente: if (newRate < oldRate) revert().
    Pero slashing, bugs del LST, o eventos de mercado pueden hacer que el rate baje.
    El revert bloquea toda actualización del oracle → el protocolo queda frozen con un
    rate stale (sobrevaluado) → bad debt potencial.
  como_funciona: |
    1. Contrato tiene: require(newRate >= lastRate, "rate decreased").
    2. Slashing reduce el rate de rETH 0.01%.
    3. Oracle intenta actualizar → revierte por la check.
    4. El protocolo queda con el rate del pre-slashing durante días.
    5. Durante ese tiempo, todos los préstamos están usando un precio inflado.
  invariante: |
    // NO asumir monotonía del exchange rate:
    // MAL: require(newRate >= lastRate);
    // BIEN: permitir bajadas pero añadir circuit breaker para bajadas grandes:
    require(newRate >= lastRate * 995 / 1000, "rate dropped > 0.5% — check slashing");
  que_mirar:
    - require(newRate >= previousRate) o assert(exchangeRate > lastExchangeRate)
    - Logic que asume que el LST siempre "vale más" con el tiempo
    - Oracle updates que pueden stuckearse si el rate baja mínimamente
    - Cálculos de profit/loss que no contemplan pérdida de rate
  como_se_arregla: |
    Permitir bajadas del rate pero con circuit breaker para bajadas grandes (>0.5%).
    Separar "oracle update logic" de "monotonía assumption".
    Documentar explícitamente que el protocolo acepta riesgo de slashing.
  trampas:
    - En la práctica los rates de mainnet LSTs casi nunca bajan.
    - El verdadero riesgo es el freeze del oracle, no el slashing per se.
  solodit_ids: []
  incidentes:
    - "Multiple Sherlock findings — protocol frozen when LST rate decreases due to revert"
    - "Rocketpool integrations — rETH rate assumed monotonic breaks during validator incident"
```

---

## 7. Stale LST Price en L2 (Sequencer Down)

```yaml
- id: lst-007
  titulo: Oracle LST en L2 sin sequencer uptime check — precio stale durante downtime
  causa_raiz: |
    En L2 (Arbitrum, Optimism, Base), los Chainlink oracles se actualizan sólo cuando
    el sequencer está activo. Si el sequencer cae, el precio queda stale hasta que vuelva.
    Protocolos de lending en L2 que usan LSTs como colateral sin verificar el sequencer
    status pueden tener precios desactualizados días → liquidaciones incorrectas o
    imposibilidad de liquidar posiciones malas.
  como_funciona: |
    1. Sequencer de Arbitrum cae por 4 horas.
    2. ETH/USD precio en mercado real cambia ±15% durante el downtime.
    3. Chainlink oracle en Arbitrum no actualiza.
    4. Protocolo de lending opera con precio de hace 4h → wrong liquidations.
    5. Cuando sequencer vuelve, si precio cayó mucho: las posiciones que deberían
       haber sido liquidadas no lo fueron → bad debt.
  invariante: |
    // Siempre verificar sequencer antes de usar feeds en L2:
    (, int256 answer,, uint256 updatedAt,) = sequencerFeed.latestRoundData();
    require(answer == 0, "sequencer down");  // 0=up, 1=down
    require(block.timestamp - updatedAt > GRACE_PERIOD, "grace period not elapsed");
  que_mirar:
    - Protocolos en Arbitrum/Optimism/Base sin check de sequencer uptime
    - Uso de Chainlink feeds en L2 para LSTs sin latestRoundData timestamp validation
    - Falta de circuit breaker cuando el oracle no ha actualizado en > N horas
    - Liquidations enabled durante posible sequencer-down period
  como_se_arregla: |
    Integrar Chainlink Sequencer Uptime Feed (disponible en Arbitrum, Optimism, Base).
    Añadir pausa automática de liquidaciones si oracle stale > GRACE_PERIOD.
    Usar TWAP on-chain (Uniswap V3) como fallback cuando el sequencer esté down.
  trampas:
    - En mainnet no existe este riesgo (no hay sequencer).
    - El riesgo es más alto en nuevas L2s con menos uptime histórico.
    - Algunos protocolos tienen governance pause como fallback — reduce pero no elimina el riesgo.
  solodit_ids:
    - "m-1-lack-of-on-chain-deviation-check-for-lst-can-lead-to-loss-of-assets-sherlock-usual-eth0-git"
    - "m-7-if-slash-validator-occurs-unstaking_queues-unstake-amount-will-not-be-accurate-sherlock-andromeda-validator-staking-ado-and-vesting-ado-git"
  incidentes:
    - "Usual ETH0 (Sherlock) — sin check de desviación on-chain del LST en L2, precio stale durante sequencer down"
    - "Multiple Sherlock L2 findings — liquidation DoS during Arbitrum sequencer downtime"
```

---

## 8. LST Donation Attack — Inflate Exchange Rate

```yaml
- id: lst-008
  titulo: Donación directa al LST vault infla el exchange rate → shares sobrevaluadas
  causa_raiz: |
    Algunos LST wrappers o vault tokens calculan su exchange rate como
    totalAssets / totalShares. Si un atacante dona tokens directamente (sin mint de shares),
    el rate sube artificialmente. Protocolos que usan este rate para valorar colateral
    o calcular rewards pueden ser engañados.
  como_funciona: |
    1. LST vault: rate = totalAssets / totalShares = 1.0
    2. Atacante dona 1000 ETH directamente al vault (sin depositar).
    3. totalAssets aumenta, totalShares sin cambio → rate = 1.5
    4. Protocolo de lending valora las shares del atacante un 50% más.
    5. Atacante toma prestado usando las shares infladas como colateral → drain.
  invariante: |
    // Para LSTs externos, NO usar getRate() directamente si puede ser manipulado:
    // Usar TWAPed rate o rate con circuit breaker de variación máxima por bloque
    require(abs(newRate - lastRate) < MAX_RATE_CHANGE_PER_BLOCK, "rate manipulation");
  que_mirar:
    - Vault LST cuyo rate se basa en balanceOf() sin protección contra donaciones
    - Protocolos que confían en rates de LSTs de terceros sin validación adicional
    - Falta de MAX_RATE_CHANGE guard en oracle de LST
    - Rate calculado como balance/supply sin accounting separado
  como_se_arregla: |
    Añadir MAX_RATE_CHANGE_PER_BLOCK o usar rate smoothing (TWAP del rate).
    Usar virtual shares (como OZ ERC4626 con decimalsOffset) para resistir donaciones.
    Para LSTs de terceros: requerir que el oracle tenga heartbeat y threshold estrictos.
  trampas:
    - Los LSTs grandes (Lido, RocketPool) son difíciles de manipular — demasiado TVL.
    - El riesgo es más real en LSTs pequeños o nuevos con poco TVL.
    - Algunos protocolos tienen caps de LTV muy conservadores que hacen el ataque no rentable.
  solodit_ids:
    - "h-04-aavevault-does-not-update-tvl-on-depositwithdraw-code4rena-mellow-protocol-mellow-protocol-contest-git"
    - "exchangerate-can-be-manipulated-leading-to-inflation-attack-cantina-none-opalprotocol-pdf"
  incidentes:
    - "Mellow Protocol (C4) — AaveVault.tvl cacheado, donación de aTokens sin actualizar el TVL"
    - "OpalProtocol (Cantina) — _exchangeRate manipulable durante deposit via donation → inflation attack"
```

---

## 9. Curve LP Token Price Manipulation via View-Only Reentrancy

```yaml
- id: lst-009
  titulo: wstETH/ETH Curve LP token price manipulable via read-only reentrancy durante remove_liquidity
  causa_raiz: |
    Los pools Curve con ETH nativo envían ETH antes de actualizar sus balances internos.
    Durante remove_liquidity(), el callback de ETH permite re-entrar a un oráculo que lee
    virtual_price o get_virtual_price() del pool. En ese momento el virtual_price está
    artificialmente bajo porque los balances internos no se actualizaron aún. Un protocolo
    de lending que use ese LP token como colateral ve un precio suprimido → liquidaciones
    injustas de posiciones sanas.
  como_funciona: |
    1. Atacante tiene una posición grande en Curve wstETH/ETH pool.
    2. Llama remove_liquidity() — pool envía ETH al atacante vía callback.
    3. En el callback, atacante llama al protocolo de lending que valora LP via virtual_price.
    4. virtual_price está temporalmente bajo → posición de víctima parece unhealthy.
    5. Atacante liquida la posición de la víctima con descuento → profit.
    6. Después del callback, pool actualiza balances y virtual_price vuelve a la normalidad.
  invariante: |
    // NUNCA leer virtual_price de Curve dentro de una transacción que interactúa con el pool.
    // Usar Chainlink LP price feed o cachear el precio en un bloque anterior:
    require(!curvePool.isReentered(), "reentrancy detected");
    // Curve V2 pools tienen un reentrancy lock que se puede verificar
  que_mirar:
    - Oracle de LP token que llama a pool.get_virtual_price() sin reentrancy check
    - Protocolo de lending que acepta Curve LP como colateral y lee precio intra-tx
    - Falta de integración con Curve reentrancy guard (withdraw_admin_fees trick)
    - Pools Curve con ETH nativo (no WETH) — son los vulnerables al callback
  como_se_arregla: |
    Verificar reentrancy lock de Curve antes de leer virtual_price.
    Usar Chainlink feeds dedicadas para LP tokens cuando existan.
    No permitir liquidaciones en el mismo bloque donde se interactúa con el pool.
  trampas:
    - Solo afecta pools con ETH nativo — pools con WETH no tienen callback.
    - Curve V2 y Curve NG tienen protecciones mejoradas contra esto.
    - ChainSecurity documentó este patrón como "view-only reentrancy" en 2023.
  solodit_ids:
    - "h-1-h-01-wsteth-eth-curve-lp-token-price-can-be-manipulated-to-cause-unexpected-liquidations-sherlock-sentiment-sentiment-update-2-git"
  incidentes:
    - "Sentiment (Sherlock) — wstETH/ETH Curve LP virtual_price manipulado via reentrancy → liquidaciones injustas"
    - "ChainSecurity advisory — View-only reentrancy en Curve pools, múltiples protocolos afectados (2023)"
    - "Jarvis Network / Midas Capital — explotados via read-only reentrancy en Curve pools"
  verificado: true
  confianza: 95
```

---

## 10. stETH/wstETH Wrapping Mismatch — Rate No Es 1:1

```yaml
- id: lst-010
  titulo: Protocolo trata stETH y wstETH como intercambiables sin convertir — accounting incorrecto
  causa_raiz: |
    wstETH es un wrapper non-rebasing de stETH. La relación wstETH:stETH NO es 1:1 — el
    rate crece con el tiempo (actualmente ~1.18 stETH por wstETH). Si un protocolo recibe
    stETH pero contabiliza como wstETH (o viceversa), o si compra stETH en un trade pero
    reporta la cantidad como si fuera wstETH, hay un error de ~15-20% en el accounting.
  como_funciona: |
    1. Protocolo ejecuta un trade para comprar stETH.
    2. La función devuelve amountBought en stETH (e.g., 108 stETH).
    3. Pero el código espera wstETH como buyToken — interpreta 108 como wstETH.
    4. 108 wstETH ≈ 127 stETH al rate actual — el protocolo cree que tiene más valor.
    5. Además, el stETH comprado nunca se wrappea — queda como stETH pero se trata como wstETH.
    Ejemplo real: Notional Finance — _executeDynamicTradeExactIn cambia buyToken a stETH pero
    nunca wrappea el resultado, devolviendo amountBought en unidades de stETH con etiqueta de wstETH.
  invariante: |
    // Siempre verificar que el token recibido coincide con el token esperado:
    if (buyToken == WRAPPED_STETH) {
        uint256 stethReceived = trade.execute();
        amountBought = WRAPPED_STETH.wrap(stethReceived);  // WRAP obligatorio
    }
  que_mirar:
    - Funciones de trade/swap donde stETH se compra pero se reporta como wstETH
    - Código con tradeUnwrapped flag que cambia buyToken pero olvida re-wrappear
    - Conversiones que asumen stETH == wstETH en cantidades
    - Funciones que mezclan balanceOf(stETH) con contabilidad en wstETH
  como_se_arregla: |
    Siempre wrappear stETH a wstETH después de recibirlo si el sistema contabiliza en wstETH.
    Usar wstETH.getWstETHByStETH() para convertir cantidades correctamente.
    Nunca mezclar unidades de stETH y wstETH en la misma variable de accounting.
  trampas:
    - El rate wstETH/stETH cambia continuamente (yield de staking).
    - En mainnet actual ~1.18 stETH = 1 wstETH — el error es significativo.
    - stETH es rebasing (balance cambia solo), wstETH es non-rebasing (rate cambia).
  solodit_ids:
    - "h-2-strategyutils_executedynamictradeexactin-does-not-wrap-steth-sherlock-notional-notional-git"
  incidentes:
    - "Notional Finance (Sherlock) — _executeDynamicTradeExactIn compra stETH pero reporta como wstETH, nunca wrappea"
  verificado: true
  confianza: 90
```

---

## 11. Node Operator Minipool Hijacking

```yaml
- id: lst-011
  titulo: Minipool de node operator puede ser hijackeada tras finalizar validación
  causa_raiz: |
    En protocolos de liquid staking donde los node operators crean minipools (GoGoPool,
    RocketPool), la máquina de estados permite transiciones desde estados terminales
    (Withdrawable, Error, Finished) de vuelta a Prelaunch. Un atacante puede recrear una
    minipool ajena usando la transición permitida, reasignándose como operador y robando
    los fondos stakeados y rewards futuros del operador original.
  como_funciona: |
    1. Node operator A crea minipool, stakea 1000 AVAX + 1000 AVAX de liquid stakers.
    2. Periodo de validación termina → minipool pasa a Withdrawable.
    3. Atacante B llama recreateMinipool() antes de que A retire sus fondos.
    4. La máquina de estados permite Withdrawable → Prelaunch (recreación válida).
    5. Atacante B se registra como nuevo operador de esa minipool → fondos de A quedan bloqueados.
    6. Atacante opera el nodo sin riesgo real (fondos de A como colateral) y cobra rewards.
  invariante: |
    // Solo el operador original puede recrear o reclamar una minipool:
    require(msg.sender == minipool.owner, "not minipool owner");
    // O asegurar que recreateMinipool verifica la identidad del operador
  que_mirar:
    - Funciones de recreación/reinicio de minipools sin verificación de ownership
    - State machine que permite transición libre desde estados terminales
    - Falta de require(msg.sender == nodeOperator) en funciones de recreación
    - Minipools en estado Withdrawable o Error con fondos aún no retirados
  como_se_arregla: |
    Verificar que solo el operador original puede recrear la minipool.
    Añadir timelock entre fin de validación y posibilidad de recreación.
    Forzar retiro de fondos antes de permitir recreación.
  trampas:
    - En GoGoPool solo Rialto (multisig) puede recrear — pero si Rialto es comprometido, el ataque es viable.
    - En RocketPool el operador debe depositar bond — limita el riesgo pero no lo elimina.
  solodit_ids:
    - "h-04-hijacking-of-node-operators-minipool-causes-loss-of-staked-funds-code4rena-gogopool-gogopool-contest-git"
  incidentes:
    - "GoGoPool (C4) — minipool hijacking via state machine: Withdrawable/Error → Prelaunch permite a atacante tomar control"
  verificado: true
  confianza: 85
```

---

## 12. RocketPool Node Distributor — Reentrancy en distribute()

```yaml
- id: lst-012
  titulo: Reentrancy en distribute() de RocketPool permite drenar fondos del distributor
  causa_raiz: |
    La función distribute() del RocketNodeDistributorDelegate calcula el share del node
    operator y le envía ETH a su withdrawal address. Si el withdrawal address es un contrato
    malicioso, puede re-entrar a distribute() y reclamar el share múltiples veces antes de
    que el balance se actualice, drenando todos los fondos (tanto del operador como del pool).
  como_funciona: |
    1. Node operator configura withdrawal address a un contrato malicioso.
    2. Llama distribute() → contrato calcula nodeShare = X ETH.
    3. Envía X ETH al contrato malicioso → callback receive()/fallback().
    4. En el callback, contrato re-llama distribute() → balance aún tiene fondos.
    5. Calcula nodeShare de nuevo (balance no actualizado) → envía X ETH otra vez.
    6. Repite hasta drenar el contrato completo — fondos de rETH holders robados.
  invariante: |
    // Patrón CEI + ReentrancyGuard obligatorio:
    function distribute() external nonReentrant {
        uint256 nodeShare = getNodeShare();
        balance -= nodeShare;  // PRIMERO actualizar estado
        (bool success,) = withdrawalAddress.call{value: nodeShare}("");
        require(success);
    }
  que_mirar:
    - Funciones distribute/claim que envían ETH sin nonReentrant
    - CEI violado — transfer antes de actualizar balance interno
    - Withdrawal address configurable por el operador (puede ser contrato malicioso)
    - Proxy contracts donde ReentrancyGuard de OZ no aplica por storage layout
  como_se_arregla: |
    Añadir reentrancy guard (custom si el storage layout no permite OZ standard).
    Aplicar CEI: actualizar balance ANTES de enviar ETH.
    Considerar pull pattern en vez de push para distribución.
  trampas:
    - RocketPool usa dynamic proxy con storage slot 0 ocupado — no podían usar OZ ReentrancyGuard directamente.
    - El fix fue un custom reentrancy guard con variable lock al final del storage layout.
    - Afecta a la distribución de rewards entre node operator y protocol, no al staking directamente.
  solodit_ids:
    - "rocketnodedistributordelegate-reentrancy-in-distribute-allows-node-owner-to-drain-distributor-funds-fixed-consensys-rocket-pool-atlas-v12-markdown"
  incidentes:
    - "RocketPool Atlas v1.2 (Consensys) — reentrancy en distribute() permite al node owner drenar todos los fondos del distributor"
  verificado: true
  confianza: 95
```

---

## 13. Frontrunning de Precio LST — Withdraw Antes del Descenso

```yaml
- id: lst-013
  titulo: Usuarios front-runnean descenso de precio de LST/LRT para evitar pérdidas
  causa_raiz: |
    Protocolos que permiten redención instantánea de tokens yield-bearing (PT/YT, shares)
    contra un buffer de ETH son vulnerables a frontrunning: un usuario monitorea el mempool
    o el beacon chain, detecta que el LST va a perder valor (rebase negativo, slashing,
    actualización de oracle), y redime instantáneamente antes de que el descenso se refleje
    en el protocolo. El resultado es que el frontrunner socializa sus pérdidas al resto.
  como_funciona: |
    1. Protocolo tiene buffer ETH para redenciones instantáneas (sin queue).
    2. Usuario monitorea beacon chain → detecta que eETH va a rebajarse (llamada a rebase()).
    3. Front-runnea la tx de rebase llamando prefundedRedeem() → obtiene ETH al rate pre-descenso.
    4. El rebase se ejecuta → el pool tiene menos valor pero el frontrunner ya salió.
    5. Usuarios restantes absorben la pérdida del frontrunner.
    Ejemplo: Napier Finance — usuarios front-runnean descenso de eETH y uniETH via mempool monitoring.
  invariante: |
    // Opciones de mitigación:
    // 1. Delay obligatorio entre deposit y withdraw (anti-flashloan):
    require(block.timestamp - lastDeposit[user] > MIN_DELAY, "too early");
    // 2. Withdrawal fee proporcional al buffer usado
    // 3. Oracle update atómico con redención (imposible en la mayoría de diseños)
  que_mirar:
    - Redención instantánea de LST/LRT tokens sin delay mínimo
    - Buffer de ETH accesible sin queue de espera
    - Falta de withdrawal fee que disuada frontrunning
    - Tokens rebasing (eETH, stETH) donde la actualización de balance es pública en mempool
  como_se_arregla: |
    Implementar withdrawal delay mínimo (al menos 1 bloque, idealmente más).
    Añadir withdrawal fee dinámica basada en el tamaño de la redención.
    Usar oracle atómico que actualice el rate ANTES de permitir redenciones.
  trampas:
    - En tokens rebasing, la tx de rebase es pública en el mempool → el frontrunning es trivial.
    - En tokens non-rebasing (wstETH, rETH), el rate solo cambia con oracle updates → más difícil de front-runnear.
    - Withdrawal delays largos reducen la usabilidad del protocolo.
  solodit_ids:
    - "h-2-users-can-frontrun-lstslrts-tokens-prices-decrease-in-order-to-avoid-losses-sherlock-napier-finance-lstlrt-integrations-git"
  incidentes:
    - "Napier Finance (Sherlock) — frontrunning de descenso de eETH/uniETH via mempool monitoring, redención instantánea contra buffer ETH"
  verificado: true
  confianza: 90
```

---

## 14. Lido Withdrawal Amount Limits — Fondos Bloqueados Permanentemente

```yaml
- id: lst-014
  titulo: Límites de cantidad de Lido withdrawal queue (MIN/MAX) bloquean fondos de integradores
  causa_raiz: |
    Lido V2 withdrawal queue tiene límites: MIN_STETH_WITHDRAWAL_AMOUNT y
    MAX_STETH_WITHDRAWAL_AMOUNT. Si un protocolo integrador inicia un withdraw con shares
    que resultan en un amount fuera de estos límites, el paso final (requestWithdrawals) reverts.
    El protocolo queda con fondos atascados: ya inició el cooldown, ya quemó los shares del
    vault, pero nunca puede completar el withdrawal de Lido.
  como_funciona: |
    1. Usuario tiene shares en un vault que representan poco stETH (< MIN_STETH_WITHDRAWAL_AMOUNT).
    2. Llama initiateWithdraw() → vault quema sus shares y envía stETH al holder contract.
    3. Cooldown pasa → usuario llama triggerExtraStep() para requestWithdrawals de Lido.
    4. Lido reverts: amount < MIN_STETH_WITHDRAWAL_AMOUNT (~100 wei) o > MAX (~1000 stETH).
    5. Withdraw nunca se completa → fondos bloqueados permanentemente.
    6. Usuario no puede depositar ni liquidar — tiene un pending withdraw que nunca finaliza.
  invariante: |
    // Validar contra límites de Lido ANTES de iniciar el withdraw:
    uint256 lidoMin = IWithdrawalQueue(LIDO_QUEUE).MIN_STETH_WITHDRAWAL_AMOUNT();
    uint256 lidoMax = IWithdrawalQueue(LIDO_QUEUE).MAX_STETH_WITHDRAWAL_AMOUNT();
    require(amount >= lidoMin && amount <= lidoMax, "outside Lido limits");
  que_mirar:
    - Integraciones con Lido que no verifican MIN/MAX_STETH_WITHDRAWAL_AMOUNT
    - Flujo de withdraw en dos fases donde la validación ocurre solo en la segunda fase
    - Shares pequeñas que pueden resultar en amounts < MIN tras conversión
    - Shares grandes que exceden MAX — necesitan splitting en múltiples requests
  como_se_arregla: |
    Verificar límites de Lido withdrawal queue ANTES de iniciar el withdraw flow.
    Para amounts grandes, splitear en múltiples requestWithdrawals de hasta MAX cada uno.
    Para amounts pequeños, acumular en un batch o devolver stETH directamente sin usar la queue.
  trampas:
    - MIN_STETH_WITHDRAWAL_AMOUNT es ~100 wei (muy bajo, pero posible con dust).
    - MAX_STETH_WITHDRAWAL_AMOUNT es ~1000 stETH (puede cambiar por DAO governance).
    - Ambos valores son configurables por Lido DAO — pueden cambiar en el futuro.
  solodit_ids:
    - "h-2-lido-withdraw-limitation-will-brick-the-withdraw-process-in-an-edge-case-sherlock-notional-leveraged-vaults-pendle-pt-and-vault-incentives-git"
  incidentes:
    - "Notional Leveraged Vaults (Sherlock) — Lido withdraw limitation bloquea fondos permanentemente cuando amount fuera de MIN/MAX"
  verificado: true
  confianza: 90
```

---

## 15. Staking Reward Manipulation — Stake Just Before Claim

```yaml
- id: lst-015
  titulo: Rewards calculados por stake actual — stake justo antes de claim para robar rewards
  causa_raiz: |
    Sistemas de reward distribution que calculan la share del reward basándose en el stake
    ACTUAL (no en el stake promediado sobre el periodo) son vulnerables a flash-stake:
    un operador deposita una gran cantidad de stake justo antes de la distribución de rewards,
    reclama su proporción inflada, y retira inmediatamente después.
  como_funciona: |
    1. Reward pool tiene 100 ETH para distribuir en el periodo actual.
    2. Hay 10 operadores con 100 RPL stakeados cada uno = 1000 RPL total.
    3. Atacante deposita 9000 RPL justo antes de claim → ahora tiene 9000/10000 = 90% del total.
    4. Atacante llama claim() → recibe 90 ETH de los 100 ETH de rewards.
    5. Los 10 operadores honestos comparten solo 10 ETH.
    6. Atacante retira los 9000 RPL después del periodo de lock mínimo.
    No necesita ser flash loan — puede ser un stake de corta duración si el lock es menor que el reward period.
  invariante: |
    // Rewards deben ser proporcionales al tiempo de stake, no solo al amount:
    uint256 reward = (stakeAmount * stakeDuration) / (totalStakeTime);
    // O usar snapshot del stake al INICIO del periodo, no al momento del claim
  que_mirar:
    - Reward distribution basada en stake actual sin considerar duración
    - Falta de snapshot del stake al inicio del periodo de rewards
    - Lock period del stake < periodo de reward distribution
    - Funciones claim() que leen effectiveStake en el momento de la llamada
  como_se_arregla: |
    Tomar snapshot del stake al inicio de cada periodo de rewards.
    Usar weighted-average stake (amount × time) para calcular proporción.
    Asegurar que lock period del stake > reward period para prevenir stake temporal.
  trampas:
    - En RocketPool el stake requiere crear minipools — alto costo de capital pero posible para whales.
    - El RPL lock period fue aumentado a 150% del effective stake como mitigación parcial.
    - Flash loans no sirven directamente si se requiere crear minipools (proceso en varios bloques).
  solodit_ids:
    - "rocketrewardpool-unpredictable-staking-rewards-as-stake-can-be-added-just-before-claiming-and-rewards-may-be-paid-to-to-operators-that-do-not-provide-a-service-to-the-system-partially-addressed-consensys-rocketpool-markdown"
  incidentes:
    - "RocketPool (Consensys) — stake añadido justo antes de claim permite capturar rewards desproporcionados"
  verificado: true
  confianza: 85
```

---

## 16. Partial vs Full Withdrawal Misclassification

```yaml
- id: lst-016
  titulo: Validator withdrawal clasificado incorrectamente — operador slashed retiene fondos indebidamente
  causa_raiz: |
    Protocolos de liquid staking distinguen partial withdrawals (skimming de rewards) de
    full withdrawals (exit de validador) por el AMOUNT recibido. Un threshold fijo (e.g., 8 ETH
    en RocketPool) determina si es partial o full. Pero un validador severamente slashed
    puede tener balance < 8 ETH al hacer exit, causando que un full withdrawal sea tratado
    como partial — el operador puede retirar fondos que deberían ir al pool.
  como_funciona: |
    1. Node operator tiene minipool con 32 ETH (8 bond + 24 rETH holders).
    2. Validador es slashed severamente → balance baja a 6 ETH.
    3. Validador hace full exit → envía 6 ETH al minipool contract.
    4. Contrato ve 6 ETH < 8 ETH threshold → clasifica como partial withdrawal.
    5. En partial withdrawal, operador recibe su "share" de los 6 ETH (e.g., 25% = 1.5 ETH + fee).
    6. Pero en un full exit con slashing, el operador debería absorber la pérdida primero.
    7. Resultado: rETH holders pierden más de lo que deberían — operador retiene fondos.
  invariante: |
    // No usar solo el amount para distinguir partial/full withdrawal:
    // Verificar el status del validador en el beacon chain
    require(validatorStatus == WITHDRAWN || amount > THRESHOLD, "ambiguous withdrawal type");
    // O usar un mapping on-chain del tipo de exit iniciado
  que_mirar:
    - Lógica de distributeBalance() que usa solo amount < threshold para clasificar withdrawal
    - Validadores que pueden ser slashed hasta tener balance < bond threshold
    - Cálculo de node operator share en partial vs full withdrawal
    - Falta de verificación del estado del validador en beacon chain
  como_se_arregla: |
    Combinar el amount con el estado del validador (beacon chain proof) para clasificar.
    Mantener un registro on-chain de si el operador inició un exit voluntario o fue slashed.
    Tratar amounts < threshold como full withdrawal si el validador está en estado WITHDRAWN.
  trampas:
    - Este escenario requiere slashing severo — poco común pero posible en eventos de inactividad prolongada.
    - EIP-7002 (triggerable withdrawals) cambia la dinámica de exits en el futuro.
    - El modeling económico del risk del 25% bond asume que el operador pierde su bond primero — pero la implementación no lo garantiza.
  solodit_ids:
    - "distinction-of-partialfull-withdrawals-is-not-guaranteed-sigmaprime-none-rocketpool-pdf"
  incidentes:
    - "RocketPool (Sigma Prime) — validador slashed con balance < 8 ETH → full exit tratado como partial withdrawal"
  verificado: true
  confianza: 85
```

---

## 17. Beacon Oracle Report Front-Running

```yaml
- id: lst-017
  titulo: Front-running del reporte de oracle beacon para arbitrar el exchange rate del LST
  causa_raiz: |
    En protocolos de liquid staking, un oracle committee reporta periódicamente los balances
    de validadores al contrato on-chain (setBeaconData, reportBeacon). Este reporte actualiza
    el exchange rate del LST. Un MEV bot o un miembro del oracle committee puede ver la tx
    de reporte en el mempool, calcular si el rate subirá o bajará, y front-runnear para
    depositar/retirar al rate antiguo → arbitraje garantizado.
  como_funciona: |
    1. Oracle committee prepara tx reportBeacon(newTotalBalance, newValidatorCount).
    2. Si newTotalBalance > expected → rate del LST subirá.
    3. Atacante ve la tx en mempool → deposita ETH → mint LST al rate antiguo (más bajo).
    4. Oracle report se ejecuta → rate sube → LST del atacante vale más.
    5. Atacante vende/redime al nuevo rate → profit sin riesgo.
    Inversamente, si el rate baja (slashing), el atacante retira antes del reporte.
  invariante: |
    // Mitigaciones:
    // 1. Oracle report en dos fases: commit + reveal
    // 2. Deposit/withdrawal rate usa el rate POST-reporte, no pre-reporte
    // 3. Flashbots Protect o private mempool para txs de reporte
    // 4. Rate smoothing: aplicar cambios gradualmente, no en un solo bloque
  que_mirar:
    - Funciones setBeaconData/reportBeacon que actualizan el rate en una sola tx
    - Falta de commit-reveal scheme para reportes de oracle
    - Deposits/withdrawals que usan el rate del bloque actual (no el futuro)
    - Oracles con pocos miembros que pueden ser MEV-aware
  como_se_arregla: |
    Implementar rate smoothing: aplicar cambios de rate gradualmente sobre N bloques.
    Usar commit-reveal para reportes de oracle.
    Deposits en el mismo bloque del reporte usan el rate pre-reporte (o post-reporte para ambos).
    Enviar oracle reports via Flashbots Protect o relay privado.
  trampas:
    - Lido mitiga esto parcialmente con reportes diarios y rate smoothing.
    - En protocolos más pequeños sin MEV protection, el riesgo es real.
    - Un miembro del oracle committee tiene ventaja informacional — no necesita mempool.
  solodit_ids:
    - "oraclemanagersetbeacondata-possible-front-running-attacks-spearbit-liquid-collective-pdf"
    - "the-reportbeacon-is-prone-to-front-running-attacks-by-oracle-members-spearbit-liquid-collective-pdf"
  incidentes:
    - "Liquid Collective (Spearbit) — setBeaconData y reportBeacon vulnerables a front-running por oracle members y MEV bots"
  verificado: true
  confianza: 85
```

---

## 18. EigenLayer Strategy Reentrancy — Token Callbacks Corrompen Shares

```yaml
- id: lst-018
  titulo: Reentrancy en EigenLayer strategies via token callbacks corrompe sharesToUnderlying
  causa_raiz: |
    EigenLayer StrategyBase calcula sharesToUnderlying como totalUnderlying/totalShares.
    Las funciones deposit() y withdraw() transfieren tokens antes/después de actualizar
    el accounting. Si el token tiene callbacks (ERC777, hooks, etc.), un atacante puede
    re-entrar a funciones view como sharesToUnderlyingView() durante la transferencia.
    En ese momento los shares están decrementados pero el balance aún no se actualizó →
    la función view devuelve un valor incorrecto que otros contratos pueden leer.
  como_funciona: |
    1. Staker llama withdraw() → StrategyManager decrementa shares.
    2. Strategy.withdraw() transfiere tokens al recipient → token tiene callback.
    3. En el callback, atacante lee sharesToUnderlyingView() → shares ya decrementados
       pero balance aún no actualizado → ratio inflado.
    4. Otro contrato que confía en sharesToUnderlyingView() toma decisión con ratio incorrecto.
    5. Posible: valorar colateral incorrectamente, permitir borrow excesivo, etc.
  invariante: |
    // StrategyBase debe verificar que los tokens aceptados NO tienen callbacks:
    // O añadir reentrancy guard a funciones view que calculan ratios:
    function sharesToUnderlyingView(uint256 shares) public view returns (uint256) {
        // Sin reentrancy guard — vulnerable durante transferencias
        return (shares * totalUnderlying) / totalShares;
    }
  que_mirar:
    - Strategies que aceptan tokens con callbacks (ERC777, hooks custom)
    - Funciones view (sharesToUnderlyingView, underlyingToSharesView) sin protection
    - StrategyManager tiene nonReentrant pero las strategies derivadas no
    - Protocolos que leen sharesToUnderlyingView durante un callback de token
  como_se_arregla: |
    Documentar explícitamente que StrategyBase NO soporta tokens con reentrancy.
    Para soporte de tokens con callbacks: añadir reentrancy guard a funciones view.
    Usar pull pattern para withdrawals (usuario claim en tx separada).
  trampas:
    - EigenLayer reconoció el issue pero no lo fixeó — documentan que StrategyBase no soporta tokens con reentrancy.
    - En la práctica, la mayoría de LSTs (stETH, rETH, cbETH) no tienen callbacks tipo ERC777.
    - El riesgo es real para strategies custom que acepten tokens exóticos.
  solodit_ids:
    - "potential-reentrancy-into-strategies-consensys-eigenlabs-eigenlayer-markdown"
  incidentes:
    - "EigenLayer (Consensys) — reentrancy potencial en strategies via token callbacks corrompe sharesToUnderlyingView"
  verificado: true
  confianza: 80
```

---

## 19. Lybra stETH Income Manipulation — Fake Rebase Donation

```yaml
- id: lst-019
  titulo: Donación directa de stETH al vault genera ingreso falso — robo de fondos via excessIncomeDistribution
  causa_raiz: |
    Protocolos que calculan el "excess income" como la diferencia entre stETH.balanceOf(vault)
    y totalDepositedAsset son vulnerables a donación directa de stETH. Un atacante dona stETH
    al vault → la diferencia se interpreta como ingreso de staking → el atacante compra ese
    "income" a precio de descuento. Combinado con first-depositor manipulation
    (_totalSupply vs _totalShares desbalanceados), permite robo directo de fondos.
  como_funciona: |
    1. Protocolo nuevo (day 0): atacante deposita 1 ETH → mint 200 eUSD.
    2. Atacante transfiere 0.2 stETH directamente al vault (donación).
    3. stETH.balanceOf(vault) = 1.2 ETH, pero totalDepositedAsset = 1.0 ETH.
    4. excessIncome = 0.2 stETH → atacante llama excessIncomeDistribution() para "comprar" el excess.
    5. La compra minta eUSD contra el stETH donado → el atacante se queda con eUSD + el stETH donado.
    6. Cuando otros depositan, el desbalance _totalSupply/_totalShares permite al atacante
       retirar más eUSD del que le corresponde.
  invariante: |
    // El excess income NO debe calcularse como diferencia de balanceOf y totalDeposited:
    // MAL: excessIncome = stETH.balanceOf(this) - totalDepositedAsset;
    // BIEN: usar un accounting interno separado para real staking yield
    uint256 realYield = oracle.getYieldSinceLastUpdate();
  que_mirar:
    - excessIncome o excessIncomeDistribution basado en balanceOf vs totalDeposited
    - Posibilidad de donación directa de stETH/wstETH al vault
    - First-depositor advantage combinado con donación
    - _totalSupply vs _totalShares que pueden desbalancearse
  como_se_arregla: |
    Calcular yield internamente (via oracle de Lido, no por balanceOf diff).
    Usar virtual shares para eliminar first-depositor manipulation.
    No permitir excessIncomeDistribution en los primeros N bloques tras deployment.
  trampas:
    - stETH es rebasing — su balanceOf() cambia automáticamente con el yield real.
    - La donación directa es indistinguible del yield real si solo se mira balanceOf.
    - Protocolos maduros con alto TVL son menos vulnerables por el costo de la donación.
  solodit_ids:
    - "h-05-making-_totalsupply-and-_totalshares-imbalance-significantly-by-providing-fake-income-leads-to-stealing-fund-code4rena-lybra-finance-lybra-finance-git"
  incidentes:
    - "Lybra Finance (C4) — donación directa de stETH crea excess income falso, combinado con first-depositor attack para robar fondos"
  verificado: true
  confianza: 90
```

---

## 20. Operator Stake-Exit Lag — Consenso Sin Riesgo

```yaml
- id: lst-020
  titulo: Operador retira stake durante lag entre selección y commitment — controla consenso sin riesgo de slashing
  causa_raiz: |
    En protocolos de restaking/middleware (Symbiotic, EigenLayer AVS), la selección de
    validadores y el commitment del validator set son operaciones no atómicas. Hay un gap
    temporal entre: (1) el cálculo del voting power basado en stake actual, y (2) el
    commitment del validator set header. Un operador malicioso puede retirar su stake durante
    este gap, manteniendo su voting power pero eliminando su riesgo de slashing.
  como_funciona: |
    1. Epoch N: operador malicioso deposita gran cantidad de stake → obtiene voting power dominante.
    2. Off-chain relay calcula voting powers, crea sigVerifier con el operador como validador.
    3. Relay llama setSigVerifier() → operador seleccionado para epoch N+1.
    4. ANTES de commitValSetHeader(): operador llama withdraw() en su vault → stake sale.
    5. commitValSetHeader() se ejecuta → operador tiene voting power pero ya no tiene stake.
    6. Operador puede firmar headers maliciosos sin riesgo — no hay stake para slashear.
    7. Si controla >quorumThreshold, puede manipular el consenso del middleware.
  invariante: |
    // Verificar stake al momento de commitment, no solo al momento de selección:
    // O hacer setSigVerifier + commitValSetHeader atómicos:
    function commitAndVerify(bytes calldata header) external {
        _setSigVerifier();  // snapshot del stake
        _commitValSetHeader(header);  // commitment inmediato
        // Sin gap entre ambas operaciones
    }
  que_mirar:
    - Separación entre setSigVerifier() y commitValSetHeader() como funciones independientes
    - commitValSetHeader() público sin restricción de caller
    - Falta de verificación de stake al momento del commitment (solo al momento de selección)
    - Withdrawal delay menor que la duración del epoch
  como_se_arregla: |
    Hacer setSigVerifier + commitValSetHeader atómicos en una sola transacción.
    Verificar que el stake del operador sigue presente al momento del commitment.
    Withdrawal delay debe ser >= duración del epoch + buffer.
  trampas:
    - En EigenLayer, el withdrawal delay de 7 días suele ser suficiente para cubrir epochs.
    - En protocolos middleware más nuevos (Symbiotic), los epochs pueden ser más cortos que el withdrawal delay.
    - El ataque requiere que el operador tenga capital significativo aunque sea temporalmente.
  solodit_ids:
    - "m-7-a-malicious-operator-will-control-consensus-without-risking-stake-stake-exit-lag-exploit-sherlock-symbiotic-relay-git"
  incidentes:
    - "Symbiotic Relay (Sherlock) — operador retira stake entre setSigVerifier y commitValSetHeader, controla consenso sin riesgo de slashing"
  verificado: true
  confianza: 85
```

---

## Attack Scenarios Summary

| ID | Patrón | Severity | Likelihood |
|----|--------|----------|------------|
| lst-001 | stETH/ETH peg assumption | High | Medium |
| lst-002 | LST exchange rate manipulation/composition | High | Medium |
| lst-003 | Withdrawal queue DoS / lockup | High | Medium |
| lst-004 | Slashing no contemplado en colateral | Medium | Low |
| lst-005 | Reentrancy en LST callbacks | High | Low |
| lst-006 | Monotonía de rate asumida → oracle freeze | Medium | Low |
| lst-007 | Sequencer down en L2 → stale LST price | High | Medium (L2 only) |
| lst-008 | Donation inflates LST exchange rate | High | Low |
| lst-009 | Curve LP view-only reentrancy (virtual_price) | High | Medium |
| lst-010 | stETH/wstETH wrapping mismatch — rate no 1:1 | High | Medium |
| lst-011 | Node operator minipool hijacking | High | Low |
| lst-012 | RocketPool distributor reentrancy | Critical | Low |
| lst-013 | Frontrunning LST price decrease | High | Medium |
| lst-014 | Lido withdrawal MIN/MAX limits → fondos bloqueados | High | Low |
| lst-015 | Stake just before claim → reward theft | Medium | Medium |
| lst-016 | Partial/full withdrawal misclassification | Medium | Low |
| lst-017 | Beacon oracle report front-running | Medium | Medium |
| lst-018 | EigenLayer strategy reentrancy via token callbacks | Medium | Low |
| lst-019 | stETH fake income via donation (Lybra pattern) | High | Low |
| lst-020 | Operator stake-exit lag → consensus sin riesgo | Medium | Low |

## Key Protocols to Check

- **Lido**: stETH (rebasing), wstETH (non-rebasing wrapper), Lido V2 withdrawal queue (MIN/MAX limits)
- **RocketPool**: rETH, rocketpool oracle, minipool withdrawal delays, distributor reentrancy, partial/full withdrawal distinction
- **Frax**: sfrxETH/frxETH, AMO interactions
- **EigenLayer**: restaking, operator withdrawal delays, slashing conditions, strategy reentrancy with callback tokens
- **Symbiotic/Middleware**: validator set commitment lag, stake-exit timing attacks
- **Curve**: LP token pricing via virtual_price, view-only reentrancy in ETH pools
- **Chainlink LST feeds**: wstETH/USD, rETH/USD, cbETH/USD (mainnet + L2 versions)
- **Lybra**: stETH vault excess income via donation, first-depositor manipulation
- **Napier/Adapters**: instant redemption frontrunning, LST/LRT price decrease arbitrage
