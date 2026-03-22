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

## Key Protocols to Check

- **Lido**: stETH (rebasing), wstETH (non-rebasing wrapper), Lido V2 withdrawal queue
- **RocketPool**: rETH, rocketpool oracle, minipool withdrawal delays
- **Frax**: sfrxETH/frxETH, AMO interactions
- **EigenLayer**: restaking, operator withdrawal delays, slashing conditions
- **Chainlink LST feeds**: wstETH/USD, rETH/USD, cbETH/USD (mainnnet + L2 versions)
