# Yield Aggregator / Strategy Vault — Bug Patterns

## Quick Reference

```
grep_targets:
  - TokenizedStrategy
  - BaseStrategy
  - _deployFunds
  - _freeFunds
  - liquidatePosition
  - prepareReturn
  - harvest
  - report
  - tend
  - totalAssets
  - _harvestAndReport
  - sharePrice
  - pricePerShare
  - strategyDebt
  - maxDebt
  - totalDebt
  - migrate
  - emergencyWithdraw
  - minAmountOut
  - setMaxDebt
  - yieldToken
  - aToken
  - stETH
  - sqrtPriceX96
  - sqrtPrice
  - slot0
```

---

## 1. Share Inflation & First Depositor

```yaml
- id: yva-001
  titulo: Share inflation / first depositor en TokenizedStrategy
  causa_raiz: |
    El primer depositante puede comprar shares con 1 wei y luego donar tokens al vault.
    Tras la donación, el precio por share se infla; el segundo depositante recibe 0 shares
    y pierde todos sus fondos. Afecta contratos que heredan de TokenizedStrategy (Yearn V3)
    cuando no hay un _setMinDebt inicial o seed de shares virtuales.
  como_funciona: |
    1. Atacante deposita 1 wei → recibe 1 share.
    2. Atacante dona X tokens directamente (transfer) al vault → totalAssets = X+1.
    3. Víctima deposita Y tokens → shares = Y * 1 / (X+1) ≈ 0 si Y << X.
    4. Víctima recibe 0 shares, no puede retirar nada.
  invariante: |
    assert(shares_minted > 0) when deposit > 0;
    equivalente: totalSupply == 0 → require virtualShares seed mechanism.
  que_mirar:
    - TokenizedStrategy hereda ERC4626 sin seed de shares virtuales
    - Primer depósito sin _setMinDebt o locked shares
    - convertToShares(1) retorna 0 cuando totalSupply > 0 y totalAssets inflado
    - Vault sin limite mínimo de depósito
  como_se_arregla: |
    Usar ERC4626 virtual shares (OpenZeppelin v5): _decimalsOffset() > 0 infla
    totalSupply internamente y hace el ataque económicamente inviable.
    Alternativa: locked shares en primer depósito (mint 10**3 shares al address(0)).
  trampas:
    - No todos los TokenizedStrategy son vulnerables — revisar la versión exacta.
    - El ataque sólo funciona si totalSupply puede llegar a exactamente 0.
    - Vaults con MIN_TOTAL_SUPPLY ya fijado no son vulnerables.
  solodit_ids: [57686, 3337, 1657, 1907]
  incidentes:
    - "Yearn V3 TokenizedStrategy (Code4rena 2023) — share inflation en primer depósito"
    - "Multiple ERC4626 forks (Sherlock 2023) — seed shares no implementadas"
```

---

## 2. Loss Accounting en BaseStrategy

```yaml
- id: yva-002
  titulo: Loss contabilizado incorrectamente en liquidatePosition / prepareReturn
  causa_raiz: |
    BaseStrategy.liquidatePosition(amountNeeded) debe retornar (liquidatedAmount, loss).
    Si la implementación retorna loss=0 cuando liquidatedAmount < amountNeeded (e.g., slippage
    o posición bajo agua), el vault registra totalAssets incorrecto → usuarios posteriores
    retiran más de lo que les corresponde a expensas de los restantes.
  como_funciona: |
    1. Strategy con posición parcialmente líquida: totalAssets=100, liquidez real=80.
    2. Usuario retira 100 → liquidatePosition retorna (80, 0) en vez de (80, 20).
    3. Vault asume 0 pérdida → computa shares mal → el vault queda insolvente.
    4. Siguientes retiros fallan o roban del siguiente usuario.
  invariante: |
    assert(liquidatedAmount + loss >= amountNeeded || liquidatedAmount == availableLiquidity);
    en prepareReturn: assert(_totalAssets() == deployedCapital + idleBalance - totalLoss);
  que_mirar:
    - liquidatePosition() con retorno fijo (loss = 0 siempre)
    - prepareReturn() que no deduce slippage ni IL de totalDebt
    - Estrategias con posiciones Uniswap V3 (IL puede ser significativa)
    - Tests de retiro que sólo prueban el happy path (sin slippage)
  como_se_arregla: |
    En liquidatePosition: loss = amountNeeded - liquidatedAmount cuando liquidatedAmount < amountNeeded.
    En prepareReturn: _profit/_loss calculados contra baseStrategyStorage.totalDebt, no contra balance().
  trampas:
    - Algunas estrategias intencionalmente no reportan pérdidas (e.g., esperan recuperación).
    - "Loss" en Yearn V3 implica reducción de totalDebt — confirmar semántica exacta del vault.
  solodit_ids: [28458]
  incidentes:
    - "Yearn V3 BaseStrategy (Solodit #28458) — loss=0 en liquidatePosition cuando slippage"
```

---

## 3. Single Strategy Failure Blocks All Withdrawals

```yaml
- id: yva-003
  titulo: Fallo de una estrategia bloquea todos los retiros del vault
  causa_raiz: |
    Vaults multi-estrategia que iteran sobre todas las estrategias en withdraw() sin manejo
    de errores individuales. Si una estrategia revierte (e.g., protocolo subyacente pausado,
    liquidez cero, rug), el loop entero revierte y ningún usuario puede retirar.
  como_funciona: |
    1. Vault tiene estrategias [A, B, C] con fondos.
    2. El protocolo de C se pausa externamente (Aave pause, Compound guardian).
    3. Usuario llama withdraw() → vault itera → llega a C.freeFunds() → revert.
    4. Toda la transacción revierte. Usuarios con fondos en A y B tampoco pueden salir.
    5. Un único actor malicioso puede crear una estrategia C "bomba" si el vault permite
       estrategias permisionadas con bajo control de calidad.
  invariante: |
    Invariante de disponibilidad: si usuario tiene shares y hay liquidez idle, withdraw() nunca revierte.
    Corolario: withdrawal de idle cash no debe depender de estrategias externas.
  que_mirar:
    - Loop en _withdrawFromStrategies() sin try/catch ni flag de skip
    - Estrategias que pueden ser añadidas por governance con timelock corto
    - Ausencia de emergencyWithdraw() per-strategy que bypasea el loop normal
    - Vault sin "idle buffer" — 100% del capital en estrategias
  como_se_arregla: |
    Añadir try/catch por estrategia en el loop de retiro.
    Mantener un % mínimo de idle cash en el vault (e.g., 10%).
    Implementar emergencyWithdraw() que sólo toca idle, ignorando estrategias.
  trampas:
    - Puede ser "by design" si el vault requiere que todas las estrategias estén sanas.
    - Revisar si hay un withdraw(maxLoss) con tolerancia que mitiga esto.
  solodit_ids: [64016]
  incidentes:
    - "Multi-strategy vault (Solodit #64016) — una estrategia pausada bloquea todos los retiros"
```

---

## 4. Rebasing Tokens Rompen Share Accounting

```yaml
- id: yva-004
  titulo: aToken / stETH rebasing rompe totalAssets y el precio de share
  causa_raiz: |
    Estrategias que cachean balances de tokens rebasing (aToken de Aave, stETH, etc.) en
    storage en vez de leerlos en cada llamada. El balance real crece continuamente por interés/
    rebase, pero el valor cacheado queda estático → totalAssets subestimado → usuarios retiran
    a precio de share deflado → pérdida para los primeros en salir que no reciben el yield.
  como_funciona: |
    1. Strategy deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea cached_balance=1000.
    2. Tiempo pasa: aUSDC balance crece a 1050 por interés.
    3. totalAssets() retorna cached_balance=1000 → pricePerShare no refleja el yield.
    4. Usuario retira antes del harvest → recibe menos de lo que le corresponde.
    5. El yield "perdido" queda en el contrato hasta que alguien llame harvest().
  invariante: |
    assert(totalAssets() >= IERC20(aToken).balanceOf(address(this)));
    equivalente: nunca leer balance desde storage si el token es rebasing.
  que_mirar:
    - Variables cached_balance, lastBalance, storedBalance en estrategias
    - Integración con Aave (aToken), Compound (cToken en versiones con interés), Lido (stETH)
    - totalAssets() que no llama balanceOf() en cada invocación
    - Estrategias que sólo actualizan el cache en harvest/tend
  como_se_arregla: |
    Siempre leer balances directamente: return IERC20(aToken).balanceOf(address(this));
    Nunca cachear balances de tokens que crecen automáticamente.
    Si se necesita tracking de depósitos (para calcular profit), usar deposited como base, no balance.
  trampas:
    - cToken de Compound NO es rebasing — el balance es fijo, crece el exchangeRate.
    - wrappedstETH (wstETH) NO es rebasing — el balance es fijo, sube el precio de la share.
    - Sólo stETH "normal" y aToken son rebasing en el sentido estricto.
  solodit_ids: [1188, 3322]
  incidentes:
    - "Yearn V2 aToken strategy (Solodit #1188) — balance cacheado no refleja yield de Aave"
    - "stETH wrapper strategy (Solodit #3322) — rebase silenciado por cache"
```

---

## 5. Tick Leído de slot0 en Estrategias Uniswap V3

```yaml
- id: yva-005
  titulo: Estrategia V3 usa slot0.tick en vez de TWAP para calcular allocations
  causa_raiz: |
    Estrategias que gestionan posiciones Uniswap V3 (Arrakis, Gamma, Ichi, etc.) deben
    calcular el tick actual para decidir rangos y rebalances. Leer slot0.sqrtPriceX96 o
    slot0.tick es manipulable con un flash swap en el mismo bloque. Un atacante puede forzar
    un rebalance en un precio extremo, dejando la estrategia en un rango desfavorable.
  como_funciona: |
    1. Estrategia usa currentTick = pool.slot0().tick para decidir si rebalancear.
    2. Atacante: flash swap → precio sale del rango → tick cambia 200 bps.
    3. Estrategia trigger: rebalance() lee slot0.tick manipulado.
    4. Estrategia mueve liquidez al rango nuevo (incorrecto) → mayor IL cuando precio revierte.
    5. Atacante revierte el flash swap → estrategia queda en rango subóptimo.
  invariante: |
    require(abs(slot0Tick - twapTick) <= MAX_DEVIATION, "price manipulation");
    alternativa: usar OracleLibrary.consult(pool, twapInterval) para tick promedio.
  que_mirar:
    - pool.slot0() sin comparación contra TWAP
    - currentTick usado directamente en lowerTick/upperTick calculations
    - Ausencia de MAX_TICK_DEVIATION check antes de rebalance
    - sqrtPriceX96 de slot0 usado para valuación de assets bajo gestión
  como_se_arregla: |
    Usar OracleLibrary.consult(pool, 1800) para TWAP de 30 minutos.
    Añadir guard: require(abs(slot0Tick - twapTick) <= maxDeviation).
    Si la desviación supera el umbral, revertir o usar el TWAP como precio de referencia.
  trampas:
    - En L2 (Optimism, Base), el TWAP de 30 min puede ser insuficiente — bloques más rápidos.
    - Algunos protocolos intencionalmente usan spot para rebalances frecuentes (design choice).
    - Verificar si existe un check de desviación que no vimos al principio.
  solodit_ids: [55033]
  incidentes:
    - "Arrakis-style V3 strategy (Solodit #55033) — slot0 tick manipulation en rebalance"
```

---

## 6. Flash Loan Attack en Estrategia Curve

```yaml
- id: yva-006
  titulo: Flash loan manipula precio de Curve pool dentro del harvest de estrategia
  causa_raiz: |
    Estrategias que harvestan recompensas y las venden en Curve pueden ser atacadas si el
    harvest no valida el precio de salida. Un atacante puede desequilibrar el pool de Curve
    antes del harvest (via flash loan), forzar a la estrategia a vender en precio desfavorable,
    y luego revertir → la estrategia pierde valor, el atacante extrae la diferencia.
  como_funciona: |
    1. Estrategia va a harvester: venderá 10k CRV por USDC en Curve.
    2. Atacante: flash loan → drena USDC del pool → precio CRV/USDC cae 30%.
    3. harvest() ejecuta la venta a precio deprimido → recibe 7k USDC.
    4. Atacante revierte el flash loan → pool normalizado.
    5. Estrategia registra "profit" de 7k en vez de 10k → usuarios pierden 3k.
  invariante: |
    require(amountOut >= minAmountOut, "slippage too high");
    minAmountOut debe ser calculado con un oracle externo, no con pool.get_dy().
  que_mirar:
    - harvest() / sellRewards() con minAmountOut = 0 o calculado del mismo pool
    - Ausencia de Chainlink o TWAP para validar precio de venta
    - Llamadas a pool.exchange() o router.swap() sin slippage protection
    - harvest() callable por cualquiera (no sólo keeper con slippage param)
  como_se_arregla: |
    Calcular minAmountOut con oracle externo (Chainlink, Uniswap TWAP).
    Añadir parámetro minAmountOut al harvest() que el keeper calcula off-chain.
    Restringir harvest() a keeper confiable con slippage protection.
  trampas:
    - Curvepool con precio muy estable (stableswap) es mucho más difícil de manipular.
    - En mainnet el gas del flash loan puede hacer el ataque no rentable para montos pequeños.
    - Verificar que el harvest realmente hace swaps en el mismo tx y no usa una queue.
  solodit_ids: [1276]
  incidentes:
    - "Yearn Curve strategy (Solodit #1276) — harvest sandwich via Curve flash loan"
```

---

## 7. Migration Parcial Deja Usuario Bloqueado

```yaml
- id: yva-007
  titulo: Migración de estrategia con retiro parcial bloquea fondos del usuario
  causa_raiz: |
    Durante migrate(newStrategy), el vault intenta retirar TODOS los fondos de la estrategia
    vieja. Si la estrategia no puede retirar el 100% (fondos locked, posición ilíquida), la
    migración falla o deja fondos huérfanos en la estrategia vieja sin shares activos.
    Usuarios que tenían exposición a esa estrategia no pueden reclamar los fondos residuales.
  como_funciona: |
    1. Vault llama oldStrategy.migrate(newStrategy) → oldStrategy intenta retirar todo.
    2. 20% de los fondos están locked en un protocolo con cooldown de 7 días.
    3. migrate() retira el 80% y lo mueve a newStrategy. El 20% queda en oldStrategy.
    4. Vault marca oldStrategy como inactiva → debtRatio=0 → nadie puede retirar de ella.
    5. Los fondos residuales están huérfanos: oldStrategy no acepta más depósitos,
       y el vault ya no los incluye en totalAssets().
  invariante: |
    post-migration: oldStrategy.estimatedTotalAssets() == 0;
    alternativa: if residual > 0, vault.revokeStrategy() con debtOutstanding tracking.
  que_mirar:
    - migrate() sin check post-migración de que oldStrategy queda a 0
    - Estrategias con locktimes o cooldowns en protocolos subyacentes
    - Vault que llama setDebtRatio(oldStrategy, 0) sin verificar debtOutstanding
    - emergencyExit no activado antes de migrate en estrategias con fondos locked
  como_se_arregla: |
    Antes de migrate: activar emergencyExit en oldStrategy → permite retiro forzado.
    En migrate(): if residual > 0, registrar como debtOutstanding y no deshabilitar la estrategia.
    Post-migración: monitor residual y permitir retiro paulatino hasta llegar a 0.
  trampas:
    - Puede ser un trade-off conocido (migración rápida acepta residual temporal).
    - Verificar si el protocolo subyacente permite retiro inmediato con penalización.
  solodit_ids: [1190]
  incidentes:
    - "Yearn V2 migration (Solodit #1190) — locked position leaves residual stranded post-migrate"
```

---

## 8. Comparación de Unidades Incorrecta en Rebalance

```yaml
- id: yva-008
  titulo: Wrong unit comparison en rebalance logic (tokens vs shares vs USD)
  causa_raiz: |
    Estrategias que comparan magnitudes de diferentes unidades sin conversión: e.g., comparar
    el balance en tokens (18 decimales) contra un threshold en USD (6 decimales), o comparar
    shares contra tokens subyacentes directamente. El resultado es que el rebalance se activa
    nunca (o siempre) porque la condición es numéricamente incorrecta.
  como_funciona: |
    Ejemplo: if (tokenBalance > minRebalanceAmount) donde tokenBalance es en 18 decimales
    y minRebalanceAmount está hardcoded en 6 decimales (1_000_000 = 1 USDC).
    Resultado: 1e18 tokens siempre > 1e6 → rebalance se activa en cada bloque.
    O el inverso: minRebalanceAmount = 1e18 y tokenBalance está en 1e6 → nunca se activa.
  invariante: |
    assert(minRebalanceAmount.decimals == token.decimals);
    o assert(minRebalanceAmount es expresado en la misma unidad que el valor comparado).
  que_mirar:
    - Constantes hardcoded en rebalance conditions sin comentario de unidades
    - Comparaciones entre variables con nombres ambiguos (amount, value, balance)
    - Integración de múltiples tokens con diferentes decimales (USDC 6, WETH 18, etc.)
    - Thresholds que no escalan con el token (1e18 hardcoded para USDC = $1T)
  como_se_arregla: |
    Normalizar siempre a una unidad común (USD con 18 decimales) antes de comparar.
    Usar comentarios explícitos: // in 18-decimal WAD, // in token-native decimals.
    Calcular thresholds dinámicamente: minAmount = threshold * 10**token.decimals().
  trampas:
    - El bug puede tener impacto mínimo si sólo afecta la frecuencia de rebalance.
    - Revisar si el rebalance excesivo genera fees que sí son material (slippage acumulado).
  solodit_ids: [737]
  incidentes:
    - "Strategy rebalance (Solodit #737) — wrong unit comparison hace rebalance nunca/siempre activarse"
```

---

## 9. External Protocol DoS Bloquea Estrategia

```yaml
- id: yva-009
  titulo: Protocolo externo puede griefear harvest cobrando fee inesperado o revirtiendo
  causa_raiz: |
    Estrategias que llaman a protocolos externos en harvest() (GMX, Synthetix, etc.) pueden
    ser bloqueadas si el protocolo externo: (1) cobra un fee en ETH que no se envía, (2) emite
    eventos de UI cost que requieren pagos, o (3) cambia una interfaz sin aviso.
    Si harvest() revierte, los rewards se acumulan sin reclamarse → dilución del APY.
  como_funciona: |
    1. GMX introduce execution fee en claimRewards() — requiere msg.value > 0.
    2. Estrategia llama claimRewards() sin enviar ETH → revert.
    3. Keeper no puede harvester → CRV/GMX rewards se acumulan sin convertir.
    4. Si la estrategia tiene reward expiry, los rewards caducan sin reclamarse.
    5. Usuarios pierden yield esperado.
  invariante: |
    Invariante de liveness: harvest() no debe revertir bajo condiciones normales del protocolo.
    Corolario: no asumir interfaces externas inmutables — usar versiones con try/catch.
  que_mirar:
    - harvest() que llama directamente a protocolos externos sin try/catch
    - Claim functions que requieren ETH (msg.value) no enviado
    - Integración con GMX V2, Synthetix Perps, o cualquier protocolo con fees dinámicos
    - Ausencia de emergencyHarvest() que puede saltarse un protocolo fallido
  como_se_arregla: |
    Envolver llamadas externas en try/catch: si falla, continuar sin los rewards ese bloque.
    Añadir msg.value forwarding cuando el protocolo requiera fees.
    Implementar harvest con flag skipExternalClaim para situaciones de emergencia.
  trampas:
    - El DoS puede ser temporal (protocolo en mantenimiento) — no siempre es un bug de la estrategia.
    - Verificar si el protocolo externo tiene una ruta alternativa de claim sin fee.
  solodit_ids: [27593]
  incidentes:
    - "GMX V2 strategy (Solodit #27593) — execution fee en claimRewards() bloquea harvest"
```

---

## 10. Harvest Sandwich — minAmountOut Zero en Swap

```yaml
- id: yva-010
  titulo: Harvest sandwich: swap sin slippage protection (minAmountOut = 0)
  causa_raiz: |
    El harvest de muchas estrategias incluye un swap de recompensas (CRV, AERO, ARB) a
    activos del vault (USDC, WETH). Si el swap se ejecuta con minAmountOut=0 o sin deadline,
    un MEV bot puede sandwichear la transacción y extraer casi todo el valor del swap.
    Esto no requiere flash loan — sólo frontrunning estándar en el mempool.
  como_funciona: |
    1. Keeper publica harvest() que venderá 50k CRV por ~35k USDC en Uniswap.
    2. MEV bot ve la tx en mempool → frontrun: compra CRV → precio sube 20%.
    3. harvest() ejecuta con precio inflado → recibe sólo 28k USDC (20% menos).
    4. MEV bot backrun: vende CRV → precio normaliza → MEV bot gana ~7k USDC.
    5. Vault registra profit de 28k en vez de 35k → ~20% del yield extraído por MEV.
  invariante: |
    require(amountOut >= minAmountOut && minAmountOut > 0, "no slippage protection");
    minAmountOut debe ser >= 95% del valor de mercado calculado con oracle.
  que_mirar:
    - Swap calls con minAmountOut = 0 o minAmountOut hardcoded muy bajo
    - swap() o exactInputSingle() sin parámetro de deadline
    - harvest() callable por cualquiera sin parámetro de slippage
    - Reward tokens de alta liquidez (CRV, CVX, AERO) — más atractivos para MEV
  como_se_arregla: |
    Usar CowSwap o 1inch Fusion para harvest off-chain con orden limit.
    O: require keeper a calcular minAmountOut off-chain y pasarlo como argumento.
    O: usar Chainlink para validar precio razonable antes del swap.
    Deadline obligatorio: block.timestamp + 30 (o más corto).
  trampas:
    - En L2 (Optimism, Base), el MEV es mucho menor — el impacto puede ser bajo.
    - Chains con builders privados (Flashbots) reducen pero no eliminan el riesgo.
    - "Keeper trusteed" puede mitigar pero no si el keeper es un contrato público.
  solodit_ids: [29988]
  incidentes:
    - "Yearn harvest (Solodit #29988) — minAmountOut=0 en reward swap — sandwich extracts yield"
```

---

## 11. HarvestFees Empuja Deuda Sobre Borrow Cap

```yaml
- id: yva-011
  titulo: harvestFees() incrementa deuda por encima del borrow cap — DoS del vault
  causa_raiz: |
    Estrategias integradas con protocolos de lending (Aave, Compound) que realizan un
    borrow dentro de harvestFees() pueden empujar el total borrowed del protocolo sobre
    su borrow cap. Si la tx que desencadena esto es el harvest del vault, el harvest revierte
    y la estrategia queda sin poder procesar fees → acumulación de deuda no liquidable.
  como_funciona: |
    1. Aave tiene USDC borrow cap al 99% de utilización.
    2. Strategy.harvestFees() llama aave.borrow(USDC, feeAmount).
    3. feeAmount pequeño empuja el total borrowed sobre el cap → revert "BorrowCapExceeded".
    4. harvest() completo revierte → fees no procesados → estrategia no puede reportar profit.
    5. Si esta condición persiste, el vault queda en estado inconsistente (estrategia con profit
       nunca reportado → totalDebt desincronizado).
  invariante: |
    pre-harvest: assert(protocol.borrowedAmount + feeAmount <= protocol.borrowCap);
    alternativa: harvest() no debe hacer borrows — separar fee collection del borrow.
  que_mirar:
    - harvestFees() o harvest() que contienen llamadas a borrow() de protocolos externos
    - Integración con Aave V3 (tiene borrow caps activos) o Compound V3
    - Fee processing que depende de disponibilidad de liquidez externa
    - Ausencia de check previo: if (borrowCapRemaining < feeAmount) skip borrow
  como_se_arregla: |
    Antes del borrow, verificar que el cap no se excederá.
    Separar fee processing del harvest principal — si falla el fee, el harvest continúa.
    Usar un mecanismo de fee acumulación sin borrow inmediato.
  trampas:
    - Borrow caps en Aave V3 cambian con governance — el check puede pasar hoy y fallar mañana.
    - Puede ser un edge case raro si el borrow cap es generoso — calcular probabilidad real.
  solodit_ids: [3513]
  incidentes:
    - "Yearn V3 strategy (Solodit #3513) — harvestFees borrow excede Aave V3 borrow cap → DoS vault"
```

---

## Attack Scenarios Summary

| ID | Attack | Severity | Likelihood |
|----|--------|----------|------------|
| yva-001 | Share inflation primer depósito | Critical | High (si no hay seed) |
| yva-002 | Loss contabilizado como 0 | High | Medium |
| yva-003 | Strategy failure bloquea retiros | High | Medium |
| yva-004 | aToken rebasing rompe accounting | High | High (frecuente) |
| yva-005 | slot0 manipulation en rebalance | Medium | Medium |
| yva-006 | Harvest sandwich via Curve flash | Medium | Medium |
| yva-007 | Migration parcial bloquea fondos | High | Low |
| yva-008 | Wrong unit comparison en rebalance | Medium | Low |
| yva-009 | External protocol DoS harvest | Medium | Medium |
| yva-010 | minAmountOut=0 harvest sandwich | Medium | High (muy frecuente) |
| yva-011 | Borrow cap exceeded en harvestFees | Medium | Low |

## Key Protocols to Check

- **Yearn V2/V3**: BaseStrategy, TokenizedStrategy, VaultV3
- **Beefy**: StrategyCommonChefLP, BeefyVaultV7
- **Convex/Curve**: BaseRewardPool integration
- **Arrakis/Gamma**: UniV3 position management
- **GMX V2**: GlvReader, ExchangeRouter fee patterns
