grep_targets:
  - "GLP"
  - "glpManager"
  - "mintAndStakeGlp"
  - "getAum"
  - "getPoolAmount"
  - "poolAmount"
  - "reservedAmounts"
  - "guaranteedUsd"
  - "globalShortSizes"
  - "getPrice"
  - "vaultTokenPrice"
  - "sharePrice"
  - "depositVault"
  - "withdrawalVault"
  - "MarketPoolValueInfo"
  - "getPoolValueInfo"
  - "openInterestInTokens"
  - "cooldownDuration"
  - "lastAddedAt"
  - "cumulativeFundingRate"
  - "autoDeleverage"
  - "ADL"
  - "maxUtilization"
  - "performanceFee"
  - "managementFee"
  - "traderPnl"
  - "deltaHedge"
  - "rebalance"
  - "compoundRewards"
  - "harvest"

# Briefing: Perpetual DEX Vaults — LP/Vault Side Patterns

## Contexto del dominio
Los protocolos de perpetuos estilo GMX/GLP usan un modelo donde los LPs depositan en un vault (GLP, GM, MUXLP, gDAI) que actua como contraparte de todos los traders. El vault gana fees de trading pero asume el riesgo de PnL adverso de los traders. Los bugs mas criticos en el LADO VAULT incluyen:
- Manipulacion del precio del vault token (GLP/GM share price) para extraer valor de LPs
- Errores en AUM que incluyen PnL no realizado incorrectamente, inflando/desinflando shares
- Front-running de depositos/retiros alrededor de eventos de PnL conocidos
- Bypass de cooldowns de deposito/retiro via transferencia del vault token
- Fee accounting incorrecto (management/performance fees sobre base incorrecta)
- Liquidation proceeds que no se distribuyen correctamente a vault depositors
- Keeper/executor MEV en la ejecucion de ordenes de deposito/retiro

**Nota**: Los patrones de TRADING (mark price, funding rate, liquidacion de posiciones) estan en `perps-derivatives.md`. Este briefing cubre exclusivamente la superficie VAULT/LP.

---

patterns:

## 1. GLP/GM Share Price Manipulation via Donation

```yaml
- id: pv-001
  titulo: Share price inflation del vault token via donacion directa o PnL manipulation
  causa_raiz: |
    El precio del vault token (GLP, GM, MUXLP) se calcula como AUM / totalSupply.
    Si un atacante puede incrementar AUM sin incrementar totalSupply (donacion directa
    de tokens al pool, o manipulacion de PnL no realizado que infla AUM), puede inflar
    el precio del share. Esto permite al atacante mint shares baratas antes, y redeem
    caras despues, o causar que nuevos depositors reciban 0 shares (first depositor attack).
  como_funciona: |
    1. Atacante deposita cantidad minima en el vault → recibe shares a precio normal
    2. Atacante transfiere tokens directamente al contrato del pool (bypass de deposit())
       o abre una posicion que genera PnL favorable inmediato que infla AUM
    3. AUM sube pero totalSupply no cambia → precio por share se infla
    4. Nuevo depositante deposita Y tokens → shares = Y * totalSupply / AUM ≈ 0
    5. Atacante redeem sus shares originales → recibe su deposito + fondos de la victima
  invariante: |
    // AUM no debe cambiar mas de X% en un solo bloque sin mint/burn correspondiente
    function check_aum_share_consistency() internal {
        uint256 aumBefore = vault.getAum(true);
        uint256 supplyBefore = glp.totalSupply();
        // After any deposit/donation
        uint256 aumAfter = vault.getAum(true);
        uint256 supplyAfter = glp.totalSupply();
        if (supplyBefore > 0 && supplyAfter == supplyBefore) {
            uint256 aumChangeBps = aumAfter > aumBefore
                ? ((aumAfter - aumBefore) * 10000) / aumBefore
                : 0;
            t(aumChangeBps <= 100, "PV-001: AUM changed >1% without supply change");
        }
    }
  que_mirar:
    - "¿El vault acepta transferencias directas de tokens sin mint de shares?"
    - "¿getAum() o getPoolValue() incluye balance real del contrato o solo tracked amounts?"
    - "¿Hay virtual shares/offset en el primer deposito?"
    - "¿poolAmount se actualiza solo via deposit/withdraw o tambien via transfer directo?"
  como_se_arregla: |
    - Usar tracked amounts internos en vez de balanceOf() para calcular AUM
    - Implementar virtual shares/assets offset (a la ERC4626 de OpenZeppelin)
    - Minimo de shares quemadas en primer deposito (dead shares)
    - Separar donaciones accidentales via sweep() que no afecta AUM
  trampas:
    - "GMX v1 usa poolAmount tracking interno, NO balanceOf — verificar si el vault especifico trackea internamente"
    - "La inflacion via PnL no realizado es mas sutil que donacion directa — requiere posicion de trading activa"
    - "Algunos vaults tienen minFirstDeposit que mitiga parcialmente"
  solodit_ids:
    - h-1-wnt-in-depositvault-can-be-drained-by-abusing-initiallongtokeninitialshorttoken-of-createdepositparams-sherlock-none-gmx-git
    - first-deposit-attack-via-share-price-manipulation-zokyo-none-vaultka-markdown
    - h-1-marketutilsgetpoolvalueinfo-does-not-use-maximize-when-evaluating-impactpoolusd-leading-to-wrong-logic-of-sherlock-none-gmx-update-git
    - mktu-1-pool-value-with-inverse-pnl-guardian-audits-none-gmx-markdown
  incidentes:
    - "Vaultka (Zokyo 2023) — share price manipulation via first deposit on GMX GM vault wrapper"
    - "SteadeFi (CodeHawks 2023) — GMX vault wrapper incorrect share pricing after fee mint"
  verificado: true
  confianza: alta
```

---

## 2. Trader PnL Socialization — Guaranteed Profit at LP Expense

```yaml
- id: pv-002
  titulo: Trader abre posicion de profit garantizado que socializa perdidas a vault LPs
  causa_raiz: |
    En modelos vault-as-counterparty (GLP), los traders profitable extraen valor
    directamente del vault. Si un atacante puede abrir una posicion con profit
    garantizado (e.g., usando oracle manipulation, same-block pricing, o arbitraje
    de price gaps entre oracle update y execution), las ganancias del trader
    se restan del AUM del vault, causando perdida directa a todos los LPs.
  como_funciona: |
    1. Atacante observa un movimiento de precio inminente (MEV, oracle update pendiente)
    2. Abre posicion long/short en la direccion favorable ANTES del update
    3. El keeper ejecuta la orden usando el precio pre-update (same-block pricing)
    4. El precio se actualiza → la posicion del atacante esta en profit inmediato
    5. Atacante cierra posicion → profit sale del pool del vault → AUM baja
    6. Todos los LPs sufren perdida proporcional via reduccion del precio de su share
  invariante: |
    // El PnL neto de todas las posiciones no debe exceder un % del AUM total
    function check_pnl_vs_aum() internal {
        int256 totalTraderPnl = vault.getGlobalPnl(true);
        uint256 aum = vault.getAum(false); // min AUM
        if (totalTraderPnl > 0) {
            // Traders in profit shouldn't exceed X% of AUM
            uint256 pnlBps = (uint256(totalTraderPnl) * 10000) / aum;
            t(pnlBps <= 5000, "PV-002: trader PnL exceeds 50% of AUM");
        }
    }
  que_mirar:
    - "¿Las ordenes se ejecutan con el precio del bloque de creacion o del bloque de ejecucion?"
    - "¿Hay un minDelay entre creacion y ejecucion de ordenes?"
    - "¿El price impact penaliza posiciones que explotan gaps de precio?"
    - "¿Hay ADL (auto-deleverage) cuando el PnL de traders supera un umbral?"
    - "¿El vault tiene max utilization que limita cuanto pueden ganar los traders?"
  como_se_arregla: |
    - Ejecutar ordenes con precio del bloque de ejecucion (no creacion)
    - Implementar minExecutionDelay (GMX v2 usa 1-2 bloques minimo)
    - Price impact que penaliza posiciones grandes unidireccionales
    - ADL automatico cuando PnL de traders excede X% del pool
    - maxPnlFactor por market que limita profit maximo por posicion
  trampas:
    - "Same-block pricing es el vector principal — si se fuerza delay, el ataque se mitiga sustancialmente"
    - "El PnL socialization es by-design en GLP — el bug es cuando se puede GARANTIZAR profit"
    - "ADL puede proteger el vault pero introduce su propio set de problemas (ver pv-008)"
  solodit_ids:
    - ordu-1-limit-increase-with-same-block-pricing-guardian-audits-none-gmx-markdown
    - h-21-creating-an-order-of-type-marketincrease-opens-an-attack-vector-where-attacker-can-execute-txs-with-stale-sherlock-none-gmx-git
    - h-7-limit-orders-are-broken-when-there-are-price-gaps-sherlock-none-gmx-git
    - global-4-arbitrage-attack-guardian-audits-none-gmx-markdown
  incidentes:
    - "GMX v1 (Sept 2022) — $565K explotados via oracle manipulation + zero-slippage trades contra GLP"
    - "Avraham Eisenberg vs GMX (Sept 2022) — intento de exploit de $30M+ contra GLP via OI manipulation"
  verificado: true
  confianza: alta
```

---

## 3. Vault Deposit Front-Running — Timing Attacks on PnL Events

```yaml
- id: pv-003
  titulo: Front-running de depositos antes de PnL favorable para capturar ganancias
  causa_raiz: |
    En un vault perpetuo, el precio del share cambia con cada trade que cierra
    (PnL del trader afecta AUM). Si un atacante puede depositar JUSTO ANTES de que
    un trade perdedor se cierre (loss del trader = gain del vault), captura una porcion
    de esas ganancias sin haber tenido exposicion al riesgo previo. Inversamente,
    puede retirar justo antes de que un trade ganador se cierre.
  como_funciona: |
    1. Atacante monitorea el mempool para ordenes de cierre de posiciones en loss
    2. Cuando detecta una posicion grande a punto de cerrar con loss (= profit para vault)
    3. Front-runs con deposito masivo al vault → recibe shares a precio pre-loss
    4. El trade cierra, el loss del trader incrementa AUM, el share price sube
    5. Atacante retira inmediatamente → captura porcion del loss del trader
    6. Los LPs originales reciben menos de lo que les corresponderia
  invariante: |
    // Depositos y retiros no deben poder ejecutarse en el mismo bloque
    // El cooldown minimo debe ser >0
    function check_deposit_cooldown() internal {
        uint256 cooldown = glpManager.cooldownDuration();
        t(cooldown > 0, "PV-003: zero cooldown allows same-block deposit/withdraw");
        // Verificar que lastAddedAt se actualiza correctamente
        uint256 lastAdded = glpManager.lastAddedAt(address(this));
        if (lastAdded > 0) {
            t(block.timestamp >= lastAdded + cooldown, "PV-003: cooldown not enforced");
        }
    }
  que_mirar:
    - "¿Hay cooldownDuration entre mint y redeem del vault token?"
    - "¿El cooldown es configurable a 0 por admin?"
    - "¿lastAddedAt se resetea en transferencias?"
    - "¿Se puede depositar y retirar en la misma transaccion via flash loan?"
    - "¿Las ordenes de deposito/retiro son 2-step (request + execute)?"
  como_se_arregla: |
    - Cooldown obligatorio entre deposit y withdraw (GMX v1: 15 min minimo)
    - Sistema 2-step: createDeposit() → keeper executeDeposit() despues de N bloques
    - Usar precio promedio del share durante el periodo de cooldown
    - Entry/exit fees que penalizan operaciones de corto plazo
  trampas:
    - "GMX v2 usa sistema 2-step con keeper, lo que mitiga significativamente"
    - "El cooldown en GMX v1 es por direccion — si se transfiere GLP, el cooldown del receptor es 0"
    - "Las fees de entrada/salida (0.2-0.4%) hacen el ataque unprofitable para movimientos chicos"
  solodit_ids:
    - h-6-malicious-keepers-can-manipulate-the-price-when-executing-an-order-sherlock-flatmoney-git
    - m-6-delayed-orders-wont-use-correct-prices-sherlock-none-gmx-git
    - vaultdeposit-possible-front-running-attack-consensys-brahma-fi-markdown
  incidentes:
    - "GMX v1 (2022-2023) — front-running de depositos GLP documentado multiples veces, mitigado con cooldown de 15 min"
    - "FlatMoney (Sherlock 2024) — keeper price manipulation en ejecucion de ordenes"
  verificado: true
  confianza: alta
```

---

## 4. AUM Calculation Mismatch — Unrealized PnL Inclusion Errors

```yaml
- id: pv-004
  titulo: AUM incluye PnL no realizado incorrectamente, inflando o desinflando shares
  causa_raiz: |
    El AUM del vault se calcula como: sum(poolAmounts) + unrealizedPnL(traders).
    Si el unrealized PnL se calcula mal (usa max vs min price incorrectamente,
    no incluye funding fees acumulados, o double-counts borrowing fees), el precio
    del share se distorsiona. Los deposits/withdrawals al precio incorrecto causan
    transferencia de valor entre LPs.
  como_funciona: |
    1. El vault calcula AUM para determinar precio de mint/redeem de shares
    2. getAum() incluye unrealized PnL de posiciones abiertas, pero usa el precio
       incorrecto (maximize=true cuando deberia ser false, o viceversa)
    3. Para DEPOSITS, AUM deberia maximizarse (LP recibe menos shares = proteccion del vault)
    4. Para WITHDRAWALS, AUM deberia minimizarse (LP recibe menos tokens = proteccion del vault)
    5. Si la logica esta invertida o es constante, se puede explotar:
       - Depositar cuando AUM esta minimizado artificialmente → shares baratas
       - Retirar cuando AUM esta maximizado artificialmente → tokens extra
  invariante: |
    // AUM para mint debe ser >= AUM para redeem
    function check_aum_maximize_minimize() internal {
        uint256 aumMax = vault.getAum(true);  // maximize = true
        uint256 aumMin = vault.getAum(false); // maximize = false
        t(aumMax >= aumMin, "PV-004: max AUM < min AUM inconsistency");
        // La diferencia no debe ser absurda
        if (aumMin > 0) {
            uint256 spreadBps = ((aumMax - aumMin) * 10000) / aumMin;
            t(spreadBps <= 500, "PV-004: AUM spread >5% indicates pricing issue");
        }
    }
  que_mirar:
    - "¿getAum(maximize) se usa consistentemente — maximize para deposits, minimize para withdrawals?"
    - "¿El PnL no realizado incluye borrowing fees y funding fees acumulados?"
    - "¿getPoolValueInfo incluye impactPoolAmount correctamente?"
    - "¿Los global shorts se valuan con max o min price segun el contexto?"
    - "¿guaranteedUsd se calcula correctamente para posiciones long?"
  como_se_arregla: |
    - Siempre usar maximize=true para calcular shares en deposits (LP recibe menos)
    - Siempre usar maximize=false para calcular tokens en withdrawals (LP recibe menos)
    - Auditar que getAum incluye todos los componentes: poolAmounts, guaranteedUsd, globalShortPnl
    - Test exhaustivo de edge cases: todos los traders en profit, todos en loss, pool vacio
  trampas:
    - "GMX v1 getAum tiene 2 paths (maximize true/false) — ambos deben ser consistentes"
    - "El impact pool en GMX v2 debe incluirse/excluirse segun contexto"
    - "guaranteedUsd tracking puede acumular error de redondeo en miles de operaciones"
  solodit_ids:
    - h-14-pool-value-calculation-uses-wrong-portion-of-the-borrowing-fees-sherlock-none-gmx-git
    - h-1-marketutilsgetpoolvalueinfo-does-not-use-maximize-when-evaluating-impactpoolusd-leading-to-wrong-logic-of-sherlock-none-gmx-update-git
    - mktu-1-pool-value-with-inverse-pnl-guardian-audits-none-gmx-markdown
    - h-11-differences-between-actual-and-cached-total-assets-can-be-arbitraged-sherlock-tokemak-git
  incidentes:
    - "GMX v2 Sherlock (2023) — pool value calculation uses wrong portion of borrowing fees (H-14)"
    - "GMX v2 Update (2023) — getPoolValueInfo does not use maximize for impactPoolUsd (H-1)"
  verificado: true
  confianza: alta
```

---

## 5. Withdrawal During High Utilization — Liquidity Drain

```yaml
- id: pv-005
  titulo: Retiro de vault shares cuando el capital esta comprometido como margen
  causa_raiz: |
    Cuando la mayoria del capital del vault esta siendo usado como contraparte
    de posiciones abiertas (alta utilizacion), los LPs no pueden retirar porque
    no hay liquidez disponible. Peor aun, si el vault permite retiros parciales
    sin verificar utilization caps, los ultimos LPs quedan atrapados asumiendo
    riesgo desproporcionado con capital insuficiente para cubrir posiciones.
  como_funciona: |
    1. Vault tiene 100M de AUM, 90M comprometido en posiciones abiertas (90% utilizacion)
    2. LP grande solicita retiro de 8M → vault solo tiene 10M disponible
    3. Si el retiro se permite, vault queda con 2M disponible para 90M en posiciones
    4. Si los traders cierran en profit, vault no tiene fondos para pagar → insolvencia
    5. Los LPs restantes asumen todo el riesgo con capital insuficiente
    6. Alternativamente: si se bloquea el retiro, los LPs quedan trapped
  invariante: |
    // Despues de un withdrawal, el vault debe mantener minimo reserveRatio
    function check_utilization_after_withdraw() internal {
        uint256 poolAmount = vault.poolAmounts(token);
        uint256 reserved = vault.reservedAmounts(token);
        if (poolAmount > 0) {
            uint256 utilizationBps = (reserved * 10000) / poolAmount;
            t(utilizationBps <= 9000, "PV-005: utilization >90% after withdrawal");
        }
    }
  que_mirar:
    - "¿Hay maxUtilization check en el path de withdrawal?"
    - "¿reservedAmounts se actualiza atomicamente con poolAmounts?"
    - "¿Se puede manipular utilization (abrir posiciones masivas) para bloquear withdrawals?"
    - "¿Hay un mecanismo de withdrawal queue para alta utilizacion?"
    - "¿Los LPs grandes pueden salir antes que los pequenos (FIFO vs pro-rata)?"
  como_se_arregla: |
    - Max utilization check en withdrawals (e.g., no permitir retiro si utilization > 80%)
    - Withdrawal queue con pro-rata distribution del capital disponible
    - Fee de retiro dinamica que sube con la utilizacion (incentiva depositos, desincentiva retiros)
    - ADL automatico que cierra posiciones de traders cuando utilization > umbral
  trampas:
    - "Un atacante podria manipular utilization abriendo posiciones grandes JUSTO antes de que los LPs quieran retirar"
    - "La fee dinamica puede ser insuficiente si el delta de utilizacion es grande en un solo bloque"
    - "El retiro bloqueado es un DoS para LPs — que puede ser un finding en si mismo"
  solodit_ids:
    - pool-token-value-is-not-checked-against-total-short-size-when-withdrawing-potentially-resulting-in-widespread-sherlock-none-level-finance-markdown
    - short-positions-are-not-limited-leading-to-potential-protocol-break-quantstamp-level-finance-markdown
    - trst-m-1-small-lp-providers-may-be-unable-to-withdraw-their-deposits-trust-security-none-lyra-finance-markdown
  incidentes:
    - "Level Finance (Quantstamp 2023) — pool token value not checked vs total short size on withdrawal"
    - "Lyra Finance (Trust Security 2023) — small LPs unable to withdraw deposits"
  verificado: true
  confianza: alta
```

---

## 6. Position Size vs Vault Capacity — Reserve Exhaustion

```yaml
- id: pv-006
  titulo: Una sola posicion de trader excede la capacidad disponible del vault
  causa_raiz: |
    El vault tiene un pool finito. Si una posicion individual (o la suma de posiciones
    en una direccion) excede la capacidad del pool, el vault queda insolvente ante
    un movimiento adverso. Los checks de reservedAmounts / maxGlobalLongSize /
    maxGlobalShortSize deben prevenir esto, pero errores en su implementacion
    permiten posiciones que superan la capacidad real.
  como_funciona: |
    1. Vault tiene poolAmount = 10M USDC
    2. Trader abre long de 50M con 10x leverage (5M collateral)
    3. Si maxGlobalLongSize no esta configurado o el check tiene un bug,
       la posicion se acepta
    4. Si el precio sube 20%, el trader tiene 10M de profit
    5. Pero el vault solo tiene 10M → no puede pagar el profit completo
    6. Los LPs pierden todo su capital, el trader no recibe su profit completo
  invariante: |
    // reservedAmounts nunca debe exceder poolAmount
    function check_reserve_ratio() internal {
        address[] memory tokens = vault.allWhitelistedTokens();
        for (uint i = 0; i < tokens.length; i++) {
            uint256 pool = vault.poolAmounts(tokens[i]);
            uint256 reserved = vault.reservedAmounts(tokens[i]);
            t(reserved <= pool, "PV-006: reserved exceeds pool amount");
        }
    }
  que_mirar:
    - "¿Hay maxGlobalLongSize / maxGlobalShortSize por market?"
    - "¿reservedAmounts se incrementa al abrir posicion y decrementa al cerrar?"
    - "¿El check reservedAmounts <= poolAmount se hace ANTES de aceptar la posicion?"
    - "¿Se puede bypasear el check con multiples posiciones pequenas?"
    - "¿Los guaranteed USD se cuentan correctamente contra el pool?"
  como_se_arregla: |
    - Enforce reservedAmounts <= poolAmount * maxUtilizationBps / 10000
    - maxGlobalLongSize y maxGlobalShortSize por market configurados y enforced
    - Open interest caps que limitan exposicion total del vault
    - Verificar que los caps se aplican DESPUES de sumar la nueva posicion
  trampas:
    - "GMX v1 tiene estos checks pero Level Finance no los tenia inicialmente"
    - "Los caps per-market no protegen si la correlacion entre markets es alta"
    - "guaranteedUsd tracking en longs necesita ser preciso para que los caps funcionen"
  solodit_ids:
    - short-positions-are-not-limited-leading-to-potential-protocol-break-quantstamp-level-finance-markdown
    - liquidity-can-be-drained-through-price-manipulation-quantstamp-level-finance-markdown
    - updating-a-marketconfig-can-break-reserve-accounting-cantina-none-hmx-pdf
    - global-4-arbitrage-attack-guardian-audits-none-gmx-markdown
  incidentes:
    - "Level Finance (Quantstamp 2023) — short positions not limited, protocol break risk"
    - "Level Finance (2023-05) — $1.1M exploit via referral abuse (related to position/pool imbalance)"
  verificado: true
  confianza: alta
```

---

## 7. Keeper/Executor Price Manipulation

```yaml
- id: pv-007
  titulo: Keeper malicioso manipula precio de ejecucion de ordenes vault
  causa_raiz: |
    En sistemas 2-step (GMX v2, FlatMoney), los keepers ejecutan ordenes
    de deposit/withdraw despues de un delay. Si el keeper puede elegir
    CUANDO ejecutar (dentro de una ventana), puede seleccionar el momento
    con precio mas favorable para si mismo o para un complice, a costa
    de los demas LPs.
  como_funciona: |
    1. LP crea orden de deposito cuando share price = $1.00
    2. El keeper tiene ventana de N bloques para ejecutar la orden
    3. Keeper espera hasta que un trade grande cierre con loss (precio sube a $1.05)
       o ejecuta justo antes de un trade profitable para traders (precio bajara)
    4. Si ejecuta deposito al precio bajo → el depositante recibe mas shares de las debidas
    5. Si ejecuta retiro al precio alto → el retirador recibe mas tokens de los debidos
    6. En ambos casos, los LPs existentes sufren dilucion o perdida
  invariante: |
    // El precio de ejecucion no debe divergir significativamente del precio de solicitud
    function check_execution_price_deviation() internal {
        // Compare price at request time vs execution time
        uint256 requestPrice = order.requestSharePrice;
        uint256 executionPrice = vault.getSharePrice();
        uint256 deviationBps;
        if (executionPrice > requestPrice) {
            deviationBps = ((executionPrice - requestPrice) * 10000) / requestPrice;
        } else {
            deviationBps = ((requestPrice - executionPrice) * 10000) / requestPrice;
        }
        t(deviationBps <= 200, "PV-007: execution price deviates >2% from request");
    }
  que_mirar:
    - "¿El keeper puede elegir el bloque de ejecucion dentro de una ventana?"
    - "¿Las ordenes usan el precio del bloque de solicitud o del bloque de ejecucion?"
    - "¿Hay un maxExecutionDelay despues del cual la orden se cancela?"
    - "¿El keeper recibe incentivo por ejecutar rapidamente?"
    - "¿Las ordenes tienen slippage protection (minOut / maxSharePrice)?"
  como_se_arregla: |
    - Forzar ejecucion en el bloque inmediatamente siguiente al delay minimo
    - Usar oracle price del momento de solicitud (no ejecucion) para el calculo de shares
    - Slippage protection en depositos y retiros (minShares / minTokensOut)
    - Keeper rotation o keeper descentralizado
  trampas:
    - "En GMX v2, el keeper malicioso es mitigado parcialmente por el minExecutionDelay"
    - "Si hay slippage protection, el ataque causa revert (no loss) — pero puede ser un DoS"
    - "El keeper puede ser el propio protocolo (centralizado) lo cual cambia el threat model"
  solodit_ids:
    - h-6-malicious-keepers-can-manipulate-the-price-when-executing-an-order-sherlock-flatmoney-git
    - h-6-keepers-can-be-forced-to-waste-gas-with-long-revert-messages-sherlock-none-gmx-git
    - m-2-m-01-incorrect-refund-of-execution-fee-to-user-sherlock-none-gmx-git
    - h-3-underestimated-gas-estimation-for-executing-withdrawals-leads-to-insufficient-keeper-compensation-sherlock-none-gmx-git
  incidentes:
    - "FlatMoney (Sherlock 2024) — malicious keeper price manipulation (H-6)"
    - "GMX v2 (Sherlock 2023) — keeper gas waste griefing (H-6)"
  verificado: true
  confianza: alta
```

---

## 8. ADL (Auto-Deleverage) Slippage and Ordering Issues

```yaml
- id: pv-008
  titulo: ADL operations sin slippage protection o con ordering incorrecto
  causa_raiz: |
    Cuando el PnL acumulado de traders excede un umbral del pool, el protocolo
    auto-cierra posiciones rentables (ADL) para proteger la solvencia del vault.
    Si las operaciones ADL no tienen slippage protection, o usan el wrong block
    number para tracking, los traders afectados sufren perdidas injustas y
    el vault puede quedar en estado inconsistente.
  como_funciona: |
    1. Pool tiene maxPnlFactor = 50% del AUM
    2. Traders acumulan profit > 50% del AUM → se activa ADL
    3. El sistema cierra posiciones rentables forzosamente
    4. Sin slippage protection: trader con 100K profit puede recibir 80K
       (el resto queda en el pool como "ahorro" para otros LPs)
    5. Con wrong block tracking (e.g., Arbitrum block vs L1 block):
       ADL se ejecuta en un periodo incorrecto, o no se ejecuta cuando deberia
  invariante: |
    // ADL debe respetar el precio de mercado ± spread razonable
    function check_adl_fairness() internal {
        // Post-ADL: el PnL del pool debe estar dentro de limites
        int256 pnl = market.getNetPnl(true);
        uint256 poolValue = market.getPoolValue(false);
        if (pnl > 0 && poolValue > 0) {
            uint256 pnlRatioBps = (uint256(pnl) * 10000) / poolValue;
            t(pnlRatioBps <= 5000, "PV-008: PnL ratio exceeds 50% post-ADL");
        }
    }
  que_mirar:
    - "¿Las operaciones ADL tienen slippage protection para el trader afectado?"
    - "¿El tracking de latestADLBlock usa block.number correcto (L1 vs L2)?"
    - "¿El order de cierre de posiciones en ADL es justo (mayor profit primero)?"
    - "¿ADL puede ser triggered por un atacante manipulando PnL temporalmente?"
    - "¿El keeper de ADL tiene incentivos alineados?"
  como_se_arregla: |
    - Slippage protection en ADL (minOut para el trader afectado)
    - Usar el block.number correcto para la chain (Arbitrum: ArbSys.arbBlockNumber())
    - ADL order: cerrar posiciones mas rentables primero (LIFO por profit)
    - Cooldown entre ADL events para prevenir manipulation
  trampas:
    - "En Arbitrum, block.number devuelve el L1 block — no el L2 block"
    - "ADL es un mecanismo de proteccion del vault — los traders ADL'd tienen un reclamo valido pero el protocolo prioriza solvencia"
    - "No todo ADL es un bug — el bug es cuando ADL ocurre injustamente o con parametros incorrectos"
  solodit_ids:
    - h-4-tracking-of-the-latest-adl-block-use-the-wrong-block-number-on-arbitrum-sherlock-none-gmx-git
    - h-5-adl-operations-do-not-have-any-slippage-protection-sherlock-none-gmx-git
    - m-1-if-block-range-it-big-and-adl-dosnt-use-currentblock-in-the-order-it-will-cause-issues-sherlock-none-gmx-git
  incidentes:
    - "GMX v2 (Sherlock 2023) — ADL uses wrong block number on Arbitrum (H-4)"
    - "GMX v2 (Sherlock 2023) — ADL no slippage protection (H-5)"
  verificado: true
  confianza: alta
```

---

## 9. Multi-Asset Vault Rebalancing Exploit

```yaml
- id: pv-009
  titulo: Explotacion de triggers de rebalanceo en vaults multi-asset
  causa_raiz: |
    Vaults multi-asset (GLP, MUXLP) mantienen target weights para cada token
    en el pool. Cuando un token se desvia de su target weight, el vault ajusta
    fees (menor fee para depositos del token underweight, mayor fee para el
    overweight). Un atacante puede manipular los pesos para obtener fees
    reducidas o forzar swaps a precios favorables durante el rebalanceo.
  como_funciona: |
    1. GLP pool tiene target weights: ETH 25%, BTC 25%, USDC 50%
    2. Atacante deposita masivamente USDC → USDC queda overweight
    3. Las fees de swap USDC→ETH bajan (el pool quiere rebalancear)
    4. Atacante hace swap USDC→ETH con fees reducidas
    5. Luego deposita ETH (ahora underweight) con fees reducidas tambien
    6. El atacante obtiene mas GLP por la misma cantidad de capital
    7. Alternativamente: el atacante puede sandwich el rebalanceo de un keeper
  invariante: |
    // Los token weights no deben divergir mas de X% de sus targets despues de un solo tx
    function check_weight_deviation() internal {
        uint256 totalAum = vault.getAum(true);
        for (uint i = 0; i < tokens.length; i++) {
            uint256 tokenAum = vault.getTokenAum(tokens[i]);
            uint256 actualWeight = (tokenAum * 10000) / totalAum;
            uint256 targetWeight = vault.tokenWeights(tokens[i]);
            uint256 deviation = actualWeight > targetWeight
                ? actualWeight - targetWeight
                : targetWeight - actualWeight;
            t(deviation <= 1000, "PV-009: token weight deviates >10% from target");
        }
    }
  que_mirar:
    - "¿Las fees de swap dependen del impacto en los target weights?"
    - "¿Se puede manipular weights con un deposito grande y luego swap?"
    - "¿Hay max capacity per token que limita depositos del token overweight?"
    - "¿Los target weights se pueden cambiar por admin atomicamente?"
    - "¿El rebalanceo automatico (keeper) es sandwichable?"
  como_se_arregla: |
    - Fee dinamica exponencial que escala con la desviacion del target weight
    - Cap por token: no aceptar depositos de un token que ya supera su target weight
    - Rebalanceo atomico via keeper con slippage protection
    - Cooldown entre cambios de target weights por governance
  trampas:
    - "El arbitraje de weights es by-design hasta cierto punto — el vault QUIERE incentivos para rebalancear"
    - "El bug es cuando el arbitrajista puede extraer mas valor del que aporta al rebalanceo"
    - "Tokens con diferente decimals (USDC 6 vs WBTC 8) agregan complejidad de calculo"
  solodit_ids:
    - liquidity-can-be-drained-through-price-manipulation-quantstamp-level-finance-markdown
    - c-01-attacker-can-manipulate-the-protocols-aum-pashov-none-fyde-markdown
    - h-2-pool-amount-adjustments-for-collateral-decreases-arent-undone-if-swaps-are-successful-sherlock-none-gmx-update-git
  incidentes:
    - "Level Finance (Quantstamp 2023) — liquidity drain via price manipulation on multi-asset pool"
    - "Fyde Protocol (Pashov 2024) — AUM manipulation in multi-asset vault"
  verificado: true
  confianza: media
```

---

## 10. Funding Rate Manipulation via OI Imbalance Against Vault

```yaml
- id: pv-010
  titulo: Manipular OI skew para forzar funding payments del vault a traders
  causa_raiz: |
    En modelos donde el vault paga/recibe funding basado en el skew de
    open interest (longs vs shorts), un atacante puede abrir posiciones masivas
    en una direccion para forzar al vault a pagar funding. Si el vault es
    counterparty de todos los traders, un skew extreme significa que el vault
    paga funding neto a los traders en la direccion dominante.
  como_funciona: |
    1. El vault es counterparty de todas las posiciones (GLP model)
    2. Atacante abre posicion long masiva → OI long >> OI short
    3. El funding rate se ajusta: longs pagan shorts (y vault recibe como "short counterparty")
       O en algunos modelos: vault paga funding a longs porque el vault NECESITA shorts
    4. Si el modelo calcula funding incorrectamente o el vault paga del pool,
       el atacante drena funding del vault via sus posiciones long
    5. LPs sufren reduccion de AUM via funding payments mal direccionados
  invariante: |
    // El funding neto pagado/recibido por el vault debe ser consistente con el skew
    function check_funding_consistency() internal {
        int256 fundingPaid = vault.cumulativeFundingRate(token);
        uint256 longOI = vault.globalLongSizes(token);
        uint256 shortOI = vault.globalShortSizes(token);
        // Si longs > shorts, el vault (como counterparty short) deberia RECIBIR funding
        if (longOI > shortOI) {
            t(fundingPaid >= 0, "PV-010: vault paying funding when longs dominate");
        }
    }
  que_mirar:
    - "¿El funding rate se calcula sobre utilizacion (reserved/pool) o sobre OI skew?"
    - "¿El vault paga o recibe funding — o ambos segun la direccion?"
    - "¿Hay caps en el funding rate maximo por periodo?"
    - "¿El calculo de funding acumula error de redondeo?"
    - "¿Un atacante puede abrir/cerrar posiciones para manipular el funding rate snapshot?"
  como_se_arregla: |
    - Funding rate caps (max funding per hour/day)
    - Usar TWAP del skew para calcular funding (no instantaneo)
    - OI caps que limitan el skew maximo
    - Funding rate formula que converge suavemente, no lineal con el skew
  trampas:
    - "En GMX v1, el borrowing fee NO es funding — es fee unidireccional del trader al vault"
    - "En Synthetix/Kwenta, el funding rate SI es bidireccional basado en skew"
    - "Manipular skew requiere capital significativo — calcular costo del ataque vs beneficio"
  solodit_ids:
    - h-20-unpaid-funding-fees-from-wrong-calculation-are-going-to-be-substracted-from-the-pool-sherlock-none-gmx-git
    - funding-payments-are-made-in-the-wrong-token-trailofbits-increment-finance-increment-protocol-pdf
    - funding-rate-manipulation-1-sigmaprime-none-tracer-pdf
    - m-10-insufficient-funding-fee-rounding-protection-sherlock-none-gmx-git
  incidentes:
    - "GMX v2 (Sherlock 2023) — unpaid funding fees subtracted from pool (H-20)"
    - "Tracer (SigmaPrime 2022) — funding rate manipulation via skew"
    - "Increment Finance (Trail of Bits 2023) — funding payments in wrong token"
  verificado: true
  confianza: alta
```

---

## 11. Vault Fee Accounting Errors — Management/Performance Fee Miscalculation

```yaml
- id: pv-011
  titulo: Fees de management/performance calculadas sobre base incorrecta
  causa_raiz: |
    Los vaults cobran fees de management (% anual sobre AUM) y/o performance
    (% sobre profit). Si la base de calculo es incorrecta — e.g., performance fee
    sobre AUM total en vez de solo profit, o management fee que no descuenta
    unrealized losses — las fees extraen mas valor del debido de los LPs.
    Peor: si fees se acumulan sin mintear shares para el fee recipient,
    el share price se distorsiona.
  como_funciona: |
    1. Vault tiene AUM = 100M, performance fee = 20%
    2. Trader cierra posicion con loss de 5M → AUM sube a 105M (profit del vault)
    3. Bug: performance fee se calcula sobre AUM total (105M * 20% = 21M)
       en vez de sobre profit (5M * 20% = 1M)
    4. Fee recipient recibe 21M en shares → LPs pierden 21M en vez de 1M
    5. Alternativamente: si no hay high watermark, fees se cobran sobre
       recuperacion de loss previo (no profit real)
  invariante: |
    // Fees mintadas no deben exceder un % razonable del profit realizado
    function check_fee_reasonableness() internal {
        uint256 feeSharesMinted = vault.pendingFeeShares();
        uint256 totalShares = vault.totalSupply();
        if (totalShares > 0) {
            uint256 feeBps = (feeSharesMinted * 10000) / totalShares;
            // Management fee: max ~2% per year ≈ 0.005% per day
            // Performance fee: max 20% of profit ≈ variable
            t(feeBps <= 200, "PV-011: fee shares exceed 2% of total supply");
        }
    }
  que_mirar:
    - "¿La performance fee se calcula sobre profit neto o sobre AUM?"
    - "¿Hay high watermark para evitar cobrar fee sobre recuperacion de losses?"
    - "¿Las fees se mintean como shares nuevas (diluyendo) o se descuentan del AUM?"
    - "¿El fee accrual es continuo o discreto (por epoch)?"
    - "¿mintFee() se llama ANTES de deposits/withdrawals para no distorsionar el share price?"
  como_se_arregla: |
    - Performance fee SOLO sobre profit neto (high watermark obligatorio)
    - Management fee sobre AUM promedio del periodo, no snapshot
    - Llamar mintFee() antes de cada deposit/withdraw para mantener share price correcto
    - Cap maximo de fees por periodo para prevenir errores de calculo catastróficos
  trampas:
    - "Si mintFee() no se llama antes de deposit, el nuevo depositante paga fees de periodos anteriores"
    - "Los vaults con fee-on-transfer tokens tienen fee-sobre-fee que distorsiona el calculo"
    - "Algunos protocolos usan 'virtual shares' para fees que nunca se mintean — verificar consistency"
  solodit_ids:
    - h-05-uneven-deduction-of-performance-fee-causes-some-kangaroovault-users-to-lose-part-of-their-token-value-code4rena-polynomial-protocol-polynomial-protocol-contest-git
    - all-functions-that-burn-or-mint-shares-for-users-should-mintfee-for-protocol-before-codehawks-steadefi-git
    - h-02-wrong-implementation-of-performancefee-can-cause-users-to-lose-50-to-100-of-their-funds-code4rena-mellow-protocol-mellow-protocol-contest-git
    - the-keeper-management-fee-is-being-calculated-wrong-zokyo-none-vaultka-markdown
  incidentes:
    - "Polynomial Protocol (Code4rena 2023) — uneven performance fee deduction, KangarooVault users lose tokens"
    - "Mellow Protocol (Code4rena 2022) — wrong performanceFee causes 50-100% user fund loss"
    - "SteadeFi (CodeHawks 2023) — mintFee not called before share mint/burn"
    - "Vaultka (Zokyo 2023) — keeper management fee calculated wrong"
  verificado: true
  confianza: alta
```

---

## 12. Liquidation Proceeds Distribution to Vault Depositors

```yaml
- id: pv-012
  titulo: Liquidation profits no distribuidos correctamente a vault LPs
  causa_raiz: |
    Cuando un trader es liquidado, su collateral restante (despues de cubrir deudas
    y penalties) deberia ir al pool del vault, beneficiando a todos los LPs.
    Si los liquidation proceeds se envian a una direccion incorrecta, se retienen
    en un contrato intermedio, o no se contabilizan en el AUM, los LPs no reciben
    el beneficio de las liquidaciones que deberian compensar su riesgo.
  como_funciona: |
    1. Trader tiene posicion con 10K collateral, posicion en loss de 8K
    2. Se activa liquidacion: 8K cubre la deuda, 500 es liquidation fee, 1.5K restante
    3. Bug: los 1.5K restantes se envian al liquidator en vez de al pool
       o se quedan en un contrato de fees sin mecanismo de claim
    4. El pool (LPs) no recibe compensacion por haber sido counterparty de la posicion perdedora
    5. El AUM no se incrementa en 1.5K → share price no refleja el ingreso
  invariante: |
    // Post-liquidacion, el poolAmount debe incrementarse por el collateral neto
    function check_liquidation_distribution() internal {
        uint256 poolBefore = vault.poolAmounts(token);
        // Execute liquidation
        vault.liquidatePosition(account, collateralToken, indexToken, isLong, feeReceiver);
        uint256 poolAfter = vault.poolAmounts(token);
        // Pool should increase by at least the remaining collateral after fees
        t(poolAfter >= poolBefore, "PV-012: pool decreased after liquidation");
    }
  que_mirar:
    - "¿El remainingCollateral despues de liquidation se suma al poolAmount?"
    - "¿El liquidation fee va al pool, al liquidator, o a un fee receiver?"
    - "¿Hay edge cases donde remainingCollateral = 0 (full loss) que no se manejan?"
    - "¿La liquidacion parcial actualiza correctamente poolAmount y reservedAmounts?"
    - "¿El PnL del trader liquidado se refleja en getAum()?"
  como_se_arregla: |
    - Liquidation remaining collateral debe ir al pool (incrementar poolAmount)
    - Liquidation fee puede ir al liquidator como incentivo, pero el exceso al pool
    - Verificar que AUM se actualiza post-liquidacion para reflejar el ingreso
    - Handle edge case de insolvency (collateral < debt) gracefully
  trampas:
    - "En GMX v1, el liquidation fee es fijo ($5) y va al liquidator — el restante va al pool"
    - "Si el trader esta underwater (debt > collateral), no hay proceeds — el vault absorbe la loss"
    - "Liquidaciones parciales en GMX v2 son mas complejas que en v1"
  solodit_ids:
    - h-3-incorrect-handling-of-pnl-during-liquidation-sherlock-flatmoney-git
    - h-15-liquidation-fees-are-permanently-frozen-on-penrose-yb-account-sherlock-tapioca-git
    - m-4-liquidation-shouldnt-be-used-to-close-positions-that-were-fully-collateralized-prior-to-collateral-require-sherlock-none-gmx-git
    - h-7-long-traders-deposited-margin-can-be-wiped-out-sherlock-flatmoney-git
  incidentes:
    - "FlatMoney (Sherlock 2024) — incorrect PnL handling during liquidation (H-3)"
    - "Tapioca (Sherlock 2024) — liquidation fees permanently frozen on Penrose YB account"
    - "FlatMoney (Sherlock 2024) — long traders margin wiped out (H-7)"
  verificado: true
  confianza: alta
```

---

## 13. Auto-Compounding Vault Sandwich Attack

```yaml
- id: pv-013
  titulo: Sandwich de auto-compound/harvest para manipular vault token price
  causa_raiz: |
    Vaults wrapper (Vaultka, SteadeFi, RageTrade) auto-compound rewards
    (e.g., esGMX, AERO) de vuelta al pool subyacente. El harvest() o
    compound() incrementa el AUM sin cambiar totalSupply. Un atacante puede
    sandwichear esta transaccion: depositar antes (shares baratas), harvest
    ejecuta (AUM sube, share price sube), retirar despues (shares caras).
  como_funciona: |
    1. Vault wrapper tiene 100 shares, AUM = 100K → precio = $1000/share
    2. Keeper va a ejecutar compound() que agrega 10K de rewards al AUM
    3. Atacante ve el tx en mempool, front-runs con deposito de 100K
       → recibe 100 shares → total: 200 shares, AUM = 200K
    4. Compound() ejecuta → AUM = 210K, 200 shares → precio = $1050/share
    5. Atacante retira 100 shares → recibe 105K (5K de profit)
    6. Sin el sandwich: AUM seria 110K, 100 shares → precio = $1100/share
       Los LPs originales pierden $50/share de los $100 que deberian ganar
  invariante: |
    // Compound/harvest no debe beneficiar desproporcionadamente a depositos recientes
    function check_compound_fairness() internal {
        uint256 sharePriceBefore = vault.sharePrice();
        vault.compound();
        uint256 sharePriceAfter = vault.sharePrice();
        // El incremento debe ser proporcional al periodo de acumulacion
        uint256 increaseBps = ((sharePriceAfter - sharePriceBefore) * 10000) / sharePriceBefore;
        t(increaseBps <= 100, "PV-013: compound increased share price >1% in single tx");
    }
  que_mirar:
    - "¿El compound() es llamable por cualquiera o solo por keeper?"
    - "¿Hay cooldown entre deposit y compound?"
    - "¿Los rewards se distribuyen linealmente (drip) o de golpe?"
    - "¿Se puede front-run la transaccion de harvest/compound?"
    - "¿El vault tiene fees de entrada que hacen el sandwich unprofitable?"
  como_se_arregla: |
    - Distribuir rewards linealmente sobre un periodo (drip feed), no de golpe
    - Depositos recientes no son elegibles para rewards acumulados antes de su deposito
    - Private mempool para compound() transactions (Flashbots Protect)
    - Entry fee >= expected compound yield por periodo
  trampas:
    - "Si los rewards son muy chicos vs AUM, el sandwich no es profitable despues de gas + fees"
    - "Los vaults con drip feed son inmunes al sandwich pero vulnerables a otros ataques de timing"
    - "Algunos vaults compound on every deposit/withdraw — el sandwich se ejecuta en CADA interaccion"
  solodit_ids:
    - h-03-v3vaulttransform-does-not-validate-the-data-input-and-allows-a-depositor-to-exploit-any-position-sherlock-none-revert-lend-git
    - h-02-fees-in-the-autocompoundingpodlp-can-be-lost-pashov-audit-group-none-peapods_2024-11-16-markdown
    - h-2-vault-inflation-attack-in-autocompoundingpodlp-is-possible-due-to-incorrectly-minting-dead-shares-sherlock-none-peapods-git
    - proactive-sandwiching-of-the-gulp-calls-consensys-growthdefi-wheat-markdown
  incidentes:
    - "GrowthDeFi WHEAT (ConsenSys 2021) — proactive sandwiching of gulp() calls"
    - "Peapods AutoCompoundingPodLP (Sherlock 2024) — vault inflation in auto-compound"
    - "Peapods (Pashov 2024) — fees lost in auto-compound"
  verificado: true
  confianza: alta
```

---

## 14. Delta-Neutral Strategy Vault Breakdown

```yaml
- id: pv-014
  titulo: Estrategia delta-neutral falla durante volatilidad extrema
  causa_raiz: |
    Vaults que implementan estrategias delta-neutral (long spot + short perp)
    asumen que la cobertura se puede mantener en todo momento. Durante volatilidad
    extrema, el hedge puede fallar si: el short perp se liquida antes de que
    el spot se venda, el slippage del rebalanceo es excesivo, o el funding rate
    del short se vuelve insostenible.
  como_funciona: |
    1. Vault delta-neutral: deposita en GLP (long exposure) + abre short en GMX (hedge)
    2. Precio de ETH cae 30% en 1 hora (crash rapido)
    3. El GLP pierde valor (long side), pero el short deberia ganar equivalente
    4. Bug: el short se liquida porque el margin es insuficiente para el movimiento
       (la posicion short necesitaba mas collateral pero el vault no lo agrego a tiempo)
    5. Ahora el vault tiene GLP (long) sin hedge → exposicion total a la caida
    6. Los LPs pierden significativamente mas de lo esperado en una estrategia "neutral"
  invariante: |
    // El delta neto de la estrategia debe estar dentro de un rango aceptable
    function check_delta_neutrality() internal {
        int256 longExposure = vault.getLongExposure(); // valor del GLP
        int256 shortExposure = vault.getShortExposure(); // valor del short perp
        int256 netDelta = longExposure + shortExposure; // deberia ser ~0
        uint256 totalExposure = uint256(longExposure > 0 ? longExposure : -longExposure);
        if (totalExposure > 0) {
            uint256 deltaRatioBps = uint256(netDelta > 0 ? netDelta : -netDelta) * 10000 / totalExposure;
            t(deltaRatioBps <= 500, "PV-014: net delta exceeds 5% of total exposure");
        }
    }
  que_mirar:
    - "¿La posicion short tiene suficiente margin para movimientos de 30-50%?"
    - "¿El rebalanceo del hedge es automatico o requiere keeper?"
    - "¿Que pasa si el short se liquida — hay mecanismo de emergency exit?"
    - "¿El vault tiene circuit breaker para pausar deposits cuando delta > umbral?"
    - "¿Los fondos para margin del short estan separados del collateral de LP?"
  como_se_arregla: |
    - Over-collateralize el short (2x margin ratio minimo)
    - Rebalanceo automatico del hedge cada N bloques o cuando delta > threshold
    - Emergency exit: si el short se liquida, vender GLP inmediatamente
    - Circuit breaker: pausar vault si delta neto > 10%
    - Validar que el hedge se puede mantener antes de aceptar depositos
  trampas:
    - "El delta-neutral vault con GMX no tiene riesgo de liquidacion del short si usa GMX perps (no hay liquidation en GMX v1 para shorts)"
    - "El riesgo real es funding rate sostenido que drena el vault lentamente"
    - "Flash crashes son raros pero devastadores — el backtest historico no los captura bien"
  solodit_ids:
    - trst-h-1-canhedge-may-return-wrong-result-when-there-is-a-pending-position-request-trust-security-none-lyra-finance-markdown
    - h-02-hedging-during-liquidation-is-incorrect-code4rena-polynomial-protocol-polynomial-protocol-contest-git
    - h-2-dngmxjuniorvaultmanager_rebalanceborrow-logic-is-flawed-and-could-result-in-vault-liquidation-sherlock-rage-trade-rage-trade-git
    - h-08-incorrect-calculation-of-usedfunds-in-liquiditypool-leads-to-lower-than-expected-token-price-code4rena-polynomial-protocol-polynomial-protocol-contest-git
  incidentes:
    - "Rage Trade (Sherlock 2023) — rebalanceBorrow logic flawed, vault liquidation risk (H-1)"
    - "Polynomial Protocol (Code4rena 2023) — incorrect usedFunds in LiquidityPool (H-8)"
    - "Lyra Finance (Trust Security 2023) — canHedge returns wrong result with pending position"
  verificado: true
  confianza: alta
```

---

## 15. Cooldown Period Bypass via Token Transfer

```yaml
- id: pv-015
  titulo: Bypass del cooldown de deposito/retiro via transferencia del vault token
  causa_raiz: |
    Los vaults perpetuos implementan cooldowns entre deposit y withdraw para
    prevenir front-running (pv-003). Pero si el vault token es un ERC20
    transferible, un atacante puede depositar con address A, transferir
    el token a address B, y retirar desde B inmediatamente porque B no tiene
    cooldown activo (lastAddedAt[B] == 0).
  como_funciona: |
    1. Atacante deposita en vault con address A → recibe shares, lastAddedAt[A] = now
    2. A transfiere shares a address B (simple ERC20 transfer)
    3. B llama withdraw() — el check es: block.timestamp >= lastAddedAt[B] + cooldown
    4. lastAddedAt[B] == 0, asi que 0 + cooldown < block.timestamp → check pasa
    5. B retira exitosamente, bypaseando completamente el cooldown
    6. Esto permite el ataque de front-running descrito en pv-003
  invariante: |
    // Transferencias deben propagar el cooldown al receptor
    function check_cooldown_on_transfer() internal {
        uint256 cooldown = glpManager.cooldownDuration();
        // Deposit with address A
        glpManager.mintAndStakeGlp(token, amount, 0, 0);
        uint256 lastAddedA = glpManager.lastAddedAt(address(this));
        // Transfer to address B
        stakedGlp.transfer(addressB, amount);
        // B's lastAddedAt should be >= A's lastAddedAt
        uint256 lastAddedB = glpManager.lastAddedAt(addressB);
        t(lastAddedB >= lastAddedA, "PV-015: cooldown not propagated on transfer");
    }
  que_mirar:
    - "¿El token de vault override _transfer / _beforeTokenTransfer para propagar cooldown?"
    - "¿lastAddedAt se actualiza en transfers o solo en deposits?"
    - "¿Se puede crear un contrato intermediario que recibe y retira en una tx?"
    - "¿El token es stakeable en otro protocolo que permite withdraw sin cooldown?"
    - "¿Hay un wrapper/router que bypasea el cooldown check?"
  como_se_arregla: |
    - Override _beforeTokenTransfer() para propagar lastAddedAt al receptor
    - O hacer el vault token non-transferable durante el periodo de cooldown
    - O implementar el cooldown en el token mismo (no en el manager)
    - O usar sistema 2-step donde withdraw crea un request y la ejecucion es despues del cooldown
  trampas:
    - "GMX v1 sGLP tiene un transfer lock durante cooldown — verificar la implementacion"
    - "Algunos wrappers (PlutusDAO, JonesDAO) pueden tener su propio token que bypasea el cooldown de GLP"
    - "El transfer a si mismo (A → A) podria resetear el cooldown — verificar edge case"
  solodit_ids:
    - h-1-the-transfer-lock-for-leveraged-position-orders-can-be-bypassed-sherlock-flatmoney-git
    - h-03-withdrawal-delay-can-be-circumvented-code4rena-prepo-prepo-contest-git
    - h-02-cooldown-and-redeem-windows-can-be-rendered-useless-code4rena-notional-notional-git
  incidentes:
    - "FlatMoney (Sherlock 2024) — transfer lock for leveraged position orders bypassed (H-1)"
    - "prePO (Code4rena 2023) — withdrawal delay circumvented (H-3)"
    - "Notional (Code4rena 2023) — cooldown and redeem windows rendered useless (H-2)"
  verificado: true
  confianza: alta
```

---

## 16. Oracle Price Deviation Window — Stale Price Execution

```yaml
- id: pv-016
  titulo: Explotacion de la ventana entre oracle update y ejecucion de ordenes del vault
  causa_raiz: |
    Los vaults perpetuos ejecutan ordenes de deposit/withdraw usando precios
    de oracle. Si hay un gap entre el momento en que el oracle se actualiza
    y el momento en que la orden se ejecuta, un atacante puede explotar
    la informacion del precio nuevo para tomar decisiones con el precio viejo.
    Especialmente critico con Pyth (pull-based) donde el keeper elige que
    precio publicar.
  como_funciona: |
    1. Oracle price actual: ETH = $2000
    2. Atacante crea orden de deposito al vault
    3. ETH sube a $2100 en la realidad, pero el oracle on-chain aun dice $2000
    4. Keeper ejecuta el deposito usando el precio viejo ($2000)
    5. Atacante recibe mas shares de las debidas (AUM calculado con precio viejo)
    6. Oracle se actualiza a $2100 → share price sube → atacante retira con profit
  invariante: |
    // Oracle prices usados en ejecucion deben ser recientes
    function check_oracle_freshness() internal {
        (uint256 price, uint256 timestamp) = oracle.getPrice(token);
        t(block.timestamp - timestamp <= 60, "PV-016: oracle price stale >60s");
        // Verificar que el precio no diverge mucho del precio de referencia
        uint256 refPrice = chainlinkOracle.latestAnswer();
        uint256 deviationBps = price > refPrice
            ? ((price - refPrice) * 10000) / refPrice
            : ((refPrice - price) * 10000) / refPrice;
        t(deviationBps <= 100, "PV-016: oracle deviation >1% from reference");
    }
  que_mirar:
    - "¿El oracle es push-based (Chainlink) o pull-based (Pyth)?"
    - "¿Hay max staleness check en el precio usado para deposits/withdrawals?"
    - "¿El keeper puede elegir cual precio publicar (Pyth permite esto)?"
    - "¿Las ordenes tienen un maxPriceAge que cancela si el precio es viejo?"
    - "¿El precio de ejecucion vs precio de solicitud tiene max deviation?"
  como_se_arregla: |
    - Max staleness de 60 segundos en precios para ejecucion
    - Comparar precio de ejecucion con precio de solicitud — revert si >X% diferencia
    - Requerir precio de ambos feeds (Chainlink + Pyth) para ejecucion
    - Ordenes cancelables si no se ejecutan dentro de ventana estrecha
  trampas:
    - "Pyth pull-based da mas control al keeper sobre que precio usar — verificar que no puede elegir precio antiguo"
    - "El heartbeat de Chainlink varia por asset (ETH: 1h, tokens chicos: 24h) — stale price es relativo"
    - "En L2, los sequencer downtime events crean gaps de oracle masivos — verificar Sequencer Uptime Feed"
  solodit_ids:
    - h-21-creating-an-order-of-type-marketincrease-opens-an-attack-vector-where-attacker-can-execute-txs-with-stale-sherlock-none-gmx-git
    - m-3-a-single-precision-value-may-not-work-for-both-the-min-and-max-prices-sherlock-none-gmx-git
    - m-6-delayed-orders-wont-use-correct-prices-sherlock-none-gmx-git
    - m-8-insufficient-oracle-validation-sherlock-none-gmx-git
  incidentes:
    - "GMX v2 (Sherlock 2023) — stale price execution via MarketIncrease order (H-21)"
    - "GMX v2 (Sherlock 2023) — delayed orders use incorrect prices (M-6)"
    - "Mango Markets (Oct 2022) — $114M exploit via oracle price manipulation (no vault directamente pero mismo vector)"
  verificado: true
  confianza: alta
```

---

## Resumen: Checklist Rapido para Auditar Perpetual Vaults

```
CHECKLIST: Perpetual DEX Vault Audit
═══════════════════════════════════════

SHARE PRICING
[ ] pv-001: ¿El vault token price es manipulable via donacion directa?
[ ] pv-004: ¿AUM usa maximize/minimize correctamente para deposits vs withdrawals?
[ ] pv-013: ¿Auto-compound es sandwichable?

LP PROTECTION
[ ] pv-002: ¿Los traders pueden garantizar profit contra el vault?
[ ] pv-003: ¿Hay cooldown entre deposit y withdraw?
[ ] pv-015: ¿El cooldown se puede bypasear via transfer?
[ ] pv-005: ¿Hay proteccion contra withdrawal drain en alta utilizacion?

POSITION LIMITS
[ ] pv-006: ¿Hay caps de OI que protegen el pool?
[ ] pv-010: ¿El funding rate puede drenar el vault?
[ ] pv-008: ¿ADL funciona correctamente?

EXECUTION
[ ] pv-007: ¿El keeper puede manipular precios de ejecucion?
[ ] pv-016: ¿Los precios de oracle son frescos para ejecucion?

ACCOUNTING
[ ] pv-011: ¿Las fees se calculan sobre la base correcta?
[ ] pv-012: ¿Los liquidation proceeds van al pool?

STRATEGY
[ ] pv-009: ¿El rebalanceo multi-asset es explotable?
[ ] pv-014: ¿La estrategia delta-neutral aguanta volatilidad extrema?
```

---

## Protocolos de Referencia y Recursos

| Protocolo | Vault Token | Modelo | Audits Notables |
|-----------|-------------|--------|-----------------|
| GMX v1 | GLP | Multi-asset pool, counterparty | Sherlock 2023 (99 findings), Guardian Audits |
| GMX v2 | GM | Per-market pools | Sherlock 2023, Guardian Audits 2023 |
| Gains Network | gDAI/gUSDC | Single-asset vault | Pashov 2023-2025, multiple rounds |
| Level Finance | LVL/LGO | Multi-asset pool, tranche | Quantstamp 2023 (exploited $1.1M) |
| HMX | HLP | Multi-asset pool | Cantina 2024 |
| Synthetix v2/v3 | sUSD debt pool | Debt shares model | SigmaPrime, multiple rounds |
| FlatMoney | UNIT | Single-asset, delta-neutral | Sherlock 2024 |
| Polynomial | KangarooVault | Delta-neutral strategies | Code4rena 2023 |
| Rage Trade | Senior/Junior | Risk tranching on GMX | Sherlock 2023 |
| SteadeFi | svToken | Strategy vaults on GMX | CodeHawks 2023 |
| Vaultka | Various | Leveraged vault wrappers | Zokyo 2023 |
| Vertex | USDC pool | Hybrid orderbook+AMM | OtterSec 2023 |
| Zaros | zLP | Perp vault with LRT collateral | Cyfrin 2024 |

---

## Fuentes Verificadas

- Sherlock GMX v2 contest: 21 HIGH, 10+ MEDIUM findings (2023)
- Guardian Audits GMX: multiple private audit rounds
- Quantstamp Level Finance: 32 findings including critical drain
- Cantina HMX: 49 findings across multiple severity levels
- Code4rena Polynomial: 33 findings including 8 HIGH
- Sherlock FlatMoney: 19 findings including 8 HIGH
- CodeHawks SteadeFi: 90+ findings including vault-specific patterns
- Pashov Gains Network: 55+ findings across multiple audit rounds
- Sherlock Rage Trade: 8 findings on delta-neutral vault strategy
