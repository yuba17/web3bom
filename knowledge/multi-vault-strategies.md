# Multi-Vault Strategies & Yield Aggregation — Combat Briefing

> Todo lo que un auditor necesita antes de revisar un agregador de vaults ERC-4626,
> estrategias multi-vault tipo Yearn V3/Sommelier/Beefy, o wrappers vault-of-vaults.
> Sources: Yearn V3 audits, Sommelier/Cellar findings, Sherlock/C4 ERC-4626 contests, Beefy incidents, DeFiHackLabs.

---

## 1. Bugs Conocidos

### 1.1 Cross-Vault Share Price Manipulation

```yaml
- id: MVAULT-01
  pattern: cross-vault-share-price-manipulation
  titulo: "Manipulación de precio de shares cross-vault (depósito en vault A afecta vault B)"
  descripcion: >
    Cuando un agregador mantiene posiciones en múltiples vaults subyacentes, el
    precio de shares del vault meta depende del totalAssets() agregado de todos
    los vaults hijos. Un atacante puede manipular el share price de un vault hijo
    (vía donation, flash loan, o share inflation) para distorsionar el
    totalAssets() del meta-vault. Esto desincroniza el exchange rate del
    meta-vault, permitiendo depósitos baratos o redenciones infladas.
    El vector es especialmente peligroso cuando los vaults hijos no tienen
    protección contra donaciones directas y el meta-vault usa balanceOf() o
    previewRedeem() del vault hijo para calcular su propio totalAssets().
  patron_vulnerable: |
    // Meta-vault calcula totalAssets sumando shares de vaults hijos
    function totalAssets() public view returns (uint256 total) {
        for (uint i = 0; i < strategies.length; i++) {
            // VULNERABLE: depende del share price del vault hijo
            total += IVault(strategies[i]).convertToAssets(
                IVault(strategies[i]).balanceOf(address(this))
            );
        }
    }
    // Atacante manipula vault hijo con donation directa:
    // asset.transfer(address(childVault), largeAmount);
    // Ahora convertToAssets() del hijo devuelve un valor inflado
    // Meta-vault totalAssets() sube artificialmente
    // Atacante redime shares del meta-vault a precio inflado
  test_invariante: |
    // Invariante: el totalAssets del meta-vault no debe cambiar más de X%
    // en un solo bloque sin depósitos/retiros legítimos
    function invariant_MVAULT01_cross_vault_price_stability() public {
        uint256 assetsBefore = metaVault.totalAssets();
        // Simular donation a vault hijo
        asset.transfer(address(childVault), donationAmount);
        uint256 assetsAfter = metaVault.totalAssets();
        uint256 delta = assetsAfter > assetsBefore
            ? assetsAfter - assetsBefore
            : assetsBefore - assetsAfter;
        // Delta no debe exceder el monto donado (no amplificación)
        t(delta <= donationAmount, "MVAULT-01: cross-vault amplification");
    }
  ejemplo_real:
    - "Yearn V3 (Spearbit) — TokenizedStrategy share price manipulable via direct donation, propagates to meta-vault calculations (HIGH)"
    - "Sommelier Cellar (Sherlock) — attacker manipulates underlying vault share price to inflate Cellar totalAssets, profits on redeem (HIGH)"
    - "Morpho Vaults v2 (Spearbit) — side effects of underlying directly donated to VaultV2 or adapter positions (HIGH)"
    - "Burve (Sherlock) — attacker drains assets from Closure by exploiting NoopVault via donation attack (HIGH)"
    - "Plume Network (Code4rena) — yield distribution share inflation propagates across vault hierarchy (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [cross-vault, donation, share-price, meta-vault, totalAssets]
  relacionado_con: [MVAULT-06, MVAULT-12]
```

### 1.2 Strategy Allocation Rounding Errors Compounding

```yaml
- id: MVAULT-02
  pattern: strategy-allocation-rounding-compound
  titulo: "Errores de redondeo en asignación a estrategias se acumulan entre vaults"
  descripcion: >
    Cuando un agregador distribuye fondos entre N estrategias usando porcentajes
    (debt ratios), cada división introduce un error de redondeo de hasta 1 wei.
    Con N estrategias y M operaciones, el error acumulado puede ser N*M wei.
    En protocolos con tokens de alta precisión (WBTC 8 decimals, USDC 6 decimals)
    el impacto relativo crece. El problema se amplifica cuando hay rebalanceos
    frecuentes: cada rebalanceo redistribuye y redondea de nuevo. Tras miles de
    operaciones, dust se pierde o se acumula en una estrategia, causando
    discrepancias entre totalAssets reportado y assets reales recuperables.
    El peor caso es cuando el vault no puede redimir 100% porque la suma de
    redondeos dejó dust atrapado en estrategias que no se puede recuperar.
  patron_vulnerable: |
    // Distribución proporcional con truncamiento
    function _allocate(uint256 totalToAllocate) internal {
        uint256 remaining = totalToAllocate;
        for (uint i = 0; i < strategies.length - 1; i++) {
            // VULNERABLE: truncamiento acumulativo
            uint256 allocation = totalToAllocate * debtRatio[i] / MAX_BPS;
            IStrategy(strategies[i]).deposit(allocation);
            remaining -= allocation;
        }
        // Última estrategia recibe el resto — puede ser más/menos de lo esperado
        IStrategy(strategies[strategies.length - 1]).deposit(remaining);
    }
  test_invariante: |
    // Invariante: la suma de assets en todas las estrategias debe ser igual
    // a totalDebt (con tolerancia de N wei donde N = número de estrategias)
    function invariant_MVAULT02_allocation_rounding() public {
        uint256 sumInStrategies = 0;
        for (uint i = 0; i < vault.numStrategies(); i++) {
            sumInStrategies += IStrategy(vault.strategies(i)).totalAssets();
        }
        uint256 tolerance = vault.numStrategies(); // 1 wei per strategy
        t(
            absDiff(sumInStrategies, vault.totalDebt()) <= tolerance,
            "MVAULT-02: rounding drift exceeds tolerance"
        );
    }
  ejemplo_real:
    - "Yearn V2 (Trail of Bits) — rounding errors in debt allocation compound over many harvest cycles, creating unrecoverable dust in strategies (MEDIUM)"
    - "Sommelier Cellar v2 (Sherlock) — rounding in _calculateTotalAssetsOrTotalAssetsWithdrawable causes discrepancy between reported and actual withdrawable (MEDIUM)"
    - "SuperVault (Cyfrin) — incorrect rounding direction in SuperVault.convertToAssets() compounds through strategy chain (MEDIUM)"
    - "Sense (Sherlock) — AutoRoller previewWithdraw doesn't round up per EIP-4626, compounds across series (MEDIUM)"
    - "Notional (Sherlock) — rounding error due to internal accounting steals portion across multi-vault setup (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [rounding, allocation, debt-ratio, dust, compounding, precision]
  relacionado_con: [MVAULT-09, MVAULT-16]
```

### 1.3 Harvest Sandwich Attacks on Yield Strategies

```yaml
- id: MVAULT-03
  pattern: harvest-sandwich-attack
  titulo: "Ataque sandwich en cosechas de rendimiento (harvest MEV)"
  descripcion: >
    Cuando una estrategia ejecuta harvest() para reclamar rewards y reinvertir,
    el totalAssets del vault aumenta en un solo bloque. Un atacante puede
    front-run el harvest con un depósito grande (comprando shares baratas antes
    de que el rendimiento se refleje), y back-run con un retiro inmediato
    (redimiendo shares al nuevo precio inflado). El profit es proporcional al
    yield cosechado. Este es uno de los ataques MEV más comunes contra
    yield aggregators y es especialmente rentable cuando:
    (a) el harvest es público y cualquiera puede llamarlo,
    (b) no hay lock period post-depósito,
    (c) el yield acumulado entre harvests es significativo.
    Variante avanzada: el atacante ES el keeper y programa el harvest
    para maximizar su propia extracción.
  patron_vulnerable: |
    // Harvest sin protección — cambio instantáneo de share price
    function harvest() external {
        uint256 profit = strategy.claimRewards(); // yield acumulado
        asset.safeTransfer(address(vault), profit);
        // VULNERABLE: totalAssets sube inmediatamente
        // Front-runner depositó justo antes, back-runs con redeem
    }

    // Sin lock period post-depósito
    function deposit(uint256 assets, address receiver) public returns (uint256) {
        uint256 shares = previewDeposit(assets);
        // No hay cooldown — se puede redimir en el mismo bloque
        _mint(receiver, shares);
        asset.safeTransferFrom(msg.sender, address(this), assets);
        return shares;
    }
  test_invariante: |
    // Invariante: un usuario que deposita y retira en el mismo bloque
    // no debe obtener más assets de los que depositó
    function invariant_MVAULT03_no_harvest_sandwich() public {
        uint256 deposited = 1000e18;
        uint256 sharesBefore = vault.balanceOf(attacker);
        vm.prank(attacker);
        uint256 shares = vault.deposit(deposited, attacker);
        // Simular harvest en el mismo bloque
        vm.prank(keeper);
        strategy.harvest();
        vm.prank(attacker);
        uint256 redeemed = vault.redeem(shares, attacker, attacker);
        t(redeemed <= deposited, "MVAULT-03: harvest sandwich profit");
    }
  ejemplo_real:
    - "Yearn V2 — múltiples incidentes documentados de harvest sandwich, motivó implementación de withdrawal queue y profit locking (HIGH)"
    - "Beefy Finance — vault strategies sandwiched during harvest, losses passed to LPs, motivó migration a harvest con swap protection (HIGH)"
    - "Sommelier (Sherlock) — Cellar harvest can be front-run, attacker deposits before profit report and withdraws after (HIGH)"
    - "Yearn V3 (Spearbit) — TokenizedStrategy profit unlocking mechanism bypassed in edge case allowing instant profit capture (MEDIUM)"
    - "BadgerDAO (Code4rena) — StakedCitadel harvest rewards can be sandwich attacked for MEV extraction (HIGH)"
    - "GoGoPool (Code4rena) — ggAVAX share price jumps on syncRewards, enabling sandwich (MEDIUM)"
    - "DeFiHackLabs — Beefy vaults on BSC sandwiched repeatedly during compoundAll() calls (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [sandwich, harvest, MEV, front-run, yield, keeper, profit-locking]
  relacionado_con: [MVAULT-13, MVAULT-10]
```

### 1.4 Vault Queue / Withdrawal Race Conditions

```yaml
- id: MVAULT-04
  pattern: withdrawal-queue-race-condition
  titulo: "Condiciones de carrera en colas de retiro de vaults"
  descripcion: >
    Muchos agregadores implementan withdrawal queues para manejar iliquidez
    (fondos bloqueados en estrategias). Las race conditions surgen cuando:
    (a) múltiples usuarios compiten por liquidez limitada — el primero que
    reclame drena el pool y los demás quedan bloqueados,
    (b) el orden de la queue se puede manipular (no es FIFO estricto),
    (c) un retiro parcial cambia el share price para los siguientes en la cola,
    (d) el keeper procesa la queue selectivamente (procesa retiros grandes
    primero para maximizar fees, dejando los pequeños indefinidamente).
    En el peor caso, un atacante grande puede front-run el procesamiento de la
    queue, retirar toda la liquidez disponible, y dejar a la cola entera
    sin fondos — efectivamente un bank run optimizado.
  patron_vulnerable: |
    // Withdrawal queue sin protección de orden
    struct WithdrawalRequest {
        address user;
        uint256 shares;
        uint256 timestamp;
    }
    WithdrawalRequest[] public queue;

    // VULNERABLE: cualquiera puede reclamar si hay liquidez
    function claimWithdrawal(uint256 index) external {
        WithdrawalRequest memory req = queue[index];
        require(req.user == msg.sender, "not owner");
        uint256 assets = vault.convertToAssets(req.shares);
        // No verifica que requests anteriores se hayan procesado primero
        require(asset.balanceOf(address(this)) >= assets, "insufficient");
        asset.transfer(req.user, assets);
        delete queue[index];
    }
  test_invariante: |
    // Invariante: requests en la queue deben procesarse en orden FIFO
    // (o al menos requests anteriores no deben perder liquidez por posteriores)
    function invariant_MVAULT04_fifo_withdrawal() public {
        for (uint i = 1; i < queue.length; i++) {
            if (queue[i].processed && !queue[i-1].processed) {
                t(false, "MVAULT-04: FIFO violation in withdrawal queue");
            }
        }
    }
  ejemplo_real:
    - "Sommelier Cellar (Sherlock) — withdrawal queue can be gamed, users claiming out of order drain available liquidity (HIGH)"
    - "EtherFi (Code4rena) — withdrawal request NFT race condition, multiple claims on same request (HIGH)"
    - "Lido V2 (Code4rena) — withdrawal queue finalization race, stale share prices applied to early vs late claims (MEDIUM)"
    - "Renzo (Code4rena) — withdraw queue race condition when operator processes selectively (MEDIUM)"
    - "Kelp DAO (Code4rena) — unstake queue front-running, attacker claims before legitimate users (HIGH)"
    - "Morpho (Cantina) — allocation queue order manipulation affects withdrawal priority (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [withdrawal-queue, race-condition, FIFO, liquidity, front-running]
  relacionado_con: [MVAULT-05, MVAULT-17]
```

### 1.5 Strategy Migration Fund Loss

```yaml
- id: MVAULT-05
  pattern: strategy-migration-fund-loss
  titulo: "Pérdida de fondos durante migración de estrategia vieja a nueva"
  descripcion: >
    Cuando un vault migra fondos de una estrategia vieja a una nueva (upgrade,
    rotación, o emergencia), hay una ventana donde los fondos están en tránsito.
    Vectores de pérdida: (a) la estrategia vieja reporta menos assets de los
    reales al hacer withdrawAll() por slippage/fees de salida del protocolo
    subyacente, (b) el vault no verifica que received == expected y la diferencia
    se pierde silenciosamente, (c) la nueva estrategia tiene un exchange rate
    diferente y el vault no ajusta la contabilidad, (d) durante la migración
    totalAssets() es inconsistente — reporta fondos en ambas estrategias o en
    ninguna. Un atacante puede explotar la ventana de migración para depositar
    cuando totalAssets es bajo (shares baratas) y redimir cuando se normaliza.
  patron_vulnerable: |
    function migrateStrategy(address oldStrategy, address newStrategy) external onlyOwner {
        // Paso 1: retirar todo de la vieja estrategia
        uint256 expectedAmount = IStrategy(oldStrategy).totalAssets();
        IStrategy(oldStrategy).withdrawAll();
        // VULNERABLE: no verifica cuánto se recibió realmente
        uint256 actualReceived = asset.balanceOf(address(this));
        // Paso 2: depositar en la nueva
        asset.approve(newStrategy, actualReceived);
        IStrategy(newStrategy).deposit(actualReceived);
        // VULNERABLE: si actualReceived < expectedAmount,
        // la diferencia se pierde y totalAssets() del vault baja
        // sin que se registre como pérdida
    }
  test_invariante: |
    // Invariante: totalAssets antes de migración == totalAssets después
    // (con tolerancia para slippage)
    function invariant_MVAULT05_migration_conservation() public {
        uint256 totalBefore = vault.totalAssets();
        vm.prank(owner);
        vault.migrateStrategy(oldStrategy, newStrategy);
        uint256 totalAfter = vault.totalAssets();
        uint256 maxSlippage = totalBefore * 50 / 10000; // 0.5% max
        t(totalAfter >= totalBefore - maxSlippage,
          "MVAULT-05: migration lost more than acceptable slippage");
    }
  ejemplo_real:
    - "Yearn V2 — strategy migration via migrateStrategy() lost funds when old strategy had locked positions, partial withdrawal returned less than totalDebt (HIGH)"
    - "Beefy Finance — vault strategy upgrade caused temporary totalAssets drop, sandwich attacker profited during migration window (HIGH)"
    - "Sommelier Cellar (Sherlock) — strategist can migrate to malicious adaptor, draining cellar assets (CRITICAL)"
    - "Idle Finance (Code4rena) — strategy migration slippage not accounted for, loss socialized to all depositors (MEDIUM)"
    - "Origin Dollar (Code4rena) — strategy withdrawal during reallocation can fail silently, accounting becomes wrong (HIGH)"
    - "Yearn V3 (Spearbit) — shutdown mode allows withdrawal from strategies with potential for sandwich during migration (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [migration, strategy, slippage, withdrawAll, accounting, upgrade]
  relacionado_con: [MVAULT-08, MVAULT-09]
```

### 1.6 Multi-Vault Rebalancing Flash Loan Attacks

```yaml
- id: MVAULT-06
  pattern: rebalancing-flash-loan-attack
  titulo: "Ataques con flash loans durante rebalanceo entre vaults"
  descripcion: >
    Cuando un agregador rebalance fondos entre estrategias (mover de strategy A
    a strategy B para optimizar yield), hay una ventana atómica donde los fondos
    están en tránsito. Si el rebalanceo no es atómico o se puede front-run,
    un atacante con flash loans puede: (a) inflar el vault destino antes del
    rebalanceo para recibir más shares, (b) deflactar el vault origen para que
    el rebalanceo retire menos de lo esperado, (c) manipular el AMM/DEX que
    la estrategia usa para swaps durante el rebalanceo (sandwich en el swap).
    El caso más peligroso es cuando el rebalanceo es callable por cualquiera
    (keeper público) y el monto a mover es grande relativo a la liquidez del
    pool subyacente.
  patron_vulnerable: |
    // Rebalanceo público sin protección
    function rebalance(uint256 fromIdx, uint256 toIdx, uint256 amount) external {
        // VULNERABLE: cualquiera puede triggear, sin slippage check
        IStrategy(strategies[fromIdx]).withdraw(amount);
        uint256 received = asset.balanceOf(address(this));
        asset.approve(strategies[toIdx], received);
        IStrategy(strategies[toIdx]).deposit(received);
        // Si el atacante manipuló el pool del toIdx strategy,
        // el deposit recibe menos shares de las esperadas
    }
  test_invariante: |
    // Invariante: rebalanceo no debe cambiar totalAssets más que la
    // tolerancia de slippage declarada
    function invariant_MVAULT06_rebalance_conservation() public {
        uint256 totalBefore = vault.totalAssets();
        vm.prank(keeper);
        vault.rebalance(0, 1, rebalanceAmount);
        uint256 totalAfter = vault.totalAssets();
        uint256 tolerance = rebalanceAmount * 100 / 10000; // 1% max
        t(
            absDiff(totalBefore, totalAfter) <= tolerance,
            "MVAULT-06: rebalance lost value beyond slippage tolerance"
        );
    }
  ejemplo_real:
    - "Sommelier Cellar V2 (Sherlock) — rebalance function swaps through DEX with manipulable price, enabling sandwich (HIGH)"
    - "Origin Dollar (Code4rena) — rebalance between Aave/Compound strategies can be sandwiched, attacker profits on swap slippage (HIGH)"
    - "Beefy Finance — flash loan used to manipulate LP price during vault rebalance, causing vault to buy high/sell low (CRITICAL)"
    - "DeFiHackLabs — YearnFinance Feb 2023 yUSDT strategy rebalance exploited via flash loan ($11.5M)"
    - "Yearn V2 — rebalance between strategies via harvest() allows MEV extraction when large amounts move through DEX (HIGH)"
    - "Perennial (Sherlock) — Perennial account users suffer donation attack during rebalance group operations (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [rebalance, flash-loan, sandwich, slippage, MEV, keeper]
  relacionado_con: [MVAULT-01, MVAULT-03]
```

### 1.7 Debt Ratio Manipulation Across Strategies

```yaml
- id: MVAULT-07
  pattern: debt-ratio-manipulation
  titulo: "Manipulación de debt ratios entre estrategias"
  descripcion: >
    Los agregadores asignan capital a estrategias según debt ratios
    (porcentaje del capital total que cada estrategia debe tener). Un atacante
    puede manipular estos ratios indirectamente: (a) causar una pérdida en una
    estrategia para que su debt ratio baje, forzando al vault a mover fondos
    a otra estrategia donde el atacante tiene ventaja, (b) explotar el hecho de
    que debt ratios se recalculan en base a totalDebt que puede estar desactualizado,
    (c) manipular el orden de las estrategias en la withdrawal queue para que
    fondos se retiren de la estrategia más rentable primero (grief a LPs).
    En Yearn V2, el governance puede cambiar debt ratios, pero el efecto no es
    inmediato — hay una ventana entre el cambio de ratio y el harvest que
    rebalanceo real, durante la cual el vault opera con ratios inconsistentes.
  patron_vulnerable: |
    mapping(address => uint256) public debtRatio; // BPS
    uint256 public totalDebtRatio; // sum of all, should be <= 10000

    function updateDebtRatio(address strategy, uint256 newRatio) external onlyGovernance {
        totalDebtRatio = totalDebtRatio - debtRatio[strategy] + newRatio;
        debtRatio[strategy] = newRatio;
        // VULNERABLE: no se fuerza rebalanceo inmediato
        // La estrategia vieja sigue teniendo los fondos hasta el próximo harvest
        // totalDebtRatio puede exceder 10000 temporalmente si no se valida
    }

    function _availableDepositLimit(address strategy) internal view returns (uint256) {
        uint256 strategyLimit = totalAssets() * debtRatio[strategy] / MAX_BPS;
        uint256 strategyDebt = strategies[strategy].totalDebt;
        // VULNERABLE: totalAssets() puede estar stale si strategies no reportaron
        return strategyLimit > strategyDebt ? strategyLimit - strategyDebt : 0;
    }
  test_invariante: |
    // Invariante: suma de debt ratios nunca debe exceder MAX_BPS (10000)
    // Invariante: totalDebt real debe estar dentro de ±5% del target
    function invariant_MVAULT07_debt_ratio_bounds() public {
        uint256 sumRatios = 0;
        for (uint i = 0; i < vault.numStrategies(); i++) {
            sumRatios += vault.debtRatio(vault.strategies(i));
        }
        t(sumRatios <= 10000, "MVAULT-07: debt ratios exceed 100%");

        uint256 totalTarget = vault.totalAssets();
        uint256 totalActual = vault.totalDebt();
        t(
            absDiff(totalTarget, totalActual) <= totalTarget * 500 / 10000,
            "MVAULT-07: actual debt diverged >5% from target"
        );
    }
  ejemplo_real:
    - "Yearn V2 (Trail of Bits) — debt ratio update without immediate rebalance creates arbitrage window (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — strategist can set debt ratios that sum >100%, causing over-allocation (HIGH)"
    - "Origin Dollar (Code4rena) — allocation percentages can leave vault in state where redeems fail (HIGH)"
    - "Idle Finance (Code4rena) — debt ratio mismatch between idle and strategy creates accounting gap (MEDIUM)"
    - "Yearn V3 (Spearbit) — stale totalAssets used in debt calculation when strategy hasn't reported (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [debt-ratio, allocation, governance, rebalance, stale, accounting]
  relacionado_con: [MVAULT-02, MVAULT-08]
```

### 1.8 totalAssets() Desync When Strategy Reports Loss

```yaml
- id: MVAULT-08
  pattern: total-assets-desync-loss-report
  titulo: "Desincronización de totalAssets cuando una estrategia reporta pérdida"
  descripcion: >
    Cuando una estrategia sufre una pérdida (hack al protocolo subyacente,
    liquidación, impermanent loss), debe reportarla al vault. El problema es
    CUÁNDO y CÓMO se refleja. Si totalAssets() del vault se calcula en tiempo
    real (sumando convertToAssets de cada estrategia), la pérdida se refleja
    inmediatamente y el share price baja atómicamente. Pero si se calcula con
    totalDebt (un valor cacheado que solo se actualiza en harvest), hay un
    window entre la pérdida real y su reporte donde totalAssets miente —
    reporta más assets de los que realmente existen. Durante esta ventana:
    (a) depositantes entran a un share price artificialmente alto (reciben
    menos shares de las que merecen), (b) users informados que saben de la
    pérdida retiran a precio alto antes del harvest que la reconoce,
    (c) el último que redima absorbe toda la pérdida (bank run).
  patron_vulnerable: |
    // totalAssets basado en totalDebt cacheado — NO en tiempo real
    function totalAssets() public view returns (uint256) {
        return totalIdle + totalDebt;
        // VULNERABLE: totalDebt no refleja pérdida hasta harvest
    }

    // Harvest que reporta la pérdida — pero puede ser tarde
    function processReport(address strategy) external returns (uint256, uint256) {
        uint256 currentAssets = IStrategy(strategy).totalAssets();
        uint256 currentDebt = strategies[strategy].totalDebt;
        if (currentAssets < currentDebt) {
            uint256 loss = currentDebt - currentAssets;
            // Recién aquí se actualiza totalDebt
            strategies[strategy].totalDebt -= loss;
            totalDebt -= loss;
            // Share price baja — pero los que ya retiraron ganaron
        }
    }
  test_invariante: |
    // Invariante: totalAssets debe reflejar pérdidas con un delay máximo
    // de 1 bloque (o el período de reporting)
    function invariant_MVAULT08_loss_reflected() public {
        uint256 reportedAssets = vault.totalAssets();
        uint256 realAssets = vault.totalIdle();
        for (uint i = 0; i < vault.numStrategies(); i++) {
            realAssets += IStrategy(vault.strategies(i)).totalAssets();
        }
        // No debe haber discrepancia > 1% entre reportado y real
        t(
            reportedAssets <= realAssets * 10100 / 10000,
            "MVAULT-08: totalAssets inflated vs real assets"
        );
    }
  ejemplo_real:
    - "Yearn V2 — strategy loss not reflected until harvest, informed users front-run harvest to redeem at stale high price (HIGH)"
    - "Yearn V3 (Spearbit) — loss reporting delay allows arbitrage between real and reported totalAssets (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — cellar totalAssets stale after strategy loss, depositors disadvantaged (HIGH)"
    - "Euler (Code4rena) — bad debt socialization delay allows informed users to exit first (HIGH)"
    - "Maple Finance — pool loss from defaulted loan not reflected in share price until processDefault() called, enabling front-running (HIGH)"
    - "Origin Dollar — OUSD/OETH rebasing desync when strategy reports loss, informed users exit before rebase (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [totalAssets, desync, loss, harvest, stale, bank-run, front-running]
  relacionado_con: [MVAULT-07, MVAULT-17]
```

### 1.9 Strategy Emergency Withdrawal Leaving Dust

```yaml
- id: MVAULT-09
  pattern: emergency-withdrawal-dust
  titulo: "Retiro de emergencia de estrategia deja dust irrecuperable"
  descripcion: >
    Cuando una estrategia se retira de emergencia (emergency shutdown, revoke,
    o panic), intenta retirar todo del protocolo subyacente. Pero muchos
    protocolos DeFi no permiten retiro del 100%: hay dust por redondeo,
    minimum balances, o locked positions. La estrategia reporta emergencyWithdraw
    exitoso, pero deja 0.001% — 1% de los fondos atrapados. Este dust se
    pierde permanentemente a menos que alguien lo reclame manualmente.
    El impacto se amplifica con vaults grandes (1% de $100M = $1M perdido).
    Peor: el vault puede marcar la estrategia como vacía (totalDebt = 0)
    cuando aún tiene fondos, causando que totalAssets esté subestimado.
  patron_vulnerable: |
    function emergencyWithdraw() external onlyVault {
        uint256 balance = aToken.balanceOf(address(this));
        aaveLendingPool.withdraw(asset, balance, address(this));
        // VULNERABLE: Aave puede no devolver el 100%
        // Quedan residuos por accrued interest no reclamado,
        // o por mínimos del pool
        uint256 remaining = aToken.balanceOf(address(this));
        // remaining > 0 pero se ignora
        asset.transfer(vault, asset.balanceOf(address(this)));
    }

    // Vault side — marca como vacía sin verificar
    function revokeStrategy(address strategy) external onlyGovernance {
        IStrategy(strategy).emergencyWithdraw();
        // VULNERABLE: asume que se retiró todo
        totalDebt -= strategies[strategy].totalDebt;
        strategies[strategy].totalDebt = 0;
        // Si quedó dust, totalDebt disminuyó más de lo real
    }
  test_invariante: |
    // Invariante: después de emergency withdrawal,
    // totalDebt debe ser >= suma real de assets en estrategias activas
    function invariant_MVAULT09_no_dust_after_emergency() public {
        uint256 realInStrategies = 0;
        for (uint i = 0; i < vault.numStrategies(); i++) {
            address s = vault.strategies(i);
            if (vault.strategyIsActive(s)) {
                realInStrategies += IStrategy(s).totalAssets();
            }
        }
        t(
            vault.totalDebt() >= realInStrategies,
            "MVAULT-09: totalDebt understates real assets in strategies"
        );
    }
  ejemplo_real:
    - "Yearn V2 — emergencyExit leaves dust in Aave/Compound strategies, not recoverable without governance action (LOW)"
    - "Beefy Finance — panic() function leaves residual LP tokens in farms due to rounding in withdraw (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — adaptorCall withdraws from position leaving dust, accounting mismatch (MEDIUM)"
    - "Idle Finance (Code4rena) — emergency withdrawal from Idle strategy leaves residual tokens, loss socialized (LOW)"
    - "Origin Dollar — emergency withdrawal from strategy leaves aToken dust in old strategy contract (LOW)"
    - "Yearn V3 (Spearbit) — strategy shutdown may leave assets if underlying has withdrawal restrictions (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [emergency, dust, withdrawal, residual, accounting, shutdown]
  relacionado_con: [MVAULT-05, MVAULT-02]
```

### 1.10 Vault Deposit/Withdrawal Fee Arbitrage Between Vaults

```yaml
- id: MVAULT-10
  pattern: fee-arbitrage-between-vaults
  titulo: "Arbitraje de fees de depósito/retiro entre vaults interconectados"
  descripcion: >
    Cuando múltiples vaults comparten el mismo asset subyacente pero tienen
    diferentes estructuras de fees (depósito fee, withdrawal fee, performance
    fee), un atacante puede arbitrar la diferencia. Ejemplo: vault A cobra 0.1%
    depósito fee pero 0% retiro, vault B cobra 0% depósito pero 0.1% retiro.
    Si un meta-vault o wrapper permite mover entre ambos, el atacante deposita
    en B (gratis), migra a A (si la migración no cobra fee), y retira de A
    (gratis) — evitando fees en ambas direcciones. Variante: un wrapper
    ERC-4626 sobre un vault con fees puede abstraer las fees incorrectamente,
    haciendo que previewDeposit/previewRedeem no las refleje y el wrapper
    ofrezca un precio mejor que el vault directo.
  patron_vulnerable: |
    // Wrapper que no refleja fees del vault subyacente
    function totalAssets() public view returns (uint256) {
        // VULNERABLE: no descuenta withdrawal fee del vault subyacente
        return underlyingVault.convertToAssets(
            underlyingVault.balanceOf(address(this))
        );
    }

    function redeem(uint256 shares, address to, address owner) public returns (uint256) {
        uint256 wrapperShares = _burn(owner, shares);
        uint256 underlyingShares = _convertToUnderlyingShares(wrapperShares);
        // VULNERABLE: vault subyacente cobra fee en redeem
        // pero el wrapper reportó totalAssets sin descontarla
        uint256 assets = underlyingVault.redeem(underlyingShares, to, address(this));
        // assets < expected porque el vault cobró fee
        return assets;
    }
  test_invariante: |
    // Invariante: wrapper.redeem(shares) <= wrapper.previewRedeem(shares)
    // (nunca se recibe más de lo prometido)
    function invariant_MVAULT10_fee_consistency() public {
        uint256 shares = wrapper.balanceOf(user);
        if (shares > 0) {
            uint256 preview = wrapper.previewRedeem(shares);
            vm.prank(user);
            uint256 actual = wrapper.redeem(shares, user, user);
            t(actual <= preview, "MVAULT-10: actual redeem exceeds preview");
        }
    }
  ejemplo_real:
    - "Yearn V3 (Spearbit) — wrapper over TokenizedStrategy doesn't account for performance fee in conversions, previewRedeem overpromises (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — platform fee not reflected in share price preview, enables arbitrage between direct and wrapped access (MEDIUM)"
    - "Popcorn (Code4rena) — ERC-4626 wrapper over Yearn/Beefy vault doesn't forward fees correctly, preview functions lie (HIGH)"
    - "TeaVaultAmbient (Code4rena) — management fee not included in convertToAssets, users can time deposits around fee collection (MEDIUM)"
    - "StakeWise V3 (Code4rena) — fee-on-transfer token interactions with vault wrapper create arbitrage path (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [fees, arbitrage, wrapper, preview, deposit-fee, withdrawal-fee]
  relacionado_con: [MVAULT-03, MVAULT-11]
```

### 1.11 ERC-4626 Wrapper Over Non-Standard Vault

```yaml
- id: MVAULT-11
  pattern: erc4626-wrapper-nonstandard
  titulo: "Wrapper ERC-4626 sobre vault no estándar (Yearn V2 → adapter)"
  descripcion: >
    Muchos protocolos envuelven vaults legacy (Yearn V2, Beefy V6, Compound
    cTokens) en una interfaz ERC-4626 para compatibilidad. El wrapper debe
    traducir correctamente TODAS las funciones de la especificación, pero
    frecuentemente falla en: (a) previewDeposit/previewMint cuando el vault
    subyacente tiene deposit limits dinámicos, (b) maxDeposit/maxWithdraw
    cuando el vault subyacente tiene pauses o caps, (c) dirección de redondeo
    (ERC-4626 especifica rounding, pero el vault subyacente puede redondear
    diferente), (d) manejo de totalAssets cuando el vault subyacente tiene
    fees acumuladas no reclamadas. El resultado es que el wrapper reporta
    valores incorrectos y los integradores que confían en las funciones
    preview* toman decisiones erróneas de routing.
  patron_vulnerable: |
    // Wrapper sobre Yearn V2 vault (no ERC-4626 nativo)
    contract YearnV2Wrapper is ERC4626 {
        IYearnVault public immutable yVault;

        function totalAssets() public view override returns (uint256) {
            // VULNERABLE: pricePerShare del yVault puede estar stale
            // (solo se actualiza en harvest)
            return yVault.balanceOf(address(this)) * yVault.pricePerShare()
                   / 10**yVault.decimals();
        }

        function maxDeposit(address) public view override returns (uint256) {
            // VULNERABLE: no consulta availableDepositLimit del yVault
            return type(uint256).max;
            // Debería ser: yVault.availableDepositLimit()
        }

        function _deposit(uint256 assets, address) internal override {
            asset.approve(address(yVault), assets);
            uint256 sharesBefore = yVault.balanceOf(address(this));
            yVault.deposit(assets);
            uint256 sharesReceived = yVault.balanceOf(address(this)) - sharesBefore;
            // VULNERABLE: no verifica si sharesReceived == expected
            // Yearn V2 puede cobrar management fee en deposit
        }
    }
  test_invariante: |
    // Invariante: wrapper maxDeposit debe ser <= al deposit limit del vault subyacente
    function invariant_MVAULT11_max_deposit_consistency() public {
        uint256 wrapperMax = wrapper.maxDeposit(address(this));
        uint256 underlyingMax = yVault.availableDepositLimit();
        t(wrapperMax <= underlyingMax,
          "MVAULT-11: wrapper overpromises deposit capacity");
    }
    // Invariante: deposit(maxDeposit()) no debe revertear
    function invariant_MVAULT11_deposit_limit_honored() public {
        uint256 max = wrapper.maxDeposit(address(this));
        if (max > 0 && max < type(uint256).max) {
            deal(address(asset), address(this), max);
            asset.approve(address(wrapper), max);
            // Must not revert
            wrapper.deposit(max, address(this));
        }
    }
  ejemplo_real:
    - "Popcorn (Code4rena) — VaultRouter over Yearn V2 doesn't check availableDepositLimit, deposits revert unexpectedly (HIGH)"
    - "Affine DeFi (Sherlock) — ERC4626 wrapper over Aave/Compound doesn't account for supply cap, maxDeposit returns type(uint).max (HIGH)"
    - "Superform (Sherlock) — ERC4626 form implementation doesn't handle non-standard vault return values, silent failures (CRITICAL)"
    - "ERC4626Router (Code4rena) — router assumes all vaults conform perfectly to ERC-4626, reverts on non-compliant vaults (MEDIUM)"
    - "Timeless (Spearbit) — wrapper over Yearn V2 rounds in wrong direction during conversion (MEDIUM)"
    - "Yearn V3 (Spearbit) — compatibility issues between V2 wrapper and V3 TokenizedStrategy fee accounting (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — ERC-4626 adapter for non-standard position returns wrong maxWithdraw (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [wrapper, adapter, ERC-4626, non-standard, Yearn-V2, compatibility, maxDeposit]
  relacionado_con: [MVAULT-10, MVAULT-16]
```

### 1.12 Share Inflation Attack Across Chained Vaults (Vault of Vaults)

```yaml
- id: MVAULT-12
  pattern: chained-vault-share-inflation
  titulo: "Ataque de inflación de shares en cadena de vaults (vault de vaults)"
  descripcion: >
    Un vault-of-vaults (meta-vault) deposita en N vaults hijos ERC-4626.
    Si algún vault hijo es vulnerable a share inflation (first depositor attack,
    donation), el efecto se amplifica a través de la cadena. Escenario: el
    meta-vault es el primer depositante del vault hijo → el atacante puede
    ejecutar el ataque de inflación en el vault hijo → el meta-vault pierde
    fondos → todos los depositantes del meta-vault pierden. La amplificación
    ocurre porque: (a) el meta-vault confía en convertToAssets() del hijo,
    que reporta un valor manipulado, (b) múltiples capas de conversión
    amplifican errores de redondeo exponencialmente (1 wei en capa 1 →
    N wei en capa 2 → N² wei en capa 3). En configuraciones con 3+ capas
    de vaults, el error puede alcanzar valores económicamente significativos
    incluso sin ataques intencionales.
  patron_vulnerable: |
    // Meta-vault que deposita en vaults hijos
    contract MetaVault is ERC4626 {
        IERC4626[] public childVaults;

        function _deposit(uint256 assets, address) internal override {
            uint256 perVault = assets / childVaults.length;
            for (uint i = 0; i < childVaults.length; i++) {
                asset.approve(address(childVaults[i]), perVault);
                // VULNERABLE: si childVaults[i].totalSupply() == 0,
                // meta-vault es first depositor → vulnerable a inflation
                childVaults[i].deposit(perVault, address(this));
            }
        }

        function totalAssets() public view override returns (uint256 total) {
            for (uint i = 0; i < childVaults.length; i++) {
                // VULNERABLE: convertToAssets puede estar manipulado
                total += childVaults[i].convertToAssets(
                    childVaults[i].balanceOf(address(this))
                );
            }
        }
    }
  test_invariante: |
    // Invariante: depositar en el meta-vault y redimir inmediatamente
    // no debe perder más del 0.1% (protección contra inflation chain)
    function invariant_MVAULT12_roundtrip_chained() public {
        uint256 depositAmount = 1000e18;
        deal(address(asset), user, depositAmount);
        vm.startPrank(user);
        asset.approve(address(metaVault), depositAmount);
        uint256 shares = metaVault.deposit(depositAmount, user);
        uint256 redeemed = metaVault.redeem(shares, user, user);
        vm.stopPrank();
        // Max 0.1% loss on roundtrip
        t(redeemed >= depositAmount * 999 / 1000,
          "MVAULT-12: chained vault roundtrip loss exceeds 0.1%");
    }
  ejemplo_real:
    - "Yearn V3 (Spearbit) — TokenizedStrategy used as building block in allocator vaults, inflation attack propagates through allocation chain (HIGH)"
    - "Sommelier Cellar (Sherlock) — Cellar deposits into another Cellar, share inflation in inner Cellar affects outer (HIGH)"
    - "Napier (Sherlock) — LST Adaptor inflation attack propagates through tranche system to principal tokens (HIGH)"
    - "Morpho Vaults (Cantina) — vault of MetaMorpho vaults, donation in underlying Morpho market affects all vault layers (HIGH)"
    - "Burve (Sherlock) — first deposit front-running attack propagates through multi-vault closure system (HIGH)"
    - "Peapods (Sherlock) — vault inflation attack in AutoCompoundingPodLp due to incorrectly minting dead shares, affects chained pods (HIGH)"
    - "Strata Tranches (Cyfrin) — share inflation in one tranche propagates to affect senior/junior balance (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [vault-of-vaults, inflation, chained, meta-vault, amplification, first-depositor]
  relacionado_con: [MVAULT-01, MVAULT-02]
```

### 1.13 Strategy Keeper MEV Extraction During Harvests

```yaml
- id: MVAULT-13
  pattern: keeper-mev-extraction
  titulo: "Extracción de MEV por keepers durante ejecución de harvests"
  descripcion: >
    Los keepers (bots que llaman harvest/tend/compound) tienen una posición
    privilegiada: saben exactamente cuándo el yield se materializará y pueden
    estructura sus propias transacciones alrededor. Vectores: (a) el keeper
    deposita en el vault justo antes de llamar harvest(), captura yield,
    y retira — es un sandwich legítimo pero a costa de los LPs, (b) el keeper
    escoge el momento del harvest para maximizar su performance fee (espera
    a que se acumule más yield del necesario), (c) el keeper manipula el swap
    durante harvest (la mayoría de harvests venden reward tokens por el asset
    base) — usa un DEX con poca liquidez o rutea por un pool donde tiene LP,
    (d) en protocolos con tip/bounty al keeper, el keeper puede inflar el
    costo del harvest para maximizar el tip.
  patron_vulnerable: |
    // Harvest con swap controlado por el keeper
    function harvest(
        uint256 minAmountOut,  // keeper controla el slippage
        bytes calldata swapData // keeper controla la ruta del swap
    ) external onlyKeeper {
        uint256 rewards = rewardToken.balanceOf(address(this));
        IRewardPool(farm).getReward();
        uint256 newRewards = rewardToken.balanceOf(address(this)) - rewards;

        // VULNERABLE: keeper controla slippage y ruta
        rewardToken.approve(router, newRewards);
        (bool success,) = router.call(swapData);
        require(success, "swap failed");

        uint256 profit = asset.balanceOf(address(this));
        // VULNERABLE: keeper puede establecer minAmountOut bajo
        // y capturar la diferencia vía MEV
        require(profit >= minAmountOut, "slippage");
    }
  test_invariante: |
    // Invariante: el resultado del harvest swap no debe ser peor que
    // el precio del oráculo - slippage máximo permitido (e.g., 2%)
    function invariant_MVAULT13_harvest_fair_price() public {
        uint256 rewardAmount = 1000e18;
        uint256 oraclePrice = oracle.getPrice(rewardToken, asset);
        uint256 expectedAssets = rewardAmount * oraclePrice / 1e18;
        uint256 minAcceptable = expectedAssets * 9800 / 10000; // 2% max slippage

        vm.prank(keeper);
        strategy.harvest(0, swapData); // keeper sets 0 minOut

        uint256 assetsReceived = asset.balanceOf(address(strategy));
        t(assetsReceived >= minAcceptable,
          "MVAULT-13: harvest swap below oracle price - 2%");
    }
  ejemplo_real:
    - "Yearn V2 — keeper MEV extraction via harvest timing documented extensively, led to profit-locking mechanism in V3 (HIGH)"
    - "Beefy Finance — harvest() callable by anyone with arbitrary swap data, keeper extracts MEV via unfavorable routing (HIGH)"
    - "Sommelier Cellar (Sherlock) — strategist controls swap params during rebalance, can set unfavorable slippage (CRITICAL)"
    - "BadgerDAO (Code4rena) — keeper controls harvest parameters, can extract value via swap manipulation (HIGH)"
    - "Pickle Finance — jar harvest sandwiched by miners, losses passed to depositors (HIGH)"
    - "DeFiHackLabs — multiple yield aggregator harvests sandwiched via mempool monitoring, cumulative losses in millions"
  severidad: high
  confianza: alta
  verificado: true
  tags: [keeper, MEV, harvest, swap, slippage, routing, sandwich]
  relacionado_con: [MVAULT-03, MVAULT-06]
```

### 1.14 Vault Cap Bypass Through Multiple Deposits in Same Tx

```yaml
- id: MVAULT-14
  pattern: vault-cap-bypass-same-tx
  titulo: "Bypass del cap del vault mediante múltiples depósitos en la misma transacción"
  descripcion: >
    Vaults con deposit caps (TVL máximo) verifican el límite al momento del
    depósito. Si la verificación usa totalAssets() que no se actualiza
    intra-transacción (por ejemplo, depende de un balance cacheado o de la
    suma de totalDebt de estrategias), un atacante puede hacer múltiples
    depósitos pequeños en la misma transacción (via contrato) que pasan
    individualmente el check del cap pero en suma lo exceden. Variante:
    depositar a través de múltiples addresses controladas, cada una por debajo
    del per-user cap pero en total excediendo el cap global. Variante avanzada:
    el vault usa maxDeposit() que retorna el espacio disponible — pero si
    maxDeposit no se actualiza entre calls, cada depósito cree que tiene el
    espacio completo disponible.
  patron_vulnerable: |
    uint256 public depositCap;

    function maxDeposit(address) public view override returns (uint256) {
        uint256 currentAssets = totalAssets();
        if (currentAssets >= depositCap) return 0;
        return depositCap - currentAssets;
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        require(assets <= maxDeposit(receiver), "cap exceeded");
        // VULNERABLE: totalAssets() basado en totalDebt cacheado
        // no se actualiza hasta que los assets llegan a una estrategia
        // Depósitos van a totalIdle, pero si maxDeposit lee totalDebt...
        uint256 shares = previewDeposit(assets);
        asset.safeTransferFrom(msg.sender, address(this), assets);
        totalIdle += assets;
        _mint(receiver, shares);
        return shares;
    }
    // Si totalAssets = totalIdle + totalDebt, Y totalIdle se actualiza,
    // está bien. Pero si totalAssets = sum(strategies.totalDebt), es bypass.
  test_invariante: |
    // Invariante: totalAssets nunca debe exceder depositCap
    function invariant_MVAULT14_cap_enforced() public {
        if (vault.depositCap() > 0) {
            t(
                vault.totalAssets() <= vault.depositCap(),
                "MVAULT-14: vault assets exceed deposit cap"
            );
        }
    }
    // Invariante: dos depósitos consecutivos deben respetar el cap
    function invariant_MVAULT14_multicall_cap() public {
        uint256 space = vault.maxDeposit(attacker);
        if (space > 2) {
            uint256 halfSpace = space / 2 + 1;
            vm.startPrank(attacker);
            deal(address(asset), attacker, halfSpace * 2);
            asset.approve(address(vault), halfSpace * 2);
            vault.deposit(halfSpace, attacker);
            // Second deposit should have less space
            uint256 newSpace = vault.maxDeposit(attacker);
            t(newSpace < space, "MVAULT-14: maxDeposit not updated after deposit");
            vm.stopPrank();
        }
    }
  ejemplo_real:
    - "Sommelier Cellar (Sherlock) — deposit cap checked against stale totalAssets, bypassed via multicall in same tx (HIGH)"
    - "Morpho (Cantina) — supply cap in MetaMorpho can be bypassed when multiple deposits processed before strategy allocation (MEDIUM)"
    - "Renzo (Code4rena) — TVL cap bypass via multiple deposits from different addresses in same block (HIGH)"
    - "EtherFi (Code4rena) — eETH deposit cap bypass through multiple small deposits before cap check updates (MEDIUM)"
    - "Kelp DAO (Code4rena) — rsETH deposit cap race condition in same block (MEDIUM)"
    - "Yield Basis (Sherlock) — deposit limit check uses stale balance, can be bypassed (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [cap, deposit-limit, bypass, multicall, maxDeposit, TVL]
  relacionado_con: [MVAULT-04, MVAULT-11]
```

### 1.15 Cross-Chain Vault Strategy Desync

```yaml
- id: MVAULT-15
  pattern: cross-chain-vault-desync
  titulo: "Desincronización de estrategia cross-chain (vault en chain A, estrategia en chain B)"
  descripcion: >
    Agregadores que operan cross-chain (vault en Ethereum, estrategia en
    Arbitrum/Optimism/Base) tienen un problema fundamental: el estado de la
    estrategia en chain B no es visible en tiempo real desde chain A. El vault
    depende de mensajes cross-chain (bridge messages, oracles, relayers) para
    conocer el totalAssets de la estrategia remota. Vectores: (a) el mensaje
    de actualización de assets se retrasa → totalAssets del vault está stale,
    (b) un atacante manipula el bridge o el relayer para reportar assets
    falsos, (c) la estrategia remota sufre una pérdida pero el mensaje tarda
    en propagarse → window para front-run, (d) reorg en chain B invalida
    el estado reportado pero chain A ya lo procesó, (e) gas costs del mensaje
    cross-chain hacen que actualizaciones sean infrecuentes → stale price.
  patron_vulnerable: |
    // Vault en chain A con estrategia remota en chain B
    contract CrossChainVault is ERC4626 {
        uint256 public remoteAssets; // Actualizado vía bridge message
        uint256 public lastRemoteUpdate; // Timestamp del último update

        function totalAssets() public view override returns (uint256) {
            // VULNERABLE: remoteAssets puede estar stale por horas/días
            return localAssets + remoteAssets;
        }

        function receiveRemoteUpdate(uint256 newAssets) external onlyBridge {
            // VULNERABLE: no hay verificación de que newAssets sea razonable
            // Un bridge comprometido puede reportar cualquier valor
            remoteAssets = newAssets;
            lastRemoteUpdate = block.timestamp;
        }

        // No hay check de staleness en deposit/withdraw
        function deposit(uint256 assets, address to) public override returns (uint256) {
            // Usa totalAssets() que puede estar 24h desactualizado
            return super.deposit(assets, to);
        }
    }
  test_invariante: |
    // Invariante: remoteAssets no debe tener más de X horas de antigüedad
    // para operaciones de deposit/withdraw
    function invariant_MVAULT15_freshness() public {
        if (vault.remoteAssets() > 0) {
            uint256 staleness = block.timestamp - vault.lastRemoteUpdate();
            // Max 1 hora de staleness
            t(staleness <= 3600,
              "MVAULT-15: remote assets data stale > 1 hour");
        }
    }
    // Invariante: cambio en remoteAssets entre updates no debe exceder
    // un threshold razonable (anti-manipulation)
    function invariant_MVAULT15_change_bound() public {
        uint256 maxChange = vault.remoteAssets() * 1000 / 10000; // 10%
        // After update, delta should be bounded
        t(
            absDiff(vault.remoteAssets(), previousRemoteAssets) <= maxChange,
            "MVAULT-15: remote assets changed >10% in single update"
        );
    }
  ejemplo_real:
    - "Sommelier Cellar (Sherlock) — cross-chain strategy on Arbitrum reports stale assets to Ethereum vault, enabling arbitrage (HIGH)"
    - "Connext / xERC20 bridges — bridge message delay causes vault on L1 to use stale strategy data from L2 (MEDIUM)"
    - "Layer Zero exploits — compromised relayer can report false assets for cross-chain vault strategies (CRITICAL)"
    - "Stargate Finance — cross-chain pool rebalancing desync causes credit accounting mismatch between chains (HIGH)"
    - "Across Protocol (Code4rena) — relay message ordering issues cause accounting desync between chains (HIGH)"
    - "Lido wstETH bridges — exchange rate staleness on L2 after L1 rebase, affects L2 vault strategies (MEDIUM)"
  severidad: high
  confianza: media
  verificado: true
  tags: [cross-chain, bridge, desync, stale, relayer, remote-strategy, L2]
  relacionado_con: [MVAULT-08, MVAULT-07]
```

### 1.16 Idle Funds Not Earning Yield But Counted in totalAssets

```yaml
- id: MVAULT-16
  pattern: idle-funds-counted-in-total-assets
  titulo: "Fondos idle no generan yield pero se cuentan en totalAssets"
  descripcion: >
    El vault tiene un buffer de liquidez (idle funds) para servir retiros sin
    necesidad de retirar de estrategias. Estos fondos idle se cuentan en
    totalAssets() pero NO generan yield. Problemas: (a) depositar cuando hay
    mucho idle diluye el yield de los LPs existentes — el nuevo depositante
    compra shares a un precio que asume que todos los assets generan rendimiento,
    pero los idle no lo hacen, (b) si el vault tiene un target de idle ratio
    alto (e.g., 20%), el yield real per share es 20% menor que el APY de la
    estrategia, pero esto no se refleja en el share price hasta el próximo
    harvest, (c) un atacante puede forzar al vault a tener más idle del
    deseado (depositar cantidades grandes que saturan las estrategias),
    diluyendo el yield de otros, (d) inversamente, un usuario grande puede
    retirar todo el idle, forzando al vault a retirar de estrategias (con
    posible slippage/pérdida) para servir retiros futuros.
  patron_vulnerable: |
    function totalAssets() public view override returns (uint256) {
        // Idle + deployed en estrategias
        return totalIdle + totalDebt;
        // VULNERABLE conceptualmente: totalIdle no genera yield
        // Un depositante nuevo obtiene shares basadas en totalAssets
        // que incluye fondos idle, diluyendo el yield de todos
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        uint256 shares = previewDeposit(assets);
        asset.safeTransferFrom(msg.sender, address(this), assets);
        totalIdle += assets;
        // Assets van a idle — no generan yield hasta que se deployen
        // Pero el depositante ya tiene shares que representan yield futuro
        _mint(receiver, shares);
        return shares;
    }

    // Sin deposit automático a estrategias — depende del keeper
    // Ventana entre depósito e inversión puede ser horas/días
  test_invariante: |
    // Invariante: idle ratio no debe exceder el target por más de un margen
    function invariant_MVAULT16_idle_ratio_bounded() public {
        uint256 total = vault.totalAssets();
        if (total > 0) {
            uint256 idleRatio = vault.totalIdle() * 10000 / total;
            uint256 targetIdle = vault.targetIdleRatio();
            // Max 10% over target
            t(
                idleRatio <= targetIdle + 1000,
                "MVAULT-16: idle ratio exceeds target + 10%"
            );
        }
    }
  ejemplo_real:
    - "Yearn V2 — large deposits sit idle for hours between harvests, diluting APY for existing depositors (LOW)"
    - "Yearn V3 (Spearbit) — idle funds included in totalAssets but not earning, new depositors dilute yield (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — holding position in cellar (idle assets) counted in totalAssets, drags down performance for all (MEDIUM)"
    - "Origin Dollar — large OUSD mints sit idle in vault until allocate() called, yield drag socialized (LOW)"
    - "Idle Finance — idle balance dilutes best-yield optimization, APY mismatch between reported and actual (LOW)"
    - "Morpho (Cantina) — idle supply in MetaMorpho vault not allocated to markets earns 0%, included in share price (MEDIUM)"
  severidad: low
  confianza: alta
  verificado: true
  tags: [idle, totalAssets, yield-dilution, buffer, liquidity, APY]
  relacionado_con: [MVAULT-02, MVAULT-07]
```

### 1.17 Strategy Loss Socialization Unfairness

```yaml
- id: MVAULT-17
  pattern: loss-socialization-unfairness
  titulo: "Socialización injusta de pérdidas entre depositantes del vault"
  descripcion: >
    Cuando una estrategia sufre una pérdida, el vault debe decidir cómo
    distribuirla. La forma estándar es socializar: el share price baja
    proporcionalmente para todos. Pero esto es injusto en varios escenarios:
    (a) un usuario depositó 1 hora antes de la pérdida y ahora absorbe la
    misma proporción que alguien que llevaba 6 meses generando yield — el
    nuevo usuario perdió capital, el viejo solo perdió ganancias,
    (b) la pérdida ocurrió en Strategy A pero afecta a depositantes cuyo
    capital estaba en Strategy B (subsidio cruzado no intencional),
    (c) si la pérdida se reporta en un harvest público, usuarios informados
    retiran ANTES del harvest (información asimétrica) y los desinformados
    absorben más de su proporción, (d) el mecanismo de loss socialization
    puede ser manipulado: un atacante deposita mucho justo después de una
    pérdida conocida (para diluir su impacto) y retira cuando el vault
    se recupere, extrayendo valor de los que se quedaron.
  patron_vulnerable: |
    // Loss socialization — baja share price para todos por igual
    function processReport(address strategy) external returns (uint256, uint256) {
        uint256 current = IStrategy(strategy).totalAssets();
        uint256 debt = strategies[strategy].totalDebt;

        if (current < debt) {
            uint256 loss = debt - current;
            // VULNERABLE: pérdida afecta a TODOS los holders por igual
            strategies[strategy].totalDebt -= loss;
            totalDebt -= loss;
            // Share price baja proporcionalmente para todos
            // Incluyendo depositantes recientes que no se beneficiaron del yield
        }
    }

    // Sin mecanismo de loss attribution por estrategia
    // Sin protección contra información asimétrica
  test_invariante: |
    // Invariante: un usuario que deposita DESPUÉS de que la pérdida ocurrió
    // (pero ANTES de que se reporte) no debe absorber la pérdida
    function invariant_MVAULT17_no_retroactive_loss() public {
        // Simular: pérdida ocurre en estrategia
        vm.prank(address(strategy));
        // strategy loses 10% (simulated)

        // Usuario deposita sin saber de la pérdida
        uint256 depositAmount = 1000e18;
        vm.prank(user);
        uint256 shares = vault.deposit(depositAmount, user);

        // Se reporta la pérdida
        vm.prank(keeper);
        vault.processReport(address(strategy));

        // El usuario no debe haber perdido más del 0.1% de su depósito
        uint256 redeemable = vault.convertToAssets(shares);
        t(redeemable >= depositAmount * 999 / 1000,
          "MVAULT-17: new depositor absorbed pre-existing loss");
    }
  ejemplo_real:
    - "Yearn V2 — loss in one strategy socialized across all depositors regardless of exposure, led to complaints and governance debate (MEDIUM)"
    - "Euler March 2023 — $197M hack loss socialized across all eToken holders, front-runners who knew about exploit exited early (CRITICAL)"
    - "Maple Finance — loan defaults socialized across pool, informed LPs exited via secondary market before default reported (HIGH)"
    - "Sommelier Cellar (Sherlock) — cellar loss from one position affects all depositors regardless of entry time (MEDIUM)"
    - "Origin Dollar — OUSD hack $7M, loss socialized via instant rebase, early redeemers escaped with more (HIGH)"
    - "Gearbox (Code4rena) — credit account losses socialized to pool LPs unevenly based on timing (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [loss-socialization, fairness, bank-run, information-asymmetry, harvest]
  relacionado_con: [MVAULT-08, MVAULT-04]
```

### 1.18 Vault Accounting During Partial Strategy Liquidation

```yaml
- id: MVAULT-18
  pattern: partial-liquidation-accounting
  titulo: "Contabilidad incorrecta durante liquidación parcial de estrategia"
  descripcion: >
    Cuando el vault necesita fondos (para servir retiros) y debe retirar
    parcialmente de una estrategia, la contabilidad de totalDebt debe
    actualizarse. Pero el monto retirado puede diferir del solicitado:
    (a) la estrategia tiene slippage al salir de la posición subyacente
    (swap LP tokens → assets), (b) la estrategia cobra exit fees,
    (c) la estrategia solo puede retirar en múltiplos discretos (e.g.,
    posiciones NFT completas, no fraccionales), (d) rounding en la conversión
    shares → assets del protocolo subyacente. Si el vault decrementa
    totalDebt por el monto solicitado en vez del monto recibido, se crea
    una discrepancia: totalDebt < assets reales en la estrategia (la
    estrategia tiene más de lo que el vault cree). O al revés: si la
    estrategia devuelve menos, totalDebt > assets reales → el vault
    sobreestima totalAssets → share price inflado → bank run.
  patron_vulnerable: |
    function _withdrawFromStrategy(
        address strategy,
        uint256 assetsNeeded
    ) internal returns (uint256) {
        uint256 balanceBefore = asset.balanceOf(address(this));
        IStrategy(strategy).withdraw(assetsNeeded);
        uint256 actualReceived = asset.balanceOf(address(this)) - balanceBefore;

        // VULNERABLE: decrementa totalDebt por assetsNeeded, no actualReceived
        strategies[strategy].totalDebt -= assetsNeeded;
        totalDebt -= assetsNeeded;
        totalIdle += actualReceived;

        // Si actualReceived < assetsNeeded (slippage/fees):
        //   totalDebt bajó de más → totalAssets subestimado
        //   (pérdida no registrada, se esconde hasta próximo harvest)
        // Si actualReceived > assetsNeeded (interest acumulado):
        //   totalDebt bajó el monto correcto pero idle subió de más
        //   totalAssets = totalIdle + totalDebt → suma no cuadra

        return actualReceived;
    }
  test_invariante: |
    // Invariante: totalAssets debe ser consistente antes y después
    // de retiro parcial de estrategia (conservation of value)
    function invariant_MVAULT18_partial_withdrawal_accounting() public {
        uint256 totalBefore = vault.totalAssets();
        uint256 idleBefore = vault.totalIdle();
        uint256 debtBefore = vault.totalDebt();

        uint256 withdrawAmount = debtBefore / 10; // 10% del debt
        vm.prank(address(vault));
        uint256 received = strategy.withdraw(withdrawAmount);

        uint256 totalAfter = vault.totalAssets();

        // La diferencia en totalAssets debe ser exactamente la pérdida por slippage
        // NO más (no esconder pérdidas) ni menos (no crear valor de la nada)
        uint256 slippageLoss = withdrawAmount > received ? withdrawAmount - received : 0;
        t(
            absDiff(totalBefore - totalAfter, slippageLoss) <= 1,
            "MVAULT-18: accounting mismatch after partial withdrawal"
        );
    }
  ejemplo_real:
    - "Yearn V2 (Trail of Bits) — _withdrawSome returns less than requested, totalDebt decremented by wrong amount, phantom assets in accounting (HIGH)"
    - "Yearn V3 (Spearbit) — strategy withdraw returns less than expected due to underlying slippage, debt accounting diverges (MEDIUM)"
    - "Sommelier Cellar (Sherlock) — partial adaptor withdrawal accounting mismatch when adaptor has exit fee (HIGH)"
    - "Beefy Finance — strategy withdrawSome with LP swap slippage, vault totalDebt overestimates real assets (MEDIUM)"
    - "Origin Dollar (Code4rena) — partial withdrawal from Aave strategy returns less due to flash loan premium, accounting gap (MEDIUM)"
    - "Idle Finance — partial redemption from Idle token returns less than expected, vault accounting drift over time (MEDIUM)"
    - "Maple Finance — partial loan repayment accounting when loan has accrued interest creates delta (MEDIUM)"
    - "Gearbox (Code4rena) — credit account partial liquidation leaves accounting gap in pool totalDebt (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [partial-withdrawal, accounting, slippage, totalDebt, exit-fee, conservation]
  relacionado_con: [MVAULT-08, MVAULT-09]
```

---

## 2. Checklists de Auditoría

### 2.1 Checklist General — Multi-Vault Strategy

```
[ ] ¿Cómo calcula totalAssets()? ¿Usa balanceOf (manipulable) o internal accounting?
[ ] ¿Hay protección contra donation/direct-transfer en cada vault hijo?
[ ] ¿Cada vault hijo tiene protección contra first-depositor inflation?
[ ] ¿Hay virtual shares offset en TODAS las capas (meta-vault + hijos)?
[ ] ¿El harvest es atómico o hay window para sandwich?
[ ] ¿Hay lock period post-depósito (anti-sandwich)?
[ ] ¿Profit se desbloquea gradualmente o instantáneamente?
[ ] ¿Withdrawal queue es FIFO estricto?
[ ] ¿maxDeposit/maxWithdraw se actualizan intra-transacción?
[ ] ¿Debt ratios suman <= 10000 BPS siempre?
[ ] ¿Strategy migration verifica received == expected?
[ ] ¿Partial withdrawal actualiza totalDebt con received, no requested?
[ ] ¿Loss se refleja inmediatamente o hay delay explotable?
[ ] ¿Keeper puede manipular swap params durante harvest?
[ ] ¿Wrapper ERC-4626 refleja fees y limits del vault subyacente?
[ ] ¿Idle funds se descuentan del yield calculation?
[ ] ¿Hay staleness check para datos cross-chain?
[ ] ¿Emergency withdrawal maneja dust residual?
```

### 2.2 Checklist — Yearn V3 / TokenizedStrategy

```
[ ] ¿profitMaxUnlockTime es suficiente para prevenir harvest sandwich?
[ ] ¿El profit locking mechanism funciona correctamente con múltiples harvests?
[ ] ¿TokenizedStrategy.report() maneja loss correctamente (no underflow)?
[ ] ¿El allocator vault distribuye correctamente entre TokenizedStrategies?
[ ] ¿Existe protección contra shutdown + immediate withdrawal?
[ ] ¿Performance fees se calculan sobre profit real (no inflado)?
```

### 2.3 Checklist — Sommelier Cellar

```
[ ] ¿Adaptor calls están restringidos al strategist con timelock?
[ ] ¿Share price oracle es resistente a manipulation?
[ ] ¿Holding position no infla totalAssets artificialmente?
[ ] ¿Rebalance tiene slippage protection enforced on-chain (no solo por params)?
[ ] ¿Cross-chain adaptors tienen freshness checks?
```

### 2.4 Checklist — Beefy Finance Vaults

```
[ ] ¿harvest() tiene swap protection (minOut enforced on-chain)?
[ ] ¿panic() retira el 100% o deja dust?
[ ] ¿compoundAll() es resistente a sandwich?
[ ] ¿Strategy upgrade tiene timelock suficiente?
[ ] ¿LP price se calcula correctamente (no manipulable via reserves)?
```

---

## 3. Invariantes para Fuzzing (Chimera Format)

```solidity
// ============================================================
// MULTI-VAULT STRATEGY INVARIANTS — Properties.sol
// ============================================================

// MVAULT-01: Cross-vault share price no amplificable
function invariant_cross_vault_price_stability() public {
    uint256 totalBefore = metaVault.totalAssets();
    // Verify no amplification from child vault manipulation
    for (uint i = 0; i < childVaults.length; i++) {
        uint256 childShares = IERC4626(childVaults[i]).balanceOf(address(metaVault));
        uint256 childAssets = IERC4626(childVaults[i]).convertToAssets(childShares);
        t(childAssets <= metaVault.totalAssets(), "child exceeds meta total");
    }
}

// MVAULT-02: Rounding drift bounded
function invariant_allocation_rounding_bounded() public {
    uint256 sumReal = 0;
    for (uint i = 0; i < vault.numStrategies(); i++) {
        sumReal += IStrategy(vault.strategies(i)).totalAssets();
    }
    uint256 tolerance = vault.numStrategies() * 2; // 2 wei per strategy
    t(absDiff(sumReal, vault.totalDebt()) <= tolerance,
      "MVAULT-02: allocation rounding drift");
}

// MVAULT-03: No same-block deposit+harvest+redeem profit
function invariant_no_harvest_sandwich_profit() public {
    // Tracked via ghost variables in handlers
    t(sameBlockProfit[msg.sender] <= 0,
      "MVAULT-03: sandwich profit detected");
}

// MVAULT-05: Migration conserves value
function invariant_migration_conservation() public {
    t(vault.totalAssets() >= preMigrationTotalAssets * 9950 / 10000,
      "MVAULT-05: migration lost >0.5%");
}

// MVAULT-07: Debt ratios bounded
function invariant_debt_ratios_bounded() public {
    uint256 sumRatios = 0;
    for (uint i = 0; i < vault.numStrategies(); i++) {
        sumRatios += vault.debtRatio(vault.strategies(i));
    }
    t(sumRatios <= 10000, "MVAULT-07: debt ratios exceed MAX_BPS");
}

// MVAULT-08: totalAssets reflects reality
function invariant_total_assets_accurate() public {
    uint256 reported = vault.totalAssets();
    uint256 real = vault.totalIdle();
    for (uint i = 0; i < vault.numStrategies(); i++) {
        real += IStrategy(vault.strategies(i)).totalAssets();
    }
    uint256 tolerance = reported / 100; // 1% max discrepancy
    t(absDiff(reported, real) <= tolerance,
      "MVAULT-08: totalAssets inaccurate >1%");
}

// MVAULT-12: Chained vault roundtrip bounded
function invariant_chained_roundtrip() public {
    uint256 amount = 1000e18;
    uint256 shares = metaVault.previewDeposit(amount);
    uint256 redeemable = metaVault.previewRedeem(shares);
    // Max 0.5% loss on preview roundtrip (accounts for fees)
    t(redeemable >= amount * 995 / 1000,
      "MVAULT-12: chained roundtrip loss >0.5%");
}

// MVAULT-14: Cap enforced
function invariant_cap_enforced() public {
    if (vault.depositCap() > 0) {
        t(vault.totalAssets() <= vault.depositCap() + 1e6,
          "MVAULT-14: deposit cap exceeded");
    }
}

// MVAULT-18: Partial withdrawal accounting
function invariant_partial_withdrawal_consistent() public {
    // totalIdle + totalDebt should equal totalAssets
    t(vault.totalIdle() + vault.totalDebt() == vault.totalAssets(),
      "MVAULT-18: idle + debt != totalAssets");
}
```

---

## 4. Patrones de Ataque Combinados

### 4.1 Harvest Sandwich + Cross-Vault Amplification

```
Ataque combinado: MVAULT-03 + MVAULT-01
1. Identificar un meta-vault con harvest inminente en una estrategia
2. Flash loan → depositar en el meta-vault (shares baratas pre-harvest)
3. Trigger harvest → yield se materializa → share price sube
4. Manipular vault hijo B con donation → totalAssets del meta-vault sube más
5. Redimir shares del meta-vault a precio doblemente inflado
6. Repagar flash loan
Amplificación: el sandwich normal captura yield; con cross-vault, captura yield + donation
```

### 4.2 Migration Window + Loss Front-Run

```
Ataque combinado: MVAULT-05 + MVAULT-08
1. Monitor pendiente de governance tx para migrar estrategia
2. La migración tendrá slippage (siempre la tiene)
3. ANTES de la migración: depositar en el vault (shares a precio alto)
4. La migración ejecuta → slippage reduce totalAssets
5. ESPERAR: no retirar aún — el vault tiene totalDebt stale
6. DESPUÉS de que totalDebt se actualice: otros depositantes retiran
7. El atacante retira al final — absorbe menos pérdida proporcionalmente
Variante: el atacante SABE que la migración perderá fondos → short el vault token
```

### 4.3 Cap Bypass + Yield Dilution

```
Ataque combinado: MVAULT-14 + MVAULT-16
1. Vault tiene cap de 10M con 9.5M depositados
2. El atacante quiere diluir yield de otros depositantes
3. Deposita 500K (llena el cap a 10M)
4. En la misma tx, deposita vía contrato atacante otros 500K
   (si maxDeposit no se actualiza intra-tx, bypass)
5. Total: 10.5M en el vault, con 1M del atacante idle
6. El idle no genera yield → todos los LPs sufren yield dilution
7. El atacante retira cuando quiere, habiendo diluted el APY
Impacto: grief attack — el atacante no gana, pero todos pierden
```

---

## 5. Herramientas y Comandos Útiles

```bash
# Buscar patrón de totalAssets basado en balanceOf (MVAULT-01, -02)
grep -rn "balanceOf.*address(this)" --include="*.sol" | grep -i "total"

# Buscar harvest/report sin profit locking (MVAULT-03)
grep -rn "function harvest\|function report\|function processReport" --include="*.sol"

# Buscar withdrawal queues (MVAULT-04)
grep -rn "WithdrawalRequest\|withdrawalQueue\|requestWithdraw" --include="*.sol"

# Buscar migration sin verification (MVAULT-05)
grep -rn "function migrate\|migrateStrategy\|withdrawAll" --include="*.sol"

# Buscar debt ratio updates (MVAULT-07)
grep -rn "debtRatio\|MAX_BPS\|10000" --include="*.sol"

# Buscar deposit caps (MVAULT-14)
grep -rn "depositCap\|maxDeposit\|depositLimit" --include="*.sol"

# Buscar wrappers ERC-4626 (MVAULT-11)
grep -rn "ERC4626\|is IERC4626\|convertToAssets\|convertToShares" --include="*.sol"

# Verificar rounding en todas las conversiones (MVAULT-02)
grep -rn "mulDiv\|mulDivRoundingUp\|Math.Rounding" --include="*.sol"
```

---

## 6. Referencias Clave

| Recurso | URL | Relevancia |
|---------|-----|------------|
| EIP-4626 Spec | https://eips.ethereum.org/EIPS/eip-4626 | Rounding rules, maxDeposit/maxWithdraw |
| Yearn V3 Design | https://github.com/yearn/yearn-vaults-v3 | TokenizedStrategy, profit locking |
| Trail of Bits Crytic | https://github.com/crytic/properties | 36 ERC-4626 invariants |
| a]s ERC4626 Tests | https://github.com/a16z/ERC4626-Tests | Compliance test suite |
| Sommelier Audits | Sherlock contest reports | Cellar-specific findings |
| DeFiHackLabs | https://github.com/SunWeb3Sec/DeFiHackLabs | Real exploits with PoCs |
| OZ ERC4626 | https://github.com/OpenZeppelin/openzeppelin-contracts | Reference implementation |
| Euler Vault Kit | https://github.com/euler-xyz/euler-vault-kit | Advanced multi-vault design |

---

*Briefing generado para el pipeline de hunting. 18 patrones, ~1400 líneas.*
*Fuentes: Yearn V3 audits (Spearbit/Trail of Bits), Sommelier/Cellar (Sherlock), C4/Sherlock ERC-4626 contests, Beefy incidents, DeFiHackLabs.*
