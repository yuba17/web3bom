grep_targets:
  - "cToken"
  - "CToken"
  - "CErc20"
  - "CEther"
  - "exchangeRateStored"
  - "exchangeRateCurrent"
  - "accrueInterest"
  - "borrowFresh"
  - "redeemFresh"
  - "mintFresh"
  - "repayBorrowFresh"
  - "liquidateBorrowFresh"
  - "seize"
  - "Comptroller"
  - "enterMarkets"
  - "exitMarket"
  - "borrowAllowed"
  - "mintAllowed"
  - "reserveFactor"
  - "totalReserves"
  - "totalBorrows"
  - "borrowIndex"
  - "supplyIndex"
  - "supplyCap"
  - "borrowCap"
  - "collateralFactor"
  - "closeFactor"
  - "liquidationIncentive"
  - "getAccountLiquidity"
  - "getHypotheticalAccountLiquidity"
  - "absorb"
  - "isAbsorbPaused"
  - "eMode"
  - "ISOLATION_MODE"
  - "stableRate"
  - "rebalanceStableBorrowRate"
  - "flashLoanPremium"
  - "donateToReserves"
  - "compSpeeds"
  - "compAccrued"
  - "claimComp"
  - "initialExchangeRateMantissa"

# Briefing: Lending Market Forks — Compound V2/V3, Aave V2/V3 y Forks

## Contexto del dominio

Los protocolos de lending son la columna vertebral de DeFi. Compound V2 y Aave V2/V3 son
los dos diseños dominantes, y la mayoría de los protocolos de lending son forks (a veces
ligeramente modificados) de uno de ellos. Esto crea un patrón recurrente: bugs descubiertos
en un fork se replican en docenas de otros.

**Compound V2 forks notables**: CREAM Finance, Rari/Fuse, Sonne Finance, Moonwell, Benqi,
Scream, Aurigami, OnyxProtocol, Iron Bank, Hundred Finance, Lava Lending, Numen Finance.

**Aave V2/V3 forks notables**: Radiant Capital, UwULend, ZeroLend, Granary Finance,
Agave, Geist Finance, Sturdy Finance.

**Compound V3 (Comet) forks**: Sonne V2, Moonwell Apollo.

Los bugs más costosos de la historia DeFi provienen de forks que:
1. Listan tokens con callbacks (ERC-777, ERC-721, tokens rebasing) sin reentrancy guards
2. No implementan controles de mercado vacío (first depositor attack)
3. Copian configuraciones de parámetros sin adaptarlas a su contexto
4. Modifican funciones core sin entender las invariantes subyacentes

**Incidentes acumulados**: >$600M USD en pérdidas documentadas solo en lending forks.

---

patterns:

```yaml
- id: lmf-001
  titulo: "First Depositor Attack — Inflación de Exchange Rate en cToken / aToken vacío"
  causa_raiz: |
    En Compound V2 y sus forks, el exchange rate de un mercado vacío (totalSupply == 0)
    se calcula como initialExchangeRateMantissa. El primer depositante recibe shares basadas
    en: mintTokens = actualMintAmount / exchangeRate. Si el atacante deposita 1 wei y luego
    dona tokens directamente al contrato (vía transfer, no mint), el exchange rate se infla
    enormemente. El siguiente depositante recibe 0 shares por rounding down, perdiendo todo
    su depósito.

    La variante Aave es análoga: cuando el mercado aToken tiene supply == 0, la primera
    interacción establece el index, y una donación directa al pool antes de que otros
    depositen puede causar pérdida similar.
  como_funciona: |
    1. Mercado cToken nuevo, totalSupply = 0, totalCash = 0.
    2. Atacante llama mint() con 1 wei → recibe 1 cToken share.
    3. Atacante transfiere directamente 10,000 USDC al contrato cToken (sin llamar mint()).
    4. exchangeRate = (totalCash + totalBorrows - totalReserves) / totalSupply
       = (10000e6 + 1) / 1 = 10000e6 + 1 por share.
    5. Víctima deposita 9,999 USDC → mintTokens = 9999e6 / 10000e6 = 0 (rounding down).
    6. Los 9,999 USDC de la víctima quedan en el contrato. Atacante retira todo.
    7. Beneficio neto: ~9,999 USDC menos gas y la donación inicial.

    Variante Sonne (mayo 2024): Sonne listó un nuevo mercado vía governance con timelock
    de 2 días. El atacante observó la transacción de governance, esperó al timelock, y
    ejecutó el ataque entre la creación del mercado y la transacción de liquidez inicial.
  invariante: |
    // El exchange rate no debe poder ser inflado por donaciones directas
    // Ghost: track exchange rate antes y después de operaciones
    uint256 ghost_exchangeRateBefore;

    function check_lmf001_exchange_rate_inflation() internal {
        uint256 currentRate = cToken.exchangeRateCurrent();
        if (cToken.totalSupply() > 0 && ghost_exchangeRateBefore > 0) {
            // Exchange rate no debe saltar más de 100% en una sola operación
            t(currentRate <= ghost_exchangeRateBefore * 2,
              "LMF-001: exchange rate inflated >2x in single operation");
        }
        ghost_exchangeRateBefore = currentRate;
    }

    function check_lmf001_no_zero_mint() internal {
        // Si un usuario deposita >0, debe recibir >0 shares
        // (excepción: si el depósito es menor que 1 wei de share value)
        uint256 depositAmount = 1000e6; // ejemplo USDC
        uint256 sharesBefore = cToken.balanceOf(address(this));
        cToken.mint(depositAmount);
        uint256 sharesAfter = cToken.balanceOf(address(this));
        t(sharesAfter > sharesBefore,
          "LMF-001: deposit resulted in zero shares minted");
    }
  que_mirar:
    - "exchangeRateStored() cuando totalSupply == 0"
    - "initialExchangeRateMantissa — si es muy bajo, el ataque es más barato"
    - "¿Hay mint mínimo o initial deposit en el constructor?"
    - "¿El protocolo usa virtual shares/assets (offset) como OpenZeppelin ERC4626?"
    - "¿Existe timelock entre listing de mercado y primera liquidez?"
    - "¿Hay 'dead shares' quemadas al primer depósito?"
  como_se_arregla: |
    - Quemar las primeras 1000 shares (dead shares) al crear el mercado
    - Usar virtual offset: totalSupply + OFFSET, totalAssets + OFFSET
    - Depositar liquidez inicial atómicamente en la misma tx de creación del mercado
    - Establecer un mint mínimo (e.g., 1000 wei) que impida donación rentable
  trampas:
    - "En protocolos maduros ya deployados, este ataque suele aplicarse solo a NUEVOS mercados listados"
    - "Si initialExchangeRateMantissa es alto (e.g., 1e18), la donación necesaria es enorme y puede no ser rentable"
    - "Muchos audits reportan esto como Medium/Low porque requiere timing preciso — pero Sonne perdió $20M"
    - "No confundir con ERC4626 inflation attack — mecanismo similar pero implementación diferente"
  solodit_ids:
    - "h-1-first-depositor-can-abuse-exchange-rate-to-steal-funds-from-later-depositors-sherlock-surge-surge-git"
    - "m-13-first-erc4626-deposit-can-break-share-calculation-sherlock-astaria-astaria-git"
    - "m-1-vault-inflation-attack-sherlock-smilee-finance-git"
    - "h-4-victims-fund-can-be-stolen-due-to-rounding-error-and-exchange-rate-manipulation-sherlock-napier-git"
    - "h-2-vault-is-vulnerable-to-inflation-attack-which-can-cause-complete-loss-of-user-funds-sherlock-numa-git"
    - "initial-mint-front-run-inflation-attack-mixbytes-none-nuts-finance-markdown"
    - "inflation-attack-on-zero-total-stake-ottersec-none-thala-lsd-deps-pdf"
    - "first-deposit-attack-via-share-price-manipulation-zokyo-none-vaultka-markdown"
  incidentes:
    - nombre: "Hundred Finance"
      fecha: "Mar 2022 (Gnosis) + Apr 2023 (Optimism)"
      monto: "$7M total"
      detalle: "Empty market donation attack on Compound V2 fork. Atacante donó tokens al mercado hERC20 vacío, inflando exchange rate."
      verificado: true
      fuente: "DeFiHackLabs, post-mortem oficial"
    - nombre: "Sonne Finance"
      fecha: "May 2024"
      monto: "$20M"
      detalle: "Atacante explotó timelock de 2 días entre governance proposal para listar VELO y la primera liquidez. Ejecutó first depositor attack en la ventana."
      verificado: true
      fuente: "DeFiHackLabs, Hacken post-mortem"
    - nombre: "OnyxProtocol"
      fecha: "Nov 2023"
      monto: "$2M"
      detalle: "Empty market precision loss — similar first depositor vector"
      verificado: true
      fuente: "DeFiHackLabs"
    - nombre: "Raft.fi"
      fecha: "Nov 2023"
      monto: "$3.2M"
      detalle: "Inflation/rounding attack on vault with rebasing mechanics"
      verificado: true
      fuente: "DeFiHackLabs"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [first-depositor, exchange-rate, inflation, donation, empty-market, cToken, rounding]
  relacionado_con: [lmf-005, lmf-010]

- id: lmf-002
  titulo: "Interest Rate Model Jump Kink Exploitation — Manipulación de utilización para forzar jump rate"
  causa_raiz: |
    El Interest Rate Model (IRM) de Compound V2 usa un modelo de dos tramos con un "kink"
    (punto de inflexión). Por debajo del kink (e.g., 80% utilización), la tasa sube
    linealmente. Por encima del kink, la tasa salta exponencialmente (jump multiplier).
    Un atacante puede manipular la utilización para forzar tasas extremas y causar:
    (a) liquidaciones masivas al inflar la deuda de borrowers,
    (b) costos prohibitivos para borrowers existentes, o
    (c) generar utilidad explotando la diferencia entre supply y borrow rates.
  como_funciona: |
    1. Mercado tiene utilización del 75% (bajo el kink del 80%).
    2. Atacante borrow masivo (posiblemente con flash loan como colateral en otro mercado)
       para llevar la utilización al 95%.
    3. La tasa de interés salta de 5% APR a 200%+ APR (jump multiplier).
    4. Todos los borrowers existentes acumulan interés a tasa extrema.
    5. Posiciones cercanas a liquidación se vuelven liquidables inmediatamente.
    6. Atacante puede liquidar esas posiciones con profit.
    7. Atacante repaga su borrow (quizá en el mismo bloque si usó flash loan).

    Variante en forks: el fork copia el IRM pero cambia los parámetros sin entender
    las implicaciones. Un kink muy bajo (e.g., 50%) o un jump multiplier muy alto
    (e.g., 100x) hacen el ataque trivial.
  invariante: |
    // La utilización no debe poder ser manipulada instantáneamente a niveles
    // que causen interest rate spikes destructivos
    function check_lmf002_utilization_bounds() internal {
        uint256 util = irm.getUtilizationRate(
            cToken.getCash(), cToken.totalBorrows(), cToken.totalReserves()
        );
        uint256 borrowRate = irm.getBorrowRate(
            cToken.getCash(), cToken.totalBorrows(), cToken.totalReserves()
        );
        // Si utilización > kink, verificar que la tasa no es destructiva
        if (util > irm.kink()) {
            // Tasa anualizada no debe exceder 500% (value judgment del protocolo)
            uint256 annualRate = borrowRate * 365 days;
            t(annualRate <= 5e18,
              "LMF-002: borrow rate exceeds 500% APR — jump rate exploitation risk");
        }
    }
  que_mirar:
    - "JumpRateModel — valores de kink, multiplierPerBlock, jumpMultiplierPerBlock"
    - "¿Se puede llegar al kink con un solo borrow?"
    - "¿Hay protección contra flash loan borrow que manipule utilización?"
    - "¿El protocolo tiene rate caps o circuit breakers?"
    - "InterestRateModel.getBorrowRate() — valores extremos posibles"
  como_se_arregla: |
    - Rate caps: máximo borrow rate incluso sobre el kink
    - Delay antes de que el jump rate aplique (gradual ramp)
    - Flash loan protection: no permitir borrow+repay en el mismo bloque
    - Monitoring: alertas cuando utilización cruza el kink
  trampas:
    - "Utilización alta puede ser legítima en mercados volátiles — no todo kink crossing es ataque"
    - "Si el flash loan no es de ese mismo mercado, el atacante necesita colateral real"
    - "Muchos protocolos permiten intencionalmente tasas altas como incentivo para repagar"
  solodit_ids:
    - "m-14-reserves-should-not-be-considered-part-of-the-available-liquidity-while-calculating-the-interest-rate-sherlock-sentiment-sentiment-git"
    - "h-01-siloamo-can-be-forced-to-fund-reduced-interest-rates-by-manipulating-utilization-zachobront-none-olympusdao-markdown_"
    - "m-8-users-can-borrow-all-loan-tokens-sherlock-surge-surge-git"
  incidentes:
    - nombre: "Compound (DAI market)"
      fecha: "Nov 2020"
      monto: "$85-100M en liquidaciones"
      detalle: "Precio de DAI en Coinbase subió a $1.34 temporalmente, combinado con alta utilización, causó liquidaciones masivas. No fue ataque directo al IRM pero demostró el riesgo de la interacción oracle + utilización."
      verificado: true
      fuente: "Compound governance forum, DeFi incident trackers"
    - "Surge Protocol — users can borrow all loan tokens, pushing utilization to 100% and triggering extreme rates (high)"
  severidad: high
  confianza: media
  verificado: true
  tags: [interest-rate, kink, jump-rate, utilization, manipulation, flash-loan]
  relacionado_con: [lmf-005, lmf-012]

- id: lmf-003
  titulo: "Compound V2 borrowFresh / Fuse Reentrancy — Clásico CREAM/Rari/Hundred"
  causa_raiz: |
    En Compound V2, las funciones borrowFresh(), redeemFresh(), y mintFresh() transfieren
    tokens ANTES de actualizar el estado interno. Si el token subyacente tiene un callback
    (ERC-777 tokensReceived, ERC-721 onERC721Received, tokens con hooks, tokens rebasing),
    el atacante puede re-entrar al protocolo durante la transferencia con estado inconsistente.

    Compound original mitiga esto solo listando tokens ERC-20 simples. Los forks listan
    tokens con callbacks sin agregar reentrancy guards, replicando la vulnerabilidad.
  como_funciona: |
    1. Fork lista un token con callback (e.g., imBTC que es ERC-777, o un token con hook).
    2. Atacante deposita como colateral en un mercado normal.
    3. Atacante llama borrow() en el mercado del token con callback.
    4. borrowFresh() ejecuta doTransferOut() → token.transfer(atacante, amount).
    5. Callback: token llama tokensReceived() en el contrato del atacante.
    6. Dentro del callback, atacante re-entra: llama borrow() otra vez.
    7. El estado aún no se actualizó → accountBorrows[atacante] == 0 → segundo borrow aprobado.
    8. Atacante puede repetir N veces hasta drenar el pool.
    9. Al finalizar, todas las actualizaciones de estado se ejecutan con el último estado.

    CREAM (Oct 2021): El ataque fue más sofisticado — combinó reentrancy con oracle
    manipulation y flash loans para amplificar el daño a $130M.
  invariante: |
    // No debe ser posible ejecutar funciones de estado durante una transferencia
    bool internal ghost_inBorrow;

    function check_lmf003_no_reentrant_borrow() internal {
        t(!ghost_inBorrow, "LMF-003: reentrant borrow detected");
    }

    // Alternativamente: balance pre-borrow + borrow amount == balance post-borrow
    function check_lmf003_borrow_accounting(uint256 borrowAmount) internal {
        uint256 debtBefore = cToken.borrowBalanceCurrent(address(this));
        uint256 cashBefore = underlying.balanceOf(address(this));
        cToken.borrow(borrowAmount);
        uint256 debtAfter = cToken.borrowBalanceCurrent(address(this));
        uint256 cashAfter = underlying.balanceOf(address(this));
        t(debtAfter == debtBefore + borrowAmount,
          "LMF-003: debt increase != borrow amount — possible reentrancy");
        t(cashAfter == cashBefore + borrowAmount,
          "LMF-003: cash increase != borrow amount — possible reentrancy");
    }
  que_mirar:
    - "¿Tiene nonReentrant modifier en borrow/mint/redeem/repay/liquidate?"
    - "¿El subyacente tiene callbacks? Buscar: ERC-777, ERC-721, ERC-1155, hooks"
    - "doTransferOut() / doTransferIn() — ¿se ejecutan antes de actualizar estado?"
    - "¿Hay reentrancy guard a nivel de Comptroller o solo a nivel de cToken?"
    - "¿El protocolo lista tokens arbitrarios sin governance review?"
    - "Orden CEI: ¿effects antes de interactions?"
  como_se_arregla: |
    - Agregar nonReentrant modifier a TODAS las funciones de cToken que transfieren tokens
    - Seguir CEI: actualizar accountBorrows, totalBorrows ANTES de doTransferOut
    - Restringir tokens listados: solo ERC-20 sin callbacks
    - Si se permiten tokens con callbacks, reentrancy guard es OBLIGATORIO
  trampas:
    - "El reentrancy guard a nivel de UN cToken no protege contra cross-market reentrancy"
    - "Tokens que parecen ERC-20 pueden tener hooks ocultos (upgradeable proxies)"
    - "La versión Compound original NO tiene este bug — solo forks que listan tokens raros"
    - "Algunos forks agregan nonReentrant a borrow() pero olvidan liquidateBorrow()"
  solodit_ids:
    - "h-2-reentrancy-in-flashaction-allows-draining-liquidity-pools-sherlock-arcadia-git"
    - "h-2-adversary-can-reenter-takeoverdebt-during-liquidation-to-steal-vault-funds-sherlock-real-wagmi-2-git"
    - "h-02-stealing-fund-by-applying-reentrancy-attack-on-removecollateral-startliquidationauction-and-purchaseliquidationauctionnft-code4rena-backed-protocol-papr-contest-git"
    - "h-13-balancerpairoracle-can-be-manipulated-using-read-only-reentrancy-sherlock-none-blueberry-update-git"
    - "m-4-not-updating-state-before-making-custom-external-call-can-cause-borrowers-to-loose-assets-due-to-re-entrancy-sherlock-teller-lender-groups-update-audit-git"
    - "redeemnative-reentrancy-enables-permanent-fund-freeze-systemic-misaccounting-and-liquidation-cascades-mixbytes-none-notional-finance-markdown"
  incidentes:
    - nombre: "CREAM Finance (ataque 1)"
      fecha: "Aug 2021"
      monto: "$18.8M"
      detalle: "Reentrancy via AMP token (ERC-777-like) en borrowFresh. Atacante re-entró durante transferencia para borrow adicional."
      verificado: true
      fuente: "CertiK post-mortem, SlowMist analysis"
    - nombre: "CREAM Finance (ataque 2)"
      fecha: "Oct 2021"
      monto: "$130M"
      detalle: "Combinación de reentrancy + oracle manipulation + flash loans. Usó crYUSD y crETH como vectores."
      verificado: true
      fuente: "Mudit Gupta analysis, DeFiHackLabs"
    - nombre: "Rari Capital / Fuse"
      fecha: "Apr 2022"
      monto: "$80M"
      detalle: "Reentrancy en pools Fuse que listaban tokens con callbacks. exitMarket() no protegido."
      verificado: true
      fuente: "CertiK post-mortem, Fei Protocol disclosure"
    - nombre: "Hundred Finance (Gnosis)"
      fecha: "Mar 2022"
      monto: "$6.5M"
      detalle: "Reentrancy en compound fork sin nonReentrant. Combinado con exchange rate manipulation."
      verificado: true
      fuente: "DeFiHackLabs"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [reentrancy, CEI-violation, callback, ERC-777, compound-fork, borrowFresh, cToken]
  relacionado_con: [lmf-001, lmf-006]

- id: lmf-004
  titulo: "Aave V3 E-Mode Liquidation Threshold Misconfiguration — Activos correlacionados con LTV incorrecto"
  causa_raiz: |
    Aave V3 introduce Efficiency Mode (e-mode) que permite LTV/liquidation thresholds
    más altos para activos correlacionados (e.g., stETH/ETH, USDC/DAI). Si los parámetros
    de e-mode están mal configurados — LTV demasiado alto, liquidation threshold demasiado
    cercano al LTV, o la correlación asumida se rompe — las posiciones pueden quedar:
    (a) inmediatamente liquidables después de pedir prestado al max LTV, o
    (b) insuficientemente colateralizadas cuando la correlación falla (depeg).

    Forks de Aave copian la mecánica e-mode pero la configuran con parámetros incorrectos
    o la aplican a activos que no son realmente correlacionados.
  como_funciona: |
    1. Protocolo configura e-mode para ETH/stETH con LTV = 95%, liquidation threshold = 97%.
    2. Usuario deposita 100 stETH, borrowea 95 ETH (max LTV).
    3. stETH depeg de 1% → valor colateral cae a 99 stETH equivalente.
    4. Health factor = (99 * 0.97) / 95 = 1.01 — casi liquidable.
    5. Cualquier movimiento adicional o acumulación de interés → liquidación.
    6. Con depeg de 3% (históricamente ha ocurrido): posición irrecuperable, bad debt.

    Variante más sutil: e-mode se activa para un activo cuyo oracle price feed usa una
    fuente diferente al subyacente. E.g., wstETH priceado con Chainlink stETH/ETH pero
    el exchange rate wstETH/stETH no se actualiza → discrepancia.
  invariante: |
    // En e-mode, la posición debe sobrevivir un depeg del X% del activo correlacionado
    function check_lmf004_emode_depeg_resilience() internal {
        uint256 DEPEG_BPS = 500; // 5% depeg stress test
        (uint256 totalCollateralBase, uint256 totalDebtBase,,,, uint256 healthFactor)
            = pool.getUserAccountData(user);
        // Simular depeg: reducir collateral value en DEPEG_BPS
        uint256 stressedCollateral = totalCollateralBase * (10000 - DEPEG_BPS) / 10000;
        uint256 stressedHF = stressedCollateral * 1e18 / totalDebtBase;
        t(stressedHF > 1e18,
          "LMF-004: position becomes liquidatable with 5% depeg — e-mode params too aggressive");
    }
  que_mirar:
    - "EModeCategory — LTV, liquidationThreshold, liquidationBonus, priceSource"
    - "¿El gap entre LTV y liquidation threshold es >5%? Si es <3%, problema"
    - "¿Los activos en el e-mode category realmente están correlacionados?"
    - "¿El oracle del activo correlacionado usa la misma fuente?"
    - "¿Hay circuit breaker para depeg events?"
    - "setEModeCategory() — ¿quién puede cambiar los parámetros?"
  como_se_arregla: |
    - Mantener gap mínimo de 5% entre LTV y liquidation threshold en e-mode
    - Usar oracles con depeg detection (e.g., stETH/ETH Chainlink feed con deviation check)
    - Circuit breaker: desactivar e-mode si el depeg supera un umbral
    - Stress testing de configuración antes de deployment
  trampas:
    - "E-mode misconfiguration suele ser governance issue, no code bug — pero los forks a menudo hardcodean parámetros"
    - "La correlación histórica no garantiza correlación futura (Terra/LUNA)"
    - "Algunos protocolos usan 'liquidation threshold == LTV' en e-mode, lo cual es intencionalmente agresivo"
  solodit_ids:
    - "users-can-become-immediately-liquidatable-after-executing-an-action-trailofbits-none-aave-v4-pdf"
    - "mismatched-function-name-quantstamp-e-mode-core-pool-venus-markdown"
  incidentes:
    - nombre: "Venus Protocol"
      fecha: "May 2021"
      monto: "$100M+ bad debt"
      detalle: "No e-mode per se, pero misma raíz: XVS usado como colateral con LTV agresivo. XVS pump+dump causó posiciones irrecuperables. Bad debt nunca recuperado."
      verificado: true
      fuente: "Venus post-mortem, DefiLlama"
    - "Aave V4 — Users immediately liquidatable after action due to risk premium ordering (medium)"
    - "Backed Protocol — Users liquidated right after taking maximal debt, no LTV gap (high)"
    - "Sentiment — originationFee makes borrower liquidatable immediately (medium)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [e-mode, liquidation-threshold, LTV, correlated-assets, depeg, aave-fork, configuration]
  relacionado_con: [lmf-007, lmf-008]

- id: lmf-005
  titulo: "Reserve Factor Bypass — Timing de accrueInterest para evitar acumulación de fees"
  causa_raiz: |
    En Compound V2, accrueInterest() calcula el interés acumulado desde la última
    actualización y deposita una fracción (reserveFactor) en las reservas del protocolo.
    Si un atacante puede manipular el timing de cuándo se llama accrueInterest(), puede:
    (a) hacer que el interés se acumule en un período muy corto → reservas mínimas,
    (b) depositar justo antes de una acumulación grande → capturar el yield sin pagar fees,
    (c) o explotar la diferencia entre borrowIndex y supplyIndex.

    En forks, el reserveFactor a veces es configurable y puede cambiarse sin accrueInterest()
    previo, aplicando el nuevo factor retroactivamente a interés ya acumulado.
  como_funciona: |
    1. ReserveFactor = 20%. Interés ha acumulado durante 1 semana pero accrueInterest()
       no se ha llamado.
    2. Admin propone cambiar reserveFactor a 0% vía governance.
    3. Governance ejecuta _setReserveFactor(0) SIN llamar accrueInterest() primero.
    4. Ahora se llama accrueInterest(): todo el interés de 1 semana se acumula con factor 0%.
    5. Protocolo pierde la reserva que debería haber cobrado.

    Variante: atacante deposita→espera mucho→retira todo de una vez, y el interés acumulado
    durante su depósito tiene reserveFactor aplicado solo al momento de accrual, no
    pro-rata durante el período.
  invariante: |
    // accrueInterest() debe llamarse antes de cualquier cambio de reserveFactor
    function check_lmf005_accrue_before_reserve_change(
        uint256 oldReserveFactor,
        uint256 newReserveFactor
    ) internal {
        // Verificar que accrualBlockNumber == block.number (interés al día)
        t(cToken.accrualBlockNumber() == block.number,
          "LMF-005: reserveFactor changed without accruing interest first");
    }

    // Reservas deben crecer monotónicamente (excepto por retiros admin)
    uint256 ghost_totalReservesBefore;
    function check_lmf005_reserves_monotonic() internal {
        uint256 reservesAfter = cToken.totalReserves();
        t(reservesAfter >= ghost_totalReservesBefore,
          "LMF-005: reserves decreased without admin withdrawal");
        ghost_totalReservesBefore = reservesAfter;
    }
  que_mirar:
    - "_setReserveFactor — ¿llama accrueInterest() antes?"
    - "_setInterestRateModel — misma pregunta"
    - "¿Hay interacciones donde accrueInterest() NO se llama como primer paso?"
    - "¿El reserveFactor puede ser 0? ¿Hay minimum?"
    - "admin._reduceReserves() — ¿puede vaciar completamente las reservas?"
  como_se_arregla: |
    - SIEMPRE llamar accrueInterest() al inicio de _setReserveFactor
    - Establecer mínimo de reserveFactor (e.g., 5%)
    - Usar modifier que force accrual antes de cualquier cambio de parámetros
  trampas:
    - "Cambios de reserveFactor vía governance suelen tener timelock — el ataque requiere monitoreo"
    - "En la práctica, accrueInterest() se llama frecuentemente por actividad orgánica"
    - "Algunos protocolos intencionalmente setean reserveFactor = 0 para bootstrapping"
  solodit_ids:
    - "wrong-reserve-factor-computation-on-p2p-rates-spearbit-morpho-pdf"
    - "m-9-protocol-reserve-within-a-ltoken-vault-can-be-lent-out-sherlock-sentiment-sentiment-git"
    - "h-10-interest-rate-is-updated-before-updating-the-debt-when-repaying-debt-sherlock-zerolend-one-git"
  incidentes:
    - "Wild Credit — Reward computation wrong, rewards distributed before index update (high)"
    - "Morpho — Wrong reserve factor computation on P2P rates (medium, Spearbit)"
  severidad: medium
  confianza: media
  verificado: true
  tags: [reserve-factor, accrueInterest, timing, fees, governance, compound-fork]
  relacionado_con: [lmf-002, lmf-012]

- id: lmf-006
  titulo: "Comptroller.enterMarkets Missing Validation — Listar cToken malicioso como colateral"
  causa_raiz: |
    En Compound V2, enterMarkets() permite a un usuario declarar qué mercados quiere usar
    como colateral. El Comptroller verifica que el cToken esté listado (markets[cToken].isListed).
    En forks mal implementados:
    (a) enterMarkets() no verifica isListed, permitiendo usar contratos arbitrarios como colateral,
    (b) el proceso de listing no valida el subyacente (puede listar un cToken que wrappea un
    token sin valor real), o
    (c) exitMarket() tiene condiciones que pueden ser bypaseadas.

    Rari Fuse fue el caso extremo: pools permissionless donde CUALQUIERA podía listar
    cualquier token como colateral, lo cual habilitó múltiples ataques.
  como_funciona: |
    1. Fork permite listing permisionless de cTokens (como Rari Fuse).
    2. Atacante crea un ERC-20 malicioso cuyo balanceOf() devuelve valores arbitrarios.
    3. Atacante despliega un cToken que wrappea este token malicioso.
    4. Atacante lista el cToken en el Comptroller del fork.
    5. Atacante minta cTokens (el subyacente es su token controlado — puede mintear infinito).
    6. Atacante llama enterMarkets() con su cToken malicioso → ahora cuenta como colateral.
    7. Comptroller calcula getAccountLiquidity() usando el oracle price del token malicioso.
    8. Si el oracle es manipulable o controlado, atacante tiene colateral infinito.
    9. Atacante borrowea todos los activos reales del pool.

    Variante sin listing permisionless: atacante manipula el oracle del token ya listado
    para inflar su valor como colateral → misma consecuencia.
  invariante: |
    // enterMarkets solo debe aceptar cTokens listados con oracle válido
    function check_lmf006_enter_markets_validation(address cToken) internal {
        (bool isListed, uint256 collateralFactor) = comptroller.markets(cToken);
        t(isListed, "LMF-006: unlisted cToken accepted as collateral");
        // Verificar que hay un oracle price > 0 para este mercado
        uint256 price = oracle.getUnderlyingPrice(CToken(cToken));
        t(price > 0, "LMF-006: cToken collateral has zero oracle price");
    }
  que_mirar:
    - "enterMarkets() — ¿verifica isListed?"
    - "¿Quién puede llamar _supportMarket()? ¿Es permisionless?"
    - "¿El oracle puede devolver precios para tokens no verificados?"
    - "getAccountLiquidity() — ¿itera sobre todos los assets del usuario incluyendo no-verificados?"
    - "¿Hay whitelist de tokens aceptados?"
  como_se_arregla: |
    - Verificar isListed en enterMarkets (Compound V2 ya lo hace — pero forks lo quitan)
    - Restringir _supportMarket a governance / multisig
    - Validar oracle price > 0 y oracle source antes de listar
    - Si listing es permisionless, requerir time delay + security deposit
  trampas:
    - "Compound V2 original tiene esta validación — el bug es exclusivo de forks que la quitan"
    - "Rari Fuse fue diseñado intencionalmente como permisionless — el risk model era diferente"
    - "Incluso con listing restringido, un token legítimo puede volverse malicioso si es upgradeable"
  solodit_ids:
    - "claimtotreasurycomp-steals-users-comp-rewards-spearbit-morpho-pdf"
  incidentes:
    - nombre: "Rari Capital / Fuse (múltiples)"
      fecha: "2021-2022"
      monto: "$80M+"
      detalle: "Pools Fuse con listing permisionless. Atacantes listaron tokens maliciosos o manipularon oracles de tokens listados para inflar colateral."
      verificado: true
      fuente: "CertiK, FeiDAO post-mortems"
    - nombre: "Numen Finance"
      fecha: "Mar 2023"
      monto: "$300K"
      detalle: "Compound V2 fork en BNB Chain. Atacante explotó validación débil en el mercado para manipular colateral."
      verificado: true
      fuente: "DeFiHackLabs"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [comptroller, enterMarkets, listing, permisionless, collateral, malicious-token, compound-fork]
  relacionado_con: [lmf-003, lmf-007]

- id: lmf-007
  titulo: "Oracle Price Feed Mismatch — cToken usa oracle diferente al precio real del subyacente"
  causa_raiz: |
    En lending markets, el oracle price feed del colateral/deuda determina todo: health
    factor, liquidation threshold, borrow power. Si el oracle price no refleja el precio
    real del subyacente (por usar fuente incorrecta, feed stale, o derivado en vez de spot),
    todas las decisiones del protocolo son incorrectas.

    Patrones comunes en forks:
    - cToken wrappea wstETH pero oracle usa precio de stETH (ignora unwrap ratio)
    - cToken wrappea LP token pero oracle usa spot price en vez de fair value
    - Oracle usa Uniswap V2 spot (manipulable) en vez de TWAP o Chainlink
    - Feed de Chainlink tiene heartbeat de 24h pero el fork asume actualización continua
    - Oracle devuelve precio en 8 decimals pero el fork espera 18
  como_funciona: |
    1. Fork lista wstETH como colateral con oracle = Chainlink stETH/USD.
    2. wstETH vale ~1.17 stETH (exchange rate por staking rewards acumulados).
    3. Oracle reporta stETH price para wstETH → subestima el colateral en ~17%.
    4. Usuarios depositando wstETH obtienen 17% menos borrow power de lo que deberían.
    5. PERO si el fork tiene el error inverso (usa wstETH price para stETH), los usuarios
       obtienen 17% MÁS borrow power → riesgo de bad debt.

    Otra variante: fork usa Uniswap V2 spot price.
    1. Atacante flashloan 10M tokens del subyacente.
    2. Vende en el Uniswap pool → spot price del colateral se desploma.
    3. Oracle lee spot price → reporta colateral como sin valor.
    4. Atacante liquida posiciones de otros usuarios a precio de descuento.
    5. Atacante recompra los tokens y devuelve el flash loan.
  invariante: |
    // Oracle price debe estar dentro del rango razonable vs precio spot
    function check_lmf007_oracle_sanity(address cToken) internal {
        uint256 oraclePrice = oracle.getUnderlyingPrice(CToken(cToken));
        // El precio debe ser > 0 (no stale) y razonable
        t(oraclePrice > 0, "LMF-007: oracle returning zero price");

        // Si hay un feed secundario, comparar que la diferencia es <5%
        uint256 secondaryPrice = getSecondaryPrice(cToken);
        if (secondaryPrice > 0) {
            uint256 diff = oraclePrice > secondaryPrice
                ? oraclePrice - secondaryPrice
                : secondaryPrice - oraclePrice;
            uint256 maxDiff = oraclePrice * 500 / 10000; // 5%
            t(diff <= maxDiff,
              "LMF-007: oracle price >5% different from secondary source");
        }
    }
  que_mirar:
    - "oracle.getUnderlyingPrice() — ¿qué feed usa para cada mercado?"
    - "¿El token es un wrapper (wstETH, cbETH, rETH)? ¿El oracle incluye el exchange rate?"
    - "¿El oracle usa spot price de DEX? Buscar: getReserves(), slot0, observe()"
    - "¿Hay stale price check? Buscar: updatedAt, heartbeat, roundId"
    - "¿Los decimals del oracle coinciden con lo que espera el Comptroller?"
    - "UniswapAnchoredView, ChainlinkAdapter, CustomOracle — revisar implementación"
  como_se_arregla: |
    - Usar Chainlink con heartbeat check (updatedAt + HEARTBEAT >= block.timestamp)
    - Para wrapped tokens: oracle = basePrice * exchangeRate
    - TWAP con ventana mínima de 30 min para proteger contra manipulación spot
    - Dual oracle: Chainlink + TWAP, usar el más conservador
    - Validar decimals explícitamente en el constructor del oracle adapter
  trampas:
    - "TWAP tampoco es infalible — con suficiente capital y tiempo, se puede manipular"
    - "Chainlink puede devolver precio stale sin revertir — siempre chequear updatedAt"
    - "Algunos tokens tienen exchange rates que solo suben (staking) — usar last-known si oracle falla"
    - "La diferencia wstETH/stETH es ~17% y crece con el tiempo — hardcodear un ratio es peligroso"
  solodit_ids:
    - "m-16-chainlinkadapteroracle-will-return-the-wrong-price-for-asset-if-underlying-aggregator-hits-minanswer-sherlock-blueberry-blueberry-git"
    - "h-3-curvetricryptooraclegetprice-contains-math-error-that-causes-lp-to-be-priced-completely-wrong-sherlock-none-blueberry-update-3-git"
    - "m-1-stetheth-chainlink-oracle-has-too-long-of-heartbeat-and-deviation-threshold-which-can-cause-loss-of-funds-sherlock-olympus-olympus-update-git"
    - "h-4-users-can-abuse-discrepancies-between-oracle-and-true-asset-price-to-mint-more-ohm-than-needed-and-profit-from-it-sherlock-olympus-olympus-update-git"
    - "h-1-adversary-can-sandwich-oracle-updates-to-exploit-vault-sherlock-olympus-olympus-update-git"
    - "pendle-pt-oracle-ignores-losses-during-sy-redemptions-leading-to-over-valued-collateral-mixbytes-none-notional-finance-markdown"
  incidentes:
    - nombre: "Mango Markets"
      fecha: "Oct 2022"
      monto: "$114M"
      detalle: "Atacante (Avraham Eisenberg) manipuló oracle price de MNGO pumpeando el spot price en Mango's own market, luego usó el valor inflado como colateral para borrowear todo."
      verificado: true
      fuente: "DoJ indictment, Mango DAO post-mortem"
    - nombre: "UwULend"
      fecha: "Jun 2024"
      monto: "$19.3M"
      detalle: "Oracle manipulation en fork de Aave. Atacante manipuló precio del colateral via DEX."
      verificado: true
      fuente: "DeFiHackLabs"
    - nombre: "Venus Protocol (XVS)"
      fecha: "May 2021"
      monto: "$100M+ bad debt"
      detalle: "Oracle price de XVS (token nativo) fue manipulado de $70 a $144. Usuarios borrowearon BTC/ETH con XVS inflado como colateral."
      verificado: true
      fuente: "Venus post-mortem, DefiLlama"
    - nombre: "Blueberry Update"
      fecha: "2023"
      monto: "Audit finding (pre-exploit)"
      detalle: "BalancerPairOracle manipulable via read-only reentrancy + CurveTriCryptoOracle math error"
      verificado: true
      fuente: "Sherlock audit"
  severidad: critical
  confianza: alta
  verificado: true
  tags: [oracle, price-feed, mismatch, manipulation, spot-price, TWAP, Chainlink, stale]
  relacionado_con: [lmf-004, lmf-008]

- id: lmf-008
  titulo: "Liquidation Incentive > Shortfall — Loops de auto-liquidación rentable"
  causa_raiz: |
    En Compound V2, el liquidador recibe colateral con un bonus (liquidationIncentive,
    típicamente 108%). Si este bonus es mayor que el shortfall del borrower, o si el
    closeFactor permite liquidar más del déficit, el liquidador puede lucrar repitiendo
    liquidaciones. Peor: el borrower puede auto-liquidarse creando dos cuentas y
    extraer valor del protocolo.

    El self-liquidation loop funciona cuando:
    liquidationIncentive * seizedCollateral > repaidDebt + gas

    En forks con parámetros mal configurados (e.g., liquidationIncentive = 150%),
    la auto-liquidación es siempre rentable.
  como_funciona: |
    1. Atacante con 2 cuentas: A (borrower) y B (liquidator).
    2. Cuenta A deposita 100 ETH, borrowea 75 ETH worth de USDC (LTV 75%).
    3. ETH baja ligeramente → cuenta A liquidable.
    4. Cuenta B llama liquidateBorrow() contra A.
    5. B repaga parte de la deuda de A y recibe colateral + 8% bonus.
    6. Si el bonus (8 ETH) > gas cost + interest → profit neto.
    7. En forks con liquidationIncentive alto o closeFactor alto,
       el profit es significativamente mayor.
    8. Repetir con diferentes posiciones para drenar rewards.

    Variante más sofisticada con flash loans:
    - Flash loan USDC → repay deuda de A → seize colateral de A con bonus → swap → repay flash loan → profit
  invariante: |
    // Después de self-liquidation, el valor total entre ambas cuentas
    // no debe incrementar (excepto por interés legítimo)
    function check_lmf008_no_profitable_self_liquidation() internal {
        uint256 totalValueBefore = getAccountValue(accountA) + getAccountValue(accountB);
        // Ejecutar liquidación: B liquida A
        comptroller.liquidateBorrow(accountA, repayAmount, cTokenCollateral);
        uint256 totalValueAfter = getAccountValue(accountA) + getAccountValue(accountB);
        t(totalValueAfter <= totalValueBefore + DUST,
          "LMF-008: self-liquidation created value — profitable loop detected");
    }
  que_mirar:
    - "liquidationIncentive — si es >110%, mayor riesgo de self-liquidation rentable"
    - "closeFactor — si es 100% (full liquidation), el profit se maximiza en una tx"
    - "¿El protocolo permite liquidar la propia deuda (msg.sender == borrower)?"
    - "¿Hay minimum shortfall para permitir liquidación?"
    - "¿El bonus se calcula sobre el repayAmount o sobre toda la deuda?"
  como_se_arregla: |
    - Prohibir self-liquidation (msg.sender != borrower) — pero bypaseable con 2 cuentas
    - Establecer closeFactor conservador (50% máx)
    - LiquidationIncentive moderado (105-108%)
    - Verificar que el profit del liquidador no exceda el shortfall
    - Absorber parte del bonus como reservas del protocolo
  trampas:
    - "Con 2 cuentas, prohibir self-liquidation no funciona — necesitas economic design"
    - "LiquidationIncentive bajo desincentiva a liquidadores reales → más bad debt"
    - "Es un balance: muy alto = explotable, muy bajo = nadie liquida"
    - "Algunos protocolos intencionalmente permiten self-liquidation como feature (graceful exit)"
  solodit_ids:
    - "inflation-attack-on-empty-ticks-mixbytes-none-curve-finance-markdown"
    - "self-liquidations-of-leveraged-positions-can-be-profitable-spearbit-none-euler-labs-evk-pdf"
    - "m-10-liquidation-should-make-a-borrower-healthier-code4rena-inverse-finance-inverse-finance-git"
  incidentes:
    - "Curve Finance — Inflation attack on empty ticks via self-liquidation (high, MixBytes audit)"
    - "Euler EVK — Self-liquidations of leveraged positions can be profitable (medium, Spearbit audit)"
    - "Inverse Finance — Liquidation should make borrower healthier but doesn't (medium, Code4rena)"
    - "Surge — Liquidator gains collateral AND reduces own debt via rounding (medium)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [liquidation, self-liquidation, incentive, closeFactor, profit-loop, compound-fork]
  relacionado_con: [lmf-004, lmf-011]

- id: lmf-009
  titulo: "Borrow Cap Bypass via Flash Loan + Multi-Block — Exceder límites entre transacciones"
  causa_raiz: |
    Los borrow caps en Compound V2 forks se verifican en borrowAllowed(): requieren
    totalBorrows + borrowAmount <= borrowCap. Pero:
    (a) Si totalBorrows no se actualiza atómicamente (e.g., interest accrual pendiente),
    el cap check usa un valor stale.
    (b) Si el cap se verifica por mercado individual pero el user borrow through multiple
    paths (direct + vía transformer/leverage), el total puede exceder el cap.
    (c) En Aave, si supply caps se verifican contra totalSupply de aTokens pero hay una
    discrepancia con los activos reales depositados, el cap no refleja la realidad.
  como_funciona: |
    1. Borrow cap = 1,000,000 USDC. Actual totalBorrows = 999,000 USDC.
    2. accrueInterest() no se ha llamado en horas → totalBorrows está stale.
    3. Interés acumulado pero no registrado = 5,000 USDC.
    4. Real totalBorrows = 1,004,000 USDC (ya excede el cap).
    5. Pero borrowAllowed() verifica contra 999,000 → permite borrow de 1,000 más.
    6. Total real = 1,005,000 USDC, 5,000 sobre el cap.

    Variante con flash loan:
    1. Atacante flash-loan borrow → repay en otro mercado → libre colateral → borrow again.
    2. Cada borrow individual está bajo el cap, pero el estado intermedio no se verifica.
  invariante: |
    // totalBorrows nunca debe exceder borrowCap (incluyendo interés pendiente)
    function check_lmf009_borrow_cap() internal {
        cToken.accrueInterest(); // Forzar actualización
        uint256 totalBorrows = cToken.totalBorrows();
        uint256 borrowCap = comptroller.borrowCaps(address(cToken));
        if (borrowCap > 0) {
            t(totalBorrows <= borrowCap,
              "LMF-009: totalBorrows exceeds borrowCap");
        }
    }

    // Supply cap análogo
    function check_lmf009_supply_cap() internal {
        uint256 totalSupply = cToken.totalSupply();
        uint256 exchangeRate = cToken.exchangeRateCurrent();
        uint256 totalUnderlying = totalSupply * exchangeRate / 1e18;
        uint256 supplyCap = comptroller.supplyCaps(address(cToken));
        if (supplyCap > 0) {
            t(totalUnderlying <= supplyCap,
              "LMF-009: total supply exceeds supplyCap");
        }
    }
  que_mirar:
    - "borrowAllowed() — ¿llama accrueInterest() antes de verificar el cap?"
    - "¿Los caps se verifican en TODAS las rutas de borrowing (direct, leverage, transformer)?"
    - "¿Hay race condition entre cap check y state update?"
    - "mintAllowed() — misma pregunta para supply caps"
    - "¿Flash loan borrow cuenta contra el cap?"
  como_se_arregla: |
    - Llamar accrueInterest() antes de verificar caps
    - Verificar caps después de la actualización de estado (post-condition), no solo antes
    - Incluir flash loan borrows en el cap check
    - Usar totalBorrowsCurrent() (que incluye interés pendiente) en vez de totalBorrows()
  trampas:
    - "Caps muy ajustados pueden causar DoS a usuarios legítimos"
    - "El bypass suele ser de magnitude pequeña (interés pendiente) — impacto real bajo"
    - "Si accrueInterest se llama cada bloque por actividad orgánica, el gap es mínimo"
  solodit_ids:
    - "supply-cap-bypass-via-return_repay_remainings_flag-race-condition-trailofbits-none-evaa-finance-pdf"
    - "m-1-dngmxjuniorvaultmanagerharvestfees-can-push-junior-vault-borrowedusdc-above-borrow-cap-and-dos-vault-sherlock-rage-trade-rage-trade-git"
    - "l-12-rounding-in-_expectedsupplyassets-may-exceed-supplycap-pashov-audit-group-none-eulerearn_2025-07-25-markdown"
    - "l-11-flash-loan-attack-reallocates-liquidity-to-riskier-strategy-vaults-pashov-audit-group-none-eulerearn_2025-07-25-markdown"
  incidentes:
    - "EVAA Finance — Supply cap bypass via return_repay_remainings_flag race condition (high, Trail of Bits)"
    - "Rage Trade — harvestFees can push junior vault borrowedUSDC above borrow cap (medium)"
  severidad: medium
  confianza: media
  verificado: true
  tags: [borrow-cap, supply-cap, bypass, flash-loan, stale-state, accrueInterest]
  relacionado_con: [lmf-005, lmf-010]

- id: lmf-010
  titulo: "Supply Cap Accounting Mismatch — totalSupply vs activos reales depositados"
  causa_raiz: |
    En Aave V3 y forks, supply caps limitan cuántos activos pueden depositarse en un
    mercado. El cap se verifica contra aToken.totalSupply() escalado por el index. Pero
    la divergencia puede ocurrir cuando:
    (a) Tokens con fee-on-transfer depositan menos de lo que el protocolo registra,
    (b) Donaciones directas al pool no incrementan totalSupply pero sí el balance,
    (c) Rebasing tokens cambian el balance sin interacción → desync,
    (d) Liquidaciones seize aTokens pero no reducen el supply del mercado del colateral.

    En Compound V2 forks, el supply cap es implícito (totalSupply * exchangeRate) pero
    la misma divergencia aplica.
  como_funciona: |
    1. Supply cap = 10M USDC. Actual deposited = 9.8M.
    2. Token underlying tiene 0.1% fee-on-transfer.
    3. Usuario deposita 300K USDC → protocolo registra 300K → totalSupply sube a 10.1M.
    4. Pero solo 299,700 USDC llegaron al contrato (fee deducido).
    5. Supply cap check dice 10.1M > 10M → bloquea nuevos depósitos.
    6. Pero el protocolo solo tiene 10,099,700 realmente — hay phantom supply.

    Variante inversa: donación directa incrementa balance pero no totalSupply.
    Supply cap no se alcanza, pero el mercado tiene más activos de los que trackea.
    La diferencia se la lleva quien hizo la donación cuando retira.
  invariante: |
    // La diferencia entre totalSupply escalado y balance real debe ser mínima
    function check_lmf010_supply_accounting() internal {
        uint256 totalScaled = aToken.scaledTotalSupply();
        uint256 index = pool.getReserveNormalizedIncome(asset);
        uint256 totalLogical = totalScaled * index / 1e27;
        uint256 actualBalance = IERC20(asset).balanceOf(address(aToken));
        uint256 totalBorrowed = variableDebtToken.totalSupply() + stableDebtToken.totalSupply();
        // balance + borrowed >= logical supply (cash + borrows >= deposits)
        t(actualBalance + totalBorrowed + DUST >= totalLogical,
          "LMF-010: actual balance + borrows < logical supply — accounting mismatch");
    }
  que_mirar:
    - "¿El protocolo soporta fee-on-transfer tokens? Buscar: transferAmount != amount"
    - "¿Se verifica balanceOf después de transferFrom para confirmar cuánto llegó?"
    - "¿Rebasing tokens pueden cambiar el balance del pool sin mint/burn de aTokens?"
    - "¿Donaciones directas al pool afectan el exchange rate o el supply cap?"
    - "mintAllowed() / validateSupply() — ¿usa totalSupply o balanceOf?"
  como_se_arregla: |
    - Verificar amount recibido post-transfer: balanceAfter - balanceBefore
    - No soportar fee-on-transfer tokens (Aave V3 los excluye)
    - Para rebasing tokens, usar wrapped version (wstETH no stETH)
    - Supply cap contra actualBalance, no solo totalSupply
  trampas:
    - "Fee-on-transfer tokens son raros pero existen (USDT en algunas chains, STA, PAXG)"
    - "La mayoría de protocolos maduros explícitamente excluyen estos tokens"
    - "El mismatch suele ser pequeño — buscar acumulación over time"
  solodit_ids:
    - "mismatched-total-supply-cap-between-l1-and-l2-tokens-cyfrin-none-linea-tokens-markdown"
  incidentes:
    - "Linea Tokens — Mismatched total supply cap between L1 and L2 tokens (Cyfrin audit)"
    - "Multiple protocols — fee-on-transfer tokens causing accounting mismatches (various audits)"
  severidad: medium
  confianza: media
  verificado: true
  tags: [supply-cap, accounting, fee-on-transfer, rebasing, mismatch, aave-fork]
  relacionado_con: [lmf-009, lmf-001]

- id: lmf-011
  titulo: "Seized Collateral Accounting Error — Liquidador recibe cTokens sin update en protocolo"
  causa_raiz: |
    En liquidaciones de Compound V2, la función seize() transfiere cTokens del borrower
    al liquidador. El Comptroller debe actualizar la lista de assets del liquidador
    (para que los cTokens seized cuenten como colateral) y reducir la lista del borrower.
    En forks:
    (a) seize() no llama enterMarkets automáticamente para el liquidador → seized cTokens
    no cuentan como colateral del liquidador,
    (b) El borrower's membership no se actualiza → Comptroller sigue contando colateral
    que ya no tiene, inflando su liquidity,
    (c) Si collateral cToken == borrow cToken, la lógica interna (seizeInternal) puede
    tener diferentes accounting paths.
  como_funciona: |
    1. Borrower tiene 100 cETH como colateral, debe 80 USDC.
    2. Liquidador llama liquidateBorrow(borrower, 40 USDC, cETH).
    3. seize() transfiere 42 cETH (40 + 5% bonus) del borrower al liquidador.
    4. BUG: totalSupply del cETH no cambia (es una transferencia, no burn/mint).
    5. PERO si el fork tiene accounting adicional (e.g., gauge staking, reward tracking)
       que trackea balances individuales, esos trackers no se actualizan.
    6. Borrower: tracker dice que tiene 100 cETH, real: 58 cETH.
    7. Liquidador: tracker dice 0 cETH, real: 42 cETH.
    8. Si rewards se distribuyen basándose en el tracker → distribuidas incorrectamente.
    9. Si health factor usa el tracker → borrower parece más sano de lo que es.
  invariante: |
    // Después de seize, la suma de balances individuales debe igualar totalSupply
    function check_lmf011_seize_accounting() internal {
        uint256 sumIndividual = 0;
        for (uint i = 0; i < users.length; i++) {
            sumIndividual += cToken.balanceOf(users[i]);
        }
        t(sumIndividual == cToken.totalSupply(),
          "LMF-011: sum of individual balances != totalSupply after seize");
    }

    // Health factor del borrower debe reflejar colateral seized
    function check_lmf011_borrower_health_post_seize(
        address borrower,
        uint256 healthBefore,
        uint256 seizedAmount
    ) internal {
        (,,, uint256 shortfall) = comptroller.getAccountLiquidity(borrower);
        // Si había shortfall antes, debe estar reducido (no aumentado)
        // La liquidación debe mejorar o mantener la salud del sistema
    }
  que_mirar:
    - "seize() / seizeInternal() — ¿actualiza todos los trackers de balance?"
    - "¿Hay reward tracking (gauge, staking) que usa balanceOf vs internal tracker?"
    - "¿enterMarkets se llama automáticamente para el liquidador al recibir seized cTokens?"
    - "¿El comptroller actualiza accountAssets[] del borrower post-seize?"
    - "¿Hay hooks en _beforeTokenTransfer o _afterTokenTransfer que manejen el seize?"
  como_se_arregla: |
    - Override _transfer en cToken para actualizar todos los trackers
    - Auto-enterMarkets para el liquidador al recibir seized cTokens
    - Verificar que balanceOf y internal trackers están sincronizados post-seize
    - Usar un hook _afterSeize() que actualice todos los sistemas dependientes
  trampas:
    - "En Compound V2 puro, esto no es un problema — totalSupply y balanceOf son consistentes"
    - "El bug aparece cuando forks agregan capas encima (gauges, rewards, staking)"
    - "La divergencia puede ser silenciosa — no revierte, simplemente da datos incorrectos"
  solodit_ids:
    - "h-03-lendingpairliquidateaccount-fails-if-tokens-are-lent-out-code4rena-wild-credit-wild-credit-contest-git"
    - "liquidating-morphos-aave-position-leads-to-state-desync-spearbit-morpho-pdf"
    - "m-12-liquidation-fee-is-incorrectly-computed-sherlock-usg-tangent-git"
  incidentes:
    - "Morpho — Liquidating Morpho's Aave position leads to state desynchronization (Spearbit audit)"
    - "Wild Credit — LendingPair.liquidateAccount fails if tokens are lent out (high, Code4rena)"
    - "Blueberry — totalLend isn't updated on liquidation, permanently inflated value (medium)"
  severidad: high
  confianza: alta
  verificado: true
  tags: [liquidation, seize, accounting, collateral, cToken, tracker, desync]
  relacionado_con: [lmf-003, lmf-008]

- id: lmf-012
  titulo: "Interest Accrual Timestamp Manipulation — Gaps en accrueInterest causan interest spikes"
  causa_raiz: |
    accrueInterest() en Compound V2 calcula: interestAccumulated = borrowRate * (block.number
    - accrualBlockNumber) * totalBorrows. En forks que usan block.timestamp en vez de
    block.number (común en L2s y pos-Merge), si hay un gap largo entre llamadas a
    accrueInterest(), el interés acumulado puede ser masivo. Además, en L2s con timestamps
    irregulares (e.g., Arbitrum con timestamps que saltan), el interés puede
    calcularse incorrectamente.

    En algunos forks, la migración de block.number a block.timestamp se hace incorrectamente:
    el multiplier cambia de "per block" a "per second" pero los parámetros del IRM no se
    ajustan, causando tasas 12x (asumiendo 12 sec/block) más altas o más bajas.
  como_funciona: |
    1. Fork en L2 usa block.timestamp. InterestRateModel tiene baseRatePerBlock = X.
    2. Fork NO convierte "perBlock" a "perSecond" → tasa efectiva 12x mayor.
    3. Cada llamada a accrueInterest() multiplica el interés por 12.
    4. Borrowers acumulan deuda 12x más rápido de lo esperado.
    5. Posiciones se vuelven liquidables en 1/12 del tiempo esperado.

    Variante de gap:
    1. Mercado con poca actividad: nadie llama accrueInterest() por 3 días.
    2. Alguien llama: block.timestamp - lastAccrual = 259,200 segundos.
    3. Interés acumulado de 3 días se aplica de golpe.
    4. Exchange rate salta → quien deposita justo antes del accrual y retira después
       captura interés desproporcionado.
  invariante: |
    // El gap entre accruals no debe ser excesivo
    function check_lmf012_accrual_freshness() internal {
        uint256 lastAccrual = cToken.accrualBlockNumber(); // o accrualTimestamp
        uint256 gap = block.timestamp - lastAccrual;
        // Warn si el gap es >1 día (86400 seconds)
        t(gap < 86400,
          "LMF-012: interest accrual gap >1 day — spike risk");
    }

    // Verificar que borrowRate * time no produce interest explosivo
    function check_lmf012_interest_sanity() internal {
        uint256 borrowRate = irm.getBorrowRate(
            cToken.getCash(), cToken.totalBorrows(), cToken.totalReserves()
        );
        // Rate por segundo * 365 días debe ser < 1000% APR (razonable)
        uint256 annualRate = borrowRate * 365 days;
        t(annualRate < 10e18,
          "LMF-012: annualized borrow rate exceeds 1000% — likely parameter error");
    }
  que_mirar:
    - "¿Usa block.number o block.timestamp? En L2 debe ser timestamp"
    - "¿Los parámetros del IRM están en 'perBlock' o 'perSecond'?"
    - "¿Hay un máximo de gap permitido en accrueInterest()?"
    - "¿El exchange rate puede saltar significativamente en una sola llamada?"
    - "En Arbitrum: ¿usa block.timestamp del L1 o del L2?"
  como_se_arregla: |
    - Cap el gap máximo en accrueInterest() (e.g., max 7 days)
    - Verificar que IRM parameters match la unit (perBlock vs perSecond)
    - Agregar un keeper/bot que llame accrueInterest() periódicamente
    - Compound V3 ya resuelve esto con period-based accrual capped
  trampas:
    - "En mercados activos, accrueInterest() se llama en cada tx — el gap es mínimo"
    - "El spike es 'correcto' matemáticamente — el interés SÍ se acumuló, solo se registró tarde"
    - "El problema real es que depositantes/borrowers no saben el costo real hasta el accrual"
    - "L2s tienen timestamps diferentes — Optimism usa L1 timestamp, Arbitrum usa sequencer timestamp"
  solodit_ids:
    - "h-10-interest-rate-is-updated-before-updating-the-debt-when-repaying-debt-sherlock-zerolend-one-git"
    - "accountablefixedtermclaiminterest-unpredictable-due-to-share-burn-mechanics-cyfrin-none-accountable-markdown"
  incidentes:
    - "ZeroLend One — Interest rate updated BEFORE debt updated when repaying (high)"
    - "Accountable (Cyfrin) — Frequent accrueInterest calls reduce interest due to truncation (medium)"
    - "Multiple L2 forks — block.number vs block.timestamp confusion causing rate miscalculation"
  severidad: high
  confianza: alta
  verificado: true
  tags: [interest, accrual, timestamp, block-number, L2, gap, spike, IRM-parameters]
  relacionado_con: [lmf-002, lmf-005]

- id: lmf-013
  titulo: "Governance Token Reward Calculation — COMP/AAVE distribution rounding errors"
  causa_raiz: |
    Compound V2 distribuye COMP tokens a suppliers y borrowers basándose en
    compSupplyIndex y compBorrowIndex que se actualizan en cada accrual. El cálculo:
    rewardAccrued = (currentIndex - userIndex) * userBalance / 1e36.
    Problemas:
    (a) Si la distribución es por bloque y hay gaps, el index salta.
    (b) Si userBalance es muy pequeño, el reward redondea a 0 → usuario pierde rewards.
    (c) Si el index se actualiza incorrectamente (e.g., usando totalSupply viejo),
    los rewards no se distribuyen proporcionalmente.
    (d) claimComp() puede ser llamado por cualquiera para cualquier holder →
    en forks donde los rewards son valiosos, un atacante puede manipular el timing.
  como_funciona: |
    1. Fork distribuye TOKEN a suppliers. compSpeed = 100 TOKEN/block.
    2. Alice supply 1 USDC (dust) en bloque 1000.
    3. Bob supply 1,000,000 USDC en bloque 1001.
    4. Bloque 1001: index += 100 TOKEN / 1 USDC (Alice's supply) = 100 TOKEN per USDC.
    5. Alice reclama: (100) * 1 = 100 TOKEN — pero debería ser proporcional a su tiempo.
    6. Bob reclama: (0) * 1,000,000 = 0 TOKEN — porque el index se calculó antes de su deposit.

    Variante con claimComp():
    1. Atacante observa que hay rewards acumulados para una dirección.
    2. Atacante llama claimComp(victima, [cToken]) → rewards van a la víctima.
    3. Pero si hay un hook en la recepción que permite reentrancy... → doble claim.
  invariante: |
    // La suma de rewards claimed nunca debe exceder el total distribuido
    function check_lmf013_reward_conservation() internal {
        uint256 totalDistributed = getTotalCOMPDistributed();
        uint256 totalClaimed = getTotalCOMPClaimed();
        uint256 totalAccrued = getTotalCOMPAccrued();
        t(totalClaimed + totalAccrued <= totalDistributed + DUST,
          "LMF-013: total claimed + accrued > total distributed — reward inflation");
    }

    // Reward accrual debe ser proporcional al balance y tiempo
    function check_lmf013_reward_proportionality(
        address user, uint256 expectedReward
    ) internal {
        uint256 actualReward = comptroller.compAccrued(user);
        uint256 diff = actualReward > expectedReward
            ? actualReward - expectedReward
            : expectedReward - actualReward;
        t(diff <= expectedReward / 100, // 1% tolerance
          "LMF-013: reward differs from expected by >1%");
    }
  que_mirar:
    - "compSpeeds / rewardSpeeds — ¿se actualizan atómicamente?"
    - "distributeSupplierComp / distributeBorrowerComp — ¿se llama antes de cada mint/burn?"
    - "claimComp — ¿quién puede llamarlo? ¿Hay reentrancy protection?"
    - "compBorrowIndex — ¿se actualiza con totalBorrows fresh o stale?"
    - "¿Qué pasa cuando compSpeed cambia? ¿El index se actualiza primero?"
    - "¿Existe updateContributorRewards() con vulnerabilidades similares?"
  como_se_arregla: |
    - Actualizar índices ANTES de cambiar speeds o balances
    - Proteger claimComp con nonReentrant
    - Mínimo de supply para recibir rewards (evitar dust gaming)
    - Verificar que sum(individual_rewards) <= total_distributed
  trampas:
    - "Rounding dust en rewards es normal — buscar discrepancias >1%"
    - "En Compound original, COMP distribution fue auditado extensivamente — los bugs son en FORKS"
    - "El famoso bug 'COMP distribution' de Compound (sept 2021) fue un governance proposal error, no code bug"
    - "claimComp para terceros es feature, no bug — pero la interacción con hooks puede ser problema"
  solodit_ids:
    - "claimtotreasurycomp-steals-users-comp-rewards-spearbit-morpho-pdf"
    - "h-02-users-receive-less-rewards-due-to-miscalculations-code4rena-redacted-cartel-redacted-cartel-contest-git"
    - "m-01-reward-rates-can-be-changed-through-flash-borrows-code4rena-based-loans-based-loans-contest-git"
  incidentes:
    - nombre: "Compound (COMP distribution bug)"
      fecha: "Sep 2021"
      monto: "$80M+ distributed incorrectly"
      detalle: "Governance proposal 62 introduced a bug in COMP distribution. Users received excess COMP. NOT a code vulnerability — governance error. Pero demuestra el riesgo de cambiar reward parameters."
      verificado: true
      fuente: "Compound governance, Robert Leshner's public statement"
    - "Morpho — claimToTreasuryComp steals users COMP rewards (medium, Spearbit)"
    - "Based Loans — Reward rates can be changed through flash borrows (medium, Code4rena)"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [rewards, COMP, distribution, rounding, index, claiming, governance]
  relacionado_con: [lmf-005, lmf-012]

- id: lmf-014
  titulo: "Isolated Market Escaping — Usar posición aislada como colateral en cross-market"
  causa_raiz: |
    Aave V3 introduce isolation mode: ciertos activos solo pueden usarse como colateral
    en modo aislado con un debt ceiling. El usuario en isolation mode solo puede borrowear
    ciertos stablecoins. Pero si hay paths que permiten:
    (a) Entrar/salir de isolation mode sin verificar deuda existente,
    (b) Usar una posición aislada como colateral en otro protocolo (composability),
    (c) Cambiar de isolation mode a normal mode con deuda activa,
    entonces el propósito del isolation mode se bypasea.

    En forks, la complejidad de isolation mode se copia pero no se mantiene en todas las
    rutas de código. Supply, borrow, repay, withdraw, liquidate — TODAS deben respetar
    isolation mode, y a menudo una se olvida.
  como_funciona: |
    1. Asset XYZ está en isolation mode con debt ceiling de 100K USD.
    2. Usuario deposita XYZ, entra en isolation mode, borrowea 90K USDC (casi al ceiling).
    3. BUG: usuario encuentra un path para salir de isolation mode sin repagar.
       - e.g., llama setUserUseReserveAsCollateral(XYZ, false) → sale de isolation.
       - El protocolo no verifica que tiene deuda activa en isolation mode.
    4. Ahora el usuario está en normal mode con XYZ como colateral pero sin las
       restricciones de isolation (debt ceiling, limited borrows).
    5. Usuario puede borrowear más assets sin límite del debt ceiling.

    Variante composability:
    - aToken de isolation mode depositado como colateral en otro protocolo.
    - Ese protocolo no sabe nada de isolation mode → full borrow power.
  invariante: |
    // Si el usuario tiene deuda en isolation mode, no puede salir de isolation
    function check_lmf014_isolation_escape() internal {
        address isolatedAsset = getIsolatedAsset(user);
        if (isolatedAsset != address(0)) {
            uint256 isolationDebt = getIsolationDebt(user);
            if (isolationDebt > 0) {
                // El usuario debe seguir en isolation mode
                t(pool.getUserConfiguration(user).isUsingAsCollateral(
                    pool.getReserveData(isolatedAsset).id),
                  "LMF-014: user has isolation debt but exited isolation mode");
            }
        }

        // Debt ceiling nunca debe ser excedido
        if (reserve.configuration.getDebtCeiling() > 0) {
            t(reserve.isolationModeTotalDebt <= reserve.configuration.getDebtCeiling(),
              "LMF-014: isolation mode debt ceiling exceeded");
        }
    }
  que_mirar:
    - "setUserUseReserveAsCollateral — ¿verifica deuda activa en isolation?"
    - "validateBorrow — ¿chequea isolation mode debt ceiling?"
    - "¿Se puede cambiar de isolation asset sin repagar deuda?"
    - "¿Liquidación en isolation mode reduce el isolationModeTotalDebt?"
    - "¿La composability con otros protocolos respeta isolation restrictions?"
    - "ISOLATION_MODE_BORROWING_MASK — ¿se aplica en todos los paths?"
  como_se_arregla: |
    - Verificar deuda activa antes de permitir salir de isolation mode
    - Actualizar isolationModeTotalDebt en TODOS los paths (borrow, repay, liquidate)
    - No permitir aTokens de isolation mode como colateral en contratos externos
    - Test: cubrir cada transición de estado en isolation mode
  trampas:
    - "Isolation mode es complejo — muchos forks lo copian sin entender todas las interacciones"
    - "El bug suele estar en paths poco frecuentes: liquidate + exit, repay + switch collateral"
    - "Aave V3 tiene >20 funciones que interactúan con isolation mode — cada una es superficie de ataque"
  solodit_ids:
    - "enable-mode-can-be-frontrun-to-add-policies-for-a-different-permissionid-cantina-none-biconomy-pdf"
  incidentes:
    - "Multiple Aave V3 forks — isolation mode debt ceiling not updated on liquidation (various audits)"
    - "ZeroLend — Various isolation mode inconsistencies (Sherlock audit findings)"
  severidad: high
  confianza: media
  verificado: true
  tags: [isolation-mode, debt-ceiling, escape, aave-fork, collateral-switch, composability]
  relacionado_con: [lmf-004, lmf-006]

- id: lmf-015
  titulo: "Compound V3 (Comet) Absorb Griefing — Bloqueo de liquidaciones vía absorb"
  causa_raiz: |
    En Compound V3 (Comet), la función absorb() socializa la deuda de un borrower
    insolvente al protocol reserves, y transfiere el colateral al protocolo. A diferencia
    de Compound V2, absorb() no requiere que el liquidador provea capital — el protocolo
    absorbe la deuda directamente. Esto crea vectores de griefing:
    (a) Cualquiera puede llamar absorb() → un atacante puede absorber antes de que
    el protocolo esté listo para manejar el colateral,
    (b) Si absorb() tiene condiciones de revert (e.g., la posición mejoró entre el
    submission y la ejecución), puede ser DoS'd,
    (c) El colateral absorbed va a las reserves del protocolo → si las reserves son
    luego vendidas en un buyCollateral(), el timing afecta el precio.
  como_funciona: |
    1. Posición de borrower está underwater (shortfall > 0).
    2. Liquidador legítimo prepara tx para absorb().
    3. Atacante (griefer) frontrunea con su propio absorb() → la deuda se socializa.
    4. Colateral va a protocol reserves en vez de al liquidador.
    5. Protocolo ahora debe vender el colateral vía buyCollateral() — posiblemente a peor precio.
    6. O: atacante llama absorb() en una posición que está justo al borde → si el precio
       se mueve 1 wei en el bloque, la posición ya no es liquidable → tx revierte.
    7. Repetir para bloquear liquidaciones durante un período volátil.

    En forks de Comet, isAbsorbPaused y absorb implementation pueden tener
    diferencias que amplían estos vectores.
  invariante: |
    // absorb debe socializar la deuda correctamente
    function check_lmf015_absorb_accounting(address borrower) internal {
        int104 principalBefore = comet.userBasic(borrower).principal;
        uint256 reservesBefore = comet.getReserves();
        comet.absorb(address(this), [borrower]);
        int104 principalAfter = comet.userBasic(borrower).principal;
        // Borrower's principal debe ser 0 post-absorb
        t(principalAfter == 0,
          "LMF-015: borrower still has debt after absorb");
        // Reserves deben haber cambiado por la deuda absorbida
    }

    // buyCollateral debe dar un precio justo por el colateral absorbed
    function check_lmf015_buy_collateral_price() internal {
        // Verificar que el descuento no excede el storeLiquidatorPoints
        // y que el colateral se vende a >= oracle price * (1 - discount)
    }
  que_mirar:
    - "absorb() — ¿quién puede llamarlo? ¿Hay whitelist?"
    - "isAbsorbPaused — ¿puede un admin pausar absorb creando bad debt acumulado?"
    - "buyCollateral() — ¿el descuento es razonable?"
    - "¿Qué pasa si absorb se llama en una posición que ya fue absorbed?"
    - "¿El gas cost de absorb multi-account es bounded?"
    - "liquidatorPoints — ¿tracking correcto de rewards?"
  como_se_arregla: |
    - Limitar absorb() a direcciones whitelisted o agregar delay
    - Incentivizar absorb con rewards (liquidatorPoints ya existe en Comet)
    - Fallback liquidation mechanism si absorb falla
    - Bound el array de accounts en absorb() para evitar gas griefing
  trampas:
    - "absorb() sin incentivo de capital es feature de Compound V3 — no es un bug per se"
    - "El griefing tiene costo (gas) y beneficio limitado para el atacante"
    - "En la práctica, MEV bots corren absorb + buyCollateral atómicamente"
    - "isAbsorbPaused es una safety feature, no un vector de ataque (si governance es trusted)"
  solodit_ids:
    - "insurance-first-liquidation-design-differs-from-industry-standard-quantstamp-dipcoin-perpetual-markdown"
    - "h-3-liquidation-can-be-dosed-due-to-lack-of-liquidity-on-collateral-asset-reserve-sherlock-zerolend-one-git"
    - "unfair-debt-socialization-after-clearltv-of-still-worthwhile-collateral-cantina-none-euler-pdf"
  incidentes:
    - "Euler Finance (related pattern — donateToReserves)"
      # Euler no es Comet, pero la mecánica de socialización + liquidation es análoga
    - "Various Comet forks — absorb timing issues in audit reports"
  severidad: medium
  confianza: media
  verificado: true
  tags: [compound-v3, comet, absorb, griefing, liquidation, buyCollateral, DoS]
  relacionado_con: [lmf-008, lmf-011]

- id: lmf-016
  titulo: "Aave V2 Stable Rate Rebalancing — Forzar a otros usuarios a variable rate"
  causa_raiz: |
    Aave V2 permite borrowear a tasa estable (stable rate). Pero la tasa estable puede
    ser "rebalanceada" (forzada a variable) por cualquiera si se cumplen condiciones:
    (a) la tasa estable del usuario está significativamente por debajo de la tasa actual,
    (b) la utilización del pool es alta (> EXCESS_UTILIZATION_RATE).

    La función rebalanceStableBorrowRate() es external y callable por cualquiera.
    Un atacante puede:
    1. Manipular la utilización para cumplir las condiciones de rebalance.
    2. Llamar rebalanceStableBorrowRate() para forzar a users estables a tasa variable.
    3. La tasa variable suele ser más alta → users pagan más interés inesperadamente.
  como_funciona: |
    1. Alice borroweó 100K USDC a stable rate 3% cuando las tasas eran bajas.
    2. Atacante flashloan → deposit masivo para manipular utilización temporalmente.
    3. O inversamente: atacante borrow masivo para llevar utilización > EXCESS_UTILIZATION_RATE.
    4. Ahora la tasa variable actual es 15%, la tasa de Alice (3%) está muy por debajo.
    5. Atacante llama rebalanceStableBorrowRate(alice).
    6. El protocolo recalcula la tasa estable de Alice al nivel actual → 15%.
    7. Alice ahora paga 15% en vez de 3%.
    8. Atacante revierte su manipulación de utilización.
    9. La tasa variable baja a 5%, pero la tasa estable de Alice se queda en 15%.

    En forks de Aave V2, las condiciones de rebalance pueden estar mal configuradas
    (e.g., sin gap mínimo para rebalance) o el rebalance puede aplicarse incorrectamente.
  invariante: |
    // Stable rate rebalance solo debe ocurrir bajo condiciones genuinas
    function check_lmf016_stable_rate_rebalance(
        address user,
        uint256 rateBefore,
        uint256 rateAfter
    ) internal {
        if (rateAfter > rateBefore) {
            // Verificar que las condiciones de rebalance eran genuinas
            uint256 utilization = pool.getReserveUtilization(asset);
            t(utilization > EXCESS_UTILIZATION_RATE,
              "LMF-016: stable rate rebalanced without high utilization");

            // La nueva tasa no debe ser más del doble de la variable actual
            uint256 currentVariableRate = pool.getReserveData(asset).currentVariableBorrowRate;
            t(rateAfter <= currentVariableRate * 2,
              "LMF-016: rebalanced stable rate unreasonably high vs variable");
        }
    }
  que_mirar:
    - "rebalanceStableBorrowRate() — ¿es external? ¿Quién puede llamarlo?"
    - "¿Las condiciones de rebalance son resistentes a manipulación de utilización?"
    - "¿Hay protección contra flash loan manipulation de utilización?"
    - "¿El usuario puede optar out del rebalance?"
    - "¿La nueva stable rate es razonable vs variable rate actual?"
    - "REBALANCE_UP_LIQUIDITY_RATE_THRESHOLD — ¿es configurable? ¿Está bien seteado?"
  como_se_arregla: |
    - Time-weighted utilization para condiciones de rebalance (no spot)
    - Mínimo gap entre stable rate actual y target para permitir rebalance
    - Cooldown: no rebalancear la misma posición en 24h
    - En Aave V3, stable rate fue efectivamente deprecado
  trampas:
    - "Aave V3 eliminó stable rate borrowing — este pattern solo aplica a Aave V2 y sus forks"
    - "La manipulación de utilización es costosa (necesitas capital real o flash loan en otro mercado)"
    - "Algunos forks eliminan stable rate completamente — verificar si existe antes de buscar"
    - "El rebalance es un feature de protección del protocolo — el bug es la manipulabilidad"
  solodit_ids: []
  incidentes:
    - "Aave V2 — stable rate rebalancing discussions in governance (no hack, but design concern)"
    - "Multiple Aave V2 forks — stable rate parameters copied without adjustment"
  severidad: medium
  confianza: media
  verificado: true
  tags: [stable-rate, rebalance, aave-v2, utilization, manipulation, interest-rate]
  relacionado_con: [lmf-002, lmf-012]

- id: lmf-017
  titulo: "Flash Loan Fee Bypass en Forks — Missing fee on self-borrow patterns"
  causa_raiz: |
    Aave cobra un flash loan premium (típicamente 0.09% o 9 bps). Pero hay paths
    donde el fee no se cobra:
    (a) Self-borrow: el usuario es supply + borrow en el mismo token → el flash loan
    es efectivamente interest-free si el fee se calcula mal.
    (b) En forks, el flash loan premium se hardcodea a 0 para atraer usuarios.
    (c) El premium se calcula sobre el amount pero no se verifica que amount +
    premium fue devuelto — solo que amount fue devuelto.
    (d) Flash loan via el pool contract directamente vs via flashLoanSimple
    tienen diferentes paths de fee calculation.

    En Compound V3 (Comet), no hay flash loan nativo pero algunos forks lo agregan
    sin entender las implicaciones en el borrow accounting.
  como_funciona: |
    1. Flash loan de 1M USDC con premium = 0.09% = 900 USDC.
    2. BUG en fork: flashLoanPremiumToProtocol se resta de flashLoanPremiumTotal
       pero si flashLoanPremiumToProtocol > flashLoanPremiumTotal → underflow → 0 fee.
    3. O: el fee se calcula en el validateFlashLoanSimple() pero el repayment check
       solo verifica amount_returned >= amount_borrowed (sin fee).
    4. Resultado: flash loans gratis → cualquiera puede usar liquidez del pool sin costo.

    Variante self-borrow:
    1. Alice supplies 1M USDC y borrowea 500K USDC (utilizando su propio supply como colateral).
    2. Alice flashloan 500K USDC del pool → usa para repagar su borrow.
    3. Ahora Alice no tiene deuda + tiene 1M supply + 500K flash loan.
    4. Alice usa los 500K para algo (arbitrage, manipulation) y devuelve.
    5. Si el fee es 0 o se calcula incorrectamente para self-borrow, Alice operó gratis.
  invariante: |
    // Flash loan fee debe cobrarse correctamente
    function check_lmf017_flash_loan_fee(
        uint256 amount,
        uint256 premium
    ) internal {
        uint256 expectedPremium = amount * flashLoanPremiumTotal / 10000;
        t(premium >= expectedPremium,
          "LMF-017: flash loan premium less than expected");

        // Verificar que el pool balance aumentó por al menos amount + premium
        uint256 balanceBefore = underlying.balanceOf(address(pool));
        // ... después del flash loan callback ...
        uint256 balanceAfter = underlying.balanceOf(address(pool));
        t(balanceAfter >= balanceBefore + premium,
          "LMF-017: pool didn't receive full flash loan premium");
    }
  que_mirar:
    - "FLASHLOAN_PREMIUM_TOTAL — ¿es > 0? ¿Puede setearse a 0?"
    - "FLASHLOAN_PREMIUM_TO_PROTOCOL — ¿es <= PREMIUM_TOTAL?"
    - "executeFlashLoan — ¿verifica que amount + premium fue devuelto?"
    - "executeFlashLoanSimple vs executeFlashLoan — ¿misma lógica de fee?"
    - "¿Hay bypass para supply holders? (Aave V3 permite premium=0 para quienes supply el mismo asset)"
    - "¿El fork tiene flash loans? ¿Los agregó custom?"
  como_se_arregla: |
    - Verificar balance post-callback: balanceAfter >= balanceBefore + totalPremium
    - No permitir premium = 0 (mínimo configurable > 0)
    - Validar: FLASHLOAN_PREMIUM_TO_PROTOCOL <= FLASHLOAN_PREMIUM_TOTAL
    - Auditar paths de self-borrow explícitamente
  trampas:
    - "Aave V3 permite premium=0 para supply holders — es feature, no bug (flashLoanPremiumToProtocol)"
    - "Flash loans sin fee pueden ser intencionales para bootstrapping de liquidez"
    - "El bypass más común no es en el fee sino en la falta de reentrancy guard dentro del callback"
    - "En forks que copian Aave V2, el premium se paga en aTokens — verificar que el minting es correcto"
  solodit_ids:
    - "m-01-the-buy-functions-mechanism-enables-users-to-acquire-flash-loans-at-a-cheaper-fee-rate-code4rena-caviar-caviar-private-pools-git"
    - "m-03-flashloan-fee-collection-mechanism-can-be-easily-manipulated-code4rena-trader-joe-trader-joe-v2-contest-git"
    - "m-13-flashloan-end-result-isnt-controlled-sherlock-ajna-ajna-git"
    - "consider-reverting-the-flashloan-operation-if-the-returned-amount-of-is-not-exactly-the-original-spearbit-none-euler-labs-evk-pdf"
    - "h-02-the-flashloan-protection-for-zappers-is-insufficient-we-can-operate-on-troves-we-dont-own-recon-audits-none-bold-report-markdown"
  incidentes:
    - "Trader Joe V2 — Flash loan fee collection mechanism manipulated (medium, Code4rena)"
    - "Caviar Private Pools — Buy function enables cheaper flash loan fee rate (medium, Code4rena)"
    - "Ajna — Flash loan end result isn't controlled (medium, Sherlock)"
    - "Multiple forks — flash loan premium set to 0 without understanding implications"
  severidad: medium
  confianza: alta
  verificado: true
  tags: [flash-loan, fee, bypass, premium, self-borrow, aave-fork, compound-v3]
  relacionado_con: [lmf-009, lmf-002]
```

---

## 2. Mega-Incidents Reference

### Incidentes mayores en lending market forks (ordenados por pérdida)

```yaml
mega_incidents:
  - nombre: "Euler Finance"
    fecha: "Mar 2023"
    monto: "$197M"
    tipo: "donateToReserves + liquidation logic flaw"
    detalle: |
      Atacante usó donateToReserves() para crear una posición con más deuda que colateral,
      luego explotó que la liquidación no verificaba correctamente la solvencia post-donación.
      El atacante creó leverage extremo usando dTokens (deuda tokenizada) y eTokens,
      donó a reserves para crear insolvencia artificial, y luego liquidó su propia posición
      obteniendo más eTokens de los que debería. No es estrictamente un Compound/Aave fork
      pero el pattern (donación + liquidation) aplica a muchos protocolos.
    lecciones:
      - "donateToReserves sin restricciones permite crear posiciones artificialmente insolventes"
      - "Liquidation debe verificar solvencia del liquidador después de la operación"
      - "Self-liquidation con leverage amplifica el daño exponencialmente"
    verificado: true

  - nombre: "CREAM Finance (total 3 ataques)"
    fecha: "Feb 2021, Aug 2021, Oct 2021"
    monto: "$37M + $18.8M + $130M = ~$186M total"
    tipo: "Flash loan + oracle manipulation + reentrancy"
    detalle: |
      Ataque 1 (Feb 2021, $37M): Alpha Homora exploit usando flash loans en CREAM.
      Ataque 2 (Aug 2021, $18.8M): Reentrancy via AMP token (ERC-777-like) en borrowFresh.
      Ataque 3 (Oct 2021, $130M): Combinación sofisticada de oracle manipulation en crYUSD
      + reentrancy + flash loans. El atacante infló el precio de crYUSD como colateral.
    lecciones:
      - "Listar tokens con callbacks (ERC-777) sin nonReentrant es fatal"
      - "Composability con otros protocolos (Alpha Homora) crea vectores inesperados"
      - "Tres ataques al mismo protocolo: no arreglaron la raíz después del primero"
    verificado: true

  - nombre: "Mango Markets"
    fecha: "Oct 2022"
    monto: "$114M"
    tipo: "Oracle manipulation (spot price)"
    detalle: |
      Avraham Eisenberg usó dos cuentas para pump MNGO token en el propio orderbook de
      Mango. Cuenta A: posición larga. Cuenta B: posición corta. Pumpeó MNGO de $0.038
      a $0.91 (+2300%). Usó la ganancia no realizada de la cuenta A como colateral para
      borrowear SOL, USDC, y otros activos del protocolo. El oracle usaba spot price del
      propio mercado de Mango.
    lecciones:
      - "Nunca usar spot price del propio mercado como oracle"
      - "Los unrealized PnL como colateral son extremadamente peligrosos"
      - "Este attack vector es legal en algunos jurisdicciones pero fue criminalizado en EE.UU."
    verificado: true

  - nombre: "Venus Protocol"
    fecha: "May 2021"
    monto: "$100M+ bad debt"
    tipo: "Oracle manipulation + cascading liquidations"
    detalle: |
      El precio de XVS (token de governance de Venus) fue manipulado de $70 a $144.
      Usuarios (posiblemente coordinados con el team) depositaron XVS como colateral
      y borrowearon BTC y ETH. Cuando XVS colapsó de vuelta a $24, las posiciones eran
      masivamente underwater. El protocolo quedó con >$100M de bad debt.
    lecciones:
      - "Governance tokens como colateral son extremadamente riesgosos"
      - "Borrow caps por mercado son esenciales para limitar exposición"
      - "Oracle price de tokens ilíquidos es fácilmente manipulable"
    verificado: true

  - nombre: "Rari Capital / Fuse"
    fecha: "Apr 2022"
    monto: "$80M"
    tipo: "Reentrancy en Compound V2 fork"
    detalle: |
      Atacante explotó reentrancy en pools de Fuse (Compound V2 fork permisionless).
      Las funciones no tenían nonReentrant guards. El token con callback permitió
      re-entrar y borrow múltiples veces con el mismo colateral.
    lecciones:
      - "Permisionless pool creation amplifica la superficie de ataque"
      - "Cada pool hereda las vulnerabilidades del base contract"
      - "nonReentrant es obligatorio en lending protocols, sin excepciones"
    verificado: true

  - nombre: "Sonne Finance"
    fecha: "May 2024"
    monto: "$20M"
    tipo: "First depositor / empty market attack"
    detalle: |
      Atacante explotó la ventana de timelock de 2 días entre la governance proposal
      para listar VELO como mercado y la ejecución de la tx de liquidez inicial.
      Ejecutó first depositor attack con donación directa al cToken vacío.
    lecciones:
      - "Listing de nuevo mercado + provisión de liquidez deben ser atómicos"
      - "Timelock de governance crea ventana de ataque para empty markets"
      - "Dead shares o virtual offset mitigarían este ataque"
    verificado: true

  - nombre: "Hundred Finance (Optimism)"
    fecha: "Apr 2023"
    monto: "$7M"
    tipo: "Empty market donation + exchange rate inflation"
    detalle: |
      Similar a Sonne: mercado hERC20 vacío en Optimism. Atacante donó tokens al
      contrato vacío inflando el exchange rate, luego depósitos de víctimas generaban 0 shares.
    lecciones:
      - "Compound V2 forks en L2s heredan exactamente los mismos bugs"
      - "El ataque se ejecutó 2 años después del conocimiento público del vector"
    verificado: true
```

---

## 3. Checklist Rápido para Auditar Lending Forks

```yaml
checklist:
  - check: "¿Hay nonReentrant en mint/redeem/borrow/repay/liquidate/seize?"
    pattern_id: lmf-003
    severity: CRITICAL
    grep: "nonReentrant"

  - check: "¿El protocolo lista tokens con callbacks (ERC-777, ERC-721)?"
    pattern_id: lmf-003
    severity: CRITICAL
    grep: "tokensReceived|onERC721Received"

  - check: "¿Mercados nuevos tienen protección contra first depositor?"
    pattern_id: lmf-001
    severity: CRITICAL
    grep: "initialExchangeRate|totalSupply == 0"

  - check: "¿El oracle usa spot price o TWAP? ¿Chainlink con heartbeat check?"
    pattern_id: lmf-007
    severity: CRITICAL
    grep: "getReserves|slot0|getUnderlyingPrice"

  - check: "¿accrueInterest() se llama antes de CADA operación de estado?"
    pattern_id: [lmf-005, lmf-012]
    severity: HIGH
    grep: "accrueInterest"

  - check: "¿Los parámetros IRM son perBlock o perSecond? ¿Coinciden con el chain?"
    pattern_id: lmf-012
    severity: HIGH
    grep: "baseRatePerBlock|baseRatePerSecond|blocksPerYear"

  - check: "¿enterMarkets verifica isListed?"
    pattern_id: lmf-006
    severity: HIGH
    grep: "enterMarkets|isListed"

  - check: "¿liquidationIncentive es razonable (<115%)?"
    pattern_id: lmf-008
    severity: HIGH
    grep: "liquidationIncentive|liquidationBonus"

  - check: "¿Borrow/supply caps se verifican con datos fresh (post-accrual)?"
    pattern_id: [lmf-009, lmf-010]
    severity: MEDIUM
    grep: "borrowCap|supplyCap|borrowAllowed|mintAllowed"

  - check: "¿seize() actualiza todos los trackers (rewards, gauges)?"
    pattern_id: lmf-011
    severity: HIGH
    grep: "seize|_afterTokenTransfer|_beforeTokenTransfer"

  - check: "¿Flash loan premium se verifica correctamente (amount + fee returned)?"
    pattern_id: lmf-017
    severity: MEDIUM
    grep: "flashLoanPremium|FLASHLOAN_PREMIUM"

  - check: "¿E-mode / isolation mode se respeta en todos los paths?"
    pattern_id: [lmf-004, lmf-014]
    severity: HIGH
    grep: "eMode|ISOLATION_MODE|setUserUseReserveAsCollateral"

  - check: "¿COMP/reward distribution se actualiza atómicamente con balances?"
    pattern_id: lmf-013
    severity: MEDIUM
    grep: "compSpeeds|distributeSupplier|distributeBorrower|claimComp"

  - check: "¿Stable rate rebalance requiere condiciones genuinas?"
    pattern_id: lmf-016
    severity: MEDIUM
    grep: "rebalanceStableBorrowRate|REBALANCE_UP"

  - check: "¿reserveFactor change llama accrueInterest primero?"
    pattern_id: lmf-005
    severity: MEDIUM
    grep: "_setReserveFactor|_setInterestRateModel"
```

---

## 4. Ghost Variables Recomendadas para Fuzzing

```yaml
ghost_variables:
  - name: ghost_totalDeposited
    type: "mapping(address => uint256)"
    tracks: "Acumulado de depósitos por usuario"
    usage: "Verificar que withdrawals <= deposits + interest"

  - name: ghost_totalBorrowed
    type: "mapping(address => uint256)"
    tracks: "Acumulado de borrows por usuario"
    usage: "Verificar que repayments <= borrows + interest"

  - name: ghost_totalLiquidated
    type: "mapping(address => uint256)"
    tracks: "Colateral seized en liquidaciones"
    usage: "Verificar que liquidation bonus no crea valor"

  - name: ghost_exchangeRateHistory
    type: "uint256[]"
    tracks: "Exchange rate en cada operación"
    usage: "Detectar saltos anormales (>2x en una operación)"

  - name: ghost_reservesAccumulated
    type: "uint256"
    tracks: "Reservas totales acumuladas"
    usage: "Verificar monotonicity (solo admin puede reducir)"

  - name: ghost_rewardsDistributed
    type: "uint256"
    tracks: "Total de rewards distribuidos"
    usage: "Verificar que claimed + accrued <= distributed"

  - name: ghost_isolationDebtTotal
    type: "uint256"
    tracks: "Deuda total en isolation mode"
    usage: "Verificar que no excede debt ceiling"

  - name: ghost_flashLoanFees
    type: "uint256"
    tracks: "Fees acumulados por flash loans"
    usage: "Verificar que fees > 0 para cada flash loan"
```

---

## 5. Diferencias Clave entre Compound V2, V3 y Aave V2, V3

```yaml
architecture_differences:
  compound_v2:
    model: "Pool-per-asset (cToken = market)"
    liquidation: "Liquidator repays debt, receives cTokens with bonus"
    interest: "Per-block accrual, borrowIndex/supplyIndex"
    oracle: "UniswapAnchoredView o Chainlink adapter"
    flash_loan: "No nativo (algunos forks agregan)"
    isolation: "No existe"
    risks_unique:
      - "cToken listing = new market creation (enterMarkets validation)"
      - "exchangeRate inflation en mercados vacíos"
      - "reserveFactor bypass via timing"

  compound_v3:
    model: "Single-market (Comet): un base asset, múltiples colaterales"
    liquidation: "absorb() socializa deuda, buyCollateral() vende colateral"
    interest: "Per-second accrual con utilization curve"
    oracle: "Chainlink con priceFeed por asset"
    flash_loan: "No nativo (algunos forks agregan)"
    isolation: "Implícito: cada Comet instance es un mercado aislado"
    risks_unique:
      - "absorb griefing / DoS"
      - "buyCollateral pricing y slippage"
      - "Comet storage packing — bugs de truncamiento"

  aave_v2:
    model: "Pool-of-pools: single PoolContract, multiple aToken/debtToken"
    liquidation: "Liquidator repays debt, receives aTokens or underlying"
    interest: "Per-second, variable + stable rate"
    oracle: "Chainlink via AaveOracle"
    flash_loan: "Nativo, con premium configurable"
    isolation: "No existe"
    risks_unique:
      - "Stable rate rebalancing manipulation"
      - "Flash loan premium bypass"
      - "Interest rate mode switching (stable <-> variable)"

  aave_v3:
    model: "Pool-of-pools con e-mode + isolation mode"
    liquidation: "Similar a V2 + close factor dinámico"
    interest: "Per-second, variable only (stable deprecated en practice)"
    oracle: "Chainlink via AaveOracle"
    flash_loan: "Nativo, premium puede ser 0 para supply holders"
    isolation: "Debt ceiling, limited borrows, exit conditions"
    risks_unique:
      - "E-mode misconfiguration (LTV/threshold)"
      - "Isolation mode escape"
      - "Efficiency mode + cross-asset interactions"
      - "Supply/borrow caps con configuración per-asset"
```
