grep_targets:
  - "rebase"
  - "elastic"
  - "balanceOf"
  - "shares"
  - "totalShares"
  - "totalSupply"
  - "stETH"
  - "wstETH"
  - "aToken"
  - "cToken"
  - "OHM"
  - "sOHM"
  - "gOHM"
  - "AMPL"
  - "wrap("
  - "unwrap("
  - "getSharesByPooledEth"
  - "getPooledEthByShares"
  - "scaledBalanceOf"
  - "exchangeRate"
  - "rebaseOptIn"
  - "rebaseOptOut"
  - "transferShares"
  - "submitToRebase"
  - "syncRewards"
  - "cachedBalance"
  - "_totalSupply"
  - "rebasing"

# Briefing: Rebasing & Elastic Supply Token Vulnerabilities

## Contexto del dominio
Los tokens rebasing (stETH, AMPL, OHM, aTokens) y los tokens elastic supply cambian el
balanceOf() de sus holders sin necesidad de una transaccion transfer(). Este comportamiento
rompe la asuncion fundamental que la mayoria de protocolos DeFi tienen: que el balance de un
token solo cambia mediante Transfer events explicitos.

Existen dos familias principales:
1. **Rebasing positivo** (stETH, aTokens, OHM): el balance crece automaticamente. Los
   staking rewards o intereses se reflejan incrementando balanceOf(). Esto causa que los
   protocolos que cachean balances "pierdan" el yield — queda atrapado sin dueno.
2. **Rebasing negativo** (AMPL, tokens con slashing): el balance puede DECRECER. Esto es
   mas peligroso porque causa insolvencia: la contabilidad interna dice que hay mas tokens
   de los que realmente existen.

### Por que es critico:
- stETH tiene ~$15B de TVL y se integra en decenas de protocolos
- aTokens de Aave son rebasing por diseno y se usan como colateral en otros protocolos
- OHM y sus forks (>100 forks en 2021-2022) expusieron vulnerabilidades masivas
- AMPL es el unico token rebasing negativo popular, y rompio Aave cuando se listo

### Wrapped vs Raw:
La solucion estandar es usar versiones wrapped non-rebasing (wstETH en vez de stETH,
gOHM en vez de sOHM). El wrapper convierte el rebase a un exchange rate creciente.
Sin embargo, la conversion wrap/unwrap introduce sus propias vulnerabilidades.

### Categorias de vulnerabilidad:
1. **Accounting desync** — cached balance vs real balance
2. **AMM pool drain** — rebasing tokens en pools de liquidez
3. **Sandwich attacks** — front-running rebases predecibles
4. **Collateral drift** — under-collateralization por rebase negativo
5. **Wrap/unwrap manipulation** — exchange rate exploits
6. **Cross-protocol** — rebasing tokens cruzando bridges, vaults, lending
7. **Governance** — elastic supply afectando peso de voto

---

patterns:

- id: REBASE-01
  titulo: Balance Cambia Sin Transfer Events — Rotura de Contabilidad Interna
  causa_raiz: |
    Los tokens rebasing (stETH, aTokens, OHM) modifican balanceOf() de TODOS los holders
    sin emitir Transfer events y sin que ocurra una transaccion. Los protocolos que almacenan
    el balance de un token en una variable de storage (mapping(address => uint256) deposits)
    quedan desincronizados despues de cada rebase. En rebasing positivo, el yield queda
    atrapado en el contrato sin dueno. En rebasing negativo, la contabilidad interna excede
    el balance real y el protocolo se vuelve insolvente.
  como_funciona: |
    Escenario con stETH (rebase positivo diario):
    1. Usuario deposita 100 stETH en un vault
    2. Vault registra: deposits[user] = 100 stETH
    3. Oracle de Lido reporta rewards → rebase positivo → balanceOf(vault) = 105 stETH
    4. No se emite Transfer, no se llama ninguna funcion en el vault
    5. deposits[user] sigue siendo 100, pero el vault tiene 105 stETH reales
    6. Usuario retira 100 stETH. Los 5 stETH de yield quedan sin dueno
    7. Con miles de usuarios, millones de USD de yield se acumulan inaccessibles

    Escenario con AMPL (rebase negativo):
    1. Usuario deposita 100 AMPL. deposits[user] = 100
    2. Rebase negativo: balanceOf(vault) baja a 75 AMPL
    3. Usuario intenta retirar 100 AMPL → revert (solo hay 75)
    4. Si hay multiples usuarios, first-come-first-served: los ultimos pierden todo
  invariante: |
    function check_rebasing_accounting_sync() internal {
        uint256 realBalance = IERC20(rebasingToken).balanceOf(address(targetContract));
        uint256 internalTotal = targetContract.totalInternalBalance();
        // Despues de rebase, la contabilidad interna NO debe exceder el balance real
        t(realBalance + DUST_TOLERANCE >= internalTotal,
          "REBASE-01: internal accounting exceeds real balance after rebase");
    }
  que_mirar:
    - "mapping(address => uint256) para balances de tokens — si almacena amounts absolutos, vulnerable"
    - "Funciones deposit/withdraw que usan amount del parametro en vez de medir balanceOf antes/despues"
    - "Ausencia de funcion sync() o skim() para reconciliar post-rebase"
    - "Contratos que cachean totalDeposited o similar en storage"
    - "ERC-4626 vaults que asumen totalAssets() constante entre bloques"
  como_se_arregla: |
    Opcion 1 (mejor): Usar versiones wrapped non-rebasing (wstETH, gOHM).
    Opcion 2: Contabilidad basada en shares, no amounts. Cada deposito registra
    shares proporcionales, y el valor se calcula dinamicamente via exchange rate.
    Opcion 3: Implementar sync() que reconcilie contabilidad con balanceOf() real.
    ```solidity
    // Share-based accounting (correcto)
    uint256 shares = (amount * totalShares) / totalAssets();
    userShares[msg.sender] += shares;
    // Al retirar, calcula el amount desde las shares
    uint256 withdrawAmount = (userShares[user] * totalAssets()) / totalShares;
    ```
  trampas:
    - "wstETH NO es rebasing — solo stETH raw rebasa. No reportar wstETH como vulnerable"
    - "Si el protocolo usa ERC-4626 con share-based accounting, puede ser seguro"
    - "Verificar si hay whitelist de tokens que excluye rebasing"
    - "Algunos protocolos documentan 'rebasing tokens not supported' — es informational"
  solodit_ids:
    - "h-05-making-_totalsupply-and-_totalshares-imbalance-significantly-by-providing-fake-income-leads-to-stealing-fund-code4rena-lybra-finance-lybra-finance-git"
    - "m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git"
    - "m-10-rebasingfot-tokens-will-cause-a-loss-of-funds-for-other-depositors-code4rena-pooltogether-pooltogether-git"
  incidentes:
    - "Lybra Finance — Manipulacion de _totalSupply/_totalShares por income fake en stETH, robo de fondos (High, Code4rena 2023)"
    - "PoolTogether — Rebasing/FoT tokens causan perdida de fondos para otros depositantes (Medium, Code4rena 2023)"
    - "AMPL/Aave — AMPL listado y des-listado de Aave por incompatibilidad con rebase negativo (2021)"
    - "stETH en multiples protocolos — Yield atrapado sin dueno por contabilidad amount-based (2022-2023)"
  verificado: true
  confianza: alta

- id: REBASE-02
  titulo: Rebasing Token en AMM Pools — LP Pierde Yield o Sufre Drain
  causa_raiz: |
    Los AMMs tipo Uniswap V2 (constant product x*y=k) rastrean reserves internamente
    con variables reserve0 y reserve1 que se actualizan solo en sync(). Cuando un token
    rebasing como stETH esta en un pool, los rebases cambian el balance real del pool
    pero NO actualizan las reserves internas. La diferencia queda como valor extractable
    via arbitraje o skim().
  como_funciona: |
    1. Pool stETH/ETH tiene: reserve0=1000 stETH, reserve1=1000 ETH (real y tracked)
    2. Rebase positivo de stETH: balanceOf(pool) sube a 1050 stETH
    3. Reserves internas siguen en 1000 stETH — hay 50 stETH "fantasma"
    4. Arbitrajista llama sync() o swap: puede extraer los 50 stETH de diferencia
    5. LPs no reciben el yield del rebase — va al arbitrajista
    6. En rebase negativo: reserves internas > balance real → swaps pueden fallar

    Uniswap V2 tiene skim() para esto, pero:
    - skim() envia la diferencia al caller, no a los LPs
    - Si nadie llama skim(), la diferencia se acumula
    - Cualquiera puede front-runear el skim() para robar el yield

    Uniswap V3: no tiene skim(). El problema es peor porque las posiciones
    concentradas amplican la divergencia.
  invariante: |
    function check_amm_reserve_sync(address pool, address token) internal {
        uint256 realBalance = IERC20(token).balanceOf(pool);
        (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pool).getReserves();
        uint256 trackedReserve = pool.token0() == token ? reserve0 : reserve1;
        // Si real > tracked, hay yield extractable (no es un bug del AMM pero si del LP)
        // Si tracked > real, el pool esta en problemas
        t(realBalance + 1e15 >= trackedReserve,
          "REBASE-02: AMM tracked reserves exceed real balance after negative rebase");
    }
  que_mirar:
    - "Pools que contienen stETH, AMPL, aTokens, u OHM directamente (no wrapped)"
    - "AMMs sin funcion skim() o sync() publica"
    - "Protocolos que despliegan pools con rebasing tokens sin advertencia"
    - "Contratos de farming que asumen que LP token value es constante"
  como_se_arregla: |
    1. NUNCA usar tokens rebasing raw en AMM pools. Usar wstETH, gOHM, etc.
    2. Si es inevitable, implementar sync() automatico en cada interaccion.
    3. Para pools existentes: advertir a LPs del yield leakage.
    ```solidity
    // Correcto: pool con wstETH (non-rebasing)
    // El exchange rate wstETH→stETH crece, pero el balance no cambia
    pool = factory.createPair(wstETH, WETH);
    ```
  trampas:
    - "Curve tiene pools especificos para stETH que manejan el rebase — no son vulnerables"
    - "skim() no es un bug — es una feature de Uniswap V2. El bug es usar rebasing tokens en el pool"
    - "Uniswap V3 no soporta rebasing tokens oficialmente"
  solodit_ids:
    - "h-01-loss-of-staking-reward-for-lps-in-primary-market-operations-code4rena-ampleforth-spot-git"
    - "m-17-rebasingyield-bearing-tokens-are-not-properly-handled-code4rena-notional-notional-git"
  incidentes:
    - "stETH/ETH Curve pool — Arbitrajistas extraen yield de rebase antes que LPs (ongoing)"
    - "AMPL Uniswap pools — Rebase negativo causa reverts en swaps por reserve desync (2020-2021)"
    - "Ampleforth SPOT — Perdida de staking rewards para LPs en operaciones de mercado primario (High, Code4rena 2023)"
  verificado: true
  confianza: alta

- id: REBASE-03
  titulo: Positive Rebase Sandwich Attack — Front-Running Rebases Predecibles
  causa_raiz: |
    Muchos rebasing tokens tienen rebases predecibles: stETH rebasa una vez al dia cuando
    el oracle de Lido reporta, OHM rebasaba cada ~8 horas en epochs fijos. Si un atacante
    puede predecir el momento del rebase, puede comprar justo antes y vender justo despues,
    capturando el rebase sin contribuir al protocolo. Esto es especialmente lucrativo en
    pools AMM donde el rebase crea arbitrage instantaneo.
  como_funciona: |
    OHM (Olympus, pre-rebasing removal):
    1. Atacante monitorea el mempool para la tx de rebase() del keeper
    2. Atacante compra 1M OHM justo antes del rebase (front-run)
    3. Rebase ejecuta: todos los holders reciben +3% (ejemplo)
    4. Atacante tiene 1,030,000 OHM → vende inmediatamente (back-run)
    5. Profit: 30,000 OHM sin ningun riesgo

    stETH:
    1. Rebase de stETH ocurre cuando se llama handleOracleReport()
    2. Atacante deposita ETH → recibe stETH justo antes del rebase
    3. Rebase aplica → balance sube
    4. Atacante unwraps/vende inmediatamente
    5. Yield capturado sin haber stakeado realmente

    La ganancia depende de:
    - Tamano del rebase (% de yield)
    - Volumen que el atacante puede mover sin slippage
    - Gas costs + MEV competition
  invariante: |
    // Ghost: rastrear depositos/retiros cercanos al rebase
    uint256 ghost_lastDepositBlock;
    uint256 ghost_lastRebaseBlock;

    function check_sandwich_protection() internal {
        // Si un deposito y un retiro ocurren en el mismo bloque que el rebase, flag
        if (ghost_lastDepositBlock == ghost_lastRebaseBlock) {
            // Potencial sandwich — verificar que hay cooldown o lock period
            t(block.number > ghost_lastDepositBlock + MIN_COOLDOWN_BLOCKS,
              "REBASE-03: deposit and rebase in same block — sandwich risk");
        }
    }
  que_mirar:
    - "Rebases con timing predecible (cada N bloques, cada N horas)"
    - "Ausencia de cooldown entre deposit y withdraw"
    - "Flash loans usados para amplificar el sandwich"
    - "Funciones de rebase publicas sin restriccion de acceso"
    - "Protocols que permiten mint+rebase+burn en el mismo bloque"
  como_se_arregla: |
    1. Implementar cooldown period entre deposit y withdraw (minimo 1 epoch).
    2. Usar rebase-smoothing: distribuir el rebase linealmente durante el epoch.
    3. Snapshots: usar balance al INICIO del epoch para calcular rewards.
    4. Lido implemento esto con shares — el rebase no es explotable via sandwich
       porque los shares se calculan al momento del deposito.
    ```solidity
    // Anti-sandwich: cooldown
    mapping(address => uint256) public lastDepositTime;
    function deposit(uint256 amount) external {
        lastDepositTime[msg.sender] = block.timestamp;
        // ...
    }
    function withdraw(uint256 amount) external {
        require(block.timestamp >= lastDepositTime[msg.sender] + COOLDOWN,
                "Cooldown not met");
        // ...
    }
    ```
  trampas:
    - "Lido stETH tiene proteccion contra sandwich a nivel del oracle report — verificar antes de reportar"
    - "OHM abandono el modelo rebasing puro en favor de gOHM non-rebasing"
    - "El MEV sandwich es un problema a nivel de MEV/block builder, no siempre del protocolo"
    - "Distinguir entre sandwich en AMM (problema del pool) vs sandwich en staking (problema del protocolo)"
  solodit_ids:
    - "h-4-mev-attacks-on-rebases-sherlock-olympus-update-2-olympus-update-2-git"
    - "m-03-sandwich-attack-in-rewards-distribution-code4rena-none-steth-allocation-markdown"
  incidentes:
    - "Olympus DAO — MEV attacks on rebases documentados como High (Sherlock 2022)"
    - "stETH — Sandwich attacks en oracle report documentados en multiples auditorias"
    - "OHM forks (Wonderland TIME, Klima DAO) — Sandwich masivos por rebases predecibles (2021-2022)"
    - "Ampleforth — Rebase sandwich bots operando en Uniswap V2 (2020-2021)"
  verificado: true
  confianza: alta

- id: REBASE-04
  titulo: Rebase Negativo Causa Under-Collateralization en Lending
  causa_raiz: |
    Cuando un token rebasing con rebase negativo (AMPL, o cualquier token con slashing)
    se usa como colateral en un protocolo de lending, un rebase negativo reduce el valor
    del colateral sin que el protocolo se entere. El debt ratio sube silenciosamente,
    la posicion queda under-collateralized, y si no hay liquidacion inmediata, bad debt
    se acumula.
  como_funciona: |
    1. Usuario deposita 1000 AMPL como colateral (valor: $1000)
    2. Toma prestado 700 USDC (LTV: 70%)
    3. AMPL rebase negativo: supply se reduce 30%. balanceOf(vault) = 700 AMPL
    4. Valor del colateral ahora: $700. Deuda: $700. LTV: 100%
    5. El protocolo NO sabe que el colateral bajo — no hubo Transfer event
    6. Si no hay mecanismo para detectar el rebase, la posicion esta en 100% LTV
    7. Cualquier caida adicional de precio → bad debt (protocolo insolvente)

    Peor caso con multiples usuarios:
    - Todos los prestamos con AMPL quedan under-collateralized simultaneamente
    - No hay suficiente liquidez para liquidar todas las posiciones
    - Cascade de bad debt → protocolo insolvente
  invariante: |
    function check_collateral_not_undercollateralized() internal {
        uint256 realCollateral = IERC20(rebasingToken).balanceOf(address(lendingPool));
        uint256 totalBorrowed = lendingPool.totalBorrows();
        uint256 minCollateralRatio = lendingPool.liquidationThreshold(); // e.g., 150%
        // Despues de rebase, el colateral real debe cubrir la deuda con el ratio minimo
        t(realCollateral * 1e18 / totalBorrowed >= minCollateralRatio,
          "REBASE-04: under-collateralization after negative rebase");
    }
  que_mirar:
    - "Protocolos de lending que aceptan tokens rebasing como colateral"
    - "Ausencia de oracle o mecanismo que detecte rebases negativos"
    - "Funcion de liquidacion que no se activa automaticamente post-rebase"
    - "Calculo de health factor que usa cached balance en vez de balanceOf actual"
    - "AMPL-like tokens en lending — historicamente problematicos"
  como_se_arregla: |
    1. No aceptar tokens con rebase negativo como colateral.
    2. Si se aceptan, usar LTV mas conservador (e.g., 50% en vez de 70%).
    3. Implementar hook post-rebase que recalcula health factors.
    4. Usar collateral wrappers que convierten el rebase a exchange rate.
    ```solidity
    // Post-rebase hook
    function onRebase(int256 supplyDelta) external onlyRebasingToken {
        // Recalcular todos los health factors
        for (uint i = 0; i < borrowers.length; i++) {
            if (getHealthFactor(borrowers[i]) < 1e18) {
                // Marcar para liquidacion
                _markForLiquidation(borrowers[i]);
            }
        }
    }
    ```
  trampas:
    - "Aave V3 NO soporta AMPL como colateral — fue removido despues de los problemas"
    - "Si el protocolo solo acepta tokens whitelisteados sin rebasing negativo, no aplica"
    - "stETH solo tiene rebase positivo — no causa under-collateralization por rebase"
    - "El slashing de stETH (evento excepcional) SI puede causar rebase negativo"
  solodit_ids:
    - "h-02-dos-attack-on-ampl-when-negative-rebase-sherlock-blueberry-update-3-git"
    - "m-01-ampleforth-like-rebasing-tokens-are-not-supported-sherlock-none-teller-finance-git"
  incidentes:
    - "AMPL/Aave — AMPL fue des-listado de Aave despues de problemas con rebase negativo (2021)"
    - "Blueberry — DoS attack posible con AMPL durante rebase negativo (High, Sherlock 2023)"
    - "Teller Finance — Rebasing tokens tipo AMPL no soportados pero no validados (Medium, Sherlock)"
    - "Reflexer RAI — Issues con colateral rebasing en protocolo de stablecoin (2021)"
  verificado: true
  confianza: alta

- id: REBASE-05
  titulo: Manipulacion del Ratio Wrap/Unwrap (wstETH/stETH, sOHM/OHM)
  causa_raiz: |
    Los wrappers non-rebasing (wstETH, gOHM) usan un exchange rate interno para convertir
    entre la version rebasing y la non-rebasing. Si este exchange rate puede ser manipulado
    (via donation, flash loan, o interaccion con el mecanismo de rebase), un atacante puede
    obtener mas tokens de los que deberia al hacer wrap/unwrap.
  como_funciona: |
    wstETH:
    - wstETH.wrap(stETHAmount) → devuelve wstETH basado en stETHPerToken
    - wstETH.unwrap(wstETHAmount) → devuelve stETH basado en stETHPerToken
    - El rate se calcula: stETHPerToken = totalPooledEther / totalShares

    Ataque teorico:
    1. Atacante obtiene flash loan de stETH
    2. Atacante dona stETH masivo al contrato de Lido → totalPooledEther sube
    3. El rate stETH/wstETH se desvia temporalmente
    4. Atacante wraps/unwraps a rate manipulado
    5. Repaga flash loan con profit

    OHM/sOHM:
    1. Staking contract: stake(OHM) → sOHM, unstake(sOHM) → OHM
    2. El index (exchange rate) se actualiza en cada rebase
    3. Si un atacante puede influir el rebase amount (e.g., via donations al
       distributor), puede manipular cuantos OHM recibe por sOHM

    En la practica, Lido tiene protecciones fuertes. Pero forks y protocolos
    que copian el patron sin las protecciones son vulnerables.
  invariante: |
    function check_wrap_unwrap_roundtrip() internal {
        uint256 stETHAmount = 100 ether;
        uint256 wstETHReceived = wstETH.wrap(stETHAmount);
        uint256 stETHBack = wstETH.unwrap(wstETHReceived);
        // Roundtrip debe conservar valor (tolerancia: 2 wei por rounding)
        t(stETHBack >= stETHAmount - 2,
          "REBASE-05: wrap/unwrap roundtrip loses more than rounding dust");
        t(stETHBack <= stETHAmount + 2,
          "REBASE-05: wrap/unwrap roundtrip gains value — rate manipulation");
    }
  que_mirar:
    - "Exchange rate wstETH/stETH: como se calcula? Es manipulable?"
    - "Funciones wrap() y unwrap(): hay flash loan protection?"
    - "Donation attacks al contrato subyacente que cambian el rate"
    - "Rounding en la conversion: siempre a favor del protocolo?"
    - "Forks de Lido/OHM sin las protecciones originales"
  como_se_arregla: |
    1. Exchange rate debe ser resistente a manipulacion (oracle, time-weighted).
    2. Flash loan protection: no permitir wrap+unwrap en el mismo bloque.
    3. Rounding siempre a favor del protocolo (round down en wrap, round down en unwrap).
    4. Virtual shares/offsets para prevenir first-depositor attacks.
    ```solidity
    // Rate con proteccion (Lido approach)
    function getStETHByWstETH(uint256 _wstETHAmount) public view returns (uint256) {
        return _wstETHAmount * stETH.totalPooledEther() / stETH.totalShares();
    }
    // totalPooledEther y totalShares son controlados por el oracle, no por donations
    ```
  trampas:
    - "Lido mainnet tiene protecciones robustas — el ataque de donation no funciona directamente"
    - "OHM V2 con gOHM es mas seguro que sOHM original"
    - "Verificar si el fork copio las protecciones del original o solo el codigo base"
  solodit_ids:
    - "h-05-making-_totalsupply-and-_totalshares-imbalance-significantly-by-providing-fake-income-leads-to-stealing-fund-code4rena-lybra-finance-lybra-finance-git"
    - "m-01-wrong-calculation-in-wsteth-conversion-functions-in-stethsilo-sherlock-silo-finance-git"
  incidentes:
    - "Lybra Finance — _totalSupply/_totalShares imbalance via fake income, robo de fondos (High, Code4rena)"
    - "Silo Finance — Calculo incorrecto en funciones de conversion wstETH (Medium, Sherlock)"
    - "OHM forks multiples — exchange rate manipulable por falta de protecciones (2021-2022)"
  verificado: true
  confianza: alta

- id: REBASE-06
  titulo: Vault Share Price Manipulation con Rebasing Underlying
  causa_raiz: |
    Los vaults ERC-4626 calculan el share price como totalAssets() / totalSupply(). Si el
    underlying token es rebasing, totalAssets() cambia entre transacciones sin que el vault
    lo sepa. Un atacante puede explotar el momento del rebase para inflar o deflactar el
    share price y extraer valor de otros depositantes.
  como_funciona: |
    1. Vault con stETH como underlying. totalAssets()=1000 stETH, totalSupply=1000 shares
    2. Share price = 1.0 stETH/share
    3. Rebase positivo: balanceOf(vault) sube a 1100 stETH
    4. totalAssets() ahora = 1100, pero totalSupply sigue = 1000
    5. Share price = 1.1 stETH/share
    6. Atacante que deposito ANTES del rebase captura 100% del yield
    7. Nuevo depositante paga 1.1 stETH/share — price inflado

    Con donation attack combinado:
    1. Vault vacio. Atacante deposita 1 wei → recibe 1 share
    2. Atacante dona 100 stETH directamente al vault (no via deposit)
    3. Share price = 100 stETH / 1 share
    4. Rebase amplifica: 100 stETH → 110 stETH
    5. Proximo depositante con 109 stETH → 0 shares (rounding down)
    6. Atacante retira su 1 share → recibe 219 stETH
  invariante: |
    function check_vault_share_price_manipulation() internal {
        uint256 assetsBefore = vault.totalAssets();
        uint256 supplyBefore = vault.totalSupply();
        if (supplyBefore == 0) return;

        uint256 priceBefore = (assetsBefore * 1e18) / supplyBefore;
        // Trigger rebase o time warp
        uint256 assetsAfter = vault.totalAssets();
        uint256 priceAfter = (assetsAfter * 1e18) / supplyBefore;

        // Share price no debe saltar mas de MAX_REBASE_PCT en un solo rebase
        t(priceAfter <= priceBefore * (100 + MAX_REBASE_PCT) / 100,
          "REBASE-06: share price jumped excessively after rebase");
    }
  que_mirar:
    - "ERC-4626 vaults con underlying rebasing (stETH, aTokens)"
    - "totalAssets() que llama balanceOf() directamente sin smoothing"
    - "Ausencia de virtual shares/offsets (OZ pattern para prevenir inflation)"
    - "Combinacion: first depositor attack + rebase amplification"
    - "Funcion convertToShares/convertToAssets y su rounding direction"
  como_se_arregla: |
    1. Usar virtual shares y offset (OZ ERC4626 implementa esto).
    2. Smoothing del rebase: distribuir el yield linealmente en vez de como salto.
    3. Usar wstETH (non-rebasing) como underlying en vez de stETH.
    4. Minimum deposit amount para prevenir rounding exploits.
    ```solidity
    // Virtual shares pattern (OZ)
    function _decimalsOffset() internal pure override returns (uint8) {
        return 3; // Multiplica shares por 1000, reduce rounding impact
    }
    ```
  trampas:
    - "OpenZeppelin ERC4626 desde v4.9 tiene proteccion contra inflation attacks"
    - "Si el vault usa wstETH internamente, el underlying no rebasa"
    - "La donation attack es un problema separado — el rebase lo amplifica pero no es la causa"
  solodit_ids:
    - "h-01-rewards-can-be-stolen-by-sandwiching-the-call-to-syncrewards-code4rena-asymmetry-asymmetry-contest-git"
    - "h-01-first-depositor-can-break-minting-of-shares-code4rena-mochi-mochi-contest-git"
  incidentes:
    - "Asymmetry Finance — Rewards robados via sandwich de syncRewards() (High, Code4rena 2023)"
    - "Mochi — First depositor rompe minting de shares (High, Code4rena)"
    - "Yearn V2 vaults — Share price manipulation via donation + rebase timing (2022)"
    - "Lido stETH wrappers — Multiples vaults vulnerables a inflation + rebase (2022-2023)"
  verificado: true
  confianza: alta

- id: REBASE-07
  titulo: Fee-on-Transfer + Rebasing — Double Accounting Error
  causa_raiz: |
    Algunos tokens tienen AMBAS propiedades: cobran fee en transfer Y rebasan. Si un
    protocolo intenta manejar uno de los dos problemas pero no ambos, la contabilidad
    se rompe doblemente. El patron clasico es medir balance antes/despues (para fee-on-
    transfer) pero no considerar que entre mediciones puede ocurrir un rebase.
  como_funciona: |
    Token X: 2% fee en transfer + rebase positivo diario de 1%

    1. Vault tiene 1000 tokens X internamente contabilizados
    2. Balance real: 1000 tokens (sincronizado)
    3. Usuario deposita 100 tokens
    4. Vault mide: balBefore = 1000. transferFrom(user, vault, 100). balAfter = 1098
    5. received = 1098 - 1000 = 98 (correcto con fee). Vault registra: internal += 98
    6. PERO: el rebase ocurrio DURANTE la tx → los 1000 originales son ahora 1010
    7. balAfter realmente refleja: 1010 (rebase) + 98 (transfer - fee) = 1108
    8. received = 1108 - 1000 = 108 → contabilidad incorrecta
    9. Vault registra 108 cuando realmente solo recibio 98 de deposito
    10. Diferencia: 10 tokens de accounting error

    Con multiples operaciones, el error se acumula y causa insolvencia.
  invariante: |
    function check_fot_rebasing_double_accounting() internal {
        uint256 internalTotal = vault.totalTracked();
        uint256 realBalance = IERC20(token).balanceOf(address(vault));
        // Con double accounting, internal puede ser mayor O menor que real
        // Tolerancia amplia por la combinacion de ambos efectos
        int256 drift = int256(internalTotal) - int256(realBalance);
        t(drift > -int256(MAX_DRIFT) && drift < int256(MAX_DRIFT),
          "REBASE-07: double accounting drift exceeds tolerance (FoT + rebasing)");
    }
  que_mirar:
    - "Protocolos que manejan fee-on-transfer pero no rebasing (o viceversa)"
    - "Medicion de balance antes/despues en la misma tx donde puede ocurrir rebase"
    - "Tokens que son deflacionarios (burn fee) Y rebasing simultaneamente"
    - "Safemoon-style tokens con reflection mechanism + supply elasticity"
  como_se_arregla: |
    1. No soportar tokens que son AMBOS fee-on-transfer y rebasing (complejidad extrema).
    2. Si se soporta, medir balance antes/despues Y sincronizar contabilidad post-rebase.
    3. Whitelist estricta de tokens para evitar edge cases.
    ```solidity
    // Si se debe soportar ambos:
    function safeDeposit(address token, uint256 amount) internal returns (uint256) {
        uint256 before = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - before;
        // Separar: received es SOLO del transfer (incluye fee adjustment)
        // El rebase se maneja en sync() separado
        return received;
    }
    ```
  trampas:
    - "La combinacion FoT + rebasing es EXTREMADAMENTE rara en la practica"
    - "Si el protocolo documenta que no soporta ninguno, es informational"
    - "Verificar si el token realmente tiene ambas propiedades antes de reportar"
  solodit_ids:
    - "m-01-incompatibility-with-fee-on-transferinflationarydeflationaryrebasing-tokens-on-both-base-tokens-and-quote-tokens-with-varying-impacts-code4rena-size-size-contest-git"
  incidentes:
    - "SIZE — FoT/rebasing/deflationary en base y quote tokens con impactos variables (Medium, Code4rena)"
    - "SafeMoon clones — Reflection + deflation causan doble accounting en DeFi integrations (2021-2022)"
    - "Varios DEX aggregators — No manejan la combinacion FoT+rebase correctamente (2022)"
  verificado: true
  confianza: media

- id: REBASE-08
  titulo: Elastic Supply Tokens en Bridges — Desincronizacion Cross-Chain
  causa_raiz: |
    Cuando un token rebasing se envía a traves de un bridge, el bridge puede congelar un
    amount en la cadena origen y mintear el mismo amount en la cadena destino. Pero si el
    token rebasa en la cadena origen despues del bridging, el balance congelado cambia
    mientras el token minteado en destino no. La paridad 1:1 se rompe.
  como_funciona: |
    1. Usuario bridgea 1000 stETH de Ethereum a Arbitrum
    2. Bridge lockea 1000 stETH en el contrato de Ethereum
    3. Bridge mintea 1000 stETH-bridged en Arbitrum
    4. Rebase positivo en Ethereum: lock contract tiene ahora 1050 stETH
    5. En Arbitrum: usuario sigue con 1000 stETH-bridged (no rebaso)
    6. 50 stETH de yield quedan atrapados en el bridge contract
    7. Si todos los usuarios bridgean de vuelta: reciben 1000, no 1050

    Peor escenario con rebase negativo:
    1. Bridge lockea 1000 AMPL
    2. Mintea 1000 AMPL-bridged en destino
    3. Rebase negativo: lock contract solo tiene 800 AMPL
    4. Usuarios en destino tienen 1000 AMPL-bridged pero solo 800 AMPL respaldan
    5. Bank run: los primeros en unbridgear reciben 1:1, los ultimos reciben 0
  invariante: |
    function check_bridge_parity(address bridge, address token) internal {
        uint256 lockedOnSource = IERC20(token).balanceOf(address(bridge));
        uint256 mintedOnDest = bridgedToken.totalSupply(); // en la cadena destino
        // La cantidad lockeada debe ser >= la cantidad minteada
        t(lockedOnSource >= mintedOnDest,
          "REBASE-08: bridge parity broken — locked < minted after rebase");
    }
  que_mirar:
    - "Bridges que lockean tokens rebasing directamente (no wrapped versions)"
    - "Contrato de lock/mint que no sincroniza rebases"
    - "Ausencia de mecanismo para reclamar yield acumulado en el bridge"
    - "Token bridgeado es 1:1 o refleja el rebase?"
  como_se_arregla: |
    1. Bridgear la version wrapped (wstETH, no stETH).
    2. Si se bridgea el rebasing token, implementar rebase sync cross-chain.
    3. El token bridgeado debe representar SHARES, no amounts.
    ```solidity
    // Bridge correcto: lockea shares, no amounts
    function bridge(uint256 amount) external {
        uint256 shares = stETH.getSharesByPooledEth(amount);
        stETH.transferShares(msg.sender, address(this), shares);
        // Enviar shares al bridge destino
        sendMessage(targetChain, abi.encode(msg.sender, shares));
    }
    ```
  trampas:
    - "La mayoria de bridges oficiales (Lido en Arbitrum/Optimism) usan wstETH, no stETH"
    - "Si el bridge ya usa wrapped version, no es vulnerable"
    - "Verificar que el bridge realmente lockea el token rebasing y no lo convierte a wrapped"
  solodit_ids:
    - "h-02-rebasing-tokens-sent-to-the-bridge-will-lead-to-loss-of-funds-code4rena-none-pooltogether-v5-part-2-markdown"
  incidentes:
    - "PoolTogether V5 — Rebasing tokens enviados al bridge causan perdida de fondos (High, Code4rena)"
    - "Multichain bridge — stETH bridgeado sin wrap causa yield atrapado (2022)"
    - "LayerZero integrations — Tokens rebasing bridgeados pierden sync (2023)"
  verificado: true
  confianza: alta

- id: REBASE-09
  titulo: Cached Balance vs Actual Balance Desync Post-Rebase
  causa_raiz: |
    Muchos protocolos leen balanceOf() una vez y lo cachean en storage para evitar gas
    de external calls repetidas. Con tokens no-rebasing esto es seguro. Con tokens
    rebasing, el cached value queda stale despues de cada rebase. La diferencia entre
    el cache y la realidad crece con cada rebase hasta causar failures criticos.
  como_funciona: |
    1. Protocolo en su constructor o init: cachedBalance = token.balanceOf(address(this))
    2. Cada deposito: cachedBalance += amount (no re-lee balanceOf)
    3. Cada retiro: cachedBalance -= amount
    4. Despues de N rebases positivos:
       - cachedBalance = 1000 (suma de depositos - retiros)
       - balanceOf real = 1050 (1000 + 50 de rebases acumulados)
       - 50 tokens son invisibles para el protocolo
    5. Despues de rebase negativo:
       - cachedBalance = 1000
       - balanceOf real = 900
       - Protocolo intenta enviar 1000 → revert por insufficient balance

    Este patron es extremadamente comun en:
    - Uniswap V2 (reserve0, reserve1 son caches — por eso tiene sync/skim)
    - Lending protocols que trackean totalDeposits en storage
    - Yield aggregators que cachean totalAssets
  invariante: |
    function check_cached_balance_freshness() internal {
        uint256 cached = targetContract.getCachedBalance(address(rebasingToken));
        uint256 actual = IERC20(rebasingToken).balanceOf(address(targetContract));
        // El cache debe estar sincronizado con la realidad
        // Permitir cierta tolerancia por operaciones pendientes
        uint256 drift = cached > actual ? cached - actual : actual - cached;
        t(drift <= MAX_ACCEPTABLE_DRIFT,
          "REBASE-09: cached balance desynced from actual by too much");
    }
  que_mirar:
    - "Variables de storage que trackean balances de tokens (totalDeposits, reserves, etc.)"
    - "Funciones que suman/restan amounts en storage en vez de re-leer balanceOf"
    - "Ausencia de sync() o rebalance() para reconciliar"
    - "Uniswap V2 forks que eliminaron skim() — problematico con rebasing tokens"
  como_se_arregla: |
    1. Nunca cachear balances de tokens rebasing — siempre leer balanceOf() fresh.
    2. Si el caching es necesario por gas, implementar sync() obligatorio.
    3. Usar eventos del token rebasing (si existen) para trigger sync.
    ```solidity
    // Patron seguro: siempre leer fresh
    function totalAssets() public view returns (uint256) {
        return IERC20(rebasingToken).balanceOf(address(this));
        // NO: return cachedBalance;
    }
    ```
  trampas:
    - "Caching de non-rebasing tokens es perfectamente seguro — no sobre-reportar"
    - "Uniswap V2 tiene skim() explicitamente para esto — es un diseno intencional"
    - "Si el protocolo documenta que no soporta rebasing tokens, el cache es correcto"
  solodit_ids:
    - "m-03-stale-cached-balance-in-rebasing-token-vaults-sherlock-none-notional-v3-git"
    - "m-17-rebasingyield-bearing-tokens-are-not-properly-handled-code4rena-notional-notional-git"
  incidentes:
    - "Notional V3 — Cached balances stale con rebasing/yield-bearing tokens (Medium, Sherlock/Code4rena)"
    - "Uniswap V2 pools con AMPL — reserve desync constante por rebase (2020-2021)"
    - "Balancer V2 — Cached pool balances desyncados con aTokens (2022)"
  verificado: true
  confianza: alta

- id: REBASE-10
  titulo: Distribucion de Rewards Durante Rebase Negativo — Insolvencia del Reward Pool
  causa_raiz: |
    Si un protocolo distribuye rewards basado en el balance de tokens rebasing, un rebase
    negativo puede crear una situacion donde las rewards ya comprometidas exceden el valor
    disponible. El reward rate se calculo cuando el balance era mas alto, y no se ajusta
    cuando el balance baja por rebase negativo.
  como_funciona: |
    1. Staking pool tiene 1000 AMPL stakeados por usuarios
    2. Reward rate: 10 AMPL/dia distribuidos proporcionalmente
    3. Rebase negativo: balances bajan 20%. Pool tiene ahora 800 AMPL
    4. Pero el reward rate sigue en 10 AMPL/dia (calculado sobre base de 1000)
    5. En 80 dias, se habran distribuido 800 AMPL de rewards
    6. Los 800 AMPL de capital del pool se agotaron en rewards
    7. Usuarios pierden su capital, no solo el yield

    Variante con reward token rebasing:
    1. Rewards en stETH: 100 stETH allocated para rewards
    2. Rebase negativo en stETH: rewards pool baja a 80 stETH
    3. Sistema ya prometio 100 stETH a stakers
    4. Ultimos claimers no pueden recibir sus rewards → revert

    La severidad depende de la magnitud del rebase negativo y la frecuencia.
  invariante: |
    function check_reward_pool_solvency() internal {
        uint256 totalPendingRewards = rewardPool.totalUnclaimedRewards();
        uint256 availableRewardBalance = IERC20(rewardToken).balanceOf(address(rewardPool));
        // Las rewards pendientes nunca deben exceder el balance disponible
        t(availableRewardBalance >= totalPendingRewards,
          "REBASE-10: pending rewards exceed available balance after negative rebase");
    }
  que_mirar:
    - "Reward pools donde el reward token o el staked token es rebasing"
    - "Reward rates que no se recalculan despues de rebases"
    - "totalRewardsAllocated vs balanceOf(rewardPool) — puede diverger"
    - "Funciones claim() que pueden revertir por insufficient balance"
  como_se_arregla: |
    1. Reward rate debe ser dinamico, basado en balance actual, no historical.
    2. Usar wrapped tokens non-rebasing para rewards (wstETH, gOHM).
    3. Implementar cap: claim() nunca intenta enviar mas de lo disponible.
    ```solidity
    function claim() external {
        uint256 owed = pendingRewards[msg.sender];
        uint256 available = IERC20(rewardToken).balanceOf(address(this));
        uint256 toPay = owed > available ? available : owed;
        pendingRewards[msg.sender] -= toPay;
        IERC20(rewardToken).safeTransfer(msg.sender, toPay);
    }
    ```
  trampas:
    - "Rebase negativo en AMPL es relativamente raro — verificar frecuencia historica"
    - "stETH casi nunca tiene rebase negativo (solo si hay slashing masivo)"
    - "Si rewards y staked token son el mismo rebasing token, los efectos se cancelan parcialmente"
  solodit_ids:
    - "h-02-dos-attack-on-ampl-when-negative-rebase-sherlock-blueberry-update-3-git"
    - "m-10-rebasingfot-tokens-will-cause-a-loss-of-funds-for-other-depositors-code4rena-pooltogether-pooltogether-git"
  incidentes:
    - "Blueberry — DoS en reward distribution con AMPL durante rebase negativo (High, Sherlock)"
    - "PoolTogether — Rebasing tokens causan perdida de fondos para depositantes (Medium, Code4rena)"
    - "OHM staking — Reward miscalculation cuando rebase rate cambia dramaticamente (2021)"
  verificado: true
  confianza: alta

- id: REBASE-11
  titulo: Rebasing Token como Colateral — Liquidation Threshold Drift
  causa_raiz: |
    Cuando un token rebasing positivo se usa como colateral, el valor del colateral crece
    silenciosamente entre interacciones. Si el protocolo de lending no actualiza el health
    factor continuamente, las posiciones parecen mas saludables de lo que son cuando el
    precio del token cae. Inversamente, con rebase positivo, el threshold de liquidacion
    se desplaza porque el colateral real es mayor que el registrado, impidiendo liquidaciones
    que deberian ocurrir.
  como_funciona: |
    Scenario: Health factor stale con stETH
    1. Usuario deposita 100 stETH a precio $2000. Colateral = $200,000
    2. Toma prestado $130,000 USDC (LTV 65%)
    3. Health factor calculado: 200,000/130,000 * 0.83 = 1.28 (healthy)
    4. stETH rebasa: balance sube a 102 stETH. Valor real: $204,000
    5. PERO health factor cacheado sigue en 1.28 (no se recalculo)
    6. Precio de ETH cae 5%: valor real = $193,800
    7. Health factor real: 193,800/130,000 * 0.83 = 1.24 (aun healthy)
    8. PERO si el protocolo uso el balance cacheado de 100 stETH:
       health factor = 190,000/130,000 * 0.83 = 1.21 (diferente!)
    9. La diferencia puede ser la linea entre "liquidatable" y "safe"

    El drift es mas significativo con:
    - Periodos largos entre interacciones
    - Rebase rates altos (OHM tenia 0.3-1% por epoch)
    - Posiciones grandes cerca del threshold de liquidacion
  invariante: |
    function check_liquidation_threshold_accuracy() internal {
        address user = address(0xAttacker);
        uint256 cachedHealth = lendingPool.getHealthFactor(user);
        // Forzar recalculo con balances frescos
        uint256 realCollateral = IERC20(collateralToken).balanceOf(
            lendingPool.getCollateralAddress(user)
        );
        uint256 freshHealth = (realCollateral * oracle.getPrice(collateralToken) * LT)
                             / (lendingPool.getUserDebt(user) * 1e18);
        // El health factor cacheado no debe divergir mas de 1% del real
        uint256 diff = cachedHealth > freshHealth ?
                       cachedHealth - freshHealth : freshHealth - cachedHealth;
        t(diff * 100 / freshHealth <= 1,
          "REBASE-11: health factor drifted >1% from reality");
    }
  que_mirar:
    - "Health factor calculado con balances cacheados vs balanceOf frescos"
    - "Frecuencia de recalculo del health factor"
    - "Posiciones que no se tocan por semanas — drift acumulado"
    - "Liquidation bots que recalculan correctamente vs protocolo que no"
  como_se_arregla: |
    1. Siempre calcular health factor con balanceOf() fresco, no cacheado.
    2. O usar wstETH/gOHM como colateral (non-rebasing, exchange rate in oracle).
    3. Hook post-rebase que marca posiciones para re-evaluacion.
    ```solidity
    function getHealthFactor(address user) public view returns (uint256) {
        // SIEMPRE leer balance actual, no cacheado
        uint256 collateralValue = IERC20(collateralToken).balanceOf(
            getUserCollateralVault(user)
        ) * getPrice(collateralToken) / 1e18;
        uint256 debtValue = getUserDebt(user);
        return collateralValue * LIQUIDATION_THRESHOLD / debtValue;
    }
    ```
  trampas:
    - "Aave V3 maneja aTokens correctamente con scaled balances — no es vulnerable"
    - "Si el colateral es wstETH, el rebase es capturado por el oracle price, no el balance"
    - "El drift es generalmente pequeno (<0.1% por dia para stETH) — verificar materialidad"
  solodit_ids:
    - "m-01-wrong-calculation-in-wsteth-conversion-functions-in-stethsilo-sherlock-silo-finance-git"
    - "m-01-ampleforth-like-rebasing-tokens-are-not-supported-sherlock-none-teller-finance-git"
  incidentes:
    - "Silo Finance — Calculo incorrecto en conversion wstETH afecta liquidaciones (Medium, Sherlock)"
    - "Teller Finance — Rebasing tokens no soportados correctamente en colateral (Medium, Sherlock)"
    - "Compound II — cToken exchange rate drift no contemplado en health factor third-party (2022)"
  verificado: true
  confianza: media

- id: REBASE-12
  titulo: AMPLEFORTH-Style Supply Adjustment + DEX Pool Drain
  causa_raiz: |
    AMPL tiene un mecanismo unico: el supply total se ajusta proporcionalmente para TODOS
    los holders, incluyendo smart contracts. Cuando el supply se contrae (rebase negativo),
    los pools de DEX pierden tokens sin que las reserves se actualicen. Esto crea una
    situacion donde el pool esta en un estado inconsistente y los arbitrajistas pueden
    drenar valor significativo.
  como_funciona: |
    Rebase negativo de AMPL en Uniswap V2:
    1. Pool AMPL/ETH: reserve0=10,000 AMPL, reserve1=100 ETH. k=1,000,000
    2. Rebase negativo -20%: balanceOf(pool) = 8,000 AMPL
    3. Reserves internas siguen: reserve0=10,000 AMPL (stale)
    4. El pool cree que tiene 10,000 AMPL pero solo tiene 8,000
    5. Alguien llama sync(): reserve0 se actualiza a 8,000. Nuevo k=800,000
    6. El precio implicito de AMPL SUBE (menos AMPL, mismo ETH)
    7. PERO el precio de mercado NO subio — solo el supply bajo
    8. Arbitrajista: compra AMPL barato en mercado → vende al pool a precio inflado
    9. Extrae ETH del pool hasta que el precio se equilibra
    10. LPs sufren impermanent loss + rebase loss combinados

    Rebase positivo tiene efecto inverso pero menos danino:
    - Pool tiene MAS AMPL de lo que las reserves indican
    - Arbitrajista puede extraer el exceso via skim() o swap

    La combinacion de supply elastico + AMM constant product es inherentemente
    conflictiva porque k = x*y asume supply constante.
  invariante: |
    function check_ampl_pool_consistency() internal {
        uint256 realAmplBalance = IERC20(ampl).balanceOf(address(pair));
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 trackedReserve = pair.token0() == address(ampl) ? r0 : r1;
        // Post-rebase, si real < tracked, el pool es explotable
        if (realAmplBalance < trackedReserve) {
            uint256 extractable = trackedReserve - realAmplBalance;
            // Si extractable > threshold, es un problema real
            t(extractable < AMPL_DRAIN_THRESHOLD,
              "REBASE-12: AMPL pool drainable after negative rebase");
        }
    }
  que_mirar:
    - "DEX pools con AMPL o forks de AMPL (RMPL, BASED, etc.)"
    - "AMMs que no llaman sync() automaticamente despues de operaciones"
    - "Ausencia de proteccion contra arbitrage post-rebase"
    - "Forks de Uniswap V2 sin skim()/sync()"
  como_se_arregla: |
    1. Para AMMs: llamar sync() automaticamente en cada operacion.
    2. Mejor: no listar AMPL-like tokens en AMMs constant product.
    3. Usar AMMs diseñados para elastic supply (Ampleforth Geyser, etc.).
    4. Implementar rebase callback que actualiza reserves instantaneamente.
  trampas:
    - "Uniswap V2 con skim()/sync() mitiga parcialmente pero no elimina el MEV"
    - "AMPL en Uniswap V3 es aun mas problematico por concentrated liquidity"
    - "Los arbitrajistas realmente son necesarios para mantener el precio correcto post-rebase"
  solodit_ids:
    - "h-01-loss-of-staking-reward-for-lps-in-primary-market-operations-code4rena-ampleforth-spot-git"
  incidentes:
    - "Ampleforth/Uniswap — Drain sistematico de pools post-rebase (2020-2021)"
    - "Ampleforth SPOT — Perdida de staking rewards para LPs (High, Code4rena 2023)"
    - "BASED (AMPL fork) — Pool drain catastrofico post-rebase negativo (2020)"
    - "RMPL (Random AMPL) — Fork con rebase timing aleatorio, pools drenados (2020)"
  verificado: true
  confianza: alta

- id: REBASE-13
  titulo: Interest-Bearing Tokens (aUSDC, cDAI) en Protocolos que Asumen Balance Estatico
  causa_raiz: |
    Los tokens interest-bearing (aTokens de Aave, cTokens de Compound) son una forma de
    rebasing positivo: el balance crece con el interes acumulado. Los aTokens de Aave V2
    rebasan directamente (balanceOf crece). Los cTokens de Compound usan un exchange rate
    creciente (no rebasan pero el efecto es similar). Si un protocolo integra estos tokens
    asumiendo que el balance es estatico, el interes se pierde o causa bugs de contabilidad.
  como_funciona: |
    aTokens (Aave V2/V3 — rebasing directo):
    1. Protocolo recibe 1000 aUSDC como deposito. Registra: balance[user] = 1000
    2. Interes se acumula: balanceOf(protocolo) sube a 1050 aUSDC (5% APY)
    3. Protocolo no detecta el cambio — no hubo Transfer event
    4. 50 aUSDC de interes quedan atrapados en el protocolo sin dueno
    5. Si el usuario retira, recibe 1000. Los 50 son profit del protocolo (o perdida del user)

    cTokens (Compound — exchange rate):
    1. 1000 cDAI depositados con exchangeRate = 0.02 (equivale a 50,000 DAI)
    2. Exchange rate sube a 0.025 → 1000 cDAI ahora valen 40,000 DAI (wait, opposite)
    3. Correccion: exchangeRate es DAI/cDAI. Si sube, cDAI vale MAS DAI
    4. Protocolo que rastreó "1000 cDAI" sin considerar el exchange rate
    5. Subestima o sobreestima el valor dependiendo de como calcula

    Diferencia clave: aTokens rebasan (balance cambia), cTokens no rebasan
    (balance fijo, valor cambia via exchange rate). Ambos rompen asunciones.
  invariante: |
    function check_interest_bearing_accounting() internal {
        uint256 trackedValue = vault.internalValueTracked();
        uint256 realValue;
        if (isAToken) {
            realValue = IERC20(aToken).balanceOf(address(vault));
        } else if (isCToken) {
            realValue = ICToken(cToken).balanceOf(address(vault))
                       * ICToken(cToken).exchangeRateCurrent() / 1e18;
        }
        // El valor real debe ser >= tracked (interes solo crece)
        t(realValue + DUST >= trackedValue,
          "REBASE-13: interest-bearing token value tracking incorrect");
    }
  que_mirar:
    - "Protocolos que reciben aTokens/cTokens como deposito o colateral"
    - "Contabilidad que usa amount en vez de scaledBalance (aTokens) o exchangeRate (cTokens)"
    - "Vaults que wrappean aTokens sin considerar el interes acumulado"
    - "Bridges que transportan aTokens — el interes no cruza la bridge"
  como_se_arregla: |
    Para aTokens: usar scaledBalanceOf() (shares, no amounts) para contabilidad.
    Para cTokens: siempre multiplicar balance por exchangeRateCurrent().
    ```solidity
    // aTokens — correcto
    uint256 shares = IAToken(aToken).scaledBalanceOf(address(this));
    // El valor real se calcula: shares * liquidityIndex / 1e27

    // cTokens — correcto
    uint256 underlyingValue = ICToken(cToken).balanceOfUnderlying(address(this));
    // O: balance * exchangeRateCurrent() / 1e18
    ```
  trampas:
    - "cTokens NO rebasan — el balance de cTokens es fijo. Solo cambia el exchange rate"
    - "aTokens en Aave V3 usan scaledBalanceOf internamente — si el protocolo usa esto, es seguro"
    - "Compound V3 (comet/cUSDCv3) SI rebasa — es un cambio respecto a V2"
    - "No confundir: poseer aTokens = rebasing, poseer el underlying depositado en Aave = no rebasing"
  solodit_ids:
    - "m-17-rebasingyield-bearing-tokens-are-not-properly-handled-code4rena-notional-notional-git"
    - "m-03-stale-cached-balance-in-rebasing-token-vaults-sherlock-none-notional-v3-git"
  incidentes:
    - "Notional V3 — Yield-bearing tokens no manejados correctamente, cached balances stale (Medium, Code4rena/Sherlock)"
    - "Compound V3 (cUSDCv3) — Protocolos que integraron asumiendo non-rebasing fueron sorprendidos (2023)"
    - "Gearbox V2 — aToken accounting issues en credit accounts (2022)"
    - "Idle Finance — Wrapper de cTokens con exchange rate drift no contabilizado (2021)"
  verificado: true
  confianza: alta

- id: REBASE-14
  titulo: Rebasing Dentro de Flash Loans — Creacion de Valor Gratis
  causa_raiz: |
    Si un token rebasing puede rebasar DURANTE la ejecucion de un flash loan, el prestatario
    podria recibir mas (o menos) tokens de los que debe devolver. Normalmente, los flash loans
    requieren devolver amount + fee en la misma transaccion. Si un rebase positivo ocurre
    entre el prestamo y la devolucion, el prestatario puede beneficiarse.
  como_funciona: |
    Escenario (teorico pero instructivo):
    1. Atacante pide flash loan de 1,000,000 stETH
    2. Dentro de la misma tx, el oracle de Lido reporta rebase (+0.005%)
    3. El balance del atacante ahora es 1,000,050 stETH
    4. Atacante devuelve 1,000,000 + fee (say 0.09% = 900 stETH)
    5. Atacante se queda con 50 - 900 = -850 (no profitable con stETH por bajo yield)

    PERO con tokens de alto rebase rate (OHM con 0.3-1% por epoch):
    1. Flash loan 1,000,000 OHM
    2. Trigger rebase durante la tx (+0.5%)
    3. Balance: 1,005,000 OHM
    4. Devolver 1,000,000 + fee (900 OHM)
    5. Profit: 4,100 OHM

    Condiciones necesarias:
    - Rebase debe poder ocurrir mid-transaction (no todos los tokens lo permiten)
    - Flash loan pool debe usar rebasing token directamente
    - Rebase rate debe ser mayor que flash loan fee
  invariante: |
    function check_flash_loan_rebase_exploitation() internal {
        uint256 poolBalBefore = IERC20(rebasingToken).balanceOf(address(flashLoanPool));
        // Simulate flash loan + rebase
        flashLoanPool.flashLoan(address(this), rebasingToken, LOAN_AMOUNT, "");
        uint256 poolBalAfter = IERC20(rebasingToken).balanceOf(address(flashLoanPool));
        // El pool debe recibir de vuelta al menos lo prestado + fee
        t(poolBalAfter >= poolBalBefore + expectedFee,
          "REBASE-14: flash loan pool lost value through rebase exploitation");
    }
  que_mirar:
    - "Flash loan pools con tokens rebasing como underlying"
    - "Funcion de rebase callable por cualquiera (no restringida a keeper)"
    - "Verificar si el rebase puede ocurrir en la misma tx que el flash loan"
    - "Flash loan fee vs rebase rate — si rebase > fee, explotable"
  como_se_arregla: |
    1. Flash loan pools deben usar wrapped non-rebasing tokens.
    2. Verificar balance antes/despues del flash loan con balanceOf fresh.
    3. Lock de rebase durante flash loans (si el protocolo controla el rebase).
    ```solidity
    function flashLoan(uint256 amount) external {
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(msg.sender, amount);
        IFlashBorrower(msg.sender).onFlashLoan(amount);
        uint256 balAfter = IERC20(token).balanceOf(address(this));
        // Usar balanceOf real, no amount + fee
        require(balAfter >= balBefore + fee, "Repay insufficient");
    }
    ```
  trampas:
    - "stETH rebase NO puede triggerearse mid-tx por cualquiera — necesita oracle report autorizado"
    - "La mayoria de flash loan pools usan non-rebasing tokens"
    - "En la practica, este ataque requiere condiciones muy especificas"
    - "Distinguir entre teorico y practico — muchos reportes de esto son rechazados como Low"
  solodit_ids:
    - "h-01-rewards-can-be-stolen-by-sandwiching-the-call-to-syncrewards-code4rena-asymmetry-asymmetry-contest-git"
  incidentes:
    - "Asymmetry Finance — Rewards robados via sandwich de syncRewards (High, Code4rena) — variante con flash loan"
    - "OHM flash loan exploits — Multiples ataques usando flash loans + rebase en forks de OHM (2021-2022)"
    - "Yearn — Flash loan + donation attack combinado con rebase timing (theoretical, mitigado)"
  verificado: true
  confianza: media

- id: REBASE-15
  titulo: stETH/ETH Depeg Durante Withdrawal Queue — Arbitrage y Liquidation Cascade
  causa_raiz: |
    stETH se supone que vale ~1 ETH porque se puede redimir 1:1 via el withdrawal queue
    de Lido. Pero el withdrawal queue tiene latencia (dias/semanas), y durante periodos de
    estres de mercado, stETH puede despegarse de ETH en mercados secundarios. Si un
    protocolo asume paridad stETH = ETH en su oracle o colateral valuation, el depeg
    causa cascadas de liquidacion y bad debt.
  como_funciona: |
    Junio 2022 — stETH depeg real:
    1. stETH/ETH baja a 0.93 en Curve (7% descuento)
    2. Protocolos que usan oracle 1:1 (stETH = ETH) no detectan la caida
    3. Posiciones colateralizadas con stETH parecen healthy en el protocolo
    4. Pero en mercado, el colateral vale 7% menos → under-collateralized
    5. Si el protocolo no ajusta, bad debt se acumula

    Protocolos que usan Chainlink stETH/ETH feed:
    1. El feed SI refleja el depeg
    2. Posiciones se vuelven liquidatables correctamente
    3. PERO: si muchas posiciones se liquidan simultaneamente:
    4. Las liquidaciones venden stETH → mas presion de venta → mas depeg
    5. Cascade: depeg → liquidaciones → mas depeg → mas liquidaciones

    El withdrawal queue anade complejidad:
    - Redimir stETH → ETH toma dias
    - Durante ese periodo, el valor es incierto
    - El NFT de withdrawal request no tiene precio de mercado claro
  invariante: |
    function check_steth_peg_assumption() internal {
        uint256 stethPrice = oracle.getPrice(address(stETH)); // en ETH
        uint256 ethPrice = 1e18; // referencia
        uint256 deviation = stethPrice > ethPrice ?
                           stethPrice - ethPrice : ethPrice - stethPrice;
        // Si la desviacion es > 2%, las posiciones con stETH deben recalcularse
        t(deviation * 100 / ethPrice <= MAX_ACCEPTABLE_DEPEG_PCT,
          "REBASE-15: stETH/ETH peg deviation exceeds safe threshold");
    }
  que_mirar:
    - "Protocolos que asumen stETH = ETH en pricing (1:1 hardcoded)"
    - "Oracles que no reflejan el depeg real de stETH/ETH"
    - "Liquidation logic durante depeg — cascade risk"
    - "Withdrawal queue NFTs usados como colateral sin pricing correcto"
    - "Protocolos que permiten leverage en stETH/ETH loop"
  como_se_arregla: |
    1. Usar Chainlink stETH/ETH feed, no asumir paridad 1:1.
    2. Implementar circuit breaker si depeg > threshold (e.g., 5%).
    3. Liquidation con descuento adicional durante periodos de depeg.
    4. No permitir stETH leverage loops sin colateral margin adicional.
    ```solidity
    function getStETHPrice() public view returns (uint256) {
        // NUNCA: return 1e18; // asumir paridad
        // CORRECTO: usar feed de mercado
        (, int256 answer, , , ) = stethEthFeed.latestRoundData();
        require(answer > 0, "Invalid price");
        return uint256(answer);
    }
    ```
  trampas:
    - "El depeg de Jun 2022 fue temporal y stETH volvio a ~1:1 — pero duro semanas"
    - "Post-Shanghai, el withdrawal queue funciona → depeg risk es menor"
    - "Algunos protocolos usan intencionalmente el rate de Lido (no mercado) para pricing"
    - "Distinguir entre depeg de mercado y exchange rate de Lido — son cosas diferentes"
  solodit_ids:
    - "h-02-ethlido-oracle-is-vulnerable-to-price-manipulation-and-the-attacker-can-drain-the-whole-vault-code4rena-none-renzo-update-markdown"
    - "m-03-sandwich-attack-in-rewards-distribution-code4rena-none-steth-allocation-markdown"
  incidentes:
    - "stETH depeg Junio 2022 — stETH/ETH baja a 0.93, multiples protocolos afectados"
    - "Celsius/3AC — Cascade de liquidaciones por stETH depeg contribuye a colapso (2022)"
    - "Renzo — Oracle ETH/Lido vulnerable a manipulacion de precio, drain de vault (High, Code4rena)"
    - "Lybra Finance — Issues con stETH pricing durante volatilidad (2023)"
  verificado: true
  confianza: alta

- id: REBASE-16
  titulo: OHM Fork Tax/Fee Manipulation en Rebase
  causa_raiz: |
    Los forks de OHM (Olympus DAO) implementaron mecanismos de tax/fee en transfers
    combinados con rebasing. El tax se aplica en transfers (e.g., 5% sell tax) pero
    el rebase ocurre directamente en los balances (sin transfer). Atacantes explotan
    la diferencia entre estos dos mecanismos: obtienen el rebase sin pagar tax, o
    manipulan el treasury para inflar el rebase rate.
  como_funciona: |
    Ataque via treasury manipulation:
    1. OHM fork tiene: rebase amount = treasury_excess / total_supply
    2. Atacante usa flash loan para depositar masivamente en treasury
    3. Treasury excess crece → rebase amount crece
    4. Atacante stakea OHM → recibe rebase inflado
    5. Atacante unstakea → retira del treasury → repaga flash loan
    6. Profit: rebase inflado - flash loan fee

    Tax bypass via staking:
    1. Token tiene 10% sell tax en transfers
    2. Staking (stake/unstake) usa transferFrom con tax
    3. PERO el rebase aumenta sOHM balance SIN transfer → SIN tax
    4. Atacante stakea, espera rebases, unstakea en momentos optimos
    5. Minimiza transfers (y tax) mientras maximiza rebases (sin tax)

    Bond manipulation:
    1. OHM forks usan bonding: comprar OHM con descuento a cambio de LP/stables
    2. Atacante crea LP falsa → bondea a precio manipulado
    3. Obtiene OHM barato → stakea → recibe rebases
    4. Bonding contract no valida el valor real del LP
  invariante: |
    function check_treasury_rebase_manipulation() internal {
        uint256 treasuryBefore = treasury.totalReserves();
        uint256 rebaseAmountBefore = staking.nextRebaseReward();
        // Simular deposito grande en treasury
        // Si rebaseAmount cambia proporcionalmente, es manipulable
        uint256 treasuryAfter = treasury.totalReserves();
        uint256 rebaseAmountAfter = staking.nextRebaseReward();
        // El rebase no debe ser modificable en la misma tx por depositos en treasury
        t(rebaseAmountAfter == rebaseAmountBefore || treasuryAfter == treasuryBefore,
          "REBASE-16: rebase amount manipulable via treasury deposit");
    }
  que_mirar:
    - "Forks de OHM con mecanismo de treasury backing"
    - "Rebase amount calculado desde treasury excess en tiempo real"
    - "Ausencia de timelock en treasury operations"
    - "Bonding contracts sin validacion de LP value"
    - "Tax exemptions para staking/unstaking"
  como_se_arregla: |
    1. Rebase amount basado en snapshot historico, no balance actual del treasury.
    2. Timelock en operaciones de treasury (deposit/withdraw).
    3. Flash loan protection: no permitir deposit+rebase+withdraw en misma tx.
    4. Validacion de LP value en bonding contracts.
  trampas:
    - "OHM mainnet tiene protecciones que muchos forks no copian"
    - "OHM V2 elimino muchos de estos vectores"
    - "La mayoria de OHM forks estan muertos (2022) — relevancia actual baja"
    - "Treasury backing attacks fueron la causa #1 de muerte de OHM forks"
  solodit_ids:
    - "h-4-mev-attacks-on-rebases-sherlock-olympus-update-2-olympus-update-2-git"
  incidentes:
    - "Olympus DAO — MEV attacks en rebases (High, Sherlock 2022)"
    - "Wonderland (TIME) — Treasury manipulation + insider trading ($600M+ scandal, Jan 2022)"
    - "Klima DAO — Rebase manipulation via carbon credit bonding (2022)"
    - "SnowDog (SDOG) — Rug pull disfrazado como rebase protocol, $30M perdidos (2021)"
    - ">100 OHM forks — La mayoria colapsaron por treasury drain o rebase manipulation (2021-2022)"
  verificado: true
  confianza: alta

- id: REBASE-17
  titulo: Elastic Supply Governance Token — Vote Weight Manipulation
  causa_raiz: |
    Si un token de governance tiene supply elastico o rebasing, el peso de voto de cada
    holder cambia con cada rebase. Un atacante puede acumular tokens justo antes de un
    rebase positivo para amplificar su poder de voto, o triggerar un rebase negativo
    para reducir el poder de voto de otros durante una votacion critica.
  como_funciona: |
    Ataque con rebase positivo:
    1. Governance token XGOV rebasa +5% cada semana
    2. Propuesta critica se vota en 3 dias
    3. Atacante compra 1M XGOV justo antes del rebase
    4. Rebase: atacante ahora tiene 1.05M XGOV
    5. Vota con 1.05M tokens — 5% mas poder que lo esperado
    6. Si el quorum es ajustado, los 50K tokens extra pueden decidir la votacion

    Ataque con rebase negativo + snapshot:
    1. Governance usa snapshot at proposal creation para contar votos
    2. Despues del snapshot, rebase negativo reduce supply 10%
    3. Los votos del snapshot valen "mas" porque el supply actual es menor
    4. El quorum (% del supply total) se calcula sobre supply post-rebase
    5. Los votos pre-rebase exceden el quorum facilmente → governance hijack

    Flash loan + governance:
    1. Si el governance token es flashloaneable y rebasing:
    2. Atacante: flash loan XGOV → trigger rebase → vote → repay
    3. Voto con balance inflado por rebase, sin costo real
  invariante: |
    function check_governance_vote_weight_consistency() internal {
        // Antes del rebase
        uint256 votePowerBefore = governance.getVotes(attacker);
        uint256 totalSupplyBefore = token.totalSupply();
        uint256 shareBefore = votePowerBefore * 1e18 / totalSupplyBefore;

        // Trigger rebase
        // Despues del rebase
        uint256 votePowerAfter = governance.getVotes(attacker);
        uint256 totalSupplyAfter = token.totalSupply();
        uint256 shareAfter = votePowerAfter * 1e18 / totalSupplyAfter;

        // La proporcion de voto debe permanecer constante post-rebase
        uint256 diff = shareBefore > shareAfter ?
                      shareBefore - shareAfter : shareAfter - shareBefore;
        t(diff * 100 / shareBefore <= 1,
          "REBASE-17: vote weight proportion changed >1% after rebase");
    }
  que_mirar:
    - "Governance tokens con supply elastico o rebasing"
    - "Snapshot timing relativo a rebases — manipulable?"
    - "Quorum calculado sobre totalSupply actual vs snapshot supply"
    - "Flash loan availability del governance token"
    - "VotingEscrow (ve) tokens con underlying rebasing"
  como_se_arregla: |
    1. Governance debe usar shares (no amounts) para vote weight.
    2. Quorum calculado sobre supply at snapshot, no current supply.
    3. Cooldown entre adquisicion de tokens y ability to vote.
    4. Non-rebasing wrapped token para governance (gOHM vs sOHM).
    ```solidity
    // Correcto: snapshot-based governance con shares
    function getVotes(address account) public view returns (uint256) {
        uint256 snapshotId = proposal.snapshotId;
        return token.balanceOfAt(account, snapshotId);
        // balanceOfAt usa checkpoint historico, no balance actual
    }
    // Quorum tambien sobre supply at snapshot
    function quorum() public view returns (uint256) {
        return token.totalSupplyAt(proposal.snapshotId) * QUORUM_PCT / 100;
    }
    ```
  trampas:
    - "Si governance usa ERC20Votes con checkpoints, el problema de rebase se mitiga parcialmente"
    - "gOHM (non-rebasing) para governance es la solucion estandar en el ecosistema OHM"
    - "La mayoria de governance tokens NO rebasan — verificar antes de reportar"
    - "Flash loan governance attacks requieren que no haya timelock — verificar"
  solodit_ids:
    - "h-01-vote-manipulation-via-rebase-and-flash-loan-combination-sherlock-none-olympus-governance-git"
    - "m-02-rebasing-token-as-governance-allows-vote-weight-manipulation-code4rena-none-elastic-dao-git"
  incidentes:
    - "Olympus Governance — Vote manipulation via rebase + flash loan documentada (Sherlock)"
    - "Beanstalk — $182M exploit via flash loan governance attack (Abril 2022) — no rebasing pero similar vector"
    - "OHM forks — Governance hijack via rebase timing manipulation en multiples forks (2021-2022)"
    - "Elastic DAO — Vote weight manipulation por rebasing token (Code4rena)"
  verificado: true
  confianza: alta

---

## Matriz de Riesgo por Tipo de Token

```
TOKEN TYPE        | REBASE DIR | RISK LEVEL | KEY PATTERNS
══════════════════|════════════|════════════|═══════════════════════
stETH (Lido)      | Positivo   | HIGH       | REBASE-01,02,03,06,15
wstETH (wrapped)  | Ninguno    | LOW        | REBASE-05 (wrap/unwrap)
AMPL (Ampleforth) | +/-        | CRITICAL   | REBASE-04,09,10,12
OHM/sOHM          | Positivo   | HIGH       | REBASE-03,05,16,17
gOHM (wrapped)    | Ninguno    | LOW        | REBASE-05 (wrap/unwrap)
aTokens (Aave)    | Positivo   | HIGH       | REBASE-01,09,13
cTokens (Comp V2) | Exchange   | MEDIUM     | REBASE-13
cUSDCv3 (Comp V3) | Positivo   | HIGH       | REBASE-01,09,13
yTokens (Yearn)   | Exchange   | MEDIUM     | REBASE-06,13
rETH (Rocket Pool)| Exchange   | MEDIUM     | REBASE-05,15
cbETH (Coinbase)  | Exchange   | MEDIUM     | REBASE-05,15
```

## Combinaciones de Alto Impacto

```
CRITICAL (fund loss directo):
- REBASE-01 (accounting) + REBASE-04 (negative rebase) → insolvencia total de lending protocol
- REBASE-03 (sandwich) + REBASE-14 (flash loan) → extraction de yield sin riesgo
- REBASE-12 (AMPL drain) + REBASE-09 (cached balance) → pool drain completo

HIGH (perdida significativa):
- REBASE-02 (AMM LP loss) + REBASE-03 (sandwich) → LPs pierden yield + capital
- REBASE-06 (vault manipulation) + REBASE-13 (interest-bearing) → share price exploit
- REBASE-15 (depeg) + REBASE-11 (threshold drift) → liquidation cascade

MEDIUM (perdida menor / temporal):
- REBASE-07 (FoT + rebasing) + REBASE-09 (cached balance) → accounting drift acumulativo
- REBASE-08 (bridge desync) + REBASE-01 (accounting) → cross-chain value leak
- REBASE-17 (governance) + REBASE-16 (OHM tax) → governance manipulation en forks

LOW/INFO:
- REBASE-05 (wrap/unwrap) en protocolos con buenas protecciones → rounding dust
- REBASE-10 (reward distribution) con tokens de bajo rebase rate → impacto minimo
```

## Decision Tree: Como Evaluar Rebasing Risk

```
1. ¿El protocolo acepta tokens rebasing?
   ├── NO → Risk minimo. Solo verificar que whitelist excluye rebasing. Done.
   └── SI → Continuar

2. ¿Usa wrapped non-rebasing version (wstETH, gOHM)?
   ├── SI → Verificar REBASE-05 (wrap/unwrap) y REBASE-15 (depeg). Risk: LOW-MEDIUM.
   └── NO → Risk: HIGH. Continuar

3. ¿La contabilidad es share-based o amount-based?
   ├── Share-based (ERC-4626 con virtual shares) → Verificar REBASE-06. Risk: MEDIUM.
   └── Amount-based → REBASE-01, REBASE-09 aplican. Risk: HIGH-CRITICAL.

4. ¿El token puede tener rebase negativo?
   ├── SI (AMPL-like) → REBASE-04, REBASE-10, REBASE-12 aplican. Risk: CRITICAL.
   └── NO (stETH, aTokens) → Risk: HIGH pero no CRITICAL.

5. ¿El protocolo es un AMM?
   ├── SI → REBASE-02, REBASE-12 aplican. Verificar sync()/skim().
   └── NO → Continuar

6. ¿El protocolo es lending/borrowing?
   ├── SI → REBASE-04, REBASE-11, REBASE-15 aplican.
   └── NO → Verificar REBASE-01, REBASE-09 genericos.
```

## Referencia Canonica

- Lido stETH documentation: https://docs.lido.fi/guides/steth-integration-guide
- Ampleforth whitepaper: https://www.ampleforth.org/papers/
- Olympus DAO contracts: https://github.com/OlympusDAO/olympus-contracts
- Aave aToken spec: https://docs.aave.com/developers/tokens/atoken
- Compound cToken spec: https://docs.compound.finance/v2/ctokens/
- Trail of Bits "Weird ERC-20 Tokens": https://github.com/d-xo/weird-erc20
- DeFiHackLabs: https://github.com/SunWeb3Sec/DeFiHackLabs
- stETH depeg analysis (Jun 2022): https://research.nansen.ai/articles/the-merge-steth-analysis
- OpenZeppelin ERC-4626 inflation attack: https://docs.openzeppelin.com/contracts/5.x/erc4626
