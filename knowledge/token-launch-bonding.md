# Token Launch & Bonding Curves — Bug Patterns

## Quick Reference

```
grep_targets:
  - bondingCurve
  - BondingCurve
  - buyToken
  - sellToken
  - getPrice
  - calculatePurchaseReturn
  - calculateSaleReturn
  - reserveBalance
  - reserveRatio
  - curveSupply
  - graduation
  - graduate
  - migrateLiquidity
  - createPool
  - addLiquidity
  - removeLiquidity
  - LBP
  - LiquidityBootstrapping
  - updateWeightsGradually
  - dutchAuction
  - startPrice
  - endPrice
  - decayRate
  - presale
  - whitelist
  - maxTransactionAmount
  - cooldown
  - antiBot
  - antiSnipe
  - launchTime
  - tradingEnabled
  - maxWallet
  - IDO
  - IFO
  - allocation
  - oversubscription
  - vestingSchedule
  - cliffDuration
  - unlockTime
  - mintAuthority
  - setFinalPrice
  - refund
  - BancorFormula
  - sigmoid
  - exponentialCurve
  - linearCurve
```

---

## 1. Bonding Curve Sandwich Attack

```yaml
- id: launch-001
  titulo: Sandwich en bonding curve — compra antes de orden grande, vende después del aumento
  causa_raiz: |
    Las bonding curves determinísticas (x^2, bancor, sigmoid) tienen una relación precio-supply
    conocida públicamente. Cualquier compra grande en el mempool es visible, y un atacante puede
    insertar una compra justo antes (front-run) y una venta justo después (back-run). La curva
    garantiza que el precio sube monotónicamente con cada compra, haciendo el sandwich 100%
    predecible — a diferencia de AMMs con pools donde hay slippage variable.
    En friend.tech, la curva price = supply^2 / 16000 hacía que compras de "keys" fueran
    extremadamente predecibles y sandwich-ables.
  como_funciona: |
    1. Víctima envía tx para comprar N tokens en la bonding curve (mempool público).
    2. Atacante ve la tx pendiente, calcula el precio post-compra usando la fórmula de la curva.
    3. Atacante front-runs: compra M tokens → precio sube de P1 a P2.
    4. Tx de la víctima ejecuta: compra N tokens a precio P2 (más caro) → precio sube a P3.
    5. Atacante back-runs: vende M tokens a precio entre P2 y P3 → profit = (P_venta - P_compra) * M.
    Cuanto más empinada la curva y más grande la orden de la víctima, más profit para el atacante.
    En protocolos tipo pump.fun sin protección anti-MEV, cada compra grande es un target.
  invariante: |
    // Slippage protection: el precio efectivo no debe exceder el máximo aceptable
    uint256 effectivePrice = totalCost / tokensBought;
    assert(effectivePrice <= maxPricePerToken);
    // Anti-sandwich: detectar si el precio cambió drásticamente en el mismo bloque
    assert(currentPrice <= lastBlockPrice * (100 + MAX_BLOCK_PRICE_CHANGE_PCT) / 100);
  que_mirar:
    - Función buy() sin parámetro minTokensOut o maxPrice
    - Curvas con pendiente empinada (cuadrática, exponencial) donde el impacto de precio es alto
    - Ausencia de commit-reveal para órdenes grandes
    - Protocolos en chains con mempool público (Ethereum L1) vs chains con sequencer (L2)
    - friend.tech style: price = n^2/16000 sin slippage protection
  como_se_arregla: |
    Implementar slippage protection obligatorio: minTokensOut en buy(), minETHOut en sell().
    Opcionalmente: commit-reveal scheme para órdenes sobre cierto umbral.
    En L2 con sequencer privado (Base, Arbitrum): el riesgo se reduce pero no se elimina
    (el sequencer puede extraer MEV). Usar Flashbots Protect o MEV-Share si disponible.
  trampas:
    - En L2 tipo Base, el sequencer es privado → sandwich clásico es más difícil, pero el
      operador del sequencer SÍ puede hacer MEV. No asumir que "L2 = sin sandwich".
    - Protocolos pueden argumentar "el usuario puede poner slippage" — pero si la UI no lo
      expone, en la práctica nadie lo usa.
    - El commit-reveal añade latencia (2 bloques mínimo) que puede ser inaceptable en UX.
  solodit_ids:
    - "h-01-_swap-is-vulnerable-to-sandwich-attacks-pashov-audit-group-none-gacha_2025-markdown"
    - "h-05-functions-in-the-votiumstrategy-contract-are-susceptible-to-sandwich-attacks-code4rena-asymmetry-finance-asymmetry-contest-git"
    - "deposit-and-withdraw-functions-are-susceptible-to-sandwich-attacks-spearbit-gauntlet-pdf"
  incidentes:
    - "friend.tech (2023) — curva cuadrática sin slippage protection. Bots extrajeron millones en MEV de compradores de keys via sandwich sistemático."
    - "pump.fun (2024) — $2M perdidos. Atacante usó flash loans para comprar hasta el graduation threshold y drenar la bonding curve."
    - "Sudoswap v2 (Cyfrin 2023) — rounding direction inconsistente en buy vs sell permitía extracción sistemática de valor en curvas."
```

---

## 2. LBP (Liquidity Bootstrapping Pool) Manipulation

```yaml
- id: launch-002
  titulo: Manipulación de pesos en LBP — compra coordinada al inicio o retraso del weight shift
  causa_raiz: |
    Los LBP (Balancer) usan pesos que cambian linealmente en el tiempo: empiezan con peso alto
    del token de proyecto (e.g., 96:4) y terminan con peso bajo (e.g., 50:50). Esto crea una
    dutch auction donde el precio baja naturalmente. Si los pesos se manipulan (cambio de
    parámetros mid-auction) o si compradores coordinados compran masivamente al inicio cuando
    el precio es artificialmente alto, la dinámica de "fair price discovery" se rompe.
    Adicionalmente, el owner del LBP puede pausar los swaps, cambiar pesos, o retirar liquidez.
  como_funciona: |
    Escenario 1 — Weight manipulation:
    1. Owner crea LBP con pesos 96:4 (token:ETH), swap habilitado.
    2. Precio inicial alto, poca gente compra, precio baja gradualmente.
    3. A mitad del LBP, owner llama updateWeightsGradually() para revertir los pesos.
    4. Precio sube artificialmente → compradores tempranos sufren dilución.

    Escenario 2 — Coordinated front-loading:
    1. LBP arranca con precio alto (diseño intencional para disuadir snipers).
    2. Grupo coordinado (o bot) compra agresivamente en los primeros bloques.
    3. El precio natural de descenso se anula por la demanda artificial.
    4. Compradores posteriores pagan precios inflados → el grupo vende post-LBP.
  invariante: |
    // Los pesos solo deben cambiar en la dirección programada (descendente para el token)
    // NUNCA incrementar el peso del token una vez que el LBP ha iniciado
    assert(newTokenWeight <= currentTokenWeight);
    // No se puede pausar swaps durante el periodo activo del LBP
    assert(!swapsPaused || block.timestamp > lbpEndTime);
  que_mirar:
    - Función updateWeightsGradually() callable por owner durante el LBP activo
    - setSwapEnabled() que permite pausar y reanudar arbitrariamente
    - exitPool() disponible para el owner durante el LBP (puede retirar liquidez unilateral)
    - Ausencia de timelock en cambios de parámetros del LBP
    - LBP en Copper Launch / Fjord: verificar si el contrato wrapper tiene restricciones adicionales
  como_se_arregla: |
    Usar contratos wrapper (como Copper Launch) que bloquean:
    - Cambio de pesos después del inicio
    - Retiro de liquidez durante el LBP
    - Pausa de swaps durante el periodo activo
    Implementar timelock para cualquier cambio de parámetros.
    Idealmente: el contrato del LBP debería ser immutable después del deploy.
  trampas:
    - Balancer V2 LBP permite al controller hacer casi cualquier cosa — la seguridad depende
      del WRAPPER, no del pool base. Auditar el wrapper (Copper, Fjord), no solo el pool.
    - El "fair price discovery" asume participantes racionales distribuidos en el tiempo.
      En la práctica, bots y whales dominan los primeros bloques.
    - Algunos LBP legítimos SÍ necesitan pausar swaps (para agregar más liquidez). La pausa
      per se no es maliciosa — el contexto importa.
  solodit_ids:
    - "front-running-attacks-on-finalize-could-affect-received-token-amounts-spearbit-gnosis-pdf"
    - "overpayment-of-one-side-of-lp-pair-onjoinpool-due-to-sandwich-or-user-error-spearbit-balancer-pdf"
    - "front-runnable-admin-fee-update-with-no-user-slippage-protection-quantstamp-solv-markdown"
  incidentes:
    - "Balancer V2 (2023) — $128M exploit via rounding errors en invariant calculation de stable pools, no LBP directo pero mismo codebase."
    - "Copper Launch (múltiples) — wrappers con bugs que permitían al owner retirar liquidez antes del fin del LBP. Reportados en foros de Balancer."
    - "Mango Markets (2022) — manipulación de precio de token en launch via trading coordinado, $114M drenados del protocolo."
```

---

## 3. Fair Launch Front-Running (Bot Sniping)

```yaml
- id: launch-003
  titulo: Bots snipean token al momento del launch — compran en bloque 0 antes que humanos
  causa_raiz: |
    Cuando un token nuevo habilita el trading (setTradingEnabled, enableTrading, o simplemente
    se agrega liquidez a un DEX), hay un momento exacto donde el token pasa de no-tradeable a
    tradeable. Bots monitorizan la mempool o los eventos de PairCreated/addLiquidity y envían
    transacciones de compra con gas alto en el mismo bloque. Obtienen tokens al precio más bajo
    posible, y venden cuando el precio sube por demanda orgánica.
  como_funciona: |
    1. Deployer llama addLiquidityETH() en Uniswap → crea el par token/WETH con liquidez inicial.
    2. Bot detecta la tx pendiente en mempool (o monitoriza evento PairCreated).
    3. Bot envía buy tx con gas extremadamente alto → ejecuta en el mismo bloque, justo después
       del addLiquidity.
    4. Bot obtiene tokens a precio de lanzamiento (mínimo posible).
    5. Compras orgánicas de la comunidad suben el precio 5-50x en minutos.
    6. Bot vende → profit inmediato de 5-50x en minutos.
    Variante: bot detecta enableTrading() tx en mempool y compra en el mismo bloque.
  invariante: |
    // Anti-snipe: no permitir compras en el mismo bloque que el addLiquidity
    // O limitar el tamaño de compra en los primeros N bloques
    require(block.number > launchBlock + SNIPE_PROTECTION_BLOCKS, "Too early");
    // Alternativa: fee alto en los primeros bloques (e.g., 99% fee → decae a normal en 30 min)
    uint256 fee = block.timestamp < launchTime + DECAY_PERIOD
        ? MAX_FEE - (MAX_FEE - NORMAL_FEE) * (block.timestamp - launchTime) / DECAY_PERIOD
        : NORMAL_FEE;
  que_mirar:
    - Token con enableTrading() o setTradingEnabled() que es una simple flag booleana
    - addLiquidity + enableTrading en transacciones separadas (gap de snipe entre ambas)
    - Ausencia de fee decay o max tx amount en los primeros bloques post-launch
    - Tokens que dependen solo de "launch time" pero el tiempo es público
    - Meteora/pump.fun copycats: swap rate limiter bypass (C4 Meteora audit 2025 — M-01)
  como_se_arregla: |
    Estrategia multi-capa:
    1. addLiquidity + enableTrading en UNA SOLA transacción (atómica)
    2. Fee decay: 99% fee decayendo a normal en 30-60 minutos
    3. Max transaction amount en los primeros N bloques
    4. Whitelist temporal para compradores iniciales (solo si es un fair launch controlado)
    5. Anti-snipe block delay: no permitir compras en launchBlock + 1
    6. Commit-reveal: compradores comprometen su compra antes, ejecutan después del launch
  trampas:
    - Muchos anti-bot mechanisms son bypasseables (ver launch-011). No confiar ciegamente.
    - El "fee decay" puede ser griefed si el atacante espera los 30 min y luego compra grande.
    - En L2 con sequencer, el sniping es más difícil pero no imposible (sequencer MEV).
    - Algunos protocolos hacen addLiquidity con un timelock → esto GARANTIZA que bots snipen.
  solodit_ids:
    - "mnbd1-5-early-pair-creation-breaks-fair-launch-of-new-moon-tokens-and-gives-an-attacker-the-possibility-to-steal-all-kas-from-bondingcurvepool-hexens-none-moonbound-markdown"
    - "c-02-the-deadline-parameter-in-uniswapv3-swap-causes-sniping-functionality-failure-in-code4rena-none-markdown"
    - "m-04-launched-tokens-are-vulnerable-to-flashloan-attacks-forcing-premature-graduation-allowing-reward-manipulation-code4rena-virtuals-protocol-virtuals-protocol-git"
  incidentes:
    - "Moonbound/Hexens — Early pair creation breaks fair launch, atacante roba todos los KAS del BondingCurvePool."
    - "Meteora DBC (C4 2025) — Swap rate limiter (anti-sniping) bypasseable via instrucción swap2."
    - "Virtuals Protocol (C4) — Flash loan attack fuerza graduation prematura, manipula rewards."
```

---

## 4. Initial Liquidity Manipulation (First Depositor Attack)

```yaml
- id: launch-004
  titulo: Primer proveedor de liquidez fija precio injusto — share inflation o ratio manipulado
  causa_raiz: |
    Cuando se crea un par en un DEX (Uniswap V2/V3, PancakeSwap), el primer LP define el
    ratio de precio entre los tokens. Si un atacante es el primer LP, puede depositar un ratio
    desequilibrado (1 wei de token A + 1000 ETH de token B) para establecer un precio
    artificialmente bajo/alto. En bonding curves con pool de liquidez, la primera compra o
    el primer depósito define el exchange rate inicial.
    Variante ERC-4626: primer depositor dona tokens para inflar el share price (inflation attack).
  como_funciona: |
    Escenario DEX:
    1. Token nuevo sin liquidez. Atacante es el primer LP.
    2. Atacante deposita ratio desequilibrado: 1 token + 10 ETH → precio = 10 ETH/token.
    3. Si el precio justo es 0.01 ETH/token, compradores que usan el pool pagan 1000x más.
    4. Atacante vende sus tokens a precio inflado → profit masivo.

    Escenario Bonding Curve con migración a DEX:
    1. Bonding curve alcanza graduation threshold.
    2. Función de migración crea pool en DEX con ratio calculado del balance de la curve.
    3. Si atacante manipuló el balance de la curve (via donation, ver launch-013), el ratio
       del pool es incorrecto → arbitraje inmediato.
  invariante: |
    // Precio inicial debe estar dentro de bounds razonables
    uint256 priceRatio = reserveA * 1e18 / reserveB;
    assert(priceRatio >= MIN_INITIAL_PRICE && priceRatio <= MAX_INITIAL_PRICE);
    // Primera liquidez debe superar un mínimo para evitar share inflation
    assert(initialLiquidity >= MINIMUM_LIQUIDITY);
  que_mirar:
    - createPool o addLiquidity sin validación de ratio mínimo/máximo
    - Ausencia de MINIMUM_LIQUIDITY quemado al primer LP (Uniswap V2 quema 1000 shares)
    - Función de migración de bonding curve a DEX que no valida el ratio
    - Pool creation permissionless donde cualquiera puede ser primer LP
    - ERC-4626 vaults sin dead shares o virtual offset
  como_se_arregla: |
    Para pools: quemar MINIMUM_LIQUIDITY (como Uniswap V2, 1000 shares a address(0)).
    Para vaults: usar virtual offset (OpenZeppelin ERC4626 con _decimalsOffset()).
    Para bonding curves con migración: el ratio del pool debe derivarse de la curva,
    no del balance actual (que puede ser manipulado por donations).
    Validar que el precio inicial está dentro de un rango razonable.
  trampas:
    - El MINIMUM_LIQUIDITY de Uniswap V2 (1000 shares) NO es suficiente si los tokens tienen
      pocos decimales o alto valor unitario. Para tokens con 6 decimales, 1000 shares = $0.001.
    - La inflation attack en ERC-4626 es un patrón conocido pero sigue apareciendo en audits
      porque los devs olvidan el offset virtual o usan una implementación custom.
    - En Uniswap V3, no hay MINIMUM_LIQUIDITY — la protección depende del rango de precios
      y la liquidez concentrada. El primer LP tiene más control sobre el precio.
  solodit_ids:
    - "h-1-first-depositor-can-abuse-exchange-rate-to-steal-funds-from-later-depositors-sherlock-surge-surge-git"
    - "m-02-first-liquidity-provider-will-suffer-from-revert-or-fund-loss-code4rena-numoen-numoen-git"
    - "c-03-blocking-the-initial-liquidity-seed-with-a-1-wei-donation-pashov-audit-group-none-markdown"
    - "front-running-pools-initialization-or-initial-deposit-can-lead-to-draining-initial-liquidity-mixbytes-none-markdown"
  incidentes:
    - "Surge (Sherlock) — Primer depositor abusa exchange rate para robar fondos de depositors posteriores."
    - "Numoen (C4) — Primer LP sufre revert o pérdida de fondos por cálculos de liquidez sin protección."
    - "Pashov Group — Donación de 1 wei bloquea el seed de liquidez inicial, DoS del pool."
```

---

## 5. Bonding Curve Math Overflow/Underflow

```yaml
- id: launch-005
  titulo: Overflow/underflow en cálculos de curvas exponenciales, cuadráticas o bancor
  causa_raiz: |
    Las bonding curves usan fórmulas matemáticas que involucran exponenciación (n^2, n^3),
    logaritmos (bancor: log/exp), o funciones sigmoides. En Solidity, estas operaciones pueden
    causar overflow (pre-0.8.0 sin SafeMath) o revert inesperado (post-0.8.0 con checked math).
    Valores extremos de supply (muy grande o muy pequeño), reserveRatio, o parámetros de curva
    pueden llevar a: precio = 0 (underflow/truncación), precio = MAX_UINT (overflow),
    o revert que bloquea compras/ventas.
  como_funciona: |
    Ejemplo 1 — Curva cuadrática overflow:
    1. Curva: price = supply^2 / divisor.
    2. supply llega a ~2^128 → supply^2 > 2^256 → overflow → revert (0.8+) o wrap-around (0.7-).
    3. Con wrap-around: precio calculado es ~0 → compra masiva por casi nada.

    Ejemplo 2 — Bancor formula precision loss:
    1. BancorFormula usa potencias fraccionarias: return = supply * ((1 + deposit/reserve)^(ratio/1e6) - 1).
    2. Para reserveRatio muy bajo (<1%) o muy alto (>99%), la función pierde precisión.
    3. Resultado: compras devuelven más tokens de los que deberían → reserve se drena.

    Ejemplo 3 — Invariant check con rent (Solana):
    1. Bonding curve valida balance == expected. Pero el balance incluye rent (Solana).
    2. Invariant check falla o pasa incorrectamente según el rent exempt minimum.
  invariante: |
    // Los parámetros de la curva deben producir precios en un rango válido
    uint256 price = calculatePrice(supply);
    assert(price > 0 && price < MAX_REASONABLE_PRICE);
    // Reserve ratio dentro de bounds
    assert(reserveRatio >= MIN_RESERVE_RATIO && reserveRatio <= MAX_RESERVE_RATIO);
    // Compra y venta son operaciones inversas (conservación):
    uint256 tokensBought = buy(ethAmount);
    uint256 ethReturned = sell(tokensBought);
    assert(ethReturned <= ethAmount); // Nunca se puede extraer más de lo depositado
  que_mirar:
    - Funciones con exponenciación sin bounds checking (supply ** exponent)
    - Uso de ABDKMathQuad o PRBMath sin verificar rangos de input
    - Divisiones donde el denominador puede ser 0 (supply = 0, reserve = 0)
    - Curvas tipo bancor con reserveRatio configurable por owner
    - Solana: validación de balance que incluye rent en el cálculo
  como_se_arregla: |
    Bounds checking estricto en todos los inputs de la curva.
    Usar bibliotecas math probadas (ABDKMathQuad, PRBMath) con wrappers que validen rangos.
    Invariant: buy(sell(amount)) <= amount para todo amount válido.
    Para Solana: restar rent del balance antes de validar el invariant de la curva.
    Tests de fuzzing con valores extremos: 0, 1, type(uint256).max, supply cerca de overflow.
  trampas:
    - Solidity 0.8+ revierte en overflow en vez de wrap-around. Esto previene explotación
      directa pero puede causar DoS (nadie puede comprar/vender si el cálculo revierte).
    - Las bibliotecas math "seguras" pueden tener sus propios edge cases. PRBMath tiene
      límites documentados que no siempre se respetan en integraciones.
    - El invariant buy(sell(x)) <= x puede fallar por 1-2 wei de rounding y eso es OK.
      Lo grave es si falla por cantidades significativas.
  solodit_ids:
    - "potential-overflows-in-bondingcurve-sigmaprime-none-angle-pdf"
    - "unbounded-curve-parameter-can-lead-to-overflow-quantstamp-vaporware-markdown"
    - "m-02-bonding-curve-invariant-check-incorrectly-validates-sol-balance-due-to-rent-inclusion-code4rena-pump-science-pump-science-git"
    - "m-01-bonding-curve-check-stepsize-numsteps-may-not-match-curvesupply-kann-none-wild-protocol-markdown"
  incidentes:
    - "Angle Protocol (SigmaPrime) — Overflows potenciales en BondingCurve por inputs sin bound."
    - "Pump Science (C4 2025) — Invariant check de bonding curve falla porque el balance SOL incluye rent."
    - "Wild Protocol (Kann) — stepSize * numSteps no matchea curveSupply, error de configuración explotable."
```

---

## 6. Token Vesting Cliff Bypass at Launch

```yaml
- id: launch-006
  titulo: Tokens del team/investors desbloqueados antes del cliff — bypass de vesting schedule
  causa_raiz: |
    Los contratos de vesting tienen un cliff period (e.g., 6 meses) donde no se pueden reclamar
    tokens. Si el contrato tiene un bug en el cálculo del cliff, o si hay una función que
    permite transferir tokens vestidos antes del cliff (staking, wrapping, delegation), los
    insiders pueden vender antes de lo prometido. Esto causa dump de precio y pérdida para
    compradores del launch que confiaron en el vesting schedule.
  como_funciona: |
    Escenario 1 — Cliff bypass via staking:
    1. Team tiene 10M tokens con cliff de 6 meses.
    2. Contrato de vesting permite stakear tokens vestidos (sin verificar cliff).
    3. Team stakea → recibe stToken → vende stToken en mercado secundario.
    4. Efecto: dump inmediato, cliff bypassed.

    Escenario 2 — Initialization bypass:
    1. Vesting contract tiene función initialize() que setea startTime.
    2. Si initialize() se puede llamar antes del TGE con startTime en el pasado:
    3. El cliff ya "pasó" al momento del TGE → tokens reclamables inmediatamente.

    Escenario 3 — Split before cliff:
    1. GovNFT con vesting: se puede hacer split() antes del cliff.
    2. Split altera el vesting schedule del parent lock adversamente.
    3. Resultado: parte de los tokens se desbloquean antes del cliff original.
  invariante: |
    // Tokens reclamados antes del cliff deben ser 0
    if (block.timestamp < startTime + cliffDuration) {
        assert(claimableAmount(beneficiary) == 0);
    }
    // Total reclamado nunca excede total asignado
    assert(totalClaimed[beneficiary] <= totalAllocation[beneficiary]);
    // No se puede transferir/stakear tokens durante el cliff period
  que_mirar:
    - Función claim() que no verifica block.timestamp >= startTime + cliff
    - Tokens vestidos que se pueden stakear/wrap/delegate sin restricción temporal
    - initialize() callable múltiples veces o con startTime arbitrario
    - Función de split/merge que altera el vesting schedule original
    - Revoke que calcula incorrectamente los tokens ya vestidos vs no vestidos
  como_se_arregla: |
    Verificar cliff en TODAS las funciones que mueven tokens vestidos (claim, stake, transfer,
    split, merge, delegate). El cliff check debe ser un modifier reutilizado.
    startTime debe setearse en el constructor o en una función one-shot con validación.
    Para tokens transferibles durante vesting: la restricción de cliff debe aplicarse al
    token derivado también (stToken, wrapper).
  trampas:
    - Un vesting "con cliff" que permite staking durante el cliff es equivalente a no tener cliff.
    - El revoke de vesting (para empleados que dejan la empresa) debe calcular correctamente
      los tokens ya vestidos linealmente. Error común: revocar devuelve TODOS los tokens sin descontar
      los linealmente vestidos post-cliff.
    - Algunos protocolos deliberadamente permiten delegation durante cliff (gobernanza).
      Esto no es un bug si delegation no implica transferencia de valor.
  solodit_ids:
    - "l-02-users-can-bypass-vesting-during-initialization-shieldify-none-spellborne-s2airdrop-markdown"
    - "m-14-lockup-of-vestings-or-completion-time-can-be-bypassed-due-to-missing-check-for-staked-tokens-sherlock-andromeda-validator-staking-ado-and-vesting-ado-git"
    - "vesting-validation-bypass-ottersec-none-polkastarter-pdf"
    - "parentlock-that-does-a-split-before-its-cliff-adversely-alters-its-vesting-schedule-cantina-none-govnft-pdf"
  incidentes:
    - "Spellborne S2 Airdrop (Shieldify) — Bypass de vesting durante initialization, tokens reclamables inmediatamente."
    - "Andromeda (Sherlock) — Lockup de vesting bypasseable via staking de tokens vestidos sin check temporal."
    - "Polkastarter (OtterSec) — Vesting validation bypass permite reclamar antes del schedule."
    - "GovNFT (Cantina) — Split antes del cliff altera adversamente el vesting schedule del parent lock."
```

---

## 7. Presale/Whitelist Bypass

```yaml
- id: launch-007
  titulo: Compra pública durante presale — bypass de whitelist via llamada directa al contrato
  causa_raiz: |
    Muchos token launches tienen fases: whitelist/presale → public sale. La restricción de
    whitelist se implementa en el frontend (UI) o con un check débil en el smart contract
    que puede ser bypaseado. Si el contrato no valida la whitelist on-chain de forma robusta,
    cualquiera puede llamar la función de compra directamente y obtener el precio de presale.
    También: whitelisted users pueden ser DoS-eados por atacantes que front-run o llenan el cap.
  como_funciona: |
    Escenario 1 — Frontend-only whitelist:
    1. Presale a 0.01 ETH/token, public sale a 0.05 ETH/token.
    2. Whitelist check solo existe en el frontend (la UI verifica y muestra el botón).
    3. Atacante llama buyPresale() directamente via etherscan/cast → compra a precio de presale.

    Escenario 2 — Whitelist DoS:
    1. Presale tiene maxPerAddress pero no maxTotal, o maxTotal > sum(maxPerAddress).
    2. Atacante genera múltiples wallets, obtiene whitelist spots (via bots en Discord, etc).
    3. Compra todo el presale allocation → usuarios legítimos no pueden comprar.

    Escenario 3 — Merkle proof manipulation:
    1. Whitelist usa Merkle tree con leaves = address solo (sin amount).
    2. Whitelisted user puede comprar cantidad ilimitada (el leaf no limita amount).
    3. Un solo whitelisted user compra todo el allocation.
  invariante: |
    // Solo whitelisted addresses pueden comprar durante presale
    if (block.timestamp < publicSaleStart) {
        assert(isWhitelisted[msg.sender] || MerkleProof.verify(proof, root, leaf));
    }
    // Cada whitelisted address tiene un cap máximo
    assert(purchased[msg.sender] + amount <= maxPerWhitelistedAddress);
    // Total presale no excede allocation
    assert(totalPresaleSold + amount <= presaleAllocation);
  que_mirar:
    - Función de compra sin modifier que verifique whitelist on-chain
    - Merkle tree con leaves que no incluyen el amount máximo por address
    - presale phase determinada por una variable que el owner puede cambiar en cualquier momento
    - Ausencia de cap por address Y cap total en la presale
    - Contratos proxy donde la whitelist se almacena en un contrato externo que puede ser cambiado
  como_se_arregla: |
    Whitelist SIEMPRE on-chain: Merkle proof con leaf = keccak256(abi.encodePacked(address, maxAmount)).
    Cap por address Y cap total, ambos enforced en el contrato.
    Fase de venta determinada por timestamps immutables, no por flags del owner.
    Si se usa un contrato externo para whitelist, debe ser immutable post-deploy.
  trampas:
    - Los Merkle trees con solo address como leaf son un anti-pattern conocido pero muy común.
    - "Whitelist" en muchos protocolos es solo un mapping(address => bool) sin cap — permite
      1 compra pero de tamaño ilimitado.
    - En Solana (Metaplex Candy Machine), la whitelist es un SPL token que puede ser transferido,
      lo que permite un mercado secundario de whitelist spots.
  solodit_ids:
    - "h-01-whitelisted-accounts-can-be-forcefully-dosed-from-buying-curvetokens-during-the-presale-code4rena-curves-protocol-curves-protocol-git"
    - "m-01-presale-buyers-can-block-other-whitelisted-buyers-from-purchases-pashov-audit-group-none-cardex_2025-01-21-markdown"
    - "locker-whitelist-bypass-ottersec-none-tribeca-pdf"
    - "compromised-operator-can-bypass-enforced-whitelist-to-deposit-in-funding-phase-spearbit-none-kinetiq-lst-protocol-pdf"
  incidentes:
    - "Curves Protocol (C4) — Whitelisted accounts DoS-eados forzosamente durante presale, no pueden comprar curveTokens."
    - "Cardex (Pashov 2025) — Presale buyers pueden bloquear a otros whitelisted compradores de sus purchases."
    - "Tribeca (OtterSec) — Whitelist bypass en locker permite acceso no autorizado."
```

---

## 8. Launch Pool Rug Pull Patterns

```yaml
- id: launch-008
  titulo: Rug pull via funciones admin — removeLiquidity, mint ilimitado, blacklist de sellers
  causa_raiz: |
    Tokens de launch con contratos que mantienen funciones admin peligrosas: el owner puede
    retirar la liquidez del DEX, mintear tokens ilimitados para dumping, o blacklistear
    addresses para prevenir ventas. Estas funciones pueden estar ocultas (código no verificado),
    ofuscadas, o ser funciones "de emergencia" que se usan maliciosamente.
  como_funciona: |
    Patrón 1 — Liquidity removal:
    1. Deployer crea token, agrega liquidez a Uniswap, comunidad compra.
    2. Deployer llama removeLiquidity() → extrae todo el ETH del pool.
    3. Token queda sin liquidez → precio = 0, compradores pierden todo.

    Patrón 2 — Unlimited mint:
    1. Token tiene función mint() solo accesible por owner.
    2. Owner mintea 10x la supply y vende en el pool → precio colapsa.

    Patrón 3 — Blacklist sellers:
    1. Token override de _beforeTokenTransfer verifica un blacklist mapping.
    2. Owner agrega a todos los holders al blacklist → nadie puede vender.
    3. Solo el owner puede vender → extrae toda la liquidez.

    Patrón 4 — Fee manipulation:
    1. Token tiene setFee() que el owner puede cambiar.
    2. Owner pone fee de venta al 99% → solo 1% llega al seller.
    3. Equivalente a un soft rug: no se puede vender, pero el contrato "funciona".
  invariante: |
    // Liquidity tokens del pool deben estar lockeados o quemados
    assert(lpToken.balanceOf(deployer) == 0 || lpLockContract.isLocked(deployer));
    // No existe función mint() pública o está renounced
    assert(owner() == address(0) || !hasMintFunction);
    // Fee de transacción tiene un máximo immutable
    assert(sellFee <= MAX_SELL_FEE); // MAX_SELL_FEE definido como constante, no variable
    // Blacklist no puede ser modificada post-launch (o no existe)
  que_mirar:
    - owner() != address(0) — ownership no renounced
    - Funciones mint(), mintTo(), emergencyMint() accesibles por owner
    - _beforeTokenTransfer con blacklist/whitelist check
    - setFee(), updateFee() sin cap máximo immutable
    - LP tokens en wallet del deployer (no lockeados en contrato de lock)
    - approve(router, MAX) en el constructor (pre-aprueba ventas masivas)
    - Código no verificado en explorer (red flag mayor)
    - Funciones con nombres inocuos que hacen cosas maliciosas (e.g., "updateMarketing" que mintea)
  como_se_arregla: |
    Para proyectos legítimos:
    - Renounce ownership post-launch
    - Lock LP tokens por mínimo 6-12 meses via contrato verificado (Team.finance, Unicrypt)
    - Fees definidos como constants o con cap immutable
    - Sin función mint post-TGE
    - Sin blacklist (o blacklist solo para compliance, timelocked)
    - Código verificado y audited antes del launch
  trampas:
    - "Ownership renounced" no es suficiente si hay un backdoor via proxy (owner del proxy
      puede cambiar la implementación). Verificar que NO es un proxy.
    - LP lock de 30 días es inútil — el rugger espera 30 días. Mínimo 6 meses.
    - Código verificado en Etherscan puede diferir del código deployado si el deployer usó
      metadata manipulation (verificar bytecode hash).
    - Algunas funciones maliciosas se ocultan en librerías importadas o contracts heredados.
  solodit_ids:
    - "m-03-governor-can-rug-pull-the-escrow-code4rena-the-graph-the-graph-l2-bridge-contest-git"
    - "m-06-centralisation-risk-admin-role-of-tokenmanagereth-can-rug-pull-all-eth-from-code4rena-axelar-axelar-git"
    - "c-02-lack-of-lastmintedperiod-update-allows-unlimited-minting-of-kitten-pashov-audit-group-none-kittenswap_2025-06-12-markdown_"
  incidentes:
    - "SQUID token (2021) — $3.4M rug pull. Contrato tenía función que impedía a holders vender (solo owner podía)."
    - "KittenSwap (Pashov 2025) — Falta de update de lastMintedPeriod permite minting ilimitado de tokens."
    - "The Graph L2 Bridge (C4) — Governor puede rug pull el escrow del bridge."
```

---

## 9. Dutch Auction NFT Mint Manipulation

```yaml
- id: launch-009
  titulo: Dutch auction para NFT mint — timing de bid, refund accounting, DoS del claim
  causa_raiz: |
    Las dutch auctions para NFT mints bajan el precio con el tiempo hasta que se vende todo
    o se llega al precio de reserva. Los participants que pagaron más que el precio final
    reciben refund de la diferencia. Errores comunes: refund accounting incorrecto (no devolver
    el exceso), DoS del mecanismo de claim (contrato que revierte en receive()), y bloqueo
    de fondos si la auction no se completa exactamente.
  como_funciona: |
    Escenario 1 — AkuDreams $34M locked:
    1. Dutch auction con counter de bids. Contrato requiere N bids mínimos antes de permitir withdraw.
    2. Algunos compradores hacen múltiples NFTs en un solo bid → counter no llega a N.
    3. Condición de withdraw nunca se cumple → $34M (11,539 ETH) bloqueados PERMANENTEMENTE.

    Escenario 2 — Refund DoS:
    1. Dutch auction termina, precio final = 1 ETH. Bidder pagó 3 ETH → refund de 2 ETH.
    2. Bidder es un contrato que revierte en receive() (DoS deliberado).
    3. Si refund usa push pattern (envía ETH directamente), toda la función se revierte.
    4. Nadie puede reclamar refunds si UN bidder es malicioso.

    Escenario 3 — finalPrice manipulation:
    1. Auction no vende todo. Owner setea finalPrice manualmente.
    2. Owner pone finalPrice alto → refunds bajos → compradores perjudicados.
    3. O: selfRefundsStartTime se setea antes de que termine la auction → full refund posible.
  invariante: |
    // Refund = pagado - finalPrice, para cada bidder
    uint256 refund = bidAmount[bidder] - finalPrice * quantity[bidder];
    assert(refund >= 0);
    // Total refunds + total retained == total collected
    assert(totalRefunds + totalRetained == totalCollected);
    // Withdraw del owner solo posible cuando auction terminó completamente
    assert(auctionComplete || block.timestamp > auctionEndTime);
  que_mirar:
    - Función withdraw() con condición basada en counter de bids (no de NFTs minteados)
    - Refund usando push pattern (address.transfer/send) sin pull pattern alternativo
    - setFinalPrice() callable por owner sin restricciones
    - Condición de "auction complete" que depende de igualdad exacta (==) en vez de (>=)
    - selfRefundsStartTime configurable antes del fin de la auction
    - Loop de refund sin límite de gas (unbounded iteration)
  como_se_arregla: |
    Usar PULL pattern para refunds: cada bidder llama claimRefund() individualmente.
    Condición de withdraw basada en bloque/timestamp, no en counter de participantes.
    finalPrice calculado automáticamente (última bid aceptada), no manualmente por owner.
    Bounds checking: require(finalPrice >= reservePrice && finalPrice <= startPrice).
    Gas-bounded loops o batch processing para refunds masivos.
  trampas:
    - El caso AkuDreams es un ejemplo extremo: el contrato era fundamentalmente broken.
      En audits reales, los bugs son más sutiles (rounding en refunds, off-by-one en timing).
    - La dutch auction de Azuki funcionó correctamente pero tuvo FUD de "insider buying" que
      no era un bug técnico sino social engineering. No confundir.
    - En NFT mints, la mayoría de los bugs son en el refund mechanism, no en la auction logic.
  solodit_ids:
    - "lack-of-monotonicity-enforcement-in-dutch-auction-rate-bumps-quantstamp-1inch-fusion-markdown"
    - "dutch-auctions-can-be-used-to-drain-honest-buyers-escrowed-funds-from-the-market-cantina-none-kim-exchange-pdf"
    - "denial-of-service-allows-blocking-operations-during-dutch-auctions-trailofbits-none-reserve-protocol-solidity-400-pdf"
  incidentes:
    - "AkuDreams (2022) — $34M (11,539 ETH) bloqueados permanentemente. Bug en counter de bids + bad increment math. Dos bugs separados, ambos críticos."
    - "1inch Fusion (Quantstamp) — Falta de enforcement de monotonicity en rate bumps de dutch auction."
    - "Kim Exchange (Cantina) — Dutch auctions usadas para drenar fondos escrowed de compradores honestos."
    - "Reserve Protocol (Trail of Bits) — DoS blocking operations durante dutch auctions."
```

---

## 10. Bonding Curve Reserve Ratio Manipulation

```yaml
- id: launch-010
  titulo: Cambio de parámetros de la curva mid-operación — reserve ratio, slope, exponent
  causa_raiz: |
    Si los parámetros que definen la forma de la bonding curve (reserve ratio en bancor,
    exponent en curvas polinomiales, slope/intercept en lineales) son modificables por el owner
    después del deploy, el owner puede cambiarlos para beneficiarse. Cambiar el reserve ratio
    altera instantáneamente el precio de compra/venta para todos los holders, sin que estos
    hayan consentido el cambio.
  como_funciona: |
    1. Bonding curve tipo bancor con reserveRatio = 50% (curva "normal").
    2. Usuarios compran tokens, reserva crece proporcionalmente.
    3. Owner cambia reserveRatio a 5% → la curva se vuelve exponencialmente más empinada.
    4. Efecto: los tokens existentes ahora "valen" mucho más en la curva, pero si todos
       intentan vender, la reserva no alcanza (porque no creció al 5%, sino al 50%).
    5. Últimos vendedores no pueden vender → bank run, loss of funds.

    Variante: owner cambia stepSize o numSteps en una curva escalonada → mismatch con supply.
  invariante: |
    // Parámetros de la curva son immutables post-deploy
    assert(reserveRatio == INITIAL_RESERVE_RATIO); // set in constructor, never changed
    assert(curveExponent == INITIAL_EXPONENT);
    // Si los parámetros son modificables, debe haber timelock
    assert(paramChangeTimestamp + TIMELOCK_DURATION <= block.timestamp);
    // Reserve ratio dentro de bounds
    assert(reserveRatio >= 1e4 && reserveRatio <= 1e6); // 1% to 100%
  que_mirar:
    - Funciones setReserveRatio(), setCurveParams(), updateSlope() sin timelock
    - Parámetros de curva como variables de storage (no constants/immutables)
    - Validación de rango en reserve ratio (puede ser 0? puede ser >100%?)
    - Efecto de cambio de parámetros en holders existentes (¿se recalculan precios?)
    - Operación atómica: ¿se pueden cambiar los params y comprar/vender en la misma tx?
  como_se_arregla: |
    Hacer parámetros immutable/constant en el constructor.
    Si necesitan ser modificables: timelock mínimo de 48h + evento emitido al proponer cambio.
    Validación de rango estricta (no permitir valores extremos que rompan la curva math).
    Snapshot del precio pre-cambio para proteger a holders existentes.
  trampas:
    - En DAOs, el governance puede votar para cambiar parámetros — esto es legítimo si hay
      timelock y los holders pueden salir antes del cambio. No es un bug per se.
    - Reserve ratio = 100% es una curva lineal (precio constante). Reserve ratio = 0%
      significaría que no hay reserva. Ambos extremos pueden ser problemáticos.
    - Algunos protocolos usan "upgrade pattern" donde cambian la implementación de la curva
      via proxy. El cambio de params es indirecto pero igual de peligroso.
  solodit_ids:
    - "reserve-ratio-cast-can-wrap-bands-spearbit-none-buck-labs-smart-contracts-pdf"
    - "incorrect-logical-operator-in-reserve-ratio-validation-allows-out-of-range-ratios-trailofbits-none-swap-coffee-ton-dex-pdf"
    - "02-calclptokensupply-cant-converge-for-large-reserve-ratios-or-very-small-reserves-code4rena-basin-basin-git"
  incidentes:
    - "Buck Labs (Spearbit) — Reserve ratio cast puede wrap bands, overflow silencioso."
    - "Swap.Coffee TON DEX (Trail of Bits) — Operador lógico incorrecto en validación de reserve ratio permite ratios fuera de rango."
    - "Basin (C4) — calcLpTokenSupply no converge para reserve ratios extremos, DoS del pool."
```

---

## 11. Anti-Bot Mechanism Bypass

```yaml
- id: launch-011
  titulo: Mecanismos anti-bot (maxTx, cooldown, blacklist) todos bypasseables por contratos
  causa_raiz: |
    Los tokens de launch implementan "protecciones" anti-bot que son fundamentalmente débiles:
    maxTransactionAmount (bypasseable con múltiples txs), cooldown por address (bypasseable con
    múltiples wallets/contratos), tx.origin == msg.sender check (bypasseable en ciertos
    contextos), y blacklists (reactivas, no preventivas). Estos mecanismos dan falsa sensación
    de seguridad mientras los bots sofisticados los evaden trivialmente.
  como_funciona: |
    Bypass de maxTransactionAmount:
    1. Token tiene maxTx = 1% of supply. Bot quiere comprar 10%.
    2. Bot despliega 10 contratos, cada uno compra 1% → total 10%. maxTx bypassed.

    Bypass de cooldown:
    1. Token tiene cooldown de 30 seg entre compras por address.
    2. Bot crea nueva wallet para cada compra. Costo: ~0.001 ETH de gas por wallet.

    Bypass de tx.origin check:
    1. Token verifica require(tx.origin == msg.sender) para "asegurar" que no es un contrato.
    2. Bot opera desde una EOA directamente (no desde contrato) → bypass trivial.
    3. Además: el check rompe composabilidad con contratos legítimos (multisig, AA wallets).

    Bypass de block-based limits:
    1. Token no permite más de 1 compra por bloque por address.
    2. Bot usa múltiples addresses en el mismo bloque → cada una compra una vez.
  invariante: |
    // Estos "invariantes" son débiles por diseño — documentar la debilidad:
    // maxTx solo limita POR TRANSACCIÓN, no por entidad. Cualquiera con múltiples wallets lo bypasea.
    // Invariante real: no se puede prevenir sybil on-chain sin identity verification.
    // Lo mejor que se puede hacer: fee decay que hace el sniping no-rentable
    uint256 effectiveFee = getDecayedFee(block.timestamp - launchTime);
    assert(effectiveFee >= MIN_FEE); // Fee siempre positivo, nunca 0 en las primeras horas
  que_mirar:
    - require(tx.origin == msg.sender) — rompe multisig y Account Abstraction
    - maxTransactionAmount sin maxWalletAmount (solo limita tx, no acumulación)
    - Cooldown basado en block.number (1 bloque = 12 seg, inútil contra bots multi-wallet)
    - Blacklist que solo se llena reactivamente (después de que el bot ya compró y vendió)
    - isContract() check que falla en el constructor (code.length == 0 durante constructor)
    - Anti-bot que se desactiva después de N bloques (bot espera N bloques y luego actúa)
    - Meteora swap2 instruction bypass del rate limiter (C4 Meteora DBC 2025)
  como_se_arregla: |
    Aceptar que anti-bot on-chain es un problema fundamentalmente difícil (Sybil resistance).
    Mecanismos más robustos:
    1. Fee decay (99% → normal en 30-60 min): no previene bots pero hace el sniping no-rentable.
    2. Commit-reveal (2 bloques): previene MEV sandwich pero añade fricción UX.
    3. Off-chain: private mempool (Flashbots Protect), sequencer privado (L2).
    4. Para NFT mints: randomized reveal, Dutch auction, allowlist con cap.
    Nunca usar tx.origin — rompe AA y multisig, no es un check de seguridad real.
  trampas:
    - Los protocolos que invierten mucho en anti-bot on-chain suelen tener bugs EN el
      mecanismo anti-bot mismo (overflow en fee calculation, DoS si blacklist es muy grande).
    - Un anti-bot "exitoso" que bloquea contratos también bloquea multisigs, Gnosis Safe,
      Account Abstraction wallets, y exchanges → pérdida de liquidez legítima.
    - El token tax (fee on transfer) puede causar incompatibilidades con DeFi (Uniswap V3
      no soporta fee-on-transfer tokens nativamente).
  solodit_ids:
    - "l-07-attacker-can-dos-token-creation-by-front-running-pashov-audit-group-none-_2025-markdown"
    - "mnbd1-6-an-attacker-can-prevent-the-graduation-of-the-bondingcurvepool-by-front-running-to-sell-a-very-small-amount-of-curve-tokens-hexens-none-moonbound-markdown"
    - "mnbd1-12-insufficient-check-of-approval-delay-in-bondingcurvepool-hexens-none-moonbound-markdown"
  incidentes:
    - "Meteora DBC (C4 2025) — Anti-sniping rate limiter bypasseable via instrucción swap2, permitiendo trades sin restricción."
    - "Moonbound (Hexens) — Múltiples bypasses: front-run de graduation, approval delay insuficiente, donación directa bloquea graduation."
    - "Numerosos tokens ERC-20 — maxTx + cooldown bypassed por bots usando factory contracts que crean wallets desechables."
```

---

## 12. IDO/IFO Allocation Manipulation

```yaml
- id: launch-012
  titulo: Manipulación de allocation en IDO/IFO — oversubscription, flash loan staking, Sybil
  causa_raiz: |
    Los IDO (Initial DEX Offering) e IFO (Initial Farm Offering) asignan tokens basándose en
    el staking previo del usuario (cuántos tokens del protocolo tiene stakeados). Los mecanismos
    de oversubscription devuelven fondos no utilizados. Errores comunes: cálculo incorrecto del
    refund en oversubscription, flash loan para inflar staking temporalmente, y Sybil attack
    para obtener múltiples allocations del tier básico.
  como_funciona: |
    Escenario 1 — Flash loan staking:
    1. IDO asigna allocation basado en balance stakeado al momento del snapshot.
    2. Si el snapshot es en el mismo bloque que la apertura del IDO:
    3. Atacante flash loans tokens → stake → snapshot → compra allocation → unstake → repaga.
    4. Resultado: allocation sin tener capital real stakeado.

    Escenario 2 — Oversubscription refund error:
    1. IFO con oversubscription: si se depositan 10x los tokens disponibles, cada usuario
       recibe 1/10 de su depósito en tokens y 9/10 en refund.
    2. Bug: refund calculado como totalDeposited - allocation * price, pero con rounding error
       que favorece a algunos usuarios → los últimos en reclamar no reciben refund completo.

    Escenario 3 — Late depositor manipulation:
    1. Pool tiene allocation proporcional al depósito. Late depositor ve los depósitos totales.
    2. Late depositor calcula su depósito óptimo para maximizar allocation por ETH gastado.
    3. Si puede depositar en el último bloque, tiene información perfecta → extrae valor.
  invariante: |
    // Total allocations == total tokens disponibles
    assert(totalAllocated <= totalTokensForSale);
    // Total refunds + total tokens sold * price == total deposited
    assert(totalRefunded + totalAllocated * pricePerToken == totalDeposited);
    // Allocation proporcional: cada usuario recibe allocation / totalDeposited * userDeposit
    // Con tolerance de 1 wei por rounding
    uint256 expectedAllocation = userDeposit * totalTokensForSale / totalDeposited;
    assert(abs(userAllocation - expectedAllocation) <= 1);
  que_mirar:
    - Snapshot mechanism: ¿es un bloque específico o "at time of purchase"?
    - Flash loan protection: ¿hay minimum staking duration antes del snapshot?
    - Refund calculation con division y posible truncación
    - Orden de operaciones: ¿se puede depositar, ver el ratio, y retirar en la misma tx?
    - Late deposit advantage: ¿se puede depositar en el último bloque con info completa?
    - Claim function que no marca como claimed → double claim
  como_se_arregla: |
    Snapshot de staking en bloque previo (no en el mismo bloque que la apertura del IDO).
    Minimum staking duration (e.g., 7 días) para evitar flash loan staking.
    Refund calculation con rounding que favorece al protocolo (ceiling para el protocolo).
    Deposit window cerrado antes del cálculo de allocations.
    claim() con check-effect-interaction pattern y mapping claimed[user] = true.
  trampas:
    - "Minimum staking duration" no previene si el atacante stakea 7 días antes con capital
      prestado de otro protocolo (no flash loan, pero same idea con más capital).
    - PancakeSwap IFO tiene un mecanismo de credit points que es más robusto pero complejo.
      No asumir que todos los IFOs tienen la misma implementación.
    - La asignación "por lotería" (vs proporcional) tiene su propio set de problemas
      (randomness manipulation, VRF reliability).
  solodit_ids:
    - "m-08-late-depositors-can-manipulate-share-allocation-to-the-detriment-of-early-investors-shieldify-none-colbfinance-vault-markdown"
    - "m-24-manipulate-allocations-from-game-using-flashloans-sherlock-derby-derby-git"
    - "m-04-launched-tokens-are-vulnerable-to-flashloan-attacks-forcing-premature-graduation-allowing-reward-manipulation-code4rena-virtuals-protocol-virtuals-protocol-git"
  incidentes:
    - "ColbFinance (Shieldify) — Late depositors manipulan share allocation en detrimento de early investors."
    - "Derby (Sherlock) — Flash loans usados para manipular allocations del game."
    - "Virtuals Protocol (C4) — Flash loan attacks fuerzan graduation prematura y manipulan rewards."
```

---

## 13. Pump.fun Style Bonding Curve — Graduation & LP Migration Bugs

```yaml
- id: launch-013
  titulo: Bugs en graduation threshold y migración de LP — donación directa, slippage, front-run
  causa_raiz: |
    Protocolos tipo pump.fun tienen dos fases: (1) bonding curve donde los tokens se compran/venden,
    y (2) graduation donde al alcanzar un threshold de market cap o reserves, la liquidez se
    migra automáticamente a un DEX (Raydium, Uniswap). La migración crea un pool, deposita
    liquidez, y quema o lockea los LP tokens. Bugs en esta transición son críticos porque
    involucran todos los fondos acumulados en la curva.
  como_funciona: |
    Escenario 1 — Donación directa bloquea graduation:
    1. Graduation trigger: require(address(this).balance >= THRESHOLD).
    2. Atacante envía ETH/SOL directamente al contrato (sin pasar por buy()).
    3. El balance supera el threshold pero el token supply no matchea.
    4. Resultado: graduation revierte porque supply != expected para ese balance, o
       graduation ejecuta con ratio incorrecto.

    Escenario 2 — Front-run graduation:
    1. Bonding curve casi llega al threshold. Atacante ve el estado on-chain.
    2. Atacante front-runs la tx de graduation: vende una cantidad tiny de tokens.
    3. El balance cae justo debajo del threshold → graduation falla.
    4. Atacante repite indefinidamente → DoS permanente de la graduation.

    Escenario 3 — Slippage en migración:
    1. Graduation migra fondos de bonding curve a DEX pool.
    2. No hay slippage protection en el addLiquidity de la migración.
    3. Atacante front-runs: crea el pool con ratio desequilibrado antes de la migración.
    4. La migración deposita al ratio manipulado → atacante extrae valor via arbitraje.

    Escenario 4 — migration_token_allocation no actualizado:
    1. Pump Science: Global::update_settings() no actualiza migration_token_allocation.
    2. Valor queda en default → migración usa allocation incorrecta → fondos perdidos o stuck.
  invariante: |
    // Graduation solo cuando balance Y supply son consistentes
    uint256 expectedBalance = calculateReserveForSupply(totalSupply());
    assert(abs(address(this).balance - expectedBalance) <= DUST_THRESHOLD);
    // Post-graduation: toda la liquidez migrada al DEX
    assert(address(this).balance <= DUST_THRESHOLD); // Bonding curve vaciada
    assert(dexPool.totalLiquidity() >= expectedLiquidity);
    // LP tokens quemados o lockeados
    assert(lpToken.balanceOf(address(this)) == 0 || lpToken.balanceOf(lockContract) > 0);
  que_mirar:
    - Graduation trigger basado solo en balance (manipulable con donaciones directas)
    - Ausencia de slippage protection en la migración (addLiquidity sin minAmounts)
    - Front-run de graduation: ¿se puede vender justo antes para hacer revert?
    - migration_token_allocation o parámetros de migración no actualizables
    - Pool creation permissionless: ¿atacante puede crear el pool antes de la migración?
    - LP tokens: ¿se queman? ¿se lockean? ¿quedan en una wallet controlada?
    - Función de migración reentrante (callback durante addLiquidity)
  como_se_arregla: |
    Graduation trigger basado en supply vendido (no en balance del contrato).
    Protección anti-donación: usar variable interna de tracking en vez de address.balance.
    Slippage protection en migración: calcular minAmounts basado en el estado pre-migración.
    Atomic migration: bloquear buys/sells durante la migración (mutex o pausa).
    Pool creation restringida: el contrato de la curva debe ser el único que puede crear el pool.
    LP tokens quemados (sent to address(0)) en la misma tx de migración.
  trampas:
    - En Solana, el rent-exempt balance complica la verificación de balance. El invariant check
      debe restar el rent del balance antes de comparar (Pump Science C4 finding).
    - La migración a Raydium/Meteora en Solana tiene pasos adicionales (initialize pool →
      add liquidity → lock LP) que no son atómicos en un solo CPI call.
    - "Quemar LP tokens" puede hacerse incorrectamente si el token de LP no soporta burn
      nativo — enviar a address(0) puede revertir en algunos tokens ERC-20.
    - Protocolos copycats de pump.fun en EVM frecuentemente copian bugs junto con features.
  solodit_ids:
    - "h-09-dos-of-launchpad-graduation-via-addliquidity-with-1-wei-donation-code4rena-gte-gte-git"
    - "mnbd1-4-tokens-cannot-graduate-if-an-attacker-transfers-kas-to-the-bondingcurvepool-contract-hexens-none-moonbound-markdown"
    - "mnbd1-6-an-attacker-can-prevent-the-graduation-of-the-bondingcurvepool-by-front-running-to-sell-a-very-small-amount-of-curve-tokens-hexens-none-moonbound-markdown"
    - "mnbd1-2-lack-of-slippage-protection-during-graduation-in-bondingcurvepool-hexens-none-moonbound-markdown"
    - "m-24-launchpad-slippage-is-not-enforced-properly-during-token-graduation-code4rena-gte-gte-git"
  incidentes:
    - "GTE (C4) — DoS de graduation via donación de 1 wei en addLiquidity. Slippage no enforced durante graduation."
    - "Moonbound (Hexens) — Tres bugs: donación directa de KAS bloquea graduation, front-run de sell previene graduation, falta slippage protection en migration."
    - "Pump Science (C4 2025) — migration_token_allocation no actualizado en update_settings(), migración usa valor default incorrecto."
    - "pump.fun (2024) — $2M exploit via empleado rogue con acceso a withdrawal authority + flash loans para drenar bonding curves."
```

---

## 14. Bonding Curve Rounding Direction Inconsistency

```yaml
- id: launch-014
  titulo: Rounding inconsistente en buy vs sell — extracción sistemática de valor via round-trips
  causa_raiz: |
    En bonding curves, las funciones de buy y sell deben usar direcciones de rounding opuestas:
    buy debe redondear CONTRA el comprador (más ETH por menos tokens) y sell debe redondear
    CONTRA el vendedor (menos ETH por los tokens vendidos). Si ambas funciones redondean en la
    misma dirección, un atacante puede hacer round-trips (compra + venta inmediata) para extraer
    valor del reserve en cada ciclo, lentamente drenando la reserva.
  como_funciona: |
    1. Bonding curve: buy rounds down (comprador recibe menos tokens) — CORRECTO.
    2. Bonding curve: sell también rounds down (vendedor recibe menos ETH) — parece CORRECTO pero...
    3. Si buy rounds down tokens pero sell rounds UP ETH (o viceversa), hay inconsistencia.
    4. Atacante: compra tokens → recibe N tokens. Vende N tokens → recibe más ETH de lo que pagó.
    5. Repite miles de veces: reserve se drena por 1-2 wei por round-trip.
    6. Con tokens de pocos decimales (6 o menos), el impacto es significativo.

    En Sudoswap v2 (Cyfrin audit): XykCurve y GDACurve tenían buy y sell con misma dirección
    de rounding → pérdida acumulativa para el pool.
  invariante: |
    // Round-trip invariant: comprar y vender inmediatamente NO debe ser profitable
    uint256 ethBefore = address(this).balance;
    uint256 tokensBought = buy{value: ethAmount}();
    uint256 ethReturned = sell(tokensBought);
    assert(ethReturned <= ethAmount); // Nunca profit en round-trip
    // Equivalente: la reserva nunca disminuye por operaciones de buy+sell
    assert(address(this).balance >= ethBefore);
  que_mirar:
    - Funciones getBuyPrice() y getSellPrice() que usan la misma operación de rounding
    - mulDiv sin especificar rounding direction (Rounding.Up vs Rounding.Down)
    - Tokens con pocos decimales (<8) donde el impacto de rounding es mayor
    - Curvas que usan librería math sin rounding explícito (ej: a * b / c sin round-up helper)
    - Ausencia de fee mínimo que cubra el rounding loss
  como_se_arregla: |
    Buy: roundUp para el costo en ETH (comprador paga más) o roundDown para tokens recibidos.
    Sell: roundDown para ETH devuelto (vendedor recibe menos).
    Invariant test: buy(x).sell() <= x para todo x > 0.
    Fee mínimo de 1 wei o 0.01% que cubre rounding losses.
    Usar FullMath.mulDivRoundingUp() de Uniswap para la dirección correcta.
  trampas:
    - En la mayoría de curvas, el rounding loss es 1-2 wei por operación. Para ser un finding
      reportable, demostrar que es acumulable (miles de operaciones) Y que el gas cost no
      supera la ganancia (en L2 con gas barato, puede ser viable).
    - Algunas curvas tienen fee que absorbe el rounding loss — si fee > rounding, no es explotable.
    - El invariant buy(sell(x)) <= x puede fallar por 1 wei y eso ser "by design". La pregunta
      es si falla por cantidades crecientes con el supply.
  solodit_ids:
    - "m-25-bonding-shares-incorrectly-reducedunstaked-on-transfer-in-launchtoken-code4rena-gte-gte-git"
    - "m-23-rounding-down-in-quote-calculation-allows-underpriced-launchtoken-purchases-code4rena-gte-gte-git"
  incidentes:
    - "Sudoswap v2 (Cyfrin 2023) — XykCurve y GDACurve usan misma dirección de rounding en buy y sell. Pérdida acumulativa para el pool. Nunca explotado en mainnet (funciones no conectadas al frontend)."
    - "GTE (C4) — Rounding down en quote calculation permite compras de LaunchToken a precio inferior al justo. Bonding shares incorrectamente reducidas en transfer."
```

---

## 15. Graduation Threshold Flash Loan Attack

```yaml
- id: launch-015
  titulo: Flash loan para forzar graduation prematura y manipular LP migration
  causa_raiz: |
    En protocolos tipo pump.fun, la graduation ocurre cuando el market cap o la reserva
    alcanza un threshold. Si la compra que trigger graduation se puede financiar con flash
    loan, el atacante puede: (1) forzar graduation en un momento desfavorable para los holders,
    (2) manipular la composición del LP pool que se crea en la migración, y (3) extraer valor
    del pool recién creado via arbitraje inmediato.
  como_funciona: |
    1. Bonding curve tiene $80K en reserves, graduation threshold es $100K.
    2. Atacante toma flash loan de $20K equivalente en ETH/SOL.
    3. Atacante compra tokens en la curva → reserves llegan a $100K → graduation se triggerea.
    4. Migración crea pool en Uniswap/Raydium con ratio basado en reserves + supply actual.
    5. Atacante ya posee tokens comprados con flash loan → puede manipular el ratio.
    6. Inmediatamente después de la migración, atacante vende en el nuevo pool.
    7. El pool recién creado tiene toda la liquidez de la curva → slippage bajo para el atacante.
    8. Atacante repaga flash loan → profit neto de la diferencia de precios.

    Variante (Virtuals Protocol): flash loan compra fuerza graduation, lo cual trigger
    distribución de rewards. Atacante captura rewards sin staking real.
  invariante: |
    // El comprador que triggerea graduation no puede vender en el mismo bloque
    if (justGraduated) {
        assert(block.number > graduationBlock);
    }
    // El pool creado en migración tiene slippage protection
    assert(poolPrice >= minAcceptablePrice && poolPrice <= maxAcceptablePrice);
    // Post-graduation: no se puede operar en la curva (solo en el pool)
    assert(!bondingCurveActive || !graduationCompleted);
  que_mirar:
    - ¿La función de compra que triggerea graduation se puede financiar con flash loan?
    - ¿El atacante puede comprar y vender en la misma tx que incluye la graduation?
    - ¿Hay cooldown post-graduation antes de permitir trades en el nuevo pool?
    - ¿La migración tiene slippage protection o el atacante puede manipular el ratio?
    - ¿Los rewards o airdrops se distribuyen al momento de la graduation?
    - ¿La curva se pausa atómicamente al graduar o hay un gap?
  como_se_arregla: |
    Anti-flash-loan en la compra que triggerea graduation:
    - require(balanceOf(msg.sender) > 0) previo al bloque actual (snapshot).
    - O: cooldown de N bloques entre última compra y graduation.
    Slippage protection en migración (ver launch-013).
    No distribuir rewards en la tx de graduation — delay de N bloques.
    Pausar la curva Y el nuevo pool por N bloques post-graduation (cooling period).
  trampas:
    - Flash loan prevention via "check balance at start of tx" puede ser bypaseado si
      el atacante tiene balance previo y solo incrementa con flash loan.
    - El cooldown post-graduation puede ser una ventana de arbitraje para otros bots.
    - En algunos protocolos, forzar graduation prematura es features, no bug (cualquiera
      puede comprar hasta el threshold). La pregunta es si la MIGRACIÓN es manipulable.
  solodit_ids:
    - "m-04-launched-tokens-are-vulnerable-to-flashloan-attacks-forcing-premature-graduation-allowing-reward-manipulation-code4rena-virtuals-protocol-virtuals-protocol-git"
    - "h-09-dos-of-launchpad-graduation-via-addliquidity-with-1-wei-donation-code4rena-gte-gte-git"
    - "mnbd1-2-lack-of-slippage-protection-during-graduation-in-bondingcurvepool-hexens-none-moonbound-markdown"
  incidentes:
    - "Virtuals Protocol (C4) — Flash loan attack fuerza graduation prematura, manipula reward distribution. Classified Medium."
    - "pump.fun (2024) — Empleado rogue usó flash loans para drenar bonding curves (ataque interno, no solo smart contract bug)."
    - "Moonbound (Hexens) — Slippage no protegida durante graduation + front-run de sell que previene graduation."
```
