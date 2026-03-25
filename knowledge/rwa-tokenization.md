# RWA Tokenization -- Combat Briefing

> **Scope**: Real World Asset (RWA) tokenization protocols — securitized on-chain assets, compliance hooks (ERC-1404/ERC-3643/T-REX), transfer restrictions, KYC/AML whitelists, NAV oracles, redemption flows, tranche structures, and asset-backed tokens.
> **Sources**: Solodit -- 40+ verified audit findings. Protocols: Centrifuge/Tinlake (Sherlock/Cantina/Spearbit 2023-2025), Ondo Finance (C4 2023, Cyfrin 2024-2025), Securitize (Cyfrin 2024-2025, multiple modules), Maple Finance (Spearbit/Cantina 2022-2024), Goldfinch/Carapace (Sherlock 2023), Fractional V2 (C4 2022), MakerDAO RWA (Cantina 2024), Strata Tranches (Cyfrin 2025).
> **Last updated**: 2026-03-22

---

## Conceptos clave antes de huntar

**Flujo RWA típico**:
```
Investor (KYC'd) → Onramp/Deposit → Compliance Check → Mint Token
                                         │
                              ┌───────────┴───────────┐
                              │  Identity Registry     │
                              │  (whitelist, country,  │
                              │   accredited status)   │
                              └────────────────────────┘

Token Transfer → preTransferCheck() → Identity Registry lookup
                                       ├── sender whitelisted?
                                       ├── receiver whitelisted?
                                       ├── country restrictions?
                                       ├── lockup period expired?
                                       └── transfer limit OK?

Redemption → Request Queue → NAV Oracle → Settlement (on/off-chain)
```

**Estándares clave**:
- **ERC-1404**: Simple restricted token — `detectTransferRestriction()` + `messageForTransferRestriction()`
- **ERC-3643 (T-REX)**: Full compliance framework — Identity Registry + Compliance Module + Claim Topics
- **ERC-7540**: Async deposit/redeem vaults (used by Centrifuge V3)

**Superficies de ataque únicas de RWA**:
1. **Compliance bypass** — el token tiene restricciones de transferencia, pero hay caminos que las esquivan
2. **Off-chain/on-chain desync** — el estado on-chain no refleja la realidad off-chain (NAV, KYC, settlement)
3. **Operator abuse** — compliance operators/forced transfers con demasiado poder
4. **Redemption manipulation** — explotar colas de redención, NAV stale, o liquidez insuficiente
5. **Tranche/waterfall** — violar la prioridad de tranches en securitización

---

## 1. Bugs Conocidos — Transfer Restrictions & Compliance

### Transfer Restriction Bypass

```yaml
- id: rwa-001
  titulo: "Bypass de transfer restrictions via approve+transferFrom o permit"
  causa_raiz: >
    ERC-1404 y ERC-3643 implementan restricciones en transfer() y transferFrom(),
    pero la función _beforeTokenTransfer() o el hook de compliance no cubre TODOS
    los caminos de movimiento de tokens. approve() + transferFrom() desde un
    contrato intermediario, o el uso de permit() (EIP-2612) para aprobar sin
    transacción, puede esquivar las verificaciones si el hook solo valida
    en transfer() directo.
  como_funciona: >
    1. Token restringido implementa detectTransferRestriction() en transfer().
    2. Pero transferFrom() no llama a detectTransferRestriction() o lo hace
       con parámetros incorrectos (e.g., msg.sender en vez de from).
    3. Holder aprueba a un contrato intermediario no-whitelisted.
    4. Contrato llama transferFrom() — tokens se mueven a dirección no autorizada.
    5. Alternativa: usar permit() para dar approval sin transacción on-chain,
       luego transferFrom() desde un relayer — la compliance check nunca ve
       la operación de approval.
  invariante: |
    // Solidity assertion
    // Toda transferencia (transfer, transferFrom, mint, burn) debe pasar por compliance
    function invariant_all_transfers_checked() public {
        // After any transfer attempt to non-whitelisted address:
        assert(token.balanceOf(nonWhitelistedAddr) == 0);
    }
  que_mirar:
    - "¿_beforeTokenTransfer() cubre transfer, transferFrom, mint, y burn?"
    - "¿detectTransferRestriction() recibe (from, to, amount) correctamente en TODOS los paths?"
    - "¿Hay permit() (EIP-2612) sin compliance check en el approval path?"
    - "¿Existe algún wrapper/router que mueva tokens sin pasar por el hook?"
    - "grep: 'function transfer(' vs 'function transferFrom(' — ¿ambos tienen el mismo hook?"
    - "grep: '_beforeTokenTransfer' — ¿se implementa? ¿cubre todos los casos?"
  como_se_arregla: >
    Implementar compliance check en _beforeTokenTransfer() (o _update() en OZ v5) que
    se ejecuta para TODOS los movimientos de tokens. Nunca implementar la restricción
    solo en transfer() — siempre en el hook base que cubre transfer, transferFrom,
    mint, y burn.
  trampas:
    - "Algunos protocolos intencionalmente permiten transferFrom sin restricción para DEX integrations — verificar si es by design"
    - "ERC-3643 tiene el hook en el compliance module, no en el token — buscar ahí"
    - "Permit no mueve tokens — solo da approval. El bypass real es permit + transferFrom"
  solodit_ids:
    - "m-08-the-restriction-manager-does-not-completely-implement-erc1404-which-leads-to-accounts-that-are-supposed-to-be-restricted-actually-having-access-to-do-with-their-tokens-as-they-see-fit-code4rena-centrifuge-centrifuge-git"
    - "not-compliant-with-erc1404-fixed-consensys-fairmint-continuous-securities-offering-markdown"
    - "l-01-pause-bypass-for-approvals-via-permit-kann-none-manifestfinance-security-review_2025-08-26-markdown"
    - "borrowing-non-approved-tokens-can-bypass-trading-restrictions-cyfrin-none-d-markdown"
  incidentes:
    - "Centrifuge (C4, MEDIUM) — restriction manager no implementa ERC-1404 completamente; cuentas restringidas pueden usar tokens libremente"
    - "Fairmint CSO (Consensys, FIX) — non-compliance con ERC-1404; transfer restrictions incompletas"
  verificado: true
  confianza: alta
```

### KYC/AML Whitelist Race Condition

```yaml
- id: rwa-002
  titulo: "Race condition al remover dirección de whitelist mientras hay transferencia in-flight"
  causa_raiz: >
    El proceso de des-whitelistear una dirección (e.g., por expiración KYC, sanción OFAC)
    no es atómico con las transferencias pendientes. Si un usuario inicia una transferencia
    (o tiene una pendiente en un mempool/sequencer) y el admin remueve su dirección del
    whitelist en el mismo bloque o bloque siguiente, la transferencia puede completarse
    porque el check de whitelist se ejecutó con el estado anterior.
  como_funciona: >
    1. Admin detecta que inversor A tiene KYC expirado, envía tx para removerlo de whitelist.
    2. Inversor A ve la tx de remoción en el mempool (o anticipa la acción).
    3. Inversor A front-runs con una transferencia a inversor B (o a sí mismo en otra wallet).
    4. La transferencia pasa porque A todavía está whitelisted cuando se ejecuta.
    5. Admin's tx se ejecuta después — A ya no está whitelisted, pero los tokens ya se movieron.
    6. En L2 sequencers (Optimism, Base), el ordering es del sequencer — el front-running
       es más difícil pero no imposible (builder puede reordenar).
  invariante: |
    // Post-condition: si un address fue removido del whitelist,
    // su balance debe ser 0 (o frozen, o transferido a recovery)
    function invariant_dewhitelisted_no_balance() public {
        for (uint i = 0; i < removedAddresses.length; i++) {
            address removed = removedAddresses[i];
            if (!identityRegistry.isWhitelisted(removed)) {
                // En un sistema ideal, balance debería ser 0 o frozen
                // En la práctica, verificar que no puede hacer más transfers
                assert(token.detectTransferRestriction(removed, anyAddr, 1) != 0);
            }
        }
    }
  que_mirar:
    - "¿La remoción de whitelist congela los tokens inmediatamente o solo previene futuras transfers?"
    - "¿Hay un periodo de gracia/cooldown entre remoción y congelamiento?"
    - "grep: 'removeInvestor' o 'updateMember' o 'revokeWhitelist' — ¿qué hace con el balance existente?"
    - "¿Se pueden front-runear las operaciones de compliance en L1?"
  como_se_arregla: >
    Implementar un mecanismo de freeze atómico: al remover de whitelist, congelar los
    tokens simultáneamente (freeze + de-whitelist en una sola tx). O usar un sistema de
    2-step: primero freeze, luego (después de n bloques) permitir recovery por compliance officer.
  trampas:
    - "En L2 con sequencer centralizado, el front-running es mucho más difícil — ajustar severidad"
    - "Algunos protocolos usan validAt timestamps que mitigan esto — verificar"
    - "No es un bug si el protocolo explícitamente documenta que la remoción solo afecta transfers futuras"
  solodit_ids:
    - "m-3-front-run-of-addblacklist-function-sherlock-telcoin-telcoin-update-git"
    - "malicious-user-holding-hilbtc-tokens-can-front-run-blacklisted-transaction-cyfrin-none-syntetika-markdown"
    - "01-a-redeemer-might-get-front-run-by-a-freezer-code4rena-reserve-reserve-git"
  incidentes:
    - "Telcoin (Sherlock, MEDIUM) — front-run de addBlacklist permite transferir tokens antes del blacklisting"
  verificado: true
  confianza: media
```

### Forced Transfer / Seize Abuse

```yaml
- id: rwa-003
  titulo: "Compliance operator puede confiscar tokens arbitrariamente via forcedTransfer/seize"
  causa_raiz: >
    Los tokens RWA necesitan un mecanismo de forced transfer para cumplir con órdenes
    judiciales y regulaciones (e.g., congelamiento OFAC). Pero si el access control
    del operador de compliance no está bien delimitado, o si el operador puede seize
    sin timelock/multisig, el riesgo de abuso es alto. Además, los tokens seized
    pueden quedar stuck si el receptor no es un inversor registrado.
  como_funciona: >
    1. Operador de compliance tiene rol FORCED_TRANSFER_ROLE o equivalente.
    2. Llama a forcedTransfer(from, to, amount) — mueve tokens sin consent del holder.
    3. Si 'to' no es un inversor registrado, los tokens quedan stuck (no puede transferirlos).
    4. Si no hay timelock, un operador malicioso puede drain tokens de cualquier holder.
    5. El burn via seize puede romper la contabilidad si el balance del inversor
       no se actualiza en el identity registry.
  invariante: |
    // Los tokens seized deben ir a una dirección válida y no quedar stuck
    function invariant_seized_tokens_accessible() public {
        address seizeTo = complianceModule.seizeRecoveryAddress();
        if (token.balanceOf(seizeTo) > 0) {
            // El recovery address debe poder mover los tokens
            assert(identityRegistry.isVerified(seizeTo) || seizeTo == treasury);
        }
    }
  que_mirar:
    - "grep: 'forcedTransfer' o 'seize' o 'forceTransfer' — ¿quién puede llamarla?"
    - "¿Hay timelock o multisig requirement para forced transfers?"
    - "¿Los tokens seized van a una dirección que puede moverlos (whitelisted/treasury)?"
    - "¿El seize actualiza el investor balance en el identity registry?"
    - "¿Existe evento/log para forced transfers (auditabilidad regulatoria)?"
  como_se_arregla: >
    Implementar timelock + multisig para forced transfers. Los tokens seized deben ir
    siempre a una dirección de recovery controlada por el protocolo (no a address(0)
    ni a una dirección arbitraria). Actualizar identity registry después de seize.
    Emitir evento específico ForcedTransfer(from, to, amount, reason).
  trampas:
    - "La existencia de forcedTransfer es un REQUISITO regulatorio, no un bug — el bug es la falta de protecciones"
    - "No confundir con burn administrativo (diferente de seize)"
    - "Algunos protocolos usan 'recover' en vez de 'seize' — misma funcionalidad"
  solodit_ids:
    - "seized-tokens-will-be-stuck-on-the-receiver-of-the-seized-funds-because-it-is-not-an-investor-and-never-receives-investorsbalance-cyfrin-none-securitize-dstoken-rebasing-markdown"
    - "burn-and-seize-functions-can-be-dos-when-investor-has-several-wallets-that-they-control-cyfrin-none-securitize-dstoken-rebasing-markdown"
    - "stale-issuance-records-after-burn-and-seize-operations-cyfrin-none-securitize-dstoken-rebasing-markdown"
    - "complianceconfigurationservicegetworldwideforcefulltransfer-is-not-applied-to-us-investors-cyfrin-none-securitize-dstoken-rebasing-markdown"
    - "m-01-admin-can-seize-pawn-collateral-via-emergencywithdrawnft-shieldify-none-shiny-markdown"
    - "consider-making-forced-transfers-revert-for-zero-amount-acknowledged-consensys-none-metamask-usd-token-markdown"
  incidentes:
    - "Securitize DSToken Rebasing (Cyfrin, MEDIUM) — tokens seized quedan stuck en el receptor porque no es un inversor y nunca recibe investorsBalance"
    - "Securitize DSToken Rebasing (Cyfrin, MEDIUM) — stale issuance records después de burn/seize causan contabilidad incorrecta para rebasing"
  verificado: true
  confianza: alta
```

---

## 2. Bugs Conocidos — NAV Oracle & Pricing

### NAV Oracle Staleness

```yaml
- id: rwa-004
  titulo: "NAV oracle off-chain no actualizado permite arbitraje con precio stale"
  causa_raiz: >
    A diferencia de oráculos on-chain (Chainlink, TWAP), los NAV feeds de RWA se actualizan
    off-chain por un NAV provider (generalmente diario o semanal). Si el precio real del
    underlying asset cambia entre actualizaciones (e.g., un bono pierde valor por default
    del emisor), el NAV on-chain refleja un precio obsoleto. Los inversores pueden
    depositar/redimir al NAV stale, extrayendo valor de otros holders.
  como_funciona: >
    1. NAV provider publica NAV = $1.00 para token respaldado por bonos corporativos.
    2. Un emisor de bonos entra en default (noticia off-chain). NAV real debería ser $0.85.
    3. NAV on-chain sigue en $1.00 porque el provider no ha actualizado (latencia 24h).
    4. Atacante deposita $100K al NAV de $1.00, recibe shares valoradas en $100K.
    5. NAV se actualiza a $0.85. Shares del atacante valen $100K, pero el pool solo tiene
       activos por $85K. Los holders existentes absorben la pérdida.
    6. Alternativamente: holder existente redime antes de la actualización, llevándose
       más de lo que le corresponde.
  invariante: |
    // El NAV no debe tener más de MAX_STALENESS de antigüedad
    function invariant_nav_freshness() public {
        uint256 lastUpdate = navOracle.lastUpdateTimestamp();
        uint256 staleness = block.timestamp - lastUpdate;
        assert(staleness <= MAX_STALENESS); // e.g., 86400 for daily
    }

    // El NAV no debe cambiar más de X% en una sola actualización (circuit breaker)
    function invariant_nav_deviation() public {
        uint256 currentNav = navOracle.getNav();
        uint256 previousNav = navOracle.previousNav();
        uint256 deviation = currentNav > previousNav
            ? ((currentNav - previousNav) * 10000) / previousNav
            : ((previousNav - currentNav) * 10000) / previousNav;
        assert(deviation <= MAX_DEVIATION_BPS); // e.g., 500 = 5%
    }
  que_mirar:
    - "¿Quién actualiza el NAV? ¿Con qué frecuencia? ¿Hay staleness check?"
    - "grep: 'updateNav' o 'setPrice' o 'publishRate' — ¿quién puede llamarla?"
    - "¿Hay circuit breaker para cambios de NAV grandes (>5%)?"
    - "¿Los deposits/redeems están bloqueados cuando el NAV es stale?"
    - "¿El NAV oracle usa timestamp o block number para staleness?"
  como_se_arregla: >
    Implementar staleness check: revert deposits/redeems si NAV tiene más de X horas
    de antigüedad. Implementar circuit breaker: si NAV cambia más de Y%, pausar
    operaciones hasta que un admin confirme. Usar epoch-based deposits (como Centrifuge)
    donde los deposits no se ejecutan al precio actual sino al precio del próximo epoch.
  trampas:
    - "NAV diario es estándar en TradFi — la 'staleness' de 24h puede ser by design"
    - "El riesgo es proporcional a la volatilidad del underlying — bonos del tesoro US tienen baja vol"
    - "Epoch-based systems mitigan esto significativamente — verificar si hay epochs"
  solodit_ids:
    - "nav-calculation-using-oracle-spot-price-instead-of-perpetual-mark-price-quantstamp-dipcoin-vault-markdown"
    - "missing-slippage-safeguard-against-nav-deviation-quantstamp-solv-protocol-btc-redemption-markdown"
    - "securitizeammnavprovider-trades-when-pool-price-and-anchor-price-differ-can-leak-value-cyfrin-none-securitize-public-stock-ramp-markdown"
    - "invalid-zero-rate-not-rejected-during-deposit-cyfrin-none-securitize-solana-vault-markdown"
    - "vaultnav-calculation-exceeds-object-limits-as-market-count-grows-causing-denial-of-service-for-all-vault-operations-quantstamp-dipcoin-vault-markdown"
  incidentes:
    - "Securitize AMM NAV Provider (Cyfrin, MEDIUM) — trades ejecutados cuando pool price y anchor price difieren causan value leakage para LPs"
    - "Solv Protocol (Quantstamp, MEDIUM) — missing slippage safeguard contra NAV deviation permite redención a precio desfavorable"
    - "Maple Finance — unrealized losses en pools causaron pérdidas para depositantes que entraron al NAV incorrecto"
  verificado: true
  confianza: alta
```

### NAV AMM Invariant Violation

```yaml
- id: rwa-005
  titulo: "AMM para RWA tokens viola invariante k, permitiendo extracción de valor"
  causa_raiz: >
    Algunos protocolos RWA usan un AMM interno para on/off-ramp (e.g., Securitize Public Stock Ramp
    con curva AMM). Si la implementación del AMM permite que k (producto constante)
    disminuya, un atacante puede extraer valor del pool haciendo trades repetidos.
    Esto es especialmente peligroso porque el NAV anchor price puede diverger del pool price.
  como_funciona: >
    1. AMM tiene reservas de RWA token y stablecoin con invariante x*y = k.
    2. Debido a rounding incorrecto o fee calculation errónea, k disminuye en cada trade.
    3. Atacante hace muchos trades pequeños (buy/sell), extrayendo la diferencia.
    4. Cada ciclo reduce k, drenando las reservas del pool.
    5. Los LPs pierden valor progresivamente.
  invariante: |
    // k nunca debe decrecer después de un trade
    function invariant_amm_k_nondecreasing() public {
        uint256 reserveA = amm.reserveA();
        uint256 reserveB = amm.reserveB();
        uint256 currentK = reserveA * reserveB;
        assert(currentK >= previousK);
        previousK = currentK;
    }
  que_mirar:
    - "grep: 'reserveA * reserveB' o equivalente — ¿se verifica que k no decrece?"
    - "¿El rounding de fees favorece al pool (round up) o al trader (round down)?"
    - "¿Hay slippage protection para trades contra el NAV anchor?"
  como_se_arregla: >
    Asegurar que el rounding siempre favorece al pool (round up en fees, round down en
    output). Verificar post-trade que k >= k_prev. Implementar minimum trade size para
    evitar que el rounding sea significativo.
  trampas:
    - "k puede aumentar legítimamente por fees — solo verificar que no decrece"
    - "Dust-level decreases (1 wei) por rounding son normales — usar tolerancia"
  solodit_ids:
    - "securitizeammnavprovider-violates-core-amm-invariant-that-k-should-never-decrease-cyfrin-none-securitize-public-stock-ramp-markdown"
    - "incorrect-rounding-direction-in-securitizeammnavproviderexecutebuybase-when-scaling-down-execprice-cyfrin-none-securitize-public-stock-ramp-markdown"
  incidentes:
    - "Securitize AMM NAV Provider (Cyfrin, MEDIUM) — AMM viola invariante k, permitiendo que k disminuya en trades"
    - "Securitize AMM NAV Provider (Cyfrin, LOW) — rounding direction incorrecto en executeBuyBase al escalar execPrice"
  verificado: true
  confianza: alta
```

---

## 3. Bugs Conocidos — Redemption & Settlement

### Redemption Queue Manipulation

```yaml
- id: rwa-006
  titulo: "Manipulación de cola de redención para drenar liquidez o front-run otros redemptions"
  causa_raiz: >
    Los protocolos RWA usan colas de redención (async redemption) porque el underlying
    no es líquido. Si la cola no tiene protecciones contra front-running o si la
    liquidez se asigna FIFO sin rate limiting, un atacante que detecta un evento
    negativo (default, downgrade) puede solicitar redención antes que otros y drenar
    toda la liquidez disponible.
  como_funciona: >
    1. Pool tiene $10M en activos, $2M en liquidez disponible para redenciones.
    2. Atacante detecta que un crédito del pool va a defaultear (info privilegiada o on-chain signal).
    3. Atacante solicita redención por $2M antes que otros holders.
    4. Pool procesa redención FIFO — atacante recibe sus $2M.
    5. Otros holders solicitan redención pero no hay liquidez — quedan trapped.
    6. El crédito defaultea. NAV cae. Holders restantes absorben toda la pérdida.
  invariante: |
    // La redención no debe drenar más que un % máximo de la liquidez en un epoch
    function invariant_redemption_rate_limit() public {
        uint256 totalRedeemed = pool.totalRedeemedThisEpoch();
        uint256 totalLiquidity = pool.availableLiquidity();
        // No más del 25% de la liquidez en un epoch
        assert(totalRedeemed <= totalLiquidity * 2500 / 10000);
    }
  que_mirar:
    - "¿La redención es FIFO, pro-rata, o epoch-based?"
    - "¿Hay rate limiting por epoch/period?"
    - "¿Las redenciones grandes necesitan cooldown o advance notice?"
    - "grep: 'requestRedeem' o 'requestWithdraw' — ¿hay límites?"
    - "¿El NAV se actualiza ANTES o DESPUÉS de procesar redenciones?"
  como_se_arregla: >
    Usar epoch-based redemption (Centrifuge model): requests se agrupan en epochs y
    se procesan pro-rata, no FIFO. Implementar redemption rate limits por epoch.
    Actualizar NAV antes de procesar cualquier redención.
  trampas:
    - "Epoch-based systems (Centrifuge) mitigan esto significativamente — verificar si hay epochs"
    - "Pro-rata distribution es más justa pero más compleja — verificar implementación"
    - "La información privilegiada es un problema off-chain, no on-chain — el bug on-chain es la falta de rate limiting"
  solodit_ids:
    - "h-01-loss-of-user-funds-when-completing-cash-redemptions-code4rena-ondo-finance-ondo-finance-contest-git"
    - "m-05-setpendingredemptionbalance-may-cause-the-users-cash-token-to-be-lost-code4rena-ondo-finance-ondo-finance-contest-git"
    - "m-05-investors-claiming-their-maxdeposit-by-using-the-liquiditypooldeposit-will-cause-other-users-to-be-unable-to-claim-their-maxdepositmaxmint-code4rena-centrifuge-centrifuge-git"
    - "checks-in-_processredeem-can-be-circumvented-and-is-missing-in-claimcanceldepositre-quest-cantina-none-centrifuge-pdf"
  incidentes:
    - "Ondo Finance (C4, HIGH) — loss of user funds al completar cash redemptions por error en accounting"
    - "Ondo Finance (C4, MEDIUM) — setPendingRedemptionBalance puede causar pérdida de cash tokens de usuarios"
    - "Centrifuge (C4, MEDIUM) — inversores claiming maxDeposit causan DoS para otros usuarios"
  verificado: true
  confianza: alta
```

### Coupon/Yield Distribution Rounding

```yaml
- id: rwa-007
  titulo: "Holders pequeños reciben 0 yield por rounding en distribución de cupones"
  causa_raiz: >
    Los tokens RWA que distribuyen yield (coupon de bonos, dividendos, interés) usan
    división entera para calcular la porción de cada holder. Si el yield total dividido
    por totalSupply es menor que 1 wei por token held, los holders pequeños reciben 0.
    El yield "perdido" queda en el contrato o se redistribuye a holders grandes.
  como_funciona: >
    1. Token tiene totalSupply = 1,000,000 tokens.
    2. Yield distribuido = 500 USDC (500e6 en 6 decimals).
    3. Holder A tiene 1 token. Su yield = 500e6 / 1e6 = 500 = $0.0005.
    4. Si la implementación divide yield por shares primero: 500e6 * 1 / 1e6 = 0 (rounding).
    5. Holder A recibe 0 USDC repetidamente en cada distribución.
    6. Acumulación: después de 100 distribuciones, A debería tener $0.05 pero tiene $0.
    7. Si hay tokens rebasing (supply adjustments), el rounding se amplifica.
  invariante: |
    // La suma de yield distribuido debe ser <= yield total (pero close)
    function invariant_yield_distribution_conservation() public {
        uint256 totalDistributed = 0;
        for (uint i = 0; i < holders.length; i++) {
            totalDistributed += yieldClaimed[holders[i]];
        }
        // Total distributed should be close to total yield (within rounding tolerance)
        assert(totalDistributed <= totalYieldAvailable);
        assert(totalYieldAvailable - totalDistributed <= holders.length); // max 1 wei lost per holder
    }
  que_mirar:
    - "grep: 'rewardPerToken' o 'accRewardPerShare' o 'yieldPerShare' — ¿precision suficiente?"
    - "¿Se usa un acumulador de alta precisión (e.g., 1e18 scaling)?"
    - "¿Los rebasing tokens actualizan el yield acumulado antes de cambiar supply?"
    - "¿Hay minimum claim amount que previene claims de 0?"
  como_se_arregla: >
    Usar un acumulador de alta precisión (rewardPerTokenStored * 1e18). Implementar
    un patrón similar a Synthetix StakingRewards donde los rewards se acumulan con
    alta precisión antes de truncarse. Para tokens rebasing, actualizar rewardPerToken
    antes de cada rebase.
  trampas:
    - "1 wei de rounding loss por operación es aceptable — focus en pérdida acumulada"
    - "En tokens de 18 decimals el problema es menor que en tokens de 6 decimals (USDC)"
    - "Rebasing tokens (como Securitize DSToken Rebasing) multiplican el problema"
  solodit_ids:
    - "complianceserviceregulatedgetcompliancetransferabletokens-should-call-idslockmanagergettransferabletokensforinvestor-cyfrin-none-securitize-dstoken-rebasing-markdown"
    - "h-08-dividend-reward-can-be-gamed-code4rena-spartan-protocol-spartan-protocol-contest-git"
    - "h-04-division-rounding-can-make-fraction-price-lower-than-intended-down-to-zero-code4rena-fractional-fractional-v2-contest-git"
  incidentes:
    - "Spartan Protocol (C4, HIGH) — dividend reward puede ser manipulado via gaming del mecanismo de distribución"
    - "Fractional V2 (C4, HIGH) — division rounding hace que fraction price sea menor de lo esperado, hasta 0"
  verificado: true
  confianza: alta
```

### Off-Chain Settlement Gap

```yaml
- id: rwa-008
  titulo: "Transferencia on-chain completa pero settlement off-chain falla, creando desync"
  causa_raiz: >
    En RWA, el token on-chain representa un claim sobre un activo off-chain (bono,
    propiedad, equity). La transferencia on-chain del token puede completarse
    instantáneamente, pero el cambio de titularidad off-chain requiere un transfer
    agent (e.g., Securitize), registros legales, o settlement T+2. Si el settlement
    off-chain falla (rechazo del transfer agent, sanción OFAC, etc.), hay un desync:
    el token está en la wallet de B pero la titularidad legal sigue en A.
  como_funciona: >
    1. Inversor A transfiere token RWA a inversor B on-chain.
    2. Transfer agent off-chain recibe notificación del evento Transfer.
    3. Transfer agent rechaza el cambio de titularidad (e.g., B no tiene KYC completo
       en la jurisdicción del activo).
    4. On-chain: B tiene el token. Off-chain: A es el titular legal.
    5. Si B intenta redimir, el protocolo puede o no honrar la redención.
    6. Si A intenta reclamar el activo off-chain, hay conflicto con el state on-chain.
  invariante: |
    // Toda transferencia debe pasar por el transfer agent ANTES de completarse on-chain
    function invariant_transfer_agent_approval() public {
        // In ERC-3643: transfers must pass through compliance module
        // that checks with transfer agent
        assert(complianceModule.canTransfer(from, to, amount));
    }
  que_mirar:
    - "¿La transferencia on-chain espera confirmación del transfer agent (2-step)?"
    - "¿Hay un mecanismo de rollback si el settlement off-chain falla?"
    - "grep: 'transferAgent' o 'settlementAgent' o 'preApproved' — ¿hay pre-approval?"
    - "¿Los redemptions verifican la titularidad off-chain o solo el balance on-chain?"
  como_se_arregla: >
    Implementar transfers 2-step: 1) request transfer (lock tokens), 2) transfer agent
    approves off-chain, 3) complete transfer on-chain. Si el transfer agent rechaza,
    los tokens se desbloquean al sender. Nunca completar un transfer sin la aprobación
    del compliance module que refleje el estado off-chain.
  trampas:
    - "Esto es más un riesgo de diseño que un bug de código — la severidad depende de las consecuencias legales"
    - "Protocolos DeFi-nativos (sin activos off-chain) no tienen este problema"
    - "ERC-3643 mitiga esto con el compliance module, pero solo si está bien implementado"
  solodit_ids:
    - "single-step-redemption-and-two-step-redemption-not-equivalent-logic-cyfrin-none-securitize-public-stock-ramp-markdown"
    - "globalregistryserviceexecutepreapprovedtransaction-is-incompatible-with-smart-wallet-operators-cyfrin-none-securitize-global-registry-markdown"
    - "asymmetry-enforcement-between-tokenissuerregisterinvestor-walletregistrarregisterwallet-and-securitizeswap_registernewinvestor-cyfrin-none-securitize-dstoken-rebasing-markdown"
  incidentes:
    - "Securitize (Cyfrin, MEDIUM) — single-step redemption y two-step redemption tienen lógica no equivalente, creando inconsistencias"
    - "Securitize (Cyfrin, LOW) — executePreApprovedTransaction incompatible con smart wallet operators"
  verificado: true
  confianza: media
```

---

## 4. Bugs Conocidos — Maturity & Bond Tokens

### Maturity Date Handling

```yaml
- id: rwa-009
  titulo: "Bond token post-maturity: comportamiento indefinido permite transfers o pricing incorrecto"
  causa_raiz: >
    Los bond tokens tienen una fecha de maturity después de la cual el holder puede
    redimir el principal + último cupón. Pero si el contrato no maneja explícitamente
    el estado post-maturity, los tokens pueden seguir siendo transferibles, el pricing
    puede ser incorrecto (precio pre-maturity vs post-maturity), y los cupones pueden
    seguir acumulándose incorrectamente.
  como_funciona: >
    1. Bond token matures en timestamp T. Antes de T, precio = f(yield, duration).
    2. Después de T, el token debería valer exactamente el face value (redimible 1:1).
    3. Pero el contrato sigue calculando precio con la fórmula pre-maturity.
    4. Si el yield ha subido, el precio pre-maturity es < face value.
    5. Atacante compra tokens post-maturity a descuento (precio pre-maturity).
    6. Redime a face value. Profit = face value - discounted price.
    7. Alternativa: tokens siguen transferibles post-maturity a wallets no-KYC,
       porque las compliance checks asumen que solo inversores acreditados compran
       a descuento (pre-maturity) pero el face value redemption no requiere eso.
  invariante: |
    // Post-maturity: token price debe ser exactamente face value
    function invariant_post_maturity_price() public {
        if (block.timestamp >= bondToken.maturityDate()) {
            uint256 price = oracle.getPrice(address(bondToken));
            uint256 faceValue = bondToken.faceValue();
            assert(price == faceValue);
        }
    }

    // Post-maturity: transfers pueden estar restringidos (solo redeem)
    function invariant_post_maturity_no_transfer() public {
        if (block.timestamp >= bondToken.maturityDate()) {
            // Verify that transfers are blocked or limited post-maturity
            bool canTransfer = bondToken.detectTransferRestriction(alice, bob, 1) == 0;
            // Depending on design: transfers should be blocked post-maturity
            // or the price should reflect face value
        }
    }
  que_mirar:
    - "grep: 'maturity' o 'maturityDate' o 'expiry' — ¿qué pasa cuando block.timestamp > maturity?"
    - "¿El oracle/pricing function tiene un case especial para post-maturity?"
    - "¿Los cupones dejan de acumularse después de maturity?"
    - "¿Los transfers están bloqueados post-maturity?"
    - "¿Hay un grace period para redención post-maturity?"
  como_se_arregla: >
    Implementar un estado POST_MATURITY explícito. Después de maturity: precio = face value,
    transfers opcionalmente bloqueados (solo redeem permitido), cupones dejan de acumularse,
    y hay un deadline para redención después del cual los fondos van a un recovery address.
  trampas:
    - "Algunos bond tokens son 'perpetual' y no tienen maturity — no aplica"
    - "El pricing post-maturity puede ser ligeramente < face value si hay default risk — verificar"
    - "Sense Protocol tenía este patrón explícitamente"
  solodit_ids:
    - "m-3-periphery_swapptsfortarget-wont-work-correctly-if-pt-is-mature-but-redeem-is-restricted-sherlock-sense-sense-update-1-git"
    - "m-2-fixed-term-bond-tokens-can-be-minted-with-non-rounded-expiry-sherlock-bond-bond-protocol-git"
  incidentes:
    - "Sense Protocol (Sherlock, MEDIUM) — PT swap no funciona correctamente si PT está mature pero redeem está restringido"
    - "Bond Protocol (Sherlock, MEDIUM) — bond tokens con expiry no redondeado causan inconsistencias"
  verificado: true
  confianza: media
```

---

## 5. Bugs Conocidos — Tranche & Waterfall

### Tranche Seniority Bypass

```yaml
- id: rwa-010
  titulo: "Junior tranche reclama fondos antes que senior tranche, violando waterfall"
  causa_raiz: >
    En securitización, los tranches tienen prioridad: senior cobra primero, mezzanine
    segundo, junior último (waterfall). Si el smart contract no enforce esta prioridad
    correctamente — e.g., permite withdrawals de junior antes de que senior esté
    completamente satisfecho, o no actualiza el estado del waterfall atómicamente —
    un holder de junior tranche puede extraer valor que debería ir a senior.
  como_funciona: >
    1. Pool tiene $10M en activos, distribuidos: $6M senior, $3M mezzanine, $1M junior.
    2. Un crédito defaultea — pool pierde $2M. Nuevo total: $8M.
    3. Waterfall: senior debería recibir $6M completos, mezzanine $2M, junior $0.
    4. Pero el contrato permite que junior haga withdraw antes de que el waterfall se ejecute.
    5. Junior retira su $1M original (que ya no existe efectivamente).
    6. Senior solo recibe $5M en vez de $6M. Pérdida indebida para senior.
  invariante: |
    // Senior tranche debe estar completamente satisfecho antes de junior
    function invariant_waterfall_priority() public {
        uint256 seniorOwed = seniorTranche.totalOwed();
        uint256 seniorPaid = seniorTranche.totalPaid();
        uint256 juniorPaid = juniorTranche.totalPaid();

        // Junior no debe recibir nada hasta que senior esté 100% pagado
        if (seniorPaid < seniorOwed) {
            assert(juniorPaid == 0);
        }
    }
  que_mirar:
    - "grep: 'tranche' y 'withdraw' o 'redeem' — ¿hay check de prioridad?"
    - "¿El waterfall se ejecuta atómicamente o pueden hacerse withdrawals parciales?"
    - "¿Los defaults se propagan correctamente de junior a senior (junior absorbe primero)?"
    - "¿Existe un mecanismo de epoch/batch que fuerza el waterfall antes de distributions?"
    - "¿Puede un holder de junior tranche transferir sus tokens a otra wallet y redimir desde ahí?"
  como_se_arregla: >
    Implementar waterfall en el mismo call de distribución: primero calcular losses,
    aplicar a junior→mezzanine→senior, luego distribuir remaining pro-rata dentro de
    cada tranche. Bloquear withdrawals individuales — solo permitir claims después
    de que el waterfall se ejecute (epoch-based).
  trampas:
    - "En algunos diseños, los tranches son contratos separados — la interacción entre ellos es el surface"
    - "No confundir waterfall de distribución con waterfall de defaults — son inversos"
    - "Centrifuge usa un modelo epoch-based que mitiga esto"
  solodit_ids:
    - "frontrunning-to-block-junior-tranche-withdrawals-cyfrin-none-strata-tranches-markdown"
    - "m-10-unable-to-deposit-to-trancheadaptor-under-certain-conditions-sherlock-napier-git"
  incidentes:
    - "Strata Tranches (Cyfrin, MEDIUM) — front-running permite bloquear withdrawals de junior tranche"
    - "Goldfinch — junior tranche holders expuestos a pérdidas indebidas por diseño de waterfall incorrecto"
  verificado: true
  confianza: media
```

---

## 6. Bugs Conocidos — Asset Backing & Collateral

### Asset Backing Ratio Manipulation

```yaml
- id: rwa-011
  titulo: "Inflación de backing ratio via depósitos circulares o flash loans"
  causa_raiz: >
    El backing ratio (collateral / tokens outstanding) determina la solvencia del
    protocolo RWA. Si un atacante puede inflar temporalmente el backing ratio —
    e.g., depositando colateral con un flash loan, mintando tokens, y luego
    retirando el colateral — puede extraer más tokens de los que debería.
    En RWA con colateral off-chain, el riesgo es que el mismo activo se use
    como colateral en múltiples protocolos (double pledge).
  como_funciona: >
    1. Protocolo RWA requiere backing ratio de 150% para mintar tokens.
    2. Atacante toma flash loan de $1M.
    3. Deposita $1M como colateral. Backing ratio sube artificialmente.
    4. Minta tokens por $666K (al ratio de 150%).
    5. Retira $1M de colateral (o lo devuelve al flash loan).
    6. Backing ratio vuelve a la normalidad, pero los tokens mintados existen.
    7. El protocolo ahora está under-collateralized.
    Variante off-chain: un emisor pledgea el mismo bono como colateral en
    Centrifuge Y en MakerDAO. Ambos creen tener 100% backing.
  invariante: |
    // Post-operation: backing ratio debe mantenerse >= minimum
    function invariant_backing_ratio() public {
        uint256 totalCollateral = vault.totalCollateralValue();
        uint256 totalTokens = token.totalSupply();
        uint256 tokenValue = totalTokens * navOracle.getNav() / 1e18;
        // Backing ratio >= minimum (e.g., 100% or 150%)
        assert(totalCollateral * 10000 / tokenValue >= MIN_BACKING_RATIO_BPS);
    }

    // No mint+withdraw en el mismo block (anti flash loan)
    function invariant_no_same_block_mint_withdraw() public {
        // lastMintBlock[user] != lastWithdrawBlock[user] when both > 0
    }
  que_mirar:
    - "¿Se puede depositar colateral y mintar tokens en la misma transacción?"
    - "¿Hay cooldown entre deposit y mint?"
    - "¿El colateral está locked o puede retirarse inmediatamente?"
    - "grep: 'collateralRatio' o 'backingRatio' — ¿se verifica post-operación?"
    - "¿Hay verificación off-chain de que el colateral no está pledged elsewhere?"
  como_se_arregla: >
    Implementar cooldown entre deposit y mint (mínimo 1 bloque). Bloquear colateral
    mientras hay tokens outstanding. Para colateral off-chain, implementar proof-of-reserves
    periódico con attestation de terceros (e.g., Chainlink PoR).
  trampas:
    - "Flash loans son imposibles con colateral off-chain — el riesgo es double pledge, no flash loans"
    - "El backing ratio puede ser < 100% legítimamente si hay unrealized losses"
    - "MakerDAO RWA vaults mitigan esto con trust structures off-chain"
  solodit_ids:
    - "temporal-collateral-ratio-inflation-during-reward-distribution-spearbit-none-buck-labs-smart-contracts-pdf"
    - "transaction-re-ordering-of-setcashinflight-can-cause-transient-collateral-ratio-divergence-spearbit-none-buck-labs-pdf"
    - "increased-risks-of-unwanted-share-price-manipulation-by-manipulating-the-pocket-usdc-balance-cantina-none-makerdao-pdf"
  incidentes:
    - "Buck Labs (Spearbit, MEDIUM) — temporal collateral ratio inflation durante distribución de rewards"
    - "Buck Labs (Spearbit, MEDIUM) — transaction re-ordering de setCashInFlight causa divergencia transitoria del collateral ratio"
    - "MakerDAO (Cantina, MEDIUM) — manipulación del pocket USDC balance permite share price manipulation"
  verificado: true
  confianza: alta
```

---

## 7. Bugs Conocidos — Regulatory Freeze & Pause

### Regulatory Freeze Bypass

```yaml
- id: rwa-012
  titulo: "Token pausado sigue movible via ciertos code paths (permit, delegate, router)"
  causa_raiz: >
    Cuando un regulador ordena congelar un token RWA, el protocolo usa pause() para
    bloquear transferencias. Pero si el modifier whenNotPaused no está en TODAS las
    funciones que mueven tokens (transferFrom, burn, delegate con transfer, router
    interactions), hay paths que permiten mover tokens durante la pausa.
  como_funciona: >
    1. Regulador ordena freeze. Admin llama pause() en el token.
    2. transfer() y transferFrom() están bloqueados (whenNotPaused).
    3. Pero approve() NO está pausada — holder da approval a un contrato.
    4. Cuando se despause, el contrato ejecuta transferFrom() inmediatamente.
    5. O peor: hay un router/vault que mueve tokens internamente sin pasar por
       transfer() (e.g., usando _transfer() interno o assembly).
    6. Alternativamente: una función de redeem/withdraw que quema tokens y envía
       underlying no está pausada — holder convierte tokens a underlying y escapa.
  invariante: |
    // Cuando pausado: ningún balance debe cambiar
    function invariant_pause_freezes_all() public {
        if (token.paused()) {
            for (uint i = 0; i < trackedAddrs.length; i++) {
                assert(token.balanceOf(trackedAddrs[i]) == balanceBefore[trackedAddrs[i]]);
            }
        }
    }
  que_mirar:
    - "grep: 'whenNotPaused' — ¿está en transfer, transferFrom, mint, burn, redeem, withdraw?"
    - "¿Approve está pausada? (puede ser legítimo no pausarla)"
    - "¿Hay funciones de redeem/withdraw que no chequean paused?"
    - "¿Hay un router o vault que interactúa con el token sin pasar por transfer()?"
    - "¿El pause afecta al token Y al vault/pool, o solo al token?"
    - "¿Existe un bypass de pausa para operaciones de compliance (seize, forced transfer)?"
  como_se_arregla: >
    whenNotPaused en TODAS las funciones que cambian balances: transfer, transferFrom,
    mint, burn. Para approve, evaluar si pausarla es necesario (impide pre-positioning
    pero también impide revocación de approvals). Para vaults/pools que interactúan con
    el token, implementar pausa separada que bloquee deposits/withdraws.
  trampas:
    - "Algunos protocolos deliberadamente permiten burn/redeem durante pausa — para que reguladores puedan recuperar fondos"
    - "Pausar approve impide que holders revoquen approvals durante emergencia — trade-off de diseño"
    - "El bypass vía router es el más peligroso y más difícil de detectar"
  solodit_ids:
    - "m-02-psm_redeem-bypasses-yzusd-pause-and-redeem-restrictions-during-execution-pashov-audit-group-none-yuzuusd_2026-01-14-markdown"
    - "setispausedforallmarkets-bypass-the-check-done-in-setisborrowpaused-and-allow-resuming-borrow-spearbit-morpho-pdf"
    - "m-05-bypass-whennotpaused-modifier-code4rena-gogopool-gogopool-contest-git"
    - "bid-submission-permitted-during-paused-contract-state-halborn-beranames-name-service-bns-contracts-v2-markdown"
    - "paused-deregistering-is-bypassed-via-registeroperatorwithchurn-cantina-none-eigenlayer-pdf"
    - "l-01-pause-bypass-for-approvals-via-permit-kann-none-manifestfinance-security-review_2025-08-26-markdown"
  incidentes:
    - "YuzuUSD (Pashov, MEDIUM) — PSM redeem bypasses pause y redeem restrictions durante ejecución"
    - "Morpho (Spearbit, MEDIUM) — setIsPausedForAllMarkets bypasses el check de setIsBorrowPaused"
    - "GoGoPool (C4, MEDIUM) — bypass de whenNotPaused modifier"
  verificado: true
  confianza: alta
```

---

## 8. Bugs Conocidos — Identity Registry & Compliance Module

### Identity Registry Desync

```yaml
- id: rwa-013
  titulo: "Registry de identidad on-chain desincronizado con proveedor KYC off-chain"
  causa_raiz: >
    El Identity Registry on-chain (ERC-3643) almacena claims de identidad verificados
    por un Claim Issuer off-chain. Si el proveedor KYC off-chain revoca una verificación
    (e.g., KYC expirado, sanción nueva) pero el registro on-chain no se actualiza,
    las compliance checks on-chain siguen viendo al inversor como válido. La actualización
    depende de un keeper/oracle que puede fallar, tener latencia, o ser censurado.
  como_funciona: >
    1. Inversor A pasa KYC off-chain. Claim Issuer emite claim on-chain.
    2. Un año después, KYC de A expira. Off-chain, A ya no es válido.
    3. El keeper que sincroniza el estado no ejecuta (gas alto, bug, downtime).
    4. On-chain, A sigue teniendo el claim válido.
    5. A puede seguir transfiriendo y recibiendo tokens RWA.
    6. Si A es sanctioned (OFAC), esto es una violación regulatoria grave.
    7. Para protocolos como Securitize: si la wallet de un inversor no tiene
       country attribute inicializado, puede bypasear restricciones de jurisdicción.
  invariante: |
    // Cada inversor verificado debe tener claims no-expirados
    function invariant_claims_not_expired() public {
        for (uint i = 0; i < investors.length; i++) {
            if (identityRegistry.isVerified(investors[i])) {
                // Verify claims are still valid
                uint256 claimExpiry = identityRegistry.getClaimExpiry(investors[i]);
                assert(claimExpiry == 0 || claimExpiry > block.timestamp);
            }
        }
    }
  que_mirar:
    - "¿Los claims tienen expiry timestamp? ¿Se verifica en transferCheck?"
    - "¿Quién actualiza el identity registry? ¿Con qué frecuencia?"
    - "grep: 'isVerified' o 'isWhitelisted' — ¿verifica expiry?"
    - "¿Hay un mecanismo de fallback si el keeper no actualiza?"
    - "¿Los country attributes se inicializan correctamente para todas las wallets?"
  como_se_arregla: >
    Implementar expiry automático en claims. Las compliance checks deben verificar
    que el claim no ha expirado (block.timestamp < claimExpiry). Implementar un
    keeper redundante y alertas si el registry no se actualiza en X horas.
    Inicializar TODOS los atributos (country, accreditation) al registrar un inversor.
  trampas:
    - "Algunos protocolos usan 'validAt' timestamps en el member struct — verificar si expiran"
    - "ERC-3643 tiene claim topics pero la expiración es del claim issuer, no del registry"
    - "La latencia de 24h puede ser aceptable para KYC pero NO para sanciones OFAC"
  solodit_ids:
    - "uninitialized-country-for-valid-investor-wallets-allows-bypassing-us-compliance-lockup-period-cyfrin-none-securitize-bridge-cctp-markdown"
    - "broken-identity-to-wallet-binding-in-redeem-allows-country-restriction-bypass-cyfrin-none-securitize-solana-redemption-markdown"
    - "same-wallet-can-be-added-multiple-times-to-an-investor-artificially-increasing-their-wallet-count-causing-adding-new-wallets-to-revert-cyfrin-none-securitize-global-registry-markdown"
    - "complianceserviceglobalwhitelistednewpretransfercheck-and-pretransfercheck-allow-blacklisted-users-to-transfer-tokens-cyfrin-none-securitize-global-registry-markdown"
    - "unused-bits-are-erased-in-updatemember-cantina-none-centrifuge-pdf"
    - "m-04-kycregistry-is-susceptible-to-signature-replay-attack-code4rena-ondo-finance-ondo-finance-contest-git"
  incidentes:
    - "Securitize Bridge CCTP (Cyfrin, HIGH) — country no inicializado para wallets válidas permite bypasear el lockup period de compliance US"
    - "Securitize Solana Redemption (Cyfrin, HIGH) — broken identity-to-wallet binding permite bypass de country restriction"
    - "Securitize Global Registry (Cyfrin, MEDIUM) — pretransfercheck permite a usuarios blacklisted transferir tokens"
    - "Ondo Finance (C4, MEDIUM) — KYC registry susceptible a signature replay attack"
  verificado: true
  confianza: alta
```

### Compliance Module Upgrade Risk

```yaml
- id: rwa-014
  titulo: "Upgrade de proxy cambia reglas de compliance retroactivamente, afectando holders existentes"
  causa_raiz: >
    Los tokens RWA son típicamente upgradeable (UUPS/TransparentProxy) porque las
    regulaciones cambian. Pero un upgrade del compliance module puede cambiar
    retroactivamente quién puede holdear tokens: e.g., un upgrade que añade restricción
    por país puede hacer que holders existentes de ese país no puedan transferir ni
    redimir sus tokens. Si no hay migration path, los tokens quedan stuck.
  como_funciona: >
    1. Token RWA permite holders de US y EU, sin lockup.
    2. Admin upgradea el compliance module: ahora US holders tienen lockup de 12 meses.
    3. Holder US que ya tiene tokens desde hace 1 mes no puede transferir por 11 meses más.
    4. El upgrade se aplica retroactivamente porque el contrato no trackea cuándo
       se adquirió cada token.
    5. Si el upgrade también cambia las condiciones de redención, el holder puede
       quedar completamente stuck (no puede transferir NI redimir).
    6. Variante: upgrade cambia de ERC-1404 a ERC-3643, y el nuevo compliance module
       no reconoce los claims del viejo identity registry.
  invariante: |
    // Post-upgrade: todos los holders existentes deben poder al menos redimir
    function invariant_post_upgrade_redeemable() public {
        for (uint i = 0; i < holders.length; i++) {
            if (token.balanceOf(holders[i]) > 0) {
                // Holder must be able to redeem even if transfer is restricted
                bool canRedeem = vault.canRedeem(holders[i], token.balanceOf(holders[i]));
                assert(canRedeem);
            }
        }
    }
  que_mirar:
    - "¿El token es upgradeable? ¿Qué contrato se upgradea (token, compliance, registry)?"
    - "¿Hay un timelock en los upgrades?"
    - "¿El upgrade puede cambiar quién puede holdear tokens?"
    - "grep: '_authorizeUpgrade' o 'upgradeToAndCall' — ¿quién puede upgradear?"
    - "¿Hay migration functions para actualizar el estado de holders existentes post-upgrade?"
    - "¿El storage layout es compatible entre versiones?"
  como_se_arregla: >
    Implementar timelock largo (7-30 días) para upgrades de compliance. Emitir evento
    de warning antes del upgrade para que holders puedan redimir. Implementar
    grandfathering: holders existentes mantienen las reglas vigentes al momento de
    adquirir sus tokens. Siempre mantener la función de redeem operativa post-upgrade.
  trampas:
    - "Upgrades de compliance son NECESARIOS para cumplir con nuevas regulaciones — no son un bug per se"
    - "El riesgo es la retroactividad y la falta de migration, no el upgrade en sí"
    - "Timelocks muy largos pueden ser un problema si la regulación exige acción inmediata"
  solodit_ids:
    - "missing-storage-gap-in-upgradeable-parent-contract-causes-storage-slot-collision-risk-cyfrin-none-securitize-vaultv2-rwasegwrap-markdown"
    - "upgradeable-contracts-which-are-inherited-from-should-use-erc7201-namespaced-storage-layouts-or-storage-gaps-to-prevent-storage-collision-cyfrin-none-securitize-public-stock-ramp-markdown"
    - "upgradeable-contracts-which-are-inherited-from-should-use-erc7201-namespaced-storage-layouts-or-storage-gaps-to-prevent-storage-collision-cyfrin-none-securitize-bridge-cctp-markdown"
    - "upgradeable-contract-initializer-not-disabled-in-constructor-allows-implementation-contract-initialization-cyfrin-none-securitize-vaultv2-rwasegwrap-markdown"
    - "no-storage-gap-for-upgradeable-contract-might-lead-to-storage-slot-collision-cyfrin-none-securitize-redemptions-markdown"
    - "oracle-upgrades-can-make-prices-inaccessible-openzeppelin-none-uma-oracle-bridging-contracts-upgrade-audit-markdown"
  incidentes:
    - "Securitize VaultV2 RWASegWrap (Cyfrin, MEDIUM) — missing storage gap en parent contract causa risk de storage collision en upgrade"
    - "Securitize (Cyfrin, MEDIUM) — initializer no deshabilitado en constructor permite inicialización de implementation contract"
    - "UMA Oracle (OpenZeppelin, MEDIUM) — oracle upgrades pueden hacer precios inaccesibles"
  verificado: true
  confianza: alta
```

---

## 9. Bugs Conocidos — Escrow & Pool Accounting

### Pool Manager Steals Pending Deposits

```yaml
- id: rwa-015
  titulo: "Pool manager roba depósitos pendientes del escrow global via request manager swap"
  causa_raiz: >
    En protocolos con escrow global (como Centrifuge V3), los depósitos de usuarios
    van a un escrow compartido mientras se procesan. Si el sistema de request managers
    es pluggable (cada pool puede setear su propio request manager), un pool manager
    malicioso puede crear requests fraudulentos con un request manager malicioso,
    luego swapear al request manager legítimo para recibir callbacks que transfieren
    fondos del escrow global a su pool.
  como_funciona: >
    1. Centrifuge V3 usa un globalEscrow para depósitos pendientes de todos los pools.
    2. Pool manager A setea un requestManager malicioso para su pool.
    3. Via el requestManager malicioso, crea deposit requests fraudulentos.
    4. Swapea requestManager al AsyncRequestManager legítimo.
    5. Triggerea approvedDeposits callback en el AsyncRequestManager legítimo.
    6. AsyncRequestManager transfiere fondos del globalEscrow al escrow de pool A.
    7. Pool A recibe fondos de OTROS pools — robo directo.
  invariante: |
    // El escrow global debe tener >= sum of all pending deposits
    function invariant_escrow_solvent() public {
        uint256 escrowBalance = underlying.balanceOf(address(globalEscrow));
        uint256 totalPending = 0;
        for (uint i = 0; i < pools.length; i++) {
            totalPending += pools[i].pendingDeposits();
        }
        assert(escrowBalance >= totalPending);
    }
  que_mirar:
    - "¿Los deposit requests están vinculados al request manager que los creó?"
    - "¿Se puede cambiar el request manager con requests pendientes?"
    - "grep: 'requestManager' o 'setRequestManager' — ¿hay validación?"
    - "¿El escrow es global (compartido) o per-pool?"
  como_se_arregla: >
    Vincular cada request al request manager que lo creó. Al cambiar request manager,
    cancelar o migrar todos los requests pendientes. No permitir que un nuevo request
    manager procese requests creados por otro.
  trampas:
    - "Este es un bug específico de Centrifuge V3 — no aplica a protocolos con escrow per-pool"
    - "La gravedad es CRITICAL porque permite robo directo de fondos de otros pools"
  solodit_ids:
    - "h-1-pool-managers-can-steal-all-other-pools-pending-deposits-from-globalescrow-via-malicious-requestmanager-swapping-sherlock-centrifuge-protocol-v3-audit-git"
    - "centrifuge-router-can-perform-untrusted-actions-on-behalf-of-open-vaults-spearbit-none-centrifuge-pdf"
    - "some-functions-of-centrifugerouter-dont-check-vault-validity-spearbit-none-centrifuge-pdf"
  incidentes:
    - "Centrifuge V3 (Sherlock, HIGH) — pool managers pueden robar todos los depósitos pendientes de globalEscrow via malicious requestManager swapping"
    - "Centrifuge (Spearbit, MEDIUM) — router puede ejecutar acciones no-trusted en nombre de vaults abiertos"
  verificado: true
  confianza: alta
```

### Ondo Finance Burner/KYC Interaction

```yaml
- id: rwa-016
  titulo: "Burner no puede quemar tokens de cuentas no-KYC verificadas por check en _beforeTokenTransfer"
  causa_raiz: >
    El token RWA tiene un check de KYC en _beforeTokenTransfer que verifica que AMBAS
    partes (sender y receiver) estén KYC verificadas. Pero el burn (transfer a address(0))
    falla porque address(0) no está KYC verificado. Esto impide que el compliance
    operator queme tokens de cuentas sanctioned o con KYC expirado.
  como_funciona: >
    1. Inversor A tiene KYC expirado o es sanctioned.
    2. Compliance officer intenta burn tokens de A: burn(A, amount).
    3. Internamente, burn llama _transfer(A, address(0), amount).
    4. _beforeTokenTransfer verifica isKYCVerified(address(0)) → false.
    5. Transacción reverts. Tokens de A no pueden ser quemados.
    6. A sigue holdeholding tokens que deberían haber sido confiscados.
    7. Alternativa: si A mismo pierde KYC, tampoco puede transferir NI ser burnado.
  invariante: |
    // El burner debe poder quemar tokens de CUALQUIER dirección
    function invariant_burner_can_always_burn() public {
        // Even if target is not KYC verified
        vm.prank(burner);
        try token.burn(targetAddr, 1) {
            // Success — correct behavior
        } catch {
            // Revert — bug! Burner should always be able to burn
            assert(false);
        }
    }
  que_mirar:
    - "grep: '_beforeTokenTransfer' o '_update' — ¿exempta burn (to == address(0))?"
    - "grep: 'burn' — ¿usa _transfer() o una función separada?"
    - "¿El KYC check se aplica a mint (from == address(0)) y burn (to == address(0))?"
    - "¿Hay un bypass para operaciones de compliance (BURNER_ROLE, COMPLIANCE_ROLE)?"
  como_se_arregla: >
    Eximir burn de la compliance check en _beforeTokenTransfer:
    if (to != address(0)) { require(isKYCVerified(to)); }
    O: dar al BURNER_ROLE un bypass explícito del KYC check.
  trampas:
    - "No confundir con el seize pattern (transfer a recovery address) vs burn (destroy tokens)"
    - "Algunos protocolos deliberadamente impiden burn de no-KYC como safety measure — verificar diseño"
  solodit_ids:
    - "m-04-the-burner-cannot-burn-tokens-from-accounts-not-kyc-verified-due-to-the-check-in-_beforetokentransfer-code4rena-ondo-finance-ondo-finance-git"
    - "m-01-admin-should-be-able-to-refund-or-redeem-the-sanctioned-users-code4rena-ondo-finance-ondo-finance-contest-git"
  incidentes:
    - "Ondo Finance (C4, MEDIUM) — burner no puede quemar tokens de cuentas no-KYC verificadas por check en _beforeTokenTransfer"
    - "Ondo Finance (C4, MEDIUM) — admin debería poder refund/redeem de usuarios sanctioned pero no puede"
  verificado: true
  confianza: alta
```

---

## 10. Bugs Conocidos — Fractional Ownership & Miscellaneous

### Fractional Ownership Recombination

```yaml
- id: rwa-017
  titulo: "Reassembling fracciones de token bypasses restricciones per-unit"
  causa_raiz: >
    Cuando un activo (NFT de propiedad, arte, bono) se fracciona en tokens fungibles,
    las restricciones que aplican a la unidad completa (e.g., mínimo de inversión,
    número máximo de holders, acreditación) pueden no aplicarse a las fracciones.
    Si las fracciones se acumulan, un holder puede recombinarlas para obtener el
    activo original sin haber pasado por las restricciones de compra de la unidad.
  como_funciona: >
    1. NFT de propiedad valorado en $100K se fracciona en 100 tokens de $1K cada uno.
    2. Restricción: solo inversores acreditados pueden comprar units >= $50K.
    3. Inversor no-acreditado compra 50 fracciones de $1K (cada una < $50K threshold).
    4. Acumula las 50 fracciones — ahora tiene $50K en el activo.
    5. Invoca recombine() o buyout() para obtener el NFT original.
    6. Nunca fue verificado como inversor acreditado para esa cantidad.
    7. Variante: si hay máximo de 500 holders (Reg D), las fracciones se transfieren
       entre muchas wallets del mismo individuo, inflando artificialmente el holder count.
  invariante: |
    // El número de holders de fracciones no debe exceder el máximo regulatorio
    function invariant_max_holders() public {
        uint256 holderCount = 0;
        for (uint i = 0; i < allAddresses.length; i++) {
            if (fractionToken.balanceOf(allAddresses[i]) > 0) {
                holderCount++;
            }
        }
        assert(holderCount <= MAX_HOLDERS); // e.g., 500 for Reg D
    }

    // Recombination debe verificar acreditación para la cantidad total
    function invariant_recombine_compliance() public {
        // Before any recombine/buyout, verify compliance for full unit value
    }
  que_mirar:
    - "grep: 'recombine' o 'buyout' o 'merge' o 'unfractionate' — ¿hay compliance check?"
    - "¿El protocolo trackea holder count? ¿Puede exceder el máximo regulatorio?"
    - "¿Las fracciones tienen minimum investment requirement separado del activo completo?"
    - "¿Las transfers de fracciones verifican que el recipient tiene acreditación adecuada?"
  como_se_arregla: >
    Implementar compliance check en recombination: verificar que el holder cumple los
    requisitos para la cantidad total, no solo para cada fracción individual.
    Trackear holder count on-chain y revertir transfers que excedan el máximo.
    Implementar minimum holding period entre compra de fracciones y recombination.
  trampas:
    - "El maximum holder count (500 para Reg D) es un requisito legal, no técnico — pero el contrato debería enforcearlo"
    - "Sybil attacks (múltiples wallets, mismo individuo) son un problema de identity, no de contrato"
    - "Algunos protocolos no permiten recombination — solo redención pro-rata"
  solodit_ids:
    - "h-16-migratefractions-may-be-called-more-than-once-by-the-same-user-which-may-lead-to-loss-of-tokens-for-other-users-code4rena-fractional-fractional-v2-contest-git"
    - "h-06-any-fractions-deposited-into-any-proposal-can-be-stolen-at-any-time-until-it-is-commited-code4rena-fractional-fractional-v2-contest-git"
    - "h-11-users-can-lose-fractions-to-precision-loss-during-migraction-if-_newfractionsupply-is-set-very-low-code4rena-fractional-fractional-v2-contest-git"
    - "h-05-migrationwithdrawcontribution-falsely-assumes-that-user-should-get-exactly-his-original-contribution-back-code4rena-fractional-fractional-v2-contest-git"
    - "m-07-buyout-module-fraction-price-is-not-updated-when-total-supply-changes-code4rena-fractional-fractional-v2-contest-git"
  incidentes:
    - "Fractional V2 (C4, HIGH) — migrateFractions puede llamarse más de una vez por el mismo usuario, causando pérdida de tokens para otros"
    - "Fractional V2 (C4, HIGH) — fracciones depositadas en proposals pueden ser robadas antes del commit"
    - "Fractional V2 (C4, HIGH) — users pierden fracciones por precision loss si newFractionSupply es muy bajo"
    - "Fractional V2 (C4, MEDIUM) — buyout module fraction price no se actualiza cuando totalSupply cambia"
  verificado: true
  confianza: alta
```

### Blacklisted User Transfer via Compliance Whitelist Gap

```yaml
- id: rwa-018
  titulo: "preTransferCheck permite a usuarios blacklisted transferir tokens por gap en compliance service"
  causa_raiz: >
    El compliance service tiene dos funciones: preTransferCheck (para transfers regulares)
    y newPreTransferCheck (para transfers nuevos). Si una de ellas no verifica el
    blacklist status del sender/receiver, un usuario blacklisted puede transferir
    tokens usando el path que no verifica. También: si getComplianceTransferableTokens
    retorna un amount positivo para usuarios blacklisted, el frontend muestra que
    pueden transferir (aunque la transfer debería fallar).
  como_funciona: >
    1. Usuario A es blacklisted en el compliance service.
    2. preTransferCheck(A, B, amount) debería revertir, pero no verifica blacklist.
    3. A transfiere tokens a B exitosamente.
    4. O: getComplianceTransferableTokens(A) retorna amount > 0 para usuario blacklisted.
    5. Frontend muestra "transferable: X tokens" a A. A intenta transferir.
    6. Si la transfer function SÍ verifica blacklist, la tx reverts (inconsistencia UX).
    7. Si la transfer function NO verifica blacklist, tokens se mueven — bypass completo.
  invariante: |
    // Usuarios blacklisted no deben poder transferir NI recibir tokens
    function invariant_blacklisted_no_transfer() public {
        for (uint i = 0; i < blacklisted.length; i++) {
            address bl = blacklisted[i];
            // Can't send
            assert(compliance.preTransferCheck(bl, anyAddr, 1) == false);
            // Can't receive
            assert(compliance.preTransferCheck(anyAddr, bl, 1) == false);
            // Transferable should be 0
            assert(compliance.getComplianceTransferableTokens(bl) == 0);
        }
    }
  que_mirar:
    - "grep: 'preTransferCheck' y 'newPreTransferCheck' — ¿ambos verifican blacklist?"
    - "grep: 'getComplianceTransferableTokens' — ¿retorna 0 para blacklisted?"
    - "¿Hay múltiples compliance services (global whitelist, regulated, etc.) con checks diferentes?"
    - "¿El blacklist check está en el token O en el compliance service? ¿En ambos?"
  como_se_arregla: >
    Verificar blacklist en TODOS los paths de compliance check. getComplianceTransferableTokens
    debe retornar 0 para blacklisted users. Centralizar la blacklist check en un lugar
    que sea llamado por TODAS las funciones de compliance.
  trampas:
    - "Hay protocolos con whitelist (solo whitelisted pueden transferir) vs blacklist (blacklisted no pueden) — lógica inversa"
    - "Global whitelist y regulated compliance pueden tener reglas diferentes — verificar ambos"
  solodit_ids:
    - "complianceserviceglobalwhitelistednewpretransfercheck-and-pretransfercheck-allow-blacklisted-users-to-transfer-tokens-cyfrin-none-securitize-global-registry-markdown"
    - "complianceserviceglobalwhitelistedgetcompliancetransferabletokens-returns-positive-token-amount-for-blacklisted-users-cyfrin-none-securitize-global-registry-markdown"
    - "inherited-accesscontrolupgradeable-functions-bypass-some-validation-checks-cyfrin-none-securitize-global-registry-markdown"
  incidentes:
    - "Securitize Global Registry (Cyfrin, HIGH) — preTransferCheck y newPreTransferCheck permiten a blacklisted users transferir tokens"
    - "Securitize Global Registry (Cyfrin, MEDIUM) — getComplianceTransferableTokens retorna amount positivo para blacklisted users"
  verificado: true
  confianza: alta
```
```

---

## 11. Bugs Conocidos — Cross-Chain & Bridge

### Bridge Compliance Bypass via Uninitialized Country

```yaml
- id: rwa-019
  titulo: "Country no inicializado en bridge permite bypasear lockup de compliance por jurisdicción"
  causa_raiz: >
    Cuando tokens RWA se bridgean cross-chain (e.g., via CCTP), la wallet destino se
    registra como inversor en la chain destino. Si el country attribute no se inicializa
    correctamente durante el bridging, la wallet queda sin country — y el compliance
    check que verifica lockup periods por jurisdicción (e.g., US = 12 meses lockup)
    no aplica el lockup porque country == 0 (undefined).
  como_funciona: >
    1. Inversor US bridgea tokens RWA de Ethereum a Base via CCTP.
    2. En Base, el bridge registra la wallet como inversor pero no setea el country.
    3. Country = 0 (undefined). El compliance check para US lockup dice:
       if (country == US_CODE) { require(holdingPeriod >= 12 months); }
    4. Country no es US_CODE — check pasa. Inversor puede transferir inmediatamente.
    5. Bypass del lockup period de 12 meses para inversores US.
    6. Violación de Regulation D/S.
  invariante: |
    // Todo inversor registrado debe tener country != 0
    function invariant_investor_has_country() public {
        for (uint i = 0; i < registeredInvestors.length; i++) {
            address inv = registeredInvestors[i];
            if (identityRegistry.isVerified(inv)) {
                uint256 country = identityRegistry.getCountry(inv);
                assert(country != 0); // Must have a valid country
            }
        }
    }
  que_mirar:
    - "grep: 'registerInvestor' o 'registerWallet' en el bridge — ¿setea country?"
    - "¿El bridge transmite el country de la chain origen a la chain destino?"
    - "¿Qué pasa si country == 0? ¿Se bypasean checks o se bloquea la operación?"
    - "¿Hay una función de update que un keeper deba llamar después del bridge?"
  como_se_arregla: >
    El bridge debe transmitir el country del inversor cross-chain y setearlo en el
    registro de la chain destino. Si no puede (limitación de payload), bloquear
    transfers hasta que un admin setee el country. require(country != 0) en toda
    compliance check.
  trampas:
    - "Solo aplica a bridges de tokens RWA con compliance — bridges genéricos no tienen este problema"
    - "Si el bridge es operado por el compliance operator, puede setear country off-chain — pero con latencia"
  solodit_ids:
    - "uninitialized-country-for-valid-investor-wallets-allows-bypassing-us-compliance-lockup-period-cyfrin-none-securitize-bridge-cctp-markdown"
    - "broken-identity-to-wallet-binding-in-redeem-allows-country-restriction-bypass-cyfrin-none-securitize-solana-redemption-markdown"
    - "pendingre-executable-messages-sourced-from-old-bridge-addresses-will-not-be-executable-if-bridge-address-is-updated-cyfrin-none-securitize-bridge-cctp-markdown"
  incidentes:
    - "Securitize Bridge CCTP (Cyfrin, HIGH) — uninitialized country para wallets permite bypasear US compliance lockup period"
    - "Securitize Solana Redemption (Cyfrin, HIGH) — broken identity-to-wallet binding permite country restriction bypass"
  verificado: true
  confianza: alta
```

---

## 12. Checklists rápidos por tipo de protocolo

### Checklist: Token RWA (ERC-20 con compliance)
```
[ ] _beforeTokenTransfer cubre transfer, transferFrom, mint, burn
[ ] Compliance check incluye sender AND receiver verification
[ ] Blacklist check en TODOS los paths (preTransferCheck + newPreTransferCheck)
[ ] Permit (EIP-2612) no bypasses compliance
[ ] Burn/seize funciona para cuentas no-KYC
[ ] Forced transfer va a dirección accesible (no stuck)
[ ] Pause bloquea TODOS los movimientos de tokens
[ ] Country attribute inicializado para todos los inversores
[ ] Claims/KYC tienen expiry verificado en transfer
[ ] Storage gaps en contratos upgradeable
```

### Checklist: Vault/Pool RWA (deposit/redeem)
```
[ ] NAV oracle tiene staleness check
[ ] NAV circuit breaker para cambios grandes
[ ] Redemptions son epoch-based o rate-limited
[ ] Escrow es per-pool (no global sin protección)
[ ] Request manager no se puede swapear con requests pendientes
[ ] Waterfall priority es enforceada en distribución
[ ] Backing ratio se verifica post-operación
[ ] No flash-loan deposit+mint en mismo block
[ ] Post-maturity pricing es correcto (= face value)
[ ] Off-chain settlement tiene rollback mechanism
```

### Checklist: Bridge RWA (cross-chain)
```
[ ] Country attribute se transmite cross-chain
[ ] Identity binding se mantiene cross-chain
[ ] Compliance checks aplican en chain destino
[ ] Bridge messages pausables no causan tokens stuck
[ ] Bridge address update no invalida messages pendientes
```

---

## 13. Protocolos de referencia

| Protocolo | Tipo | Estándar | Findings conocidos | Audits |
|-----------|------|----------|-------------------|--------|
| Centrifuge/Tinlake | Lending pools RWA | ERC-7540, ERC-1404 | globalEscrow theft, router untrusted actions | Sherlock 2025, Spearbit 2024, Cantina 2024 |
| Ondo Finance | USDY/OUSG tokens | Custom compliance | Burner KYC block, cash redemption loss, KYC replay | C4 2023, Cyfrin 2024 |
| Securitize | Transfer agent + tokens | DS Protocol (custom) | Blacklist bypass, country bypass, seized tokens stuck | Cyfrin 2024-2025 (10+ audits) |
| Maple Finance | Lending pools | Custom | Unaccounted collateral, depositor front-run, interest desync | Spearbit 2022, Cantina 2024 |
| Goldfinch | Credit pools | Custom | Protection buyer multiple buys | Sherlock (Carapace) 2023 |
| Fractional V2 | NFT fractionalization | Custom | Migration exploits, fraction price rounding, stolen fractions | C4 2022 |
| MakerDAO RWA | CDP vaults | Custom | Pocket USDC manipulation, controller role issues | Cantina 2024 |
| Strata Tranches | Yield tranching | Custom | Junior tranche front-running, tranche deposit DoS | Cyfrin 2025 |
| Buck Labs | Collateral ratio | Custom | Temporal ratio inflation, setCashInFlight reordering | Spearbit 2024 |

---

## 14. Notas para el hunter

**Lo que diferencia RWA de DeFi puro**:
1. **Compliance es ley, no feature** — un bypass de transfer restriction es una violación legal, no solo un bug técnico. La severidad siempre sube.
2. **Off-chain state matters** — el activo subyacente existe en el mundo real. El estado on-chain puede diverger de la realidad sin que haya un bug de código.
3. **Operator trust model** — hay más roles privilegiados (compliance officer, transfer agent, NAV provider, forced transfer operator). El attack surface de centralization es mayor.
4. **Regulatory jurisdiction** — un bug que no importa en US puede ser crítico en EU (o viceversa). El country check es crucial.
5. **Upgradability** — casi todos los tokens RWA son upgradeable porque las regulaciones cambian. Storage collision y retroactive rule changes son risks reales.

**High-value targets para hunting**:
- Transfer restriction bypasses (siempre reportables, regulators lo toman en serio)
- NAV oracle manipulation (arbitrage directo, fund loss)
- Escrow/pool accounting (direct fund theft)
- Blacklist/whitelist gaps (regulatory violation = high severity)
- Cross-chain compliance bypass (novel attack surface, poco auditado)
