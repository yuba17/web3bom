# DeFi Insurance & Cover Protocols — Combat Briefing

> Everything an auditor needs before reading a DeFi insurance, cover, or parametric insurance contract.
> Sources: Solodit DB (InsureDAO, Tidal, Y2K, SCProtection, Adrena findings), Cover Protocol post-mortem (PeckShield/Mudit Gupta),
> Nexus Mutual incident report, InsurAce UST depeg claims, DeFiHackLabs exploit DB.

---

## 0. Modelo Mental — Cómo Funcionan los Protocolos de Insurance

### Actores principales:
- **Cover buyer** — paga premiums para proteger sus posiciones (e.g., smart contract hack, depeg)
- **Underwriter / Capital provider** — deposita capital en risk pools para ganar yield de premiums, asumiendo riesgo de claims
- **Claim assessor / Voter** — evalúa claims y vota si son válidos (puede ser governance, staker, o oracle)
- **Parametric oracle** — en insurance paramétrico, decide automáticamente si el trigger event ocurrió

### Flujo de dinero típico:
```
Premium (buyer) → Risk Pool ← Capital (underwriter)
                      ↓
              Claim Payout (si evento ocurre)
```

### Variantes principales:
1. **Discretionary** (Nexus Mutual) — stakers votan para aprobar/rechazar claims
2. **Parametric** (Neptune Mutual, Y2K) — payout automático si oracle confirma evento (depeg, hack)
3. **Hybrid** (InsurAce) — oracle + governance para validar claims

### Superficies de ataque únicas de insurance:
- La tensión entre cover buyers y underwriters crea incentivos adversariales
- Los claim assessment processes son atacables vía governance/vote manipulation
- Los risk pools tienen timing attacks únicos (depositar antes de claim, retirar antes de payout)
- La correlación de riesgos puede causar insolvencia sistémica (e.g., UST depeg afecta todos los pools)

---

## 1. Bugs Conocidos

### 1.1 Cover Pool Insolvency — Claims Exceed Pool Capital

```yaml
- id: ins-001
  titulo: "Insolvencia del pool de capital — últimos reclamantes pierden fondos"
  causa_raiz: >
    En protocolos de insurance discretionary o paramétrico, el pool de capital
    puede ser insuficiente para cubrir todas las claims si: (a) los premiums
    cobrados no reflejan el riesgo real, (b) múltiples eventos correlacionados
    disparan claims simultáneas, o (c) no hay un mecanismo de socialización
    de pérdidas. Los primeros en reclamar cobran 100%, los últimos reciben
    nada — es un first-come-first-served race condition.
  como_funciona: |
    1. Risk pool tiene $1M en capital de underwriters
    2. Se venden $5M en covers (apalancamiento 5:1 — común en insurance DeFi)
    3. Evento trigger ocurre (e.g., exploit del protocolo cubierto)
    4. Primeros claimants llaman claim() y drenan el pool
    5. Últimos claimants ven el pool vacío — claim() revierte o retorna 0
    6. No hay mecanismo de backstop ni socialización proporcional
  invariante: |
    // INV: Si hay claims válidas, cada claimant debe recibir al menos
    // su parte proporcional (pro-rata) del capital disponible
    function check_prorata_payout() internal view {
        if (totalValidClaims > poolBalance) {
            for (uint i = 0; i < claimants.length; i++) {
                uint256 expected = claimants[i].amount * poolBalance / totalValidClaims;
                assertGte(claimants[i].received, expected - 1,
                    "INS-001: claimant received less than pro-rata share");
            }
        }
    }
  que_mirar:
    - "¿El payout es first-come-first-served o pro-rata?"
    - "¿Hay un coverage ratio mínimo enforceado (e.g., pool >= 50% de total cover)?"
    - "¿Existe un mecanismo de backstop (treasury, secondary pool, reinsurance)?"
    - "¿Se puede comprar cover ilimitado contra un pool finito?"
    - "¿Qué pasa cuando totalActiveCover > poolCapital?"
  como_se_arregla: >
    Implementar payout pro-rata cuando claims excedan capital disponible.
    Enforcer coverage ratio mínimo (MCR — Minimum Capital Requirement).
    Limitar cover vendido como porcentaje del pool. Implementar reinsurance
    o backstop treasury. Socializar pérdidas proporcionalmente.
  trampas:
    - "Algunos protocolos diseñan intencionalmente apalancamiento alto (5-10x) — verificar si es by design y documentado"
    - "MCR checks pueden existir solo en buy() pero no se re-verifican cuando capital se retira"
    - "El evento puede ser parcial (depeg al 50%) — payout no tiene que ser 100%"
  solodit_ids:
    - m-04-system-debt-is-not-handled-when-insurance-pools-become-insolvent-code4rena-insuredao-insuredao-contest-git
    - insurance-funding-rate-increases-indefinitely-sigmaprime-none-tracer-pdf
    - m-15-partial-repayment-is-not-possible-in-liquidation-if-no-funds-on-the-insurance-pool-pashov-audit-group-none-sharwafinance-markdown
  incidentes:
    - "InsurAce UST Depeg (May 2022) — $11.7M in claims against ~$94K in premiums collected. Protocol honored claims but exposed systemic risk of correlated depeg events across DeFi."
    - "InsureDAO (Code4rena) — M-04: System debt not handled when insurance pools become insolvent, leaving last claimants with nothing (MEDIUM)"
    - "Sharwafinance (Pashov) — M-15: Partial repayment not possible in liquidation when insurance pool has no funds (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.2 Premium Calculation Manipulation — Flash-Staking to Reduce Rates

```yaml
- id: ins-002
  titulo: "Manipulación de cálculo de premiums via flash-staking"
  causa_raiz: >
    Los premiums se calculan como función del ratio utilization = totalCover / poolCapital.
    Si un atacante puede inflar poolCapital temporalmente (vía flash loan + stake),
    el utilization ratio baja y con él el premium rate. El atacante compra cover
    barato y luego retira el stake. El pool queda con cover vendido a precio
    inferior al riesgo real.
  como_funciona: |
    1. Premium = basePremium * (totalCover / poolCapital) — a más capital, menor premium
    2. Atacante flash-loans $10M → deposita en risk pool → poolCapital sube
    3. En la misma tx: compra cover a premium reducido (utilization bajó)
    4. Atacante retira stake del pool → repaga flash loan
    5. Pool queda con cover vendido a premium insuficiente para el riesgo real
    6. Si ocurre el evento, el pool no tiene suficiente capital
  invariante: |
    // INV: El premium cobrado por unidad de cover debe reflejar el utilization
    // DESPUÉS de la compra, no antes
    function check_premium_post_purchase() internal view {
        uint256 utilizationAfter = totalActiveCover * 1e18 / poolCapital;
        uint256 expectedPremium = calculatePremium(utilizationAfter);
        assertGte(lastPremiumCharged, expectedPremium,
            "INS-002: premium charged is below post-purchase utilization rate");
    }
  que_mirar:
    - "¿El premium se calcula con el estado ANTES o DESPUÉS de la compra?"
    - "¿Se puede depositar y retirar capital en la misma transacción?"
    - "¿Hay un lock period mínimo para capital providers?"
    - "¿Se puede comprar cover con flash-loaned tokens?"
    - "¿El cálculo de premium usa un TWAP o lectura instantánea?"
  como_se_arregla: >
    Calcular premium basado en utilization POST-compra. Enforcer lock period mínimo
    para capital providers (e.g., 7 días). Usar TWAP de utilization en vez de
    lectura instantánea. Prevenir stake + buy + unstake en mismo bloque.
  trampas:
    - "Si hay cooldown de 7+ días para unstake, flash-staking no es viable — confirmar que el cooldown realmente se enforcea"
    - "Premiums fijos (no dependientes de utilization) no son vulnerables a este vector"
    - "El ataque puede no ser rentable si el premium savings < gas + flash loan fees"
  solodit_ids:
    - addpremium-a-back-runner-may-cause-an-insurance-holder-to-lose-their-refunds-by-calling-addpremium-right-after-the-original-call-fixed-consensys-none-tidal-markdown
    - poolbuy-users-may-end-up-paying-more-than-intended-due-to-changes-in-policyweeklypremium-fixed-consensys-none-tidal-markdown
    - m-12-avoid-paying-insurance-code4rena-tracer-tracer-git
  incidentes:
    - "Tidal (Consensys) — addPremium back-runner can cause insurance holder to lose refunds by calling addPremium right after original call (HIGH)"
    - "Tidal (Consensys) — Pool.buy: users may end up paying more than intended due to changes in policy.weeklyPremium mid-transaction (MEDIUM)"
    - "Tracer (Code4rena) — M-12: Users can avoid paying insurance by manipulating calculations (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.3 Claim Assessment Oracle Manipulation

```yaml
- id: ins-003
  titulo: "Manipulación de oracle para triggear claims falsas"
  causa_raiz: >
    En insurance paramétrico, el payout depende de un oracle que reporta si el
    evento ocurrió (e.g., precio del token cayó debajo de threshold = depeg).
    Si el oracle usa un spot price manipulable (e.g., DEX TWAP corto, Chainlink
    con circuit breakers), un atacante puede manipular el precio temporalmente
    para triggear el claim y cobrar el payout sin que el evento real haya ocurrido.
  como_funciona: |
    1. Insurance paramétrico: si precio de TOKEN < $0.95 → depeg trigger → payout
    2. Oracle usa Uniswap V3 TWAP con ventana corta (e.g., 10 min)
    3. Atacante flash-loans capital → ejecuta swap masivo en Uniswap pool
    4. Precio del par baja temporalmente debajo de $0.95
    5. Atacante llama triggerDepeg() que lee el oracle → confirma depeg
    6. Atacante cobra payout del pool de insurance
    7. Precio se recupera después del flashloan — no hubo depeg real
  invariante: |
    // INV: El trigger oracle debe ser resistente a manipulación single-block
    function check_oracle_manipulation_resistance() internal view {
        // El TWAP window debe ser >= 30 minutos
        assertGte(oracleWindow, 30 minutes,
            "INS-003: oracle TWAP window too short for manipulation resistance");
        // Verificar que no se pueda triggear y cobrar en mismo bloque
        assertGt(block.timestamp - lastTriggerTimestamp, 1,
            "INS-003: trigger and claim in same block");
    }
  que_mirar:
    - "¿Qué oracle usa el protocolo para determinar el evento trigger?"
    - "¿El TWAP window es suficiente (>= 30 min para resistir flash loans)?"
    - "¿Hay un grace period entre trigger y payout (e.g., challenge window)?"
    - "¿El trigger requiere confirmación de múltiples fuentes?"
    - "¿Se puede triggear y cobrar en la misma transacción?"
    - "¿Hay circuit breakers en el oracle que pueden causar false positives?"
  como_se_arregla: >
    Usar TWAP con ventana >= 30 minutos. Requerir confirmación multi-oracle
    (Chainlink + Uniswap). Implementar challenge period después del trigger
    donde se puede disputar. Prevenir trigger + claim en misma tx. Usar
    Chainlink con circuit breaker checks.
  trampas:
    - "Chainlink circuit breakers pueden CAUSAR false triggers si el precio reportado se congela en un valor stale durante crash real"
    - "TWAP largo protege contra flash loans pero no contra manipulación sostenida (e.g., gradual drain)"
    - "Algunos protocolos usan Chainlink como primary + DEX TWAP como secondary — verificar ambos"
  solodit_ids:
    - m-11-arbitrum-sequencer-downtime-lasting-before-and-beyond-epoch-expiry-prevents-triggering-depeg-sherlock-none-y2k-git
    - h-02-end-epoch-cannot-be-triggered-preventing-winners-to-withdraw-code4rena-y2k-finance-y2k-finance-contest-git
    - m-13-null-epochs-will-freeze-rollovers-sherlock-none-y2k-git
  incidentes:
    - "Y2K Finance (Sherlock) — M-11: Arbitrum sequencer downtime lasting before and beyond epoch expiry prevents triggering depeg — oracle goes stale, valid claims blocked (MEDIUM)"
    - "Y2K Finance (Code4rena) — H-02: End epoch cannot be triggered, preventing winners from withdrawing payouts (HIGH)"
    - "Y2K Finance (Sherlock) — M-13: Null epochs freeze rollovers, blocking claim processing (MEDIUM)"
    - "Mango Markets (Nov 2022) — $114M oracle manipulation attack on perps — same oracle manipulation vector applicable to parametric insurance"
  severidad: critical
  confianza: alta
  verificado: true
```

### 1.4 Double-Claiming — Same Incident Across Multiple Products

```yaml
- id: ins-004
  titulo: "Double-claiming: mismo incidente reclamado en múltiples productos"
  causa_raiz: >
    Cuando un usuario tiene cover en múltiples pools o productos que cubren el
    mismo riesgo subyacente (e.g., "smart contract hack" y "depeg" ambos
    aplicables al mismo exploit), puede reclamar contra ambos pools por el mismo
    evento. Si no hay un registry global de claims por incidente, el atacante
    cobra 2x o más.
  como_funciona: |
    1. Atacante compra Cover A ("smart contract hack" en Protocolo X) por $100K
    2. Atacante compra Cover B ("depeg event" en Token Y del Protocolo X) por $100K
    3. Exploit en Protocolo X causa hack Y depeg simultáneamente
    4. Atacante reclama contra Pool A: "fue un smart contract hack" → cobra $100K
    5. Atacante reclama contra Pool B: "hubo depeg del token" → cobra $100K
    6. Pérdida real del atacante: $50K. Cobro total: $200K. Profit: $150K
  invariante: |
    // INV: Un usuario no puede cobrar más que su pérdida real total
    // sumando todos los covers que tenga
    function check_no_double_claim() internal view {
        for (uint i = 0; i < users.length; i++) {
            uint256 totalPayout = getTotalPayoutAcrossAllPools(users[i]);
            uint256 totalCoverage = getTotalCoverageAmount(users[i]);
            assertLte(totalPayout, totalCoverage,
                "INS-004: user received more than total coverage across all pools");
        }
    }
  que_mirar:
    - "¿Hay un registry global de claims por incident ID?"
    - "¿Puede un usuario tener cover en múltiples pools que cubran el mismo riesgo?"
    - "¿El claim check verifica contra TODOS los pools o solo contra uno?"
    - "¿El incident ID es único por evento o por producto?"
    - "¿Se puede transferir un cover NFT después de reclamar en otro pool?"
  como_se_arregla: >
    Implementar registry global de incident IDs. Cuando se reclama, verificar
    que el usuario no haya reclamado por el mismo incidente en otro pool.
    Limitar payout total por usuario por incidente a su pérdida real
    (require proof of loss). Cover NFTs deben ser non-transferable durante
    claim window.
  trampas:
    - "Protocolos con un solo tipo de cover (e.g., solo smart contract hack) no son vulnerables a cross-product double claim"
    - "Si cada pool tiene assessors independientes, la coordinación es difícil — puede ser by design que se permita"
    - "Proof of loss es difícil de implementar on-chain"
  solodit_ids:
    - h-02-typo-in-pooltemplate-unlock-function-results-in-user-being-able-to-unlock-multiple-times-code4rena-insuredao-insuredao-contest-git
    - m-01-numerical-error-in-_claim_fees-double-counts-yield-fees-in-some-scenarios-0x52-none-adapterfi-markdown
  incidentes:
    - "InsureDAO (Code4rena) — H-02: Typo in PoolTemplate.unlock() lets user unlock (claim) multiple times — direct double-claim bug (HIGH)"
    - "InsurAce UST Depeg (May 2022) — Multiple cover types (UST depeg + Anchor protocol hack) could theoretically both trigger for same event. Protocol manually handled deduplication."
  severidad: high
  confianza: media
  verificado: true
```

### 1.5 Capital Efficiency Attack — Minimum Stake, Maximum Cover

```yaml
- id: ins-005
  titulo: "Ataque de eficiencia de capital — stake mínimo para underwrite máximo cover"
  causa_raiz: >
    Si el protocolo permite underwriters hacer stake de una cantidad mínima
    para habilitar la venta de cover mucho mayor (alto leverage ratio), un
    atacante puede: (a) como underwriter, hacer stake mínimo y ganar premiums
    desproporcionados, o (b) como buyer, explotar que el pool está
    under-capitalized comprando cover barato que nunca será pagado.
  como_funciona: |
    1. Pool permite leverage de 10:1 (sell $10 cover per $1 staked)
    2. Underwriter deposita $100 mínimo → puede underwrite $1000 en covers
    3. Underwriter gana premiums sobre $1000 en cover, arriesgando solo $100
    4. Si ocurre claim de $1000, pool solo tiene $100 → insolvencia
    5. Otros underwriters pierden su capital cubriendo el gap
    6. O: no hay suficiente capital y claimants pierden
  invariante: |
    // INV: Coverage ratio mínimo debe estar enforceado en todo momento
    function check_minimum_capital_ratio() internal view {
        uint256 ratio = poolCapital * 1e18 / totalActiveCover;
        assertGte(ratio, MIN_COVERAGE_RATIO,
            "INS-005: pool capital below minimum coverage ratio");
    }
    // INV: No se puede comprar cover si empuja ratio debajo del mínimo
    function check_cover_purchase_respects_mcr() internal view {
        uint256 ratioAfter = poolCapital * 1e18 / (totalActiveCover + newCoverAmount);
        assertGte(ratioAfter, MIN_COVERAGE_RATIO,
            "INS-005: cover purchase would violate MCR");
    }
  que_mirar:
    - "¿Hay un MCR (Minimum Capital Requirement) enforceado?"
    - "¿Se re-verifica el MCR cuando underwriters retiran capital?"
    - "¿Cuál es el leverage ratio máximo permitido?"
    - "¿El MCR se calcula globalmente o por pool individual?"
    - "¿Un underwriter puede retirar capital cuando hay claims pendientes?"
  como_se_arregla: >
    Enforcer MCR tanto al comprar cover como al retirar capital. Limitar
    leverage ratio (e.g., máximo 5:1). Re-calcular MCR dinámicamente cuando
    cambia el capital o el cover activo. Bloquear retiros de capital cuando
    MCR estaría violado post-retiro.
  trampas:
    - "MCR check solo en buy() pero no en withdraw() — la violación ocurre en el retiro, no en la compra"
    - "Nexus Mutual usa MCR global que se re-calcula por bloque — verificar frecuencia"
    - "Un ratio alto (50%+) es conservador pero reduce capital efficiency legítima"
  solodit_ids:
    - m-16-function-changecontroller-has-rug-potential-as-admin-can-unilaterally-withdraw-all-user-funds-from-both-risk-and-insure-vaults-code4rena-y2k-finance-y2k-finance-contest-git
    - users-can-sell-their-market-seat-without-paying-loss-coverage-cyfrin-none-deriverse-dex-markdown
    - excess-insurance-coverage-payments-can-get-temporarily-stuck-sigmaprime-none-brava-labs-pdf
  incidentes:
    - "Y2K Finance (Code4rena) — M-16: changeController allows admin to unilaterally withdraw all user funds from both risk and insure vaults — capital can be drained (MEDIUM)"
    - "Deriverse DEX (Cyfrin) — Users can sell market seat without paying loss coverage, exiting risk without paying obligations (MEDIUM)"
    - "Nexus Mutual — MCR calculations historically allowed capital below safe ratios during rapid cover growth periods"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.6 Claim Voting Manipulation — Vote Buying for Fraudulent Claims

```yaml
- id: ins-006
  titulo: "Manipulación del voting de claims — soborno de voters para aprobar claims falsas"
  causa_raiz: >
    En protocolos con claim assessment basado en governance (staker voting),
    los voters pueden ser sobornados on-chain vía bribe markets. Si el payout
    de la claim es mayor que el costo de sobornar suficientes voters, un
    atacante puede comprar una claim falsa. Peor: voters racionales votan
    YES en claims dudosas si el costo de investigar supera su reward por votar.
  como_funciona: |
    1. Atacante compra cover por $500K en el protocolo de insurance
    2. No ocurre ningún evento real que justifique una claim
    3. Atacante crea un bribe pool: "Vote YES en mi claim, gana X tokens"
    4. El soborno total ($50K) < payout esperado ($500K)
    5. Voters votan YES porque el bribe > su staking reward por votar NO
    6. Claim se aprueba — atacante cobra $500K del pool
    7. Underwriters pierden capital para cubrir una claim fraudulenta
  invariante: |
    // INV: El costo económico de manipular una votación debe exceder
    // el payout máximo posible
    function check_vote_manipulation_cost() internal view {
        uint256 costToFlipVote = totalStakedInAssessment * minimumStakePercent / 100;
        assertGt(costToFlipVote, maxPayoutPerClaim,
            "INS-006: cost to manipulate vote < max claim payout");
    }
  que_mirar:
    - "¿Cuánto stake se necesita para controlar la votación?"
    - "¿Los voters arriesgan su stake si votan incorrectamente (slashing)?"
    - "¿Hay un quorum mínimo para que la votación sea válida?"
    - "¿Se usa vote-escrowed tokens (ve) que no se pueden transferir?"
    - "¿Existe un challenge/dispute mechanism post-votación?"
    - "¿Los voters son recompensados/penalizados basado en el resultado final?"
  como_se_arregla: >
    Slashing para voters que votan en el lado perdedor. Quorum alto
    (>50% del total staked). Lock period largo para claim assessors
    que previene dump post-vote. Dispute mechanism con appeals court.
    Requerir stake proporcional al claim amount para iniciar claim.
  trampas:
    - "Nexus Mutual requiere NXM staking para votar — el token no es líquido, lo que dificulta bribing"
    - "Si hay pocos voters activos, el quorum puede ser trivial de alcanzar"
    - "Vote-escrowed tokens reducen pero no eliminan el riesgo — se pueden sobornar off-chain"
  solodit_ids:
    - deflating-the-total-amount-of-votes-in-a-checkpoint-to-steal-bribes-and-create-solvency-issues-immunefi-alchemix-git
    - inflation-of-total-votes-and-potential-freeze-of-unclaimable-bribes-immunefi-alchemix-git
  incidentes:
    - "Alchemix (Immunefi) — Deflating total votes in a checkpoint to steal bribes and create solvency issues — same attack pattern applicable to claim assessment (HIGH)"
    - "Alchemix (Immunefi) — Inflation of total votes and potential freeze of unclaimable bribes — vote manipulation in gauge system (HIGH)"
    - "Beanstalk (Apr 2022) — $182M governance attack via flash-loaned voting power — same vector applicable to insurance claim voting"
  severidad: critical
  confianza: media
  verificado: true
```

### 1.7 Premium-to-Claim Ratio Exploit — Buying Cover Just Before Known Incident

```yaml
- id: ins-007
  titulo: "Compra de cover justo antes de incidente conocido — front-running de claims"
  causa_raiz: >
    Si un atacante tiene información adelantada sobre un exploit o depeg
    inminente (e.g., ve la tx de exploit en el mempool, o detecta un bug
    antes de que sea explotado), puede comprar cover momentos antes del
    evento y cobrar el payout completo habiendo pagado un premium mínimo.
    El ratio premium:payout es absurdamente favorable al atacante.
  como_funciona: |
    1. Atacante detecta exploit pendiente en el mempool (o sabe del bug)
    2. Atacante compra cover por $1M, pagando premium de $200 (0.02%)
    3. En el mismo bloque o siguiente, el exploit ocurre
    4. Atacante reclama el payout: $1M
    5. Profit: $1M - $200 = $999.8K
    6. El pool pierde $1M, los underwriters absorben la pérdida
  invariante: |
    // INV: Cover comprado en las últimas N horas no debe ser elegible
    // para claims del mismo período (waiting period)
    function check_cover_waiting_period() internal view {
        for (uint i = 0; i < activeClaims.length; i++) {
            uint256 coverPurchaseTime = getCoverPurchaseTimestamp(activeClaims[i].coverId);
            uint256 incidentTime = activeClaims[i].incidentTimestamp;
            assertGte(incidentTime - coverPurchaseTime, WAITING_PERIOD,
                "INS-007: claim filed for incident within waiting period");
        }
    }
  que_mirar:
    - "¿Hay un waiting period entre compra de cover y elegibilidad para claims?"
    - "¿El waiting period es suficiente (>= 72 horas ideal)?"
    - "¿Se puede comprar cover y reclamar en la misma transacción?"
    - "¿La compra de cover es instantánea o tiene un cooldown?"
    - "¿El protocolo chequea si el incidente ocurrió ANTES de la compra?"
  como_se_arregla: >
    Enforcer waiting period mínimo de 72+ horas entre compra y elegibilidad.
    Verificar timestamp del incidente vs timestamp de compra del cover.
    Implementar anti-frontrunning (e.g., commit-reveal para compra de cover).
    Limitar cover amount comprable en una sola transacción.
  trampas:
    - "Un waiting period de 24h puede ser insuficiente — algunos exploits son predecibles con días de anticipación"
    - "Covers renovados automáticamente no deberían tener waiting period — solo primeras compras"
    - "El atacante podría comprar cover semanas antes y esperar — el waiting period no previene esto"
  solodit_ids:
    - h-2-design-of-bufferbinarypool-allows-lps-to-game-option-expiry-sherlock-buffer-finance-buffer-finance-git
    - h-04-nftxlpstaking-is-subject-to-a-flash-loan-attack-that-can-steal-nearly-all-rewardsfees-that-have-accrued-for-a-particular-vault-code4rena-nftx-nftx-git
  incidentes:
    - "Buffer Finance (Sherlock) — H-2: LPs can game option expiry by staking just before OTM expiry — same timing exploitation pattern (HIGH)"
    - "InsurAce UST Depeg (May 2022) — Some users reportedly purchased cover during the early stages of the depeg, before the full collapse. $94K in premiums vs $11.7M in claims paid out."
    - "Traditional insurance — Anti-selection (adverse selection) is the primary reason waiting periods exist in all forms of insurance"
  severidad: critical
  confianza: alta
  verificado: true
```

### 1.8 Cover NFT Transfer During Pending Claim

```yaml
- id: ins-008
  titulo: "Transferencia de Cover NFT durante claim pendiente — venta de posición cubierta"
  causa_raiz: >
    Muchos protocolos representan covers como NFTs (ERC-721). Si un usuario
    puede transferir/vender el cover NFT mientras tiene una claim pendiente,
    dos problemas emergen: (a) el comprador del NFT puede cobrar una claim
    que no le corresponde, o (b) el vendedor cobra la claim Y vende el NFT,
    obteniendo doble beneficio. Si el claim se asocia al NFT y no al usuario,
    la transferencia redirige el payout.
  como_funciona: |
    1. User A tiene cover NFT #42 con claim pendiente por $100K
    2. User A lista el NFT en OpenSea por $50K (bajo porque "puede que no paguen")
    3. User B compra el NFT por $50K
    4. La claim se aprueba — payout de $100K va al holder actual del NFT (User B)
    5. User B profit: $100K - $50K = $50K
    6. O peor: User A transfere el NFT a sí mismo en otra wallet, cobra claim Y vende el NFT
  invariante: |
    // INV: Cover NFTs con claims pendientes no deben ser transferibles
    function check_no_transfer_during_claim() internal view {
        for (uint i = 0; i < pendingClaims.length; i++) {
            uint256 coverId = pendingClaims[i].coverId;
            address currentOwner = coverNFT.ownerOf(coverId);
            address claimInitiator = pendingClaims[i].claimant;
            assertEq(currentOwner, claimInitiator,
                "INS-008: cover NFT transferred while claim is pending");
        }
    }
  que_mirar:
    - "¿El cover se representa como NFT transferible?"
    - "¿Se bloquean transferencias cuando hay claims pendientes?"
    - "¿El payout va al owner actual del NFT o al claimant original?"
    - "¿Se puede iniciar una claim desde una dirección diferente al owner?"
    - "¿El NFT tiene un hook _beforeTokenTransfer que revierte en estado CLAIMING?"
  como_se_arregla: >
    Override _beforeTokenTransfer para bloquear transferencias cuando
    hay claims pendientes. Registrar claimant address en el momento
    del claim y pagar SIEMPRE al claimant original, no al holder actual.
    Implementar soul-bound behavior durante claim window.
  trampas:
    - "Armor.fi arNFT wrapping — wrapping un cover NFT en arNFT puede evadir los transfer locks del protocolo original"
    - "Si el payout va al claimant original (no al NFT holder), el transfer durante claim es inofensivo"
    - "Algunos protocolos permiten claim transfer intencionalmente como feature (e.g., claim trading markets)"
  solodit_ids:
    - m-02-transferring-the-position-nft-while-there-is-an-unexecuted-position-might-lead-to-unexpected-situations-pashov-audit-group-none-pearlabs-markdown
    - the-operator-address-is-not-reset-after-the-position-token-transfer-mixbytes-none-algebra-finance-markdown
    - m-10-the-old-position-owner-could-cause-damage-to-the-new-position-owner-pashov-audit-group-none-pearlabs-markdown
  incidentes:
    - "Pearlabs (Pashov) — M-02: Transferring position NFT while there is an unexecuted position might lead to unexpected situations — state not cleaned on transfer (MEDIUM)"
    - "Algebra Finance (Mixbytes) — Operator address not reset after position token transfer — stale permissions persist (MEDIUM)"
    - "Armor.fi — arNFT wrapping allowed users to wrap Nexus Mutual covers as transferable ERC-721, creating secondary market for covers with potential transfer-during-claim issues"
  severidad: medium
  confianza: alta
  verificado: true
```

### 1.9 Parametric Trigger Manipulation — Oracle Attack on Automated Payouts

```yaml
- id: ins-009
  titulo: "Manipulación de trigger paramétrico — ataque al oracle de payout automático"
  causa_raiz: >
    Insurance paramétrico paga automáticamente cuando una condición on-chain
    se cumple (e.g., precio < threshold, TVL cae > X%, sequencer offline > Y horas).
    Si el atacante puede manipular las variables que el trigger lee, puede causar
    un false trigger y cobrar payout sin evento real. A diferencia de ins-003
    (oracle manipulation genérica), este patrón se centra en la lógica del
    trigger contract y sus edge cases.
  como_funciona: |
    1. Parametric insurance: trigger si TVL del protocolo cubierto cae > 50%
    2. El trigger lee TVL via totalAssets() del vault del protocolo
    3. Atacante flash-loans un retiro masivo del vault → TVL cae temporalmente > 50%
    4. Atacante llama checkTrigger() → condición se cumple → payout se activa
    5. Atacante re-deposita en el vault → TVL vuelve a normal
    6. Atacante cobra payout por "caída de TVL" que fue artificial
  invariante: |
    // INV: El trigger debe leer valores promediados, no instantáneos
    function check_trigger_uses_averaged_value() internal view {
        // El trigger no debe poder activarse y resolverse en el mismo bloque
        assertGt(triggerResolutionDelay, 0,
            "INS-009: trigger resolves in same block as activation");
        // El valor usado para trigger debe ser un promedio, no un snapshot
        assertGte(triggerObservationWindow, 1 hours,
            "INS-009: trigger observation window too short");
    }
  que_mirar:
    - "¿El trigger lee un valor instantáneo o promediado?"
    - "¿Hay un observation window / confirmation period?"
    - "¿El trigger puede activarse y resolverse en la misma transacción?"
    - "¿Las variables que lee el trigger son manipulables (balanceOf, totalAssets, etc.)?"
    - "¿Hay un dispute period después del trigger antes del payout?"
    - "¿El trigger contract usa msg.sender checks para prevenir self-triggering?"
  como_se_arregla: >
    Usar valores promediados con ventana larga (>= 1 hora). Implementar
    confirmation period: trigger se activa, espera N bloques, re-verifica.
    Usar Chainlink con heartbeat + deviation threshold en vez de on-chain reads.
    Dispute window post-trigger. Prevenir que el mismo usuario active el trigger
    y cobre el payout.
  trampas:
    - "Neptune Mutual usa un modelo semi-paramétrico con reporting + governance — no es puro oracle"
    - "Triggers basados en sequencer uptime (Arbitrum/Optimism) son más difíciles de manipular que triggers de precio"
    - "La manipulación puede costar más que el payout si el pool es pequeño"
  solodit_ids:
    - m-11-arbitrum-sequencer-downtime-lasting-before-and-beyond-epoch-expiry-prevents-triggering-depeg-sherlock-none-y2k-git
    - h-02-end-epoch-cannot-be-triggered-preventing-winners-to-withdraw-code4rena-y2k-finance-y2k-finance-contest-git
  incidentes:
    - "Y2K Finance — Built as parametric depeg insurance. Multiple audit findings around trigger mechanics: epoch triggering blocked by sequencer downtime, null epochs freezing rollovers."
    - "Neptune Mutual — Uses incident reporting + governance resolution, reducing pure oracle manipulation risk but introducing governance attack surface."
  severidad: critical
  confianza: alta
  verificado: true
```

### 1.10 Pool Share Dilution — Depositing Just Before Claim Payout

```yaml
- id: ins-010
  titulo: "Dilución de pool shares — depósito justo antes de payout para diluir stakers existentes"
  causa_raiz: >
    Si un atacante puede depositar capital en un risk pool justo ANTES de que
    se distribuya un payout de claim (pero DESPUÉS de que el evento trigger
    ocurrió), diluye las pérdidas de los underwriters existentes. Los stakers
    originales pierden más de lo esperado porque el nuevo depósito toma parte
    de su payout sin haber asumido el riesgo real.
  como_funciona: |
    1. Pool tiene $1M de 10 underwriters ($100K cada uno)
    2. Evento trigger ocurre — claim de $500K pendiente
    3. Antes de que claim se procese, atacante deposita $1M adicional
    4. Pool ahora tiene $2M capital, 11 participantes
    5. Claim de $500K se distribuye proporcionalmente: cada uno pierde 25%
    6. Los 10 stakers originales pierden $25K cada uno (debería ser $50K)
    7. El atacante deposita $1M, pierde $250K, pero gana $750K en shares
    8. O: el atacante diluye legítimamente a stakers para reducir su pérdida
  invariante: |
    // INV: Depósitos después de trigger event no deben participar en
    // el payout de claims de eventos anteriores al depósito
    function check_no_dilution_post_trigger() internal view {
        for (uint i = 0; i < recentDeposits.length; i++) {
            assertLt(recentDeposits[i].timestamp, lastTriggerTimestamp,
                "INS-010: deposit made after trigger event participates in payout");
        }
    }
  que_mirar:
    - "¿Se pueden hacer depósitos mientras hay claims pendientes?"
    - "¿Los depósitos post-trigger están excluidos del payout del evento actual?"
    - "¿Hay un deposit freeze durante claim processing?"
    - "¿El payout se calcula basado en shares al momento del trigger o al momento del payout?"
    - "¿Existe un snapshot mechanism para fijar shares al momento del evento?"
  como_se_arregla: >
    Freeze deposits durante claim processing window. Snapshot shares al
    momento del trigger event — solo shares existentes en el snapshot
    participan en el payout. Implementar epoch-based accounting donde
    depósitos en epoch N solo asumen riesgo de epoch N+1.
  trampas:
    - "El atacante también PIERDE capital por el payout — la dilución no es free money, solo redistribución"
    - "Epoch-based systems (Y2K) previenen esto por diseño — verificar que epochs no sean bypasseables"
    - "El freeze de depósitos puede causar DoS si el claim processing es lento"
  solodit_ids:
    - winning-pods-can-be-frontrun-with-large-deposits-consensys-pooltogether-pods-markdown
    - payout-distributions-to-remora-token-holders-are-diluted-by-initial-token-owner-mint-cyfrin-none-remora-pledge-markdown
    - m-30-stakingrewards-reward-rate-can-be-dragged-out-and-diluted-code4rena-concur-finance-concur-finance-contest-git
  incidentes:
    - "PoolTogether Pods (Consensys) — Winning pods can be frontrun with large deposits — same dilution pattern in insurance context (HIGH)"
    - "Remora Pledge (Cyfrin) — Payout distributions diluted by initial token owner mint — dilution via timing attack (MEDIUM)"
    - "Concur Finance (Code4rena) — M-30: StakingRewards reward rate can be dragged out and diluted — applicable to premium distribution (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.11 Withdrawal Timing Attack — Unstaking Capital When Claim Is Imminent

```yaml
- id: ins-011
  titulo: "Ataque de timing en retiros — retirar capital cuando claim es inminente"
  causa_raiz: >
    Si un underwriter puede monitorear on-chain signals de un claim inminente
    (e.g., depeg en progreso, exploit recién ocurrido, claim submitted pero
    no resuelta), puede retirar su capital del pool ANTES de que el payout
    se procese. Los underwriters restantes asumen toda la pérdida.
    Equivalent a "cancelar tu póliza de seguro cuando ves que la casa
    se está incendiando."
  como_funciona: |
    1. Underwriter tiene $100K staked en el risk pool
    2. Exploit ocurre en el protocolo cubierto — claim inminente
    3. Underwriter ve la claim en el mempool (o en la UI)
    4. Underwriter llama withdraw() → su capital sale del pool
    5. Claim se procesa — el pool tiene menos capital → otros stakers pagan más
    6. El underwriter que se retiró escapa sin pérdida
  invariante: |
    // INV: Retiros deben estar bloqueados cuando hay claims pendientes
    // o cuando el MCR se violaría
    function check_no_withdrawal_during_claims() internal view {
        if (pendingClaimsCount > 0) {
            // Verificar que no se procesaron retiros después del primer claim
            assertEq(withdrawalsAfterFirstClaim, 0,
                "INS-011: withdrawal processed while claims are pending");
        }
    }
    // INV: Cooldown mínimo para retiros
    function check_withdrawal_cooldown() internal view {
        for (uint i = 0; i < recentWithdrawals.length; i++) {
            uint256 stakeTime = getStakeTimestamp(recentWithdrawals[i].user);
            assertGte(recentWithdrawals[i].timestamp - stakeTime, MIN_STAKE_DURATION,
                "INS-011: withdrawal before minimum stake duration");
        }
    }
  que_mirar:
    - "¿Hay un cooldown period para retiros (unstake delay)?"
    - "¿Se bloquean retiros cuando hay claims pendientes?"
    - "¿El cooldown es suficiente (>= 14 días ideal para insurance)?"
    - "¿Se puede cancelar el cooldown y re-iniciar?"
    - "¿La señal de claim (submit) freeze los retiros de todo el pool?"
    - "¿Existe un unbonding period tipo PoS?"
  como_se_arregla: >
    Enforcer cooldown largo (14-30 días) para retiros. Bloquear retiros
    cuando hay claims pendientes no resueltas. Implementar epoch-based
    withdrawal: request en epoch N, ejecutar en epoch N+2. Snapshot
    stakers al momento del claim — solo stakers en snapshot pagan.
  trampas:
    - "Cooldowns muy largos desincentivan participación legítima — balance es clave"
    - "Si el cooldown empezó ANTES del evento, el retiro podría ser legítimo"
    - "Nexus Mutual tiene 90-day assessment period — suficiente para prevenir este vector"
    - "Verificar si requestWithdraw() tambien se bloquea, no solo executeWithdraw()"
  solodit_ids:
    - cooldown-deactivation-instantly-unlocks-pending-cooldown-funds-cyfrin-none-boundary-markdown
    - cooldown-manipulation-in-unstake-account-may-allow-premature-withdrawals-quantstamp-torch-finance-markdown
    - 06-users-can-sidestep-the-cooldownduration-in-an-edge-case-code4rena-loopfi-loopfi-git
  incidentes:
    - "Boundary (Cyfrin) — Cooldown deactivation instantly unlocks pending cooldown funds — allows bypassing withdrawal delay (LOW)"
    - "Torch Finance (Quantstamp) — Cooldown manipulation in unstake account may allow premature withdrawals (LOW)"
    - "LoopFi (Code4rena) — Users can sidestep cooldownDuration in edge case — withdrawal timing bypass (LOW)"
    - "Nexus Mutual — Historically, stakers could signal withdrawal during claim assessment periods. Updated to freeze exits during active claims."
  severidad: high
  confianza: alta
  verificado: true
```

### 1.12 Risk Model Bypass — Accepting Correlated Risks Without Diversification

```yaml
- id: ins-012
  titulo: "Bypass del modelo de riesgo — aceptar riesgos correlacionados sin descuento"
  causa_raiz: >
    Insurance funciona porque los riesgos se diversifican: no todos los
    protocolos sufren exploits al mismo tiempo. Pero si el pool acepta
    covers de protocolos altamente correlacionados (e.g., todos forks de
    Compound, o todos en el mismo L2), un solo evento puede triggear
    claims en TODOS los covers simultáneamente, causando insolvencia.
    El modelo de pricing no descuenta por correlación.
  como_funciona: |
    1. Pool de insurance cubre 10 protocolos, todos forks de Aave en Base
    2. Pricing model trata cada cover como riesgo independiente
    3. MCR se calcula como: max(cover_i) en vez de sum(cover_i * correlation_ij)
    4. Exploit en Aave core es encontrado — afecta a TODOS los 10 forks
    5. Claims simultáneas de los 10 protocolos superan el capital del pool
    6. Pool es insolvente — últimos claimants pierden todo
  invariante: |
    // INV: Capital reservado debe considerar correlación entre covers
    function check_correlated_risk_reserve() internal view {
        uint256 totalCorrelatedExposure = calculateCorrelatedExposure();
        assertGte(poolCapital, totalCorrelatedExposure * SAFETY_MARGIN / 100,
            "INS-012: pool capital insufficient for correlated risk exposure");
    }
  que_mirar:
    - "¿El modelo de pricing considera correlación entre protocolos cubiertos?"
    - "¿Se limita la exposición a un solo tipo de protocolo (e.g., max 30% del pool en lending forks)?"
    - "¿El MCR se calcula como max(covers) o sum(covers)?"
    - "¿Se agrupan protocolos por stack tecnológico (e.g., Solidity compiler version, L2 compartido)?"
    - "¿Hay límites de concentración por chain/categoria?"
  como_se_arregla: >
    Implementar correlation matrix entre protocolos cubiertos. Ajustar
    pricing por cluster de riesgo. Limitar concentración: max X% del pool
    en una sola categoría/chain/codebase. Calcular MCR con correlación:
    reserve = sqrt(sum(cover_i^2 * correlation_matrix)). Diversification
    requirements para el pool.
  trampas:
    - "La correlación es difícil de estimar on-chain — la mayoría de protocolos usan heurísticas simples"
    - "Sherlock maneja esto con audit-based cover — cada protocolo auditado individualmente"
    - "Algunos protocolos usan 'staking pools' separados por categoría como forma primitiva de diversificación"
  solodit_ids:
    - m-04-system-debt-is-not-handled-when-insurance-pools-become-insolvent-code4rena-insuredao-insuredao-contest-git
    - insurance-funding-rate-increases-indefinitely-sigmaprime-none-tracer-pdf
  incidentes:
    - "UST Depeg (May 2022) — Correlated event: UST depeg triggered claims across Anchor, Mirror, Lido-on-Terra simultaneously. InsurAce faced $11.7M in correlated claims."
    - "Euler Finance (Mar 2023) — $197M exploit. Multiple insurance protocols had covers on Euler — correlated exposure to single codebase."
    - "Compound fork exploits (2023) — Series of inflation attacks on CompoundV2 forks: HundredFinance ($7M), Sonne ($20M), etc. Protocols covering multiple forks had correlated exposure."
  severidad: medium
  confianza: media
  verificado: true
```

### 1.13 Shield Mining Reward Exploitation — Farming Rewards Without Real Risk

```yaml
- id: ins-013
  titulo: "Explotación de shield mining — farming rewards sin asumir riesgo real"
  causa_raiz: >
    Shield mining es un incentive mechanism donde protocolos ofrecen tokens
    como reward a underwriters que depositan capital en sus pools específicos.
    Si el reward se calcula solo por staking amount sin verificar que el
    capital realmente está backing covers activos, un atacante puede stakear
    en pools sin cover activo para ganar rewards risk-free.
  como_funciona: |
    1. Protocolo X ofrece 1000 TOKEN/día a underwriters de su pool de insurance
    2. Pool tiene $1M en cover activo pero permite $5M en capital
    3. Atacante deposita $4M en el pool — no hay más cover que underwrite
    4. Atacante gana 80% de los rewards (4M/5M del capital total)
    5. El capital del atacante NO está en riesgo porque no hay covers que cubra
    6. Atacante retira capital + rewards — never had real exposure
  invariante: |
    // INV: Rewards deben ser proporcionales al riesgo asumido, no al capital depositado
    function check_rewards_proportional_to_risk() internal view {
        for (uint i = 0; i < stakers.length; i++) {
            uint256 riskExposure = getEffectiveRiskExposure(stakers[i]);
            uint256 rewardShare = getRewardShare(stakers[i]);
            // Si no hay riesgo, no hay reward
            if (riskExposure == 0) {
                assertEq(rewardShare, 0,
                    "INS-013: rewards earned without risk exposure");
            }
        }
    }
  que_mirar:
    - "¿Los rewards se calculan por capital staked o por capital at-risk?"
    - "¿Se puede stakear en un pool sin cover activo?"
    - "¿El capital excedente (over MCR) sigue ganando rewards?"
    - "¿Hay un cap en el ratio capital/cover para rewards?"
    - "¿Los rewards se distribuyen uniformemente o por utilization del capital?"
  como_se_arregla: >
    Calcular rewards basados en capital at-risk (min(staked, proportional_cover)),
    no en total staked. Cap rewards cuando utilization < X%. Implementar
    reward decay: rewards decrecen linealmente cuando utilization < 50%.
    Solo pagar shield mining rewards si hay covers activos en el pool.
  trampas:
    - "Capital excedente mejora la solvencia del pool — penalizarlo demasiado reduce la seguridad"
    - "Nexus Mutual limita shield mining rewards por pool capacity — verificar el cap"
    - "Flash-staking para farming rewards requiere que no haya lock period"
  solodit_ids:
    - m-12-after-the-vault-expires-users-may-still-receive-rewards-through-the-stakingrewards-contract-code4rena-y2k-finance-y2k-finance-contest-git
    - m-13-dishonest-stakers-can-siphon-rewards-from-xtoken-holders-through-the-deposit-function-in-nftxinventorystaking-code4rena-nftx-nftx-git
    - reward-claim-post-expiry-of-locked-stake-ottersec-none-adrena-pdf
  incidentes:
    - "Y2K Finance (Code4rena) — M-12: After vault expires, users may still receive rewards through StakingRewards — rewards without risk (MEDIUM)"
    - "NFTX (Code4rena) — M-13: Dishonest stakers can siphon rewards via deposit function — farming rewards without assuming real risk (MEDIUM)"
    - "Adrena (OtterSec) — Reward claim post expiry of locked stake — claiming rewards on expired positions (HIGH)"
    - "Nexus Mutual — Shield mining introduced to incentivize underwriting specific protocols. Early versions lacked utilization-based caps."
  severidad: medium
  confianza: alta
  verificado: true
```

### 1.14 Expired Cover Still Claimable — Grace Period or Missing Expiry Check

```yaml
- id: ins-014
  titulo: "Cover expirado sigue siendo reclamable — grace period o falta de check de expiración"
  causa_raiz: >
    Covers tienen una fecha de expiración. Si el contrato no verifica
    correctamente que el cover está activo al momento de la claim, o si
    hay un grace period mal implementado, un usuario puede reclamar
    usando un cover expirado. Esto es especialmente peligroso si los
    premiums dejaron de pagarse pero el cover sigue "activo" en el contrato.
  como_funciona: |
    1. User tiene cover que expiró hace 30 días
    2. Exploit ocurre en el protocolo cubierto
    3. User llama claim() con su cover ID expirado
    4. claim() no verifica cover.expiryDate o la compara incorrectamente
    5. Claim se procesa — payout del pool para un cover que ya no debería estar activo
    6. Los underwriters pagan un claim que no estaba cubierto por premiums
  invariante: |
    // INV: Solo covers activos (no expirados) pueden tener claims
    function check_claim_within_cover_period() internal view {
        for (uint i = 0; i < activeClaims.length; i++) {
            uint256 coverId = activeClaims[i].coverId;
            uint256 expiryDate = getCoverExpiry(coverId);
            uint256 incidentDate = activeClaims[i].incidentTimestamp;
            assertLte(incidentDate, expiryDate,
                "INS-014: claim for incident after cover expiry");
        }
    }
    // INV: Grace period no debe exceder X días
    function check_grace_period_bounded() internal view {
        assertLte(gracePeriod, MAX_GRACE_PERIOD,
            "INS-014: grace period exceeds maximum");
    }
  que_mirar:
    - "¿El claim() verifica que block.timestamp < cover.expiryDate?"
    - "¿Hay un grace period? ¿Cuánto dura?"
    - "¿El grace period aplica al incidente o al momento de filing del claim?"
    - "¿Se puede renovar un cover expirado retroactivamente?"
    - "¿Los covers auto-renew sin pago de premium?"
    - "¿Qué pasa si el premium payment falla pero el cover no se cancela?"
  como_se_arregla: >
    Verificar explícitamente block.timestamp <= cover.expiryDate en claim().
    Grace period solo para filing del claim (incidente debió ocurrir durante
    vigencia). No permitir renovación retroactiva. Cancelar cover
    automáticamente cuando premium no se paga.
  trampas:
    - "Grace periods son comunes y legítimos (7-14 días) — el bug es cuando son excesivos o mal implementados"
    - "Comparar incidentDate vs expiryDate, no claimDate vs expiryDate — el incidente debe haber ocurrido durante la vigencia"
    - "Timestamps en L2 pueden tener drift con L1 — verificar qué clock se usa"
  solodit_ids:
    - h-1-fixed-term-teller-tokens-can-be-created-with-an-expiry-in-the-past-sherlock-bond-bond-protocol-git
    - minting-zero-amount-deadlock-is-produced-during-payout-claiming-halborn-degis-scprotection-markdown
    - m-12-after-the-vault-expires-users-may-still-receive-rewards-through-the-stakingrewards-contract-code4rena-y2k-finance-y2k-finance-contest-git
  incidentes:
    - "Bond Protocol (Sherlock) — H-1: Fixed Term Teller tokens can be created with an expiry in the past — expired instruments still valid (HIGH)"
    - "SCProtection/Degis (Halborn) — Minting zero amount deadlock produced during payout claiming — claiming mechanism fails at boundary (HIGH)"
    - "Y2K Finance (Code4rena) — M-12: After vault expires, users may still receive rewards — expired state not properly enforced (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
```

### 1.15 Infinite Token Mint via Staking Contract Logic Error

```yaml
- id: ins-015
  titulo: "Mint infinito de tokens via error en lógica de staking/farming del insurance protocol"
  causa_raiz: >
    Protocolos de insurance con staking rewards o governance tokens pueden
    tener bugs en sus contratos de farming que permiten mint infinito.
    El ejemplo canónico es Cover Protocol (Dec 2020): el contrato de farming
    Blacksmith.sol cacheaba pool data en memory, actualizaba en storage,
    pero olvidaba actualizar la copia en memory. La data stale permitía
    recalcular rewards incorrectamente y mintear tokens infinitos.
  como_funciona: |
    1. Contrato de farming cachea poolData en variable memory
    2. poolData se actualiza en storage (state change)
    3. La copia en memory NO se actualiza — queda con valores stale
    4. Los cálculos de reward usan la copia stale en memory
    5. Atacante explota la discrepancia: llama claim() repetidamente
    6. Cada llamada recalcula con data stale → mintea tokens duplicados
    7. Atacante mintea quintillones de tokens → dump en DEX → drain liquidez
  invariante: |
    // INV: Total tokens minteados por farming nunca debe exceder
    // el reward allocation
    function check_no_infinite_mint() internal view {
        uint256 totalMinted = governanceToken.totalSupply() - initialSupply;
        assertLte(totalMinted, totalRewardAllocation,
            "INS-015: tokens minted exceed total reward allocation");
    }
    // INV: Un usuario no puede ganar más rewards que el total pool allocation
    function check_per_user_mint_cap() internal view {
        for (uint i = 0; i < users.length; i++) {
            uint256 userMinted = totalMintedByUser[users[i]];
            assertLte(userMinted, maxRewardPerUser,
                "INS-015: user minted more than max reward cap");
        }
    }
  que_mirar:
    - "¿El contrato de farming cachea data en memory y luego usa la copia stale?"
    - "¿Se actualiza storage Y memory consistentemente?"
    - "¿Hay un supply cap en el token de governance/rewards?"
    - "¿Se puede llamar a la función de claim repetidamente en la misma tx?"
    - "¿El reward calculation usa accumulators actualizados correctamente?"
    - "Buscar: 'Pool memory pool = poolData[_pid]' seguido de storage update sin sync a memory"
  como_se_arregla: >
    Siempre re-leer de storage después de actualizar, o actualizar AMBOS
    storage y memory. Implementar supply cap en el mint. Usar reentrancy
    guard en claim(). Verificar reward calculation con invariant tests
    que confirmen totalMinted <= totalAllocated.
  trampas:
    - "El bug de Cover Protocol era una línea: la copia memory no se sincronizó con storage"
    - "Este tipo de bug pasa code review porque el storage se actualiza correctamente — el problema está en la referencia stale"
    - "Forge coverage puede no detectar esto si los tests no hacen claim() múltiple en secuencia"
  solodit_ids:
    - infinite-minting-of-flux-through-voterpoke-immunefi-alchemix-git
    - addtidal-_updateusertidal-withdrawtidal-wrong-arithmetic-calculations-fixed-consensys-none-tidal-markdown
  incidentes:
    - "Cover Protocol (Dec 2020) — $4.4M exploit. Blacksmith.sol farming contract cached pool data in memory, updated storage, but used stale memory copy for reward calculations. Attacker minted 40+ quintillion COVER tokens. White hat returned most funds."
    - "Alchemix (Immunefi) — Infinite minting of FLUX through voter.poke() — governance token infinite mint (HIGH)"
    - "Tidal (Consensys) — addTidal/withdrawTidal wrong arithmetic calculations — staking reward miscalculation (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
```

---

## 2. Checklists Rápidos

### 2.1 Pre-audit de Insurance Protocol (15 min)

```
[ ] Identificar modelo: discretionary, parametric, o hybrid
[ ] Mapear flujo de premiums: buyer → pool → underwriter
[ ] Verificar MCR (Minimum Capital Requirement) — ¿se enforcea?
[ ] Identificar claim assessment mechanism (voting, oracle, hybrid)
[ ] Verificar cooldowns: stake, unstake, claim, payout
[ ] Cover representado como: NFT, ERC-20 share, o mapping
[ ] ¿Hay shield mining / staking rewards? → vector ins-013
[ ] ¿Parametric trigger? → vector ins-003, ins-009
[ ] ¿Múltiples cover types para mismo protocolo? → vector ins-004
[ ] Listar oracles usados y sus ventanas de observación
```

### 2.2 Grep Patterns para Insurance Contracts

```bash
# Coverage y premiums
grep -rn "premium\|coverage\|underwrite\|cover amount\|coverAmount" src/
grep -rn "MCR\|minCapital\|capitalRequirement\|coverageRatio" src/
grep -rn "maxCoverAmount\|leverageRatio\|utilizationRatio" src/

# Claims y payouts
grep -rn "claim\|payout\|assess\|resolve\|trigger" src/
grep -rn "claimId\|incidentId\|incidentDate\|eventTimestamp" src/
grep -rn "expiry\|expired\|gracePeriod\|coverEnd\|coverExpiry" src/

# Staking y cooldowns
grep -rn "cooldown\|unbond\|lockPeriod\|stakingPeriod\|withdrawDelay" src/
grep -rn "pendingWithdraw\|requestWithdraw\|executeWithdraw" src/
grep -rn "shieldMining\|miningReward\|stakingReward" src/

# Oracle y triggers
grep -rn "trigger\|depeg\|depegged\|oraclePrice\|twapPrice" src/
grep -rn "observation\|window\|confirmationPeriod\|challengeWindow" src/

# Voting y governance
grep -rn "assessor\|vote\|quorum\|slash\|penalty" src/
grep -rn "claimVote\|assessVote\|disputePeriod\|appeal" src/

# Memory vs storage (Cover Protocol bug)
grep -rn "memory.*pool\|Pool memory\|memory.*data" src/
```

### 2.3 Invariantes Universales de Insurance

```solidity
// ===== SOLVENCY =====
// INV-INS-SOLV-001: Pool capital >= MCR en todo momento
assert(poolCapital >= minCapitalRequired);

// INV-INS-SOLV-002: Total payouts <= pool capital + backstop
assert(totalPayoutsProcessed <= poolCapital + backstopReserve);

// INV-INS-SOLV-003: Sum(premiums) tracked == sum(premiums) received
assert(accountedPremiums <= token.balanceOf(address(pool)));

// ===== COVERAGE =====
// INV-INS-COV-001: Active cover cannot exceed max allowed by capital
assert(totalActiveCover <= poolCapital * maxLeverageRatio / 1e18);

// INV-INS-COV-002: Cover must be within validity period for claims
assert(block.timestamp <= cover.expiryDate || cover.status != ACTIVE);

// INV-INS-COV-003: Premium paid >= minimum for coverage amount
assert(premiumPaid >= calculateMinPremium(coverAmount, duration));

// ===== TIMING =====
// INV-INS-TIME-001: Cannot buy cover and claim in same tx
assert(cover.purchaseBlock < claim.submissionBlock);

// INV-INS-TIME-002: Cannot deposit and withdraw in same tx
assert(deposit.block + cooldownBlocks <= withdrawal.block);

// INV-INS-TIME-003: Cooldown cannot be bypassed
assert(block.timestamp >= staker.cooldownEnd || !staker.canWithdraw);

// ===== CLAIM INTEGRITY =====
// INV-INS-CLM-001: Same incident cannot be claimed twice by same user
assert(!hasClaimed[user][incidentId] || claimAmount == 0);

// INV-INS-CLM-002: Payout amount <= cover amount
assert(claimPayout <= cover.amount);

// INV-INS-CLM-003: Claims from expired covers must be rejected
assert(incident.timestamp <= cover.expiryDate);
```

---

## 3. Protocolos de Referencia

### 3.1 Nexus Mutual
- **Modelo**: Discretionary — stakers votan claims, NXM token governance
- **MCR**: Global MCR recalculado por bloque, MCR% determina token price via bonding curve
- **Claims**: 3-day voting period, assessors stake NXM, slashing si votan incorrectamente
- **Incidente Hugh Karp (Dec 2020)**: $8M — personal wallet hack vía MetaMask modificado maliciosamente, no fallo del protocolo. Atacante ganó remote access al PC de Karp, reemplazó extensión MetaMask por versión maliciosa, Karp aprobó una tx que envió 370K NXM al atacante. El contrato del protocolo NO fue comprometido.
- **Relevancia para auditors**: El claim assessment process es atacable si pocos voters participan (quorum bajo).

### 3.2 InsurAce
- **Modelo**: Hybrid — oracle + governance, multi-chain coverage
- **UST Depeg (May 2022)**: $11.7M en claims pagados a 173+ claimants contra $94K en premiums. Demostró que insurance DeFi puede funcionar pero expuso riesgo sistémico de eventos correlacionados.
- **Riesgos**: Portfolio-based cover permite diversificación pero también permite double-exposure.

### 3.3 Cover Protocol
- **Modelo**: Prediction market-style cover tokens (CLAIM/NOCLAIM)
- **Exploit (Dec 2020)**: $4.4M — Blacksmith.sol farming contract tenía bug de memory vs storage. Pool data cacheada en memory, actualizada en storage, pero memory copy no sincronizada. Atacante minteó 40+ quintillones de COVER tokens. White hat devolvió mayoría.
- **Post-mortem**: PeckShield, Mudit Gupta análisis detallados disponibles.

### 3.4 Y2K Finance
- **Modelo**: Parametric depeg insurance con epoch-based vaults
- **Audit findings**: Múltiples issues en trigger mechanics (sequencer downtime blocking triggers, null epochs freezing rollovers, expired vaults still paying rewards).
- **Relevancia**: Ejemplo perfecto de cómo epoch-based design previene algunos ataques (dilution, timing) pero introduce otros (epoch boundary edge cases).

### 3.5 Neptune Mutual
- **Modelo**: Parametric con incident reporting + governance resolution
- **Diseño**: Semi-paramétrico — no es puro oracle, requiere reportero + resolución governance. Reduces oracle manipulation pero introduce governance attack surface.

### 3.6 Sherlock
- **Modelo**: Audit-based cover — cubre exploits en protocolos auditados por Sherlock
- **Único**: La cobertura está ligada a la calidad del audit. Si Sherlock auditó y se encontró el bug, pagan. Si es un bug fuera del scope, no pagan.
- **Riesgo**: Correlación entre protocolos auditados (si hay fallo sistémico en el proceso de audit).

### 3.7 Armor.fi
- **Modelo**: arNFT wrapping — wraps Nexus Mutual covers como ERC-721 transferibles
- **Riesgo**: Wrapping permite crear mercado secundario de covers, introduciendo transfer-during-claim issues (ins-008). El wrapper puede evadir lock mechanisms del protocolo subyacente.

### 3.8 Unslashed Finance
- **Modelo**: Capital pool con underwriter staking, premium streaming
- **Diseño**: Premium pagado como stream (por segundo), no lump sum. Reduce premium manipulation pero requiere accounting complejo.

---

## 4. Cross-References con Otros Briefings

| Patrón Insurance | Briefing Relacionado | Conexión |
|---|---|---|
| ins-001 (insolvency) | vault-erc4626.md (vault-001) | Pool shares = vault shares — mismos vectores de dilución |
| ins-002 (premium manipulation) | flash-loan.md | Flash loans amplifican capital para manipular rates |
| ins-003, ins-009 (oracle) | oracle.md | Mismos vectores de manipulación de oracle aplican |
| ins-006 (vote manipulation) | governance.md | Governance attacks aplican directamente a claim voting |
| ins-007 (front-running) | mev-sandwich.md | MEV strategies para front-run cover purchases |
| ins-010 (pool dilution) | staking.md (staking-002) | Flash-staking para dilución de rewards/losses |
| ins-011 (withdrawal timing) | staking.md (staking-002) | Cooldown bypass patterns compartidos |
| ins-013 (shield mining) | staking.md (staking-001) | Reward-per-share rounding en shield mining |
| ins-015 (infinite mint) | token-erc20.md | Token supply manipulation patterns |

---

## 5. Incidentes Reales — Resumen Cronológico

| Fecha | Protocolo | Tipo | Impacto | Vector |
|---|---|---|---|---|
| Dec 14, 2020 | Nexus Mutual (Hugh Karp) | Personal wallet hack | $8M NXM | Social engineering + malicious MetaMask extension |
| Dec 28, 2020 | Cover Protocol | Infinite token mint | $4.4M | Memory vs storage desync in Blacksmith.sol farming |
| May 13, 2022 | InsurAce (UST Depeg) | Legitimate claims | $11.7M paid out | Correlated depeg event, $94K premiums vs $11.7M claims |
| Mar 13, 2023 | Euler Finance | Smart contract exploit | $197M | Flash loan + donate attack — multiple insurance pools had exposure |
| May 2024 | Sonne Finance | CompoundV2 inflation | $20M | Share inflation — covered by some insurance protocols |

---

## 6. Anti-Patrones del Auditor

1. **"El MCR está bien porque lo veo en buy()"** → Verificar que TAMBIÉN se enforcea en withdraw(). La insolvencia ocurre cuando alguien retira, no cuando compra.

2. **"Hay cooldown de 7 días, no se puede flashstake"** → Verificar que el cooldown no se puede resetear, cancelar, o bypasear con transfer del staking token.

3. **"El oracle usa Chainlink, es seguro"** → Chainlink tiene heartbeat delays y circuit breakers que pueden causar false triggers en insurance paramétrico.

4. **"Es parametric, no hay manipulación posible"** → Si el trigger lee un valor on-chain manipulable (balanceOf, totalAssets, spot price), es manipulable.

5. **"El cover NFT tiene transfer lock"** → Verificar que el lock aplica a TODOS los mecanismos de transferencia (transferFrom, safeTransferFrom, approve + transferFrom).

6. **"Los premiums se pagan por stream, no hay front-running"** → El atacante puede subscribirse al stream justo antes del evento y cancelar después.

7. **"Solo hay un tipo de cover, no hay double-claim"** → Verificar cross-protocol: el usuario puede tener cover en Nexus Mutual Y en InsurAce para el mismo riesgo.
