# Gauge Systems & Vote Escrow — Bug Patterns

> Patrones de vulnerabilidad en sistemas de gauges (Curve, Velodrome/Aerodrome, Solidly forks),
> vote-escrow (veCRV, veNFT), bribe markets, y boost mechanics.
> Fuentes: Code4rena Velodrome/Canto/Maia/veRWA, Sherlock Velocimeter/MagicSea,
> Spearbit Velodrome Finance, Immunefi Alchemix, Trail of Bits Curve DAO,
> CodeHawks RAAC, Certora Solidly, OpenZeppelin Retro/Thena.

---

## Quick Reference

```
grep_targets:
  - VotingEscrow
  - GaugeController
  - Gauge
  - Bribe
  - ExternalBribe
  - InternalBribe
  - Voter
  - Minter
  - RewardsDistributor
  - veNFT
  - veCRV
  - create_lock
  - increase_amount
  - increase_unlock_time
  - withdraw
  - merge
  - split
  - vote_for_gauge_weights
  - notifyRewardAmount
  - deliverBribes
  - getReward
  - earned
  - checkpoint
  - checkpoint_token
  - totalSupply
  - balanceOfNFT
  - balanceOfAtNFT
  - getPastVotes
  - workingSupply
  - workingBalance
  - user_checkpoint
  - claimable_tokens
  - deposit_for
  - poke
  - reset
  - killGauge
  - activeGaugeNumber
  - rewardPerToken
  - rewardPerTokenStored
  - tokenRewardsPerEpoch
  - totalWeight
  - weights
  - votes
  - poolVote
  - isAlive
  - MAX_REWARD_TOKENS
  - EPOCH_DURATION
  - distribute
  - updatePeriod
  - claimBribes
  - claimFees
```

---

## 1. Vote Escrow Lock Bypass — Merge/Transfer de tokens bloqueados

```yaml
- id: gauge-001
  titulo: "Bypass del lock de vote-escrow mediante merge, split, o transferencia de veNFT"
  causa_raiz: |
    En sistemas ve basados en NFTs (Solidly/Velodrome forks), la función merge()
    combina el balance de dos veNFTs en uno solo y quema el original. Si el sistema
    usa optimizaciones como bit-packing para trackear el estado de "voted" por tokenId,
    un reset() con un tokenId no-votado puede borrar el flag "voted" del tokenId que
    SÍ votó (porque comparten la misma palabra uint256 en el mapping). Esto permite
    hacer merge del veNFT votado hacia otro, multiplicando votos efectivos.
    En otros casos, withdraw() tras lock expirado no limpia delegaciones históricas,
    dejando "voting power fantasma" en checkpoints.
  como_funciona: |
    1. Atacante tiene 2 veNFTs en el mismo rango de bit-packing (tokenId A y B).
    2. Vota con tokenId A → voted[A] = true.
    3. Llama reset(B) → como A y B comparten la misma palabra en el mapping,
       el bit de A se borra indirectamente.
    4. merge(A, B) ahora funciona porque voted[A] aparece como false.
    5. El voto de A sigue contando, pero el balance está ahora en B.
    6. Repite: vota con B, reset con otro tokenId del mismo rango, merge...
    7. Resultado: votos ilimitados con el mismo capital.
    Variante (Velodrome C4): transferir veNFT post-lock expiry no limpia
    delegaciones → getPastVotes() retorna valores inflados permanentemente.
  invariante: |
    // Invariante: votos totales emitidos <= voting power total disponible
    uint256 totalVotesCast;
    for (uint i = 0; i < gauges.length; i++) {
        totalVotesCast += weights[gauges[i]];
    }
    assert(totalVotesCast <= votingEscrow.totalSupply());

    // Invariante: veNFT votado no puede hacer merge
    // assert(!voted[tokenId] || merge reverts)
  que_mirar:
    - "merge() o split() verifican voted[tokenId] ANTES de ejecutar?"
    - "reset() limpia solo el tokenId especificado o puede afectar a otros?"
    - "Hay bit-packing u optimización en el mapping de voted?"
    - "transferFrom() de veNFT limpia votos y delegaciones del sender?"
    - "withdraw() post-expiry limpia checkpoints de delegación?"
  como_se_arregla: |
    Usar mapping(uint256 => bool) simple para voted (no bit-packing).
    Requerir reset() del propio tokenId antes de merge/split/transfer.
    En withdraw(): limpiar numCheckpoints y delegates del tokenId.
  trampas:
    - "En Velodrome v2+ la optimización de bit-packing fue removida — el bug de Solidly original ya no aplica en forks modernos. Verificar versión."
    - "Si merge() ya verifica voted[tokenId] correctamente, este vector está cerrado."
    - "El getPastVotes() inflado post-transfer puede ser by-design si el protocolo no usa governance on-chain."
  solodit_ids:
    - "h-01-users-can-get-unlimited-votes-code4rena-velodrome-finance-velodrome-finance-git"
    - "voting-manipulation-cause-by-the-possibility-to-transfer-venft-immunefi-zerolend-git"
    - "merging-tokens-allows-multiple-flux-accruals-within-an-epoch-immunefi-alchemix-git"
    - "undound-flux-accrual-through-reset-and-merge-immunefi-alchemix-git"
  incidentes:
    - "Solidly (Certora) — veNFT merge bypass via bit-packed voted mapping: votos ilimitados con 2 NFTs. Detectado pre-deploy por Certora Prover."
    - "Velodrome v1 (C4) — Users get unlimited votes via transfer+re-lock cycle: getPastVotes retorna valores incorrectos permanentemente (HIGH)."
    - "Alchemix (Immunefi) — Merging tokens allows multiple FLUX accruals within an epoch: reset+merge loop genera FLUX ilimitado (HIGH)."
    - "ZeroLend (Immunefi) — veNFT transferable permite manipulación de voting power sin restricciones (HIGH)."
  severidad: critical
  confianza: alta
  verificado: true
  tags: [vote-escrow, veNFT, merge, lock-bypass, unlimited-votes, bit-packing]
  relacionado_con: [gauge-006, gauge-009]
```

---

## 2. Voting Power Snapshot Staleness — Votar con checkpoint obsoleto

```yaml
- id: gauge-002
  titulo: "Voting power basado en checkpoint stale permite votar después de cambiar posición"
  causa_raiz: |
    El voting power se calcula desde checkpoints históricos (balanceOfAtNFT o
    getPastVotes en un bloque pasado). Si el sistema permite votar usando un
    snapshot tomado ANTES de que el usuario reduzca su posición (withdraw parcial,
    merge out, o transferencia), el usuario retiene voting power que ya no posee.
    En Curve-style: vote_for_gauge_weights() usa slope/bias del VotingEscrow
    sin verificar si el lock fue extendido o reducido desde el último checkpoint.
    Variante: emergencyWithdraw() no resetea checkpoints.
  como_funciona: |
    1. Usuario tiene veNFT con 1000 tokens lockeados, checkpoint registrado en bloque N.
    2. En bloque N+1: usuario transfiere el veNFT o hace withdraw parcial.
    3. En bloque N+2: sistema de voting usa balanceOfAtNFT(bloque N) como referencia.
    4. El usuario (o el nuevo dueño + el anterior vía delegación stale) vota con
       el power del bloque N, que ya no refleja la realidad.
    5. Resultado: votos inflados → gauge recibe más emisiones de las que debería.
  invariante: |
    // El voting power usado para votar debe reflejar el balance actual
    uint256 votePower = votingEscrow.balanceOfNFT(tokenId);
    uint256 usedPower = usedWeights[tokenId];
    assert(usedPower <= votePower);
  que_mirar:
    - "vote() usa balanceOfNFT(tokenId) actual o un snapshot histórico?"
    - "Después de withdraw/merge/transfer, se invalidan los votos activos?"
    - "emergencyWithdraw() resetea checkpoints y numCheckpoints?"
    - "poke() existe para actualizar votos con el balance actual?"
    - "Hay un delay entre cambio de balance y cuando el voto expira?"
  como_se_arregla: |
    Usar balance actual (no snapshot) para gauge voting, o forzar reset()
    antes de cualquier operación que reduzca el balance.
    Implementar poke() que cualquiera pueda llamar para actualizar votos stale.
    emergencyWithdraw() debe resetear checkpoints a cero.
  trampas:
    - "Los snapshots son correctos para governance voting (evitar flash-loan) — el problema es específico de gauge voting donde el power debe ser actual."
    - "Si poke() existe y es callable por cualquiera, el riesgo se mitiga (pero requiere que alguien lo llame)."
    - "Voting power que decae linealmente con el tiempo es by-design en ve — no confundir con staleness."
  solodit_ids:
    - "h-05-voting-overwrites-checkpointvoted-in-last-checkpoint-so-users-can-just-vote-right-before-claiming-rewards-code4rena-velodrome-finance-velodrome-finance-git"
    - "historical-power-manipulation-in-veraactoken-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "missing-checkpoint-reset-in-veraactokenemergencywithdraw-function-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "venft-transfers-leave-unclaimed-rewards-and-do-not-alter-votes-spearbit-none-infrared-contracts-pdf"
  incidentes:
    - "Velodrome v1 (C4) — Voting overwrites checkpoint.voted en el último checkpoint: usuarios votan justo antes de claim para cumplir el check de 'has voted' (HIGH)."
    - "RAAC (CodeHawks) — Historical power manipulation en veRAACToken: checkpoints no reflejan estado actual (LOW)."
    - "RAAC (CodeHawks) — emergencyWithdraw no resetea checkpoints: voting power fantasma persiste (LOW)."
    - "Infrared (Spearbit) — veNFT transfers dejan unclaimed rewards y no alteran votos existentes (LOW)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [snapshot, checkpoint, stale, voting-power, poke, balanceOfNFT]
  relacionado_con: [gauge-001, gauge-009]
```

---

## 3. Gauge Weight Manipulation via Flash Voting

```yaml
- id: gauge-003
  titulo: "Manipulación de pesos de gauge mediante vote-and-withdraw rápido o flash loans"
  causa_raiz: |
    En sistemas tipo Curve, GaugeController.vote_for_gauge_weights() usa el
    slope del VotingEscrow del votante. Si no hay cooldown entre votar y retirar
    el lock (o transferir el veToken), un usuario puede votar, retirar/vender
    inmediatamente, y el voto persiste hasta el siguiente epoch. En Solidly forks,
    si no hay lock mínimo, un flash loan puede crear un lock, votar, y destruirlo
    en la misma transacción.
    Trail of Bits documentó este patrón en Curve DAO: "quick vote and withdraw".
  como_funciona: |
    1. Atacante obtiene gran cantidad de tokens via flash loan (si no hay lock mínimo)
       o compra temporalmente.
    2. create_lock() con duración mínima permitida.
    3. vote_for_gauge_weights() con 100% del power hacia el gauge objetivo.
    4. Si lock mínimo = 0 o 1 bloque: withdraw() en la misma transacción.
    5. El voto queda registrado y afecta la distribución de emisiones por todo el epoch.
    6. En Curve: el usuario vende el CRV después de votar — el voto persiste
       por WEIGHT_VOTE_DELAY (10 días en Curve original).
    Variante: en Solidly forks sin WEIGHT_VOTE_DELAY, esto se hace en 1 tx.
  invariante: |
    // Invariante: no se puede votar y retirar en el mismo bloque
    // (o dentro del cooldown period)
    assert(block.timestamp >= lastVoteTime[tokenId] + VOTE_COOLDOWN);

    // Invariante: lock duration mínima para crear un veNFT
    assert(lockEnd - block.timestamp >= MIN_LOCK_DURATION);
  que_mirar:
    - "Hay WEIGHT_VOTE_DELAY o cooldown entre voto y withdraw/transfer?"
    - "El lock mínimo es > 0 bloques/segundos?"
    - "Se puede crear lock + votar + withdraw en la misma transacción?"
    - "vote_for_gauge_weights verifica que el lock NO expira antes del epoch end?"
    - "El voto se invalida automáticamente cuando el lock expira?"
  como_se_arregla: |
    Implementar WEIGHT_VOTE_DELAY (Curve usa 10 días).
    Lock mínimo de 1 epoch para poder votar.
    Invalidar votos cuando el lock expira antes del final del epoch.
    Verificar lock expiry > next epoch boundary en vote().
  trampas:
    - "En Curve mainnet el WEIGHT_VOTE_DELAY de 10 días mitiga este ataque casi completamente."
    - "Solidly forks que copian el código pero no copian el delay son los más vulnerables."
    - "Si el lock mínimo es de 1 epoch y la flash loan no puede mantener el lock, no es explotable."
    - "No confundir con front-running de notifyRewardAmount (ese es staking-002, no gauge voting)."
  solodit_ids:
    - "gaugecontroller-allows-for-quick-vote-and-withdraw-voting-strategy-trailofbits-curve-dao-pdf"
    - "flash-loan-attack-on-gauge-reward-distribution-via-get_adjustment-manipulation-mixbytes-none-yield-basis-markdown"
    - "h-02-voters-from-votingescrow-can-vote-infinite-times-in-vote_for_gauge_weights-of-gaugecontroller-code4rena-canto-canto-git"
  incidentes:
    - "Curve DAO (Trail of Bits) — GaugeController allows quick vote and withdraw strategy: votar y vender CRV antes del epoch end (MEDIUM)."
    - "Yield Basis (MixBytes) — Flash loan attack on gauge reward distribution via get_adjustment() manipulation (HIGH)."
    - "Canto (C4) — VotingEscrow permite votar infinite veces en vote_for_gauge_weights vía delegación (HIGH)."
    - "Beanstalk (2022) — Flash loan de $182M para tomar control de governance y drenar treasury (real exploit, $80M profit)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [flash-loan, flash-vote, weight-vote-delay, cooldown, gauge-weight]
  relacionado_con: [gauge-001, gauge-014]
```

---

## 4. Emission Rate Retroactive Changes

```yaml
- id: gauge-004
  titulo: "Cambio de tasa de emisión afecta retroactivamente rewards ya acumulados"
  causa_raiz: |
    Cuando la función que establece la tasa de emisión (setRewardRate,
    notifyRewardAmount, setDebtInterestApr) no acumula primero las rewards
    pendientes con la tasa anterior, el cambio se aplica retroactivamente
    a todo el periodo no-reclamado. Si la tasa sube, usuarios que no han
    hecho claim reciben más de lo merecido. Si baja, pierden rewards legítimos.
    En gauge systems: si el Minter cambia la tasa global sin llamar
    checkpoint_token() primero, las emisiones del periodo anterior se
    recalculan con la nueva tasa.
  como_funciona: |
    1. Epoch 1: emissionRate = 100 TOKENS/day. Alice stakea durante 7 días.
    2. Sin hacer claim, la governance cambia emissionRate = 200 TOKENS/day
       sin acumular primero las rewards de Alice con la tasa anterior.
    3. Alice hace claim: el cálculo usa 200 TOKENS/day para TODO el periodo
       (7 días anteriores + días nuevos).
    4. Alice recibe 200 * 7 = 1400 tokens en vez de 100 * 7 = 700 tokens.
    5. Resultado: exceso de emisiones → protocolo se queda sin reward tokens,
       o últimos en reclamar reciben 0.
  invariante: |
    // Invariante: cambio de rate debe acumular rewards pendientes primero
    // En test: capturar earned() ANTES y DESPUÉS de setRate()
    uint256 earnedBefore = gauge.earned(alice);
    // setRate() should NOT change earnedBefore
    vm.prank(admin);
    gauge.setRewardRate(newRate);
    uint256 earnedAfter = gauge.earned(alice);
    // Sin avanzar el tiempo, earned no debe cambiar
    assert(earnedAfter == earnedBefore);
  que_mirar:
    - "setRewardRate / notifyRewardAmount llama updateReward() o _checkpoint() antes?"
    - "El earned() calcula con la tasa vigente en cada sub-periodo o con la tasa actual?"
    - "Hay un periodFinish que separa periodos con diferentes tasas?"
    - "El Minter llama checkpoint_token() antes de cambiar emissions?"
    - "Se usa rewardPerTokenStored para acumular incrementalmente?"
  como_se_arregla: |
    SIEMPRE llamar updateReward(address(0)) o checkpoint antes de cambiar la tasa.
    Usar el patrón Synthetix donde notifyRewardAmount() calcula remaining rewards
    del periodo anterior y las suma al nuevo periodo.
    Nunca modificar rewardRate sin acumular rewardPerTokenStored primero.
  trampas:
    - "El patrón Synthetix estándar ya maneja esto correctamente — verificar que el fork no modificó notifyRewardAmount."
    - "Un admin que llama setRate sin updateReward es un bug de implementación, no de diseño."
    - "Si rewards se distribuyen linealmente con periodFinish, el impacto retroactivo es limitado al periodo actual, no a todos los periodos históricos."
  solodit_ids:
    - "modifications-to-rewards-and-fees-can-apply-retroactively-sigmaprime-none-stader-labs-pdf"
    - "m-3-manager-can-retroactively-apply-new-rate-to-past-time-misallocating-emissions-invariant-broken-sherlock-super-dca-liquidity-network-git"
    - "m-01-retroactive-parameter-updates-cause-unfair-reward-distribution-codehawks-none-honeypotfinance-nftstaking-git"
  incidentes:
    - "Stader Labs (SigmaPrime) — Modifications to rewards and fees apply retroactively: setFees sin acumular previamente (LOW)."
    - "Super DCA (Sherlock) — Manager puede aplicar nueva tasa retroactivamente a tiempo pasado, rompiendo invariante de emisiones (MEDIUM)."
    - "HoneypotFinance NFTStaking (CodeHawks) — Retroactive parameter updates causan distribución injusta de rewards (MEDIUM)."
    - "JPEG'd (C4) — setDebtInterestApr should accrue debt first: cambio de tasa sin acumular interés pendiente (MEDIUM)."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [emission-rate, retroactive, updateReward, checkpoint, notifyRewardAmount]
  relacionado_con: [gauge-005, staking-002]
```

---

## 5. Gauge Reward Distribution Rounding — Truncación de rewardPerShare

```yaml
- id: gauge-005
  titulo: "Truncación en rewardPerToken drena rewards de stakers pequeños"
  causa_raiz: |
    El acumulador rewardPerToken += (reward * PRECISION) / totalSupply usa
    división entera. Cuando totalSupply es muy grande relativo a reward, el
    incremento se trunca a cero y las rewards se pierden silenciosamente.
    En gauge systems esto es más grave porque las emisiones se distribuyen
    por epoch y hay muchos gauges compitiendo por las mismas rewards.
    Variante: premature division en _calculateReward donde
    (amount * weight / totalWeight) / duration pierde precisión.
  como_funciona: |
    1. Gauge tiene totalSupply = 1e24 (muchos LP stakers).
    2. Epoch reward = 1000 tokens con PRECISION = 1e18.
    3. rewardPerToken += 1000 * 1e18 / 1e24 = 1e18 * 1000 / 1e24 = 0 (truncado).
    4. NINGÚN staker recibe rewards para este epoch.
    5. Los reward tokens quedan atrapados en el contrato permanentemente.
    6. Si dust se acumula en múltiples epochs, un staker que controla un %
       significativo del supply puede extraer el dust acumulado.
  invariante: |
    // Invariante: rewardPerToken debe ser monótonamente creciente
    uint256 rpsBefore = gauge.rewardPerTokenStored();
    // ... advance time + notifyRewardAmount ...
    uint256 rpsAfter = gauge.rewardPerTokenStored();
    assert(rpsAfter >= rpsBefore);

    // Invariante: total distributed <= total allocated
    uint256 totalDistributed;
    for (uint i = 0; i < stakers.length; i++) {
        totalDistributed += gauge.earned(stakers[i]);
    }
    assert(totalDistributed <= totalAllocated);
  que_mirar:
    - "PRECISION constant es 1e18 o mayor? Valores menores son peligrosos."
    - "Se usa mulDiv o FullMath para evitar overflow Y mantener precisión?"
    - "El dust perdido por rounding se trackea en variable separada?"
    - "Hay minimum stake amount que previene totalSupply microscópico?"
    - "En _calculateReward, el orden de operaciones preserva precisión (multiply before divide)?"
  como_se_arregla: |
    Usar PRECISION >= 1e18. Usar mulDiv (OpenZeppelin) para cálculos.
    Trackear dust en variable separada y redistribuirlo.
    Hacer multiply before divide: (amount * weight * duration) / totalWeight en vez de
    (amount * weight / totalWeight) / duration.
  trampas:
    - "1 wei de rounding por operación generalmente no es explotable excepto en L2 con gas barato."
    - "Si totalSupply es razonable (1e18-1e22), la truncación a 0 no ocurre con PRECISION = 1e18."
    - "Rebasing tokens en gauges causan drift natural del acumulador — no es un rounding bug."
  solodit_ids:
    - "premature-division-in-reward-calculation-leads-to-reduced-payout-precision-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "h-01-incorrect-next-epoch-supply-usage-affects-reward-calculation-pashov-audit-group-none-kittenswap_2025-05-07-markdown"
    - "m-16-accumulated-rewards-per-share-can-round-to-zero-code4rena-gte-gte-git"
  incidentes:
    - "RAAC (CodeHawks) — Premature division en reward calculation reduce precisión de payout (MEDIUM)."
    - "KittenSwap (Pashov) — Incorrect next epoch supply usage afecta cálculo de rewards en boundary (HIGH)."
    - "GTE (C4) — Accumulated rewards per share can round to zero cuando totalStaked es grande (MEDIUM)."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [rounding, precision, rewardPerToken, truncation, mulDiv, dust]
  relacionado_con: [staking-001, gauge-004]
```

---

## 6. Vote Delegation Double-Counting

```yaml
- id: gauge-006
  titulo: "Votos delegados contados doble: delegator y delegatee votan con el mismo power"
  causa_raiz: |
    En sistemas de delegación de votos, cuando un usuario delega su voting power
    a otro, el sistema debe asegurar que solo el delegatee puede votar con ese
    power. Si la implementación no deshabilita correctamente el voto del delegator,
    ambos pueden votar — duplicando efectivamente el voting power.
    Variante con self-delegation: ERC721Votes permite que el dueño del token
    se auto-delegue, y si _delegate() no verifica este caso, el power se cuenta
    doble (balance + delegated).
  como_funciona: |
    1. Alice tiene veNFT con 1000 voting power.
    2. Alice delega a Bob → Bob tiene 1000 delegated power.
    3. Bug: Alice aún puede llamar vote() directamente porque el sistema
       verifica balanceOf(Alice) en vez de getVotes(Alice) (que debería ser 0
       tras delegación).
    4. Ambos votan con 1000 power → 2000 power total de 1000 real.
    Variante (Nouns Builder): self-delegation en ERC721Votes hace que
    _moveDelegateVotes se llame con from == to, incrementando power sin
    decrementarlo de nadie.
  invariante: |
    // Invariante: suma de voting power delegado == totalSupply
    uint256 totalDelegated;
    for (uint i = 0; i < holders.length; i++) {
        totalDelegated += votingEscrow.getVotes(holders[i]);
    }
    assert(totalDelegated == votingEscrow.totalSupply());
  que_mirar:
    - "vote() verifica getVotes(msg.sender) o balanceOf(msg.sender)?"
    - "delegate() decrementa power del delegator?"
    - "Self-delegation (delegate(self)) maneja from == to correctamente?"
    - "transferFrom() actualiza delegaciones del sender Y del receiver?"
    - "Hay un MAX_DELEGATES limit que previene array DoS?"
  como_se_arregla: |
    vote() debe usar getVotes() (net de delegaciones) no balanceOf() (raw).
    _moveDelegateVotes debe no-op cuando from == to (self-delegation).
    Enforce que delegate() sets voting power of delegator to 0 for gauge voting.
  trampas:
    - "Self-delegation es el comportamiento DEFAULT en muchos contracts (OpenZeppelin) — verificar que el constructor inicializa delegates[msg.sender] = msg.sender."
    - "Delegación de voting power para governance (proposals) y para gauge voting pueden ser sistemas separados — verificar ambos."
    - "En Velocimeter el MAX_DELEGATES = 1024 causa DoS con 23M gas para transfer — el fix del double-count no debe introducir array DoS."
  solodit_ids:
    - "double-voting-by-delegaters-sigmaprime-none-tracer-pdf"
    - "h-04-erc721votes-token-owners-can-double-voting-power-through-self-delegation-code4rena-nouns-builder-nouns-builder-contest-git"
    - "malicious-users-can-double-their-voting-power-cyfrin-none-cyfrin-templedao-v21-markdown"
    - "the-delegator-resetting-self-delegation-causes-multiple-issues-in-the-protocol-cyfrin-none-cyfrin-templedao-v21-markdown"
  incidentes:
    - "Tracer (SigmaPrime) — Double voting by delegaters: delegator Y delegatee votan con el mismo power (HIGH)."
    - "Nouns Builder (C4) — ERC721Votes token owners can double voting power through self delegation (HIGH)."
    - "TempleDAO (Cyfrin) — Malicious users can double their voting power via delegation reset (HIGH)."
    - "Velocimeter (Sherlock) — DOS attack via MAX_DELEGATES = 1024: 23M gas para transfer/withdraw (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [delegation, double-counting, self-delegation, getVotes, balanceOf]
  relacionado_con: [gauge-001, gauge-002]
```

---

## 7. Gauge Creation DoS — Reward token flooding y gauge ilimitados

```yaml
- id: gauge-007
  titulo: "Creación ilimitada de gauges o reward tokens causa DoS en loops de distribución"
  causa_raiz: |
    En Velodrome/Solidly forks, notifyRewardAmount() en Gauge/Bribe es permissionless
    y permite agregar cualquier token como reward token hasta MAX_REWARD_TOKENS (16).
    Un atacante puede llenar el array con tokens maliciosos que reviertan en transfer,
    bloqueando deliverBribes() o getReward() para todos los usuarios.
    Variante: si gauges se pueden crear sin restricción, la función distribute()
    que itera sobre todos los gauges puede exceder el gas limit del bloque.
  como_funciona: |
    Ataque 1 (Reward Token Flooding):
    1. Atacante crea token ERC20 malicioso que acepta transferFrom pero revierte en transfer.
    2. Llama notifyRewardAmount(maliciousToken, 1 wei) en el Gauge/Bribe.
    3. Repite con 15 tokens diferentes hasta llenar rewards[].
    4. deliverBribes() intenta transferir cada reward token → revierte en el malicioso.
    5. TODAS las rewards legítimas quedan bloqueadas permanentemente.

    Ataque 2 (Gauge DoS):
    1. Voter.createGauge() sin restricción → crear cientos de gauges.
    2. distribute() itera sobre todos los gauges activos.
    3. Con suficientes gauges, distribute() excede block gas limit → DoS.
  invariante: |
    // Invariante: solo tokens whitelisted pueden ser reward tokens
    // assert(isWhitelisted[rewardToken] || msg.sender == admin)

    // Invariante: distribute() debe funcionar con N gauges
    uint256 gasStart = gasleft();
    voter.distribute();
    uint256 gasUsed = gasStart - gasleft();
    assert(gasUsed < block.gaslimit * 80 / 100);
  que_mirar:
    - "notifyRewardAmount tiene access control o cualquiera puede llamarlo?"
    - "MAX_REWARD_TOKENS existe? Qué pasa cuando se llena?"
    - "Hay función removeRewardToken() o los tokens son permanentes?"
    - "distribute() itera sobre todos los gauges o usa pagination?"
    - "createGauge() tiene restricciones (whitelist, fee, governance approval)?"
  como_se_arregla: |
    Restringir notifyRewardAmount a owner/voter solamente.
    Agregar removeRewardToken() con access control.
    Implementar pagination en distribute() con startIndex/endIndex.
    Requerir governance approval para createGauge().
  trampas:
    - "En Velodrome v2, notifyRewardAmount fue restringido — solo es vulnerable en v1 y forks que no actualizaron."
    - "El DoS por gas puede no ser explotable si distribute() acepta rangos de gauges."
    - "Algunos protocolos permiten notifyRewardAmount permissionless BY DESIGN para que cualquiera pueda agregar incentivos — verificar intención."
  solodit_ids:
    - "m-08-temporary-dos-by-calling-notifyrewardamount-in-bribegauge-with-malicious-tokens-code4rena-velodrome-finance-velodrome-finance-git"
    - "incorrect-gauge-weight-initialization-in-addgauge-causes-permanent-dos-in-updateperiod-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "unlimited-gauge-numbers-can-dos-users-distribute-action-immunefi-alchemix-git"
  incidentes:
    - "Velodrome v1 (C4) — notifyRewardAmount permissionless permite DoS temporal con tokens maliciosos en Gauge/Bribe: todos los reward tokens bloqueados (MEDIUM)."
    - "Velodrome v1 (C4) — Gauge's reward tokens array can be permanently flooded up to MAX_REWARD_TOKENS = 16, sin función de removal (MEDIUM)."
    - "Alchemix (Immunefi) — Unlimited gauge numbers can DoS user's distribute action: cientos de gauges exceden gas (MEDIUM)."
    - "RAAC (CodeHawks) — Incorrect gauge weight initialization in addGauge causes permanent DoS in updatePeriod (MEDIUM)."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [DoS, notifyRewardAmount, MAX_REWARD_TOKENS, reward-flooding, gas-limit, createGauge]
  relacionado_con: [gauge-004, staking-003]
```

---

## 8. Bribe Market Exploitation — Claim bribes sin votar o vote-then-withdraw

```yaml
- id: gauge-008
  titulo: "Reclamar bribes sin haber votado, o votar y retirar antes del epoch end"
  causa_raiz: |
    Los bribe contracts distribuyen incentivos a los votantes de un gauge.
    Si hay desync entre el momento en que se registra el voto y cuando se
    toma el snapshot para distribución de bribes, un atacante puede:
    (a) reclamar bribes de epochs en los que no votó, o
    (b) votar justo antes del snapshot, retirar después, y cobrar bribes sin
    mantener el lock durante todo el epoch.
    Alchemix tuvo MÚLTIPLES findings de este tipo en Immunefi.
  como_funciona: |
    Ataque 1 (Claim sin votar):
    1. El bribe contract usa tokenRewardsPerEpoch[token][epochStart] para distribución.
    2. deliverReward() no resetea tokenRewardsPerEpoch a 0 después de distribuir.
    3. Atacante llama claimBribes() para un epoch anterior → recibe rewards de nuevo.

    Ataque 2 (Vote-then-withdraw):
    1. Atacante observa bribes depositados para epoch N.
    2. Justo antes del epoch flip: crea lock + vota por el gauge bribeado.
    3. Epoch N termina, snapshot se toma incluyendo el voto del atacante.
    4. Atacante reclama bribes proporcionales a su voting power.
    5. Inmediatamente retira/vende el veToken.

    Ataque 3 (Desync bribes/emissions):
    1. Bribes se depositan y son claimables sin que el gauge reciba emisiones.
    2. Votante cobra bribes pero el pool no recibe los emissions esperados.
  invariante: |
    // Invariante: solo se puede reclamar bribes para epochs donde se votó
    // assert(hasVoted[tokenId][epochId] == true || claimBribes reverts)

    // Invariante: total bribes claimed <= total bribes deposited per epoch
    uint256 totalClaimed;
    for (uint i = 0; i < voters.length; i++) {
        totalClaimed += bribe.claimed(voters[i], epoch);
    }
    assert(totalClaimed <= bribe.totalRewardsForEpoch(epoch));
  que_mirar:
    - "claimBribes verifica que el usuario VOTÓ durante ese epoch?"
    - "deliverReward resetea tokenRewardsPerEpoch después de distribuir?"
    - "Hay desync temporal entre cuándo se registran votos y cuándo se distribuyen bribes?"
    - "El snapshot de votos para bribes se toma al inicio o al final del epoch?"
    - "Se puede votar después de que el snapshot ya fue tomado?"
  como_se_arregla: |
    Verificar que el usuario votó durante el epoch antes de permitir claim.
    Resetear tokenRewardsPerEpoch a 0 después de distribución.
    Tomar snapshot al FINAL del epoch, no al inicio.
    Implementar cooldown entre voto y eligibilidad para bribes (mínimo 1 epoch).
  trampas:
    - "En Velodrome v2 el bribe system fue rediseñado significativamente — muchos de estos bugs son v1."
    - "Si bribes se distribuyen proporcionalmente a voting power Y hay lock mínimo de 1 epoch, el ataque de vote-then-withdraw se mitiga."
    - "Los bribes son un sistema social/económico — algunos protocolos consideran 'acceptable' que un usuario vote solo para bribes."
  solodit_ids:
    - "a-user-is-able-to-claim-more-bribes-than-they-have-earned-immunefi-alchemix-git"
    - "claiming-bribes-for-epochs-you-didnt-vote-for-leading-to-protocol-insolvency-immunefi-alchemix-git"
    - "desync-between-bribes-being-paid-and-gauge-distribution-allows-voters-to-receive-bribes-without-spearbit-none-velodrome-finance-pdf"
    - "front-running-of-poketokens-could-lead-to-loss-of-portion-of-bribe-claims-to-all-voters-of-a-gauge-immunefi-alchemix-git"
    - "h-4-voters-will-lose-all-bribe-rewards-forever-if-they-do-not-claim-their-rewards-after-the-last-bribing-period-sherlock-magicsea-the-native-dex-on-the-iotaevm-git"
  incidentes:
    - "Alchemix (Immunefi) — Claiming bribes for epochs you didn't vote for, leading to protocol insolvency (HIGH)."
    - "Alchemix (Immunefi) — User able to claim more bribes than earned via checkpoint manipulation (HIGH)."
    - "Velodrome (Spearbit) — Desync between bribes being paid and gauge distribution: voters receive bribes without triggering emissions (MEDIUM)."
    - "Alchemix (Immunefi) — Front-running of pokeTokens leads to loss of bribe claims for all gauge voters (HIGH)."
    - "MagicSea (Sherlock) — Voters lose ALL bribe rewards forever if they don't claim after last bribing period (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [bribe, claim, epoch, desync, vote-then-withdraw, deliverReward]
  relacionado_con: [gauge-003, gauge-014]
```

---

## 9. veToken Balance Decay Miscalculation

```yaml
- id: gauge-009
  titulo: "Error en el cálculo del decay lineal del balance de veToken (slope/bias)"
  causa_raiz: |
    En vote-escrow estilo Curve, el voting power decae linealmente:
    balance = bias - slope * (t - t0), donde bias = amount * (lockEnd - t0) / MAXTIME.
    Errores comunes: (a) no actualizar el slope/bias global cuando un usuario
    modifica su lock, (b) underflow cuando t > lockEnd sin protection,
    (c) epoch boundary calculations que no alinean timestamps correctamente,
    (d) totalSupply decay que no suma los slopes individuales de forma correcta.
    Esto afecta tanto voting power como reward distribution.
  como_funciona: |
    1. En Curve-style: global slope_changes[] tracking qué slope se elimina en qué
       timestamp. Si un usuario hace increase_unlock_time(), el sistema debe
       (a) remover el slope_change antiguo, (b) agregar el nuevo.
    2. Bug: si solo se agrega el nuevo sin remover el antiguo, el slope_change
       antiguo sigue programado → cuando ese timestamp llega, totalSupply decay
       se decrementa DOS VECES (slope antiguo + slope nuevo).
    3. Resultado: totalSupply se desploma a 0 prematuramente.
    4. Con totalSupply near-zero: cualquier user con balance mínimo tiene 99%+ del
       voting power → controla todas las emisiones.
    Variante: underflow en balance = bias - slope * dt cuando dt > bias/slope,
    retornando tipo(uint256).max en unchecked arithmetic.
  invariante: |
    // Invariante: totalSupply >= sum de balanceOfNFT de todos los tokens
    uint256 sumBalances;
    for (uint i = 1; i <= maxTokenId; i++) {
        if (ownerOf(i) != address(0)) {
            sumBalances += votingEscrow.balanceOfNFT(i);
        }
    }
    assert(votingEscrow.totalSupply() >= sumBalances);
    // Tolerancia: sumBalances puede ser < totalSupply por rounding, pero no al revés

    // Invariante: balance nunca es negativo (underflow)
    assert(votingEscrow.balanceOfNFT(tokenId) <= votingEscrow.locked(tokenId).amount);
  que_mirar:
    - "increase_unlock_time() actualiza slope_changes[] correctamente (remove old + add new)?"
    - "balanceOfNFT retorna 0 cuando t > lockEnd o puede underflow?"
    - "totalSupply usa slope_changes para calcular decay o recalcula desde scratch?"
    - "Los timestamps en epoch boundaries están alineados a semanas (como Curve) o custom?"
    - "Hay protección contra underflow en bias - slope * dt?"
  como_se_arregla: |
    En increase_unlock_time: remover slope_change antiguo ANTES de agregar nuevo.
    Retornar 0 (no underflow) cuando bias < slope * dt.
    Usar math con checked arithmetic para detectar underflows.
    Alinear timestamps a epoch boundaries (múltiplos de WEEK en Curve).
  trampas:
    - "El decay lineal ES el comportamiento esperado de veTokens — no reportar 'balance decrece con el tiempo' como bug."
    - "Discrepancias pequeñas (< 1%) entre totalSupply y sum(balances) son normales por rounding de slopes."
    - "Si el protocolo usa veNFTs (no veCRV), el decay puede estar implementado diferente — verificar la implementación específica."
  solodit_ids:
    - "lack-of-time-weighted-voting-and-weight-decay-in-gaugecontroller-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "faulty-gauge-weight-update-formula-voting-power-delta-not-considered-leading-to-arithmetic-underflow-and-vote-weight-inconsistency-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "h-02-losing-voting-power-in-rewards-distribution-pashov-audit-group-none-hyperstable_2025-03-19-markdown"
  incidentes:
    - "RAAC (CodeHawks) — Lack of time-weighted voting and weight decay in GaugeController: votos no decaen, distorsionando distribución (MEDIUM)."
    - "RAAC (CodeHawks) — Faulty gauge weight update formula: voting power delta no considerado, arithmetic underflow (HIGH)."
    - "Hyperstable (Pashov) — Losing voting power in rewards distribution: decay mal calculado causa pérdida (HIGH)."
    - "Canto (C4) — update_market() nextEpoch calculation incorrect: epoch boundaries mal alineados (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [decay, slope, bias, totalSupply, underflow, slope_changes, veToken]
  relacionado_con: [gauge-002, gauge-014]
```

---

## 10. Cross-Gauge Reward Manipulation

```yaml
- id: gauge-010
  titulo: "Stakear en gauge A pero reclamar rewards de gauge B, o manipular distribución entre gauges"
  causa_raiz: |
    Cuando el sistema de distribución de rewards usa un pool global
    (Voter.distribute()) que itera sobre todos los gauges, errores en la
    lógica de distribución pueden causar que un gauge reciba rewards
    destinadas a otro. Esto ocurre cuando:
    (a) availableRewards se decrementa sequentially — primer gauge roba de los siguientes,
    (b) los pesos de distribución se calculan incorrectamente o no suman 100%,
    (c) claimable_tokens usa un index incorrecto al mapear gauge → rewards.
    En ZeroLend: rewards enviadas al PoolVoter eran undispatchable y se perdían.
  como_funciona: |
    1. Voter.distribute() calcula: reward[gaugeI] = totalEmissions * weight[gaugeI] / totalWeight.
    2. Bug: si massUpdatePools itera secuencialmente y DECREMENTA availableRewards
       después de cada pool, el primer pool reduce lo que queda para los demás.
    3. Pool 1 (weight 50%) recibe 50% de totalEmissions → availableRewards -= 50%.
    4. Pool 2 (weight 30%) recibe 30% de availableRewards (que ya es 50%) = 15% real.
    5. Pool 2 recibió 15% en vez de 30% → stolen by Pool 1.
    6. Últimos pools reciben near-zero.
  invariante: |
    // Invariante: sum of distributed rewards == total emissions
    uint256 totalDistributed;
    for (uint i = 0; i < gauges.length; i++) {
        totalDistributed += gauge[i].claimable();
    }
    // Debe ser approx igual a totalEmissions (±rounding)
    assert(totalDistributed <= totalEmissions);
    assert(totalDistributed >= totalEmissions - gauges.length); // max rounding loss

    // Invariante: cada gauge recibe proporcional a su weight
    // reward[i] ~= totalEmissions * weight[i] / totalWeight
  que_mirar:
    - "distribute() calcula rewards de cada gauge independientemente del total distribuido?"
    - "Hay un shared 'remaining' que se decrementa sequentially?"
    - "totalWeight == sum de todos los weights individuales?"
    - "Se puede llamar distribute() múltiples veces para el mismo epoch?"
    - "Rewards no distribuidas (por gauge muerto) se acumulan o se pierden?"
  como_se_arregla: |
    Calcular cada reward de forma independiente: reward[i] = totalEmissions * weight[i] / totalWeight.
    No usar variable 'remaining' que se decrementa.
    Guard contra distribute() duplicado por epoch con mapping(epoch => distributed).
  trampas:
    - "La distribución sequential con remaining no siempre es un bug — si se hace correctamente (cada uno recibe weight/totalWeight * original), el remaining se actualiza bien."
    - "Dust acumulado por rounding en distribución es normal — solo reportar si es > 1% del total."
    - "Si distribute() es permissionless y se puede llamar para gauges individuales, no hay DoS por gas."
  solodit_ids:
    - "h-01-incorrect-next-epoch-supply-usage-affects-reward-calculation-pashov-audit-group-none-kittenswap_2025-05-07-markdown"
    - "gaugecontroller-calculereward-implementation-will-cause-smaller-shares-to-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "any-rewards-sent-to-the-poolvoter-will-be-undispatchable-and-lost-immunefi-zerolend-git"
    - "bug-in-reward-distribution-logic-leads-to-theft-of-rewards-immunefi-zerolend-git"
  incidentes:
    - "ZeroLend (Immunefi) — Any rewards sent to the PoolVoter will be undispatchable and lost (HIGH)."
    - "ZeroLend (Immunefi) — Bug in reward distribution logic leads to theft of rewards (HIGH)."
    - "RAAC (CodeHawks) — GaugeController._calculateReward causes smaller shares to receive disproportionate rewards (HIGH)."
    - "KittenSwap (Pashov) — Incorrect next epoch supply usage affects reward calculation: rewards mal distribuidas entre gauges (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [cross-gauge, distribute, weight, totalWeight, sequential, availableRewards]
  relacionado_con: [gauge-005, gauge-015]
```

---

## 11. Gauge Kill / Deprecation Accounting Errors

```yaml
- id: gauge-011
  titulo: "Gauge killed/paused sigue distribuyendo rewards o bloquea fondos de usuarios"
  causa_raiz: |
    Cuando un gauge se "mata" (killGauge()) o se pausa, el sistema debe:
    (a) detener emisiones futuras, (b) permitir a stakers retirar su LP,
    (c) actualizar totalWeight y activeGaugeNumber correctamente.
    Los bugs ocurren cuando: killGauge no decrementa activeGaugeNumber
    (causando sobre-emisión), o cuando usuarios no pueden unstake de un gauge muerto,
    o cuando el gauge muerto sigue recibiendo votos y acumulando rewards que nadie
    puede reclamar.
  como_funciona: |
    Ataque 1 (Sobre-emisión):
    1. Protocolo tiene 10 gauges activos, activeGaugeNumber = 10.
    2. Governance mata gauge #3: isAlive[3] = false.
    3. Bug: activeGaugeNumber NO se decrementa → sigue siendo 10.
    4. weeklyEmission / activeGaugeNumber calcula emissions para 10 gauges.
    5. Solo 9 gauges reciben: cada uno recibe 1/10 en vez de 1/9.
    6. El 1/10 restante se pierde o se acumula en el Voter contract.

    Ataque 2 (Fondos bloqueados):
    1. Usuario tiene LP staked en gauge #3.
    2. Governance mata gauge #3.
    3. withdraw() tiene un require(isAlive[gauge]) → usuario no puede retirar.
    4. Fondos bloqueados permanentemente.

    Ataque 3 (Votos en gauge muerto):
    1. Gauge #3 está muerto pero vote() no verifica isAlive.
    2. Usuarios siguen votando por gauge muerto → votos no producen emisiones.
    3. Voting power efectivamente perdido.
  invariante: |
    // Invariante: activeGaugeNumber == count de gauges con isAlive == true
    uint256 aliveCount;
    for (uint i = 0; i < allGauges.length; i++) {
        if (isAlive[allGauges[i]]) aliveCount++;
    }
    assert(activeGaugeNumber == aliveCount);

    // Invariante: stakers pueden withdraw de gauge muerto
    // (withdraw NO debe revertir para gauges killed)
  que_mirar:
    - "killGauge() decrementa activeGaugeNumber?"
    - "withdraw() funciona para gauges muertos (no tiene require(isAlive))?"
    - "vote() verifica isAlive antes de registrar voto?"
    - "Las rewards acumuladas pre-kill son reclamables post-kill?"
    - "reviveGauge() existe? Qué estado restaura?"
  como_se_arregla: |
    killGauge() debe decrementar activeGaugeNumber.
    withdraw() debe funcionar independientemente de isAlive.
    vote() debe revertir para gauges muertos.
    claimRewards() debe permitir reclamar rewards acumuladas pre-kill.
  trampas:
    - "Algunos protocolos NO usan activeGaugeNumber para cálculos — verificar si realmente afecta emisiones."
    - "killGauge puede ser un admin-only action — si requires governance proposal + timelock, el impacto es menor."
    - "No confundir gauge 'paused' (temporal) con 'killed' (permanente) — pueden tener lógicas diferentes."
  solodit_ids:
    - "h-4-pause-or-kill-gauge-can-lead-to-flow-token-stuck-in-voter-sherlock-velocimeter-git"
    - "killed-gauge-can-be-voted-for-openzeppelin-none-retrothena-audit-markdown"
    - "the-killed-gauge-will-return-the-incorrect-rate-mixbytes-none-curve-finance-markdown"
    - "h-01-repeated-distributions-for-killed-gauges-can-block-valid-distributions-pashov-audit-group-none-kittenswap_2025-07-31-markdown"
    - "killing-a-gauge-could-result-in-stuck-funds-openzeppelin-none-retrothena-audit-markdown"
  incidentes:
    - "Velocimeter (Sherlock) — pause/kill gauge no decrementa activeGaugeNumber: más FLOW tokens emitidos de lo esperado (HIGH)."
    - "Velocimeter (Sherlock) — pause/kill gauge deja FLOW tokens stuck en Voter contract (HIGH)."
    - "Retro/Thena (OpenZeppelin) — Killed gauge can be voted for: voting power perdido (HIGH)."
    - "Retro/Thena (OpenZeppelin) — Killing a gauge could result in stuck funds: stakers no pueden retirar (HIGH)."
    - "Curve Finance (MixBytes) — The killed gauge will return the incorrect rate (LOW)."
    - "KittenSwap (Pashov) — Repeated distributions for killed gauges block valid distributions (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [killGauge, isAlive, activeGaugeNumber, stuck-funds, paused, deprecation]
  relacionado_con: [gauge-007, gauge-010]
```

---

## 12. NFT Position Staking in Gauges — Bugs de custodia y liquidación

```yaml
- id: gauge-012
  titulo: "Bugs al stakear posiciones NFT (Uni V3 / Aerodrome style) en gauges: custodia, liquidación, compounding"
  causa_raiz: |
    En sistemas como Revert Lend / Aerodrome, una posición Uniswap V3 (NFT ERC721)
    se stakea en un gauge para ganar rewards. El NFT sale de la custodia del vault
    y entra en la del gauge. Esto crea problemas cuando:
    (a) El vault necesita liquidar una posición que está staked en el gauge,
    (b) El valor de la posición cambia (swap, rerange) mientras está en el gauge,
    (c) El gauge no actualiza reward checkpoints al cambiar liquidez.
    La custodia dual (vault vs gauge) es una superficie de ataque rica.
  como_funciona: |
    Ataque (Revert Lend style):
    1. Borrower stakea su posición NFT en GaugeManager para ganar AERO rewards.
    2. La posición se transfiere del V3Vault al gauge.
    3. La posición se vuelve liquidable (oracle price cambia).
    4. Liquidador llama liquidate() en V3Vault.
    5. V3Vault intenta tomar el NFT pero está en el gauge → o revierte (DoS de
       liquidación) o la fee de liquidación no se calcula correctamente porque
       el NFT no está en el vault.
    6. Variante: compound() se llama en AutoRangeAndCompound mientras el NFT está
       en el gauge → la posición cambia de rango sin que el gauge se entere.
  invariante: |
    // Invariante: NFT está en EXACTAMENTE un lugar (vault XOR gauge, never both/neither)
    address nftOwner = nonfungiblePositionManager.ownerOf(tokenId);
    bool inVault = (nftOwner == address(vault));
    bool inGauge = (nftOwner == address(gauge));
    assert(inVault != inGauge); // XOR

    // Invariante: posición staked es liquidable (liquidación no revierte)
    // Si health < 1, liquidate() debe poder ejecutarse
  que_mirar:
    - "Quién tiene custodia del NFT cuando está staked en gauge?"
    - "liquidate() puede ejecutar cuando el NFT está en el gauge (no en el vault)?"
    - "onERC721Received callback del gauge puede bloquear transferencias?"
    - "compound/rerange actualizan el estado del gauge cuando cambian la posición?"
    - "Las fees del NFT (Uniswap fees) se reclaman correctamente desde el gauge?"
  como_se_arregla: |
    Liquidación debe poder unstake del gauge atómicamente en la misma tx.
    El gauge debe emitir evento / callback cuando la posición cambia.
    Usar proxy/wrapper que mantiene custodia virtual sin mover el NFT físicamente.
    GaugeManager debe implementar unstakeForLiquidation() callable por el vault.
  trampas:
    - "En Revert Lend, el GaugeManager mantiene una referencia lógica — el NFT puede no moverse físicamente. Verificar la implementación real."
    - "Aerodrome gauges nativos manejan NFT positions diferente de UniV3Staker. No asumir que son iguales."
    - "El auto-compound que cambia ticks no necesariamente afecta al gauge si el gauge solo trackea balances, no ticks."
  solodit_ids:
    - "nft-cannot-be-withdrawn-after-all-liquidity-was-removed-from-the-position-spearbit-none-velodrome-finance-pdf"
    - "staked-lockers-cannot-be-unlocked-without-prior-unstaking-mixbytes-none-velodrome-markdown"
    - "bribe-and-fee-token-emissions-can-be-gamed-by-users-spearbit-none-velodrome-finance-pdf"
  incidentes:
    - "Velodrome (Spearbit) — NFT cannot be withdrawn after all liquidity was removed from the position: staker bloqueado (MEDIUM)."
    - "Velodrome (MixBytes) — Staked lockers cannot be unlocked without prior unstaking (LOW)."
    - "Velodrome (Spearbit) — Bribe and fee token emissions can be gamed by users via position manipulation (MEDIUM)."
    - "Revert Lend (C4 2024) — Multiple liquidation-related findings when positions interact with external gauge systems."
  severidad: high
  confianza: alta
  verificado: true
  tags: [NFT, ERC721, gauge-staking, custodia, liquidation, compound, rerange]
  relacionado_con: [gauge-011, lending-vault]
```

---

## 13. Boost Calculation Exploit — workingSupply manipulation

```yaml
- id: gauge-013
  titulo: "Manipulación de workingSupply/workingBalance para inflar boost de rewards"
  causa_raiz: |
    En Curve-style gauges, el boost se calcula como:
    workingBalance = min(userLiquidity, 0.4 * userLiquidity + 0.6 * totalLiquidity * veCRV_user / veCRV_total).
    workingSupply = sum(workingBalances). Las rewards se distribuyen proporcional
    a workingBalance/workingSupply.
    Si workingSupply se puede manipular (e.g., siempre se sobreescribe en vez de
    actualizar incrementalmente, o la delegación de boost no actualiza workingSupply),
    el atacante puede inflar su share de rewards.
  como_funciona: |
    Ataque (RAAC style):
    1. BoostController calcula workingSupply para un gauge.
    2. Bug: setBoost() sobreescribe workingSupply en vez de hacer +=/-=.
    3. Si solo el atacante llama setBoost(), workingSupply = solo su workingBalance.
    4. Su share = workingBalance / workingSupply = 100% de las rewards.
    5. Otros stakers no reciben nada hasta que alguien llame setBoost para ellos.

    Variante: delegation removal no reduce workingSupply del delegatee.
    1. Alice delega boost a Bob → Bob's workingBalance aumenta.
    2. Alice remove delegación → workingSupply debería decrementarse.
    3. Bug: workingSupply no se actualiza → Bob mantiene boost inflado.
    4. Efecto permanente: workingSupply queda inflado, diluyendo rewards de todos.
  invariante: |
    // Invariante: workingSupply == sum de workingBalances
    uint256 sumWorking;
    for (uint i = 0; i < stakers.length; i++) {
        sumWorking += gauge.workingBalance(stakers[i]);
    }
    assert(gauge.workingSupply() == sumWorking);

    // Invariante: workingBalance <= user's staked balance
    assert(gauge.workingBalance(user) <= gauge.balanceOf(user));
  que_mirar:
    - "workingSupply se actualiza incrementalmente (+=/-=) o se sobreescribe?"
    - "Todas las funciones que cambian balances (stake/unstake/delegate) actualizan workingSupply?"
    - "La delegación de boost actualiza workingSupply del gauge?"
    - "user_checkpoint() recalcula workingBalance y actualiza workingSupply?"
    - "Hay un kick() function para forzar actualización de usuarios inactivos?"
  como_se_arregla: |
    workingSupply debe actualizarse incrementalmente: -= oldWorking, += newWorking.
    Cada operación que cambia balance o boost debe llamar user_checkpoint().
    Implementar kick() para que cualquiera pueda forzar update de usuarios stale.
  trampas:
    - "El boost de 2.5x en Curve es el máximo teórico — en la práctica raramente se alcanza. Verificar los parámetros reales."
    - "workingSupply overwrite puede ser by-design si se recalcula desde scratch en cada operación (but expensive in gas)."
    - "En protocolos sin veCRV boost (flat rewards), este patrón no aplica."
  solodit_ids:
    - "workingsupply-would-always-be-overwritten-in-boostcontrollersol-impacting-reward-calculations-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "permanent-boost-inflation-through-delegation-removal-in-boostcontrollersol-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "weight-calculation-mismatch-in-rwagauge-contract-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "missing-boost-state-update-in-extend-and-withdraw-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "RAAC (CodeHawks) — workingSupply always overwritten in BoostController: impacta reward calculations para todos los stakers (MEDIUM)."
    - "RAAC (CodeHawks) — Permanent boost inflation through delegation removal: workingSupply nunca se reduce (MEDIUM)."
    - "RAAC (CodeHawks) — Weight calculation mismatch in RWAGauge contract (LOW)."
    - "RAAC (CodeHawks) — Missing boost state update in extend() and withdraw(): boost no se actualiza al cambiar lock (MEDIUM)."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [boost, workingSupply, workingBalance, delegation, veCRV, kick]
  relacionado_con: [gauge-005, gauge-006]
```

---

## 14. Epoch Boundary Timing Attacks — Double-claim y skip de penalties

```yaml
- id: gauge-014
  titulo: "Acciones en el instante exacto del epoch flip para double-claim o evadir penalties"
  causa_raiz: |
    Los gauge systems operan en epochs (típicamente 1 semana). En el momento exacto
    del epoch boundary (block.timestamp == epochStart + EPOCH_DURATION), la lógica
    de distribución puede tener off-by-one errors que permiten:
    (a) reclamar rewards del epoch N Y del epoch N+1 en la misma transacción,
    (b) depositar justo después del flip para capturar rewards del epoch completo,
    (c) evitar penalización de lock expirado votando justo antes del flip.
    El caching de totalSupply en RewardsDistributor es una fuente frecuente de este bug.
  como_funciona: |
    Ataque 1 (Double claim via epoch boundary):
    1. Epoch N termina en timestamp T.
    2. En timestamp T exacto: earned() calcula rewards incluyendo AMBOS epochs.
    3. Atacante llama getReward() → recibe rewards de epoch N + epoch N+1.
    4. Otros usuarios del epoch N+1 reciben menos.

    Ataque 2 (FLUX accrual via merge at boundary):
    1. Cada epoch, FLUX se acumula proporcionalmente al veNFT balance.
    2. En el epoch boundary: merge token A → B.
    3. B ahora tiene el balance combinado y acumula FLUX como si hubiera
       tenido ese balance todo el epoch.
    4. Reset token B, crear nuevo token C, merge B → C, repetir.
    5. FLUX infinito en un epoch.

    Ataque 3 (Reward dilution via caching):
    1. RewardsDistributor cachea totalSupply al inicio del epoch.
    2. Nuevos stakers llegan durante el epoch pero no están en el cache.
    3. Reward calculation usa cached totalSupply (menor) → existing stakers
       reciben más de lo que deberían.
  invariante: |
    // Invariante: rewards claimed en epoch N no pueden incluir epoch N+1
    uint256 currentEpoch = block.timestamp / EPOCH_DURATION;
    uint256 claimedEpoch = lastClaimEpoch[user];
    assert(claimedEpoch <= currentEpoch);

    // Invariante: no se puede acumular FLUX/rewards más de 1 vez por epoch por token
    assert(lastAccrualEpoch[tokenId] < currentEpoch || accrued[tokenId] == 0);
  que_mirar:
    - "earned() usa >= o > para epoch boundary? Off-by-one?"
    - "RewardsDistributor cachea totalSupply? Cuándo se actualiza?"
    - "merge/split en epoch boundary permite doble acumulación?"
    - "El epoch flip es inclusive o exclusive? (timestamp == epochEnd pertenece a N o N+1?)"
    - "checkpoint_token() se llama al inicio del epoch o es lazy?"
  como_se_arregla: |
    Usar convention consistente para boundaries: epoch N = [epochStart, epochEnd).
    No cachear totalSupply — usar supply al momento del claim.
    Implementar per-epoch claim tracking para prevenir double-claim.
    merge/split deben checkpoint FLUX accrual antes de ejecutar.
  trampas:
    - "Off-by-one en epoch boundaries es sutil — necesitas PoC con timestamp exacto para demostrar."
    - "El caching de totalSupply en RewardsDistributor puede ser intencional para gas optimization — verificar si hay update mechanism."
    - "Algunos protocolos usan block.number en vez de block.timestamp para epochs — diferentes vectores de ataque."
  solodit_ids:
    - "reward-calculates-earned-incorrectly-on-each-epoch-boundary-spearbit-none-velodrome-finance-pdf"
    - "merging-tokens-allows-multiple-flux-accruals-within-an-epoch-immunefi-alchemix-git"
    - "m-16-double-reward-claim-in-externalbribe-pashov-audit-group-none-kittenswap_2025-05-07-markdown"
    - "h-02-update-market-nextepoch-calculation-incorrect-code4rena-canto-canto-git"
    - "timestamp-boundary-condition-causes-reward-dilution-for-active-operators-codehawks-none-suzaku-core-git"
  incidentes:
    - "Velodrome (Spearbit) — Reward calculates earned incorrectly on each epoch boundary: off-by-one en cálculo (HIGH)."
    - "Alchemix (Immunefi) — Merging tokens allows multiple FLUX accruals within an epoch: FLUX infinito (HIGH)."
    - "Alchemix (Immunefi) — Infinite minting of FLUX through Merge at epoch boundary (HIGH)."
    - "KittenSwap (Pashov) — Double reward claim in ExternalBribe: claim en boundary cubre 2 epochs (MEDIUM)."
    - "Canto (C4) — update_market() nextEpoch calculation incorrect: epoch math error (HIGH)."
    - "Suzaku Core (CodeHawks) — Timestamp boundary condition causes reward dilution for active operators (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [epoch, boundary, double-claim, off-by-one, timing, merge, FLUX, totalSupply-cache]
  relacionado_con: [gauge-001, gauge-008, gauge-009]
```

---

## 15. totalAllocation Desync — Suma de allocations individuales != total tracked

```yaml
- id: gauge-015
  titulo: "Desync entre sum(individual allocations) y totalAllocation/totalWeight tracked"
  causa_raiz: |
    Los sistemas de gauge mantienen dos contabilidades paralelas:
    (a) weights[gauge] — peso individual de cada gauge (sum de votos),
    (b) totalWeight — peso total (debe ser == sum de weights[]).
    Si alguna operación modifica weights[] sin actualizar totalWeight (o viceversa),
    se crea un desync. Lo mismo aplica a totalAllocation en bribe/reward contracts
    y a usedWeights[tokenId] vs sum de votes individuales.
    Esto causa: distribución incorrecta (un gauge recibe más/menos),
    arithmetic underflow en totalWeight -= weight, o votos "fantasma".
  como_funciona: |
    1. Usuario vota: weights[gaugeA] += 1000, totalWeight += 1000. OK.
    2. Governance remueve gaugeA: weights[gaugeA] se borra.
    3. Bug: totalWeight NO se decrementa → totalWeight incluye 1000 fantasma.
    4. Distribución: reward[gaugeB] = emissions * weights[gaugeB] / totalWeight.
    5. totalWeight es más grande de lo real → gaugeB recibe MENOS emissions.
    6. Las emissions del peso fantasma se pierden.

    Variante: vote() con pool inválido no falla pero no incrementa weights[]:
    1. _vote() intenta votar para pool que no tiene gauge.
    2. El voto se descuenta de usedWeights[tokenId] pero no se agrega a weights[pool].
    3. Desync: usedWeights > sum(votes) → usuario "perdió" voting power.
  invariante: |
    // Invariante: totalWeight == sum de weights de gauges vivos
    uint256 sumWeights;
    for (uint i = 0; i < allGauges.length; i++) {
        if (isAlive[allGauges[i]]) {
            sumWeights += weights[allGauges[i]];
        }
    }
    assert(totalWeight == sumWeights);

    // Invariante: usedWeights[tokenId] == sum de votes[tokenId][pool] para todos los pools
    uint256 sumVotes;
    for (uint i = 0; i < pools.length; i++) {
        sumVotes += votes[tokenId][pools[i]];
    }
    assert(usedWeights[tokenId] == sumVotes);
  que_mirar:
    - "remove_gauge / killGauge actualiza totalWeight?"
    - "vote() para pool sin gauge revierte o silently no-ops?"
    - "reset() decrementa tanto weights[pool] como totalWeight?"
    - "poke() recalcula correctamente o puede introducir desync?"
    - "Hay funciones view que recalculan totalWeight desde scratch para verificar?"
  como_se_arregla: |
    killGauge/removeGauge debe decrementar totalWeight por weights[gauge].
    vote() debe revertir si el pool no tiene gauge activo.
    Agregar función de reconciliación que recalcula totalWeight from scratch.
    Usar single source of truth: calcular totalWeight siempre desde sum(weights[]).
  trampas:
    - "El desync puede ser muy pequeño (1-2 wei por operación) y solo acumularse con miles de operaciones — no siempre es explotable."
    - "Si totalWeight se recalcula from scratch en cada distribute(), el desync se auto-corrige."
    - "Verificar que el gauge removido NO es re-agregable — si puede revivirse, el desync se puede revertir."
    - "veRWA (C4) — remover gauge bloquea voting power permanentemente. Es el mismo root cause pero el impacto es en el usuario, no en la distribución."
  solodit_ids:
    - "gauge-voting-misallocation-vulnerability-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "h-01-if-a-gauge-that-a-user-has-voted-for-gets-removed-their-voting-power-all-code4rena-canto-canto-git"
    - "m-07-incorrect-accounting-of-free-weight-in-decrementweightuntilfree-code4rena-tribe-turbo-tribe-turbo-contest-git"
    - "m-03-weight-loss-possible-due-to-invalid-pool-votes-in-vote-pashov-audit-group-none-kittenswap_2025-05-07-markdown"
    - "h-08-if-governance-removes-a-gauge-users-voting-power-for-that-gauge-will-be-lost-code4rena-canto-canto-git"
  incidentes:
    - "Canto (C4) — If gauge is removed, user's voting power for that gauge is permanently lost: totalWeight desync (HIGH)."
    - "RAAC (CodeHawks) — Gauge voting misallocation vulnerability: weights y totalWeight no sincronizados (HIGH)."
    - "Tribe (C4) — Incorrect accounting of free weight in _decrementWeightUntilFree: desync en weight tracking (MEDIUM)."
    - "KittenSwap (Pashov) — Weight loss possible due to invalid pool votes in _vote(): voto para pool sin gauge no revierte (MEDIUM)."
    - "veRWA (C4) — remove_gauge traps user voting power forever: require re-adding gauge for users to re-vote (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [totalWeight, totalAllocation, desync, weights, usedWeights, remove-gauge, accounting]
  relacionado_con: [gauge-010, gauge-011]
```

---

## 16. Gauge Reward Distribution During Staking — Reward update antes de balance change

```yaml
- id: gauge-016
  titulo: "Rewards no actualizadas antes de cambio de balance en stake/unstake de gauge"
  causa_raiz: |
    Siguiendo el patrón Synthetix, TODA función que modifica el balance de un
    staker (deposit, withdraw, stake, unstake) DEBE llamar updateReward() ANTES
    del cambio de balance. Si el update ocurre DESPUÉS (o no ocurre), el
    rewardPerTokenStored se calcula con el balance nuevo en vez del viejo,
    causando que el usuario gane rewards que no le corresponden (si depositó)
    o pierda rewards legítimas (si retiró).
  como_funciona: |
    1. Gauge tiene: Alice staked 100 LP, totalSupply = 100, rewardPerToken = 10.
    2. Alice earned = 100 * 10 = 1000 (pendiente de claim).
    3. Bob llama deposit(1000 LP). Bug: el contrato actualiza totalSupply a 1100
       ANTES de llamar updateReward().
    4. updateReward() calcula: newRewardPerToken con totalSupply = 1100.
    5. Las rewards del periodo anterior se diluyen: Alice pierde rewards.
    6. Variante en withdraw: withdrawToken() es public pero no llama
       _updateRewardForAllTokens() → rewards se pierden.
  invariante: |
    // Invariante: updateReward se llama ANTES de cambiar balance
    // (verificable en tests: earned() antes y después de deposit/withdraw sin avanzar tiempo)
    uint256 earnedBefore = gauge.earned(alice);
    vm.prank(bob);
    gauge.deposit(amount);
    // Sin avanzar tiempo, Alice's earned no debe cambiar
    assert(gauge.earned(alice) == earnedBefore);
  que_mirar:
    - "deposit()/withdraw() tienen modifier updateReward(msg.sender)?"
    - "Hay funciones alternativas (depositFor, withdrawToken) que bypasean el modifier?"
    - "El modifier se ejecuta ANTES de la lógica de balance change?"
    - "Las funciones externas que llaman deposit/withdraw internamente mantienen el modifier?"
    - "exit() combina withdraw + getReward atomically?"
  como_se_arregla: |
    Usar modifier updateReward(msg.sender) en TODA función que modifique balance.
    Asegurar que el modifier se ejecuta ANTES del cambio de estado.
    Revisar TODAS las funciones que cambian balance (incluyendo helpers internos).
  trampas:
    - "Si el modifier está presente pero se ejecuta DESPUÉS del balance change (via un bug en Solidity ordering), el efecto es el mismo que no tenerlo."
    - "En gauges con múltiples reward tokens, verificar que ALL tokens se actualizan, no solo el principal."
    - "NotifyRewardAmount con amount = 0 puede ser un edge case que rompe el cálculo."
  solodit_ids:
    - "h-05-voting-overwrites-checkpointvoted-in-last-checkpoint-so-users-can-just-vote-right-before-claiming-rewards-code4rena-velodrome-finance-velodrome-finance-git"
    - "m-1-new-staking-positions-still-gets-the-full-reward-amount-as-with-old-stakings-diluting-rewards-for-old-stakers-sherlock-magicsea-the-native-dex-on-the-iotaevm-git"
    - "gauge-rewards-are-not-transferred-to-gauge-when-distributerewards-is-called-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "Velodrome v1 (C4) — withdrawToken() público no llama _updateRewardForAllTokens: rewards perdidas para usuarios que retiran (HIGH)."
    - "MagicSea (Sherlock) — New staking positions get full reward amount as old ones: rewards diluidas para stakers existentes (MEDIUM)."
    - "RAAC (CodeHawks) — Gauge rewards not transferred to gauge when distributeRewards() is called: rewards stuck en controller (HIGH)."
    - "MagicSea (Sherlock) — withdrawFromPosition calls _harvestPosition before _updateBoostMultiplierInfoAndRewardDebt: order of operations bug (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [updateReward, modifier, balance-change, deposit, withdraw, order-of-operations]
  relacionado_con: [staking-001, staking-004, gauge-005]
```

---

## 17. Max Lock Permanent Trap — Enabling max lock sin poder deshabilitarlo

```yaml
- id: gauge-017
  titulo: "Usuario habilita max lock en VotingEscrow pero no puede deshabilitar, atrapando tokens"
  causa_raiz: |
    Algunos forks de Solidly implementan un "max lock" feature que mantiene el
    voting power al máximo sin decay. El usuario llama enable_max_lock() y su
    lock se extiende automáticamente al máximo en cada interacción. El bug ocurre
    cuando disable_max_lock() no existe, no funciona, o tiene un require que nunca
    se satisface. El usuario queda con sus tokens locked permanentemente (o hasta
    que alguien despliegue una actualización).
  como_funciona: |
    1. Usuario llama enable_max_lock(tokenId) → max_locked[tokenId] = true.
    2. Cada vez que alguien interactúa con el token (poke, vote, claim), el lock
       se extiende automáticamente: lockEnd = block.timestamp + MAXTIME.
    3. Usuario quiere retirar → llama disable_max_lock(tokenId).
    4. Bug: disable_max_lock() tiene un require que falla (e.g., requiere que
       el lock ya haya expirado, pero max lock previene la expiración).
    5. O: disable_max_lock() simplemente no existe en el contrato.
    6. Tokens trapped forever: ni withdraw ni transfer funcionan mientras
       max_locked es true y el lock no ha expirado.
  invariante: |
    // Invariante: si se puede habilitar max lock, se debe poder deshabilitar
    votingEscrow.enable_max_lock(tokenId);
    assert(max_locked[tokenId] == true);
    votingEscrow.disable_max_lock(tokenId);
    assert(max_locked[tokenId] == false);
    // Post-disable: lockEnd debe ser <= block.timestamp + MAXTIME (no infinito)
  que_mirar:
    - "Existe disable_max_lock() function?"
    - "disable_max_lock() tiene requires que lo hacen un no-op o unreachable?"
    - "Con max lock habilitado, puede el usuario hacer withdraw() alguna vez?"
    - "max_lock se resetea en transfer/merge/split?"
    - "Governance puede force-disable max lock en emergencia?"
  como_se_arregla: |
    Implementar disable_max_lock() sin restricciones excesivas.
    disable_max_lock() debe setear max_locked = false y dejar lockEnd como está.
    El withdraw debe funcionar después de disable + wait for expiry.
  trampas:
    - "Este bug es específico de Solidly forks con la feature de max lock. Curve original no tiene esta feature."
    - "Si el protocolo tiene governance que puede upgrade, los tokens no están permanentemente trapped — solo temporalmente."
    - "Algunos usuarios QUIEREN max lock permanente (es una feature) — solo es bug si no pueden desactivarla."
  solodit_ids:
    - "users-can-be-locked-from-voting-openzeppelin-none-retrothena-audit-markdown"
  incidentes:
    - "Velocimeter (Sherlock) — Voters can enable maxLock but cannot disable it: voting power no decrease pero tokens trapped (HIGH)."
    - "Retro/Thena (OpenZeppelin) — Users can be locked from voting: max lock prevents interaction (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [max-lock, enable, disable, trapped-tokens, VotingEscrow, Solidly-fork]
  relacionado_con: [gauge-001, gauge-011]
```

---

## 18. Gauge Weight Initialization Error — addGauge con peso incorrecto

```yaml
- id: gauge-018
  titulo: "Inicialización incorrecta de peso en addGauge causa DoS o distribución errónea"
  causa_raiz: |
    Cuando se agrega un nuevo gauge al sistema, su peso inicial debe ser 0
    (y crecer con los votos) o un valor base seteado por governance. Si addGauge()
    inicializa el peso incorrectamente (e.g., no inicializa time_weight,
    o setea un valor que causa division by zero en distribute), el nuevo gauge
    puede causar DoS en todo el sistema de distribución.
    En Curve-style: _get_weight() bypasea lógica si time_weight[gauge] == 0,
    retornando 0 siempre — incluso después de que usuarios voten.
  como_funciona: |
    1. Governance agrega nuevo gauge: addGauge(gaugeAddress).
    2. Bug: time_weight[gaugeAddress] no se inicializa (queda en 0).
    3. Usuarios votan por el nuevo gauge: vote_for_gauge_weights(gaugeAddress, 10000).
    4. En el siguiente checkpoint: _get_weight(gaugeAddress) verifica if (t > 0).
    5. Como time_weight = 0, t = 0, la condición falla → retorna weight = 0.
    6. Los votos de los usuarios no tienen efecto → el gauge nunca recibe emisiones.
    7. Peor: si el peso votado se acumula internamente pero _get_weight retorna 0,
       totalWeight no incluye estos votos → desync permanente.
  invariante: |
    // Invariante: después de addGauge, el gauge debe poder recibir votos efectivos
    voter.addGauge(newGauge);
    vm.prank(veHolder);
    voter.vote(tokenId, [newGauge], [10000]);
    // Avanzar 1 epoch
    vm.warp(block.timestamp + EPOCH_DURATION);
    voter.distribute();
    // El gauge debe haber recibido > 0 emissions
    assert(gauge.earned() > 0 || totalWeight == 0);
  que_mirar:
    - "addGauge inicializa time_weight / time_sum correctamente?"
    - "El primer voto después de addGauge funciona como esperado?"
    - "Governance debe llamar change_gauge_weight ANTES de que usuarios voten?"
    - "_get_weight retorna 0 para gauges recién agregados?"
    - "updatePeriod() itera sobre el nuevo gauge?"
  como_se_arregla: |
    addGauge() debe inicializar time_weight[gauge] = block.timestamp (o next epoch).
    _get_weight() debe manejar el caso de gauge recién agregado sin retornar 0 siempre.
    Agregar test: addGauge → vote → distribute → verify emissions received.
  trampas:
    - "En Curve DAO original, governance DEBE llamar change_gauge_weight antes de que usuarios voten — esto es by-design, no un bug."
    - "Si el protocolo tiene un 'warm-up period' para nuevos gauges, el peso 0 inicial puede ser intencional."
    - "Verificar si time_weight se inicializa en el constructor del gauge vs en addGauge del controller."
  solodit_ids:
    - "incorrect-gauge-weight-initialization-in-addgauge-causes-permanent-dos-in-updateperiod-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "missing-validation-for-minimum-vote-weight-in-vote-function-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
    - "lack-of-time-weighted-voting-and-weight-decay-in-gaugecontroller-codehawks-regnum-aurum-acquisition-corp-core-contracts-git"
  incidentes:
    - "RAAC (CodeHawks) — Incorrect gauge weight initialization in addGauge causes permanent DoS in updatePeriod (MEDIUM)."
    - "veRWA (C4) — Gauge weight not updated properly if governance doesn't change weight before voting: _get_weight returns 0 forever (HIGH)."
    - "RAAC (CodeHawks) — Missing validation for minimum vote weight in vote function (LOW)."
  severidad: medium
  confianza: alta
  verificado: true
  tags: [addGauge, initialization, time_weight, _get_weight, DoS, weight-zero]
  relacionado_con: [gauge-011, gauge-015]
```

---

## 19. Staking Position Lock Multiplier Manipulation

```yaml
- id: gauge-019
  titulo: "Manipulación del multiplicador de lock al agregar a posición existente"
  causa_raiz: |
    En sistemas tipo MlumStaking (MagicSea), el multiplier de rewards se calcula
    basado en la duración del lock al momento de crear la posición. Si el usuario
    puede agregar tokens a una posición existente (addToPosition), y el multiplier
    se recalcula basado en la duración ORIGINAL (no en la duración restante),
    el usuario puede crear una posición con lock largo, esperar hasta casi la
    expiración, y luego agregar tokens que obtienen un multiplier alto por un
    lock que está a punto de expirar.
  como_funciona: |
    1. Alice crea posición con lock de 365 días, amount = 100 tokens.
       lockMultiplier = max (basado en 365 días).
    2. Pasan 364 días. Lock casi expirado.
    3. Alice llama addToPosition(100_000 tokens).
    4. Bug: el multiplier para los 100_000 nuevos tokens se basa en el lock
       ORIGINAL de 365 días, no en el tiempo RESTANTE de 1 día.
    5. amountWithMultiplier = 100_100 * maxMultiplier (en vez de 100 * max + 100_000 * min).
    6. Alice reclama rewards desproporcionadas por 1 día de lock efectivo.
    7. Al día siguiente: lock expira, Alice retira todo.
  invariante: |
    // Invariante: el multiplier efectivo debe reflejar el tiempo restante
    uint256 remainingLock = position.lockEnd - block.timestamp;
    uint256 expectedMultiplier = getMultiplierByDuration(remainingLock);
    assert(position.lockMultiplier <= expectedMultiplier + TOLERANCE);
  que_mirar:
    - "addToPosition recalcula el multiplier basado en tiempo restante o en duración original?"
    - "El multiplier se aplica al amount total o solo al amount nuevo?"
    - "Se puede addToPosition cuando el lock está a punto de expirar?"
    - "harvestPosition se llama ANTES de actualizar amountWithMultiplier?"
    - "Hay un mínimo de lock restante para addToPosition?"
  como_se_arregla: |
    addToPosition debe recalcular el multiplier basado en el lock time restante.
    O: addToPosition debe resetear el lock al valor original (extender el lock).
    O: requerir un lock mínimo restante para addToPosition.
  trampas:
    - "Si addToPosition EXTIENDE el lock al valor original, el usuario pierde flexibilidad — puede ser by-design que el multiplier se base en la duración original."
    - "Verificar si el multiplier se usa para voting power, reward boost, o ambos — el impacto varía."
    - "Si hay un max multiplier cap (_maxGlobalMultiplier), el impacto puede ser limitado."
  solodit_ids:
    - "m-1-new-staking-positions-still-gets-the-full-reward-amount-as-with-old-stakings-diluting-rewards-for-old-stakers-sherlock-magicsea-the-native-dex-on-the-iotaevm-git"
    - "l-02-users-can-have-vote-weight-even-when-their-position-expired-shieldify-none-guanciale-stake-markdown"
  incidentes:
    - "MagicSea (Sherlock) — MlumStaking::addToPosition assigns multiplier based on initial lock duration instead of remaining: users game high multiplier near lock expiry (MEDIUM)."
    - "MagicSea (Sherlock) — User can manipulate position size and claim larger rewards: addToPosition near expiry with high amount captures outsized rewards (HIGH)."
    - "MagicSea (Sherlock) — withdrawFromPosition allows users to gain extra rewards: harvest before update of amountWithMultiplier (HIGH)."
  severidad: high
  confianza: alta
  verificado: true
  tags: [lock-multiplier, addToPosition, staking, lock-duration, amountWithMultiplier]
  relacionado_con: [staking-002, gauge-013]
```

---

## 20. Bribe Reward Token High Decimals DoS

```yaml
- id: gauge-020
  titulo: "Tokens con decimals altos causan DoS en BribeRewarder por overflow/gas"
  causa_raiz: |
    El BribeRewarder calcula rewardsPerPeriod dividiendo el total de rewards entre
    el número de periodos. Con tokens de 24+ decimals, los valores intermedios
    en el cálculo de reward-per-token pueden exceder uint256 o consumir gas
    excesivo en las multiplicaciones. Si alguien registra un bribe con un token
    de decimals altos, el rewarder puede quedar en DoS permanente.
  como_funciona: |
    1. Atacante (o usuario legítimo) registra bribe con token de 24 decimals.
    2. BribeRewarder calcula: rewardPerToken = totalReward * PRECISION / totalVotes.
    3. Con 24 decimals: totalReward = 1e24 * amount.
    4. totalReward * PRECISION (1e18) = 1e42 * amount → overflow en uint256 si
       amount es moderadamente grande.
    5. Alternativa sin overflow: la multiplicación consume gas excesivo en cada
       _modify / _claim call → transacciones reviertan por out-of-gas.
    6. Efecto: TODAS las bribes del periodo son irreclamables.
  invariante: |
    // Invariante: BribeRewarder debe funcionar con tokens de cualquier decimal
    // (o revertir en register, no en claim)
    // Test con token de 24 decimals
    MockERC20 highDecToken = new MockERC20(24);
    bribeRewarder.register(epoch, highDecToken, amount);
    // ... advance to epoch end ...
    bribeRewarder.claim(user); // NO debe revertir por overflow
  que_mirar:
    - "Los cálculos de reward usan SafeMath o unchecked?"
    - "Hay validación de decimals del token al registrar bribe?"
    - "PRECISION constant es compatible con tokens de 24+ decimals sin overflow?"
    - "Se usan mulDiv para evitar overflow en intermedios?"
    - "Hay whitelist de tokens aceptados para bribes?"
  como_se_arregla: |
    Whitelist de tokens para bribes (solo tokens aprobados).
    Usar mulDiv (OpenZeppelin) para cálculos intermedios.
    Validar decimals del token: revertir si > 18.
    Escalar tokens de alto decimal a 18 decimals antes de calcular.
  trampas:
    - "No todos los tokens de alto decimal causan overflow — depende de los montos y de PRECISION."
    - "El DoS solo afecta al periodo con el bribe problemático — periodos futuros sin ese token funcionan."
    - "Si hay whitelist de tokens, este vector está cerrado."
  solodit_ids:
    - "h-4-voters-will-lose-all-bribe-rewards-forever-if-they-do-not-claim-their-rewards-after-the-last-bribing-period-sherlock-magicsea-the-native-dex-on-the-iotaevm-git"
  incidentes:
    - "MagicSea (Sherlock) — Tokens with high decimals DoS the BribeRewarder contract: _modify reverts por overflow en cálculos intermedios (MEDIUM)."
  severidad: medium
  confianza: media
  verificado: true
  tags: [bribe, decimals, overflow, DoS, BribeRewarder, precision]
  relacionado_con: [gauge-007, gauge-008]
```
