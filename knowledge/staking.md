# Staking / Rewards — Combat Briefing

> Everything an auditor needs before reading a staking or reward distribution contract.
> Sources: invariant-registry/staking/reward_distribution.json (INV-STAKE-001..008), compositions/multi_actor.json, universal/exploit_derived.json.

---

## 1. Bugs Conocidos

### 1.1 Reward-Per-Share Rounding Exploitation

```yaml
- id: staking-001
  pattern: reward-per-share-rounding
  name: "Reward-per-share accumulator rounding exploitation"
  causa_raiz: >
    The rewardPerToken accumulator uses integer division:
    rewardPerToken += (reward * PRECISION) / totalStaked.
    When totalStaked is large relative to reward, the increment rounds
    to zero and rewards are silently lost. When totalStaked is tiny,
    the increment is enormous and a small staker captures outsized
    rewards. Repeated small operations can accumulate extractable
    rounding errors.
  como_funciona: |
    1. Attacker stakes a tiny amount when totalStaked is near zero
    2. Reward notification arrives, rewardPerToken jumps massively
    3. Attacker claims rewards, capturing nearly the full allocation
    4. OR: attacker repeatedly stakes/unstakes in small amounts,
       accumulating rounding in their favor each time
    5. Over many operations, extracted dust exceeds gas cost
  invariante: "rewardPerToken must monotonically increase (INV-STAKE-002). Total rewards distributed must never exceed total allocated (INV-STAKE-006)."
  que_mirar:
    - "What PRECISION constant is used? (1e18 is standard, lower is dangerous)"
    - "Is rewardPerToken calculated with mulDiv or raw division?"
    - "Does the accumulator round against the user (down for credits)?"
    - "Can totalStaked reach very small values (1 wei)?"
    - "Is there a minimum stake amount enforced?"
  como_se_arregla: "Use high precision constant (1e18 minimum). Round accumulator updates down. Enforce minimum stake amount. Track dust in a separate variable rather than losing it."
  trampas:
    - "1 wei rounding per operation is generally not exploitable unless repeatable cheaply"
    - "Penalty mechanisms may intentionally reduce effective rewards — not a rounding bug"
    - "Rebasing staking tokens naturally cause accumulator drift"
  incidentes:
    - "Redacted Cartel/PirexRewards — User with tiny pxGMX balance gets amount=0 from rounding, accrued rewards zeroed permanently (HIGH, C4)"
    - "Gamma Staking — cumulatedReward scaled by 1e36 overflows uint256 when multiplied by staker balance; griefable by staking 1 wei (MEDIUM, Sherlock)"
    - "Derby — rewardPerLockedToken rounds to zero when price() has 6 decimals (Idle USDC), silently losing all vault rewards (MEDIUM, Sherlock)"
    - "Union Finance — lockedCoinAge accumulator manipulable by not updating lastUpdated for maxed vouches, stealing all UNION rewards (HIGH, Sherlock)"
    - "Olympusdao — _claimInternalRewards accounting bug lets user drain entire reward balance (HIGH, Sherlock)"
    - "ZLRewardsController (Spearbit) — massUpdatePools sequential iteration reduces availableRewards after each pool, first pools steal from later pools (MEDIUM)"
    - "HYBUX — Incorrect reward calculation in NFT staking (CRITICAL)"
  severidad: high
  confianza: alta
  fuente: "INV-STAKE-002, INV-STAKE-006, INV-EXPLOIT-005"
  verificado: true
  tags: [rounding, precision, reward-per-token, accumulator, dust]
  relacionado_con: [staking-003, staking-004]
```

### 1.2 Stake Just Before Distribution (Timing Attack)

```yaml
- id: staking-002
  pattern: flash-stake-timing-attack
  name: "Stake just before reward distribution to capture disproportionate share"
  causa_raiz: >
    If there is no lock period or cooldown, an attacker can observe a
    pending notifyRewardAmount or reward transfer in the mempool,
    front-run it with a large stake, then immediately unstake and claim
    after the reward is distributed. Flash loans amplify this to
    infinite capital. The attacker dilutes all existing stakers' rewards
    in a single block.
  como_funciona: |
    1. Attacker monitors mempool for notifyRewardAmount() calls
    2. Attacker front-runs: flash loan -> stake large amount
    3. notifyRewardAmount() executes, distributing to all stakers
    4. Attacker claims rewards proportional to their massive stake
    5. Attacker unstakes, repays flash loan, keeps profit
    6. Existing stakers receive near-zero rewards for the period
  invariante: "A user who stakes must wait at least the minimum lock period before unstaking (INV-STAKE-005). Staking after reward period ends yields zero new rewards (INV-STAKE-007)."
  que_mirar:
    - "Is there a cooldown or minimum lock period?"
    - "Can stake + unstake happen in the same block/transaction?"
    - "Does updateReward() run before or after balance changes?"
    - "Is notifyRewardAmount access-controlled and called via timelock?"
    - "Are rewards distributed linearly over time or lump-sum?"
  como_se_arregla: "Enforce minimum lock period (block-based or time-based). Use warm-up period where new stakes earn 0 rewards for N blocks. Distribute rewards linearly over a duration rather than lump-sum."
  trampas:
    - "Contracts without lock periods are vulnerable by design — confirm this is unintentional"
    - "Linear distribution (Synthetix rewardsDuration) mitigates single-block extraction but not multi-block flash loans"
    - "Private mempool (Flashbots) reduces but does not eliminate risk"
  incidentes:
    - "Buffer Finance — LPs game option expiry by staking before OTM expiry and withdrawing after 10-min lock (HIGH, Sherlock)"
    - "Locke — User can stake before stream creator produces funding stream, capturing unearned rewards (MEDIUM)"
    - "Knox Finance — Users withdraw before epoch end to avoid performance fees, forcing other users to pay their share (MEDIUM)"
    - "Yieldy — Rebases can be frontrun even when warmUpPeriod > 0 by withdrawing during cool down (MEDIUM)"
    - "Mantle Network — Front-running unstakeRequestWithPermit invalidates user transaction (MEDIUM)"
    - "Onchainheroes — Uninitialized stakeDuration allows immediate unstake, bypassing fishing duration (MEDIUM, Shieldify)"
    - "Soulsclub Wheel — Stake manipulation during cooldown period allows probability gaming (HIGH)"
  severidad: high
  confianza: alta
  fuente: "INV-STAKE-005, COMP-MULTI-001 (sandwich pattern)"
  verificado: true
  tags: [flash-loan, timing, MEV, front-run, lock-period, cooldown]
  relacionado_con: [staking-001, staking-005, dex-014]
  nota_severidad: "critical solo si distribución es lump-sum sin rewardsDuration. Con distribución lineal (Synthetix), rebajado a HIGH porque el atacante solo puede capturar la porción proporcional del bloque — no extraer el total."
```

### 1.3 Reward Donation Inflation

```yaml
- id: staking-003
  pattern: reward-donation-inflation
  name: "Direct token donation inflates reward accumulator or share price"
  causa_raiz: >
    If the staking contract reads reward token balance via balanceOf()
    instead of internal accounting, an attacker can donate reward tokens
    directly to inflate the reward rate or exchange rate. This is the
    staking equivalent of the ERC-4626 donation attack. Combined with
    first-staker scenarios, the attacker controls the exchange rate.
  como_funciona: |
    1. Attacker is first staker with 1 wei
    2. Attacker donates large amount of reward token to the contract
    3. rewardPerToken or exchange rate inflates enormously
    4. Attacker claims inflated rewards or redeems at inflated rate
    5. OR: donation causes integer overflow in accumulator math
    6. Subsequent stakers receive diluted or zero rewards
  invariante: "Total rewards distributed never exceeds total allocated (INV-STAKE-006). Token balance vs internal accounting must not drift exploitably (INV-EXPLOIT-012)."
  que_mirar:
    - "Does the contract use balanceOf for reward calculations?"
    - "Is there a notifyRewardAmount() that explicitly tracks allocated rewards?"
    - "Can reward tokens be sent directly without calling a function?"
    - "Is there a sweep/skim for excess tokens?"
    - "Does the contract distinguish between staking token and reward token donations?"
  como_se_arregla: "Use internal accounting for reward tracking (notifyRewardAmount pattern). Never read balanceOf for reward calculations. Add sweep function for accidentally sent tokens."
  trampas:
    - "Protocols with same staking and reward token are more vulnerable"
    - "Some protocols intentionally accept donations as extra yield — verify design intent"
    - "Virtual shares offset mitigates share-price inflation but not reward accumulator inflation"
  incidentes:
    - "River Protocol — 1 wei force-sent via selfdestruct before first deposit makes sharesToMint=0 for all future depositors (HIGH, Spearbit)"
    - "Collateral.sol (C4) — First depositor mints 1 share then donates to strategy controller, all subsequent depositors get 0 shares (HIGH)"
    - "Thala LSD — Inflation attack on zero total stake: first depositor manipulates exchange rate via staking fee + donation (MEDIUM, OtterSec)"
    - "Stakehouse — Old stakers claim new stakers' ETH deposits as 'rewards' via accumulated rewards per LP inflation (HIGH, C4)"
  severidad: critical
  confianza: alta
  fuente: "INV-STAKE-006, INV-EXPLOIT-014, COMP-MULTI-002"
  verificado: true
  tags: [donation, inflation, balanceOf, internal-accounting, reward-token]
  relacionado_con: [staking-001, staking-004]
```

### 1.4 Double-Claim Prevention Failure

```yaml
- id: staking-004
  pattern: double-claim-rewards
  name: "User claims rewards multiple times for the same period"
  causa_raiz: >
    The reward checkpoint (userRewardPerTokenPaid) is not updated
    atomically with the claim, or the earned() function can be
    manipulated between checkpoint and transfer. Cross-function
    reentrancy during reward token transfer can re-enter claim().
    Epoch boundary transitions may fail to reset claim status.
  como_funciona: |
    1. User stakes and accumulates rewards over time
    2. User calls getReward() — callback during reward transfer
    3. During callback, re-enters getReward() or a function that
       recalculates earned() before userRewardPerTokenPaid is updated
    4. Second claim succeeds because checkpoint not yet written
    5. OR: user claims at epoch N boundary, then epoch N+1 starts,
       user's earned amount includes both epochs
  invariante: "User cannot claim more rewards than earned() at time of call (INV-STAKE-003). No double-counting across epoch boundaries (INV-STAKE-008)."
  que_mirar:
    - "Is userRewardPerTokenPaid updated BEFORE or AFTER reward transfer?"
    - "Is there a reentrancy guard on getReward()?"
    - "Does the reward token have callbacks (ERC-777, hooks)?"
    - "Is rewards[user] zeroed before transfer?"
    - "Are epoch transitions atomic with checkpoint updates?"
    - "Can getReward be called via multiple paths (exit, withdraw, claim)?"
  como_se_arregla: "Follow checks-effects-interactions: zero rewards[user] and update userRewardPerTokenPaid BEFORE transferring tokens. Apply ReentrancyGuard. Use pull pattern."
  trampas:
    - "Standard Synthetix pattern is safe IF modifiers are applied correctly"
    - "ERC-20 transfers (no hooks) do not enable reentrancy — only flag for ERC-777 or native ETH"
    - "Leftover rewards from previous epoch rolled into new epoch is expected in some designs"
  incidentes:
    - "AI Arena — Reentrancy on claimRewards() lets player mint extra fighter NFTs via smart contract callback (HIGH, C4)"
    - "Ajna — RewardsManager doesn't delete old bucket snapshot on unstaking, allowing stale state claims (HIGH, Sherlock)"
    - "Ajna — Claiming from future non-existent epoch prevents claiming for those epochs later (MEDIUM, Sherlock)"
    - "Aries Market — Missing timestamp update in add_reward/remove_reward causes same time_diff counted twice (MEDIUM, Otter Audits)"
    - "SuperDCAStaking — Bucket rewards wiped by stake/unstake before accrueRewards, zeroing delta (HIGH, Sherlock)"
    - "BribeRewarder (Sherlock) — Global _lastUpdateTimestamp makes unclaimed previous-period rewards unrecoverable (HIGH)"
    - "StakingKo (Cantina) — delegateStake updates lastPrintedAt without minting accumulated rewards, zeroing unclaimed yield (HIGH)"
    - "Golom — Repeated calls to multiStakerClaim in same block drains funds (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-STAKE-003, INV-STAKE-008, INV-EXPLOIT-011, INV-EXPLOIT-024"
  verificado: true
  tags: [double-claim, reentrancy, epoch-boundary, checkpoint, CEI]
  relacionado_con: [staking-002, staking-006]
```

### 1.5 Cooldown / Unstake Bypass

```yaml
- id: staking-005
  pattern: cooldown-unstake-bypass
  name: "Bypassing cooldown or lock period to unstake early"
  causa_raiz: >
    The cooldown mechanism tracks lastStakeTime per user but fails to
    account for transfers, delegations, or multiple stake positions.
    A user can transfer staked tokens (or shares) to another address
    that has no cooldown, then unstake from there. Or the cooldown
    resets on partial unstake but not on claim, creating a race.
  como_funciona: |
    1. User stakes and cooldown timer starts
    2. User transfers staking receipt tokens to address B
    3. Address B has no cooldown history -> unstakes immediately
    4. OR: user calls claim (no cooldown check), which triggers
       a code path that also releases principal
    5. OR: emergencyWithdraw() skips cooldown entirely
  invariante: "Unstaking reduces user balance by exact amount (INV-STAKE-004). Flash stake prevention via minimum lock period (INV-STAKE-005)."
  que_mirar:
    - "Are staking receipts transferable? If so, does cooldown transfer with them?"
    - "Does emergencyWithdraw bypass the cooldown?"
    - "Can partial unstake reset the cooldown for the remaining stake?"
    - "Does claiming rewards have a separate cooldown from unstaking?"
    - "Can a user unstake via exit() without the cooldown that withdraw() enforces?"
    - "Is cooldown per-address or per-position?"
  como_se_arregla: "Make staking receipts non-transferable (soulbound) OR transfer cooldown with the token via _beforeTokenTransfer hook. Apply cooldown to ALL withdrawal paths including emergencyWithdraw."
  trampas:
    - "Non-transferable tokens may break composability — check if protocol requires it"
    - "Protocols with no lock period have no bypass to find"
    - "Some protocols allow admin to skip cooldown by design (not a bug if documented)"
  incidentes:
    - "Telcoin — Withdraw delay bypassed by initiating withdrawal early (MEDIUM, Sherlock)"
    - "Onchainheroes — Uninitialized stakeDuration=0 lets user bypass fishing duration entirely (MEDIUM, Shieldify)"
    - "Kinetiq LST — Withdrawal delay bypassed when L1 operations processed more than once per 24 hours (MEDIUM)"
    - "Brix Money — User bypasses staking restrictions through composer to deposit on another chain (MEDIUM)"
    - "GoGoPool — Any duration passable by node operator, no enforcement (MEDIUM, C4)"
  severidad: high
  confianza: alta
  fuente: "INV-STAKE-004, INV-STAKE-005, INV-EXPLOIT-025"
  verificado: true
  tags: [cooldown, lock-period, transfer-bypass, emergency-withdraw, soulbound]
  relacionado_con: [staking-002, staking-006]
```

### 1.6 Reward Token Exhaustion / Insolvency

```yaml
- id: staking-006
  pattern: reward-token-exhaustion
  name: "Contract runs out of reward tokens before all claims are served"
  causa_raiz: >
    The rewardRate is set based on notifyRewardAmount but the contract
    does not verify that sufficient reward tokens are actually held.
    Rounding in per-second distribution accumulates: over thousands
    of operations, total distributed can exceed total allocated.
    Multiple notifyRewardAmount calls with leftover periods compound
    the error.
  como_funciona: |
    1. Admin calls notifyRewardAmount(1000e18) but only sends 999e18
    2. OR: rounding in rewardRate = amount / duration loses dust per period
    3. Over many epochs, the accumulated rounding shortfall grows
    4. Last claimers call getReward() but contract has insufficient balance
    5. Transaction reverts -> last users cannot claim
    6. OR: attacker front-runs to claim before others, leaving them insolvent
  invariante: "Total rewards distributed never exceeds total allocated (INV-STAKE-006). Contract reward token balance >= sum of all unclaimed rewards."
  que_mirar:
    - "Does notifyRewardAmount verify actual token balance received?"
    - "Is rewardRate = amount / duration losing dust? (amount % duration != 0)"
    - "Can notifyRewardAmount be called mid-period? How are leftovers handled?"
    - "Is there a recoverable dust mechanism?"
    - "Can admin recover reward tokens while users have unclaimed rewards?"
    - "What happens on the last claim if balance is 1 wei short?"
  como_se_arregla: "Verify reward token balance in notifyRewardAmount. Track cumulative distributions via ghost variable. Use pull pattern with min(earned, balance) to prevent reverts. Reserve dust for last claimer."
  trampas:
    - "Rounding of 1-2 wei per epoch is not exploitable — use tolerance"
    - "Protocols that allow admin to top up rewards mid-period may self-correct"
    - "Fee-on-transfer reward tokens cause natural balance deficit — protocol must account for this"
  incidentes:
    - "Olympusdao — Internal reward tokens accrue indefinitely with no end timestamp, over-committing and breaking all claims (MEDIUM, Sherlock)"
    - "Morpho — Setting new rewards manager breaks claiming old rewards (MEDIUM, Spearbit)"
    - "Hybra Finance — Rollover rewards permanently lost due to flawed rewardRate calculation (MEDIUM)"
    - "Covalent — unstake should update exchange rates first to prevent insolvency (HIGH)"
    - "Salty — Compounding pendingRewards reduction means higher upkeep frequency distributes fewer total rewards (MEDIUM, C4)"
    - "Concur Finance — Wrong reward token calculation in MasterChef, allocating incorrect amounts (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-STAKE-006, INV-STAKE-003, INV-EXPLOIT-012"
  verificado: true
  tags: [insolvency, reward-exhaustion, rounding, last-claimer, notifyRewardAmount]
  relacionado_con: [staking-001, staking-004]
```

---

### 1.9 ERC721 Position Staking (Gauge Style)

> Patrones específicos de contratos donde el token stakeado es un NFT ERC721 (posición Uniswap V3 / Aerodrome Slipstream).
> Código de referencia: `GaugeManager.sol` (revert-lend). Todos los patrones están basados en código concreto del contrato.

```yaml
- id: gauge-001
  pattern: onerc721received-from-validation-missing
  name: "onERC721Received sin validar `from` → staker hijacking en forks de gauge"
  causa_raiz: |
    Los contratos gauge que implementan onERC721Received deben validar que `from`
    sea una dirección autorizada (vault o gauge registrado). Sin esa validación,
    cualquier actor puede llamar npm.safeTransferFrom(victim, gauge, victimTokenId)
    si previamente se aprobó el gauge, y el gauge registraría al atacante como staker
    del NFT de la víctima. GaugeManager.sol tiene la protección correcta:
    `from != address(vault) && from != tokenIdToGauge[tokenId]`. Sin embargo,
    forks de Aerodrome/Velodrome que copian el patrón sin este check son vulnerables.
    El segundo check `from == tokenIdToGauge[tokenId]` es también relevante: garantiza
    que solo el gauge originalmente registrado puede devolver el NFT al GaugeManager
    durante el unstake — si un gauge malicioso se registrara, podría reutilizar este path.
  como_funciona: |
    1. Gauge fork implementa onERC721Received aceptando cualquier `from`
    2. Atacante llama npm.safeTransferFrom(atacante, gauge, tokenId_victima)
       (requiere que la víctima haya aprobado el gauge previamente, o que el atacante
       sea el owner del NFT y quiera registrarlo en nombre de otra cuenta de accounting)
    3. Gauge llama vault.ownerOf(tokenId) — si el vault ya trackea ese tokenId al atacante,
       el atacante acumula rewards de la posición de la víctima
    4. OU: gauge simplemente acepta el NFT sin validar nada y queda bloqueado
  invariante: "onERC721Received solo acepta NFTs desde vault (stake) o gauge registrado (unstake)"
  que_mirar:
    - "¿Valida onERC721Received que `from` sea vault o tokenIdToGauge[tokenId]?"
    - "¿Valida que msg.sender sea exactamente el NPM de Aerodrome/Uniswap V3?"
    - "¿El gauge fork usa una dirección de NPM diferente que podría no ser el token esperado?"
    - "¿Puede un atacante manipular tokenIdToGauge para añadir su dirección como 'from' válido?"
  como_se_arregla: "Validar en onERC721Received: (1) msg.sender == address(nonfungiblePositionManager) y (2) from == address(vault) || from == tokenIdToGauge[tokenId]. Rechazar todo lo demás con revert."
  trampas:
    - "GaugeManager.sol de revert-lend YA tiene ambas protecciones — no reportar aquí como bug"
    - "Aerodrome CLGauge oficial también protege el path — buscar en forks personalizados que copian la interfaz sin la validación"
    - "El check msg.sender == NPM es necesario pero no suficiente — hay que validar `from` también"
  severidad: high
  confianza: media
  fuente: "análisis GaugeManager.sol líneas 526-542 revert-lend 2026-03-20"
  verificado: false
  tags: [gauge, erc721, onERC721Received, staking, aerodrome, velodrome, from-validation]
  relacionado_con: [staking-005]

- id: gauge-002
  pattern: compound-zero-slippage-add-liquidity
  name: "increaseLiquidity con amount0Min=0/amount1Min=0 en compound automático"
  causa_raiz: |
    El flujo de compounding automático ejecuta: getReward() → swap AERO→token0/token1
    (validado con TWAP de 60s) → increaseLiquidity(..., 0, 0, deadline). El paso de
    increaseLiquidity usa amount0Min=0 y amount1Min=0 porque el contrato no puede
    conocer el slippage que el usuario aceptaría. Esto expone el addLiquidity a un
    sandwich: un atacante puede mover el precio del pool entre el swap y el addLiquidity,
    causando que el contrato añada liquidez en proporciones desfavorables. En liquidez
    concentrada este ataque es más severo que en AMMs clásicos porque toda la liquidez
    va a un rango estrecho — un movimiento de precio puede dejar la mitad de los tokens
    como "leftover" sin añadir.
  como_funciona: |
    1. Usuario llama compoundRewards(tokenId, ...) — observable en mempool
    2. Atacante front-runs: swap grande mueve sqrtPriceX96 del pool de la posición
    3. GaugeManager ejecuta _swapAeroForPosition: swap AERO→tokens con validación TWAP ✓
    4. GaugeManager llama _addLiquidity → increaseLiquidity(..., 0, 0, deadline)
    5. El precio del pool se movió: increaseLiquidity añade proporción incorrecta
       (mucho token0, poco token1 o viceversa), dejando el exceso como leftover
    6. Atacante back-runs: restaura el precio, captura el diferencial del desbalanceo
    7. Víctima recibe menos liquidez compuesta; protocolo cobra 2% sobre menos liquidity
  invariante: "amountAdded0/maxAddAmount0 >= MIN_EFFICIENCY (ej: 90%) — eficiencia baja indica precio movido"
  que_mirar:
    - "¿Los parámetros amount0Min y amount1Min en increaseLiquidity son 0? (línea 491 en GaugeManager.sol)"
    - "¿El TWAP del swap cubre también el paso de addLiquidity o solo el swap AERO→tokens?"
    - "¿Puede el usuario pasar minEfficiency como parámetro a compoundRewards?"
    - "¿La ventana entre _swapAeroForPosition y _addLiquidity es sandwichable?"
  como_se_arregla: "Derivar amount0Min/amount1Min desde el TWAP del pool antes del increaseLiquidity (mismo patrón que _validateSwap usa para los swaps). Llamar: (expected0, expected1) = LiquidityAmounts.getAmountsForLiquidity(twapSqrtPriceX96, ..., liquidity) y aplicar 1-2% de tolerancia."
  trampas:
    - "El swap AERO→tokens SÍ tiene validación TWAP via _validateSwap — el bug es SOLO en el paso de addLiquidity subsecuente"
    - "Para posiciones out-of-range, amount0Min o amount1Min siendo 0 para el token no-activo es CORRECTO — no es bug"
    - "El sandwich del addLiquidity requiere capital para mover el precio del pool de la posición, que puede ser más líquido que el pool de reward"
  severidad: medium
  confianza: alta
  fuente: "análisis GaugeManager.sol líneas 473-506 (especialmente 491) revert-lend 2026-03-20"
  verificado: true
  tags: [gauge, compound, slippage, increaseLiquidity, sandwich, concentrated-liquidity, aerodrome]
  relacionado_con: [staking-002, gauge-004]

- id: gauge-003
  pattern: npm-ownerof-diverges-after-stake
  name: "npm.ownerOf(tokenId) retorna el gauge tras stakear — contratos externos rompen"
  causa_raiz: |
    Cuando una posición se stakea via GaugeManager.stakePosition(), el NFT se transfiere:
    vault → GaugeManager → gauge. Tras el deposit al gauge, nonfungiblePositionManager.ownerOf(tokenId)
    devuelve la dirección del gauge (o GaugeManager), NO el propietario original.
    El vault trackea la propiedad lógica via su propio mapping interno (vault.ownerOf).
    Cualquier contrato externo que use npm.ownerOf() para verificar ownership, enviar
    fondos, o gate funcionalidad verá el gauge como owner — causando pérdida de rewards,
    acceso bloqueado o lógica de liquidación incorrecta.
  como_funciona: |
    1. Usuario stakea posición → npm.ownerOf(tokenId) = gauge (no vault, no usuario)
    2. Protocolo externo llama npm.collect(tokenId, recipient) → revert: not owner
    3. OU: protocolo de rewards externo usa npm.ownerOf como destinatario → envía al gauge
    4. Gauge no tiene función para reenviar esos tokens al owner real → fondos quemados
    5. OU: liquidador verifica custody via npm.ownerOf → ve gauge → asume posición no
       está en vault → saltea la liquidación → posición underwater sin liquidar
    6. OU: integración de terceros (farming agregator) falla al intentar npm.approve o
       npm.safeTransferFrom porque el owner actual es el gauge, no el usuario esperado
  invariante: "vault.ownerOf(tokenId) y npm.ownerOf(tokenId) deben ser consistentes cuando la posición NO está stakeada; documentar la divergencia cuando sí está stakeada"
  que_mirar:
    - "¿Usa el liquidador npm.ownerOf o vault.ownerOf para verificar custody?"
    - "¿Hay contratos de fees externos que envíen tokens a npm.ownerOf(tokenId)?"
    - "¿CLGauge.deposit() de Aerodrome llama npm.collect() durante el deposit? ¿A qué address?"
    - "¿Hay integraciones de terceros (aggregators, peripherals) que asuman npm.ownerOf == usuario?"
  como_se_arregla: "Usar siempre vault.ownerOf para determinar el propietario lógico en todos los contratos del protocolo. Exponer un helper isStaked(tokenId) para contratos externos. Documentar en NatSpec que npm.ownerOf diverge durante el staking period."
  trampas:
    - "npm.ownerOf devuelve el GAUGE (una dirección real), no address(0) — el error es de confusión de ownership, no de token inexistente"
    - "Aerodrome CLGauge.deposit() llama NPM.collect() a msg.sender (GaugeManager), y GaugeManager reenvía al owner vía _sendDepositDeltas — las fees pre-stake no se pierden en revert-lend"
    - "El vault de revert-lend ya maneja esta divergencia correctamente internamente — el riesgo es en integraciones externas"
  severidad: medium
  confianza: alta
  fuente: "análisis GaugeManager.sol stakePosition() flujo completo revert-lend 2026-03-20"
  verificado: true
  tags: [gauge, erc721, ownerOf, staking, aerodrome, custody, third-party-integration]
  relacionado_con: [gauge-001]

- id: gauge-004
  pattern: reward-swap-twap-60s-aerodrome
  name: "REWARD_TWAP_SECONDS=60 para validación de swap en compound — manipulable en Base"
  causa_raiz: |
    GaugeManager usa REWARD_TWAP_SECONDS=60 como ventana TWAP para validar el precio
    del swap AERO → token0/token1 durante el compounding (_validateSwap). En Base con
    bloques de 2 segundos, 60 segundos = 30 bloques. Un atacante puede distorsionar el
    TWAP del rewardBasePool (ej: AERO/USDC o AERO/WETH) durante 30 bloques consecutivos
    antes de que ocurra un compound, logrando que el contrato swap AERO a un precio
    desfavorable al validar contra un TWAP ya manipulado. El parámetro
    REWARD_MAX_TWAP_TICK_DIFFERENCE=200 (~2% de diferencia de precio) provee algo de
    protección pero no es suficiente si el TWAP de referencia ya está sesgado.
  como_funciona: |
    1. Atacante identifica pool con AERO como reward base (rewardBasePools[token] = pool)
    2. Atacante mantiene una posición grande en el pool durante 30+ bloques (≥60s en Base)
    3. TWAP del pool se desplaza hacia el precio manipulado
    4. Cualquier llamada a compoundRewards ejecuta _swapAeroToTarget
    5. _validateSwap compara contra el TWAP de 60s (ya manipulado) → acepta el precio
    6. El swap AERO → tokens se ejecuta a precio desfavorable para el position owner
    7. Atacante cierra su posición en el pool de reward, realizando el arbitraje
    NOTA: el atacante puede también ser quien llama compoundRewards si hay un incentivo
    económico (compoundRewards es callable por vault o owner — no completamente abierta)
  invariante: "TWAP window × pool_liquidity > max_extractable_reward_value — el costo de manipulación debe superar el reward compoundado"
  que_mirar:
    - "¿Cuánto es REWARD_TWAP_SECONDS? (60 en este contrato — línea 27)"
    - "¿Cuál es el TVL del pool configurado en rewardBasePools[token]?"
    - "¿REWARD_MAX_TWAP_TICK_DIFFERENCE=200 es suficiente dado el TVL del pool?"
    - "¿El pool de reward es el mismo que el pool de la posición (self-compounding)? Si es así, el costo de manipulación es mayor"
    - "¿Quién puede llamar compoundRewards? ¿Solo el owner o cualquier address?"
  como_se_arregla: "Aumentar REWARD_TWAP_SECONDS a 300-600 segundos. Verificar que el TVL del rewardBasePool supere un umbral mínimo antes de configurarlo. Considerar hacer REWARD_TWAP_SECONDS configurable por pool según su liquidez."
  trampas:
    - "REWARD_MAX_TWAP_TICK_DIFFERENCE=200 significa que el swap es rechazado si el precio spot diverge >2% del TWAP — pero el bug es que el propio TWAP ya está manipulado"
    - "En Base mainnet, Aerodrome AERO/USDC y AERO/WETH tienen alta liquidez — la manipulación de 30 bloques es costosa para rewards pequeños pero viable para posiciones grandes"
    - "compoundRewards solo puede ser llamado por vault o owner del tokenId — no es callable arbitrariamente por cualquier MEV bot"
  severidad: medium
  confianza: media
  fuente: "análisis GaugeManager.sol líneas 27-29 y _swapThroughPool() revert-lend 2026-03-20"
  verificado: true
  tags: [gauge, twap, aerodrome, slipstream, reward-compound, swap-manipulation, base-chain]
  relacionado_con: [gauge-002, staking-002]

- id: staking-009
  pattern: boost-multiplier-retroactive-application
  name: "Boost/multiplier applied retroactively to past unclaimed rewards"
  causa_raiz: >
    When a staking contract applies a boost multiplier (from locking, veToken weight,
    or time bonus) inside the earned() function without first checkpointing accrued
    rewards at the old multiplier, any change in multiplier retroactively inflates
    or deflates all unclaimed rewards. The pattern: earned = balance * boost *
    (rewardPerToken - userRewardPerTokenPaid). If boost changes without snapshotting
    rewards first, the new boost multiplies the entire delta.
  como_funciona: |
    1. User stakes tokens at day 0 with no lock (boost = 1x)
    2. Rewards accrue for 90 days at 1x multiplier
    3. User calls setLockStatus() or increases lock duration, boost becomes 2x
    4. earned() now returns balance * 2x * fullDelta — retroactively doubling 90 days of rewards
    5. User claims inflated rewards and optionally unlocks after minimum period
    6. OR: admin changes monsterMultiplier/baseVotes parameter, changing voting power mid-stake
       causing unstake to underflow (voting power at unstake > voting power at stake)
  invariante: |
    assert(rewardsClaimedByUser <= rewardsAccruedAtCurrentMultiplier + rewardsSnapshotAtOldMultiplier);
    // Before any multiplier change: rewards[user] must be checkpointed
  que_mirar:
    - "getBoost(_account) or multiplier used inside earned()"
    - "setLockStatus or extendLock without calling updateReward first"
    - "monsterMultiplier or baseVotes changed by admin without re-snapshotting"
    - "getTokenVotingPower used in both stake and unstake independently"
    - "Lock duration extension without reward checkpoint"
  como_se_arregla: "Always call updateReward(user) / checkpoint accrued rewards BEFORE changing any multiplier, boost, or voting power parameter. Snapshot voting power at stake time for unstake calculation."
  trampas:
    - "If boost only applies to future rewards (post-checkpoint), this is not vulnerable"
    - "Multiplier changes by admin that only affect new stakes are safe"
  incidentes:
    - "Meta — setLockStatus() retroactively applies boost to 90 days of unclaimed rewards (HIGH)"
    - "FrankenDAO — admin changing monsterMultiplier causes unstake underflow, locking NFTs (HIGH)"
    - "NeoTokyo — totalPoints changes from stake/unstake retroactively affect all existing positions (HIGH, C4)"
    - "BOB-Staking — Bonuses obtainable without proper locking due to flawed lock period (HIGH)"
    - "Nayms — Stake boost inflation via repeated stake/unstake inflates next interval boost (HIGH, Quantstamp)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [boost, multiplier, retroactive, lock, veToken, checkpoint, voting-power]

- id: staking-010
  pattern: reward-token-lifecycle-mismatch
  name: "Reward token add/remove/re-add breaks accounting permanently"
  causa_raiz: >
    When reward tokens are removed from a staking contract, the global accumulator
    (accumulatedRewardsPerShare in the struct) is deleted, but per-user tracking
    (userRewardDebts mapping by token address) persists. If the same token is
    re-added, the global tracker resets to zero while user trackers retain old values,
    causing underflow on claim. Separately, removing a reward token while users have
    unclaimed balances makes those rewards permanently unclaimable.
  como_funciona: |
    1. Reward token X is active, users accumulate rewards, accRewardsPerShare = 100
    2. User A has userRewardDebt[X] = 50, meaning 50 units already claimed
    3. Admin removes token X — struct deleted, accRewardsPerShare gone
    4. User A's userRewardDebt[X] = 50 persists in mapping
    5. Admin re-adds token X — accRewardsPerShare starts at 0
    6. User A tries to claim: 0 - 50 = underflow revert
    7. OR: users with unclaimed rewards when token removed lose them forever
  invariante: |
    // On reward token removal: all user debts for that token must be zero or claimable
    assert(userRewardDebt[user][removedToken] == 0 || claimOnlyModeEnabled);
  que_mirar:
    - "removeRewardToken or similar function that deletes from array"
    - "addRewardToken that doesn't check if token was previously removed"
    - "userRewardDebts stored in mapping(address => mapping(address => uint256))"
    - "Claim function iterating current rewardTokens array only"
    - "rewardsPerSecond with no end timestamp (infinite accrual)"
  como_se_arregla: "Never fully delete reward token state. Move removed tokens to 'claim-only' mode. On re-add, verify no stale user debts exist or reset them. Add endTimestamp to reward accrual."
  trampas:
    - "If protocol never re-adds removed tokens, underflow path is unreachable"
    - "Infinite reward accrual is only a problem if contract balance is insufficient"
  incidentes:
    - "Olympusdao — Removed reward tokens permanently lose unclaimed balances (MEDIUM, Sherlock)"
    - "Olympusdao — Re-added reward tokens cause underflow on claim (MEDIUM, Sherlock)"
    - "Olympusdao — Internal reward tokens accrue indefinitely, over-commit and break all claims (MEDIUM, Sherlock)"
    - "Olympusdao — Cached rewards underflow freezes user rewards temporarily (MEDIUM, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [reward-token, add-remove, lifecycle, underflow, accounting, mapping-persistence]

- id: staking-011
  pattern: withdrawal-without-reward-settlement
  name: "Withdraw/unstake path skips reward settlement, losing unclaimed rewards"
  causa_raiz: >
    Multiple withdrawal paths exist (withdraw, withdrawETH, exit, emergencyWithdraw,
    redeem) but not all of them call the reward settlement function before reducing
    the user's balance. When balance drops to zero, all future reward calculations
    return zero and unclaimed rewards are orphaned in the contract. The withdrawal
    update logic may also reset claimed[] to max or zero rewards[] without transferring.
  como_funciona: |
    1. User has staked balance and accrued unclaimed rewards
    2. User calls withdrawETH() or alternative withdrawal path
    3. This path burns LP tokens / reduces balance but does NOT call _distributeRewards()
    4. User's balance is now 0, earned() returns 0
    5. Unclaimed rewards are permanently orphaned in the contract
    6. OR: on new deposit, _setClaimedToMax() overwrites unclaimed rewards
  invariante: |
    // Before any balance reduction: pending rewards must be settled
    assert(pendingRewards(user) == 0 || rewardsTransferred);
    // After withdrawal: user.rewards >= rewardsBeforeWithdrawal
  que_mirar:
    - "withdrawETH or exit functions that don't call updateReward"
    - "_setClaimedToMax called on deposit without first distributing"
    - "_withdrawUpdateRewardState resetting userRewardDebts BEFORE computing difference"
    - "Multiple withdrawal paths — check EACH one settles rewards"
    - "balance burned before reward calculation"
  como_se_arregla: "Call updateReward(user) or distribute pending rewards in EVERY withdrawal/deposit path. Never zero claimed/debt state before computing outstanding rewards."
  trampas:
    - "If rewards are auto-compounded into stake, withdrawal implicitly includes them"
    - "emergencyWithdraw intentionally forfeits rewards in some designs"
  incidentes:
    - "Stakehouse — withdrawETH() burns LP without distributing rewards, orphaning them (HIGH, C4)"
    - "Stakehouse — _onDepositETH sets claimed to max, erasing unclaimed rewards (HIGH, C4)"
    - "Olympusdao — _withdrawUpdateRewardState resets claimed before computing diff, inflating cache (HIGH, Sherlock)"
    - "Blueberry — Re-depositing to Ichi farm sends ICHI rewards to spell contract, not user (HIGH, Sherlock)"
    - "SynthVault (Spartan) — withdraw forfeits all accumulated rewards (HIGH)"
    - "Hybra Finance — Users emergency withdrawing lose all past accrued rewards (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [withdrawal, reward-settlement, orphaned-rewards, balance-zero, multiple-paths]

- id: staking-012
  pattern: staking-exchange-rate-manipulation
  name: "Asymmetric exchange rate between stake and unstake enables drain"
  causa_raiz: >
    Staking mints receipt tokens at a fixed 1:1 ratio but burning/unstaking uses
    the current exchange rate (which includes accumulated rewards), or vice versa.
    This asymmetry allows attackers to loop stake->unstake to extract rewards
    without genuine time commitment. Also applies when exchange rate is updated
    manually (not atomically), enabling front-running.
  como_funciona: |
    1. Protocol mints stToken at 1:1 with baseToken on stake
    2. Rewards accumulate, exchange rate of stToken/baseToken increases above 1:1
    3. Attacker stakes X baseToken, receives X stToken (1:1 mint)
    4. Attacker unstakes X stToken, receives X * exchangeRate baseToken (>X)
    5. Profit = X * (exchangeRate - 1), repeat until rewards drained
    6. OR: manual updateExchangeRate() call allows front-running with wrap/unwrap
  invariante: |
    // Mint and burn must use the SAME exchange rate
    assert(stTokenMinted == baseTokenDeposited * stTokenSupply / totalBaseControlled);
    assert(baseTokenReturned == stTokenBurned * totalBaseControlled / stTokenSupply);
  que_mirar:
    - "stake() minting at 1:1 while unstake() uses exchangeRate"
    - "mint(msg.sender, amount) without dividing by exchange rate"
    - "updateExchangeRate() as separate public/manual function"
    - "wrap/unwrap with different rate calculations"
    - "burnTicket or similar intermediate step between stake and unstake"
  como_se_arregla: "Always use current exchange rate for BOTH minting and burning. Make exchange rate updates atomic with state changes. Never allow 1:1 mint when exchange rate > 1."
  trampas:
    - "If exchange rate is always 1:1 (no reward accumulation in rate), this doesn't apply"
    - "Cooldown periods between stake and unstake mitigate the loop"
  incidentes:
    - "Aria/RWIPStaking — stRWIP minted 1:1 but burned at exchange rate, attacker drains all rewards (HIGH, Cantina)"
    - "wstTAO — Manual updateExchangeRate() enables front-running wrap at favorable rate (HIGH, Quantstamp)"
    - "Thala LSD — Inflation attack on zero total stake via exchange rate manipulation (MEDIUM, OtterSec)"
    - "Mantle Network — Fixed exchange rate at unstaking fails to socialize slashing (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [exchange-rate, mint-burn-asymmetry, drain, front-running, wrap-unwrap]

- id: staking-013
  pattern: reward-distribution-when-zero-supply
  name: "Rewards distributed when totalSupply is zero are permanently lost"
  causa_raiz: >
    When notifyRewardAmount() or reward distribution occurs while totalStaked == 0,
    the rewardPerToken accumulator cannot increase (division by zero is skipped or
    returns stored value). Rewards allocated during this period are never assigned
    to anyone and become locked in the contract. Similarly, division by zero in
    gauge weight distribution causes permanent DoS.
  como_funciona: |
    1. All stakers withdraw, totalSupply drops to 0
    2. Reward distribution triggers (notifyRewardAmount or epoch transition)
    3. rewardPerToken() returns rewardPerTokenStored unchanged (totalSupply == 0 branch)
    4. Rewards for this period are allocated but rewardPerToken doesn't increase
    5. When new staker deposits, rewardPerToken starts fresh — gap period rewards are lost
    6. OR: totalWeightLocked == 0 causes division by zero, blocking all state transitions
  invariante: |
    // If totalSupply == 0 during reward period, those rewards must be recoverable
    assert(rewardsDistributed + recoverableRewards == totalAllocated);
    // Division by totalWeight must handle zero case
    assert(totalWeight > 0 || distributionSkipped);
  que_mirar:
    - "rewardPerToken() with if (totalSupply == 0) return rewardPerTokenStored"
    - "notifyRewardAmount callable when totalStaked == 0"
    - "Division by totalWeight or totalPoints without zero check"
    - "epoch or cycle advancement blocked by zero denominator"
    - "Rewards sent to contract before any staker exists"
  como_se_arregla: "Queue rewards when totalSupply == 0 and distribute when first staker arrives. Add zero-check before division in distribution. Allow admin to recover rewards from zero-supply periods."
  trampas:
    - "Some protocols intentionally allow rewards to accumulate for first staker"
    - "Dust amounts of totalSupply (1 wei) avoid the zero case but create rounding issues"
  incidentes:
    - "Wenwin — Rewards sent to staking contract with zero stakers are locked forever (MEDIUM, C4)"
    - "Convergence — totalWeightLocked==0 causes division by zero, locking all CVG permanently (MEDIUM, Sherlock)"
    - "Tigris Trade — distribute() skips epoch update when totalShares==0, breaking later bonds (MEDIUM, C4)"
    - "Locke — UnaccruedSeconds don't increase when nobody staking, rewards lost (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [zero-supply, lost-rewards, division-by-zero, DoS, epoch-lock]

- id: staking-014
  pattern: slashing-bypass-via-frontrun
  name: "Slashing mechanism bypassed via frontrunning or withdrawal timing"
  causa_raiz: >
    Slashing functions can be blocked or circumvented because: (1) staking in the
    same block triggers checkpoint protection that also blocks slash, (2) withdrawal
    delay can be initiated before slash is processed, (3) node operators can avoid
    slash by manipulating minipool timing or error states. The slashing amount may
    also be miscalculated due to stale reward estimates.
  como_funciona: |
    1. Slasher submits slash(user) transaction to mempool
    2. User sees pending slash, front-runs with stake(1 wei) in same block
    3. checkpointProtection modifier reverts slash because stake modified in same block
    4. User repeats indefinitely while withdrawal delay counts down
    5. Once delay expires, user withdraws all funds — slash never executed
    6. OR: node operator triggers recordStakingError() to avoid slash while keeping rewards
  invariante: |
    // Slash must not be blockable by the slashee's own actions
    assert(slashExecutable || slasheeCannotInterfere);
    // Slashed amount must reflect actual expected rewards
    assert(slashedAmount <= expectedRewards(duration, amount));
  que_mirar:
    - "checkpointProtection modifier applied to both slash and stake"
    - "Same-block restriction that can be triggered by slashee"
    - "withdrawDelay countdown concurrent with slash window"
    - "recordStakingError not resetting reward eligibility"
    - "getExpectedAVAXRewardsAmt using inaccurate rate calculations"
  como_se_arregla: "Exempt slash() from checkpoint protection. Use Flashbots or private mempool for slash. Freeze withdrawals when slash is pending. Reset reward eligibility on staking errors."
  trampas:
    - "If slashing is admin-only via timelock, frontrunning is less practical"
    - "Protocols without slashing mechanism are not affected"
  incidentes:
    - "Telcoin — stake(1) frontrun blocks slash via checkpointProtection, bypass slashing while withdrawal delay runs (MEDIUM, Sherlock)"
    - "GoGoPool — Node operator avoids slash via recordStakingError while keeping reward eligibility (MEDIUM, C4)"
    - "GoGoPool — Node operator slashed for full duration despite 14-day reward cycle (HIGH, C4)"
    - "GoGoPool — MinipoolManager slash amount wrong due to inaccurate reward estimation (MEDIUM, C4)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [slashing, frontrun, checkpoint, bypass, withdrawal-delay, node-operator]

- id: staking-015
  pattern: claimed-tracking-on-transfer
  name: "Token transfer breaks per-user reward tracking (claimed/debt not adjusted)"
  causa_raiz: >
    When staking receipt tokens or LP tokens are transferred between users, the
    claimed[] or rewardDebt mapping for the sender is not adjusted downward. The
    sender retains a claimed[] value computed for their old (higher) balance. This
    can cause: (1) underflow when computing sender's future rewards, (2) DoS on
    sender's subsequent operations, (3) orphaned rewards that nobody can claim.
    The receiver gets tokens without corresponding debt, potentially over-claiming.
  como_funciona: |
    1. User A has 100 LP tokens, claimed[A] = 80 (based on 100 tokens worth of rewards)
    2. User A transfers 50 LP tokens to User B
    3. claimed[A] remains 80, but A now only has 50 tokens
    4. Max claimable for 50 tokens might be 60 — but claimed[A] = 80 > 60
    5. A's claim underflows: 60 - 80 = revert
    6. B has 50 tokens with claimed[B] = 0, can claim rewards they didn't earn
    7. A cannot transfer, claim, or interact — permanently DoS'd
  invariante: |
    // claimed[user] must never exceed maxClaimable for user's current balance
    assert(claimed[user] <= accumulatedPerToken * balanceOf(user));
    // On transfer: adjust both sender and receiver claimed proportionally
  que_mirar:
    - "Transfer of staking/LP tokens without adjusting claimed[] or rewardDebt"
    - "_beforeTokenTransfer or _afterTokenTransfer hooks missing reward adjustment"
    - "claimed[user][token] as absolute value vs proportional to balance"
    - "Underflow in accumulatedPerToken * balance - claimed"
    - "beforeTokenTransfer calling _distributeRewards but not adjusting claimed"
  como_se_arregla: "In _beforeTokenTransfer: settle pending rewards for both sender and receiver, then adjust claimed[]/rewardDebt proportionally. Or make receipt tokens non-transferable."
  trampas:
    - "If receipt tokens are non-transferable (soulbound), this doesn't apply"
    - "If transfer hook settles AND adjusts claimed, it's safe"
  incidentes:
    - "Stakehouse — Transfer of GiantMevAndFeesPool tokens leaves claimed[] too high, causing DoS and orphaned rewards (HIGH, C4)"
    - "Stakehouse — When users transfer GiantLP, some rewards lost (MEDIUM, C4)"
    - "Yield — Transferring wCVX to another account duplicates protocol earned yield (HIGH)"
    - "RabbitHole — NFT transfer after claim lets seller front-run buyer, buyer gets worthless claimed NFT (MEDIUM, C4)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [transfer, claimed-tracking, rewardDebt, underflow, DoS, LP-token]

- id: staking-016
  pattern: interest-accrual-desync-in-rewards
  name: "Reward denominator includes accrued interest but user numerator does not"
  causa_raiz: >
    In lending/staking hybrids where debt accrues interest, the global reward
    accumulator uses totalDebt (with interest applied) as denominator, but individual
    user debt may not have interest applied at the same time. When another user's
    action triggers global interest accrual but not the claiming user's, the
    claimant's share is computed with stale (smaller) numerator against inflated
    denominator, losing rewards.
  como_funciona: |
    1. Global debt = 100, User debt = 50, rewardIntegral = 0
    2. Time passes, 10% interest accrues
    3. Another user triggers action that updates totalDebt to 110 (interest applied globally)
    4. 100 reward tokens arrive, rewardIntegral = 100/110 = 0.909
    5. Original user claims: 50 * 0.909 = 45.45 (should be 50)
    6. Loss because user's debt wasn't updated to 55 before reward calculation
  invariante: |
    assert(userDebtWithInterest / totalDebtWithInterest == userFairShare);
    // Interest must be accrued for user BEFORE computing their reward share
  que_mirar:
    - "rewardIntegral using totalActiveDebt or totalBorrows as denominator"
    - "_applyPendingRewards or accrueInterest called globally but not per-user"
    - "updateIntegrals using stale user balance"
    - "Reward per debt token with interest accrual"
    - "MasterChef-style rewards on debt positions"
  como_se_arregla: "Always accrue interest for the specific user before computing their reward share. Or use a time-weighted approach that accounts for interest growth."
  trampas:
    - "If interest accrual is atomic for all users, desync doesn't occur"
    - "Small interest rates over short periods may produce negligible drift"
  incidentes:
    - "Bima — TroveManager rewardIntegral uses interest-inflated totalDebt but user debt is stale, losing ~10% of rewards (HIGH, Cantina)"
    - "Sway — Imprecise reward distribution using total_stakes without accounting for pending unapplied rewards (MEDIUM, Otter Audits)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [interest, debt, desync, reward-integral, lending, trove]

- id: staking-017
  pattern: unstake-accounting-total-vs-user
  name: "Unstake reduces total shares instead of user shares, zeroing all rewards"
  causa_raiz: >
    The unstake function reads the total shares for the current cycle/pool and
    subtracts the total from itself (shares -= shares, effectively zeroing it)
    instead of subtracting only the user's portion. This destroys the denominator
    for all reward calculations, causing all users to lose rewards. Related: unstake
    not deducting from user's StakingInfo allows repeated unstake to drain contract.
  como_funciona: |
    1. Multiple users have staked, totalShares = 1000
    2. User A (100 shares) calls unstake()
    3. Bug: shares = _rewardPoolShares[poolId][cycleId] (= 1000)
    4. _rewardPoolShares[poolId][cycleId] -= shares (1000 - 1000 = 0)
    5. All users' reward calculations now divide by 0 or return 0
    6. OR: unstake doesn't deduct from user.stakedAmount, allowing repeated calls
  invariante: |
    // Unstake must only reduce user's share, not total
    assert(_rewardPoolShares[poolId][cycleId] >= userShares);
    assert(postUnstakeTotalShares == preUnstakeTotalShares - userShares);
    // User balance must decrease on unstake
    assert(stakingInfo[user].amount == preAmount - unstakeAmount);
  que_mirar:
    - "shares = totalShares[poolId] followed by totalShares[poolId] -= shares"
    - "Unstake reading total instead of user-specific balance"
    - "Missing balance deduction in initiateUnstake or unstake"
    - "Same orderId reusable across multiple unstake calls"
  como_se_arregla: "Read user's share amount specifically. Deduct user shares from total. Mark orderId as consumed after unstake. Add invariant test: totalShares == sum(userShares)."
  trampas:
    - "If only one user exists, totalShares == userShares and bug is invisible"
  incidentes:
    - "Surge — Unstake zeroes ALL pool shares instead of user's shares, destroying rewards for everyone (HIGH, Shieldify)"
    - "Sapien — initiateUnstake/unstake never deduct from StakingInfo, allowing repeated drain (HIGH, Quantstamp)"
    - "Stakehouse — Unstaking doesn't update sETHUserClaimForKnot mapping (HIGH, C4)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [unstake, total-shares, accounting, drain, zeroing]

- id: staking-018
  pattern: reward-rate-change-retroactive
  name: "Reward rate changes applied retroactively to past periods"
  causa_raiz: >
    When rewardRate or rewardRatePerDay changes (via admin action or epoch
    transition), the new rate is applied to calculate rewards for the entire
    staking duration rather than only from the change point forward. Users
    who unstake after a rate increase receive inflated rewards; after a decrease,
    they receive less than earned. Unprotected changeRewardSpeed allows
    unauthorized rate manipulation to drain contracts.
  como_funciona: |
    1. User stakes at time T0 with rewardRate = R1
    2. At time T1, admin changes rewardRate to R2
    3. User unstakes at T2, rewards calculated as: amount * R2 * (T2 - T0)
    4. Should be: amount * R1 * (T1 - T0) + amount * R2 * (T2 - T1)
    5. If R2 > R1, user gets excess rewards; if R2 < R1, user loses rewards
    6. OR: attacker deploys vault using target staking contract, calls changeRewardSpeed
       to set absurdly high rate, drains 99% of reward balance
  invariante: |
    // Rewards must be checkpointed before rate change
    assert(rewardsAccrued == sum(rate_i * duration_i) for each rate period i);
    // changeRewardSpeed must be access-controlled to the staking contract's admin
  que_mirar:
    - "rewardRatePerDay or rewardRate used with full (unstakeTime - stakeTime) duration"
    - "changeRewardSpeed or setRewardRate without updateReward checkpoint"
    - "Permissionless changeRewardSpeed via vault deployment"
    - "Reward calculation: amount * currentRate * totalDuration (no segmentation)"
    - "Missing access control on reward rate modification"
  como_se_arregla: "Checkpoint all user rewards before any rate change. Calculate rewards per-period with the rate active during that period. Restrict reward rate changes to authorized callers only with rate caps."
  trampas:
    - "If rate only changes once (at deployment), no retroactive issue"
    - "Linear distribution (Synthetix rewardRate = amount / duration) handles this via lastTimeRewardApplicable"
  incidentes:
    - "DIAWhitelistedStaking — Rewards use current rewardRatePerDay for entire duration, ignoring historical changes (HIGH, Hacken)"
    - "Popcorn — Anyone deploys vault to call changeRewardSpeed, drains 99% of reward tokens in 12 seconds (HIGH, C4)"
    - "Aries Market — add_reward/remove_reward don't update farm.timestamp, double-counting same time_diff (MEDIUM, Otter Audits)"
    - "Salty — Compounding reduction of pendingRewards means higher call frequency distributes fewer total rewards (MEDIUM, C4)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [reward-rate, retroactive, rate-change, access-control, drain]

- id: staking-019
  pattern: validator-selection-dos
  name: "Validator selection logic DoS from stopped/exited validators or duplicates"
  causa_raiz: >
    In liquid staking protocols, the validator selection algorithm incorrectly
    handles exited/stopped validators. Using (funded - stopped) as the selection
    metric picks exhausted operators over available ones. When stopped == funded
    and no keys remain, the function returns empty results, permanently blocking
    new deposits from being staked. Duplicate validator addition wastes depositor
    funds by sending >32 ETH to one validator.
  como_funciona: |
    1. Operator A has funded=10, stopped=10, keys=10 (fully exhausted)
    2. Operator B has funded=0, stopped=0, keys=10 (fully available)
    3. Selection loop picks minimum (funded - stopped): A has 0, B has 0
    4. A is selected first (lower index), but has 0 available keys
    5. Function returns empty array — no validators can be selected
    6. All new ETH deposits cannot be staked, accumulating idle in contract
    7. OR: duplicate validator keys receive >32 ETH, wasting capital
  invariante: |
    // Selection must pick operators with available (unfunded) keys
    assert(selectedOperator.keys - selectedOperator.funded > 0);
    // No duplicate validator keys
    assert(unique(validatorKeys));
  que_mirar:
    - "_hasFundableKeys using stopped in calculation"
    - "pickNextValidators returning empty when available operators exist"
    - "funded - stopped as selection metric"
    - "addValidators without deduplication check"
    - "_getNextValidatorsFromActiveOperators loop logic"
  como_se_arregla: "Do not use stopped in fundable key calculation. Available keys = min(keys, limit) - funded. Add deduplication on validator key addition. Skip exhausted operators in selection loop."
  trampas:
    - "If protocol has no validator exit mechanism, stopped is always 0"
    - "Single-operator protocols don't have selection issues"
  incidentes:
    - "Liquid Collective — _hasFundableKeys returns true for exhausted operators, DoS staking (CRITICAL, Spearbit)"
    - "Liquid Collective — Selection picks operator with funded==stopped, returns empty, blocking all staking (CRITICAL, Spearbit)"
    - "Liquid Collective — Wrong index for stopped validator count in exit selection (HIGH, Spearbit)"
    - "Liquid Collective — Duplicate validators waste depositor capital (MEDIUM, Spearbit)"
    - "Liquid Collective — removeValidators frontrun changes key set unexpectedly (HIGH, Spearbit)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [validator, selection, DoS, liquid-staking, stopped, funded, exhausted]

- id: staking-020
  pattern: voting-with-expired-lock
  name: "Voting power retained after lock expiry or used across delegation boundaries"
  causa_raiz: >
    veToken or staking-based governance allows voting with positions whose lock
    has expired but hasn't been withdrawn. The contract checks lock existence but
    not remaining lock duration relative to epoch length. Users can vote, withdraw,
    re-stake, and vote again in the same epoch. Separately, delegation mechanics
    can trap delegatees or remove votes from wrong address on unstake.
  como_funciona: |
    1. User locks tokens for 2 years, receives veToken voting power
    2. Lock expires, user doesn't withdraw
    3. Voting function checks lock.amount > 0 but not lock.end > block.timestamp + epochDuration
    4. User votes in current epoch with expired lock
    5. User withdraws locked tokens (lock.amount = 0)
    6. User re-stakes minimal amount, votes again in same epoch
    7. OR: malicious delegate creates proposals continuously, trapping delegatees
    8. OR: unstake by approved operator removes votes from msg.sender instead of owner
  invariante: |
    // Voting requires lock.end > currentEpoch.end
    assert(lock.end > block.timestamp + epochDuration);
    // Each user can only vote once per epoch per token
    assert(votesUsed[epoch][tokenId] <= 1);
    // Unstake removes votes from token owner, not caller
  que_mirar:
    - "Vote function checking lock.amount but not lock.end"
    - "Remaining lock period vs epoch duration validation"
    - "withdraw + restake + vote in same epoch"
    - "lockedWhileVotesCast modifier applied to unstake/delegate"
    - "Delegate creating proposals to prevent delegatee unstaking"
    - "votingPower subtracted from msg.sender vs ownerOf(tokenId)"
  como_se_arregla: "Require remainingLockTime > epochDuration for voting. Track votes per epoch per tokenId. Allow emergency unstake regardless of delegate's proposal status. Subtract voting power from owner, not msg.sender."
  trampas:
    - "Expired locks with zero power naturally can't vote in some implementations"
    - "If delegation is disabled, trap scenario doesn't apply"
  incidentes:
    - "MagicSea/MlumStaking — Vote with expired lock, withdraw, restake, vote again in same epoch (HIGH, Sherlock)"
    - "FrankenDAO — Delegate traps delegatees indefinitely via continuous proposals (MEDIUM, Sherlock)"
    - "FrankenDAO — Unstake removes votes from msg.sender not owner (HIGH, Sherlock)"
    - "KittenSwap — Weight loss from invalid pool votes diluting valid gauge allocation (MEDIUM, Pashov)"
    - "Hybra Finance — Dust vote on one pool prevents poke() (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [voting, expired-lock, veToken, delegation, epoch, governance]

- id: staking-021
  pattern: cross-contract-reward-interface-mismatch
  name: "External reward claiming fails due to incorrect interface or reentrancy lock conflict"
  causa_raiz: >
    When a staking protocol integrates with external reward sources (Curve gauges,
    Berachain RewardVaults, Compound COMP, Aura/Convex), the interface used to
    claim rewards may have wrong function signatures, or the claim flow creates
    reentrancy lock conflicts (nonReentrant on getReward calls notifyRewardAmount
    which is also nonReentrant). Separately, claimToTreasury may sweep reward
    tokens along with reserves when the reward token is also a market token.
  como_funciona: |
    1. Protocol integrates external reward vault with getReward(address)
    2. External vault's actual signature is getReward(address, address)
    3. All calls to claim rewards revert — rewards permanently locked
    4. OR: getReward() acquires nonReentrant lock, calls voter.distribute()
    5. distribute() calls back notifyRewardAmount() which also requires nonReentrant
    6. Second lock acquisition reverts — reward distribution permanently broken
    7. OR: claimToTreasury(cCOMP) sweeps both reserves AND user reward COMP
  invariante: |
    // External interface must match actual function signature
    assert(IVault(vault).getReward.selector == externalVault.getReward.selector);
    // Cross-contract calls must not create reentrancy lock deadlock
    assert(noDeadlockInCallChain(getReward -> distribute -> notifyRewardAmount));
  que_mirar:
    - "Interface definitions for external reward vaults (getReward parameters)"
    - "nonReentrant on both getReward and notifyRewardAmount in call chain"
    - "claimToTreasury with token that is also a reward token"
    - "External gauge claim functions with different signatures across versions"
    - "Reentrancy guard: global vs per-function in cross-contract calls"
  como_se_arregla: "Verify external interfaces against deployed contracts. Temporarily release reentrancy lock before cross-contract reward distribution calls. Separate reserve sweeping from reward token accounting."
  trampas:
    - "If protocol uses same codebase as external reward source, interface matches"
    - "Single-contract systems don't have cross-contract lock issues"
  incidentes:
    - "D2 — Wrong getReward interface for Berachain RewardVaults, all BGT rewards locked (HIGH, Cyfrin)"
    - "Hyperstable — nonReentrant on getReward conflicts with notifyRewardAmount callback, breaking distribution (MEDIUM, Pashov)"
    - "Morpho — claimToTreasury(COMP) sweeps user COMP rewards along with reserves (MEDIUM, Spearbit)"
    - "Notional Finance — Inability to claim rewards from Curve gauge (HIGH)"
    - "Sentiment — CurveLPStaking gauge rewards cannot be claimed (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [interface, external-rewards, reentrancy-lock, curve, berachain, COMP]

- id: staking-022
  pattern: griefing-via-zero-amount-or-spam
  name: "Zero-amount operations or spam transactions grief staking state"
  causa_raiz: >
    Functions that accept arbitrary amounts (including 0) or can be called by
    anyone on behalf of others can be used to grief: (1) transferring 0 tokens
    resets reward multipliers, (2) staking 1 wei for a victim during warmup
    creates a DoS, (3) permissionless getReward(user) claims at unfavorable
    time, (4) flooding stake/unstake requests bloats state or delays confirmations.
  como_funciona: |
    1. Attacker transfers 0 reward tokens to victim
    2. Transfer hook triggers: newPosition == prevPosition condition met
    3. Victim's reward multiplier reset to 1x (from higher earned multiplier)
    4. Zero cost to attacker, permanent damage to victim's rewards
    5. OR: attacker calls stake(1 wei, victim) during warmup period
    6. Victim's warmup resets, cannot claim until new warmup expires
    7. Attacker repeats to permanently DoS victim's claiming
  invariante: |
    // Zero-amount transfers must not modify reward state
    assert(multiplier_after_zero_transfer == multiplier_before);
    // Staking on behalf of others must not reset their state
    assert(warmupExpiry_after_thirdPartyStake == warmupExpiry_before);
    // getReward must not be callable at arbitrary times by third parties
  que_mirar:
    - "Transfer of 0 amount triggering state changes"
    - "stake(amount, recipient) callable by anyone"
    - "getReward(user) permissionless — can force claim at bad time"
    - "stake/unstake with tiny amounts flooding confirmation queue"
    - "DoS via warmup period reset on any stake event"
  como_se_arregla: "Require amount > 0 for all state-changing operations. Make third-party staking opt-in. Restrict getReward to msg.sender or approved callers. Rate-limit stake/unstake requests."
  trampas:
    - "If zero-amount transfers are properly no-ops (early return), safe"
    - "If warmup doesn't reset on additional stakes, DoS path is blocked"
  incidentes:
    - "SMRewardDistributor — 0-token transfer resets victim's reward multiplier to 1 permanently (HIGH, Cantina)"
    - "Yieldy — stake(1 wei, victim) resets warmup period, permanent DoS on claiming (HIGH)"
    - "NeoTokyo — permissionless getReward(user) forces claim when totalPoints is high, reducing rewards (HIGH, C4)"
    - "Recall — Flooding stake/unstake requests DoS confirmChange, blocking validator collateral claims (MEDIUM, C4)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [griefing, zero-amount, spam, DoS, warmup, multiplier-reset]

- id: staking-023
  pattern: staked-balance-used-outside-staking
  name: "Staked tokens usable for other purposes without unstaking"
  causa_raiz: >
    When staked tokens or their receipt tokens can be used for other purposes
    (providing liquidity, transferring, spending) without triggering unstake
    logic, the user maintains phantom staking balance and continues earning
    rewards on tokens they effectively withdrew. Missing balance checks allow
    staked tokens to be directed elsewhere.
  como_funciona: |
    1. User stakes 100 tokens, receives staking position
    2. User calls provideLiquidity(100) using same tokens — no check against staked balance
    3. Staking contract still shows user has 100 staked (phantom balance)
    4. User continues earning staking rewards on 100 tokens
    5. After LP lock period, user withdraws liquidity tax-free
    6. User has both: liquidity withdrawal proceeds + ongoing staking rewards on phantom balance
  invariante: |
    // Available balance must exclude staked amount
    assert(availableBalance(user) == totalBalance(user) - stakedBalance(user));
    // Staked tokens cannot be transferred or used elsewhere
    assert(stakedTokens.locked == true);
  que_mirar:
    - "provideLiquidity or addLiquidity not checking getAvailableBalance"
    - "Staked tokens transferable without reducing staking position"
    - "Multiple uses of same token balance (stake + LP + collateral)"
    - "Receipt tokens usable as collateral while original is staked"
  como_se_arregla: "Check available (non-staked) balance before any token use. Lock staked tokens explicitly. Deduct from staking position when tokens are used elsewhere."
  trampas:
    - "If staking uses a separate token (receipt/wrapper), original is free to use"
    - "Composability may intentionally allow receipt token use as collateral"
  incidentes:
    - "FluidLocker — Staked tokens withdrawn via provideLiquidity without unstaking, earning rewards on phantom balance (HIGH, Sherlock)"
    - "ZeroLend — OmnichainStaking allows burning voting power to unstake any NFT, swapping cheap lock for expensive one (HIGH, Immunefi)"
    - "CasimirManager — Stake 1 ETH to fill validator then immediately unstake, forcing validator exit with 64 ETH (HIGH, Pashov)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [phantom-balance, staked-tokens, liquidity, double-use, available-balance]

- id: staking-024
  pattern: reward-claim-tracking-not-keyed-by-token
  name: "Reward claim epoch tracker not keyed by reward token, claiming one token blocks all others"
  causa_raiz: >
    In multi-token reward systems, the lastEpochClaimed mapping is keyed only
    by user address (or operator address) and NOT by the reward token. When a
    staker/operator claims rewards for token A at epoch N, the contract updates
    lastEpochClaimed[user] = N for ALL tokens. If token B rewards for epochs
    < N have not been distributed yet, those rewards become permanently
    unreachable because the claim loop starts from lastEpochClaimed + 1.
  como_funciona: |
    1. Protocol distributes rewards in two tokens: TOKEN_A and TOKEN_B
    2. Epoch 4 arrives; rewards for TOKEN_A epoch 1 are distributed
    3. Operator claims TOKEN_A rewards -> lastEpochClaimed[operator] = 4
    4. Epoch 5: TOKEN_B rewards for epoch 2 are now distributed
    5. Operator tries to claim TOKEN_B for epoch 2
    6. Claim loop starts at epoch 5 (lastEpochClaimed + 1), skipping epoch 2 entirely
    7. TOKEN_B rewards for epochs 1-4 are permanently lost
  invariante: |
    // lastEpochClaimed must be tracked per (user, token) pair
    assert(lastEpochClaimed[user][tokenA] independent of lastEpochClaimed[user][tokenB]);
    // Claiming token A must not affect claimability of token B
  que_mirar:
    - "lastEpochClaimed or lastEpochClaimedOperator keyed only by address"
    - "Single mapping(address => uint48) instead of mapping(address => mapping(address => uint48))"
    - "Claim function accepting rewardToken parameter but updating global epoch tracker"
    - "Multiple reward tokens with asynchronous distribution schedules"
    - "claimRewards iterating from lastEpochClaimed to currentEpoch without per-token offset"
  como_se_arregla: "Key the lastEpochClaimed mapping by both user address AND reward token address. Each token's claim progress must be independent. Alternatively, track claims per (epoch, user, token) triple."
  trampas:
    - "If all reward tokens are always distributed in the same epoch, this is not exploitable"
    - "Single-token reward systems are unaffected"
  incidentes:
    - "Suzaku Core - lastEpochClaimedStaker/Curator/Operator not keyed by reward token, claiming one token blocks all others (HIGH, Cyfrin)"
    - "Suzaku Core — _calculateOperatorShare fetches current asset classes for historical epoch; new asset class causes division by zero, locking epoch rewards permanently (HIGH, Cyfrin)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [multi-token, reward-claim, epoch, mapping-key, permanent-loss]

- id: staking-025
  pattern: future-epoch-stake-cache-manipulation
  name: "Permissionless caching of future epoch stakes locks in manipulable values"
  causa_raiz: >
    Functions that cache operator/validator stake values per epoch lack validation
    that the requested epoch is in the past or current. When called with a future
    epoch, checkpoint-based lookups (upperLookupRecent) return the CURRENT values
    for future timestamps. Once cached with the totalStakeCached flag set to true,
    the values are immutable for that epoch. An attacker with high current stake
    can cache future epochs, then reduce their stake before those epochs arrive,
    locking in inflated reward shares.
  como_funciona: |
    1. Operator has 1000 ETH staked in current epoch N
    2. Operator calls calcAndCacheStakes(epoch=N+5, assetClassId) -- no epoch validation
    3. Cache stores operatorStakeCache[N+5][assetClass][operator] = 1000 ETH
    4. totalStakeCached[N+5][assetClass] = true (immutable flag)
    5. Operator unstakes 900 ETH before epoch N+5 arrives
    6. When epoch N+5 occurs, reward distribution uses cached 1000 ETH instead of actual 100 ETH
    7. Operator receives 10x their fair share of rewards
  invariante: |
    // Cache must only be set for past/current epochs
    assert(epoch <= currentEpoch || !totalStakeCached[epoch][assetClass]);
    // Cached values must reflect actual stake at epoch start
    assert(cachedStake[epoch][operator] == actualStake(epochStartTs, operator));
  que_mirar:
    - "calcAndCacheStakes or similar function without epoch <= currentEpoch check"
    - "totalStakeCached flag that prevents recalculation once set"
    - "upperLookupRecent returning latest values for future timestamps"
    - "Permissionless (public/external) cache functions"
    - "forceUpdateNodes or rebalancing that reads cached values"
  como_se_arregla: "Add strict epoch validation: require(epoch <= currentEpoch). Alternatively, only allow caching in the distributeRewards flow where the epoch is guaranteed to be past."
  trampas:
    - "If cache functions are access-controlled to trusted roles, risk is lower"
    - "If cache can be overwritten (no immutable flag), this is mitigated"
  incidentes:
    - "Suzaku Core - calcAndCacheStakes allows future epoch caching, locking in manipulable stake values (HIGH, Cyfrin)"
    - "Suzaku Core - forceUpdateNodes compromised by premature cache entries (HIGH, Cyfrin)"
    - "Suzaku Core — initializeValidatorStakeUpdate caches stake before P-Chain confirmation; unconfirmed increase included in rewards, fails on P-Chain (HIGH, Cyfrin)"
    - "Suzaku Core — _wasActiveAt uses >= instead of > for disabledTime; operator disabled at epochStartTs still counted, diluting active operators' rewards (HIGH, Cyfrin)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [epoch, cache, future, stake-manipulation, immutable-flag, restaking]

- id: staking-026
  pattern: gauge-kill-destroys-accumulated-rewards
  name: "Gauge deactivation zeroes accumulated rewards without settling or preserving them"
  causa_raiz: >
    When an admin or emergency council kills a gauge, the killGauge function sets
    claimable[gauge] = 0 and/or redirects future emissions to the minter, but does
    NOT first settle pending rewards by calling updateGauge or _claimFees. The
    totalWeight used for reward distribution is also not adjusted, causing remaining
    active gauges to receive less than their fair share (rewards calculated against
    stale totalWeight that includes the killed gauge). If the gauge is later revived,
    it starts with zero claimable, permanently losing pre-kill rewards.
  como_funciona: |
    1. Gauge A has 100 KITTEN in claimable rewards and 30% of totalWeight
    2. Emergency council calls killGauge(gaugeA)
    3. claimable[gaugeA] = 0 -- 100 KITTEN permanently lost
    4. totalWeight still includes gaugeA's weight (not adjusted)
    5. Next notifyRewardAmount distributes to active gauges using stale totalWeight
    6. Active gauges each receive less because totalWeight is inflated
    7. Killed gauge's weight share of emissions goes nowhere (stuck in contract)
    8. If gauge is revived, it restarts with 0 claimable -- pre-kill rewards unrecoverable
  invariante: |
    // Before kill: settle all pending rewards
    assert(claimable[gauge] == fullySettledRewards || rewardsTransferredToMinter);
    // After kill: totalWeight must be adjusted
    assert(totalWeight == sum(activeGaugeWeights));
  que_mirar:
    - "killGauge setting claimable[gauge] = 0 without calling updateGauge first"
    - "totalWeight not decremented when gauge is killed"
    - "_claimFees only called inside notifyRewardAmount (unreachable for killed gauges)"
    - "reviveGauge not restoring previous claimable amount"
    - "isAlive check inside reward accrual causing silent skip without weight adjustment"
  como_se_arregla: "Call updateGauge and _claimFees before killing. Transfer claimable amount to minter or reserve. Decrement totalWeight by the killed gauge's weight. On revive, restore from reserve or start fresh with adjusted totalWeight."
  trampas:
    - "If claimable is transferred to minter (not zeroed), funds are recoverable"
    - "If protocol never kills gauges, this is not reachable"
    - "Some protocols intentionally burn killed gauge rewards"
  incidentes:
    - "KittenSwap - killGauge zeros claimable without settling, 100% reward loss (HIGH, Pashov)"
    - "KittenSwap - gauge fees stuck in pair contract after kill because _claimFees unreachable (MEDIUM, Pashov)"
    - "KittenSwap - gauge still usable after killing, no deposit check (LOW, Pashov)"
    - "Hyperstable - missing claimable reward transfer in killGauge (LOW, Pashov)"
    - "RAAC - emergencyShutdown causes gauge to lose accumulated rewards at next distribution (MEDIUM, CodeHawks)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [gauge, kill, reward-loss, totalWeight, ve-DEX, emergency, settlement]

- id: staking-027
  pattern: reward-stream-reset-via-dust-donation
  name: "Dust token donation resets reward stream duration, diluting per-second distribution"
  causa_raiz: >
    Reward contracts that detect new rewards via balanceOf delta (unseen reward
    pattern) recalculate rewardPerSecond using the formula:
    (newAmount + leftover) / rewardStreamTime. If anyone can trigger this
    recalculation (e.g. by sending 1 wei of reward token to the contract), the
    entire leftover is re-spread over a fresh rewardStreamTime. Repeated dust
    donations keep resetting the distribution timer, effectively freezing reward
    delivery to near-zero per second.
  como_funciona: |
    1. Admin sends 1000 USDC as rewards, rewardPerSecond = 1000/604800 (1 week)
    2. After 3 days, 571 USDC distributed, 429 USDC leftover
    3. Attacker sends 1 wei USDC to contract
    4. Anyone calls claimRewards which triggers trackUnseenReward
    5. Unseen = 1 wei, rewardPerSecond = (1 + 429e6) / 604800 = same leftover spread over fresh week
    6. Effective distribution rate halved compared to intended schedule
    7. Attacker repeats every few hours, keeping rewards near-frozen
    8. Cost: only gas + 1 wei per attack
  invariante: |
    // Unseen reward detection must not be triggerable with dust amounts
    assert(unseenAmount >= minRewardThreshold || noRecalculation);
    // rewardPerSecond should not decrease due to external token transfers
  que_mirar:
    - "trackUnseenReward or _handleUnseenReward reading balanceOf delta"
    - "rewardPerSecond recalculated with (newAmount + leftover) / fullDuration"
    - "No minimum threshold on unseen reward amount"
    - "Public/permissionless functions triggering reward tracking"
    - "balanceOf-based reward detection instead of notifyRewardAmount pattern"
  como_se_arregla: "Use explicit notifyRewardAmount with access control instead of balanceOf detection. If using unseen pattern, require minimum unseen amount threshold. Alternatively, only extend remaining duration proportionally to new amount."
  trampas:
    - "If reward detection is access-controlled (only admin), dust attack is blocked"
    - "If minimum unseen threshold is enforced, dust amounts are filtered"
    - "Standard Synthetix notifyRewardAmount pattern is immune to this"
  incidentes:
    - "DefiApp/MFDLogic - Dust reward token donation resets rewardPerSecond, extending vesting for all users (MEDIUM, Cantina)"
    - "Kwenta - USDC 6-decimal precision + frequent updates cause rewardPerToken to round to zero (MEDIUM, Sherlock)"
    - "DIA Staking — claim() with daysElapsed=0 on sub-day intervals advances rewardLastUpdateTime without distributing rewards; griefable via frequent calls (HIGH, MixBytes)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [dust, donation, reward-stream, balanceOf, griefing, rewardPerSecond]

- id: staking-028
  pattern: stake-on-behalf-hijacks-user-state
  name: "Permissionless stake-on-behalf overwrites victim's delegation, multiplier, or warmup"
  causa_raiz: >
    When a staking function accepts a (amount, receiver, delegatee) tuple and
    the caller can specify any receiver, the function overwrites the receiver's
    delegatee without the receiver's consent. By staking 1 wei for a victim with
    a new delegatee, the attacker hijacks the victim's entire voting power.
    Similarly, stake-on-behalf can reset warmup timers, flood lock arrays causing
    OOG on withdrawal, or overwrite reward accumulator state.
  como_funciona: |
    1. Victim has 1000 veTokens delegated to validatorA
    2. Attacker calls stake(1 wei, victim, attacker) -- stakes 1 wei for victim
    3. _delegate(victim, attacker) overwrites victim's delegation to point to attacker
    4. Attacker now controls victim's 1000 veToken voting power
    5. Attacker stakes 1 wei for multiple large holders, accumulating majority voting power
    6. Attacker submits and passes malicious governance proposal
    7. OR: attacker floods victim's userLocks array with tiny stakes -> OOG on withdrawal
  invariante: |
    // Delegation change must require receiver's consent
    assert(msg.sender == receiver || receiver.approved(msg.sender));
    // Stake-on-behalf must not modify receiver's existing delegation
    assert(delegatee_after == delegatee_before || msg.sender == receiver);
    // userLocks array length must be bounded per user
    assert(userLocks[user].length <= MAX_LOCKS);
  que_mirar:
    - "stake(amount, receiver, delegatee) where receiver != msg.sender allowed"
    - "_delegate(receiver, delegatee) called unconditionally in stake"
    - "No minimum stake amount allowing 1 wei attacks"
    - "userLocks or StakedLock array grows unbounded on each stake call"
    - "Warmup period reset on any stake event including third-party stakes"
  como_se_arregla: "Require msg.sender == receiver for delegation changes, or only call _delegate when msg.sender == receiver. Set minimum stake amount. Cap userLocks array length per user. Do not reset warmup on third-party stakes."
  trampas:
    - "If stake-on-behalf is restricted to approved callers, attack surface is limited"
    - "If delegation is separate from staking (standalone delegate() function), this specific path may not exist"
  incidentes:
    - "Virtuals Protocol - Anyone calls stake(1 wei, victim, attacker) to hijack delegation and voting power (HIGH, C4)"
    - "Virtuals Protocol - Validator score initialized to maxScore, earn full rewards without participation (HIGH, C4)"
    - "DefiApp - Flooding userLocks array via permissionless stake-on-behalf causes OOG on withdrawal (HIGH, Cantina)"
    - "Yieldy - stake(1 wei, victim) resets warmup period, permanent DoS on claiming (HIGH)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [delegation-hijack, stake-on-behalf, voting-power, griefing, OOG, array-flooding]

- id: staking-029
  pattern: reward-accumulator-uninitialized-for-new-stakes
  name: "New staker's reward accumulator initialized to zero, claims all historical rewards"
  causa_raiz: >
    When a new staker enters the system, their per-user reward accumulator
    (rewardAccumulator, userRewardPerTokenPaid, inflationIndex, or similar) is
    not initialized to the current global accumulator value. The earned() function
    computes rewards as: globalAccumulator - userAccumulator. Since userAccumulator
    starts at 0, the new staker is credited with ALL rewards accumulated since
    contract deployment, not just rewards since they staked.
  como_funciona: |
    1. Contract deployed, globalAccumulator starts at 0
    2. Rewards accumulate for 90 days, globalAccumulator reaches 1000
    3. Existing stakers have userAccumulator = 500 (claimed partway through)
    4. New staker arrives, stakes 100 tokens
    5. newStaker.userAccumulator = 0 (never initialized)
    6. earned(newStaker) = 100 * (1000 - 0) = 100,000 (should be 0)
    7. New staker claims 100,000 reward tokens, draining from existing stakers
    8. Repeatable: stake -> claim -> unstake -> repeat with new address
  invariante: |
    // On stake: user accumulator must be set to current global accumulator
    assert(newStore.rewardAccumulator == globalRewardAccumulator);
    // earned() for a brand new stake must return 0
    assert(earned(newStaker) == 0 immediately after staking);
  que_mirar:
    - "_internalStakeForAddress not setting rewardAccumulator to current global value"
    - "updateReward modifier skipped for new stakers (if staker.lastStakedEpoch == 0)"
    - "userRewardPerTokenPaid remaining 0 when vestingRate is 0 at stake time"
    - "Conditional _updateRewards only called if staker.lastStakedEpoch > 0"
    - "inflationIndex or gInflationIndex not assigned to new user"
  como_se_arregla: "Always initialize userRewardPerTokenPaid (or equivalent) to the current global rewardPerToken at the time of staking. Do not skip updateReward for first-time stakers. Set newStore.rewardAccumulator = currentGlobalAccumulator in _internalStakeForAddress."
  trampas:
    - "If the protocol has no accumulated rewards before first stake, this is harmless"
    - "Synthetix-style contracts with updateReward modifier on stake() are immune if modifier runs unconditionally"
  incidentes:
    - "DIA Staking - rewardAccumulator not initialized on stake creation, new stakers claim all historical rewards (CRITICAL, MixBytes)"
    - "NodeOps - lastStakedEpoch not set, _updateRewards skipped for new stakers, claim rewards from epoch 0 (HIGH, Halborn)"
    - "NodeOps - _updateRewards double-counts: staker.rewards += staker.rewards + calculated, exponential inflation (HIGH, Halborn)"
    - "TempleGold - userRewardPerTokenPaid = 0 for new stakes because vestingRate is 0, claims all past rewards (HIGH, CodeHawks)"
    - "DIA Staking — permissionless addRewardToPool + 1-share manipulation enables inflation attack; victim receives 0 shares, attacker drains deposit (CRITICAL, MixBytes)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [accumulator, initialization, historical-rewards, drain, first-staker, rewardPerToken]

- id: staking-030
  pattern: two-step-unstake-missing-state-persistence
  name: "Two-step unstake process loses withdrawal request between initiate and complete"
  causa_raiz: >
    Many staking protocols split unstaking into two steps: (1) initiate unstake
    (burn receipt tokens, start cooldown), and (2) complete withdrawal (transfer
    underlying). If the initiate step burns tokens or adjusts balances but fails
    to persist the withdrawal request in storage (e.g. withdrawalRequests[user]),
    the user's tokens are destroyed with no record of the pending withdrawal.
    The complete step checks withdrawalRequests and finds nothing, so the user
    receives nothing. Also occurs when fallback paths (validator unstake vs
    buffer unstake) have asymmetric state writes.
  como_funciona: |
    1. User calls unstake(amount) which burns their staking receipt tokens
    2. Contract checks buffer: insufficient balance, falls back to validator unstake
    3. Validator unstake path returns amountUnstaked but does NOT write withdrawalRequests[user]
    4. User's receipt tokens are already burned (irreversible)
    5. User calls withdraw() which reads withdrawalRequests[msg.sender] -- empty
    6. withdraw() reverts or returns 0 -- user receives nothing
    7. User has lost both receipt tokens AND underlying tokens
    8. No recovery mechanism exists
  invariante: |
    // Every code path that burns receipt tokens MUST persist withdrawal request
    assert(receiptBurned => withdrawalRequests[user].amount > 0);
    // After unstake: user must have either tokens returned OR withdrawal request saved
    assert(tokensReturned || withdrawalRequests[user].amount == unstakeAmount);
  que_mirar:
    - "Multiple unstake code paths (buffer vs validator) with different state writes"
    - "Fallback paths that return early without persisting withdrawalRequests"
    - "receipt token burn before withdrawal request storage write"
    - "withdrawalRequests populated in one path but not the other"
    - "stakingDelayStartTime not reset after claimUnstake, blocking future stakes"
    - "Concurrent unstake requests sharing same currentWithheldETH without reservation"
  como_se_arregla: "Ensure ALL code paths that burn receipt tokens also persist the withdrawal request. Use a single unified state write after all branching logic. Add invariant check: if tokens burned, withdrawalRequest must be non-zero."
  trampas:
    - "If protocol only has a single unstake path (no fallback), this doesn't apply"
    - "If receipt tokens are not burned until withdrawal completes, tokens are safe"
  incidentes:
    - "Mystic Finance - Validator unstake fallback path burns frxETH but doesn't save withdrawalRequests, permanent fund loss (HIGH, Kann)"
    - "Mystic Finance - Multiple concurrent unstake() calls share same currentWithheldETH, later withdrawals fail (MEDIUM, Kann)"
    - "SXT - stakingDelayStartTime not reset after claimUnstake, blocks future staking (MEDIUM, Pashov)"
    - "Casimir - fulfillUnstakes uses stale withdrawnEffectiveBalance, over-fulfills and causes underflow DoS (MEDIUM, Cyfrin)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [two-step-unstake, withdrawal-request, state-persistence, fund-loss, fallback-path]

- id: staking-031
  pattern: reward-to-wrong-recipient-after-custody-transfer
  name: "Rewards sent to current token holder instead of original staker after custody transfer"
  causa_raiz: >
    When staked NFT positions (Uniswap V3 NFPs, veTokens, validator NFTs) are
    transferred to a staking gauge/contract, ownership changes to the contract.
    If the reward claim function uses ownerOf(tokenId) to determine the recipient,
    it sends rewards to the contract itself (the current owner) instead of the
    original depositor. The rewards become permanently trapped. Similarly, after
    operator key reassignment, claim-by-key maps to the new operator address,
    allowing the new operator to re-claim already-claimed rewards.
  como_funciona: |
    1. User deposits NFP tokenId into CLGauge, ownership transfers to gauge contract
    2. Rewards accumulate for tokenId
    3. User calls getReward(tokenId) which internally calls _getReward
    4. _getReward does: owner = nfp.ownerOf(tokenId) -- returns gauge contract address
    5. Reward transferred from gauge to gauge (self-transfer), permanently trapped
    6. OR: Operator key X was assigned to operatorA, who claimed epoch 5 rewards
    7. Key X reassigned to operatorB
    8. operatorB claims epoch 5 rewards using key X -- claimed[epoch][recipient] is different
    9. Double claim: same rewards paid to both operatorA and operatorB
  invariante: |
    // Reward recipient must be the depositor, not current NFT owner
    assert(rewardRecipient == originalDepositor[tokenId]);
    // claimed[epoch] must be keyed by operatorKey, not resolved address
    assert(claimed[epoch][operatorKey] prevents re-claim after key reassignment);
  que_mirar:
    - "getReward using nfp.ownerOf(tokenId) as transfer recipient"
    - "NFT custody transferred to staking contract on deposit"
    - "No mapping from tokenId to original depositor address"
    - "operatorByKey() resolving to different address after key reassignment"
    - "claimed mapping keyed by resolved address instead of operator key"
  como_se_arregla: "Store original depositor address on deposit, use it as reward recipient. For operator rewards, key claimed mapping by operatorKey bytes32 instead of resolved address."
  trampas:
    - "If staking contract doesn't take NFT custody (uses approval instead), ownerOf is correct"
    - "If operator keys are immutable (never reassigned), double-claim is impossible"
  incidentes:
    - "KittenSwap - CLGauge._getReward sends KITTEN to nfp.ownerOf() which is the gauge itself, 100% rewards lost (CRITICAL, Pashov)"
    - "Tanssi - ODefaultOperatorRewards tracks claimed by recipient address, key reassignment enables double-claim (MEDIUM, Pashov)"
    - "Blueberry - Re-depositing to Ichi farm sends ICHI rewards to spell contract, not user (HIGH, Sherlock)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [custody-transfer, ownerOf, wrong-recipient, NFT, operator-key, double-claim]
```

---

## 2. Cross-Cutting Patterns from Exploit Registry

### 2.1 Cross-Function Reentrancy in Staking

```yaml
- id: staking-032
  pattern: staking-cross-function-reentrancy
  name: "Cross-function reentrancy via reward token callback"
  causa_raiz: >
    If the reward or staking token has transfer hooks (ERC-777, ERC-1155,
    native ETH), a callback during getReward() can re-enter stake() or
    withdraw(), reading stale state. The reentrancy guard on getReward()
    does not protect stake() if they have separate guards.
  como_funciona: |
    1. Attacker calls getReward()
    2. Contract transfers reward tokens -> callback to attacker
    3. During callback, attacker calls stake() or withdraw()
    4. stake()/withdraw() reads stale rewardPerTokenStored
    5. Attacker's checkpoint is set incorrectly
    6. Subsequent claim extracts excess rewards
  invariante: "Total staked equals sum of individual stakes (INV-STAKE-001). All state modifications complete before external calls (INV-EXPLOIT-011)."
  que_mirar:
    - "Is ReentrancyGuard applied globally or per-function?"
    - "Do reward/staking tokens have transfer hooks?"
    - "Is updateReward modifier called on ALL public functions?"
    - "Are state writes completed before any token transfer?"
  como_se_arregla: "Use a single global ReentrancyGuard across all state-changing functions. Follow CEI pattern. Use OpenZeppelin ReentrancyGuard (not custom)."
  trampas:
    - "Pure ERC-20 tokens without hooks cannot trigger this"
    - "Per-function reentrancy guards create a false sense of security"
  incidentes:
    - "Stakehouse — _distributeETHRewardsToUserForToken ETH callback enables reentrancy across deposit/withdraw/claim (HIGH, C4)"
    - "Stakehouse — withdrawDETH reentrancy in GiantSavETHVaultPool from no whitelist check (HIGH, C4)"
    - "Recall — Reentrancy in leave() halts bottom-up checkpoints (HIGH, C4)"
    - "Notional/Exponent — Cross-contract reentrancy via WithdrawalRequestManager serving multiple vaults (HIGH, Sherlock)"
    - "AI Arena — claimRewards reentrancy via smart contract wallet mints excess NFTs (HIGH, C4)"
  severidad: critical
  confianza: alta
  fuente: "COMP-MULTI-003, INV-EXPLOIT-011, INV-EXPLOIT-019"
  verificado: true
  tags: [reentrancy, cross-function, callback, ERC-777, global-guard]
  relacionado_con: [staking-004]
```

### 2.2 Emergency Withdraw Accounting Break

```yaml
- id: staking-033
  pattern: emergency-withdraw-accounting
  name: "Emergency withdraw breaks reward accounting invariants"
  causa_raiz: >
    emergencyWithdraw() in MasterChef-style contracts removes principal
    without calling updateReward(). The user's rewardDebt is not adjusted,
    totalStaked decreases but rewardPerTokenStored remains stale.
    Subsequent operations see inflated rewards for remaining stakers.
  como_funciona: |
    1. User A and B each stake 100 tokens
    2. Rewards accumulate: 10 tokens allocated
    3. User A calls emergencyWithdraw() — gets 100 tokens back, rewards forfeited
    4. totalStaked drops to 100, but rewardPerToken was computed with 200
    5. User B now earns rewards as if they were the only staker the entire time
    6. User B claims 10 tokens (full allocation) despite sharing the period
  invariante: "Total rewards distributed never exceeds total allocated (INV-STAKE-006). Emergency withdraw amount <= user deposited (INV-EXPLOIT-025)."
  que_mirar:
    - "Does emergencyWithdraw update totalStaked?"
    - "Does it update rewardPerTokenStored?"
    - "Does it zero the user's rewardDebt?"
    - "Can remaining stakers claim more than their fair share after emergency exit?"
    - "Can emergencyWithdraw be called when not paused?"
  como_se_arregla: "Call updateReward(user) inside emergencyWithdraw before modifying balances. Or accept that forfeited rewards are redistributed (document as intended behavior)."
  trampas:
    - "Redistributing forfeited rewards to remaining stakers may be intentional"
    - "MasterChef emergencyWithdraw by design forfeits rewards — not always a bug"
  incidentes:
    - "Ampera/OpenZeppelin — Unit-based accounting with claims reducing total tokens causes units-per-token inflation, eventually locking funds permanently (HIGH)"
    - "Hybra Finance — Users emergency withdrawing lose all past accrued rewards without accounting update (MEDIUM)"
    - "Stakehouse — BringUnusedETHBackIntoGiantPool doesn't update idleETH, stuck funds (HIGH, C4)"
    - "Stakehouse — GiantLP with transferHookProcessor can't be burned, funds stuck in Giant Pool (HIGH, C4)"
    - "Tigris — Malicious user steals all assets in BondNFT via accounting gap in emergency path (HIGH, C4)"
  severidad: high
  confianza: media
  fuente: "INV-EXPLOIT-025, INV-STAKE-001, INV-STAKE-006"
  verificado: true
  tags: [emergency-withdraw, accounting, MasterChef, forfeited-rewards]
  relacionado_con: [staking-005, staking-006]

- id: staking-034
  pattern: staked-nft-collateral-liquidation-race
  name: "Staked NFT collateral: collateral value computed before unstake causes health-check/valuation mismatch"
  causa_raiz: >
    In lending protocols that allow NFT LP positions to be staked in an external gauge
    while simultaneously serving as collateral, the health check evaluates the position
    under staked semantics (fees excluded from collateral value via `ignoreFees=true`)
    but the liquidation value and liquidator cost are calculated using that same stale
    staked valuation. When the position is unstaked immediately after (to return the NFT
    to the vault for liquidation processing), the NFT now includes unclaimed fees that
    were excluded from the collateral calculation — a discrepancy between what the
    liquidator pays and what they actually receive. In the opposite direction, if the
    health check uses un-staked valuation for a staked position, collateral value is
    overstated and the protocol may fail to trigger liquidation on positions that are
    actually undercollateralized.
  como_funciona: |
    Revert Lend implementation (V3Vault.sol):
    1. `liquidate()` calls `_checkLoanIsHealthy(tokenId, debt, false)` at line 742.
    2. Inside, `_isStaked(tokenId)` returns true → `ignoreFees=true` → fee value excluded from fullValue.
    3. collateralValue = fullValue (no fees) * collateralFactor.
    4. `liquidationValue` and `liquidatorCost` are computed from this fee-excluded fullValue.
    5. Then `_unstakeIfNeeded(tokenId)` at line 748 returns NFT to vault WITH accumulated fees.
    6. `_sendPositionValue()` collects fees (lines 1116-1133) when delivering collateral to liquidator.
    7. Result: liquidator receives more value than `liquidationValue` accounted for (fee windfall),
       or in a protocol where fees increase collateral value post-unstake, the protocol over-delivers.
    Direction of harm depends on magnitude of unclaimed fees vs liquidation math.
  invariante: |
    // Collateral value used for liquidation must match value actually received by liquidator
    assert(valueReceivedByLiquidator <= liquidationValue + DUST_TOLERANCE);
    // If staked, collateral value must not include fees (staked positions can't collect fees via oracle)
    if (isStaked(tokenId)) assert(feeValue == 0 || collateralValue ignores feeValue);
  que_mirar:
    - "Does _checkLoanIsHealthy use the same fee-inclusion mode before and after unstaking?"
    - "Is `ignoreFees` set correctly for staked vs. un-staked positions during health check?"
    - "Can fees accumulated while staked inflate liquidator returns beyond `liquidationValue`?"
    - "Is there a path where `tokenIdToGauge` changes between health check and unstake (reentrancy)?"
    - "Does compoundRewards (which temporarily unstakes and restakes) affect health check timing?"
    - "Is `_isStaked` a storage read that can be front-run to manipulate the fee-inclusion mode?"
  como_se_arregla: >
    Evaluate health and compute liquidation amounts AFTER unstaking, or ensure the same
    fee-inclusion semantics are used throughout. Re-running `_checkLoanIsHealthy` after
    `_unstakeIfNeeded` with updated `ignoreFees` would ensure consistent valuation.
    Alternative: prohibit staking positions that have outstanding debt, or cap fee value
    inclusion at the time of liquidation to what was priced at health check time.
  trampas:
    - "Revert Lend uses `ignoreFees=true` for staked to be CONSERVATIVE (lower collateral value) — this actually protects the protocol from being under-collateralized. The liquidator windfall is a feature, not a bug in their case."
    - "The real risk is the reverse: if a protocol counts staked fee value as collateral but the fees are not claimable during liquidation, collateral is overstated."
    - "During compoundRewards, the position is temporarily unstaked and restaked — if a liquidation is triggered in the same block between these steps, `_isStaked` returns false and fees ARE included in collateral."
  incidentes:
    - "No verified incident found for this exact pattern in the Solodit DB (2026-03-21 search)"
    - "Related: NFT cannot be withdrawn after all liquidity removed from CLGauge (Velodrome/Spearbit, MEDIUM) — gauge custody block pattern"
  severidad: medium
  confianza: media
  fuente: "Análisis GaugeManager.sol + V3Vault.sol revert-lend 2026"
  verificado: false
  tags: [staking, NFT, collateral, lending, liquidation, gauge, fee-exclusion, oracle]
  relacionado_con: [staking-033, lending-040]

- id: staking-035
  pattern: compound-rewards-staked-collateral-vault-desync
  name: "compoundRewards on staked collateral: vault oracle sees new liquidity but health re-check timing creates window"
  causa_raiz: >
    When a lending protocol delegates compounding (reinvesting earned gauge rewards into LP
    liquidity) to an external GaugeManager, the compound operation temporarily moves the NFT
    out of the gauge (unstake → add liquidity → restake). During this window, `_isStaked(tokenId)`
    returns false. Any health check triggered in this window evaluates the position with fees
    INCLUDED (since ignoreFees is now false), potentially accepting a higher collateral value
    than the post-restake oracle would use. Additionally, `compoundRewards` is callable by
    anyone (owner OR vault), meaning an attacker can trigger a compound to create this window
    at a time advantageous to them (e.g., immediately before/during a borrow call).
  como_funciona: |
    1. User has position staked in gauge, used as collateral in vault, near health boundary.
    2. Attacker (or user) calls `GaugeManager.compoundRewards()` on that tokenId.
    3. Inside compound: `IGauge(gauge).withdraw(tokenId)` — NFT moves to GaugeManager.
    4. `_isStaked(tokenId)` still returns true (tokenIdToGauge not deleted yet).
    5. `_addLiquidity()` adds new token amounts to the NFT, increasing its liquidity.
    6. `IGauge(gauge).deposit(tokenId)` — NFT goes back to gauge.
    7. The vault's oracle will price the higher-liquidity position at next health check.
    8. Net effect: collateral value increases after compound → user can borrow more.
    Potential griefing scenario:
    1. User near max borrow.
    2. Attacker calls compoundRewards (small rewards → small liquidity increase).
    3. Vault's next health check sees higher collateral value.
    4. User borrows up to new collateral ceiling.
    5. Rewards stop flowing (gauge killed / AERO price drops) → collateral value reverts to pre-compound level.
    6. Position becomes undercollateralized.
  invariante: |
    // Collateral value after compound must be re-verified against outstanding debt
    // before compound operation is considered complete
    assert(collateralValue(tokenId) >= outstandingDebt(tokenId) / collateralFactor);
    // compoundRewards must not increase borrowable amount for a position with existing debt
    // without a health re-check
  que_mirar:
    - "Does the vault re-check loan health after compoundRewards adds liquidity to a collateral position?"
    - "Who can call compoundRewards — only owner, or anyone? (GaugeManager: owner OR vault)"
    - "Can compoundRewards be called on a position with outstanding debt to inflate collateral?"
    - "Does the oracle value update immediately after liquidity addition, or is there a TWAP delay?"
    - "Is the compound's reward→liquidity swap path sandwichable to increase collateral value above real market price?"
  como_se_arregla: >
    After compoundRewards executes, verify that outstanding debt is still within healthy
    bounds of the updated collateral value. Alternatively, cap the borrow limit to pre-compound
    collateral value (record collateral value at borrow time and use the lower of current vs. recorded).
    The safest fix: require that the health factor IMPROVES or stays constant after compound (never
    allows new borrows based solely on compounded liquidity gains).
  trampas:
    - "Revert Lend's compoundRewards is permissionless (owner or vault) — this IS the intended design for keeper automation"
    - "The oracle uses TWAP, so a single compound won't immediately reflect at full new value — mitigates but doesn't eliminate"
    - "A vault that calls compoundRewards inside transform() (line 533-537 V3Vault) does so BEFORE unstaking for the transform — this is intentional pre-processing, not a bug"
  incidentes:
    - "No verified incident for this exact pattern (2026-03-21 search)"
    - "Conceptually related: Ethereum Credit Guild M-19 — gauge stakers can be unstaked despite full debt allocation (C4, MEDIUM)"
  severidad: medium
  confianza: baja
  fuente: "Análisis GaugeManager.sol + V3Vault.sol revert-lend 2026"
  verificado: false
  tags: [staking, compound, collateral, lending, gauge, oracle, health-factor, permissionless]
  relacionado_con: [staking-034, lending-040]
```

---

## 2.3 Real-World Incidents (Verified)

```yaml
- id: staking-incident-001
  name: "SNK exploit"
  fecha: "2023-05"
  perdida: "$197K"
  causa_raiz: "Reward calculation error"
  categoria: "Reward-per-share rounding / miscalculation"
  vector: "Flawed reward computation allowed attacker to extract more rewards than entitled"
  leccion: "Reward accumulators must be fuzzed with small stakes and large reward injections. See staking-001."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-001, staking-006]
  tags: [reward-calculation, real-exploit]

- id: staking-incident-002
  name: "OSN exploit"
  fecha: "2024-05"
  perdida: "$109K"
  causa_raiz: "Reward distribution problem"
  categoria: "Reward distribution logic flaw"
  vector: "Incorrect reward distribution logic allowed disproportionate claim"
  leccion: "Invariant INV-STAKE-006 (totalDistributed <= totalAllocated) would catch this class of bug."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-001, staking-006]
  tags: [reward-distribution, real-exploit]

- id: staking-incident-003
  name: "BNO exploit"
  fecha: "2023-07"
  perdida: "$505K"
  causa_raiz: "Emergency withdraw flaw"
  categoria: "Emergency withdraw accounting break"
  vector: "emergencyWithdraw path broke reward accounting invariants, enabling fund extraction"
  leccion: "Emergency withdraw MUST update all accounting state. See staking-008."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-008, staking-005]
  tags: [emergency-withdraw, real-exploit]

- id: staking-incident-004
  name: "OKC exploit"
  fecha: "2023-11"
  perdida: "$6,268"
  causa_raiz: "Reward unlock logic flaw"
  categoria: "Cooldown/unlock bypass"
  vector: "Reward unlock mechanism exploitable to claim rewards before intended unlock time"
  leccion: "Lock periods must be enforced on ALL paths including claim. See staking-005."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-005]
  tags: [reward-unlock, cooldown-bypass, real-exploit]

- id: staking-incident-005
  name: "OTSeaStaking exploit"
  fecha: "2024-09"
  perdida: "$26K"
  causa_raiz: "Logic flaw in staking contract"
  categoria: "Staking logic error"
  vector: "Logic flaw allowed attacker to manipulate staking state for profit"
  leccion: "Fuzz all staking state transitions. INV-STAKE-001 (totalStaked == sum of balances) catches many logic errors."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-001]
  tags: [logic-flaw, staking, real-exploit]

- id: staking-incident-006
  name: "Penpiexyz_io exploit"
  fecha: "2024-09"
  perdida: "$27.3M"
  causa_raiz: "Reentrancy combined with reward manipulation"
  categoria: "Cross-function reentrancy + reward manipulation"
  vector: "Reentrancy during reward claim allowed attacker to manipulate reward state and extract massive funds"
  leccion: "CRITICAL: Global reentrancy guards are mandatory. Per-function guards leave cross-function paths open. See staking-007."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-007, staking-004]
  tags: [reentrancy, reward-manipulation, cross-function, real-exploit]

- id: staking-incident-007
  name: "yearnFinance exploit"
  fecha: "2023-04"
  perdida: "$11.6M"
  causa_raiz: "Misconfiguration in vault/staking setup"
  categoria: "Configuration error"
  vector: "Misconfigured vault parameters allowed attacker to exploit staking/yield logic"
  leccion: "Deployment configurations must be validated. Forked mainnet testing catches misconfigurations that unit tests miss."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [staking-003, staking-006]
  tags: [misconfiguration, vault, real-exploit]
```

---

## 3. Invariant Checklist (Quick Reference)

| ID | Invariant | Tier | Source |
|----|-----------|------|--------|
| INV-STAKE-001 | totalStaked == sum(balanceOf(all_stakers)) | 1 | reward_distribution.json |
| INV-STAKE-002 | rewardPerToken monotonically increases | 1 | reward_distribution.json |
| INV-STAKE-003 | claimed <= earned(user) at call time | 1 | reward_distribution.json |
| INV-STAKE-004 | unstake(amount) reduces balance by exactly amount | 2 | reward_distribution.json |
| INV-STAKE-005 | unstake reverts within lock period | 2 | reward_distribution.json |
| INV-STAKE-006 | totalDistributed <= totalAllocated | 1 | reward_distribution.json |
| INV-STAKE-007 | stake after periodFinish earns zero new rewards | 2 | reward_distribution.json |
| INV-STAKE-008 | no double-counting across epoch boundaries | 1 | reward_distribution.json |

**Tier 1** = hard fail = confirmed bug. **Tier 2** = needs review, may have dust tolerance.

---

## 4. Grep Targets

```
rewardPerToken
rewardPerTokenStored
rewardRate
notifyRewardAmount
periodFinish
lastTimeRewardApplicable
userRewardPerTokenPaid
earned
getReward
stake(
unstake(
withdraw(
cooldown
lockPeriod
emergencyWithdraw
totalStaked
_totalSupply
balances[
```

---

## 5. Fuzzing Priority

1. **Solvency**: totalDistributed <= totalAllocated (ghost variable required)
2. **Monotonicity**: rewardPerToken never decreases
3. **Overclaim**: no user extracts more than earned()
4. **Flash stake**: stake + claim + unstake in same block yields <= gas cost
5. **Accounting**: totalStaked == sum(individual balances) after every operation
6. **Epoch boundary**: notifyRewardAmount mid-period does not double-count

Run Medusa first (stateful sequences), then Echidna optimization (maximize attacker profit).

---

## Solodit Verified Findings

### Maps to staking-001 (reward-per-share rounding)
- **[HIGH] Updating pool total points doesn't affect existing stake positions** — Changing totalPoints retroactively inflates/deflates existing stakers' reward shares since rewards use current totalPoints, not time-weighted (NeoTokyoStaker, C4)
- **[HIGH] Incorrect accounting in SyndicateRewardsProcessor** — `claimed[user][token]` set equal to `due` instead of incremented by `due`, causing first claim correct but subsequent claims to steal from others (StakeHouse, C4)
- **[HIGH] User's accrued rewards lost on small stakes** — When user balance is tiny relative to totalSupply, `(rewardState * userRewards) / globalRewards` rounds to zero, and accrued rewards are zeroed out before the transfer (PirexRewards, C4)
- **[MEDIUM] Integer overflow when calculating rewards** — cumulatedReward scaled by 1e36 can overflow uint256 when multiplied by staker balance; griefable by staking 1 wei and depositing 1e18 reward (Gamma Staking, Sherlock)
- **[MEDIUM] Vault loses rewards due to low-decimal price precision** — When `price()` has 6 decimals (Idle USDC), `rewardPerLockedToken` rounds to zero for small performance periods, silently losing all rewards (Derby, Sherlock)
- **[MEDIUM] Imprecise reward distribution using total_stakes as denominator** — Using total_stakes without accounting for pending unapplied rewards creates semantic imprecision; troves with applied rewards get more, unapplied get less (Sway trove-manager, Otter Audits)
- **[HIGH] Vault rewards incorrectly scaled by cross-asset-class totals** — Using operator's total rewards across ALL asset classes to scale individual vault rewards creates dilution; operators with asymmetric stake across asset classes get incorrect distributions (Rewards contract, Pashov)

### Maps to staking-002 (flash-stake timing attack)
- **[HIGH] NFTXLPStaking flash loan attack** — No lock period on LP staking allows flash loan -> stake -> claim all accrued fees -> unstake -> repay in single tx; the flash-loaned stake dwarfs legitimate stakers' shares (NFTX, C4)
- **[HIGH] Gauge reward system gamed with repeated stake/withdraw** — No minimum staking period or time-weighted averages allows temporarily staking large amounts, accruing rewards, withdrawing, and repeating to maximize rewards (RAAC Gauge, CodeHawks)
- **[MEDIUM] depositFees frontrunnable** — Attacker front-runs fee deposit with large lock(), captures 50% of fees intended for existing stakers, then claims and exits immediately (BkdLocker, C4)
- **[HIGH] MEV extractable from distribute()** — Attacker stakes immediately before distribute() and unstakes after, capturing a proportional share of rewards with zero time commitment; harvest() being public amplifies the attack (GMXDepositor, Quantstamp)
- **[HIGH] Accrued limit order fees stolen** — Attacker creates large limit order to capture 90% of liquidity, swaps to fill, then withdraws, stealing accumulated fees from existing orders in one block (LimitOrderHook, OpenZeppelin)

### Maps to staking-003 (reward donation inflation)
- **[HIGH] 1 wei attacker freezes all deposits** — Attacker force-sends 1 wei via selfdestruct before any deposit, making `_assetBalance() > 0` while `_totalSupply() == 0`, so `sharesToMint = 0` for all subsequent depositors (River protocol, Spearbit)
- **[HIGH] Share price manipulation via donation to strategy controller** — First depositor mints 1 share then donates to strategy controller; subsequent depositors get 0 shares due to inflated share price (Collateral.sol, C4)

### Maps to staking-004 (double-claim)
- **[HIGH] Voter loses bribe rewards when another voter votes before claim** — `_lastUpdateTimestamp` is global not per-period; once updated to next period, unclaimed rewards from previous period become unrecoverable (BribeRewarder, Sherlock)
- **[HIGH] Stakers lose earned aSugar on second stake** — `cheque.lastPrintedAt` updated on delegateStake() without minting accumulated rewards from prior stakes, silently zeroing unclaimed yield between stakes (StakingKo, Cantina)
- **[HIGH] Bucket rewards wiped by stake/unstake before accrueRewards** — lastRewardIndex reset in stake/unstake without settling pending rewards; anyone can call stake/unstake right before accrueReward to zero the bucket's delta (SuperDCAStaking, Sherlock)

### Maps to staking-005 (cooldown/unstake bypass)
- **[HIGH] Attacker steals locked NFT balance** — OmnichainStaking unstake allows burning voting power to unstake any NFT; two NFTs with same power but different locked balances enable swapping cheap lock for expensive one (ZeroLend, Immunefi)
- **[HIGH] Missing balance deduction in unstaking** — `initiateUnstake()` and `unstake()` never deduct staked amount from user's StakingInfo, allowing repeated `unstake()` calls with same orderId to drain contract (SapienStaking, Quantstamp)
- **[HIGH] Staked tokens withdrawn via provideLiquidity without unstaking** — Missing `getAvailableBalance()` check allows using staked tokens for Uniswap liquidity, then withdrawing tax-free after 6 months while staking rewards continue accruing on phantom balance (FluidLocker, Sherlock)

### Maps to staking-006 (reward exhaustion/insolvency)
- **[HIGH] Incorrect reward calculation when reward rate changes** — Rewards calculated using current rewardRatePerDay regardless of historical rate changes; identical stakes get different rewards depending on when unstake is called (DIAWhitelistedStaking, Hacken)
- **[MEDIUM] Missing timestamp update causes double-claimed rewards** — add_reward/remove_reward call update_reward but don't update farm.timestamp, causing same time_diff rewards to be counted twice on subsequent operations (Aries Market, Otter Audits)
- **[MEDIUM] Reward pools get less than promised share** — Compounding reduction of `pendingRewards[poolID]` means higher call frequency of performUpkeep() distributes fewer total rewards; 2.5%/day never reaches 100% distribution (Salty, C4)

### Maps to staking-007 (cross-function reentrancy)
- **[HIGH] Cross-contract reentrancy allows YIELD_TOKEN theft** — Single WithdrawalRequestManager serving multiple approved vaults enables cross-contract reentrancy; attacker drains YIELD_TOKENs from manager to their strategy, inflating balanceOf delta and minting excess shares (Notional/Exponent, Sherlock)

### Maps to staking-008 (emergency withdraw accounting)
- **[HIGH] Funds locked in TimeBasedCollateralPool** — Unit-based accounting with claims reducing total tokens causes units-per-token to inflate over time; eventually requires astronomical unit amounts to represent single tokens, locking funds permanently (Ampera, OpenZeppelin)

### New patterns not in existing bugs
- **[HIGH] Signature replay between stake/unstake/reward functions** — Same signature format `keccak256(abi.encodePacked(userWallet, rewardAmount, orderId))` used across SapienRewards and SapienStaking; staking signatures replayable to claim unauthorized rewards (Sapien, Quantstamp)
- **[HIGH] Stake boost inflation via repeated stake/unstake** — Unstake zeros current interval boost but not next interval's `stakeBoost[nextVTokenId]`; repeated stake/unstake inflates next interval's boost, enabling outsized reward claims with minimal final stake (Nayms, Quantstamp)
- **[HIGH] Voting with stale position after lock expiry** — No check that remaining lock period > epoch time allows voting after lock expires, then withdrawing, re-staking, and voting again in same epoch with same balance (MagicSea/MlumStaking, Sherlock)
- **[HIGH] stRWIP always minted 1:1 regardless of exchange rate** — Staking mints stRWIP 1:1 with RWIP but burning uses current exchange rate (>1:1 due to rewards); attacker loops stake->burnTicket->unstake to drain all staking rewards (RWIPStaking, Cantina)
- **[HIGH] Malicious staker forces validator withdrawals** — Stake 1 ETH to trigger distributeStakes filling a validator, then immediately unstake forcing a validator exit; repeatable with 64 ETH to force 2 exits per cycle, griefing genuine stakers (CasimirManager, Pashov)
- **[HIGH] BlockBeforeSend hook DoS on staking** — Cosmos tokenfactory denom creator sets BeforeSendHook to invalid address, causing all transfers to fail; depositing these tokens into validator rewards pool permanently blocks all staking operations (MANTRA Chain, C4)
- **[HIGH] Griefer resets reward multiplier via zero transfer** — Transferring 0 tokens to a user triggers `newPosition == prevPosition` condition, resetting their reward multiplier to 1; no cost to attacker, permanent damage to victim's rewards (SMRewardDistributor, Cantina)
- **[HIGH] Delayed exchange rate updates enable front-running** — Manual `updateExchangeRate()` for wrapped TAO allows front-running with wrap() at favorable rate then immediate unwrap request; changes plxTAO total supply making calculated rate stale, potentially leaving protocol in debt (wstTAO, Quantstamp)
- **[HIGH] Old stakers steal new stakers' deposits** — After validator registration and derivative minting, accumulated rewards per LP token include the ETH from new deposits; old staker with 4 ETH can claim all new deposits as "rewards" (StakingFundsVault, C4)
- **[MEDIUM] Inequitable reward distribution from dynamic available rewards** — massUpdatePools iterates pools sequentially, reducing availableRewards after each; pool ordering determines reward share, first pools get full allocation while later pools get remainder (ZLRewardsController, Spearbit)
