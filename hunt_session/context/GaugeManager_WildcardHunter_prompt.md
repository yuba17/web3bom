# WildcardHunter — GaugeManager Analysis

## Tu Identidad
Eres el **WildcardHunter** del equipo de bug hunting de revert-lend.
Tu especialidad: **Novel bugs, unconventional vectors, assumption violations, composability risks**

## Tu Objetivo
Analizar `GaugeManager` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/revert-lend/src/GaugeManager.sol`
**Dominio**: staking

```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import "v3-core/interfaces/IUniswapV3Pool.sol";
import "v3-periphery/interfaces/INonfungiblePositionManager.sol";

import "./interfaces/IVault.sol";
import "./interfaces/IGaugeManager.sol";
import "./interfaces/aerodrome/IAerodromeSlipstreamFactory.sol";
import "./interfaces/aerodrome/IAerodromeSlipstreamPool.sol";
import "./interfaces/aerodrome/IGauge.sol";
import "./utils/Swapper.sol";

/// @notice Gauge helper for vaulted positions.
contract GaugeManager is Ownable2Step, ReentrancyGuard, IERC721Receiver, Swapper, IGaugeManager {
    using SafeERC20 for IERC20;

    uint64 public constant MAX_REWARD_X64 = 368_934_881_474_191_032; // floor(Q64 / 50)
    // Reward compounding validates each fixed route hop against both TWAP deviation and a minimum output bound
    // derived from the current pool price before executing the swap.
    uint32 private constant REWARD_TWAP_SECONDS = 60;
    uint16 private constant REWARD_MAX_TWAP_TICK_DIFFERENCE = 200;
    uint64 private constant REWARD_MAX_PRICE_DIFFERENCE_X64 = 368_934_881_474_191_032; // floor(Q64 / 50)

    IERC20 public immutable aeroToken;
    IVault public immutable vault;
    address public override withdrawer;
    uint64 public totalRewardX64 = MAX_REWARD_X64; // 2%

    mapping(address => address) public override poolToGauge;
    mapping(uint256 => address) public override tokenIdToGauge;
    mapping(address => address) public override rewardBasePools;

    struct CompoundState {
        address gauge;
        address owner;
        address token0;
        address token1;
        IUniswapV3Pool positionPool;
        uint256 aeroAmount;
        uint256 spentAero;
        uint256 amount0Out;
        uint256 amount1Out;
        uint256 maxAddAmount0;
        uint256 maxAddAmount1;
        uint256 amountAdded0;
        uint256 amountAdded1;
        uint256 rewardAmount0;
        uint256 rewardAmount1;
    }

    constructor(
        INonfungiblePositionManager _npm,
        IERC20 _aeroToken,
        IVault _vault,
        address _universalRouter,
        address _zeroxAllowanceHolder
    ) Swapper(_npm, _universalRouter, _zeroxAllowanceHolder) {
        if (address(_aeroToken) == address(0) || address(_vault) == address(0)) {
            revert InvalidConfig();
        }

        aeroToken = _aeroToken;
        vault = _vault;
        withdrawer = msg.sender;

        emit WithdrawerChanged(msg.sender);
    }

    function setGauge(address pool, address gauge) external override onlyOwner {
        if (pool == address(0) || gauge == address(0)) {
            revert InvalidConfig();
        }

        (bool success, bytes memory data) =
            pool.staticcall(abi.encodeWithSelector(IAerodromeSlipstreamPool.gauge.selector));
        if (!success || data.length < 32 || abi.decode(data, (address)) != gauge) {
            revert InvalidPool();
        }

        poolToGauge[pool] = gauge;
        emit GaugeSet(pool, gauge);
    }

    function setRewardBasePool(address baseToken, address pool) external override onlyOwner {
        if (baseToken == address(0) || baseToken == address(aeroToken)) {
            revert InvalidConfig();
        }

        if (pool == address(0)) {
            delete rewardBasePools[baseToken];
            emit RewardBasePoolSet(baseToken, address(0));
            return;
        }

        IAerodromeSlipstreamPool slipstreamPool = IAerodromeSlipstreamPool(pool);
        address token0 = slipstreamPool.token0();
        address token1 = slipstreamPool.token1();
        if (!(token0 == address(aeroToken) && token1 == baseToken || token0 == baseToken && token1 == address(aeroToken)))
        {
            revert InvalidPool();
        }

        address resolved = IAerodromeSlipstreamFactory(factory).getPool(token0, token1, slipstreamPool.tickSpacing());
        if (resolved != pool) {
            revert InvalidPool();
        }

        rewardBasePools[baseToken] = pool;
        emit RewardBasePoolSet(baseToken, pool);
    }

    function setWithdrawer(address _withdrawer) external override onlyOwner {
        if (_withdrawer == address(0)) {
            revert InvalidConfig();
        }
        withdrawer = _withdrawer;
        emit WithdrawerChanged(_withdrawer);
    }

    function withdrawBalances(address[] calldata tokens, address to) external override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 i;
        uint256 count = tokens.length;
        address token;
        uint256 balance;
        for (; i < count; ++i) {
            token = tokens[i];
            balance = IERC20(token).balanceOf(address(this));
            if (balance != 0) {
                IERC20(token).safeTransfer(to, balance);
            }
        }
    }

    function withdrawETH(address to) external override {
        if (msg.sender != withdrawer) {
            revert Unauthorized();
        }

        uint256 balance = address(this).balance;
        if (balance != 0) {
            (bool sent,) = to.call{value: balance}("");
            if (!sent) {
                revert EtherSendFailed();
            }
        }
    }

    function stakePosition(uint256 tokenId) external override nonReentrant {
        _requireVaultCaller();
        if (tokenIdToGauge[tokenId] != address(0)) {
            revert InvalidConfig();
        }

        address owner = vault.ownerOf(tokenId);
        if (owner == address(0)) {
            revert Unauthorized();
        }

        if (nonfungiblePositionManager.ownerOf(tokenId) != address(vault)) {
            revert Unauthorized();
        }

        (,, address token0, address token1, uint24 feeOrTickSpacing,,,,,,,) =
            nonfungiblePositionManager.positions(tokenId);

        IUniswapV3Pool pool = _getPool(token0, token1, feeOrTickSpacing);
        address gauge = poolToGauge[address(pool)];
        if (gauge == address(0)) {
            revert NotConfigured();
        }

        uint256 token0Before = IERC20(token0).balanceOf(address(this));
        uint256 token1Before = IERC20(token1).balanceOf(address(this));
        nonfungiblePositionManager.safeTransferFrom(address(vault), address(this), tokenId);
        nonfungiblePositionManager.approve(gauge, tokenId);
        IGauge(gauge).deposit(tokenId);
        // Slipstream CLGauge.deposit triggers NPM.collect to msg.sender, so any pre-stake accrued token0/token1
        // fees are realized during staking and forwarded here to the position owner.
        _sendDepositDeltas(token0, token1, owner, token0Before, token1Before);

        // NOTE FOR AUDITS:
        // We intentionally do not enforce `ownerOf(tokenId) == gauge` post-deposit here.
        // Some gauge implementations may custody via intermediate contracts/wrappers while still exposing
        // the configured gauge as the canonical integration endpoint for getReward/withdraw.
        // This is an accepted trust-boundary assumption on configured gauges.
        // Vault-side `_stake()` still enforces that custody leaves the vault to block no-op managers.
        tokenIdToGauge[tokenId] = gauge;
        emit PositionStaked(tokenId, owner, gauge);
    }

    function unstakePosition(uint256 tokenId) external override nonReentrant {
        _requireVaultCaller();

        bool wasStaked = _unstakePosition(tokenId);
        if (!wasStaked) {
            revert NotStaked();
        }
    }

    function unstakeIfStaked(uint256 tokenId) external override nonReentrant returns (bool wasStaked) {
        _requireVaultCaller();
        return _unstakePosition(tokenId);
    }

    function _unstakePosition(uint256 tokenId) inter
```

## Contexto de Solodit (bugs similares en protocolos similares)
Buscando 'staking' [SQLite FTS5] (dominio: staking)...

Top 5 findings relevantes: (16ms)

 1. [LOW] StakedSui Object Merge — Volo
 2. [LOW] Limit Bypass via stake_coins — Tortuga
 3. [LOW] Limit Bypass Through Stake Coins Invocation — Tortugal TIP
 4. [LOW] Incorrect Removal Of Pending Deposit Stake — Hubble Farms
 5. [LOW] Validator deactivation / reactivation does not consider next_delta_stake during  — Monad

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: GaugeManager | Dominio: staking
Los siguientes 5 findings de protocolos similares son relevantes:

1. [LOW] StakedSui Object Merge (Volo)
   ## Staking Pool Functionality

## Description
`staking_pool::join_staked_sui` facilitates the merging of Staked Sui objects when their metadata matche...

2. [LOW] Limit Bypass via stake_coins (Tortuga)
   ## Stake Router Overview

The `stake_router` provides two entrypoints to stake coins:

- **`stake_router::stake_coins`**: A permissionless staking end...

3. [LOW] Limit Bypass Through Stake Coins Invocation (Tortugal TIP)
   ## Stake Router Overview

The `stake_router` provides two entry points to stake coins:

- **`stake_router::stake_coins`**  
  A permissionless staking...

4. [LOW] Incorrect Removal Of Pending Deposit Stake (Hubble Farms)
   ## Stake Operations Overview

In `stake_operations`, `convert_stake_to_amount` converts a stake (represented as a decimal) into an equivalent amount o...

5. [LOW] Validator deactivation / reactivation does not consider next_delta_stake during the boundary pe- (Monad)
   ## Risk Assessment

**Severity:** Low Risk

**Context:** No context files were provided by the reviewer.

## Description

Issue found in commit hash `...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


## Briefing del Dominio (staking)
## PATRONES CONOCIDOS (busca primero estos)
### 1.1 Reward-Per-Share Rounding Exploitation
### 1.2 Stake Just Before Distribution (Timing Attack)
### 1.3 Reward Donation Inflation
### 1.4 Double-Claim Prevention Failure
### 1.5 Cooldown / Unstake Bypass
### 1.6 Reward Token Exhaustion / Insolvency
### 1.9 ERC721 Position Staking (Gauge Style)
### 2.1 Cross-Function Reentrancy in Staking
### 2.2 Emergency Withdraw Accounting Break

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ 1 wei rounding per operation is generally not exploitable unless repeatable cheaply
  ⚠ Penalty mechanisms may intentionally reduce effective rewards — not a rounding bug
  ⚠ Rebasing staking tokens naturally cause accumulator drift
  ⚠ Contracts without lock periods are vulnerable by design — confirm this is unintentional
  ⚠ Linear distribution (Synthetix rewardsDuration) mitigates single-block extraction but not multi-block flash loans
  ⚠ Private mempool (Flashbots) reduces but does not eliminate risk
  ⚠ Protocols with same staking and reward token are more vulnerable
  ⚠ Some protocols intentionally accept donations as extra yield — verify design intent
  ⚠ Virtual shares offset mitigates share-price inflation but not reward accumulator inflation
  ⚠ Standard Synthetix pattern is safe IF modifiers are applied correctly
  ⚠ ERC-20 transfers (no hooks) do not enable reentrancy — only flag for ERC-777 or native ETH
  ⚠ Leftover rewards from previous epoch rolled into new epoch is expected in some designs

## CHECKLIST DE INVARIANTES
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

## GREP TARGETS
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

## INCIDENTES REALES (protocolos afectados)
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

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Novel bugs) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `GM` (ej: GM-01, GM-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_GaugeManager_WildcardHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: GM-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "GM-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
