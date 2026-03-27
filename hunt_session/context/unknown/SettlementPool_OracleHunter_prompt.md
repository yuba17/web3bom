# OracleHunter — SettlementPool Analysis

## Tu Identidad
Eres el **OracleHunter** del equipo de bug hunting de variational.
Tu especialidad: **Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies**

## Tu Objetivo
Analizar `SettlementPool` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `variational-audit/src/SettlementPool.sol`
**Dominio**: reentrancy


## Asset Flow Map
### Money IN (deposits/receives)
- L105 _depositUSDCOnBehalf(): try _usdc().transferFrom(sender, address(this), amount) {

### Money OUT (withdrawals/sends)
- L255 withdrawFees(): try _usdc().transfer(requestor, amountRequested) {
- L275 _withdrawUSDCOnBehalf(): try _usdc().transfer(requestor, amountRequested) {

### Balance Reads (manipulation vectors)
- L79 _totalBalance(): return _usdc().balanceOf(address(this));
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.2;

import "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import "lib/openzeppelin-contracts/contracts/security/ReentrancyGuard.sol";
import "./interfaces/ISettlementPool.sol";
import "./interfaces/ISettlementPoolDeployer.sol";
import "./interfaces/ISettlementPoolFactory.sol";
import "./interfaces/IOracle.sol";
import "./library/SettlementPools.sol";
import {console} from "../lib/forge-std/src/console.sol";

contract SettlementPool is ISettlementPool, ReentrancyGuard {
    /// @inheritdoc ISettlementPoolMembers
    address public override factory;
    /// @inheritdoc ISettlementPoolMembers
    address public override creatorAddress;
    /// @inheritdoc ISettlementPoolMembers
    uint128 public override poolUuid;

    // TODO: docs
    uint256 private randNonce = 0;
    mapping(address => bool) public otherAddresses;
    mapping(uint128 => bool) public transfers_processed;

    modifier onlyParties() {
        require(
            msg.sender == creatorAddress || otherAddresses[msg.sender],
            "SettlementPool: Unauthorized."
        );
        _;
    }

    modifier onlyFactoryOwner() {
        require(
            msg.sender == ISettlementPoolFactory(factory).getOwner(),
            "SettlementPool: Unauthorized."
        );
        _;
    }

    modifier onlyOracle() {
        require(
            msg.sender == address(_oracle()),
            "SettlementPool: Unauthorized."
        );
        _;
    }


    /// @notice Initialize the pool with its data
    function initialize(
        address _creatorAddress,
        address _factory,
        address[] calldata _otherAddresses,
        uint128 _poolUuid
    ) external nonReentrant  {
        require(msg.sender != address(0), "SettlementPool: Sender must be non-zero");
        require(msg.sender == address(ISettlementPoolFactory(_factory)), "SettlementPool: Only factory can initialize");
        require(factory == address(0), "SettlementPool: can only initialize once");
        require(_creatorAddress != address(0), "SettlementPool: Creator address must be non-zero");

        // Initialize state
        creatorAddress = _creatorAddress;
        poolUuid = _poolUuid;
        factory = _factory;

        for (uint256 i = 0; i < _otherAddresses.length; i++) {
            require(_otherAddresses[i] != address(0), "SettlementPool: Other address must be non-zero");
            otherAddresses[_otherAddresses[i]] = true;
        }
    }


    /// @dev Get the pool's balance of USDC
    /// @dev This function could be further optimized
    /// See https://github.com/Uniswap/v3-core/blob/main/contracts/UniswapV3Pool.sol#L140
    function _totalBalance() private view returns (uint256) {
        return _usdc().balanceOf(address(this));
    }

    function _oracle() private view returns (IOracle) {
        return ISettlementPoolFactory(factory).oracle();
    }

    function _usdc() private view returns (IERC20) {
        return ISettlementPoolFactory(factory).usdcAddress();
    }

    function _depositUSDCOnBehalf(
        address sender,
        uint256 amount,
        uint128 transferUuid,
        bool emitDepositedEvent
    ) private {
        require(amount > 0, "SettlementPool: Cannot deposit 0 USDC.");
        require(transfers_processed[transferUuid] == false, "this transfer has already been processed");
        uint256 allowance = _usdc().allowance(sender, address(this));
        require(
            allowance >= amount,
            "SettlementPool: You must approve the contract to transfer at least the amount you are trying to deposit."
        );

        // todo: We first should make sure that there is not negative equity in the pool before incrementing tokens owed
        try _usdc().transferFrom(sender, address(this), amount) {
            if (transferUuid != 0) {
                transfers_processed[transferUuid] = true;
            }
            if (emitDepositedEvent) {
                emit Deposited(address(this), sender, amount, transferUuid);
            }
        } catch {
            revert("SettlementPool: Could not deposit USDC.");
        }
    }

    /// @inheritdoc ISettlementPool
    function checkOtherAddress(address addr) external view override returns (bool) {
        return otherAddresses[addr];
    }

    function batchDepositUSDCAtomic(
        address creatorPartyAddress,
        uint256 creatorPartyAmountRequested,
        SettlementPools.AtomicDepositBatchItem[] calldata items
    ) external nonReentrant onlyOracle {
        for (uint i = 0; i < items.length; i++) {
            require(creatorPartyAmountRequested > 0 || items[i].otherPartyAmountRequested > 0, "SettlementPool: when creator amount is 0, all other amounts must be > 0");
            uint128 transferUuid = items[i].parentQuoteUuid;
            if (creatorPartyAmountRequested > 0) {
                _depositUSDCOnBehalf(
                    creatorPartyAddress,
                    creatorPartyAmountRequested,
                    transferUuid,
                    false /* emitDepositedEvent */
                );
                // we reset this to 0 now in case there is also a deposit required for the other company. We only
                // need to check dupes once per atomic deposit so by resetting this to 0 here the second deposit will
                // skip the dupe check
                transferUuid = 0;
            }
            if (items[i].otherPartyAmountRequested > 0) {
                _depositUSDCOnBehalf(
                    items[i].otherPartyAddress,
                    items[i].otherPartyAmountRequested,
                    transferUuid,
                    false /* emitDepositedEvent */
                );
            }
        }
        emit BatchDepositedAtomic(
            address(this),
            creatorPartyAddress,
            creatorPartyAmountRequested,
            items
        );
    }

    function depositUSDCAtomic(
        address partyOneAddress,
        address partyTwoAddress,
        uint256 partyOneAmountRequested,
        uint256 partyTwoAmountRequested,
        uint128 rfqUuid,
        uint128 parentQuoteUuid
    ) external nonReentrant onlyOracle {
        // if only the first party requested deposit we skip the rest and simply emit the event because
        // we already completed the single party transfer in the calling function
        if (partyOneAmountRequested > 0 && partyTwoAmountRequested == 0) {
            emit DepositedAtomic(
                address(this),
                partyOneAddress,
                partyTwoAddress,
                partyOneAmountRequested,
                partyTwoAmountRequested,
                rfqUuid,
                parentQuoteUuid
            );
            return;
        }
        require(parentQuoteUuid != 0, "SettlementPool: parentQuoteUuid must be non-zero");
        require(
            partyOneAmountRequested > 0 || partyTwoAmountRequested > 0,
            "one of the two deposit amounts must be non-zero"
        );
        uint128 transferUuid = parentQuoteUuid;
        if (partyOneAmountRequested > 0) {
            _depositUSDCOnBehalf(
                partyOneAddress,
                partyOneAmountRequested,
                transferUuid,
                false /* emitDepositedEvent */
            );
            // we reset this to 0 now in case there is also a deposit required for the other company. We only
            // need to check dupes once per atomic deposit so by resetting this to 0 here the second deposit will
            // skip the dupe check
            transferUuid = 0;
        }
        if (partyTwoAmountRequested > 0) {
            _depositUSDCOnBehalf(
                partyTwoAddress,
                partyTwoAmountRequested,
                transferUuid,
                false /* emitDepositedEvent */
            );
        }
        emit DepositedAtomic(
            address(this),
            partyOneAddress,
            partyTwoAddress,
            partyOneAmountRequested,
            partyTwoAmountRequested,
            rfqUuid,
            parentQuoteUuid
        );
    }

    // depositUSDC deposits USDC tokens to the settlement pool on behalf of creator or one of the other parties
    // TODO: here and below document check, effects, interact patter in each key function
    function depositUSDC(
        uint256 amount,
        uint128 transferUuid
    ) external nonReentrant onlyParties {
        require(transferUuid != 0, "SettlementPool: transferUuid must be non-zero");
        _depositUSDCOnBehalf(
            msg.sender,
            amount,
            transferUuid,
            true /* emitDepositedEvent */
        );
    }

    function depositUSDCOnBehalfOfParty(
        address sender,
        uint256 amount,
        uint128 transferUuid
    ) external nonReentrant onlyOracle {
        require(transferUuid != 0, "SettlementPool: transferUuid must be non-zero");
        _depositUSDCOnBehalf(
            sender,
            amount,
            transferUuid,
            true /* emitDepositedEvent */
        );
    }

    function withdrawFees(
        address requestor,
        uint256 amountRequested,
        uint128 fees_batch_id
    ) external nonReentrant onlyOracle {
        require(amountRequested > 0, "SettlementPool: Cannot withdraw 0 USDC.");
        require(fees_batch_id != 0, "must provide non-zero fees_batch_id");
        require(transfers_processed[fees_batch_id] == false, "this fees batch has already been processed");
        try _usdc().transfer(requestor, amountRequested) {
            transfers_processed[fees_batch_id] = true;
        } catch {
            revert("SettlementPool: Could not withdraw USDC.");
        }
    }

    function _withdrawUSDCOnBehalf(
        address requestor,
        uint256 amountRequested,
        uint128 transferUuid,
        bool emitDepositedEvent
    ) private {
        require(amountRequested > 0, "SettlementPool: Cannot withdraw 0 USDC.");
        require(transferUuid != 0, "must provide non-zero transferUuid");
        require(
            requestor == creatorAddress || otherAddresses[requestor] == true,
            "requestor must be one of creatorCompany or otherCompany"
        );
        require(transfers_processed[transferUuid] == false, "this transfer has already been processed");
        try _usdc().transfer(requestor, amountRequested) {
            transfers_processed[transferUuid] = true;
            if (emitDepositedEvent) {
                emit Withdrawn(address(this), requestor, amountRequested, transferUuid);
            }
        } catch {
            revert("SettlementPool: Could not withdraw USDC.");
        }
    }

    function depositUSDCNoEvent(
        address sender,
        uint256 amount,
        uint128 transferUuid
    ) external nonReentrant onlyOracle {
        _depositUSDCOnBehalf(
            sender,
            amount,
            transferUuid,
            false /* emitDepositedEvent */
        );
    }

    function withdrawUSDCNoEvent(
        address requestor,
        uint256 amountRequested,
        uint128 transferUuid
    ) external nonReentrant onlyOracle {
        _withdrawUSDCOnBehalf(
            requestor,
            amountRequested,
            transferUuid,
            false /* emit_event */
        );
    }

    function withdrawUSDC(
        address requestor,
        uint256 amountRequested,
        uint128 transferUuid
    ) external nonReentrant onlyOracle {
        _withdrawUSDCOnBehalf(
            requestor,
            amountRequested,
            transferUuid,
            true /* emit_event */
        );
    }

    function addOtherParty(address otherAddress) external nonReentrant onlyOracle {
        require(
            otherAddresses[otherAddress] == false,
            "SettlementPool: the given address is already a party in the pool"
        );
        otherAddresses[otherAddress] = true;
        emit OtherPartyAdded(address(this), otherAddress);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre SettlementPool
Buscando 'SettlementPool' [SQLite FTS5] (dominio: general)...

Top 2 findings relevantes: (1ms)

 1. [LOW] [I-04] Not used event can be removed — Cadmos
 2. [LOW] [I-03] Check for zero balance in `cancelDeposit` — Cadmos

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: SettlementPool | Dominio: general
Los siguientes 2 findings de protocolos similares son relevantes:

1. [LOW] [I-04] Not used event can be removed (Cadmos)
   The `ForcedTransfer` event in `SettlementPool` is not used and can be removed....

2. [LOW] [I-03] Check for zero balance in `cancelDeposit` (Cadmos)
   The `cancelDeposit` method in `SettlementPool` is missing a check if the caller has more than zero balance....

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio reentrancy
Buscando 'SettlementPool _totalBalance _oracle _depositUSDCOnBehalf checkOtherAddress' [SQLite FTS5] (dominio: reentrancy)...
Top 6 findings relevantes: (8ms)
 1. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amoun — Kinetiq_2025-02-26
 2. [HIGH] L2ContractMigrationFacet doesn't increase total Stalk and Roots — Beanstalk: The Finale
 3. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken  — Astera
 4. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken  — Cod3x lend
 5. [HIGH] [C-02] Pending stake not accounted for in liquidity calculations — Coinflip_2025-02-19
 6. [HIGH] Incorrect `pricePerShare` calculation on zero totalSupply — Umami
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: SettlementPool _totalBalance _oracle _depositUSDCOnBehalf checkOtherAddress | Dominio: reentrancy
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amount (Kinetiq_2025-02-26)
## Severity
**Impact:** High
**Likelihood:** Medium
## Description
`OracleManager::generatePerformance` is supposed to be called once every hour ...
2. [HIGH] L2ContractMigrationFacet doesn't increase total Stalk and Roots (Beanstalk: The Finale)
   ## Summary
L2ContractMigrationFacet is used to migrate deposits owned by smart contracts.
Problem is that it increases balance of Stalk and Roots as...
3. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken transfers in- (Astera)
   ## Security Issue: Reward Distribution Index Overflow
**Severity:** High Risk  
**Context:** `RewardsDistributor.sol#L501`  
## Description
The rewa...
4. [HIGH] Index can reach type(uint104).max when asset totalSupply is dust and DoS aToken transfers inDefinetely (Cod3x lend)
   **Severity:** High Risk  
**Context:** RewardsDistributor.sol#L501  
**Description:**  
The reward formula in Reward Distributors (RewardsDistribut...
5. [HIGH] [C-02] Pending stake not accounted for in liquidity calculations (Coinflip_2025-02-19)
   ## Severity
**Impact:** High
**Likelihood:** High
## Description
The `Staking` contract uses `IERC20(token).balanceOf(address(this))` to determine...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'SettlementPool _totalBalance _oracle _depositUSDCOnBehalf ch' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (9ms)
 1. [HIGH] [H-03] Storage root assignment missing in tree finalization — Initia
 2. [HIGH] [H-04] `ReportSlashingEvent` reverts if outdated balance is below slashing amoun — Kinetiq_2025-02-26
 3. [HIGH] [H-01] UniswapConfig getters return wrong token config if token config does not  — Based Loans
 4. [HIGH] L2ContractMigrationFa

## Briefing del Dominio (reentrancy)
### Briefing principal: reentrancy

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ nonReentrant no protege contra cross-function reentrancy si las dos funciones no comparten el lock
  ⚠ El patrón mutex (locked = true) solo protege el contrato actual, no contratos hermanos
  ⚠ Los callbacks ERC721/ERC1155 pueden disparar reentrancy en funciones que parecen seguras
  ⚠ Uniswap V3 usa un 'locked' flag global — esto protege contra cross-function reentrancy dentro del pool
  ⚠ Los protocolos multi-contract con callbacks entre contratos tienen la mayor superficie de cross-function reentrancy
  ⚠ Los delegates en Gnosis Safe pueden explotar cross-function reentrancy entre módulos
  ⚠ Las read-only reentrancy no modifican estado → nonReentrant no ayuda en el contrato víctima
  ⚠ La defensa está del lado del protocolo que LEE el precio, no del protocolo de AMM
  ⚠ Balancer V2 tuvo exactamente este bug — se arregló exponiendo reentrancyGuardEntered()
  ⚠ transferFrom (sin 'safe') no llama el callback — más seguro contra reentrancy pero menos seguro para receptores de contrato que no saben recibir NFTs
  ⚠ ERC1155 tiene el mismo patrón con onERC1155Received y onERC1155BatchReceived
  ⚠ El TWAP no es afectado por flash loans — el precio solo se actualiza al final del bloque


### Grep targets adicionales (dex)
```
getReserves
reserve0
reserve1
sqrtPriceX96
slot0
liquidity
tickCurrent
amountOutMin
minAmountOut
deadline
block.timestamp

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Price manipulation) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `SP` (ej: SP-01, SP-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_SettlementPool_OracleHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: SP-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "SP-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Flash Loan Hypothesis (OBLIGATORIO — responde para CADA función que modifica estado)
Después de tu análisis libre, pasa por estas 12 preguntas para cada función relevante:
1. ¿Lee estado manipulable? (getReserves, slot0, balanceOf, get_virtual_price)
2. ¿Ese estado afecta movimiento de fondos?
3. ¿Se puede leer y consumir en la misma tx? (sin delays/timelocks)
4. ¿Hay verificación post-acción? (patrón FREI-PI)
5. ¿Tiene reentrancy guard?
6. ¿Si es callback, verifica initiator? (no solo msg.sender == pool)
7. ¿Usa spot price (manipulable) o TWAP (más seguro)?
8. ¿Reward/share se calcula por balance instantáneo?
9. ¿Hay cap/threshold cruzable atómicamente? (pasar de "sano" a "liquidable" en 1 tx)
10. ¿Permite self-liquidation con bonus > flash fee?
11. ¿Fee rounding a zero con montos pequeños?
12. ¿Checkpoint usa storage (persistente) o memory (se pierde)?

>80% de los exploits flash loan siguen: FLASH → MANIPULATE STATE → EXTRACT VALUE → RESTORE → REPAY.
Si una función responde "sí" a las preguntas 1+2+3, es un candidato fuerte.

## Oracle Deep Check (OBLIGATORIO — para cada fuente de precio)
Para CADA llamada a latestRoundData() o equivalente:
1. ¿Se verifica updatedAt contra un heartbeat? ¿El heartbeat es ESPECÍFICO por feed o genérico?
2. ¿Se chequea answeredInRound >= roundId?
3. ¿Se chequea price > 0?
4. ¿Hay check de L2 sequencer down? (Arbitrum/Optimism/Base: sequencerUptimeFeed)
5. ¿Existe minAnswer/maxAnswer que clampea el precio en flash crashes?
6. ¿El oracle puede ser sandwicheado? (front-run de oracle update para explotar el vault)

Oracle-Liquidity Mismatch (cmichel/Rari): ¿cuánto capital se necesita para manipular el oracle vs cuánto se puede extraer? Si manipulación < extracción → explotable.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
