# AccessHunter — PreLiquidationFactory Analysis

## Tu Identidad
Eres el **AccessHunter** del equipo de bug hunting de morpho-pre-liquidation.
Tu especialidad: **Access control, missing modifiers, privilege escalation, role misconfig**

## Tu Objetivo
Analizar `PreLiquidationFactory` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/morpho/pre-liquidation/src/PreLiquidationFactory.sol`
**Dominio**: lending


```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.27;

import {IPreLiquidation, PreLiquidationParams} from "./interfaces/IPreLiquidation.sol";
import {IPreLiquidationFactory} from "./interfaces/IPreLiquidationFactory.sol";
import {IMorpho, Id} from "../lib/morpho-blue/src/interfaces/IMorpho.sol";

import {ErrorsLib} from "./libraries/ErrorsLib.sol";
import {EventsLib} from "./libraries/EventsLib.sol";

import {PreLiquidation} from "./PreLiquidation.sol";

/// @title PreLiquidationFactory
/// @author Morpho Labs
/// @custom:contact security@morpho.org
/// @notice A linear LIF and linear LCF pre-liquidation factory contract for Morpho.
contract PreLiquidationFactory is IPreLiquidationFactory {
    /* IMMUTABLE */

    /// @notice The address of the Morpho contract.
    IMorpho public immutable MORPHO;

    /* STORAGE */

    /// @notice Mapping which returns true if the address is a PreLiquidation contract created by this factory.
    mapping(address => bool) public isPreLiquidation;

    /* CONSTRUCTOR */

    /// @param morpho The address of the Morpho contract.
    constructor(address morpho) {
        require(morpho != address(0), ErrorsLib.ZeroAddress());

        MORPHO = IMorpho(morpho);
    }

    /* EXTERNAL */

    /// @notice Creates a PreLiquidation contract.
    /// @param id The Morpho market for PreLiquidations.
    /// @param preLiquidationParams The PreLiquidation params for the PreLiquidation contract.
    /// @dev Warning: This function will revert without data if the pre-liquidation already exists.
    function createPreLiquidation(Id id, PreLiquidationParams calldata preLiquidationParams)
        external
        returns (IPreLiquidation)
    {
        IPreLiquidation preLiquidation =
            IPreLiquidation(address(new PreLiquidation{salt: 0}(address(MORPHO), id, preLiquidationParams)));

        emit EventsLib.CreatePreLiquidation(address(preLiquidation), id, preLiquidationParams);

        isPreLiquidation[address(preLiquidation)] = true;

        return preLiquidation;
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre PreLiquidationFactory
Buscando 'PreLiquidationFactory' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (5ms)


### HIGH findings en dominio lending
Buscando 'PreLiquidationFactory createPreLiquidation' [SQLite FTS5] (dominio: lending)...
Sin resultados para los criterios dados. (4ms)

### Cross-domain HIGH relevantes
Buscando 'PreLiquidationFactory createPreLiquidation' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (1ms)

## Briefing del Dominio (lending)
### Briefing principal: lending

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Rounding dust (1 wei per operation) is normal in integer math -- allow tolerance of max(numPayments, numLoans) + 1
  ⚠ Mock oracles produce unrealistic AUM values -- always confirm on fork
  ⚠ Some protocols batch-accrue via 'touch()' -- verify it covers all paths
  ⚠ Open-term vs fixed-term loans have different accrual mechanics
  ⚠ Interest accrual over long periods can legitimately make positions unhealthy -- not a bug
  ⚠ Oracle price updates between check and execution create edge cases
  ⚠ Rounding can make unrealizedLosses slightly exceed AUM -- allow tolerance of numLoans + 1
  ⚠ Mock liquidation tests often miss the real oracle impact
  ⚠ Partial liquidity scenarios are complex but not bugs -- check the partialLiquidity flag logic
  ⚠ Queue processing in batches may leave dust -- tolerance needed
  ⚠ Rounding tolerance needed: max(numPayments, numLoans) + 1 for interest aggregates
  ⚠ Open-term and fixed-term have different aggregate tracking -- check both

## CHECKLIST DE INVARIANTES
When you open a new lending protocol's code, check these in order:
### Architecture (5 min)
- [ ] Map the contract hierarchy: Vault/Pool -> LoanManager -> Loan
- [ ] Identify: where is `totalAssets` computed? Is it `balanceOf` or internal tracking?
- [ ] Identify: ERC4626 vault? Custom share math?
- [ ] Identify: oracle source and type (Chainlink, TWAP, custom)
- [ ] Identify: interest rate model (linear, kinked, adaptive)
- [ ] Identify: withdrawal mechanism (instant, queued/cyclical, timelock)
### Interest Accrual (10 min)
- [ ] Is `accrueInterest()` called FIRST in every state-changing function?
- [ ] Does the interest accumulator only increase? (INV-INT-005)
- [ ] Is there a MAX interest rate cap? (INV-INT-004)
- [ ] Can `lastAccrualTimestamp` ever be in the future? (INV-INT-002)
- [ ] Fixed-term: is `domainEnd` == earliest payment due date? (INV-LOAN-014)
- [ ] Open-term: is `payment.startDate` == `dateFunded` or `datePaid`? (INV-LOAN-034)
### Share/Exchange Rate (10 min)
- [ ] `sum(balanceOf) == totalSupply`? (INV-POOL-007)
- [ ] `totalAssets >= totalSupply` (exchange rate >= 1)? (INV-POOL-003)
- [ ] First depositor inflation protection? (dead shares, virtual offset)
- [ ] `convertToShares` and `convertToAssets` are inverse? (INV-POOL-004, INV-POOL-005)

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Access control) es relevante
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
ID prefix para este componente: `PLF` (ej: PLF-01, PLF-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_PreLiquidationFactory_AccessHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: PLF-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "PLF-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```



## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
