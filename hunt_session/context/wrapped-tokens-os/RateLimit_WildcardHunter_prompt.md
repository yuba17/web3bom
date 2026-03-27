# WildcardHunter — RateLimit Analysis

## Tu Identidad
Eres el **WildcardHunter** del equipo de bug hunting de wrapped-tokens-os.
Tu especialidad: **Novel bugs, unconventional vectors, assumption violations, composability risks**

## Tu Objetivo
Analizar `RateLimit` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/wrapped-tokens-os/contracts/wrapped-tokens/RateLimit.sol`
**Dominio**: access


```solidity
/**
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022 Coinbase, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

pragma solidity 0.8.6;

import { Ownable } from "@openzeppelin4.2.0/contracts/access/Ownable.sol";

/**
 * @title RateLimit
 * @dev Rate limiting contract for function calls
 */
contract RateLimit is Ownable {
    /**
     * @dev Mapping denoting caller addresses
     * @return Boolean denoting whether the given address is a caller
     */
    mapping(address => bool) public callers;

    /**
     * @dev Mapping denoting caller address rate limit intervals
     * @return A time in seconds representing the duration of the given callers interval
     */
    mapping(address => uint256) public intervals;

    /**
     * @dev Mapping denoting when a given caller's allowance was last updated
     * @return The time in seconds since a given caller's allowance was last updated
     */
    mapping(address => uint256) public allowancesLastSet;

    /**
     * @dev Mapping denoting a given caller's maximum allowance
     * @return The maximum allowance of a given caller
     */
    mapping(address => uint256) public maxAllowances;

    /**
     * @dev Mapping denoting a given caller's stored allowance
     * @return The stored allowance of a given caller
     */
    mapping(address => uint256) public allowances;

    /**
     * @notice Emitted on caller configuration
     * @param caller The address configured to make rate limited calls
     * @param amount The maximum allowance for the given caller
     * @param interval The amount of time in seconds before a caller's allowance is replenished
     */
    event CallerConfigured(
        address indexed caller,
        uint256 amount,
        uint256 interval
    );

    /**
     * @notice Emitted on caller removal
     * @param caller The address of the caller being removed
     */
    event CallerRemoved(address indexed caller);

    /**
     * @notice Emitted on caller allowance replenishment
     * @param caller The address of the caller whose allowance is being replenished
     * @param allowance The current allowance for the given caller post replenishment
     * @param amountReplenished The allowance amount that was replenished for the given caller
     */
    event AllowanceReplenished(
        address indexed caller,
        uint256 allowance,
        uint256 amountReplenished
    );

    /**
     * @dev Throws if called by any account other than a caller
     * @dev Rate limited functionality in inheriting contracts must have the only caller modifier
     */
    modifier onlyCallers() {
        require(callers[msg.sender], "RateLimit: caller is not whitelisted");
        _;
    }

    /**
     * @dev Function to add/update a new caller. Also updates allowancesLastSet for that caller.
     * @param caller The address of the caller
     * @param amount The call amount allowed for the caller for a given interval
     * @param interval The interval for a given caller
     */
    function configureCaller(
        address caller,
        uint256 amount,
        uint256 interval
    ) external onlyOwner {
        require(caller != address(0), "RateLimit: caller is the zero address");
        require(amount > 0, "RateLimit: amount is zero");
        require(interval > 0, "RateLimit: interval is zero");
        callers[caller] = true;
        maxAllowances[caller] = allowances[caller] = amount;
        allowancesLastSet[caller] = block.timestamp;
        intervals[caller] = interval;
        emit CallerConfigured(caller, amount, interval);
    }

    /**
     * @dev Function to remove a caller.
     * @param caller The address of the caller
     */
    function removeCaller(address caller) external onlyOwner {
        delete callers[caller];
        delete intervals[caller];
        delete allowancesLastSet[caller];
        delete maxAllowances[caller];
        delete allowances[caller];
        emit CallerRemoved(caller);
    }

    /**
     * @dev Helper function to calculate the estimated allowance given caller address
     * @param caller The address whose call allowance is being estimated
     * @return The allowance of the given caller if their allowance were to be replenished
     */
    function estimatedAllowance(address caller)
        external
        view
        returns (uint256)
    {
        return allowances[caller] + _getReplenishAmount(caller);
    }

    /**
     * @dev Get the current caller allowance for an account
     * @param caller The address of the caller
     * @return The allowance of the given caller post replenishment
     */
    function currentAllowance(address caller) public returns (uint256) {
        _replenishAllowance(caller);
        return allowances[caller];
    }

    /**
     * @dev Helper function to replenish a caller's allowance over the interval in proportion to time elapsed, up to their maximum allowance
     * @param caller The address whose allowance is being updated
     */
    function _replenishAllowance(address caller) internal {
        if (allowances[caller] == maxAllowances[caller]) {
            return;
        }
        uint256 amountToReplenish = _getReplenishAmount(caller);
        if (amountToReplenish == 0) {
            return;
        }

        allowances[caller] = allowances[caller] + amountToReplenish;
        allowancesLastSet[caller] = block.timestamp;
        emit AllowanceReplenished(
            caller,
            allowances[caller],
            amountToReplenish
        );
    }

    /**
     * @dev Helper function to calculate the replenishment amount
     * @param caller The address whose allowance is being estimated
     * @return The allowance amount to be replenished for the given caller
     */
    function _getReplenishAmount(address caller)
        internal
        view
        returns (uint256)
    {
        uint256 secondsSinceAllowanceSet = block.timestamp -
            allowancesLastSet[caller];

        uint256 amountToReplenish = (secondsSinceAllowanceSet *
            maxAllowances[caller]) / intervals[caller];
        uint256 allowanceAfterReplenish = allowances[caller] +
            amountToReplenish;

        if (allowanceAfterReplenish > maxAllowances[caller]) {
            amountToReplenish = maxAllowances[caller] - allowances[caller];
        }
        return amountToReplenish;
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre RateLimit
Buscando 'RateLimit' [SQLite FTS5] (dominio: general)...

Top 5 findings relevantes: (14ms)

 1. [GAS] [G-02] Lots of duplicated code between `RateLimited.sol` and `MultiRateLimited.s — Volt Protocol
 2. [LOW] Misleading Rate Limit Condition — DerivaDEX 2
 3. [LOW] Implement Rate Limit — Render Network
 4. [LOW] Refill RateLimiter Before Setting Rate — USDV
 5. [LOW] `RateLimiter` Does Not Refill After 60 Seconds — Tensorplex Labs

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: RateLimit | Dominio: general
Los siguientes 5 findings de protocolos similares son relevantes:

1. [GAS] [G-02] Lots of duplicated code between `RateLimited.sol` and `MultiRateLimited.sol` (Volt Protocol)
   
The functionality of `RateLimited.sol` can be achieved by using either `address(0)` or `address(this)` as the `rateLimitedAddress` so having a separa...

2. [LOW] Misleading Rate Limit Condition (DerivaDEX 2)
   **Update**
The team fixed the issue as recommended.

**File(s) affected:**`libs/LibCollateral.sol`

**Description:** The `LibCollateral.sol:commitWith...

3. [LOW] Implement Rate Limit (Render Network)
   ## API Security Concerns

The bridge does not enable a rate limit on the website APIs, facilitating DOS attacks.

## Remediation

Implement a rate lim...

4. [LOW] Refill RateLimiter Before Setting Rate (USDV)
   ## RateLimiters in USDV

RateLimiters are used to limit the speed at which USDV can be minted or burned with respect to certain collateral tokens. 

#...

5. [LOW] `RateLimiter` Does Not Refill After 60 Seconds (Tensorplex Labs)
   **Update**
Marked as "Fixed" by the client. Addressed in: `ba2f25be53f42a04c2ae4a862a3b3061d29daca6`. The client provided the following explanation:

...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio access
Buscando 'RateLimit configureCaller removeCaller estimatedAllowance currentAllowance' [SQLite FTS5] (dominio: access)...
Top 1 findings relevantes: (56ms)
 1. [HIGH] H-5: attacker can drain StopLimit contract funds through Bracket contract becaus — Oku's New Order Types Contract Contest
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: RateLimit configureCaller removeCaller estimatedAllowance currentAllowance | Dominio: access
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] H-5: attacker can drain StopLimit contract funds through Bracket contract because it gives type(uint256).max  allowance to bracket contract for input token in performUpkeep function (Oku's New Order Types Contract Contest)
   Source: https://github.com/sherlock-audit/2024-11-oku-judging/issues/700 
## Found by 
0xaxaxa, Contest-Squad, rudhra1749, whitehair0330, xiaoming90
...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'RateLimit configureCaller removeCaller estimatedAllowance cu' [SQLite FTS5] (dominio: general)...
Top 4 findings relevantes: (13ms)
 1. [HIGH] Unauthenticated disperser clients can fill the global rate limit even if unauthR — EigenDA vCISO
 2. [HIGH] Risk of DoS attacks due to rate limits — Ondo Finance: Ondo Protocol
 3. [HIGH] [C-01] Gateway creator can steal all tokens from the GatewayRegistry — Subsquid
 4. [HIGH] [C-01] Gateway creator can steal all tokens from the GatewayRegistry — Subsquid
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: RateLimit configureCaller removeCaller estimatedAllowance cu | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:
1. [HIGH] Unauthenticated disperser clients can fill the global rate l

## Briefing del Dominio (access)
### Briefing principal: access

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ Some functions are intentionally permissionless (liquidation, keeper calls) -- verify it SHOULD be restricted
  ⚠ Access control may be enforced deeper in the call stack via an internal function
  ⚠ Not always exploitable by attacker -- more of a governance risk
  ⚠ Some protocols intentionally use single-step for simplicity (low value contracts)
  ⚠ reinitializer(version) is legitimate for upgrade migrations -- only flag if version is re-callable
  ⚠ Standard OpenZeppelin TransparentUpgradeableProxy and UUPS are safe by default
  ⚠ Focus on custom proxy implementations
  ⚠ Emergency pause mechanisms intentionally skip timelock -- this is expected
  ⚠ Cap decreases are often instant by design (reducing exposure is safe)
  ⚠ Centralization concerns are often out of scope for bug bounties unless the bounty explicitly covers governance
  ⚠ Multi-sig is considered trusted in most bounty programs
  ⚠ tx.origin == msg.sender as an anti-contract guard is a different pattern (not auth bypass, but can be bypassed via constructor calls)



## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Novel bugs) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
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
ID prefix para este componente: `RL` (ej: RL-01, RL-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_RateLimit_WildcardHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: RL-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "RL-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Deadlock Analysis (OBLIGATORIO — después de tu búsqueda creativa)
Para cada safety check, margin, cap, o límite en el contrato:
1. ¿Puede BLOQUEAR una operación de emergencia? (repay, withdraw, liquidate, unstake)
2. ¿Hay un escenario donde el usuario NO PUEDE deshacer su posición?
3. ¿El safety mechanism puede dejar fondos permanentemente bloqueados?
4. ¿Un cap que protege al protocolo puede impedir que un usuario se salve de liquidación?

Bug real: Safety margin aplicado al cálculo de repago impedía que usuarios repagaran → liquidados sin poder hacer nada.
Busca: require/assert/if que revierten en funciones de salida (withdraw, repay, unstake, emergencyWithdraw).

## Composability Attack (samczsun — "Two Rights Make A Wrong")
Para cada interacción con un contrato externo:
1. ¿Qué ASUME este contrato sobre el comportamiento del otro?
2. ¿Bajo qué condiciones esa asunción se viola?
3. ¿Se puede crear un estado donde ambos contratos son internamente consistentes pero juntos son inseguros?
Bug real: SushiSwap MISO — msg.value reutilizado en loop de batch. Auction y batch handler eran seguros individualmente.

## "Reimplementa de Memoria" (cmichel — MENTALIDAD)
Después de leer el contrato, pregúntate: ¿podría reimplementar esto desde cero sin mirar el código?
Si tu versión mental DIFIERE del código real en algún punto → ese punto es un candidato a bug.
La gap entre "qué debería hacer" y "qué realmente hace" es donde viven los bugs novedosos.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
