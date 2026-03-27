# DoSHunter — RateLimit Analysis

## Tu Identidad
Eres el **DoSHunter** del equipo de bug hunting de wrapped-tokens-os.
Tu especialidad: **Denial of service, gas griefing, unbounded loops, blocked withdrawals, revert-based DoS, resource exhaustion, emergency function blocking**

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
2. **Identifica** las funciones donde tu especialidad (Denial of service) es relevante
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
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_RateLimit_DoSHunter.yaml`

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

## DoS / Griefing Deep Check (OBLIGATORIO — la clase de vuln MÁS IGNORADA, 2,279 findings en Solodit)

### Sección 1: Unbounded Loops & Gas Exhaustion (8 items)
Para CADA loop (for, while) en el contrato:
1. ¿El loop itera sobre un array cuyo tamaño puede crecer sin límite? (usuarios, tokens, markets, orders)
2. ¿Hay un cap máximo en el tamaño del array? ¿Es razonable para el gas limit del bloque?
3. ¿Hay operaciones storage-write DENTRO del loop? (cada SSTORE = 5K-20K gas)
4. ¿Hay external calls DENTRO del loop? (cada call = variable gas, puede revert y bloquear el loop)
5. ¿La función afectada es una función CRÍTICA? (withdraw, liquidate, claim, emergencyWithdraw)
6. ¿Un atacante puede inflar el array a bajo costo? (crear muchas posiciones pequeñas, registrar muchos tokens)
7. ¿El patrón pull-over-push se usa correctamente? (no enviar a N usuarios en 1 tx → dejar que cada uno retire)
8. ¿Hay paginación o batch limits para operaciones sobre colecciones grandes?

Bug real: GovernorBravo — iteración sobre todas las proposals sin límite → gas DoS.
Bug real: Nouns DAO — iteración sobre voters bloqueó settleAuction().

### Sección 2: Revert-Based DoS — Bloqueo de Funciones Críticas (7 items)
1. ¿Alguna función de SALIDA (withdraw, repay, unstake, emergencyWithdraw) hace external call que puede revert?
   - ¿La función envía ETH con transfer/send a una dirección que puede ser un contrato sin receive()?
   - ¿La función llama a un token que puede pausarse/bloquearse? (USDC blocklist, pausable tokens)
2. ¿Una función de liquidación depende de que el liquidado coopere? (callback, approve, token transfer)
3. ¿Hay un require/assert en una función de emergencia que puede fallar en condiciones extremas?
4. ¿Un oracle caído (reverts) bloquea withdrawals? (Chainlink puede revert si no hay respuesta)
5. ¿Un safety check (health factor, collateral ratio) puede impedir que un usuario repague su deuda?
6. ¿Hay try/catch alrededor de calls que pueden fallar? ¿O un revert en el call propaga y bloquea todo?
7. ¿Funciones de governance/timelock pueden quedar permanentemente bloqueadas? (propuesta que revierte en execute)

Bug real: Akutars — $34M bloqueados porque refund() dependía de transfer() a contratos sin receive().
Bug real: Safety margin en repay impedía repago → usuarios forzados a liquidación ($3M Rari Fuse).

### Sección 3: Front-Running & Grief (5 items)
1. ¿Un atacante puede front-run una transacción para hacerla revert? (sandwich the tx, manipular estado previo)
2. ¿Hay operaciones donde el first-mover gana y puede bloquear a otros? (claim, initialize, createPool)
3. ¿Se puede inflar el gas cost de una transacción ajena? (returnbomb: retornar datos enormes en un callback)
4. ¿Existe donation attack que cambia el estado para hacer revert la tx de la víctima?
5. ¿Un atacante puede crear dust positions para bloquear operaciones batch?

Bug real: ERC-4626 inflation — first depositor envía dust para hacer revert todos los deposits siguientes.
Bug real: returnbomb — contrato malicioso retorna 2MB de datos en callback, agotando gas del caller.

### Sección 4: Resource Exhaustion & State Bloat (5 items)
1. ¿Se pueden crear entidades (positions, orders, tokens) sin costo mínimo? → spam attack
2. ¿Hay storage que crece sin mecanismo de limpieza? (mappings que solo crecen, nunca se borran)
3. ¿El protocolo depende de un keeper/relayer? ¿Qué pasa si el keeper no actúa? (liquidaciones pendientes)
4. ¿Hay rate limiting en funciones que consumen recursos? (createMarket, addToken, registerOracle)
5. ¿Deadline/expiry de operaciones pendientes? ¿O quedan en pending para siempre?

### Sección 5: Emergency & Recovery Blocking (4 items)
1. ¿La función pause() puede ser llamada pero unpause() no existe o requiere multisig con keys perdidas?
2. ¿El modo emergencia permite SIEMPRE retirar fondos? ¿O el emergency también se puede bloquear?
3. ¿Hay timelock que puede quedar permanentemente en estado pendiente? (no se puede cancelar ni ejecutar)
4. ¿Shutdown/migration path funciona si el contrato principal está en un estado inesperado?

Bug real: Compound cETH — admin key loss + pause sin unpause alternativo = fondos bloqueados.
Bug real: Wormhole — guardian set update bloqueado por quorum issue → bridge congelado.

### Solidity Assertion Patterns para DoS

1. **Unbounded loop gas check:**
```solidity
// Verificar que la función no excede gas razonable para N entradas
uint256 gasBefore = gasleft();
target.processAll();
uint256 gasUsed = gasBefore - gasleft();
// Si gasUsed crece linealmente con N, escalar a 100+ entradas bloqueará la tx
t(gasUsed < 5_000_000, "DOS-XX: processAll exceeds 5M gas");
```

2. **Revert-based withdrawal block:**
```solidity
// Crear un contrato que revierte en receive()
RevertOnReceive blocker = new RevertOnReceive();
// Depositar como blocker, luego intentar withdraw
target.deposit{value: 1 ether}(address(blocker));
try target.withdraw(address(blocker), 1 ether) {
    // Si withdraw tiene try/catch o pull pattern, OK
} catch {
    t(false, "DOS-XX: withdraw blocked by reverting receiver");
}
```

3. **Emergency function always callable:**
```solidity
// Poner el contrato en el peor estado posible
_putContractInBadState();
// emergencyWithdraw DEBE funcionar siempre
try target.emergencyWithdraw{gas: 500000}() {
    // OK — emergency funciona
} catch {
    t(false, "DOS-XX: emergencyWithdraw blocked in bad state");
}
```

4. **Array growth → gas DoS:**
```solidity
// Añadir N elementos y medir gas de operación afectada
for (uint i = 0; i < 100; i++) {
    target.addElement(i);
}
uint256 gasBefore = gasleft();
target.processElements();
uint256 gasFor100 = gasBefore - gasleft();
// Proyectar: si 100 elem = X gas, 10K elem = 100X gas > block limit
t(gasFor100 < 500_000, "DOS-XX: processElements scales linearly — DoS at ~10K elements");
```

5. **Oracle failure doesn't block withdrawals:**
```solidity
// Simular oracle caído (reverts)
mockOracle.setShouldRevert(true);
// Withdraw DEBE funcionar aún sin oracle
try target.withdraw{gas: 300000}(user, amount) {
    // OK — withdraw no depende de oracle
} catch {
    t(false, "DOS-XX: withdraw blocked when oracle is down");
}
```

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Los DoS bugs son los más fuzzeables — gas measurements + try/catch patterns son directos.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
