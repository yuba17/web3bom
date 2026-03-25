# WildcardHunter — Bundler3 Analysis

## Tu Identidad
Eres el **WildcardHunter** del equipo de bug hunting de morpho-bundler3.
Tu especialidad: **Novel bugs, unconventional vectors, assumption violations, composability risks**

## Tu Objetivo
Analizar `Bundler3` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/morpho-bundler3/src/Bundler3.sol`
**Dominio**: trust


## Asset Flow Map
### Money OUT (withdrawals/sends)
- L63 _multicall(): (bool success, bytes memory returnData) = to.call{value: bundle[i].value}(bundle[i].data);
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.28;

import {IBundler3, Call} from "./interfaces/IBundler3.sol";

import {ErrorsLib} from "./libraries/ErrorsLib.sol";
import {UtilsLib} from "./libraries/UtilsLib.sol";

/// @custom:security-contact security@morpho.org
/// @notice Enables batching multiple calls in a single one.
/// @notice Transiently stores the initiator of the multicall.
/// @notice Can be reentered by the last unreturned callee with known data.
/// @dev Anybody can do arbitrary calls with this contract, so it should not be approved/authorized anywhere.
contract Bundler3 is IBundler3 {
    /* TRANSIENT STORAGE */

    /// @notice The initiator of the multicall transaction.
    address public transient initiator;

    /// @notice Hash of the concatenation of the sender and the hash of the calldata of the next call to `reenter`.
    bytes32 public transient reenterHash;

    /* EXTERNAL */

    /// @notice Executes a sequence of calls.
    /// @dev Locks the initiator so that the sender can be identified by other contracts.
    /// @param bundle The ordered array of calldata to execute.
    function multicall(Call[] calldata bundle) external payable {
        require(initiator == address(0), ErrorsLib.AlreadyInitiated());

        initiator = msg.sender;

        _multicall(bundle);

        initiator = address(0);
    }

    /// @notice Executes a sequence of calls.
    /// @dev Useful during callbacks.
    /// @dev Can only be called by the last unreturned callee with known data.
    /// @param bundle The ordered array of calldata to execute.
    function reenter(Call[] calldata bundle) external {
        require(
            reenterHash == keccak256(bytes.concat(bytes20(msg.sender), keccak256(msg.data[4:]))),
            ErrorsLib.IncorrectReenterHash()
        );
        _multicall(bundle);
        // After _multicall the value of reenterHash is bytes32(0).
    }

    /* INTERNAL */

    /// @notice Executes a sequence of calls.
    function _multicall(Call[] calldata bundle) internal {
        require(bundle.length > 0, ErrorsLib.EmptyBundle());

        for (uint256 i; i < bundle.length; ++i) {
            address to = bundle[i].to;
            bytes32 callbackHash = bundle[i].callbackHash;
            if (callbackHash == bytes32(0)) reenterHash = bytes32(0);
            else reenterHash = keccak256(bytes.concat(bytes20(to), callbackHash));

            (bool success, bytes memory returnData) = to.call{value: bundle[i].value}(bundle[i].data);
            if (!bundle[i].skipRevert && !success) UtilsLib.lowLevelRevert(returnData);

            require(reenterHash == bytes32(0), ErrorsLib.MissingExpectedReenter());
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre Bundler3
Buscando 'Bundler3' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (14ms)


### HIGH findings en dominio trust
Buscando 'Bundler3 multicall reenter _multicall' [SQLite FTS5] (dominio: trust)...

Top 6 findings relevantes: (111ms)

 1. [HIGH] ETH left in threednsregcontrol contract can be stolen  — 3DNS Inc
 2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commi — 3DNS Inc
 3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of A — SphereX Audit
 4. [HIGH] Signature does not take all parameters into account and can be reused — Common Pool
 5. [HIGH] Denial-of-Service (DoS) by Opening a Credit Account on Behalf of the CreditFacad — Gearbox
 6. [HIGH] [H-01] Excess Payment When Plugin Owner Reduces Price — Bullasv2

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bundler3 multicall reenter _multicall | Dominio: trust
Los siguientes 6 findings de protocolos similares son relevantes:

1. [HIGH] ETH left in threednsregcontrol contract can be stolen  (3DNS Inc)
   ## Multicall Vulnerability Analysis

**Context:** `Multicall.sol#L19-L29`  
The `multicall()` function can (recursively) call itself via `functionDele...

2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commitment  (3DNS Inc)
   ## Commitment Orderflow Vulnerability Analysis

## Context
- CommitmentOrderflow.sol#L140
- Multicall.sol#L23

## Description

### ThreeDNSRegControl ...

3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of All Likely Loop Lengths and Combinations (SphereX Audit)
   The current implementation requires explicit permission for each possible loop length if a protected method (internal, public, or external) is invoked...

4. [HIGH] Signature does not take all parameters into account and can be reused (Common Pool)
   ##### Description

The `CommonPool`'s `allocateFunds` function accepts a Deposit / Withdraw payload and a corresponding signature (it is a structure m...

5. [HIGH] Denial-of-Service (DoS) by Opening a Credit Account on Behalf of the CreditFacade Contract (Gearbox)
   ## Description

Malicious actors can create a Denial-of-Service (DoS) condition on the Gearbox protocol by opening a new `creditAccount` on behalf o...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'Bundler3 multicall reenter _multicall' [SQLite FTS5] (dominio: general)...

Top 4 findings relevantes: (6ms)

 1. [HIGH] ETH left in threednsregcontrol contract can be stolen  — 3DNS Inc
 2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commi — 3DNS Inc
 3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of A — SphereX Audit
 4. [HIGH] Signature does not take all parameters into account and can be reused — Common Pool

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: Bundler3 multicall reenter _multicall | Dominio: general
Los siguientes 4 findings de protocolos similares son relevantes:

1. [HIGH] ETH left in threednsregcontrol contract can be stolen  (3DNS Inc)
   ## Multicall Vulnerability Analysis

**Context:** `Multicall.sol#L19-L29`  
The `multicall()` function can (recursively) call itself via `functionDele...

2. [HIGH] Anyone can drain the whole ETH balance of ThreeDNSRegControl when making a commitment  (3DNS Inc)
   ## Commitment Orderflow Vulnerability Analysis

## Context
- CommitmentOrderflow.sol#L140
- Multicall.sol#L23

## Description

### ThreeDNSRegControl ...

3. [HIGH] Loop-Called Methods and MultiCall Contracts Require an Individual Allowance of All Likely Loop Lengths and Combinations (SphereX 

## Briefing del Dominio (trust)
### Briefing principal: trust

## TRAMPAS — NO pierdas tiempo en esto
  ⚠ La mayoría de protocolos DeFi mainstream usan USDC/WETH — no son FoT.
  ⚠ El impacto real depende de si el token en scope puede ser FoT (verificar docs del protocolo).
  ⚠ Algunos auditores marcan esto como LOW/INFO si el protocolo explícitamente excluye FoT.
  ⚠ ERC777 ya no es popular post-2022, pero sigue siendo un vector con tokens heredados.
  ⚠ USDC/USDT no son ERC777, pero protocolos con reward tokens configurables sí son vulnerables.
  ⚠ GearBox demostró que ERC777 como colateral puede bloquear liquidaciones (DOS, no drain).
  ⚠ Circle rara vez bloquea direcciones de contratos DeFi — el riesgo es real pero bajo.
  ⚠ El riesgo más práctico es el griefing de liquidaciones en lending protocols.
  ⚠ Verificar si el protocolo tiene USDC como único colateral o tiene alternativas.
  ⚠ cToken de Compound NO es rebasing — su balance es fijo, sube el exchangeRate.
  ⚠ wstETH NO es rebasing — el precio sube, no el balance.
  ⚠ Sólo stETH "nativo" y aToken son rebasing en el sentido estricto.

## CHECKLIST DE INVARIANTES
```yaml
- id: tb-003
  titulo: Blocklist de USDC/USDT bloquea retiros o liquidaciones del protocolo
  causa_raiz: |
    USDC y USDT tienen función de blacklist/blocklist: el emisor puede bloquear cualquier
    address. Si el contrato o un usuario clave es bloqueado, transfer() revierte → función
    de retiro o liquidación revierte → fondos quedan congelados indefinidamente.
  como_funciona: |
    Path A (usuario bloqueado): Ganador de lotería/subasta bloqueado → transfer() revierte
    → nadie puede completar la distribución → protocolo atascado.
    Path B (protocolo bloqueado): Circle bloquea el propio contrato del protocolo →
    todos los usuarios pierden acceso a sus fondos.
    Path C (griefing): Atacante fuerza al lender/borrower a ser blacklisted → DoS de
    liquidaciones → bad debt acumula.
  invariante: |
    // No se puede invariar on-chain, pero arquitecturalmente:
    // nunca push tokens a usuarios en flujos críticos — usar pull pattern
    // mapping(address => uint256) public claimable;
    // function claim() external { ... token.safeTransfer(msg.sender, amount); }
  que_mirar:

## GREP TARGETS
```yaml
- id: tb-004
  titulo: Tokens rebasing (aToken, stETH) rompen contabilidad si se cachea el balance
  causa_raiz: |
    Tokens como aToken de Aave o stETH de Lido incrementan su balance automáticamente
    con el tiempo (rebasing positivo) sin emitir Transfer events. Si el contrato cachea
    el balance en storage en vez de llamar a balanceOf() cada vez, el valor cacheado
    queda desactualizado → underestima activos → shares sobreemitidas o pérdida de yield.
  como_funciona: |
    1. Vault deposita 1000 USDC en Aave, recibe 1000 aUSDC. Cachea balance=1000.
    2. 30 días pasan: balance real de aUSDC = 1050 (5% yield).
    3. totalAssets() retorna 1000 en vez de 1050 → pricePerShare subestimado.
    4. Usuario que deposita en este momento recibe shares de más → diluye a los existentes.
    5. Cuando alguien hace harvest, los 50 USDC "extra" aparecen como profit inesperado.
  invariante: |


### Grep targets adicionales (inputval)
```bash
# Unbounded loops over user input
grep -rn "for.*\.length" src/ --include="*.sol"
grep -rn "while.*length" src/ --include="*.sol"
# Missing zero-address checks
grep -rn "function set\|function update\|function change" src/ --include="*.sol" | grep -i "address"
# Hardcoded zero slippage
grep -rn "amountOutMin.*=.*0\|minAmountOut.*=.*0\|minOut.*=.*0" src/ --include="*.sol"
# Deadline == block.timestamp (no protection)
grep -rn "block.timestamp" src/ --include="*.sol" | grep -i "deadline"
# Unsafe downcasts
grep -rn "uint128(\|uint96(\|uint64(\|uint48(\|uint32(\|int128(\|int96(" src/ --include="*.sol"

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Novel bugs) es relevante
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
ID prefix para este componente: `B` (ej: B-01, B-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_Bundler3_WildcardHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: B-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "B-01: value decreased");
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
