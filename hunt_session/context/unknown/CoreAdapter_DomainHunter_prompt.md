# DomainHunter — CoreAdapter Analysis

## Tu Identidad
Eres el **DomainHunter** del equipo de bug hunting de morpho-bundler3.
Tu especialidad: **Protocol-specific invariants, cross-component interactions, economic attacks**

## Tu Objetivo
Analizar `CoreAdapter` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/CoreAdapter.sol`
**Dominio**: trust


## Asset Flow Map
### Money IN (deposits/receives)
- L40 receive(): accepts ETH via payable receive

### Money OUT (withdrawals/sends)
- L70 erc20Transfer(): if (amount > 0) SafeERC20.safeTransfer(IERC20(token), receiver, amount);

### Balance Reads (manipulation vectors)
- L52 nativeTransfer(): if (amount == type(uint256).max) amount = address(this).balance;
- L67 erc20Transfer(): if (amount == type(uint256).max) amount = IERC20(token).balanceOf(address(this));
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

import {ErrorsLib} from "../libraries/ErrorsLib.sol";
import {SafeERC20, IERC20} from "../../lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "../../lib/openzeppelin-contracts/contracts/utils/Address.sol";
import {IBundler3} from "../interfaces/IBundler3.sol";
import {UtilsLib} from "../libraries/UtilsLib.sol";

/// @custom:security-contact security@morpho.org
/// @notice Common contract to all Bundler3 adapters.
abstract contract CoreAdapter {
    /* IMMUTABLES */

    /// @notice The address of the Bundler3 contract.
    address public immutable BUNDLER3;

    /* CONSTRUCTOR */

    /// @param bundler3 The address of the Bundler3 contract.
    constructor(address bundler3) {
        require(bundler3 != address(0), ErrorsLib.ZeroAddress());

        BUNDLER3 = bundler3;
    }

    /* MODIFIERS */

    /// @dev Prevents a function from being called outside of a bundle context.
    /// @dev Ensures the value of initiator() is correct.
    modifier onlyBundler3() {
        require(msg.sender == BUNDLER3, ErrorsLib.UnauthorizedSender());
        _;
    }

    /* FALLBACKS */

    /// @notice Native tokens are received by the adapter and should be used afterwards.
    /// @dev Allows the wrapped native contract to transfer native tokens to the adapter.
    receive() external payable virtual {}

    /* ACTIONS */

    /// @notice Transfers native assets.
    /// @param receiver The address that will receive the native tokens.
    /// @param amount The amount of native tokens to transfer. Pass `type(uint).max` to transfer the adapter's balance
    /// (this allows 0 value transfers).
    function nativeTransfer(address receiver, uint256 amount) external onlyBundler3 {
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(receiver != address(this), ErrorsLib.AdapterAddress());

        if (amount == type(uint256).max) amount = address(this).balance;
        else require(amount != 0, ErrorsLib.ZeroAmount());

        if (amount > 0) Address.sendValue(payable(receiver), amount);
    }

    /// @notice Transfers ERC20 tokens.
    /// @param token The address of the ERC20 token to transfer.
    /// @param receiver The address that will receive the tokens.
    /// @param amount The amount of token to transfer. Pass `type(uint).max` to transfer the adapter's balance (this
    /// allows 0 value transfers).
    function erc20Transfer(address token, address receiver, uint256 amount) external onlyBundler3 {
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(receiver != address(this), ErrorsLib.AdapterAddress());

        if (amount == type(uint256).max) amount = IERC20(token).balanceOf(address(this));
        else require(amount != 0, ErrorsLib.ZeroAmount());

        if (amount > 0) SafeERC20.safeTransfer(IERC20(token), receiver, amount);
    }

    /* INTERNAL */

    /// @notice Returns the current initiator stored in the adapter.
    /// @dev The initiator value being non-zero indicates that a bundle is being processed.
    function initiator() internal view returns (address) {
        return IBundler3(BUNDLER3).initiator();
    }

    /// @notice Calls bundler3.reenter with an already encoded Call array.
    /// @dev Useful to skip an ABI decode-encode step when transmitting callback data.
    /// @param data An abi-encoded Call[].
    function reenterBundler3(bytes calldata data) internal {
        (bool success, bytes memory returnData) = BUNDLER3.call(bytes.concat(IBundler3.reenter.selector, data));
        if (!success) UtilsLib.lowLevelRevert(returnData);
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre CoreAdapter
Buscando 'CoreAdapter' [SQLite FTS5] (dominio: general)...

Top 3 findings relevantes: (7ms)

 1. [LOW] nativeTransfer() and erc20Transfer() cannot be used to skim remaining balances d — Morpho Bundler v3
 2. [LOW] EthereumGeneralAdapter1.wrapStEth() leaves dust amounts of stETH behind due to L — Morpho Bundler v3
 3. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows  — Morpho Bundler v3

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: CoreAdapter | Dominio: general
Los siguientes 3 findings de protocolos similares son relevantes:

1. [LOW] nativeTransfer() and erc20Transfer() cannot be used to skim remaining balances due to zero (Morpho Bundler v3)
   ## Amount Check

**Severity:** Low Risk  
**Context:** CoreAdapter.sol#L54, CoreAdapter.sol#L70  

**Description:**  
In CoreAdapter, the `nativeTrans...

2. [LOW] EthereumGeneralAdapter1.wrapStEth() leaves dust amounts of stETH behind due to Lido's 1-2 wei (Morpho Bundler v3)
   ## Corner Case

**Severity:** Low Risk  
**Context:** CoreAdapter.sol#L68-L72, EthereumGeneralAdapter1.sol#L111-L115  
**Description:** 

When `Ethere...

3. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows stealing funds (Morpho Bundler v3)
   ## Security Report

## Severity: Low Risk

### Context
`ParaswapAdapter.sol#L55`

### Description
The `ParaswapAdapter` contract has several functions...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'CoreAdapter nativeTransfer erc20Transfer initiator reenterBundler3' [SQLite FTS5] (dominio: trust)...
Top 6 findings relevantes: (100ms)
 1. [HIGH] Usage of msg.value in a loop. — Tokensfarm
 2. [HIGH] Usage of msg.value in the loop. — Tokensfarm
 3. [HIGH] TokenDrop: Unprotected initialize() function — PoolTogether - Pods
 4. [HIGH] [H-03]  Wrong implementation of `EIP712MetaTransaction` — Rolla
 5. [HIGH] 18_deploy_RollupRevenueVault.ts – Deployment Script Leaves Contract Uninitialize — Linea - Burn Mechanism
 6. [HIGH] Owner is not initialized — Lyopay
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: CoreAdapter nativeTransfer erc20Transfer initiator reenterBundler3 | Dominio: trust
Los siguientes 6 findings de protocolos similares son relevantes:
1. [HIGH] Usage of msg.value in a loop. (Tokensfarm)
   **Description**
Perpetual Tokens FarmSDK.sol, function notice Reduced StakeWithout StakeId(), line 1433.
TokensFarmSDK.sol, function notice ReducedSt...
2. [HIGH] Usage of msg.value in the loop. (Tokensfarm)
   **Description**
Perpetual TokensFarmSDK.sol, function notice Reduced StakeWithoutStakeld(), line 1433.
TokensFarmSDK.sol, function notice Reduced Sta...
3. [HIGH] TokenDrop: Unprotected initialize() function (PoolTogether - Pods)
   #### Description
The `TokenDrop.initialize()` function is unprotected and can be called multiple times.
**code/pods-v3-contracts/contracts/TokenDr...
4. [HIGH] [H-03]  Wrong implementation of `EIP712MetaTransaction` (Rolla)
   _Submitted by WatchPug_
1.  `EIP712MetaTransaction` is a utils contract that intended to be inherited by concrete (actual) contracts, therefore. it's...
5. [HIGH] 18_deploy_RollupRevenueVault.ts – Deployment Script Leaves Contract Uninitialized; fallback Does Not Enforce msg.value > 0 ✓ Fixed (Linea - Burn Mechanism)
   ...
Export to GitHub ...
Set external GitHub Repo ...
Export to Clipboard (json)
Export to Clipboard (text)
#### Resolution
Fixed in commit [831...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'CoreAdapter nativeTransfer erc20Transfer initiator reenterB

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

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad (Protocol-specific invariants) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `CA` (ej: CA-01, CA-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_CoreAdapter_DomainHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: CA-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "CA-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
