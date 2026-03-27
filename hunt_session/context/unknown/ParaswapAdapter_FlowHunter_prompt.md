# FlowHunter — ParaswapAdapter Analysis

## Tu Identidad
Eres el **FlowHunter** del equipo de bug hunting de morpho-bundler3.
Tu especialidad: **Reentrancy, CEI violations, token flow, callback abuse, fund routing**

## Tu Objetivo
Analizar `ParaswapAdapter` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `/home/kali/Documents/Web3/audit-agents/contracts/morpho/bundler3/src/adapters/ParaswapAdapter.sol`
**Dominio**: trust


## Asset Flow Map
### Money OUT (withdrawals/sends)
- L198 swap(): SafeERC20.safeTransfer(IERC20(destToken), receiver, destAmount);

### Approvals (attack surface)
- L181 swap(): SafeERC20.forceApprove(IERC20(srcToken), augustus, type(uint256).max);
- L186 swap(): SafeERC20.forceApprove(IERC20(srcToken), augustus, 0);

### Balance Reads (manipulation vectors)
- L64 sell(): uint256 newSrcAmount = IERC20(srcToken).balanceOf(address(this));
- L178 swap(): uint256 srcInitial = IERC20(srcToken).balanceOf(address(this));
- L179 swap(): uint256 destInitial = IERC20(destToken).balanceOf(address(this));
- L188 swap(): uint256 srcFinal = IERC20(srcToken).balanceOf(address(this));
- L189 swap(): uint256 destFinal = IERC20(destToken).balanceOf(address(this));
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.28;

import {IParaswapAdapter, Offsets, MarketParams} from "../interfaces/IParaswapAdapter.sol";
import {IAugustusRegistry} from "../interfaces/IAugustusRegistry.sol";
import {CoreAdapter, ErrorsLib, IERC20, SafeERC20, UtilsLib} from "./CoreAdapter.sol";
import {BytesLib} from "../libraries/BytesLib.sol";
import {Math} from "../../lib/openzeppelin-contracts/contracts/utils/math/Math.sol";
import {IMorpho, MorphoBalancesLib} from "../../lib/morpho-blue/src/libraries/periphery/MorphoBalancesLib.sol";

/// @custom:security-contact security@morpho.org
/// @notice Adapter for trading with Paraswap.
contract ParaswapAdapter is CoreAdapter, IParaswapAdapter {
    using Math for uint256;
    using BytesLib for bytes;

    /* IMMUTABLES */

    /// @notice The address of the Augustus registry.
    IAugustusRegistry public immutable AUGUSTUS_REGISTRY;

    /// @notice The address of the Morpho contract.
    IMorpho public immutable MORPHO;

    /* CONSTRUCTOR */

    /// @param bundler3 The address of the Bundler3 contract.
    /// @param morpho The address of the Morpho protocol.
    /// @param augustusRegistry The address of Paraswap's registry of Augustus contracts.
    constructor(address bundler3, address morpho, address augustusRegistry) CoreAdapter(bundler3) {
        require(morpho != address(0), ErrorsLib.ZeroAddress());
        require(augustusRegistry != address(0), ErrorsLib.ZeroAddress());

        MORPHO = IMorpho(morpho);
        AUGUSTUS_REGISTRY = IAugustusRegistry(augustusRegistry);
    }

    /* SWAP ACTIONS */

    /// @notice Sells an exact amount. Can check for a minimum purchased amount.
    /// @notice Compatibility with Augustus versions different from 6.2 is not guaranteed.
    /// @notice This function should be used immediately after sending tokens to the adapter, and any tokens remaining
    /// in the adapter after a swap should be transferred out immediately.
    /// @param augustus Address of the swapping contract. Must be in Paraswap's Augustus registry.
    /// @param callData Swap data to call `augustus` with. Contains routing information.
    /// @param srcToken Token to sell.
    /// @param destToken Token to buy.
    /// @param sellEntireBalance If true, adjusts amounts to sell the current balance of this contract.
    /// @param offsets Offsets in callData of the exact sell amount (`exactAmount`), minimum buy amount (`limitAmount`)
    /// and quoted buy amount (`quotedAmount`).
    /// @dev The quoted buy amount will change only if its offset is not zero.
    /// @param receiver Address to which bought assets will be sent. Any leftover `srcToken` should be skimmed
    /// separately.
    function sell(
        address augustus,
        bytes memory callData,
        address srcToken,
        address destToken,
        bool sellEntireBalance,
        Offsets calldata offsets,
        address receiver
    ) external {
        if (sellEntireBalance) {
            uint256 newSrcAmount = IERC20(srcToken).balanceOf(address(this));
            updateAmounts(callData, offsets, newSrcAmount, Math.Rounding.Ceil);
        }

        swap({
            augustus: augustus,
            callData: callData,
            srcToken: srcToken,
            destToken: destToken,
            maxSrcAmount: callData.get(offsets.exactAmount),
            minDestAmount: callData.get(offsets.limitAmount),
            receiver: receiver
        });
    }

    /// @notice Buys an exact amount. Can check for a maximum sold amount.
    /// @notice Compatibility with Augustus versions different from 6.2 is not guaranteed.
    /// @notice This function should be used immediately after sending tokens to the adapter, and any tokens remaining
    /// in the adapter after a swap should be transferred out immediately.
    /// @param augustus Address of the swapping contract. Must be in Paraswap's Augustus registry.
    /// @param callData Swap data to call `augustus`. Contains routing information.
    /// @param srcToken Token to sell.
    /// @param destToken Token to buy.
    /// @param newDestAmount Adjusted amount to buy. Will be used to update callData before sent to Augustus contract.
    /// @param offsets Offsets in callData of the exact buy amount (`exactAmount`), maximum sell amount (`limitAmount`)
    /// and quoted sell amount (`quotedAmount`).
    /// @dev The quoted sell amount will change only if its offset is not zero.
    /// @param receiver Address to which bought assets will be sent. Any leftover `srcToken` should be skimmed
    /// separately.
    function buy(
        address augustus,
        bytes memory callData,
        address srcToken,
        address destToken,
        uint256 newDestAmount,
        Offsets calldata offsets,
        address receiver
    ) public {
        if (newDestAmount != 0) {
            updateAmounts(callData, offsets, newDestAmount, Math.Rounding.Floor);
        }

        swap({
            augustus: augustus,
            callData: callData,
            srcToken: srcToken,
            destToken: destToken,
            maxSrcAmount: callData.get(offsets.limitAmount),
            minDestAmount: callData.get(offsets.exactAmount),
            receiver: receiver
        });
    }

    /// @notice Buys an amount corresponding to a user's Morpho debt.
    /// @notice Compatibility with Augustus versions different from 6.2 is not guaranteed.
    /// @notice This function should be used immediately after sending tokens to the adapter, and any tokens remaining
    /// in the adapter after a swap should be transferred out immediately.
    /// @param augustus Address of the swapping contract. Must be in Paraswap's Augustus registry.
    /// @param callData Swap data to call `augustus`. Contains routing information.
    /// @param srcToken Token to sell.
    /// @param marketParams Market parameters of the market with Morpho debt. The user must have nonzero debt.
    /// @param offsets Offsets in callData of the exact buy amount (`exactAmount`), maximum sell amount (`limitAmount`)
    /// and quoted sell amount (`quotedAmount`).
    /// @param onBehalf The amount bought will be exactly `onBehalf`'s debt.
    /// @param receiver Address to which bought assets will be sent. Any leftover `src` tokens should be skimmed
    /// separately.
    function buyMorphoDebt(
        address augustus,
        bytes memory callData,
        address srcToken,
        MarketParams calldata marketParams,
        Offsets calldata offsets,
        address onBehalf,
        address receiver
    ) external {
        uint256 debtAmount = MorphoBalancesLib.expectedBorrowAssets(MORPHO, marketParams, onBehalf);
        require(debtAmount != 0, ErrorsLib.ZeroAmount());
        buy({
            augustus: augustus,
            callData: callData,
            srcToken: srcToken,
            destToken: marketParams.loanToken,
            newDestAmount: debtAmount,
            offsets: offsets,
            receiver: receiver
        });
    }

    /* INTERNAL FUNCTIONS */

    /// @dev Executes the swap specified by `callData` with `augustus`.
    /// @dev Even if this adapter holds no approval, swaps are restricted to Bundler3 here as in all adapters in
    /// order to simplify the security model.
    /// @param augustus Address of the swapping contract. Must be in Paraswap's Augustus registry.
    /// @param callData Swap data to call `augustus`. Contains routing information.
    /// @param srcToken Token to sell.
    /// @param destToken Token to buy.
    /// @param maxSrcAmount Maximum amount of `srcToken` to sell.
    /// @param minDestAmount Minimum amount of `destToken` to buy.
    /// @param receiver Address to which bought assets will be sent. Any leftover `src` tokens should be skimmed
    /// separately.
    function swap(
        address augustus,
        bytes memory callData,
        address srcToken,
        address destToken,
        uint256 maxSrcAmount,
        uint256 minDestAmount,
        address receiver
    ) internal onlyBundler3 {
        require(AUGUSTUS_REGISTRY.isValidAugustus(augustus), ErrorsLib.InvalidAugustus());
        require(receiver != address(0), ErrorsLib.ZeroAddress());
        require(minDestAmount != 0, ErrorsLib.ZeroAmount());

        uint256 srcInitial = IERC20(srcToken).balanceOf(address(this));
        uint256 destInitial = IERC20(destToken).balanceOf(address(this));

        SafeERC20.forceApprove(IERC20(srcToken), augustus, type(uint256).max);

        (bool success, bytes memory returnData) = augustus.call(callData);
        if (!success) UtilsLib.lowLevelRevert(returnData);

        SafeERC20.forceApprove(IERC20(srcToken), augustus, 0);

        uint256 srcFinal = IERC20(srcToken).balanceOf(address(this));
        uint256 destFinal = IERC20(destToken).balanceOf(address(this));

        uint256 srcAmount = srcInitial - srcFinal;
        uint256 destAmount = destFinal - destInitial;

        require(srcAmount <= maxSrcAmount, ErrorsLib.SellAmountTooHigh());
        require(destAmount >= minDestAmount, ErrorsLib.BuyAmountTooLow());

        if (receiver != address(this)) {
            SafeERC20.safeTransfer(IERC20(destToken), receiver, destAmount);
        }
    }

    /// @notice Sets exact amount in `callData` to `exactAmount`.
    /// @notice Proportionally scale limit amount in `callData`.
    /// @notice If `offsets.quotedAmount` is not zero, proportionally scale quoted amount in `callData`.
    function updateAmounts(bytes memory callData, Offsets calldata offsets, uint256 exactAmount, Math.Rounding rounding)
        internal
        pure
    {
        uint256 oldExactAmount = callData.get(offsets.exactAmount);
        callData.set(offsets.exactAmount, exactAmount);

        uint256 limitAmount = callData.get(offsets.limitAmount).mulDiv(exactAmount, oldExactAmount, rounding);
        callData.set(offsets.limitAmount, limitAmount);

        if (offsets.quotedAmount > 0) {
            uint256 quotedAmount = callData.get(offsets.quotedAmount).mulDiv(exactAmount, oldExactAmount, rounding);
            callData.set(offsets.quotedAmount, quotedAmount);
        }
    }
}

```

## Contexto de Solodit (bugs similares en protocolos similares)
### Findings sobre ParaswapAdapter
Buscando 'ParaswapAdapter' [SQLite FTS5] (dominio: general)...

Top 1 findings relevantes: (5ms)

 1. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows  — Morpho Bundler v3

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: ParaswapAdapter | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:

1. [LOW] Lack of onlyBundler modifier inside functions of ParaswapAdapter adapter allows stealing funds (Morpho Bundler v3)
   ## Security Report

## Severity: Low Risk

### Context
`ParaswapAdapter.sol#L55`

### Description
The `ParaswapAdapter` contract has several functions...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio trust
Buscando 'ParaswapAdapter buyMorphoDebt updateAmounts' [SQLite FTS5] (dominio: trust)...
Sin resultados para los criterios dados. (10ms)

### Cross-domain HIGH relevantes
Buscando 'ParaswapAdapter buyMorphoDebt updateAmounts' [SQLite FTS5] (dominio: general)...
Sin resultados para los criterios dados. (2ms)

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
2. **Identifica** las funciones donde tu especialidad (Reentrancy) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `PA` (ej: PA-01, PA-02...)

## Output Requerido
**Escribe tu análisis en**: `/home/kali/Documents/Web3/hunt_session/hypotheses/hyp_ParaswapAdapter_FlowHunter.yaml`

Ejemplo de invariante bien formado:
```yaml
- id: PA-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "PA-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
