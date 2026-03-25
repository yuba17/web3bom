# Contexto de Hunt — PreLiquidation

**Protocolo**: morpho-pre-liquidation
**Dominio**: liquidation-mechanics
**LOC**: 121
**Archivo**: /home/kali/Documents/Web3/morpho-pre-liquidation/src/PreLiquidation.sol
**Generado**: 2026-03-23T15:35:10.654303Z

## Solodit Context
### Findings sobre PreLiquidation
Buscando 'PreLiquidation' [SQLite FTS5] (dominio: general)...

Top 2 findings relevantes: (6ms)

 1. [LOW] Liquidations May Fail Due to Underflow in `CurveConvexLib.checkReentrancyContext — Notional Finance
 2. [MEDIUM] M-6: No slippage check for liquidators when they burn USG from their account wit — USG - Tangent

============================================================

## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation | Dominio: general
Los siguientes 2 findings de protocolos similares son relevantes:

1. [LOW] Liquidations May Fail Due to Underflow in `CurveConvexLib.checkReentrancyContext()` (Notional Finance)
   ##### Description
`CurveConvexLib.checkReentrancyContext()` is called during liquidations to check whether the reentrancy flag in Curve pools is enabl...

2. [MEDIUM] M-6: No slippage check for liquidators when they burn USG from their account without Swapping first. (USG - Tangent)
   
Source: https://github.com/sherlock-audit/2025-08-usg-tangent-judging/issues/178 

## Found by 
3rdeye, BADROBINX, Bigsam, Brene, Pro\_King, Tigerfra...

INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.


### HIGH findings en dominio liquidation-mechanics
Buscando 'PreLiquidation marketParams preLiquidationParams preLiquidate onMorphoRepay' [SQLite FTS5] (dominio: liquidation-mechanics)...
Top 1 findings relevantes: (39ms)
 1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` — Catalyst
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation marketParams preLiquidationParams preLiquidate onMorphoRepay | Dominio: liquidation-mechanics
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` (Catalyst)
   **Severity**
**Impact:** Medium
**Likelihood:** High
**Description**
When market is created, it is allowed that `params.premint` and the `...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

### Cross-domain HIGH relevantes
Buscando 'PreLiquidation marketParams preLiquidationParams preLiquidat' [SQLite FTS5] (dominio: general)...
Top 1 findings relevantes: (12ms)
 1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` — Catalyst
============================================================
## Findings Similares de Solodit (contexto para hunters)
Componente: PreLiquidation marketParams preLiquidationParams preLiquidat | Dominio: general
Los siguientes 1 findings de protocolos similares son relevantes:
1. [HIGH] [H-01] Broken mint if market pre-mint less than `p` (Catalyst)
   **Severity**
**Impact:** Medium
**Likelihood:** High
**Description**
When market is created, it is allowed that `params.premint` and the `...
INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.
Verifica si el componente actual tiene las mismas vulnerabilidades.

## Briefing del Dominio
No disponible

## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

ERROR: Slither no pudo analizar /home/kali/Documents/Web3/morpho-pre-liquidation/src/PreLiquidation.sol: Invalid compilation: 
Compilation failed. Can you run build command?
/home/kali/Documents/Web3/morpho-pre-liquidation/out/build-info is not a directory.



