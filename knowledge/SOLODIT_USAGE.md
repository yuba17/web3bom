# Solodit Search — Guía para Hunters

**Base de datos**: `knowledge/solodit.db` (SQLite FTS5, 50.962 findings)
**Script**: `audit-agents/solodit_search.py`
**Velocidad**: ~20ms por query (vs ~4s antes)

---

## Cuándo consultar

Consulta Solodit **después de leer el contrato**, cuando tengas hipótesis concretas.
NO lo consultes al principio para "inspirarte" — eso sesga el análisis.

**Momento correcto**: "Veo que `compoundRewards` pasa `amount0Min=0` — ¿hay precedentes de esto?"
→ `solodit_search.py "amount0Min increaseLiquidity" --domain dex_amm`

---

## Dominios disponibles

| Flag `--domain` | Categoría en DB | Cuándo usar |
|---|---|---|
| `staking` | staking | Gauge, reward, epoch, stake/unstake |
| `lending` | lending | Borrow, liquidate, interest, collateral |
| `vault` | vault | ERC4626, share price, deposit/withdraw |
| `oracle` | oracle | TWAP, Chainlink, staleness, price feed |
| `dex_amm` | dex_amm | Swap, slippage, tick, liquidity, Uniswap |
| `perpetuals` | perpetuals | Leverage, margin, PnL, funding rate, GMX |
| `access_control` | access_control | onlyOwner, roles, unauthorized |
| `flash_loan` | flash_loan | Reentrancy, callback, flash borrow |
| `bridge` | bridge | Cross-chain, message replay, nonce |
| `token` | token | ERC20, fee-on-transfer, rebase |
| `proxy_upgrade` | proxy_upgrade | Delegatecall, storage collision |
| `signature_replay` | signature_replay | Permit, ecrecover, nonce |
| `zk_circuits` | zk_circuits | Constraints, witnesses, proofs |
| `dos_griefing` | dos_griefing | DoS, griefing, locked funds, brick |
| `arithmetic` | arithmetic | Overflow, precision loss, wrong calculation |
| `governance` | governance | DAO, multisig, timelock, proposal |
| `timing_mev` | timing_mev | Frontrun, sandwich, MEV, timestamp |
| `centralization` | centralization | Admin risk, rug pull, privileged role |
| `initialization` | initialization | Uninitialized, missing constructor |
| `solana` | solana | Lamports, borsh, PDA, SPL token |
| `cosmos_wasm` | cosmos_wasm | CosmWasm, IBC, wasm, sudo |

---

## Estrategia: genérico → específico

```bash
# 1. Empieza genérico con keyword del código
solodit_search.py "compoundRewards gauge"

# 2. Refina con dominio
solodit_search.py --domain staking "compoundRewards gauge"

# 3. Busca el patrón exacto que viste en el código
solodit_search.py --domain dex_amm "increaseLiquidity amount0Min 0"

# 4. Si sabes el protocolo similar
solodit_search.py --domain staking --protocol "velodrome" "CLGauge reward"
```

---

## Queries efectivas vs inefectivas

| Inefectiva | Efectiva | Por qué |
|---|---|---|
| `"reentrancy"` | `"getReward reentrancy callback"` | Demasiado genérico |
| `"slippage"` | `"amount0Min 0 sandwich increaseLiquidity"` | Usa nombres de función reales |
| `"oracle manipulation"` | `"TWAP 60 seconds CLPool tick"` | Parámetros concretos |
| `"access control"` | `"onlyVault withdrawer missing check"` | Contexto del contrato |
| `"reward bug"` | `"rewardPerToken epoch boundary double claim"` | Patrón específico |

**Regla**: copia nombres de funciones/variables del código directamente en la query.

---

## Comandos útiles

```bash
# Búsqueda básica
python3 audit-agents/solodit_search.py "gauge reward staker"

# Con dominio y severidad
python3 audit-agents/solodit_search.py --domain staking --severity high "epoch reward"

# Ver contenido completo del finding
python3 audit-agents/solodit_search.py --format full --limit 3 "CLGauge"

# Incluir nuestros findings anteriores
python3 audit-agents/solodit_search.py --our-findings "sandwich compound"

# Contexto para hunter (output estructurado)
python3 audit-agents/solodit_search.py --domain staking --hunter-context \
    --component GaugeManager "gauge reward compound"

# Sin filtro de dominio (todos los 50K findings)
python3 audit-agents/solodit_search.py "increaseLiquidity slippage"
```

---

## Añadir nuestros propios findings

```bash
# Wizard interactivo
python3 audit-agents/add_finding.py --interactive

# Desde ficha de hunt (importa confirmed_findings[])
python3 audit-agents/add_finding.py --from-ficha hunt_session/fichas/revert-lend/GaugeManager.yaml

# Importar reporte público (C4/Sherlock/Cyfrin)
python3 audit-agents/add_finding.py --import-report \
    https://github.com/code-423n4/2024-01-protocol/blob/main/report.md

# Ver todos nuestros findings
python3 audit-agents/add_finding.py --list
```

Nuestros findings se muestran con tag `[OUR]` en los resultados y tienen IDs formato `OUR-YYYY-NNN`.

---

## Reconstruir el índice

```bash
# Primera vez o si se actualiza el JSONL
python3 audit-agents/build_solodit_index.py

# Forzar reconstrucción
python3 audit-agents/build_solodit_index.py --rebuild

# Verificar stats del DB
python3 audit-agents/build_solodit_index.py --verify
```

---

## Notas de la DB

- **50.962 findings** indexados con FTS5 (Porter stemmer: "staking" ≈ "stake" ≈ "staked")
- **21 categorías**: 12 originales + 9 nuevas (perpetuals, dos_griefing, arithmetic, governance, timing_mev, centralization, initialization, solana, cosmos_wasm)
- **1.539 findings** con categoría de ground truth (`solodit_by_category/`)
- **~26.000 findings** auto-clasificados por keyword scoring (56% cobertura total)
- El filtro `--domain` filtra por categoría; sin `--domain`, busca los 50K
- Los findings sin categoría pueden aparecer en cualquier búsqueda por keyword
- **Sin categoría ≠ sin valor**: 2.473 HIGH findings siguen sin categoría (muchos son bugs lógicos de protocolo)
