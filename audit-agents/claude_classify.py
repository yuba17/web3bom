#!/usr/bin/env python3
"""
claude_classify.py — Clasifica findings sin categoría usando Claude Opus.

Estrategia:
  - Lee findings sin categoría de solodit.db
  - Los envía en batches de 20 a claude-opus-4-6
  - Claude clasifica con razonamiento de seguridad real
  - Actualiza la DB con categorías + fuente="claude_opus"
  - Resumible: solo procesa lo que sigue sin categoría

Uso:
    python3 audit-agents/claude_classify.py --dry-run       # preview sin guardar
    python3 audit-agents/claude_classify.py                 # clasifica HIGH+MEDIUM
    python3 audit-agents/claude_classify.py --all           # incluye LOW y GAS
    python3 audit-agents/claude_classify.py --severity HIGH # solo HIGH

Necesita ANTHROPIC_API_KEY en ~/.env o en entorno.
"""

import json
import os
import re
import sqlite3
import sys
import time
import argparse
from pathlib import Path
from typing import Optional

# ── Paths ────────────────────────────────────────────────────────────────────
WEB3_DIR = Path.home() / "Documents/Web3"
DB_PATH = WEB3_DIR / "knowledge/solodit.db"
ENV_PATH = WEB3_DIR / ".env"

# ── Config ───────────────────────────────────────────────────────────────────
OPUS_MODEL = "claude-opus-4-6"
BATCH_SIZE = 20           # findings por request a la API
MIN_CONFIDENCE = 0.75     # umbral para aceptar clasificación
CONTENT_PREVIEW = 250     # chars de contenido a enviar (ahorra tokens)
RATE_LIMIT_SLEEP = 0.3    # segundos entre batches (evitar 429)

# ── Categorías con descripciones para el prompt ───────────────────────────────
CATEGORIES = {
    "staking":          "Gauge, reward distribution, epoch, stake/unstake, emission rates, vote escrow, rewardPerToken",
    "lending":          "Liquidation, collateral, borrow rate, health factor, interest accrual, LTV, bad debt",
    "vault":            "ERC4626, share price, deposit/withdraw, share inflation, totalAssets, first depositor",
    "oracle":           "TWAP, Chainlink, price staleness, spot price manipulation, getReserves, sqrtPriceX96",
    "dex_amm":          "Uniswap, concentrated liquidity, swap, slippage, AMM, tick, liquidity provision",
    "perpetuals":       "Leverage trading, margin, PnL, funding rate, stop-loss, GMX, position size, auto-delever",
    "access_control":   "Missing authorization, unauthorized caller, missing modifier, privilege escalation, role bypass",
    "flash_loan":       "Flash loan, reentrancy, reentrant, callback, CEI violation, ERC777 tokensReceived",
    "bridge":           "Cross-chain, message relay, bridge exploit, Wormhole, LayerZero, message replay",
    "token":            "ERC20, fee-on-transfer, rebasing token, token inflation, double spend, permit2",
    "proxy_upgrade":    "Delegatecall, storage collision, upgradeable, UUPS, uninitialized proxy",
    "signature_replay": "Signature replay, ecrecover, permit, EIP-712, domain separator, nonce reuse",
    "zk_circuits":      "ZK proof, circuit constraint, witness, soundness, prover, Circom, Groth16, Halo2",
    "dos_griefing":     "DoS, griefing, locked funds, unbounded loop, brick contract, out of gas, freeze funds",
    "arithmetic":       "Overflow, underflow, precision loss, wrong calculation, rounding error, off-by-one",
    "governance":       "DAO, multisig, timelock, voting manipulation, proposal, threshold bypass",
    "timing_mev":       "Frontrunning, sandwich attack, MEV, timestamp manipulation, back-running, JIT",
    "centralization":   "Admin can steal, rug pull, privileged role, single point of failure, owner risk",
    "initialization":   "Uninitialized variable, missing constructor, first deposit attack, deployment config",
    "solana":           "Lamports, borsh, PDA, SPL token, Anchor, sysvar, Solana-specific",
    "cosmos_wasm":      "CosmWasm, IBC, wasm, sudo, submessage, bank module, Cosmos SDK",
}

CATEGORY_LIST = "\n".join(f"- {k}: {v}" for k, v in CATEGORIES.items())

SYSTEM_PROMPT = f"""You are an expert smart contract security auditor. Your job is to classify security audit findings into exactly one category.

Categories:
{CATEGORY_LIST}

Rules:
1. Output ONLY valid JSON, no markdown, no explanation outside JSON.
2. For each finding, pick the SINGLE best category.
3. Set confidence between 0.0 and 1.0 (how certain you are).
4. If no category fits well, or if confidence < 0.75, use empty string "".
5. Base your judgment on the security vulnerability type, not the protocol name.

Output format:
[
  {{"id": 12345, "category": "staking", "confidence": 0.95}},
  {{"id": 12346, "category": "arithmetic", "confidence": 0.88}},
  {{"id": 12347, "category": "", "confidence": 0.0}}
]"""


def load_api_key() -> str:
    """Carga ANTHROPIC_API_KEY desde entorno o .env"""
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key

    if ENV_PATH.exists():
        for line in ENV_PATH.read_text().splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                if key:
                    return key

    print("ERROR: ANTHROPIC_API_KEY no encontrada.")
    print(f"Añádela a {ENV_PATH}:")
    print("  ANTHROPIC_API_KEY=sk-ant-...")
    sys.exit(1)


def get_unclassified(db: sqlite3.Connection, severities: list[str], limit: int = 0) -> list[dict]:
    """Lee findings sin categoría filtrados por severidad."""
    cur = db.cursor()
    placeholders = ",".join("?" * len(severities))
    query = f"""
        SELECT rowid, id, title, content, severity
        FROM findings_fts
        WHERE category = ''
        AND severity IN ({placeholders})
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                ELSE 4
            END,
            rowid
    """
    if limit > 0:
        query += f" LIMIT {limit}"

    cur.execute(query, severities)
    rows = cur.fetchall()
    return [
        {
            "rowid": r[0],
            "id": r[1],
            "title": r[2] or "",
            "content": (r[3] or "")[:CONTENT_PREVIEW],
            "severity": r[4],
        }
        for r in rows
    ]


def build_user_prompt(batch: list[dict]) -> str:
    """Construye el prompt de usuario con los findings del batch."""
    items = []
    for f in batch:
        text = f["title"]
        if f["content"]:
            text += " | " + f["content"].replace("\n", " ").strip()
        items.append({"id": f["id"], "text": text[:400]})
    return "Classify these security findings:\n" + json.dumps(items, ensure_ascii=False)


def parse_response(text: str, batch: list[dict]) -> list[dict]:
    """Parsea la respuesta JSON de Claude. Maneja markdown code blocks."""
    # Eliminar markdown si está presente
    text = re.sub(r"```(?:json)?", "", text).strip()

    try:
        results = json.loads(text)
        if not isinstance(results, list):
            return []
        # Validar estructura
        valid = []
        for r in results:
            if not isinstance(r, dict):
                continue
            cat = r.get("category", "")
            conf = float(r.get("confidence", 0))
            if cat not in CATEGORIES and cat != "":
                cat = ""
            if conf < MIN_CONFIDENCE:
                cat = ""
            valid.append({"id": r.get("id"), "category": cat, "confidence": conf})
        return valid
    except (json.JSONDecodeError, ValueError, TypeError):
        return []


def update_db(db: sqlite3.Connection, results: list[dict]) -> int:
    """Actualiza categorías en la DB. Retorna número de filas actualizadas."""
    cur = db.cursor()
    updated = 0
    for r in results:
        if r["category"]:
            # FTS5 no soporta UPDATE directo en columnas — necesitamos DELETE+INSERT
            # Pero solo columnas UNINDEXED como category sí se pueden actualizar
            cur.execute(
                "UPDATE findings_fts SET category = ? WHERE id = ?",
                (r["category"], r["id"])
            )
            if cur.rowcount > 0:
                updated += 1
    db.commit()
    return updated


def classify_batch(client, batch: list[dict]) -> tuple[list[dict], int]:
    """Envía un batch a Claude y retorna (resultados_parseados, tokens_usados)."""
    import anthropic

    user_prompt = build_user_prompt(batch)
    response = client.messages.create(
        model=OPUS_MODEL,
        max_tokens=600,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}]
    )

    raw = response.content[0].text
    tokens = response.usage.input_tokens + response.usage.output_tokens
    results = parse_response(raw, batch)
    return results, tokens


def main():
    parser = argparse.ArgumentParser(description="Clasifica findings con Claude Opus")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview: muestra predicciones sin guardar en DB")
    parser.add_argument("--all", action="store_true",
                        help="Procesa todos los findings sin categoría (incluye LOW/GAS)")
    parser.add_argument("--severity", default=None,
                        help="Filtrar por severidad: HIGH, MEDIUM, LOW, CRITICAL")
    parser.add_argument("--limit", type=int, default=0,
                        help="Máximo número de findings a procesar (0 = todos)")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                        help=f"Findings por request (default: {BATCH_SIZE})")
    args = parser.parse_args()

    # Determinar severidades a procesar
    if args.severity:
        severities = [args.severity.upper()]
    elif args.all:
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "GAS", "INFO"]
    else:
        severities = ["CRITICAL", "HIGH", "MEDIUM"]

    # Cargar API key e inicializar cliente
    api_key = load_api_key()
    try:
        import anthropic
    except ImportError:
        print("ERROR: pip install anthropic --break-system-packages")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    # Conectar a DB
    if not DB_PATH.exists():
        print(f"ERROR: DB no encontrada en {DB_PATH}")
        print("Corre primero: python3 audit-agents/build_solodit_index.py")
        sys.exit(1)

    db = sqlite3.connect(str(DB_PATH))
    findings = get_unclassified(db, severities, limit=args.limit)

    if not findings:
        print(f"No hay findings sin categoría con severidad: {', '.join(severities)}")
        db.close()
        return

    total = len(findings)
    batches = [findings[i:i + args.batch_size] for i in range(0, total, args.batch_size)]

    print(f"{'DRY RUN — ' if args.dry_run else ''}Clasificando {total} findings "
          f"({', '.join(severities)}) en {len(batches)} batches con {OPUS_MODEL}")

    # Estimación de costo (rough)
    est_tokens = total * 80  # ~80 tokens promedio por finding (input)
    est_cost = (est_tokens / 1_000_000) * 15  # $15/M tokens input opus
    print(f"Estimación: ~{est_tokens:,} tokens, ~${est_cost:.2f} USD\n")

    total_classified = 0
    total_tokens = 0
    stats: dict[str, int] = {}
    errors = 0

    for i, batch in enumerate(batches):
        batch_num = i + 1
        try:
            results, tokens = classify_batch(client, batch)
            total_tokens += tokens

            classified_in_batch = [r for r in results if r["category"]]
            total_classified += len(classified_in_batch)

            for r in classified_in_batch:
                stats[r["category"]] = stats.get(r["category"], 0) + 1

            if args.dry_run:
                # Mostrar preview
                for r in results:
                    title = next((f["title"] for f in batch if f["id"] == r["id"]), "?")
                    cat = r["category"] or "(sin categoría)"
                    conf = r["confidence"]
                    sev = next((f["severity"] for f in batch if f["id"] == r["id"]), "?")
                    print(f"  [{sev}] {cat:20s} {conf:.2f}  {title[:70]}")
            else:
                update_db(db, results)

            # Progress
            pct = (batch_num / len(batches)) * 100
            cls_rate = (total_classified / (batch_num * args.batch_size)) * 100
            print(f"\rBatch {batch_num:4d}/{len(batches)} | "
                  f"{pct:5.1f}% | "
                  f"Clasificados: {total_classified:5d} ({cls_rate:.0f}%) | "
                  f"Tokens: {total_tokens:,}",
                  end="", flush=True)

            # Rate limiting
            time.sleep(RATE_LIMIT_SLEEP)

        except Exception as e:
            errors += 1
            print(f"\nERROR en batch {batch_num}: {e}")
            if errors > 5:
                print("Demasiados errores consecutivos, abortando.")
                break
            time.sleep(2)

    print()  # newline después del \r
    print("\n" + "=" * 60)
    print(f"{'DRY RUN — NADA GUARDADO' if args.dry_run else 'COMPLETADO'}")
    print(f"  Findings procesados : {total}")
    print(f"  Clasificados        : {total_classified} "
          f"({100*total_classified/max(total,1):.1f}%)")
    print(f"  Sin categoría       : {total - total_classified}")
    print(f"  Tokens usados       : {total_tokens:,}")
    print(f"  Costo estimado      : ~${(total_tokens/1_000_000)*15:.2f} USD")
    print(f"  Errores             : {errors}")

    if stats:
        print(f"\n  Por categoría:")
        for cat, cnt in sorted(stats.items(), key=lambda x: -x[1]):
            print(f"    {cat:20s}: {cnt:5d}")

    db.close()

    if not args.dry_run and total_classified > 0:
        print(f"\nDB actualizada. Verifica con:")
        print(f"  python3 audit-agents/build_solodit_index.py --verify")


if __name__ == "__main__":
    main()
