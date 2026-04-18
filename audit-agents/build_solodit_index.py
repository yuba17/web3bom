#!/usr/bin/env python3
"""
build_solodit_index.py — Construye SQLite FTS5 index desde Solodit JSONL + by_category/

Uso:
    python3 build_solodit_index.py
    python3 build_solodit_index.py --rebuild   # fuerza reconstrucción
    python3 build_solodit_index.py --verify     # solo verifica stats del DB existente
"""

import json
import sqlite3
import sys
import time
import argparse

from paths import WEB3_DIR
JSONL_PATH = WEB3_DIR / "knowledge/solodit_all_findings.jsonl"
CAT_DIR = WEB3_DIR / "knowledge/solodit_by_category"
DB_PATH = WEB3_DIR / "knowledge/solodit.db"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "GAS": "GAS",
    "OPTIMIZATION": "GAS",
    "NC": "INFO",
    "QA": "INFO",
}

# Keywords por categoría para clasificación automática.
# Orden importa: categorías más específicas primero para evitar falsos positivos.
# Cada entrada: (keyword, peso). Peso 3 = muy específico, 2 = específico, 1 = genérico.
CATEGORY_KEYWORDS: dict = {
    # ── Chains alternativas (clasificar primero: señal muy específica) ──────
    # Solana: solo términos ÚNICOS del ecosistema Solana, no existen en EVM
    "solana": [
        ("solana", 3),          # palabra "solana" explícita
        ("lamports", 3),        # unidad de SOL, solo existe en Solana
        ("borsh", 3),           # serialización exclusiva de Solana
        ("sysvar", 3),          # concepto de Solana
        ("spl-token", 3),       # biblioteca SPL específica
        ("spl token program", 3),
        ("program derived address", 3),
        ("pda validation", 3),
        ("anchor idl", 3),
        ("account discriminator", 3),
        ("rent exempt", 3),
        ("cpi guard", 3),
        ("solana program", 3),
        ("remaining_accounts", 3),  # snake_case = Rust/Solana
    ],
    "cosmos_wasm": [
        ("cosmwasm", 3), ("cosmos sdk", 3), ("wasm", 3), ("ibc", 3),
        ("msg_", 3), ("querier", 3), ("deps.storage", 3), ("deps.api", 3),
        ("submessage", 3), ("reply handler", 3), ("bank module", 3),
        ("staking module", 3), ("sudo", 3), ("migrate", 2),
        ("instantiate", 2), ("execute msg", 3), ("query msg", 3),
        ("attr", 2), ("response", 1),
    ],
    # ── ZK (señal muy específica) ────────────────────────────────────────
    "zk_circuits": [
        ("zero-knowledge", 3), ("zk proof", 3), ("zk circuit", 3),
        ("zkp", 3), ("circuit constraint", 3), ("witness", 3),
        ("prover", 3), ("groth16", 3), ("plonk", 3), ("fiat-shamir", 3),
        ("transcript", 2), ("snark", 3), ("stark", 3), ("halo2", 3),
        ("circom", 3), ("bellman", 3), ("soundness", 2), ("completeness", 2),
        ("zk rollup", 3), ("cairo", 3), ("starknet", 2),
    ],
    # ── Criptografía / firmas ─────────────────────────────────────────────
    "signature_replay": [
        ("signature replay", 3), ("replay attack", 3), ("ecrecover", 3),
        ("eip712", 3), ("eip-712", 3), ("domain separator", 3),
        ("typehash", 3), ("ecdsa", 3), ("permit", 2),
        ("signed message", 2), ("malleability", 3), ("v r s", 2),
        ("nonce reuse", 3), ("replay protection", 3),
    ],
    # ── Proxy / upgrades ─────────────────────────────────────────────────
    "proxy_upgrade": [
        ("storage collision", 3), ("storage slot", 3), ("delegatecall", 3),
        ("uups", 3), ("transparent proxy", 3), ("beacon proxy", 3),
        ("upgradeto", 3), ("upgradeable", 3), ("initializer", 3),
        ("uninitialized proxy", 3), ("implementation slot", 3),
        ("proxy admin", 3), ("openzeppelin proxy", 3), ("eip1967", 3),
    ],
    # ── Bridges / cross-chain ─────────────────────────────────────────────
    "bridge": [
        ("bridge", 3), ("cross-chain", 3), ("crosschain", 3),
        ("wormhole", 3), ("layerzero", 3), ("chainlink ccip", 3),
        ("axelar", 3), ("hyperlane", 3), ("stargate", 3),
        ("message relay", 3), ("message replay", 3), ("validator set", 2),
        ("sequencer", 2), ("relayer", 2), ("canonical bridge", 3),
        ("optimistic bridge", 3), ("zk bridge", 3),
    ],
    # ── Flash loans / reentrancy ──────────────────────────────────────────
    "flash_loan": [
        ("flashloan", 3), ("flash loan", 3), ("flash borrow", 3),
        ("reentrancy", 3), ("reentrant", 3), ("read-only reentrancy", 3),
        ("cross-function reentrancy", 3), ("cross-contract reentrancy", 3),
        ("checks-effects-interactions", 3), ("CEI violation", 3),
        ("callback attack", 2), ("erc777", 2), ("tokensreceived", 3),
        ("single transaction", 2), ("atomic exploit", 2),
    ],
    # ── Oracles / precios ─────────────────────────────────────────────────
    "oracle": [
        ("oracle manipulation", 3), ("twap manipulation", 3),
        ("chainlink", 2), ("latestrounddata", 3), ("updatedat", 3),
        ("answeredinround", 3), ("price feed", 3), ("staleness", 3),
        ("heartbeat", 3), ("spot price manipulation", 3),
        ("sqrtpricex96", 3), ("getreserves", 3), ("slot0 price", 3),
        ("price manipulation", 2), ("oracle price", 2),
        # Spot price and LP oracle patterns
        ("spot price", 2), ("ichi vault", 3), ("lp oracle", 3),
        ("manipulable oracle", 3), ("easily manipulated", 2),
        ("understates value", 3), ("overstates value", 3),
        ("stale price", 3), ("price stale", 3),
    ],
    # ── DoS / griefing ────────────────────────────────────────────────────
    "dos_griefing": [
        ("denial of service", 3), ("dos attack", 3), ("griefing", 3),
        ("gas griefing", 3), ("block gas limit", 3), ("unbounded loop", 3),
        ("array unbounded", 3), ("out of gas", 3), ("selfdestruct", 3),
        ("force eth", 3), ("stuck funds", 3), ("locked funds", 3),
        ("freeze funds", 3), ("permanent lock", 3), ("deadlock", 3),
        ("griefable", 3), ("dust attack", 3),
        # Contract bricking patterns
        ("brick", 2), ("bricked", 2), ("bricks the", 3),
        ("cannot be called", 3), ("always reverts", 3), ("will always revert", 3),
        ("permanently broken", 3), ("irreversibly broken", 3),
    ],
    # ── Aritmética / precisión ────────────────────────────────────────────
    "arithmetic": [
        ("integer overflow", 3), ("integer underflow", 3),
        ("arithmetic overflow", 3), ("precision loss", 3),
        ("rounding error", 3), ("truncation", 3), ("division by zero", 3),
        ("mulDiv", 3), ("fullmath", 3), ("unchecked arithmetic", 3),
        ("uint256 overflow", 3), ("unsafe casting", 3),
        ("type casting", 2), ("phantom overflow", 3),
        # Common patterns in titles
        ("overflow", 2), ("underflow", 2),
        ("wrong calculation", 3), ("incorrect calculation", 3),
        ("wrongly calculated", 3), ("incorrectly calculated", 3),
        ("calculation error", 3), ("miscalculation", 3),
        ("stale value", 3), ("stale share", 3),
        ("incorrect amount", 3), ("wrong amount", 3),
        ("off by one", 3), ("off-by-one", 3),
    ],
    # ── Inicialización / deployment ────────────────────────────────────────
    "initialization": [
        ("uninitialized", 3), ("not initialized", 3), ("missing initializer", 3),
        ("constructor missing", 3), ("deployment misconfiguration", 3),
        ("initial state", 2), ("initialize function", 2),
        ("first deposit", 2), ("bootstrap", 2), ("genesis", 2),
        ("deployment", 2), ("factory deployment", 2),
        ("initial parameters", 2), ("default value", 2),
    ],
    # ── Governance / DAO ──────────────────────────────────────────────────
    "governance": [
        ("governance attack", 3), ("voting manipulation", 3),
        ("proposal", 2), ("timelock", 3), ("multisig", 3),
        ("dao", 2), ("flash loan governance", 3),
        ("vote buying", 3), ("quorum manipulation", 3),
        ("governance bypass", 3), ("timelocked", 2),
        ("on-chain governance", 3), ("off-chain governance", 3),
        # Multisig threshold bypass patterns
        ("bypass threshold", 3), ("signer threshold", 3),
        ("valid signers", 3), ("signer count", 3),
        ("hatssignergate", 3), ("multisig bypass", 3),
    ],
    # ── Timing / MEV ─────────────────────────────────────────────────────
    "timing_mev": [
        ("front.running", 3), ("frontrunning", 3), ("front-run", 3),
        ("sandwich attack", 3), ("mev extraction", 3), ("maximal extractable", 3),
        ("block.timestamp manipulation", 3), ("timestamp dependency", 3),
        ("block number dependency", 3), ("back-running", 3),
        ("just-in-time", 3), ("jit liquidity", 3),
        ("mempool", 2), ("transaction ordering", 3), ("price impact mev", 3),
    ],
    # ── Centralización ────────────────────────────────────────────────────
    "centralization": [
        ("centralization risk", 3), ("single point of failure", 3),
        ("privileged role", 3), ("admin can", 3), ("owner can", 3),
        ("rug pull", 3), ("exit scam", 3), ("malicious admin", 3),
        ("trusted admin", 2), ("centralized", 2), ("single admin", 3),
        ("emergency pause", 2), ("unilateral", 2),
    ],
    # ── Control de acceso ─────────────────────────────────────────────────
    "access_control": [
        ("access control", 3), ("missing access control", 3),
        ("unauthorized access", 3), ("privilege escalation", 3),
        ("missing onlyowner", 3), ("onlyrole", 3), ("missing modifier", 3),
        ("missing check", 2), ("caller not authorized", 3),
        ("acl bypass", 3), ("role bypass", 3), ("permission", 2),
        # Common access control patterns
        ("anyone can", 3), ("any user can", 3),
        ("steal funds", 3), ("steal all", 3),
        ("arbitrary caller", 3), ("no authentication", 3),
        ("unprotected function", 3), ("missing authentication", 3),
    ],
    # ── Staking / rewards ─────────────────────────────────────────────────
    "staking": [
        ("staking", 3), ("stake", 2), ("unstake", 3), ("gauge", 3),
        ("rewardpertoken", 3), ("rewardrate", 3), ("notifyrewardamount", 3),
        ("getreward", 3), ("totalstaked", 3), ("epoch reward", 3),
        ("claim reward", 3), ("lock period", 3), ("cooldown", 3),
        ("emission rate", 3), ("boosted reward", 3), ("vltoken", 3),
        ("vote escrow", 3), ("vetoken", 3),
        # Common reward patterns
        ("reward accounting", 3), ("reward distribution", 3),
        ("double claim", 3), ("double claiming", 3),
        ("rewards stolen", 3), ("steal rewards", 3),
        ("accrued rewards", 3), ("reward calculation", 3),
    ],
    # ── Lending / borrowing ───────────────────────────────────────────────
    "lending": [
        ("liquidation", 3), ("undercollateralized", 3), ("overcollateralized", 3),
        ("borrow rate", 3), ("supply rate", 3), ("interest accrual", 3),
        ("health factor", 3), ("collateral ratio", 3), ("ltv ratio", 3),
        ("bad debt", 3), ("reserve factor", 3), ("utilization rate", 3),
        ("irm", 3), ("compound interest", 2), ("debt position", 2),
    ],
    # ── Vault / ERC4626 ───────────────────────────────────────────────────
    "vault": [
        ("erc4626", 3), ("totalassets", 3), ("converttoshares", 3),
        ("converttoassets", 3), ("previewdeposit", 3), ("previewredeem", 3),
        ("share inflation", 3), ("virtual shares", 3), ("share price manipulation", 3),
        ("first depositor attack", 3), ("donation attack vault", 3),
        ("max deposit", 2), ("max withdraw", 2), ("yield vault", 2),
    ],
    # ── Perpetuals / derivados ────────────────────────────────────────────
    "perpetuals": [
        ("perpetual", 3), ("perp protocol", 3),
        ("leverage trading", 3), ("leveraged position", 3),
        ("margin trading", 3), ("margin call", 3),
        ("funding rate", 3), ("open interest", 3),
        ("pnl", 3), ("mark price", 3),
        ("liquidation price", 3), ("stop loss", 3),
        ("auto delever", 3), ("auto-delever", 3),
        ("position size", 2), ("long position", 2), ("short position", 2),
        ("collateral ratio", 2),
        ("trigger fee", 3), ("closing fee", 3),
        ("unrealized pnl", 3), ("realized pnl", 3),
        ("gmx", 3), ("kwenta", 3), ("synthetix perp", 3),
        ("increase position", 2), ("decrease position", 2),
    ],
    # ── DEX / AMM ────────────────────────────────────────────────────────
    "dex_amm": [
        ("uniswap v3", 3), ("concentrated liquidity", 3), ("tick range", 3),
        ("sqrtpricelimitx96", 3), ("amountoutminimum", 3), ("slippage protection", 3),
        ("liquidity provision", 3), ("addliquidity", 3), ("removeliquidity", 3),
        ("swap path", 3), ("amm invariant", 3), ("constant product", 3),
        ("pool manipulation", 3), ("velodrome", 3), ("aerodrome", 3),
    ],
    # ── Tokens / ERC20 ────────────────────────────────────────────────────
    "token": [
        ("fee on transfer", 3), ("deflationary token", 3), ("rebasing token", 3),
        ("erc777", 3), ("erc1155", 3), ("token inflation", 3),
        ("mint burn", 2), ("total supply", 2), ("token accounting", 3),
        ("double spend", 3), ("phantom shares", 3), ("token rescue", 2),
        ("permit2", 3), ("approval race", 3),
    ],
}

# Mínimo score para asignar categoría automática.
# Con weights 1/2/3 y bonus x2 en título:
#   - peso-3 en título = 6  ✓ (muy confiable)
#   - peso-2 en título = 4  ✓ (confiable)
#   - peso-3 en body   = 3  ✓ (suficiente)
#   - peso-2 en body   = 2  ✗ (necesita más señal)
AUTO_CLASSIFY_MIN_SCORE = 3


def infer_category(title: str, content: str) -> str:
    """
    Clasifica un finding en una categoría usando keyword scoring.
    Retorna '' si no hay suficiente confianza (score < MIN_SCORE).
    """
    text = (title + " " + (content or "")).lower()
    scores: dict = {}

    for category, keywords in CATEGORY_KEYWORDS.items():
        score = 0
        for kw, weight in keywords:
            kw_lower = kw.lower()
            if kw_lower in text:
                # Bonus si aparece en el título (más señal)
                score += weight * (2 if kw_lower in title.lower() else 1)
        if score > 0:
            scores[category] = score

    if not scores:
        return ""

    best_cat = max(scores, key=scores.get)
    best_score = scores[best_cat]

    # Requiere mínimo de confianza para evitar ruido
    if best_score < AUTO_CLASSIFY_MIN_SCORE:
        return ""

    # Desempate: si dos categorías tienen score cercano (dentro del 30%), la más específica gana
    # (zk_circuits > flash_loan > proxy_upgrade > ... > token)
    specificity_order = list(CATEGORY_KEYWORDS.keys())  # más específica primero
    second_best = sorted(scores.items(), key=lambda x: -x[1])
    if len(second_best) >= 2:
        _, s2 = second_best[1]
        if s2 >= best_score * 0.8:
            # Empate — elegir la más específica según el orden
            for cat in specificity_order:
                if cat in scores and scores[cat] >= best_score * 0.8:
                    return cat

    return best_cat


CREATE_SQL = """
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    id UNINDEXED,
    title,
    content,
    summary,
    category UNINDEXED,
    protocol UNINDEXED,
    firm UNINDEXED,
    severity UNINDEXED,
    report_date UNINDEXED,
    quality_score UNINDEXED,
    slug UNINDEXED,
    tokenize = 'porter unicode61'
);

CREATE TABLE IF NOT EXISTS our_findings (
    id TEXT PRIMARY KEY,
    title TEXT,
    content TEXT,
    category TEXT,
    protocol TEXT,
    component TEXT,
    severity TEXT,
    confirmed_by TEXT,
    poc_file TEXT,
    solodit_refs TEXT,
    date_found TEXT,
    competition TEXT
);

CREATE INDEX IF NOT EXISTS idx_our_cat ON our_findings(category);
CREATE INDEX IF NOT EXISTS idx_our_sev ON our_findings(severity);
"""

INSERT_SQL = "INSERT INTO findings_fts VALUES (?,?,?,?,?,?,?,?,?,?,?)"


def normalize_severity(impact: str) -> str:
    if not impact:
        return "INFO"
    upper = impact.upper().strip()
    return SEVERITY_MAP.get(upper, upper)


def build_id_to_category() -> dict:
    """Lee todos los archivos by_category/ y construye map id→category."""
    id_to_cat = {}
    for cat_file in sorted(CAT_DIR.glob("*.json")):
        cat_name = cat_file.stem  # staking, lending, etc.
        try:
            data = json.loads(cat_file.read_text())
        except Exception as e:
            print(f"  WARN: error leyendo {cat_file.name}: {e}")
            continue
        if not isinstance(data, list):
            print(f"  WARN: {cat_file.name} no es lista, skip")
            continue
        for finding in data:
            fid = str(finding.get("id", ""))
            if fid:
                # Si un finding aparece en múltiples categorías, última gana
                id_to_cat[fid] = cat_name
    return id_to_cat


def build_index(rebuild: bool = False) -> int:
    """Construye el índice. Retorna número de findings insertados."""
    if DB_PATH.exists() and not rebuild:
        print(f"DB ya existe: {DB_PATH}")
        print("Usa --rebuild para forzar reconstrucción.")
        return verify_index()

    if DB_PATH.exists():
        print(f"Eliminando DB existente...")
        DB_PATH.unlink()

    t0 = time.time()

    # 1. Build id→category map
    print("Leyendo archivos by_category/...")
    id_to_cat = build_id_to_category()
    total_categorized = len(id_to_cat)
    print(f"  {total_categorized:,} findings tienen categoría asignada")

    # 2. Crear DB y tablas
    print(f"\nCreando {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    conn.executescript(CREATE_SQL)
    conn.commit()

    # 3. Procesar JSONL e insertar
    print(f"Procesando {JSONL_PATH}...")
    inserted = 0
    no_category = 0
    auto_classified = 0
    category_counts: dict = {}
    errors = 0
    batch = []
    BATCH_SIZE = 2000

    with open(JSONL_PATH, encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError as e:
                errors += 1
                if errors <= 5:
                    print(f"  WARN línea {line_num}: {e}")
                continue

            fid = str(finding.get("id", ""))
            category = id_to_cat.get(fid, "")

            if not category:
                # Clasificación automática por keywords
                category = infer_category(
                    finding.get("title", ""),
                    finding.get("content", "") or finding.get("summary", ""),
                )
                if category:
                    auto_classified += 1
                else:
                    no_category += 1

            if category:
                category_counts[category] = category_counts.get(category, 0) + 1

            severity = normalize_severity(finding.get("impact", ""))

            batch.append((
                fid,
                (finding.get("title") or ""),
                (finding.get("content") or ""),
                (finding.get("summary") or ""),
                category,
                (finding.get("protocol") or ""),
                (finding.get("firm") or ""),
                severity,
                (finding.get("report_date") or ""),
                str(finding.get("quality_score") or ""),
                (finding.get("slug") or ""),
            ))

            if len(batch) >= BATCH_SIZE:
                conn.executemany(INSERT_SQL, batch)
                conn.commit()
                inserted += len(batch)
                batch = []
                if inserted % 10000 == 0:
                    elapsed = time.time() - t0
                    print(f"  {inserted:,} insertados ({elapsed:.1f}s)...")

    # Flush último batch
    if batch:
        conn.executemany(INSERT_SQL, batch)
        conn.commit()
        inserted += len(batch)

    # Optimize FTS5 index
    print("Optimizando índice FTS5...")
    conn.execute("INSERT INTO findings_fts(findings_fts) VALUES('optimize')")
    conn.commit()
    conn.close()

    elapsed = time.time() - t0
    db_size_mb = DB_PATH.stat().st_size / 1024 / 1024

    from_bycat = inserted - auto_classified - no_category
    classified_total = inserted - no_category

    print(f"\n{'='*50}")
    print(f"✓ Build completo en {elapsed:.1f}s")
    print(f"  DB size: {db_size_mb:.1f} MB")
    print(f"  Total insertados:              {inserted:,}")
    print(f"  Con categoría (by_category/):  {from_bycat:,}")
    print(f"  Auto-clasificados (keywords):  {auto_classified:,}")
    print(f"  Sin categoría (misc/ruido):    {no_category:,} ({no_category*100//max(inserted,1)}%)")
    print(f"  Cobertura total:               {classified_total*100//max(inserted,1)}%")
    print(f"  Errores de parse: {errors}")
    print(f"\n  Por categoría (by_category + auto):")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"    {cat:20s}: {count:5d}")
    print(f"    {'(sin categoría)':20s}: {no_category:5d}")

    return inserted


def verify_index() -> int:
    """Verifica stats del DB existente."""
    if not DB_PATH.exists():
        print(f"✗ DB no existe: {DB_PATH}")
        return 0

    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM findings_fts").fetchone()[0]

    print(f"\n✓ DB existente: {DB_PATH}")
    print(f"  DB size: {DB_PATH.stat().st_size/1024/1024:.1f} MB")
    print(f"  Total findings: {total:,}")

    # Stats por categoría
    cats = conn.execute("""
        SELECT category, COUNT(*) as n
        FROM findings_fts
        WHERE category != ''
        GROUP BY category
        ORDER BY n DESC
    """).fetchall()
    print(f"\n  Por categoría:")
    for cat, n in cats:
        print(f"    {cat:20s}: {n:4d}")

    no_cat = conn.execute(
        "SELECT COUNT(*) FROM findings_fts WHERE category = ''"
    ).fetchone()[0]
    print(f"    {'(sin categoría)':20s}: {no_cat:4d}")

    # Stats por severidad
    sevs = conn.execute("""
        SELECT severity, COUNT(*) as n
        FROM findings_fts
        GROUP BY severity
        ORDER BY n DESC
    """).fetchall()
    print(f"\n  Por severidad:")
    for sev, n in sevs:
        print(f"    {sev:12s}: {n:5d}")

    # Test de velocidad
    t0 = time.time()
    conn.execute(
        "SELECT COUNT(*) FROM findings_fts WHERE findings_fts MATCH 'gauge reward'"
    ).fetchone()
    t1 = time.time()
    print(f"\n  Query test ('gauge reward'): {(t1-t0)*1000:.1f}ms")

    our_count = conn.execute("SELECT COUNT(*) FROM our_findings").fetchone()[0]
    print(f"  our_findings: {our_count} entries")

    conn.close()
    return total


def main():
    parser = argparse.ArgumentParser(description="Construye SQLite FTS5 index para Solodit")
    parser.add_argument("--rebuild", action="store_true", help="Fuerza reconstrucción si DB ya existe")
    parser.add_argument("--verify", action="store_true", help="Solo verifica stats del DB existente")
    args = parser.parse_args()

    if args.verify:
        n = verify_index()
        return 0 if n > 0 else 1

    n = build_index(rebuild=args.rebuild)
    return 0 if n > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
