#!/usr/bin/env python3
"""
solodit_search.py — Búsqueda en base de datos local de Solodit
Soporta SQLite FTS5 (rápido) con fallback a JSONL scan (backward compat).

Uso:
    python3 solodit_search.py "gauge reward epoch"
    python3 solodit_search.py --domain staking --limit 10
    python3 solodit_search.py --protocol "revert lend" --domain lending
    python3 solodit_search.py --severity high --limit 20 "reentrancy reward"
    python3 solodit_search.py --our-findings --limit 5 "rounding"
    python3 solodit_search.py --component GaugeManager --format full
"""

import sys
import json
import re
import sqlite3
import time
import argparse

from paths import WEB3_DIR
DB_PATH = WEB3_DIR / "knowledge/solodit.db"
SOLODIT_JSONL = WEB3_DIR / "knowledge/solodit_all_findings.jsonl"
SOLODIT_BULK = WEB3_DIR / "knowledge/solodit_bulk_findings.json"
SOLODIT_INDEX = WEB3_DIR / "knowledge/solodit_findings_index.md"

# Mapeo domain → category en la DB (categorías reales de by_category/)
DOMAIN_TO_CATEGORY = {
    # Categorías originales
    "staking": "staking",
    "lending": "lending",
    "vault": "vault",
    "oracle": "oracle",
    "dex": "dex_amm",
    "dex_amm": "dex_amm",
    "amm": "dex_amm",
    "access": "access_control",
    "access_control": "access_control",
    "flash": "flash_loan",
    "flash_loan": "flash_loan",
    "bridge": "bridge",
    "token": "token",
    "proxy": "proxy_upgrade",
    "proxy_upgrade": "proxy_upgrade",
    "signature": "signature_replay",
    "signature_replay": "signature_replay",
    "zk": "zk_circuits",
    "zk_circuits": "zk_circuits",
    # Nuevas categorías
    "solana": "solana",
    "rust": "solana",
    "anchor": "solana",
    "cosmos": "cosmos_wasm",
    "cosmwasm": "cosmos_wasm",
    "wasm": "cosmos_wasm",
    "dos": "dos_griefing",
    "griefing": "dos_griefing",
    "dos_griefing": "dos_griefing",
    "arithmetic": "arithmetic",
    "overflow": "arithmetic",
    "precision": "arithmetic",
    "init": "initialization",
    "initialization": "initialization",
    "governance": "governance",
    "dao": "governance",
    "timing": "timing_mev",
    "mev": "timing_mev",
    "timing_mev": "timing_mev",
    "centralization": "centralization",
    "admin": "centralization",
    "perpetuals": "perpetuals",
    "perp": "perpetuals",
    "leverage": "perpetuals",
    "margin": "perpetuals",
    "gmx": "perpetuals",
}

# Keywords por dominio para fallback JSONL scan
DOMAIN_KEYWORDS = {
    "staking": ["stake", "unstake", "gauge", "reward", "epoch", "claim", "rewardPerToken",
                "totalStaked", "rewardRate", "notifyReward", "getReward"],
    "lending": ["borrow", "repay", "liquidat", "collateral", "health factor", "interest rate",
                "utilization", "reserve", "lend", "debt", "ltv"],
    "vault": ["deposit", "withdraw", "share", "asset", "totalAssets", "totalSupply",
              "convertToShares", "convertToAssets", "ERC4626", "previewDeposit"],
    "oracle": ["oracle", "price", "twap", "getPrice", "latestAnswer", "staleness",
               "manipulation", "spot price", "AMM price"],
    "dex": ["swap", "liquidity", "pool", "AMM", "tick", "sqrt", "Uniswap", "slippage",
            "fee tier", "range", "position"],
    "dex_amm": ["swap", "liquidity", "pool", "AMM", "tick", "sqrt", "Uniswap", "slippage"],
    "access": ["onlyOwner", "role", "access control", "unauthorized", "missing check", "admin"],
    "access_control": ["onlyOwner", "role", "access control", "unauthorized"],
    "flash": ["flashloan", "flash loan", "callback", "reentrancy", "CEI"],
    "flash_loan": ["flashloan", "flash loan", "callback", "reentrancy"],
    "bridge": ["bridge", "cross-chain", "message", "nonce", "replay", "validator"],
    "token": ["ERC20", "transfer", "approve", "allowance", "fee on transfer", "rebas"],
    "proxy": ["proxy", "upgrade", "implementation", "delegatecall", "storage"],
    "proxy_upgrade": ["proxy", "upgrade", "implementation", "delegatecall"],
    "signature": ["signature", "replay", "nonce", "ecrecover", "permit"],
    "signature_replay": ["signature", "replay", "nonce", "ecrecover"],
    "zk": ["constraint", "circuit", "zk", "proof", "witness"],
    "zk_circuits": ["constraint", "circuit", "zk", "proof"],
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "gas": 0}


# ─── SQLite FTS5 backend ─────────────────────────────────────────────────────

def _build_fts5_match(keywords: list) -> str:
    """
    Construye expresión FTS5 MATCH desde lista de keywords.
    ["gauge reward", "epoch"] → gauge OR reward OR epoch
    Términos con guión (STK-1) se pasan como "STK-1" (quoted) para evitar
    que FTS5 interprete '-' como NOT operator.
    """
    terms = []
    for kw in keywords:
        for part in kw.strip().split():
            # Quitar caracteres peligrosos para FTS5 excepto letras/números/guión/guión_bajo
            clean = re.sub(r'[^a-zA-Z0-9_\-]', '', part)
            if not clean or len(clean) < 2:
                continue
            # Si contiene guión → quoted string para evitar NOT operator en FTS5
            if '-' in clean:
                terms.append(f'"{clean}"')
            else:
                terms.append(clean)

    if not terms:
        return ""

    # Deduplicar preservando orden
    seen = set()
    unique = []
    for t in terms:
        tl = t.lower().strip('"')
        if tl not in seen:
            seen.add(tl)
            unique.append(t)

    return " OR ".join(unique)


def _expand_severity(severity_filter: str) -> list:
    """'high' → ['HIGH', 'CRITICAL']"""
    sev = severity_filter.upper().strip()
    if sev in ("HIGH", "H"):
        return ["HIGH", "CRITICAL"]
    if sev in ("CRITICAL", "C"):
        return ["CRITICAL"]
    if sev in ("MEDIUM", "M"):
        return ["MEDIUM"]
    if sev in ("LOW", "L"):
        return ["LOW", "INFO"]
    return [sev]


def search_sqlite(
    keywords: list,
    category: str = "",
    severity_filter: str = "",
    protocol_filter: str = "",
    limit: int = 10,
    include_our_findings: bool = False,
) -> list:
    """Búsqueda usando SQLite FTS5."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    results = []

    # ── Solodit findings via FTS5 ─────────────────────────────────────────
    fts_query = _build_fts5_match(keywords)

    if fts_query or category:
        params = []
        where_clauses = []

        if fts_query:
            where_clauses.append("findings_fts MATCH ?")
            params.append(fts_query)

        if category:
            where_clauses.append("category = ?")
            params.append(category)

        if severity_filter:
            sevs = _expand_severity(severity_filter)
            placeholders = ",".join("?" * len(sevs))
            where_clauses.append(f"severity IN ({placeholders})")
            params.extend(sevs)

        if protocol_filter:
            where_clauses.append("protocol LIKE ?")
            params.append(f"%{protocol_filter}%")

        params.append(limit)

        order_by = "rank" if fts_query else "quality_score DESC"
        sql = f"""
            SELECT id, title, content, summary, severity, protocol, firm,
                   category, slug, quality_score
            FROM findings_fts
            WHERE {' AND '.join(where_clauses)}
            ORDER BY {order_by}
            LIMIT ?
        """

        try:
            rows = conn.execute(sql, params).fetchall()
            for row in rows:
                content = row["content"] or row["summary"] or ""
                results.append({
                    "id": row["id"],
                    "title": row["title"],
                    "content": content,
                    "severity": row["severity"],
                    "impact": row["severity"],
                    "protocol": row["protocol"],
                    "firm": row["firm"],
                    "category": row["category"],
                    "slug": row["slug"],
                    "_source": "solodit",
                })
        except sqlite3.OperationalError as e:
            print(f"  WARN FTS5 query error: {e}")

    # ── our_findings (opcional) ───────────────────────────────────────────
    if include_our_findings:
        our_where = []
        our_params = []

        if keywords:
            # Split multi-word keywords into individual terms for LIKE matching
            all_terms = []
            for kw in keywords:
                all_terms.extend(kw.strip().split())
            conditions = []
            for term in all_terms:
                if len(term) >= 2:
                    conditions.append("(LOWER(title) LIKE ? OR LOWER(content) LIKE ?)")
                    our_params.extend([f"%{term.lower()}%", f"%{term.lower()}%"])
            if conditions:
                our_where.append(f"({' OR '.join(conditions)})")

        if category:
            our_where.append("category = ?")
            our_params.append(category)

        if severity_filter:
            sevs = _expand_severity(severity_filter)
            placeholders = ",".join("?" * len(sevs))
            our_where.append(f"severity IN ({placeholders})")
            our_params.extend(sevs)

        our_sql = "SELECT * FROM our_findings"
        if our_where:
            our_sql += f" WHERE {' AND '.join(our_where)}"
        our_sql += " ORDER BY date_found DESC LIMIT ?"
        our_params.append(limit)

        try:
            our_rows = conn.execute(our_sql, our_params).fetchall()
            for row in our_rows:
                results.append({
                    "id": row["id"],
                    "title": row["title"],
                    "content": row["content"] or "",
                    "severity": row["severity"],
                    "impact": row["severity"],
                    "protocol": row["protocol"],
                    "category": row["category"],
                    "slug": "",
                    "_source": "our_findings",
                })
        except Exception as e:
            print(f"  WARN our_findings error: {e}")

    conn.close()
    # our_findings always appended at the end, FTS5 results fill the limit first
    # Combined list is returned (may exceed limit if our_findings adds entries)
    return results


# ─── JSONL fallback backend ──────────────────────────────────────────────────

def load_findings_jsonl() -> list:
    findings = []
    if SOLODIT_JSONL.exists():
        with open(SOLODIT_JSONL, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        pass
        if findings:
            return findings

    if SOLODIT_BULK.exists():
        try:
            data = json.loads(SOLODIT_BULK.read_text())
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("findings", data.get("results", []))
        except Exception:
            pass

    return []


def score_finding_jsonl(finding: dict, keywords: list, severity_filter: str) -> float:
    text_fields = [
        finding.get("title", ""),
        finding.get("content", ""),
        finding.get("summary", ""),
        str(finding.get("protocol", "")),
    ]
    full_text = " ".join(str(f) for f in text_fields).lower()
    if not full_text.strip():
        return 0.0

    if severity_filter:
        sev = finding.get("impact", "").lower()
        if severity_filter.lower() not in sev:
            return 0.0

    score = 0.0
    for kw in keywords:
        kw_lower = kw.lower()
        count = full_text.count(kw_lower)
        if count > 0:
            if kw_lower in finding.get("title", "").lower():
                score += 3.0
            else:
                score += min(count * 0.5, 2.0)

    sev = finding.get("impact", "").lower()
    score += SEVERITY_ORDER.get(sev, 0) * 0.5
    return score


def search_jsonl(
    keywords: list,
    domain: str = "",
    severity_filter: str = "",
    protocol_filter: str = "",
    limit: int = 10,
) -> list:
    """Búsqueda por scan JSONL (fallback)."""
    all_kws = list(keywords)
    if domain:
        all_kws.extend(DOMAIN_KEYWORDS.get(domain.lower(), [])[:5])

    findings = load_findings_jsonl()
    if not findings:
        return []

    if protocol_filter:
        pf = protocol_filter.lower()
        findings = [f for f in findings if pf in str(f.get("protocol", "")).lower()]

    scored = []
    for f in findings:
        s = score_finding_jsonl(f, all_kws, severity_filter)
        if s > 0:
            scored.append((s, f))

    scored.sort(key=lambda x: x[0], reverse=True)

    results = []
    for _, f in scored[:limit]:
        results.append({
            "id": str(f.get("id", "")),
            "title": f.get("title", ""),
            "content": f.get("content", "") or f.get("summary", ""),
            "severity": f.get("impact", "?"),
            "impact": f.get("impact", "?"),
            "protocol": f.get("protocol", ""),
            "category": "",
            "slug": f.get("slug", ""),
            "_source": "jsonl",
        })
    return results


# ─── Formatters (mismo formato que antes) ───────────────────────────────────

def format_finding_brief(finding: dict, rank: int) -> str:
    title = (finding.get("title") or "Sin título")[:80]
    protocol = finding.get("protocol") or "unknown"
    severity = (finding.get("severity") or finding.get("impact") or "?").upper()
    source_tag = " [OUR]" if finding.get("_source") == "our_findings" else ""
    line = f"{rank:2}. [{severity}] {title}{source_tag}"
    if protocol and protocol != "unknown":
        line += f" — {protocol}"
    return line


def format_finding_full(finding: dict, rank: int) -> str:
    title = finding.get("title") or "Sin título"
    protocol = finding.get("protocol") or "unknown"
    severity = (finding.get("severity") or finding.get("impact") or "?").upper()
    category = finding.get("category") or ""

    desc = (finding.get("content") or "")[:300].strip()
    if len(finding.get("content") or "") > 300:
        desc += "..."

    slug = finding.get("slug") or ""
    url = f"https://solodit.xyz/issues/{slug}" if slug else ""

    lines = [
        f"\n{'─'*60}",
        f"#{rank} [{severity}] {title}",
        f"Protocolo: {protocol}",
    ]
    if category:
        lines.append(f"Categoría: {category}")
    if finding.get("_source") == "our_findings":
        lines.append("Fuente: OUR FINDINGS")
    if url:
        lines.append(f"URL: {url}")
    if desc:
        lines.append(f"\n{desc}")
    return "\n".join(lines)


def generate_hunter_context(component: str, domain: str, findings: list) -> str:
    if not findings:
        return ""
    lines = [
        f"\n## Findings Similares de Solodit (contexto para hunters)",
        f"Componente: {component} | Dominio: {domain}",
        f"Los siguientes {len(findings)} findings de protocolos similares son relevantes:\n",
    ]
    for i, f in enumerate(findings[:5], 1):
        title = f.get("title") or "Sin título"
        sev = (f.get("severity") or "?").upper()
        protocol = f.get("protocol") or "unknown"
        desc = (f.get("content") or "")[:200]
        lines.append(f"{i}. [{sev}] {title} ({protocol})")
        if desc:
            lines.append(f"   {desc[:150]}...")
        lines.append("")
    lines.append("INSTRUCCIÓN: Estos patrones han sido explotados en protocolos similares.")
    lines.append("Verifica si el componente actual tiene las mismas vulnerabilidades.")
    return "\n".join(lines)


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Busca findings en Solodit (SQLite FTS5 o JSONL fallback)"
    )
    parser.add_argument("keywords", nargs="*", help="Keywords de búsqueda")
    parser.add_argument("--domain", "-d", type=str, default="",
                        help="Dominio/categoría (staking/lending/oracle/dex_amm/...)")
    parser.add_argument("--protocol", "-p", type=str, default="",
                        help="Filtrar por protocolo")
    parser.add_argument("--severity", "-s", type=str, default="",
                        help="Filtrar severidad (high/medium/critical)")
    parser.add_argument("--limit", "-l", type=int, default=10,
                        help="Número de resultados")
    parser.add_argument("--format", "-f", choices=["brief", "full"], default="brief",
                        help="Formato de salida")
    parser.add_argument("--component", "-c", type=str, default="",
                        help="Nombre del componente (para contexto de hunter)")
    parser.add_argument("--hunter-context", action="store_true",
                        help="Genera texto de contexto para hunters")
    parser.add_argument("--our-findings", action="store_true",
                        help="Incluye our_findings tabla en resultados")
    parser.add_argument("--max-scan", type=int, default=50000,
                        help="Máx findings a escanear (solo modo JSONL)")
    parser.add_argument("--force-jsonl", action="store_true",
                        help="Fuerza uso del scan JSONL aunque exista solodit.db")
    args = parser.parse_args()

    keywords = args.keywords or []
    if not keywords and not args.domain and not args.our_findings:
        parser.print_help()
        return 1

    use_sqlite = DB_PATH.exists() and not args.force_jsonl
    category = DOMAIN_TO_CATEGORY.get(args.domain.lower(), "") if args.domain else ""

    backend = "SQLite FTS5" if use_sqlite else "JSONL scan"
    query_str = " ".join(keywords) if keywords else f"(domain={args.domain})"
    print(f"Buscando '{query_str}' [{backend}] (dominio: {args.domain or 'general'})...")

    t0 = time.time()

    if use_sqlite:
        results = search_sqlite(
            keywords=keywords,
            category=category,
            severity_filter=args.severity,
            protocol_filter=args.protocol,
            limit=args.limit,
            include_our_findings=args.our_findings,
        )
    else:
        print("Cargando JSONL... ", end="", flush=True)
        results = search_jsonl(
            keywords=keywords,
            domain=args.domain,
            severity_filter=args.severity,
            protocol_filter=args.protocol,
            limit=args.limit,
        )
        print("cargado")

    elapsed = time.time() - t0

    if not results:
        print(f"Sin resultados para los criterios dados. ({elapsed*1000:.0f}ms)")
        return 0

    print(f"\nTop {len(results)} findings relevantes: ({elapsed*1000:.0f}ms)\n")

    for i, finding in enumerate(results, 1):
        if args.format == "full":
            print(format_finding_full(finding, i))
        else:
            print(format_finding_brief(finding, i))

    if args.hunter_context and results:
        context = generate_hunter_context(
            component=args.component or " ".join(keywords),
            domain=args.domain or "general",
            findings=results,
        )
        print("\n" + "=" * 60)
        print(context)

    return 0


if __name__ == "__main__":
    sys.exit(main())
