#!/usr/bin/env python3
"""
add_finding.py — Añade findings a our_findings tabla en solodit.db

Uso:
    python3 add_finding.py --interactive
    python3 add_finding.py --from-ficha hunt_session/fichas/revert-lend/GaugeManager.yaml
    python3 add_finding.py --import-report https://github.com/org/audits/blob/main/report.md
    python3 add_finding.py --list
"""

import json
import sqlite3
import sys
import re
import argparse
from pathlib import Path
from datetime import datetime

WEB3_DIR = Path.home() / "Documents/Web3"
DB_PATH = WEB3_DIR / "knowledge/solodit.db"

CATEGORIES = [
    "staking", "lending", "vault", "oracle", "dex_amm",
    "access_control", "flash_loan", "bridge", "token",
    "proxy_upgrade", "signature_replay", "zk_circuits", "other"
]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Keywords para inferir categoría desde texto
CATEGORY_KEYWORDS = {
    "staking": ["stake", "unstake", "gauge", "reward", "epoch", "notifyReward", "rewardPerToken"],
    "lending": ["borrow", "repay", "liquidat", "collateral", "health factor", "utilization", "debt"],
    "vault": ["vault", "share", "deposit", "withdraw", "ERC4626", "totalAssets"],
    "oracle": ["oracle", "price feed", "twap", "chainlink", "latestRoundData", "staleness"],
    "dex_amm": ["swap", "liquidity", "amm", "tick", "uniswap", "slippage", "amountOut"],
    "access_control": ["onlyOwner", "access control", "unauthorized", "missing check", "role"],
    "flash_loan": ["flashloan", "flash loan", "callback", "reentrancy"],
    "bridge": ["bridge", "cross-chain", "message", "nonce", "replay"],
    "token": ["erc20", "transfer", "approve", "allowance", "fee on transfer"],
    "proxy_upgrade": ["proxy", "upgrade", "implementation", "delegatecall", "storage collision"],
    "signature_replay": ["signature", "replay", "nonce", "ecrecover", "permit"],
    "zk_circuits": ["constraint", "circuit", "zk", "proof", "witness"],
}


def get_db():
    if not DB_PATH.exists():
        print(f"✗ DB no encontrada: {DB_PATH}")
        print("  Ejecuta: python3 audit-agents/build_solodit_index.py")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def next_id(conn) -> str:
    """Genera el siguiente ID formato OUR-YYYY-NNN."""
    year = datetime.now().year
    prefix = f"OUR-{year}-"
    existing = conn.execute(
        "SELECT id FROM our_findings WHERE id LIKE ? ORDER BY id DESC LIMIT 1",
        (f"{prefix}%",)
    ).fetchone()
    if existing:
        last_num = int(existing[0].split("-")[2])
        return f"{prefix}{last_num+1:03d}"
    return f"{prefix}001"


def infer_category(text: str) -> str:
    """Infiere categoría desde texto del finding."""
    text_lower = text.lower()
    scores = {}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in text_lower)
        if score > 0:
            scores[cat] = score
    if scores:
        return max(scores, key=scores.get)
    return "other"


def infer_severity(text: str) -> str:
    """Infiere severidad desde patrones comunes en reportes."""
    patterns = [
        (r"\*\*[Ss]everity[:\*]+\s*(Critical|High|Medium|Low)", 1),
        (r"##\s+(Critical|High|Medium|Low)\s+Risk", 1),
        (r"\[(C|H|M|L)-\d+\]", 1),
        (r"Severity:\s*(Critical|High|Medium|Low)", 1),
        (r"Risk:\s*(Critical|High|Medium|Low)", 1),
    ]
    map_abbrev = {"C": "CRITICAL", "H": "HIGH", "M": "MEDIUM", "L": "LOW"}
    for pattern, _ in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            val = m.group(1)
            if val.upper() in map_abbrev:
                return map_abbrev[val.upper()]
            return val.upper()
    return "MEDIUM"


def insert_finding(conn, finding: dict) -> str:
    fid = next_id(conn)
    conn.execute("""
        INSERT INTO our_findings
        (id, title, content, category, protocol, component, severity,
         confirmed_by, poc_file, solodit_refs, date_found, competition)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        fid,
        finding.get("title", ""),
        finding.get("content", ""),
        finding.get("category", ""),
        finding.get("protocol", ""),
        finding.get("component", ""),
        finding.get("severity", "MEDIUM"),
        finding.get("confirmed_by", ""),
        finding.get("poc_file", ""),
        finding.get("solodit_refs", ""),
        finding.get("date_found", datetime.now().strftime("%Y-%m-%d")),
        finding.get("competition", ""),
    ))
    conn.commit()
    return fid


# ─── Modo interactive ────────────────────────────────────────────────────────

def interactive_wizard() -> dict:
    print("\n=== Añadir Finding a our_findings ===\n")

    def ask(prompt, default=""):
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default

    def ask_choice(prompt, choices, default=""):
        print(f"{prompt}")
        for i, c in enumerate(choices, 1):
            print(f"  {i}. {c}")
        val = input(f"  Elige número [{default}]: ").strip()
        try:
            idx = int(val) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        return default

    title = ask("Título del finding")
    if not title:
        print("✗ Título requerido.")
        sys.exit(1)

    content = ask("Descripción completa (o path a archivo .md)")
    if content and Path(content).exists():
        content = Path(content).read_text()

    severity = ask_choice("Severidad:", SEVERITIES, "HIGH")
    category = ask_choice("Categoría:", CATEGORIES, infer_category(title + " " + content[:500]))
    protocol = ask("Protocolo (ej: revert-lend)")
    component = ask("Componente/contrato (ej: GaugeManager)")
    confirmed_by = ask("Confirmado por (fork/medusa/echidna/manual)", "manual")
    poc_file = ask("Path al PoC Foundry (opcional)")
    solodit_refs = ask("IDs Solodit relacionados (coma-separados, opcional)")
    competition = ask("Plataforma (Cantina/C4/Immunefi/etc)", "Cantina")

    return {
        "title": title,
        "content": content,
        "severity": severity,
        "category": category,
        "protocol": protocol,
        "component": component,
        "confirmed_by": confirmed_by,
        "poc_file": poc_file,
        "solodit_refs": solodit_refs,
        "competition": competition,
    }


# ─── Modo --from-ficha ───────────────────────────────────────────────────────

def from_ficha(ficha_path: str) -> list:
    """Importa findings confirmados desde ficha YAML del hunt."""
    try:
        import yaml
    except ImportError:
        # Fallback: parse manual básico
        yaml = None

    path = Path(ficha_path)
    if not path.exists():
        # Intenta rutas relativas al WEB3_DIR
        path = WEB3_DIR / ficha_path
    if not path.exists():
        print(f"✗ Ficha no encontrada: {ficha_path}")
        sys.exit(1)

    text = path.read_text()

    if yaml:
        data = yaml.safe_load(text)
    else:
        # Parse manual rudimentario para YAML simple
        data = {}
        for line in text.split("\n"):
            if ": " in line and not line.startswith(" "):
                k, v = line.split(": ", 1)
                data[k.strip()] = v.strip().strip("'\"")

    protocol = data.get("protocol", "")
    component = data.get("component", "")
    category = data.get("domain", "other")
    competition_map = {
        "cantina": "Cantina", "c4": "Code4rena",
        "code4rena": "Code4rena", "immunefi": "Immunefi",
        "sherlock": "Sherlock"
    }

    confirmed = data.get("confirmed_findings", [])
    if not confirmed:
        print(f"  No hay confirmed_findings en {path.name}")
        return []

    findings = []
    for cf in confirmed:
        if isinstance(cf, dict):
            title = cf.get("title", cf.get("name", ""))
            content = cf.get("description", cf.get("content", ""))
            severity = cf.get("severity", "MEDIUM").upper()
            poc = cf.get("poc_file", cf.get("poc", ""))
        elif isinstance(cf, str):
            title = cf
            content = ""
            severity = "MEDIUM"
            poc = ""
        else:
            continue

        findings.append({
            "title": title,
            "content": content,
            "category": category,
            "protocol": protocol,
            "component": component,
            "severity": severity,
            "confirmed_by": "fork",
            "poc_file": poc,
            "competition": "Cantina",
        })

    return findings


# ─── Modo --import-report ────────────────────────────────────────────────────

def import_report(url: str) -> list:
    """Descarga y parsea un reporte público de C4/Sherlock/Cyfrin."""
    try:
        import urllib.request
    except ImportError:
        print("✗ urllib no disponible")
        sys.exit(1)

    # Convertir GitHub blob URL a raw URL
    raw_url = url
    if "github.com" in url and "/blob/" in url:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

    print(f"Descargando: {raw_url}")
    try:
        req = urllib.request.Request(raw_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"✗ Error descargando: {e}")
        sys.exit(1)

    print(f"  {len(content):,} chars descargados")

    # Parsear findings del markdown
    findings = parse_markdown_report(content, url)
    print(f"  {len(findings)} findings parseados")
    return findings


def parse_markdown_report(text: str, source_url: str = "") -> list:
    """Parsea findings de un reporte markdown de auditoría."""
    findings = []

    # Patrones de headers de findings en reportes comunes:
    # C4: ## [H-01] Title, ## [M-01] Title
    # Sherlock: ## Issue H-01: Title, ### Title
    # Cyfrin: ## [H-1] Title, **Severity: High**
    # Generic: ## High: Title, ## [HIGH] Title

    # Separar por headers de sección (## o ###)
    sections = re.split(r"\n(?=#{1,3}\s)", text)

    finding_patterns = [
        # C4/Cyfrin: [H-01], [M-01], [L-01]
        re.compile(r"^#+\s*\[([HCML][-\s]?\d+)\]\s*(.+)", re.IGNORECASE),
        # Generic severity in header: ## High: Title, ## [HIGH] Title
        re.compile(r"^#+\s*(?:\[)?(Critical|High|Medium|Low)(?:\])?\s*[:\-]?\s*(.+)", re.IGNORECASE),
        # Sherlock: ## Issue H-1: Title
        re.compile(r"^#+\s*Issue\s+([HCML]-\d+)[:\s]+(.+)", re.IGNORECASE),
    ]

    abbrev_map = {
        "H": "HIGH", "C": "CRITICAL", "M": "MEDIUM", "L": "LOW",
        "HIGH": "HIGH", "CRITICAL": "CRITICAL", "MEDIUM": "MEDIUM", "LOW": "LOW",
    }

    for section in sections:
        lines = section.strip().split("\n")
        if not lines:
            continue
        header = lines[0].strip()
        body = "\n".join(lines[1:]).strip()

        matched_severity = None
        matched_title = None

        for pattern in finding_patterns:
            m = pattern.match(header)
            if m:
                severity_raw = m.group(1).upper().rstrip("-0123456789 ")
                matched_severity = abbrev_map.get(severity_raw, "MEDIUM")
                matched_title = m.group(2).strip()
                break

        if not matched_title:
            continue

        # Skip si es muy corto (probablemente no es un finding real)
        if len(body) < 50:
            continue

        # Inferir categoría desde el texto completo
        full_text = matched_title + " " + body
        category = infer_category(full_text)

        findings.append({
            "title": matched_title,
            "content": body[:5000],  # Limitar longitud
            "severity": matched_severity,
            "category": category,
            "protocol": _extract_protocol_from_url(source_url),
            "component": "",
            "confirmed_by": "audit_report",
            "poc_file": "",
            "solodit_refs": "",
            "competition": _detect_platform(source_url),
        })

    return findings


def _extract_protocol_from_url(url: str) -> str:
    """Extrae nombre del protocolo de la URL del reporte."""
    if not url:
        return ""
    # https://github.com/code-423n4/2024-01-protocolname → protocolname
    m = re.search(r"/(\d{4}-\d{2}-[^/]+)", url)
    if m:
        return m.group(1).split("-", 2)[-1] if "-" in m.group(1) else m.group(1)
    # https://github.com/org/protocol-audit → protocol
    parts = url.rstrip("/").split("/")
    if parts:
        return parts[-1].replace("-audit", "").replace("-report", "")
    return ""


def _detect_platform(url: str) -> str:
    """Detecta la plataforma del concurso desde la URL."""
    url_lower = url.lower()
    if "code-423n4" in url_lower or "code4rena" in url_lower:
        return "Code4rena"
    if "sherlock" in url_lower:
        return "Sherlock"
    if "cantina" in url_lower:
        return "Cantina"
    if "cyfrin" in url_lower:
        return "Cyfrin"
    if "immunefi" in url_lower:
        return "Immunefi"
    return ""


# ─── Modo --list ─────────────────────────────────────────────────────────────

def list_findings():
    conn = get_db()
    rows = conn.execute("""
        SELECT id, severity, category, protocol, component, title, date_found
        FROM our_findings
        ORDER BY date_found DESC, id DESC
        LIMIT 50
    """).fetchall()
    conn.close()

    if not rows:
        print("our_findings está vacío. Usa --interactive o --from-ficha para añadir.")
        return

    print(f"\n{'ID':15s} {'SEV':8s} {'CAT':15s} {'PROTOCOL':15s} {'TITLE'}")
    print("-" * 80)
    for row in rows:
        fid, sev, cat, proto, comp, title, date = row
        print(f"{fid:15s} {sev:8s} {(cat or '?'):15s} {(proto or '?'):15s} {title[:40]}")


# ─── main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Añade findings a our_findings tabla en solodit.db"
    )
    parser.add_argument("--interactive", action="store_true",
                        help="Wizard interactivo para añadir un finding")
    parser.add_argument("--from-ficha", metavar="YAML",
                        help="Importa findings confirmados desde ficha YAML del hunt")
    parser.add_argument("--import-report", metavar="URL",
                        help="Descarga e importa reporte público de C4/Sherlock/Cyfrin")
    parser.add_argument("--list", action="store_true",
                        help="Lista todos los findings en our_findings")
    parser.add_argument("--dry-run", action="store_true",
                        help="Muestra qué se insertaría sin insertar")
    args = parser.parse_args()

    if args.list:
        list_findings()
        return 0

    conn = get_db()
    findings_to_insert = []

    if args.interactive:
        findings_to_insert = [interactive_wizard()]

    elif args.from_ficha:
        findings_to_insert = from_ficha(args.from_ficha)
        if not findings_to_insert:
            print("  No hay findings confirmados para importar.")
            return 0

    elif args.import_report:
        findings_to_insert = import_report(args.import_report)
        if not findings_to_insert:
            print("  No se encontraron findings en el reporte.")
            return 0

    else:
        parser.print_help()
        return 1

    if args.dry_run:
        print(f"\n[DRY RUN] Se insertarían {len(findings_to_insert)} findings:")
        for f in findings_to_insert:
            print(f"  [{f.get('severity','?')}] {f.get('title','?')[:60]} ({f.get('category','?')})")
        return 0

    # Insertar
    inserted_ids = []
    for finding in findings_to_insert:
        fid = insert_finding(conn, finding)
        inserted_ids.append(fid)
        print(f"✓ {fid} [{finding.get('severity','?')}] {finding.get('title','')[:60]}")

    conn.close()
    print(f"\n✓ {len(inserted_ids)} finding(s) añadido(s) a our_findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
