#!/usr/bin/env python3
"""
ingest_rejections.py — Ingesta rechazos y duplicados de Bounty Radar para generar reglas de feedback.

Conecta a la DB PostgreSQL de Bounty Radar (vía DATABASE_URL o REST API fallback),
extrae findings con status REJECTED/DUPLICATE, clasifica cada rechazo, y genera
hunt_session/feedback/rejection_rules.yaml con patrones accionables.

Uso:
    python3 audit-agents/ingest_rejections.py
    python3 audit-agents/ingest_rejections.py --api-only         # fuerza REST API (sin psycopg2)
    python3 audit-agents/ingest_rejections.py --db-url "postgresql://..."  # override DATABASE_URL
"""

import sys
import os
import re
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

import yaml

# ── Paths ────────────────────────────────────────────────────────────────────

BOUNTY_RADAR_DIR = Path.home() / "Documents/Web3/bounty-radar"
ENV_LOCAL = BOUNTY_RADAR_DIR / ".env.local"
ENV_FILE = BOUNTY_RADAR_DIR / ".env"
GLOBAL_ENV = Path.home() / "Documents/Web3/.env"
OUTPUT_DIR = Path.home() / "Documents/Web3/hunt_session/feedback"
OUTPUT_FILE = OUTPUT_DIR / "rejection_rules.yaml"

# ── Env loading ──────────────────────────────────────────────────────────────


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a .env file into a dict, ignoring comments and blank lines."""
    env = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        # Strip surrounding quotes
        val = val.strip().strip("'").strip('"')
        env[key.strip()] = val
    return env


def get_database_url(override: Optional[str] = None) -> Optional[str]:
    """
    Resolve DATABASE_URL from (in priority order):
    1. Explicit --db-url override
    2. Environment variable DATABASE_URL
    3. bounty-radar/.env.local
    4. bounty-radar/.env
    """
    if override:
        return override

    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]

    for env_path in [ENV_LOCAL, ENV_FILE]:
        env = load_env_file(env_path)
        if env.get("DATABASE_URL"):
            return env["DATABASE_URL"]

    # Try to construct from docker-compose pattern + DB_PASSWORD
    db_password = None
    for env_path in [ENV_LOCAL, ENV_FILE, GLOBAL_ENV]:
        env = load_env_file(env_path)
        if env.get("DB_PASSWORD"):
            db_password = env["DB_PASSWORD"]
            break

    if db_password:
        # Default docker-compose pattern, but use localhost (assumes port forwarding)
        return f"postgresql://radar:{db_password}@localhost:5432/bountyradar"

    return None


# ── DB fetching (psycopg2) ───────────────────────────────────────────────────

FINDINGS_QUERY = """
SELECT
    f.id,
    f.title,
    f.severity,
    f.status,
    f."rejectionNote",
    f."reviewThread",
    f."submittedAt",
    f."resolvedAt",
    f."createdAt",
    f.description,
    p.name AS program_name,
    p.platform,
    p.type AS program_type
FROM "Finding" f
JOIN "Program" p ON f."programId" = p.id
WHERE f.status IN ('REJECTED', 'DUPLICATE')
ORDER BY f."createdAt" DESC;
"""


def fetch_findings_db(database_url: str) -> list[dict]:
    """Fetch rejected/duplicate findings via direct psycopg2 connection."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        print("  [!] psycopg2 no instalado. Instala con: pip install psycopg2-binary")
        print("  [!] Intentando fallback a REST API...")
        return []

    try:
        conn = psycopg2.connect(database_url, connect_timeout=10)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(FINDINGS_QUERY)
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"  [!] Error conectando a PostgreSQL: {e}")
        print("  [!] Intentando fallback a REST API...")
        return []


# ── REST API fetching (fallback) ─────────────────────────────────────────────


def fetch_findings_api() -> list[dict]:
    """Fetch rejected/duplicate findings via Bounty Radar REST API."""
    try:
        import requests
    except ImportError:
        print("  [!] requests no instalado. Instala con: pip install requests")
        sys.exit(1)

    # Need constants.py for auth
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from constants import derive_session_token

    env = load_env_file(GLOBAL_ENV)
    password = env.get("BOUNTY_RADAR_PASSWORD", "")
    if not password:
        print("  [!] BOUNTY_RADAR_PASSWORD no encontrado en ~/.../Web3/.env")
        sys.exit(1)

    base_url = "https://bugbounty.0mnia.dev"
    sess = requests.Session()
    token = derive_session_token(password)
    sess.cookies.set("br_session", token, domain="bugbounty.0mnia.dev")
    sess.headers.update({"Content-Type": "application/json"})

    # Fetch all findings
    print("  Conectando a Bounty Radar API...")
    try:
        r = sess.get(f"{base_url}/api/findings", timeout=30)
        r.raise_for_status()
        all_findings = r.json()
    except Exception as e:
        print(f"  [!] Error API: {e}")
        sys.exit(1)

    # Fetch all programs for enrichment
    try:
        r = sess.get(f"{base_url}/api/programs", timeout=30)
        r.raise_for_status()
        programs = {p["id"]: p for p in r.json()}
    except Exception:
        programs = {}

    # Filter and normalize to match DB schema
    results = []
    for f in all_findings:
        if f.get("status") not in ("REJECTED", "DUPLICATE"):
            continue
        prog = programs.get(f.get("programId"), {})
        results.append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", "MEDIUM"),
            "status": f.get("status", ""),
            "rejectionNote": f.get("rejectionNote", ""),
            "reviewThread": f.get("reviewThread", ""),
            "submittedAt": f.get("submittedAt"),
            "resolvedAt": f.get("resolvedAt"),
            "createdAt": f.get("createdAt"),
            "description": f.get("description", ""),
            "program_name": prog.get("name", "unknown"),
            "platform": prog.get("platform", "unknown"),
            "program_type": prog.get("type", "BOUNTY"),
        })

    return results


# ── Classification ───────────────────────────────────────────────────────────

CATEGORY_PATTERNS = {
    "trusted_role": {
        "patterns": [
            r"\btrusted\b", r"\badmin\b", r"\bowner\b", r"\bmanager\b",
            r"\bprivileged\b", r"\brole\b", r"\bgovernance\b", r"\bmultisig\b",
            r"\bauthorized\b", r"\boperator\b", r"\bkeeper\b", r"\bguardian\b",
            r"\bcentraliz", r"\btrust\s+assumption",
        ],
        "rule": "If attack requires trusted/privileged role action, REJECT. RedTeam must filter these.",
    },
    "no_impact": {
        "patterns": [
            r"\bno\s+(security\s+)?impact\b", r"\bcosmetic\b", r"\bux\b",
            r"\binformational\b", r"\bno\s+loss\b", r"\bno\s+fund", r"\binsufficient\s+impact\b",
            r"\bminimal\s+impact\b", r"\bnegligible\b", r"\bno\s+real\b",
            r"\bdust\b", r"\brounding\b", r"\bprecision\b",
        ],
        "rule": "If impact is cosmetic/dust/UX-only with no fund loss, REJECT. Quantify impact in USD.",
    },
    "by_design": {
        "patterns": [
            r"\bby\s+design\b", r"\bintentional\b", r"\bdocumented\b",
            r"\bexpected\s+behavior\b", r"\bknown\s+(issue|limitation)\b",
            r"\bwon'?t\s+fix\b", r"\baccepted\s+risk\b", r"\bworking\s+as\s+(intended|designed)\b",
        ],
        "rule": "If behavior is documented/intentional, REJECT. Check known issues list before reporting.",
    },
    "oos": {
        "patterns": [
            r"\bout\s+of\s+scope\b", r"\boos\b", r"\bnot\s+in\s+scope\b",
            r"\bscope\b.*\bexclu", r"\bexclud",
        ],
        "rule": "If target contract/function is out of scope, REJECT. Always verify scope before deep diving.",
    },
    "duplicate": {
        "patterns": [
            r"\bduplicate\b", r"\bdup\b", r"\balready\s+(reported|known|submitted)\b",
            r"\bsame\s+(issue|finding|bug|vuln)\b",
        ],
        "rule": "Duplicate of another submission. Check existing findings before reporting.",
    },
}


def classify_rejection(finding: dict) -> str:
    """
    Classify a rejected/duplicate finding into a category.
    Searches rejectionNote, reviewThread, title, and description.
    Returns the first matching category, or 'unknown'.
    """
    # For DUPLICATE status, classify as duplicate directly
    if finding.get("status") == "DUPLICATE":
        return "duplicate"

    # Build searchable text from all relevant fields
    text_parts = [
        finding.get("rejectionNote") or "",
        finding.get("reviewThread") or "",
        finding.get("title") or "",
        finding.get("description") or "",
    ]
    text = " ".join(text_parts).lower()

    if not text.strip():
        return "unknown"

    # Check each category (order matters: most specific first)
    for category in ["oos", "trusted_role", "by_design", "no_impact", "duplicate"]:
        patterns = CATEGORY_PATTERNS[category]["patterns"]
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return category

    return "unknown"


# ── Output generation ────────────────────────────────────────────────────────


def generate_lessons(categories: dict, total: int) -> list[str]:
    """Generate actionable lessons from rejection data."""
    lessons = []

    if total == 0:
        lessons.append("No rejections found yet - keep building the dataset.")
        return lessons

    # Sort by count descending
    sorted_cats = sorted(categories.items(), key=lambda x: x[1]["count"], reverse=True)

    for cat_name, cat_data in sorted_cats:
        count = cat_data["count"]
        if count == 0:
            continue
        pct = round(100 * count / total)
        if cat_name == "trusted_role":
            lessons.append(
                f"{pct}% of rejections ({count}/{total}) are trusted_role "
                f"- RedTeam MUST filter attacks requiring privileged access."
            )
        elif cat_name == "no_impact":
            lessons.append(
                f"{pct}% of rejections ({count}/{total}) are no_impact "
                f"- Always quantify fund loss in USD before reporting."
            )
        elif cat_name == "by_design":
            lessons.append(
                f"{pct}% of rejections ({count}/{total}) are by_design "
                f"- Read known issues and documentation BEFORE deep diving."
            )
        elif cat_name == "oos":
            lessons.append(
                f"{pct}% of rejections ({count}/{total}) are out_of_scope "
                f"- Verify scope boundaries before investing time."
            )
        elif cat_name == "duplicate":
            lessons.append(
                f"{pct}% of rejections ({count}/{total}) are duplicates "
                f"- Check public findings and common patterns for the protocol."
            )
        elif cat_name == "unknown":
            if pct > 20:
                lessons.append(
                    f"{pct}% of rejections ({count}/{total}) are unclassified "
                    f"- Review these manually and add rejectionNote to improve classification."
                )

    # Cross-cutting lessons
    dup_count = categories.get("duplicate", {}).get("count", 0)
    rej_count = total - dup_count
    if total > 0:
        lessons.append(
            f"Total: {rej_count} rejections + {dup_count} duplicates out of {total} closed findings."
        )

    return lessons


def build_output(findings: list[dict]) -> dict:
    """Build the YAML output structure."""
    # Initialize categories
    categories = {}
    for cat_name, cat_info in CATEGORY_PATTERNS.items():
        categories[cat_name] = {
            "count": 0,
            "findings": [],
            "rule": cat_info["rule"],
        }
    categories["unknown"] = {
        "count": 0,
        "findings": [],
        "rule": "Unclassified rejection - review manually and add rejectionNote.",
    }

    # Classify each finding
    total_rejections = 0
    total_duplicates = 0

    for f in findings:
        category = classify_rejection(f)

        if f.get("status") == "DUPLICATE":
            total_duplicates += 1
        else:
            total_rejections += 1

        categories[category]["count"] += 1

        # Build compact finding summary
        summary = {
            "id": f.get("id", ""),
            "title": (f.get("title") or "")[:120],
            "severity": f.get("severity", ""),
            "status": f.get("status", ""),
            "program": f.get("program_name", ""),
            "platform": f.get("platform", ""),
            "program_type": f.get("program_type", ""),
        }

        # Add dates if available
        for date_field in ["submittedAt", "resolvedAt"]:
            val = f.get(date_field)
            if val:
                if isinstance(val, datetime):
                    summary[date_field] = val.isoformat()
                else:
                    summary[date_field] = str(val)

        # Add rejection context (truncated)
        note = f.get("rejectionNote") or ""
        if note:
            summary["rejectionNote"] = note[:300]
        thread = f.get("reviewThread") or ""
        if thread:
            summary["reviewThread"] = thread[:300]

        categories[category]["findings"].append(summary)

    # Remove empty categories
    categories = {k: v for k, v in categories.items() if v["count"] > 0}

    total = total_rejections + total_duplicates
    lessons = generate_lessons(categories, total)

    output = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "total_rejections": total_rejections,
        "total_duplicates": total_duplicates,
        "rejection_categories": categories,
        "lessons": lessons,
    }

    return output


# ── Summary table ────────────────────────────────────────────────────────────


def print_summary(output: dict):
    """Print a summary table to stdout."""
    total = output["total_rejections"] + output["total_duplicates"]
    print(f"\n{'=' * 70}")
    print(f"  REJECTION ANALYSIS — {total} findings analyzed")
    print(f"{'=' * 70}")
    print(f"  Rejections: {output['total_rejections']}")
    print(f"  Duplicates: {output['total_duplicates']}")
    print()

    # Category table
    print(f"  {'Category':<16} {'Count':>6} {'%':>6}  Rule (short)")
    print(f"  {'-' * 60}")

    cats = output.get("rejection_categories", {})
    for cat_name, cat_data in sorted(cats.items(), key=lambda x: x[1]["count"], reverse=True):
        count = cat_data["count"]
        pct = round(100 * count / total) if total > 0 else 0
        rule_short = cat_data["rule"][:50]
        print(f"  {cat_name:<16} {count:>6} {pct:>5}%  {rule_short}")

    print()

    # Findings detail
    for cat_name, cat_data in sorted(cats.items(), key=lambda x: x[1]["count"], reverse=True):
        if not cat_data["findings"]:
            continue
        print(f"  [{cat_name.upper()}]")
        for f in cat_data["findings"]:
            sev = f.get("severity", "?")
            prog = f.get("program", "?")
            title = f.get("title", "")[:60]
            note = f.get("rejectionNote", "")[:40]
            note_display = f" | Note: {note}" if note else ""
            print(f"    {sev:<8} {prog:<20} {title}{note_display}")
        print()

    # Lessons
    print(f"  LESSONS LEARNED:")
    for i, lesson in enumerate(output.get("lessons", []), 1):
        print(f"    {i}. {lesson}")

    print(f"\n{'=' * 70}")
    print(f"  Output: {OUTPUT_FILE}")
    print(f"{'=' * 70}\n")


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Ingesta rechazos de Bounty Radar y genera reglas de feedback"
    )
    parser.add_argument(
        "--api-only", action="store_true",
        help="Fuerza uso de REST API (sin psycopg2)"
    )
    parser.add_argument(
        "--db-url", metavar="URL",
        help="Override DATABASE_URL (ej: postgresql://radar:pass@localhost:5432/bountyradar)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="No escribir archivo, solo imprimir resumen"
    )
    args = parser.parse_args()

    print(f"\n{'=' * 70}")
    print(f"  INGEST REJECTIONS — Bounty Radar Feedback Loop")
    print(f"{'=' * 70}\n")

    findings = []

    # Strategy 1: Direct DB via psycopg2
    if not args.api_only:
        db_url = get_database_url(args.db_url)
        if db_url:
            # Mask password in output
            masked = re.sub(r'://([^:]+):([^@]+)@', r'://\1:****@', db_url)
            print(f"  [1] Intentando conexion PostgreSQL: {masked}")
            findings = fetch_findings_db(db_url)
            if findings:
                print(f"  [OK] {len(findings)} findings obtenidos via psycopg2\n")
        else:
            print("  [1] DATABASE_URL no encontrado, saltando psycopg2\n")

    # Strategy 2: REST API fallback
    if not findings:
        print(f"  [2] Usando REST API (https://bugbounty.0mnia.dev)...")
        findings = fetch_findings_api()
        if findings:
            print(f"  [OK] {len(findings)} findings obtenidos via REST API\n")

    if not findings:
        print("  [!] No se encontraron findings REJECTED/DUPLICATE.")
        print("  Esto es normal si aun no hay findings cerrados en Bounty Radar.")
        # Still generate empty output
        output = build_output([])
    else:
        output = build_output(findings)

    # Print summary
    print_summary(output)

    # Write YAML
    if not args.dry_run:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_FILE, "w") as f:
            yaml.dump(
                output,
                f,
                default_flow_style=False,
                allow_unicode=True,
                sort_keys=False,
                width=120,
            )
        print(f"  [OK] Archivo generado: {OUTPUT_FILE}")
    else:
        print("  [DRY-RUN] No se escribio archivo.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
