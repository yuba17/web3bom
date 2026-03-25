#!/usr/bin/env python3
"""
report_finding.py — Agente de reporte: crea programa + finding en Bounty Radar y genera draft.

Uso:
    python3 report_finding.py --finding VV-O-02
    python3 report_finding.py --finding VV-O-02 --dry-run
    python3 report_finding.py --finding VV-O-02 --poc test/chimera/PoC_VVO02.t.sol
"""

import sys
import re
import json
import shutil
import argparse
import requests
import yaml
from pathlib import Path
from datetime import datetime

from constants import derive_session_token, SEVERITY_MAP, CATEGORY_MAP

BASE_URL   = "https://bugbounty.0mnia.dev"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
ENV_FILE   = Path.home() / "Documents/Web3/.env"
HYP_DIR    = Path.home() / "Documents/Web3/hunt_session/hypotheses"
REPO_DIR_FALLBACK = Path.home() / "Documents/Web3/revert-lend"


def get_repo_dir() -> Path:
    """Lee repo_path de current_hunt.json. Fallback a REPO_DIR_FALLBACK."""
    if STATE_FILE.exists():
        try:
            state = json.loads(STATE_FILE.read_text())
            rp = state.get("repo_path", "")
            if rp and Path(rp).exists():
                return Path(rp)
        except Exception:
            pass
    return REPO_DIR_FALLBACK

# Bug bounty (Immunefi, Sherlock): payout fijo por severidad, tú eres el único reclamando.
# min% y max% del maxPayout del programa.
BUG_BOUNTY_PCT = {
    "CRITICAL": (0.40, 1.00),
    "HIGH":     (0.15, 0.40),
    "MEDIUM":   (0.05, 0.15),
    "LOW":      (0.01, 0.05),
    "INFO":     (0.00, 0.01),
}

# Competición (Cantina, Code4rena): pool fijo dividido entre todos los hunters válidos.
# Histórico Cantina ($20K–$100K pools, 2023-2025):
#   High único:      8–20% del pool  (~$4K–$10K en pool de $50K)
#   High duplicado:  4–10% del pool  (split entre 2–3 hunters)
#   → usamos rango conservador: 6–15% para High
#   Critical único: 20–50% del pool
#   Medium único:   2–6% del pool
#   Low único:      0.5–2% del pool
COMPETITION_PCT = {
    "CRITICAL": (0.20, 0.50),
    "HIGH":     (0.06, 0.15),
    "MEDIUM":   (0.02, 0.06),
    "LOW":      (0.005, 0.02),
    "INFO":     (0.00, 0.005),
}


def estimate_payout(severity: str, max_payout: int, program_type: str = "bug_bounty") -> tuple[int | None, int | None]:
    """Estima rango de payout según severidad, pool/maxPayout y tipo de programa."""
    if not max_payout:
        return None, None
    table = COMPETITION_PCT if program_type == "competition" else BUG_BOUNTY_PCT
    pct = table.get(severity, (0.02, 0.06))
    return int(max_payout * pct[0]), int(max_payout * pct[1])

PLATFORM_MAP = {
    "cantina": "CANTINA", "immunefi": "IMMUNEFI",
    "code4rena": "CODE4RENA", "sherlock": "SHERLOCK",
}


def parse_payout(raw: str) -> int:
    """Parse payout strings like '$100K max (Critical)', '$2.5M', '50000', etc."""
    if not raw:
        return 0
    clean = raw.replace("$", "").replace(",", "").strip()
    # Extract first number (int or float), handle K/M suffix
    m = re.match(r'([\d.]+)\s*([KkMm])?', clean)
    if not m:
        return 0
    num = float(m.group(1))
    suffix = (m.group(2) or "").upper()
    if suffix == "K":
        num *= 1_000
    elif suffix == "M":
        num *= 1_000_000
    return int(num)

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def make_session(password: str) -> requests.Session:
    s = requests.Session()
    token = derive_session_token(password)
    s.cookies.set("br_session", token, domain="bugbounty.0mnia.dev")
    s.headers.update({"Content-Type": "application/json"})
    return s


def api_get(path: str, sess: requests.Session):
    r = sess.get(f"{BASE_URL}{path}", timeout=15)
    r.raise_for_status()
    return r.json()


def api_post(path: str, data: dict, sess: requests.Session) -> dict:
    r = sess.post(f"{BASE_URL}{path}", json=data, timeout=30)
    r.raise_for_status()
    return r.json()


def api_patch(path: str, data: dict, sess: requests.Session) -> dict:
    r = sess.patch(f"{BASE_URL}{path}", json=data, timeout=15)
    r.raise_for_status()
    return r.json()


# ── Telegram ──────────────────────────────────────────────────────────────────

def get_telegram_config(sess: requests.Session) -> tuple[str, str]:
    """Lee TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID desde la settings API."""
    try:
        settings = api_get("/api/settings", sess)
        keys = {s["key"]: s for s in settings.get("keys", [])}
        # Los valores enmascarados no sirven para enviar — necesitamos leerlos del .env local
        env = load_env()
        token = env.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = env.get("TELEGRAM_CHAT_ID", "")
        return token, chat_id
    except Exception:
        return "", ""


def escape_telegram_md(text: str) -> str:
    """Escapa caracteres especiales de Telegram MarkdownV2."""
    # En MarkdownV2 hay que escapar: _ * [ ] ( ) ~ ` > # + - = | { } . !
    # Excepto los que usamos intencionalmente para formato (*bold*, etc.)
    # Usamos Markdown v1 (más simple): solo escapar ` y [ ]
    return text.replace('`', r'\`').replace('[', r'\[').replace(']', r'\]')


def send_telegram(message: str, sess: requests.Session):
    """Envía mensaje de Telegram. Fallo silencioso si no está configurado."""
    token, chat_id = get_telegram_config(sess)
    if not token or not chat_id:
        return
    try:
        # Escapar backticks en el mensaje completo para evitar parse errors
        safe_message = escape_telegram_md(message)
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": safe_message, "parse_mode": "Markdown",
                  "disable_web_page_preview": True},
            timeout=10
        )
        if r.ok:
            print("  ✓ Notificación Telegram enviada")
        else:
            print(f"  ⚠ Telegram error: {r.text[:100]}")
    except Exception as e:
        print(f"  ⚠ Telegram no disponible: {e}")


# ── State ─────────────────────────────────────────────────────────────────────

def load_env() -> dict:
    env = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def load_state() -> dict:
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(state: dict):
    if STATE_FILE.exists():
        shutil.copy2(STATE_FILE, STATE_FILE.with_suffix(".backup.json"))
    tmp = STATE_FILE.with_suffix(".tmp.json")
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ── Program: dedup + create ───────────────────────────────────────────────────

def find_or_create_program(state: dict, sess: requests.Session, dry_run: bool) -> str:
    """
    Busca el programa en Bounty Radar por nombre+plataforma.
    Si no existe, lo crea con los datos de current_hunt.json.
    Nunca crea duplicados.
    """
    protocol  = state.get("protocol", "")
    platform  = PLATFORM_MAP.get(state.get("platform", "").lower(), "CANTINA")
    keywords  = [kw for kw in re.split(r"[-_\s]+", protocol.lower()) if len(kw) > 3]

    programs = api_get("/api/programs", sess)

    # Dedup: buscar por plataforma + cualquier keyword del nombre del protocolo
    matches = [
        p for p in programs
        if p.get("platform") == platform
        and any(kw in p["name"].lower() for kw in keywords)
    ]

    if len(matches) == 1:
        print(f"  ✓ Program encontrado: {matches[0]['name']} ({matches[0]['id']})")
        return matches[0]["id"]

    if len(matches) > 1:
        # Múltiples matches — tomar el de mayor score
        best = max(matches, key=lambda p: p.get("score", 0))
        print(f"  ⚠ Múltiples programs encontrados, usando el de mayor score: {best['name']}")
        return best["id"]

    # No existe — crear
    print(f"  Program '{protocol}' no encontrado en Bounty Radar. Creando...")

    max_payout = parse_payout(state.get("payout", "0"))

    deadline = state.get("deadline")
    end_date = None
    if deadline:
        try:
            end_date = datetime.strptime(deadline, "%Y-%m-%d").isoformat() + "Z"
        except ValueError:
            pass

    # Dominio principal del protocolo → categoría
    domains = list(set(state.get("component_domains", {}).values()))
    primary_domain = domains[0] if domains else "OTHER"
    category = CATEGORY_MAP.get(primary_domain.lower(), "OTHER")

    repo_url = state.get("repo_path", "")
    repo_urls = []
    if repo_url and "github" in repo_url:
        repo_urls = [repo_url]

    payload = {
        "platform":    platform,
        "name":        protocol,
        "url":         "",
        "type":        "CONTEST",
        "maxPayout":   max_payout,
        "poolSize":    max_payout,
        "category":    category,
        "repoUrls":    repo_urls,
        "commitHash":  state.get("commit"),
        "endDate":     end_date,
        "status":      "ANALYZING",
        "notes":       f"Hunt iniciado con MultiHunter. Repo: {state.get('repo_path', '')}",
    }

    if dry_run:
        print(f"  [DRY-RUN] Crearía program: {payload['name']} ({platform}, {category}, ${max_payout:,})")
        return "dry-run-program-id"

    result = api_post("/api/programs", payload, sess)
    program_id = result["id"]
    print(f"  ✓ Program creado: {result['name']} ({program_id})")
    return program_id


# ── Finding: dedup ────────────────────────────────────────────────────────────

def check_finding_duplicate(finding_id: str, program_id: str, state: dict, sess: requests.Session) -> str | None:
    """
    Nivel 1: local — radar_id en current_hunt.json
    Nivel 2: remoto — GET /api/findings, busca [finding_id] en títulos del programa
    """
    for f in state.get("findings", []):
        if f.get("id") == finding_id and f.get("radar_id"):
            return f["radar_id"]

    findings = api_get("/api/findings", sess)
    tag = f"[{finding_id}]"
    for f in findings:
        if f.get("programId") == program_id and tag in (f.get("title") or ""):
            return f["id"]

    return None


# ── Hypothesis + PoC ──────────────────────────────────────────────────────────

def find_hypothesis(finding_id: str) -> tuple[dict, Path]:
    for hyp_path in sorted(HYP_DIR.glob("hyp_*.yaml")):
        try:
            data = yaml.safe_load(hyp_path.read_text())
        except Exception:
            continue
        if not data:
            continue
        for key in ("invariants", "findings", "hypotheses"):
            for entry in (data.get(key) or []):
                if isinstance(entry, dict) and entry.get("id") == finding_id:
                    return entry, hyp_path
    raise ValueError(f"Finding '{finding_id}' no encontrado en ningún hyp_*.yaml")


def find_report(finding_id: str, state_entry: dict | None) -> tuple[str | None, str | None]:
    """
    Busca el markdown del reporte generado por ReportWriter.
    Retorna (contenido, título_extraído) o (None, None) si no existe.
    Orden de búsqueda:
    1. report_file en current_hunt.json (guardado por ReportWriter)
    2. Autodetección por nombre en REPO_DIR/reports/
    """
    # 1. Ruta registrada en el estado
    repo_dir = get_repo_dir()
    report_path = None
    if state_entry and state_entry.get("report_file"):
        p = Path(state_entry["report_file"])
        if not p.is_absolute():
            p = repo_dir / state_entry["report_file"]
        if p.exists():
            report_path = p

    # 2. Autodetección por finding_id en reports/
    if not report_path:
        reports_dir = repo_dir / "reports"
        if reports_dir.exists():
            clean = finding_id.replace("-", "").replace("_", "").lower()
            for md in reports_dir.glob("*.md"):
                if finding_id.lower() in md.name.lower() or clean in md.name.lower():
                    report_path = md
                    break

    if not report_path:
        return None, None

    content = report_path.read_text()

    # Extraer título: primero H1, si no hay H1 tomar el primer H2
    title = None
    first_h2 = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not stripped.startswith("## "):
            title = stripped[2:].strip()
            break
        if first_h2 is None and stripped.startswith("## "):
            first_h2 = stripped[3:].strip()
    if not title:
        title = first_h2

    return content, title


def find_poc(finding_id: str, explicit_path: str | None) -> str | None:
    repo_dir = get_repo_dir()
    if explicit_path:
        p = Path(explicit_path)
        if not p.is_absolute():
            p = repo_dir / explicit_path
        return p.read_text() if p.exists() else None

    clean = finding_id.replace("-", "").replace("_", "")
    candidates = [
        repo_dir / f"test/chimera/PoC_{clean}.t.sol",
        repo_dir / f"test/chimera/PoC_{finding_id}.t.sol",
        repo_dir / f"test/PoC_{clean}.t.sol",
    ]
    for c in candidates:
        if c.exists():
            return c.read_text()

    test_dir = repo_dir / "test"
    if test_dir.exists():
        for sol in test_dir.rglob("*.sol"):
            if clean.lower() in sol.stem.lower() or finding_id.lower() in sol.stem.lower():
                return sol.read_text()

    return None


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Crea finding en Bounty Radar + genera draft")
    parser.add_argument("--finding",      required=True, metavar="ID")
    parser.add_argument("--poc",          metavar="FILE", help="Path al PoC (autodetectado si no)")
    parser.add_argument("--dry-run",      action="store_true")
    parser.add_argument("--password")
    parser.add_argument("--estimate-min", type=int, metavar="USD", help="Payout mínimo estimado (override auto)")
    parser.add_argument("--estimate-max", type=int, metavar="USD", help="Payout máximo estimado (override auto)")
    args = parser.parse_args()

    env      = load_env()
    password = args.password or env.get("BOUNTY_RADAR_PASSWORD", "")
    if not password:
        print("✗ Falta BOUNTY_RADAR_PASSWORD en .env")
        sys.exit(1)

    finding_id = args.finding
    state      = load_state()
    sess       = make_session(password)

    print(f"\n{'='*60}")
    print(f"  REPORT FINDING: {finding_id}")
    print(f"{'='*60}")

    # ── 1. Hipótesis ─────────────────────────────────────────────────────────
    print(f"\n[1/6] Buscando hipótesis...")
    state_entry = next((f for f in state.get("findings", []) if f.get("id") == finding_id), None)
    try:
        hyp, hyp_path = find_hypothesis(finding_id)
        print(f"  ✓ {hyp_path.name} | Tier {hyp.get('tier')} | {hyp.get('confidence')}% confidence")
    except ValueError as e:
        if state_entry:
            print(f"  ⚠ {e} — usando current_hunt.json como fallback")
            hyp = {
                "id": finding_id,
                # title > description > root_cause como fallback en cascada
                "description": (state_entry.get("description")
                                or state_entry.get("title")
                                or state_entry.get("root_cause")
                                or ""),
                "tier": 1,
                "confidence": state_entry.get("confidence", 80),
                "solidity": "",
            }
        else:
            print(f"  ✗ {e}")
            sys.exit(1)

    # Validar status reportable
    if state_entry:
        status = state_entry.get("status", "hypothesis")
        # Si ya tiene radar_id → skip limpio (no doble-registro)
        if state_entry.get("radar_id") and status not in ("hypothesis", "confirmed"):
            print(f"  ⚠ Finding ya registrado en Bounty Radar: {state_entry['radar_id']}")
            print(f"  Status local: {status} | radar_status: {state_entry.get('radar_status', '?')}")
            print(f"  Usa submit_finding.py --update {finding_id} --status <nuevo> para cambiarlo.")
            sys.exit(0)
        if status not in ("hypothesis", "confirmed", "registered"):
            print(f"  ✗ Status '{status}' — no registrable (usa submit_finding.py para actualizarlo)")
            sys.exit(1)
        if status == "hypothesis" and not args.dry_run:
            print(f"\n  ⚠ HIPÓTESIS sin PoC confirmado en fork.")
            if input("  ¿Continuar? (escribe 'si'): ").strip().lower() != "si":
                sys.exit(0)

    # ── 2. Reporte markdown (ReportWriter output) ─────────────────────────────
    print(f"\n[2/6] Buscando reporte markdown...")
    report_content, report_title = find_report(finding_id, state_entry)
    if report_content:
        print(f"  ✓ Reporte encontrado ({len(report_content)} chars) | Título: {report_title[:80] if report_title else 'N/A'}")
    else:
        print(f"  ⚠ Sin reporte markdown — usando descripción del YAML (ejecuta ReportWriter primero)")

    # ── 3. PoC ───────────────────────────────────────────────────────────────
    print(f"\n[3/6] Buscando PoC...")
    # Autodetect from state_entry.poc_file if no explicit --poc
    explicit_poc = args.poc
    if not explicit_poc and state_entry and state_entry.get("poc_file"):
        explicit_poc = state_entry["poc_file"]
    poc_code = find_poc(finding_id, explicit_poc)
    # Precedencia:
    #   1. .sol file encontrado → pocCode = contenido, VERIFIED
    #   2. report_content existe → PoC inline en descripción (ReportWriter garantiza fork confirmado), VERIFIED
    #   3. Ninguno → DRAFT (no registrar sin PoC)
    if poc_code:
        poc_status = "PASSING"
        print(f"  ✓ PoC .sol encontrado ({len(poc_code)} chars)")
    elif report_content:
        poc_status = "PASSING"  # PoC inline en el markdown de ReportWriter
        print(f"  ✓ PoC inline en reporte markdown (ReportWriter confirmado)")
    else:
        poc_status = "NONE"
        print(f"  ⚠ Sin PoC")

    # ── 4. Program ───────────────────────────────────────────────────────────
    print(f"\n[4/6] Verificando program en Bounty Radar...")
    program_id = find_or_create_program(state, sess, args.dry_run)

    # ── 5. Dedup finding ─────────────────────────────────────────────────────
    print(f"\n[5/6] Verificando duplicados...")
    existing = check_finding_duplicate(finding_id, program_id, state, sess)
    if existing:
        print(f"  ⚠ Ya existe: {BASE_URL}/findings/{existing}")
        print(f"  Usa submit_finding.py --update {finding_id} --status ... para actualizarlo.")
        sys.exit(0)
    print(f"  ✓ No existe — creando")

    # ── 6. Construir payload ──────────────────────────────────────────────────
    component    = (state_entry or {}).get("component", "")
    # severity: cascada — state_entry.severity_final > state_entry.severity > hyp.escalation_to > hyp.severity > MEDIUM
    severity_raw = (
        (state_entry or {}).get("severity_final")
        or (state_entry or {}).get("severity")
        or hyp.get("escalation_to")
        or hyp.get("severity")
        or "unknown"
    ).lower()
    severity = SEVERITY_MAP.get(severity_raw, "MEDIUM")

    # Payout estimates: derivados de maxPayout del programa + severidad
    max_payout = parse_payout(state.get("payout", "0"))
    program_type = state.get("program_type", "bug_bounty")
    est_min, est_max = estimate_payout(severity, max_payout, program_type)
    if args.estimate_min is not None:
        est_min = args.estimate_min
    if args.estimate_max is not None:
        est_max = args.estimate_max

    # Descripción: usar el markdown de ReportWriter si existe, fallback al YAML
    # Cantina limita títulos a 120 chars — truncar en palabra completa
    def _truncate_title(prefix: str, body: str, max_len: int = 120) -> str:
        if len(prefix) + len(body) <= max_len:
            return f"{prefix}{body}"
        avail = max_len - len(prefix)
        truncated = body[:avail].rsplit(' ', 1)[0]  # cortar en palabra completa
        return f"{prefix}{truncated}"

    if report_content:
        full_desc = report_content
        _body = report_title if report_title else hyp.get('description', '')
        title = _truncate_title(f"[{finding_id}] ", _body)
    else:
        description     = hyp.get("description", "")
        attack_scenario = hyp.get("attack_scenario", "")
        notes           = hyp.get("notes", "")
        full_desc = description
        if attack_scenario:
            full_desc += f"\n\n**Attack Scenario:**\n{attack_scenario}"
        if notes:
            full_desc += f"\n\n**Notes:**\n{notes}"
        title = _truncate_title(f"[{finding_id}] ", description)

    # Impact y likelihood: leer del state_entry (guardados por RedTeam o manualmente).
    # Si no están, derivar defaults razonables desde severity para no enviar null.
    _IMPACT_DEFAULTS    = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
    _LIKELIHOOD_DEFAULTS = {"CRITICAL": "High", "HIGH": "Medium", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
    impact_val     = (state_entry or {}).get("impact_rating") \
                     or (state_entry or {}).get("impact") \
                     or _IMPACT_DEFAULTS.get(severity, "Medium")
    likelihood_val = (state_entry or {}).get("likelihood") \
                     or _LIKELIHOOD_DEFAULTS.get(severity, "Medium")
    # Normalizar a capitalización correcta (UI acepta "High"/"Medium"/"Low"/"Critical")
    _VALID_IMPACT     = {"Critical", "High", "Medium", "Low"}
    _VALID_LIKELIHOOD = {"High", "Medium", "Low"}
    impact_val     = impact_val.capitalize() if impact_val.capitalize() in _VALID_IMPACT else _IMPACT_DEFAULTS.get(severity, "Medium")
    likelihood_val = likelihood_val.capitalize() if likelihood_val.capitalize() in _VALID_LIKELIHOOD else _LIKELIHOOD_DEFAULTS.get(severity, "Medium")

    # Duplicate risk: parse from immunefi_assessment.risk_of_duplicate in YAML
    dup_risk_label = None
    dup_risk_pct = None
    raw_dup_risk = (hyp.get("immunefi_assessment") or {}).get("risk_of_duplicate", "")
    if not raw_dup_risk:
        raw_dup_risk = hyp.get("risk_of_duplicate", "")
    if raw_dup_risk:
        raw_upper = raw_dup_risk.upper()
        if "HIGH" in raw_upper:
            dup_risk_label = "HIGH"
        elif "MEDIUM" in raw_upper or "MED" in raw_upper:
            dup_risk_label = "MEDIUM"
        elif "LOW" in raw_upper:
            dup_risk_label = "LOW"
        # Extract percentage if present: "HIGH (80%)" -> 80
        pct_match = re.search(r'(\d+)\s*%', raw_dup_risk)
        if pct_match:
            dup_risk_pct = int(pct_match.group(1))

    payload = {
        "programId":    program_id,
        "title":        title,
        "severity":     severity,
        "impact":       impact_val,
        "likelihood":   likelihood_val,
        "affectedFile": f"src/{component}.sol" if component else "",
        "description":  full_desc,
        "codeSnippet":  hyp.get("solidity", ""),
        "pocCode":      poc_code or "",
        "pocStatus":    poc_status,
        "status":       "DRAFT",  # API requires DRAFT on creation; use PATCH to transition
        "estimateMin":  est_min,
        "estimateMax":  est_max,
        "duplicateRisk":    dup_risk_label,
        "duplicateRiskPct": dup_risk_pct,
        "payoutAmount": None,  # se actualiza en submit_finding.py --update --payout
    }

    if args.dry_run:
        est_range = f"${est_min:,}–${est_max:,}" if est_min is not None else "N/A"
        print(f"\n{'='*60}\n  DRY RUN\n{'='*60}")
        dup_info = f"{dup_risk_label} ({dup_risk_pct}%)" if dup_risk_label else "N/A"
        print(f"  Title:    {title}")
        print(f"  Severity: {severity} | Impact: {impact_val} | Likelihood: {likelihood_val}")
        print(f"  Dup Risk: {dup_info}")
        print(f"  PoC: {poc_status} | Status: {payload['status']}")
        print(f"  Estimate: {est_range} (maxPayout=${max_payout:,})")
        print(f"  Desc ({len(full_desc)} chars): {full_desc[:150]}...")
        return 0

    # ── Crear finding + draft ─────────────────────────────────────────────────
    print(f"\n[6/6] Creando finding...")
    try:
        result = api_post("/api/findings", payload, sess)
    except requests.HTTPError as e:
        print(f"  ✗ {e.response.text}")
        sys.exit(1)

    radar_id = result["id"]
    print(f"  ✓ Finding creado: {radar_id} | Status: {result['status']}")

    print(f"\n[6/6] Generando draft del reporte (Claude)...")
    try:
        draft = api_post(f"/api/findings/{radar_id}/generate-report", {}, sess)
        print(f"  ✓ Draft generado ({len(draft.get('draft', ''))} chars)")
    except Exception as e:
        print(f"  ⚠ Draft no generado: {e} — genera desde la UI")

    # ── Actualizar state ──────────────────────────────────────────────────────
    if state_entry:
        for f in state["findings"]:
            if f.get("id") == finding_id:
                f["radar_id"]     = radar_id
                f["radar_status"] = result["status"]
                f["status"]       = "registered"   # avanza el estado local
                break
    else:
        state.setdefault("findings", []).append({
            "id": finding_id, "status": "registered",
            "radar_id": radar_id, "radar_status": result["status"],
            "component": component,
        })
    save_state(state)
    print(f"  ✓ radar_id guardado en current_hunt.json")

    # ── Telegram ─────────────────────────────────────────────────────────────
    protocol  = state.get("protocol", "unknown")
    est_range = f"${est_min:,}–${est_max:,}" if est_min is not None else "sin estimación"
    dup_info = f"{dup_risk_label} ({dup_risk_pct}%)" if dup_risk_label else "N/A"
    msg = (
        f"🎯 *Nuevo Finding Registrado*\n\n"
        f"*{finding_id}* — {severity}\n"
        f"Protocolo: {protocol}\n"
        f"Dup Risk: {dup_info}\n"
        f"PoC: {poc_status}\n"
        f"Status: {result['status']}\n"
        f"Estimación: {est_range}\n\n"
        f"[Ver en Bounty Radar]({BASE_URL}/findings/{radar_id})"
    )
    send_telegram(msg, sess)

    # ── Verificación GET ──────────────────────────────────────────────────────
    print(f"\n[✓] Verificando finding en Bounty Radar...")
    try:
        confirmed = api_get(f"/api/findings/{radar_id}", sess)
        print(f"  ✓ GET /api/findings/{radar_id} → status: {confirmed.get('status')} | severity: {confirmed.get('severity')} | title: {confirmed.get('title', '')[:60]}")
    except Exception as e:
        print(f"  ⚠ No se pudo verificar: {e}")

    # ── Resumen ───────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  ✓ FINDING REGISTRADO")
    print(f"{'='*60}")
    print(f"  URL: {BASE_URL}/findings/{radar_id}")
    print(f"\n  Próximo paso: revisa el draft y cuando lo reportes en Cantina:")
    print(f"  python3 audit-agents/submit_finding.py --update {finding_id} \\")
    print(f"    --status REPORTED --submission-url <URL_CANTINA>")

    return 0


if __name__ == "__main__":
    sys.exit(main())
