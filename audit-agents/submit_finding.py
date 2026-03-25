#!/usr/bin/env python3
"""
submit_finding.py — Integración con Bounty Radar (bugbounty.0mnia.dev)

Uso:
    python3 submit_finding.py --list-programs
    python3 submit_finding.py --show GM-A-08
    python3 submit_finding.py --update GM-A-08 --status VERIFIED
    python3 submit_finding.py --update GM-A-08 --status REPORTED --submission-url https://cantina.xyz/...
    python3 submit_finding.py --update GM-A-08 --status ACCEPTED --payout 7500
    python3 submit_finding.py --update GM-A-08 --status REJECTED --note "duplicate of issue #45"
    python3 submit_finding.py --reset GM-A-08 --to-status POC_READY   # delete+recreate
    python3 submit_finding.py --sync                                    # pull radar → local
"""

import sys
import json
import shutil
import argparse
import requests
from pathlib import Path

from constants import (
    derive_session_token,
    RADAR_TO_LOCAL,
    SEVERITY_MAP,
    CATEGORY_MAP,
    ALLOWED_PATCH,
    REQUIRES_RESET,
)

# Config
BASE_URL   = "https://bugbounty.0mnia.dev"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
ENV_FILE   = Path.home() / "Documents/Web3/.env"
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

# ── Helpers ───────────────────────────────────────────────────────────────────

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
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


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


def get_session(password: str) -> requests.Session:
    s = requests.Session()
    token = derive_session_token(password)
    s.cookies.set("br_session", token, domain="bugbounty.0mnia.dev")
    s.headers.update({"Content-Type": "application/json"})
    return s


def api_get(path: str, sess: requests.Session) -> dict | list:
    r = sess.get(f"{BASE_URL}{path}", timeout=15)
    r.raise_for_status()
    return r.json()


def api_post(path: str, data: dict, sess: requests.Session) -> dict:
    r = sess.post(f"{BASE_URL}{path}", json=data, timeout=15)
    r.raise_for_status()
    return r.json()


def api_patch(path: str, data: dict, sess: requests.Session) -> dict:
    r = sess.patch(f"{BASE_URL}{path}", json=data, timeout=15)
    r.raise_for_status()
    return r.json()


def api_delete(path: str, sess: requests.Session) -> bool:
    r = sess.delete(f"{BASE_URL}{path}", timeout=15)
    return r.status_code in (200, 204)


def find_in_state(state: dict, finding_id: str) -> dict | None:
    for f in state.get("findings", []):
        if f.get("id") == finding_id:
            return f
    return None


def read_poc(poc_file: str) -> str:
    """Lee el PoC del repo."""
    p = get_repo_dir() / poc_file
    if p.exists():
        return p.read_text()
    return ""


def _truncate_title(prefix: str, body: str, max_len: int = 120) -> str:
    """Trunca título a max_len chars, cortando en palabra completa (Cantina limit)."""
    if len(prefix) + len(body) <= max_len:
        return f"{prefix}{body}"
    avail = max_len - len(prefix)
    truncated = body[:avail].rsplit(' ', 1)[0]
    return f"{prefix}{truncated}"


def build_creation_payload(state: dict, finding: dict, program_id: str,
                            target_status: str = "POC_READY") -> dict:
    """Construye el payload para POST /api/findings desde current_hunt.json."""
    # Preferir severity_final (post-RedTeam) sobre severity (propuesta inicial)
    sev_raw_key  = "severity_final" if finding.get("severity_final") else "severity"
    severity_raw = finding.get(sev_raw_key, "unknown").lower()
    severity     = SEVERITY_MAP.get(severity_raw, "MEDIUM")
    component    = finding.get("component", "")
    fid          = finding.get("id", "")
    description  = finding.get("description", "")

    # Payout estimate
    payout_str = state.get("payout", "0").replace("$", "").replace("K", "000").replace(",", "")
    try:
        max_payout = int(payout_str)
    except ValueError:
        max_payout = 0
    pct_map = {
        "CRITICAL": (0.40, 1.00), "HIGH": (0.15, 0.40),
        "MEDIUM": (0.05, 0.15),   "LOW": (0.01, 0.05), "INFO": (0.00, 0.01),
    }
    pct = pct_map.get(severity, (0.05, 0.15))
    est_min = int(max_payout * pct[0]) if max_payout else None
    est_max = int(max_payout * pct[1]) if max_payout else None

    # PoC
    poc_file = finding.get("poc_file", "")
    poc_code = read_poc(poc_file) if poc_file else ""
    poc_status = "PASSING" if poc_code else "NONE"

    # Report content
    report_file = finding.get("report_file", "")
    report_content = ""
    if report_file:
        rp = get_repo_dir() / report_file
        if rp.exists():
            report_content = rp.read_text()

    domain = state.get("component_domains", {}).get(component, "OTHER")
    category = CATEGORY_MAP.get(domain.lower(), "OTHER")

    # Impact y likelihood: leer del finding, fallback a defaults por severidad
    _IMPACT_DEFAULTS     = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
    _LIKELIHOOD_DEFAULTS = {"CRITICAL": "High", "HIGH": "Medium", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Low"}
    _VALID_IMPACT        = {"Critical", "High", "Medium", "Low"}
    _VALID_LIKELIHOOD    = {"High", "Medium", "Low"}
    raw_impact     = finding.get("impact_rating") or finding.get("impact") or _IMPACT_DEFAULTS.get(severity, "Medium")
    raw_likelihood = finding.get("likelihood") or _LIKELIHOOD_DEFAULTS.get(severity, "Medium")
    impact_val     = raw_impact.capitalize() if raw_impact.capitalize() in _VALID_IMPACT else _IMPACT_DEFAULTS.get(severity, "Medium")
    likelihood_val = raw_likelihood.capitalize() if raw_likelihood.capitalize() in _VALID_LIKELIHOOD else _LIKELIHOOD_DEFAULTS.get(severity, "Medium")

    return {
        "programId":    program_id,
        "title":        _truncate_title(f"[{fid}] ", description),
        "severity":     severity,
        "impact":       impact_val,
        "likelihood":   likelihood_val,
        "category":     category,
        "affectedFile": f"src/{component}.sol",
        "description":  report_content or description,
        "pocCode":      poc_code,
        "pocStatus":    poc_status,
        "status":       target_status,
        "estimateMin":  est_min,
        "estimateMax":  est_max,
    }


# ── Comandos ──────────────────────────────────────────────────────────────────

def list_programs(sess: requests.Session):
    programs = api_get("/api/programs", sess)
    print(f"\n{'ID':<28} {'Platform':<12} {'Name':<35} {'Status'}")
    print("-" * 90)
    for p in programs:
        print(f"{p['id']:<28} {p['platform']:<12} {p['name'][:34]:<35} {p['status']}")


def show_finding(finding_id: str, sess: requests.Session):
    """Muestra estado local + Bounty Radar side by side."""
    state   = load_state()
    finding = find_in_state(state, finding_id)

    if not finding:
        print(f"✗ '{finding_id}' no encontrado en current_hunt.json")
        sys.exit(1)

    radar_id = finding.get("radar_id")

    print(f"\n{'='*55}")
    print(f"  {finding_id}")
    print(f"{'='*55}")
    print(f"  LOCAL")
    print(f"    status:       {finding.get('status')}")
    print(f"    severity:     {finding.get('severity')}")
    print(f"    radar_status: {finding.get('radar_status', '—')}")
    print(f"    radar_id:     {radar_id or '—'}")

    if radar_id:
        try:
            f = api_get(f"/api/findings/{radar_id}", sess)
            print(f"\n  BOUNTY RADAR")
            print(f"    status:       {f.get('status')}")
            print(f"    pocStatus:    {f.get('pocStatus')}")
            print(f"    severity:     {f.get('severity')}")
            print(f"    submittedAt:  {f.get('submittedAt') or '—'}")
            print(f"    submissionUrl:{f.get('submissionUrl') or '—'}")
            print(f"    payoutAmount: {f.get('payoutAmount') or '—'}")
            current = f.get('status', '')
            allowed = ALLOWED_PATCH.get(current, [])
            needs_reset = REQUIRES_RESET.get(current, [])
            print(f"\n  TRANSICIONES DISPONIBLES")
            if allowed:
                print(f"    vía --update:  {', '.join(allowed)}")
            else:
                print(f"    vía --update:  ninguna (estado terminal)")
            if needs_reset:
                print(f"    vía --reset:   {', '.join(needs_reset)}")
            print(f"\n  URL: {BASE_URL}/findings/{radar_id}")
        except requests.HTTPError as e:
            print(f"\n  ✗ Error al consultar Bounty Radar: {e}")
    print()


def update_finding(finding_id: str, new_status: str, sess: requests.Session,
                   payout: int | None, note: str | None, submission_url: str | None):
    """Actualiza status via PATCH. Si la transición no está permitida, sugiere --reset."""
    state   = load_state()
    finding = find_in_state(state, finding_id)

    if not finding:
        print(f"✗ '{finding_id}' no encontrado en current_hunt.json")
        sys.exit(1)

    radar_id = finding.get("radar_id")
    if not radar_id:
        print(f"✗ '{finding_id}' no tiene radar_id — regístralo primero con report_finding.py")
        sys.exit(1)

    # Pre-flight: obtener estado actual y validar transición
    current_data = api_get(f"/api/findings/{radar_id}", sess)
    current_status = current_data.get("status", "UNKNOWN")
    allowed = ALLOWED_PATCH.get(current_status, [])
    needs_reset = REQUIRES_RESET.get(current_status, [])

    if new_status not in allowed:
        print(f"\n✗ Transición bloqueada: {current_status} → {new_status}")
        if new_status in needs_reset:
            print(f"  Esta transición requiere delete+recreate.")
            print(f"  Usa: python3 submit_finding.py --reset {finding_id} --to-status {new_status}")
        elif allowed:
            print(f"  Transiciones permitidas desde {current_status}: {', '.join(allowed)}")
        else:
            print(f"  {current_status} es un estado terminal. No hay transiciones disponibles vía PATCH.")
            if needs_reset:
                print(f"  Transiciones posibles vía --reset: {', '.join(needs_reset)}")
        sys.exit(1)

    payload: dict = {"status": new_status}
    if payout is not None:
        payload["payoutAmount"] = payout
    if note:
        payload["rejectionNote"] = note
    if submission_url:
        payload["submissionUrl"] = submission_url

    result = api_patch(f"/api/findings/{radar_id}", payload, sess)
    print(f"\n✓ {finding_id}: {current_status} → {result['status']}")

    # Actualizar state local
    for f in state["findings"]:
        if f.get("id") == finding_id:
            f["radar_status"] = result["status"]
            local = RADAR_TO_LOCAL.get(result["status"])
            if local:
                f["status"] = local
            if payout:
                f["payout"] = payout
            if note:
                f.pop("radar_note", None)
            break

    if new_status == "ACCEPTED":
        state["confirmed_findings"] = state.get("confirmed_findings", 0) + 1
        print(f"  confirmed_findings → {state['confirmed_findings']}")
    elif new_status in ("REJECTED", "DUPLICATE"):
        print(f"  ℹ Finding {new_status.lower()} — documenta la lección.")

    save_state(state)
    print(f"  ✓ current_hunt.json actualizado")

    if submission_url:
        print(f"  URL: {submission_url}")


def reset_finding(finding_id: str, target_status: str, sess: requests.Session):
    """
    Delete + recreate: permite cualquier transición de vuelta.
    Preserva toda la metadata (pocCode, description, severity, etc.)
    """
    state   = load_state()
    finding = find_in_state(state, finding_id)

    if not finding:
        print(f"✗ '{finding_id}' no encontrado en current_hunt.json")
        sys.exit(1)

    radar_id = finding.get("radar_id")

    # Validar target_status es un estado de creación válido
    CREATABLE = ["DRAFT", "POC_READY", "ANALYZING", "VERIFIED"]
    if target_status not in CREATABLE:
        print(f"✗ '{target_status}' no es un estado de creación válido.")
        print(f"  Estados posibles al recrear: {', '.join(CREATABLE)}")
        sys.exit(1)

    # Buscar program_id
    protocol = state.get("protocol", "")
    programs = api_get("/api/programs", sess)
    proto_norm = protocol.lower().replace("-", " ").replace("_", " ")
    matches = [p for p in programs if proto_norm in p["name"].lower() or
               any(word in p["name"].lower() for word in proto_norm.split() if len(word) > 3)]
    if not matches:
        print(f"✗ No se encontró program para '{protocol}'")
        sys.exit(1)
    program_id = matches[0]["id"]

    # Mostrar estado actual y pedir confirmación
    current_status = "—"
    if radar_id:
        try:
            current_data = api_get(f"/api/findings/{radar_id}", sess)
            current_status = current_data.get("status", "—")
        except Exception:
            pass

    print(f"\n  Finding:  {finding_id}")
    print(f"  radar_id: {radar_id or '(sin registro previo)'}")
    print(f"  Estado actual en Bounty Radar: {current_status}")
    print(f"  Estado objetivo tras recrear:  {target_status}")
    print(f"\n  ⚠  Esto BORRARÁ el finding actual y lo recreará con un nuevo ID.")
    confirm = input("  ¿Confirmas? (escribe 'si'): ").strip().lower()
    if confirm != "si":
        print("  Cancelado.")
        sys.exit(0)

    # Borrar finding actual
    if radar_id:
        deleted = api_delete(f"/api/findings/{radar_id}", sess)
        if deleted:
            print(f"\n  ✓ Borrado: {radar_id}")
        else:
            print(f"  ⚠ No se pudo borrar {radar_id} — puede que ya no exista, continuando.")

    # Recrear con nuevo status
    payload = build_creation_payload(state, finding, program_id, target_status)
    result = api_post("/api/findings", payload, sess)
    new_radar_id = result["id"]
    print(f"  ✓ Recreado: {new_radar_id} | status={result['status']}")

    # Actualizar state local con nuevo radar_id
    for f in state["findings"]:
        if f.get("id") == finding_id:
            f["radar_id"]     = new_radar_id
            f["radar_status"] = result["status"]
            f["status"]       = RADAR_TO_LOCAL.get(result["status"], f.get("status"))
            f.pop("radar_note", None)
            break

    save_state(state)
    print(f"  ✓ current_hunt.json actualizado con nuevo radar_id")
    print(f"\n  URL: {BASE_URL}/findings/{new_radar_id}")


def patch_fields(finding_id: str, sess: requests.Session,
                 impact: str | None, likelihood: str | None, severity: str | None):
    """
    PATCH campos de metadata (impact, likelihood, severity) sin cambiar el status.
    Útil para corregir valores mal enviados en el registro inicial.
    """
    state   = load_state()
    finding = find_in_state(state, finding_id)
    if not finding:
        print(f"✗ '{finding_id}' no encontrado en current_hunt.json")
        sys.exit(1)
    radar_id = finding.get("radar_id")
    if not radar_id:
        print(f"✗ '{finding_id}' no tiene radar_id")
        sys.exit(1)

    _VALID_IMPACT     = {"Critical", "High", "Medium", "Low"}
    _VALID_LIKELIHOOD = {"High", "Medium", "Low"}
    _VALID_SEVERITY   = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    payload: dict = {}
    if impact:
        v = impact.capitalize()
        if v not in _VALID_IMPACT:
            print(f"✗ impact inválido '{impact}'. Válidos: {sorted(_VALID_IMPACT)}")
            sys.exit(1)
        payload["impact"] = v
        finding["impact_rating"] = v
    if likelihood:
        v = likelihood.capitalize()
        if v not in _VALID_LIKELIHOOD:
            print(f"✗ likelihood inválido '{likelihood}'. Válidos: {sorted(_VALID_LIKELIHOOD)}")
            sys.exit(1)
        payload["likelihood"] = v
        finding["likelihood"] = v
    if severity:
        v = severity.upper()
        if v not in _VALID_SEVERITY:
            print(f"✗ severity inválido '{severity}'. Válidos: {sorted(_VALID_SEVERITY)}")
            sys.exit(1)
        payload["severity"] = v
        finding["severity_final"] = v.lower()

    if not payload:
        print("✗ Nada que patchear — usa --impact, --likelihood y/o --severity")
        sys.exit(1)

    result = api_patch(f"/api/findings/{radar_id}", payload, sess)
    print(f"\n✓ {finding_id} actualizado:")
    for k in ("severity", "impact", "likelihood"):
        if k in payload:
            print(f"  {k}: {result.get(k)}")

    save_state(state)
    print(f"  ✓ current_hunt.json actualizado")


def sync_all(sess: requests.Session):
    """Pull Bounty Radar → actualiza radar_status en current_hunt.json."""
    state = load_state()
    findings_local = {f.get("radar_id"): f for f in state.get("findings", []) if f.get("radar_id")}

    if not findings_local:
        print("No hay findings con radar_id en current_hunt.json")
        return

    all_radar = api_get("/api/findings", sess)
    radar_by_id = {f["id"]: f for f in all_radar}

    updated = 0
    print(f"\n{'Finding':<12} {'Local radar_status':<18} {'Radar real':<18} {'Sync'}")
    print("-" * 60)
    for radar_id, local_f in findings_local.items():
        fid           = local_f.get("id", "?")
        local_rs      = local_f.get("radar_status", "—")
        radar_f       = radar_by_id.get(radar_id)
        if not radar_f:
            print(f"{fid:<12} {local_rs:<18} {'(not found)':<18} ⚠ borrado en radar")
            continue
        real_rs = radar_f.get("status", "—")
        if local_rs == real_rs:
            print(f"{fid:<12} {local_rs:<18} {real_rs:<18} ✅")
        else:
            # Actualizar local
            local_f["radar_status"] = real_rs
            new_local = RADAR_TO_LOCAL.get(real_rs)
            if new_local:
                local_f["status"] = new_local
            print(f"{fid:<12} {local_rs:<18} {real_rs:<18} ✅ corregido")
            updated += 1

    if updated:
        save_state(state)
        print(f"\n  ✓ {updated} finding(s) actualizados en current_hunt.json")
    else:
        print(f"\n  ✓ Todo sincronizado, sin cambios")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Integración con Bounty Radar")
    parser.add_argument("--list-programs", action="store_true")
    parser.add_argument("--show",        metavar="FINDING_ID", help="Muestra estado local + radar del finding")
    parser.add_argument("--update",      metavar="FINDING_ID", help="Actualiza status via PATCH")
    parser.add_argument("--patch",       metavar="FINDING_ID", help="Patchea campos de metadata (impact, likelihood, severity)")
    parser.add_argument("--reset",       metavar="FINDING_ID", help="Delete+recreate para transiciones hacia atrás")
    parser.add_argument("--to-status",   help="Status objetivo (para --reset)")
    parser.add_argument("--status",      help="Nuevo status (para --update)")
    parser.add_argument("--impact",      help="Impact rating: Critical|High|Medium|Low (para --patch)")
    parser.add_argument("--likelihood",  help="Likelihood: High|Medium|Low (para --patch)")
    parser.add_argument("--payout",      type=int)
    parser.add_argument("--note",        help="Nota de rechazo o contexto")
    parser.add_argument("--submission-url", help="URL de la submission en la plataforma")
    parser.add_argument("--sync",        action="store_true", help="Pull Bounty Radar → sincroniza local")
    parser.add_argument("--password")
    args = parser.parse_args()

    env      = load_env()
    password = args.password or env.get("BOUNTY_RADAR_PASSWORD", "")
    if not password:
        print("✗ Falta BOUNTY_RADAR_PASSWORD en .env o --password")
        sys.exit(1)

    sess = get_session(password)

    if args.list_programs:
        list_programs(sess)

    elif args.show:
        show_finding(args.show, sess)

    elif args.update:
        if not args.status:
            print("✗ --update requiere --status")
            sys.exit(1)
        update_finding(args.update, args.status.upper(), sess,
                       args.payout, args.note, args.submission_url)

    elif args.patch:
        patch_fields(args.patch, sess, args.impact, args.likelihood,
                     args.status)  # --status se reutiliza para severity aquí

    elif args.reset:
        if not args.to_status:
            print("✗ --reset requiere --to-status")
            sys.exit(1)
        reset_finding(args.reset, args.to_status.upper(), sess)

    elif args.sync:
        sync_all(sess)

    else:
        parser.print_help()


if __name__ == "__main__":
    sys.exit(main())
