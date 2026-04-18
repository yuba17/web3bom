#!/usr/bin/env python3
"""
sync_state.py — Sincroniza current_hunt.json con el estado real de Bounty Radar.

Uso:
    python3 audit-agents/sync_state.py
    python3 audit-agents/sync_state.py --dry-run
    python3 audit-agents/sync_state.py --verbose

Para cada finding con radar_id en current_hunt.json, consulta bugbounty.0mnia.dev
y actualiza el estado local si ha cambiado en la UI.
"""

import sys
import argparse
import requests
from pathlib import Path
from datetime import datetime

from constants import derive_session_token, RADAR_TO_LOCAL, REMOTE_SEVERITY

from paths import STATE_FILE
from state_manager import load_state as _sm_load_state, save_state as _sm_save_state

BASE_URL   = "https://bugbounty.0mnia.dev"
ENV_FILE   = Path.home() / "Documents/Web3/.env"


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
    """Wrapper around state_manager.load_state that exits if file missing."""
    if not STATE_FILE.exists():
        print("✗ current_hunt.json no encontrado")
        sys.exit(1)
    return _sm_load_state()


def save_state(state: dict):
    """Inject last_sync sidecar, then delegate to state_manager with backup."""
    state["last_sync"] = datetime.utcnow().isoformat() + "Z"
    _sm_save_state(state, backup=True)


def get_session(password: str) -> requests.Session:
    s = requests.Session()
    token = derive_session_token(password)
    s.cookies.set("br_session", token, domain="bugbounty.0mnia.dev")
    s.headers.update({"Content-Type": "application/json"})
    return s


def fetch_finding(radar_id: str, sess: requests.Session) -> dict | None:
    try:
        r = sess.get(f"{BASE_URL}/api/findings/{radar_id}", timeout=15)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            return None
        raise


def main():
    parser = argparse.ArgumentParser(description="Sincroniza current_hunt.json con Bounty Radar")
    parser.add_argument("--dry-run",  action="store_true", help="Muestra cambios sin guardar")
    parser.add_argument("--verbose",  action="store_true", help="Muestra todos los findings, no solo los que cambiaron")
    parser.add_argument("--password", help="BOUNTY_RADAR_PASSWORD (o usar .env)")
    args = parser.parse_args()

    env      = load_env()
    password = args.password or env.get("BOUNTY_RADAR_PASSWORD", "")
    if not password:
        print("✗ Falta BOUNTY_RADAR_PASSWORD en .env")
        sys.exit(1)

    state = load_state()
    sess  = get_session(password)

    findings = state.get("findings", [])
    syncable = [f for f in findings if f.get("radar_id")]

    print(f"\n{'='*55}")
    print(f"  SYNC BOUNTY RADAR → current_hunt.json")
    print(f"  Protocolo: {state.get('protocol', '?')} | Findings con radar_id: {len(syncable)}")
    print(f"{'='*55}\n")

    if not syncable:
        print("  Sin findings con radar_id — nada que sincronizar.")
        print("  Usa report_finding.py --finding <ID> para registrar findings.")
        return 0

    changes = []

    for f in findings:
        radar_id = f.get("radar_id")
        if not radar_id:
            if args.verbose:
                print(f"  [{f['id']}] Sin radar_id — skip")
            continue

        remote = fetch_finding(radar_id, sess)
        if remote is None:
            print(f"  ⚠ [{f['id']}] radar_id {radar_id} no encontrado en Bounty Radar")
            continue

        remote_status   = remote.get("status", "")
        remote_severity = remote.get("severity", "")
        remote_payout   = remote.get("payoutAmount")
        remote_url      = remote.get("submissionUrl", "")

        local_status   = f.get("status", "")
        local_severity = f.get("severity", "")

        new_status   = RADAR_TO_LOCAL.get(remote_status, local_status)
        new_severity = REMOTE_SEVERITY.get(remote_severity, local_severity)

        updated = False
        field_changes = []

        if new_status != local_status:
            f["status"] = new_status
            f["radar_status"] = remote_status
            field_changes.append(f"status: {local_status} → {new_status}")
            updated = True

        if new_severity != local_severity:
            f["severity"] = new_severity
            field_changes.append(f"severity: {local_severity} → {new_severity}")
            updated = True

        if remote_payout and f.get("payout") != remote_payout:
            f["payout"] = remote_payout
            field_changes.append(f"payout: ${remote_payout:,}")
            updated = True

            # Actualizar confirmed_findings si fue aceptado con payout
            if new_status == "accepted":
                state["confirmed_findings"] = state.get("confirmed_findings", 0)

        if remote_url and not f.get("submission_url"):
            f["submission_url"] = remote_url
            field_changes.append(f"submission_url guardada")
            updated = True

        if updated:
            changes.append((f["id"], field_changes))
            print(f"  ✓ [{f['id']}] {' | '.join(field_changes)}")
        elif args.verbose:
            print(f"  · [{f['id']}] Sin cambios (status: {local_status}, severity: {local_severity})")

    print()

    if not changes:
        print("  Todo sincronizado — sin cambios.")
    else:
        print(f"  {len(changes)} finding(s) actualizados.")
        if args.dry_run:
            print("  [DRY-RUN] Cambios NO guardados.")
        else:
            save_state(state)
            print(f"  ✓ current_hunt.json actualizado.")

    print(f"\n  URL Bounty Radar: {BASE_URL}/findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
