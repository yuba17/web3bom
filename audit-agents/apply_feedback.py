#!/usr/bin/env python3
"""
apply_feedback.py — L8 Feedback Loop Automatizado
Lee pending_briefing_updates de fichas y los aplica a los briefings.
También procesa archivos de SYNTHESIS generados por work-completion.sh
y archivos de hipótesis en hunt_session/hypotheses/hyp_*.yaml.

Uso:
    python3 apply_feedback.py                    # procesa fichas e hipótesis del hunt activo
    python3 apply_feedback.py --dry-run          # muestra qué haría sin cambiar nada
    python3 apply_feedback.py --synthesis-only   # solo procesa archivos de SYNTHESIS
    python3 apply_feedback.py --ficha FILE.yaml  # procesa una ficha específica
    python3 apply_feedback.py --hypotheses       # procesa solo archivos de hipótesis
"""

import sys
import os
import re
import json
import yaml
import glob
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
import shutil

# Paths
WEB3_DIR = Path.home() / "Documents/Web3"
KNOWLEDGE_DIR = WEB3_DIR / "knowledge"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
VAULT_RAW = Path.home() / "obsidian-vault" / "web3-audit" / "_raw"


def _apply_path_overrides(*, knowledge_dir: str | None, vault_dir: str | None) -> None:
    """Override KNOWLEDGE_DIR and VAULT_RAW for testability and benchmark sandboxing.

    No-op when both args are None. vault_dir is treated as the vault root;
    VAULT_RAW becomes <vault_dir>/_raw.
    """
    global KNOWLEDGE_DIR, VAULT_RAW
    if knowledge_dir is not None:
        KNOWLEDGE_DIR = Path(knowledge_dir).resolve()
    if vault_dir is not None:
        VAULT_RAW = (Path(vault_dir) / "_raw").resolve()

def _load_protocol() -> str:
    """Load current protocol from hunt state."""
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text())
        return state.get("protocol", "unknown")
    return "unknown"

def get_hyp_dir(protocol: str) -> Path:
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d

MEMORY_DIR = Path.home() / ".claude/MEMORY"
SYNTHESIS_DIR = MEMORY_DIR / "LEARNING/SYNTHESIS"
FAILURES_DIR = MEMORY_DIR / "LEARNING/FAILURES"
EVENTS_FILE = MEMORY_DIR / "STATE/events.jsonl"

BRIEFING_MAP = {
    "vault": "vault-erc4626.md",
    "vault-erc4626": "vault-erc4626.md",
    "lending": "lending.md",
    "oracle": "oracle.md",
    "access-control": "access-control.md",
    "access": "access-control.md",
    "dex": "dex-amm.md",
    "dex-amm": "dex-amm.md",
    "staking": "staking.md",
    "flash-loan": "flash-loan.md",
    "flash": "flash-loan.md",
    "bridge": "bridge.md",
    "token": "token-erc20.md",
    "token-erc20": "token-erc20.md",
    "proxy": "proxy-upgrade.md",
    "proxy-upgrade": "proxy-upgrade.md",
    "zk": "zk-circuits.md",
    "zk-circuits": "zk-circuits.md",
    "signature": "signature-replay.md",
    "signature-replay": "signature-replay.md",
}


def emit_event(event_type: str, data: dict):
    """Emitir evento al stream de observabilidad."""
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": event_type,
        **data
    }
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def resolve_briefing(briefing_ref: str) -> Path | None:
    """Resuelve una referencia de briefing a un Path."""
    # Formato: "staking.md" o "staking.md/stk-004" o "staking"
    briefing_name = briefing_ref.split("/")[0].strip()

    # Primero intento directo
    direct = KNOWLEDGE_DIR / briefing_name
    if direct.exists():
        return direct

    # Luego por alias
    for alias, filename in BRIEFING_MAP.items():
        if alias in briefing_name.lower():
            candidate = KNOWLEDGE_DIR / filename
            if candidate.exists():
                return candidate

    return None


def add_to_trampas(briefing_path: Path, content: str, source: str, dry_run: bool) -> bool:
    """Añade una entrada al campo trampas del último bug entry del briefing."""
    if dry_run:
        print(f"  [DRY-RUN] Añadiría trampa a {briefing_path.name}:")
        print(f"    '{content[:80]}...' " if len(content) > 80 else f"    '{content}'")
        return True

    text = briefing_path.read_text()

    # Buscar el último bloque de trampas en el briefing
    # Añadimos al final de la sección de trampas del último bug
    trampa_entry = f'\n    - "{content}"  # añadido por apply_feedback — fuente: {source}'

    # Patrón: última ocurrencia de "trampas:" en el archivo
    last_trampas = text.rfind("  trampas:")
    if last_trampas == -1:
        # No hay sección trampas, añadir al final del archivo
        with open(briefing_path, "a") as f:
            f.write(f"\n\n<!-- FEEDBACK {datetime.utcnow().date()} -->\n")
            f.write(f"<!-- TRAMPA: {content} -->\n")
            f.write(f"<!-- FUENTE: {source} -->\n")
        print(f"  ✓ Trampa añadida al final de {briefing_path.name}")
        return True

    # Encontrar el final del bloque trampas (siguiente clave YAML al mismo nivel)
    after_trampas = last_trampas + len("  trampas:")
    # Buscar el siguiente campo YAML al mismo nivel (2 espacios de indentación)
    next_field = re.search(r'\n  \w', text[after_trampas:])

    if next_field:
        insert_pos = after_trampas + next_field.start()
        new_text = text[:insert_pos] + trampa_entry + text[insert_pos:]
    else:
        new_text = text + trampa_entry

    briefing_path.write_text(new_text)
    print(f"  ✓ Trampa añadida a {briefing_path.name}")
    return True


def add_bug_entry(briefing_path: Path, entry: dict, source: str, dry_run: bool) -> bool:
    """Añade una nueva bug entry al briefing."""
    if dry_run:
        entry_id = entry.get('id', 'unknown')
        print(f"  [DRY-RUN] Añadiría bug entry '{entry_id}' a {briefing_path.name}")
        return True

    # Generar YAML de la nueva entrada
    yaml_entry = yaml.dump([entry], default_flow_style=False, allow_unicode=True, indent=2)
    # Indentar para que encaje en el bloque de bugs
    indented = "\n".join("    " + line for line in yaml_entry.split("\n"))

    text = briefing_path.read_text()

    # Buscar el final de la sección "Bugs Conocidos"
    bugs_section = text.find("## 1. Bugs Conocidos")
    if bugs_section == -1:
        bugs_section = text.find("## Bugs Conocidos")

    if bugs_section == -1:
        # Añadir al final
        with open(briefing_path, "a") as f:
            f.write(f"\n\n## Nuevos Bugs (via apply_feedback — {source})\n\n```yaml\n{yaml_entry}```\n")
        print(f"  ✓ Bug entry añadida al final de {briefing_path.name}")
        return True

    # Buscar la siguiente sección ## después de Bugs Conocidos
    next_section = re.search(r'\n## [^1]', text[bugs_section + 20:])
    if next_section:
        insert_pos = bugs_section + 20 + next_section.start()
        addition = f"\n\n```yaml\n# Añadido por apply_feedback — fuente: {source}\n{yaml_entry}```\n"
        new_text = text[:insert_pos] + addition + text[insert_pos:]
    else:
        new_text = text + f"\n\n```yaml\n# Añadido por apply_feedback — fuente: {source}\n{yaml_entry}```\n"

    briefing_path.write_text(new_text)
    print(f"  ✓ Bug entry '{entry.get('id', 'unknown')}' añadida a {briefing_path.name}")
    return True


def process_update(update: dict, source: str, dry_run: bool) -> bool:
    """Procesa un pending_briefing_update individual."""
    action = update.get("action", "")
    briefing_ref = update.get("briefing", "")
    content = update.get("content", "")

    if not action or not briefing_ref:
        print(f"  ⚠ Update incompleto (falta action o briefing): {update}")
        return False

    briefing_path = resolve_briefing(briefing_ref)
    if not briefing_path:
        print(f"  ✗ No se encontró briefing '{briefing_ref}'")
        return False

    if action == "add_to_trampas":
        return add_to_trampas(briefing_path, content, source, dry_run)
    elif action == "add_bug_entry":
        entry = update.get("entry", {})
        if not entry:
            # Intentar parsear content como YAML
            try:
                entry = yaml.safe_load(content)
            except:
                entry = {"id": "unknown", "description": content}
        return add_bug_entry(briefing_path, entry, source, dry_run)
    elif action == "add_invariant":
        # Añadir invariante a la sección de invariantes clave
        if dry_run:
            print(f"  [DRY-RUN] Añadiría invariante a {briefing_path.name}: {content[:60]}")
            return True
        with open(briefing_path, "a") as f:
            f.write(f"\n<!-- INVARIANTE (via apply_feedback — {source}): {content} -->\n")
        print(f"  ✓ Invariante añadido a {briefing_path.name}")
        return True
    else:
        print(f"  ⚠ Acción desconocida: '{action}'")
        return False


_WIKI_STAGED_FILES: list[Path] = []


def wiki_ingest_finding(finding_id: str, hyp_path: Path, protocol: str):
    """Copy confirmed finding to Obsidian vault for persistent knowledge."""
    if not VAULT_RAW.exists():
        return
    dest = VAULT_RAW / f"finding_{protocol}_{finding_id}.yaml"
    if not dest.exists():
        shutil.copy2(hyp_path, dest)
        print(f"  [wiki] Staged {finding_id} for vault ingest")
        _WIKI_STAGED_FILES.append(dest)


def wiki_ingest_flush(dry_run: bool = False):
    """Promote everything in VAULT_RAW/ into the vault via /wiki-ingest skill.

    Runs after all findings for the session have been staged. Failure-tolerant:
    missing skill, timeout, or claude CLI absence do not abort apply_feedback.
    """
    if dry_run or not _WIKI_STAGED_FILES:
        return
    staged_names = ", ".join(p.name for p in _WIKI_STAGED_FILES[:8])
    if len(_WIKI_STAGED_FILES) > 8:
        staged_names += f" (+{len(_WIKI_STAGED_FILES) - 8} more)"
    prompt = (
        f"/wiki-ingest Promote all pending files under {VAULT_RAW} into the vault. "
        f"Newly staged findings this run: {staged_names}. "
        f"Deduplicate against existing pages and add cross-links where appropriate."
    )
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--output-format", "text"],
            capture_output=True, text=True, timeout=900
        )
        if result.returncode == 0:
            print(f"  [wiki-ingest] Flushed {len(_WIKI_STAGED_FILES)} staged finding(s) into vault")
        else:
            print(f"  [wiki-ingest] skill exited rc={result.returncode}: {result.stderr[:200]}")
    except FileNotFoundError:
        print("  [wiki-ingest] claude CLI not found, skipping flush")
    except subprocess.TimeoutExpired:
        print("  [wiki-ingest] Timeout after 15min, staged files remain in _raw/")


def process_ficha(ficha_path: Path, dry_run: bool) -> int:
    """Procesa una ficha YAML y aplica sus pending_briefing_updates."""
    try:
        with open(ficha_path) as f:
            ficha = yaml.safe_load(f)
    except Exception as e:
        print(f"  ✗ Error leyendo {ficha_path.name}: {e}")
        return 0

    if not ficha:
        return 0

    applied = 0
    source = f"{ficha.get('protocol', 'unknown')}/{ficha.get('component', ficha_path.stem)}"

    # NOTA: false_positives de fichas NO se aplican automáticamente.
    # Solo se aplican pending_briefing_updates manuales (confirmados por humano o fork PoC).

    # Buscar pending_briefing_updates directos
    direct_updates = ficha.get("pending_briefing_updates", [])
    for update in direct_updates:
        if isinstance(update, dict):
            if process_update(update, source, dry_run):
                applied += 1

    return applied


def process_hypothesis(hyp_path: Path, dry_run: bool) -> int:
    """Procesa un archivo de hipótesis YAML y aplica sus pending_briefing_updates.

    Reads:
      - false_positives[].pending_briefing_update  (singular dict per entry)
      - top-level pending_briefing_updates[]        (list of dicts)

    Skips entries that already have briefing_update_applied: true.
    After applying, writes briefing_update_applied: true back into the entry
    so the file is not processed twice.
    """
    try:
        with open(hyp_path) as f:
            hyp = yaml.safe_load(f)
    except Exception as e:
        print(f"  ✗ Error leyendo {hyp_path.name}: {e}")
        return 0

    if not hyp:
        return 0

    applied = 0
    dirty = False  # track whether we need to write back
    source = f"hyp/{hyp.get('hunter', hyp_path.stem)}/{hyp.get('component', '')}"

    # NOTA: false_positives de hipótesis NO se aplican automáticamente.
    # Un hunter de IA diciendo "esto es false positive" no es validación suficiente.
    # Solo se aplican cuando hay confirmación externa (plataforma) o fork PoC ejecutado por humano.

    # --- top-level pending_briefing_updates[] ---
    direct_updates = hyp.get("pending_briefing_updates", [])
    for update in direct_updates:
        if not isinstance(update, dict):
            continue
        if update.get("briefing_update_applied"):
            continue
        if process_update(update, source, dry_run):
            applied += 1
            if not dry_run:
                update["briefing_update_applied"] = True
                dirty = True

    # Stage validated findings for Obsidian vault
    protocol = _load_protocol()
    for inv in hyp.get("hypotheses", hyp.get("invariants", [])):
        if inv.get("validated") and inv.get("confidence", 0) >= 60:
            wiki_ingest_finding(inv.get("id", "unknown"), hyp_path, protocol)

    # Write back modified structure only when something changed
    if dirty and not dry_run:
        try:
            with open(hyp_path, "w") as f:
                yaml.dump(hyp, f, default_flow_style=False, allow_unicode=True, indent=2,
                          sort_keys=False)
            print(f"  ✓ {hyp_path.name} actualizado con briefing_update_applied markers")
        except Exception as e:
            print(f"  ✗ No se pudo escribir de vuelta {hyp_path.name}: {e}")

    return applied


def process_hypothesis_files(hyp_dir: Path, dry_run: bool) -> int:
    """Procesa todos los archivos hyp_*.yaml en hyp_dir."""
    if not hyp_dir.exists():
        print(f"Directorio de hipótesis no encontrado: {hyp_dir}")
        return 0

    hyp_files = sorted(hyp_dir.glob("hyp_*.yaml"))
    if not hyp_files:
        print(f"No hay archivos hyp_*.yaml en {hyp_dir}")
        return 0

    print(f"Encontrados {len(hyp_files)} archivos de hipótesis en {hyp_dir}")
    total = 0
    for hyp_path in hyp_files:
        print(f"\nProcesando hipótesis: {hyp_path.name}")
        applied = process_hypothesis(hyp_path, dry_run)
        print(f"  → {applied} updates aplicados")
        total += applied
    return total


def process_synthesis_files(dry_run: bool) -> int:
    """Procesa archivos de SYNTHESIS generados por work-completion.sh."""
    if not SYNTHESIS_DIR.exists():
        return 0

    applied = 0
    for md_file in SYNTHESIS_DIR.glob("*.md"):
        print(f"\nProcesando synthesis: {md_file.name}")
        try:
            content = md_file.read_text()
            # Extraer bloques YAML entre ``` yaml y ```
            yaml_blocks = re.findall(r'```yaml\n(.*?)```', content, re.DOTALL)
            for block in yaml_blocks:
                try:
                    updates = yaml.safe_load(block)
                    if isinstance(updates, list):
                        for update in updates:
                            if isinstance(update, dict) and "action" in update:
                                if process_update(update, md_file.stem, dry_run):
                                    applied += 1
                except:
                    pass
        except Exception as e:
            print(f"  ✗ Error: {e}")

    return applied


def mark_ficha_processed(ficha_path: Path, dry_run: bool):
    """Marca una ficha como procesada añadiendo timestamp (append — no re-serializa el YAML)."""
    if dry_run:
        return
    try:
        timestamp = datetime.utcnow().isoformat() + "Z"
        text = ficha_path.read_text()
        # Si ya tiene feedback_applied, actualizar la línea existente
        if "feedback_applied:" in text:
            new_text = re.sub(
                r'^feedback_applied:.*$',
                f'feedback_applied: "{timestamp}"',
                text,
                flags=re.MULTILINE
            )
            ficha_path.write_text(new_text)
        else:
            # Añadir al final como línea YAML simple
            with open(ficha_path, "a") as f:
                f.write(f'\nfeedback_applied: "{timestamp}"\n')
    except:
        pass


def main():
    parser = argparse.ArgumentParser(description="Aplica pending_briefing_updates a briefings")
    parser.add_argument("--dry-run", action="store_true", help="Muestra qué haría sin modificar nada")
    parser.add_argument("--synthesis-only", action="store_true", help="Solo procesa archivos SYNTHESIS")
    parser.add_argument("--hypotheses", action="store_true", help="Solo procesa archivos de hipótesis hyp_*.yaml")
    parser.add_argument("--ficha", type=str, help="Procesa una ficha específica")
    parser.add_argument("--fichas-dir", type=str, help="Directorio de fichas (default: hunt_session/fichas)")
    parser.add_argument("--hyp-dir", type=str, help="Directorio de hipótesis (default: hunt_session/hypotheses)")
    parser.add_argument("--knowledge-dir", default=None,
                        help="Override KNOWLEDGE_DIR (default: $WEB3_DIR/knowledge). "
                             "Used by tests and benchmark sandboxing.")
    parser.add_argument("--vault-dir", default=None,
                        help="Override Obsidian vault root "
                             "(default: ~/obsidian-vault/web3-audit). "
                             "VAULT_RAW becomes <vault-dir>/_raw.")
    args = parser.parse_args()
    _apply_path_overrides(knowledge_dir=args.knowledge_dir, vault_dir=args.vault_dir)

    if args.dry_run:
        print("=== DRY RUN — no se modificará nada ===\n")

    total_applied = 0

    # Modo: ficha específica
    if args.ficha:
        ficha_path = Path(args.ficha)
        if not ficha_path.exists():
            ficha_path = HUNT_SESSION_DIR / "fichas" / args.ficha
        if ficha_path.exists():
            print(f"\nProcesando ficha: {ficha_path}")
            applied = process_ficha(ficha_path, args.dry_run)
            print(f"  → {applied} updates aplicados")
            if applied > 0 and not args.dry_run:
                mark_ficha_processed(ficha_path, args.dry_run)
            total_applied += applied
        else:
            print(f"✗ Ficha no encontrada: {args.ficha}")
            sys.exit(1)

    # Modo: synthesis only
    elif args.synthesis_only:
        print("Procesando archivos SYNTHESIS...")
        total_applied += process_synthesis_files(args.dry_run)

    # Modo: solo hipótesis
    elif args.hypotheses:
        hyp_dir = Path(args.hyp_dir) if args.hyp_dir else get_hyp_dir(_load_protocol())
        print("Procesando archivos de hipótesis...")
        total_applied += process_hypothesis_files(hyp_dir, args.dry_run)

    # Modo: todas las fichas del hunt activo
    else:
        fichas_dir = Path(args.fichas_dir) if args.fichas_dir else HUNT_SESSION_DIR / "fichas" / _load_protocol()

        # Procesar fichas
        if fichas_dir.exists():
            fichas = list(fichas_dir.glob("*.yaml"))
            if fichas:
                print(f"Encontradas {len(fichas)} fichas en {fichas_dir}")
                for ficha_path in fichas:
                    # Saltar fichas ya procesadas
                    try:
                        with open(ficha_path) as f:
                            data = yaml.safe_load(f)
                        if data and data.get("feedback_applied"):
                            print(f"\n  ✓ {ficha_path.name} — ya procesada ({data['feedback_applied'][:10]})")
                            continue
                    except:
                        pass

                    print(f"\nProcesando: {ficha_path.name}")
                    applied = process_ficha(ficha_path, args.dry_run)
                    print(f"  → {applied} updates aplicados")
                    if applied > 0 and not args.dry_run:
                        mark_ficha_processed(ficha_path, args.dry_run)
                    total_applied += applied
            else:
                print(f"No hay fichas en {fichas_dir}")

        # Procesar synthesis
        print("\nProcesando archivos SYNTHESIS...")
        total_applied += process_synthesis_files(args.dry_run)

        # NOTA: hipótesis no se procesan en modo default.
        # Los false_positives de hunters solo se aplican con confirmación externa.

    # Promote any staged findings into the Obsidian vault via /wiki-ingest
    wiki_ingest_flush(dry_run=args.dry_run)

    # Resumen
    print(f"\n{'='*50}")
    print(f"Total updates aplicados: {total_applied}")
    if args.dry_run:
        print("(DRY RUN — ningún archivo fue modificado)")

    # Emitir evento
    if not args.dry_run:
        emit_event("feedback.applied", {"updates_count": total_applied})

    return 0


if __name__ == "__main__":
    sys.exit(main())
