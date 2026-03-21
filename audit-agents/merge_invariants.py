#!/usr/bin/env python3
"""
merge_invariants.py — Fusiona hipótesis YAML de hunters → Properties.sol (formato Chimera)

Lee archivos hunt_session/hypotheses/hyp_*.yaml generados por los hunters,
extrae invariantes validados, y los inserta en Properties.sol evitando duplicados.

Uso:
    python3 merge_invariants.py                          # fusiona hypotheses del hunt activo
    python3 merge_invariants.py --dry-run                # muestra qué generaría sin modificar
    python3 merge_invariants.py --hyp FILE.yaml          # procesa una hipótesis específica
    python3 merge_invariants.py --output FILE.sol        # escribe a archivo diferente
    python3 merge_invariants.py --generate-only          # solo imprime el código a stdout
    python3 merge_invariants.py --list                   # lista invariantes existentes en Properties.sol

Schema de hipótesis YAML esperado:
    protocol: revert-lend
    component: GaugeManager
    domain: staking
    hunter: MathHunter
    validation_target: GaugeManager.sol
    invariants:
      - id: GH-01
        tier: 1                    # 1=hard fail, 2=needs review, 3=optimization
        type: property             # property | optimize | ghost
        description: "texto"
        attack_scenario: "texto"
        solidity: |               # cuerpo de la función (sin firma)
          gte(x, y, "GH-01: msg");
        ghost_vars:               # opcional: vars de ghost a declarar
          - "uint256 internal ghost_lastRewardPerToken;"
        validated: true
        priority: high            # high | medium | low
"""

import sys
import re
import yaml
import argparse
import json
from pathlib import Path
from datetime import datetime

WEB3_DIR = Path.home() / "Documents/Web3"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
HYPOTHESES_DIR = HUNT_SESSION_DIR / "hypotheses"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"

# Archivo Properties.sol por defecto (se detecta del hunt activo)
DEFAULT_PROPERTIES = None


def load_current_hunt() -> dict:
    """Carga el estado del hunt activo."""
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except:
            pass
    return {}


def find_properties_sol(hunt: dict) -> Path | None:
    """Localiza Properties.sol del hunt activo."""
    repo = hunt.get("repo_path")
    if repo:
        # Buscar en test/chimera/ primero
        candidates = [
            Path(repo) / "test/chimera/Properties.sol",
            Path(repo) / "test/Properties.sol",
            Path(repo) / "src/test/chimera/Properties.sol",
        ]
        for c in candidates:
            if c.exists():
                return c

    # Buscar globalmente en WEB3_DIR
    matches = list(WEB3_DIR.glob("*/test/chimera/Properties.sol"))
    if matches:
        return matches[0]

    return None


def load_hypothesis_file(path: Path) -> dict | None:
    """Carga y valida un archivo de hipótesis YAML."""
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            print(f"  ✗ {path.name}: no es un dict YAML válido")
            return None
        invariants = data.get("invariants", [])
        if not invariants:
            print(f"  ⚠ {path.name}: sin invariants")
        return data
    except Exception as e:
        print(f"  ✗ Error leyendo {path.name}: {e}")
        return None


def extract_existing_ids(properties_text: str) -> set:
    """Extrae IDs de invariantes ya presentes en Properties.sol."""
    # Busca patrones como: property_gh_01, optimize_gh_01, "GH-01", INV-01
    ids = set()

    # En comentarios tipo /// @notice GH-01
    for m in re.finditer(r'@notice\s+([A-Z]{1,4}-\d+)', properties_text):
        ids.add(m.group(1))

    # En strings de mensajes tipo "GH-01 TEXT"
    for m in re.finditer(r'"([A-Z]{1,4}-\d+)[:\s]', properties_text):
        ids.add(m.group(1))

    # En nombres de función tipo property_gh_01
    for m in re.finditer(r'function (?:property|optimize)_([a-z]+_\d+)', properties_text):
        raw = m.group(1).upper().replace('_', '-')
        ids.add(raw)

    return ids


def id_to_function_name(inv_id: str, inv_type: str) -> str:
    """Convierte 'GH-01' + 'property' → 'property_gh_01'."""
    clean = inv_id.lower().replace('-', '_')
    if inv_type == "optimize":
        return f"optimize_{clean}"
    return f"property_{clean}"


def generate_property_function(inv: dict, source: str) -> str:
    """Genera código Solidity de una función property_*."""
    inv_id = inv.get("id", "XX-00")
    desc = inv.get("description", "")
    attack = inv.get("attack_scenario", "")
    body = inv.get("solidity", "    // TODO: implement").rstrip()
    tier = inv.get("tier", 2)
    fn_name = id_to_function_name(inv_id, "property")

    tier_comment = "TIER 1 — HARD FAIL" if tier == 1 else "TIER 2 — NEEDS REVIEW"

    lines = [
        f"    // {tier_comment}",
        f"    /// @notice {inv_id}: {desc}",
    ]
    if attack:
        lines.append(f"    /// Attack: {attack}")
    lines.append(f"    /// Source: {source}")
    lines.append(f"    function {fn_name}() public {{")

    # Indentar el body
    for line in body.split("\n"):
        if line.strip():
            lines.append(f"        {line.strip()}")
        else:
            lines.append("")

    lines.append("    }")
    return "\n".join(lines)


def generate_optimize_function(inv: dict, source: str) -> str:
    """Genera código Solidity de una función optimize_*."""
    inv_id = inv.get("id", "XX-00")
    desc = inv.get("description", "")
    body = inv.get("solidity", "    return 0;").rstrip()
    fn_name = id_to_function_name(inv_id, "optimize")

    lines = [
        f"    // OPTIMIZATION",
        f"    /// @notice {inv_id}: {desc}",
        f"    /// Source: {source}",
        f"    function {fn_name}() public returns (int256) {{",
    ]

    for line in body.split("\n"):
        if line.strip():
            lines.append(f"        {line.strip()}")
        else:
            lines.append("")

    lines.append("    }")
    return "\n".join(lines)


def generate_ghost_var(var_decl: str) -> str:
    """Formatea una declaración de ghost variable."""
    decl = var_decl.strip()
    if not decl.endswith(";"):
        decl += ";"
    return f"    {decl}"


def process_hypothesis(hyp_data: dict, existing_ids: set, dry_run: bool) -> dict:
    """
    Procesa hipótesis y devuelve:
      - new_ghosts: list[str]    — declaraciones de ghost vars a añadir
      - new_properties: list[str] — funciones property_* a añadir
      - new_optimizes: list[str] — funciones optimize_* a añadir
      - skipped: list[str]       — IDs ya existentes
    """
    source = "{}/{}".format(
        hyp_data.get("component", "unknown"),
        hyp_data.get("hunter", "hunter")
    )

    result = {
        "new_ghosts": [],
        "new_properties": [],
        "new_optimizes": [],
        "skipped": [],
    }

    for inv in hyp_data.get("invariants", []):
        if not isinstance(inv, dict):
            continue

        # Solo procesar validados (o si no tiene flag, asumir True)
        if not inv.get("validated", True):
            continue

        # Solo high/medium priority
        priority = inv.get("priority", "medium").lower()
        if priority == "low":
            continue

        inv_id = inv.get("id", "").upper()
        if not inv_id:
            continue

        if inv_id in existing_ids:
            result["skipped"].append(inv_id)
            continue

        inv_type = inv.get("type", "property").lower()

        if inv_type == "ghost":
            for var in inv.get("ghost_vars", []):
                result["new_ghosts"].append(generate_ghost_var(var))
        elif inv_type == "optimize":
            result["new_optimizes"].append(generate_optimize_function(inv, source))
            # Ghost vars asociadas
            for var in inv.get("ghost_vars", []):
                result["new_ghosts"].append(generate_ghost_var(var))
        else:  # property (default)
            result["new_properties"].append(generate_property_function(inv, source))
            # Ghost vars asociadas
            for var in inv.get("ghost_vars", []):
                result["new_ghosts"].append(generate_ghost_var(var))

        existing_ids.add(inv_id)  # Prevenir duplicados entre archivos

    return result


def insert_into_properties_sol(
    properties_path: Path,
    new_ghosts: list,
    new_properties: list,
    new_optimizes: list,
    dry_run: bool,
) -> bool:
    """Inserta el código generado en Properties.sol."""
    text = properties_path.read_text()
    modified = False

    # Insertar ghost vars después del último ghost existente o en la sección GHOST VARIABLES
    if new_ghosts:
        # Dedup dentro del run Y contra lo que ya existe en el archivo
        unique_ghosts = [g for g in dict.fromkeys(new_ghosts) if g.strip().split()[2].rstrip(";") not in text]
        if not unique_ghosts:
            new_ghosts = []  # todas ya existen
        ghost_block = "\n".join(unique_ghosts)

        ghost_section = text.find("GHOST VARIABLES")
        if ghost_section == -1:
            ghost_section = text.find("ghost_")

        if ghost_section != -1:
            # Buscar fin de la sección de ghost vars (primera función después)
            after_ghosts = ghost_section
            fn_pos = text.find("\n    function ", after_ghosts)
            if fn_pos != -1:
                insertion = f"\n    // --- Ghost vars añadidas por merge_invariants ---\n{ghost_block}\n"
                text = text[:fn_pos] + insertion + text[fn_pos:]
                modified = True
        else:
            # Añadir en la primera línea dentro del contrato
            contract_open = text.find("{")
            if contract_open != -1:
                insertion = f"\n    // --- Ghost vars añadidas por merge_invariants ---\n{ghost_block}\n"
                text = text[:contract_open + 1] + insertion + text[contract_open + 1:]
                modified = True

    # Insertar properties antes del bloque OPTIMIZATION o antes del último }
    if new_properties:
        props_code = "\n\n" + "\n\n".join(new_properties)

        opt_section = text.find("// ═══════════════════════ OPTIMIZATION")
        if opt_section == -1:
            opt_section = text.find("function optimize_")
        if opt_section == -1:
            opt_section = text.rfind("}")  # último cierre del contrato

        if opt_section != -1:
            insertion = f"\n    // --- Invariantes añadidos por merge_invariants ({datetime.utcnow().date()}) ---{props_code}\n"
            text = text[:opt_section] + insertion + text[opt_section:]
            modified = True
        else:
            # Añadir al final del archivo antes del último }
            last_brace = text.rfind("}")
            if last_brace != -1:
                text = text[:last_brace] + f"\n{props_code}\n" + text[last_brace:]
                modified = True

    # Insertar optimizes antes del último }
    if new_optimizes:
        opts_code = "\n\n" + "\n\n".join(new_optimizes)
        last_brace = text.rfind("}")
        if last_brace != -1:
            text = text[:last_brace] + f"\n{opts_code}\n" + text[last_brace:]
            modified = True

    if not modified:
        print("  Nada que insertar.")
        return False

    if dry_run:
        print(f"\n  [DRY-RUN] Se insertaría en {properties_path.name}:")
        if new_ghosts:
            print(f"    {len(new_ghosts)} ghost variable(s)")
        if new_properties:
            print(f"    {len(new_properties)} property function(s)")
        if new_optimizes:
            print(f"    {len(new_optimizes)} optimize function(s)")
        return True

    properties_path.write_text(text)
    print(f"  ✓ {properties_path.name} actualizado")
    return True


def list_invariants(properties_path: Path):
    """Lista los invariantes existentes en Properties.sol."""
    text = properties_path.read_text()
    print(f"\nInvariantes en {properties_path}:\n")

    # Extraer funciones property_ y optimize_
    for m in re.finditer(
        r'/// @notice ([A-Z]+-\d+[^\n]*)\n.*?function (property_|optimize_)(\w+)',
        text, re.DOTALL
    ):
        notice = m.group(1)
        fn_prefix = m.group(2)
        fn_name = m.group(3)
        print(f"  [{fn_prefix}{fn_name}]  {notice}")


def main():
    parser = argparse.ArgumentParser(
        description="Fusiona hipótesis YAML de hunters → Properties.sol (Chimera)"
    )
    parser.add_argument("--dry-run", action="store_true", help="No modifica archivos")
    parser.add_argument("--hyp", type=str, help="Procesa solo esta hipótesis YAML")
    parser.add_argument("--hypotheses-dir", type=str, help="Directorio de hipótesis")
    parser.add_argument("--output", type=str, help="Properties.sol de destino")
    parser.add_argument("--generate-only", action="store_true", help="Solo imprime código generado")
    parser.add_argument("--list", action="store_true", help="Lista invariantes existentes")
    parser.add_argument("--include-low", action="store_true", help="Incluye invariantes de prioridad low")
    args = parser.parse_args()

    hunt = load_current_hunt()

    # Localizar Properties.sol
    if args.output:
        properties_path = Path(args.output)
    else:
        properties_path = find_properties_sol(hunt)

    if not properties_path or not properties_path.exists():
        print(f"✗ No se encontró Properties.sol")
        print(f"  Especifica con --output FILE.sol")
        return 1

    if args.list:
        list_invariants(properties_path)
        return 0

    if args.dry_run:
        print("=== DRY RUN — no se modificará nada ===\n")

    properties_text = properties_path.read_text()
    existing_ids = extract_existing_ids(properties_text)
    print(f"Invariantes existentes en Properties.sol: {len(existing_ids)}")
    if existing_ids:
        print(f"  IDs: {', '.join(sorted(existing_ids))}")

    # Localizar hipótesis
    if args.hyp:
        hyp_files = [Path(args.hyp)]
        if not hyp_files[0].exists():
            hyp_files = [HYPOTHESES_DIR / args.hyp]
        if not hyp_files[0].exists():
            print(f"✗ Hipótesis no encontrada: {args.hyp}")
            return 1
    else:
        hyp_dir = Path(args.hypotheses_dir) if args.hypotheses_dir else HYPOTHESES_DIR
        if not hyp_dir.exists():
            print(f"✗ No existe directorio de hipótesis: {hyp_dir}")
            print(f"  Crea hipótesis en: {HYPOTHESES_DIR}/hyp_<component>_<hunter>.yaml")
            return 1
        hyp_files = sorted(p for p in hyp_dir.glob("hyp_*.yaml") if "template" not in p.name)
        if not hyp_files:
            print(f"  Sin archivos hyp_*.yaml en {hyp_dir}")
            return 0

    print(f"\nProcesando {len(hyp_files)} archivo(s) de hipótesis...\n")

    # Acumular todos los cambios
    all_ghosts = []
    all_properties = []
    all_optimizes = []
    total_skipped = []

    for hyp_path in hyp_files:
        print(f"  {hyp_path.name}")
        hyp_data = load_hypothesis_file(hyp_path)
        if not hyp_data:
            continue

        # Ajustar priority filter si --include-low
        if args.include_low:
            for inv in hyp_data.get("invariants", []):
                if isinstance(inv, dict) and inv.get("priority") == "low":
                    inv["priority"] = "medium"

        result = process_hypothesis(hyp_data, existing_ids, args.dry_run)

        n_new = len(result["new_properties"]) + len(result["new_optimizes"])
        n_skip = len(result["skipped"])
        print(f"    → {n_new} nuevo(s), {n_skip} ya existente(s)")
        if result["skipped"]:
            print(f"    skipped: {', '.join(result['skipped'])}")

        all_ghosts.extend(result["new_ghosts"])
        all_properties.extend(result["new_properties"])
        all_optimizes.extend(result["new_optimizes"])
        total_skipped.extend(result["skipped"])

    total_new = len(all_properties) + len(all_optimizes)
    print(f"\nTotal a insertar: {total_new} invariante(s), {len(all_ghosts)} ghost var(s)")

    if total_new == 0 and not all_ghosts:
        print("Nada nuevo que añadir.")
        return 0

    # Modo generate-only: imprimir a stdout
    if args.generate_only:
        print("\n" + "=" * 60)
        print("// CÓDIGO GENERADO — pegar en Properties.sol\n")
        if all_ghosts:
            print("// Ghost variables:")
            print("\n".join(all_ghosts))
            print()
        if all_properties:
            print("// Property invariants:")
            print("\n\n".join(all_properties))
            print()
        if all_optimizes:
            print("// Optimization functions:")
            print("\n\n".join(all_optimizes))
        return 0

    # Insertar en Properties.sol
    print(f"\nInsertando en {properties_path}...")
    success = insert_into_properties_sol(
        properties_path,
        all_ghosts,
        all_properties,
        all_optimizes,
        args.dry_run,
    )

    if success and not args.dry_run:
        print(f"\n✓ Properties.sol actualizado con {total_new} invariante(s) nuevo(s)")
        print(f"  Siguiente paso: FOUNDRY_PROFILE=chimera forge build")

    return 0


if __name__ == "__main__":
    sys.exit(main())
