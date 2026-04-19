#!/usr/bin/env python3
"""
merge_invariants.py — Fusiona hipótesis YAML de hunters → archivos Properties*.sol (formato Chimera)

MODO SPLIT (default): genera un archivo por hunter:
    PropertiesMath.sol, PropertiesAccess.sol, PropertiesFlow.sol, etc.
    Cada uno hereda de Properties.sol (base con ghost vars).
    CryticTester.sol se actualiza para heredar de todos.

MODO MONOLÍTICO (--monolithic): comportamiento legacy, todo en Properties.sol.

Uso:
    python3 merge_invariants.py                          # split per-hunter (default)
    python3 merge_invariants.py --monolithic             # modo legacy en un solo archivo
    python3 merge_invariants.py --dry-run                # muestra qué generaría sin modificar
    python3 merge_invariants.py --hyp FILE.yaml          # procesa una hipótesis específica
    python3 merge_invariants.py --output FILE.sol        # monolithic a archivo específico
    python3 merge_invariants.py --generate-only          # solo imprime el código a stdout
    python3 merge_invariants.py --list                   # lista invariantes existentes
    python3 merge_invariants.py --component V3Vault      # filtra por componente

Schema de hipótesis YAML esperado:
    protocol: revert-lend
    component: GaugeManager
    domain: staking
    hunter: MathHunter
    invariants:
      - id: GH-01
        tier: 1
        type: property
        description: "texto"
        attack_scenario: "texto"
        solidity: |
          gte(x, y, "GH-01: msg");
        ghost_vars:
          - "uint256 internal ghost_lastRewardPerToken;"
        validated: true
        priority: high
"""

import sys
import re
import subprocess
import yaml
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

from paths import WEB3_DIR, HUNT_SESSION_DIR, STATE_FILE
from state_manager import load_state
from merge.constants import (
    HUNTER_FILE_MAP,
    CROSS_COMPONENT_HUNTERS,
    _PRAGMA,
    REQUIRED_HYP_FIELDS,
    HUNTER_REQUIRED_TABLES,
)
from merge.solidity import (
    id_to_function_name,
    _wrap_comment,
    _clean_solidity_body,
    _sanitize_solidity,
    generate_property_function,
    generate_optimize_function,
    generate_ghost_var,
)

def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d

def validate_hypothesis(hyp: dict, source_file: str) -> list[str]:
    """Validate a single hypothesis. Returns list of warnings."""
    warnings = []
    for field in REQUIRED_HYP_FIELDS:
        if field not in hyp or not hyp[field]:
            warnings.append(f"  {source_file}: {hyp.get('id', '?')} missing '{field}'")
    sol = hyp.get("solidity", "")
    if sol and not any(kw in sol for kw in ["t(", "eq(", "gte(", "lte(", "assert", "require"]):
        warnings.append(f"  {source_file}: {hyp.get('id', '?')} solidity has no assertion")
    return warnings


def dedup_hypotheses(hypotheses: list[dict]) -> list[dict]:
    """Remove near-duplicate hypotheses across hunters before merge.

    Two hypotheses are duplicates if:
    - Same primary function referenced AND >50% keyword overlap in description
    Keep the one with highest confidence. Tag with _merged_count.
    """
    from collections import defaultdict

    groups = defaultdict(list)
    for hyp in hypotheses:
        # Extract function names from solidity/description
        text = f"{hyp.get('description', '')} {hyp.get('solidity', '')}".lower()
        functions = set()
        for token in re.findall(r'\b(\w+)\s*\(', text):
            if token not in ('require', 'assert', 'revert', 'emit', 'if', 'for', 'while',
                             'gte', 'lte', 'eq', 't', 'gt', 'lt', 'true', 'false'):
                functions.add(token)
        key = frozenset(functions) if functions else frozenset([hyp.get('id', str(id(hyp)))])
        groups[key].append(hyp)

    deduped = []
    total_merged = 0
    for key, group in groups.items():
        if len(group) == 1:
            deduped.append(group[0])
        else:
            best = max(group, key=lambda h: h.get("confidence", 0))
            best["_merged_count"] = len(group)
            best["_merged_from"] = [h.get("_hunter", h.get("id", "?")) for h in group if h != best]
            deduped.append(best)
            total_merged += len(group) - 1

    if total_merged > 0:
        print(f"[dedup] Merged {total_merged} duplicate hypotheses ({len(hypotheses)} → {len(deduped)})")

    return deduped


def detect_pragma(chimera_dir: Path) -> str:
    """Detect pragma from project source files. Checks Setup.sol first, then src/."""
    candidates = []
    setup = chimera_dir / "Setup.sol"
    if setup.exists():
        candidates.append(setup)
    # Walk up to find src/
    repo = chimera_dir
    for _ in range(5):
        src = repo / "src"
        if src.is_dir():
            candidates.extend(sorted(src.glob("**/*.sol"))[:5])
            break
        repo = repo.parent
    for f in candidates:
        try:
            for line in f.read_text(encoding="utf-8").splitlines():
                m = re.match(r'\s*(pragma\s+solidity\s+[^;]+;)', line)
                if m:
                    return m.group(1)
        except Exception:
            continue
    return _PRAGMA


def load_current_hunt() -> dict:
    """Carga el estado del hunt activo. Corrupted JSON swallowed to {}."""
    try:
        return load_state()
    except json.JSONDecodeError:
        return {}


def find_chimera_dir(hunt: dict) -> Path | None:
    """Localiza el directorio test/chimera/ del hunt activo."""
    repo = hunt.get("repo_path")
    if repo:
        candidates = [
            Path(repo) / "test/chimera",
            Path(repo) / "test",
            Path(repo) / "src/test/chimera",
        ]
        for c in candidates:
            if (c / "Properties.sol").exists():
                return c

    matches = list(WEB3_DIR.glob("*/test/chimera/Properties.sol"))
    if matches:
        return matches[0].parent

    return None


def find_properties_sol(hunt: dict) -> Path | None:
    """Localiza Properties.sol del hunt activo."""
    chimera_dir = find_chimera_dir(hunt)
    if chimera_dir:
        return chimera_dir / "Properties.sol"
    return None


def load_hypothesis_file(path: Path) -> dict | None:
    """Carga y valida un archivo de hipótesis YAML."""
    try:
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            print(f"  ✗ {path.name}: no es un dict YAML válido")
            return None
        invariants = data.get("invariants", data.get("findings", data.get("hypotheses", [])))
        if not invariants:
            print(f"  ⚠ {path.name}: sin invariants/findings/hypotheses")
        return data
    except Exception as e:
        print(f"  ✗ Error leyendo {path.name}: {e}")
        return None


def validate_evidence_tables(hyp_data: dict) -> list[str]:
    """Check if hypothesis YAML includes required structured evidence tables.

    Returns list of warning strings for missing tables.
    Does NOT block merge — warns only, so hunters can still produce results
    even if they skip a table (but the warning makes it visible).
    """
    warnings = []
    hunter = hyp_data.get("hunter", "")
    required = HUNTER_REQUIRED_TABLES.get(hunter, [])

    if not required:
        return warnings

    for table_name in required:
        # Check top-level and inside each invariant
        has_table = table_name in hyp_data
        if not has_table:
            # Also check inside invariants
            for inv in hyp_data.get("invariants", hyp_data.get("findings", hyp_data.get("hypotheses", []))):
                if isinstance(inv, dict) and table_name in inv:
                    has_table = True
                    break

        if not has_table:
            warnings.append(
                f"⚠ {hunter}: missing required '{table_name}' table. "
                f"Re-run hunter with structured evidence requirement."
            )

    return warnings


def extract_existing_ids_from_dir(chimera_dir: Path) -> set:
    """Extrae IDs de invariantes de TODOS los archivos Properties*.sol del directorio."""
    ids = set()
    for sol_file in chimera_dir.glob("Properties*.sol"):
        ids.update(extract_existing_ids(sol_file.read_text()))
    return ids


def extract_existing_ids(properties_text: str) -> set:
    """Extrae IDs de invariantes ya presentes en un archivo .sol."""
    ids = set()

    for m in re.finditer(r'@notice\s+([A-Z]{1,4}-\d+)', properties_text):
        ids.add(m.group(1))

    for m in re.finditer(r'"([A-Z]{1,4}-\d+)[:\s]', properties_text):
        ids.add(m.group(1))

    for m in re.finditer(r'function (?:property|optimize)_([a-z]+_\d+)', properties_text):
        raw = m.group(1).upper().replace('_', '-')
        ids.add(raw)

    return ids


def process_hypothesis(hyp_data: dict, existing_ids: set, include_low: bool = False) -> dict:
    """
    Procesa hipótesis y devuelve:
      - hunter: str               — nombre del hunter
      - component: str            — nombre del componente
      - new_ghosts: list[str]     — declaraciones de ghost vars
      - new_properties: list[str] — funciones property_*
      - new_optimizes: list[str]  — funciones optimize_*
      - skipped: list[str]        — IDs ya existentes
    """
    source = "{}/{}".format(
        hyp_data.get("component", "unknown"),
        hyp_data.get("hunter", "hunter")
    )

    result = {
        "hunter": hyp_data.get("hunter", "unknown"),
        "component": hyp_data.get("component", "unknown"),
        "new_ghosts": [],
        "new_properties": [],
        "new_optimizes": [],
        "skipped": [],
    }

    for inv in hyp_data.get("invariants", hyp_data.get("findings", hyp_data.get("hypotheses", []))):
        if not isinstance(inv, dict):
            continue

        # ── Schema validation (Task 12) ──
        _val_warnings = validate_hypothesis(inv, source)
        if _val_warnings:
            for w in _val_warnings:
                print(f"[validate] WARNING: {w}")
            # Skip if missing critical 'solidity' field
            if not inv.get("solidity"):
                print(f"[validate] SKIPPING {inv.get('id', '?')} — no solidity code")
                continue

        priority = str(inv.get("priority", "medium")).lower()
        if priority == "low" and not include_low:
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
            for var in inv.get("ghost_vars", []):
                result["new_ghosts"].append(generate_ghost_var(var))
        else:
            result["new_properties"].append(generate_property_function(inv, source))
            for var in inv.get("ghost_vars", []):
                result["new_ghosts"].append(generate_ghost_var(var))

        existing_ids.add(inv_id)

    return result


# ═══════════════════════════════════════════════════════════════════════
# SPLIT MODE — un archivo por hunter
# ═══════════════════════════════════════════════════════════════════════

def _dedup_ghosts(ghosts: list[str], existing_text: str) -> list[str]:
    """Dedup ghost vars contra lo que ya existe en un archivo."""
    seen = set()
    result = []
    for g in ghosts:
        stripped = g.strip()
        if not stripped or len(stripped.split()) < 3:
            continue
        var_name = stripped.split()[2].rstrip(";")
        if var_name in existing_text or var_name in seen:
            continue
        seen.add(var_name)
        result.append(g)
    return result


def generate_hunter_sol_file(
    hunter_suffix: str,
    base_contract: str,
    ghosts: list[str],
    properties: list[str],
    optimizes: list[str],
    component: str,
    pragma: str = _PRAGMA,
) -> str:
    """Genera el contenido completo de un archivo PropertiesX.sol."""
    contract_name = f"Properties{hunter_suffix}"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        pragma,
        "",
        f'import "./{base_contract}.sol";',
        "",
        f"/// @title {component} {hunter_suffix} Hunter Invariants",
        f"/// @notice Auto-generated by merge_invariants.py ({date_str})",
        f"/// @dev Inherits {base_contract} for ghost vars and setup access",
        f"abstract contract {contract_name} is {base_contract} {{",
        "",
    ]

    # Ghost variables
    if ghosts:
        lines.append(f"    // ======= GHOST VARIABLES ({hunter_suffix}Hunter) =======")
        lines.append("")
        lines.extend(ghosts)
        lines.append("")

    # Property invariants
    if properties:
        lines.append(f"    // ======= PROPERTY INVARIANTS ({hunter_suffix}Hunter) =======")
        lines.append("")
        lines.extend(f"{p}\n" for p in properties)

    # Optimization functions
    if optimizes:
        lines.append(f"    // ======= OPTIMIZATION FUNCTIONS ({hunter_suffix}Hunter) =======")
        lines.append("")
        lines.extend(f"{o}\n" for o in optimizes)

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def generate_cross_component_sol_file(
    ghosts: list[str],
    properties: list[str],
    optimizes: list[str],
    components: list[str],
    pragma: str = _PRAGMA,
) -> str:
    """
    Genera PropertiesCross.sol para invariantes cross-component.
    A diferencia de los PropertiesX.sol normales, este NO hereda de Properties
    (que tiene setup de un solo contrato). En su lugar, declara variables de estado
    para los contratos involucrados que se setean en el setup del test.
    """
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    comp_label = " + ".join(components)

    lines = [
        "// SPDX-License-Identifier: UNLICENSED",
        pragma,
        "",
        f"/// @title Cross-Component Invariants: {comp_label}",
        f"/// @notice Auto-generated by merge_invariants.py ({date_str})",
        f"/// @dev EdgeHunter output. Setup must deploy all referenced contracts.",
        f"/// @dev Inherits nothing — setup function must initialize contract refs.",
        "abstract contract PropertiesCross {",
        "",
        f"    // ======= CROSS-COMPONENT CONTRACT REFERENCES =======",
        f"    // These must be set in the test setup (e.g., CryticTester.setUp())",
        f"    // Example: crossContractA = address(deployedA);",
        "",
    ]

    # Declare address vars for each component
    for i, comp in enumerate(components):
        var_name = f"crossContract{chr(65 + i)}"  # crossContractA, crossContractB, ...
        lines.append(f"    address internal {var_name}; // {comp}")
    lines.append("")

    # Ghost variables
    if ghosts:
        lines.append(f"    // ======= GHOST VARIABLES (EdgeHunter) =======")
        lines.append("")
        lines.extend(ghosts)
        lines.append("")

    # Property invariants
    if properties:
        lines.append(f"    // ======= CROSS-COMPONENT INVARIANTS (EdgeHunter) =======")
        lines.append("")
        lines.extend(f"{p}\n" for p in properties)

    # Optimization functions
    if optimizes:
        lines.append(f"    // ======= OPTIMIZATION FUNCTIONS (EdgeHunter) =======")
        lines.append("")
        lines.extend(f"{o}\n" for o in optimizes)

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def update_target_functions_import(chimera_dir: Path, hunter_suffixes: list,
                                   dry_run: bool = False, pragma: str = _PRAGMA):
    """
    Actualiza TargetFunctions.sol para heredar del contrato agregador
    que incluye todos los PropertiesX.sol.

    En vez de tocar TargetFunctions directamente (que es código del usuario),
    generamos un PropertiesAll.sol intermedio que hereda de todos.
    TargetFunctions hereda de PropertiesAll en vez de Properties.
    """
    all_file = chimera_dir / "PropertiesAll.sol"
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    imports = ['import "./Properties.sol";']
    parents = ["Properties"]

    for suffix in sorted(hunter_suffixes):
        imports.append(f'import "./Properties{suffix}.sol";')
        parents.append(f"Properties{suffix}")

    content = [
        "// SPDX-License-Identifier: UNLICENSED",
        pragma,
        "",
        *imports,
        "",
        f"/// @title Aggregator — inherits base Properties + all per-hunter Properties",
        f"/// @notice Auto-generated by merge_invariants.py ({date_str})",
        f"/// @dev TargetFunctions inherits this instead of Properties directly",
        f"abstract contract PropertiesAll is {', '.join(parents)} {{",
        "",
        "}",
        "",
    ]

    all_content = "\n".join(content)

    if dry_run:
        print(f"\n  [DRY-RUN] Generaría {all_file.name}:")
        print(f"    Herencia: {' → '.join(parents)}")
        return True

    all_file.write_text(all_content)
    print(f"  ✓ {all_file.name} generado (hereda {len(parents)} contratos)")

    # Actualizar TargetFunctions.sol para importar PropertiesAll en vez de Properties
    tf_path = chimera_dir / "TargetFunctions.sol"
    if tf_path.exists():
        tf_text = tf_path.read_text()
        # Solo cambiar si todavía importa Properties directamente
        if 'import "./Properties.sol"' in tf_text and 'import "./PropertiesAll.sol"' not in tf_text:
            tf_text = tf_text.replace(
                'import "./Properties.sol";',
                'import "./PropertiesAll.sol";'
            )
            tf_text = tf_text.replace(
                "is Properties",
                "is PropertiesAll"
            )
            tf_path.write_text(tf_text)
            print(f"  ✓ TargetFunctions.sol actualizado: Properties → PropertiesAll")
        elif 'import "./PropertiesAll.sol"' in tf_text:
            print(f"  ✓ TargetFunctions.sol ya importa PropertiesAll")
        else:
            print(f"  ⚠ TargetFunctions.sol: no se encontró import de Properties")

    return True


def clean_properties_base(chimera_dir: Path, dry_run: bool) -> None:
    """Limpia Properties.sol eliminando invariantes de merges anteriores.

    Mantiene solo el código base (ghost vars + invariantes originales INV-*).
    Todo lo que fue añadido por merge_invariants.py se elimina, ya que ahora
    va en archivos split separados.
    """
    props_path = chimera_dir / "Properties.sol"
    if not props_path.exists():
        return

    text = props_path.read_text()

    # Buscar el marcador de merge_invariants o el primer invariante no-INV
    # El patrón: "// --- Invariantes añadidos por merge_invariants" o
    # "// --- Ghost vars añadidas por merge_invariants ---" (el segundo bloque)
    # Buscar marcadores de invariantes añadidos (NO ghost vars, esas se quedan)
    marker_es = "// --- Invariantes añadidos por merge_invariants"
    marker_en = "// --- Invariants added by merge_invariants"

    cut_pos = -1
    for m in [marker_es, marker_en]:
        pos = text.find(m)
        if pos != -1:
            cut_pos = pos
            break

    if cut_pos == -1:
        # No merge markers — check for non-base property functions (VV-*, AC-*, etc.)
        # Base functions use names like property_solvency, property_debtSharesConsistency, etc.
        # Merge-generated use property_vv_m_01, property_vv_ac_01, etc.
        non_base = re.search(r'\n    function property_vv_\w+\(', text)
        if not non_base:
            non_base = re.search(r'\n    function property_[a-z]{2}_\w+\(', text)
        if non_base:
            cut_pos = non_base.start()

    if cut_pos == -1:
        return  # Properties.sol is already clean

    # Find the last valid line before the cut point
    # We want to keep everything up to the last complete function before the marker
    lines = text[:cut_pos].rstrip().split('\n')

    # Remove trailing empty lines
    while lines and not lines[-1].strip():
        lines.pop()

    # Close the contract
    cleaned = '\n'.join(lines) + '\n\n}\n'
    cleaned += '// NOTE: Hunter-generated invariants are in separate PropertiesX.sol files.\n'
    cleaned += '// See PropertiesAll.sol for the aggregator.\n'

    if dry_run:
        original_lines = text.count('\n')
        cleaned_lines = cleaned.count('\n')
        print(f"  [DRY-RUN] Limpiaría Properties.sol: {original_lines} → {cleaned_lines} líneas")
        return

    props_path.write_text(cleaned)
    original_lines = text.count('\n')
    cleaned_lines = cleaned.count('\n')
    print(f"  ✓ Properties.sol limpiado: {original_lines} → {cleaned_lines} líneas (base only)")


def run_split_mode(
    chimera_dir: Path,
    hyp_files: list[Path],
    existing_ids: set,
    include_low: bool,
    dry_run: bool,
    component_filter: str | None,
) -> int:
    """Modo split: genera un PropertiesX.sol por hunter."""

    # Detectar pragma del proyecto
    pragma = detect_pragma(chimera_dir)
    print(f"Pragma detectado: {pragma}")

    # Paso 0: limpiar Properties.sol de invariantes de merges anteriores
    print("--- Limpiando Properties.sol (base only) ---")
    clean_properties_base(chimera_dir, dry_run)

    # Re-escanear IDs después de la limpieza (solo quedan los base INV-*)
    existing_ids = extract_existing_ids_from_dir(chimera_dir)
    print(f"  IDs base después de limpieza: {len(existing_ids)}")

    print(f"\nProcesando {len(hyp_files)} archivo(s) de hipótesis (modo SPLIT)...\n")

    # Agrupar por hunter
    hunter_data: dict[str, dict] = defaultdict(lambda: {
        "ghosts": [], "properties": [], "optimizes": [],
        "skipped": [], "component": "unknown"
    })

    for hyp_path in hyp_files:
        print(f"  {hyp_path.name}")
        hyp_data = load_hypothesis_file(hyp_path)
        if not hyp_data:
            continue

        # Validate evidence tables
        table_warnings = validate_evidence_tables(hyp_data)
        for w in table_warnings:
            print(f"  {w}")

        # Filtrar por componente si se especificó
        if component_filter and hyp_data.get("component", "").lower() != component_filter.lower():
            print(f"    → skip (componente {hyp_data.get('component')} != {component_filter})")
            continue

        result = process_hypothesis(hyp_data, existing_ids, include_low)

        hunter_name = result["hunter"]
        n_new = len(result["new_properties"]) + len(result["new_optimizes"])
        n_skip = len(result["skipped"])
        print(f"    → {hunter_name}: {n_new} nuevo(s), {n_skip} ya existente(s)")
        if result["skipped"]:
            print(f"    skipped: {', '.join(result['skipped'])}")

        hd = hunter_data[hunter_name]
        hd["ghosts"].extend(result["new_ghosts"])
        hd["properties"].extend(result["new_properties"])
        hd["optimizes"].extend(result["new_optimizes"])
        hd["skipped"].extend(result["skipped"])
        hd["component"] = result["component"]

    # ─── Dedup invariantes por body similarity (cross-hunter) ──────────
    def _extract_body(prop_code: str) -> str:
        """Extract the function body (between { and }) normalized for comparison."""
        lines = prop_code.split("\n")
        body_lines = []
        in_body = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("function ") and stripped.endswith("{"):
                in_body = True
                continue
            if stripped == "}" and in_body:
                break
            if in_body and stripped and not stripped.startswith("//"):
                # Normalize: remove whitespace, lowercase identifiers won't help
                # but removing comments and whitespace catches copy-paste dupes
                body_lines.append(stripped)
        return "\n".join(body_lines)

    def _dedup_properties_cross_hunter(hunter_data_dict: dict) -> int:
        """Dedup properties across all hunters by body similarity.
        Keeps the first occurrence (highest-priority hunter) and removes dupes."""
        import difflib
        seen_bodies: list[tuple[str, str, str]] = []  # (body, hunter, fn_name)
        total_removed = 0

        # Collect all properties with their bodies
        all_props = []
        for hunter_name, data in sorted(hunter_data_dict.items()):
            for prop in data["properties"]:
                body = _extract_body(prop)
                fn_match = re.search(r'function\s+(property_\w+)', prop)
                fn_name = fn_match.group(1) if fn_match else "unknown"
                all_props.append((hunter_name, prop, body, fn_name))

        # Mark duplicates
        dupes_to_remove: dict[str, list[str]] = defaultdict(list)  # hunter → list of props to remove
        for i, (hunter, prop, body, fn_name) in enumerate(all_props):
            if not body or len(body) < 20:
                continue
            is_dupe = False
            for seen_body, seen_hunter, seen_fn in seen_bodies:
                similarity = difflib.SequenceMatcher(None, body, seen_body).ratio()
                if similarity > 0.65:
                    dupes_to_remove[hunter].append(prop)
                    is_dupe = True
                    print(f"    DEDUP: {fn_name} ({hunter}) ≈ {seen_fn} ({seen_hunter}) "
                          f"[{similarity:.0%}] — removing")
                    total_removed += 1
                    break
            if not is_dupe:
                seen_bodies.append((body, hunter, fn_name))

        # Remove dupes from hunter_data
        for hunter_name, props_to_remove in dupes_to_remove.items():
            remove_set = set(id(p) for p in props_to_remove)
            hunter_data_dict[hunter_name]["properties"] = [
                p for p in hunter_data_dict[hunter_name]["properties"]
                if id(p) not in remove_set
            ]

        return total_removed

    print("\n--- Deduplicating invariants across hunters ---")
    removed = _dedup_properties_cross_hunter(hunter_data)
    total_before_dedup = sum(len(d["properties"]) + len(d["optimizes"]) for d in hunter_data.values())
    print(f"  Removed {removed} duplicate invariants, {total_before_dedup} remaining")

    # Generar archivos por hunter
    generated_suffixes = []
    total_new = 0
    total_ghosts = 0

    # Leer Properties.sol base para dedup de ghosts
    base_text = (chimera_dir / "Properties.sol").read_text() if (chimera_dir / "Properties.sol").exists() else ""

    for hunter_name, data in sorted(hunter_data.items()):
        n_props = len(data["properties"])
        n_opts = len(data["optimizes"])
        if n_props == 0 and n_opts == 0 and not data["ghosts"]:
            continue

        suffix = HUNTER_FILE_MAP.get(hunter_name)
        if not suffix:
            # Fallback: usar el nombre del hunter sin "Hunter"
            suffix = hunter_name.replace("Hunter", "")
            print(f"  ⚠ Hunter '{hunter_name}' no está en HUNTER_FILE_MAP, usando suffix '{suffix}'")

        # Dedup ghosts contra Properties.sol base y contra archivos ya existentes
        target_file = chimera_dir / f"Properties{suffix}.sol"
        existing_file_text = target_file.read_text() if target_file.exists() else ""
        combined_existing = base_text + existing_file_text
        unique_ghosts = _dedup_ghosts(data["ghosts"], combined_existing)

        # Cross-component hunters get a special file that doesn't inherit Properties
        if hunter_name in CROSS_COMPONENT_HUNTERS:
            # Extract component names from the hypothesis data
            # EdgeHunter files are named hyp_CompA_CompB_EdgeHunter.yaml
            # The component field contains "CompA_CompB" or similar
            comp_str = data["component"]
            components = [c.strip() for c in comp_str.replace("_", " ").split() if c.strip()]
            if len(components) < 2:
                components = [comp_str, "unknown"]

            content = generate_cross_component_sol_file(
                ghosts=unique_ghosts,
                properties=data["properties"],
                optimizes=data["optimizes"],
                components=components,
                pragma=pragma,
            )
        else:
            content = generate_hunter_sol_file(
                hunter_suffix=suffix,
                base_contract="Properties",
                ghosts=unique_ghosts,
                properties=data["properties"],
                optimizes=data["optimizes"],
                component=data["component"],
                pragma=pragma,
            )

        if dry_run:
            print(f"\n  [DRY-RUN] Properties{suffix}.sol:")
            print(f"    {n_props} property, {n_opts} optimize, {len(unique_ghosts)} ghost")
        else:
            target_file.write_text(content)
            print(f"  ✓ Properties{suffix}.sol: {n_props} property, {n_opts} optimize, {len(unique_ghosts)} ghost")

        generated_suffixes.append(suffix)
        total_new += n_props + n_opts
        total_ghosts += len(unique_ghosts)

    if total_new == 0 and total_ghosts == 0:
        print("\nNada nuevo que añadir.")
        return 0

    # Generar PropertiesAll.sol agregador
    print(f"\n--- Generando agregador ---")

    # Incluir suffixes de archivos que ya existan en disco (de runs anteriores)
    all_suffixes = set(generated_suffixes)
    for sol_file in chimera_dir.glob("Properties*.sol"):
        name = sol_file.stem
        if name.startswith("Properties") and name not in ("Properties", "PropertiesAll"):
            existing_suffix = name[len("Properties"):]
            all_suffixes.add(existing_suffix)

    update_target_functions_import(chimera_dir, sorted(all_suffixes), dry_run, pragma=pragma)

    print(f"\n{'[DRY-RUN] ' if dry_run else ''}Resumen:")
    print(f"  {len(generated_suffixes)} archivo(s) generados")
    print(f"  {total_new} invariante(s) nuevo(s)")
    print(f"  {total_ghosts} ghost var(s)")
    print(f"  Siguiente paso: FOUNDRY_PROFILE=chimera forge build")

    return 0


# ═══════════════════════════════════════════════════════════════════════
# MONOLITHIC MODE — todo en Properties.sol (legacy)
# ═══════════════════════════════════════════════════════════════════════

def insert_into_properties_sol(
    properties_path: Path,
    new_ghosts: list,
    new_properties: list,
    new_optimizes: list,
    dry_run: bool,
) -> bool:
    """Inserta el código generado en Properties.sol (modo monolítico)."""
    text = properties_path.read_text()
    modified = False

    if new_ghosts:
        unique_ghosts = _dedup_ghosts(new_ghosts, text)
        if not unique_ghosts:
            new_ghosts = []
        ghost_block = "\n".join(unique_ghosts)

        ghost_section = text.find("GHOST VARIABLES")
        if ghost_section == -1:
            ghost_section = text.find("ghost_")

        if ghost_section != -1:
            after_ghosts = ghost_section
            fn_pos = text.find("\n    function ", after_ghosts)
            if fn_pos != -1:
                insertion = f"\n    // --- Ghost vars added by merge_invariants ---\n{ghost_block}\n"
                text = text[:fn_pos] + insertion + text[fn_pos:]
                modified = True
        else:
            contract_open = text.find("{")
            if contract_open != -1:
                insertion = f"\n    // --- Ghost vars added by merge_invariants ---\n{ghost_block}\n"
                text = text[:contract_open + 1] + insertion + text[contract_open + 1:]
                modified = True

    if new_properties:
        props_code = "\n\n" + "\n\n".join(new_properties)
        opt_section = text.find("function optimize_")
        if opt_section == -1:
            opt_section = text.rfind("}")

        if opt_section != -1:
            insertion = f"\n    // --- Invariants added by merge_invariants ({datetime.now(timezone.utc).date()}) ---{props_code}\n"
            text = text[:opt_section] + insertion + text[opt_section:]
            modified = True

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


def run_monolithic_mode(
    properties_path: Path,
    hyp_files: list[Path],
    existing_ids: set,
    include_low: bool,
    dry_run: bool,
    generate_only: bool,
    component_filter: str | None,
) -> int:
    """Modo monolítico legacy: todo en un Properties.sol."""
    print(f"\nProcesando {len(hyp_files)} archivo(s) de hipótesis (modo MONOLÍTICO)...\n")

    all_ghosts = []
    all_properties = []
    all_optimizes = []

    for hyp_path in hyp_files:
        print(f"  {hyp_path.name}")
        hyp_data = load_hypothesis_file(hyp_path)
        if not hyp_data:
            continue

        # Validate evidence tables
        table_warnings = validate_evidence_tables(hyp_data)
        for w in table_warnings:
            print(f"  {w}")

        if component_filter and hyp_data.get("component", "").lower() != component_filter.lower():
            print(f"    → skip (componente {hyp_data.get('component')} != {component_filter})")
            continue

        result = process_hypothesis(hyp_data, existing_ids, include_low)

        n_new = len(result["new_properties"]) + len(result["new_optimizes"])
        n_skip = len(result["skipped"])
        print(f"    → {n_new} nuevo(s), {n_skip} ya existente(s)")
        if result["skipped"]:
            print(f"    skipped: {', '.join(result['skipped'])}")

        all_ghosts.extend(result["new_ghosts"])
        all_properties.extend(result["new_properties"])
        all_optimizes.extend(result["new_optimizes"])

    total_new = len(all_properties) + len(all_optimizes)
    print(f"\nTotal a insertar: {total_new} invariante(s), {len(all_ghosts)} ghost var(s)")

    if total_new == 0 and not all_ghosts:
        print("Nada nuevo que añadir.")
        return 0

    if generate_only:
        print("\n" + "=" * 60)
        print("// GENERATED CODE\n")
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

    print(f"\nInsertando en {properties_path}...")
    success = insert_into_properties_sol(
        properties_path, all_ghosts, all_properties, all_optimizes, dry_run,
    )

    if success and not dry_run:
        print(f"\n✓ Properties.sol actualizado con {total_new} invariante(s) nuevo(s)")
        print(f"  Siguiente paso: FOUNDRY_PROFILE=chimera forge build")

    return 0


# ═══════════════════════════════════════════════════════════════════════
# LIST
# ═══════════════════════════════════════════════════════════════════════

def list_invariants(chimera_dir: Path):
    """Lista los invariantes existentes en todos los Properties*.sol."""
    total = 0
    for sol_file in sorted(chimera_dir.glob("Properties*.sol")):
        text = sol_file.read_text()
        fns = list(re.finditer(
            r'/// @notice ([A-Z]+-\d+[^\n]*)\n.*?function (property_|optimize_)(\w+)',
            text, re.DOTALL
        ))
        if not fns:
            continue

        print(f"\n{sol_file.name} ({len(fns)} invariantes):")
        for m in fns:
            notice = m.group(1)
            fn_prefix = m.group(2)
            fn_name = m.group(3)
            print(f"  [{fn_prefix}{fn_name}]  {notice}")
        total += len(fns)

    print(f"\nTotal: {total} invariantes")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Fusiona hipótesis YAML de hunters → Properties*.sol (Chimera)"
    )
    parser.add_argument("--dry-run", action="store_true", help="No modifica archivos")
    parser.add_argument("--monolithic", action="store_true", help="Modo legacy: todo en Properties.sol")
    parser.add_argument("--hyp", type=str, help="Procesa solo esta hipótesis YAML")
    parser.add_argument("--hypotheses-dir", type=str, help="Directorio de hipótesis")
    parser.add_argument("--output", type=str, help="Properties.sol de destino (fuerza monolithic)")
    parser.add_argument("--generate-only", action="store_true", help="Solo imprime código generado")
    parser.add_argument("--list", action="store_true", help="Lista invariantes existentes")
    parser.add_argument("--include-low", action="store_true", help="Incluye invariantes de prioridad low")
    parser.add_argument("--component", "-c", type=str, help="Filtra por componente")
    parser.add_argument("--session-dir", type=str, default="", help="Override HUNT_SESSION_DIR (benchmark mode)")
    parser.add_argument("--protocol", type=str, default="", help="Protocol name (benchmark mode, overrides current_hunt.json)")
    args = parser.parse_args()

    hunt = load_current_hunt()

    # Gate enforcement: verify deepdive is complete before merge
    if args.component and not args.list and not args.generate_only:
        # If --hypotheses-dir is passed, do a direct file existence check
        # (avoids pipeline_gate.py namespace mismatch in benchmark mode)
        if args.hypotheses_dir:
            dd_file = Path(args.hypotheses_dir) / f"hyp_{args.component}_DeepDiveHunter.yaml"
            gate_ok = dd_file.exists()
        else:
            gate_cmd = [
                sys.executable,
                str(Path(__file__).parent / "pipeline_gate.py"),
                "-c", args.component, "--gate", "deepdive"
            ]
            if args.session_dir:
                gate_cmd += ["--session-dir", args.session_dir]
            if args.protocol:
                gate_cmd += ["--protocol", args.protocol]
            gate_result = subprocess.run(gate_cmd, capture_output=True)
            gate_ok = gate_result.returncode == 0
        if not gate_ok:
            print(f"\u2717 Gate FAIL: deepdive gate not passed for {args.component}")
            print(f"  Run hunters + deepdive before merge_invariants.py")
            print(f"  Use: pipeline_gate.py -c {args.component} --status")
            return 1

    # Si --output se especifica, forzar modo monolítico
    if args.output:
        args.monolithic = True

    # Localizar chimera dir
    chimera_dir = find_chimera_dir(hunt)
    properties_path = find_properties_sol(hunt)

    if args.output:
        properties_path = Path(args.output)
        chimera_dir = properties_path.parent

    if not properties_path or not properties_path.exists():
        print("✗ No se encontró Properties.sol")
        print("  Especifica con --output FILE.sol")
        return 1

    if args.list:
        list_invariants(chimera_dir)
        return 0

    if args.dry_run:
        print("=== DRY RUN ===\n")

    # Escanear IDs existentes en TODOS los archivos Properties*.sol
    existing_ids = extract_existing_ids_from_dir(chimera_dir)
    print(f"Invariantes existentes: {len(existing_ids)}")
    if existing_ids and len(existing_ids) <= 40:
        print(f"  IDs: {', '.join(sorted(existing_ids))}")

    # Localizar hipótesis
    protocol = hunt.get("protocol", "")

    if args.hyp:
        hyp_files = [Path(args.hyp)]
        if not hyp_files[0].exists():
            hyp_files = [get_hyp_dir(protocol) / args.hyp]
        if not hyp_files[0].exists():
            print(f"✗ Hipótesis no encontrada: {args.hyp}")
            return 1
    else:
        hyp_dir = Path(args.hypotheses_dir) if args.hypotheses_dir else get_hyp_dir(protocol)
        if not hyp_dir.exists():
            print(f"✗ No existe directorio de hipótesis: {hyp_dir}")
            return 1
        hyp_files = sorted(p for p in hyp_dir.glob("hyp_*.yaml") if "template" not in p.name)
        if not hyp_files:
            print(f"  Sin archivos hyp_*.yaml en {hyp_dir}")
            return 0

    # Ejecutar modo
    if args.monolithic:
        rc = run_monolithic_mode(
            properties_path, hyp_files, existing_ids,
            args.include_low, args.dry_run, args.generate_only, args.component,
        )
    else:
        if args.generate_only:
            print("⚠ --generate-only solo funciona con --monolithic")
            return 1
        rc = run_split_mode(
            chimera_dir, hyp_files, existing_ids,
            args.include_low, args.dry_run, args.component,
        )

    # Auto-mark merge gate on success
    if rc == 0 and not args.dry_run and args.component:
        try:
            subprocess.run([
                "python3", str(Path(__file__).parent / "pipeline_gate.py"),
                "-c", args.component, "--mark", "merge"
            ], check=False, capture_output=True)
        except Exception:
            pass

    return rc


if __name__ == "__main__":
    sys.exit(main())
