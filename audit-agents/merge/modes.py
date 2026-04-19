"""Orchestrators for merge_invariants package."""
import re
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

from merge.constants import HUNTER_FILE_MAP, CROSS_COMPONENT_HUNTERS
from merge.loading import (
    detect_pragma,
    load_hypothesis_file,
    validate_evidence_tables,
)
from merge.hypothesis import (
    process_hypothesis,
    _dedup_ghosts,
    extract_existing_ids_from_dir,
)
from merge.files import (
    generate_hunter_sol_file,
    generate_cross_component_sol_file,
    update_target_functions_import,
    clean_properties_base,
)


# ═══════════════════════════════════════════════════════════════════════
# SPLIT MODE — un archivo por hunter
# ═══════════════════════════════════════════════════════════════════════

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
