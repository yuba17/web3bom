"""Hypothesis processing for merge_invariants package."""
import re
from pathlib import Path

from merge.solidity import (
    generate_ghost_var,
    generate_property_function,
    generate_optimize_function,
)
from merge.loading import validate_hypothesis


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
