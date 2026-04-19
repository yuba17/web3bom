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
import subprocess
import argparse
from pathlib import Path

from merge.loading import (
    get_hyp_dir,
    load_current_hunt,
    find_chimera_dir,
    find_properties_sol,
)
from merge.hypothesis import (
    extract_existing_ids_from_dir,
)
from merge.modes import (
    run_split_mode,
    insert_into_properties_sol,
    run_monolithic_mode,
    list_invariants,
)


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
