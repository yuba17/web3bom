#!/usr/bin/env python3
"""
Hunt Dashboard Server — Read-only dashboard for bug bounty hunting pipeline.

Reads current_hunt.json + YAML fichas + hypothesis files.
Serves a consolidated JSON at /api/dashboard.
Does NOT modify any pipeline files.

Usage:
    python3 serve.py
    python3 serve.py --port 9090
    python3 serve.py --hunt-dir /path/to/hunt_session
    python3 serve.py --state /path/to/current_hunt.json
"""
import argparse
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None

# Defaults
DEFAULT_PORT = 8080
DEFAULT_STATE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
DEFAULT_HUNT_DIR = Path.cwd() / "hunt_session"

# Narrative templates (Spanish)
HUNTER_DOMAINS_ES = {
    "MathHunter": "Overflow, redondeo, precisión de precios",
    "AccessHunter": "Control de acceso, roles, modifiers",
    "FlowHunter": "Reentrancy, flujo de tokens, callbacks",
    "OracleHunter": "Manipulación de precios, TWAP, oráculos",
    "DomainHunter": "Invariantes del protocolo, ataques económicos",
    "WildcardHunter": "Vectores no convencionales, composabilidad",
    "TrustBoundaryHunter": "Límites de confianza, proxies, tokens raros",
}

CHECKLIST_LABELS = {
    "full_code_read": ("Lectura completa del código",
                       "Se leyó cada línea del contrato para entender la lógica completa."),
    "protocol_model": ("Modelo del protocolo",
                       "Documentado: qué hace, flujo de fondos, tokens, roles y dependencias externas."),
    "ai_invariants_generated": ("Invariantes generados",
                                "Propiedades que NUNCA deberían romperse. Cada una con código Solidity y escenario de ataque."),
    "invariants_added_to_properties": ("Invariantes en Properties.sol",
                                       "Propiedades añadidas al contrato de testing Chimera, listas para fuzzear."),
    "handlers_added": ("Handlers en TargetFunctions.sol",
                       "Funciones wrapper para cada función pública — el fuzzer las llama aleatoriamente."),
    "boundary_values": ("Valores límite en handlers",
                        "5% ceros, 5% unos, 5% máximos, 20% diminutos — los bugs de redondeo necesitan extremos."),
    "optimization_functions": ("Funciones de optimización",
                               "Funciones optimize_* para Echidna: maximiza el beneficio del atacante automáticamente."),
    "compile_check": ("Compilación — forge build",
                      "Verificando que todo compila sin errores antes de lanzar los fuzzers."),
    "foundry_fuzz": ("Fuzzing Foundry (5,000 runs)",
                     "Primera pasada rápida (~2 min). Valida invariantes y detecta bugs obvios."),
    "findings_logged": ("Findings documentados",
                        "Cada invariante roto se documenta en HUNT_TRACKER.md con severidad y análisis."),
    "tier1_separated": ("Invariantes Tier 1 confirmados",
                        "Separar findings confirmados (pérdida de fondos) de dust/artefactos de mock."),
    "tolerance_tuned": ("Tolerancias ajustadas",
                        "Clasificar cada fallo: bug real / redondeo / artefacto. Ajustar para explorar más profundo."),
}

NARRATIVE_TEMPLATES = {
    "hunter_launched": "Analizando {component} en busca de {domain_desc}. El hunter lee el código fuente completo y genera hipótesis de vulnerabilidad.",
    "hunter_completed": "Encontró {count} hipótesis. {tier1} de Tier 1 (posible pérdida de fondos).",
    "component_started": "Componente {priority} de {total} en el scope. {loc} líneas de código.",
    "component_completed": "Checklist de 12 items completado. {n_findings} findings, {n_hyp} hipótesis analizadas.",
    "convergence": "{count} hunters señalaron {function}() independientemente. Alta probabilidad de bug real.",
}

FUZZ_NARRATIVES = {
    1: "Foundry ejecutó runs aleatorios. Validación rápida de invariantes.",
    2: "Medusa busca secuencias multi-paso que el fuzzing aleatorio no alcanza.",
    3: "Fork de mainnet: confirmando findings contra contratos reales deployados.",
    4: "Echidna maximiza el beneficio del atacante automáticamente.",
    5: "Halmos prueba propiedades matemáticas para TODOS los inputs posibles.",
}


def load_hunt_state(state_path: str) -> dict:
    """Load current_hunt.json. Returns {} if missing, {'error': ...} if malformed."""
    p = Path(state_path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError as e:
        return {"error": f"JSON malformed: {e}"}
    except Exception as e:
        return {"error": str(e)}


def _load_yaml(path: Path) -> dict | None:
    """Load a YAML file. Returns None on failure."""
    try:
        if yaml:
            return yaml.safe_load(path.read_text())
        return {"_raw": True, "path": str(path)}
    except Exception:
        return None


def load_fichas(hunt_dir: str, protocol: str) -> dict:
    """Load ficha YAMLs for a protocol. Returns {component: ficha_data}."""
    fichas_dir = Path(hunt_dir) / "fichas" / protocol
    if not fichas_dir.is_dir():
        return {}
    result = {}
    for f in fichas_dir.glob("*.yaml"):
        if f.name == "ficha_template.yaml":
            continue
        data = _load_yaml(f)
        if data and isinstance(data, dict):
            comp = data.get("component", f.stem)
            result[comp] = {
                "status": data.get("status", "unknown"),
                "hunters_completed": data.get("hunters_completed", {}),
                "checklist": data.get("checklist", {}),
                "confirmed_findings": data.get("confirmed_findings", []),
                "dismissed_findings": data.get("dismissed_findings", []),
                "notes": data.get("notes", ""),
                "time_tracking": data.get("time_tracking", {}),
            }
    return result


def _extract_functions(text: str) -> list[str]:
    """Extract function names from text using regex heuristics."""
    fns = set()
    fns.update(re.findall(r'function\s+(\w+)\s*\(', text))
    fns.update(re.findall(r'\b(\w+)\(\)', text))
    noise = {'require', 'assert', 'emit', 'revert', 'return', 'if', 'for', 'while',
             'constructor', 'receive', 'fallback', 'this', 'super', 'check', 'test'}
    return sorted(fns - noise)


def load_hypotheses(hyp_dir: str) -> dict:
    """Load hypothesis YAMLs. Returns {component: {hunter: {count, tier1, items, functions_mentioned}}}."""
    d = Path(hyp_dir)
    if not d.is_dir():
        return {}
    result: dict = defaultdict(dict)
    known_hunters = set(HUNTER_DOMAINS_ES.keys())

    for f in sorted(d.glob("hyp_*.yaml")):
        if f.name == "hyp_template.yaml":
            continue
        data = _load_yaml(f)
        if not data or not isinstance(data, dict):
            continue

        component = data.get("component", "")
        hunter = data.get("hunter", "")

        if not component or not hunter:
            stem = f.stem
            parts = stem.replace("hyp_", "").rsplit("_", 1)
            if len(parts) == 2 and parts[1] in known_hunters:
                component = component or parts[0]
                hunter = hunter or parts[1]
            else:
                component = component or parts[0]
                hunter = hunter or "Other"

        invariants = data.get("invariants", [])
        if not isinstance(invariants, list):
            invariants = []

        all_text = ""
        items = []
        tier1_count = 0
        for inv in invariants:
            if not isinstance(inv, dict):
                continue
            desc = str(inv.get("description", ""))
            sol = str(inv.get("solidity", ""))
            conf = inv.get("confidence", 50)
            if isinstance(conf, str):
                try:
                    conf = int(conf.rstrip('%'))
                except ValueError:
                    conf = 50
            tier = 1 if conf >= 70 else 2
            if tier == 1:
                tier1_count += 1
            all_text += f" {desc} {sol}"
            items.append({
                "id": inv.get("id", ""),
                "description": desc,
                "confidence": conf,
                "tier": tier,
            })

        fns = _extract_functions(all_text)

        result[component][hunter] = {
            "count": len(items),
            "tier1": tier1_count,
            "items": items,
            "functions_mentioned": fns,
        }

    return dict(result)


def compute_convergence(hypotheses: dict) -> dict:
    """Compute function convergence map from hypotheses. Returns {component: [{function, hunters, count}]}."""
    result = {}
    for component, hunters in hypotheses.items():
        fn_hunters: dict[str, set] = defaultdict(set)
        for hunter_name, hunter_data in hunters.items():
            for fn in hunter_data.get("functions_mentioned", []):
                fn_hunters[fn].add(hunter_name)
        convergent = [
            {"function": fn, "hunters": sorted(hset), "count": len(hset)}
            for fn, hset in fn_hunters.items()
            if len(hset) >= 2
        ]
        if convergent:
            convergent.sort(key=lambda x: x["count"], reverse=True)
            result[component] = convergent
    return result


def build_activity_log(hunt_dir: str, hypotheses: dict) -> list:
    """Build activity log from file timestamps."""
    events = []
    d = Path(hunt_dir)

    hyp_dir = d / "hypotheses"
    if hyp_dir.is_dir():
        for f in hyp_dir.glob("hyp_*.yaml"):
            if f.name == "hyp_template.yaml":
                continue
            mtime = f.stat().st_mtime
            stem = f.stem.replace("hyp_", "")
            parts = stem.rsplit("_", 1)
            component = parts[0] if parts else stem
            hunter = parts[1] if len(parts) == 2 else "Unknown"

            h_data = hypotheses.get(component, {}).get(hunter, {})
            count = h_data.get("count", 0)
            tier1 = h_data.get("tier1", 0)

            narrative = NARRATIVE_TEMPLATES["hunter_completed"].format(
                count=count, tier1=tier1
            )

            events.append({
                "time": datetime.fromtimestamp(mtime).strftime("%H:%M"),
                "timestamp": mtime,
                "event": f"{hunter} completado — {count} hipótesis, {tier1} Tier 1",
                "narrative": narrative,
                "type": "success",
                "component": component,
            })

    ctx_dir = d / "context"
    if ctx_dir.is_dir():
        for f in ctx_dir.glob("*_prompt.md"):
            mtime = f.stat().st_mtime
            stem = f.stem.replace("_prompt", "")
            parts = stem.rsplit("_", 1)
            component = parts[0] if parts else stem
            hunter = parts[1] if len(parts) == 2 else "Unknown"

            domain_desc = HUNTER_DOMAINS_ES.get(hunter, "análisis")
            narrative = NARRATIVE_TEMPLATES["hunter_launched"].format(
                component=component, domain_desc=domain_desc
            )

            events.append({
                "time": datetime.fromtimestamp(mtime).strftime("%H:%M"),
                "timestamp": mtime,
                "event": f"{hunter} lanzado para {component}",
                "narrative": narrative,
                "type": "info",
                "component": component,
            })

    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)
    for e in events:
        e.pop("timestamp", None)
    return events[:50]


def derive_confirmed_count(findings: list) -> int:
    """Count findings with status != PARKED."""
    return sum(1 for f in findings if f.get("status", "").upper() != "PARKED")


def build_dashboard(state_path: str, hunt_dir: str) -> dict:
    """Build the complete dashboard JSON response."""
    state = load_hunt_state(state_path)

    if "error" in state:
        return {"error": state["error"], "protocol": None}

    if not state:
        return {"error": "No hay hunt activo", "protocol": None}

    protocol = state.get("protocol", "unknown")
    findings = state.get("findings", [])

    fichas = load_fichas(hunt_dir, protocol)
    hypotheses = load_hypotheses(str(Path(hunt_dir) / "hypotheses"))
    convergence = compute_convergence(hypotheses)
    activity_log = build_activity_log(hunt_dir, hypotheses)

    components_done = state.get("components_done", [])
    component_map = state.get("component_map", [])
    total_components = len(components_done) + len(state.get("components_remaining", []))
    if total_components == 0 and component_map:
        total_components = len([c for c in component_map if c.get("loc", 0) >= 50])

    return {
        "protocol": protocol,
        "platform": state.get("platform", ""),
        "payout": state.get("payout", ""),
        "status": state.get("status", "unknown"),
        "current_component": state.get("current_component"),
        "components_done": components_done,
        "components_remaining": state.get("components_remaining", []),
        "total_components": total_components,
        "component_map": component_map,
        "findings": findings,
        "confirmed_count": derive_confirmed_count(findings),
        "fichas": fichas,
        "hypotheses": {
            comp: {
                hunter: {k: v for k, v in data.items() if k != "functions_mentioned"}
                for hunter, data in hunters.items()
            }
            for comp, hunters in hypotheses.items()
        },
        "convergence": convergence,
        "activity_log": activity_log,
        "checklist_labels": {k: {"label": v[0], "desc": v[1]} for k, v in CHECKLIST_LABELS.items()},
        "hunter_domains": HUNTER_DOMAINS_ES,
        "timestamp": datetime.now().isoformat(),
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves index.html and /api/dashboard."""

    state_path = str(DEFAULT_STATE)
    hunt_dir = str(DEFAULT_HUNT_DIR)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/dashboard":
            data = build_dashboard(self.state_path, self.hunt_dir)
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/" or parsed.path == "":
            self.path = "/index.html"
            super().do_GET()
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/refresh":
            data = build_dashboard(self.state_path, self.hunt_dir)
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress noisy access logs, keep errors."""
        if args and "200" in str(args):
            return
        super().log_message(format, *args)


def main():
    parser = argparse.ArgumentParser(description="Hunt Dashboard Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--hunt-dir", type=str, default=str(DEFAULT_HUNT_DIR))
    parser.add_argument("--state", type=str, default=str(DEFAULT_STATE))
    args = parser.parse_args()

    DashboardHandler.state_path = args.state
    DashboardHandler.hunt_dir = args.hunt_dir

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    server = HTTPServer(("127.0.0.1", args.port), DashboardHandler)
    print(f"Hunt Dashboard → http://localhost:{args.port}")
    print(f"  State:    {args.state}")
    print(f"  Hunt dir: {args.hunt_dir}")
    print(f"  Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
