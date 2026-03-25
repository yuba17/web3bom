# Hunt Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local read-only dashboard that shows hunt progress (components, checklist, hunters, fuzzing, findings) in real time.

**Architecture:** Python stdlib HTTP server (`serve.py`) reads `current_hunt.json` + YAML fichas + hypothesis files, consolidates into one JSON endpoint. Single-page HTML app (`index.html`) with Alpine.js fetches every 5s and renders everything with dark/light theme support.

**Tech Stack:** Python 3 stdlib (`http.server`, `json`, `yaml`), Alpine.js 3 (bundled locally), vanilla CSS with custom properties.

**Spec:** `docs/superpowers/specs/2026-03-23-hunt-dashboard-design.md`

---

## File Structure

```
hunt-dashboard/
  serve.py          ← HTTP server + /api/dashboard endpoint (~200 lines)
  index.html        ← SPA (HTML + CSS + Alpine.js) (~600 lines)
  alpine.min.js     ← Alpine.js v3 bundled locally (~15KB)
```

---

### Task 1: Create directory and download Alpine.js

**Files:**
- Create: `hunt-dashboard/alpine.min.js`

- [ ] **Step 1: Create directory and download Alpine.js**

```bash
mkdir -p hunt-dashboard
curl -sL https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js -o hunt-dashboard/alpine.min.js
```

- [ ] **Step 2: Verify download**

```bash
test -s hunt-dashboard/alpine.min.js && echo "OK" || echo "FAIL"
# Expected: OK
wc -c hunt-dashboard/alpine.min.js
# Expected: ~15000-50000 bytes
```

- [ ] **Step 3: Commit**

```bash
git add hunt-dashboard/alpine.min.js
git commit -m "feat(dashboard): add Alpine.js v3 bundled locally"
```

---

### Task 2: Build `serve.py` — HTTP server + data consolidation

**Files:**
- Create: `hunt-dashboard/serve.py`
- Test: `hunt-dashboard/test_serve.py`

This is the core backend. It reads all data sources and serves a consolidated JSON.

- [ ] **Step 1: Write test for data consolidation**

```python
# hunt-dashboard/test_serve.py
"""Tests for serve.py data consolidation logic."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add parent to path so we can import serve
sys.path.insert(0, os.path.dirname(__file__))
import serve


class TestLoadHuntState(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        result = serve.load_hunt_state("/nonexistent/path.json")
        self.assertEqual(result, {})

    def test_valid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"protocol": "test", "findings": []}, f)
            f.flush()
            result = serve.load_hunt_state(f.name)
            self.assertEqual(result["protocol"], "test")
            os.unlink(f.name)

    def test_malformed_json_returns_error(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{bad json")
            f.flush()
            result = serve.load_hunt_state(f.name)
            self.assertIn("error", result)
            os.unlink(f.name)


class TestLoadFichas(unittest.TestCase):
    def test_no_fichas_dir(self):
        result = serve.load_fichas("/nonexistent", "test-proto")
        self.assertEqual(result, {})

    def test_loads_yaml_excludes_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            proto_dir = Path(tmpdir) / "test-proto"
            proto_dir.mkdir()
            # Write a ficha
            (proto_dir / "Vault.yaml").write_text(
                "component: Vault\nstatus: complete\n"
                "hunters_completed:\n  MathHunter: true\n"
                "checklist:\n  full_code_read: true\n"
            )
            # Write template (should be excluded)
            (Path(tmpdir) / "ficha_template.yaml").write_text("template: true\n")
            result = serve.load_fichas(tmpdir, "test-proto")
            self.assertIn("Vault", result)
            self.assertEqual(result["Vault"]["status"], "complete")


class TestLoadHypotheses(unittest.TestCase):
    def test_no_dir(self):
        result = serve.load_hypotheses("/nonexistent")
        self.assertEqual(result, {})

    def test_parses_component_hunter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hyp_file = Path(tmpdir) / "hyp_Vault_MathHunter.yaml"
            hyp_file.write_text(
                "component: Vault\nhunter: MathHunter\n"
                "invariants:\n"
                "  - id: MATH-01\n"
                "    description: 'test invariant for withdraw()'\n"
                "    confidence: 75\n"
                "    solidity: 'function check_withdraw() public {}'\n"
            )
            # Template should be excluded
            (Path(tmpdir) / "hyp_template.yaml").write_text("template: true\n")
            result = serve.load_hypotheses(tmpdir)
            self.assertIn("Vault", result)
            self.assertIn("MathHunter", result["Vault"])
            self.assertEqual(result["Vault"]["MathHunter"]["count"], 1)


class TestComputeConvergence(unittest.TestCase):
    def test_two_hunters_same_function(self):
        hypotheses = {
            "Vault": {
                "MathHunter": {
                    "count": 1, "tier1": 0,
                    "items": [{"id": "M1", "description": "rounding in withdraw()", "confidence": 50}],
                    "functions_mentioned": ["withdraw"]
                },
                "FlowHunter": {
                    "count": 1, "tier1": 0,
                    "items": [{"id": "F1", "description": "reentrancy in withdraw()", "confidence": 60}],
                    "functions_mentioned": ["withdraw"]
                }
            }
        }
        result = serve.compute_convergence(hypotheses)
        self.assertIn("Vault", result)
        self.assertEqual(len(result["Vault"]), 1)
        self.assertEqual(result["Vault"][0]["function"], "withdraw")
        self.assertEqual(result["Vault"][0]["count"], 2)


class TestBuildActivityLog(unittest.TestCase):
    def test_empty_dir(self):
        result = serve.build_activity_log("/nonexistent", {})
        self.assertEqual(result, [])


class TestDeriveConfirmedCount(unittest.TestCase):
    def test_counts_non_parked(self):
        findings = [
            {"status": "PARKED"}, {"status": "CONFIRMED"}, {"status": "REPORTED"}
        ]
        self.assertEqual(serve.derive_confirmed_count(findings), 2)

    def test_all_parked(self):
        findings = [{"status": "PARKED"}, {"status": "PARKED"}]
        self.assertEqual(serve.derive_confirmed_count(findings), 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd hunt-dashboard && python3 -m pytest test_serve.py -v 2>&1 | head -30
# Expected: ModuleNotFoundError or ImportError (serve.py doesn't exist yet)
```

- [ ] **Step 3: Implement `serve.py`**

```python
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
import time
from collections import defaultdict
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    # Fallback: minimal YAML parser for simple files
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
        # Minimal fallback without PyYAML — just return raw text indicator
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
    # Pattern 1: function foo( in Solidity
    fns.update(re.findall(r'function\s+(\w+)\s*\(', text))
    # Pattern 2: foo() in descriptions
    fns.update(re.findall(r'\b([a-z_]\w+)\(\)', text))
    # Filter noise
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

        # Fallback: parse from filename if fields missing
        if not component or not hunter:
            stem = f.stem  # hyp_Vault_MathHunter
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

        # Extract function mentions
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
        # Only functions flagged by 2+ hunters
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

    # Hypothesis files → hunter completed events
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

            # Get counts from hypotheses dict
            h_data = hypotheses.get(component, {}).get(hunter, {})
            count = h_data.get("count", 0)
            tier1 = h_data.get("tier1", 0)

            domain_desc = HUNTER_DOMAINS_ES.get(hunter, "análisis")
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

    # Prompt files → hunter launched events
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

    # Sort by timestamp descending (newest first)
    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)

    # Remove internal timestamp field
    for e in events:
        e.pop("timestamp", None)

    # Limit to 50 most recent
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

    # Load data sources
    fichas = load_fichas(hunt_dir, protocol)
    hypotheses = load_hypotheses(str(Path(hunt_dir) / "hypotheses"))
    convergence = compute_convergence(hypotheses)
    activity_log = build_activity_log(hunt_dir, hypotheses)

    # Build response
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
            # Just return fresh data (same as GET /api/dashboard)
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

    # Serve from hunt-dashboard/ directory
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
```

- [ ] **Step 4: Run tests**

```bash
cd hunt-dashboard && python3 -m pytest test_serve.py -v
# Expected: All 8 tests PASS
```

- [ ] **Step 5: Smoke test with real data**

```bash
cd ~/Documents/Web3 && python3 -c "
import sys; sys.path.insert(0, 'hunt-dashboard')
import serve
data = serve.build_dashboard(
    str(serve.DEFAULT_STATE),
    str(serve.DEFAULT_HUNT_DIR)
)
import json
print(json.dumps({
    'protocol': data.get('protocol'),
    'components_done': len(data.get('components_done', [])),
    'findings': len(data.get('findings', [])),
    'fichas': len(data.get('fichas', {})),
    'hypotheses_components': len(data.get('hypotheses', {})),
    'convergence_components': len(data.get('convergence', {})),
    'activity_log_count': len(data.get('activity_log', [])),
}, indent=2))
"
# Expected: real data from PancakeSwap Infinity hunt
```

- [ ] **Step 6: Commit**

```bash
git add hunt-dashboard/serve.py hunt-dashboard/test_serve.py
git commit -m "feat(dashboard): serve.py — data consolidation + HTTP server"
```

---

### Task 3: Build `index.html` — Header + Progress + Component Map

**Files:**
- Create: `hunt-dashboard/index.html`

This creates the HTML shell with the first 3 sections: header, progress bar, component map. The component detail (Task 4) and other sections build on top.

- [ ] **Step 1: Create `index.html` with header, progress, and component map**

Create the file with:
- Full CSS (both themes, all styles from mockup v3)
- Alpine.js app initialization with `x-data` containing: `data: null, expanded: null, expandedFinding: null, expandedHunter: null, filter: 'all', loading: true`
- `init()` method that fetches `/api/dashboard` and sets up 5s interval
- Header section with protocol name, platform, payout, theme toggle, refresh indicator
- Progress bar section computed from `components_done.length / total_components`
- Component map grid with click-to-expand (`@click="expanded = expanded === comp.name ? null : comp.name"`)
- Filter buttons (all/done/active/pending)
- Alpine.js loaded from local `alpine.min.js` with CDN fallback

Key Alpine.js patterns to use:
```html
<div x-data="dashboard()" x-init="init()">
  <!-- Header uses x-text="data.protocol" etc -->
  <!-- Component map uses template x-for="comp in filteredComponents" -->
  <!-- Click: @click="expanded = expanded === comp.name ? null : comp.name" -->
</div>
<script>
function dashboard() {
  return {
    data: null, expanded: null, expandedFinding: null,
    expandedHunter: null, filter: 'all', loading: true,
    async init() {
      await this.refresh();
      setInterval(() => this.refresh(), 5000);
    },
    async refresh() {
      try {
        const r = await fetch('/api/dashboard');
        this.data = await r.json();
        this.loading = false;
      } catch(e) { console.error('Refresh failed:', e); }
    },
    get filteredComponents() {
      if (!this.data?.component_map) return [];
      if (this.filter === 'all') return this.data.component_map;
      return this.data.component_map.filter(c => c.status === this.filter);
    },
    setTheme(t) {
      document.documentElement.setAttribute('data-theme', t);
      localStorage.setItem('hunt-theme', t);
    }
  }
}
// Restore theme
const saved = localStorage.getItem('hunt-theme');
if (saved) document.documentElement.setAttribute('data-theme', saved);
</script>
```

All Spanish labels. Use the exact CSS from the mockup v3 (with CSS custom properties for theming).

- [ ] **Step 2: Test manually**

```bash
cd ~/Documents/Web3 && python3 hunt-dashboard/serve.py &
sleep 1
curl -s http://localhost:8080 | head -5
# Expected: <!DOCTYPE html>
curl -s http://localhost:8080/api/dashboard | python3 -m json.tool | head -10
# Expected: valid JSON with protocol, findings, etc.
kill %1
```

- [ ] **Step 3: Commit**

```bash
git add hunt-dashboard/index.html
git commit -m "feat(dashboard): index.html — header, progress, component map"
```

---

### Task 4: Add Component Detail panel (checklist + hunters + convergence + fuzzing)

**Files:**
- Modify: `hunt-dashboard/index.html`

Add the expandable detail panel that appears when a component is clicked. Contains 4 sub-sections.

- [ ] **Step 1: Add component detail HTML**

Inside `index.html`, after the component grid, add a `<div x-show="expanded" x-transition>` block containing:

**4a. Checklist**: iterate over `data.checklist_labels` keys, cross-reference with `data.fichas[expanded]?.checklist`. Show ✓/◉/○ icons with label and description in Spanish.

```html
<!-- Pattern: -->
<template x-for="[key, meta] in Object.entries(data.checklist_labels)" :key="key">
  <div class="check-item"
       :class="{ done: fichaChecklist[key], active: isActiveStep(key), pending: !fichaChecklist[key] && !isActiveStep(key) }">
    <span class="icon" x-text="fichaChecklist[key] ? '✓' : isActiveStep(key) ? '◉' : '○'"></span>
    <div class="check-item-content">
      <span class="label" x-text="meta.label"></span>
      <span class="desc" x-text="meta.desc"></span>
    </div>
  </div>
</template>
```

Add computed property `fichaChecklist` that returns `data.fichas[expanded]?.checklist || {}`.
Add `isActiveStep(key)` — the first unchecked step after all previous are checked.

**4b. Hunters**: iterate `data.fichas[expanded]?.hunters_completed`. For each hunter show card with domain from `data.hunter_domains[name]`, hypothesis count from `data.hypotheses[expanded]?.[name]`, click to expand items.

**4c. Convergence**: show `data.convergence[expanded]` if it exists. Each row: function name + hunter dots + count.

**4d. Fuzzing**: 5 static phase cards. Phase 1 state derived from `fichaChecklist.foundry_fuzz`. Others show as pending.

- [ ] **Step 2: Test manually**

Open `http://localhost:8080` in browser. Click a component with a ficha (e.g., one in `pancakeswap-infinity`). Verify:
- Checklist shows 12 items with correct states
- Hunters show with domain descriptions
- Convergence map appears if hypotheses exist
- Fuzzing phases render

- [ ] **Step 3: Commit**

```bash
git add hunt-dashboard/index.html
git commit -m "feat(dashboard): component detail — checklist, hunters, convergence, fuzzing"
```

---

### Task 5: Add Activity Feed + Findings table

**Files:**
- Modify: `hunt-dashboard/index.html`

- [ ] **Step 1: Add activity feed panel**

Add the right-side activity feed panel inside the main layout grid (alongside the component detail). Uses `data.activity_log` array. Each entry shows time, event, narrative, with type-based coloring.

```html
<div class="live-feed">
  <div class="live-feed-title"><span class="refresh-dot"></span> Actividad en Vivo</div>
  <template x-for="event in data.activity_log" :key="event.time + event.event">
    <div class="feed-item" :class="event.type">
      <div class="feed-time" x-text="event.time"></div>
      <div class="feed-event" x-text="event.event"></div>
      <div class="feed-narrative" x-text="event.narrative"></div>
    </div>
  </template>
</div>
```

- [ ] **Step 2: Add findings table**

Below the main layout, add the findings section. Each finding row is clickable to expand details.

```html
<template x-for="f in data.findings" :key="f.id">
  <tr @click="expandedFinding = expandedFinding === f.id ? null : f.id" style="cursor:pointer">
    <td x-text="f.id" style="color:var(--accent)"></td>
    <td x-text="f.title"></td>
    <td><span class="sev" :class="f.severity" x-text="f.severity"></span></td>
    <td x-text="f.component"></td>
    <td><span class="finding-status" :class="f.status.toLowerCase()" x-text="f.status"></span></td>
    <td x-text="(f.confidence || '?') + '%'"></td>
  </tr>
  <!-- Expanded row -->
  <tr x-show="expandedFinding === f.id" x-transition>
    <td colspan="6" style="padding:12px; color:var(--text-dim); font-size:11px">
      <div><strong>Componente:</strong> <span x-text="f.component"></span></div>
      <div><strong>Severidad:</strong> <span x-text="f.severity"></span></div>
      <div><strong>Confianza:</strong> <span x-text="(f.confidence || '?') + '%'"></span></div>
    </td>
  </tr>
</template>
```

- [ ] **Step 3: Test manually**

Open browser. Verify:
- Activity feed shows events sorted by time (newest first)
- Narratives in Spanish are readable
- Findings table renders with correct severity colors
- Click on finding expands detail row

- [ ] **Step 4: Commit**

```bash
git add hunt-dashboard/index.html
git commit -m "feat(dashboard): activity feed + findings table"
```

---

### Task 6: Integration test with real data

**Files:**
- Modify: `hunt-dashboard/test_serve.py` (add integration test)

- [ ] **Step 1: Add integration test**

Add to `test_serve.py`:

```python
class TestBuildDashboardIntegration(unittest.TestCase):
    """Integration test with real hunt data (if available)."""

    def test_real_data_if_available(self):
        state_path = str(Path.home() / ".claude/MEMORY/STATE/current_hunt.json")
        hunt_dir = str(Path.home() / "Documents/Web3/hunt_session")
        if not Path(state_path).exists():
            self.skipTest("No real hunt data available")

        data = serve.build_dashboard(state_path, hunt_dir)

        # Should not error
        self.assertNotIn("error", data)
        # Should have protocol
        self.assertIsNotNone(data.get("protocol"))
        # Should have checklist_labels (always present)
        self.assertEqual(len(data["checklist_labels"]), 12)
        # Should have hunter_domains (always present)
        self.assertGreaterEqual(len(data["hunter_domains"]), 6)
        # JSON serializable
        json.dumps(data, ensure_ascii=False)

    def test_server_startup(self):
        """Verify serve.py has valid syntax and can be imported."""
        import serve
        self.assertTrue(hasattr(serve, 'main'))
        self.assertTrue(hasattr(serve, 'build_dashboard'))
        self.assertTrue(hasattr(serve, 'DashboardHandler'))
```

- [ ] **Step 2: Run all tests**

```bash
cd hunt-dashboard && python3 -m pytest test_serve.py -v
# Expected: All tests PASS (including integration with real data)
```

- [ ] **Step 3: Full smoke test**

```bash
cd ~/Documents/Web3
python3 hunt-dashboard/serve.py --port 8081 &
sleep 1
# Verify API returns valid JSON
curl -s http://localhost:8081/api/dashboard | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(f'Protocol: {data.get(\"protocol\")}')
print(f'Components done: {len(data.get(\"components_done\", []))}')
print(f'Findings: {len(data.get(\"findings\", []))}')
print(f'Fichas: {len(data.get(\"fichas\", {}))}')
print(f'Hypotheses: {len(data.get(\"hypotheses\", {}))}')
print(f'Activity log: {len(data.get(\"activity_log\", []))}')
print(f'Convergence: {len(data.get(\"convergence\", {}))}')
assert data.get('protocol'), 'No protocol!'
assert len(data.get('checklist_labels', {})) == 12, 'Checklist labels missing!'
print('ALL OK')
"
# Verify HTML loads
curl -s http://localhost:8081/ | grep -c "alpine"
# Expected: >= 1
kill %1
```

- [ ] **Step 4: Commit**

```bash
git add hunt-dashboard/test_serve.py
git commit -m "test(dashboard): integration tests with real hunt data"
```

---

### Task 7: Add `.gitignore` entry and final cleanup

**Files:**
- Modify: `hunt-dashboard/index.html` (any polish)
- Check: `.gitignore` for `.superpowers/` entry

- [ ] **Step 1: Verify `.superpowers/` is in `.gitignore`**

```bash
grep -q ".superpowers" .gitignore 2>/dev/null && echo "Already in .gitignore" || echo ".superpowers/" >> .gitignore
```

- [ ] **Step 2: Final manual test**

```bash
cd ~/Documents/Web3 && python3 hunt-dashboard/serve.py &
# Open http://localhost:8080 in browser
# Test: Dark mode → Light mode → persists on refresh
# Test: Click component → detail expands with checklist
# Test: Wait 5s → auto-refresh (no flicker)
# Test: Click finding → expands
# Test: Activity feed shows events
kill %1
```

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore(dashboard): add .superpowers to gitignore"
```
