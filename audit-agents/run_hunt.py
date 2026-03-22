#!/usr/bin/env python3
"""
run_hunt.py — Coordinador autónomo del pipeline de hunting

Prepara el contexto para los 6 hunters, orquesta el análisis, y actualiza el estado.
Este script es el punto de entrada para un hunt autónomo de un componente.

Uso:
    python3 run_hunt.py --component GaugeManager
    python3 run_hunt.py --component GaugeManager --hunters math,access,flow
    python3 run_hunt.py --status                    # estado del hunt actual
    python3 run_hunt.py --complete GaugeManager     # marca componente como completo
    python3 run_hunt.py --init-ficha GaugeManager   # crea ficha vacía para el componente

Salida:
    - hunt_session/context/{Component}_context.md  (contexto para hunters)
    - hunt_session/fichas/{protocol}/{Component}.yaml  (ficha del componente)
    - Imprime los prompts que Claude debe ejecutar con Agent tool
"""

import sys
import os
import re
import json
import yaml
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

WEB3_DIR = Path.home() / "Documents/Web3"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
AUDIT_AGENTS_DIR = WEB3_DIR / "audit-agents"
STATE_FILE = Path.home() / ".claude/MEMORY/STATE/current_hunt.json"
KNOWLEDGE_DIR = WEB3_DIR / "knowledge"
SOLODIT_SEARCH = AUDIT_AGENTS_DIR / "solodit_search.py"

HUNTER_DOMAINS = {
    "MathHunter":    ("math",    "Overflow, rounding, precision, exchange rate math, share price manipulation"),
    "AccessHunter":  ("access",  "Access control, missing modifiers, privilege escalation, role misconfig"),
    "FlowHunter":    ("flow",    "Reentrancy, CEI violations, token flow, callback abuse, fund routing"),
    "OracleHunter":  ("oracle",  "Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies"),
    "DomainHunter":  ("domain",  "Protocol-specific invariants, cross-component interactions, economic attacks"),
    "WildcardHunter":("wildcard","Novel bugs, unconventional vectors, assumption violations, composability risks"),
}

DOMAIN_BRIEFING = {
    # Core DeFi
    "staking":    "knowledge/staking.md",
    "lending":    "knowledge/lending.md",
    "vault":      "knowledge/vault-erc4626.md",
    "oracle":     "knowledge/oracle.md",
    "dex":        "knowledge/dex-amm.md",
    "flash":      "knowledge/flash-loan.md",
    "token":      "knowledge/token-erc20.md",
    # Security primitives
    "access":     "knowledge/access-control.md",
    "signature":  "knowledge/signature-replay.md",
    "proxy":      "knowledge/proxy-upgrade.md",
    # Bridges & L2
    "bridge":     "knowledge/bridge.md",
    "opstack":    "knowledge/bridge-opstack.md",
    # Emerging
    "erc4337":    "knowledge/erc4337-account-abstraction.md",
    "zk":         "knowledge/zk-circuits.md",
    "governance": "knowledge/governance.md",
    "nft":        "knowledge/nft-erc721.md",
    "yield":      "knowledge/yield-aggregator.md",
}

# Keywords para auto-detectar dominios del código fuente del contrato.
# Orden importa: más keywords específicas = mejor señal.
DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "opstack":   ["OptimismPortal", "CrossDomainMessenger", "L2OutputOracle",
                  "FaultDisputeGame", "PreimageOracle", "finalizeWithdrawal",
                  "proveWithdrawal", "respectedGameType", "SuperchainConfig"],
    "erc4337":   ["UserOperation", "EntryPoint", "IPaymaster", "validateUserOp",
                  "handleOps", "IAccount", "PackedUserOperation", "SpendPermission"],
    "staking":   ["gauge", "emission", "bribe", "veToken", "GaugeManager",
                  "notifyRewardAmount", "rewardPerToken", "earned", "getReward",
                  "stake", "unstake", "checkpoint", "votingPower"],
    "lending":   ["borrow", "repay", "liquidat", "collateral", "debtShares",
                  "lendingPool", "healthFactor", "maxWithdraw", "utilizationRate"],
    "vault":     ["totalAssets", "convertToShares", "convertToAssets",
                  "maxDeposit", "ERC4626", "previewDeposit", "previewMint"],
    "oracle":    ["twap", "getPrice", "latestRoundData", "IUniswapV3Pool",
                  "observe", "slot0", "sqrtPriceX96", "getPriceX96", "TWAP"],
    "dex":       ["swap", "addLiquidity", "removeLiquidity", "tick",
                  "IUniswapV3", "getAmountOut", "reserve0", "reserve1", "k ="],
    "flash":     ["flashLoan", "executeFlashLoan", "onFlashLoan",
                  "flashCallback", "IERC3156", "maxFlashLoan"],
    "bridge":    ["LayerZero", "CCIP", "lzReceive", "ccipReceive",
                  "xCall", "relayMessage", "sendMessage", "IBC"],
    "proxy":     ["upgradeable", "implementation", "StorageSlot",
                  "UUPSUpgradeable", "TransparentUpgradeableProxy", "_upgradeToAndCall"],
    "signature": ["ecrecover", "ECDSA", "EIP712", "permit",
                  "SignatureChecker", "nonces", "DOMAIN_SEPARATOR"],
    "access":    ["onlyOwner", "AccessControl", "Ownable", "onlyRole",
                  "hasRole", "grantRole", "revokeRole"],
    "token":     ["feeOnTransfer", "rebase", "deflation", "taxed",
                  "elastic", "shares", "_gonsPerFragment"],
    "zk":        ["Groth16", "PlonK", "verifyProof", "IVerifier",
                  "zkProof", "circuit", "snark", "constraint"],
    "governance": ["Governor", "TimelockController", "propose", "castVote",
                   "proposalThreshold", "quorum", "vetoer", "timelock",
                   "GovernorBravo", "getPastVotes", "proposalsPassed"],
    "nft":        ["ERC721", "onERC721Received", "safeTransferFrom", "tokenId",
                   "ownerOf", "getApproved", "setApprovalForAll", "_safeMint",
                   "IERC721", "ERC721Enumerable", "NonfungiblePositionManager"],
    "yield":      ["BaseStrategy", "TokenizedStrategy", "harvest", "tend",
                   "prepareReturn", "liquidatePosition", "_deployFunds", "_freeFunds",
                   "strategyDebt", "maxDebt", "pricePerShare", "totalDebt",
                   "yieldToken", "aToken", "harvestFees", "migrate"],
}


def load_hunt_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError as e:
            print(f"✗ CRÍTICO: current_hunt.json corrupto: {e}")
            backup = STATE_FILE.with_suffix('.backup.json')
            if backup.exists():
                print(f"  Recuperando desde backup: {backup}")
                try:
                    return json.loads(backup.read_text())
                except Exception:
                    pass
            print(f"  Sin recuperación posible. Revisa {STATE_FILE}")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Error leyendo current_hunt.json: {e}")
            sys.exit(1)
    return {}


def save_hunt_state(state: dict):
    """Escritura atómica: escribe a .tmp, luego rename. Mantiene .backup.json."""
    import tempfile, shutil as _shutil
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    # Guardar backup antes de sobreescribir
    if STATE_FILE.exists():
        _shutil.copy2(STATE_FILE, STATE_FILE.with_suffix('.backup.json'))
    # Escritura atómica via rename
    tmp = STATE_FILE.with_suffix('.tmp.json')
    try:
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_FILE)
    except Exception as e:
        print(f"✗ Error guardando estado: {e}")
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def find_contract(component: str, repo_path: str) -> Path | None:
    """Localiza el contrato Solidity de un componente."""
    repo = Path(repo_path)
    candidates = [
        repo / f"src/{component}.sol",
        repo / f"contracts/{component}.sol",
        repo / f"src/automators/{component}.sol",
        repo / f"src/transformers/{component}.sol",
        repo / f"src/utils/{component}.sol",
        repo / f"src/interfaces/{component}.sol",
    ]
    for c in candidates:
        if c.exists():
            return c

    # Búsqueda recursiva
    matches = list(repo.glob(f"**/{component}.sol"))
    if matches:
        return matches[0]

    return None


def count_locs(file_path: Path) -> int:
    """Cuenta líneas de código (excluyendo comentarios y líneas vacías)."""
    try:
        lines = file_path.read_text().split("\n")
        code_lines = [l for l in lines if l.strip() and not l.strip().startswith("//")]
        return len(code_lines)
    except:
        return 0


def get_solodit_context(domain: str, keywords: list, component: str = "") -> str:
    """
    Obtiene contexto de Solodit con múltiples queries específicas.
    3 búsquedas: (1) componente+dominio, (2) solo dominio HIGH/CRITICAL, (3) sin dominio
    para maximizar señal relevante para el hunter.
    """
    if not SOLODIT_SEARCH.exists():
        return ""

    def run_search(extra_args: list, q: str) -> str:
        try:
            result = subprocess.run(
                [sys.executable, str(SOLODIT_SEARCH), *extra_args, q],
                capture_output=True, text=True, timeout=20
            )
            return result.stdout or ""
        except Exception:
            return ""

    parts = []
    seen_titles: set = set()

    # Query 1: componente específico (sin filtro de dominio — mayor recall)
    if component:
        out = run_search(["--limit", "5", "--hunter-context", "--component", component], component)
        if out.strip():
            parts.append(f"### Findings sobre {component}\n{out}")
            for line in out.splitlines():
                if line.startswith(" ") and "]" in line:
                    seen_titles.add(line.strip()[:60])

    # Query 2: dominio + keywords del contrato, solo HIGH/CRITICAL
    kw = " ".join(k for k in keywords if k.lower() != domain)[:80]
    if kw:
        out = run_search(["--domain", domain, "--severity", "high",
                          "--limit", "6", "--hunter-context"], kw)
        if out.strip():
            # Dedup: omitir líneas ya vistas
            filtered = [l for l in out.splitlines()
                        if not any(l.strip()[:60] in t for t in seen_titles)]
            if filtered:
                parts.append(f"### HIGH findings en dominio {domain}\n" + "\n".join(filtered))

    # Query 3: query genérica sin dominio para patrones cross-domain
    generic_kw = (kw or domain)[:60]
    out = run_search(["--severity", "high", "--limit", "4", "--hunter-context"], generic_kw)
    if out.strip():
        filtered = [l for l in out.splitlines()
                    if not any(l.strip()[:60] in t for t in seen_titles)]
        if filtered:
            parts.append(f"### Cross-domain HIGH relevantes\n" + "\n".join(filtered))

    combined = "\n\n".join(parts)
    return combined[:4000]  # aumentado de 2000 a 4000


def detect_domains(contract_src: str, max_domains: int = 3) -> list:
    """
    Auto-detecta los dominios más relevantes del código fuente del contrato.
    Devuelve hasta max_domains dominios ordenados por número de keywords encontradas.
    """
    src_lower = contract_src.lower()
    scores: dict[str, int] = {}
    for domain, keywords in DOMAIN_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw.lower() in src_lower)
        if score > 0:
            scores[domain] = score
    return [d for d, _ in sorted(scores.items(), key=lambda x: -x[1])][:max_domains]


def load_briefing_single(domain: str) -> str:
    """Carga y comprime un único briefing."""
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except:
        return ""

    lines = text.split("\n")
    sections = {
        "bugs_index": [],    # Lista de bugs conocidos (solo IDs + nombres)
        "trampas": [],       # Falsos positivos — NO perder tiempo en esto
        "checklist": [],     # Invariant checklist
        "grep": [],          # Grep targets
        "incidents": [],     # Incidentes reales
    }

    current = None
    in_trampa_block = False

    for i, line in enumerate(lines):
        # Índice de bugs conocidos (solo titulos)
        if line.startswith("### 1.") or line.startswith("### 2."):
            sections["bugs_index"].append(line.strip())
            current = None

        # Sección checklist
        elif "Invariant Checklist" in line or "## 3." in line:
            current = "checklist"
        elif "Grep Targets" in line or "## 4." in line:
            current = "grep"
        elif "Real-World Incidents" in line or "## 2.3" in line:
            current = "incidents"

        # Líneas de trampas (captura las listas de trampas de cada bug)
        elif line.strip() == "trampas:":
            in_trampa_block = True
        elif in_trampa_block:
            if line.strip().startswith("- ") or line.strip().startswith("  - "):
                sections["trampas"].append(line.strip())
            elif line.strip() and not line.strip().startswith(" "):
                in_trampa_block = False

        # Acumular secciones estructuradas
        elif current in sections:
            if line.strip():
                sections[current].append(line)
            # Stop at next ## section
            if line.startswith("## ") and current != "checklist":
                current = None

    # Construir el resumen comprimido
    parts = []

    if sections["bugs_index"]:
        parts.append("## PATRONES CONOCIDOS (busca primero estos)")
        parts.extend(sections["bugs_index"])

    if sections["trampas"]:
        parts.append("\n## TRAMPAS — NO pierdas tiempo en esto")
        # Dedup y limitar
        seen = set()
        for t in sections["trampas"]:
            clean = t.strip().lstrip("- ").strip('"')
            if clean and clean not in seen:
                seen.add(clean)
                parts.append(f"  ⚠ {clean}")
                if len(seen) >= 12:
                    break

    if sections["checklist"]:
        parts.append("\n## CHECKLIST DE INVARIANTES")
        parts.extend(sections["checklist"][:20])

    if sections["grep"]:
        parts.append("\n## GREP TARGETS")
        parts.extend(sections["grep"][:15])

    if sections["incidents"]:
        parts.append("\n## INCIDENTES REALES (protocolos afectados)")
        parts.extend(sections["incidents"][:10])

    result = "\n".join(parts)

    # Fallback: si la extracción no obtuvo nada útil, usar los primeros 4000 chars
    if len(result) < 200:
        return text[:4000]

    return result


def load_grep_targets_only(domain: str) -> str:
    """Carga solo la sección Quick Grep Targets de un briefing — versión compacta para dominios secundarios."""
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except:
        return ""

    lines = text.split("\n")
    in_grep = False
    grep_lines = []
    for line in lines:
        if "Grep Targets" in line or "Quick Grep" in line or "## 4." in line:
            in_grep = True
            continue
        if in_grep:
            if line.startswith("## ") and grep_lines:
                break
            if line.strip():
                grep_lines.append(line)
            if len(grep_lines) >= 12:
                break

    return "\n".join(grep_lines)


def load_briefings(domains: list) -> str:
    """
    Carga briefings para múltiples dominios con estrategia de peso diferenciado:
    - Dominio primario (index 0): extracto completo (~1500 chars) — patrones, trampas, grep
    - Dominio secundario (index 1): solo grep targets (~300 chars) — señal sin ruido
    - Dominio terciario (index 2+): omitido — el Solodit context cubre cross-domain

    Rationale: más de un briefing completo satura el contexto del hunter con patrones
    irrelevantes y baja la calidad de los invariantes generados. Solo la sección
    de grep targets es suficientemente señal/ruido para dominios secundarios.
    """
    if not domains:
        return ""

    parts = []
    primary = domains[0]
    primary_text = load_briefing_single(primary)
    if primary_text:
        parts.append(f"### Briefing principal: {primary}\n{primary_text}")

    if len(domains) > 1:
        secondary = domains[1]
        grep_text = load_grep_targets_only(secondary)
        if grep_text:
            parts.append(f"\n### Grep targets adicionales ({secondary})\n{grep_text}")

    return "\n\n".join(parts)


def generate_hunter_prompt(
    hunter_name: str,
    component: str,
    contract_path: Path,
    domain: str,
    solodit_ctx: str,
    briefing_excerpt: str,
    protocol: str,
) -> str:
    """Genera el prompt completo para un hunter específico."""
    _, focus = HUNTER_DOMAINS.get(hunter_name, ("general", "General analysis"))
    abbreviation = "".join(w[0] for w in re.findall(r'[A-Z][a-z]*', component)).upper()
    if not abbreviation:
        abbreviation = component[:3].upper()

    contract_preview = ""
    contract_truncated = False
    CONTRACT_CHAR_LIMIT = 60_000
    if contract_path and contract_path.exists():
        full_src = contract_path.read_text()
        if len(full_src) > CONTRACT_CHAR_LIMIT:
            contract_preview = full_src[:CONTRACT_CHAR_LIMIT]
            contract_truncated = True
        else:
            contract_preview = full_src

    hyp_output = str(WEB3_DIR / f"hunt_session/hypotheses/hyp_{component}_{hunter_name}.yaml")

    return f"""# {hunter_name} — {component} Analysis

## Tu Identidad
Eres el **{hunter_name}** del equipo de bug hunting de {protocol}.
Tu especialidad: **{focus}**

## Tu Objetivo
Analizar `{component}` y producir invariantes ESPECÍFICOS y TESTABLES en formato Chimera.
No busques bugs genéricos. Busca bugs que nazcan de la lógica ESPECÍFICA de este componente.

## Contrato a Analizar
**Archivo**: `{contract_path}`
**Dominio**: {domain}
{"⚠ CONTRATO TRUNCADO: se muestran los primeros 60,000 chars. Usa el Read tool en " + str(contract_path) + " para leer el resto." if contract_truncated else ""}

```solidity
{contract_preview}
```

## Contexto de Solodit (bugs similares en protocolos similares)
{solodit_ctx or "Sin contexto disponible — busca patrones propios"}

## Briefing del Dominio ({domain})
{briefing_excerpt or "Sin briefing disponible"}

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad ({focus.split(',')[0]}) es relevante
3. **Genera 5-10 invariantes** — específicos, no genéricos
4. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
5. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
6. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

## Schema del Archivo de Salida
El archivo DEBE seguir el schema de `hunt_session/hypotheses/hyp_template.yaml`.
ID prefix para este componente: `{abbreviation}` (ej: {abbreviation}-01, {abbreviation}-02...)

## Output Requerido
**Escribe tu análisis en**: `{hyp_output}`

Ejemplo de invariante bien formado:
```yaml
- id: {abbreviation}-01
  tier: 1
  type: property
  description: "Descripción exacta del invariante"
  attack_scenario: "Si falla, un atacante puede extraer X fondos haciendo Y"
  solidity: |
    uint256 current = contract.value();
    gte(current, previous, "{abbreviation}-01: value decreased");
  validated: true
  priority: high
  confidence: 80
```

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
"""


def create_context_file(
    component: str,
    contract_path: Path,
    domain: str,
    solodit_ctx: str,
    briefing_excerpt: str,
    protocol: str,
) -> Path:
    """Crea el archivo de contexto compartido para todos los hunters."""
    context_dir = HUNT_SESSION_DIR / "context"
    context_dir.mkdir(parents=True, exist_ok=True)
    context_file = context_dir / f"{component}_context.md"

    locs = count_locs(contract_path) if contract_path else 0

    content = f"""# Contexto de Hunt — {component}

**Protocolo**: {protocol}
**Dominio**: {domain}
**LOC**: {locs}
**Archivo**: {contract_path}
**Generado**: {datetime.utcnow().isoformat()}Z

## Solodit Context
{solodit_ctx or "No disponible"}

## Briefing del Dominio
{briefing_excerpt[:2000] if briefing_excerpt else "No disponible"}
"""
    context_file.write_text(content)
    return context_file


def init_ficha(component: str, domain: str, protocol: str, repo_path: str) -> Path:
    """Crea una ficha vacía para el componente."""
    template = HUNT_SESSION_DIR / "fichas" / "ficha_template.yaml"
    ficha_dir = HUNT_SESSION_DIR / "fichas" / protocol
    ficha_dir.mkdir(parents=True, exist_ok=True)
    ficha_path = ficha_dir / f"{component}.yaml"

    if ficha_path.exists():
        print(f"  Ficha ya existe: {ficha_path}")
        return ficha_path

    contract_path = find_contract(component, repo_path) if repo_path else None
    locs = count_locs(contract_path) if contract_path else 0

    ficha = {
        "protocol": protocol,
        "component": component,
        "file": str(contract_path.relative_to(Path(repo_path))) if contract_path and repo_path else f"src/{component}.sol",
        "domain": domain,
        "locs": locs,
        "audited_at": datetime.utcnow().isoformat() + "Z",
        "auditor": "Claude/MultiHunter",
        "status": "in_progress",
        "confirmed_findings": [],
        "dismissed_findings": [],
        "false_positives": [],
        "pending_briefing_updates": [],
        "hunters_completed": {h: False for h in HUNTER_DOMAINS},
        "checklist": {
            "full_code_read": False,
            "protocol_model": False,
            "ai_invariants_generated": False,
            "invariants_added_to_properties": False,
            "handlers_added": False,
            "boundary_values": False,
            "optimization_functions": False,
            "compile_check": False,
            "foundry_fuzz": False,
            "findings_logged": False,
            "tier1_separated": False,
            "tolerance_tuned": False,
        },
        "notes": "",
        "feedback_applied": None,
    }

    with open(ficha_path, "w") as f:
        yaml.dump(ficha, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"  ✓ Ficha creada: {ficha_path}")
    return ficha_path


def print_status(state: dict):
    """Imprime el estado del hunt activo."""
    if not state:
        print("No hay hunt activo en STATE/current_hunt.json")
        return

    print(f"\n{'='*60}")
    print(f"  HUNT ACTIVO: {state.get('protocol', '?').upper()}")
    print(f"{'='*60}")
    print(f"  Plataforma:  {state.get('platform', '?')}")
    print(f"  Payout:      {state.get('payout', '?')}")
    print(f"  Deadline:    {state.get('deadline', '?')}")
    print(f"  Componente:  {state.get('current_component', '?')}")
    print(f"  Completados: {', '.join(state.get('components_done', []))}")
    print(f"  Pendientes:  {', '.join(state.get('components_remaining', []))}")
    print(f"  Findings:    {state.get('confirmed_findings', 0)}")

    findings = state.get("findings", [])
    for f in findings:
        status_icon = "⚠️ " if f.get("status") == "confirmed_not_reported" else "✓ "
        print(f"    {status_icon}[{f.get('severity','?').upper()}] {f.get('id')}: {f.get('description','')[:60]}")

    # Check fichas
    fichas_dir = HUNT_SESSION_DIR / "fichas" / state.get("protocol", "")
    if fichas_dir.exists():
        fichas = list(fichas_dir.glob("*.yaml"))
        print(f"\n  Fichas ({len(fichas)}):")
        for ficha_path in fichas:
            try:
                data = yaml.safe_load(ficha_path.read_text())
                hunters_done = sum(1 for v in data.get("hunters_completed", {}).values() if v)
                total_hunters = len(HUNTER_DOMAINS)
                status = data.get("status", "?")
                print(f"    {ficha_path.stem}: {hunters_done}/{total_hunters} hunters | {status}")
            except:
                print(f"    {ficha_path.stem}: (error leyendo)")

    # Check hypotheses
    hyps = list((HUNT_SESSION_DIR / "hypotheses").glob(f"hyp_*.yaml"))
    if hyps:
        print(f"\n  Hipótesis ({len(hyps)}):")
        for h in sorted(hyps):
            if "template" in h.name:
                continue
            try:
                data = yaml.safe_load(h.read_text())
                n_inv = len([i for i in data.get("invariants", []) if i.get("validated", True)])
                print(f"    {h.name}: {n_inv} invariantes validados")
            except:
                print(f"    {h.name}")


def main():
    parser = argparse.ArgumentParser(description="Coordinador autónomo de bug hunting")
    parser.add_argument("--component", "-c", type=str, help="Componente a huntar")
    parser.add_argument("--hunters", type=str, default="all",
                        help="Hunters a usar: all | math,access,flow,oracle,domain,wildcard")
    parser.add_argument("--domain", "-d", type=str, help="Dominio del componente")
    parser.add_argument("--status", "-s", action="store_true", help="Muestra estado del hunt")
    parser.add_argument("--init-ficha", type=str, metavar="COMPONENT", help="Solo crea ficha vacía")
    parser.add_argument("--complete", type=str, metavar="COMPONENT", help="Marca componente como completo")
    parser.add_argument("--no-solodit", action="store_true", help="Omitir búsqueda en Solodit")
    parser.add_argument("--print-prompts", action="store_true", help="Imprime prompts de hunters a stdout")
    args = parser.parse_args()

    state = load_hunt_state()

    if args.status:
        print_status(state)
        return 0

    if args.init_ficha:
        domain = args.domain or state.get("domain", "general")
        protocol = state.get("protocol", "unknown")
        repo = state.get("repo_path", "")
        init_ficha(args.init_ficha, domain, protocol, repo)
        return 0

    if args.complete:
        comp = args.complete
        if comp in state.get("components_remaining", []):
            state["components_remaining"].remove(comp)
        if comp not in state.get("components_done", []):
            state.setdefault("components_done", []).append(comp)
        # Avanzar current_component al siguiente pendiente
        remaining = state.get("components_remaining", [])
        state["current_component"] = remaining[0] if remaining else None
        state["last_session"] = datetime.utcnow().isoformat() + "Z"
        save_hunt_state(state)
        print(f"✓ {comp} marcado como completado")
        if remaining:
            print(f"→ Siguiente componente: {remaining[0]}")
        # Auto-aplicar feedback de hipótesis al briefing
        print(f"\nAplicando feedback de hipótesis a briefings...")
        try:
            result = subprocess.run(
                [sys.executable, str(AUDIT_AGENTS_DIR / "apply_feedback.py"), "--hypotheses"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                # Mostrar solo el total final
                for line in reversed(result.stdout.splitlines()):
                    if "Total updates" in line:
                        print(f"  ✓ {line.strip()}")
                        break
            else:
                print(f"  ⚠ apply_feedback error: {result.stderr[:200]}")
        except Exception as e:
            print(f"  ⚠ apply_feedback no ejecutado: {e}")
        return 0

    if not args.component:
        parser.print_help()
        return 1

    component = args.component
    protocol = state.get("protocol", "unknown")
    repo_path = state.get("repo_path", "")

    # Auto-detectar dominios del contrato si no se especifica --domain
    component_domains = state.get("component_domains", {})
    forced_domain = args.domain or component_domains.get(component)

    # Localizar contrato temprano para poder hacer auto-detección
    contract_path_early = find_contract(component, repo_path) if repo_path else None
    detected_domains: list = []
    if not forced_domain and contract_path_early and contract_path_early.exists():
        src = contract_path_early.read_text()
        detected_domains = detect_domains(src, max_domains=2)
        if detected_domains:
            print(f"  Auto-detectado dominios: {detected_domains}")

    # Prioridad: --domain > component_domains > auto-detect > state.domain > staking
    if forced_domain:
        domains = [forced_domain]
    elif detected_domains:
        domains = detected_domains
    else:
        domains = [state.get("domain", "staking")]

    domain = domains[0]  # dominio primario (para Solodit y retrocompat)

    print(f"\n{'='*60}")
    print(f"  PREPARANDO HUNT: {component}")
    print(f"{'='*60}")

    # Localizar contrato (puede que ya lo tengamos de la auto-detección)
    contract_path = contract_path_early or (find_contract(component, repo_path) if repo_path else None)
    if not contract_path:
        print(f"  ⚠ Contrato no encontrado. Especifica --domain o comprueba repo_path")
    else:
        locs = count_locs(contract_path)
        print(f"  Contrato: {contract_path} ({locs} LOC)")

    # Solodit context — keywords extraídos del contrato si existe
    solodit_ctx = ""
    if not args.no_solodit:
        print(f"  Buscando contexto en Solodit (3 queries)...")
        # Extraer keywords específicos del contrato para queries más precisas
        contract_keywords = [component]
        if contract_path and contract_path.exists():
            src = contract_path.read_text()
            # Extraer nombres de funciones públicas/externas relevantes
            fn_names = re.findall(r'function\s+(\w+)\s*\(', src)
            # Quedarse con las más específicas (no getters genéricos)
            specific_fns = [f for f in fn_names
                           if len(f) > 6 and f not in
                           ('initialize', 'constructor', 'receive', 'fallback',
                            'transfer', 'approve', 'allowance', 'balanceOf')][:4]
            contract_keywords.extend(specific_fns)
        contract_keywords.append(domain)
        solodit_ctx = get_solodit_context(domain, contract_keywords, component=component)
        if solodit_ctx:
            print(f"  ✓ Contexto Solodit obtenido ({len(solodit_ctx)} chars, keywords: {contract_keywords[:4]})")
        else:
            print(f"  ⚠ Sin contexto Solodit")

    # Briefings (primario completo + secundario solo grep)
    briefing_excerpt = load_briefings(domains)
    if briefing_excerpt:
        label = " + ".join(domains)
        print(f"  ✓ Briefings cargados: {label}")

    # Crear context file
    ctx_file = create_context_file(component, contract_path, domain, solodit_ctx, briefing_excerpt, protocol)
    print(f"  ✓ Context file: {ctx_file}")

    # Crear/actualizar ficha
    ficha_path = init_ficha(component, domain, protocol, repo_path)

    # Actualizar current_component en state
    state["current_component"] = component
    save_hunt_state(state)

    # Determinar hunters
    if args.hunters == "all":
        selected_hunters = list(HUNTER_DOMAINS.keys())
    else:
        selected_hunters = []
        for h in args.hunters.split(","):
            h = h.strip().lower()
            for name in HUNTER_DOMAINS:
                if h in name.lower():
                    selected_hunters.append(name)

    print(f"\n  Hunters seleccionados: {', '.join(selected_hunters)}")

    # Generar prompts
    prompts = {}
    for hunter_name in selected_hunters:
        prompts[hunter_name] = generate_hunter_prompt(
            hunter_name, component, contract_path, domain,
            solodit_ctx, briefing_excerpt, protocol
        )

    if args.print_prompts:
        for name, prompt in prompts.items():
            print(f"\n{'='*60}")
            print(f"PROMPT: {name}")
            print(f"{'='*60}")
            print(prompt[:500] + "...(truncado)")

    # Guardar prompts en context/
    prompts_dir = HUNT_SESSION_DIR / "context"
    for name, prompt in prompts.items():
        prompt_file = prompts_dir / f"{component}_{name}_prompt.md"
        prompt_file.write_text(prompt)

    print(f"\n{'='*60}")
    print(f"  LISTO PARA HUNT AUTÓNOMO")
    print(f"{'='*60}")
    print(f"\n  Prompts generados en: hunt_session/context/")
    print(f"  Ficha creada en:      {ficha_path}")
    print(f"  Context en:           {ctx_file}")
    print(f"\n  SIGUIENTE PASO — ejecutar en Claude con Agent tool:")
    print(f"\n  Lanza 6 hunters en paralelo usando:")
    print(f"  Agent(subagent_type='general', prompt=<contenido de cada _prompt.md>)")
    print(f"\n  Cada hunter escribe su resultado en:")
    for h in selected_hunters:
        print(f"    hunt_session/hypotheses/hyp_{component}_{h}.yaml")
    print(f"\n  Cuando todos terminen (pipeline completo):")
    print(f"    python3 audit-agents/merge_invariants.py              # YAML → Properties.sol")
    print(f"    FOUNDRY_PROFILE=chimera forge build --build-info      # compilar")
    print(f"    FOUNDRY_PROFILE=chimera forge test --fuzz-runs 5000   # Phase 1: mock quick")
    print(f"    forge test --match-contract ForkTester --fuzz-runs 10000  # Phase 3: fork")
    print(f"    medusa fuzz --config test/chimera/medusa.json --timeout 600  # Phase 4")
    print(f"    python3 audit-agents/apply_feedback.py --hypotheses   # actualizar briefings")
    print(f"\n  Si hay findings confirmados con fork PoC:")
    print(f"    python3 audit-agents/report_finding.py --finding <ID>  # crea en Bounty Radar + Telegram")
    print(f"    python3 audit-agents/submit_finding.py --update <ID> --status REPORTED --submission-url <URL>")
    print(f"\n  ⚠  OBLIGATORIO: ejecutar merge_invariants.py ANTES del fuzzing")

    return 0


if __name__ == "__main__":
    sys.exit(main())
