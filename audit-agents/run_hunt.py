#!/usr/bin/env python3
"""
run_hunt.py — Coordinador autónomo del pipeline de hunting

Prepara el contexto para los 7 hunters, orquesta el análisis, y actualiza el estado.
Este script es el punto de entrada para un hunt autónomo de un componente.

Uso:
    python3 run_hunt.py --component GaugeManager
    python3 run_hunt.py --component GaugeManager --hunters math,access,flow
    python3 run_hunt.py --status                    # estado del hunt actual
    python3 run_hunt.py --complete GaugeManager     # marca componente como completo
    python3 run_hunt.py --init-ficha GaugeManager   # crea ficha vacía para el componente
    python3 run_hunt.py --map-components            # escanea repo, genera component_map
    python3 run_hunt.py --map-components --force     # regenera component_map existente

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
from collections import Counter

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
    "TrustBoundaryHunter":("trust","Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions"),
    "SignatureHunter":("signature","Signature replay, permit abuse, EIP-712 issues, nonce handling, ecrecover validation, approval/allowance patterns, Permit2, meta-transactions"),
    "DoSHunter":     ("dos",      "Denial of service, gas griefing, unbounded loops, blocked withdrawals, revert-based DoS, resource exhaustion, emergency function blocking"),
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
    # Trust boundaries
    "trust":      "knowledge/trust-boundaries.md",
    # Bridges & L2
    "bridge":     "knowledge/bridge.md",
    "opstack":    "knowledge/bridge-opstack.md",
    # Emerging
    "erc4337":    "knowledge/erc4337-account-abstraction.md",
    "zk":         "knowledge/zk-circuits.md",
    "governance": "knowledge/governance.md",
    "nft":        "knowledge/nft-erc721.md",
    "yield":      "knowledge/yield-aggregator.md",
    "liquid":     "knowledge/liquid-staking.md",
    "perps":      "knowledge/perps-derivatives.md",
    "crosschain": "knowledge/cross-chain-intents.md",
    "vesting":    "knowledge/vesting-tokenomics.md",
    "options":    "knowledge/options-structured-products.md",
    "mev":        "knowledge/mev-sandwich.md",
    "reentrancy": "knowledge/reentrancy-patterns.md",
    "inputval":   "knowledge/input-validation.md",
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
    "inputval":  ["uint128(", "uint96(", "uint64(", "SafeCast",
                  "minAmountOut", "amountOutMin", "deadline",
                  "setFee", "updateFee", "MAX_FEE", "batch", "executeBatch"],
    "trust":      ["safeTransfer", "safeApprove", "forceApprove", "delegatecall",
                   "call{value", "fallback", "receive", "ERC777", "tokensReceived",
                   "feeOnTransfer", "rebase", "permit", "callback", "hook",
                   "implementation", "proxy", "upgradeTo", "selfdestruct"],
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
    "liquid":     ["stETH", "wstETH", "cbETH", "rETH", "LidoOracle",
                   "getPooledEthByShares", "getSharesByPooledEth", "exchangeRate",
                   "liquidStaking", "LST", "withdrawalQueue", "requestWithdrawal",
                   "unstakeEth", "submitEth", "deposit", "IStaking"],
    "perps":      ["openPosition", "closePosition", "increasePosition", "decreasePosition",
                   "fundingRate", "markPrice", "indexPrice", "liquidatePosition",
                   "IMX", "IPerp", "IPerpetual", "unrealizedPnl", "realizedPnl",
                   "maxLeverage", "maintenanceMargin", "positionSize", "entryPrice",
                   "GMX", "GLP", "clearinghouse", "openInterest", "skewScale"],
    "crosschain": ["lzReceive", "ccipReceive", "xCall", "relayMessage",
                   "executeMessage", "validateMessage", "bridgeToken",
                   "lockAndMint", "burnAndRelease", "intent", "fillOrder",
                   "solver", "destinationChain", "srcChainId", "dstChainId",
                   "trustedRemote", "setTrustedRemote", "ILayerZeroEndpoint",
                   "IRouterClient", "IWormhole", "nonce", "messageHash"],
    "vesting":    ["vesting", "vestingSchedule", "cliff", "release",
                   "vestedAmount", "claimable", "startTime", "vestingPeriod",
                   "revoke", "accelerate", "allocate", "linearVesting",
                   "ERC20Votes", "getPastVotes", "delegate", "checkpoint",
                   "totalSupply", "mint", "emissionRate", "MAX_SUPPLY"],
    "reentrancy": ["nonReentrant", "ReentrancyGuard", ".call{", "receive()",
                   "fallback()", "onERC721Received", "onERC1155Received",
                   "tokensReceived", "uniswapV3SwapCallback", "flashLoan",
                   "executeOperation", "locked", "_status", "CEI"],
    "mev":        ["slippage", "minAmountOut", "amountOutMinimum", "deadline",
                   "sqrtPriceLimitX96", "slot0", "sqrtPriceX96", "priceImpact",
                   "sandwich", "frontrun", "backrun", "TWAP", "observe",
                   "maxSlippage", "minOut", "amountOutMin"],
    "options":    ["strike", "expiry", "premium", "optionType", "exerciseOption",
                   "settleOption", "putOption", "callOption", "writeOption",
                   "underlyingAsset", "settlementPrice", "impliedVolatility",
                   "DOV", "tranches", "senior", "junior", "leveragedToken",
                   "IVault", "structuredProduct"],
}


def run_prescan(contract_path: Path, repo_path: str) -> dict:
    """
    Ejecuta pre-scan estático independiente: Semgrep + Slitherin + Aderyn.
    Resultados se guardan en results/ y NO se inyectan en prompts de hunters.
    Se cruzan después del hunt con las hipótesis de los hunters.
    Retorna dict con paths de los resultados.
    """
    results_dir = Path(repo_path) / "results" if repo_path else HUNT_SESSION_DIR / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    scan_results = {}
    src_dir = contract_path.parent if contract_path else Path(repo_path) / "src"

    # Semgrep (smart contracts rules)
    print("  [pre-scan] Semgrep...")
    semgrep_out = results_dir / "semgrep.json"
    try:
        result = subprocess.run(
            ["semgrep", "--config", "p/smart-contracts", "--json", str(src_dir)],
            capture_output=True, text=True, timeout=120
        )
        if result.stdout:
            semgrep_out.write_text(result.stdout)
            # Count findings
            try:
                data = json.loads(result.stdout)
                n = len(data.get("results", []))
                print(f"  [pre-scan] ✓ Semgrep: {n} warnings → {semgrep_out}")
                scan_results["semgrep"] = {"path": str(semgrep_out), "count": n}
            except json.JSONDecodeError:
                print(f"  [pre-scan] ⚠ Semgrep: output no válido")
        else:
            print(f"  [pre-scan] ⚠ Semgrep: sin output. ¿Instalado? pip install semgrep")
    except FileNotFoundError:
        print(f"  [pre-scan] ⚠ Semgrep no instalado. Instalar: pip install semgrep")
    except subprocess.TimeoutExpired:
        print(f"  [pre-scan] ⚠ Semgrep timeout (>120s)")
    except Exception as e:
        print(f"  [pre-scan] ⚠ Semgrep error: {e}")

    # Slitherin (DeFi-specific detectors)
    print("  [pre-scan] Slitherin...")
    slitherin_out = results_dir / "slitherin.json"
    try:
        result = subprocess.run(
            ["slitherin", str(src_dir), "--separated", "--json", str(slitherin_out)],
            capture_output=True, text=True, timeout=180
        )
        if result.returncode == 0:
            print(f"  [pre-scan] ✓ Slitherin → {slitherin_out}")
            scan_results["slitherin"] = {"path": str(slitherin_out)}
        else:
            print(f"  [pre-scan] ⚠ Slitherin: {result.stderr[:200] if result.stderr else 'error'}")
    except FileNotFoundError:
        print(f"  [pre-scan] ⚠ Slitherin no instalado. Instalar: pip install slitherin")
    except subprocess.TimeoutExpired:
        print(f"  [pre-scan] ⚠ Slitherin timeout (>180s)")
    except Exception as e:
        print(f"  [pre-scan] ⚠ Slitherin error: {e}")

    # Aderyn (Cyfrin, Rust-based)
    print("  [pre-scan] Aderyn...")
    aderyn_out = results_dir / "aderyn.json"
    try:
        result = subprocess.run(
            ["aderyn", "--output", str(aderyn_out), str(src_dir)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            print(f"  [pre-scan] ✓ Aderyn → {aderyn_out}")
            scan_results["aderyn"] = {"path": str(aderyn_out)}
        else:
            print(f"  [pre-scan] ⚠ Aderyn: {result.stderr[:200] if result.stderr else 'error'}")
    except FileNotFoundError:
        print(f"  [pre-scan] ⚠ Aderyn no instalado. Instalar: cyfrinup && aderyn")
    except subprocess.TimeoutExpired:
        print(f"  [pre-scan] ⚠ Aderyn timeout (>120s)")
    except Exception as e:
        print(f"  [pre-scan] ⚠ Aderyn error: {e}")

    # Guardar resumen
    summary_path = results_dir / "prescan_summary.json"
    summary_path.write_text(json.dumps(scan_results, indent=2))
    print(f"  [pre-scan] Resumen guardado en: {summary_path}")

    return scan_results


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

    # Búsqueda recursiva (excluir out/, forge-cache/, dependencies/, lib/, node_modules/)
    skip_dirs = {"out", "forge-cache", "dependencies", "lib", "node_modules", "artifacts"}
    matches = [
        m for m in repo.glob(f"**/{component}.sol")
        if m.is_file() and not any(part in skip_dirs for part in m.relative_to(repo).parts)
    ]
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


def generate_asset_flow_map(contract_path: Path) -> str:
    """
    Genera un mapa de flujo de activos a partir del código fuente del contrato.
    Extrae transfers, ETH sends, approvals, mints/burns, y balance reads
    con contexto de función y número de línea para dar a los hunters
    una visión rápida de dónde entra y sale dinero.
    """
    if not contract_path or not contract_path.exists():
        return ""

    try:
        src = contract_path.read_text()
    except Exception:
        return ""

    lines = src.split("\n")

    # Patterns to detect asset flow operations
    patterns = {
        "money_in": [
            (r'\.transferFrom\(', "transferFrom"),
            (r'\.safeTransferFrom\(', "safeTransferFrom"),
            (r'msg\.value', "msg.value"),
        ],
        "money_out": [
            (r'\.transfer\(', "transfer"),
            (r'\.safeTransfer\(', "safeTransfer"),
            (r'\.call\{value:', "call{value:}"),
        ],
        "approvals": [
            (r'\.approve\(', "approve"),
            (r'\.safeApprove\(', "safeApprove"),
            (r'\.forceApprove\(', "forceApprove"),
        ],
        "balance_reads": [
            (r'balanceOf\(', "balanceOf"),
            (r'address\(this\)\.balance', "address(this).balance"),
        ],
        "mint_burn": [
            (r'\.mint\(', "mint"),
            (r'\.burn\(', "burn"),
            (r'_mint\(', "_mint"),
            (r'_burn\(', "_burn"),
        ],
    }

    # Track current function context
    current_function = "<top-level>"
    results: dict[str, list[str]] = {k: [] for k in patterns}

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Track function context
        fn_match = re.match(r'\s*function\s+(\w+)\s*\(', line)
        if fn_match:
            current_function = fn_match.group(1) + "()"

        # Also track receive/fallback
        if re.match(r'\s*(receive|fallback)\s*\(', line):
            current_function = stripped.split("(")[0].strip() + "()"
            # receive() is a money_in indicator
            if "receive" in stripped:
                results["money_in"].append(
                    f"- L{line_num} {current_function}: accepts ETH via payable receive"
                )

        # Check each pattern category
        for category, pattern_list in patterns.items():
            for regex, label in pattern_list:
                if re.search(regex, line):
                    # Clean up the line for display (trim whitespace, cap length)
                    display_line = stripped
                    if len(display_line) > 120:
                        display_line = display_line[:117] + "..."
                    results[category].append(
                        f"- L{line_num} {current_function}: {display_line}"
                    )

    # Filter out .transfer( matches that are actually .transferFrom(
    # to avoid double-counting
    filtered_out = []
    for entry in results["money_out"]:
        if "transferFrom" not in entry and "safeTransferFrom" not in entry:
            filtered_out.append(entry)
    results["money_out"] = filtered_out

    # Build the formatted output
    sections = []
    section_map = [
        ("money_in",      "Money IN (deposits/receives)"),
        ("money_out",     "Money OUT (withdrawals/sends)"),
        ("approvals",     "Approvals (attack surface)"),
        ("mint_burn",     "Minting/Burning"),
        ("balance_reads", "Balance Reads (manipulation vectors)"),
    ]

    for key, title in section_map:
        if results[key]:
            sections.append(f"### {title}\n" + "\n".join(results[key]))

    if not sections:
        return ""

    return "## Asset Flow Map\n" + "\n\n".join(sections) + "\n"


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


def extract_dependency_overrides(contract_path: Path, repo_path: str) -> str:
    """
    Detecta funciones 'override' en el contrato, resuelve la función original
    en lib/ (OZ/Solmate/Solady), y retorna ambas para que los hunters vean
    las assumptions de la librería vs el uso del protocolo.
    """
    if not contract_path or not contract_path.exists():
        return ""

    try:
        src = contract_path.read_text()
    except Exception:
        return ""

    lines = src.split("\n")
    repo = Path(repo_path) if repo_path else None

    # 1. Extraer imports
    imports = {}  # alias → path relativo
    for line in lines:
        m = re.match(r'import\s+\{([^}]+)\}\s+from\s+"([^"]+)"', line)
        if m:
            names = [n.strip() for n in m.group(1).split(",")]
            path = m.group(2)
            for name in names:
                imports[name] = path
        m = re.match(r'import\s+"([^"]+)"', line)
        if m:
            imports[Path(m.group(1)).stem] = m.group(1)

    if not imports:
        return ""

    # 2. Encontrar funciones con 'override'
    overrides = []
    current_func = None
    func_lines = []
    brace_count = 0
    in_func = False

    for i, line in enumerate(lines, 1):
        fn_match = re.match(r'\s*function\s+(\w+)\s*\([^)]*\).*\boverride\b', line)
        if fn_match and not in_func:
            current_func = fn_match.group(1)
            func_lines = [line]
            brace_count = line.count("{") - line.count("}")
            in_func = brace_count > 0 or "{" not in line
            if brace_count == 0 and "{" in line:
                # One-liner
                overrides.append({"name": current_func, "line": i, "code": "\n".join(func_lines)})
                in_func = False
        elif in_func:
            func_lines.append(line)
            brace_count += line.count("{") - line.count("}")
            if brace_count <= 0 and "{" in "".join(func_lines):
                overrides.append({"name": current_func, "line": i - len(func_lines) + 1, "code": "\n".join(func_lines)})
                in_func = False

    if not overrides:
        return ""

    # 3. Para cada override, buscar la función original en lib/
    parts = ["## Dependency Overrides — Assumptions de Librerías\n"]
    parts.append("El protocolo overridea estas funciones de librerías externas.")
    parts.append("Verifica que el override NO viole las assumptions de la librería original.\n")

    lib_dirs = []
    if repo:
        for d in ["lib", "node_modules/@openzeppelin", "node_modules"]:
            candidate = repo / d
            if candidate.exists():
                lib_dirs.append(candidate)

    for override in overrides[:10]:  # Limitar a 10 para no explotar contexto
        func_name = override["name"]
        parts.append(f"### Override: `{func_name}()` (L{override['line']})")
        parts.append(f"```solidity\n{override['code'][:500]}\n```\n")

        # Buscar original en lib/
        original_found = False
        for lib_dir in lib_dirs:
            try:
                for sol_file in lib_dir.rglob("*.sol"):
                    try:
                        lib_src = sol_file.read_text(errors='ignore')
                        # Buscar la función con NatSpec
                        pattern = rf'((?:\s*///[^\n]*\n|\s*/\*\*[\s\S]*?\*/\s*\n)*\s*function\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*\{{)'
                        m = re.search(pattern, lib_src)
                        if m:
                            # Extraer función completa (hasta el cierre de llave)
                            start = m.start()
                            bc = 0
                            end = start
                            for j, ch in enumerate(lib_src[m.start():], m.start()):
                                if ch == "{":
                                    bc += 1
                                elif ch == "}":
                                    bc -= 1
                                    if bc == 0:
                                        end = j + 1
                                        break
                            original_code = lib_src[start:end]
                            rel_path = sol_file.relative_to(repo) if repo else sol_file.name
                            parts.append(f"**Original** en `{rel_path}`:")
                            parts.append(f"```solidity\n{original_code[:800]}\n```\n")
                            original_found = True
                            break
                    except Exception:
                        continue
                if original_found:
                    break
            except Exception:
                continue

        if not original_found:
            parts.append("*Original no encontrado en lib/ — verificar manualmente*\n")

    return "\n".join(parts)


def _hunter_specific_section(hunter_name: str) -> str:
    """Genera secciones especializadas por tipo de hunter (Items 2,3,5,6 del plan de mejoras)."""

    if hunter_name == "FlowHunter":
        return """## Flash Loan Hypothesis (OBLIGATORIO — responde para CADA función que modifica estado)
Después de tu análisis libre, pasa por estas 12 preguntas para cada función relevante:
1. ¿Lee estado manipulable? (getReserves, slot0, balanceOf, get_virtual_price)
2. ¿Ese estado afecta movimiento de fondos?
3. ¿Se puede leer y consumir en la misma tx? (sin delays/timelocks)
4. ¿Hay verificación post-acción? (patrón FREI-PI)
5. ¿Tiene reentrancy guard?
6. ¿Si es callback, verifica initiator? (no solo msg.sender == pool)
7. ¿Usa spot price (manipulable) o TWAP (más seguro)?
8. ¿Reward/share se calcula por balance instantáneo?
9. ¿Hay cap/threshold cruzable atómicamente? (pasar de "sano" a "liquidable" en 1 tx)
10. ¿Permite self-liquidation con bonus > flash fee?
11. ¿Fee rounding a zero con montos pequeños?
12. ¿Checkpoint usa storage (persistente) o memory (se pierde)?

>80% de los exploits flash loan siguen: FLASH → MANIPULATE STATE → EXTRACT VALUE → RESTORE → REPAY.
Si una función responde "sí" a las preguntas 1+2+3, es un candidato fuerte.

## Tabla de Tokens con Callbacks (REFERENCIA — consulta al analizar transfers/mints)
| Estándar | Función que dispara callback | Callback en receptor |
|----------|------------------------------|---------------------|
| ERC-721 | safeMint, safeTransferFrom | onERC721Received |
| ERC-1155 | safeTransferFrom, safeBatchTransferFrom | onERC1155Received, onERC1155BatchReceived |
| ERC-777 | send, transfer (DEPRECADO pero existe) | tokensReceived (via ERC-1820 registry) |
| ERC-677 | transferAndCall (LINK, xDAI) | onTokenTransfer |
| ETH nativo | transfer, call{value} | receive(), fallback() |

⚠ Las funciones "safe" son PARADÓJICAMENTE más peligrosas — ejecutan callbacks al receptor.
⚠ Read-only reentrancy: funciones view que leen state de un pool durante callback cuando el state es inconsistente (ChainSecurity/Curve).

## State Machine Model (OBLIGATORIO — output incluido en hyp_*.yaml)
Modela el componente como una máquina de estados finita (FSM). Este output es CRÍTICO — lo usará DeepDiveHunter.

**Paso 1 — Identificar estados:**
Lista TODOS los estados posibles del contrato/posición/usuario. Ejemplos:
  - Vault: EMPTY → ACTIVE → PAUSED → MIGRATING
  - Position: OPEN → HEALTHY → UNDERWATER → LIQUIDATABLE → LIQUIDATED → CLOSED
  - Order: PENDING → FILLED → PARTIALLY_FILLED → CANCELLED → EXPIRED

**Paso 2 — Mapear transiciones:**
Para CADA par de estados, identifica qué función(es) ejecutan la transición:
```
HEALTHY → UNDERWATER: price drop (oracle update, no función directa)
UNDERWATER → LIQUIDATABLE: cuando ltv > lltv (automático por precio)
LIQUIDATABLE → LIQUIDATED: liquidate() / preLiquidate()
OPEN → CLOSED: withdraw() con amount=totalBalance
```

**Paso 3 — Buscar anomalías (AQUÍ ESTÁN LOS BUGS):**
1. **Transiciones ilegales**: ¿Se puede ir de LIQUIDATED → ACTIVE? ¿De CLOSED → OPEN sin nuevo depósito?
2. **Estados stuck (fondos atrapados)**: ¿Hay algún estado sin transición de salida? ¿Puede un usuario quedar atrapado?
3. **Race conditions**: ¿Dos transiciones concurrentes pueden dejar el estado inconsistente?
4. **Transiciones faltantes**: ¿Debería existir PAUSED → EMERGENCY_WITHDRAW pero no existe?
5. **Bypass de estados**: ¿Se puede saltar de PENDING directamente a FILLED sin validación intermedia?

**Output requerido en el YAML:**
```yaml
state_machine:
  states: [EMPTY, ACTIVE, UNDERWATER, LIQUIDATABLE, LIQUIDATED]
  transitions:
    - from: EMPTY, to: ACTIVE, via: "deposit()", guard: "amount > 0"
    - from: ACTIVE, to: UNDERWATER, via: "oracle price drop", guard: "none (automatic)"
  anomalies:
    - type: stuck_state, state: LIQUIDATED, description: "residual dust puede quedar atrapado"
    - type: illegal_transition, from: LIQUIDATED, to: ACTIVE, via: "deposit() no verifica estado"
```

Bug real: Rari Fuse — posición liquidada podía re-depositarse y crear deuda fantasma.
Bug real: Compound v2 — cToken stuck en PAUSED sin función de unpause por admin key loss."""

    elif hunter_name == "OracleHunter":
        return """## Oracle Deep Check (OBLIGATORIO — para cada fuente de precio)
NOTA: Flash Loan Hypothesis (12 preguntas) es responsabilidad de FlowHunter. NO la dupliques aquí.
Enfócate en tu especialidad: ORÁCULOS y fuentes de precio.
Para CADA llamada a latestRoundData() o equivalente:
1. ¿Se verifica updatedAt contra un heartbeat? ¿El heartbeat es ESPECÍFICO por feed o genérico?
2. ¿Se chequea answeredInRound >= roundId?
3. ¿Se chequea price > 0?
4. ¿Hay check de L2 sequencer down? (Arbitrum/Optimism/Base: sequencerUptimeFeed)
5. ¿Existe minAnswer/maxAnswer que clampea el precio en flash crashes?
6. ¿El oracle puede ser sandwicheado? (front-run de oracle update para explotar el vault)

Oracle-Liquidity Mismatch (cmichel/Rari): ¿cuánto capital se necesita para manipular el oracle vs cuánto se puede extraer? Si manipulación < extracción → explotable."""

    elif hunter_name == "DomainHunter":
        return """## Symmetric Inspection (OBLIGATORIO — después de tu análisis de dominio)
Identifica TODOS los pares simétricos del contrato. Pares comunes:
  deposit/withdraw, mint/burn, lock/unlock, stake/unstake, borrow/repay, open/close

Para CADA par, verifica estas 5 dimensiones:
1. **State variables**: ¿ambas funciones actualizan las mismas variables (en dirección opuesta)?
2. **Validaciones**: ¿mismas validaciones (o su inversa lógica)?
3. **Events**: ¿ambas emiten el evento correspondiente?
4. **Modifiers**: ¿mismos modifiers aplicados (nonReentrant, whenNotPaused)?
5. **Edge cases**: ¿amount=0, amount=max, balance=0 manejados simétricamente?

Cualquier asimetría es un candidato a invariante. Documenta qué variable/check/event falta en qué función.
Bug real: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M.

## Constraint Inference (0xRajeev — OBLIGATORIO)
Para cada validación/require que encuentres:
1. Observa qué se valida en N-1 code paths que hacen algo similar.
2. El path que NO tiene esa validación es el bug candidato.
Ejemplo: si 5 de 6 funciones de withdraw verifican healthFactor, la 6ta que no lo hace es sospechosa.

## Traza Hacia Atrás (samczsun — MENTALIDAD)
No empieces preguntando "¿hay un bug aquí?". Empieza preguntando:
"¿De dónde puede SALIR valor del protocolo?" (withdraw, redeem, liquidate, claim, transfer).
Para cada punto de salida, traza HACIA ATRÁS: ¿qué condiciones se deben cumplir? ¿Se pueden manipular?"""

    elif hunter_name == "MathHunter":
        return """## Decimal Universality (OBLIGATORIO — después de tu análisis matemático)
Para CADA operación aritmética que involucre tokens o precios:
- ¿Funciona con 6 decimales (USDC, USDT)?
- ¿Funciona con 8 decimales (WBTC)?
- ¿Funciona con 18 decimales (WETH, DAI)?
- ¿Funciona con 2 decimales (tokens exóticos)?
- ¿minOut/slippage protection funciona correctamente para TODOS los tokens?
- ¿Hay divisiones donde numerador tiene menos decimales que denominador? (resultado trunca a 0)

Bug real: slippage check hardcodeado para USDC (6 dec) aplicado a WETH (18 dec) → protección inefectiva.
Bug real: price = tokenAmount * oraclePrice / 1e18 con tokenAmount de 6 dec → pierde 12 dec de precisión.

## Bidirectional Rounding Check (Sec3/Josselin Feist — OBLIGATORIO)
Para cada función BIDIRECCIONAL (swap A→B y B→A, mint/redeem, deposit/withdraw):
1. Localiza cada "rounding signature" (multiplicación seguida de división)
2. ¿Se redondea CONSISTENTEMENTE? (down en output, up en fee — o viceversa)
3. ¿Un round-trip (A→B→A) puede ser rentable para el atacante? Si deposit(X) y luego withdraw da > X → bug
4. "Round in favor of protocol" tiene side effects: atacantes pueden extraer valor de OTROS USUARIOS (no del pool)

## Fuzz para Maximizar (Dacian — MENTALIDAD)
Cuando escribas invariantes de math, piensa en modo OPTIMIZACIÓN no solo VERIFICACIÓN:
- No solo "¿hay precision loss?" sino "¿cuál es el INPUT que MAXIMIZA la precision loss?"
- Escribe una función optimize_precisionLoss() que Echidna pueda maximizar"""

    elif hunter_name == "WildcardHunter":
        return """## Deadlock Analysis (OBLIGATORIO — después de tu búsqueda creativa)
Para cada safety check, margin, cap, o límite en el contrato:
1. ¿Puede BLOQUEAR una operación de emergencia? (repay, withdraw, liquidate, unstake)
2. ¿Hay un escenario donde el usuario NO PUEDE deshacer su posición?
3. ¿El safety mechanism puede dejar fondos permanentemente bloqueados?
4. ¿Un cap que protege al protocolo puede impedir que un usuario se salve de liquidación?

Bug real: Safety margin aplicado al cálculo de repago impedía que usuarios repagaran → liquidados sin poder hacer nada.
Busca: require/assert/if que revierten en funciones de salida (withdraw, repay, unstake, emergencyWithdraw).

## Composability Attack (samczsun — "Two Rights Make A Wrong")
Para cada interacción con un contrato externo:
1. ¿Qué ASUME este contrato sobre el comportamiento del otro?
2. ¿Bajo qué condiciones esa asunción se viola?
3. ¿Se puede crear un estado donde ambos contratos son internamente consistentes pero juntos son inseguros?
Bug real: SushiSwap MISO — msg.value reutilizado en loop de batch. Auction y batch handler eran seguros individualmente.

## "Reimplementa de Memoria" (cmichel — MENTALIDAD)
Después de leer el contrato, pregúntate: ¿podría reimplementar esto desde cero sin mirar el código?
Si tu versión mental DIFIERE del código real en algún punto → ese punto es un candidato a bug.
La gap entre "qué debería hacer" y "qué realmente hace" es donde viven los bugs novedosos."""

    elif hunter_name == "AccessHunter":
        return """## Trust Boundary Mapping (0xRajeev — OBLIGATORIO)
Para CADA función external/public, clasifica en estas 10 categorías de confianza:
1. **Caller trust**: ¿quién puede llamar? ¿está restringido correctamente?
2. **Callee trust**: ¿a quién llama? ¿confía en el retorno?
3. **Token trust**: ¿asume comportamiento estándar? (USDT no retorna bool, fee-on-transfer, rebasing)
4. **Oracle trust**: ¿confía en que el precio es correcto y fresco?
5. **Admin trust**: ¿qué puede hacer el admin? ¿puede rugpullear?
6. **Time trust**: ¿depende de block.timestamp? ¿manipulable?
7. **Value trust**: ¿valida rangos de parámetros?
8. **State trust**: ¿asume un estado previo que puede no existir?
9. **Compiler trust**: ¿usa features que dependen de versión del compilador?
10. **Chain trust**: ¿asume una chain específica? (gas, block time, precompiles)

## Complete Mediation (0xRajeev #196 — MENTALIDAD)
CADA path de acceso debe verificar autorización. No solo los paths obvios.
Pregunta: "¿Hay ALGÚN camino para llegar a esta operación crítica SIN pasar por el modifier/check?"
Busca: funciones internas que hacen lo mismo que la pública pero sin el modifier, delegatecall que bypasea modifiers, paths via callback.

## REGLA CRÍTICA: Generar Solidity Assertions (OBLIGATORIO — sin excepciones)
AccessHunter DEBE producir assertions Solidity fuzzeables para CADA hipótesis. NO texto descriptivo solo.

**Patrones de assertion para access control:**

1. **Role check invariant** — verifica que solo el rol correcto puede ejecutar:
```solidity
// Probar que un usuario sin rol NO puede ejecutar la función
try target.protectedFunction{gas: 100000}(args) {
    // Si no revierte, el access control falla
    t(false, "AC-XX: protectedFunction callable without role");
} catch {}
```

2. **Authorization bypass** — verifica que no hay paths alternativos:
```solidity
// Después de llamar a functionA (que podría escalar privilegios)
bool hasRoleBefore = target.hasRole(ROLE, attacker);
target.functionA(maliciousArgs);
bool hasRoleAfter = target.hasRole(ROLE, attacker);
t(hasRoleBefore == hasRoleAfter, "AC-XX: privilege escalation via functionA");
```

3. **State-dependent access** — verifica que el estado no bypasea checks:
```solidity
// Verificar que paused/emergency state bloquea correctamente
target.pause();
try target.sensitiveFunction{gas: 100000}(args) {
    t(false, "AC-XX: sensitiveFunction callable when paused");
} catch {}
```

4. **Initialization guard** — verifica que no se puede re-inicializar:
```solidity
// Después de init, no se puede re-init
try target.initialize{gas: 100000}(newArgs) {
    t(false, "AC-XX: contract re-initializable");
} catch {}
```

5. **Self-authorization** — verifica que un usuario no puede autorizarse a sí mismo:
```solidity
uint256 balBefore = token.balanceOf(attacker);
// Intentar operación que requiere autorización de otro
target.executeOnBehalf(victim, attacker, amount);
uint256 balAfter = token.balanceOf(attacker);
t(balAfter <= balBefore, "AC-XX: self-authorization extracts value");
```

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Si no puedes escribir el assertion, la hipótesis es demasiado vaga — descártala o concretiza."""

    elif hunter_name == "TrustBoundaryHunter":
        return """## Compiler Version Check (OBLIGATORIO)
1. Verifica la versión de Solidity del contrato
2. Consulta https://docs.soliditylang.org/en/latest/bugs.html — ¿hay bugs conocidos para esa versión?
3. Si usa Vyper: verificar que NO es 0.2.15-0.3.0 (reentrancy lock failure → $69M Curve hack 2023)

## Weird ERC-20 Checklist (d-xo — OBLIGATORIO si el contrato interactúa con tokens)
Para cada token que el contrato maneja, verificar:
- ¿Retorna bool en transfer/approve? (USDT, BNB, OMG NO retornan)
- ¿Requiere approve(0) antes de re-approve? (USDT, KNC)
- ¿Revierte en transfer de valor 0? (LEND)
- ¿Es rebasing? (stETH, AMPL — balance cambia sin transfer)
- ¿Tiene fee-on-transfer? (amount recibido < amount enviado)
- ¿Tiene blocklist? (USDC, USDT — pueden bloquear el contrato)
- ¿Usa SafeERC20 para todas las interacciones?

Si el contrato asume comportamiento estándar ERC-20 y acepta tokens arbitrarios → HIGH risk."""

    elif hunter_name == "SignatureHunter":
        return """## Signature & Permit Deep Check (OBLIGATORIO — para CADA uso de firma/permit en el contrato)

### Checklist ecrecover / ECDSA (7 items):
1. ¿`ecrecover` valida que el resultado NO es `address(0)`? (firma inválida retorna 0)
2. ¿Se usa OpenZeppelin ECDSA.recover() o se llama ecrecover directamente? (OZ previene malleable sigs)
3. ¿Se normaliza el valor `s`? (EIP-2: s debe estar en lower half → previene signature malleability)
4. ¿El `v` se valida como 27 o 28? (valores inválidos = comportamiento indefinido)
5. ¿Se usa `abi.encodePacked` con tipos de longitud variable? (collision: abi.encodePacked("ab","c") == abi.encodePacked("a","bc"))
6. ¿Hay protección contra front-running de la firma? (otro usuario puede ver la firma en mempool y usarla primero)
7. ¿La firma tiene deadline/expiry? (firma sin expiración = válida eternamente)

### Checklist EIP-712 / Domain Separator (5 items):
1. ¿El `DOMAIN_SEPARATOR` incluye `chainId`? (sin chainId → replay cross-chain post-fork)
2. ¿Se recalcula el `DOMAIN_SEPARATOR` si `chainId` cambia? (o está cacheado inmutablemente?)
3. ¿El `DOMAIN_SEPARATOR` incluye `address(this)`? (sin → replay en otro contrato del mismo protocolo)
4. ¿Los typeHash son correctos y únicos por función? (copy-paste de typeHash = replay entre funciones)
5. ¿Se hashea TODO el struct (no campos parciales)?

### Checklist Nonce (4 items):
1. ¿El nonce se incrementa ANTES del efecto? (si se incrementa después y hay revert parcial → replay)
2. ¿El nonce es per-address o global? (global = DoS: alguien consume tu nonce)
3. ¿Se puede usar nonce=0 como primer valor? (algunos contratos empiezan en 1, skip del 0 = confusión)
4. ¿Hay nonce-gap attack? (saltar nonces para invalidar firmas legítimas de otros usuarios)

### Checklist Permit / Permit2 (6 items):
1. ¿`permit()` puede ser front-runned? (atacante ve permit en mempool, lo ejecuta antes, luego hace transferFrom)
   → Mitigación: usar try/catch en permit, verificar allowance después
2. ¿Se verifica que el `permit` fue exitoso? (algunos tokens no implementan permit correctamente)
3. ¿Hay interacción con Permit2 (Uniswap)? Si sí: ¿se valida que la allowance de Permit2 es correcta?
4. ¿Approval infinita (`type(uint256).max`) se usa sin necesidad? (riesgo si el contrato es comprometido)
5. ¿Se revocan approvals después de usarlas? (allowance residual = attack surface)
6. ¿transferFrom puede ser llamada por alguien que NO debería tener acceso a los fondos?
   Bug real: Morpho Bundler3 ($2.6M) — approve iba al adapter en vez de al Bundler → cualquiera podía usar la allowance.

### Checklist Meta-Transactions / Gasless (3 items):
1. ¿El relayer puede censurar transacciones? (no reenviar la meta-tx)
2. ¿Se valida que msg.sender en el contexto correcto? (ERC-2771: _msgSender() vs msg.sender confusion)
3. ¿El gas price de la meta-tx puede ser manipulado para hacer DoS?

### Attack Patterns de Alta Prioridad:
- **Permit front-run**: usuario firma permit → atacante la usa primero → drains funds
- **Cross-chain replay**: firma válida en L1 reusada en L2 (o viceversa)
- **Same-chain replay**: firma sin nonce o con nonce reutilizable
- **Signature phishing**: usuario firma algo que parece inocuo pero autoriza transfer
- **Approval confusion**: approve va a contrato equivocado (Morpho Bundler3)
- **Deadline bypass**: firmas sin expiración usadas meses después en condiciones diferentes"""

    elif hunter_name == "DoSHunter":
        return """## DoS / Griefing Deep Check (OBLIGATORIO — la clase de vuln MÁS IGNORADA, 2,279 findings en Solodit)

### Sección 1: Unbounded Loops & Gas Exhaustion (8 items)
Para CADA loop (for, while) en el contrato:
1. ¿El loop itera sobre un array cuyo tamaño puede crecer sin límite? (usuarios, tokens, markets, orders)
2. ¿Hay un cap máximo en el tamaño del array? ¿Es razonable para el gas limit del bloque?
3. ¿Hay operaciones storage-write DENTRO del loop? (cada SSTORE = 5K-20K gas)
4. ¿Hay external calls DENTRO del loop? (cada call = variable gas, puede revert y bloquear el loop)
5. ¿La función afectada es una función CRÍTICA? (withdraw, liquidate, claim, emergencyWithdraw)
6. ¿Un atacante puede inflar el array a bajo costo? (crear muchas posiciones pequeñas, registrar muchos tokens)
7. ¿El patrón pull-over-push se usa correctamente? (no enviar a N usuarios en 1 tx → dejar que cada uno retire)
8. ¿Hay paginación o batch limits para operaciones sobre colecciones grandes?

Bug real: GovernorBravo — iteración sobre todas las proposals sin límite → gas DoS.
Bug real: Nouns DAO — iteración sobre voters bloqueó settleAuction().

### Sección 2: Revert-Based DoS — Bloqueo de Funciones Críticas (7 items)
1. ¿Alguna función de SALIDA (withdraw, repay, unstake, emergencyWithdraw) hace external call que puede revert?
   - ¿La función envía ETH con transfer/send a una dirección que puede ser un contrato sin receive()?
   - ¿La función llama a un token que puede pausarse/bloquearse? (USDC blocklist, pausable tokens)
2. ¿Una función de liquidación depende de que el liquidado coopere? (callback, approve, token transfer)
3. ¿Hay un require/assert en una función de emergencia que puede fallar en condiciones extremas?
4. ¿Un oracle caído (reverts) bloquea withdrawals? (Chainlink puede revert si no hay respuesta)
5. ¿Un safety check (health factor, collateral ratio) puede impedir que un usuario repague su deuda?
6. ¿Hay try/catch alrededor de calls que pueden fallar? ¿O un revert en el call propaga y bloquea todo?
7. ¿Funciones de governance/timelock pueden quedar permanentemente bloqueadas? (propuesta que revierte en execute)

Bug real: Akutars — $34M bloqueados porque refund() dependía de transfer() a contratos sin receive().
Bug real: Safety margin en repay impedía repago → usuarios forzados a liquidación ($3M Rari Fuse).

### Sección 3: Front-Running & Grief (5 items)
1. ¿Un atacante puede front-run una transacción para hacerla revert? (sandwich the tx, manipular estado previo)
2. ¿Hay operaciones donde el first-mover gana y puede bloquear a otros? (claim, initialize, createPool)
3. ¿Se puede inflar el gas cost de una transacción ajena? (returnbomb: retornar datos enormes en un callback)
4. ¿Existe donation attack que cambia el estado para hacer revert la tx de la víctima?
5. ¿Un atacante puede crear dust positions para bloquear operaciones batch?

Bug real: ERC-4626 inflation — first depositor envía dust para hacer revert todos los deposits siguientes.
Bug real: returnbomb — contrato malicioso retorna 2MB de datos en callback, agotando gas del caller.

### Sección 4: Resource Exhaustion & State Bloat (5 items)
1. ¿Se pueden crear entidades (positions, orders, tokens) sin costo mínimo? → spam attack
2. ¿Hay storage que crece sin mecanismo de limpieza? (mappings que solo crecen, nunca se borran)
3. ¿El protocolo depende de un keeper/relayer? ¿Qué pasa si el keeper no actúa? (liquidaciones pendientes)
4. ¿Hay rate limiting en funciones que consumen recursos? (createMarket, addToken, registerOracle)
5. ¿Deadline/expiry de operaciones pendientes? ¿O quedan en pending para siempre?

### Sección 5: Emergency & Recovery Blocking (4 items)
1. ¿La función pause() puede ser llamada pero unpause() no existe o requiere multisig con keys perdidas?
2. ¿El modo emergencia permite SIEMPRE retirar fondos? ¿O el emergency también se puede bloquear?
3. ¿Hay timelock que puede quedar permanentemente en estado pendiente? (no se puede cancelar ni ejecutar)
4. ¿Shutdown/migration path funciona si el contrato principal está en un estado inesperado?

Bug real: Compound cETH — admin key loss + pause sin unpause alternativo = fondos bloqueados.
Bug real: Wormhole — guardian set update bloqueado por quorum issue → bridge congelado.

### Solidity Assertion Patterns para DoS

1. **Unbounded loop gas check:**
```solidity
// Verificar que la función no excede gas razonable para N entradas
uint256 gasBefore = gasleft();
target.processAll();
uint256 gasUsed = gasBefore - gasleft();
// Si gasUsed crece linealmente con N, escalar a 100+ entradas bloqueará la tx
t(gasUsed < 5_000_000, "DOS-XX: processAll exceeds 5M gas");
```

2. **Revert-based withdrawal block:**
```solidity
// Crear un contrato que revierte en receive()
RevertOnReceive blocker = new RevertOnReceive();
// Depositar como blocker, luego intentar withdraw
target.deposit{value: 1 ether}(address(blocker));
try target.withdraw(address(blocker), 1 ether) {
    // Si withdraw tiene try/catch o pull pattern, OK
} catch {
    t(false, "DOS-XX: withdraw blocked by reverting receiver");
}
```

3. **Emergency function always callable:**
```solidity
// Poner el contrato en el peor estado posible
_putContractInBadState();
// emergencyWithdraw DEBE funcionar siempre
try target.emergencyWithdraw{gas: 500000}() {
    // OK — emergency funciona
} catch {
    t(false, "DOS-XX: emergencyWithdraw blocked in bad state");
}
```

4. **Array growth → gas DoS:**
```solidity
// Añadir N elementos y medir gas de operación afectada
for (uint i = 0; i < 100; i++) {
    target.addElement(i);
}
uint256 gasBefore = gasleft();
target.processElements();
uint256 gasFor100 = gasBefore - gasleft();
// Proyectar: si 100 elem = X gas, 10K elem = 100X gas > block limit
t(gasFor100 < 500_000, "DOS-XX: processElements scales linearly — DoS at ~10K elements");
```

5. **Oracle failure doesn't block withdrawals:**
```solidity
// Simular oracle caído (reverts)
mockOracle.setShouldRevert(true);
// Withdraw DEBE funcionar aún sin oracle
try target.withdraw{gas: 300000}(user, amount) {
    // OK — withdraw no depende de oracle
} catch {
    t(false, "DOS-XX: withdraw blocked when oracle is down");
}
```

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Los DoS bugs son los más fuzzeables — gas measurements + try/catch patterns son directos."""

    else:
        return ""


def _extract_public_signatures(contract_path: Path) -> list[str]:
    """Extrae firmas de funciones public/external de un contrato Solidity.

    Devuelve líneas tipo: 'function vaultInfo() external view returns (uint256, uint256, ...)'
    para que los hunters sepan qué getters existen y no se los inventen.
    """
    if not contract_path or not contract_path.exists():
        return []

    src = contract_path.read_text()
    sigs = []
    # Match function declarations that are public or external
    for m in re.finditer(
        r'function\s+(\w+)\s*\(([^)]*)\)\s+'
        r'((?:(?:public|external|view|pure|payable|virtual|override|returns\s*\([^)]*\))\s*)+)',
        src
    ):
        fn_name = m.group(1)
        params = m.group(2).strip()
        modifiers = m.group(3).strip()
        # Only include public/external
        if 'public' in modifiers or 'external' in modifiers:
            # Clean up: keep just the essential signature
            sig = f"function {fn_name}({params}) {modifiers}"
            # Normalize whitespace
            sig = re.sub(r'\s+', ' ', sig).strip()
            sigs.append(f"  {sig};")
    return sigs


def _extract_state_vars_from_setup(chimera_dir: Path) -> list[str]:
    """Extrae state variables de TODOS los archivos *Setup*.sol del directorio chimera."""
    state_vars = []
    seen = set()

    for setup_file in sorted(chimera_dir.glob("*Setup*.sol")):
        src = setup_file.read_text()
        for line in src.split("\n"):
            stripped = line.strip()
            # Skip comments and empty lines
            if stripped.startswith("//") or stripped.startswith("/*") or not stripped:
                continue
            # Match state variable declarations (broad regex)
            if re.match(
                r'(\w+(?:\[\])?)\s+(public|internal)\s+\w+',
                stripped
            ) and not stripped.startswith("function") and not stripped.startswith("constructor"):
                if stripped not in seen:
                    seen.add(stripped)
                    state_vars.append(f"  {stripped}")
            # Also match 'address public alice' style
            elif re.match(r'address\s+(public|internal)?\s*(alice|bob|carol|owner|deployer)', stripped):
                if stripped not in seen:
                    seen.add(stripped)
                    state_vars.append(f"  {stripped}")

    return state_vars


def _extract_ghost_vars(chimera_dir: Path) -> list[str]:
    """Extrae ghost variables de TODOS los Properties*.sol del directorio chimera."""
    ghosts = []
    seen = set()

    for props_file in sorted(chimera_dir.glob("Properties*.sol")):
        src = props_file.read_text()
        for line in src.split("\n"):
            stripped = line.strip()
            if "ghost_" in stripped and not stripped.startswith("//"):
                if any(t in stripped for t in ("uint256", "int256", "mapping", "bool", "address", "bytes")):
                    if stripped not in seen:
                        seen.add(stripped)
                        ghosts.append(f"  {stripped}")

    return ghosts


def _extract_setup_helpers(chimera_dir: Path) -> list[str]:
    """Extrae funciones helper (internal) de Setup y TargetFunctions."""
    helpers = []
    seen = set()

    for sol_file in [chimera_dir / "TargetFunctions.sol"] + list(chimera_dir.glob("*Setup*.sol")):
        if not sol_file.exists():
            continue
        src = sol_file.read_text()
        for m in re.finditer(
            r'function\s+(_\w+)\s*\(([^)]*)\)\s+(internal[^{]*)',
            src
        ):
            fn_name = m.group(1)
            params = m.group(2).strip()
            modifiers = m.group(3).strip()
            sig = f"{fn_name}({params}) {modifiers}"
            sig = re.sub(r'\s+', ' ', sig).strip()
            if fn_name not in seen:
                seen.add(fn_name)
                helpers.append(f"  {sig};")

    return helpers


def generate_chimera_context(repo_path: Path, contract_path: Path = None) -> str:
    """Extrae un snippet completo del setup Chimera para que los hunters escriban Solidity compilable.

    Busca TODOS los *Setup*.sol y Properties*.sol, extrae:
    - State variables (contratos, tokens, actores)
    - Ghost variables existentes
    - Funciones públicas/external del contrato target (getters!)
    - Internal helpers disponibles
    - Assertion helpers

    Si no existe test/chimera/, devuelve string vacío.
    """
    chimera_dir = repo_path / "test" / "chimera"
    if not chimera_dir.exists():
        return ""

    snippet_lines = [
        "## Contexto Chimera (OBLIGATORIO — lee antes de escribir Solidity)",
        "",
        "Tu código se insertará en un archivo `PropertiesX.sol` que hereda de `Properties.sol`.",
        "Properties.sol hereda del Setup (variables de estado, contratos, actores).",
        "NO escribas `function invariant_...()` — solo el BODY. merge_invariants.py genera el wrapper.",
        "",
    ]

    # 1. State variables from ALL Setup files
    state_vars = _extract_state_vars_from_setup(chimera_dir)
    if state_vars:
        snippet_lines.append("### Variables y contratos disponibles (heredados de Setup):")
        snippet_lines.append("```solidity")
        snippet_lines.extend(state_vars[:50])
        snippet_lines.append("```")

    # 2. Public/external function signatures from the target contract
    if contract_path:
        pub_sigs = _extract_public_signatures(contract_path)
        if pub_sigs:
            snippet_lines.append("")
            snippet_lines.append("### Funciones públicas del contrato target (getters y setters disponibles):")
            snippet_lines.append("```solidity")
            snippet_lines.extend(pub_sigs[:80])
            snippet_lines.append("```")

    # 3. Ghost variables from ALL Properties*.sol files
    ghosts = _extract_ghost_vars(chimera_dir)
    if ghosts:
        snippet_lines.append("")
        snippet_lines.append("### Ghost variables existentes (ya declaradas, puedes usarlas):")
        snippet_lines.append("```solidity")
        snippet_lines.extend(ghosts[:40])
        snippet_lines.append("```")

    # 4. Internal helpers
    helpers = _extract_setup_helpers(chimera_dir)
    if helpers:
        snippet_lines.append("")
        snippet_lines.append("### Helpers internos disponibles:")
        snippet_lines.append("```solidity")
        snippet_lines.extend(helpers[:20])
        snippet_lines.append("```")

    # 5. Assertion helpers (siempre presentes en Chimera)
    snippet_lines.extend([
        "",
        "### Assertion helpers (de chimera/Asserts.sol):",
        "```solidity",
        "t(bool condition, string memory msg)    // assert true",
        "eq(uint256 a, uint256 b, string memory msg)  // assert ==",
        "gte(uint256 a, uint256 b, string memory msg) // assert >=",
        "lte(uint256 a, uint256 b, string memory msg) // assert <=",
        "gt(uint256 a, uint256 b, string memory msg)  // assert >",
        "lt(uint256 a, uint256 b, string memory msg)  // assert <",
        "```",
        "",
        "### REGLAS para tu código Solidity:",
        "1. **Solo el body** — NO escribas `function invariant_...()`. Solo las líneas internas.",
        "2. **Usa EXACTAMENTE las variables de arriba** — NO inventes nombres. Si no está listado, NO existe.",
        "3. **Usa los getters listados arriba** — Si necesitas un valor del contrato, busca en la lista de funciones públicas.",
        "4. **Usa helpers Chimera** — `t()`, `eq()`, `gte()`, NO `require()` ni `assert()`.",
        "5. **Sin caracteres unicode** en strings — usa `--` en vez de `—`, ASCII puro.",
        "6. **Si necesitas ghost vars nuevas**, declara en el campo `ghost_vars` del YAML, NO en el body.",
        "7. **Si una función no está en la lista de arriba, NO LA USES.** Compilará mal.",
    ])

    return "\n".join(snippet_lines)


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

    # Generate asset flow map
    asset_flow_map = generate_asset_flow_map(contract_path)

    # Generate Chimera context snippet (detect repo root from contract_path)
    chimera_ctx = ""
    if contract_path:
        # Walk up to find test/chimera/
        repo_candidate = contract_path.parent
        for _ in range(6):
            if (repo_candidate / "test" / "chimera").exists():
                chimera_ctx = generate_chimera_context(repo_candidate, contract_path)
                break
            repo_candidate = repo_candidate.parent

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

{asset_flow_map if asset_flow_map else ""}```solidity
{contract_preview}
```

## Contexto de Solodit (bugs similares en protocolos similares)
{solodit_ctx or "Sin contexto disponible — busca patrones propios"}

## Briefing del Dominio ({domain})
{briefing_excerpt or "Sin briefing disponible"}

{chimera_ctx}

## Tu Proceso
1. **Lee CADA línea** del contrato — no te saltes nada
2. **Identifica** las funciones donde tu especialidad ({focus.split(',')[0]}) es relevante
3. **Genera MÍNIMO 5 invariantes (sin límite superior)** — específicos, no genéricos. 5 es el PISO, no el techo. Si el contrato es complejo, genera 15-20+.
4. **Para cada invariante, lista TODAS las formas de ROMPERLO.** No verifiques que se cumple — asume que NO se cumple y busca CÓMO. Algunos ángulos que NO debes olvidar (pero no te limites a estos):
   - Manipular el estado ANTES de que se evalúe (donation, front-running, flash loan, oracle manipulation)
   - Encontrar otro path que no pasa por el check (otra función, callback, delegatecall, contrato externo)
   - Valores extremos (0, 1, type(uint256).max, dust amounts)
   - Timing inesperado (primer depositor, mid-liquidation, paused state, pool vacío)
   - Combinar con otra función del mismo protocolo (stake+withdraw en 1 tx, borrow+liquidate self)
5. **Para cada invariante**: escribe el Solidity del body (sin firma de función)
6. **Clasifica** tier (1=bug confirmado si falla, 2=revisar, 3=solo optimización)
7. **Investiga y descarta** hipótesis débiles — mejor 3 buenas que 10 mediocres

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

{_hunter_specific_section(hunter_name)}

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
"""


def generate_deepdive_prompt(
    component: str,
    contract_path: Path,
    protocol: str,
) -> str:
    """Genera el prompt del DeepDiveHunter usando resultados de los 7 hunters."""
    hyp_dir = HUNT_SESSION_DIR / "hypotheses"

    # Collect all hypotheses from the 7 hunters
    all_hypotheses = []
    all_fps = []
    existing_ids = set()

    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        if "DeepDive" in hyp_file.name or "template" in hyp_file.name:
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            for inv in data.get("invariants", []):
                all_hypotheses.append({
                    "id": inv.get("id", "?"),
                    "hunter": data.get("hunter", hyp_file.stem),
                    "description": inv.get("description", ""),
                    "confidence": inv.get("confidence", 0),
                    "tier": inv.get("tier", 3),
                    "priority": inv.get("priority", "low"),
                    "solidity": inv.get("solidity", ""),
                })
                existing_ids.add(inv.get("id", ""))
            for fp in data.get("false_positives", []):
                all_fps.append({
                    "id": fp.get("id", "?"),
                    "reason": fp.get("reason", ""),
                })
        except Exception:
            continue

    # Filter to confidence >= 50%
    strong = [h for h in all_hypotheses if h["confidence"] >= 50]

    # Find convergences: group by function references in solidity/description
    func_mentions = Counter()
    func_hunters = {}
    for h in strong:
        text = (h.get("solidity", "") + " " + h.get("description", "")).lower()
        # Extract function-like references (re is imported at module level)
        funcs = re.findall(r'(?:function\s+)?(\w+)\s*\(', text)
        for f in funcs:
            if f in ("require", "assert", "revert", "emit", "if", "for", "while", "gte", "lte", "eq", "gt", "lt", "t"):
                continue
            func_mentions[f] += 1
            if f not in func_hunters:
                func_hunters[f] = set()
            func_hunters[f].add(h["hunter"])

    # Top 5 by hunter convergence (functions flagged by most distinct hunters)
    convergences = sorted(
        [(f, len(hunters), count) for f, hunters, count in
         [(f, func_hunters.get(f, set()), func_mentions[f]) for f in func_mentions]
         if len(hunters) >= 2],
        key=lambda x: (-x[1], -x[2])
    )[:5]

    # Build convergence map text
    conv_text = "## Convergence Map\n\n"
    if convergences:
        for func_name, n_hunters, n_mentions in convergences:
            hunters_list = ", ".join(sorted(func_hunters[func_name]))
            conv_text += f"- **{func_name}()**: flagged by {n_hunters} hunters ({hunters_list}), {n_mentions} mentions\n"
    else:
        conv_text += "No strong convergences found (no function flagged by 2+ hunters).\n"
        conv_text += "Focus on value exit points instead.\n"

    # Build existing hypotheses list (for dedup)
    existing_text = "## Existing Hypotheses (DO NOT DUPLICATE)\n\n"
    for h in all_hypotheses:
        existing_text += f"- [{h['id']}] ({h['hunter']}, {h['confidence']}%): {h['description']}\n"

    # Build false positives list
    fp_text = "## Already Debunked (DO NOT REPEAT)\n\n"
    for fp in all_fps:
        fp_text += f"- [{fp['id']}]: {fp['reason']}\n"

    # Read contract source
    contract_src = ""
    if contract_path and contract_path.exists():
        contract_src = contract_path.read_text()
        if len(contract_src) > 60_000:
            contract_src = contract_src[:60_000] + "\n// ... TRUNCATED"

    abbreviation = "".join(w[0] for w in re.findall(r'[A-Z][a-z]*', component)).upper()
    if not abbreviation:
        abbreviation = component[:3].upper()

    hyp_output = str(HUNT_SESSION_DIR / f"hypotheses/hyp_{component}_DeepDiveHunter.yaml")

    return f"""# DeepDiveHunter — {component} Deep Analysis

## Tu Identidad
Eres el **DeepDiveHunter** del equipo de bug hunting de {protocol}.
No escaneas patrones — PIENSAS como samczsun. Trazas hacia atrás desde puntos de salida de valor.

## Tu Input
Tienes los resultados de 9 hunters que ya analizaron este componente.
Tu trabajo: encontrar lo que ELLOS NO VIERON. Profundidad, no amplitud.
**IMPORTANTE**: FlowHunter incluye un State Machine Model (FSM) en su output. ÚSALO:
- Busca transiciones ilegales que los otros hunters no detectaron
- Busca estados stuck donde fondos quedan atrapados
- Busca bypasses de estados intermedios (saltar validaciones)

## Contrato
```solidity
{contract_src}
```

{conv_text}

{existing_text}

{fp_text}

## Tu Proceso (OBLIGATORIO — sigue las 4 secciones en orden)

### Sección 1: Design Assumption Analysis
Para cada función crítica: ¿qué asume el developer que nunca pasará?
Lista cada asunción. Para cada una: construye un escenario concreto que la viole.

### Sección 2: Cross-Function State Analysis
Para cada PAR de funciones críticas: ¿qué pasa si se llaman en orden inesperado?
¿Qué estado deja A que hace que B se comporte diferente?

### Sección 3: Value Exit Trace (metodología samczsun)
Identifica TODOS los puntos donde sale valor del protocolo.
Para CADA uno, traza HACIA ATRÁS: ¿qué condiciones deben cumplirse? ¿se pueden manipular?

### Sección 4: State Machine Attack Paths
Usa el FSM del FlowHunter. Para cada anomalía reportada:
- ¿El stuck state puede causar pérdida de fondos? ¿Cuánto?
- ¿La transición ilegal se puede explotar con una secuencia concreta de txs?
- ¿Hay un ataque de 2+ pasos que abuse del orden de transiciones?
Si FlowHunter NO incluyó FSM, constrúyelo tú a partir del código.

### Sección 5: Convergence Deep-Dive
Donde 2+ hunters señalaron lo mismo: ¿hay un bug más profundo detrás?

## Output
Escribe en: `{hyp_output}`

**MÁXIMO 5 hipótesis.** Cada una DEBE tener:
- `solidity` field estándar (Chimera assertions — OBLIGATORIO para merge_invariants.py)
- `poc_sketch` field (outline de test Foundry)
- `call_stack` field (traza de ejecución)
- `confidence` >= 60%

ID prefix: `{abbreviation}-DD` (ej: {abbreviation}-DD-01)

## Reglas
- NO dupliques IDs o descripciones de la lista de hipótesis existentes
- NO repitas false positives ya debunked
- CADA hipótesis necesita un `poc_sketch` concreto — si no puedes escribirlo, es demasiado vaga
- Prefiere 2 excelentes sobre 5 mediocres
- `validated: true` solo si confidence >= 60%
"""


def check_chimera_exists(repo_path: Path) -> bool:
    """Check if the repo already has a Chimera fuzzing setup."""
    chimera_dir = repo_path / "test" / "chimera"
    if not chimera_dir.exists():
        return False
    # Must have at least Properties.sol and TargetFunctions.sol
    has_properties = (chimera_dir / "Properties.sol").exists()
    has_targets = (chimera_dir / "TargetFunctions.sol").exists()
    return has_properties and has_targets


def parse_bounty_value(payout_str: str) -> int:
    """Extract max numeric bounty value from payout string.

    Examples:
        "Critical up to $1M, High $20K" → 1_000_000
        "$50,000" → 50_000
        "Up to $500K" → 500_000
        "" or unparseable → 100_000 (default high — safer)
    """
    if not payout_str:
        return 100_000  # default: assume high value (safer)

    # Find all dollar amounts
    amounts = []
    for match in re.finditer(r'\$\s*([\d,.]+)\s*([KkMm])?', payout_str):
        num_str = match.group(1).replace(",", "")
        try:
            value = float(num_str)
        except ValueError:
            continue
        suffix = (match.group(2) or "").upper()
        if suffix == "K":
            value *= 1_000
        elif suffix == "M":
            value *= 1_000_000
        amounts.append(int(value))

    return max(amounts) if amounts else 100_000


def create_context_file(
    component: str,
    contract_path: Path,
    domain: str,
    solodit_ctx: str,
    briefing_excerpt: str,
    protocol: str,
    flatten_output: str = "",
    dep_overrides: str = "",
    symmetric_output: str = "",
) -> Path:
    """Crea el archivo de contexto compartido para todos los hunters."""
    context_dir = HUNT_SESSION_DIR / "context"
    context_dir.mkdir(parents=True, exist_ok=True)
    context_file = context_dir / f"{component}_context.md"

    locs = count_locs(contract_path) if contract_path else 0

    flatten_section = ""
    if flatten_output:
        flatten_section = f"""
## Deep Flatten — Secuencia Real de Ejecución
Las funciones críticas (que mueven fondos) han sido aplanadas: modifiers inlineados,
funciones internas expandidas. READ/WRITE/EXTERNAL muestran el orden real.
⚠ CEI WARNING indica que un WRITE ocurre DESPUÉS de un EXTERNAL call.

{flatten_output}
"""

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
{flatten_section}
{dep_overrides if dep_overrides else ""}
{("## Symmetric Analysis\n" + symmetric_output) if symmetric_output else ""}"""
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
            "deepdive_hunter": False,
            "fuzzing_phase1_executed": False,
            "fuzzing_phase2_executed": False,
        },
        "notes": "",
        "feedback_applied": None,
    }

    with open(ficha_path, "w") as f:
        yaml.dump(ficha, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"  ✓ Ficha creada: {ficha_path}")
    return ficha_path


def generate_component_map(state: dict) -> list[dict]:
    """
    Escanea el repo del hunt activo y genera un mapa de componentes con:
    - name, files (paths relativos), loc, priority, reason, depends_on, status

    Persiste el mapa en current_hunt.json bajo 'component_map'.
    Si ya existe, lo devuelve sin regenerar (usar --map-components --force para regenerar).
    """
    repo_path = state.get("repo_path", "")
    if not repo_path:
        print("✗ No hay repo_path en current_hunt.json")
        return []

    repo = Path(repo_path)
    if not repo.exists():
        print(f"✗ Repo no existe: {repo}")
        return []

    # Buscar todos los .sol en src/ o contracts/ (excluyendo test/, lib/, interfaces/)
    sol_files = []
    for pattern in ["src/**/*.sol", "contracts/**/*.sol"]:
        sol_files.extend(repo.glob(pattern))

    # Filtrar: excluir tests, libraries, interfaces, mocks
    exclude_patterns = ["test/", "lib/", "node_modules/", "mock/", "Mock",
                        "script/", "interface/", "interfaces/"]
    filtered = []
    for f in sol_files:
        rel = str(f.relative_to(repo))
        if any(ex in rel for ex in exclude_patterns):
            continue
        # Excluir interfaces puras (archivos que empiezan con I + mayúscula)
        if f.stem.startswith("I") and len(f.stem) > 1 and f.stem[1].isupper():
            continue
        filtered.append(f)

    # Agrupar por componente (nombre del archivo sin extensión)
    # Si hay múltiples repos (e.g., PancakeSwap), escanear todos
    extra_repos = state.get("extra_repos", [])
    for extra in extra_repos:
        extra_repo = Path(extra)
        if extra_repo.exists():
            for pattern in ["src/**/*.sol", "contracts/**/*.sol"]:
                for f in extra_repo.glob(pattern):
                    rel = str(f.relative_to(extra_repo))
                    if any(ex in rel for ex in exclude_patterns):
                        continue
                    if f.stem.startswith("I") and len(f.stem) > 1 and f.stem[1].isupper():
                        continue
                    filtered.append(f)

    # Construir componentes: agrupar archivos relacionados
    # Un "componente" = un contrato principal + sus libraries internas
    components_done = set(state.get("components_done", []))
    components_remaining = state.get("components_remaining", [])

    component_map = []
    seen_names = set()

    for f in sorted(filtered, key=lambda x: x.stat().st_size, reverse=True):
        name = f.stem
        if name in seen_names:
            continue
        seen_names.add(name)

        loc = count_locs(f)
        if loc < 10:  # Ignorar archivos triviales
            continue

        # Determinar status
        if name in components_done:
            status = "done"
        elif name in components_remaining:
            status = "pending"
        else:
            status = "unmapped"

        # Path relativo para portabilidad
        try:
            rel_path = str(f.relative_to(repo))
        except ValueError:
            # Archivo de otro repo
            rel_path = str(f)

        # Detectar dependencias leyendo imports
        depends_on = []
        try:
            src = f.read_text()
            imports = re.findall(r'import\s+.*?["\'].*?/(\w+)\.sol["\']', src)
            depends_on = [imp for imp in imports
                         if imp in seen_names or imp in [x.stem for x in filtered]]
            depends_on = list(set(depends_on) - {name})[:5]  # max 5
        except Exception:
            pass

        component_map.append({
            "name": name,
            "files": [rel_path],
            "loc": loc,
            "status": status,
            "depends_on": depends_on,
        })

    # Ordenar por LOC descendente (mayor primero = mayor prioridad)
    component_map.sort(key=lambda c: c["loc"], reverse=True)

    # Asignar prioridad
    for i, comp in enumerate(component_map):
        comp["priority"] = i + 1

    return component_map


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

    # Component map
    cmap = state.get("component_map", [])
    if cmap:
        print(f"\n  Component Map ({len(cmap)} componentes):")
        for c in cmap:
            icon = "✓" if c.get("status") == "done" else "→" if c.get("status") == "pending" else "○"
            deps = f" ← {', '.join(c['depends_on'])}" if c.get("depends_on") else ""
            files = ", ".join(c.get("files", []))
            print(f"    {icon} [{c.get('priority', '?')}] {c['name']} ({c.get('loc', '?')} LOC) {files}{deps}")

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
    parser.add_argument("--map-components", action="store_true",
                        help="Escanea el repo y genera component_map en current_hunt.json")
    parser.add_argument("--force", action="store_true",
                        help="Regenerar component_map aunque ya exista")
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

    if args.map_components:
        existing = state.get("component_map", [])
        if existing and not args.force:
            print(f"✓ component_map ya existe ({len(existing)} componentes). Usa --force para regenerar.")
            # Mostrar el mapa existente
            for c in existing:
                icon = "✓" if c.get("status") == "done" else "→" if c.get("status") == "pending" else "○"
                print(f"  {icon} [{c.get('priority', '?')}] {c['name']} ({c.get('loc', '?')} LOC) {', '.join(c.get('files', []))}")
            return 0

        cmap = generate_component_map(state)
        if not cmap:
            print("✗ No se pudo generar component_map")
            return 1

        state["component_map"] = cmap

        # Auto-poblar components_remaining si está vacío
        if not state.get("components_remaining") and not state.get("components_done"):
            state["components_remaining"] = [c["name"] for c in cmap if c["loc"] >= 50]
            print(f"\n  Auto-poblado components_remaining: {len(state['components_remaining'])} componentes (>= 50 LOC)")

        save_hunt_state(state)
        print(f"\n✓ component_map generado: {len(cmap)} componentes")
        for c in cmap:
            icon = "✓" if c.get("status") == "done" else "→" if c.get("status") == "pending" else "○"
            deps = f" ← {', '.join(c['depends_on'])}" if c.get("depends_on") else ""
            print(f"  {icon} [{c['priority']}] {c['name']} ({c['loc']} LOC) {', '.join(c['files'])}{deps}")
        return 0

    if args.complete:
        comp = args.complete
        # ── GATE CHECK: pipeline_gate must pass before marking complete ──
        gate_script = AUDIT_AGENTS_DIR / "pipeline_gate.py"
        if gate_script.exists():
            print(f"  Verificando pipeline gates para {comp}...")
            gate_result = subprocess.run(
                [sys.executable, str(gate_script), "--component", comp, "--gate", "all"],
                capture_output=True, text=True, timeout=30
            )
            if gate_result.returncode != 0:
                print(f"\n⛔ NO se puede marcar {comp} como completo — pipeline gates fallan:\n")
                print(gate_result.stdout)
                print(f"\nArregla los gates que fallan y vuelve a intentar.")
                print(f"Para bypass (SOLO si sabes lo que haces): --force")
                if not args.force:
                    return 1
                print(f"\n⚠ BYPASS FORZADO por --force — marcando como completo sin gates")
            else:
                print(f"  ✅ Todos los pipeline gates pasaron")

        if comp in state.get("components_remaining", []):
            state["components_remaining"].remove(comp)
        if comp not in state.get("components_done", []):
            state.setdefault("components_done", []).append(comp)
        # Avanzar current_component al siguiente pendiente
        remaining = state.get("components_remaining", [])
        state["current_component"] = remaining[0] if remaining else None
        # Sincronizar status en component_map
        for c in state.get("component_map", []):
            if c["name"] == comp:
                c["status"] = "done"
                break
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

    # Pre-scan estático (independiente de hunters — resultados en results/)
    print(f"\n  Ejecutando pre-scan estático...")
    prescan_results = run_prescan(contract_path, repo_path)

    # Briefings (primario completo + secundario solo grep)
    briefing_excerpt = load_briefings(domains)
    if briefing_excerpt:
        label = " + ".join(domains)
        print(f"  ✓ Briefings cargados: {label}")

    # Dependency overrides (OZ/Solmate/Solady assumptions vs protocolo)
    dep_overrides = ""
    if contract_path and contract_path.exists() and repo_path:
        print(f"  Analizando dependency overrides...")
        dep_overrides = extract_dependency_overrides(contract_path, repo_path)
        if dep_overrides:
            n_overrides = dep_overrides.count("### Override:")
            print(f"  ✓ {n_overrides} overrides de librerías detectados")
        else:
            print(f"  ✓ Sin overrides de librerías")

    # Symmetric analysis (pares de funciones — output va al contexto de hunters)
    symmetric_output = ""
    if contract_path and contract_path.exists():
        print(f"  Ejecutando symmetric_analyzer...")
        sym_script = AUDIT_AGENTS_DIR / "symmetric_analyzer.py"
        if sym_script.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(sym_script), str(contract_path)],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip() and "ERROR" not in result.stdout[:20]:
                    symmetric_output = result.stdout
                    n_asym = symmetric_output.count("**YES** | **NO**") + symmetric_output.count("**NO** | **YES**")
                    print(f"  ✓ Symmetric analyzer: {n_asym} asimetrías detectadas")
                elif "ERROR" in (result.stdout or ""):
                    print(f"  ⚠ Symmetric analyzer: {result.stdout[:200]}")
                else:
                    print(f"  ⚠ Symmetric analyzer: sin output")
            except subprocess.TimeoutExpired:
                print(f"  ⚠ Symmetric analyzer timeout (>60s)")
            except Exception as e:
                print(f"  ⚠ Symmetric analyzer error: {e}")

    # Deep flatten (funciones críticas — output va al contexto de hunters)
    flatten_output = ""
    if contract_path and contract_path.exists():
        print(f"  Ejecutando deep_flatten (funciones críticas)...")
        deep_flatten_script = AUDIT_AGENTS_DIR / "deep_flatten.py"
        if deep_flatten_script.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(deep_flatten_script), str(contract_path), "--critical-only"],
                    capture_output=True, text=True, timeout=60
                )
                if result.returncode == 0 and result.stdout.strip():
                    flatten_output = result.stdout
                    n_funcs = flatten_output.count("## ")
                    print(f"  ✓ Deep flatten: {n_funcs} funciones críticas aplanadas")
                elif result.stderr:
                    print(f"  ⚠ Deep flatten: {result.stderr[:200]}")
                else:
                    print(f"  ⚠ Deep flatten: sin output")
            except subprocess.TimeoutExpired:
                print(f"  ⚠ Deep flatten timeout (>60s)")
            except Exception as e:
                print(f"  ⚠ Deep flatten error: {e}")

    # Crear context file
    ctx_file = create_context_file(component, contract_path, domain, solodit_ctx, briefing_excerpt, protocol, flatten_output, dep_overrides, symmetric_output)
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
    print(f"    medusa fuzz --config test/chimera/medusa.json --timeout 600  # Phase 2: Medusa stateful")
    print(f"    echidna . --contract CryticTester --config test/chimera/echidna.yaml  # Phase 4: optimization")
    print(f"    ~/.local/bin/halmos --function check_ --loop 10        # Phase 5: symbolic (math pura)")
    print(f"    python3 audit-agents/apply_feedback.py --hypotheses   # actualizar briefings")
    print(f"\n  Si hay findings confirmados con fork PoC:")
    print(f"    /variant-hunt <FINDING_ID>                             # buscar variantes en todo el scope")
    print(f"    python3 audit-agents/report_finding.py --finding <ID>  # crea en Bounty Radar + Telegram")
    print(f"    python3 audit-agents/submit_finding.py --update <ID> --status REPORTED --submission-url <URL>")
    print(f"\n  ⚠  OBLIGATORIO: ejecutar merge_invariants.py ANTES del fuzzing")

    return 0


if __name__ == "__main__":
    sys.exit(main())
