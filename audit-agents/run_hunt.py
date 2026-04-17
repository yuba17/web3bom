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


def mark_gate(component: str, gate: str):
    """Mark a pipeline gate as completed after a phase finishes."""
    try:
        subprocess.run([
            "python3", str(AUDIT_AGENTS_DIR / "pipeline_gate.py"),
            "-c", component, "--mark", gate
        ], check=False, capture_output=True)
    except Exception:
        pass


def query_wiki_context(domain: str, component: str) -> str:
    """Thin re-export — see context_enrichment.query_wiki_context for details."""
    from context_enrichment import query_wiki_context as _impl
    return _impl(domain, component)


def load_graph_report(protocol: str) -> str:
    """Load graphify GRAPH_REPORT.md for protocol if available."""
    graph_dir = HUNT_SESSION_DIR / "graph" / protocol
    for report_name in ("GRAPH_REPORT.md", "graphify-out/GRAPH_REPORT.md"):
        report = graph_dir / report_name
        if report.exists():
            content = report.read_text(errors="ignore")
            if len(content) > 3000:
                content = content[:3000] + "\n[... truncated]"
            return f"\n## Structural Graph (Graphify)\n{content}\n"
    return ""


def load_rejection_context() -> str:
    """Load rejection rules as anti-patterns for hunters."""
    rules_path = HUNT_SESSION_DIR / "feedback" / "rejection_rules.yaml"
    if not rules_path.exists():
        return ""
    try:
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        if not rules:
            return ""
        lines = ["\n## Anti-Patterns (Rechazados en plataformas reales -- NO reportar estos)"]
        categories = rules.get("rejection_categories", {})
        for cat_name, cat_data in categories.items():
            if cat_name == "duplicate":
                continue  # duplicates are not anti-patterns, just competition
            rule_text = cat_data.get("rule", "")
            count = cat_data.get("count", 0)
            if rule_text:
                lines.append(f"- **{cat_name}** ({count}x rechazado): {rule_text}")
        for lesson in rules.get("lessons", []):
            lines.append(f"- {lesson}")
        return "\n".join(lines) if len(lines) > 1 else ""
    except Exception:
        return ""


def load_few_shot_examples(hunter_domain: str) -> str:
    """Load 2-3 relevant few-shot examples for this hunter's domain."""
    domain_categories = {
        "math": ["rounding", "accounting"], "access": ["access"],
        "flow": ["accounting", "logic"], "oracle": ["oracle"],
        "domain": ["logic", "accounting"], "dos": ["dos"],
        "logic": ["logic"], "adversarial": ["accounting", "oracle", "logic"],
        "trust": ["access", "logic"], "signature": ["access"],
        "wildcard": ["logic", "dos"],
    }
    cats = domain_categories.get(hunter_domain, ["logic"])
    examples_dir = AUDIT_AGENTS_DIR / "few_shot_examples"
    if not examples_dir.exists():
        return ""
    results = []
    for cat in cats:
        cat_file = examples_dir / f"{cat}.yaml"
        if not cat_file.exists():
            continue
        try:
            data = yaml.safe_load(cat_file.read_text())
            for ex in data.get("examples", [])[:2]:
                results.append(
                    f"### {ex.get('title', '?')} ({ex.get('source', '')})\n"
                    f"```solidity\n{ex.get('vulnerable_code', '').strip()}\n```\n"
                    f"{ex.get('explanation', '').strip()}\n"
                )
        except Exception:
            continue
    if not results:
        return ""
    return (
        "\n---\n## Ejemplos Reales de Bugs (Few-Shot — bugs confirmados en auditorías reales)\n"
        + "\n".join(results[:3])
    )


def get_hyp_dir(protocol: str) -> Path:
    """Return protocol-namespaced hypotheses directory."""
    d = HUNT_SESSION_DIR / "hypotheses" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_context_dir(protocol: str) -> Path:
    """Return protocol-namespaced context directory."""
    d = HUNT_SESSION_DIR / "context" / protocol
    d.mkdir(parents=True, exist_ok=True)
    return d

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

# KB briefings mapped to each hunter's specialty.
# Each hunter gets patterns from these briefings as background knowledge (appendix).
# WildcardHunter intentionally excluded — works best without anchoring.
HUNTER_KB_BRIEFINGS: dict[str, list[str]] = {
    "MathHunter":    ["knowledge/math-libraries.md", "knowledge/fee-distribution.md"],
    "AccessHunter":  ["knowledge/access-control.md", "knowledge/proxy-upgrade.md"],
    "FlowHunter":    ["knowledge/reentrancy-patterns.md", "knowledge/liquidation-mechanics.md", "knowledge/flash-loan.md"],
    "OracleHunter":  ["knowledge/oracle.md", "knowledge/mev-sandwich.md"],
    "DomainHunter":  [],  # Gets domain-specific briefing dynamically
    "TrustBoundaryHunter": ["knowledge/trust-boundaries.md", "knowledge/weird-erc20.md", "knowledge/cross-chain-messaging.md"],
    "SignatureHunter": ["knowledge/signature-replay.md", "knowledge/permit2-approvals.md"],
    "DoSHunter":     ["knowledge/input-validation.md"],
}


def extract_kb_pattern_summaries(briefing_paths: list[str], max_patterns: int = 30) -> str:
    """
    Extract pattern ID + title from KB briefings as a compact appendix.
    Returns ~30-50 lines of 'id: one-line description' for hunter background knowledge.
    """
    patterns = []
    for bp in briefing_paths:
        full_path = KNOWLEDGE_DIR.parent / bp if not Path(bp).is_absolute() else Path(bp)
        if not full_path.exists():
            # Try from WEB3_DIR
            full_path = WEB3_DIR / bp
        if not full_path.exists():
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Extract pattern entries: look for "- id:" and "pattern:" / "titulo:" lines
        current_id = None
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("- id:"):
                current_id = stripped.replace("- id:", "").strip()
            elif stripped.startswith("pattern:") and current_id:
                pattern_name = stripped.replace("pattern:", "").strip()
                patterns.append(f"- {current_id}: {pattern_name}")
                current_id = None
            elif stripped.startswith("titulo:") and current_id:
                title = stripped.replace("titulo:", "").strip().strip('"')
                if title and len(title) < 120:
                    # Update last pattern entry if it matches, otherwise add new
                    updated = False
                    if patterns:
                        for i in range(len(patterns) - 1, -1, -1):
                            if patterns[i].startswith(f"- {current_id}:"):
                                patterns[i] = f"- {current_id}: {title}"
                                updated = True
                                break
                    if not updated:
                        patterns.append(f"- {current_id}: {title}")
                current_id = None

    if not patterns:
        return ""

    # Deduplicate and limit
    seen = set()
    unique = []
    for p in patterns:
        pid = p.split(":")[0]
        if pid not in seen:
            seen.add(pid)
            unique.append(p)

    unique = unique[:max_patterns]
    return "\n".join(unique)


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


def select_hunters(contract_source: str, protocol_type: str = None,
                   profiles_path: str = None) -> list[str]:
    """Select hunters based on code features and protocol type.
    Tier 0 always. Tier 1 if triggers match. Tier 2 if triggers match.
    Returns ordered list of hunter names."""
    if profiles_path is None:
        profiles_path = str(AUDIT_AGENTS_DIR / "hunter_profiles.yaml")
    profiles_file = Path(profiles_path)
    if not profiles_file.exists():
        # Fallback: return all known hunters
        return list(HUNTER_DOMAINS.keys())

    with open(profiles_file) as f:
        profiles = yaml.safe_load(f)

    source_lower = contract_source.lower()
    selected = list(profiles.get("tier0", []))

    if not protocol_type:
        protocol_type = detect_protocol_type(source_lower, profiles)

    for tier_key in ("tier1", "tier2"):
        for hunter, config in profiles.get(tier_key, {}).items():
            triggers = config.get("triggers", [])
            ptypes = config.get("protocol_types", ["*"])
            min_loc = config.get("min_loc", 0)

            if "*" not in ptypes and protocol_type not in ptypes:
                continue
            if triggers and any(t.lower() in source_lower for t in triggers):
                selected.append(hunter)
                continue
            if min_loc and source_lower.count("\n") >= min_loc:
                selected.append(hunter)

    return list(dict.fromkeys(selected))  # deduplicate preserving order


def detect_protocol_type(source_lower: str, profiles: dict = None) -> str:
    """Auto-detect protocol type from source code."""
    if profiles is None:
        profiles_path = AUDIT_AGENTS_DIR / "hunter_profiles.yaml"
        if profiles_path.exists():
            with open(profiles_path) as f:
                profiles = yaml.safe_load(f)
        else:
            return "unknown"
    scores = {}
    for ptype, keywords in profiles.get("protocol_type_signals", {}).items():
        score = sum(1 for kw in keywords if kw.lower() in source_lower)
        if score > 0:
            scores[ptype] = score
    return max(scores, key=scores.get) if scores else "unknown"


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

    # Slither (fallback from slitherin if not available)
    print("  [pre-scan] Slither...")
    slither_out = results_dir / "slither.json"
    try:
        # Try slitherin first, fallback to slither
        import shutil as _sh
        slither_cmd = "slitherin" if _sh.which("slitherin") else "slither"
        result = subprocess.run(
            [slither_cmd, str(src_dir), "--json", str(slither_out)],
            capture_output=True, text=True, timeout=180
        )
        if slither_out.exists() and slither_out.stat().st_size > 10:
            try:
                data = json.loads(slither_out.read_text())
                detectors = data.get("results", {}).get("detectors", [])
                high_med = [d for d in detectors if d.get("impact", "").lower() in ("high", "medium")]
                print(f"  [pre-scan] ✓ {slither_cmd}: {len(detectors)} total, {len(high_med)} high/medium → {slither_out}")
                scan_results["slither"] = {"path": str(slither_out), "count": len(detectors)}
            except json.JSONDecodeError:
                print(f"  [pre-scan] ✓ {slither_cmd} → {slither_out} (could not parse count)")
                scan_results["slither"] = {"path": str(slither_out)}
        else:
            print(f"  [pre-scan] ⚠ {slither_cmd}: no output or empty file")
            if result.stderr:
                print(f"  [pre-scan]   stderr: {result.stderr[:300]}")
    except FileNotFoundError:
        print(f"  [pre-scan] ⚠ Slither no instalado. Instalar: pipx install slither-analyzer")
    except subprocess.TimeoutExpired:
        print(f"  [pre-scan] ⚠ Slither timeout (>180s)")
    except Exception as e:
        print(f"  [pre-scan] ⚠ Slither error: {e}")

    # Aderyn (Cyfrin, Rust-based) — must run from project root to read foundry.toml remappings
    print("  [pre-scan] Aderyn...")
    aderyn_out = results_dir / "aderyn.json"
    # Detect project root: walk up from src_dir to find foundry.toml
    project_root = src_dir
    for parent in [src_dir] + list(Path(src_dir).parents):
        if (Path(parent) / "foundry.toml").exists():
            project_root = str(parent)
            break
    try:
        result = subprocess.run(
            ["aderyn", "--output", str(aderyn_out), "--src", str(src_dir), str(project_root)],
            capture_output=True, text=True, timeout=120
        )
        # Aderyn may panic after writing output (cosmetic bug in 0.1.x) — check file exists
        if aderyn_out.exists() and aderyn_out.stat().st_size > 10:
            try:
                data = json.loads(aderyn_out.read_text())
                n_high = len(data.get("high_issues", {}).get("issues", []))
                n_med = len(data.get("medium_issues", {}).get("issues", []))
                print(f"  [pre-scan] ✓ Aderyn: {n_high} high, {n_med} medium → {aderyn_out}")
                scan_results["aderyn"] = {"path": str(aderyn_out), "count": n_high + n_med}
            except json.JSONDecodeError:
                print(f"  [pre-scan] ✓ Aderyn → {aderyn_out} (could not parse)")
                scan_results["aderyn"] = {"path": str(aderyn_out)}
        elif result.returncode != 0:
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


# [BENCHMARK-IMPROVE-1] Parse prescan results into hunter-consumable signals
# Benchmark gap: M-10 (infinite loop from path.skipToken() not reassigned) is a trivial
# "unused return value" pattern that Slither/Aderyn detect automatically, but results
# were NOT injected into hunter prompts. This function bridges that gap.
HIGH_VALUE_DETECTORS = {
    # Slither detectors that correlate with real bugs
    "unused-return", "unchecked-lowlevel", "uninitialized-state",
    "divide-before-multiply", "reentrancy-eth", "reentrancy-no-eth",
    "incorrect-equality", "shadowing-state", "locked-ether",
    "controlled-delegatecall", "arbitrary-send-erc20", "suicidal",
    "unprotected-upgrade", "msg-value-loop",
    # Aderyn detectors
    "unused-return-value", "unchecked-return", "state-variable-shadowing",
    "divide-before-multiply", "reentrancy",
    # Semgrep
    "solidity.security",
}


def parse_prescan_for_hunters(prescan_results: dict, contract_name: str = "") -> str:
    """
    Parse Slither/Aderyn/Semgrep JSON results and format high-value signals
    for injection into hunter prompts. Only includes findings that correlate
    with real bugs (HIGH_VALUE_DETECTORS).

    Returns YAML-formatted string ready for prompt injection.
    """
    signals = []

    # Parse Slither/Slitherin JSON
    for tool_key in ("slitherin", "slither"):
        tool_data = prescan_results.get(tool_key, {})
        tool_path = tool_data.get("path")
        if not tool_path or not Path(tool_path).exists():
            continue
        try:
            raw = json.loads(Path(tool_path).read_text())
            # Slither format: {"results": {"detectors": [...]}} or {"results": [...]}
            detectors = []
            if isinstance(raw, dict):
                res = raw.get("results", raw)
                if isinstance(res, dict):
                    detectors = res.get("detectors", [])
                elif isinstance(res, list):
                    detectors = res
            for det in detectors:
                check = det.get("check", det.get("detector", ""))
                impact = det.get("impact", "").lower()
                confidence = det.get("confidence", "").lower()
                # Only high-value: high/medium impact OR known-good detector
                if check not in HIGH_VALUE_DETECTORS and impact not in ("high", "medium"):
                    continue
                # Filter to relevant contract if specified
                desc = det.get("description", "")[:300]
                elements = det.get("elements", [])
                locations = []
                relevant = not contract_name  # if no filter, include all
                for elem in elements[:5]:
                    src = elem.get("source_mapping", {})
                    fn = src.get("filename_short", src.get("filename_relative", ""))
                    lines = src.get("lines", [])
                    line_str = f"L{lines[0]}-{lines[-1]}" if lines else ""
                    if fn:
                        locations.append(f"{fn}:{line_str}")
                        if contract_name and contract_name.lower() in fn.lower():
                            relevant = True
                if not relevant:
                    continue
                signals.append({
                    "tool": tool_key,
                    "detector": check,
                    "impact": impact,
                    "confidence": confidence,
                    "description": desc.strip(),
                    "locations": locations[:3],
                })
        except (json.JSONDecodeError, KeyError, TypeError):
            continue

    # Parse Aderyn JSON
    aderyn_data = prescan_results.get("aderyn", {})
    aderyn_path = aderyn_data.get("path")
    if aderyn_path and Path(aderyn_path).exists():
        try:
            raw = json.loads(Path(aderyn_path).read_text())
            # Aderyn format: {"high_issues": {"issues": [...]}, "medium_issues": {...}, ...}
            for severity in ("critical_issues", "high_issues", "medium_issues"):
                section = raw.get(severity, {})
                issues = section.get("issues", [])
                for issue in issues:
                    title = issue.get("title", "")
                    detector = issue.get("detector_name", "")
                    instances = issue.get("instances", [])
                    locs = []
                    relevant = not contract_name
                    for inst in instances[:5]:
                        fn = inst.get("contract_path", inst.get("src", ""))
                        line = inst.get("line_no", inst.get("src_char", ""))
                        if fn:
                            locs.append(f"{fn}:L{line}" if line else fn)
                            if contract_name and contract_name.lower() in fn.lower():
                                relevant = True
                    if not relevant:
                        continue
                    signals.append({
                        "tool": "aderyn",
                        "detector": detector,
                        "impact": severity.replace("_issues", ""),
                        "description": title[:300],
                        "locations": locs[:3],
                    })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # Parse Semgrep JSON
    semgrep_data = prescan_results.get("semgrep", {})
    semgrep_path = semgrep_data.get("path")
    if semgrep_path and Path(semgrep_path).exists():
        try:
            raw = json.loads(Path(semgrep_path).read_text())
            for result in raw.get("results", []):
                check_id = result.get("check_id", "")
                severity = result.get("extra", {}).get("severity", "").lower()
                if severity not in ("error", "warning") and not any(d in check_id for d in HIGH_VALUE_DETECTORS):
                    continue
                fn = result.get("path", "")
                relevant = not contract_name or (contract_name.lower() in fn.lower())
                if not relevant:
                    continue
                line_start = result.get("start", {}).get("line", "")
                line_end = result.get("end", {}).get("line", "")
                msg = result.get("extra", {}).get("message", "")[:200]
                signals.append({
                    "tool": "semgrep",
                    "detector": check_id.split(".")[-1] if "." in check_id else check_id,
                    "impact": severity,
                    "description": msg.strip(),
                    "locations": [f"{fn}:L{line_start}-{line_end}"] if fn else [],
                })
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    if not signals:
        return ""

    # Format as YAML-like text for prompt injection
    lines = [f"# Static Analysis Signals ({len(signals)} high-value findings from prescan)"]
    for i, sig in enumerate(signals[:25], 1):  # cap at 25 signals
        lines.append(f"- title: \"{sig['detector']}\"")
        lines.append(f"  tool: {sig['tool']}")
        lines.append(f"  impact: {sig.get('impact', 'unknown')}")
        lines.append(f"  description: \"{sig['description']}\"")
        if sig.get("locations"):
            lines.append(f"  locations: {sig['locations']}")
        lines.append("")

    return "\n".join(lines)


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


_asset_flow_cache: dict = {}

def _generate_asset_flow_rich(contract_path: Path) -> str:
    """
    Calls protocol_analyzer.py --asset-flow for Slither-based rich asset flow.
    Returns markdown string or empty string on failure.
    Cached per contract_path to avoid running Slither 9 times.
    """
    if not contract_path or not contract_path.exists():
        return ""

    cache_key = str(contract_path)
    if cache_key in _asset_flow_cache:
        return _asset_flow_cache[cache_key]

    analyzer_script = AUDIT_AGENTS_DIR / "protocol_analyzer.py"
    if not analyzer_script.exists():
        _asset_flow_cache[cache_key] = ""
        return ""

    try:
        result = subprocess.run(
            [sys.executable, str(analyzer_script), "--asset-flow", str(contract_path)],
            capture_output=True, text=True, timeout=90,
        )
        output = result.stdout.strip()
        if output and "Rich Asset Flow Map" in output:
            _asset_flow_cache[cache_key] = output + "\n"
            return _asset_flow_cache[cache_key]
        _asset_flow_cache[cache_key] = ""
        return ""
    except Exception as e:
        print(f"[!] Rich asset flow failed: {e}")
        _asset_flow_cache[cache_key] = ""
        return ""


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
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Math / precision → MathHunter | Access control / roles → AccessHunter
- Oracle price feeds → OracleHunter | Token quirks → TrustBoundaryHunter
TÚ: reentrancy, CEI violations, callbacks, state transitions, flash loans, fund routing, state machine.

## Flash Loan Hypothesis (OBLIGATORIO — responde para CADA función que modifica estado)
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
Bug real: Compound v2 — cToken stuck en PAUSED sin función de unpause por admin key loss.

## Multi-TX State Sequences (OBLIGATORIO — después del FSM)
Diferente de reentrancy (misma TX). Busca bugs INTER-BLOQUE:
1. **TX1 (bloque N) deja estado X → TX2 (bloque N+1) lee estado X**: ¿es consistente? ¿TX2 asume que nadie más tocó el estado entre bloques?
2. **Race conditions entre usuarios**: ¿dos usuarios ejecutando la misma función en el mismo bloque producen resultado inesperado? (e.g., dos liquidadores compitiendo)
3. **Front-run observable**: ¿un observador de mempool puede front-run TX1 para alterar el resultado de TX2? (no sandwich genérico — secuencias ESPECÍFICAS de este contrato)
4. **State staleness**: ¿hay funciones que leen state que debería haberse actualizado pero no se llamó al actualizador? (accrue interest, update rewards)

Para cada secuencia encontrada: documenta TX1, TX2, estado intermedio, y el impacto económico.

## Derived State Freshness Map (OBLIGATORIO para protocolos con rates/indexes/rewards)
Mapea la cadena de dependencias entre valores derivados:

```yaml
derived_state_map:
  - state: currentBorrowingRate
    written_by: [updateInterestRates]
    read_by: [latestBorrowingIndex, _updateIndexes]
    stale_risk: "If utilization changes without calling updateInterestRates, _updateIndexes uses stale rate"
    verdict: STALE_RISK
```

Para CADA par donde `read_by` de stateA incluye una función que no está en
`written_by` de stateA → hay un path donde se lee stale. Documéntalo."""

    elif hunter_name == "OracleHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Flash loans / reentrancy → FlowHunter | Access control → AccessHunter | Math precision → MathHunter
TÚ: price feeds, TWAP manipulation, oracle staleness, spot vs TWAP, oracle dependencies, L2 sequencer.

## Oracle Deep Check (OBLIGATORIO — para cada fuente de precio)
Para CADA llamada a latestRoundData() o equivalente:
1. ¿Se verifica updatedAt contra un heartbeat? ¿El heartbeat es ESPECÍFICO por feed o genérico?
2. ¿Se chequea answeredInRound >= roundId?
3. ¿Se chequea price > 0?
4. ¿Hay check de L2 sequencer down? (Arbitrum/Optimism/Base: sequencerUptimeFeed)
5. ¿Existe minAnswer/maxAnswer que clampea el precio en flash crashes?
6. ¿El oracle puede ser sandwicheado? (front-run de oracle update para explotar el vault)

Oracle-Liquidity Mismatch (cmichel/Rari): ¿cuánto capital se necesita para manipular el oracle vs cuánto se puede extraer? Si manipulación < extracción → explotable.

## L2 Oracle Specifics (OBLIGATORIO si el contrato se deploya en L2 — Base/Arbitrum/Optimism)
1. **Sequencer uptime feed**: ¿se consulta? ¿hay grace period después de que el sequencer vuelve? (usuarios no pueden reaccionar inmediatamente)
2. **block.timestamp en L2**: en Arbitrum es el timestamp del L1 batch, no del L2 block — ¿afecta TWAP o staleness checks?
3. **Heartbeat divergente**: Chainlink feeds en L2 a menudo tienen heartbeats DIFERENTES que en L1 (e.g., ETH/USD: 1h en L1, 20min en Optimism). ¿El contrato usa el heartbeat correcto por chain?
4. **Multi-chain oracle consistency**: si el mismo protocolo está en L1+L2, ¿los precios pueden divergir temporalmente? ¿eso abre arbitrage explotable?
5. **Fallback oracle en L2**: si el primary feed falla en L2, ¿hay fallback? ¿o la función revierte bloqueando liquidaciones?"""

    elif hunter_name == "DomainHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Math genérico / precision → MathHunter | Access control genérico → AccessHunter
- Reentrancy / CEI → FlowHunter | Oracle feeds → OracleHunter
TÚ: lógica de NEGOCIO específica del protocolo, simetría funcional, invariantes económicos, constraint inference.

## Symmetric Inspection (OBLIGATORIO — después de tu análisis de dominio)
Identifica TODOS los pares simétricos del contrato. Pares comunes:
  deposit/withdraw, mint/burn, lock/unlock, stake/unstake, borrow/repay, open/close

Para CADA par, verifica estas 8 dimensiones:
1. **State variables**: ¿ambas funciones actualizan las mismas variables (en dirección opuesta)?
2. **Validaciones**: ¿mismas validaciones (o su inversa lógica)?
3. **Events**: ¿ambas emiten el evento correspondiente?
4. **Modifiers**: ¿mismos modifiers aplicados (nonReentrant, whenNotPaused)?
5. **Edge cases**: ¿amount=0, amount=max, balance=0 manejados simétricamente?
6. **Fee handling**: ¿ambas funciones cobran/acreditan fees simétricamente? (fee en deposit pero no en withdraw = leak)
7. **Event ordering**: ¿eventos emitidos ANTES o DESPUÉS del state change en ambas? (inconsistencia = off-chain confusion)
8. **Ghost variable tracking**: ¿totalDeposited se incrementa en deposit Y se decrementa en withdraw por la MISMA cantidad?

Cualquier asimetría es un candidato a invariante. Documenta qué variable/check/event falta en qué función.
Bug real: GMX — openShort actualizaba globalShortAveragePrices, closeShort NO → $42M.

## Constraint Inference (0xRajeev — OBLIGATORIO)
Para cada validación/require que encuentres:
1. Observa qué se valida en N-1 code paths que hacen algo similar.
2. El path que NO tiene esa validación es el bug candidato.
Ejemplo: si 5 de 6 funciones de withdraw verifican healthFactor, la 6ta que no lo hace es sospechosa.

## Parameter Usage Consistency (OBLIGATORIO)
Para CADA parámetro de configuración (threshold, limit, cap, fee, rate, max*, min*):
Lista TODAS las funciones que lo leen y QUÉ HACEN con él.

```yaml
parameter_consistency:
  - param: maxTimesLeverage
    usages:
      - {function: "_checkWithinlimits", line: 467, usage: "min(vp.maxTimesLeverage, maxLevTimes)"}
      - {function: "isLiquidateable", line: 408, usage: "vp.maxTimesLeverage - 1e18 (ignores pool limit)"}
    consistent: false
    verdict: "BUG — open validates against min(A,B) but liquidation uses only A"
```

REGLA: Si function_validate usa `restriction(param)` y function_execute usa
`param` sin la misma restricción → INCONSISTENCIA → Tier 1 si afecta apertura vs liquidación.

ESPECIALMENTE buscar: ¿puede un estado ser creado válidamente por F_create
y ser inmediatamente inválido según F_validate?

## Traza Hacia Atrás (samczsun — MENTALIDAD)
No empieces preguntando "¿hay un bug aquí?". Empieza preguntando:
"¿De dónde puede SALIR valor del protocolo?" (withdraw, redeem, liquidate, claim, transfer).
Para cada punto de salida, traza HACIA ATRÁS: ¿qué condiciones se deben cumplir? ¿Se pueden manipular?"""

    elif hunter_name == "MathHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Access control / roles → AccessHunter | Reentrancy / CEI → FlowHunter
- Oracle manipulation → OracleHunter | Gas DoS → DoSHunter
TÚ: overflow, underflow, precision loss, rounding direction, share price math, exchange rates.

## Pre-Descarte (OBLIGATORIO — ANTES de escribir cada hipótesis en el YAML)
Para cada hipótesis matemática, verifica PRIMERO estos 4 filtros:
1. **¿Está en `unchecked {}` block?** → Si la aritmética es checked (Solidity ≥0.8, sin unchecked), un overflow REVIERTE, no es explotable — descarta overflow genéricos fuera de unchecked
2. **¿El input está acotado por un require/if anterior?** → Calcula el rango REAL del input, no asumas type(uint256).max
3. **¿La precision loss es < 1 wei para inputs realistas?** → Prueba con montos reales ($100, $1M, $100M). Si la pérdida es dust → false_positive con razón
4. **¿La función es internal y solo se llama con valores controlados?** → Traza TODOS los call sites. Si todos pre-validan, descarta

Solo hipótesis que SOBREVIVEN los 4 filtros van al YAML. Las descartadas van a `false_positives:` con la razón específica.

## Decimal Impact Table (OBLIGATORIO — reemplaza texto libre)
Para CADA operación aritmética que involucra token amounts o precios,
DEBES producir esta tabla en tu output YAML bajo el campo `decimal_analysis`:

```yaml
decimal_analysis:
  - operation: "L149: cross * totalSupply / bal0 / bal1"
    intermediate_max_bits: 96
    result_6dec: "1e6 — OK"
    result_8dec: "1e8 — OK"
    result_18dec: "1e18 — OK"
    overflow_risk: false
    truncation_risk: false
    verdict: SAFE
```

Si tu YAML no incluye `decimal_analysis` con al menos 1 entrada por operación
aritmética crítica → el merge_invariants.py lo rechazará.

NO escribas "funciona para 6/8/18" sin la tabla numérica con bits calculados.

## Boundary Collapse Check (OBLIGATORIO)
Para CADA integer division cuyo resultado se usa en comparación (<, <=, >, >=):
1. ¿Cuál es el valor MÍNIMO válido del divisor?
2. Si min_divisor → quotient == 0: ¿la comparación sigue siendo correcta?
3. TABLA en tu output YAML bajo `boundary_analysis`:

```yaml
boundary_analysis:
  - line: 236
    expression: "modulo < (tickSpacing / 2)"
    divisor: tickSpacing
    divisor_min: 1
    quotient_at_min: 0
    comparison_becomes: "modulo < 0 → always false for uint"
    verdict: BUG
```

## Bidirectional Rounding Check (Sec3/Josselin Feist — OBLIGATORIO)
Para cada función BIDIRECCIONAL (swap A→B y B→A, mint/redeem, deposit/withdraw):
1. Localiza cada "rounding signature" (multiplicación seguida de división)
2. ¿Se redondea CONSISTENTEMENTE? (down en output, up en fee — o viceversa)
3. ¿Un round-trip (A→B→A) puede ser rentable para el atacante? Si deposit(X) y luego withdraw da > X → bug
4. "Round in favor of protocol" tiene side effects: atacantes pueden extraer valor de OTROS USUARIOS (no del pool)

## Fuzz para Maximizar (Dacian — MENTALIDAD)
Cuando escribas invariantes de math, piensa en modo OPTIMIZACIÓN no solo VERIFICACIÓN:
- No solo "¿hay precision loss?" sino "¿cuál es el INPUT que MAXIMIZA la precision loss?"
- Para CADA hipótesis con precision loss, escribe una función `optimize_` que Echidna pueda maximizar:
```solidity
// Echidna intentará maximizar el return value
function optimize_precisionLoss(uint256 amount) public returns (int256) {
    uint256 shares = vault.deposit(amount);
    uint256 redeemed = vault.redeem(shares);
    return int256(amount) - int256(redeemed); // maximizar pérdida del usuario
}
```
Si NO puedes escribir la función optimize_, la hipótesis de precision loss es especulativa — baja confidence a 50%."""

    elif hunter_name == "WildcardHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices en estos — referencia si detectas algo):
- Math/precision → MathHunter | Reentrancy/callbacks → FlowHunter | Access control → AccessHunter
- Oracles → OracleHunter | Signatures → SignatureHunter | Gas DoS/loops → DoSHunter
TÚ: vectores que NO encajan en ningún otro hunter. Lo raro, lo inesperado, lo creativo.

## Checklist de Vectores Exclusivos (OBLIGATORIO — revisa cada uno contra el código)
Estos son PUNTOS DE PARTIDA, no tu scope completo. Si encuentras algo fuera de esta lista, perfecto.
1. **SafeCast / type conversion**: ¿hay toUint128, toInt256, toUint96 que truncan silenciosamente en `unchecked` blocks?
2. **abi.decode de datos externos**: ¿se valida longitud? ¿puede revert con datos malformados o vacíos?
3. **CREATE2 / address prediction**: ¿se puede pre-computar address y enviar ETH/tokens antes de deploy?
4. **selfdestruct / PUSH0**: ¿el contrato asume que code.length > 0 implica "es contrato"? ¿address(x).code.length post-selfdestruct?
5. **EVM precompile edge cases**: ¿usa ecrecover, modexp, bn256? ¿inputs fuera de rango producen resultados inesperados?
6. **Transient storage (EIP-1153)**: ¿usa tstore/tload? ¿se limpia al final de la tx? ¿cross-call leaks?
7. **Returndata bomb**: ¿low-level call sin límite de returndata size? (2MB returndata = OOG)
8. **Dirty upper bits**: ¿compara bytes32/address que podría tener dirty bits en posiciones altas?
9. **Immutable vs recalculable**: ¿variable immutable que debería recalcularse? (chainId, DOMAIN_SEPARATOR cacheado)
10. **Array deletion gaps**: ¿delete array[i] deja slot en zero sin compactar? ¿afecta iteraciones posteriores?
11. **Phantom overflow en unchecked**: ¿arithmetic dentro de `unchecked {}` que puede overflow con inputs extremos?
12. **Storage collision en proxy patterns**: ¿variables de herencia múltiple colisionan en storage layout?

## Deadlock Analysis (OBLIGATORIO — después del checklist)
Para cada safety check, margin, cap, o límite en el contrato:
1. ¿Puede BLOQUEAR una operación de emergencia? (repay, withdraw, liquidate, unstake)
2. ¿El safety mechanism puede dejar fondos permanentemente bloqueados?
3. ¿Un cap que protege al protocolo puede impedir que un usuario se salve de liquidación?
Bug real: Safety margin en repay impedía repago → liquidados sin poder hacer nada.

## Composability Attack (samczsun — "Two Rights Make A Wrong")
Para cada interacción con un contrato externo:
1. ¿Qué ASUME este contrato sobre el comportamiento del otro?
2. ¿Se puede crear un estado donde ambos contratos son internamente consistentes pero JUNTOS son inseguros?
Bug real: SushiSwap MISO — msg.value reutilizado en loop de batch.

## Mentalidad cmichel
¿Podrías reimplementar esto de memoria? Donde tu versión mental DIFIERA del código real → candidato a bug."""

    elif hunter_name == "AccessHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Token quirks / external trust → TrustBoundaryHunter | Signatures / permits → SignatureHunter
- Math / precision → MathHunter | Reentrancy / callbacks → FlowHunter
TÚ: roles, modifiers, privilege escalation, authorization paths, initialization guards.

## State Variable Lifecycle Audit (OBLIGATORIO — ANTES de trust boundary mapping)
Para CADA state variable del contrato, produce esta tabla:

```yaml
state_var_lifecycle:
  - name: feeRecipient
    type: address
    declared_line: 47
    writes: []
    reads_in_value_context:
      - {line: 328, context: "safeTransfer(feeRecipient, pf0)"}
    verdict: DEAD_STATE — address never set, transfers go to address(0)
  - name: owner
    type: address
    declared_line: 12
    writes: [{line: 65, context: "constructor: owner = msg.sender"}]
    reads_in_value_context: [{line: 500, context: "modifier onlyOwner"}]
    verdict: SAFE
```

Si `writes` está vacío y `reads_in_value_context` tiene entries → TIER 1.
Si un contrato hermano en scope tiene setter para la misma variable y este contrato no → flag como OVERSIGHT.

## Trust Boundary Mapping (0xRajeev — OBLIGATORIO)
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

**CADA invariante en tu YAML DEBE tener un campo `solidity:` con código real.** Si no puedes escribir el assertion, la hipótesis es demasiado vaga — descártala o concretiza.

## Filtro Pre-Output (OBLIGATORIO — antes de escribir el YAML)
Para cada hipótesis, clasifica ANTES de incluirla:
- "Admin/owner puede hacer X malo" → tier: 3, confidence: max 50% (centralización, rara vez pagado en bounties)
- "Requiere multisig malicioso o governance attack" → tier: 2, documenta pero no Tier 1
- "Usuario sin privilegios extrae fondos o bloquea fondos ajenos" → tier: 1, INVESTIGA A FONDO
- "Initialization/upgrade risk en contrato ya deployed" → tier: 1 (verificable on-chain)
- "Initialization/upgrade risk en contrato pre-launch" → tier: 2

Si no puedes describir el ataque en 5 pasos concretos → baja el confidence 10%."""

    elif hunter_name == "TrustBoundaryHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Access control / roles / modifiers → AccessHunter
- Signatures / permits / EIP-712 → SignatureHunter
- Protocol business logic → DomainHunter
TÚ: trust en contratos EXTERNOS, token quirks, proxy patterns, compiler/EVM assumptions.

## External Call Trust Matrix (OBLIGATORIO — tu sección MÁS IMPORTANTE)
Para CADA external call en el contrato, llena esta fila:
| Línea | Target | ¿Return value usado? | ¿Qué pasa si reverts? | ¿Qué pasa si retorna valor manipulado? | ¿Quién controla target? |

Busca específicamente:
1. **Unchecked return values**: ¿se ignora el bool de transfer/approve/call?
2. **Trust en retorno**: ¿se usa balanceOf() de un token externo como fuente de verdad sin verificar delta?
3. **Delegatecall a target variable**: ¿el target puede cambiar? ¿quién lo controla?
4. **Callback trust**: ¿se valida que el callback viene del contrato esperado? (no solo msg.sender == pool)
5. **External state dependency**: ¿una función depende de un estado externo que puede cambiar entre el check y el use?

## Weird ERC-20 Checklist (d-xo — OBLIGATORIO si el contrato interactúa con tokens)
Para cada token que el contrato maneja, verificar:
- ¿Retorna bool en transfer/approve? (USDT, BNB, OMG NO retornan) → ¿usa SafeERC20?
- ¿Requiere approve(0) antes de re-approve? (USDT, KNC)
- ¿Revierte en transfer de valor 0? (LEND)
- ¿Es rebasing? (stETH, AMPL — balance cambia sin transfer)
- ¿Tiene fee-on-transfer? (amount recibido < amount enviado)
- ¿Tiene blocklist? (USDC, USDT — pueden bloquear el contrato)
- ¿Tiene hook/callback? (ERC-777 tokensReceived, ERC-677 onTokenTransfer)
Si el contrato asume ERC-20 estándar y acepta tokens arbitrarios → HIGH risk.

## Proxy/Upgrade Invariants (OBLIGATORIO si el contrato es upgradeable o usa proxy)
1. ¿Storage layout preservado entre versiones? (herencia múltiple = riesgo de collision)
2. ¿Initializer tiene reinit guard? (initializer vs reinitializer)
3. ¿Constructor de implementation vacío? (si no, el state del constructor no existe en proxy)
4. ¿Funciones nuevas colisionan con proxy admin selectors? (function clashing)
5. ¿Hay delegatecall a contrato que puede ser destruido o reemplazado?

## Compiler Version Check (OBLIGATORIO)
1. Verifica versión Solidity — ¿bugs conocidos? (soliditylang.org/en/latest/bugs.html)
2. Si Solidity < 0.8.20: ¿desplegado en chain sin PUSH0? (Shanghai EVM)
3. Si Vyper: verificar que NO es 0.2.15-0.3.0 (reentrancy lock failure → $69M Curve 2023)

## Integration Assumption Verification (OBLIGATORIO si interactúa con protocolo externo)
Para CADA interacción con protocolo externo (Uniswap, Chainlink, Aave, Compound, etc.):

```yaml
integration_assumptions:
  - external_protocol: "Uniswap V3"
    call: "pool.observations(index)"
    assumption: "uninitialized slots return timestamp=0"
    actual_behavior: "uninitialized slots return timestamp=1"
    code_check: "L322: if (timestamp == 0) revert"
    match: false
    verdict: "BUG — sentinel value mismatch"
```

Proceso:
1. Listar CADA external call a protocolo conocido
2. Para cada uno: ¿qué ASUME el código sobre el return value?
3. Verificar contra el comportamiento REAL del protocolo externo
4. Sentinel values son los MÁS peligrosos: 0 vs 1, empty vs default, revert vs return(0)

## REGLA: Solidity Assertions Obligatorias
CADA hipótesis DEBE tener campo `solidity:` con assertion real. Confidence mínimo: 55%.
Si no puedes escribir el assertion, la hipótesis es demasiado vaga — descártala o concretiza."""

    elif hunter_name == "SignatureHunter":
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Access control genérico / roles → AccessHunter | Reentrancy / callbacks → FlowHunter
- Math / precision → MathHunter
TÚ: firmas, permits, nonces, EIP-712, ecrecover, meta-transactions, allowance/approval patterns.

## Signature & Permit Deep Check (OBLIGATORIO — para CADA uso de firma/permit en el contrato)

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
        return """## Scope Anti-Overlap
Responsabilidad PRIMARIA de otros hunters (no profundices — referencia si detectas algo):
- Reentrancy / CEI → FlowHunter | Access control → AccessHunter | Math → MathHunter
TÚ: gas griefing, unbounded loops, revert-based DoS, blocked withdrawals, resource exhaustion, emergency blocking.

## DoS / Griefing Deep Check (OBLIGATORIO — la clase de vuln MÁS IGNORADA, 2,279 findings en Solodit)

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

### Sección 1b: Loop Termination Proof (DISTINTO de Sección 1)
Sección 1 pregunta "¿puede el loop ser MUY LARGO?".
Esta sección pregunta "¿TERMINA el loop? ¿Siempre?"

Para CADA loop (while/for), produce:

```yaml
loop_termination:
  - location: "L568: while (path.hasMultiplePools())"
    control_variable: path
    progression_in_body: "path.skipToken() called but return NOT assigned"
    terminates: false
    verdict: INFINITE_LOOP
  - location: "L315: for (uint256 i = 1; i <= N; i++)"
    control_variable: i
    progression_in_body: "i++ in for header"
    terminates: true
    verdict: SAFE
```

CLAVE: funciones pure/view (como `bytes.skipToken()`) retornan un NUEVO valor,
NO mutan el input. Si se llama `x.method()` sin `x = x.method()`, x NO CAMBIA.

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


def _run_symmetric_analysis(contract_path: Path) -> str:
    """Run symmetric_analyzer.py and return output. Cached per file."""
    if not contract_path or not contract_path.exists():
        return ""
    sym_script = AUDIT_AGENTS_DIR / "symmetric_analyzer.py"
    if not sym_script.exists():
        return ""
    contract_name = contract_path.stem  # Foo.sol → Foo
    try:
        result = subprocess.run(
            [sys.executable, str(sym_script), str(contract_path), "--contract", contract_name],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip() and "ERROR" not in result.stdout[:20]:
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _run_deep_flatten(contract_path: Path) -> str:
    """Run deep_flatten.py --critical-only and return output."""
    if not contract_path or not contract_path.exists():
        return ""
    script = AUDIT_AGENTS_DIR / "deep_flatten.py"
    if not script.exists():
        return ""
    contract_name = contract_path.stem
    try:
        result = subprocess.run(
            [sys.executable, str(script), str(contract_path), "--critical-only", "--contract", contract_name],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return ""


# Module-level cache to avoid re-running Slither per hunter
_symmetric_cache: dict[str, str] = {}
_flatten_cache: dict[str, str] = {}


def generate_hunter_prompt(
    hunter_name: str,
    component: str,
    contract_path: Path,
    domain: str,
    solodit_ctx: str,
    briefing_excerpt: str,
    protocol: str,
    prepass_signals: str = "",
) -> str:
    """Genera el prompt completo para un hunter específico."""
    _, focus = HUNTER_DOMAINS.get(hunter_name, ("general", "General analysis"))
    abbreviation = "".join(w[0] for w in re.findall(r'[A-Z][a-z]*', component)).upper()
    if not abbreviation:
        abbreviation = component[:3].upper()

    contract_preview = ""
    contract_truncated = False
    CONTRACT_CHAR_LIMIT = 60_000
    library_preview = ""
    if contract_path and contract_path.exists():
        full_src = contract_path.read_text()
        if len(full_src) > CONTRACT_CHAR_LIMIT:
            contract_preview = full_src[:CONTRACT_CHAR_LIMIT]
            contract_truncated = True
        else:
            contract_preview = full_src

        # [BENCHMARK-IMPROVE-3] Include project-local libraries in hunter context
        # Libraries (ReserveLogic, InterestRateUtils, etc.) often contain critical bugs
        # that hunters miss when they only see the main contract.
        lib_texts = []
        lib_char_budget = 20_000  # budget for all libraries combined
        lib_dir = contract_path.parent / "libraries"
        if not lib_dir.exists():
            lib_dir = contract_path.parent  # same dir
        for sol_file in sorted(contract_path.parent.rglob("*.sol")):
            # Skip the main contract itself, test files, interfaces, and node_modules
            if sol_file == contract_path:
                continue
            rel = str(sol_file.relative_to(contract_path.parent))
            if any(skip in rel for skip in ["test/", "node_modules/", "lib/", "interfaces/"]):
                continue
            # Only include project-local libraries (not OZ, not Uniswap)
            if "libraries/" in rel or "types/" in rel or "utils/" in rel:
                lib_src = sol_file.read_text()
                if len(lib_src) > 8000:
                    lib_src = lib_src[:8000] + "\n// ... truncated ..."
                lib_texts.append(f"// === {rel} ===\n{lib_src}")
        if lib_texts:
            combined = "\n\n".join(lib_texts)
            if len(combined) > lib_char_budget:
                combined = combined[:lib_char_budget] + "\n// ... libraries truncated ..."
            library_preview = combined

    hyp_output = str(get_hyp_dir(protocol) / f"hyp_{component}_{hunter_name}.yaml")

    # Generate asset flow map (rich Slither-based, fallback to regex)
    asset_flow_map = _generate_asset_flow_rich(contract_path)
    if not asset_flow_map:
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

    # Generate symmetric analysis (cached — runs once for all hunters)
    cache_key = str(contract_path) if contract_path else ""
    if cache_key and cache_key not in _symmetric_cache:
        _symmetric_cache[cache_key] = _run_symmetric_analysis(contract_path)
    symmetric_section = _symmetric_cache.get(cache_key, "")
    if symmetric_section and "No se encontraron pares" not in symmetric_section:
        symmetric_section = f"""
## Symmetric Analysis (asimetrías entre pares de funciones)
{symmetric_section}
"""
    else:
        symmetric_section = ""

    # Generate KB pattern appendix (background knowledge, not directive)
    kb_appendix = ""
    kb_briefings = HUNTER_KB_BRIEFINGS.get(hunter_name, [])
    if kb_briefings:
        kb_patterns = extract_kb_pattern_summaries(kb_briefings)
        if kb_patterns:
            kb_appendix = f"""
---
## APPENDIX: Patrones conocidos en tu dominio (referencia — NO limites tu análisis a estos)
Estos patrones se han visto en auditorías reales. Úsalos como background, no como checklist.
Si reconoces alguno en el código, investígalo. Pero tu análisis principal debe ser independiente.

{kb_patterns}
"""

    # Inject wiki and graph context
    wiki_ctx = query_wiki_context(domain, component)
    # Prepend the synthesized /wiki-query brief (generated by scope_intake.py)
    # if present — richer than keyword-matched snippets.
    wiki_brief_path = HUNT_SESSION_DIR / "context" / protocol / "wiki_prior_knowledge.md"
    if wiki_brief_path.exists():
        try:
            brief = wiki_brief_path.read_text(errors="ignore")
            if len(brief) > 3000:
                brief = brief[:3000] + "\n[... truncated]"
            wiki_ctx = f"\n## Prior Knowledge Brief (/wiki-query)\n{brief}\n{wiki_ctx}"
        except Exception:
            pass
    graph_ctx = load_graph_report(protocol)
    rejection_ctx = load_rejection_context()
    hunter_domain_key, _ = HUNTER_DOMAINS.get(hunter_name, ("general", "General"))
    few_shot_ctx = load_few_shot_examples(hunter_domain_key)

    # Prepass signals section
    prepass_section = ""
    if prepass_signals:
        prepass_section = f"""
## ⚠ SEÑALES DEL PRE-ANÁLISIS ESTÁTICO (Detection Engine)
Las siguientes señales fueron detectadas automáticamente. DEBES verificar cada una que corresponda a tu especialidad.
Si confirmas el bug, inclúyelo como invariante Tier 1. Si descartas, documenta por qué en false_positives.

```yaml
{prepass_signals}
```
"""

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

{asset_flow_map if asset_flow_map else ""}{symmetric_section}```solidity
{contract_preview}
```
{"" if not library_preview else '''
## Project Libraries (ANALIZAR CON LA MISMA PROFUNDIDAD que el contrato principal)
⚠ CRÍTICO: Las libraries contienen lógica de negocio (interest rates, reserves, math).
Bugs en libraries afectan TODOS los contratos que las usan. NO las trates como "código confiable".
Para cada función de library llamada desde el contrato principal:
1. Lee la implementación completa
2. Verifica ordering de operaciones (¿se actualiza el rate ANTES o DESPUÉS de usarlo?)
3. Verifica precision con decimals extremos (6, 8, 18)
4. Verifica que los return values se usen correctamente

```solidity
''' + library_preview + '''
```
'''}

## Contexto de Solodit (bugs similares en protocolos similares)
{solodit_ctx or "Sin contexto disponible — busca patrones propios"}

## Briefing del Dominio ({domain})
{briefing_excerpt or "Sin briefing disponible"}

{wiki_ctx}{graph_ctx}{rejection_ctx}{few_shot_ctx}{prepass_section}{chimera_ctx}

## Razonamiento Paso a Paso (OBLIGATORIO antes de cada hipótesis)

Para CADA posible vulnerabilidad, razona explícitamente:
1. **Qué hace esta función**: describe en 1 frase
2. **Qué asume sobre el estado**: precondiciones implícitas
3. **Qué pasa si esa asunción es falsa**: escenario concreto
4. **Cómo se explota**: paso a paso del atacante
5. **Cuánto pierde la víctima**: en USD o % del pool

Si no puedes completar los 5 pasos con datos concretos, la hipótesis tiene confidence < 60%.

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
  poc_sketch: |
    function test_{abbreviation}_01() public {{
        // 1. Setup: deploy protocol, seed liquidity
        // 2. Estado previo: record contract.value()
        // 3. Acción del atacante: call function with malicious params
        // 4. Verificación: assert contract.value() decreased
    }}
  validated: true
  priority: high
  confidence: 80
```

**IMPORTANTE**: Para CADA invariante con confidence >= 60%, incluir `poc_sketch` con los 4 pasos (Setup, Estado previo, Acción, Verificación). Sin poc_sketch = hipótesis incompleta.

{_hunter_specific_section(hunter_name)}

## Regla Anti-Tunnel-Vision (aplica a TODOS los hunters) — CRÍTICA
**BENCHMARK DATA**: En tests reales, perdemos ~25% de findings porque el hunter encuentra UN bug
en una función y deja de buscar OTROS bugs en la MISMA función. Esto NO es aceptable.

Si durante tu análisis identificas un bug en función F():
1. **PARA.** Marca el bug encontrado. Luego VUELVE al inicio de F() y lee CADA LÍNEA de nuevo
   buscando bugs ADICIONALES de tipos DIFERENTES al que ya encontraste.
2. **Busca TODAS estas categorías** en F() antes de pasar a otra función:
   - ¿Hay un off-by-one en algún boundary check? (`<` vs `<=`, `>=` vs `>`)
   - ¿Hay un return value ignorado o no reasignado?
   - ¿Hay integer division que redondea a zero con parámetros extremos?
   - ¿Se usa `slot0()` cuando debería ser `sqrtPriceX96` derivado, o viceversa?
   - ¿Hay un ordering bug (state read before update vs after)?
3. **Busca si funciones adyacentes** (mismo caller, misma familia) tienen el mismo error pattern
4. **Documenta**: `related_functions_audited: [list]` + `additional_bugs_in_same_function: [list]`

Un hunter que reporta 1 bug en una función cuando hay 3 es PEOR que uno que reporta 0 —
porque crea falsa sensación de cobertura.

## Reglas Críticas
- **Sin genéricos**: "el contrato podría tener reentrancy" NO es un invariante
- **Con ataque concreto**: especifica exactamente cómo se perdería dinero
- **Confidence honesto**: si no estás seguro al 60%+, marca validated: false
- **False positives**: si investigas algo y es by design, añádelo a false_positives con la lección
{kb_appendix}"""


def _extract_deployments_from_scope_master(component: str, protocol: str = "") -> list[dict]:
    """Extract deployment table for a component from SCOPE_MASTER.md."""
    # Find SCOPE_MASTER
    hunt_session = Path("hunt_session")
    scope_masters = list(hunt_session.glob("context/*/SCOPE_MASTER.md"))
    scope_master = None
    for sm in scope_masters:
        if protocol and protocol.lower() in sm.parent.name.lower():
            scope_master = sm
            break
    if not scope_master and scope_masters:
        scope_master = scope_masters[0]
    if not scope_master:
        return []

    text = scope_master.read_text()
    comp_escaped = re.escape(component)
    # Split text into sections by ### headings, match component in heading line
    sections = re.split(r'\n(?=###\s)', text)
    target_section = None
    for sec in sections:
        heading = sec.split('\n')[0]
        if re.search(comp_escaped, heading, re.IGNORECASE):
            target_section = sec
            break
    if not target_section:
        return []

    deployments = []
    # Match table rows with backtick-wrapped 0x addresses
    for row in re.findall(r'\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*`(0x[a-fA-F0-9]+)`\s*\|\s*([^|]+?)\s*\|', target_section):
        name, chain, address, estado = [x.strip() for x in row]
        if chain.lower() in ("chain", "---", ""):
            continue
        deployments.append({"name": name, "chain": chain, "address": address, "estado": estado})
    return deployments


# [BENCHMARK-IMPROVE-5] Cross-Function Invariant Consistency Checker
# Benchmark gap: H-04 and H-05 — _checkWithinlimits and isLiquidateable enforce
# contradictory rules using the same parameter (maxTimesLeverage).
# This function detects pairs of functions sharing state variables and flags
# potential inconsistencies for DeepDiveHunter to investigate.
def _extract_consistency_pairs(contract_path: Path) -> str:
    """
    Analyze a contract for function pairs that share state variables
    and may enforce contradictory invariants.
    Returns formatted text for DeepDive prompt injection.
    """
    if not contract_path or not contract_path.exists():
        return ""

    source = contract_path.read_text()
    filename = contract_path.name

    # Step 1: Extract all state variables
    state_vars = set()
    for match in re.finditer(
        r'^\s+(?:uint\d*|int\d*|address|bool|bytes\d*|mapping)\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*[;=]',
        source, re.MULTILINE
    ):
        state_vars.add(match.group(1))
    # Also match storage structs accessed as members
    for match in re.finditer(r'(\w+)\.(\w+)', source):
        if match.group(1) in state_vars:
            state_vars.add(f"{match.group(1)}.{match.group(2)}")

    if not state_vars:
        return ""

    # Step 2: Map functions → state variables they READ
    func_pattern = re.compile(r'function\s+(\w+)\s*\(([^)]*)\)[^{]*\{', re.DOTALL)
    func_reads: dict[str, set] = {}
    func_lines: dict[str, int] = {}

    for func_match in func_pattern.finditer(source):
        func_name = func_match.group(1)
        line_num = source[:func_match.start()].count('\n') + 1
        func_lines[func_name] = line_num

        body_start = source.find('{', func_match.end() - 1)
        body_end = -1
        depth = 0
        for i in range(body_start, min(body_start + 30000, len(source))):
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
                if depth == 0:
                    body_end = i
                    break
        if body_end < 0:
            continue

        body = source[body_start:body_end]
        reads = set()
        for var in state_vars:
            if var in body:
                reads.add(var)
        if reads:
            func_reads[func_name] = reads

    # Step 3: Find pairs with shared state variables (potential consistency issues)
    pairs = []
    func_names = list(func_reads.keys())
    for i in range(len(func_names)):
        for j in range(i + 1, len(func_names)):
            f1, f2 = func_names[i], func_names[j]
            shared = func_reads[f1] & func_reads[f2]
            # Only interesting if they share non-trivial state
            # Filter out common variables like 'owner', 'paused', 'msg.sender'
            shared_interesting = {v for v in shared
                                  if v not in ('owner', 'paused', '_owner', 'msg')}
            if len(shared_interesting) >= 2:  # At least 2 shared state vars = high signal
                pairs.append((f1, f2, shared_interesting))

    if not pairs:
        return ""

    # Step 4: Format for DeepDive prompt
    # Sort by number of shared variables (most shared first)
    pairs.sort(key=lambda x: len(x[2]), reverse=True)

    lines = [
        "## ⚠ Cross-Function Invariant Consistency Check [BENCHMARK-IMPROVE-5]",
        "**CRITICAL**: In benchmark testing, we MISSED 2 HIGH findings (H-04, H-05) because",
        "two functions enforced contradictory rules using the same state variables.",
        "Example: _checkWithinlimits allowed leverage up to maxTimesLeverage,",
        "but isLiquidateable used (maxTimesLeverage - 1e18) as divisor → contradiction.",
        "",
        "For EACH pair below, answer: **Do both functions enforce the SAME invariant on the shared variables?**",
        "If they use the same variable in DIFFERENT ways (different thresholds, different formulas,",
        "different inequality directions), that is a **potential HIGH severity finding.**",
        "",
    ]

    for f1, f2, shared in pairs[:10]:  # Cap at 10 pairs
        l1 = func_lines.get(f1, "?")
        l2 = func_lines.get(f2, "?")
        shared_str = ", ".join(sorted(shared)[:5])
        lines.append(f"### {f1}() (L{l1}) ↔ {f2}() (L{l2})")
        lines.append(f"   Shared state: `{shared_str}`")
        lines.append(f"   Questions:")
        lines.append(f"   - Do both use `{list(shared)[0]}` with the SAME threshold/formula?")
        lines.append(f"   - If {f1} allows a state, does {f2} correctly handle that state?")
        lines.append(f"   - Can a user satisfy {f1}'s check but fail {f2}'s check (or vice versa)?")
        lines.append("")

    return "\n".join(lines)


def generate_deepdive_prompt(
    component: str,
    contract_path: Path,
    protocol: str,
) -> str:
    """Genera el prompt del DeepDiveHunter usando resultados de los 7 hunters."""
    hyp_dir = get_hyp_dir(protocol)

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

    hyp_output = str(get_hyp_dir(protocol) / f"hyp_{component}_DeepDiveHunter.yaml")

    # Generate rich asset flow for DeepDive
    asset_flow_dd = _generate_asset_flow_rich(contract_path)
    if not asset_flow_dd:
        asset_flow_dd = generate_asset_flow_map(contract_path)

    # [BENCHMARK-IMPROVE-5] Generate consistency pairs for cross-function invariant check
    consistency_section = _extract_consistency_pairs(contract_path)

    # Generate deep flatten for DeepDive (critical functions: READ/WRITE/EXTERNAL order)
    cache_key = str(contract_path) if contract_path else ""
    if cache_key and cache_key not in _flatten_cache:
        _flatten_cache[cache_key] = _run_deep_flatten(contract_path)
    flatten_dd = _flatten_cache.get(cache_key, "")
    flatten_section = ""
    if flatten_dd:
        flatten_section = f"""
## Deep Flatten — Secuencia Real de Ejecución
Funciones críticas aplanadas: modifiers inlineados, calls internos expandidos.
Busca WRITEs después de EXTERNALs (CEI violations) y secuencias READ→EXTERNAL→WRITE.

{flatten_dd}
"""

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

{asset_flow_dd if asset_flow_dd else ""}

{flatten_section}

{conv_text}

{existing_text}

{fp_text}

## Tu Proceso (OBLIGATORIO — sigue las 4 secciones en orden)

### Sección 0: Full Function Audit After Finding (OBLIGATORIO)
REGLA: cuando encuentres un bug en una función, DETENTE.
Audita CADA LÍNEA RESTANTE de esa función antes de pasar a la siguiente hipótesis.

Una función con 1 bug tiene P(otro bug) ≈ 30%.
Evidencia: checkPoolActivity (3 bugs en 1 función), isLiquidateable (2 bugs en 1 función).

Proceso:
1. Bug encontrado en F() línea N → audita líneas N+1 hasta fin de F()
2. ¿Las funciones hermanas (llamadas por el mismo caller) tienen el mismo patrón?
3. ¿Contratos hermanos en scope tienen la versión correcta? (comparar setters, validators)
4. Solo después de auditar F() completa, pasa a la siguiente hipótesis.
5. Documenta en tu YAML: `related_functions_audited: [list]` para cada finding.

### Sección 1: Design Assumption Analysis
Para cada función crítica: ¿qué asume el developer que nunca pasará?
Lista cada asunción. Para cada una: construye un escenario concreto que la viole.

### Sección 2: Cross-Function State Analysis
Para cada PAR de funciones críticas: ¿qué pasa si se llaman en orden inesperado?
¿Qué estado deja A que hace que B se comporte diferente?

### Sección 2.5: Cross-Function Invariant Consistency (OBLIGATORIO)
**BENCHMARK DATA**: Perdimos 2 HIGH findings (28% de HIGHs) porque dos funciones
enforceaban reglas CONTRADICTORIAS sobre la misma variable de estado.

Para cada par de funciones que comparten variables de estado:
1. Extrae la FÓRMULA o CONDICIÓN exacta que cada función aplica a la variable compartida
2. Compara: ¿son consistentes? ¿Usan el mismo threshold, la misma dirección de inequality?
3. Si f1 permite un valor X, ¿f2 lo maneja correctamente cuando recibe X?
4. EJEMPLO: _checkWithinlimits permitía leverage = maxTimesLeverage, pero isLiquidateable
   usaba (maxTimesLeverage - 1e18) como divisor → posición inmediatamente liquidable tras apertura.

{consistency_section}

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

**Sin límite artificial.** Genera todas las que tengan confidence >= 60%. Cada una DEBE tener:
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


def generate_crosschain_prompt(
    component: str,
    contract_path: Path,
    protocol: str,
) -> str | None:
    """Genera el prompt del CrossChainHunter. Returns None if single-chain (skip)."""
    hyp_dir = get_hyp_dir(protocol)

    deployments = _extract_deployments_from_scope_master(component, protocol)
    chains = set(d["chain"] for d in deployments)
    if len(chains) < 2:
        skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
        skip_file.parent.mkdir(parents=True, exist_ok=True)
        skip_file.write_text(f"single-chain component ({', '.join(chains) if chains else 'no deployments found'})")
        return None

    deploy_text = "## Deployment Map\n\n"
    deploy_text += "| Contrato | Chain | Address | Estado |\n"
    deploy_text += "|----------|-------|---------|--------|\n"
    for d in deployments:
        deploy_text += f"| {d['name']} | {d['chain']} | `{d['address']}` | {d['estado']} |\n"
    deploy_text += f"\n**Chains**: {', '.join(sorted(chains))} ({len(chains)} chains)\n"

    relevant_hunters = ["SignatureHunter", "TrustBoundaryHunter", "FlowHunter", "AccessHunter"]
    hunter_context = ""
    existing_ids = set()
    for hunter in relevant_hunters:
        hyp_file = hyp_dir / f"hyp_{component}_{hunter}.yaml"
        if not hyp_file.exists():
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            findings = data.get("invariants", data.get("findings", []))
            if findings:
                hunter_context += f"\n### {hunter} findings ({len(findings)}):\n"
                for inv in findings:
                    inv_id = inv.get("id", "?")
                    existing_ids.add(inv_id)
                    hunter_context += f"- [{inv_id}] ({inv.get('confidence', '?')}%): {inv.get('description', '')}\n"
        except Exception:
            continue

    all_fps = []
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        if "CrossChain" in hyp_file.name or "DeepDive" in hyp_file.name:
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            for inv in data.get("invariants", []):
                existing_ids.add(inv.get("id", ""))
            for fp in data.get("false_positives", []):
                all_fps.append(f"- [{fp.get('id', '?')}]: {fp.get('reason', '')}")
        except Exception:
            continue

    existing_text = "## Existing IDs (DO NOT DUPLICATE)\n" + ", ".join(sorted(existing_ids))
    fp_text = "## Already Debunked\n" + ("\n".join(all_fps) if all_fps else "None yet.")

    verify_context = ""
    verify_file = Path(f"hunt_session/context/{protocol}/crosschain_verification_{component}.json")
    if verify_file.exists():
        try:
            import json as _json
            vdata = _json.loads(verify_file.read_text())
            verify_context = f"\n## On-Chain Verification (from crosschain_verify.py)\n```json\n{_json.dumps(vdata, indent=2)[:3000]}\n```\n"
        except Exception:
            pass

    contract_src = ""
    if contract_path and contract_path.exists():
        contract_src = contract_path.read_text()
        if len(contract_src) > 60_000:
            contract_src = contract_src[:60_000] + "\n// ... TRUNCATED"

    abbreviation = "".join(w[0] for w in re.findall(r'[A-Z][a-z]*', component)).upper()
    if not abbreviation:
        abbreviation = component[:3].upper()

    hyp_output = str(hyp_dir / f"hyp_{component}_CrossChainHunter.yaml")

    return f"""# CrossChainHunter — {component} Cross-Chain Analysis

## Tu Identidad
Eres el **CrossChainHunter** del equipo de bug hunting de {protocol}.
Analizas vulnerabilidades que SOLO EXISTEN porque el contrato esta desplegado en multiples chains.
Los 9 hunters paralelos ya analizaron el codigo single-chain. Tu trabajo: encontrar lo que se pierde
cuando el mismo contrato vive en {len(chains)} chains distintas.

{deploy_text}

## Contrato
```solidity
{contract_src}
```

## Context de Hunters Relevantes
{hunter_context if hunter_context else "No hay outputs de hunters relevantes aun."}

{verify_context}

{existing_text}

{fp_text}

## Tu Proceso (10 pasos — sigue en orden)

### Paso 1: Deployment Mapping
Documenta el deployment_map completo. Para cada address, registra chain + verified status.

### Paso 2: Signature Replay (CC-1)
Busca EIP-712 domain separators. Para cada uno: incluye block.chainid? Es immutable o dinamico?

### Paso 3: Bridge/Messaging Replay (CC-2)
Solo si componente es bridge: Message ID incluye source chain + dest chain + nonce?

### Paso 4: Config Divergence (CC-3)
Mismo address en N chains: constructor args identicos? Rate limits, thresholds, fees difieren?

### Paso 5: Bytecode Mismatch (CC-4)
Bytecode identico en todas las chains? Si difiere: que cambio?

### Paso 6: Nonce/State Collision (CC-5)
Los nonces incluyen chainId? Una operacion en chain A puede afectar chain B?

### Paso 7: Uninitialized Deployment (CC-6)
Solo para proxies: initialized en todas las chains?

### Paso 8: Proxy Upgrade Desync (CC-7)
Solo para proxies: implementation address identica en todas las chains?

### Paso 9: Cross-Chain State Dependencies (CC-8)
El contrato depende de datos de otra chain? Cual es el max staleness posible?

### Paso 10: L2-Specific Behavior
block.number/timestamp semantica? tx.origin con AA? Gas model asimetrico?

## Output
Escribe en: `{hyp_output}`

**Sin limite artificial de hipotesis.** Genera todas las que tengan confidence >= 60%.
Las 8 categorias (CC-1 a CC-8) son GUIA, no restriccion. category: other si no encaja.

Cada hipotesis DEBE tener:
- `solidity` field (Chimera assertions) — si es fuzzeeable
- O descripcion detallada con verificacion manual — si no es fuzzeeable
- `chains_affected` field
- `confidence` >= 60% para `validated: true`

ID prefix: `{abbreviation}-CC` (ej: {abbreviation}-CC-01)

## Reglas
- NO dupliques IDs o descripciones existentes
- NO repitas false positives ya debunked
- Documenta TODO: si no puedes verificar algo, marca como pending_verification
- Prefiere hipotesis con PoC concreto sobre especulacion teorica
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
    context_dir = get_context_dir(protocol)
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


# =============================================================================
# CROSS-COMPONENT ANALYSIS (Rule 0.5 — Automated)
# =============================================================================

def find_cross_component_pairs(state: dict) -> list[tuple[str, str, list[str]]]:
    """
    Find pairs of completed components that interact with each other.
    Returns list of (comp_a, comp_b, shared_dependencies) tuples.
    """
    done = state.get("components_done", [])
    if len(done) < 2:
        return []

    cmap = {c["name"]: c for c in state.get("component_map", [])}
    pairs = []
    seen = set()

    for comp_a in done:
        info_a = cmap.get(comp_a, {})
        deps_a = set(info_a.get("depends_on", []))

        for comp_b in done:
            if comp_a == comp_b:
                continue
            key = tuple(sorted([comp_a, comp_b]))
            if key in seen:
                continue
            seen.add(key)

            info_b = cmap.get(comp_b, {})
            deps_b = set(info_b.get("depends_on", []))

            # Check if they reference each other
            interactions = []
            if comp_b in deps_a:
                interactions.append(f"{comp_a} imports {comp_b}")
            if comp_a in deps_b:
                interactions.append(f"{comp_b} imports {comp_a}")

            # Check shared dependencies (both depend on same contract)
            shared = deps_a & deps_b
            if shared:
                interactions.append(f"shared deps: {', '.join(shared)}")

            if interactions:
                pairs.append((comp_a, comp_b, interactions))

    return pairs


def generate_cross_component_map(comp_a: str, comp_b: str, repo_path: str, protocol: str) -> str:
    """
    Generate a detailed interaction map between two components using Slither.
    Returns markdown with: cross-calls, shared state, trust assumptions.
    """
    path_a = find_contract(comp_a, repo_path)
    path_b = find_contract(comp_b, repo_path)

    if not path_a or not path_b:
        return f"Could not find contract files for {comp_a} and/or {comp_b}"

    # Use protocol_analyzer to get function details for both
    sys.path.insert(0, str(AUDIT_AGENTS_DIR))
    try:
        from protocol_analyzer import run_layer1_slither
    except ImportError:
        return "protocol_analyzer not available"

    src_dir = str(Path(path_a).parent)
    try:
        all_contracts = run_layer1_slither(src_dir)
    except Exception as e:
        return f"Slither failed: {e}"

    # Find our two contracts
    info_a = next((c for c in all_contracts if comp_a.lower() in c.name.lower()), None)
    info_b = next((c for c in all_contracts if comp_b.lower() in c.name.lower()), None)

    if not info_a or not info_b:
        return f"Could not find {comp_a} and/or {comp_b} in Slither output"

    md = []
    md.append(f"# Cross-Component Interaction Map: {comp_a} ↔ {comp_b}\n")

    # 1. Cross-calls: A calling B's functions
    a_calls_b = []
    b_calls_a = []
    for func in info_a.functions:
        for call in func.external_calls:
            if comp_b.lower() in call.lower():
                a_calls_b.append(f"- `{comp_a}.{func.name}()` → `{call}`")

    for func in info_b.functions:
        for call in func.external_calls:
            if comp_a.lower() in call.lower():
                b_calls_a.append(f"- `{comp_b}.{func.name}()` → `{call}`")

    md.append("## Cross-Calls\n")
    if a_calls_b:
        md.append(f"### {comp_a} → {comp_b}")
        md.extend(a_calls_b)
        md.append("")
    if b_calls_a:
        md.append(f"### {comp_b} → {comp_a}")
        md.extend(b_calls_a)
        md.append("")
    if not a_calls_b and not b_calls_a:
        md.append("No direct cross-calls detected (interaction may be through shared state or intermediary).\n")

    # 2. Shared state: variables that both read or write
    vars_a = {v["name"]: v for v in info_a.state_variables}
    vars_b = {v["name"]: v for v in info_b.state_variables}
    shared_vars = set(vars_a.keys()) & set(vars_b.keys())

    # Also check if A reads state that B writes and vice versa
    a_reads = set()
    a_writes = set()
    b_reads = set()
    b_writes = set()
    for func in info_a.functions:
        a_reads.update(func.reads_state)
        a_writes.update(func.writes_state)
    for func in info_b.functions:
        b_reads.update(func.reads_state)
        b_writes.update(func.writes_state)

    # A writes what B reads (A can influence B's behavior)
    a_influences_b = a_writes & b_reads
    b_influences_a = b_writes & a_reads

    md.append("## Shared & Cross-Influenced State\n")
    if shared_vars:
        md.append(f"**Shared variable names**: {', '.join(sorted(shared_vars))}")
        md.append("")
    if a_influences_b:
        md.append(f"**{comp_a} writes → {comp_b} reads**: {', '.join(sorted(a_influences_b))}")
        md.append(f"  Risk: {comp_a} can manipulate state that {comp_b} trusts")
        md.append("")
    if b_influences_a:
        md.append(f"**{comp_b} writes → {comp_a} reads**: {', '.join(sorted(b_influences_a))}")
        md.append(f"  Risk: {comp_b} can manipulate state that {comp_a} trusts")
        md.append("")
    if not shared_vars and not a_influences_b and not b_influences_a:
        md.append("No shared or cross-influenced state detected.\n")

    # 3. Asymmetric guards: function in A has guard but corresponding call in B doesn't
    md.append("## Guard Comparison\n")
    md.append(f"| Function | Contract | Modifiers | Reentrancy Guard |")
    md.append(f"|----------|----------|-----------|------------------|")
    for func in info_a.functions:
        if func.visibility in ("public", "external") and func.external_calls:
            mods = ", ".join(func.modifiers) if func.modifiers else "NONE"
            guard = "YES" if func.has_reentrancy_guard else "NO"
            md.append(f"| `{func.name}()` | {comp_a} | {mods} | {guard} |")
    for func in info_b.functions:
        if func.visibility in ("public", "external") and func.external_calls:
            mods = ", ".join(func.modifiers) if func.modifiers else "NONE"
            guard = "YES" if func.has_reentrancy_guard else "NO"
            md.append(f"| `{func.name}()` | {comp_b} | {mods} | {guard} |")
    md.append("")

    return "\n".join(md)


def generate_edge_hunter_prompt(
    comp_a: str, comp_b: str, interaction_map: str,
    path_a: Path, path_b: Path, protocol: str,
) -> str:
    """
    Generate a focused EdgeHunter prompt for cross-component analysis.
    Lighter than DeepDive: only cross-call functions + interaction map.
    Looks for bugs that ONLY exist in the interaction between two components.
    """
    # Read ONLY the cross-call functions, not full contracts
    # Parse interaction map to find relevant function names
    cross_funcs_a = set()
    cross_funcs_b = set()
    for line in interaction_map.split("\n"):
        if f"`{comp_a}." in line and "→" in line:
            # Extract function name from `CompA.funcName()` → `call`
            try:
                fname = line.split(f"`{comp_a}.")[1].split("(")[0]
                cross_funcs_a.add(fname)
            except (IndexError, ValueError):
                pass
        if f"`{comp_b}." in line and "→" in line:
            try:
                fname = line.split(f"`{comp_b}.")[1].split("(")[0]
                cross_funcs_b.add(fname)
            except (IndexError, ValueError):
                pass

    # Extract relevant code sections (cross-call functions only + their helpers)
    FUNC_LIMIT = 15_000
    def extract_relevant_functions(path: Path, func_names: set) -> str:
        if not path or not path.exists() or not func_names:
            return path.read_text()[:FUNC_LIMIT] if path and path.exists() else ""
        src = path.read_text()
        # If we can't parse well, return truncated full source
        if len(src) <= FUNC_LIMIT:
            return src
        # Try to extract just the relevant functions
        lines = src.split("\n")
        relevant = []
        in_func = False
        brace_depth = 0
        for i, line in enumerate(lines):
            # Check if this line starts a relevant function
            if any(f"function {fn}" in line for fn in func_names):
                in_func = True
                brace_depth = 0
            if in_func:
                relevant.append(f"{line}")
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0 and "{" in "".join(relevant[-5:]):
                    in_func = False
                    relevant.append("")
        extracted = "\n".join(relevant)
        if extracted and len(extracted) > 200:
            return f"// Cross-call functions extracted from {path.name}\n\n{extracted}"
        return src[:FUNC_LIMIT] + "\n// ... TRUNCATED"

    src_a = extract_relevant_functions(path_a, cross_funcs_a)
    src_b = extract_relevant_functions(path_b, cross_funcs_b)

    abbreviation = f"{comp_a[:2]}{comp_b[:2]}".upper()
    hyp_output = str(get_hyp_dir(protocol) / f"hyp_{comp_a}_{comp_b}_EdgeHunter.yaml")

    # Collect HIGH-CONFIDENCE hypotheses from both components (only cross-relevant)
    hyp_dir = get_hyp_dir(protocol)
    relevant_hyps = []
    for hyp_file in sorted(hyp_dir.glob("hyp_*.yaml")):
        if "template" in hyp_file.name:
            continue
        if comp_a not in hyp_file.name and comp_b not in hyp_file.name:
            continue
        try:
            data = yaml.safe_load(hyp_file.read_text())
            if not data:
                continue
            for inv in data.get("invariants", []):
                desc = inv.get("description", "").lower()
                # Only include hypotheses that mention the OTHER component or cross-component patterns
                other = comp_b if comp_a in hyp_file.name else comp_a
                if (other.lower() in desc or "cross" in desc or "external" in desc
                        or "callback" in desc or "reentran" in desc):
                    relevant_hyps.append(
                        f"[{inv.get('id', '?')}] ({inv.get('confidence', 0)}%): {inv.get('description', '')}"
                    )
        except Exception:
            continue

    hyps_text = ""
    if relevant_hyps:
        hyps_text = "## Cross-Relevant Hypotheses from Individual Hunts\n\n"
        for h in relevant_hyps:
            hyps_text += f"- {h}\n"
        hyps_text += "\nThese are LEADS — investigate but don't duplicate.\n"

    return f"""# EdgeHunter — {comp_a} ↔ {comp_b}

## Tu Identidad
Eres el **EdgeHunter** de {protocol}. Tu ÚNICO objetivo: encontrar bugs que existen
SOLO en la INTERACCIÓN entre {comp_a} y {comp_b}. No buscas bugs dentro de un
componente — eso ya lo hicieron los 9 hunters + DeepDive.

## Interaction Map (Slither)
{interaction_map}

## Código Relevante — {comp_a}
```solidity
{src_a}
```

## Código Relevante — {comp_b}
```solidity
{src_b}
```

{hyps_text}

## Checklist (OBLIGATORIO — en orden)

### 1. Trust Boundaries
Para cada cross-call en el interaction map:
- ¿Qué asume el caller sobre el return value? ¿Puede ser manipulado?
- ¿Hay validaciones que un lado asume pero el otro no enforce?

### 2. State Manipulation Across Components
Para cada cross-influenced state variable:
- ¿Se puede manipular estado en {comp_a} para explotar {comp_b} (o viceversa)?
- ¿Flash loan + secuencia multi-tx extrae valor cruzando ambos?

### 3. Guard Gaps
- ¿Reentrancy guard en uno pero no en el otro para la misma operación?
- ¿Access control bypaseable via path cruzado?

### 4. Atomicity
- ¿Operación multi-step puede quedar a medias entre los dos?
- ¿Front-running de la secuencia cross-component?

## Output
Escribe en: `{hyp_output}`

El YAML DEBE tener estos campos top-level (para merge_invariants.py):
```yaml
hunter: EdgeHunter
component: "{comp_a}_{comp_b}"
invariants:
  - id: {abbreviation}-EH-01
    description: "..."
    solidity: |
      // Chimera assertions referenciando AMBOS contratos
      // Usa crossContractA y crossContractB como addresses
      // Ejemplo: ICompA(crossContractA).balanceOf(...)
    poc_sketch: "..."
    call_stack: "..."
    confidence: 75
    tier: 1
    type: property
```

ID prefix: `{abbreviation}-EH` (ej: {abbreviation}-EH-01)

Cada hipótesis DEBE tener:
- `description`: qué se rompe
- `solidity`: assertions Chimera usando `crossContractA`/`crossContractB` como interface addresses
- `call_stack`: secuencia EXACTA de txs cruzando ambos componentes
- `poc_sketch`: outline de test Foundry con ambos contratos
- `confidence` >= 60%
- `tier`: 1 (hard fail) o 2 (needs review)
- `type`: property (default) u optimize

## Reglas
- SOLO bugs cross-component. Si el ataque funciona con UN solo contrato, no es para ti.
- **Sin límite artificial.** Genera todas las que tengan confidence >= 60%. Calidad > cantidad, pero no cortes artificialmente.
- El interaction map te dice DÓNDE. Tú piensas QUÉ puede salir mal.
"""


def run_cross_component_check(state: dict) -> int:
    """
    Auto-check for cross-component interactions after completing a component.
    Called from --complete. Returns number of pairs found.
    """
    pairs = find_cross_component_pairs(state)
    if not pairs:
        print("  No cross-component interactions detected between completed components.")
        return 0

    protocol = state.get("protocol", "unknown")
    repo_path = state.get("repo_path", "")
    hyp_dir = get_hyp_dir(protocol)

    # Check which pairs already have EdgeHunter output
    new_pairs = []
    for comp_a, comp_b, interactions in pairs:
        edge_file = hyp_dir / f"hyp_{comp_a}_{comp_b}_EdgeHunter.yaml"
        edge_file_rev = hyp_dir / f"hyp_{comp_b}_{comp_a}_EdgeHunter.yaml"
        if not edge_file.exists() and not edge_file_rev.exists():
            new_pairs.append((comp_a, comp_b, interactions))

    if not new_pairs:
        print("  All cross-component pairs already have EdgeHunter analysis.")
        return 0

    print(f"\n{'='*60}")
    print(f"  RULE 0.5: Cross-Component Interactions Detected!")
    print(f"{'='*60}")
    print(f"  {len(new_pairs)} new pair(s) to analyze:\n")

    for comp_a, comp_b, interactions in new_pairs:
        print(f"  → {comp_a} ↔ {comp_b}")
        for inter in interactions:
            print(f"    - {inter}")

    print(f"\n  Generating interaction maps and EdgeHunter prompts...")

    prompts = {}
    for comp_a, comp_b, interactions in new_pairs:
        print(f"\n  Analyzing: {comp_a} ↔ {comp_b}")
        interaction_map = generate_cross_component_map(comp_a, comp_b, repo_path, protocol)

        path_a = find_contract(comp_a, repo_path)
        path_b = find_contract(comp_b, repo_path)

        prompt = generate_edge_hunter_prompt(
            comp_a, comp_b, interaction_map,
            path_a, path_b, protocol,
        )

        prompt_file = get_context_dir(protocol) / f"edge_{comp_a}_{comp_b}.md"
        prompt_file.write_text(prompt)
        prompts[f"{comp_a}↔{comp_b}"] = prompt_file
        print(f"    ✓ EdgeHunter prompt: {prompt_file}")

    # Detect transitive chains: if A↔B and B↔C, generate A→B→C chain hunter
    chain_prompts = _detect_transitive_chains(new_pairs, pairs, protocol, repo_path, hyp_dir)
    prompts.update(chain_prompts)

    print(f"\n  ⚡ Launch EdgeHunters with Agent tool (one per pair/chain):")
    for pair_name, prompt_file in prompts.items():
        print(f'    Agent: Read {prompt_file} and execute the EdgeHunter analysis')

    return len(prompts)


def _detect_transitive_chains(
    new_pairs: list[tuple[str, str, list[str]]],
    all_pairs: list[tuple[str, str, list[str]]],
    protocol: str, repo_path: str, hyp_dir: Path,
) -> dict:
    """
    Detect transitive interaction chains (A↔B + B↔C → A→B→C).
    Returns dict of chain_name → prompt_file for chain EdgeHunters.
    """
    # Build adjacency from ALL pairs (not just new)
    adj: dict[str, set[str]] = {}
    for a, b, _ in all_pairs:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    # Find chains of length 3 (A-B-C where A and C don't interact directly)
    chains = []
    seen = set()
    for mid in adj:
        neighbors = adj[mid]
        if len(neighbors) < 2:
            continue
        for a in neighbors:
            for c in neighbors:
                if a >= c:  # avoid duplicates
                    continue
                if c in adj.get(a, set()):
                    continue  # A↔C exists directly, pair-level EdgeHunter covers it
                key = tuple(sorted([a, mid, c]))
                if key in seen:
                    continue
                seen.add(key)
                chains.append((a, mid, c))

    if not chains:
        return {}

    prompts = {}
    for comp_a, comp_mid, comp_c in chains:
        chain_name = f"{comp_a}→{comp_mid}→{comp_c}"
        chain_file = hyp_dir / f"hyp_{comp_a}_{comp_mid}_{comp_c}_EdgeHunter.yaml"
        if chain_file.exists():
            continue

        print(f"\n  🔗 Transitive chain detected: {chain_name}")

        # Generate maps for both edges
        map_ab = generate_cross_component_map(comp_a, comp_mid, repo_path, protocol)
        map_bc = generate_cross_component_map(comp_mid, comp_c, repo_path, protocol)

        abbreviation = f"{comp_a[:2]}{comp_mid[:2]}{comp_c[:2]}".upper()
        prompt = f"""# EdgeHunter — Transitive Chain: {chain_name}

## Tu Identidad
Eres el **EdgeHunter** de {protocol}. Buscas bugs que SOLO existen cuando
{comp_a}, {comp_mid}, y {comp_c} interactúan en CADENA.

{comp_a} interactúa con {comp_mid}, y {comp_mid} interactúa con {comp_c},
pero {comp_a} y {comp_c} NO interactúan directamente.
Esto crea un path transitivo: un atacante puede manipular {comp_a} → afectar
{comp_mid} → explotar {comp_c} (o al revés).

## Interaction Map: {comp_a} ↔ {comp_mid}
{map_ab}

## Interaction Map: {comp_mid} ↔ {comp_c}
{map_bc}

## Checklist

### 1. Transitive State Manipulation
- ¿Puede un atacante usar {comp_a} para cambiar estado en {comp_mid} que luego
  {comp_c} lee como trusted?
- ¿El path inverso ({comp_c} → {comp_mid} → {comp_a}) también es explotable?

### 2. Trust Chain Breaks
- {comp_c} confía en {comp_mid}. {comp_mid} confía en {comp_a}.
  ¿{comp_a} puede abusar de esta confianza transitiva?

### 3. Multi-Tx Attack Sequences
- ¿Hay una secuencia de 3+ txs que cruza los 3 componentes y extrae valor?
- ¿Flash loan amplifica alguno de estos paths?

## Output
Escribe en: `{chain_file}`

El YAML DEBE tener estos campos top-level:
```yaml
hunter: EdgeHunter
component: "{comp_a}_{comp_mid}_{comp_c}"
invariants:
  - id: {abbreviation}-CH-01
    description: "..."
    solidity: |
      // Usa crossContractA, crossContractB, crossContractC
    call_stack: "..."
    confidence: 70
    tier: 1
    type: property
```

ID prefix: `{abbreviation}-CH` (ej: {abbreviation}-CH-01)

**Sin límite artificial.** Genera todas las que tengan confidence >= 60%. Solo las que necesiten los 3 componentes para el ataque.
"""
        prompt_path = get_context_dir(protocol) / f"edge_chain_{comp_a}_{comp_mid}_{comp_c}.md"
        prompt_path.write_text(prompt)
        prompts[chain_name] = prompt_path
        print(f"    ✓ Chain EdgeHunter prompt: {prompt_path}")

    return prompts


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
    _protocol = state.get("protocol", "unknown")
    hyps = list(get_hyp_dir(_protocol).glob(f"hyp_*.yaml"))
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
    parser.add_argument("--cross-component", action="store_true",
                        help="Ejecutar análisis cross-component (Rule 0.5) manualmente")
    parser.add_argument("--no-solodit", action="store_true", help="Omitir búsqueda en Solodit")
    parser.add_argument("--print-prompts", action="store_true", help="Imprime prompts de hunters a stdout")
    parser.add_argument("--map-components", action="store_true",
                        help="Escanea el repo y genera component_map en current_hunt.json")
    parser.add_argument("--force", action="store_true",
                        help="Regenerar component_map aunque ya exista")
    parser.add_argument("--backfill", action="store_true",
                        help="Solo genera prompts para hunters que NO tienen hyp_*.yaml para el componente")
    args = parser.parse_args()

    state = load_hunt_state()

    if args.status:
        print_status(state)
        return 0

    if args.cross_component:
        n = run_cross_component_check(state)
        if n == 0:
            print("No new cross-component pairs to analyze.")
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

        # Auto-trigger cross-component check (Rule 0.5)
        run_cross_component_check(state)

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
    # Skip prescan if --no-solodit (benchmark mode) to avoid network hangs
    prescan_results = {}
    if not args.no_solodit:
        print(f"\n  Ejecutando pre-scan estático...")
        prescan_results = run_prescan(contract_path, repo_path)
    else:
        print(f"\n  Pre-scan estático: SKIP (--no-solodit mode)")

    # Detection Engine prepass (static + exploit patterns → YAML signals for hunters)
    prepass_signals = ""
    detection_engine = AUDIT_AGENTS_DIR / "detection_engine.py"
    if detection_engine.exists() and contract_path and contract_path.exists():
        print(f"\n  Ejecutando detection_engine --prepass...")
        prepass_out = HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
        prepass_out.parent.mkdir(parents=True, exist_ok=True)
        try:
            src_dir = str(contract_path.parent)
            result = subprocess.run(
                [sys.executable, str(detection_engine), "--prepass",
                 "--source", src_dir, "--name", component,
                 "--output", str(prepass_out.parent)],
                capture_output=True, text=True, timeout=120
            )
            prepass_yaml = prepass_out.parent / f"{component}_prepass.yaml"
            if prepass_yaml.exists():
                prepass_signals = prepass_yaml.read_text()
                n_signals = prepass_signals.count("- title:")
                print(f"  ✓ Detection engine prepass: {n_signals} signals → {prepass_yaml}")
            else:
                print(f"  ⚠ Detection engine: no prepass YAML generated")
        except subprocess.TimeoutExpired:
            print(f"  ⚠ Detection engine timeout (>120s)")
        except Exception as e:
            print(f"  ⚠ Detection engine error: {e}")
    else:
        print(f"\n  Detection engine prepass: SKIP (engine o contrato no encontrado)")

    # [BENCHMARK-IMPROVE-1] Parse prescan results (Slither/Aderyn/Semgrep) into signals
    # and merge with detection_engine prepass signals
    if prescan_results:
        contract_name = contract_path.stem if contract_path else ""
        prescan_signals = parse_prescan_for_hunters(prescan_results, contract_name)
        if prescan_signals:
            n_prescan = prescan_signals.count("- title:")
            print(f"  ✓ Prescan signals parsed: {n_prescan} high-value findings for hunters")
            if prepass_signals:
                prepass_signals = prepass_signals.rstrip() + "\n\n" + prescan_signals
            else:
                prepass_signals = prescan_signals

    # [BENCHMARK-IMPROVE-4] Parameter Boundary Scanner
    # Addresses M-03 (tickSpacing=1 asymmetry) and M-08 (WBTC precision loss)
    boundary_context = ""
    if contract_path and contract_path.exists():
        try:
            from parameter_boundary_scanner import scan_contract, format_for_hunter_prompt
            boundary_result = scan_contract(contract_path)
            boundary_context = format_for_hunter_prompt(boundary_result)
            if boundary_context:
                n_hyps = len(boundary_result.get("hypotheses", []))
                print(f"  ✓ Boundary scanner: {n_hyps} edge-case hypotheses for {boundary_result.get('parameters_found', 0)} params")
                if prepass_signals:
                    prepass_signals = prepass_signals.rstrip() + "\n\n" + boundary_context
                else:
                    prepass_signals = boundary_context
            else:
                print(f"  ✓ Boundary scanner: no edge-case parameters found")
        except ImportError:
            print(f"  ⚠ Boundary scanner: parameter_boundary_scanner.py not found")
        except Exception as e:
            print(f"  ⚠ Boundary scanner error: {e}")

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

    # --backfill: filtrar a solo hunters sin hyp_*.yaml existente
    if args.backfill:
        hyp_dir = get_hyp_dir(protocol)
        existing_hunters = set()
        for hyp_file in hyp_dir.glob(f"hyp_{component}_*.yaml"):
            # Extraer hunter name: hyp_Component_HunterName.yaml
            parts = hyp_file.stem.split("_")
            if len(parts) >= 3:
                hunter_name = parts[-1]
                # Match against known hunter names
                for known in HUNTER_DOMAINS:
                    if known.replace("Hunter", "") == hunter_name.replace("Hunter", ""):
                        existing_hunters.add(known)
        missing = [h for h in selected_hunters if h not in existing_hunters]
        if missing:
            print(f"\n  BACKFILL: {len(existing_hunters)} hunters ya ejecutados, {len(missing)} faltantes")
            for h in existing_hunters:
                print(f"    ✓ {h} (ya existe)")
            selected_hunters = missing
        else:
            print(f"\n  BACKFILL: todos los hunters ya tienen hipótesis para {component}")
            return 0

    print(f"\n  Hunters seleccionados: {', '.join(selected_hunters)}")

    # Generar prompts
    prompts = {}
    for hunter_name in selected_hunters:
        prompts[hunter_name] = generate_hunter_prompt(
            hunter_name, component, contract_path, domain,
            solodit_ctx, briefing_excerpt, protocol,
            prepass_signals=prepass_signals
        )

    if args.print_prompts:
        for name, prompt in prompts.items():
            print(f"\n{'='*60}")
            print(f"PROMPT: {name}")
            print(f"{'='*60}")
            print(prompt[:500] + "...(truncado)")

    # Guardar prompts en context/
    prompts_dir = get_context_dir(protocol)
    for name, prompt in prompts.items():
        prompt_file = prompts_dir / f"{component}_{name}_prompt.md"
        prompt_file.write_text(prompt)

    # Generate CrossChainHunter prompt (conditional on multi-chain)
    cc_prompt = generate_crosschain_prompt(component, contract_path, protocol)
    if cc_prompt:
        cc_prompt_file = prompts_dir / f"{component}_CrossChainHunter_prompt.md"
        cc_prompt_file.write_text(cc_prompt)
        print(f"\n  CrossChainHunter prompt saved: {cc_prompt_file}")
        print(f"  -> Run AFTER 9 hunters, BEFORE DeepDiveHunter")
    else:
        print(f"\n  CrossChainHunter: SKIP (single-chain component)")

    print(f"\n{'='*60}")
    print(f"  LISTO PARA HUNT AUTÓNOMO")
    print(f"{'='*60}")
    print(f"\n  Prompts generados en: hunt_session/context/{protocol}/")
    print(f"  Ficha creada en:      {ficha_path}")
    print(f"  Context en:           {ctx_file}")
    print(f"\n  SIGUIENTE PASO — ejecutar en Claude con Agent tool:")
    print(f"\n  Lanza 6 hunters en paralelo usando:")
    print(f"  Agent(subagent_type='general', prompt=<contenido de cada _prompt.md>)")
    print(f"\n  Cada hunter escribe su resultado en:")
    for h in selected_hunters:
        print(f"    hunt_session/hypotheses/{protocol}/hyp_{component}_{h}.yaml")
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
