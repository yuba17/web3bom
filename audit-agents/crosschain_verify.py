#!/usr/bin/env python3
"""
crosschain_verify.py — On-chain verification for CrossChainHunter.

Compares bytecodes, proxy implementations, and storage slots across chains
for multi-chain deployments.

Usage:
    python3 audit-agents/crosschain_verify.py --component <name> [--program <program>]

Output:
    hunt_session/context/{protocol}/crosschain_verification_{component}.json

Requires:
    - ETHERSCAN_API_KEY in .env (for Ethereum)
    - BASESCAN_API_KEY in .env (for Base)
    - ARBISCAN_API_KEY in .env (for Arbitrum)
    - OPTIMISM_API_KEY in .env (for Optimism)
    - POLYGONSCAN_API_KEY in .env (for Polygon)
    - RPC URLs: ETH_RPC_URL, BASE_RPC_URL, etc.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    from web3 import Web3
except ImportError:
    Web3 = None

# ─── Config ──────────────────────────────────────────────────────────────────

CHAIN_CONFIG = {
    "Ethereum": {
        "rpc_env": "ETH_RPC_URL",
        "api_env": "ETHERSCAN_API_KEY",
        "api_url": "https://api.etherscan.io/api",
    },
    "ETH": {
        "rpc_env": "ETH_RPC_URL",
        "api_env": "ETHERSCAN_API_KEY",
        "api_url": "https://api.etherscan.io/api",
    },
    "Base": {
        "rpc_env": "BASE_RPC_URL",
        "api_env": "BASESCAN_API_KEY",
        "api_url": "https://api.basescan.org/api",
    },
    "Arbitrum": {
        "rpc_env": "ARB_RPC_URL",
        "api_env": "ARBISCAN_API_KEY",
        "api_url": "https://api.arbiscan.io/api",
    },
    "Optimism": {
        "rpc_env": "OP_RPC_URL",
        "api_env": "OPTIMISM_API_KEY",
        "api_url": "https://api-optimistic.etherscan.io/api",
    },
    "Polygon": {
        "rpc_env": "POLYGON_RPC_URL",
        "api_env": "POLYGONSCAN_API_KEY",
        "api_url": "https://api.polygonscan.com/api",
    },
}

# EIP-1967 implementation slot
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# OZ initialized slot (slot 0 for most initializable contracts)
INITIALIZED_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"

HUNT_SESSION = Path("hunt_session")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def load_env():
    """Load .env file if exists."""
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def get_web3(chain: str) -> "Web3 | None":
    """Get Web3 instance for a chain."""
    if Web3 is None:
        return None
    config = CHAIN_CONFIG.get(chain)
    if not config:
        return None
    rpc_url = os.environ.get(config["rpc_env"], "")
    if not rpc_url:
        return None
    return Web3(Web3.HTTPProvider(rpc_url))


def get_bytecode(w3: "Web3", address: str) -> str:
    """Get bytecode at address."""
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(address))
        return code.hex()
    except Exception as e:
        return f"ERROR: {e}"


def get_storage_at(w3: "Web3", address: str, slot: str) -> str:
    """Read storage slot."""
    try:
        val = w3.eth.get_storage_at(Web3.to_checksum_address(address), slot)
        return val.hex()
    except Exception as e:
        return f"ERROR: {e}"


def bytecode_hash(bytecode: str) -> str:
    """Hash bytecode for comparison."""
    if bytecode.startswith("ERROR") or bytecode == "0x":
        return bytecode
    return hashlib.sha256(bytes.fromhex(bytecode.replace("0x", ""))).hexdigest()[:16]


def extract_deployments_from_scope_master(component: str, program: str = "") -> list[dict]:
    """Extract deployment table from SCOPE_MASTER.md."""
    # Find SCOPE_MASTER
    scope_masters = list(HUNT_SESSION.glob("context/*/SCOPE_MASTER.md"))
    scope_master = None
    for sm in scope_masters:
        if program and program.lower() in sm.parent.name.lower():
            scope_master = sm
            break
    if not scope_master and scope_masters:
        scope_master = scope_masters[0]
    if not scope_master:
        return []

    text = scope_master.read_text()
    comp_escaped = re.escape(component)
    # Split text into sections by ### headings
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
        deployments.append({
            "name": name,
            "chain": chain,
            "address": address,
        })
    return deployments


# ─── Main ────────────────────────────────────────────────────────────────────

def verify_component(component: str, program: str = ""):
    """Run cross-chain verification for a component."""
    load_env()

    deployments = extract_deployments_from_scope_master(component, program)
    if not deployments:
        print(f"x No deployments found for '{component}' in SCOPE_MASTER")
        return 1

    chains = set(d["chain"] for d in deployments)
    if len(chains) < 2:
        print(f"x Single-chain component ({', '.join(chains)}), nothing to verify")
        return 0

    print(f"CrossChain Verify: {component}")
    print(f"Chains: {', '.join(sorted(chains))}")
    print(f"Deployments: {len(deployments)}")
    print()

    results = {
        "component": component,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "deployments": [],
        "bytecode_match": True,
        "config_diffs": [],
        "implementation_diffs": [],
        "alerts": [],
    }

    bytecode_hashes = {}

    for dep in deployments:
        chain = dep["chain"]
        address = dep["address"]
        name = dep["name"]

        entry = {
            "name": name,
            "chain": chain,
            "address": address,
            "bytecode_hash": "pending",
            "is_proxy": False,
            "implementation": None,
            "initialized_slot_0": "pending",
        }

        w3 = get_web3(chain)
        if w3 is None:
            entry["bytecode_hash"] = "NO_RPC"
            entry["initialized_slot_0"] = "NO_RPC"
            results["deployments"].append(entry)
            print(f"  [{chain}] {name} ({address[:10]}...): NO RPC configured")
            continue

        # Get bytecode
        code = get_bytecode(w3, address)
        bhash = bytecode_hash(code)
        entry["bytecode_hash"] = bhash

        # Check if proxy (read implementation slot)
        impl = get_storage_at(w3, address, IMPLEMENTATION_SLOT)
        if impl and impl != "0x" + "0" * 64 and not impl.startswith("ERROR"):
            impl_addr = "0x" + impl[-40:]
            entry["is_proxy"] = True
            entry["implementation"] = impl_addr
            # Get implementation bytecode too
            impl_code = get_bytecode(w3, impl_addr)
            entry["implementation_bytecode_hash"] = bytecode_hash(impl_code)

        # Read slot 0 (initialized)
        slot0 = get_storage_at(w3, address, INITIALIZED_SLOT)
        entry["initialized_slot_0"] = slot0

        results["deployments"].append(entry)

        # Track for comparison
        key = name
        if key not in bytecode_hashes:
            bytecode_hashes[key] = []
        bytecode_hashes[key].append((chain, bhash, entry.get("implementation_bytecode_hash")))

        status = "PROXY" if entry["is_proxy"] else "EOA/CONTRACT"
        print(f"  [{chain}] {name}: {bhash} ({status})")
        time.sleep(0.2)  # Rate limit

    # Compare bytecodes
    for name, entries in bytecode_hashes.items():
        hashes = set(h for _, h, _ in entries if not h.startswith("ERROR") and h != "NO_RPC")
        if len(hashes) > 1:
            results["bytecode_match"] = False
            chains_by_hash = {}
            for chain, h, _ in entries:
                chains_by_hash.setdefault(h, []).append(chain)
            alert = f"BYTECODE_MISMATCH: {name} — {len(hashes)} different versions: "
            alert += ", ".join(f"{h[:8]}({','.join(cs)})" for h, cs in chains_by_hash.items())
            results["alerts"].append(alert)
            print(f"\n  ALERT: {alert}")

        # Compare implementation bytecodes (for proxies)
        impl_hashes = set(h for _, _, h in entries if h and not h.startswith("ERROR"))
        if len(impl_hashes) > 1:
            alert = f"IMPLEMENTATION_MISMATCH: {name} — proxy points to different implementations"
            results["implementation_diffs"].append(alert)
            results["alerts"].append(alert)
            print(f"\n  ALERT: {alert}")

    # Save output
    protocol = program or "unknown"
    # Try to find protocol from scope master path
    for sm in HUNT_SESSION.glob("context/*/SCOPE_MASTER.md"):
        if program and program.lower() in sm.parent.name.lower():
            protocol = sm.parent.name
            break

    output_dir = HUNT_SESSION / "context" / protocol
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"crosschain_verification_{component}.json"
    output_file.write_text(json.dumps(results, indent=2))

    print(f"\nResults saved: {output_file}")
    if results["alerts"]:
        print(f"\n{len(results['alerts'])} ALERTS — review before CrossChainHunter")
    else:
        print(f"\nNo alerts — all deployments appear consistent")

    return 0


def main():
    parser = argparse.ArgumentParser(description="Cross-chain deployment verification")
    parser.add_argument("--component", "-c", required=True, help="Component name (as in SCOPE_MASTER)")
    parser.add_argument("--program", "-p", default="", help="Program name (for SCOPE_MASTER lookup)")
    args = parser.parse_args()

    sys.exit(verify_component(args.component, args.program))


if __name__ == "__main__":
    main()
