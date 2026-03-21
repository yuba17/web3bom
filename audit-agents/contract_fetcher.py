#!/usr/bin/env python3
"""
Contract Fetcher — Download verified contracts from Etherscan/BSCScan/etc.
==========================================================================
Fetches source code of verified contracts from block explorers.

Usage:
    python contract_fetcher.py 0x1234...abcd
    python contract_fetcher.py 0x1234...abcd --chain bsc
    python contract_fetcher.py 0x1234...abcd --chain polygon --output contracts/
"""
import os
import sys
import json
import argparse
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()

EXPLORERS = {
    "eth": {
        "api": "https://api.etherscan.io/api",
        "key_env": "ETHERSCAN_API_KEY",
        "name": "Etherscan",
    },
    "bsc": {
        "api": "https://api.bscscan.com/api",
        "key_env": "BSCSCAN_API_KEY",
        "name": "BscScan",
    },
    "polygon": {
        "api": "https://api.polygonscan.com/api",
        "key_env": "POLYGONSCAN_API_KEY",
        "name": "PolygonScan",
    },
    "arbitrum": {
        "api": "https://api.arbiscan.io/api",
        "key_env": "ARBISCAN_API_KEY",
        "name": "Arbiscan",
    },
    "optimism": {
        "api": "https://api-optimistic.etherscan.io/api",
        "key_env": "OPTIMISM_API_KEY",
        "name": "Optimism Explorer",
    },
    "base": {
        "api": "https://api.basescan.org/api",
        "key_env": "BASESCAN_API_KEY",
        "name": "BaseScan",
    },
    "avalanche": {
        "api": "https://api.snowtrace.io/api",
        "key_env": "SNOWTRACE_API_KEY",
        "name": "SnowTrace",
    },
}


def fetch_contract(address: str, chain: str = "eth", output_dir: str = "contracts") -> list[str]:
    """Fetch verified contract source code from a block explorer."""
    explorer = EXPLORERS.get(chain)
    if not explorer:
        print(f"[ERROR] Unknown chain: {chain}. Available: {', '.join(EXPLORERS.keys())}")
        return []

    api_key = os.getenv(explorer["key_env"], "")
    if not api_key:
        print(f"[WARN] No API key for {explorer['name']}. Set {explorer['key_env']} in .env")
        print(f"[WARN] Proceeding without key (rate limited)...")

    params = {
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
    }
    if api_key:
        params["apikey"] = api_key

    print(f"[*] Fetching {address} from {explorer['name']}...")
    resp = requests.get(explorer["api"], params=params, timeout=30)
    data = resp.json()

    if data.get("status") != "1" or not data.get("result"):
        print(f"[ERROR] {data.get('message', 'Unknown error')}: {data.get('result', '')}")
        return []

    result = data["result"][0]
    contract_name = result.get("ContractName", "Unknown")
    source = result.get("SourceCode", "")
    compiler = result.get("CompilerVersion", "")
    abi_str = result.get("ABI", "")
    implementation = result.get("Implementation", "")

    if not source:
        print(f"[ERROR] Contract not verified or no source code available")
        return []

    print(f"[*] Contract: {contract_name}")
    print(f"[*] Compiler: {compiler}")

    if implementation:
        print(f"[*] Proxy detected! Implementation: {implementation}")
        print(f"[*] Fetching implementation contract...")
        impl_files = fetch_contract(implementation, chain, output_dir)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    saved_files = []

    # Handle multi-file source (Solidity Standard JSON)
    if source.startswith("{{"):
        # Double-braced JSON format from Etherscan
        source = source[1:-1]  # Remove outer braces
        try:
            source_json = json.loads(source)
            sources = source_json.get("sources", {})
            for filename, content in sources.items():
                file_path = out_path / filename.replace("/", os.sep)
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_text(content.get("content", ""), encoding="utf-8")
                saved_files.append(str(file_path))
                print(f"  [+] Saved: {file_path}")
        except json.JSONDecodeError:
            # Fallback to single file
            file_path = out_path / f"{contract_name}.sol"
            file_path.write_text(source, encoding="utf-8")
            saved_files.append(str(file_path))
            print(f"  [+] Saved: {file_path}")
    elif source.startswith("["):
        # Array format (multiple sources)
        try:
            sources = json.loads(source)
            for item in sources:
                if isinstance(item, dict):
                    for filename, content in item.items():
                        file_path = out_path / filename.replace("/", os.sep)
                        file_path.parent.mkdir(parents=True, exist_ok=True)
                        code = content.get("content", content) if isinstance(content, dict) else content
                        file_path.write_text(code, encoding="utf-8")
                        saved_files.append(str(file_path))
                        print(f"  [+] Saved: {file_path}")
        except json.JSONDecodeError:
            file_path = out_path / f"{contract_name}.sol"
            file_path.write_text(source, encoding="utf-8")
            saved_files.append(str(file_path))
    else:
        # Single file source
        file_path = out_path / f"{contract_name}.sol"
        file_path.write_text(source, encoding="utf-8")
        saved_files.append(str(file_path))
        print(f"  [+] Saved: {file_path}")

    # Save ABI
    if abi_str and abi_str != "Contract source code not verified":
        abi_path = out_path / f"{contract_name}.abi.json"
        try:
            abi = json.loads(abi_str)
            abi_path.write_text(json.dumps(abi, indent=2), encoding="utf-8")
            print(f"  [+] ABI saved: {abi_path}")
        except json.JSONDecodeError:
            pass

    # Save metadata
    meta_path = out_path / f"{contract_name}.meta.json"
    meta = {
        "address": address,
        "chain": chain,
        "name": contract_name,
        "compiler": compiler,
        "implementation": implementation or None,
        "files": saved_files,
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"\n[*] Done! {len(saved_files)} file(s) saved to {out_path}/")
    print(f"[*] Run audit: python audit.py {out_path}/")
    return saved_files


def main():
    parser = argparse.ArgumentParser(description="Fetch verified contract source from block explorers")
    parser.add_argument("address", help="Contract address (0x...)")
    parser.add_argument("--chain", "-c", default="eth",
                        choices=list(EXPLORERS.keys()),
                        help="Blockchain (default: eth)")
    parser.add_argument("--output", "-o", default="contracts",
                        help="Output directory (default: contracts/)")
    parser.add_argument("--audit", "-a", action="store_true",
                        help="Auto-run audit after fetching")

    args = parser.parse_args()
    files = fetch_contract(args.address, args.chain, args.output)

    if args.audit and files:
        import subprocess
        for f in files:
            if f.endswith(".sol"):
                print(f"\n{'='*60}")
                print(f"Running audit on {f}...")
                print(f"{'='*60}\n")
                subprocess.run([sys.executable, "audit.py", f])


if __name__ == "__main__":
    main()
