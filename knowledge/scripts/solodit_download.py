#!/usr/bin/env python3
"""
Solodit Bulk Findings Downloader
Downloads vulnerability findings from Solodit API and saves to JSON.
Usage: python3 solodit_download.py [--keywords "flash loan"] [--impact HIGH] [--pages 5]
Requires: CYFRIN_API_KEY in .env or environment
"""

import json, time, os, sys, argparse
import urllib.request
from pathlib import Path

def load_api_key():
    key = os.environ.get("CYFRIN_API_KEY")
    if key:
        return key
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith("CYFRIN_API_KEY="):
                return line.split("=", 1)[1].strip()
    print("ERROR: Set CYFRIN_API_KEY in .env or environment")
    sys.exit(1)

def search(api_key, keywords, impact=None, page=1, page_size=20):
    url = "https://solodit.cyfrin.io/api/v1/solodit/findings"
    filters = {"keywords": keywords, "sortField": "Quality", "sortDirection": "Desc"}
    if impact:
        filters["impact"] = impact if isinstance(impact, list) else [impact]
    payload = json.dumps({"page": page, "pageSize": page_size, "filters": filters}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('X-Cyfrin-API-Key', api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return {"findings": []}

def main():
    parser = argparse.ArgumentParser(description="Download Solodit findings")
    parser.add_argument("--keywords", default=None, help="Search keywords")
    parser.add_argument("--impact", default="HIGH", help="Impact filter: HIGH, MEDIUM, LOW")
    parser.add_argument("--pages", type=int, default=5, help="Number of pages to fetch")
    parser.add_argument("--output", default=None, help="Output JSON file")
    parser.add_argument("--all-categories", action="store_true", help="Download all predefined categories")
    args = parser.parse_args()

    api_key = load_api_key()

    if args.all_categories:
        categories = {
            "vault": ["ERC4626 vault inflation", "vault donation exchange rate", "vault rounding"],
            "lending": ["lending liquidation bad debt", "borrow interest accrual", "health factor collateral", "CompoundV2 inflation"],
            "oracle": ["Chainlink stale price", "TWAP manipulation", "oracle manipulation flash loan", "read-only reentrancy oracle", "sequencer L2"],
            "flash_loan": ["flash loan attack", "flash loan callback", "flash mint"],
            "access_control": ["missing access control", "arbitrary call delegatecall", "unprotected initialize"],
            "dex_amm": ["AMM swap slippage", "DEX manipulation", "sandwich frontrunning"],
            "staking": ["staking reward precision", "reward distribution", "stake timing"],
            "token": ["fee-on-transfer token", "rebasing token", "ERC20 approve", "token self-transfer"],
            "bridge": ["bridge message replay", "cross-chain nonce", "L2 sequencer"],
            "proxy": ["proxy storage collision", "uninitialized implementation", "UUPS upgrade"],
            "zk": ["zero knowledge circuit", "ZK proof soundness", "range check circuit"],
            "signature": ["signature replay EIP712", "ecrecover malleability", "permit deadline"],
        }

        all_findings = {}
        total = 0
        request_count = 0

        for cat, kw_list in categories.items():
            all_findings[cat] = []
            seen_ids = set()
            for kw in kw_list:
                if request_count > 0 and request_count % 18 == 0:
                    print(f"  Rate limit pause...", flush=True)
                    time.sleep(62)
                result = search(api_key, kw, [args.impact], page_size=20)
                request_count += 1
                for f in result.get("findings", []):
                    fid = f.get("id", "")
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        all_findings[cat].append({
                            "id": fid, "title": f.get("title", ""),
                            "impact": f.get("impact", ""),
                            "content": f.get("content", "")[:2000],
                        })
                        total += 1
                time.sleep(3.5)
            print(f"{cat}: {len(all_findings[cat])}", flush=True)

        outpath = args.output or str(Path(__file__).parent.parent / "solodit_bulk_findings.json")
        with open(outpath, 'w') as f:
            json.dump(all_findings, f, indent=2)
        print(f"\nTotal: {total} → {outpath}")

    elif args.keywords:
        all_findings = []
        seen_ids = set()
        for page in range(1, args.pages + 1):
            result = search(api_key, args.keywords, [args.impact], page=page)
            for f in result.get("findings", []):
                fid = f.get("id", "")
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    all_findings.append({
                        "id": fid, "title": f.get("title", ""),
                        "impact": f.get("impact", ""),
                        "content": f.get("content", "")[:3000],
                    })
            print(f"Page {page}: {len(result.get('findings', []))} results", flush=True)
            time.sleep(3.5)

        outpath = args.output or "/tmp/solodit_search.json"
        with open(outpath, 'w') as f:
            json.dump(all_findings, f, indent=2)
        print(f"\nTotal: {len(all_findings)} → {outpath}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
