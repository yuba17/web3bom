#!/usr/bin/env python3
"""
Solodit Finding Categorizer
Classifies 50K+ findings into our 12 briefing categories using keyword matching + tag analysis.
Input: knowledge/solodit_all_findings.jsonl
Output: knowledge/solodit_categorized.json (by category, with stats)
        knowledge/solodit_category_index.md (human-readable index)

Usage: python3 solodit_categorize.py [--top N] [--impact HIGH]
"""

import json, sys, re, argparse
from pathlib import Path
from collections import defaultdict, Counter

INPUT_FILE = Path(__file__).parent.parent / "solodit_all_findings.jsonl"
OUTPUT_JSON = Path(__file__).parent.parent / "solodit_categorized.json"
OUTPUT_INDEX = Path(__file__).parent.parent / "solodit_category_index.md"

# Category definitions: name → (keywords in title/content, tag patterns, negative keywords)
CATEGORIES = {
    "vault": {
        "keywords": [
            r"\bvault\b", r"\berc.?4626\b", r"\bshare.?price\b", r"\bshare.?inflation\b",
            r"\bdeposit.*withdraw\b", r"\bwithdraw.*deposit\b", r"\bfirst.?deposit\b",
            r"\bexchange.?rate\b", r"\bconvertToShares\b", r"\bconvertToAssets\b",
            r"\bmint.*redeem\b", r"\bredeem.*mint\b", r"\btotalAssets\b",
            r"\bshare.*manipulat\b", r"\bdonation.?attack\b",
        ],
        "tags": ["erc4626", "vault", "share", "yearn", "beefy"],
        "negative": [r"\boracle.?vault\b"],
    },
    "lending": {
        "keywords": [
            r"\blending\b", r"\bborrow\b", r"\brepay\b", r"\bcollateral\b",
            r"\bliquidat\b", r"\bhealth.?factor\b", r"\bltv\b", r"\bcompound\b",
            r"\baave\b", r"\binterest.?rate\b", r"\binterest.?accrual\b",
            r"\bbad.?debt\b", r"\bunder.?collateral\b", r"\bover.?collateral\b",
            r"\bctoken\b", r"\batoken\b", r"\bdebt.?token\b", r"\bflash.?loan.*lend\b",
            r"\bpool.*borrow\b", r"\bsupply.*rate\b", r"\butilization.?rate\b",
        ],
        "tags": ["lending", "borrow", "compound", "aave", "liquidation", "collateral"],
        "negative": [],
    },
    "oracle": {
        "keywords": [
            r"\boracle\b", r"\bchainlink\b", r"\bprice.?feed\b", r"\btwap\b",
            r"\bstale.?price\b", r"\bprice.?manipulat\b", r"\blatestRoundData\b",
            r"\bsequencer\b", r"\bheartbeat\b", r"\bprice.?deviation\b",
            r"\bgetPrice\b", r"\bpriceFeed\b", r"\bpyth\b", r"\bband\b",
            r"\bredstone\b", r"\bwstETH.*price\b", r"\bstETH.*rate\b",
        ],
        "tags": ["oracle", "chainlink", "price", "twap", "pyth"],
        "negative": [],
    },
    "flash_loan": {
        "keywords": [
            r"\bflash.?loan\b", r"\bflash.?mint\b", r"\bflash.?borrow\b",
            r"\bcallback.*flash\b", r"\bflash.*callback\b", r"\bflash.*attack\b",
            r"\bsame.?block\b", r"\batomic\b", r"\bflash.*manipulat\b",
        ],
        "tags": ["flash", "flashloan", "atomic"],
        "negative": [],
    },
    "access_control": {
        "keywords": [
            r"\baccess.?control\b", r"\bunauthorized\b", r"\bonlyOwner\b",
            r"\brequire.*msg\.sender\b", r"\bmissing.*access\b", r"\bmissing.*auth\b",
            r"\bprivileg\b", r"\brole\b", r"\badmin\b", r"\bowner\b",
            r"\brug.?pull\b", r"\btimelock\b", r"\bgovernance\b", r"\bmulti.?sig\b",
            r"\binitializ\b.*\bunprotect\b", r"\bunprotect\b.*\binitializ\b",
            r"\bdelegatecall\b", r"\barbitrary.?call\b",
        ],
        "tags": ["access", "owner", "admin", "governance", "role", "timelock"],
        "negative": [],
    },
    "dex_amm": {
        "keywords": [
            r"\bamm\b", r"\bdex\b", r"\bswap\b", r"\bliquidity.?pool\b",
            r"\buniswap\b", r"\bsushiswap\b", r"\bcurve\b", r"\bbalancer\b",
            r"\bslippage\b", r"\bsandwich\b", r"\bfront.?run\b",
            r"\bprice.?impact\b", r"\bmin.*amount.*out\b", r"\bdeadline\b",
            r"\bLP\b.*\btoken\b", r"\bimpermanent\b", r"\btick\b.*\brange\b",
            r"\bconcentrated.?liquidity\b", r"\baerrodrome\b", r"\bvelodrome\b",
            r"\bpancakeswap\b", r"\bcamelot\b",
        ],
        "tags": ["dex", "amm", "swap", "uniswap", "curve", "balancer", "slippage", "sandwich"],
        "negative": [],
    },
    "staking": {
        "keywords": [
            r"\bstaking\b", r"\bstake\b", r"\bunstake\b", r"\breward.?distribut\b",
            r"\breward.?rate\b", r"\bepoch\b", r"\bdelegat\b", r"\bvalidator\b",
            r"\brewardPerToken\b", r"\bearned\b", r"\bclaim.*reward\b",
            r"\breward.*claim\b", r"\bboost\b", r"\bgauge\b", r"\bve\b",
            r"\bvoting.?escrow\b", r"\bstaking.*pool\b",
        ],
        "tags": ["staking", "reward", "gauge", "epoch", "validator", "delegation"],
        "negative": [],
    },
    "token": {
        "keywords": [
            r"\berc.?20\b", r"\berc.?721\b", r"\berc.?1155\b", r"\berc.?777\b",
            r"\bfee.?on.?transfer\b", r"\brebasing\b", r"\bdeflation\b",
            r"\bapprove\b.*\brace\b", r"\bpermit\b", r"\btransfer.*hook\b",
            r"\bsafeTransfer\b", r"\bdecimal\b", r"\bblacklist\b",
            r"\bmint\b.*\bburn\b", r"\bburn\b.*\bmint\b",
            r"\btoken.*compat\b", r"\bweird.*token\b",
        ],
        "tags": ["erc20", "erc721", "erc1155", "token", "nft", "permit"],
        "negative": [r"\boracle\b", r"\blending\b"],
    },
    "bridge": {
        "keywords": [
            r"\bbridge\b", r"\bcross.?chain\b", r"\bL1\b.*\bL2\b", r"\bL2\b.*\bL1\b",
            r"\bmessage.?pass\b", r"\brelay\b", r"\brollup\b",
            r"\bchain.?id\b", r"\bnonce.*replay\b", r"\breplay.*nonce\b",
            r"\blayer.?zero\b", r"\bwormhole\b", r"\baxelar\b", r"\bhyperlane\b",
            r"\bsequencer\b.*\bdown\b", r"\bfinality\b",
        ],
        "tags": ["bridge", "crosschain", "l2", "rollup", "relay", "layerzero"],
        "negative": [],
    },
    "proxy_upgrade": {
        "keywords": [
            r"\bproxy\b", r"\bupgrade\b", r"\bdelegatecall\b",
            r"\bstorage.?collision\b", r"\bstorage.?layout\b",
            r"\bUUPS\b", r"\btransparent.?proxy\b", r"\bbeacon\b",
            r"\binitializ\b", r"\b__gap\b", r"\bselfdestruct\b",
            r"\bimplementation\b.*\bslot\b",
        ],
        "tags": ["proxy", "upgrade", "uups", "initializer", "delegatecall"],
        "negative": [],
    },
    "zk_circuits": {
        "keywords": [
            r"\bzk\b", r"\bzero.?knowledge\b", r"\bcircuit\b", r"\bproof\b",
            r"\bverifier\b", r"\bprover\b", r"\bconstraint\b",
            r"\bfiat.?shamir\b", r"\bgroth16\b", r"\bplonk\b", r"\bstark\b",
            r"\bsnark\b", r"\bwitness\b", r"\br1cs\b",
            r"\bmerkle.?proof\b", r"\bcommitment\b",
        ],
        "tags": ["zk", "circuit", "proof", "snark", "stark", "verifier"],
        "negative": [],
    },
    "signature_replay": {
        "keywords": [
            r"\bsignature\b", r"\breplay\b", r"\becrecover\b", r"\bEIP.?712\b",
            r"\bEIP.?191\b", r"\bnonce\b.*\bsign\b", r"\bsign\b.*\bnonce\b",
            r"\bpermit\b", r"\bmalleab\b", r"\bdomain.?separator\b",
            r"\bsigV\b", r"\bsigR\b", r"\bsigS\b", r"\bECDSA\b",
            r"\bisValidSignature\b", r"\bERC.?1271\b",
        ],
        "tags": ["signature", "replay", "ecrecover", "permit", "eip712"],
        "negative": [],
    },
}

def score_finding(finding, cat_config):
    """Score how well a finding matches a category. Returns (score, matched_keywords)."""
    text = f"{finding.get('title', '')} {finding.get('content', '')} {finding.get('summary', '')}".lower()
    tags = [t.lower() for t in finding.get("tags", [])]

    score = 0
    matched = []

    # Keyword matches (title worth 3x, content worth 1x)
    title_lower = finding.get("title", "").lower()
    for kw in cat_config["keywords"]:
        if re.search(kw, title_lower, re.IGNORECASE):
            score += 3
            matched.append(kw)
        elif re.search(kw, text, re.IGNORECASE):
            score += 1
            matched.append(kw)

    # Tag matches (worth 2x each)
    for tag_pattern in cat_config["tags"]:
        for tag in tags:
            if tag_pattern.lower() in tag.lower():
                score += 2
                matched.append(f"tag:{tag}")

    # Negative keywords (penalize)
    for neg in cat_config.get("negative", []):
        if re.search(neg, title_lower, re.IGNORECASE):
            score -= 5

    return score, matched

def categorize_all(findings, min_score=2, top_n=None, impact_filter=None):
    """Categorize all findings. Each finding goes to its best-matching category."""
    categorized = {cat: [] for cat in CATEGORIES}
    categorized["uncategorized"] = []
    stats = Counter()

    for f in findings:
        if impact_filter and f.get("impact", "").upper() != impact_filter.upper():
            continue

        best_cat = None
        best_score = 0
        best_matched = []

        for cat_name, cat_config in CATEGORIES.items():
            score, matched = score_finding(f, cat_config)
            if score > best_score:
                best_score = score
                best_cat = cat_name
                best_matched = matched

        if best_score >= min_score:
            entry = {
                "id": f["id"],
                "title": f["title"],
                "impact": f["impact"],
                "slug": f.get("slug", ""),
                "firm": f.get("firm", ""),
                "protocol": f.get("protocol", ""),
                "score": best_score,
                "matched_keywords": best_matched[:5],
                "summary": f.get("summary", "")[:300],
            }
            categorized[best_cat].append(entry)
            stats[best_cat] += 1
        else:
            categorized["uncategorized"].append({
                "id": f["id"],
                "title": f["title"],
                "impact": f["impact"],
                "best_score": best_score,
            })
            stats["uncategorized"] += 1

    # Sort each category by score descending
    for cat in categorized:
        categorized[cat].sort(key=lambda x: x.get("score", 0), reverse=True)
        if top_n:
            categorized[cat] = categorized[cat][:top_n]

    return categorized, stats

def write_index(categorized, stats, output_path):
    """Write human-readable markdown index."""
    total = sum(stats.values())
    with open(output_path, "w") as f:
        f.write(f"# Solodit Complete Database — Categorized Index\n")
        f.write(f"# Total: {total:,} findings across {len(CATEGORIES)} categories\n")
        f.write(f"# Generated: {__import__('time').strftime('%Y-%m-%d %H:%M')}\n\n")

        f.write("## Summary\n\n")
        f.write("| Category | Findings | % of Total |\n")
        f.write("|----------|----------|------------|\n")
        for cat in list(CATEGORIES.keys()) + ["uncategorized"]:
            count = stats.get(cat, 0)
            pct = (count / total * 100) if total > 0 else 0
            f.write(f"| {cat} | {count:,} | {pct:.1f}% |\n")
        f.write(f"| **TOTAL** | **{total:,}** | **100%** |\n\n")

        for cat_name in CATEGORIES:
            findings = categorized.get(cat_name, [])
            f.write(f"## {cat_name} ({len(findings):,} findings)\n\n")

            # Show top 20 by score
            for i, entry in enumerate(findings[:20]):
                impact = entry.get("impact", "?")
                title = entry.get("title", "untitled")[:100]
                protocol = entry.get("protocol", "")
                firm = entry.get("firm", "")
                score = entry.get("score", 0)
                f.write(f"{i+1}. **[{impact}]** {title}")
                if protocol:
                    f.write(f" — _{protocol}_")
                if firm:
                    f.write(f" ({firm})")
                f.write(f" [score:{score}]\n")

            if len(findings) > 20:
                f.write(f"\n... and {len(findings) - 20:,} more findings\n")
            f.write("\n")

        # Uncategorized
        uncat = categorized.get("uncategorized", [])
        if uncat:
            f.write(f"## uncategorized ({len(uncat):,} findings)\n\n")
            f.write("These findings didn't match any category strongly enough (score < 2).\n")
            f.write("They may need new categories or refined keywords.\n\n")
            # Show sample
            for entry in uncat[:10]:
                f.write(f"- **[{entry.get('impact','')}]** {entry.get('title','')[:100]}\n")
            if len(uncat) > 10:
                f.write(f"\n... and {len(uncat) - 10:,} more\n")

def main():
    parser = argparse.ArgumentParser(description="Categorize Solodit findings")
    parser.add_argument("--top", type=int, default=None, help="Keep only top N per category")
    parser.add_argument("--impact", default=None, help="Filter by impact: HIGH, MEDIUM, LOW")
    parser.add_argument("--min-score", type=int, default=2, help="Minimum match score (default 2)")
    parser.add_argument("--input", default=None, help="Input JSONL file (default: solodit_all_findings.jsonl)")
    args = parser.parse_args()

    input_file = Path(args.input) if args.input else INPUT_FILE
    if not input_file.exists():
        print(f"ERROR: {input_file} not found. Run solodit_download_all.py first.")
        sys.exit(1)

    # Load findings
    print(f"Loading findings from {input_file}...", flush=True)
    findings = []
    with open(input_file) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    print(f"Loaded {len(findings):,} findings", flush=True)

    # Categorize
    print("Categorizing...", flush=True)
    categorized, stats = categorize_all(findings, min_score=args.min_score,
                                         top_n=args.top, impact_filter=args.impact)

    # Save JSON
    with open(OUTPUT_JSON, "w") as f:
        json.dump(categorized, f, indent=1)
    json_size = OUTPUT_JSON.stat().st_size / (1024 * 1024)
    print(f"Saved: {OUTPUT_JSON} ({json_size:.1f} MB)")

    # Save index
    write_index(categorized, stats, OUTPUT_INDEX)
    print(f"Saved: {OUTPUT_INDEX}")

    # Print stats
    print(f"\n{'='*50}")
    total = sum(stats.values())
    for cat in list(CATEGORIES.keys()) + ["uncategorized"]:
        count = stats.get(cat, 0)
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {cat:20s} {count:6,} ({pct:5.1f}%) {bar}")
    print(f"  {'TOTAL':20s} {total:6,}")

if __name__ == "__main__":
    main()
