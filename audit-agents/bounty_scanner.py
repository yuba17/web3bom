#!/usr/bin/env python3
"""
Bounty Scanner — Multi-platform bug bounty aggregator and scorer.
=================================================================
Fetches active bug bounty programs from Code4rena, Immunefi, and Cantina,
scores them using a weighted heuristic system, and outputs a ranked table.

Usage:
    python bounty_scanner.py
    python bounty_scanner.py --min-bounty 100000
    python bounty_scanner.py --platform immunefi
    python bounty_scanner.py --lang solidity --top 20
    python bounty_scanner.py --refresh          # force re-fetch (skip cache)

Requirements:
    pip install requests beautifulsoup4 rich
"""

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

console = Console()

CACHE_DIR = Path(__file__).resolve().parent / "reports"
CACHE_FILE = CACHE_DIR / "bounty_scanner_cache.json"
OUTPUT_FILE = CACHE_DIR / "bounty_scanner_results.json"
CACHE_TTL_HOURS = 6

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Known fork projects (lowercased protocol names that are forks of major protocols)
KNOWN_FORKS = {
    "sushiswap", "pancakeswap", "quickswap", "spookyswap", "trader joe",
    "camelot", "baseswap", "aerodrome", "velodrome", "ramses",
    "radiant", "granary", "seamless", "moonwell", "benqi", "venus",
    "ironbank", "cream", "hundred finance", "agave", "geist",
    "beefy", "yearn", "harvest", "pickle finance",
    "synapse", "multichain", "stargate",
}

# Category-to-complexity mapping (heuristic baseline)
CATEGORY_COMPLEXITY = {
    "bridge": 0.85, "cross-chain": 0.85,
    "lending": 0.75, "cdp": 0.75,
    "perps": 0.80, "derivatives": 0.80, "options": 0.80,
    "dex": 0.60, "amm": 0.60,
    "staking": 0.50, "restaking": 0.70,
    "oracle": 0.70,
    "l2": 0.65, "rollup": 0.65,
    "nft": 0.35, "gaming": 0.40,
    "dao": 0.45, "governance": 0.45,
    "yield": 0.65, "vault": 0.60,
    "stablecoin": 0.70,
    "insurance": 0.65,
    "payments": 0.40,
    "wallet": 0.45,
    "infrastructure": 0.55,
    "defi": 0.65,  # generic
}

# Language detection keywords
LANGUAGE_KEYWORDS = {
    "solidity": ["solidity", "evm", "ethereum", "polygon", "arbitrum",
                 "optimism", "bsc", "avalanche", "base", "scroll",
                 "linea", "zksync", "fantom", "gnosis", "celo", "mantle"],
    "rust": ["rust", "solana", "anchor", "near", "sui", "aptos"],
    "cosmwasm": ["cosmwasm", "cosmos", "terra", "osmosis", "injective", "sei"],
    "cairo": ["cairo", "starknet"],
    "vyper": ["vyper"],
    "move": ["move", "sui", "aptos"],
    "huff": ["huff"],
}

# ---------------------------------------------------------------------------
# Data fetching — Immunefi
# ---------------------------------------------------------------------------


def _extract_next_data(html: str) -> list[dict]:
    """Parse Next.js streamed data from __next_f.push() calls."""
    results = []
    # Find all self.__next_f.push() payloads
    pattern = re.compile(r'self\.__next_f\.push\(\s*\[.*?,\s*"(.*?)"\s*\]\s*\)', re.DOTALL)
    for match in pattern.finditer(html):
        chunk = match.group(1)
        # Unescape
        chunk = chunk.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
        results.append(chunk)
    return results


def fetch_immunefi(session: requests.Session) -> list[dict]:
    """Fetch active bounty programs from Immunefi."""
    programs = []
    try:
        resp = session.get("https://immunefi.com/bug-bounty/", headers=HEADERS, timeout=20)
        resp.raise_for_status()
        html = resp.text

        # Strategy 1: parse embedded Next.js data chunks for bounty objects
        chunks = _extract_next_data(html)
        combined = "\n".join(chunks)

        # Extract bounty entries using regex over the combined serialized data
        # Look for patterns like "project":"Name" ... "maxBounty":123456
        bounty_pattern = re.compile(
            r'"project"\s*:\s*"([^"]+)".*?"maxBounty"\s*:\s*(\d+)'
            r'(?:.*?"tags"\s*:\s*\{[^}]*"language"\s*:\s*\[([^\]]*)\])?',
            re.DOTALL,
        )
        seen = set()
        for m in bounty_pattern.finditer(combined):
            name = m.group(1)
            if name in seen:
                continue
            seen.add(name)
            max_bounty = int(m.group(2))
            lang_raw = m.group(3) or ""
            languages = [l.strip().strip('"') for l in lang_raw.split(",") if l.strip()]

            programs.append({
                "name": name,
                "platform": "Immunefi",
                "max_bounty": max_bounty,
                "languages": languages if languages else _guess_languages(name, ""),
                "category": "",
                "url": f"https://immunefi.com/bug-bounty/{name.lower().replace(' ', '')}/",
                "prior_audits": None,
                "loc": None,
                "is_fork": _is_fork(name),
                "description": "",
            })

        # Strategy 2: fallback — parse visible HTML
        if not programs:
            soup = BeautifulSoup(html, "html.parser")
            # Try to find bounty cards/rows
            for link in soup.find_all("a", href=re.compile(r"/bug-bounty/\w+")):
                href = link.get("href", "")
                slug = href.rstrip("/").split("/")[-1]
                text = link.get_text(separator=" ", strip=True)
                # Try to find bounty amount nearby
                amount = _extract_amount(text)
                name = slug.replace("-", " ").title()
                if name and name not in seen:
                    seen.add(name)
                    programs.append({
                        "name": name,
                        "platform": "Immunefi",
                        "max_bounty": amount or 0,
                        "languages": _guess_languages(name, text),
                        "category": "",
                        "url": f"https://immunefi.com{href}",
                        "prior_audits": None,
                        "loc": None,
                        "is_fork": _is_fork(name),
                        "description": text[:200],
                    })

    except Exception as e:
        console.print(f"[yellow]Immunefi fetch error: {e}[/yellow]")

    # Strategy 3: hardcoded high-value programs as baseline
    if len(programs) < 5:
        console.print("[dim]Using curated Immunefi program list as fallback.[/dim]")
        programs = _immunefi_fallback()

    return programs


def _immunefi_fallback() -> list[dict]:
    """Curated list of top Immunefi programs (updated periodically)."""
    raw = [
        ("LayerZero", 15_000_000, ["solidity"], "bridge"),
        ("Wormhole", 10_000_000, ["solidity", "rust"], "bridge"),
        ("MakerDAO", 10_000_000, ["solidity"], "cdp"),
        ("GMX", 5_000_000, ["solidity"], "perps"),
        ("Uniswap", 3_000_000, ["solidity"], "dex"),
        ("Olympus DAO", 3_300_000, ["solidity"], "defi"),
        ("EigenLayer", 2_000_000, ["solidity"], "restaking"),
        ("Lido", 2_000_000, ["solidity"], "staking"),
        ("Optimism", 2_000_000, ["solidity"], "l2"),
        ("Arbitrum", 2_000_000, ["solidity"], "l2"),
        ("Polygon", 2_000_000, ["solidity"], "l2"),
        ("Synthetix", 2_000_000, ["solidity"], "derivatives"),
        ("dYdX", 2_000_000, ["solidity"], "perps"),
        ("Balancer", 1_000_000, ["solidity"], "dex"),
        ("Scroll", 1_000_000, ["solidity"], "l2"),
        ("Morpho", 555_000, ["solidity"], "lending"),
        ("Chainlink", 500_000, ["solidity"], "oracle"),
        ("Compound", 500_000, ["solidity"], "lending"),
        ("Pendle", 500_000, ["solidity"], "yield"),
        ("Curve Finance", 250_000, ["solidity", "vyper"], "dex"),
        ("Aave", 250_000, ["solidity"], "lending"),
        ("1inch", 200_000, ["solidity"], "dex"),
        ("Sommelier", 250_000, ["solidity", "rust"], "vault"),
        ("Euler", 200_000, ["solidity"], "lending"),
        ("Etherfi", 250_000, ["solidity"], "restaking"),
        ("Renzo", 250_000, ["solidity"], "restaking"),
        ("Across Protocol", 500_000, ["solidity"], "bridge"),
        ("Puffer Finance", 200_000, ["solidity"], "restaking"),
    ]
    return [
        {
            "name": name,
            "platform": "Immunefi",
            "max_bounty": bounty,
            "languages": langs,
            "category": cat,
            "url": f"https://immunefi.com/bug-bounty/{name.lower().replace(' ', '').replace('-', '')}/",
            "prior_audits": None,
            "loc": None,
            "is_fork": _is_fork(name),
            "description": "",
        }
        for name, bounty, langs, cat in raw
    ]


# ---------------------------------------------------------------------------
# Data fetching — Code4rena
# ---------------------------------------------------------------------------


def fetch_code4rena(session: requests.Session) -> list[dict]:
    """Fetch active bounty programs from Code4rena."""
    programs = []
    try:
        resp = session.get("https://code4rena.com/bounties", headers=HEADERS, timeout=20)
        resp.raise_for_status()
        html = resp.text

        # Try to extract Next.js data
        chunks = _extract_next_data(html)
        combined = "\n".join(chunks)

        # Look for bounty objects in serialized data
        # Pattern: "title":"...", "max_bounty":... or similar
        title_pat = re.compile(
            r'"title"\s*:\s*"([^"]{2,80})".*?"max_bounty"\s*:\s*"?(\d+)"?',
            re.DOTALL,
        )
        seen = set()
        for m in title_pat.finditer(combined):
            name = m.group(1)
            if name in seen or len(name) > 60:
                continue
            seen.add(name)
            max_bounty = int(m.group(2))
            programs.append({
                "name": name,
                "platform": "Code4rena",
                "max_bounty": max_bounty,
                "languages": _guess_languages(name, ""),
                "category": "",
                "url": f"https://code4rena.com/bounties",
                "prior_audits": None,
                "loc": None,
                "is_fork": _is_fork(name),
                "description": "",
            })

        # Fallback: parse HTML directly
        if not programs:
            soup = BeautifulSoup(html, "html.parser")
            # Look for bounty cards
            cards = soup.find_all("div", class_=re.compile(r"bounty|card|program", re.I))
            for card in cards:
                text = card.get_text(separator=" ", strip=True)
                name_el = card.find(["h2", "h3", "h4", "a"])
                if name_el:
                    name = name_el.get_text(strip=True)
                    if name and len(name) < 60 and name not in seen:
                        seen.add(name)
                        amount = _extract_amount(text)
                        programs.append({
                            "name": name,
                            "platform": "Code4rena",
                            "max_bounty": amount or 0,
                            "languages": _guess_languages(name, text),
                            "category": "",
                            "url": f"https://code4rena.com/bounties",
                            "prior_audits": None,
                            "loc": None,
                            "is_fork": _is_fork(name),
                            "description": text[:200],
                        })

    except Exception as e:
        console.print(f"[yellow]Code4rena fetch error: {e}[/yellow]")

    if len(programs) < 3:
        console.print("[dim]Using curated Code4rena program list as fallback.[/dim]")
        programs = _code4rena_fallback()

    return programs


def _code4rena_fallback() -> list[dict]:
    """Curated Code4rena bounties fallback."""
    raw = [
        ("Blast", 1_000_000, ["solidity"], "l2"),
        ("Open Dollar", 200_000, ["solidity"], "cdp"),
        ("PoolTogether", 200_000, ["solidity"], "defi"),
        ("Badger DAO", 250_000, ["solidity"], "vault"),
        ("ENS", 250_000, ["solidity"], "infrastructure"),
        ("Safe", 500_000, ["solidity"], "wallet"),
        ("Nexus Mutual", 200_000, ["solidity"], "insurance"),
        ("Nouns DAO", 100_000, ["solidity"], "dao"),
    ]
    return [
        {
            "name": name,
            "platform": "Code4rena",
            "max_bounty": bounty,
            "languages": langs,
            "category": cat,
            "url": "https://code4rena.com/bounties",
            "prior_audits": None,
            "loc": None,
            "is_fork": _is_fork(name),
            "description": "",
        }
        for name, bounty, langs, cat in raw
    ]


# ---------------------------------------------------------------------------
# Data fetching — Cantina
# ---------------------------------------------------------------------------


def fetch_cantina(session: requests.Session) -> list[dict]:
    """Fetch active bounty programs from Cantina."""
    programs = []
    try:
        resp = session.get("https://cantina.xyz/bounties", headers=HEADERS, timeout=20)
        resp.raise_for_status()
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")

        # Cantina lists bounties in card-like elements
        # Try to find program entries from the page text
        text_content = soup.get_text(separator="\n", strip=True)

        # Also try embedded data
        chunks = _extract_next_data(html)
        combined = "\n".join(chunks)

        # Parse JSON-like bounty objects from script data
        name_pat = re.compile(
            r'"(?:name|title|project)"\s*:\s*"([^"]{2,60})"'
            r'.*?"(?:totalPayout|maxPayout|prize|reward)"\s*:\s*"?(\d[\d,]*)"?',
            re.DOTALL,
        )
        seen = set()
        for m in name_pat.finditer(combined):
            name = m.group(1)
            amount_str = m.group(2).replace(",", "")
            if name in seen or not amount_str.isdigit():
                continue
            seen.add(name)
            programs.append({
                "name": name,
                "platform": "Cantina",
                "max_bounty": int(amount_str),
                "languages": _guess_languages(name, ""),
                "category": "",
                "url": "https://cantina.xyz/bounties",
                "prior_audits": None,
                "loc": None,
                "is_fork": _is_fork(name),
                "description": "",
            })

    except Exception as e:
        console.print(f"[yellow]Cantina fetch error: {e}[/yellow]")

    if len(programs) < 3:
        console.print("[dim]Using curated Cantina program list as fallback.[/dim]")
        programs = _cantina_fallback()

    return programs


def _cantina_fallback() -> list[dict]:
    """Curated Cantina bounties fallback."""
    raw = [
        ("Uniswap Labs", 15_500_000, ["solidity"], "dex"),
        ("Euler", 7_500_000, ["solidity"], "lending"),
        ("Coinbase", 5_000_000, ["solidity"], "infrastructure"),
        ("Morpho", 2_500_000, ["solidity"], "lending"),
        ("Pendle Finance", 2_000_000, ["solidity"], "yield"),
        ("Yearn Finance", 1_000_000, ["solidity"], "vault"),
        ("Frax Finance", 500_000, ["solidity"], "stablecoin"),
        ("Ribbon Finance", 250_000, ["solidity"], "vault"),
    ]
    return [
        {
            "name": name,
            "platform": "Cantina",
            "max_bounty": bounty,
            "languages": langs,
            "category": cat,
            "url": "https://cantina.xyz/bounties",
            "prior_audits": None,
            "loc": None,
            "is_fork": _is_fork(name),
            "description": "",
        }
        for name, bounty, langs, cat in raw
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_amount(text: str) -> Optional[int]:
    """Pull a dollar amount from text like '$1,500,000' or '1.5M'."""
    # Match $X,XXX,XXX or $X.XM patterns
    m = re.search(r'\$\s*([\d,]+(?:\.\d+)?)\s*([MmKk])?', text)
    if m:
        num = float(m.group(1).replace(",", ""))
        suffix = (m.group(2) or "").upper()
        if suffix == "M":
            num *= 1_000_000
        elif suffix == "K":
            num *= 1_000
        return int(num)

    # Match plain large numbers near bounty-related words
    m = re.search(r'(\d{1,3}(?:,\d{3})+)', text)
    if m:
        return int(m.group(1).replace(",", ""))

    return None


def _guess_languages(name: str, description: str) -> list[str]:
    """Guess smart contract languages from protocol name and description."""
    combined = f"{name} {description}".lower()
    detected = []
    for lang, keywords in LANGUAGE_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            detected.append(lang)
    return detected if detected else ["solidity"]  # default assumption


def _is_fork(name: str) -> bool:
    """Check if a protocol is a known fork."""
    return name.lower().strip() in KNOWN_FORKS


def _infer_category(program: dict) -> str:
    """Infer category from name/description if not already set."""
    if program.get("category"):
        return program["category"]

    combined = f"{program['name']} {program.get('description', '')}".lower()
    category_hints = {
        "bridge": ["bridge", "cross-chain", "messaging", "relay"],
        "lending": ["lend", "borrow", "money market", "interest rate"],
        "dex": ["swap", "exchange", "amm", "liquidity pool", "dex"],
        "perps": ["perpetual", "perps", "futures", "margin"],
        "staking": ["stake", "staking", "validator", "delegation"],
        "restaking": ["restake", "restaking", "eigen"],
        "l2": ["rollup", "layer 2", "l2", "sequencer", "zk-proof"],
        "oracle": ["oracle", "price feed", "data feed"],
        "cdp": ["cdp", "collateral debt", "stablecoin mint"],
        "vault": ["vault", "yield", "strategy", "aggregat"],
        "nft": ["nft", "collectible", "marketplace"],
        "dao": ["dao", "governance", "voting"],
        "insurance": ["insurance", "cover", "claims"],
        "stablecoin": ["stablecoin", "peg", "stable coin"],
        "wallet": ["wallet", "multisig", "safe"],
        "infrastructure": ["infra", "node", "rpc", "indexer"],
    }
    for cat, hints in category_hints.items():
        if any(h in combined for h in hints):
            return cat
    return "defi"


# ---------------------------------------------------------------------------
# Scoring system
# ---------------------------------------------------------------------------


def score_program(program: dict) -> dict:
    """
    Score a bounty program on five dimensions (each 0.0 - 1.0):

    1. Novel Code Density (NCD)   — estimated originality of codebase
    2. Audit Gap (AG)             — lack of prior audits = more opportunity
    3. Mechanism Complexity (MC)  — protocol complexity = more bugs
    4. Bounty Economics (BE)      — reward per expected effort
    5. Competition Level (CL)     — inverse of expected competitor count

    Final score = weighted average * 100
    """
    name_lower = program["name"].lower()
    cat = program.get("category", "defi")

    # --- 1. Novel Code Density (0.0 - 1.0) ---
    # Fork => low novelty; newer/unique protocols => higher
    if program.get("is_fork"):
        ncd = 0.20
    elif program.get("loc") and program["loc"] > 5000:
        ncd = 0.75  # large codebase likely has novel components
    else:
        ncd = 0.60  # default: moderate novelty assumed

    # Boost for categories that tend to have novel mechanisms
    if cat in ("bridge", "restaking", "derivatives", "perps", "cdp"):
        ncd = min(1.0, ncd + 0.15)

    # --- 2. Audit Gap (0.0 - 1.0) ---
    prior = program.get("prior_audits")
    if prior is None:
        # Unknown = assume moderate gap
        ag = 0.55
    elif prior == 0:
        ag = 1.0  # unaudited = maximum opportunity
    elif prior <= 2:
        ag = 0.65
    elif prior <= 5:
        ag = 0.40
    else:
        ag = 0.20  # heavily audited

    # --- 3. Mechanism Complexity (0.0 - 1.0) ---
    mc = CATEGORY_COMPLEXITY.get(cat, 0.55)
    # Multi-language programs are more complex
    if len(program.get("languages", [])) > 1:
        mc = min(1.0, mc + 0.10)

    # --- 4. Bounty Economics (0.0 - 1.0) ---
    bounty = program.get("max_bounty", 0)
    if bounty >= 10_000_000:
        be = 1.00
    elif bounty >= 5_000_000:
        be = 0.90
    elif bounty >= 2_000_000:
        be = 0.80
    elif bounty >= 1_000_000:
        be = 0.70
    elif bounty >= 500_000:
        be = 0.55
    elif bounty >= 200_000:
        be = 0.40
    elif bounty >= 100_000:
        be = 0.30
    elif bounty >= 50_000:
        be = 0.20
    else:
        be = 0.10

    # --- 5. Competition Level (0.0 - 1.0, higher = less competition = better) ---
    # Heuristic: bigger bounties attract more competition
    # Platform matters: Immunefi has more traffic than Cantina
    platform = program.get("platform", "")
    if bounty >= 5_000_000:
        cl = 0.25  # very high competition
    elif bounty >= 1_000_000:
        cl = 0.40
    elif bounty >= 500_000:
        cl = 0.55
    elif bounty >= 200_000:
        cl = 0.65
    else:
        cl = 0.80  # low competition

    # Cantina tends to have fewer researchers
    if platform == "Cantina":
        cl = min(1.0, cl + 0.10)
    # Code4rena bounties tend to be less crowded than Immunefi
    elif platform == "Code4rena":
        cl = min(1.0, cl + 0.05)

    # Less common languages attract fewer auditors
    langs = program.get("languages", [])
    if any(l in langs for l in ("rust", "cosmwasm", "cairo", "move", "huff")):
        cl = min(1.0, cl + 0.15)
    if "vyper" in langs:
        cl = min(1.0, cl + 0.10)

    # --- Weighted composite ---
    weights = {
        "novel_code_density": 0.20,
        "audit_gap": 0.20,
        "mechanism_complexity": 0.20,
        "bounty_economics": 0.25,
        "competition_level": 0.15,
    }

    scores = {
        "novel_code_density": round(ncd, 2),
        "audit_gap": round(ag, 2),
        "mechanism_complexity": round(mc, 2),
        "bounty_economics": round(be, 2),
        "competition_level": round(cl, 2),
    }

    composite = sum(scores[k] * weights[k] for k in weights)
    scores["composite"] = round(composite * 100, 1)

    return scores


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


def _load_cache() -> Optional[dict]:
    """Load cached results if fresh enough."""
    if not CACHE_FILE.exists():
        return None
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        cached_time = datetime.fromisoformat(data["timestamp"])
        if datetime.now() - cached_time < timedelta(hours=CACHE_TTL_HOURS):
            return data
    except (json.JSONDecodeError, KeyError, ValueError):
        pass
    return None


def _save_cache(programs: list[dict]):
    """Persist fetched programs to cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp": datetime.now().isoformat(),
        "programs": programs,
    }
    CACHE_FILE.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def fetch_all_programs(force_refresh: bool = False) -> list[dict]:
    """Fetch programs from all platforms, with caching."""

    if not force_refresh:
        cached = _load_cache()
        if cached:
            console.print(
                f"[dim]Using cached data from {cached['timestamp'][:19]} "
                f"({len(cached['programs'])} programs). Use --refresh to re-fetch.[/dim]"
            )
            return cached["programs"]

    session = requests.Session()
    all_programs = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task_imm = progress.add_task("Fetching Immunefi bounties...", total=None)
        immunefi = fetch_immunefi(session)
        progress.update(task_imm, description=f"Immunefi: {len(immunefi)} programs")
        progress.remove_task(task_imm)

        task_c4a = progress.add_task("Fetching Code4rena bounties...", total=None)
        code4rena = fetch_code4rena(session)
        progress.update(task_c4a, description=f"Code4rena: {len(code4rena)} programs")
        progress.remove_task(task_c4a)

        task_can = progress.add_task("Fetching Cantina bounties...", total=None)
        cantina = fetch_cantina(session)
        progress.update(task_can, description=f"Cantina: {len(cantina)} programs")
        progress.remove_task(task_can)

    all_programs = immunefi + code4rena + cantina

    # Deduplicate by normalized name (keep highest bounty across platforms)
    deduped = {}
    for p in all_programs:
        key = re.sub(r"[^a-z0-9]", "", p["name"].lower())
        if key in deduped:
            existing = deduped[key]
            # If same program on multiple platforms, keep both but mark it
            if existing["platform"] != p["platform"]:
                # Keep the one with higher bounty as primary, note multi-platform
                if p["max_bounty"] > existing["max_bounty"]:
                    p["also_on"] = existing["platform"]
                    deduped[key] = p
                else:
                    existing["also_on"] = p["platform"]
            elif p["max_bounty"] > existing["max_bounty"]:
                deduped[key] = p
        else:
            deduped[key] = p

    programs = list(deduped.values())

    # Enrich: infer missing categories
    for p in programs:
        if not p.get("category"):
            p["category"] = _infer_category(p)

    # Score each program
    for p in programs:
        p["scores"] = score_program(p)

    # Sort by composite score (descending)
    programs.sort(key=lambda p: p["scores"]["composite"], reverse=True)

    _save_cache(programs)
    return programs


def display_results(
    programs: list[dict],
    min_bounty: int = 0,
    platform_filter: Optional[str] = None,
    lang_filter: Optional[str] = None,
    top_n: int = 50,
):
    """Render scored programs as a rich table."""
    filtered = programs

    if min_bounty > 0:
        filtered = [p for p in filtered if p.get("max_bounty", 0) >= min_bounty]
    if platform_filter:
        pf = platform_filter.lower()
        filtered = [p for p in filtered if p["platform"].lower().startswith(pf)]
    if lang_filter:
        lf = lang_filter.lower()
        filtered = [p for p in filtered if lf in [l.lower() for l in p.get("languages", [])]]

    filtered = filtered[:top_n]

    if not filtered:
        console.print("[yellow]No programs match your filters.[/yellow]")
        return

    # Summary panel
    total_value = sum(p.get("max_bounty", 0) for p in filtered)
    platforms = set(p["platform"] for p in filtered)
    console.print(
        Panel(
            f"[bold]{len(filtered)}[/bold] programs across "
            f"[bold]{', '.join(sorted(platforms))}[/bold]  |  "
            f"Total max payout: [bold green]${total_value:,.0f}[/bold green]  |  "
            f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            title="Bounty Scanner Results",
            border_style="cyan",
        )
    )

    # Main table
    table = Table(show_lines=True, expand=False)
    table.add_column("#", width=3, justify="right", style="dim")
    table.add_column("Protocol", style="bold cyan", width=20, no_wrap=True)
    table.add_column("Platform", width=10)
    table.add_column("Max Payout", style="bold green", width=13, justify="right")
    table.add_column("Language", width=14)
    table.add_column("Category", width=12)
    table.add_column("Fork?", width=5, justify="center")
    table.add_column("NCD", width=4, justify="right")
    table.add_column("AG", width=4, justify="right")
    table.add_column("MC", width=4, justify="right")
    table.add_column("BE", width=4, justify="right")
    table.add_column("CL", width=4, justify="right")
    table.add_column("Score", style="bold yellow", width=5, justify="right")

    for i, p in enumerate(filtered, 1):
        s = p.get("scores", {})
        bounty_str = _format_bounty(p.get("max_bounty", 0))

        # Color-code the composite score
        composite = s.get("composite", 0)
        if composite >= 70:
            score_style = "[bold green]"
        elif composite >= 55:
            score_style = "[bold yellow]"
        else:
            score_style = "[dim]"

        # Platform indicator
        platform_str = p["platform"]
        if p.get("also_on"):
            platform_str += f" +{p['also_on'][:3]}"

        langs = ", ".join(p.get("languages", []))[:14]
        fork_str = "Y" if p.get("is_fork") else ""

        table.add_row(
            str(i),
            p["name"][:20],
            platform_str,
            bounty_str,
            langs,
            p.get("category", "")[:12],
            fork_str,
            str(s.get("novel_code_density", "")),
            str(s.get("audit_gap", "")),
            str(s.get("mechanism_complexity", "")),
            str(s.get("bounty_economics", "")),
            str(s.get("competition_level", "")),
            f"{score_style}{composite}{score_style.replace('[', '[/')}",
        )

    console.print(table)

    # Legend
    console.print(
        "\n[dim]Score columns: NCD=Novel Code Density, AG=Audit Gap, "
        "MC=Mechanism Complexity, BE=Bounty Economics, CL=Competition Level[/dim]"
    )
    console.print(
        "[dim]Weights: NCD=20%, AG=20%, MC=20%, BE=25%, CL=15%. "
        "Score = weighted average * 100.[/dim]"
    )

    # Top picks
    console.print("\n[bold]Top Picks by Strategy:[/bold]")
    # Best overall
    if filtered:
        best = filtered[0]
        console.print(
            f"  [green]Best overall:[/green] {best['name']} "
            f"({best['platform']}, ${best.get('max_bounty', 0):,.0f}, "
            f"score {best['scores']['composite']})"
        )
    # Best for low competition
    low_comp = sorted(filtered, key=lambda p: p["scores"].get("competition_level", 0), reverse=True)
    if low_comp:
        lc = low_comp[0]
        console.print(
            f"  [green]Least competition:[/green] {lc['name']} "
            f"({lc['platform']}, CL={lc['scores']['competition_level']})"
        )
    # Best bounty economics
    best_econ = sorted(filtered, key=lambda p: p["scores"].get("bounty_economics", 0), reverse=True)
    if best_econ:
        be = best_econ[0]
        console.print(
            f"  [green]Best economics:[/green] {be['name']} "
            f"({be['platform']}, ${be.get('max_bounty', 0):,.0f})"
        )
    # Most complex (highest bug surface)
    most_complex = sorted(filtered, key=lambda p: p["scores"].get("mechanism_complexity", 0), reverse=True)
    if most_complex:
        mc = most_complex[0]
        console.print(
            f"  [green]Most complex:[/green] {mc['name']} "
            f"({mc['platform']}, MC={mc['scores']['mechanism_complexity']})"
        )

    console.print()


def _format_bounty(amount: int) -> str:
    """Format bounty amount in human-readable form."""
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.1f}M"
    elif amount >= 1_000:
        return f"${amount / 1_000:.0f}K"
    elif amount > 0:
        return f"${amount:,}"
    return "N/A"


def save_results(programs: list[dict], output_path: Optional[str] = None):
    """Save scored results to JSON for historical tracking."""
    out = Path(output_path) if output_path else OUTPUT_FILE
    out.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_programs": len(programs),
        "total_max_payout": sum(p.get("max_bounty", 0) for p in programs),
        "platforms": list(set(p["platform"] for p in programs)),
        "programs": programs,
    }

    out.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    console.print(f"[dim]Results saved to {out}[/dim]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Scan and score active bug bounty programs across Code4rena, Immunefi, and Cantina.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python bounty_scanner.py                    # scan all platforms\n"
            "  python bounty_scanner.py --min-bounty 500000\n"
            "  python bounty_scanner.py --platform immunefi --top 10\n"
            "  python bounty_scanner.py --lang rust\n"
            "  python bounty_scanner.py --refresh          # skip cache\n"
        ),
    )
    parser.add_argument(
        "--min-bounty", "-m", type=int, default=0,
        help="Minimum max-payout to display (default: 0)",
    )
    parser.add_argument(
        "--platform", "-p", default=None,
        help="Filter by platform: immunefi, code4rena, cantina",
    )
    parser.add_argument(
        "--lang", "-l", default=None,
        help="Filter by language: solidity, rust, vyper, cosmwasm, cairo, move",
    )
    parser.add_argument(
        "--top", "-t", type=int, default=50,
        help="Show top N results (default: 50)",
    )
    parser.add_argument(
        "--refresh", "-r", action="store_true",
        help="Force re-fetch from all platforms (skip cache)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"Output JSON path (default: {OUTPUT_FILE})",
    )

    args = parser.parse_args()

    console.print(
        Panel(
            "[bold]Bug Bounty Scanner[/bold]\n"
            "Aggregating programs from Immunefi, Code4rena, and Cantina",
            border_style="bright_blue",
        )
    )

    programs = fetch_all_programs(force_refresh=args.refresh)

    display_results(
        programs,
        min_bounty=args.min_bounty,
        platform_filter=args.platform,
        lang_filter=args.lang,
        top_n=args.top,
    )

    save_results(programs, args.output)


if __name__ == "__main__":
    main()
