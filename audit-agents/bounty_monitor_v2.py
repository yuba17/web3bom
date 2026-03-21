#!/usr/bin/env python3
"""
Bounty Monitor v2 — Automatic Web3 Bug Bounty Triage System
=============================================================
Monitors all major audit competition and bug bounty platforms for new programs.
Auto-scores, triages, and sends notifications for high-priority targets.

Platforms monitored:
  - Immunefi (bug bounties)
  - Code4rena (audit competitions)
  - Sherlock (audit contests)
  - Cantina (competitions)
  - CodeHawks / Cyfrin (audit competitions)
  - HackenProof (bug bounties)

Usage:
    python bounty_monitor_v2.py                    # Full scan, all platforms
    python bounty_monitor_v2.py --platform immunefi # Single platform
    python bounty_monitor_v2.py --notify discord    # Enable Discord alerts
    python bounty_monitor_v2.py --notify telegram   # Enable Telegram alerts
    python bounty_monitor_v2.py --daemon            # Run continuously (5-min interval)
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

console = Console()
logger = logging.getLogger("bounty_monitor")

DATA_DIR = Path(__file__).parent / "reports" / "bounty_monitor"
SEEN_FILE = DATA_DIR / "seen_programs.json"
SCORES_FILE = DATA_DIR / "scored_programs.json"
LOG_FILE = DATA_DIR / "monitor.log"

POLL_INTERVAL_SECONDS = 300  # 5 minutes

# Notification config (set via env vars)
DISCORD_WEBHOOK_URL = os.environ.get("BOUNTY_DISCORD_WEBHOOK", "")
TELEGRAM_BOT_TOKEN = os.environ.get("BOUNTY_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("BOUNTY_TELEGRAM_CHAT_ID", "")

# DefiLlama API for TVL enrichment
DEFILLAMA_API = "https://api.llama.fi"

# Your expertise profile — adjust to match your skills
EXPERTISE = {
    "languages": ["solidity", "vyper", "rust"],  # languages you audit
    "categories": ["defi", "lending", "dex", "perps", "staking", "bridge", "restaking"],
    "chains": ["ethereum", "arbitrum", "optimism", "base", "polygon", "avalanche"],
    "max_loc_comfortable": 5000,  # max LOC you can audit in a contest window
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class Platform(str, Enum):
    IMMUNEFI = "immunefi"
    CODE4RENA = "code4rena"
    SHERLOCK = "sherlock"
    CANTINA = "cantina"
    CODEHAWKS = "codehawks"
    HACKENPROOF = "hackenproof"


class ProgramType(str, Enum):
    BUG_BOUNTY = "bug_bounty"       # Ongoing, post-deployment
    AUDIT_CONTEST = "audit_contest"  # Time-boxed, pre-deployment


class Verdict(str, Enum):
    PRIORITY = "PRIORITY"      # Drop everything, start now
    INTERESTING = "INTERESTING" # Queue for review
    MAYBE = "MAYBE"            # Look at if time allows
    SKIP = "SKIP"              # Do not pursue


@dataclass
class BountyProgram:
    """Unified representation of a bounty/contest across all platforms."""
    id: str                          # unique key: platform:slug
    platform: str
    program_type: str
    name: str
    url: str
    max_payout: float = 0.0
    currency: str = "USDC"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    language: str = "solidity"       # primary language
    loc: int = 0                     # lines of code in scope
    category: str = "unknown"
    chain: str = "unknown"
    repo_url: str = ""
    tvl: float = 0.0                 # from DefiLlama
    prior_audits: int = 0
    is_first_bounty: bool = False
    competitors_estimate: int = 0
    discovered_at: str = ""
    raw_data: dict = field(default_factory=dict)

    # Scoring output
    score: float = 0.0
    verdict: str = Verdict.MAYBE.value
    score_breakdown: dict = field(default_factory=dict)
    red_flags: list = field(default_factory=list)
    green_flags: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Platform Fetchers
# ---------------------------------------------------------------------------

class BaseFetcher:
    """Base class for platform-specific fetchers."""

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html",
    }

    def fetch(self) -> list[BountyProgram]:
        raise NotImplementedError

    def _get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("headers", self.HEADERS)
        kwargs.setdefault("timeout", 30)
        return requests.get(url, **kwargs)


class ImmunefiNetcher(BaseFetcher):
    """
    Immunefi data source: unofficial mirror of all bounty programs.

    Primary:  GitHub mirror at infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial
              Updated automatically whenever any program changes.
              URL: https://raw.githubusercontent.com/infosec-us-team/
                   Immunefi-Bug-Bounty-Programs-Unofficial/main/projects.json

    Backup:   Scrape immunefi.com/bug-bounty/ — Next.js SSR embeds JSON in page props.

    Fields available: id, project, maxBounty, launchDate, updatedDate,
                      kyc, assets (type, url), impacts, etc.
    """

    PROJECTS_URL = (
        "https://raw.githubusercontent.com/infosec-us-team/"
        "Immunefi-Bug-Bounty-Programs-Unofficial/main/projects.json"
    )
    PROJECT_DETAIL_URL = (
        "https://raw.githubusercontent.com/infosec-us-team/"
        "Immunefi-Bug-Bounty-Programs-Unofficial/main/project/{slug}.json"
    )

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            resp = self._get(self.PROJECTS_URL)
            resp.raise_for_status()
            data = resp.json()

            for item in data:
                slug = item.get("id", item.get("project", "unknown"))
                max_bounty = self._parse_bounty(item.get("maxBounty", 0))

                prog = BountyProgram(
                    id=f"immunefi:{slug}",
                    platform=Platform.IMMUNEFI.value,
                    program_type=ProgramType.BUG_BOUNTY.value,
                    name=item.get("project", slug),
                    url=f"https://immunefi.com/bug-bounty/{slug}/",
                    max_payout=max_bounty,
                    start_date=item.get("launchDate", ""),
                    category=self._infer_category(item),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    raw_data=item,
                )
                programs.append(prog)

        except Exception as e:
            logger.error(f"Immunefi fetch failed: {e}")
        return programs

    def _parse_bounty(self, val) -> float:
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            cleaned = re.sub(r"[^0-9.]", "", val)
            return float(cleaned) if cleaned else 0.0
        return 0.0

    def _infer_category(self, item: dict) -> str:
        desc = json.dumps(item).lower()
        for cat in ["lending", "dex", "bridge", "staking", "perps", "oracle", "l2"]:
            if cat in desc:
                return cat
        return "defi"


class Code4renaFetcher(BaseFetcher):
    """
    Code4rena data source: HTML page at code4rena.com/audits with embedded
    Next.js JSON containing all contest data.

    Key data in page props:
      contestId, title, slug, status, startTime, endTime,
      formattedAmount, league, repo, findingsRepo

    Alternative: code4rena.com/api/v0/contests (undocumented, may break)
    Also monitor: @code4rena on X, #announcements on Code4rena Discord
    """

    AUDITS_URL = "https://code4rena.com/audits"
    # Undocumented API endpoint (inspect network tab on audits page)
    API_URL = "https://code4rena.com/api/v0/contests"

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            # Try API first
            try:
                resp = self._get(self.API_URL)
                resp.raise_for_status()
                contests = resp.json()
            except Exception:
                # Fall back to scraping page props from Next.js HTML
                contests = self._scrape_page_props()

            for c in contests:
                slug = c.get("slug", c.get("title", "unknown"))
                prize = self._parse_prize(c.get("formattedAmount", c.get("prizePool", "0")))
                status = c.get("status", "").lower()

                # Only care about upcoming or active contests
                if status in ("completed", "reporting", "finalized"):
                    continue

                prog = BountyProgram(
                    id=f"code4rena:{slug}",
                    platform=Platform.CODE4RENA.value,
                    program_type=ProgramType.AUDIT_CONTEST.value,
                    name=c.get("title", slug),
                    url=f"https://code4rena.com/audits/{slug}",
                    max_payout=prize,
                    start_date=c.get("startTime", ""),
                    end_date=c.get("endTime", ""),
                    repo_url=c.get("repo", ""),
                    chain=c.get("league", "ETH").lower(),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    raw_data=c,
                )
                programs.append(prog)

        except Exception as e:
            logger.error(f"Code4rena fetch failed: {e}")
        return programs

    def _scrape_page_props(self) -> list[dict]:
        """Extract contest data from Next.js __NEXT_DATA__ script tag."""
        resp = self._get(self.AUDITS_URL)
        resp.raise_for_status()
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
            # Navigate the Next.js props tree — structure may vary
            props = data.get("props", {}).get("pageProps", {})
            return props.get("contests", props.get("audits", []))
        return []

    def _parse_prize(self, val) -> float:
        if isinstance(val, (int, float)):
            return float(val)
        cleaned = re.sub(r"[^0-9.]", "", str(val))
        return float(cleaned) if cleaned else 0.0


class SherlockFetcher(BaseFetcher):
    """
    Sherlock data source: audits.sherlock.xyz/contests
    React app with client-side data. Contest data loaded via internal API.

    Key fields in React Query state:
      prizePool, startsAt, endsAt, status, title, shortDescription,
      logoUrl, rewards, token

    Known endpoint (inspect network tab): GET /contests or GraphQL
    Also: GitHub repos at github.com/sherlock-audit/ for each contest
    """

    CONTESTS_URL = "https://audits.sherlock.xyz/contests"
    # Sherlock's internal API (reverse-engineered from network tab)
    API_URL = "https://mainnet-contest.sherlock.xyz/contests"

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            # Try the internal API
            try:
                resp = self._get(self.API_URL)
                resp.raise_for_status()
                contests = resp.json()
                if isinstance(contests, dict):
                    contests = contests.get("contests", contests.get("data", []))
            except Exception:
                # Fall back to page scraping
                contests = self._scrape_page(self.CONTESTS_URL)

            for c in contests:
                if not isinstance(c, dict):
                    continue
                title = c.get("title", "unknown")
                slug = title.lower().replace(" ", "-")
                status = c.get("status", "").upper()

                if status in ("FINISHED",):
                    continue

                prog = BountyProgram(
                    id=f"sherlock:{slug}",
                    platform=Platform.SHERLOCK.value,
                    program_type=ProgramType.AUDIT_CONTEST.value,
                    name=title,
                    url=f"https://audits.sherlock.xyz/contests/{c.get('id', slug)}",
                    max_payout=float(c.get("prizePool", c.get("rewards", 0))),
                    currency=c.get("token", "USDC"),
                    start_date=c.get("startsAt", c.get("startDate", "")),
                    end_date=c.get("endsAt", c.get("endDate", "")),
                    category="defi",
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    raw_data=c,
                )
                programs.append(prog)

        except Exception as e:
            logger.error(f"Sherlock fetch failed: {e}")
        return programs

    def _scrape_page(self, url: str) -> list[dict]:
        """Extract data from Sherlock's React app page."""
        resp = self._get(url)
        # Try to find React Query dehydrated state
        match = re.search(r'"dehydratedState":\s*(\{.*?\})\s*[,}]', resp.text, re.DOTALL)
        if match:
            try:
                state = json.loads(match.group(1))
                queries = state.get("queries", [])
                for q in queries:
                    data = q.get("state", {}).get("data", [])
                    if isinstance(data, list) and len(data) > 0:
                        return data
            except json.JSONDecodeError:
                pass
        return []


class CantinaFetcher(BaseFetcher):
    """
    Cantina data source: cantina.xyz/competitions
    Next.js app with server-side rendered data.

    No public API documented. Data must be scraped from page or
    reverse-engineered from network requests.

    Also monitor: @cantaboraxyz on X, Cantina Discord #competitions
    """

    COMPETITIONS_URL = "https://cantina.xyz/competitions"
    # Cantina's internal Next.js API route (check network tab)
    API_URL = "https://cantina.xyz/api/competitions"

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            try:
                resp = self._get(self.API_URL)
                resp.raise_for_status()
                competitions = resp.json()
            except Exception:
                competitions = self._scrape_nextjs(self.COMPETITIONS_URL)

            for c in competitions:
                if not isinstance(c, dict):
                    continue
                name = c.get("name", c.get("title", "unknown"))
                slug = c.get("id", name.lower().replace(" ", "-"))

                prog = BountyProgram(
                    id=f"cantina:{slug}",
                    platform=Platform.CANTINA.value,
                    program_type=ProgramType.AUDIT_CONTEST.value,
                    name=name,
                    url=f"https://cantina.xyz/competitions/{slug}",
                    max_payout=self._parse_prize(c.get("prizePool", c.get("prize", "0"))),
                    start_date=c.get("startDate", ""),
                    end_date=c.get("endDate", ""),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    raw_data=c,
                )
                programs.append(prog)

        except Exception as e:
            logger.error(f"Cantina fetch failed: {e}")
        return programs

    def _scrape_nextjs(self, url: str) -> list[dict]:
        resp = self._get(url)
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
            props = data.get("props", {}).get("pageProps", {})
            return props.get("competitions", props.get("opportunities", []))
        return []

    def _parse_prize(self, val) -> float:
        if isinstance(val, (int, float)):
            return float(val)
        cleaned = re.sub(r"[^0-9.]", "", str(val))
        return float(cleaned) if cleaned else 0.0


class CodeHawksFetcher(BaseFetcher):
    """
    CodeHawks / Cyfrin data source: codehawks.cyfrin.io/contests
    Also: cyfrin.io/codehawks/competitive-audits

    Monitor @CodeHawks on X, CodeHawks Discord
    """

    CONTESTS_URL = "https://codehawks.cyfrin.io/contests"
    API_URL = "https://codehawks.cyfrin.io/api/contests"

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            try:
                resp = self._get(self.API_URL)
                resp.raise_for_status()
                contests = resp.json()
                if isinstance(contests, dict):
                    contests = contests.get("contests", contests.get("data", []))
            except Exception:
                contests = self._scrape_page()

            for c in contests:
                if not isinstance(c, dict):
                    continue
                name = c.get("title", c.get("name", "unknown"))
                slug = c.get("slug", c.get("id", name.lower().replace(" ", "-")))

                prog = BountyProgram(
                    id=f"codehawks:{slug}",
                    platform=Platform.CODEHAWKS.value,
                    program_type=ProgramType.AUDIT_CONTEST.value,
                    name=name,
                    url=f"https://codehawks.cyfrin.io/contests/{slug}",
                    max_payout=float(c.get("prizePool", c.get("prize", 0))),
                    start_date=c.get("startDate", ""),
                    end_date=c.get("endDate", ""),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    raw_data=c,
                )
                programs.append(prog)

        except Exception as e:
            logger.error(f"CodeHawks fetch failed: {e}")
        return programs

    def _scrape_page(self) -> list[dict]:
        resp = self._get(self.CONTESTS_URL)
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
            props = data.get("props", {}).get("pageProps", {})
            return props.get("contests", [])
        return []


class HackenProofFetcher(BaseFetcher):
    """
    HackenProof data source: hackenproof.com/programs
    No known public API. Scrape the programs listing page.

    Also monitor: @HackenProof on X, HackenProof Discord
    """

    PROGRAMS_URL = "https://hackenproof.com/programs"

    def fetch(self) -> list[BountyProgram]:
        programs = []
        try:
            resp = self._get(self.PROGRAMS_URL)
            # HackenProof uses Next.js or similar SSR
            match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
                props = data.get("props", {}).get("pageProps", {})
                items = props.get("programs", props.get("bounties", []))

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name", item.get("title", "unknown"))
                    slug = item.get("slug", name.lower().replace(" ", "-"))

                    prog = BountyProgram(
                        id=f"hackenproof:{slug}",
                        platform=Platform.HACKENPROOF.value,
                        program_type=ProgramType.BUG_BOUNTY.value,
                        name=name,
                        url=f"https://hackenproof.com/programs/{slug}",
                        max_payout=float(item.get("maxBounty", item.get("reward", 0))),
                        discovered_at=datetime.now(timezone.utc).isoformat(),
                        raw_data=item,
                    )
                    programs.append(prog)

        except Exception as e:
            logger.error(f"HackenProof fetch failed: {e}")
        return programs


# ---------------------------------------------------------------------------
# Enrichment: TVL, LOC, Audit History
# ---------------------------------------------------------------------------

class Enricher:
    """Enrich bounty programs with TVL data, LOC counts, and audit history."""

    def enrich(self, program: BountyProgram) -> BountyProgram:
        """Add TVL, LOC, and other metadata. Best-effort, never fails."""
        self._enrich_tvl(program)
        self._enrich_loc(program)
        self._enrich_language(program)
        return program

    def _enrich_tvl(self, program: BountyProgram):
        """Look up TVL on DefiLlama."""
        if program.tvl > 0:
            return
        try:
            slug = program.name.lower().replace(" ", "-")
            resp = requests.get(
                f"{DEFILLAMA_API}/protocol/{slug}",
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                program.tvl = float(data.get("currentChainTvls", {}).get("total", 0))
                if program.tvl == 0:
                    program.tvl = float(data.get("tvl", [{}])[-1].get("totalLiquidityUSD", 0))
        except Exception:
            pass

    def _enrich_loc(self, program: BountyProgram):
        """Estimate LOC from GitHub repo if available."""
        if program.loc > 0 or not program.repo_url:
            return
        try:
            # Extract owner/repo from GitHub URL
            match = re.search(r"github\.com/([^/]+/[^/]+)", program.repo_url)
            if not match:
                return
            repo = match.group(1).rstrip("/")
            resp = requests.get(
                f"https://api.github.com/repos/{repo}/languages",
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=10,
            )
            if resp.status_code == 200:
                langs = resp.json()
                # Rough estimate: 1 byte ~ 0.04 lines for Solidity
                sol_bytes = langs.get("Solidity", 0) + langs.get("Rust", 0) + langs.get("Vyper", 0)
                program.loc = int(sol_bytes * 0.04) if sol_bytes > 0 else 0

                # Detect primary language
                if langs:
                    program.language = max(langs, key=langs.get).lower()
        except Exception:
            pass

    def _enrich_language(self, program: BountyProgram):
        """Infer language from chain/platform if not already set."""
        if program.language != "solidity":
            return
        chain = program.chain.lower()
        if chain in ("solana", "sui", "aptos"):
            program.language = "rust"
        elif chain in ("cosmos", "osmosis"):
            program.language = "rust"  # CosmWasm
        elif chain in ("near",):
            program.language = "rust"


# ---------------------------------------------------------------------------
# Scoring & Triage Engine
# ---------------------------------------------------------------------------

class TriageScorer:
    """
    Score and triage bounty programs based on multiple factors.

    Score range: 0-100
    Verdict thresholds:
      >= 75: PRIORITY  (drop everything)
      >= 50: INTERESTING (queue for review)
      >= 25: MAYBE (look at if time permits)
      <  25: SKIP
    """

    # Weight distribution (must sum to 100)
    WEIGHTS = {
        "payout":           25,  # Raw payout attractiveness
        "payout_per_loc":   20,  # $/LOC ratio — efficiency metric
        "expertise_match":  20,  # Language + category + chain match
        "competition":      15,  # Lower competition = higher score
        "freshness":        10,  # New code / first bounty bonus
        "tvl":              10,  # Higher TVL = juicier target
    }

    def score(self, program: BountyProgram) -> BountyProgram:
        """Compute score, verdict, flags."""
        breakdown = {}
        red_flags = []
        green_flags = []

        # --- Payout score (0-100 scale) ---
        payout = program.max_payout
        if payout >= 1_000_000:
            breakdown["payout"] = 100
        elif payout >= 500_000:
            breakdown["payout"] = 85
        elif payout >= 200_000:
            breakdown["payout"] = 70
        elif payout >= 100_000:
            breakdown["payout"] = 55
        elif payout >= 50_000:
            breakdown["payout"] = 40
        elif payout >= 20_000:
            breakdown["payout"] = 25
        else:
            breakdown["payout"] = 10
            if payout < 10_000:
                red_flags.append(f"Tiny payout: ${payout:,.0f}")

        # --- Payout per LOC ---
        if program.loc > 0:
            ratio = payout / program.loc
            if ratio >= 100:
                breakdown["payout_per_loc"] = 100
                green_flags.append(f"Excellent $/LOC: ${ratio:,.0f}/line")
            elif ratio >= 50:
                breakdown["payout_per_loc"] = 80
                green_flags.append(f"Good $/LOC: ${ratio:,.0f}/line")
            elif ratio >= 20:
                breakdown["payout_per_loc"] = 60
            elif ratio >= 10:
                breakdown["payout_per_loc"] = 40
            else:
                breakdown["payout_per_loc"] = 20
                red_flags.append(f"Low $/LOC: ${ratio:,.1f}/line")
        else:
            breakdown["payout_per_loc"] = 50  # Unknown, neutral

        # --- Expertise match ---
        match_score = 0
        if program.language.lower() in EXPERTISE["languages"]:
            match_score += 40
            green_flags.append(f"Language match: {program.language}")
        else:
            red_flags.append(f"Out-of-expertise language: {program.language}")
            match_score -= 20

        if program.category.lower() in EXPERTISE["categories"]:
            match_score += 35
            green_flags.append(f"Category match: {program.category}")

        if program.chain.lower() in EXPERTISE["chains"]:
            match_score += 25

        breakdown["expertise_match"] = max(0, min(100, match_score))

        # --- Competition level ---
        if program.program_type == ProgramType.BUG_BOUNTY.value:
            # Bug bounties: always "competing" but less time-pressured
            breakdown["competition"] = 60
        else:
            # Audit contests: estimate from payout (higher payout = more competitors)
            if payout >= 500_000:
                breakdown["competition"] = 30  # Very competitive
                red_flags.append("High-payout contest = heavy competition")
            elif payout >= 100_000:
                breakdown["competition"] = 50
            elif payout >= 50_000:
                breakdown["competition"] = 70
            else:
                breakdown["competition"] = 85
                green_flags.append("Lower competition expected")

        # --- Freshness ---
        if program.is_first_bounty:
            breakdown["freshness"] = 100
            green_flags.append("FIRST BOUNTY — likely unaudited code")
        elif program.prior_audits == 0:
            breakdown["freshness"] = 90
            green_flags.append("No prior audits found")
        elif program.prior_audits <= 2:
            breakdown["freshness"] = 60
        elif program.prior_audits <= 5:
            breakdown["freshness"] = 30
        else:
            breakdown["freshness"] = 10
            red_flags.append(f"{program.prior_audits} prior audits — well-picked-over")

        # --- TVL ---
        tvl = program.tvl
        if tvl >= 1_000_000_000:
            breakdown["tvl"] = 100
            green_flags.append(f"Very high TVL: ${tvl/1e9:.1f}B")
        elif tvl >= 100_000_000:
            breakdown["tvl"] = 80
        elif tvl >= 10_000_000:
            breakdown["tvl"] = 60
        elif tvl > 0:
            breakdown["tvl"] = 40
        else:
            breakdown["tvl"] = 50  # Unknown, neutral

        # --- LOC feasibility check ---
        if program.loc > EXPERTISE["max_loc_comfortable"] * 2:
            red_flags.append(f"Very large scope: {program.loc:,} LOC")
        elif program.loc > EXPERTISE["max_loc_comfortable"]:
            red_flags.append(f"Large scope: {program.loc:,} LOC (above comfort zone)")

        # --- Compute weighted total ---
        total = 0.0
        for key, weight in self.WEIGHTS.items():
            component = breakdown.get(key, 50)
            total += component * (weight / 100.0)

        # --- Clamp red-flag penalty ---
        critical_reds = sum(1 for f in red_flags if any(
            kw in f.lower() for kw in ["tiny payout", "out-of-expertise", "prior audits"]
        ))
        total = max(0, total - critical_reds * 8)

        # --- Determine verdict ---
        if total >= 75:
            verdict = Verdict.PRIORITY
        elif total >= 50:
            verdict = Verdict.INTERESTING
        elif total >= 25:
            verdict = Verdict.MAYBE
        else:
            verdict = Verdict.SKIP

        program.score = round(total, 1)
        program.verdict = verdict.value
        program.score_breakdown = breakdown
        program.red_flags = red_flags
        program.green_flags = green_flags
        return program


# ---------------------------------------------------------------------------
# Notification System
# ---------------------------------------------------------------------------

class Notifier:
    """Send alerts for high-priority bounties via Discord and Telegram."""

    def notify(self, program: BountyProgram, channels: list[str]):
        """Send notification to specified channels."""
        if program.verdict not in (Verdict.PRIORITY.value, Verdict.INTERESTING.value):
            return

        msg = self._format_message(program)

        if "discord" in channels and DISCORD_WEBHOOK_URL:
            self._send_discord(msg, program)
        if "telegram" in channels and TELEGRAM_BOT_TOKEN:
            self._send_telegram(msg)
        if "console" in channels:
            console.print(Panel(msg, title=f"[bold red]NEW: {program.name}[/bold red]"))

    def _format_message(self, p: BountyProgram) -> str:
        emoji = {"PRIORITY": "!!!", "INTERESTING": ">>", "MAYBE": "--", "SKIP": "  "}
        return (
            f"{emoji.get(p.verdict, '')} [{p.verdict}] {p.name}\n"
            f"Platform:  {p.platform} ({p.program_type})\n"
            f"Payout:    ${p.max_payout:,.0f} {p.currency}\n"
            f"Score:     {p.score}/100\n"
            f"Language:  {p.language} | Chain: {p.chain} | Category: {p.category}\n"
            f"LOC:       {p.loc:,} | TVL: ${p.tvl:,.0f}\n"
            f"URL:       {p.url}\n"
            f"Repo:      {p.repo_url or 'N/A'}\n"
            f"Dates:     {p.start_date or 'N/A'} -> {p.end_date or 'N/A'}\n"
            f"Green:     {', '.join(p.green_flags) or 'None'}\n"
            f"Red:       {', '.join(p.red_flags) or 'None'}\n"
        )

    def _send_discord(self, msg: str, p: BountyProgram):
        """Send rich embed to Discord webhook."""
        color = {"PRIORITY": 0xFF0000, "INTERESTING": 0xFFA500}.get(p.verdict, 0x808080)
        payload = {
            "embeds": [{
                "title": f"[{p.verdict}] {p.name} — ${p.max_payout:,.0f}",
                "description": msg,
                "url": p.url,
                "color": color,
                "fields": [
                    {"name": "Platform", "value": p.platform, "inline": True},
                    {"name": "Score", "value": f"{p.score}/100", "inline": True},
                    {"name": "Language", "value": p.language, "inline": True},
                ],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }]
        }
        try:
            requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        except Exception as e:
            logger.error(f"Discord notification failed: {e}")

    def _send_telegram(self, msg: str):
        """Send message via Telegram bot."""
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
                timeout=10,
            )
        except Exception as e:
            logger.error(f"Telegram notification failed: {e}")


# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

class StateManager:
    """Track which programs we've already seen to detect new ones."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.seen: dict[str, str] = {}  # id -> first_seen_timestamp
        self._load()

    def _load(self):
        if SEEN_FILE.exists():
            self.seen = json.loads(SEEN_FILE.read_text(encoding="utf-8"))

    def _save(self):
        SEEN_FILE.write_text(json.dumps(self.seen, indent=2), encoding="utf-8")

    def is_new(self, program_id: str) -> bool:
        return program_id not in self.seen

    def mark_seen(self, program_id: str):
        if program_id not in self.seen:
            self.seen[program_id] = datetime.now(timezone.utc).isoformat()
            self._save()

    def get_all_seen(self) -> dict:
        return self.seen.copy()


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

FETCHERS = {
    Platform.IMMUNEFI: ImmunefiNetcher,
    Platform.CODE4RENA: Code4renaFetcher,
    Platform.SHERLOCK: SherlockFetcher,
    Platform.CANTINA: CantinaFetcher,
    Platform.CODEHAWKS: CodeHawksFetcher,
    Platform.HACKENPROOF: HackenProofFetcher,
}


def run_scan(
    platforms: list[str] | None = None,
    notify_channels: list[str] | None = None,
    enrich: bool = True,
    verbose: bool = False,
) -> list[BountyProgram]:
    """
    Run a full scan across all platforms.
    Returns list of NEW programs found this scan, scored and triaged.
    """
    notify_channels = notify_channels or ["console"]
    state = StateManager()
    enricher = Enricher()
    scorer = TriageScorer()
    notifier = Notifier()

    all_programs = []
    new_programs = []

    # Determine which platforms to scan
    target_platforms = (
        [Platform(p) for p in platforms] if platforms
        else list(Platform)
    )

    for platform in target_platforms:
        fetcher_cls = FETCHERS.get(platform)
        if not fetcher_cls:
            continue

        console.print(f"[dim]Scanning {platform.value}...[/dim]")
        try:
            fetcher = fetcher_cls()
            programs = fetcher.fetch()
            console.print(f"  [dim]Found {len(programs)} programs on {platform.value}[/dim]")

            for prog in programs:
                all_programs.append(prog)
                if state.is_new(prog.id):
                    if enrich:
                        enricher.enrich(prog)
                    scorer.score(prog)
                    new_programs.append(prog)
                    state.mark_seen(prog.id)
                    notifier.notify(prog, notify_channels)

        except Exception as e:
            logger.error(f"Error scanning {platform.value}: {e}")
            if verbose:
                console.print(f"  [red]Error: {e}[/red]")

    # Sort new programs by score descending
    new_programs.sort(key=lambda p: p.score, reverse=True)

    # Save scored results
    if new_programs:
        _save_results(new_programs)

    return new_programs


def _save_results(programs: list[BountyProgram]):
    """Persist scored programs to JSON."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    existing = []
    if SCORES_FILE.exists():
        try:
            existing = json.loads(SCORES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing.extend([asdict(p) for p in programs])
    SCORES_FILE.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")


def display_results(programs: list[BountyProgram]):
    """Display scored programs in a rich table."""
    if not programs:
        console.print("[yellow]No new programs found this scan.[/yellow]")
        return

    table = Table(
        title=f"New Bounty Programs Found ({len(programs)})",
        show_lines=True,
    )
    table.add_column("Verdict", width=12)
    table.add_column("Score", width=6, justify="right")
    table.add_column("Platform", width=12)
    table.add_column("Name", width=25, style="bold")
    table.add_column("Payout", width=14, justify="right")
    table.add_column("Lang", width=10)
    table.add_column("LOC", width=8, justify="right")
    table.add_column("Green Flags", width=30)
    table.add_column("Red Flags", width=30)

    verdict_styles = {
        "PRIORITY": "bold red",
        "INTERESTING": "bold yellow",
        "MAYBE": "dim",
        "SKIP": "dim strikethrough",
    }

    for p in programs:
        style = verdict_styles.get(p.verdict, "")
        table.add_row(
            Text(p.verdict, style=style),
            str(p.score),
            p.platform,
            p.name,
            f"${p.max_payout:,.0f}",
            p.language,
            f"{p.loc:,}" if p.loc > 0 else "?",
            "\n".join(p.green_flags[:3]) if p.green_flags else "-",
            "\n".join(p.red_flags[:3]) if p.red_flags else "-",
        )

    console.print(table)

    # Summary
    by_verdict = {}
    for p in programs:
        by_verdict.setdefault(p.verdict, []).append(p)

    console.print(f"\n[bold]Summary:[/bold]")
    for v in [Verdict.PRIORITY, Verdict.INTERESTING, Verdict.MAYBE, Verdict.SKIP]:
        count = len(by_verdict.get(v.value, []))
        if count:
            console.print(f"  {v.value}: {count} programs")


def daemon_mode(platforms=None, notify_channels=None):
    """Run continuously, polling every POLL_INTERVAL_SECONDS."""
    console.print(f"[bold]Daemon mode: polling every {POLL_INTERVAL_SECONDS}s[/bold]")
    while True:
        try:
            console.print(f"\n[dim]--- Scan at {datetime.now(timezone.utc).isoformat()} ---[/dim]")
            new = run_scan(platforms, notify_channels)
            if new:
                display_results(new)
            else:
                console.print("[dim]No new programs.[/dim]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped.[/yellow]")
            break
        except Exception as e:
            logger.error(f"Scan error: {e}")
            console.print(f"[red]Scan error: {e}[/red]")

        time.sleep(POLL_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Web3 Bug Bounty Monitor & Triage System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bounty_monitor_v2.py                          # Scan all platforms
  python bounty_monitor_v2.py --platform immunefi      # Immunefi only
  python bounty_monitor_v2.py --platform code4rena sherlock  # Multiple
  python bounty_monitor_v2.py --notify discord telegram # Send alerts
  python bounty_monitor_v2.py --daemon                  # Run continuously
  python bounty_monitor_v2.py --daemon --notify discord # Daemon + Discord

Environment variables for notifications:
  BOUNTY_DISCORD_WEBHOOK   Discord webhook URL
  BOUNTY_TELEGRAM_TOKEN    Telegram bot token
  BOUNTY_TELEGRAM_CHAT_ID  Telegram chat ID
        """,
    )
    parser.add_argument(
        "--platform", "-p", nargs="+",
        choices=[p.value for p in Platform],
        help="Platforms to monitor (default: all)",
    )
    parser.add_argument(
        "--notify", "-n", nargs="+",
        choices=["discord", "telegram", "console"],
        default=["console"],
        help="Notification channels",
    )
    parser.add_argument(
        "--daemon", "-d", action="store_true",
        help="Run continuously in daemon mode",
    )
    parser.add_argument(
        "--no-enrich", action="store_true",
        help="Skip TVL/LOC enrichment (faster)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Clear seen-programs state (treat all as new)",
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ] if LOG_FILE.parent.exists() else [logging.StreamHandler()],
    )

    if args.reset:
        if SEEN_FILE.exists():
            SEEN_FILE.unlink()
            console.print("[yellow]State reset.[/yellow]")

    if args.daemon:
        daemon_mode(args.platform, args.notify)
    else:
        programs = run_scan(
            platforms=args.platform,
            notify_channels=args.notify,
            enrich=not args.no_enrich,
            verbose=args.verbose,
        )
        display_results(programs)


if __name__ == "__main__":
    main()
