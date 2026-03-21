"""
Bounty Monitor — Configuration and Expertise Profile
======================================================
Edit this file to match YOUR skills, preferences, and notification setup.
"""

# ---------------------------------------------------------------------------
# Your Expertise Profile
# ---------------------------------------------------------------------------
# The scoring engine uses this to prioritize bounties that match your skills.

EXPERTISE_PROFILE = {
    # Languages you can audit (order = preference)
    "languages": ["solidity", "vyper", "rust"],

    # Protocol categories you're strongest in
    "categories": [
        "defi",       # General DeFi
        "lending",    # Aave, Compound, Morpho-style
        "dex",        # Uniswap, Curve-style
        "perps",      # GMX, dYdX-style
        "staking",    # Lido, EigenLayer-style
        "bridge",     # Cross-chain bridges
        "restaking",  # EigenLayer, Symbiotic
        "vault",      # Yield vaults, ERC-4626
    ],

    # Chains you're comfortable with
    "chains": [
        "ethereum", "arbitrum", "optimism", "base",
        "polygon", "avalanche", "bsc", "scroll",
    ],

    # Max lines of code you can realistically audit in a 1-week contest
    "max_loc_comfortable": 5000,

    # Max LOC you'd attempt for a very high-payout contest
    "max_loc_stretch": 10000,
}


# ---------------------------------------------------------------------------
# Scoring Weights (must sum to 100)
# ---------------------------------------------------------------------------

SCORING_WEIGHTS = {
    "payout":           25,   # Raw max bounty amount
    "payout_per_loc":   20,   # $/LOC efficiency ratio
    "expertise_match":  20,   # Language + category + chain fit
    "competition":      15,   # Estimated competitor count
    "freshness":        10,   # New code / first bounty
    "tvl":              10,   # Protocol TVL (higher = juicier)
}


# ---------------------------------------------------------------------------
# Verdict Thresholds
# ---------------------------------------------------------------------------

VERDICT_THRESHOLDS = {
    "PRIORITY":    75,   # Score >= 75: drop everything, start now
    "INTERESTING": 50,   # Score >= 50: queue for review today
    "MAYBE":       25,   # Score >= 25: look at if free time
    # Below 25: SKIP
}


# ---------------------------------------------------------------------------
# Red Flags (auto-skip or penalize)
# ---------------------------------------------------------------------------

RED_FLAG_RULES = {
    # Minimum payout to bother with (below this = auto-SKIP)
    "min_payout": 5_000,

    # Max prior audits before marking as "well-picked-over"
    "max_prior_audits": 10,

    # Languages outside expertise get a penalty
    "unfamiliar_language_penalty": 15,  # points deducted

    # Scope too large for your capacity
    "max_loc_hard_skip": 20_000,
}


# ---------------------------------------------------------------------------
# Green Flags (bonus points)
# ---------------------------------------------------------------------------

GREEN_FLAG_RULES = {
    # First-ever bounty/audit for this protocol
    "first_bounty_bonus": 15,

    # Excellent $/LOC ratio threshold
    "excellent_dollar_per_loc": 100,  # $/line

    # New protocol (launched < 30 days ago)
    "new_protocol_bonus": 10,
}


# ---------------------------------------------------------------------------
# Monitoring Sources — What to Watch
# ---------------------------------------------------------------------------

# Twitter/X accounts to monitor (use a Twitter list or Nitter RSS)
TWITTER_ACCOUNTS = [
    # Platform official accounts
    "@code4rena",        # Announces all new C4 contests
    "@immunefi",         # New bounty program launches
    "@shaborudefi",      # Sherlock new contests
    "@cantaboraxyz",     # Cantina competitions
    "@CodeHawks",        # Cyfrin CodeHawks contests
    "@HackenProof",      # HackenProof new programs

    # Aggregators and security researchers who RT new bounties
    "@CDSecurity_",      # CD Security — contest aggregation
    "@bytes032",         # Active contest announcer
    "@pashovkrum",       # Top auditor, shares contest intel
    "@0xJohnnyTime",     # JohnnyTime — contest guides/announcements
    "@patrickalphac",    # Patrick Collins / Cyfrin — CodeHawks
    "@SpearbitDAO",      # Spearbit/Cantina parent
    "@AuditOne_io",      # Audit aggregator
    "@Guardian_Audits",  # Shares new contests
    "@0xMacro",          # Security firm, shares bounty intel
]

# Discord servers with announcement channels
DISCORD_SERVERS = {
    "Code4rena": {
        "invite": "https://discord.gg/code4rena",
        "channels": ["#announcements", "#new-audits"],
        "notes": "Best source for C4 — contests announced here first",
    },
    "Sherlock": {
        "invite": "https://discord.gg/sherlock",
        "channels": ["#announcements", "#contest-announcements"],
        "notes": "New contests posted here before Twitter",
    },
    "Cantina": {
        "invite": "https://discord.gg/cantina",
        "channels": ["#competitions", "#announcements"],
        "notes": "Competition launches announced here",
    },
    "CodeHawks": {
        "invite": "https://discord.gg/cyfrin",
        "channels": ["#announcements", "#contests"],
        "notes": "Cyfrin CodeHawks contest announcements",
    },
    "Immunefi": {
        "invite": "https://discord.gg/immunefi",
        "channels": ["#announcements", "#new-bounties"],
        "notes": "New bounty program launches",
    },
    "HackenProof": {
        "invite": "https://discord.gg/hackenproof",
        "channels": ["#announcements"],
        "notes": "New program launches",
    },
}

# GitHub repos to watch for changes (use GitHub Actions or watch notifications)
GITHUB_WATCH_REPOS = [
    # Immunefi unofficial mirror — auto-updates when any program changes
    "infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial",

    # Sherlock audit repos — new repo = new contest
    # Pattern: sherlock-audit/YYYY-MM-*
    "sherlock-audit",  # org-level watch

    # Cantina competition repos
    "cantina-competitions",  # org-level watch

    # Code4rena contest repos
    "code-423n4",  # org-level watch

    # CodeHawks
    "Cyfrin",  # org-level watch

    # Aggregation repos
    "JeffCX/collection-web3-bug-bounty",
    "ZhangZhuoSJTU/Web3Bugs",
]

# BBRadar — aggregator that indexes most platforms
BBRADAR_URL = "https://bbradar.io/"
# BBRadar claims new programs appear "within minutes" of platform publication


# ---------------------------------------------------------------------------
# Platform-Specific Data Access Notes
# ---------------------------------------------------------------------------

PLATFORM_ACCESS_NOTES = {
    "immunefi": {
        "best_source": "GitHub mirror (projects.json)",
        "api_url": "https://raw.githubusercontent.com/infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial/main/projects.json",
        "detail_url": "https://raw.githubusercontent.com/infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial/main/project/{slug}.json",
        "update_frequency": "Near real-time (bot commits on any program change)",
        "tools": [
            "ibb (CLI): github.com/infosec-us-team/ibb",
            "immunefi-terminal: github.com/shortdoom/immunefi-terminal",
        ],
        "notes": "No official public API. The GitHub mirror is the most reliable programmatic source.",
    },
    "code4rena": {
        "best_source": "Scrape code4rena.com/audits (Next.js page props)",
        "api_url": "code4rena.com/api/v0/contests (undocumented, may break)",
        "page_url": "https://code4rena.com/audits",
        "data_format": "JSON embedded in __NEXT_DATA__ script tag",
        "fields": "contestId, title, slug, status, startTime, endTime, formattedAmount, league, repo",
        "tools": ["code4rena-scraper: github.com/0237h/code4rena-scraper"],
        "notes": "No official API. Next.js page props are the most reliable. Also check their Discord #announcements.",
    },
    "sherlock": {
        "best_source": "Internal API at mainnet-contest.sherlock.xyz/contests",
        "page_url": "https://audits.sherlock.xyz/contests",
        "data_format": "JSON via React Query dehydrated state",
        "fields": "prizePool, startsAt, endsAt, status, title, shortDescription, token",
        "tools": ["audit-reports (Go): github.com/zaskoh/audit-reports"],
        "notes": "Internal API found via network inspection. Also watch github.com/sherlock-audit for new repos.",
    },
    "cantina": {
        "best_source": "Scrape cantina.xyz/competitions (Next.js page props)",
        "page_url": "https://cantina.xyz/competitions",
        "data_format": "JSON embedded in __NEXT_DATA__ script tag",
        "fields": "name, prizePool, startDate, endDate, status",
        "notes": "No public API. Scraping required. Also check cantina.xyz/opportunities/competitions.",
    },
    "codehawks": {
        "best_source": "Scrape codehawks.cyfrin.io/contests",
        "page_url": "https://codehawks.cyfrin.io/contests",
        "notes": "Relatively new platform. Contest frequency is lower than C4/Sherlock.",
    },
    "hackenproof": {
        "best_source": "Scrape hackenproof.com/programs",
        "page_url": "https://hackenproof.com/programs",
        "notes": "200+ active programs. No known public API.",
    },
}
