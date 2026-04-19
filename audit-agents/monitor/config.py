"""Configuration for monitor package."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

console = Console()
logger = logging.getLogger("target_monitor")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "reports" / "target_monitor"
STATE_FILE = DATA_DIR / "state.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
LOG_FILE = DATA_DIR / "monitor.log"

POLL_INTERVAL = 600  # 10 minutes for daemon mode

# API keys — filter out placeholder values
def _get_key(env_var: str) -> str:
    val = os.environ.get(env_var, "")
    if val in ("", "TU_KEY_AQUI", "TU_TOKEN_AQUI", "TU_CHAT_ID_AQUI"):
        return ""
    return val

GITHUB_TOKEN = _get_key("GITHUB_TOKEN")
ETHERSCAN_API_KEY = _get_key("ETHERSCAN_API_KEY")
ARBISCAN_API_KEY = _get_key("ARBISCAN_API_KEY")
BASESCAN_API_KEY = _get_key("BASESCAN_API_KEY")
OPTIMISM_API_KEY = _get_key("OPTIMISM_API_KEY")
ALCHEMY_API_KEY = _get_key("ALCHEMY_API_KEY")

# Notification config (shared with bounty_monitor_v2.py)
TELEGRAM_BOT_TOKEN = _get_key("BOUNTY_TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = _get_key("BOUNTY_TELEGRAM_CHAT_ID")
DISCORD_WEBHOOK_URL = _get_key("BOUNTY_DISCORD_WEBHOOK")

# Etherscan-compatible explorer APIs
EXPLORERS = {
    "ethereum": {
        "api": "https://api.etherscan.io/api",
        "key": ETHERSCAN_API_KEY,
    },
    "arbitrum": {
        "api": "https://api.arbiscan.io/api",
        "key": ARBISCAN_API_KEY,
    },
    "base": {
        "api": "https://api.basescan.org/api",
        "key": BASESCAN_API_KEY,
    },
    "optimism": {
        "api": "https://api-optimistic.etherscan.io/api",
        "key": OPTIMISM_API_KEY,
    },
}


# ---------------------------------------------------------------------------
# WATCHLIST: Edit these to match your current targets
# ---------------------------------------------------------------------------

# GitHub repos to watch for post-audit commits
# Format: {repo: {"last_audit_date": "YYYY-MM-DD", "bounty_url": "...", "max_bounty": N}}
GITHUB_WATCHLIST = {
    # --- Top Immunefi bounties ---
    "euler-xyz/euler-vault-kit": {
        "last_audit_date": "2024-12-01",
        "bounty_url": "https://immunefi.com/bug-bounty/euler/",
        "max_bounty": 4_000_000,
        "branch": "master",
        "paths_of_interest": ["src/"],  # only alert on changes in these paths
    },
    "morpho-org/morpho-blue": {
        "last_audit_date": "2024-06-01",
        "bounty_url": "https://immunefi.com/bug-bounty/morpho/",
        "max_bounty": 2_500_000,
        "branch": "main",
        "paths_of_interest": ["src/"],
    },
    "aave/aave-v3-core": {
        "last_audit_date": "2024-09-01",
        "bounty_url": "https://immunefi.com/bug-bounty/aave/",
        "max_bounty": 1_000_000,
        "branch": "main",
        "paths_of_interest": ["contracts/"],
    },
    "Uniswap/v4-core": {
        "last_audit_date": "2024-10-01",
        "bounty_url": "https://immunefi.com/bug-bounty/uniswapv4/",
        "max_bounty": 15_500_000,
        "branch": "main",
        "paths_of_interest": ["src/"],
    },
    "compound-finance/comet": {
        "last_audit_date": "2024-03-01",
        "bounty_url": "https://immunefi.com/bug-bounty/compound/",
        "max_bounty": 1_000_000,
        "branch": "main",
        "paths_of_interest": ["contracts/"],
    },
    "curvefi/curve-stablecoin": {
        "last_audit_date": "2024-01-01",
        "bounty_url": "https://immunefi.com/bug-bounty/curve/",
        "max_bounty": 2_500_000,
        "branch": "main",
        "paths_of_interest": ["contracts/"],
    },
    "MakerdaoOracle/osm": {
        "last_audit_date": "2024-06-01",
        "bounty_url": "https://immunefi.com/bug-bounty/makerdao/",
        "max_bounty": 10_000_000,
        "branch": "master",
        "paths_of_interest": ["src/"],
    },
    "pendle-finance/pendle-core-v2-public": {
        "last_audit_date": "2024-08-01",
        "bounty_url": "https://immunefi.com/bug-bounty/pendle/",
        "max_bounty": 2_000_000,
        "branch": "main",
        "paths_of_interest": ["contracts/"],
    },
    "lidofinance/lido-dao": {
        "last_audit_date": "2024-07-01",
        "bounty_url": "https://immunefi.com/bug-bounty/lido/",
        "max_bounty": 2_000_000,
        "branch": "master",
        "paths_of_interest": ["contracts/"],
    },
    "OlympusDAO/olympus-v3": {
        "last_audit_date": "2024-04-01",
        "bounty_url": "https://immunefi.com/bug-bounty/olympusdao/",
        "max_bounty": 3_300_000,
        "branch": "master",
        "paths_of_interest": ["src/"],
    },
    # --- Add more as you find high-value targets ---
}


# Proxy contracts to watch for implementation upgrades
# Format: {label: {"address": "0x...", "chain": "ethereum", "bounty_url": "...", "max_bounty": N}}
PROXY_WATCHLIST = {
    # --- Euler ---
    "Euler: EVC (EthereumVaultConnector)": {
        "address": "0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/euler/",
        "max_bounty": 4_000_000,
    },
    # --- Aave v3 Pool (proxy) ---
    "Aave V3: Pool (Ethereum)": {
        "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/aave/",
        "max_bounty": 1_000_000,
    },
    # --- Compound III (Comet proxy) ---
    "Compound III: cUSDCv3": {
        "address": "0xc3d688B66703497DAA19211EEdff47f25384cdc3",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/compound/",
        "max_bounty": 1_000_000,
    },
    # --- Lido stETH ---
    "Lido: stETH": {
        "address": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/lido/",
        "max_bounty": 2_000_000,
    },
    # --- Pendle Router ---
    "Pendle: Router V4": {
        "address": "0x888888888889758F76e7103c6CbF23ABbF58F946",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/pendle/",
        "max_bounty": 2_000_000,
    },
    # --- Add more proxies you want to watch ---
}


# Deployer addresses to watch for new contract deployments
# Format: {label: {"address": "0x...", "chain": "ethereum", "bounty_url": "...", "max_bounty": N}}
DEPLOYER_WATCHLIST = {
    "Euler Labs deployer": {
        "address": "0x9D741Bc475A76b29C31509Fa4890Ab7CF8F7dde0",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/euler/",
        "max_bounty": 4_000_000,
    },
    "Uniswap deployer": {
        "address": "0x6C9FC64A53c1b71FB7c9Bc853cDe0c1642dff2Ef",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/uniswapv4/",
        "max_bounty": 15_500_000,
    },
    "Aave deployer": {
        "address": "0xEE56e2B3D491590B5b31738cC34d5232F378a8D5",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/aave/",
        "max_bounty": 1_000_000,
    },
    "Compound deployer": {
        "address": "0x6d903f6003cca6255D85CcA4D3B5E5146dC33925",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/compound/",
        "max_bounty": 1_000_000,
    },
    "Morpho deployer": {
        "address": "0x9c67cD57FEe5B9ccA16A30A1C8B20823d0AFd4C2",
        "chain": "ethereum",
        "bounty_url": "https://immunefi.com/bug-bounty/morpho/",
        "max_bounty": 2_500_000,
    },
    # --- Add more deployer addresses ---
    # To find deployer addresses:
    # 1. Go to Etherscan, find the protocol's core contract
    # 2. Click "Contract Creator" link
    # 3. That EOA or multisig is the deployer
}
