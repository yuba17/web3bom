"""Alert + State dataclasses for monitor package."""
import json
from dataclasses import dataclass, field
from pathlib import Path

from monitor.config import DATA_DIR, STATE_FILE


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """A monitoring alert."""
    id: str                   # unique key
    alert_type: str           # "github_commit", "proxy_upgrade", "new_deployment"
    target: str               # repo or contract label
    title: str                # short description
    details: str              # full details
    url: str                  # link to view
    bounty_url: str           # link to bounty program
    max_bounty: float         # max payout
    priority_score: float     # 0-100 priority
    timestamp: str            # ISO timestamp
    chain: str = ""           # blockchain (for on-chain alerts)
    address: str = ""         # contract address (for on-chain alerts)
    raw_data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# State Management
# ---------------------------------------------------------------------------

class State:
    """Persistent state to track what we've already seen."""

    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.data = {
            "github_last_sha": {},     # repo -> last commit SHA
            "proxy_impl": {},          # label -> last implementation address
            "deployer_last_tx": {},    # label -> last transaction hash
            "deployer_last_block": {}, # label -> last checked block number
        }
        self._load()

    def _load(self):
        if STATE_FILE.exists():
            try:
                saved = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                for key in self.data:
                    if key in saved:
                        self.data[key] = saved[key]
            except Exception:
                pass

    def save(self):
        STATE_FILE.write_text(
            json.dumps(self.data, indent=2, default=str),
            encoding="utf-8",
        )

    def get(self, category: str, key: str, default=None):
        return self.data.get(category, {}).get(key, default)

    def set(self, category: str, key: str, value):
        if category not in self.data:
            self.data[category] = {}
        self.data[category][key] = value
        self.save()
