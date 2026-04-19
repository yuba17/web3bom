"""ProxyUpgradeMonitor for monitor package."""
import time
from datetime import datetime, timezone
from typing import Optional

import requests

from monitor.config import (
    ALCHEMY_API_KEY,
    EXPLORERS,
    PROXY_WATCHLIST,
    console,
    logger,
)
from monitor.notifier import Notifier
from monitor.state import Alert, State


class ProxyUpgradeMonitor:
    """
    Detect implementation changes in proxy contracts.

    Method: Read the EIP-1967 implementation storage slot.
    Slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

    Uses Etherscan API:
      GET /?module=proxy&action=eth_getStorageAt
        &address={proxy_address}
        &position=0x360894...
        &tag=latest

    Alternative (more reliable): eth_getStorageAt via Alchemy/Infura JSON-RPC:
      POST https://eth-mainnet.g.alchemy.com/v2/{key}
      {"method": "eth_getStorageAt", "params": [address, slot, "latest"]}

    Recommended cron: every 15 minutes (96 calls/day per contract)
    """

    # EIP-1967 implementation slot
    IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    # EIP-1967 admin slot (for admin changes)
    ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
    # EIP-1967 beacon slot
    BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

    def __init__(self, state: State, notifier: Notifier):
        self.state = state
        self.notifier = notifier

    def check_all(self, notify_channels: list[str]) -> list[Alert]:
        """Check all watched proxies for implementation changes."""
        alerts = []
        for label, config in PROXY_WATCHLIST.items():
            try:
                alert = self._check_proxy(label, config, notify_channels)
                if alert:
                    alerts.append(alert)
                time.sleep(0.3)  # Rate limit
            except Exception as e:
                logger.error(f"Proxy check failed for {label}: {e}")
        return alerts

    def _check_proxy(self, label: str, config: dict, notify_channels: list[str]) -> Optional[Alert]:
        """Check a single proxy for implementation change."""
        address = config["address"]
        chain = config.get("chain", "ethereum")
        bounty_url = config.get("bounty_url", "")
        max_bounty = config.get("max_bounty", 0)

        current_impl = self._read_storage_slot(address, self.IMPL_SLOT, chain)
        if not current_impl or current_impl == "0x" + "0" * 64:
            # Not a standard EIP-1967 proxy, try Etherscan's proxy detection
            current_impl = self._etherscan_get_implementation(address, chain)
            if not current_impl:
                logger.debug(f"{label}: not a detectable proxy or empty slot")
                return None

        # Normalize to checksum-style
        current_impl = current_impl.lower().strip()

        saved_impl = self.state.get("proxy_impl", label)

        # First run: save and return
        if saved_impl is None:
            self.state.set("proxy_impl", label, current_impl)
            console.print(f"  [dim]{label}: impl = {current_impl[-10:]}[/dim]")
            return None

        if current_impl == saved_impl:
            return None

        # UPGRADE DETECTED
        self.state.set("proxy_impl", label, current_impl)

        # Extract the address from the storage slot value (last 40 hex chars)
        impl_address = "0x" + current_impl[-40:]
        old_impl_address = "0x" + saved_impl[-40:]

        explorer_base = {
            "ethereum": "https://etherscan.io",
            "arbitrum": "https://arbiscan.io",
            "base": "https://basescan.org",
            "optimism": "https://optimistic.etherscan.io",
        }.get(chain, "https://etherscan.io")

        alert = Alert(
            id=f"proxy_upgrade:{label}:{current_impl[-10:]}",
            alert_type="proxy_upgrade",
            target=label,
            title=f"PROXY UPGRADE: {label}",
            details=(
                f"Implementation changed!\n"
                f"Old: {old_impl_address}\n"
                f"New: {impl_address}\n"
                f"Chain: {chain}\n"
                f"Proxy: {address}\n"
                f"ACTION: Diff old vs new implementation code immediately."
            ),
            url=f"{explorer_base}/address/{impl_address}#code",
            bounty_url=bounty_url,
            max_bounty=max_bounty,
            priority_score=90.0,  # Proxy upgrades are always high priority
            timestamp=datetime.now(timezone.utc).isoformat(),
            chain=chain,
            address=address,
            raw_data={
                "old_impl": old_impl_address,
                "new_impl": impl_address,
                "proxy": address,
            },
        )

        self.notifier.send(alert, notify_channels)
        return alert

    def _read_storage_slot(self, address: str, slot: str, chain: str) -> Optional[str]:
        """Read a storage slot using Alchemy JSON-RPC or Etherscan."""

        # Method 1: Alchemy JSON-RPC (preferred, no rate limit issues)
        if ALCHEMY_API_KEY:
            chain_prefix = {
                "ethereum": "eth-mainnet",
                "arbitrum": "arb-mainnet",
                "base": "base-mainnet",
                "optimism": "opt-mainnet",
            }.get(chain, "eth-mainnet")

            try:
                resp = requests.post(
                    f"https://{chain_prefix}.g.alchemy.com/v2/{ALCHEMY_API_KEY}",
                    json={
                        "jsonrpc": "2.0",
                        "method": "eth_getStorageAt",
                        "params": [address, slot, "latest"],
                        "id": 1,
                    },
                    timeout=10,
                )
                data = resp.json()
                return data.get("result")
            except Exception as e:
                logger.debug(f"Alchemy call failed: {e}")

        # Method 2: Etherscan API
        explorer = EXPLORERS.get(chain)
        if not explorer or not explorer["key"]:
            return None

        try:
            resp = requests.get(
                explorer["api"],
                params={
                    "module": "proxy",
                    "action": "eth_getStorageAt",
                    "address": address,
                    "position": slot,
                    "tag": "latest",
                    "apikey": explorer["key"],
                },
                timeout=10,
            )
            data = resp.json()
            return data.get("result")
        except Exception as e:
            logger.debug(f"Etherscan storage read failed: {e}")
            return None

    def _etherscan_get_implementation(self, address: str, chain: str) -> Optional[str]:
        """Use Etherscan's getsourcecode which returns Implementation for verified proxies."""
        explorer = EXPLORERS.get(chain)
        if not explorer or not explorer["key"]:
            return None

        try:
            resp = requests.get(
                explorer["api"],
                params={
                    "module": "contract",
                    "action": "getsourcecode",
                    "address": address,
                    "apikey": explorer["key"],
                },
                timeout=10,
            )
            data = resp.json()
            if data.get("status") == "1" and data.get("result"):
                impl = data["result"][0].get("Implementation", "")
                if impl:
                    return "0x" + "0" * 24 + impl[2:].lower()
        except Exception:
            pass
        return None
