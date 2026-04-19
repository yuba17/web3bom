"""DeploymentMonitor for monitor package."""
import time
from datetime import datetime, timezone

import requests

from monitor.config import (
    DEPLOYER_WATCHLIST,
    EXPLORERS,
    logger,
)
from monitor.notifier import Notifier
from monitor.state import Alert, State


class DeploymentMonitor:
    """
    Watch deployer addresses for new contract deployments.

    Uses Etherscan API:
      GET /?module=account&action=txlist
        &address={deployer}
        &startblock={last_block}
        &sort=desc
        &apikey={key}

    Filter for: contract creation transactions (to == null or to == "")

    Recommended cron: every 15 minutes
    """

    def __init__(self, state: State, notifier: Notifier):
        self.state = state
        self.notifier = notifier

    def check_all(self, notify_channels: list[str]) -> list[Alert]:
        """Check all watched deployers for new deployments."""
        alerts = []
        for label, config in DEPLOYER_WATCHLIST.items():
            try:
                new_alerts = self._check_deployer(label, config, notify_channels)
                alerts.extend(new_alerts)
                time.sleep(0.3)  # Rate limit
            except Exception as e:
                logger.error(f"Deployment check failed for {label}: {e}")
        return alerts

    def _check_deployer(self, label: str, config: dict, notify_channels: list[str]) -> list[Alert]:
        """Check a deployer for new contract creation transactions."""
        address = config["address"]
        chain = config.get("chain", "ethereum")
        bounty_url = config.get("bounty_url", "")
        max_bounty = config.get("max_bounty", 0)

        explorer = EXPLORERS.get(chain)
        if not explorer or not explorer["key"]:
            logger.warning(f"No API key for {chain}, skipping {label}")
            return []

        # Get last checked block
        last_block = self.state.get("deployer_last_block", label) or 0

        # Fetch transactions from deployer since last block
        resp = requests.get(
            explorer["api"],
            params={
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": int(last_block) + 1,
                "endblock": 99999999,
                "sort": "desc",
                "apikey": explorer["key"],
            },
            timeout=15,
        )
        data = resp.json()

        if data.get("status") != "1" or not data.get("result"):
            # No new transactions or error
            return []

        txs = data["result"]
        if not isinstance(txs, list):
            return []

        # Filter for contract creation (to == "" or to is empty)
        creation_txs = []
        for tx in txs:
            to_addr = tx.get("to", "").strip()
            if to_addr == "" and tx.get("isError", "1") == "0":
                creation_txs.append(tx)

        # Also check internal transactions for CREATE/CREATE2
        try:
            resp2 = requests.get(
                explorer["api"],
                params={
                    "module": "account",
                    "action": "txlistinternal",
                    "address": address,
                    "startblock": int(last_block) + 1,
                    "endblock": 99999999,
                    "sort": "desc",
                    "apikey": explorer["key"],
                },
                timeout=15,
            )
            data2 = resp2.json()
            if data2.get("status") == "1" and isinstance(data2.get("result"), list):
                for tx in data2["result"]:
                    if tx.get("type", "").lower() == "create":
                        creation_txs.append(tx)
        except Exception:
            pass

        if not creation_txs:
            # Update last block even if no creations (so we don't re-check)
            if txs:
                newest_block = max(int(tx.get("blockNumber", 0)) for tx in txs)
                self.state.set("deployer_last_block", label, newest_block)
            return []

        # Update state
        newest_block = max(int(tx.get("blockNumber", 0)) for tx in txs)
        self.state.set("deployer_last_block", label, newest_block)

        # Build alerts
        alerts = []
        explorer_base = {
            "ethereum": "https://etherscan.io",
            "arbitrum": "https://arbiscan.io",
            "base": "https://basescan.org",
            "optimism": "https://optimistic.etherscan.io",
        }.get(chain, "https://etherscan.io")

        for tx in creation_txs:
            tx_hash = tx.get("hash", "unknown")
            contract_address = tx.get("contractAddress", "unknown")
            block = tx.get("blockNumber", "?")

            alert = Alert(
                id=f"deployment:{label}:{tx_hash[:16]}",
                alert_type="new_deployment",
                target=label,
                title=f"NEW DEPLOYMENT by {label}",
                details=(
                    f"New contract deployed!\n"
                    f"Contract: {contract_address}\n"
                    f"TX: {tx_hash}\n"
                    f"Block: {block}\n"
                    f"Chain: {chain}\n"
                    f"ACTION: Fetch source code and analyze for bugs."
                ),
                url=f"{explorer_base}/tx/{tx_hash}",
                bounty_url=bounty_url,
                max_bounty=max_bounty,
                priority_score=85.0,  # New deployments are high priority
                timestamp=datetime.now(timezone.utc).isoformat(),
                chain=chain,
                address=contract_address,
                raw_data={
                    "tx_hash": tx_hash,
                    "contract_address": contract_address,
                    "deployer": address,
                },
            )

            self.notifier.send(alert, notify_channels)
            alerts.append(alert)

        return alerts
