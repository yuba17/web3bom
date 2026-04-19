#!/usr/bin/env python3
"""
Target Monitor — GitHub Commits, Proxy Upgrades, New Deployments
=================================================================
Complements bounty_monitor_v2.py (which tracks new bounty programs).
This script monitors EXISTING targets for exploitable changes:

  1. GitHub commits after last audit date (new code = new bugs)
  2. Proxy contract upgrades (implementation changes on-chain)
  3. New contract deployments from known deployer addresses

Usage:
    python target_monitor.py                       # Run all monitors
    python target_monitor.py --monitor github      # GitHub only
    python target_monitor.py --monitor onchain     # Proxy + deployments only
    python target_monitor.py --daemon              # Run continuously
    python target_monitor.py --notify telegram     # Send Telegram alerts

Environment variables (in .env):
    GITHUB_TOKEN            GitHub personal access token (for API rate limits)
    ETHERSCAN_API_KEY       Etherscan API key
    ARBISCAN_API_KEY        Arbiscan API key
    BASESCAN_API_KEY        BaseScan API key
    ALCHEMY_API_KEY         Alchemy API key (optional, for WebSocket monitoring)
    BOUNTY_TELEGRAM_TOKEN   Telegram bot token
    BOUNTY_TELEGRAM_CHAT_ID Telegram chat ID
    BOUNTY_DISCORD_WEBHOOK  Discord webhook URL
"""

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from rich.table import Table
from rich.panel import Panel

from monitor.config import (
    console,
    logger,
    BASE_DIR,
    DATA_DIR,
    STATE_FILE,
    ALERTS_FILE,
    LOG_FILE,
    POLL_INTERVAL,
    _get_key,
    GITHUB_TOKEN,
    ETHERSCAN_API_KEY,
    ARBISCAN_API_KEY,
    BASESCAN_API_KEY,
    OPTIMISM_API_KEY,
    ALCHEMY_API_KEY,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    DISCORD_WEBHOOK_URL,
    EXPLORERS,
    PROXY_WATCHLIST,
    DEPLOYER_WATCHLIST,
)


# ---------------------------------------------------------------------------
# Data Models + State (migrated to monitor.state)
# ---------------------------------------------------------------------------

from monitor.state import Alert, State
from monitor.notifier import Notifier
from monitor.github import GitHubMonitor


# ---------------------------------------------------------------------------
# Monitor 2: Proxy Upgrade Detection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Monitor 3: New Contract Deployments
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Target Scoring (for new targets discovered via any monitor)
# ---------------------------------------------------------------------------

def score_target(
    max_bounty: float,
    days_since_launch: int,
    audit_count: int,
    platform: str = "immunefi",
) -> dict:
    """
    Score a target for prioritization.

    Formula:
      score = (max_bounty * freshness_multiplier * (1/audit_count)) / competition_estimate

    Returns dict with score, breakdown, and recommendation.
    """
    # Freshness multiplier
    if days_since_launch <= 7:
        freshness = 3.0
        freshness_label = "< 1 week (3x)"
    elif days_since_launch <= 30:
        freshness = 2.0
        freshness_label = "< 1 month (2x)"
    elif days_since_launch <= 90:
        freshness = 1.0
        freshness_label = "< 3 months (1x)"
    else:
        freshness = 0.5
        freshness_label = "> 3 months (0.5x)"

    # Audit count factor
    effective_audits = max(1, audit_count)
    audit_factor = 1.0 / effective_audits
    audit_label = f"{audit_count} audits (1/{effective_audits})"

    # Competition estimate by platform
    competition_map = {
        "immunefi": 50,       # Many hunters, but less time pressure
        "code4rena": 200,     # Very competitive for high-payout
        "sherlock": 150,      # Competitive but smaller pool
        "cantina": 80,        # Smaller, more senior pool
        "codehawks": 60,      # Newer, less crowded
        "hackenproof": 30,    # Less known, fewer hunters
    }
    competition = competition_map.get(platform.lower(), 100)
    comp_label = f"{platform} (est. {competition} hunters)"

    # Raw score (normalize to 0-100 range)
    raw = (max_bounty * freshness * audit_factor) / competition
    # Normalize: $1M bounty, 1 week old, 0 audits, low-comp platform = ~100
    normalized = min(100, (raw / 1000))

    recommendation = "SKIP"
    if normalized >= 70:
        recommendation = "PRIORITY -- start immediately"
    elif normalized >= 40:
        recommendation = "INTERESTING -- review this week"
    elif normalized >= 15:
        recommendation = "MAYBE -- if nothing better"

    return {
        "score": round(normalized, 2),
        "raw_score": round(raw, 2),
        "recommendation": recommendation,
        "breakdown": {
            "max_bounty": f"${max_bounty:,.0f}",
            "freshness": freshness_label,
            "audit_factor": audit_label,
            "competition": comp_label,
        },
        "formula": f"({max_bounty:,.0f} * {freshness} * {audit_factor:.2f}) / {competition} = {raw:,.2f}",
    }


# ---------------------------------------------------------------------------
# Main Orchestrator
# ---------------------------------------------------------------------------

def run_monitors(
    monitors: list[str] | None = None,
    notify_channels: list[str] | None = None,
) -> list[Alert]:
    """Run all or selected monitors."""
    notify_channels = notify_channels or ["console"]
    monitors = monitors or ["github", "onchain"]

    state = State()
    notifier = Notifier()
    all_alerts = []

    if "github" in monitors:
        console.print("\n[bold]--- GitHub Commit Monitor ---[/bold]")
        if not GITHUB_TOKEN:
            console.print("[yellow]WARNING: No GITHUB_TOKEN set. Rate limited to 60 req/hr.[/yellow]")
        gh = GitHubMonitor(state, notifier)
        alerts = gh.check_all(notify_channels)
        all_alerts.extend(alerts)
        console.print(f"  GitHub: {len(alerts)} alert(s)")

    if "onchain" in monitors or "proxy" in monitors:
        console.print("\n[bold]--- Proxy Upgrade Monitor ---[/bold]")
        has_key = any(v["key"] for v in EXPLORERS.values()) or ALCHEMY_API_KEY
        if not has_key:
            console.print("[yellow]WARNING: No ETHERSCAN_API_KEY or ALCHEMY_API_KEY set.[/yellow]")
        proxy = ProxyUpgradeMonitor(state, notifier)
        alerts = proxy.check_all(notify_channels)
        all_alerts.extend(alerts)
        console.print(f"  Proxy upgrades: {len(alerts)} alert(s)")

    if "onchain" in monitors or "deploy" in monitors:
        console.print("\n[bold]--- Deployment Monitor ---[/bold]")
        deploy = DeploymentMonitor(state, notifier)
        alerts = deploy.check_all(notify_channels)
        all_alerts.extend(alerts)
        console.print(f"  New deployments: {len(alerts)} alert(s)")

    # Summary
    if all_alerts:
        console.print(f"\n[bold green]Total alerts: {len(all_alerts)}[/bold green]")
        table = Table(title="Alerts Summary")
        table.add_column("Priority", width=10, justify="right")
        table.add_column("Type", width=18)
        table.add_column("Target", width=35)
        table.add_column("Title", width=45)
        table.add_column("Bounty", width=14, justify="right")

        for a in sorted(all_alerts, key=lambda x: x.priority_score, reverse=True):
            style = "bold red" if a.priority_score >= 80 else "yellow" if a.priority_score >= 50 else ""
            table.add_row(
                f"{a.priority_score:.0f}",
                a.alert_type,
                a.target,
                a.title,
                f"${a.max_bounty:,.0f}",
                style=style,
            )
        console.print(table)
    else:
        console.print(f"\n[dim]No alerts. All monitored targets are unchanged.[/dim]")

    return all_alerts


def daemon_mode(monitors=None, notify_channels=None):
    """Run continuously."""
    console.print(f"[bold]Daemon mode: checking every {POLL_INTERVAL}s[/bold]")
    while True:
        try:
            console.print(f"\n[dim]=== Scan at {datetime.now(timezone.utc).isoformat()} ===[/dim]")
            run_monitors(monitors, notify_channels)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped.[/yellow]")
            break
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            console.print(f"[red]Error: {e}[/red]")

        time.sleep(POLL_INTERVAL)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Target Monitor: GitHub commits, proxy upgrades, new deployments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python target_monitor.py                          # Run all monitors once
  python target_monitor.py --monitor github         # GitHub commits only
  python target_monitor.py --monitor onchain        # Proxy upgrades + deployments
  python target_monitor.py --monitor proxy          # Proxy upgrades only
  python target_monitor.py --monitor deploy         # New deployments only
  python target_monitor.py --daemon                 # Run continuously (10 min interval)
  python target_monitor.py --notify telegram        # Send alerts to Telegram
  python target_monitor.py --score 1000000 7 0 immunefi  # Score a target

Environment variables:
  GITHUB_TOKEN            GitHub PAT (recommended, 5000 req/hr vs 60)
  ETHERSCAN_API_KEY       For proxy/deployment monitoring
  ALCHEMY_API_KEY         Alternative RPC for proxy slot reads
  BOUNTY_TELEGRAM_TOKEN   Telegram bot token
  BOUNTY_TELEGRAM_CHAT_ID Telegram chat ID
  BOUNTY_DISCORD_WEBHOOK  Discord webhook URL

Cron setup (recommended):
  # Bounty platforms: every 30 min
  */30 * * * * cd /path/to/audit-agents && python bounty_monitor_v2.py --notify telegram

  # GitHub commits: every 30 min
  */30 * * * * cd /path/to/audit-agents && python target_monitor.py --monitor github --notify telegram

  # On-chain (proxy + deploy): every 15 min
  */15 * * * * cd /path/to/audit-agents && python target_monitor.py --monitor onchain --notify telegram
        """,
    )
    parser.add_argument(
        "--monitor", "-m", nargs="+",
        choices=["github", "onchain", "proxy", "deploy"],
        help="Which monitors to run (default: all)",
    )
    parser.add_argument(
        "--notify", "-n", nargs="+",
        choices=["console", "telegram", "discord"],
        default=["console"],
        help="Notification channels",
    )
    parser.add_argument(
        "--daemon", "-d", action="store_true",
        help="Run continuously",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose logging",
    )
    parser.add_argument(
        "--reset", action="store_true",
        help="Clear all saved state (re-initialize)",
    )
    parser.add_argument(
        "--score", nargs=4,
        metavar=("MAX_BOUNTY", "DAYS_OLD", "AUDIT_COUNT", "PLATFORM"),
        help="Score a target: max_bounty days_since_launch audit_count platform",
    )

    args = parser.parse_args()

    # Setup logging
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
        ],
    )

    # Score mode
    if args.score:
        result = score_target(
            max_bounty=float(args.score[0]),
            days_since_launch=int(args.score[1]),
            audit_count=int(args.score[2]),
            platform=args.score[3],
        )
        console.print(Panel(
            f"Score:          {result['score']}/100\n"
            f"Recommendation: {result['recommendation']}\n"
            f"Formula:        {result['formula']}\n"
            f"Max Bounty:     {result['breakdown']['max_bounty']}\n"
            f"Freshness:      {result['breakdown']['freshness']}\n"
            f"Audits:         {result['breakdown']['audit_factor']}\n"
            f"Competition:    {result['breakdown']['competition']}",
            title="Target Score",
        ))
        return

    # Reset state
    if args.reset:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
        console.print("[yellow]State cleared.[/yellow]")

    # Run monitors
    if args.daemon:
        daemon_mode(args.monitor, args.notify)
    else:
        run_monitors(args.monitor, args.notify)


if __name__ == "__main__":
    main()
