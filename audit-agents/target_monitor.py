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
    DATA_DIR,
    STATE_FILE,
    LOG_FILE,
    POLL_INTERVAL,
    GITHUB_TOKEN,
    ALCHEMY_API_KEY,
    EXPLORERS,
)


# ---------------------------------------------------------------------------
# Data Models + State (migrated to monitor.state)
# ---------------------------------------------------------------------------

from monitor.state import Alert, State
from monitor.notifier import Notifier
from monitor.github import GitHubMonitor
from monitor.proxy import ProxyUpgradeMonitor
from monitor.deployment import DeploymentMonitor


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
