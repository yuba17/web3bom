"""CLI entry point for monitor package."""
import argparse
import logging

from rich.panel import Panel

from monitor.config import (
    console,
    DATA_DIR,
    STATE_FILE,
    LOG_FILE,
)
from monitor.orchestrator import score_target, run_monitors, daemon_mode


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
