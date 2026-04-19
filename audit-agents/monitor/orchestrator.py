"""Orchestration for monitor package."""
import time
from datetime import datetime, timezone

from rich.table import Table

from monitor.config import (
    console,
    logger,
    POLL_INTERVAL,
    GITHUB_TOKEN,
    ALCHEMY_API_KEY,
    EXPLORERS,
)
from monitor.state import Alert, State
from monitor.notifier import Notifier
from monitor.github import GitHubMonitor
from monitor.proxy import ProxyUpgradeMonitor
from monitor.deployment import DeploymentMonitor


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
