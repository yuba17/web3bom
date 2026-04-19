"""Notifier class for monitor package."""
import json
from dataclasses import asdict

import requests
from rich.panel import Panel

from monitor.config import (
    ALERTS_FILE,
    DISCORD_WEBHOOK_URL,
    TELEGRAM_BOT_TOKEN,
    TELEGRAM_CHAT_ID,
    console,
    logger,
)
from monitor.state import Alert


class Notifier:
    """Send alerts via Telegram, Discord, console, and file."""

    def send(self, alert: Alert, channels: list[str]):
        msg = self._format(alert)

        # Always save to file
        self._save_to_file(alert)

        if "console" in channels:
            color = "red" if alert.priority_score >= 80 else "yellow" if alert.priority_score >= 50 else "white"
            console.print(Panel(msg, title=f"[bold {color}]{alert.alert_type.upper()}: {alert.target}[/bold {color}]"))

        if "telegram" in channels and TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            self._send_telegram(msg)

        if "discord" in channels and DISCORD_WEBHOOK_URL:
            self._send_discord(alert)

    def _format(self, a: Alert) -> str:
        priority_label = "CRITICAL" if a.priority_score >= 80 else "HIGH" if a.priority_score >= 50 else "MEDIUM"
        return (
            f"[{priority_label}] {a.title}\n"
            f"Type:     {a.alert_type}\n"
            f"Target:   {a.target}\n"
            f"Bounty:   ${a.max_bounty:,.0f}\n"
            f"Priority: {a.priority_score:.0f}/100\n"
            f"URL:      {a.url}\n"
            f"Bounty:   {a.bounty_url}\n"
            f"Details:  {a.details}\n"
            f"Time:     {a.timestamp}\n"
        )

    def _save_to_file(self, alert: Alert):
        existing = []
        if ALERTS_FILE.exists():
            try:
                existing = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        existing.append(asdict(alert))
        # Keep last 500 alerts
        existing = existing[-500:]
        ALERTS_FILE.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")

    def _send_telegram(self, msg: str):
        try:
            # Escape markdown special chars for Telegram
            text = msg.replace("_", "\\_").replace("*", "\\*").replace("[", "\\[")
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
        except Exception as e:
            logger.error(f"Telegram send failed: {e}")

    def _send_discord(self, alert: Alert):
        try:
            color = 0xFF0000 if alert.priority_score >= 80 else 0xFFA500 if alert.priority_score >= 50 else 0x808080
            payload = {
                "embeds": [{
                    "title": f"[{alert.alert_type.upper()}] {alert.title}",
                    "description": alert.details,
                    "url": alert.url,
                    "color": color,
                    "fields": [
                        {"name": "Target", "value": alert.target, "inline": True},
                        {"name": "Bounty", "value": f"${alert.max_bounty:,.0f}", "inline": True},
                        {"name": "Priority", "value": f"{alert.priority_score:.0f}/100", "inline": True},
                        {"name": "Bounty Program", "value": alert.bounty_url, "inline": False},
                    ],
                    "timestamp": alert.timestamp,
                }]
            }
            requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
        except Exception as e:
            logger.error(f"Discord send failed: {e}")
