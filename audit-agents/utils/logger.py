"""Colored logging utility for audit agents."""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

def banner():
    console.print(Panel.fit(
        "[bold cyan]Web3 Audit Agents[/bold cyan]\n"
        "[dim]Multi-Agent Smart Contract Security Scanner[/dim]",
        border_style="cyan"
    ))

def agent_start(name: str, description: str):
    console.print(f"\n[bold yellow][AGENT][/bold yellow] {name}: {description}")

def agent_done(name: str, findings: int):
    color = "red" if findings > 0 else "green"
    console.print(f"[bold {color}][DONE][/bold {color}] {name}: {findings} finding(s)")

def finding(severity: str, title: str, location: str = ""):
    colors = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
    style = colors.get(severity.upper(), "white")
    loc = f" @ {location}" if location else ""
    console.print(f"  [{style}][{severity.upper()}][/{style}] {title}{loc}")

def info(msg: str):
    console.print(f"[dim]  > {msg}[/dim]")

def error(msg: str):
    console.print(f"[bold red][ERROR][/bold red] {msg}")

def results_table(findings_list: list):
    table = Table(title="Audit Findings Summary", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Agent", width=20)
    table.add_column("Finding", width=50)
    table.add_column("Location", width=30)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings_list, key=lambda f: severity_order.get(f.get("severity", "INFO").upper(), 5))
    for f in sorted_findings:
        sev = f.get("severity", "INFO").upper()
        colors = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
        style = colors.get(sev, "white")
        table.add_row(
            f"[{style}]{sev}[/{style}]",
            f.get("agent", ""),
            f.get("title", ""),
            f.get("location", "")
        )
    console.print(table)
