#!/usr/bin/env python3
"""
Quick Start — Interactive guide to using the audit system.
============================================================
Walks you through the available tools and their usage.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console(force_terminal=True)


def main():
    console.print(Panel.fit(
        "[bold cyan]Web3 Bug Bounty Audit System[/bold cyan]\n"
        "[dim]Your complete toolkit for finding vulnerabilities[/dim]",
        border_style="cyan",
    ))

    # Tools overview
    table = Table(title="Available Commands", box=box.ROUNDED, show_lines=True)
    table.add_column("Command", style="bold green", width=50)
    table.add_column("Description", width=45)

    commands = [
        ("python audit.py <file.sol>", "Scan a contract with all 9 agents"),
        ("python audit.py <file.sol> --report markdown -o report.md", "Generate markdown report"),
        ("python audit.py <dir/> --recursive", "Scan all .sol files in directory"),
        ("python audit.py <file> --agents reentrancy,oracle", "Run specific agents only"),
        ("", ""),
        ("python contract_fetcher.py 0xADDRESS", "Download contract from Etherscan"),
        ("python contract_fetcher.py 0xADDR --chain polygon", "Download from other chains"),
        ("python contract_fetcher.py 0xADDR --audit", "Download and auto-audit"),
        ("", ""),
        ("python full_pipeline.py 0xADDRESS", "Full pipeline: fetch+audit+PoC"),
        ("python full_pipeline.py file.sol --local", "Pipeline on local file"),
        ("", ""),
        ("python poc_generator.py reports/audit.json", "Generate Foundry PoC templates"),
        ("python bounty_monitor.py", "Show active bounty programs"),
        ("python bounty_monitor.py --min-bounty 500000", "Filter by minimum reward"),
        ("python bounty_monitor.py --category lending", "Filter by category"),
    ]

    for cmd, desc in commands:
        if cmd:
            table.add_row(cmd, desc)
        else:
            table.add_row("─" * 40, "─" * 35)

    console.print(table)

    # Agents
    console.print("\n[bold]9 Specialized Audit Agents:[/bold]")
    agents = [
        ("PatternScanner", "Known vuln patterns via regex", "delegatecall, selfdestruct, tx.origin..."),
        ("ReentrancyDetector", "Classic + cross-function reentrancy", "CEI violations, missing guards"),
        ("AccessControlDetector", "Missing/broken access control", "#1 Web3 vuln — $953M+ losses"),
        ("OracleDetector", "Oracle + flash loan risks", "Spot price, stale feeds, balance-as-price"),
        ("LogicDetector", "Business logic bugs", "Rounding, first depositor, unchecked returns"),
        ("ProxyDetector", "Proxy/upgradeability", "Uninitialized impl, storage collision"),
        ("TokenDetector", "Token interaction bugs", "Fee-on-transfer, ERC777 hooks, approvals"),
        ("GasOptimizer", "Gas + DoS vectors", "Storage in loops, unbounded iterations"),
        ("SlitherAnalyzer", "Slither integration", "40+ detector categories"),
    ]

    agent_table = Table(box=box.SIMPLE)
    agent_table.add_column("Agent", style="cyan", width=22)
    agent_table.add_column("Focus", width=30)
    agent_table.add_column("Detects", style="dim", width=40)
    for name, focus, detects in agents:
        agent_table.add_row(name, focus, detects)
    console.print(agent_table)

    # Workflow
    console.print("\n[bold]Recommended Workflow:[/bold]")
    console.print("""
[cyan]1.[/cyan] Find target:     python bounty_monitor.py --category lending
[cyan]2.[/cyan] Fetch contract:  python contract_fetcher.py 0xADDRESS --chain eth
[cyan]3.[/cyan] Run audit:       python audit.py contracts/ --recursive --report markdown -o report.md
[cyan]4.[/cyan] Generate PoCs:   python poc_generator.py reports/audit.json
[cyan]5.[/cyan] Write exploit:   cd foundry-workspace && forge test --match-path test/poc/ -vvvv
[cyan]6.[/cyan] Submit report to Immunefi/Code4rena/Sherlock
""")

    # Quick tips
    console.print("[bold]Quick Tips:[/bold]")
    console.print("  [dim]- Start with --agents access_control,oracle for highest-impact bugs[/dim]")
    console.print("  [dim]- Always fork mainnet when writing PoCs: forge test --fork-url $ETH_RPC_URL[/dim]")
    console.print("  [dim]- Focus on ONE protocol for 2-3 weeks before moving on[/dim]")
    console.print("  [dim]- Read 3 Solodit findings daily: https://solodit.xyz[/dim]")
    console.print("  [dim]- Fill in .env with your Etherscan + Alchemy API keys[/dim]")


if __name__ == "__main__":
    main()
