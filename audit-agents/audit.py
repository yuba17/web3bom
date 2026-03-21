#!/usr/bin/env python3
"""
Web3 Audit Agents — Multi-Agent Smart Contract Security Scanner
================================================================
Orchestrates multiple specialized agents to analyze Solidity contracts
for vulnerabilities. Each agent focuses on a specific attack surface.

Usage:
    python audit.py <contract.sol>
    python audit.py <contract.sol> --report markdown
    python audit.py <contract.sol> --agents reentrancy,access_control
    python audit.py contracts/ --recursive
"""
import sys
import os
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import logger
from utils.solidity_parser import parse_solidity
from agents.base_agent import BaseAgent
from agents.pattern_agent import PatternAgent
from agents.reentrancy_agent import ReentrancyAgent
from agents.access_control_agent import AccessControlAgent
from agents.oracle_agent import OracleAgent
from agents.logic_agent import LogicAgent
from agents.gas_agent import GasOptimizationAgent
from agents.slither_agent import SlitherAgent
from agents.proxy_agent import ProxyAgent
from agents.token_agent import TokenAgent
from report_generator import generate_markdown_report, generate_json_report


# All available agents
ALL_AGENTS: dict[str, type[BaseAgent]] = {
    "pattern": PatternAgent,
    "reentrancy": ReentrancyAgent,
    "access_control": AccessControlAgent,
    "oracle": OracleAgent,
    "logic": LogicAgent,
    "proxy": ProxyAgent,
    "token": TokenAgent,
    "gas": GasOptimizationAgent,
    "slither": SlitherAgent,
}


def run_audit(file_path: str, agent_names: list[str] | None = None, report_format: str = "table") -> list[dict]:
    """Run all agents against a Solidity file and return findings."""
    logger.banner()
    logger.console.print(f"\n[bold]Target:[/bold] {file_path}")
    logger.console.print(f"[bold]Date:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Parse contract
    try:
        contract = parse_solidity(file_path)
    except Exception as e:
        logger.error(f"Failed to parse {file_path}: {e}")
        return []

    logger.console.print(f"[dim]Contract: {contract.name or 'Unknown'}[/dim]")
    logger.console.print(f"[dim]Solidity: {contract.solidity_version or 'Unknown'}[/dim]")
    logger.console.print(f"[dim]Functions: {len(contract.functions)}[/dim]")
    logger.console.print(f"[dim]Imports: {len(contract.imports)}[/dim]")
    logger.console.print(f"[dim]Uses Proxy: {contract.uses_proxy}[/dim]")
    if contract.inheritance:
        logger.console.print(f"[dim]Inherits: {', '.join(contract.inheritance)}[/dim]")

    # Select agents
    if agent_names:
        agents_to_run = {k: v for k, v in ALL_AGENTS.items() if k in agent_names}
    else:
        agents_to_run = ALL_AGENTS

    # Run agents
    all_findings = []
    for name, agent_class in agents_to_run.items():
        agent = agent_class()
        logger.agent_start(agent.name, agent.description)

        try:
            findings = agent.analyze(contract)
            for f in findings:
                logger.finding(f.severity, f.title, f.location)
                all_findings.append(f.to_dict())
            logger.agent_done(agent.name, len(findings))
        except Exception as e:
            logger.error(f"Agent {name} failed: {e}")

    # Summary
    logger.console.print("\n")
    if all_findings:
        logger.results_table(all_findings)
    else:
        logger.console.print("[bold green]No findings! (or all agents skipped)[/bold green]")

    # Severity counts
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.console.print("\n[bold]Summary:[/bold]")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            colors = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
            logger.console.print(f"  [{colors[sev]}]{sev}: {count}[/{colors[sev]}]")

    return all_findings


def scan_directory(directory: str, agent_names: list[str] | None = None, report_format: str = "table") -> list[dict]:
    """Scan all .sol files in a directory."""
    sol_files = list(Path(directory).rglob("*.sol"))
    if not sol_files:
        logger.error(f"No .sol files found in {directory}")
        return []

    logger.console.print(f"[bold]Found {len(sol_files)} Solidity files[/bold]\n")
    all_findings = []
    for sol_file in sol_files:
        findings = run_audit(str(sol_file), agent_names, report_format)
        all_findings.extend(findings)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Web3 Audit Agents - Smart Contract Security Scanner")
    parser.add_argument("target", help="Solidity file or directory to audit")
    parser.add_argument("--agents", help="Comma-separated list of agents to run", default=None)
    parser.add_argument("--report", choices=["table", "markdown", "json"], default="table",
                        help="Output report format")
    parser.add_argument("--output", "-o", help="Output file for report", default=None)
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directory recursively")

    args = parser.parse_args()
    agent_names = args.agents.split(",") if args.agents else None
    target = Path(args.target)

    if target.is_dir() or args.recursive:
        findings = scan_directory(str(target), agent_names, args.report)
    elif target.is_file():
        findings = run_audit(str(target), agent_names, args.report)
    else:
        logger.error(f"Target not found: {args.target}")
        sys.exit(1)

    # Generate report file if requested
    if args.output and findings:
        output_path = args.output
        if args.report == "markdown":
            report = generate_markdown_report(findings, str(target))
            Path(output_path).write_text(report, encoding="utf-8")
        elif args.report == "json":
            report = generate_json_report(findings, str(target))
            Path(output_path).write_text(report, encoding="utf-8")
        logger.console.print(f"\n[bold green]Report saved to: {output_path}[/bold green]")


if __name__ == "__main__":
    main()
