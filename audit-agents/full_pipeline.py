#!/usr/bin/env python3
"""
Full Pipeline — Fetch contract, audit, and generate PoC in one command.
=========================================================================
The complete bug bounty workflow in a single command.

Usage:
    python full_pipeline.py 0xADDRESS
    python full_pipeline.py 0xADDRESS --chain polygon
    python full_pipeline.py path/to/contract.sol --local
    python full_pipeline.py 0xADDRESS --chain eth --agents reentrancy,oracle --poc
"""
import sys
import os
import argparse
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import logger
from contract_fetcher import fetch_contract
from audit import run_audit, scan_directory
from report_generator import generate_markdown_report, generate_json_report
from poc_generator import generate_poc


def full_pipeline(target: str, chain: str = "eth", local: bool = False,
                  agent_names: list[str] | None = None, generate_pocs: bool = True):
    """Run the complete audit pipeline."""
    logger.banner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Step 1: Get contract source
    logger.console.print("\n[bold cyan]═══ STEP 1: Acquire Contract Source ═══[/bold cyan]\n")

    if local:
        sol_files = [target] if target.endswith('.sol') else list(Path(target).rglob("*.sol"))
        logger.console.print(f"[*] Local mode: {len(sol_files) if isinstance(sol_files, list) else 1} file(s)")
    else:
        output_dir = f"contracts/{target[:10]}_{timestamp}"
        sol_files = fetch_contract(target, chain, output_dir)
        if not sol_files:
            logger.error("Failed to fetch contract. Check address and API key.")
            return

    # Step 2: Run audit
    logger.console.print("\n[bold cyan]═══ STEP 2: Multi-Agent Audit ═══[/bold cyan]\n")

    all_findings = []
    files_to_audit = sol_files if isinstance(sol_files, list) else [sol_files]

    for sol_file in files_to_audit:
        if not sol_file.endswith('.sol'):
            continue
        findings = run_audit(sol_file, agent_names)
        all_findings.extend(findings)

    if not all_findings:
        logger.console.print("[green]No findings detected.[/green]")
        return

    # Step 3: Generate reports
    logger.console.print("\n[bold cyan]═══ STEP 3: Generate Reports ═══[/bold cyan]\n")

    reports_dir = Path("reports") / timestamp
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Markdown report
    md_report = generate_markdown_report(all_findings, target)
    md_path = reports_dir / "audit_report.md"
    md_path.write_text(md_report, encoding="utf-8")
    logger.console.print(f"  [+] Markdown report: {md_path}")

    # JSON report
    json_report = generate_json_report(all_findings, target)
    json_path = reports_dir / "audit_report.json"
    json_path.write_text(json_report, encoding="utf-8")
    logger.console.print(f"  [+] JSON report: {json_path}")

    # Step 4: Generate PoCs
    if generate_pocs:
        logger.console.print("\n[bold cyan]═══ STEP 4: Generate PoC Templates ═══[/bold cyan]\n")

        poc_dir = f"foundry-workspace/test/poc/{timestamp}"
        report_data = json.loads(json_report)
        generated = 0

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for finding in report_data.get("findings", []):
            sev = finding.get("severity", "INFO")
            if severity_order.get(sev, 4) <= 2:  # MEDIUM and above
                result = generate_poc(finding, poc_dir)
                if result:
                    logger.console.print(f"  [+] PoC: {result}")
                    generated += 1

        logger.console.print(f"\n  Generated {generated} PoC template(s)")
        logger.console.print(f"  [dim]Edit and run: cd foundry-workspace && forge test --match-path test/poc/ -vvvv[/dim]")

    # Summary
    severity_counts = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    logger.console.print("\n[bold cyan]═══ PIPELINE COMPLETE ═══[/bold cyan]\n")
    logger.console.print(f"[bold]Target:[/bold] {target}")
    logger.console.print(f"[bold]Total findings:[/bold] {len(all_findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            colors = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
            logger.console.print(f"  [{colors[sev]}]{sev}: {count}[/{colors[sev]}]")

    logger.console.print(f"\n[bold]Reports:[/bold] {reports_dir}/")
    logger.console.print(f"[bold]Next steps:[/bold]")
    logger.console.print(f"  1. Review findings in {md_path}")
    logger.console.print(f"  2. Edit PoC templates and write working exploits")
    logger.console.print(f"  3. Submit to bug bounty platform with PoC")


def main():
    parser = argparse.ArgumentParser(description="Full bug bounty pipeline: fetch → audit → PoC")
    parser.add_argument("target", help="Contract address (0x...) or local path")
    parser.add_argument("--chain", "-c", default="eth",
                        choices=["eth", "bsc", "polygon", "arbitrum", "optimism", "base", "avalanche"],
                        help="Blockchain (default: eth)")
    parser.add_argument("--local", "-l", action="store_true",
                        help="Target is a local file/directory")
    parser.add_argument("--agents", "-a", default=None,
                        help="Comma-separated agent list")
    parser.add_argument("--no-poc", action="store_true",
                        help="Skip PoC generation")

    args = parser.parse_args()
    agent_names = args.agents.split(",") if args.agents else None

    full_pipeline(
        target=args.target,
        chain=args.chain,
        local=args.local,
        agent_names=agent_names,
        generate_pocs=not args.no_poc,
    )


if __name__ == "__main__":
    main()
