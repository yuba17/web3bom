#!/usr/bin/env python3
"""
Detection Engine — The Killer Bug Finder

Multi-layer vulnerability detection system that runs ALL analysis tools
against a target and consolidates findings.

Layers:
1. Static Analysis (Slither + Aderyn)
2. Invariant Matching + Foundry Fuzzing
3. Symbolic Execution (Halmos)
4. LLM Hypothesis Generation (via Claude Code sub-agents)
5. Exploit-Derived Pattern Matching (DeFiHackLabs patterns)

Usage:
    python detection_engine.py --source ./target/src --name "protocol" --output ./results/
    python detection_engine.py --source ./target/src --name "protocol" --layers static,invariant
    python detection_engine.py --source ./target/src --name "protocol" --fast  # layers 1+5 only
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from registry import get_registry, InvariantRegistry
from matcher import MatcherPipeline


# =============================================================================
# CONFIGURATION
# =============================================================================

SLITHER_BIN = "slither"
ADERYN_BIN = "aderyn"
HALMOS_BIN = "halmos"
FORGE_BIN = "forge"

FINDING_SEVERITIES = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class Finding:
    """A single detected vulnerability."""

    def __init__(self, title: str, severity: str, layer: str, description: str,
                 location: str = "", code_snippet: str = "", invariant_id: str = "",
                 confidence: float = 0.5, poc_hint: str = ""):
        self.title = title
        self.severity = severity.lower()
        self.layer = layer
        self.description = description
        self.location = location
        self.code_snippet = code_snippet
        self.invariant_id = invariant_id
        self.confidence = confidence
        self.poc_hint = poc_hint
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "layer": self.layer,
            "description": self.description,
            "location": self.location,
            "code_snippet": self.code_snippet,
            "invariant_id": self.invariant_id,
            "confidence": self.confidence,
            "poc_hint": self.poc_hint,
            "timestamp": self.timestamp,
        }

    def severity_score(self) -> int:
        return FINDING_SEVERITIES.get(self.severity, 0)

    def __repr__(self):
        return f"<Finding [{self.severity.upper()}] {self.title} (layer={self.layer}, conf={self.confidence:.0%})>"


class DetectionReport:
    """Consolidated report from all detection layers."""

    def __init__(self, target_name: str, source_dir: str):
        self.target_name = target_name
        self.source_dir = source_dir
        self.findings: list[Finding] = []
        self.layer_stats: dict[str, dict] = {}
        self.start_time = time.time()
        self.end_time: Optional[float] = None

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_layer_stats(self, layer: str, stats: dict):
        self.layer_stats[layer] = stats

    def finalize(self):
        self.end_time = time.time()

    def elapsed_minutes(self) -> float:
        end = self.end_time or time.time()
        return (end - self.start_time) / 60

    def to_dict(self) -> dict:
        return {
            "target": self.target_name,
            "source_dir": self.source_dir,
            "generated": datetime.now().isoformat(),
            "elapsed_minutes": round(self.elapsed_minutes(), 1),
            "total_findings": len(self.findings),
            "by_severity": {
                sev: sum(1 for f in self.findings if f.severity == sev)
                for sev in ["critical", "high", "medium", "low"]
            },
            "by_layer": {
                layer: sum(1 for f in self.findings if f.layer == layer)
                for layer in set(f.layer for f in self.findings)
            },
            "layer_stats": self.layer_stats,
            "findings": sorted(
                [f.to_dict() for f in self.findings],
                key=lambda x: FINDING_SEVERITIES.get(x["severity"], 0),
                reverse=True,
            ),
        }

    def print_summary(self):
        print(f"\n{'='*70}")
        print(f"DETECTION ENGINE REPORT: {self.target_name}")
        print(f"{'='*70}")
        print(f"Source: {self.source_dir}")
        print(f"Time: {self.elapsed_minutes():.1f} minutes")
        print(f"Total findings: {len(self.findings)}")
        print()

        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f.severity, []).append(f)

        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_sev:
                print(f"  {sev.upper()}: {len(by_sev[sev])}")
                for f in by_sev[sev]:
                    print(f"    [{f.layer:12s}] {f.title}")
                    if f.location:
                        print(f"                  @ {f.location}")

        print(f"\nLayer stats:")
        for layer, stats in self.layer_stats.items():
            print(f"  {layer}: {stats}")

        print(f"{'='*70}")


# =============================================================================
# LAYER 1: STATIC ANALYSIS
# =============================================================================

def run_static_analysis(source_dir: str, report: DetectionReport) -> list[Finding]:
    """Run Slither and Aderyn static analysis."""
    findings = []
    print("\n[Layer 1] Static Analysis...")

    # --- Slither ---
    slither_findings = _run_slither(source_dir)
    findings.extend(slither_findings)

    # --- Aderyn ---
    aderyn_findings = _run_aderyn(source_dir)
    findings.extend(aderyn_findings)

    report.add_layer_stats("static", {
        "slither_findings": len(slither_findings),
        "aderyn_findings": len(aderyn_findings),
    })

    for f in findings:
        report.add_finding(f)

    print(f"  Slither: {len(slither_findings)} findings")
    print(f"  Aderyn: {len(aderyn_findings)} findings")
    return findings


def _run_slither(source_dir: str) -> list[Finding]:
    """Run Slither and parse JSON output."""
    findings = []
    try:
        result = subprocess.run(
            [SLITHER_BIN, source_dir, "--json", "-"],
            capture_output=True, text=True, timeout=300,
            cwd=str(Path(source_dir).parent),
        )
        if result.stdout:
            data = json.loads(result.stdout)
            detectors = data.get("results", {}).get("detectors", [])
            for det in detectors:
                sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
                severity = sev_map.get(det.get("impact", ""), "info")
                if severity == "info":
                    continue  # Skip informational

                elements = det.get("elements", [])
                location = ""
                if elements:
                    elem = elements[0]
                    source = elem.get("source_mapping", {})
                    filename = source.get("filename_short", "")
                    lines = source.get("lines", [])
                    if filename and lines:
                        location = f"{filename}:{lines[0]}"

                findings.append(Finding(
                    title=f"[Slither] {det.get('check', 'unknown')}: {det.get('description', '')[:100]}",
                    severity=severity,
                    layer="static/slither",
                    description=det.get("description", ""),
                    location=location,
                    confidence=0.7 if severity in ("high", "medium") else 0.4,
                ))
    except FileNotFoundError:
        print("  Slither not found, skipping...")
    except subprocess.TimeoutExpired:
        print("  Slither timed out (5min limit)")
    except (json.JSONDecodeError, Exception) as e:
        print(f"  Slither error: {e}")
    return findings


def _run_aderyn(source_dir: str) -> list[Finding]:
    """Run Aderyn and parse output."""
    findings = []
    try:
        result = subprocess.run(
            [ADERYN_BIN, source_dir, "--output", "json"],
            capture_output=True, text=True, timeout=120,
            cwd=str(Path(source_dir).parent),
        )
        # Aderyn outputs JSON to stdout or a file
        output = result.stdout
        if output:
            try:
                data = json.loads(output)
                for issue in data.get("high_issues", []):
                    findings.append(Finding(
                        title=f"[Aderyn] {issue.get('title', '')}",
                        severity="high",
                        layer="static/aderyn",
                        description=issue.get("description", ""),
                        location=issue.get("location", ""),
                        confidence=0.6,
                    ))
                for issue in data.get("medium_issues", []):
                    findings.append(Finding(
                        title=f"[Aderyn] {issue.get('title', '')}",
                        severity="medium",
                        layer="static/aderyn",
                        description=issue.get("description", ""),
                        location=issue.get("location", ""),
                        confidence=0.5,
                    ))
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        print("  Aderyn not found, skipping...")
    except subprocess.TimeoutExpired:
        print("  Aderyn timed out")
    except Exception as e:
        print(f"  Aderyn error: {e}")
    return findings


# =============================================================================
# LAYER 2: INVARIANT MATCHING
# =============================================================================

def run_invariant_matching(source_dir: str, report: DetectionReport,
                           max_payout: int = 100000) -> list[Finding]:
    """Match invariants from registry against target source code."""
    findings = []
    print("\n[Layer 2] Invariant Matching...")

    pipeline = MatcherPipeline()
    results = pipeline.match(source_dir=source_dir, max_payout=max_payout)

    # Convert matched invariants to findings (these are HYPOTHESES to test)
    critical_matches = [r for r in results if r.invariant.severity == "critical"]
    high_matches = [r for r in results if r.invariant.severity == "high"]

    # Only report high-confidence matches as actionable findings
    for r in results:
        if r.confidence >= 0.6:
            findings.append(Finding(
                title=f"[Invariant] {r.invariant.title}",
                severity=r.invariant.severity,
                layer="invariant/match",
                description=f"{r.invariant.invariant_natural}\n\nSolidity check:\n{r.invariant.invariant_solidity}",
                invariant_id=r.invariant.id,
                confidence=r.confidence * 0.5,  # Halve confidence since these are hypotheses, not confirmed
                poc_hint=f"Add to Foundry invariant test: {r.invariant.invariant_solidity}",
            ))

    report.add_layer_stats("invariant", {
        "total_matched": len(results),
        "critical": len(critical_matches),
        "high": len(high_matches),
        "high_confidence_hypotheses": len(findings),
    })

    for f in findings:
        report.add_finding(f)

    print(f"  Matched: {len(results)} invariants")
    print(f"  High-confidence hypotheses: {len(findings)}")
    return findings


# =============================================================================
# LAYER 3: SYMBOLIC EXECUTION
# =============================================================================

def run_symbolic(source_dir: str, report: DetectionReport) -> list[Finding]:
    """Run Halmos symbolic execution if available."""
    findings = []
    print("\n[Layer 3] Symbolic Execution (Halmos)...")

    try:
        # Check if Halmos is available
        result = subprocess.run(
            [HALMOS_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            print("  Halmos not available, skipping...")
            report.add_layer_stats("symbolic", {"status": "not_installed"})
            return findings
    except FileNotFoundError:
        print("  Halmos not installed, skipping...")
        report.add_layer_stats("symbolic", {"status": "not_installed"})
        return findings

    # Run Halmos on test files if they exist
    parent_dir = Path(source_dir).parent
    test_dir = parent_dir / "test"
    if not test_dir.exists():
        print("  No test/ directory found, skipping Halmos...")
        report.add_layer_stats("symbolic", {"status": "no_tests"})
        return findings

    try:
        result = subprocess.run(
            [HALMOS_BIN, "--root", str(parent_dir), "--solver-timeout-assertion", "60000"],
            capture_output=True, text=True, timeout=600,
            cwd=str(parent_dir),
        )

        # Parse Halmos output for counterexamples
        output = result.stdout + result.stderr
        counterexamples = output.count("Counterexample")
        violations = output.count("FAIL")

        if violations > 0:
            findings.append(Finding(
                title=f"[Halmos] {violations} symbolic violations found",
                severity="high",
                layer="symbolic/halmos",
                description=f"Halmos found {violations} assertion violations with {counterexamples} counterexamples.\n\nRaw output (first 2000 chars):\n{output[:2000]}",
                confidence=0.8,  # Symbolic proofs are high confidence
            ))

        report.add_layer_stats("symbolic", {
            "status": "completed",
            "violations": violations,
            "counterexamples": counterexamples,
        })
        print(f"  Violations: {violations}, Counterexamples: {counterexamples}")

    except subprocess.TimeoutExpired:
        print("  Halmos timed out (10min limit)")
        report.add_layer_stats("symbolic", {"status": "timeout"})
    except Exception as e:
        print(f"  Halmos error: {e}")
        report.add_layer_stats("symbolic", {"status": f"error: {e}"})

    for f in findings:
        report.add_finding(f)
    return findings


# =============================================================================
# LAYER 4: LLM HYPOTHESIS AGENTS (generates prompts for Claude Code)
# =============================================================================

def generate_hypothesis_prompts(source_dir: str, report: DetectionReport,
                                 output_dir: str) -> list[str]:
    """Generate hypothesis agent prompts for Claude Code sub-agents.

    These are NOT auto-executed — they are prompts you feed to Claude Code.
    The killer insight: use Claude Code's Agent tool to run these in parallel.
    """
    print("\n[Layer 4] LLM Hypothesis Agent Prompts...")

    source_path = Path(source_dir)
    sol_files = sorted(source_path.rglob("*.sol"))
    sol_files = [f for f in sol_files if not any(
        skip in str(f).lower() for skip in ["test", "lib", "node_modules", "mock", "script"]
    )]

    # Collect source code (truncated for prompt size)
    source_code = ""
    file_list = []
    for f in sol_files[:20]:  # Max 20 files
        try:
            content = f.read_text(encoding="utf-8")
            source_code += f"\n// === {f.name} ===\n{content}\n"
            file_list.append(str(f.relative_to(source_path)))
        except UnicodeDecodeError:
            continue

    # Truncate if too long
    if len(source_code) > 100000:
        source_code = source_code[:100000] + "\n// ... truncated ..."

    prompts = []
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # The 5 Universal Hypothesis Agents (proven patterns from V6 methodology)
    hypotheses = [
        {
            "name": "H1_accounting_desync",
            "title": "Accounting Desync Hunter (37% of all criticals)",
            "prompt": f"""You are hunting for ACCOUNTING DESYNC bugs — the #1 vulnerability class (37% of all critical payouts).

Look for:
1. Internal accounting (totalAssets, totalShares, balances mapping) that can diverge from actual token balances
2. Functions that modify balances without updating internal state
3. Donation/direct transfer attacks that inflate exchange rates
4. Rounding errors that accumulate over multiple operations
5. Missing balance checks after external calls

For each finding: exact file, line, function, attack scenario, and Foundry PoC sketch.

Source files: {', '.join(file_list)}

Code:
{source_code[:50000]}""",
        },
        {
            "name": "H2_access_control",
            "title": "Access Control Gap Hunter (19% of criticals)",
            "prompt": f"""You are hunting for ACCESS CONTROL bugs — the #2 vulnerability class (19% of critical payouts).

Look for:
1. Functions missing onlyOwner/onlyAdmin/onlyRole modifiers that should have them
2. Sibling functions where one has a modifier and the other doesn't
3. Initializer functions callable more than once
4. Role assignment without proper checks
5. Privilege escalation paths (low-privilege role can reach high-privilege action)

For each finding: exact file, line, function, who can call it that shouldn't.

Source files: {', '.join(file_list)}

Code:
{source_code[:50000]}""",
        },
        {
            "name": "H3_input_validation",
            "title": "Input Validation & Edge Case Hunter",
            "prompt": f"""You are hunting for INPUT VALIDATION and EDGE CASE bugs.

Look for:
1. Missing zero-amount checks (deposit(0), transfer(0))
2. Missing zero-address checks
3. Array length mismatches between parameters
4. Integer overflow/underflow in custom math (not SafeMath)
5. Division by zero in edge cases (empty pool, first depositor)
6. Unchecked external call return values
7. Type casting truncation (uint256 -> uint128 etc.)

For each finding: exact file, line, function, edge case input that breaks it.

Source files: {', '.join(file_list)}

Code:
{source_code[:50000]}""",
        },
        {
            "name": "H4_reentrancy_callback",
            "title": "Reentrancy & Callback Exploitation Hunter",
            "prompt": f"""You are hunting for REENTRANCY and CALLBACK exploitation bugs.

Look for:
1. State changes AFTER external calls (classic reentrancy)
2. Cross-function reentrancy (callback calls different function on same contract)
3. Read-only reentrancy (view function returns stale state during callback)
4. ERC777/ERC1155 hook exploitation
5. Flash loan callback exploitation
6. Missing reentrancy guards on functions that interact with unknown tokens
7. Reentrancy guard on function A but not on function B that shares state

For each finding: exact file, line, the external call, the state that's vulnerable.

Source files: {', '.join(file_list)}

Code:
{source_code[:50000]}""",
        },
        {
            "name": "H5_economic_logic",
            "title": "Economic & Business Logic Bug Hunter",
            "prompt": f"""You are hunting for ECONOMIC and BUSINESS LOGIC bugs — the hardest to find, highest payouts.

Look for:
1. Flash loan + price manipulation sequences
2. Oracle manipulation (spot price used where TWAP needed)
3. Sandwich attack vectors (front-run + back-run profit extraction)
4. Fee bypass paths (operations that skip fee collection)
5. Liquidation logic errors (self-liquidation, bad debt creation)
6. Share price manipulation (first depositor, donation attack)
7. Rounding direction that favors attacker (should always round against user)
8. State machine violations (skip required steps, revert to old state)
9. Cross-contract value extraction (protocol A trusts protocol B's price)

Think like an attacker with $100M in flash loans. What sequence of transactions extracts value?

For each finding: exact attack sequence (step 1, step 2...), profit calculation, Foundry PoC sketch.

Source files: {', '.join(file_list)}

Code:
{source_code[:50000]}""",
        },
    ]

    for h in hypotheses:
        prompt_file = out_path / f"{h['name']}.md"
        with open(prompt_file, "w", encoding="utf-8") as f:
            f.write(f"# {h['title']}\n\n{h['prompt']}")
        prompts.append(str(prompt_file))

    # Also generate a MASTER prompt that combines all hypotheses for a single Claude Code agent
    master_prompt = f"""You are a Web3 security researcher hunting for bugs in this protocol.
Run 5 parallel agents using the Agent tool, each focused on a different vulnerability class:

1. Accounting Desync (37% of criticals) — internal vs actual balance divergence
2. Access Control (19% of criticals) — missing modifiers, privilege escalation
3. Input Validation — zero amounts, overflow, type truncation
4. Reentrancy & Callbacks — state after external calls, cross-function
5. Economic Logic — flash loan attacks, oracle manipulation, fee bypass

Source directory: {source_dir}
Files: {', '.join(file_list)}

For EACH finding output:
- Title
- Severity (Critical/High/Medium)
- File:Line
- Root cause
- Attack scenario (step by step)
- Foundry PoC sketch

Only report findings that an UNPRIVILEGED attacker can exploit. No admin-only bugs."""

    master_file = out_path / "MASTER_HUNT_PROMPT.md"
    with open(master_file, "w", encoding="utf-8") as f:
        f.write(master_prompt)
    prompts.append(str(master_file))

    report.add_layer_stats("hypothesis", {
        "prompts_generated": len(prompts),
        "source_files_included": len(file_list),
        "source_chars": len(source_code),
    })

    print(f"  Generated {len(prompts)} hypothesis prompts in {output_dir}")
    print(f"  Use MASTER_HUNT_PROMPT.md with Claude Code to run all 5 agents in parallel")
    return prompts


# =============================================================================
# LAYER 5: EXPLOIT-DERIVED PATTERN MATCHING
# =============================================================================

def run_exploit_pattern_matching(source_dir: str, report: DetectionReport) -> list[Finding]:
    """Check source code against patterns from real-world exploits (DeFiHackLabs).

    This layer asks: "Does this code have the same vulnerability that caused $X hack?"
    """
    findings = []
    print("\n[Layer 5] Exploit-Derived Pattern Matching...")

    source_path = Path(source_dir)
    sol_files = list(source_path.rglob("*.sol"))
    sol_files = [f for f in sol_files if not any(
        skip in str(f).lower() for skip in ["test", "lib", "node_modules", "mock"]
    )]

    combined_source = ""
    for f in sol_files:
        try:
            combined_source += f.read_text(encoding="utf-8") + "\n"
        except UnicodeDecodeError:
            continue

    source_lower = combined_source.lower()

    # High-confidence exploit patterns with grep-able indicators
    exploit_checks = [
        {
            "name": "Spot price without TWAP (Oracle manipulation)",
            "indicators": ["getamountsout", "getreserves", "slot0", "latestanswer"],
            "anti_indicators": ["twap", "observe", "consult"],
            "severity": "critical",
            "description": "Uses spot price that can be manipulated in same transaction via flash loan. 25% of DeFi hacks.",
            "real_hacks": "UwuLend $19.3M, Sonne $20M, Makina $5.1M",
        },
        {
            "name": "Missing reentrancy guard on token interaction",
            "indicators": ["transfer(", "transferfrom(", "safetransfer(", ".call{value:"],
            "anti_indicators": ["nonreentrant", "reentrancyguard", "_status"],
            "severity": "high",
            "description": "External call without reentrancy protection. Classic $420M+ loss vector.",
            "real_hacks": "Euler $197M, Prisma $11M, Curve $70M",
        },
        {
            "name": "First depositor / share inflation vulnerable",
            "indicators": ["totalsupply() == 0", "totalsupply()==0", "shares == 0", "_mint("],
            "anti_indicators": ["virtual shares", "dead shares", "min_deposit", "1000"],
            "severity": "critical",
            "description": "Vault with no first-depositor protection. Attacker deposits 1 wei, donates to inflate.",
            "real_hacks": "Sonne $20M, PolterFinance $7M, Radiant $4.5M",
        },
        {
            "name": "Arbitrary external call (calldata injection)",
            "indicators": [".call(", "functioncall(", "address(target).call", "delegatecall("],
            "anti_indicators": ["onlyowner", "onlyadmin", "msg.sender =="],
            "severity": "critical",
            "description": "User-controlled address + calldata enables arbitrary interaction.",
            "real_hacks": "DeltaPrime $4.75M, TransitSwap $21M, DoughFinance $1.81M",
        },
        {
            "name": "Rounding favors user (should favor protocol)",
            "indicators": ["muldi", "divup", "muldiv(", "fullmul(", "/ totalsupply"],
            "anti_indicators": [],
            "severity": "high",
            "description": "Division rounding may favor attacker in deposit/withdraw. Check rounding direction.",
            "real_hacks": "BalancerV2 $120M, KyberSwap $46M",
        },
        {
            "name": "Unchecked low-level call return",
            "indicators": [".call{", ".call("],
            "anti_indicators": ["require(success", "if (!success", "revert"],
            "severity": "high",
            "description": "Low-level call without checking return value. Silently fails.",
            "real_hacks": "Multiple DeFi protocols",
        },
        {
            "name": "Missing slippage protection",
            "indicators": ["swap(", "exchange(", "getamountout"],
            "anti_indicators": ["minamountout", "slippage", "deadline", "minreturn", "amountoutmin"],
            "severity": "medium",
            "description": "Swap without minimum output amount. Sandwich attackable.",
            "real_hacks": "MEV losses across DeFi ($1B+ cumulative)",
        },
        {
            "name": "Proxy storage collision risk",
            "indicators": ["delegatecall", "upgradeto", "implementation()", "eip1967"],
            "anti_indicators": ["openzeppelin", "transparentproxy", "uups"],
            "severity": "critical",
            "description": "Custom proxy without standard storage layout. Storage collision risk.",
            "real_hacks": "Bybit $1.5B, LeverageSIR $353K",
        },
        {
            "name": "Missing initializer protection",
            "indicators": ["initialize(", "init(", "__init"],
            "anti_indicators": ["initializer", "initialized", "onlyonce"],
            "severity": "critical",
            "description": "Initializer function may be callable multiple times or by anyone.",
            "real_hacks": "Wormhole $320M (related), multiple protocols",
        },
        {
            "name": "Flash loan callback without state validation",
            "indicators": ["onflashloan", "flashloancallback", "receivetokens", "uniswapv2call", "uniswapv3flashcallback"],
            "anti_indicators": ["msg.sender == pool", "msg.sender == lender"],
            "severity": "high",
            "description": "Flash loan callback without sender validation. Attacker can call directly.",
            "real_hacks": "Multiple DeFi exploits",
        },
    ]

    matched_patterns = 0
    for check in exploit_checks:
        has_indicator = any(ind in source_lower for ind in check["indicators"])
        has_anti = any(anti in source_lower for anti in check["anti_indicators"]) if check["anti_indicators"] else False

        if has_indicator and not has_anti:
            matched_patterns += 1
            # Find the specific location
            location = ""
            for f in sol_files:
                try:
                    content = f.read_text(encoding="utf-8").lower()
                    for ind in check["indicators"]:
                        if ind in content:
                            lines = content.split("\n")
                            for i, line in enumerate(lines):
                                if ind in line:
                                    location = f"{f.name}:{i+1}"
                                    break
                            if location:
                                break
                except UnicodeDecodeError:
                    continue
                if location:
                    break

            findings.append(Finding(
                title=f"[ExploitPattern] {check['name']}",
                severity=check["severity"],
                layer="exploit_pattern",
                description=f"{check['description']}\n\nReal-world hacks: {check['real_hacks']}",
                location=location,
                confidence=0.4,  # Pattern match = hypothesis, needs manual verification
                poc_hint=f"Verify: does this code path actually lack the protection? Check anti-patterns: {check['anti_indicators']}",
            ))

    report.add_layer_stats("exploit_pattern", {
        "patterns_checked": len(exploit_checks),
        "patterns_matched": matched_patterns,
    })

    for f in findings:
        report.add_finding(f)

    print(f"  Checked {len(exploit_checks)} exploit patterns")
    print(f"  Matched: {matched_patterns} potential vulnerabilities")
    return findings


# =============================================================================
# MAIN ENGINE
# =============================================================================

def run_detection(source_dir: str, name: str, output_dir: str,
                  layers: Optional[list[str]] = None, max_payout: int = 100000) -> DetectionReport:
    """Run the full detection engine."""

    all_layers = ["static", "invariant", "symbolic", "hypothesis", "exploit"]
    if layers:
        active_layers = [l for l in layers if l in all_layers]
    else:
        active_layers = all_layers

    report = DetectionReport(target_name=name, source_dir=source_dir)

    print(f"\n{'='*70}")
    print(f"DETECTION ENGINE: {name}")
    print(f"Source: {source_dir}")
    print(f"Layers: {', '.join(active_layers)}")
    print(f"{'='*70}")

    # Layer 1: Static Analysis
    if "static" in active_layers:
        run_static_analysis(source_dir, report)

    # Layer 2: Invariant Matching
    if "invariant" in active_layers:
        run_invariant_matching(source_dir, report, max_payout)

    # Layer 3: Symbolic Execution
    if "symbolic" in active_layers:
        run_symbolic(source_dir, report)

    # Layer 4: Hypothesis Prompts
    if "hypothesis" in active_layers:
        generate_hypothesis_prompts(source_dir, report, output_dir)

    # Layer 5: Exploit Pattern Matching
    if "exploit" in active_layers:
        run_exploit_pattern_matching(source_dir, report)

    report.finalize()

    # Save report
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    report_file = out_path / f"{name}_detection_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2)

    report.print_summary()
    print(f"\nFull report: {report_file}")
    print(f"Hypothesis prompts: {output_dir}/H*.md")
    print(f"\nNEXT: Run MASTER_HUNT_PROMPT.md in Claude Code for deep LLM analysis")

    return report


def main():
    parser = argparse.ArgumentParser(description="Multi-layer vulnerability detection engine")
    parser.add_argument("--source", required=True, help="Path to target source code")
    parser.add_argument("--name", required=True, help="Target name")
    parser.add_argument("--output", default="./detection-results", help="Output directory")
    parser.add_argument("--layers", help="Comma-separated layers: static,invariant,symbolic,hypothesis,exploit")
    parser.add_argument("--fast", action="store_true", help="Fast mode: static + exploit only")
    parser.add_argument("--payout", type=int, default=100000, help="Max bounty payout")

    args = parser.parse_args()

    layers = None
    if args.fast:
        layers = ["static", "exploit"]
    elif args.layers:
        layers = args.layers.split(",")

    run_detection(
        source_dir=args.source,
        name=args.name,
        output_dir=args.output,
        layers=layers,
        max_payout=args.payout,
    )


if __name__ == "__main__":
    main()
