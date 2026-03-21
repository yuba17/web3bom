"""Pattern-based vulnerability scanner using regex matching."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class PatternAgent(BaseAgent):
    name = "PatternScanner"
    description = "Scans for known vulnerability patterns using regex"

    # Each pattern: (regex, severity, title, description, recommendation)
    PATTERNS = [
        # === CRITICAL ===
        (
            r'\.delegatecall\(',
            "HIGH", "Delegatecall Usage",
            "delegatecall executes code in the caller's context. If the target is user-controlled, the contract can be taken over.",
            "Ensure delegatecall target is immutable or properly validated."
        ),
        (
            r'selfdestruct\s*\(|SELFDESTRUCT',
            "HIGH", "Selfdestruct Present",
            "selfdestruct can destroy the contract and send remaining ETH. Can be weaponized if access control is weak.",
            "Remove selfdestruct or ensure it's behind multi-sig."
        ),
        # === HIGH ===
        (
            r'tx\.origin',
            "HIGH", "tx.origin Used for Authentication",
            "tx.origin returns the original sender of the transaction. It can be phished via a malicious contract.",
            "Use msg.sender instead of tx.origin for authentication."
        ),
        (
            r'block\.timestamp\s*[<>=]|now\s*[<>=]',
            "LOW", "Timestamp Dependence",
            "block.timestamp can be slightly manipulated by miners (~15 seconds). Avoid for critical time-dependent logic.",
            "Use block.number for ordering. Accept timestamp imprecision if used."
        ),
        (
            r'abi\.encodePacked\([^)]*,\s*[^)]*\)',
            "MEDIUM", "abi.encodePacked with Multiple Arguments",
            "abi.encodePacked with multiple dynamic types can cause hash collisions (e.g., abi.encodePacked('a','bc') == abi.encodePacked('ab','c')).",
            "Use abi.encode instead of abi.encodePacked for hashing."
        ),
        (
            r'ecrecover\(',
            "MEDIUM", "ecrecover Usage",
            "ecrecover can return address(0) for invalid signatures. Missing zero-address check leads to signature bypass.",
            "Check ecrecover result is not address(0). Consider using OpenZeppelin's ECDSA library."
        ),
        (
            r'\.transfer\(\s*\w',
            "MEDIUM", "Use of .transfer()",
            ".transfer() forwards only 2300 gas, which can fail for contracts with receive/fallback logic since the Istanbul hard fork.",
            "Use .call{value: amount}('') with reentrancy guard instead."
        ),
        (
            r'block\.blockhash|blockhash\(',
            "MEDIUM", "Blockhash Used as Randomness",
            "blockhash is predictable and can be manipulated by miners. Not suitable for randomness.",
            "Use Chainlink VRF or commit-reveal scheme for randomness."
        ),
        (
            r'assembly\s*\{',
            "INFO", "Inline Assembly Usage",
            "Inline assembly bypasses Solidity safety checks. Review carefully for correctness.",
            "Document assembly blocks thoroughly. Verify with formal methods if critical."
        ),
        (
            r'unchecked\s*\{',
            "INFO", "Unchecked Arithmetic Block",
            "Unchecked blocks disable overflow/underflow checks. Intentional for gas optimization but risky if preconditions aren't validated.",
            "Verify all unchecked operations have proven bounds."
        ),
        # === Dangerous external interactions ===
        (
            r'\.call\{value:',
            "INFO", "Low-level ETH Transfer",
            "Low-level .call{value:} is the recommended ETH transfer method but requires reentrancy protection.",
            "Ensure nonReentrant modifier or CEI pattern is applied."
        ),
        (
            r'IERC20\([^)]+\)\.transferFrom\(',
            "INFO", "ERC20 transferFrom",
            "Some tokens don't return bool (USDT). Some have fee-on-transfer. Some have rebasing logic.",
            "Use SafeERC20.safeTransferFrom. Account for fee-on-transfer tokens."
        ),
    ]

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()
        lines = contract.source.split('\n')

        for pattern, severity, title, description, recommendation in self.PATTERNS:
            for i, line in enumerate(lines, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                    continue
                if re.search(pattern, line):
                    self.add_finding(
                        severity=severity,
                        title=title,
                        description=description,
                        location=f"{contract.file_path}:{i}",
                        recommendation=recommendation,
                        code_snippet=stripped,
                    )

        return self.findings
