"""Business logic vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class LogicAgent(BaseAgent):
    name = "LogicDetector"
    description = "Detects business logic vulnerabilities, edge cases, and arithmetic issues"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()
        self._check_first_depositor(contract)
        self._check_rounding_issues(contract)
        self._check_unchecked_return(contract)
        self._check_division_before_multiplication(contract)
        self._check_missing_deadline(contract)
        self._check_hardcoded_addresses(contract)
        self._check_unbounded_loops(contract)
        return self.findings

    def _check_first_depositor(self, contract: SolidityContract):
        """Check for first depositor / share inflation attack surface."""
        for func in contract.functions:
            if func.name.lower() not in ('deposit', 'mint', 'stake', 'supply'):
                continue

            has_total_supply_check = bool(re.search(r'totalSupply\(\)\s*==\s*0', func.body))
            has_min_shares = bool(re.search(r'(MINIMUM_LIQUIDITY|MIN_SHARES|deadShares|1000)', func.body))

            if has_total_supply_check and not has_min_shares:
                self.add_finding(
                    severity="HIGH",
                    title=f"First Depositor Attack Surface in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` checks for totalSupply == 0 but doesn't burn "
                        f"minimum shares. First depositor can manipulate share price by: "
                        f"1) Deposit 1 wei, 2) Donate large amount directly, "
                        f"3) Next depositor gets 0 shares due to rounding."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=(
                        "Burn a minimum amount of shares on first deposit (like Uniswap's MINIMUM_LIQUIDITY = 1000) "
                        "or use virtual shares/assets (OpenZeppelin ERC4626 pattern)."
                    ),
                )

    def _check_rounding_issues(self, contract: SolidityContract):
        """Check for rounding direction issues in share/token calculations."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            # Division that might round down to zero
            if re.search(r'\w+\s*\*\s*\w+\s*/\s*\w+', line):
                # Check if it's in a user-favoring context
                context_before = '\n'.join(lines[max(0, i-5):i])
                if re.search(r'(withdraw|redeem|claim|reward)', context_before, re.IGNORECASE):
                    self.add_finding(
                        severity="LOW",
                        title="Potential Rounding Issue in User-Favoring Context",
                        description=(
                            "Division in withdrawal/claim context. Verify rounding direction "
                            "favors the protocol (round down for withdrawals, round up for deposits)."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation="Use mulDivUp/mulDivDown (Solady/OZ Math) to control rounding direction.",
                        code_snippet=line.strip(),
                    )

    def _check_unchecked_return(self, contract: SolidityContract):
        """Check for unchecked return values on external calls."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            # ERC20 transfer/approve without checking return value
            if re.search(r'(?<!safe)\b(transfer|transferFrom|approve)\s*\(', stripped):
                # Check if return value is used
                if not re.search(r'(require|bool|if|assert|success)', stripped):
                    if not re.search(r'safe(Transfer|Approve)', stripped):
                        self.add_finding(
                            severity="MEDIUM",
                            title="Unchecked ERC20 Return Value",
                            description=(
                                "ERC20 transfer/approve called without checking return value. "
                                "Some tokens (USDT) don't return bool. Others return false on failure."
                            ),
                            location=f"{contract.file_path}:{i}",
                            recommendation="Use SafeERC20's safeTransfer/safeApprove from OpenZeppelin.",
                            code_snippet=stripped,
                        )

    def _check_division_before_multiplication(self, contract: SolidityContract):
        """Check for precision loss from division before multiplication."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            # Pattern: (a / b) * c — loses precision
            if re.search(r'\([^)]+/[^)]+\)\s*\*', line):
                self.add_finding(
                    severity="MEDIUM",
                    title="Division Before Multiplication (Precision Loss)",
                    description="Division before multiplication causes precision loss in Solidity integer arithmetic.",
                    location=f"{contract.file_path}:{i}",
                    recommendation="Reorder to multiply first, then divide: `a * c / b` instead of `(a / b) * c`.",
                    code_snippet=line.strip(),
                )

    def _check_missing_deadline(self, contract: SolidityContract):
        """Check for swap/trade functions without deadline parameter."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['swap', 'trade', 'exchange']):
                continue

            has_deadline = bool(re.search(r'deadline|expiry|validUntil|block\.timestamp', func.body))
            if not has_deadline:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"Missing Deadline in `{func.name}()`",
                    description=(
                        f"Swap function `{func.name}` has no deadline parameter. "
                        f"A transaction could sit in the mempool and execute at an unfavorable time."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add a `deadline` parameter and check `require(block.timestamp <= deadline);`",
                )

    def _check_hardcoded_addresses(self, contract: SolidityContract):
        """Check for hardcoded addresses that might be wrong on different chains."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            addresses = re.findall(r'0x[a-fA-F0-9]{40}', line)
            for addr in addresses:
                if addr == '0x' + '0' * 40:  # skip address(0)
                    continue
                self.add_finding(
                    severity="INFO",
                    title="Hardcoded Address",
                    description=f"Address {addr} is hardcoded. Verify it's correct for the target chain.",
                    location=f"{contract.file_path}:{i}",
                    recommendation="Consider making addresses configurable via constructor or immutable variables.",
                    code_snippet=line.strip(),
                )

    def _check_unbounded_loops(self, contract: SolidityContract):
        """Check for loops iterating over dynamic arrays (DoS risk)."""
        for func in contract.functions:
            if func.visibility in ('internal', 'private'):
                continue
            # for loop over .length
            if re.search(r'for\s*\([^)]*\.length', func.body):
                self.add_finding(
                    severity="MEDIUM",
                    title=f"Unbounded Loop in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` iterates over a dynamic array. "
                        f"If the array grows too large, the function will run out of gas (DoS)."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add a maximum iteration limit or use pagination.",
                )
