"""ERC20/ERC721 token interaction vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class TokenAgent(BaseAgent):
    name = "TokenDetector"
    description = "Detects token interaction bugs — fee-on-transfer, rebasing, approval race, ERC777 hooks"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()
        self._check_fee_on_transfer(contract)
        self._check_approval_race(contract)
        self._check_unsafe_erc20(contract)
        self._check_erc777_hooks(contract)
        self._check_double_spending_approval(contract)
        self._check_phantom_overflow(contract)
        self._check_missing_slippage(contract)
        return self.findings

    def _check_fee_on_transfer(self, contract: SolidityContract):
        """Check if protocol accounts for fee-on-transfer tokens."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue

            # Pattern: transferFrom then use the exact amount (not checking actual received)
            if re.search(r'(transferFrom|safeTransferFrom)\s*\(', line):
                # Look ahead for the amount being used directly
                context = '\n'.join(lines[i:min(i+5, len(lines))])
                # If amount parameter is used directly without balance check
                if not re.search(r'balanceOf\(address\(this\)\)', context):
                    self.add_finding(
                        severity="MEDIUM",
                        title="Potential Fee-on-Transfer Token Issue",
                        description=(
                            "transferFrom is called but the actual received amount isn't verified. "
                            "If a fee-on-transfer token (like USDT with fees) is used, "
                            "the contract will credit more than it received."
                        ),
                        location=f"{contract.file_path}:{i}",
                        recommendation=(
                            "Measure actual received amount:\n"
                            "```\n"
                            "uint256 before = token.balanceOf(address(this));\n"
                            "token.safeTransferFrom(msg.sender, address(this), amount);\n"
                            "uint256 received = token.balanceOf(address(this)) - before;\n"
                            "```"
                        ),
                        code_snippet=line.strip(),
                    )
                    break  # One finding is enough

    def _check_approval_race(self, contract: SolidityContract):
        """Check for ERC20 approval race condition."""
        for func in contract.functions:
            if 'approve' in func.body and func.name != 'approve':
                # Check if it does approve without setting to 0 first
                approves = list(re.finditer(r'\.approve\(', func.body))
                if len(approves) >= 1:
                    # Check if there's a zero-approve before
                    if not re.search(r'\.approve\([^,]+,\s*0\)', func.body):
                        self.add_finding(
                            severity="LOW",
                            title=f"ERC20 Approval Without Zero-Reset in `{func.name}()`",
                            description=(
                                "ERC20 approve is called without first setting to 0. "
                                "Some tokens (USDT) require approval to be set to 0 before "
                                "changing to a new value."
                            ),
                            location=f"{contract.file_path}:{func.line_start}",
                            recommendation="Set approve to 0 first, or use increaseAllowance/safeIncreaseAllowance.",
                        )

    def _check_unsafe_erc20(self, contract: SolidityContract):
        """Check for direct ERC20 calls without SafeERC20."""
        has_safe_erc20 = bool(re.search(r'(SafeERC20|safeTransfer|safeTransferFrom|safeApprove)', contract.source))
        if has_safe_erc20:
            return

        # Check if any ERC20 interaction exists
        has_erc20 = bool(re.search(r'(IERC20|ERC20|\.transfer\(|\.transferFrom\(|\.approve\()', contract.source))
        if has_erc20:
            self.add_finding(
                severity="MEDIUM",
                title="ERC20 Interactions Without SafeERC20",
                description=(
                    "Contract interacts with ERC20 tokens without using SafeERC20. "
                    "Not all tokens conform to the standard — USDT doesn't return bool, "
                    "some tokens revert on zero-amount transfers."
                ),
                location=contract.file_path,
                recommendation=(
                    "Use OpenZeppelin SafeERC20:\n"
                    "```\n"
                    "using SafeERC20 for IERC20;\n"
                    "token.safeTransfer(to, amount);\n"
                    "```"
                ),
            )

    def _check_erc777_hooks(self, contract: SolidityContract):
        """Check if contract is vulnerable to ERC777 token hooks (reentrancy vector)."""
        for func in contract.functions:
            if func.mutability in ('view', 'pure'):
                continue
            # If function does token transfer and state change
            has_token_transfer = bool(re.search(r'\.(transfer|transferFrom|safeTransfer)', func.body))
            has_state_after = False
            if has_token_transfer:
                # Check if state changes happen after transfer
                transfer_pos = re.search(r'\.(transfer|transferFrom|safeTransfer)', func.body)
                if transfer_pos:
                    after_transfer = func.body[transfer_pos.end():]
                    has_state_after = bool(re.search(r'\w+\s*[\[\]]*\s*[+\-]?=', after_transfer))

            if has_token_transfer and has_state_after and 'nonReentrant' not in func.modifiers:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"ERC777 Hook Reentrancy Risk in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` does a token transfer before state updates. "
                        f"If the token is ERC777 (or any token with transfer hooks), "
                        f"the receiver can re-enter during the transfer callback."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add nonReentrant modifier and follow CEI pattern.",
                )

    def _check_double_spending_approval(self, contract: SolidityContract):
        """Check for approve without amount validation in token contracts."""
        if contract.name and 'Token' not in contract.name and 'ERC20' not in contract.name:
            return

        for func in contract.functions:
            if func.name != 'approve':
                continue
            if 'type(uint256).max' not in func.body and 'uint256(-1)' not in func.body:
                if not re.search(r'allowance|_approve', func.body):
                    self.add_finding(
                        severity="INFO",
                        title="Custom approve() — Verify Race Condition Protection",
                        description="Custom approve implementation found. Verify it handles the approval race condition.",
                        location=f"{contract.file_path}:{func.line_start}",
                        recommendation="Consider using increaseAllowance/decreaseAllowance instead.",
                    )

    def _check_phantom_overflow(self, contract: SolidityContract):
        """Check for potential phantom overflow in token math."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            # type(uint256).max or 2**256 - 1 used in balance/supply context
            if re.search(r'type\(uint256\)\.max', line):
                context = '\n'.join(lines[max(0, i-3):min(len(lines), i+3)])
                if re.search(r'(balance|supply|amount|total)', context, re.IGNORECASE):
                    self.add_finding(
                        severity="INFO",
                        title="type(uint256).max in Token Context",
                        description="Maximum uint256 value used near balance/supply logic. Verify no overflow scenarios.",
                        location=f"{contract.file_path}:{i}",
                        recommendation="Verify arithmetic safety around max value usage.",
                    )

    def _check_missing_slippage(self, contract: SolidityContract):
        """Check for swap/exchange without slippage protection."""
        for func in contract.functions:
            name_lower = func.name.lower()
            if not any(kw in name_lower for kw in ['swap', 'exchange', 'trade', 'remove_liquidity', 'removeliquidity']):
                continue

            has_min_amount = bool(re.search(
                r'(minAmount|amountOutMin|minimumOut|minOut|slippage|_min)',
                func.body
            ))
            if not has_min_amount:
                self.add_finding(
                    severity="HIGH",
                    title=f"Missing Slippage Protection in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` performs a swap/exchange without "
                        f"minimum output amount parameter. Users can be sandwiched "
                        f"(MEV) and receive far less than expected."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add a `minAmountOut` parameter and enforce it.",
                )
