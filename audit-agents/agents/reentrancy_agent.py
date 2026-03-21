"""Reentrancy vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract, SolidityFunction


class ReentrancyAgent(BaseAgent):
    name = "ReentrancyDetector"
    description = "Detects reentrancy vulnerabilities (classic, cross-function, read-only)"

    EXTERNAL_CALL_PATTERNS = [
        r'\.call\{value:',
        r'\.call\(',
        r'\.delegatecall\(',
        r'\.transfer\(',
        r'\.send\(',
        r'IERC\d+\([^)]*\)\.\w+\(',
        r'safeTransfer\(',
        r'safeTransferFrom\(',
    ]

    STATE_CHANGE_PATTERNS = [
        r'\b\w+\s*\[.*\]\s*[+\-*/]?=',  # mapping/array assignment
        r'\b\w+\s*=\s*\w',               # variable assignment
        r'\b\w+\s*\+\+',                  # increment
        r'\b\w+\s*\-\-',                  # decrement
    ]

    REENTRANCY_GUARD_PATTERNS = [
        r'nonReentrant',
        r'ReentrancyGuard',
        r'_locked',
        r'_notEntered',
        r'mutex',
    ]

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()

        for func in contract.functions:
            if func.visibility in ('internal', 'private'):
                continue
            if func.mutability in ('view', 'pure'):
                continue

            self._check_classic_reentrancy(contract, func)
            self._check_missing_guard(contract, func)

        self._check_cross_function_reentrancy(contract)
        return self.findings

    def _check_classic_reentrancy(self, contract: SolidityContract, func: SolidityFunction):
        """Check if external calls happen before state changes (CEI violation)."""
        body_lines = func.body.split('\n')

        first_external_call_line = None
        last_state_change_line = None

        for i, line in enumerate(body_lines):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue

            for pattern in self.EXTERNAL_CALL_PATTERNS:
                if re.search(pattern, stripped):
                    if first_external_call_line is None:
                        first_external_call_line = i
                    break

            for pattern in self.STATE_CHANGE_PATTERNS:
                if re.search(pattern, stripped) and not stripped.startswith('//'):
                    last_state_change_line = i

        # CEI violation: external call before state change
        if (first_external_call_line is not None and
            last_state_change_line is not None and
            first_external_call_line < last_state_change_line):

            # Check for reentrancy guard
            has_guard = any(mod in func.modifiers for mod in ['nonReentrant'])
            if not has_guard:
                has_guard = any(
                    re.search(p, func.body) for p in self.REENTRANCY_GUARD_PATTERNS
                )

            if not has_guard:
                self.add_finding(
                    severity="HIGH",
                    title=f"Potential Reentrancy in `{func.name}()`",
                    description=(
                        f"Function `{func.name}` makes an external call before updating state "
                        f"(Checks-Effects-Interactions violation). No reentrancy guard detected."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation=(
                        "Apply the CEI pattern (move state changes before external calls) "
                        "or add a `nonReentrant` modifier from OpenZeppelin's ReentrancyGuard."
                    ),
                )
            else:
                self.add_finding(
                    severity="INFO",
                    title=f"CEI Violation in `{func.name}()` (guarded)",
                    description=(
                        f"Function `{func.name}` has external call before state change, "
                        f"but a reentrancy guard is present. Still, CEI pattern is recommended."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Consider reordering to follow CEI pattern as defense in depth.",
                )

    def _check_missing_guard(self, contract: SolidityContract, func: SolidityFunction):
        """Check if payable/ETH-handling functions lack reentrancy protection."""
        if func.has_ether_transfer and 'nonReentrant' not in func.modifiers:
            # Only flag if not already flagged by classic check
            already_flagged = any(
                f.title.startswith("Potential Reentrancy") and func.name in f.title
                for f in self.findings
            )
            if not already_flagged:
                self.add_finding(
                    severity="MEDIUM",
                    title=f"ETH Transfer Without Reentrancy Guard in `{func.name}()`",
                    description=f"Function `{func.name}` transfers ETH without `nonReentrant` modifier.",
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Add `nonReentrant` modifier to all functions that transfer ETH.",
                )

    def _check_cross_function_reentrancy(self, contract: SolidityContract):
        """Check for cross-function reentrancy (two public functions sharing state)."""
        external_callers = []
        state_changers = []

        for func in contract.functions:
            if func.visibility in ('internal', 'private'):
                continue
            if func.has_external_call:
                external_callers.append(func)
            if func.has_state_change and func.mutability not in ('view', 'pure'):
                state_changers.append(func)

        # If we have functions that do external calls AND separate functions that change state,
        # there's potential for cross-function reentrancy
        for caller in external_callers:
            for changer in state_changers:
                if caller.name == changer.name:
                    continue
                if 'nonReentrant' not in caller.modifiers:
                    # Check if they share any state variable patterns
                    caller_vars = set(re.findall(r'\b(\w+)\[', caller.body))
                    changer_vars = set(re.findall(r'\b(\w+)\[', changer.body))
                    shared = caller_vars & changer_vars
                    if shared:
                        self.add_finding(
                            severity="MEDIUM",
                            title=f"Potential Cross-Function Reentrancy: `{caller.name}()` -> `{changer.name}()`",
                            description=(
                                f"Functions `{caller.name}` (has external call) and `{changer.name}` "
                                f"(changes state) share state variables: {shared}. An attacker could "
                                f"re-enter `{changer.name}` during `{caller.name}`'s external call."
                            ),
                            location=f"{contract.file_path}:{caller.line_start}",
                            recommendation="Use a shared reentrancy guard across both functions.",
                        )
