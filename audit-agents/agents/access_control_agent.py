"""Access Control vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract, SolidityFunction


class AccessControlAgent(BaseAgent):
    name = "AccessControlDetector"
    description = "Detects missing or broken access control (#1 Web3 vulnerability)"

    # Functions that should ALWAYS have access control
    SENSITIVE_FUNCTIONS = [
        'mint', 'burn', 'pause', 'unpause', 'upgrade', 'setAdmin',
        'setOwner', 'transferOwnership', 'withdraw', 'withdrawAll',
        'emergencyWithdraw', 'setFee', 'setPrice', 'setOracle',
        'initialize', 'init', 'setup', 'configure', 'setImplementation',
        'destroy', 'kill', 'selfdestruct', 'suicide',
        'addMinter', 'removeMinter', 'grantRole', 'revokeRole',
        'setGovernance', 'setTreasury', 'setRewardRate',
        'recoverToken', 'rescue', 'sweep',
    ]

    # Known access control modifiers
    ACCESS_MODIFIERS = [
        'onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance',
        'onlyMinter', 'onlyAuthorized', 'onlyOperator', 'onlyKeeper',
        'whenNotPaused', 'initializer', 'onlyProxy', 'onlyDelegateCall',
        'auth', 'restricted', 'requiresAuth',
    ]

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()

        for func in contract.functions:
            if func.visibility in ('internal', 'private'):
                continue

            self._check_unprotected_sensitive(contract, func)
            self._check_tx_origin(contract, func)
            self._check_unprotected_initialize(contract, func)
            self._check_missing_zero_address(contract, func)

        self._check_unprotected_selfdestruct(contract)
        return self.findings

    def _check_unprotected_sensitive(self, contract: SolidityContract, func: SolidityFunction):
        """Check if sensitive functions lack access control."""
        func_lower = func.name.lower()

        is_sensitive = any(s.lower() in func_lower for s in self.SENSITIVE_FUNCTIONS)
        if not is_sensitive:
            return

        has_access_control = any(
            mod.lower() in [m.lower() for m in self.ACCESS_MODIFIERS]
            for mod in func.modifiers
        )

        # Also check for require(msg.sender == ...) in body
        if not has_access_control:
            has_access_control = bool(re.search(
                r'require\s*\(\s*msg\.sender\s*==',
                func.body
            ))

        # Check for if (msg.sender != ...) revert
        if not has_access_control:
            has_access_control = bool(re.search(
                r'if\s*\(\s*msg\.sender\s*!=',
                func.body
            ))

        if not has_access_control:
            severity = "CRITICAL" if func_lower in ['initialize', 'init', 'setup'] else "HIGH"
            self.add_finding(
                severity=severity,
                title=f"Unprotected Sensitive Function: `{func.name}()`",
                description=(
                    f"Function `{func.name}` appears to be a sensitive/admin function "
                    f"({func.visibility}) but has no access control modifier or msg.sender check."
                ),
                location=f"{contract.file_path}:{func.line_start}",
                recommendation=(
                    f"Add appropriate access control (e.g., `onlyOwner` modifier) to `{func.name}()`."
                ),
            )

    def _check_tx_origin(self, contract: SolidityContract, func: SolidityFunction):
        """Check for tx.origin usage in authentication."""
        if 'tx.origin' in func.body:
            # Check if it's used for auth
            if re.search(r'(require|assert|if)\s*\([^)]*tx\.origin', func.body):
                self.add_finding(
                    severity="HIGH",
                    title=f"tx.origin Authentication in `{func.name}()`",
                    description=(
                        "tx.origin is used for authentication. An attacker can trick the "
                        "real owner into calling a malicious contract that then calls this function."
                    ),
                    location=f"{contract.file_path}:{func.line_start}",
                    recommendation="Replace tx.origin with msg.sender for authentication.",
                )

    def _check_unprotected_initialize(self, contract: SolidityContract, func: SolidityFunction):
        """Check if initialize functions can be called multiple times."""
        if func.name.lower() not in ('initialize', 'init', 'setup', 'configure'):
            return

        has_initializer = 'initializer' in func.modifiers
        has_initialized_check = bool(re.search(r'(initialized|_initialized)', func.body))

        if not has_initializer and not has_initialized_check:
            self.add_finding(
                severity="CRITICAL",
                title=f"Unprotected Initializer: `{func.name}()`",
                description=(
                    f"Function `{func.name}` appears to be an initializer but lacks the "
                    f"`initializer` modifier or a manual initialization check. "
                    f"It may be callable multiple times, allowing an attacker to re-initialize the contract."
                ),
                location=f"{contract.file_path}:{func.line_start}",
                recommendation=(
                    "Use OpenZeppelin's `initializer` modifier or add a boolean guard: "
                    "`require(!initialized); initialized = true;`"
                ),
            )

    def _check_missing_zero_address(self, contract: SolidityContract, func: SolidityFunction):
        """Check if address parameters are validated against zero address."""
        if func.name.lower() in ('constructor',):
            return

        # Only check functions that set important addresses
        sets_address = bool(re.search(
            r'(owner|admin|governance|treasury|oracle|operator)\s*=\s*\w+',
            func.body
        ))
        if not sets_address:
            return

        has_zero_check = bool(re.search(
            r'(address\(0\)|address\(0x0\)|!= 0x0|!= address\(0\))',
            func.body
        ))

        if not has_zero_check:
            self.add_finding(
                severity="MEDIUM",
                title=f"Missing Zero-Address Check in `{func.name}()`",
                description=(
                    f"Function `{func.name}` sets a critical address without checking "
                    f"for address(0). Accidentally setting to zero address could lock the contract."
                ),
                location=f"{contract.file_path}:{func.line_start}",
                recommendation="Add `require(newAddress != address(0), 'zero address');`",
            )

    def _check_unprotected_selfdestruct(self, contract: SolidityContract):
        """Check for selfdestruct without proper access control."""
        for func in contract.functions:
            if 'selfdestruct' in func.body or 'SELFDESTRUCT' in func.body:
                has_access = any(m in self.ACCESS_MODIFIERS for m in func.modifiers)
                if not has_access and func.visibility in ('public', 'external'):
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"Unprotected selfdestruct in `{func.name}()`",
                        description="selfdestruct can be called by anyone, destroying the contract.",
                        location=f"{contract.file_path}:{func.line_start}",
                        recommendation="Add strict access control or remove selfdestruct.",
                    )
