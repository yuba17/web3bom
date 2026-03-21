"""Proxy and upgradeability vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class ProxyAgent(BaseAgent):
    name = "ProxyDetector"
    description = "Detects proxy/upgradeability vulnerabilities (SC10) — storage collisions, uninitialized proxies"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()

        if not contract.uses_proxy and not self._has_proxy_patterns(contract):
            return self.findings

        self._check_uninitialized_implementation(contract)
        self._check_storage_collision(contract)
        self._check_delegatecall_to_untrusted(contract)
        self._check_function_clashing(contract)
        self._check_selfdestruct_in_impl(contract)
        self._check_missing_gap(contract)
        return self.findings

    def _has_proxy_patterns(self, contract: SolidityContract) -> bool:
        return bool(re.search(
            r'(delegatecall|Proxy|Upgradeable|TransparentUpgradeable|UUPSUpgradeable|ERC1967|implementation)',
            contract.source
        ))

    def _check_uninitialized_implementation(self, contract: SolidityContract):
        """Implementation contract must disable initializers in constructor."""
        has_upgradeable = any('Upgradeable' in inh for inh in contract.inheritance)
        if not has_upgradeable:
            return

        has_constructor_disable = bool(re.search(
            r'constructor\s*\([^)]*\)\s*\{[^}]*_disableInitializers',
            contract.source,
            re.DOTALL
        ))

        if not has_constructor_disable:
            self.add_finding(
                severity="HIGH",
                title="Implementation Missing _disableInitializers()",
                description=(
                    "Upgradeable implementation contract doesn't call _disableInitializers() "
                    "in its constructor. An attacker could initialize the implementation "
                    "directly and potentially selfdestruct it, bricking all proxies."
                ),
                location=contract.file_path,
                recommendation=(
                    "Add to constructor:\n"
                    "```\n"
                    "constructor() { _disableInitializers(); }\n"
                    "```"
                ),
            )

    def _check_storage_collision(self, contract: SolidityContract):
        """Check for potential storage layout issues in upgradeable contracts."""
        has_upgradeable = any('Upgradeable' in inh for inh in contract.inheritance)
        if not has_upgradeable:
            return

        # Check for state variables declared before inherited ones
        lines = contract.source.split('\n')
        in_contract = False
        has_state_var = False
        for i, line in enumerate(lines, 1):
            if re.match(r'\s*contract\s+\w+', line):
                in_contract = True
                continue
            if in_contract and re.match(r'\s*(uint|int|address|bool|string|bytes|mapping|struct)\w*\s', line):
                has_state_var = True
            if in_contract and 'function' in line:
                break

        # Not a precise check, but flag for manual review
        if has_state_var and has_upgradeable:
            self.add_finding(
                severity="INFO",
                title="Upgradeable Contract with State Variables — Verify Storage Layout",
                description=(
                    "Upgradeable contract declares state variables. When upgrading, "
                    "new variables must only be appended (never inserted or reordered) "
                    "to avoid storage collision."
                ),
                location=contract.file_path,
                recommendation="Use OpenZeppelin's storage gap pattern and never change variable order.",
            )

    def _check_delegatecall_to_untrusted(self, contract: SolidityContract):
        """Check for delegatecall to addresses that could be user-controlled."""
        for func in contract.functions:
            if 'delegatecall' not in func.body:
                continue

            # Check if the delegatecall target is a function parameter
            param_match = re.search(r'(\w+)\.delegatecall', func.body)
            if param_match:
                target_var = param_match.group(1)
                # If target could be from function args or storage that user can set
                if func.visibility in ('external', 'public'):
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"Delegatecall in Public Function `{func.name}()`",
                        description=(
                            f"Function `{func.name}` uses delegatecall. If the target address "
                            f"(`{target_var}`) can be influenced by a user, an attacker can "
                            f"execute arbitrary code in this contract's context, taking full control."
                        ),
                        location=f"{contract.file_path}:{func.line_start}",
                        recommendation="Ensure delegatecall target is immutable or heavily restricted.",
                    )

    def _check_function_clashing(self, contract: SolidityContract):
        """Check if proxy and implementation might have function selector clashes."""
        if 'TransparentUpgradeableProxy' in contract.source:
            return  # TransparentProxy handles this

        if re.search(r'(Proxy|delegatecall)', contract.source):
            # Check for admin/upgrade functions in implementation
            risky_funcs = ['admin', 'implementation', 'upgradeTo', 'upgradeToAndCall']
            for func in contract.functions:
                if func.name in risky_funcs and func.visibility in ('external', 'public'):
                    self.add_finding(
                        severity="MEDIUM",
                        title=f"Potential Proxy Function Clash: `{func.name}()`",
                        description=(
                            f"Function `{func.name}` in implementation could clash with "
                            f"proxy admin functions if not using TransparentProxy pattern."
                        ),
                        location=f"{contract.file_path}:{func.line_start}",
                        recommendation="Use TransparentUpgradeableProxy or UUPS pattern to avoid clashes.",
                    )

    def _check_selfdestruct_in_impl(self, contract: SolidityContract):
        """Selfdestruct in implementation contract can brick all proxies."""
        has_upgradeable = any('Upgradeable' in inh for inh in contract.inheritance)
        if not has_upgradeable:
            return

        if 'selfdestruct' in contract.source or 'SELFDESTRUCT' in contract.source:
            self.add_finding(
                severity="CRITICAL",
                title="Selfdestruct in Upgradeable Implementation",
                description=(
                    "An upgradeable implementation contract contains selfdestruct. "
                    "If an attacker can call it directly (not through proxy), it destroys "
                    "the implementation, bricking all proxies that point to it."
                ),
                location=contract.file_path,
                recommendation="Never use selfdestruct in upgradeable contracts. Remove it.",
            )

    def _check_missing_gap(self, contract: SolidityContract):
        """Check if upgradeable base contract is missing storage gap."""
        has_upgradeable = any('Upgradeable' in inh for inh in contract.inheritance)
        if not has_upgradeable:
            return

        has_gap = bool(re.search(r'__gap|_gap|uint256\[\d+\]\s+private\s+\w*gap', contract.source))
        if not has_gap:
            self.add_finding(
                severity="LOW",
                title="Missing Storage Gap in Upgradeable Contract",
                description=(
                    "Upgradeable contract doesn't declare a storage gap (e.g., "
                    "`uint256[50] private __gap`). Adding variables in future upgrades "
                    "could corrupt storage of derived contracts."
                ),
                location=contract.file_path,
                recommendation="Add `uint256[50] private __gap;` at the end of state variables.",
            )
