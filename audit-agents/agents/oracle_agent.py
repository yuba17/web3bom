"""Oracle manipulation and flash loan vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class OracleAgent(BaseAgent):
    name = "OracleDetector"
    description = "Detects oracle manipulation, flash loan, and price feed vulnerabilities"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()
        self._check_spot_price_usage(contract)
        self._check_oracle_staleness(contract)
        self._check_single_oracle(contract)
        self._check_flash_loan_surface(contract)
        self._check_balance_as_price(contract)
        return self.findings

    def _check_spot_price_usage(self, contract: SolidityContract):
        """Check for AMM spot price usage (manipulable via flash loans)."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            # getReserves() is the classic AMM spot price pattern
            if re.search(r'getReserves\s*\(', line):
                self.add_finding(
                    severity="HIGH",
                    title="AMM Spot Price Usage (getReserves)",
                    description=(
                        "getReserves() returns the current AMM reserves, which can be "
                        "manipulated within a single transaction via flash loans. "
                        "Never use spot prices for pricing logic."
                    ),
                    location=f"{contract.file_path}:{i}",
                    recommendation="Use Chainlink price feeds or TWAP oracles instead.",
                    code_snippet=line.strip(),
                )

            # Direct reserve ratio calculation
            if re.search(r'reserve[01]\s*[*/]\s*\d*\s*[*/]?\s*reserve[01]', line):
                self.add_finding(
                    severity="HIGH",
                    title="Direct Reserve Ratio Price Calculation",
                    description="Price calculated directly from reserve ratios is flash-loan manipulable.",
                    location=f"{contract.file_path}:{i}",
                    recommendation="Use Chainlink or TWAP for price feeds.",
                    code_snippet=line.strip(),
                )

    def _check_oracle_staleness(self, contract: SolidityContract):
        """Check if Chainlink oracle responses are validated for staleness."""
        has_chainlink = bool(re.search(r'latestRoundData|AggregatorV3Interface', contract.source))
        if not has_chainlink:
            return

        has_staleness_check = bool(re.search(
            r'(updatedAt|answeredInRound|roundId|block\.timestamp\s*-\s*updatedAt)',
            contract.source
        ))
        has_price_validation = bool(re.search(r'price\s*[><=]+\s*0|answer\s*[><=]+\s*0', contract.source))

        if not has_staleness_check:
            self.add_finding(
                severity="MEDIUM",
                title="Chainlink Oracle Missing Staleness Check",
                description=(
                    "Chainlink latestRoundData() is called but there's no check for stale data. "
                    "If the oracle goes down or data is outdated, the protocol will use stale prices."
                ),
                location=contract.file_path,
                recommendation=(
                    "Add staleness validation:\n"
                    "```\n"
                    "(, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();\n"
                    "require(block.timestamp - updatedAt < STALENESS_THRESHOLD);\n"
                    "require(price > 0);\n"
                    "```"
                ),
            )

        if not has_price_validation:
            self.add_finding(
                severity="MEDIUM",
                title="Chainlink Oracle Missing Price Validation",
                description="Oracle price is not checked for zero or negative values.",
                location=contract.file_path,
                recommendation="Add `require(price > 0, 'Invalid price');` after latestRoundData().",
            )

    def _check_single_oracle(self, contract: SolidityContract):
        """Check if only a single oracle source is used without fallback."""
        oracle_sources = 0
        if re.search(r'AggregatorV3Interface|chainlink', contract.source, re.IGNORECASE):
            oracle_sources += 1
        if re.search(r'UniswapV[23]|TWAP|observe\(', contract.source):
            oracle_sources += 1
        if re.search(r'Band|DIA|API3|Pyth', contract.source):
            oracle_sources += 1

        if oracle_sources == 1:
            self.add_finding(
                severity="LOW",
                title="Single Oracle Source Without Fallback",
                description=(
                    "Only one oracle source detected. If it fails or is manipulated, "
                    "the protocol has no fallback."
                ),
                location=contract.file_path,
                recommendation="Consider implementing a fallback oracle or using multiple sources.",
            )

    def _check_flash_loan_surface(self, contract: SolidityContract):
        """Check for flash loan attack surface."""
        lines = contract.source.split('\n')

        # Check for flash loan callbacks (the contract receives flash loans)
        flash_patterns = [
            (r'onFlashLoan\s*\(', "IFlashBorrower callback"),
            (r'executeOperation\s*\(', "Aave flash loan callback"),
            (r'uniswapV2Call\s*\(', "Uniswap V2 flash swap callback"),
            (r'uniswapV3FlashCallback\s*\(', "Uniswap V3 flash callback"),
            (r'pancakeCall\s*\(', "PancakeSwap flash callback"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in flash_patterns:
                if re.search(pattern, line):
                    self.add_finding(
                        severity="INFO",
                        title=f"Flash Loan Callback Present: {desc}",
                        description=f"Contract implements {desc}. Verify flash loan logic is secure.",
                        location=f"{contract.file_path}:{i}",
                        recommendation="Verify caller validation and ensure no price manipulation is possible.",
                    )

    def _check_balance_as_price(self, contract: SolidityContract):
        """Check if contract balance is used as a price indicator."""
        lines = contract.source.split('\n')
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('//'):
                continue
            # balanceOf used in division/multiplication (potential price calc)
            if re.search(r'balanceOf\([^)]+\)\s*[*/]', line) or re.search(r'[*/]\s*balanceOf\(', line):
                self.add_finding(
                    severity="HIGH",
                    title="Token Balance Used in Price Calculation",
                    description=(
                        "balanceOf() is used in arithmetic that may determine pricing. "
                        "An attacker can donate tokens to the contract to manipulate this value."
                    ),
                    location=f"{contract.file_path}:{i}",
                    recommendation="Use internal accounting instead of balanceOf() for pricing logic.",
                    code_snippet=line.strip(),
                )
