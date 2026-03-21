"""Gas optimization and DoS vulnerability detection agent."""
import re
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract


class GasOptimizationAgent(BaseAgent):
    name = "GasOptimizer"
    description = "Detects gas inefficiencies and gas-related DoS vectors"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()
        lines = contract.source.split('\n')

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            # Storage in loops
            if re.search(r'for\s*\(', stripped):
                # Look ahead for storage reads/writes in loop body
                loop_body = '\n'.join(lines[i:min(i+20, len(lines))])
                storage_in_loop = re.findall(r'\b(\w+)\[', loop_body)
                if storage_in_loop:
                    self.add_finding(
                        severity="INFO",
                        title="Storage Access in Loop",
                        description="Storage reads/writes inside loops are expensive. Cache in memory.",
                        location=f"{contract.file_path}:{i}",
                        recommendation="Cache storage values in memory variables before the loop.",
                    )

            # String errors instead of custom errors (Solidity 0.8.4+)
            if re.search(r'require\s*\([^,]+,\s*"[^"]{20,}"', stripped):
                self.add_finding(
                    severity="INFO",
                    title="Long Error String in require()",
                    description="Long string error messages increase deployment and runtime gas costs.",
                    location=f"{contract.file_path}:{i}",
                    recommendation="Use custom errors (Solidity 0.8.4+): `error Unauthorized();`",
                    code_snippet=stripped[:80],
                )

            # != 0 is cheaper than > 0 for unsigned
            if re.search(r'>\s*0\b', stripped) and 'uint' in '\n'.join(lines[max(0,i-5):i]):
                self.add_finding(
                    severity="INFO",
                    title="Use != 0 Instead of > 0",
                    description="For unsigned integers, `!= 0` is slightly cheaper than `> 0`.",
                    location=f"{contract.file_path}:{i}",
                    recommendation="Replace `> 0` with `!= 0` for gas savings.",
                )

        return self.findings
