"""Slither integration agent — wraps slither static analyzer."""
import json
import subprocess
import shutil
from .base_agent import BaseAgent, Finding
from utils.solidity_parser import SolidityContract
from utils import logger


SEVERITY_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
    "Optimization": "INFO",
}


class SlitherAgent(BaseAgent):
    name = "SlitherAnalyzer"
    description = "Runs Slither static analysis (requires slither-analyzer installed)"

    def analyze(self, contract: SolidityContract) -> list[Finding]:
        self.reset()

        if not shutil.which("slither"):
            logger.info("Slither not installed. Skipping. Install with: pip install slither-analyzer")
            self.add_finding(
                severity="INFO",
                title="Slither Not Available",
                description="slither-analyzer is not installed. Install it for deeper static analysis.",
                recommendation="pip install slither-analyzer && pip install solc-select",
            )
            return self.findings

        try:
            result = subprocess.run(
                ["slither", contract.file_path, "--json", "-"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                detectors = data.get("results", {}).get("detectors", [])

                for det in detectors:
                    severity = SEVERITY_MAP.get(det.get("impact", ""), "INFO")
                    check = det.get("check", "unknown")
                    description = det.get("description", "No description")

                    # Extract first source mapping for location
                    location = ""
                    elements = det.get("elements", [])
                    if elements:
                        elem = elements[0]
                        source = elem.get("source_mapping", {})
                        filename = source.get("filename_relative", "")
                        lines_list = source.get("lines", [])
                        if filename and lines_list:
                            location = f"{filename}:{lines_list[0]}"

                    self.add_finding(
                        severity=severity,
                        title=f"Slither: {check}",
                        description=description[:500],
                        location=location,
                        recommendation=f"See Slither detector docs for `{check}`.",
                    )

            elif result.stderr:
                # Slither may output errors
                logger.info(f"Slither stderr: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            logger.error("Slither timed out after 120 seconds")
        except json.JSONDecodeError:
            logger.info("Could not parse Slither JSON output")
        except Exception as e:
            logger.error(f"Slither error: {e}")

        return self.findings
