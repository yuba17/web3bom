"""Base class for all audit agents."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from utils.solidity_parser import SolidityContract


@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    location: str = ""  # file:line
    agent: str = ""
    recommendation: str = ""
    code_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "agent": self.agent,
            "recommendation": self.recommendation,
            "code_snippet": self.code_snippet,
        }


class BaseAgent(ABC):
    """Base class all audit agents inherit from."""

    name: str = "BaseAgent"
    description: str = "Base audit agent"

    def __init__(self):
        self.findings: list[Finding] = []

    @abstractmethod
    def analyze(self, contract: SolidityContract) -> list[Finding]:
        """Run analysis on a parsed contract. Returns list of findings."""
        pass

    def add_finding(self, severity: str, title: str, description: str,
                    location: str = "", recommendation: str = "", code_snippet: str = "") -> Finding:
        f = Finding(
            severity=severity,
            title=title,
            description=description,
            location=location,
            agent=self.name,
            recommendation=recommendation,
            code_snippet=code_snippet,
        )
        self.findings.append(f)
        return f

    def reset(self):
        self.findings = []
