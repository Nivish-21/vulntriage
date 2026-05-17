from dataclasses import dataclass
from typing import Literal, Protocol

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class LLMProvider(Protocol):
    def complete(self, system: str, user: str) -> str: ...


@dataclass(frozen=True)
class CVE:
    id: str
    package: str
    installed_version: str
    fix_versions: list[str]
    aliases: list[str]
    description: str


@dataclass(frozen=True)
class RankedCVE:
    rank: int
    cve: CVE
    real_risk: RiskLevel
    reasoning: str
    fix_command: str
    cvss: str = ""
    breaking_changes: str = ""
    kev: bool = False
    epss: str = ""
