from dataclasses import dataclass
from typing import Literal

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


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
