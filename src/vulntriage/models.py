from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from packaging.version import InvalidVersion, Version

RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class LLMProvider(Protocol):
    def complete(self, system: str, user: str) -> str: ...


def min_fix_version(versions: Sequence[str]) -> str | None:
    """Return the lowest version string from a sequence, using semver ordering.

    Returns None if the sequence is empty (no fix published yet).
    """
    if not versions:
        return None
    try:
        return str(min(versions, key=Version))
    except InvalidVersion:
        # Fallback: lexicographic sort if any version is non-PEP-440.
        return min(versions)


@dataclass(frozen=True)
class CVE:
    id: str
    package: str
    installed_version: str
    fix_versions: tuple[str, ...]
    aliases: tuple[str, ...]
    description: str

    def __post_init__(self) -> None:
        # Coerce iterables to tuple — type hints aren't enforced at runtime,
        # and a list here would silently break the frozen=True guarantee.
        object.__setattr__(self, "fix_versions", tuple(self.fix_versions))
        object.__setattr__(self, "aliases", tuple(self.aliases))


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
    code_changes: str = ""
