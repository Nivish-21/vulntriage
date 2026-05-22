"""SARIF 2.1.0 output for vulntriage.

SARIF is the format consumed by GitHub code-scanning, GitLab security
dashboards, and Sonar. One scan = one SARIF "run"; each ranked CVE is a
result. CRITICAL/HIGH map to 'error', MEDIUM to 'warning', LOW/INFO to
'note' per common SARIF conventions for vulnerability scanners.

Output is deterministic for the same input so SARIF diffs in CI are
meaningful (no spurious churn between runs).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from vulntriage.models import RankedCVE

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VERSION = "2.1.0"
_TOOL_INFO_URI = "https://pypi.org/project/vulntriage/"

_LEVEL_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_DEP_FILES: tuple[str, ...] = ("requirements.txt", "pyproject.toml")


def _tool_version() -> str:
    try:
        return version("vulntriage")
    except PackageNotFoundError:
        return "0.0.0"


def _find_package_line(dep_file: Path, package: str) -> int | None:
    """Return 1-indexed line number where `package` appears, or None."""
    try:
        text = dep_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    needle = package.lower()
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip().lower()
        # Match common pin forms: name==x, name>=x, "name>=x", name[extra]==x
        if stripped.startswith(needle) or f'"{needle}' in stripped:
            # Disambiguate prefix collisions: require non-alnum boundary after.
            tail_pos = stripped.find(needle) + len(needle)
            if tail_pos >= len(stripped) or not stripped[tail_pos].isalnum():
                return i
    return None


def _location_for(package: str, project_root: Path) -> dict[str, Any]:
    for name in _DEP_FILES:
        path = project_root / name
        if path.exists():
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": name},
                }
            }
            line = _find_package_line(path, package)
            if line is not None:
                location["physicalLocation"]["region"] = {"startLine": line}
            return location
    return {"physicalLocation": {"artifactLocation": {"uri": "."}}}


def _result(r: RankedCVE, project_root: Path) -> dict[str, Any]:
    return {
        "ruleId": r.cve.id,
        "level": _LEVEL_MAP.get(r.real_risk, "note"),
        "message": {"text": r.reasoning},
        "locations": [_location_for(r.cve.package, project_root)],
        "properties": {
            "rank": r.rank,
            "real_risk": r.real_risk,
            "cvss_score": r.cvss,
            "epss_pct": r.epss,
            "kev": r.kev,
            "package": r.cve.package,
            "installed_version": r.cve.installed_version,
            "fix_command": r.fix_command,
        },
    }


def _rules_from(ranked: Sequence[RankedCVE]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for r in ranked:
        if r.cve.id in seen:
            continue
        seen[r.cve.id] = {
            "id": r.cve.id,
            "shortDescription": {"text": r.cve.id},
            "fullDescription": {
                "text": r.cve.description or f"Vulnerability {r.cve.id}"
            },
            "helpUri": f"https://nvd.nist.gov/vuln/detail/{r.cve.id}",
        }
    # Sort by ID for deterministic output regardless of input order.
    return [seen[k] for k in sorted(seen)]


def to_sarif(ranked: Sequence[RankedCVE], project_root: Path) -> dict[str, Any]:
    """Serialise a list of ranked CVEs to a SARIF 2.1.0 dictionary."""
    return {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulntriage",
                        "version": _tool_version(),
                        "informationUri": _TOOL_INFO_URI,
                        "rules": _rules_from(ranked),
                    }
                },
                "results": [_result(r, project_root) for r in ranked],
            }
        ],
    }


def render_sarif(ranked: Sequence[RankedCVE], project_root: Path) -> None:
    """Print SARIF JSON to stdout. Silently swallows BrokenPipeError."""
    payload = json.dumps(
        to_sarif(ranked, project_root),
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
    try:
        print(payload)
        sys.stdout.flush()
    except BrokenPipeError:
        pass
