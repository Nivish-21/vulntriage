import json
import subprocess
from typing import Any

from vulntriage.exceptions import AuditError, ParseError
from vulntriage.models import CVE


def parse_pip_audit_output(raw: str) -> list[CVE]:
    try:
        data: list[dict[str, Any]] = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON from pip-audit: {exc}") from exc
    cves: list[CVE] = []
    for package in data:
        for vuln in package.get("vulns", []):
            cves.append(
                CVE(
                    id=vuln["id"],
                    package=package["name"],
                    installed_version=package["version"],
                    fix_versions=vuln.get("fix_versions", []),
                    aliases=vuln.get("aliases", []),
                    description=vuln.get("description", ""),
                )
            )
    return cves


def run_audit() -> list[CVE]:
    try:
        result = subprocess.run(
            ["pip-audit", "--format", "json", "--no-fail-on-found"],
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise AuditError(
            "pip-audit not found. Install it with: pip install pip-audit"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise AuditError(f"pip-audit exited with code {exc.returncode}") from exc
    return parse_pip_audit_output(result.stdout.decode("utf-8"))
