import json
import os
import subprocess
from pathlib import Path
from typing import Any

from vulntriage.exceptions import AuditError, ParseError
from vulntriage.models import CVE

_AUDIT_TIMEOUT = int(os.environ.get("VULNTRIAGE_AUDIT_TIMEOUT", "120"))


def parse_pip_audit_output(raw: str) -> list[CVE]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON from pip-audit: {exc}") from exc
    # pip-audit >=2.x wraps output in {"dependencies": [...], "fixes": [...]}
    # older versions returned a bare list
    if isinstance(parsed, dict):
        data: list[dict[str, Any]] = parsed.get("dependencies", [])
    else:
        data = parsed
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


def run_audit(project_root: Path) -> list[CVE]:
    req = project_root / "requirements.txt"
    toml = project_root / "pyproject.toml"
    if req.exists():
        cmd = ["pip-audit", "-r", str(req), "--format", "json"]
    elif toml.exists():
        cmd = ["pip-audit", "--path", str(project_root), "--format", "json"]
    else:
        cmd = ["pip-audit", "--format", "json"]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=_AUDIT_TIMEOUT)
    except FileNotFoundError as exc:
        raise AuditError(
            "pip-audit not found. Install it with: pip install pip-audit"
        ) from exc
    except subprocess.TimeoutExpired:
        raise AuditError(
            f"pip-audit timed out after {_AUDIT_TIMEOUT}s. "
            "Set VULNTRIAGE_AUDIT_TIMEOUT to override."
        )
    # exit 0 = no vulns, exit 1 = vulns found — both produce valid JSON stdout
    # exit 2+ = actual error (bad environment, resolution failure, etc.)
    if result.returncode > 1:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise AuditError(f"pip-audit exited with code {result.returncode}: {stderr}")
    return parse_pip_audit_output(result.stdout.decode("utf-8", errors="replace"))
