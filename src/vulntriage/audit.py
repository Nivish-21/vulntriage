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
                    fix_versions=tuple(vuln.get("fix_versions", [])),
                    aliases=tuple(vuln.get("aliases", [])),
                    description=vuln.get("description", ""),
                )
            )
    return cves


def _run_cmd(cmd: list[str]) -> list[CVE]:
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


def _merge(scoped: list[CVE], env: list[CVE]) -> list[CVE]:
    """Merge scoped + full-env results, deduplicating by CVE ID.

    Scoped entries take priority — they carry the correct package context.
    Full-env entries fill in anything not declared in the project files.
    """
    seen = {cve.id for cve in scoped}
    return scoped + [cve for cve in env if cve.id not in seen]


def run_audit(project_root: Path) -> list[CVE]:
    req = project_root / "requirements.txt"
    toml = project_root / "pyproject.toml"

    if req.exists():
        scoped = _run_cmd(["pip-audit", "-r", str(req), "--format", "json"])
        env = _run_cmd(["pip-audit", "--format", "json"])
        return _merge(scoped, env)
    elif toml.exists():
        scoped = _run_cmd(
            ["pip-audit", "--path", str(project_root), "--format", "json"]
        )
        env = _run_cmd(["pip-audit", "--format", "json"])
        return _merge(scoped, env)
    else:
        return _run_cmd(["pip-audit", "--format", "json"])
