import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.audit import parse_pip_audit_output, run_audit
from vulntriage.exceptions import AuditError, ParseError


def test_parse_single_package_single_vuln(pip_audit_json: str) -> None:
    cves = parse_pip_audit_output(pip_audit_json)
    assert len(cves) == 2
    req_cve = next(c for c in cves if c.package == "requests")
    assert req_cve.id == "PYSEC-2023-74"
    assert req_cve.installed_version == "2.28.0"
    assert req_cve.fix_versions == ["2.31.0"]
    assert "CVE-2023-32681" in req_cve.aliases


def test_parse_empty_list() -> None:
    cves = parse_pip_audit_output("[]")
    assert cves == []


def test_parse_package_no_vulns() -> None:
    raw = json.dumps([{"name": "requests", "version": "2.31.0", "vulns": []}])
    cves = parse_pip_audit_output(raw)
    assert cves == []


def test_parse_invalid_json_raises() -> None:
    with pytest.raises(ParseError):
        parse_pip_audit_output("not json")


def test_parse_multiple_vulns_same_package() -> None:
    raw = json.dumps(
        [
            {
                "name": "pkg",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "CVE-A",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "",
                    },
                    {
                        "id": "CVE-B",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "",
                    },
                ],
            }
        ]
    )
    cves = parse_pip_audit_output(raw)
    assert len(cves) == 2
    assert {c.id for c in cves} == {"CVE-A", "CVE-B"}


def test_run_audit_success() -> None:
    fake_output = json.dumps(
        [
            {
                "name": "requests",
                "version": "2.28.0",
                "vulns": [
                    {
                        "id": "CVE-2023-32681",
                        "fix_versions": ["2.31.0"],
                        "aliases": [],
                        "description": "test",
                    }
                ],
            }
        ]
    ).encode()
    mock_result = MagicMock()
    mock_result.stdout = fake_output
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        cves = run_audit()
    mock_run.assert_called_once_with(
        ["pip-audit", "--format", "json", "--no-fail-on-found"],
        capture_output=True,
        check=True,
    )
    assert len(cves) == 1
    assert cves[0].package == "requests"


def test_run_audit_pip_audit_not_found() -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(AuditError, match="pip-audit not found"):
            run_audit()


def test_run_audit_nonzero_exit() -> None:
    with patch(
        "subprocess.run", side_effect=subprocess.CalledProcessError(1, "pip-audit")
    ):
        with pytest.raises(AuditError, match="exited with code 1"):
            run_audit()
