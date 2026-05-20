import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.audit import _AUDIT_TIMEOUT, _merge, parse_pip_audit_output, run_audit
from vulntriage.exceptions import AuditError, ParseError


def test_parse_single_package_single_vuln(pip_audit_json: str) -> None:
    cves = parse_pip_audit_output(pip_audit_json)
    assert len(cves) == 2
    req_cve = next(c for c in cves if c.package == "requests")
    assert req_cve.id == "PYSEC-2023-74"
    assert req_cve.installed_version == "2.28.0"
    assert req_cve.fix_versions == ("2.31.0",)
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


def test_run_audit_success(tmp_path: Path) -> None:
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
    mock_result.returncode = 0
    mock_result.stdout = fake_output
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        cves = run_audit(tmp_path)
    mock_run.assert_called_once_with(
        ["pip-audit", "--format", "json"],
        capture_output=True,
        timeout=_AUDIT_TIMEOUT,
    )
    assert len(cves) == 1
    assert cves[0].package == "requests"


def test_run_audit_pip_audit_not_found(tmp_path: Path) -> None:
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(AuditError, match="pip-audit not found"):
            run_audit(tmp_path)


def test_run_audit_error_exit(tmp_path: Path) -> None:
    mock_result = MagicMock()
    mock_result.returncode = 2
    mock_result.stderr = b"resolution failed"
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(AuditError, match="exited with code 2"):
            run_audit(tmp_path)


def test_run_audit_exit_1_returns_cves(tmp_path: Path) -> None:
    """exit code 1 = vulns found — should parse and return CVEs, not raise."""
    fake_output = json.dumps(
        [
            {
                "name": "requests",
                "version": "2.28.0",
                "vulns": [
                    {
                        "id": "PYSEC-2023-74",
                        "fix_versions": ["2.31.0"],
                        "aliases": [],
                        "description": "test",
                    }
                ],
            }
        ]
    ).encode()
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = fake_output
    with patch("subprocess.run", return_value=mock_result):
        cves = run_audit(tmp_path)
    assert len(cves) == 1
    assert cves[0].package == "requests"


def test_run_audit_timeout(tmp_path: Path) -> None:
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired("pip-audit", _AUDIT_TIMEOUT),
    ):
        with pytest.raises(AuditError, match=str(_AUDIT_TIMEOUT)):
            run_audit(tmp_path)


def test_run_audit_uses_requirements_txt(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = b"[]"
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        run_audit(tmp_path)
    assert mock_run.call_count == 2
    mock_run.assert_any_call(
        ["pip-audit", "-r", str(req), "--format", "json"],
        capture_output=True,
        timeout=_AUDIT_TIMEOUT,
    )
    mock_run.assert_any_call(
        ["pip-audit", "--format", "json"],
        capture_output=True,
        timeout=_AUDIT_TIMEOUT,
    )


def test_run_audit_uses_pyproject_toml(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = b"[]"
    with patch("subprocess.run", return_value=mock_result) as mock_run:
        run_audit(tmp_path)
    assert mock_run.call_count == 2
    mock_run.assert_any_call(
        ["pip-audit", "--path", str(tmp_path), "--format", "json"],
        capture_output=True,
        timeout=_AUDIT_TIMEOUT,
    )
    mock_run.assert_any_call(
        ["pip-audit", "--format", "json"],
        capture_output=True,
        timeout=_AUDIT_TIMEOUT,
    )


def test_merge_env_cves_fill_gap() -> None:
    """CVEs from bare env scan that aren't in scoped scan appear in merged output."""
    from vulntriage.models import CVE

    scoped = [
        CVE(
            id="CVE-A",
            package="requests",
            installed_version="1.0",
            fix_versions=[],
            aliases=[],
            description="",
        )
    ]
    env = [
        CVE(
            id="CVE-A",
            package="requests",
            installed_version="1.0",
            fix_versions=[],
            aliases=[],
            description="",
        ),
        CVE(
            id="CVE-B",
            package="pip",
            installed_version="26.0",
            fix_versions=[],
            aliases=[],
            description="",
        ),
    ]
    merged = _merge(scoped, env)
    assert len(merged) == 2
    assert {c.id for c in merged} == {"CVE-A", "CVE-B"}


def test_merge_scoped_entry_takes_priority() -> None:
    """When same CVE ID appears in both, scoped entry is kept."""
    from vulntriage.models import CVE

    scoped_cve = CVE(
        id="CVE-A",
        package="requests",
        installed_version="1.0",
        fix_versions=["2.0"],
        aliases=[],
        description="scoped",
    )
    env_cve = CVE(
        id="CVE-A",
        package="requests",
        installed_version="1.0",
        fix_versions=[],
        aliases=[],
        description="env",
    )
    merged = _merge([scoped_cve], [env_cve])
    assert len(merged) == 1
    assert merged[0].description == "scoped"


def test_run_audit_env_cves_included_with_requirements(tmp_path: Path) -> None:
    """CVEs from bare env scan are merged when requirements.txt exists."""

    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")

    scoped_output = json.dumps(
        [
            {
                "name": "requests",
                "version": "2.28.0",
                "vulns": [
                    {
                        "id": "CVE-A",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "",
                    }
                ],
            }
        ]
    ).encode()
    env_output = json.dumps(
        [
            {
                "name": "requests",
                "version": "2.28.0",
                "vulns": [
                    {
                        "id": "CVE-A",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "",
                    }
                ],
            },
            {
                "name": "pip",
                "version": "26.0",
                "vulns": [
                    {
                        "id": "CVE-B",
                        "fix_versions": [],
                        "aliases": [],
                        "description": "",
                    }
                ],
            },
        ]
    ).encode()

    scoped_result = MagicMock(returncode=1, stdout=scoped_output)
    env_result = MagicMock(returncode=1, stdout=env_output)

    with patch("subprocess.run", side_effect=[scoped_result, env_result]):
        cves = run_audit(tmp_path)

    assert {c.id for c in cves} == {"CVE-A", "CVE-B"}
    assert len(cves) == 2


def test_run_audit_non_utf8_stdout(tmp_path: Path) -> None:
    """Non-UTF-8 bytes must raise ParseError (bad JSON), not UnicodeDecodeError."""
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = b"\xff\xfe"
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(ParseError):
            run_audit(tmp_path)
