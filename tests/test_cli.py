from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from vulntriage.cli import app
from vulntriage.exceptions import AuditError, AuthError, ContextError, ParseError
from vulntriage.models import CVE, RankedCVE

runner = CliRunner()


def _make_cve() -> CVE:
    return CVE(
        id="CVE-2023-32681",
        package="requests",
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="Test vuln",
    )


def _make_ranked(real_risk: str = "HIGH") -> RankedCVE:
    return RankedCVE(
        rank=1,
        cve=_make_cve(),
        real_risk=real_risk,
        reasoning="Direct dep.",
        fix_command="pip install requests==2.31.0",
    )


def test_scan_exits_1_when_api_key_missing() -> None:
    result = runner.invoke(app, ["scan"], env={"ANTHROPIC_API_KEY": ""})
    assert result.exit_code == 1
    assert "ANTHROPIC_API_KEY" in result.output


def test_scan_exits_1_on_audit_error() -> None:
    with patch(
        "vulntriage.cli.run_audit", side_effect=AuditError("pip-audit not found")
    ):
        result = runner.invoke(app, ["scan"], env={"ANTHROPIC_API_KEY": "test-key"})
    assert result.exit_code == 1
    assert "pip-audit not found" in result.output


def test_scan_exits_0_when_no_cves(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with patch("vulntriage.cli.run_audit", return_value=[]):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 0


def test_scan_exits_1_on_high_risk(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 1


def test_scan_exits_0_on_low_risk(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 0


def test_scan_continues_on_context_error(tmp_path: Path) -> None:
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", side_effect=ContextError("no file")),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 0


def test_scan_exits_1_on_parse_error(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", side_effect=ParseError("bad json")),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 1
    assert "bad json" in result.output


def test_scan_exits_1_on_auth_error(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch(
            "vulntriage.cli.rank_cves",
            side_effect=AuthError("Invalid or expired Anthropic API key."),
        ),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "bad-key"},
        )
    assert result.exit_code == 1
    assert "Invalid or expired" in result.output


def test_scan_warns_on_dropped_cves(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    cve1 = _make_cve()
    cve2 = CVE(
        id="CVE-2023-99999",
        package="urllib3",
        installed_version="1.26.0",
        fix_versions=["2.0.0"],
        aliases=[],
        description="Another vuln",
    )
    with (
        patch("vulntriage.cli.run_audit", return_value=[cve1, cve2]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "1 CVE(s) were dropped" in result.output
