import json
from unittest.mock import patch

from vulntriage.models import CVE, RankedCVE
from vulntriage.output import determine_exit_code, render_json, render_table


def _make_ranked(real_risk: str, rank: int = 1) -> RankedCVE:
    cve = CVE(
        id="CVE-2023-32681",
        package="requests",
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="Test vuln",
    )
    return RankedCVE(
        rank=rank,
        cve=cve,
        real_risk=real_risk,
        reasoning="Direct dependency used in every request.",
        fix_command="pip install requests==2.31.0",
    )


def test_determine_exit_code_critical_returns_1() -> None:
    assert determine_exit_code([_make_ranked("CRITICAL")]) == 1


def test_determine_exit_code_high_returns_1() -> None:
    assert determine_exit_code([_make_ranked("HIGH")]) == 1


def test_determine_exit_code_medium_returns_0() -> None:
    assert determine_exit_code([_make_ranked("MEDIUM")]) == 0


def test_determine_exit_code_low_returns_0() -> None:
    assert determine_exit_code([_make_ranked("LOW")]) == 0


def test_determine_exit_code_empty_returns_0() -> None:
    assert determine_exit_code([]) == 0


def test_determine_exit_code_mixed_high_and_low_returns_1() -> None:
    ranked = [_make_ranked("HIGH", rank=1), _make_ranked("LOW", rank=2)]
    assert determine_exit_code(ranked) == 1


def test_render_table_empty_prints_no_vulns(capsys: object) -> None:
    with patch("vulntriage.output.console") as mock_console:
        render_table([])
        mock_console.print.assert_called_once()
        call_arg = mock_console.print.call_args[0][0]
        assert "No vulnerabilities" in call_arg


def test_render_table_prints_table_for_ranked(capsys: object) -> None:
    with patch("vulntriage.output.console") as mock_console:
        render_table([_make_ranked("HIGH")])
        mock_console.print.assert_called_once()


# --- fail_on threshold tests ---


def test_determine_exit_code_fail_on_medium_triggers_on_medium() -> None:
    assert determine_exit_code([_make_ranked("MEDIUM")], fail_on="MEDIUM") == 1


def test_determine_exit_code_fail_on_critical_ignores_high() -> None:
    assert determine_exit_code([_make_ranked("HIGH")], fail_on="CRITICAL") == 0


def test_determine_exit_code_fail_on_low_triggers_on_low() -> None:
    assert determine_exit_code([_make_ranked("LOW")], fail_on="LOW") == 1


# --- render_json tests ---


def test_render_json_empty_prints_empty_array(capsys: object) -> None:
    render_json([])
    out = capsys.readouterr().out
    assert json.loads(out) == []


def test_render_json_contains_expected_fields(capsys: object) -> None:
    render_json([_make_ranked("HIGH")])
    out = capsys.readouterr().out
    items = json.loads(out)
    assert len(items) == 1
    item = items[0]
    assert item["rank"] == 1
    assert item["id"] == "CVE-2023-32681"
    assert item["package"] == "requests"
    assert item["installed_version"] == "2.28.0"
    assert item["real_risk"] == "HIGH"
    assert "reasoning" in item
    assert "fix_command" in item
