import json
from pathlib import Path
from unittest.mock import patch

from vulntriage.models import CVE, RankedCVE
from vulntriage.output import (
    determine_exit_code,
    render_json,
    render_table,
    save_report,
)


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
        assert mock_console.print.call_count >= 1
        first_call_arg = mock_console.print.call_args_list[0][0][0]
        from rich.table import Table

        assert isinstance(first_call_arg, Table)


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
    assert "cvss" in item
    assert "kev" in item
    assert "epss" in item
    assert "reasoning" in item
    assert "fix_command" in item
    assert "breaking_changes" in item


def test_render_json_kev_and_epss_values(capsys: object) -> None:
    cve = CVE(
        id="CVE-2023-32681",
        package="requests",
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="Test vuln",
    )
    ranked = RankedCVE(
        rank=1,
        cve=cve,
        real_risk="CRITICAL",
        reasoning="x",
        fix_command="pip install requests==2.31.0",
        kev=True,
        epss="97.5%",
    )
    render_json([ranked])
    items = json.loads(capsys.readouterr().out)
    assert items[0]["kev"] is True
    assert items[0]["epss"] == "97.5%"


# --- save_report tests ---


def test_save_report_creates_file(tmp_path: Path) -> None:
    ranked = [_make_ranked("HIGH")]
    path = save_report(
        ranked, {"provider": "anthropic", "cves_found": 1, "cves_ranked": 1}, tmp_path
    )
    assert path.exists()
    assert path.suffix == ".json"
    assert path.parent == tmp_path


def test_save_report_file_contents(tmp_path: Path) -> None:
    ranked = [_make_ranked("HIGH")]
    path = save_report(
        ranked,
        {
            "provider": "anthropic",
            "project_root": "/project",
            "cves_found": 1,
            "cves_ranked": 1,
        },
        tmp_path,
    )
    data = json.loads(path.read_text())
    assert "timestamp" in data
    assert data["provider"] == "anthropic"
    assert data["cves_found"] == 1
    assert data["cves_ranked"] == 1
    assert len(data["results"]) == 1
    result = data["results"][0]
    assert result["id"] == "CVE-2023-32681"
    assert result["real_risk"] == "HIGH"
    assert "kev" in result
    assert "epss" in result


def test_save_report_creates_output_dir(tmp_path: Path) -> None:
    nested = tmp_path / "reports" / "subdir"
    ranked = [_make_ranked("LOW")]
    path = save_report(ranked, {"provider": "openai"}, nested)
    assert nested.is_dir()
    assert path.exists()


def test_render_json_swallows_broken_pipe(monkeypatch) -> None:
    def fake_print(*_args, **_kwargs) -> None:
        raise BrokenPipeError

    monkeypatch.setattr("builtins.print", fake_print)
    render_json([_make_ranked("HIGH")])


def test_render_json_swallows_broken_pipe_empty_list(monkeypatch) -> None:
    def fake_print(*_args, **_kwargs) -> None:
        raise BrokenPipeError

    monkeypatch.setattr("builtins.print", fake_print)
    render_json([])
