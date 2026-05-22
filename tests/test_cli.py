from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from vulntriage.cli import _ranked_to_dict, _resolve_cve_id, app
from vulntriage.exceptions import AuditError, AuthError, ContextError, ParseError
from vulntriage.models import CVE, RankedCVE

runner = CliRunner()


@pytest.fixture(autouse=True)
def _no_scan_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent tests from touching the real on-disk scan cache."""
    monkeypatch.setattr("vulntriage.cli.scan_cache_get", lambda key: None)
    monkeypatch.setattr("vulntriage.cli.scan_cache_set", lambda key, data: None)


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


def test_scan_prints_provider_name(tmp_path: Path) -> None:
    mock_provider = MagicMock()
    mock_provider.name = "anthropic (claude-sonnet-4-6)"
    with (
        patch("vulntriage.cli.get_provider", return_value=mock_provider),
        patch("vulntriage.cli.run_audit", return_value=[]),
    ):
        result = runner.invoke(app, ["scan", "--project-root", str(tmp_path)])
    assert "anthropic (claude-sonnet-4-6)" in result.output


def test_fail_on_medium_exits_1_on_medium_risk(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("MEDIUM")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--fail-on", "MEDIUM"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 1


def test_fail_on_critical_exits_0_on_high_risk(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--fail-on", "CRITICAL"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 0


def test_format_json_calls_render_json(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    ranked = [_make_ranked("HIGH")]
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=ranked),
        patch("vulntriage.cli.render_json") as mock_json,
        patch("vulntriage.cli.render_table") as mock_table,
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--format", "json"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_json.assert_called_once_with(ranked)
    mock_table.assert_not_called()
    assert result.exit_code == 1


def test_format_json_empty_calls_render_json_with_empty_list(tmp_path: Path) -> None:
    with (
        patch("vulntriage.cli.run_audit", return_value=[]),
        patch("vulntriage.cli.render_json") as mock_json,
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--format", "json"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_json.assert_called_once_with([])
    assert result.exit_code == 0


def test_vulnignore_suppresses_cve(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / ".vulnignore").write_text("CVE-2023-32681 accepted\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.rank_cves") as mock_rank,
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_rank.assert_not_called()
    assert result.exit_code == 0


def test_vulnignore_missing_file_does_not_error(tmp_path: Path) -> None:
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


def test_scan_exits_1_on_invalid_fail_on() -> None:
    result = runner.invoke(
        app,
        ["scan", "--fail-on", "EXTREME"],
        env={"ANTHROPIC_API_KEY": "test-key"},
    )
    assert result.exit_code == 1
    assert "invalid --fail-on" in result.output


def test_scan_accepts_lowercase_fail_on(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--fail-on", "high"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert result.exit_code == 1


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


def test_output_dir_calls_save_report(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    out_dir = tmp_path / "reports"
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
        patch(
            "vulntriage.cli.save_report", return_value=out_dir / "vulntriage-test.json"
        ) as mock_save,
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--output-dir", str(out_dir)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_save.assert_called_once()
    assert "Report saved" in result.output
    assert result.exit_code == 0


def test_no_output_dir_does_not_call_save_report(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
        patch("vulntriage.cli.save_report") as mock_save,
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_save.assert_not_called()
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# _resolve_cve_id
# ---------------------------------------------------------------------------


def _make_pysec_cve(aliases: list[str] | None = None) -> CVE:
    return CVE(
        id="PYSEC-2022-43012",
        package="setuptools",
        installed_version="65.0.0",
        fix_versions=["65.5.1"],
        aliases=aliases if aliases is not None else ["CVE-2022-40897"],
        description="Test PYSEC vuln",
    )


def test_resolve_cve_id_returns_first_cve_alias() -> None:
    assert _resolve_cve_id(_make_pysec_cve()) == "CVE-2022-40897"


def test_resolve_cve_id_falls_back_to_raw_id_when_no_aliases() -> None:
    cve = _make_pysec_cve(aliases=[])
    assert _resolve_cve_id(cve) == "PYSEC-2022-43012"


def test_resolve_cve_id_pure_cve_id_is_unchanged() -> None:
    assert _resolve_cve_id(_make_cve()) == "CVE-2023-32681"


def test_resolve_cve_id_skips_non_cve_aliases() -> None:
    cve = _make_pysec_cve(aliases=["GHSA-xxxx-yyyy-zzzz", "CVE-2022-12345"])
    assert _resolve_cve_id(cve) == "CVE-2022-12345"


def test_scan_resolves_pysec_alias_for_threat_intel_fetch(tmp_path: Path) -> None:
    """fetch_cvss_scores and fetch_epss receive the CVE alias, not the raw PYSEC ID."""
    (tmp_path / "requirements.txt").write_text("setuptools==65.0.0\n")
    pysec_cve = _make_pysec_cve()  # id=PYSEC-2022-43012, alias=CVE-2022-40897
    with (
        patch("vulntriage.cli.run_audit", return_value=[pysec_cve]),
        patch("vulntriage.cli.read_stack_context", return_value="setuptools==65.0.0"),
        patch(
            "vulntriage.cli.fetch_cvss_data",
            return_value={"CVE-2022-40897": {"score": "7.5", "vector": "N"}},
        ) as mock_nvd,
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch(
            "vulntriage.cli.fetch_epss",
            return_value={"CVE-2022-40897": "42.1"},
        ) as mock_epss,
        patch(
            "vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]
        ) as mock_rank,
        patch("vulntriage.cli.render_table"),
    ):
        runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )

    # Fetches used the CVE alias
    assert mock_nvd.call_args.args[0] == ["CVE-2022-40897"]
    assert mock_epss.call_args.args[0] == ["CVE-2022-40897"]

    # rank_cves received dicts keyed by the raw PYSEC ID
    kwargs = mock_rank.call_args.kwargs
    assert kwargs["nvd_data"] == {"PYSEC-2022-43012": {"score": "7.5", "vector": "N"}}
    assert kwargs["epss_scores"] == {"PYSEC-2022-43012": "42.1"}


# ---------------------------------------------------------------------------
# Task 2 — CVE deduplication
# ---------------------------------------------------------------------------


def test_scan_deduplicates_duplicate_cve_ids(tmp_path: Path) -> None:
    """pip-audit can emit the same CVE ID for multiple package records; deduplicate."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    cve = _make_cve()  # id=CVE-2023-32681
    dup = CVE(
        id="CVE-2023-32681",  # same id, different package record
        package="urllib3",
        installed_version="1.26.0",
        fix_versions=["2.0.0"],
        aliases=[],
        description="Duplicate record",
    )
    with (
        patch("vulntriage.cli.run_audit", return_value=[cve, dup]),
        patch("vulntriage.cli.read_stack_context", return_value=""),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch(
            "vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]
        ) as mock_rank,
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "Deduplicated 1" in result.output
    called_cves: list[CVE] = mock_rank.call_args.args[0]
    assert len(called_cves) == 1
    assert called_cves[0].id == "CVE-2023-32681"


# ---------------------------------------------------------------------------
# Task 3 — Scan result caching
# ---------------------------------------------------------------------------


def test_scan_cache_hit_skips_run_audit(tmp_path: Path) -> None:
    """A warm cache skips pip-audit, NVD/EPSS/KEV fetches, and rank_cves entirely."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    cached_results = [_ranked_to_dict(_make_ranked("HIGH"))]
    with (
        patch("vulntriage.cli.scan_cache_get", return_value=cached_results),
        patch("vulntriage.cli.run_audit") as mock_audit,
        patch("vulntriage.cli.rank_cves") as mock_rank,
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "cached" in result.output.lower()
    mock_audit.assert_not_called()
    mock_rank.assert_not_called()
    assert result.exit_code == 1  # HIGH risk triggers exit 1


def test_no_cache_flag_skips_cache_read(tmp_path: Path) -> None:
    """--no-cache must not call scan_cache_get; full scan still runs."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.scan_cache_get") as mock_get,
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value=""),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
    ):
        runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--no-cache"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_get.assert_not_called()


def test_scan_cache_set_called_after_ranking(tmp_path: Path) -> None:
    """scan_cache_set is called with the scan key and serialised ranked list."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.scan_cache_get", return_value=None),
        patch("vulntriage.cli.scan_cache_set") as mock_set,
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value=""),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("LOW")]),
        patch("vulntriage.cli.render_table"),
    ):
        runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    mock_set.assert_called_once()
    key, data = mock_set.call_args.args
    assert key.startswith("scan_")
    assert isinstance(data, list)
    assert len(data) == 1


def test_privacy_warning_shown_for_cloud_provider(tmp_path: Path) -> None:
    """A note about sending dependency data is shown before cloud LLM calls."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "dependency list sent" in result.output


def test_privacy_warning_not_shown_offline(tmp_path: Path) -> None:
    """No privacy warning when --offline flag is set (no cloud calls made)."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path), "--offline"],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "dependency list sent" not in result.output


def test_stale_vulnignore_warning_emitted(tmp_path: Path) -> None:
    """Suppressed IDs that no longer match any CVE produce a stderr warning."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / ".vulnignore").write_text("CVE-2023-32681\nCVE-1999-0000 long-gone\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[_make_ranked("HIGH")]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "CVE-1999-0000" in result.output
    assert "no longer match" in result.output


def test_stale_vulnignore_no_warning_when_all_match(tmp_path: Path) -> None:
    """No stale warning when every .vulnignore ID still maps to a reported CVE."""
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / ".vulnignore").write_text("CVE-2023-32681\n")
    with (
        patch("vulntriage.cli.run_audit", return_value=[_make_cve()]),
        patch("vulntriage.cli.read_stack_context", return_value="requests==2.28.0"),
        patch("vulntriage.cli.fetch_cvss_data", return_value={}),
        patch("vulntriage.cli.fetch_kev", return_value=set()),
        patch("vulntriage.cli.fetch_epss", return_value={}),
        patch("vulntriage.cli.rank_cves", return_value=[]),
        patch("vulntriage.cli.render_table"),
    ):
        result = runner.invoke(
            app,
            ["scan", "--project-root", str(tmp_path)],
            env={"ANTHROPIC_API_KEY": "test-key"},
        )
    assert "no longer match" not in result.output


# --- v0.10.0 --airgap mode ----------------------------------------------------


def test_airgap_forces_ollama_when_no_provider_chosen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("VULNTRIAGE_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    captured: dict[str, str] = {}

    def fake_get_provider(name: str | None = None) -> MagicMock:
        captured["name"] = name or "<none>"
        p = MagicMock()
        p.name = "ollama (mocked)"
        return p

    with patch("vulntriage.cli.get_provider", side_effect=fake_get_provider):
        with patch("vulntriage.cli.run_audit", side_effect=AuditError("stop here")):
            result = runner.invoke(app, ["scan", "--airgap"])
    # We don't care that audit failed — we care that get_provider was called
    # with 'ollama' explicitly.
    assert captured.get("name") == "ollama"
    assert result.exit_code == 1


def test_airgap_rejects_anthropic_provider() -> None:
    result = runner.invoke(
        app,
        ["scan", "--airgap"],
        env={"VULNTRIAGE_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "x"},
    )
    assert result.exit_code == 1
    assert "airgap" in result.output.lower()
    assert "anthropic" in result.output.lower()


def test_airgap_rejects_openai_provider() -> None:
    result = runner.invoke(
        app, ["scan", "--airgap"], env={"VULNTRIAGE_PROVIDER": "openai"}
    )
    assert result.exit_code == 1
    assert "airgap" in result.output.lower()


def test_airgap_implies_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """--airgap must skip NVD/KEV/EPSS fetches even without --offline."""
    seen: dict[str, bool] = {}

    def fake_fetch_cvss(cve_ids, **kwargs):  # type: ignore[no-untyped-def]
        seen["offline"] = bool(kwargs.get("offline"))
        return {}

    with patch("vulntriage.cli.get_provider") as gp:
        provider_mock = MagicMock()
        provider_mock.name = "ollama"
        gp.return_value = provider_mock
        with patch("vulntriage.cli.run_audit", return_value=[_make_cve()]):
            with patch("vulntriage.cli.read_stack_context", return_value="stack"):
                with patch("vulntriage.cli.load_ignores", return_value=set()):
                    with patch(
                        "vulntriage.cli.fetch_cvss_data",
                        side_effect=fake_fetch_cvss,
                    ):
                        with patch("vulntriage.cli.fetch_kev", return_value=set()):
                            with patch("vulntriage.cli.fetch_epss", return_value={}):
                                with patch(
                                    "vulntriage.cli.rank_cves",
                                    return_value=[_make_ranked()],
                                ):
                                    with patch(
                                        "vulntriage.cli.fetch_deprecation_info",
                                        return_value={},
                                    ):
                                        runner.invoke(app, ["scan", "--airgap"])
    assert seen.get("offline") is True
