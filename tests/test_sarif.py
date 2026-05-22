import json
from pathlib import Path

import pytest

from vulntriage.models import CVE, RankedCVE
from vulntriage.sarif import render_sarif, to_sarif


def _cve(
    cve_id: str = "CVE-2024-12345",
    package: str = "requests",
    installed: str = "2.31.0",
    fix_versions: tuple[str, ...] = ("2.32.0",),
    description: str = "Test vuln.",
) -> CVE:
    return CVE(
        id=cve_id,
        package=package,
        installed_version=installed,
        fix_versions=fix_versions,
        aliases=(),
        description=description,
    )


def _ranked(
    cve: CVE | None = None,
    rank: int = 1,
    risk: str = "HIGH",
    reasoning: str = "Used on request path.",
    fix_command: str = "pip install requests>=2.32.0",
    cvss: str = "7.5",
    epss: str = "12.3%",
    kev: bool = False,
) -> RankedCVE:
    return RankedCVE(
        rank=rank,
        cve=cve or _cve(),
        real_risk=risk,
        reasoning=reasoning,
        fix_command=fix_command,
        cvss=cvss,
        epss=epss,
        kev=kev,
        breaking_changes="",
        code_changes="",
    )


def test_sarif_empty_input_produces_valid_schema(tmp_path: Path) -> None:
    out = to_sarif([], project_root=tmp_path)
    assert out["$schema"].startswith("https://")
    assert out["version"] == "2.1.0"
    assert len(out["runs"]) == 1
    assert out["runs"][0]["results"] == []
    assert out["runs"][0]["tool"]["driver"]["name"] == "vulntriage"
    assert "version" in out["runs"][0]["tool"]["driver"]
    assert out["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_single_result_round_trips_through_json(tmp_path: Path) -> None:
    payload = to_sarif([_ranked()], project_root=tmp_path)
    text = json.dumps(payload)
    parsed = json.loads(text)
    assert parsed["runs"][0]["results"][0]["ruleId"] == "CVE-2024-12345"


@pytest.mark.parametrize(
    "risk,expected_level",
    [
        ("CRITICAL", "error"),
        ("HIGH", "error"),
        ("MEDIUM", "warning"),
        ("LOW", "note"),
        ("INFO", "note"),
    ],
)
def test_sarif_severity_mapping(risk: str, expected_level: str, tmp_path: Path) -> None:
    out = to_sarif([_ranked(risk=risk)], project_root=tmp_path)
    assert out["runs"][0]["results"][0]["level"] == expected_level


def test_sarif_message_uses_reasoning_text(tmp_path: Path) -> None:
    r = _ranked(reasoning="Reachable via session.send().")
    out = to_sarif([r], project_root=tmp_path)
    assert out["runs"][0]["results"][0]["message"]["text"] == (
        "Reachable via session.send()."
    )


def test_sarif_location_resolves_to_requirements_line(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.0\nrequests==2.31.0\nboto3==1.0.0\n")
    out = to_sarif([_ranked()], project_root=tmp_path)
    loc = out["runs"][0]["results"][0]["locations"][0]
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "requirements.txt"
    # requests is on line 2 (1-indexed)
    assert loc["physicalLocation"]["region"]["startLine"] == 2


def test_sarif_location_resolves_to_pyproject_line(tmp_path: Path) -> None:
    pyp = tmp_path / "pyproject.toml"
    pyp.write_text(
        '[project]\nname = "x"\ndependencies = [\n  "flask>=2.0",\n'
        '  "requests==2.31.0",\n]\n'
    )
    out = to_sarif([_ranked()], project_root=tmp_path)
    loc = out["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "pyproject.toml"
    assert loc["physicalLocation"]["region"]["startLine"] == 5


def test_sarif_location_degrades_to_file_when_line_not_found(
    tmp_path: Path,
) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.0.0\n")  # no requests entry
    out = to_sarif([_ranked()], project_root=tmp_path)
    loc = out["runs"][0]["results"][0]["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
    assert "region" not in loc["physicalLocation"]


def test_sarif_location_degrades_to_project_root_when_no_dep_file(
    tmp_path: Path,
) -> None:
    out = to_sarif([_ranked()], project_root=tmp_path)
    locs = out["runs"][0]["results"][0]["locations"]
    # Must always have at least one location for SARIF consumers
    assert len(locs) == 1
    assert locs[0]["physicalLocation"]["artifactLocation"]["uri"] == "."


def test_sarif_preserves_threat_intel_properties(tmp_path: Path) -> None:
    r = _ranked(cvss="9.8", epss="97.5%", kev=True)
    out = to_sarif([r], project_root=tmp_path)
    props = out["runs"][0]["results"][0]["properties"]
    assert props["cvss_score"] == "9.8"
    assert props["epss_pct"] == "97.5%"
    assert props["kev"] is True


def test_sarif_rules_deduplicated_per_unique_cve(tmp_path: Path) -> None:
    # Same CVE appearing twice should produce ONE rule entry, two results
    cve = _cve()
    out = to_sarif(
        [_ranked(cve=cve, rank=1), _ranked(cve=cve, rank=2)],
        project_root=tmp_path,
    )
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CVE-2024-12345"
    assert len(out["runs"][0]["results"]) == 2


def test_sarif_rules_carry_description(tmp_path: Path) -> None:
    cve = _cve(description="Improper authentication in requests.")
    out = to_sarif([_ranked(cve=cve)], project_root=tmp_path)
    rule = out["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "CVE-2024-12345"
    assert "Improper authentication" in rule["fullDescription"]["text"]


def test_sarif_output_is_deterministic_for_same_input(tmp_path: Path) -> None:
    rs = [_ranked(rank=1), _ranked(rank=2, cve=_cve(cve_id="CVE-2024-99999"))]
    first = json.dumps(to_sarif(rs, project_root=tmp_path), sort_keys=True)
    second = json.dumps(to_sarif(rs, project_root=tmp_path), sort_keys=True)
    assert first == second


def test_sarif_handles_unicode_in_reasoning(tmp_path: Path) -> None:
    r = _ranked(reasoning="使用在认证路径 — also OK with ☃ snowman.")
    out = to_sarif([r], project_root=tmp_path)
    text = json.dumps(out, ensure_ascii=False)
    assert "认证" in text
    assert "☃" in text


def test_render_sarif_prints_json_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    render_sarif([_ranked()], project_root=tmp_path)
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["version"] == "2.1.0"
    assert parsed["runs"][0]["results"][0]["ruleId"] == "CVE-2024-12345"


def test_render_sarif_swallows_broken_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_print(*args: object, **kwargs: object) -> None:
        raise BrokenPipeError()

    monkeypatch.setattr("builtins.print", fake_print)
    # Must not raise
    render_sarif([_ranked()], project_root=tmp_path)
