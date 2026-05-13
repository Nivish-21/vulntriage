import json
from unittest.mock import MagicMock, patch

import anthropic
import pytest

from vulntriage.exceptions import AuthError, ParseError
from vulntriage.models import CVE
from vulntriage.ranker import build_prompt, parse_claude_response, rank_cves


def _make_cve(cve_id: str = "CVE-2023-32681", package: str = "requests") -> CVE:
    return CVE(
        id=cve_id,
        package=package,
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="Test vuln",
    )


def test_build_prompt_contains_cve_id() -> None:
    cves = [_make_cve()]
    prompt = build_prompt(cves, "requests==2.28.0")
    assert "CVE-2023-32681" in prompt
    assert "requests==2.28.0" in prompt


def test_build_prompt_contains_all_cves() -> None:
    cves = [_make_cve("CVE-A"), _make_cve("CVE-B", "urllib3")]
    prompt = build_prompt(cves, "")
    assert "CVE-A" in prompt
    assert "CVE-B" in prompt


def test_parse_claude_response_valid_json() -> None:
    cve = _make_cve()
    response = json.dumps(
        [
            {
                "id": "CVE-2023-32681",
                "real_risk": "HIGH",
                "reasoning": "Direct dep used for every HTTP call.",
                "fix_command": "pip install requests==2.31.0",
            }
        ]
    )
    ranked = parse_claude_response(response, [cve])
    assert len(ranked) == 1
    assert ranked[0].real_risk == "HIGH"
    assert ranked[0].rank == 1
    assert ranked[0].cve is cve


def test_parse_claude_response_strips_code_fence() -> None:
    cve = _make_cve()
    response = (
        "```json\n"
        + json.dumps(
            [
                {
                    "id": "CVE-2023-32681",
                    "real_risk": "LOW",
                    "reasoning": "Transitive only.",
                    "fix_command": "pip install requests==2.31.0",
                }
            ]
        )
        + "\n```"
    )
    ranked = parse_claude_response(response, [cve])
    assert ranked[0].real_risk == "LOW"


def test_parse_claude_response_unknown_id_skipped() -> None:
    cve = _make_cve()
    response = json.dumps(
        [
            {
                "id": "CVE-UNKNOWN",
                "real_risk": "HIGH",
                "reasoning": "x",
                "fix_command": "pip install x",
            }
        ]
    )
    ranked = parse_claude_response(response, [cve])
    assert ranked == []


def test_parse_claude_response_invalid_json_raises() -> None:
    with pytest.raises(ParseError):
        parse_claude_response("not json at all", [_make_cve()])


def test_rank_cves_calls_api_and_returns_ranked() -> None:
    cve = _make_cve()
    fake_response_text = json.dumps(
        [
            {
                "id": "CVE-2023-32681",
                "real_risk": "HIGH",
                "reasoning": "Direct dep.",
                "fix_command": "pip install requests==2.31.0",
            }
        ]
    )
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fake_response_text)]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_message
        ranked = rank_cves([cve], "requests==2.28.0", api_key="test-key")
    assert len(ranked) == 1
    assert ranked[0].real_risk == "HIGH"
    mock_client.messages.create.assert_called_once()


def test_parse_claude_response_missing_field_raises() -> None:
    cve = _make_cve()
    response = json.dumps([{"id": "CVE-2023-32681", "real_risk": "HIGH"}])
    with pytest.raises(ParseError, match="missing required field"):
        parse_claude_response(response, [cve])


def test_parse_claude_response_invalid_risk_raises() -> None:
    cve = _make_cve()
    response = json.dumps(
        [
            {
                "id": "CVE-2023-32681",
                "real_risk": "EXTREME",
                "reasoning": "x",
                "fix_command": "pip install x",
            }
        ]
    )
    with pytest.raises(ParseError, match="unrecognised risk level"):
        parse_claude_response(response, [cve])


def test_rank_cves_raises_auth_error_on_bad_key() -> None:
    class FakeAuthError(anthropic.AuthenticationError):
        def __init__(self) -> None:
            pass

    cve = _make_cve()
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.side_effect = FakeAuthError()
        with pytest.raises(AuthError):
            rank_cves([cve], "", api_key="bad-key")


def test_rank_cves_raises_parse_error_on_empty_content() -> None:
    mock_message = MagicMock()
    mock_message.content = []
    cve = _make_cve()
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_message
        with pytest.raises(ParseError, match="empty or non-text"):
            rank_cves([cve], "", api_key="test-key")
