import json
from unittest.mock import MagicMock, patch

import anthropic
import openai
import pytest

from vulntriage.exceptions import AuthError, ParseError
from vulntriage.models import CVE
from vulntriage.ranker import (
    AnthropicProvider,
    GeminiProvider,
    OllamaProvider,
    OpenAIProvider,
    build_prompt,
    get_provider,
    parse_claude_response,
    rank_cves,
)


def _make_cve(cve_id: str = "CVE-2023-32681", package: str = "requests") -> CVE:
    return CVE(
        id=cve_id,
        package=package,
        installed_version="2.28.0",
        fix_versions=["2.31.0"],
        aliases=[],
        description="Test vuln",
    )


def _fake_response(cve_id: str = "CVE-2023-32681", risk: str = "HIGH") -> str:
    return json.dumps(
        [
            {
                "id": cve_id,
                "real_risk": risk,
                "reasoning": "Direct dep used for every HTTP call.",
                "fix_command": "pip install requests==2.31.0",
            }
        ]
    )


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# parse_claude_response
# ---------------------------------------------------------------------------


def test_parse_claude_response_valid_json() -> None:
    cve = _make_cve()
    ranked = parse_claude_response(_fake_response(), [cve])
    assert len(ranked) == 1
    assert ranked[0].real_risk == "HIGH"
    assert ranked[0].rank == 1
    assert ranked[0].cve is cve


def test_parse_claude_response_strips_code_fence() -> None:
    cve = _make_cve()
    response = "```json\n" + _fake_response(risk="LOW") + "\n```"
    ranked = parse_claude_response(response, [cve])
    assert ranked[0].real_risk == "LOW"


def test_parse_claude_response_all_unknown_ids_raises() -> None:
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
    with pytest.raises(ParseError, match="hallucinated"):
        parse_claude_response(response, [cve])


def test_parse_claude_response_partial_unknown_ids_kept() -> None:
    cve_a = _make_cve("CVE-A")
    cve_b = _make_cve("CVE-B", "urllib3")
    response = json.dumps(
        [
            {
                "id": "CVE-A",
                "real_risk": "HIGH",
                "reasoning": "x",
                "fix_command": "pip install a",
            },
            {
                "id": "CVE-UNKNOWN",
                "real_risk": "LOW",
                "reasoning": "y",
                "fix_command": "pip install y",
            },
        ]
    )
    ranked = parse_claude_response(response, [cve_a, cve_b])
    assert len(ranked) == 1
    assert ranked[0].cve.id == "CVE-A"


def test_parse_claude_response_invalid_json_raises() -> None:
    with pytest.raises(ParseError):
        parse_claude_response("not json at all", [_make_cve()])


def test_parse_claude_response_missing_field_raises() -> None:
    response = json.dumps([{"id": "CVE-2023-32681", "real_risk": "HIGH"}])
    with pytest.raises(ParseError, match="missing required field"):
        parse_claude_response(response, [_make_cve()])


def test_parse_claude_response_invalid_risk_raises() -> None:
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
        parse_claude_response(response, [_make_cve()])


# ---------------------------------------------------------------------------
# AnthropicProvider
# ---------------------------------------------------------------------------


def test_anthropic_provider_raises_auth_error_when_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(AuthError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider()


def test_anthropic_provider_raises_auth_error_on_bad_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "bad-key")

    class FakeAuthError(anthropic.AuthenticationError):
        def __init__(self) -> None:
            pass

    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.side_effect = FakeAuthError()
        provider = AnthropicProvider()
        with pytest.raises(AuthError):
            provider.complete("system", "user")


def test_anthropic_provider_raises_parse_error_on_empty_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    mock_message = MagicMock()
    mock_message.content = []
    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_message
        provider = AnthropicProvider()
        with pytest.raises(ParseError, match="empty or non-text"):
            provider.complete("system", "user")


def test_anthropic_provider_returns_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="hello")]
    with patch("anthropic.Anthropic") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_message
        provider = AnthropicProvider()
        assert provider.complete("system", "user") == "hello"


# ---------------------------------------------------------------------------
# get_provider
# ---------------------------------------------------------------------------


def test_get_provider_returns_anthropic_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("VULNTRIAGE_PROVIDER", raising=False)
    assert isinstance(get_provider(), AnthropicProvider)


def test_get_provider_respects_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("VULNTRIAGE_PROVIDER", "anthropic")
    assert isinstance(get_provider(), AnthropicProvider)


def test_get_provider_raises_on_unknown_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNTRIAGE_PROVIDER", "grok")
    with pytest.raises(ValueError, match="Unknown provider"):
        get_provider()


def test_get_provider_returns_openai_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNTRIAGE_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    assert isinstance(get_provider(), OpenAIProvider)


# ---------------------------------------------------------------------------
# OpenAIProvider
# ---------------------------------------------------------------------------


def test_openai_provider_raises_auth_error_when_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(AuthError, match="OPENAI_API_KEY"):
        OpenAIProvider()


def test_openai_provider_raises_auth_error_on_bad_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "bad-key")

    class FakeAuthError(openai.AuthenticationError):
        def __init__(self) -> None:
            pass

    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = FakeAuthError()
        provider = OpenAIProvider()
        with pytest.raises(AuthError):
            provider.complete("system", "user")


def test_openai_provider_raises_parse_error_on_empty_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    mock_response = MagicMock()
    mock_response.choices = []
    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response
        provider = OpenAIProvider()
        with pytest.raises(ParseError, match="empty"):
            provider.complete("system", "user")


def test_openai_provider_returns_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    mock_choice = MagicMock()
    mock_choice.message.content = "hello"
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]
    with patch("openai.OpenAI") as mock_cls:
        mock_client = MagicMock()
        mock_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response
        provider = OpenAIProvider()
        assert provider.complete("system", "user") == "hello"


# ---------------------------------------------------------------------------
# GeminiProvider
# ---------------------------------------------------------------------------


def test_gemini_provider_raises_auth_error_when_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    with pytest.raises(AuthError, match="GOOGLE_API_KEY"):
        GeminiProvider()


def test_gemini_provider_raises_auth_error_on_bad_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "bad-key")

    class FakeClientError(Exception):
        status_code = 401

    with patch("vulntriage.ranker._genai_module") as mock_genai:
        mock_client = MagicMock()
        mock_genai.Client.return_value = mock_client
        mock_client.models.generate_content.side_effect = FakeClientError()
        provider = GeminiProvider()
        with pytest.raises(AuthError):
            provider.complete("system", "user")


def test_gemini_provider_raises_parse_error_on_empty_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    mock_response = MagicMock()
    mock_response.text = None
    with patch("vulntriage.ranker._genai_module") as mock_genai:
        mock_client = MagicMock()
        mock_genai.Client.return_value = mock_client
        mock_client.models.generate_content.return_value = mock_response
        provider = GeminiProvider()
        with pytest.raises(ParseError, match="empty"):
            provider.complete("system", "user")


def test_gemini_provider_returns_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    mock_response = MagicMock()
    mock_response.text = "hello"
    with patch("vulntriage.ranker._genai_module") as mock_genai:
        mock_client = MagicMock()
        mock_genai.Client.return_value = mock_client
        mock_client.models.generate_content.return_value = mock_response
        provider = GeminiProvider()
        assert provider.complete("system", "user") == "hello"


def test_get_provider_returns_gemini_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNTRIAGE_PROVIDER", "gemini")
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    with patch("vulntriage.ranker._genai_module") as mock_genai:
        mock_genai.Client.return_value = MagicMock()
        assert isinstance(get_provider(), GeminiProvider)


# ---------------------------------------------------------------------------
# OllamaProvider
# ---------------------------------------------------------------------------


def test_ollama_provider_raises_parse_error_on_empty_content() -> None:
    mock_response = MagicMock()
    mock_response.message.content = None
    with patch("vulntriage.ranker._ollama_module") as mock_ollama:
        mock_client = MagicMock()
        mock_ollama.Client.return_value = mock_client
        mock_client.chat.return_value = mock_response
        provider = OllamaProvider()
        with pytest.raises(ParseError, match="empty"):
            provider.complete("system", "user")


def test_ollama_provider_returns_text() -> None:
    mock_response = MagicMock()
    mock_response.message.content = "hello"
    with patch("vulntriage.ranker._ollama_module") as mock_ollama:
        mock_client = MagicMock()
        mock_ollama.Client.return_value = mock_client
        mock_client.chat.return_value = mock_response
        provider = OllamaProvider()
        assert provider.complete("system", "user") == "hello"


def test_get_provider_returns_ollama_when_env_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VULNTRIAGE_PROVIDER", "ollama")
    with patch("vulntriage.ranker._ollama_module") as mock_ollama:
        mock_ollama.Client.return_value = MagicMock()
        assert isinstance(get_provider(), OllamaProvider)


# ---------------------------------------------------------------------------
# rank_cves (integration via injected mock provider)
# ---------------------------------------------------------------------------


def test_rank_cves_uses_injected_provider() -> None:
    cve = _make_cve()
    mock_provider = MagicMock()
    mock_provider.complete.return_value = _fake_response()
    ranked = rank_cves([cve], "requests==2.28.0", provider=mock_provider)
    assert len(ranked) == 1
    assert ranked[0].real_risk == "HIGH"
    mock_provider.complete.assert_called_once()


def test_rank_cves_passes_system_and_prompt_to_provider() -> None:
    cve = _make_cve()
    mock_provider = MagicMock()
    mock_provider.complete.return_value = _fake_response()
    rank_cves([cve], "stack-context", provider=mock_provider)
    call_args = mock_provider.complete.call_args
    system_arg, user_arg = call_args[0]
    assert "security engineer" in system_arg.lower()
    assert "CVE-2023-32681" in user_arg
    assert "stack-context" in user_arg
