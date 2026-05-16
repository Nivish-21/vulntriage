import json
import os
import re
from typing import Any

import anthropic

from vulntriage.exceptions import AuthError, ParseError
from vulntriage.models import CVE, LLMProvider, RankedCVE

try:
    import openai as _openai_module
except ImportError:
    _openai_module = None  # type: ignore[assignment]

try:
    from google import genai as _genai_module
except ImportError:
    _genai_module = None  # type: ignore[assignment]

try:
    import ollama as _ollama_module
except ImportError:
    _ollama_module = None  # type: ignore[assignment]

VALID_RISK_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

CLAUDE_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
# Static instructions live here so prompt caching can absorb them on repeat scans.
# Cached tokens cost 10% of normal input price (Anthropic 5-min TTL).
SYSTEM_PROMPT = (
    "You are a senior security engineer ranking Python vulnerabilities "
    "by real exploitability. "
    "You will receive CVE IDs with package names and versions inside "
    "<cves> tags, and the project's installed dependency list inside "
    "<stack> tags. "
    "Rank each CVE by actual reachability in this specific project — "
    "not raw CVSS score. "
    "Rules:\n"
    "- A transitive dep with no exposed API surface is LOW even if "
    "CVSS is 9.8.\n"
    "- A direct dep called at every request boundary is HIGH even if "
    "CVSS is 5.0.\n"
    "- Only return IDs that appear in <cves>. Never invent new IDs.\n"
    "- fix_command must be a valid pip install command, nothing else.\n"
    "- reasoning must be one sentence (<=20 words).\n"
    "Return ONLY a valid JSON array. No markdown fences, no prose."
)


class AnthropicProvider:
    name = f"anthropic ({CLAUDE_MODEL})"

    def __init__(self) -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise AuthError(
                "ANTHROPIC_API_KEY is not set. Get a key from https://console.anthropic.com"
            )
        self._client = anthropic.Anthropic(api_key=api_key, timeout=60.0, max_retries=3)

    def complete(self, system: str, user: str) -> str:
        try:
            message = self._client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=MAX_TOKENS,
                system=[
                    {
                        "type": "text",
                        "text": system,
                        # Cache the static system instructions across repeat scans.
                        # Cached tokens cost 10% of normal input price (5-min TTL).
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.AuthenticationError as exc:
            raise AuthError("Invalid or expired Anthropic API key.") from exc
        if not message.content or not hasattr(message.content[0], "text"):
            raise ParseError("Claude returned an empty or non-text response.")
        return message.content[0].text


OPENAI_MODEL = "gpt-4o-mini"


class OpenAIProvider:
    name = f"openai ({OPENAI_MODEL})"

    def __init__(self) -> None:
        if _openai_module is None:
            raise ImportError(
                "openai package is not installed. Run: pip install 'vulntriage[openai]'"
            )
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise AuthError(
                "OPENAI_API_KEY is not set. Get a key from https://platform.openai.com/api-keys"
            )
        self._client = _openai_module.OpenAI(
            api_key=api_key, timeout=60.0, max_retries=3
        )

    def complete(self, system: str, user: str) -> str:
        try:
            response = self._client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
        except _openai_module.AuthenticationError as exc:
            raise AuthError("Invalid or expired OpenAI API key.") from exc
        if not response.choices or response.choices[0].message.content is None:
            raise ParseError("OpenAI returned an empty response.")
        return response.choices[0].message.content


GEMINI_MODEL = "gemini-2.0-flash"


class GeminiProvider:
    name = f"gemini ({GEMINI_MODEL})"

    def __init__(self) -> None:
        if _genai_module is None:
            raise ImportError(
                "google-genai package is not installed. "
                "Run: pip install 'vulntriage[gemini]'"
            )
        api_key = os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise AuthError(
                "GOOGLE_API_KEY is not set. Get a free key from https://aistudio.google.com/apikey"
            )
        self._client = _genai_module.Client(api_key=api_key)

    def complete(self, system: str, user: str) -> str:
        try:
            response = self._client.models.generate_content(
                model=GEMINI_MODEL,
                contents=user,
                config=_genai_module.types.GenerateContentConfig(
                    system_instruction=system,
                ),
            )
        except Exception as exc:
            if hasattr(exc, "status_code") and exc.status_code in (401, 403):
                raise AuthError("Invalid or expired Google API key.") from exc
            raise
        if not response.text:
            raise ParseError("Gemini returned an empty response.")
        return response.text


OLLAMA_MODEL_DEFAULT = "llama3.2"
OLLAMA_HOST_DEFAULT = "http://localhost:11434"


class OllamaProvider:
    def __init__(self) -> None:
        if _ollama_module is None:
            raise ImportError(
                "ollama package is not installed. Run: pip install 'vulntriage[ollama]'"
            )
        host = os.environ.get("OLLAMA_HOST", OLLAMA_HOST_DEFAULT)
        self._model = os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)
        self.name = f"ollama ({self._model})"
        self._client = _ollama_module.Client(host=host)

    def complete(self, system: str, user: str) -> str:
        response = self._client.chat(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = response.message.content
        if not content:
            raise ParseError("Ollama returned an empty response.")
        return content


_PROVIDERS: dict[str, type] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: str | None = None) -> LLMProvider:
    provider_name = (name or os.environ.get("VULNTRIAGE_PROVIDER", "anthropic")).lower()
    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        valid = ", ".join(sorted(_PROVIDERS))
        raise ValueError(f"Unknown provider: {provider_name!r}. Valid options: {valid}")
    return cls()


def _cve_to_dict(cve: CVE) -> dict[str, Any]:
    # Omit description and aliases — Claude already knows CVE details from training.
    # Sending them back would add tokens and create a prompt-injection surface.
    return {
        "id": cve.id,
        "package": cve.package,
        "installed_version": cve.installed_version,
        "fix_versions": cve.fix_versions,
    }


def build_prompt(cves: list[CVE], stack_context: str) -> str:
    cve_list = json.dumps([_cve_to_dict(c) for c in cves], indent=2)
    return (
        "<stack>\n"
        f"{stack_context}\n"
        "</stack>\n\n"
        "<cves>\n"
        f"{cve_list}\n"
        "</cves>\n\n"
        "Return a JSON array. Each item must have exactly these keys:\n"
        '  "id": string — must match an id from <cves>\n'
        '  "real_risk": string — one of CRITICAL, HIGH, MEDIUM, LOW, INFO\n'
        '  "reasoning": string — one sentence (≤20 words)\n'
        '  "fix_command": string — pip install command\n\n'
        "Order by real_risk descending (CRITICAL first)."
    )


def parse_claude_response(response_text: str, cves: list[CVE]) -> list[RankedCVE]:
    cve_by_id = {c.id: c for c in cves}
    block_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
    json_str = block_match.group(1).strip() if block_match else response_text.strip()
    try:
        data: list[dict[str, Any]] = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Could not extract JSON from Claude response: {exc}") from exc
    ranked: list[RankedCVE] = []
    for i, item in enumerate(data, start=1):
        try:
            item_id = item["id"]
            real_risk = item["real_risk"]
            reasoning = item["reasoning"]
            fix_command = item["fix_command"]
        except KeyError as exc:
            raise ParseError(
                f"Claude response item missing required field: {exc}"
            ) from exc
        if real_risk not in VALID_RISK_LEVELS:
            raise ParseError(f"Claude returned unrecognised risk level: {real_risk!r}")
        cve = cve_by_id.get(item_id)
        if cve is None:
            continue
        ranked.append(
            RankedCVE(
                rank=i,
                cve=cve,
                real_risk=real_risk,
                reasoning=reasoning,
                fix_command=fix_command,
            )
        )
    if cves and not ranked:
        raise ParseError(
            "LLM response contained no recognised CVE IDs — "
            "all entries were dropped. The model may have hallucinated IDs."
        )
    return ranked


def rank_cves(
    cves: list[CVE],
    stack_context: str,
    provider: LLMProvider | None = None,
) -> list[RankedCVE]:
    if provider is None:
        provider = get_provider()
    response_text = provider.complete(SYSTEM_PROMPT, build_prompt(cves, stack_context))
    return parse_claude_response(response_text, cves)
