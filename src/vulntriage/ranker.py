import html
import json
import os
import re
import subprocess
import sys
import time
from typing import Any

import anthropic

from vulntriage.exceptions import AuditError, AuthError, ParseError
from vulntriage.models import CVE, LLMProvider, RankedCVE, min_fix_version

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

# Allowlist: pip install + space-separated package specs. Rejects shell operators.
_FIX_CMD_RE = re.compile(r"^pip install\s+[a-zA-Z0-9._\->=<!\[\],\s]+$")

CLAUDE_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 4096
# Static instructions live here so prompt caching can absorb them on repeat scans.
# Cached tokens cost 10% of normal input price (Anthropic 5-min TTL).
SYSTEM_PROMPT = (
    "You are a senior security engineer ranking Python vulnerabilities "
    "by real exploitability in a specific project. "
    "You will receive CVE IDs with package names, versions, and descriptions inside "
    "<cves> tags, and the project's dependency list inside <stack> tags. "
    "The <stack> section also includes import-presence lines showing which packages "
    "are actually imported in the source code and which specific symbols are used.\n"
    "Each CVE entry may include threat intelligence fields:\n"
    "  cvss_score — authoritative CVSS v3.1/v3.0 base score from NVD"
    " (empty if unavailable)\n"
    "  kev — true if CISA has confirmed this CVE is actively exploited in the wild\n"
    "  epss_pct — EPSS exploitation probability percentage (e.g. '97.5%')\n"
    "  min_fix_version — the minimum package version that fixes this CVE\n"
    "Rank each CVE by actual reachability — not raw CVSS score.\n"
    "Rules:\n"
    "- A package marked 'NOT FOUND IN SOURCE' is a transitive dep — rank LOW or INFO "
    "unless CVSS is critical and kev=true.\n"
    "- A package marked 'IMPORTED' with specific symbols is a direct dep — use the "
    "listed symbols to judge which attack vectors are reachable.\n"
    "- A direct dep called at every request boundary is HIGH even if CVSS is 5.0.\n"
    "- kev=true is strong evidence of real-world exploitation — weight it heavily.\n"
    "- High epss_pct (>50%) indicates the community expects exploitation soon.\n"
    "- pip, setuptools, and other install/build tools are NOT reachable at "
    "application runtime unless the app explicitly invokes pip at runtime. "
    "Mark them LOW or INFO.\n"
    "- Only return IDs that appear in <cves>. Never invent new IDs.\n"
    "- fix_command must be a valid pip install command, nothing else.\n"
    "- reasoning: 1-2 sentences. Name the specific attack type (e.g. RCE via "
    "unsafe deserialization, path traversal in file-upload handler, SSRF via "
    "URL fetch). Then state reachability: name the specific API surface or "
    "code path in this stack that would trigger it. Never write generic "
    "statements like 'X is used for Y' without naming the attack vector.\n"
    "- cvss: The published CVSS v3.1 base score as a decimal string "
    "(e.g. '9.8'). Use 'N/A' if no score is publicly available.\n"
    "- breaking_changes: 1 sentence. Describe any API changes, removed "
    "features, or behaviour differences a developer must verify after "
    "upgrading to the fix version. "
    "If the upgrade is safe and backwards-compatible, say so explicitly.\n"
    "- code_changes: 1-2 sentences. Given the imported symbols listed in <stack>, "
    "name specifically which call sites, function signatures, or import paths change "
    "between installed_version and min_fix_version. If none of the used symbols are "
    "affected, say so explicitly. If the package is not imported in source, say "
    "'Package not directly imported — no source changes needed.'\n"
    "Return ONLY a valid JSON array. No markdown fences, no prose."
)


class AnthropicProvider:
    name = f"anthropic ({CLAUDE_MODEL})"

    def __init__(self) -> None:
        api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
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
        api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
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
        api_key = (os.environ.get("GOOGLE_API_KEY") or "").strip()
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
OLLAMA_START_TIMEOUT = 15


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
        self._server_proc: subprocess.Popen[bytes] | None = None
        if not self._is_server_reachable():
            self._start_ollama_server()
        self._was_loaded = self._is_model_loaded()

    def _is_server_reachable(self) -> bool:
        try:
            self._client.ps()
            return True
        except Exception:
            return False

    def _start_ollama_server(self) -> None:
        print("Starting Ollama server...", file=sys.stderr)
        try:
            self._server_proc = subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            raise AuditError(
                "ollama is not installed or not on PATH. "
                "Install from https://ollama.com/download"
            ) from None
        deadline = time.time() + OLLAMA_START_TIMEOUT
        while time.time() < deadline:
            time.sleep(0.5)
            if self._is_server_reachable():
                return
        self._server_proc.terminate()
        raise AuditError(
            f"Ollama server did not become ready within {OLLAMA_START_TIMEOUT}s. "
            "Is ollama installed correctly?"
        )

    def _is_model_loaded(self) -> bool:
        try:
            running = self._client.ps()
            return any(m.model == self._model for m in running.models)
        except Exception:
            return False

    def _unload_model(self) -> None:
        try:
            self._client.generate(model=self._model, prompt="", keep_alive=0)
        except Exception:
            pass

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
        if not self._was_loaded:
            self._unload_model()
        return content


_PROVIDERS: dict[str, type] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
}


def get_provider(name: str | None = None) -> LLMProvider:
    provider_name = (
        (name or os.environ.get("VULNTRIAGE_PROVIDER", "anthropic")).strip().lower()
    )
    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        valid = ", ".join(sorted(_PROVIDERS))
        raise ValueError(f"Unknown provider: {provider_name!r}. Valid options: {valid}")
    return cls()


def _cve_to_dict(
    cve: CVE,
    nvd_scores: dict[str, str] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> dict[str, Any]:
    # Omit description and aliases — Claude already knows CVE details from training.
    # Sending them back would add tokens and create a prompt-injection surface.
    entry: dict[str, Any] = {
        "id": cve.id,
        "package": cve.package,
        "installed_version": cve.installed_version,
        "fix_versions": cve.fix_versions,
        "min_fix_version": min_fix_version(cve.fix_versions) or "",
    }
    if nvd_scores is not None:
        entry["cvss_score"] = nvd_scores.get(cve.id, "")
    if kev_set is not None:
        entry["kev"] = cve.id in kev_set
    if epss_scores is not None:
        entry["epss_pct"] = epss_scores.get(cve.id, "")
    return entry


def build_prompt(
    cves: list[CVE],
    stack_context: str,
    nvd_scores: dict[str, str] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> str:
    cve_list = json.dumps(
        [_cve_to_dict(c, nvd_scores, kev_set, epss_scores) for c in cves], indent=2
    )
    escaped_stack = html.escape(stack_context)
    return (
        "<stack>\n"
        f"{escaped_stack}\n"
        "</stack>\n\n"
        "<cves>\n"
        f"{cve_list}\n"
        "</cves>\n\n"
        "Return a JSON array. Each item must have exactly these keys:\n"
        '  "id": string — must match an id from <cves>\n'
        '  "real_risk": string — one of CRITICAL, HIGH, MEDIUM, LOW, INFO\n'
        '  "reasoning": string — specific attack type + reachability in this '
        "stack (1-2 sentences)\n"
        '  "fix_command": string — pip install command\n'
        '  "cvss": string — CVSS v3.1 base score (e.g. "9.8") or "N/A"\n'
        '  "breaking_changes": string — what to verify after upgrading (1 sentence)\n'
        '  "code_changes": string — which call sites/symbols change (1-2 sentences)\n\n'
        "Order by real_risk descending (CRITICAL first)."
    )


def parse_claude_response(
    response_text: str,
    cves: list[CVE],
    nvd_scores: dict[str, str] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> list[RankedCVE]:
    cve_by_id = {c.id: c for c in cves}
    block_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
    json_str = block_match.group(1).strip() if block_match else response_text.strip()
    # Extract outermost [...] — strips prose before/after JSON (Gemma, gpt-4o-mini).
    array_match = re.search(r"\[[\s\S]*\]", json_str)
    if array_match:
        json_str = array_match.group(0)
    # Strip trailing commas before closing braces/brackets (Gemma, llama).
    json_str = re.sub(r",\s*([}\]])", r"\1", json_str)
    try:
        data: list[dict[str, Any]] = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Could not extract JSON from Claude response: {exc}") from exc
    ranked: list[RankedCVE] = []
    for i, item in enumerate(data, start=1):
        # Use .get() for all fields — weaker models (Gemma, llama) occasionally
        # drop or rename fields on large batches. Skip the item rather than
        # aborting the whole parse; the final empty-check below catches total failure.
        item_id = item.get("id")
        real_risk = item.get("real_risk")
        if not item_id or not real_risk:
            continue
        if real_risk not in VALID_RISK_LEVELS:
            continue
        reasoning = item.get("reasoning", "")
        fix_command = item.get("fix_command") or item.get("fix", "")
        if fix_command and not _FIX_CMD_RE.match(fix_command):
            fix_command = ""
        cve = cve_by_id.get(item_id)
        if cve is None:
            continue
        # NVD score is authoritative; override LLM-returned CVSS when available.
        cvss = (nvd_scores or {}).get(item_id) or item.get("cvss", "")
        ranked.append(
            RankedCVE(
                rank=i,
                cve=cve,
                real_risk=real_risk,
                reasoning=reasoning,
                fix_command=fix_command,
                cvss=cvss,
                breaking_changes=item.get("breaking_changes", ""),
                kev=item_id in (kev_set or set()),
                epss=(epss_scores or {}).get(item_id, ""),
                code_changes=item.get("code_changes", ""),
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
    nvd_scores: dict[str, str] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> list[RankedCVE]:
    if provider is None:
        provider = get_provider()
    prompt = build_prompt(cves, stack_context, nvd_scores, kev_set, epss_scores)
    response_text = provider.complete(SYSTEM_PROMPT, prompt)
    return parse_claude_response(response_text, cves, nvd_scores, kev_set, epss_scores)
