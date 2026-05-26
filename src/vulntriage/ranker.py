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
    "The <stack> section may also include a 'Project type:' line "
    "(web_service / cli / library) inferred from imports.\n"
    "Each CVE entry may include threat intelligence fields:\n"
    "  cvss_score — authoritative CVSS v3.1/v3.0 base score from NVD"
    " (empty if unavailable)\n"
    "  attack_vector — NVD CVSS attack vector: N=Network, A=Adjacent, "
    "L=Local, P=Physical (empty if unavailable)\n"
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
    "- attack_vector matters: an L (Local) or P (Physical) CVE in a library "
    "called by a web_service project is almost never reachable from a remote "
    "attacker; default to LOW. N (Network) CVEs in libraries on the request "
    "path of a web_service project are high-priority. For cli/library "
    "projects, weight reachability by what the CLI actually exposes.\n"
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
    "- code_changes: 1-2 sentences. The <stack> section lists exact call sites as "
    "'file:line  func(kwarg=, ...)'. Reference those specific locations when "
    "describing what changes between installed_version and min_fix_version — e.g. "
    "'src/api.py:42 requests.get() needs verify= kwarg added'. If none of the "
    "listed call sites are affected by the fix, say so explicitly. If no call sites "
    "are listed for this package, say "
    "'Package not directly imported — no source changes needed.'\n"
    "Return ONLY a valid JSON array. No markdown fences, no prose."
)

# Stripped-down prompt for local models (Ollama). Same semantics as SYSTEM_PROMPT
# but shorter and more explicit about JSON structure — local models follow concrete
# templates better than long rule lists.
OLLAMA_SYSTEM_PROMPT = (
    "You are a CVE ranking tool. Output ONLY a JSON array."
    " No prose. No markdown fences.\n"
    "Start your response with [ and end with ].\n\n"
    "Rules:\n"
    "- 'NOT FOUND IN SOURCE' means transitive dep"
    " → real_risk: LOW (unless kev=true)\n"
    "- 'IMPORTED' with call sites"
    " → judge reachability from the specific functions listed\n"
    "- verify=False in requests.get() is HIGH"
    " if CVE is about certificate validation\n"
    "- kev=true → weight toward HIGH or CRITICAL\n"
    "- Only return IDs that appear in <cves>. Never invent new IDs.\n\n"
    "Each array item must have exactly these 7 keys:\n"
    '{"id":"CVE-XXXX-YYYY","real_risk":"HIGH",'
    '"reasoning":"specific attack + reachability",'
    '"fix_command":"pip install pkg>=X.Y","cvss":"N/A",'
    '"breaking_changes":"...",'
    '"code_changes":"file:line func() or Package not directly imported"}\n\n'
    "real_risk must be exactly one of: CRITICAL HIGH MEDIUM LOW INFO"
)

OLLAMA_TIMEOUT = 120  # seconds per batch call


class AnthropicProvider:
    def __init__(self, model: str | None = None) -> None:
        self._model = model or CLAUDE_MODEL
        self.name = f"anthropic ({self._model})"
        api_key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        if not api_key:
            raise AuthError(
                "ANTHROPIC_API_KEY is not set. Get a key from https://console.anthropic.com"
            )
        self._client = anthropic.Anthropic(api_key=api_key, timeout=60.0, max_retries=3)

    def complete(self, system: str, user: str) -> str:
        try:
            message = self._client.messages.create(
                model=self._model,
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
    def __init__(self, model: str | None = None) -> None:
        self._model = model or OPENAI_MODEL
        self.name = f"openai ({self._model})"
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
                model=self._model,
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
    def __init__(self, model: str | None = None) -> None:
        self._model = model or GEMINI_MODEL
        self.name = f"gemini ({self._model})"
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
                model=self._model,
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
    def __init__(self, model: str | None = None) -> None:
        if _ollama_module is None:
            raise ImportError(
                "ollama package is not installed. Run: pip install 'vulntriage[ollama]'"
            )
        host = os.environ.get("OLLAMA_HOST", OLLAMA_HOST_DEFAULT)
        self._model = model or os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL_DEFAULT)
        self.name = f"ollama ({self._model})"
        self._client = _ollama_module.Client(host=host, timeout=OLLAMA_TIMEOUT)
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
                # Use the local-model-optimised prompt regardless of what the caller
                # passes — the full SYSTEM_PROMPT is too long for most local models.
                {"role": "system", "content": OLLAMA_SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            options={"temperature": 0, "num_predict": 2048},
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


def get_provider(name: str | None = None, model: str | None = None) -> LLMProvider:
    provider_name = (
        (name or os.environ.get("VULNTRIAGE_PROVIDER", "anthropic")).strip().lower()
    )
    cls = _PROVIDERS.get(provider_name)
    if cls is None:
        valid = ", ".join(sorted(_PROVIDERS))
        raise ValueError(f"Unknown provider: {provider_name!r}. Valid options: {valid}")
    return cls(model=model)


def _cve_to_dict(
    cve: CVE,
    nvd_data: dict[str, dict[str, str]] | None = None,
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
    if nvd_data is not None:
        nvd_entry = nvd_data.get(cve.id, {})
        entry["cvss_score"] = nvd_entry.get("score", "")
        entry["attack_vector"] = nvd_entry.get("vector", "")
    if kev_set is not None:
        entry["kev"] = cve.id in kev_set
    if epss_scores is not None:
        entry["epss_pct"] = epss_scores.get(cve.id, "")
    return entry


def build_prompt(
    cves: list[CVE],
    stack_context: str,
    nvd_data: dict[str, dict[str, str]] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> str:
    cve_list = json.dumps(
        [_cve_to_dict(c, nvd_data, kev_set, epss_scores) for c in cves], indent=2
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
    nvd_data: dict[str, dict[str, str]] | None = None,
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
    except json.JSONDecodeError:
        # Fallback 1: quote unquoted object keys at line-start (phi4-mini bare keys).
        fixed = re.sub(
            r"^(\s*)([A-Za-z_]\w*)(\s*:)", r'\1"\2"\3', json_str, flags=re.MULTILINE
        )
        try:
            data = json.loads(fixed)
        except json.JSONDecodeError:
            # Fallback 2: truncated array repair — local models sometimes cut off
            # mid-object when they hit num_predict. Close the last open object and
            # the array so we salvage whichever entries completed successfully.
            truncated = fixed.rstrip().rstrip(",")
            if not truncated.endswith("]"):
                if not truncated.endswith("}"):
                    truncated += "}"
                truncated += "]"
                truncated = re.sub(r",\s*([}\]])", r"\1", truncated)
            try:
                data = json.loads(truncated)
            except json.JSONDecodeError as exc:
                raise ParseError(
                    f"Could not extract JSON from LLM response: {exc}"
                ) from exc
    seen_ids: set[str] = set()
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
        if item_id in seen_ids:
            continue
        seen_ids.add(item_id)
        reasoning = item.get("reasoning") or ""
        fix_command = item.get("fix_command") or item.get("fix") or ""
        if fix_command and not _FIX_CMD_RE.match(fix_command):
            fix_command = ""
        cve = cve_by_id.get(item_id)
        if cve is None:
            continue
        # NVD score is authoritative; override LLM-returned CVSS when available.
        nvd_score = (nvd_data or {}).get(item_id, {}).get("score")
        cvss = str(nvd_score) if nvd_score is not None else (item.get("cvss") or "")
        ranked.append(
            RankedCVE(
                rank=i,
                cve=cve,
                real_risk=real_risk,
                reasoning=reasoning,
                fix_command=fix_command,
                cvss=cvss,
                breaking_changes=item.get("breaking_changes") or "",
                kev=item_id in (kev_set or set()),
                epss=(epss_scores or {}).get(item_id, ""),
                code_changes=item.get("code_changes") or "",
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
    nvd_data: dict[str, dict[str, str]] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
) -> list[RankedCVE]:
    if provider is None:
        provider = get_provider()
    prompt = build_prompt(cves, stack_context, nvd_data, kev_set, epss_scores)
    response_text = provider.complete(SYSTEM_PROMPT, prompt)
    return parse_claude_response(response_text, cves, nvd_data, kev_set, epss_scores)


_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def rank_cves_batched(
    cves: list[CVE],
    stack_context: str,
    provider: LLMProvider | None = None,
    batch_size: int = 10,
    nvd_data: dict[str, dict[str, str]] | None = None,
    kev_set: set[str] | None = None,
    epss_scores: dict[str, str] | None = None,
    progress_callback: Any | None = None,
) -> list[RankedCVE]:
    """Rank CVEs in batches and merge results sorted by severity.

    Splits `cves` into chunks of `batch_size`, ranks each independently,
    then merges and re-ranks the full result set by severity descending.
    Use this for local models (Ollama) that have limited context windows.
    """
    if provider is None:
        provider = get_provider()
    if batch_size <= 0 or len(cves) <= batch_size:
        return rank_cves(cves, stack_context, provider, nvd_data, kev_set, epss_scores)

    chunks = [cves[i : i + batch_size] for i in range(0, len(cves), batch_size)]
    total = len(chunks)
    merged: list[RankedCVE] = []
    for i, chunk in enumerate(chunks, start=1):
        if progress_callback is not None:
            progress_callback(i, total, len(chunk))
        batch_ranked = rank_cves(
            chunk, stack_context, provider, nvd_data, kev_set, epss_scores
        )
        merged.extend(batch_ranked)

    # Stable sort: CRITICAL first; within the same tier, preserve batch order.
    merged.sort(key=lambda r: _SEVERITY_ORDER.get(r.real_risk, 0), reverse=True)

    # Re-number ranks 1..N on the merged list.
    return [
        RankedCVE(
            rank=idx,
            cve=r.cve,
            real_risk=r.real_risk,
            reasoning=r.reasoning,
            fix_command=r.fix_command,
            cvss=r.cvss,
            breaking_changes=r.breaking_changes,
            code_changes=r.code_changes,
            kev=r.kev,
            epss=r.epss,
        )
        for idx, r in enumerate(merged, start=1)
    ]
