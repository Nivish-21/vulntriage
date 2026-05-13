import json
import re
from typing import Any

import anthropic

from vulntriage.exceptions import AuthError, ParseError
from vulntriage.models import CVE, RankedCVE

VALID_RISK_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

CLAUDE_MODEL = "claude-sonnet-4-6"
MAX_TOKENS = 1024
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
    return ranked


def rank_cves(cves: list[CVE], stack_context: str, api_key: str) -> list[RankedCVE]:
    client = anthropic.Anthropic(api_key=api_key, timeout=60.0, max_retries=3)
    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    # Cache the static system instructions across repeat scans.
                    # Cached tokens cost 10% of normal input price (5-min TTL).
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": build_prompt(cves, stack_context)}],
        )
    except anthropic.AuthenticationError as exc:
        raise AuthError("Invalid or expired Anthropic API key.") from exc
    if not message.content or not hasattr(message.content[0], "text"):
        raise ParseError("Claude returned an empty or non-text response.")
    return parse_claude_response(message.content[0].text, cves)
