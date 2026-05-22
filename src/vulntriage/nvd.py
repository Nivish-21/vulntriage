import json
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from vulntriage.cache import read_cache, write_cache

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NO_KEY_DELAY = 6.1  # 5 req/30s → sleep between requests
_KEY_DELAY = 0.7  # 50 req/30s

# NVD returns long form ("NETWORK"); we ship a single char to the LLM to save tokens.
_VECTOR_MAP: dict[str, str] = {
    "NETWORK": "N",
    "ADJACENT_NETWORK": "A",
    "LOCAL": "L",
    "PHYSICAL": "P",
}

_EMPTY: dict[str, str] = {"score": "", "vector": ""}


def _extract_cvss(data: dict) -> dict[str, str]:
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return dict(_EMPTY)
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    score = ""
    vector = ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            raw_score = cvss_data.get("baseScore")
            if raw_score is not None:
                score = str(raw_score)
            raw_vector = cvss_data.get("attackVector", "")
            vector = _VECTOR_MAP.get(raw_vector, "")
            break
    return {"score": score, "vector": vector}


def _fetch_one(
    cve_id: str,
    api_key: str | None,
    timeout: int,
) -> dict[str, str]:
    cache_key = f"nvd_{cve_id}"
    cached = read_cache(cache_key)
    if cached is not None:
        # Backwards-compat: pre-v0.9.0 cache entries only have "score".
        return {
            "score": cached.get("score", ""),
            "vector": cached.get("vector", ""),
        }

    url = f"{_NVD_BASE}?cveId={cve_id}"
    req = Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    result = dict(_EMPTY)
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        result = _extract_cvss(data)
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass

    write_cache(cache_key, result)
    return result


def fetch_cvss_data(
    cve_ids: list[str],
    api_key: str | None = None,
    timeout: int = 10,
    offline: bool = False,
) -> dict[str, dict[str, str]]:
    """Return {cve_id: {"score": str, "vector": "N"|"A"|"L"|"P"|""}} per CVE."""
    if offline:
        return {cve_id: dict(_EMPTY) for cve_id in cve_ids}

    delay = _KEY_DELAY if api_key else _NO_KEY_DELAY
    results: dict[str, dict[str, str]] = {}
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(delay)
        results[cve_id] = _fetch_one(cve_id, api_key, timeout)
    return results
