import json
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from vulntriage.cache import read_cache, write_cache

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NO_KEY_DELAY = 6.1  # 5 req/30s → sleep between requests
_KEY_DELAY = 0.7  # 50 req/30s


def _extract_cvss(data: dict) -> str:
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return ""
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return str(score)
    return ""


def _fetch_one(
    cve_id: str,
    api_key: str | None,
    timeout: int,
) -> str:
    cache_key = f"nvd_{cve_id}"
    cached = read_cache(cache_key)
    if cached is not None:
        return cached.get("score", "")

    url = f"{_NVD_BASE}?cveId={cve_id}"
    req = Request(url)
    if api_key:
        req.add_header("apiKey", api_key)

    score = ""
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        score = _extract_cvss(data)
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass

    write_cache(cache_key, {"score": score})
    return score


def fetch_cvss_scores(
    cve_ids: list[str],
    api_key: str | None = None,
    timeout: int = 10,
    offline: bool = False,
) -> dict[str, str]:
    if offline:
        return {cve_id: "" for cve_id in cve_ids}

    delay = _KEY_DELAY if api_key else _NO_KEY_DELAY
    results: dict[str, str] = {}
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(delay)
        results[cve_id] = _fetch_one(cve_id, api_key, timeout)
    return results
