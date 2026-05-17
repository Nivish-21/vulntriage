import json
from urllib.error import URLError
from urllib.request import urlopen

from vulntriage.cache import read_cache, write_cache

_EPSS_BASE = "https://api.first.org/data/v1/epss"


def _to_percent(raw: str) -> str:
    try:
        return f"{round(float(raw) * 100, 1)}%"
    except (ValueError, TypeError):
        return ""


def fetch_epss(
    cve_ids: list[str],
    timeout: int = 10,
    offline: bool = False,
) -> dict[str, str]:
    if not cve_ids:
        return {}

    if offline:
        return {cve_id: "" for cve_id in cve_ids}

    results: dict[str, str] = {}
    uncached: list[str] = []

    for cve_id in cve_ids:
        cached = read_cache(f"epss_{cve_id}")
        if cached is not None:
            results[cve_id] = cached.get("epss", "")
        else:
            uncached.append(cve_id)

    if uncached:
        fetched = _batch_fetch(uncached, timeout)
        for cve_id in uncached:
            score = fetched.get(cve_id, "")
            results[cve_id] = score
            write_cache(f"epss_{cve_id}", {"epss": score})

    return results


def _batch_fetch(cve_ids: list[str], timeout: int) -> dict[str, str]:
    url = f"{_EPSS_BASE}?cve={','.join(cve_ids)}"
    try:
        with urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
        return {
            item["cve"]: _to_percent(item.get("epss", ""))
            for item in data.get("data", [])
            if "cve" in item
        }
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, KeyError):
        return {}
