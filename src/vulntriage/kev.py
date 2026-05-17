import json
from urllib.error import URLError
from urllib.request import urlopen

from vulntriage.cache import read_cache, write_cache

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_KEY = "kev"


def fetch_kev(timeout: int = 10, offline: bool = False) -> set[str]:
    if offline:
        return set()

    cached = read_cache(_CACHE_KEY)
    if cached is not None:
        return set(cached.get("ids", []))

    try:
        with urlopen(_KEV_URL, timeout=timeout) as resp:
            data = json.loads(resp.read())
        ids = [v["cveID"] for v in data.get("vulnerabilities", []) if "cveID" in v]
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, KeyError):
        return set()

    write_cache(_CACHE_KEY, {"ids": ids})
    return set(ids)
