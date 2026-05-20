import json
import sys
from datetime import UTC, datetime
from urllib.error import URLError
from urllib.request import urlopen

from vulntriage.cache import read_cache, write_cache

_PYPI_BASE = "https://pypi.org/pypi"
_INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"
_UNMAINTAINED_YEARS = 2


def _years_since(date_str: str) -> float:
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        delta = datetime.now(tz=UTC) - dt
        return delta.days / 365.25
    except (ValueError, TypeError):
        return 0.0


def _fetch_one(package: str, timeout: int) -> dict | None:
    cache_key = f"pypi_{package}"
    cached = read_cache(cache_key)
    if cached is not None:
        return cached

    url = f"{_PYPI_BASE}/{package}/json"
    try:
        with urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None

    info = data.get("info", {})
    classifiers: list[str] = info.get("classifiers", [])
    releases: dict = data.get("releases", {})

    last_release_date = ""
    if releases:
        all_dates: list[str] = []
        for version_files in releases.values():
            for f in version_files:
                upload_time = f.get("upload_time", "")
                if upload_time:
                    all_dates.append(upload_time)
        if all_dates:
            last_release_date = max(all_dates)

    result = {
        "deprecated": _INACTIVE_CLASSIFIER in classifiers,
        "unmaintained": (
            bool(last_release_date)
            and _years_since(last_release_date) > _UNMAINTAINED_YEARS
        ),
        "last_release": last_release_date[:10] if last_release_date else "",
        "years_since": (
            round(_years_since(last_release_date), 1) if last_release_date else 0.0
        ),
    }
    write_cache(cache_key, result)
    return result


def fetch_deprecation_info(
    packages: list[str],
    offline: bool = False,
    timeout: int = 10,
) -> dict[str, dict]:
    """Return deprecation/maintenance info for each package.

    Keys: deprecated, unmaintained, last_release, years_since.
    Missing packages (fetch error) are omitted from the result.
    """
    if offline:
        return {}

    results: dict[str, dict] = {}
    for pkg in packages:
        info = _fetch_one(pkg, timeout)
        if info is None:
            print(
                f"Warning: could not fetch PyPI metadata for {pkg!r} — skipping",
                file=sys.stderr,
            )
            continue
        results[pkg] = info
    return results
