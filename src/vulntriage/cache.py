import json
import time
from pathlib import Path
from typing import Any

CACHE_DIR = Path.home() / ".cache" / "vulntriage"
TTL_SECONDS = 86_400  # 24 hours


def read_cache(key: str) -> dict[str, Any] | None:
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > TTL_SECONDS:
        return None
    return json.loads(path.read_text())  # type: ignore[no-any-return]


def write_cache(key: str, data: dict[str, Any]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{key}.json").write_text(json.dumps(data))


SCAN_CACHE_TTL = 3_600  # 1 hour


def scan_cache_get(key: str) -> list[dict[str, Any]] | None:
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    if time.time() - path.stat().st_mtime > SCAN_CACHE_TTL:
        return None
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else None


def scan_cache_set(key: str, results: list[dict[str, Any]]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{key}.json").write_text(json.dumps(results))
