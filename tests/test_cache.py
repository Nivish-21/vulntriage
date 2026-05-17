import time
from pathlib import Path

import pytest

from vulntriage.cache import TTL_SECONDS, read_cache, write_cache


@pytest.fixture()
def tmp_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    return tmp_path


def test_read_cache_miss_no_file(tmp_cache: Path) -> None:
    assert read_cache("nvd_CVE-2024-1234") is None


def test_write_then_read_hit(tmp_cache: Path) -> None:
    data = {"score": "7.5", "version": "v3.1"}
    write_cache("nvd_CVE-2024-1234", data)
    result = read_cache("nvd_CVE-2024-1234")
    assert result == data


def test_read_cache_expired(tmp_cache: Path) -> None:
    data = {"score": "5.0"}
    write_cache("nvd_CVE-2024-9999", data)
    path = tmp_cache / "nvd_CVE-2024-9999.json"
    stale_mtime = time.time() - TTL_SECONDS - 1
    import os

    os.utime(path, (stale_mtime, stale_mtime))
    assert read_cache("nvd_CVE-2024-9999") is None


def test_write_creates_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nested = tmp_path / "a" / "b" / "vulntriage"
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", nested)
    write_cache("kev", {"ids": []})
    assert (nested / "kev.json").exists()


def test_read_returns_correct_type(tmp_cache: Path) -> None:
    write_cache("epss_CVE-2024-5555", {"epss": "12.3"})
    result = read_cache("epss_CVE-2024-5555")
    assert isinstance(result, dict)
    assert result["epss"] == "12.3"
