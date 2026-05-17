import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.kev import fetch_kev


def _mock_response(payload: dict) -> MagicMock:
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(payload).encode()
    return mock


KEV_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228"},
        {"cveID": "CVE-2022-30190"},
    ]
}


def test_fetch_kev_returns_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.kev.urlopen", return_value=_mock_response(KEV_PAYLOAD)):
        result = fetch_kev()
    assert isinstance(result, set)
    assert "CVE-2021-44228" in result
    assert "CVE-2022-30190" in result


def test_fetch_kev_uses_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch(
        "vulntriage.kev.urlopen", return_value=_mock_response(KEV_PAYLOAD)
    ) as mock_open:
        fetch_kev()
        fetch_kev()
    assert mock_open.call_count == 1


def test_fetch_kev_timeout_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.kev.urlopen", side_effect=TimeoutError()):
        result = fetch_kev()
    assert result == set()


def test_fetch_kev_url_error_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.error import URLError

    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.kev.urlopen", side_effect=URLError("network unreachable")):
        result = fetch_kev()
    assert result == set()


def test_fetch_kev_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.kev.urlopen") as mock_open:
        result = fetch_kev(offline=True)
    mock_open.assert_not_called()
    assert result == set()


def test_fetch_kev_empty_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch(
        "vulntriage.kev.urlopen", return_value=_mock_response({"vulnerabilities": []})
    ):
        result = fetch_kev()
    assert result == set()
