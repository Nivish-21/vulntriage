import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.epss import fetch_epss


def _mock_response(payload: dict) -> MagicMock:
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(payload).encode()
    return mock


EPSS_PAYLOAD = {
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97534"},
        {"cve": "CVE-2022-30190", "epss": "0.00231"},
    ]
}


def test_fetch_epss_returns_percentages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen", return_value=_mock_response(EPSS_PAYLOAD)):
        result = fetch_epss(["CVE-2021-44228", "CVE-2022-30190"])
    assert result["CVE-2021-44228"] == "97.5%"
    assert result["CVE-2022-30190"] == "0.2%"


def test_fetch_epss_partial_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partial = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97534"}]}
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen", return_value=_mock_response(partial)):
        result = fetch_epss(["CVE-2021-44228", "CVE-9999-0001"])
    assert result["CVE-2021-44228"] == "97.5%"
    assert result["CVE-9999-0001"] == ""


def test_fetch_epss_timeout_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen", side_effect=TimeoutError()):
        result = fetch_epss(["CVE-2024-1111"])
    assert result == {"CVE-2024-1111": ""}


def test_fetch_epss_url_error_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.error import URLError

    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen", side_effect=URLError("down")):
        result = fetch_epss(["CVE-2024-2222"])
    assert result == {"CVE-2024-2222": ""}


def test_fetch_epss_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen") as mock_open:
        result = fetch_epss(["CVE-2024-3333"], offline=True)
    mock_open.assert_not_called()
    assert result == {"CVE-2024-3333": ""}


def test_fetch_epss_uses_cache_per_cve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch(
        "vulntriage.epss.urlopen", return_value=_mock_response(EPSS_PAYLOAD)
    ) as mock_open:
        fetch_epss(["CVE-2021-44228", "CVE-2022-30190"])
        result = fetch_epss(["CVE-2021-44228", "CVE-2022-30190"])
    # second call should be entirely from cache — no additional HTTP
    assert mock_open.call_count == 1
    assert result["CVE-2021-44228"] == "97.5%"


def test_fetch_epss_empty_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.epss.urlopen") as mock_open:
        result = fetch_epss([])
    mock_open.assert_not_called()
    assert result == {}
