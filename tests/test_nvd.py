import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.nvd import fetch_cvss_scores


def _mock_response(payload: dict) -> MagicMock:
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(payload).encode()
    return mock


NVD_V31 = {
    "vulnerabilities": [
        {"cve": {"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}
    ]
}

NVD_V30_ONLY = {
    "vulnerabilities": [
        {"cve": {"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}]}}}
    ]
}

NVD_V2_ONLY = {
    "vulnerabilities": [
        {"cve": {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}}}
    ]
}

NVD_NO_METRICS = {"vulnerabilities": [{"cve": {"metrics": {}}}]}

NVD_EMPTY = {"vulnerabilities": []}


def test_fetch_cvss_v31_score(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)):
        result = fetch_cvss_scores(["CVE-2024-1234"])
    assert result == {"CVE-2024-1234": "9.8"}


def test_fetch_cvss_v30_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V30_ONLY)):
        result = fetch_cvss_scores(["CVE-2024-2222"])
    assert result == {"CVE-2024-2222": "7.5"}


def test_fetch_cvss_v2_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V2_ONLY)):
        result = fetch_cvss_scores(["CVE-2024-3333"])
    assert result == {"CVE-2024-3333": "5.0"}


def test_fetch_cvss_no_metrics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_NO_METRICS)):
        result = fetch_cvss_scores(["CVE-2024-4444"])
    assert result == {"CVE-2024-4444": ""}


def test_fetch_cvss_empty_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_EMPTY)):
        result = fetch_cvss_scores(["CVE-2024-5555"])
    assert result == {"CVE-2024-5555": ""}


def test_fetch_cvss_timeout_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", side_effect=TimeoutError()):
        result = fetch_cvss_scores(["CVE-2024-6666"])
    assert result == {"CVE-2024-6666": ""}


def test_fetch_cvss_http_error_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.error import URLError

    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", side_effect=URLError("429")):
        result = fetch_cvss_scores(["CVE-2024-7777"])
    assert result == {"CVE-2024-7777": ""}


def test_fetch_cvss_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen") as mock_open:
        result = fetch_cvss_scores(["CVE-2024-8888"], offline=True)
    mock_open.assert_not_called()
    assert result == {"CVE-2024-8888": ""}


def test_fetch_cvss_uses_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch(
        "vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)
    ) as mock_open:
        fetch_cvss_scores(["CVE-2024-9999"])
        fetch_cvss_scores(["CVE-2024-9999"])
    assert mock_open.call_count == 1


def test_fetch_multiple_cves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with (
        patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)),
        patch("vulntriage.nvd.time.sleep"),
    ):
        result = fetch_cvss_scores(["CVE-2024-0001", "CVE-2024-0002"])
    assert "CVE-2024-0001" in result
    assert "CVE-2024-0002" in result
