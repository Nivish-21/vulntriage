import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vulntriage.nvd import fetch_cvss_data


def _mock_response(payload: dict) -> MagicMock:
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(payload).encode()
    return mock


def _wrap_v31(score: float, attack_vector: str = "NETWORK") -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "attackVector": attack_vector,
                                }
                            }
                        ]
                    }
                }
            }
        ]
    }


NVD_V31 = _wrap_v31(9.8, "NETWORK")
NVD_V30_ONLY = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "cvssData": {
                                "baseScore": 7.5,
                                "attackVector": "ADJACENT_NETWORK",
                            }
                        }
                    ]
                }
            }
        }
    ]
}
NVD_V2_ONLY = {
    "vulnerabilities": [
        {
            "cve": {
                "metrics": {
                    "cvssMetricV2": [
                        {"cvssData": {"baseScore": 5.0, "attackVector": "LOCAL"}}
                    ]
                }
            }
        }
    ]
}
NVD_NO_METRICS = {"vulnerabilities": [{"cve": {"metrics": {}}}]}
NVD_EMPTY = {"vulnerabilities": []}


def test_fetch_cvss_v31_score_and_vector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)):
        result = fetch_cvss_data(["CVE-2024-1234"])
    assert result == {"CVE-2024-1234": {"score": "9.8", "vector": "N"}}


def test_fetch_cvss_v30_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V30_ONLY)):
        result = fetch_cvss_data(["CVE-2024-2222"])
    assert result == {"CVE-2024-2222": {"score": "7.5", "vector": "A"}}


def test_fetch_cvss_v2_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V2_ONLY)):
        result = fetch_cvss_data(["CVE-2024-3333"])
    assert result == {"CVE-2024-3333": {"score": "5.0", "vector": "L"}}


def test_fetch_cvss_unknown_vector_normalizes_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    payload = _wrap_v31(9.0, "FUTURE_VECTOR_TYPE")
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(payload)):
        result = fetch_cvss_data(["CVE-2024-2025"])
    assert result["CVE-2024-2025"]["score"] == "9.0"
    assert result["CVE-2024-2025"]["vector"] == ""


def test_fetch_cvss_physical_vector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    payload = _wrap_v31(4.0, "PHYSICAL")
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(payload)):
        result = fetch_cvss_data(["CVE-2024-9001"])
    assert result["CVE-2024-9001"]["vector"] == "P"


def test_fetch_cvss_no_metrics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_NO_METRICS)):
        result = fetch_cvss_data(["CVE-2024-4444"])
    assert result == {"CVE-2024-4444": {"score": "", "vector": ""}}


def test_fetch_cvss_empty_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_EMPTY)):
        result = fetch_cvss_data(["CVE-2024-5555"])
    assert result == {"CVE-2024-5555": {"score": "", "vector": ""}}


def test_fetch_cvss_timeout_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", side_effect=TimeoutError()):
        result = fetch_cvss_data(["CVE-2024-6666"])
    assert result == {"CVE-2024-6666": {"score": "", "vector": ""}}


def test_fetch_cvss_http_error_graceful(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.error import URLError

    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen", side_effect=URLError("429")):
        result = fetch_cvss_data(["CVE-2024-7777"])
    assert result == {"CVE-2024-7777": {"score": "", "vector": ""}}


def test_fetch_cvss_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch("vulntriage.nvd.urlopen") as mock_open:
        result = fetch_cvss_data(["CVE-2024-8888"], offline=True)
    mock_open.assert_not_called()
    assert result == {"CVE-2024-8888": {"score": "", "vector": ""}}


def test_fetch_cvss_uses_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with patch(
        "vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)
    ) as mock_open:
        fetch_cvss_data(["CVE-2024-9999"])
        fetch_cvss_data(["CVE-2024-9999"])
    assert mock_open.call_count == 1


def test_fetch_cvss_cache_backwards_compat_score_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pre-v0.9.0 cache entries lack 'vector' — must read without crashing."""
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    from vulntriage.cache import write_cache

    write_cache("nvd_CVE-2024-OLD", {"score": "8.1"})  # no "vector" key
    result = fetch_cvss_data(["CVE-2024-OLD"])
    assert result == {"CVE-2024-OLD": {"score": "8.1", "vector": ""}}


def test_fetch_multiple_cves(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulntriage.cache.CACHE_DIR", tmp_path)
    with (
        patch("vulntriage.nvd.urlopen", return_value=_mock_response(NVD_V31)),
        patch("vulntriage.nvd.time.sleep"),
    ):
        result = fetch_cvss_data(["CVE-2024-0001", "CVE-2024-0002"])
    assert "CVE-2024-0001" in result
    assert "CVE-2024-0002" in result
