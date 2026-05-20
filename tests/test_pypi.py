import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from vulntriage.pypi import fetch_deprecation_info

_INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"


def _mock_pypi_response(
    classifiers: list[str],
    last_upload: str,
) -> bytes:
    data = {
        "info": {"classifiers": classifiers},
        "releases": {
            "1.0": [{"upload_time": last_upload}],
        },
    }
    return json.dumps(data).encode()


@patch("vulntriage.pypi.read_cache", return_value=None)
@patch("vulntriage.pypi.write_cache")
@patch("vulntriage.pypi.urlopen")
def test_deprecated_package(mock_urlopen, mock_write, mock_read) -> None:
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = _mock_pypi_response(
        [_INACTIVE_CLASSIFIER], "2020-01-01T00:00:00"
    )
    mock_urlopen.return_value = resp

    result = fetch_deprecation_info(["somepkg"])
    assert result["somepkg"]["deprecated"] is True


@patch("vulntriage.pypi.read_cache", return_value=None)
@patch("vulntriage.pypi.write_cache")
@patch("vulntriage.pypi.urlopen")
def test_unmaintained_old_release(mock_urlopen, mock_write, mock_read) -> None:
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = _mock_pypi_response([], "2019-01-01T00:00:00")
    mock_urlopen.return_value = resp

    result = fetch_deprecation_info(["oldpkg"])
    assert result["oldpkg"]["unmaintained"] is True
    assert result["oldpkg"]["deprecated"] is False


@patch("vulntriage.pypi.read_cache", return_value=None)
@patch("vulntriage.pypi.write_cache")
@patch("vulntriage.pypi.urlopen")
def test_active_package(mock_urlopen, mock_write, mock_read) -> None:
    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")
    resp = MagicMock()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    resp.read.return_value = _mock_pypi_response([], now)
    mock_urlopen.return_value = resp

    result = fetch_deprecation_info(["activepkg"])
    assert result["activepkg"]["deprecated"] is False
    assert result["activepkg"]["unmaintained"] is False


def test_offline_returns_empty() -> None:
    result = fetch_deprecation_info(["requests"], offline=True)
    assert result == {}


@patch("vulntriage.pypi.read_cache", return_value=None)
@patch("vulntriage.pypi.write_cache")
@patch("vulntriage.pypi.urlopen", side_effect=OSError("network error"))
def test_http_error_skips_package(mock_urlopen, mock_write, mock_read, capsys) -> None:
    result = fetch_deprecation_info(["badpkg"])
    assert "badpkg" not in result


@patch("vulntriage.pypi.read_cache")
def test_cache_hit_skips_network(mock_read) -> None:
    mock_read.return_value = {
        "deprecated": False,
        "unmaintained": False,
        "last_release": "2024-01-01",
        "years_since": 0.5,
    }
    result = fetch_deprecation_info(["cached_pkg"])
    assert result["cached_pkg"]["deprecated"] is False
