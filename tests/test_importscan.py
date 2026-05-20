from pathlib import Path

import pytest

from vulntriage.importscan import scan_imports


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


def test_bare_import(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "import requests\n")
    result = scan_imports(tmp_path)
    assert "requests" in result
    assert result["requests"] == set()


def test_from_import_symbols(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "from requests import Session, get\n")
    result = scan_imports(tmp_path)
    assert result["requests"] == {"Session", "get"}


def test_multiple_files_merged(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", "from requests import Session\n")
    _write(tmp_path, "b.py", "from requests import get\nimport urllib3\n")
    result = scan_imports(tmp_path)
    assert result["requests"] == {"Session", "get"}
    assert "urllib3" in result


def test_syntax_error_file_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    _write(tmp_path, "bad.py", "def foo(\n")  # SyntaxError
    _write(tmp_path, "good.py", "import flask\n")
    result = scan_imports(tmp_path)
    assert "flask" in result
    assert "bad" not in str(result)


def test_venv_excluded(tmp_path: Path) -> None:
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "secret.py").write_text("import secret_pkg\n")
    _write(tmp_path, "app.py", "import myapp\n")
    result = scan_imports(tmp_path)
    assert "secret_pkg" not in result
    assert "myapp" in result


def test_normalize_hyphen_to_underscore(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "import google_auth\n")
    result = scan_imports(tmp_path)
    assert "google_auth" in result


def test_empty_project(tmp_path: Path) -> None:
    result = scan_imports(tmp_path)
    assert result == {}


def test_subpackage_top_level_only(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "from urllib.parse import urlencode\n")
    result = scan_imports(tmp_path)
    assert "urllib" in result
    assert result["urllib"] == {"urlencode"}
