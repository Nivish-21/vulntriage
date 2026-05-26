from pathlib import Path

import pytest

from vulntriage.importscan import (
    _extract_call_sites,
    _extract_imports,
    scan_call_sites,
    scan_imports,
    scan_project,
)


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


# --- alias_map and call-site extraction ---


def test_alias_map_bare_import() -> None:
    source = "import requests as req\n"
    _, alias_map = _extract_imports(source)
    assert alias_map["req"] == "requests"


def test_alias_map_from_import() -> None:
    source = "from requests import get\n"
    _, alias_map = _extract_imports(source)
    assert alias_map["get"] == "requests"


def test_alias_map_from_import_aliased_symbol() -> None:
    source = "from requests import get as rget\n"
    _, alias_map = _extract_imports(source)
    assert alias_map["rget"] == "requests"


def test_extract_call_sites_attribute_call() -> None:
    source = "import requests\nrequests.get('http://x', verify=False, timeout=5)\n"
    _, alias_map = _extract_imports(source)
    sites = _extract_call_sites(source, "app.py", alias_map)
    assert "requests" in sites
    site = sites["requests"][0]
    assert site["file"] == "app.py"
    assert site["line"] == 2
    assert site["func"] == "requests.get"
    assert "verify" in site["kwargs"]
    assert "timeout" in site["kwargs"]


def test_extract_call_sites_alias_resolved() -> None:
    source = "import requests as req\nreq.post('/api', json={})\n"
    _, alias_map = _extract_imports(source)
    sites = _extract_call_sites(source, "api.py", alias_map)
    assert "requests" in sites
    assert sites["requests"][0]["func"] == "req.post"


def test_extract_call_sites_bare_symbol_call() -> None:
    source = "from requests import get\nget('http://x')\n"
    _, alias_map = _extract_imports(source)
    sites = _extract_call_sites(source, "app.py", alias_map)
    assert "requests" in sites
    assert sites["requests"][0]["func"] == "get"
    assert sites["requests"][0]["kwargs"] == []


def test_extract_call_sites_no_kwargs_shows_empty_list() -> None:
    source = "import requests\nrequests.get('http://x')\n"
    _, alias_map = _extract_imports(source)
    sites = _extract_call_sites(source, "app.py", alias_map)
    assert sites["requests"][0]["kwargs"] == []


def test_extract_call_sites_star_kwargs_excluded() -> None:
    source = "import requests\nrequests.get('http://x', **opts)\n"
    _, alias_map = _extract_imports(source)
    sites = _extract_call_sites(source, "app.py", alias_map)
    # **opts has kw.arg=None — must not appear in kwargs list
    assert sites["requests"][0]["kwargs"] == []


def test_scan_call_sites_cap_per_package(tmp_path: Path) -> None:
    lines = ["import requests\n"]
    for i in range(15):
        lines.append(f"requests.get('url{i}')\n")
    _write(tmp_path, "app.py", "".join(lines))
    sites = scan_call_sites(tmp_path)
    assert len(sites["requests"]) == 10


def test_scan_project_returns_both(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "import requests\nrequests.get('http://x')\n")
    imports, call_sites = scan_project(tmp_path)
    assert "requests" in imports
    assert "requests" in call_sites
    assert call_sites["requests"][0]["func"] == "requests.get"


def test_scan_imports_delegates_to_scan_project(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "from flask import Flask\n")
    result = scan_imports(tmp_path)
    assert "flask" in result
    assert "Flask" in result["flask"]


def test_unrelated_calls_not_captured(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", "import requests\nprint('hello')\nlen([])\n")
    sites = scan_call_sites(tmp_path)
    # print and len are builtins, not in alias_map — should not appear
    assert "builtins" not in sites
    flat_funcs = [s["func"] for pkg in sites.values() for s in pkg]
    assert "print" not in flat_funcs
    assert "len" not in flat_funcs
