from pathlib import Path

import pytest

from vulntriage.cli import _read_dep_content
from vulntriage.context import _read_lock_file, read_stack_context
from vulntriage.exceptions import ContextError


def test_reads_requirements_txt(requirements_txt_path: Path) -> None:
    context = read_stack_context(requirements_txt_path.parent)
    assert "requests==2.28.0" in context
    assert "urllib3==1.26.0" in context


def test_falls_back_to_pyproject_toml(
    pyproject_toml_path: Path, tmp_path: Path
) -> None:
    # Copy pyproject_sample.toml into a temp dir with no requirements.txt
    toml_content = pyproject_toml_path.read_text()
    (tmp_path / "pyproject.toml").write_text(toml_content)
    context = read_stack_context(tmp_path)
    assert "requests" in context


def test_requirements_txt_takes_priority(
    requirements_txt_path: Path, pyproject_toml_path: Path, tmp_path: Path
) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    (tmp_path / "pyproject.toml").write_text(pyproject_toml_path.read_text())
    context = read_stack_context(tmp_path)
    assert "flask==3.0.0" in context
    assert "requests" not in context


def test_raises_when_neither_file_exists(tmp_path: Path) -> None:
    with pytest.raises(ContextError, match="No requirements.txt or pyproject.toml"):
        read_stack_context(tmp_path)


def test_requirements_txt_unicode_error_raises(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_bytes(b"\xff\xfe invalid utf-8 \x80\x81")
    with pytest.raises(ContextError, match="non-UTF-8"):
        read_stack_context(tmp_path)


def test_pyproject_toml_unicode_error_raises(tmp_path: Path) -> None:
    toml_file = tmp_path / "pyproject.toml"
    toml_file.write_bytes(b"\xff\xfe invalid utf-8 \x80\x81")
    with pytest.raises(ContextError, match="non-UTF-8"):
        read_stack_context(tmp_path)


def test_import_section_included_when_cve_packages_given(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "app.py").write_text("from requests import Session\n")
    context = read_stack_context(tmp_path, cve_packages=["requests"])
    assert "Import presence in source:" in context
    assert "requests: IMPORTED" in context
    assert "Session" in context


def test_import_section_not_found_marks_transitive(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.0\n")
    (tmp_path / "app.py").write_text("import requests\n")
    context = read_stack_context(tmp_path, cve_packages=["urllib3"])
    assert "urllib3: NOT FOUND IN SOURCE" in context


def test_no_import_section_when_no_cve_packages(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    context = read_stack_context(tmp_path)
    assert "Import presence in source:" not in context


def test_poetry_dependencies_extracted(tmp_path: Path) -> None:
    """[tool.poetry.dependencies] with string specs is included."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'requests = "^2.28"\n'
        'fastapi = ">=0.95"\n'
    )
    context = read_stack_context(tmp_path)
    assert "requests^2.28" in context
    assert "fastapi>=0.95" in context
    # python pin is not a runtime dep
    assert "python^3.11" not in context


def test_poetry_dict_spec_extracted(tmp_path: Path) -> None:
    """[tool.poetry.dependencies] with dict spec uses the version key."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n"
        'django = {version = "^4.2", extras = ["argon2"]}\n'
    )
    context = read_stack_context(tmp_path)
    assert "django^4.2" in context


def test_poetry_and_pep621_merged(tmp_path: Path) -> None:
    """A project with both tables surfaces deps from both."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\n"
        'dependencies = ["click>=8.0"]\n'
        "\n"
        "[tool.poetry.dependencies]\n"
        'requests = "^2.28"\n'
    )
    context = read_stack_context(tmp_path)
    assert "click>=8.0" in context
    assert "requests^2.28" in context


def test_poetry_dep_without_version_spec(tmp_path: Path) -> None:
    """Dict spec with no version key falls back to bare package name."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poetry.dependencies]\n" 'mypkg = {extras = ["all"]}\n'
    )
    context = read_stack_context(tmp_path)
    assert "mypkg" in context


def test_project_type_web_service_detected(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.104.0\n")
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\n")
    context = read_stack_context(tmp_path, cve_packages=["fastapi"])
    assert "Project type: web_service (fastapi detected)" in context


def test_project_type_cli_detected(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("typer==0.12.0\n")
    (tmp_path / "main.py").write_text("import typer\n")
    context = read_stack_context(tmp_path, cve_packages=["typer"])
    assert "Project type: cli (typer detected)" in context


def test_project_type_library_when_no_framework(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "lib.py").write_text("import requests\n")
    context = read_stack_context(tmp_path, cve_packages=["requests"])
    assert "Project type: library" in context


def test_project_type_unknown_when_no_imports(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    context = read_stack_context(tmp_path)
    assert "Project type: unknown" in context


def test_project_type_web_wins_over_cli(tmp_path: Path) -> None:
    """When both web and CLI frameworks imported, web_service takes precedence."""
    (tmp_path / "requirements.txt").write_text("fastapi==0.104.0\nclick==8.0\n")
    (tmp_path / "app.py").write_text("from fastapi import FastAPI\nimport click\n")
    context = read_stack_context(tmp_path, cve_packages=["fastapi"])
    assert "web_service" in context
    assert "cli" not in context.split("Project type:")[1].split("\n")[0]


def test_project_type_present_without_cve_packages(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("django==4.2\n")
    (tmp_path / "app.py").write_text("from django.urls import path\n")
    context = read_stack_context(tmp_path)
    assert "Project type: web_service (django detected)" in context
    # Import section header still gated on cve_packages
    assert "Import presence in source:" not in context


def test_call_site_line_appears_in_import_section(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "app.py").write_text(
        "import requests\nrequests.get('http://x', verify=False)\n"
    )
    context = read_stack_context(tmp_path, cve_packages=["requests"])
    assert "app.py:2" in context
    assert "requests.get" in context
    assert "verify=" in context


def test_call_site_indented_two_spaces(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "app.py").write_text("import requests\nrequests.post('/api')\n")
    context = read_stack_context(tmp_path, cve_packages=["requests"])
    # call-site lines must start with two spaces
    call_site_lines = [
        ln for ln in context.splitlines() if "app.py" in ln and "requests.post" in ln
    ]
    assert call_site_lines, "no call-site line found"
    assert call_site_lines[0].startswith("  ")


def test_bare_call_no_kwargs_shows_empty_parens(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "app.py").write_text("import requests\nrequests.head('http://x')\n")
    context = read_stack_context(tmp_path, cve_packages=["requests"])
    assert "requests.head()" in context


def test_package_without_call_sites_shows_no_extra_lines(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.0\n")
    (tmp_path / "app.py").write_text("import urllib3\n")
    context = read_stack_context(tmp_path, cve_packages=["urllib3"])
    lines = context.splitlines()
    imported_line = next(ln for ln in lines if "urllib3: IMPORTED" in ln)
    idx = lines.index(imported_line)
    # next line (if any) must not be an indented call-site line
    if idx + 1 < len(lines):
        assert not lines[idx + 1].startswith("  ")


def test_pyjwt_alias_resolved_to_jwt_import(tmp_path: Path) -> None:
    """pyjwt (pip name) → jwt (import name): call sites must be surfaced."""
    (tmp_path / "requirements.txt").write_text("PyJWT==1.7.1\n")
    (tmp_path / "app.py").write_text(
        "import jwt\njwt.encode({'sub': '1'}, 'secret', algorithm='HS256')\n"
    )
    context = read_stack_context(tmp_path, cve_packages=["PyJWT"])
    assert "IMPORTED as 'jwt'" in context
    assert "jwt.encode" in context


def test_pyjwt_alias_call_sites_shown(tmp_path: Path) -> None:
    """Call sites under the jwt import name must appear under the PyJWT entry."""
    (tmp_path / "requirements.txt").write_text("PyJWT==1.7.1\n")
    (tmp_path / "app.py").write_text(
        "import jwt\njwt.decode('tok', 'secret', algorithms=['HS256'])\n"
    )
    context = read_stack_context(tmp_path, cve_packages=["PyJWT"])
    assert "app.py:2" in context
    assert "jwt.decode" in context
    assert "algorithms=" in context


def test_unknown_pip_name_still_shows_not_found(tmp_path: Path) -> None:
    """A package with no alias and no import shows NOT FOUND."""
    (tmp_path / "requirements.txt").write_text("some-obscure-lib==1.0\n")
    (tmp_path / "app.py").write_text("import requests\n")
    context = read_stack_context(tmp_path, cve_packages=["some-obscure-lib"])
    assert "NOT FOUND IN SOURCE" in context


# ---------------------------------------------------------------------------
# Lock-file support tests (v0.16.0)
# ---------------------------------------------------------------------------

_UV_LOCK = """\
version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "certifi"
version = "2023.7.22"
"""

_POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.28.0"
description = "Python HTTP for Humans."
category = "main"
optional = false
python-versions = ">=3.7"

[[package]]
name = "urllib3"
version = "1.26.18"
description = "HTTP library with thread-safe connection pooling."
category = "main"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*"
"""

_PDM_LOCK = """\
[metadata]
groups = ["default"]
strategy = ["cross_platform"]

[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "idna"
version = "3.4"
"""


def test_uv_lock_appended_to_context(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "uv.lock").write_text(_UV_LOCK)
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies (from uv.lock):" in context
    assert "requests==2.31.0" in context
    assert "certifi==2023.7.22" in context


def test_poetry_lock_appended_to_context(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "poetry.lock").write_text(_POETRY_LOCK)
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies (from poetry.lock):" in context
    assert "urllib3==1.26.18" in context


def test_pdm_lock_appended_to_context(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "pdm.lock").write_text(_PDM_LOCK)
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies (from pdm.lock):" in context
    assert "idna==3.4" in context


def test_lock_file_priority_uv_over_poetry(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "uv.lock").write_text(_UV_LOCK)
    (tmp_path / "poetry.lock").write_text(_POETRY_LOCK)
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies (from uv.lock):" in context
    assert "Resolved dependencies (from poetry.lock):" not in context


def test_no_lock_file_no_resolved_section(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies" not in context


def test_malformed_lock_file_no_crash(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    (tmp_path / "uv.lock").write_text("this is not valid TOML ][[\n")
    result = _read_lock_file(tmp_path)
    assert result is None
    context = read_stack_context(tmp_path)
    assert "Resolved dependencies" not in context


def test_read_dep_content_includes_lock_file(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "uv.lock").write_text(_UV_LOCK)
    content = _read_dep_content(tmp_path)
    # _read_dep_content returns raw file text for cache-key computation; the
    # lock file appears as raw TOML, not formatted pkg==version lines.
    assert "requests==2.31.0" in content
    assert 'name = "certifi"' in content
