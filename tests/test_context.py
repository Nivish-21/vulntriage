from pathlib import Path

import pytest

from vulntriage.context import read_stack_context
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
