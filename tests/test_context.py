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
