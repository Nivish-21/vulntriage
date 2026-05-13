from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pip_audit_json() -> str:
    return (FIXTURES / "pip_audit_output.json").read_text()


@pytest.fixture
def requirements_txt_path() -> Path:
    return FIXTURES / "requirements.txt"


@pytest.fixture
def pyproject_toml_path() -> Path:
    return FIXTURES / "pyproject_sample.toml"
