import tomllib
from pathlib import Path

from vulntriage.exceptions import ContextError


def read_stack_context(project_root: Path) -> str:
    req_file = project_root / "requirements.txt"
    if req_file.exists():
        try:
            return req_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContextError(
                f"requirements.txt contains non-UTF-8 content: {exc}"
            ) from exc
    pyproject_file = project_root / "pyproject.toml"
    if pyproject_file.exists():
        try:
            content = pyproject_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContextError(
                f"pyproject.toml contains non-UTF-8 content: {exc}"
            ) from exc
        data = tomllib.loads(content)
        deps: list[str] = data.get("project", {}).get("dependencies", [])
        return "\n".join(deps)
    raise ContextError(f"No requirements.txt or pyproject.toml found in {project_root}")
