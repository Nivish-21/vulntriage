import tomllib
from pathlib import Path
from typing import Any

from vulntriage.exceptions import ContextError
from vulntriage.importscan import scan_imports


def _extract_poetry_deps(poetry_table: dict[str, Any]) -> list[str]:
    """Flatten [tool.poetry.dependencies] into requirements-style lines.

    Skips the `python` key (interpreter pin, not a runtime dep).
    Handles both string specs ("^2.28") and dict specs ({"version": "^4.2", ...}).
    """
    lines: list[str] = []
    for name, spec in poetry_table.items():
        if name == "python":
            continue
        if isinstance(spec, str):
            lines.append(f"{name}{spec}")
        elif isinstance(spec, dict):
            version = spec.get("version", "")
            lines.append(f"{name}{version}" if version else name)
        else:
            lines.append(name)
    return lines


def _build_import_section(project_root: Path, cve_packages: list[str]) -> str:
    """Return a formatted import-presence block for the LLM stack context."""
    imported = scan_imports(project_root)
    lines: list[str] = []
    for pkg in cve_packages:
        normalized = pkg.lower().replace("-", "_")
        if normalized in imported:
            symbols = sorted(imported[normalized])
            if symbols:
                lines.append(f"{pkg}: IMPORTED — symbols used: {', '.join(symbols)}")
            else:
                lines.append(f"{pkg}: IMPORTED (bare import, no specific symbols)")
        else:
            lines.append(f"{pkg}: NOT FOUND IN SOURCE (likely transitive dep)")
    return "\n".join(lines)


def read_stack_context(
    project_root: Path, cve_packages: list[str] | None = None
) -> str:
    req_file = project_root / "requirements.txt"
    if req_file.exists():
        try:
            dep_content = req_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ContextError(
                f"requirements.txt contains non-UTF-8 content: {exc}"
            ) from exc
    else:
        pyproject_file = project_root / "pyproject.toml"
        if pyproject_file.exists():
            try:
                content = pyproject_file.read_text(encoding="utf-8")
            except UnicodeDecodeError as exc:
                raise ContextError(
                    f"pyproject.toml contains non-UTF-8 content: {exc}"
                ) from exc
            data = tomllib.loads(content)
            deps: list[str] = list(data.get("project", {}).get("dependencies", []))
            poetry_table = (
                data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            )
            if isinstance(poetry_table, dict):
                deps.extend(_extract_poetry_deps(poetry_table))
            dep_content = "\n".join(deps)
        else:
            raise ContextError(
                f"No requirements.txt or pyproject.toml found in {project_root}"
            )

    if not cve_packages:
        return dep_content

    import_section = _build_import_section(project_root, cve_packages)
    return f"{dep_content}\n\nImport presence in source:\n{import_section}"
