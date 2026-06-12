import tomllib
from pathlib import Path
from typing import Any

from vulntriage.exceptions import ContextError
from vulntriage.importscan import scan_project

_LOCK_FILE_PRIORITY: tuple[str, ...] = ("uv.lock", "poetry.lock", "pdm.lock")

_WEB_FRAMEWORKS = frozenset(
    {
        "fastapi",
        "flask",
        "django",
        "starlette",
        "aiohttp",
        "sanic",
        "tornado",
        "bottle",
        "falcon",
        "quart",
        "pyramid",
    }
)
_CLI_FRAMEWORKS = frozenset({"typer", "click", "argparse", "fire", "docopt"})

# pip install name → Python import name when they differ
_PIP_IMPORT_ALIASES: dict[str, str] = {
    "pyjwt": "jwt",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "opencv-python": "cv2",
    "python-dotenv": "dotenv",
    "mysqlclient": "MySQLdb",
    "psycopg2-binary": "psycopg2",
    "pyyaml": "yaml",
    "pyserial": "serial",
    "pyzmq": "zmq",
    "python-magic": "magic",
    "gitpython": "git",
}


def _read_lock_file(project_root: Path) -> str | None:
    """Return a formatted resolved-deps section from the first lock file found.

    Priority: uv.lock > poetry.lock > pdm.lock.
    Returns None when no lock file exists, TOML parsing fails, or no packages found.
    """
    for filename in _LOCK_FILE_PRIORITY:
        lock_path = project_root / filename
        if not lock_path.exists():
            continue
        try:
            content = lock_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            return None
        packages = data.get("package", [])
        if not isinstance(packages, list):
            return None
        lines: list[str] = []
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = pkg.get("version")
            if name and version:
                lines.append(f"{name}=={version}")
        if not lines:
            return None
        return f"Resolved dependencies (from {filename}):\n" + "\n".join(lines)
    return None


def _detect_project_type(imported: dict[str, set[str]]) -> str:
    """Infer project type from top-level imports. Web wins over CLI on ties."""
    if not imported:
        return "unknown"
    if _WEB_FRAMEWORKS & imported.keys():
        return "web_service"
    if _CLI_FRAMEWORKS & imported.keys():
        return "cli"
    return "library"


def _detected_framework(imported: dict[str, set[str]], project_type: str) -> str:
    """Return the specific framework name detected, for prompt clarity."""
    if project_type == "web_service":
        for pkg in sorted(_WEB_FRAMEWORKS & imported.keys()):
            return pkg
    if project_type == "cli":
        for pkg in sorted(_CLI_FRAMEWORKS & imported.keys()):
            return pkg
    return ""


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
    """Return a formatted import-presence + call-site block for the LLM stack."""
    imported, call_sites = scan_project(project_root)
    lines: list[str] = []
    for pkg in cve_packages:
        normalized = pkg.lower().replace("-", "_")
        if normalized in imported:
            symbols = sorted(imported[normalized])
            if symbols:
                lines.append(f"{pkg}: IMPORTED — symbols used: {', '.join(symbols)}")
            else:
                lines.append(f"{pkg}: IMPORTED (bare import, no specific symbols)")
            for site in call_sites.get(normalized, []):
                kwargs_str = (
                    f"({', '.join(k + '=' for k in site['kwargs'])})"
                    if site["kwargs"]
                    else "()"
                )
                lines.append(
                    f"  {site['file']}:{site['line']}  {site['func']}{kwargs_str}"
                )
        else:
            # Try pip→import name alias (e.g. pyjwt → jwt)
            import_name = _PIP_IMPORT_ALIASES.get(normalized, normalized)
            if import_name != normalized and import_name in imported:
                symbols = sorted(imported[import_name])
                if symbols:
                    lines.append(
                        f"{pkg}: IMPORTED as '{import_name}'"
                        f" — symbols used: {', '.join(symbols)}"
                    )
                else:
                    lines.append(
                        f"{pkg}: IMPORTED as '{import_name}'"
                        " (bare import, no specific symbols)"
                    )
                for site in call_sites.get(import_name, []):
                    kwargs_str = (
                        f"({', '.join(k + '=' for k in site['kwargs'])})"
                        if site["kwargs"]
                        else "()"
                    )
                    lines.append(
                        f"  {site['file']}:{site['line']}  {site['func']}{kwargs_str}"
                    )
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

    lock_section = _read_lock_file(project_root)
    if lock_section:
        dep_content = f"{dep_content}\n\n{lock_section}"

    imported, _ = scan_project(project_root)
    project_type = _detect_project_type(imported)
    framework = _detected_framework(imported, project_type)
    type_line = (
        f"Project type: {project_type} ({framework} detected)"
        if framework
        else f"Project type: {project_type}"
    )

    if not cve_packages:
        return f"{dep_content}\n\n{type_line}"

    import_section = _build_import_section(project_root, cve_packages)
    return (
        f"{dep_content}\n\n{type_line}\n\n"
        f"Import presence in source:\n{import_section}"
    )
