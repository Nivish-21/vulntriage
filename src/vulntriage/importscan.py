import ast
import sys
from pathlib import Path
from typing import TypedDict

_SKIP_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "env",
        ".env",
        "site-packages",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".git",
        ".tox",
        ".nox",
    }
)

_MAX_CALL_SITES_PER_PKG = 10


class CallSite(TypedDict):
    file: str
    line: int
    func: str
    kwargs: list[str]


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def _walk_py_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _extract_imports(
    source: str,
) -> tuple[dict[str, set[str]], dict[str, str]]:
    """Parse import statements.

    Returns (imports, alias_map) where:
      imports: normalized package name → set of imported symbol names
      alias_map: local name used in code → normalized package name
        e.g. "req" → "requests" for `import requests as req`
              "get" → "requests" for `from requests import get`
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}, {}

    imports: dict[str, set[str]] = {}
    alias_map: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                key = _normalize(top)
                imports.setdefault(key, set())
                # `import requests as req` → alias_map["req"] = "requests"
                local = alias.asname if alias.asname else alias.name.split(".")[0]
                alias_map[local] = key
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top = node.module.split(".")[0]
            key = _normalize(top)
            symbols = {a.name for a in node.names}
            existing = imports.setdefault(key, set())
            existing.update(symbols)
            # `from requests import get` → alias_map["get"] = "requests"
            # `from requests import get as g` → alias_map["g"] = "requests"
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                alias_map[local] = key

    return imports, alias_map


def _extract_call_sites(
    source: str,
    rel_path: str,
    alias_map: dict[str, str],
) -> dict[str, list[CallSite]]:
    """Walk ast.Call nodes; map each invocation back to its package.

    Returns: normalized package name → list of CallSite dicts.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    sites: dict[str, list[CallSite]] = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        pkg: str | None = None
        func_name: str = ""

        func = node.func
        if isinstance(func, ast.Attribute):
            # requests.get() / req.get() / requests.Session().mount()
            root_obj = func.value
            # unwrap one level of chaining: Session().mount → Session
            if isinstance(root_obj, ast.Call) and isinstance(
                root_obj.func, ast.Attribute
            ):
                root_obj = root_obj.func.value
            elif isinstance(root_obj, ast.Call) and isinstance(
                root_obj.func, ast.Name
            ):
                root_obj = root_obj.func

            if isinstance(root_obj, ast.Name) and root_obj.id in alias_map:
                pkg = alias_map[root_obj.id]
                func_name = f"{root_obj.id}.{func.attr}"
            elif isinstance(root_obj, ast.Attribute):
                # deeper chain like pkg.sub.method — take leftmost Name
                inner = root_obj
                while isinstance(inner, ast.Attribute):
                    inner = inner.value
                if isinstance(inner, ast.Name) and inner.id in alias_map:
                    pkg = alias_map[inner.id]
                    func_name = f"{inner.id}.{root_obj.attr}.{func.attr}"

        elif isinstance(func, ast.Name):
            # bare `get(...)` after `from requests import get`
            if func.id in alias_map:
                pkg = alias_map[func.id]
                func_name = func.id

        if pkg is None:
            continue

        kwargs = [kw.arg for kw in node.keywords if kw.arg is not None]
        site: CallSite = {
            "file": rel_path,
            "line": node.lineno,
            "func": func_name,
            "kwargs": kwargs,
        }
        sites.setdefault(pkg, []).append(site)

    return sites


def scan_call_sites(
    project_root: Path,
) -> dict[str, list[CallSite]]:
    """Scan the project for call sites, capped at _MAX_CALL_SITES_PER_PKG each."""
    combined: dict[str, list[CallSite]] = {}

    for py_file in _walk_py_files(project_root):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        _, alias_map = _extract_imports(source)
        if not alias_map:
            continue

        try:
            rel_path = str(py_file.relative_to(project_root))
        except ValueError:
            rel_path = str(py_file)

        file_sites = _extract_call_sites(source, rel_path, alias_map)
        for pkg, sites in file_sites.items():
            existing = combined.setdefault(pkg, [])
            remaining = _MAX_CALL_SITES_PER_PKG - len(existing)
            if remaining > 0:
                existing.extend(sites[:remaining])

    return combined


def scan_project(
    project_root: Path,
) -> tuple[dict[str, set[str]], dict[str, list[CallSite]]]:
    """Return (imports, call_sites) for the project in a single pass."""
    combined_imports: dict[str, set[str]] = {}
    combined_sites: dict[str, list[CallSite]] = {}

    for py_file in _walk_py_files(project_root):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        file_imports, alias_map = _extract_imports(source)

        if not file_imports:
            try:
                ast.parse(source)
            except SyntaxError:
                print(
                    f"Warning: skipping {py_file} (SyntaxError)",
                    file=sys.stderr,
                )
                continue

        for pkg, symbols in file_imports.items():
            existing = combined_imports.setdefault(pkg, set())
            existing.update(symbols)

        if alias_map:
            try:
                rel_path = str(py_file.relative_to(project_root))
            except ValueError:
                rel_path = str(py_file)

            file_sites = _extract_call_sites(source, rel_path, alias_map)
            for pkg, sites in file_sites.items():
                existing_sites = combined_sites.setdefault(pkg, [])
                remaining = _MAX_CALL_SITES_PER_PKG - len(existing_sites)
                if remaining > 0:
                    existing_sites.extend(sites[:remaining])

    return combined_imports, combined_sites


def scan_imports(project_root: Path) -> dict[str, set[str]]:
    """Return a mapping of normalised package name → set of imported symbols.

    An empty symbol set means the package was bare-imported (`import pkg`).
    Skips files with SyntaxError, warns to stderr.
    """
    imports, _ = scan_project(project_root)
    return imports
