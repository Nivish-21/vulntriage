import ast
import sys
from pathlib import Path

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


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_")


def _walk_py_files(root: Path):
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def _extract_imports(source: str) -> dict[str, set[str]]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    imports: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                key = _normalize(top)
                imports.setdefault(key, set())
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            top = node.module.split(".")[0]
            key = _normalize(top)
            symbols = {a.name for a in node.names}
            existing = imports.setdefault(key, set())
            existing.update(symbols)
    return imports


def scan_imports(project_root: Path) -> dict[str, set[str]]:
    """Return a mapping of normalised package name → set of imported symbols.

    An empty symbol set means the package was bare-imported (`import pkg`).
    Skips files with SyntaxError, warns to stderr.
    """
    combined: dict[str, set[str]] = {}
    for py_file in _walk_py_files(project_root):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_imports = _extract_imports(source)
        if not file_imports:
            # Check if it was a syntax error (re-parse to confirm)
            try:
                ast.parse(source)
            except SyntaxError:
                print(
                    f"Warning: skipping {py_file} (SyntaxError)",
                    file=sys.stderr,
                )
        for pkg, symbols in file_imports.items():
            existing = combined.setdefault(pkg, set())
            existing.update(symbols)
    return combined
