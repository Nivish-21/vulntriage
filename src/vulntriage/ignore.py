from pathlib import Path

IGNORE_FILENAME = ".vulnignore"


def load_ignores(project_root: Path) -> frozenset[str]:
    path = project_root / IGNORE_FILENAME
    if not path.exists():
        return frozenset()
    ids: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        cve_id = stripped.split()[0]
        ids.append(cve_id)
    return frozenset(ids)
