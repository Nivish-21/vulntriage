from pathlib import Path

from vulntriage.ignore import load_ignores


def test_load_ignores_returns_empty_when_no_file(tmp_path: Path) -> None:
    assert load_ignores(tmp_path) == frozenset()


def test_load_ignores_parses_ids(tmp_path: Path) -> None:
    (tmp_path / ".vulnignore").write_text(
        "CVE-2023-32681 Accepted: low-risk internal usage\n"
        "CVE-2023-99999 Won't fix until Q4\n"
    )
    result = load_ignores(tmp_path)
    assert result == {"CVE-2023-32681", "CVE-2023-99999"}


def test_load_ignores_skips_comments(tmp_path: Path) -> None:
    (tmp_path / ".vulnignore").write_text(
        "# This is a comment\n" "CVE-2023-32681 real entry\n"
    )
    result = load_ignores(tmp_path)
    assert result == {"CVE-2023-32681"}


def test_load_ignores_skips_blank_lines(tmp_path: Path) -> None:
    (tmp_path / ".vulnignore").write_text("\n" "CVE-2023-32681\n" "\n")
    result = load_ignores(tmp_path)
    assert result == {"CVE-2023-32681"}


def test_load_ignores_id_only_line(tmp_path: Path) -> None:
    (tmp_path / ".vulnignore").write_text("CVE-2023-32681\n")
    assert load_ignores(tmp_path) == {"CVE-2023-32681"}
