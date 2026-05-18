import hashlib
import os
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from vulntriage.audit import run_audit
from vulntriage.cache import scan_cache_get, scan_cache_set
from vulntriage.context import read_stack_context
from vulntriage.epss import fetch_epss
from vulntriage.exceptions import AuditError, AuthError, ContextError, ParseError
from vulntriage.ignore import load_ignores
from vulntriage.kev import fetch_kev
from vulntriage.models import CVE, RankedCVE
from vulntriage.nvd import fetch_cvss_scores
from vulntriage.output import (
    SEVERITY,
    determine_exit_code,
    render_json,
    render_table,
    save_report,
)
from vulntriage.ranker import get_provider, rank_cves

app = typer.Typer(help="Rank pip-audit CVEs by real exploitability using Claude AI.")
_console = Console(stderr=True)


def _resolve_cve_id(cve: CVE) -> str:
    """Return the first CVE-prefixed alias, or cve.id if no CVE alias exists."""
    for alias in cve.aliases:
        if alias.startswith("CVE-"):
            return alias
    return cve.id


def _read_dep_content(project_root: Path) -> str:
    for name in ("requirements.txt", "pyproject.toml"):
        p = project_root / name
        if p.exists():
            return p.read_text(encoding="utf-8")
    return ""


def _ranked_to_dict(r: RankedCVE) -> dict[str, Any]:
    return {
        "rank": r.rank,
        "real_risk": r.real_risk,
        "reasoning": r.reasoning,
        "fix_command": r.fix_command,
        "cvss": r.cvss,
        "breaking_changes": r.breaking_changes,
        "kev": r.kev,
        "epss": r.epss,
        "cve_id": r.cve.id,
        "cve_package": r.cve.package,
        "cve_installed_version": r.cve.installed_version,
        "cve_fix_versions": r.cve.fix_versions,
        "cve_aliases": r.cve.aliases,
        "cve_description": r.cve.description,
    }


def _ranked_from_dict(d: dict[str, Any]) -> RankedCVE:
    return RankedCVE(
        rank=d["rank"],
        cve=CVE(
            id=d["cve_id"],
            package=d["cve_package"],
            installed_version=d["cve_installed_version"],
            fix_versions=d["cve_fix_versions"],
            aliases=d["cve_aliases"],
            description=d["cve_description"],
        ),
        real_risk=d["real_risk"],
        reasoning=d["reasoning"],
        fix_command=d["fix_command"],
        cvss=d["cvss"],
        breaking_changes=d["breaking_changes"],
        kev=d["kev"],
        epss=d["epss"],
    )


@app.callback()
def _root() -> None:
    """vulntriage — CVE triage powered by Claude."""


@app.command()
def scan(
    project_root: Path = typer.Option(
        Path("."),
        "--project-root",
        "-p",
        help="Root of the project to scan (needs requirements.txt or pyproject.toml).",
        exists=True,
        file_okay=False,
        resolve_path=True,
    ),
    fail_on: str = typer.Option(
        "HIGH",
        "--fail-on",
        help="Minimum risk level that triggers exit code 1 (CRITICAL/HIGH/MEDIUM/LOW/INFO).",  # noqa: E501
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table (default) or json.",
    ),
    output_dir: Path | None = typer.Option(
        None,
        "--output-dir",
        help="Directory to write a timestamped JSON report. Omit to skip saving.",
        file_okay=False,
        resolve_path=True,
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Skip all network calls (NVD, CISA KEV, EPSS). Uses cached data only.",
    ),
    no_cache: bool = typer.Option(
        False,
        "--no-cache",
        help="Skip scan result cache; always run a fresh scan.",
    ),
) -> None:
    """Run pip-audit and rank CVEs by real risk using Claude."""
    fail_on_upper = fail_on.upper()
    if fail_on_upper not in SEVERITY:
        valid = "/".join(sorted(SEVERITY, key=SEVERITY.get, reverse=True))  # type: ignore[arg-type]
        typer.echo(
            f"Error: invalid --fail-on value {fail_on!r}. Must be one of: {valid}",
            err=True,
        )
        raise typer.Exit(1)

    try:
        provider = get_provider()
    except (AuthError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Using provider: {provider.name}", err=True)

    dep_content = _read_dep_content(project_root)
    cache_key = (
        "scan_"
        + hashlib.sha256(
            f"{dep_content}|{fail_on_upper}|{offline}|{provider.name}".encode()
        ).hexdigest()[:16]
    )

    if not no_cache:
        cached = scan_cache_get(cache_key)
        if cached is not None:
            typer.echo("Using cached scan results.", err=True)
            ranked = [_ranked_from_dict(d) for d in cached]
            if output_format == "json":
                render_json(ranked)
            else:
                render_table(ranked)
            if output_dir is not None:
                report_path = save_report(
                    ranked,
                    metadata={
                        "provider": provider.name,
                        "project_root": str(project_root),
                        "cves_found": len(ranked),
                        "cves_ranked": len(ranked),
                    },
                    output_dir=output_dir,
                )
                typer.echo(f"Report saved: {report_path}", err=True)
            raise typer.Exit(determine_exit_code(ranked, fail_on=fail_on_upper))

    try:
        with _console.status("Running pip-audit..."):
            cves = run_audit()
    except AuditError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    # Deduplicate: pip-audit may report the same vuln ID once per affected package.
    seen_ids: set[str] = set()
    deduped: list[CVE] = []
    for c in cves:
        if c.id not in seen_ids:
            seen_ids.add(c.id)
            deduped.append(c)
    if len(deduped) < len(cves):
        dups = len(cves) - len(deduped)
        typer.echo(f"Deduplicated {dups} duplicate CVE(s).", err=True)
    cves = deduped

    ignored = load_ignores(project_root)
    if ignored:
        before = len(cves)
        cves = [c for c in cves if c.id not in ignored]
        suppressed = before - len(cves)
        if suppressed:
            typer.echo(f"Suppressed {suppressed} CVE(s) via .vulnignore.", err=True)

    if not cves:
        if output_format == "json":
            render_json([])
        else:
            render_table([])
        raise typer.Exit(0)

    try:
        stack_context = read_stack_context(project_root)
    except ContextError as exc:
        typer.echo(f"Warning: {exc}. Proceeding without stack context.", err=True)
        stack_context = ""

    # Resolve PYSEC IDs to their CVE aliases for NVD/EPSS lookups.
    # NVD and EPSS reject PYSEC-* IDs; only CVE-* IDs return data.
    _id_map = {c.id: _resolve_cve_id(c) for c in cves}
    resolved_ids = list(_id_map.values())
    nvd_api_key: str | None = os.environ.get("NVD_API_KEY") or None

    with _console.status("Fetching threat intelligence (NVD, KEV, EPSS)..."):
        _nvd_raw = fetch_cvss_scores(resolved_ids, api_key=nvd_api_key, offline=offline)
        _kev_raw = fetch_kev(offline=offline)
        _epss_raw = fetch_epss(resolved_ids, offline=offline)

    # Remap to raw cve.id keys so ranker lookups work correctly.
    nvd_scores = {raw: _nvd_raw.get(resolved, "") for raw, resolved in _id_map.items()}
    epss_scores = {
        raw: _epss_raw.get(resolved, "") for raw, resolved in _id_map.items()
    }
    kev_set = {raw for raw, resolved in _id_map.items() if resolved in _kev_raw}

    try:
        with _console.status(f"Ranking {len(cves)} CVE(s) with {provider.name}..."):
            ranked = rank_cves(
                cves,
                stack_context,
                provider=provider,
                nvd_scores=nvd_scores,
                kev_set=kev_set,
                epss_scores=epss_scores,
            )
    except AuthError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)
    except ParseError as exc:
        typer.echo(f"Error: Claude response could not be parsed: {exc}", err=True)
        raise typer.Exit(1)

    if len(ranked) < len(cves):
        typer.echo(
            f"Warning: {len(cves) - len(ranked)} CVE(s) were dropped from ranking.",
            err=True,
        )

    scan_cache_set(cache_key, [_ranked_to_dict(r) for r in ranked])

    if output_format == "json":
        render_json(ranked)
    else:
        render_table(ranked)

    if output_dir is not None:
        report_path = save_report(
            ranked,
            metadata={
                "provider": provider.name,
                "project_root": str(project_root),
                "cves_found": len(cves),
                "cves_ranked": len(ranked),
            },
            output_dir=output_dir,
        )
        typer.echo(f"Report saved: {report_path}", err=True)

    raise typer.Exit(determine_exit_code(ranked, fail_on=fail_on_upper))
