import hashlib
import os
import signal
import sys
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
from vulntriage.nvd import fetch_cvss_data
from vulntriage.output import (
    SEVERITY,
    determine_exit_code,
    render_json,
    render_table,
    save_report,
)
from vulntriage.pypi import fetch_deprecation_info
from vulntriage.ranker import get_provider, rank_cves
from vulntriage.sarif import render_sarif

_VALID_FORMATS: frozenset[str] = frozenset({"table", "json", "sarif"})

# Restore Unix default for SIGPIPE so piping output to `head -1` or similar
# closes silently instead of raising BrokenPipeError on stdout flush at exit.
if sys.platform != "win32":
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

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
        "code_changes": r.code_changes,
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
            fix_versions=tuple(d["cve_fix_versions"]),
            aliases=tuple(d["cve_aliases"]),
            description=d["cve_description"],
        ),
        real_risk=d["real_risk"],
        reasoning=d["reasoning"],
        fix_command=d["fix_command"],
        cvss=d["cvss"],
        breaking_changes=d["breaking_changes"],
        code_changes=d.get("code_changes", ""),
        kev=d["kev"],
        epss=d["epss"],
    )


def _dispatch_output(
    ranked: list[RankedCVE], output_format: str, project_root: Path
) -> None:
    if output_format == "json":
        render_json(ranked)
    elif output_format == "sarif":
        render_sarif(ranked, project_root)
    else:
        render_table(ranked)


def _print_deprecation_warnings(dep_info: dict[str, dict]) -> None:
    warnings = []
    for pkg, info in dep_info.items():
        if info.get("deprecated"):
            warnings.append(
                f"  [bold red]DEPRECATED[/bold red] {pkg} — "
                "marked 'Development Status :: 7 - Inactive' on PyPI"
            )
        elif info.get("unmaintained"):
            years = info.get("years_since", 0)
            last = info.get("last_release", "unknown")
            warnings.append(
                f"  [yellow]UNMAINTAINED[/yellow] {pkg} — "
                f"last release {last} ({years:.1f} years ago)"
            )
    if warnings:
        _console.print("\n[bold]Deprecation / Maintenance Warnings:[/bold]")
        for w in warnings:
            _console.print(w)


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
        help="Output format: table (default), json, or sarif.",
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
    airgap: bool = typer.Option(
        False,
        "--airgap",
        help=(
            "Fully offline mode: implies --offline and forces --provider ollama. "
            "Rejects cloud providers (anthropic/openai/gemini). Requires a local "
            "Ollama daemon."
        ),
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

    output_format = output_format.lower()
    if output_format not in _VALID_FORMATS:
        valid_fmt = "/".join(sorted(_VALID_FORMATS))
        typer.echo(
            f"Error: invalid --format value {output_format!r}. "
            f"Must be one of: {valid_fmt}",
            err=True,
        )
        raise typer.Exit(1)

    provider_override: str | None = None
    if airgap:
        offline = True
        env_provider = os.environ.get("VULNTRIAGE_PROVIDER", "").strip().lower()
        if env_provider and env_provider != "ollama":
            typer.echo(
                f"Error: --airgap is incompatible with --provider {env_provider!r}. "
                "Airgap mode requires the local 'ollama' provider. Unset "
                "VULNTRIAGE_PROVIDER or set it to 'ollama'.",
                err=True,
            )
            raise typer.Exit(1)
        provider_override = "ollama"

    try:
        provider = get_provider(provider_override)
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
            _dispatch_output(ranked, output_format, project_root)
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
            cves = run_audit(project_root)
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
        stale = sorted(ignored - {c.id for c in cves})
        if stale:
            noun = "entry" if len(stale) == 1 else "entries"
            typer.echo(
                f"Warning: {len(stale)} .vulnignore {noun} no longer match any "
                f"reported CVE: {', '.join(stale)}",
                err=True,
            )
        before = len(cves)
        cves = [c for c in cves if c.id not in ignored]
        suppressed = before - len(cves)
        if suppressed:
            typer.echo(f"Suppressed {suppressed} CVE(s) via .vulnignore.", err=True)

    if not cves:
        _dispatch_output([], output_format, project_root)
        raise typer.Exit(0)

    cve_packages = list({c.package for c in cves})
    try:
        stack_context = read_stack_context(project_root, cve_packages=cve_packages)
    except ContextError as exc:
        typer.echo(f"Warning: {exc}. Proceeding without stack context.", err=True)
        stack_context = ""

    # Resolve PYSEC IDs to their CVE aliases for NVD/EPSS lookups.
    # NVD and EPSS reject PYSEC-* IDs; only CVE-* IDs return data.
    _id_map = {c.id: _resolve_cve_id(c) for c in cves}
    resolved_ids = list(_id_map.values())
    nvd_api_key: str | None = os.environ.get("NVD_API_KEY") or None

    with _console.status("Fetching threat intelligence (NVD, KEV, EPSS)..."):
        _nvd_raw = fetch_cvss_data(resolved_ids, api_key=nvd_api_key, offline=offline)
        _kev_raw = fetch_kev(offline=offline)
        _epss_raw = fetch_epss(resolved_ids, offline=offline)

    # Remap to raw cve.id keys so ranker lookups work correctly.
    nvd_data = {
        raw: _nvd_raw.get(resolved, {"score": "", "vector": ""})
        for raw, resolved in _id_map.items()
    }
    epss_scores = {
        raw: _epss_raw.get(resolved, "") for raw, resolved in _id_map.items()
    }
    kev_set = {raw for raw, resolved in _id_map.items() if resolved in _kev_raw}

    if not offline and not provider.name.startswith("ollama"):
        typer.echo(
            f"Note: dependency list sent to {provider.name} for CVE ranking. "
            "Use --offline or VULNTRIAGE_PROVIDER=ollama for local-only analysis.",
            err=True,
        )

    try:
        with _console.status(f"Ranking {len(cves)} CVE(s) with {provider.name}..."):
            ranked = rank_cves(
                cves,
                stack_context,
                provider=provider,
                nvd_data=nvd_data,
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

    with _console.status("Checking PyPI maintenance status..."):
        dep_info = fetch_deprecation_info(cve_packages, offline=offline)

    _dispatch_output(ranked, output_format, project_root)

    _print_deprecation_warnings(dep_info)

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
