from pathlib import Path

import typer
from rich.console import Console

from vulntriage.audit import run_audit
from vulntriage.context import read_stack_context
from vulntriage.exceptions import AuditError, AuthError, ContextError, ParseError
from vulntriage.ignore import load_ignores
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

    try:
        with _console.status("Running pip-audit..."):
            cves = run_audit()
    except AuditError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

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

    try:
        with _console.status(f"Ranking {len(cves)} CVE(s) with {provider.name}..."):
            ranked = rank_cves(cves, stack_context, provider=provider)
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
