from pathlib import Path

import typer

from vulntriage.audit import run_audit
from vulntriage.context import read_stack_context
from vulntriage.exceptions import AuditError, AuthError, ContextError, ParseError
from vulntriage.output import determine_exit_code, render_table
from vulntriage.ranker import get_provider, rank_cves

app = typer.Typer(help="Rank pip-audit CVEs by real exploitability using Claude AI.")


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
) -> None:
    """Run pip-audit and rank CVEs by real risk using Claude."""
    try:
        provider = get_provider()
    except (AuthError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    try:
        cves = run_audit()
    except AuditError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(1)

    if not cves:
        render_table([])
        raise typer.Exit(0)

    try:
        stack_context = read_stack_context(project_root)
    except ContextError as exc:
        typer.echo(f"Warning: {exc}. Proceeding without stack context.", err=True)
        stack_context = ""

    try:
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
    render_table(ranked)
    raise typer.Exit(determine_exit_code(ranked))
