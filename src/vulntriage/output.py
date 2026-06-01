import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.rule import Rule
from rich.table import Table

from vulntriage.models import RankedCVE, min_fix_version

RISK_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

SEVERITY: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "NONE": 5,
}

console = Console()


def _fix_line(r: RankedCVE) -> str:
    """One line telling the user the exact upgrade and the version delta.

    Prefers the LLM's fix_command; falls back to a synthesised pip command so the
    user always has something copy-pasteable. Escaped because package specs can
    contain '[extras]', which Rich would otherwise read as markup.
    """
    mfv = min_fix_version(r.cve.fix_versions)
    if not mfv:
        return "[dim]No fix released yet — monitor the advisory.[/dim]"
    raw = r.fix_command.strip() or f'pip install "{r.cve.package}>={mfv}"'
    cmd = escape(raw)
    delta = (
        f"[dim](you have {escape(r.cve.installed_version)} "
        f"→ need ≥ {escape(mfv)})[/dim]"
    )
    return f"[green]{cmd}[/green]   {delta}"


def _severity_line(r: RankedCVE) -> str:
    """Compact severity facts; omitted entirely when nothing is known."""
    parts: list[str] = []
    if r.cvss:
        parts.append(f"CVSS {escape(r.cvss)}")
    if r.epss:
        parts.append(f"EPSS {escape(r.epss)}")
    if r.kev:
        parts.append("[bold yellow]★ exploited in the wild (CISA KEV)[/bold yellow]")
    return " · ".join(parts)


def _is_meaningful_code_change(text: str) -> bool:
    return bool(text.strip()) and "not directly imported" not in text.lower()


def render_table(ranked: list[RankedCVE]) -> None:
    if not ranked:
        console.print("[green]✓ No vulnerabilities found.[/green]")
        return

    n = len(ranked)
    console.print(
        f"\n[bold cyan]vulntriage — CVE Priority Report[/bold cyan]   "
        f"[dim]({n} finding{'s' if n != 1 else ''}, highest priority first)[/dim]\n"
    )

    for r in ranked:
        colour = RISK_COLOURS.get(r.real_risk, "white")
        kev_badge = "  [bold yellow]★ CISA KEV[/bold yellow]" if r.kev else ""
        header = (
            f"[{colour}]#{r.rank}  {escape(r.real_risk)}[/{colour}]  "
            f"[bold]{escape(r.cve.package)} {escape(r.cve.installed_version)}[/bold]"
            f"{kev_badge}"
        )
        console.print(Rule(header, align="left", style=colour))

        card = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2, 0, 0))
        card.add_column(style="bold dim", width=9, no_wrap=True)
        card.add_column(overflow="fold")

        card.add_row("CVE", f"[bold]{escape(r.cve.id)}[/bold]")
        if r.reasoning.strip():
            card.add_row("Why", escape(r.reasoning))
        card.add_row("Fix", _fix_line(r))
        if r.breaking_changes.strip():
            card.add_row("Breaking", f"[yellow]{escape(r.breaking_changes)}[/yellow]")
        if _is_meaningful_code_change(r.code_changes):
            card.add_row("Code", f"[dim]{escape(r.code_changes)}[/dim]")
        severity = _severity_line(r)
        if severity:
            card.add_row("Severity", severity)

        console.print(card)
        console.print()

    if any(not r.cvss for r in ranked):
        console.print(
            "[dim]Note: CVSS/EPSS shown only where available — "
            "run without --offline to fetch authoritative scores from NVD.[/dim]"
        )


def render_json(ranked: list[RankedCVE]) -> None:
    payload = json.dumps(
        [
            {
                "rank": r.rank,
                "id": r.cve.id,
                "package": r.cve.package,
                "installed_version": r.cve.installed_version,
                "min_fix_version": min_fix_version(r.cve.fix_versions) or "",
                "real_risk": r.real_risk,
                "cvss": r.cvss,
                "kev": r.kev,
                "epss": r.epss,
                "reasoning": r.reasoning,
                "fix_command": r.fix_command,
                "breaking_changes": r.breaking_changes,
                "code_changes": r.code_changes,
            }
            for r in ranked
        ],
        indent=2,
    )
    try:
        print(payload)
        sys.stdout.flush()
    except BrokenPipeError:
        # SIGPIPE handler in cli.py handles this on Unix; this branch covers
        # Windows (no SIGPIPE) and direct library use without the CLI entry.
        pass


def determine_exit_code(ranked: list[RankedCVE], fail_on: str = "HIGH") -> int:
    threshold = SEVERITY[fail_on]
    return 1 if any(SEVERITY[r.real_risk] >= threshold for r in ranked) else 0


def save_report(
    ranked: list[RankedCVE],
    metadata: dict[str, object],
    output_dir: Path,
) -> Path:
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"vulntriage-{timestamp}.json"
    report: dict[str, object] = {
        "timestamp": timestamp,
        **metadata,
        "results": [
            {
                "rank": r.rank,
                "id": r.cve.id,
                "package": r.cve.package,
                "installed_version": r.cve.installed_version,
                "min_fix_version": min_fix_version(r.cve.fix_versions) or "",
                "real_risk": r.real_risk,
                "cvss": r.cvss,
                "kev": r.kev,
                "epss": r.epss,
                "reasoning": r.reasoning,
                "fix_command": r.fix_command,
                "breaking_changes": r.breaking_changes,
                "code_changes": r.code_changes,
            }
            for r in ranked
        ],
    }
    path.write_text(json.dumps(report, indent=2))
    return path
