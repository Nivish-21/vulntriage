import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
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


def render_table(ranked: list[RankedCVE]) -> None:
    if not ranked:
        console.print("[green]✓ No vulnerabilities found.[/green]")
        return
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        title="[bold]vulntriage — CVE Priority Report[/bold]",
        title_style="bold cyan",
    )
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("CVE / PYSEC ID", style="bold", min_width=18)
    table.add_column("Package", min_width=12)
    table.add_column("Risk", min_width=8)
    table.add_column("CVSS", style="dim", min_width=5)
    table.add_column("EPSS", style="dim", min_width=6)
    table.add_column("Min Fix", style="cyan", min_width=10)
    table.add_column("Reasoning", min_width=30)
    table.add_column("Fix", style="green", min_width=25)
    table.add_column("Breaking Changes", style="yellow", min_width=25)
    table.add_column("Code Changes", style="dim", min_width=25)
    for r in ranked:
        colour = RISK_COLOURS.get(r.real_risk, "white")
        cve_cell = r.cve.id
        if r.kev:
            cve_cell = f"{r.cve.id}\n[bold yellow]★ CISA KEV[/bold yellow]"
        mfv = min_fix_version(r.cve.fix_versions)
        min_fix_cell = f">= {mfv}" if mfv else "no fix"
        table.add_row(
            str(r.rank),
            cve_cell,
            f"{r.cve.package} {r.cve.installed_version}",
            f"[{colour}]{r.real_risk}[/{colour}]",
            escape(r.cvss) if r.cvss else "—",
            escape(r.epss) if r.epss else "—",
            min_fix_cell,
            escape(r.reasoning),
            escape(r.fix_command),
            escape(r.breaking_changes),
            escape(r.code_changes),
        )
    console.print(table)
    if any(not r.cvss for r in ranked):
        console.print(
            "[dim]Note: CVSS scores marked '—' are unavailable. "
            "Run without --offline to fetch authoritative scores from NVD.[/dim]"
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
