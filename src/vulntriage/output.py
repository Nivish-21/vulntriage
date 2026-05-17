import json
from datetime import UTC, datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from vulntriage.models import RankedCVE, RiskLevel

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
    table.add_column("Reasoning", min_width=30)
    table.add_column("Fix", style="green", min_width=25)
    table.add_column("Breaking Changes", style="yellow", min_width=25)
    for r in ranked:
        colour = RISK_COLOURS.get(r.real_risk, "white")
        table.add_row(
            str(r.rank),
            r.cve.id,
            f"{r.cve.package} {r.cve.installed_version}",
            f"[{colour}]{r.real_risk}[/{colour}]",
            escape(r.cvss) if r.cvss else "—",
            escape(r.reasoning),
            escape(r.fix_command),
            escape(r.breaking_changes),
        )
    console.print(table)


def render_json(ranked: list[RankedCVE]) -> None:
    print(
        json.dumps(
            [
                {
                    "rank": r.rank,
                    "id": r.cve.id,
                    "package": r.cve.package,
                    "installed_version": r.cve.installed_version,
                    "real_risk": r.real_risk,
                    "cvss": r.cvss,
                    "reasoning": r.reasoning,
                    "fix_command": r.fix_command,
                    "breaking_changes": r.breaking_changes,
                }
                for r in ranked
            ],
            indent=2,
        )
    )


def determine_exit_code(ranked: list[RankedCVE], fail_on: RiskLevel = "HIGH") -> int:
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
                "real_risk": r.real_risk,
                "cvss": r.cvss,
                "reasoning": r.reasoning,
                "fix_command": r.fix_command,
                "breaking_changes": r.breaking_changes,
            }
            for r in ranked
        ],
    }
    path.write_text(json.dumps(report, indent=2))
    return path
