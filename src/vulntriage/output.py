from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from vulntriage.models import RankedCVE

RISK_COLOURS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
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
    table.add_column("Reasoning", min_width=30)
    table.add_column("Fix", style="green", min_width=25)
    for r in ranked:
        colour = RISK_COLOURS.get(r.real_risk, "white")
        table.add_row(
            str(r.rank),
            r.cve.id,
            f"{r.cve.package} {r.cve.installed_version}",
            f"[{colour}]{r.real_risk}[/{colour}]",
            escape(r.reasoning),
            escape(r.fix_command),
        )
    console.print(table)


def determine_exit_code(ranked: list[RankedCVE]) -> int:
    return 1 if any(r.real_risk in {"CRITICAL", "HIGH"} for r in ranked) else 0
