"""
Reusable Rich panel and table helpers for the YULA AI Scanner terminal UI.

These helpers ensure a consistent visual style across all UI components.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from yula_ai_scanner.reporting.severity import SEVERITY_COLORS, SeverityRating


def make_results_summary(
    severity_counts: dict[str, int],
    total: int,
    duration: float,
    report_path: str,
) -> Panel:
    """Create a final scan summary panel.

    Args:
        severity_counts: Dict of severity → count.
        total: Total payloads tested.
        duration: Scan duration in seconds.
        report_path: Path where the report was saved.

    Returns:
        Rich Panel with the final summary.
    """
    table = Table.grid(padding=(0, 3))
    table.add_column("Severity", no_wrap=True)
    table.add_column("Count", justify="right")

    for severity in (
        SeverityRating.CRITICAL, SeverityRating.HIGH, SeverityRating.MEDIUM,
        SeverityRating.LOW, SeverityRating.INFO, SeverityRating.SAFE,
    ):
        count = severity_counts.get(severity.value, 0)
        if count > 0 or severity == SeverityRating.SAFE:
            color = SEVERITY_COLORS[severity]
            table.add_row(
                f"[{color}]{severity.value}[/{color}]",
                f"[{color}]{count}[/{color}]",
            )

    table.add_row("", "")
    table.add_row("[dim]Total Tested[/dim]", f"[bold]{total:,}[/bold]")
    table.add_row("[dim]Duration[/dim]", f"[bold]{duration:.1f}s[/bold]")
    table.add_row("[dim]Report[/dim]", f"[link={report_path}]{report_path}[/link]")

    return Panel(
        table,
        title="[bold bright_cyan]Scan Complete[/bold bright_cyan]",
        border_style="bright_cyan",
        padding=(1, 2),
    )
