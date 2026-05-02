"""
YULA AI Scanner ASCII art banner displayed at startup and embedded in the TUI.
"""

from __future__ import annotations

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


_BANNER_LINES = (
    "██╗   ██╗██╗   ██╗██╗      █████╗ ",
    "╚██╗ ██╔╝██║   ██║██║     ██╔══██╗",
    " ╚████╔╝ ██║   ██║██║     ███████║",
    "  ╚██╔╝  ██║   ██║██║     ██╔══██║",
    "   ██║   ╚██████╔╝███████╗██║  ██║",
    "   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝",
)

_LOGO_COLOR = "bright_green"

_VERSION = "1.0.0"
_TAGLINE = "AI Vulnerability Scanner"
_CREATOR = "İhsan BILKAY"
_HANDLE = "0xIHSN"


def _render_logo() -> Text:
    """Render the YULA logo in solid neon-green hacker style."""
    logo = Text(justify="left", no_wrap=True)
    for line in _BANNER_LINES:
        logo.append(line + "\n", style=f"bold {_LOGO_COLOR}")
    return logo


def _render_info_grid(template_count: int | None) -> Table:
    """Render the info grid below the logo."""
    grid = Table.grid(padding=(0, 2), expand=False)
    grid.add_column(justify="right", style="dim")
    grid.add_column(justify="left")

    grid.add_row(
        "[green]▸ version[/green]",
        f"[bold bright_green]v{_VERSION}[/bold bright_green]  "
        f"[dim green]│[/dim green]  [bright_green]{_TAGLINE}[/bright_green]",
    )

    if template_count is not None:
        grid.add_row(
            "[green]▸ payloads[/green]",
            f"[bold bright_red]{template_count}[/bold bright_red] "
            f"[dim]attack vectors armed[/dim]",
        )

    grid.add_row(
        "[green]▸ Author[/green]",
        f"[bright_white]{_CREATOR}[/bright_white]  "
        f"[dim]::[/dim]  [bold bright_green]@{_HANDLE}[/bold bright_green]",
    )
    return grid


def make_banner_panel(template_count: int | None = None) -> Panel:
    """Full standalone banner panel for pre-scan and non-TUI commands."""
    logo = Align.center(_render_logo())
    rule = Text("[ " + "─" * 38 + " ]", style="dim green", justify="center")
    info = Align.center(_render_info_grid(template_count))
    status = Align.center(
        Text.from_markup(
            "[blink bright_green]●[/blink bright_green] [bright_green]ONLINE[/bright_green]   "
            "[bright_red]●[/bright_red] [bright_red]OFFENSIVE[/bright_red]   "
            "[bright_yellow]●[/bright_yellow] [bright_yellow]AI-NATIVE[/bright_yellow]"
        )
    )

    return Panel(
        Group(logo, rule, info, rule, status),
        border_style="bright_green",
        padding=(1, 4),
        title="[bold bright_green]▓▒░ YULA // AI SCANNER ░▒▓[/bold bright_green]",
        title_align="center",
        subtitle="[dim green italic]> offensive ai security testing :: cli_[/dim green italic]",
        subtitle_align="center",
    )


def render_banner(console: Console, template_count: int | None = None) -> None:
    """Render the YULA AI Scanner startup banner to the console."""
    console.print(make_banner_panel(template_count))
    console.print()
