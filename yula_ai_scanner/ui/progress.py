"""
Streaming CLI progress display for the scan execution.

Prints a header on enter, streams one styled line per result, and prints a
findings summary on exit. A Rich Progress bar updates inline at the bottom
during the scan.

No alt-screen, no Layout — works reliably in any terminal including
embedded IDE panes that Rich's TTY detection mis-identifies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from yula_ai_scanner.config.scan_schema import VisibilityLevel
from yula_ai_scanner.reporting.severity import (
    SEVERITY_COLORS,
    SeverityRating,
    compute_severity,
)

if TYPE_CHECKING:
    from yula_ai_scanner.engine.executor import TestResult


_LOG_MODE_LABELS: dict[VisibilityLevel, str] = {
    VisibilityLevel.PUBLIC: "vulnerable findings only (-v)",
    VisibilityLevel.INTERNAL: "all tested templates (-vv)",
    VisibilityLevel.CONFIDENTIAL: "full detail",
    VisibilityLevel.DEBUG: "full prompt + response + evaluation (-vvv)",
}


def _http_style(code: int) -> str:
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "bold cyan"
    if 400 <= code < 500:
        return "bold yellow"
    if 500 <= code < 600:
        return "bold red"
    return "bold white"


class ScanProgress:
    """Streaming CLI progress display for the scan execution.

    Public API:
        with ScanProgress(...) as progress:
            ...
            progress.update(result)

    The `is_paused` attribute is kept (always False) for backwards
    compatibility with the executor's defensive `getattr` check.
    """

    is_paused: bool = False

    def __init__(
        self,
        total: int,
        visibility: VisibilityLevel,
        target_url: str = "",
        auth_type: str = "",
        template_count: int = 0,
        console: Console | None = None,
    ) -> None:
        self.total = total
        self.visibility = visibility
        self.target_url = target_url
        self.auth_type = auth_type
        self.template_count = template_count
        self.console = console or Console()

        self._start_time = datetime.now(timezone.utc)
        self._counters: dict[str, int] = {s.value: 0 for s in SeverityRating}
        self._completed = 0

        self._progress = Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bold cyan]{task.description}[/bold cyan]"),
            BarColumn(bar_width=40, style="dim cyan", complete_style="bright_cyan"),
            MofNCompleteColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[dim]·[/dim]"),
            TimeElapsedColumn(),
            TextColumn("[dim]· ETA[/dim]"),
            TimeRemainingColumn(),
            console=self.console,
            transient=False,
        )
        self._task_id = self._progress.add_task("Scanning", total=total)

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "ScanProgress":
        self._print_header()
        self._progress.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._progress.stop()
        self._print_summary()

    # ── Public API ────────────────────────────────────────────────────────────

    def update(self, result: "TestResult") -> None:
        """Record one result, advance the bar, and stream a line above it."""
        self._completed += 1
        self._progress.advance(self._task_id)

        if result.status == "vulnerable":
            severity = compute_severity(result)
            self._counters[severity.value] = self._counters.get(severity.value, 0) + 1
        elif result.status == "safe":
            self._counters[SeverityRating.SAFE.value] = (
                self._counters.get(SeverityRating.SAFE.value, 0) + 1
            )
        else:
            self._counters[SeverityRating.INFO.value] = (
                self._counters.get(SeverityRating.INFO.value, 0) + 1
            )

        if self.visibility == VisibilityLevel.PUBLIC and result.status != "vulnerable":
            return

        self._progress.console.print(self._format_result(result))

        if self.visibility == VisibilityLevel.DEBUG:
            self._print_debug_detail(result)

    # ── Render helpers ────────────────────────────────────────────────────────

    def _print_debug_detail(self, result: "TestResult") -> None:
        """Print full prompt, full response, and evaluation for one result.

        Used at -vvv (DEBUG) verbosity.
        """
        c = self._progress.console
        p = result.payload

        c.print(Text("  ─ Prompt ─────────────────────────────", style="dim cyan"))
        c.print(Text(p.prompt, style="white"), overflow="fold")

        c.print(Text("  ─ Response ───────────────────────────", style="dim cyan"))
        if result.response is not None:
            c.print(Text(result.response, style="bright_white"), overflow="fold")
        else:
            c.print(Text("(no response)", style="dim italic"))

        c.print(Text("  ─ Evaluation ─────────────────────────", style="dim cyan"))
        eval_table = Table.grid(padding=(0, 2))
        eval_table.add_column(style="dim", no_wrap=True, min_width=14)
        eval_table.add_column(style="bright_white", overflow="fold")
        eval_table.add_row("Status", result.status)
        eval_table.add_row("Confidence", f"{result.confidence:.2f}")
        eval_table.add_row(
            "Matched signals",
            ", ".join(result.matched_signals) if result.matched_signals else "—",
        )
        eval_table.add_row("Template", p.template_id or "—")
        eval_table.add_row("Template name", p.template_name or "—")
        eval_table.add_row("Intent", p.intent_id or "—")
        eval_table.add_row("Technique", p.technique_id or "—")
        eval_table.add_row("Evasion", p.evasion_id or "—")
        if result.http_status is not None:
            eval_table.add_row("HTTP status", str(result.http_status))
        eval_table.add_row("Duration", f"{result.duration_ms:.0f} ms")
        if result.error_message:
            eval_table.add_row("Error", result.error_message)
        c.print(eval_table)
        c.print()

    def _print_header(self) -> None:
        c = self.console
        c.print()
        c.rule(
            "[bold bright_cyan]◈ YULA AI Scanner — scan started[/bold bright_cyan]",
            style="bright_cyan",
        )

        info = Table.grid(padding=(0, 2))
        info.add_column(style="dim", no_wrap=True, min_width=11)
        info.add_column(style="bright_white", overflow="fold")
        info.add_row("Target", self.target_url or "—")
        info.add_row("Auth", self.auth_type or "—")
        info.add_row(
            "Visibility",
            f"{self.visibility.value.upper()}  "
            f"[dim]· {_LOG_MODE_LABELS[self.visibility]}[/dim]",
        )
        info.add_row("Templates", str(self.template_count))
        info.add_row("Payloads", f"{self.total:,}")
        c.print(info)
        c.rule(style="dim cyan")
        c.print()

    def _print_summary(self) -> None:
        c = self.console
        elapsed = int((datetime.now(timezone.utc) - self._start_time).total_seconds())
        minutes, seconds = divmod(elapsed, 60)
        elapsed_str = f"{minutes}m {seconds:02d}s" if minutes else f"{seconds}s"

        total_vulns = sum(
            self._counters.get(sev.value, 0)
            for sev in (
                SeverityRating.CRITICAL,
                SeverityRating.HIGH,
                SeverityRating.MEDIUM,
                SeverityRating.LOW,
            )
        )

        c.print()
        c.rule(
            "[bold bright_cyan]◈ Findings[/bold bright_cyan]",
            style="bright_cyan",
        )

        table = Table.grid(padding=(0, 4))
        table.add_column(no_wrap=True, min_width=12)
        table.add_column(justify="right", min_width=6)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "INFO"):
            count = self._counters.get(sev, 0)
            try:
                color = SEVERITY_COLORS[SeverityRating(sev)]
            except ValueError:
                color = "white"
            style = f"bold {color}" if count > 0 else "dim"
            table.add_row(Text(sev, style=style), Text(str(count), style=style))

        table.add_row(Text(""), Text(""))
        vuln_style = "bold red" if total_vulns > 0 else "dim"
        table.add_row(
            Text("VULNS", style=vuln_style),
            Text(str(total_vulns), style=vuln_style),
        )
        table.add_row(
            Text("Elapsed", style="dim"),
            Text(elapsed_str, style="dim"),
        )
        c.print(table)
        c.rule(style="dim cyan")

    def _format_result(self, result: "TestResult") -> Text:
        """Format one result as a single-line styled row."""
        text = Text()
        ts = datetime.now().strftime("%H:%M:%S")
        text.append(f"{ts} ", style="dim")

        if result.status == "vulnerable":
            severity = compute_severity(result)
            color = SEVERITY_COLORS[severity]
            text.append(f" {severity.value:^8} ", style=f"bold reverse {color}")
        elif result.status == "safe":
            text.append("   SAFE   ", style="bold reverse green")
        elif result.status == "timeout":
            text.append(" TIMEOUT  ", style="bold reverse yellow")
        else:
            text.append("  ERROR   ", style="bold reverse red")

        text.append("  ")

        label = result.payload.template_name or result.payload.label

        if self.visibility == VisibilityLevel.DEBUG:
            if result.http_status is not None:
                text.append(
                    f"HTTP {result.http_status} ",
                    style=_http_style(result.http_status),
                )
            label_style = (
                "bright_white" if result.status == "vulnerable" else "dim"
            )
            text.append(f"{label[:48]}", style=label_style)
            if result.status == "vulnerable":
                text.append(f"  conf={result.confidence:.2f}", style="bold cyan")
                if result.matched_signals:
                    sigs = ", ".join(result.matched_signals[:2])
                    text.append(f"  [{sigs}]", style="dim magenta")
            text.append(f"  {result.duration_ms:.0f}ms", style="dim")

        elif self.visibility == VisibilityLevel.CONFIDENTIAL:
            label_style = (
                "bright_white" if result.status == "vulnerable" else "dim"
            )
            text.append(f"{label[:60]}", style=label_style)
            if result.status == "vulnerable":
                text.append(f"  conf={result.confidence:.2f}", style="bold cyan")
                if result.matched_signals:
                    sigs = ", ".join(result.matched_signals[:3])
                    text.append(f"  [{sigs}]", style="dim magenta")
            text.append(f"  {result.duration_ms:.0f}ms", style="dim")

        elif self.visibility == VisibilityLevel.INTERNAL:
            label_style = (
                "bright_white" if result.status == "vulnerable" else "dim"
            )
            text.append(f"{label[:72]}", style=label_style)
            if result.status == "vulnerable":
                text.append(f"  conf={result.confidence:.2f}", style="bold cyan")

        else:  # PUBLIC — only vulnerable reach here
            text.append(f"{label[:72]}", style="bright_white")
            text.append(f"  conf={result.confidence:.2f}", style="bold cyan")

        return text
