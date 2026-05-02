"""Centralized HTTP request/response logger for all adapters.

Adapters call `record_exchange(...)` after each HTTP call. The exchange is
always written to the JSON file logger at DEBUG level (the file handler
configured in `logging_setup.py` always captures DEBUG). The same call also
returns the exchange dict so the adapter can attach it to its AdapterResponse,
letting the executor decide later whether to print it to the terminal.

Terminal printing modes:
  - print_to_terminal=True (-v / -vv / -vvv): executor explicitly calls
    print_exchange() for vulnerable findings.
  - print_all_exchanges=True (-vvvv): every recorded exchange is auto-printed
    immediately, including failed/timeout requests (record_failed_exchange).
    In this mode print_exchange becomes a no-op to prevent double-printing.

Failed requests (no response received — timeouts, connection errors) should
be reported via `record_failed_exchange(...)` so the user still sees what was
attempted.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from rich.console import Console
from rich.json import JSON

_logger = logging.getLogger("yula_ai_scanner.http")
_console: Console | None = None
_print_to_terminal: bool = False
_print_all_exchanges: bool = False


def configure(
    console: Console | None,
    print_to_terminal: bool,
    print_all_exchanges: bool = False,
) -> None:
    """Configure terminal printing. File logging is always on.

    Args:
        console: Rich Console used for terminal output.
        print_to_terminal: Enables explicit print_exchange() calls (vulnerable-only).
        print_all_exchanges: When True, every recorded exchange (success or
            failure) is auto-printed immediately. Set by `-vvvv`.
    """
    global _console, _print_to_terminal, _print_all_exchanges
    _console = console
    _print_to_terminal = print_to_terminal
    _print_all_exchanges = print_all_exchanges


def is_print_all_enabled() -> bool:
    """Return True when -vvvv auto-print mode is on."""
    return _print_all_exchanges


def record_exchange(
    method: str,
    url: str,
    request_headers: dict[str, str],
    request_body: Any,
    response_status: int | None,
    response_body: str | None,
    duration_ms: float,
) -> dict[str, Any]:
    """Always log the exchange to the file logger; return the exchange dict.

    The returned dict can be attached to AdapterResponse.exchanges so the
    executor can later print it conditionally. When `-vvvv` is active, the
    exchange is also printed to the terminal immediately.
    """
    exchange: dict[str, Any] = {
        "method": method,
        "url": url,
        "request_headers": dict(request_headers),
        "request_body": request_body,
        "response_status": response_status,
        "response_body": response_body,
        "duration_ms": duration_ms,
    }
    _logger.debug("HTTP exchange", extra=exchange)
    if _print_all_exchanges:
        _render_exchange(exchange)
    return exchange


def record_failed_exchange(
    method: str,
    url: str,
    request_headers: dict[str, str],
    request_body: Any,
    error: BaseException,
    duration_ms: float,
) -> dict[str, Any]:
    """Record a request that never received a response (timeout, connection error).

    Always written to the file log at WARNING. When `-vvvv` is active the
    request and the error are also printed to the terminal so the user sees
    exactly what was sent before the failure.
    """
    error_repr = f"{type(error).__name__}: {error}" if str(error) else type(error).__name__
    exchange: dict[str, Any] = {
        "method": method,
        "url": url,
        "request_headers": dict(request_headers),
        "request_body": request_body,
        "response_status": None,
        "response_body": None,
        "duration_ms": duration_ms,
        "error": error_repr,
    }
    _logger.warning("HTTP exchange failed", extra=exchange)
    if _print_all_exchanges:
        _render_exchange(exchange)
    return exchange


def print_exchange(exchange: dict[str, Any]) -> None:
    """Print one recorded exchange to the terminal if printing is enabled.

    No-op when `-vvvv` mode is on, since record_exchange already printed it.
    """
    if _print_all_exchanges:
        return
    if not (_print_to_terminal and _console is not None):
        return
    _render_exchange(exchange)


def _render_exchange(exchange: dict[str, Any]) -> None:
    """Render one exchange to the configured console."""
    if _console is None:
        return

    method = exchange.get("method", "")
    url = exchange.get("url", "")
    headers = exchange.get("request_headers") or {}
    request_body = exchange.get("request_body")
    status = exchange.get("response_status")
    response_body = exchange.get("response_body")
    duration_ms = float(exchange.get("duration_ms") or 0.0)
    error = exchange.get("error")

    _console.print(f"[bold cyan]→ {method} {url}[/bold cyan]")
    if headers:
        _console.print("[dim]Request headers:[/dim]")
        for k, v in headers.items():
            _console.print(f"  {k}: {v}")
    _console.print("[dim]Request body:[/dim]")
    _print_body(request_body)

    if error is not None:
        _console.print(
            f"[bold red]✗ FAILED ({duration_ms:.0f}ms): {error}[/bold red]"
        )
    else:
        _console.print(f"[bold cyan]← {status} ({duration_ms:.0f}ms)[/bold cyan]")
        _console.print("[dim]Response body:[/dim]")
        _print_body(response_body)
    _console.print()


def _print_body(body: Any) -> None:
    """Pretty-print a request/response body, with JSON highlighting when possible."""
    if _console is None:
        return
    if body is None or body == "":
        _console.print("[dim](no body)[/dim]")
        return
    if isinstance(body, (dict, list)):
        _console.print(JSON.from_data(body, indent=2))
        return
    if isinstance(body, str):
        stripped = body.strip()
        if stripped and stripped[0] in "{[":
            try:
                _console.print(JSON(stripped, indent=2))
                return
            except (ValueError, json.JSONDecodeError):
                pass
        _console.print(body)
        return
    _console.print(str(body))
