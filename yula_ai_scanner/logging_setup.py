"""
Structured logging configuration for YULA AI Scanner.

Two log handlers are configured:
  1. Console handler (Rich): Human-readable, colorized output. Log level is
     controlled by the scan config. Only shown at INFO and above by default.
  2. File handler (JSON): Machine-readable JSON lines written to the log file.
     Always written at DEBUG level for complete forensic records, regardless
     of the console log level. Each line is a valid JSON object.

The file log always captures full detail (payloads, responses, signal matches)
even when the console is set to a higher visibility level. This ensures
complete audit trails without cluttering the terminal output.

Usage:
    from yula_ai_scanner.logging_setup import setup_logging
    logger = setup_logging(level="INFO", log_file="output/yula-ai-scanner.log")
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


class _JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines for the file handler.

    Each log line is a complete JSON object on a single line, suitable
    for ingestion by log management systems (Datadog, Splunk, ELK, etc.).
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format one log record as a JSON string.

        Args:
            record: The Python logging LogRecord.

        Returns:
            JSON-encoded string (no trailing newline).
        """
        log_entry: dict = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include any extra fields attached to the record
        extra_fields = {
            k: v
            for k, v in record.__dict__.items()
            if k not in {
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            }
        }
        if extra_fields:
            log_entry["extra"] = extra_fields

        # Include exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    console: Console | None = None,
) -> logging.Logger:
    """Configure and return the root YULA AI Scanner logger.

    Args:
        level: Console log level (DEBUG/INFO/WARNING/ERROR).
               Controls what is shown in the terminal.
        log_file: Path to the JSON log file. If None, file logging is disabled.
                  Parent directories are created automatically.

    Returns:
        Configured logger for the 'yula_ai_scanner' namespace.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Clear any existing handlers on the package logger
    logger = logging.getLogger("yula_ai_scanner")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)  # Capture everything; handlers filter independently
    logger.propagate = False  # Don't bubble up to root logger

    # ── Console handler (Rich, colorized) ────────────────────────────────────
    console_handler = RichHandler(
        level=numeric_level,
        console=console,
        rich_tracebacks=True,
        markup=True,
        show_path=False,
        show_time=False,
    )
    console_handler.setFormatter(
        logging.Formatter("%(message)s")  # Rich handler formats the rest
    )
    logger.addHandler(console_handler)

    # ── File handler (JSON, always at DEBUG) ──────────────────────────────────
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(
            filename=str(file_path),
            encoding="utf-8",
            mode="a",  # Append — don't overwrite previous scan logs
        )
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_handler.setFormatter(_JsonFormatter())
        logger.addHandler(file_handler)

    return logger
