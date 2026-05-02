"""
Pydantic models for scan configuration (scan.yaml).

This module defines the structure of the main scan configuration file.
Every field has a sensible default so users can start with a minimal config
and override only what they need.

Visibility levels control how much detail is shown in the live UI and written
to the final report — this is important for sharing results with different
audiences (public summaries vs. internal security reviews vs. full audits).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class VisibilityLevel(str, Enum):
    """Controls how much detail is shown in the UI and report.

    Attributes:
        PUBLIC: Pass/fail counts only — safe to share externally.
        INTERNAL: Categories, matched signals, recommendations — for internal teams.
        CONFIDENTIAL: Full payloads + full AI responses — for security auditors.
        DEBUG: TUI shows HTTP status + response excerpt per request; report includes
               full payloads + responses (same as CONFIDENTIAL in the report).
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    DEBUG = "debug"


class ScanSettings(BaseModel):
    """Runtime parameters for the scan execution.

    Attributes:
        visibility: How much detail to show/record.
        max_payloads: Optional cap on total payloads (None = unlimited).
        concurrency: Maximum number of in-flight requests at any time.
        requests_per_minute: Token bucket rate limit for API calls.
        timeout_seconds: Per-request HTTP timeout.
        max_retries: Number of retries on transient network errors.
    """

    visibility: VisibilityLevel = VisibilityLevel.INTERNAL
    max_payloads: int | None = None
    concurrency: int = Field(default=5, ge=1, le=50)
    requests_per_minute: int = Field(default=60, ge=1, le=1000)
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    max_retries: int = Field(default=3, ge=0, le=10)
    vulnerability_threshold: float = Field(default=0.5, ge=0.1, le=0.95)
    # When a template has its own matchers, also run the global signal bank
    # at this scaling factor (0.0 = disabled). The final confidence is
    # max(template_score, scale * signal_score).
    signals_blend: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("max_payloads", mode="before")
    @classmethod
    def allow_null_max_payloads(cls, v: object) -> int | None:
        """Accept null/None from YAML for unlimited payloads."""
        return None if v is None else int(v)  # type: ignore[arg-type]


class OutputConfig(BaseModel):
    """Where to write report and log files.

    Attributes:
        report_path: Output path for the Markdown report.
        log_file: Output path for the JSON-structured log file (None = no file log).
        log_level: Python logging level for console output.
    """

    report_path: str = "output/report.md"
    log_file: str | None = "output/yula-ai-scanner.log"
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Ensure log level is one of the standard Python logging levels."""
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}, got '{v}'")
        return v.upper()


class ScanConfig(BaseModel):
    """Root model for scan.yaml — the main user-facing configuration file.

    Attributes:
        scan: Runtime scan settings.
        output: Report and log file paths.
    """

    scan: ScanSettings = Field(default_factory=ScanSettings)
    output: OutputConfig = Field(default_factory=OutputConfig)
