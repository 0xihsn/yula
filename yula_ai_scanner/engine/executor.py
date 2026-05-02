"""
Test executor: orchestrates async execution of all attack payloads.

The TestExecutor is the core of the scan engine. It:
  1. Takes the full list of AttackPayload objects from the matrix builder
  2. Sends each one through the configured adapter (OpenAI/Anthropic/Custom/Web)
  3. Passes each response through the VulnerabilityAnalyzer
  4. Builds TestResult objects with full metadata
  5. Updates the live progress display
  6. Logs results at the appropriate verbosity level

Concurrency model:
  - API targets: uses asyncio.gather with a semaphore-gated wrapper to run
    up to `concurrency` requests in flight simultaneously.
  - Webpage targets: always runs sequentially (concurrency=1) because there
    is only one browser and one page — parallel execution is not possible.

Error handling:
  - Transient network errors are retried by the retry decorator.
  - Per-test exceptions are caught and recorded as status="error" — they
    never abort the scan. The test continues with the next payload.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel

from yula_ai_scanner.config.scan_schema import ScanConfig
from yula_ai_scanner.config.target_schema import TargetConfig, WebpageEndpointConfig
from yula_ai_scanner.engine.adapters import get_adapter
from yula_ai_scanner.engine.adapters.base import BaseAdapter
from yula_ai_scanner.engine.http_log import print_exchange
from yula_ai_scanner.engine.rate_limiter import RateLimiter
from yula_ai_scanner.engine.retry import make_retry_decorator
from yula_ai_scanner.taxonomy.models import AttackPayload

if TYPE_CHECKING:
    from yula_ai_scanner.detection.analyzer import VulnerabilityAnalyzer
    from yula_ai_scanner.ui.progress import ScanProgress

logger = logging.getLogger("yula_ai_scanner.executor")


class TestResult(BaseModel):
    """Complete record of one executed attack test.

    Attributes:
        payload: The attack payload that was sent.
        response: AI response text (None on timeout/connection error).
        raw_response: Full JSON response body (for CONFIDENTIAL reports).
        status: Outcome of the test.
        confidence: Vulnerability confidence score [0.0, 1.0].
        matched_signals: Names of detection signals that fired.
        duration_ms: Wall-clock time for the request in milliseconds.
        timestamp: UTC timestamp when the test was executed.
        http_status: HTTP status code (None for web adapter tests).
        error_message: Error description (set when status="error").
        finish_reason: Normalised stop reason from the model (forwarded
            from the adapter): "stop"|"length"|"content_filter"|None.
            None for adapters that cannot observe it.
    """

    payload: AttackPayload
    response: str | None = None
    raw_response: str | None = None
    status: Literal["vulnerable", "safe", "error", "timeout"] = "safe"
    confidence: float = 0.0
    matched_signals: list[str] = []
    duration_ms: float = 0.0
    timestamp: datetime = None  # type: ignore[assignment]
    http_status: int | None = None
    error_message: str | None = None
    finish_reason: str | None = None

    model_config = {"arbitrary_types_allowed": True}

    def model_post_init(self, __context: object) -> None:
        """Set timestamp to now if not provided."""
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.now(timezone.utc))


class TestExecutor:
    """Orchestrates async execution of all attack payloads against a target.

    Attributes:
        scan_config: Scan settings (concurrency, rate limit, retries, etc.).
        target_config: Target definition (endpoint type, auth, etc.).
        analyzer: VulnerabilityAnalyzer instance for scoring responses.
    """

    def __init__(
        self,
        scan_config: ScanConfig,
        target_config: TargetConfig,
        analyzer: "VulnerabilityAnalyzer",
    ) -> None:
        """Initialise the executor.

        Args:
            scan_config: The loaded scan configuration.
            target_config: The loaded target configuration.
            analyzer: Initialised VulnerabilityAnalyzer.
        """
        self.scan_config = scan_config
        self.target_config = target_config
        self.analyzer = analyzer

        settings = scan_config.scan

        # Web targets must be sequential — one browser, one page
        is_web = isinstance(target_config.endpoint, WebpageEndpointConfig)
        effective_concurrency = 1 if is_web else settings.concurrency

        self._rate_limiter = RateLimiter(
            requests_per_minute=settings.requests_per_minute,
            concurrency=effective_concurrency,
        )
        self._retry = make_retry_decorator(settings.max_retries)
        self._timeout = settings.timeout_seconds

    async def run_all(
        self,
        payloads: list[AttackPayload],
        progress: "ScanProgress",
    ) -> list[TestResult]:
        """Execute all attack payloads and return the results.

        Creates one adapter, sets it up, runs all tests, then tears it down.

        Args:
            payloads: List of attack payloads from the matrix builder.
            progress: Live progress display (updated after each test).

        Returns:
            List of TestResult objects (one per payload).
        """
        adapter = get_adapter(self.target_config, self._timeout)

        results: list[TestResult] = []

        async with adapter:
            # Wrap the send methods with the retry decorator.
            retried_send = self._retry(adapter.send)
            retried_send_turns = self._retry(adapter.send_turns)

            # Web targets: sequential. API targets: concurrent via gather.
            is_web = isinstance(self.target_config.endpoint, WebpageEndpointConfig)

            if is_web:
                for payload in payloads:
                    result = await self._run_one(
                        payload, retried_send, retried_send_turns, progress
                    )
                    results.append(result)
                    progress.update(result)
            else:
                tasks = [
                    self._run_one(payload, retried_send, retried_send_turns, progress)
                    for payload in payloads
                ]
                for future in asyncio.as_completed(tasks):
                    result = await future
                    results.append(result)
                    progress.update(result)

        return results

    async def _run_one(
        self,
        payload: AttackPayload,
        send_fn: object,
        send_turns_fn: object | None = None,
        progress: "ScanProgress | None" = None,
    ) -> TestResult:
        """Execute a single attack payload.

        Sequential payloads (those with `followup_prompts`) are routed through
        `send_turns_fn`, which threads the full ordered turn list through ONE
        adapter invocation (preserving conversation history). Single-turn
        payloads use `send_fn` as before.
        """
        # Pause point: block before acquiring a rate-limiter slot.
        # Uses `is True` identity so MagicMock stubs in tests are never truthy here.
        if getattr(progress, "is_paused", False) is True:
            while getattr(progress, "is_paused", False) is True:
                await asyncio.sleep(0.05)

        await self._rate_limiter.acquire()
        try:
            start_ms = time.monotonic() * 1000

            logger.debug(
                "Sending payload",
                extra={
                    "intent": payload.intent_id,
                    "technique": payload.technique_id,
                    "evasion": payload.evasion_id,
                    "prompt_length": len(payload.prompt),
                    "turns": 1 + len(payload.followup_prompts),
                },
            )

            if payload.is_sequential and send_turns_fn is not None:
                adapter_response = await send_turns_fn(payload.all_turns)
            else:
                adapter_response = await send_fn(payload.prompt)

            status, confidence, signals = self.analyzer.analyze(
                payload,
                adapter_response.text,
                turn_texts=adapter_response.turn_texts or None,
                finish_reason=adapter_response.finish_reason,
            )

            logger.debug(
                "Test complete: %s (confidence=%.2f)",
                status,
                confidence,
                extra={
                    "intent": payload.intent_id,
                    "status": status,
                    "signals": signals,
                },
            )

            if status == "vulnerable":
                for exchange in adapter_response.exchanges:
                    print_exchange(exchange)

            return TestResult(
                payload=payload,
                response=adapter_response.text,
                raw_response=adapter_response.raw_body,
                status=status,
                confidence=confidence,
                matched_signals=signals,
                duration_ms=adapter_response.duration_ms,
                http_status=adapter_response.http_status,
                finish_reason=adapter_response.finish_reason,
            )

        except asyncio.TimeoutError:
            logger.warning("Timeout on payload: %s", payload.intent_id)
            return TestResult(
                payload=payload,
                status="timeout",
                error_message="Request timed out",
                duration_ms=time.monotonic() * 1000 - start_ms,
            )
        except Exception as exc:
            logger.warning(
                "Error on payload %s: %s",
                payload.intent_id,
                str(exc),
            )
            return TestResult(
                payload=payload,
                status="error",
                error_message=str(exc),
                duration_ms=time.monotonic() * 1000 - start_ms,
            )
        finally:
            self._rate_limiter.release()
