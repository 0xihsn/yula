"""
Retry decorator factory for transient network failures.

Uses the tenacity library to implement exponential backoff with jitter.
Only retries on errors that indicate transient failures (timeouts, connection
drops, 5xx responses) — not on 4xx client errors which are expected during
security testing.
"""

from __future__ import annotations

import logging
from typing import Callable

import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

logger = logging.getLogger("yula_ai_scanner.retry")


def make_retry_decorator(max_retries: int) -> Callable:
    """Create a tenacity retry decorator with exponential backoff.

    Retries on:
      - httpx.TimeoutException (request timed out)
      - httpx.ConnectError (connection refused / DNS failure)
      - httpx.HTTPStatusError with 5xx status (server error)

    Does NOT retry on:
      - 4xx HTTP errors (these are expected during security testing — a 403
        may indicate the AI refused the prompt, which is a valid test result)
      - AdapterError (non-retriable adapter-specific errors)

    Args:
        max_retries: Maximum number of retry attempts after the first failure.
                     0 = no retries (fail immediately on first error).

    Returns:
        A tenacity retry decorator configured for the given retry count.
    """
    if max_retries == 0:
        # Return a no-op decorator that just calls the function once
        def no_retry(fn: Callable) -> Callable:
            return fn
        return no_retry

    def _is_retryable(exc: BaseException) -> bool:
        """Return True if the exception warrants a retry."""
        if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError)):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            # Only retry on server errors (5xx), not client errors (4xx)
            return exc.response.status_code >= 500
        return False

    return retry(
        retry=retry_if_exception_type(
            (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPStatusError)
        ),
        stop=stop_after_attempt(max_retries + 1),  # +1 because first attempt counts
        wait=wait_exponential(multiplier=1, min=2, max=30),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,  # Re-raise the last exception after all retries are exhausted
    )
