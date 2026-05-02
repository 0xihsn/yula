"""
Async token bucket rate limiter for controlling request throughput.

The token bucket algorithm allows bursts up to `concurrency` simultaneous
requests, while the long-run average is capped to `requests_per_minute`.

How it works:
  - A semaphore gates concurrent requests to `concurrency` at a time.
  - Between acquisitions, we enforce a minimum inter-request interval of
    60 / requests_per_minute seconds to smooth out the rate.
  - This means: if you set concurrency=5 and rpm=60, up to 5 requests fire
    simultaneously at the start, then each new request waits at least 1s
    from the previous one.

Thread safety: this class is not thread-safe (it's designed for asyncio).
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket rate limiter.

    Attributes:
        requests_per_minute: Maximum average request rate.
        concurrency: Maximum simultaneous in-flight requests.
    """

    def __init__(self, requests_per_minute: int, concurrency: int) -> None:
        """Initialise the rate limiter.

        Args:
            requests_per_minute: Maximum average requests per minute.
            concurrency: Maximum simultaneous requests allowed.
        """
        self.requests_per_minute = requests_per_minute
        self.concurrency = concurrency
        # Minimum seconds between releasing requests into the pipeline
        self._min_interval: float = 60.0 / max(requests_per_minute, 1)
        self._semaphore = asyncio.Semaphore(concurrency)
        self._last_release: float = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to send one request.

        Waits until:
          1. A concurrency slot is available (semaphore)
          2. The minimum inter-request interval has elapsed (rate limit)

        This method is a coroutine and must be awaited.
        """
        # Enforce inter-request interval before acquiring the semaphore
        # Use a lock so only one coroutine calculates the sleep at a time
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_release
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_release = time.monotonic()

        # Then acquire a concurrency slot
        await self._semaphore.acquire()

    def release(self) -> None:
        """Release a concurrency slot after a request completes."""
        self._semaphore.release()
