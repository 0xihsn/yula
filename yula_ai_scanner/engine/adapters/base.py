"""
Abstract base adapter and response model for all target adapters.

All adapters share the same interface so the executor can work with any
target type (OpenAI, Anthropic, custom API, web page) through a single call.

The lifecycle is:
  1. setup()   — one-time initialization (connection pool, browser launch)
  2. send()    — called once per attack payload
  3. teardown()— cleanup after all tests complete

Adapters must be used as async context managers or have setup/teardown called
explicitly. The executor handles this lifecycle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel


class AdapterResponse(BaseModel):
    """Structured response returned by any adapter.

    For single-turn calls `text` is the assistant reply and `turn_texts` is empty.
    For multi-turn calls (`send_turns`) `text` is the joined transcript of every
    assistant reply and `turn_texts` carries the per-turn assistant replies in
    order — used for per-turn analysis.

    Attributes:
        text: Extracted response text (joined for multi-turn).
        http_status: HTTP status code of the LAST request (None for web adapter).
        raw_body: Raw JSON of the LAST response body (None if not applicable).
        duration_ms: Total wall-clock time across all turns in milliseconds.
        turn_texts: Per-turn assistant replies (empty for single-turn calls).
        exchanges: Per-turn HTTP exchange records (one per request). Used by
            the executor to print request/response detail conditionally.
        finish_reason: Normalised stop reason from the model — "stop" |
            "length" | "content_filter" | None. For multi-turn this is the
            LAST turn's reason. None for adapters that cannot observe it
            (web, custom). Lets the analyzer distinguish a model that
            complied from one cut off by max_tokens.
    """

    text: str
    http_status: int | None = None
    raw_body: str | None = None
    duration_ms: float = 0.0
    turn_texts: list[str] = []
    exchanges: list[dict[str, Any]] = []
    finish_reason: str | None = None


class BaseAdapter(ABC):
    """Abstract base class for all YULA AI Scanner target adapters.

    Subclasses implement the three lifecycle methods below. The executor
    calls setup() once, then send() for each payload, then teardown().
    """

    @abstractmethod
    async def setup(self) -> None:
        """Perform one-time setup before sending any payloads.

        Examples: create httpx.AsyncClient, launch Playwright browser,
        validate connectivity to the target endpoint.

        Raises:
            Any exception indicating the target is unreachable or misconfigured.
        """

    @abstractmethod
    async def send(self, prompt: str) -> AdapterResponse:
        """Send one attack prompt to the target and return the response.

        Args:
            prompt: The attack payload string to send.

        Returns:
            AdapterResponse with the AI's response text and metadata.

        Raises:
            httpx.TimeoutException: On request timeout.
            httpx.ConnectError: On connection failure.
            AdapterError: On any adapter-specific error.
        """

    @abstractmethod
    async def teardown(self) -> None:
        """Clean up resources after all tests complete.

        Examples: close httpx.AsyncClient, close Playwright browser.
        This method should not raise exceptions — log and swallow them.
        """

    async def send_turns(self, turns: list[str]) -> AdapterResponse:
        """Send a multi-turn conversation, returning the joined transcript.

        Default implementation calls `send` per turn with NO shared history —
        suitable as a graceful fallback only. Adapters that natively support
        message history (OpenAI, Anthropic, etc.) override this to thread the
        full conversation through a single accumulating `messages` list.

        Args:
            turns: Ordered list of user-side prompts (turn 1 .. turn N).

        Returns:
            AdapterResponse where `text` is the joined assistant transcript
            and `turn_texts` is the per-turn assistant replies.
        """
        if not turns:
            return AdapterResponse(text="", turn_texts=[])
        if len(turns) == 1:
            return await self.send(turns[0])

        replies: list[str] = []
        last: AdapterResponse | None = None
        total_duration = 0.0
        for prompt in turns:
            last = await self.send(prompt)
            replies.append(last.text)
            total_duration += last.duration_ms
        assert last is not None
        return AdapterResponse(
            text="\n---\n".join(replies),
            http_status=last.http_status,
            raw_body=last.raw_body,
            duration_ms=total_duration,
            turn_texts=replies,
            finish_reason=last.finish_reason,
        )

    async def __aenter__(self) -> "BaseAdapter":
        """Support usage as an async context manager."""
        await self.setup()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Ensure teardown is always called."""
        await self.teardown()


class AdapterError(Exception):
    """Raised when an adapter encounters a non-retriable error."""


# Mapping from each provider's native stop-reason vocabulary to a small
# normalised set used by the analyzer. Anything unknown maps to None.
_FINISH_REASON_MAP: dict[str, str] = {
    # OpenAI / vLLM / Ollama / LM Studio / Together / Groq / Fireworks
    "stop": "stop",
    "length": "length",
    "content_filter": "content_filter",
    "tool_calls": "stop",
    "function_call": "stop",
    # Anthropic
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "tool_use": "stop",
    # Gemini (uppercase)
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "OTHER": None,
    # Cohere v2 (uppercase)
    "COMPLETE": "stop",
    "STOP_SEQUENCE": "stop",
    "ERROR": None,
    "ERROR_TOXIC": "content_filter",
    "ERROR_LIMIT": "length",
    "USER_CANCEL": None,
}


def normalise_finish_reason(raw: str | None) -> str | None:
    """Map a provider-native stop reason to one of "stop"|"length"|"content_filter"|None.

    None passes through (used by adapters that cannot observe the field).
    Unknown values map to None so the analyzer treats them as no-signal.
    """
    if raw is None:
        return None
    return _FINISH_REASON_MAP.get(raw, _FINISH_REASON_MAP.get(raw.lower()))
