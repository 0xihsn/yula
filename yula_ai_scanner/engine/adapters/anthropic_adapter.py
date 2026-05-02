"""
Anthropic Messages API adapter.

Sends prompts to the Anthropic API using the /v1/messages endpoint format.

Request format:
  POST {url}
  Content-Type: application/json
  x-api-key: {api_key}
  anthropic-version: {version}

  {
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
    "system": "<system_prompt>",
    "messages": [{"role": "user", "content": "<prompt>"}]
  }

Response extraction: content[0].text
"""

from __future__ import annotations

import json
import time

import httpx

from yula_ai_scanner.config.target_schema import AnthropicEndpointConfig, AuthConfig
from yula_ai_scanner.engine.adapters.base import (
    AdapterError,
    AdapterResponse,
    BaseAdapter,
    normalise_finish_reason,
)
from yula_ai_scanner.engine.auth.provider import AuthProvider
from yula_ai_scanner.engine.http_log import record_exchange, record_failed_exchange


class AnthropicAdapter(BaseAdapter):
    """Adapter for the Anthropic Messages API.

    Attributes:
        endpoint: Anthropic endpoint configuration.
        auth_provider: Handles applying x-api-key headers.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: AnthropicEndpointConfig,
        auth: AuthConfig,
        timeout_seconds: int = 30,
    ) -> None:
        """Initialise the adapter.

        Args:
            endpoint: Anthropic endpoint configuration.
            auth: Authentication configuration (expects api_key type).
            timeout_seconds: HTTP request timeout.
        """
        self.endpoint = endpoint
        self.auth_provider = AuthProvider(auth)
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Create the shared httpx.AsyncClient with Anthropic-specific headers."""
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "anthropic-version": self.endpoint.anthropic_version,
        }
        # Anthropic uses x-api-key instead of Authorization: Bearer
        authed_headers = self.auth_provider.get_anthropic_headers(base_headers)

        self._client = httpx.AsyncClient(
            headers=authed_headers,
            timeout=httpx.Timeout(self.timeout),
            verify=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def send(self, prompt: str) -> AdapterResponse:
        """Send one prompt to the Anthropic Messages API.

        Args:
            prompt: The attack payload to send.

        Returns:
            AdapterResponse with the model's reply text.

        Raises:
            AdapterError: If the response format is unexpected.
            httpx.TimeoutException: On request timeout.
        """
        if self._client is None:
            raise RuntimeError("Adapter not set up — call setup() first")

        body: dict = {
            "model": self.endpoint.model,
            "max_tokens": self.endpoint.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        # System prompt is a top-level field in Anthropic's API (not in messages)
        if self.endpoint.system_prompt:
            body["system"] = self.endpoint.system_prompt

        start_ms = time.monotonic() * 1000
        try:
            response = await self._client.post(self.endpoint.url, json=body)
        except BaseException as exc:
            record_failed_exchange(
                method="POST",
                url=str(self.endpoint.url),
                request_headers=dict(self._client.headers),
                request_body=body,
                error=exc,
                duration_ms=time.monotonic() * 1000 - start_ms,
            )
            raise
        duration_ms = time.monotonic() * 1000 - start_ms

        exchange = record_exchange(
            method="POST",
            url=str(self.endpoint.url),
            request_headers=dict(self._client.headers),
            request_body=body,
            response_status=response.status_code,
            response_body=response.text,
            duration_ms=duration_ms,
        )

        response.raise_for_status()

        raw_body = response.text
        try:
            data = response.json()
            text = data["content"][0]["text"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AdapterError(
                f"Unexpected Anthropic response format: {exc}\nBody: {raw_body[:500]}"
            ) from exc

        finish_reason = normalise_finish_reason(data.get("stop_reason"))

        return AdapterResponse(
            text=text,
            http_status=response.status_code,
            raw_body=raw_body,
            duration_ms=duration_ms,
            exchanges=[exchange],
            finish_reason=finish_reason,
        )

    async def send_turns(self, turns: list[str]) -> AdapterResponse:
        """Multi-turn variant. Threads `messages` through Anthropic's API.

        Anthropic places the system prompt at the top level (not in messages),
        so we accumulate only user/assistant turns in `messages`.
        """
        if self._client is None:
            raise RuntimeError("Adapter not set up — call setup() first")
        if not turns:
            return AdapterResponse(text="", turn_texts=[])

        messages: list[dict] = []
        replies: list[str] = []
        last_status: int | None = None
        last_body: str | None = None
        last_finish_reason: str | None = None
        total_duration = 0.0
        exchanges: list[dict] = []

        for turn in turns:
            messages.append({"role": "user", "content": turn})
            body: dict = {
                "model": self.endpoint.model,
                "max_tokens": self.endpoint.max_tokens,
                "messages": messages,
            }
            if self.endpoint.system_prompt:
                body["system"] = self.endpoint.system_prompt

            start_ms = time.monotonic() * 1000
            try:
                response = await self._client.post(self.endpoint.url, json=body)
            except BaseException as exc:
                record_failed_exchange(
                    method="POST",
                    url=str(self.endpoint.url),
                    request_headers=dict(self._client.headers),
                    request_body=body,
                    error=exc,
                    duration_ms=time.monotonic() * 1000 - start_ms,
                )
                raise
            turn_duration = time.monotonic() * 1000 - start_ms
            total_duration += turn_duration
            exchanges.append(record_exchange(
                method="POST",
                url=str(self.endpoint.url),
                request_headers=dict(self._client.headers),
                request_body=body,
                response_status=response.status_code,
                response_body=response.text,
                duration_ms=turn_duration,
            ))
            response.raise_for_status()
            last_body = response.text
            last_status = response.status_code
            try:
                data = response.json()
                reply = data["content"][0]["text"]
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise AdapterError(
                    f"Unexpected Anthropic response format: {exc}\nBody: {last_body[:500]}"
                ) from exc
            last_finish_reason = normalise_finish_reason(data.get("stop_reason"))
            replies.append(reply)
            messages.append({"role": "assistant", "content": reply})

        return AdapterResponse(
            text="\n---\n".join(replies),
            http_status=last_status,
            raw_body=last_body,
            duration_ms=total_duration,
            turn_texts=replies,
            exchanges=exchanges,
            finish_reason=last_finish_reason,
        )

    async def teardown(self) -> None:
        """Close the httpx.AsyncClient."""
        if self._client:
            await self._client.aclose()
            self._client = None
