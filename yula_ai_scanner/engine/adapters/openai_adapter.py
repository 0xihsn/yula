"""
OpenAI-compatible API adapter.

Sends prompts to any endpoint implementing the /v1/chat/completions
specification. Compatible with:
  - OpenAI API (api.openai.com)
  - Azure OpenAI
  - vLLM local server
  - Ollama (with /v1 prefix)
  - LM Studio
  - llama.cpp HTTP server
  - Together AI, Groq, Mistral, Fireworks, etc.

Request format:
  POST {url}
  Content-Type: application/json
  Authorization: Bearer {api_key}

  {
    "model": "gpt-4o",
    "messages": [
      {"role": "system", "content": "<system_prompt>"},
      {"role": "user", "content": "<prompt>"}
    ],
    "max_tokens": 1024,
    "temperature": 0.7
  }

Response extraction: choices[0].message.content
"""

from __future__ import annotations

import json
import time

import httpx

from yula_ai_scanner.config.target_schema import AuthConfig, OpenAIEndpointConfig
from yula_ai_scanner.engine.adapters.base import (
    AdapterError,
    AdapterResponse,
    BaseAdapter,
    normalise_finish_reason,
)
from yula_ai_scanner.engine.auth.provider import AuthProvider
from yula_ai_scanner.engine.http_log import record_exchange, record_failed_exchange


class OpenAIAdapter(BaseAdapter):
    """Adapter for OpenAI /v1/chat/completions compatible APIs.

    Attributes:
        endpoint: Endpoint configuration (URL, model, system prompt, etc.).
        auth_provider: Handles applying authentication headers.
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: OpenAIEndpointConfig,
        auth: AuthConfig,
        timeout_seconds: int = 30,
    ) -> None:
        """Initialise the adapter.

        Args:
            endpoint: OpenAI endpoint configuration.
            auth: Authentication configuration.
            timeout_seconds: HTTP request timeout.
        """
        self.endpoint = endpoint
        self.auth_provider = AuthProvider(auth)
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Create the shared httpx.AsyncClient.

        The client is reused across all requests to benefit from
        HTTP keep-alive connection pooling.
        """
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # Merge extra headers from config, then apply auth headers on top
        base_headers.update(self.endpoint.extra_headers)
        authed_headers = self.auth_provider.apply_to_headers(base_headers)

        self._client = httpx.AsyncClient(
            headers=authed_headers,
            timeout=httpx.Timeout(self.timeout),
            cookies=self.auth_provider.get_cookies(),
            verify=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def send(self, prompt: str) -> AdapterResponse:
        """Send one prompt to the OpenAI chat completions endpoint.

        Args:
            prompt: The attack payload to send as the user message.

        Returns:
            AdapterResponse with the model's reply text.

        Raises:
            AdapterError: If the response cannot be parsed or is missing fields.
            httpx.TimeoutException: On request timeout.
            httpx.ConnectError: On connection failure.
        """
        if self._client is None:
            raise RuntimeError("Adapter not set up — call setup() first")

        # Build messages array — include system prompt if configured
        messages = []
        if self.endpoint.system_prompt:
            messages.append({"role": "system", "content": self.endpoint.system_prompt})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": self.endpoint.model,
            "messages": messages,
            "max_tokens": self.endpoint.max_tokens,
            "temperature": self.endpoint.temperature,
        }

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

        # Raise on HTTP 4xx/5xx — tenacity will retry on 5xx
        response.raise_for_status()

        raw_body = response.text
        try:
            data = response.json()
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AdapterError(
                f"Unexpected OpenAI response format: {exc}\nBody: {raw_body[:500]}"
            ) from exc

        finish_reason = normalise_finish_reason(
            data.get("choices", [{}])[0].get("finish_reason")
        )

        return AdapterResponse(
            text=text,
            http_status=response.status_code,
            raw_body=raw_body,
            duration_ms=duration_ms,
            exchanges=[exchange],
            finish_reason=finish_reason,
        )

    async def send_turns(self, turns: list[str]) -> AdapterResponse:
        """Send N user turns as a single accumulating conversation.

        Each turn is appended as a `user` message; the assistant's reply is
        appended back into the messages list and the next turn is sent with
        the full history. Returns one AdapterResponse whose `text` is the
        concatenation of assistant replies (joined with `\\n---\\n`) and
        `turn_texts` carries the per-turn replies.
        """
        if self._client is None:
            raise RuntimeError("Adapter not set up — call setup() first")
        if not turns:
            return AdapterResponse(text="", turn_texts=[])

        messages: list[dict] = []
        if self.endpoint.system_prompt:
            messages.append({"role": "system", "content": self.endpoint.system_prompt})

        replies: list[str] = []
        last_status: int | None = None
        last_body: str | None = None
        last_finish_reason: str | None = None
        total_duration = 0.0
        exchanges: list[dict] = []

        for turn in turns:
            messages.append({"role": "user", "content": turn})
            body = {
                "model": self.endpoint.model,
                "messages": messages,
                "max_tokens": self.endpoint.max_tokens,
                "temperature": self.endpoint.temperature,
            }
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
                reply = data["choices"][0]["message"]["content"]
            except (KeyError, IndexError, json.JSONDecodeError) as exc:
                raise AdapterError(
                    f"Unexpected OpenAI response format: {exc}\nBody: {last_body[:500]}"
                ) from exc
            last_finish_reason = normalise_finish_reason(
                data.get("choices", [{}])[0].get("finish_reason")
            )
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
        """Close the httpx.AsyncClient and release connection pool."""
        if self._client:
            await self._client.aclose()
            self._client = None
