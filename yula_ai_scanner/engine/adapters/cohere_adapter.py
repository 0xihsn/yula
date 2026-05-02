"""
Cohere Chat API adapter (v2).

Sends prompts to the Cohere /v2/chat endpoint.

Request format:
  POST https://api.cohere.com/v2/chat
  Content-Type: application/json
  Authorization: Bearer {api_key}

  {
    "model": "command-r-plus",
    "messages": [
      {"role": "system", "content": "<system_prompt>"},
      {"role": "user", "content": "<prompt>"}
    ],
    "max_tokens": 1024
  }

Response extraction: message.content[0].text
"""

from __future__ import annotations

import json
import time

import httpx

from yula_ai_scanner.config.target_schema import AuthConfig, CohereEndpointConfig
from yula_ai_scanner.engine.adapters.base import (
    AdapterError,
    AdapterResponse,
    BaseAdapter,
    normalise_finish_reason,
)
from yula_ai_scanner.engine.http_log import record_exchange, record_failed_exchange


class CohereAdapter(BaseAdapter):
    """Adapter for the Cohere Chat API v2.

    Attributes:
        endpoint: Cohere endpoint configuration.
        auth: Authentication config (expects api_key or bearer).
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: CohereEndpointConfig,
        auth: AuthConfig,
        timeout_seconds: int = 30,
    ) -> None:
        self.endpoint = endpoint
        self.auth = auth
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    def _get_bearer_token(self) -> str:
        """Extract the API key / bearer token from auth config."""
        return self.auth.api_key or self.auth.token or ""

    async def setup(self) -> None:
        """Create the shared httpx.AsyncClient with auth headers."""
        token = self._get_bearer_token()
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.timeout),
            verify=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def send(self, prompt: str) -> AdapterResponse:
        """Send one prompt to the Cohere Chat API.

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

        messages: list[dict] = []
        if self.endpoint.system_prompt:
            messages.append({"role": "system", "content": self.endpoint.system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: dict = {
            "model": self.endpoint.model,
            "messages": messages,
            "max_tokens": self.endpoint.max_tokens,
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

        response.raise_for_status()

        raw_body = response.text
        try:
            data = response.json()
            text = data["message"]["content"][0]["text"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AdapterError(
                f"Unexpected Cohere response format: {exc}\nBody: {raw_body[:500]}"
            ) from exc

        finish_reason = normalise_finish_reason(data.get("finish_reason"))

        return AdapterResponse(
            text=text,
            http_status=response.status_code,
            raw_body=raw_body,
            duration_ms=duration_ms,
            exchanges=[exchange],
            finish_reason=finish_reason,
        )

    async def teardown(self) -> None:
        """Close the httpx.AsyncClient."""
        if self._client:
            await self._client.aclose()
            self._client = None
