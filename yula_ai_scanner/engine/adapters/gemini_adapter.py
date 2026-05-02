"""
Google Gemini API adapter.

Sends prompts to the Gemini generateContent endpoint.

Request format:
  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}
  Content-Type: application/json

  {
    "systemInstruction": {"parts": [{"text": "<system_prompt>"}]},
    "contents": [{"role": "user", "parts": [{"text": "<prompt>"}]}],
    "generationConfig": {"maxOutputTokens": 1024}
  }

Response extraction: candidates[0].content.parts[0].text
"""

from __future__ import annotations

import json
import time

import httpx

from yula_ai_scanner.config.target_schema import AuthConfig, GeminiEndpointConfig
from yula_ai_scanner.engine.adapters.base import (
    AdapterError,
    AdapterResponse,
    BaseAdapter,
    normalise_finish_reason,
)
from yula_ai_scanner.engine.http_log import record_exchange, record_failed_exchange


class GeminiAdapter(BaseAdapter):
    """Adapter for the Google Gemini generateContent API.

    Attributes:
        endpoint: Gemini endpoint configuration.
        auth: Authentication config (expects api_key).
        timeout: Per-request timeout in seconds.
    """

    def __init__(
        self,
        endpoint: GeminiEndpointConfig,
        auth: AuthConfig,
        timeout_seconds: int = 30,
    ) -> None:
        self.endpoint = endpoint
        self.auth = auth
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    def _build_url(self) -> str:
        """Build the full request URL, substituting the model name."""
        return self.endpoint.url.replace("{model}", self.endpoint.model)

    def _get_api_key(self) -> str:
        """Extract the API key from auth config."""
        return self.auth.api_key or ""

    async def setup(self) -> None:
        """Create the shared httpx.AsyncClient."""
        self._client = httpx.AsyncClient(
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=httpx.Timeout(self.timeout),
            verify=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    async def send(self, prompt: str) -> AdapterResponse:
        """Send one prompt to the Gemini generateContent API.

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
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": self.endpoint.max_tokens},
        }
        if self.endpoint.system_prompt:
            body["systemInstruction"] = {
                "parts": [{"text": self.endpoint.system_prompt}]
            }

        url = self._build_url()
        params = {}
        api_key = self._get_api_key()
        if api_key:
            params["key"] = api_key

        start_ms = time.monotonic() * 1000
        try:
            response = await self._client.post(url, json=body, params=params)
        except BaseException as exc:
            record_failed_exchange(
                method="POST",
                url=url,
                request_headers=dict(self._client.headers),
                request_body=body,
                error=exc,
                duration_ms=time.monotonic() * 1000 - start_ms,
            )
            raise
        duration_ms = time.monotonic() * 1000 - start_ms

        exchange = record_exchange(
            method="POST",
            url=str(response.request.url),
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
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AdapterError(
                f"Unexpected Gemini response format: {exc}\nBody: {raw_body[:500]}"
            ) from exc

        finish_reason = normalise_finish_reason(
            data.get("candidates", [{}])[0].get("finishReason")
        )

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
