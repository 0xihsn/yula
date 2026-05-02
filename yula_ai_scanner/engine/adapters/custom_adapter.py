"""
Custom REST API adapter.

Handles any HTTP API that accepts a configurable JSON body with a {prompt}
placeholder. The response path uses dot-notation to extract the response text
from arbitrarily nested JSON structures.

This adapter supports GET, POST, and PUT methods with any Content-Type.
"""

from __future__ import annotations

import json
import time

import httpx

from yula_ai_scanner.config.target_schema import AuthConfig, CustomAPIEndpointConfig
from yula_ai_scanner.engine.adapters.base import AdapterError, AdapterResponse, BaseAdapter
from yula_ai_scanner.engine.auth.provider import AuthProvider
from yula_ai_scanner.engine.http_log import record_exchange, record_failed_exchange


class CustomAdapter(BaseAdapter):
    """Adapter for generic REST API targets.

    Uses a configurable body template with a {prompt} placeholder and a
    dot-notation response path to extract the AI's reply from the JSON response.

    Attributes:
        endpoint: Custom API endpoint configuration.
        auth_provider: Applies authentication headers.
        timeout: Per-request timeout.
    """

    def __init__(
        self,
        endpoint: CustomAPIEndpointConfig,
        auth: AuthConfig,
        timeout_seconds: int = 30,
    ) -> None:
        """Initialise the adapter.

        Args:
            endpoint: Custom API endpoint configuration.
            auth: Authentication configuration.
            timeout_seconds: HTTP request timeout.
        """
        self.endpoint = endpoint
        self.auth_provider = AuthProvider(auth)
        self.timeout = timeout_seconds
        self._client: httpx.AsyncClient | None = None

    async def setup(self) -> None:
        """Create the shared httpx.AsyncClient."""
        base_headers = {
            "Content-Type": self.endpoint.content_type,
            "Accept": "application/json",
        }
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
        """Send one prompt using the configured body template and HTTP method.

        Substitutes {prompt} in the body template with the actual payload,
        sends the request, and extracts the response using response_path.

        Args:
            prompt: The attack payload.

        Returns:
            AdapterResponse with extracted response text.

        Raises:
            AdapterError: If {prompt} substitution fails or response path is invalid.
        """
        if self._client is None:
            raise RuntimeError("Adapter not set up — call setup() first")

        # Safely substitute {prompt} in the body template
        # Use a safe substitute that won't fail on other {braces} in the template
        try:
            body_str = self.endpoint.body_template.replace(
                "{prompt}", _escape_json_string(prompt)
            )
        except Exception as exc:
            raise AdapterError(
                f"Failed to substitute {{prompt}} in body_template: {exc}"
            ) from exc

        start_ms = time.monotonic() * 1000

        method = self.endpoint.method.upper()
        logged_request_body: object = (
            {"query": prompt} if method == "GET" else body_str
        )
        try:
            if method == "GET":
                # For GET requests, body_str is sent as a query parameter
                response = await self._client.get(
                    self.endpoint.url,
                    params={"query": prompt},
                )
            else:
                # POST / PUT — send body as raw string (already JSON-formatted)
                response = await self._client.request(
                    method=method,
                    url=self.endpoint.url,
                    content=body_str,
                )
        except BaseException as exc:
            record_failed_exchange(
                method=method,
                url=str(self.endpoint.url),
                request_headers=dict(self._client.headers),
                request_body=logged_request_body,
                error=exc,
                duration_ms=time.monotonic() * 1000 - start_ms,
            )
            raise

        duration_ms = time.monotonic() * 1000 - start_ms

        exchange = record_exchange(
            method=method,
            url=str(response.request.url),
            request_headers=dict(self._client.headers),
            request_body=logged_request_body,
            response_status=response.status_code,
            response_body=response.text,
            duration_ms=duration_ms,
        )

        response.raise_for_status()

        raw_body = response.text
        try:
            data = response.json()
            text = _extract_by_path(data, self.endpoint.response_path)
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise AdapterError(
                f"Cannot extract response using path '{self.endpoint.response_path}': "
                f"{exc}\nBody: {raw_body[:500]}"
            ) from exc

        return AdapterResponse(
            text=str(text),
            http_status=response.status_code,
            raw_body=raw_body,
            duration_ms=duration_ms,
            exchanges=[exchange],
        )

    async def teardown(self) -> None:
        """Close the httpx.AsyncClient."""
        if self._client:
            await self._client.aclose()
            self._client = None


def _extract_by_path(data: dict | list, path: str) -> object:
    """Traverse a nested dict/list using dot-notation path.

    Examples:
      path="response"                → data["response"]
      path="data.text"               → data["data"]["text"]
      path="choices.0.message.text"  → data["choices"][0]["message"]["text"]

    Args:
        data: Parsed JSON response body.
        path: Dot-separated key path. Integer segments index lists.

    Returns:
        The value at the given path.

    Raises:
        KeyError: If a dict key is missing.
        IndexError: If a list index is out of range.
        TypeError: If the path traverses through a non-dict/non-list.
    """
    current = data
    for segment in path.split("."):
        if isinstance(current, list):
            current = current[int(segment)]
        else:
            current = current[segment]
    return current


def _escape_json_string(value: str) -> str:
    """Escape a string for safe embedding inside a JSON string value.

    Escapes backslashes, double quotes, and control characters so the
    substituted body_template remains valid JSON.

    Args:
        value: Raw prompt string.

    Returns:
        JSON-safe escaped string (without surrounding quotes).
    """
    return json.dumps(value)[1:-1]  # json.dumps adds surrounding quotes — strip them
