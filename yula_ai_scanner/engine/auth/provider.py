"""
Authentication provider: applies credentials to HTTP requests and browsers.

The AuthProvider is a stateless helper that knows how to translate an AuthConfig
(loaded from a target YAML) into concrete request modifications:
  - HTTP headers (for API adapters using httpx)
  - Cookie dicts (for both httpx and Playwright)
  - Browser form login (for the web adapter using Playwright)

All credential values must already be resolved (env vars substituted) by the
time an AuthProvider is constructed — the ConfigLoader handles that step.
"""

from __future__ import annotations

import asyncio
import base64
from typing import TYPE_CHECKING

from yula_ai_scanner.config.target_schema import AuthConfig, AuthType

if TYPE_CHECKING:
    # Playwright types — only available if playwright is installed
    from playwright.async_api import Page


class AuthenticationError(Exception):
    """Raised when authentication fails (e.g. form login submission errors)."""


class AuthProvider:
    """Applies authentication to HTTP requests and Playwright browser sessions.

    This class is intentionally stateless — it derives everything it needs
    from the AuthConfig passed at construction time. This makes it safe to
    share across async tasks without locking.

    Attributes:
        auth: The resolved authentication configuration.
    """

    def __init__(self, auth: AuthConfig) -> None:
        """Initialise with an already-resolved auth config.

        Args:
            auth: AuthConfig with all ${ENV_VAR} references already substituted.
        """
        self.auth = auth

    def apply_to_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Return a new headers dict with authentication headers merged in.

        This is a pure function — it does not modify the input dict.

        Args:
            headers: Existing headers dict (may be empty).

        Returns:
            New headers dict with auth headers added.
        """
        result = dict(headers)  # copy — do not mutate the input

        auth_type = self.auth.type

        if auth_type == AuthType.API_KEY:
            # OpenAI convention: API key as Bearer token
            key = self.auth.api_key or ""
            result["Authorization"] = f"Bearer {key}"

        elif auth_type == AuthType.BEARER:
            token = self.auth.token or ""
            result["Authorization"] = f"Bearer {token}"

        elif auth_type == AuthType.BASIC:
            username = self.auth.username or ""
            password = self.auth.password or ""
            credentials = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()
            result["Authorization"] = f"Basic {credentials}"

        # COOKIE and FORM_LOGIN headers are handled separately via get_cookies()
        # and perform_form_login() — not via HTTP headers.

        return result

    def get_anthropic_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Apply Anthropic-specific auth headers (x-api-key, not Authorization).

        Args:
            headers: Existing headers dict.

        Returns:
            New headers dict with x-api-key header added.
        """
        result = dict(headers)
        if self.auth.type == AuthType.API_KEY and self.auth.api_key:
            result["x-api-key"] = self.auth.api_key
        return result

    def get_cookies(self) -> dict[str, str]:
        """Return a cookie name→value dict for httpx requests.

        Returns:
            Dict of cookie names to values, or empty dict if auth type is not cookie.
        """
        if self.auth.type != AuthType.COOKIE:
            return {}
        return {c.name: c.value for c in self.auth.cookies}

    def get_playwright_cookies(self) -> list[dict]:
        """Return Playwright-format cookie dicts for browser context injection.

        Playwright's add_cookies() expects a list of dicts with specific fields.

        Returns:
            List of cookie dicts compatible with Playwright's add_cookies().
        """
        if self.auth.type not in {AuthType.COOKIE, AuthType.FORM_LOGIN}:
            return []
        return [
            {
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "secure": c.secure,
                "httpOnly": False,
                "sameSite": "Lax",
            }
            for c in self.auth.cookies
        ]

    async def perform_form_login(self, page: "Page") -> None:
        """Navigate to the login page and submit credentials using Playwright.

        This method is only relevant for the web adapter (Playwright). It
        navigates to the login URL, fills in username/password fields, submits
        the form, and waits for the post-login redirect.

        Limited to a single username/password/submit triplet. For richer login
        flows (MFA, hidden CSRF tokens, multi-step pages), prefer
        `endpoint.setup` steps in the target YAML and leave `auth.type` as
        `none` or `cookie`.

        Args:
            page: Playwright Page object (from an active browser context).

        Raises:
            AuthenticationError: If the login URL, username/password selector,
                                  or submit selector are not configured.
        """
        auth = self.auth

        if auth.type != AuthType.FORM_LOGIN:
            return  # Nothing to do for non-form-login auth types

        if not auth.login_url:
            raise AuthenticationError(
                "form_login auth type requires 'login_url' to be set in target config"
            )

        # Navigate to the login page
        await page.goto(auth.login_url)

        # Fill username
        if auth.username_selector and auth.username:
            await page.fill(auth.username_selector, auth.username)

        # Fill password
        if auth.password_selector and auth.password:
            await page.fill(auth.password_selector, auth.password)

        # Submit the form
        if auth.submit_selector:
            await page.click(auth.submit_selector)
        else:
            # Fall back to pressing Enter in the last filled field
            await page.keyboard.press("Enter")

        # Wait for navigation / redirect after form submission
        try:
            await page.wait_for_load_state("networkidle",
                                           timeout=auth.post_login_wait_ms)
        except Exception:
            # Some SPAs don't trigger networkidle — wait a fixed time instead
            await asyncio.sleep(auth.post_login_wait_ms / 1000)
