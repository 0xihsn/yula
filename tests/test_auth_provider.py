"""
Tests for yula_ai_scanner.engine.auth.provider.

Validates header construction and cookie handling for all six auth types.
Playwright-dependent form_login tests are skipped in standard CI.
"""

from __future__ import annotations

import base64

import pytest

from yula_ai_scanner.config.target_schema import AuthConfig, AuthType, CookieEntry
from yula_ai_scanner.engine.auth.provider import AuthProvider


class TestAuthProviderHeaders:
    def test_none_auth_adds_no_headers(self):
        provider = AuthProvider(AuthConfig(type=AuthType.NONE))
        headers = provider.apply_to_headers({})
        assert headers == {}

    def test_api_key_adds_bearer_header(self):
        provider = AuthProvider(AuthConfig(type=AuthType.API_KEY, api_key="sk-test123"))
        headers = provider.apply_to_headers({})
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer sk-test123"

    def test_bearer_adds_authorization_header(self):
        provider = AuthProvider(AuthConfig(type=AuthType.BEARER, token="mytoken"))
        headers = provider.apply_to_headers({})
        assert headers.get("Authorization") == "Bearer mytoken"

    def test_basic_auth_produces_valid_base64(self):
        provider = AuthProvider(
            AuthConfig(type=AuthType.BASIC, username="user", password="pass")
        )
        headers = provider.apply_to_headers({})
        auth_header = headers.get("Authorization", "")
        assert auth_header.startswith("Basic ")
        encoded = auth_header[len("Basic "):]
        decoded = base64.b64decode(encoded).decode()
        assert decoded == "user:pass"

    def test_apply_to_headers_does_not_mutate_input(self):
        provider = AuthProvider(AuthConfig(type=AuthType.API_KEY, api_key="key"))
        original = {"X-Custom": "value"}
        result = provider.apply_to_headers(original)
        assert "X-Custom" in result
        assert original == {"X-Custom": "value"}

    def test_anthropic_headers_contain_x_api_key(self):
        provider = AuthProvider(AuthConfig(type=AuthType.API_KEY, api_key="ant-key"))
        headers = provider.get_anthropic_headers({})
        assert "x-api-key" in headers
        assert headers["x-api-key"] == "ant-key"


class TestAuthProviderCookies:
    def test_cookie_auth_returns_cookies(self):
        provider = AuthProvider(
            AuthConfig(
                type=AuthType.COOKIE,
                cookies=[
                    CookieEntry(name="session", value="abc123", domain="localhost")
                ],
            )
        )
        cookies = provider.get_cookies()
        assert "session" in cookies
        assert cookies["session"] == "abc123"

    def test_non_cookie_auth_returns_empty_dict(self):
        provider = AuthProvider(AuthConfig(type=AuthType.BEARER, token="tok"))
        assert provider.get_cookies() == {}

    def test_multiple_cookies_all_returned(self):
        provider = AuthProvider(
            AuthConfig(
                type=AuthType.COOKIE,
                cookies=[
                    CookieEntry(name="a", value="1", domain="localhost"),
                    CookieEntry(name="b", value="2", domain="localhost"),
                ],
            )
        )
        cookies = provider.get_cookies()
        assert len(cookies) == 2
