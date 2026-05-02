"""
Adapter factory: returns the correct adapter for a given target type.
"""

from __future__ import annotations

from yula_ai_scanner.config.target_schema import TargetConfig
from yula_ai_scanner.engine.adapters.base import BaseAdapter


def get_adapter(target: TargetConfig, timeout_seconds: int = 30) -> BaseAdapter:
    """Instantiate the appropriate adapter for the given target configuration.

    Args:
        target: Validated target configuration (loaded from a target YAML file).
        timeout_seconds: HTTP timeout to pass to API adapters.

    Returns:
        An uninitialised BaseAdapter subclass instance. Call setup() before use.

    Raises:
        ValueError: If the target type is not recognised.
    """
    from yula_ai_scanner.config.target_schema import (
        AnthropicEndpointConfig,
        CohereEndpointConfig,
        CustomAPIEndpointConfig,
        GeminiEndpointConfig,
        OpenAIEndpointConfig,
        WebpageEndpointConfig,
    )
    from yula_ai_scanner.engine.adapters.anthropic_adapter import AnthropicAdapter
    from yula_ai_scanner.engine.adapters.cohere_adapter import CohereAdapter
    from yula_ai_scanner.engine.adapters.custom_adapter import CustomAdapter
    from yula_ai_scanner.engine.adapters.gemini_adapter import GeminiAdapter
    from yula_ai_scanner.engine.adapters.openai_adapter import OpenAIAdapter
    from yula_ai_scanner.engine.adapters.web_adapter import WebAdapter

    ep = target.endpoint
    auth = target.auth

    if isinstance(ep, OpenAIEndpointConfig):
        return OpenAIAdapter(ep, auth, timeout_seconds)
    if isinstance(ep, AnthropicEndpointConfig):
        return AnthropicAdapter(ep, auth, timeout_seconds)
    if isinstance(ep, GeminiEndpointConfig):
        return GeminiAdapter(ep, auth, timeout_seconds)
    if isinstance(ep, CohereEndpointConfig):
        return CohereAdapter(ep, auth, timeout_seconds)
    if isinstance(ep, CustomAPIEndpointConfig):
        return CustomAdapter(ep, auth, timeout_seconds)
    if isinstance(ep, WebpageEndpointConfig):
        return WebAdapter(ep, auth)

    raise ValueError(f"Unknown target type: {target.type}")
