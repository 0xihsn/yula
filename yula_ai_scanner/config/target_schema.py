"""
Pydantic models for target configuration (targets/*.yaml).

A "target" describes the AI system under test: its endpoint URL, API format,
and authentication credentials. YULA AI Scanner supports six target types:

  openai      — OpenAI-compatible REST API. Works with: OpenAI, vLLM, Ollama,
                LM Studio, llama.cpp server, Together AI, Groq, Mistral,
                Azure OpenAI, OpenRouter, Perplexity, xAI (Grok), DeepSeek,
                Fireworks AI, Cerebras Inference, SambaNova Cloud,
                NVIDIA NIM (build.nvidia.com or self-hosted), DeepInfra,
                Databricks Foundation Model APIs, Moonshot (Kimi),
                Zhipu (GLM / BigModel), Alibaba DashScope (compatible mode),
                Meta Llama API (compat), Hyperbolic, and any other server
                implementing the /v1/chat/completions specification.
  anthropic   — Anthropic Messages API
  gemini      — Google Gemini API (generativelanguage.googleapis.com)
  cohere      — Cohere Chat API (api.cohere.com/v2/chat)
  custom_api  — Any HTTP API with a configurable JSON body template. Used
                for Hugging Face Inference, Replicate, Cloudflare Workers AI,
                AI21 Studio (Jamba), Writer (Palmyra), and similar.
  webpage     — A web page with an AI chat input field (uses Playwright).
                Used for ChatGPT-web, Claude.ai, Gemini.google.com,
                Microsoft Copilot, HuggingChat, Poe, Le Chat, etc.

AWS Bedrock and Google Vertex AI require provider-specific request signing
(SigV4 / OAuth2) that YULA does not implement natively. Use an OpenAI-
compatible proxy (Bedrock Access Gateway, LiteLLM Proxy) or the
Vertex /openapi endpoint with a `gcloud auth print-access-token` bearer.
See config/targets/bedrock_target.yaml and vertexai_target.yaml.

Authentication types supported:
  none        — No authentication
  api_key     — Sent as X-Api-Key or Authorization: Bearer header
  bearer      — Authorization: Bearer {token}
  basic       — Authorization: Basic base64(username:password)
  cookie      — Inject cookies into requests / browser session
  form_login  — Navigate to a login page and submit credentials (webpage only)

All credential values support ${ENV_VAR} interpolation — never hardcode secrets
in YAML files. The ConfigLoader resolves these at load time.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class AuthType(str, Enum):
    """Supported authentication mechanisms.

    Attributes:
        NONE: No authentication required.
        API_KEY: API key in a header (typically X-Api-Key or Authorization: Bearer).
        BEARER: Bearer token in Authorization header.
        BASIC: HTTP Basic authentication (username + password).
        COOKIE: Session cookies injected into requests.
        FORM_LOGIN: Browser-based form login (Playwright only).
    """

    NONE = "none"
    API_KEY = "api_key"
    BEARER = "bearer"
    BASIC = "basic"
    COOKIE = "cookie"
    FORM_LOGIN = "form_login"


class CookieEntry(BaseModel):
    """One browser/HTTP cookie definition.

    Attributes:
        name: Cookie name.
        value: Cookie value (supports ${ENV_VAR} interpolation).
        domain: Domain the cookie applies to.
        path: URL path scope.
        secure: Whether the cookie requires HTTPS.
    """

    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False


class AuthConfig(BaseModel):
    """Authentication configuration for a target.

    Only the fields relevant to the selected auth type need to be set.
    All string credential fields support ${ENV_VAR} interpolation.

    Attributes:
        type: Which authentication mechanism to use.
        api_key: API key value (used with api_key auth type).
        token: Bearer token value (used with bearer auth type).
        username: Username for basic auth or form login.
        password: Password for basic auth or form login.
        cookies: List of cookies to inject (used with cookie auth type).
        login_url: URL of the login page (used with form_login auth type).
        username_selector: CSS selector for username input field.
        password_selector: CSS selector for password input field.
        submit_selector: CSS selector for the login submit button.
        post_login_wait_ms: Milliseconds to wait after login form submission.
    """

    type: AuthType = AuthType.NONE
    api_key: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    cookies: list[CookieEntry] = Field(default_factory=list)
    login_url: str | None = None
    username_selector: str | None = None
    password_selector: str | None = None
    submit_selector: str | None = None
    post_login_wait_ms: int = Field(default=2000, ge=0)


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint configurations (one per target type)
# ─────────────────────────────────────────────────────────────────────────────


class OpenAIEndpointConfig(BaseModel):
    """Endpoint config for OpenAI-compatible APIs.

    Compatible with: OpenAI, vLLM, Ollama, LM Studio, llama.cpp server,
    Together AI, Groq, and any server implementing the /v1/chat/completions spec.

    Attributes:
        url: Full URL to the chat completions endpoint.
        model: Model identifier to request.
        system_prompt: Optional system prompt to inject for testing.
        max_tokens: Maximum tokens in the AI's response.
        temperature: Sampling temperature (0.0 = deterministic).
        extra_headers: Additional HTTP headers to include.
    """

    url: str
    model: str = "gpt-4o"
    system_prompt: str | None = None
    max_tokens: int = Field(default=1024, ge=1, le=32768)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    extra_headers: dict[str, str] = Field(default_factory=dict)


class AnthropicEndpointConfig(BaseModel):
    """Endpoint config for the Anthropic Messages API.

    Attributes:
        url: Anthropic API endpoint URL.
        model: Claude model identifier.
        system_prompt: Optional system prompt for testing.
        max_tokens: Maximum tokens in the response.
        anthropic_version: API version header value.
    """

    url: str = "https://api.anthropic.com/v1/messages"
    model: str = "claude-3-5-sonnet-20241022"
    system_prompt: str | None = None
    max_tokens: int = Field(default=1024, ge=1, le=32768)
    anthropic_version: str = "2023-06-01"


class CustomAPIEndpointConfig(BaseModel):
    """Endpoint config for any custom HTTP API.

    The body_template must contain a {prompt} placeholder which YULA AI Scanner
    substitutes with each attack payload before sending.

    response_path uses dot-notation to extract the response text from the
    JSON response body (e.g. "data.message.text" → body["data"]["message"]["text"]).

    Attributes:
        url: Full API endpoint URL.
        method: HTTP method (GET, POST, PUT).
        body_template: JSON body template with {prompt} placeholder.
        response_path: Dot-notation path to extract response text from JSON body.
        content_type: Content-Type header value.
        extra_headers: Additional HTTP headers.
    """

    url: str
    method: str = "POST"
    body_template: str  # Must contain {prompt}
    response_path: str = "response"
    content_type: str = "application/json"
    extra_headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("body_template")
    @classmethod
    def must_contain_prompt_placeholder(cls, v: str) -> str:
        """Ensure the body template has a {prompt} substitution placeholder."""
        if "{prompt}" not in v:
            raise ValueError(
                "body_template must contain '{prompt}' as the substitution placeholder"
            )
        return v

    @field_validator("method")
    @classmethod
    def uppercase_method(cls, v: str) -> str:
        """Normalize HTTP method to uppercase."""
        return v.upper()


# ─────────────────────────────────────────────────────────────────────────────
# Webpage target — sub-models for the step-based flow
# ─────────────────────────────────────────────────────────────────────────────


class Viewport(BaseModel):
    """Browser viewport size (pixels)."""

    width: int = Field(default=1280, ge=200, le=4096)
    height: int = Field(default=800, ge=200, le=4096)


class BrowserConfig(BaseModel):
    """Browser launch + context options.

    All fields are optional; defaults reproduce the old flat behaviour
    (chromium, headless, no viewport override).

    Attributes:
        engine: Playwright browser engine.
        headless: Run headless (set False to watch the browser).
        viewport: Optional explicit viewport size.
        user_agent: Override navigator.userAgent.
        extra_http_headers: Extra HTTP headers added to every browser request.
        navigation_wait: Page-load condition after navigate().
        navigation_timeout_ms: Timeout for navigate() / wait_for_load_state.
    """

    engine: Literal["chromium", "firefox", "webkit"] = "chromium"
    headless: bool = True
    viewport: Viewport | None = None
    user_agent: str | None = None
    extra_http_headers: dict[str, str] = Field(default_factory=dict)
    navigation_wait: Literal["networkidle", "load", "domcontentloaded"] = "networkidle"
    navigation_timeout_ms: int = Field(default=15000, ge=500)


# Step-action enum lives as a plain Literal so YAML stays string-friendly.
StepAction = Literal[
    "navigate",
    "click",
    "fill",
    "type",
    "wait",
    "extract",
    "evaluate",
    "press_key",
    "reload",
    "sleep",
]


class FlowStep(BaseModel):
    """One scriptable browser step.

    Not every field applies to every action — see the `action`-specific
    requirements enforced in `_check_action_requirements`.

    Attributes:
        action: Which Playwright primitive to invoke.
        selector: CSS / XPath / text selector (most actions).
        fallback_selectors: Tried in order if `selector` does not match.
        url: Target URL (action=navigate).
        value: Text to type / fill (action=fill | type). Supports `{prompt}`
            and `{var}` substitution from earlier `extract` steps.
        method: Fill method (action=fill).
        delay_ms: Per-keystroke delay (action=type).
        state: Wait state (action=wait).
        contains: Required text substring (action=wait, state=text).
        timeout_ms: Action-specific timeout (wait, navigate, reload).
        attribute: HTML attribute to read (action=extract, method=attribute).
        extract_method: How to read the value (action=extract).
        script: JS expression (action=evaluate or action=extract method=evaluate).
        store_as: Name to bind the extracted value to for later substitution.
        key: Keyboard key to press (action=press_key).
        ms: Sleep duration in milliseconds (action=sleep).
        optional: If True, missing selector / failure does not raise.
    """

    action: StepAction
    selector: str | None = None
    fallback_selectors: list[str] = Field(default_factory=list)
    url: str | None = None
    value: str | None = None
    method: Literal["fill", "type", "press_sequentially"] = "fill"
    delay_ms: int = Field(default=0, ge=0)
    state: Literal["visible", "hidden", "attached", "detached", "text", "networkidle"] = "visible"
    contains: str | None = None
    timeout_ms: int = Field(default=10000, ge=0)
    attribute: str | None = None
    extract_method: Literal["inner_text", "text_content", "inner_html", "attribute", "evaluate"] = "inner_text"
    script: str | None = None
    store_as: str | None = None
    key: str = "Enter"
    ms: int = Field(default=0, ge=0)
    optional: bool = False

    @model_validator(mode="after")
    def _check_action_requirements(self) -> "FlowStep":
        a = self.action
        if a == "navigate" and not self.url:
            raise ValueError("step action=navigate requires 'url'")
        if a in {"click", "fill", "type", "wait", "extract"} and not self.selector:
            raise ValueError(f"step action={a} requires 'selector'")
        if a in {"fill", "type"} and self.value is None:
            raise ValueError(f"step action={a} requires 'value'")
        if a == "wait" and self.state == "text" and not self.contains:
            raise ValueError("step action=wait state=text requires 'contains'")
        if a == "extract" and self.extract_method == "attribute" and not self.attribute:
            raise ValueError("step action=extract method=attribute requires 'attribute'")
        if a == "extract" and self.extract_method == "evaluate" and not self.script:
            raise ValueError("step action=extract method=evaluate requires 'script'")
        if a == "evaluate" and not self.script:
            raise ValueError("step action=evaluate requires 'script'")
        if a == "sleep" and self.ms <= 0:
            raise ValueError("step action=sleep requires 'ms' > 0")
        return self


class PromptInput(BaseModel):
    """One field to populate before submitting the prompt.

    Attributes:
        selector: Target element selector.
        fallback_selectors: Tried in order if `selector` does not match.
        value: Text to enter. Supports `{prompt}` and `{var_name}` placeholders.
        method: Playwright fill method.
        delay_ms: Per-keystroke delay (only for method=type).
    """

    selector: str
    fallback_selectors: list[str] = Field(default_factory=list)
    value: str = "{prompt}"
    method: Literal["fill", "type", "press_sequentially"] = "fill"
    delay_ms: int = Field(default=0, ge=0)


class SubmitConfig(BaseModel):
    """How to submit the populated form."""

    method: Literal["click", "press_enter", "press_key"] = "press_enter"
    selector: str | None = None
    fallback_selectors: list[str] = Field(default_factory=list)
    key: str = "Enter"

    @model_validator(mode="after")
    def _check_method_requirements(self) -> "SubmitConfig":
        if self.method == "click" and not self.selector:
            raise ValueError("submit.method=click requires 'selector'")
        return self


class WaitForConfig(BaseModel):
    """How to wait for the AI response to be ready for extraction.

    Attributes:
        selector: Element to watch.
        fallback_selectors: Tried in order if `selector` does not match.
        state: Wait condition.
        contains: Required substring (only for state=text).
        timeout_ms: Maximum wait.
        settle_ms: Extra dwell after the condition fires (covers streaming tokens).
    """

    selector: str
    fallback_selectors: list[str] = Field(default_factory=list)
    state: Literal["visible", "hidden", "attached", "detached", "text", "networkidle"] = "visible"
    contains: str | None = None
    timeout_ms: int = Field(default=8000, ge=500)
    settle_ms: int = Field(default=500, ge=0)

    @model_validator(mode="after")
    def _check_state_requirements(self) -> "WaitForConfig":
        if self.state == "text" and not self.contains:
            raise ValueError("wait_for.state=text requires 'contains'")
        return self


class ExtractConfig(BaseModel):
    """How to read the response off the page.

    Attributes:
        selector: Element to read. Defaults to wait_for.selector when omitted
            (set by the normalizer, not by Pydantic).
        fallback_selectors: Tried in order if `selector` does not match.
        method: Reading strategy.
        attribute: HTML attribute name (method=attribute).
        script: JS expression that receives the element (method=evaluate).
        pick: Which match to read when the selector resolves to many elements.
        regex: Optional post-processing regex.
        regex_group: Capture group to keep (default 0 = whole match).
    """

    selector: str | None = None
    fallback_selectors: list[str] = Field(default_factory=list)
    method: Literal["inner_text", "text_content", "inner_html", "attribute", "evaluate"] = "inner_text"
    attribute: str | None = None
    script: str | None = None
    pick: Literal["first", "last", "all"] = "last"
    regex: str | None = None
    regex_group: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _check_method_requirements(self) -> "ExtractConfig":
        if self.method == "attribute" and not self.attribute:
            raise ValueError("extract.method=attribute requires 'attribute'")
        if self.method == "evaluate" and not self.script:
            raise ValueError("extract.method=evaluate requires 'script'")
        return self


class ResetConfig(BaseModel):
    """How to reset state between separate AttackPayloads."""

    action: Literal["click", "reload", "none"] = "none"
    selector: str | None = None
    fallback_selectors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_action_requirements(self) -> "ResetConfig":
        if self.action == "click" and not self.selector:
            raise ValueError("reset.action=click requires 'selector'")
        return self


class PromptCycle(BaseModel):
    """The per-prompt interaction recipe (the part that repeats per payload).

    Attributes:
        before: Steps run before populating inputs (per send).
        inputs: One or more fields to fill.
        submit: How to submit.
        wait_for: How to wait for the response.
        extract: How to read the response.
        reset: How to clear state between separate AttackPayloads.
    """

    before: list[FlowStep] = Field(default_factory=list)
    inputs: list[PromptInput]
    submit: SubmitConfig = Field(default_factory=SubmitConfig)
    wait_for: WaitForConfig
    extract: ExtractConfig = Field(default_factory=ExtractConfig)
    reset: ResetConfig = Field(default_factory=ResetConfig)


class WebpageEndpointConfig(BaseModel):
    """Endpoint config for web page targets driven by Playwright.

    YULA AI Scanner launches a real browser and interacts with the page just
    like a human user. The schema supports two equivalent styles:

    1. **Shorthand** (legacy, simple chat UIs): set the flat fields
       `input_field`, `submit_button`, `response_container`, `clear_button`,
       and `response_wait_ms`.

    2. **Flow** (multi-step, CSRF, hidden fields, custom waits): set the
       `prompt:` block and optionally `setup:`, `browser:`. The shorthand
       response fields must NOT be combined with `prompt:` — pick one style
       per file.

    The two are normalised internally so the adapter only sees one shape.
    See `to_flow()` for the normalised representation.

    Attributes:
        url: URL of the chat page (always required).
        browser: Browser engine name OR a full BrowserConfig object.
        headless: Headless mode (legacy alias; prefer browser.headless).
        setup: Steps run once after navigation/auth.
        prompt: Per-prompt interaction cycle (mutually exclusive with shorthand
            response fields).
        input_field: Shorthand — selector for the prompt input.
        submit_button: Shorthand — selector for the send button (null = Enter).
        response_container: Shorthand — selector for the AI response element.
        clear_button: Shorthand — selector for a clear/reset button (null = skip).
        response_wait_ms: Shorthand — response timeout (ms, min 500).
    """

    url: str
    browser: str | BrowserConfig = Field(default_factory=BrowserConfig)
    headless: bool | None = None
    setup: list[FlowStep] = Field(default_factory=list)
    prompt: PromptCycle | None = None
    # ── Shorthand response fields (mutually exclusive with `prompt`) ────────
    input_field: str | None = None
    submit_button: str | None = None
    response_container: str | None = None
    clear_button: str | None = None
    response_wait_ms: int = Field(default=8000, ge=500)

    @field_validator("browser", mode="before")
    @classmethod
    def _coerce_browser(cls, v: Any) -> Any:
        """Accept `browser: chromium` (string) or `browser: { engine: ... }` (dict)."""
        if isinstance(v, str):
            return BrowserConfig(engine=v)  # type: ignore[arg-type]
        return v

    @model_validator(mode="after")
    def _check_shape(self) -> "WebpageEndpointConfig":
        """Enforce shorthand-XOR-flow and required fields."""
        shorthand_response_fields = {
            "input_field": self.input_field,
            "submit_button": self.submit_button,
            "response_container": self.response_container,
            "clear_button": self.clear_button,
        }
        shorthand_set = {k for k, v in shorthand_response_fields.items() if v is not None}

        if self.prompt is not None and shorthand_set:
            raise ValueError(
                "Webpage endpoint mixes shorthand response fields "
                f"({', '.join(sorted(shorthand_set))}) with a 'prompt:' block. "
                "Use one style or the other — see docs/target_types.md."
            )

        if self.prompt is None:
            # Shorthand mode — input_field and response_container are required.
            missing = [
                name for name in ("input_field", "response_container")
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(
                    "Webpage endpoint requires either a 'prompt:' block or "
                    f"the shorthand fields. Missing: {', '.join(missing)}."
                )

        # Apply legacy `headless` to browser config when caller used shorthand.
        if self.headless is not None:
            assert isinstance(self.browser, BrowserConfig)
            self.browser = self.browser.model_copy(update={"headless": self.headless})

        return self

    def to_flow(self) -> tuple[BrowserConfig, list[FlowStep], PromptCycle]:
        """Return the normalised (browser, setup, prompt) the adapter consumes.

        Builds a PromptCycle from shorthand fields when no `prompt:` block was
        given. Validation errors have already been raised by `_check_shape`.
        """
        assert isinstance(self.browser, BrowserConfig)

        if self.prompt is not None:
            # Default extract.selector to wait_for.selector if not set explicitly.
            prompt = self.prompt
            if prompt.extract.selector is None:
                prompt = prompt.model_copy(
                    update={
                        "extract": prompt.extract.model_copy(
                            update={"selector": prompt.wait_for.selector},
                        ),
                    }
                )
            return self.browser, list(self.setup), prompt

        # Shorthand → build an equivalent PromptCycle.
        assert self.input_field is not None and self.response_container is not None

        submit = (
            SubmitConfig(method="click", selector=self.submit_button)
            if self.submit_button
            else SubmitConfig(method="press_enter")
        )
        reset = (
            ResetConfig(action="click", selector=self.clear_button)
            if self.clear_button
            else ResetConfig(action="none")
        )
        prompt = PromptCycle(
            inputs=[PromptInput(selector=self.input_field, value="{prompt}")],
            submit=submit,
            wait_for=WaitForConfig(
                selector=self.response_container,
                state="visible",
                timeout_ms=self.response_wait_ms,
                settle_ms=500,
            ),
            extract=ExtractConfig(
                selector=self.response_container,
                method="inner_text",
                pick="last",
            ),
            reset=reset,
        )
        return self.browser, list(self.setup), prompt


class GeminiEndpointConfig(BaseModel):
    """Endpoint config for the Google Gemini API.

    Uses the generateContent endpoint from the Generative Language API.
    Authentication is via an API key passed as a query parameter.

    Attributes:
        url: Base URL template — {model} is replaced with the model name.
        model: Gemini model identifier (e.g. gemini-1.5-flash, gemini-1.5-pro).
        system_prompt: Optional system instruction injected as systemInstruction.
        max_tokens: Maximum output tokens.
    """

    url: str = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    model: str = "gemini-1.5-flash"
    system_prompt: str | None = None
    max_tokens: int = Field(default=1024, ge=1, le=32768)


class CohereEndpointConfig(BaseModel):
    """Endpoint config for the Cohere Chat API (v2).

    Uses the /v2/chat endpoint. Authentication is via a Bearer token.

    Attributes:
        url: Cohere chat endpoint URL.
        model: Cohere model identifier (e.g. command-r-plus, command-r).
        system_prompt: Optional system message prepended to the conversation.
        max_tokens: Maximum tokens in the response.
    """

    url: str = "https://api.cohere.com/v2/chat"
    model: str = "command-r-plus"
    system_prompt: str | None = None
    max_tokens: int = Field(default=1024, ge=1, le=32768)


# ─────────────────────────────────────────────────────────────────────────────
# Root target model
# ─────────────────────────────────────────────────────────────────────────────

# Union type for the endpoint field — Pydantic discriminates on 'type'
AnyEndpointConfig = (
    OpenAIEndpointConfig
    | AnthropicEndpointConfig
    | GeminiEndpointConfig
    | CohereEndpointConfig
    | CustomAPIEndpointConfig
    | WebpageEndpointConfig
)


class TargetConfig(BaseModel):
    """Root model for a target YAML file.

    Attributes:
        type: Target type — determines which adapter and endpoint schema to use.
        endpoint: Endpoint-specific configuration.
        auth: Authentication configuration.
        options: Extra key-value options passed through to the adapter.
    """

    type: Literal["openai", "anthropic", "gemini", "cohere", "custom_api", "webpage"]
    endpoint: AnyEndpointConfig
    auth: AuthConfig = Field(default_factory=AuthConfig)
    options: dict = Field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "TargetConfig":
        """Construct TargetConfig from a raw dict, routing endpoint by type.

        This is needed because Pydantic cannot automatically discriminate the
        endpoint union without a discriminator field on the endpoint model itself.

        Args:
            data: Raw dict loaded from a target YAML file.

        Returns:
            Validated TargetConfig instance.

        Raises:
            ValueError: If 'type' is missing or unrecognised.
        """
        target_type = data.get("type")
        endpoint_data = data.get("endpoint", {})

        endpoint_model_map: dict[str, type] = {
            "openai": OpenAIEndpointConfig,
            "anthropic": AnthropicEndpointConfig,
            "gemini": GeminiEndpointConfig,
            "cohere": CohereEndpointConfig,
            "custom_api": CustomAPIEndpointConfig,
            "webpage": WebpageEndpointConfig,
        }

        if target_type not in endpoint_model_map:
            raise ValueError(
                f"Unknown target type '{target_type}'. "
                f"Must be one of: {list(endpoint_model_map)}"
            )

        endpoint_cls = endpoint_model_map[target_type]
        # Build with the concrete endpoint model
        data_copy = {**data, "endpoint": endpoint_cls.model_validate(endpoint_data)}
        # Remove 'type' from inner dict to avoid conflict with Literal validation
        return cls.model_validate(data_copy)
