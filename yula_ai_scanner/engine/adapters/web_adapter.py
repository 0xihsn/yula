"""
Web page adapter: drives a real browser using Playwright.

This adapter is used when the AI system under test is a web application with
a visible chat input field. YULA AI Scanner launches a real browser, interacts
with it exactly as a user would (filling the input, clicking send, reading the
response), and extracts the AI's reply from the DOM.

Key design decisions:
  - A single persistent browser context is maintained across all test payloads.
    This preserves session state (cookies, localStorage, login state) and avoids
    repeatedly logging in for each test — which would be very slow.
  - The adapter is NOT safe to use concurrently (one browser, one page).
    The executor must run web adapter tests sequentially (concurrency=1 is
    enforced when target.type == "webpage").
  - The endpoint config is normalised to a single (BrowserConfig, setup_steps,
    PromptCycle) shape via WebpageEndpointConfig.to_flow() so this adapter only
    ever consumes one representation, regardless of whether the user wrote the
    shorthand or the full step-based form.

Prerequisites:
  pip install playwright
  playwright install chromium
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from yula_ai_scanner.config.target_schema import (
    AuthConfig,
    BrowserConfig,
    ExtractConfig,
    FlowStep,
    PromptCycle,
    PromptInput,
    ResetConfig,
    SubmitConfig,
    WaitForConfig,
    WebpageEndpointConfig,
)
from yula_ai_scanner.engine.adapters.base import AdapterError, AdapterResponse, BaseAdapter
from yula_ai_scanner.engine.auth.provider import AuthProvider

logger = logging.getLogger("yula_ai_scanner.web_adapter")


class WebAdapter(BaseAdapter):
    """Playwright-based adapter for web page AI chat interfaces.

    Attributes:
        endpoint: Web page endpoint configuration (URL, selectors, browser).
        auth_provider: Handles cookie injection and form login.
    """

    def __init__(
        self,
        endpoint: WebpageEndpointConfig,
        auth: AuthConfig,
    ) -> None:
        """Initialise the adapter."""
        self.endpoint = endpoint
        self.auth_provider = AuthProvider(auth)
        # Resolved at setup() time — kept None until then so that __init__
        # never raises (e.g. for validation-only flows).
        self._browser_cfg: BrowserConfig | None = None
        self._setup_steps: list[FlowStep] = []
        self._prompt: PromptCycle | None = None
        # Variables captured by `extract` steps — available for substitution
        # in subsequent step values (e.g. CSRF tokens read in setup).
        self._vars: dict[str, str] = {}
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────

    async def setup(self) -> None:
        """Launch the browser, inject cookies, perform login, run setup steps."""
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise ImportError(
                "playwright is required for webpage targets. "
                "Install it: pip install playwright && playwright install chromium"
            ) from exc

        self._browser_cfg, self._setup_steps, self._prompt = self.endpoint.to_flow()

        self._playwright = await async_playwright().start()
        browser_type = getattr(self._playwright, self._browser_cfg.engine)
        self._browser = await browser_type.launch(headless=self._browser_cfg.headless)

        ctx_kwargs: dict[str, Any] = {}
        if self._browser_cfg.viewport is not None:
            ctx_kwargs["viewport"] = {
                "width": self._browser_cfg.viewport.width,
                "height": self._browser_cfg.viewport.height,
            }
        if self._browser_cfg.user_agent:
            ctx_kwargs["user_agent"] = self._browser_cfg.user_agent
        if self._browser_cfg.extra_http_headers:
            ctx_kwargs["extra_http_headers"] = dict(self._browser_cfg.extra_http_headers)

        self._context = await self._browser.new_context(**ctx_kwargs)

        playwright_cookies = self.auth_provider.get_playwright_cookies()
        if playwright_cookies:
            await self._context.add_cookies(playwright_cookies)

        self._page = await self._context.new_page()

        # Auth: built-in form_login runs first; richer flows belong in `setup:`.
        try:
            await self.auth_provider.perform_form_login(self._page)
        except Exception as exc:
            raise AdapterError(f"Form login failed: {exc}") from exc

        await self._page.goto(
            self.endpoint.url,
            timeout=self._browser_cfg.navigation_timeout_ms,
        )
        try:
            await self._page.wait_for_load_state(
                self._browser_cfg.navigation_wait,
                timeout=self._browser_cfg.navigation_timeout_ms,
            )
        except Exception as exc:
            logger.debug("Initial wait_for_load_state failed (non-fatal): %s", exc)

        for step in self._setup_steps:
            await self._run_step(step)

    async def teardown(self) -> None:
        """Close the browser and stop Playwright. Errors are swallowed."""
        try:
            if self._context:
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._playwright:
                await self._playwright.stop()
        except Exception as exc:
            logger.debug("Browser teardown error (non-fatal): %s", exc)
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._playwright = None

    # ──────────────────────────────────────────────────────────────────────
    # Per-payload execution
    # ──────────────────────────────────────────────────────────────────────

    async def send(self, prompt: str) -> AdapterResponse:
        """Run one prompt cycle: reset → before → inputs → submit → wait → extract."""
        if self._page is None or self._prompt is None:
            raise RuntimeError("Adapter not set up — call setup() first")

        start_ms = time.monotonic() * 1000
        await self._apply_reset(self._prompt.reset)
        text = await self._run_prompt_cycle(self._prompt, prompt)
        duration_ms = time.monotonic() * 1000 - start_ms

        return AdapterResponse(
            text=text,
            http_status=None,
            raw_body=None,
            duration_ms=duration_ms,
        )

    async def send_turns(self, turns: list[str]) -> AdapterResponse:
        """Multi-turn variant — reset once at top, then loop without resets."""
        if self._page is None or self._prompt is None:
            raise RuntimeError("Adapter not set up — call setup() first")
        if not turns:
            return AdapterResponse(text="", turn_texts=[])

        replies: list[str] = []
        total_duration = 0.0

        await self._apply_reset(self._prompt.reset)

        for turn in turns:
            start_ms = time.monotonic() * 1000
            text = await self._run_prompt_cycle(self._prompt, turn)
            replies.append(text)
            total_duration += time.monotonic() * 1000 - start_ms

        return AdapterResponse(
            text="\n---\n".join(replies),
            http_status=None,
            raw_body=None,
            duration_ms=total_duration,
            turn_texts=replies,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Step engine
    # ──────────────────────────────────────────────────────────────────────

    async def _run_prompt_cycle(self, cycle: PromptCycle, prompt: str) -> str:
        """Drive one full prompt cycle and return the extracted response text."""
        for step in cycle.before:
            await self._run_step(step, prompt=prompt)

        for field in cycle.inputs:
            await self._fill_input(field, prompt)

        await self._submit(cycle.submit)
        await self._wait_for_response(cycle.wait_for)
        return await self._extract(cycle.extract, cycle.wait_for)

    async def _fill_input(self, field: PromptInput, prompt: str) -> None:
        value = self._render(field.value, prompt=prompt)
        locator = await self._resolve_locator(
            field.selector, field.fallback_selectors, "input field"
        )
        try:
            await locator.click()
            if field.method == "fill":
                await locator.fill(value)
            elif field.method == "type":
                await locator.type(value, delay=field.delay_ms or None)
            else:  # press_sequentially
                await locator.press_sequentially(value, delay=field.delay_ms or None)
        except Exception as exc:
            raise AdapterError(
                f"Cannot populate input '{field.selector}' (method={field.method}): {exc}"
            ) from exc

    async def _submit(self, cfg: SubmitConfig) -> None:
        if cfg.method == "press_enter":
            await self._page.keyboard.press("Enter")
            return
        if cfg.method == "press_key":
            await self._page.keyboard.press(cfg.key)
            return
        # method == click
        assert cfg.selector is not None  # enforced by validator
        locator = await self._resolve_locator(
            cfg.selector, cfg.fallback_selectors, "submit button"
        )
        try:
            await locator.click()
        except Exception as exc:
            raise AdapterError(
                f"Cannot click submit '{cfg.selector}': {exc}"
            ) from exc

    async def _wait_for_response(self, cfg: WaitForConfig) -> None:
        if cfg.state == "networkidle":
            try:
                await self._page.wait_for_load_state("networkidle", timeout=cfg.timeout_ms)
            except Exception as exc:
                raise AdapterError(
                    f"networkidle did not settle within {cfg.timeout_ms}ms: {exc}"
                ) from exc
            if cfg.settle_ms:
                await asyncio.sleep(cfg.settle_ms / 1000)
            return

        locator = await self._resolve_locator(
            cfg.selector, cfg.fallback_selectors, "response container", visible_check=False
        )
        try:
            if cfg.state == "text":
                assert cfg.contains is not None  # enforced by validator
                await locator.filter(has_text=cfg.contains).first.wait_for(
                    state="visible", timeout=cfg.timeout_ms
                )
            else:
                await locator.first.wait_for(state=cfg.state, timeout=cfg.timeout_ms)
        except Exception as exc:
            raise AdapterError(
                f"Response selector '{cfg.selector}' did not reach state={cfg.state} "
                f"within {cfg.timeout_ms}ms: {exc}"
            ) from exc

        if cfg.settle_ms:
            await asyncio.sleep(cfg.settle_ms / 1000)

    async def _extract(self, cfg: ExtractConfig, wait_cfg: WaitForConfig) -> str:
        # `cfg.selector` is normalised to wait_cfg.selector when omitted, but
        # double-check here for defensiveness.
        selector = cfg.selector or wait_cfg.selector
        locator = await self._resolve_locator(
            selector, cfg.fallback_selectors, "extract target", visible_check=False
        )

        if cfg.pick == "first":
            target = locator.first
        elif cfg.pick == "last":
            try:
                target = locator.last
            except Exception:
                target = locator
        else:  # all
            target = locator

        try:
            if cfg.method == "inner_text":
                text = await target.inner_text() if cfg.pick != "all" else "\n".join(
                    await locator.all_inner_texts()
                )
            elif cfg.method == "text_content":
                text = (await target.text_content()) or ""
            elif cfg.method == "inner_html":
                text = await target.inner_html()
            elif cfg.method == "attribute":
                assert cfg.attribute is not None
                text = (await target.get_attribute(cfg.attribute)) or ""
            else:  # evaluate
                assert cfg.script is not None
                text = await target.evaluate(cfg.script)
                if not isinstance(text, str):
                    text = str(text)
        except Exception as exc:
            raise AdapterError(
                f"Cannot read response from '{selector}' (method={cfg.method}): {exc}"
            ) from exc

        text = text.strip()

        if cfg.regex:
            match = re.search(cfg.regex, text, flags=re.DOTALL)
            if match is None:
                raise AdapterError(
                    f"Extract regex {cfg.regex!r} did not match response text"
                )
            try:
                text = match.group(cfg.regex_group)
            except IndexError as exc:
                raise AdapterError(
                    f"Extract regex group {cfg.regex_group} out of range"
                ) from exc

        return text

    async def _apply_reset(self, cfg: ResetConfig) -> None:
        if cfg.action == "none":
            return
        if cfg.action == "reload":
            try:
                await self._page.reload()
                if self._browser_cfg is not None:
                    await self._page.wait_for_load_state(
                        self._browser_cfg.navigation_wait,
                        timeout=self._browser_cfg.navigation_timeout_ms,
                    )
            except Exception as exc:
                logger.debug("Reset reload failed (non-fatal): %s", exc)
            return
        # action == click
        assert cfg.selector is not None
        try:
            locator = await self._resolve_locator(
                cfg.selector, cfg.fallback_selectors, "reset button", optional=True
            )
            if locator is None:
                return
            if await locator.first.is_visible(timeout=1000):
                await locator.first.click()
                await asyncio.sleep(0.3)
        except Exception as exc:
            logger.debug("Reset click failed (non-fatal): %s", exc)

    async def _run_step(self, step: FlowStep, *, prompt: str | None = None) -> None:
        """Dispatch a single FlowStep against the current page."""
        a = step.action
        try:
            if a == "navigate":
                assert step.url is not None
                await self._page.goto(step.url, timeout=step.timeout_ms or None)
                if self._browser_cfg is not None:
                    await self._page.wait_for_load_state(
                        self._browser_cfg.navigation_wait,
                        timeout=self._browser_cfg.navigation_timeout_ms,
                    )
                return

            if a == "reload":
                await self._page.reload(timeout=step.timeout_ms or None)
                return

            if a == "sleep":
                await asyncio.sleep(step.ms / 1000)
                return

            if a == "press_key":
                await self._page.keyboard.press(step.key)
                return

            if a == "evaluate":
                assert step.script is not None
                value = await self._page.evaluate(step.script)
                if step.store_as:
                    self._vars[step.store_as] = "" if value is None else str(value)
                return

            # All remaining actions resolve a selector.
            assert step.selector is not None
            locator = await self._resolve_locator(
                step.selector,
                step.fallback_selectors,
                f"step action={a}",
                optional=step.optional,
            )
            if locator is None:
                return  # optional step, selector not found

            if a == "click":
                await locator.first.click()
                return

            if a == "fill":
                value = self._render(step.value or "", prompt=prompt)
                if step.method == "fill":
                    await locator.first.fill(value)
                elif step.method == "type":
                    await locator.first.type(value, delay=step.delay_ms or None)
                else:
                    await locator.first.press_sequentially(value, delay=step.delay_ms or None)
                return

            if a == "type":
                value = self._render(step.value or "", prompt=prompt)
                await locator.first.type(value, delay=step.delay_ms or None)
                return

            if a == "wait":
                if step.state == "text":
                    assert step.contains is not None
                    await locator.filter(has_text=step.contains).first.wait_for(
                        state="visible", timeout=step.timeout_ms
                    )
                else:
                    await locator.first.wait_for(state=step.state, timeout=step.timeout_ms)
                return

            if a == "extract":
                if step.extract_method == "attribute":
                    assert step.attribute is not None
                    value = (await locator.first.get_attribute(step.attribute)) or ""
                elif step.extract_method == "evaluate":
                    assert step.script is not None
                    value = await locator.first.evaluate(step.script)
                    value = "" if value is None else str(value)
                elif step.extract_method == "text_content":
                    value = (await locator.first.text_content()) or ""
                elif step.extract_method == "inner_html":
                    value = await locator.first.inner_html()
                else:  # inner_text
                    value = await locator.first.inner_text()
                if step.store_as:
                    self._vars[step.store_as] = str(value).strip()
                return

        except AdapterError:
            raise
        except Exception as exc:
            if step.optional:
                logger.debug("Optional step action=%s failed: %s", a, exc)
                return
            raise AdapterError(f"Step action={a} failed: {exc}") from exc

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    async def _resolve_locator(
        self,
        selector: str,
        fallbacks: list[str],
        purpose: str,
        *,
        optional: bool = False,
        visible_check: bool = True,
    ) -> Any:
        """Try `selector`, then each fallback, returning the first that matches.

        For `visible_check=True` (default), "matches" means at least one element
        is found (count > 0). The actual visibility/state wait is done by the
        caller. With `optional=True`, returns None instead of raising when no
        selector matches.
        """
        candidates = [selector, *fallbacks]
        last_err: Exception | None = None
        for sel in candidates:
            try:
                locator = self._page.locator(sel)
                if visible_check:
                    count = await locator.count()
                    if count == 0:
                        continue
                return locator
            except Exception as exc:
                last_err = exc
                continue
        if optional:
            return None
        tried = ", ".join(repr(s) for s in candidates)
        suffix = f" (last error: {last_err})" if last_err else ""
        raise AdapterError(f"No selector for {purpose} matched. Tried: {tried}{suffix}")

    def _render(self, template: str, *, prompt: str | None) -> str:
        """Substitute `{prompt}` and `{var_name}` placeholders.

        Variables captured by earlier `extract` steps live in `self._vars`.
        Unknown placeholders raise AdapterError (better than silent empty fill).
        """
        substitutions: dict[str, str] = dict(self._vars)
        if prompt is not None:
            substitutions["prompt"] = prompt

        def _replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in substitutions:
                raise AdapterError(
                    f"Unknown placeholder {{{name}}} in step value. "
                    f"Available: {sorted(substitutions.keys())}"
                )
            return substitutions[name]

        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", _replace, template)
