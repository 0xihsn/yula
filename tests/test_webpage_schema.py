"""
Schema tests for the webpage target — validation only, no Playwright required.

Covers:
  - Shorthand (flat fields) normalises to a PromptCycle
  - Flow style validates and round-trips through to_flow()
  - Mixing shorthand response fields with `prompt:` is rejected
  - Per-step / per-config validators catch missing required fields
  - Browser field accepts both `chromium` (string) and {engine: ...} (dict)
  - ${ENV_VAR} interpolation flows into nested step values
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from yula_ai_scanner.config.loader import load_target_config
from yula_ai_scanner.config.target_schema import (
    BrowserConfig,
    ExtractConfig,
    FlowStep,
    PromptCycle,
    PromptInput,
    ResetConfig,
    SubmitConfig,
    TargetConfig,
    WaitForConfig,
    WebpageEndpointConfig,
)


# ──────────────────────────────────────────────────────────────────────
# Shorthand → flow normalisation
# ──────────────────────────────────────────────────────────────────────


def test_shorthand_minimal_validates_and_normalises():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        input_field="#in",
        response_container=".out",
    )
    browser, setup, prompt = cfg.to_flow()

    assert isinstance(browser, BrowserConfig)
    assert browser.engine == "chromium"
    assert browser.headless is True
    assert setup == []

    assert prompt.inputs == [PromptInput(selector="#in", value="{prompt}")]
    assert prompt.submit.method == "press_enter"
    assert prompt.wait_for.selector == ".out"
    assert prompt.wait_for.timeout_ms == 8000
    assert prompt.extract.selector == ".out"
    assert prompt.extract.pick == "last"
    assert prompt.reset.action == "none"


def test_shorthand_with_submit_and_clear_normalises():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        input_field="#in",
        submit_button="#go",
        response_container=".out",
        clear_button=".clear",
        response_wait_ms=12000,
    )
    _, _, prompt = cfg.to_flow()
    assert prompt.submit.method == "click"
    assert prompt.submit.selector == "#go"
    assert prompt.reset.action == "click"
    assert prompt.reset.selector == ".clear"
    assert prompt.wait_for.timeout_ms == 12000


def test_shorthand_legacy_headless_carries_into_browser_config():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        headless=False,
        input_field="#in",
        response_container=".out",
    )
    browser, _, _ = cfg.to_flow()
    assert browser.headless is False


def test_shorthand_missing_required_fields_rejected():
    with pytest.raises(ValidationError) as excinfo:
        WebpageEndpointConfig(url="http://x/chat")
    msg = str(excinfo.value)
    assert "input_field" in msg and "response_container" in msg


# ──────────────────────────────────────────────────────────────────────
# Flow style
# ──────────────────────────────────────────────────────────────────────


def test_flow_style_validates_and_extract_selector_defaults_to_wait_for():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        prompt=PromptCycle(
            inputs=[PromptInput(selector="#in")],
            submit=SubmitConfig(method="press_enter"),
            wait_for=WaitForConfig(selector=".out", state="visible"),
            # extract.selector intentionally omitted — should default to ".out"
        ),
    )
    _, _, prompt = cfg.to_flow()
    assert prompt.extract.selector == ".out"


def test_flow_style_with_setup_steps_and_browser_object():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        browser=BrowserConfig(engine="firefox", headless=False),
        setup=[
            FlowStep(
                action="extract",
                selector="input[name=csrf]",
                extract_method="attribute",
                attribute="value",
                store_as="csrf",
            ),
        ],
        prompt=PromptCycle(
            inputs=[
                PromptInput(selector="input[name=csrf]", value="{csrf}"),
                PromptInput(selector="#in", value="{prompt}"),
            ],
            submit=SubmitConfig(method="click", selector="#go"),
            wait_for=WaitForConfig(selector=".out", state="visible"),
        ),
    )
    browser, setup, prompt = cfg.to_flow()
    assert browser.engine == "firefox"
    assert browser.headless is False
    assert len(setup) == 1
    assert setup[0].store_as == "csrf"
    assert len(prompt.inputs) == 2


# ──────────────────────────────────────────────────────────────────────
# XOR enforcement: shorthand vs flow
# ──────────────────────────────────────────────────────────────────────


def test_mixing_shorthand_and_prompt_block_rejected():
    with pytest.raises(ValidationError) as excinfo:
        WebpageEndpointConfig(
            url="http://x/chat",
            input_field="#in",  # shorthand
            response_container=".out",  # shorthand
            prompt=PromptCycle(  # flow
                inputs=[PromptInput(selector="#in")],
                wait_for=WaitForConfig(selector=".out", state="visible"),
            ),
        )
    msg = str(excinfo.value)
    assert "shorthand" in msg.lower() and "prompt" in msg.lower()


# ──────────────────────────────────────────────────────────────────────
# Browser field coercion
# ──────────────────────────────────────────────────────────────────────


def test_browser_string_coerces_to_browser_config():
    cfg = WebpageEndpointConfig(
        url="http://x/chat",
        browser="webkit",  # type: ignore[arg-type]
        input_field="#in",
        response_container=".out",
    )
    browser, _, _ = cfg.to_flow()
    assert browser.engine == "webkit"
    assert browser.headless is True  # default preserved


# ──────────────────────────────────────────────────────────────────────
# Per-step validators
# ──────────────────────────────────────────────────────────────────────


def test_navigate_requires_url():
    with pytest.raises(ValidationError, match="action=navigate requires 'url'"):
        FlowStep(action="navigate")


def test_wait_state_text_requires_contains():
    with pytest.raises(ValidationError, match="state=text requires 'contains'"):
        FlowStep(action="wait", selector="#x", state="text")


def test_extract_attribute_requires_attribute():
    with pytest.raises(ValidationError, match="method=attribute requires 'attribute'"):
        FlowStep(action="extract", selector="#x", extract_method="attribute")


def test_extract_evaluate_requires_script():
    with pytest.raises(ValidationError, match="method=evaluate requires 'script'"):
        FlowStep(action="extract", selector="#x", extract_method="evaluate")


def test_evaluate_step_requires_script():
    with pytest.raises(ValidationError, match="action=evaluate requires 'script'"):
        FlowStep(action="evaluate")


def test_submit_click_requires_selector():
    with pytest.raises(ValidationError, match="submit.method=click requires 'selector'"):
        SubmitConfig(method="click")


def test_wait_for_text_requires_contains():
    with pytest.raises(ValidationError, match="wait_for.state=text requires 'contains'"):
        WaitForConfig(selector="#x", state="text")


def test_extract_attribute_config_requires_attribute():
    with pytest.raises(ValidationError, match="extract.method=attribute requires 'attribute'"):
        ExtractConfig(method="attribute")


def test_reset_click_requires_selector():
    with pytest.raises(ValidationError, match="reset.action=click requires 'selector'"):
        ResetConfig(action="click")


def test_unknown_step_action_rejected():
    with pytest.raises(ValidationError):
        FlowStep(action="teleport")  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────
# ${ENV_VAR} interpolation reaches nested step fields
# ──────────────────────────────────────────────────────────────────────


def test_env_var_interpolation_in_step_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WEB_USER", "alice")
    monkeypatch.setenv("WEB_PASS", "s3cret")

    cfg_yaml = {
        "type": "webpage",
        "endpoint": {
            "url": "http://x/chat",
            "setup": [
                {"action": "fill", "selector": "#u", "value": "${WEB_USER}"},
                {"action": "fill", "selector": "#p", "value": "${WEB_PASS}"},
            ],
            "prompt": {
                "inputs": [{"selector": "#in", "value": "{prompt}"}],
                "submit": {"method": "press_enter"},
                "wait_for": {"selector": ".out", "state": "visible"},
            },
        },
        "auth": {"type": "none"},
    }
    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump(cfg_yaml), encoding="utf-8")

    target = load_target_config(path)
    assert isinstance(target.endpoint, WebpageEndpointConfig)
    setup = target.endpoint.setup
    assert setup[0].value == "alice"
    assert setup[1].value == "s3cret"


# ──────────────────────────────────────────────────────────────────────
# Bundled example configs all validate
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "filename",
    [
        "webpage_target.yaml",
        "gandalf.lakera.yaml",
        "webpage_form_login.yaml",
        "webpage_multi_input.yaml",
    ],
)
def test_bundled_webpage_configs_validate(
    filename: str,
    monkeypatch: pytest.MonkeyPatch,
):
    # Stub env vars referenced by the bundled examples.
    monkeypatch.setenv("SESSION_TOKEN", "stub")
    monkeypatch.setenv("APP_USERNAME", "stub")
    monkeypatch.setenv("APP_PASSWORD", "stub")

    project_root = Path(__file__).parent.parent
    target = load_target_config(project_root / "config" / "targets" / filename)
    assert isinstance(target, TargetConfig)
    assert isinstance(target.endpoint, WebpageEndpointConfig)
    # to_flow() must succeed for every bundled config.
    target.endpoint.to_flow()
