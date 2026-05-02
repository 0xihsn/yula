"""
Tests for yula_ai_scanner.config.loader, scan_schema, and target_schema.

Validates YAML loading, env-var interpolation, and Pydantic validation
for both scan and target config files.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from yula_ai_scanner.config.loader import ConfigurationError, load_scan_config, load_target_config
from yula_ai_scanner.config.scan_schema import ScanConfig, VisibilityLevel
from yula_ai_scanner.config.target_schema import AuthType, TargetConfig


# ---------------------------------------------------------------------------
# Scan config tests
# ---------------------------------------------------------------------------

class TestScanConfigLoader:
    def _write_yaml(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "scan.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        return p

    def test_default_scan_config_loads(self):
        config = ScanConfig()
        assert config.scan.visibility == VisibilityLevel.INTERNAL

    def test_load_minimal_scan_yaml(self, tmp_path):
        path = self._write_yaml(tmp_path, {"scan": {"visibility": "public"}})
        config = load_scan_config(path)
        assert config.scan.visibility == VisibilityLevel.PUBLIC

    def test_missing_file_raises_configuration_error(self, tmp_path):
        with pytest.raises(ConfigurationError):
            load_scan_config(tmp_path / "nonexistent.yaml")

    def test_env_var_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_LOG_LEVEL", "DEBUG")
        path = self._write_yaml(
            tmp_path, {"output": {"log_level": "${MY_LOG_LEVEL}"}}
        )
        config = load_scan_config(path)
        assert config.output.log_level == "DEBUG"

    def test_missing_env_var_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("MISSING_VAR_XYZ", raising=False)
        path = self._write_yaml(
            tmp_path, {"output": {"log_file": "${MISSING_VAR_XYZ}"}}
        )
        with pytest.raises(ConfigurationError):
            load_scan_config(path)


# ---------------------------------------------------------------------------
# Target config tests
# ---------------------------------------------------------------------------

class TestTargetConfigLoader:
    def _write_target(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "target.yaml"
        p.write_text(yaml.dump(data), encoding="utf-8")
        return p

    def test_load_openai_target(self, tmp_path):
        data = {
            "type": "openai",
            "endpoint": {
                "url": "http://localhost:8080/v1/chat/completions",
                "model": "gpt-4o",
            },
            "auth": {"type": "none"},
        }
        path = self._write_target(tmp_path, data)
        config = load_target_config(path)
        assert config.type == "openai"
        assert config.endpoint.url == "http://localhost:8080/v1/chat/completions"

    def test_load_anthropic_target(self, tmp_path):
        data = {
            "type": "anthropic",
            "endpoint": {
                "url": "https://api.anthropic.com/v1/messages",
                "model": "claude-3-5-sonnet-20241022",
            },
            "auth": {"type": "api_key", "api_key": "ant-test"},
        }
        path = self._write_target(tmp_path, data)
        config = load_target_config(path)
        assert config.type == "anthropic"
        assert config.auth.type == AuthType.API_KEY

    def test_load_custom_api_target(self, tmp_path):
        data = {
            "type": "custom_api",
            "endpoint": {
                "url": "http://localhost:9000/api/chat",
                "body_template": '{"message": "{prompt}"}',
                "response_path": "response.text",
            },
            "auth": {"type": "none"},
        }
        path = self._write_target(tmp_path, data)
        config = load_target_config(path)
        assert config.type == "custom_api"

    def test_invalid_target_type_raises(self, tmp_path):
        data = {"type": "unknown_type", "auth": {"type": "none"}}
        path = self._write_target(tmp_path, data)
        with pytest.raises(ConfigurationError):
            load_target_config(path)

    def test_api_key_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "sk-test-from-env")
        data = {
            "type": "openai",
            "endpoint": {"url": "http://localhost/v1/chat/completions"},
            "auth": {"type": "api_key", "api_key": "${TEST_API_KEY}"},
        }
        path = self._write_target(tmp_path, data)
        config = load_target_config(path)
        assert config.auth.api_key == "sk-test-from-env"
