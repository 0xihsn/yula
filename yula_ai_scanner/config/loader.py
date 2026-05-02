"""
YAML configuration loader with environment variable interpolation.

Loads and validates both scan.yaml and target YAML files. All string values
in the YAML files that match ${VARIABLE_NAME} are resolved from the process
environment before Pydantic validation runs.

Env var interpolation allows secrets (API keys, tokens, passwords) to be kept
out of config files and instead set as environment variables or in a .env file.

Example:
    api_key: "${OPENAI_API_KEY}"   →   api_key: "sk-actual-key-value"

Missing env vars raise ConfigurationError immediately at startup so the user
gets a clear error message before any scan begins.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from dotenv import load_dotenv

from yula_ai_scanner.config.scan_schema import ScanConfig
from yula_ai_scanner.config.target_schema import TargetConfig


class ConfigurationError(Exception):
    """Raised when a config file is invalid or references a missing env var."""


# Matches ${VARIABLE_NAME} patterns in YAML string values
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def load_scan_config(path: str | Path) -> ScanConfig:
    """Load and validate a scan.yaml file.

    Resolves environment variable references before Pydantic validation.
    Also loads any .env file in the project root directory automatically.

    Args:
        path: Path to scan.yaml.

    Returns:
        Validated ScanConfig instance.

    Raises:
        ConfigurationError: If the file is missing, invalid YAML, contains
                            unresolvable env var references, or fails validation.
    """
    path = Path(path)
    _load_dotenv(path.parent)

    raw = _read_yaml(path)
    interpolated = _interpolate_env_vars(raw, path)

    try:
        return ScanConfig.model_validate(interpolated)
    except Exception as exc:
        raise ConfigurationError(
            f"scan.yaml validation failed: {exc}"
        ) from exc


def load_target_config(path: str | Path) -> TargetConfig:
    """Load and validate a target YAML file.

    Resolves environment variable references before Pydantic validation.

    Args:
        path: Path to a target YAML file (e.g. config/targets/openai_target.yaml).

    Returns:
        Validated TargetConfig instance.

    Raises:
        ConfigurationError: If the file is missing, invalid, or fails validation.
    """
    path = Path(path)
    _load_dotenv(path.parent.parent)  # the project root .env

    raw = _read_yaml(path)
    interpolated = _interpolate_env_vars(raw, path)

    try:
        return TargetConfig.from_dict(interpolated)
    except Exception as exc:
        raise ConfigurationError(
            f"Target config '{path}' validation failed: {exc}"
        ) from exc


def _read_yaml(path: Path) -> dict:
    """Read and parse a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed Python dict.

    Raises:
        ConfigurationError: If the file does not exist or contains invalid YAML.
    """
    if not path.exists():
        raise ConfigurationError(f"Config file not found: {path}")
    try:
        content = path.read_text(encoding="utf-8")
        result = yaml.safe_load(content)
        return result or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid YAML in {path}: {exc}") from exc


def _load_dotenv(directory: Path) -> None:
    """Load a .env file from the given directory if it exists.

    Args:
        directory: Directory to look for a .env file in.
    """
    dotenv_path = directory / ".env"
    if dotenv_path.exists():
        load_dotenv(dotenv_path, override=False)  # don't override already-set vars


def _interpolate_env_vars(data: object, source_path: Path) -> object:
    """Recursively replace ${VAR_NAME} patterns with environment variable values.

    Walks the entire parsed YAML structure (dicts, lists, strings) and
    substitutes any ${VAR_NAME} reference with the corresponding env var value.

    Args:
        data: Parsed YAML data (dict, list, str, or scalar).
        source_path: Source file path (used in error messages).

    Returns:
        Data structure with env var references replaced.

    Raises:
        ConfigurationError: If a referenced environment variable is not set.
    """
    if isinstance(data, dict):
        return {k: _interpolate_env_vars(v, source_path) for k, v in data.items()}
    if isinstance(data, list):
        return [_interpolate_env_vars(item, source_path) for item in data]
    if isinstance(data, str):
        return _resolve_string(data, source_path)
    # Integers, floats, booleans, None — return as-is
    return data


def _resolve_string(value: str, source_path: Path) -> str:
    """Substitute all ${VAR_NAME} references in a string value.

    Args:
        value: String that may contain ${VAR_NAME} patterns.
        source_path: Source file path (for error messages).

    Returns:
        String with all env var references substituted.

    Raises:
        ConfigurationError: If any referenced variable is not set.
    """
    def replace_match(match: re.Match) -> str:  # type: ignore[type-arg]
        var_name = match.group(1)
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ConfigurationError(
                f"Environment variable '{var_name}' referenced in {source_path} "
                f"is not set. Set it in your shell or in the project root .env"
            )
        return env_value

    return _ENV_VAR_RE.sub(replace_match, value)
