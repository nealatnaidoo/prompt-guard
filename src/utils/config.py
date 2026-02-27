"""Configuration loader."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from YAML file with environment variable overrides."""
    config_path = Path(path) if path else _DEFAULT_CONFIG_PATH

    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    # Allow env var overrides for key settings
    env_overrides = {
        "PROMPT_GUARD_HOST": ("service", "host"),
        "PROMPT_GUARD_PORT": ("service", "port"),
        "PROMPT_GUARD_LOG_LEVEL": ("service", "log_level"),
        "PROMPT_GUARD_THREAT_THRESHOLD": ("detection", "threat_threshold"),
        "PROMPT_GUARD_LLM_JUDGE_ENABLED": ("semantic_detector", "llm_judge_enabled"),
    }

    for env_key, config_path_parts in env_overrides.items():
        raw_value = os.environ.get(env_key)
        if raw_value is not None:
            # Navigate to the right nested dict
            d = config
            for part in config_path_parts[:-1]:
                d = d.setdefault(part, {})
            # Type coercion
            coerced: Any
            if raw_value.lower() in ("true", "false"):
                coerced = raw_value.lower() == "true"
            elif raw_value.isdigit():
                coerced = int(raw_value)
            else:
                try:
                    coerced = float(raw_value)
                except ValueError:
                    coerced = raw_value
            d[config_path_parts[-1]] = coerced

    return config
