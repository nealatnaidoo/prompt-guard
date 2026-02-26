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
        value = os.environ.get(env_key)
        if value is not None:
            # Navigate to the right nested dict
            d = config
            for part in config_path_parts[:-1]:
                d = d.setdefault(part, {})
            # Type coercion
            if value.lower() in ("true", "false"):
                value = value.lower() == "true"
            elif value.isdigit():
                value = int(value)
            else:
                try:
                    value = float(value)
                except ValueError:
                    pass
            d[config_path_parts[-1]] = value

    return config
