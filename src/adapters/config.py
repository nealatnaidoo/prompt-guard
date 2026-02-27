"""YamlFileConfigAdapter — loads config from YAML files.

Wraps the existing load_config() logic from src/utils/config.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..ports.config import ConfigPort
from ..utils.config import load_config


class YamlFileConfigAdapter(ConfigPort):
    """Production adapter that loads configuration from a YAML file."""

    def __init__(self, path: str | Path | None = None):
        self._path = path

    def load(self) -> dict[str, Any]:
        """Load and return configuration from YAML file."""
        return load_config(self._path)
