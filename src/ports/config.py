"""ConfigPort — abstract interface for configuration loading.

Decouples domain services from filesystem/YAML details.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ConfigPort(ABC):
    """Port for loading application configuration."""

    @abstractmethod
    def load(self) -> dict[str, Any]:
        """Load and return the configuration dictionary."""
        ...
