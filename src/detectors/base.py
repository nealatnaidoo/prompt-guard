"""Base detector interface and registry."""

from __future__ import annotations

import abc
from typing import Any

from ..models.schemas import DetectorFinding


class BaseDetector(abc.ABC):
    """Abstract base class for all content detectors."""

    name: str = "base"
    version: str = "0.1.0"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abc.abstractmethod
    async def scan(self, content: str, metadata: dict[str, Any]) -> list[DetectorFinding]:
        """Scan content and return list of findings.

        Each detector should return findings with scores between 0.0 and 1.0.
        An empty list means nothing suspicious detected.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} v{self.version}>"


class DetectorRegistry:
    """Registry for managing available detectors."""

    def __init__(self):
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        self._detectors[detector.name] = detector

    def get(self, name: str) -> BaseDetector | None:
        return self._detectors.get(name)

    def all(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def names(self) -> list[str]:
        return list(self._detectors.keys())

    def __len__(self) -> int:
        return len(self._detectors)
